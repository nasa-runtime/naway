//! 固定 HTTP 消息插件传输；原始 Bytes 共享发送，响应动作必须完整验证后才生效。

use std::path::Path;

use anyhow::{ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use http::HeaderValue;
use sha2::{Digest, Sha256};

use super::Failure;

#[derive(Clone, Debug)]
pub(super) struct Plan {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    authorization: Option<HeaderValue>,
    ca_identity: Option<[u8; 32]>,
    pub(super) fail_open: bool,
    allow_rewrite: bool,
    include_consumer: bool,
}

impl Plan {
    /// 业务作用：冻结插件目标与凭据，禁止消息内容选择外呼地址或通过重定向转送正文。
    ///
    /// 参数说明：
    /// - `cfg`：外部消息插件声明，包含端点、信任与修改权限。
    /// - `directory`：文件 SecretSource 的解析根。
    ///
    /// 返回：共享连接池的传输计划；目标、凭据或 CA 非法时拒绝整份候选。
    pub(super) fn build(
        cfg: &crate::config::model::WsMessagePluginCfg,
        directory: &Path,
    ) -> Result<Self> {
        let crate::config::model::WsMessagePluginCfg::External {
            endpoint,
            authorization,
            ca_certificate,
            fail_open,
            allow_rewrite,
            include_consumer,
        } = cfg
        else {
            anyhow::bail!("external WebSocket plugin declaration required");
        };
        let url = reqwest::Url::parse(endpoint)?;
        ensure!(
            endpoint.len() <= 2048
                && matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid WebSocket plugin endpoint"
        );
        let authorization = if authorization.is_empty() {
            None
        } else {
            let value = crate::security::secret::resolve_text(
                authorization,
                directory,
                "WebSocket plugin authorization",
            )?;
            ensure!(
                !value.is_empty() && value.len() <= 4096,
                "invalid WebSocket plugin authorization size"
            );
            let mut header =
                HeaderValue::from_str(&value).context("invalid WebSocket plugin authorization")?;
            header.set_sensitive(true);
            Some(header)
        };
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(8);
        let ca_identity = if !ca_certificate.is_empty() {
            ensure!(
                url.scheme() == "https",
                "WebSocket plugin CA requires HTTPS"
            );
            let pem = crate::security::secret::resolve_text(
                ca_certificate,
                directory,
                "WebSocket plugin CA",
            )?;
            client = client.add_root_certificate(crate::tls::trust::http_ca(pem.as_bytes())?);
            Some(Sha256::digest(pem.as_bytes()).into())
        } else {
            None
        };
        Ok(Self {
            client: client.build()?,
            endpoint: url,
            authorization,
            ca_identity,
            fail_open: *fail_open,
            allow_rewrite: *allow_rewrite,
            include_consumer: *include_consumer,
        })
    }

    /// 业务作用：发送完整原始消息并取得有界动作，不把插件响应头或正文作为额外网关配置解释。
    ///
    /// 参数说明：
    /// - `body`：已验证完整载荷，发送时共享 Bytes backing。
    /// - `context`：冻结握手身份、方向和消息 opcode。
    /// - `maximum`：允许的插件输出硬上限。
    ///
    /// 返回：allow 保留原 Bytes，replace 仅在显式授权且输出完整时返回新正文；其它动作或故障有独立分类。
    pub(super) async fn call(
        &self,
        body: Bytes,
        context: &super::Context<'_>,
        maximum: usize,
    ) -> Result<Bytes, Failure> {
        // 工作席位先于外呼取得，依赖故障开放不能绕过本地正文与并发预算。
        let _workspace = crate::extensions::resources::Lease::acquire(
            maximum.saturating_mul(2).saturating_add(64 * 1024),
        )
        .map_err(|_| Failure::Capacity)?;
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .header(
                "x-naway-ws-direction",
                if context.from_client {
                    "client"
                } else {
                    "server"
                },
            )
            .header(
                "x-naway-ws-opcode",
                if context.opcode == super::super::OpCode::Text {
                    "text"
                } else {
                    "binary"
                },
            );
        if let Some(authorization) = &self.authorization {
            request = request.header("authorization", authorization.clone());
        }
        if self.include_consumer {
            if let Some(consumer) = context.consumer {
                if consumer.len() > 1024 {
                    return Err(Failure::Invalid);
                }
                let mut value = HeaderValue::from_str(consumer).map_err(|_| Failure::Invalid)?;
                value.set_sensitive(true);
                request = request.header("x-naway-ws-consumer", value);
            }
        }
        let mut response = request
            .body(body.clone())
            .send()
            .await
            .map_err(|_| Failure::Dependency)?;
        if response.status().is_server_error() {
            return Err(Failure::Dependency);
        }
        if response.status() != http::StatusCode::OK {
            return Err(Failure::Invalid);
        }
        let headers = response.headers();
        if headers.len() > 64
            || headers
                .iter()
                .map(|(key, value)| key.as_str().len() + value.len())
                .sum::<usize>()
                > 16384
            || headers
                .get_all("content-encoding")
                .iter()
                .any(|value| value != "identity")
        {
            return Err(Failure::Invalid);
        }
        let mut actions = headers.get_all("x-naway-ws-action").iter();
        let action = actions
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(Failure::Invalid)?;
        if actions.next().is_some() {
            return Err(Failure::Invalid);
        }
        let action = match action {
            "allow" => 0,
            "drop" => 1,
            "close" => 2,
            "replace" if self.allow_rewrite => 3,
            _ => return Err(Failure::Invalid),
        };
        let limit = if action == 3 {
            maximum
        } else {
            0
        };
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(Failure::Invalid);
        }
        let mut first = Bytes::new();
        let mut joined = BytesMut::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Dependency)? {
            if chunk.is_empty() {
                continue;
            }
            let used = if joined.is_empty() {
                first.len()
            } else {
                joined.len()
            };
            if chunk.len() > limit.saturating_sub(used) {
                return Err(Failure::Invalid);
            }
            if first.is_empty() && joined.is_empty() {
                first = chunk;
            } else {
                if joined.is_empty() {
                    joined = BytesMut::with_capacity(limit);
                    joined.extend_from_slice(&first);
                    first = Bytes::new();
                }
                joined.extend_from_slice(&chunk);
            }
        }
        match action {
            0 => Ok(body),
            1 => Err(Failure::Drop),
            2 => Err(Failure::Close),
            3 => Ok(if joined.is_empty() {
                first
            } else {
                joined.freeze()
            }),
            _ => unreachable!("validated plugin action"),
        }
    }
}

impl PartialEq for Plan {
    /// 业务作用：比较固定消息外呼的授权、信任和修改权限，连接池活动不影响配置身份。
    ///
    /// 参数说明：
    /// - `other`：已经解析实际凭据与 CA 的候选计划。
    ///
    /// 返回：全部冻结声明相同时为真；不发请求或访问连接池状态。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            client: _,
            endpoint,
            authorization,
            ca_identity,
            fail_open,
            allow_rewrite,
            include_consumer,
        } = self;
        endpoint == &other.endpoint
            && authorization == &other.authorization
            && ca_identity == &other.ca_identity
            && fail_open == &other.fail_open
            && allow_rewrite == &other.allow_rewrite
            && include_consumer == &other.include_consumer
    }
}

impl Eq for Plan {}
