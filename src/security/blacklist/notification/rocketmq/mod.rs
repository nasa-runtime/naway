//! 固定RocketMQ Proxy的普通消息桥接；回执不等于接收业务副作用已经完成。

mod wire;

use super::{AclNotifier, Event};
use anyhow::{ensure, Result};
use futures::future::BoxFuture;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zeroize::Zeroizing;

pub(super) struct Spec {
    endpoint: Endpoint,
    access_point: wire::Endpoints,
    topic: wire::Resource,
    access_key: Option<Zeroizing<String>>,
    secret_key: Option<Zeroizing<String>>,
    timeout: Duration,
}

impl Spec {
    /// 业务作用：冻结受信Proxy、普通消息主题与认证材料，不沿路由响应自动连接其它地址。
    ///
    /// 参数说明：
    /// - `cfg`：平台明确选择的RocketMQ出口。
    /// - `config_dir`：SecretSource文件解析基准。
    /// - `timeout`：每次RPC的已验证期限，外层仍限制整个事件年龄。
    ///
    /// 返回：未连接的固定Endpoint与材料；非法地址、主题、身份或不完整认证拒绝候选。
    pub(super) fn build(
        cfg: &crate::config::model::AclNotificationTransport,
        config_dir: &Path,
        timeout: Duration,
    ) -> Result<Arc<Self>> {
        let crate::config::model::AclNotificationTransport::Rocketmq {
            endpoint,
            topic,
            namespace,
            allow_plaintext,
            tls,
            access_key,
            secret_key,
        } = cfg
        else {
            anyhow::bail!("ACL RocketMQ plan unavailable");
        };
        let url = super::plan::endpoint(endpoint, *allow_plaintext)?;
        ensure!(
            url.path() == "/" && url.query().is_none(),
            "ACL RocketMQ proxy endpoint cannot contain path or query"
        );
        super::plan::topic(topic)?;
        ensure!(
            namespace.len() <= 64
                && namespace
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "invalid ACL RocketMQ namespace"
        );
        let access_key = access_key
            .as_deref()
            .map(|raw| super::plan::secret(raw, config_dir))
            .transpose()?;
        let secret_key = secret_key
            .as_deref()
            .map(|raw| super::plan::secret(raw, config_dir))
            .transpose()?;
        ensure!(
            access_key.is_some() == secret_key.is_some(),
            "ACL RocketMQ requires both access_key and secret_key"
        );
        if let (Some(access), Some(secret)) = (&access_key, &secret_key) {
            ensure!(
                !access.is_empty()
                    && access.len() <= 128
                    && access
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'.' | b'_' | b'-'))
                    && !secret.is_empty(),
                "invalid ACL RocketMQ credentials"
            );
        }
        let mut endpoint = Endpoint::from_shared(url.to_string())
            .map_err(|_| anyhow::anyhow!("invalid ACL RocketMQ endpoint"))?
            .connect_timeout(timeout)
            .timeout(timeout);
        if url.scheme() == "https" {
            let materials = super::plan::tls_material(tls, config_dir)?;
            let mut transport = ClientTlsConfig::new();
            transport = if let Some(ca) = materials.ca {
                transport.ca_certificate(tonic::transport::Certificate::from_pem(ca.as_bytes()))
            } else {
                transport.with_native_roots()
            };
            if let (Some(cert), Some(key)) = (materials.cert, materials.key) {
                transport = transport.identity(tonic::transport::Identity::from_pem(
                    cert.as_bytes(),
                    key.as_bytes(),
                ));
            }
            endpoint = endpoint
                .tls_config(transport)
                .map_err(|_| anyhow::anyhow!("invalid ACL RocketMQ TLS material"))?;
        } else {
            // 明文无法兑现信任或客户端身份材料，不能接受声明后再忽略它们。
            ensure!(
                tls.ca_pem.is_none()
                    && tls.client_cert_pem.is_none()
                    && tls.client_key_pem.is_none(),
                "ACL plaintext RocketMQ cannot configure TLS material"
            );
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("ACL RocketMQ host unavailable"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let scheme = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => 1,
            Ok(std::net::IpAddr::V6(_)) => 2,
            Err(_) => 3,
        };
        let access_point = wire::Endpoints {
            scheme,
            addresses: vec![wire::Address {
                host: host.to_owned(),
                port: i32::from(
                    url.port_or_known_default()
                        .ok_or_else(|| anyhow::anyhow!("ACL RocketMQ port unavailable"))?,
                ),
            }],
        };
        Ok(Arc::new(Self {
            endpoint,
            access_point,
            topic: wire::Resource {
                namespace: namespace.clone(),
                name: topic.clone(),
            },
            access_key,
            secret_key,
            timeout,
        }))
    }
}

struct Rocketmq {
    channel: Option<Channel>,
    spec: Arc<Spec>,
}

impl Rocketmq {
    /// 业务作用：为受信固定方法调用生成新鲜MQv2认证头，不让请求或broker响应选择目标。
    ///
    /// 参数说明：
    /// - `event`：跨重试保持原身份的已确认操作。
    /// - `body`：当前固定RPC的类型化消息。
    ///
    /// 返回：带固定协议、实例域、期限和可选HMAC-SHA1认证的请求，不回显秘密。
    fn request<T>(&self, event: &Event, body: T) -> Result<tonic::Request<T>> {
        let mut request = tonic::Request::new(body);
        request.set_timeout(self.spec.timeout);
        let instance = event
            .event_id
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("ACL RocketMQ event identity unavailable"))?
            .0;
        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut values = vec![
            ("x-mq-client-id", format!("naway-acl-{instance}")),
            ("x-mq-request-id", event.event_id.clone()),
            ("x-mq-date-time", date.clone()),
            ("x-mq-language", "RUST".to_owned()),
            ("x-mq-protocol", "v2".to_owned()),
            ("x-mq-client-version", env!("CARGO_PKG_VERSION").to_owned()),
            ("x-mq-namespace", self.spec.topic.namespace.clone()),
        ];
        if let (Some(access), Some(secret)) = (&self.spec.access_key, &self.spec.secret_key) {
            let mut signature = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes())
                .map_err(|_| anyhow::anyhow!("ACL RocketMQ signature unavailable"))?;
            signature.update(date.as_bytes());
            values.push((
                "authorization",
                format!(
                    "MQv2-HMAC-SHA1 Credential={}, SignedHeaders=x-mq-date-time, Signature={:X}",
                    access.as_str(),
                    signature.finalize().into_bytes()
                ),
            ));
        }
        for (name, value) in values {
            request.metadata_mut().insert(
                name,
                value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid ACL RocketMQ metadata"))?,
            );
        }
        Ok(request)
    }

    /// 业务作用：执行一次有界类型化RPC，响应中的未知字段不改变固定目的地或消息权限。
    ///
    /// 参数说明：
    /// - `method`：本模块固定的QueryRoute或SendMessage路径。
    /// - `event`：实际操作身份，用于每次请求认证。
    /// - `body`：该固定方法的类型化消息。
    ///
    /// 返回：最大64KiB的完整RPC响应；连接、协议或大小错误统一拒绝，不读取远端错误正文给管理端。
    async fn rpc<Q, R>(&self, method: &'static str, event: &Event, body: Q) -> Result<R>
    where
        Q: prost::Message + Default + Send + Sync + 'static,
        R: prost::Message + Default + Send + Sync + 'static,
    {
        let channel = self
            .channel
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ACL RocketMQ channel retired"))?
            .clone();
        let mut grpc = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(64 * 1024)
            .max_encoding_message_size(8192);
        grpc.ready()
            .await
            .map_err(|_| anyhow::anyhow!("ACL RocketMQ channel unavailable"))?;
        grpc.unary(
            self.request(event, body)?,
            http::uri::PathAndQuery::from_static(method),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|_| anyhow::anyhow!("ACL RocketMQ RPC unavailable"))
    }
}

impl AclNotifier for Rocketmq {
    /// 业务作用：先验证普通消息的可写leader路由，再向原固定Proxy投递单条原通知并复验逐条回执。
    ///
    /// 参数说明：
    /// - `event`：已经确认写入事实的原事件。
    /// - `body`：所有尝试保持不变的完整JSON。
    ///
    /// 返回：总状态与唯一消息回执均为OK才确认；路由不足、类型不符和部分失败不软放行。
    fn send<'a>(&'a mut self, event: &'a Event, body: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let routes: wire::QueryRouteResponse = self
                .rpc(
                    "/apache.rocketmq.v2.MessagingService/QueryRoute",
                    event,
                    wire::QueryRouteRequest {
                        topic: Some(self.spec.topic.clone()),
                        endpoints: Some(self.spec.access_point.clone()),
                    },
                )
                .await?;
            ensure!(
                ok(&routes.status) && routes.queues.len() <= 1024,
                "ACL RocketMQ route unavailable"
            );
            let queue = routes
                .queues
                .iter()
                .find(|queue| {
                    queue.topic.as_ref() == Some(&self.spec.topic)
                        && queue.id >= 0
                        && matches!(queue.permission, 3 | 4)
                        && queue.broker.as_ref().is_some_and(|broker| broker.id == 0)
                        && queue.accepted_types.contains(&1)
                })
                .ok_or_else(|| anyhow::anyhow!("ACL RocketMQ normal write route unavailable"))?;
            let hash = Sha256::digest(event.event_id.as_bytes());
            let message_id = format!(
                "01{:032X}",
                u128::from_be_bytes(hash[..16].try_into().expect("fixed message digest"))
            );
            let now = super::receiver::now_ms()?;
            // 路由仅证明原主题可写，返回的其它broker地址绝不取得新增外连权力。
            let response: wire::SendMessageResponse = self
                .rpc(
                    "/apache.rocketmq.v2.MessagingService/SendMessage",
                    event,
                    wire::SendMessageRequest {
                        messages: vec![wire::Message {
                            topic: Some(self.spec.topic.clone()),
                            properties: std::collections::BTreeMap::from([(
                                "event_id".to_owned(),
                                event.event_id.clone(),
                            )]),
                            system: Some(wire::SystemProperties {
                                keys: vec![event.event_id.clone()],
                                message_id,
                                body_encoding: 1,
                                message_type: 1,
                                born_timestamp: Some(prost_types::Timestamp {
                                    seconds: (now / 1000) as i64,
                                    nanos: ((now % 1000) * 1_000_000) as i32,
                                }),
                                born_host: "naway".to_owned(),
                                queue_id: queue.id,
                            }),
                            body: body.to_vec(),
                        }],
                    },
                )
                .await?;
            ensure!(
                ok(&response.status)
                    && response.results.len() == 1
                    && response.results.iter().all(|result| ok(&result.status)
                        && !result.message_id.is_empty()
                        && result.offset >= 0),
                "ACL RocketMQ delivery was not acknowledged"
            );
            Ok(())
        })
    }

    /// 业务作用：释放唯一当前Proxy通道，不保留旧配置的客户端句柄或长期遥测订阅。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：撤下全部发送句柄；传输层已收到的请求仍可能完成，不自动重放原封禁。
    fn shutdown(&mut self) -> BoxFuture<'_, Result<()>> {
        self.channel.take();
        Box::pin(std::future::ready(Ok(())))
    }
}

/// 业务作用：只接受明确OK状态，缺失状态不能当作默认成功。
///
/// 参数说明：
/// - `status`：原RPC或逐条消息返回的状态。
///
/// 返回：协议OK为真；其它状态包括部分成功或未知均为假。
fn ok(status: &Option<wire::Status>) -> bool {
    status.as_ref().is_some_and(|status| status.code == 20_000)
}

/// 业务作用：由唯一worker创建惰性Proxy通道，不在候选编译期拨号或创建MQ后台会话。
///
/// 参数说明：
/// - `spec`：冻结的固定Proxy、主题和材料。
///
/// 返回：单通道普通消息适配器，连接只在实际RPC时建立。
pub(super) fn build(spec: Arc<Spec>) -> Box<dyn AclNotifier> {
    Box::new(Rocketmq {
        channel: Some(spec.endpoint.connect_lazy()),
        spec,
    })
}
