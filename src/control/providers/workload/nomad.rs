//! Nomad 固定命名空间与服务注册目录；完整一致读取才能确认路由，分页或索引倒退不刷新权威。

use super::super::model::{identifier, Declaration};
use super::{project, response, rule, Instance, State};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

pub(crate) struct Reader {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    authorization: Option<http::HeaderValue>,
    namespace: String,
    service: String,
    long_poll_ms: u64,
}

pub(in crate::control::providers) struct Scope {
    pub namespace: String,
    pub service: String,
    pub region: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Registration {
    #[serde(rename = "ID")]
    id: String,
    namespace: String,
    service_name: String,
    #[serde(default)]
    tags: Option<Vec<String>>,
    address: String,
    port: u16,
    create_index: u64,
    modify_index: u64,
}

impl Reader {
    /// 业务作用：固定单个服务的 namespace/region 与有界阻塞查询，不读取或暴露整个集群。
    ///
    /// 参数说明：
    /// - `client`：是本地传输权威
    /// - `endpoint`：是本地传输权威
    /// - `authorization`：是本地传输权威
    /// - `scope`：为固定 namespace/service/region
    /// - `long_poll_ms`：约束等待。
    /// - `deadline_ms`：约束等待。
    ///
    /// 返回：只读服务目录客户端；模糊范围、路径或不足的超时余量拒绝。
    pub(in crate::control::providers) fn new(
        client: reqwest::Client,
        mut endpoint: reqwest::Url,
        authorization: Option<http::HeaderValue>,
        scope: Scope,
        long_poll_ms: u64,
        deadline_ms: u64,
    ) -> Result<Self> {
        let Scope {
            namespace,
            service,
            region,
        } = scope;
        ensure!(
            endpoint.path() == "/"
                && identifier(&namespace)
                && identifier(&service)
                && identifier(&region),
            "invalid Nomad service scope"
        );
        ensure!(
            (100..=20000).contains(&long_poll_ms)
                && long_poll_ms + long_poll_ms / 16 + 100 <= deadline_ms,
            "invalid Nomad blocking query budget"
        );
        endpoint.set_path(&format!("/v1/service/{service}"));
        endpoint
            .query_pairs_mut()
            .append_pair("namespace", &namespace)
            .append_pair("region", &region)
            .append_pair("consistent", "true");
        Ok(Self {
            client,
            endpoint,
            authorization,
            namespace,
            service,
            long_poll_ms,
        })
    }

    /// 业务作用：取得完整服务注册集合并验证本地范围、索引与标签，再进入来源中立投影。
    ///
    /// 参数说明：
    /// - `namespace`：是网关 namespace
    /// - `previous`：为上次已发布证据
    /// - `document`：为上次已发布证据
    /// - `maximum`：为全轮正文预算。
    ///
    /// 返回：完整 IR 与待提交索引/标签水位；部分页、同版异文、回退、越域或超限整轮拒绝。
    pub(in crate::control::providers) async fn read(
        &self,
        namespace: &str,
        previous: &State,
        document: Option<&Declaration>,
        maximum: usize,
    ) -> Result<(Declaration, State)> {
        let mut endpoint = self.endpoint.clone();
        if previous.native_index > 0 {
            endpoint
                .query_pairs_mut()
                .append_pair("index", &previous.native_index.to_string())
                .append_pair("wait", &format!("{}ms", self.long_poll_ms));
        }
        let mut request = self
            .client
            .get(endpoint)
            .header(http::header::ACCEPT_ENCODING, "identity");
        if let Some(authorization) = &self.authorization {
            request = request.header("x-nomad-token", authorization.clone());
        }
        let (mut registrations, headers): (Vec<Registration>, _) =
            response(request, &mut {
                maximum
            }).await?;
        let index = headers
            .get("x-nomad-index")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
            .context("Nomad index missing or invalid")?;
        ensure!(
            index > 0 && index >= previous.native_index,
            "Nomad service index regressed"
        );
        // 请求不启用分页；出现续页令牌就没有完整删除证据，不能把这一页当成全目录。
        ensure!(
            headers
                .get("x-nomad-nexttoken")
                .is_none_or(|value| value.is_empty()),
            "partial Nomad service directory rejected"
        );
        ensure!(
            registrations.len() <= 4096,
            "Nomad registration capacity reached"
        );
        registrations.sort_by(|left, right| left.id.cmp(&right.id));
        for registration in &mut registrations {
            registration.tags.get_or_insert_with(Vec::new).sort();
        }
        let mut ids = BTreeSet::new();
        let mut instances = Vec::new();
        for registration in &registrations {
            ensure!(
                !registration.id.is_empty()
                    && registration.id.len() <= 512
                    && !registration.id.chars().any(char::is_control)
                    && ids.insert(&registration.id),
                "invalid or duplicate Nomad registration identity"
            );
            ensure!(
                registration.namespace == self.namespace
                    && registration.service_name == self.service,
                "Nomad registration outside authorized scope"
            );
            ensure!(
                registration.create_index > 0
                    && registration.create_index <= registration.modify_index
                    && registration.modify_index <= index,
                "invalid Nomad registration index"
            );
            let tags = registration.tags.as_deref().unwrap_or_default();
            ensure!(tags.len() <= 128, "Nomad tag capacity reached");
            let mut labels = BTreeMap::new();
            for tag in tags {
                ensure!(tag.len() <= 4096, "Nomad tag byte budget reached");
                if tag.starts_with("naway.") {
                    let (key, value) = tag
                        .split_once('=')
                        .context("invalid Nomad configuration tag")?;
                    ensure!(
                        labels.insert(key.to_owned(), value.to_owned()).is_none(),
                        "duplicate Nomad configuration tag"
                    );
                }
            }
            if let Some(rule) = rule(&labels)? {
                let address = registration
                    .address
                    .parse::<IpAddr>()
                    .context("Nomad service IP must be explicit")?;
                ensure!(
                    registration.port > 0
                        && rule.port == registration.port
                        && !address.is_unspecified()
                        && !address.is_multicast(),
                    "Nomad registration address or declared port rejected"
                );
                instances.push(Instance {
                    rule,
                    address: SocketAddr::new(address, registration.port),
                });
                ensure!(
                    instances.len() <= 1024,
                    "Nomad enabled workload capacity reached"
                );
            }
        }
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&registrations)?).into();
        // 索引来自服务端已提交目录；同索引内容变化和恢复旧备份必须显式更换本地来源权威。
        ensure!(
            index != previous.native_index || digest == previous.native_digest,
            "Nomad service index content conflict"
        );
        let (document, mut state) = project(namespace, instances, previous, document)?;
        state.native_index = index;
        state.native_digest = digest;
        Ok((document, state))
    }
}
