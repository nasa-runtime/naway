//! Docker Engine 只读完整容器目录；不持有 Unix socket、不执行容器检查或任何写操作。

use super::super::model::Declaration;
use super::{project, response, rule, Instance, State};
use crate::config::providers::DockerAddressCfg;
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

pub(crate) struct Reader {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    authorization: Option<http::HeaderValue>,
    address: DockerAddressCfg,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Container {
    id: String,
    state: String,
    labels: BTreeMap<String, String>,
    #[serde(default)]
    ports: Vec<Port>,
    #[serde(default)]
    network_settings: Networks,
}
#[derive(Deserialize)]
struct Port {
    #[serde(rename = "IP", default)]
    ip: String,
    #[serde(rename = "PrivatePort")]
    private: u16,
    #[serde(rename = "PublicPort", default)]
    public: u16,
    #[serde(rename = "Type")]
    kind: String,
}
#[derive(Deserialize, Default)]
struct Networks {
    #[serde(rename = "Networks", default)]
    networks: BTreeMap<String, Network>,
}
#[derive(Deserialize)]
struct Network {
    #[serde(rename = "IPAddress", default)]
    address: String,
}

impl Reader {
    /// 业务作用：固定 Engine API 目录与网络寻址策略，不授予读取者任意 Docker 操作能力。
    ///
    /// 参数说明：
    /// - `client`：是本地传输信任
    /// - `endpoint`：是本地传输信任
    /// - `authorization`：是本地传输信任
    /// - `address`：明确指定容器网络或已发布端口。
    ///
    /// 返回：只请求固定容器列表的读取者；无自动 API 降级、无宿主 socket 或隐式网络选择。
    pub(in crate::control::providers) fn new(
        client: reqwest::Client,
        mut endpoint: reqwest::Url,
        authorization: Option<http::HeaderValue>,
        address: DockerAddressCfg,
    ) -> Result<Self> {
        ensure!(endpoint.path() == "/", "Docker endpoint must be an origin");
        if let DockerAddressCfg::Network {
            name,
        } = &address
        {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
                "invalid Docker network"
            );
        }
        endpoint.set_path("/v1.51/containers/json");
        endpoint
            .query_pairs_mut()
            .append_pair("all", "false")
            .append_pair(
                "filters",
                r#"{"label":["naway.enable=true"],"status":["running"]}"#,
            );
        Ok(Self {
            client,
            endpoint,
            authorization,
            address,
        })
    }

    /// 业务作用：完整重读显式开启且运行中的容器，失败不将部分目录解释成删除。
    ///
    /// 参数说明：
    /// - `namespace`：是同代已发布投影
    /// - `previous`：是同代已发布投影
    /// - `document`：是同代已发布投影
    /// - `maximum`：为本轮总响应预算。
    ///
    /// 返回：受限 IR 与候选标签水位；未知地址、歧义绑定、旧策略版本或超限整轮拒绝。
    pub(in crate::control::providers) async fn read(
        &self,
        namespace: &str,
        previous: &State,
        document: Option<&Declaration>,
        maximum: usize,
    ) -> Result<(Declaration, State)> {
        let mut request = self
            .client
            .get(self.endpoint.clone())
            .header(http::header::ACCEPT_ENCODING, "identity");
        if let Some(authorization) = &self.authorization {
            request = request.header(http::header::AUTHORIZATION, authorization.clone());
        }
        let (containers, _): (Vec<Container>, _) = response(request, &mut {
            maximum
        }).await?;
        ensure!(
            containers.len() <= 4096,
            "Docker container capacity reached"
        );
        let mut ids = BTreeSet::new();
        let mut instances = Vec::new();
        for container in containers {
            ensure!(
                container.id.len() == 64
                    && container.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && ids.insert(container.id),
                "invalid or duplicate Docker container identity"
            );
            if container.state != "running" {
                continue;
            }
            let Some(rule) = rule(&container.labels)? else {
                continue;
            };
            ensure!(
                container.ports.len() <= 64 && container.network_settings.networks.len() <= 32,
                "Docker networking capacity reached"
            );
            let address = match &self.address {
                DockerAddressCfg::Network {
                    name,
                } => {
                    let address = container
                        .network_settings
                        .networks
                        .get(name)
                        .context("Docker container network missing")?
                        .address
                        .parse::<IpAddr>()
                        .context("invalid Docker container address")?;
                    SocketAddr::new(address, rule.port)
                }
                DockerAddressCfg::Published => {
                    let mut matching = container.ports.iter().filter(|port| {
                        port.private == rule.port && port.kind == "tcp" && port.public > 0
                    });
                    let port = matching.next().context("Docker published port missing")?;
                    ensure!(matching.next().is_none(), "ambiguous Docker published port");
                    SocketAddr::new(
                        port.ip
                            .parse::<IpAddr>()
                            .context("Docker published IP must be explicit")?,
                        port.public,
                    )
                }
            };
            // 未指定地址不是可拨号身份；后续完整编译还必须通过本地 backend origin/CIDR 与端口能力。
            ensure!(
                !address.ip().is_unspecified() && !address.ip().is_multicast(),
                "Docker destination address rejected"
            );
            instances.push(Instance {
                rule,
                address,
            });
            ensure!(
                instances.len() <= 1024,
                "Docker enabled workload capacity reached"
            );
        }
        project(namespace, instances, previous, document)
    }
}
