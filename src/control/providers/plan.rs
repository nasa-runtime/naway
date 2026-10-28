//! 固定来源能力与传输信任计划；只在构建阶段读取本地凭据，数据面不持有读源客户端。

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::compile::{validate_origin, Policy};
use super::model::{identifier, Authority, Kind, Reference, MAX_SOURCES, MAX_SOURCE_BYTES};
use crate::config::model::GatewayConfig;
use crate::config::providers::{HttpSecurityCfg, ScopeCfg, SourceCfg, TransportCfg};
use crate::control::ownership::{Owner, PLATFORM};

pub(super) struct Plan {
    pub signature: [u8; 32],
    pub incarnation: u64,
    pub sources: BTreeMap<String, Source>,
    pub policies: BTreeMap<String, Policy>,
}

pub(super) struct Source {
    pub authority: Authority,
    pub config: SourceCfg,
    pub transport: Transport,
    pub health: parking_lot::Mutex<super::metrics::Health>,
}

pub(super) enum Transport {
    Ecs(Box<super::workload::ecs::Reader>),
    Nomad(super::workload::nomad::Reader),
    Docker(super::workload::docker::Reader),
    Zookeeper(super::zookeeper::Reader),
    Redis(Box<super::redis::Reader>),
    Consul(super::consul::Reader),
    Etcd(super::etcd::Reader),
    Https {
        client: reqwest::Client,
        endpoint: reqwest::Url,
        authorization: Option<http::HeaderValue>,
    },
}

enum PreparedTransport {
    Zookeeper(super::zookeeper::Reader),
    Http(reqwest::Url, Credentials, HttpKind),
    Redis(Box<super::redis::Reader>),
}

enum HttpKind {
    Ecs(Box<super::workload::ecs::Settings>),
    Nomad {
        namespace: String,
        service: String,
        region: String,
        long_poll_ms: u64,
    },
    Docker(crate::config::providers::DockerAddressCfg),
    Https,
    Consul {
        key: String,
        long_poll_ms: u64,
    },
    Etcd {
        key: String,
        cluster_id: u64,
        long_poll_ms: u64,
    },
}

struct Credentials {
    bearer: String,
    ca: String,
    certificate: String,
    key: String,
}

impl Plan {
    /// 业务作用：冻结来源能力、归属和传输信任，秘密轮换改变代际，旧客户端观测不能进入新事实源。
    ///
    /// 参数说明：
    /// - `cfg`：为完整本地声明
    /// - `directory`：为凭据路径根
    /// - `previous`：为上一已发布传输计划。
    ///
    /// 返回：关闭时无计划；启用时返回有限固定目录，相同权威复用旧连接池，错误拒绝整个候选。
    pub(super) fn build(
        cfg: &GatewayConfig,
        directory: &Path,
        previous: Option<&Arc<Self>>,
    ) -> Result<Option<Arc<Self>>> {
        let providers = &cfg.providers;
        if !providers.enabled {
            ensure!(
                providers.sources.is_empty(),
                "disabled providers must not contain sources"
            );
            return Ok(None);
        }
        ensure!(
            cfg.ownership.enabled,
            "configuration providers require ownership"
        );
        ensure!(
            cfg.control_plane.mode == crate::config::model::ControlPlaneModeCfg::Native
                && !cfg.control_plane.xds.enabled,
            "configuration providers require native control-plane ownership"
        );
        ensure!(
            (1..=MAX_SOURCES).contains(&providers.sources.len()),
            "provider source capacity reached"
        );
        let mut hash = Sha256::new();
        feed(&mut hash, &serde_json::to_vec(providers)?);
        let mut resolved = Vec::new();
        let mut ids = BTreeSet::new();
        let mut namespaces = BTreeMap::new();
        for source in &providers.sources {
            ensure!(ids.insert(source.id.clone()), "duplicate provider source");
            ensure!(
                (100..=60000).contains(&source.poll_interval_ms)
                    && (100..=30000).contains(&source.deadline_ms)
                    && (1024..=MAX_SOURCE_BYTES).contains(&source.max_body_bytes)
                    && source.max_stale_ms >= source.poll_interval_ms + source.deadline_ms + 100,
                "invalid provider transport budgets"
            );
            let owner = if source.workspace == PLATFORM {
                Owner {
                    workspace: PLATFORM.into(),
                    tenant: PLATFORM.into(),
                    environment: PLATFORM.into(),
                }
            } else {
                let workspace = cfg
                    .ownership
                    .workspaces
                    .get(&source.workspace)
                    .context("provider workspace missing")?;
                Owner {
                    workspace: source.workspace.clone(),
                    tenant: workspace.tenant.clone(),
                    environment: workspace.environment.clone(),
                }
            };
            let authority = Authority {
                source: source.id.clone(),
                namespace: source.namespace.clone(),
                owner,
                priority: source.priority,
                max_stale: Duration::from_millis(source.max_stale_ms),
            };
            authority.validate()?;
            if let Some(previous_owner) =
                namespaces.insert(authority.namespace.clone(), authority.owner.clone())
            {
                ensure!(
                    previous_owner == authority.owner,
                    "provider namespace owner conflict"
                );
            }
            feed(&mut hash, &serde_json::to_vec(&authority.owner)?);
            let policy = policy(&source.scope)?;
            let transport = match &source.transport {
                TransportCfg::Zookeeper {
                    endpoint,
                    path,
                    long_poll_ms,
                    security,
                } => {
                    let credentials = [
                        secret(&security.digest_auth, directory)?,
                        secret(&security.ca_certificate, directory)?,
                        secret(&security.client_certificate, directory)?,
                        secret(&security.client_private_key, directory)?,
                    ];
                    for value in &credentials {
                        feed(&mut hash, value.as_bytes());
                    }
                    PreparedTransport::Zookeeper(super::zookeeper::Reader::build(
                        endpoint,
                        path,
                        *long_poll_ms,
                        source.deadline_ms,
                        security.allow_loopback_plaintext,
                        credentials,
                    )?)
                }
                TransportCfg::Https {
                    endpoint,
                    security,
                }
                | TransportCfg::ConsulKv {
                    endpoint,
                    security,
                    ..
                }
                | TransportCfg::Etcd {
                    endpoint,
                    security,
                    ..
                }
                | TransportCfg::Docker {
                    endpoint,
                    security,
                    ..
                }
                | TransportCfg::Nomad {
                    endpoint,
                    security,
                    ..
                }
                | TransportCfg::Ecs {
                    endpoint,
                    security,
                    ..
                } => {
                    let endpoint = endpoint_url(endpoint, security.allow_loopback_http)?;
                    let kind = match &source.transport {
                        TransportCfg::Ecs {
                            region,
                            cluster_arn,
                            service,
                            container,
                            credentials,
                            ..
                        } => {
                            // ECS 只使用 SigV4，不能把另一种令牌混入固定 AWS 权威。
                            ensure!(
                                security.bearer_token.is_empty(),
                                "ECS requires SigV4 credentials only"
                            );
                            let access_key_id = secret(&credentials.access_key_id, directory)?;
                            let secret_access_key =
                                secret(&credentials.secret_access_key, directory)?;
                            let session_token = secret(&credentials.session_token, directory)?;
                            for value in [&access_key_id, &secret_access_key, &session_token] {
                                feed(&mut hash, value.as_bytes());
                            }
                            HttpKind::Ecs(Box::new(super::workload::ecs::Settings {
                                region: region.clone(),
                                cluster_arn: cluster_arn.clone(),
                                service: service.clone(),
                                container: container.clone(),
                                access_key_id,
                                secret_access_key,
                                session_token,
                            }))
                        }
                        TransportCfg::Nomad {
                            namespace,
                            service,
                            region,
                            long_poll_ms,
                            ..
                        } => HttpKind::Nomad {
                            namespace: namespace.clone(),
                            service: service.clone(),
                            region: region.clone(),
                            long_poll_ms: *long_poll_ms,
                        },
                        TransportCfg::Docker {
                            address,
                            ..
                        } => HttpKind::Docker(address.clone()),
                        TransportCfg::Etcd {
                            key,
                            cluster_id,
                            long_poll_ms,
                            ..
                        } => {
                            let cluster_id = super::etcd::validate(
                                &endpoint,
                                key,
                                cluster_id,
                                *long_poll_ms,
                                source.deadline_ms,
                            )?;
                            HttpKind::Etcd {
                                key: key.clone(),
                                cluster_id,
                                long_poll_ms: *long_poll_ms,
                            }
                        }
                        TransportCfg::ConsulKv {
                            key,
                            long_poll_ms,
                            ..
                        } => {
                            super::consul::validate(
                                &endpoint,
                                key,
                                *long_poll_ms,
                                source.deadline_ms,
                            )?;
                            HttpKind::Consul {
                                key: key.clone(),
                                long_poll_ms: *long_poll_ms,
                            }
                        }
                        _ => HttpKind::Https,
                    };
                    let credentials = Credentials {
                        bearer: secret(&security.bearer_token, directory)?,
                        ca: secret(&security.ca_certificate, directory)?,
                        certificate: secret(&security.client_certificate, directory)?,
                        key: secret(&security.client_private_key, directory)?,
                    };
                    for value in [
                        &credentials.bearer,
                        &credentials.ca,
                        &credentials.certificate,
                        &credentials.key,
                    ] {
                        feed(&mut hash, value.as_bytes());
                    }
                    PreparedTransport::Http(endpoint, credentials, kind)
                }
                TransportCfg::Redis {
                    endpoint,
                    key,
                    protocol_namespace,
                    security,
                } => {
                    let password = secret(&security.password, directory)?;
                    feed(&mut hash, password.as_bytes());
                    PreparedTransport::Redis(Box::new(super::redis::Reader::build(
                        endpoint,
                        key,
                        protocol_namespace,
                        security,
                        password,
                        source.deadline_ms,
                    )?))
                }
            };
            resolved.push((source, authority, policy, transport));
        }
        let signature: [u8; 32] = hash.finalize().into();
        if let Some(previous) = previous.filter(|plan| plan.signature == signature) {
            return Ok(Some((*previous).clone()));
        }
        let mut sources = BTreeMap::new();
        let mut policies = BTreeMap::new();
        for (config, authority, policy, prepared) in resolved {
            let transport = match prepared {
                PreparedTransport::Zookeeper(reader) => Transport::Zookeeper(reader),
                PreparedTransport::Redis(reader) => Transport::Redis(reader),
                PreparedTransport::Http(endpoint, credentials, kind) => {
                    let mut client = reqwest::Client::builder()
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::none())
                        .no_gzip()
                        .no_brotli()
                        .no_deflate()
                        .no_zstd()
                        .connect_timeout(Duration::from_millis(config.deadline_ms))
                        .timeout(Duration::from_millis(config.deadline_ms))
                        .pool_max_idle_per_host(1);
                    if !credentials.ca.is_empty() {
                        client = client.add_root_certificate(
                            crate::tls::trust::http_ca(credentials.ca.as_bytes())
                                .context("invalid provider CA")?,
                        );
                    }
                    ensure!(
                        credentials.certificate.is_empty() == credentials.key.is_empty(),
                        "provider client certificate and private key must be paired"
                    );
                    if !credentials.certificate.is_empty() {
                        client = client.identity(
                            reqwest::Identity::from_pem(
                                format!("{}\n{}", credentials.certificate, credentials.key)
                                    .as_bytes(),
                            )
                            .context("invalid provider client identity")?,
                        );
                    }
                    let authorization = if credentials.bearer.is_empty() {
                        None
                    } else {
                        ensure!(
                            credentials.bearer.len() <= 4096
                                && !credentials.bearer.chars().any(char::is_whitespace),
                            "invalid provider bearer token"
                        );
                        let value = match kind {
                            HttpKind::Https | HttpKind::Docker(_) => {
                                format!("Bearer {}", credentials.bearer)
                            }
                            HttpKind::Consul {
                                ..
                            }
                            | HttpKind::Etcd {
                                ..
                            }
                            | HttpKind::Nomad {
                                ..
                            } => credentials.bearer,
                            HttpKind::Ecs(_) => anyhow::bail!("ECS bearer authentication rejected"),
                        };
                        let mut header = http::HeaderValue::from_str(&value)
                            .context("invalid provider authentication token")?;
                        header.set_sensitive(true);
                        Some(header)
                    };
                    let client = client
                        .build()
                        .context("provider HTTP client build failed")?;
                    match kind {
                        HttpKind::Ecs(settings) => Transport::Ecs(Box::new(
                            super::workload::ecs::Reader::new(client, endpoint, *settings)?,
                        )),
                        HttpKind::Nomad {
                            namespace,
                            service,
                            region,
                            long_poll_ms,
                        } => Transport::Nomad(super::workload::nomad::Reader::new(
                            client,
                            endpoint,
                            authorization,
                            super::workload::nomad::Scope {
                                namespace,
                                service,
                                region,
                            },
                            long_poll_ms,
                            config.deadline_ms,
                        )?),
                        HttpKind::Docker(address) => {
                            Transport::Docker(super::workload::docker::Reader::new(
                                client,
                                endpoint,
                                authorization,
                                address,
                            )?)
                        }
                        HttpKind::Etcd {
                            key,
                            cluster_id,
                            long_poll_ms,
                        } => Transport::Etcd(super::etcd::Reader::new(
                            client,
                            endpoint,
                            authorization,
                            key,
                            cluster_id,
                            long_poll_ms,
                        )?),
                        HttpKind::Https => Transport::Https {
                            client,
                            endpoint,
                            authorization,
                        },
                        HttpKind::Consul {
                            key,
                            long_poll_ms,
                        } => Transport::Consul(super::consul::Reader::new(
                            client,
                            endpoint,
                            authorization,
                            key,
                            long_poll_ms,
                        )?),
                    }
                }
            };
            policies.insert(config.id.clone(), policy);
            sources.insert(
                config.id.clone(),
                Source {
                    authority,
                    config: config.clone(),
                    transport,
                    health: Default::default(),
                },
            );
        }
        Ok(Some(Arc::new(Self {
            signature,
            incarnation: next_incarnation()?,
            sources,
            policies,
        })))
    }
}

/// 业务作用：为每次重新建立的来源权威分配进程内不可复用身份，阻止配置撤销后恢复造成旧观测复活。
///
/// 参数说明: 无。
///
/// 返回：单调唯一身份；序号耗尽时拒绝新计划，不回绕为旧代。
fn next_incarnation() -> Result<u64> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    })
    .map_err(|_| anyhow::anyhow!("provider incarnation space exhausted"))
}

/// 业务作用：把有限本地能力转换成精确集合；重复项与模糊名称不能在后续合并时改变含义。
///
/// 参数说明：
/// - `scope`：是来源允许使用的监听、后端、模板与跨 namespace 引用范围。
///
/// 返回：强类型权限计划；超限、缺省端口、非法标识或未知对象种类拒绝。
fn policy(scope: &ScopeCfg) -> Result<Policy> {
    ensure!(
        scope.listeners.len() <= 64
            && scope.backend_origins.len() <= 256
            && scope.backend_networks.len() <= 32
            && scope.templates.len() <= 128
            && scope.references.len() <= 1024,
        "provider capability budget reached"
    );
    let mut policy = Policy {
        listeners: BTreeSet::new(),
        origins: BTreeSet::new(),
        networks: Vec::new(),
        templates: BTreeSet::new(),
        references: BTreeSet::new(),
    };
    for raw in &scope.listeners {
        let address: SocketAddr = raw.parse().context("invalid provider listen capability")?;
        ensure!(
            address.port() != 0 && policy.listeners.insert(address),
            "invalid or duplicate provider listen capability"
        );
    }
    for raw in &scope.backend_origins {
        let uri = reqwest::Url::parse(raw).context("invalid provider backend capability")?;
        let origin = uri.origin().ascii_serialization();
        ensure!(
            policy.origins.insert(origin),
            "duplicate provider backend capability"
        );
        validate_origin(raw, &policy)?;
    }
    for network in &scope.backend_networks {
        ensure!(
            !network.ports.is_empty() && network.ports.len() <= 64 && !network.ports.contains(&0),
            "provider backend port capability invalid"
        );
        let ports: BTreeSet<_> = network.ports.iter().copied().collect();
        ensure!(
            ports.len() == network.ports.len(),
            "duplicate provider backend port"
        );
        policy
            .networks
            .push((crate::io::net::Cidr::parse(&network.cidr)?, ports));
    }
    for name in &scope.templates {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                && policy.templates.insert(name.clone()),
            "invalid or duplicate provider template capability"
        );
    }
    for reference in &scope.references {
        ensure!(
            identifier(&reference.namespace) && identifier(&reference.name),
            "invalid provider reference capability"
        );
        let kind = match reference.kind.as_str() {
            "listener" => Kind::Listener,
            "service" => Kind::Service,
            "middleware" => Kind::Middleware,
            _ => anyhow::bail!("unsupported provider reference capability"),
        };
        ensure!(
            policy.references.insert(Reference {
                namespace: reference.namespace.clone(),
                kind,
                name: reference.name.clone()
            }),
            "duplicate provider reference capability"
        );
    }
    Ok(policy)
}

/// 业务作用：限制配置事实源的传输权威，禁止凭据 URL、自动跳转与公网明文配置注入。
///
/// 参数说明：
/// - `raw`：是固定 endpoint
/// - `allow_loopback_http`：只授权 IP loopback 的本机明文入口。
///
/// 返回：严格 HTTP(S) 地址；公网页面必须使用受信 HTTPS，query 和 fragment 一律拒绝。
fn endpoint_url(raw: &str, allow_loopback_http: bool) -> Result<reqwest::Url> {
    ensure!(
        raw.len() <= 2048
            && !raw.contains(['\\', '$', '?', '#'])
            && !raw.chars().any(char::is_control),
        "invalid provider endpoint"
    );
    let url = reqwest::Url::parse(raw).context("invalid provider endpoint")?;
    ensure!(
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid provider endpoint authority"
    );
    let loopback = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && allow_loopback_http && loopback),
        "provider endpoint requires HTTPS"
    );
    Ok(url)
}

/// 业务作用：仅解析固定本地 SecretSource，来源配置不能包含明文凭据或请求另一远程秘密服务。
///
/// 参数说明：
/// - `reference`：是空值或环境/挂载文件引用
/// - `directory`：为本地路径基准。
///
/// 返回：有界秘密文本；不输出引用或秘密内容，错误拒绝计划。
fn secret(reference: &str, directory: &Path) -> Result<String> {
    if reference.is_empty() {
        return Ok(String::new());
    }
    ensure!(
        ["env://", "file://", "k8s-file://", "vault-agent://"]
            .iter()
            .any(|prefix| reference.starts_with(prefix)),
        "provider credentials require a local SecretSource"
    );
    crate::security::secret::resolve_text(reference, directory, "configuration provider credential")
        .map_err(|_| anyhow::anyhow!("configuration provider credential unavailable"))
}

/// 业务作用：对配置与秘密材料进行无拼接歧义的身份绑定，不把材料本身写入公开状态。
///
/// 参数说明：
/// - `hash`：是当前计划摘要
/// - `bytes`：是一个完整字段。
///
/// 返回：摘要状态追加长度和内容，不执行外部副作用。
fn feed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// 业务作用：列出来源传输依赖的本地秘密文件，保证轮换同时进入指纹与精确 watcher。
///
/// 参数说明：
/// - `cfg`：是本地来源声明
/// - `directory`：为配置根。
///
/// 返回：有限文件路径；环境变量不生成虚构路径，关闭时没有额外观察目标。
pub(crate) fn dependency_paths(
    cfg: &crate::config::providers::ProvidersCfg,
    directory: &Path,
) -> Vec<std::path::PathBuf> {
    if !cfg.enabled {
        return Vec::new();
    }
    cfg.sources
        .iter()
        .flat_map(|source| {
            let values: Vec<&String> = match &source.transport {
                TransportCfg::Ecs {
                    credentials,
                    security,
                    ..
                } => vec![
                    &credentials.access_key_id,
                    &credentials.secret_access_key,
                    &credentials.session_token,
                    &security.ca_certificate,
                    &security.client_certificate,
                    &security.client_private_key,
                ],
                TransportCfg::Zookeeper {
                    security,
                    ..
                } => vec![
                    &security.digest_auth,
                    &security.ca_certificate,
                    &security.client_certificate,
                    &security.client_private_key,
                ],
                TransportCfg::Redis {
                    security,
                    ..
                } => vec![&security.password],
                TransportCfg::Https {
                    security:
                        HttpSecurityCfg {
                            bearer_token,
                            ca_certificate,
                            client_certificate,
                            client_private_key,
                            ..
                        },
                    ..
                }
                | TransportCfg::Docker {
                    security:
                        HttpSecurityCfg {
                            bearer_token,
                            ca_certificate,
                            client_certificate,
                            client_private_key,
                            ..
                        },
                    ..
                }
                | TransportCfg::Nomad {
                    security:
                        HttpSecurityCfg {
                            bearer_token,
                            ca_certificate,
                            client_certificate,
                            client_private_key,
                            ..
                        },
                    ..
                }
                | TransportCfg::ConsulKv {
                    security:
                        HttpSecurityCfg {
                            bearer_token,
                            ca_certificate,
                            client_certificate,
                            client_private_key,
                            ..
                        },
                    ..
                }
                | TransportCfg::Etcd {
                    security:
                        HttpSecurityCfg {
                            bearer_token,
                            ca_certificate,
                            client_certificate,
                            client_private_key,
                            ..
                        },
                    ..
                } => vec![
                    bearer_token,
                    ca_certificate,
                    client_certificate,
                    client_private_key,
                ],
            };
            values
                .into_iter()
                .filter_map(|value| crate::security::secret::dependency_path(value, directory))
        })
        .collect()
}
