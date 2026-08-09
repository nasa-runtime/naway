//! CDS/RDS 选择性 protobuf surface、严格字段白名单与依赖 warming 状态机。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use prost::Message;
use prost_types::{Any, Duration as ProtoDuration};

use crate::config::model::{UpstreamsCfg, VariablesCfg, XdsLimitsCfg, XdsResourceOwnerCfg};
use crate::config::{
    GatewaySnapshot, Http3RuntimeCfg, InMemoryTlsMaterial, ProxyProtocolRuntimeCfg, ProxyRuntime,
    TlsRuntimeCfg,
};
use crate::routing::Router;
use crate::upstream::{DynamicUpstreamStore, UpstreamDirectory, UpstreamInstance};
use crate::variable::VariablePlan;

pub(crate) const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub(crate) const RDS_TYPE_URL: &str =
    "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub(crate) const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
pub(crate) const SDS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
const HTTP_PROTOCOL_OPTIONS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions";
const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_FILTER_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";
const DOWNSTREAM_TLS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";

/// xDS resource 超过 bootstrap 硬预算；transport 据此返回 RESOURCE_EXHAUSTED NACK。
#[derive(Debug)]
pub(crate) struct XdsResourceExhausted(pub(crate) &'static str);

impl std::fmt::Display for XdsResourceExhausted {
    /// 业务作用：向 NACK 输出固定低敏预算错误，避免回显 resource 内容或高基数名称。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：写入固定错误摘要的格式化结果。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for XdsResourceExhausted {}

/// CDS 到 Naway 上游协议的精确映射。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XdsUpstreamProtocol {
    /// HTTP/1.1 明文上游。
    H1,
    /// HTTP/2 prior-knowledge 明文上游。
    H2c,
}

/// CDS 到 Naway 负载均衡算法的精确映射。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XdsLbPolicy {
    /// 平滑加权轮询。
    RoundRobin,
    /// 最少在途连接。
    LeastRequest,
}

/// 已完成 CDS 白名单校验的 native cluster 计划。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XdsClusterPlan {
    /// CDS resource 名，同时是 native logical service 名。
    pub name: String,
    /// EDS 订阅名；缺省等于 cluster name。
    pub eds_service_name: String,
    /// 上游 HTTP 协议。
    pub protocol: XdsUpstreamProtocol,
    /// 上游 LB 算法。
    pub lb_policy: XdsLbPolicy,
    /// TCP connect timeout 毫秒值。
    pub connect_timeout_ms: u64,
}

/// 一条已转换但尚未编译成 Router 的 native route 声明。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XdsRoutePlan {
    /// 稳定 route id；必要时含 virtual-host/domain/weight 后缀。
    pub id: String,
    /// `lb://cluster` 或仅用于 direct response 的不可达占位 URI。
    pub uri: String,
    /// 复用 Naway 原生 predicate DSL，后续必须再经过 Router 完整校验。
    pub predicates: Vec<String>,
    /// 复用 Naway 原生 filter DSL，当前只用于 fixed return/redirect。
    pub filters: Vec<String>,
}

/// 一份 RDS RouteConfiguration 的 native 候选。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XdsRouteTablePlan {
    /// RouteConfiguration.name，必须等于具有 xDS route ownership 的 native proxy id。
    pub name: String,
    /// 保持 Envoy virtual-host/route 先后语义的展开路由。
    pub routes: Vec<XdsRoutePlan>,
    /// 所有 forward action 引用的 CDS cluster。
    pub referenced_clusters: BTreeSet<String>,
}

/// LDS 中一个可由 Naway 精确执行的 HTTP listener 计划。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XdsListenerPlan {
    /// LDS resource/name，也是 native proxy generation 的稳定 id。
    pub name: String,
    /// 唯一 TCP socket 地址。
    pub listen: String,
    /// 单 filter chain 的 SNI/Host allowlist。
    pub server_names: Vec<String>,
    /// HCM 通过 ADS RDS 引用的 RouteConfiguration.name。
    pub route_name: String,
    /// TLS/SDS 终止计划；None 表示明文 HTTP。
    pub tls: Option<XdsDownstreamTlsPlan>,
}

/// LDS DownstreamTlsContext 到 SDS secret 名的最小、安全映射。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XdsDownstreamTlsPlan {
    /// 必须解析为 TLS certificate 类型的 SDS secret。
    pub certificate_secret: String,
    /// 可选 validation-context secret，用于下游 mTLS。
    pub validation_secret: Option<String>,
    /// 是否强制下游客户端证书；只有 validation secret 存在时合法。
    pub require_client_certificate: bool,
}

/// SDS 已完成字段白名单与 PEM 大小门的内存材料。
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum XdsSecretPlan {
    /// 服务端证书链与私钥。
    TlsCertificate {
        /// PEM 证书链。
        certificate_chain: Arc<[u8]>,
        /// PEM 私钥。
        private_key: Arc<[u8]>,
    },
    /// 下游 mTLS 信任根。
    ValidationContext {
        /// PEM CA bundle。
        trusted_ca: Arc<[u8]>,
    },
}

impl std::fmt::Debug for XdsSecretPlan {
    /// 业务作用：只输出 SDS 材料类型与长度，禁止配置诊断意外泄露私钥或 CA 内容。
    ///
    /// 参数说明：`formatter` 是标准格式化目标。
    ///
    /// 返回：不含任何 PEM 字节的调试摘要。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsCertificate {
                certificate_chain,
                private_key,
            } => formatter
                .debug_struct("TlsCertificate")
                .field("certificate_chain_bytes", &certificate_chain.len())
                .field("private_key_bytes", &private_key.len())
                .finish(),
            Self::ValidationContext { trusted_ca } => formatter
                .debug_struct("ValidationContext")
                .field("trusted_ca_bytes", &trusted_ca.len())
                .finish(),
        }
    }
}

/// 同一依赖闭包内可原子发布的 CDS/RDS active generation。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct XdsPolicySnapshot {
    /// 当前 SotW LDS 全集；native-listener profile 中为空。
    pub listeners: BTreeMap<String, XdsListenerPlan>,
    /// 当前 SotW CDS 全集。
    pub clusters: BTreeMap<String, XdsClusterPlan>,
    /// 当前 SotW RDS 全集。
    pub routes: BTreeMap<String, XdsRouteTablePlan>,
    /// 当前 listener 依赖的 SDS 材料；native-secret profile 中为空。
    pub secrets: BTreeMap<String, XdsSecretPlan>,
    /// 只在依赖闭包完整时递增。
    pub generation: u64,
}

/// 接受资源后的发布判定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum XdsPolicyOutcome {
    /// 候选闭包完整，可交给 single-writer 构建并发布。
    Active(XdsPolicySnapshot),
    /// 候选已 ACK/accepted，但缺少依赖；旧 active 必须继续服务。
    Warming {
        /// 缺失的 RDS table 或 CDS cluster，带资源域前缀。
        missing: BTreeSet<String>,
        /// 本轮 accepted candidate 的资源总数。
        resources: usize,
    },
}

/// 每 type accepted 与跨 type active 分离的 CDS/RDS cache。
#[derive(Clone)]
pub(crate) struct XdsPolicyCache {
    required_route_tables: BTreeSet<String>,
    listener_owned: bool,
    secret_owned: bool,
    listeners_observed: bool,
    accepted_listeners: BTreeMap<String, XdsListenerPlan>,
    accepted_clusters: BTreeMap<String, XdsClusterPlan>,
    accepted_routes: BTreeMap<String, XdsRouteTablePlan>,
    accepted_endpoint_clusters: BTreeSet<String>,
    accepted_secrets: BTreeMap<String, XdsSecretPlan>,
    active: Option<XdsPolicySnapshot>,
    warming_since: Option<Instant>,
    warming_timeout_reported: bool,
    next_generation: u64,
}

impl XdsPolicyCache {
    /// 业务作用：创建尚未取得任何 CDS/RDS 的 fail-closed cache，并锁定 native listener 所需 RDS 名。
    ///
    /// 参数说明：`required_route_tables` 是 xDS 拥有 route 域时每个 native proxy id。
    ///
    /// 返回：accepted 为空、active 为空的 cache。
    pub(crate) fn new(required_route_tables: BTreeSet<String>) -> Self {
        Self {
            required_route_tables,
            listener_owned: false,
            secret_owned: false,
            listeners_observed: true,
            accepted_listeners: BTreeMap::new(),
            accepted_clusters: BTreeMap::new(),
            accepted_routes: BTreeMap::new(),
            accepted_endpoint_clusters: BTreeSet::new(),
            accepted_secrets: BTreeMap::new(),
            active: None,
            warming_since: None,
            warming_timeout_reported: false,
            next_generation: 1,
        }
    }

    /// 业务作用：创建 LDS/SDS 全域由 xDS 拥有的 fail-closed cache，首个 LDS 证据前不得发布空拓扑。
    ///
    /// 参数说明：无。
    ///
    /// 返回：所有 accepted 域为空且 listener response 尚未观察的 cache。
    pub(crate) fn new_full_xds() -> Self {
        Self {
            required_route_tables: BTreeSet::new(),
            listener_owned: true,
            secret_owned: true,
            listeners_observed: false,
            accepted_listeners: BTreeMap::new(),
            accepted_clusters: BTreeMap::new(),
            accepted_routes: BTreeMap::new(),
            accepted_endpoint_clusters: BTreeSet::new(),
            accepted_secrets: BTreeMap::new(),
            active: None,
            warming_since: None,
            warming_timeout_reported: false,
            next_generation: 1,
        }
    }

    /// 业务作用：以完整 LDS 替换 listener 候选，并原子派生 RDS/SDS 依赖名。
    ///
    /// 参数说明：`listeners` 已完成 socket/filter/TLS 白名单；`now` 固定 warming 起点。
    ///
    /// 返回：五域闭合时给出 active；否则列出缺失 RDS/CDS/EDS/SDS 证据并保留 LKG。
    pub(crate) fn accept_listeners(
        &mut self,
        listeners: BTreeMap<String, XdsListenerPlan>,
        now: Instant,
    ) -> XdsPolicyOutcome {
        let required_route_tables = listeners
            .values()
            .map(|listener| listener.route_name.clone())
            .collect::<BTreeSet<_>>();
        let required_secrets = listeners
            .values()
            .filter_map(|listener| listener.tls.as_ref())
            .flat_map(|tls| {
                std::iter::once(tls.certificate_secret.as_str())
                    .chain(tls.validation_secret.as_deref())
            })
            .collect::<BTreeSet<_>>();
        // listener 不再引用某域时立即删除其 accepted 证据；未来再次订阅同名资源必须收到新
        // response，不能把失权期间的旧 RDS/SDS 当成当前控制面证明。
        self.accepted_routes
            .retain(|name, _| required_route_tables.contains(name));
        self.accepted_secrets
            .retain(|name, _| required_secrets.contains(name.as_str()));
        self.required_route_tables = required_route_tables;
        self.accepted_listeners = listeners;
        self.listeners_observed = true;
        self.reconcile(now)
    }

    /// 业务作用：以完整 SDS 替换内存 secret 候选，再复验每个 TLS listener 的材料类型闭包。
    ///
    /// 参数说明：`secrets` 的 PEM 仍只驻留内存；`now` 固定 warming 起点。
    ///
    /// 返回：全部 listener 依赖类型匹配时可能给出 active；缺失或错类型保持 warming/LKG。
    pub(crate) fn accept_secrets(
        &mut self,
        secrets: BTreeMap<String, XdsSecretPlan>,
        now: Instant,
    ) -> XdsPolicyOutcome {
        self.accepted_secrets = secrets;
        self.reconcile(now)
    }

    /// 业务作用：以完整 SotW CDS 替换 accepted cluster 集，再复验 RDS 依赖闭包。
    ///
    /// 参数说明：`clusters` 必须在调用前完成整份 response 校验；`now` 固定 warming 起点。
    ///
    /// 返回：依赖齐全时给出新 active generation；否则列出缺失依赖且保留旧 active。
    pub(crate) fn accept_clusters(
        &mut self,
        clusters: BTreeMap<String, XdsClusterPlan>,
        now: Instant,
    ) -> XdsPolicyOutcome {
        self.accepted_clusters = clusters;
        self.reconcile(now)
    }

    /// 业务作用：以完整 SotW RDS 替换 accepted route 集，再复验 native proxy 与 CDS 依赖。
    ///
    /// 参数说明：`routes` 必须在调用前完成整份 response 校验；`now` 固定 warming 起点。
    ///
    /// 返回：依赖齐全时给出新 active generation；否则列出缺失依赖且保留旧 active。
    pub(crate) fn accept_routes(
        &mut self,
        routes: BTreeMap<String, XdsRouteTablePlan>,
        now: Instant,
    ) -> XdsPolicyOutcome {
        self.accepted_routes = routes;
        self.reconcile(now)
    }

    /// 业务作用：登记一份 EDS SotW 已覆盖的 physical cluster 集，再复验 CDS/RDS/EDS 完整闭包。
    ///
    /// 参数说明：`clusters` 是本轮显式订阅的 EDS 名全集；缺失 resource 已由 EDS 语义表示为空表；
    /// `now` 固定 warming 起点。
    ///
    /// 返回：路由、cluster 与 endpoint 闭合时给出 active；否则保持旧 active 并列出缺失依赖。
    pub(crate) fn accept_endpoints(
        &mut self,
        clusters: BTreeSet<String>,
        now: Instant,
    ) -> XdsPolicyOutcome {
        self.accepted_endpoint_clusters = clusters;
        self.reconcile(now)
    }

    /// 业务作用：CDS transport identity 变化后只保留仍可证明同语义的 EDS accepted 证据。
    ///
    /// 参数说明：`retain` 是 cluster/service/protocol/timeout 全相同的 physical EDS 名集合。
    ///
    /// 返回：无；失去证据的 cluster 下一次 reconcile 必须重新 warming，旧 active 不受影响。
    pub(crate) fn retain_endpoint_clusters(&mut self, retain: &BTreeSet<String>) {
        self.accepted_endpoint_clusters
            .retain(|cluster| retain.contains(cluster));
    }

    /// 业务作用：读取最近完整发布的 CDS/RDS LKG，供 warming 或坏版本期间继续服务。
    ///
    /// 参数说明：无。
    ///
    /// 返回：至少完成过一次依赖闭包时返回 active snapshot，否则返回 None。
    #[cfg(test)]
    pub(crate) fn active(&self) -> Option<&XdsPolicySnapshot> {
        self.active.as_ref()
    }

    /// 业务作用：判断当前 accepted 候选是否已经超过 bootstrap warming timeout。
    ///
    /// 参数说明：`now` 是同一单调时钟；`timeout` 是有界 bootstrap 值。
    ///
    /// 返回：存在未闭合候选且持续时间达到门限时返回 true。
    #[cfg(test)]
    pub(crate) fn warming_expired(&self, now: Instant, timeout: Duration) -> bool {
        self.warming_since
            .is_some_and(|started| now.saturating_duration_since(started) >= timeout)
    }

    /// 业务作用：给 ADS 接收循环提供当前 warming 周期的一次性超时唤醒点，避免无新 response 时永远不告警。
    ///
    /// 参数说明：`timeout` 是 bootstrap 已校验的 warming 上限。
    ///
    /// 返回：尚未报告且仍在 warming 时返回单调时钟 deadline；其余状态返回 None。
    pub(crate) fn warming_deadline(&self, timeout: Duration) -> Option<Instant> {
        (!self.warming_timeout_reported)
            .then_some(self.warming_since)
            .flatten()
            .and_then(|started| started.checked_add(timeout))
    }

    /// 业务作用：消费当前 warming 周期的超时事件，防止接收循环在已过期 deadline 上空转和重复计数。
    ///
    /// 参数说明：无。
    ///
    /// 返回：首次消费当前周期时返回 true；不在 warming 或已经消费时返回 false。
    pub(crate) fn mark_warming_timeout_reported(&mut self) -> bool {
        if self.warming_since.is_none() || self.warming_timeout_reported {
            return false;
        }
        self.warming_timeout_reported = true;
        true
    }

    /// 业务作用：只在 required RDS 与所有 cluster 引用齐全时创建新 active generation。
    ///
    /// 参数说明：`now` 用于首次进入当前 warming 周期时定锚。
    ///
    /// 返回：完整闭包或带精确缺失集合的 warming 状态。
    fn reconcile(&mut self, now: Instant) -> XdsPolicyOutcome {
        let mut missing = BTreeSet::new();
        if self.listener_owned && !self.listeners_observed {
            missing.insert("lds:*".to_owned());
        }
        for route_name in &self.required_route_tables {
            if !self.accepted_routes.contains_key(route_name) {
                missing.insert(format!("rds:{route_name}"));
            }
        }
        for route_name in &self.required_route_tables {
            if let Some(table) = self.accepted_routes.get(route_name) {
                for cluster in &table.referenced_clusters {
                    if !self.accepted_clusters.contains_key(cluster) {
                        missing.insert(format!("cds:{cluster}"));
                    }
                }
            }
        }
        for cluster in self.accepted_clusters.values() {
            if !self
                .accepted_endpoint_clusters
                .contains(&cluster.eds_service_name)
            {
                missing.insert(format!("eds:{}", cluster.eds_service_name));
            }
        }
        if self.secret_owned {
            for listener in self.accepted_listeners.values() {
                let Some(tls) = &listener.tls else {
                    continue;
                };
                if !matches!(
                    self.accepted_secrets.get(&tls.certificate_secret),
                    Some(XdsSecretPlan::TlsCertificate { .. })
                ) {
                    missing.insert(format!("sds:certificate:{}", tls.certificate_secret));
                }
                if let Some(validation_secret) = &tls.validation_secret {
                    if !matches!(
                        self.accepted_secrets.get(validation_secret),
                        Some(XdsSecretPlan::ValidationContext { .. })
                    ) {
                        missing.insert(format!("sds:validation:{validation_secret}"));
                    }
                }
            }
        }
        if !missing.is_empty() {
            if self.warming_since.is_none() {
                self.warming_since = Some(now);
                self.warming_timeout_reported = false;
            }
            return XdsPolicyOutcome::Warming {
                missing,
                resources: self
                    .accepted_listeners
                    .len()
                    .saturating_add(self.accepted_secrets.len())
                    .saturating_add(
                        self.accepted_clusters
                            .len()
                            .saturating_add(self.accepted_routes.len()),
                    ),
            };
        }
        self.warming_since = None;
        self.warming_timeout_reported = false;
        let routes = self
            .required_route_tables
            .iter()
            .filter_map(|name| {
                self.accepted_routes
                    .get(name)
                    .cloned()
                    .map(|route| (name.clone(), route))
            })
            .collect();
        let required_secrets = self
            .accepted_listeners
            .values()
            .filter_map(|listener| listener.tls.as_ref())
            .flat_map(|tls| {
                std::iter::once(tls.certificate_secret.as_str())
                    .chain(tls.validation_secret.as_deref())
            })
            .collect::<BTreeSet<_>>();
        let secrets = required_secrets
            .into_iter()
            .filter_map(|name| {
                self.accepted_secrets
                    .get(name)
                    .cloned()
                    .map(|secret| (name.to_owned(), secret))
            })
            .collect();
        let snapshot = XdsPolicySnapshot {
            listeners: self.accepted_listeners.clone(),
            clusters: self.accepted_clusters.clone(),
            routes,
            secrets,
            generation: self.next_generation,
        };
        self.next_generation = self.next_generation.saturating_add(1);
        self.active = Some(snapshot.clone());
        XdsPolicyOutcome::Active(snapshot)
    }
}

/// 业务作用：把完整 CDS/RDS/EDS 依赖闭包编译成下一份原生 GatewaySnapshot 候选。
///
/// 参数说明：`base` 提供 native 治理/bootstrap 域；`policy` 覆盖 xDS 拥有的
/// listeners/routes/clusters/secrets；`endpoints` 是同一闭包的 EDS LKG；`version` 是 single-writer 分配的新版本；
/// `cfg_path` 用于原生 Router/UpstreamDirectory 的路径边界校验。
///
/// 返回：全部 native 二次校验通过时返回候选快照；任一 DSL、服务或依赖失败时零发布。
pub(crate) fn materialize_policy_snapshot(
    base: &GatewaySnapshot,
    policy: &XdsPolicySnapshot,
    endpoints: &std::collections::HashMap<String, Vec<UpstreamInstance>>,
    version: u64,
    cfg_path: &Path,
) -> Result<GatewaySnapshot> {
    let upstreams = build_policy_upstreams(base, &policy.clusters, endpoints, cfg_path)?;
    let listener_owned = base.control_plane.xds.ownership.listeners == XdsResourceOwnerCfg::Xds;
    let mut proxies = if listener_owned {
        let mut proxies = Vec::with_capacity(policy.listeners.len());
        for listener in policy.listeners.values() {
            let table = policy.routes.get(&listener.route_name).with_context(|| {
                format!(
                    "missing active RDS table `{}` for LDS listener `{}`",
                    listener.route_name, listener.name
                )
            })?;
            let router = Arc::new(build_policy_router(table, cfg_path)?);
            let tls = listener
                .tls
                .as_ref()
                .map(|tls| materialize_listener_tls(listener, tls, &policy.secrets))
                .transpose()?;
            proxies.push(ProxyRuntime {
                id: listener.name.clone(),
                listen: listener.listen.clone(),
                plain_enabled: tls.is_none(),
                tls,
                http3: Http3RuntimeCfg::default(),
                // xDS 在此分支拥有完整 listener，不能继承 Kubernetes Gateway 的逐监听器
                // hostname/TLS 选择范围，否则会把另一控制面的租户门禁错误套到 xDS 路由。
                gateway_listeners: Arc::new(Vec::new()),
                server_names: Arc::new(listener.server_names.clone()),
                proxy_protocol: ProxyProtocolRuntimeCfg {
                    enabled: false,
                    allow_v1: false,
                    allow_v2: false,
                    accept_from: Arc::new(Vec::new()),
                    timeout_ms: 0,
                },
                trusted_proxies: Arc::new(Vec::new()),
                limits: base.limits.clone(),
                timeouts: base.timeouts.clone(),
                redirect_https: None,
                hsts_header: None,
                router,
            });
        }
        proxies
    } else {
        let mut proxies = Vec::with_capacity(base.proxies.len());
        for proxy in base.proxies.iter() {
            let table = policy
                .routes
                .get(&proxy.id)
                .with_context(|| format!("missing active RDS table for proxy `{}`", proxy.id))?;
            let router = build_policy_router(table, cfg_path)?;
            let mut next_proxy: ProxyRuntime = proxy.clone();
            next_proxy.router = Arc::new(router);
            proxies.push(next_proxy);
        }
        proxies
    };
    proxies.sort_by(|left, right| left.id.cmp(&right.id));
    let default_router = proxies
        .first()
        .map(|proxy| proxy.router.clone())
        .unwrap_or_else(|| base.router.clone());

    let mut next = base.clone();
    next.version = version;
    next.router = default_router;
    next.upstreams = Arc::new(upstreams);
    next.listen = proxies
        .first()
        .map(|proxy| proxy.listen.clone())
        .unwrap_or_else(|| "0.0.0.0:0".to_owned());
    next.tls = proxies.first().and_then(|proxy| proxy.tls.clone());
    next.proxies = Arc::new(proxies);
    Ok(next)
}

/// 业务作用：把 LDS 的 SDS 名引用解析成只驻留当前 Snapshot 的 TLS 材料，拒绝类型错配或缺失依赖。
///
/// 参数说明：`listener` 提供 socket/name；`tls` 是已验证引用；`secrets` 是同一 active generation。
///
/// 返回：证书、私钥与可选客户端 CA 齐全时返回 TLS runtime；任何缺失保持旧 listener generation。
fn materialize_listener_tls(
    listener: &XdsListenerPlan,
    tls: &XdsDownstreamTlsPlan,
    secrets: &BTreeMap<String, XdsSecretPlan>,
) -> Result<TlsRuntimeCfg> {
    let (certificate_chain, private_key) = match secrets.get(&tls.certificate_secret) {
        Some(XdsSecretPlan::TlsCertificate {
            certificate_chain,
            private_key,
        }) => (certificate_chain.clone(), private_key.clone()),
        _ => bail!(
            "LDS listener `{}` is missing TLS certificate secret `{}`",
            listener.name,
            tls.certificate_secret
        ),
    };
    let client_ca = tls
        .validation_secret
        .as_ref()
        .map(|name| match secrets.get(name) {
            Some(XdsSecretPlan::ValidationContext { trusted_ca }) => Ok(trusted_ca.clone()),
            _ => bail!(
                "LDS listener `{}` is missing validation-context secret `{name}`",
                listener.name
            ),
        })
        .transpose()?;
    Ok(TlsRuntimeCfg {
        listen: listener.listen.clone(),
        cert_file: std::path::PathBuf::new(),
        key_file: std::path::PathBuf::new(),
        keypair_manifest_file: None,
        certs: Vec::new(),
        client_auth: None,
        acme: None,
        in_memory: Some(Arc::new(InMemoryTlsMaterial {
            certificate_chain,
            private_key,
            client_ca,
            require_client_certificate: tls.require_client_certificate,
        })),
    })
}

/// 业务作用：在 ADS ACK 前用原生 UpstreamDirectory 复验 CDS 服务策略，避免 warming 候选把编译错误延迟归因到其它 type。
///
/// 参数说明：`base` 提供 discovery 边界；`clusters` 是本轮 CDS 全量候选；`cfg_path` 是路径基准。
///
/// 返回：原生服务配置可编译时成功；任一 source/protocol/LB 或路径约束失败时拒绝本轮 CDS。
pub(crate) fn validate_cds_native(
    base: &GatewaySnapshot,
    clusters: &BTreeMap<String, XdsClusterPlan>,
    cfg_path: &Path,
) -> Result<()> {
    build_policy_upstreams(base, clusters, &std::collections::HashMap::new(), cfg_path).map(|_| ())
}

/// 业务作用：在 ADS ACK 前用原生 Router 复验每份 RDS DSL，保证错误由产生它的 RDS response 立即 NACK。
///
/// 参数说明：`routes` 是本轮 RDS 全量候选；`cfg_path` 是原生 filter/path 解析基准。
///
/// 返回：全部 route table 可独立编译时成功；predicate/filter/weight 冲突时整份失败。
pub(crate) fn validate_rds_native(
    routes: &BTreeMap<String, XdsRouteTablePlan>,
    cfg_path: &Path,
) -> Result<()> {
    routes
        .values()
        .try_for_each(|table| build_policy_router(table, cfg_path).map(|_| ()))
}

/// 业务作用：把已验证 CDS 计划与同代 endpoint 转成原生服务目录，供预检和最终原子物化共享完全相同的编译路径。
///
/// 参数说明：`base` 提供 discovery；`clusters` 是 logical service 策略；`endpoints` 是同代实例；
/// `cfg_path` 是原生路径边界。
///
/// 返回：成功返回只读 UpstreamDirectory；配置反序列化或原生服务校验失败时返回错误。
fn build_policy_upstreams(
    base: &GatewaySnapshot,
    clusters: &BTreeMap<String, XdsClusterPlan>,
    endpoints: &std::collections::HashMap<String, Vec<UpstreamInstance>>,
    cfg_path: &Path,
) -> Result<UpstreamDirectory> {
    let services = clusters
        .values()
        .map(|cluster| {
            let protocol = match cluster.protocol {
                XdsUpstreamProtocol::H1 => "h1",
                XdsUpstreamProtocol::H2c => "h2c",
            };
            let lb_policy = match cluster.lb_policy {
                XdsLbPolicy::RoundRobin => "round_robin",
                XdsLbPolicy::LeastRequest => "least_conn",
            };
            (
                cluster.name.clone(),
                serde_json::json!({
                    "source": "xds",
                    "registry_service": cluster.eds_service_name,
                    "scheme": "http",
                    "protocol": protocol,
                    "lb_policy": lb_policy
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let upstream_cfg: UpstreamsCfg = serde_json::from_value(serde_json::json!({
        "services": services
    }))
    .context("materialize xDS upstream config")?;
    let dynamic = DynamicUpstreamStore::new();
    let managed = clusters.keys().cloned().collect::<Vec<_>>();
    dynamic.replace_managed_services(&managed, endpoints.clone());
    UpstreamDirectory::build_with_dynamic_at_discovery(
        &upstream_cfg,
        dynamic,
        &base.discovery,
        cfg_path,
    )
    .context("compile xDS upstream directory")
}

/// 业务作用：把一份 RDS native 计划编译成请求热路径 Router，预检与最终发布共用同一语义门。
///
/// 参数说明：`table` 是单个 native proxy 的 route table；`cfg_path` 提供 filter 文件边界。
///
/// 返回：全部 route DSL 可执行时返回 Router；冲突、越界或不支持 filter 时返回错误。
fn build_policy_router(table: &XdsRouteTablePlan, cfg_path: &Path) -> Result<Router> {
    let variables = VariablePlan::build(&VariablesCfg::default())
        .context("build isolated xDS route variables")?;
    let config_dir = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    let route_cfgs = table
        .routes
        .iter()
        .map(|route| {
            serde_json::from_value(serde_json::json!({
                "id": route.id,
                "uri": route.uri,
                "predicates": route.predicates,
                "filters": route.filters
            }))
            .with_context(|| format!("materialize xDS route `{}`", route.id))
        })
        .collect::<Result<Vec<_>>>()?;
    Router::build(&route_cfgs, variables, config_dir)
        .with_context(|| format!("compile xDS RDS table `{}`", table.name))
}

/// 业务作用：把完整 CDS SotW resources 转成 native cluster 计划，任一错误保持零副作用。
///
/// 参数说明：`resources` 来自同一 DiscoveryResponse；`limits` 是 bootstrap 硬预算。
///
/// 返回：按 cluster name 排序的完整替换集；未知字段、扩展、重复资源或不精确语义返回错误。
pub(crate) fn translate_cds_resources(
    resources: &[Any],
    limits: &XdsLimitsCfg,
) -> Result<BTreeMap<String, XdsClusterPlan>> {
    ensure_resource_budget(resources, limits, "CDS")?;
    let mut translated = BTreeMap::new();
    for resource in resources {
        anyhow::ensure!(
            resource.type_url == CDS_TYPE_URL,
            "CDS Any has mismatched type_url"
        );
        validate_cluster_wire(&resource.value).context("validate CDS protobuf surface")?;
        let cluster = Cluster::decode(resource.value.as_slice()).context("decode CDS Cluster")?;
        let plan = translate_cluster(cluster)?;
        anyhow::ensure!(
            translated.insert(plan.name.clone(), plan).is_none(),
            "duplicate CDS cluster"
        );
    }
    let mut physical_owners = BTreeMap::new();
    for plan in translated.values() {
        if let Some(owner) = physical_owners.insert(&plan.eds_service_name, &plan.name) {
            bail!(
                "CDS clusters `{owner}` and `{}` share EDS service name `{}`",
                plan.name,
                plan.eds_service_name
            );
        }
    }
    Ok(translated)
}

/// 业务作用：把完整 RDS SotW resources 展开为 native route 计划并锁定允许的 proxy owner。
///
/// 参数说明：`resources` 是同一 DiscoveryResponse；`allowed_route_tables` 是显式订阅的 native
/// proxy id；`limits` 限制 resource 与 warming 展开规模。
///
/// 返回：按 RouteConfiguration.name 排序的完整替换集；越权 table、未知字段或语义差异返回错误。
pub(crate) fn translate_rds_resources(
    resources: &[Any],
    allowed_route_tables: &BTreeSet<String>,
    limits: &XdsLimitsCfg,
) -> Result<BTreeMap<String, XdsRouteTablePlan>> {
    ensure_resource_budget(resources, limits, "RDS")?;
    let mut translated = BTreeMap::new();
    let mut expanded_routes = 0usize;
    for resource in resources {
        anyhow::ensure!(
            resource.type_url == RDS_TYPE_URL,
            "RDS Any has mismatched type_url"
        );
        validate_route_configuration_wire(&resource.value)
            .context("validate RDS protobuf surface")?;
        let config = RouteConfiguration::decode(resource.value.as_slice())
            .context("decode RouteConfiguration")?;
        validate_resource_name(&config.name, "RDS RouteConfiguration.name")?;
        anyhow::ensure!(
            allowed_route_tables.contains(&config.name),
            "unsubscribed RDS route table `{}`",
            config.name
        );
        let plan = translate_route_configuration(config)?;
        expanded_routes = expanded_routes.saturating_add(plan.routes.len());
        if expanded_routes > limits.max_warming_resources {
            bail!("RDS expanded routes exceed max_warming_resources");
        }
        anyhow::ensure!(
            translated.insert(plan.name.clone(), plan).is_none(),
            "duplicate RDS route table"
        );
    }
    Ok(translated)
}

/// 业务作用：把完整 LDS resources 转成 Naway 单 TCP socket、单 HCM→RDS filter chain 计划。
///
/// 参数说明：`resources` 来自同一 LDS response；`limits` 是 bootstrap 资源/字节硬预算。
///
/// 返回：按 listener name 排序的完整替换集；UDP/QUIC、listener filter、socket option、
/// 多 filter chain 或未知扩展全部拒绝，避免静默执行成另一套拓扑。
pub(crate) fn translate_lds_resources(
    resources: &[Any],
    limits: &XdsLimitsCfg,
) -> Result<BTreeMap<String, XdsListenerPlan>> {
    ensure_resource_budget(resources, limits, "LDS")?;
    let mut translated = BTreeMap::new();
    let mut addresses = BTreeSet::new();
    for resource in resources {
        anyhow::ensure!(
            resource.type_url == LDS_TYPE_URL,
            "LDS Any has mismatched type_url"
        );
        validate_listener_wire(&resource.value).context("validate LDS protobuf surface")?;
        let listener =
            Listener::decode(resource.value.as_slice()).context("decode LDS Listener")?;
        let plan = translate_listener(listener)?;
        anyhow::ensure!(
            addresses.insert(plan.listen.clone()),
            "duplicate LDS listener socket address"
        );
        anyhow::ensure!(
            translated.insert(plan.name.clone(), plan).is_none(),
            "duplicate LDS listener name"
        );
    }
    Ok(translated)
}

/// 业务作用：把完整 SDS resources 转成不实现序列化/明文调试的内存证书或 CA 计划。
///
/// 参数说明：`resources` 来自同一 SDS response；`limits` 是 bootstrap 资源/字节硬预算。
///
/// 返回：仅 inline PEM TLS certificate 或 validation context 成功；文件、环境变量、generic
/// secret、session ticket key 和任意扩展均拒绝。
pub(crate) fn translate_sds_resources(
    resources: &[Any],
    limits: &XdsLimitsCfg,
) -> Result<BTreeMap<String, XdsSecretPlan>> {
    ensure_resource_budget(resources, limits, "SDS")?;
    let mut translated = BTreeMap::new();
    for resource in resources {
        anyhow::ensure!(
            resource.type_url == SDS_TYPE_URL,
            "SDS Any has mismatched type_url"
        );
        validate_secret_wire(&resource.value).context("validate SDS protobuf surface")?;
        let secret = Secret::decode(resource.value.as_slice()).context("decode SDS Secret")?;
        validate_resource_name(&secret.name, "SDS Secret.name")?;
        let plan = match secret
            .secret_type
            .context("SDS Secret payload is required")?
        {
            secret::SecretType::TlsCertificate(certificate) => {
                let certificate_chain = inline_data_source(
                    certificate
                        .certificate_chain
                        .as_ref()
                        .context("SDS TLS certificate_chain is required")?,
                    "SDS certificate_chain",
                )?;
                let private_key = inline_data_source(
                    certificate
                        .private_key
                        .as_ref()
                        .context("SDS TLS private_key is required")?,
                    "SDS private_key",
                )?;
                anyhow::ensure!(
                    !certificate_chain.is_empty() && !private_key.is_empty(),
                    "SDS TLS certificate/key cannot be empty"
                );
                XdsSecretPlan::TlsCertificate {
                    certificate_chain: Arc::from(certificate_chain),
                    private_key: Arc::from(private_key),
                }
            }
            secret::SecretType::ValidationContext(validation) => {
                let trusted_ca = inline_data_source(
                    validation
                        .trusted_ca
                        .as_ref()
                        .context("SDS validation_context.trusted_ca is required")?,
                    "SDS trusted_ca",
                )?;
                anyhow::ensure!(!trusted_ca.is_empty(), "SDS trusted_ca cannot be empty");
                XdsSecretPlan::ValidationContext {
                    trusted_ca: Arc::from(trusted_ca),
                }
            }
        };
        anyhow::ensure!(
            translated.insert(secret.name, plan).is_none(),
            "duplicate SDS secret name"
        );
    }
    Ok(translated)
}

/// 业务作用：把单个已白名单校验的 LDS Listener 映射为 native listener/RDS/SDS 引用。
///
/// 参数说明：`listener` 只含 name/address/单 filter chain。
///
/// 返回：TCP 地址、HCM RDS 和可选 downstream TLS 可精确执行时成功；语义分叉则失败。
fn translate_listener(listener: Listener) -> Result<XdsListenerPlan> {
    validate_resource_name(&listener.name, "LDS Listener.name")?;
    let address = listener
        .address
        .context("LDS Listener.address is required")?;
    let listener_address::Address::SocketAddress(socket) = address
        .address
        .context("LDS Listener requires socket_address")?;
    anyhow::ensure!(
        socket.protocol == 0,
        "LDS supports only TCP socket protocol"
    );
    let ip = socket
        .address
        .parse::<std::net::IpAddr>()
        .context("LDS socket_address.address must be an IP literal")?;
    anyhow::ensure!(
        (1..=u16::MAX as u32).contains(&socket.port_value),
        "LDS socket port must be within 1..=65535"
    );
    let listen = std::net::SocketAddr::new(ip, socket.port_value as u16).to_string();
    anyhow::ensure!(
        listener.filter_chains.len() == 1,
        "LDS currently requires exactly one filter chain"
    );
    let chain = listener
        .filter_chains
        .into_iter()
        .next()
        .expect("filter chain length checked");
    anyhow::ensure!(
        chain.filters.len() == 1,
        "LDS filter chain requires exactly one network filter"
    );
    let mut server_names = chain
        .filter_chain_match
        .as_ref()
        .map(|matcher| matcher.server_names.clone())
        .unwrap_or_default();
    let mut seen_names = BTreeSet::new();
    for name in &mut server_names {
        validate_domain(name).context("validate LDS filter-chain server_name")?;
        anyhow::ensure!(name != "*", "LDS SNI server_name cannot be global wildcard");
        *name = canonical_domain(name);
        anyhow::ensure!(
            seen_names.insert(name.clone()),
            "duplicate LDS filter-chain server_name"
        );
    }
    let filter = chain
        .filters
        .into_iter()
        .next()
        .expect("filter length checked");
    anyhow::ensure!(
        filter.name == "envoy.filters.network.http_connection_manager",
        "LDS supports only envoy.filters.network.http_connection_manager"
    );
    let typed = filter
        .typed_config
        .context("LDS HCM typed_config is required")?;
    anyhow::ensure!(typed.type_url == HCM_TYPE_URL, "LDS HCM type_url mismatch");
    let hcm = HttpConnectionManager::decode(typed.value.as_slice()).context("decode LDS HCM")?;
    anyhow::ensure!(hcm.codec_type == 0, "LDS HCM codec_type must be AUTO");
    anyhow::ensure!(
        !hcm.stat_prefix.is_empty(),
        "LDS HCM stat_prefix is required"
    );
    let rds = hcm.rds.context("LDS HCM requires RDS")?;
    anyhow::ensure!(
        matches!(
            rds.config_source
                .and_then(|source| source.config_source_specifier),
            Some(config_source::ConfigSourceSpecifier::Ads(_))
        ),
        "LDS HCM RDS config source must use ADS"
    );
    validate_resource_name(&rds.route_config_name, "LDS HCM route_config_name")?;
    anyhow::ensure!(
        hcm.http_filters.len() == 1 && hcm.http_filters[0].name == "envoy.filters.http.router",
        "LDS HCM requires exactly one envoy.filters.http.router filter"
    );
    let router = hcm.http_filters[0]
        .typed_config
        .as_ref()
        .context("LDS HCM router typed_config is required")?;
    anyhow::ensure!(
        router.type_url == ROUTER_FILTER_TYPE_URL && router.value.is_empty(),
        "LDS HCM router filter must use an empty v3 Router config"
    );
    let tls = chain
        .transport_socket
        .map(translate_downstream_transport_socket)
        .transpose()?;
    if let Some(matcher) = &chain.filter_chain_match {
        let expected_transport = if tls.is_some() { "tls" } else { "" };
        anyhow::ensure!(
            matcher.transport_protocol == expected_transport,
            "LDS filter-chain transport_protocol must match TLS presence"
        );
        if !matcher.application_protocols.is_empty() {
            anyhow::ensure!(
                matcher.application_protocols == ["h2", "http/1.1"],
                "LDS filter-chain ALPN must be exactly h2,http/1.1"
            );
        }
    }
    anyhow::ensure!(
        tls.is_some() || server_names.is_empty(),
        "LDS SNI server_names require downstream TLS"
    );
    Ok(XdsListenerPlan {
        name: listener.name,
        listen,
        server_names,
        route_name: rds.route_config_name,
        tls,
    })
}

/// 业务作用：解析 LDS TLS transport socket，并把证书/校验依赖严格收敛到当前 ADS 的 SDS 名。
///
/// 参数说明：`socket` 是单 filter chain 的 transport_socket。
///
/// 返回：一个证书 secret 与可选 validation secret；inline/file/provider 等路径失败。
fn translate_downstream_transport_socket(socket: TransportSocket) -> Result<XdsDownstreamTlsPlan> {
    anyhow::ensure!(
        socket.name == "envoy.transport_sockets.tls",
        "LDS supports only envoy.transport_sockets.tls"
    );
    let typed = socket
        .typed_config
        .context("LDS TLS transport_socket typed_config is required")?;
    anyhow::ensure!(
        typed.type_url == DOWNSTREAM_TLS_TYPE_URL,
        "LDS downstream TLS type_url mismatch"
    );
    let context = DownstreamTlsContext::decode(typed.value.as_slice())
        .context("decode LDS DownstreamTlsContext")?;
    let common = context
        .common_tls_context
        .context("LDS DownstreamTlsContext.common_tls_context is required")?;
    anyhow::ensure!(
        common.tls_certificate_sds_secret_configs.len() == 1,
        "LDS TLS requires exactly one certificate SDS secret"
    );
    anyhow::ensure!(
        common.alpn_protocols.is_empty() || common.alpn_protocols == ["h2", "http/1.1"],
        "LDS TLS ALPN must be empty or exactly h2,http/1.1"
    );
    let certificate_secret = translate_sds_reference(
        &common.tls_certificate_sds_secret_configs[0],
        "LDS TLS certificate",
    )?;
    let validation_secret = common
        .validation_context_sds_secret_config
        .as_ref()
        .map(|secret| translate_sds_reference(secret, "LDS TLS validation context"))
        .transpose()?;
    let require_client_certificate = context.require_client_certificate.unwrap_or(false);
    anyhow::ensure!(
        !require_client_certificate || validation_secret.is_some(),
        "LDS require_client_certificate needs validation_context_sds_secret_config"
    );
    Ok(XdsDownstreamTlsPlan {
        certificate_secret,
        validation_secret,
        require_client_certificate,
    })
}

/// 业务作用：校验一个 SDS 引用只指向当前 ADS，禁止 listener 自带远端或文件配置源。
///
/// 参数说明：`secret` 是 CommonTlsContext 中的引用；`label` 用于低敏定位。
///
/// 返回：合法稳定 secret 名；缺名或非 ADS ConfigSource 失败。
fn translate_sds_reference(secret: &SdsSecretConfig, label: &str) -> Result<String> {
    validate_resource_name(&secret.name, label)?;
    anyhow::ensure!(
        matches!(
            secret
                .sds_config
                .as_ref()
                .and_then(|source| source.config_source_specifier.as_ref()),
            Some(config_source::ConfigSourceSpecifier::Ads(_))
        ),
        "{label} config source must use ADS"
    );
    Ok(secret.name.clone())
}

/// 业务作用：提取已通过 wire 白名单的 inline DataSource，不允许路径或环境变量进入执行层。
///
/// 参数说明：`source` 是 SDS 内联 PEM；`label` 用于低敏错误。
///
/// 返回：独占 PEM 字节；缺少 specifier 时失败。
fn inline_data_source(source: &DataSource, label: &str) -> Result<Vec<u8>> {
    match source.specifier.as_ref() {
        Some(data_source::Specifier::InlineBytes(bytes)) => Ok(bytes.clone()),
        Some(data_source::Specifier::InlineString(value)) => Ok(value.as_bytes().to_vec()),
        None => bail!("{label} inline value is required"),
    }
}

/// 业务作用：把一个已验证 CDS Cluster 映射到当前可精确执行的 EDS/H1-H2/LB 子集。
///
/// 参数说明：`cluster` 已通过 raw wire allowlist。
///
/// 返回：精确 native 计划；非 EDS、自定义扩展、冲突协议或非法 duration 返回错误。
fn translate_cluster(cluster: Cluster) -> Result<XdsClusterPlan> {
    validate_resource_name(&cluster.name, "CDS Cluster.name")?;
    let discovery_type = match cluster.cluster_discovery_type {
        Some(cluster::ClusterDiscoveryType::Type(value)) => value,
        None => bail!("CDS Cluster.type is required"),
    };
    anyhow::ensure!(
        discovery_type == 3,
        "CDS currently supports only EDS clusters"
    );
    let eds = cluster
        .eds_cluster_config
        .context("CDS EDS cluster requires eds_cluster_config")?;
    let config_source = eds
        .eds_config
        .context("CDS eds_cluster_config requires ADS config source")?;
    anyhow::ensure!(
        matches!(
            config_source.config_source_specifier,
            Some(config_source::ConfigSourceSpecifier::Ads(_))
        ),
        "CDS EDS config source must use ADS"
    );
    let eds_service_name = if eds.service_name.is_empty() {
        cluster.name.clone()
    } else {
        validate_resource_name(&eds.service_name, "CDS EdsClusterConfig.service_name")?;
        eds.service_name
    };
    let connect_timeout_ms = cluster
        .connect_timeout
        .as_ref()
        .map(proto_duration_ms)
        .transpose()?
        .unwrap_or(5_000);
    anyhow::ensure!(
        (1..=60_000).contains(&connect_timeout_ms),
        "CDS connect_timeout must be within 1ms..=60s"
    );
    let lb_policy = match cluster.lb_policy {
        0 => XdsLbPolicy::RoundRobin,
        1 => XdsLbPolicy::LeastRequest,
        other => bail!("unsupported CDS lb_policy {other}"),
    };
    let legacy_h2 = cluster.http2_protocol_options.is_some();
    let typed_protocol =
        translate_typed_protocol_options(&cluster.typed_extension_protocol_options)?;
    anyhow::ensure!(
        !(legacy_h2 && typed_protocol.is_some()),
        "CDS cannot set legacy and typed HTTP protocol options together"
    );
    let protocol = if legacy_h2 || typed_protocol == Some(XdsUpstreamProtocol::H2c) {
        XdsUpstreamProtocol::H2c
    } else {
        XdsUpstreamProtocol::H1
    };
    Ok(XdsClusterPlan {
        name: cluster.name,
        eds_service_name,
        protocol,
        lb_policy,
        connect_timeout_ms,
    })
}

/// 业务作用：解析唯一允许的 Envoy upstream HTTP protocol typed extension，拒绝其它插件。
///
/// 参数说明：`options` 是 Cluster.typed_extension_protocol_options map。
///
/// 返回：未声明时 None；显式 H1/H2 时返回对应协议；未知 key/type/字段返回错误。
fn translate_typed_protocol_options(
    options: &std::collections::HashMap<String, Any>,
) -> Result<Option<XdsUpstreamProtocol>> {
    if options.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(options.len() == 1, "CDS supports one typed protocol option");
    let any = options
        .get("envoy.extensions.upstreams.http.v3.HttpProtocolOptions")
        .context("unsupported CDS typed_extension_protocol_options key")?;
    anyhow::ensure!(
        any.type_url == HTTP_PROTOCOL_OPTIONS_TYPE_URL,
        "CDS HTTP protocol option has mismatched type_url"
    );
    validate_http_protocol_options_wire(&any.value)?;
    let options = HttpProtocolOptions::decode(any.value.as_slice())
        .context("decode CDS HttpProtocolOptions")?;
    match options.upstream_protocol_options {
        Some(http_protocol_options::UpstreamProtocolOptions::ExplicitHttpConfig(explicit)) => {
            match explicit.protocol_config {
                Some(explicit_http_config::ProtocolConfig::HttpProtocolOptions(_)) => {
                    Ok(Some(XdsUpstreamProtocol::H1))
                }
                Some(explicit_http_config::ProtocolConfig::Http2ProtocolOptions(_)) => {
                    Ok(Some(XdsUpstreamProtocol::H2c))
                }
                None => bail!("CDS explicit_http_config requires H1 or H2"),
            }
        }
        None => bail!("CDS HttpProtocolOptions requires explicit_http_config"),
    }
}

/// 业务作用：按 virtual-host/domain/route 顺序展开 RDS，同时收集 CDS 依赖。
///
/// 参数说明：`config` 已通过 raw allowlist 且名称已完成 owner 校验。
///
/// 返回：可交给 native Router 二次编译的计划；域名、route id 或 action 非法时失败。
fn translate_route_configuration(config: RouteConfiguration) -> Result<XdsRouteTablePlan> {
    validate_virtual_host_domains(&config.virtual_hosts)?;
    let mut routes = Vec::new();
    let mut referenced_clusters = BTreeSet::new();
    let mut route_index = 0usize;
    for virtual_host in config.virtual_hosts {
        for route in virtual_host.routes {
            let base_name = if route.name.is_empty() {
                format!("route-{route_index}")
            } else {
                validate_resource_name(&route.name, "RDS Route.name")?;
                route.name.clone()
            };
            route_index = route_index.saturating_add(1);
            let route_match = route.r#match.context("RDS Route.match is required")?;
            let base_predicates = translate_route_match(route_match)?;
            for (domain_index, domain) in virtual_host.domains.iter().enumerate() {
                let mut predicates = base_predicates.clone();
                if domain != "*" {
                    predicates.push(format!("Host={domain}"));
                }
                let id = format!(
                    "xds-{}-{}-{}-{domain_index}",
                    config.name, virtual_host.name, base_name
                );
                let expanded = translate_route_action(id, predicates, route.action.clone())?;
                for plan in &expanded {
                    if let Some(cluster) = plan.uri.strip_prefix("lb://") {
                        if cluster != "__xds_direct_response__" {
                            referenced_clusters.insert(cluster.to_owned());
                        }
                    }
                }
                routes.extend(expanded);
            }
        }
    }
    Ok(XdsRouteTablePlan {
        name: config.name,
        routes,
        referenced_clusters,
    })
}

/// 业务作用：在展开为全局 native route 前证明每个 domain 只属于一个 VirtualHost，保持 Envoy 先选 vhost、再选 route 的语义。
///
/// 参数说明：`virtual_hosts` 是同一 RouteConfiguration 的完整有序集合。
///
/// 返回：名称/domain 合法且跨 vhost 不相交时成功；重复或 wildcard 覆盖冲突时失败。
fn validate_virtual_host_domains(virtual_hosts: &[VirtualHost]) -> Result<()> {
    let mut owned_domains = Vec::<(usize, String)>::new();
    for (owner_index, virtual_host) in virtual_hosts.iter().enumerate() {
        validate_resource_name(&virtual_host.name, "RDS VirtualHost.name")?;
        anyhow::ensure!(
            !virtual_host.domains.is_empty(),
            "RDS VirtualHost.domains is required"
        );
        let mut local_domains = BTreeSet::new();
        for domain in &virtual_host.domains {
            validate_domain(domain)?;
            let canonical = canonical_domain(domain);
            anyhow::ensure!(
                local_domains.insert(canonical.clone()),
                "duplicate RDS domain in one VirtualHost"
            );
            for (previous_owner, previous_domain) in &owned_domains {
                if *previous_owner != owner_index && domains_overlap(previous_domain, &canonical) {
                    bail!(
                        "overlapping RDS domains `{previous_domain}` and `{canonical}` across VirtualHosts"
                    );
                }
            }
            owned_domains.push((owner_index, canonical));
        }
    }
    Ok(())
}

/// 业务作用：把已验证 domain 规范为 native Host matcher 的大小写与尾点语义，供所有权冲突判定。
///
/// 参数说明：`domain` 已通过 [`validate_domain`]。
///
/// 返回：小写且去除尾点的 exact、`*.suffix` 或 `*`。
fn canonical_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// 业务作用：判断两个 Envoy domain pattern 是否可能匹配同一 Host，阻止展开后跨 vhost 错误回退。
///
/// 参数说明：`left`/`right` 是已规范化的 exact、leading wildcard 或全局 wildcard。
///
/// 返回：存在任一共同可匹配 host 时返回 true。
fn domains_overlap(left: &str, right: &str) -> bool {
    if left == "*" || right == "*" {
        return true;
    }
    match (left.strip_prefix("*."), right.strip_prefix("*.")) {
        (None, None) => left == right,
        (Some(left_suffix), None) => host_is_below_suffix(right, left_suffix),
        (None, Some(right_suffix)) => host_is_below_suffix(left, right_suffix),
        (Some(left_suffix), Some(right_suffix)) => {
            left_suffix == right_suffix
                || host_is_below_suffix(left_suffix, right_suffix)
                || host_is_below_suffix(right_suffix, left_suffix)
        }
    }
}

/// 业务作用：精确判定 host 是否位于 wildcard suffix 下一层或更深，避免字符串后缀把 `badexample.com` 误算为子域。
///
/// 参数说明：`host`/`suffix` 均为小写且无尾点的合法 DNS 名。
///
/// 返回：`host` 在 `suffix` 前还有非空 label 和点分隔符时返回 true。
fn host_is_below_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

/// 业务作用：把 RDS path/header matcher 转成无语义损失的 native predicate 子集。
///
/// 参数说明：`route_match` 只允许 exact/prefix、大小写敏感和 exact/presence header。
///
/// 返回：有序 predicate DSL；缺 path、反转 matcher 或无法精确表示的语义返回错误。
fn translate_route_match(route_match: RouteMatch) -> Result<Vec<String>> {
    anyhow::ensure!(
        route_match.case_sensitive.unwrap_or(true),
        "RDS case_sensitive=false is unsupported"
    );
    let mut predicates = Vec::new();
    match route_match.path_specifier {
        Some(route_match::PathSpecifier::Prefix(prefix)) => {
            validate_path(&prefix)?;
            predicates.push(format!("Path={prefix}"));
        }
        Some(route_match::PathSpecifier::Path(path)) => {
            validate_path(&path)?;
            predicates.push(format!("PathExact={path}"));
        }
        None => bail!("RDS RouteMatch path is required"),
    }
    for header in route_match.headers {
        validate_header_name(&header.name)?;
        match (header.name.as_str(), header.header_match_specifier) {
            (":method", Some(header_matcher::HeaderMatchSpecifier::ExactMatch(value))) => {
                anyhow::ensure!(
                    !value.is_empty()
                        && value.len() <= 16
                        && value.bytes().all(|byte| byte.is_ascii_uppercase()),
                    "RDS :method exact matcher must be uppercase safe ASCII"
                );
                predicates.push(format!("Method={value}"));
            }
            (":method", _) => bail!("RDS :method supports exact_match only"),
            (_, Some(header_matcher::HeaderMatchSpecifier::ExactMatch(value))) => {
                validate_header_value(&value)?;
                predicates.push(format!("Header={},exact,{value}", header.name));
            }
            (_, Some(header_matcher::HeaderMatchSpecifier::PresentMatch(true))) => {
                predicates.push(format!("Header={},present", header.name));
            }
            (_, Some(header_matcher::HeaderMatchSpecifier::PresentMatch(false))) => {
                predicates.push(format!("Header={},absent", header.name));
            }
            (_, None) => bail!("RDS HeaderMatcher specifier is required"),
        }
    }
    Ok(predicates)
}

/// 业务作用：把 forward、weighted、redirect 与 direct-response action 展开为 native routes。
///
/// 参数说明：`id`/`predicates` 是已经规范化的 route 身份与 matcher；`action` 是 RDS oneof。
///
/// 返回：单 action 一条 route，weighted action 多条稳定 Weight route；未知或空 action 返回错误。
fn translate_route_action(
    id: String,
    predicates: Vec<String>,
    action: Option<route::Action>,
) -> Result<Vec<XdsRoutePlan>> {
    match action {
        Some(route::Action::Route(action)) => match action.cluster_specifier {
            Some(route_action::ClusterSpecifier::Cluster(cluster)) => {
                validate_resource_name(&cluster, "RDS RouteAction.cluster")?;
                Ok(vec![XdsRoutePlan {
                    id,
                    uri: format!("lb://{cluster}"),
                    predicates,
                    filters: Vec::new(),
                }])
            }
            Some(route_action::ClusterSpecifier::WeightedClusters(weighted)) => {
                anyhow::ensure!(
                    (2..=32).contains(&weighted.clusters.len()),
                    "RDS weighted_clusters requires 2..=32 entries"
                );
                let group = stable_weight_group(&id);
                let mut plans = Vec::with_capacity(weighted.clusters.len());
                let mut total = 0u64;
                let mut seen = HashSet::new();
                for (index, cluster) in weighted.clusters.into_iter().enumerate() {
                    validate_resource_name(&cluster.name, "RDS weighted cluster name")?;
                    anyhow::ensure!(
                        seen.insert(cluster.name.clone()),
                        "duplicate weighted cluster"
                    );
                    let weight = cluster.weight.unwrap_or(1);
                    anyhow::ensure!(
                        weight > 0 && weight <= 1_000_000,
                        "invalid weighted cluster weight"
                    );
                    total = total
                        .checked_add(u64::from(weight))
                        .context("weighted cluster sum overflow")?;
                    let mut member_predicates = predicates.clone();
                    member_predicates.push(format!("Weight={group},{weight}"));
                    plans.push(XdsRoutePlan {
                        id: format!("{id}-weight-{index}"),
                        uri: format!("lb://{}", cluster.name),
                        predicates: member_predicates,
                        filters: Vec::new(),
                    });
                }
                anyhow::ensure!(
                    total <= u64::from(u32::MAX),
                    "weighted cluster sum exceeds uint32"
                );
                Ok(plans)
            }
            None => bail!("RDS RouteAction cluster specifier is required"),
        },
        Some(route::Action::DirectResponse(action)) => {
            anyhow::ensure!(
                (200..600).contains(&action.status),
                "invalid RDS direct response status"
            );
            let body = action
                .body
                .map(translate_inline_data_source)
                .transpose()?
                .unwrap_or_default();
            anyhow::ensure!(
                body.len() <= 4096,
                "RDS direct response body exceeds 4096 bytes"
            );
            let filter = if body.is_empty() {
                format!("return {}", action.status)
            } else {
                anyhow::ensure!(
                    !body.bytes().any(|byte| byte.is_ascii_control()),
                    "RDS direct response body contains control characters"
                );
                format!("return {} {body}", action.status)
            };
            Ok(vec![XdsRoutePlan {
                id,
                uri: "lb://__xds_direct_response__".to_owned(),
                predicates,
                filters: vec![filter],
            }])
        }
        Some(route::Action::Redirect(action)) => {
            let scheme = match action.scheme_rewrite_specifier {
                Some(redirect_action::SchemeRewriteSpecifier::SchemeRedirect(scheme))
                    if matches!(scheme.as_str(), "http" | "https") =>
                {
                    scheme
                }
                _ => bail!("RDS redirect requires explicit scheme_redirect=http|https"),
            };
            anyhow::ensure!(
                !action.host_redirect.is_empty(),
                "RDS redirect requires host_redirect"
            );
            validate_header_value(&action.host_redirect)?;
            let path = match action.path_rewrite_specifier {
                Some(redirect_action::PathRewriteSpecifier::PathRedirect(path)) => path,
                _ => bail!("RDS redirect requires fixed path_redirect"),
            };
            validate_path(&path)?;
            anyhow::ensure!(
                action.strip_query,
                "RDS fixed redirect requires strip_query=true"
            );
            let status = match action.response_code {
                0 => 301,
                1 => 302,
                2 => 303,
                3 => 307,
                4 => 308,
                other => bail!("invalid RDS redirect response_code {other}"),
            };
            let port = match action.port_redirect {
                0 => String::new(),
                1..=65535 => format!(":{}", action.port_redirect),
                _ => bail!("invalid RDS redirect port"),
            };
            Ok(vec![XdsRoutePlan {
                id,
                uri: "lb://__xds_direct_response__".to_owned(),
                predicates,
                filters: vec![format!(
                    "return {status} {scheme}://{}{port}{path}",
                    action.host_redirect
                )],
            }])
        }
        None => bail!("RDS Route action is required"),
    }
}

/// 业务作用：把 direct-response DataSource 限定为 UTF-8 inline 内容，禁止读取本机文件或环境变量。
///
/// 参数说明：`source` 是 RDS DirectResponseAction.body。
///
/// 返回：inline string/UTF-8 bytes；filename、environment 或缺失 specifier 返回错误。
fn translate_inline_data_source(source: DataSource) -> Result<String> {
    match source.specifier {
        Some(data_source::Specifier::InlineString(value)) => Ok(value),
        Some(data_source::Specifier::InlineBytes(value)) => {
            String::from_utf8(value).context("RDS inline_bytes must be UTF-8")
        }
        None => bail!("RDS DataSource specifier is required"),
    }
}

/// 业务作用：执行所有 xDS resource 共用的条数与单资源字节硬门。
///
/// 参数说明：`resources` 是同 type SotW 全集；`limits` 是 bootstrap；`label` 用于 NACK。
///
/// 返回：预算内成功；超限返回可分类错误文本，调用方不得进入 decode/apply。
fn ensure_resource_budget(resources: &[Any], limits: &XdsLimitsCfg, label: &str) -> Result<()> {
    if resources.len() > limits.max_resources_per_type {
        return Err(XdsResourceExhausted(match label {
            "CDS" => "CDS resources exceed max_resources_per_type",
            "RDS" => "RDS resources exceed max_resources_per_type",
            _ => "xDS resources exceed max_resources_per_type",
        })
        .into());
    }
    if resources
        .iter()
        .any(|resource| resource.value.len() > limits.max_resource_bytes)
    {
        return Err(XdsResourceExhausted(match label {
            "CDS" => "CDS resource exceeds max_resource_bytes",
            "RDS" => "RDS resource exceeds max_resource_bytes",
            _ => "xDS resource exceeds max_resource_bytes",
        })
        .into());
    }
    Ok(())
}

/// 业务作用：验证 xDS resource 名可安全用于 owner、route id 和 metrics 外的诊断文本。
///
/// 参数说明：`value` 是 cluster/table/route 名；`field` 用于定位错误。
///
/// 返回：1..=256 bytes 安全 ASCII 成功，其它值失败。
fn validate_resource_name(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 256,
        "{field} must be 1..=256 bytes"
    );
    anyhow::ensure!(
        value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        }),
        "{field} contains unsupported characters"
    );
    Ok(())
}

/// 业务作用：限制 RDS domain 到 native Host predicate 可精确表达的 exact/leading-wildcard 子集。
///
/// 参数说明：`domain` 是 VirtualHost.domains 单项。
///
/// 返回：`*`、合法 exact host 或 `*.suffix` 成功；端口、控制字符和其它 wildcard 失败。
fn validate_domain(domain: &str) -> Result<()> {
    let canonical = domain.trim_end_matches('.');
    anyhow::ensure!(
        !canonical.is_empty() && canonical.len() <= 253,
        "RDS domain length is invalid"
    );
    if canonical == "*" {
        return Ok(());
    }
    let value = canonical.strip_prefix("*.").unwrap_or(canonical);
    anyhow::ensure!(
        !value.is_empty() && !value.contains('*') && !value.contains(':'),
        "RDS domain is outside exact/leading-wildcard allowlist"
    );
    anyhow::ensure!(
        value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        }),
        "RDS domain contains an invalid DNS label"
    );
    Ok(())
}

/// 业务作用：限制 RDS path 到 native exact/prefix matcher 的安全 origin-form 子集。
///
/// 参数说明：`path` 是 RouteMatch 或固定 redirect path。
///
/// 返回：以 `/` 开头、无控制字符/fragment 且不超过 8192 bytes 时成功。
fn validate_path(path: &str) -> Result<()> {
    anyhow::ensure!(
        path.starts_with('/')
            && path.len() <= 8192
            && !path.contains('#')
            && !path.bytes().any(|byte| byte.is_ascii_control()),
        "RDS path is outside safe origin-form allowlist"
    );
    Ok(())
}

/// 业务作用：校验 matcher header 名并允许 Envoy 的 `:method` 伪头特例。
///
/// 参数说明：`name` 是 HeaderMatcher.name。
///
/// 返回：`:method` 或合法普通 HTTP header name 成功。
fn validate_header_name(name: &str) -> Result<()> {
    if name == ":method" {
        return Ok(());
    }
    http::HeaderName::from_bytes(name.as_bytes())
        .context("RDS HeaderMatcher.name is invalid")
        .map(|_| ())
}

/// 业务作用：限制会进入 predicate 或 Location 的 RDS 字符串，阻断控制字符与内存放大。
///
/// 参数说明：`value` 是 header matcher/value 或 redirect host。
///
/// 返回：1..=256 printable ASCII 成功，其它值失败。
fn validate_header_value(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "RDS header value must be 1..=256 printable ASCII bytes"
    );
    Ok(())
}

/// 业务作用：把任意 route id 压缩成 native Weight group 的稳定安全 ASCII 标识。
///
/// 参数说明：`id` 是已规范化展开 route id。
///
/// 返回：最多 64 bytes 的确定性 FNV-1a 十六进制 group。
fn stable_weight_group(id: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("xds-{hash:016x}")
}

/// 业务作用：把 protobuf Duration 转成无溢出毫秒，并拒绝负数与非规范 nanos。
///
/// 参数说明：`duration` 来自 CDS executable timeout。
///
/// 返回：向上取整到毫秒的 u64；负数、nanos 越界或乘法溢出失败。
fn proto_duration_ms(duration: &ProtoDuration) -> Result<u64> {
    anyhow::ensure!(
        duration.seconds >= 0 && (0..1_000_000_000).contains(&duration.nanos),
        "invalid protobuf Duration"
    );
    let seconds = u64::try_from(duration.seconds).context("Duration seconds overflow")?;
    let millis = seconds
        .checked_mul(1_000)
        .context("Duration milliseconds overflow")?;
    let nanos = u64::try_from(duration.nanos).context("Duration nanos overflow")?;
    millis
        .checked_add(nanos.div_ceil(1_000_000))
        .context("Duration total overflow")
}

#[derive(Clone, Copy)]
enum WireValue<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32,
}

/// 业务作用：零拷贝遍历 protobuf wire，阻止 prost 把未知 executable 字段静默丢弃。
///
/// 参数说明：`bytes` 是完整 message；`visit` 校验每个字段的编号、类型和嵌套 surface。
///
/// 返回：完整消费且全部字段通过时成功；截断、溢出、group 或未知字段失败。
fn walk_fields<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u32, WireValue<'a>) -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        let key = take_varint(&mut bytes)?;
        let field = u32::try_from(key >> 3).context("protobuf field number overflow")?;
        anyhow::ensure!(field > 0, "protobuf field number cannot be zero");
        let value = match key & 7 {
            0 => WireValue::Varint(take_varint(&mut bytes)?),
            1 => {
                take_exact(&mut bytes, 8)?;
                WireValue::Fixed64
            }
            2 => {
                let len = usize::try_from(take_varint(&mut bytes)?)
                    .context("protobuf length overflow")?;
                WireValue::Bytes(take_exact(&mut bytes, len)?)
            }
            5 => {
                take_exact(&mut bytes, 4)?;
                WireValue::Fixed32
            }
            wire => bail!("unsupported protobuf wire type {wire}"),
        };
        visit(field, value)?;
    }
    Ok(())
}

/// 业务作用：读取有十字节上限的 protobuf varint，防截断和移位溢出。
///
/// 参数说明：`bytes` 会推进到 varint 之后。
///
/// 返回：合法 u64；截断或第十字节溢出失败。
fn take_varint(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let (&byte, rest) = bytes.split_first().context("truncated protobuf varint")?;
        *bytes = rest;
        if shift == 63 && byte > 1 {
            bail!("protobuf varint overflow");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint exceeds ten bytes")
}

/// 业务作用：从 wire 输入借用固定长度片段，不复制 payload。
///
/// 参数说明：`bytes` 会推进；`len` 来自已校验可转 usize 的 protobuf length。
///
/// 返回：长度足够时返回借用切片，截断时失败。
fn take_exact<'a>(bytes: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    anyhow::ensure!(bytes.len() >= len, "truncated protobuf field");
    let (head, tail) = bytes.split_at(len);
    *bytes = tail;
    Ok(head)
}

/// 业务作用：断言当前 wire value 是 length-delimited，并返回嵌套 bytes。
///
/// 参数说明：`value` 是 walker 输出；`field` 用于错误定位。
///
/// 返回：Bytes variant 的借用内容；其它 wire type 失败。
fn expect_bytes<'a>(value: WireValue<'a>, field: &str) -> Result<&'a [u8]> {
    match value {
        WireValue::Bytes(bytes) => Ok(bytes),
        WireValue::Varint(value) => bail!("{field} expected bytes, got varint {value}"),
        WireValue::Fixed64 => bail!("{field} expected bytes, got fixed64"),
        WireValue::Fixed32 => bail!("{field} expected bytes, got fixed32"),
    }
}

/// 业务作用：断言当前 wire value 是 varint。
///
/// 参数说明：`value` 是 walker 输出；`field` 用于错误定位。
///
/// 返回：Varint 数值；其它 wire type 失败。
fn expect_varint(value: WireValue<'_>, field: &str) -> Result<u64> {
    match value {
        WireValue::Varint(value) => Ok(value),
        _ => bail!("{field} expected varint"),
    }
}

/// 业务作用：拒绝 protobuf singular 字段重复出现，避免 oneof/last-wins 语义被隐藏。
///
/// 参数说明：`seen` 是当前 message 字段集；`field` 是编号；`name` 用于错误定位。
///
/// 返回：首次出现成功，重复失败。
fn mark_singular(seen: &mut HashSet<u32>, field: u32, name: &str) -> Result<()> {
    anyhow::ensure!(seen.insert(field), "duplicate {name}");
    Ok(())
}

/// 业务作用：验证 LDS Listener 仅包含 name、单 socket address 与 filter chains，拒绝所有内核/扩展副作用。
///
/// 参数说明：`bytes` 是 Listener Any payload。
///
/// 返回：最小 TCP/HCM surface 合法时成功；UDP、QUIC、listener filter、socket option 等失败。
fn validate_listener_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "Listener.name")?;
            expect_bytes(value, "Listener.name").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "Listener.address")?;
            validate_listener_address_wire(expect_bytes(value, "Listener.address")?)
        }
        3 => validate_filter_chain_wire(expect_bytes(value, "Listener.filter_chains")?),
        9 => bail!("LDS listener_filters are outside the supported profile"),
        13 => bail!("LDS socket_options are outside the supported profile"),
        18 => bail!("LDS UDP/QUIC listener configuration is outside the supported profile"),
        other => bail!("unknown or unsupported Listener field {other}"),
    })
}

/// 业务作用：验证 LDS Address 只能选择 IP socket，禁止 pipe/internal address。
///
/// 参数说明：`bytes` 是 core Address message。
///
/// 返回：唯一 socket_address 成功；其它地址类型失败。
fn validate_listener_address_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen, "duplicate Address.socket_address");
            seen = true;
            validate_listener_socket_wire(expect_bytes(value, "Address.socket_address")?)
        }
        other => bail!("Address field {other} is outside IP socket allowlist"),
    })?;
    anyhow::ensure!(seen, "Address.socket_address is required");
    Ok(())
}

/// 业务作用：验证 LDS SocketAddress 只含 TCP protocol、IP literal 与 port_value。
///
/// 参数说明：`bytes` 是 SocketAddress message。
///
/// 返回：字段形态合法时成功；named port/resolver/interface/namespace 等失败。
fn validate_listener_socket_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "SocketAddress.protocol")?;
            expect_varint(value, "SocketAddress.protocol").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "SocketAddress.address")?;
            expect_bytes(value, "SocketAddress.address").map(|_| ())
        }
        3 => {
            mark_singular(&mut singular, field, "SocketAddress.port_value")?;
            expect_varint(value, "SocketAddress.port_value").map(|_| ())
        }
        other => bail!("SocketAddress field {other} is outside TCP IP/port allowlist"),
    })
}

/// 业务作用：验证单 LDS filter chain 只含匹配条件、network filters 与可选 TLS transport。
///
/// 参数说明：`bytes` 是 FilterChain message。
///
/// 返回：没有 metadata、PROXY protocol、on-demand 或扩展发现时成功。
fn validate_filter_chain_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "FilterChain.filter_chain_match")?;
            validate_filter_chain_match_wire(expect_bytes(value, "FilterChain.match")?)
        }
        3 => validate_network_filter_wire(expect_bytes(value, "FilterChain.filters")?),
        6 => {
            mark_singular(&mut singular, field, "FilterChain.transport_socket")?;
            validate_transport_socket_wire(expect_bytes(value, "FilterChain.transport_socket")?)
        }
        other => bail!("unknown or unsupported FilterChain field {other}"),
    })
}

/// 业务作用：限制 filter-chain match 到 SNI、TLS transport 与固定 ALPN，避免 native matcher 语义缺失。
///
/// 参数说明：`bytes` 是 FilterChainMatch message。
///
/// 返回：仅 fields 9/10/11 成功；IP/port/source 等匹配条件失败。
fn validate_filter_chain_match_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        9 => {
            mark_singular(&mut singular, field, "FilterChainMatch.transport_protocol")?;
            expect_bytes(value, "FilterChainMatch.transport_protocol").map(|_| ())
        }
        10 => expect_bytes(value, "FilterChainMatch.application_protocols").map(|_| ()),
        11 => expect_bytes(value, "FilterChainMatch.server_names").map(|_| ()),
        other => bail!("unknown or unsupported FilterChainMatch field {other}"),
    })
}

/// 业务作用：验证 network Filter 只能携带唯一 name 与 typed_config Any。
///
/// 参数说明：`bytes` 是 Filter message。
///
/// 返回：静态 typed extension 形态成功；ECDS/Struct/未知字段失败。
fn validate_network_filter_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "Filter.name")?;
            expect_bytes(value, "Filter.name").map(|_| ())
        }
        4 => {
            mark_singular(&mut singular, field, "Filter.typed_config")?;
            validate_hcm_any_wire(expect_bytes(value, "Filter.typed_config")?)
        }
        other => bail!("unknown or unsupported Filter field {other}"),
    })
}

/// 业务作用：验证 HCM Any 并递归限制其 payload surface。
///
/// 参数说明：`bytes` 是 HCM google.protobuf.Any。
///
/// 返回：type/value 唯一且 payload 通过 HCM 白名单时成功。
fn validate_hcm_any_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "HCM Any.type_url")?;
            expect_bytes(value, "HCM Any.type_url").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "HCM Any.value")?;
            validate_hcm_wire(expect_bytes(value, "HCM Any.value")?)
        }
        other => bail!("unknown HCM Any field {other}"),
    })
}

/// 业务作用：验证 HCM 只含 AUTO codec、stat prefix、ADS RDS 与 router HTTP filter。
///
/// 参数说明：`bytes` 是 HttpConnectionManager payload。
///
/// 返回：最小 HCM→RDS surface 成功；inline route、upgrade、tracing、header mutation 等失败。
fn validate_hcm_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "HCM.codec_type")?;
            expect_varint(value, "HCM.codec_type").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "HCM.stat_prefix")?;
            expect_bytes(value, "HCM.stat_prefix").map(|_| ())
        }
        3 => {
            mark_singular(&mut singular, field, "HCM.rds")?;
            validate_hcm_rds_wire(expect_bytes(value, "HCM.rds")?)
        }
        5 => validate_http_filter_wire(expect_bytes(value, "HCM.http_filters")?),
        other => bail!("unknown or unsupported HttpConnectionManager field {other}"),
    })
}

/// 业务作用：验证 HCM RDS 只引用当前 ADS 与一个 route_config_name。
///
/// 参数说明：`bytes` 是 HCM.Rds message。
///
/// 返回：ADS ConfigSource/name 唯一时成功。
fn validate_hcm_rds_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "Rds.config_source")?;
            validate_config_source_wire(expect_bytes(value, "Rds.config_source")?)
        }
        2 => {
            mark_singular(&mut singular, field, "Rds.route_config_name")?;
            expect_bytes(value, "Rds.route_config_name").map(|_| ())
        }
        other => bail!("unknown Rds field {other}"),
    })
}

/// 业务作用：验证 HCM HTTP filter 只能携带 name 与静态 typed_config。
///
/// 参数说明：`bytes` 是 HttpFilter message。
///
/// 返回：router filter 可解码形态成功；ECDS/disabled/matcher 等字段失败。
fn validate_http_filter_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "HttpFilter.name")?;
            expect_bytes(value, "HttpFilter.name").map(|_| ())
        }
        4 => {
            mark_singular(&mut singular, field, "HttpFilter.typed_config")?;
            validate_any_wire(expect_bytes(value, "HttpFilter.typed_config")?)
        }
        other => bail!("unknown or unsupported HttpFilter field {other}"),
    })
}

/// 业务作用：验证 transport socket 只含名称与 DownstreamTlsContext Any。
///
/// 参数说明：`bytes` 是 TransportSocket message。
///
/// 返回：静态 TLS typed config 成功；其它扩展字段失败。
fn validate_transport_socket_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "TransportSocket.name")?;
            expect_bytes(value, "TransportSocket.name").map(|_| ())
        }
        3 => {
            mark_singular(&mut singular, field, "TransportSocket.typed_config")?;
            validate_downstream_tls_any_wire(expect_bytes(value, "TransportSocket.typed_config")?)
        }
        other => bail!("unknown TransportSocket field {other}"),
    })
}

/// 业务作用：验证 DownstreamTlsContext Any，并递归校验 SDS 引用 surface。
///
/// 参数说明：`bytes` 是 TLS google.protobuf.Any。
///
/// 返回：type/value 唯一且 payload 合法时成功。
fn validate_downstream_tls_any_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "TLS Any.type_url")?;
            expect_bytes(value, "TLS Any.type_url").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "TLS Any.value")?;
            validate_downstream_tls_wire(expect_bytes(value, "TLS Any.value")?)
        }
        other => bail!("unknown TLS Any field {other}"),
    })
}

/// 业务作用：验证 DownstreamTlsContext 只含 common context 与 require-client-certificate。
///
/// 参数说明：`bytes` 是 DownstreamTlsContext payload。
///
/// 返回：session ticket、OCSP、SNI 强制等未映射字段缺席时成功。
fn validate_downstream_tls_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(
                &mut singular,
                field,
                "DownstreamTlsContext.common_tls_context",
            )?;
            validate_common_tls_context_wire(expect_bytes(value, "common_tls_context")?)
        }
        2 => {
            mark_singular(
                &mut singular,
                field,
                "DownstreamTlsContext.require_client_certificate",
            )?;
            validate_bool_wrapper(expect_bytes(value, "require_client_certificate")?)
        }
        other => bail!("unknown or unsupported DownstreamTlsContext field {other}"),
    })
}

/// 业务作用：验证 CommonTlsContext 仅以当前 ADS 引用证书/validation SDS，并使用固定 ALPN。
///
/// 参数说明：`bytes` 是 CommonTlsContext message。
///
/// 返回：一个证书引用、可选 validation 引用和 ALPN 成功；inline/provider/combined context 失败。
fn validate_common_tls_context_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        4 => expect_bytes(value, "CommonTlsContext.alpn_protocols").map(|_| ()),
        6 => validate_sds_reference_wire(expect_bytes(value, "certificate SDS reference")?),
        7 => {
            mark_singular(&mut singular, field, "validation SDS reference")?;
            validate_sds_reference_wire(expect_bytes(value, "validation SDS reference")?)
        }
        other => bail!("unknown or unsupported CommonTlsContext field {other}"),
    })
}

/// 业务作用：验证 SdsSecretConfig 只含 secret 名与 ADS ConfigSource。
///
/// 参数说明：`bytes` 是 SdsSecretConfig message。
///
/// 返回：name/source 唯一且 source 为 ADS 时成功。
fn validate_sds_reference_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "SdsSecretConfig.name")?;
            expect_bytes(value, "SdsSecretConfig.name").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "SdsSecretConfig.sds_config")?;
            validate_config_source_wire(expect_bytes(value, "SdsSecretConfig.sds_config")?)
        }
        other => bail!("unknown SdsSecretConfig field {other}"),
    })
}

/// 业务作用：验证 SDS Secret 只包含 name 与 certificate/validation 二选一。
///
/// 参数说明：`bytes` 是 Secret Any payload。
///
/// 返回：内联 TLS identity 或 CA surface 成功；ticket/generic secret 失败。
fn validate_secret_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "Secret.name")?;
            expect_bytes(value, "Secret.name").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, 100, "Secret.type")?;
            validate_tls_certificate_wire(expect_bytes(value, "Secret.tls_certificate")?)
        }
        4 => {
            mark_singular(&mut singular, 100, "Secret.type")?;
            validate_validation_context_wire(expect_bytes(value, "Secret.validation_context")?)
        }
        3 | 5 => bail!("SDS session-ticket/generic secret is outside the supported profile"),
        other => bail!("unknown Secret field {other}"),
    })
}

/// 业务作用：验证 SDS TlsCertificate 只有内联证书链与私钥。
///
/// 参数说明：`bytes` 是 TlsCertificate message。
///
/// 返回：两个 DataSource 通过 inline 白名单时成功；password/provider/OCSP 等失败。
fn validate_tls_certificate_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 | 2 => {
            mark_singular(&mut singular, field, "TlsCertificate material")?;
            validate_data_source_wire(expect_bytes(value, "TlsCertificate material")?)
        }
        other => bail!("unknown or unsupported TlsCertificate field {other}"),
    })
}

/// 业务作用：验证 SDS CertificateValidationContext 只包含内联 trusted_ca。
///
/// 参数说明：`bytes` 是 CertificateValidationContext message。
///
/// 返回：唯一 trusted_ca 成功；SAN/hash/CRL/custom validator 等失败。
fn validate_validation_context_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen, "duplicate CertificateValidationContext.trusted_ca");
            seen = true;
            validate_data_source_wire(expect_bytes(value, "trusted_ca")?)
        }
        other => bail!("unknown or unsupported CertificateValidationContext field {other}"),
    })?;
    anyhow::ensure!(seen, "CertificateValidationContext.trusted_ca is required");
    Ok(())
}

/// 业务作用：严格验证 CDS Cluster 顶层 surface；所有未映射执行字段均 NACK。
///
/// 参数说明：`bytes` 是 Cluster Any payload。
///
/// 返回：仅 name/type/EDS config/connect timeout/LB/H2 protocol 字段成功。
fn validate_cluster_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    let mut typed_protocol_keys = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "Cluster.name")?;
            expect_bytes(value, "Cluster.name").map(|_| ())
        }
        2 | 6 => {
            mark_singular(&mut singular, field, "Cluster enum")?;
            expect_varint(value, "Cluster enum").map(|_| ())
        }
        3 => {
            mark_singular(&mut singular, field, "Cluster.eds_cluster_config")?;
            validate_eds_cluster_config_wire(expect_bytes(value, "Cluster.eds_cluster_config")?)
        }
        4 => {
            mark_singular(&mut singular, field, "Cluster.connect_timeout")?;
            validate_duration_wire(expect_bytes(value, "Cluster.connect_timeout")?)
        }
        14 => {
            mark_singular(&mut singular, field, "Cluster.http2_protocol_options")?;
            anyhow::ensure!(
                expect_bytes(value, "Cluster.http2_protocol_options")?.is_empty(),
                "CDS legacy HTTP/2 options must be empty"
            );
            Ok(())
        }
        36 => {
            let key =
                validate_typed_protocol_map_entry(expect_bytes(value, "Cluster.typed protocol")?)?;
            anyhow::ensure!(
                typed_protocol_keys.insert(key),
                "duplicate Cluster.typed_extension_protocol_options key"
            );
            Ok(())
        }
        33 => bail!("CDS EDS cluster cannot embed load_assignment"),
        24 => bail!("CDS transport_socket is not enabled before TLS profile mapping"),
        other => bail!("unknown or unsupported Cluster field {other}"),
    })
}

/// 业务作用：验证 EDS cluster config 只引用当前 ADS stream 与可选安全 service name。
///
/// 参数说明：`bytes` 是 EdsClusterConfig message。
///
/// 返回：唯一 ConfigSource 与 service_name 字段成功，其它字段失败。
fn validate_eds_cluster_config_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "EdsClusterConfig.eds_config")?;
            validate_config_source_wire(expect_bytes(value, "EdsClusterConfig.eds_config")?)
        }
        2 => {
            mark_singular(&mut singular, field, "EdsClusterConfig.service_name")?;
            expect_bytes(value, "EdsClusterConfig.service_name").map(|_| ())
        }
        other => bail!("unknown EdsClusterConfig field {other}"),
    })
}

/// 业务作用：验证 ConfigSource 精确选择 ADS，不允许另一路径或远端 API 绕过 bootstrap authority。
///
/// 参数说明：`bytes` 是 ConfigSource message。
///
/// 返回：唯一空 ADS marker 成功；其它 source/timeout/version 字段失败。
fn validate_config_source_wire(bytes: &[u8]) -> Result<()> {
    let mut seen_ads = false;
    walk_fields(bytes, |field, value| match field {
        3 => {
            anyhow::ensure!(!seen_ads, "duplicate ConfigSource.ads");
            seen_ads = true;
            anyhow::ensure!(
                expect_bytes(value, "ConfigSource.ads")?.is_empty(),
                "ADS marker must be empty"
            );
            Ok(())
        }
        other => bail!("ConfigSource field {other} is outside ADS allowlist"),
    })?;
    anyhow::ensure!(seen_ads, "ConfigSource.ads is required");
    Ok(())
}

/// 业务作用：验证 Cluster typed protocol map entry 的 key/Any wire 形态。
///
/// 参数说明：`bytes` 是 protobuf map entry。
///
/// 返回：唯一 key/value 成功并返回 UTF-8 key；重复、缺失或未知字段失败。
fn validate_typed_protocol_map_entry(bytes: &[u8]) -> Result<String> {
    let mut singular = HashSet::new();
    let mut key = None;
    let mut has_value = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "typed protocol key")?;
            let raw = expect_bytes(value, "typed protocol key")?;
            key = Some(
                std::str::from_utf8(raw)
                    .context("typed protocol key must be UTF-8")?
                    .to_owned(),
            );
            Ok(())
        }
        2 => {
            mark_singular(&mut singular, field, "typed protocol value")?;
            has_value = true;
            validate_any_wire(expect_bytes(value, "typed protocol value")?)
        }
        other => bail!("unknown typed protocol map field {other}"),
    })?;
    anyhow::ensure!(has_value, "typed protocol map value is required");
    key.context("typed protocol map key is required")
}

/// 业务作用：验证 google.protobuf.Any 只含唯一 type_url/value。
///
/// 参数说明：`bytes` 是 Any message。
///
/// 返回：规范字段成功；重复或未知字段失败。
fn validate_any_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 | 2 => {
            mark_singular(&mut singular, field, "Any field")?;
            expect_bytes(value, "Any field").map(|_| ())
        }
        other => bail!("unknown Any field {other}"),
    })
}

/// 业务作用：验证 typed HttpProtocolOptions 仅选择空 H1 或 H2 explicit config。
///
/// 参数说明：`bytes` 是 HttpProtocolOptions Any payload。
///
/// 返回：唯一 field 3 explicit config 成功；其它通用或扩展选项失败。
fn validate_http_protocol_options_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        3 => {
            anyhow::ensure!(!seen, "duplicate HttpProtocolOptions.explicit_http_config");
            seen = true;
            validate_explicit_http_config_wire(expect_bytes(value, "explicit_http_config")?)
        }
        other => bail!("HttpProtocolOptions field {other} is unsupported"),
    })?;
    anyhow::ensure!(seen, "HttpProtocolOptions.explicit_http_config is required");
    Ok(())
}

/// 业务作用：验证 explicit protocol oneof 只含一个空 H1/H2 options message。
///
/// 参数说明：`bytes` 是 ExplicitHttpConfig message。
///
/// 返回：field 1 或 2 恰好一个且为空时成功。
fn validate_explicit_http_config_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 | 2 => {
            anyhow::ensure!(!seen, "duplicate explicit HTTP protocol oneof");
            seen = true;
            anyhow::ensure!(
                expect_bytes(value, "explicit HTTP protocol")?.is_empty(),
                "H1/H2 options must be empty"
            );
            Ok(())
        }
        other => bail!("unsupported explicit HTTP protocol field {other}"),
    })?;
    anyhow::ensure!(seen, "explicit HTTP protocol is required");
    Ok(())
}

/// 业务作用：验证 protobuf Duration 只含 seconds/nanos 两个 singular varint。
///
/// 参数说明：`bytes` 是 Duration message。
///
/// 返回：已知字段无重复时成功；未知或错误 wire type 失败。
fn validate_duration_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 | 2 => {
            mark_singular(&mut singular, field, "Duration field")?;
            expect_varint(value, "Duration field").map(|_| ())
        }
        other => bail!("unknown Duration field {other}"),
    })
}

/// 业务作用：验证 RouteConfiguration 顶层只含 name 与 inline virtual_hosts。
///
/// 参数说明：`bytes` 是 RDS Any payload。
///
/// 返回：allowlist 成功；VHDS、header mutation、插件和 metadata 等字段失败。
fn validate_route_configuration_wire(bytes: &[u8]) -> Result<()> {
    let mut seen_name = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen_name, "duplicate RouteConfiguration.name");
            seen_name = true;
            expect_bytes(value, "RouteConfiguration.name").map(|_| ())
        }
        2 => validate_virtual_host_wire(expect_bytes(value, "RouteConfiguration.virtual_hosts")?),
        other => bail!("unknown or unsupported RouteConfiguration field {other}"),
    })?;
    anyhow::ensure!(seen_name, "RouteConfiguration.name is required");
    Ok(())
}

/// 业务作用：验证 VirtualHost 只含 name/domains/ordered routes。
///
/// 参数说明：`bytes` 是单个 VirtualHost。
///
/// 返回：allowlist 成功；TLS enforcement、matcher tree、filter config 和 mutation 失败。
fn validate_virtual_host_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "VirtualHost.name")?;
            expect_bytes(value, "VirtualHost.name").map(|_| ())
        }
        2 => expect_bytes(value, "VirtualHost.domains").map(|_| ()),
        3 => validate_route_wire(expect_bytes(value, "VirtualHost.routes")?),
        other => bail!("unknown or unsupported VirtualHost field {other}"),
    })
}

/// 业务作用：验证 Route 只含 name/match 与一个 forward/redirect/direct action。
///
/// 参数说明：`bytes` 是单个 Route。
///
/// 返回：allowlist 成功；metadata/filter/mutation/tracing 等字段失败。
fn validate_route_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        14 => {
            mark_singular(&mut singular, field, "Route.name")?;
            expect_bytes(value, "Route.name").map(|_| ())
        }
        1 => {
            mark_singular(&mut singular, field, "Route.match")?;
            validate_route_match_wire(expect_bytes(value, "Route.match")?)
        }
        2 => {
            mark_singular(&mut singular, 100, "Route.action")?;
            validate_route_action_wire(expect_bytes(value, "Route.route")?)
        }
        3 => {
            mark_singular(&mut singular, 100, "Route.action")?;
            validate_redirect_action_wire(expect_bytes(value, "Route.redirect")?)
        }
        7 => {
            mark_singular(&mut singular, 100, "Route.action")?;
            validate_direct_response_wire(expect_bytes(value, "Route.direct_response")?)
        }
        other => bail!("unknown or unsupported Route field {other}"),
    })
}

/// 业务作用：验证 RouteMatch 只含 exact/prefix、case-sensitive 与受限 headers。
///
/// 参数说明：`bytes` 是 RouteMatch。
///
/// 返回：allowlist 成功；regex/runtime/query/grpc/dynamic matcher 等字段失败。
fn validate_route_match_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 | 2 => {
            mark_singular(&mut singular, 100, "RouteMatch.path oneof")?;
            expect_bytes(value, "RouteMatch.path").map(|_| ())
        }
        4 => {
            mark_singular(&mut singular, field, "RouteMatch.case_sensitive")?;
            validate_bool_wrapper(expect_bytes(value, "RouteMatch.case_sensitive")?)
        }
        6 => validate_header_matcher_wire(expect_bytes(value, "RouteMatch.headers")?),
        other => bail!("unknown or unsupported RouteMatch field {other}"),
    })
}

/// 业务作用：验证 HeaderMatcher 只含 name 与 exact/presence oneof。
///
/// 参数说明：`bytes` 是 HeaderMatcher。
///
/// 返回：allowlist 成功；invert、regex/range/string matcher 等字段失败。
fn validate_header_matcher_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "HeaderMatcher.name")?;
            expect_bytes(value, "HeaderMatcher.name").map(|_| ())
        }
        4 => {
            mark_singular(&mut singular, 100, "HeaderMatcher specifier")?;
            expect_bytes(value, "HeaderMatcher.exact_match").map(|_| ())
        }
        7 => {
            mark_singular(&mut singular, 100, "HeaderMatcher specifier")?;
            expect_varint(value, "HeaderMatcher.present_match").map(|_| ())
        }
        other => bail!("unknown or unsupported HeaderMatcher field {other}"),
    })
}

/// 业务作用：验证 forward action 只选择单 cluster 或 weighted clusters。
///
/// 参数说明：`bytes` 是 RouteAction。
///
/// 返回：allowlist 成功；rewrite/timeout/retry/plugin 等尚未精确映射的字段失败。
fn validate_route_action_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen, "duplicate RouteAction cluster specifier");
            seen = true;
            expect_bytes(value, "RouteAction.cluster").map(|_| ())
        }
        3 => {
            anyhow::ensure!(!seen, "duplicate RouteAction cluster specifier");
            seen = true;
            validate_weighted_clusters_wire(expect_bytes(value, "RouteAction.weighted_clusters")?)
        }
        other => bail!("unknown or unsupported RouteAction field {other}"),
    })?;
    anyhow::ensure!(seen, "RouteAction cluster specifier is required");
    Ok(())
}

/// 业务作用：验证 WeightedCluster 只含 name+weight 的 ordered cluster entries。
///
/// 参数说明：`bytes` 是 WeightedCluster。
///
/// 返回：allowlist 成功；runtime key/total weight/header mutation 等字段失败。
fn validate_weighted_clusters_wire(bytes: &[u8]) -> Result<()> {
    walk_fields(bytes, |field, value| match field {
        1 => validate_cluster_weight_wire(expect_bytes(value, "WeightedCluster.clusters")?),
        other => bail!("unknown or unsupported WeightedCluster field {other}"),
    })
}

/// 业务作用：验证单个 ClusterWeight 只含 name 与 UInt32Value weight。
///
/// 参数说明：`bytes` 是 ClusterWeight。
///
/// 返回：allowlist 成功；cluster header、metadata、mutation 和 typed config 失败。
fn validate_cluster_weight_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "ClusterWeight.name")?;
            expect_bytes(value, "ClusterWeight.name").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "ClusterWeight.weight")?;
            validate_u32_wrapper(expect_bytes(value, "ClusterWeight.weight")?)
        }
        other => bail!("unknown or unsupported ClusterWeight field {other}"),
    })
}

/// 业务作用：验证 redirect action 仅含显式 scheme/host/port/fixed path/status/strip-query。
///
/// 参数说明：`bytes` 是 RedirectAction。
///
/// 返回：allowlist 成功；prefix/regex/https bool 等不能精确映射的字段失败。
fn validate_redirect_action_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 | 2 | 7 => {
            mark_singular(&mut singular, field, "RedirectAction string")?;
            expect_bytes(value, "RedirectAction string").map(|_| ())
        }
        3 | 6 | 8 => {
            mark_singular(&mut singular, field, "RedirectAction numeric")?;
            expect_varint(value, "RedirectAction numeric").map(|_| ())
        }
        other => bail!("unknown or unsupported RedirectAction field {other}"),
    })
}

/// 业务作用：验证 direct response 只含 status 与 inline DataSource body。
///
/// 参数说明：`bytes` 是 DirectResponseAction。
///
/// 返回：allowlist 成功；body format 或未知字段失败。
fn validate_direct_response_wire(bytes: &[u8]) -> Result<()> {
    let mut singular = HashSet::new();
    walk_fields(bytes, |field, value| match field {
        1 => {
            mark_singular(&mut singular, field, "DirectResponse.status")?;
            expect_varint(value, "DirectResponse.status").map(|_| ())
        }
        2 => {
            mark_singular(&mut singular, field, "DirectResponse.body")?;
            validate_data_source_wire(expect_bytes(value, "DirectResponse.body")?)
        }
        other => bail!("unknown or unsupported DirectResponse field {other}"),
    })
}

/// 业务作用：验证 DataSource 只能内联 bytes/string，禁止控制面要求读取节点文件或环境变量。
///
/// 参数说明：`bytes` 是 DataSource message。
///
/// 返回：field 2 或 3 唯一出现时成功，其它字段失败。
fn validate_data_source_wire(bytes: &[u8]) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        2 | 3 => {
            anyhow::ensure!(!seen, "duplicate DataSource specifier");
            seen = true;
            expect_bytes(value, "DataSource inline value").map(|_| ())
        }
        other => bail!("DataSource field {other} is outside inline allowlist"),
    })?;
    anyhow::ensure!(seen, "DataSource inline value is required");
    Ok(())
}

/// 业务作用：验证 BoolValue 只有唯一 value varint。
///
/// 参数说明：`bytes` 是 google.protobuf.BoolValue。
///
/// 返回：零或一个 value 成功；未知/重复字段失败。
fn validate_bool_wrapper(bytes: &[u8]) -> Result<()> {
    validate_scalar_wrapper(bytes, "BoolValue")
}

/// 业务作用：验证 UInt32Value 只有唯一 value varint。
///
/// 参数说明：`bytes` 是 google.protobuf.UInt32Value。
///
/// 返回：零或一个 value 成功；未知/重复字段失败。
fn validate_u32_wrapper(bytes: &[u8]) -> Result<()> {
    validate_scalar_wrapper(bytes, "UInt32Value")
}

/// 业务作用：复用 protobuf scalar wrapper 的严格字段门。
///
/// 参数说明：`bytes` 是 wrapper message；`name` 用于错误定位。
///
/// 返回：仅 field 1 varint 且不重复时成功。
fn validate_scalar_wrapper(bytes: &[u8], name: &str) -> Result<()> {
    let mut seen = false;
    walk_fields(bytes, |field, value| match field {
        1 => {
            anyhow::ensure!(!seen, "duplicate {name}.value");
            seen = true;
            expect_varint(value, name).map(|_| ())
        }
        other => bail!("unknown {name} field {other}"),
    })
}

#[derive(Clone, PartialEq, Message)]
struct EmptyMessage {}

#[derive(Clone, PartialEq, Message)]
struct Listener {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    address: Option<ListenerAddress>,
    #[prost(message, repeated, tag = "3")]
    filter_chains: Vec<FilterChain>,
}

#[derive(Clone, PartialEq, Message)]
struct ListenerAddress {
    #[prost(oneof = "listener_address::Address", tags = "1")]
    address: Option<listener_address::Address>,
}

mod listener_address {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Address {
        #[prost(message, tag = "1")]
        SocketAddress(super::ListenerSocketAddress),
    }
}

#[derive(Clone, PartialEq, Message)]
struct ListenerSocketAddress {
    #[prost(int32, tag = "1")]
    protocol: i32,
    #[prost(string, tag = "2")]
    address: String,
    #[prost(uint32, tag = "3")]
    port_value: u32,
}

#[derive(Clone, PartialEq, Message)]
struct FilterChain {
    #[prost(message, optional, tag = "1")]
    filter_chain_match: Option<FilterChainMatch>,
    #[prost(message, repeated, tag = "3")]
    filters: Vec<NetworkFilter>,
    #[prost(message, optional, tag = "6")]
    transport_socket: Option<TransportSocket>,
}

#[derive(Clone, PartialEq, Message)]
struct FilterChainMatch {
    #[prost(string, tag = "9")]
    transport_protocol: String,
    #[prost(string, repeated, tag = "10")]
    application_protocols: Vec<String>,
    #[prost(string, repeated, tag = "11")]
    server_names: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct NetworkFilter {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "4")]
    typed_config: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
struct HttpConnectionManager {
    #[prost(int32, tag = "1")]
    codec_type: i32,
    #[prost(string, tag = "2")]
    stat_prefix: String,
    #[prost(message, optional, tag = "3")]
    rds: Option<HcmRds>,
    #[prost(message, repeated, tag = "5")]
    http_filters: Vec<HttpFilter>,
}

#[derive(Clone, PartialEq, Message)]
struct HcmRds {
    #[prost(message, optional, tag = "1")]
    config_source: Option<ConfigSource>,
    #[prost(string, tag = "2")]
    route_config_name: String,
}

#[derive(Clone, PartialEq, Message)]
struct HttpFilter {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "4")]
    typed_config: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
struct TransportSocket {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "3")]
    typed_config: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
struct DownstreamTlsContext {
    #[prost(message, optional, tag = "1")]
    common_tls_context: Option<CommonTlsContext>,
    #[prost(message, optional, tag = "2")]
    require_client_certificate: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct CommonTlsContext {
    #[prost(string, repeated, tag = "4")]
    alpn_protocols: Vec<String>,
    #[prost(message, repeated, tag = "6")]
    tls_certificate_sds_secret_configs: Vec<SdsSecretConfig>,
    #[prost(message, optional, tag = "7")]
    validation_context_sds_secret_config: Option<SdsSecretConfig>,
}

#[derive(Clone, PartialEq, Message)]
struct SdsSecretConfig {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    sds_config: Option<ConfigSource>,
}

#[derive(Clone, PartialEq, Message)]
struct Secret {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(oneof = "secret::SecretType", tags = "2, 4")]
    secret_type: Option<secret::SecretType>,
}

mod secret {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum SecretType {
        #[prost(message, tag = "2")]
        TlsCertificate(super::SdsTlsCertificate),
        #[prost(message, tag = "4")]
        ValidationContext(super::SdsValidationContext),
    }
}

#[derive(Clone, PartialEq, Message)]
struct SdsTlsCertificate {
    #[prost(message, optional, tag = "1")]
    certificate_chain: Option<DataSource>,
    #[prost(message, optional, tag = "2")]
    private_key: Option<DataSource>,
}

#[derive(Clone, PartialEq, Message)]
struct SdsValidationContext {
    #[prost(message, optional, tag = "1")]
    trusted_ca: Option<DataSource>,
}

#[derive(Clone, PartialEq, Message)]
struct Cluster {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(oneof = "cluster::ClusterDiscoveryType", tags = "2")]
    cluster_discovery_type: Option<cluster::ClusterDiscoveryType>,
    #[prost(message, optional, tag = "3")]
    eds_cluster_config: Option<EdsClusterConfig>,
    #[prost(message, optional, tag = "4")]
    connect_timeout: Option<ProtoDuration>,
    #[prost(int32, tag = "6")]
    lb_policy: i32,
    #[prost(message, optional, tag = "14")]
    http2_protocol_options: Option<EmptyMessage>,
    #[prost(map = "string, message", tag = "36")]
    typed_extension_protocol_options: std::collections::HashMap<String, Any>,
}

mod cluster {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum ClusterDiscoveryType {
        #[prost(int32, tag = "2")]
        Type(i32),
    }
}

#[derive(Clone, PartialEq, Message)]
struct EdsClusterConfig {
    #[prost(message, optional, tag = "1")]
    eds_config: Option<ConfigSource>,
    #[prost(string, tag = "2")]
    service_name: String,
}

#[derive(Clone, PartialEq, Message)]
struct ConfigSource {
    #[prost(oneof = "config_source::ConfigSourceSpecifier", tags = "3")]
    config_source_specifier: Option<config_source::ConfigSourceSpecifier>,
}

mod config_source {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum ConfigSourceSpecifier {
        #[prost(message, tag = "3")]
        Ads(super::EmptyMessage),
    }
}

#[derive(Clone, PartialEq, Message)]
struct HttpProtocolOptions {
    #[prost(oneof = "http_protocol_options::UpstreamProtocolOptions", tags = "3")]
    upstream_protocol_options: Option<http_protocol_options::UpstreamProtocolOptions>,
}

mod http_protocol_options {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum UpstreamProtocolOptions {
        #[prost(message, tag = "3")]
        ExplicitHttpConfig(super::ExplicitHttpConfig),
    }
}

#[derive(Clone, PartialEq, Message)]
struct ExplicitHttpConfig {
    #[prost(oneof = "explicit_http_config::ProtocolConfig", tags = "1, 2")]
    protocol_config: Option<explicit_http_config::ProtocolConfig>,
}

mod explicit_http_config {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum ProtocolConfig {
        #[prost(message, tag = "1")]
        HttpProtocolOptions(super::EmptyMessage),
        #[prost(message, tag = "2")]
        Http2ProtocolOptions(super::EmptyMessage),
    }
}

#[derive(Clone, PartialEq, Message)]
struct RouteConfiguration {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, repeated, tag = "2")]
    virtual_hosts: Vec<VirtualHost>,
}

#[derive(Clone, PartialEq, Message)]
struct VirtualHost {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, repeated, tag = "2")]
    domains: Vec<String>,
    #[prost(message, repeated, tag = "3")]
    routes: Vec<Route>,
}

#[derive(Clone, PartialEq, Message)]
struct Route {
    #[prost(string, tag = "14")]
    name: String,
    #[prost(message, optional, tag = "1")]
    r#match: Option<RouteMatch>,
    #[prost(oneof = "route::Action", tags = "2, 3, 7")]
    action: Option<route::Action>,
}

mod route {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Action {
        #[prost(message, tag = "2")]
        Route(super::RouteAction),
        #[prost(message, tag = "3")]
        Redirect(super::RedirectAction),
        #[prost(message, tag = "7")]
        DirectResponse(super::DirectResponseAction),
    }
}

#[derive(Clone, PartialEq, Message)]
struct RouteMatch {
    #[prost(oneof = "route_match::PathSpecifier", tags = "1, 2")]
    path_specifier: Option<route_match::PathSpecifier>,
    #[prost(message, optional, tag = "4")]
    case_sensitive: Option<bool>,
    #[prost(message, repeated, tag = "6")]
    headers: Vec<HeaderMatcher>,
}

mod route_match {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum PathSpecifier {
        #[prost(string, tag = "1")]
        Prefix(String),
        #[prost(string, tag = "2")]
        Path(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct HeaderMatcher {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(oneof = "header_matcher::HeaderMatchSpecifier", tags = "4, 7")]
    header_match_specifier: Option<header_matcher::HeaderMatchSpecifier>,
}

mod header_matcher {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum HeaderMatchSpecifier {
        #[prost(string, tag = "4")]
        ExactMatch(String),
        #[prost(bool, tag = "7")]
        PresentMatch(bool),
    }
}

#[derive(Clone, PartialEq, Message)]
struct RouteAction {
    #[prost(oneof = "route_action::ClusterSpecifier", tags = "1, 3")]
    cluster_specifier: Option<route_action::ClusterSpecifier>,
}

mod route_action {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum ClusterSpecifier {
        #[prost(string, tag = "1")]
        Cluster(String),
        #[prost(message, tag = "3")]
        WeightedClusters(super::WeightedCluster),
    }
}

#[derive(Clone, PartialEq, Message)]
struct WeightedCluster {
    #[prost(message, repeated, tag = "1")]
    clusters: Vec<ClusterWeight>,
}

#[derive(Clone, PartialEq, Message)]
struct ClusterWeight {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    weight: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct RedirectAction {
    #[prost(string, tag = "1")]
    host_redirect: String,
    #[prost(oneof = "redirect_action::PathRewriteSpecifier", tags = "2")]
    path_rewrite_specifier: Option<redirect_action::PathRewriteSpecifier>,
    #[prost(int32, tag = "3")]
    response_code: i32,
    #[prost(bool, tag = "6")]
    strip_query: bool,
    #[prost(oneof = "redirect_action::SchemeRewriteSpecifier", tags = "7")]
    scheme_rewrite_specifier: Option<redirect_action::SchemeRewriteSpecifier>,
    #[prost(uint32, tag = "8")]
    port_redirect: u32,
}

mod redirect_action {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum PathRewriteSpecifier {
        #[prost(string, tag = "2")]
        PathRedirect(String),
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum SchemeRewriteSpecifier {
        #[prost(string, tag = "7")]
        SchemeRedirect(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct DirectResponseAction {
    #[prost(uint32, tag = "1")]
    status: u32,
    #[prost(message, optional, tag = "2")]
    body: Option<DataSource>,
}

#[derive(Clone, PartialEq, Message)]
struct DataSource {
    #[prost(oneof = "data_source::Specifier", tags = "2, 3")]
    specifier: Option<data_source::Specifier>,
}

mod data_source {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Specifier {
        #[prost(bytes, tag = "2")]
        InlineBytes(Vec<u8>),
        #[prost(string, tag = "3")]
        InlineString(String),
    }
}

#[path = "../../tests/unit/xds_resources.rs"]
#[cfg(test)]
mod tests;
