//! Dynamic service discovery runtime.
//!
//! The request path never talks to a registry. Background tasks watch Nacos or poll
//! Consul/Eureka/DNS/Kubernetes, translate provider-neutral instances into gateway
//! upstream instances, and publish immutable snapshots into [`DynamicUpstreamStore`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use bytes::BytesMut;
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::model::{
    ConsulDiscoveryCfg, DiscoveryCfg, DnsDiscoveryCfg, EurekaDiscoveryCfg, KubernetesDiscoveryCfg,
    NacosDiscoveryCfg,
};
use crate::config::GatewaySnapshot;
use crate::metrics::{Metrics, RegistryBackendMetric, RegistryPollMetric};
use crate::upstream::{
    discovery_instances_to_upstreams, registry_instances_to_upstreams, DynamicUpstreamStore,
    NacosWatchSpec, RegistryInstance, RegistryKind, RegistryWatchSpec,
};

/// 后台服务发现任务管理器；请求热路径只读取它发布的不可变实例快照。
pub struct NacosDiscoveryManager {
    dynamic: Arc<DynamicUpstreamStore>,
    metrics: Arc<Metrics>,
    tasks: Mutex<HashMap<String, WatchTask>>,
    registry_tasks: Mutex<HashMap<String, RegistryTask>>,
}

const MAX_REGISTRY_RESPONSE_BYTES_HARD: usize = 16 * 1024 * 1024;
const MAX_REGISTRY_INSTANCES_HARD: usize = 4_096;

/// 解析 V7 registry SecretSource 并 fail-fast 校验所有后台资源预算。
///
/// 返回值进入不可变 snapshot；后台 worker 只使用已解析凭据，不在轮询路径
/// 重复读 env/文件。
pub(crate) fn build_runtime_config(
    mut cfg: DiscoveryCfg,
    config_dir: &std::path::Path,
) -> anyhow::Result<DiscoveryCfg> {
    if cfg.nacos.enabled {
        anyhow::ensure!(
            !cfg.nacos.server_addr.trim().is_empty(),
            "discovery.nacos.server_addr cannot be empty"
        );
        validate_poll_budget(
            "nacos",
            cfg.nacos.poll_interval_ms,
            1_000,
            cfg.nacos.stale_ttl_ms,
        )?;
        anyhow::ensure!(
            (100..=3_600_000).contains(&cfg.nacos.reconnect_backoff_ms),
            "discovery.nacos.reconnect_backoff_ms must be within 100..=3600000"
        );
        anyhow::ensure!(
            cfg.nacos.stale_ttl_ms <= 365 * 24 * 60 * 60 * 1_000,
            "discovery.nacos.stale_ttl_ms must be <=31536000000"
        );
        if cfg.nacos.self_register.enabled {
            anyhow::ensure!(
                (100..=60_000).contains(&cfg.nacos.self_register.deregister_timeout_ms),
                "discovery.nacos.self_register.deregister_timeout_ms must be within 100..=60000"
            );
        }
        cfg.nacos.password = crate::secret::resolve_text(
            &cfg.nacos.password,
            config_dir,
            "discovery.nacos.password",
        )?;
    }
    if cfg.consul.enabled {
        validate_http_registry(
            "consul",
            &mut cfg.consul.base_url,
            cfg.consul.poll_interval_ms,
            cfg.consul.request_timeout_ms,
            cfg.consul.stale_ttl_ms,
            cfg.consul.max_response_bytes,
            cfg.consul.max_instances,
        )?;
        cfg.consul.token =
            crate::secret::resolve_text(&cfg.consul.token, config_dir, "discovery.consul.token")?;
    }
    if cfg.eureka.enabled {
        validate_http_registry(
            "eureka",
            &mut cfg.eureka.base_url,
            cfg.eureka.poll_interval_ms,
            cfg.eureka.request_timeout_ms,
            cfg.eureka.stale_ttl_ms,
            cfg.eureka.max_response_bytes,
            cfg.eureka.max_instances,
        )?;
        cfg.eureka.password = crate::secret::resolve_text(
            &cfg.eureka.password,
            config_dir,
            "discovery.eureka.password",
        )?;
    }
    if cfg.dns.enabled {
        validate_poll_budget(
            "dns",
            cfg.dns.poll_interval_ms,
            cfg.dns.request_timeout_ms,
            cfg.dns.stale_ttl_ms,
        )?;
        if !(1..=MAX_REGISTRY_INSTANCES_HARD).contains(&cfg.dns.max_addresses) {
            bail!("discovery.dns.max_addresses must be within 1..={MAX_REGISTRY_INSTANCES_HARD}");
        }
    }
    if cfg.kubernetes.enabled {
        validate_http_registry(
            "kubernetes",
            &mut cfg.kubernetes.api_server,
            cfg.kubernetes.poll_interval_ms,
            cfg.kubernetes.request_timeout_ms,
            cfg.kubernetes.stale_ttl_ms,
            cfg.kubernetes.max_response_bytes,
            cfg.kubernetes.max_instances,
        )?;
        anyhow::ensure!(
            !cfg.kubernetes.namespace.trim().is_empty(),
            "discovery.kubernetes.namespace cannot be empty"
        );
        cfg.kubernetes.bearer_token = crate::secret::resolve_text(
            &cfg.kubernetes.bearer_token,
            config_dir,
            "discovery.kubernetes.bearer_token",
        )?;
        if !cfg.kubernetes.ca_certificate.is_empty() {
            cfg.kubernetes.ca_certificate = crate::secret::resolve_text(
                &cfg.kubernetes.ca_certificate,
                config_dir,
                "discovery.kubernetes.ca_certificate",
            )?;
        }
    }
    Ok(cfg)
}

fn validate_http_registry(
    name: &str,
    base_url: &mut String,
    poll_interval_ms: u64,
    request_timeout_ms: u64,
    stale_ttl_ms: u64,
    max_response_bytes: usize,
    max_instances: usize,
) -> anyhow::Result<()> {
    validate_poll_budget(name, poll_interval_ms, request_timeout_ms, stale_ttl_ms)?;
    let parsed = reqwest::Url::parse(base_url)
        .with_context(|| format!("discovery.{name} endpoint is not a URL"))?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "discovery.{name} endpoint must be http(s) with an authority"
    );
    anyhow::ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "discovery.{name} endpoint must not embed credentials"
    );
    *base_url = base_url.trim_end_matches('/').to_owned();
    anyhow::ensure!(
        (1..=MAX_REGISTRY_RESPONSE_BYTES_HARD).contains(&max_response_bytes),
        "discovery.{name}.max_response_bytes must be within 1..={MAX_REGISTRY_RESPONSE_BYTES_HARD}"
    );
    anyhow::ensure!(
        (1..=MAX_REGISTRY_INSTANCES_HARD).contains(&max_instances),
        "discovery.{name}.max_instances must be within 1..={MAX_REGISTRY_INSTANCES_HARD}"
    );
    Ok(())
}

fn validate_poll_budget(
    name: &str,
    poll_interval_ms: u64,
    request_timeout_ms: u64,
    stale_ttl_ms: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        (100..=3_600_000).contains(&poll_interval_ms),
        "discovery.{name}.poll_interval_ms must be within 100..=3600000"
    );
    anyhow::ensure!(
        (50..=60_000).contains(&request_timeout_ms),
        "discovery.{name}.request_timeout_ms must be within 50..=60000"
    );
    anyhow::ensure!(
        stale_ttl_ms == 0 || stale_ttl_ms >= poll_interval_ms,
        "discovery.{name}.stale_ttl_ms must be 0 or at least poll_interval_ms"
    );
    anyhow::ensure!(
        stale_ttl_ms <= 365 * 24 * 60 * 60 * 1_000,
        "discovery.{name}.stale_ttl_ms must be <=31536000000"
    );
    Ok(())
}

/// 网关节点自注册管理器。
pub struct GatewaySelfRegistration {
    guard: Arc<AsyncMutex<Option<nasa::discovery::nacos::RegistrationGuard>>>,
    task: tokio::task::JoinHandle<()>,
}

impl GatewaySelfRegistration {
    /// 业务作用：启动网关节点自注册后台任务，并确保注册广告与所有 readiness 权威门一致。
    ///
    /// 参数说明：`snap` 感知配置热更；`ready`/`active_health`/`additional_ready` 分别提供
    /// listener、关键上游和 xDS 等附加控制权门禁。
    ///
    /// 返回：持有后台 task 与当前 Nacos registration guard 的管理器。
    pub fn spawn(
        snap: Arc<ArcSwap<GatewaySnapshot>>,
        ready: Arc<AtomicBool>,
        active_health: Arc<crate::health::ActiveHealthChecker>,
        additional_ready: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        let guard = Arc::new(AsyncMutex::new(None));
        let task_guard = guard.clone();
        let task = tokio::spawn(async move {
            run_gateway_self_registration(snap, ready, active_health, additional_ready, task_guard)
                .await;
        });
        Self { guard, task }
    }

    /// 优雅停机时显式注销当前注册实例。
    ///
    /// # 参数
    /// - `timeout_ms`: 注销等待上限。
    pub async fn deregister(self, timeout_ms: u64) {
        self.task.abort();
        let Some(guard) = self.guard.lock().await.take() else {
            return;
        };
        let timeout = Duration::from_millis(timeout_ms.max(100));
        match tokio::time::timeout(timeout, guard.deregister()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "gateway self-registration deregister failed"),
            Err(_) => tracing::warn!("gateway self-registration deregister timed out"),
        }
    }
}

#[derive(Clone, Debug)]
struct GatewayRegistrationSpec {
    cfg: NacosDiscoveryCfg,
    service_name: String,
    instance: nasa::discovery::Instance,
}

impl GatewayRegistrationSpec {
    /// 判定两次广告是否指向【同一个 Nacos 注册身份】。
    ///
    /// 身份相同的 weight/health/metadata 变化可通过 RegistrationGuard 原位 refresh，不需要
    /// deregister→register；只有本函数判定不同才必须替换注册身份。
    ///
    /// # 参数
    /// - `other`: 本轮期望广告的注册规格。
    fn same_nacos_registration_identity(&self, other: &Self) -> bool {
        self.service_name == other.service_name
            && self.instance.ip == other.instance.ip
            && self.instance.port == other.instance.port
            && self.instance.ephemeral == other.instance.ephemeral
            && self.instance.cluster_name == other.instance.cluster_name
            && self.cfg.server_addr == other.cfg.server_addr
            && self.cfg.namespace == other.cfg.namespace
            && self.cfg.group == other.cfg.group
            && self.cfg.app_name == other.cfg.app_name
            && self.cfg.discovery_ip == other.cfg.discovery_ip
            && self.cfg.username == other.cfg.username
            && self.cfg.password == other.cfg.password
    }

    fn same_nacos_registration_payload(&self, other: &Self) -> bool {
        self.instance.weight.to_bits() == other.instance.weight.to_bits()
            && self.instance.healthy == other.instance.healthy
            && self.instance.enabled == other.instance.enabled
            && self.instance.metadata == other.instance.metadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationAction {
    None,
    Register,
    Deregister,
    Refresh,
    Replace,
}

/// 计算本轮需要对 Nacos 做的最小注册动作。
///
/// 同身份 payload（包括自动 version 和运维 metadata）变化走原位 Refresh；地址/连接身份变化才
/// Replace。这样配置版本可被 consistency 端点及时看到，又不会因每次 reload 摘掉节点。
///
/// # 参数
/// - `registered`: 当前已生效的注册规格(`None` = 未注册)。
/// - `desired`: 本轮期望的注册规格(`None` = 本轮不应广告本节点)。
fn registration_action(
    registered: Option<&GatewayRegistrationSpec>,
    desired: Option<&GatewayRegistrationSpec>,
) -> RegistrationAction {
    match (registered, desired) {
        (None, None) => RegistrationAction::None,
        (None, Some(_)) => RegistrationAction::Register,
        (Some(_), None) => RegistrationAction::Deregister,
        (Some(current), Some(next)) if !current.same_nacos_registration_identity(next) => {
            RegistrationAction::Replace
        }
        (Some(current), Some(next)) if !current.same_nacos_registration_payload(next) => {
            RegistrationAction::Refresh
        }
        (Some(_), Some(_)) => RegistrationAction::None,
    }
}

/// 业务作用：持续把“真实可接流量”的本节点广告到 Nacos，并在任一 readiness 门关闭时注销。
///
/// 参数说明：`snap`/`ready`/`active_health`/`additional_ready` 共同形成有效就绪证据；`guard`
/// 持有当前外部注册副作用，供换身份与停机补偿。
///
/// 返回：后台循环正常不返回；task 被取消时由上层显式注销残留 registration。
async fn run_gateway_self_registration(
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    ready: Arc<AtomicBool>,
    active_health: Arc<crate::health::ActiveHealthChecker>,
    additional_ready: Arc<dyn Fn() -> bool + Send + Sync>,
    guard: Arc<AsyncMutex<Option<nasa::discovery::nacos::RegistrationGuard>>>,
) {
    let mut registered: Option<GatewayRegistrationSpec> = None;
    loop {
        let current = snap.load();
        let desired = if gateway_advertised_ready(
            current.as_ref(),
            ready.load(Ordering::Acquire),
            &active_health,
            additional_ready(),
        ) {
            build_gateway_registration_spec(current.as_ref())
        } else {
            // 发现面与 `/readyz` 统一采用严格语义：listener 未就绪或任一 critical
            // route 无可用上游都不广告节点，恢复后由本循环重新注册。
            Ok(None)
        };
        match desired {
            Ok(desired) => match registration_action(registered.as_ref(), desired.as_ref()) {
                RegistrationAction::None => {}
                RegistrationAction::Deregister => {
                    if let Some(old) = registered.take() {
                        deregister_current_gateway(
                            &guard,
                            old.cfg.self_register.deregister_timeout_ms,
                        )
                        .await;
                    }
                }
                RegistrationAction::Register => {
                    let spec = desired.expect("registration action requires desired spec");
                    match register_gateway_spec(&spec).await {
                        Ok(new_guard) => {
                            *guard.lock().await = Some(new_guard);
                            tracing::info!(
                                service = %spec.service_name,
                                ip = %spec.instance.ip,
                                port = spec.instance.port,
                                "gateway self-registration applied"
                            );
                            registered = Some(spec);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "gateway self-registration failed; retrying");
                        }
                    }
                }
                RegistrationAction::Refresh => {
                    let spec = desired.expect("registration refresh requires desired spec");
                    match refresh_gateway_registration(&guard, &spec).await {
                        Ok(()) => registered = Some(spec),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "gateway self-registration refresh failed; keeping previous registration"
                        ),
                    }
                }
                RegistrationAction::Replace => {
                    if let Some(old) = registered.take() {
                        deregister_current_gateway(
                            &guard,
                            old.cfg.self_register.deregister_timeout_ms,
                        )
                        .await;
                    }
                    let spec = desired.expect("registration replace requires desired spec");
                    match register_gateway_spec(&spec).await {
                        Ok(new_guard) => {
                            *guard.lock().await = Some(new_guard);
                            tracing::info!(
                                service = %spec.service_name,
                                ip = %spec.instance.ip,
                                port = spec.instance.port,
                                "gateway self-registration applied"
                            );
                            registered = Some(spec);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "gateway self-registration failed; retrying");
                        }
                    }
                }
            },
            Err(e) => {
                if let Some(old) = registered.take() {
                    deregister_current_gateway(&guard, old.cfg.self_register.deregister_timeout_ms)
                        .await;
                }
                tracing::warn!(error = %e, "gateway self-registration config invalid; retrying");
            }
        }

        let backoff_ms = snap.load().discovery.nacos.reconnect_backoff_ms.max(100);
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
    }
}

async fn refresh_gateway_registration(
    guard: &Arc<AsyncMutex<Option<nasa::discovery::nacos::RegistrationGuard>>>,
    spec: &GatewayRegistrationSpec,
) -> anyhow::Result<()> {
    let mut slot = guard.lock().await;
    let current = slot
        .as_mut()
        .context("gateway registration guard is missing")?;
    let timeout = Duration::from_millis(spec.cfg.self_register.deregister_timeout_ms.max(100));
    tokio::time::timeout(timeout, current.refresh(spec.instance.clone()))
        .await
        .context("gateway self-registration refresh timed out")??;
    tracing::debug!(
        service = %spec.service_name,
        version = ?spec.instance.metadata.get("gateway.version"),
        "gateway self-registration metadata refreshed in place"
    );
    Ok(())
}

/// 业务作用：统一 self-registration 与 `/readyz` 的 listener、控制权和关键上游门禁口径。
///
/// 参数说明：`snap`/`active_health` 计算关键依赖；两个 bool 分别表示 listener 与附加控制面门。
///
/// 返回：所有门禁同时通过时才允许对外广告节点。
fn gateway_advertised_ready(
    snap: &GatewaySnapshot,
    listener_ready: bool,
    active_health: &crate::health::ActiveHealthChecker,
    additional_ready: bool,
) -> bool {
    listener_ready
        && additional_ready
        && crate::health::critical_upstreams_not_ready(snap, active_health).is_empty()
}

async fn deregister_current_gateway(
    guard: &Arc<AsyncMutex<Option<nasa::discovery::nacos::RegistrationGuard>>>,
    timeout_ms: u64,
) {
    let Some(current) = guard.lock().await.take() else {
        return;
    };
    let timeout = Duration::from_millis(timeout_ms.max(100));
    match tokio::time::timeout(timeout, current.deregister()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "gateway self-registration deregister failed"),
        Err(_) => tracing::warn!("gateway self-registration deregister timed out"),
    }
}

/// 进程启动时刻(Unix 毫秒)。只取一次:注册 payload 每次 refresh 都要带同一个值,
/// 否则集群视图会把同一节点误判成"刚重启"。
fn process_started_at_ms() -> u128 {
    static STARTED_AT_MS: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    *STARTED_AT_MS.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or_default()
    })
}

fn build_gateway_registration_spec(
    snap: &GatewaySnapshot,
) -> anyhow::Result<Option<GatewayRegistrationSpec>> {
    let mut cfg = snap.discovery.nacos.clone();
    if !cfg.enabled || !cfg.self_register.enabled {
        return Ok(None);
    }
    anyhow::ensure!(
        !cfg.server_addr.trim().is_empty(),
        "discovery.nacos.server_addr is required when self_register is enabled"
    );
    let service_name = trimmed_non_empty(Some(&cfg.self_register.service_name))
        .unwrap_or_else(|| cfg.app_name.trim().to_string());
    anyhow::ensure!(
        !service_name.is_empty(),
        "discovery.nacos.self_register.service_name or app_name is required"
    );
    let listen: SocketAddr = snap
        .listen
        .parse()
        .with_context(|| format!("invalid default proxy listen `{}`", snap.listen))?;
    let ip = resolve_gateway_registration_ip(&cfg, listen)?;
    let port = if cfg.self_register.port == 0 {
        listen.port()
    } else {
        cfg.self_register.port
    };
    anyhow::ensure!(port != 0, "self_register port cannot be 0");
    anyhow::ensure!(
        cfg.self_register.weight.is_finite() && cfg.self_register.weight >= 0.0,
        "self_register weight must be finite and >= 0"
    );

    let mut metadata = cfg.self_register.metadata.clone();
    metadata.insert("gateway.version".to_string(), snap.version.to_string());
    metadata.insert(
        "gateway.schema_version".to_string(),
        snap.schema_version.to_string(),
    );
    metadata.insert("gateway.listen".to_string(), snap.listen.clone());
    // P0-3 集群视图:节点上报**已上线**配置指纹与进程启动时刻,让 Console 能判断
    // "同版本但内容不同"(指纹分叉)以及节点新旧,而不是只看一个版本号。
    if let Some(fingerprint) = snap.config_fingerprint {
        metadata.insert("gateway.fingerprint".to_string(), fingerprint.to_string());
    }
    metadata.insert(
        "gateway.started_at_ms".to_string(),
        process_started_at_ms().to_string(),
    );
    metadata.insert(
        "gateway.admin_listen".to_string(),
        snap.admin_listen.clone(),
    );
    if let Some(edge) = snap.grpc_edge_cluster.as_deref() {
        if edge.membership == crate::config::model::GrpcEdgeMembershipCfg::Nacos {
            let advertised_ip: IpAddr = ip
                .parse()
                .context("validated gateway registration ip became invalid")?;
            let relay_ip = if edge.relay_listen.ip().is_unspecified() {
                advertised_ip
            } else {
                edge.relay_listen.ip()
            };
            let relay_addr = SocketAddr::new(relay_ip, edge.relay_listen.port());
            metadata.insert("gateway.edge.protocol".to_string(), "1".to_string());
            metadata.insert(
                "gateway.edge.cluster_id".to_string(),
                edge.cluster_id.to_string(),
            );
            metadata.insert("gateway.edge.node_id".to_string(), edge.node_id.to_string());
            metadata.insert(
                "gateway.edge.relay_addr".to_string(),
                relay_addr.to_string(),
            );
        }
    }
    if let Ok(node_id) = std::env::var("GW_NODE_ID") {
        if let Some(node_id) = trimmed_non_empty(Some(&node_id)) {
            metadata.insert("gateway.node_id".to_string(), node_id);
        }
    }

    let cluster = trimmed_non_empty(cfg.self_register.cluster.as_deref());
    // `nasa` 注册时会用 NacosProps.discovery_ip 覆盖 Instance.ip;注册专用 props 必须写入最终 IP,
    // 否则 self_register.ip 会被 discovery_ip 反向覆盖。
    cfg.discovery_ip = Some(ip.clone());
    let instance = nasa::discovery::Instance::new(ip, port)
        .with_weight(cfg.self_register.weight)
        .with_ephemeral(cfg.self_register.ephemeral)
        .with_cluster_opt(cluster)
        .with_metadata_map(metadata);
    Ok(Some(GatewayRegistrationSpec {
        cfg,
        service_name,
        instance,
    }))
}

fn resolve_gateway_registration_ip(
    cfg: &NacosDiscoveryCfg,
    listen: SocketAddr,
) -> anyhow::Result<String> {
    let configured = trimmed_non_empty(cfg.self_register.ip.as_deref())
        .or_else(|| trimmed_non_empty(cfg.discovery_ip.as_deref()));
    if let Some(ip) = configured {
        let parsed: IpAddr = ip
            .parse()
            .with_context(|| format!("invalid gateway self-register ip `{ip}`"))?;
        anyhow::ensure!(
            !parsed.is_unspecified(),
            "gateway self-register ip cannot be unspecified"
        );
        return Ok(parsed.to_string());
    }

    let listen_ip = listen.ip();
    anyhow::ensure!(
        !listen_ip.is_unspecified(),
        "gateway self-register ip is required when default proxy listen is wildcard"
    );
    Ok(listen_ip.to_string())
}

fn trimmed_non_empty(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

async fn register_gateway_spec(
    spec: &GatewayRegistrationSpec,
) -> anyhow::Result<nasa::discovery::nacos::RegistrationGuard> {
    let props = nacos_props(&spec.cfg);
    let client = nasa::discovery::nacos::NacosDiscoveryClient::connect(&props).await?;
    client
        .register(&spec.service_name, spec.instance.clone())
        .await
}

impl NacosDiscoveryManager {
    /// 以默认指标注册表构造管理器。
    pub fn new(dynamic: Arc<DynamicUpstreamStore>) -> Arc<Self> {
        Self::with_metrics(dynamic, Arc::new(Metrics::default()))
    }

    /// 构造共享管理器并接入进程级低基数指标。
    pub fn with_metrics(dynamic: Arc<DynamicUpstreamStore>, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            dynamic,
            metrics,
            tasks: Mutex::new(HashMap::new()),
            registry_tasks: Mutex::new(HashMap::new()),
        })
    }

    /// Reconcile Nacos watch tasks from the current immutable policy snapshot.
    /// This is intentionally synchronous: task startup/connect happens inside
    /// spawned async tasks, so reload never blocks on registry IO.
    pub fn reconcile(&self, snap: &GatewaySnapshot) {
        let cfg = snap.discovery.nacos.clone();
        let cfg_key = NacosTaskKey::from(&cfg);
        let mut desired = if cfg.enabled {
            snap.upstreams.nacos_watch_specs()
        } else {
            Vec::new()
        };
        desired.sort_by(|a, b| a.logical_service.cmp(&b.logical_service));

        let mut tasks = self.tasks.lock().expect("nacos discovery mutex poisoned");
        tasks.retain(|logical_service, task| {
            let keep = desired.iter().any(|spec| {
                spec.logical_service == *logical_service
                    && *spec == task.spec
                    && task.cfg_key == cfg_key
            });
            if !keep {
                task.handle.abort();
                self.dynamic.remove_service(logical_service);
            }
            keep
        });

        if !cfg.enabled {
            drop(tasks);
            self.reconcile_polling_registries(snap);
            return;
        }
        if cfg.server_addr.trim().is_empty() {
            tracing::error!("Nacos discovery enabled but discovery.nacos.server_addr is empty");
            drop(tasks);
            self.reconcile_polling_registries(snap);
            return;
        }

        for spec in desired {
            if tasks.contains_key(&spec.logical_service) {
                continue;
            }
            let handle = spawn_nacos_watch(cfg.clone(), spec.clone(), self.dynamic.clone());
            tasks.insert(
                spec.logical_service.clone(),
                WatchTask {
                    spec,
                    cfg_key: cfg_key.clone(),
                    handle,
                },
            );
        }
        drop(tasks);
        self.reconcile_polling_registries(snap);
    }

    fn reconcile_polling_registries(&self, snap: &GatewaySnapshot) {
        let mut desired = snap.upstreams.registry_watch_specs();
        desired.sort_by(|a, b| a.logical_service.cmp(&b.logical_service));
        let mut tasks = self
            .registry_tasks
            .lock()
            .expect("registry discovery mutex poisoned");
        tasks.retain(|logical_service, task| {
            let keep = desired.iter().any(|spec| {
                spec.logical_service == *logical_service
                    && *spec == task.spec
                    && polling_backend(&snap.discovery, spec.kind)
                        .as_ref()
                        .is_some_and(|backend| backend == &task.backend)
            });
            if !keep {
                task.handle.abort();
                self.dynamic.remove_service(logical_service);
            }
            keep
        });
        for spec in desired {
            if tasks.contains_key(&spec.logical_service) {
                continue;
            }
            let Some(backend) = polling_backend(&snap.discovery, spec.kind) else {
                tracing::error!(
                    service = %spec.logical_service,
                    registry = ?spec.kind,
                    "dynamic service references a disabled registry backend"
                );
                self.dynamic.remove_service(&spec.logical_service);
                continue;
            };
            let handle = spawn_registry_poll(
                backend.clone(),
                spec.clone(),
                self.dynamic.clone(),
                self.metrics.clone(),
            );
            tasks.insert(
                spec.logical_service.clone(),
                RegistryTask {
                    spec,
                    backend,
                    handle,
                },
            );
        }
    }
}

struct WatchTask {
    spec: NacosWatchSpec,
    cfg_key: NacosTaskKey,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, PartialEq, Eq)]
struct NacosTaskKey {
    server_addr: String,
    namespace: String,
    group: String,
    app_name: String,
    discovery_ip: Option<String>,
    username: String,
    password: String,
    poll_interval_ms: u64,
    reconnect_backoff_ms: u64,
}

impl From<&NacosDiscoveryCfg> for NacosTaskKey {
    fn from(cfg: &NacosDiscoveryCfg) -> Self {
        Self {
            server_addr: cfg.server_addr.clone(),
            namespace: cfg.namespace.clone(),
            group: cfg.group.clone(),
            app_name: cfg.app_name.clone(),
            discovery_ip: cfg.discovery_ip.clone(),
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            poll_interval_ms: cfg.poll_interval_ms,
            reconnect_backoff_ms: cfg.reconnect_backoff_ms,
        }
    }
}

struct RegistryTask {
    spec: RegistryWatchSpec,
    backend: PollingBackend,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, PartialEq, Eq)]
enum PollingBackend {
    Consul(ConsulDiscoveryCfg),
    Eureka(EurekaDiscoveryCfg),
    Dns(DnsDiscoveryCfg),
    Kubernetes(KubernetesDiscoveryCfg),
}

fn polling_backend(cfg: &DiscoveryCfg, kind: RegistryKind) -> Option<PollingBackend> {
    match kind {
        RegistryKind::Consul if cfg.consul.enabled => {
            Some(PollingBackend::Consul(cfg.consul.clone()))
        }
        RegistryKind::Eureka if cfg.eureka.enabled => {
            Some(PollingBackend::Eureka(cfg.eureka.clone()))
        }
        RegistryKind::Dns if cfg.dns.enabled => Some(PollingBackend::Dns(cfg.dns.clone())),
        RegistryKind::Kubernetes if cfg.kubernetes.enabled => {
            Some(PollingBackend::Kubernetes(cfg.kubernetes.clone()))
        }
        _ => None,
    }
}

fn spawn_registry_poll(
    backend: PollingBackend,
    spec: RegistryWatchSpec,
    dynamic: Arc<DynamicUpstreamStore>,
    metrics: Arc<Metrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = match build_registry_http_client(&backend) {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(service = %spec.logical_service, %error, "build registry HTTP client failed");
                return;
            }
        };
        let interval = Duration::from_millis(registry_poll_interval_ms(&backend));
        let timeout = Duration::from_millis(registry_timeout_ms(&backend));
        loop {
            let attempt =
                tokio::time::timeout(timeout, fetch_registry_instances(&client, &backend, &spec))
                    .await;
            match attempt {
                Ok(Ok(discovered)) => match registry_instances_to_upstreams(&spec, discovered) {
                    Ok(upstreams) => {
                        let count = upstreams.len();
                        dynamic.replace_service(&spec.logical_service, upstreams);
                        metrics.inc_registry_poll(
                            registry_metric_backend(spec.kind),
                            RegistryPollMetric::Success,
                        );
                        tracing::debug!(
                            service = %spec.logical_service,
                            registry = ?spec.kind,
                            instances = count,
                            "registry upstream snapshot applied"
                        );
                    }
                    Err(error) => {
                        metrics.inc_registry_poll(
                            registry_metric_backend(spec.kind),
                            RegistryPollMetric::InvalidSnapshot,
                        );
                        tracing::warn!(
                            service = %spec.logical_service,
                            registry = ?spec.kind,
                            %error,
                            "invalid registry snapshot; keeping last-known-good"
                        );
                    }
                },
                Ok(Err(error)) => {
                    metrics.inc_registry_poll(
                        registry_metric_backend(spec.kind),
                        RegistryPollMetric::Error,
                    );
                    tracing::warn!(
                        service = %spec.logical_service,
                        registry = ?spec.kind,
                        %error,
                        "registry poll failed; keeping last-known-good"
                    );
                }
                Err(_) => {
                    metrics.inc_registry_poll(
                        registry_metric_backend(spec.kind),
                        RegistryPollMetric::Timeout,
                    );
                    tracing::warn!(
                        service = %spec.logical_service,
                        registry = ?spec.kind,
                        timeout_ms = registry_timeout_ms(&backend),
                        "registry poll timed out; keeping last-known-good"
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

fn registry_metric_backend(kind: RegistryKind) -> RegistryBackendMetric {
    match kind {
        RegistryKind::Consul => RegistryBackendMetric::Consul,
        RegistryKind::Eureka => RegistryBackendMetric::Eureka,
        RegistryKind::Dns => RegistryBackendMetric::Dns,
        RegistryKind::Kubernetes => RegistryBackendMetric::Kubernetes,
    }
}

fn build_registry_http_client(backend: &PollingBackend) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if let PollingBackend::Kubernetes(cfg) = backend {
        if !cfg.ca_certificate.is_empty() {
            let certificate = reqwest::Certificate::from_pem(cfg.ca_certificate.as_bytes())
                .context("parse discovery.kubernetes.ca_certificate")?;
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder.build().context("build registry HTTP client")
}

fn registry_poll_interval_ms(backend: &PollingBackend) -> u64 {
    match backend {
        PollingBackend::Consul(cfg) => cfg.poll_interval_ms,
        PollingBackend::Eureka(cfg) => cfg.poll_interval_ms,
        PollingBackend::Dns(cfg) => cfg.poll_interval_ms,
        PollingBackend::Kubernetes(cfg) => cfg.poll_interval_ms,
    }
}

fn registry_timeout_ms(backend: &PollingBackend) -> u64 {
    match backend {
        PollingBackend::Consul(cfg) => cfg.request_timeout_ms,
        PollingBackend::Eureka(cfg) => cfg.request_timeout_ms,
        PollingBackend::Dns(cfg) => cfg.request_timeout_ms,
        PollingBackend::Kubernetes(cfg) => cfg.request_timeout_ms,
    }
}

async fn fetch_registry_instances(
    client: &reqwest::Client,
    backend: &PollingBackend,
    spec: &RegistryWatchSpec,
) -> anyhow::Result<Vec<RegistryInstance>> {
    match backend {
        PollingBackend::Consul(cfg) => fetch_consul(client, cfg, spec).await,
        PollingBackend::Eureka(cfg) => fetch_eureka(client, cfg, spec).await,
        PollingBackend::Dns(cfg) => fetch_dns(cfg, spec).await,
        PollingBackend::Kubernetes(cfg) => fetch_kubernetes(client, cfg, spec).await,
    }
}

async fn fetch_consul(
    client: &reqwest::Client,
    cfg: &ConsulDiscoveryCfg,
    spec: &RegistryWatchSpec,
) -> anyhow::Result<Vec<RegistryInstance>> {
    let service = percent_encoding::utf8_percent_encode(
        &spec.registry_service,
        percent_encoding::NON_ALPHANUMERIC,
    );
    let mut url = reqwest::Url::parse(&format!("{}/v1/health/service/{service}", cfg.base_url))?;
    {
        let mut query = url.query_pairs_mut();
        if cfg.passing_only {
            query.append_pair("passing", "true");
        }
        if !cfg.datacenter.is_empty() {
            query.append_pair("dc", &cfg.datacenter);
        }
        if !cfg.tag.is_empty() {
            query.append_pair("tag", &cfg.tag);
        }
    }
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if !cfg.token.is_empty() {
        request = request.header("x-consul-token", &cfg.token);
    }
    let value = fetch_bounded_json(request, cfg.max_response_bytes).await?;
    let Some(items) = value.as_array() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        bail!("Consul response must be a JSON array");
    };
    if items.len() > cfg.max_instances {
        bail!("Consul response exceeds max_instances");
    }
    let mut instances = Vec::with_capacity(items.len());
    for item in items {
        let service = item.get("Service").context("Consul item missing Service")?;
        let node = item.get("Node").unwrap_or(&Value::Null);
        let host = string_field(service, "Address")
            .or_else(|| string_field(node, "Address"))
            .context("Consul instance missing address")?;
        let port = u16_field(service.get("Port")).context("Consul instance missing port")?;
        let passing = item
            .get("Checks")
            .and_then(Value::as_array)
            .map(|checks| {
                checks
                    .iter()
                    .all(|check| string_field(check, "Status").as_deref() == Some("passing"))
            })
            .unwrap_or(true);
        let weight = service
            .get("Weights")
            .and_then(|weights| weights.get("Passing"))
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(1)
            .max(1);
        let metadata = string_map(service.get("Meta"));
        instances.push(RegistryInstance {
            host,
            port,
            weight,
            down: !passing,
            backup: metadata_bool_value(&metadata, "gateway.backup"),
            metadata,
        });
    }
    Ok(instances)
}

async fn fetch_eureka(
    client: &reqwest::Client,
    cfg: &EurekaDiscoveryCfg,
    spec: &RegistryWatchSpec,
) -> anyhow::Result<Vec<RegistryInstance>> {
    let app = percent_encoding::utf8_percent_encode(
        &spec.registry_service,
        percent_encoding::NON_ALPHANUMERIC,
    );
    let url = format!("{}/eureka/apps/{app}", cfg.base_url);
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if !cfg.username.is_empty() || !cfg.password.is_empty() {
        request = request.basic_auth(&cfg.username, Some(&cfg.password));
    }
    let value = fetch_bounded_json(request, cfg.max_response_bytes).await?;
    let application = value.get("application").or_else(|| {
        value
            .get("applications")
            .and_then(|apps| apps.get("application"))
    });
    let Some(application) = application else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        bail!("Eureka response missing application");
    };
    let applications: Vec<&Value> = match application {
        Value::Array(values) => values.iter().collect(),
        other => vec![other],
    };
    let mut instances = Vec::new();
    for application in applications {
        let Some(raw_instances) = application.get("instance") else {
            continue;
        };
        let items: Vec<&Value> = match raw_instances {
            Value::Array(values) => values.iter().collect(),
            other => vec![other],
        };
        for item in items {
            if instances.len() >= cfg.max_instances {
                bail!("Eureka response exceeds max_instances");
            }
            if string_field(item, "status").is_some_and(|status| !status.eq_ignore_ascii_case("UP"))
            {
                continue;
            }
            let host = string_field(item, "ipAddr")
                .or_else(|| string_field(item, "hostName"))
                .context("Eureka instance missing ipAddr/hostName")?;
            let port = u16_field(item.get("port")).context("Eureka instance missing port")?;
            let metadata = string_map(item.get("metadata"));
            instances.push(RegistryInstance {
                host,
                port,
                weight: 1,
                down: false,
                backup: metadata_bool_value(&metadata, "gateway.backup"),
                metadata,
            });
        }
    }
    Ok(instances)
}

async fn fetch_dns(
    cfg: &DnsDiscoveryCfg,
    spec: &RegistryWatchSpec,
) -> anyhow::Result<Vec<RegistryInstance>> {
    let port = spec
        .port
        .context("DNS registry service requires registry_port")?;
    anyhow::ensure!(port > 0, "DNS registry_port cannot be zero");
    let resolved = tokio::net::lookup_host((spec.registry_service.as_str(), port))
        .await
        .context("resolve DNS registry service")?;
    let mut addresses = resolved.collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    if addresses.len() > cfg.max_addresses {
        bail!("DNS response exceeds max_addresses");
    }
    Ok(addresses
        .into_iter()
        .map(|address| RegistryInstance {
            host: address.ip().to_string(),
            port: address.port(),
            weight: 1,
            down: false,
            backup: false,
            metadata: HashMap::from([("registry".to_owned(), "dns".to_owned())]),
        })
        .collect())
}

async fn fetch_kubernetes(
    client: &reqwest::Client,
    cfg: &KubernetesDiscoveryCfg,
    spec: &RegistryWatchSpec,
) -> anyhow::Result<Vec<RegistryInstance>> {
    let namespace = spec.namespace.as_deref().unwrap_or(&cfg.namespace);
    let encoded_namespace =
        percent_encoding::utf8_percent_encode(namespace, percent_encoding::NON_ALPHANUMERIC);
    let service = percent_encoding::utf8_percent_encode(
        &spec.registry_service,
        percent_encoding::NON_ALPHANUMERIC,
    );
    let port_selector = match (spec.port_name.as_deref(), spec.port) {
        (Some(name), _) => KubernetesEndpointPortSelector::Name(name.to_owned()),
        (None, Some(port)) => {
            if spec.service_import {
                KubernetesEndpointPortSelector::Number(port)
            } else {
                resolve_kubernetes_service_port(
                    client,
                    cfg,
                    namespace,
                    &spec.registry_service,
                    port,
                )
                .await?
            }
        }
        (None, None) => KubernetesEndpointPortSelector::Single,
    };
    let value = if spec.service_import {
        Value::Null
    } else {
        let url = format!(
            "{}/api/v1/namespaces/{encoded_namespace}/endpoints/{service}",
            cfg.api_server
        );
        fetch_kubernetes_object(client, cfg, url).await?
    };
    let subsets = value
        .get("subsets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if subsets.is_empty() {
        let selector = if spec.service_import {
            format!(
                "multicluster.kubernetes.io/service-name={}",
                spec.registry_service
            )
        } else {
            format!("kubernetes.io/service-name={}", spec.registry_service)
        };
        let encoded_selector =
            percent_encoding::utf8_percent_encode(&selector, percent_encoding::NON_ALPHANUMERIC);
        let slices_url = format!(
            "{}/apis/discovery.k8s.io/v1/namespaces/{encoded_namespace}/endpointslices?labelSelector={encoded_selector}",
            cfg.api_server
        );
        let slices = fetch_kubernetes_object(client, cfg, slices_url).await?;
        if let Some(instances) = parse_kubernetes_endpoint_slices(
            &slices,
            &port_selector,
            namespace,
            spec.service_import,
            cfg.max_instances,
        )? {
            return Ok(instances);
        }
    }
    let mut instances = Vec::new();
    for subset in subsets {
        let ports = subset
            .get("ports")
            .and_then(Value::as_array)
            .context("Kubernetes endpoint subset missing ports")?;
        let port = select_kubernetes_endpoint_port(ports, &port_selector)?;
        let addresses = subset
            .get("addresses")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for address in addresses {
            if instances.len() >= cfg.max_instances {
                bail!("Kubernetes response exceeds max_instances");
            }
            let host = string_field(&address, "ip")
                .or_else(|| string_field(&address, "hostname"))
                .context("Kubernetes endpoint address missing ip/hostname")?;
            let mut metadata = HashMap::from([
                ("registry".to_owned(), "kubernetes".to_owned()),
                ("namespace".to_owned(), namespace.to_owned()),
            ]);
            if let Some(name) = address
                .get("targetRef")
                .and_then(|target| string_field(target, "name"))
            {
                metadata.insert("target".to_owned(), name);
            }
            instances.push(RegistryInstance {
                host,
                port,
                weight: 1,
                down: false,
                backup: false,
                metadata,
            });
        }
    }
    Ok(instances)
}

/// 业务作用：解析 discovery.k8s.io/v1 EndpointSlice，为无 legacy Endpoints 的
/// selectorless、headless 和新集群 Service 提供真实后端。
///
/// 参数说明：`value` 是按 service-name label 筛选后的 LIST；`port_selector` 已由
/// Service port/targetPort 解析；`namespace` 进入低基数 metadata；`max_instances` 是硬上限。
///
/// 返回：API 不可用或 LIST 无对象时返回 None 以允许 legacy 结果；存在 slice 时返回
/// 去重后的 ready、非 terminating 地址（可为空）；坏结构或超限返回错误并保留 LKG。
fn parse_kubernetes_endpoint_slices(
    value: &Value,
    port_selector: &KubernetesEndpointPortSelector,
    namespace: &str,
    service_import: bool,
    max_instances: usize,
) -> anyhow::Result<Option<Vec<RegistryInstance>>> {
    if value.is_null() {
        return Ok(None);
    }
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .context("Kubernetes EndpointSlice LIST missing items")?;
    if items.is_empty() {
        return Ok(None);
    }
    let mut instances = Vec::new();
    let mut seen = HashSet::new();
    for slice in items {
        let ports = slice
            .get("ports")
            .and_then(Value::as_array)
            .context("Kubernetes EndpointSlice missing ports")?;
        let port = match select_kubernetes_endpoint_port(ports, port_selector) {
            Ok(port) => port,
            Err(_) => continue,
        };
        // EndpointSlice 使用 omitempty；单栈集群中另一地址族的空 slice 会完全省略
        // endpoints。这里必须把缺省视为空集合，否则一个合法空 slice 会连带屏蔽同组
        // 已就绪地址，令整个 Service 错误进入无上游状态。
        let endpoints = slice
            .get("endpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for endpoint in endpoints {
            let ready = endpoint
                .pointer("/conditions/ready")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let terminating = endpoint
                .pointer("/conditions/terminating")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !ready || terminating {
                continue;
            }
            let addresses = endpoint
                .get("addresses")
                .and_then(Value::as_array)
                .context("Kubernetes EndpointSlice endpoint missing addresses")?;
            for address in addresses {
                let host = address
                    .as_str()
                    .filter(|host| !host.is_empty() && host.len() <= 253)
                    .context("Kubernetes EndpointSlice address is invalid")?;
                if !seen.insert((host.to_owned(), port)) {
                    continue;
                }
                anyhow::ensure!(
                    instances.len() < max_instances,
                    "Kubernetes EndpointSlice response exceeds max_instances"
                );
                let mut metadata = HashMap::from([
                    ("registry".to_owned(), "kubernetes".to_owned()),
                    ("namespace".to_owned(), namespace.to_owned()),
                ]);
                if service_import {
                    metadata.insert("service_import".to_owned(), "true".to_owned());
                    if let Some(cluster) = slice
                        .pointer("/metadata/labels/multicluster.kubernetes.io~1source-cluster")
                        .and_then(Value::as_str)
                    {
                        metadata.insert("cluster".to_owned(), cluster.to_owned());
                    }
                }
                if let Some(zone) = endpoint.get("zone").and_then(Value::as_str).or_else(|| {
                    endpoint
                        .pointer("/topology/topology.kubernetes.io~1zone")
                        .and_then(Value::as_str)
                }) {
                    metadata.insert("zone".to_owned(), zone.to_owned());
                }
                if let Some(name) = endpoint
                    .get("targetRef")
                    .and_then(|target| string_field(target, "name"))
                {
                    metadata.insert("target".to_owned(), name);
                }
                instances.push(RegistryInstance {
                    host: host.to_owned(),
                    port,
                    weight: 1,
                    down: false,
                    backup: false,
                    metadata,
                });
            }
        }
    }
    anyhow::ensure!(
        !instances.is_empty()
            || items.iter().all(|slice| {
                slice
                    .get("endpoints")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
            }),
        "Kubernetes EndpointSlice set has no usable port or ready endpoint"
    );
    Ok(Some(instances))
}

/// 业务作用：按已解析的 Service port 选择 Endpoints/EndpointSlice 中的实际端口，
/// 保证两种发现对象使用相同 targetPort 语义。
///
/// 参数说明：`ports` 是对象端口数组；`selector` 是 name、number 或唯一端口门禁。
///
/// 返回：匹配且合法的端口返回 u16；缺失、歧义或坏值返回错误。
fn select_kubernetes_endpoint_port(
    ports: &[Value],
    selector: &KubernetesEndpointPortSelector,
) -> anyhow::Result<u16> {
    match selector {
        KubernetesEndpointPortSelector::Name(name) => ports
            .iter()
            .find(|port| string_field(port, "name").as_deref() == Some(name.as_str()))
            .and_then(|port| u16_field(port.get("port")))
            .with_context(|| format!("Kubernetes endpoint has no port named `{name}`")),
        KubernetesEndpointPortSelector::Number(number) => ports
            .iter()
            .find(|port| u16_field(port.get("port")) == Some(*number))
            .and_then(|port| u16_field(port.get("port")))
            .with_context(|| format!("Kubernetes endpoint has no target port `{number}`")),
        KubernetesEndpointPortSelector::Single => {
            anyhow::ensure!(
                ports.len() == 1,
                "Kubernetes endpoint has multiple ports; registry_port_name is required"
            );
            u16_field(ports[0].get("port")).context("Kubernetes endpoint port invalid")
        }
    }
}

enum KubernetesEndpointPortSelector {
    Name(String),
    Number(u16),
    Single,
}

/// 业务作用：将 Gateway/Ingress 引用的 Service port 编号解析为 Endpoints 中的
/// port name 或 Pod targetPort，避免把虚拟 Service port 与实际端点端口误作相等。
///
/// 参数说明：transport 参数限定 API 和凭据；`namespace`/`service_name` 是已验证
/// Kubernetes 身份；`service_port` 是 Route backendRef 的数字端口。
///
/// 返回：Service port 存在时优先返回稳定 port name，无 name 时返回数字或命名
/// targetPort；Service 缺失、结构坏或端口不存在时保留上游 LKG。
async fn resolve_kubernetes_service_port(
    client: &reqwest::Client,
    cfg: &KubernetesDiscoveryCfg,
    namespace: &str,
    service_name: &str,
    service_port: u16,
) -> anyhow::Result<KubernetesEndpointPortSelector> {
    let encoded_namespace =
        percent_encoding::utf8_percent_encode(namespace, percent_encoding::NON_ALPHANUMERIC);
    let service =
        percent_encoding::utf8_percent_encode(service_name, percent_encoding::NON_ALPHANUMERIC);
    let url = format!(
        "{}/api/v1/namespaces/{encoded_namespace}/services/{service}",
        cfg.api_server
    );
    let value = fetch_kubernetes_object(client, cfg, url).await?;
    anyhow::ensure!(!value.is_null(), "Kubernetes Service does not exist");
    let ports = value
        .pointer("/spec/ports")
        .and_then(Value::as_array)
        .context("Kubernetes Service missing spec.ports")?;
    let port = ports
        .iter()
        .find(|port| u16_field(port.get("port")) == Some(service_port))
        .with_context(|| format!("Kubernetes Service has no port `{service_port}`"))?;
    if let Some(name) = string_field(port, "name").filter(|name| !name.is_empty()) {
        return Ok(KubernetesEndpointPortSelector::Name(name));
    }
    match port.get("targetPort") {
        Some(Value::String(name)) if !name.is_empty() => {
            Ok(KubernetesEndpointPortSelector::Name(name.clone()))
        }
        Some(value) => u16_field(Some(value))
            .map(KubernetesEndpointPortSelector::Number)
            .context("Kubernetes Service targetPort is invalid"),
        None => Ok(KubernetesEndpointPortSelector::Number(service_port)),
    }
}

/// 业务作用：以统一凭据和响应大小门禁读取单个 Kubernetes core API 对象。
///
/// 参数说明：`url` 只由已 percent-encode 的 namespace/resource name 构造；`cfg`
/// 提供 bearer token 和字节上限。
///
/// 返回：2xx 返回有界 JSON，404 返回 Null，transport、RBAC、超限或 JSON 错误失败。
async fn fetch_kubernetes_object(
    client: &reqwest::Client,
    cfg: &KubernetesDiscoveryCfg,
    url: String,
) -> anyhow::Result<Value> {
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if !cfg.bearer_token.is_empty() {
        request = request.bearer_auth(&cfg.bearer_token);
    }
    fetch_bounded_json(request, cfg.max_response_bytes).await
}

async fn fetch_bounded_json(
    request: reqwest::RequestBuilder,
    max_bytes: usize,
) -> anyhow::Result<Value> {
    let response = request.send().await.context("send registry request")?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Value::Null);
    }
    let declared_length = response.content_length();
    if let Some(length) = declared_length {
        if length > max_bytes as u64 {
            bail!("registry response Content-Length exceeds max_response_bytes");
        }
    }
    // JSON provider APIs cannot be parsed without owning their complete document. We therefore
    // perform exactly one bounded accumulation; Content-Length (when present) pre-sizes the buffer
    // to avoid geometric reallocations, while the streamed hard check also protects chunked bodies.
    let capacity = declared_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut body = BytesMut::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read registry response chunk")?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            bail!("registry response exceeds max_response_bytes");
        }
        body.extend_from_slice(&chunk);
    }
    anyhow::ensure!(status.is_success(), "registry returned HTTP {status}");
    serde_json::from_slice(&body).context("decode registry JSON")
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn u16_field(value: Option<&Value>) -> Option<u16> {
    let value = value?;
    let value = value.get("$").unwrap_or(value);
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .or_else(|| value.as_str()?.parse().ok())
}

fn string_map(value: Option<&Value>) -> HashMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| match value {
                    Value::String(value) => Some((key.clone(), value.clone())),
                    Value::Number(value) => Some((key.clone(), value.to_string())),
                    Value::Bool(value) => Some((key.clone(), value.to_string())),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn metadata_bool_value(metadata: &HashMap<String, String>, key: &str) -> bool {
    metadata
        .get(key)
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn spawn_nacos_watch(
    cfg: NacosDiscoveryCfg,
    spec: NacosWatchSpec,
    dynamic: Arc<DynamicUpstreamStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let reconnect_backoff = Duration::from_millis(cfg.reconnect_backoff_ms.max(100));
        loop {
            if let Err(e) = run_nacos_watch_once(&cfg, &spec, &dynamic).await {
                tracing::warn!(
                    service = %spec.logical_service,
                    nacos_service = %spec.nacos_service,
                    error = %e,
                    "Nacos watch failed; keeping last-known-good and reconnecting"
                );
            }
            tokio::time::sleep(reconnect_backoff).await;
        }
    })
}

async fn run_nacos_watch_once(
    cfg: &NacosDiscoveryCfg,
    spec: &NacosWatchSpec,
    dynamic: &Arc<DynamicUpstreamStore>,
) -> anyhow::Result<()> {
    let props = nacos_props(cfg);
    let client = nasa::discovery::nacos::NacosDiscoveryClient::connect(&props).await?;
    let options = nasa::discovery::nacos::SubscribeOptions::new()
        .with_poll_interval(Duration::from_millis(cfg.poll_interval_ms.max(100)))
        .with_clusters(spec.clusters.clone());
    let (guard, mut rx) = client
        .subscribe_channel_with_options(&spec.nacos_service, options)
        .await?;
    let _guard = guard;

    let initial = rx.borrow().clone();
    apply_discovery_snapshot(dynamic, spec, &initial);
    // ★N1:watch 存活期间周期性「触活」last-known-good★。Nacos 对稳定不变的服务不会重复推送,
    //   若不触活,updated_at 会停在上次【变更】时刻,超过 stale_ttl 后 service_fresh 误判 stale →
    //   critical readyz 无谓抖到 503、被前置 LB 摘流。触活周期取 poll 间隔;watch 一旦断
    //   (`rx.changed()` Err → 本函数返回、交 spawn_nacos_watch 重连退避),触活随之停止 → stale_ttl 正常计时降级。
    let mut liveness = tokio::time::interval(Duration::from_millis(cfg.poll_interval_ms.max(100)));
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    liveness.tick().await; // 首个 tick 立即就绪,丢弃——刚 apply 过、不必立即再触活。
    loop {
        tokio::select! {
            changed = rx.changed() => {
                // watch 关闭 → Err → 退出本次 run(由外层重连退避);停止触活,让 stale_ttl 正常计时。
                changed?;
                let snapshot = rx.borrow().clone();
                apply_discovery_snapshot(dynamic, spec, &snapshot);
            }
            _ = liveness.tick() => {
                // watch 仍连着、服务无变更:仅刷新 fresh 时间戳(不改实例),保持 service_fresh=true。
                dynamic.touch_service(&spec.logical_service);
            }
        }
    }
}

pub(crate) fn nacos_props(cfg: &NacosDiscoveryCfg) -> nasa::discovery::nacos::NacosProps {
    let mut props = nasa::discovery::nacos::NacosProps::new(&cfg.server_addr)
        .with_namespace(&cfg.namespace)
        .with_group(&cfg.group)
        .with_app_name(&cfg.app_name)
        .with_discovery_ip_opt(cfg.discovery_ip.as_deref());
    if !cfg.username.is_empty() || !cfg.password.is_empty() {
        props = props.with_auth(&cfg.username, &cfg.password);
    }
    props
}

/// 解析本网关自注册用的 Nacos 服务名(与 [`build_gateway_registration_spec`] 同一口径:
/// `self_register.service_name` 非空则用它,否则回退 `app_name`)。
///
/// 供 `/admin/cluster/consistency` 反查本网关集群成员时定位服务名。
///
/// # 参数
/// - `cfg`: `discovery.nacos` 配置。
///
/// # 返回
/// 服务名;`self_register`/`enabled` 关闭或名字为空时返回 `None`。
pub(crate) fn self_register_service_name(cfg: &NacosDiscoveryCfg) -> Option<String> {
    if !cfg.enabled || !cfg.self_register.enabled {
        return None;
    }
    trimmed_non_empty(Some(&cfg.self_register.service_name))
        .or_else(|| trimmed_non_empty(Some(&cfg.app_name)))
}

fn apply_discovery_snapshot(
    dynamic: &Arc<DynamicUpstreamStore>,
    spec: &NacosWatchSpec,
    instances: &[nasa::discovery::Instance],
) {
    match discovery_instances_to_upstreams(spec, instances) {
        Ok(upstreams) => {
            let count = upstreams.len();
            dynamic.replace_service(&spec.logical_service, upstreams);
            tracing::info!(
                service = %spec.logical_service,
                nacos_service = %spec.nacos_service,
                instances = count,
                "Nacos upstream snapshot applied"
            );
        }
        Err(e) => {
            tracing::warn!(
                service = %spec.logical_service,
                nacos_service = %spec.nacos_service,
                error = %e,
                "skip invalid Nacos upstream snapshot"
            );
        }
    }
}
