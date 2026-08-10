//! 主动健康探测(§5.1)。
//!
//! 后台任务按服务配置的间隔 TCP/HTTP 探测每个上游实例,连续成功/失败达阈值即翻转健康态。
//! 数据面热路径只读一个 `ArcSwap<HashSet<String>>`(当前不健康 URI 集合),选实例时把它并入
//! `excluded`,与被动摘除(§5.1)叠加成「主动探测 + 被动摘除」双保险。探测本身只发生在后台任务,
//! 绝不进入请求热路径。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(feature = "http3")]
use anyhow::Context as _;
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Empty, Full};
use hyper::header::{CONTENT_TYPE, TE};
use hyper::{Method, Request, Version};
use hyper_rustls::FixedServerNameResolver;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::config::model::HealthCheckCfg;
use crate::config::GatewaySnapshot;
use crate::metrics::Metrics;
use crate::tls::UpstreamTlsProfile;
use crate::upstream::UpstreamProtocol;

type ProbeHttpClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;
type ProbeTlsClientPool = HashMap<Arc<str>, ProbeHttpClient>;
type ProbeGrpcClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
type ProbeGrpcTlsClientPool = HashMap<Arc<str>, ProbeGrpcClient>;

const GRPC_HEALTH_PATH: &str = "/grpc.health.v1.Health/Check";
const GRPC_HEALTH_MAX_SERVICE_BYTES: usize = 1024;
const GRPC_HEALTH_MAX_RESPONSE_BYTES: usize = 1024;

/// 探测方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthKind {
    /// TCP connect 成功即健康(协议无关,适用于 MySQL/Redis/gRPC 等任意 TCP 上游)。
    Tcp,
    /// HTTP GET 指定 path,按状态码判健康。
    Http,
    /// 标准 `grpc.health.v1.Health/Check`；仅 `SERVING` 且 `grpc-status=0` 算健康。
    Grpc,
    /// 发送固定小 datagram 并等待响应；不进入数据面 session table。
    Udp,
}

/// 从 yml `health_check` 编译出的主动健康策略。无 `health_check` 段 = 关闭。
#[derive(Clone)]
pub struct ActiveHealthPolicy {
    kind: HealthKind,
    path: String,
    interval: Duration,
    jitter: Duration,
    timeout: Duration,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    expected_status: Option<u16>,
    grpc_service: Arc<str>,
    udp_payload: Bytes,
    udp_expected_response: Option<Bytes>,
}

impl ActiveHealthPolicy {
    /// 业务作用：在快照构建期把主动健康配置编译为有界策略，拒绝协议字段混用、
    /// 失控 deadline/阈值与会造成忙轮询的抖动预算。
    ///
    /// 参数说明：`cfg` 是单个 service 的声明式健康检查配置。
    ///
    /// 返回：成功时返回可由后台任务共享的不可变策略；非法配置返回错误并阻止快照上线。
    pub fn parse(cfg: &HealthCheckCfg) -> anyhow::Result<Self> {
        let kind = match cfg.r#type.trim().to_ascii_lowercase().as_str() {
            "tcp" => HealthKind::Tcp,
            "http" => HealthKind::Http,
            "grpc" => HealthKind::Grpc,
            "udp" => HealthKind::Udp,
            other => anyhow::bail!("unsupported health_check type `{other}` (tcp|http|grpc|udp)"),
        };
        if kind != HealthKind::Udp
            && (!cfg.udp_payload.is_empty() || cfg.udp_expected_response.is_some())
        {
            anyhow::bail!("UDP health fields require health_check type=udp");
        }
        if kind == HealthKind::Udp && cfg.udp_payload.is_empty() {
            anyhow::bail!("UDP health check requires a non-empty udp_payload");
        }
        if kind != HealthKind::Grpc && !cfg.grpc_service.is_empty() {
            anyhow::bail!("grpc_service requires health_check type=grpc");
        }
        if kind == HealthKind::Grpc {
            anyhow::ensure!(
                cfg.expected_status.is_none(),
                "gRPC health check does not accept expected_status"
            );
            anyhow::ensure!(
                cfg.grpc_service.len() <= GRPC_HEALTH_MAX_SERVICE_BYTES,
                "health_check.grpc_service must be <=1024 bytes"
            );
            anyhow::ensure!(
                !cfg.grpc_service.chars().any(char::is_control),
                "health_check.grpc_service cannot contain control characters"
            );
        }
        if cfg.udp_payload.len() > 4096
            || cfg
                .udp_expected_response
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
        {
            anyhow::bail!("UDP health payload/expected response must be <= 4096 bytes");
        }
        anyhow::ensure!(
            (100..=3_600_000).contains(&cfg.interval_ms),
            "health_check.interval_ms must be within 100..=3600000"
        );
        anyhow::ensure!(
            cfg.jitter_ms <= cfg.interval_ms / 2,
            "health_check.jitter_ms must not exceed half of interval_ms"
        );
        anyhow::ensure!(
            (50..=60_000).contains(&cfg.timeout_ms),
            "health_check.timeout_ms must be within 50..=60000"
        );
        anyhow::ensure!(
            (1..=1_000_000).contains(&cfg.healthy_threshold)
                && (1..=1_000_000).contains(&cfg.unhealthy_threshold),
            "health_check healthy/unhealthy thresholds must be within 1..=1000000"
        );
        anyhow::ensure!(
            cfg.path.len() <= 8 * 1024,
            "health_check.path must be <=8192 bytes"
        );
        if let Some(status) = cfg.expected_status {
            anyhow::ensure!(
                (100..=599).contains(&status),
                "health_check.expected_status must be within 100..=599"
            );
        }
        let path = if cfg.path.starts_with('/') {
            cfg.path.clone()
        } else {
            format!("/{}", cfg.path)
        };
        Ok(Self {
            kind,
            path,
            interval: Duration::from_millis(cfg.interval_ms),
            jitter: Duration::from_millis(cfg.jitter_ms),
            timeout: Duration::from_millis(cfg.timeout_ms),
            healthy_threshold: cfg.healthy_threshold,
            unhealthy_threshold: cfg.unhealthy_threshold,
            expected_status: cfg.expected_status,
            grpc_service: Arc::from(cfg.grpc_service.as_str()),
            udp_payload: Bytes::copy_from_slice(cfg.udp_payload.as_bytes()),
            udp_expected_response: cfg
                .udp_expected_response
                .as_ref()
                .map(|value| Bytes::copy_from_slice(value.as_bytes())),
        })
    }

    /// 业务作用：向后台调度器暴露基础探测间隔，用于选择不会漏轮的全局 tick。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未叠加单实例 jitter 的基础间隔。
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 业务作用：在快照上线前约束 gRPC 健康检查必须使用可承载标准 gRPC 的 HTTP/2
    /// transport，避免 H1/H3 配置被运行期持续误判为不健康。
    ///
    /// 参数说明：`protocol` 是 service 已解析的上游协议。
    ///
    /// 返回：协议与探针兼容时成功；不兼容时返回配置错误。
    pub fn validate_protocol(&self, protocol: UpstreamProtocol) -> anyhow::Result<()> {
        if self.kind == HealthKind::Grpc {
            anyhow::ensure!(
                matches!(
                    protocol,
                    UpstreamProtocol::Auto | UpstreamProtocol::H2 | UpstreamProtocol::H2c
                ),
                "gRPC health check requires upstream protocol auto, h2, or h2c"
            );
        }
        Ok(())
    }

    /// 业务作用：为同一 service 的实例生成分散但有界的下一轮间隔，降低 reload 或启动后
    /// 同步探测造成的连接尖峰，同时保证不会早于 `interval-jitter`。
    ///
    /// 参数说明：`instance_key` 是稳定健康身份；`sequence` 是该实例已调度轮次。
    ///
    /// 返回：位于 `[interval-jitter, interval+jitter]` 的确定性间隔。
    fn jittered_interval(&self, instance_key: &str, sequence: u64) -> Duration {
        health_jitter_delay(self.interval, self.jitter, instance_key, sequence)
    }
}

/// 一个服务的探测目标:策略 + 当前实例列表(静态来自 yml,nacos 来自动态目录)。
pub struct HealthTarget {
    /// 逻辑服务名。
    pub service: String,
    /// 该服务共享的探测协议、阈值和 deadline。
    pub policy: ActiveHealthPolicy,
    /// 当前静态或动态发现实例快照。
    pub instances: Vec<HealthInstanceTarget>,
}

/// 主动健康探测的单实例目标。
#[derive(Clone)]
pub struct HealthInstanceTarget {
    /// 内部健康状态 key,等价 `uri` 或 `uri + tls_profile`。
    pub key: String,
    /// 上游 base URI。
    pub uri: String,
    /// 上游传输协议；HTTP 探测必须与数据面一致，避免 H3 健康却被 TCP/Hyper 误判。
    pub protocol: UpstreamProtocol,
    /// HTTP 探测使用的上游 TLS profile。
    pub tls_profile: Option<UpstreamTlsProfile>,
}

/// 一个服务的主动健康汇总,供 `/metrics` 出每服务健康实例数(§13 `gw_upstream_healthy{upstream}` / N5)。
/// service 名是低基数(配置 key,数量有界),可安全作 Prometheus label。
pub struct ServiceHealthSummary {
    /// 逻辑服务名。
    pub service: String,
    /// 当前健康实例数。
    pub healthy: u32,
    /// 当前参与探测的实例总数。
    pub total: u32,
}

/// 单实例的探测累积状态(仅后台任务持有)。
struct InstanceHealth {
    consecutive_ok: u32,
    consecutive_fail: u32,
    healthy: bool,
    last_probe: Option<Instant>,
    probe_sequence: u64,
}

impl InstanceHealth {
    /// 业务作用：初始化单实例迟滞状态，并让首次调度立即到期，避免启动窗口内长时间
    /// 把尚未验证的实例保留为健康。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：初始健康、计数清零且首次探测已到期的状态。
    fn new() -> Self {
        // 初始视为健康(与静态 healthy=true 默认一致):首轮探测出结果前不误摘实例。
        Self {
            consecutive_ok: 0,
            consecutive_fail: 0,
            healthy: true,
            last_probe: None,
            probe_sequence: 0,
        }
    }
}

/// 主动健康检查器:常驻(生命周期=进程),不随配置快照换版丢失。
pub struct ActiveHealthChecker {
    /// 热路径读:当前不健康 URI 集合。
    unhealthy: ArcSwap<HashSet<String>>,
    /// 仅后台任务持有:每实例连续成功/失败计数 + 健康标记 + 上次探测时刻。
    state: Mutex<HashMap<String, InstanceHealth>>,
    metrics: Arc<Metrics>,
    /// HTTP 探测专用 client(h1/h2);TCP 探测直接 connect,不走它。
    http_client: ProbeHttpClient,
    /// HTTP 探测专用 TLS profile 连接池:profile key -> client。
    tls_clients: Mutex<ProbeTlsClientPool>,
    /// gRPC Health 专用 HTTP/2-only client；与普通 HTTP 探测隔离，禁止协议降级。
    grpc_client: OnceLock<ProbeGrpcClient>,
    /// gRPC Health 专用 TLS profile 连接池:profile key -> HTTP/2-only client。
    grpc_tls_clients: Mutex<ProbeGrpcTlsClientPool>,
    /// 每服务健康汇总的共享快照:供 `/metrics` 出 gw_upstream_healthy{service} 低基数指标(§13 / N5)。
    summary: ArcSwap<Vec<ServiceHealthSummary>>,
}

impl ActiveHealthChecker {
    /// 业务作用：构造进程级健康检查器及按 transport 隔离的探测连接池，使健康状态在
    /// 配置 reload 间保持迟滞计数，同时确保 gRPC 探针不会降级到 HTTP/1.1。
    ///
    /// 参数说明：`metrics` 接收低基数探测结果与不健康实例计数。
    ///
    /// 返回：可在后台任务与数据面之间共享的检查器。
    pub fn new(metrics: Arc<Metrics>) -> Arc<Self> {
        // http 探测 client 同时启用 h1/h2:TLS 上游按 ALPN 协商(h2 上游的 http 探测也能通)。
        // ⚠ 明文 h2c / gRPC 上游无法用 h1 探测(N3):这类上游应配 `type: tcp`(连接级探活、协议无关)。
        let http_client = build_probe_http_client(None);
        Arc::new(Self {
            unhealthy: ArcSwap::from_pointee(HashSet::new()),
            state: Mutex::new(HashMap::new()),
            metrics,
            http_client,
            tls_clients: Mutex::new(HashMap::new()),
            grpc_client: OnceLock::new(),
            grpc_tls_clients: Mutex::new(HashMap::new()),
            summary: ArcSwap::from_pointee(Vec::new()),
        })
    }

    /// 业务作用：提供管理/调试侧兼容的不健康 URI 拷贝，不应在请求热路径使用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：调用时刻 unhealthy 快照中的 URI 列表。
    pub fn unhealthy_uris(&self) -> Vec<String> {
        self.unhealthy.load().iter().cloned().collect()
    }

    /// 业务作用：查询单个健康 identity 是否已被主动探测摘除，供低频控制面和测试核对。
    ///
    /// 参数说明：`uri` 是包含 TLS profile 时已扩展的健康状态 key。
    ///
    /// 返回：当前共享快照将该 identity 标为不健康时为 true。
    pub fn is_unhealthy(&self, uri: &str) -> bool {
        self.unhealthy.load().contains(uri)
    }

    /// 业务作用：向 LB 与 readiness 提供同一份不可变不健康集合，确保摘除事实原子一致。
    ///
    /// 用途(N2 / §24):供 `/readyz` 判定与「选实例」保持一致——某 critical 服务的实例若被主动探测
    /// 全判为不健康,`select` 会返 503,则 `readyz` 也应转 503,而非「select 挂但 readyz 仍报 ready」的
    /// 不一致(那会让前置 LB 继续往一个转发必失败的节点分流)。
    pub fn unhealthy_set(&self) -> Arc<HashSet<String>> {
        self.unhealthy.load_full()
    }

    /// 业务作用：向 metrics 暴露每服务 healthy/total 的低基数共享快照，避免逐采集重扫状态表。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最近完成一轮 cycle 后原子发布的汇总 `Arc`。
    pub fn service_health(&self) -> Arc<Vec<ServiceHealthSummary>> {
        self.summary.load_full()
    }

    /// 业务作用：跑一轮到期实例探测，按连续成功/失败阈值更新数据面共享的
    /// 不健康集合与每服务汇总。
    ///
    /// 参数说明：`targets` 是当前配置/发现快照中的探测目标。
    ///
    /// 返回：无；到期探测完成后原子发布 unhealthy 与 summary 快照。
    pub async fn run_cycle(&self, targets: Vec<HealthTarget>) {
        let now = Instant::now();
        let mut current: HashSet<String> = HashSet::new();
        // 每个实例健康 key 的 (healthy_threshold, unhealthy_threshold),供探测后判翻转。
        let mut thresholds: HashMap<String, (u32, u32)> = HashMap::new();
        let mut due: Vec<(HealthInstanceTarget, ActiveHealthPolicy)> = Vec::new();
        {
            let mut state = self.state.lock().expect("health state mutex poisoned");
            for target in &targets {
                for inst in &target.instances {
                    current.insert(inst.key.clone());
                    thresholds.insert(
                        inst.key.clone(),
                        (
                            target.policy.healthy_threshold,
                            target.policy.unhealthy_threshold,
                        ),
                    );
                    let entry = state
                        .entry(inst.key.clone())
                        .or_insert_with(InstanceHealth::new);
                    let due_after = target
                        .policy
                        .jittered_interval(&inst.key, entry.probe_sequence);
                    if entry
                        .last_probe
                        .is_none_or(|last_probe| now.duration_since(last_probe) >= due_after)
                    {
                        entry.last_probe = Some(now);
                        entry.probe_sequence = entry.probe_sequence.wrapping_add(1);
                        due.push((inst.clone(), target.policy.clone()));
                    }
                }
            }
            // 清理已消失(配置删除 / nacos 摘除)的实例状态,避免内存滞留。
            state.retain(|uri, _| current.contains(uri));
        }

        // 并发探测到期实例(探测在后台任务,不阻塞热路径)。
        let mut set = JoinSet::new();
        for (inst, policy) in due {
            let http_client = self.http_client_for(inst.tls_profile.as_ref());
            let grpc_client = self.grpc_client_for(inst.tls_profile.as_ref());
            set.spawn(async move {
                let ok = probe_instance(&http_client, &grpc_client, &inst, &policy).await;
                (inst.key, ok)
            });
        }
        let mut results = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(result) = joined {
                results.push(result);
            }
        }

        {
            let mut state = self.state.lock().expect("health state mutex poisoned");
            for (key, ok) in results {
                // N5:每次探测结果计数(ok=可达 / fail=不可达或状态不符),供 gw_active_health_probe_total。
                self.metrics.inc_active_health_probe(ok);
                let Some((healthy_threshold, unhealthy_threshold)) = thresholds.get(&key).copied()
                else {
                    continue;
                };
                if let Some(entry) = state.get_mut(&key) {
                    apply_probe_result(entry, ok, healthy_threshold, unhealthy_threshold, &key);
                }
            }
            let unhealthy: HashSet<String> = state
                .iter()
                .filter(|(_, s)| !s.healthy)
                .map(|(uri, _)| uri.clone())
                .collect();
            // N5:每服务健康汇总(healthy = 该服务实例中不在不健康集合的数量);在移交 unhealthy 前算,避免再借。
            let summary = targets
                .iter()
                .map(|target| ServiceHealthSummary {
                    service: target.service.clone(),
                    healthy: target
                        .instances
                        .iter()
                        .filter(|inst| !unhealthy.contains(&inst.key))
                        .count() as u32,
                    total: target.instances.len() as u32,
                })
                .collect::<Vec<_>>();
            self.summary.store(Arc::new(summary));
            self.metrics
                .set_active_health_unhealthy(unhealthy.len() as u64);
            self.unhealthy.store(Arc::new(unhealthy));
        }
    }

    /// 业务作用：按 TLS identity 复用普通 HTTP 探测池，避免周期探测重复解析证书并跨身份混池。
    ///
    /// 参数说明：`profile` 是上游已验证的 TLS 配置；None 使用公共根。
    ///
    /// 返回：支持 H1/H2 协商的普通 HTTP 探测 client。
    fn http_client_for(&self, profile: Option<&UpstreamTlsProfile>) -> ProbeHttpClient {
        let Some(profile) = profile else {
            return self.http_client.clone();
        };
        let mut clients = self
            .tls_clients
            .lock()
            .expect("health tls clients mutex poisoned");
        if let Some(client) = clients.get(&profile.key) {
            return client.clone();
        }
        let client = build_probe_http_client(Some(profile));
        clients.insert(profile.key.clone(), client.clone());
        client
    }

    /// 业务作用：按 TLS identity 复用 gRPC HTTP/2-only 探测池，防止与普通 HTTP client
    /// 共享协议协商状态后出现 H1 降级或跨证书身份复用。
    ///
    /// 参数说明：`profile` 是上游已验证的 TLS 配置；None 使用公共根。
    ///
    /// 返回：强制 HTTP/2 的 gRPC Health 探测 client。
    fn grpc_client_for(&self, profile: Option<&UpstreamTlsProfile>) -> ProbeGrpcClient {
        let Some(profile) = profile else {
            // 未配置 gRPC health 的默认进程不创建第二份 connector/TLS roots；首次真实
            // gRPC 目标出现时再单飞构建，保持普通 HTTP/TCP 数据面的 idle 资源基线。
            return self
                .grpc_client
                .get_or_init(|| build_probe_grpc_client(None))
                .clone();
        };
        let mut clients = self
            .grpc_tls_clients
            .lock()
            .expect("gRPC health TLS clients mutex poisoned");
        if let Some(client) = clients.get(&profile.key) {
            return client.clone();
        }
        let client = build_probe_grpc_client(Some(profile));
        clients.insert(profile.key.clone(), client.clone());
        client
    }
}

/// 业务作用：让 `/readyz` 与 Nacos self-registration 共用数据面同源的 critical upstream
/// 可用性判定，避免 LB 已无候选但控制面仍广告本节点。
///
/// 参数说明：`snap` 是当前配置快照；`checker` 提供同一时刻的主动摘除集合。
///
/// 返回：结合 active health 与 discovery stale TTL 后不可用的 critical service 名列表。
pub fn critical_upstreams_not_ready(
    snap: &GatewaySnapshot,
    checker: &ActiveHealthChecker,
) -> Vec<String> {
    snap.upstreams.critical_not_ready(&checker.unhealthy_set())
}

/// 业务作用：构建普通 HTTP 主动探测 client，并复用配置构建期已解析好的 TLS 材料，
/// 使 H1/H2 HTTP 健康路径与业务证书身份一致。
///
/// 参数说明：`profile` 是 HTTP 上游 TLS profile；None 使用内置公共根证书。
///
/// 返回：可按 scheme/ALPN 使用 H1 或 H2 的 Hyper client。
fn build_probe_http_client(profile: Option<&UpstreamTlsProfile>) -> ProbeHttpClient {
    let connector = match profile {
        None => hyper_rustls::HttpsConnectorBuilder::new()
            // CI/macOS 无 Keychain 时仍使用内置 Mozilla roots；避免健康检查因系统信任库不可读而 panic。
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build(),
        Some(profile) => {
            let mut config = profile.client_config.as_ref().clone();
            config.alpn_protocols.clear();
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http();
            let builder = if let Some(server_name) = &profile.server_name {
                let name = ServerName::try_from(server_name.as_ref().to_string())
                    .expect("validated upstream tls server_name");
                builder.with_server_name_resolver(FixedServerNameResolver::new(name))
            } else {
                builder
            };
            builder.enable_http1().enable_http2().build()
        }
    };
    Client::builder(TokioExecutor::new()).build(connector)
}

/// 业务作用：构建标准 gRPC Health 专用 client，强制 h2/h2c prior knowledge，禁止健康
/// 请求因连接池协商或明文 scheme 静默退化到 HTTP/1.1。
///
/// 参数说明：`profile` 是 gRPC 上游 TLS profile；None 使用内置公共根证书或明文 h2c。
///
/// 返回：请求 body 为有界 protobuf frame、transport 强制 HTTP/2 的 Hyper client。
fn build_probe_grpc_client(profile: Option<&UpstreamTlsProfile>) -> ProbeGrpcClient {
    let connector = match profile {
        None => hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http2()
            .build(),
        Some(profile) => {
            let mut config = profile.client_config.as_ref().clone();
            config.alpn_protocols.clear();
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http();
            let builder = if let Some(server_name) = &profile.server_name {
                let name = ServerName::try_from(server_name.as_ref().to_string())
                    .expect("validated upstream tls server_name");
                builder.with_server_name_resolver(FixedServerNameResolver::new(name))
            } else {
                builder
            };
            builder.enable_http2().build()
        }
    };
    let mut builder = Client::builder(TokioExecutor::new());
    builder.http2_only(true);
    builder.build(connector)
}

/// 业务作用：累计单实例探测结果并仅在连续阈值满足时翻转健康态，以迟滞阻止一次瞬时
/// 网络波动反复摘除/恢复业务路由。
///
/// 参数说明：`entry` 是常驻实例状态；`ok` 是本轮结果；两个 threshold 是翻转门槛；
/// `uri` 只用于低频状态迁移日志。
///
/// 返回：无；可能原地更新计数与健康标记并记录一次状态迁移。
fn apply_probe_result(
    entry: &mut InstanceHealth,
    ok: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    uri: &str,
) {
    if ok {
        entry.consecutive_ok = entry.consecutive_ok.saturating_add(1);
        entry.consecutive_fail = 0;
        if !entry.healthy && entry.consecutive_ok >= healthy_threshold {
            entry.healthy = true;
            tracing::info!(upstream = uri, "active health check: upstream recovered");
        }
    } else {
        entry.consecutive_fail = entry.consecutive_fail.saturating_add(1);
        entry.consecutive_ok = 0;
        if entry.healthy && entry.consecutive_fail >= unhealthy_threshold {
            entry.healthy = false;
            tracing::warn!(
                upstream = uri,
                "active health check: upstream marked unhealthy"
            );
        }
    }
}

/// 业务作用：把配置的基础 interval 与 jitter 编译为单实例、单轮次的确定性分散间隔，
/// 无需全局 RNG/锁即可避免同一时刻向所有上游发起探测。
///
/// 参数说明：`interval` 是基础间隔；`jitter` 是对称上限；`instance_key` 和 `sequence`
/// 共同形成稳定但逐轮变化的采样输入。
///
/// 返回：jitter 为零时原样返回 interval；否则返回构建期已保证非零的对称区间值。
fn health_jitter_delay(
    interval: Duration,
    jitter: Duration,
    instance_key: &str,
    sequence: u64,
) -> Duration {
    let jitter_ms = jitter.as_millis() as u64;
    if jitter_ms == 0 {
        return interval;
    }
    // 调度随机化不承担密码学职责；FNV 只用于把稳定实例 identity 与轮次均匀映射到
    // 有界时间窗，避免引入共享 RNG 锁或把敏感信息写入状态。
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in instance_key
        .as_bytes()
        .iter()
        .copied()
        .chain(sequence.to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let interval_ms = interval.as_millis() as u64;
    let span = jitter_ms.saturating_mul(2).saturating_add(1);
    Duration::from_millis(interval_ms - jitter_ms + hash % span)
}

/// 以实例的真实传输协议执行一次主动健康探测。
///
/// 业务作用：将 TCP/UDP 探测保持为显式运维选择，HTTP 探测则区分 Hyper
/// H1/H2 与真实 QUIC/H3，避免健康结论与业务传输脱节。
///
/// 参数说明：`client` 是 H1/H2 探测池；`instance` 含 URI/协议/TLS identity；
/// `policy` 定义探测方式、路径、deadline 与状态码约束。
///
/// 返回：探测在 deadline 内满足策略时为 true，否则为 false。
async fn probe_instance(
    http_client: &ProbeHttpClient,
    grpc_client: &ProbeGrpcClient,
    instance: &HealthInstanceTarget,
    policy: &ActiveHealthPolicy,
) -> bool {
    match policy.kind {
        HealthKind::Tcp => probe_tcp(&instance.uri, policy.timeout).await,
        HealthKind::Http => {
            #[cfg(feature = "http3")]
            if instance.protocol == UpstreamProtocol::H3 {
                // H3 只有 UDP/QUIC+TLS+HTTP/3 整链路成功才算健康；用 TCP 或
                // Hyper h1/h2 探测会产生「端口存活但 H3 不可用」的假阳性。
                return probe_http3(&instance.uri, instance.tls_profile.as_ref(), policy).await;
            }
            probe_http(http_client, &instance.uri, policy).await
        }
        HealthKind::Grpc => probe_grpc(grpc_client, &instance.uri, policy).await,
        HealthKind::Udp => probe_udp(&instance.uri, policy).await,
    }
}

/// 业务作用：调用标准 `grpc.health.v1.Health/Check` 并同时验证 HTTP/2、gRPC trailer 与
/// protobuf `SERVING` 状态，避免只检查端口或 HTTP 200 形成应用层假阳性。
///
/// 参数说明：`client` 是强制 HTTP/2 的独立探测池；`uri` 是上游 base URI；`policy`
/// 提供 service 名与单次 deadline。
///
/// 返回：deadline 内收到唯一、未压缩、资源有界的响应消息，且 `grpc-status=0`、
/// `status=SERVING` 时为 true；任一传输、协议或解析错误均为 false。
async fn probe_grpc(client: &ProbeGrpcClient, uri: &str, policy: &ActiveHealthPolicy) -> bool {
    let target = format!("{uri}{GRPC_HEALTH_PATH}");
    let request_body = encode_grpc_health_request(&policy.grpc_service);
    let Ok(request) = Request::builder()
        .method(Method::POST)
        .version(Version::HTTP_2)
        .uri(&target)
        .header(CONTENT_TYPE, "application/grpc+proto")
        .header(TE, "trailers")
        .body(Full::new(request_body))
    else {
        return false;
    };
    let exchange = async {
        let response = client.request(request).await.ok()?;
        if response.version() != Version::HTTP_2 || response.status() != http::StatusCode::OK {
            return None;
        }
        if !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_grpc_content_type)
        {
            return None;
        }
        let header_status = parse_grpc_status(response.headers());
        let mut trailer_status = None;
        let mut payload = BytesMut::new();
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.ok()?;
            match frame.into_data() {
                Ok(data) => {
                    if payload.len().saturating_add(data.len()) > GRPC_HEALTH_MAX_RESPONSE_BYTES {
                        return None;
                    }
                    payload.extend_from_slice(&data);
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        trailer_status = Some(parse_grpc_status(&trailers));
                    }
                }
            }
        }
        let final_status = trailer_status.unwrap_or(header_status);
        if final_status != Some(0) {
            return None;
        }
        decode_grpc_health_serving(&payload).then_some(())
    };
    matches!(
        tokio::time::timeout(policy.timeout, exchange).await,
        Ok(Some(()))
    )
}

/// 业务作用：把配置的 service 名编码为标准 HealthCheckRequest unary gRPC frame，且不依赖
/// 可选 descriptor/prost feature，保证核心健康检查在默认制品可用。
///
/// 参数说明：`service` 是已在构建期限制长度并排除控制字符的完整 service 名。
///
/// 返回：5 字节 gRPC envelope 加 protobuf request；空 service 编码为空 protobuf message。
fn encode_grpc_health_request(service: &str) -> Bytes {
    let mut message = Vec::with_capacity(service.len().saturating_add(8));
    if !service.is_empty() {
        message.push(0x0a);
        push_protobuf_varint(service.len() as u64, &mut message);
        message.extend_from_slice(service.as_bytes());
    }
    let mut frame = Vec::with_capacity(message.len().saturating_add(5));
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

/// 业务作用：验证标准 HealthCheckResponse 的 gRPC envelope，并从可前向兼容的 protobuf
/// 字段流中读取 `status`，拒绝压缩、截断、多消息或畸形 wire type。
///
/// 参数说明：`frame` 是在硬上限内聚合的单个 unary gRPC 响应 body。
///
/// 返回：消息结构完整且最终 status 枚举值为 `SERVING(1)` 时为 true。
fn decode_grpc_health_serving(frame: &[u8]) -> bool {
    if frame.len() < 5 || frame[0] != 0 {
        return false;
    }
    let declared = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if declared != frame.len().saturating_sub(5) {
        return false;
    }
    let message = &frame[5..];
    let mut offset = 0;
    let mut status = 0_u64;
    while offset < message.len() {
        let Some(key) = read_protobuf_varint(message, &mut offset) else {
            return false;
        };
        let field = key >> 3;
        let wire = key & 0x07;
        if field == 0 {
            return false;
        }
        if field == 1 && wire == 0 {
            let Some(value) = read_protobuf_varint(message, &mut offset) else {
                return false;
            };
            status = value;
            continue;
        }
        if !skip_protobuf_field(message, &mut offset, wire) {
            return false;
        }
    }
    status == 1
}

/// 业务作用：读取 protobuf varint 并同时执行 10 字节与移位上限检查，防止恶意健康响应
/// 通过溢出或不终止编码绕过有界解析。
///
/// 参数说明：`input` 是消息切片；`offset` 是读游标并在成功时推进。
///
/// 返回：合法 u64 varint；截断、超过 10 字节或第 10 字节溢出时返回 None。
fn read_protobuf_varint(input: &[u8], offset: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input.get(*offset)?;
        *offset = offset.saturating_add(1);
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// 业务作用：跳过 HealthCheckResponse 中未知但合法的 protobuf 字段，使新增字段不会误伤
/// 健康判断，同时拒绝 group 等未支持 wire type 与所有越界长度。
///
/// 参数说明：`input` 是 protobuf message；`offset` 是当前字段 value 起点；`wire` 是 wire type。
///
/// 返回：字段完整且游标安全推进时为 true，否则为 false。
fn skip_protobuf_field(input: &[u8], offset: &mut usize, wire: u64) -> bool {
    let length = match wire {
        0 => return read_protobuf_varint(input, offset).is_some(),
        1 => 8,
        2 => {
            let Some(length) = read_protobuf_varint(input, offset) else {
                return false;
            };
            let Ok(length) = usize::try_from(length) else {
                return false;
            };
            length
        }
        5 => 4,
        _ => return false,
    };
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    if end > input.len() {
        return false;
    }
    *offset = end;
    true
}

/// 业务作用：写出 protobuf/u64 varint，供有界 HealthCheckRequest 编码共享，避免引入
/// 只在可选 feature 出现的生成代码依赖。
///
/// 参数说明：`value` 是待编码整数；`output` 是调用方预分配缓冲区。
///
/// 返回：无；追加规范最短 varint。
fn push_protobuf_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

/// 业务作用：识别 gRPC content-type 家族但拒绝普通 JSON/HTTP 响应，防止仅凭 200 状态
/// 把代理错误页误判为健康。
///
/// 参数说明：`value` 是已通过 HTTP header UTF-8 校验的 content-type。
///
/// 返回：去除参数后的媒体类型以 `application/grpc` 开头时为 true。
fn is_grpc_content_type(value: &str) -> bool {
    value.split(';').next().is_some_and(|media| {
        let media = media.trim();
        media == "application/grpc" || media.starts_with("application/grpc+")
    })
}

/// 业务作用：从 gRPC response headers 或 trailers 读取规范十进制状态码，任何缺失、
/// 非 UTF-8 或非数字值都保持失败闭合。
///
/// 参数说明：`headers` 是 response head 或最终 trailers。
///
/// 返回：合法 u32 `grpc-status`；缺失或畸形时返回 None。
fn parse_grpc_status(headers: &http::HeaderMap) -> Option<u32> {
    headers.get("grpc-status")?.to_str().ok()?.parse().ok()
}

/// 使用真实 QUIC/TLS/H3 GET 探测 HTTP/3 上游。
///
/// 业务作用：验证 DNS、UDP 可达性、证书/SNI、ALPN、H3 SETTINGS 和业务
/// 健康路径，确保主动摘除依据与 `protocol: h3` 数据面一致。
///
/// 参数说明：`uri` 是 HTTPS 实例基址；`profile` 是构建期已验证的 CA/SNI/mTLS
/// 身份；`policy` 提供路径、deadline 和期望状态。
///
/// 返回：在单一 deadline 内拿到符合状态约束的 H3 响应头时为 true；任一
/// DNS/TLS/QUIC/H3/状态步骤失败或超时时为 false。探测结束会关闭临时 connection。
#[cfg(feature = "http3")]
async fn probe_http3(
    uri: &str,
    profile: Option<&UpstreamTlsProfile>,
    policy: &ActiveHealthPolicy,
) -> bool {
    let probe = async {
        let profile = profile.context("HTTP/3 health target has no TLS profile")?;
        let base: http::Uri = uri.parse().context("parse HTTP/3 health target URI")?;
        anyhow::ensure!(
            base.scheme_str() == Some("https"),
            "HTTP/3 health target must use https"
        );
        let host = base.host().context("HTTP/3 health target has no host")?;
        let port = base.port_u16().unwrap_or(443);
        let server_name = profile.server_name.as_deref().unwrap_or(host);
        let target = tokio::net::lookup_host((host, port))
            .await
            .context("resolve HTTP/3 health target")?
            .next()
            .context("HTTP/3 health DNS returned no address")?;
        let bind: std::net::SocketAddr = if target.is_ipv6() {
            "[::]:0"
                .parse()
                .context("parse IPv6 health probe bind address")?
        } else {
            "0.0.0.0:0"
                .parse()
                .context("parse IPv4 health probe bind address")?
        };
        let mut endpoint =
            quinn::Endpoint::client(bind).context("bind HTTP/3 health probe endpoint")?;
        let mut tls = profile.client_config.as_ref().clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .context("build HTTP/3 health probe TLS config")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(0))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(8))
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0)
            .max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(policy.timeout)
                    .context("convert HTTP/3 health idle timeout")?,
            ));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        let quic = endpoint
            .connect(target, server_name)
            .context("start HTTP/3 health handshake")?
            .await
            .context("complete HTTP/3 health handshake")?;
        let mut builder = h3::client::builder();
        builder
            .max_field_section_size(64 * 1024)
            .enable_extended_connect(false)
            .enable_datagram(false);
        let (mut driver, mut sender): (_, h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>) =
            builder
                .build(h3_quinn::Connection::new(quic))
                .await
                .context("initialize HTTP/3 health connection")?;
        let target_uri = format!("{uri}{}", policy.path);
        let request = Request::builder()
            .method(Method::GET)
            .version(http::Version::HTTP_3)
            .uri(target_uri)
            .body(())
            .context("build HTTP/3 health request")?;
        let exchange = async {
            let mut stream = sender
                .send_request(request)
                .await
                .context("open HTTP/3 health request stream")?;
            stream
                .finish()
                .await
                .context("finish HTTP/3 health request")?;
            let response = stream
                .recv_response()
                .await
                .context("receive HTTP/3 health response")?;
            let status = response.status().as_u16();
            Ok::<_, anyhow::Error>(match policy.expected_status {
                Some(expected) => status == expected,
                None => (200..300).contains(&status),
            })
        };
        let result = tokio::select! {
            result = exchange => result,
            error = driver.wait_idle() => Err(anyhow::anyhow!(
                "HTTP/3 health connection closed before response: {error}"
            )),
        };
        // 健康探测不进入数据面连接池；拿到 response head 后立即关闭，
        // 避免周期探测跨轮积累 socket/driver。
        endpoint.close(quinn::VarInt::from_u32(0), b"health probe complete");
        result
    };
    match tokio::time::timeout(policy.timeout, probe).await {
        Ok(Ok(ok)) => ok,
        Ok(Err(error)) => {
            tracing::debug!(upstream = uri, %error, "HTTP/3 active health probe failed");
            false
        }
        Err(_) => {
            tracing::debug!(upstream = uri, "HTTP/3 active health probe timed out");
            false
        }
    }
}

/// 业务作用：向 UDP 上游发送配置期限定的 datagram 并验证有界响应，不把探测流量写入
/// 数据面 session table。
///
/// 参数说明：`uri` 提供目标 authority；`policy` 提供 payload、可选精确响应与 deadline。
///
/// 返回：deadline 内收到 1..=4096 字节且满足响应策略时为 true。
async fn probe_udp(uri: &str, policy: &ActiveHealthPolicy) -> bool {
    let Some(authority) = uri_socket_authority(uri) else {
        return false;
    };
    let probe = async {
        let target = tokio::net::lookup_host(authority).await.ok()?.next()?;
        let bind = if target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await.ok()?;
        socket.connect(target).await.ok()?;
        socket.send(&policy.udp_payload).await.ok()?;
        let mut response = [0_u8; 4097];
        let length = socket.recv(&mut response).await.ok()?;
        if length == 0 || length > 4096 {
            return Some(false);
        }
        Some(match &policy.udp_expected_response {
            Some(expected) => response[..length] == expected[..],
            None => true,
        })
    };
    matches!(
        tokio::time::timeout(policy.timeout, probe).await,
        Ok(Some(true))
    )
}

/// 业务作用：验证上游 authority 在 deadline 内可建立 TCP 连接，作为协议无关的最低层探活。
///
/// 参数说明：`uri` 提供 host/port；`timeout` 限制 DNS/连接总等待时间。
///
/// 返回：成功建立连接时为 true；URI、解析、连接或 deadline 失败时为 false。
async fn probe_tcp(uri: &str, timeout: Duration) -> bool {
    let Some(addr) = uri_socket_authority(uri) else {
        return false;
    };
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect(addr.as_str())).await,
        Ok(Ok(_))
    )
}

/// 业务作用：通过配置路径与状态码执行普通 HTTP 应用层探活，使用与上游一致的 TLS identity。
///
/// 参数说明：`client` 是 H1/H2 探测池；`uri` 是 base URI；`policy` 提供路径、状态和 deadline。
///
/// 返回：deadline 内收到匹配的 response head 时为 true，不等待业务 body 聚合。
async fn probe_http(
    client: &Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    uri: &str,
    policy: &ActiveHealthPolicy,
) -> bool {
    let target = format!("{uri}{}", policy.path);
    let Ok(request) = Request::builder()
        .method(Method::GET)
        .uri(&target)
        .body(Empty::<Bytes>::new())
    else {
        return false;
    };
    match tokio::time::timeout(policy.timeout, client.request(request)).await {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            match policy.expected_status {
                Some(expected) => status == expected,
                None => (200..300).contains(&status),
            }
        }
        _ => false,
    }
}

/// 业务作用：把上游 base URI 规范化为 socket authority，供 TCP/UDP 探针复用且正确处理 IPv6。
///
/// 参数说明：`uri` 是已声明的 HTTP(S) base URI。
///
/// 返回：带显式端口的 `host:port`；URI 无 authority 时返回 None。
fn uri_socket_authority(uri: &str) -> Option<String> {
    let parsed: http::Uri = uri.parse().ok()?;
    let authority = parsed.authority()?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(match parsed.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    Some(format!("{}:{port}", bracket_ipv6_host(host)))
}

/// 业务作用：为裸 IPv6 host 补方括号，避免与后接端口的冒号产生 authority 歧义。
///
/// 参数说明：`host` 是 URI parser 提取的无端口 host。
///
/// 返回：IPv6 的 `[host]` 或其它 host 原值拷贝。
fn bracket_ipv6_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// 业务作用：启动常驻主动健康调度任务，每轮从最新快照重建目标并以有界 tick 驱动探测，
/// reload 删除策略时仍发布空 cycle 清除旧摘除状态。
///
/// 参数说明：`checker` 是进程级迟滞状态；`snap` 是可热换的网关快照。
///
/// 返回：后台 Tokio task handle；任务持续到进程关闭或 handle 被 abort。
pub fn spawn_active_health(
    checker: Arc<ActiveHealthChecker>,
    snap: Arc<ArcSwap<GatewaySnapshot>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (targets, tick) = {
                let snapshot = snap.load_full();
                let targets = snapshot.upstreams.active_health_targets();
                let tick = targets
                    .iter()
                    .map(|t| t.policy.interval())
                    .min()
                    .unwrap_or(Duration::from_secs(5))
                    .max(Duration::from_millis(250));
                (targets, tick)
            };
            // 即使当前没有任何 health_check 目标,也要跑一轮空 cycle 清掉旧 state/unhealthy。
            // 否则 reload 删除 health_check 后,旧的不健康 URI 会继续影响选实例与 /readyz。
            checker.run_cycle(targets).await;
            tokio::time::sleep(tick).await;
        }
    })
}
