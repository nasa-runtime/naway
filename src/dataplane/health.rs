//! 主动健康探测(§5.1)。
//!
//! 后台任务按服务配置的间隔 TCP/HTTP 探测每个上游实例,连续成功/失败达阈值即翻转健康态。
//! 数据面热路径只读一个 `ArcSwap<HashSet<String>>`(当前不健康 URI 集合),选实例时把它并入
//! `excluded`,与被动摘除(§5.1)叠加成「主动探测 + 被动摘除」双保险。探测本身只发生在后台任务,
//! 绝不进入请求热路径。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Method, Request};
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

type ProbeHttpClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;
type ProbeTlsClientPool = HashMap<Arc<str>, ProbeHttpClient>;

/// 探测方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthKind {
    /// TCP connect 成功即健康(协议无关,适用于 MySQL/Redis/gRPC 等任意 TCP 上游)。
    Tcp,
    /// HTTP GET 指定 path,按状态码判健康。
    Http,
    /// 发送固定小 datagram 并等待响应；不进入数据面 session table。
    Udp,
}

/// 从 yml `health_check` 编译出的主动健康策略。无 `health_check` 段 = 关闭。
#[derive(Clone)]
pub struct ActiveHealthPolicy {
    kind: HealthKind,
    path: String,
    interval: Duration,
    timeout: Duration,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    expected_status: Option<u16>,
    udp_payload: Bytes,
    udp_expected_response: Option<Bytes>,
}

impl ActiveHealthPolicy {
    /// build 期解析;非法 type 直接报错(坏配置不上线,§7.2)。
    pub fn parse(cfg: &HealthCheckCfg) -> anyhow::Result<Self> {
        let kind = match cfg.r#type.trim().to_ascii_lowercase().as_str() {
            "tcp" => HealthKind::Tcp,
            "http" => HealthKind::Http,
            "udp" => HealthKind::Udp,
            other => anyhow::bail!("unsupported health_check type `{other}` (tcp|http|udp)"),
        };
        if kind != HealthKind::Udp
            && (!cfg.udp_payload.is_empty() || cfg.udp_expected_response.is_some())
        {
            anyhow::bail!("UDP health fields require health_check type=udp");
        }
        if kind == HealthKind::Udp && cfg.udp_payload.is_empty() {
            anyhow::bail!("UDP health check requires a non-empty udp_payload");
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
            timeout: Duration::from_millis(cfg.timeout_ms),
            healthy_threshold: cfg.healthy_threshold,
            unhealthy_threshold: cfg.unhealthy_threshold,
            expected_status: cfg.expected_status,
            udp_payload: Bytes::copy_from_slice(cfg.udp_payload.as_bytes()),
            udp_expected_response: cfg
                .udp_expected_response
                .as_ref()
                .map(|value| Bytes::copy_from_slice(value.as_bytes())),
        })
    }

    /// 返回后台调度使用的探测间隔。
    pub fn interval(&self) -> Duration {
        self.interval
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
    last_probe: Instant,
}

impl InstanceHealth {
    fn new(now: Instant) -> Self {
        // 初始视为健康(与静态 healthy=true 默认一致):首轮探测出结果前不误摘实例。
        Self {
            consecutive_ok: 0,
            consecutive_fail: 0,
            healthy: true,
            last_probe: now.checked_sub(Duration::from_secs(3600)).unwrap_or(now),
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
    /// 每服务健康汇总的共享快照:供 `/metrics` 出 gw_upstream_healthy{service} 低基数指标(§13 / N5)。
    summary: ArcSwap<Vec<ServiceHealthSummary>>,
}

impl ActiveHealthChecker {
    /// 构造进程级健康检查器及独立探测连接池。
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
            summary: ArcSwap::from_pointee(Vec::new()),
        })
    }

    /// 当前不健康 URI 列表(调试/兼容用)。请求热路径应优先用 [`Self::unhealthy_set`],避免整表克隆。
    pub fn unhealthy_uris(&self) -> Vec<String> {
        self.unhealthy.load().iter().cloned().collect()
    }

    /// 某 URI 当前是否被主动探测判为不健康。
    pub fn is_unhealthy(&self, uri: &str) -> bool {
        self.unhealthy.load().contains(uri)
    }

    /// 返回当前不健康 URI 集合的共享快照(`Arc` 免拷贝)。
    ///
    /// 用途(N2 / §24):供 `/readyz` 判定与「选实例」保持一致——某 critical 服务的实例若被主动探测
    /// 全判为不健康,`select` 会返 503,则 `readyz` 也应转 503,而非「select 挂但 readyz 仍报 ready」的
    /// 不一致(那会让前置 LB 继续往一个转发必失败的节点分流)。
    pub fn unhealthy_set(&self) -> Arc<HashSet<String>> {
        self.unhealthy.load_full()
    }

    /// `/metrics` 用:每服务健康汇总快照(healthy/total 实例数,§13 / N5)。返回 `Arc` 免拷贝。
    pub fn service_health(&self) -> Arc<Vec<ServiceHealthSummary>> {
        self.summary.load_full()
    }

    /// 跑一轮探测:读当前快照的健康目标,探测「到期」的实例,更新健康态与不健康集合。
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
                        .or_insert_with(|| InstanceHealth::new(now));
                    if now.duration_since(entry.last_probe) >= target.policy.interval {
                        entry.last_probe = now;
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
            let client = self.http_client_for(inst.tls_profile.as_ref());
            set.spawn(async move {
                let ok = probe_instance(&client, &inst.uri, &policy).await;
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
}

/// `/readyz` 与 Nacos self-registration 共用的 critical upstream 判定。
///
/// 返回不可用的 critical service 名列表；判定与数据面选实例共用 active-health
/// 与 Nacos stale TTL 事实，避免探针已 503 但发现面仍广告该节点。
pub fn critical_upstreams_not_ready(
    snap: &GatewaySnapshot,
    checker: &ActiveHealthChecker,
) -> Vec<String> {
    snap.upstreams.critical_not_ready(&checker.unhealthy_set())
}

/// 构建 HTTP 主动探测 client。自定义 profile 使用配置构建期已解析好的证书材料。
///
/// # 参数
/// - `profile`: HTTP 上游 TLS profile;None 使用系统根证书。
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

/// 连续成功/失败达阈值即翻转健康态(带迟滞,避免抖动)。
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

async fn probe_instance(
    client: &Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    uri: &str,
    policy: &ActiveHealthPolicy,
) -> bool {
    match policy.kind {
        HealthKind::Tcp => probe_tcp(uri, policy.timeout).await,
        HealthKind::Http => probe_http(client, uri, policy).await,
        HealthKind::Udp => probe_udp(uri, policy).await,
    }
}

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

async fn probe_tcp(uri: &str, timeout: Duration) -> bool {
    let Some(addr) = uri_socket_authority(uri) else {
        return false;
    };
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect(addr.as_str())).await,
        Ok(Ok(_))
    )
}

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

/// 从上游 base URI 抽出 `host:port`(供 TCP connect);缺省端口按 scheme 补(http=80,https=443)。
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

fn bracket_ipv6_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// 后台探测任务:每轮读当前快照的健康目标,探测到期实例。间隔取所有服务 interval 的最小值(≥250ms 防忙轮询)。
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

#[path = "../../tests/unit/health.rs"]
#[cfg(test)]
mod tests;
