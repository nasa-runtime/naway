//! Naway 入口。
//!
//! - `naway --config zcf/naway.yml`:启动数据面(监听 + 无感热更)。
//! - `naway -s reload`:向运行中的进程发 SIGHUP 触发热更(nginx `-s reload` 风格)。

// 包名/二进制已经品牌化为 `naway`。crate 内大量 `Gateway*` 类型表达的是通用网关领域模型，
// 保留别名可避免把品牌重命名错误扩大成公共 Rust 类型/API 的破坏性迁移。
extern crate naway as gateway;

use std::collections::HashMap;
use std::future::Future;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use parking_lot::Mutex as ParkingMutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::ReadBuf;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

use gateway::access_log::{AccessLogger, AccessMethod, AccessPath, AccessRecord};
use gateway::admin;
use gateway::config::model::{ServerLimitsCfg, TimeoutCfg};
use gateway::config::{
    load_snapshot_with_dynamic, GatewaySnapshot, ProxyListenTopology, ProxyProtocolRuntimeCfg,
    ProxyRuntime, StreamProtocolRuntime, StreamRouteRuntime, StreamRuntime,
};
use gateway::discovery::{GatewaySelfRegistration, NacosDiscoveryManager};
use gateway::metrics::Metrics;
use gateway::proxy::{
    ConnectionClientIpHeader, DownstreamConnectionLease, GatewayProxy, ProxyRuntimeState,
};
use gateway::proxy_protocol::{encode_proxy_protocol_header, strip_proxy_protocol, ConnInfo};
use gateway::reload;
use gateway::tls::{build_server_config, spawn_cert_watcher, SharedServerConfig};
use gateway::upstream::{DynamicUpstreamStore, PassiveHealthPolicy};

#[derive(Debug, Parser)]
#[command(name = "naway")]
#[command(about = "Naway high-performance Rust traffic + business gateway")]
struct Args {
    /// 运行形态；省略时兼容旧命令，按 `all-in-one` 启动。
    #[command(subcommand)]
    command: Option<RunMode>,
    /// 主配置文件路径(默认 /data/naway/naway.yml,或环境变量 NATE_CONFIG；兼容旧 GW_CONFIG)。
    #[arg(long)]
    config: Option<String>,
    /// 向运行中的进程发信号:`reload` = SIGHUP 热更(nginx `-s reload` 风格)。
    #[arg(short = 's', long = "signal")]
    signal: Option<String>,
}

/// 单一二进制的平面部署模式；生产可把数据面与控制面拆成不同权限/生命周期的进程。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
enum RunMode {
    /// 只运行数据面与最小观测/节点运维入口。
    Data,
    /// 只运行完整管理面；不绑定 public HTTP/TLS/L4 listener。
    Admin,
    /// 同一进程同时运行数据面与完整管理面，兼容旧启动方式。
    AllInOne,
}

impl RunMode {
    /// 当前模式是否承载真实业务流量。
    fn runs_data(self) -> bool {
        matches!(self, Self::Data | Self::AllInOne)
    }

    /// 映射为 library 管理面权限边界，避免 admin 模块依赖 binary CLI 类型。
    fn admin_plane_mode(self) -> admin::AdminPlaneMode {
        match self {
            Self::Data => admin::AdminPlaneMode::Data,
            Self::Admin => admin::AdminPlaneMode::Admin,
            Self::AllInOne => admin::AdminPlaneMode::AllInOne,
        }
    }
}

/// Naway 外部配置固定目录(可 Docker 挂载)。`GW_*` 仅保留为旧迁移变量，不再提供旧品牌默认入口。
const DEFAULT_CONFIG_DIR: &str = "/data/naway";
const DEFAULT_CONFIG_FILE: &str = "naway.yml";

/// L7 HTTP 数据面的进程级共享依赖。
///
/// Snapshot 可热换；代理器、连接预算、在途计数和指标必须常驻，避免 reload 把运行态清零。
#[derive(Clone)]
struct DataPlaneState {
    /// 当前不可变配置快照指针；请求/accept 只做一次原子读取。
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// 常驻 HTTP 代理执行器，持有连接池与限流/健康运行态。
    proxy: Arc<GatewayProxy>,
    /// 按 proxy id 隔离的物理连接预算。
    connection_budget: Arc<ConnectionBudget>,
    /// HTTP + stream 共用的进程级在途连接数，供停机 drain 判断。
    active_connections: Arc<AtomicU64>,
    /// 数据面低基数指标。
    metrics: Arc<Metrics>,
}

/// 为下游传输增加“连续写 Pending”超时，不缓存也不复制 HTTP body。
///
/// Hyper 只有在 socket 可写时才继续 poll response body；若客户端停止读取，仅给上游 body 包 idle
/// timer 不会被 poll，无法释放连接。本 wrapper 在 TCP/TLS write/flush/shutdown 真正 Pending 时计时，
/// 成功写入后立即清零，因此不会因 SSE/gRPC 暂时没有输出而误杀连接。
struct DownstreamWriteTimeoutIo<I> {
    /// 已完成 PROXY protocol/TLS 握手后的真实下游 IO。
    inner: I,
    /// 单次连续 Pending 上限；None 表示关闭。
    timeout: Option<Duration>,
    /// 首次 Pending 时惰性创建，后续阻塞段只原地 reset；每条物理连接至多一次堆分配。
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// 当前是否已经为连续 Pending 段设置 deadline；Ready 后只清标志，不销毁 timer。
    write_blocked: bool,
}

impl<I> DownstreamWriteTimeoutIo<I> {
    /// 包装一个下游 IO；`timeout_ms=0` 保持原行为且不创建 timer。
    fn new(inner: I, timeout_ms: u64) -> Self {
        Self {
            inner,
            timeout: (timeout_ms > 0).then(|| Duration::from_millis(timeout_ms)),
            timer: None,
            write_blocked: false,
        }
    }

    /// 在 inner write 持续 Pending 时推进 deadline。
    fn poll_pending_timeout(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), io::Error>> {
        let Some(timeout) = self.timeout else {
            return Poll::Pending;
        };
        if !self.write_blocked {
            let deadline = tokio::time::Instant::now() + timeout;
            if let Some(timer) = self.timer.as_mut() {
                timer.as_mut().reset(deadline);
            } else {
                self.timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
            }
            self.write_blocked = true;
        }
        let timer = self.timer.as_mut().expect("blocked write has a timer");
        if timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "downstream write timed out",
            )))
        } else {
            Poll::Pending
        }
    }

    /// 任一 write/flush/shutdown 完成后重新从下一次 Pending 起计时。
    ///
    /// 保留已分配的 `Sleep` 很重要：h2 会在小 DATA/HEADERS 帧间频繁经历短 Pending，若每次
    /// Ready 都 drop，数据面会反复进入 Tokio timer wheel 的分配/锁路径。旧 deadline 后续即使
    /// 产生一次多余 wake 也不会报超时，因为下一段 Pending 会先 reset 到自己的新 deadline。
    fn write_progressed(&mut self) {
        self.write_blocked = false;
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for DownstreamWriteTimeoutIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for DownstreamWriteTimeoutIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Pending => self
                .poll_pending_timeout(cx)
                .map(|result| result.map(|()| 0)),
            Poll::Ready(result) => {
                self.write_progressed();
                Poll::Ready(result)
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => self.poll_pending_timeout(cx),
            Poll::Ready(result) => {
                self.write_progressed();
                Poll::Ready(result)
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Pending => self.poll_pending_timeout(cx),
            Poll::Ready(result) => {
                self.write_progressed();
                Poll::Ready(result)
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => self
                .poll_pending_timeout(cx)
                .map(|result| result.map(|()| 0)),
            Poll::Ready(result) => {
                self.write_progressed();
                Poll::Ready(result)
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// 每个 HTTP proxy 的物理下游连接预算。计数器常驻进程，不随 Snapshot 换版重置；limit 每次等待时
/// 从当前快照读取，因此调小预算会在现有连接自然退出后自动收敛，调大则立即唤醒 accept loop。
#[derive(Default)]
struct ConnectionBudget {
    /// proxy id -> 常驻计数器；reload 调整 limit 时不能替换计数器，否则会漏算旧连接。
    ///
    /// accept 是建连热路径，且同一 proxy 的明文/TLS listener 可能并发查表；使用不带 poisoning
    /// 的 `parking_lot::Mutex` 缩短极短临界区。表只在首次见到 listener id 时写入，锁内不 await。
    entries: ParkingMutex<HashMap<String, Arc<ConnectionBudgetEntry>>>,
}

/// 单个 proxy 的连接预算状态。
struct ConnectionBudgetEntry {
    /// 已占用的物理 TCP/TLS 连接数。
    active: AtomicU64,
    /// 连接释放或预算变化后的唤醒点；等待方会重新读取最新 Snapshot limit。
    changed: Notify,
}

/// 一个已占用的物理连接名额；Drop 是唯一归还路径，覆盖正常结束、握手失败和 task 取消。
struct ConnectionSlot {
    /// 所属 proxy 的常驻预算状态。
    entry: Arc<ConnectionBudgetEntry>,
}

/// 单条已接收连接从同一份不可变 Snapshot 固化的配置。
///
/// 连接建立后只保留真正需要的三个紧凑配置值，不持有整个 [`GatewaySnapshot`]，因此旧快照不会被
/// keep-alive/WS 长连接长期钉住。PROXY protocol 策略与预算上限也来自同一版本，避免 reload
/// 恰好发生在两次独立读取之间时拼出混合配置。
struct AcceptedConnection {
    /// 已占用的物理连接名额；任何后续失败都通过 Drop 自动归还。
    slot: ConnectionSlot,
    /// accept 后、TLS/HTTP 前需要执行的 PROXY protocol 策略。
    proxy_protocol: ProxyProtocolRuntimeCfg,
    /// 用于 listener 级 Builder cache 换版判断；配置版本只会随成功 reload 单调递增。
    snapshot_version: u64,
    /// 构造/命中 Hyper Builder 所需的同版资源上限。
    limits: ServerLimitsCfg,
    /// 下游写、请求头读取与总连接超时。
    timeouts: TimeoutCfg,
}

/// Hyper connection driver 只保留共享协议 Builder 与连接期超时，不钉住完整路由快照。
struct DownstreamConnectionConfig {
    /// 同一 listener、同一 Snapshot 版本共享的只读 HTTP/1+HTTP/2 Builder。
    server: Arc<auto::Builder<TokioExecutor>>,
    /// 写超时与总连接超时仍由各 connection future 直接读取。
    timeouts: TimeoutCfg,
}

/// accept loop 的协议 Builder cache。Builder 在 `serve_connection_with_upgrades` 后只读，因此
/// 同版连接可安全共享；活动旧连接持有自己的 `Arc`，reload 重建不会中断它们。
struct CachedDownstreamServer {
    /// 生成 Builder 的 Gateway Snapshot 版本。
    snapshot_version: u64,
    /// 预配置且只读的 Hyper server Builder。
    server: Arc<auto::Builder<TokioExecutor>>,
}

/// 把 accept 名额、进程活跃计数和指标绑定成同一个 Drop 边界。普通 HTTP 由 connection task
/// 持有；Upgrade 时 [`DownstreamConnectionLease`] 的 clone 被移动进 WS tunnel task。
struct ConnectionLifetime {
    _slot: ConnectionSlot,
    active_connections: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionLifetime {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        self.metrics.dec_active_connection();
    }
}

impl ConnectionBudget {
    /// 获取或创建指定 proxy 的常驻预算状态。
    ///
    /// # 参数
    /// - `proxy_id`: 数据面 listener 的稳定 id；相同 id 的明文/TLS listener 共享预算。
    ///
    /// 返回：可跨 task 持有的预算状态。该函数不占用连接名额。
    fn entry(&self, proxy_id: &str) -> Arc<ConnectionBudgetEntry> {
        let mut entries = self.entries.lock();
        // listener id 长期稳定；命中时借用查询，避免每次 accept 为 `entry(String)` 分配 key。
        if let Some(entry) = entries.get(proxy_id) {
            return entry.clone();
        }
        let entry = Arc::new(ConnectionBudgetEntry {
            active: AtomicU64::new(0),
            changed: Notify::new(),
        });
        entries.insert(proxy_id.to_owned(), entry.clone());
        entry
    }

    /// 非阻塞尝试占用一个物理连接名额。
    ///
    /// # 参数
    /// - `proxy_id`: 数据面 listener 的稳定 id。
    /// - `limit`: 当前 Snapshot 的连接上限；`0` 表示不限制，但仍记账以支持后续热调小。
    ///
    /// 返回：成功时返回 RAII 名额；达到上限返回 `None`，调用方不得继续创建连接 task。
    #[cfg(test)]
    fn try_acquire(&self, proxy_id: &str, limit: usize) -> Option<ConnectionSlot> {
        let entry = self.entry(proxy_id);
        Self::try_acquire_entry(&entry, limit)
    }

    /// 在已经定位预算条目的情况下执行无锁 CAS；成功前不 clone `Arc`，失败路径零分配。
    fn try_acquire_entry(
        entry: &Arc<ConnectionBudgetEntry>,
        limit: usize,
    ) -> Option<ConnectionSlot> {
        let limit = limit.min(u64::MAX as usize) as u64;
        let acquired = entry
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                (limit == 0 || active < limit).then_some(active.saturating_add(1))
            })
            .is_ok();
        // 必须惰性构造 RAII slot：`then_some` 会在 CAS 失败时也先构造值，临时值 Drop 会错误减计数。
        acquired.then(|| ConnectionSlot {
            entry: entry.clone(),
        })
    }

    /// 已 accept 的单个 socket 在这里等待预算。每个 listener 最多持有一个等待 socket，内核 backlog
    /// 承担其余排队，因此达到预算时不会无限 `tokio::spawn`（架构规范 §23）。
    ///
    /// # 参数
    /// - `proxy_id`: 当前 accept loop 对应的稳定 proxy id。
    /// - `entry`: listener 启动时定位一次的常驻预算句柄；热路径不再查 HashMap。
    /// - `snap`: 当前配置指针；每次被唤醒都重新读取 limit，使热调大/调小都能收敛。
    /// - `shutdown`: 停机广播；等待预算期间收到停机必须放弃已 accept socket。
    ///
    /// 返回：获得名额时返回 RAII slot 及同版连接配置；proxy 被删除、停机或广播关闭时返回
    /// `None`。
    async fn acquire(
        proxy_id: &str,
        entry: &Arc<ConnectionBudgetEntry>,
        snap: &Arc<ArcSwap<GatewaySnapshot>>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Option<AcceptedConnection> {
        loop {
            if *shutdown.borrow() {
                return None;
            }
            // 单次原子读取内同时取得 limit、PROXY 与 Hyper 参数。只有 CAS 成功才 clone 配置，
            // 达到上限的等待循环不制造临时 Vec/Arc 或延长旧 Snapshot 生命周期。
            let snapshot = snap.load();
            let proxy = snapshot.proxy(proxy_id)?;
            let limit = proxy.limits.max_connections;
            let changed = entry.changed.notified();
            if let Some(slot) = Self::try_acquire_entry(entry, limit) {
                return Some(AcceptedConnection {
                    slot,
                    proxy_protocol: proxy.proxy_protocol.clone(),
                    snapshot_version: snapshot.version,
                    limits: proxy.limits.clone(),
                    timeouts: proxy.timeouts.clone(),
                });
            }
            drop(snapshot);
            tokio::select! {
                _ = changed => {}
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return None;
                    }
                }
            }
        }
    }
}

impl Drop for ConnectionSlot {
    /// 归还名额并唤醒所有等待 listener；等待方会用 CAS 竞争最新可用名额。
    fn drop(&mut self) {
        self.entry.active.fetch_sub(1, Ordering::AcqRel);
        self.entry.changed.notify_waiters();
    }
}

#[path = "../tests/unit/main_binary.rs"]
#[cfg(test)]
mod connection_budget_tests;

/// L4 stream 负载均衡常驻状态。
///
/// 与配置快照解耦:reload 不应重置 `least_conn` 在途计数或 `round_robin` 游标。
#[derive(Clone, Default)]
struct StreamLbState {
    /// 上游 health_key -> 当前 stream 会话数。
    inflight: Arc<ParkingMutex<HashMap<Arc<str>, Arc<AtomicU64>>>>,
    /// 服务名 -> round_robin 单调游标。
    rr: Arc<ParkingMutex<HashMap<String, u64>>>,
    /// 上游 health_key -> 被动健康失败状态。
    failures: Arc<ParkingMutex<HashMap<String, StreamUpstreamFailureState>>>,
}

impl StreamLbState {
    /// 取某 stream 服务的下一个 round_robin 序号。
    ///
    /// # 参数
    /// - `service`: `lb://service` 的逻辑服务名。
    fn next_rr(&self, service: &str) -> u64 {
        let mut map = self.rr.lock();
        // 服务名来自快照且长期命中；只在首次出现时拥有一份 key。
        let counter = match map.get_mut(service) {
            Some(counter) => counter,
            None => {
                map.insert(service.to_owned(), 0);
                map.get_mut(service).expect("inserted stream rr counter")
            }
        };
        let current = *counter;
        *counter = counter.wrapping_add(1);
        current
    }

    /// 返回当前仍处于被动摘除窗口内的上游 health_key。
    ///
    /// # 参数
    /// - `policy`: 服务级被动健康策略。
    fn ejected_upstreams(&self, policy: PassiveHealthPolicy) -> Vec<String> {
        if !policy.enabled() {
            return Vec::new();
        }
        let now = Instant::now();
        let mut map = self.failures.lock();
        map.retain(|_, state| {
            state
                .ejected_until
                .map(|until| until > now)
                .unwrap_or(state.fails > 0)
        });
        map.iter()
            .filter_map(|(health_key, state)| {
                state
                    .ejected_until
                    .filter(|until| *until > now)
                    .map(|_| health_key.clone())
            })
            .collect()
    }

    /// 记录 stream 上游成功,清除对应失败状态。
    ///
    /// # 参数
    /// - `health_key`: 选中的上游实例身份键。
    fn record_success(&self, health_key: &str) {
        self.failures.lock().remove(health_key);
    }

    /// 记录 stream 上游失败,达到阈值后临时摘除。
    ///
    /// # 参数
    /// - `health_key`: 选中的上游实例身份键。
    /// - `policy`: 服务级被动健康策略。
    fn record_failure(&self, health_key: &str, policy: PassiveHealthPolicy) {
        if !policy.enabled() {
            return;
        }
        let now = Instant::now();
        let mut map = self.failures.lock();
        // 正常失败窗口内会重复命中同一 key；先借用查询，避免每次失败复制 URI。
        if !map.contains_key(health_key) {
            map.insert(
                health_key.to_owned(),
                StreamUpstreamFailureState {
                    fails: 0,
                    ejected_until: None,
                },
            );
        }
        let state = map
            .get_mut(health_key)
            .expect("stream failure state inserted above");
        if state
            .ejected_until
            .map(|until| until <= now)
            .unwrap_or(false)
        {
            state.ejected_until = None;
            state.fails = 0;
        }
        state.fails = state.fails.saturating_add(1);
        if state.fails >= policy.max_fails {
            state.ejected_until = Some(now + Duration::from_millis(policy.fail_timeout_ms));
            state.fails = 0;
            tracing::warn!(
                upstream = health_key,
                fail_timeout_ms = policy.fail_timeout_ms,
                "stream upstream passively ejected"
            );
        }
    }
}

#[derive(Clone)]
struct StreamUpstreamFailureState {
    fails: u32,
    ejected_until: Option<Instant>,
}

/// L4 stream 数据面共享状态。
#[derive(Clone)]
struct StreamPlaneState {
    /// 当前配置快照指针。
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// 主动健康探测器。
    active_health: Arc<gateway::health::ActiveHealthChecker>,
    /// stream 负载均衡常驻状态。
    lb: StreamLbState,
    /// 进程级连接数计数。
    active_connections: Arc<AtomicU64>,
    /// 共享 metrics。
    metrics: Arc<Metrics>,
    /// 非阻塞 access log。
    access_log: AccessLogger,
}

/// 主配置文件路径解析，优先级：`--config` > `NATE_CONFIG` > 兼容 `GW_CONFIG` >
/// `${NATE_CONFIG_DIR:-/data/naway}/naway.yml`。接口守卫 `interface-guard.yml` 相对主配置目录解析,
/// 故与主配置同放该固定目录(便于整目录挂载)。
fn config_path(args: &Args) -> PathBuf {
    if let Some(c) = &args.config {
        return c.into();
    }
    if let Ok(c) = std::env::var("NATE_CONFIG") {
        return c.into();
    }
    if let Ok(c) = std::env::var("GW_CONFIG") {
        return c.into();
    }
    if let Ok(dir) = std::env::var("NATE_CONFIG_DIR") {
        return PathBuf::from(dir).join(DEFAULT_CONFIG_FILE);
    }
    if let Ok(dir) = std::env::var("GW_CONFIG_DIR") {
        let dir = PathBuf::from(dir);
        let branded = dir.join(DEFAULT_CONFIG_FILE);
        return branded;
    }
    PathBuf::from(DEFAULT_CONFIG_DIR).join(DEFAULT_CONFIG_FILE)
}

fn pidfile_path() -> PathBuf {
    std::env::var("NATE_PIDFILE")
        .or_else(|_| std::env::var("GW_PIDFILE"))
        .unwrap_or_else(|_| "naway.pid".to_string())
        .into()
}

/// `-s reload`:读 pidfile → 向进程发 SIGHUP。
fn send_signal(sig: &str) -> Result<()> {
    if sig != "reload" {
        anyhow::bail!("unsupported signal `{sig}` (only `reload`)");
    }
    let pf = pidfile_path();
    // PID 最多十余字节；固定读 65 字节避免被篡改 pidfile 触发无界分配。
    let file =
        std::fs::File::open(&pf).with_context(|| format!("open pidfile {}", pf.display()))?;
    let mut bytes = Vec::with_capacity(16);
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 65), &mut bytes)
        .with_context(|| format!("read pidfile {}", pf.display()))?;
    anyhow::ensure!(
        bytes.len() <= 64,
        "pidfile {} exceeds 64 bytes",
        pf.display()
    );
    let raw_pid = std::str::from_utf8(&bytes)
        .with_context(|| format!("pidfile {} is not UTF-8", pf.display()))?;
    let pid = parse_reload_pid(raw_pid)?;
    // SAFETY: kill(2) 只发信号,不解引用指针。
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    if rc != 0 {
        anyhow::bail!(
            "kill {pid} SIGHUP failed: {}",
            std::io::Error::last_os_error()
        );
    }
    println!("sent SIGHUP to gateway pid {pid} (reload)");
    Ok(())
}

/// 解析 `-s reload` 使用的 PID，并拒绝 Unix `kill(2)` 的进程组/广播特殊值。
///
/// # 参数
///
/// - `raw`：pidfile 的完整文本；允许外围空白，但只接受正 `i32` PID。
fn parse_reload_pid(raw: &str) -> Result<i32> {
    let pid = raw.trim().parse::<i32>().context("parse pid")?;
    anyhow::ensure!(
        pid > 0,
        "pidfile must contain a positive process id; zero/negative values have process-group semantics"
    );
    Ok(pid)
}

/// 把同一 listener、同一 Snapshot 版本的 Hyper Builder 构造成本摊薄到一次。
///
/// `auto::Builder` 内含 HTTP/1 parser 与 HTTP/2 flow-control 配置。旧实现把它放在每条
/// connection task 内，10k 长连接会同时保留 10k 份完全相同的 Builder。这里按 listener
/// 缓存只读实例：命中只做一次 `Arc` 增计数；reload 后首条新连接重建，旧连接继续持有旧版本。
///
/// # 参数
/// - `cache`: 当前 accept loop 私有的单项 cache，无锁且不会跨 listener 争用。
/// - `snapshot_version`: 本连接读取配置时的原子快照版本。
/// - `limits`: 请求头、HTTP/2 stream 与 flow-control 的硬预算。
/// - `timeouts`: header timer 写入 Builder，其余连接期超时随返回值移动。
fn downstream_connection_config(
    cache: &mut Option<CachedDownstreamServer>,
    snapshot_version: u64,
    limits: &ServerLimitsCfg,
    timeouts: TimeoutCfg,
) -> DownstreamConnectionConfig {
    if let Some(cached) = cache
        .as_ref()
        .filter(|cached| cached.snapshot_version == snapshot_version)
    {
        return DownstreamConnectionConfig {
            server: cached.server.clone(),
            timeouts,
        };
    }

    let mut server = auto::Builder::new(TokioExecutor::new());
    // 读请求头超时(slowloris 防护)走配置，0 = 关闭；timer 同样只需按配置版本装配一次。
    let header_read_timeout = if timeouts.header_read_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(timeouts.header_read_timeout_ms))
    };
    server
        .http1()
        .max_headers(limits.max_headers)
        .max_buf_size(limits.max_header_bytes.max(8192))
        .header_read_timeout(header_read_timeout)
        .timer(TokioTimer::new());
    server
        .http2()
        .max_concurrent_streams(Some(limits.max_concurrent_streams))
        // 显式、有界 flow-control，不启用 adaptive window：后者会覆盖配置窗口并随 BDP
        // 动态放大，破坏 §23 可审计的资源预算。窗口只发放 credit，不 collect body。
        .initial_stream_window_size(Some(limits.h2_initial_stream_window_bytes))
        .initial_connection_window_size(Some(limits.h2_initial_connection_window_bytes))
        .max_header_list_size(limits.max_header_bytes.min(u32::MAX as usize) as u32)
        .timer(TokioTimer::new());
    let server = Arc::new(server);
    *cache = Some(CachedDownstreamServer {
        snapshot_version,
        server: server.clone(),
    });
    DownstreamConnectionConfig { server, timeouts }
}

fn spawn_downstream_connection<I>(
    stream: I,
    conn: ConnInfo,
    proxy_id: Arc<str>,
    downstream_proto: &'static str,
    state: DataPlaneState,
    config: DownstreamConnectionConfig,
    slot: ConnectionSlot,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let DownstreamConnectionConfig { server, timeouts } = config;
    // IP header 只依赖已完成 PROXY protocol 校验的连接地址。提前到 accept/connection 层构造，
    // 让 H2 多路复用的每个 RPC 只 clone 不可变 HeaderValue；trusted XFF 改写仍由请求层核对。
    let connection_client_ip_header = ConnectionClientIpHeader::new(conn);
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    state.metrics.inc_active_connection();
    let connection_lifetime = DownstreamConnectionLease::new(ConnectionLifetime {
        _slot: slot,
        active_connections: state.active_connections.clone(),
        metrics: state.metrics.clone(),
    });
    tokio::spawn(async move {
        let io = TokioIo::new(DownstreamWriteTimeoutIo::new(
            stream,
            timeouts.downstream_write_timeout_ms,
        ));
        let proxy = state.proxy.clone();
        let request_connection_lifetime = connection_lifetime.clone();
        let request_client_ip_header = connection_client_ip_header;
        let svc = service_fn(move |mut req: hyper::Request<Incoming>| {
            // 只有带 Upgrade 头的候选请求才 clone/分配 Extensions。普通 HTTP/1 keep-alive 与
            // HTTP/2 热路径完全不承担 WS 生命周期修复成本；proxy::handle 仍完整校验 GET、h1、
            // Connection: upgrade 和 websocket 值，非法 Upgrade 不会进入隧道。
            if req.headers().contains_key(hyper::header::UPGRADE) {
                req.extensions_mut()
                    .insert(request_connection_lifetime.clone());
            }
            proxy.clone().handle_with_connection_ip_header(
                req,
                conn,
                downstream_proto,
                proxy_id.clone(),
                request_client_ip_header.clone(),
            )
        });
        // Builder 按 listener/Snapshot 共享且在 serve 阶段只读。连接 future 借用 `server`，本 task
        // 持有 Arc 直到正常结束或 Upgrade 完成，避免任何自引用或悬空借用。
        let connection = server.serve_connection_with_upgrades(io, svc);
        let result = if timeouts.connection_timeout_ms == 0 {
            connection.await
        } else {
            match tokio::time::timeout(
                Duration::from_millis(timeouts.connection_timeout_ms),
                connection,
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    tracing::debug!(peer = %conn.real_peer, "connection closed by total timeout");
                    return;
                }
            }
        };
        if let Err(e) = result {
            tracing::debug!(error = %e, "connection closed with error");
        }
        // `connection_lifetime` 在普通 HTTP 结束时随 service/task 释放；若发生 Upgrade，隧道持有
        // 另一个 clone，最后一个 clone Drop 才统一归还预算与两个 active counter。
    });
}

fn spawn_plain_accept_loop(
    listener: TcpListener,
    proxy_id: Arc<str>,
    state: DataPlaneState,
    mut shutdown: watch::Receiver<bool>,
) {
    // listener id 与预算 entry 同寿命：bootstrap 时查表一次，之后每个 accept 只做原子 CAS。
    // 这也避免明文/TLS listener 并发建连时在全局 HashMap 短锁上互相干扰。
    let budget_entry = state.connection_budget.entry(&proxy_id);
    tokio::spawn(async move {
        let local = listener.local_addr().ok();
        info!(?local, proxy = %proxy_id, "data plane listening");
        // 单 listener 单项 cache；同版建连无锁命中，reload 首条连接才重建协议 Builder。
        let mut server_cache = None;
        loop {
            // ★L7:accept 与停机信号二选一——SIGTERM 后 changed() 触发即停收新连接(§24),
            //   再由 main 的 drain 等在途请求收尾。
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        continue;
                    }
                },
                _ = shutdown.changed() => {
                    info!(proxy = %proxy_id, "stop accepting new connections (shutdown)");
                    break;
                }
            };
            configure_downstream_tcp(&stream, peer);
            let Some(accepted) =
                ConnectionBudget::acquire(&proxy_id, &budget_entry, &state.snap, &mut shutdown)
                    .await
            else {
                break;
            };
            let AcceptedConnection {
                slot,
                proxy_protocol,
                snapshot_version,
                limits,
                timeouts,
            } = accepted;
            let downstream = downstream_connection_config(
                &mut server_cache,
                snapshot_version,
                &limits,
                timeouts,
            );
            if !proxy_protocol.enabled {
                // 绝大多数直连 listener 不启用 PROXY protocol。旧路径仍为每个连接 spawn 一个
                // 只会立即返回的 strip task，随后 `spawn_downstream_connection` 再 spawn Hyper
                // driver，10k 建连因此产生两次 task 分配/调度。禁用时地址完全来自 accept，直接
                // 进入 driver 即可；启用路径仍必须独立 task 异步读有界 header，不能阻塞 accept。
                spawn_downstream_connection(
                    stream,
                    ConnInfo::plain(peer),
                    proxy_id.clone(),
                    "http",
                    state.clone(),
                    downstream,
                    slot,
                );
                continue;
            }
            let state = state.clone();
            let proxy_id = proxy_id.clone();
            tokio::spawn(async move {
                match strip_proxy_protocol(stream, peer, &proxy_protocol).await {
                    Ok((stream, conn)) => spawn_downstream_connection(
                        stream, conn, proxy_id, "http", state, downstream, slot,
                    ),
                    Err(e) => warn!(peer = %peer, error = %e, "proxy protocol rejected connection"),
                }
            });
        }
    });
}

fn spawn_tls_accept_loop(
    listener: TcpListener,
    proxy_id: Arc<str>,
    tls_config: SharedServerConfig,
    state: DataPlaneState,
    mut shutdown: watch::Receiver<bool>,
) {
    // 与明文 listener 相同，预算句柄在启动期固定；reload 只更新 Snapshot 中的 limit。
    let budget_entry = state.connection_budget.entry(&proxy_id);
    tokio::spawn(async move {
        let local = listener.local_addr().ok();
        info!(?local, proxy = %proxy_id, "tls data plane listening");
        let mut server_cache = None;
        loop {
            // ★L7:同明文入口,SIGTERM 后停收新 TLS 连接。
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "tls accept failed");
                        continue;
                    }
                },
                _ = shutdown.changed() => {
                    info!(proxy = %proxy_id, "stop accepting new tls connections (shutdown)");
                    break;
                }
            };
            configure_downstream_tcp(&stream, peer);
            let Some(accepted) =
                ConnectionBudget::acquire(&proxy_id, &budget_entry, &state.snap, &mut shutdown)
                    .await
            else {
                break;
            };
            let AcceptedConnection {
                slot,
                proxy_protocol,
                snapshot_version,
                limits,
                timeouts,
            } = accepted;
            let downstream = downstream_connection_config(
                &mut server_cache,
                snapshot_version,
                &limits,
                timeouts,
            );
            // ★廉价:从 ArcSwap 取当前证书配置(仅 Arc clone),不再每条连接读盘 + 解析证书(去 DoS 放大 + 去阻塞)。
            let acceptor = TlsAcceptor::from(tls_config.load_full());
            let state = state.clone();
            let proxy_id = proxy_id.clone();
            tokio::spawn(async move {
                match strip_proxy_protocol(stream, peer, &proxy_protocol).await {
                    Ok((stream, mut conn)) => match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // mTLS(§19):握手成功且出示了客户端证书(已被 verifier 校验通过)→ 标记 verified,
                            // 供数据面注入 X-Client-Cert-Verified。require 模式下无证书握手会在上面 accept 失败。
                            conn.client_cert_verified = tls_stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .is_some_and(|certs| !certs.is_empty());
                            spawn_downstream_connection(
                                tls_stream, conn, proxy_id, "https", state, downstream, slot,
                            )
                        }
                        Err(e) => warn!(peer = %peer, error = %e, "tls handshake failed"),
                    },
                    Err(e) => {
                        warn!(peer = %peer, error = %e, "proxy protocol rejected tls connection")
                    }
                }
            });
        }
    });
}

/// 为 L7 下游 TCP socket 启用小帧低延迟模式。
///
/// HTTP/2/gRPC 会把 HEADERS、5-byte gRPC envelope、短 DATA 和 WINDOW_UPDATE 复用在长寿命
/// transport 上。保留系统默认 Nagle 时，这些 frame 可能与对端 delayed ACK 形成约 40ms 的
/// 停顿；这不是合理的吞吐/资源折中，因为 h2 本身已经在 driver 层聚合一次就绪写。这里只切换
/// socket 标志，不建立用户态 buffer、不复制 payload，也不改变慢下游写超时和背压。
///
/// `setsockopt` 失败不会拒绝一个已经 accept 的合法连接；保留服务可用性并记录 peer，性能门会
/// 暴露平台是否无法提供该选项。
fn configure_downstream_tcp(stream: &TcpStream, peer: SocketAddr) {
    if let Err(error) = stream.set_nodelay(true) {
        warn!(%peer, %error, "failed to enable TCP_NODELAY on downstream connection");
    }
}

/// 等待 ACME 首签 keypair 落盘后，在同一进程激活已经绑定的 TLS listener。
///
/// # 参数
/// - `listener`: 启动期已绑定的 TLS socket，避免签发完成时端口被其它进程抢占。
/// - `proxy_id`: listener 所属 proxy id。
/// - `tls_cfg`: cert/key、SNI、mTLS 与激活轮询配置。
/// - `state`: L7 数据面共享状态。
/// - `shutdown`: 停机广播；首签未完成时也必须及时释放已绑定 socket。
/// - `pending_tls`: 全进程尚未激活的 TLS listener 数。
/// - `ready`: 全部 deferred TLS 激活后置 true，使 `/readyz` 与实际服务能力一致。
fn spawn_deferred_tls_accept_loop(
    listener: TcpListener,
    proxy_id: Arc<str>,
    tls_cfg: gateway::config::TlsRuntimeCfg,
    state: DataPlaneState,
    mut shutdown: watch::Receiver<bool>,
    pending_tls: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let poll_ms = tls_cfg
            .acme
            .as_ref()
            .map(|acme| acme.activation_poll_ms)
            .unwrap_or(250)
            .max(1);
        let mut last_error = None;
        loop {
            match build_server_config(&tls_cfg) {
                Ok(server_config) => {
                    let shared_tls: SharedServerConfig = Arc::new(ArcSwap::new(server_config));
                    spawn_cert_watcher(tls_cfg.clone(), shared_tls.clone());
                    let listen = listener.local_addr().ok();
                    spawn_tls_accept_loop(listener, proxy_id.clone(), shared_tls, state, shutdown);
                    let previous = pending_tls.fetch_sub(1, Ordering::AcqRel);
                    if previous == 1 {
                        ready.store(true, Ordering::Release);
                    }
                    info!(proxy = %proxy_id, ?listen, "ACME bootstrap keypair installed; TLS listener activated without restart");
                    return;
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    if tls_cfg.cert_file.is_file()
                        && tls_cfg.key_file.is_file()
                        && last_error.as_deref() != Some(message.as_str())
                    {
                        warn!(proxy = %proxy_id, error = %message, "deferred TLS keypair exists but is not usable; keeping listener inactive");
                    }
                    last_error = Some(message);
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!(proxy = %proxy_id, "stop deferred TLS activation (shutdown)");
                        return;
                    }
                }
            }
        }
    });
}

#[derive(Clone)]
struct UdpSessionHandle {
    id: u64,
    sender: mpsc::Sender<QueuedUdpDatagram>,
}

/// listener 级 UDP 内存硬预算。单会话 channel/receive buffer 各自有界仍不够：大量 client 可
/// 同时建 session 并填满各自 queue。256MiB 同时覆盖实际排队 payload 与每 session 的上游接收
/// buffer；semaphore 本身不预分配这块内存。
const UDP_BUFFERED_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// 一份 UDP payload 及其字节预算。permit 与 `Bytes` 一起在 channel 中 move；发送完成、session
/// 建立失败或队列关闭时由 RAII 自动归还，不需要额外计数锁。
struct QueuedUdpDatagram {
    bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}

fn reserve_udp_datagram(budget: &Arc<Semaphore>, payload: &[u8]) -> Option<QueuedUdpDatagram> {
    let permits = u32::try_from(payload.len()).ok()?;
    // 先 reserve 再 copy：全局预算耗尽时不能仍为攻击流量分配 payload。
    let permit = budget.clone().try_acquire_many_owned(permits).ok()?;
    Some(QueuedUdpDatagram {
        bytes: Bytes::copy_from_slice(payload),
        _permit: permit,
    })
}

static STREAM_UDP_SESSION_SEQ: AtomicU64 = AtomicU64::new(1);
/// IPv4 UDP payload 的协议最大值。listener 缓冲固定按协议上限分配一次，使
/// `udp.max_datagram_bytes` 热更调大后也不会继续被旧快照的小缓冲静默截断。
const UDP_MAX_PAYLOAD_BYTES: usize = 65_507;

/// 启动 UDP listener。主 socket 只做一次 datagram 接收与按客户端地址分派；每个活动
/// client 建一个 connected upstream socket，形成 `(client,listener,upstream)` 短会话。
/// channel 满或 session 表满时立即丢当前 datagram，绝不让单个慢上游反压整个 listener。
fn spawn_stream_udp_loop(
    socket: Arc<UdpSocket>,
    bound_runtime: StreamRuntime,
    state: StreamPlaneState,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let sessions = Arc::new(ParkingMutex::new(
            HashMap::<SocketAddr, UdpSessionHandle>::new(),
        ));
        let resource_budget = Arc::new(Semaphore::new(UDP_BUFFERED_MEMORY_BUDGET_BYTES));
        // listener 生命周期跨越普通配置 reload；按协议上限固定 64 KiB 的单份缓冲，运行期再用
        // 当前快照的 max_datagram_bytes 判定是否接收。每 listener 一次分配，不按报文分配。
        let mut buffer = vec![0_u8; UDP_MAX_PAYLOAD_BYTES + 1];
        info!(stream = %bound_runtime.id, listen = ?socket.local_addr(), "stream udp listening");
        loop {
            let (length, peer) = tokio::select! {
                received = socket.recv_from(&mut buffer) => match received {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(stream = %bound_runtime.id, %error, "stream UDP receive failed");
                        state.metrics.inc_stream_error();
                        continue;
                    }
                },
                _ = shutdown.changed() => {
                    info!(stream = %bound_runtime.id, "stop receiving new UDP stream datagrams (shutdown)");
                    break;
                }
            };
            let runtime = current_stream_runtime(&state.snap, &bound_runtime.id)
                .unwrap_or_else(|| bound_runtime.clone());
            if length > runtime.udp.max_datagram_bytes {
                state.metrics.inc_stream_udp_drop();
                continue;
            }
            // Datagram ownership requires one copy out of the reusable listener buffer；全局字节 permit
            // 在复制前取得，避免“每 session 有界但 session 总数巨大”仍形成无界 payload。
            let Some(datagram) = reserve_udp_datagram(&resource_budget, &buffer[..length]) else {
                state.metrics.inc_stream_udp_drop();
                continue;
            };
            let mut table = sessions.lock();
            if let Some(session) = table.get(&peer).cloned() {
                match session.sender.try_send(datagram) {
                    Ok(()) => {
                        state.metrics.inc_stream_udp_datagram(true);
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        state.metrics.inc_stream_udp_drop();
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(returned)) => {
                        table.remove(&peer);
                        // Reuse ownership returned by the closed channel; no second payload copy.
                        drop(table);
                        create_udp_session(
                            socket.clone(),
                            sessions.clone(),
                            peer,
                            returned,
                            runtime,
                            state.clone(),
                            resource_budget.clone(),
                        );
                        continue;
                    }
                }
            }
            if table.len() >= runtime.udp.max_sessions {
                state.metrics.inc_stream_udp_drop();
                continue;
            }
            drop(table);
            create_udp_session(
                socket.clone(),
                sessions.clone(),
                peer,
                datagram,
                runtime,
                state.clone(),
                resource_budget.clone(),
            );
        }
        // Dropping all senders asks session tasks to finish; connected sockets close without RST semantics.
        sessions.lock().clear();
    });
}

/// 建立一个 UDP session 控制对象并派生实际 I/O task。插入表和首包 enqueue 都是同步的，
/// 因此 listener 即使在 DNS/上游 socket 初始化期间继续收到同 client 数据，也只进入同一有界队列。
fn create_udp_session(
    listener: Arc<UdpSocket>,
    sessions: Arc<ParkingMutex<HashMap<SocketAddr, UdpSessionHandle>>>,
    peer: SocketAddr,
    first: QueuedUdpDatagram,
    runtime: StreamRuntime,
    state: StreamPlaneState,
    resource_budget: Arc<Semaphore>,
) {
    let Some(route) = runtime.routes.iter().find(|route| route.default).cloned() else {
        state.metrics.inc_stream_udp_drop();
        return;
    };
    let snapshot = state.snap.load();
    let reservation =
        match resolve_stream_upstream(&snapshot, &route, &state.lb, &state.active_health) {
            Ok(reservation) if reservation.tls_profile.is_none() => reservation,
            Ok(_) => {
                state.metrics.inc_stream_udp_drop();
                return;
            }
            Err(error) => {
                warn!(stream = %runtime.id, %peer, %error, "resolve UDP stream upstream failed");
                state.metrics.inc_stream_udp_drop();
                return;
            }
        };
    drop(snapshot);
    let receive_buffer_bytes = runtime.udp.max_datagram_bytes.saturating_add(1);
    let Ok(receive_buffer_permit) = resource_budget
        .try_acquire_many_owned(u32::try_from(receive_buffer_bytes).unwrap_or(u32::MAX))
    else {
        state.metrics.inc_stream_udp_drop();
        return;
    };
    let id = STREAM_UDP_SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let (sender, receiver) = mpsc::channel(runtime.udp.queue_capacity);
    if sender.try_send(first).is_err() {
        state.metrics.inc_stream_udp_drop();
        return;
    }
    sessions
        .lock()
        .insert(peer, UdpSessionHandle { id, sender });
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    state.metrics.inc_active_connection();
    state.metrics.inc_stream_connection();
    state.metrics.inc_stream_udp_datagram(true);
    tokio::spawn(run_udp_session(
        listener,
        sessions,
        id,
        peer,
        runtime,
        route,
        reservation,
        receiver,
        receive_buffer_permit,
        state,
    ));
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    listener: Arc<UdpSocket>,
    sessions: Arc<ParkingMutex<HashMap<SocketAddr, UdpSessionHandle>>>,
    id: u64,
    peer: SocketAddr,
    runtime: StreamRuntime,
    route: StreamRouteRuntime,
    reservation: StreamUpstreamReservation,
    mut receiver: mpsc::Receiver<QueuedUdpDatagram>,
    _receive_buffer_permit: OwnedSemaphorePermit,
    state: StreamPlaneState,
) {
    let started = std::time::Instant::now();
    let log_ctx = StreamAccessLogCtx {
        request_id: next_stream_request_id(),
        stream_id: Arc::from(format!("{}:{}", runtime.id, route.id)),
        upstream: reservation.log_target.clone(),
        peer: peer.to_string(),
        started,
    };
    let result = async {
        let upstream_addr = tokio::net::lookup_host(reservation.addr.as_str())
            .await
            .with_context(|| format!("resolve UDP upstream {}", reservation.addr))?
            .next()
            .context("UDP upstream DNS returned no address")?;
        let bind = if upstream_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let upstream = UdpSocket::bind(bind).await.context("bind UDP session socket")?;
        upstream
            .connect(upstream_addr)
            .await
            .context("connect UDP session socket")?;
        let mut upstream_buffer = vec![0_u8; runtime.udp.max_datagram_bytes.saturating_add(1)];
        let idle = tokio::time::sleep(Duration::from_millis(runtime.udp.idle_timeout_ms));
        tokio::pin!(idle);
        let total = tokio::time::sleep(Duration::from_millis(runtime.timeout_ms.max(1)));
        tokio::pin!(total);
        let mut down = 0_u64;
        let mut up = 0_u64;
        loop {
            tokio::select! {
                maybe = receiver.recv() => {
                    let Some(datagram) = maybe else { break };
                    upstream.send(&datagram.bytes).await.context("send UDP upstream datagram")?;
                    down = down.saturating_add(datagram.bytes.len() as u64);
                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(runtime.udp.idle_timeout_ms));
                }
                received = upstream.recv(&mut upstream_buffer) => {
                    let length = received.context("receive UDP upstream datagram")?;
                    if length > runtime.udp.max_datagram_bytes {
                        state.metrics.inc_stream_udp_drop();
                        continue;
                    }
                    listener.send_to(&upstream_buffer[..length], peer).await.context("send UDP downstream datagram")?;
                    up = up.saturating_add(length as u64);
                    state.metrics.inc_stream_udp_datagram(false);
                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(runtime.udp.idle_timeout_ms));
                }
                _ = &mut idle => break,
                _ = &mut total, if runtime.timeout_ms > 0 => break,
            }
        }
        Ok::<_, anyhow::Error>((down, up))
    }
    .await;

    {
        let mut table = sessions.lock();
        // 只删除自己；一个刚重建的新 session 可能已占用同一 peer key。
        if table.get(&peer).is_some_and(|current| current.id == id) {
            table.remove(&peer);
        }
    }
    match result {
        Ok((down, up)) => {
            record_stream_upstream_success(&state, &reservation);
            state.metrics.add_stream_bytes(down, up);
            log_stream_access(&state.access_log, &log_ctx, 200, down, up);
        }
        Err(error) => {
            record_stream_upstream_failure(&state, &reservation);
            state.metrics.inc_stream_error();
            log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
            tracing::debug!(stream = %runtime.id, %peer, %error, "UDP stream session failed");
        }
    }
    finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
}

/// 启动 L4 stream TCP accept loop。
///
/// # 参数
/// - `listener`: 已绑定的 stream listener。
/// - `runtime`: stream 运行期配置。
/// - `state`: stream 数据面共享状态。
/// - `shutdown`: 停机广播。
fn spawn_stream_accept_loop(
    listener: TcpListener,
    runtime: StreamRuntime,
    tls: Option<SharedServerConfig>,
    state: StreamPlaneState,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let local = listener.local_addr().ok();
        info!(?local, stream = %runtime.id, upstream = %runtime.upstream, "stream tcp listening");
        loop {
            let (downstream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(stream = %runtime.id, error = %e, "stream accept failed");
                        continue;
                    }
                },
                _ = shutdown.changed() => {
                    info!(stream = %runtime.id, "stop accepting new stream connections (shutdown)");
                    break;
                }
            };
            spawn_stream_connection(
                downstream,
                peer,
                runtime.clone(),
                tls.clone(),
                state.clone(),
            );
        }
    });
}

/// 处理一条 L4 stream TCP 连接。
///
/// # 参数
/// - `downstream`: 下游 TCP socket。
/// - `peer`: 下游对端地址。
/// - `bound_runtime`: 启动期绑定 socket 的 stream 配置,仅作为当前快照缺失时的兜底。
/// - `state`: stream 数据面共享状态。
fn spawn_stream_connection(
    downstream: TcpStream,
    peer: SocketAddr,
    bound_runtime: StreamRuntime,
    tls: Option<SharedServerConfig>,
    state: StreamPlaneState,
) {
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    state.metrics.inc_active_connection();
    state.metrics.inc_stream_connection();
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let runtime =
            current_stream_runtime(&state.snap, &bound_runtime.id).unwrap_or(bound_runtime);
        let downstream_local = downstream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(peer.ip(), 0));
        let mut log_ctx = StreamAccessLogCtx {
            request_id: next_stream_request_id(),
            stream_id: Arc::from(runtime.id.as_str()),
            upstream: Arc::from(runtime.upstream.as_str()),
            peer: peer.to_string(),
            started,
        };
        let (stream, conn) = match strip_proxy_protocol(downstream, peer, &runtime.proxy_protocol)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                warn!(stream = %runtime.id, peer = %peer, error = %e, "stream proxy protocol rejected");
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
        };
        let mut downstream: BoxStreamIo = match tls {
            Some(config) => {
                // 先剥可信 PROXY header，再开始 TLS；这与前置 L4 LB 的 wire 顺序一致。
                // acceptor 只 clone 当前 ArcSwap 证书指针，热路径不读盘/解析 PEM。
                let accept = TlsAcceptor::from(config.load_full()).accept(stream);
                match tokio::time::timeout(
                    Duration::from_millis(runtime.tls_handshake_timeout_ms),
                    accept,
                )
                .await
                {
                    Ok(Ok(stream)) => Box::new(stream),
                    Ok(Err(error)) => {
                        warn!(stream = %runtime.id, peer = %peer, %error, "stream TLS handshake failed");
                        state.metrics.inc_stream_error();
                        log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                        finish_stream_connection(
                            state.active_connections.clone(),
                            state.metrics.clone(),
                        );
                        return;
                    }
                    Err(_) => {
                        warn!(stream = %runtime.id, peer = %peer, "stream TLS handshake timeout");
                        state.metrics.inc_stream_error();
                        log_stream_access(&state.access_log, &log_ctx, 408, 0, 0);
                        finish_stream_connection(
                            state.active_connections.clone(),
                            state.metrics.clone(),
                        );
                        return;
                    }
                }
            }
            None => Box::new(stream),
        };
        let peer = conn.real_peer;
        log_ctx.peer = peer.to_string();
        let preread = if runtime.preread.ssl_preread {
            match stream_preread_sni(
                &mut downstream,
                runtime.preread.timeout_ms,
                runtime.preread.max_bytes,
            )
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    warn!(stream = %runtime.id, peer = %peer, error = %e, "stream ssl preread failed");
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
            }
        } else if runtime.preread.mqtt_connect {
            match stream_preread_mqtt_connect(
                &mut downstream,
                runtime.preread.timeout_ms,
                runtime.preread.max_bytes,
            )
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    warn!(stream = %runtime.id, peer = %peer, %error, "stream MQTT CONNECT preread failed");
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
            }
        } else {
            StreamPrereadResult {
                sni: None,
                mqtt_client_id: None,
                bytes: Vec::new(),
            }
        };
        let Some(route) = select_stream_route(
            &runtime,
            preread.sni.as_deref(),
            preread.mqtt_client_id.as_deref(),
        ) else {
            warn!(stream = %runtime.id, peer = %peer, sni = ?preread.sni, mqtt_client_id = ?preread.mqtt_client_id, "no matching stream route");
            state.metrics.inc_stream_error();
            log_stream_access(&state.access_log, &log_ctx, 404, 0, 0);
            finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
            return;
        };
        log_ctx.stream_id = Arc::from(format!("{}:{}", runtime.id, route.id));
        let current_snap = state.snap.load();
        let reservation = match resolve_stream_upstream(
            &current_snap,
            route,
            &state.lb,
            &state.active_health,
        ) {
            Ok(reservation) => reservation,
            Err(e) => {
                warn!(stream = %runtime.id, peer = %peer, upstream = %route.upstream, error = %e, "stream upstream resolve failed");
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
        };
        drop(current_snap);
        log_ctx.upstream = reservation.log_target.clone();
        let upstream_addr = reservation.addr.clone();
        let connect = connect_stream_upstream(&reservation);
        let upstream = if runtime.connect_timeout_ms == 0 {
            connect.await
        } else {
            match tokio::time::timeout(Duration::from_millis(runtime.connect_timeout_ms), connect)
                .await
            {
                Ok(result) => result,
                Err(_) => {
                    warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, "stream upstream connect timeout");
                    record_stream_upstream_failure(&state, &reservation);
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 504, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
            }
        };
        let mut upstream: BoxStreamIo = match upstream {
            Ok(upstream) => upstream,
            Err(e) => {
                warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, error = %e, "stream upstream connect failed");
                record_stream_upstream_failure(&state, &reservation);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
        };
        if runtime.proxy_protocol_to_upstream.enabled {
            let header = match encode_proxy_protocol_header(
                peer,
                downstream_local,
                runtime.proxy_protocol_to_upstream.version,
            ) {
                Ok(header) => header,
                Err(e) => {
                    warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, error = %e, "stream upstream proxy protocol header build failed");
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
            };
            if let Err(e) = upstream.write_all(&header).await {
                warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, error = %e, "stream upstream proxy protocol header write failed");
                record_stream_upstream_failure(&state, &reservation);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
        }
        if !preread.bytes.is_empty() {
            if let Err(e) = upstream.write_all(&preread.bytes).await {
                warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, error = %e, "stream preread replay to upstream failed");
                record_stream_upstream_failure(&state, &reservation);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
        }
        // WHY:L4 stream 不解析应用层协议,只搬运字节;copy_bidirectional 保持双向背压。
        let copied = io::copy_bidirectional(&mut downstream, &mut upstream);
        let result = if runtime.timeout_ms == 0 {
            copied.await
        } else {
            match tokio::time::timeout(Duration::from_millis(runtime.timeout_ms), copied).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(stream = %runtime.id, peer = %peer, elapsed_ms = started.elapsed().as_millis(), "stream session timeout");
                    record_stream_upstream_failure(&state, &reservation);
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 504, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
            }
        };
        match result {
            Ok((down, up)) => {
                let down = down.saturating_add(preread.bytes.len() as u64);
                record_stream_upstream_success(&state, &reservation);
                state.metrics.add_stream_bytes(down, up);
                log_stream_access(&state.access_log, &log_ctx, 200, down, up);
                tracing::debug!(
                    stream = %runtime.id,
                    peer = %peer,
                    upstream = %upstream_addr,
                    bytes_downstream_to_upstream = down,
                    bytes_upstream_to_downstream = up,
                    elapsed_ms = started.elapsed().as_millis(),
                    "stream session closed"
                );
            }
            Err(e) => {
                record_stream_upstream_failure(&state, &reservation);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                tracing::debug!(stream = %runtime.id, peer = %peer, error = %e, "stream session closed with error")
            }
        }
        finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
    });
}

/// stream preread 结果。
struct StreamPrereadResult {
    /// TLS ClientHello 中的 SNI。
    sni: Option<String>,
    /// MQTT CONNECT 中的 client id。
    mqtt_client_id: Option<String>,
    /// 已从下游读取、必须原样写给上游的字节。
    bytes: Vec<u8>,
}

/// 根据 preread SNI 选择 stream route。
///
/// # 参数
/// - `runtime`: stream listener 运行配置。
/// - `sni`: preread 得到的 SNI。
fn select_stream_route<'a>(
    runtime: &'a StreamRuntime,
    sni: Option<&str>,
    mqtt_client_id: Option<&str>,
) -> Option<&'a gateway::config::StreamRouteRuntime> {
    let sni = sni.map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase());
    if let Some(sni) = sni.as_deref() {
        if let Some(route) = runtime
            .routes
            .iter()
            .find(|route| route.sni.as_deref() == Some(sni))
        {
            return Some(route);
        }
    }
    if let Some(client_id) = mqtt_client_id {
        if let Some(route) = runtime
            .routes
            .iter()
            .find(|route| route.mqtt_client_id.as_deref() == Some(client_id))
        {
            return Some(route);
        }
    }
    runtime.routes.iter().find(|route| route.default)
}

/// 读取当前快照里的 stream listener 配置。
///
/// # 参数
/// - `snap`: 当前配置快照指针。
/// - `stream_id`: 启动期已绑定 listener 的 id。
fn current_stream_runtime(
    snap: &Arc<ArcSwap<GatewaySnapshot>>,
    stream_id: &str,
) -> Option<StreamRuntime> {
    snap.load()
        .stream_listeners
        .iter()
        .find(|runtime| runtime.id == stream_id)
        .cloned()
}

/// 一次 stream 上游选择的 in-flight reservation。
struct StreamUpstreamReservation {
    /// 可直接传给 `TcpStream::connect` 的地址。
    addr: String,
    /// access log 展示用目标。`lb://` 时记录选中实例 URI,直连时记录地址。
    log_target: Arc<str>,
    /// 需要参与被动健康记录的上游实例身份键。
    selected_health_key: Option<Arc<str>>,
    /// 服务级被动健康策略。
    passive_policy: PassiveHealthPolicy,
    /// 已解析的 raw TCP TLS client profile；None 表示明文上游。
    tls_profile: Option<gateway::tls::UpstreamTlsProfile>,
    /// profile 未覆盖 SNI 时使用的目标 host；构建/解析后共享，不在握手时切字符串。
    tls_server_name: Option<Arc<str>>,
    /// `least_conn` 常驻计数器；直连地址不参与服务级 LB，故为空。
    counter: Option<Arc<AtomicU64>>,
    /// true 表示 Drop 必须归还计数；为后续显式移交所有权预留不重复释放的不变式。
    release_on_drop: bool,
}

impl Drop for StreamUpstreamReservation {
    /// TCP 隧道结束、连接失败或 task 被取消时统一归还 `least_conn` 名额。
    fn drop(&mut self) {
        if self.release_on_drop {
            if let Some(counter) = &self.counter {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// 记录 stream 上游成功。
///
/// # 参数
/// - `state`: stream 数据面共享状态。
/// - `reservation`: 本次选中的上游 reservation。
fn record_stream_upstream_success(
    state: &StreamPlaneState,
    reservation: &StreamUpstreamReservation,
) {
    if let Some(health_key) = reservation.selected_health_key.as_deref() {
        state.lb.record_success(health_key);
    }
}

/// 记录 stream 上游失败。
///
/// # 参数
/// - `state`: stream 数据面共享状态。
/// - `reservation`: 本次选中的上游 reservation。
fn record_stream_upstream_failure(
    state: &StreamPlaneState,
    reservation: &StreamUpstreamReservation,
) {
    if let Some(health_key) = reservation.selected_health_key.as_deref() {
        state
            .lb
            .record_failure(health_key, reservation.passive_policy);
    }
}

/// 解析 stream route 的上游目标。
///
/// # 参数
/// - `snap`: 当前配置快照。
/// - `target`: route 上的 `upstream`,支持直连地址或 `lb://service`。
/// - `stream_lb`: stream 负载均衡常驻状态。
/// - `active_health`: 主动健康探测器。
fn resolve_stream_upstream(
    snap: &GatewaySnapshot,
    route: &StreamRouteRuntime,
    stream_lb: &StreamLbState,
    active_health: &gateway::health::ActiveHealthChecker,
) -> Result<StreamUpstreamReservation> {
    let target = route.upstream.as_str();
    if let Some(service) = target.strip_prefix("lb://") {
        if service.is_empty() || !snap.upstreams.has_service(service) {
            anyhow::bail!("unknown stream upstream service `{service}`");
        }
        let passive_policy = snap
            .upstreams
            .passive_health_policy(service)
            .unwrap_or_else(PassiveHealthPolicy::disabled);
        let passive_excluded = stream_lb.ejected_upstreams(passive_policy);
        let active_unhealthy = active_health.unhealthy_set();
        let mut inflight = stream_lb.inflight.lock();
        let inst = snap
            .upstreams
            .select_instance_where(
                service,
                |health_key| {
                    passive_excluded
                        .iter()
                        .any(|excluded| excluded == health_key)
                        || active_unhealthy.contains(health_key)
                },
                |health_key| {
                    inflight
                        .get(health_key)
                        .map(|counter| counter.load(Ordering::Relaxed))
                        .unwrap_or(0)
                },
                || stream_lb.next_rr(service),
            )
            .with_context(|| format!("no healthy stream upstream for service `{service}`"))?;
        let log_target = inst.uri.clone();
        let (addr, tls, server_name) = stream_addr_from_upstream_uri(&inst.uri)?;
        let tls_profile = if tls {
            Some(match &inst.tls_profile {
                Some(profile) => profile.clone(),
                None => default_stream_upstream_tls_profile()?,
            })
        } else {
            None
        };
        let health_key = inst.health_key.clone();
        // 稳态命中只 clone 计数器 Arc；实例首次出现才复制 health_key 作为 map 所有权。
        let counter = match inflight.get(health_key.as_ref()) {
            Some(counter) => counter.clone(),
            None => {
                let counter = Arc::new(AtomicU64::new(0));
                inflight.insert(health_key.clone(), counter.clone());
                counter
            }
        };
        drop(inflight);
        counter.fetch_add(1, Ordering::Relaxed);
        return Ok(StreamUpstreamReservation {
            addr,
            log_target,
            selected_health_key: Some(health_key),
            passive_policy,
            tls_profile,
            tls_server_name: tls.then(|| Arc::from(server_name.as_str())),
            counter: Some(counter),
            release_on_drop: true,
        });
    }

    let authority = target
        .trim()
        .parse::<http::uri::Authority>()
        .with_context(|| format!("invalid stream upstream `{target}`"))?;
    anyhow::ensure!(
        authority.port_u16().is_some(),
        "stream upstream `{target}` requires an explicit port"
    );
    let addr = authority.as_str().to_owned();
    let tls_profile = route.upstream_tls.clone();
    let tls_server_name = tls_profile
        .as_ref()
        .map(|_| Arc::from(authority.host().to_owned()));
    Ok(StreamUpstreamReservation {
        addr: addr.clone(),
        log_target: Arc::from(addr),
        selected_health_key: None,
        passive_policy: PassiveHealthPolicy::disabled(),
        tls_profile,
        tls_server_name,
        counter: None,
        release_on_drop: false,
    })
}

/// 把上游服务实例 URI 转换为 stream TCP dial 地址。
///
/// # 参数
/// - `uri`: `UpstreamDirectory` 选出的实例 URI。
fn stream_addr_from_upstream_uri(uri: &str) -> Result<(String, bool, String)> {
    if let Some(addr) = uri.strip_prefix("tcp://") {
        let addr = addr.trim_end_matches('/');
        let authority = addr
            .parse::<http::uri::Authority>()
            .with_context(|| format!("invalid stream upstream tcp uri `{uri}`"))?;
        anyhow::ensure!(authority.port_u16().is_some(), "stream URI requires a port");
        return Ok((
            authority.as_str().to_owned(),
            false,
            authority.host().to_owned(),
        ));
    }

    let parsed: http::Uri = uri
        .parse()
        .with_context(|| format!("invalid stream upstream uri `{uri}`"))?;
    let tls = match parsed.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        Some(other) => anyhow::bail!("unsupported stream upstream scheme `{other}`"),
        None => anyhow::bail!("stream upstream uri `{uri}` has no scheme"),
    };
    let authority = parsed
        .authority()
        .with_context(|| format!("stream upstream uri `{uri}` has no authority"))?
        .as_str();
    let authority = authority
        .parse::<http::uri::Authority>()
        .with_context(|| format!("stream upstream uri `{uri}` has invalid authority"))?;
    anyhow::ensure!(authority.port_u16().is_some(), "stream URI requires a port");
    Ok((
        authority.as_str().to_owned(),
        tls,
        authority.host().to_owned(),
    ))
}

/// 默认平台根证书 profile 只构建一次；不在每条 L4 TLS 连接重复加载系统 trust store。
fn default_stream_upstream_tls_profile() -> Result<gateway::tls::UpstreamTlsProfile> {
    static PROFILE: OnceLock<std::result::Result<gateway::tls::UpstreamTlsProfile, String>> =
        OnceLock::new();
    PROFILE
        .get_or_init(|| {
            gateway::tls::build_upstream_tls_profile(None, None, None, None)
                .map_err(|error| format!("{error:#}"))
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

/// 建立明文或 TLS stream 上游。TLS 握手属于 connect deadline，避免 TCP 已连但 TLS
/// dependency 卡住时绕过 `connect_timeout_ms`。Box 仅按连接分配一次，payload 不聚合。
async fn connect_stream_upstream(reservation: &StreamUpstreamReservation) -> Result<BoxStreamIo> {
    let tcp = TcpStream::connect(reservation.addr.as_str())
        .await
        .with_context(|| format!("connect stream upstream {}", reservation.addr))?;
    let Some(profile) = &reservation.tls_profile else {
        return Ok(Box::new(tcp));
    };
    let name = profile
        .server_name
        .clone()
        .or_else(|| reservation.tls_server_name.clone())
        .context("stream TLS upstream has no server name")?;
    let server_name = ServerName::try_from(name.to_string())
        .with_context(|| format!("invalid stream TLS server name `{name}`"))?;
    let connector = TlsConnector::from(profile.client_config.clone());
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("stream upstream TLS handshake")?;
    Ok(Box::new(tls))
}

/// 有界 preread MQTT CONNECT 并解析 client id。读取的 wire bytes 原样回放给上游，
/// parser 只借用当前 Vec，不为字段切片分配；最终仅为 route key 创建一个小 String。
async fn stream_preread_mqtt_connect(
    downstream: &mut (impl AsyncRead + Unpin),
    timeout_ms: u64,
    max_bytes: usize,
) -> Result<StreamPrereadResult> {
    let read = async {
        let mut bytes = Vec::with_capacity(max_bytes.min(4096));
        let mut buffer = [0_u8; 1024];
        loop {
            match parse_mqtt_connect_client_id(&bytes)? {
                MqttConnectParse::Complete(client_id) => {
                    return Ok(StreamPrereadResult {
                        sni: None,
                        mqtt_client_id: Some(client_id.to_owned()),
                        bytes,
                    })
                }
                MqttConnectParse::NeedMore => {}
            }
            if bytes.len() >= max_bytes {
                anyhow::bail!("MQTT CONNECT exceeds preread.max_bytes");
            }
            let capacity = buffer.len().min(max_bytes - bytes.len());
            let length = downstream
                .read(&mut buffer[..capacity])
                .await
                .context("read MQTT CONNECT preread")?;
            if length == 0 {
                anyhow::bail!("downstream closed before complete MQTT CONNECT");
            }
            bytes.extend_from_slice(&buffer[..length]);
        }
    };
    if timeout_ms == 0 {
        read.await
    } else {
        tokio::time::timeout(Duration::from_millis(timeout_ms), read)
            .await
            .context("MQTT CONNECT preread timeout")?
    }
}

enum MqttConnectParse<'a> {
    NeedMore,
    Complete(&'a str),
}

/// 解析 MQTT 3.1/3.1.1/5 CONNECT variable header 与 client id。只接受首包 CONNECT，
/// 拒绝畸形 remaining-length/properties/UTF-8，避免恶意长度让 preread 路由走 default。
fn parse_mqtt_connect_client_id(bytes: &[u8]) -> Result<MqttConnectParse<'_>> {
    if bytes.is_empty() {
        return Ok(MqttConnectParse::NeedMore);
    }
    anyhow::ensure!(bytes[0] == 0x10, "first MQTT packet must be CONNECT");
    let Some((remaining, fixed_len)) = decode_mqtt_variable_byte_integer(bytes, 1)? else {
        return Ok(MqttConnectParse::NeedMore);
    };
    let packet_end = fixed_len
        .checked_add(remaining)
        .context("MQTT CONNECT length overflow")?;
    if bytes.len() < packet_end {
        return Ok(MqttConnectParse::NeedMore);
    }
    let mut cursor = fixed_len;
    let protocol = mqtt_utf8(bytes, &mut cursor, packet_end)?;
    let expected_level = match protocol {
        "MQIsdp" => 3,
        "MQTT" => {
            if cursor >= packet_end {
                anyhow::bail!("MQTT CONNECT missing protocol level");
            }
            bytes[cursor]
        }
        _ => anyhow::bail!("unsupported MQTT protocol name"),
    };
    if cursor >= packet_end {
        anyhow::bail!("MQTT CONNECT missing protocol level");
    }
    let level = bytes[cursor];
    cursor += 1;
    anyhow::ensure!(
        level == expected_level && matches!(level, 3..=5),
        "unsupported MQTT protocol level"
    );
    anyhow::ensure!(cursor < packet_end, "MQTT CONNECT missing flags");
    let flags = bytes[cursor];
    cursor += 1;
    anyhow::ensure!(flags & 0x01 == 0, "MQTT CONNECT reserved flag is set");
    anyhow::ensure!(
        !(flags & 0x40 != 0 && flags & 0x80 == 0),
        "MQTT password flag requires username flag"
    );
    anyhow::ensure!(
        !(flags & 0x04 == 0 && flags & 0x38 != 0),
        "MQTT will flags are inconsistent"
    );
    cursor = cursor.checked_add(2).context("MQTT keepalive overflow")?;
    anyhow::ensure!(cursor <= packet_end, "MQTT CONNECT missing keepalive");
    if level == 5 {
        let Some((properties_len, next)) = decode_mqtt_variable_byte_integer(bytes, cursor)? else {
            return Ok(MqttConnectParse::NeedMore);
        };
        cursor = next
            .checked_add(properties_len)
            .context("MQTT properties length overflow")?;
        anyhow::ensure!(
            cursor <= packet_end,
            "MQTT CONNECT properties exceed packet"
        );
    }
    let client_id = mqtt_utf8(bytes, &mut cursor, packet_end)?;
    anyhow::ensure!(
        client_id.len() <= 256 && !client_id.is_empty() && !client_id.chars().any(|ch| ch == '\0'),
        "MQTT client id must be 1..=256 UTF-8 bytes without NUL"
    );
    Ok(MqttConnectParse::Complete(client_id))
}

/// MQTT variable byte integer；返回 `(value,next_cursor)`，输入尚未完整时返回 None。
fn decode_mqtt_variable_byte_integer(bytes: &[u8], start: usize) -> Result<Option<(usize, usize)>> {
    let mut value = 0usize;
    let mut multiplier = 1usize;
    for offset in 0..4 {
        let index = start + offset;
        let Some(byte) = bytes.get(index).copied() else {
            return Ok(None);
        };
        value = value
            .checked_add(((byte & 0x7f) as usize).saturating_mul(multiplier))
            .context("MQTT variable integer overflow")?;
        if byte & 0x80 == 0 {
            return Ok(Some((value, index + 1)));
        }
        multiplier = multiplier.saturating_mul(128);
    }
    anyhow::bail!("MQTT variable integer exceeds four bytes")
}

fn mqtt_utf8<'a>(bytes: &'a [u8], cursor: &mut usize, end: usize) -> Result<&'a str> {
    let length_end = cursor
        .checked_add(2)
        .context("MQTT UTF-8 length overflow")?;
    anyhow::ensure!(length_end <= end, "MQTT UTF-8 field missing length");
    let length = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
    let value_end = length_end
        .checked_add(length)
        .context("MQTT UTF-8 field overflow")?;
    anyhow::ensure!(value_end <= end, "MQTT UTF-8 field exceeds CONNECT packet");
    *cursor = value_end;
    std::str::from_utf8(&bytes[length_end..value_end]).context("MQTT field is not UTF-8")
}

/// preread TLS ClientHello 并解析 SNI。
///
/// # 参数
/// - `downstream`: 下游 TCP socket。
/// - `timeout_ms`: preread 超时(ms),0 表示不限制。
/// - `max_bytes`: 最多读取字节数。
async fn stream_preread_sni(
    downstream: &mut (impl AsyncRead + Unpin),
    timeout_ms: u64,
    max_bytes: usize,
) -> Result<StreamPrereadResult> {
    let fut = async {
        let mut bytes = Vec::with_capacity(max_bytes.min(4096));
        let mut buf = vec![0_u8; 1024.min(max_bytes.max(1))];
        loop {
            if bytes.len() >= max_bytes {
                return Ok(StreamPrereadResult {
                    sni: None,
                    mqtt_client_id: None,
                    bytes,
                });
            }
            let read_cap = buf.len().min(max_bytes - bytes.len());
            let n = downstream
                .read(&mut buf[..read_cap])
                .await
                .context("read stream preread bytes")?;
            if n == 0 {
                return Ok(StreamPrereadResult {
                    sni: None,
                    mqtt_client_id: None,
                    bytes,
                });
            }
            bytes.extend_from_slice(&buf[..n]);
            match parse_tls_client_hello_sni(bytes.as_slice()) {
                TlsSniParse::Complete(sni) => {
                    return Ok(StreamPrereadResult {
                        sni,
                        mqtt_client_id: None,
                        bytes,
                    })
                }
                TlsSniParse::NeedMore => continue,
                TlsSniParse::NotTls => {
                    return Ok(StreamPrereadResult {
                        sni: None,
                        mqtt_client_id: None,
                        bytes,
                    })
                }
            }
        }
    };
    if timeout_ms == 0 {
        fut.await
    } else {
        tokio::time::timeout(Duration::from_millis(timeout_ms), fut)
            .await
            .context("stream ssl preread timeout")?
    }
}

/// TLS SNI 解析状态。
enum TlsSniParse {
    /// 已解析完成;没有 SNI 时为 None。
    Complete(Option<String>),
    /// 需要更多字节。
    NeedMore,
    /// 当前流不是 TLS ClientHello。
    NotTls,
}

/// 从 TLS ClientHello 解析 SNI。
///
/// # 参数
/// - `bytes`: 从 TCP 流 preread 到的字节。
fn parse_tls_client_hello_sni(bytes: &[u8]) -> TlsSniParse {
    if bytes.len() < 5 {
        return TlsSniParse::NeedMore;
    }
    if bytes[0] != 22 {
        return TlsSniParse::NotTls;
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len {
        return TlsSniParse::NeedMore;
    }
    let record = &bytes[5..5 + record_len];
    if record.len() < 4 || record[0] != 1 {
        return TlsSniParse::NotTls;
    }
    let hello_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    if record.len() < 4 + hello_len {
        return TlsSniParse::NeedMore;
    }
    parse_client_hello_body_sni(&record[4..4 + hello_len])
        .map_or(TlsSniParse::Complete(None), |sni| {
            TlsSniParse::Complete(Some(sni))
        })
}

/// 从 ClientHello body 解析 server_name 扩展。
///
/// # 参数
/// - `body`: TLS handshake ClientHello body。
fn parse_client_hello_body_sni(body: &[u8]) -> Option<String> {
    let mut pos = 0;
    read_exact_advance(body, &mut pos, 2)?; // legacy_version
    read_exact_advance(body, &mut pos, 32)?; // random
    let session_len = *read_exact_advance(body, &mut pos, 1)?.first()? as usize;
    read_exact_advance(body, &mut pos, session_len)?;
    let cipher_len = read_u16_advance(body, &mut pos)? as usize;
    read_exact_advance(body, &mut pos, cipher_len)?;
    let compression_len = *read_exact_advance(body, &mut pos, 1)?.first()? as usize;
    read_exact_advance(body, &mut pos, compression_len)?;
    let extensions_len = read_u16_advance(body, &mut pos)? as usize;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }
    while pos + 4 <= extensions_end {
        let ext_type = read_u16_advance(body, &mut pos)?;
        let ext_len = read_u16_advance(body, &mut pos)? as usize;
        let ext = read_exact_advance(body, &mut pos, ext_len)?;
        if ext_type == 0 {
            return parse_sni_extension(ext);
        }
    }
    None
}

/// 解析 server_name 扩展。
///
/// # 参数
/// - `ext`: server_name 扩展 body。
fn parse_sni_extension(ext: &[u8]) -> Option<String> {
    let mut pos = 0;
    let list_len = read_u16_advance(ext, &mut pos)? as usize;
    let list_end = pos.checked_add(list_len)?;
    if list_end > ext.len() {
        return None;
    }
    while pos + 3 <= list_end {
        let name_type = *read_exact_advance(ext, &mut pos, 1)?.first()?;
        let name_len = read_u16_advance(ext, &mut pos)? as usize;
        let name = read_exact_advance(ext, &mut pos, name_len)?;
        if name_type == 0 {
            let sni = std::str::from_utf8(name).ok()?;
            return Some(sni.trim_end_matches('.').to_ascii_lowercase());
        }
    }
    None
}

/// 从切片读取固定长度并推进游标。
///
/// # 参数
/// - `bytes`: 源切片。
/// - `pos`: 当前游标。
/// - `len`: 读取长度。
fn read_exact_advance<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    let out = &bytes[*pos..end];
    *pos = end;
    Some(out)
}

/// 从切片读取 u16 并推进游标。
///
/// # 参数
/// - `bytes`: 源切片。
/// - `pos`: 当前游标。
fn read_u16_advance(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let value = read_exact_advance(bytes, pos, 2)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

/// 释放 L4 stream 连接计数。
///
/// # 参数
/// - `active_connections`: 进程级连接数计数。
/// - `metrics`: 共享 metrics。
fn finish_stream_connection(active_connections: Arc<AtomicU64>, metrics: Arc<Metrics>) {
    active_connections.fetch_sub(1, Ordering::Relaxed);
    metrics.dec_active_connection();
    metrics.dec_stream_connection();
}

struct StreamAccessLogCtx {
    request_id: String,
    stream_id: Arc<str>,
    upstream: Arc<str>,
    peer: String,
    started: std::time::Instant,
}

static STREAM_REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);

/// 生成 stream access log 的连接 id。
fn next_stream_request_id() -> String {
    let seq = STREAM_REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("stream-{seq:016x}")
}

/// 写入一条 L4 stream 连接级 access log。
///
/// # 参数
/// - `access_log`: 非阻塞 access log。
/// - `ctx`: stream 连接上下文。
/// - `status`: 网关侧归一化状态码。
/// - `downstream_to_upstream`: 下游到上游字节数。
/// - `upstream_to_downstream`: 上游到下游字节数。
fn log_stream_access(
    access_log: &AccessLogger,
    ctx: &StreamAccessLogCtx,
    status: u16,
    downstream_to_upstream: u64,
    upstream_to_downstream: u64,
) {
    access_log.log(AccessRecord {
        request_id: ctx.request_id.clone(),
        trace_id: None,
        method: AccessMethod::Stream,
        path: AccessPath::Stream(ctx.stream_id.clone()),
        route_id: None,
        upstream: Some(ctx.upstream.clone()),
        upstream_attempts: 1,
        status,
        elapsed: ctx.started.elapsed(),
        peer: ctx.peer.clone(),
        bytes_downstream_to_upstream: Some(downstream_to_upstream),
        bytes_upstream_to_downstream: Some(upstream_to_downstream),
    });
}

struct BoundProxy {
    id: String,
    listen: SocketAddr,
    listener: TcpListener,
    tls: Option<BoundTlsProxy>,
}

struct BoundTlsProxy {
    listen: SocketAddr,
    listener: TcpListener,
    mode: BoundTlsMode,
}

/// TLS listener 启动形态：已有 keypair 立即 accept，或 ACME 首签后在同进程激活。
enum BoundTlsMode {
    /// 启动期已构建可用 rustls 配置。
    Ready(SharedServerConfig),
    /// socket 已绑定，但 cert/key 尚不存在；后台检测到完整 keypair 后才开始 accept。
    Deferred(Box<gateway::config::TlsRuntimeCfg>),
}

struct BoundStream {
    runtime: StreamRuntime,
    listen: SocketAddr,
    socket: BoundStreamSocket,
    /// TCP TLS termination config. ArcSwap watcher hot-swaps certs without rebinding the socket.
    tls: Option<SharedServerConfig>,
}

enum BoundStreamSocket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

struct ActiveListenerGeneration {
    topology: ProxyListenTopology,
    stop: watch::Sender<bool>,
}

/// V7 数据面 listener supervisor。所有可能失败的 bind/TLS build 都在 reload 的 prepare
/// 阶段完成；active map 仅在 commit 的短临界区替换 stop handle，不持锁执行 I/O。
#[derive(Clone)]
struct ListenerSupervisor {
    active: Arc<Mutex<HashMap<String, ActiveListenerGeneration>>>,
    data_plane: DataPlaneState,
    stream_plane: StreamPlaneState,
    pending_tls: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
}

struct PreparedListenerSwitch {
    supervisor: ListenerSupervisor,
    candidate_topologies: HashMap<String, ProxyListenTopology>,
    proxies: Vec<BoundProxy>,
    streams: Vec<BoundStream>,
    removed: Vec<String>,
}

impl ListenerSupervisor {
    fn new(
        data_plane: DataPlaneState,
        stream_plane: StreamPlaneState,
        pending_tls: Arc<AtomicU64>,
        ready: Arc<AtomicBool>,
    ) -> Self {
        Self {
            active: Arc::new(Mutex::new(HashMap::new())),
            data_plane,
            stream_plane,
            pending_tls,
            ready,
        }
    }

    /// 激活启动期已经绑定完成的 listener，并把每组 accept loop 收口到独立 stop channel。
    fn install_initial(
        &self,
        snapshot: &GatewaySnapshot,
        proxies: Vec<BoundProxy>,
        streams: Vec<BoundStream>,
    ) -> (Vec<String>, Vec<String>) {
        let topologies = snapshot
            .listen_topology()
            .into_iter()
            .map(|topology| (topology.id.clone(), topology))
            .collect::<HashMap<_, _>>();
        let mut proxy_log = Vec::new();
        let mut stream_log = Vec::new();
        for bound in proxies {
            let key = format!("proxy:{}", bound.id);
            let topology = topologies
                .get(&key)
                .expect("initial proxy topology matches bound listener")
                .clone();
            proxy_log.extend(self.activate_proxy(bound, topology));
        }
        for bound in streams {
            let key = stream_topology_key(&bound.runtime);
            let topology = topologies
                .get(&key)
                .expect("initial stream topology matches bound listener")
                .clone();
            stream_log.push(self.activate_stream(bound, topology));
        }
        (proxy_log, stream_log)
    }

    fn activate_proxy(&self, bound: BoundProxy, topology: ProxyListenTopology) -> Vec<String> {
        let key = topology.id.clone();
        let (stop, stop_rx) = watch::channel(false);
        let proxy_id: Arc<str> = Arc::from(bound.id.clone());
        let mut log = vec![format!("{}@{}", bound.id, bound.listen)];
        spawn_plain_accept_loop(
            bound.listener,
            proxy_id.clone(),
            self.data_plane.clone(),
            stop_rx.clone(),
        );
        if let Some(tls) = bound.tls {
            match tls.mode {
                BoundTlsMode::Ready(config) => {
                    log.push(format!("{}@{}(tls)", bound.id, tls.listen));
                    spawn_tls_accept_loop(
                        tls.listener,
                        proxy_id,
                        config,
                        self.data_plane.clone(),
                        stop_rx,
                    );
                }
                BoundTlsMode::Deferred(tls_cfg) => {
                    log.push(format!("{}@{}(tls-pending)", bound.id, tls.listen));
                    spawn_deferred_tls_accept_loop(
                        tls.listener,
                        proxy_id,
                        *tls_cfg,
                        self.data_plane.clone(),
                        stop_rx,
                        self.pending_tls.clone(),
                        self.ready.clone(),
                    );
                }
            }
        }
        let old = self
            .active
            .lock()
            .expect("listener supervisor active map poisoned")
            .insert(key, ActiveListenerGeneration { topology, stop });
        if let Some(old) = old {
            let _ = old.stop.send(true);
        }
        log
    }

    fn activate_stream(&self, bound: BoundStream, topology: ProxyListenTopology) -> String {
        let key = topology.id.clone();
        let log = format!(
            "{}@{}{}",
            bound.runtime.id,
            bound.listen,
            if bound.tls.is_some() { "(tls)" } else { "" }
        );
        let (stop, stop_rx) = watch::channel(false);
        match bound.socket {
            BoundStreamSocket::Tcp(listener) => spawn_stream_accept_loop(
                listener,
                bound.runtime,
                bound.tls,
                self.stream_plane.clone(),
                stop_rx,
            ),
            BoundStreamSocket::Udp(socket) => {
                spawn_stream_udp_loop(socket, bound.runtime, self.stream_plane.clone(), stop_rx)
            }
        }
        let old = self
            .active
            .lock()
            .expect("listener supervisor active map poisoned")
            .insert(key, ActiveListenerGeneration { topology, stop });
        if let Some(old) = old {
            let _ = old.stop.send(true);
        }
        log
    }

    fn stop_removed(&self, keys: &[String]) {
        let removed = {
            let mut active = self
                .active
                .lock()
                .expect("listener supervisor active map poisoned");
            keys.iter()
                .filter_map(|key| active.remove(key))
                .collect::<Vec<_>>()
        };
        for listener in removed {
            let _ = listener.stop.send(true);
        }
    }

    fn shutdown(&self) {
        let listeners = self
            .active
            .lock()
            .expect("listener supervisor active map poisoned")
            .drain()
            .map(|(_, listener)| listener)
            .collect::<Vec<_>>();
        for listener in listeners {
            let _ = listener.stop.send(true);
        }
    }
}

impl gateway::reload::ListenerTopologyReconciler for ListenerSupervisor {
    fn prepare<'a>(
        &'a self,
        candidate: &'a GatewaySnapshot,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn gateway::reload::PreparedListenerTopology>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let candidate_topologies = candidate
                .listen_topology()
                .into_iter()
                .map(|topology| (topology.id.clone(), topology))
                .collect::<HashMap<_, _>>();
            let current_topologies = self
                .active
                .lock()
                .expect("listener supervisor active map poisoned")
                .iter()
                .map(|(id, listener)| (id.clone(), listener.topology.clone()))
                .collect::<HashMap<_, _>>();
            let changed = candidate_topologies
                .iter()
                .filter_map(|(id, topology)| {
                    (current_topologies.get(id) != Some(topology)).then_some(id.clone())
                })
                .collect::<std::collections::HashSet<_>>();
            let removed = current_topologies
                .keys()
                .filter(|id| !candidate_topologies.contains_key(*id))
                .cloned()
                .collect::<Vec<_>>();

            // ACME worker 的 challenge/renewal 生命周期目前仍按证书 identity 常驻；没有 stop
            // handle，故不能假装 listener 已热切而旧签发 worker 也完成交接。普通 TLS/明文/L4
            // 均支持热切，ACME 拓扑变更 fail-fast 保留旧版。
            for id in changed.iter().chain(removed.iter()) {
                if current_topologies.get(id).is_some_and(topology_uses_acme)
                    || candidate_topologies.get(id).is_some_and(topology_uses_acme)
                {
                    anyhow::bail!(
                        "listener `{id}` uses ACME; changing/removing its topology requires restart"
                    );
                }
            }

            let mut proxies = Vec::new();
            for proxy in candidate.proxies.iter() {
                let key = format!("proxy:{}", proxy.id);
                if changed.contains(&key) {
                    proxies.push(bind_proxy(proxy).await?);
                }
            }
            let mut streams = Vec::new();
            for stream in candidate.stream_listeners.iter() {
                let key = stream_topology_key(stream);
                if changed.contains(&key) {
                    streams.push(bind_stream(stream).await?);
                }
            }
            Ok(Box::new(PreparedListenerSwitch {
                supervisor: self.clone(),
                candidate_topologies,
                proxies,
                streams,
                removed,
            })
                as Box<dyn gateway::reload::PreparedListenerTopology>)
        })
    }
}

impl gateway::reload::PreparedListenerTopology for PreparedListenerSwitch {
    fn commit(mut self: Box<Self>) {
        for bound in self.proxies.drain(..) {
            let key = format!("proxy:{}", bound.id);
            let topology = self
                .candidate_topologies
                .remove(&key)
                .expect("prepared proxy topology remains available");
            self.supervisor.activate_proxy(bound, topology);
        }
        for bound in self.streams.drain(..) {
            let key = stream_topology_key(&bound.runtime);
            let topology = self
                .candidate_topologies
                .remove(&key)
                .expect("prepared stream topology remains available");
            self.supervisor.activate_stream(bound, topology);
        }
        self.supervisor.stop_removed(self.removed.as_slice());
    }
}

fn stream_topology_key(stream: &StreamRuntime) -> String {
    format!(
        "stream:{}:{}",
        stream.id,
        match stream.protocol {
            StreamProtocolRuntime::Tcp => "tcp",
            StreamProtocolRuntime::Udp => "udp",
        }
    )
}

fn topology_uses_acme(topology: &ProxyListenTopology) -> bool {
    topology.tls.as_ref().is_some_and(|tls| tls.acme.is_some())
}

/// L4 payload transport abstraction. Boxing costs one allocation per accepted connection, not per
/// frame; `copy_bidirectional` still moves fixed-size chunks with bounded memory and never buffers
/// an application message. It keeps the TCP/TLS combinations out of four duplicated proxy loops.
trait StreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> StreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxStreamIo = Box<dyn StreamIo>;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    let run_mode = args.command.unwrap_or(RunMode::AllInOne);

    // 信号子命令(不启动服务)。
    if let Some(sig) = args.signal.as_deref() {
        return send_signal(sig);
    }

    let cfg_path = config_path(&args);

    // 启动自举(对标 Higress 首次启动生成默认配置):检测固定配置目录下的 yml 是否齐全,
    // 缺失则新建最低运行默认(能监听、无路由/不拦任何接口),不覆盖已存在文件。
    gateway::config::bootstrap::ensure(&cfg_path)
        .with_context(|| format!("bootstrap config dir for {}", cfg_path.display()))?;

    // 初始快照(v1)。启动期配置错误直接失败退出(不带病上线)。
    let version = Arc::new(AtomicU64::new(1));
    // 指标对象必须早于服务发现创建，使首轮 registry poll（可能发生在 listener 绑定前）
    // 也不会丢失成功/错误/超时事实；后续数据面、管理面共享同一组原子计数器。
    let metrics = Arc::new(Metrics::default());
    let dynamic_upstreams = DynamicUpstreamStore::new();
    let discovery = NacosDiscoveryManager::with_metrics(dynamic_upstreams.clone(), metrics.clone());
    let snapshot = load_snapshot_with_dynamic(&cfg_path, 1, dynamic_upstreams.clone())
        .with_context(|| format!("load initial config from {}", cfg_path.display()))?;
    // 审计 hash-chain/client 是 bootstrap 资源；启动时完整验旧 spool，篡改或 endpoint 配置错误均 fail-fast。
    let admin_audit = gateway::admin_audit::AdminAuditLog::open(&snapshot.admin_audit)
        .context("open admin audit log")?;
    // 日志仍由 nasa::log 统一格式化/滚动/热调级；OTel layer 同挂一个 tracing subscriber，
    // 避免两个全局 subscriber 争用。必须先读 bootstrap telemetry 配置再一次性初始化。
    let telemetry = gateway::telemetry::TelemetryRuntime::build(&snapshot.telemetry)
        .context("build OpenTelemetry runtime")?;
    nasa::log::init_with_default_and_layer(
        "gateway=info,info",
        tracing_opentelemetry::layer().with_tracer(telemetry.tracer()),
    );
    // reload channel 容量和去抖窗口属 bootstrap 执行参数；worker 建立后不在热更时自重建。
    let reload_cfg = snapshot.reload.clone();
    discovery.reconcile(&snapshot);
    // 管理面监听(§14.1:与数据面端口隔离);同为 bootstrap 层,启动期绑定一次、热更不重绑。
    let admin_listen: SocketAddr = snapshot
        .admin_listen
        .parse()
        .with_context(|| format!("invalid admin.listen `{}`", snapshot.admin_listen))?;
    // Admin-only 进程不得绑定或启动任何 public 数据面资源；配置仍完整 build，供 dry-run/
    // explain 使用同一份强类型语义，避免控制面校验与数据面执行产生分叉。
    let initial_proxies = if run_mode.runs_data() {
        snapshot.proxies.as_ref().clone()
    } else {
        Vec::new()
    };
    let initial_streams = if run_mode.runs_data() {
        snapshot.stream_listeners.as_ref().clone()
    } else {
        Vec::new()
    };
    // V3 运行态后端启动期装配:默认 local 零外部依赖;redis 通过 nasa::redis fail-fast 建连。
    let runtime_state_cfg = snapshot.runtime_state.clone();
    let rate_limiter = gateway::runtime_state::build_rate_limiter(&runtime_state_cfg)
        .await
        .context("build runtime rate limiter")?;
    let rate_limiter = Arc::new(gateway::runtime_state::SwappableRateLimiter::new(
        rate_limiter,
    ));
    let proxy_rate_limiter: Arc<dyn gateway::runtime_state::RateLimiter> = rate_limiter.clone();
    let conn_limiter = gateway::runtime_state::build_conn_limiter(&runtime_state_cfg)
        .await
        .context("build runtime conn limiter")?;
    let conn_limiter = Arc::new(gateway::runtime_state::SwappableConnLimiter::new(
        conn_limiter,
    ));
    let proxy_conn_limiter: Arc<dyn gateway::runtime_state::ConnLimiter> = conn_limiter.clone();
    // §10.6 R3 熔断统计后端:默认 local 各自统计;circuit_breaker.shared=true 时跨节点共享。
    let circuit_stats = gateway::runtime_state::build_circuit_stats(&runtime_state_cfg)
        .await
        .context("build runtime circuit stats")?;
    let circuit_stats = Arc::new(gateway::runtime_state::SwappableCircuitStats::new(
        circuit_stats,
    ));
    let proxy_circuit_stats: Arc<dyn gateway::runtime_state::CircuitStats> = circuit_stats.clone();
    // §20 HMAC 防重放守卫:默认 local 内存去重;replay_guard.backend=redis 时跨节点 SET NX PX。
    let replay_guard = gateway::runtime_state::build_replay_guard(&runtime_state_cfg)
        .await
        .context("build runtime replay guard")?;
    let replay_guard = Arc::new(gateway::runtime_state::SwappableReplayGuard::new(
        replay_guard,
    ));
    let proxy_replay_guard: Arc<dyn gateway::runtime_state::ReplayGuard> = replay_guard.clone();
    let dynamic_store = gateway::runtime_state::build_dynamic_store(&runtime_state_cfg, &cfg_path)
        .await
        .context("build runtime dynamic store")?;
    let dynamic_store = Arc::new(gateway::runtime_state::SwappableDynamicStore::new(
        dynamic_store,
    ));
    let proxy_dynamic_store: Arc<dyn gateway::runtime_state::DynamicStore> = dynamic_store.clone();
    let blacklist = Arc::new(
        gateway::blacklist::BlacklistCache::new(&runtime_state_cfg.blacklist)
            .context("build runtime blacklist cache")?,
    );
    if blacklist.is_enabled() {
        let collection = blacklist.collection();
        blacklist
            .refresh_from_store(proxy_dynamic_store.as_ref(), &collection)
            .await
            .context("load initial runtime blacklist")?;
    }
    gateway::blacklist::spawn_blacklist_refresh(blacklist.clone(), dynamic_store.clone());
    let interface_disable = Arc::new(
        gateway::guard::DynamicInterfaceGuardCache::new(&runtime_state_cfg.interface_disable)
            .context("build runtime interface disable cache")?,
    );
    if interface_disable.is_enabled() {
        let collection = interface_disable.collection();
        interface_disable
            .refresh_from_store(proxy_dynamic_store.as_ref(), &collection)
            .await
            .context("load initial runtime interface disable")?;
    }
    gateway::guard::spawn_interface_disable_refresh(
        interface_disable.clone(),
        dynamic_store.clone(),
    );
    // V5 cache L2 是显式 bootstrap 依赖：local 默认零网络；redis 模式启动期 fail-fast 建连，
    // 运行中 GET/SET 错误仍 fail-open 成普通 miss，不阻断业务数据面。
    let http_cache = gateway::http_cache::HttpCacheRuntime::build(&runtime_state_cfg.http_cache)
        .await
        .context("build HTTP cache runtime")?;
    let snap = Arc::new(ArcSwap::from_pointee(snapshot));
    http_cache.spawn_invalidation_worker(snap.clone());
    let history_root = cfg_path
        .parent()
        .map(|parent| parent.join(".gateway-config-history"))
        .unwrap_or_else(|| PathBuf::from(".gateway-config-history"));
    let config_history = gateway::config_history::ConfigHistory::new(history_root, 128);
    {
        let initial = snap.load();
        config_history.record_initial(&cfg_path, &initial);
    }
    // 常驻长连接表必须早于 reload worker 创建，使成功换版可以按全局策略安排 stale drain。
    let conn_registry = gateway::conn_registry::ConnectionRegistry::new();

    // 就绪标志:数据面监听绑定后置 true;停机时置 false → /readyz 转 503,供前置 LB 摘流(§24)。
    let ready = Arc::new(AtomicBool::new(false));
    let active_connections = Arc::new(AtomicU64::new(0));
    let access_log = AccessLogger::spawn(
        metrics.clone(),
        snap.clone(),
        snap.load().access_log.queue_size,
    )
    .context("start access log sinks")?;
    let access_log_shutdown = access_log.clone();
    let stream_access_log = access_log.clone();
    // 管理/观测面(独立内网监听:/healthz /readyz;端口与数据面隔离,§14.1)。
    // 监听在启动期绑定,失败即 fatal(据 Codex 审查记录 P2#1:健康端点是容器部署关键依赖);
    // 之后的 accept 循环若 runtime 出错,不影响数据面转发。
    let admin_listener = TcpListener::bind(admin_listen)
        .await
        .with_context(|| format!("bind admin.listen {admin_listen}"))?;
    // 主动健康探测器(§5.1):后台按服务 health_check 探测上游,不健康实例不进 LB 候选;/readyz 也据它判 critical
    // 可用性(N2)。常驻(与快照解耦)、读当前快照的健康目标;与被动摘除叠加成双保险。
    // ★在 AdminState 之前构造★——admin readyz 与数据面选实例共用【同一个】checker,可用性判定才一致(N2)。
    let active_health = gateway::health::ActiveHealthChecker::new(metrics.clone());
    gateway::health::spawn_active_health(active_health.clone(), snap.clone());

    let admin_state = admin::AdminState::new(
        snap.clone(),
        cfg_path.clone(),
        ready.clone(),
        metrics.clone(),
        conn_registry.clone(),
        active_health.clone(),
        admin::AdminRuntimeState {
            mode: run_mode.admin_plane_mode(),
            config_history: config_history.clone(),
            dynamic_store: dynamic_store.clone(),
            blacklist: blacklist.clone(),
            interface_disable: interface_disable.clone(),
            http_cache: http_cache.clone(),
            audit: admin_audit,
        },
    );
    // V8:proxy 构造在 admin serve 之后,提前留一份句柄以便把边缘订阅索引注入
    // /metrics 渲染;未编 feature 时零残留。
    #[cfg(feature = "grpc-edge")]
    let admin_state_for_edge = admin_state.clone();
    tokio::spawn(admin::serve(admin_listener, admin_state));

    // 代理(持有原子快照 + 常驻上游连接池 + 长连接注册表 + 主动健康检查器)。
    let proxy = GatewayProxy::new(
        snap.clone(),
        metrics.clone(),
        access_log,
        conn_registry.clone(),
        ProxyRuntimeState {
            rate_limiter: proxy_rate_limiter,
            conn_limiter: proxy_conn_limiter,
            circuit_stats: proxy_circuit_stats,
            replay_guard: proxy_replay_guard,
            dynamic_store: dynamic_store.clone(),
            blacklist: blacklist.clone(),
            interface_disable: interface_disable.clone(),
            http_cache: http_cache.clone(),
            telemetry: telemetry.clone(),
        },
        active_health.clone(),
    );
    #[cfg(feature = "grpc-edge")]
    admin_state_for_edge.attach_edge_hub(proxy.grpc_edge_hub());
    // 集群传输随初始快照启动。relay 与 Redis Pub/Sub 已在配置构建期严格互斥，
    // 这里按 mode 只启动其中一条链路，避免重复散出。
    #[cfg(feature = "grpc-edge")]
    if run_mode.runs_data() {
        if let Some(cluster) = snap.load().grpc_edge_cluster.clone() {
            match cluster.mode {
                gateway::config::model::GrpcEdgeClusterModeCfg::Relay => {
                    let membership = cluster.membership;
                    #[cfg(feature = "redis-runtime")]
                    let plan_session_directory = cluster.session_directory.clone();
                    #[cfg(feature = "redis-runtime")]
                    let cluster_identity = (cluster.cluster_id.clone(), cluster.node_id.clone());
                    let relay =
                        gateway::edge_relay::EdgeRelay::start(cluster, proxy.grpc_edge_hub())
                            .await
                            .context("start grpc edge relay")?;
                    if membership == gateway::config::model::GrpcEdgeMembershipCfg::Nacos {
                        relay
                            .start_nacos_membership(snap.load().discovery.nacos.clone())
                            .context("start grpc edge Nacos membership")?;
                    }
                    proxy.attach_edge_relay(relay.clone());
                    admin_state_for_edge.attach_edge_relay(relay.clone());
                    // SessionDirectory 只属于 relay 定向寻址；Redis bus 模式不启动它。
                    #[cfg(feature = "redis-runtime")]
                    if let Some(directory_cfg) = plan_session_directory {
                        let proxy_for_directory = proxy.clone();
                        let admin_for_directory = admin_state_for_edge.clone();
                        let boot_id = relay.boot_id();
                        let (cluster_id, node_id) = cluster_identity;
                        tokio::spawn(async move {
                            let mut backoff = std::time::Duration::from_millis(500);
                            loop {
                                match gateway::edge_directory::SessionDirectory::connect(
                                    &directory_cfg,
                                    &cluster_id,
                                    &node_id,
                                    boot_id,
                                )
                                .await
                                {
                                    Ok(directory) => {
                                        proxy_for_directory
                                            .attach_edge_directory(directory.clone());
                                        admin_for_directory.attach_edge_directory(directory);
                                        tracing::info!("edge session directory attached");
                                        return;
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            error = %format!("{error:#}"),
                                            "edge session directory unavailable; push uses broadcast-probe"
                                        );
                                        tokio::time::sleep(backoff).await;
                                        backoff =
                                            (backoff * 2).min(std::time::Duration::from_secs(30));
                                    }
                                }
                            }
                        });
                    }
                }
                gateway::config::model::GrpcEdgeClusterModeCfg::RedisPubsub => {
                    #[cfg(feature = "redis-runtime")]
                    {
                        let bus = gateway::edge_redis_bus::EdgeRedisBus::start(
                            cluster,
                            proxy.grpc_edge_hub(),
                        )
                        .await
                        .context("start grpc edge Redis Pub/Sub bus")?;
                        proxy.attach_edge_redis_bus(bus.clone());
                        admin_state_for_edge.attach_edge_redis_bus(bus);
                    }
                    #[cfg(not(feature = "redis-runtime"))]
                    unreachable!("redis_pubsub plan requires redis-runtime at build time");
                }
                gateway::config::model::GrpcEdgeClusterModeCfg::RedisStream => {
                    #[cfg(feature = "redis-runtime")]
                    {
                        let bus = gateway::edge_redis_bus::EdgeRedisStreamBus::start(
                            cluster,
                            proxy.grpc_edge_hub(),
                        )
                        .await
                        .context("start grpc edge Redis Stream bus")?;
                        proxy.attach_edge_redis_stream(bus.clone());
                        admin_state_for_edge.attach_edge_redis_stream(bus);
                    }
                    #[cfg(not(feature = "redis-runtime"))]
                    unreachable!("redis_stream plan requires redis-runtime at build time");
                }
                gateway::config::model::GrpcEdgeClusterModeCfg::None => {}
            }
        }
    }
    proxy.reconcile_runtime_identities(&snap.load());
    if run_mode.runs_data() {
        // 连接预热使用与真实转发完全相同的 Hyper client cache/物理 socket 预算。worker 会
        // 自动识别 reload 与动态发现新增实例；只预热一次，不把它变成周期业务探测。
        proxy.spawn_upstream_prewarm();
    }
    let data_plane = DataPlaneState {
        snap: snap.clone(),
        proxy: proxy.clone(),
        connection_budget: Arc::new(ConnectionBudget::default()),
        active_connections: active_connections.clone(),
        metrics: metrics.clone(),
    };
    let stream_lb = StreamLbState::default();
    let stream_plane = StreamPlaneState {
        snap: snap.clone(),
        active_health: active_health.clone(),
        lb: stream_lb,
        active_connections: active_connections.clone(),
        metrics: metrics.clone(),
        access_log: stream_access_log,
    };

    let mut bound_proxies = Vec::with_capacity(initial_proxies.len());
    for proxy_cfg in &initial_proxies {
        bound_proxies.push(bind_proxy(proxy_cfg).await?);
    }
    let mut bound_streams = Vec::with_capacity(initial_streams.len());
    for stream_cfg in &initial_streams {
        bound_streams.push(bind_stream(stream_cfg).await?);
    }

    // 写 pidfile(供 `-s reload` 定位进程)。★放在两个 listener 都绑定成功之后★——
    // 否则启动期 bind 失败(如 admin/data 端口被占)会残留一个指向已退出进程的 stale pidfile。
    let pf = pidfile_path();
    std::fs::write(&pf, std::process::id().to_string())
        .with_context(|| format!("write pidfile {}", pf.display()))?;

    let pending_tls = Arc::new(AtomicU64::new(
        bound_proxies
            .iter()
            .filter(|bound| {
                bound
                    .tls
                    .as_ref()
                    .is_some_and(|tls| matches!(&tls.mode, BoundTlsMode::Deferred(_)))
            })
            .count() as u64,
    ));
    let listener_supervisor = Arc::new(ListenerSupervisor::new(
        data_plane,
        stream_plane,
        pending_tls.clone(),
        ready.clone(),
    ));
    let initial_snapshot = snap.load_full();
    let (proxy_log, stream_log) = listener_supervisor.install_initial(
        initial_snapshot.as_ref(),
        bound_proxies,
        bound_streams,
    );
    drop(initial_snapshot);

    // listener 已进入 supervisor 后再启动唯一 reload worker；从此数据面拓扑也遵守
    // bind/build → ArcSwap publish → accept generation handoff 的同一事务边界。
    let reload_handle = reload::spawn(
        cfg_path.clone(),
        snap.clone(),
        version.clone(),
        reload::ReloadRuntime {
            dynamic_upstreams: dynamic_upstreams.clone(),
            discovery: discovery.clone(),
            rate_limiter: rate_limiter.clone(),
            conn_limiter: conn_limiter.clone(),
            circuit_stats: circuit_stats.clone(),
            replay_guard: replay_guard.clone(),
            dynamic_store: dynamic_store.clone(),
            blacklist: blacklist.clone(),
            interface_disable: interface_disable.clone(),
            conn_registry: conn_registry.clone(),
            proxy: Some(proxy.clone()),
            listener_topology: if run_mode.runs_data() {
                Some(listener_supervisor.clone())
            } else {
                None
            },
        },
        config_history.clone(),
        reload_cfg,
    );
    // Kubernetes 对象只在后台编译成物化候选，并通过上面的唯一 reload worker 发布。
    gateway::kubernetes_routes::spawn_controller(snap.clone(), cfg_path.clone(), reload_handle);
    // HTTP listeners 已开始服务后再启动 ACME：CA 在 `set_ready` 后才能命中 HTTP-01 临时响应。
    // ACME 配置属于 bootstrap 拓扑，reload 不会悄悄留下旧 worker；签发成功写 cert/key 后由既有 watcher 热换。
    let acme_workers = if run_mode.runs_data() {
        gateway::acme::spawn_acme_workers(
            initial_proxies.iter().filter_map(|proxy| proxy.tls.clone()),
            runtime_state_cfg.clone(),
            proxy.acme_http01_store(),
        )
        .await
        .context("start ACME workers")?
    } else {
        0
    };
    if acme_workers > 0 {
        info!(workers = acme_workers, "ACME certificate workers started");
    }
    // 无 seed ACME 首签期间 TLS socket 虽已绑定但尚不 accept；readiness 必须保持 503，避免 LB
    // 把业务流量送到只有 challenge 能力的半就绪节点。最后一个 deferred listener 激活时会置 true。
    if pending_tls.load(Ordering::Acquire) == 0 {
        ready.store(true, Ordering::Release);
    }
    // V4 网关节点自注册:后台只感知快照变化并写注册中心,请求热路径不访问 Nacos。
    let self_registration = run_mode.runs_data().then(|| {
        GatewaySelfRegistration::spawn(snap.clone(), ready.clone(), active_health.clone())
    });
    info!(
        proxies = %proxy_log.join(","),
        streams = %stream_log.join(","),
        %admin_listen,
        config = %cfg_path.display(),
        mode = ?run_mode,
        "gateway started"
    );

    // 优雅退出:Ctrl-C 停 accept、清 pidfile。
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
            // 停机:先置 /readyz=503(前置 LB 摘流)。
            _ = sigint.recv() => { info!("SIGINT received, shutting down"); ready.store(false, Ordering::Relaxed); }
            _ = sigterm.recv() => { info!("SIGTERM received, shutting down"); ready.store(false, Ordering::Relaxed); }
    }
    let deregister_timeout_ms = snap
        .load()
        .discovery
        .nacos
        .self_register
        .deregister_timeout_ms;
    if let Some(self_registration) = self_registration {
        self_registration.deregister(deregister_timeout_ms).await;
    }
    // ★L7:supervisor 停止所有当前 accept generation；已建 HTTP/TCP 连接仍独立持有 IO，
    // 随后由统一 active_connections 预算等待自然 drain。
    listener_supervisor.shutdown();

    let drain_timeout_ms = snap
        .load()
        .proxies
        .iter()
        .map(|proxy| proxy.timeouts.drain_timeout_ms)
        .max()
        .unwrap_or(0);
    if drain_timeout_ms > 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(drain_timeout_ms);
        while active_connections.load(Ordering::Relaxed) > 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let _ = std::fs::remove_file(&pf);
    if let Err(error) = access_log_shutdown.shutdown().await {
        warn!(%error, "access log sink shutdown/flush failed");
    }
    if let Err(error) = telemetry.shutdown() {
        warn!(%error, "OpenTelemetry shutdown/flush failed");
    }
    info!("gateway stopped");
    Ok(())
}

async fn bind_proxy(proxy: &ProxyRuntime) -> Result<BoundProxy> {
    let listen: SocketAddr = proxy
        .listen
        .parse()
        .with_context(|| format!("invalid proxy `{}` listen `{}`", proxy.id, proxy.listen))?;
    let listener = bind_reuseport_tcp(listen)
        .with_context(|| format!("bind proxy `{}` listen {listen}", proxy.id))?;
    let tls = match &proxy.tls {
        Some(tls_cfg) => {
            let tls_listen: SocketAddr = tls_cfg.listen.parse().with_context(|| {
                format!(
                    "invalid proxy `{}` tls.listen `{}`",
                    proxy.id, tls_cfg.listen
                )
            })?;
            // 即使没有 seed keypair 也先绑定 TLS 端口；否则首签期间端口可能被其它进程抢占，
            // 并且签发后无法在同一进程安全激活 listener。
            let tls_listener = bind_reuseport_tcp(tls_listen)
                .with_context(|| format!("bind proxy `{}` tls.listen {tls_listen}", proxy.id))?;
            let mode = if tls_cfg.acme.as_ref().is_some_and(|acme| {
                acme.bootstrap_without_seed
                    && (!tls_cfg.cert_file.is_file() || !tls_cfg.key_file.is_file())
            }) {
                warn!(proxy = %proxy.id, %tls_listen, "ACME bootstrap: seed certificate missing; TLS socket bound and awaiting first issuance");
                BoundTlsMode::Deferred(Box::new(tls_cfg.clone()))
            } else {
                let server_config = build_server_config(tls_cfg).with_context(|| {
                    format!("build initial tls server config for proxy `{}`", proxy.id)
                })?;
                let shared_tls: SharedServerConfig = Arc::new(ArcSwap::new(server_config));
                spawn_cert_watcher(tls_cfg.clone(), shared_tls.clone());
                BoundTlsMode::Ready(shared_tls)
            };
            Some(BoundTlsProxy {
                listen: tls_listen,
                listener: tls_listener,
                mode,
            })
        }
        None => None,
    };
    Ok(BoundProxy {
        id: proxy.id.clone(),
        listen,
        listener,
        tls,
    })
}

async fn bind_stream(stream: &StreamRuntime) -> Result<BoundStream> {
    let listen: SocketAddr = stream
        .listen
        .parse()
        .with_context(|| format!("invalid stream `{}` listen `{}`", stream.id, stream.listen))?;
    let socket = match stream.protocol {
        StreamProtocolRuntime::Tcp => BoundStreamSocket::Tcp(
            bind_reuseport_tcp(listen)
                .with_context(|| format!("bind stream `{}` TCP {listen}", stream.id))?,
        ),
        StreamProtocolRuntime::Udp => BoundStreamSocket::Udp(Arc::new(
            bind_reuseport_udp(listen)
                .with_context(|| format!("bind stream `{}` UDP {listen}", stream.id))?,
        )),
    };
    let tls = stream
        .tls
        .as_ref()
        .map(|tls| {
            let config = build_server_config(tls)
                .with_context(|| format!("build stream `{}` TLS config", stream.id))?;
            let shared: SharedServerConfig = Arc::new(ArcSwap::new(config));
            spawn_cert_watcher(tls.clone(), shared.clone());
            Ok::<_, anyhow::Error>(shared)
        })
        .transpose()?;
    Ok(BoundStream {
        runtime: stream.clone(),
        listen,
        socket,
        tls,
    })
}

/// 创建启动期与热更期统一使用的 TCP listener。所有数据面 socket 从第一次绑定起就启用
/// SO_REUSEPORT；否则旧 socket 已存在时再给新 socket单方面设置该选项仍无法安全重绑。
fn bind_reuseport_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(libc::SOMAXCONN)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// UDP 与 TCP 使用同一重绑纪律；旧 UDP session task 持有自己的 upstream socket，主 listener
/// 交接只影响后续 datagram，不创建全量报文缓冲。
fn bind_reuseport_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}
