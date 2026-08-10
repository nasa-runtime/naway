//! Naway 入口。
//!
//! - `naway --config zcf/naway.yml`:启动数据面(监听 + 无感热更)。
//! - `naway -s reload`:向运行中的进程发 SIGHUP 触发热更(nginx `-s reload` 风格)。

// 包名/二进制已经品牌化为 `naway`。crate 内大量 `Gateway*` 类型表达的是通用网关领域模型，
// 保留别名可避免把品牌重命名错误扩大成公共 Rust 类型/API 的破坏性迁移。
extern crate naway as gateway;

// Linux 生产数据面的 HTTP/H2 请求会创建大量短命协议对象；mimalloc 避免 glibc arena 在
// 多 Tokio worker 下形成额外锁竞争和长期 RSS 滞留。macOS/Windows 开发环境仍使用系统分配器。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::HashMap;
use std::future::Future;
use std::io::IoSlice;
#[cfg(feature = "http3")]
use std::net::IpAddr;
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
#[cfg(feature = "http3")]
use gateway::config::model::Http3RetryCfg;
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
use gateway::tls::{build_server_config, spawn_cert_watcher_until, SharedServerConfig};
use gateway::upstream::{DynamicUpstreamStore, PassiveHealthPolicy};

#[derive(Debug, Parser)]
#[command(name = "naway")]
#[command(about = "Naway high-performance Rust traffic + business gateway")]
struct Args {
    /// 运行形态；省略时兼容旧命令，按 `all-in-one` 启动。
    #[command(subcommand)]
    command: Option<RunMode>,
    /// 主配置文件路径（默认 `/data/naway/naway.yml`，或环境变量 `NAWAY_CONFIG`；兼容 `GW_CONFIG`）。
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
    /// 运行本地 service-mesh sidecar 数据面；业务 listener 强制只绑定 loopback。
    Sidecar,
    /// 只运行完整管理面；不绑定 public HTTP/TLS/L4 listener。
    Admin,
    /// 同一进程同时运行数据面与完整管理面，兼容旧启动方式。
    AllInOne,
}

impl RunMode {
    /// 业务作用：判断当前进程是否需要创建业务数据面资源。
    ///
    /// 参数说明：无。
    ///
    /// 返回：`data`、`sidecar`、`all-in-one` 返回 true，纯 `admin` 返回 false。
    fn runs_data(self) -> bool {
        matches!(self, Self::Data | Self::Sidecar | Self::AllInOne)
    }

    /// 业务作用：把 CLI 部署模式映射到管理 API 权限边界，避免 admin 模块依赖 binary 类型。
    ///
    /// 参数说明：无。
    ///
    /// 返回：sidecar 与 data 均只开放数据面最小运维权限，其余模式保持原管理边界。
    fn admin_plane_mode(self) -> admin::AdminPlaneMode {
        match self {
            Self::Data => admin::AdminPlaneMode::Data,
            Self::Sidecar => admin::AdminPlaneMode::Sidecar,
            Self::Admin => admin::AdminPlaneMode::Admin,
            Self::AllInOne => admin::AdminPlaneMode::AllInOne,
        }
    }

    /// 业务作用：标记是否启用 sidecar 专属 listener 暴露门禁。
    ///
    /// 参数说明：无。
    ///
    /// 返回：仅 `sidecar` 模式返回 true。
    fn is_sidecar(self) -> bool {
        self == Self::Sidecar
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
    /// HTTP/3 按 proxy+来源 IP 隔离的连接硬门；跨 listener generation 常驻，防止 reload 绕限。
    #[cfg(feature = "http3")]
    http3_peer_connection_budget: Arc<Http3PeerConnectionBudget>,
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
    /// 业务作用：为下游 IO 建立只约束连续写阻塞的 deadline 状态，不改变读取和 body 流式语义。
    ///
    /// 参数说明：`inner` 是已完成接入校验的下游 IO；`timeout_ms=0` 表示关闭写超时。
    ///
    /// 返回：返回尚未启动计时的 IO wrapper；计时器只在第一次写 `Pending` 时惰性创建。
    fn new(inner: I, timeout_ms: u64) -> Self {
        Self {
            inner,
            timeout: (timeout_ms > 0).then(|| Duration::from_millis(timeout_ms)),
            timer: None,
            write_blocked: false,
        }
    }

    /// 业务作用：在 inner write 持续 `Pending` 时启动或推进 deadline，防止停读客户端永久占用连接。
    ///
    /// 参数说明：`cx` 提供当前 IO task 的唤醒器。
    ///
    /// 返回：deadline 未到时保持 `Pending`；到期后返回 `TimedOut` 并终止 Hyper 连接驱动。
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

    /// 业务作用：复验已经进入阻塞段的单调时钟 deadline，避免 task 延迟调度后被一次偶然可写绕过超时。
    ///
    /// 参数说明：无。
    ///
    /// 返回：阻塞段已超过 deadline 时返回 `TimedOut`；未计时或尚未到期时返回 `None`。
    fn expired_write_timeout(&self) -> Option<io::Error> {
        (self.write_blocked
            && self
                .timer
                .as_ref()
                .is_some_and(|timer| timer.deadline() <= tokio::time::Instant::now()))
        .then(|| io::Error::new(io::ErrorKind::TimedOut, "downstream write timed out"))
    }

    /// 业务作用：在 write/flush/shutdown 实际完成后结束当前阻塞段，使下一次 `Pending` 使用新 deadline。
    ///
    /// 保留已分配的 `Sleep` 很重要：h2 会在小 DATA/HEADERS 帧间频繁经历短 Pending，若每次
    /// Ready 都 drop，数据面会反复进入 Tokio timer wheel 的分配/锁路径。旧 deadline 后续即使
    /// 产生一次多余 wake 也不会报超时，因为下一段 Pending 会先 reset 到自己的新 deadline。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；只清除当前阻塞标记并保留计时器分配。
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
        if let Some(error) = self.expired_write_timeout() {
            return Poll::Ready(Err(error));
        }
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
        if let Some(error) = self.expired_write_timeout() {
            return Poll::Ready(Err(error));
        }
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
        if let Some(error) = self.expired_write_timeout() {
            return Poll::Ready(Err(error));
        }
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
        if let Some(error) = self.expired_write_timeout() {
            return Poll::Ready(Err(error));
        }
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

/// HTTP/3 来源 IP 连接预算；计数表只包含已有全局名额的 Initial/connection，规模受全局硬门约束。
#[cfg(feature = "http3")]
#[derive(Default)]
struct Http3PeerConnectionBudget {
    /// proxy id -> 来源 IP -> 当前握手或已建立连接数；reload 不替换这张表。
    entries: ParkingMutex<HashMap<String, HashMap<IpAddr, u64>>>,
}

/// 单条 QUIC handshake/connection 占用的来源 IP 名额。
#[cfg(feature = "http3")]
struct Http3PeerConnectionSlot {
    budget: Arc<Http3PeerConnectionBudget>,
    proxy_id: Arc<str>,
    peer_ip: IpAddr,
}

/// 单条已接收连接从同一份不可变 Snapshot 固化的配置。
///
/// PROXY protocol 策略与预算上限来自同一版本，避免 reload 恰好发生在两次独立读取之间时拼出
/// 混合配置。listener 快照只作为“该 listener 已被删除”后的排空兜底；同 id 仍存在时每个请求
/// 继续读取最新版，避免普通 keep-alive 长期绕过策略更新。
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
    /// accept 时的 listener generation；删除 listener 后只服务该物理连接上的在途/排空请求。
    listener_snapshot: Arc<GatewaySnapshot>,
}

/// Hyper connection driver 只保留共享协议 Builder 与连接期超时，不钉住完整路由快照。
struct DownstreamConnectionConfig {
    /// 同一 listener、同一 Snapshot 版本共享的只读 HTTP/1+HTTP/2 Builder。
    server: Arc<auto::Builder<TokioExecutor>>,
    /// 写超时与总连接超时仍由各 connection future 直接读取。
    timeouts: TimeoutCfg,
}

/// 一条已准入连接交给 Hyper driver 的协议参数与 listener 排空 generation。
struct DownstreamConnectionDispatch {
    /// 可按 Snapshot version 共享 Builder 的紧凑连接配置。
    config: DownstreamConnectionConfig,
    /// listener 删除后的连接排空兜底；同 id 存在时请求仍使用最新 Snapshot。
    listener_snapshot: Arc<GatewaySnapshot>,
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
    #[cfg(feature = "http3")]
    quic: bool,
}

impl Drop for ConnectionLifetime {
    /// 业务作用：在 TCP 或 QUIC 下游 connection 完整退出时一次性归还全局连接
    /// 计数，避免错误/取消分支泄漏 gauge。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；QUIC generation 额外归还 `gw_quic_connections_active`。
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        self.metrics.dec_active_connection();
        #[cfg(feature = "http3")]
        if self.quic {
            self.metrics.dec_quic_connection();
        }
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
            let snapshot = snap.load_full();
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
                    listener_snapshot: snapshot.clone(),
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

#[cfg(feature = "http3")]
impl Http3PeerConnectionBudget {
    /// 非阻塞占用一个来源 IP 名额。
    ///
    /// 业务作用：在 QUIC handshake task 创建前限制单一来源的连接占用，并让计数跨 reload
    /// generation 连续，避免攻击者借热更得到第二份预算。
    ///
    /// 参数说明：`proxy_id` 是逻辑 listener；`peer_ip` 取自 Initial 源地址；`limit` 是同版硬门。
    ///
    /// 返回：未达上限时返回 RAII 名额；达到上限返回 None，调用方必须协议级拒绝 Initial。
    fn try_acquire(
        self: &Arc<Self>,
        proxy_id: &Arc<str>,
        peer_ip: IpAddr,
        limit: usize,
    ) -> Option<Http3PeerConnectionSlot> {
        let limit = limit.min(u64::MAX as usize) as u64;
        let mut entries = self.entries.lock();
        let peers = entries.entry(proxy_id.to_string()).or_default();
        let active = peers.entry(peer_ip).or_default();
        if *active >= limit {
            return None;
        }
        *active = active.saturating_add(1);
        Some(Http3PeerConnectionSlot {
            budget: self.clone(),
            proxy_id: proxy_id.clone(),
            peer_ip,
        })
    }
}

impl Drop for ConnectionSlot {
    /// 归还名额并唤醒所有等待 listener；等待方会用 CAS 竞争最新可用名额。
    fn drop(&mut self) {
        self.entry.active.fetch_sub(1, Ordering::AcqRel);
        self.entry.changed.notify_waiters();
    }
}

#[cfg(feature = "http3")]
impl Drop for Http3PeerConnectionSlot {
    /// 业务作用：在握手失败、连接结束或 task 取消的同一个 Drop 边界归还来源 IP 名额。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；最后一个名额释放时同时删除 IP/proxy 空表，避免长期积累来源键。
    fn drop(&mut self) {
        let mut entries = self.budget.entries.lock();
        let remove_proxy = if let Some(peers) = entries.get_mut(self.proxy_id.as_ref()) {
            let remove_peer = if let Some(active) = peers.get_mut(&self.peer_ip) {
                *active = active.saturating_sub(1);
                *active == 0
            } else {
                false
            };
            if remove_peer {
                peers.remove(&self.peer_ip);
            }
            peers.is_empty()
        } else {
            false
        };
        if remove_proxy {
            entries.remove(self.proxy_id.as_ref());
        }
    }
}


/// L4 stream 负载均衡常驻状态。
///
/// 与配置快照解耦:reload 不应重置 `least_conn` 在途计数或 `round_robin` 游标。
#[derive(Clone, Default)]
struct StreamLbState {
    /// 上游 health_key -> 当前 stream 会话数。
    inflight: Arc<ParkingMutex<HashMap<Arc<str>, Arc<AtomicU64>>>>,
    /// 逻辑服务名或 route id -> round_robin 单调游标。
    rr: Arc<ParkingMutex<HashMap<String, u64>>>,
    /// 上游 health_key -> 被动健康失败状态。
    failures: Arc<ParkingMutex<HashMap<String, StreamUpstreamFailureState>>>,
}

impl StreamLbState {
    /// 业务作用：为 stream 逻辑服务或带权 route 分配跨 reload 连续的 round-robin 序号。
    ///
    /// 参数说明：`scope` 是 `lb://service` 的逻辑服务名或带权 route id。
    ///
    /// 返回：返回当前序号并以 wrapping 语义推进游标；同一 scope 的并发调用串行化。
    fn next_rr(&self, scope: &str) -> u64 {
        let mut map = self.rr.lock();
        // scope 来自已验证快照且长期命中；只在首次出现时拥有一份 key。
        let counter = match map.get_mut(scope) {
            Some(counter) => counter,
            None => {
                map.insert(scope.to_owned(), 0);
                map.get_mut(scope).expect("inserted stream rr counter")
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
    /// MQTT listener 级连接预算；只在协议治理制品中存在。
    #[cfg(feature = "mqtt-governance")]
    mqtt_connections: MqttConnectionBudget,
    /// Kafka listener 级连接预算；只在协议治理制品中存在。
    #[cfg(feature = "kafka-governance")]
    kafka_connections: KafkaConnectionBudget,
}

/// MQTT listener 连接数快照外常驻状态；热更降低上限时新连接立即按新值拒绝。
#[cfg(feature = "mqtt-governance")]
#[derive(Clone, Default)]
struct MqttConnectionBudget {
    usage: Arc<ParkingMutex<HashMap<Arc<str>, MqttListenerUsage>>>,
}

/// 一个 MQTT listener 跨快照连接共享的实时预留量。
#[cfg(feature = "mqtt-governance")]
#[derive(Clone, Copy, Default)]
struct MqttListenerUsage {
    connections: usize,
    buffered_bytes: usize,
}

#[cfg(feature = "mqtt-governance")]
impl MqttConnectionBudget {
    /// 业务作用：在 TLS/CONNECT preread 之前预留 listener 级 MQTT 连接名额，慢握手也不能绕过硬门。
    ///
    /// 参数说明：`listener_id` 是快照内稳定标识；`maximum` 是连接上限；
    /// `buffer_reservation` 是新连接双向最大 packet 预留；`maximum_buffered_bytes` 是 listener 聚合上限。
    ///
    /// 返回：余额充足时返回 RAII guard；已达上限时返回 None 且不改变计数。
    fn try_acquire(
        &self,
        listener_id: &str,
        maximum: usize,
        buffer_reservation: usize,
        maximum_buffered_bytes: usize,
    ) -> Option<MqttConnectionGuard> {
        let mut usage = self.usage.lock();
        let current = usage.get(listener_id).copied().unwrap_or_default();
        let next_buffered = current.buffered_bytes.checked_add(buffer_reservation)?;
        if current.connections >= maximum || next_buffered > maximum_buffered_bytes {
            return None;
        }
        let key: Arc<str> = usage
            .get_key_value(listener_id)
            .map(|(key, _)| key.clone())
            .unwrap_or_else(|| Arc::from(listener_id));
        usage.insert(
            key.clone(),
            MqttListenerUsage {
                connections: current.connections + 1,
                buffered_bytes: next_buffered,
            },
        );
        Some(MqttConnectionGuard {
            usage: self.usage.clone(),
            listener_id: key,
            buffer_reservation,
        })
    }
}

/// MQTT 连接名额；任务取消、握手失败与正常断开都由 Drop 统一归还。
#[cfg(feature = "mqtt-governance")]
struct MqttConnectionGuard {
    usage: Arc<ParkingMutex<HashMap<Arc<str>, MqttListenerUsage>>>,
    listener_id: Arc<str>,
    buffer_reservation: usize,
}

#[cfg(feature = "mqtt-governance")]
impl Drop for MqttConnectionGuard {
    /// 业务作用：在任意退出路径归还 MQTT listener 名额，避免错误分支泄漏导致永久拒绝。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；当前 listener 连接计数减一并归还双向 buffer 预留，归零时移除 map 项。
    fn drop(&mut self) {
        let mut usage = self.usage.lock();
        if let Some(current) = usage.get_mut(self.listener_id.as_ref()) {
            current.connections = current.connections.saturating_sub(1);
            current.buffered_bytes = current
                .buffered_bytes
                .saturating_sub(self.buffer_reservation);
            if current.connections == 0 {
                usage.remove(self.listener_id.as_ref());
            }
        }
    }
}

/// Kafka listener 连接数快照外常驻状态；热更降低上限时新连接立即按新值拒绝。
#[cfg(feature = "kafka-governance")]
#[derive(Clone, Default)]
struct KafkaConnectionBudget {
    usage: Arc<ParkingMutex<HashMap<Arc<str>, KafkaListenerUsage>>>,
}

/// 一个 Kafka listener 跨快照连接共享的实时预留量。
#[cfg(feature = "kafka-governance")]
#[derive(Clone, Copy, Default)]
struct KafkaListenerUsage {
    connections: usize,
    buffered_bytes: usize,
}

#[cfg(feature = "kafka-governance")]
impl KafkaConnectionBudget {
    /// 业务作用：在 PROXY/TLS/首 frame 前预留 Kafka 连接与双向 frame buffer，阻断慢握手绕过资源门。
    ///
    /// 参数说明：`listener_id` 是稳定 listener 标识；`maximum` 是连接上限；
    /// `buffer_reservation` 是单连接双向预留；`maximum_buffered_bytes` 是 listener 聚合上限。
    ///
    /// 返回：预算充足时返回 RAII guard；连接或聚合 buffer 达上限时返回 None 且不改变计数。
    fn try_acquire(
        &self,
        listener_id: &str,
        maximum: usize,
        buffer_reservation: usize,
        maximum_buffered_bytes: usize,
    ) -> Option<KafkaConnectionGuard> {
        let mut usage = self.usage.lock();
        let current = usage.get(listener_id).copied().unwrap_or_default();
        let next_buffered = current.buffered_bytes.checked_add(buffer_reservation)?;
        if current.connections >= maximum || next_buffered > maximum_buffered_bytes {
            return None;
        }
        let key: Arc<str> = usage
            .get_key_value(listener_id)
            .map(|(key, _)| key.clone())
            .unwrap_or_else(|| Arc::from(listener_id));
        usage.insert(
            key.clone(),
            KafkaListenerUsage {
                connections: current.connections + 1,
                buffered_bytes: next_buffered,
            },
        );
        Some(KafkaConnectionGuard {
            usage: self.usage.clone(),
            listener_id: key,
            buffer_reservation,
        })
    }
}

/// Kafka 连接名额；任务取消、握手失败与正常断开都由 Drop 统一归还。
#[cfg(feature = "kafka-governance")]
struct KafkaConnectionGuard {
    usage: Arc<ParkingMutex<HashMap<Arc<str>, KafkaListenerUsage>>>,
    listener_id: Arc<str>,
    buffer_reservation: usize,
}

#[cfg(feature = "kafka-governance")]
impl Drop for KafkaConnectionGuard {
    /// 业务作用：在任意退出路径归还 Kafka listener 名额，防止错误分支泄漏后永久拒绝新连接。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；连接计数与双向 buffer 预留同步归还，归零时移除 listener 项。
    fn drop(&mut self) {
        let mut usage = self.usage.lock();
        if let Some(current) = usage.get_mut(self.listener_id.as_ref()) {
            current.connections = current.connections.saturating_sub(1);
            current.buffered_bytes = current
                .buffered_bytes
                .saturating_sub(self.buffer_reservation);
            if current.connections == 0 {
                usage.remove(self.listener_id.as_ref());
            }
        }
    }
}

/// 业务作用：解析 Naway 主配置路径，并保持显式参数、品牌环境变量与通用兼容变量的确定优先级。
///
/// 参数说明：`args` 提供命令行显式配置路径。
///
/// 返回：依次选择 `--config`、`NAWAY_CONFIG`、`GW_CONFIG`、`NAWAY_CONFIG_DIR`、
/// `GW_CONFIG_DIR` 或默认目录下的 `naway.yml`；接口守卫相对最终主配置目录解析。
fn config_path(args: &Args) -> PathBuf {
    if let Some(c) = &args.config {
        return c.into();
    }
    if let Ok(c) = std::env::var("NAWAY_CONFIG") {
        return c.into();
    }
    if let Ok(c) = std::env::var("GW_CONFIG") {
        return c.into();
    }
    if let Ok(dir) = std::env::var("NAWAY_CONFIG_DIR") {
        return PathBuf::from(dir).join(DEFAULT_CONFIG_FILE);
    }
    if let Ok(dir) = std::env::var("GW_CONFIG_DIR") {
        let dir = PathBuf::from(dir);
        let branded = dir.join(DEFAULT_CONFIG_FILE);
        return branded;
    }
    PathBuf::from(DEFAULT_CONFIG_DIR).join(DEFAULT_CONFIG_FILE)
}

/// 业务作用：解析 Naway pidfile 路径，确保信号发送端与运行进程使用同一品牌配置入口。
///
/// 参数说明：无。
///
/// 返回：优先返回 `NAWAY_PIDFILE`，其次兼容 `GW_PIDFILE`，否则返回当前目录的 `naway.pid`。
fn pidfile_path() -> PathBuf {
    std::env::var("NAWAY_PIDFILE")
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

/// 业务作用：把同一 listener、同一 Snapshot 版本的 Hyper Builder 构造成本摊薄到一次，
/// 避免连接规模增长时重复保留等价协议配置。
///
/// `auto::Builder` 内含 HTTP/1 parser 与 HTTP/2 flow-control 配置。旧实现把它放在每条
/// connection task 内，10k 长连接会同时保留 10k 份完全相同的 Builder。这里按 listener
/// 缓存只读实例：命中只做一次 `Arc` 增计数；reload 后首条新连接重建，旧连接继续持有旧版本。
///
/// 参数说明：`cache` 是当前 accept loop 私有单项缓存；`snapshot_version` 是连接读取的原子配置
/// 版本；`limits` 提供请求头、HTTP/2 stream 与 flow-control 硬预算；`timeouts` 提供协议计时门。
///
/// 返回：可供本连接使用的共享 server 与连接期 timeout；版本变化时先换缓存，旧连接继续持有旧值。
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

/// 业务作用：把一条已准入的下游连接交给共享 Hyper server，并把连接预算、活跃指标、
/// 可信客户端地址缓存和 Upgrade 生命周期绑定到同一个可取消 task。
///
/// 参数说明：`stream` 是已完成监听层握手的 IO；`conn`/`proxy_id`/`downstream_proto` 标识
/// 本连接的可信入口上下文；`state`/`dispatch` 提供数据面、同版 server 与 listener 排空快照；
/// `slot` 持有连接预算。
///
/// 返回：无返回值；函数成功 spawn 连接驱动，连接结束、超时或 task 取消时通过 Drop 归还预算。
fn spawn_downstream_connection<I>(
    stream: I,
    conn: ConnInfo,
    proxy_id: Arc<str>,
    downstream_proto: &'static str,
    state: DataPlaneState,
    dispatch: DownstreamConnectionDispatch,
    slot: ConnectionSlot,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let DownstreamConnectionDispatch {
        config: DownstreamConnectionConfig { server, timeouts },
        listener_snapshot,
    } = dispatch;
    // IP header 只依赖已完成 PROXY protocol 校验的连接地址。提前到 accept/connection 层构造，
    // 让 H2 多路复用的每个 RPC 只 clone 不可变 HeaderValue；trusted XFF 改写仍由请求层核对。
    let connection_client_ip_header = ConnectionClientIpHeader::new(&conn);
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    state.metrics.inc_active_connection();
    let connection_lifetime = DownstreamConnectionLease::new(ConnectionLifetime {
        _slot: slot,
        active_connections: state.active_connections.clone(),
        metrics: state.metrics.clone(),
        #[cfg(feature = "http3")]
        quic: false,
    });
    tokio::spawn(async move {
        let io = TokioIo::new(DownstreamWriteTimeoutIo::new(
            stream,
            timeouts.downstream_write_timeout_ms,
        ));
        let proxy = state.proxy.clone();
        let request_connection_lifetime = connection_lifetime.clone();
        let request_client_ip_header = connection_client_ip_header;
        let request_listener_snapshot = listener_snapshot;
        let request_conn = conn.clone();
        let svc = service_fn(move |mut req: hyper::Request<Incoming>| {
            // 只有带 Upgrade 头的候选请求才 clone/分配 Extensions。普通 HTTP/1 keep-alive 与
            // HTTP/2 热路径完全不承担 WS 生命周期修复成本；proxy::handle 仍完整校验 GET、h1、
            // Connection: upgrade 和 websocket 值，非法 Upgrade 不会进入隧道。
            if req.headers().contains_key(hyper::header::UPGRADE) {
                req.extensions_mut()
                    .insert(request_connection_lifetime.clone());
            }
            // Hyper 会把 service future 直接嵌进每个 H2Stream task；该请求状态机约 14KiB，若
            // 保持内联，建流时会在栈与 task storage 间重复整块复制。这里只装箱 future 本身，
            // 请求/响应 body 仍按 Bytes 零拷贝流转，取消时 Drop 该 Box 仍同步取消原状态机。
            Box::pin(proxy.clone().handle_with_connection_ip_header(
                req,
                request_conn.clone(),
                downstream_proto,
                proxy_id.clone(),
                request_client_ip_header.clone(),
                request_listener_snapshot.clone(),
            ))
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
                listener_snapshot,
            } = accepted;
            let downstream = DownstreamConnectionDispatch {
                config: downstream_connection_config(
                    &mut server_cache,
                    snapshot_version,
                    &limits,
                    timeouts,
                ),
                listener_snapshot,
            };
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
                listener_snapshot,
            } = accepted;
            let downstream = DownstreamConnectionDispatch {
                config: downstream_connection_config(
                    &mut server_cache,
                    snapshot_version,
                    &limits,
                    timeouts,
                ),
                listener_snapshot,
            };
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
                            // SNI 是 TLS 连接级权威证据；请求 Host 不能覆盖它。共享 HTTPS
                            // socket 后续据此拒绝跨 Gateway listener 的 H2 连接合并。
                            conn.tls_server_name =
                                tls_stream.get_ref().1.server_name().map(|name| {
                                    Arc::from(name.trim_end_matches('.').to_ascii_lowercase())
                                });
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

/// 启动 HTTP/3/QUIC accept loop。
///
/// 业务作用：在握手 task 创建前同时执行 HTTP/3 专属连接上限、全 proxy 共享连接预算与 Retry
/// 地址验证；停机或 reload 时先关闭 endpoint 的新连接入口，已建立连接仍按统一 drain 计数收尾。
///
/// 参数说明：`endpoint` 是 prepare 阶段已绑定的 UDP endpoint；`runtime` 是同版 H3 硬预算；
/// `certificate_updates` 串行接收新握手配置；`proxy_id` 标识逻辑 listener；`state` 提供统一
/// 代理、预算和指标；`shutdown` 是 generation 停收广播。
///
/// 返回：无同步返回值；函数派生一个受 shutdown 管理的 accept task。
#[cfg(feature = "http3")]
fn spawn_http3_accept_loop(
    endpoint: quinn::Endpoint,
    runtime: gateway::config::Http3RuntimeCfg,
    mut certificate_updates: watch::Receiver<Option<quinn::ServerConfig>>,
    proxy_id: Arc<str>,
    state: DataPlaneState,
    mut shutdown: watch::Receiver<bool>,
) {
    let budget_entry = state.connection_budget.entry(&proxy_id);
    tokio::spawn(async move {
        let local = endpoint.local_addr().ok();
        info!(?local, proxy = %proxy_id, "HTTP/3 QUIC data plane listening");
        let mut certificate_updates_open = true;
        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => incoming,
                    None => break,
                },
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        // 先撤销 server config，旧 generation 不再接受 Initial；已握手连接仍持有
                        // 自己的 endpoint/connection 状态，交给统一 drain 而不是粗暴 CONNECTION_CLOSE。
                        endpoint.set_server_config(None);
                        info!(proxy = %proxy_id, "stop accepting new HTTP/3 connections (shutdown)");
                        break;
                    }
                    continue;
                }
                changed = certificate_updates.changed(), if certificate_updates_open => {
                    if changed.is_err() {
                        certificate_updates_open = false;
                    } else if let Some(config) = certificate_updates.borrow_and_update().clone() {
                        // 与停机分支在同一个 accept task 串行执行；一旦 shutdown 把 server config
                        // 置空并 break，证书 watcher 再也没有机会重新开放旧 generation。
                        endpoint.set_server_config(Some(config));
                        info!(proxy = %proxy_id, "HTTP/3 certificate reloaded for new handshakes");
                    }
                    continue;
                }
            };
            let peer = incoming.remote_address();
            if endpoint.open_connections() >= runtime.max_connections {
                // HTTP/3 专属上限必须在握手 task 前拒绝，否则攻击者可绕过配置制造无界 task。
                state.metrics.inc_quic_handshake_rejected();
                incoming.refuse();
                continue;
            }
            if should_retry_http3(&incoming, &runtime, endpoint.open_connections()) {
                match incoming.retry() {
                    Ok(()) => state.metrics.inc_quic_handshake_retry(),
                    Err(error) => {
                        state.metrics.inc_quic_handshake_error();
                        tracing::debug!(%peer, %error, "HTTP/3 Retry could not be issued");
                    }
                }
                continue;
            }

            // QUIC 与同 proxy 的 TCP/TLS 共用 limits.max_connections。用非阻塞 CAS 在握手前
            // 占位，预算耗尽时直接拒绝 Initial，不能像 TCP 那样持有一个已 accept socket 等待。
            let snapshot = state.snap.load();
            let Some(proxy_runtime) = snapshot.proxy(&proxy_id) else {
                state.metrics.inc_quic_handshake_rejected();
                incoming.refuse();
                continue;
            };
            let Some(slot) = ConnectionBudget::try_acquire_entry(
                &budget_entry,
                proxy_runtime.limits.max_connections,
            ) else {
                state.metrics.inc_quic_handshake_rejected();
                incoming.refuse();
                continue;
            };
            let Some(peer_slot) = state.http3_peer_connection_budget.try_acquire(
                &proxy_id,
                peer.ip(),
                runtime.max_connections_per_ip,
            ) else {
                // 单来源门必须在 handshake task 前执行；拒绝时全局 slot 随本分支 Drop 归还，
                // 不给同一 IP 建排队 task，也不影响其它来源争用剩余容量。
                state.metrics.inc_quic_handshake_rejected();
                incoming.refuse();
                continue;
            };
            let connection_timeout_ms = proxy_runtime.timeouts.connection_timeout_ms;
            drop(snapshot);

            let connecting = match incoming.accept() {
                Ok(connecting) => connecting,
                Err(error) => {
                    state.metrics.inc_quic_handshake_error();
                    tracing::debug!(%peer, %error, "HTTP/3 QUIC Initial rejected");
                    continue;
                }
            };
            let proxy = state.proxy.clone();
            let proxy_id = proxy_id.clone();
            let active_connections = state.active_connections.clone();
            let metrics = state.metrics.clone();
            let max_header_bytes = runtime.max_request_header_bytes;
            let mut connection_shutdown = shutdown.clone();
            tokio::spawn(async move {
                // 从 Initial 到 connection task 完整结束都计入来源预算，握手失败/取消也由 RAII 归还。
                let _peer_slot = peer_slot;
                let connection = tokio::select! {
                    result = connecting => match result {
                        Ok(connection) => connection,
                        Err(error) => {
                            metrics.inc_quic_handshake_error();
                            tracing::debug!(%peer, %error, "HTTP/3 QUIC handshake failed");
                            return;
                        }
                    },
                    changed = connection_shutdown.changed() => {
                        if changed.is_err() || *connection_shutdown.borrow() {
                            return;
                        }
                        return;
                    }
                };
                active_connections.fetch_add(1, Ordering::Relaxed);
                metrics.inc_active_connection();
                metrics.inc_quic_connection();
                let _lifetime = ConnectionLifetime {
                    _slot: slot,
                    active_connections,
                    metrics: metrics.clone(),
                    quic: true,
                };
                let serving = gateway::http3::serve_connection(
                    connection,
                    proxy,
                    proxy_id,
                    peer,
                    max_header_bytes,
                    metrics,
                    connection_shutdown,
                );
                let result = if connection_timeout_ms == 0 {
                    serving.await
                } else {
                    match tokio::time::timeout(
                        Duration::from_millis(connection_timeout_ms),
                        serving,
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            tracing::debug!(%peer, "HTTP/3 connection closed by total timeout");
                            return;
                        }
                    }
                };
                if let Err(error) = result {
                    tracing::debug!(%peer, %error, "HTTP/3 connection closed with error");
                }
            });
        }
    });
}

/// 判断一个未完成握手的 QUIC Initial 是否必须先经过 Retry 地址验证。
///
/// 业务作用：`always` 强制抗源地址伪造，`auto` 在连接占用达到 75% 后开启验证以降低正常期额外
/// RTT；已经携带有效 token 的连接绝不重复 Retry，避免形成握手循环。
///
/// 参数说明：`incoming` 提供地址验证状态；`runtime` 提供策略与连接硬门；`open_connections`
/// 是 endpoint 当前已打开连接数。
///
/// 返回：true 表示调用方应发送 Retry 并停止本次握手，false 表示可继续预算校验。
#[cfg(feature = "http3")]
fn should_retry_http3(
    incoming: &quinn::Incoming,
    runtime: &gateway::config::Http3RuntimeCfg,
    open_connections: usize,
) -> bool {
    http3_retry_required(
        runtime.retry,
        incoming.remote_address_validated(),
        incoming.may_retry(),
        open_connections,
        runtime.max_connections,
    )
}

/// 对纯地址验证状态执行 HTTP/3 Retry 策略判定。
///
/// 业务作用：把压力水位和防重复 Retry 不变量集中为可单测的纯函数，避免 accept loop 分支在
/// 后续调优时把已验证客户端重新送入 Retry 循环。
///
/// 参数说明：`policy` 是配置策略；`address_validated`/`may_retry` 来自 Quinn；
/// `open_connections`/`max_connections` 是当前占用与 H3 专属硬上限。
///
/// 返回：true 表示必须先发 Retry；false 表示本层允许继续进入连接预算校验。
#[cfg(feature = "http3")]
fn http3_retry_required(
    policy: Http3RetryCfg,
    address_validated: bool,
    may_retry: bool,
    open_connections: usize,
    max_connections: usize,
) -> bool {
    if address_validated || !may_retry {
        return false;
    }
    match policy {
        Http3RetryCfg::Off => false,
        Http3RetryCfg::Always => true,
        // 3/4 是明确的资源保护水位；乘法使用饱和运算，极端配置也不会溢出后关闭保护。
        Http3RetryCfg::Auto => {
            open_connections.saturating_mul(4) >= max_connections.saturating_mul(3)
        }
    }
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

/// 业务作用：等待 ACME 首签 keypair 落盘后激活已绑定 TLS socket，并把任务限制在 listener generation 内。
///
/// 参数说明：`listener` 防止首签期间端口被抢；`proxy_id` 用于观测；`tls_cfg` 描述材料和轮询；
/// `state` 是数据面状态；`shutdown` 撤销本代；`readiness` 统一约束 pending、就绪与停机事实。
///
/// 返回：无同步返回值；后台仅在证书完整可用后启动 accept，取消或坏材料均保持端口不服务。
fn spawn_deferred_tls_accept_loop(
    listener: TcpListener,
    proxy_id: Arc<str>,
    tls_cfg: gateway::config::TlsRuntimeCfg,
    state: DataPlaneState,
    mut shutdown: watch::Receiver<bool>,
    readiness: DeferredTlsReadiness,
) {
    tokio::spawn(async move {
        let _pending = PendingTlsActivation::new(readiness);
        let poll_ms = tls_cfg
            .acme
            .as_ref()
            .map(|acme| acme.activation_poll_ms)
            .unwrap_or(250)
            .max(1);
        let mut last_error = None;
        loop {
            if *shutdown.borrow() {
                return;
            }
            match build_server_config(&tls_cfg) {
                Ok(server_config) => {
                    let shared_tls: SharedServerConfig = Arc::new(ArcSwap::new(server_config));
                    spawn_cert_watcher_until(tls_cfg.clone(), shared_tls.clone(), shutdown.clone());
                    let listen = listener.local_addr().ok();
                    spawn_tls_accept_loop(listener, proxy_id.clone(), shared_tls, state, shutdown);
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

/// 一个 deferred TLS generation 对全进程 pending/readiness 事实的 RAII 占位。
struct PendingTlsActivation {
    readiness: DeferredTlsReadiness,
}

/// 无 seed TLS listener 共享的就绪状态；generation 热换与进程停机必须操作同一组原子事实。
#[derive(Clone)]
struct DeferredTlsReadiness {
    pending: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
}

impl PendingTlsActivation {
    /// 业务作用：接管调用方已增加的 deferred TLS 计数，保证所有退出路径都能归还。
    ///
    /// 参数说明：`readiness` 统一持有全进程待激活数、就绪位和停机位。
    ///
    /// 返回：返回只应在对应 activation task 内持有的 RAII guard。
    fn new(readiness: DeferredTlsReadiness) -> Self {
        Self { readiness }
    }
}

impl Drop for PendingTlsActivation {
    /// 业务作用：在激活、热移除、取消或 panic 后归还 pending 事实，避免 readiness 永久卡住。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；最后一个 pending 退出且进程未停机时发布 ready=true。
    fn drop(&mut self) {
        let previous = self.readiness.pending.fetch_sub(1, Ordering::AcqRel);
        if previous == 1 && !self.readiness.stopping.load(Ordering::Acquire) {
            self.readiness.ready.store(true, Ordering::Release);
        }
    }
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

/// 业务作用：为一条 L4 TCP 连接固定建连时路由/上游，执行可选 TLS、preread、
/// MQTT 治理和双向背压；热更不会把已建连接中途改道。
///
/// 参数说明：`downstream` 是下游 TCP socket；`peer` 是直连对端；`bound_runtime` 是绑定
/// socket 的启动期兜底配置；`tls` 是可热换的服务端 TLS；`state` 是 stream 共享状态。
///
/// 返回：无；函数创建可取消任务，所有成功/失败路径均归还连接计数并记录低基数结果。
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
        #[cfg(feature = "mqtt-governance")]
        let _mqtt_connection_guard = if let Some(policy) = runtime.mqtt.as_ref() {
            // 必须先抢连接名额再做 PROXY/TLS/CONNECT preread，否则慢握手可在解析前堆积无界 task。
            let Some(guard) = state.mqtt_connections.try_acquire(
                &runtime.id,
                policy.max_connections(),
                policy.connection_buffer_reservation(),
                policy.max_buffered_bytes(),
            ) else {
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT connection budget exhausted");
                state
                    .metrics
                    .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::ResourceLimit);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 429, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            };
            Some(guard)
        } else {
            None
        };
        #[cfg(feature = "kafka-governance")]
        let _kafka_connection_guard = if let Some(policy) = runtime.kafka.as_ref() {
            // 连接名额必须覆盖 PROXY/TLS 和首 frame deadline，否则攻击者可在 parser 前堆积无界 task。
            let Some(guard) = state.kafka_connections.try_acquire(
                &runtime.id,
                policy.max_connections(),
                policy.connection_buffer_reservation(),
                policy.max_buffered_bytes(),
            ) else {
                warn!(stream = %runtime.id, peer = %peer, "stream Kafka connection budget exhausted");
                state
                    .metrics
                    .inc_stream_kafka_rejection(gateway::kafka::KafkaViolationKind::ResourceLimit);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 429, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            };
            Some(guard)
        } else {
            None
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
        let mut downstream: BoxStreamIo = match tls.as_ref() {
            Some(config) if !runtime.preread.ssl_preread => {
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
            _ => Box::new(stream),
        };
        let peer = conn.real_peer;
        log_ctx.peer = peer.to_string();
        let mut preread = if runtime.preread.ssl_preread {
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
                    #[cfg(feature = "mqtt-governance")]
                    if runtime.mqtt.is_some() {
                        state
                            .metrics
                            .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::Malformed);
                    }
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
                #[cfg(feature = "mqtt-governance")]
                mqtt_protocol_level: None,
                #[cfg(feature = "mqtt-governance")]
                mqtt_packet_len: None,
                #[cfg(feature = "mqtt-governance")]
                mqtt_clean_start: None,
                bytes: Vec::new(),
            }
        };
        #[cfg(feature = "mqtt-governance")]
        if let Some(policy) = runtime.mqtt.as_ref() {
            let Some(client_id) = preread.mqtt_client_id.as_deref() else {
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT governance missing CONNECT client id");
                state
                    .metrics
                    .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::Malformed);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            };
            if !policy.allows_client_id(client_id) {
                // client ACL 在 upstream resolve/dial 之前执行，被拒绝身份不得触达 broker 也不污染被动健康。
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT client id rejected by ACL");
                state
                    .metrics
                    .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::NotAuthorized);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 403, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            if !matches!(preread.mqtt_protocol_level, Some(4 | 5)) {
                warn!(stream = %runtime.id, peer = %peer, level = ?preread.mqtt_protocol_level, "stream MQTT governance rejects unsupported protocol level");
                state
                    .metrics
                    .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::Protocol);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            if preread.mqtt_packet_len != Some(preread.bytes.len()) {
                // CONNECT 之后的 pipelined 字节尚未经状态机，不能随 preread buffer 整段回放绕过 ACL/QoS 门。
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT client sent packets before CONNACK");
                state
                    .metrics
                    .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::Protocol);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            if preread.mqtt_clean_start != Some(true) {
                // 跨连接 persistent session 的订阅/QoS2 状态由 broker 持有，本地单连接硬门无法安全重建；
                // 治理 profile 因此只接受 Clean Session/Start，需持久会话时应显式使用透明 TCP profile。
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT governance requires Clean Session/Start");
                state
                    .metrics
                    .inc_stream_mqtt_rejection(gateway::mqtt::MqttViolationKind::Protocol);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
        }
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
        if route.terminate_tls {
            let Some(config) = tls.as_ref() else {
                warn!(stream = %runtime.id, peer = %peer, "stream route TLS termination has no server identity");
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 500, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            };
            // ClientHello 已用于 SNI 权威选路，必须在同一连接内原样回放给 rustls 后再开放
            // 明文上游；直接丢弃会让握手失败，先建上游则会让未认证连接触达业务端口。
            let replay = ReplayStreamIo::new(std::mem::take(&mut preread.bytes), downstream);
            let accept = TlsAcceptor::from(config.load_full()).accept(replay);
            downstream = match tokio::time::timeout(
                Duration::from_millis(runtime.tls_handshake_timeout_ms),
                accept,
            )
            .await
            {
                Ok(Ok(stream)) => Box::new(stream),
                Ok(Err(error)) => {
                    warn!(stream = %runtime.id, peer = %peer, %error, "stream selected-route TLS handshake failed");
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
                Err(_) => {
                    warn!(stream = %runtime.id, peer = %peer, "stream selected-route TLS handshake timeout");
                    state.metrics.inc_stream_error();
                    log_stream_access(&state.access_log, &log_ctx, 408, 0, 0);
                    finish_stream_connection(
                        state.active_connections.clone(),
                        state.metrics.clone(),
                    );
                    return;
                }
            };
        }
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
        // TCP 建连及可选上游 TLS 握手成功已经证明实例可达，应立即清除此前被动失败；后续
        // 会话级 reset/timeout 可能由任一客户端主动关闭触发，不能摘除共享实例并放大为全局故障。
        record_stream_upstream_success(&state, &reservation);
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
        #[cfg(feature = "mqtt-governance")]
        if let Some(policy) = runtime.mqtt.clone() {
            let protocol_level = preread
                .mqtt_protocol_level
                .expect("MQTT governance preread level validated before upstream resolve");
            // CONNECT 是唯一枚在上游建连前已解析的 packet；先精确回放它，后续字节必须全部经状态机。
            if let Err(error) = upstream.write_all(&preread.bytes).await {
                warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, %error, "stream MQTT CONNECT replay failed");
                record_stream_upstream_failure(&state, &reservation);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            let governed = gateway::mqtt::proxy(downstream, upstream, protocol_level, policy);
            let result = if runtime.timeout_ms == 0 {
                governed.await
            } else {
                match tokio::time::timeout(Duration::from_millis(runtime.timeout_ms), governed)
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(stream = %runtime.id, peer = %peer, elapsed_ms = started.elapsed().as_millis(), "stream MQTT session timeout");
                        state.metrics.inc_stream_mqtt_rejection(
                            gateway::mqtt::MqttViolationKind::ResourceLimit,
                        );
                        state.metrics.inc_stream_error();
                        log_stream_access(
                            &state.access_log,
                            &log_ctx,
                            504,
                            preread.bytes.len() as u64,
                            0,
                        );
                        finish_stream_connection(
                            state.active_connections.clone(),
                            state.metrics.clone(),
                        );
                        return;
                    }
                }
            };
            match result {
                Ok(report) => {
                    let down = report
                        .downstream_to_upstream_bytes
                        .saturating_add(preread.bytes.len() as u64);
                    let up = report.upstream_to_downstream_bytes;
                    record_stream_upstream_success(&state, &reservation);
                    state.metrics.add_stream_bytes(down, up);
                    state.metrics.add_stream_mqtt_packets(
                        report.downstream_to_upstream_packets,
                        report.upstream_to_downstream_packets,
                    );
                    log_stream_access(&state.access_log, &log_ctx, 200, down, up);
                    tracing::debug!(
                        stream = %runtime.id,
                        peer = %peer,
                        upstream = %upstream_addr,
                        mqtt_packets_downstream_to_upstream = report.downstream_to_upstream_packets,
                        mqtt_packets_upstream_to_downstream = report.upstream_to_downstream_packets,
                        bytes_downstream_to_upstream = down,
                        bytes_upstream_to_downstream = up,
                        elapsed_ms = started.elapsed().as_millis(),
                        "stream MQTT governed session closed"
                    );
                }
                Err(error) => {
                    let report = error.report();
                    let down = report
                        .downstream_to_upstream_bytes
                        .saturating_add(preread.bytes.len() as u64);
                    let up = report.upstream_to_downstream_bytes;
                    if error.peer() == gateway::mqtt::MqttPeer::Broker {
                        record_stream_upstream_failure(&state, &reservation);
                    }
                    let status = match error.kind() {
                        gateway::mqtt::MqttViolationKind::NotAuthorized => 403,
                        gateway::mqtt::MqttViolationKind::PacketTooLarge => 413,
                        gateway::mqtt::MqttViolationKind::ResourceLimit => 429,
                        gateway::mqtt::MqttViolationKind::Malformed
                        | gateway::mqtt::MqttViolationKind::Protocol => 400,
                    };
                    state.metrics.inc_stream_error();
                    state.metrics.add_stream_bytes(down, up);
                    state.metrics.add_stream_mqtt_packets(
                        report.downstream_to_upstream_packets,
                        report.upstream_to_downstream_packets,
                    );
                    state.metrics.inc_stream_mqtt_rejection(error.kind());
                    log_stream_access(&state.access_log, &log_ctx, status, down, up);
                    warn!(
                        stream = %runtime.id,
                        peer = %peer,
                        upstream = %upstream_addr,
                        mqtt_peer = ?error.peer(),
                        mqtt_violation = %error.kind(),
                        %error,
                        "stream MQTT governance terminated session"
                    );
                }
            }
            finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
            return;
        }
        #[cfg(feature = "kafka-governance")]
        if let Some(policy) = runtime.kafka.clone() {
            // Kafka profile 禁止 preread，确保首枚 request 也必须经过 header/ACL/correlation 状态机。
            debug_assert!(preread.bytes.is_empty());
            let governed = gateway::kafka::proxy(downstream, upstream, policy);
            let result = if runtime.timeout_ms == 0 {
                governed.await
            } else {
                match tokio::time::timeout(Duration::from_millis(runtime.timeout_ms), governed)
                    .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(stream = %runtime.id, peer = %peer, elapsed_ms = started.elapsed().as_millis(), "stream Kafka session timeout");
                        state.metrics.inc_stream_kafka_rejection(
                            gateway::kafka::KafkaViolationKind::ResourceLimit,
                        );
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
                Ok(report) => {
                    record_stream_upstream_success(&state, &reservation);
                    state.metrics.add_stream_bytes(
                        report.downstream_to_upstream_bytes,
                        report.upstream_to_downstream_bytes,
                    );
                    state.metrics.add_stream_kafka_frames(
                        report.downstream_to_upstream_frames,
                        report.upstream_to_downstream_frames,
                    );
                    log_stream_access(
                        &state.access_log,
                        &log_ctx,
                        200,
                        report.downstream_to_upstream_bytes,
                        report.upstream_to_downstream_bytes,
                    );
                    tracing::debug!(
                        stream = %runtime.id,
                        peer = %peer,
                        upstream = %upstream_addr,
                        kafka_frames_downstream_to_upstream = report.downstream_to_upstream_frames,
                        kafka_frames_upstream_to_downstream = report.upstream_to_downstream_frames,
                        elapsed_ms = started.elapsed().as_millis(),
                        "stream Kafka governed session closed"
                    );
                }
                Err(error) => {
                    let report = error.report();
                    if error.peer() == gateway::kafka::KafkaPeer::Broker {
                        record_stream_upstream_failure(&state, &reservation);
                    }
                    let status = match error.kind() {
                        gateway::kafka::KafkaViolationKind::NotAuthorized => 403,
                        gateway::kafka::KafkaViolationKind::FrameTooLarge => 413,
                        gateway::kafka::KafkaViolationKind::ResourceLimit => 429,
                        gateway::kafka::KafkaViolationKind::Malformed
                        | gateway::kafka::KafkaViolationKind::Protocol => 400,
                    };
                    state.metrics.inc_stream_error();
                    state.metrics.add_stream_bytes(
                        report.downstream_to_upstream_bytes,
                        report.upstream_to_downstream_bytes,
                    );
                    state.metrics.add_stream_kafka_frames(
                        report.downstream_to_upstream_frames,
                        report.upstream_to_downstream_frames,
                    );
                    state.metrics.inc_stream_kafka_rejection(error.kind());
                    log_stream_access(
                        &state.access_log,
                        &log_ctx,
                        status,
                        report.downstream_to_upstream_bytes,
                        report.upstream_to_downstream_bytes,
                    );
                    warn!(
                        stream = %runtime.id,
                        peer = %peer,
                        upstream = %upstream_addr,
                        kafka_peer = ?error.peer(),
                        kafka_violation = %error.kind(),
                        %error,
                        "stream Kafka governance terminated session"
                    );
                }
            }
            finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
            return;
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
                // 建连后的双向 relay 错误无法可靠归因于上游；客户端 reset 也会让
                // copy_bidirectional 返回错误，因此这里只终止当前会话，不污染实例健康状态。
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
    /// CONNECT 声明的 MQTT protocol level。
    #[cfg(feature = "mqtt-governance")]
    mqtt_protocol_level: Option<u8>,
    /// CONNECT packet 的精确 wire 长度，用于拒绝未经治理的 pipelined packet。
    #[cfg(feature = "mqtt-governance")]
    mqtt_packet_len: Option<usize>,
    /// CONNECT 的 Clean Session(v3.1.1)/Clean Start(v5) 位。
    #[cfg(feature = "mqtt-governance")]
    mqtt_clean_start: Option<bool>,
    /// 已从下游读取、必须原样写给上游的字节。
    bytes: Vec<u8>,
}

/// 业务作用：根据 TLS preread SNI 或 MQTT client id 选择唯一 stream route，保证精确
/// SNI 优先于 wildcard，且更长的 wildcard suffix 优先，避免流量落入宽泛租户路由。
///
/// 参数说明：`runtime` 是当前 stream listener 快照；`sni` 与 `mqtt_client_id` 来自有界 preread。
///
/// 返回：返回优先级最高的匹配路由；没有显式匹配时返回 default，仍无匹配则拒绝连接。
fn select_stream_route<'a>(
    runtime: &'a StreamRuntime,
    sni: Option<&str>,
    mqtt_client_id: Option<&str>,
) -> Option<&'a gateway::config::StreamRouteRuntime> {
    let sni = sni.map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase());
    if let Some(sni) = sni.as_deref() {
        if let Some(route) = select_stream_sni_route(&runtime.routes, sni) {
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

/// 业务作用：按 Gateway API hostname 语义匹配 stream SNI，并固定 exact、最长 wildcard
/// suffix 的优先顺序，避免配置顺序改变实际后端。
///
/// 参数说明：`routes` 是同一 listener 的已验证 route；`sni` 是规范化的小写 hostname。
///
/// 返回：精确路由存在时返回精确路由；否则返回最具体 wildcard；没有匹配时返回 None。
fn select_stream_sni_route<'a>(
    routes: &'a [gateway::config::StreamRouteRuntime],
    sni: &str,
) -> Option<&'a gateway::config::StreamRouteRuntime> {
    routes
        .iter()
        .find(|route| route.sni.as_deref() == Some(sni))
        .or_else(|| {
            routes
                .iter()
                .filter(|route| {
                    route
                        .sni
                        .as_deref()
                        .is_some_and(|pattern| stream_sni_matches(pattern, sni))
                })
                .max_by_key(|route| route.sni.as_deref().map_or(0, str::len))
        })
}

/// 业务作用：判断 stream route 的 Gateway API suffix wildcard 是否覆盖实际 SNI，且不把
/// `*.example.com` 错误扩展到 apex `example.com`。
///
/// 参数说明：`pattern` 是已小写化的 route SNI；`sni` 是已小写化的 ClientHello SNI。
///
/// 返回：精确或合法 `*.` suffix 匹配时返回 true，其余模式与 apex 返回 false。
fn stream_sni_matches(pattern: &str, sni: &str) -> bool {
    if pattern == sni {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    !suffix.is_empty()
        && sni.len() > suffix.len()
        && sni.ends_with(suffix)
        && sni.as_bytes().get(sni.len() - suffix.len() - 1) == Some(&b'.')
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

/// 业务作用：在上游连接或 TLS 握手成功后清除 stream 被动健康失败，避免客户端后续断开误伤共享实例。
///
/// 参数说明：`state` 是 stream 数据面共享状态；`reservation` 是本次选中的上游 reservation。
///
/// 返回：无返回值；逻辑服务目标会更新被动健康状态，直连目标不产生副作用。
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

/// 业务作用：为 stream route 选择带权逻辑目标和健康实例，并登记连接级负载均衡 reservation。
///
/// 参数说明：`snap` 是当前配置快照；`route` 是已匹配路由；`stream_lb` 保存游标、失败与在途状态；
/// `active_health` 提供主动健康排除集合。
///
/// 返回：目标可解析且存在健康实例时返回必须在连接结束时释放的 reservation；引用缺失、
/// 地址非法或没有健康实例时返回错误且不建立上游连接。
fn resolve_stream_upstream(
    snap: &GatewaySnapshot,
    route: &StreamRouteRuntime,
    stream_lb: &StreamLbState,
    active_health: &gateway::health::ActiveHealthChecker,
) -> Result<StreamUpstreamReservation> {
    let target = select_weighted_stream_upstream(route, stream_lb);
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

/// 业务作用：按 Gateway API backendRef 权重为每条 TCP 连接或 UDP session 选择逻辑上游，
/// 并让零权重后端永不进入数据面。
///
/// 参数说明：`route` 是不可变路由快照；`stream_lb` 持有跨 reload 单调游标。
///
/// 返回：带权集合非空时返回按累计权重命中的目标；否则返回兼容单一 `upstream`。
fn select_weighted_stream_upstream<'a>(
    route: &'a StreamRouteRuntime,
    stream_lb: &StreamLbState,
) -> &'a str {
    if route.weighted_upstreams.is_empty() {
        return route.upstream.as_str();
    }
    let total = route
        .weighted_upstreams
        .iter()
        .map(|(_, weight)| u64::from(*weight))
        .sum::<u64>();
    debug_assert!(total > 0);
    let mut ticket = stream_lb.next_rr(&route.id) % total;
    for (upstream, weight) in route.weighted_upstreams.iter() {
        let weight = u64::from(*weight);
        if ticket < weight {
            return upstream.as_str();
        }
        ticket -= weight;
    }
    unreachable!("validated stream backend weights must cover the selection ticket")
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

/// 业务作用：有界 preread 首个 MQTT CONNECT，为 client-id 路由和可选协议治理提供
/// 版本/精确 packet 边界；原始 wire 仅在选定上游后回放。
///
/// 参数说明：`downstream` 是已完成 PROXY/TLS 的下游流；`timeout_ms` 是整个 CONNECT deadline；
/// `max_bytes` 是 preread 累计硬门。
///
/// 返回：完整合法 CONNECT 的 client id、level、packet 长度和已读 wire；慢包、超长、截断或
/// 畸形 CONNECT 返回错误，不连接上游。
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
                MqttConnectParse::Complete(info) => {
                    return Ok(StreamPrereadResult {
                        sni: None,
                        mqtt_client_id: Some(info.client_id.to_owned()),
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_protocol_level: Some(info.protocol_level),
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_packet_len: Some(info.packet_len),
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_clean_start: Some(info.clean_start),
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
    Complete(MqttConnectInfo<'a>),
}

/// CONNECT preread 只借用当前有界 buffer 的解析结果。
struct MqttConnectInfo<'a> {
    client_id: &'a str,
    #[cfg(feature = "mqtt-governance")]
    protocol_level: u8,
    #[cfg(feature = "mqtt-governance")]
    packet_len: usize,
    #[cfg(feature = "mqtt-governance")]
    clean_start: bool,
}

/// 业务作用：解析 MQTT 3.1/3.1.1/5 CONNECT 的协议名、level、flags、properties 边界与 client id，
/// 防止畸形长度被误当 default route。
///
/// 参数说明：`bytes` 是从连接起始累积的有界 preread buffer。
///
/// 返回：字段尚未到齐时 NeedMore；完整时返回借用 client id、level 和 CONNECT wire 终点；
/// 非 CONNECT、非法 VBI/flags/protocol/UTF-8 返回错误。
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
    anyhow::ensure!(
        !(flags & 0x04 != 0 && flags & 0x18 == 0x18),
        "MQTT will QoS must not be 3"
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
    if flags & 0x04 != 0 {
        if level == 5 {
            let Some((properties_len, next)) = decode_mqtt_variable_byte_integer(bytes, cursor)?
            else {
                return Ok(MqttConnectParse::NeedMore);
            };
            cursor = next
                .checked_add(properties_len)
                .context("MQTT will properties length overflow")?;
            anyhow::ensure!(
                cursor <= packet_end,
                "MQTT will properties exceed CONNECT packet"
            );
        }
        let _will_topic = mqtt_utf8(bytes, &mut cursor, packet_end)?;
        let _will_payload = mqtt_binary(bytes, &mut cursor, packet_end)?;
    }
    if flags & 0x80 != 0 {
        let _username = mqtt_utf8(bytes, &mut cursor, packet_end)?;
    }
    if flags & 0x40 != 0 {
        let _password = mqtt_binary(bytes, &mut cursor, packet_end)?;
    }
    anyhow::ensure!(
        cursor == packet_end,
        "MQTT CONNECT contains trailing payload bytes"
    );
    Ok(MqttConnectParse::Complete(MqttConnectInfo {
        client_id,
        #[cfg(feature = "mqtt-governance")]
        protocol_level: level,
        #[cfg(feature = "mqtt-governance")]
        packet_len: packet_end,
        #[cfg(feature = "mqtt-governance")]
        clean_start: flags & 0x02 != 0,
    }))
}

/// 业务作用：有界解码 MQTT Variable Byte Integer，不让恶意 continuation 制造溢出或无界等待。
///
/// 参数说明：`bytes` 是 preread buffer；`start` 是 VBI 起始偏移。
///
/// 返回：完整时返回 `(value,next_cursor)`，字节未到齐返回 None，超四字节/溢出返回错误。
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
            anyhow::ensure!(
                mqtt_variable_integer_len(value) == offset + 1,
                "MQTT variable integer is not minimally encoded"
            );
            return Ok(Some((value, index + 1)));
        }
        multiplier = multiplier.saturating_mul(128);
    }
    anyhow::bail!("MQTT variable integer exceeds four bytes")
}

/// 业务作用：计算 MQTT Variable Byte Integer 唯一最短编码长度，供 preread 拒绝非 canonical 长度。
///
/// 参数说明：`value` 是已有界解码的非负整数。
///
/// 返回：编码该值需要的 1–4 字节数。
fn mqtt_variable_integer_len(mut value: usize) -> usize {
    let mut length = 1;
    while value >= 128 {
        value /= 128;
        length += 1;
    }
    length
}

/// 业务作用：从 CONNECT packet 边界内读取两字节长度前缀的 UTF-8 字段。
///
/// 参数说明：`bytes` 是 preread buffer；`cursor` 会移到字段末尾；`end` 是 CONNECT 精确终点。
///
/// 返回：边界内的借用 UTF-8 字符串；长度越界或非 UTF-8 返回错误。
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
    let value =
        std::str::from_utf8(&bytes[length_end..value_end]).context("MQTT field is not UTF-8")?;
    anyhow::ensure!(
        !value.chars().any(|character| {
            character == '\0'
                || matches!(character as u32, 0xfdd0..=0xfdef)
                || character as u32 & 0xffff == 0xfffe
                || character as u32 & 0xffff == 0xffff
        }),
        "MQTT UTF-8 field contains a forbidden code point"
    );
    Ok(value)
}

/// 业务作用：在 CONNECT 精确 packet 边界内跳过 will/password 二进制字段，不复制敏感内容。
///
/// 参数说明：`bytes` 是 preread buffer；`cursor` 会移到字段末尾；`end` 是 CONNECT 终点。
///
/// 返回：边界内的借用 binary 切片；长度截断或溢出返回错误。
fn mqtt_binary<'a>(bytes: &'a [u8], cursor: &mut usize, end: usize) -> Result<&'a [u8]> {
    let length_end = cursor
        .checked_add(2)
        .context("MQTT binary length overflow")?;
    anyhow::ensure!(length_end <= end, "MQTT binary field missing length");
    let length = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
    let value_end = length_end
        .checked_add(length)
        .context("MQTT binary field overflow")?;
    anyhow::ensure!(value_end <= end, "MQTT binary field exceeds CONNECT packet");
    *cursor = value_end;
    Ok(&bytes[length_end..value_end])
}

/// 业务作用：有界 preread TLS ClientHello 并只提取 SNI，为 passthrough route 选择上游，
/// 不终止 TLS 也不消费需回放的原始 wire。
///
/// 参数说明：`downstream` 是下游 TCP 字节流；`timeout_ms` 是整个 preread deadline，0 表示
/// 不限制；`max_bytes` 是 ClientHello 累计读取硬门。
///
/// 返回：解析到的可选 SNI 和必须回放给上游的原始字节；读取 IO/deadline 失败返回错误。
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
                    #[cfg(feature = "mqtt-governance")]
                    mqtt_protocol_level: None,
                    #[cfg(feature = "mqtt-governance")]
                    mqtt_packet_len: None,
                    #[cfg(feature = "mqtt-governance")]
                    mqtt_clean_start: None,
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
                    #[cfg(feature = "mqtt-governance")]
                    mqtt_protocol_level: None,
                    #[cfg(feature = "mqtt-governance")]
                    mqtt_packet_len: None,
                    #[cfg(feature = "mqtt-governance")]
                    mqtt_clean_start: None,
                    bytes,
                });
            }
            bytes.extend_from_slice(&buf[..n]);
            match parse_tls_client_hello_sni(bytes.as_slice()) {
                TlsSniParse::Complete(sni) => {
                    return Ok(StreamPrereadResult {
                        sni,
                        mqtt_client_id: None,
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_protocol_level: None,
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_packet_len: None,
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_clean_start: None,
                        bytes,
                    })
                }
                TlsSniParse::NeedMore => continue,
                TlsSniParse::NotTls => {
                    return Ok(StreamPrereadResult {
                        sni: None,
                        mqtt_client_id: None,
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_protocol_level: None,
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_packet_len: None,
                        #[cfg(feature = "mqtt-governance")]
                        mqtt_clean_start: None,
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
    listener: Option<TcpListener>,
    tls: Option<BoundTlsProxy>,
    #[cfg(feature = "http3")]
    http3: Option<BoundHttp3Proxy>,
}

/// prepare 阶段已经完整构建、等待 commit 激活的 HTTP/3 endpoint。
#[cfg(feature = "http3")]
struct BoundHttp3Proxy {
    /// 与 TLS TCP listener 相同的逻辑地址/端口，仅 transport 为 UDP。
    listen: SocketAddr,
    /// 已绑定 UDP 但 server config 为空的候选；commit 前不会抢旧 generation 的 QUIC Initial。
    endpoint: gateway::http3::PreparedServerEndpoint,
    /// 与 endpoint 同版的 HTTP/3 运行计划。
    runtime: gateway::config::Http3RuntimeCfg,
}

struct BoundTlsProxy {
    listen: SocketAddr,
    listener: TcpListener,
    /// watcher/延迟激活共用的完整 TLS 材料来源。
    runtime: gateway::config::TlsRuntimeCfg,
    mode: BoundTlsMode,
}

/// TLS listener 启动形态：已有 keypair 立即 accept，或 ACME 首签后在同进程激活。
enum BoundTlsMode {
    /// 启动期已构建可用 rustls 配置。
    Ready(SharedServerConfig),
    /// socket 已绑定，但 cert/key 尚不存在；后台检测到完整 keypair 后才开始 accept。
    Deferred,
}

struct BoundStream {
    runtime: StreamRuntime,
    listen: SocketAddr,
    socket: BoundStreamSocket,
    /// prepare 只构建 TLS；文件 watcher 要等 generation commit 后再启动。
    tls: Option<BoundStreamTls>,
}

struct BoundStreamTls {
    runtime: gateway::config::TlsRuntimeCfg,
    config: SharedServerConfig,
}

enum BoundStreamSocket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

struct ActiveListenerGeneration {
    topology: ProxyListenTopology,
    stop: watch::Sender<bool>,
}

struct ActiveAdminGeneration {
    listen: SocketAddr,
    stop: watch::Sender<bool>,
}

/// 数据面 listener supervisor。所有可能失败的 bind/TLS build 都在 reload 的 prepare
/// 阶段完成；active map 仅在 commit 的短临界区替换 stop handle，不持锁执行 I/O。
#[derive(Clone)]
struct ListenerSupervisor {
    active: Arc<Mutex<HashMap<String, ActiveListenerGeneration>>>,
    active_admin: Arc<Mutex<Option<ActiveAdminGeneration>>>,
    active_acme: Arc<Mutex<Option<gateway::acme::AcmeWorkerGeneration>>>,
    active_acme_runtime_signature: Arc<Mutex<String>>,
    data_plane: DataPlaneState,
    stream_plane: StreamPlaneState,
    admin_state: Arc<admin::AdminState>,
    acme_http01: Arc<gateway::acme::Http01ChallengeStore>,
    manages_data: bool,
    deferred_tls: DeferredTlsReadiness,
}

struct PreparedListenerSwitch {
    supervisor: ListenerSupervisor,
    candidate_topologies: HashMap<String, ProxyListenTopology>,
    proxies: Vec<BoundProxy>,
    streams: Vec<BoundStream>,
    admin: Option<(SocketAddr, TcpListener)>,
    acme: Option<(gateway::acme::PreparedAcmeWorkers, String)>,
    removed: Vec<String>,
}

impl ListenerSupervisor {
    /// 业务作用：创建统一管理 data、stream、admin listener 与 ACME worker generation 的两阶段协调器。
    ///
    /// 参数说明：`data_plane`/`stream_plane` 是 accept loop 共享状态；`admin_state` 是管理面状态；
    /// `acme_http01` 是 challenge 事实表；`manages_data` 区分 admin-only 进程；`deferred_tls`
    /// 共同约束无 seed TLS 的就绪发布。
    ///
    /// 返回：返回尚未接管任何 listener generation 的 supervisor。
    fn new(
        data_plane: DataPlaneState,
        stream_plane: StreamPlaneState,
        admin_state: Arc<admin::AdminState>,
        acme_http01: Arc<gateway::acme::Http01ChallengeStore>,
        manages_data: bool,
        deferred_tls: DeferredTlsReadiness,
    ) -> Self {
        Self {
            active: Arc::new(Mutex::new(HashMap::new())),
            active_admin: Arc::new(Mutex::new(None)),
            active_acme: Arc::new(Mutex::new(None)),
            active_acme_runtime_signature: Arc::new(Mutex::new(String::new())),
            data_plane,
            stream_plane,
            admin_state,
            acme_http01,
            manages_data,
            deferred_tls,
        }
    }

    /// 业务作用：激活启动期已经绑定完成的 listener，并把每组 accept loop 收口到独立 stop channel。
    ///
    /// 参数说明：`snapshot` 提供已验证拓扑及 ACME 锁连接签名；`proxies`/`streams`/`admin_listener`
    /// 是启动前绑定资源；`admin_listen` 是规范化管理地址；`acme` 是不含签发副作用的候选 worker。
    ///
    /// 返回：返回 proxy 与 stream 的低基数启动摘要；所有 generation 已归 supervisor 管理。
    fn install_initial(
        &self,
        snapshot: &GatewaySnapshot,
        proxies: Vec<BoundProxy>,
        streams: Vec<BoundStream>,
        admin_listener: TcpListener,
        admin_listen: SocketAddr,
        acme: Option<gateway::acme::PreparedAcmeWorkers>,
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
        self.activate_admin(admin_listener, admin_listen);
        if let Some(acme) = acme {
            self.activate_acme(
                acme,
                gateway::runtime_state::rate_limiter_config_signature(&snapshot.runtime_state),
            );
        }
        (proxy_log, stream_log)
    }

    /// 业务作用：先启动候选管理面 generation，再停止旧 accept 并让既有连接优雅 drain。
    ///
    /// 参数说明：`listener` 是 prepare 完成的 socket；`listen` 是规范化地址摘要。
    ///
    /// 返回：无返回值；候选启动不再含可失败 I/O，旧代只在新代获得任务所有权后停止。
    fn activate_admin(&self, listener: TcpListener, listen: SocketAddr) {
        let (stop, stop_rx) = watch::channel(false);
        tokio::spawn(admin::serve_until(
            listener,
            self.admin_state.clone(),
            stop_rx,
        ));
        let old = self
            .active_admin
            .lock()
            .expect("admin listener supervisor poisoned")
            .replace(ActiveAdminGeneration { listen, stop });
        if let Some(old) = old {
            // 新管理面已经持有监听任务后才撤销旧代，避免热换窗口失去 /readyz 与配置控制面。
            let _ = old.stop.send(true);
        }
    }

    /// 业务作用：激活候选 ACME worker generation，并立即撤销旧代签发权威。
    ///
    /// 参数说明：`prepared` 已在快照发布前完成 provider 与锁后端初始化；
    /// `runtime_signature` 记录本代锁连接参数，供后续 reload 判定是否必须重建。
    ///
    /// 返回：无返回值；旧代取消会触发 challenge lease 清理，新代成为唯一续期所有者。
    fn activate_acme(
        &self,
        prepared: gateway::acme::PreparedAcmeWorkers,
        runtime_signature: String,
    ) {
        let count = prepared.len();
        let next = prepared.activate();
        let old = self
            .active_acme
            .lock()
            .expect("ACME worker supervisor poisoned")
            .replace(next);
        *self
            .active_acme_runtime_signature
            .lock()
            .expect("ACME runtime signature poisoned") = runtime_signature;
        drop(old);
        if count > 0 {
            info!(
                workers = count,
                "ACME certificate worker generation activated"
            );
        }
    }

    /// 激活一组已经 prepare 成功的 HTTP/TLS/HTTP3 listener。
    ///
    /// 业务作用：先启动候选 generation 的全部 accept loop，再原子替换 stop handle 并停收旧
    /// generation，保证 reload 不出现 TCP 已换版但 QUIC 仍指向旧治理快照的半切换状态。
    ///
    /// 参数说明：`bound` 持有已绑定 socket/endpoint；`topology` 是与候选快照同版的比较摘要。
    ///
    /// 返回：用于启动日志的 listener 地址列表。
    fn activate_proxy(&self, bound: BoundProxy, topology: ProxyListenTopology) -> Vec<String> {
        let key = topology.id.clone();
        let (stop, stop_rx) = watch::channel(false);
        let proxy_id: Arc<str> = Arc::from(bound.id.clone());
        let mut log = Vec::new();
        #[cfg(feature = "http3")]
        let http3 = bound.http3.map(|http3| {
            let endpoint = http3.endpoint.activate();
            (http3.listen, http3.runtime, endpoint)
        });
        #[cfg(feature = "http3")]
        let mut http3_certificate_updates = None;
        if let Some(listener) = bound.listener {
            log.push(format!("{}@{}", bound.id, bound.listen));
            spawn_plain_accept_loop(
                listener,
                proxy_id.clone(),
                self.data_plane.clone(),
                stop_rx.clone(),
            );
        }
        if let Some(tls) = bound.tls {
            match tls.mode {
                BoundTlsMode::Ready(config) => {
                    log.push(format!("{}@{}(tls)", bound.id, tls.listen));
                    if tls.runtime.in_memory.is_none() {
                        // 文件 watcher 只能在 commit 后启动；prepare 中启动会让失败候选泄漏后台
                        // task。SDS 材料随 Snapshot generation 原子切换，不创建文件 watcher。
                        spawn_cert_watcher_until(
                            tls.runtime.clone(),
                            config.clone(),
                            stop_rx.clone(),
                        );
                        #[cfg(feature = "http3")]
                        if let Some((_, runtime, _)) = &http3 {
                            http3_certificate_updates = Some(gateway::http3::spawn_cert_watcher(
                                tls.runtime.clone(),
                                runtime.clone(),
                                stop_rx.clone(),
                            ));
                        }
                    }
                    spawn_tls_accept_loop(
                        tls.listener,
                        proxy_id.clone(),
                        config,
                        self.data_plane.clone(),
                        stop_rx.clone(),
                    );
                }
                BoundTlsMode::Deferred => {
                    log.push(format!("{}@{}(tls-pending)", bound.id, tls.listen));
                    // 候选快照已声明 TLS 能力但证书尚未就绪；在任务启动前先关闭 readiness，
                    // 防止新 generation 只开放 challenge/明文半边时被前置 LB 当成完整节点。
                    self.deferred_tls.ready.store(false, Ordering::Release);
                    self.deferred_tls.pending.fetch_add(1, Ordering::AcqRel);
                    spawn_deferred_tls_accept_loop(
                        tls.listener,
                        proxy_id.clone(),
                        tls.runtime,
                        self.data_plane.clone(),
                        stop_rx.clone(),
                        self.deferred_tls.clone(),
                    );
                }
            }
        }
        #[cfg(feature = "http3")]
        if let Some((listen, runtime, endpoint)) = http3 {
            log.push(format!("{}@{}(h3/udp)", bound.id, listen));
            spawn_http3_accept_loop(
                endpoint,
                runtime,
                http3_certificate_updates
                    .expect("HTTP/3 listener always has a ready TLS certificate watcher"),
                proxy_id,
                self.data_plane.clone(),
                stop_rx,
            );
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

    /// 业务作用：激活已 prepare 的 L4 listener，并在新代持有 accept 权后停止同标识旧代。
    ///
    /// 参数说明：`bound` 持有候选 socket/TLS 材料；`topology` 是与候选快照同版的比较摘要。
    ///
    /// 返回：返回用于启动日志的 listener 地址摘要。
    fn activate_stream(&self, bound: BoundStream, topology: ProxyListenTopology) -> String {
        let key = topology.id.clone();
        let tls_enabled = bound.tls.is_some();
        let log = format!(
            "{}@{}{}",
            bound.runtime.id,
            bound.listen,
            if tls_enabled { "(tls)" } else { "" }
        );
        let (stop, stop_rx) = watch::channel(false);
        let tls = bound.tls.map(|tls| {
            spawn_cert_watcher_until(tls.runtime, tls.config.clone(), stop_rx.clone());
            tls.config
        });
        match bound.socket {
            BoundStreamSocket::Tcp(listener) => spawn_stream_accept_loop(
                listener,
                bound.runtime,
                tls,
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

    /// 业务作用：在候选 generation 全部激活后停收已从新快照删除的 listener。
    ///
    /// 参数说明：`keys` 是 prepare 阶段基于旧/新拓扑差集冻结的 listener 标识。
    ///
    /// 返回：无返回值；既有连接仍独立持有 IO 并按正常 drain 规则结束。
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

    /// 业务作用：撤销进程内全部 listener 与 ACME generation 的新增工作权，并保持 readiness 关闭。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；已建立连接继续由全局 drain 预算管理。
    fn shutdown(&self) {
        // 停机事实必须先于取消 deferred TLS；否则最后一个 RAII guard 退出会短暂重开 readiness。
        self.deferred_tls.stopping.store(true, Ordering::Release);
        self.deferred_tls.ready.store(false, Ordering::Release);
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
        if let Some(admin) = self
            .active_admin
            .lock()
            .expect("admin listener supervisor poisoned")
            .take()
        {
            let _ = admin.stop.send(true);
        }
        self.active_acme
            .lock()
            .expect("ACME worker supervisor poisoned")
            .take();
    }
}

impl gateway::reload::ListenerTopologyReconciler for ListenerSupervisor {
    /// 业务作用：完成 data/stream/admin socket、TLS 材料和 ACME provider/锁的候选期准备。
    ///
    /// 参数说明：`candidate` 是尚未发布且已完成语义校验的完整快照。
    ///
    /// 返回：全部可失败资源就绪时返回切换事务；任一 bind/build/connect 失败则保留所有在线代。
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
            let candidate_topologies = if self.manages_data {
                candidate
                    .listen_topology()
                    .into_iter()
                    .map(|topology| (topology.id.clone(), topology))
                    .collect::<HashMap<_, _>>()
            } else {
                HashMap::new()
            };
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
            let acme_changed = changed.iter().chain(removed.iter()).any(|id| {
                current_topologies.get(id).is_some_and(topology_uses_acme)
                    || candidate_topologies.get(id).is_some_and(topology_uses_acme)
            }) || (candidate_topologies.values().any(topology_uses_acme)
                && *self
                    .active_acme_runtime_signature
                    .lock()
                    .expect("ACME runtime signature poisoned")
                    != gateway::runtime_state::rate_limiter_config_signature(
                        &candidate.runtime_state,
                    ));

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
            let candidate_admin: SocketAddr = candidate
                .admin_listen
                .parse()
                .with_context(|| format!("invalid admin.listen `{}`", candidate.admin_listen))?;
            let current_admin = self
                .active_admin
                .lock()
                .expect("admin listener supervisor poisoned")
                .as_ref()
                .map(|active| active.listen)
                .context("admin listener generation is missing")?;
            let admin = if candidate_admin != current_admin {
                Some((
                    candidate_admin,
                    TcpListener::bind(candidate_admin).await.with_context(|| {
                        format!("bind candidate admin.listen {candidate_admin}")
                    })?,
                ))
            } else {
                None
            };
            let acme = if acme_changed {
                Some((
                    gateway::acme::prepare_acme_workers(
                        candidate
                            .proxies
                            .iter()
                            .filter_map(|proxy| proxy.tls.clone()),
                        candidate.runtime_state.clone(),
                        self.acme_http01.clone(),
                    )
                    .await
                    .context("prepare candidate ACME worker generation")?,
                    gateway::runtime_state::rate_limiter_config_signature(&candidate.runtime_state),
                ))
            } else {
                None
            };
            Ok(Box::new(PreparedListenerSwitch {
                supervisor: self.clone(),
                candidate_topologies,
                proxies,
                streams,
                admin,
                acme,
                removed,
            })
                as Box<dyn gateway::reload::PreparedListenerTopology>)
        })
    }
}

impl gateway::reload::PreparedListenerTopology for PreparedListenerSwitch {
    /// 业务作用：在候选快照已发布后交接 listener 与签发权威，先开放新代再停收旧代。
    ///
    /// 参数说明：无；事务自身持有 prepare 成功的候选资源和旧/新差集。
    ///
    /// 返回：无返回值；commit 不执行可失败外部初始化，旧连接继续优雅 drain。
    fn commit(mut self: Box<Self>) {
        if let Some((listen, listener)) = self.admin.take() {
            self.supervisor.activate_admin(listener, listen);
        }
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
        if let Some((acme, runtime_signature)) = self.acme.take() {
            // 候选 listener 已启动且快照已经发布，此时交接 worker 权威；旧 challenge 会在取消分支清理。
            self.supervisor.activate_acme(acme, runtime_signature);
        }
        self.supervisor.stop_removed(self.removed.as_slice());
    }
}

/// 业务作用：为 TCP/UDP stream listener 生成跨 reload 稳定且不会协议碰撞的 supervisor 标识。
///
/// 参数说明：`stream` 是已编译的 L4 listener 运行配置。
///
/// 返回：返回包含业务 id 与 transport 的内部 key。
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

/// 业务作用：判断 listener 拓扑是否依赖 ACME worker，用于限定签发代际重建范围。
///
/// 参数说明：`topology` 是当前或候选 proxy listener 摘要。
///
/// 返回：TLS 配置含 ACME 时返回 true，否则返回 false。
fn topology_uses_acme(topology: &ProxyListenTopology) -> bool {
    topology.tls.as_ref().is_some_and(|tls| tls.acme.is_some())
}

/// L4 payload transport abstraction. Boxing costs one allocation per accepted connection, not per
/// frame; `copy_bidirectional` still moves fixed-size chunks with bounded memory and never buffers
/// an application message. It keeps the TCP/TLS combinations out of four duplicated proxy loops.
trait StreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> StreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxStreamIo = Box<dyn StreamIo>;

/// 在不复制后续载荷的前提下，将 preread 字节先回放给协议栈，再继续读取真实下游连接。
struct ReplayStreamIo {
    /// 尚未回放完的有界 preread 缓冲。
    prefix: Vec<u8>,
    /// 下一次回放位置。
    offset: usize,
    /// preread 后的真实下游 IO。
    inner: BoxStreamIo,
}

impl ReplayStreamIo {
    /// 业务作用：把已消费的 ClientHello 与原连接重新拼成连续 TLS 字节流。
    ///
    /// 参数说明：`prefix` 是有界 preread 字节；`inner` 是读取位置已经越过该前缀的连接。
    ///
    /// 返回：返回从前缀起始位置读取、写操作直达原连接的 IO wrapper。
    fn new(prefix: Vec<u8>, inner: BoxStreamIo) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl AsyncRead for ReplayStreamIo {
    /// 业务作用：优先回放 preread 前缀，耗尽后无缝转交真实连接读取。
    ///
    /// 参数说明：`cx` 与 `buf` 遵循 Tokio `AsyncRead` 契约。
    ///
    /// 返回：前缀或真实连接产生数据时返回 Ready；底层等待时返回 Pending。
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let count = buf.remaining().min(this.prefix.len() - this.offset);
            buf.put_slice(&this.prefix[this.offset..this.offset + count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayStreamIo {
    /// 业务作用：将 TLS 握手及后续响应直接写回原连接，不经过 preread 缓冲。
    ///
    /// 参数说明：`cx` 与 `buf` 遵循 Tokio `AsyncWrite` 契约。
    ///
    /// 返回：透传底层写入进度或错误。
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    /// 业务作用：刷新原连接的待发送 TLS 记录。
    ///
    /// 参数说明：`cx` 遵循 Tokio `AsyncWrite` 契约。
    ///
    /// 返回：透传底层刷新结果。
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    /// 业务作用：关闭原连接的写半部，保持 TLS shutdown 的传输语义。
    ///
    /// 参数说明：`cx` 遵循 Tokio `AsyncWrite` 契约。
    ///
    /// 返回：透传底层关闭结果。
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 业务作用：完成 Naway 进程 bootstrap、控制面/数据面装配、readiness 开放与有序停机。
///
/// 参数说明：无；CLI 与环境变量由 `Args`/配置加载器读取。
///
/// 返回：全部启动与停机步骤成功时返回成功；bootstrap 或不可恢复运行错误返回失败退出。
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
    if run_mode.is_sidecar() {
        // sidecar 的本地边界必须在打开任何外部资源前成立；失败直接退出，不能先短暂暴露端口。
        snapshot
            .validate_sidecar_listeners()
            .context("validate sidecar listener isolation")?;
    }
    // 审计 hash-chain/client 是 bootstrap 资源；启动时完整验旧 spool，篡改或 endpoint 配置错误均 fail-fast。
    let admin_audit = gateway::admin_audit::AdminAuditLog::open(&snapshot.admin_audit)
        .context("open admin audit log")?;
    // 日志仍由 nasa::log 统一格式化/滚动/热调级；OTel layer 同挂一个 tracing subscriber，
    // 避免两个全局 subscriber 争用。必须先读 bootstrap telemetry 配置再一次性初始化。
    let telemetry_generation = gateway::telemetry::TelemetryRuntime::build(&snapshot.telemetry)
        .context("build OpenTelemetry runtime")?;
    nasa::log::init_with_default_and_layer(
        "gateway=info,info",
        tracing_opentelemetry::layer().with_tracer(telemetry_generation.tracer()),
    );
    let telemetry = gateway::telemetry::SwappableTelemetryRuntime::new(telemetry_generation);
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
    let http_cache_generation =
        gateway::http_cache::HttpCacheRuntime::build(&runtime_state_cfg.http_cache)
            .await
            .context("build HTTP cache runtime")?;
    let http_cache = gateway::http_cache::SwappableHttpCacheRuntime::new(http_cache_generation);
    let snap = Arc::new(ArcSwap::from_pointee(snapshot));
    let apply_coordinator = Arc::new(reload::SnapshotApplyCoordinator::default());
    // xDS 状态句柄先接入 admin/readiness，网络 task 等 listener supervisor 建好后才启动；
    // 后续 reload 继续复用该句柄并由 generation manager 撤销旧 owner。
    #[cfg(feature = "xds-client")]
    let xds_bootstrap = if run_mode.runs_data() && snap.load().control_plane.xds.enabled {
        let initial = snap.load();
        let specs = initial.upstreams.xds_watch_specs();
        let xds_cfg = initial.control_plane.xds.clone();
        drop(initial);
        Some((xds_cfg, specs))
    } else {
        None
    };
    #[cfg(feature = "xds-client")]
    let xds_status = run_mode.runs_data().then(gateway::xds::new_status);
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
    // 监听在启动期绑定，失败即 fatal；健康端点是容器部署关键依赖，不能静默缺席。
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
            audit: admin_audit.clone(),
            #[cfg(feature = "xds-client")]
            xds_status: xds_status.clone(),
        },
    );
    // V8:proxy 构造在 admin serve 之后,提前留一份句柄以便把边缘订阅索引注入
    // /metrics 渲染;未编 feature 时零残留。
    #[cfg(feature = "grpc-edge")]
    let admin_state_for_edge = admin_state.clone();

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
    #[cfg(feature = "grpc-edge")]
    admin_state_for_edge.attach_edge_relay_slot(proxy.edge_relay_slot());
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    admin_state_for_edge.attach_edge_redis_bus_slot(proxy.edge_redis_bus_slot());
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    admin_state_for_edge.attach_edge_redis_stream_slot(proxy.edge_redis_stream_slot());
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
                        proxy.attach_edge_redis_bus(bus);
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
                        proxy.attach_edge_redis_stream(bus);
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
        #[cfg(feature = "http3")]
        http3_peer_connection_budget: Arc::new(Http3PeerConnectionBudget::default()),
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
        #[cfg(feature = "mqtt-governance")]
        mqtt_connections: MqttConnectionBudget::default(),
        #[cfg(feature = "kafka-governance")]
        kafka_connections: KafkaConnectionBudget::default(),
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

    let deferred_tls = DeferredTlsReadiness {
        pending: Arc::new(AtomicU64::new(0)),
        ready: ready.clone(),
        stopping: Arc::new(AtomicBool::new(false)),
    };
    // ACME 的 provider 与分布式锁也属于候选资源：启动 generation 前完整 prepare，避免 listener
    // 已开放后才发现续期权威不可用。真正签发任务要等 HTTP listener 激活后再启动。
    let initial_acme = if run_mode.runs_data() {
        Some(
            gateway::acme::prepare_acme_workers(
                initial_proxies.iter().filter_map(|proxy| proxy.tls.clone()),
                runtime_state_cfg.clone(),
                proxy.acme_http01_store(),
            )
            .await
            .context("prepare initial ACME workers")?,
        )
    } else {
        None
    };
    let listener_supervisor = Arc::new(ListenerSupervisor::new(
        data_plane,
        stream_plane,
        admin_state,
        proxy.acme_http01_store(),
        run_mode.runs_data(),
        deferred_tls.clone(),
    ));
    let initial_snapshot = snap.load_full();
    let (proxy_log, stream_log) = listener_supervisor.install_initial(
        initial_snapshot.as_ref(),
        bound_proxies,
        bound_streams,
        admin_listener,
        admin_listen,
        initial_acme,
    );
    drop(initial_snapshot);

    #[cfg(feature = "xds-client")]
    let xds_manager = if run_mode.runs_data() {
        let manager = gateway::xds::XdsGenerationManager::new(
            dynamic_upstreams.clone(),
            gateway::xds::XdsSnapshotRuntime {
                snap: snap.clone(),
                version: version.clone(),
                apply_coordinator: apply_coordinator.clone(),
                cfg_path: cfg_path.clone(),
                listener_topology: Some(listener_supervisor.clone()),
            },
            xds_status
                .as_ref()
                .expect("data plane has a pre-created xDS status")
                .clone(),
        );
        if let Some((xds_cfg, specs)) = xds_bootstrap {
            manager.start_initial(xds_cfg, specs);
        }
        Some(manager)
    } else {
        None
    };

    // listener 已进入 supervisor 后再启动唯一 reload worker；从此数据面拓扑也遵守
    // bind/build → ArcSwap publish → accept generation handoff 的同一事务边界。
    let reload_handle = reload::spawn(
        cfg_path.clone(),
        snap.clone(),
        version.clone(),
        reload::ReloadRuntime {
            apply_coordinator: apply_coordinator.clone(),
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
            sidecar_mode: run_mode.is_sidecar(),
            listener_topology: Some(listener_supervisor.clone()),
            access_log: Some(access_log_shutdown.clone()),
            admin_audit: Some(admin_audit.clone()),
            http_cache: Some(http_cache.clone()),
            telemetry: Some(telemetry.clone()),
            #[cfg(feature = "xds-client")]
            xds: xds_manager.clone(),
        },
        config_history.clone(),
        reload_cfg,
    );
    // Kubernetes 对象只在后台编译成物化候选，并通过上面的唯一 reload worker 发布。
    gateway::kubernetes_routes::spawn_controller(snap.clone(), cfg_path.clone(), reload_handle);
    // 无 seed ACME 首签期间 TLS socket 虽已绑定但尚不 accept；readiness 必须保持 503，避免 LB
    // 把业务流量送到只有 challenge 能力的半就绪节点。最后一个 deferred listener 激活时会置 true。
    if deferred_tls.pending.load(Ordering::Acquire) == 0 {
        ready.store(true, Ordering::Release);
    }
    // V4 网关节点自注册:后台只感知快照变化并写注册中心,请求热路径不访问 Nacos。
    #[cfg(feature = "xds-client")]
    let registration_control_ready: Arc<dyn Fn() -> bool + Send + Sync> = match &xds_status {
        Some(status) => {
            let status = status.clone();
            let snapshot = snap.clone();
            Arc::new(move || !snapshot.load().control_plane.xds.enabled || status.ready())
        }
        None => Arc::new(|| true),
    };
    #[cfg(not(feature = "xds-client"))]
    let registration_control_ready: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(|| true);
    let self_registration = run_mode.runs_data().then(|| {
        GatewaySelfRegistration::spawn(
            snap.clone(),
            ready.clone(),
            active_health.clone(),
            registration_control_ready,
        )
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

/// 在 listener two-phase prepare 阶段绑定一个 proxy 的全部 transport。
///
/// 业务作用：只有明文 TCP、TLS TCP 和可选 QUIC UDP 全部绑定且证书可构建时才返回候选，任何
/// 一项失败都会阻止快照发布，避免同一逻辑入口出现协议能力分裂。
///
/// 参数说明：`proxy` 是候选快照中已完成语义校验的 listener 运行配置。
///
/// 返回：成功时返回等待 commit 的 socket 集；失败时释放本次 prepare 已绑定资源并保留旧代。
async fn bind_proxy(proxy: &ProxyRuntime) -> Result<BoundProxy> {
    let listen: SocketAddr = proxy
        .listen
        .parse()
        .with_context(|| format!("invalid proxy `{}` listen `{}`", proxy.id, proxy.listen))?;
    let listener = if proxy.plain_enabled {
        Some(
            bind_reuseport_tcp(listen)
                .with_context(|| format!("bind proxy `{}` listen {listen}", proxy.id))?,
        )
    } else {
        None
    };
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
            let mode = if tls_cfg.in_memory.is_none()
                && tls_cfg.acme.as_ref().is_some_and(|acme| {
                    acme.bootstrap_without_seed
                        && (!tls_cfg.cert_file.is_file() || !tls_cfg.key_file.is_file())
                }) {
                warn!(proxy = %proxy.id, %tls_listen, "ACME bootstrap: seed certificate missing; TLS socket bound and awaiting first issuance");
                BoundTlsMode::Deferred
            } else {
                let server_config = build_server_config(tls_cfg).with_context(|| {
                    format!("build initial tls server config for proxy `{}`", proxy.id)
                })?;
                let shared_tls: SharedServerConfig = Arc::new(ArcSwap::new(server_config));
                BoundTlsMode::Ready(shared_tls)
            };
            Some(BoundTlsProxy {
                listen: tls_listen,
                listener: tls_listener,
                runtime: tls_cfg.clone(),
                mode,
            })
        }
        None => None,
    };
    #[cfg(feature = "http3")]
    let http3 = if proxy.http3.enabled {
        let tls_cfg = proxy
            .tls
            .as_ref()
            .expect("HTTP/3 TLS presence was validated during snapshot build");
        let h3_listen: SocketAddr = tls_cfg.listen.parse().with_context(|| {
            format!(
                "invalid proxy `{}` HTTP/3 tls.listen `{}`",
                proxy.id, tls_cfg.listen
            )
        })?;
        // 首版不允许 QUIC 在 ACME 无 seed 阶段静默缺席；需要等证书完整落盘再 reload，保证
        // TCP TLS 与 UDP H3 在同一次 two-phase commit 中共同可服务。
        anyhow::ensure!(
            tls_cfg.cert_file.is_file() && tls_cfg.key_file.is_file(),
            "proxy `{}` HTTP/3 requires an installed TLS keypair before listener activation",
            proxy.id
        );
        let socket = bind_reuseport_udp(h3_listen)
            .with_context(|| format!("bind proxy `{}` HTTP/3 UDP {h3_listen}", proxy.id))?
            .into_std()
            .context("convert HTTP/3 UDP socket for Quinn")?;
        let endpoint = gateway::http3::build_server_endpoint(tls_cfg, &proxy.http3, socket)
            .with_context(|| format!("build proxy `{}` HTTP/3 endpoint", proxy.id))?;
        Some(BoundHttp3Proxy {
            listen: h3_listen,
            endpoint,
            runtime: proxy.http3.clone(),
        })
    } else {
        None
    };
    Ok(BoundProxy {
        id: proxy.id.clone(),
        listen,
        listener,
        tls,
        #[cfg(feature = "http3")]
        http3,
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
            Ok::<_, anyhow::Error>(BoundStreamTls {
                runtime: tls.clone(),
                config: shared,
            })
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
