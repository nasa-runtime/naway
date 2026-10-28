//! 监听器、连接预算和候选资源的两阶段交接。

use std::collections::HashMap;
use std::future::Future;
use std::io::IoSlice;
#[cfg(feature = "http3")]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use parking_lot::Mutex as ParkingMutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::ReadBuf;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Notify};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use gateway::admin;
#[cfg(feature = "http3")]
use gateway::config::model::Http3RetryCfg;
use gateway::config::model::{ServerLimitsCfg, TimeoutCfg};
use gateway::config::{
    GatewaySnapshot, ProxyListenTopology, ProxyProtocolRuntimeCfg, ProxyRuntime,
    StreamProtocolRuntime, StreamRuntime,
};
use gateway::observability::metrics::Metrics;
use gateway::protocols::proxy_protocol::{strip_proxy_protocol, ConnInfo};
use gateway::proxy::{ConnectionClientIpHeader, DownstreamConnectionLease, GatewayProxy};
use gateway::tls::{build_server_config, spawn_cert_watcher_until, SharedServerConfig};

use super::stream::*;

/// L7 HTTP 数据面的进程级共享依赖。
///
/// Snapshot 可热换；代理器、连接预算、在途计数和指标必须常驻，避免 reload 把运行态清零。
#[derive(Clone)]
pub(super) struct DataPlaneState {
    /// 当前不可变配置快照指针；请求/accept 只做一次原子读取。
    pub(super) snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// 常驻 HTTP 代理执行器，持有连接池与限流/健康运行态。
    pub(super) proxy: Arc<GatewayProxy>,
    /// 按 proxy id 隔离的物理连接预算。
    pub(super) connection_budget: Arc<ConnectionBudget>,
    /// HTTP/3 按 proxy+来源 IP 隔离的连接硬门；跨 listener generation 常驻，防止 reload 绕限。
    #[cfg(feature = "http3")]
    pub(super) http3_peer_connection_budget: Arc<Http3PeerConnectionBudget>,
    /// HTTP + stream 共用的进程级在途连接数，供停机 drain 判断。
    pub(super) active_connections: Arc<AtomicU64>,
    /// 数据面低基数指标。
    pub(super) metrics: Arc<Metrics>,
}

/// 为下游传输增加“连续写 Pending”超时，不缓存也不复制 HTTP body。
///
/// Hyper 只有在 socket 可写时才继续 poll response body；若客户端停止读取，仅给上游 body 包 idle
/// timer 不会被 poll，无法释放连接。本 wrapper 在 TCP/TLS write/flush/shutdown 真正 Pending 时计时，
/// 成功写入后立即清零，因此不会因 SSE/gRPC 暂时没有输出而误杀连接。
pub(super) struct DownstreamWriteTimeoutIo<I> {
    /// 已完成 PROXY protocol/TLS 握手后的真实下游 IO。
    pub(super) inner: I,
    /// 单次连续 Pending 上限；None 表示关闭。
    pub(super) timeout: Option<Duration>,
    /// 首次 Pending 时惰性创建，后续阻塞段只原地 reset；每条物理连接至多一次堆分配。
    pub(super) timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// 当前是否已经为连续 Pending 段设置 deadline；Ready 后只清标志，不销毁 timer。
    pub(super) write_blocked: bool,
}

impl<I> DownstreamWriteTimeoutIo<I> {
    /// 业务作用：为下游 IO 建立只约束连续写阻塞的 deadline 状态，不改变读取和 body 流式语义。
    ///
    /// 参数说明：
    /// - `inner`：已经完成接入校验的下游 IO。
    /// - `timeout_ms`：写超时毫秒数，0 表示关闭写超时。
    ///
    /// 返回：返回尚未启动计时的 IO wrapper；计时器只在第一次写 `Pending` 时惰性创建。
    pub(super) fn new(inner: I, timeout_ms: u64) -> Self {
        Self {
            inner,
            timeout: (timeout_ms > 0).then(|| Duration::from_millis(timeout_ms)),
            timer: None,
            write_blocked: false,
        }
    }

    /// 业务作用：在 inner write 持续 `Pending` 时启动或推进 deadline，防止停读客户端永久占用连接。
    ///
    /// 参数说明：
    /// - `cx`：提供当前 IO task 的唤醒器。
    ///
    /// 返回：deadline 未到时保持 `Pending`；到期后返回 `TimedOut` 并终止 Hyper 连接驱动。
    pub(super) fn poll_pending_timeout(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
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
    /// 参数说明: 无。
    ///
    /// 返回：阻塞段已超过 deadline 时返回 `TimedOut`；未计时或尚未到期时返回 `None`。
    pub(super) fn expired_write_timeout(&self) -> Option<io::Error> {
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
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；只清除当前阻塞标记并保留计时器分配。
    pub(super) fn write_progressed(&mut self) {
        self.write_blocked = false;
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for DownstreamWriteTimeoutIo<I> {
    /// 业务作用：在底层连接与调用方缓冲之间推进异步读取，保留 Pending 和连接错误的传播语义。
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for DownstreamWriteTimeoutIo<I> {
    /// 业务作用：向底层连接推进异步写入，通过 Pending 将背压传回调用方。
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

    /// 业务作用：驱动已提交字节的异步刷新，把底层阻塞和传输错误传回连接状态机。
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

    /// 业务作用：推进写方向的有序关闭，使待发送数据与底层连接关闭遵守异步协议。
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

    /// 业务作用：把分散缓冲区交给底层连接发送，保留写入背压且不先拼接完整载荷。
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

    /// 业务作用：向上层报告当前连接是否支持分散写，避免选择底层无法承接的发送方式。
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// 每个 HTTP proxy 的物理下游连接预算。计数器常驻进程，不随 Snapshot 换版重置；limit 每次等待时
/// 从当前快照读取，因此调小预算会在现有连接自然退出后自动收敛，调大则立即唤醒 accept loop。
#[derive(Default)]
pub(super) struct ConnectionBudget {
    /// proxy id -> 常驻计数器；reload 调整 limit 时不能替换计数器，否则会漏算旧连接。
    ///
    /// accept 是建连热路径，且同一 proxy 的明文/TLS listener 可能并发查表；使用不带 poisoning
    /// 的 `parking_lot::Mutex` 缩短极短临界区。表只在首次见到 listener id 时写入，锁内不 await。
    pub(super) entries: ParkingMutex<HashMap<String, Arc<ConnectionBudgetEntry>>>,
}

/// 单个 proxy 的连接预算状态。
pub(super) struct ConnectionBudgetEntry {
    /// 已占用的物理 TCP/TLS 连接数。
    pub(super) active: AtomicU64,
    /// 连接释放或预算变化后的唤醒点；等待方会重新读取最新 Snapshot limit。
    pub(super) changed: Notify,
}

/// 一个已占用的物理连接名额；Drop 是唯一归还路径，覆盖正常结束、握手失败和 task 取消。
pub(super) struct ConnectionSlot {
    /// 所属 proxy 的常驻预算状态。
    pub(super) entry: Arc<ConnectionBudgetEntry>,
}

/// HTTP/3 来源 IP 连接预算；计数表只包含已有全局名额的 Initial/connection，规模受全局硬门约束。
#[cfg(feature = "http3")]
#[derive(Default)]
pub(super) struct Http3PeerConnectionBudget {
    /// proxy id -> 来源 IP -> 当前握手或已建立连接数；reload 不替换这张表。
    pub(super) entries: ParkingMutex<HashMap<String, HashMap<IpAddr, u64>>>,
}

/// 单条 QUIC handshake/connection 占用的来源 IP 名额。
#[cfg(feature = "http3")]
pub(super) struct Http3PeerConnectionSlot {
    pub(super) budget: Arc<Http3PeerConnectionBudget>,
    pub(super) proxy_id: Arc<str>,
    pub(super) peer_ip: IpAddr,
}

/// 单条已接收连接从同一份不可变 Snapshot 固化的配置。
///
/// PROXY protocol 策略与预算上限来自同一版本，避免 reload 恰好发生在两次独立读取之间时拼出
/// 混合配置。listener 快照只作为“该 listener 已被删除”后的排空兜底；同 id 仍存在时每个请求
/// 继续读取最新版，避免普通 keep-alive 长期绕过策略更新。
pub(super) struct AcceptedConnection {
    /// 已占用的物理连接名额；任何后续失败都通过 Drop 自动归还。
    pub(super) slot: ConnectionSlot,
    /// accept 后、TLS/HTTP 前需要执行的 PROXY protocol 策略。
    pub(super) proxy_protocol: ProxyProtocolRuntimeCfg,
    /// 用于 listener 级 Builder cache 换版判断；配置版本只会随成功 reload 单调递增。
    pub(super) snapshot_version: u64,
    /// 构造/命中 Hyper Builder 所需的同版资源上限。
    pub(super) limits: ServerLimitsCfg,
    /// 下游写、请求头读取与总连接超时。
    pub(super) timeouts: TimeoutCfg,
    /// accept 时的 listener generation；删除 listener 后只服务该物理连接上的在途/排空请求。
    pub(super) listener_snapshot: Arc<GatewaySnapshot>,
}

/// Hyper connection driver 只保留共享协议 Builder 与连接期超时，不钉住完整路由快照。
pub(super) struct DownstreamConnectionConfig {
    /// 同一 listener、同一 Snapshot 版本共享的只读 HTTP/1+HTTP/2 Builder。
    pub(super) server: Arc<auto::Builder<TokioExecutor>>,
    /// 写超时与总连接超时仍由各 connection future 直接读取。
    pub(super) timeouts: TimeoutCfg,
}

/// 一条已准入连接交给 Hyper driver 的协议参数与 listener 排空 generation。
pub(super) struct DownstreamConnectionDispatch {
    /// 可按 Snapshot version 共享 Builder 的紧凑连接配置。
    pub(super) config: DownstreamConnectionConfig,
    /// listener 删除后的连接排空兜底；同 id 存在时请求仍使用最新 Snapshot。
    pub(super) listener_snapshot: Arc<GatewaySnapshot>,
}

/// accept loop 的协议 Builder cache。Builder 在 `serve_connection_with_upgrades` 后只读，因此
/// 同版连接可安全共享；活动旧连接持有自己的 `Arc`，reload 重建不会中断它们。
pub(super) struct CachedDownstreamServer {
    /// 生成 Builder 的 Gateway Snapshot 版本。
    pub(super) snapshot_version: u64,
    /// 预配置且只读的 Hyper server Builder。
    pub(super) server: Arc<auto::Builder<TokioExecutor>>,
}

/// 把 accept 名额、进程活跃计数和指标绑定成同一个 Drop 边界。普通 HTTP 由 connection task
/// 持有；Upgrade 时 [`DownstreamConnectionLease`] 的 clone 被移动进 WS tunnel task。
pub(super) struct ConnectionLifetime {
    pub(super) _slot: ConnectionSlot,
    pub(super) active_connections: Arc<AtomicU64>,
    pub(super) metrics: Arc<Metrics>,
    #[cfg(feature = "http3")]
    pub(super) quic: bool,
}

impl Drop for ConnectionLifetime {
    /// 业务作用：在 TCP 或 QUIC 下游 connection 完整退出时一次性归还全局连接
    /// 计数，避免错误/取消分支泄漏 gauge。
    ///
    /// 参数说明: 无。
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
    /// 业务作用：获取或创建指定 proxy 的常驻预算状态。
    ///
    /// 参数说明：
    /// - `proxy_id`: 数据面 listener 的稳定 id；相同 id 的明文/TLS listener 共享预算。
    ///
    /// 返回：可跨 task 持有的预算状态。该函数不占用连接名额。
    pub(super) fn entry(&self, proxy_id: &str) -> Arc<ConnectionBudgetEntry> {
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

    /// 业务作用：在已经定位预算条目的情况下执行无锁 CAS；成功前不 clone `Arc`，失败路径零分配。
    pub(super) fn try_acquire_entry(
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

    /// 业务作用：已 accept 的单个 socket 在这里等待预算。每个 listener 最多持有一个等待 socket，内核 backlog
    /// 承担其余排队，因此达到预算时不会无限 `tokio::spawn`。
    ///
    /// 参数说明：
    /// - `proxy_id`: 当前 accept loop 对应的稳定 proxy id。
    /// - `entry`: listener 启动时定位一次的常驻预算句柄；热路径不再查 HashMap。
    /// - `snap`: 当前配置指针；每次被唤醒都重新读取 limit，使热调大/调小都能收敛。
    /// - `shutdown`: 停机广播；等待预算期间收到停机必须放弃已 accept socket。
    ///
    /// 返回：获得名额时返回 RAII slot 及同版连接配置；proxy 被删除、停机或广播关闭时返回
    /// `None`。
    pub(super) async fn acquire(
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
    /// 参数说明：
    /// - `proxy_id`：是逻辑 listener
    /// - `peer_ip`：取自 Initial 源地址
    /// - `limit`：是同版硬门。
    ///
    /// 返回：未达上限时返回 RAII 名额；达到上限返回 None，调用方必须协议级拒绝 Initial。
    pub(super) fn try_acquire(
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
    /// 业务作用：归还名额并唤醒所有等待 listener；等待方会用 CAS 竞争最新可用名额。
    fn drop(&mut self) {
        self.entry.active.fetch_sub(1, Ordering::AcqRel);
        self.entry.changed.notify_waiters();
    }
}

#[cfg(feature = "http3")]
impl Drop for Http3PeerConnectionSlot {
    /// 业务作用：在握手失败、连接结束或 task 取消的同一个 Drop 边界归还来源 IP 名额。
    ///
    /// 参数说明: 无。
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
/// 业务作用：把同一 listener、同一 Snapshot 版本的 Hyper Builder 构造成本摊薄到一次，
/// 避免连接规模增长时重复保留等价协议配置。
///
/// `auto::Builder` 内含 HTTP/1 parser 与 HTTP/2 flow-control 配置。按 listener 缓存只读实例，
/// 避免每条长连接重复保留相同的协议配置；命中只增加 `Arc` 引用计数，reload 后首条新连接重建，
/// 旧连接继续持有旧版本。
///
/// 参数说明：
/// - `cache`：是当前 accept loop 私有单项缓存
/// - `snapshot_version`：是连接读取的原子配置 版本
/// - `limits`：提供请求头、HTTP/2 stream 与 flow-control 硬预算
/// - `timeouts`：提供协议计时门。
///
/// 返回：可供本连接使用的共享 server 与连接期 timeout；版本变化时先换缓存，旧连接继续持有旧值。
pub(super) fn downstream_connection_config(
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
        // 动态放大，破坏  可审计的资源预算。窗口只发放 credit，不 collect body。
        .initial_stream_window_size(Some(limits.h2_initial_stream_window_bytes))
        .initial_connection_window_size(Some(limits.h2_initial_connection_window_bytes))
        .max_header_list_size(limits.max_header_bytes.min(u32::MAX as usize) as u32)
        .timer(TokioTimer::new());
    let server = Arc::new(server);
    *cache = Some(CachedDownstreamServer {
        snapshot_version,
        server: server.clone(),
    });
    DownstreamConnectionConfig {
        server,
        timeouts,
    }
}

/// 业务作用：把一条已准入的下游连接交给共享 Hyper server，并把连接预算、活跃指标、
/// 可信客户端地址缓存和 Upgrade 生命周期绑定到同一个可取消 task。
///
/// 参数说明：
/// - `stream`：是已完成监听层握手的 IO
/// - `conn`：标识 本连接的可信入口上下文
/// - `proxy_id`：标识 本连接的可信入口上下文
/// - `downstream_proto`：标识 本连接的可信入口上下文
/// - `state`：提供数据面、同版 server 与 listener 排空快照
/// - `dispatch`：提供数据面、同版 server 与 listener 排空快照
/// - `slot`：持有连接预算。
///
/// 返回：无返回值；函数成功 spawn 连接驱动，连接结束、超时或 task 取消时通过 Drop 归还预算。
pub(super) fn spawn_downstream_connection<I>(
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
        config: DownstreamConnectionConfig {
            server,
            timeouts,
        },
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
            // HTTP/2 热路径完全不承担 WS 生命周期维护成本；proxy::handle 仍完整校验 GET、h1、
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

/// 业务作用：驱动明文监听器的连接接入，在接受请求前完成连接预算和入口协议约束。
pub(super) fn spawn_plain_accept_loop(
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
            // accept 与停机信号二选一——SIGTERM 后 changed 触发即停收新连接,
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

/// 业务作用：驱动 TLS 监听器接入，在握手预算、证书和入口身份成立后交给统一数据面。
pub(super) fn spawn_tls_accept_loop(
    listener: TcpListener,
    proxy_id: Arc<str>,
    tls_config: SharedServerConfig,
    client_auth: Option<gateway::config::ClientAuthRuntime>,
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
            // 同明文入口，SIGTERM 后停收新 TLS 连接。
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
            // 从 ArcSwap 取得当前证书配置，建连只克隆 Arc，避免磁盘读取和证书解析放大连接开销。
            let acceptor = TlsAcceptor::from(tls_config.load_full());
            let state = state.clone();
            let proxy_id = proxy_id.clone();
            let client_auth = client_auth.clone();
            tokio::spawn(async move {
                match strip_proxy_protocol(stream, peer, &proxy_protocol).await {
                    Ok((stream, mut conn)) => match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(error) = gateway::tls::verify_client_certificate_spiffe(
                                tls_stream.get_ref().1.peer_certificates(),
                                client_auth.as_ref(),
                            ) {
                                warn!(peer = %peer, %error, "client SPIFFE identity rejected");
                                return;
                            }
                            // 在线吊销证据必须在业务协议读取前完成；否则被吊销身份可能先发送一条请求。
                            if let Err(error) = gateway::tls::verify_client_certificate_ocsp(
                                tls_stream.get_ref().1.peer_certificates(),
                                client_auth.as_ref(),
                            )
                            .await
                            {
                                warn!(peer = %peer, %error, "client certificate OCSP check failed");
                                return;
                            }
                            // mTLS:握手成功且出示了客户端证书(已被 verifier 校验通过)→ 标记 verified,
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
/// 参数说明：
/// - `endpoint`：是 prepare 阶段已绑定的 UDP endpoint
/// - `runtime`：是同版 H3 硬预算
/// - `certificate_updates`：串行接收新握手配置
/// - `proxy_id`：标识逻辑 listener
/// - `state`：提供统一 代理、预算和指标
/// - `shutdown`：是 generation 停收广播。
///
/// 返回：无同步返回值；函数派生一个受 shutdown 管理的 accept task。
#[cfg(feature = "http3")]
pub(super) fn spawn_http3_accept_loop(
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
            let connection_runtime = runtime.clone();
            let mut connection_shutdown = shutdown.clone();
            tokio::spawn(async move {
                // 从 Initial 到 connection task 完整结束都计入来源预算，握手失败/取消也由 RAII 归还。
                let _peer_slot = peer_slot;
                // 只有 listener 与 route 共同启用 early data 时才允许 H3 在握手确认前读取 stream；
                // 每条流仍由 Quinn 真值标记和统一代理门禁裁决，不能因提早调度绕过鉴权或 anti-replay。
                let early_attempt = if connection_runtime.zero_rtt {
                    connecting
                        .into_0rtt()
                        .map(|(connection, established)| (connection, Some(established)))
                } else {
                    Err(connecting)
                };
                let (connection, early_established) = match early_attempt {
                    Ok(ready) => ready,
                    Err(connecting) => {
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
                        (connection, None)
                    }
                };
                active_connections.fetch_add(1, Ordering::Relaxed);
                metrics.inc_active_connection();
                metrics.inc_quic_connection();
                if let Some(established) = early_established {
                    let handshake_metrics = metrics.clone();
                    tokio::spawn(async move {
                        if established.await {
                            handshake_metrics.inc_quic_handshake_success();
                        } else {
                            handshake_metrics.inc_quic_handshake_error();
                        }
                    });
                } else {
                    metrics.inc_quic_handshake_success();
                }
                let _lifetime = ConnectionLifetime {
                    _slot: slot,
                    active_connections,
                    metrics: metrics.clone(),
                    quic: true,
                };
                let serving = gateway::protocols::http3::serve_connection(
                    connection,
                    proxy,
                    proxy_id,
                    peer,
                    connection_runtime,
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
/// 参数说明：
/// - `incoming`：提供地址验证状态
/// - `runtime`：提供策略与连接硬门
/// - `open_connections`：是 endpoint 当前已打开连接数。
///
/// 返回：true 表示调用方应发送 Retry 并停止本次握手，false 表示可继续预算校验。
#[cfg(feature = "http3")]
pub(super) fn should_retry_http3(
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
/// 业务作用：按压力水位和地址验证状态裁决 Retry，避免将已验证客户端重新送入 Retry 循环。
///
/// 参数说明：
/// - `policy`：是配置策略
/// - `address_validated`：来自 Quinn
/// - `may_retry`：来自 Quinn
/// - `open_connections`：是当前占用与 H3 专属硬上限。
/// - `max_connections`：是当前占用与 H3 专属硬上限。
///
/// 返回：true 表示必须先发 Retry；false 表示本层允许继续进入连接预算校验。
#[cfg(feature = "http3")]
pub(super) fn http3_retry_required(
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

/// 业务作用：为 L7 下游 TCP socket 启用小帧低延迟模式。
///
/// HTTP/2/gRPC 会把 HEADERS、5-byte gRPC envelope、短 DATA 和 WINDOW_UPDATE 复用在长寿命
/// transport 上。保留系统默认 Nagle 时，这些 frame 可能与对端 delayed ACK 形成约 40ms 的
/// 停顿；这不是合理的吞吐/资源折中，因为 h2 本身已经在 driver 层聚合一次就绪写。这里只切换
/// socket 标志，不建立用户态 buffer、不复制 payload，也不改变慢下游写超时和背压。
///
/// `setsockopt` 失败不会拒绝一个已经 accept 的合法连接；保留服务可用性并记录 peer，性能门会
/// 暴露平台是否无法提供该选项。
pub(super) fn configure_downstream_tcp(stream: &TcpStream, peer: SocketAddr) {
    if let Err(error) = stream.set_nodelay(true) {
        warn!(%peer, %error, "failed to enable TCP_NODELAY on downstream connection");
    }
}

/// 业务作用：等待 ACME 首签 keypair 落盘后激活已绑定 TLS socket，并把任务限制在 listener generation 内。
///
/// 参数说明：
/// - `listener`：防止首签期间端口被抢
/// - `proxy_id`：用于观测
/// - `tls_cfg`：描述材料和轮询
/// - `state`：是数据面状态
/// - `shutdown`：撤销本代
/// - `readiness`：统一约束 pending、就绪与停机事实。
///
/// 返回：无同步返回值；后台仅在证书完整可用后启动 accept，取消或坏材料均保持端口不服务。
pub(super) fn spawn_deferred_tls_accept_loop(
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
                    spawn_tls_accept_loop(
                        listener,
                        proxy_id.clone(),
                        shared_tls,
                        tls_cfg.client_auth.clone(),
                        state,
                        shutdown,
                    );
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
pub(super) struct PendingTlsActivation {
    pub(super) readiness: DeferredTlsReadiness,
}

/// 无 seed TLS listener 共享的就绪状态；generation 热换与进程停机必须操作同一组原子事实。
#[derive(Clone)]
pub(super) struct DeferredTlsReadiness {
    pub(super) pending: Arc<AtomicU64>,
    pub(super) ready: Arc<AtomicBool>,
    pub(super) stopping: Arc<AtomicBool>,
}

impl PendingTlsActivation {
    /// 业务作用：接管调用方已增加的 deferred TLS 计数，保证所有退出路径都能归还。
    ///
    /// 参数说明：
    /// - `readiness`：统一持有全进程待激活数、就绪位和停机位。
    ///
    /// 返回：返回只应在对应 activation task 内持有的 RAII guard。
    pub(super) fn new(readiness: DeferredTlsReadiness) -> Self {
        Self {
            readiness,
        }
    }
}

impl Drop for PendingTlsActivation {
    /// 业务作用：在激活、热移除、取消或 panic 后归还 pending 事实，避免 readiness 永久卡住。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；最后一个 pending 退出且进程未停机时发布 ready=true。
    fn drop(&mut self) {
        let previous = self.readiness.pending.fetch_sub(1, Ordering::AcqRel);
        if previous == 1 && !self.readiness.stopping.load(Ordering::Acquire) {
            self.readiness.ready.store(true, Ordering::Release);
        }
    }
}
pub(super) struct BoundProxy {
    pub(super) id: String,
    pub(super) listen: SocketAddr,
    pub(super) listener: Option<TcpListener>,
    pub(super) tls: Option<BoundTlsProxy>,
    #[cfg(feature = "http3")]
    pub(super) http3: Option<BoundHttp3Proxy>,
}

/// prepare 阶段已经完整构建、等待 commit 激活的 HTTP/3 endpoint。
#[cfg(feature = "http3")]
pub(super) struct BoundHttp3Proxy {
    /// 与 TLS TCP listener 相同的逻辑地址/端口，仅 transport 为 UDP。
    pub(super) listen: SocketAddr,
    /// 已绑定 UDP 但 server config 为空的候选；commit 前不会抢旧 generation 的 QUIC Initial。
    pub(super) endpoint: gateway::protocols::http3::PreparedServerEndpoint,
    /// 与 endpoint 同版的 HTTP/3 运行计划。
    pub(super) runtime: gateway::config::Http3RuntimeCfg,
}

pub(super) struct BoundTlsProxy {
    pub(super) listen: SocketAddr,
    pub(super) listener: TcpListener,
    /// watcher/延迟激活共用的完整 TLS 材料来源。
    pub(super) runtime: gateway::config::TlsRuntimeCfg,
    pub(super) mode: BoundTlsMode,
}

/// TLS listener 启动形态：已有 keypair 立即 accept，或 ACME 首签后在同进程激活。
pub(super) enum BoundTlsMode {
    /// 启动期已构建可用 rustls 配置。
    Ready(SharedServerConfig),
    /// socket 已绑定，但 cert/key 尚不存在；后台检测到完整 keypair 后才开始 accept。
    Deferred,
}

pub(super) struct BoundStream {
    pub(super) runtime: StreamRuntime,
    pub(super) listen: SocketAddr,
    pub(super) socket: BoundStreamSocket,
    /// prepare 只构建 TLS；文件 watcher 要等 generation commit 后再启动。
    pub(super) tls: Option<BoundStreamTls>,
}

pub(super) struct BoundStreamTls {
    pub(super) runtime: gateway::config::TlsRuntimeCfg,
    pub(super) config: SharedServerConfig,
}

pub(super) enum BoundStreamSocket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

pub(super) struct ActiveListenerGeneration {
    pub(super) topology: ProxyListenTopology,
    pub(super) stop: watch::Sender<bool>,
}

pub(super) struct ActiveAdminGeneration {
    pub(super) listen: SocketAddr,
    pub(super) stop: watch::Sender<bool>,
}

/// 数据面 listener supervisor。所有可能失败的 bind/TLS build 都在 reload 的 prepare
/// 阶段完成；active map 仅在 commit 的短临界区替换 stop handle，不持锁执行 I/O。
#[derive(Clone)]
pub(super) struct ListenerSupervisor {
    pub(super) active: Arc<Mutex<HashMap<String, ActiveListenerGeneration>>>,
    pub(super) active_admin: Arc<Mutex<Option<ActiveAdminGeneration>>>,
    pub(super) active_acme: Arc<Mutex<Option<gateway::tls::acme::AcmeWorkerGeneration>>>,
    pub(super) active_acme_runtime_signature: Arc<Mutex<String>>,
    pub(super) data_plane: DataPlaneState,
    pub(super) stream_plane: StreamPlaneState,
    pub(super) admin_state: Arc<admin::AdminState>,
    pub(super) acme_http01: Arc<gateway::tls::acme::Http01ChallengeStore>,
    pub(super) manages_data: bool,
    pub(super) deferred_tls: DeferredTlsReadiness,
}

pub(super) struct PreparedListenerSwitch {
    pub(super) supervisor: ListenerSupervisor,
    pub(super) candidate_topologies: HashMap<String, ProxyListenTopology>,
    pub(super) proxies: Vec<BoundProxy>,
    pub(super) streams: Vec<BoundStream>,
    pub(super) admin: Option<(SocketAddr, TcpListener)>,
    pub(super) acme: Option<(gateway::tls::acme::PreparedAcmeWorkers, String)>,
    pub(super) removed: Vec<String>,
}

impl ListenerSupervisor {
    /// 业务作用：创建统一管理 data、stream、admin listener 与 ACME worker generation 的两阶段协调器。
    ///
    /// 参数说明：
    /// - `data_plane`：是 accept loop 共享状态
    /// - `stream_plane`：是 accept loop 共享状态
    /// - `admin_state`：是管理面状态
    /// - `acme_http01`：是 challenge 事实表
    /// - `manages_data`：区分 admin-only 进程
    /// - `deferred_tls`：共同约束无 seed TLS 的就绪发布。
    ///
    /// 返回：返回尚未接管任何 listener generation 的 supervisor。
    pub(super) fn new(
        data_plane: DataPlaneState,
        stream_plane: StreamPlaneState,
        admin_state: Arc<admin::AdminState>,
        acme_http01: Arc<gateway::tls::acme::Http01ChallengeStore>,
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
    /// 参数说明：
    /// - `snapshot`：提供已验证拓扑及 ACME 锁连接签名
    /// - `proxies`：是启动前绑定资源
    /// - `streams`：是启动前绑定资源
    /// - `admin_listener`：是启动前绑定资源
    /// - `admin_listen`：是规范化管理地址
    /// - `acme`：是不含签发副作用的候选 worker。
    ///
    /// 返回：返回 proxy 与 stream 的低基数启动摘要；所有 generation 已归 supervisor 管理。
    pub(super) fn install_initial(
        &self,
        snapshot: &GatewaySnapshot,
        proxies: Vec<BoundProxy>,
        streams: Vec<BoundStream>,
        admin_listener: TcpListener,
        admin_listen: SocketAddr,
        acme: Option<gateway::tls::acme::PreparedAcmeWorkers>,
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
                gateway::runtime::state::rate_limiter_config_signature(&snapshot.runtime_state),
            );
        }
        (proxy_log, stream_log)
    }

    /// 业务作用：先启动候选管理面 generation，再停止旧 accept 并让既有连接优雅 drain。
    ///
    /// 参数说明：
    /// - `listener`：是 prepare 完成的 socket
    /// - `listen`：是规范化地址摘要。
    ///
    /// 返回：无返回值；候选启动不再含可失败 I/O，旧代只在新代获得任务所有权后停止。
    pub(super) fn activate_admin(&self, listener: TcpListener, listen: SocketAddr) {
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
            .replace(ActiveAdminGeneration {
                listen,
                stop,
            });
        if let Some(old) = old {
            // 新管理面已经持有监听任务后才撤销旧代，避免热换窗口失去 /readyz 与配置控制面。
            let _ = old.stop.send(true);
        }
    }

    /// 业务作用：激活候选 ACME worker generation，并立即撤销旧代签发权威。
    ///
    /// 参数说明：
    /// - `prepared`：已在快照发布前完成 provider 与锁后端初始化
    /// - `runtime_signature`：记录本代锁连接参数，供后续 reload 判定是否必须重建。
    ///
    /// 返回：无返回值；旧代取消会触发 challenge lease 清理，新代成为唯一续期所有者。
    pub(super) fn activate_acme(
        &self,
        prepared: gateway::tls::acme::PreparedAcmeWorkers,
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
    /// 参数说明：
    /// - `bound`：持有已绑定 socket/endpoint
    /// - `topology`：是与候选快照同版的比较摘要。
    ///
    /// 返回：用于启动日志的 listener 地址列表。
    pub(super) fn activate_proxy(
        &self,
        bound: BoundProxy,
        topology: ProxyListenTopology,
    ) -> Vec<String> {
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
                            http3_certificate_updates =
                                Some(gateway::protocols::http3::spawn_cert_watcher(
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
                        tls.runtime.client_auth.clone(),
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
            .insert(
                key,
                ActiveListenerGeneration {
                    topology,
                    stop,
                },
            );
        if let Some(old) = old {
            let _ = old.stop.send(true);
        }
        log
    }

    /// 业务作用：激活已 prepare 的 L4 listener，并在新代持有 accept 权后停止同标识旧代。
    ///
    /// 参数说明：
    /// - `bound`：持有候选 socket/TLS 材料
    /// - `topology`：是与候选快照同版的比较摘要。
    ///
    /// 返回：返回用于启动日志的 listener 地址摘要。
    pub(super) fn activate_stream(
        &self,
        bound: BoundStream,
        topology: ProxyListenTopology,
    ) -> String {
        let key = topology.id.clone();
        let tls_enabled = bound.tls.is_some();
        let log = format!(
            "{}@{}{}",
            bound.runtime.id,
            bound.listen,
            if tls_enabled {
                "(tls)"
            } else {
                ""
            }
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
            .insert(
                key,
                ActiveListenerGeneration {
                    topology,
                    stop,
                },
            );
        if let Some(old) = old {
            let _ = old.stop.send(true);
        }
        log
    }

    /// 业务作用：在候选 generation 全部激活后停收已从新快照删除的 listener。
    ///
    /// 参数说明：
    /// - `keys`：是 prepare 阶段基于旧/新拓扑差集冻结的 listener 标识。
    ///
    /// 返回：无返回值；既有连接仍独立持有 IO 并按正常 drain 规则结束。
    pub(super) fn stop_removed(&self, keys: &[String]) {
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
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；已建立连接继续由全局 drain 预算管理。
    pub(super) fn shutdown(&self) {
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

impl gateway::control::reload::ListenerTopologyReconciler for ListenerSupervisor {
    /// 业务作用：完成 data/stream/admin socket、TLS 材料和 ACME provider/锁的候选期准备。
    ///
    /// 参数说明：
    /// - `candidate`：是尚未发布且已完成语义校验的完整快照。
    ///
    /// 返回：全部可失败资源就绪时返回切换事务；任一 bind/build/connect 失败则保留所有在线代。
    fn prepare<'a>(
        &'a self,
        candidate: &'a GatewaySnapshot,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn gateway::control::reload::PreparedListenerTopology>>>
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
                    != gateway::runtime::state::rate_limiter_config_signature(
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
                    gateway::tls::acme::prepare_acme_workers(
                        candidate
                            .proxies
                            .iter()
                            .filter_map(|proxy| proxy.tls.clone()),
                        candidate.runtime_state.clone(),
                        self.acme_http01.clone(),
                    )
                    .await
                    .context("prepare candidate ACME worker generation")?,
                    gateway::runtime::state::rate_limiter_config_signature(
                        &candidate.runtime_state,
                    ),
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
                as Box<
                    dyn gateway::control::reload::PreparedListenerTopology,
                >)
        })
    }
}

impl gateway::control::reload::PreparedListenerTopology for PreparedListenerSwitch {
    /// 业务作用：在候选快照已发布后交接 listener 与签发权威，先开放新代再停收旧代。
    ///
    /// 参数说明: 无。
    ///
    /// 事务自身持有 prepare 成功的候选资源和旧/新差集。
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
/// 参数说明：
/// - `stream`：是已编译的 L4 listener 运行配置。
///
/// 返回：返回包含业务 id 与 transport 的内部 key。
pub(super) fn stream_topology_key(stream: &StreamRuntime) -> String {
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
/// 参数说明：
/// - `topology`：是当前或候选 proxy listener 摘要。
///
/// 返回：TLS 配置含 ACME 时返回 true，否则返回 false。
pub(super) fn topology_uses_acme(topology: &ProxyListenTopology) -> bool {
    topology.tls.as_ref().is_some_and(|tls| tls.acme.is_some())
}
/// 在 listener two-phase prepare 阶段绑定一个 proxy 的全部 transport。
///
/// 业务作用：只有明文 TCP、TLS TCP 和可选 QUIC UDP 全部绑定且证书可构建时才返回候选，任何
/// 一项失败都会阻止快照发布，避免同一逻辑入口出现协议能力分裂。
///
/// 参数说明：
/// - `proxy`：是候选快照中已完成语义校验的 listener 运行配置。
///
/// 返回：成功时返回等待 commit 的 socket 集；失败时释放本次 prepare 已绑定资源并保留旧代。
pub(super) async fn bind_proxy(proxy: &ProxyRuntime) -> Result<BoundProxy> {
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
        let endpoint =
            gateway::protocols::http3::build_server_endpoint(tls_cfg, &proxy.http3, socket)
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

/// 业务作用：准备流式监听所需 socket 与运行资源，绑定失败不启动半完成的入口。
pub(super) async fn bind_stream(stream: &StreamRuntime) -> Result<BoundStream> {
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

/// 业务作用：创建启动期与热更期统一使用的 TCP listener。所有数据面 socket 从第一次绑定起就启用
/// SO_REUSEPORT；否则旧 socket 已存在时再给新 socket单方面设置该选项仍无法安全重绑。
pub(super) fn bind_reuseport_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(libc::SOMAXCONN)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// 业务作用：UDP 与 TCP 使用同一重绑纪律；旧 UDP session task 持有自己的 upstream socket，主 listener
/// 交接只影响后续 datagram，不创建全量报文缓冲。
pub(super) fn bind_reuseport_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}
