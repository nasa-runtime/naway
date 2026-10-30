//! TCP、UDP 与 TLS stream 的准入、选址和流式转发。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use parking_lot::Mutex as ParkingMutex;
use tokio::io::ReadBuf;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

use gateway::config::{GatewaySnapshot, StreamRouteRuntime, StreamRuntime};
use gateway::observability::access_log::{AccessLogger, AccessMethod, AccessPath, AccessRecord};
use gateway::observability::metrics::Metrics;
use gateway::protocols::proxy_protocol::{encode_proxy_protocol_header, strip_proxy_protocol};
use gateway::tls::SharedServerConfig;
use gateway::upstream::PassiveHealthPolicy;

/// L4 stream 负载均衡常驻状态。
///
/// 与配置快照解耦:reload 不应重置 `least_conn` 在途计数或 `round_robin` 游标。
#[derive(Clone, Default)]
pub(super) struct StreamLbState {
    /// 上游 health_key -> 当前 stream 会话数。
    pub(super) inflight: Arc<ParkingMutex<HashMap<Arc<str>, Arc<AtomicU64>>>>,
    /// 逻辑服务名或 route id -> round_robin 单调游标。
    pub(super) rr: Arc<ParkingMutex<HashMap<String, u64>>>,
    /// 与 HTTP 共享同一实例反馈和被动健康事实，不随 stream listener 热更重置。
    pub(super) health: Arc<gateway::upstream::passive::Registry>,
}

impl StreamLbState {
    /// 业务作用：为 stream 逻辑服务或带权 route 分配跨 reload 连续的 round-robin 序号。
    ///
    /// 参数说明：
    /// - `scope`：是 `lb://service` 的逻辑服务名或带权 route id。
    ///
    /// 返回：返回当前序号并以 wrapping 语义推进游标；同一 scope 的并发调用串行化。
    pub(super) fn next_rr(&self, scope: &str) -> u64 {
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

    /// 业务作用：返回当前仍处于被动摘除窗口内的上游 health_key。
    ///
    /// 参数说明：
    /// - `policy`: 服务级被动健康策略。
    pub(super) fn ejected_upstreams(&self, policy: PassiveHealthPolicy) -> Vec<String> {
        self.health.ejected(policy)
    }

    /// 业务作用：记录 stream 上游成功,清除对应失败状态。
    ///
    /// 参数说明：
    /// - `health_key`: 选中的上游实例身份键。
    pub(super) fn record_success(&self, health_key: &str) {
        self.health.success(health_key);
    }

    /// 业务作用：记录 stream 上游失败,达到阈值后临时摘除。
    ///
    /// 参数说明：
    /// - `health_key`: 选中的上游实例身份键。
    /// - `policy`: 服务级被动健康策略。
    pub(super) fn record_failure(&self, health_key: &str, policy: PassiveHealthPolicy) {
        self.health.failure(health_key, policy);
    }
}

/// L4 stream 数据面共享状态。
#[derive(Clone)]
pub(super) struct StreamPlaneState {
    /// 当前配置快照指针。
    pub(super) snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// L4 与 HTTP 共用归属预算，不能按协议分别扩大工作区容量。
    pub(super) workspace_proxy: Arc<gateway::proxy::GatewayProxy>,
    /// 主动健康探测器。
    pub(super) active_health: Arc<gateway::upstream::health::ActiveHealthChecker>,
    /// stream 负载均衡常驻状态。
    pub(super) lb: StreamLbState,
    /// 进程级连接数计数。
    pub(super) active_connections: Arc<AtomicU64>,
    /// 共享 metrics。
    pub(super) metrics: Arc<Metrics>,
    /// 非阻塞 access log。
    pub(super) access_log: AccessLogger,
    /// MQTT listener 级连接预算；只在协议治理制品中存在。
    #[cfg(feature = "mqtt-governance")]
    pub(super) mqtt_connections: MqttConnectionBudget,
    /// Kafka listener 级连接预算；只在协议治理制品中存在。
    #[cfg(feature = "kafka-governance")]
    pub(super) kafka_connections: KafkaConnectionBudget,
}

/// MQTT listener 连接数快照外常驻状态；热更降低上限时新连接立即按新值拒绝。
#[cfg(feature = "mqtt-governance")]
#[derive(Clone, Default)]
pub(super) struct MqttConnectionBudget {
    pub(super) usage: Arc<ParkingMutex<HashMap<Arc<str>, MqttListenerUsage>>>,
}

/// 一个 MQTT listener 跨快照连接共享的实时预留量。
#[cfg(feature = "mqtt-governance")]
#[derive(Clone, Copy, Default)]
pub(super) struct MqttListenerUsage {
    pub(super) connections: usize,
    pub(super) buffered_bytes: usize,
}

#[cfg(feature = "mqtt-governance")]
impl MqttConnectionBudget {
    /// 业务作用：在 TLS/CONNECT preread 之前预留 listener 级 MQTT 连接名额，慢握手也不能绕过硬门。
    ///
    /// 参数说明：
    /// - `listener_id`：是快照内稳定标识
    /// - `maximum`：是连接上限
    /// - `buffer_reservation`：是新连接双向最大 packet 预留
    /// - `maximum_buffered_bytes`：是 listener 聚合上限。
    ///
    /// 返回：余额充足时返回 RAII guard；已达上限时返回 None 且不改变计数。
    pub(super) fn try_acquire(
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
pub(super) struct MqttConnectionGuard {
    pub(super) usage: Arc<ParkingMutex<HashMap<Arc<str>, MqttListenerUsage>>>,
    pub(super) listener_id: Arc<str>,
    pub(super) buffer_reservation: usize,
}

#[cfg(feature = "mqtt-governance")]
impl Drop for MqttConnectionGuard {
    /// 业务作用：在任意退出路径归还 MQTT listener 名额，避免错误分支泄漏导致永久拒绝。
    ///
    /// 参数说明: 无。
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
pub(super) struct KafkaConnectionBudget {
    pub(super) usage: Arc<ParkingMutex<HashMap<Arc<str>, KafkaListenerUsage>>>,
}

/// 一个 Kafka listener 跨快照连接共享的实时预留量。
#[cfg(feature = "kafka-governance")]
#[derive(Clone, Copy, Default)]
pub(super) struct KafkaListenerUsage {
    pub(super) connections: usize,
    pub(super) buffered_bytes: usize,
}

#[cfg(feature = "kafka-governance")]
impl KafkaConnectionBudget {
    /// 业务作用：在 PROXY/TLS/首 frame 前预留 Kafka 连接与双向 frame buffer，阻断慢握手绕过资源门。
    ///
    /// 参数说明：
    /// - `listener_id`：是稳定 listener 标识
    /// - `maximum`：是连接上限
    /// - `buffer_reservation`：是单连接双向预留
    /// - `maximum_buffered_bytes`：是 listener 聚合上限。
    ///
    /// 返回：预算充足时返回 RAII guard；连接或聚合 buffer 达上限时返回 None 且不改变计数。
    pub(super) fn try_acquire(
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
pub(super) struct KafkaConnectionGuard {
    pub(super) usage: Arc<ParkingMutex<HashMap<Arc<str>, KafkaListenerUsage>>>,
    pub(super) listener_id: Arc<str>,
    pub(super) buffer_reservation: usize,
}

#[cfg(feature = "kafka-governance")]
impl Drop for KafkaConnectionGuard {
    /// 业务作用：在任意退出路径归还 Kafka listener 名额，防止错误分支泄漏后永久拒绝新连接。
    ///
    /// 参数说明: 无。
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
#[derive(Clone)]
pub(super) struct UdpSessionHandle {
    pub(super) id: u64,
    pub(super) sender: mpsc::Sender<QueuedUdpDatagram>,
}

/// listener 级 UDP 内存硬预算。单会话 channel/receive buffer 各自有界仍不够：大量 client 可
/// 同时建 session 并填满各自 queue。256MiB 同时覆盖实际排队 payload 与每 session 的上游接收
/// buffer；semaphore 本身不预分配这块内存。
pub(super) const UDP_BUFFERED_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// 一份 UDP payload 及其字节预算。permit 与 `Bytes` 一起在 channel 中 move；发送完成、session
/// 建立失败或队列关闭时由 RAII 自动归还，不需要额外计数锁。
pub(super) struct QueuedUdpDatagram {
    pub(super) bytes: Bytes,
    pub(super) _permit: OwnedSemaphorePermit,
}

/// 业务作用：在排入 UDP 数据报之前预留节点缓冲额度，阻止突发输入绕过会话队列上限。
pub(super) fn reserve_udp_datagram(
    budget: &Arc<Semaphore>,
    payload: &[u8],
) -> Option<QueuedUdpDatagram> {
    let permits = u32::try_from(payload.len()).ok()?;
    // 先 reserve 再 copy：全局预算耗尽时不能仍为攻击流量分配 payload。
    let permit = budget.clone().try_acquire_many_owned(permits).ok()?;
    Some(QueuedUdpDatagram {
        bytes: Bytes::copy_from_slice(payload),
        _permit: permit,
    })
}

pub(super) static STREAM_UDP_SESSION_SEQ: AtomicU64 = AtomicU64::new(1);
/// IPv4 UDP payload 的协议最大值。listener 缓冲固定按协议上限分配一次，使
/// `udp.max_datagram_bytes` 热更调大后也不会继续被旧快照的小缓冲静默截断。
pub(super) const UDP_MAX_PAYLOAD_BYTES: usize = 65_507;

/// 业务作用：启动 UDP listener。主 socket 只做一次 datagram 接收与按客户端地址分派；每个活动
/// client 建一个 connected upstream socket，形成 `(client,listener,upstream)` 短会话。
/// channel 满或 session 表满时立即丢当前 datagram，绝不让单个慢上游反压整个 listener。
pub(super) fn spawn_stream_udp_loop(
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
            let Some(runtime) = current_stream_runtime(&state.snap, &bound_runtime.id) else {
                // 入口已经退休时不得以旧配置新建会话；既有会话只按自己的冻结配置结束。
                state.metrics.inc_stream_udp_drop();
                continue;
            };
            if length > runtime.udp.max_datagram_bytes {
                state.metrics.inc_stream_udp_drop();
                continue;
            }
            // 数据报必须从可复用监听缓冲区复制一次才能独立持有；全局字节 permit
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
                        // 复用关闭通道归还的数据报所有权，避免第二次正文复制。
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
        // 丢弃发送端使会话任务结束；已连接的 UDP socket 随之关闭，不具有 TCP RST 语义。
        sessions.lock().clear();
    });
}

/// 业务作用：固定 UDP 会话归属并预留容量，再建立有界队列与上游任务。
///
/// 参数说明：
/// - `listener`：为入口与目录
/// - `sessions`：为入口与目录
/// - `peer`：是首包
/// - `first`：是首包
/// - `runtime`：标识入口
/// - `state`：为常驻数据面
/// - `resource_budget`：限制正文内存。
///
/// 返回：容量、归属或选址失败时丢弃首包；成功时会话持有名额直至终止。
pub(super) fn create_udp_session(
    listener: Arc<UdpSocket>,
    sessions: Arc<ParkingMutex<HashMap<SocketAddr, UdpSessionHandle>>>,
    peer: SocketAddr,
    first: QueuedUdpDatagram,
    runtime: StreamRuntime,
    state: StreamPlaneState,
    resource_budget: Arc<Semaphore>,
) {
    let snapshot = state.snap.load_full();
    let Some(runtime) = snapshot
        .stream_listeners
        .iter()
        .find(|candidate| candidate.id == runtime.id)
        .cloned()
    else {
        state.metrics.inc_stream_udp_drop();
        return;
    };
    // 归属和上游必须来自同一快照，不能在异步初始化期间改用新 owner 的引用权限。
    let Ok(workspace_permit) = state
        .workspace_proxy
        .admit_stream_workspace(&snapshot, &runtime.id)
    else {
        state.metrics.inc_stream_udp_drop();
        return;
    };
    let Some(route) = runtime.routes.iter().find(|route| route.default).cloned() else {
        state.metrics.inc_stream_udp_drop();
        return;
    };
    let reservation = match resolve_stream_upstream(
        &snapshot,
        &route,
        &state.lb,
        &state.active_health,
        peer.ip(),
    ) {
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
    sessions.lock().insert(
        peer,
        UdpSessionHandle {
            id,
            sender,
        },
    );
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
        workspace_permit,
        state,
    ));
}

#[allow(clippy::too_many_arguments)]
/// 业务作用：在完整 UDP 会话生命周期内持有归属、连接和缓冲区预算并双向转发。
///
/// 参数说明：
/// - `listener`：已绑定的 UDP 入口。
/// - `sessions`：当前入口的会话目录。
/// - `id`：本次会话的唯一标识。
/// - `peer`：下游客户端地址。
/// - `runtime`：当前会话固定的运行态。
/// - `route`：已经选择的路由。
/// - `reservation`：已取得的上游选址与资源预留。
/// - `receiver`：首包及后续数据包的有界接收队列。
/// - `_receive_buffer_permit`：会话存活期间持有的接收缓冲区配额。
/// - `_workspace_permit`：会话存活期间持有的工作区容量。
/// - `state`：共享代理状态与观测依赖。
///
/// 返回：会话正常结束或任务取消后归还工作区容量，原目录仅删除匹配的会话。
pub(super) async fn run_udp_session(
    listener: Arc<UdpSocket>,
    sessions: Arc<ParkingMutex<HashMap<SocketAddr, UdpSessionHandle>>>,
    id: u64,
    peer: SocketAddr,
    runtime: StreamRuntime,
    route: StreamRouteRuntime,
    mut reservation: StreamUpstreamReservation,
    mut receiver: mpsc::Receiver<QueuedUdpDatagram>,
    _receive_buffer_permit: OwnedSemaphorePermit,
    _workspace_permit: gateway::proxy::StreamWorkspacePermit,
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
    let mut outlier = reservation.outlier.take();
    let probe_deadline = outlier.as_ref().and_then(|attempt| attempt.deadline());
    let result = async {
        let setup = async {
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
            upstream.connect(upstream_addr).await.context("connect UDP session socket")?;
            Ok::<_, anyhow::Error>(upstream)
        };
        let upstream = if let Some(deadline) = probe_deadline {
            // DNS 与本地 socket 建立也属于本次探测期限，不能在进入收包循环前无限持有恢复权。
            anyhow::ensure!(deadline > std::time::Instant::now(), "UDP probe authority expired before setup");
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), setup)
                .await.context("UDP probe setup deadline exceeded")??
        } else {
            setup.await?
        };
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
                    let Some(datagram) = maybe else {
                        break
                    };
                    if outlier.is_some() && probe_deadline.is_some_and(|deadline| deadline <= std::time::Instant::now()) {
                        anyhow::bail!("UDP probe authority expired before send");
                    }
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
                    // 首个有界上游回包才证明 UDP 可达；本地 connect 成功不能作为恢复证据。
                    if let Some(attempt) = outlier.take() {
                        attempt.complete(false, started.elapsed());
                    }
                    listener.send_to(&upstream_buffer[..length], peer).await.context("send UDP downstream datagram")?;
                    up = up.saturating_add(length as u64);
                    state.metrics.inc_stream_udp_datagram(false);
                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(runtime.udp.idle_timeout_ms));
                }
                _ = async {
                    if let Some(deadline) = probe_deadline {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if outlier.is_some() => {
                    anyhow::bail!("UDP recovery probe response deadline exceeded");
                }
                _ = &mut idle => {
                    if down > 0 {
                        if let Some(attempt) = outlier.take() {
                            attempt.complete(true, started.elapsed());
                        }
                    }
                    break;
                }
                _ = &mut total, if runtime.timeout_ms > 0 => {
                    if down > 0 {
                        if let Some(attempt) = outlier.take() {
                            attempt.complete(true, started.elapsed());
                        }
                    }
                    break;
                }
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
            if let Some(attempt) = outlier.take() {
                attempt.complete(true, started.elapsed());
            }
            record_stream_upstream_failure(&state, &reservation);
            state.metrics.inc_stream_error();
            log_stream_access(&state.access_log, &log_ctx, 502, 0, 0);
            tracing::debug!(stream = %runtime.id, %peer, %error, "UDP stream session failed");
        }
    }
    finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
}

/// 业务作用：启动 L4 stream TCP accept loop。
///
/// 参数说明：
/// - `listener`: 已绑定的 stream listener。
/// - `runtime`: stream 运行期配置。
/// - `state`: stream 数据面共享状态。
/// - `shutdown`: 停机广播。
/// - `tls`：与该入口绑定的可选 TLS 握手计划。
pub(super) fn spawn_stream_accept_loop(
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
/// 参数说明：
/// - `downstream`：是下游 TCP socket
/// - `peer`：是直连对端
/// - `bound_runtime`：是绑定 socket 的启动期兜底配置
/// - `tls`：是可热换的服务端 TLS
/// - `state`：是 stream 共享状态。
///
/// 返回：无；函数创建可取消任务，所有成功/失败路径均归还连接计数并记录低基数结果。
pub(super) fn spawn_stream_connection(
    downstream: TcpStream,
    peer: SocketAddr,
    bound_runtime: StreamRuntime,
    tls: Option<SharedServerConfig>,
    state: StreamPlaneState,
) {
    let snapshot = state.snap.load_full();
    let Some(runtime) = snapshot
        .stream_listeners
        .iter()
        .find(|candidate| candidate.id == bound_runtime.id)
        .cloned()
    else {
        // 已退休入口不再接受新连接，不能借启动配置继续取得业务上游。
        state.metrics.inc_stream_error();
        return;
    };
    let Ok(workspace_permit) = state
        .workspace_proxy
        .admit_stream_workspace(&snapshot, &runtime.id)
    else {
        // 在派生任务和 TLS/preread 之前拒绝，慢握手也必须消耗本域预算。
        state.metrics.inc_stream_error();
        return;
    };
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    state.metrics.inc_active_connection();
    state.metrics.inc_stream_connection();
    tokio::spawn(async move {
        let _workspace_permit = workspace_permit;
        let started = std::time::Instant::now();
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
                state.metrics.inc_stream_mqtt_rejection(
                    gateway::protocols::mqtt::MqttViolationKind::ResourceLimit,
                );
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
                state.metrics.inc_stream_kafka_rejection(
                    gateway::protocols::kafka::KafkaViolationKind::ResourceLimit,
                );
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
                    Ok(Ok(stream)) => {
                        if let Err(error) = gateway::tls::verify_client_certificate_spiffe(
                            stream.get_ref().1.peer_certificates(),
                            runtime
                                .tls
                                .as_ref()
                                .and_then(|tls| tls.client_auth.as_ref()),
                        ) {
                            warn!(stream = %runtime.id, peer = %peer, %error, "stream client SPIFFE identity rejected");
                            state.metrics.inc_stream_error();
                            log_stream_access(&state.access_log, &log_ctx, 403, 0, 0);
                            finish_stream_connection(
                                state.active_connections.clone(),
                                state.metrics.clone(),
                            );
                            return;
                        }
                        if let Err(error) = gateway::tls::verify_client_certificate_ocsp(
                            stream.get_ref().1.peer_certificates(),
                            runtime
                                .tls
                                .as_ref()
                                .and_then(|tls| tls.client_auth.as_ref()),
                        )
                        .await
                        {
                            warn!(stream = %runtime.id, peer = %peer, %error, "stream client certificate OCSP check failed");
                            state.metrics.inc_stream_error();
                            log_stream_access(&state.access_log, &log_ctx, 403, 0, 0);
                            finish_stream_connection(
                                state.active_connections.clone(),
                                state.metrics.clone(),
                            );
                            return;
                        }
                        Box::new(stream)
                    }
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
                        state.metrics.inc_stream_mqtt_rejection(
                            gateway::protocols::mqtt::MqttViolationKind::Malformed,
                        );
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
                state.metrics.inc_stream_mqtt_rejection(
                    gateway::protocols::mqtt::MqttViolationKind::Malformed,
                );
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            };
            if !policy.allows_client_id(client_id) {
                // client ACL 在 upstream resolve/dial 之前执行，被拒绝身份不得触达 broker 也不污染被动健康。
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT client id rejected by ACL");
                state.metrics.inc_stream_mqtt_rejection(
                    gateway::protocols::mqtt::MqttViolationKind::NotAuthorized,
                );
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 403, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            if !matches!(preread.mqtt_protocol_level, Some(4 | 5)) {
                warn!(stream = %runtime.id, peer = %peer, level = ?preread.mqtt_protocol_level, "stream MQTT governance rejects unsupported protocol level");
                state.metrics.inc_stream_mqtt_rejection(
                    gateway::protocols::mqtt::MqttViolationKind::Protocol,
                );
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            if preread.mqtt_packet_len != Some(preread.bytes.len()) {
                // CONNECT 之后的 pipelined 字节尚未经状态机，不能随 preread buffer 整段回放绕过 ACL/QoS 门。
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT client sent packets before CONNACK");
                state.metrics.inc_stream_mqtt_rejection(
                    gateway::protocols::mqtt::MqttViolationKind::Protocol,
                );
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 400, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
            }
            if preread.mqtt_clean_start != Some(true) {
                // 跨连接 persistent session 的订阅/QoS2 状态由 broker 持有，本地单连接硬门无法安全重建；
                // 治理 profile 因此只接受 Clean Session/Start，需持久会话时应显式使用透明 TCP profile。
                warn!(stream = %runtime.id, peer = %peer, "stream MQTT governance requires Clean Session/Start");
                state.metrics.inc_stream_mqtt_rejection(
                    gateway::protocols::mqtt::MqttViolationKind::Protocol,
                );
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
                Ok(Ok(stream)) => {
                    if let Err(error) = gateway::tls::verify_client_certificate_spiffe(
                        stream.get_ref().1.peer_certificates(),
                        runtime
                            .tls
                            .as_ref()
                            .and_then(|tls| tls.client_auth.as_ref()),
                    ) {
                        warn!(stream = %runtime.id, peer = %peer, %error, "selected stream client SPIFFE identity rejected");
                        state.metrics.inc_stream_error();
                        log_stream_access(&state.access_log, &log_ctx, 403, 0, 0);
                        finish_stream_connection(
                            state.active_connections.clone(),
                            state.metrics.clone(),
                        );
                        return;
                    }
                    if let Err(error) = gateway::tls::verify_client_certificate_ocsp(
                        stream.get_ref().1.peer_certificates(),
                        runtime
                            .tls
                            .as_ref()
                            .and_then(|tls| tls.client_auth.as_ref()),
                    )
                    .await
                    {
                        warn!(stream = %runtime.id, peer = %peer, %error, "selected stream client certificate OCSP check failed");
                        state.metrics.inc_stream_error();
                        log_stream_access(&state.access_log, &log_ctx, 403, 0, 0);
                        finish_stream_connection(
                            state.active_connections.clone(),
                            state.metrics.clone(),
                        );
                        return;
                    }
                    Box::new(stream)
                }
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
        let current_snap = snapshot;
        let mut reservation = match resolve_stream_upstream(
            &current_snap,
            route,
            &state.lb,
            &state.active_health,
            peer.ip(),
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
        let outlier = reservation.outlier.take();
        let connect = async {
            let connect = connect_stream_upstream(&reservation);
            if runtime.connect_timeout_ms == 0 {
                Ok(connect.await)
            } else {
                tokio::time::timeout(Duration::from_millis(runtime.connect_timeout_ms), connect)
                    .await
            }
        };
        let observed =
            gateway::upstream::passive::window::Attempt::observe(outlier, connect, |result| {
                Some(!matches!(result, Ok(Ok(_))))
            })
            .await;
        let upstream = match observed {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(()) => {
                warn!(stream = %runtime.id, peer = %peer, upstream = %upstream_addr, "stream upstream connect timeout");
                record_stream_upstream_failure(&state, &reservation);
                state.metrics.inc_stream_error();
                log_stream_access(&state.access_log, &log_ctx, 504, 0, 0);
                finish_stream_connection(state.active_connections.clone(), state.metrics.clone());
                return;
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
            let governed =
                gateway::protocols::mqtt::proxy(downstream, upstream, protocol_level, policy);
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
                            gateway::protocols::mqtt::MqttViolationKind::ResourceLimit,
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
                    if error.peer() == gateway::protocols::mqtt::MqttPeer::Broker {
                        record_stream_upstream_failure(&state, &reservation);
                    }
                    let status = match error.kind() {
                        gateway::protocols::mqtt::MqttViolationKind::NotAuthorized => 403,
                        gateway::protocols::mqtt::MqttViolationKind::PacketTooLarge => 413,
                        gateway::protocols::mqtt::MqttViolationKind::ResourceLimit => 429,
                        gateway::protocols::mqtt::MqttViolationKind::Malformed
                        | gateway::protocols::mqtt::MqttViolationKind::Protocol => 400,
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
            let governed = gateway::protocols::kafka::proxy(downstream, upstream, policy);
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
                            gateway::protocols::kafka::KafkaViolationKind::ResourceLimit,
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
                    if error.peer() == gateway::protocols::kafka::KafkaPeer::Broker {
                        record_stream_upstream_failure(&state, &reservation);
                    }
                    let status = match error.kind() {
                        gateway::protocols::kafka::KafkaViolationKind::NotAuthorized => 403,
                        gateway::protocols::kafka::KafkaViolationKind::FrameTooLarge => 413,
                        gateway::protocols::kafka::KafkaViolationKind::ResourceLimit => 429,
                        gateway::protocols::kafka::KafkaViolationKind::Malformed
                        | gateway::protocols::kafka::KafkaViolationKind::Protocol => 400,
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
pub(super) struct StreamPrereadResult {
    /// TLS ClientHello 中的 SNI。
    pub(super) sni: Option<String>,
    /// MQTT CONNECT 中的 client id。
    pub(super) mqtt_client_id: Option<String>,
    /// CONNECT 声明的 MQTT protocol level。
    #[cfg(feature = "mqtt-governance")]
    pub(super) mqtt_protocol_level: Option<u8>,
    /// CONNECT packet 的精确 wire 长度，用于拒绝未经治理的 pipelined packet。
    #[cfg(feature = "mqtt-governance")]
    pub(super) mqtt_packet_len: Option<usize>,
    /// CONNECT 的 Clean Session(v3.1.1)/Clean Start(v5) 位。
    #[cfg(feature = "mqtt-governance")]
    pub(super) mqtt_clean_start: Option<bool>,
    /// 已从下游读取、必须原样写给上游的字节。
    pub(super) bytes: Vec<u8>,
}

/// 业务作用：根据 TLS preread SNI 或 MQTT client id 选择唯一 stream route，保证精确
/// SNI 优先于 wildcard，且更长的 wildcard suffix 优先，避免流量落入宽泛租户路由。
///
/// 参数说明：
/// - `runtime`：是当前 stream listener 快照
/// - `sni`：来自有界 preread。
/// - `mqtt_client_id`：来自有界 preread。
///
/// 返回：返回优先级最高的匹配路由；没有显式匹配时返回 default，仍无匹配则拒绝连接。
pub(super) fn select_stream_route<'a>(
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
/// 参数说明：
/// - `routes`：是同一 listener 的已验证 route
/// - `sni`：是规范化的小写 hostname。
///
/// 返回：精确路由存在时返回精确路由；否则返回最具体 wildcard；没有匹配时返回 None。
pub(super) fn select_stream_sni_route<'a>(
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
/// 参数说明：
/// - `pattern`：是已小写化的 route SNI
/// - `sni`：是已小写化的 ClientHello SNI。
///
/// 返回：精确或合法 `*.` suffix 匹配时返回 true，其余模式与 apex 返回 false。
pub(super) fn stream_sni_matches(pattern: &str, sni: &str) -> bool {
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

/// 业务作用：读取当前快照里的 stream listener 配置。
///
/// 参数说明：
/// - `snap`: 当前配置快照指针。
/// - `stream_id`: 启动期已绑定 listener 的 id。
pub(super) fn current_stream_runtime(
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
pub(super) struct StreamUpstreamReservation {
    /// 可直接传给 `TcpStream::connect` 的地址。
    pub(super) addr: String,
    /// access log 展示用目标。`lb://` 时记录选中实例 URI,直连时记录地址。
    pub(super) log_target: Arc<str>,
    /// 需要参与被动健康记录的上游实例身份键。
    pub(super) selected_health_key: Option<Arc<str>>,
    /// 服务级被动健康策略。
    pub(super) passive_policy: PassiveHealthPolicy,
    /// 同一实例目录授予的窗口观察权；TCP 到握手完成，UDP 到首个响应包结束观察。
    pub(super) outlier: Option<gateway::upstream::passive::window::Attempt>,
    /// 已解析的 raw TCP TLS client profile；None 表示明文上游。
    pub(super) tls_profile: Option<gateway::tls::UpstreamTlsProfile>,
    /// profile 未覆盖 SNI 时使用的目标 host；构建/解析后共享，不在握手时切字符串。
    pub(super) tls_server_name: Option<Arc<str>>,
    /// `least_conn` 常驻计数器；直连地址不参与服务级 LB，故为空。
    pub(super) counter: Option<Arc<AtomicU64>>,
    /// true 表示 Drop 必须归还计数；为后续显式移交所有权预留不重复释放的不变式。
    pub(super) release_on_drop: bool,
}

impl Drop for StreamUpstreamReservation {
    /// 业务作用：TCP 隧道结束、连接失败或 task 被取消时统一归还 `least_conn` 名额。
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
/// 参数说明：
/// - `state`：是 stream 数据面共享状态
/// - `reservation`：是本次选中的上游 reservation。
///
/// 返回：无返回值；逻辑服务目标会更新被动健康状态，直连目标不产生副作用。
pub(super) fn record_stream_upstream_success(
    state: &StreamPlaneState,
    reservation: &StreamUpstreamReservation,
) {
    if let Some(health_key) = reservation.selected_health_key.as_deref() {
        state.lb.record_success(health_key);
    }
}

/// 业务作用：记录 stream 上游失败。
///
/// 参数说明：
/// - `state`: stream 数据面共享状态。
/// - `reservation`: 本次选中的上游 reservation。
pub(super) fn record_stream_upstream_failure(
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
/// 参数说明：
/// - `snap`：是当前配置快照
/// - `route`：是已匹配路由
/// - `stream_lb`：保存游标、失败与在途状态
/// - `active_health`：提供主动健康排除集合。
/// - `peer`：传输层确认的来源 IP；TCP 已应用受信 PROXY protocol，UDP 使用实际报文来源。
///
/// 返回：目标可解析且存在健康实例时返回必须在连接结束时释放的 reservation；引用缺失、
/// 地址非法或没有健康实例时返回错误且不建立上游连接。
pub(super) fn resolve_stream_upstream(
    snap: &GatewaySnapshot,
    route: &StreamRouteRuntime,
    stream_lb: &StreamLbState,
    active_health: &gateway::upstream::health::ActiveHealthChecker,
    peer: IpAddr,
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
        let outlier_group =
            snap.upstreams
                .outlier_group(&stream_lb.health, service, snap.version)?;
        let window_excluded = outlier_group
            .as_ref()
            .map(|group| group.blocked())
            .unwrap_or_default();
        let passive_excluded = stream_lb.ejected_upstreams(passive_policy);
        let active_facts = active_health.unhealthy_set();
        // L4 与 HTTP 按同一当前服务策略读取，不能继承相同端点在其它服务中的探测拒绝。
        let active_unhealthy =
            active_facts.service(service, snap.upstreams.active_health_identity(service));
        let mut hints = gateway::upstream::LbSelectHints::default();
        if matches!(
            snap.upstreams.hash_source(service),
            Some(gateway::upstream::LbHashSource::RemoteAddr)
        ) {
            // 只在建连时规范化受信来源；不解析隧道内 HTTP 头，也不允许业务 payload 改写路由键。
            hints.hash = Some(gateway::upstream::hash::stable_hash(
                peer.to_string().as_bytes(),
            ));
        }
        let feedback = snap
            .upstreams
            .load_feedback(service)
            .filter(|policy| policy.enabled());
        let feedback_now = feedback.map(|_| gateway::upstream::load::monotonic_ms());
        let feedback_baseline = feedback.zip(feedback_now).and_then(|(policy, now)| {
            snap.upstreams
                .load_feedback_baseline_observed(service, |instance| {
                    stream_lb
                        .health
                        .load_score(instance, snap.version, policy, now)
                })
        });
        let mut inflight = stream_lb.inflight.lock();
        let inst = snap
            .upstreams
            .select_instance_observed(
                service,
                hints,
                |health_key| {
                    passive_excluded
                        .iter()
                        .any(|excluded| excluded == health_key)
                        || window_excluded
                            .iter()
                            .any(|excluded| excluded.as_ref() == health_key)
                        || active_unhealthy.contains(health_key)
                },
                |instance| {
                    // L4 不解析不透明业务字节，只消费同服务、同代的共享负载反馈；缺证据统一回落连接数。
                    if let Some(baseline) = feedback_baseline {
                        return stream_lb
                            .health
                            .load_score(
                                instance,
                                snap.version,
                                feedback.expect("feedback baseline has policy"),
                                feedback_now.expect("feedback baseline has timestamp"),
                            )
                            .unwrap_or(baseline);
                    }
                    inflight
                        .get(instance.health_key.as_ref())
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
        // 选择快照可能与另一个恢复探测并发；真正预留前再次取得独占权，拒绝重复探测。
        let outlier = outlier_group
            .as_ref()
            .map(|group| {
                group
                    .acquire(&health_key)
                    .context("stream outlier probe is unavailable")
            })
            .transpose()?;
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
            outlier,
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
        outlier: None,
        tls_profile,
        tls_server_name,
        counter: None,
        release_on_drop: false,
    })
}

/// 业务作用：按 Gateway API backendRef 权重为每条 TCP 连接或 UDP session 选择逻辑上游，
/// 并让零权重后端永不进入数据面。
///
/// 参数说明：
/// - `route`：是不可变路由快照
/// - `stream_lb`：持有跨 reload 单调游标。
///
/// 返回：带权集合非空时返回按累计权重命中的目标；否则返回兼容单一 `upstream`。
pub(super) fn select_weighted_stream_upstream<'a>(
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

/// 业务作用：把上游服务实例 URI 转换为 stream TCP dial 地址。
///
/// 参数说明：
/// - `uri`: `UpstreamDirectory` 选出的实例 URI。
pub(super) fn stream_addr_from_upstream_uri(uri: &str) -> Result<(String, bool, String)> {
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

/// 业务作用：默认平台根证书 profile 只构建一次；不在每条 L4 TLS 连接重复加载系统 trust store。
pub(super) fn default_stream_upstream_tls_profile() -> Result<gateway::tls::UpstreamTlsProfile> {
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

/// 业务作用：建立明文或 TLS stream 上游。TLS 握手属于 connect deadline，避免 TCP 已连但 TLS
/// dependency 卡住时绕过 `connect_timeout_ms`。Box 仅按连接分配一次，payload 不聚合。
pub(super) async fn connect_stream_upstream(
    reservation: &StreamUpstreamReservation,
) -> Result<BoxStreamIo> {
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
/// 参数说明：
/// - `downstream`：是已完成 PROXY/TLS 的下游流
/// - `timeout_ms`：是整个 CONNECT deadline
/// - `max_bytes`：是 preread 累计硬门。
///
/// 返回：完整合法 CONNECT 的 client id、level、packet 长度和已读 wire；慢包、超长、截断或
/// 畸形 CONNECT 返回错误，不连接上游。
pub(super) async fn stream_preread_mqtt_connect(
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

pub(super) enum MqttConnectParse<'a> {
    NeedMore,
    Complete(MqttConnectInfo<'a>),
}

/// CONNECT preread 只借用当前有界 buffer 的解析结果。
pub(super) struct MqttConnectInfo<'a> {
    pub(super) client_id: &'a str,
    #[cfg(feature = "mqtt-governance")]
    pub(super) protocol_level: u8,
    #[cfg(feature = "mqtt-governance")]
    pub(super) packet_len: usize,
    #[cfg(feature = "mqtt-governance")]
    pub(super) clean_start: bool,
}

/// 业务作用：解析 MQTT 3.1/3.1.1/5 CONNECT 的协议名、level、flags、properties 边界与 client id，
/// 防止畸形长度被误当 default route。
///
/// 参数说明：
/// - `bytes`：是从连接起始累积的有界 preread buffer。
///
/// 返回：字段尚未到齐时 NeedMore；完整时返回借用 client id、level 和 CONNECT wire 终点；
/// 非 CONNECT、非法 VBI/flags/protocol/UTF-8 返回错误。
pub(super) fn parse_mqtt_connect_client_id(bytes: &[u8]) -> Result<MqttConnectParse<'_>> {
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
/// 参数说明：
/// - `bytes`：是 preread buffer
/// - `start`：是 VBI 起始偏移。
///
/// 返回：完整时返回 `(value,next_cursor)`，字节未到齐返回 None，超四字节/溢出返回错误。
pub(super) fn decode_mqtt_variable_byte_integer(
    bytes: &[u8],
    start: usize,
) -> Result<Option<(usize, usize)>> {
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
/// 参数说明：
/// - `value`：是已有界解码的非负整数。
///
/// 返回：编码该值需要的 1–4 字节数。
pub(super) fn mqtt_variable_integer_len(mut value: usize) -> usize {
    let mut length = 1;
    while value >= 128 {
        value /= 128;
        length += 1;
    }
    length
}

/// 业务作用：从 CONNECT packet 边界内读取两字节长度前缀的 UTF-8 字段。
///
/// 参数说明：
/// - `bytes`：是 preread buffer
/// - `cursor`：会移到字段末尾
/// - `end`：是 CONNECT 精确终点。
///
/// 返回：边界内的借用 UTF-8 字符串；长度越界或非 UTF-8 返回错误。
pub(super) fn mqtt_utf8<'a>(bytes: &'a [u8], cursor: &mut usize, end: usize) -> Result<&'a str> {
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
/// 参数说明：
/// - `bytes`：是 preread buffer
/// - `cursor`：会移到字段末尾
/// - `end`：是 CONNECT 终点。
///
/// 返回：边界内的借用 binary 切片；长度截断或溢出返回错误。
pub(super) fn mqtt_binary<'a>(bytes: &'a [u8], cursor: &mut usize, end: usize) -> Result<&'a [u8]> {
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
/// 参数说明：
/// - `downstream`：是下游 TCP 字节流
/// - `timeout_ms`：是整个 preread deadline，0 表示 不限制
/// - `max_bytes`：是 ClientHello 累计读取硬门。
///
/// 返回：解析到的可选 SNI 和必须回放给上游的原始字节；读取 IO/deadline 失败返回错误。
pub(super) async fn stream_preread_sni(
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
pub(super) enum TlsSniParse {
    /// 已解析完成;没有 SNI 时为 None。
    Complete(Option<String>),
    /// 需要更多字节。
    NeedMore,
    /// 当前流不是 TLS ClientHello。
    NotTls,
}

/// 业务作用：从 TLS ClientHello 解析 SNI。
///
/// 参数说明：
/// - `bytes`: 从 TCP 流 preread 到的字节。
pub(super) fn parse_tls_client_hello_sni(bytes: &[u8]) -> TlsSniParse {
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

/// 业务作用：从 ClientHello body 解析 server_name 扩展。
///
/// 参数说明：
/// - `body`: TLS handshake ClientHello body。
pub(super) fn parse_client_hello_body_sni(body: &[u8]) -> Option<String> {
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

/// 业务作用：解析 server_name 扩展。
///
/// 参数说明：
/// - `ext`: server_name 扩展 body。
pub(super) fn parse_sni_extension(ext: &[u8]) -> Option<String> {
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

/// 业务作用：从切片读取固定长度并推进游标。
///
/// 参数说明：
/// - `bytes`: 源切片。
/// - `pos`: 当前游标。
/// - `len`: 读取长度。
pub(super) fn read_exact_advance<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    let out = &bytes[*pos..end];
    *pos = end;
    Some(out)
}

/// 业务作用：从切片读取 u16 并推进游标。
///
/// 参数说明：
/// - `bytes`: 源切片。
/// - `pos`: 当前游标。
pub(super) fn read_u16_advance(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let value = read_exact_advance(bytes, pos, 2)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

/// 业务作用：释放 L4 stream 连接计数。
///
/// 参数说明：
/// - `active_connections`: 进程级连接数计数。
/// - `metrics`: 共享 metrics。
pub(super) fn finish_stream_connection(active_connections: Arc<AtomicU64>, metrics: Arc<Metrics>) {
    active_connections.fetch_sub(1, Ordering::Relaxed);
    metrics.dec_active_connection();
    metrics.dec_stream_connection();
}

pub(super) struct StreamAccessLogCtx {
    pub(super) request_id: String,
    pub(super) stream_id: Arc<str>,
    pub(super) upstream: Arc<str>,
    pub(super) peer: String,
    pub(super) started: std::time::Instant,
}

pub(super) static STREAM_REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);

/// 业务作用：生成 stream access log 的连接 id。
pub(super) fn next_stream_request_id() -> String {
    let seq = STREAM_REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("stream-{seq:016x}")
}

/// 业务作用：写入一条 L4 stream 连接级 access log。
///
/// 参数说明：
/// - `access_log`: 非阻塞 access log。
/// - `ctx`: stream 连接上下文。
/// - `status`: 网关侧归一化状态码。
/// - `downstream_to_upstream`: 下游到上游字节数。
/// - `upstream_to_downstream`: 上游到下游字节数。
pub(super) fn log_stream_access(
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
        route_chain: None,
        upstream: Some(ctx.upstream.clone()),
        upstream_attempts: 1,
        status,
        elapsed: ctx.started.elapsed(),
        peer: ctx.peer.clone(),
        bytes_downstream_to_upstream: Some(downstream_to_upstream),
        bytes_upstream_to_downstream: Some(upstream_to_downstream),
    });
}
/// L4 正文传输抽象；装箱只在接入连接时分配一次，不按帧分配。
/// TCP/TLS 组合共用转发循环，`copy_bidirectional` 仍按固定大小分块搬运，内存有界且不聚合应用消息。
pub(super) trait StreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> StreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub(super) type BoxStreamIo = Box<dyn StreamIo>;

/// 在不复制后续载荷的前提下，将 preread 字节先回放给协议栈，再继续读取真实下游连接。
pub(super) struct ReplayStreamIo {
    /// 尚未回放完的有界 preread 缓冲。
    pub(super) prefix: Vec<u8>,
    /// 下一次回放位置。
    pub(super) offset: usize,
    /// preread 后的真实下游 IO。
    pub(super) inner: BoxStreamIo,
}

impl ReplayStreamIo {
    /// 业务作用：把已消费的 ClientHello 与原连接重新拼成连续 TLS 字节流。
    ///
    /// 参数说明：
    /// - `prefix`：是有界 preread 字节
    /// - `inner`：是读取位置已经越过该前缀的连接。
    ///
    /// 返回：返回从前缀起始位置读取、写操作直达原连接的 IO wrapper。
    pub(super) fn new(prefix: Vec<u8>, inner: BoxStreamIo) -> Self {
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
    /// 参数说明：
    /// - `cx`：遵循 Tokio `AsyncRead` 契约。
    /// - `buf`：遵循 Tokio `AsyncRead` 契约。
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
    /// 参数说明：
    /// - `cx`：遵循 Tokio `AsyncWrite` 契约。
    /// - `buf`：遵循 Tokio `AsyncWrite` 契约。
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
    /// 参数说明：
    /// - `cx`：遵循 Tokio `AsyncWrite` 契约。
    ///
    /// 返回：透传底层刷新结果。
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    /// 业务作用：关闭原连接的写半部，保持 TLS shutdown 的传输语义。
    ///
    /// 参数说明：
    /// - `cx`：遵循 Tokio `AsyncWrite` 契约。
    ///
    /// 返回：透传底层关闭结果。
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}
