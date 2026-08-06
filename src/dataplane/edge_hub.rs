//! V8-1/V8-2 gRPC 边缘模式运行时(架构规范 §25.2.4/§25.2.5)。
//!
//! 本模块整体由 feature `grpc-edge` 门控(见 lib.rs):默认构建不编译、不改变任何
//! 默认路径行为(A10)。V8-1 落 Subscribe 侧:增量解帧器、双维有界 EdgeRing、
//! tenant 作用域的 EdgeHub 订阅索引、channel-backed 订阅响应 Body 与治理关闭;
//! V8-2 落发布面本地散出:`publish_group`/`push_user` 共享 fanout 内核(唯一
//! payload 租约 + Drop 链预算结算 + 在途任务门)、unary 回执自产与 PublishStream
//! 节流令牌桶(`StreamRateGate`,背压不丢)。跨节点 relay/probe 归 V8-3/V8-4,
//! 本文件不含任何跨节点通信。
//!
//! 并发纪律(§25.2.5):所有锁内操作都是 O(1)/O(丢弃数) 的非等待操作;绝不在
//! DashMap guard 或 group 锁下 await、写 socket 或访问外部存储。

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use futures::task::AtomicWaker;
use http::header::HeaderValue;
use hyper::body::{Body, Frame, SizeHint};
use parking_lot::Mutex;
use tokio::time::{Instant as TokioInstant, Sleep};

use crate::conn_registry::{CloseNotified, ConnGuard};
use crate::grpc_edge::GrpcEdgePlan;
use crate::resp::BoxError;

/// gRPC message 前缀:compressed flag 1B + 大端长度 4B。
pub const GRPC_PREFIX_BYTES: usize = 5;

/// SubReq 读取总预算:登记 session 之前的有界读取,慢/停滞客户端在这里被掐断,
/// 不占索引、不占注册表(§25.2.3 相位序:失败永远发生在登记之前)。
pub const SUBSCRIBE_READ_DEADLINE: Duration = Duration::from_secs(10);

// ── 增量解帧器(§25.2.4 NeedPrefix/NeedPayload/EOS 状态机) ──

/// 解帧错误;映射到 gRPC status 的职责在调用方(协议层错误一律 INVALID_ARGUMENT,
/// 超限走 RESOURCE_EXHAUSTED)。
#[derive(Debug, PartialEq, Eq)]
pub enum GrpcDecodeError {
    /// compressed flag != 0:edge 面强制 identity(§25.2.3),压缩帧直接拒绝。
    CompressedFlag,
    /// prefix 声明的 message 长度超过 `max_msg_bytes`;在分配重组缓冲之前拒绝。
    MessageTooLarge {
        /// prefix 声明的 body 长度。
        declared: usize,
    },
    /// EOS 落在半个 prefix/payload 中间:客户端截断,非法。
    TruncatedMessage,
}

/// 解帧状态。
enum DecodeState {
    /// 还差 0..5 字节凑齐 prefix。
    Prefix {
        /// 已收集的 prefix 字节。
        header: [u8; GRPC_PREFIX_BYTES],
        /// 已填充长度。
        filled: usize,
    },
    /// prefix 已定,正在收集 payload;`frame` 里已含 5 字节 prefix。
    Payload {
        /// 有界重组缓冲(容量恰为 5+len,收满即产出)。
        frame: BytesMut,
        /// 目标总长(5+len)。
        total: usize,
    },
}

/// 有界增量 gRPC message 解帧器。
///
/// 产出单位恒为完整的 `[5B prefix + protobuf body]` 帧(§25.2.4:订阅队列/重组
/// 单位是完整帧,绝不把半条 message 暴露给下游)。同一 `Bytes` chunk 内 prefix 与
/// payload 连续时零拷贝 slice;跨 chunk 才分配恰好 `5+len` 的重组缓冲。
pub struct GrpcMessageDecoder {
    /// 单条 message body(不含 prefix)上限;读 prefix 后、分配缓冲前检查。
    max_msg_bytes: usize,
    state: DecodeState,
    /// 跨 chunk 重组累计复制的字节数,供 `payload_reassembly_bytes` 指标诚实上报
    /// (§25.2.8:`fanout_serialize` 只证明没做 protobuf marshal,不掩盖重组复制)。
    reassembled_bytes: u64,
}

impl GrpcMessageDecoder {
    /// 新建解帧器。
    pub fn new(max_msg_bytes: usize) -> Self {
        Self {
            max_msg_bytes,
            state: DecodeState::Prefix {
                header: [0; GRPC_PREFIX_BYTES],
                filled: 0,
            },
            reassembled_bytes: 0,
        }
    }

    /// 送入一个 DATA chunk,把解出的完整帧追加进 `out`。
    ///
    /// # 参数
    /// - `chunk`: 本次到达的字节;函数会消费它(split_to),调用后剩余为空。
    /// - `out`: 完整帧输出;一个 chunk 可产出 0..N 帧。
    pub fn feed(&mut self, chunk: &mut Bytes, out: &mut Vec<Bytes>) -> Result<(), GrpcDecodeError> {
        while !chunk.is_empty() {
            match &mut self.state {
                DecodeState::Prefix { header, filled } => {
                    // 快路径:缓冲为空且本 chunk 含完整帧 → 整帧零拷贝 slice。
                    if *filled == 0 && chunk.len() >= GRPC_PREFIX_BYTES {
                        let declared = parse_prefix(&chunk[..GRPC_PREFIX_BYTES])?;
                        if declared > self.max_msg_bytes {
                            return Err(GrpcDecodeError::MessageTooLarge { declared });
                        }
                        let total = GRPC_PREFIX_BYTES + declared;
                        if chunk.len() >= total {
                            out.push(chunk.split_to(total));
                            continue;
                        }
                        // 跨 chunk:恰量分配,把已有部分搬进重组缓冲。
                        let mut frame = BytesMut::with_capacity(total);
                        frame.extend_from_slice(chunk);
                        self.reassembled_bytes += chunk.len() as u64;
                        chunk.clear();
                        self.state = DecodeState::Payload { frame, total };
                        continue;
                    }
                    // 慢路径:prefix 本身被切开,逐字节凑满 5 字节再判长度。
                    let need = GRPC_PREFIX_BYTES - *filled;
                    let take = need.min(chunk.len());
                    header[*filled..*filled + take].copy_from_slice(&chunk[..take]);
                    *filled += take;
                    let taken = chunk.split_to(take);
                    self.reassembled_bytes += taken.len() as u64;
                    if *filled < GRPC_PREFIX_BYTES {
                        continue;
                    }
                    let declared = parse_prefix(&header[..])?;
                    if declared > self.max_msg_bytes {
                        return Err(GrpcDecodeError::MessageTooLarge { declared });
                    }
                    let total = GRPC_PREFIX_BYTES + declared;
                    let mut frame = BytesMut::with_capacity(total);
                    frame.put_slice(&header[..]);
                    if total == GRPC_PREFIX_BYTES {
                        // 零长度 protobuf message 在 prefix 最后一字节恰好位于 chunk 尾部时，
                        // 已经是一条完整消息；不能等一个永远不会到来的后续 DATA 才产出。
                        out.push(frame.freeze());
                        self.state = DecodeState::Prefix {
                            header: [0; GRPC_PREFIX_BYTES],
                            filled: 0,
                        };
                    } else {
                        self.state = DecodeState::Payload { frame, total };
                    }
                }
                DecodeState::Payload { frame, total } => {
                    let need = *total - frame.len();
                    let take = need.min(chunk.len());
                    frame.extend_from_slice(&chunk[..take]);
                    self.reassembled_bytes += take as u64;
                    let _ = chunk.split_to(take);
                    if frame.len() == *total {
                        let complete = std::mem::take(frame).freeze();
                        out.push(complete);
                        self.state = DecodeState::Prefix {
                            header: [0; GRPC_PREFIX_BYTES],
                            filled: 0,
                        };
                    }
                }
            }
        }
        Ok(())
    }

    /// EOS 合法性:只有正好停在"无半帧"的 Prefix(0) 状态才合法(§25.2.4)。
    pub fn finish(&self) -> Result<(), GrpcDecodeError> {
        match &self.state {
            DecodeState::Prefix { filled: 0, .. } => Ok(()),
            _ => Err(GrpcDecodeError::TruncatedMessage),
        }
    }

    /// 跨 chunk 重组累计复制字节(诚实指标;零拷贝快路径不累计)。
    pub fn reassembled_bytes(&self) -> u64 {
        self.reassembled_bytes
    }
}

/// 解析 5 字节 prefix,返回 body 长度。
fn parse_prefix(prefix: &[u8]) -> Result<usize, GrpcDecodeError> {
    if prefix[0] != 0 {
        return Err(GrpcDecodeError::CompressedFlag);
    }
    Ok(u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]) as usize)
}

/// 有界读取"恰好一个 message + EOS"(Subscribe 的 SubReq 与 unary Publish/Push 的
/// FramePush 同一契约,§25.2.3)。
///
/// # 参数
/// - `body`: 下游请求 body。
/// - `max_msg_bytes`: 单条 message 上限(route `limits.max_msg_bytes`)。
/// - `deadline`: 总读取预算;慢/停滞客户端不能占住注册前的处理任务。
///
/// 返回:完整 `[prefix+payload]` 帧 + 跨 DATA 重组字节(诚实指标,零拷贝快路径为 0)。
/// 多于一个 message、半帧 EOS、压缩位、超限、超时都拒绝——失败路径永远发生在
/// 登记 session / 散出之前。
pub async fn read_single_message<B>(
    body: B,
    max_msg_bytes: usize,
    deadline: Duration,
) -> Result<(Bytes, u64), SingleMessageError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    tokio::time::timeout(deadline, async move {
        let mut body = std::pin::pin!(body);
        let mut decoder = GrpcMessageDecoder::new(max_msg_bytes);
        let mut frames: Vec<Bytes> = Vec::with_capacity(1);
        while let Some(next) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
            let frame = next.map_err(|error| SingleMessageError::Transport(error.into()))?;
            match frame.into_data() {
                Ok(mut data) => {
                    decoder
                        .feed(&mut data, &mut frames)
                        .map_err(SingleMessageError::Decode)?;
                    if frames.len() > 1 {
                        return Err(SingleMessageError::ExtraMessage);
                    }
                }
                // gRPC 请求侧不该有 trailers;出现即协议错误。
                Err(_trailers) => return Err(SingleMessageError::UnexpectedTrailers),
            }
        }
        decoder.finish().map_err(SingleMessageError::Decode)?;
        match frames.len() {
            1 => Ok((frames.remove(0), decoder.reassembled_bytes())),
            0 => Err(SingleMessageError::MissingMessage),
            _ => Err(SingleMessageError::ExtraMessage),
        }
    })
    .await
    .map_err(|_| SingleMessageError::Deadline)?
}

/// SubReq 读取失败分类;调用方据此映射 gRPC status。
pub enum SingleMessageError {
    /// framing/压缩位/截断(→ INVALID_ARGUMENT)。
    Decode(GrpcDecodeError),
    /// 超过 `max_msg_bytes` 之外的第二条 message(→ INVALID_ARGUMENT)。
    ExtraMessage,
    /// EOS 前一个 message 都没有(→ INVALID_ARGUMENT)。
    MissingMessage,
    /// 请求侧出现 trailers(→ INVALID_ARGUMENT)。
    UnexpectedTrailers,
    /// 读取超时(→ INVALID_ARGUMENT;慢发送方不占注册前资源)。
    Deadline,
    /// 传输层错误(连接问题,无法回包也无需回包)。
    Transport(BoxError),
}

// ── EdgeRing:双维有界、单消费者、锁内非等待 ──

/// 关闭原因;决定订阅 body 收尾 trailer 的 `grpc-status`/`grpc-message`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeCloseReason {
    /// 管理面/换版 drain(→ 14 "gateway draining")。
    Drain,
    /// 按 IP/consumer 策略封禁(→ 14 "gateway policy violation")。
    Policy,
    /// route 级最长存活到期(→ 14 "gateway max age")。
    MaxAge,
    /// route 级帧间空闲到期(→ 14 "gateway idle")。
    Idle,
    /// close_slow 策略断开慢消费者(→ 14 "gateway slow consumer")。
    SlowConsumer,
    /// single_session 新登录建立 fence 后替换旧连接(→ 10 "session replaced")。
    SessionReplaced,
    /// 正常业务收尾(→ 0)。
    Normal,
}

impl EdgeCloseReason {
    /// trailer 的 (grpc-status, grpc-message)。message 按 gRPC 规范 percent-escaped。
    pub fn trailer(self) -> (HeaderValue, HeaderValue) {
        let (status, message) = match self {
            Self::Normal => ("0", "gateway%20close"),
            Self::Drain => ("14", "gateway%20draining"),
            Self::Policy => ("14", "gateway%20policy%20violation"),
            Self::MaxAge => ("14", "gateway%20max%20age"),
            Self::Idle => ("14", "gateway%20idle"),
            Self::SlowConsumer => ("14", "gateway%20slow%20consumer"),
            Self::SessionReplaced => ("10", "session%20replaced"),
        };
        (
            HeaderValue::from_static(status),
            HeaderValue::from_static(message),
        )
    }
}

/// push 结果;V8-2 fanout 据此计数/断开。
#[derive(Debug, PartialEq, Eq)]
pub enum RingPush {
    /// 已入队。
    Enqueued,
    /// drop_oldest:为腾位弹掉了 n 条旧帧后入队。
    DroppedOldest(usize),
    /// drop_new:队满,本帧被拒。
    DroppedNew,
    /// close_slow:队满即关流;本帧被拒且 ring 进入关闭态。
    ClosedSlow,
    /// ring 已关闭,帧被拒。
    Closed,
}

/// 唯一 payload 的驻留租约(§25.2.4):`Bytes` 自带引用计数,禁止 `Arc<Bytes>`;
/// 需要"唯一 payload 内存"记账时用本类型——permit 只按唯一 payload 申请一次,
/// 所有队列仅复制小型 `Arc<PayloadLease>`,最后一个引用离开时归还节点预算。
pub struct PayloadLease {
    /// 帧全长(prefix+body),即申请的预算量。
    len: usize,
    hub: Arc<EdgeHub>,
}

impl Drop for PayloadLease {
    fn drop(&mut self) {
        self.hub
            .payload_bytes
            .fetch_sub(self.len, Ordering::Relaxed);
    }
}

/// 队列元素:业务帧字节 + 共享 payload 租约。`bytes` clone 是引用计数,
/// 元素本身 Drop 即结束该队列对唯一 payload 的一份驻留引用。
pub struct QueuedFrame {
    /// 完整 `[prefix+body]` 帧;订阅 body 直接以它写 DATA。
    pub bytes: Bytes,
    _lease: Arc<PayloadLease>,
    /// 队列引用记账:构造 +1、Drop -1;弹旧/清队/交付全部经 Drop 自动结算,
    /// 任何路径都不可能漏减(§25.2.5 queue_refs 预算)。
    _queue_ref: QueueRefGuard,
}

impl std::fmt::Debug for QueuedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedFrame")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// 节点队列引用守卫。
struct QueueRefGuard {
    hub: Arc<EdgeHub>,
}

impl QueueRefGuard {
    fn try_new(hub: Arc<EdgeHub>, max: usize) -> Option<Self> {
        try_reserve(&hub.queue_refs, 1, max).then_some(Self { hub })
    }
}

impl Drop for QueueRefGuard {
    fn drop(&mut self) {
        self.hub.queue_refs.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 并发 fanout 任务守卫(构造 +1/Drop -1;publish 在途门)。
struct FanoutJobGuard {
    hub: Arc<EdgeHub>,
}

impl Drop for FanoutJobGuard {
    fn drop(&mut self) {
        self.hub.fanout_jobs.fetch_sub(1, Ordering::Relaxed);
    }
}

/// ring 内部状态;单把 `parking_lot::Mutex` 下全部操作 O(1)/O(弹出数),无等待。
struct RingInner {
    queue: VecDeque<QueuedFrame>,
    /// 队内逻辑字节(帧全长累计);与消息数构成双维预算。
    bytes: usize,
    closed: Option<EdgeCloseReason>,
}

/// 溢出策略的运行时形态(由 V8-0R 配置枚举映射;latest_by_key 的 key 语义要等
/// V8-2 的 publish envelope 定型,当前按 drop_oldest 执行并在计划构建处注释)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RingOverflow {
    /// 弹旧入新(同一临界区释放旧帧字节配额后入队,普通 mpsc 冒充不了,§25.2.5)。
    DropOldest,
    /// 拒新保旧 FIFO。
    DropNew,
    /// 队满即关流。
    CloseSlow,
}

/// 每订阅流一份的双维有界发送环。
///
/// 单消费者(订阅响应 body)+ 多生产者(V8-2 fanout);消费者侧用 `AtomicWaker`
/// 订阅唤醒。所有维度(消息数/逻辑字节)在同一临界区内维护,保证预算恒等式。
pub struct EdgeRing {
    inner: Mutex<RingInner>,
    consumer: AtomicWaker,
    max_messages: usize,
    max_bytes: usize,
    overflow: RingOverflow,
    /// 因溢出被丢弃的帧计数(gap 观测;§25.2.8)。
    dropped: AtomicU64,
}

impl EdgeRing {
    /// 新建 ring;上限来自 route 计划(构建期已校验 ≥ 一条最大帧)。
    pub fn new(max_messages: usize, max_bytes: usize, overflow: RingOverflow) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(RingInner {
                queue: VecDeque::new(),
                bytes: 0,
                closed: None,
            }),
            consumer: AtomicWaker::new(),
            max_messages,
            max_bytes,
            overflow,
            dropped: AtomicU64::new(0),
        })
    }

    /// 非阻塞入队一帧(完整 `[prefix+payload]` + 共享租约)。
    pub fn push(&self, frame: QueuedFrame) -> RingPush {
        let frame_len = frame.bytes.len();
        let outcome = {
            let mut inner = self.inner.lock();
            if inner.closed.is_some() {
                return RingPush::Closed;
            }
            // 单帧本身超过整队字节预算:任何策略都装不下,按丢新处理(不弹空整队)。
            if frame_len > self.max_bytes {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return RingPush::DroppedNew;
            }
            let over = |inner: &RingInner| {
                inner.queue.len() >= self.max_messages || inner.bytes + frame_len > self.max_bytes
            };
            if !over(&inner) {
                inner.bytes += frame_len;
                inner.queue.push_back(frame);
                RingPush::Enqueued
            } else {
                match self.overflow {
                    RingOverflow::DropOldest => {
                        let mut popped = 0usize;
                        while over(&inner) {
                            let Some(old) = inner.queue.pop_front() else {
                                break;
                            };
                            inner.bytes -= old.bytes.len();
                            popped += 1;
                        }
                        self.dropped.fetch_add(popped as u64, Ordering::Relaxed);
                        inner.bytes += frame_len;
                        inner.queue.push_back(frame);
                        RingPush::DroppedOldest(popped)
                    }
                    RingOverflow::DropNew => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        RingPush::DroppedNew
                    }
                    RingOverflow::CloseSlow => {
                        // close_slow 的业务含义是立即隔离慢连接。若先排空旧队列再发 trailer，
                        // 最慢的连接反而继续长期占用 payload/ref 预算，无法形成 OOM 保护。
                        let dropped = inner.queue.len().saturating_add(1);
                        inner.queue.clear();
                        inner.bytes = 0;
                        inner.closed = Some(EdgeCloseReason::SlowConsumer);
                        self.dropped.fetch_add(dropped as u64, Ordering::Relaxed);
                        RingPush::ClosedSlow
                    }
                }
            }
        };
        // 锁外唤醒:消费者可能正 Pending 等帧或等关闭。
        self.consumer.wake();
        outcome
    }

    /// 单消费者取帧;`Pending` 前登记 waker 并复查,封住 push/close 与注册的竞态。
    pub fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Result<QueuedFrame, EdgeCloseReason>> {
        // 快路径:先无 waker 操作试一次。
        if let Some(ready) = self.try_pop() {
            return Poll::Ready(ready);
        }
        self.consumer.register(cx.waker());
        match self.try_pop() {
            Some(ready) => Poll::Ready(ready),
            None => Poll::Pending,
        }
    }

    fn try_pop(&self) -> Option<Result<QueuedFrame, EdgeCloseReason>> {
        let mut inner = self.inner.lock();
        if let Some(frame) = inner.queue.pop_front() {
            inner.bytes -= frame.bytes.len();
            return Some(Ok(frame));
        }
        inner.closed.map(Err)
    }

    /// 清空残留帧并返回条数;订阅注销(含 RST)时结算 queue_refs,防引用计数泄漏。
    fn drain_remaining(&self) -> usize {
        let mut inner = self.inner.lock();
        let n = inner.queue.len();
        inner.bytes = 0;
        inner.queue.clear();
        n
    }

    /// 幂等关闭;首因保留(晚到的关闭不覆盖已发布原因)。
    pub fn close(&self, reason: EdgeCloseReason) {
        {
            let mut inner = self.inner.lock();
            if inner.closed.is_none() {
                inner.closed = Some(reason);
            }
        }
        self.consumer.wake();
    }

    /// 溢出丢帧累计。
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 单测专用:以给定 hub 记账构造一帧(生产路径走 fanout 内部构造)。
    #[cfg(test)]
    pub(crate) fn test_frame(hub: &Arc<EdgeHub>, bytes: Bytes) -> QueuedFrame {
        let len = bytes.len();
        hub.payload_bytes.fetch_add(len, Ordering::Relaxed);
        QueuedFrame {
            bytes,
            _lease: Arc::new(PayloadLease {
                len,
                hub: hub.clone(),
            }),
            _queue_ref: QueueRefGuard::try_new(hub.clone(), usize::MAX)
                .expect("test queue-ref reservation"),
        }
    }

    /// 单测专用的非阻塞取帧(生产消费者一律走 `poll_pop` 以获得唤醒登记)。
    #[cfg(test)]
    pub(crate) fn try_pop_for_test(&self) -> Option<Result<QueuedFrame, EdgeCloseReason>> {
        self.try_pop()
    }
}

// ── EdgeHub:tenant 作用域订阅索引 + 基数上限 ──

/// tenant 作用域 group 键(§25.2.5:group key 必须含 tenant,防跨租户串台)。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EdgeGroupKey {
    /// 租户;单租户部署恒为 "default"。
    pub tenant: Arc<str>,
    /// 业务 group id。
    pub group: Arc<str>,
}

/// tenant 作用域 user 键。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EdgeUserKey {
    /// 租户。
    pub tenant: Arc<str>,
    /// 已验证 principal 映射出的用户身份。
    pub user: Arc<str>,
}

/// group 成员表。外层 DashMap 已按 key hash 分片;组内单锁在 V8-1(注册/注销)
/// 足够,fanout 热路径的组内分片留给 V8-2 按基准决定(§25.2.5 bucket 分片)。
pub struct GroupMembers {
    members: parking_lot::RwLock<HashMap<u64, Arc<EdgeRing>>>,
}

/// 一个 user 的在线 session 记录;ring 供定向 push 本地投递。
struct UserSession {
    stream_id: u64,
    ring: Arc<EdgeRing>,
    single_session_token: Option<u64>,
}

/// 进程常驻的边缘订阅索引(不进 Snapshot;地位同 ConnectionRegistry)。
pub struct EdgeHub {
    next_stream_id: AtomicU64,
    active_streams: AtomicUsize,
    active_groups: AtomicUsize,
    groups: DashMap<EdgeGroupKey, Arc<GroupMembers>>,
    users: DashMap<EdgeUserKey, Mutex<Vec<UserSession>>>,
    /// single_session 的本地 fencing token。claim 先全网更新 fence，再允许订阅登记。
    session_fences: DashMap<EdgeUserKey, u64>,
    /// 节点唯一 payload 驻留字节(同一份 payload 全部队列只计一次;lease Drop 归还)。
    payload_bytes: AtomicUsize,
    /// 全节点队列引用总数(QueuedFrame 构造/Drop 自动结算)。
    queue_refs: AtomicUsize,
    /// 并发 fanout 任务数(publish 在途门)。
    fanout_jobs: AtomicUsize,
    /// 发布总数/预算拒绝数/溢出丢帧数/跨 DATA 重组字节(§25.2.8 低基数观测)。
    publish_total: AtomicU64,
    publish_rejected_total: AtomicU64,
    dropped_frames_total: AtomicU64,
    reassembly_bytes_total: AtomicU64,
    /// 10ms 心跳观测到的 Tokio 最大调度超时(微秒)。只在存在 runtime 时启动弱引用
    /// monitor；它不持有 Hub 生命周期，也不进入每消息热路径。
    runtime_schedule_pause_max_us: AtomicU64,
    /// 大规模订阅波次排空后触发一次 glibc trim。小流量不碰 allocator 全局锁；达到
    /// 10k 活跃流才置位，最后一条流退出时异步执行一次。
    drain_trim_armed: AtomicBool,
    /// E1 interest 传播目标；Weak 避免 hub↔relay 强引用环，relay 换代时可替换。
    interest_relay: parking_lot::RwLock<Weak<crate::edge_relay::EdgeRelay>>,
}

/// 订阅准入失败;调用方映射 RESOURCE_EXHAUSTED(8)。
#[derive(Debug, PartialEq, Eq)]
pub enum EdgeAdmitError {
    /// 节点订阅流总数达上限。
    Streams,
    /// 节点 group 总数达上限。
    Groups,
    /// 目标 group 成员数达上限。
    Members,
    /// 该 user 并发 session 达上限。
    Sessions,
}

impl EdgeAdmitError {
    /// 低基数拒绝原因(日志/报错用)。
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Streams => "max_streams_per_node",
            Self::Groups => "max_groups_per_node",
            Self::Members => "max_members_per_group",
            Self::Sessions => "max_sessions_per_user",
        }
    }
}

impl EdgeHub {
    /// 业务作用：创建进程唯一的 edge 订阅索引，并启动不持有 Hub 生命周期的调度停顿观测器。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回可共享的空 Hub；不在 Tokio runtime 内构造时只跳过观测任务，索引仍可用于测试。
    pub fn new() -> Arc<Self> {
        let hub = Arc::new(Self {
            next_stream_id: AtomicU64::new(1),
            active_streams: AtomicUsize::new(0),
            active_groups: AtomicUsize::new(0),
            groups: DashMap::new(),
            users: DashMap::new(),
            session_fences: DashMap::new(),
            payload_bytes: AtomicUsize::new(0),
            queue_refs: AtomicUsize::new(0),
            fanout_jobs: AtomicUsize::new(0),
            publish_total: AtomicU64::new(0),
            publish_rejected_total: AtomicU64::new(0),
            dropped_frames_total: AtomicU64::new(0),
            reassembly_bytes_total: AtomicU64::new(0),
            runtime_schedule_pause_max_us: AtomicU64::new(0),
            drain_trim_armed: AtomicBool::new(false),
            interest_relay: parking_lot::RwLock::new(Weak::new()),
        });
        // 单测可能在 Tokio runtime 外构造 Hub；此时不启动观测任务。生产 Proxy 在
        // runtime 内创建，弱引用使任务随 Hub 自动结束，不形成进程常驻泄漏。
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&hub);
            handle.spawn(async move {
                const PERIOD: Duration = Duration::from_millis(10);
                let mut deadline = TokioInstant::now() + PERIOD;
                loop {
                    tokio::time::sleep_until(deadline).await;
                    let now = TokioInstant::now();
                    let Some(hub) = weak.upgrade() else {
                        return;
                    };
                    let lag_us = now
                        .saturating_duration_since(deadline)
                        .as_micros()
                        .min(u128::from(u64::MAX)) as u64;
                    hub.runtime_schedule_pause_max_us
                        .fetch_max(lag_us, Ordering::Relaxed);
                    // 从实际唤醒时刻重新排下一拍；大暂停只记一次，不能用追赶循环制造
                    // 一串无意义的 0 延迟采样。
                    deadline = now + PERIOD;
                }
            });
        }
        hub
    }

    /// 业务作用：绑定当前 relay 的 interest 传播端，使 group 首次出现/消失可刷新远端 hint。
    ///
    /// 参数说明：`relay` 是当前 generation 的弱引用，避免 Hub 与 relay 形成强引用环。
    ///
    /// 返回：无返回值；热换代会覆盖旧引用，旧代释放后通知自动降级为无操作。
    pub(crate) fn attach_interest_relay(&self, relay: Weak<crate::edge_relay::EdgeRelay>) {
        *self.interest_relay.write() = relay;
    }

    /// 业务作用：为新建 relay 链路生成当前本地 group interest 全量快照。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回 tenant/group 的独立引用列表；快照之后的并发变化由 revision 增量补齐。
    pub(crate) fn group_interests(&self) -> Vec<(Arc<str>, Arc<str>)> {
        self.groups
            .iter()
            .map(|entry| (entry.key().tenant.clone(), entry.key().group.clone()))
            .collect()
    }

    /// 业务作用：复验某个 interest 增量发送时目标 group 是否仍有本地成员，避免发布过期 up/down。
    ///
    /// 参数说明：`tenant`/`group` 是已经过身份与长度门的本地索引键。
    ///
    /// 返回：仍存在非空 group 时返回 `true`，否则返回 `false`。
    pub(crate) fn has_group_interest(&self, tenant: &str, group: &str) -> bool {
        self.groups.contains_key(&EdgeGroupKey {
            tenant: Arc::from(tenant),
            group: Arc::from(group),
        })
    }

    /// 业务作用：把 group 的首成员/末成员状态变化交给当前 relay 控制队列；无 relay 时保持单机语义。
    ///
    /// 参数说明：`key` 是发生空/非空边界迁移的 tenant/group 键。
    ///
    /// 返回：无返回值；控制队列过载的拆链与 fail-open 由 relay 负责。
    fn notify_interest(&self, key: &EdgeGroupKey) {
        if let Some(relay) = self.interest_relay.read().upgrade() {
            relay.interest_changed(key.tenant.clone(), key.group.clone());
        }
    }

    /// 当前活跃订阅流数(gauge)。
    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    /// 当前 group 数(gauge)。
    pub fn group_count(&self) -> usize {
        self.active_groups.load(Ordering::Relaxed)
    }

    /// 唯一 payload 驻留字节(gauge)。
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes.load(Ordering::Relaxed)
    }

    /// 队列引用总数(gauge)。
    pub fn queue_refs(&self) -> usize {
        self.queue_refs.load(Ordering::Relaxed)
    }

    /// 业务作用：向 V8-6 资源门与管理面暴露进程启动以来 edge runtime 的最大调度停顿。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回微秒计数的单调最大值。
    pub fn runtime_schedule_pause_max_us(&self) -> u64 {
        self.runtime_schedule_pause_max_us.load(Ordering::Relaxed)
    }

    /// 发布/拒绝/丢帧/重组观测(counter 四元组,/metrics 渲染用)。
    pub fn publish_counters(&self) -> (u64, u64, u64, u64) {
        (
            self.publish_total.load(Ordering::Relaxed),
            self.publish_rejected_total.load(Ordering::Relaxed),
            self.dropped_frames_total.load(Ordering::Relaxed),
            self.reassembly_bytes_total.load(Ordering::Relaxed),
        )
    }

    /// 群播本地散出(§25.2.5):唯一 payload 记账一次,N 个订阅队列只复制共享引用;
    /// 分 chunk 让出调度,绝不让一次 O(N) 循环独占 runtime worker。
    ///
    /// # 参数
    /// - `limits`: 节点级预算上限(本地发布=命中 route 的 `plan.limits`;
    ///   relay 收包侧没有 route,用 §25.2.9 默认预算,见 edge_relay)。
    /// - `tenant`/`group`: tenant 作用域目标组。
    /// - `frame`: 完整 `[prefix+body]` 业务帧(网关不解析,§25.2.2)。
    /// - `reassembled`: 本次请求解帧的跨 DATA 重组字节(诚实观测)。
    pub async fn publish_group(
        self: &Arc<Self>,
        limits: &crate::grpc_edge::GrpcEdgeLimitsPlan,
        tenant: Arc<str>,
        group: Arc<str>,
        frame: Bytes,
        reassembled: u64,
    ) -> Result<LocalFanoutOutcome, EdgePublishError> {
        let rings: Vec<Arc<EdgeRing>> = match self.groups.get(&EdgeGroupKey { tenant, group }) {
            // 读锁内只 clone Arc(§25.2.5 锁纪律);订阅天然竞态,空组不是错误。
            Some(bucket) => bucket.members.read().values().cloned().collect(),
            None => Vec::new(),
        };
        self.fanout(limits, rings, frame, reassembled, true).await
    }

    /// 定向单播本地投递:该 user 全部在线 session 各收一份(multi_session,§25.2.7)。
    pub async fn push_user(
        self: &Arc<Self>,
        limits: &crate::grpc_edge::GrpcEdgeLimitsPlan,
        tenant: Arc<str>,
        user: Arc<str>,
        frame: Bytes,
        reassembled: u64,
    ) -> Result<LocalFanoutOutcome, EdgePublishError> {
        let rings: Vec<Arc<EdgeRing>> = match self.users.get(&EdgeUserKey { tenant, user }) {
            Some(sessions) => sessions
                .lock()
                .iter()
                .map(|session| session.ring.clone())
                .collect(),
            None => Vec::new(),
        };
        // sessions_per_user ≤ 64,无需 chunk 让出。
        self.fanout(limits, rings, frame, reassembled, false).await
    }

    /// 共享散出内核:预算(fanout_jobs/payload/queue_refs)→ 逐环非阻塞 try-push。
    async fn fanout(
        self: &Arc<Self>,
        limits: &crate::grpc_edge::GrpcEdgeLimitsPlan,
        rings: Vec<Arc<EdgeRing>>,
        frame: Bytes,
        reassembled: u64,
        chunked: bool,
    ) -> Result<LocalFanoutOutcome, EdgePublishError> {
        const FANOUT_CHUNK: usize = 256;
        self.publish_total.fetch_add(1, Ordering::Relaxed);
        self.reassembly_bytes_total
            .fetch_add(reassembled, Ordering::Relaxed);
        // 在途 fanout 任务门。
        if !try_reserve(&self.fanout_jobs, 1, limits.max_fanout_jobs) {
            self.publish_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(EdgePublishError::FanoutJobs);
        }
        let _job = FanoutJobGuard { hub: self.clone() };
        // 唯一 payload 预算:CAS 精确预留,任一时刻不越上限;Drop 链自动归还。
        let len = frame.len();
        if !try_reserve(&self.payload_bytes, len, limits.max_payload_bytes) {
            self.publish_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(EdgePublishError::PayloadBudget);
        }
        let lease = Arc::new(PayloadLease {
            len,
            hub: self.clone(),
        });
        let mut outcome = LocalFanoutOutcome {
            members: rings.len() as u32,
            ..LocalFanoutOutcome::default()
        };
        for (index, ring) in rings.iter().enumerate() {
            if chunked && index > 0 && index % FANOUT_CHUNK == 0 {
                // cooperative budget:大群不独占 worker,不饿死普通 L7 请求(§25.2.5)。
                tokio::task::yield_now().await;
            }
            // 全局引用预算:满则本次投递按丢弃计,不中断其余成员。
            let Some(queue_ref) = QueueRefGuard::try_new(self.clone(), limits.max_queue_refs)
            else {
                outcome.dropped_budget += 1;
                continue;
            };
            let queued = QueuedFrame {
                bytes: frame.clone(),
                _lease: lease.clone(),
                _queue_ref: queue_ref,
            };
            match ring.push(queued) {
                RingPush::Enqueued => outcome.accepted += 1,
                RingPush::DroppedOldest(n) => {
                    outcome.accepted += 1;
                    outcome.dropped_oldest += n as u64;
                }
                RingPush::DroppedNew => outcome.dropped_new += 1,
                RingPush::ClosedSlow => outcome.closed_slow += 1,
                RingPush::Closed => outcome.dropped_new += 1,
            }
        }
        self.dropped_frames_total.fetch_add(
            outcome.dropped_oldest
                + outcome.dropped_new
                + u64::from(outcome.closed_slow)
                + u64::from(outcome.dropped_budget),
            Ordering::Relaxed,
        );
        Ok(outcome)
    }

    /// 登记一条订阅:按 plan 上限准入,创建 ring,写入 group/user 索引。
    ///
    /// 返回的 [`EdgeSubscription`] Drop 时幂等摘除全部索引项。
    pub fn subscribe(
        self: &Arc<Self>,
        plan: &GrpcEdgePlan,
        tenant: Arc<str>,
        user: Arc<str>,
        group: Arc<str>,
    ) -> Result<EdgeSubscription, EdgeAdmitError> {
        self.subscribe_inner(plan, tenant, user, group, None)
    }

    /// 业务作用：登记一条已经完成全网 fencing 的 single-session 订阅，并复验 token 仍为当前权威。
    ///
    /// 参数说明：`plan` 提供准入预算；`tenant`/`user`/`group` 是已验证作用域；`token` 是 relay claim 结果。
    ///
    /// 返回：成功返回可 Drop 的订阅句柄；预算不足或 token 已失权时返回对应准入错误且回滚索引。
    pub fn subscribe_single(
        self: &Arc<Self>,
        plan: &GrpcEdgePlan,
        tenant: Arc<str>,
        user: Arc<str>,
        group: Arc<str>,
        token: u64,
    ) -> Result<EdgeSubscription, EdgeAdmitError> {
        self.subscribe_inner(plan, tenant, user, group, Some(token))
    }

    /// 业务作用：统一执行 multi-session 与 single-session 的原子准入、索引登记和失败补偿。
    ///
    /// 参数说明：`plan` 提供预算/队列策略；`tenant`/`user`/`group` 是已验证键；
    /// `single_session_token` 为 `Some` 时必须匹配本地 fence。
    ///
    /// 返回：全部索引提交后返回订阅句柄；任一门失败则完整回滚并返回低基数错误。
    fn subscribe_inner(
        self: &Arc<Self>,
        plan: &GrpcEdgePlan,
        tenant: Arc<str>,
        user: Arc<str>,
        group: Arc<str>,
        single_session_token: Option<u64>,
    ) -> Result<EdgeSubscription, EdgeAdmitError> {
        let limits = &plan.limits;
        if !try_reserve(&self.active_streams, 1, limits.max_streams_per_node) {
            return Err(EdgeAdmitError::Streams);
        }
        if self.active_streams.load(Ordering::Relaxed) >= 10_000 {
            self.drain_trim_armed.store(true, Ordering::Relaxed);
        }
        let group_key = EdgeGroupKey {
            tenant: tenant.clone(),
            group,
        };
        let user_key = EdgeUserKey { tenant, user };
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let ring = EdgeRing::new(
            plan.send_queue_max_messages,
            plan.send_queue_max_bytes,
            map_overflow(plan.overflow),
        );

        let first_interest;
        {
            let bucket = match self.groups.entry(group_key.clone()) {
                Entry::Occupied(entry) => entry.get().clone(),
                Entry::Vacant(entry) => {
                    if !try_reserve(&self.active_groups, 1, limits.max_groups_per_node) {
                        self.active_streams.fetch_sub(1, Ordering::Relaxed);
                        return Err(EdgeAdmitError::Groups);
                    }
                    entry
                        .insert(Arc::new(GroupMembers {
                            members: parking_lot::RwLock::new(HashMap::new()),
                        }))
                        .clone()
                }
            };
            let mut members = bucket.members.write();
            first_interest = members.is_empty();
            if members.len() >= limits.max_members_per_group {
                // 回滚空组:本次插入建出的空 bucket 不留残影。
                drop(members);
                self.remove_group_if_empty(&group_key);
                self.active_streams.fetch_sub(1, Ordering::Relaxed);
                return Err(EdgeAdmitError::Members);
            }
            members.insert(stream_id, ring.clone());
        }
        let sessions_entry = self
            .users
            .entry(user_key.clone())
            .or_insert_with(|| Mutex::new(Vec::with_capacity(2)));
        let mut sessions = sessions_entry.lock();
        if let Some(token) = single_session_token {
            if self.session_fences.get(&user_key).map(|fence| *fence) != Some(token) {
                drop(sessions);
                drop(sessions_entry);
                if let Some(bucket) = self.groups.get(&group_key).map(|entry| entry.clone()) {
                    bucket.members.write().remove(&stream_id);
                    self.remove_group_if_empty(&group_key);
                }
                self.users
                    .remove_if(&user_key, |_, sessions| sessions.lock().is_empty());
                self.active_streams.fetch_sub(1, Ordering::Relaxed);
                return Err(EdgeAdmitError::Sessions);
            }
        }
        if sessions.len() >= limits.max_sessions_per_user {
            drop(sessions);
            drop(sessions_entry);
            if let Some(bucket) = self.groups.get(&group_key).map(|entry| entry.clone()) {
                bucket.members.write().remove(&stream_id);
                self.remove_group_if_empty(&group_key);
            }
            self.users
                .remove_if(&user_key, |_, sessions| sessions.lock().is_empty());
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            return Err(EdgeAdmitError::Sessions);
        }
        sessions.push(UserSession {
            stream_id,
            ring: ring.clone(),
            single_session_token,
        });
        drop(sessions);
        drop(sessions_entry);
        if first_interest {
            self.notify_interest(&group_key);
        }

        Ok(EdgeSubscription {
            hub: self.clone(),
            group_key,
            user_key,
            stream_id,
            ring,
            removed: AtomicBool::new(false),
            single_session_token,
        })
    }

    /// 业务作用：发布 single-session fencing token，并立即关闭该用户所有非当前 token 的旧连接。
    ///
    /// 参数说明：`tenant`/`user` 标识已验证用户，`token` 是 owner 排定的新权威版本。
    ///
    /// 返回：无返回值；fence 先发布到本地表，再触发旧 ring 关闭，避免新订阅越过保护态。
    pub(crate) fn fence_single_session(&self, tenant: Arc<str>, user: Arc<str>, token: u64) {
        let key = EdgeUserKey { tenant, user };
        self.session_fences.insert(key.clone(), token);
        if let Some(sessions) = self.users.get(&key) {
            let sessions = sessions.lock();
            for session in sessions.iter() {
                if session.single_session_token != Some(token) {
                    session.ring.close(EdgeCloseReason::SessionReplaced);
                }
            }
        }
    }

    /// 业务作用：仅在本地已无会话且 token 仍匹配时释放 fence，阻止迟到 release 误伤新登录。
    ///
    /// 参数说明：`tenant`/`user` 标识用户，`token` 是待释放的旧会话权威。
    ///
    /// 返回：无返回值；条件不满足时保留当前 fence。
    pub(crate) fn release_session_fence(&self, tenant: &str, user: &str, token: u64) {
        let key = EdgeUserKey {
            tenant: Arc::from(tenant),
            user: Arc::from(user),
        };
        let empty = self
            .users
            .get(&key)
            .is_none_or(|sessions| sessions.lock().is_empty());
        if empty {
            self.session_fences
                .remove_if(&key, |_, current| *current == token);
        }
    }

    /// 业务作用：在线性化的 DashMap 分片锁内删除空 group，并同步归还 group 基数预算。
    ///
    /// 参数说明：`key` 是可能已空的 tenant/group 键。
    ///
    /// 返回：实际删除条目时返回 `true`，调用方据此发送唯一的 interest-down 通知。
    fn remove_group_if_empty(&self, key: &EdgeGroupKey) -> bool {
        // DashMap remove_if 在 shard 写锁内执行谓词,与并发 subscribe 的 entry 互斥。
        let removed = self
            .groups
            .remove_if(key, |_, bucket| bucket.members.read().is_empty())
            .is_some();
        if removed {
            self.active_groups.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    /// 业务作用：幂等摘除订阅的 group/user 索引、归还全部资源，并触发 interest/session 收尾。
    ///
    /// 参数说明：`sub` 是正在 Drop 的订阅身份与 ring 句柄。
    ///
    /// 返回：无返回值；最后一条大规模流退出时异步触发 allocator drain，不阻塞 Tokio worker。
    fn unsubscribe(&self, sub: &EdgeSubscription) {
        if let Some(bucket) = self.groups.get(&sub.group_key).map(|b| b.clone()) {
            bucket.members.write().remove(&sub.stream_id);
            if self.remove_group_if_empty(&sub.group_key) {
                self.notify_interest(&sub.group_key);
            }
        }
        if let Some(sessions) = self.users.get(&sub.user_key) {
            let mut sessions = sessions.lock();
            sessions.retain(|session| session.stream_id != sub.stream_id);
        }
        self.users
            .remove_if(&sub.user_key, |_, sessions| sessions.lock().is_empty());
        // 立即清空残留帧,让 payload/queue_refs 经 Drop 链即时归还(RST 后不滞留)。
        let _ = sub.ring.drain_remaining();
        let previous = self.active_streams.fetch_sub(1, Ordering::AcqRel);
        if previous == 1 && self.drain_trim_armed.swap(false, Ordering::AcqRel) {
            trim_allocator_after_large_drain();
        }
        if let Some(token) = sub.single_session_token {
            if let Some(relay) = self.interest_relay.read().upgrade() {
                relay.session_closed(
                    sub.user_key.tenant.clone(),
                    sub.user_key.user.clone(),
                    token,
                );
            }
        }
    }
}

/// 业务作用：在 Linux GNU 大规模 edge 波次完全排空后异步归还 glibc arena，满足 RSS drain 硬门。
///
/// 参数说明：无。
///
/// 返回：无返回值；没有 Tokio runtime 时跳过，且不影响逻辑资源归还。
///
/// glibc 会把大批短命 ring/body allocation 留在 arena，逻辑 gauge 已归零但容器 RSS
/// 长期不回落。只在 Linux GNU 且“曾同时存在 ≥10k edge 流并已全部排空”时异步 trim；
/// 其它平台保持 no-op。spawn_blocking 避免 allocator 全局整理占用 Tokio worker。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim_allocator_after_large_drain() {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(|| unsafe {
            let _ = malloc_trim(0);
        });
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
/// 业务作用：在非 Linux GNU 平台保留统一的 drain 调用点，不改变平台默认分配器行为。
///
/// 参数说明：无。
///
/// 返回：无返回值。
fn trim_allocator_after_large_drain() {}

/// 对共享原子预算做严格的 compare-exchange 预留。先 `load` 再 `fetch_add` 会让并发
/// 发布同时越过上限；硬预算必须保证任一时刻 `current + amount <= max`。
fn try_reserve(counter: &AtomicUsize, amount: usize, max: usize) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        if next > max {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

/// 本地散出结果(§25.2.8:只报 accepted/enqueued/rejected,绝不叫 delivered——
/// 入队不等于客户端已消费)。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LocalFanoutOutcome {
    /// 本地目标成员数(订阅竞态下的瞬时快照)。
    pub members: u32,
    /// 成功入队份数。
    pub accepted: u32,
    /// drop_oldest 弹掉的旧帧数。
    pub dropped_oldest: u64,
    /// drop_new/已关环拒收份数。
    pub dropped_new: u64,
    /// close_slow 触发断流的成员数。
    pub closed_slow: u32,
    /// 因全局 queue_refs 预算拒绝的份数。
    pub dropped_budget: u32,
}

/// 发布面预算拒绝(→ RESOURCE_EXHAUSTED)。
#[derive(Debug, PartialEq, Eq)]
pub enum EdgePublishError {
    /// 节点唯一 payload 字节预算耗尽。
    PayloadBudget,
    /// 并发 fanout 任务门耗尽。
    FanoutJobs,
}

impl EdgePublishError {
    /// 低基数拒绝原因。
    pub fn reason(&self) -> &'static str {
        match self {
            Self::PayloadBudget => "max_payload_bytes",
            Self::FanoutJobs => "max_fanout_jobs",
        }
    }
}

/// 回执消息(PublishSummary / PushSummary)的 protobuf 字段号。
///
/// 这是**对外 wire 契约**的一部分:`proto/naway/edge/v1/edge.proto` 里的字段号必须
/// 与这里逐一相等,由 `edge_proto_matches_wire_contract` 用例锁死。改动任一侧而不改
/// 另一侧会让已生成的多语言 SDK 静默解析错字段,因此不允许在调用点写裸数字。
///
/// PushSummary 刻意与 PublishSummary **共用同一编号空间**:2/3/4 在 push 语义下无意义,
/// 保留不用,不得复用它们表达别的含义。
pub mod summary_field {
    /// 本地实际入队份数(绝不叫 delivered:入队 ≠ 终端已消费)。
    pub const ACCEPTED: u32 = 1;
    /// 未入队份数(队满丢弃 + queue_refs 预算拒绝)。
    pub const DROPPED: u32 = 2;
    /// 因慢消费被主动断流的成员数。
    pub const CLOSED_SLOW: u32 = 3;
    /// 已处理消息条数(unary 恒 1;流式凭它续传)。
    pub const MESSAGES: u32 = 4;
    /// peer 侧实际入队份数。
    pub const PEERS_ACCEPTED: u32 = 5;
    /// 明确拒绝的 peer 数。
    pub const PEERS_REJECTED: u32 = 6;
    /// 断线或无回执的 peer 数(不自动重试)。
    pub const PEERS_UNKNOWN: u32 = 7;
}

/// 手工编码平坦 varint-only protobuf 消息并封 gRPC 帧(回执专用,不引 prost;
/// §25.2 控制面小消息不违反"业务 payload 零解析")。proto3 语义:0 值字段省略。
pub fn encode_flat_grpc_message(fields: &[(u32, u64)]) -> Bytes {
    let mut body = BytesMut::new();
    for (tag, value) in fields {
        if *value == 0 {
            continue;
        }
        put_varint(&mut body, u64::from(*tag) << 3);
        put_varint(&mut body, *value);
    }
    let mut framed = BytesMut::with_capacity(GRPC_PREFIX_BYTES + body.len());
    framed.put_u8(0);
    framed.put_u32(body.len() as u32);
    framed.extend_from_slice(&body);
    framed.freeze()
}

pub(crate) fn put_varint(buf: &mut BytesMut, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.put_u8(byte);
            break;
        }
        buf.put_u8(byte | 0x80);
    }
}

/// unary gRPC 自响应 body:恰好一帧 message + 一次 `grpc-status: 0` trailer。
pub struct UnaryGrpcResponseBody {
    frame: Option<Bytes>,
    trailers_sent: bool,
}

impl UnaryGrpcResponseBody {
    /// 以一条已封帧 message 构造。
    pub fn new(frame: Bytes) -> Self {
        Self {
            frame: Some(frame),
            trailers_sent: false,
        }
    }
}

impl Body for UnaryGrpcResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(frame) = self.frame.take() {
            return Poll::Ready(Some(Ok(Frame::data(frame))));
        }
        if !self.trailers_sent {
            self.trailers_sent = true;
            let mut trailers = http::HeaderMap::with_capacity(1);
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.frame.is_none() && self.trailers_sent
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 一枚令牌的定点刻度(纳令牌;整数运算,paused-clock 测试可精确断言)。
const RATE_TOKEN: u128 = 1_000_000_000;

/// PublishStream 每秒消息数节流(§25.2.3 四门之一):令牌桶,容量 = 1 秒配额,
/// 连续补充。
///
/// 语义是**背压**而不是拒绝:无令牌时 `acquire` 挂起,调用方因此暂停读请求体,
/// HTTP/2 流控把压力传导回发布方——消息不丢、流不断。单流独享一把,无共享状态。
pub struct StreamRateGate {
    /// 每秒补充令牌数,同时是桶容量(允许 1 秒突发后收敛稳态)。
    rate: u128,
    /// 纳令牌余额。
    balance: u128,
    last: TokioInstant,
}

impl StreamRateGate {
    /// 新建满桶(首秒允许突发到配额)。
    pub fn new(max_msgs_per_sec: u64) -> Self {
        let rate = u128::from(max_msgs_per_sec.max(1));
        Self {
            rate,
            balance: rate * RATE_TOKEN,
            last: TokioInstant::now(),
        }
    }

    /// 取一枚令牌;不足则睡到恰好补齐缺口(背压点,不忙轮询)。
    pub async fn acquire(&mut self) {
        loop {
            let now = TokioInstant::now();
            let elapsed = now.saturating_duration_since(self.last);
            self.last = now;
            let cap = self.rate * RATE_TOKEN;
            self.balance = (self.balance + elapsed.as_nanos() * self.rate).min(cap);
            if self.balance >= RATE_TOKEN {
                self.balance -= RATE_TOKEN;
                return;
            }
            let deficit = RATE_TOKEN - self.balance;
            // 上取整:deficit ≤ 1e9 且 rate ≥ 1,等待纳秒数必然落在 u64 内。
            let wait_nanos = deficit.div_ceil(self.rate) as u64;
            tokio::time::sleep(Duration::from_nanos(wait_nanos)).await;
        }
    }
}

/// V8-0R 配置枚举 → 运行时策略。latest_by_key 的业务 key 依赖 V8-2 publish
/// envelope 定型,当前按 drop_oldest 执行(publish 面尚不存在,无生产影响)。
fn map_overflow(cfg: crate::config::model::GrpcEdgeOverflowCfg) -> RingOverflow {
    use crate::config::model::GrpcEdgeOverflowCfg as Cfg;
    match cfg {
        Cfg::DropOldest | Cfg::LatestByKey => RingOverflow::DropOldest,
        Cfg::DropNew => RingOverflow::DropNew,
        Cfg::CloseSlow => RingOverflow::CloseSlow,
    }
}

/// 订阅登记句柄;Drop 幂等摘除 group/user 索引与计数。
pub struct EdgeSubscription {
    hub: Arc<EdgeHub>,
    group_key: EdgeGroupKey,
    user_key: EdgeUserKey,
    stream_id: u64,
    ring: Arc<EdgeRing>,
    removed: AtomicBool,
    single_session_token: Option<u64>,
}

impl EdgeSubscription {
    /// 本订阅的发送环(body 消费;V8-2 fanout 生产)。
    pub fn ring(&self) -> &Arc<EdgeRing> {
        &self.ring
    }

    /// 稳定 stream id(观测/去重用)。
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl Drop for EdgeSubscription {
    fn drop(&mut self) {
        if !self.removed.swap(true, Ordering::AcqRel) {
            self.hub.unsubscribe(self);
        }
    }
}

// ── 订阅响应 Body(channel-backed;§25.2.3 响应契约) ──

/// Subscribe 自响应 body:从 ring 取完整帧下发,治理关闭时发一次合法 trailer。
///
/// 释放顺序与 GrpcDrainBody 一致:先置 done/清 inner 状态,再靠 Drop 链
/// (subscription → hub 摘除;guard → registry 注销)完成清理;RST/客户端断开
/// 走 hyper Drop 本体,同样幂等。
pub struct EdgeSubscribeBody {
    /// ring 与订阅登记;trailer 发出后取走(先摘索引再结束流)。
    subscription: Option<EdgeSubscription>,
    /// §6.1 注册表守卫:close_by_route/ip/consumer 与 drain_stale 的关闭源。
    guard: Option<ConnGuard>,
    close_wait: CloseNotified,
    /// route 级最长存活;0 = 不限。
    lifetime: Option<Pin<Box<Sleep>>>,
    /// route 级帧间空闲预算;仅在曾经 Pending 后计时(惰性,同 CountedBody)。
    idle_timeout: Duration,
    idle_sleep: Option<Pin<Box<Sleep>>>,
    /// V8-7 目录租约(不透明持有):具体类型由 `edge_directory` 提供,Drop 即摘除
    /// 自己那条 field。放在 body 里让"租约生命周期 == 订阅流生命周期"结构性成立;
    /// 未编 `redis-runtime` 或 `session_registry=none` 时恒为 None,零成本。
    directory_lease: Option<Arc<dyn Send + Sync>>,
    done: bool,
}

impl EdgeSubscribeBody {
    /// 组装订阅 body。
    ///
    /// # 参数
    /// - `subscription`: 已登记的订阅(索引/ring)。
    /// - `guard`: 已在 ConnectionRegistry 登记的守卫(LongProto::GrpcStream 语义)。
    /// - `idle_timeout_ms`: 帧间空闲预算,0 关闭。
    /// - `max_lifetime_ms`: 最长存活,0 不限。
    pub fn new(
        subscription: EdgeSubscription,
        guard: ConnGuard,
        idle_timeout_ms: u64,
        max_lifetime_ms: u64,
    ) -> Self {
        let close_wait = guard.closed();
        Self {
            subscription: Some(subscription),
            guard: Some(guard),
            close_wait,
            lifetime: (max_lifetime_ms > 0)
                .then(|| Box::pin(tokio::time::sleep(Duration::from_millis(max_lifetime_ms)))),
            idle_timeout: Duration::from_millis(idle_timeout_ms),
            idle_sleep: None,
            directory_lease: None,
            done: false,
        }
    }

    /// 挂上 V8-7 目录租约(builder;无目录时不调用)。
    pub fn with_directory_lease(mut self, lease: Arc<dyn Send + Sync>) -> Self {
        self.directory_lease = Some(lease);
        self
    }

    /// 终止流并产出唯一 trailer;所有关闭入口共用同一释放顺序。
    fn finish(&mut self, reason: EdgeCloseReason) -> Frame<Bytes> {
        self.subscription.take();
        self.guard.take();
        // 目录租约与订阅同生共死:摘索引的同一处也摘指路条,不留脏条目。
        self.directory_lease.take();
        self.lifetime.take();
        self.idle_sleep.take();
        self.done = true;
        let (status, message) = reason.trailer();
        let mut trailers = http::HeaderMap::with_capacity(2);
        trailers.insert("grpc-status", status);
        trailers.insert("grpc-message", message);
        Frame::trailers(trailers)
    }

    /// 注册表关闭码 → 关闭原因(1008=策略封禁,其余按 drain)。
    fn registry_reason(&self) -> EdgeCloseReason {
        match self.guard.as_ref().map(ConnGuard::ws_close_code) {
            Some(1008) => EdgeCloseReason::Policy,
            _ => EdgeCloseReason::Drain,
        }
    }
}

impl Body for EdgeSubscribeBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        // 1) 管理面关闭:同步码快查;Pending 分支才登记 waker(复用注册表竞态封装)。
        if self
            .guard
            .as_ref()
            .is_some_and(|guard| guard.requested_close_code().is_some())
        {
            let reason = self.registry_reason();
            return Poll::Ready(Some(Ok(self.finish(reason))));
        }
        // 2) 最长存活。
        if self
            .lifetime
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Some(Ok(self.finish(EdgeCloseReason::MaxAge))));
        }
        // 3) ring 取帧/关闭。
        let ring = self
            .subscription
            .as_ref()
            .expect("subscription exists until done")
            .ring()
            .clone();
        match ring.poll_pop(cx) {
            Poll::Ready(Ok(frame)) => {
                // 有帧到达:空闲计时(若已建立)向后推。取出字节后 QueuedFrame 的
                // lease/queue_ref 守卫随解构 Drop,预算即时归还(队列驻留语义)。
                let QueuedFrame { bytes, .. } = frame;
                let idle_timeout = self.idle_timeout;
                if let Some(sleep) = self.idle_sleep.as_mut() {
                    let deadline = TokioInstant::now() + idle_timeout;
                    sleep.as_mut().reset(deadline);
                }
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Err(reason)) => Poll::Ready(Some(Ok(self.finish(reason)))),
            Poll::Pending => {
                // 管理面关闭可能夹在快查与 ring 注册之间:注册 waker 后复查。
                let registry_close = self.close_wait.subscribe_if_needed(cx);
                if registry_close {
                    let reason = self.registry_reason();
                    return Poll::Ready(Some(Ok(self.finish(reason))));
                }
                // 惰性空闲计时:首次 Pending 才建 timer,短命流不进 timer wheel。
                if self.idle_timeout > Duration::ZERO {
                    if self.idle_sleep.is_none() {
                        let deadline = TokioInstant::now() + self.idle_timeout;
                        self.idle_sleep = Some(Box::pin(tokio::time::sleep_until(deadline)));
                    }
                    if self
                        .idle_sleep
                        .as_mut()
                        .expect("idle timer just ensured")
                        .as_mut()
                        .poll(cx)
                        .is_ready()
                    {
                        return Poll::Ready(Some(Ok(self.finish(EdgeCloseReason::Idle))));
                    }
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[path = "../../tests/unit/edge_hub.rs"]
#[cfg(test)]
mod tests;
