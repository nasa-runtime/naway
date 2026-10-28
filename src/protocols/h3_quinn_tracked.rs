//! HTTP/3 服务端入站 Quinn 适配。
//!
//! 上游 `h3-quinn` 保持底层 `quinn::RecvStream` 私有，无法把其真实 0-RTT 属性
//! 传给路由管线。本模块只适配服务端接收流并记录该属性；H3/QPACK 状态机仍
//! 由 `h3`执行，服务端主动开流仍复用 `h3-quinn`。

use std::collections::HashSet;
use std::convert::TryInto;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{self, Poll};

use bytes::{Buf, Bytes};
use futures::{ready, stream, Stream, StreamExt};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use h3_datagram::quic_traits::DatagramConnectionExt;
use parking_lot::Mutex;
use quinn::{AcceptBi, AcceptUni, OpenBi, OpenUni, ReadError, VarInt};
use tokio_util::sync::ReusableBoxFuture;

type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;

/// 真实 0-RTT request stream 登记表。
///
/// 业务作用：在 Quinn 入站层记录并一次性消费 early stream id，避免应用层
/// 依赖客户端可伪造的 header 判断 0-RTT。
#[derive(Clone, Default)]
pub(crate) struct EarlyStreamTracker {
    streams: Arc<Mutex<HashSet<u64>>>,
}

impl EarlyStreamTracker {
    /// 业务作用：在 request header 解码完成后消费对应的传输层 early 证据。
    ///
    /// 参数说明：
    /// - `stream_id`：是 H3 request stream 的稳定 QUIC id。
    ///
    /// 返回：该 id 由 Quinn 标记为 0-RTT 时返回 `true`，证据随即删除。
    pub(crate) fn take(&self, stream_id: StreamId) -> bool {
        self.streams.lock().remove(&stream_id.into_inner())
    }

    /// 业务作用：在底层流被 H3 状态机接管前保存其真实 early 位。
    ///
    /// 参数说明：
    /// - `stream`：是尚未被包装的 Quinn 接收流。
    ///
    /// 返回：无；普通 1-RTT 流不会创建任何登记。
    fn observe(&self, stream: &quinn::RecvStream) {
        if stream.is_0rtt() {
            self.streams.lock().insert(u64::from(stream.id()));
        }
    }
}

/// 带 0-RTT 证据追踪的 Quinn H3 服务端连接。
pub(crate) struct Connection {
    conn: quinn::Connection,
    incoming_bi: BoxStreamSync<'static, <AcceptBi<'static> as Future>::Output>,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    incoming_uni: BoxStreamSync<'static, <AcceptUni<'static> as Future>::Output>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
    early: EarlyStreamTracker,
}

impl Connection {
    /// 业务作用：为一条 Quinn 连接创建 H3 入站适配和同源 early-stream 证据句柄。
    ///
    /// 参数说明：
    /// - `conn`：是 listener 已接受的 QUIC 连接。
    ///
    /// 返回：返回供 `h3` 消费的适配器与供路由管线消费的追踪器。
    pub(crate) fn new(conn: quinn::Connection) -> (Self, EarlyStreamTracker) {
        let early = EarlyStreamTracker::default();
        let connection = Self {
            conn: conn.clone(),
            incoming_bi: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_bi().await, conn))
            })),
            opening_bi: None,
            incoming_uni: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_uni().await, conn))
            })),
            opening_uni: None,
            early: early.clone(),
        };
        (connection, early)
    }
}

impl<B> quic::Connection<B> for Connection
where
    B: Buf,
{
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    /// 业务作用：接收一条客户端双向流，并在失去底层类型前记录真实 0-RTT 位。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：流就绪时返回 H3 双向流；连接失败时返回协议错误。
    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
            .expect("QUIC accept stream is persistent")
            .map_err(convert_connection_error)?;
        self.early.observe(&recv);
        Poll::Ready(Ok(BidiStream {
            send: SendStream::new(send),
            recv: RecvStream::new(recv),
        }))
    }

    /// 业务作用：接收 H3 control/QPACK 单向流，不把它们误认为业务请求。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：流就绪时返回只读适配；连接失败时返回协议错误。
    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let recv = ready!(self.incoming_uni.poll_next_unpin(cx))
            .expect("QUIC accept stream is persistent")
            .map_err(convert_connection_error)?;
        Poll::Ready(Ok(RecvStream::new(recv)))
    }

    /// 业务作用：复用官方 `h3-quinn` 主动开流实现，避免入站追踪改变出站协议行为。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回绑定同一 Quinn 连接的官方开流句柄。
    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl<B> DatagramConnectionExt<B> for Connection
where
    B: Buf,
{
    type SendDatagramHandler = h3_quinn::datagram::SendDatagramHandler;
    type RecvDatagramHandler = h3_quinn::datagram::RecvDatagramHandler;

    /// 业务作用：向 WebTransport 状态机提供绑定同一 Quinn 连接的 DATAGRAM 发送句柄。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回官方 Quinn DATAGRAM 适配器，发送能力仍受 transport 协商与队列硬门约束。
    fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
        let official = h3_quinn::Connection::new(self.conn.clone());
        <h3_quinn::Connection as DatagramConnectionExt<B>>::send_datagram_handler(&official)
    }

    /// 业务作用：向 WebTransport 状态机提供绑定同一 Quinn 连接的 DATAGRAM 接收句柄。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回官方 Quinn DATAGRAM 适配器；连接级分发仍由唯一消费方按 session id 限流。
    fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
        let official = h3_quinn::Connection::new(self.conn.clone());
        <h3_quinn::Connection as DatagramConnectionExt<B>>::recv_datagram_handler(&official)
    }
}

impl<B> quic::OpenStreams<B> for Connection
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    /// 业务作用：为 H3 状态机主动创建双向流，并保持与入站流一致的适配语义。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：流配额可用时返回双向流，连接失败时返回 transport 错误。
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        poll_open_bidi(&self.conn, &mut self.opening_bi, cx)
    }

    /// 业务作用：为 H3 control/QPACK 状态机主动创建单向发送流。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：流配额可用时返回发送流，连接失败时返回 transport 错误。
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        poll_open_send(&self.conn, &mut self.opening_uni, cx)
    }

    /// 业务作用：用 H3 错误码关闭整个 QUIC 连接，阻止错误连接继续接收业务流。
    ///
    /// 参数说明：
    /// - `code`：是 H3 应用错误码
    /// - `reason`：是不含敏感数据的关闭原因。
    ///
    /// 返回：无；关闭信号由 Quinn 异步交付给对端。
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        close_connection(&self.conn, code, reason);
    }
}

/// H3 主动开流句柄。
pub(crate) struct OpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl<B> quic::OpenStreams<B> for OpenStreams
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    /// 业务作用：为持有 opener 的 H3 子任务创建双向流。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：流配额可用时返回双向流，连接失败时返回 transport 错误。
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        poll_open_bidi(&self.conn, &mut self.opening_bi, cx)
    }

    /// 业务作用：为持有 opener 的 H3 子任务创建单向发送流。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：流配额可用时返回发送流，连接失败时返回 transport 错误。
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        poll_open_send(&self.conn, &mut self.opening_uni, cx)
    }

    /// 业务作用：用 H3 错误码关闭 opener 所属连接，避免子任务失去连接终止能力。
    ///
    /// 参数说明：
    /// - `code`：是 H3 应用错误码
    /// - `reason`：是不含敏感数据的关闭原因。
    ///
    /// 返回：无；关闭信号由 Quinn 异步交付给对端。
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        close_connection(&self.conn, code, reason);
    }
}

/// 轮询创建一条 Quinn 双向流。
///
/// 业务作用：集中维护可取消 open future，保证 pending 后再次 poll 不会重复申请流额度。
///
/// 参数说明：
/// - `conn`：是目标连接
/// - `opening`：保存未完成 future
/// - `cx`：是调度上下文。
///
/// 返回：成功时返回 H3 双向流适配，连接失败时返回 transport 错误。
fn poll_open_bidi<B: Buf>(
    conn: &quinn::Connection,
    opening: &mut Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    cx: &mut task::Context<'_>,
) -> Poll<Result<BidiStream<B>, StreamErrorIncoming>> {
    let pending = opening.get_or_insert_with(|| {
        Box::pin(stream::unfold(conn.clone(), |conn| async {
            Some((conn.open_bi().await, conn))
        }))
    });
    let (send, recv) = ready!(pending.poll_next_unpin(cx))
        .expect("QUIC open stream is persistent")
        .map_err(|error| StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(error),
        })?;
    Poll::Ready(Ok(BidiStream {
        send: SendStream::new(send),
        recv: RecvStream::new(recv),
    }))
}

/// 轮询创建一条 Quinn 单向发送流。
///
/// 业务作用：集中维护可取消 open future，保证 control/QPACK 流申请遵循 Quinn 反压。
///
/// 参数说明：
/// - `conn`：是目标连接
/// - `opening`：保存未完成 future
/// - `cx`：是调度上下文。
///
/// 返回：成功时返回 H3 发送流适配，连接失败时返回 transport 错误。
fn poll_open_send<B: Buf>(
    conn: &quinn::Connection,
    opening: &mut Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
    cx: &mut task::Context<'_>,
) -> Poll<Result<SendStream<B>, StreamErrorIncoming>> {
    let pending = opening.get_or_insert_with(|| {
        Box::pin(stream::unfold(conn.clone(), |conn| async {
            Some((conn.open_uni().await, conn))
        }))
    });
    let send = ready!(pending.poll_next_unpin(cx))
        .expect("QUIC open stream is persistent")
        .map_err(|error| StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(error),
        })?;
    Poll::Ready(Ok(SendStream::new(send)))
}

/// 关闭 Quinn 连接。
///
/// 业务作用：统一校验 H3 error code 到 QUIC VarInt 的转换并发送连接关闭。
///
/// 参数说明：
/// - `conn`：是目标连接
/// - `code`：是 H3 应用错误码
/// - `reason`：是关闭原因。
///
/// 返回：无；合法 H3 错误码总能映射到 QUIC VarInt。
fn close_connection(conn: &quinn::Connection, code: h3::error::Code, reason: &[u8]) {
    conn.close(
        VarInt::from_u64(code.value()).expect("H3 error code is a valid QUIC VarInt"),
        reason,
    );
}

/// 将 Quinn 连接错误映射到 H3 transport 错误域。
///
/// 业务作用：保留对端关闭码与超时类型，使 H3 状态机能采取正确终态。
///
/// 参数说明：
/// - `error`：是 Quinn 连接终止原因。
///
/// 返回：返回等价的 H3 入站连接错误。
fn convert_connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match error {
        quinn::ConnectionError::ApplicationClosed(closed) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: closed.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        other => ConnectionErrorIncoming::Undefined(Arc::new(other)),
    }
}

/// 双向 request stream 适配。
pub(crate) struct BidiStream<B: Buf> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;

    /// 业务作用：将一条 request stream 拆为可独立驱动的发送与接收半边。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回所有权互斥的发送半边与接收半边。
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    /// 业务作用：从双向流的接收半边按序读取 H3 frame 字节。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：返回下一段有序字节、流结束或协议错误。
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    /// 业务作用：通知对端停止发送当前 request stream，用于拒绝或取消收尾。
    ///
    /// 参数说明：
    /// - `error_code`：是 H3 应用错误码。
    ///
    /// 返回：无；关闭竞态按幂等操作处理。
    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    /// 业务作用：返回用于 H3 request 归属与 early 证据关联的流标识。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回已校验可表示为 H3 `StreamId` 的 QUIC id。
    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    /// 业务作用：在写入新 H3 frame 前排空上一段未完成数据。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：可接收新 frame 时成功，写失败时返回 transport 错误。
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    /// 业务作用：完成响应发送方向，保留对端继续发送请求尾部的能力。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：FIN 提交成功时成功，流已关闭时返回错误。
    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    /// 业务作用：以显式 H3 码重置响应发送方向。
    ///
    /// 参数说明：
    /// - `reset_code`：是 H3 应用错误码。
    ///
    /// 返回：无；重复关闭按幂等语义忽略。
    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    /// 业务作用：交付一段已编码 H3 frame，并阻止上一段尚未排空时被覆盖。
    ///
    /// 参数说明：
    /// - `data`：是 H3 生成的有界写入缓冲。
    ///
    /// 返回：接管数据时成功，调用顺序破坏时返回内部错误。
    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    /// 业务作用：返回响应发送方向的 QUIC 流标识。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 H3 状态机使用的流 id。
    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for BidiStream<B> {
    /// 业务作用：为 WebTransport 等无 H3 DATA frame 外壳的流转发原始字节。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文
    /// - `buf`：是待发数据。
    ///
    /// 返回：返回已写字节数，连接或流失败时返回 transport 错误。
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

/// Quinn 接收半边适配。
pub(crate) struct RecvStream {
    stream: Option<quinn::RecvStream>,
    read_chunk: ReadChunkFuture,
}

type ReadChunkFuture = ReusableBoxFuture<
    'static,
    (
        quinn::RecvStream,
        Result<Option<quinn::Chunk>, quinn::ReadError>,
    ),
>;

impl RecvStream {
    /// 业务作用：创建保持 Quinn 流所有权的可取消有序读适配。
    ///
    /// 参数说明：
    /// - `stream`：是底层接收半边。
    ///
    /// 返回：返回首次 poll 时才安装真实读 future 的适配器。
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream: Some(stream),
            read_chunk: ReusableBoxFuture::new(async {
                unreachable!()
            }),
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    /// 业务作用：按 QUIC offset 有序读取下一段字节，保持 H3 frame 解码顺序。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：返回下一段字节、流结束或映射后的 H3 transport 错误。
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(mut stream) = self.stream.take() {
            self.read_chunk.set(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            });
        }
        let (stream, chunk) = ready!(self.read_chunk.poll(cx));
        self.stream = Some(stream);
        Poll::Ready(Ok(chunk
            .map_err(convert_read_error)?
            .map(|chunk| chunk.bytes)))
    }

    /// 业务作用：停止接收对端在当前流上的后续字节。
    ///
    /// 参数说明：
    /// - `error_code`：是 H3 拒绝或取消码。
    ///
    /// 返回：无；流已终止时不再改变结果。
    fn stop_sending(&mut self, error_code: u64) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.stop(VarInt::from_u64(error_code).unwrap_or(VarInt::MAX));
        }
    }

    /// 业务作用：暴露 H3 状态机与 early 证据共用的稳定流标识。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回当前 Quinn 流的 H3 id。
    fn recv_id(&self) -> StreamId {
        let raw: u64 = self
            .stream
            .as_ref()
            .expect("receive stream is retained between polls")
            .id()
            .into();
        raw.try_into().expect("Quinn stream id is a valid H3 id")
    }
}

/// 将 Quinn 读错误映射到 H3 流错误域。
///
/// 业务作用：保留对端 reset 码与连接终态，不把输入错误误报为内部 panic。
///
/// 参数说明：
/// - `error`：是 Quinn 有序读失败。
///
/// 返回：返回等价 H3 入站流错误。
fn convert_read_error(error: ReadError) -> StreamErrorIncoming {
    match error {
        ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        ReadError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(error),
        },
        ReadError::IllegalOrderedRead => {
            StreamErrorIncoming::Unknown("unordered QUIC read rejected".into())
        }
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

/// Quinn 发送半边适配。
pub(crate) struct SendStream<B: Buf> {
    stream: quinn::SendStream,
    writing: Option<WriteBuf<B>>,
}

impl<B: Buf> SendStream<B> {
    /// 业务作用：创建一次最多持有一个 H3 写缓冲的发送适配。
    ///
    /// 参数说明：
    /// - `stream`：是底层 Quinn 发送半边。
    ///
    /// 返回：返回尚未占用写缓冲的适配器。
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
    /// 业务作用：排空当前 H3 写缓冲，为下一个 frame 提供反压保证。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文。
    ///
    /// 返回：缓冲全部交付时成功，对端停止或连接失败时返回错误。
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = self.writing.as_mut() {
            while data.has_remaining() {
                let written = ready!(Pin::new(&mut self.stream).poll_write(cx, data.chunk()))
                    .map_err(convert_write_error)?;
                data.advance(written);
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    /// 业务作用：提交 QUIC FIN，明确当前响应不再发送后续字节。
    ///
    /// 参数说明：
    /// - `_cx`：是 trait 要求的调度上下文，Quinn 的 FIN 提交为同步操作。
    ///
    /// 返回：FIN 已提交时成功，流已关闭时返回错误。
    fn poll_finish(
        &mut self,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|error| StreamErrorIncoming::Unknown(Box::new(error))),
        )
    }

    /// 业务作用：立即重置响应发送方向，不继续占用排队字节。
    ///
    /// 参数说明：
    /// - `reset_code`：是 H3 应用错误码。
    ///
    /// 返回：无；超出 QUIC VarInt 时使用最大安全码。
    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
    }

    /// 业务作用：接管一段 H3 编码数据，保证前一段未排空时不被覆盖。
    ///
    /// 参数说明：
    /// - `data`：是 H3 生成的写缓冲。
    ///
    /// 返回：当前无待发数据时成功，trait 调用顺序违反时返回连接内部错误。
    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "H3 send stream reused before readiness".to_owned(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }

    /// 业务作用：返回当前响应发送半边的 H3 流标识。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回可由 H3 状态机消费的流 id。
    fn send_id(&self) -> StreamId {
        let raw: u64 = self.stream.id().into();
        raw.try_into().expect("Quinn stream id is a valid H3 id")
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for SendStream<B> {
    /// 业务作用：不添加 H3 DATA frame 外壳地写入原始 stream 字节。
    ///
    /// 参数说明：
    /// - `cx`：是异步调度上下文
    /// - `buf`：是待发数据。
    ///
    /// 返回：返回已写字节数，对端停止或连接失败时返回错误。
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if self.writing.is_some() {
            return Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "unframed write overlaps framed H3 data".to_owned(),
                ),
            }));
        }
        let written = ready!(Pin::new(&mut self.stream).poll_write(cx, buf.chunk()))
            .map_err(convert_write_error)?;
        buf.advance(written);
        Poll::Ready(Ok(written))
    }
}

/// 将 Quinn 写错误映射到 H3 流错误域。
///
/// 业务作用：保留 STOP_SENDING 码和连接终态，使上层不重试不可恢复写。
///
/// 参数说明：
/// - `error`：是 Quinn 写失败。
///
/// 返回：返回等价 H3 transport 错误。
fn convert_write_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(error),
        },
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}
