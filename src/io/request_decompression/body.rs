//! 有界流式请求解码与迟到失败传播。

use super::{strip_representation, Policy, Rejected, State};
use crate::{routing::ContentCoding, BoxBody, BoxError};
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder};
use bytes::{Buf, Bytes, BytesMut};
use http::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

pub(super) static GZIP_ACTIVE: AtomicUsize = AtomicUsize::new(0);
pub(super) static BROTLI_ACTIVE: AtomicUsize = AtomicUsize::new(0);
pub(super) static INPUT_BYTES: AtomicUsize = AtomicUsize::new(0);
const MAX_INPUT_BYTES: usize = 64 << 20;

/// 随解码器实际生命周期释放的进程并发凭证。
struct Permit(&'static AtomicUsize);

impl Permit {
    /// 业务作用：在构造编码库状态前取得进程额度，不允许热更重建绕过上限。
    ///
    /// 参数说明：
    /// - `coding`：需要占用的解码算法。
    ///
    /// 返回：取得槽位的凭证；容量不足立即503，不创建等待队列。
    fn acquire(coding: ContentCoding) -> Result<Self, Rejected> {
        let (counter, maximum) = match coding {
            ContentCoding::Gzip => (&GZIP_ACTIVE, 64),
            ContentCoding::Brotli => (&BROTLI_ACTIVE, 8),
        };
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < maximum).then_some(used + 1)
            })
            .map_err(|_| Rejected::Capacity)?;
        Ok(Self(counter))
    }
}

impl Drop for Permit {
    /// 业务作用：完成、失败和取消都归还同一个算法槽，不依赖后台清扫。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：进程活跃解码数量减少一。
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 输入只持有一个Bytes视图；编码库通过AsyncBufRead借用当前前缀。
struct Input {
    body: BoxBody,
    current: Bytes,
    retained: usize,
    trailers: Option<HeaderMap>,
    trailer_seen: bool,
    done: bool,
    check_brotli: bool,
    encoded: u64,
    consumed: u64,
    max_encoded: u64,
    work: usize,
    polls: usize,
    state: Arc<State>,
}

impl Input {
    /// 业务作用：为输入帧建立所有权与长度账目，构造时不消费客户端正文。
    ///
    /// 参数说明：
    /// - `body`：认证后的原始正文。
    /// - `coding`：首字节是否需要Brotli窗口验证。
    /// - `limit`：编码实体总字节上限。
    /// - `state`：共享首个失败。
    ///
    /// 返回：没有正文分配或复制的输入适配器。
    fn new(body: BoxBody, coding: ContentCoding, limit: u64, state: Arc<State>) -> Self {
        Self {
            body,
            current: Bytes::new(),
            retained: 0,
            trailers: None,
            trailer_seen: false,
            done: false,
            check_brotli: matches!(coding, ContentCoding::Brotli),
            encoded: 0,
            consumed: 0,
            max_encoded: limit,
            work: 0,
            polls: 0,
            state,
        }
    }

    /// 业务作用：消费完当前帧或取消时归还保留预算，Bytes切片不提前减少底层分配计费。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：释放当前输入视图及其已占用字节。
    fn release(&mut self) {
        self.current = Bytes::new();
        INPUT_BYTES.fetch_sub(std::mem::take(&mut self.retained), Ordering::AcqRel);
    }

    /// 业务作用：在底层IO错误类型擦除前冻结客户端拒绝，保持跨消费方归因。
    ///
    /// 参数说明：
    /// - `error`：固定拒绝类别。
    ///
    /// 返回：携带原始类型的IO错误。
    fn error(&self, error: Rejected) -> io::Error {
        self.state.reject(error);
        io::Error::other(error)
    }
}

impl Drop for Input {
    /// 业务作用：取消或解码器销毁时释放仍被保留的原始帧预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归还当前请求尚未交付的输入内存账目。
    fn drop(&mut self) {
        self.release();
        super::metrics::BYTES[0].fetch_add(self.encoded, Ordering::Relaxed);
    }
}

impl AsyncBufRead for Input {
    /// 业务作用：借用有界输入前缀，验证编码大小、Brotli窗口与HTTP实体结束顺序。
    ///
    /// 参数说明：
    /// - `cx`：异步唤醒上下文。
    ///
    /// 返回：可借用输入、背压或固定拒绝；EOF只来自完整HTTP输入结束。
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        loop {
            // 空帧与无输出成员也消耗执行预算，防止畸形输入在一个poll内独占worker。
            if this.work >= 16 << 10 || this.polls >= 64 {
                this.work = 0;
                this.polls = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if !this.current.is_empty() {
                return Poll::Ready(Ok(
                    &this.current[..this.current.len().min((16 << 10) - this.work)]
                ));
            }
            this.release();
            if this.done {
                return Poll::Ready(Ok(&[]));
            }
            this.polls += 1;
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => this.done = true,
                Poll::Ready(Some(Err(_))) => {
                    return Poll::Ready(Err(this.error(Rejected::Malformed)))
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if this.trailer_seen {
                            return Poll::Ready(Err(this.error(Rejected::Malformed)));
                        }
                        if data.len() as u64 > this.max_encoded - this.encoded {
                            return Poll::Ready(Err(this.error(Rejected::Limit)));
                        }
                        if let Some(&first) = data.first().filter(|_| this.check_brotli) {
                            // 编码库支持额外large-window语法；HTTP入口只接受RFC标准窗口，防止对端放大字典分配。
                            if first & 0x7f == 0x11 {
                                return Poll::Ready(Err(this.error(Rejected::Malformed)));
                            }
                            this.check_brotli = false;
                        }
                        if INPUT_BYTES
                            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                                (data.len() <= MAX_INPUT_BYTES - used).then_some(used + data.len())
                            })
                            .is_err()
                        {
                            return Poll::Ready(Err(this.error(Rejected::Capacity)));
                        }
                        this.retained = data.len();
                        this.encoded += data.len() as u64;
                        this.current = data;
                    }
                    Err(frame) => {
                        let Ok(mut trailers) = frame.into_trailers() else {
                            return Poll::Ready(Err(this.error(Rejected::Malformed)));
                        };
                        if this.trailer_seen
                            || trailers.len() > 64
                            || trailers
                                .iter()
                                .map(|(name, value)| name.as_str().len() + value.len())
                                .sum::<usize>()
                                > 32 << 10
                        {
                            return Poll::Ready(Err(this.error(Rejected::Malformed)));
                        }
                        strip_representation(&mut trailers);
                        // 认证和路由已经冻结，trailers不得重新引入身份或转发控制字段。
                        if trailers.iter().any(|(name, value)| {
                            let name = name.as_str();
                            super::forbidden_trailer(name)
                                || value.as_bytes().iter().any(|byte| byte.is_ascii_control())
                        }) {
                            return Poll::Ready(Err(this.error(Rejected::Malformed)));
                        }
                        this.trailer_seen = true;
                        this.trailers = Some(trailers);
                    }
                },
            }
        }
    }

    /// 业务作用：推进借用视图并按实际被codec消费的压缩字节计费膨胀比。
    ///
    /// 参数说明：
    /// - `amount`：codec已消费的前缀长度。
    ///
    /// 返回：不复制实体，累计实际输入及协作工作预算。
    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        let consumed = amount.min(this.current.len());
        this.current.advance(consumed);
        this.consumed += consumed as u64;
        this.work += consumed;
    }
}

impl AsyncRead for Input {
    /// 业务作用：提供AsyncBufRead的兼容读取入口，codec正常路径直接借用输入。
    ///
    /// 参数说明：
    /// - `cx`：异步唤醒上下文。
    /// - `output`：调用方持有的输出缓冲。
    ///
    /// 返回：推进有界读取并保留输入错误及背压。
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let input = ready!(self.as_mut().poll_fill_buf(cx))?;
        let length = input.len().min(output.remaining());
        output.put_slice(&input[..length]);
        self.consume(length);
        Poll::Ready(Ok(()))
    }
}

/// 保留具体codec类型，完成后仍可复验原HTTP输入EOF与trailers。
enum Codec {
    Gzip(Box<GzipDecoder<Input>>),
    Brotli(Box<BrotliDecoder<Input>>),
}

impl Codec {
    /// 业务作用：取得codec输入账目并在压缩流结束后继续复验HTTP边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：输入适配器独占引用，不移动或复制已读内容。
    fn input(&mut self) -> &mut Input {
        match self {
            Self::Gzip(codec) => codec.get_mut(),
            Self::Brotli(codec) => codec.get_mut(),
        }
    }

    /// 业务作用：推进当前算法的有界解码，禁止借助额外聚合缓冲绕开背压。
    ///
    /// 参数说明：
    /// - `cx`：异步唤醒上下文。
    /// - `output`：本次最多一个chunk的最终输出缓冲。
    ///
    /// 返回：解码进度、等待输入或编码错误。
    fn poll(&mut self, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Gzip(codec) => Pin::new(codec.as_mut()).poll_read(cx, output),
            Self::Brotli(codec) => Pin::new(codec.as_mut()).poll_read(cx, output),
        }
    }
}

/// 活跃处理持有codec及名额，结束时一起释放。
struct Active {
    codec: Codec,
    _permit: Permit,
}

pub(super) struct Decoded {
    active: Option<Active>,
    policy: Policy,
    state: Arc<State>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    decoded: u64,
    codec_done: bool,
    frames: usize,
    output: Option<BytesMut>,
}

impl Decoded {
    /// 业务作用：冻结策略并取得解码容量，输入直到下游轮询才开始消费。
    ///
    /// 参数说明：
    /// - `body`：原始编码正文。
    /// - `coding`：已验证的单层算法。
    /// - `policy`：请求冻结的资源边界。
    /// - `state`：错误传播对象。
    ///
    /// 返回：可流式读取的正文；容量不足返回本地拒绝。
    pub(super) fn new(
        body: BoxBody,
        coding: ContentCoding,
        policy: Policy,
        state: Arc<State>,
    ) -> Result<Self, Rejected> {
        let permit = Permit::acquire(coding)?;
        let input = Input::new(body, coding, policy.encoded, state.clone());
        let codec = match coding {
            ContentCoding::Gzip => {
                let mut codec = GzipDecoder::new(input);
                codec.multiple_members(true);
                Codec::Gzip(Box::new(codec))
            }
            ContentCoding::Brotli => Codec::Brotli(Box::new(BrotliDecoder::new(input))),
        };
        Ok(Self {
            active: Some(Active {
                codec,
                _permit: permit,
            }),
            deadline: Box::pin(tokio::time::sleep(Duration::from_millis(policy.timeout_ms))),
            policy,
            state,
            decoded: 0,
            codec_done: false,
            frames: 0,
            output: None,
        })
    }

    /// 业务作用：冻结失败并立即释放输入与codec，错误后禁止继续消费客户端正文。
    ///
    /// 参数说明：
    /// - `error`：本次拒绝类别。
    ///
    /// 返回：一次拥有型错误帧，之后正文结束。
    fn reject(&mut self, error: Rejected) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.state.reject(error);
        self.active = None;
        self.output = None;
        super::metrics::BYTES[1].fetch_add(std::mem::take(&mut self.decoded), Ordering::Relaxed);
        Poll::Ready(Some(Err(Box::new(error))))
    }
}

impl Body for Decoded {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按需解码并在交付前检查明文额度，完整EOF后才交付trailers。
    ///
    /// 参数说明：
    /// - `cx`：异步唤醒上下文。
    ///
    /// 返回：一个有界数据帧、trailers、背压或固定本地错误。
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.active.is_none() {
            return Poll::Ready(None);
        }
        // 先检查绝对期限，再消费任何输入；等待上传与背压均不能为攻击者续期。
        if this.deadline.as_mut().poll(cx).is_ready() {
            return this.reject(Rejected::Deadline);
        }
        if this.frames >= 8 {
            this.frames = 0;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let active = this.active.as_mut().expect("active decoder");
        if !this.codec_done {
            let mut output = this
                .output
                .take()
                .unwrap_or_else(|| BytesMut::with_capacity(this.policy.chunk));
            let mut buffer = ReadBuf::uninit(output.spare_capacity_mut());
            match active.codec.poll(cx, &mut buffer) {
                Poll::Pending => {
                    this.output = Some(output);
                    return Poll::Pending;
                }
                Poll::Ready(Err(_)) => {
                    return this.reject(this.state.failure().unwrap_or(Rejected::Malformed));
                }
                Poll::Ready(Ok(())) => {}
            }
            let length = buffer.filled().len();
            if length != 0 {
                let total = this.decoded + length as u64;
                let allowed = active.codec.input().consumed.max(1024) * this.policy.ratio;
                // 只有仍在两种预算内的完整帧才可交给正文检查器或上游，拒绝帧不泄漏部分输出。
                if total > this.policy.decoded || total > allowed {
                    return this.reject(Rejected::Limit);
                }
                // SAFETY: ReadBuf仅将codec实际初始化的前缀标为filled，length不超过当前spare容量。
                unsafe {
                    output.set_len(length);
                }
                this.decoded = total;
                this.frames += 1;
                return Poll::Ready(Some(Ok(Frame::data(output.freeze()))));
            }
            this.codec_done = true;
        }
        // Brotli完成不意味着HTTP完成；复验未消费尾部并等到真实EOF，避免忽略坏尾部或丢失trailers。
        let input = active.codec.input();
        match Pin::new(&mut *input).poll_fill_buf(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => this.reject(this.state.failure().unwrap_or(Rejected::Malformed)),
            Poll::Ready(Ok(tail)) if !tail.is_empty() => this.reject(Rejected::Malformed),
            Poll::Ready(Ok(_)) => {
                let trailers = input.trailers.take();
                this.active = None;
                super::metrics::EVENTS[0].fetch_add(1, Ordering::Relaxed);
                super::metrics::BYTES[1]
                    .fetch_add(std::mem::take(&mut this.decoded), Ordering::Relaxed);
                Poll::Ready(trailers.map(|headers| Ok(Frame::trailers(headers))))
            }
        }
    }

    /// 业务作用：只有输入完整验证并交付trailers后才声明结束，空编码输入仍需校验。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：codec与输入均已释放时为true。
    fn is_end_stream(&self) -> bool {
        self.active.is_none()
    }

    /// 业务作用：声明解码长度未知，禁止HTTP栈沿用压缩实体长度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：结束为零，其余不提供精确长度。
    fn size_hint(&self) -> SizeHint {
        if self.active.is_none() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}

impl Drop for Decoded {
    /// 业务作用：未完整验证便取消的上传形成独立结果，计入已实际交付的明文字节。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：结束未结算的观察账目，输入与并发凭证由字段析构释放。
    fn drop(&mut self) {
        if self.active.is_some() {
            super::metrics::EVENTS[6].fetch_add(1, Ordering::Relaxed);
            super::metrics::BYTES[1].fetch_add(self.decoded, Ordering::Relaxed);
        }
    }
}

pub(super) struct ResponseGuard {
    inner: Option<BoxBody>,
    state: Arc<State>,
    done: bool,
}

impl ResponseGuard {
    /// 业务作用：让已发送响应观察迟到的上传失败，防止错误后继续交付响应实体。
    ///
    /// 参数说明：
    /// - `inner`：原始响应流。
    /// - `state`：请求解码失败记录。
    ///
    /// 返回：不读取或复制正文的响应观察器。
    pub(super) fn new(inner: BoxBody, state: Arc<State>) -> Self {
        Self {
            inner: Some(inner),
            state,
            done: false,
        }
    }
}

impl Body for ResponseGuard {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：交付响应前复验上传失败，已提交响应头时用流错误结束连接或流。
    ///
    /// 参数说明：
    /// - `cx`：响应等待者的唤醒上下文。
    ///
    /// 返回：原响应帧、背压或迟到的本地请求错误。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        self.state.wake.register(cx.waker());
        if let Some(error) = self.state.failure() {
            self.done = true;
            self.inner = None;
            return Poll::Ready(Some(Err(Box::new(error))));
        }
        let result = Pin::new(self.inner.as_mut().expect("active response")).poll_frame(cx);
        if let Some(error) = self.state.failure() {
            self.done = true;
            self.inner = None;
            return Poll::Ready(Some(Err(Box::new(error))));
        }
        if matches!(result, Poll::Ready(None | Some(Err(_)))) {
            self.done = true;
            self.inner = None;
        }
        result
    }

    /// 业务作用：保留底层响应结束语义，不为早返回上游无限读取上传正文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原响应已结束或观察到失败时为true。
    fn is_end_stream(&self) -> bool {
        self.done
            || (self.state.failure().is_none()
                && self.inner.as_ref().is_none_or(Body::is_end_stream))
    }

    /// 业务作用：保持响应长度声明，正文上传的编码变换不改变响应表示。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原响应长度提示。
    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map(Body::size_hint)
            .unwrap_or_else(|| SizeHint::with_exact(0))
    }
}
