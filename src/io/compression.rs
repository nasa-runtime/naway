//! V5 HTTP 响应内容编码协商与流式 gzip/Brotli 编解码。
//!
//! 这里故意把 Hyper `Body` 适配成 `AsyncBufRead`，让 codec 直接借用当前 `Bytes`
//! frame 作为输入。默认路径不进入本模块；启用压缩的 route 也只保留【一个上游
//! frame 的未消费尾部 + 一个固定上限的下游输出块】，不聚合完整响应。

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use async_compression::tokio::bufread::{BrotliDecoder, BrotliEncoder, GzipDecoder, GzipEncoder};
use async_compression::Level;
use bytes::{Buf, Bytes, BytesMut};
use http::header::{
    ACCEPT_ENCODING, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, VARY,
};
use http::{HeaderMap, HeaderValue, Method};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::{Response, StatusCode};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

use crate::metrics::Metrics;
use crate::routing::{CompressionPolicy, ContentCoding};
use crate::{text_status, BoxBody, BoxError};

/// 客户端对本网关支持的内容编码给出的千分制 q 值。
///
/// `Option` 区分“未显式出现”和“显式 q=0”；通配符只在没有具体 token 时生效。
#[derive(Clone, Copy, Default)]
pub(crate) struct AcceptedEncodings {
    /// `Accept-Encoding` 是否出现；缺失意味着只接受 identity。
    present: bool,
    /// gzip 的显式 q 值。
    gzip: Option<u16>,
    /// Brotli 的显式 q 值。
    brotli: Option<u16>,
    /// `*` 的 q 值。
    wildcard: Option<u16>,
    /// identity 的显式 q 值。
    identity: Option<u16>,
}

impl AcceptedEncodings {
    /// 从请求头解析内容编码偏好，全程借用 HeaderMap，不构造 token `String`。
    ///
    /// 多行 header 按一个逗号列表处理；非法 q 值只禁用对应 token，不让坏偏好头
    /// 变成请求级 400。重复 token 取最大 q 值，避免代理合并多行后意外降级。
    ///
    /// # 参数
    /// - `headers`: 安全 path 规范化前后的请求头均可；本函数不修改它。
    pub(crate) fn parse(headers: &HeaderMap) -> Self {
        let mut accepted = Self::default();
        for value in headers.get_all(ACCEPT_ENCODING) {
            accepted.present = true;
            let Ok(raw) = value.to_str() else {
                continue;
            };
            for item in raw
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                let mut fields = item.split(';');
                let coding = fields.next().unwrap_or_default().trim();
                let mut quality = 1000;
                for parameter in fields {
                    let Some((name, value)) = parameter.trim().split_once('=') else {
                        continue;
                    };
                    if name.trim().eq_ignore_ascii_case("q") {
                        quality = parse_quality(value.trim()).unwrap_or(0);
                    }
                }
                let slot = if coding.eq_ignore_ascii_case("gzip") {
                    Some(&mut accepted.gzip)
                } else if coding.eq_ignore_ascii_case("br") {
                    Some(&mut accepted.brotli)
                } else if coding == "*" {
                    Some(&mut accepted.wildcard)
                } else if coding.eq_ignore_ascii_case("identity") {
                    Some(&mut accepted.identity)
                } else {
                    None
                };
                if let Some(slot) = slot {
                    *slot = Some(slot.unwrap_or(0).max(quality));
                }
            }
        }
        accepted
    }

    /// 返回指定编码的有效 q 值；具体 token 优先于 `*`。
    ///
    /// # 参数
    /// - `coding`: 服务端正在评估的 gzip 或 Brotli。
    fn quality(self, coding: ContentCoding) -> u16 {
        if !self.present {
            return 0;
        }
        match coding {
            ContentCoding::Gzip => self.gzip,
            ContentCoding::Brotli => self.brotli,
        }
        .or(self.wildcard)
        .unwrap_or(0)
    }

    /// 判断客户端是否允许 identity。
    ///
    /// RFC 9110 规定 identity 默认可接受；只有显式 `identity;q=0`，或没有更具体
    /// identity 条目时的 `*;q=0`，才排除它。
    fn identity_allowed(self) -> bool {
        self.identity
            .map(|quality| quality > 0)
            .unwrap_or_else(|| self.wildcard != Some(0))
    }

    /// 按 route 算法顺序和客户端 q 值选择输出编码。
    ///
    /// # 参数
    /// - `policy`: build 期编译的 route 压缩策略；算法顺序用于 q 值相同时裁决。
    fn select(self, policy: &CompressionPolicy) -> Option<ContentCoding> {
        let mut selected = None;
        let mut selected_quality = 0;
        for &coding in &policy.algorithms {
            let quality = self.quality(coding);
            if quality > selected_quality {
                selected = Some(coding);
                selected_quality = quality;
            }
        }
        selected
    }
}

/// 将 qvalue 解析为 0..=1000 的整数，避免热路径浮点和临时字符串。
///
/// # 参数
/// - `raw`: `q=` 后的借用文本；仅接受 RFC 形式 0、1、0.xxx、1.000。
fn parse_quality(raw: &str) -> Option<u16> {
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let mut value = 0_u16;
            let mut scale = 100_u16;
            for digit in fraction.bytes() {
                value += u16::from(digit - b'0') * scale;
                scale /= 10;
            }
            Some(value)
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

/// 对一个 route 响应应用内容编码协商。
///
/// 执行顺序要求：header/CORS → `sub_filter` → 本函数 → `limit_rate`。因此文本改写
/// 看到未压缩实体，而带宽限制统计真正上网线的压缩字节。已是客户端支持的 gzip/br
/// 响应完全直通；不支持时才以流式 decoder 退回 identity。
///
/// # 参数
/// - `resp`: 上游、静态服务或网关短路产生的响应；body 所有权被移动，不做 collect。
/// - `policy`: 最终 response route 的压缩配置。
/// - `accepted`: 请求入口一次解析出的 Accept-Encoding 小值对象。
/// - `method`: 原请求方法；HEAD 响应不得创建会产生实体字节的 codec。
/// - `metrics`: 共享低基数指标；仅真实执行 codec 时累加。
pub(crate) fn apply_response_compression(
    mut resp: Response<BoxBody>,
    policy: &CompressionPolicy,
    accepted: AcceptedEncodings,
    method: &Method,
    metrics: &Metrics,
) -> Response<BoxBody> {
    if method == Method::HEAD
        || response_must_not_have_body(resp.status())
        || resp.status() == StatusCode::SWITCHING_PROTOCOLS
        || resp.headers().contains_key(CONTENT_RANGE)
        || cache_control_forbids_transform(resp.headers())
    {
        return resp;
    }

    match existing_content_coding(resp.headers()) {
        ExistingCoding::Other => resp,
        ExistingCoding::Gzip if accepted.quality(ContentCoding::Gzip) > 0 => {
            append_accept_encoding_vary(resp.headers_mut());
            resp
        }
        ExistingCoding::Brotli if accepted.quality(ContentCoding::Brotli) > 0 => {
            append_accept_encoding_vary(resp.headers_mut());
            resp
        }
        ExistingCoding::Gzip if accepted.identity_allowed() => {
            prepare_transformed_headers(resp.headers_mut(), None);
            metrics.inc_decompression_gzip();
            wrap_codec(resp, CodecAction::Decode(ContentCoding::Gzip), policy)
        }
        ExistingCoding::Brotli if accepted.identity_allowed() => {
            prepare_transformed_headers(resp.headers_mut(), None);
            metrics.inc_decompression_brotli();
            wrap_codec(resp, CodecAction::Decode(ContentCoding::Brotli), policy)
        }
        ExistingCoding::Gzip | ExistingCoding::Brotli => not_acceptable(resp),
        ExistingCoding::Identity => {
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            let known_too_small = resp
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(|length| length < policy.min_length)
                .unwrap_or(false);
            if known_too_small || !policy.permits_content_type(content_type) {
                return resp;
            }
            let Some(coding) = accepted.select(policy) else {
                return if accepted.identity_allowed() {
                    resp
                } else {
                    not_acceptable(resp)
                };
            };
            prepare_transformed_headers(resp.headers_mut(), Some(coding));
            match coding {
                ContentCoding::Gzip => metrics.inc_compression_gzip(),
                ContentCoding::Brotli => metrics.inc_compression_brotli(),
            }
            wrap_codec(resp, CodecAction::Encode(coding), policy)
        }
    }
}

/// 在客户端明确拒绝 identity 及所有可用编码时生成 406。
///
/// 上游 body 在响应头尚未发给下游前被 drop，传播取消并释放连接/并发 RAII；只移动
/// extensions，保留 access log 使用的上游 trace，不复制上游 header 或 payload。
///
/// # 参数
/// - `resp`: 已取得但无法按客户端能力表达的响应。
fn not_acceptable(mut resp: Response<BoxBody>) -> Response<BoxBody> {
    let extensions = std::mem::take(resp.extensions_mut());
    let mut rejected = text_status(406, "no acceptable content encoding");
    *rejected.extensions_mut() = extensions;
    rejected
}

/// 响应头里已有的内容编码分类。
enum ExistingCoding {
    /// 无编码或显式 identity。
    Identity,
    /// 单层 gzip。
    Gzip,
    /// 单层 Brotli。
    Brotli,
    /// 多层、未知或不可解析编码；为了不破坏实体，保持原样。
    Other,
}

/// 识别单层上游 `Content-Encoding`，不为 token 分配字符串。
///
/// # 参数
/// - `headers`: 当前响应头。
fn existing_content_coding(headers: &HeaderMap) -> ExistingCoding {
    let mut found = None;
    for value in headers.get_all(CONTENT_ENCODING) {
        let Ok(raw) = value.to_str() else {
            return ExistingCoding::Other;
        };
        for coding in raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            if found.is_some() {
                return ExistingCoding::Other;
            }
            found = Some(if coding.eq_ignore_ascii_case("identity") {
                ExistingCoding::Identity
            } else if coding.eq_ignore_ascii_case("gzip") {
                ExistingCoding::Gzip
            } else if coding.eq_ignore_ascii_case("br") {
                ExistingCoding::Brotli
            } else {
                ExistingCoding::Other
            });
        }
    }
    found.unwrap_or(ExistingCoding::Identity)
}

/// 判断响应是否声明 `Cache-Control: no-transform`。
///
/// # 参数
/// - `headers`: 当前响应头；多行值逐项借用扫描。
fn cache_control_forbids_transform(headers: &HeaderMap) -> bool {
    headers.get_all(CACHE_CONTROL).iter().any(|value| {
        value
            .to_str()
            .map(|raw| {
                raw.split(',').any(|directive| {
                    directive
                        .trim()
                        .split_once('=')
                        .map(|(name, _)| name.trim())
                        .unwrap_or_else(|| directive.trim())
                        .eq_ignore_ascii_case("no-transform")
                })
            })
            .unwrap_or(false)
    })
}

/// 判断状态码是否禁止实体 body。
///
/// # 参数
/// - `status`: 当前响应状态。
fn response_must_not_have_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

/// 为内容变换修正实体元数据。
///
/// `Content-Length`、`Content-MD5` 与字节范围都针对变换前表示，继续透传会造成截断或
/// 校验错误。强 ETag 降为弱验证器，保留“语义等价”同时不再声称逐字节相同。
///
/// # 参数
/// - `headers`: 原地修改的响应头，避免复制整份 HeaderMap。
/// - `coding`: 编码时写入 gzip/br；解码回 identity 时传 `None` 并删除该头。
fn prepare_transformed_headers(headers: &mut HeaderMap, coding: Option<ContentCoding>) {
    headers.remove(CONTENT_LENGTH);
    headers.remove(ACCEPT_RANGES);
    headers.remove(http::header::HeaderName::from_static("content-md5"));
    match coding {
        Some(coding) => {
            headers.insert(CONTENT_ENCODING, HeaderValue::from_static(coding.as_str()));
        }
        None => {
            headers.remove(CONTENT_ENCODING);
        }
    }
    weaken_strong_etag(headers);
    append_accept_encoding_vary(headers);
}

/// 将强 ETag 原地替换为弱 ETag。
///
/// 只有确实发生内容编码变换的慢路径才分配这几十字节的控制面字符串；body 本身仍按
/// `Bytes` frame 流式处理。非法 ETag 直接删除，避免构造非法下游响应头。
///
/// # 参数
/// - `headers`: 当前响应头。
fn weaken_strong_etag(headers: &mut HeaderMap) {
    let Some(raw) = headers.get(ETAG).and_then(|value| value.to_str().ok()) else {
        return;
    };
    if raw.starts_with("W/") || raw.starts_with("w/") {
        return;
    }
    let mut weak = String::with_capacity(raw.len() + 2);
    weak.push_str("W/");
    weak.push_str(raw);
    match HeaderValue::from_str(&weak) {
        Ok(value) => {
            headers.insert(ETAG, value);
        }
        Err(_) => {
            headers.remove(ETAG);
        }
    }
}

/// 确保响应按 `Accept-Encoding` 区分共享缓存变体。
///
/// 允许使用多个 Vary header，避免为拼接已有值而复制整行。若已有 `*` 或
/// `Accept-Encoding` token 则不重复追加。
///
/// # 参数
/// - `headers`: 当前响应头。
fn append_accept_encoding_vary(headers: &mut HeaderMap) {
    let already_varies = headers.get_all(VARY).iter().any(|value| {
        value
            .to_str()
            .map(|raw| {
                raw.split(',').any(|name| {
                    let name = name.trim();
                    name == "*" || name.eq_ignore_ascii_case("accept-encoding")
                })
            })
            .unwrap_or(true)
    });
    if !already_varies {
        headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

/// codec 的方向和算法。
#[derive(Clone, Copy)]
enum CodecAction {
    /// 把 identity 实体压成指定编码。
    Encode(ContentCoding),
    /// 把客户端不支持的上游编码解成 identity。
    Decode(ContentCoding),
}

/// 用流式 codec 包裹响应 body。
///
/// # 参数
/// - `resp`: 已修正内容编码相关 header 的响应。
/// - `action`: 编码/解码方向和算法。
/// - `policy`: 提供算法 level 与单输出块内存上限。
fn wrap_codec(
    resp: Response<BoxBody>,
    action: CodecAction,
    policy: &CompressionPolicy,
) -> Response<BoxBody> {
    resp.map(|body| {
        // trailers 极少出现，但必须在 codec EOF 后原样发出。共享槽只在“收到 trailers”
        // 和“codec 完成”两个冷点加锁，普通 data frame 没有锁操作。
        let trailers = Arc::new(Mutex::new(None));
        let source = BodyBufReader::new(body, trailers.clone(), policy.chunk_bytes);
        let reader: Pin<Box<dyn AsyncRead + Send + Sync>> = match action {
            CodecAction::Encode(ContentCoding::Gzip) => Box::pin(GzipEncoder::with_quality(
                source,
                Level::Precise(policy.gzip_level),
            )),
            CodecAction::Encode(ContentCoding::Brotli) => Box::pin(BrotliEncoder::with_quality(
                source,
                Level::Precise(policy.brotli_quality),
            )),
            CodecAction::Decode(ContentCoding::Gzip) => Box::pin(GzipDecoder::new(source)),
            CodecAction::Decode(ContentCoding::Brotli) => Box::pin(BrotliDecoder::new(source)),
        };
        StreamingCodecBody {
            reader,
            trailers,
            chunk_bytes: policy.chunk_bytes,
            finished: false,
        }
        .boxed()
    })
}

/// 把 Hyper frame body 暴露为 codec 可直接借用的 `AsyncBufRead`。
///
/// `current` 持有一个引用计数 `Bytes`，`consume` 只移动 view 起点，不复制 payload。
/// codec 通过 `poll_fill_buf` 借用该 slice；只有通用 `AsyncRead` 兼容入口会 copy，
/// async-compression 的 bufread codec 不走那个入口。
struct BodyBufReader {
    /// 原始响应 body。
    inner: Pin<Box<BoxBody>>,
    /// 当前尚未被 codec 消费完的上游 data frame。
    current: Option<Bytes>,
    /// codec EOF 后再交给 Hyper 的 trailer 槽。
    trailers: Arc<Mutex<Option<HeaderMap>>>,
    /// 单次 codec poll 最多消费的输入字节，防高压缩比大 frame 长时间占用 Tokio worker。
    input_budget_bytes: usize,
    /// 自上次协作让出执行权后已消费的输入字节。
    consumed_since_yield: usize,
    /// 到达输入预算后，让下一次 fill_buf 先返回一次 Pending。
    yield_pending: bool,
    /// 内层 body 已结束。
    done: bool,
}

impl BodyBufReader {
    /// 建立一个零聚合的 Body→AsyncBufRead 适配器。
    ///
    /// # 参数
    /// - `body`: 原始 BoxBody，后续逐帧 poll。
    /// - `trailers`: 与输出 body 共享的 trailer 槽。
    /// - `input_budget_bytes`: 一轮同步 codec 工作最多消费的输入量。
    fn new(
        body: BoxBody,
        trailers: Arc<Mutex<Option<HeaderMap>>>,
        input_budget_bytes: usize,
    ) -> Self {
        Self {
            inner: Box::pin(body),
            current: None,
            trailers,
            input_budget_bytes,
            consumed_since_yield: 0,
            yield_pending: false,
            done: false,
        }
    }

    /// 保存 trailers；多个 trailer frame 合并进同一 HeaderMap 后只向下游发送一次。
    ///
    /// # 参数
    /// - `incoming`: 从原始 body 取得的 trailer header。
    fn store_trailers(&self, incoming: HeaderMap) {
        let mut slot = self
            .trailers
            .lock()
            .expect("compression trailer mutex poisoned");
        match slot.as_mut() {
            Some(existing) => existing.extend(incoming),
            None => *slot = Some(incoming),
        }
    }
}

impl AsyncBufRead for BodyBufReader {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.yield_pending {
            // async-compression 会在一次 poll 内循环读取，直到填满输出；高压缩比输入可能
            // 因此一次吞掉超大上游 frame。主动返回一次 Pending 把 CPU 时间还给 Tokio，
            // 同时 wake 自己继续，不引入 timer、任务或 payload copy。
            this.yield_pending = false;
            this.consumed_since_yield = 0;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        loop {
            if this.current.as_ref().is_some_and(|data| !data.is_empty()) {
                let remaining_budget = this
                    .input_budget_bytes
                    .saturating_sub(this.consumed_since_yield)
                    .max(1);
                let data = this.current.as_deref().unwrap_or_default();
                return Poll::Ready(Ok(&data[..data.len().min(remaining_budget)]));
            }
            this.current = None;
            if this.done {
                return Poll::Ready(Ok(&[]));
            }
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => this.current = Some(data),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            this.store_trailers(trailers);
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Ready(None) => this.done = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        if let Some(data) = this.current.as_mut() {
            // codec 必须只消费 `poll_fill_buf` 暴露的范围；min 是防御第三方实现违约，
            // 也避免 Bytes::advance 因错误 amount panic 影响整个连接任务。
            let consumed = amount.min(data.len());
            data.advance(consumed);
            this.consumed_since_yield = this.consumed_since_yield.saturating_add(consumed);
            if this.consumed_since_yield >= this.input_budget_bytes {
                this.yield_pending = true;
            }
        }
    }
}

impl AsyncRead for BodyBufReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = ready!(self.as_mut().poll_fill_buf(cx))?;
        let copied = available.len().min(output.remaining());
        output.put_slice(&available[..copied]);
        self.consume(copied);
        Poll::Ready(Ok(()))
    }
}

/// 将 codec 的 `AsyncRead` 输出重新暴露为 Hyper Body。
///
/// 每次 poll 最多分配 `chunk_bytes` 的最终输出所有权；frame 交给 Hyper 后不能复用
/// 这块内存，因此这次分配是内容变换路径的必要成本。没有额外 pending 队列，Hyper
/// 不继续 poll 时 codec 和上游 body 都自然停止，保留端到端背压。
struct StreamingCodecBody {
    /// gzip/br encoder 或 decoder。
    reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
    /// 输入侧捕获的 trailer。
    trailers: Arc<Mutex<Option<HeaderMap>>>,
    /// 单个输出 frame 上限。
    chunk_bytes: usize,
    /// codec EOF 及可选 trailer 都已经交付。
    finished: bool,
}

impl Body for StreamingCodecBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        let mut output = BytesMut::with_capacity(self.chunk_bytes);
        let read = {
            // ReadBuf 可以安全写进 BytesMut 未初始化的 spare capacity，避免每个压缩块
            // 先无意义清零。下面只把 ReadBuf 明确标记 filled 的前缀设为已初始化长度。
            let spare = output.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(spare);
            match self.reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => read_buf.filled().len(),
                Poll::Ready(Err(error)) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                Poll::Pending => return Poll::Pending,
            }
        };
        if read > 0 {
            // SAFETY: `read` 来自 ReadBuf::filled，仅覆盖 codec 已初始化的 spare 前缀，且
            // 不超过创建 BytesMut 时的 capacity；因此 set_len 后所有可见字节都已初始化。
            unsafe { output.set_len(read) };
            return Poll::Ready(Some(Ok(Frame::data(output.freeze()))));
        }

        self.finished = true;
        let trailers = self
            .trailers
            .lock()
            .expect("compression trailer mutex poisoned")
            .take();
        Poll::Ready(trailers.map(|trailers| Ok(Frame::trailers(trailers))))
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        // 编码后长度无法由输入精确推导；返回 unknown 防 Hyper 生成错误 Content-Length。
        SizeHint::default()
    }
}

#[path = "../../tests/unit/compression.rs"]
#[cfg(test)]
mod tests;
