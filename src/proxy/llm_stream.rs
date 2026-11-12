//! 模型响应的累计字节、可选 SSE 事件边界与绝对截止约束。

use crate::{BoxBody, BoxError};
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::future::Future;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::{Instant, Sleep};

/// 业务作用：在模型 SSE 解码或交付前限制资源消耗，同时保留原字节、扩展字段与背压。
///
/// 参数说明：
/// - `response`：提供商原始 SSE 或协议转换后的 SSE 响应。
/// - `max_response_bytes`：当前阶段允许通过的累计 DATA 字节上限。
/// - `max_event_bytes`：包含分隔符的单个 SSE 事件字节上限；首事件包含可选 UTF-8 BOM。
/// - `deadline`：从本次模型调用开始计算的绝对截止，不因收到响应头或协议转换而延后。
///
/// 返回：预算内原样传递 DATA 与 trailers；越界或到期时终止流并释放上游，已交付前缀不会回收。
pub(super) fn wrap_response(
    response: Response<BoxBody>,
    max_response_bytes: usize,
    max_event_bytes: usize,
    deadline: Instant,
) -> Response<BoxBody> {
    wrap_budget(
        response,
        max_response_bytes,
        Some(max_event_bytes),
        deadline,
    )
}

/// 业务作用：约束提供商不透明响应实体的大小与等待时间，保留其状态、媒体类型和原始字节。
///
/// 参数说明：
/// - `response`：已建立响应头、不能按统一成功协议解析的提供商响应。
/// - `max_response_bytes`：允许交付的累计 DATA 字节上限。
/// - `deadline`：本次提供商调用开始时冻结的绝对截止。
///
/// 返回：预算内透明交付正文及 trailers；超额或到期终止正文并释放上游，不重新生成响应头。
pub(super) fn wrap_opaque_response(
    response: Response<BoxBody>,
    max_response_bytes: usize,
    deadline: Instant,
) -> Response<BoxBody> {
    wrap_budget(response, max_response_bytes, None, deadline)
}

/// 业务作用：为模型响应建立统一资源状态，使事件解析只在明确的 SSE 路径生效。
///
/// 参数说明：
/// - `response`：需要附加流式资源门的提供商响应。
/// - `max_response_bytes`：累计 DATA 字节上限。
/// - `max_event_bytes`：SSE 事件硬门；None 表示不透明实体，不检查事件边界。
/// - `deadline`：跨响应阶段不延后的调用截止。
///
/// 返回：持有同一累计额度与绝对截止的响应，任一预算耗尽后只报告一次正文错误。
fn wrap_budget(
    response: Response<BoxBody>,
    max_response_bytes: usize,
    max_event_bytes: Option<usize>,
    deadline: Instant,
) -> Response<BoxBody> {
    response.map(|inner| {
        BudgetBody {
            inner: Some(inner),
            remaining: max_response_bytes,
            max_event_bytes,
            event_bytes: 0,
            line_has_content: false,
            previous_cr: false,
            completed_event_bytes: None,
            bom_prefix_bytes: 0,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
        }
        .boxed()
    })
}

struct BudgetBody {
    inner: Option<BoxBody>,
    remaining: usize,
    max_event_bytes: Option<usize>,
    event_bytes: usize,
    line_has_content: bool,
    previous_cr: bool,
    completed_event_bytes: Option<usize>,
    bom_prefix_bytes: usize,
    deadline: Pin<Box<Sleep>>,
}

impl BudgetBody {
    /// 业务作用：统一限制累计响应字节，并只为 SSE 跨数据块识别 CR、LF、CRLF 事件边界。
    ///
    /// 参数说明：
    /// - `data`：本次尚未交付的 DATA；不透明实体只累计长度，SSE 仅扫描换行，不复制业务内容。
    ///
    /// 返回：完整数据块在预算内时扣减累计额度，并按协议维护事件位置；否则保持原计数并拒绝交付。
    fn accept(&mut self, data: &[u8]) -> bool {
        // 当前块必须完整落在剩余额度内；不能先交付一部分，再依赖后续轮询发现累计越界。
        if data.len() > self.remaining {
            return false;
        }
        // 错误协议可能是 JSON、文本或二进制，不能把其中的换行解释为 SSE 事件或改写内容。
        let Some(max_event_bytes) = self.max_event_bytes else {
            self.remaining -= data.len();
            return true;
        };
        let mut event_bytes = self.event_bytes;
        let mut line_has_content = self.line_has_content;
        let mut previous_cr = self.previous_cr;
        let mut completed_event_bytes = self.completed_event_bytes;
        let mut bom_prefix_bytes = self.bom_prefix_bytes;
        for byte in data {
            if previous_cr && *byte == b'\n' {
                // CRLF 是一次换行；跨块 LF 仍计入它实际结束的事件，不能借重置获得额外一个字节。
                if let Some(completed) = completed_event_bytes {
                    if completed == max_event_bytes {
                        return false;
                    }
                } else {
                    if event_bytes == max_event_bytes {
                        return false;
                    }
                    event_bytes += 1;
                }
                previous_cr = false;
                completed_event_bytes = None;
                continue;
            }
            previous_cr = false;
            completed_event_bytes = None;
            // 只有完整分隔符能重置事件预算，提供商拆分 HTTP 数据块不能获得额外事件额度。
            if event_bytes == max_event_bytes {
                return false;
            }
            event_bytes += 1;
            if bom_prefix_bytes < 3 {
                // 流首 BOM 不属于行内容，不能让其后的合法空行与下一个事件合并；原字节仍计入额度。
                if *byte == [0xef, 0xbb, 0xbf][bom_prefix_bytes] {
                    bom_prefix_bytes += 1;
                    continue;
                }
                line_has_content |= bom_prefix_bytes > 0;
                bom_prefix_bytes = 3;
            }
            if matches!(*byte, b'\r' | b'\n') {
                if !line_has_content {
                    if *byte == b'\r' {
                        completed_event_bytes = Some(event_bytes);
                    }
                    event_bytes = 0;
                }
                line_has_content = false;
                previous_cr = *byte == b'\r';
            } else {
                line_has_content = true;
            }
        }
        self.remaining -= data.len();
        self.event_bytes = event_bytes;
        self.line_has_content = line_has_content;
        self.previous_cr = previous_cr;
        self.completed_event_bytes = completed_event_bytes;
        self.bom_prefix_bytes = bom_prefix_bytes;
        true
    }

    /// 业务作用：释放未完成的提供商响应并只向下游报告一次资源门终止，禁止继续读取或交付。
    ///
    /// 参数说明：
    /// - `kind`：区分持续时间耗尽与字节边界拒绝。
    /// - `reason`：不包含提供商内容的固定终止原因。
    ///
    /// 返回：一次流错误；后续轮询直接结束，原始上游状态立即释放。
    fn stop(
        &mut self,
        kind: ErrorKind,
        reason: &'static str,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.inner = None;
        Poll::Ready(Some(Err(Box::new(Error::new(kind, reason)))))
    }
}

impl Body for BudgetBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：在上游读取和下游交付之间执行同一绝对期限与字节门，不改变合法帧的内容及顺序。
    ///
    /// 参数说明：
    /// - `cx`：下游背压驱动的轮询上下文。
    ///
    /// 返回：预算内原帧、暂时等待或一次终止错误；拒绝之后不再轮询上游。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.inner.is_none() {
            return Poll::Ready(None);
        }
        // 即使上游此时已有数据就绪，过期调用也不再拥有继续消耗或交付模型输出的资源预算。
        if self.deadline.as_mut().poll(cx).is_ready() {
            return self.stop(ErrorKind::TimedOut, "LLM stream deadline exceeded");
        }
        let frame = Pin::new(self.inner.as_mut().expect("active LLM stream body")).poll_frame(cx);
        match frame {
            Poll::Ready(Some(Ok(frame))) => {
                // 在交付当前数据块前整体复验预算；已交付的合法前缀不能成为继续发送超额事件的理由。
                if frame.data_ref().is_some_and(|data| !self.accept(data)) {
                    return self.stop(ErrorKind::InvalidData, "LLM stream byte limit exceeded");
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.inner = None;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：让下游正确识别预算终止和上游正常结束，避免已经结束的流被继续调度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：资源门已结束或内层正文已结束时为 true。
    fn is_end_stream(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(|inner| inner.is_end_stream())
    }

    /// 业务作用：把提供商实体长度提示限制在尚可交付的累计额度内。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已结束时为零；否则返回不超过剩余额度的长度提示。
    fn size_hint(&self) -> SizeHint {
        let Some(inner) = self.inner.as_ref() else {
            return SizeHint::with_exact(0);
        };
        let inner = inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().min(self.remaining as u64));
        hint.set_upper(
            inner
                .upper()
                .unwrap_or(self.remaining as u64)
                .min(self.remaining as u64),
        );
        hint
    }
}
