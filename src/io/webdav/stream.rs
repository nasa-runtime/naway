//! DAV 协议小实体的有界收集，以及完整响应期的并发与取消租约。

use crate::{BoxBody, BoxError};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

pub(super) struct Lease {
    pub _permit: super::admission::Permit,
    pub budget: nabudget::RequestBudget,
    pub authority: super::filesystem::Authority,
    pub filesystem: Option<super::filesystem::FileSystem>,
}
impl Drop for Lease {
    /// 业务作用：下游取消或处理失败时撤销本次文件系统权威，后台阻塞操作随后不能继续副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：置位取消事实；未提交文件随最后一个文件系统视图释放而撤下。
    fn drop(&mut self) {
        self.budget.cancel();
    }
}

/// 业务作用：只为 XML 等小型协议控制实体收集字节，不用于文件上传下载。
///
/// 参数说明：
/// - `body`：待收集的有界协议流。
/// - `limit`：请求 XML 或 multistatus 的字节硬上限。
///
/// 返回：完整且没有 trailers 的实体；超限、过多空帧或读取失败拒绝。
pub(super) async fn collect(mut body: BoxBody, limit: usize) -> Result<Bytes, BoxError> {
    let mut bytes = BytesMut::new();
    let mut empty = 0usize;
    while let Some(frame) = body.frame().await {
        let data = frame?
            .into_data()
            .map_err(|_| "WebDAV control trailers are unsupported")?;
        if data.is_empty() {
            empty += 1;
            if empty > 1024 {
                return Err("WebDAV empty-frame limit exceeded".into());
            }
            continue;
        }
        if data.len() > limit.saturating_sub(bytes.len()) {
            return Err("WebDAV control entity limit exceeded".into());
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes.freeze())
}

pub(super) struct GuardedBody {
    body: BoxBody,
    lease: Option<Lease>,
    deadline: Pin<Box<Sleep>>,
    done: bool,
}

struct EngineBody(parking_lot::Mutex<dav_server::body::Body>);
impl EngineBody {
    /// 业务作用：把单消费者 DAV 引擎流接入网关的 Sync body 契约，不创建额外后台任务。
    ///
    /// 参数说明：
    /// - `body`：标准引擎返回的 Send 实体流。
    ///
    /// 返回：仍按 poll 直接推进的流；正文不复制或聚合。
    fn wrap(body: dav_server::body::Body) -> BoxBody {
        Self(parking_lot::Mutex::new(body)).boxed()
    }
}

/// 业务作用：对外提供标准 DAV 引擎流的安全类型适配。
///
/// 参数说明：
/// - `body`：协议引擎响应实体。
///
/// 返回：网关公共流式 body，取消时直接销毁原引擎流。
pub(super) fn engine_body(body: dav_server::body::Body) -> BoxBody {
    EngineBody::wrap(body)
}

impl Body for EngineBody {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：仅通过独占可变借用推进引擎流，不在持锁期间等待异步任务。
    ///
    /// 参数说明：
    /// - `cx`：下游消费唤醒上下文。
    ///
    /// 返回：引擎原始帧、等待或错误；实体内存仍受其 16 KiB 读取配置约束。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(self.0.get_mut())
            .poll_frame(cx)
            .map(|frame| frame.map(|frame| frame.map_err(|error| Box::new(error) as BoxError)))
    }
    /// 业务作用：查询引擎是否已经确认流结束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层明确结束时为 true。
    fn is_end_stream(&self) -> bool {
        self.0.lock().is_end_stream()
    }
    /// 业务作用：保留标准 DAV 实体流的长度提示。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：引擎提供的可信长度范围。
    fn size_hint(&self) -> SizeHint {
        self.0.lock().size_hint()
    }
}
impl GuardedBody {
    /// 业务作用：把目录、路由并发和总 deadline 延续到响应正文结束。
    ///
    /// 参数说明：
    /// - `body`：已经通过响应控制面检查的实体流。
    /// - `lease`：本次请求持有的完整资源租约。
    /// - `deadline`：从请求准入开始计算的绝对截止时刻。
    ///
    /// 返回：取消即撤权、到期即终止的流式响应包装。
    pub fn wrap(body: BoxBody, lease: Lease, deadline: Instant) -> BoxBody {
        Self {
            body,
            lease: Some(lease),
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            done: false,
        }
        .boxed()
    }
}
impl Body for GuardedBody {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：推进有界响应并在终止、失败或期限到达时释放资源权威。
    ///
    /// 参数说明：
    /// - `cx`：当前消费任务唤醒上下文。
    ///
    /// 返回：下游一帧或终止；总 deadline 包含慢客户端等待时间。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        use std::future::Future;
        if self.done {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(cx).is_ready()
            || self.lease.as_ref().is_none_or(|lease| !(lease.authority)())
        {
            self.done = true;
            self.lease.take();
            return Poll::Ready(Some(Err("WebDAV response authority expired".into())));
        }
        let result = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.done = true;
            self.lease.take();
        }
        result
    }
    /// 业务作用：转达底层已确定的流结束，不延长空响应的资源占用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：终止或底层确认为空时为 true。
    fn is_end_stream(&self) -> bool {
        self.done || self.body.is_end_stream()
    }
    /// 业务作用：保留文件流可信长度供 HTTP framing 使用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层实体长度提示，不聚合正文计算长度。
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

pub(super) struct CheckedBody {
    body: BoxBody,
    authority: super::filesystem::Authority,
    deadline: Pin<Box<Sleep>>,
    remaining: u64,
    done: bool,
}
impl CheckedBody {
    /// 业务作用：使上传在每个实体帧前复验同一执行权威，不靠聚合文件证明长度。
    ///
    /// 参数说明：
    /// - `body`：原始流式上传。
    /// - `authority`：快照、来源期限与取消状态的联合复验。
    /// - `deadline`：包含慢客户端等待的请求期限。
    /// - `length`：唯一 Content-Length 声明的精确长度。
    ///
    /// 返回：不复制数据帧的包装；提前结束、超长、trailer 或撤权使上传失败。
    pub fn wrap(
        body: BoxBody,
        authority: super::filesystem::Authority,
        deadline: Instant,
        length: u64,
    ) -> BoxBody {
        Self {
            body,
            authority,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            remaining: length,
            done: false,
        }
        .boxed()
    }
}
impl Body for CheckedBody {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：扣减已声明的剩余上传字节，失权后停止向本地或代理后端交付新帧。
    ///
    /// 参数说明：
    /// - `cx`：上传发送者的唤醒上下文。
    ///
    /// 返回：一个原始帧或有界错误；短实体不能被当成完整文件。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        use std::future::Future;
        if self.done {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(cx).is_ready() || !(self.authority)() {
            self.done = true;
            return Poll::Ready(Some(Err("WebDAV upload authority expired".into())));
        }
        let result = Pin::new(&mut self.body).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                let length = frame.data_ref().map(|bytes| bytes.len() as u64);
                if length.is_none_or(|length| length > self.remaining) {
                    self.done = true;
                    return Poll::Ready(Some(Err("WebDAV upload entity length mismatch".into())));
                }
                self.remaining -= length.expect("data frame");
            }
            Poll::Ready(None) if self.remaining != 0 => {
                self.done = true;
                return Poll::Ready(Some(Err("WebDAV upload ended early".into())));
            }
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => self.done = true,
            _ => {}
        }
        result
    }
    /// 业务作用：仅在长度吻合且底层结束时允许 HTTP 发送者省略后续 poll。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已终止或精确完成时为 true。
    fn is_end_stream(&self) -> bool {
        self.done || (self.remaining == 0 && self.body.is_end_stream())
    }
    /// 业务作用：保持精确上传长度用于上游 framing。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未交付的已声明字节数。
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}
