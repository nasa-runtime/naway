//! 在最终 HTTP body 交付边界复验权限，已经缓冲的结果也不能绕过撤权。

use crate::{BoxBody, BoxError};
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

/// 业务作用：把最终实体与当前配置、请求预算和关闭状态绑定，包含已经完整缓冲的响应。
///
/// 参数说明：
/// - `response`：是裁决后的响应
/// - `live`：持有该响应全生命周期的权限所有者。
///
/// 返回：逐次交付前后均复验权限的实体；失权时丢弃内容并关闭响应。
pub(crate) fn guard(
    response: Response<BoxBody>,
    live: impl Fn() -> bool + Send + Sync + Unpin + 'static,
) -> Response<BoxBody> {
    response.map(|body| {
        Delivery {
            body,
            live,
            stopped: false,
        }
        .boxed()
    })
}

struct Delivery<F> {
    body: BoxBody,
    live: F,
    stopped: bool,
}
impl<F: Fn() -> bool + Send + Sync + Unpin> Body for Delivery<F> {
    type Data = Bytes;
    type Error = BoxError;
    /// 业务作用：避免在正文已就绪和实际发送之间的配置换代窗口交付旧权限结果。
    ///
    /// 参数说明：
    /// - `cx`：是下游轮询上下文。
    ///
    /// 返回：当前授权仍有效时交付原始帧，否则只返回一次低敏关闭错误。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.stopped {
            return Poll::Ready(None);
        }
        let frame = if (self.live)() {
            Pin::new(&mut self.body).poll_frame(cx)
        } else {
            Poll::Pending
        };
        if !(self.live)() {
            self.stopped = true;
            self.body = crate::full_body(Bytes::new());
            return Poll::Ready(Some(Err(
                anyhow::anyhow!("AI delivery authority expired").into()
            )));
        }
        frame
    }
}
