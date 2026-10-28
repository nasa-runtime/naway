//! 正文帧只移动原始所有权，观察不预读、不聚合或改变错误。

use super::{Outcome, Tracker};
use crate::observability::metrics::Metrics;
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub(crate) struct Observed<B: Body> {
    inner: B,
    tracker: Tracker,
}

impl<B: Body> Drop for Observed<B> {
    /// 业务作用：消费方依据原正文结束提示跳过poll时，仍按已确认EOF结算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只补充已知EOF事实；未结束正文由唯一观察器记录提前丢弃。
    fn drop(&mut self) {
        if self.inner.is_end_stream() {
            self.tracker.finish(Outcome::Eof);
        }
    }
}

impl<B: Body> Observed<B> {
    /// 业务作用：在请求正文唯一消费边界安装观察，保留真实空正文的结束提示。
    ///
    /// 参数说明：
    /// - `body`：未经解码或治理聚合的原始下游正文。
    /// - `metrics`：当前进程的共享事实源。
    ///
    /// 返回：不读帧的包装，原正文仍控制背压和错误。
    pub(crate) fn request(body: B, metrics: Arc<Metrics>) -> Self {
        Self::new(body, Tracker::request(metrics))
    }

    /// 业务作用：把唯一终态权交给正文持有者，已知空体不要求额外poll才能结束。
    ///
    /// 参数说明：
    /// - `inner`：当前方向正文。
    /// - `tracker`：与该正文对应的唯一结算权。
    ///
    /// 返回：空体已结算，其余终态随帧消费或丢弃发生。
    pub(super) fn new(inner: B, mut tracker: Tracker) -> Self {
        if inner.is_end_stream() {
            tracker.finish(Outcome::Eof);
        }
        Self {
            inner,
            tracker,
        }
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for Observed<B> {
    type Data = Bytes;
    type Error = B::Error;

    /// 业务作用：在原帧交付时记录真实字节和终态，Pending不生成流量或结束事实。
    ///
    /// 参数说明：
    /// - `cx`：下游消费方提供的唤醒上下文。
    ///
    /// 返回：原始DATA/trailers/错误；结束后不再读取或重复结算。
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.tracker.finished {
            return Poll::Ready(None);
        }
        let result = Pin::new(&mut this.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.tracker.bytes(data.len());
                }
                // HTTP trailers结束实体，消费方也可依据结束提示跳过下一次poll；终止帧交付时同步结算。
                if frame.is_trailers() || this.inner.is_end_stream() {
                    this.tracker.finish(Outcome::Eof);
                }
            }
            Poll::Ready(Some(Err(_))) => this.tracker.finish(Outcome::BodyError),
            Poll::Ready(None) => this.tracker.finish(Outcome::Eof),
            Poll::Pending => {}
        }
        result
    }

    /// 业务作用：保留空体及消费结束提示，避免HTTP adapter无意义地继续读取。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已确认终态或原正文明确结束时为true，不以长度推算EOF。
    fn is_end_stream(&self) -> bool {
        self.tracker.finished || self.inner.is_end_stream()
    }

    /// 业务作用：透明传递原正文长度提示，保持既有协议分帧选择。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正文提示，不将该值计入字节事实。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
