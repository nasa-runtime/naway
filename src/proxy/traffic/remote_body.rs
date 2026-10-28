//! 共享调度的网络等待与发送等待都只持有当前帧，取消不撤销已发布的时间债务。

use super::*;
use crate::runtime::traffic_limit::{
    metrics,
    pacing::RequestPacing,
    redis::{bandwidth::Shaper, Failure},
    resources::{Rejected, Retained},
    QuotaFailMode,
};

pub(super) struct ShapedBody {
    inner: Pin<Box<BoxBody>>,
    shaper: Shaper,
    pending: Option<Frame<Bytes>>,
    wait: Option<
        parking_lot::Mutex<futures::future::BoxFuture<'static, Result<(), crate::BoxError>>>,
    >,
    retained: Option<Retained>,
    pacing: Option<RequestPacing>,
    ended: bool,
}

impl ShapedBody {
    /// 业务作用：为流式实体附加远端带宽调度，不预读或复制帧。
    ///
    /// 参数说明：
    /// - `inner`：原始实体。
    /// - `shaper`：冻结方向策略与共享连接。
    /// - `pacing`：仅请求方向提供的本地等待归因事实。
    ///
    /// 返回：尚未申请等待名额的流式包装体。
    pub(super) fn new(inner: BoxBody, shaper: Shaper, pacing: Option<RequestPacing>) -> Self {
        Self {
            inner: Box::pin(inner),
            shaper,
            pending: None,
            wait: None,
            retained: None,
            pacing,
            ended: false,
        }
    }

    /// 业务作用：资源、期限或账本错误后关闭底层流，不在失败后继续发送实体。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本地流控类型错误，供上游健康统计排除本地拒绝。
    fn reject(&mut self) -> Poll<Option<Result<Frame<Bytes>, crate::BoxError>>> {
        self.ended = true;
        self.pending = None;
        self.wait = None;
        self.retained = None;
        self.inner = Box::pin(full_body(Bytes::new()));
        Poll::Ready(Some(Err(Box::new(Rejected))))
    }
}

impl Body for ShapedBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：在整帧共享预留和发送期限通过后透传原始 Bytes，并保持 trailer 顺序。
    ///
    /// 参数说明：
    /// - `cx`：当前异步轮询上下文。
    ///
    /// 返回：共享时刻未到返回 Pending；任何硬资源门失败都终止实体，不受 fail-open 绕过。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        loop {
            if let Some(wait) = self.wait.as_mut() {
                match wait.get_mut().as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => return self.reject(),
                    Poll::Ready(Ok(())) => {
                        self.wait = None;
                        self.retained = None;
                        return Poll::Ready(self.pending.take().map(Ok));
                    }
                }
            }
            let frame = match self.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => frame,
                other => return other,
            };
            let bytes = frame.data_ref().map_or(0, |data| data.len() as u64);
            let free = bytes.min(self.shaper.after_remaining);
            self.shaper.after_remaining -= free;
            let charged = bytes - free;
            if charged == 0 {
                return Poll::Ready(Some(Ok(frame)));
            }
            // 先取得帧容量再发起远端副作用，避免无处保留实体却已推进共享时间债务。
            let Some(retained) = Retained::acquire(bytes) else {
                return self.reject();
            };
            if let Some(pacing) = &self.pacing {
                pacing.mark_wait();
            }
            let ledger = self.shaper.ledger.clone();
            let policy = self.shaper.policy.clone();
            let fail_mode = self.shaper.fail_mode;
            let deadline = tokio::time::Instant::now() + self.shaper.max_wait;
            self.wait = Some(parking_lot::Mutex::new(Box::pin(async move {
                let work = async {
                    match policy.reserve(&ledger, charged).await {
                        Ok(delay) => {
                            if tokio::time::Instant::now() + delay >= deadline {
                                return Err(Failure::Deadline);
                            }
                            tokio::time::sleep(delay).await;
                            Ok(())
                        }
                        Err(Failure::Unavailable | Failure::StateCapacity)
                            if fail_mode == QuotaFailMode::FailOpen =>
                        {
                            metrics::STATE_OPEN.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                };
                let result = tokio::time::timeout_at(deadline, work)
                    .await
                    .unwrap_or(Err(Failure::Deadline));
                if let Err(error) = result {
                    if error == Failure::Deadline {
                        metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
                    } else {
                        metrics::STATE_CLOSED.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(Box::new(Rejected) as crate::BoxError);
                }
                Ok(())
            })));
            self.retained = Some(retained);
            self.pending = Some(frame);
        }
    }

    /// 业务作用：避免底层已结束但远端仍等待的最后一帧被提前丢弃。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：拒绝终止或底层结束且没有保留帧时为 true。
    fn is_end_stream(&self) -> bool {
        self.ended || (self.inner.is_end_stream() && self.pending.is_none())
    }

    /// 业务作用：保持实体长度提示，并包含已从底层移入调度等待的字节。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚待交付实体的大小界限，不改变 HTTP framing。
    fn size_hint(&self) -> SizeHint {
        let original = self.inner.size_hint();
        let mut hint = SizeHint::new();
        let bytes = self
            .pending
            .as_ref()
            .and_then(Frame::data_ref)
            .map_or(0, |data| data.len() as u64);
        let upper = original.upper().and_then(|upper| upper.checked_add(bytes));
        hint.set_lower(original.lower().saturating_add(bytes));
        if let Some(upper) = upper {
            hint.set_upper(upper);
        }
        hint
    }
}
