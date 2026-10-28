//! 可信用量的硬事实门独立于账本可用性，不能被 fail-open 跳过。

use super::*;
use crate::runtime::traffic_limit::usage::Facts;

pub(super) struct Guard {
    inner: BoxBody,
    facts: Facts,
    ended: bool,
}

impl Guard {
    /// 业务作用：为流式 provider 传播同一份事实门，不缓冲或重复解析响应实体。
    ///
    /// 参数说明：
    /// - `inner`：包含真实 provider 解析与成本结算的响应体。
    /// - `facts`：当前准入冻结的可信用量状态。
    ///
    /// 返回：等待下游轮询的零实体复制包装。
    pub(super) fn new(inner: BoxBody, facts: Facts) -> Self {
        Self {
            inner,
            facts,
            ended: false,
        }
    }
}

impl Body for Guard {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：在 provider 推进事实后、帧交付前复验硬门，坏成本立即取消底层流。
    ///
    /// 参数说明：
    /// - `cx`：下游背压与取消上下文。
    ///
    /// 返回：原始帧或一次本地拒绝；资源和已知成本由原结算上下文释放。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let frame = Pin::new(&mut self.inner).poll_frame(cx);
        if self.facts.invalid() {
            self.ended = true;
            self.inner = full_body(Bytes::new());
            return Poll::Ready(Some(Err(Box::new(
                crate::runtime::traffic_limit::resources::Rejected,
            ))));
        }
        frame
    }

    /// 业务作用：保留尚未轮询完成的事实校验机会，避免空实体提前跳过坏证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已经拒绝，或底层结束且事实未失效时为真。
    fn is_end_stream(&self) -> bool {
        self.ended || (self.inner.is_end_stream() && !self.facts.invalid())
    }

    /// 业务作用：保持底层长度合同，事实门不改变成功响应的实体字节。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层原始长度提示。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
