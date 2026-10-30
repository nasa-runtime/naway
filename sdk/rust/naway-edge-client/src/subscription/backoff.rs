//! 重连截止属于订阅状态，取消一次等待不能重置下一次拨号的最早时刻。

use crate::{EdgeError, Result};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Backoff {
    base: Duration,
    max: Duration,
    next: Duration,
    deadline: Option<Instant>,
}

impl Backoff {
    /// 业务作用：验证重连预算并建立没有待拨号任务的初始退避状态。
    ///
    /// 参数说明：
    /// - `base`：第一次断流后必须等待的时间。
    /// - `max`：连续无消息断流的最大间隔，不得超过24小时。
    ///
    /// 返回：合法区间成功；零值、反转或过大区间返回协议配置错误。
    pub(super) fn new(base: Duration, max: Duration) -> Result<Self> {
        if base.is_zero() || base > max || max > Duration::from_secs(86400) {
            return Err(EdgeError::Protocol(
                "reconnect must satisfy 0 < base <= max <= 24h".into(),
            ));
        }
        Ok(Self {
            base,
            max,
            next: base,
            deadline: None,
        })
    }

    /// 业务作用：在失去当前流后冻结下一次拨号截止，连续空流不能绕过指数退避。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：登记一次等待并饱和增长后续间隔；已有等待不被推迟或缩短。
    pub(super) fn arm(&mut self) {
        if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + self.next);
            self.next = self.next.saturating_mul(2).min(self.max);
        }
    }

    /// 业务作用：等待当前订阅的最早重连时刻，未来被取消时仍保留同一个截止。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：等待完成后清除截止；取消等待没有状态变化或新网络动作。
    pub(super) async fn wait(&mut self) {
        if let Some(deadline) = self.deadline {
            tokio::time::sleep_until(deadline).await;
            self.deadline = None;
        }
    }

    /// 业务作用：仅在已交付完整业务消息后恢复基础重连间隔。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：下一次断流从基础间隔开始，不以成功响应头替代业务进展。
    pub(super) fn delivered(&mut self) {
        self.next = self.base;
    }
}
