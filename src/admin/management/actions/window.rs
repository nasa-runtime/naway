//! 签名绝对期限与首次接收的单调期限同时生效，时钟异常不延长写入权。

use crate::control::actions::command::Delivery;
use anyhow::{ensure, Context, Result};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_SPAN_MS: u64 = 20_000;
const CLOCK_MARGIN_MS: u64 = 1_000;

pub(super) struct Window {
    received_at: Instant,
    received_wall_ms: u64,
    deadline: Instant,
    absolute_deadline_ms: u64,
}

impl Window {
    /// 业务作用：首次接收已验签投递时冻结唯一短期窗口，相同投递重试必须复用这个窗口。
    ///
    /// 参数说明：
    /// - `delivery`：已绑定发行者和会话的完整签名期限。
    ///
    /// 返回：同时受墙钟和单调时钟限制的窗口；异常系统时间、过长跨度或余量不足拒绝。
    pub(super) fn admit(delivery: &Delivery) -> Result<Self> {
        Self::at(delivery, unix_millis()?, Instant::now())
    }

    /// 业务作用：将一次实际时钟采样转换为不能续期的执行截止，保守扣除发行者与节点时钟误差。
    ///
    /// 参数说明：
    /// - `delivery`：原签名中的绝对签发与到期时刻。
    /// - `wall_ms`：同一次接收的 Unix 毫秒。
    /// - `now`：紧邻墙钟采样的单调时刻。
    ///
    /// 返回：余量充足时建立窗口；时钟偏差或期限算术异常拒绝，不生成宽松默认值。
    fn at(delivery: &Delivery, wall_ms: u64, now: Instant) -> Result<Self> {
        let span = delivery
            .expires_at_ms
            .checked_sub(delivery.issued_at_ms)
            .context("node action time range is reversed")?;
        let end = delivery
            .expires_at_ms
            .checked_sub(CLOCK_MARGIN_MS)
            .context("node action has no clock margin")?;
        ensure!(
            delivery.issued_at_ms > 0
                && (1..=MAX_SPAN_MS).contains(&span)
                && delivery.expires_at_ms <= i64::MAX as u64
                && wall_ms > 0
                && wall_ms < end
                && delivery.issued_at_ms.saturating_sub(wall_ms) <= CLOCK_MARGIN_MS,
            "node action time authority is unavailable"
        );
        let deadline = now
            .checked_add(Duration::from_millis(end - wall_ms))
            .context("node action monotonic deadline is unavailable")?;
        Ok(Self {
            received_at: now,
            received_wall_ms: wall_ms,
            deadline,
            absolute_deadline_ms: end,
        })
    }

    /// 业务作用：在每次新的业务决定前复验剩余窗口，墙钟回退、跳变或等待不能恢复已过期资格。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：两个截止和时钟连续性都成立时成功；失败只关闭新的决定，不撤销已持久文件方向。
    pub(super) fn check(&self) -> Result<()> {
        self.check_at(unix_millis()?, Instant::now())
    }

    /// 业务作用：检查当前墙钟与单调流逝是否仍证明原窗口有效，允许误差不会累积到后续受理。
    ///
    /// 参数说明：
    /// - `wall_ms`：本次副作用门采样的 Unix 毫秒。
    /// - `now`：同次单调时刻。
    ///
    /// 返回：原期限内且相对时钟偏移不超过容差时成功，否则拒绝。
    fn check_at(&self, wall_ms: u64, now: Instant) -> Result<()> {
        let elapsed = now
            .checked_duration_since(self.received_at)
            .context("node action monotonic clock moved backward")?;
        let expected = self
            .received_wall_ms
            .saturating_add(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
        ensure!(
            now < self.deadline
                && wall_ms < self.absolute_deadline_ms
                && wall_ms.abs_diff(expected) <= CLOCK_MARGIN_MS,
            "node action deadline or clock continuity expired"
        );
        Ok(())
    }
}

/// 业务作用：取得可比较的绝对时刻，系统时间不可用时关闭当前命令而不是借零值续期。
///
/// 参数说明: 无。
///
/// 返回：可表达的正 Unix 毫秒，epoch 之前或溢出拒绝。
fn unix_millis() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
