use anyhow::{ensure, Result};
use std::time::Duration;

/// 以首次需求为起点线性增加补充速率；空闲后重新收紧桶容量，不积累冷启动突发信用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Warmup {
    pub(crate) period: Duration,
    pub(crate) cold_factor: u16,
    pub(crate) cold_after: Duration,
}

impl Warmup {
    /// 业务作用：冻结预热曲线及冷却边界，阻止额外突发或过大的数值绕过冷启动保护。
    ///
    /// 参数说明：
    /// - `period_ms`：从冷态速率线性增长到稳定速率的毫秒数。
    /// - `cold_factor`：冷态速率相对于稳定速率的除数。
    /// - `cold_after_ms`：连续无请求达到该时长后再次冷启动。
    /// - `limit`：稳定补充窗口的额度。
    /// - `burst`：额外突发容量，预热规则必须为零。
    ///
    /// 返回：有效且有界的控制曲线；任何参数不合法时拒绝候选。
    pub(crate) fn build(
        period_ms: u64,
        cold_factor: u16,
        cold_after_ms: u64,
        limit: u64,
        burst: u64,
    ) -> Result<Self> {
        ensure!(
            (1..=600_000).contains(&period_ms),
            "warmup_ms must be within 1..600000"
        );
        ensure!(
            (2..=1000).contains(&cold_factor),
            "cold_factor must be within 2..1000"
        );
        ensure!(
            (1..=600_000).contains(&cold_after_ms),
            "cold_after_ms must be within 1..600000"
        );
        ensure!(
            limit > 0 && limit <= 1u64 << 32 && burst == 0,
            "warmup requires rate <= 2^32 and burst=0"
        );
        Ok(Self {
            period: Duration::from_millis(period_ms),
            cold_factor,
            cold_after: Duration::from_millis(cold_after_ms),
        })
    }

    /// 业务作用：计算当前容量与区间内真实可补充额度，不能按区间结束速率回填整个预热期。
    ///
    /// 参数说明：
    /// - `limit`：稳定窗口容量。
    /// - `window`：稳定补充周期。
    /// - `from`：上次补充相对预热起点的时间。
    /// - `to`：本次补充相对同一起点的时间。
    ///
    /// 返回：当前桶容量及本次补充量；跨过预热终点时只有后半段采用完整稳定速率。
    pub(crate) fn allowance(
        self,
        limit: u64,
        window: Duration,
        from: Duration,
        to: Duration,
    ) -> (f64, f64) {
        let period = self.period.as_secs_f64();
        let cold = 1.0 / f64::from(self.cold_factor);
        let start = from.as_secs_f64().min(period);
        let end = to.as_secs_f64().min(period).max(start);
        let ramp = (end - start) * (cold + (1.0 - cold) * (start + end) / (2.0 * period));
        let steady = to
            .saturating_sub(self.period)
            .saturating_sub(from.saturating_sub(self.period))
            .as_secs_f64();
        let fraction = cold + (1.0 - cold) * (to.as_secs_f64() / period).min(1.0);
        let capacity = (limit as f64 * fraction).max(1.0);
        (
            capacity,
            limit as f64 / window.as_secs_f64() * (ramp + steady),
        )
    }
}

impl std::fmt::Display for Warmup {
    /// 业务作用：将预热时序纳入规则身份，避免不同控制曲线共享已变热的桶。
    ///
    /// 参数说明：
    /// - `formatter`：写入状态身份的目标。
    ///
    /// 返回：包含全部时间与速率参数的稳定文本。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.period.as_millis(),
            self.cold_factor,
            self.cold_after.as_millis()
        )
    }
}
