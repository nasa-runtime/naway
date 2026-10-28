//! 被动窗口摘除的配置边界与固定空间统计。

pub use crate::config::model::OutlierCfg as Policy;
use anyhow::{ensure, Result};

impl Policy {
    /// 业务作用：在候选构建时限定统计与恢复预算，拒绝没有有效阈值或可能摘光实例的配置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：参数全部有界时成功；非法窗口、比例、样本数或时长拒绝整个配置候选。
    pub fn validate(&self) -> Result<()> {
        ensure!(
            cfg!(feature = "upstream-outlier"),
            "outlier requires feature `upstream-outlier`"
        );
        ensure!(
            (160..=300_000).contains(&self.window_ms),
            "outlier.window_ms must be within 160..=300000"
        );
        ensure!(
            (1..=1_000_000).contains(&self.min_samples),
            "outlier.min_samples must be within 1..=1000000"
        );
        ensure!(
            self.failure_percent <= 100
                && self.slow_percent <= 100
                && (self.failure_percent != 0 || self.slow_percent != 0),
            "outlier requires at least one nonzero percentage within 1..=100"
        );
        ensure!(
            (1..=99).contains(&self.max_ejection_percent),
            "outlier.max_ejection_percent must be within 1..=99"
        );
        ensure!(
            (1..=300_000).contains(&self.slow_ms),
            "outlier.slow_ms must be within 1..=300000"
        );
        ensure!(
            (1..=300_000).contains(&self.base_ejection_ms)
                && (self.base_ejection_ms..=300_000).contains(&self.max_ejection_ms),
            "outlier ejection durations must satisfy 1 <= base <= max <= 300000"
        );
        ensure!(
            (1..=60_000).contains(&self.probe_timeout_ms),
            "outlier.probe_timeout_ms must be within 1..=60000"
        );
        Ok(())
    }

    /// 业务作用：按实例目录规模计算摘除硬上限，小服务不会因向上取整被全部摘除。
    ///
    /// 参数说明：
    /// - `instances`：当前目录中可参与调度的不同实例数。
    ///
    /// 返回：向下取整后的最大同时摘除数；单实例服务为零。
    #[cfg(feature = "upstream-outlier")]
    pub(super) fn capacity(self, instances: usize) -> usize {
        instances.saturating_mul(self.max_ejection_percent as usize) / 100
    }
}

#[cfg(feature = "upstream-outlier")]
#[derive(Clone, Copy, Default)]
struct Bucket {
    tick: u64,
    total: u64,
    failed: u64,
    slow: u64,
}

#[cfg(feature = "upstream-outlier")]
#[derive(Default)]
pub(super) struct Window {
    buckets: [Bucket; 16],
}

#[cfg(feature = "upstream-outlier")]
impl Window {
    /// 业务作用：把一个已完成真实尝试计入固定时间桶，避免为每个请求保存事件或分配内存。
    ///
    /// 参数说明：
    /// - `policy`：定义窗口、最小样本和失败/慢调用阈值。
    /// - `now_ms`：进程内共享的单调毫秒时刻。
    /// - `failed`：是否存在真实上游失败证据。
    /// - `elapsed_ms`：尝试开始至结果可判定的耗时。
    ///
    /// 返回：窗口内样本充足且任一已启用比例达到阈值时为 true；不直接改变健康状态。
    pub(super) fn observe(
        &mut self,
        policy: Policy,
        now_ms: u64,
        failed: bool,
        elapsed_ms: u64,
    ) -> bool {
        let width = policy.window_ms.div_ceil(16);
        let tick = now_ms / width;
        let bucket = &mut self.buckets[(tick % 16) as usize];
        if bucket.tick != tick {
            *bucket = Bucket {
                tick,
                ..Bucket::default()
            };
        }
        bucket.total = bucket.total.saturating_add(1);
        bucket.failed = bucket.failed.saturating_add(u64::from(failed));
        bucket.slow = bucket
            .slow
            .saturating_add(u64::from(elapsed_ms >= policy.slow_ms));
        let mut total = 0_u128;
        let mut failed = 0_u128;
        let mut slow = 0_u128;
        for sample in &self.buckets {
            // 已到边界的整桶不再参与判断；窗口只保留固定十六桶，误差不超过一个桶宽。
            if tick.saturating_sub(sample.tick) < 16 {
                total += u128::from(sample.total);
                failed += u128::from(sample.failed);
                slow += u128::from(sample.slow);
            }
        }
        total >= u128::from(policy.min_samples)
            && ((policy.failure_percent != 0
                && failed * 100 >= total * u128::from(policy.failure_percent))
                || (policy.slow_percent != 0
                    && slow * 100 >= total * u128::from(policy.slow_percent)))
    }
}
