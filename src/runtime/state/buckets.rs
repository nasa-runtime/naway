//! 桶状态读取不补充令牌，不推进预热，也不通过清理改变后续请求的准入事实。

use super::LocalRateLimiter;
use crate::runtime::sentinel::buckets::{Counts, Observation, SCAN_LIMIT};
use std::time::Instant;

impl LocalRateLimiter {
    /// 业务作用：有界观察当前本机保留桶，锁忙或容量超限时不阻塞业务或提交部分计数。
    ///
    /// 参数说明：
    /// - now：本轮单调观察时刻，整张表使用同一时间判定冷却与过期。
    ///
    /// 返回：完整互斥分类或有限不可用原因；不读取客户维度内容，不改变桶状态。
    pub(super) fn observe_buckets(&self, now: Instant) -> Observation {
        let Some(buckets) = self.buckets.try_lock() else {
            return Observation::Busy;
        };
        // HashMap 遍历成本取决于槽容量，稀疏表也不能绕过管理查询的工作预算。
        if buckets.len() > SCAN_LIMIT || buckets.capacity() > SCAN_LIMIT {
            return Observation::Capacity;
        }
        let mut counts = Counts {
            total: buckets.len(),
            ..Counts::default()
        };
        for bucket in buckets.values() {
            let idle = now.saturating_duration_since(bucket.last_refill);
            if idle > bucket.idle_ttl {
                counts.expired += 1;
            } else if let Some(plan) = bucket.warmup {
                if idle >= plan.cold_after {
                    counts.cold += 1;
                } else if now.saturating_duration_since(bucket.warmup_started) < plan.period {
                    counts.warming += 1;
                } else {
                    counts.warm += 1;
                }
            } else {
                counts.steady += 1;
            }
        }
        Observation::Local(counts)
    }
}
