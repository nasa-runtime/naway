//! 一次真实上游请求固定的负载观察权；反馈不通过可变请求头传递。

use super::{report, InstanceLoad, LoadFeedback, LoadFeedbackPolicy};
use http::HeaderMap;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct Observation {
    entry: Arc<InstanceLoad>,
    policy: LoadFeedbackPolicy,
    recorded: bool,
}

impl Observation {
    /// 业务作用：在选中真实实例时固定反馈对象，使迟到响应不能按地址重建已撤销的状态。
    ///
    /// 参数说明：
    /// - `entry`：共享目录授予的实例反馈句柄。
    /// - `policy`：本次请求冻结的负载策略。
    ///
    /// 返回：尚未记录的观察权；不复制业务载荷，不产生外部副作用。
    pub(crate) fn new(entry: Arc<InstanceLoad>, policy: LoadFeedbackPolicy) -> Self {
        Self {
            entry,
            policy,
            recorded: false,
        }
    }

    /// 业务作用：在真实响应头到达时采集首字节延迟或 ORCA，避免被下游传输耗时污染。
    ///
    /// 参数说明：
    /// - `headers`：上游原始响应头，在插件、浏览器协议转换或缓存之前读取。
    /// - `elapsed`：从真实发送开始至响应头到达的时长。
    ///
    /// 返回：记录一次有效反馈；非法或缺失利用率保留 trailer 采集机会。
    pub(crate) fn headers(&mut self, headers: &HeaderMap, elapsed: Duration) {
        if self.recorded {
            return;
        }
        match self.policy.feedback {
            LoadFeedback::LatencyEwma => {
                self.entry.record_latency(
                    elapsed.as_micros().min(u64::MAX as u128) as u64,
                    self.policy.smoothing_bp,
                );
                self.recorded = true;
            }
            LoadFeedback::Utilization => self.trailers(headers),
            LoadFeedback::None => {}
        }
    }

    /// 业务作用：从真实上游 trailers 采集尚未记录的利用率，不重复计入同一次请求。
    ///
    /// 参数说明：
    /// - `headers`：上游 trailer 元数据，保持原始内容供下游读取。
    ///
    /// 返回：仅合法报告推进数值和新鲜度；取消、错误、缺失和非法值不生成反馈。
    pub(crate) fn trailers(&mut self, headers: &HeaderMap) {
        if self.recorded || self.policy.feedback != LoadFeedback::Utilization {
            return;
        }
        if let Some(value) = report::from_headers(headers, &self.policy.orca_header) {
            self.entry
                .record_utilization(value, self.policy.smoothing_bp);
            self.recorded = true;
            super::metrics::ACCEPTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if headers.contains_key(report::BINARY_HEADER)
            || headers.contains_key(self.policy.orca_header.as_ref())
        {
            super::metrics::INVALID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// 业务作用：判定是否仍需观察 trailers，已记录的请求不向响应实体保留额外状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：利用率尚无有效样本时为 true，其余情况可立即释放观察权。
    pub(crate) fn needs_trailers(&self) -> bool {
        !self.recorded && self.policy.feedback == LoadFeedback::Utilization
    }
}
