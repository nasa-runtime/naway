//! 三种指标出口共用当前限流器的只读事实，不保存后端或客户维度的历史。

use super::Metrics;
use crate::runtime::{sentinel::buckets::Observation, state::RateLimiter};
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::Arc;

pub(crate) static DESCRIPTORS: [MetricDescriptor; 2] = [
    MetricDescriptor {
        name: "gw_rate_bucket_observation",
        help: "Current rate limiter bucket observation status, one active status per node.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &["status"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_rate_local_buckets",
        help: "Current local backend retained bucket instances, without customer dimensions.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &["state"],
        histogram_bounds: &[],
    },
];

impl Metrics {
    /// 业务作用：启动时绑定唯一主限流器的弱引用，指标出口不能延长业务后端生命周期。
    ///
    /// 参数说明：
    /// - limiter：数据面实际使用的可热替换限流器。
    ///
    /// 返回：首次绑定成功；重复绑定拒绝，避免监控在两个不明 owner 之间切换。
    pub fn bind_rate_limiter(&self, limiter: &Arc<dyn RateLimiter>) -> anyhow::Result<()> {
        self.rate_limiter
            .set(Arc::downgrade(limiter))
            .map_err(|_| anyhow::anyhow!("metrics rate limiter already bound"))
    }

    /// 业务作用：在采样期间短暂持有当前限流 owner，结束后立即归还引用且不缓存旧值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界原生摘要；没有绑定或 owner 已退出时明确不可用。
    fn bucket_observation(&self) -> Observation {
        self.rate_limiter
            .get()
            .and_then(std::sync::Weak::upgrade)
            .map_or(Observation::Unavailable, |limiter| {
                limiter.bucket_observation()
            })
    }
}

/// 业务作用：将一次完整观察映射为固定状态系列，未知时不输出可能被误读为零的桶数。
///
/// 参数说明：
/// - metrics：已绑定唯一限流器的数据面指标 owner。
///
/// 返回：七个状态位及可选的六个本地计数，不触发 Redis 操作或记录客户身份。
pub(crate) fn samples(metrics: &Metrics) -> Vec<MetricSample> {
    let observation = metrics.bucket_observation();
    let active = match observation {
        Observation::Local(_) => "local",
        Observation::Shared => "shared",
        Observation::Preallocated => "preallocated",
        Observation::Unsupported => "unsupported",
        Observation::Busy => "busy",
        Observation::Capacity => "capacity",
        Observation::Unavailable => "unavailable",
    };
    let mut samples = Vec::with_capacity(13);
    for status in [
        "local",
        "shared",
        "preallocated",
        "unsupported",
        "busy",
        "capacity",
        "unavailable",
    ] {
        samples.push(MetricSample {
            name: DESCRIPTORS[0].name,
            labels: vec![("status", status.into())],
            value: MetricValue::Gauge(f64::from(status == active)),
        });
    }
    if let Observation::Local(counts) = observation {
        for (state, value) in [
            ("total", counts.total),
            ("steady", counts.steady),
            ("cold", counts.cold),
            ("warming", counts.warming),
            ("warm", counts.warm),
            ("expired", counts.expired),
        ] {
            samples.push(MetricSample {
                name: DESCRIPTORS[1].name,
                labels: vec![("state", state.into())],
                value: MetricValue::Gauge(value as f64),
            });
        }
    }
    samples
}
