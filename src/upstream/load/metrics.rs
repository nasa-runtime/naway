//! 负载反馈的固定基数事件与订阅数量，不泄漏服务地址或报告内容。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static EVENTS: MetricDescriptor = MetricDescriptor {
    name: "gw_upstream_load_reports_total",
    help: "Backend feedback reports and subscription outcomes.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["outcome"],
    histogram_bounds: &[],
};
pub(crate) static ACTIVE: MetricDescriptor = MetricDescriptor {
    name: "gw_upstream_orca_subscriptions",
    help: "Retained out-of-band ORCA subscription tasks.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &[],
    histogram_bounds: &[],
};
pub(crate) static ACCEPTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static INVALID: AtomicU64 = AtomicU64::new(0);
pub(crate) static STALE: AtomicU64 = AtomicU64::new(0);
pub(crate) static CAPACITY: AtomicU64 = AtomicU64::new(0);
pub(crate) static RETRIES: AtomicU64 = AtomicU64::new(0);
pub(crate) static SUBSCRIPTIONS: AtomicU64 = AtomicU64::new(0);

/// 业务作用：从统一原子计数生成 Prometheus、OTLP 和管理面共用的低敏样本。
///
/// 参数说明: 无。
///
/// 返回：固定五类事件和一个订阅数量，不随实例或请求维度增长。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut samples = Vec::with_capacity(6);
    for (outcome, counter) in [
        ("accepted", &ACCEPTED),
        ("invalid", &INVALID),
        ("stale", &STALE),
        ("capacity_denied", &CAPACITY),
        ("reconnect", &RETRIES),
    ] {
        samples.push(MetricSample {
            name: EVENTS.name,
            labels: vec![("outcome", outcome.into())],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    samples.push(MetricSample {
        name: ACTIVE.name,
        labels: vec![],
        value: MetricValue::Gauge(SUBSCRIPTIONS.load(Ordering::Relaxed) as f64),
    });
    samples
}

/// 业务作用：用同一指标定义输出反馈事件，避免文本与遥测出口口径分叉。
///
/// 参数说明：
/// - `out`：当前指标响应缓冲。
///
/// 返回：追加固定样本，不访问注册中心或业务上游。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&EVENTS, &ACTIVE], &samples(), out);
}
