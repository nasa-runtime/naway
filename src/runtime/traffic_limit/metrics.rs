//! 流量等待的固定基数资源与拒绝原因，所有遥测出口共享同一事实。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static EVENTS: MetricDescriptor = MetricDescriptor {
    name: "gw_traffic_wait_events_total",
    help: "Traffic shaping and delayed admission resource outcomes.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["outcome"],
    histogram_bounds: &[],
};
pub(crate) static STATE: MetricDescriptor = MetricDescriptor {
    name: "gw_traffic_wait_resources",
    help: "Retained traffic waiters and logical entity bytes.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &["resource"],
    histogram_bounds: &[],
};
pub(crate) static CAPACITY: AtomicU64 = AtomicU64::new(0);
pub(crate) static DEADLINE: AtomicU64 = AtomicU64::new(0);
pub(crate) static STATE_OPEN: AtomicU64 = AtomicU64::new(0);
pub(crate) static STATE_CLOSED: AtomicU64 = AtomicU64::new(0);
pub(crate) static UNKNOWN_BODY: AtomicU64 = AtomicU64::new(0);
pub(super) static WAITERS: AtomicU64 = AtomicU64::new(0);
pub(super) static RETAINED_BYTES: AtomicU64 = AtomicU64::new(0);

/// 业务作用：为 Prometheus、OTLP 与管理读面输出同源的等待占用和失败事实。
///
/// 参数说明: 无。
///
/// 返回：固定五类事件和两个资源样本，不随路由、工作区或请求维度增长。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut samples = Vec::with_capacity(7);
    for (outcome, counter) in [
        ("capacity_denied", &CAPACITY),
        ("wait_deadline", &DEADLINE),
        ("state_fail_open", &STATE_OPEN),
        ("state_fail_closed", &STATE_CLOSED),
        ("unknown_body", &UNKNOWN_BODY),
    ] {
        samples.push(MetricSample {
            name: EVENTS.name,
            labels: vec![("outcome", outcome.into())],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    for (resource, counter) in [("waiters", &WAITERS), ("retained_bytes", &RETAINED_BYTES)] {
        samples.push(MetricSample {
            name: STATE.name,
            labels: vec![("resource", resource.into())],
            value: MetricValue::Gauge(counter.load(Ordering::Relaxed) as f64),
        });
    }
    samples
}

/// 业务作用：以共用描述符与样本生成文本指标，避免文本和结构化出口口径不同。
///
/// 参数说明：
/// - `out`：当前指标响应缓冲。
///
/// 返回：追加低基数样本，不执行网络或账本操作。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&EVENTS, &STATE], &samples(), out);
}
