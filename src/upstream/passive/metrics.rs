//! 窗口摘除的固定低基数事件和真实保留状态数量。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static EVENTS: MetricDescriptor = MetricDescriptor {
    name: "gw_upstream_outlier_events_total",
    help: "Passive outlier transitions by fixed outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["outcome"],
    histogram_bounds: &[],
};
pub(crate) static STATE: MetricDescriptor = MetricDescriptor {
    name: "gw_upstream_outlier_state",
    help: "Retained passive outlier state by resource kind.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &["resource"],
    histogram_bounds: &[],
};
pub(super) static EJECTED: AtomicU64 = AtomicU64::new(0);
pub(super) static CAPPED: AtomicU64 = AtomicU64::new(0);
pub(super) static PROBE: AtomicU64 = AtomicU64::new(0);
pub(super) static RECOVERED: AtomicU64 = AtomicU64::new(0);
pub(super) static FAILED: AtomicU64 = AtomicU64::new(0);
pub(super) static CANCELLED: AtomicU64 = AtomicU64::new(0);
pub(super) static STALE: AtomicU64 = AtomicU64::new(0);
pub(super) static DENIED: AtomicU64 = AtomicU64::new(0);
pub(super) static GROUPS: AtomicU64 = AtomicU64::new(0);
pub(super) static ENTRIES: AtomicU64 = AtomicU64::new(0);

/// 业务作用：从同一原子事实生成两个观测出口的样本，不引入实例名或请求维度标签。
///
/// 参数说明: 无。
///
/// 返回：八个事件计数与两个保留资源数量，指标基数不随服务和节点增加。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut samples = Vec::with_capacity(10);
    for (outcome, counter) in [
        ("ejected", &EJECTED),
        ("capped", &CAPPED),
        ("probe_started", &PROBE),
        ("recovered", &RECOVERED),
        ("probe_failed", &FAILED),
        ("probe_cancelled", &CANCELLED),
        ("stale", &STALE),
        ("capacity_denied", &DENIED),
    ] {
        samples.push(MetricSample {
            name: EVENTS.name,
            labels: vec![("outcome", outcome.into())],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    for (resource, counter) in [("groups", &GROUPS), ("instances", &ENTRIES)] {
        samples.push(MetricSample {
            name: STATE.name,
            labels: vec![("resource", resource.into())],
            value: MetricValue::Gauge(counter.load(Ordering::Relaxed) as f64),
        });
    }
    samples
}

/// 业务作用：按统一描述符渲染窗口摘除状态，保持 Prometheus 与 OTLP 口径一致。
///
/// 参数说明：
/// - `out`：当前指标文本缓冲区。
///
/// 返回：追加固定十个系列，不读取业务实体或远端状态。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&EVENTS, &STATE], &samples(), out);
}
