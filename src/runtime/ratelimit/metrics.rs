//! 批领额度的固定低基数观测；不记录规则、工作区或请求维度。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static EVENTS: MetricDescriptor = MetricDescriptor {
    name: "gw_rate_preallocation_events_total",
    help: "Local preallocation outcomes and returned tokens.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["outcome"],
    histogram_bounds: &[],
};
pub(crate) static STATE: MetricDescriptor = MetricDescriptor {
    name: "gw_rate_preallocation_state",
    help: "Retained preallocation resources including retired backends.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &["resource"],
    histogram_bounds: &[],
};
pub(super) static GRANTS: AtomicU64 = AtomicU64::new(0);
pub(super) static HITS: AtomicU64 = AtomicU64::new(0);
pub(super) static DENIED: AtomicU64 = AtomicU64::new(0);
pub(super) static RETURNED: AtomicU64 = AtomicU64::new(0);
pub(super) static ERRORS: AtomicU64 = AtomicU64::new(0);
pub(super) static EXPIRED: AtomicU64 = AtomicU64::new(0);
pub(super) static ENTRIES: AtomicU64 = AtomicU64::new(0);
pub(super) static BACKENDS: AtomicU64 = AtomicU64::new(0);

/// 业务作用：为 Prometheus 与 OTLP 输出同源批领事实，不生成请求维度标签。
///
/// 参数说明: 无。
///
/// 返回：六个事件和两个保留资源数；所有系列在进程生命周期内固定。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut values = Vec::with_capacity(8);
    for (outcome, counter) in [
        ("grant_calls", &GRANTS),
        ("local_hits", &HITS),
        ("denied", &DENIED),
        ("returned_tokens", &RETURNED),
        ("dependency_errors", &ERRORS),
        ("expired", &EXPIRED),
    ] {
        values.push(MetricSample {
            name: EVENTS.name,
            labels: vec![("outcome", outcome.into())],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    for (resource, counter) in [("backends", &BACKENDS), ("keys", &ENTRIES)] {
        values.push(MetricSample {
            name: STATE.name,
            labels: vec![("resource", resource.into())],
            value: MetricValue::Gauge(counter.load(Ordering::Relaxed) as f64),
        });
    }
    values
}

/// 业务作用：把固定描述符与原子样本写入既有指标响应。
///
/// 参数说明：
/// - `out`：统一 Prometheus 响应缓冲区。
///
/// 返回：追加批领系列，不访问 Redis 或泄露业务身份。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&EVENTS, &STATE], &samples(), out);
}
