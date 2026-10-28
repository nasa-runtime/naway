//! 管理端低基数事实；指标不携带节点、资源名、身份摘要或错误原文。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static EVENTS: MetricDescriptor = MetricDescriptor {
    name: "gw_xds_server_events_total",
    help: "ADS management events by fixed outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["outcome"],
    histogram_bounds: &[],
};
pub(crate) static ACTIVE: MetricDescriptor = MetricDescriptor {
    name: "gw_xds_server_streams",
    help: "ADS response streams retaining admission capacity.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &[],
    histogram_bounds: &[],
};

pub(crate) static STREAMS: AtomicU64 = AtomicU64::new(0);
pub(crate) static ACK: AtomicU64 = AtomicU64::new(0);
pub(crate) static NACK: AtomicU64 = AtomicU64::new(0);
pub(crate) static STALE_NONCE: AtomicU64 = AtomicU64::new(0);
pub(crate) static SLOW: AtomicU64 = AtomicU64::new(0);
pub(crate) static DENIED: AtomicU64 = AtomicU64::new(0);
pub(crate) static HEARTBEAT: AtomicU64 = AtomicU64::new(0);
pub(crate) static SECRET_SENDS: AtomicU64 = AtomicU64::new(0);

/// 业务作用：从固定原子事实生成管理端状态，不记录客户端提供的错误文本或资源内容。
///
/// 参数说明: 无。
///
/// 返回：固定八项计数，调用方可与当前已发布投影摘要合并展示。
pub(crate) fn status() -> serde_json::Value {
    serde_json::json!({
        "streams": STREAMS.load(Ordering::Relaxed),
        "ack": ACK.load(Ordering::Relaxed),
        "nack": NACK.load(Ordering::Relaxed),
        "stale_nonce": STALE_NONCE.load(Ordering::Relaxed),
        "slow_streams": SLOW.load(Ordering::Relaxed),
        "denied": DENIED.load(Ordering::Relaxed),
        "heartbeats": HEARTBEAT.load(Ordering::Relaxed),
        "secret_sends": SECRET_SENDS.load(Ordering::Relaxed),
    })
}

/// 业务作用：向 Prometheus 和 OTLP 提供相同的固定基数管理端事实。
///
/// 参数说明: 无。
///
/// 返回：七项事件计数与一项真实保留流数量，不包含外部输入标签。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut samples = vec![MetricSample {
        name: ACTIVE.name,
        labels: Vec::new(),
        value: MetricValue::Gauge(STREAMS.load(Ordering::Relaxed) as f64),
    }];
    for (outcome, counter) in [
        ("ack", &ACK),
        ("nack", &NACK),
        ("stale_nonce", &STALE_NONCE),
        ("slow", &SLOW),
        ("denied", &DENIED),
        ("heartbeat", &HEARTBEAT),
        ("secret_send", &SECRET_SENDS),
    ] {
        samples.push(MetricSample {
            name: EVENTS.name,
            labels: vec![("outcome", outcome.into())],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    samples
}

/// 业务作用：复用同一指标目录和样本输出管理端计数，避免两种出口各自维护统计。
///
/// 参数说明：
/// - `out`：当前指标文本缓冲。
///
/// 返回：追加固定八个系列，不访问资源缓存或秘密。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&EVENTS, &ACTIVE], &samples(), out);
}
