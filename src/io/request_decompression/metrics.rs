//! 解码资源与固定结果观测，不保存请求内容或维度历史。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) static EVENTS: [AtomicU64; 7] = [const {
    AtomicU64::new(0)
}; 7];
pub(super) static BYTES: [AtomicU64; 2] = [const {
    AtomicU64::new(0)
}; 2];
pub(crate) static DESCRIPTORS: [MetricDescriptor; 4] = [
    MetricDescriptor {
        name: "gw_request_decompression_events_total",
        help: "Request decoding outcomes including cancellation.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["outcome"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_request_decompression_bytes_total",
        help: "Accepted input and delivered output bytes of finished decoders.",
        unit: "By",
        kind: MetricKind::Counter,
        label_names: &["direction"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_request_decompression_active",
        help: "Active request codecs sharing process capacity across configuration changes.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &["algorithm"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_request_decompression_retained_bytes",
        help: "Input frame bytes retained by active request codecs.",
        unit: "By",
        kind: MetricKind::Gauge,
        label_names: &[],
        histogram_bounds: &[],
    },
];

/// 业务作用：为实时管理与OTLP读取固定结果和当前容量，不产生请求级标签。
///
/// 参数说明: 无。
///
/// 返回：十二项固定样本；输入输出字节在解码器结束时结算。
pub(crate) fn samples() -> Vec<MetricSample> {
    let mut samples: Vec<_> = [
        "completed",
        "malformed",
        "limit",
        "unsupported",
        "deadline",
        "capacity",
        "cancelled",
    ]
    .into_iter()
    .zip(EVENTS.iter())
    .map(|(outcome, value)| MetricSample {
        name: DESCRIPTORS[0].name,
        labels: vec![("outcome", outcome.into())],
        value: MetricValue::Counter(value.load(Ordering::Relaxed)),
    })
    .collect();
    for (direction, value) in ["encoded", "decoded"].into_iter().zip(BYTES.iter()) {
        samples.push(MetricSample {
            name: DESCRIPTORS[1].name,
            labels: vec![("direction", direction.into())],
            value: MetricValue::Counter(value.load(Ordering::Relaxed)),
        });
    }
    for (algorithm, value) in [
        ("gzip", &super::body::GZIP_ACTIVE),
        ("br", &super::body::BROTLI_ACTIVE),
    ] {
        samples.push(MetricSample {
            name: DESCRIPTORS[2].name,
            labels: vec![("algorithm", algorithm.into())],
            value: MetricValue::Gauge(value.load(Ordering::Relaxed) as f64),
        });
    }
    samples.push(MetricSample {
        name: DESCRIPTORS[3].name,
        labels: vec![],
        value: MetricValue::Gauge(super::body::INPUT_BYTES.load(Ordering::Relaxed) as f64),
    });
    samples
}

/// 业务作用：用统一描述符输出Prometheus当前解码事实，保持多出口口径一致。
///
/// 参数说明：
/// - `out`：已有指标响应缓冲。
///
/// 返回：追加固定系列，不扫描请求或动态配置。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(
        &DESCRIPTORS.iter().collect::<Vec<_>>(),
        &samples(),
        out,
    );
}
