//! 固定HTTP实体与生命周期指标，所有出口共用同一进程事实。

use crate::observability::metrics::ShardedCounter;
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const BOUNDS_MS: [u64; 12] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
const BUCKET_LABELS: [&str; 13] = [
    "1", "5", "10", "25", "50", "100", "250", "500", "1000", "2500", "5000", "10000", "+Inf",
];

#[derive(Default)]
pub(crate) struct Counters {
    pub(super) bytes: [ShardedCounter; 2],
    pub(super) requests: [ShardedCounter; 3],
    pub(super) responses: [ShardedCounter; 4],
    pub(super) active: AtomicU64,
    pub(super) duration_micros: ShardedCounter,
    pub(super) duration_count: ShardedCounter,
    pub(super) buckets: [ShardedCounter; 13],
}

pub(crate) static DESCRIPTORS: [MetricDescriptor; 7] = [
    MetricDescriptor {
        name: "gw_http_body_bytes_total",
        help: "HTTP encoded DATA bytes consumed from requests or supplied to the response adapter; excludes protocol overhead and delivery acknowledgement.",
        unit: "By",
        kind: MetricKind::Counter,
        label_names: &["direction"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_http_request_body_events_total",
        help: "Observed request body EOF, errors or early drops; a drop does not identify the party responsible.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["outcome"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_http_response_events_total",
        help: "HTTP response lifecycle outcomes at the local body boundary, including drops before response headers.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["outcome"],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_http_response_inflight",
        help: "HTTP responses waiting for headers or local body completion; excludes established upgraded tunnels.",
        unit: "",
        kind: MetricKind::Gauge,
        label_names: &[],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_http_response_duration_microseconds_total",
        help: "Total elapsed microseconds from HTTP ingress to local response body EOF; no-body responses end when their head is ready.",
        unit: "us",
        kind: MetricKind::Counter,
        label_names: &[],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_http_response_duration_count",
        help: "Responses with observed body EOF, irrespective of HTTP status; excludes errors, drops and upgraded tunnels.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &[],
        histogram_bounds: &[],
    },
    MetricDescriptor {
        name: "gw_http_response_duration_bucket_total",
        help: "Non-cumulative local response EOF duration buckets; upper_bound_ms identifies each disjoint bucket inclusive upper bound.",
        unit: "",
        kind: MetricKind::Counter,
        label_names: &["upper_bound_ms"],
        histogram_bounds: &[],
    },
];

impl Counters {
    /// 业务作用：读取固定二十五项HTTP事实，采集不锁住数据面或枚举请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：线程分片的弱一致累计快照，维度全部来自静态枚举。
    pub(crate) fn samples(&self) -> Vec<MetricSample> {
        let mut samples = Vec::with_capacity(25);
        for (descriptor, key, labels, counters) in [
            (
                0,
                "direction",
                &["request", "response"][..],
                &self.bytes[..],
            ),
            (
                1,
                "outcome",
                &["eof", "body_error", "dropped"][..],
                &self.requests[..],
            ),
            (
                2,
                "outcome",
                &["eof", "body_error", "dropped", "upgraded"][..],
                &self.responses[..],
            ),
            (6, "upper_bound_ms", &BUCKET_LABELS[..], &self.buckets[..]),
        ] {
            for (label, value) in labels.iter().zip(counters) {
                samples.push(MetricSample {
                    name: DESCRIPTORS[descriptor].name,
                    labels: vec![(key, (*label).into())],
                    value: MetricValue::Counter(value.load()),
                });
            }
        }
        samples.push(MetricSample {
            name: DESCRIPTORS[3].name,
            labels: vec![],
            value: MetricValue::Gauge(self.active.load(Ordering::Relaxed) as f64),
        });
        for (descriptor, value) in [(4, &self.duration_micros), (5, &self.duration_count)] {
            samples.push(MetricSample {
                name: DESCRIPTORS[descriptor].name,
                labels: vec![],
                value: MetricValue::Counter(value.load()),
            });
        }
        samples
    }

    /// 业务作用：用共享描述符渲染HTTP事实，使文本与结构化出口保持相同单位和终态。
    ///
    /// 参数说明：
    /// - `output`：调用方已有指标响应缓冲。
    ///
    /// 返回：追加固定系列，不产生另一个计数器或正文采样。
    pub(crate) fn render(&self, output: &mut String) {
        nametrics_core::atomic::render_snapshot(
            &DESCRIPTORS.iter().collect::<Vec<_>>(),
            &self.samples(),
            output,
        );
    }
}
