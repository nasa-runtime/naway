//! 低基数结构化指标目录；适配器读取原子事实，不反解析 Prometheus 文本。

use super::Metrics;
use crate::config::GatewaySnapshot;

/// 已计入时延事实的采样请求关联，仅存放在固定槽位，不作为指标标签。
#[derive(Clone, Copy)]
pub(crate) struct DurationExemplar {
    pub value: f64,
    pub time_unix_nano: u64,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
}

/// 业务作用：非阻塞读取有限 exemplar 槽，只导出本次采集时刻之前的已记录观测。
///
/// 参数说明：
/// - `metrics`：是事实源
/// - `now`：是本次快照时间戳。
///
/// 返回：最多十三项 exemplar；竞争或锁损坏时为空，不影响累计指标。
pub(crate) fn exemplars(metrics: &Metrics, now: u64) -> Vec<DurationExemplar> {
    metrics
        .request_duration_exemplars
        .try_lock()
        .map(|values| {
            values
                .iter()
                .flatten()
                .copied()
                .filter(|value| {
                    value.time_unix_nano <= now
                        && value.time_unix_nano >= metrics.started_unix_nanos
                })
                .collect()
        })
        .unwrap_or_default()
}
use arc_swap::ArcSwap;
use nametrics_core::{
    LegacyMetricsSource, MetricDescriptor, MetricHub, MetricKind, MetricSample, MetricValue,
};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, Weak};

const CORE_NAMES: &[&str] = &[
    "gw_requests_total",
    "gw_responses_1xx_total",
    "gw_responses_2xx_total",
    "gw_responses_3xx_total",
    "gw_responses_4xx_total",
    "gw_responses_5xx_total",
    "gw_upstream_errors_total",
    "gw_upstream_attempts_total",
    "gw_upstream_overloaded_total",
    "gw_upstream_retry_status_total",
    "gw_upstream_retry_error_total",
    "gw_upstream_retry_exhausted_total",
    "gw_upstream_hedge_started_total",
    "gw_upstream_hedge_primary_won_total",
    "gw_upstream_hedge_secondary_won_total",
    "gw_upstream_hedge_failed_total",
    "gw_interface_blocked_total",
    "gw_no_route_total",
    "gw_acl_denied_total",
    "gw_blacklist_denied_total",
    "gw_ext_authz_allowed_total",
    "gw_ext_authz_denied_total",
    "gw_ext_authz_errors_total",
    "gw_mirror_requests_total",
    "gw_mirror_errors_total",
    "gw_mirror_skipped_total",
    "gw_rate_limited_total",
    "gw_conn_limited_total",
    "gw_circuit_rejected_total",
    "gw_stream_connections_total",
    "gw_stream_connection_errors_total",
    "gw_stream_bytes_downstream_to_upstream_total",
    "gw_stream_bytes_upstream_to_downstream_total",
];
pub(crate) const DURATION_BOUNDS: &[f64] = &[
    0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
];
static DURATION: MetricDescriptor = MetricDescriptor {
    name: "gw_request_duration_seconds",
    help: "HTTP request time to response head.",
    unit: "s",
    kind: MetricKind::Histogram,
    label_names: &[],
    histogram_bounds: DURATION_BOUNDS,
};
static CONFIG: MetricDescriptor = MetricDescriptor {
    name: "gw_config_version",
    help: "Published configuration generation.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &[],
    histogram_bounds: &[],
};
static UPSTREAMS: MetricDescriptor = MetricDescriptor {
    name: "gw_upstream_services",
    help: "Configured upstream services.",
    unit: "",
    kind: MetricKind::Gauge,
    label_names: &[],
    histogram_bounds: &[],
};
static WAF: MetricDescriptor = MetricDescriptor {
    name: "gw_waf_requests_total",
    help: "WAF interventions by fixed outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["result"],
    histogram_bounds: &[],
};
pub(crate) static EXPORT: MetricDescriptor = MetricDescriptor {
    name: "gw_telemetry_export_total",
    help: "Telemetry records and delivery attempts by fixed signal and outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["signal", "outcome"],
    histogram_bounds: &[],
};

/// 业务作用：建立固定核心名称到 NASA descriptor 的唯一静态映射。
///
/// 参数说明: 无。
///
/// 返回：进程生命周期不变的目录，无请求输入参与名称、标签或桶定义。
fn descriptors() -> &'static [&'static MetricDescriptor] {
    static CORE: OnceLock<Vec<MetricDescriptor>> = OnceLock::new();
    static ALL: OnceLock<Vec<&'static MetricDescriptor>> = OnceLock::new();
    ALL.get_or_init(|| {
        let core = CORE.get_or_init(|| {
            CORE_NAMES
                .iter()
                .map(|name| MetricDescriptor {
                    name,
                    help: name,
                    unit: "",
                    kind: MetricKind::Counter,
                    label_names: &[],
                    histogram_bounds: &[],
                })
                .collect()
        });
        let result = core
            .iter()
            .chain([&DURATION, &CONFIG, &UPSTREAMS, &WAF, &EXPORT])
            .chain(super::governance::DESCRIPTORS.iter())
            .chain([&crate::observability::ai::SUMMARY])
            .chain([&crate::routing::layers::metrics::DESCRIPTOR])
            .chain(crate::runtime::sentinel::queue::metrics::DESCRIPTORS.iter())
            .chain(super::buckets::DESCRIPTORS.iter())
            .chain(crate::io::request_decompression::metrics::DESCRIPTORS.iter())
            .chain(crate::observability::http_stream::metrics::DESCRIPTORS.iter())
            .chain(crate::observability::circuit::DESCRIPTORS.iter())
            .chain(crate::observability::response_codec::DESCRIPTORS.iter())
            .chain([
                &crate::upstream::load::metrics::EVENTS,
                &crate::upstream::load::metrics::ACTIVE,
                &crate::runtime::traffic_limit::metrics::EVENTS,
                &crate::runtime::traffic_limit::metrics::STATE,
            ])
            .chain([
                #[cfg(feature = "upstream-outlier")]
                &crate::upstream::passive::metrics::EVENTS,
                #[cfg(feature = "upstream-outlier")]
                &crate::upstream::passive::metrics::STATE,
                #[cfg(feature = "rate-preallocation")]
                &crate::runtime::ratelimit::metrics::EVENTS,
                #[cfg(feature = "rate-preallocation")]
                &crate::runtime::ratelimit::metrics::STATE,
            ])
            .collect::<Vec<_>>();
        #[cfg(feature = "config-providers")]
        let result = {
            let mut result = result;
            result.push(&crate::control::providers::metrics::DESCRIPTOR);
            result
        };
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        let result = {
            let mut result = result;
            result.push(&crate::protocols::cgi::metrics::DESCRIPTOR);
            result
        };
        #[cfg(feature = "webdav")]
        let result = {
            let mut result = result;
            result.push(&crate::io::webdav::metrics::DESCRIPTOR);
            result
        };
        #[cfg(feature = "media-streaming")]
        let result = {
            let mut result = result;
            result.push(&crate::io::media::metrics::DESCRIPTOR);
            result
        };
        #[cfg(feature = "lua-scripts")]
        let result = {
            let mut result = result;
            result.push(&crate::extensions::scripts::metrics::DESCRIPTOR);
            result
        };
        #[cfg(feature = "xds-server")]
        let result = {
            let mut result = result;
            result.push(&crate::control::xds_server::metrics::EVENTS);
            result.push(&crate::control::xds_server::metrics::ACTIVE);
            result
        };
        result
    })
}

struct Source {
    metrics: Weak<Metrics>,
    snapshot: Weak<ArcSwap<GatewaySnapshot>>,
}

impl LegacyMetricsSource for Source {
    /// 业务作用：声明该兼容源的全部固定指标合同。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：静态目录，由 MetricHub 统一检查冲突与系列预算。
    fn descriptors(&self) -> &'static [&'static MetricDescriptor] {
        descriptors()
    }

    /// 业务作用：从数据面已有计数器生成结构化事实，采集期间不获取网络或请求 body。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：进程 owner 仍存在时返回有限快照，否则为空，不回退文本猜测。
    fn snapshot(&self) -> Option<Vec<MetricSample>> {
        let Some(metrics) = self.metrics.upgrade() else {
            return Some(Vec::new());
        };
        let Some(snapshot) = self.snapshot.upgrade() else {
            return Some(Vec::new());
        };
        let snap = snapshot.load();
        Some(samples(
            &metrics,
            snap.version,
            snap.upstreams.service_count(),
        ))
    }

    /// 业务作用：保持兼容源协议完整，文本由同一结构化样本渲染。
    ///
    /// 参数说明：
    /// - `output`：是调用方输出缓冲区。
    ///
    /// 返回：追加同一 descriptor 合同下的样本，不修改计数事实。
    fn render_prometheus(&self, output: &mut String) {
        nametrics_core::atomic::render_snapshot(
            descriptors(),
            &self.snapshot().unwrap_or_default(),
            output,
        );
    }
}

/// 业务作用：在激活出口前登记有限系列预算，禁止名称冲突候选进入运行态。
///
/// 参数说明：
/// - `metrics`：是已发布进程事实的 owner，只保存弱引用以避免循环持有。
/// - `snapshot`：是已发布进程事实的 owner，只保存弱引用以避免循环持有。
///
/// 返回：完成目录审计的 MetricHub；任何登记失败均返回错误。
pub(crate) fn hub(
    metrics: &Arc<Metrics>,
    snapshot: &Arc<ArcSwap<GatewaySnapshot>>,
) -> anyhow::Result<Arc<MetricHub>> {
    let hub = Arc::new(MetricHub::new());
    hub.register_legacy_source_reserved(
        Arc::new(Source {
            metrics: Arc::downgrade(metrics),
            snapshot: Arc::downgrade(snapshot),
        }),
        CORE_NAMES.len() + DURATION_BOUNDS.len() + 3 + 2 + 4 + 33 + 29 + 90 + 25 + 10 + 32,
    )
    .map_err(|error| anyhow::anyhow!("gateway metric catalog rejected: {error:?}"))?;
    Ok(hub)
}

/// 业务作用：读取已存在的累计计数、配置代和固定结果，不接受用户或 URL 标签。
///
/// 参数说明：
/// - `metrics`：是事实源
/// - `generation`：来自同一份已发布快照。
/// - `services`：来自同一份已发布快照。
///
/// 返回：有限结构化样本；直方图 count 与同份非累计桶之和一致。
fn samples(metrics: &Metrics, generation: u64, services: usize) -> Vec<MetricSample> {
    let mut samples: Vec<_> = metrics
        .core_counters()
        .into_iter()
        .map(|(name, count)| MetricSample {
            name,
            labels: vec![],
            value: MetricValue::Counter(count),
        })
        .collect();
    let (buckets, sum, count) = duration_snapshot(metrics);
    samples.push(MetricSample {
        name: DURATION.name,
        labels: vec![],
        value: MetricValue::Histogram {
            bounds: DURATION_BOUNDS,
            buckets,
            sum,
            count,
        },
    });
    for (name, value) in [
        (CONFIG.name, generation as f64),
        (UPSTREAMS.name, services as f64),
    ] {
        samples.push(MetricSample {
            name,
            labels: vec![],
            value: MetricValue::Gauge(value),
        });
    }
    for (result, counter) in [
        ("monitored", &metrics.waf_monitored_total),
        ("blocked", &metrics.waf_blocked_total),
        ("too_large", &metrics.waf_too_large_total),
        ("body_read_error", &metrics.waf_body_read_error_total),
    ] {
        samples.push(MetricSample {
            name: WAF.name,
            labels: vec![("result", result.into())],
            value: MetricValue::Counter(counter.load(Ordering::Relaxed)),
        });
    }
    samples.extend(crate::observability::telemetry::otlp::export_samples());
    samples.extend(super::governance::samples());
    #[cfg(feature = "config-providers")]
    samples.extend(crate::control::providers::metrics::samples());
    samples.extend(metrics.ai.summary());
    samples.extend(crate::routing::layers::metrics::samples());
    samples.extend(crate::upstream::load::metrics::samples());
    samples.extend(crate::runtime::traffic_limit::metrics::samples());
    samples.extend(crate::runtime::sentinel::queue::metrics::samples());
    samples.extend(super::buckets::samples(metrics));
    samples.extend(crate::io::request_decompression::metrics::samples());
    samples.extend(metrics.http_stream.samples());
    samples.extend(metrics.circuits.samples());
    samples.extend(metrics.response_codec.samples());
    #[cfg(feature = "upstream-outlier")]
    samples.extend(crate::upstream::passive::metrics::samples());
    #[cfg(feature = "rate-preallocation")]
    samples.extend(crate::runtime::ratelimit::metrics::samples());
    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
    samples.extend(crate::protocols::cgi::metrics::samples());
    #[cfg(feature = "webdav")]
    samples.extend(crate::io::webdav::metrics::samples());
    #[cfg(feature = "media-streaming")]
    samples.extend(crate::io::media::metrics::samples());
    #[cfg(feature = "lua-scripts")]
    samples.extend(crate::extensions::scripts::metrics::samples());
    #[cfg(feature = "xds-server")]
    samples.extend(crate::control::xds_server::metrics::samples());
    samples
}

/// 业务作用：为控制台提供与指标出口同源的固定目录，不解析内部状态或抓取文本。
///
/// 参数说明：
/// - `metrics`：是当前已发布事实。
/// - `generation`：是当前已发布事实。
/// - `services`：是当前已发布事实。
///
/// 返回：带稳定 schema 的低基数读模型，关闭新出口时不创建此读面。
pub(crate) fn dashboard(metrics: &Metrics, generation: u64, services: usize) -> serde_json::Value {
    let points: Vec<_> = samples(metrics, generation, services)
        .into_iter()
        .map(|sample| {
            let value = match sample.value {
                MetricValue::Counter(value) => serde_json::json!(value),
                MetricValue::Gauge(value) => serde_json::json!(value),
                MetricValue::Histogram {
                    bounds,
                    buckets,
                    sum,
                    count,
                } => serde_json::json!({
                    "bounds":bounds,
                    "buckets":buckets,
                    "sum":sum,
                    "count":count
                }),
            };
            serde_json::json!({
                "name":sample.name,
                "labels":sample.labels.into_iter().collect::<std::collections::BTreeMap<_,
                _>>(),
                "value":value
            })
        })
        .collect();
    serde_json::json!({
        "schema_version":1,
        "metrics":points
    })
}

/// 业务作用：从同一组时延桶和累计事实构造协议要求的完整直方图。
///
/// 参数说明：
/// - `metrics`：是进程事实源。
///
/// 返回：有限桶、溢出桶、近似同期 sum 和与桶总和一致的 count。
pub(crate) fn duration_snapshot(metrics: &Metrics) -> (Vec<u64>, f64, u64) {
    let mut buckets: Vec<_> = metrics
        .request_duration_buckets
        .iter()
        .map(|bucket| bucket.load())
        .collect();
    let finite = buckets.iter().copied().fold(0u64, u64::saturating_add);
    let count = metrics.request_duration_count.load().max(finite);
    buckets.push(count - finite);
    (
        buckets,
        metrics.request_duration_sum_micros.load() as f64 / 1_000_000.0,
        count,
    )
}

/// 业务作用：只在启用新出口时增加固定出口诊断族，保持关闭态文本不变。
///
/// 参数说明：
/// - `metrics`：提供同一 AI 事实
/// - `out`：是 Prometheus 输出缓冲区。
///
/// 返回：从同一进程原子事实追加文本，不创建另一套记录器。
pub(crate) fn render_extra(metrics: &Metrics, out: &mut String) {
    let mut samples = crate::observability::telemetry::otlp::export_samples();
    samples.extend(super::governance::samples());
    samples.extend(metrics.ai.summary());
    let descriptors: Vec<_> = [&EXPORT, &crate::observability::ai::SUMMARY]
        .into_iter()
        .chain(super::governance::DESCRIPTORS.iter())
        .collect();
    nametrics_core::atomic::render_snapshot(&descriptors, &samples, out);
}

/// 业务作用：记录进程累计指标的起始或采集时刻。
///
/// 参数说明: 无。
///
/// 返回：有界 Unix 纳秒时间；时钟早于 epoch 时为零。
pub(crate) fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}
