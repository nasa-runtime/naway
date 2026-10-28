//! 把 NASA 结构化指标目录编码为 OTLP，保留原计数器与固定标签合同。

use super::{wire::string_attribute, MetricSource};
use crate::config::GatewaySnapshot;
use crate::observability::metrics::{catalog, Metrics};
use arc_swap::ArcSwap;
use nametrics_core::{MetricFamilySnapshot, MetricKind, MetricValue};
use opentelemetry_proto::tonic::metrics::v1::{
    metric, number_data_point, AggregationTemporality, Gauge, Histogram, HistogramDataPoint,
    Metric, NumberDataPoint, Sum,
};
use std::sync::Arc;

/// 业务作用：注册统一目录后冻结累计起始时刻，后续采集只读取同一组进程事实。
///
/// 参数说明：
/// - `metrics`：是当前进程的数据面与配置事实 owner。
/// - `snapshot`：是当前进程的数据面与配置事实 owner。
///
/// 返回：无网络行为的有限采集闭包；目录冲突或预算登记失败时返回错误。
pub(in crate::observability::telemetry) fn bind(
    metrics: &Arc<Metrics>,
    snapshot: &Arc<ArcSwap<GatewaySnapshot>>,
) -> anyhow::Result<MetricSource> {
    let hub = catalog::hub(metrics, snapshot)?;
    let start = metrics.started_unix_nanos;
    let weak_metrics = Arc::downgrade(metrics);
    Ok(Arc::new(move || {
        let now = catalog::unix_nanos().max(start);
        let exemplars = weak_metrics
            .upgrade()
            .map(|metrics| catalog::exemplars(&metrics, now))
            .unwrap_or_default();
        hub.family_snapshot()
            .into_iter()
            .map(|family| {
                let mut metric = encode(family, start, now);
                if metric.name == "gw_request_duration_seconds" {
                    if let Some(metric::Data::Histogram(histogram)) = &mut metric.data {
                        for point in &mut histogram.data_points {
                            point.exemplars = exemplars.iter().map(|sample| opentelemetry_proto::tonic::metrics::v1::Exemplar {
                                time_unix_nano: sample.time_unix_nano,
                                    trace_id: sample.trace_id.to_vec(),
                                    span_id: sample.span_id.to_vec(),
                                    value: Some(opentelemetry_proto::tonic::metrics::v1::exemplar::Value::AsDouble(sample.value)), ..Default::default()
                            }).collect();
                        }
                    }
                }
                metric
            })
            .collect()
    }))
}

/// 业务作用：按已验证的 family 类型编码，不从名称后缀猜测 Counter、Gauge 或 Histogram。
///
/// 参数说明：
/// - `family`：来自 MetricHub
/// - `start`：是同一累计序列的时间界限。
/// - `now`：是同一累计序列的时间界限。
///
/// 返回：标准 OTLP 指标，不在属性中混入 trace、用户或原始 URL。
fn encode(family: MetricFamilySnapshot, start: u64, now: u64) -> Metric {
    let mut numbers = Vec::new();
    let mut histograms = Vec::new();
    for sample in family.samples {
        let attributes = sample
            .labels
            .into_iter()
            .map(|(key, value)| string_attribute(key, &value))
            .collect();
        match sample.value {
            MetricValue::Counter(value) => numbers.push(NumberDataPoint {
                attributes,
                start_time_unix_nano: start,
                time_unix_nano: now,
                value: Some(if value <= i64::MAX as u64 {
                    number_data_point::Value::AsInt(value as i64)
                } else {
                    number_data_point::Value::AsDouble(value as f64)
                }),
                ..Default::default()
            }),
            MetricValue::Gauge(value) => numbers.push(NumberDataPoint {
                attributes,
                time_unix_nano: now,
                value: Some(number_data_point::Value::AsDouble(value)),
                ..Default::default()
            }),
            MetricValue::Histogram {
                bounds,
                buckets,
                sum,
                count,
            } => histograms.push(HistogramDataPoint {
                attributes,
                start_time_unix_nano: start,
                time_unix_nano: now,
                count,
                sum: Some(sum),
                bucket_counts: buckets,
                explicit_bounds: bounds.to_vec(),
                ..Default::default()
            }),
        }
    }
    let data = match family.kind {
        MetricKind::Counter => metric::Data::Sum(Sum {
            data_points: numbers,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        }),
        MetricKind::Gauge => metric::Data::Gauge(Gauge {
            data_points: numbers,
        }),
        MetricKind::Histogram => metric::Data::Histogram(Histogram {
            data_points: histograms,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
        }),
    };
    Metric {
        name: family.name.into(),
        description: family.description.into(),
        unit: family.unit.into(),
        data: Some(data),
        ..Default::default()
    }
}
