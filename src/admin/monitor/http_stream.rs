//! HTTP实体与完整正文区间读面，缺少系列或覆盖不完整时不推算完成分布。

use super::model::Point;
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct View {
    availability: &'static str,
    request_bytes_per_second: Option<f64>,
    response_bytes_per_second: Option<f64>,
    inflight: Option<f64>,
    completed_per_second: Option<f64>,
    errors_per_second: Option<f64>,
    dropped_per_second: Option<f64>,
    mean_ms: Option<f64>,
    p95_ms: Option<f64>,
}

/// 业务作用：用同一有效区间的固定系列生成正文摘要，混合旧节点或计数读取不一致时保留未知分位。
///
/// 参数说明：
/// - `points`：单节点或数据角色集群的区间指标，包含每项覆盖状态。
///
/// 返回：原始字节与生命周期事实；完整覆盖且桶/次数一致时才给出完成均值和P95。
pub(super) fn view(points: &[Point<'_>]) -> View {
    let find = |name, label: Option<(&str, &str)>| {
        points.iter().find(|point| {
            point.name == name
                && match label {
                    Some((key, value)) => {
                        point.labels.len() == 1
                            && point.labels.get(key).is_some_and(|label| label == value)
                    }
                    None => point.labels.is_empty(),
                }
        })
    };
    let rate = |name, label| find(name, label).and_then(|point| point.per_second);
    let selected: Vec<_> = points
        .iter()
        .filter(|point| {
            crate::observability::http_stream::metrics::DESCRIPTORS
                .iter()
                .any(|descriptor| descriptor.name == point.name)
        })
        .collect();
    let complete = selected.len() == 25
        && selected
            .iter()
            .all(|point| point.availability == "available");
    let mut result = View {
        availability: if complete {
            "available"
        } else if selected
            .iter()
            .any(|point| point.current.is_some() || point.per_second.is_some())
        {
            "partial"
        } else {
            "unknown"
        },
        request_bytes_per_second: rate("gw_http_body_bytes_total", Some(("direction", "request"))),
        response_bytes_per_second: rate(
            "gw_http_body_bytes_total",
            Some(("direction", "response")),
        ),
        inflight: find("gw_http_response_inflight", None).and_then(|point| point.current),
        completed_per_second: rate("gw_http_response_events_total", Some(("outcome", "eof"))),
        errors_per_second: rate(
            "gw_http_response_events_total",
            Some(("outcome", "body_error")),
        ),
        dropped_per_second: rate(
            "gw_http_response_events_total",
            Some(("outcome", "dropped")),
        ),
        mean_ms: None,
        p95_ms: None,
    };
    // 不同系列可能只有不同的节点子集可用；没有完整组覆盖就不能混合它们计算均值或分位。
    if !complete {
        return result;
    }
    let bounds = [
        1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
    ];
    let labels = [
        "1", "5", "10", "25", "50", "100", "250", "500", "1000", "2500", "5000", "10000", "+Inf",
    ];
    let mut buckets = [0.0; 13];
    for (index, label) in labels.iter().enumerate() {
        let Some(value) = rate(
            "gw_http_response_duration_bucket_total",
            Some(("upper_bound_ms", label)),
        ) else {
            result.availability = "unknown";
            return result;
        };
        buckets[index] = value;
    }
    let Some(count) = find("gw_http_response_duration_count", None) else {
        return result;
    };
    let total: f64 = buckets.iter().sum();
    let Some((count_rate, sum_rate)) = count
        .per_second
        .zip(rate("gw_http_response_duration_microseconds_total", None))
    else {
        return result;
    };
    // 分片计数在观察瞬间是弱一致的；桶次数与完成次数不一致时不伪造可解释的延迟。
    if (total - count_rate).abs() > total.max(count_rate).max(1.0) * 1e-9 {
        result.availability = "inconsistent";
        return result;
    }
    let sum_ms = sum_rate / 1000.0;
    let minimum: f64 = bounds
        .iter()
        .zip(buckets.iter().skip(1))
        .map(|(lower, count)| lower * count)
        .sum();
    let maximum: f64 = bounds
        .iter()
        .zip(buckets.iter())
        .map(|(upper, count)| upper * count)
        .sum();
    let tolerance = sum_ms.max(minimum).max(maximum).max(1.0) * 1e-9;
    if sum_ms + tolerance < minimum || (buckets[12] == 0.0 && sum_ms > maximum + tolerance) {
        result.availability = "inconsistent";
        return result;
    }
    if total <= 0.0 {
        return result;
    }
    result.mean_ms = Some(sum_rate / total / 1000.0);
    if count.delta.unwrap_or(0) < 20 {
        return result;
    }
    let rank = total * 0.95;
    let mut lower = 0.0;
    let mut cumulative = 0.0;
    for (upper, value) in bounds.into_iter().zip(buckets) {
        if cumulative + value >= rank && value > 0.0 {
            result.p95_ms = Some(lower + (upper - lower) * (rank - cumulative) / value);
            break;
        }
        cumulative += value;
        lower = upper;
    }
    result
}
