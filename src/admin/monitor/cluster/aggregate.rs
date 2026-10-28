//! 集群区间聚合按节点实际时间归一化，保留每项指标的覆盖范围。

use super::super::model;
use std::collections::BTreeMap;

type Key = (String, BTreeMap<String, String>);

#[derive(Default)]
struct Sum {
    kind: &'static str,
    current: f64,
    rate: f64,
    delta: u64,
    valid: usize,
}

#[derive(Default)]
pub(in crate::admin::monitor) struct Aggregate {
    series: BTreeMap<Key, Sum>,
    bounds: Vec<u64>,
    buckets: Vec<f64>,
    count: u64,
    duration_rate: f64,
    latency_nodes: usize,
    min_interval: Option<u64>,
    max_interval: Option<u64>,
    pub capacity: bool,
}

impl Aggregate {
    /// 业务作用：把一个节点的有效速率和可加瞬时数量并入固定容量目录。
    ///
    /// 参数说明：
    /// - `points`：同一节点的区间事实。
    /// - `latency`：同一节点区间直方图。
    /// - `elapsed`：节点实际单调区间，缺失时不能加入时延聚合。
    ///
    /// 返回：更新当前轮累加器；不保留节点历史或重复累计值。
    pub(in crate::admin::monitor) fn add(
        &mut self,
        points: &[model::Point<'_>],
        latency: &model::Latency,
        elapsed: Option<u64>,
    ) {
        for point in points {
            if point.kind == "gauge" && !additive_gauge(point.name) {
                continue;
            }
            let key = (point.name.to_owned(), point.labels.clone());
            if !self.series.contains_key(&key) && self.series.len() >= model::MAX_SERIES {
                self.capacity = true;
                continue;
            }
            let sum = self.series.entry(key).or_default();
            if sum.kind.is_empty() {
                sum.kind = point.kind;
            }
            // 同名不同类型不能合并，防止不同节点目录冲突后生成含义不明的数字。
            if sum.kind != point.kind {
                continue;
            }
            if let Some(value) = point
                .current
                .or(point.per_second)
                .filter(|value| value.is_finite())
            {
                if let Some(total) = sum.delta.checked_add(point.delta.unwrap_or(0)) {
                    sum.delta = total;
                    sum.current += point.current.unwrap_or(0.0);
                    sum.rate += point.per_second.unwrap_or(0.0);
                    sum.valid += usize::from(value.is_finite());
                }
            }
        }
        let Some((buckets, elapsed)) = latency.buckets.as_ref().zip(elapsed) else {
            return;
        };
        if self.latency_nodes == 0 {
            self.bounds.clone_from(&latency.bounds_ms);
            self.buckets.resize(buckets.len(), 0.0);
        }
        // 不同直方图目录不能按索引相加，缺失节点通过独立时延覆盖数暴露。
        if self.bounds != latency.bounds_ms || self.buckets.len() != buckets.len() || elapsed == 0 {
            return;
        }
        let Some(count) = self.count.checked_add(latency.count.unwrap_or(0)) else {
            return;
        };
        let seconds = elapsed as f64 / 1000.0;
        for (sum, value) in self.buckets.iter_mut().zip(buckets) {
            *sum += *value as f64 / seconds;
        }
        self.duration_rate +=
            latency.mean_ms.unwrap_or(0.0) * latency.count.unwrap_or(0) as f64 / seconds;
        self.count = count;
        self.latency_nodes += 1;
        self.min_interval = Some(self.min_interval.map_or(elapsed, |old| old.min(elapsed)));
        self.max_interval = Some(self.max_interval.map_or(elapsed, |old| old.max(elapsed)));
    }

    /// 业务作用：生成可供摘要及页面共用的当前聚合指标，部分覆盖不能冒充全量。
    ///
    /// 参数说明：
    /// - `total`：本轮应覆盖的节点总数。
    ///
    /// 返回：仅引用当前累加器的有限指标视图。
    pub(super) fn points(&self, total: usize) -> Vec<model::Point<'_>> {
        self.series
            .iter()
            .map(|((name, labels), value)| model::Point {
                name,
                labels,
                kind: value.kind,
                availability: if value.valid == 0 {
                    "unknown"
                } else if value.valid < total {
                    "partial"
                } else {
                    "available"
                },
                current: (value.kind == "gauge" && value.valid > 0 && value.current.is_finite())
                    .then_some(value.current),
                delta: (value.kind == "counter" && value.valid > 0).then_some(value.delta),
                per_second: (value.kind == "counter" && value.valid > 0 && value.rate.is_finite())
                    .then_some(value.rate),
            })
            .collect()
    }

    /// 业务作用：输出归一化时延分布和真实样本量，避免不同区间对分位权重产生偏差。
    ///
    /// 参数说明：
    /// - `total`：应覆盖的节点数。
    ///
    /// 返回：每秒桶、估算分位与覆盖信息，低样本或溢出桶分位为null。
    pub(in crate::admin::monitor) fn latency(&self, total: usize) -> serde_json::Value {
        let rate: f64 = self.buckets.iter().sum();
        serde_json::json!({
            "availability": if self.latency_nodes == 0 {
                "unknown"
            } else if self.latency_nodes < total {
                "partial"
            } else if self.count == 0 {
                "no_samples"
            } else {
                "available"
            },
            "count": (self.latency_nodes > 0).then_some(self.count),
            "mean_ms": (rate > 0.0).then(|| self.duration_rate / rate),
            "p50_ms": self.quantile(0.50, 5),
            "p95_ms": self.quantile(0.95, 20),
            "p99_ms": self.quantile(0.99, 100),
            "bounds_ms": self.bounds,
            "buckets": if self.latency_nodes > 0 {
                Some(&self.buckets)
            } else {
                None
            },
            "bucket_unit": "per_second",
            "bucket_total": rate,
            "valid_nodes": self.latency_nodes,
            "total_nodes": total,
            "min_interval_ms": self.min_interval,
            "max_interval_ms": self.max_interval,
        })
    }

    /// 业务作用：在有限桶内按归一化权重估算分位，并用真实观测次数限制可信度。
    ///
    /// 参数说明：
    /// - `fraction`：固定分位比例。
    /// - `minimum`：所需实际样本数量。
    ///
    /// 返回：有限毫秒估值；零流量、样本不足或落入溢出桶时返回未知。
    fn quantile(&self, fraction: f64, minimum: u64) -> Option<f64> {
        let total: f64 = self.buckets.iter().sum();
        if self.count < minimum || total <= 0.0 || !total.is_finite() {
            return None;
        }
        let rank = total * fraction;
        let mut lower = 0.0;
        let mut cumulative = 0.0;
        for (index, value) in self.buckets.iter().enumerate() {
            if cumulative + value >= rank && *value > 0.0 {
                let upper = *self.bounds.get(index)? as f64;
                return Some(lower + (upper - lower) * (rank - cumulative) / value);
            }
            cumulative += value;
            lower = *self.bounds.get(index)? as f64;
        }
        None
    }
}

/// 业务作用：仅合并有明确加法含义的瞬时数量，配置版本、比例或状态码不进行算术叠加。
///
/// 参数说明：
/// - `name`：固定目录指标名。
///
/// 返回：已知数量或资源占用返回true，其余瞬时项仅在节点读面显示。
fn additive_gauge(name: &str) -> bool {
    // 桶数按实例相加；每节点互斥的观测状态位相加后表示该状态的节点覆盖数量。
    matches!(
        name,
        "gw_active_connections"
            | "gw_circuit_state_instances"
            | "gw_circuit_active_calls"
            | "gw_rate_bucket_observation"
            | "gw_rate_local_buckets"
            | "gw_response_codec_inflight"
            | "gw_http_response_inflight"
            | "gw_management_active_connections"
            | "gw_management_rpc_active"
            | "gw_sentinel_queue_waiting"
            | "gw_request_decompression_active"
            | "gw_request_decompression_retained_bytes"
            | "gw_stream_active_connections"
            | "gw_process_resident_bytes"
            | "gw_long_connections_current"
            | "gw_long_connections_stale"
            | "gw_active_health_unhealthy"
            | "gw_edge_active_streams"
            | "gw_edge_payload_bytes"
            | "gw_edge_queue_refs"
            | "gw_edge_relay_queue_depth"
    )
}
