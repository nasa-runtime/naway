//! 有界实时读模型与区间计算，只处理相邻样本，不保存时间序列。

use nametrics_core::{MetricSample, MetricValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(in crate::admin) const MAX_SERIES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admin) struct Reading {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::admin) enum Value {
    Counter {
        total: u64,
    },
    Gauge {
        current: f64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admin) struct Histogram {
    pub bounds_ms: Vec<u64>,
    pub buckets: Vec<u64>,
    pub sum_micros: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admin) struct NodeState {
    pub mode: String,
    pub ready: bool,
    pub config_version: u64,
    pub config_fingerprint: Option<String>,
    pub discovery_enabled: bool,
    pub configuration_enabled: bool,
    pub proxies: usize,
    pub routes: usize,
    pub services: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admin) struct Sample {
    pub schema_version: u8,
    pub boot_id: String,
    pub sample_id: u64,
    pub sampled_at_ms: u64,
    pub elapsed_ms: u64,
    pub sampling_period_ms: u64,
    pub state: NodeState,
    pub readings: Vec<Reading>,
    pub latency: Histogram,
    pub capabilities: BTreeMap<String, bool>,
    // HTTP原始指标读取权不包含对象目录权；路由身份仅通过明确授权的管理gRPC及独立读面交付。
    #[serde(skip)]
    pub route_traffic: Option<crate::observability::http_stream::routes::Snapshot>,
}

#[derive(Debug, Serialize)]
pub(in crate::admin) struct Point<'a> {
    pub name: &'a str,
    pub labels: &'a BTreeMap<String, String>,
    pub kind: &'static str,
    pub availability: &'static str,
    pub current: Option<f64>,
    pub delta: Option<u64>,
    pub per_second: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(in crate::admin) struct Latency {
    pub availability: &'static str,
    pub count: Option<u64>,
    pub mean_ms: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub bounds_ms: Vec<u64>,
    pub buckets: Option<Vec<u64>>,
}

/// 业务作用：把 NASA 结构化原子事实转换为有限管理协议，不展开任意直方图或标签。
///
/// 参数说明：
/// - `samples`：固定指标目录生成的样本。
///
/// 返回：计数与瞬时状态列表；时延直方图由独立字段承载。
pub(in crate::admin) fn readings(samples: Vec<MetricSample>) -> Vec<Reading> {
    samples
        .into_iter()
        .filter_map(|sample| {
            let value = match sample.value {
                MetricValue::Counter(total) => Value::Counter {
                    total,
                },
                MetricValue::Gauge(current) if current.is_finite() => Value::Gauge {
                    current,
                },
                _ => return None,
            };
            Some(Reading {
                name: sample.name.to_owned(),
                labels: sample
                    .labels
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
                value,
            })
        })
        .collect()
}

/// 业务作用：拒绝超容量、重复系列和非法数值，保证采样与远端输入不会扩大内存或产生错误速率。
///
/// 参数说明：
/// - `sample`：本机或远端完整累计样本。
///
/// 返回：合法样本排序后返回true；违反固定协议时返回false，调用方丢弃基线。
pub(in crate::admin) fn validate(sample: &mut Sample) -> bool {
    if sample.schema_version != 1
        || !matches!(sample.sampling_period_ms, 1000 | 2000 | 5000 | 10000)
        || sample.boot_id.is_empty()
        || sample.boot_id.len() > 64
        || sample.readings.len() > MAX_SERIES
        || sample.latency.bounds_ms.len() > 32
        || sample.latency.buckets.len() != sample.latency.bounds_ms.len() + 1
        || sample
            .state
            .config_fingerprint
            .as_ref()
            .is_some_and(|value| value.len() > 64)
        || !matches!(
            sample.state.mode.as_str(),
            "data" | "sidecar" | "admin" | "all-in-one"
        )
        || sample.capabilities.len() > 64
        || sample.capabilities.keys().any(|key| key.len() > 64)
        || sample
            .route_traffic
            .as_ref()
            .is_some_and(|routes| !routes.valid())
        || !sample
            .latency
            .bounds_ms
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return false;
    }
    for reading in &sample.readings {
        if reading.name.len() > 96
            || reading.labels.len() > 3
            || reading
                .labels
                .iter()
                .any(|(key, value)| key.len() > 32 || value.len() > 64)
            || matches!(reading.value, Value::Gauge {
                current
            } if !current.is_finite())
        {
            return false;
        }
    }
    sample
        .readings
        .sort_by(|a, b| (&a.name, &a.labels).cmp(&(&b.name, &b.labels)));
    !sample
        .readings
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name && pair[0].labels == pair[1].labels)
}

/// 业务作用：只让同一进程连续成功的短间隔样本参与速率换算，失联或重启后重新建立基线。
///
/// 参数说明：
/// - `current`：当前累计事实。
/// - `previous`：唯一保留的上个成功样本。
///
/// 返回：合法区间毫秒数；首样本、重复、时钟回退或超过三周期返回未知。
pub(in crate::admin) fn interval(current: &Sample, previous: Option<&Sample>) -> Option<u64> {
    interval_with_period(current, previous, current.sampling_period_ms)
}

/// 业务作用：按观察方与节点的较长周期验证连续区间，允许异步集群采样而不吸收失联空档。
///
/// 参数说明：
/// - `current`：当前累计事实。
/// - `previous`：唯一成功基线。
/// - `period_ms`：观察协调器的有效周期。
///
/// 返回：同进程、同采样周期且未过期的区间，否则返回未知。
pub(in crate::admin) fn interval_with_period(
    current: &Sample,
    previous: Option<&Sample>,
    period_ms: u64,
) -> Option<u64> {
    let previous = previous?;
    if current.boot_id != previous.boot_id
        || current.sample_id <= previous.sample_id
        || current.sampling_period_ms != previous.sampling_period_ms
        || current.state.config_version != previous.state.config_version
        || current.state.config_fingerprint != previous.state.config_fingerprint
    {
        return None;
    }
    current
        .elapsed_ms
        .checked_sub(previous.elapsed_ms)
        .filter(|elapsed| {
            (1..=period_ms.max(current.sampling_period_ms).saturating_mul(3)).contains(elapsed)
        })
}

/// 业务作用：输出当前瞬时状态和相邻累计差值，计数器重置不能伪造零或负速率。
///
/// 参数说明：
/// - `current`：本轮完整样本。
/// - `previous`：同一采样范围的唯一基线。
///
/// 返回：固定系列的当前值或区间增量，未建立基线的计数项明确为unknown。
pub(in crate::admin) fn points<'a>(
    current: &'a Sample,
    previous: Option<&Sample>,
) -> Vec<Point<'a>> {
    points_with_period(current, previous, current.sampling_period_ms)
}

/// 业务作用：按共享协调器实际周期计算固定系列，远端慢周期不被误判为零流量。
///
/// 参数说明：
/// - `current`：当前样本。
/// - `previous`：前次成功基线。
/// - `period_ms`：观察协调器周期。
///
/// 返回：瞬时状态及有效区间速率，无法证明连续时保留未知。
pub(in crate::admin) fn points_with_period<'a>(
    current: &'a Sample,
    previous: Option<&Sample>,
    period_ms: u64,
) -> Vec<Point<'a>> {
    let elapsed = interval_with_period(current, previous, period_ms);
    current
        .readings
        .iter()
        .map(|reading| {
            let old = previous.and_then(|sample| {
                sample
                    .readings
                    .binary_search_by(|value| {
                        (&value.name, &value.labels).cmp(&(&reading.name, &reading.labels))
                    })
                    .ok()
                    .map(|index| &sample.readings[index])
            });
            let (kind, value, delta) = match (&reading.value, old.map(|value| &value.value)) {
                (
                    Value::Gauge {
                        current,
                    },
                    _,
                ) => ("gauge", Some(*current), None),
                (
                    Value::Counter {
                        total,
                    },
                    Some(Value::Counter {
                        total: old,
                    }),
                ) if elapsed.is_some() => ("counter", None, total.checked_sub(*old)),
                _ => ("counter", None, None),
            };
            Point {
                name: &reading.name,
                labels: &reading.labels,
                kind,
                availability: if value.is_some() || delta.is_some() {
                    "available"
                } else {
                    "unknown"
                },
                current: value,
                delta,
                per_second: delta
                    .zip(elapsed)
                    .map(|(value, millis)| value as f64 * 1000.0 / millis as f64),
            }
        })
        .collect()
}

/// 业务作用：从同一时延口径的相邻桶计算当前分布和估算分位，不平均历史或节点分位。
///
/// 参数说明：
/// - `current`：当前累计直方图。
/// - `previous`：上次成功直方图，缺失代表重新采样。
///
/// 返回：非累计区间桶；任何桶或sum回退均为未知，样本不足或落入溢出桶的分位为空。
pub(in crate::admin) fn latency(current: &Histogram, previous: Option<&Histogram>) -> Latency {
    let delta = previous
        .filter(|old| {
            old.bounds_ms == current.bounds_ms && old.buckets.len() == current.buckets.len()
        })
        .and_then(|old| {
            let buckets = current
                .buckets
                .iter()
                .zip(&old.buckets)
                .map(|(now, old)| now.checked_sub(*old))
                .collect::<Option<Vec<_>>>()?;
            let count = buckets
                .iter()
                .try_fold(0u64, |total, value| total.checked_add(*value))?;
            let sum = current.sum_micros.checked_sub(old.sum_micros)?;
            Some((buckets, count, sum))
        });
    let mut result = Latency {
        availability: "unknown",
        count: None,
        mean_ms: None,
        p50_ms: None,
        p95_ms: None,
        p99_ms: None,
        bounds_ms: current.bounds_ms.clone(),
        buckets: None,
    };
    if let Some((buckets, count, sum)) = delta {
        result.availability = if count == 0 {
            "no_samples"
        } else {
            "available"
        };
        result.count = Some(count);
        result.mean_ms = (count > 0).then(|| sum as f64 / count as f64 / 1000.0);
        result.p50_ms = quantile(&current.bounds_ms, &buckets, count, 50, 5);
        result.p95_ms = quantile(&current.bounds_ms, &buckets, count, 95, 20);
        result.p99_ms = quantile(&current.bounds_ms, &buckets, count, 99, 100);
        result.buckets = Some(buckets);
    }
    result
}

/// 业务作用：按区间非累计桶插值估算分位，同时保留低样本与无穷桶的不确定性。
///
/// 参数说明：
/// - `bounds`：有限毫秒上界。
/// - `buckets`：区间桶数，最后一项为溢出桶。
/// - `count`：同一组桶的样本总数。
/// - `percentile`：固定分位百分数。
/// - `minimum`：该分位的最少观测数。
///
/// 返回：有限桶内估算毫秒，样本不足或无法确定上界时返回None。
fn quantile(
    bounds: &[u64],
    buckets: &[u64],
    count: u64,
    percentile: u64,
    minimum: u64,
) -> Option<f64> {
    if count < minimum {
        return None;
    }
    let rank = count as f64 * percentile as f64 / 100.0;
    let mut before = 0u64;
    let mut lower = 0u64;
    for (&upper, &size) in bounds.iter().zip(buckets) {
        if size > 0 && before.saturating_add(size) as f64 >= rank {
            return Some(
                lower as f64 + (upper - lower) as f64 * (rank - before as f64) / size as f64,
            );
        }
        before = before.saturating_add(size);
        lower = upper;
    }
    None
}

/// 业务作用：对保留基线的实体容量进行保守计费，把容器节点和字符串容量计入总预算。
///
/// 参数说明：
/// - `sample`：已经通过有限协议校验的样本。
///
/// 返回：大于等于当前保留结构的估算字节数，用于接收槽与集群基线的独立容量门。
pub(in crate::admin) fn retained_bytes(sample: &Sample) -> usize {
    let mut bytes = std::mem::size_of::<Sample>()
        + 1024
        + sample.boot_id.capacity()
        + sample.state.mode.capacity()
        + sample
            .state
            .config_fingerprint
            .as_ref()
            .map_or(0, String::capacity)
        + sample.latency.bounds_ms.capacity() * 8
        + sample.latency.buckets.capacity() * 8
        + sample.readings.capacity() * std::mem::size_of::<Reading>();
    for reading in &sample.readings {
        bytes += reading.name.capacity();
        // 合法标签最多三项，共用一个树叶节点；节点只计费一次，字符串仍逐项计入实际容量。
        if !reading.labels.is_empty() {
            bytes += 1024;
        }
        for (key, value) in &reading.labels {
            bytes += key.capacity() + value.capacity();
        }
    }
    for key in sample.capabilities.keys() {
        bytes += 1024 + key.capacity();
    }
    bytes += sample
        .route_traffic
        .as_ref()
        .map_or(0, |routes| routes.retained_bytes());
    bytes
}
