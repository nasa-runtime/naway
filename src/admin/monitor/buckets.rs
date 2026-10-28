//! 当前限流桶按节点实例聚合，缺席或共享后端不冒充完整的本地桶计数。

use super::model::Point;
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct View {
    availability: &'static str,
    local_nodes: Option<f64>,
    shared_nodes: Option<f64>,
    preallocated_nodes: Option<f64>,
    unsupported_nodes: Option<f64>,
    busy_nodes: Option<f64>,
    capacity_nodes: Option<f64>,
    unavailable_nodes: Option<f64>,
    total: Option<f64>,
    steady: Option<f64>,
    cold: Option<f64>,
    warming: Option<f64>,
    warm: Option<f64>,
    expired: Option<f64>,
}

/// 业务作用：按本轮完整状态事实输出本地桶摘要，保留异构后端和失联造成的覆盖边界。
///
/// 参数说明：
/// - points：同一轮经过节点覆盖计算的瞬时指标。
///
/// 返回：本地节点的互斥桶分类及各观测状态节点数；未知、矛盾或非本地后端不输出桶数。
pub(super) fn view(points: &[Point<'_>]) -> View {
    let find = |name: &str, label: &str, value: &str| {
        points.iter().find(|point| {
            point.name == name
                && point.kind == "gauge"
                && point.labels.len() == 1
                && point.labels.get(label).is_some_and(|item| item == value)
        })
    };
    let statuses = [
        "local",
        "shared",
        "preallocated",
        "unsupported",
        "busy",
        "capacity",
        "unavailable",
    ]
    .map(|status| find("gw_rate_bucket_observation", "status", status));
    let buckets = ["total", "steady", "cold", "warming", "warm", "expired"]
        .map(|state| find("gw_rate_local_buckets", "state", state));
    let value = |point: Option<&Point<'_>>| {
        point
            .and_then(|point| point.current)
            .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
    };
    let status = statuses.map(value);
    let counts = buckets.map(value);
    // 缺少本地 owner 或互斥分类不能闭合时，零值和旧桶数都不能作为当前业务事实。
    let observed = status[0].is_some_and(|nodes| nodes > 0.0)
        && counts.iter().all(Option::is_some)
        && counts[0] == Some(counts[1..].iter().flatten().sum());
    let complete = observed
        && statuses
            .iter()
            .chain(&buckets)
            .all(|point| point.is_some_and(|point| point.availability == "available"))
        && status[1..].iter().all(|value| *value == Some(0.0));
    let count = |index: usize| observed.then_some(counts[index]).flatten();
    View {
        availability: if complete {
            "available"
        } else if observed {
            "partial"
        } else if status.iter().flatten().any(|nodes| *nodes > 0.0) {
            "unavailable"
        } else {
            "unknown"
        },
        local_nodes: status[0],
        shared_nodes: status[1],
        preallocated_nodes: status[2],
        unsupported_nodes: status[3],
        busy_nodes: status[4],
        capacity_nodes: status[5],
        unavailable_nodes: status[6],
        total: count(0),
        steady: count(1),
        cold: count(2),
        warming: count(3),
        warm: count(4),
        expired: count(5),
    }
}
