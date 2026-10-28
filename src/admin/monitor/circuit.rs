//! 节点本地熔断执行状态摘要，缺少状态事实时保留覆盖边界。

use super::model::Point;
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct View {
    availability: &'static str,
    closed: Option<f64>,
    open: Option<f64>,
    half_open: Option<f64>,
    active_calls: Option<f64>,
}

/// 业务作用：从真实执行状态的固定瞬时量建立集群或本机保护摘要，不推算配置规则数量。
///
/// 参数说明：
/// - `points`：已校验成员覆盖的本轮指标。
///
/// 返回：可用节点的状态实例数量与活动许可；旧节点缺少系列或失联时明确部分或未知。
pub(super) fn view(points: &[Point<'_>]) -> View {
    let find = |state: Option<&str>| {
        points.iter().find(|point| match state {
            Some(state) => {
                point.name == "gw_circuit_state_instances"
                    && point.labels.len() == 1
                    && point
                        .labels
                        .get("state")
                        .is_some_and(|value| value == state)
            }
            None => point.name == "gw_circuit_active_calls" && point.labels.is_empty(),
        })
    };
    let selected = [
        find(Some("closed")),
        find(Some("open")),
        find(Some("half_open")),
        find(None),
    ];
    // 状态读面只需要当前瞬时量；不能因累计迁移尚无差值基线而掩盖正在生效的保护。
    let complete = selected.iter().all(|point| {
        point.is_some_and(|point| point.availability == "available" && point.current.is_some())
    });
    let current = |index: usize| selected[index].and_then(|point| point.current);
    View {
        availability: if complete {
            "available"
        } else if selected
            .iter()
            .any(|point| point.is_some_and(|point| point.current.is_some()))
        {
            "partial"
        } else {
            "unknown"
        },
        closed: current(0),
        open: current(1),
        half_open: current(2),
        active_calls: current(3),
    }
}
