//! 已构建快照的对象差异摘要。

use super::model::{Changes, Summary};
use crate::config::GatewaySnapshot;

/// 业务作用：生成两个已构建快照的稳定语义差异，并把两份独立规则文档的实际规则纳入影响面。
///
/// 参数说明：
/// - `current`：已经通过完整构建器的活动快照。
/// - `candidate`：已经通过完整构建器的候选快照。
///
/// 返回：各领域稳定排序的对象增删改摘要，只比较同代实际计划，不重新读取或编码原文。
pub(in crate::admin) fn compare(current: &GatewaySnapshot, candidate: &GatewaySnapshot) -> Summary {
    let (routes_added, routes_removed, routes_changed) = super::route::changes(current, candidate);
    let (upstreams_added, upstreams_removed, upstreams_changed) = current
        .upstreams
        .configuration_changes(&candidate.upstreams);
    let (listeners_added, listeners_removed, listeners_changed) =
        super::listener::changes(current, candidate);
    let (sentinel_added, sentinel_removed, sentinel_changed) =
        super::sentinel::changes(&current.sentinel_rules, &candidate.sentinel_rules);
    let (guard_added, guard_removed, guard_changed) = current
        .interface_guard
        .configuration_changes(&candidate.interface_guard);
    Summary {
        current_version: current.version,
        candidate_version: candidate.version,
        routes: Changes {
            added: routes_added,
            removed: routes_removed,
            changed: routes_changed,
        },
        upstreams: Changes {
            // 比较借用快照名称；结果必须独立于随后清理的候选，只在这个边界取得名称所有权。
            added: upstreams_added.into_iter().map(str::to_owned).collect(),
            removed: upstreams_removed.into_iter().map(str::to_owned).collect(),
            changed: upstreams_changed.into_iter().map(str::to_owned).collect(),
        },
        listeners: Changes {
            added: listeners_added,
            removed: listeners_removed,
            changed: listeners_changed,
        },
        sentinel: Changes {
            added: sentinel_added,
            removed: sentinel_removed,
            changed: sentinel_changed,
        },
        interface_guard: Changes {
            added: guard_added.into_iter().map(str::to_owned).collect(),
            removed: guard_removed.into_iter().map(str::to_owned).collect(),
            changed: guard_changed.into_iter().map(str::to_owned).collect(),
        },
    }
}
