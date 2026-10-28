//! 已构建快照的对象差异摘要。

use crate::config::GatewaySnapshot;

/// 业务作用：生成两个已构建快照的稳定语义差异，并把 Sentinel 独立文档的规则 id 纳入影响面。
///
/// 参数说明：
/// - `current`：已经通过完整构建器的活动快照。
/// - `candidate`：已经通过完整构建器的候选快照。
///
/// 返回：按字典序排列的对象增删改摘要，Sentinel 只比较同代实际规则，不重新读取原文。
pub(super) fn compare(current: &GatewaySnapshot, candidate: &GatewaySnapshot) -> serde_json::Value {
    let (routes_added, routes_removed, routes_changed) = super::route::changes(current, candidate);
    let (upstreams_added, upstreams_removed, upstreams_changed) = current
        .upstreams
        .configuration_changes(&candidate.upstreams);
    let (listeners_added, listeners_removed, listeners_changed) =
        super::listener::changes(current, candidate);
    let (sentinel_added, sentinel_removed, sentinel_changed) =
        super::sentinel::changes(&current.sentinel_rules, &candidate.sentinel_rules);
    serde_json::json!({
        "current_version": current.version,
        "candidate_version": candidate.version,
        "routes": {
            "added": routes_added,
            "removed": routes_removed,
            "changed": routes_changed
        },
        "upstreams": {
            "added": upstreams_added,
            "removed": upstreams_removed,
            "changed": upstreams_changed,
        },
        "listeners": {
            "added": listeners_added,
            "removed": listeners_removed,
            "changed": listeners_changed
        },
        "sentinel": {
            "added": sentinel_added,
            "removed": sentinel_removed,
            "changed": sentinel_changed
        },
    })
}
