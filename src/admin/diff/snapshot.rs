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
    let route_index = |snapshot: &GatewaySnapshot| {
        let mut routes = std::collections::BTreeMap::new();
        for proxy in snapshot.proxies.iter() {
            for route in proxy.router.routes() {
                routes.insert(
                    format!("{}/{}", proxy.id, route.id),
                    route.admin_semantic_json(),
                );
            }
        }
        routes
    };
    let current_routes = route_index(current);
    let candidate_routes = route_index(candidate);
    let (routes_added, routes_removed, routes_changed) =
        map_semantic_changes(&current_routes, &candidate_routes);
    let current_upstreams = current
        .upstreams
        .service_names()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let candidate_upstreams = candidate
        .upstreams
        .service_names()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let listener_index = |snapshot: &GatewaySnapshot| {
        snapshot
            .listen_topology()
            .into_iter()
            .map(|listener| {
                (
                    listener.id,
                    serde_json::json!({
                        "listen": listener.listen,
                        "plain": listener.plain_enabled,
                        "tls": listener.tls.is_some(),
                        "http3": listener.http3.enabled,
                    }),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let (listeners_added, listeners_removed, listeners_changed) =
        map_semantic_changes(&listener_index(current), &listener_index(candidate));
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
            "added": candidate_upstreams.difference(&current_upstreams).cloned().collect::<Vec<_>>(),
            "removed": current_upstreams.difference(&candidate_upstreams).cloned().collect::<Vec<_>>(),
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

/// 业务作用：对两个以稳定业务 id 索引的 JSON 计划计算增删改集。
///
/// 参数说明：
/// - `current`：的 key 是业务身份，value 是不含密钥的规范语义。
/// - `candidate`：的 key 是业务身份，value 是不含密钥的规范语义。
///
/// 返回：分别返回字典序的 added、removed 和 value 不同的 changed id。
fn map_semantic_changes(
    current: &std::collections::BTreeMap<String, serde_json::Value>,
    candidate: &std::collections::BTreeMap<String, serde_json::Value>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let added = candidate
        .keys()
        .filter(|key| !current.contains_key(*key))
        .cloned()
        .collect();
    let removed = current
        .keys()
        .filter(|key| !candidate.contains_key(*key))
        .cloned()
        .collect();
    let changed = current
        .iter()
        .filter_map(|(key, value)| {
            candidate
                .get(key)
                .filter(|candidate| *candidate != value)
                .map(|_| key.clone())
        })
        .collect();
    (added, removed, changed)
}
