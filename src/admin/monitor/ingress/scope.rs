//! 全局守卫规则不委派；工作区只读取同代接入入口的实际拒绝计数。

use super::Node;
use crate::admin::catalog::Catalog;
use crate::admin::cluster::facts::Facts;

/// 业务作用：以完整HTTP入口目录核验采样身份和本域读取权威，不能按全局计数分摊。
///
/// 参数说明：
/// - `node`：当前共享采样节点。
/// - `facts`：目录绑定的节点及启动、配置事实。
/// - `catalog`：完整接收的对象目录，不来自请求字段。
/// - `scope`：已获准读取的工作区和权限摘要，平台读取为None。
///
/// 返回：完整身份、清单与归属一致时为available；缺席或不一致撤下本节点所有入口事实。
pub(super) fn verify(
    node: &Node,
    facts: &Facts,
    catalog: &Catalog,
    scope: Option<(&str, &[u8; 32])>,
) -> &'static str {
    let Some(sample) = &node.sample else {
        return "unknown";
    };
    if facts.boot_id != sample.boot_id
        || facts.mode != sample.state.mode
        || facts.config_version != sample.state.config_version
        || facts.config_fingerprint != sample.state.config_fingerprint
        || catalog.version != sample.state.config_version
        || catalog.fingerprint.map(|value| format!("{value:016x}"))
            != sample.state.config_fingerprint
    {
        // 入口归属可随配置换代，旧采样不能使用新目录的工作区授权。
        return "generation_mismatch";
    }
    if catalog.capacity {
        return "capacity";
    }
    if let Some((workspace, authority)) = scope {
        if !catalog.scope_supported {
            return "unsupported";
        }
        if catalog
            .scopes
            .binary_search_by(|value| value.workspace.as_str().cmp(workspace))
            .ok()
            .is_none_or(|index| catalog.scopes[index].digest != *authority)
        {
            // 当前成员和主体角色未获该节点确认时，不用平台权限补授本域事实。
            return "authority_mismatch";
        }
    }
    let Some(ingress) = &sample.ingress_protection else {
        return "unsupported";
    };
    if ingress.capacity {
        return "capacity";
    }
    for row in &ingress.rows {
        let entry = catalog
            .entries
            .binary_search_by(|entry| entry.key().cmp(&("listener", "", row.listener.as_str())))
            .ok()
            .map(|index| &catalog.entries[index]);
        if entry.is_none_or(|entry| entry.workspace != row.workspace) {
            // 完整清单先核验再过滤，错误归属不能藏在其它工作区的行中。
            return "ownership_mismatch";
        }
    }
    if catalog
        .entries
        .iter()
        .filter(|entry| entry.kind == "listener")
        .count()
        != ingress.rows.len()
    {
        return "ownership_mismatch";
    }
    "available"
}
