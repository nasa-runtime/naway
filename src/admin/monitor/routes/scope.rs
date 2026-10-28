//! 工作区指标与目录必须来自同一节点配置，独立平台权限不能代替工作区证明。

use super::Node;
use crate::admin::catalog::Catalog;
use crate::admin::cluster::facts::Facts;

/// 业务作用：检查遥测与目录的同代身份及本域证明，目录缺席不能通过样本中的归属字符串补权。
///
/// 参数说明：
/// - `node`：当前集群观察轮次中的原生样本。
/// - `facts`：节点目录所绑定的当前成员事实。
/// - `catalog`：已经完整接收的低敏目录。
/// - `workspace`：当前主体获准读取的工作区。
/// - `authority`：本机冻结的成员、主体和角色权威摘要。
///
/// 返回：全部归属与读取证明匹配为available，否则给出固定原因，不输出任何行。
pub(super) fn verify(
    node: &Node,
    facts: &Facts,
    catalog: &Catalog,
    workspace: &str,
    authority: &[u8; 32],
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
        // 新目录与旧采样不允许拼接，尤其不能把旧工作区的累计值归给同名新对象。
        return "generation_mismatch";
    }
    if catalog.capacity {
        return "capacity";
    }
    if !catalog.scope_supported {
        return "unsupported";
    }
    if catalog
        .scopes
        .binary_search_by(|scope| scope.workspace.as_str().cmp(workspace))
        .ok()
        .is_none_or(|index| catalog.scopes[index].digest != *authority)
    {
        // 节点缺少同一读取授权时，既不能展示流量，也不能凭空证明对象不存在。
        return "authority_mismatch";
    }
    let Some(routes) = &sample.route_traffic else {
        return "unsupported";
    };
    for row in &routes.rows {
        let entry = catalog
            .entries
            .binary_search_by(|entry| entry.key().cmp(&("route", &row.proxy, &row.route)))
            .ok()
            .map(|index| &catalog.entries[index]);
        if entry.is_none_or(|entry| entry.workspace != row.workspace) {
            // 先核对完整路由身份再过滤本域，防止遗漏或错误归属被过滤操作掩盖。
            return "ownership_mismatch";
        }
    }
    if catalog
        .entries
        .iter()
        .filter(|entry| entry.kind == "route")
        .count()
        != routes.rows.len()
    {
        return "ownership_mismatch";
    }
    "available"
}
