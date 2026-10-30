//! 服务事实必须与完整目录和当前成员配置同代，工作区字符串本身不能授予读取权。

use crate::admin::catalog::Catalog;
use crate::admin::cluster::facts::Facts;
use crate::admin::monitor::model::Sample;

/// 业务作用：核对全部服务身份的同代归属，并在工作区读取时复验成员与主体权威。
///
/// 参数说明：
/// - `sample`：当前成员的完整原生样本。
/// - `facts`：当前成员事实，不能用旧目录代替。
/// - `catalog`：该节点完整接收的低敏目录。
/// - `scope`：已获准读取的工作区与当前权威摘要，平台读取为 None。
///
/// 返回：全部匹配为 available；任何缺口撤下此节点的服务事实。
pub(super) fn verify(
    sample: &Sample,
    facts: &Facts,
    catalog: &Catalog,
    scope: Option<(&str, &[u8; 32])>,
) -> &'static str {
    if facts.boot_id != sample.boot_id
        || facts.mode != sample.state.mode
        || facts.config_version != sample.state.config_version
        || facts.config_fingerprint != sample.state.config_fingerprint
        || catalog.version != sample.state.config_version
        || catalog.fingerprint.map(|value| format!("{value:016x}"))
            != sample.state.config_fingerprint
    {
        // 目录与采样跨越配置发布后，同名对象可能已换归属，不能拼接旧实例事实。
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
            .binary_search_by(|scope| scope.workspace.as_str().cmp(workspace))
            .ok()
            .is_none_or(|index| catalog.scopes[index].digest != *authority)
        {
            // 远端没有同一成员和读取授权时，不能以本机平台权补授工作区访问。
            return "authority_mismatch";
        }
    }
    let Some(services) = &sample.service_state else {
        return "unsupported";
    };
    if services.capacity {
        return "capacity";
    }
    for row in &services.rows {
        let entry = catalog
            .entries
            .binary_search_by(|entry| entry.key().cmp(&("upstream", "", &row.service)))
            .ok()
            .map(|index| &catalog.entries[index]);
        if entry.is_none_or(|entry| entry.workspace != row.workspace) {
            // 全量身份核对先于域过滤，避免错误归属被过滤操作隐藏。
            return "ownership_mismatch";
        }
    }
    if catalog
        .entries
        .iter()
        .filter(|entry| entry.kind == "upstream")
        .count()
        != services.rows.len()
    {
        return "ownership_mismatch";
    }
    "available"
}
