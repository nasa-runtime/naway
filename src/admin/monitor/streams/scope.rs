//! 完整监听器清单与同代采样共同证明对象归属，工作区字符串本身不授予读取权。

use super::Node;
use crate::admin::catalog::Catalog;
use crate::admin::cluster::facts::Facts;

/// 业务作用：在过滤任何工作区行之前验证完整监听器目录、配置代与独立读取权威。
///
/// 参数说明：
/// - `node`：本轮唯一原生样本与区间。
/// - `facts`：完整目录绑定的当前节点事实。
/// - `catalog`：同一成员完整接收的对象及监听器目录。
/// - `scope`：已获准读取的工作区与成员角色摘要，平台读取为 None。
///
/// 返回：全部身份、协议、归属与权限一致时为 available；任何缺口撤下该节点全部监听器事实。
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
        // 同名监听器可以在热更时转移归属，旧采样不能与新目录拼接。
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
            // 节点未确认相同成员和主体角色时，平台读取权不能补授本域流量。
            return "authority_mismatch";
        }
    }
    let (Some(directory), Some(streams)) = (&catalog.streams, &sample.stream_traffic) else {
        return "unsupported";
    };
    if directory.capacity || streams.capacity {
        return "capacity";
    }
    for row in &streams.rows {
        let expected = match row.protocol.as_str() {
            "tcp" => 0,
            "udp" => 1,
            _ => return "ownership_mismatch",
        };
        let entry = directory
            .entries
            .binary_search_by(|entry| {
                entry
                    .key()
                    .cmp(&("stream_listener", "", row.listener.as_str()))
            })
            .ok()
            .map(|index| &directory.entries[index]);
        if entry.is_none_or(|entry| entry.workspace != row.workspace || entry.flags != expected) {
            // 先验证全量映射再执行本域筛选，不能把错误归属隐藏在过滤之外。
            return "ownership_mismatch";
        }
    }
    if directory.entries.len() != streams.rows.len() {
        return "ownership_mismatch";
    }
    "available"
}
