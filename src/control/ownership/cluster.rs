//! 工作区集群读取绑定成员与主体权威，不把本机对象分布混入权限证明。

use super::{config::Role, WorkspaceCfg};
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// 业务作用：编译各工作区的节点读取范围及权限摘要，分布不同不能被误认为权限一致或相反。
///
/// 参数说明：
/// - `workspaces`：已经通过主体、归属和配额验证的工作区声明。
///
/// 返回：每工作区固定摘要；重复、超量或非法节点身份拒绝整个候选。
pub(super) fn compile(
    workspaces: &BTreeMap<String, WorkspaceCfg>,
) -> Result<BTreeMap<String, [u8; 32]>> {
    let mut result = BTreeMap::new();
    for (id, scope) in workspaces {
        ensure!(
            scope.cluster_nodes.len() <= 128,
            "workspace cluster node capacity exceeded"
        );
        let nodes: BTreeSet<_> = scope.cluster_nodes.iter().collect();
        ensure!(
            nodes.len() == scope.cluster_nodes.len(),
            "workspace cluster node identities must be unique"
        );
        for node in &nodes {
            super::token(node)?;
        }
        let mut hash = Sha256::new();
        hash.update(b"naway-workspace-read\0");
        for value in [id, &scope.tenant, &scope.environment] {
            field(&mut hash, value);
        }
        hash.update((scope.members.len() as u64).to_be_bytes());
        for (principal, role) in &scope.members {
            field(&mut hash, principal);
            hash.update([match role {
                Role::Viewer => 0,
                Role::Operator => 1,
                Role::Administrator => 2,
            }]);
        }
        hash.update((nodes.len() as u64).to_be_bytes());
        for node in nodes {
            field(&mut hash, node);
        }
        result.insert(id.clone(), hash.finalize().into());
    }
    Ok(result)
}

/// 业务作用：使身份字段按长度分隔进入摘要，避免不同分段组合得到相同权限输入。
///
/// 参数说明：
/// - `hash`：本工作区的增量摘要状态。
/// - `text`：已验证的身份值。
///
/// 返回：原地更新摘要，不分配或序列化配置。
fn field(hash: &mut Sha256, text: &str) {
    hash.update((text.len() as u64).to_be_bytes());
    hash.update(text.as_bytes());
}
