//! 材料权限独立于三文档提案，精确归属和当前主体必须同时成立。

pub(super) use super::super::authorization::Scope;
use super::{model::Target, Error};
use crate::{
    config::{
        model::{AdminAction, AdminResource},
        GatewaySnapshot,
    },
    control::ownership::config::Action,
};
use sha2::{Digest, Sha256};

/// 业务作用：按当前身份和独立材料权限授权，工作区成员不能通过平台或其它工作区读写材料。
///
/// 参数说明：
/// - `scope`：请求选定的唯一域。
/// - `snapshot`：当前完整认证与对象归属目录。
/// - `principal`：真实已认证主体或原创建者。
/// - `action`：明确读取、提交或审阅动作。
///
/// 返回：平台具备独立提案权限，或工作区当前成员具有该动作权限时成功。
pub(super) fn check(
    scope: &Scope,
    snapshot: &GatewaySnapshot,
    principal: &str,
    action: Action,
) -> Result<(), Error> {
    let identity = snapshot
        .admin_auth
        .principals
        .iter()
        .find(|entry| entry.id.as_ref() == principal)
        .ok_or(Error::Denied)?;
    let permission = if action == Action::Read {
        AdminAction::Read
    } else {
        AdminAction::Write
    };
    // 工作区身份不持有平台 grant，只能经当前成员动作及后续完整目标归属门取得受限权威。
    let allowed = if let Some(workspace) = &scope.workspace {
        snapshot.ownership.enabled() && snapshot.ownership.allows(principal, workspace, action)
    } else {
        identity.allows(AdminResource::CertificateProposals, permission)
            && identity.allows(AdminResource::Certs, permission)
            && identity.allows(AdminResource::Cluster, permission)
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::Denied)
    }
}

/// 业务作用：将冻结目标限定在当前精确材料对象归属中，工作区不得接管未归属或另一工作区的身份。
///
/// 参数说明：
/// - `scope`：已经通过成员动作检查的域。
/// - `snapshot`：当前归属图。
/// - `targets`：提案的全部原目标，不按在线情况采样。
///
/// 返回：工作区所有目标均精确归属才成功；平台保留全局管理资格。
pub(super) fn targets(
    scope: &Scope,
    snapshot: &GatewaySnapshot,
    targets: &[Target],
) -> Result<(), Error> {
    let Some(workspace) = &scope.workspace else {
        return Ok(());
    };
    let binding = snapshot.ownership.binding(workspace).ok_or(Error::Denied)?;
    let (membership, _) = snapshot
        .ownership
        .cluster_scope(workspace)
        .ok_or(Error::Denied)?;
    for target in targets {
        let key = object_key(target);
        // 当前节点分母与材料对象归属必须一起成立，监听器同名不能授予另一个节点或租户的写权。
        if !membership
            .cluster_nodes
            .iter()
            .any(|node| node == &target.node_id)
            || snapshot.ownership.object_owner(&key) != Some(&binding.owner)
        {
            return Err(Error::Denied);
        }
    }
    Ok(())
}

/// 业务作用：在独立材料域冻结权限和每个目标的当前归属，同配置 Admin 可交叉审阅，归属变更使旧批准失效。
///
/// 参数说明：
/// - `scope`：固定平台或工作区身份。
/// - `snapshot`：当前权限与归属快照。
/// - `targets`：已经排序并通过归属门的全部目标。
///
/// 返回：带域分隔和长度帧的摘要，不包含可读凭据。
pub(super) fn authority(
    scope: &Scope,
    snapshot: &GatewaySnapshot,
    targets: &[Target],
) -> Result<[u8; 32], Error> {
    let base = crate::control::actions::authorization::Scope::parse(&scope.key)
        .and_then(|value| value.authority_through(snapshot, AdminResource::CertificateProposals))
        .ok_or(Error::Denied)?;
    let mut hash = Sha256::new();
    hash.update(b"naway-certificate-proposal-authority\0");
    hash.update(base);
    for target in targets {
        let key = object_key(target);
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key.as_bytes());
        if let Some(owner) = snapshot.ownership.object_owner(&key) {
            hash.update([1]);
            for field in [&owner.workspace, &owner.tenant, &owner.environment] {
                hash.update((field.len() as u64).to_be_bytes());
                hash.update(field.as_bytes());
            }
        } else {
            hash.update([0]);
        }
    }
    Ok(hash.finalize().into())
}

/// 业务作用：使用证书目录相同的对象命名空间，HTTP 与 TCP 同名入口不能混用归属。
///
/// 参数说明：
/// - `target`：已验证的逻辑材料目标。
///
/// 返回：归属目录中的唯一证书对象键。
fn object_key(target: &Target) -> String {
    let kind = match target.target.kind {
        crate::tls::targets::Kind::Proxy => "certificate",
        crate::tls::targets::Kind::Stream => "stream_certificate",
    };
    format!("{kind}:{}", target.target.listener)
}
