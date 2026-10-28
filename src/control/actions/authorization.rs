//! 提案和目标执行共用当前主体与工作区授权，不以命令中的身份声明授予权限。

use super::domain::Domain;
use crate::{
    config::{model::AdminAction, GatewaySnapshot},
    control::ownership::config::Action,
};
#[cfg(feature = "admin-operations-pgsql")]
use sha2::{Digest, Sha256};

/// 借用原始权限域，平台与工作区键不能相互冒充。
pub(crate) struct Scope<'a> {
    #[cfg(feature = "admin-operations-pgsql")]
    key: &'a str,
    workspace: Option<&'a str>,
}

impl<'a> Scope<'a> {
    /// 业务作用：解释持久意图的唯一 scope，严格复用既有工作区标识边界，不分配新的键。
    ///
    /// 参数说明：
    /// - `key`：平台或带固定前缀的工作区标识。
    ///
    /// 返回：精确合法范围的借用；未知前缀、空工作区、超限或非法字符返回空。
    pub(crate) fn parse(key: &'a str) -> Option<Self> {
        let workspace = if key == "platform" {
            None
        } else {
            let value = key.strip_prefix("workspace.")?;
            if !crate::config::operations::token(value, 118) {
                return None;
            }
            Some(value)
        };
        Some(Self {
            #[cfg(feature = "admin-operations-pgsql")]
            key,
            workspace,
        })
    }

    /// 业务作用：按实际领域和风险动作验证当前主体，工作区授权不能继承平台权限或另一工作区角色。
    ///
    /// 参数说明：
    /// - `snapshot`：当前完整认证及归属快照。
    /// - `principal`：已认证调用者或已签名意图中的稳定主体，仍必须存在于本机目录。
    /// - `domain`：被操作的真实配置领域。
    /// - `action`：读取、写入或审阅的明确业务动作。
    ///
    /// 返回：主体存在且拥有当前精确范围的权限才为真；不依赖浏览器凭据相同或数据库连接。
    pub(crate) fn allows(
        &self,
        snapshot: &GatewaySnapshot,
        principal: &str,
        domain: Domain,
        action: Action,
    ) -> bool {
        let Some(identity) = snapshot
            .admin_auth
            .principals
            .iter()
            .find(|entry| entry.id.as_ref() == principal)
        else {
            return false;
        };
        match self.workspace {
            Some(workspace) => {
                snapshot.ownership.enabled()
                    && snapshot.ownership.allows(principal, workspace, action)
            }
            None => identity.allows(
                domain.identity().1,
                if action == Action::Read {
                    AdminAction::Read
                } else {
                    AdminAction::Write
                },
            ),
        }
    }

    /// 业务作用：冻结与监听地址无关的审批权威，同配置的多个 Admin 必须得到相同摘要。
    ///
    /// 参数说明：
    /// - `snapshot`：创建或审阅时的已发布主体与工作区目录。
    ///
    /// 返回：保持排序、长度分帧和原始凭据贡献的摘要；缺失工作区返回空，秘密不进入输出字段。
    #[cfg(feature = "admin-operations-pgsql")]
    pub(crate) fn authority(&self, snapshot: &GatewaySnapshot) -> Option<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(b"naway-operation-proposal-authority\0");
        field(&mut digest, self.key.as_bytes());
        let mut principals: Vec<_> = snapshot.admin_auth.principals.iter().collect();
        principals.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        for principal in principals {
            field(&mut digest, principal.id.as_bytes());
            field(&mut digest, &principal.permission_bits().to_be_bytes());
            field(
                &mut digest,
                principal.bearer_token.as_deref().unwrap_or_default(),
            );
            field(
                &mut digest,
                principal.basic_expected.as_deref().unwrap_or_default(),
            );
        }
        if let Some(workspace) = self.workspace {
            let binding = snapshot.ownership.binding(workspace)?;
            for value in [
                &binding.owner.workspace,
                &binding.owner.tenant,
                &binding.owner.environment,
                &binding.authority_digest,
            ] {
                field(&mut digest, value.as_bytes());
            }
        }
        Some(digest.finalize().into())
    }
}

/// 业务作用：为权限摘要固定字段边界，凭据或身份分段不能因直接拼接产生歧义。
///
/// 参数说明：
/// - `digest`：同一权限域的增量摘要。
/// - `bytes`：当前字段的借用原字节。
///
/// 返回：只推进摘要，不复制或输出凭据。
#[cfg(feature = "admin-operations-pgsql")]
fn field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
