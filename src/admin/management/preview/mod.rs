//! 原目标只读预览使用独立签名、有限构建和短期结果，不创建持久发布动作。

mod body;
mod client;
pub(in crate::admin) mod command;
mod node;
mod session;
mod wire;

pub(in crate::admin::management) use client::Channel;
#[cfg(feature = "admin-operations-workflow-pgsql")]
mod delivery;
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(in crate::admin::management) use delivery::Offer;
#[cfg(feature = "admin-operations-workflow-pgsql")]
mod run;
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(in crate::admin) use run::{inspect, recheck, Completed};

use crate::control::ownership::config::Action;
use crate::{
    config::GatewaySnapshot,
    control::actions::{authorization::Scope, domain::Domain},
};

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::admin) enum Reason {
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    Unsupported,
    Disabled,
    Unavailable,
    Capacity,
    Expired,
    Denied,
    BaselineChanged,
    CandidateInvalid,
}

/// 业务作用：对预览请求者验证实际领域的读取与构建权限，工作区不能继承平台授权。
///
/// 参数说明：
/// - `snapshot`：当前冻结的完整权限与归属配置。
/// - `scope`：原提案的平台或精确工作区键。
/// - `principal`：实际请求者的稳定身份。
/// - `domain`：原提案的配置文档领域。
///
/// 返回：主体仍具有读取及对应构建资格时为真；无主体、未知范围或只读工作区角色拒绝。
pub(in crate::admin) fn allows(
    snapshot: &GatewaySnapshot,
    scope: &str,
    principal: &str,
    domain: Domain,
) -> bool {
    let Some(authority) = Scope::parse(scope) else {
        return false;
    };
    if !authority.allows(snapshot, principal, domain, Action::Read) {
        return false;
    }
    if scope != "platform" {
        return authority.allows(snapshot, principal, domain, Action::Write);
    }
    snapshot
        .admin_auth
        .principals
        .iter()
        .find(|entry| entry.id.as_ref() == principal)
        .is_some_and(|entry| {
            entry.allows(
                domain.identity().1,
                crate::config::model::AdminAction::DryRun,
            )
        })
}
