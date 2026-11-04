//! 材料持久入口只适配请求范围和错误，业务授权由共享控制域执行。

pub(super) use super::super::authorization::Scope;
use super::{model::Target, Error};
use crate::control::material::authorization;
use crate::{config::GatewaySnapshot, control::ownership::config::Action};

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
    authorization::check(&scope.key, snapshot, principal, action).ok_or(Error::Denied)
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
    authorization::targets(&scope.key, snapshot, targets).ok_or(Error::Denied)
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
    authorization::authority(&scope.key, snapshot, targets).ok_or(Error::Denied)
}
