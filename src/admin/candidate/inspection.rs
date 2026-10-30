//! 同一冻结基线的归档读取、候选构建和有限管理比较。

use super::{load_documents, workspace::Workspace, BuildError};
use crate::{admin::AdminState, config::GatewaySnapshot};
use bytes::Bytes;
use std::sync::Arc;

pub(in crate::admin) enum DocumentKind {
    Gateway,
    Sentinel,
    InterfaceGuard,
}

/// 业务作用：让归档、完整候选和比较共用一个真实工作许可，避免异步等待混合基线或取消后遗留正文。
///
/// 参数说明：
/// - `state`：提供统一候选容量、归档与真实部署根。
/// - `active`：请求冻结且结束前仍须复验的活动快照。
/// - `kind`：完整三文档中唯一替换的文档类型。
/// - `body`：有界且已确认 UTF-8 的候选原文，转交工作单元持有。
/// - `inspect`：只读取两个已构建快照的比较，不发布配置或取得新的文件写权。
///
/// 返回：比较完成且工作区清理成功的结果；归档缺失、容量不足或构建失败不修改活动配置。
pub(in crate::admin) async fn inspect_archived<T: Send + 'static>(
    state: &AdminState,
    active: Arc<GatewaySnapshot>,
    kind: DocumentKind,
    body: Bytes,
    inspect: impl FnOnce(&GatewaySnapshot, &GatewaySnapshot) -> T + Send + 'static,
) -> Result<T, BuildError> {
    inspect_guarded(
        state,
        active,
        kind,
        body,
        (),
        |_, _, _| Ok(()),
        move |_, current, candidate| inspect(current, candidate),
    )
    .await
}

/// 业务作用：使目标预览的权限 owner、原文范围检查、完整比较与真实清理属于同一个候选工作单元。
///
/// 参数说明：
/// - `state`：提供统一候选容量、版本归档与部署根。
/// - `active`：本次构建唯一冻结的原活动快照。
/// - `kind`：唯一替换的配置文档领域。
/// - `body`：已获权的有界原始候选。
/// - `owner`：必须保留到工作区清理结束的权限与容量 owner。
/// - `validate`：在任何候选依赖读取前验证原文基线与允许变更范围。
/// - `inspect`：完成构建后从实际快照生成有限只读结果。
///
/// 返回：构建、比较和清理全部完成后的结果；等待者取消不提前释放 owner 或真实构建许可。
pub(in crate::admin) async fn inspect_guarded<C: Send + 'static, T: Send + 'static>(
    state: &AdminState,
    active: Arc<GatewaySnapshot>,
    kind: DocumentKind,
    body: Bytes,
    owner: C,
    validate: impl FnOnce(&C, &crate::control::history::ArchivedDocs, &[u8]) -> Result<(), BuildError>
        + Send
        + 'static,
    inspect: impl FnOnce(&C, &GatewaySnapshot, &GatewaySnapshot) -> T + Send + 'static,
) -> Result<T, BuildError> {
    let permit = state.candidate_builds.acquire()?;
    let version = active.version.checked_add(1).ok_or(BuildError::Exhausted)?;
    let history = state.config_history.clone();
    let real = state.cfg_path.clone();
    permit
        .spawn(move |permit| {
            // 归档由冻结版本选择；缺失时不能回退到可能尚未发布的当前磁盘文件。
            let mut docs = history
                .read_archived(active.version)
                .map_err(|_| BuildError::Baseline)?;
            // 原文范围必须先于候选依赖加载成立；不能构建越权文档后再尝试隐藏其结果。
            validate(&owner, &docs, &body)?;
            let text = String::from_utf8(Vec::from(body))
                .map_err(|_| BuildError::Invalid("candidate must be UTF-8".into()))?;
            match kind {
                DocumentKind::Gateway => docs.gateway = text,
                DocumentKind::Sentinel => docs.sentinel_rules = text,
                DocumentKind::InterfaceGuard => docs.interface_guard = text,
            }
            Workspace::validate(&docs).map_err(|error| BuildError::Invalid(error.to_string()))?;
            let mut workspace =
                Workspace::create(&real, permit).map_err(|_| BuildError::Workspace)?;
            workspace.write(&docs).map_err(|_| BuildError::Workspace)?;
            let built = load_documents(&real, workspace.documents(), version, &active, &history);
            let inspected = built.map(|candidate| inspect(&owner, &active, &candidate));
            // 即使候选构建失败也先完成真实清理；清理未确认会关闭该容量域，不继续积累候选原文。
            workspace.cleanup().map_err(|_| BuildError::Workspace)?;
            drop(owner);
            inspected.map_err(|error| BuildError::Invalid(error.to_string()))
        })
        .await
        .map_err(|_| BuildError::Worker)?
}
