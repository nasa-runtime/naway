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
            let inspected = built.map(|candidate| inspect(&active, &candidate));
            // 即使候选构建失败也先完成真实清理；清理未确认会关闭该容量域，不继续积累候选原文。
            workspace.cleanup().map_err(|_| BuildError::Workspace)?;
            inspected.map_err(|error| BuildError::Invalid(error.to_string()))
        })
        .await
        .map_err(|_| BuildError::Worker)?
}
