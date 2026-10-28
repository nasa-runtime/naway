//! 集群原文复用本机 bootstrap 和工作区边界，远程签名不能扩大配置写入范围。

use crate::{
    admin::management::actions::Work,
    config::{candidate::Documents, GatewaySnapshot},
    control::actions::domain::Domain,
};
use anyhow::{ensure, Result};
use std::path::Path;

/// 业务作用：在工作区候选进入完整构建前检查原始声明范围，拒绝未委派字段和跨租户正文。
///
/// 参数说明：
/// - `work`：已验签且当前写入权限仍有效的工作。
/// - `bytes`：原命令唯一领域的完整原文。
///
/// 返回：平台范围或经原对象动作证明的工作区主配置成功；全局规则、错误基线或越权变化拒绝。
pub(super) fn require_scope(work: &Work, bytes: &[u8]) -> Result<()> {
    let command = work.command();
    let Some(workspace) = command.intent.scope.strip_prefix("workspace.") else {
        ensure!(
            command.intent.scope == "platform",
            "node action scope differs"
        );
        return Ok(());
    };
    // 当前两份规则属于不可委派的平台资源，工作区角色不能通过完整文件替换间接修改它们。
    ensure!(
        command.intent.domain == Domain::Gateway,
        "global node rules require platform authority"
    );
    let active = work.active();
    let limit = crate::config::document::MAX_DOCUMENT_BYTES;
    let original = crate::io::bounded_io::read_file(
        &active.source_config_path,
        limit,
        "node workspace baseline",
    )?;
    ensure!(
        active
            .document_identity
            .as_ref()
            .is_some_and(|identity| identity.matches_gateway(&original)),
        "node workspace baseline identity changed"
    );
    let baseline = crate::config::document::parse(&original, limit)?;
    let candidate = crate::config::document::parse(bytes, command.intent.candidate_bytes as usize)?;
    active
        .ownership
        .validate_replacement(baseline, candidate, &command.intent.creator, workspace)
}

/// 业务作用：让节点原文重建沿用远程配置的本机权威保护，阻止签名业务候选改变发行者或持久后端。
///
/// 参数说明：
/// - `real`：真实部署根。
/// - `documents`：本次隔离原文集合。
/// - `version`：候选版本。
/// - `active`：原活动实例的当前本机权威。
/// - `history`：已经持文件事务的永久节点验证入口。
///
/// 返回：完整且未越过本机权威的候选；任何改变拒绝，不发布资源或重新编码原文。
pub(super) fn load(
    real: &Path,
    documents: Documents<'_>,
    version: u64,
    active: &GatewaySnapshot,
    history: &crate::control::history::ConfigHistory,
) -> Result<GatewaySnapshot> {
    let built = super::load_documents(real, documents, version, active, history)?;
    ensure!(
        crate::control::reload::remote_bootstrap_change(active, &built).is_none(),
        "node candidate changes local bootstrap authority"
    );
    Ok(built)
}
