//! 材料任务审计仅记录请求身份与公开影响摘要，不记录候选或秘密派生摘要。

use crate::admin::{
    audit::{AdminAuditPayload, WorkspaceAudit},
    operations::{
        certificates::preview::Context,
        model::{hex, Error},
    },
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 业务作用：为原完整影响执行建立必要审计，工作区仍绑定当前精确归属。
///
/// 参数说明：
/// - `context`：真实请求、范围与活动配置。
/// - `impact`：公开完整影响摘要，不能传入候选材料摘要。
///
/// 返回：低敏尝试事件；缺少当前工作区绑定时拒绝创建。
pub(super) fn attempt(context: &Context<'_>, impact: &str) -> Result<AdminAuditPayload, Error> {
    let workspace = context
        .scope
        .workspace
        .as_deref()
        .map(|workspace| {
            context
                .snapshot
                .ownership
                .binding(workspace)
                .map(|binding| WorkspaceAudit {
                    binding,
                    candidate_sha256: impact.into(),
                    approved_by: None,
                })
                .ok_or(Error::Denied)
        })
        .transpose()?;
    Ok(AdminAuditPayload {
        workspace,
        ts_ms: now()?,
        principal: context.principal.into(),
        method: context.request.method.to_string(),
        path: context.request.uri.path().into(),
        resource: "certificate-proposals".into(),
        action: "write".into(),
        phase: "attempt".into(),
        status: None,
        query_sha256: context
            .request
            .uri
            .query()
            .map(|query| hex(&Sha256::digest(query.as_bytes()))),
        config_version: context.snapshot.version,
    })
}

/// 业务作用：为实际审计取得当前绝对时刻，系统时钟异常时不伪造完成时间。
///
/// 参数说明: 无。
///
/// 返回：当前Unix毫秒；时钟早于纪元时拒绝。
pub(super) fn now() -> Result<u128, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis())
        .map_err(|_| Error::Unavailable)
}

/// 业务作用：使用实际持久审计owner并限制等待，超时不能成为继续任务创建的许可。
///
/// 参数说明：
/// - `context`：原管理请求所绑定的审计资源。
/// - `payload`：完整低敏事件。
///
/// 返回：审计明确同步后成功；超时或写入失败拒绝下一业务动作。
pub(super) async fn persist(
    context: &Context<'_>,
    payload: AdminAuditPayload,
) -> Result<(), Error> {
    tokio::time::timeout(
        Duration::from_secs(5),
        context.state.audit.record_required(payload),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)
}
