//! 显式确认原摘要后创建执行，审计先于持久决定，未知结果只能按原身份回读。

use super::Context;
use crate::admin::{
    audit::{AdminAuditPayload, WorkspaceAudit},
    operations::{
        execution::authority::{self, Authority},
        model::{hex, Error},
        workflow::start::Request,
    },
};
use crate::control::ownership::config::Action;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    candidate_sha256: String,
}

/// 业务作用：以原提案和原摘要创建唯一执行，并将当前请求主体纳入持久审计与提交门。
///
/// 参数说明：
/// - context：冻结完整快照、认证主体、范围和共享存储。
/// - id：已经过规范路径检查的原提案。
/// - bytes：至多 256 字节的确认正文。
///
/// 返回：已提交创建或原身份重放；提交后审计或授权变化返回未知结果，禁止生成替代执行。
pub(in crate::admin::operations::api) async fn execute(
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
) -> Result<serde_json::Value, Error> {
    context.query.scope.check(
        context.snapshot,
        context.principal,
        context.query.domain,
        Action::Write,
    )?;
    authority::running(context.state, context.store, context.snapshot)?;
    let digest = confirmation(context.request, bytes)?;
    let record = context.store.read(&context.query.scope.key, id).await?;
    if record.domain != context.query.domain.identity().0 {
        return Err(Error::Missing);
    }
    if record.candidate_sha256 != hex(&digest) {
        return Err(Error::Conflict);
    }
    let workspace = context
        .query
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
                    candidate_sha256: record.candidate_sha256.clone(),
                    approved_by: record.reviewer.clone(),
                })
                .ok_or(Error::Denied)
        })
        .transpose()?;
    let mut audit = AdminAuditPayload {
        workspace,
        ts_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_millis(),
        principal: context.principal.to_owned(),
        method: context.request.method.to_string(),
        path: context.request.uri.path().to_owned(),
        resource: crate::admin::audit::resource_name(context.query.domain.identity().1).to_owned(),
        action: "write".to_owned(),
        phase: "attempt".to_owned(),
        status: None,
        query_sha256: context
            .request
            .uri
            .query()
            .map(|query| hex(&Sha256::digest(query.as_bytes()))),
        config_version: context.snapshot.version,
    };
    // 完整持久审计先于任何执行创建；取消等待不能截断已经开始的审计追加。
    persist_audit(context, audit.clone()).await?;
    let authority = Authority::new(context.state, Arc::clone(context.snapshot)).await;
    let authorize = |frozen: &crate::admin::operations::execution::frozen::Frozen, initial| {
        authority.check(context.store, frozen, initial, Some(context.principal))
    };
    let started = context
        .store
        .start_execution(
            &Request {
                id,
                scope: &context.query.scope.key,
                domain: context.query.domain,
                digest: &digest,
            },
            &authorize,
        )
        .await?;
    // 已提交决定不会因随后审计或请求快照失权而撤销；必须保留原身份并明确要求回读。
    authorize(&started.frozen, false).map_err(|_| Error::OutcomeUnknown)?;
    audit.phase = "completed".to_owned();
    audit.status = Some(200);
    audit.ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::OutcomeUnknown)?
        .as_millis();
    persist_audit(context, audit)
        .await
        .map_err(|_| Error::OutcomeUnknown)?;
    authorize(&started.frozen, false).map_err(|_| Error::OutcomeUnknown)?;
    Ok(serde_json::json!({
        "operation_id": id,
        "cluster_id": context.store.plan.config.cluster_id,
        "candidate_sha256": record.candidate_sha256,
        "created": started.created,
        "replayed": !started.created,
        "target_count": started.frozen.targets.len()
    }))
}

/// 业务作用：限制执行确认只携带原摘要，避免写入口接受新目标、正文或协议歧义。
///
/// 参数说明：
/// - request：实际请求头。
/// - bytes：有界确认原文。
///
/// 返回：规范 SHA-256；未知或重复字段、内容类型和非小写摘要均拒绝。
fn confirmation(request: &http::request::Parts, bytes: &[u8]) -> Result<[u8; 32], Error> {
    let mut types = request.headers.get_all(http::header::CONTENT_TYPE).iter();
    let content_type = types
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Invalid)?;
    if types.next().is_some()
        || !matches!(
            content_type,
            "application/json" | "application/json; charset=utf-8"
        )
        || bytes.len() > 256
    {
        return Err(Error::Invalid);
    }
    let confirmation: Confirmation = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let raw = confirmation.candidate_sha256.as_bytes();
    if raw.len() != 64
        || !raw
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::Invalid);
    }
    let mut digest = [0; 32];
    for (output, pair) in digest.iter_mut().zip(raw.chunks_exact(2)) {
        let value = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *output = (value(pair[0]) << 4) | value(pair[1]);
    }
    Ok(digest)
}

/// 业务作用：限制请求等待时间，同时沿用不会被请求取消截断的强制审计写入。
///
/// 参数说明：
/// - context：当前真实审计 owner 与请求权威。
/// - payload：仅含低敏操作身份的固定载荷。
///
/// 返回：审计明确持久后成功；超时或失败不会授权后续创建。
async fn persist_audit(context: &Context<'_>, payload: AdminAuditPayload) -> Result<(), Error> {
    tokio::time::timeout(
        Duration::from_secs(5),
        context.state.audit.record_required(payload),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)
}
