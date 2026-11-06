//! 执行只接受原完整影响的明确确认，原任务身份提供跨Admin重放与一致查询。

mod audit;

use super::{
    authority::{self, Authority},
    frozen::Frozen,
    view,
};
use crate::{
    admin::{
        self,
        operations::{
            certificates::{
                authorization,
                preview::{self, Context},
            },
            model::{hex, Error},
        },
        BoxBody,
    },
    control::ownership::config::Action,
};
use http::{Method, Response};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    impact_id: String,
    impact_sha256: String,
}

#[derive(Serialize)]
struct Started<'a> {
    cluster_id: &'a str,
    scope: &'a str,
    proposal_id: &'a str,
    impact_id: &'a str,
    operation_id: &'a str,
    created: bool,
    replayed: bool,
    target_count: u32,
    node_count: usize,
}

/// 业务作用：只选择原材料的独立执行子路径，材料批准和影响审批入口不隐式开始安装。
///
/// 参数说明：
/// - `suffix`：已经剥离材料固定前缀的原路径。
///
/// 返回：属于执行子路径时为真，具体身份仍须通过分发检查。
pub(in crate::admin::operations::certificates) fn matches(suffix: &str) -> bool {
    suffix.ends_with("/execution")
}

/// 业务作用：在异步读取和持久决定之间重新认证原请求，查询已有任务不要求执行开关仍开启。
///
/// 参数说明：
/// - `context`：保留原凭据、精确快照与真实owner的请求。
///
/// 返回：原请求仍有同范围读权且结构已安装时成功；停机、撤权或换代立即拒绝。
fn current(context: &Context<'_>) -> Result<(), Error> {
    preview::identity(context)?;
    if !context.store.material_execution_installed {
        return Err(Error::Unavailable);
    }
    authorization::check(
        context.scope,
        context.snapshot,
        context.principal,
        Action::Read,
    )
}

/// 业务作用：按原父材料查询或创建唯一完整执行，客户端不能替换候选、目标和来源证明。
///
/// 参数说明：
/// - `context`：已经认证并持有材料及工作区并发名额的请求。
/// - `suffix`：精确的原材料执行子路径。
/// - `body`：写入确认的原始有界流。
///
/// 返回：同一快照的完整事实或明确提交的任务身份；未知提交只按原路径回读。
pub(in crate::admin::operations::certificates) async fn dispatch(
    context: &Context<'_>,
    suffix: &str,
    body: axum::body::Body,
) -> Result<Response<BoxBody>, Error> {
    let id = suffix
        .strip_prefix('/')
        .and_then(|value| value.strip_suffix("/execution"))
        .filter(|id| crate::admin::operations::certificates::model::valid_hex(id, 32))
        .ok_or(Error::Missing)?;
    if form_urlencoded::parse(context.request.uri.query().unwrap_or_default().as_bytes())
        .any(|(key, _)| key != "workspace")
    {
        return Err(Error::Invalid);
    }
    current(context)?;
    if context.request.method == Method::GET {
        let view = context
            .store
            .material_execution_view(context.scope, id, context.snapshot)
            .await?;
        current(context)?;
        let response = view.response()?;
        current(context)?;
        return Ok(response);
    }
    if context.request.method != Method::POST {
        return Err(Error::Invalid);
    }
    authorization::check(
        context.scope,
        context.snapshot,
        context.principal,
        Action::Write,
    )?;
    authority::running(context.state, context.store, context.snapshot)?;
    let bytes = match admin::collect_bounded_admin_body(context.request, body, 256).await {
        Ok(bytes) => bytes,
        Err(response) => return Ok(*response),
    };
    let confirmation = confirmation(context.request, &bytes)?;
    current(context)?;
    let mut event = audit::attempt(context, &confirmation.impact_sha256)?;
    // 持久审计先于候选解密和任务创建；取消请求不能把审计尚未确认当成已获执行资格。
    audit::persist(context, event.clone()).await?;
    let authority = Authority::new(context.state, context.snapshot.clone()).await;
    let entry = context
        .store
        .material_cache
        .prepare(
            &authority,
            context.store,
            &context.scope.key,
            id,
            context.principal,
        )
        .await?;
    let first = entry.frozen.nodes.first().ok_or(Error::Conflict)?;
    if first.impact_id != confirmation.impact_id
        || hex(&first.impact_sha256) != confirmation.impact_sha256
    {
        return Err(Error::Conflict);
    }
    // 原审批与当前配置必须共同覆盖持久决定，候选认证等待后才持发布权，避免在KDF期间阻塞配置发布。
    let publication = tokio::time::timeout(
        Duration::from_secs(2),
        context.state.apply_coordinator.lock_owned(),
    )
    .await
    .map_err(|_| Error::Capacity)?;
    let authorize = |frozen: &Frozen, initial| {
        current(context)?;
        authority.check(context.store, frozen, initial, Some(context.principal))
    };
    let started = context
        .store
        .start_material_execution(entry, &authorize)
        .await?;
    let entry = context
        .store
        .material_cache
        .retain(started.entry)
        .map_err(|_| Error::OutcomeUnknown)?;
    authorize(&entry.frozen, false).map_err(|_| Error::OutcomeUnknown)?;
    drop(publication);
    // 已提交任务不会因结果审计或HTTP回包丢失而撤销，之后失败只允许沿原身份恢复。
    event.phase = "completed".into();
    event.status = Some(200);
    event.ts_ms = audit::now().map_err(|_| Error::OutcomeUnknown)?;
    audit::persist(context, event)
        .await
        .map_err(|_| Error::OutcomeUnknown)?;
    authorize(&entry.frozen, false).map_err(|_| Error::OutcomeUnknown)?;
    let first = &entry.frozen.nodes[0];
    view::encode(&Started {
        cluster_id: &first.baseline.cluster_id,
        scope: &first.scope,
        proposal_id: &first.proposal_id,
        impact_id: &first.impact_id,
        operation_id: &first.operation_id,
        created: started.created,
        replayed: !started.created,
        target_count: first.target_count,
        node_count: entry.frozen.nodes.len(),
    })
}

/// 业务作用：执行确认仅绑定公开的完整影响身份和摘要，不接受新材料或替代节点集合。
///
/// 参数说明：
/// - `request`：实际请求头，重复内容类型必须拒绝。
/// - `bytes`：最多256字节的原确认正文。
///
/// 返回：唯一规范的原影响确认；重复字段、未知字段、大小写摘要或非法内容类型拒绝。
fn confirmation(request: &http::request::Parts, bytes: &[u8]) -> Result<Confirmation, Error> {
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
    let value: Confirmation = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if !crate::admin::operations::certificates::model::valid_hex(&value.impact_id, 32)
        || !crate::admin::operations::certificates::model::valid_hex(&value.impact_sha256, 64)
    {
        return Err(Error::Invalid);
    }
    Ok(value)
}
