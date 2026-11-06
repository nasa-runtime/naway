//! 完整影响入口仅引用原材料身份；登记、查询和双人审阅具有各自明确的权限。

use super::{
    model::Record,
    reading::{self, Selection},
    review, storage, Error,
};
use crate::admin::operations::certificates::{
    authorization,
    preview::{self, Context},
};
use crate::{
    admin::{self, BoxBody},
    control::ownership::config::Action,
};
use http::{Method, Response, StatusCode};
use std::time::Duration;

/// 业务作用：仅选择独立影响路径，旧材料查询与 pair-only 审阅保持原来的解释。
///
/// 参数说明：
/// - `suffix`：已移除材料 API 固定前缀的路径。
///
/// 返回：属于影响上下文、唯一影响或明确子动作时为真，具体身份仍由分发验证。
pub(in crate::admin::operations::certificates) fn matches(suffix: &str) -> bool {
    suffix == "/impact-context"
        || suffix.ends_with("/impact")
        || suffix.ends_with("/impact/review")
        || suffix.ends_with("/impact/resolve")
}

/// 业务作用：复验影响功能、原身份和唯一查询范围，不让异步正文保留已关闭的审批入口。
///
/// 参数说明：
/// - `context`：已经过材料普通读权和有界并发门的请求。
///
/// 返回：独立功能显式开启且当前实例权威不变时成功，关闭或换代立即拒绝。
fn current(context: &Context<'_>) -> Result<(), Error> {
    preview::identity(context)?;
    if !context.store.material_impact_installed
        || !context
            .snapshot
            .admin_operations
            .as_ref()
            .is_some_and(|plan| plan.config.certificates.impact_approvals.enabled)
    {
        return Err(Error::Missing);
    }
    if form_urlencoded::parse(context.request.uri.query().unwrap_or_default().as_bytes())
        .any(|(key, _)| key != "workspace")
    {
        return Err(Error::Invalid);
    }
    authorization::check(
        context.scope,
        context.snapshot,
        context.principal,
        Action::Read,
    )
}

/// 业务作用：完整记录交付前检查全部共享对象，写入和审阅额外复验两名创建者及冻结权威。
///
/// 参数说明：
/// - `context`：当前请求者和完整归属快照。
/// - `record`：来自服务端持久校验的完整影响。
/// - `writing`：当前是否准备改变审批状态；普通查询只要求当前可读完整范围。
///
/// 返回：当前完整范围允许该操作时成功；跨域共享、创建者失权或审批权威改变时拒绝。
pub(super) fn authorize(
    context: &Context<'_>,
    record: &Record,
    writing: bool,
) -> Result<(), Error> {
    current(context)?;
    let impact_authority = record
        .proof
        .authority(&context.scope.key, context.snapshot)
        .ok_or(Error::Denied)?;
    if record.cluster_id != context.store.plan.config.cluster_id
        || record.scope != context.scope.key
    {
        return Err(Error::Denied);
    }
    if writing {
        // 审阅不能给已失权的材料创建者或影响登记者补发资格，全部共享归属也不能沿用旧证据。
        for principal in [&record.creator, &record.material_creator] {
            authorization::check(context.scope, context.snapshot, principal, Action::Write)?;
        }
        if impact_authority != record.impact_authority
            || authorization::authority(context.scope, context.snapshot, &record.proof.targets)?
                != record.authority
        {
            return Err(Error::Denied);
        }
    }
    Ok(())
}

/// 业务作用：按固定路由分别执行完整影响登记、查询和独立审阅，客户端不能提交替代证明或目标。
///
/// 参数说明：
/// - `context`：原材料入口已经认证并持有请求名额的上下文。
/// - `suffix`：独立影响路径后缀。
/// - `body`：仍受实际接收限额约束的原始正文流。
///
/// 返回：已确认的完整低敏事实；未知提交只通过原幂等身份恢复，批准本身不触发材料执行。
pub(in crate::admin::operations::certificates) async fn dispatch(
    context: &Context<'_>,
    suffix: &str,
    body: axum::body::Body,
) -> Result<Response<BoxBody>, Error> {
    current(context)?;
    if suffix == "/impact-context" {
        if context.request.method != Method::GET {
            return Err(Error::Invalid);
        }
        let admission = context.store.context().await?;
        current(context)?;
        let config = &context
            .snapshot
            .admin_operations
            .as_ref()
            .ok_or(Error::Missing)?
            .config
            .certificates
            .impact_approvals;
        return encode(&serde_json::json!({
            "cluster_id": context.store.plan.config.cluster_id,
            "scope": context.scope.key,
            "admission_epoch": admission.epoch.to_string(),
            "epoch_expires_at_ms": admission.expires,
            "accept_proposals": config.accept_proposals,
            "execution_supported": false,
            "access": {
                "read": true,
                "write": authorization::check(context.scope, context.snapshot, context.principal, Action::Write).is_ok(),
                "review": authorization::check(context.scope, context.snapshot, context.principal, Action::Review).is_ok()
            },
            "capacity": {
                "max_records": config.max_records,
                "max_records_per_scope": config.max_records_per_scope,
                "max_total_bytes": config.max_total_bytes,
                "max_proof_bytes": crate::config::operations::certificates::impact::MAX_PROOF_BYTES
            }
        }));
    }
    let (id, action) = suffix
        .strip_prefix('/')
        .and_then(|suffix| suffix.split_once("/impact"))
        .ok_or(Error::Missing)?;
    if !super::super::model::valid_hex(id, 32) || !matches!(action, "" | "/review" | "/resolve") {
        return Err(Error::Missing);
    }
    if context.request.method == Method::GET && matches!(action, "" | "/resolve") {
        let selection = if action == "/resolve" {
            let request = original(context, id)?;
            Selection::Original {
                creator: context.principal,
                epoch: request.epoch,
                key: request.key,
            }
        } else {
            Selection::Proposal(id)
        };
        let record = reading::read(context.store, &context.scope.key, selection)
            .await?
            .ok_or(Error::Missing)?;
        if record.proposal_id != id {
            return Err(Error::Missing);
        }
        authorize(context, &record, false)?;
        return record_response(&record);
    }
    if context.request.method != Method::POST
        || action == "/resolve"
        || !admin::request_content_type(context.request, "application/json")
    {
        return Err(Error::Invalid);
    }
    if action.is_empty() {
        return register(context, id, body).await;
    }
    if authorization::check(
        context.scope,
        context.snapshot,
        context.principal,
        Action::Write,
    )
    .is_err()
        && authorization::check(
            context.scope,
            context.snapshot,
            context.principal,
            Action::Review,
        )
        .is_err()
    {
        return Err(Error::Denied);
    }
    let bytes = match admin::collect_bounded_admin_body(context.request, body, 1024).await {
        Ok(bytes) => bytes,
        Err(response) => return Ok(*response),
    };
    let review: review::Review = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    if !super::super::model::valid_hex(&review.impact_id, 32)
        || !super::super::model::valid_hex(&review.impact_sha256, 64)
    {
        return Err(Error::Invalid);
    }
    let action = if matches!(review.decision, super::super::review::Decision::Cancel) {
        Action::Write
    } else {
        Action::Review
    };
    // 正文与发布锁等待期间可能撤权，持锁后重新认证再进入持久状态转换。
    let _publication = tokio::time::timeout(
        Duration::from_secs(2),
        context.state.apply_coordinator.lock_owned(),
    )
    .await
    .map_err(|_| Error::Capacity)?;
    current(context)?;
    authorization::check(context.scope, context.snapshot, context.principal, action)?;
    review::apply(context.store, context, id, &review).await?;
    let record = reading::read(context.store, &context.scope.key, Selection::Proposal(id))
        .await
        .map_err(|_| Error::OutcomeUnknown)?
        .ok_or(Error::OutcomeUnknown)?;
    authorize(context, &record, false).map_err(|_| Error::OutcomeUnknown)?;
    record_response(&record)
}

/// 业务作用：服务端对原候选运行全部节点预检后登记完整影响，同请求回放不重复解密或驱动节点。
///
/// 参数说明：
/// - `context`：当前身份、精确范围与管理资源。
/// - `id`：原材料唯一身份。
/// - `body`：仅允许空 JSON 对象的确认流。
///
/// 返回：已提交的唯一完整影响；任一节点失败、原状态变化或权限改变均不登记。
async fn register(
    context: &Context<'_>,
    id: &str,
    body: axum::body::Body,
) -> Result<Response<BoxBody>, Error> {
    authorization::check(
        context.scope,
        context.snapshot,
        context.principal,
        Action::Write,
    )?;
    let request = original(context, id)?;
    let bytes = match admin::collect_bounded_admin_body(context.request, body, 256).await {
        Ok(bytes) => bytes,
        Err(response) => return Ok(*response),
    };
    preview::confirm(&bytes)?;
    current(context)?;
    let replay = reading::read(
        context.store,
        &context.scope.key,
        Selection::Original {
            creator: request.creator,
            epoch: request.epoch,
            key: request.key,
        },
    )
    .await?;
    if let Some(record) = replay {
        if record.proposal_id != id {
            return Err(Error::Conflict);
        }
        authorize(context, &record, false)?;
        return record_response(&record);
    }
    // 受理热关闭只阻断新登记；原请求事实仍可恢复，不能要求调用者重复上传或换新幂等键。
    if !context
        .snapshot
        .admin_operations
        .as_ref()
        .is_some_and(|plan| plan.config.certificates.impact_approvals.accept_proposals)
    {
        return Err(Error::Denied);
    }
    if reading::read(context.store, &context.scope.key, Selection::Proposal(id))
        .await?
        .is_some()
    {
        return Err(Error::Conflict);
    }
    storage::preflight(context.store, request).await?;
    let permit = context
        .state
        .management
        .admit_material_preview()
        .map_err(|_| Error::Capacity)?;
    let observation = preview::observe(context, id, &bytes, permit).await?;
    let _publication = tokio::time::timeout(
        Duration::from_secs(2),
        context.state.apply_coordinator.lock_owned(),
    )
    .await
    .map_err(|_| Error::Capacity)?;
    current(context)?;
    // 取得发布锁后再复验原节点基线，排队期间重启或配置换代不得登记先前的成功。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    for item in &observation.observed {
        let completed = item.result.as_ref().map_err(|_| Error::Conflict)?;
        tokio::time::timeout_at(
            deadline,
            admin::management::material_preview::recheck(
                context.state,
                context.snapshot,
                &item.intent,
                completed.session,
            ),
        )
        .await
        .map_err(|_| Error::Conflict)?
        .map_err(|_| Error::Conflict)?;
    }
    let candidate = storage::Candidate::from_observation(observation)?;
    let impact_authority = authorize_candidate(context, &candidate)?;
    let remaining = candidate.window.remaining().map_err(|_| Error::Conflict)?;
    let impact_id = tokio::time::timeout(
        remaining.min(Duration::from_secs(6)),
        storage::submit(context, request, &candidate, &impact_authority),
    )
    .await
    .map_err(|_| Error::OutcomeUnknown)??;
    let record = reading::read(context.store, &context.scope.key, Selection::Proposal(id))
        .await
        .map_err(|_| Error::OutcomeUnknown)?
        .ok_or(Error::OutcomeUnknown)?;
    if record.id != impact_id {
        return Err(Error::OutcomeUnknown);
    }
    authorize(context, &record, false).map_err(|_| Error::OutcomeUnknown)?;
    record_response(&record)
}

/// 业务作用：登记事务等待后复验原凭据、两名创建主体和全部来源，不能把配置锁当作凭据续期。
///
/// 参数说明：
/// - `context`：仍持有配置发布权的原请求上下文。
/// - `candidate`：服务端已确认全部原目标的完整影响候选。
///
/// 返回：当前完整共享对象权威；自然到期、停机、原创建者失权或归属变化均拒绝写入。
pub(super) fn authorize_candidate(
    context: &Context<'_>,
    candidate: &storage::Candidate,
) -> Result<[u8; 32], Error> {
    current(context)?;
    preview::current(context)?;
    // 原材料和影响登记的实际主体都需要当前 Write，不能由已保存材料代替任一主体的权限。
    for principal in [context.principal, candidate.stamp.context.creator.as_str()] {
        authorization::check(context.scope, context.snapshot, principal, Action::Write)?;
    }
    if authorization::authority(context.scope, context.snapshot, &candidate.proof.targets)?
        != candidate.stamp.authority
    {
        return Err(Error::Denied);
    }
    candidate
        .proof
        .authority(&context.scope.key, context.snapshot)
        .ok_or(Error::Denied)
}

/// 业务作用：固定影响登记的原请求身份，不让重试通过换代或重复头改变幂等命名空间。
///
/// 参数说明：
/// - `context`：包含唯一请求头和当前主体的上下文。
/// - `proposal`：路径明确指定的原材料身份。
///
/// 返回：规范正代际与有界幂等键的借用；非规范文本、重复头或非法主体拒绝。
fn original<'a>(
    context: &'a Context<'_>,
    proposal: &'a str,
) -> Result<storage::Request<'a>, Error> {
    let key = super::super::api::header(context.request, "idempotency-key")?;
    let text = super::super::api::header(context.request, "naway-admission-epoch")?;
    let epoch = text.parse::<i64>().map_err(|_| Error::Invalid)?;
    if epoch <= 0
        || epoch.to_string() != text
        || !crate::config::operations::token(key, 128)
        || !crate::config::operations::token(context.principal, 128)
    {
        return Err(Error::Invalid);
    }
    Ok(storage::Request {
        scope: &context.scope.key,
        creator: context.principal,
        key,
        epoch,
        proposal,
    })
}

/// 业务作用：直接借用完整记录输出公开响应，不复制来源树或暴露隐藏的授权及材料意图摘要。
///
/// 参数说明：
/// - `record`：已经复验范围和当前身份的完整持久记录。
///
/// 返回：唯一完整影响对象及该审批入口的能力边界，不返回私钥、路径或下载令牌。
fn record_response(record: &Record) -> Result<Response<BoxBody>, Error> {
    #[derive(serde::Serialize)]
    struct Response<'a> {
        impact: &'a Record,
        execution_supported: bool,
    }
    encode(&Response {
        impact: record,
        execution_supported: false,
    })
}

/// 业务作用：为影响 HTTP 输出设置证明与固定元数据的总上限，禁止交付部分序列化结果。
///
/// 参数说明：
/// - `value`：无秘密的完整公开投影。
///
/// 返回：私有不可缓存的完整 JSON；超量或编码失败封闭响应。
fn encode(value: &impl serde::Serialize) -> Result<Response<BoxBody>, Error> {
    let bytes = super::encoding::bytes(
        value,
        crate::config::operations::certificates::impact::MAX_PROOF_BYTES + 16384,
    )?;
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(admin::full_body(bytes.into()))
        .map_err(|_| Error::Unavailable)
}
