//! 证书材料的独立有界接口；所有响应明确区分受理、目标证明和实际交付。

use super::{
    Error, Store,
    authorization::{self, Scope},
    model::{Candidate, Record, Submission},
    reading::{self, Selection},
    response, review, storage,
};
use crate::{
    admin::{self, AdminRequest, AdminState, BoxBody},
    control::ownership::config::Action,
};
use http::{Method, Response, StatusCode};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

struct Query {
    scope: Scope,
    after: String,
    limit: usize,
}

/// 业务作用：在收取材料之前认证和限制并发，写入取得配置发布权后再次认证并保留到事务结束。
///
/// 参数说明：
/// - `req`：独立管理监听接收的请求。
/// - `state`：当前快照、共享数据库和配置发布协调器。
///
/// 返回：无秘密的私有 JSON；关闭、越权、状态冲突和未知提交分别明确拒绝。
pub(in crate::admin) async fn handle(
    req: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    match Box::pin(dispatch(req, state)).await {
        Ok(response) => private(response),
        Err(error) => failure(error),
    }
}

/// 业务作用：按精确路径分发材料请求，异步等待不保留旧身份写权，所有持久写入共用固定锁序。
///
/// 参数说明：
/// - `req`：原始有界管理请求。
/// - `state`：已经启动的管理运行态。
///
/// 返回：已确认的低敏事实或封闭错误；原目标预检不改变审批，也不授予持久交付资格。
async fn dispatch(req: AdminRequest, state: Arc<AdminState>) -> Result<Response<BoxBody>, Error> {
    // Data 不开放持久材料管理入口，不能通过共用制品绕过部署职责。
    if !state.mode.full_control_plane() {
        return Err(Error::Missing);
    }
    let snapshot = state.snap.load_full();
    let (request, body) = req.into_parts();
    let identity = match admin::authenticate_admin_request(&request, &state) {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };
    if let Some(response) = admin::reject_untrusted_admin_browser_origin(&request, &state) {
        return Ok(response);
    }
    let store = state.operations.get().ok_or(Error::Missing)?;
    let plan = snapshot
        .admin_operations
        .as_ref()
        .filter(|plan| plan.config.certificates.enabled)
        .ok_or(Error::Missing)?;
    let query = query(request.uri.query())?;
    authorization::check(
        &query.scope,
        &snapshot,
        &identity.principal_id,
        Action::Read,
    )?;
    let _permit = store.admission.try_acquire().map_err(|_| Error::Capacity)?;
    let _workspace_permit = match query.scope.workspace.as_deref() {
        Some(workspace) => Some(
            state
                .workspace_operations
                .acquire_admin(&snapshot.ownership, workspace, 2)
                .map_err(|_| Error::Capacity)?,
        ),
        None => None,
    };
    let suffix = request
        .uri
        .path()
        .strip_prefix("/api/certificate-proposals")
        .ok_or(Error::Missing)?;
    #[cfg(feature = "node-actions")]
    if super::impact::matches(suffix) {
        return super::impact::dispatch(
            &super::preview::Context {
                state: &state,
                store,
                snapshot: &snapshot,
                request: &request,
                scope: &query.scope,
                principal: &identity.principal_id,
            },
            suffix,
            body,
        )
        .await;
    }
    if request.method == Method::GET {
        let value = read(
            store,
            &query,
            suffix,
            &request,
            &identity.principal_id,
            &snapshot,
            plan.config.certificates.accept_proposals,
        )
        .await?;
        // 查询期间权限或归属换代后整份响应作废，不能向当前身份交付旧范围的内容。
        if !Arc::ptr_eq(&snapshot, &state.snap.load_full()) {
            return Err(Error::Conflict);
        }
        return Ok(value);
    }
    if request.method != Method::POST || !admin::request_content_type(&request, "application/json")
    {
        return Err(Error::Invalid);
    }
    #[cfg(feature = "node-actions")]
    if let Some(id) = suffix
        .strip_prefix('/')
        .and_then(|value| value.strip_suffix("/preview"))
    {
        if !super::model::valid_hex(id, 32)
            || form_urlencoded::parse(request.uri.query().unwrap_or_default().as_bytes())
                .any(|(key, _)| key != "workspace")
        {
            return Err(Error::Invalid);
        }
        // 预检会向原受信节点交付秘密并读取完整TLS依赖，普通读取或单独审阅权不能触发该工作。
        authorization::check(
            &query.scope,
            &snapshot,
            &identity.principal_id,
            Action::Write,
        )?;
        let permit = state
            .management
            .admit_material_preview()
            .map_err(|_| Error::Capacity)?;
        let bytes = match admin::collect_bounded_admin_body(&request, body, 256).await {
            Ok(bytes) => bytes,
            Err(response) => return Ok(*response),
        };
        return super::preview::inspect(
            &super::preview::Context {
                state: &state,
                store,
                snapshot: &snapshot,
                request: &request,
                scope: &query.scope,
                principal: &identity.principal_id,
            },
            id,
            &bytes,
            permit,
        )
        .await;
    }
    let review_id = suffix
        .strip_prefix('/')
        .and_then(|value| value.strip_suffix("/review"))
        .filter(|value| super::model::valid_hex(value, 32));
    if !suffix.is_empty() && review_id.is_none() {
        return Err(Error::Missing);
    }
    // 读取资格不能成为大量材料上传资格；先按路径检查动作，再在正文解析后核对具体审阅决定。
    if suffix.is_empty() {
        authorization::check(
            &query.scope,
            &snapshot,
            &identity.principal_id,
            Action::Write,
        )?;
        if !plan.config.certificates.accept_proposals {
            return Err(Error::Denied);
        }
    } else if authorization::check(
        &query.scope,
        &snapshot,
        &identity.principal_id,
        Action::Write,
    )
    .is_err()
        && authorization::check(
            &query.scope,
            &snapshot,
            &identity.principal_id,
            Action::Review,
        )
        .is_err()
    {
        return Err(Error::Denied);
    }
    let limit = if suffix.is_empty() {
        plan.config.certificates.max_material_bytes as usize * 6 + 400000
    } else {
        1024
    };
    let bytes = match admin::collect_bounded_admin_body(&request, body, limit).await {
        Ok(bytes) => Zeroizing::new(Vec::<u8>::from(bytes)),
        Err(response) => return Ok(*response),
    };
    // 先持配置发布权再进入共享事务，正文读取或排队期间的撤权必须在本次操作前生效。
    let publication = Arc::new(
        tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned())
            .await
            .map_err(|_| Error::Capacity)?,
    );
    let current = match admin::authenticate_admin_request(&request, &state) {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };
    if let Some(response) = admin::reject_untrusted_admin_browser_origin(&request, &state) {
        return Ok(response);
    }
    if !Arc::ptr_eq(&snapshot, &state.snap.load_full())
        || current.principal_id != identity.principal_id
    {
        return Err(Error::Conflict);
    }
    let keyring = plan.certificate_keys.clone().ok_or(Error::Unavailable)?;
    let id = if suffix.is_empty() {
        authorization::check(
            &query.scope,
            &snapshot,
            &identity.principal_id,
            Action::Write,
        )?;
        if !plan.config.certificates.accept_proposals {
            return Err(Error::Denied);
        }
        let key = header(&request, "idempotency-key")?;
        if !crate::config::operations::token(key, 128)
            || !crate::config::operations::token(&identity.principal_id, 128)
        {
            return Err(Error::Invalid);
        }
        let submission: Submission = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        let candidate = Candidate::build(
            submission,
            plan.config.certificates.max_material_bytes as usize,
            &plan.config.cluster_id,
        )?;
        authorization::targets(&query.scope, &snapshot, &candidate.targets)?;
        let authority = authorization::authority(&query.scope, &snapshot, &candidate.targets)?;
        storage::submit(
            store,
            storage::Submission {
                scope: &query.scope.key,
                creator: &identity.principal_id,
                client_key: key,
                authority,
                candidate,
                keyring,
                publication: publication.clone(),
            },
        )
        .await?
    } else {
        let id = review_id.ok_or(Error::Missing)?;
        let review: review::Review = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        let action = if matches!(review.decision, review::Decision::Cancel) {
            Action::Write
        } else {
            Action::Review
        };
        authorization::check(&query.scope, &snapshot, &identity.principal_id, action)?;
        let record = exact(store, &query, Selection::Id(id), &snapshot).await?;
        // 审阅者不能给已经失权的创建者补发材料资格，原意图必须仍受当前授权约束。
        authorization::check(&query.scope, &snapshot, &record.creator, Action::Write)?;
        let authority = authorization::authority(&query.scope, &snapshot, &record.targets)?;
        review::apply(
            store,
            review::Request {
                scope: &query.scope.key,
                id,
                principal: &identity.principal_id,
                authority,
                review,
                keyring,
                publication: publication.clone(),
            },
        )
        .await?;
        id.to_owned()
    };
    // 已提交之后查询失败属于未知响应，不把读故障误报为未保存；调用者只按原请求身份恢复。
    let record = exact(store, &query, Selection::Id(&id), &snapshot)
        .await
        .map_err(|_| Error::OutcomeUnknown)?;
    response::encode(&response::Single {
        proposal: &record,
    })
}

/// 业务作用：提供受理窗口、有限目录或原请求恢复，不向持有普通读权的主体装载密文。
///
/// 参数说明：
/// - `store`：材料存储 owner。
/// - `query`：精确授权范围和有限游标。
/// - `suffix`：已剥离固定路由前缀的路径。
/// - `request`：原请求恢复所需的唯一头。
/// - `principal`：真实已认证主体，只能恢复自己的幂等键。
/// - `snapshot`：本次读取的当前归属快照。
/// - `accept_proposals`：本次快照的独立材料受理开关，不从长期资源副本推断。
///
/// 返回：明确未执行的完整低敏事实；范围变化不泄露其它域的材料。
async fn read(
    store: &Store,
    query: &Query,
    suffix: &str,
    request: &http::request::Parts,
    principal: &str,
    snapshot: &crate::config::GatewaySnapshot,
    accept_proposals: bool,
) -> Result<Response<BoxBody>, Error> {
    if suffix == "/context" {
        let context = store.context().await?;
        let config = &store.plan.config.certificates;
        return response::encode(&response::Context {
            cluster_id: &store.plan.config.cluster_id,
            scope: &query.scope.key,
            admission_epoch: context.epoch,
            epoch_expires_at_ms: context.expires,
            epoch_required: true,
            accept_proposals,
            access: response::Access {
                read: true,
                write: authorization::check(&query.scope, snapshot, principal, Action::Write)
                    .is_ok(),
                review: authorization::check(&query.scope, snapshot, principal, Action::Review)
                    .is_ok(),
            },
            capacity: response::Capacity {
                max_records: config.max_records,
                max_records_per_scope: config.max_records_per_scope,
                max_material_bytes: config.max_material_bytes,
                max_total_bytes: config.max_total_bytes,
            },
        });
    }
    if suffix.is_empty() {
        let mut records = reading::read(
            store,
            &query.scope.key,
            Selection::Page {
                after: &query.after,
                limit: query.limit as i64 + 1,
            },
        )
        .await?;
        let more = records.len() > query.limit;
        records.truncate(query.limit);
        for record in &records {
            authorization::targets(&query.scope, snapshot, &record.targets)?;
        }
        let next = if more {
            records.last().map(|record| record.id.as_str())
        } else {
            None
        };
        return response::encode(&response::Page {
            proposals: &records,
            next_after: next,
        });
    }
    let selection = if suffix == "/resolve" {
        let key = header(request, "idempotency-key")?;
        let text = header(request, "naway-admission-epoch")?;
        let epoch = text.parse::<i64>().map_err(|_| Error::Invalid)?;
        if !crate::config::operations::token(key, 128) || epoch <= 0 || epoch.to_string() != text {
            return Err(Error::Invalid);
        }
        Selection::Original {
            creator: principal,
            epoch,
            key,
        }
    } else {
        Selection::Id(
            suffix
                .strip_prefix('/')
                .filter(|value| super::model::valid_hex(value, 32))
                .ok_or(Error::Missing)?,
        )
    };
    let record = exact(store, query, selection, snapshot).await?;
    response::encode(&response::Single {
        proposal: &record,
    })
}

/// 业务作用：在返回精确记录前复验完整目标归属，不以持久 scope 字符串替代当前归属证明。
///
/// 参数说明：
/// - `store`：共享存储。
/// - `query`：当前唯一授权范围。
/// - `selection`：精确提案或原请求身份。
/// - `snapshot`：当前归属图。
///
/// 返回：唯一完整记录；缺记录、异常重复或归属不符拒绝。
async fn exact(
    store: &Store,
    query: &Query,
    selection: Selection<'_>,
    snapshot: &crate::config::GatewaySnapshot,
) -> Result<Record, Error> {
    let mut records = reading::read(store, &query.scope.key, selection).await?;
    if records.len() > 1 {
        return Err(Error::Unavailable);
    }
    let record = records.pop().ok_or(Error::Missing)?;
    authorization::targets(&query.scope, snapshot, &record.targets)?;
    Ok(record)
}

/// 业务作用：拒绝重复或未知查询参数，让范围和游标只有一种解释。
///
/// 参数说明：
/// - `raw`：请求的有限查询字符串。
///
/// 返回：合法精确范围、游标和最多一百条的分页预算。
fn query(raw: Option<&str>) -> Result<Query, Error> {
    let raw = raw.unwrap_or_default();
    if raw.len() > 1024 {
        return Err(Error::Invalid);
    }
    let mut workspace = None;
    let mut after = String::new();
    let mut limit = 50;
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        if !seen.insert(key.to_string()) {
            return Err(Error::Invalid);
        }
        match key.as_ref() {
            "workspace" => workspace = Some(value.into_owned()),
            "after" if super::model::valid_hex(&value, 32) => after = value.into_owned(),
            "limit" => {
                limit = value.parse().map_err(|_| Error::Invalid)?;
                if !(1..=100).contains(&limit) {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
    }
    Ok(Query {
        scope: Scope::new(workspace)?,
        after,
        limit,
    })
}

/// 业务作用：原请求恢复与提交只接受单个文本身份头，避免代理合并或重复头改变幂等键。
///
/// 参数说明：
/// - `request`：本次管理请求元数据。
/// - `name`：代码指定的身份头名称。
///
/// 返回：唯一文本借用；缺失、重复或非文本值拒绝。
pub(super) fn header<'a>(request: &'a http::request::Parts, name: &str) -> Result<&'a str, Error> {
    let mut values = request.headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Invalid)?;
    if values.next().is_some() {
        return Err(Error::Invalid);
    }
    Ok(value)
}

/// 业务作用：用固定错误分类表达材料操作失败，未知提交只能按原身份查询。
///
/// 参数说明：
/// - `error`：封闭业务错误。
///
/// 返回：私有低敏 JSON，不回显 SQL、材料、秘密来源或解析输入。
fn failure(error: Error) -> Response<BoxBody> {
    let (status, name) = match error {
        Error::Expired => (StatusCode::GONE, "admission_epoch_expired"),
        Error::Invalid => (StatusCode::BAD_REQUEST, "invalid_certificate_proposal"),
        Error::Conflict => (StatusCode::CONFLICT, "certificate_proposal_conflict"),
        Error::Capacity => (
            StatusCode::TOO_MANY_REQUESTS,
            "certificate_proposal_capacity",
        ),
        Error::Missing => (StatusCode::NOT_FOUND, "not_found"),
        Error::Denied => (StatusCode::FORBIDDEN, "forbidden"),
        Error::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "material_authority_unavailable",
        ),
        Error::OutcomeUnknown => (StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown"),
    };
    private(admin::json(
        status,
        serde_json::json!({
            "error": name,
            "execution_supported": false,
            "targets_validated": false
        }),
    ))
}

/// 业务作用：禁止缓存跨主体复用提案响应，身份与材料状态只对本次授权请求有效。
///
/// 参数说明：
/// - `response`：当前请求的成功或拒绝响应。
///
/// 返回：附加 no-store 的原响应。
fn private(mut response: Response<BoxBody>) -> Response<BoxBody> {
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
