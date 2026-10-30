//! 有界持久提案接口；保存、批准和实际生效使用不同合同。

mod execution;
mod preview;

use super::{
    authorization::Scope,
    model::{Candidate, Decision, Domain, Error, Review, Submission},
    Store,
};
use crate::admin::{self, AdminRequest, AdminState, BoxBody};
use crate::control::ownership::config::Action;
use http::{Method, Response, StatusCode};
use std::{sync::Arc, time::Duration};

struct Query {
    scope: Scope,
    domain: Domain,
    after: String,
    limit: i64,
}

/// 业务作用：在任何正文读取或数据库调用之前认证并限制范围和并发，再路由精确提案动作。
///
/// 参数说明：
/// - `req`：独立管理监听接收的请求。
/// - `state`：当前权限目录、部署角色与存储 owner。
///
/// 返回：私有低敏 JSON 或显式授权的原文；异步期间发生权限换代时拒绝交付旧授权结果。
pub(in crate::admin) async fn handle(
    req: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    if !state.mode.full_control_plane() {
        return failure(Error::Missing);
    }
    let snapshot = state.snap.load_full();
    let (request, body) = req.into_parts();
    let identity = match admin::authenticate_admin_request(&request, &state) {
        Ok(identity) => identity,
        // 认证拒绝也属于当前主体的管理响应，不能被共享缓存复用于其它会话。
        Err(response) => return private(*response),
    };
    if let Some(response) = admin::reject_untrusted_admin_browser_origin(&request, &state) {
        return private(response);
    }
    let Some(store) = state.operations.get() else {
        return failure(Error::Missing);
    };
    let Some(plan) = &snapshot.admin_operations else {
        return failure(Error::Missing);
    };
    let query = match query(request.uri.query()) {
        Ok(query) => query,
        Err(error) => return failure(error),
    };
    if query
        .scope
        .check(
            &snapshot,
            &identity.principal_id,
            query.domain,
            Action::Read,
        )
        .is_err()
    {
        return failure(Error::Denied);
    }
    let Ok(_permit) = store.admission.try_acquire() else {
        return failure(Error::Capacity);
    };
    // 工作区沿用已有独立管理名额，慢正文或数据库等待不能独占全部提案入口。
    let _workspace_permit = match query.scope.workspace.as_deref() {
        Some(workspace) => {
            match state
                .workspace_operations
                .acquire_admin(&snapshot.ownership, workspace, 2)
            {
                Ok(permit) => Some(permit),
                Err(_) => return failure(Error::Capacity),
            }
        }
        None => None,
    };
    let write = request.method == Method::POST;
    let path = request.uri.path();
    let suffix = path
        .strip_prefix("/api/operations/proposals")
        .unwrap_or("invalid");
    let draft = write && suffix == "/draft";
    if draft {
        // 草稿不产生执行权威，但编辑入口仍要求当前范围的写资格，不能借读取权限扩大管理能力。
        if query
            .scope
            .check(
                &snapshot,
                &identity.principal_id,
                query.domain,
                Action::Write,
            )
            .is_err()
        {
            return failure(Error::Denied);
        }
        if !admin::request_content_type(&request, "application/json") {
            return failure(Error::Invalid);
        }
    }
    let execution_id = suffix
        .strip_prefix('/')
        .and_then(|path| path.strip_suffix("/execute"))
        .filter(|id| valid_id(id));
    let preview_id = suffix
        .strip_prefix('/')
        .and_then(|path| path.strip_suffix("/preview"))
        .filter(|id| valid_id(id));
    if write && preview_id.is_some() {
        // 只读预览仍可能读取候选依赖，构建授权必须先于正文与共享候选装载。
        if !preview::allows(&snapshot, &query, &identity.principal_id) {
            return failure(Error::Denied);
        }
        if !admin::request_content_type(&request, "application/json") {
            return failure(Error::Invalid);
        }
    }
    if write && execution_id.is_none() && preview_id.is_none() && !plan.config.accept_proposals {
        return failure(Error::Unavailable);
    }
    if write
        && execution_id.is_some()
        && query
            .scope
            .check(
                &snapshot,
                &identity.principal_id,
                query.domain,
                Action::Write,
            )
            .is_err()
    {
        return failure(Error::Denied);
    }
    let execution_context = execution::Context {
        state: &state,
        store,
        snapshot: &snapshot,
        query: &query,
        request: &request,
        principal: &identity.principal_id,
    };
    let result = if request.method == Method::GET {
        drop(body);
        if let Some(id) = suffix
            .strip_prefix('/')
            .and_then(|path| path.strip_suffix("/execution"))
            .filter(|id| valid_id(id))
        {
            execution::read(&execution_context, id)
                .await
                .map(|value| admin::json(StatusCode::OK, value))
        } else if suffix == "/resolve" {
            match super::reading::resolve(
                store,
                &query.scope,
                query.domain,
                &identity.principal_id,
                &request,
            )
            .await
            {
                Ok(record) => Ok(admin::json(
                    StatusCode::OK,
                    serde_json::json!({
                        "proposal": record,
                        "cluster_id": store.plan.config.cluster_id,
                        "execution_supported": execution::supported(),
                        "targets_validated": false,
                        "validation": "syntax_only"
                    }),
                )),
                Err(error) => Err(error),
            }
        } else if let Some(id) = suffix
            .strip_prefix('/')
            .and_then(|path| path.strip_suffix("/candidate"))
        {
            if !valid_id(id) {
                return failure(Error::Missing);
            }
            super::reading::candidate(
                store,
                &query.scope,
                query.domain,
                id,
                &identity.principal_id,
                &snapshot,
            )
            .await
        } else {
            read(store, &query, suffix).await.map(|mut value| {
                if suffix == "/context" {
                    if let (Some(target), Some(capability)) = (
                        value.as_object_mut(),
                        execution::capability(&state, store, &snapshot).as_object(),
                    ) {
                        target.extend(capability.clone());
                    }
                    if let (Some(target), Some(capability)) = (
                        value.as_object_mut(),
                        preview::capability(&execution_context).as_object(),
                    ) {
                        target.extend(capability.clone());
                    }
                    value["accept_proposals"] = (plan.config.accept_proposals
                        && value["capacity"]["matches_config"] == true)
                        .into();
                    value["permissions"] = serde_json::to_value(query.scope.access(
                        &snapshot,
                        &identity.principal_id,
                        query.domain,
                    ))
                    .expect("serialize fixed proposal permissions");
                }
                admin::json(StatusCode::OK, value)
            })
        }
    } else if write {
        let max_bytes = if execution_id.is_some() || preview_id.is_some() {
            256
        } else {
            (plan.config.max_candidate_bytes as usize).saturating_mul(6) + 128 * 1024
        };
        let bytes = match tokio::time::timeout(
            Duration::from_secs(5),
            admin::collect_bounded_admin_body(&request, body, max_bytes),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => return failure(Error::Invalid),
            Err(_) => return failure(Error::Unavailable),
        };
        // 慢正文不能保留被撤销的授权；数据库提交后还会复验，同一已保存意图可按原键回读。
        if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
            return failure(Error::Conflict);
        }
        if draft {
            super::draft::handle(
                &state,
                query.domain,
                bytes,
                plan.config.max_candidate_bytes as usize,
                &store.plan.config.cluster_id,
                &query.scope.key,
            )
            .await
        } else if let Some(id) = preview_id {
            tokio::time::timeout(
                Duration::from_secs(20),
                Box::pin(preview::inspect(&state, &execution_context, id, &bytes)),
            )
            .await
            .unwrap_or(Err(Error::Expired))
        } else if let Some(id) = execution_id {
            Box::pin(execution::execute(&execution_context, id, &bytes))
                .await
                .map(|value| admin::json(StatusCode::OK, value))
        } else {
            Box::pin(write_proposal(
                store,
                &query,
                suffix,
                &request,
                &identity.principal_id,
                &snapshot,
                &bytes,
            ))
            .await
            .map(|value| admin::json(StatusCode::OK, value))
        }
    } else {
        Err(Error::Invalid)
    };
    if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
        return failure(if write && !draft && preview_id.is_none() {
            Error::OutcomeUnknown
        } else {
            Error::Conflict
        });
    }
    match result {
        Ok(response) => private(response),
        Err(error) => failure(error),
    }
}

/// 业务作用：解析唯一范围、领域和稳定游标，拒绝重复参数及未知选项。
///
/// 参数说明：
/// - `raw`：请求 URI 中的有限查询字符串。
///
/// 返回：精确查询计划；没有领域参数时使用 gateway。
fn query(raw: Option<&str>) -> Result<Query, Error> {
    let raw = raw.unwrap_or_default();
    if raw.len() > 1024 {
        return Err(Error::Invalid);
    }
    let mut workspace = None;
    let mut domain = Domain::Gateway;
    let mut after = String::new();
    let mut limit = 50;
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        if !seen.insert(key.to_string()) {
            return Err(Error::Invalid);
        }
        match key.as_ref() {
            "workspace" => workspace = Some(value.into_owned()),
            "domain" => {
                domain = match value.as_ref() {
                    "gateway" => Domain::Gateway,
                    "sentinel" => Domain::Sentinel,
                    "interface-guard" => Domain::InterfaceGuard,
                    _ => return Err(Error::Invalid),
                }
            }
            "after" if valid_id(&value) => after = value.into_owned(),
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
        domain,
        after,
        limit,
    })
}

/// 业务作用：提供有界列表或精确记录，始终区分未执行的提案与实际节点结果。
///
/// 参数说明：
/// - `store`：同集群的持久权威。
/// - `query`：已授权范围和分页边界。
/// - `suffix`：入口后缀，为空或精确提案 id。
///
/// 返回：带真实能力边界的记录；不返回候选原文或跨范围存在性。
async fn read(store: &Store, query: &Query, suffix: &str) -> Result<serde_json::Value, Error> {
    let mut value = if suffix == "/context" {
        let context = store.context().await?;
        serde_json::json!({
            "cluster_id": store.plan.config.cluster_id,
            "scope": query.scope.key,
            "admission_epoch": context.epoch,
            "epoch_expires_at_ms": context.expires,
            "epoch_required": context.required,
            "capacity": context.capacity.view(&store.plan.config)
        })
    } else if suffix.is_empty() {
        let mut records = store
            .list(
                &query.scope.key,
                query.domain.identity().0,
                &query.after,
                query.limit + 1,
            )
            .await?;
        let more = records.len() > query.limit as usize;
        records.truncate(query.limit as usize);
        let next_after = if more {
            records.last().map(|record| record.id.clone())
        } else {
            None
        };
        serde_json::json!({
            "proposals": records, "next_after": next_after
        })
    } else {
        let id = suffix
            .strip_prefix('/')
            .filter(|id| valid_id(id))
            .ok_or(Error::Missing)?;
        let record = store.read(&query.scope.key, id).await?;
        if record.domain != query.domain.identity().0 {
            return Err(Error::Missing);
        }
        serde_json::json!({
            "proposal": record
        })
    };
    value["execution_supported"] = execution::supported().into();
    if suffix == "/context" {
        value["workflow_schema_installed"] = store.workflow_installed.into();
        #[cfg(feature = "admin-operations-workflow-pgsql")]
        {
            value["workflow_storage_ready"] = store.workflow.get().is_some().into();
            value["delivery_schema_installed"] = store.delivery_installed.into();
            if let Some(workflow) = store.workflow.get() {
                value["workflow"] =
                    serde_json::to_value(&workflow.summary).map_err(|_| Error::Unavailable)?;
            }
        }
        #[cfg(not(feature = "admin-operations-workflow-pgsql"))]
        {
            value["workflow_storage_ready"] = false.into();
        }
    }
    value["cluster_id"] = store.plan.config.cluster_id.clone().into();
    value["targets_validated"] = false.into();
    value["validation"] = "syntax_only".into();
    Ok(value)
}

/// 业务作用：在领域授权后保存候选或提交一次审阅，任何分支都不下发目标命令。
///
/// 参数说明：
/// - `store`：已通过启动门的持久权威。
/// - `query`：当前授权范围和领域。
/// - `suffix`：精确提交或审阅路径。
/// - `request`：包含幂等头的请求元数据。
/// - `principal`：已认证的稳定主体。
/// - `snapshot`：本请求冻结的权限快照。
/// - `bytes`：已完成超时和长度约束的正文。
///
/// 返回：已保存的低敏事实；权限、状态或摘要冲突拒绝且无数据面副作用。
async fn write_proposal(
    store: &Store,
    query: &Query,
    suffix: &str,
    request: &http::request::Parts,
    principal: &str,
    snapshot: &crate::config::GatewaySnapshot,
    bytes: &[u8],
) -> Result<serde_json::Value, Error> {
    let authority = query.scope.authority(snapshot)?;
    let id = if suffix.is_empty() {
        query
            .scope
            .check(snapshot, principal, query.domain, Action::Write)?;
        if !crate::config::operations::token(principal, 128) {
            return Err(Error::Denied);
        }
        let mut keys = request.headers.get_all("idempotency-key").iter();
        let key = keys
            .next()
            .and_then(|key| key.to_str().ok())
            .filter(|key| crate::config::operations::token(key, 128))
            .ok_or(Error::Invalid)?;
        if keys.next().is_some() {
            return Err(Error::Invalid);
        }
        let submission: Submission = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if submission.domain != query.domain {
            return Err(Error::Invalid);
        }
        // 冻结意图只能引用本提案的发行集群，不能把另一信任域的存储证明带入后续执行链。
        if submission.targets.iter().any(|target| {
            target
                .node_baseline
                .as_ref()
                .is_some_and(|baseline| baseline.cluster_id != store.plan.config.cluster_id)
        }) {
            return Err(Error::Invalid);
        }
        let candidate =
            Candidate::build(submission, store.plan.config.max_candidate_bytes as usize)?;
        store
            .submit(&query.scope.key, principal, key, &authority, &candidate)
            .await?
    } else {
        let id = suffix
            .strip_prefix('/')
            .and_then(|value| value.strip_suffix("/review"))
            .filter(|id| valid_id(id))
            .ok_or(Error::Missing)?;
        let review: Review = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        let action = if matches!(review.decision, Decision::Cancel) {
            Action::Write
        } else {
            Action::Review
        };
        query
            .scope
            .check(snapshot, principal, query.domain, action)?;
        let record = store.read(&query.scope.key, id).await?;
        if record.domain != query.domain.identity().0 {
            return Err(Error::Missing);
        }
        query
            .scope
            .check(snapshot, &record.creator, query.domain, Action::Write)?;
        store
            .review(&query.scope.key, id, principal, &authority, &review)
            .await?;
        id.to_owned()
    };
    read(store, query, &format!("/{id}")).await
}

/// 业务作用：限制操作路径为固定长度小写随机身份，拒绝路径层次或编码歧义。
///
/// 参数说明：
/// - `id`：已从路径或游标提取的身份。
///
/// 返回：仅 32 字节小写十六进制为真。
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// 业务作用：使用固定错误分类表达持久操作失败，不回显数据库、SQL或候选内容。
///
/// 参数说明：
/// - `error`：权限、容量、协议或事务结果分类。
///
/// 返回：私有 JSON；未知结果明确提示按原幂等身份回读。
fn failure(error: Error) -> Response<BoxBody> {
    let (status, name) = match error {
        Error::Expired => (StatusCode::GONE, "admission_epoch_expired"),
        Error::Invalid => (StatusCode::BAD_REQUEST, "invalid_proposal"),
        Error::Conflict => (StatusCode::CONFLICT, "proposal_conflict"),
        Error::Capacity => (StatusCode::TOO_MANY_REQUESTS, "proposal_capacity"),
        Error::Missing => (StatusCode::NOT_FOUND, "not_found"),
        Error::Denied => (StatusCode::FORBIDDEN, "forbidden"),
        Error::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
        Error::OutcomeUnknown => (StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown"),
    };
    private(admin::json(
        status,
        serde_json::json!({
            "error": name, "execution_supported": execution::supported()
        }),
    ))
}

/// 业务作用：防止共享代理或浏览器缓存将一个主体的提案事实交付给另一主体。
///
/// 参数说明：
/// - `response`：已经过精确范围过滤的管理响应。
///
/// 返回：带 no-store 的原响应。
fn private(mut response: Response<BoxBody>) -> Response<BoxBody> {
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
