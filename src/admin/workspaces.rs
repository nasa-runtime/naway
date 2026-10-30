//! 工作区管理入口先认证再选择范围；不复用返回全平台状态的旧 handler。

use super::*;
use http::HeaderValue;

/// 业务作用：提供当前主体可见的工作区与对象归属，隐藏其它工作区的存在性和配置内容。
///
/// 参数说明：
/// - `req`：为管理请求
/// - `state`：提供当前快照与认证目录。
///
/// 返回：有界私有目录；未认证、未授权、禁用或非控制节点均不能读取租户对象。
pub(super) async fn handle(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (mut request, body) = req.into_parts();
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    // 先冻结判权基线，凭据认证期间发生轮换时，响应复验会拒绝旧认证与新配置的混合结果。
    let snapshot = state.snap.load_full();
    let identity = match authenticate_admin_request(&request, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&request, &state) {
        return response;
    }
    if !snapshot.ownership.enabled() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    if request.method == Method::GET && request.uri.path() == "/api/workspaces" {
        return private(
            json(
                StatusCode::OK,
                serde_json::json!({
                    "workspaces":snapshot.ownership.list(&identity.principal_id)
                }),
            ),
            snapshot.config_fingerprint,
        );
    }
    let Some((workspace, endpoint)) = request
        .uri
        .path()
        .strip_prefix("/api/workspaces/")
        .and_then(|path| path.split_once('/'))
    else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    if !valid_token(workspace)
        || !snapshot.ownership.allows(
            &identity.principal_id,
            workspace,
            crate::control::ownership::config::Action::Read,
        )
    {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let workspace = workspace.to_owned();
    let endpoint = endpoint.to_owned();
    let watch = endpoint == "watch" && request.method == Method::GET;
    let runtime = if watch {
        &state.workspace_watches
    } else {
        &state.workspace_operations
    };
    let _permit = match runtime.acquire_admin(
        &snapshot.ownership,
        &workspace,
        if watch {
            1
        } else {
            2
        },
    ) {
        Ok(permit) => permit,
        Err(_) => {
            return plain(
                StatusCode::TOO_MANY_REQUESTS,
                "workspace operation capacity exhausted\n",
            )
        }
    };
    if request.method == Method::POST && review_path(request.uri.path()).is_some() {
        return review_pending_change(AdminRequest::from_parts(request, body), state.clone()).await;
    }
    if request.method == Method::POST && rollout_path(request.uri.path()).is_some() {
        return review_rollout(state.clone(), request, identity).await;
    }
    if request.method == Method::POST && endpoint == "changes" {
        return propose(&state, &mut request, body, identity, &workspace, snapshot).await;
    }
    if request.method != Method::GET {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    }
    if endpoint == "cluster/catalog" {
        return catalog::workspace::read(&state, &request, &identity, &snapshot, &workspace);
    }
    if endpoint == "monitor/routes" {
        return monitor::routes::read(&state, &request, &snapshot, Some(&workspace));
    }
    if endpoint == "monitor/services" {
        return monitor::services::read(&state, &request, &snapshot, Some(&workspace));
    }
    let Some((offset, limit)) = page(request.uri.query()) else {
        return plain(StatusCode::BAD_REQUEST, "invalid page parameters\n");
    };
    if watch {
        return watch_workspace(&state, &request, &workspace, snapshot.config_fingerprint).await;
    }
    if let Some(expected) = request.headers.get(hyper::header::IF_MATCH) {
        if snapshot
            .config_fingerprint
            .map(|fp| format!("\"{fp:016x}\""))
            .as_deref()
            != expected.to_str().ok()
        {
            return plain(
                StatusCode::PRECONDITION_FAILED,
                "workspace page generation changed\n",
            );
        }
    }
    let Some(binding) = snapshot.ownership.binding(&workspace) else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let value = match endpoint.as_str() {
        "objects" => {
            snapshot
                .ownership
                .objects_page(&identity.principal_id, &workspace, offset, limit)
        }
        "changes" => Some(serde_json::json!({
            "changes":state.approvals.workspace_snapshot(&binding.owner)
        })),
        "rollouts" => {
            let records = state.rollouts.inner.lock();
            Some(serde_json::json!({
                "rollouts":records.iter().filter(|record| record.workspace.as_ref().is_some_and(|scope| scope.binding.owner == binding.owner)).map(|record| serde_json::json!({
                    "id":record.id,
                    "phase":record.phase,
                    "base_version":record.base_version,
                    "initiator":record.initiator,
                    "approver":record.approver,
                    "candidate_etag":format!("\"sha256-{}\"",record.candidate_digest),
                    "workspace":record.workspace
                })).collect::<Vec<_>>()
            }))
        }
        "audit" => {
            let events = state.audit.workspace_snapshot(&binding.owner).await;
            // 不返回全局 sequence/HMAC，防止单工作区由链序号推算其它租户活动。
            let mut own: Vec<_> = events
                .into_iter()
                .filter_map(|event| {
                    event
                        .payload
                        .workspace
                        .as_ref()
                        .is_some_and(|audit| audit.binding.owner == binding.owner)
                        .then_some(event.payload)
                })
                .skip(offset)
                .take(limit + 1)
                .collect();
            let next_offset = (own.len() > limit).then_some(offset + limit);
            own.truncate(limit);
            if state.snap.load().version != snapshot.version {
                return plain(StatusCode::CONFLICT, "workspace authority changed\n");
            }
            Some(serde_json::json!({
                "events":own,
                "next_offset":next_offset
            }))
        }
        "export" => match state
            .config_history
            .read_archived(snapshot.version)
            .and_then(|docs| {
                crate::config::document::parse(
                    docs.gateway.as_bytes(),
                    crate::config::document::MAX_DOCUMENT_BYTES,
                )
            }) {
            Ok(document) => snapshot
                .ownership
                .export_page(&document, &identity.principal_id, &workspace, offset, limit)
                .ok(),
            Err(_) => return plain(StatusCode::CONFLICT, "workspace archive unavailable\n"),
        },
        _ => None,
    };
    // 异步审计读取、归档解析和其它读面都必须复验代际；撤权后不能交付旧快照形成的可见集合。
    if state.snap.load().version != snapshot.version {
        return plain(StatusCode::CONFLICT, "workspace authority changed\n");
    }
    let response = match value {
        Some(mut value) => {
            value["configuration_version"] = serde_json::json!(snapshot.version);
            json(StatusCode::OK, value)
        }
        None => plain(StatusCode::NOT_FOUND, "not found\n"),
    };
    private(response, snapshot.config_fingerprint)
}

/// 业务作用：只向工作区返回发布合同内的字段，防止集群节点地址、dataId、外部错误细节进入租户读面。
///
/// 参数说明：
/// - `response`：是同一发布链的内部响应。
///
/// 返回：保留 HTTP 状态与安全操作令牌的有界 JSON；内部错误文本统一隐藏。
pub(super) async fn publication_response(response: Response<BoxBody>) -> Response<BoxBody> {
    let status = response.status();
    let etag = response.headers().get(hyper::header::ETAG).cloned();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            bytes.clear();
            break;
        };
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > 64 * 1024 {
                bytes.clear();
                break;
            }
            bytes.extend_from_slice(&data);
        }
    }
    let value = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default();
    let mut safe = serde_json::json!({
        "ok":status.is_success()
    });
    for key in [
        "status",
        "version",
        "fingerprint",
        "etag",
        "rollout_id",
        "base_version",
        "candidate_etag",
    ] {
        if let Some(value) = value.get(key) {
            safe[key] = value.clone();
        }
    }
    if !status.is_success() {
        safe["error"] =
            serde_json::json!("workspace publication rejected; refresh authorized state");
    }
    let mut response = private(json(status, safe), None);
    if let Some(etag) = etag {
        response.headers_mut().insert(hyper::header::ETAG, etag);
    }
    response
}

/// 业务作用：解析固定的工作区 rollout 动作路径，避免 query 参数把操作引向另一发布域。
///
/// 参数说明：
/// - `path`：是原始 URI 路径。
///
/// 返回：合法的域、rollout id 和 approve/reject 动作；其它形态返回 None。
pub(super) fn rollout_path(path: &str) -> Option<(&str, &str, &str)> {
    let mut parts = path.strip_prefix("/api/workspaces/")?.split('/');
    let workspace = parts.next()?;
    if !valid_token(workspace) || parts.next()? != "rollouts" {
        return None;
    }
    let id = parts.next()?;
    let action = parts.next()?;
    if !valid_token(id) || !matches!(action, "approve" | "reject") || parts.next().is_some() {
        return None;
    }
    Some((workspace, id, action))
}

/// 业务作用：复验后台发布仍属于已批准的原始或候选权限图，成员撤销不能被旧 rollout 继续使用。
///
/// 参数说明：
/// - `state`：提供当前快照
/// - `record`：保存冻结 owner 与候选
/// - `principal`：为可选当前审批人。
///
/// 返回：平台记录保持旧语义；工作区图、owner 与角色全部匹配才允许继续。
pub(super) fn rollout_authority(
    state: &AdminState,
    record: &RolloutRecord,
    principal: Option<&str>,
) -> bool {
    let Some(scope) = &record.workspace else {
        return true;
    };
    let current = state.snap.load();
    let workspace = &scope.binding.owner.workspace;
    let Some(binding) = current.ownership.binding(workspace) else {
        return false;
    };
    (binding == scope.binding || record.candidate_authority.as_ref() == Some(&binding))
        && scope.approved_by.as_deref().is_some_and(|principal| {
            current.ownership.allows(
                principal,
                workspace,
                crate::control::ownership::config::Action::Review,
            )
        })
        && principal
            .or(record.approver.as_deref())
            .is_none_or(|principal| {
                current.ownership.allows(
                    principal,
                    workspace,
                    crate::control::ownership::config::Action::Review,
                )
            })
}

/// 业务作用：确保平台旧动作入口和其它工作区不能消费工作区 rollout 的执行权。
///
/// 参数说明：
/// - `request`：当前动作路径与权限请求。
/// - `identity`：已认证调用主体。
/// - `state`：提供当前配置与角色目录的管理状态。
/// - `record`：目标渐进发布的冻结记录。
///
/// 返回：路径归属、当前角色和冻结权威都匹配才返回 true。
pub(super) fn rollout_action_allowed(
    request: &AdminRequestParts,
    identity: &AdminIdentity,
    state: &AdminState,
    record: &RolloutRecord,
) -> bool {
    match &record.workspace {
        Some(scope) => {
            rollout_path(request.uri.path())
                .is_some_and(|(workspace, _, _)| workspace == scope.binding.owner.workspace)
                && rollout_authority(state, record, Some(&identity.principal_id))
        }
        None => rollout_path(request.uri.path()).is_none(),
    }
}

/// 业务作用：以本域权限和持久审计驱动既有集群审批状态机，不授予平台 Config/Write。
///
/// 参数说明：
/// - `state`：为管理状态
/// - `request`：提供候选 ETag
/// - `identity`：为已认证主体。
///
/// 返回：唯一阶段转换结果；越权或审计不可用不执行外部动作。
fn review_rollout(
    state: Arc<AdminState>,
    mut request: AdminRequestParts,
    identity: AdminIdentity,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<BoxBody>> + Send>> {
    Box::pin(async move {
        let (_, id, action) = rollout_path(request.uri.path()).expect("validated rollout path");
        let action = action.to_owned();
        let Some(record) = state.rollouts.get(id) else {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        };
        if !rollout_action_allowed(&request, &identity, &state, &record) {
            return plain(StatusCode::FORBIDDEN, "workspace rollout action denied\n");
        }
        if let Some(scope) = record.workspace {
            request.extensions.insert(scope);
        }
        if record_admin_audit(
            &state,
            &identity,
            &request,
            AdminResource::Config,
            AdminAction::Write,
            "attempt",
            None,
        )
        .await
        .is_err()
        {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n");
        }
        let result = if action == "approve" {
            approve_cluster_rollout(&request, &identity, state.clone()).await
        } else {
            reject_cluster_rollout(&request, &identity, state.clone()).await
        };
        let result = publication_response(result).await;
        finish_config_write(&state, &identity, &request, AdminResource::Config, result).await
    })
}

/// 业务作用：将已授权的工作区声明变成完整候选并登记双人审批，不直接改事实源。
///
/// 参数说明：
/// - `state`：工作区管理状态与持久审计依赖。
/// - `parts`：已认证请求头与路径。
/// - `body`：按预算读取的 JSON 请求体。
/// - `identity`：冻结的本次调用主体。
/// - `workspace`：已经授权的工作区范围。
/// - `snapshot`：本次判权使用的配置快照。
///
/// 返回：完整构建、持久审计、基线复验和容量均成功才返回 202；任一拒绝没有配置副作用。
async fn propose(
    state: &Arc<AdminState>,
    parts: &mut AdminRequestParts,
    body: axum::body::Body,
    identity: AdminIdentity,
    workspace: &str,
    snapshot: Arc<GatewaySnapshot>,
) -> Response<BoxBody> {
    use crate::control::ownership::{config::Action, mutation::Mutation};
    if !snapshot.admin_approval.enabled
        || !snapshot
            .ownership
            .allows(&identity.principal_id, workspace, Action::Write)
    {
        return plain(
            StatusCode::FORBIDDEN,
            "workspace write requires approval and operator authority\n",
        );
    }
    let Some(fingerprint) = snapshot.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "configuration fingerprint unavailable\n",
        );
    };
    let expected = format!("\"{fingerprint:016x}\"");
    if parts
        .headers
        .get_all(hyper::header::IF_MATCH)
        .iter()
        .count()
        != 1
        || parts
            .headers
            .get(hyper::header::IF_MATCH)
            .and_then(|value| value.to_str().ok())
            != Some(expected.as_str())
    {
        return plain(
            StatusCode::PRECONDITION_FAILED,
            "If-Match must match the workspace ETag\n",
        );
    }
    if !request_content_type(parts, "application/json") {
        return plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json required\n",
        );
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        collect_bounded_admin_body(parts, body, 64 * 1024),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return plain(StatusCode::BAD_REQUEST, "invalid workspace action body\n"),
    };
    let mutation: Mutation = match serde_json::from_slice(&bytes) {
        Ok(mutation) => mutation,
        Err(_) => return plain(StatusCode::BAD_REQUEST, "invalid workspace action\n"),
    };
    if !current_config_baseline_matches(state, snapshot.version, fingerprint).await {
        return plain(StatusCode::PRECONDITION_FAILED, "configuration changed\n");
    }
    let baseline = match state.config_history.read_archived(snapshot.version) {
        Ok(baseline) => baseline,
        Err(_) => return plain(StatusCode::CONFLICT, "configuration archive unavailable\n"),
    };
    let mut document = match crate::config::document::parse(
        baseline.gateway.as_bytes(),
        crate::config::document::MAX_DOCUMENT_BYTES,
    ) {
        Ok(document) => document,
        Err(_) => return plain(StatusCode::CONFLICT, "configuration archive invalid\n"),
    };
    let applied = match mutation {
        Mutation::Rollback {
            object,
            version,
        } => (|| -> anyhow::Result<()> {
            let archive = state.config_history.read_archived(version)?;
            let previous = crate::config::document::parse(
                archive.gateway.as_bytes(),
                crate::config::document::MAX_DOCUMENT_BYTES,
            )?;
            let config: crate::config::model::GatewayConfig =
                serde_json::from_value(previous.clone())?;
            let old_ownership = crate::control::ownership::OwnershipCatalog::build(&config)?;
            snapshot.ownership.rollback_object(
                &mut document,
                &previous,
                &old_ownership,
                &identity.principal_id,
                workspace,
                &object,
            )
        })(),
        mutation => {
            snapshot
                .ownership
                .mutate(&mut document, &identity.principal_id, workspace, mutation)
        }
    };
    if applied.is_err() {
        return plain(
            StatusCode::FORBIDDEN,
            "workspace action is outside delegated authority\n",
        );
    }
    let gateway = match crate::config::document::encode(
        &document,
        crate::config::document::MAX_DOCUMENT_BYTES,
    ) {
        Ok(gateway) => gateway,
        Err(_) => {
            return plain(
                StatusCode::BAD_REQUEST,
                "workspace candidate exceeds budget\n",
            )
        }
    };
    let target = crate::control::history::ArchivedDocs {
        gateway,
        interface_guard: baseline.interface_guard.clone(),
        sentinel_rules: baseline.sentinel_rules.clone(),
    };
    let binding = snapshot
        .ownership
        .binding(workspace)
        .expect("authorized workspace exists");
    let payload = ApprovalPayload::WorkspaceDocuments {
        binding: binding.clone(),
        target: target.clone(),
        baseline: baseline.clone(),
    };
    let digest = approval_payload_digest(&payload);
    parts.extensions.insert(audit::WorkspaceAudit {
        binding,
        candidate_sha256: digest,
        approved_by: None,
    });
    // 候选归属和摘要先进入持久审计，再允许完整 builder 读取扩展或外部依赖。
    if record_admin_audit(
        state,
        &identity,
        parts,
        AdminResource::Config,
        AdminAction::Write,
        "attempt",
        None,
    )
    .await
    .is_err()
    {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n");
    }
    let response = if let Err(error) = validate_cluster_candidate(state, &target).await {
        error.policy_response("workspace candidate violates gateway ownership or resource policy\n")
    } else if !current_config_baseline_matches(state, snapshot.version, fingerprint).await {
        plain(StatusCode::PRECONDITION_FAILED, "configuration changed\n")
    } else {
        let prepared = PreparedConfigWrite {
            identity: AdminIdentity {
                principal_id: identity.principal_id.clone(),
                permissions: Some(0),
            },
            baseline,
            base_version: snapshot.version,
            base_fingerprint: fingerprint,
        };
        submit_approval_change(state, &prepared, AdminResource::Config, payload)
    };
    private(
        finish_config_write(state, &identity, parts, AdminResource::Config, response).await,
        None,
    )
}

/// 业务作用：限制目录查询的参数集合与单页预算，不接受模糊或重复的分页权威。
///
/// 参数说明：
/// - `query`：为原始 URL 查询。
///
/// 返回：合法偏移与页长；未知、重复或越界参数返回 None。
fn page(query: Option<&str>) -> Option<(usize, usize)> {
    let mut offset = None;
    let mut limit = None;
    let query = query.unwrap_or_default();
    if query.len() > 128 {
        return None;
    }
    for entry in query.split('&').filter(|entry| !entry.is_empty()) {
        let (key, value) = entry.split_once('=')?;
        let target = match key {
            "offset" => &mut offset,
            "limit" => &mut limit,
            _ => return None,
        };
        if target.is_some() {
            return None;
        }
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *target = Some(value.parse::<usize>().ok()?);
    }
    let (offset, limit) = (offset.unwrap_or(0), limit.unwrap_or(128));
    (offset <= 65_536 && (1..=128).contains(&limit)).then_some((offset, limit))
}

/// 业务作用：提供限时、每域独立限额的配置长轮询，权限撤销后不继续发送旧域状态。
///
/// 参数说明：
/// - `state`：为常驻管理状态
/// - `request`：保留认证凭据
/// - `workspace`：为已授权域
/// - `fingerprint`：为起始代际。
///
/// 返回：最多等待十秒；代际改变返回新本域摘要，无变化返回 304，撤权立即拒绝。
async fn watch_workspace(
    state: &AdminState,
    request: &AdminRequestParts,
    workspace: &str,
    fingerprint: Option<u64>,
) -> Response<BoxBody> {
    let expected = request
        .headers
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    let initial = fingerprint.map(|value| format!("\"{value:016x}\""));
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let identity = match authenticate_admin_request(request, state) {
            Ok(identity) => identity,
            Err(response) => return *response,
        };
        let current = state.snap.load_full();
        if !current.ownership.allows(
            &identity.principal_id,
            workspace,
            crate::control::ownership::config::Action::Read,
        ) {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        }
        if expected != initial.as_deref() || current.config_fingerprint != fingerprint {
            return private(
                json(
                    StatusCode::OK,
                    current
                        .ownership
                        .objects(&identity.principal_id, workspace)
                        .expect("authorized workspace"),
                ),
                current.config_fingerprint,
            );
        }
        if tokio::time::Instant::now() >= until {
            return private(
                plain(StatusCode::NOT_MODIFIED, ""),
                current.config_fingerprint,
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// 业务作用：识别固定工作区审批路径，不能通过额外层级或编码路径把候选映射到另一域。
///
/// 参数说明：
/// - `path`：为不含 query 的原始管理路径。
///
/// 返回：合法路径中的工作区、change id 和动作；其它形态返回 None。
pub(super) fn review_path(path: &str) -> Option<(&str, &str, &str)> {
    let mut parts = path.strip_prefix("/api/workspaces/")?.split('/');
    let workspace = parts.next()?;
    if !valid_token(workspace) || parts.next()? != "changes" {
        return None;
    }
    let id = parts.next()?;
    let action = parts.next()?;
    if !valid_token(id) || !matches!(action, "approve" | "reject") || parts.next().is_some() {
        return None;
    }
    Some((workspace, id, action))
}

/// 业务作用：限制管理路径标识，保持配置 id 与 URL 段一一对应。
///
/// 参数说明：
/// - `value`：是单个路径段。
///
/// 返回：安全 ASCII 短标识有效，其它返回 false。
fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// 业务作用：禁止浏览器或中间代理共享工作区响应，并为声明编辑提供整体配置 CAS 基线。
///
/// 参数说明：
/// - `response`：为已授权响应
/// - `fingerprint`：为同代配置集指纹。
///
/// 返回：带 private/no-store 与可选 ETag 的响应。
fn private(mut response: Response<BoxBody>, fingerprint: Option<u64>) -> Response<BoxBody> {
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    if let Some(fingerprint) = fingerprint {
        response.headers_mut().insert(
            hyper::header::ETAG,
            HeaderValue::from_str(&format!("\"{fingerprint:016x}\""))
                .expect("hex fingerprint header"),
        );
    }
    response
}
