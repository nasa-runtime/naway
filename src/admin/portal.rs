//! 门户自助应用变更只登记既有 maker-checker 候选，不建立第二条配置发布通道。

use super::*;
use crate::portal::management::{
    Actor, ApplicationCfg, ApplicationState, Authentication, Credential, Role, Subscription,
};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Register {
        id: String,
        team: String,
        title: String,
        plan: String,
        #[serde(default)]
        redirect_uris: BTreeSet<String>,
        #[serde(default)]
        subscriptions: Vec<Subscription>,
    },
    Update {
        title: String,
        plan: String,
        redirect_uris: BTreeSet<String>,
        subscriptions: Vec<Subscription>,
    },
    Transfer {
        team: String,
    },
    Revoke,
    CreateCredential {
        id: String,
    },
    RotateCredential {
        id: String,
        replacement: String,
    },
    RevokeCredential {
        id: String,
    },
}

/// 业务作用：隔离门户 SSO、自助读面和应用申请；管理凭据不能作为开发者身份隐式透传。
///
/// 参数说明：
/// - `req`：是原始请求
/// - `state`：提供快照、完整归档、审批和持久审计。
///
/// 返回：已验证团队范围内的低敏读面或待审批结果；任何直接发布路径均不可达。
pub(super) async fn handle(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let snapshot = state.snap.load_full();
    let Some(management) = snapshot.developer_portal.management.as_ref() else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let (mut parts, body) = req.into_parts();
    let callback = parts.uri.path() == "/api/developer/account/callback";
    let mut body = Some(body);
    let saml = if callback && parts.method == Method::POST {
        if !matches!(
            management.cfg.sso,
            crate::portal::management::SsoCfg::Saml {
                ..
            }
        ) || !request_content_type(&parts, "application/x-www-form-urlencoded")
        {
            return plain(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid identity binding\n",
            );
        }
        let bytes = match tokio::time::timeout(
            Duration::from_secs(5),
            collect_bounded_admin_body(&parts, body.take().expect("body owned"), 256 * 1024),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            _ => return plain(StatusCode::BAD_REQUEST, "invalid identity body\n"),
        };
        let values: Vec<_> = form_urlencoded::parse(&bytes).collect();
        if values.len() != 1 || values[0].0 != "SAMLResponse" {
            return plain(StatusCode::BAD_REQUEST, "invalid identity form\n");
        }
        Some(values[0].1.to_string())
    } else {
        None
    };
    let actor = match management
        .authenticate(&parts, saml.as_deref(), &state.portal_saml_replay)
        .await
    {
        Authentication::Actor(actor) => actor,
        Authentication::Response(response) => return response,
    };
    // 认证外呼可能跨过一次配置发布；旧身份映射和会话不能在新代上继续申请变更或读取应用。
    if state.snap.load().version != snapshot.version {
        return plain(StatusCode::CONFLICT, "portal policy changed\n");
    }
    let path = parts.uri.path();
    if parts.method == Method::GET && path == "/api/developer/account/login" {
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(hyper::header::LOCATION, "/developer")
            .header(hyper::header::CACHE_CONTROL, "private, no-store")
            .body(full_body(Bytes::new()))
            .expect("fixed portal redirect");
    }
    if parts.method == Method::GET
        && matches!(
            path,
            "/api/developer/account/usage" | "/api/developer/account/usage/export"
        )
    {
        let export = path.ends_with("/export");
        let applications = management.usage_applications(&actor, export);
        let query: Vec<_> =
            form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes()).collect();
        if query.len() > 1 || query.first().is_some_and(|(key, _)| key != "cursor") {
            return plain(StatusCode::BAD_REQUEST, "invalid usage query\n");
        }
        let cursor = query.first().map(|(_, value)| value.as_ref());
        let result = state.usage_meter.query(&applications, export, cursor).await;
        // 用量响应外呼期间可能撤销角色；旧授权不能把已取得的事实发布给客户端。
        if state.snap.load().version != snapshot.version {
            return plain(StatusCode::CONFLICT, "portal policy changed\n");
        }
        let mut response = match result {
            Ok(usage) => json(
                StatusCode::OK,
                serde_json::json!({
                    "ok":true,
                    "usage":usage
                }),
            ),
            Err(_) => plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "usage source unavailable\n",
            ),
        };
        response.headers_mut().insert(
            hyper::header::CACHE_CONTROL,
            http::HeaderValue::from_static("private, no-store"),
        );
        return response;
    }
    if parts.method == Method::GET && path.starts_with("/api/developer/account/products") {
        let products = &snapshot.developer_portal.products;
        let teams = actor.roles.keys().map(String::as_str).collect();
        if path == "/api/developer/account/products" {
            let mut response = json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "products": products.team_json(&teams)
                }),
            );
            response.headers_mut().insert(
                hyper::header::CACHE_CONTROL,
                http::HeaderValue::from_static("private, no-store"),
            );
            return response;
        }
        let Some((product, version, document)) =
            product_document_path(path, "/api/developer/account/products/")
        else {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        };
        let Some(document) = products.team_document(product, version, document, &teams) else {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, document.content_type)
            .header(hyper::header::CACHE_CONTROL, "private, no-store")
            .header("x-content-type-options", "nosniff")
            .header(
                "content-security-policy",
                "default-src 'none'; sandbox; frame-ancestors 'none'",
            )
            .body(full_body(document.body.clone()))
            .expect("bounded team document response");
    }
    if parts.method == Method::GET
        && matches!(
            path,
            "/api/developer/account" | "/api/developer/account/applications"
        )
    {
        let mut response = json(
            StatusCode::OK,
            serde_json::json!({
                "ok":true,
                "principal":actor.principal.as_ref(),
                "roles":actor.roles,
                "applications":management.applications(&actor),
                "etag":snapshot.config_fingerprint.map(config_etag)
            }),
        );
        response.headers_mut().insert(
            hyper::header::CACHE_CONTROL,
            http::HeaderValue::from_static("private, no-store"),
        );
        return response;
    }
    if parts.method != Method::POST {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let application = if path == "/api/developer/account/applications" {
        None
    } else {
        let Some(id) = path
            .strip_prefix("/api/developer/account/applications/")
            .and_then(|s| s.strip_suffix("/actions"))
        else {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        };
        if !valid_consumer_id(id) {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        }
        Some(id.to_owned())
    };
    // 门户会话由浏览器自动携带，写操作必须有明确可信 Origin，不采用 CLI 缺 Origin 放行语义。
    if parts.headers.get_all(hyper::header::ORIGIN).iter().count() != 1
        || !parts
            .headers
            .get(hyper::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                management
                    .cfg
                    .allowed_origins
                    .iter()
                    .any(|origin| origin == v)
            })
    {
        return plain(StatusCode::FORBIDDEN, "untrusted portal origin\n");
    }
    let Some(fingerprint) = snapshot.config_fingerprint else {
        return plain(StatusCode::CONFLICT, "configuration baseline unavailable\n");
    };
    let expected = config_etag(fingerprint);
    match parts
        .headers
        .get(hyper::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        None => return plain(StatusCode::PRECONDITION_REQUIRED, "If-Match required\n"),
        Some(value) if value != expected => {
            return plain(StatusCode::PRECONDITION_FAILED, "configuration changed\n")
        }
        _ => {}
    }
    if !request_content_type(&parts, "application/json") {
        return plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json required\n",
        );
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        collect_bounded_admin_body(&parts, body.take().expect("JSON body owned"), 64 * 1024),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return plain(StatusCode::BAD_REQUEST, "invalid application body\n"),
    };
    let action: Action = match serde_json::from_slice(&bytes) {
        Ok(action) => action,
        Err(_) => return plain(StatusCode::BAD_REQUEST, "invalid application action\n"),
    };
    let identity = AdminIdentity {
        principal_id: actor.principal.clone(),
        permissions: Some(0),
    };
    // 审计成功和基线复验必须先于生成凭据和登记审批；调用失败不能留下已生效的半份应用配置。
    if record_admin_audit(
        &state,
        &identity,
        &parts,
        AdminResource::Consumers,
        AdminAction::Write,
        "attempt",
        None,
    )
    .await
    .is_err()
    {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n");
    }
    let result = propose(
        &state,
        &mut parts,
        &actor,
        application.as_deref(),
        action,
        snapshot.version,
        fingerprint,
    )
    .await;
    finish_config_write(&state, &identity, &parts, AdminResource::Consumers, result).await
}

/// 业务作用：将团队授权后的应用动作变成完整候选，复用全量构建、CAS 与既有双人审批。
///
/// 参数说明：
/// - `state`：门户与审批依赖所在管理状态。
/// - `parts`：当前已认证请求头与路径。
/// - `actor`：冻结的门户主体。
/// - `application`：目标应用。
/// - `action`：经过验证的有界申请动作。
/// - `version`：申请绑定的配置基线版本。
/// - `fingerprint`：申请绑定的完整配置指纹。
///
/// 返回：只返回待审批令牌，凭据创建可一次返回尚未生效的高熵 key；失败不修改事实源。
async fn propose(
    state: &Arc<AdminState>,
    parts: &mut AdminRequestParts,
    actor: &Actor,
    application: Option<&str>,
    action: Action,
    version: u64,
    fingerprint: u64,
) -> Response<BoxBody> {
    if !current_config_baseline_matches(state, version, fingerprint).await {
        return plain(StatusCode::PRECONDITION_FAILED, "configuration changed\n");
    }
    let ownership = state.snap.load().ownership.clone();
    let binding = if ownership.enabled() {
        let key = match &action {
            Action::Register {
                team,
                ..
            } => format!("team:{team}"),
            _ => format!("application:{}", application.unwrap_or_default()),
        };
        let Some(owner) = ownership.object_owner(&key) else {
            return plain(StatusCode::FORBIDDEN, "application owner unavailable\n");
        };
        if let Action::Transfer {
            team,
        } = &action
        {
            // 单域审批不能转移另一域的控制权；跨域所有权迁移只能由平台完整配置流程裁决。
            if ownership.object_owner(&format!("team:{team}")) != Some(owner) {
                return plain(
                    StatusCode::FORBIDDEN,
                    "cross-workspace application transfer denied\n",
                );
            }
        }
        ownership.binding(&owner.workspace)
    } else {
        None
    };
    let _permit = match binding.as_ref() {
        Some(binding) => {
            match state
                .workspace_operations
                .acquire_admin(&ownership, &binding.owner.workspace, 2)
            {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return plain(
                        StatusCode::TOO_MANY_REQUESTS,
                        "workspace operation capacity exhausted\n",
                    )
                }
            }
        }
        None => None,
    };
    let baseline = match state.config_history.read_archived(version) {
        Ok(docs) => docs,
        Err(_) => return plain(StatusCode::CONFLICT, "configuration archive unavailable\n"),
    };
    let mut document = match crate::config::document::parse(
        baseline.gateway.as_bytes(),
        crate::config::document::MAX_DOCUMENT_BYTES,
    ) {
        Ok(doc) => doc,
        Err(_) => return plain(StatusCode::CONFLICT, "configuration archive invalid\n"),
    };
    let Some(management) = document
        .get_mut("developer_portal")
        .and_then(|v| v.get_mut("management"))
    else {
        return plain(StatusCode::CONFLICT, "portal configuration unavailable\n");
    };
    let mut policy: crate::portal::management::ManagementCfg =
        match serde_json::from_value(management.clone()) {
            Ok(cfg) => cfg,
            Err(_) => return plain(StatusCode::CONFLICT, "portal configuration invalid\n"),
        };
    let secret = match mutate(&mut policy.applications, actor, application, action) {
        Ok(secret) => secret,
        Err(status) => return plain(status, "application action denied\n"),
    };
    management["applications"] = match serde_json::to_value(&policy.applications) {
        Ok(value) => value,
        Err(_) => {
            return plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "candidate encoding failed\n",
            )
        }
    };
    let gateway = match crate::config::document::encode(
        &document,
        crate::config::document::MAX_DOCUMENT_BYTES,
    ) {
        Ok(doc) => doc,
        Err(_) => return plain(StatusCode::BAD_REQUEST, "candidate budget exceeded\n"),
    };
    let target = crate::control::history::ArchivedDocs {
        gateway,
        interface_guard: baseline.interface_guard.clone(),
        sentinel_rules: baseline.sentinel_rules.clone(),
    };
    let payload = match binding {
        Some(binding) => ApprovalPayload::WorkspaceDocuments {
            binding,
            target: target.clone(),
            baseline: baseline.clone(),
        },
        None => ApprovalPayload::Documents {
            target: target.clone(),
            baseline: baseline.clone(),
        },
    };
    if let ApprovalPayload::WorkspaceDocuments {
        binding,
        ..
    } = &payload
    {
        parts.extensions.insert(audit::WorkspaceAudit {
            binding: binding.clone(),
            candidate_sha256: approval_payload_digest(&payload),
            approved_by: None,
        });
        let identity = AdminIdentity {
            principal_id: actor.principal.clone(),
            permissions: Some(0),
        };
        if record_admin_audit(
            state,
            &identity,
            parts,
            AdminResource::Consumers,
            AdminAction::Write,
            "attempt",
            None,
        )
        .await
        .is_err()
        {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n");
        }
    }
    if let Err(error) = validate_cluster_candidate(state, &target).await {
        return error.policy_response("application candidate violates product or gateway policy\n");
    }
    if !current_config_baseline_matches(state, version, fingerprint).await {
        return plain(StatusCode::PRECONDITION_FAILED, "configuration changed\n");
    }
    let prepared = PreparedConfigWrite {
        identity: AdminIdentity {
            principal_id: actor.principal.clone(),
            permissions: Some(0),
        },
        baseline: baseline.clone(),
        base_version: version,
        base_fingerprint: fingerprint,
    };
    let response = submit_approval_change(state, &prepared, AdminResource::Consumers, payload);
    match secret {
        Some((key, id)) if response.status() == StatusCode::ACCEPTED => {
            inject_created_api_key(response, key, id).await
        }
        _ => response,
    }
}

/// 业务作用：在应用副本上执行最小角色授权与状态迁移，所有凭据变更保持摘要与撤销同一候选原子提交。
///
/// 参数说明：
/// - `apps`：是副本
/// - `actor`：的角色不可由动作覆盖
/// - `target`：是路径身份
/// - `action`：是期望变更。
///
/// 返回：无凭据动作返回 None；创建/轮换返回一次性原文及 key id；拒绝不发布该副本。
fn mutate(
    apps: &mut Vec<ApplicationCfg>,
    actor: &Actor,
    target: Option<&str>,
    action: Action,
) -> Result<Option<(String, String)>, StatusCode> {
    let permits =
        |team: &str, role: Role| actor.roles.get(team).is_some_and(|actual| *actual >= role);
    if let Action::Register {
        id,
        team,
        title,
        plan,
        redirect_uris,
        subscriptions,
    } = action
    {
        if target.is_some() || !permits(&team, Role::Developer) {
            return Err(StatusCode::FORBIDDEN);
        }
        if id.len() > 48
            || !valid_consumer_id(&id)
            || apps.len() >= 4096
            || apps.iter().any(|app| app.id == id)
        {
            return Err(StatusCode::CONFLICT);
        }
        let app = ApplicationCfg {
            consumer: format!("portal-app-{id}"),
            id,
            team,
            title,
            plan,
            redirect_uris,
            subscriptions,
            credentials: Vec::new(),
            state: ApplicationState::Active,
        };
        crate::portal::management::validate_application(&app)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        apps.push(app);
        return Ok(None);
    }
    let app = apps
        .iter_mut()
        .find(|app| Some(app.id.as_str()) == target && actor.roles.contains_key(&app.team))
        .ok_or(StatusCode::NOT_FOUND)?;
    if !permits(&app.team, Role::Developer) {
        return Err(StatusCode::FORBIDDEN);
    }
    if app.state != ApplicationState::Active {
        return Err(StatusCode::CONFLICT);
    }
    let mut secret = None;
    match action {
        Action::Update {
            title,
            plan,
            redirect_uris,
            subscriptions,
        } => {
            app.title = title;
            app.plan = plan;
            app.redirect_uris = redirect_uris;
            app.subscriptions = subscriptions;
        }
        Action::Transfer {
            team,
        } => {
            // 转移同时要求原团队与目标团队 owner，不能用自己有权的目标团队夺取别人的应用。
            if !permits(&app.team, Role::Owner) || !permits(&team, Role::Owner) {
                return Err(StatusCode::FORBIDDEN);
            }
            app.team = team;
        }
        Action::Revoke => {
            if !permits(&app.team, Role::Owner) {
                return Err(StatusCode::FORBIDDEN);
            }
            app.state = ApplicationState::Revoked;
            for key in &mut app.credentials {
                key.revoked = true;
            }
        }
        Action::CreateCredential {
            id,
        } => {
            secret = Some(create_credential(app, id)?);
        }
        Action::RotateCredential {
            id,
            replacement,
        } => {
            let old = app
                .credentials
                .iter_mut()
                .find(|key| key.id == id && !key.revoked)
                .ok_or(StatusCode::NOT_FOUND)?;
            old.revoked = true;
            secret = Some(create_credential(app, replacement)?);
        }
        Action::RevokeCredential {
            id,
        } => {
            app.credentials
                .iter_mut()
                .find(|key| key.id == id)
                .ok_or(StatusCode::NOT_FOUND)?
                .revoked = true;
        }
        Action::Register {
            ..
        } => unreachable!(),
    }
    crate::portal::management::validate_application(app).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(secret)
}

/// 业务作用：生成高熵 API key 并仅将摘要加入候选，原文不进入配置归档和审批记录。
///
/// 参数说明：
/// - `app`：是尚未发布应用
/// - `id`：为团队选择的有界凭据身份。
///
/// 返回：一次性原文与身份；容量、重复身份或随机源失败时拒绝。
fn create_credential(app: &mut ApplicationCfg, id: String) -> Result<(String, String), StatusCode> {
    if !valid_consumer_id(&id)
        || app.credentials.len() >= 16
        || app.credentials.iter().any(|key| key.id == id)
    {
        return Err(StatusCode::CONFLICT);
    }
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let key = format!(
        "nwy_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    app.credentials.push(Credential {
        id: id.clone(),
        sha256: nasa::crypto::sha256_cased(&key, false),
        revoked: false,
    });
    Ok((key, id))
}
