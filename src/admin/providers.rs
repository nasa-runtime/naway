//! 来源管理仅读取已授权的同代声明；候选验证与导出均没有向事实源写入的能力。

use super::*;
use crate::control::ownership::{config::Action, Owner, PLATFORM};
use crate::control::providers::{Input, Snapshot};

type Leases = Arc<(
    tokio::sync::SemaphorePermit<'static>,
    Option<crate::control::ownership::admission::Permit>,
)>;
static OPERATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// 业务作用：为来源状态、解释、导出和候选差异执行认证、归属、预算与最终撤权复验。
///
/// 参数说明：
/// - `req`：为管理请求
/// - `state`：共享当前完整配置与权限。
///
/// 返回：有界私有读模型；未授权来源隐藏存在性，候选只构建不发布也不连接远端来源。
pub(super) async fn handle(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let active = state.snap.load_full();
    let Some(providers) = active.providers.clone() else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let Ok(global) = OPERATIONS.try_acquire() else {
        return plain(
            StatusCode::TOO_MANY_REQUESTS,
            "source operation capacity exhausted\n",
        );
    };
    if parts.uri.path() == "/api/providers" {
        if parts.method != Method::GET {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        }
        if parts.uri.query().is_some() {
            return plain(StatusCode::BAD_REQUEST, "unexpected query\n");
        }
        let sources: Vec<_> = providers
            .owners()
            .filter(|(_, owner)| allowed(&active, &identity, owner, false))
            .filter_map(|(id, _)| providers.summary(id))
            .collect();
        if state.snap.load().version != active.version {
            return plain(StatusCode::CONFLICT, "source authority changed\n");
        }
        let mut value = serde_json::json!({
            "sources":sources
        });
        if identity.allows(AdminResource::Config, AdminAction::Read) {
            value["federation_digest"] = serde_json::json!(providers.federation_digest());
        }
        return response(json(StatusCode::OK, value), None, Arc::new((global, None)));
    }
    let fields: Vec<_> = parts
        .uri
        .path()
        .trim_start_matches("/api/providers/")
        .split('/')
        .collect();
    if fields.len() != 2 || !valid_id(fields[0]) {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let (id, endpoint) = (fields[0], fields[1]);
    let candidate = matches!(endpoint, "dry-run" | "diff");
    if !matches!(
        endpoint,
        "status" | "explain" | "export" | "dry-run" | "diff"
    ) {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    if parts.method
        != if candidate {
            Method::POST
        } else {
            Method::GET
        }
    {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    }
    let Some((_, owner)) = providers.owners().find(|(source, _)| *source == id) else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    // 不因名称命中就暴露来源；工作区写者只能验证本域候选，不能取得平台配置编辑权。
    if !allowed(&active, &identity, owner, candidate) {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let local = if owner.workspace == PLATFORM {
        None
    } else {
        match state
            .workspace_operations
            .acquire_admin(&active.ownership, &owner.workspace, 2)
        {
            Ok(permit) => Some(permit),
            Err(_) => {
                return plain(
                    StatusCode::TOO_MANY_REQUESTS,
                    "workspace operation capacity exhausted\n",
                )
            }
        }
    };
    let leases = Arc::new((global, local));
    let expected = providers.etag(id).expect("known source");
    let (offset, limit) = match page(parts.uri.query()) {
        Some(value) => value,
        None => return plain(StatusCode::BAD_REQUEST, "invalid page parameters\n"),
    };
    if endpoint != "explain" && parts.uri.query().is_some() {
        return plain(StatusCode::BAD_REQUEST, "unexpected query\n");
    }
    let if_match = parts
        .headers
        .get(hyper::header::IF_MATCH)
        .and_then(|value| value.to_str().ok());
    if (candidate || endpoint == "export" || offset != 0) && if_match.is_none() {
        return response(
            plain(
                StatusCode::PRECONDITION_REQUIRED,
                "source If-Match required\n",
            ),
            Some(&expected),
            leases,
        );
    }
    if if_match.is_some_and(|value| value != expected) {
        return response(
            plain(
                StatusCode::PRECONDITION_FAILED,
                "source declaration changed\n",
            ),
            Some(&expected),
            leases,
        );
    }
    if (candidate || endpoint == "export")
        && record_admin_audit(
            &state,
            &identity,
            &parts,
            AdminResource::Config,
            if candidate {
                AdminAction::DryRun
            } else {
                AdminAction::Read
            },
            "provider_read",
            None,
        )
        .await
        .is_err()
    {
        return response(
            plain(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n"),
            None,
            leases,
        );
    }
    let result = if candidate {
        validate_candidate(
            &state,
            &parts,
            body,
            active.clone(),
            providers.clone(),
            id,
            leases.clone(),
        )
        .await
    } else {
        drop(body);
        match endpoint {
            "status" => json(StatusCode::OK, providers.summary(id).expect("known source")),
            "explain" => json(
                StatusCode::OK,
                providers.explain(id, offset, limit).expect("known source"),
            ),
            "export" => match providers.export(id) {
                Ok(value) => json(StatusCode::OK, value),
                Err(_) => plain(
                    StatusCode::CONFLICT,
                    "source cannot be replayed within current version or object budget\n",
                ),
            },
            _ => unreachable!(),
        }
    };
    let current = state.snap.load_full();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(_) => return response(plain(StatusCode::NOT_FOUND, "not found\n"), None, leases),
    };
    let visible = current.providers.as_ref().is_some_and(|now| {
        now.owners().any(|(source, current_owner)| {
            source == id
                && current_owner == owner
                && allowed(&current, &identity, current_owner, candidate)
        })
    });
    // 审计或完整构建可能跨过撤权；交付前复验 owner、成员关系及来源语义，旧候选不能泄露撤权前声明。
    if !visible {
        return response(plain(StatusCode::NOT_FOUND, "not found\n"), None, leases);
    }
    if current
        .providers
        .as_ref()
        .and_then(|now| now.etag(id))
        .as_deref()
        != Some(expected.as_str())
        || !current
            .providers
            .as_ref()
            .is_some_and(|now| now.same_authority(&providers))
    {
        return response(
            plain(
                StatusCode::CONFLICT,
                "source authority or declaration changed\n",
            ),
            None,
            leases,
        );
    }
    response(result, Some(&expected), leases)
}

/// 业务作用：只允许全平台显式权限或本域成员动作，不把 workspace reader 提升为全局管理员。
///
/// 参数说明：
/// - `snapshot`：是当前归属与认证
/// - `identity`：是当前归属与认证
/// - `owner`：为来源本地权威
/// - `candidate`：区分只读与候选验证。
///
/// 返回：授权成立才允许读取来源或构建候选。
fn allowed(
    snapshot: &GatewaySnapshot,
    identity: &AdminIdentity,
    owner: &Owner,
    candidate: bool,
) -> bool {
    identity.allows(
        AdminResource::Config,
        if candidate {
            AdminAction::DryRun
        } else {
            AdminAction::Read
        },
    ) || snapshot.ownership.allows(
        &identity.principal_id,
        &owner.workspace,
        if candidate {
            Action::Write
        } else {
            Action::Read
        },
    )
}

/// 业务作用：使用完整产品构建器验证来源候选，失败不发布目录、水位、路由或外部来源写入。
///
/// 参数说明：
/// - `state`：固定管理输入
/// - `parts`：固定管理输入
/// - `body`：固定管理输入
/// - `active`：是同代授权基线
/// - `providers`：是同代授权基线
/// - `id`：是同代授权基线
/// - `leases`：覆盖阻塞构建的实际生命周期。
///
/// 返回：语义增删改摘要或固定错误，未知字段和权限错误不反射候选内容。
async fn validate_candidate(
    state: &Arc<AdminState>,
    parts: &AdminRequestParts,
    body: axum::body::Body,
    active: Arc<GatewaySnapshot>,
    providers: Arc<Snapshot>,
    id: &str,
    leases: Leases,
) -> Response<BoxBody> {
    if !request_content_type(parts, "application/json")
        && !request_content_type(parts, "application/yaml")
    {
        return plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "source declaration requires JSON or YAML\n",
        );
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        collect_bounded_admin_body(parts, body, providers.body_limit(id).expect("known source")),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(response)) => return *response,
        Err(_) => {
            return plain(
                StatusCode::REQUEST_TIMEOUT,
                "source candidate body deadline reached\n",
            )
        }
    };
    let observation = match providers.candidate(id, &bytes) {
        Ok(observation) => observation,
        Err(_) => return plain(StatusCode::BAD_REQUEST, "source declaration rejected\n"),
    };
    let path = state.cfg_path.clone();
    let version = active.version.saturating_add(1);
    let previous = providers.clone();
    let built = tokio::task::spawn_blocking(move || {
        // HTTP 取消不能释放仍在构建的名额，阻止重复取消堆积后台任务。
        let _leases = leases;
        crate::config::load_snapshot_with_providers(
            &path,
            version,
            crate::upstream::DynamicUpstreamStore::new(),
            Input {
                previous: Some(previous),
                observation: Some(observation),
            },
        )
    })
    .await;
    match built {
        Ok(Ok(candidate)) => match candidate.providers {
            Some(next) => json(
                StatusCode::OK,
                serde_json::json!({
                    "ok":true,
                    "published":false,
                    "diff":providers.diff(&next,id)
                }),
            ),
            None => plain(StatusCode::CONFLICT, "source authority changed\n"),
        },
        _ => plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source candidate failed complete build\n",
        ),
    }
}

/// 业务作用：限定来源路径标识，拒绝路径歧义及无界名称。
///
/// 参数说明：
/// - `value`：为路径内未解码名称。
///
/// 返回：有限 ASCII 标识通过，其它输入保持未知资源。
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// 业务作用：严格解析解释页偏移，拒绝重复键、未知参数或无界单页。
///
/// 参数说明：
/// - `query`：为 URI 查询部分。
///
/// 返回：偏移最多8192、页大小1–128，缺省为0/64。
fn page(query: Option<&str>) -> Option<(usize, usize)> {
    let (mut offset, mut limit) = (None, None);
    if let Some(query) = query {
        for entry in query.split('&') {
            let (key, value) = entry.split_once('=')?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let value: usize = value.parse().ok()?;
            match key {
                "offset" if offset.is_none() && value <= 8192 => offset = Some(value),
                "limit" if limit.is_none() && (1..=128).contains(&value) => limit = Some(value),
                _ => return None,
            }
        }
    }
    Some((offset.unwrap_or(0), limit.unwrap_or(64)))
}

/// 业务作用：禁止共享缓存，并将全局与工作区预算延长到响应正文释放，慢下载不能无界堆积导出。
///
/// 参数说明：
/// - `result`：为私有响应
/// - `etag`：为来源语义摘要
/// - `leases`：是本次操作所有名额。
///
/// 返回：带私有缓存控制及可选 ETag 的有界正文。
fn response(
    mut result: Response<BoxBody>,
    etag: Option<&str>,
    leases: Leases,
) -> Response<BoxBody> {
    result.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, no-store"),
    );
    if let Some(etag) = etag {
        if let Ok(value) = http::HeaderValue::from_str(etag) {
            result.headers_mut().insert(hyper::header::ETAG, value);
        }
    }
    result.map(|body| {
        body.map_frame(move |frame| {
            let _leases = &leases;
            frame
        })
        .boxed()
    })
}
