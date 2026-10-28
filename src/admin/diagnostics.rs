//! 诊断接口的独立授权、持久审计和限量交付，不复用普通配置读权限。

use super::*;

/// 业务作用：为限时诊断执行身份、Origin、部署平面、精确 RBAC、审计和最终代际门禁。
///
/// 参数说明：
/// - `request`：是管理请求，只有申请读取有限 JSON
/// - `state`：与数据面共用诊断 owner。
///
/// 返回：低敏元信息或已脱敏样本；任何权限、预算、审计或配置失配都不产生新的采集权威。
pub(super) async fn handle(request: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let generation = state.snap.load().version;
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    if !state.mode.full_control_plane()
        || !crate::observability::telemetry::tap::enabled(&state.snap.load())
    {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let suffix = parts
        .uri
        .path()
        .strip_prefix("/api/diagnostics")
        .unwrap_or_default();
    let action = if suffix.is_empty() {
        match parts.method {
            Method::GET => "list",
            Method::POST => "propose",
            _ => return plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n"),
        }
    } else {
        if parts.method != Method::POST {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        }
        match suffix.rsplit('/').next() {
            Some("approve") => "approve",
            Some("stop") => "stop",
            Some("download") => "download",
            _ => return plain(StatusCode::NOT_FOUND, "not found\n"),
        }
    };
    let permission = if matches!(action, "list" | "download") {
        AdminAction::Read
    } else {
        AdminAction::Write
    };
    if !identity.allows(AdminResource::Diagnostics, permission) {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    let id = if suffix.is_empty() {
        ""
    } else {
        let fields: Vec<_> = suffix.trim_start_matches('/').split('/').collect();
        if fields.len() != 2
            || fields[0].len() > 64
            || !fields[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return plain(StatusCode::NOT_FOUND, "not found\n");
        }
        fields[0]
    };
    let proposal = if action == "propose" {
        let bytes =
            match tokio::time::timeout(Duration::from_secs(2), axum::body::to_bytes(body, 8192))
                .await
            {
                Ok(Ok(bytes)) => bytes,
                _ => return plain(StatusCode::BAD_REQUEST, "invalid diagnostics request\n"),
            };
        match serde_json::from_slice::<crate::observability::telemetry::tap::Request>(&bytes) {
            Ok(request) => Some(request),
            Err(_) => return plain(StatusCode::BAD_REQUEST, "invalid diagnostics request\n"),
        }
    } else {
        drop(body);
        None
    };
    // 下载会把受控样本交付到进程外，同样必须先取得持久审计确认，不能作为普通 GET 旁路。
    if action != "list"
        && record_admin_audit(
            &state,
            &identity,
            &parts,
            AdminResource::Diagnostics,
            permission,
            "attempt",
            None,
        )
        .await
        .is_err()
    {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n");
    }
    let current = state.snap.load();
    if current.version != generation || !crate::observability::telemetry::tap::enabled(&current) {
        return plain(StatusCode::CONFLICT, "diagnostics generation changed\n");
    }
    drop(current);
    let registry = &state.telemetry.tap;
    let mut download_permit = None;
    let result = match action {
        "propose" => registry.propose(
            proposal.expect("validated proposal"),
            &identity.principal_id,
            generation,
        ),
        "approve" => {
            let digest = parts
                .headers
                .get(http::header::IF_MATCH)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .trim_matches('"');
            registry.approve(id, digest, &identity.principal_id, generation)
        }
        "stop" => registry.stop(id, generation).map(|()| {
            serde_json::json!({
                "ok":true
            })
        }),
        "download" => registry.download(id, generation).map(|(value, permit)| {
            download_permit = Some(permit);
            value
        }),
        _ => registry.list(),
    };
    let status = if result.is_ok() {
        if action == "propose" {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        }
    } else {
        StatusCode::CONFLICT
    };
    if action != "list" {
        // 终态审计失败不重新执行动作；申请与下载计数都已提交，重试仍受唯一状态和预算限制。
        if record_admin_audit(
            &state,
            &identity,
            &parts,
            AdminResource::Diagnostics,
            permission,
            "completed",
            Some(status.as_u16()),
        )
        .await
        .is_err()
        {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "diagnostics action committed; audit completion unavailable\n",
            );
        }
    }
    // 审计等待期间发生的配置换代不得把旧样本交付给新权限域。
    if state.snap.load().version != generation {
        return plain(StatusCode::CONFLICT, "diagnostics generation changed\n");
    }
    if let Ok(value) = &result {
        let session_id = if action == "download" {
            value["session"]["id"].as_str()
        } else {
            value["id"].as_str()
        };
        if session_id.is_some_and(|id| !registry.available(id, generation)) {
            return plain(StatusCode::CONFLICT, "diagnostics session retired\n");
        }
    }
    let value = result.unwrap_or_else(|_| {
        serde_json::json!({
            "ok":false,
            "error":"diagnostics state, scope or budget rejected"
        })
    });
    let mut response = if let Some(permit) = download_permit {
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(permit.bytes(&value)))
            .expect("build bounded diagnostics download")
    } else {
        json(status, value)
    };
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        http::HeaderValue::from_static("nosniff"),
    );
    response
}
