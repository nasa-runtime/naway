//! 配置差异绑定单一活动基线，并在有界构建结束后复验当前身份。

mod listener;
mod sentinel;
mod snapshot;

use super::{
    authenticate_admin_request, candidate, collect_bounded_admin_body, config_etag, json, plain,
    reject_untrusted_admin_browser_origin, request_content_type, AdminAction, AdminRequest,
    AdminResource, AdminState, BoxBody,
};
use hyper::{header, Response, StatusCode};
use std::sync::Arc;

/// 业务作用：在同一不可变基线与当前授权下比较完整候选，不把单节点构建声明为集群已发布事实。
///
/// 参数说明：
/// - `req`：选择 all、routes、sentinel、upstreams 或 listeners 的 YAML 候选，可携带精确整体 If-Match。
/// - `state`：提供当前快照、归档、统一候选预算和身份规则。
///
/// 返回：合法且同基线时返回低敏差异和 ETag；失权、换代、过载或候选非法均无发布副作用。
pub(super) async fn semantic_config_diff(
    req: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    let kind = req
        .uri()
        .path()
        .strip_prefix("/api/config/")
        .and_then(|path| path.strip_suffix("/diff"))
        .unwrap_or_default()
        .to_owned();
    if !matches!(
        kind.as_str(),
        "all" | "routes" | "sentinel" | "upstreams" | "listeners"
    ) {
        return plain(StatusCode::NOT_FOUND, "unsupported diff kind\n");
    }
    let (parts, body) = req.into_parts();
    let active = state.snap.load_full();
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
    if !identity.allows(AdminResource::Config, AdminAction::DryRun) {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    if !request_content_type(&parts, "application/yaml") {
        return plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/yaml\n",
        );
    }
    let Some(fingerprint) = active.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "active configuration fingerprint unavailable\n",
        );
    };
    let etag = config_etag(fingerprint);
    if parts.headers.contains_key(header::IF_MATCH)
        && (parts.headers.get_all(header::IF_MATCH).iter().count() != 1
            || parts
                .headers
                .get(header::IF_MATCH)
                .and_then(|value| value.to_str().ok())
                != Some(etag.as_str()))
    {
        return plain(
            StatusCode::PRECONDITION_FAILED,
            "configuration baseline differs\n",
        );
    }
    let body =
        match collect_bounded_admin_body(&parts, body, active.admin_max_config_body_bytes).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    if std::str::from_utf8(&body).is_err() {
        return plain(StatusCode::BAD_REQUEST, "candidate must be UTF-8\n");
    }
    // 读取请求正文期间也可能撤权或换代；旧请求不能占用新基线的构建任务。
    if !Arc::ptr_eq(&active, &state.snap.load_full()) {
        return plain(StatusCode::CONFLICT, "configuration baseline changed\n");
    }
    let document = if kind == "sentinel" {
        candidate::DocumentKind::Sentinel
    } else {
        candidate::DocumentKind::Gateway
    };
    let diff =
        candidate::inspect_archived(&state, active.clone(), document, body, snapshot::compare)
            .await;
    // 构建任务不持授权租约；必须先重新认证判权，再决定是否允许输出旧任务的比较结果。
    let current_identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if !current_identity.allows(AdminResource::Config, AdminAction::DryRun)
        || current_identity.principal_id != identity.principal_id
    {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    if !Arc::ptr_eq(&active, &state.snap.load_full()) {
        return plain(StatusCode::CONFLICT, "configuration baseline changed\n");
    }
    let mut diff = match diff {
        Ok(diff) => diff,
        Err(error) => {
            return error.policy_response("candidate is not valid for configuration comparison\n")
        }
    };
    if kind != "all" {
        diff.as_object_mut()
            .expect("fixed comparison shape")
            .retain(|key, _| {
                matches!(key.as_str(), "current_version" | "candidate_version") || key == &kind
            });
    }
    let mut response = json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "scope": "local",
            "diff": diff
        }),
    );
    response.headers_mut().insert(
        header::ETAG,
        header::HeaderValue::from_str(&etag).expect("fixed fingerprint ETag"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    // 编码可能处理大目录，最终检查仍不能省略，避免编码期间的权限撤销被旧响应越过。
    if !Arc::ptr_eq(&active, &state.snap.load_full()) {
        return plain(StatusCode::CONFLICT, "configuration baseline changed\n");
    }
    response
}
