//! 授权修改单份活动 YAML，语法格式化与整组候选校验共用同代基线。

use std::sync::Arc;

use bytes::Bytes;
use hyper::{header, Method, Response, StatusCode};
use serde_json::json as value;

use super::module_resource;
use crate::admin::{
    approval_required, authenticate_admin_request, candidate, collect_bounded_admin_body,
    config_etag, current_config_baseline_matches, json, plain, publication, record_admin_audit,
    reject_untrusted_admin_browser_origin, request_content_type, AdminAction, AdminRequest,
    AdminState, BoxBody,
};
use crate::config::{document, GatewaySnapshot};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Write,
    Validate,
    Format,
}

pub(in crate::admin) struct Action {
    name: String,
    operation: Operation,
}

impl Action {
    /// 业务作用：将三个具名模块操作绑定到固定路由，模块名随后只能在活动清单中查找。
    /// 参数说明：
    /// - `method`：实际 HTTP 方法。
    /// - `path`：未经路径解码的请求路径。
    /// 返回：匹配规范模块路由时交付操作和名称。多级路径和转义名称不匹配。
    pub(in crate::admin) fn for_request(method: &Method, path: &str) -> Option<Self> {
        let rest = path.strip_prefix("/api/config/modules/")?;
        let (name, operation) = match *method {
            Method::PUT => (rest, Operation::Write),
            Method::POST => {
                let (name, action) = rest.split_once('/')?;
                let operation = match action {
                    "dry-run" => Operation::Validate,
                    "format" => Operation::Format,
                    _ => return None,
                };
                (name, operation)
            }
            _ => return None,
        };
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            operation,
        })
    }
}

/// 业务作用：以真实配置源、模块权限和完整配置 ETag 约束编辑、校验及发布操作。
/// 参数说明：
/// - `request`：仅接受有界的原始 YAML 正文。
/// - `state`：当前活动代、持久审计和发布权限。
/// - `action`：规范路由确定的模块与操作。
/// 返回：格式化预览、校验收据或发布收据。拒绝时保留原事实源，审计故障不能伪造执行结果。
pub(in crate::admin) async fn handle(
    request: AdminRequest,
    state: Arc<AdminState>,
    action: Action,
) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
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
    if parts.uri.query().is_some() {
        return plain(
            StatusCode::BAD_REQUEST,
            "query parameters are not supported\n",
        );
    }
    let active = state.snap.load_full();
    let Some(index) = active
        .named_documents
        .iter()
        .position(|doc| doc.name == action.name)
    else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let module = &active.named_documents[index];
    let resource = module_resource(module.domain);
    let available = module.content.is_some();
    let permission = if action.operation == Operation::Write {
        AdminAction::Write
    } else {
        AdminAction::DryRun
    };
    if !identity.allows(resource, permission) {
        let _ = record_admin_audit(
            &state,
            &identity,
            &parts,
            resource,
            permission,
            "completed",
            Some(403),
        )
        .await;
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    if record_admin_audit(
        &state, &identity, &parts, resource, permission, "attempt", None,
    )
    .await
    .is_err()
    {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "configuration audit unavailable\n",
        );
    }
    // 已受理请求的原文处理、写入及结果审计由同一任务持有，传输断开不撤销正在执行的写入。
    let task = tokio::spawn(async move {
        let response = async {
        if action.operation == Operation::Write && approval_required(&state, resource) {
            // 三文档 maker-checker 不携带具名文件的写权，审批启用时必须保持拒绝。
            return plain(StatusCode::CONFLICT, "named module publication requires the configured approval workflow\n");
        }
        let Some(fingerprint) = active.config_fingerprint else {
            return plain(StatusCode::CONFLICT, "configuration fingerprint unavailable\n");
        };
        if !available {
            return plain(StatusCode::CONFLICT, "active module exceeds editing budget\n");
        }
        let etag = config_etag(fingerprint);
        match parts.headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok()) {
            None => return plain(StatusCode::PRECONDITION_REQUIRED, "If-Match is required\n"),
            Some(provided) if provided != etag => {
                return plain(StatusCode::PRECONDITION_FAILED, "configuration baseline changed\n");
            }
            _ => {}
        }
        if !request_content_type(&parts, "application/yaml") {
            return plain(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/yaml\n");
        }
        let bytes = match collect_bounded_admin_body(&parts, body, active.admin_max_config_body_bytes).await {
            Ok(bytes) => bytes,
            Err(response) => return *response,
        };
        if std::str::from_utf8(&bytes).is_err() {
            return plain(StatusCode::BAD_REQUEST, "YAML document must be UTF-8\n");
        }
        if !current_config_baseline_matches(&state, active.version, fingerprint).await {
            return plain(StatusCode::PRECONDITION_FAILED, "configuration baseline changed\n");
        }
        if action.operation == Operation::Format {
            return format_document(&state, &action.name, &etag, bytes, &active).await;
        }
        if let Err(error) = candidate::build_named(&state, active.clone(), index, bytes.clone()).await {
            return error.response();
        }
        if action.operation == Operation::Validate {
            if !current_config_baseline_matches(&state, active.version, fingerprint).await {
                return plain(StatusCode::PRECONDITION_FAILED, "configuration baseline changed\n");
            }
            return json(StatusCode::OK, value!({"ok": true, "applied": false, "document": action.name, "source_etag": etag}));
        }
        publication::publish_named(&state, active, index, bytes).await
        }.await;
        if permission == AdminAction::Write {
            return crate::admin::finish_config_write(
                &state, &identity, &parts, resource, response,
            )
            .await;
        }
        if record_admin_audit(
            &state,
            &identity,
            &parts,
            resource,
            permission,
            "completed",
            Some(response.status().as_u16()),
        )
        .await
        .is_err()
        {
            return plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "validation result audit failed\n",
            );
        }
        response
    });
    task.await.unwrap_or_else(|_| {
        json(
            StatusCode::INTERNAL_SERVER_ERROR,
            value!({
                "ok": false,
                "error": "configuration edit worker failed",
                "operation_may_have_completed": permission == AdminAction::Write,
            }),
        )
    })
}

/// 业务作用：按 naml 有界语法生成两空格预览，禁止求值占位符或写入配置。
/// 参数说明：
/// - `state`：提供与其它候选共用的实际任务许可。
/// - `name`：经过模块授权的文档名称。
/// - `etag`：候选预览基于的完整配置条件。
/// - `bytes`：用户提交的 YAML 原文。
/// - `active`：当前原文限制与配置版本。
/// 返回：格式化原文与预览状态，语法或预算失败时返回拒绝。
async fn format_document(
    state: &AdminState,
    name: &str,
    etag: &str,
    bytes: Bytes,
    active: &GatewaySnapshot,
) -> Response<BoxBody> {
    let permit = match state.candidate_builds.acquire() {
        Ok(permit) => permit,
        Err(error) => return error.response(),
    };
    let limit = active.admin_max_config_body_bytes;
    match permit
        .spawn(move |_| {
            let mapping = document::parse(&bytes, limit)?;
            anyhow::ensure!(
                mapping.is_object(),
                "configuration document must be a mapping"
            );
            let formatted = document::encode(&mapping, limit)?;
            Ok::<_, anyhow::Error>((formatted.as_bytes() != bytes.as_ref(), formatted))
        })
        .await
    {
        Ok(Ok((changed, content))) => json(
            StatusCode::OK,
            value!({
                "ok": true, "applied": false, "document": name, "source_etag": etag,
                "indentation": 2, "comments_preserved": false, "changed": changed, "content": content,
            }),
        ),
        Ok(Err(error)) => candidate::BuildError::Invalid(error.to_string()).response(),
        Err(_) => candidate::BuildError::Worker.response(),
    }
}
