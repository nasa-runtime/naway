//! 跨节点材料条件入口保留完整原目标，当前事实不能补齐调用者缺失的基线。

mod input;
mod response;

use crate::{
    admin::{
        self,
        management::material::{self, command::Intent, Completed, Reason},
        AdminRequest, AdminState, BoxBody,
    },
    config::GatewaySnapshot,
    control::{material::authorization, ownership::config::Action},
};
use futures::{stream, StreamExt};
use http::{Response, StatusCode};
use std::sync::Arc;

struct Observed {
    intent: Arc<Intent>,
    result: Result<Completed, Reason>,
}

/// 业务作用：按原节点聚合一次性材料查询，平台与工作区都不能隐藏离线或拒绝的原目标。
///
/// 参数说明：
/// - `request`：带真实凭据、精确 scope 和完整原目标基线的有界请求。
/// - `state`：本 Admin 的当前授权、发行身份及集群通信 owner。
///
/// 返回：完整分母的低敏结果；无权限、无能力或非法输入拒绝，不提交任何材料或安装动作。
pub(in crate::admin) async fn handle(
    request: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let snapshot = state.snap.load_full();
    let scope = match input::scope(parts.uri.query()) {
        Some(scope) => scope,
        None => {
            return response::failure(
                StatusCode::BAD_REQUEST,
                "invalid_material_conditions_request",
            )
        }
    };
    let principal = match authorize(&state, &parts, &snapshot, &scope) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    if parts.method != http::Method::POST
        || !admin::request_content_type(&parts, "application/json")
    {
        return response::failure(
            StatusCode::BAD_REQUEST,
            "invalid_material_conditions_request",
        );
    }
    let _permit = match state.management.admit_material_conditions() {
        Ok(permit) => permit,
        Err(_) => {
            return response::failure(
                StatusCode::TOO_MANY_REQUESTS,
                "material_conditions_capacity",
            )
        }
    };
    let _workspace = if let Some(workspace) = scope.strip_prefix("workspace.") {
        match state
            .workspace_operations
            .acquire_admin(&snapshot.ownership, workspace, 2)
        {
            Ok(permit) => Some(permit),
            Err(_) => {
                return response::failure(
                    StatusCode::TOO_MANY_REQUESTS,
                    "material_conditions_capacity",
                )
            }
        }
    } else {
        None
    };
    let bytes = match admin::collect_bounded_admin_body(&parts, body, 128 * 1024).await {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let input = match serde_json::from_slice::<input::Input>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return response::failure(
                StatusCode::BAD_REQUEST,
                "invalid_material_conditions_request",
            )
        }
    };
    let mut nonce = [0; 16];
    if getrandom::getrandom(&mut nonce).is_err() {
        return response::failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "material_conditions_unavailable",
        );
    }
    let query = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let intents = match input::prepare(input, &snapshot, &scope, &principal, &query) {
        Ok(intents) => intents,
        Err(code) => return response::failure(code, "material_conditions_request_denied"),
    };
    // 正文等待可能跨越撤权，只有同一个已认证主体和完整快照仍成立才允许发行任何节点命令。
    match authorize(&state, &parts, &snapshot, &scope) {
        Ok(current) if current == principal => {}
        Ok(_) => return response::failure(StatusCode::FORBIDDEN, "material_conditions_denied"),
        Err(response) => return *response,
    }
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok());
    let Some((issued, expires)) =
        issued.and_then(|issued| issued.checked_add(20_000).map(|expires| (issued, expires)))
    else {
        return response::failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "material_conditions_unavailable",
        );
    };
    let window = match material::RequestWindow::preview(issued, expires) {
        Ok(window) => window,
        Err(_) => {
            return response::failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "material_conditions_unavailable",
            )
        }
    };
    let mut observed = stream::iter(intents.into_iter().map(|intent| {
        let state = state.clone();
        let snapshot = snapshot.clone();
        async move {
            let result = material::inspect(state, snapshot, intent.clone(), issued, expires).await;
            Observed {
                intent,
                result,
            }
        }
    }))
    .buffer_unordered(16)
    .collect::<Vec<_>>()
    .await;
    // 等待其它节点期间，已经成功的节点可能重启或换代；最终全量复验不能只相信早到的结果。
    for observation in &mut observed {
        if let Ok(completed) = &observation.result {
            if let Err(reason) =
                material::recheck(&state, &snapshot, &observation.intent, completed.session).await
            {
                observation.result = Err(reason);
            }
        }
    }
    if window.check().is_err() {
        // 聚合不能为早到结果延长原签名期限；本机和远端都撤下已经超期的成功条件。
        for observation in &mut observed {
            if observation.result.is_ok() {
                observation.result = Err(Reason::Expired);
            }
        }
    }
    match authorize(&state, &parts, &snapshot, &scope) {
        Ok(current) if current == principal => {}
        Ok(_) => return response::failure(StatusCode::FORBIDDEN, "material_conditions_denied"),
        Err(response) => return *response,
    }
    observed.sort_unstable_by(|left, right| left.intent.node.cmp(&right.intent.node));
    let output = response::encode(&query, &scope, &observed);
    if !Arc::ptr_eq(&snapshot, &state.snap.load_full()) {
        return response::failure(
            StatusCode::PRECONDITION_FAILED,
            "material_conditions_authority_changed",
        );
    }
    output
}

/// 业务作用：用当前真实身份和材料域读取权验证入口，纯 Data 或工作区外主体不能借集群查询枚举来源。
///
/// 参数说明：
/// - `state`：当前进程角色和认证状态。
/// - `parts`：原请求凭据与浏览器来源。
/// - `snapshot`：整次查询冻结的授权实例。
/// - `scope`：唯一平台或工作区范围。
///
/// 返回：当前稳定主体；失权、换代、角色或 Origin 不符时拒绝，不发出节点请求。
fn authorize(
    state: &AdminState,
    parts: &http::request::Parts,
    snapshot: &Arc<GatewaySnapshot>,
    scope: &str,
) -> Result<String, Box<Response<BoxBody>>> {
    let identity = admin::authenticate_admin_request(parts, state)?;
    if let Some(response) = admin::reject_untrusted_admin_browser_origin(parts, state) {
        return Err(Box::new(response));
    }
    if !state.mode.full_control_plane() {
        return Err(Box::new(response::failure(
            StatusCode::NOT_FOUND,
            "material_conditions_unavailable",
        )));
    }
    if !Arc::ptr_eq(snapshot, &state.snap.load_full()) {
        return Err(Box::new(response::failure(
            StatusCode::PRECONDITION_FAILED,
            "material_conditions_authority_changed",
        )));
    }
    if !snapshot.admin_auth.enabled
        || !snapshot.admin_auth.rbac_enabled
        || authorization::check(scope, snapshot, &identity.principal_id, Action::Read).is_none()
    {
        return Err(Box::new(response::failure(
            StatusCode::FORBIDDEN,
            "material_conditions_denied",
        )));
    }
    Ok(identity.principal_id.to_string())
}
