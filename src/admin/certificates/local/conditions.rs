//! 精确本机材料条件按需读取，集群安装事实仍由独立的活动证书目录提供。

use crate::{
    admin::{
        authenticate_admin_request, collect_bounded_admin_body, full_body, json,
        reject_untrusted_admin_browser_origin, request_content_type, AdminAction, AdminRequest,
        AdminRequestParts, AdminResource, AdminState, BoxBody,
    },
    config::GatewaySnapshot,
    tls::{
        keypair::conditions::{self, Conditions, Unavailable},
        targets::Target,
    },
};
use bytes::Bytes;
use http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    target: Target,
    boot_id: String,
    base_version: u64,
    base_fingerprint: String,
}

#[derive(Serialize)]
struct Output<'a> {
    scope: &'static str,
    boot_id: &'a str,
    base_version: u64,
    base_fingerprint: &'a str,
    target: &'a Target,
    conditions: &'a Conditions,
    execution_supported: bool,
}

/// 业务作用：为同进程维护提供精确目标的公开条件，拒绝旧启动、旧配置及缺少平台权限的请求。
///
/// 参数说明：
/// - `request`：只包含逻辑目标和原配置条件的有界 JSON，不接受路径或材料正文。
/// - `state`：当前认证、配置发布协调器及两个实际读取名额。
///
/// 返回：同一原目标的完整条件；权限或基线变化、容量不足与不可证明来源均拒绝，不创建安装动作。
pub(in crate::admin) async fn read(
    request: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let snapshot = match authorize(&state, &parts) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if parts.uri.query().is_some() || !request_content_type(&parts, "application/json") {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_material_conditions_request",
        );
    }
    let permit = match state.certificates.conditions.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return failure(
                StatusCode::TOO_MANY_REQUESTS,
                "material_conditions_capacity",
            )
        }
    };
    let body = match collect_bounded_admin_body(&parts, body, 2048).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let input = match serde_json::from_slice::<Input>(&body) {
        Ok(input) => input,
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "invalid_material_conditions_request",
            )
        }
    };
    if !input.target.valid()
        || input.base_fingerprint.len() != 16
        || !input
            .base_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_material_conditions_request",
        );
    }
    let publication =
        match tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned())
            .await
        {
            Ok(guard) => Arc::new(guard),
            Err(_) => {
                return failure(
                    StatusCode::TOO_MANY_REQUESTS,
                    "material_conditions_capacity",
                )
            }
        };
    // 正文和排队都可能跨越撤权或换代；持有发布权之后重新认证，不能让旧读请求观察新目标。
    let current = match authorize(&state, &parts) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if !Arc::ptr_eq(&snapshot, &current)
        || input.boot_id != state.monitor.boot_id()
        || input.base_version != snapshot.version
        || u64::from_str_radix(&input.base_fingerprint, 16).ok() != snapshot.config_fingerprint
    {
        return failure(
            StatusCode::PRECONDITION_FAILED,
            "material_conditions_baseline_changed",
        );
    }
    let input = Arc::new(input);
    let active = snapshot.clone();
    let owner = state.clone();
    let original = input.clone();
    let guard = publication.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _publication = guard;
        // 配置权威、文件事务、材料锁按固定顺序持有；HTTP 取消不释放真实读取仍需要的许可。
        owner.config_history.with_stable_local_files(|| {
            if !Arc::ptr_eq(&active, &owner.snap.load_full())
                || crate::config::config_fingerprint(&active.source_config_path).ok()
                    != active.config_fingerprint
            {
                return None;
            }
            let observed = conditions::read(&active, &original.target);
            if crate::config::config_fingerprint(&active.source_config_path).ok()
                != active.config_fingerprint
            {
                return None;
            }
            Some(observed)
        })
    })
    .await;
    // 只有最终当前主体仍有完整平台读取权时才交付来源关系，失权后的迟到结果直接丢弃。
    let current = match authorize(&state, &parts) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if !Arc::ptr_eq(&snapshot, &current) {
        return failure(
            StatusCode::PRECONDITION_FAILED,
            "material_conditions_baseline_changed",
        );
    }
    let observation = match result {
        Ok(Some(Ok(value))) => value,
        Ok(None) => {
            return failure(
                StatusCode::PRECONDITION_FAILED,
                "material_conditions_baseline_changed",
            )
        }
        Ok(Some(Err(reason))) => return unavailable(reason),
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "material_conditions_unavailable",
            )
        }
    };
    let output = Output {
        scope: "local",
        boot_id: &input.boot_id,
        base_version: input.base_version,
        base_fingerprint: &input.base_fingerprint,
        target: &input.target,
        conditions: &observation,
        execution_supported: false,
    };
    match serde_json::to_vec(&output) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::CACHE_CONTROL, "no-store")
            .body(full_body(Bytes::from(bytes)))
            .expect("build material conditions response"),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "material_conditions_unavailable",
        ),
    }
}

/// 业务作用：将来源关系读取限定在平台证书和集群读权限，工作区不能从本机入口枚举其它归属。
///
/// 参数说明：
/// - `state`：当前进程角色和认证快照。
/// - `parts`：当前请求的真实凭据和浏览器来源。
///
/// 返回：获权的当前快照；角色不支持、失权或不可信来源均无材料读取。
fn authorize(
    state: &AdminState,
    parts: &AdminRequestParts,
) -> Result<Arc<GatewaySnapshot>, Box<Response<BoxBody>>> {
    let identity = authenticate_admin_request(parts, state)?;
    if let Some(response) = reject_untrusted_admin_browser_origin(parts, state) {
        return Err(Box::new(response));
    }
    // 该维护入口只属于本机全功能实例，不能让纯 Admin 假称自己是目标，或扩大 Data 的 HTTP 管理权限。
    if !state.mode.full_control_plane() || !state.mode.runs_data() {
        return Err(Box::new(failure(
            StatusCode::NOT_FOUND,
            "material_conditions_target_absent",
        )));
    }
    if !identity.allows(AdminResource::Certs, AdminAction::Read)
        || !identity.allows(AdminResource::Cluster, AdminAction::Read)
    {
        return Err(Box::new(failure(
            StatusCode::FORBIDDEN,
            "material_conditions_denied",
        )));
    }
    Ok(state.snap.load_full())
}

/// 业务作用：映射有限的来源拒绝原因，不把底层路径或文件系统诊断交给管理调用者。
///
/// 参数说明：
/// - `reason`：同锁材料观察的固定失败类别。
///
/// 返回：明确的 HTTP 失败，不交付不完整的共享影响。
fn unavailable(reason: Unavailable) -> Response<BoxBody> {
    let (status, code) = match reason {
        Unavailable::TargetAbsent => (StatusCode::NOT_FOUND, "material_conditions_target_absent"),
        Unavailable::ExternalSource => {
            (StatusCode::CONFLICT, "material_conditions_external_source")
        }
        Unavailable::Capacity => (
            StatusCode::TOO_MANY_REQUESTS,
            "material_conditions_capacity",
        ),
        Unavailable::Storage => (
            StatusCode::SERVICE_UNAVAILABLE,
            "material_conditions_unavailable",
        ),
        Unavailable::ImpactUnproven => {
            (StatusCode::CONFLICT, "material_conditions_impact_unproven")
        }
    };
    failure(status, code)
}

/// 业务作用：为条件查询输出固定失败并禁止缓存，避免旧来源证明被当作当前权威。
///
/// 参数说明：
/// - `status`：业务失败对应的状态码。
/// - `code`：不包含用户输入的固定原因。
///
/// 返回：带 no-store 的低敏 JSON。
fn failure(status: StatusCode, code: &'static str) -> Response<BoxBody> {
    let mut response = json(
        status,
        serde_json::json!({
            "ok": false,
            "error": code
        }),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
