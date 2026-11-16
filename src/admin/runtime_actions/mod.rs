//! 类型化运行态动作与当前实例条件；实际副作用仍使用既有原生执行体。

mod model;
pub(in crate::admin) use model::Inputs;

use super::*;
use http_body_util::BodyExt as _;
use model::{Action, Kind};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tokio::sync::Semaphore;

const MAX_BODY_BYTES: usize = 8192;

/// 进程级受理容量与独立实例身份，不随配置热更重新开放容量。
pub(super) struct Runtime {
    identity: OnceLock<Option<[u8; 16]>>,
    permits: Arc<Semaphore>,
}

impl Runtime {
    /// 业务作用：建立四个有限运行态动作槽，实例熵源在首次使用时读取。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有后台任务、外部写入或待办历史的进程级状态。
    pub(super) fn new() -> Self {
        Self {
            identity: OnceLock::new(),
            permits: Arc::new(Semaphore::new(4)),
        }
    }

    /// 业务作用：让条件绑定独立进程身份，实例重建不能复用旧运维条件。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定随机身份；熵源失败时保持不可用，不以计数或墙钟回退。
    fn identity(&self) -> Option<&[u8; 16]> {
        self.identity
            .get_or_init(|| {
                let mut value = [0; 16];
                getrandom::getrandom(&mut value).ok().map(|()| value)
            })
            .as_ref()
    }
}

/// 业务作用：为四类原生运行态副作用提供类型化输入、精确权限、同实例条件和有限任务生命周期。
///
/// 参数说明：
/// - `request`：同源能力读取或显式JSON动作，不接受远端节点地址与查询参数。
/// - `state`：接入进程的实际运行态与唯一配置发布协调器。
///
/// 返回：只读能力、原生动作的固定结果或明确拒绝；取消等待不撤销已受理任务，不自动重试。
pub(super) async fn handle(request: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = request.into_parts();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    // 完整管理权限不能借Data入口扩大最小管理面，动作也不会被转发到其它节点。
    if !state.mode.full_control_plane() {
        return failure(StatusCode::NOT_FOUND, "not_found", false);
    }
    if parts.uri.query().is_some() {
        return failure(StatusCode::BAD_REQUEST, "invalid_runtime_action", false);
    }
    if !kinds().into_iter().any(|kind| allowed(&identity, kind)) {
        return failure(StatusCode::FORBIDDEN, "forbidden", false);
    }
    if parts.method == Method::GET {
        return capabilities(&state, &identity);
    }
    if parts.method != Method::POST {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", false);
    }
    if !request_content_type(&parts, "application/json") {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_runtime_action",
            false,
        );
    }
    let Ok(permit) = state.runtime_actions.permits.clone().try_acquire_owned() else {
        return failure(
            StatusCode::TOO_MANY_REQUESTS,
            "runtime_action_capacity",
            false,
        );
    };
    let bytes = match tokio::time::timeout(
        Duration::from_secs(2),
        axum::body::to_bytes(body, MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_runtime_action", false),
    };
    let action = match serde_json::from_slice::<Action>(&bytes) {
        Ok(action) => action,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_runtime_action", false),
    };
    if !allowed(&identity, action.kind()) {
        return failure(StatusCode::FORBIDDEN, "forbidden", false);
    }
    let input = match action.prepare(format!("{:x}", Sha256::digest(&bytes))) {
        Ok(input) => input,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_runtime_action", false),
    };
    if !allowed(&identity, input.kind) {
        return failure(StatusCode::FORBIDDEN, "forbidden", false);
    }
    let expected = match parts
        .headers
        .get(http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) if value.len() == 74 && value.starts_with('"') && value.ends_with('"') => {
            value.to_owned()
        }
        _ => {
            return failure(
                StatusCode::PRECONDITION_REQUIRED,
                "runtime_action_condition_required",
                false,
            )
        }
    };
    let initiator = identity.principal_id.clone();
    let kind = input.kind;
    // 任务拥有受理槽与实际执行权；HTTP等待取消只丢弃结果，不释放仍在写事实源的任务容量。
    let work = tokio::spawn(async move {
        let _permit = permit;
        execute(state, parts, input, expected, initiator).await
    });
    match tokio::time::timeout(Duration::from_secs(6), work).await {
        Ok(Ok(response)) if response.status().is_success() => outcome(kind, response).await,
        Ok(Ok(response)) => response,
        _ => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_action_outcome_unknown",
            true,
        ),
    }
}

/// 业务作用：只给当前主体展示可执行的原生动作及其本机条件，不披露其它主体的对象目录。
///
/// 参数说明：
/// - `state`：实际接入实例。
/// - `identity`：本次认证冻结的动作位。
///
/// 返回：无历史、秘密和目标清单的有界JSON；实例身份不可用时拒绝开放动作。
fn capabilities(state: &AdminState, identity: &AdminIdentity) -> Response<BoxBody> {
    let snapshot = state.snap.load_full();
    let Some(condition) = condition(state, &snapshot, identity) else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_action_unavailable",
            false,
        );
    };
    let actions = kinds()
        .into_iter()
        .map(|kind| {
            let granted = allowed(identity, kind);
            let configured = match kind {
                Kind::Blacklist(_) => snapshot.runtime_state.blacklist.enabled,
                Kind::InterfaceDisable(_) => snapshot.runtime_state.interface_disable.enabled,
                Kind::Connections | Kind::CacheInvalidate => true,
            };
            (
                kind.name().to_owned(),
                json!({
                    "allowed": granted,
                    "enabled": granted && configured,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let mut response = json(
        StatusCode::OK,
        json!({
            "schema_version": 1,
            "mode": admin_mode_name(state.mode),
            "config_version": snapshot.version.to_string(),
            "actions": actions,
            "max_body_bytes": MAX_BODY_BYTES,
            "max_grace_ms": model::MAX_GRACE_MS.to_string(),
            "default_grace_ms": snapshot.long_connections.drain_grace_ms.to_string(),
            "cluster_execution": false,
        }),
    );
    response.headers_mut().insert(
        http::header::ETAG,
        http::HeaderValue::from_str(&condition).expect("fixed runtime condition"),
    );
    private(response)
}

/// 业务作用：在唯一配置发布权下复验主体与条件，再审计和执行原生副作用，避免等待期间失权。
///
/// 参数说明：
/// - `state`：任务持有的接入实例。
/// - `parts`：原始凭据、Origin与审计身份。
/// - `input`：已验证的有限原生参数。
/// - `expected`：用户复核时取得的原实例条件。
/// - `initiator`：受理时认证主体，执行前不得换成另一身份。
///
/// 返回：固定结果或拒绝；实际工作结束前始终保留配置发布权和受理容量。
async fn execute(
    state: Arc<AdminState>,
    mut parts: AdminRequestParts,
    input: Inputs,
    expected: String,
    initiator: Arc<str>,
) -> Response<BoxBody> {
    let Ok(_publication) =
        tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned()).await
    else {
        return failure(
            StatusCode::TOO_MANY_REQUESTS,
            "runtime_action_capacity",
            false,
        );
    };
    // 与快照提交者共用发布权后才复验，不能让旧凭据或旧实例条件跨权限、后端或配置换代执行。
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if identity.principal_id != initiator || !allowed(&identity, input.kind) {
        return failure(StatusCode::FORBIDDEN, "forbidden", false);
    }
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    let snapshot = state.snap.load_full();
    if condition(&state, &snapshot, &identity).as_deref() != Some(expected.as_str()) {
        return failure(
            StatusCode::PRECONDITION_FAILED,
            "runtime_action_condition_changed",
            false,
        );
    }
    let kind = input.kind;
    let (resource, action) = kind.permission();
    parts.extensions.insert(input);
    // 外部事实与关闭信号均不可假定能撤销；持久attempt确认必须先于实际动作。
    if record_admin_audit(&state, &identity, &parts, resource, action, "attempt", None)
        .await
        .is_err()
    {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_action_audit_unavailable",
            false,
        );
    }
    let response = match kind {
        Kind::Blacklist(blocked) => set_blacklist_ip(&parts, &state, &identity, blocked).await,
        Kind::InterfaceDisable(disabled) => set_interface_disable(&parts, &state, disabled).await,
        Kind::Connections => close_long_connections(&parts, &state),
        Kind::CacheInvalidate => purge_http_cache(&parts, &state).await,
    };
    // completed失败发生在副作用之后，不能重新执行或把结果包装成未提交。
    if record_admin_audit(
        &state,
        &identity,
        &parts,
        resource,
        action,
        "completed",
        Some(response.status().as_u16()),
    )
    .await
    .is_err()
    {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_action_outcome_unknown",
            true,
        );
    }
    if response.status().is_success() {
        response
    } else {
        rejected(response.status())
    }
}

/// 业务作用：同一进程内给旧原生执行体交付精确JSON参数，避免URI编码、拼接与二次解码改变目标。
///
/// 参数说明：
/// - `request`：只有受理后的类型化入口带有Inputs扩展。
/// - `key`：原生执行体固定使用的参数名。
///
/// 返回：类型化原值，或既有入口的原始查询串值；两种来源不会混合回退。
pub(super) fn parameter<'a>(request: &'a AdminRequestParts, key: &str) -> Option<&'a str> {
    if let Some(input) = request.extensions.get::<Inputs>() {
        return input.parameters.get(key).map(String::as_str);
    }
    query_param(request.uri.query().unwrap_or_default(), key)
}

/// 业务作用：让类型化动作与旧动作共用低敏审计字段，正文只记录摘要，不记录选择器或固定响应原文。
///
/// 参数说明：
/// - `request`：可能含进程内已验证输入的请求。
///
/// 返回：原始有限正文摘要；旧查询串入口由其既有摘要逻辑处理。
pub(super) fn audit_digest(request: &AdminRequestParts) -> Option<&str> {
    request
        .extensions
        .get::<Inputs>()
        .map(|input| input.digest.as_str())
}

/// 业务作用：按当前主体、配置与随机实例身份绑定复核条件，条件本身不代替权限或一次性动作令牌。
///
/// 参数说明：
/// - `state`：当前接入进程。
/// - `snapshot`：本轮不可变配置。
/// - `identity`：当前主体及完整动作位。
///
/// 返回：固定强条件；实例熵源不可用时不开放动作。
fn condition(
    state: &AdminState,
    snapshot: &GatewaySnapshot,
    identity: &AdminIdentity,
) -> Option<String> {
    let nonce = state.runtime_actions.identity()?;
    let bytes = serde_json::to_vec(&(
        nonce,
        snapshot.version,
        snapshot.config_fingerprint,
        identity.principal_id.as_ref(),
        identity.permissions,
    ))
    .expect("fixed runtime authority");
    Some(format!("\"runtime-{:x}\"", Sha256::digest(bytes)))
}

/// 业务作用：统一四类固定动作，防止能力读面和执行授权使用不同分母。
///
/// 参数说明: 无。
///
/// 返回：不包含用户输入或远端动作的固定集合。
fn kinds() -> [Kind; 4] {
    [
        Kind::Blacklist(false),
        Kind::InterfaceDisable(false),
        Kind::Connections,
        Kind::CacheInvalidate,
    ]
}

/// 业务作用：独立检查原生资源动作，不能把read、write或角色名升级为紧急关闭权限。
///
/// 参数说明：
/// - `identity`：已认证主体。
/// - `kind`：页面固定动作。
///
/// 返回：原生RBAC明确允许时为真。
fn allowed(identity: &AdminIdentity, kind: Kind) -> bool {
    let (resource, action) = kind.permission();
    identity.allows(resource, action)
}

/// 业务作用：将原生执行结果适配成有限固定字段，不把原生错误正文或Redis连接错误交给页面。
///
/// 参数说明：
/// - `kind`：实际执行的固定动作。
/// - `response`：同一原生执行体的响应。
///
/// 返回：成功结果中的计数与generation保留十进制字符串；不完整响应或失败均视为结果可能未知。
async fn outcome(kind: Kind, response: Response<BoxBody>) -> Response<BoxBody> {
    let status = response.status();
    if !status.is_success() {
        return rejected(status);
    }
    let mut body = response.into_body();
    let mut bytes = BytesMut::new();
    let mut frames = 0;
    while let Some(frame) = body.frame().await {
        frames += 1;
        let Ok(frame) = frame else {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime_action_outcome_unknown",
                true,
            );
        };
        let Ok(data) = frame.into_data() else {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime_action_outcome_unknown",
                true,
            );
        };
        if frames > 4 || data.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime_action_outcome_unknown",
                true,
            );
        }
        bytes.extend_from_slice(&data);
    }
    let result = match kind {
        Kind::CacheInvalidate => {
            let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            match value
                .as_ref()
                .and_then(|value| value.get("generation"))
                .and_then(serde_json::Value::as_u64)
            {
                Some(generation) => json!({
                    "generation": generation.to_string(),
                }),
                None => {
                    return failure(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "runtime_action_outcome_unknown",
                        true,
                    )
                }
            }
        }
        Kind::Connections | Kind::Blacklist(true) => {
            let text = std::str::from_utf8(&bytes).unwrap_or_default();
            let count = text
                .rsplit_once('=')
                .and_then(|(_, value)| value.trim_end_matches('\n').parse::<u64>().ok());
            let Some(count) = count else {
                return failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "runtime_action_outcome_unknown",
                    true,
                );
            };
            json!({
                "signals": count.to_string(),
                "scheduled": text.starts_with("scheduled "),
            })
        }
        Kind::Blacklist(false) | Kind::InterfaceDisable(_) => json!({
            "acknowledged": true,
        }),
    };
    private(json(
        status,
        json!({
            "ok": true,
            "kind": kind.name(),
            "result": result,
            "cluster_execution": false,
        }),
    ))
}

/// 业务作用：区分四个原生执行体的写入前拒绝与写入或刷新失败，不能把依赖失败自动当作未提交。
///
/// 参数说明：
/// - `status`：四个固定原生执行体的失败状态。
///
/// 返回：参数、目标缺失和配置关闭表示尚未执行；存储、缓存或刷新失败保持副作用可能已发生。
fn rejected(status: StatusCode) -> Response<BoxBody> {
    // 这些状态在固定执行体中只出现在副作用之前；其余状态不能推断事实源没有接受写入。
    let may_have_completed = !matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::CONFLICT
    );
    failure(status, "runtime_action_rejected", may_have_completed)
}

/// 业务作用：所有拒绝只交付固定状态与未知语义，不回显凭据、输入原文或底层错误。
///
/// 参数说明：
/// - `status`：对应拒绝阶段的HTTP状态。
/// - `error`：页面固定错误身份。
/// - `may_have_completed`：副作用是否可能已经发生。
///
/// 返回：禁止缓存的有限JSON；未知结果不触发自动补偿或重新执行。
fn failure(status: StatusCode, error: &'static str, may_have_completed: bool) -> Response<BoxBody> {
    private(json(
        status,
        json!({
            "ok": false,
            "error": error,
            "operation_may_have_completed": may_have_completed,
        }),
    ))
}

/// 业务作用：动作条件与结果仅属于当前主体，不允许浏览器缓存后跨主体复用。
///
/// 参数说明：
/// - `response`：已构造的有限能力、结果或错误。
///
/// 返回：带no-store与nosniff的响应。
fn private(mut response: Response<BoxBody>) -> Response<BoxBody> {
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
