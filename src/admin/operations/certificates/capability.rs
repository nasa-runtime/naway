//! 独立材料执行能力不改变旧pair-only批准的含义，具体任务仍须完整影响批准。

use super::{
    authorization::{self, Scope},
    Error, Store,
};
use crate::{
    admin::{AdminState, BoxBody},
    config::GatewaySnapshot,
    control::ownership::config::Action,
};
use http::{Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct Capability<'a> {
    cluster_id: &'a str,
    scope: &'a str,
    execution_supported: bool,
    execution_enabled: bool,
    execution_ready: bool,
    execution_reason: &'static str,
    can_request_execution: bool,
    full_impact_approval_required: bool,
}

/// 业务作用：区分制品支持、独立开关、发行就绪和当前请求者写权，不能由配置执行能力推定材料资格。
///
/// 参数说明：
/// - `state`：当前管理角色与实际资源owner。
/// - `store`：请求使用的同一共享存储。
/// - `snapshot`：当前完整配置快照。
/// - `scope`：已认证读取范围。
/// - `principal`：本次真实请求者。
///
/// 返回：没有秘密、目标或候选摘要的能力说明；不会登记任务或访问节点。
pub(super) fn response(
    state: &AdminState,
    store: &Store,
    snapshot: &Arc<GatewaySnapshot>,
    scope: &Scope,
    principal: &str,
) -> Result<Response<BoxBody>, Error> {
    let supported = cfg!(all(
        feature = "node-actions",
        feature = "admin-operations-workflow-pgsql"
    ));
    let enabled = snapshot
        .admin_operations
        .as_ref()
        .is_some_and(|plan| plan.config.certificates.execution.enabled);
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    let ready = super::execution::authority::running(state, store, snapshot).is_ok();
    #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
    let ready = {
        let _ = state;
        false
    };
    let value = Capability {
        cluster_id: &store.plan.config.cluster_id,
        scope: &scope.key,
        execution_supported: supported,
        execution_enabled: enabled,
        execution_ready: ready,
        execution_reason: if !supported {
            "unsupported"
        } else if !enabled {
            "disabled"
        } else if ready {
            "ready"
        } else {
            "authority_unavailable"
        },
        can_request_execution: ready
            && authorization::check(scope, snapshot, principal, Action::Write).is_ok(),
        full_impact_approval_required: true,
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(crate::admin::full_body(bytes.into()))
        .map_err(|_| Error::Unavailable)
}
