//! 原提案预览只产生短期审阅事实，不参与审批或持久执行。

use super::execution::Context;
#[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
use super::Store;
use super::{Error, Query};
use crate::{
    admin::{AdminState, BoxBody},
    config::GatewaySnapshot,
};
use std::sync::Arc;

#[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
mod request;
#[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
mod source;

/// 业务作用：在读取候选之前判断当前主体是否具有预览所需的读取及构建资格。
///
/// 参数说明：
/// - `snapshot`：当前完整权限快照。
/// - `query`：已解析的精确领域及工作区。
/// - `principal`：实际认证主体。
///
/// 返回：制品支持且主体仍获权时为真；不以只读权限代替候选构建授权。
pub(super) fn allows(snapshot: &GatewaySnapshot, query: &Query, principal: &str) -> bool {
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    {
        crate::admin::management::preview::allows(
            snapshot,
            &query.scope.key,
            principal,
            query.domain,
        )
    }
    #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
    {
        let _ = (snapshot, query, principal);
        false
    }
}

/// 业务作用：交付当前入口的只读集群预览能力，避免页面把执行开关当作预览开关。
///
/// 参数说明：
/// - `context`：已经通过当前范围读取授权的管理请求。
///
/// 返回：制品能力、当前发行就绪及主体权限；具体目标仍需逐个验证独立开关和基线。
pub(super) fn capability(context: &Context<'_>) -> serde_json::Value {
    let supported = cfg!(all(
        feature = "node-actions",
        feature = "admin-operations-workflow-pgsql"
    ));
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    let ready = current(context.state, context.store, context.snapshot).is_ok();
    #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
    let ready = false;
    serde_json::json!({
        "preview_supported": supported,
        "preview_ready": ready,
        "preview_allowed": allows(context.snapshot, context.query, context.principal)
    })
}

/// 业务作用：复验本次共享读取与签名发行仍属于当前管理配置及存储 owner。
///
/// 参数说明：
/// - `state`：当前管理生命周期。
/// - `store`：实际读取原提案的存储。
/// - `snapshot`：请求开始时冻结的管理快照。
///
/// 返回：同一运行权威仍有效时成功；停机、换代或集群不符时拒绝交付事实。
#[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
fn current(
    state: &AdminState,
    store: &Store,
    snapshot: &Arc<GatewaySnapshot>,
) -> Result<(), Error> {
    if store.stopping.is_cancelled()
        || !Arc::ptr_eq(&state.snap.load_full(), snapshot)
        || !snapshot
            .admin_operations
            .as_ref()
            .is_some_and(|plan| plan.same_bootstrap(&store.plan))
        || !state
            .operations
            .get()
            .is_some_and(|installed| std::ptr::eq(installed.as_ref(), store))
    {
        return Err(Error::Conflict);
    }
    state
        .management
        .action_plan(snapshot, &store.plan.config.cluster_id)
        .map_err(|_| Error::Unavailable)?;
    Ok(())
}

/// 业务作用：仅接受原提案身份和空确认正文，客户端不能替换预览候选或目标。
///
/// 参数说明：
/// - `state`：供候选工作持有的管理 owner。
/// - `context`：当前认证、范围及共享存储。
/// - `id`：规范原提案身份。
/// - `bytes`：有界 JSON 正文。
///
/// 返回：全部原目标的短期事实或封闭失败；不产生持久副作用。
pub(super) async fn inspect(
    state: &Arc<AdminState>,
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
) -> Result<http::Response<BoxBody>, Error> {
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    {
        request::inspect(state, context, id, bytes).await
    }
    #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
    {
        let _ = (state, context, id, bytes);
        Err(Error::Unavailable)
    }
}
