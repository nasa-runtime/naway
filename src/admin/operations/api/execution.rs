//! 执行能力、原意图创建和一致进度入口，候选原文只由原持久记录提供。

use super::{Query, Store};
use crate::{admin::AdminState, config::GatewaySnapshot};
use std::sync::Arc;

/// 业务作用：区分制品能力与当前开关，避免把已安装存储误报成执行就绪。
///
/// 参数说明: 无。
///
/// 返回：当前制品同时包含工作流与节点动作时为真。
pub(super) const fn supported() -> bool {
    cfg!(all(
        feature = "admin-operations-workflow-pgsql",
        feature = "node-actions"
    ))
}

/// 业务作用：向集群页面交付当前执行门，不读取候选正文或改变持久工作流。
///
/// 参数说明：
/// - state：当前管理角色与存储 owner。
/// - store：请求实际使用的共享存储。
/// - snapshot：本次请求冻结的完整配置实例。
///
/// 返回：能力、开关、就绪和有限原因；具体提案仍需独立检查原审批与全部目标。
pub(super) fn capability(
    state: &AdminState,
    store: &Store,
    snapshot: &Arc<GatewaySnapshot>,
) -> serde_json::Value {
    let enabled = snapshot
        .admin_operations
        .as_ref()
        .is_some_and(|plan| plan.config.execution.enabled);
    #[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
    let ready = super::super::execution::authority::running(state, store, snapshot).is_ok();
    #[cfg(not(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions")))]
    let ready = {
        let _ = (state, store);
        false
    };
    let reason = if !supported() {
        "unsupported"
    } else if !enabled {
        "disabled"
    } else if ready {
        "ready"
    } else {
        "authority_unavailable"
    };
    serde_json::json!({
        "execution_supported": supported(),
        "execution_enabled": enabled,
        "execution_ready": ready,
        "execution_reason": reason
    })
}

#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
mod request;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(super) use request::execute;

pub(super) struct Context<'a> {
    pub state: &'a AdminState,
    pub store: &'a Store,
    pub snapshot: &'a Arc<GatewaySnapshot>,
    pub query: &'a Query,
    pub request: &'a http::request::Parts,
    pub principal: &'a str,
}

/// 业务作用：按当前范围读取全部原目标的持久进度，执行关闭不撤下已有记录。
///
/// 参数说明：
/// - context：已经通过认证和范围 Read 的本次请求。
/// - id：规范提案身份。
///
/// 返回：未启动或完整执行快照；缺少组件时明确不可用，不推测执行结果。
pub(super) async fn read(
    context: &Context<'_>,
    id: &str,
) -> Result<serde_json::Value, super::Error> {
    #[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
    {
        context
            .store
            .execution_view(&context.query.scope.key, context.query.domain, id)
            .await
    }
    #[cfg(not(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions")))]
    {
        let _ = (
            context.state,
            context.store,
            context.snapshot,
            context.query,
            context.request,
            context.principal,
            id,
        );
        Err(super::Error::Unavailable)
    }
}

/// 业务作用：在缺少节点执行组件时封闭写入口，不借提案存储伪造执行成功。
///
/// 参数说明：
/// - context：已认证的请求与当前共享存储。
/// - id：原提案身份。
/// - bytes：经过独立长度门的正文。
///
/// 返回：明确不可用，且无持久或节点副作用。
#[cfg(not(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions")))]
pub(super) async fn execute(
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
) -> Result<serde_json::Value, super::Error> {
    let _ = (context, id, bytes);
    Err(super::Error::Unavailable)
}
