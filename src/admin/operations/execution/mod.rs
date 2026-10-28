//! 持久执行的集群命名空间；存储绑定本身不授予节点动作权限。

#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(super) mod authority;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(super) mod cache;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(super) mod frozen;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
mod lease;
mod namespace;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(super) mod publisher;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
mod release;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
pub(super) mod runtime;
#[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
mod view;

use super::{model::Error, Store};
use crate::config::operations::Plan;
use std::sync::Arc;

/// 业务作用：离线查看或显式绑定执行存储所属集群，避免工作流从共享表跨集群取走命令。
///
/// 参数说明：
/// - `plan`：当前配置选定的数据库、schema 和集群身份。
/// - `bind`：显式绑定命令为真，只读状态命令为假。
///
/// 返回：低敏持久绑定；冲突或未知提交不开放监听，也不声称目标操作已经执行。
pub(super) async fn maintain(plan: Arc<Plan>, bind: bool) -> anyhow::Result<serde_json::Value> {
    let store = Store::connect(plan).await?;
    let result = if bind {
        store.bind_execution_namespace().await
    } else {
        store.execution_namespace().await
    };
    store.close().await;
    let binding = result.map_err(|error| match error {
        Error::OutcomeUnknown => anyhow::anyhow!("execution namespace outcome unknown; retain the original cluster and schema, then inspect or retry the same binding"),
        Error::Conflict => anyhow::anyhow!("execution namespace conflicts with an existing cluster"),
        _ => anyhow::anyhow!("execution namespace authority unavailable"),
    })?;
    Ok(serde_json::json!({
        "cluster_id": store.plan.config.cluster_id,
        "namespace": {
            "bound_cluster_id": binding.cluster,
            "bound_at_ms": binding.bound_at_ms,
            "matches_config": binding.permits(&store.plan.config.cluster_id),
        },
        "execution_available": false,
        "workflow_schema_installed": store.workflow_installed,
        "delivery_schema_installed": store.delivery_installed,
    }))
}
