//! 跨管理节点的持久提案权威；与实时采样及数据转发生命周期分离。

mod api;
mod authorization;
mod capacity;
mod connection;
mod execution;
mod model;
mod reading;
mod retention;
mod schema;
mod store;
#[cfg(feature = "admin-operations-workflow-pgsql")]
mod workflow;

use super::AdminState;
pub(super) use api::handle;
use std::sync::Arc;
pub use store::Store;

/// 业务作用：仅在完整管理模式为显式启用的持久操作建立唯一存储 owner。
///
/// 参数说明：
/// - `state`：已装配但尚未开放监听的管理运行态。
///
/// 返回：启用时返回并挂接存储；关闭或纯数据模式不创建数据库连接。
pub async fn start(state: &Arc<AdminState>) -> anyhow::Result<Option<Arc<Store>>> {
    if !state.mode.full_control_plane() {
        return Ok(None);
    }
    let Some(plan) = state.snap.load().admin_operations.clone() else {
        return Ok(None);
    };
    let store = Store::open(plan).await?;
    if state.operations.set(store.clone()).is_err() {
        store.close().await;
        anyhow::bail!("operations owner already installed");
    }
    #[cfg(all(feature = "admin-operations-workflow-pgsql", feature = "node-actions"))]
    if let Err(error) = store.start_executor(state) {
        store.close().await;
        return Err(error);
    }
    store.start_retention();
    Ok(Some(store))
}

/// 业务作用：执行显式数据库初始化命令，结束后关闭资源且不开放任何服务监听。
///
/// 参数说明：
/// - `plan`：当前完整配置解析出的持久权威。
///
/// 返回：迁移和结构复验均通过才成功；失败不继续启动服务。
pub async fn migrate(plan: &crate::config::operations::Plan) -> anyhow::Result<()> {
    let pool = schema::connect(plan).await?;
    let result = schema::gate(&pool, plan, true, false).await;
    pool.close().await;
    result.map(|_| ())
}

/// 业务作用：以显式维护命令读取或调整共享容量，结果输出前关闭数据库资源且不开放监听。
///
/// 参数说明：
/// - `plan`：配置选定的持久权威和目标四项预算。
/// - `expected`：原容量令牌；没有令牌时只读查看当前合同。
///
/// 返回：当前低敏合同；冲突或提交未知时不声称调整已经完成。
pub async fn maintain_capacity(
    plan: Arc<crate::config::operations::Plan>,
    expected: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    capacity::maintain(plan, expected).await
}

/// 业务作用：离线查看或绑定持久执行命名空间，结束后关闭资源且不启动任何节点动作。
///
/// 参数说明：
/// - `plan`：完整配置解析出的数据库和集群身份。
/// - `bind`：用户显式选择绑定时为真，只读查看时为假。
///
/// 返回：低敏绑定事实；异集群和未知提交不会被描述为成功。
pub async fn maintain_execution_namespace(
    plan: Arc<crate::config::operations::Plan>,
    bind: bool,
) -> anyhow::Result<serde_json::Value> {
    execution::maintain(plan, bind).await
}

/// 业务作用：为显式维护进程初始化或复验 NASA 工作流存储，结束后关闭连接资源。
///
/// 参数说明：
/// - `plan`：当前配置中已验证的持久权威。
/// - `migrate`：明确初始化时为真，只读验证时为假。
///
/// 返回：结构或定义的低敏状态；没有工作流制品能力、绑定或正确结构时失败。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub async fn maintain_workflow(
    plan: Arc<crate::config::operations::Plan>,
    migrate: bool,
) -> anyhow::Result<serde_json::Value> {
    workflow::maintain(plan, migrate).await
}
