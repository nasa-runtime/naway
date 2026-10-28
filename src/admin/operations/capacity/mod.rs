//! 共享容量的显式维护和启动登记；普通配置热更不能覆盖数据库预算。

mod model;
mod storage;

use super::{model::Error, Store};
use crate::config::operations::Plan;
pub(super) use model::Contract;
use model::{Expected, Limits};
use std::sync::Arc;

/// 业务作用：在不开监听、不启动清理器的维护进程中查看或比较交换集群容量合同。
///
/// 参数说明：
/// - `plan`：配置指定的数据库身份、集群及目标预算。
/// - `expected`：空表示只读查看；有值表示用户明确选择的原容量令牌。
///
/// 返回：明确提交或单次读取的低敏持久合同；未知提交保留原令牌恢复提示，不声称已经回滚。
pub(in crate::admin::operations) async fn maintain(
    plan: Arc<Plan>,
    expected: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let expected = expected.map(Expected::parse).transpose().map_err(|_| {
        anyhow::anyhow!("invalid capacity expected token; use revision:lowercase-sha256")
    })?;
    let store = Store::connect(plan).await?;
    let result = if let Some(expected) = expected {
        store.change_capacity(expected).await
    } else {
        store.capacity_status().await
    };
    store.close().await;
    let contract = result.map_err(|error| match error {
        Error::OutcomeUnknown => anyhow::anyhow!("capacity outcome unknown; retain the original expected token and target limits, then inspect or retry the same request"),
        Error::Conflict => anyhow::anyhow!("capacity expected token conflicts with the current contract"),
        Error::Capacity => anyhow::anyhow!("retained proposal usage exceeds requested capacity"),
        Error::Missing => anyhow::anyhow!("operations cluster has not been registered"),
        _ => anyhow::anyhow!("capacity authority unavailable"),
    })?;
    Ok(serde_json::json!({
        "cluster_id": store.plan.config.cluster_id,
        "capacity": contract.view(&store.plan.config)
    }))
}
