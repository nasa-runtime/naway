//! 管理推送成员使用独立授权，不从gRPC地址推断HTTP抓取端口。

use super::{model, AdminState};
use crate::config::GatewaySnapshot;
use std::sync::Arc;
use std::time::Instant;

pub(super) struct Peer {
    pub id: String,
    pub result: Result<(Arc<model::Sample>, Instant), &'static str>,
}

/// 业务作用：判断当前配置是否允许管理通道接收实时指标，保持HTTP抓取授权独立。
///
/// 参数说明：
/// - `snapshot`：已发布的完整配置。
///
/// 返回：制品能力、认证、监控及接收开关同时成立时为true。
pub(super) fn enabled(snapshot: &GatewaySnapshot) -> bool {
    #[cfg(feature = "admin-grpc")]
    return snapshot.admin_auth.enabled
        && snapshot.admin_monitor.enabled
        && snapshot
            .admin_management
            .as_ref()
            .and_then(|plan| plan.receiver.as_ref())
            .is_some_and(|receiver| receiver.metrics);
    #[cfg(not(feature = "admin-grpc"))]
    {
        let _ = snapshot;
        false
    }
}

/// 业务作用：读取显式声明的推送成员，缺少样本的节点仍保留在预期覆盖中。
///
/// 参数说明：
/// - `state`：当前管理接收槽与监听生命周期。
/// - `snapshot`：本轮聚合的唯一配置权威。
///
/// 返回：当前样本共享引用或明确失败原因；不会发起网络请求或隐式回退HTTP。
pub(super) fn read(state: &AdminState, snapshot: &GatewaySnapshot) -> Vec<Peer> {
    #[cfg(feature = "admin-grpc")]
    if enabled(snapshot) {
        return state
            .management
            .observations(
                snapshot
                    .admin_management
                    .as_ref()
                    .expect("enabled management receiver"),
            )
            .into_iter()
            .map(|value| Peer {
                id: value.id,
                result: value
                    .sample
                    .map(|current| (current.sample.clone(), current.at))
                    .ok_or(value.metrics_availability),
            })
            .collect();
    }
    let _ = (state, snapshot);
    Vec::new()
}

/// 业务作用：让本机行使用显式管理节点身份，与其它Admin入口保持同一成员标识。
///
/// 参数说明：
/// - `snapshot`：本机当前管理计划。
///
/// 返回：已配置管理身份或传统本机标识，不猜测网络地址。
pub(super) fn local_id(snapshot: &GatewaySnapshot) -> &str {
    #[cfg(feature = "admin-grpc")]
    if let Some(plan) = &snapshot.admin_management {
        return &plan.node_id;
    }
    let _ = snapshot;
    "local"
}
