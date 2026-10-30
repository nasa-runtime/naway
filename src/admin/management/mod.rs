//! 独立节点管理通信；当前事实接收不授予配置或业务动作的执行权。

#[cfg(feature = "node-actions")]
pub(in crate::admin) mod actions;
mod baseline;
mod catalog;
mod issuer;
pub(in crate::admin) mod metrics;
mod plan;
#[cfg(feature = "node-actions")]
pub(in crate::admin) mod preview;
mod protocol;
mod publication;
mod receiver;
mod reporter;
mod runtime;
mod security;
mod telemetry;

pub(crate) use plan::Plan;
pub use runtime::Manager;
#[cfg(feature = "node-journal")]
pub(crate) use security::identifier as valid_node_id;

const FRESHNESS: std::time::Duration = std::time::Duration::from_secs(6);
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_MESSAGE: usize = 32 * 1024;

/// 业务作用：把管理身份与接入拓扑作为本地授权边界，远程业务配置不能重新指定管理信任域。
///
/// 参数说明：
/// - `current`：活动快照中的管理权威。
/// - `candidate`：远程候选携带的管理权威。
///
/// 返回：开关、节点、成员、目标、实际TLS及发行身份材料都相同时为true。
pub(crate) fn same_authority(current: Option<&Plan>, candidate: Option<&Plan>) -> bool {
    match (current, candidate) {
        (None, None) => true,
        (Some(current), Some(candidate)) => current.authority == candidate.authority,
        _ => false,
    }
}
