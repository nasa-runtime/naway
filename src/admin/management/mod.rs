//! 独立节点管理通信；当前事实接收不授予配置或业务动作的执行权。

#[cfg(feature = "node-actions")]
pub(in crate::admin) mod actions;
mod baseline;
mod catalog;
mod certificates;
mod consumers;
mod issuer;
#[cfg(feature = "node-actions")]
pub(in crate::admin) mod material;
#[cfg(feature = "node-actions")]
pub(in crate::admin) mod material_actions;
#[cfg(feature = "node-actions")]
pub(in crate::admin) mod material_preview;
pub(in crate::admin) mod metrics;
mod plan;
#[cfg(feature = "node-actions")]
pub(in crate::admin) mod preview;
mod protocol;
mod publication;
mod receiver;
mod replication;
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

/// 业务作用：集群共享 YAML 只允许延续本节点原有的管理证书绑定和出站目标。
/// 参数说明：
/// - `active`：本机已发布的管理引导与目录。
/// - `candidate`：已完整验证的共享配置候选。
/// 返回：身份、授权和监听拓扑仍匹配时才可写入其它业务文件。
pub(super) fn same_file_sync_authority(
    active: &crate::config::GatewaySnapshot,
    candidate: &crate::config::GatewaySnapshot,
) -> bool {
    matches!(
        (&active.admin_management, &candidate.admin_management),
        (Some(active), Some(next)) if active.authority == next.authority
    )
}

/// 业务作用：在监听开放前初始化本地共享原文的共同代次，拒绝重启时观察到的半成品。
/// 参数说明：
/// - `snapshot`：从配置事实源完整装配的启动快照。
/// 返回：本地具名模式确认精确的持久基线后启动，Nacos 继续由配置中心管理。
pub fn initialize_local_file_sync(snapshot: &crate::config::GatewaySnapshot) -> anyhow::Result<()> {
    if !replication::enabled() || snapshot.config_bundle_digest.is_some() {
        return Ok(());
    }
    let plan = snapshot
        .admin_management
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("local YAML replication requires management gRPC"))?;
    let signer = plan
        .receiver
        .as_ref()
        .and_then(|receiver| receiver.issuer.as_ref())
        .ok_or_else(|| {
            anyhow::anyhow!("local YAML replication requires a management issuer identity")
        })?;
    anyhow::ensure!(
        !plan.targets.is_empty()
            && plan.targets.iter().all(|target| {
                target
                    .issuer
                    .as_ref()
                    .is_some_and(|issuer| issuer.cluster() == signer.cluster())
            }),
        "local YAML replication requires explicitly trusted nodes in one cluster"
    );
    // 启动必须先确认未决写入结果；既不是旧代也不是目标代时，中间态不能成为在线配置。
    replication::Published::capture_checked(snapshot)?;
    Ok(())
}
