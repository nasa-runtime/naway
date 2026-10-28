//! 实时监控采样与静态成员的构建门，不在候选阶段执行发现或网络连接。

use super::model::{AdminAction, AdminMonitorCfg, AdminResource};
use super::AdminAuthRuntimeCfg;
use anyhow::{ensure, Context, Result};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub id: String,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub enabled: bool,
    pub period: Duration,
    pub use_discovery: bool,
    pub peers: Arc<[Peer]>,
}

/// 业务作用：把有限静态监控成员编译为固定地址，只有明确授予跨节点读取权时允许启用。
///
/// 参数说明：
/// - `cfg`：候选采样与成员声明。
/// - `auth`：同一候选已验证的管理认证与权限。
///
/// 返回：纯内存计划；非法周期、地址、重复成员或缺少远端读取授权时拒绝候选。
pub(super) fn build(cfg: &AdminMonitorCfg, auth: &AdminAuthRuntimeCfg) -> Result<Arc<Plan>> {
    ensure!(
        matches!(cfg.sample_interval_ms, 1000 | 2000 | 5000 | 10000),
        "admin.monitor.sample_interval_ms must be 1000, 2000, 5000 or 10000"
    );
    ensure!(
        cfg.peers.len() <= 128,
        "admin.monitor.peers exceeds 128 nodes"
    );
    if cfg.enabled && !cfg.peers.is_empty() {
        // 静态地址属于主动内网访问权，匿名管理或只持工作区凭据都不能借配置打开跳板。
        ensure!(
            auth.enabled && auth.allow_cluster_metrics_scrape,
            "static monitor peers require authenticated cluster metrics scrape permission"
        );
        if auth.rbac_enabled {
            let bit = 1_u128
                << (AdminResource::Cluster.index() * AdminAction::COUNT
                    + AdminAction::Read.index());
            ensure!(
                auth.principals
                    .iter()
                    .any(|principal| principal.permissions & bit != 0),
                "static monitor peers require a cluster/read principal"
            );
        }
    }
    let mut ids = HashSet::new();
    let mut addresses = HashSet::new();
    let mut peers = Vec::with_capacity(cfg.peers.len());
    for peer in &cfg.peers {
        ensure!(
            !peer.id.is_empty()
                && peer.id.len() <= 64
                && peer
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
            "monitor peer id must contain 1..=64 safe ASCII characters"
        );
        let address: SocketAddr = peer
            .address
            .parse()
            .context("monitor peer address must be an IP:port socket address")?;
        ensure!(
            address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
            "monitor peer address must identify a unicast node and a nonzero port"
        );
        ensure!(
            ids.insert(peer.id.clone()) && addresses.insert(address),
            "duplicate monitor peer id or address"
        );
        peers.push(Peer {
            id: peer.id.clone(),
            address,
        });
    }
    Ok(Arc::new(Plan {
        enabled: cfg.enabled,
        period: Duration::from_millis(cfg.sample_interval_ms),
        use_discovery: cfg.use_discovery,
        peers: peers.into(),
    }))
}
