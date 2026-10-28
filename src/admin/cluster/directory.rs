//! 静态及自注册成员的有限管理目录；读目标不代表远端写入权限。

use crate::config::{monitor::Peer, GatewaySnapshot};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub(in crate::admin) struct Members {
    pub peers: Vec<Peer>,
    pub truncated: bool,
    pub discovery_available: bool,
    pub discovery_enabled: bool,
    pub stale: bool,
    pub conflicting_ids: bool,
}

impl Members {
    /// 业务作用：创建尚未声明远端HTTP目标的完整空目录，独立管理通道不借此触发发现。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无失败标记的空目录，调用方另行判断是否仅声明接入节点。
    pub(in crate::admin) fn empty() -> Self {
        Self {
            peers: Vec::new(),
            truncated: false,
            discovery_available: true,
            discovery_enabled: false,
            stale: false,
            conflicting_ids: false,
        }
    }
}

#[derive(Default)]
pub(in crate::admin) struct Cache {
    peers: Vec<Peer>,
}

/// 业务作用：以配置静态成员为优先，再合并当前实际启用的自注册目录。
///
/// 参数说明：
/// - `discovery`：所有管理监听共享的有界成员查询。
/// - `snapshot`：同代配置与发现开关。
/// - `cache`：当前配置代内最后完整发现的有限成员目录。
///
/// 返回：最多127个远端目标，为本机保留一个位置；失败或截断明确标记。
pub(in crate::admin) async fn read(
    discovery: &super::discovery::Runtime,
    snapshot: &Arc<GatewaySnapshot>,
    cache: &mut Cache,
) -> Members {
    let mut result = Members::empty();
    let mut ids = HashMap::new();
    let mut addresses = HashSet::new();
    for peer in snapshot.admin_monitor.peers.iter().cloned() {
        insert(&mut result, &mut ids, &mut addresses, peer);
    }
    let nacos = &snapshot.discovery.nacos;
    // 双开关与自注册身份共同限定发现域，关闭注册中心时不能借监控重新建立外部连接。
    if !snapshot.admin_monitor.use_discovery || !snapshot.discovery.enabled || !nacos.enabled {
        cache.peers.clear();
        return result;
    }
    let Some(service) = crate::upstream::discovery::self_register_service_name(nacos) else {
        cache.peers.clear();
        return result;
    };
    result.discovery_enabled = true;
    match discovery
        .discover(nacos, service, Duration::from_secs(1))
        .await
    {
        Ok(mut instances) => {
            instances.sort_by(|a, b| (&a.ip, a.port).cmp(&(&b.ip, b.port)));
            for instance in instances {
                let Ok(address) = crate::admin::cluster_metrics_target(&instance) else {
                    result.discovery_available = false;
                    continue;
                };
                if address.ip().is_unspecified() || address.ip().is_multicast() {
                    result.discovery_available = false;
                    continue;
                }
                let id = instance
                    .metadata
                    .get("gateway.node_id")
                    .filter(|value| !value.is_empty() && value.len() <= 64)
                    .cloned()
                    .unwrap_or_else(|| address.to_string());
                insert(
                    &mut result,
                    &mut ids,
                    &mut addresses,
                    Peer {
                        id,
                        address,
                    },
                );
            }
        }
        Err(_) => result.discovery_available = false,
    }
    reconcile(&mut result, cache, &mut ids, &mut addresses);
    result
}

/// 业务作用：仅用完整且无冲突的目录替换已知成员，发现失败不能被解释为节点退休。
///
/// 参数说明：
/// - `members`：当前静态及发现结果。
/// - `cache`：当前配置代内最后完整目录。
/// - `ids`：本轮已接收的稳定身份。
/// - `addresses`：本轮已接收的管理地址。
///
/// 返回：成功时更新有限缓存；证据不完整时合并旧成员并显式保留陈旧或容量状态。
fn reconcile(
    members: &mut Members,
    cache: &mut Cache,
    ids: &mut HashMap<String, std::net::SocketAddr>,
    addresses: &mut HashSet<std::net::SocketAddr>,
) {
    if members.discovery_available && !members.conflicting_ids && !members.truncated {
        cache.peers.clone_from(&members.peers);
    } else {
        // 发现失败不是成员退休证据；保留原成员继续显示失联，不能缩小分母制造全量成功。
        members.stale = !cache.peers.is_empty();
        for peer in cache.peers.iter().cloned() {
            insert(members, ids, addresses, peer);
        }
    }
}

/// 业务作用：去重稳定成员并在插入前执行总节点预算，避免目录规模直接决定外连数量。
///
/// 参数说明：
/// - `members`：本轮有限成员结果。
/// - `ids`：已接收的稳定身份。
/// - `addresses`：已接收的管理地址。
/// - `peer`：待合并的目标。
///
/// 返回：相同成员去重，身份冲突和容量不足明确标记；不能把冲突目录当完整事实。
fn insert(
    members: &mut Members,
    ids: &mut HashMap<String, std::net::SocketAddr>,
    addresses: &mut HashSet<std::net::SocketAddr>,
    peer: Peer,
) {
    if let Some(previous) = ids.get(&peer.id) {
        members.conflicting_ids |= *previous != peer.address;
        return;
    }
    if addresses.contains(&peer.address) {
        return;
    }
    if members.peers.len() >= 127 {
        members.truncated = true;
        return;
    }
    ids.insert(peer.id.clone(), peer.address);
    addresses.insert(peer.address);
    members.peers.push(peer);
}
