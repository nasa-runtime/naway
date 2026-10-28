//! 节点当前部署事实，不读取业务内容、凭据或指标历史。

use super::transport::{self, Endpoint};
use crate::admin::{AdminState, BoxBody};
use crate::config::GatewaySnapshot;
use http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admin) struct Facts {
    pub schema_version: u8,
    pub node_id: Option<String>,
    pub boot_id: String,
    pub mode: String,
    pub ready: bool,
    pub config_version: u64,
    pub config_fingerprint: Option<String>,
    pub discovery_enabled: bool,
    pub configuration_enabled: bool,
    pub proxies: usize,
    pub routes: usize,
    pub services: usize,
}

/// 业务作用：读取固定角色、同代配置和当前就绪门，关闭实时指标采样不影响节点管理事实。
///
/// 参数说明：
/// - `state`：只读管理句柄与当前运行态。
/// - `snapshot`：本轮冻结的配置身份。
///
/// 返回：无凭据、业务正文或原始配置的节点摘要。
pub(in crate::admin) fn collect(state: &AdminState, snapshot: &GatewaySnapshot) -> Facts {
    let summary = snapshot.summary();
    let node_id = std::env::var("GW_NODE_ID")
        .ok()
        .or_else(|| {
            snapshot
                .discovery
                .nacos
                .self_register
                .metadata
                .get("gateway.node_id")
                .cloned()
        })
        .filter(|value| safe_identity(value));
    #[cfg(feature = "admin-grpc")]
    let node_id = snapshot
        .admin_management
        .as_ref()
        .map(|plan| plan.node_id.clone())
        .or(node_id);
    #[cfg(feature = "xds-client")]
    let xds_ready = !snapshot.control_plane.xds.enabled
        || state
            .xds_status
            .as_ref()
            .is_some_and(|status| status.ready());
    #[cfg(not(feature = "xds-client"))]
    let xds_ready = true;
    let ready = !state.mode.runs_data()
        || (state.ready.load(Ordering::Acquire)
            && xds_ready
            && crate::upstream::health::critical_upstreams_not_ready(
                snapshot,
                &state.active_health,
            )
            .is_empty());
    Facts {
        schema_version: 1,
        node_id,
        boot_id: state.monitor.boot_id().to_owned(),
        mode: crate::admin::admin_mode_name(state.mode).into(),
        ready,
        config_version: snapshot.version,
        config_fingerprint: snapshot
            .config_fingerprint
            .map(|value| format!("{value:016x}")),
        discovery_enabled: snapshot.discovery.enabled,
        configuration_enabled: snapshot.config_source.enabled,
        proxies: summary.proxies,
        routes: summary.routes,
        services: summary.upstream_services,
    }
}

/// 业务作用：提供Data、Sidecar和Admin共同遵守的低敏只读事实端点。
///
/// 参数说明：
/// - `state`：已经完成Cluster/Read鉴权的管理状态。
///
/// 返回：当前同代摘要；不启动监控或外部发现。
pub(in crate::admin) fn read(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load_full();
    let facts = collect(state, &snapshot);
    let body = serde_json::to_vec(&facts).expect("fixed node facts serialize");
    super::response(StatusCode::OK, body.into(), 0)
}

/// 业务作用：只接收符合固定协议和新鲜度约束的节点事实，缺失或非法身份不能进入目录权威。
///
/// 参数说明：
/// - `target`：服务器已验证的管理目标。
/// - `authorization`：本机配置派生的只读凭据。
///
/// 返回：有限当前事实及观测时刻；错误分类不暴露原始实体。
pub(super) async fn fetch(
    target: SocketAddr,
    authorization: &str,
) -> Result<(Facts, Instant), &'static str> {
    let reply = transport::get(target, authorization, Endpoint::Facts).await?;
    let facts: Facts = serde_json::from_slice(&reply.bytes).map_err(|_| "invalid_sample")?;
    if !validate(&facts) {
        return Err("invalid_sample");
    }
    // 旧快照不能通过重新建立HTTP连接获得新的观测年龄。
    if reply.age > 6000 {
        return Err("stale");
    }
    let at = reply
        .started
        .checked_sub(Duration::from_millis(reply.age))
        .ok_or("stale")?;
    Ok((facts, at))
}

/// 业务作用：限制节点摘要的身份、角色和数量范围，防止有限HTTP实体在解释后产生含糊目录。
///
/// 参数说明：
/// - `facts`：尚未接受的远端摘要。
///
/// 返回：完整固定合同合法时为true，未知角色或非法身份一律拒绝。
fn validate(facts: &Facts) -> bool {
    facts.schema_version == 1
        && safe_identity(&facts.boot_id)
        && facts.node_id.as_deref().is_none_or(safe_identity)
        && matches!(
            facts.mode.as_str(),
            "admin" | "data" | "sidecar" | "all-in-one"
        )
        && facts.config_fingerprint.as_ref().is_none_or(|value| {
            value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && facts.proxies <= 1_000_000
        && facts.routes <= 1_000_000
        && facts.services <= 1_000_000
}

/// 业务作用：把公开节点标识限制为有限ASCII文本，避免控制字符或过长身份污染管理显示与比较。
///
/// 参数说明：
/// - `value`：节点或进程启动标识。
///
/// 返回：非空且不超过64字节的安全标识为true。
fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}
