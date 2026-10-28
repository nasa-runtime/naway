//! 管理主体的低敏能力读面；按钮状态来自已编译权限，凭据不进入响应。

use super::{AdminIdentity, AdminState, BoxBody};
use crate::config::model::{AdminAction, AdminResource};
use http::{Response, StatusCode};

/// 业务作用：返回当前已认证主体的实际权限与部署能力，支持页面按权展示。
///
/// 参数说明：
/// - `state`：当前已发布配置与部署模式。
/// - `identity`：认证阶段冻结的主体及权限位。
///
/// 返回：不含认证材料的私有JSON；工作区列表仅包含该主体获授权的域。
pub(super) fn read(state: &AdminState, identity: &AdminIdentity) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let resources = [
        ("config", AdminResource::Config),
        ("routes", AdminResource::Routes),
        ("interface-guard", AdminResource::InterfaceGuard),
        ("sentinel", AdminResource::Sentinel),
        ("acl", AdminResource::Acl),
        ("secrets", AdminResource::Secrets),
        ("consumers", AdminResource::Consumers),
        ("certs", AdminResource::Certs),
        ("cluster", AdminResource::Cluster),
        ("cache", AdminResource::Cache),
        ("connections", AdminResource::Connections),
        ("upstreams", AdminResource::Upstreams),
        ("audit", AdminResource::Audit),
        ("diagnostics", AdminResource::Diagnostics),
    ];
    let actions = [
        ("read", AdminAction::Read),
        ("dry-run", AdminAction::DryRun),
        ("write", AdminAction::Write),
        ("emergency-kill", AdminAction::EmergencyKill),
        ("rollback", AdminAction::Rollback),
    ];
    let permissions = resources
        .into_iter()
        .map(|(name, resource)| {
            let allowed: Vec<_> = actions
                .iter()
                .filter_map(|(name, action)| identity.allows(resource, *action).then_some(*name))
                .collect();
            (name.to_owned(), serde_json::json!(allowed))
        })
        .collect::<serde_json::Map<_, _>>();
    let workspaces = snapshot.ownership.list(&identity.principal_id);
    let workspaces = workspaces.as_array().map(Vec::as_slice).unwrap_or_default();
    let visible: Vec<_> = workspaces
        .iter()
        .take(256)
        .map(|workspace| {
            serde_json::json!({
                "id": workspace["id"],
                "tenant": workspace["tenant"],
                "environment": workspace["environment"],
                "role": workspace["role"],
            })
        })
        .collect();
    let operations = snapshot
        .admin_operations
        .as_ref()
        .filter(|_| state.mode.full_control_plane());
    let operations = match operations {
        Some(plan) => serde_json::json!({
            "enabled": true,
            "accept_proposals": plan.config.accept_proposals,
            "cluster_id": plan.config.cluster_id,
            "max_candidate_bytes": plan.config.max_candidate_bytes,
            "max_targets": crate::config::operations::MAX_TARGETS,
            "min_ttl_seconds": 60,
            "max_ttl_seconds": 86400,
        }),
        None => serde_json::json!({
            "enabled": false
        }),
    };
    let mut response = super::json(
        StatusCode::OK,
        serde_json::json!({
            "schema_version": 1,
            "principal": identity.principal_id.as_ref(),
            "mode": super::admin_mode_name(state.mode),
            "permissions": permissions,
            "ownership_enabled": snapshot.ownership.enabled(),
            "operations": operations,
            "monitor": {
                "enabled": snapshot.admin_monitor.enabled,
                "sampling_period_ms": snapshot.admin_monitor.period.as_millis(),
                "cluster_enabled": super::monitor::cluster_enabled(&snapshot),
            },
            "workspaces": visible,
            "workspaces_truncated": workspaces.len() > 256,
            "features": {
                "config_providers": cfg!(feature = "config-providers"),
                "telemetry": cfg!(feature = "telemetry-otlp"),
                "grpc_edge": cfg!(feature = "grpc-edge"),
                "admin_grpc": cfg!(feature = "admin-grpc"),
                "admin_operations_pgsql": cfg!(feature = "admin-operations-pgsql"),
                "redis_runtime": cfg!(feature = "redis-runtime"),
                "http3": cfg!(feature = "http3"),
            },
        }),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
