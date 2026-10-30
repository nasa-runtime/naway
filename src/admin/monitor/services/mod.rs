//! 单个逻辑服务的集群当前状态按明确成员展示，不保留历史或枚举后端地址。

mod scope;

use crate::admin::{AdminState, BoxBody};
use crate::config::{
    model::{AdminAction, AdminResource},
    GatewaySnapshot,
};
use crate::upstream::observation::{Counts, Row};
use http::{request::Parts, Response, StatusCode};
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize)]
struct NodeView<'a> {
    id: &'a str,
    availability: &'static str,
    config_version: Option<u64>,
    config_fingerprint: Option<&'a str>,
    sample_age_ms: Option<u128>,
    service: Option<&'a Row>,
}

#[derive(Serialize)]
struct Coverage {
    total: usize,
    observed: usize,
    not_present: usize,
    control_nodes: usize,
    unknown: usize,
    complete_directory: bool,
}

#[derive(Serialize)]
struct View<'a> {
    schema_version: u8,
    scope: &'static str,
    workspace: Option<&'a str>,
    service: &'a str,
    availability: &'static str,
    sampling_period_ms: u64,
    coverage: Coverage,
    node_observations: Option<Counts>,
    nodes: Vec<NodeView<'a>>,
}

/// 业务作用：为平台或工作区返回同一逻辑服务的全部预期节点观察，不把缺失节点换算为零。
///
/// 参数说明：
/// - `state`：共享集群采样与目录运行态。
/// - `request`：认证请求与唯一服务查询条件。
/// - `snapshot`：本次授权冻结的活动配置。
/// - `workspace`：明确授权的工作区，None 表示平台读取。
///
/// 返回：有界当前事实与覆盖范围；失权、换代或证据不足不交付旧服务状态。
pub(in crate::admin) fn read(
    state: &AdminState,
    request: &Parts,
    snapshot: &Arc<GatewaySnapshot>,
    workspace: Option<&str>,
) -> Response<BoxBody> {
    let identity = match crate::admin::authenticate_admin_request(request, state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    let authority = if let Some(workspace) = workspace {
        if !snapshot.ownership.allows(
            &identity.principal_id,
            workspace,
            crate::control::ownership::config::Action::Read,
        ) {
            // 工作区权限独立成立，节点范围与平台角色均不能补授访问。
            return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
        }
        let Some(authority) = snapshot.ownership.cluster_scope(workspace) else {
            return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
        };
        Some(authority)
    } else {
        if !identity.allows(AdminResource::Cluster, AdminAction::Read)
            || !identity.allows(AdminResource::Upstreams, AdminAction::Read)
        {
            return crate::admin::plain(
                StatusCode::FORBIDDEN,
                "service monitoring requires cluster and upstream read permissions\n",
            );
        }
        None
    };
    let Some(service) = query(request.uri.query()) else {
        return crate::admin::plain(
            StatusCode::BAD_REQUEST,
            "invalid service monitoring query\n",
        );
    };
    let Ok(_permit) = state.monitor.object_readers.try_acquire() else {
        return crate::admin::plain(
            StatusCode::TOO_MANY_REQUESTS,
            "object monitoring readers exhausted\n",
        );
    };
    let publication = match super::cluster::object_sample(state, snapshot) {
        Ok(value) => value,
        Err(reason) => return super::pending(reason, snapshot.admin_monitor.period),
    };
    let directory = crate::admin::cluster::current(state, snapshot).ok();
    let ids: BTreeSet<&str> = match authority {
        Some((scope, _)) => scope.cluster_nodes.iter().map(String::as_str).collect(),
        None => publication
            .nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect(),
    };
    let total = if authority.is_some() {
        ids.len()
    } else {
        publication.total.max(ids.len())
    };
    let mut nodes = Vec::with_capacity(ids.len());
    let (mut observed, mut not_present, mut controls) = (0usize, 0usize, 0usize);
    let mut observations = Counts::default();
    for id in ids {
        let mut matches = publication.nodes.iter().filter(|node| node.id == id);
        let node = matches.next();
        let mut availability = if matches.next().is_some() {
            "identity_conflict"
        } else {
            status(node)
        };
        let mut view = NodeView {
            id,
            availability,
            config_version: None,
            config_fingerprint: None,
            sample_age_ms: None,
            service: None,
        };
        if availability == "available" {
            let mut matches = directory
                .as_ref()
                .into_iter()
                .flat_map(|value| value.nodes.iter())
                .filter(|node| node.id == id);
            let entry = matches.next();
            availability = if matches.next().is_some() {
                "identity_conflict"
            } else if let Some(entry) =
                entry.filter(|entry| matches!(entry.availability, "available" | "not_ready"))
            {
                match (entry.facts.as_deref(), entry.catalog.as_deref()) {
                    (Some(facts), Some(catalog)) => scope::verify(
                        node.expect("available node")
                            .sample
                            .as_deref()
                            .expect("available sample"),
                        facts,
                        catalog,
                        authority.map(|(_, digest)| (workspace.expect("scoped read"), digest)),
                    ),
                    _ => "pending",
                }
            } else {
                "unknown"
            };
        }
        if availability == "available" {
            let node = node.expect("verified node");
            let sample = node.sample.as_deref().expect("verified sample");
            let rows = &sample
                .service_state
                .as_ref()
                .expect("verified services")
                .rows;
            let row = rows
                .binary_search_by(|row| row.service.cmp(&service))
                .ok()
                .map(|index| &rows[index])
                .filter(|row| workspace.is_none_or(|workspace| row.workspace == workspace));
            // 工作区只接收本域服务事实，节点全局配置身份仅交付平台管理读取。
            view.config_version = workspace.is_none().then_some(sample.state.config_version);
            view.config_fingerprint = workspace
                .is_none()
                .then_some(sample.state.config_fingerprint.as_deref())
                .flatten();
            view.sample_age_ms = Some(node.at.elapsed().as_millis());
            view.service = row;
            if let Some(counts) = row.and_then(|row| row.counts) {
                observed += 1;
                add(&mut observations, counts);
            } else if let Some(row) = row {
                // 发现尚未发布或已经过期时，只保留有限来源信息，不沿用旧实例数量。
                availability = match row.availability {
                    crate::upstream::observation::Availability::Missing => "discovery_missing",
                    _ => "discovery_stale",
                };
            } else {
                not_present += 1;
                availability = "not_present";
            }
        } else if availability == "control_only" {
            controls += 1;
        }
        view.availability = availability;
        nodes.push(view);
    }
    let unknown = total.saturating_sub(observed + not_present + controls);
    let complete_directory = authority.is_some() || publication.complete_directory;
    let view = View {
        schema_version: 1,
        scope: if authority.is_some() {
            "workspace_cluster"
        } else {
            "cluster"
        },
        workspace,
        service: &service,
        availability: if total == 0 {
            "unconfigured"
        } else if unknown > 0 || !complete_directory {
            "partial"
        } else {
            "available"
        },
        sampling_period_ms: snapshot.admin_monitor.period.as_millis() as u64,
        coverage: Coverage {
            total,
            observed,
            not_present,
            control_nodes: controls,
            unknown,
            complete_directory,
        },
        node_observations: (observed > 0).then_some(observations),
        nodes,
    };
    let Some(body) = super::encode(&view) else {
        return super::pending("capacity", snapshot.admin_monitor.period);
    };
    if !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
        // 权限或成员配置在编码期间换代，已完成的旧授权实体仍必须撤下。
        return crate::admin::plain(
            StatusCode::CONFLICT,
            "service monitoring authority changed\n",
        );
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "private, no-store")
        .header("x-content-type-options", "nosniff")
        .header(
            "x-naway-sample-age-ms",
            publication.at.elapsed().as_millis().to_string(),
        )
        .body(crate::full_body(body))
        .expect("fixed service monitoring response")
}

/// 业务作用：在完整目录证明前区分不可观测、控制节点和旧协议，禁止借用本机替代远端。
///
/// 参数说明：
/// - `node`：当前唯一成员事实，缺席为 None。
///
/// 返回：固定有限原因，只有 available 才继续核对归属与当前配置。
fn status(node: Option<&super::routes::Node>) -> &'static str {
    let Some(node) = node else {
        return "unknown";
    };
    let Some(sample) = &node.sample else {
        return node.availability;
    };
    if node.at.elapsed() > Duration::from_millis(sample.sampling_period_ms) * 3 {
        return "stale";
    }
    if sample.state.mode == "admin" {
        return "control_only";
    }
    match &sample.service_state {
        None => "unsupported",
        Some(value) if value.capacity => "capacity",
        Some(_) => "available",
    }
}

/// 业务作用：仅接收一个有限逻辑服务身份，拒绝分页、历史窗口及重复条件。
///
/// 参数说明：
/// - `text`：HTTP 原始查询。
///
/// 返回：合法服务身份；空白、控制字符、过长或未知条件返回 None。
fn query(text: Option<&str>) -> Option<String> {
    let text = text?;
    if text.len() > 1024 {
        return None;
    }
    let mut values = form_urlencoded::parse(text.as_bytes());
    let (key, value) = values.next()?;
    if key != "service"
        || value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || values.next().is_some()
    {
        return None;
    }
    Some(value.into_owned())
}

/// 业务作用：累计各节点的实例观察数，保留重叠分类，不声称已经去重为物理实例数。
///
/// 参数说明：
/// - `sum`：已验证节点的累计观察值。
/// - `value`：当前节点有限计数。
///
/// 返回：原地增加计数；固定成员和实例预算保证正常总数有限。
fn add(sum: &mut Counts, value: Counts) {
    sum.instances = sum.instances.saturating_add(value.instances);
    sum.configured_selectable = sum
        .configured_selectable
        .saturating_add(value.configured_selectable);
    sum.manually_down = sum.manually_down.saturating_add(value.manually_down);
    sum.backup = sum.backup.saturating_add(value.backup);
    sum.active_rejected = sum.active_rejected.saturating_add(value.active_rejected);
}
