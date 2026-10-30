//! 实时路由分页绑定同一采样与授权代，缺席节点不被隐去，工作区不继承平台数据。

use super::{aggregate, scope, Publication};
use crate::admin::{AdminState, BoxBody};
use crate::config::{
    model::{AdminAction, AdminResource},
    GatewaySnapshot,
};
use http::{request::Parts, Response, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

struct Query {
    search: String,
    offset: usize,
    limit: usize,
}

#[derive(Serialize)]
struct NodeView<'a> {
    id: &'a str,
    availability: &'static str,
}

#[derive(Serialize)]
struct Coverage {
    total: usize,
    complete: usize,
    valid: usize,
    control_nodes: usize,
    unknown: usize,
    complete_directory: bool,
}

#[derive(Serialize)]
struct View<'a> {
    schema_version: u8,
    scope: &'static str,
    workspace: Option<&'a str>,
    availability: &'static str,
    sampling_period_ms: u64,
    coverage: Coverage,
    nodes: Vec<NodeView<'a>>,
    rows: Vec<aggregate::Row<'a>>,
    total_rows: usize,
    offset: usize,
    next_offset: Option<usize>,
}

/// 业务作用：在当前主体、配置与节点证明范围内读取路由实时区间，不返回历史或全局流量分摊。
///
/// 参数说明：
/// - `state`：共享集群采样及目录的唯一管理运行态。
/// - `request`：经认证的原始查询与分页条件。
/// - `snapshot`：本次请求冻结的完整权限配置。
/// - `workspace`：独立工作区域，None代表平台集群读取。
///
/// 返回：有限当前页与覆盖情况；缺权限、证据、容量或同代条件时拒绝旧结果。
pub(in crate::admin) fn read(
    state: &AdminState,
    request: &Parts,
    snapshot: &Arc<GatewaySnapshot>,
    workspace: Option<&str>,
) -> Response<BoxBody> {
    // 在调用方冻结快照之后重新认证，旧凭据或旧角色不能与更新后的范围混合使用。
    let identity = match crate::admin::authenticate_admin_request(request, state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    let scope = if let Some(workspace) = workspace {
        if !snapshot.ownership.allows(
            &identity.principal_id,
            workspace,
            crate::control::ownership::config::Action::Read,
        ) {
            // 域名存在与否都不能越过工作区门，平台角色不会补授本域可见性。
            return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
        }
        let Some(scope) = snapshot.ownership.cluster_scope(workspace) else {
            return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
        };
        Some(scope)
    } else {
        if !identity.allows(AdminResource::Cluster, AdminAction::Read)
            || !identity.allows(AdminResource::Routes, AdminAction::Read)
        {
            return crate::admin::plain(
                StatusCode::FORBIDDEN,
                "route monitoring requires cluster and route read permissions\n",
            );
        }
        None
    };
    let Some(query) = query(request.uri.query()) else {
        return crate::admin::plain(StatusCode::BAD_REQUEST, "invalid route monitoring query\n");
    };
    let Ok(_permit) = state.monitor.object_readers.try_acquire() else {
        return crate::admin::plain(
            StatusCode::TOO_MANY_REQUESTS,
            "route monitoring readers exhausted\n",
        );
    };
    let publication = match super::super::cluster::object_sample(state, snapshot) {
        Ok(value) => value,
        Err(reason) => return super::super::pending(reason, snapshot.admin_monitor.period),
    };
    let directory = workspace.and_then(|_| crate::admin::cluster::current(state, snapshot).ok());
    let ids: BTreeSet<&str> = match scope {
        Some((scope, _)) => scope.cluster_nodes.iter().map(String::as_str).collect(),
        None => publication
            .nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect(),
    };
    let total = if scope.is_some() {
        ids.len()
    } else {
        publication.total.max(ids.len())
    };
    let mut nodes = Vec::with_capacity(ids.len());
    let mut rows = aggregate::Rows::default();
    let (mut complete, mut valid, mut controls) = (0usize, 0usize, 0usize);
    let mut hash = Sha256::new();
    stamp(&mut hash, state.monitor.boot_id().as_bytes());
    stamp(&mut hash, workspace.unwrap_or_default().as_bytes());
    stamp(&mut hash, query.search.as_bytes());
    hash.update(publication.sequence.to_be_bytes());
    if let Some((_, authority)) = scope {
        hash.update(authority);
    }
    for id in ids {
        let mut matches = publication.nodes.iter().filter(|node| node.id == id);
        let node = matches.next();
        let mut availability = if matches.next().is_some() {
            "identity_conflict"
        } else {
            status(node)
        };
        if availability == "available" {
            if let Some((_, authority)) = scope {
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
                        (Some(facts), Some(catalog)) => {
                            hash.update(catalog.digest);
                            hash.update(catalog.scope_digest);
                            scope::verify(
                                node.expect("available node"),
                                facts,
                                catalog,
                                workspace.expect("scoped read"),
                                authority,
                            )
                        }
                        _ => "pending",
                    }
                } else {
                    "unknown"
                };
            }
        }
        if availability == "available" {
            let node = node.expect("available node");
            if !rows.add(node, workspace, &query.search) {
                // 全量目录超出聚合预算时撤下整页，禁止把截断结果标为完整或无匹配路由。
                return super::super::pending("capacity", snapshot.admin_monitor.period);
            }
            complete += 1;
            valid += usize::from(node.interval_ms.is_some());
            if node.interval_ms.is_none() {
                availability = "sampling";
            }
        } else if availability == "control_only" {
            controls += 1;
        }
        stamp(&mut hash, id.as_bytes());
        stamp(&mut hash, availability.as_bytes());
        nodes.push(NodeView {
            id,
            availability,
        });
    }
    let unknown = total.saturating_sub(complete + controls);
    let complete_directory = scope.is_some() || publication.complete_directory;
    let unknown_rows = unknown + usize::from(!complete_directory);
    let (total_rows, rows) = rows.page(unknown_rows, query.offset, query.limit);
    let etag = format!("\"{:x}\"", hash.finalize());
    if let Some(response) = condition(request, &query, &etag) {
        return response;
    }
    let value = View {
        schema_version: 1,
        scope: if scope.is_some() {
            "workspace_cluster"
        } else {
            "cluster"
        },
        workspace,
        availability: if total == 0 {
            "unconfigured"
        } else if unknown > 0 || !complete_directory {
            "partial"
        } else if valid < complete {
            "sampling"
        } else {
            "available"
        },
        sampling_period_ms: snapshot.admin_monitor.period.as_millis() as u64,
        coverage: Coverage {
            total,
            complete,
            valid,
            control_nodes: controls,
            unknown,
            complete_directory,
        },
        nodes,
        rows,
        total_rows,
        offset: query.offset,
        next_offset: (query.offset.saturating_add(query.limit) < total_rows)
            .then_some(query.offset + query.limit),
    };
    let Some(body) = super::super::encode(&value) else {
        return super::super::pending("capacity", snapshot.admin_monitor.period);
    };
    if !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
        // 编码期间本机权限或成员范围可能被热撤销，旧授权实体必须在交付前失效。
        return crate::admin::plain(StatusCode::CONFLICT, "route monitoring authority changed\n");
    }
    response(body, &publication, etag)
}

/// 业务作用：区分控制节点、旧协议、容量与陈旧采样，任何缺口不默认成为零流量。
///
/// 参数说明：
/// - `node`：唯一成员对应的当前事实，缺席时为None。
///
/// 返回：固定有限状态，只有available可以进入路由累计。
fn status(node: Option<&super::Node>) -> &'static str {
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
    match &sample.route_traffic {
        None => "unsupported",
        Some(value) if value.capacity => "capacity",
        Some(_) => "available",
    }
}

/// 业务作用：拒绝重复、历史或无界查询，搜索只在配置对象身份中进行。
///
/// 参数说明：
/// - `text`：HTTP原始查询字符串。
///
/// 返回：有限的搜索与分页条件；非法输入返回None。
fn query(text: Option<&str>) -> Option<Query> {
    let text = text.unwrap_or_default();
    if text.len() > 1024 {
        return None;
    }
    let mut seen = BTreeSet::new();
    let mut result = Query {
        search: String::new(),
        offset: 0,
        limit: 25,
    };
    for (key, value) in form_urlencoded::parse(text.as_bytes()) {
        if !seen.insert(key.to_string()) {
            return None;
        }
        match key.as_ref() {
            "search" if value.len() <= 64 && !value.chars().any(char::is_control) => {
                result.search = value.into_owned()
            }
            "offset" if value.bytes().all(|byte| byte.is_ascii_digit()) => {
                result.offset = value.parse().ok()?
            }
            "limit" if value.bytes().all(|byte| byte.is_ascii_digit()) => {
                result.limit = value.parse().ok()?
            }
            _ => return None,
        }
    }
    (result.offset <= 1024 && (1..=100).contains(&result.limit)).then_some(result)
}

/// 业务作用：分页和详情只接受同一实时样本，新的区间不能悄悄接到旧页之后。
///
/// 参数说明：
/// - `request`：原请求的条件头。
/// - `query`：经过范围验证的分页条件。
/// - `etag`：包含样本、节点证据与授权范围的当前摘要。
///
/// 返回：条件满足为None；缺失或过期条件给出明确拒绝，不保存旧页供重查。
fn condition(request: &Parts, query: &Query, etag: &str) -> Option<Response<BoxBody>> {
    let values = request.headers.get_all(http::header::IF_MATCH);
    if values.iter().count() > 1
        || values
            .iter()
            .next()
            .is_some_and(|value| value.to_str().ok() != Some(etag))
    {
        return Some(crate::admin::plain(
            StatusCode::PRECONDITION_FAILED,
            "route sample changed\n",
        ));
    }
    if query.offset > 0 && values.iter().next().is_none() {
        return Some(crate::admin::plain(
            StatusCode::PRECONDITION_REQUIRED,
            "route pagination requires If-Match\n",
        ));
    }
    None
}

/// 业务作用：让范围与成员状态以无歧义字段参与分页身份，不序列化内部业务结构。
///
/// 参数说明：
/// - `hash`：当前分页摘要。
/// - `bytes`：一个完整且有限的字段。
///
/// 返回：原地追加长度与原始字节，不分配副本。
fn stamp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// 业务作用：交付已完成同代复验的当前实体，响应不能被跨用户缓存。
///
/// 参数说明：
/// - `body`：已在1MiB预算内编码的完整实体。
/// - `publication`：原采样轮次，用于有效年龄。
/// - `etag`：本范围的分页条件。
///
/// 返回：共享Bytes的私有JSON响应，不创建额外正文副本。
fn response(body: bytes::Bytes, publication: &Publication, etag: String) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "private, no-store")
        .header("x-content-type-options", "nosniff")
        .header(http::header::ETAG, etag)
        .header(
            "x-naway-sample-age-ms",
            publication.at.elapsed().as_millis().to_string(),
        )
        .body(crate::full_body(body))
        .expect("fixed route monitoring response")
}
