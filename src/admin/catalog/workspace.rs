//! 工作区集群对象只使用平台声明成员及同代权限证明，不继承平台目录可见性。

use super::{read as shared, Catalog};
use crate::admin::{AdminIdentity, AdminState, BoxBody};
use crate::config::GatewaySnapshot;
use http::{request::Parts, Response, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Serialize)]
struct Node<'a> {
    id: &'a str,
    availability: &'static str,
}

#[derive(Serialize)]
struct Coverage {
    total: usize,
    complete: usize,
    unknown: usize,
}

#[derive(Serialize)]
struct View<'a> {
    schema_version: u8,
    scope: &'static str,
    workspace: &'a str,
    tenant: &'a str,
    environment: &'a str,
    domain: &'a str,
    availability: &'static str,
    coverage: Coverage,
    nodes: &'a [Node<'a>],
    objects: &'a [shared::Object<'a>],
    total_objects: usize,
    offset: usize,
    next_offset: Option<usize>,
    sampling_period_ms: u64,
}

/// 业务作用：将工作区授权范围内的目录汇聚为同代对象分布，权限缺席与对象缺失严格区分。
///
/// 参数说明：
/// - `state`：共享目录和配置状态，不按浏览器请求发起独立节点采样。
/// - `request`：已认证请求的查询及分页条件。
/// - `identity`：当前调用主体，仍需与冻结快照复验。
/// - `snapshot`：工作区入口冻结的完整权限配置。
/// - `workspace`：已解析的工作区身份。
///
/// 返回：只含授权节点和对象的有界私有响应；缺少证明保持未知，换代拒绝旧游标。
pub(in crate::admin) fn read(
    state: &AdminState,
    request: &Parts,
    identity: &AdminIdentity,
    snapshot: &Arc<GatewaySnapshot>,
    workspace: &str,
) -> Response<BoxBody> {
    if !snapshot.ownership.allows(
        &identity.principal_id,
        workspace,
        crate::control::ownership::config::Action::Read,
    ) {
        // 路径归属不能代替当前主体授权，禁止借内部调用把平台权限扩展到工作区。
        return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let Some((scope, authority)) = snapshot.ownership.cluster_scope(workspace) else {
        return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let Some(query) = shared::query(request.uri.query()) else {
        return crate::admin::plain(StatusCode::BAD_REQUEST, "invalid catalog query\n");
    };
    let Ok(_permit) = state.catalog.requests.try_acquire() else {
        return crate::admin::plain(StatusCode::TOO_MANY_REQUESTS, "catalog readers exhausted\n");
    };
    let publication = if scope.cluster_nodes.is_empty() {
        None
    } else {
        crate::admin::cluster::current(state, snapshot).ok()
    };
    let mut ids: Vec<_> = scope.cluster_nodes.iter().map(String::as_str).collect();
    ids.sort_unstable();
    let mut nodes = Vec::with_capacity(ids.len());
    let mut catalogs = Vec::with_capacity(ids.len());
    let mut hash = Sha256::new();
    hash.update(b"naway-workspace-catalog\0");
    hash.update(authority);
    for text in [workspace, query.domain.as_str(), query.search.as_str()] {
        field(&mut hash, text);
    }
    for id in &ids {
        let mut matches = publication
            .as_ref()
            .into_iter()
            .flat_map(|value| value.nodes.iter())
            .filter(|node| node.id == *id);
        let node = matches.next();
        let conflict = matches.next().is_some();
        let facts = node.and_then(|node| node.facts.as_deref());
        let catalog = node
            .and_then(|node| node.catalog.as_deref())
            .filter(|catalog| {
                facts.is_some_and(|facts| {
                    facts.config_version == catalog.version
                        && facts.config_fingerprint
                            == catalog.fingerprint.map(|value| format!("{value:016x}"))
                })
            });
        let availability = if conflict
            || node.is_some_and(|node| node.availability == "identity_conflict")
        {
            "identity_conflict"
        } else if node.is_none() {
            "unknown"
        } else if !node.is_some_and(|node| matches!(node.availability, "available" | "not_ready")) {
            "unavailable"
        } else if catalog.is_some_and(|catalog| catalog.capacity) {
            "capacity"
        } else if let Some(catalog) = catalog {
            authority_status(catalog, workspace, authority)
        } else if node.is_some_and(|node| node.address.starts_with("gRPC / ")) {
            "pending"
        } else {
            "unsupported"
        };
        // 分页身份只散列授权节点的内部事实，不将全局指纹、地址或其它工作区元数据交付调用者。
        field(&mut hash, id);
        field(&mut hash, availability);
        field(&mut hash, facts.map_or("", |facts| facts.boot_id.as_str()));
        field(
            &mut hash,
            facts
                .and_then(|facts| facts.config_fingerprint.as_deref())
                .unwrap_or_default(),
        );
        hash.update(facts.map_or(0, |facts| facts.config_version).to_be_bytes());
        if let Some(catalog) = catalog {
            hash.update(catalog.digest);
            hash.update(catalog.scope_digest);
        }
        // 目录完整且读取权威一致才证明对象不存在；不一致节点的所有对象都保持不可见。
        catalogs.push(catalog.filter(|_| availability == "available"));
        nodes.push(Node {
            id,
            availability,
        });
    }
    let etag = format!("\"{:x}\"", hash.finalize());
    let conditions = request.headers.get_all(http::header::IF_MATCH);
    if conditions.iter().count() > 1
        || conditions
            .iter()
            .next()
            .is_some_and(|value| value.to_str().ok() != Some(etag.as_str()))
    {
        return crate::admin::plain(
            StatusCode::PRECONDITION_FAILED,
            "catalog generation changed\n",
        );
    }
    if query.offset > 0 && conditions.iter().next().is_none() {
        return crate::admin::plain(
            StatusCode::PRECONDITION_REQUIRED,
            "catalog pagination requires If-Match\n",
        );
    }
    let (total, objects) = match shared::objects(&query, &catalogs, &ids, |entry| {
        entry.workspace == workspace
            && entry.tenant == scope.tenant
            && entry.environment == scope.environment
    }) {
        Ok(objects) => objects,
        Err(reason) => return crate::admin::plain(StatusCode::SERVICE_UNAVAILABLE, reason),
    };
    let complete = catalogs.iter().filter(|catalog| catalog.is_some()).count();
    let availability = if ids.is_empty() {
        "unconfigured"
    } else if complete == ids.len() {
        "available"
    } else {
        "partial"
    };
    let value = View {
        schema_version: 1,
        scope: "workspace_cluster",
        workspace,
        tenant: &scope.tenant,
        environment: &scope.environment,
        domain: &query.domain,
        availability,
        coverage: Coverage {
            total: ids.len(),
            complete,
            unknown: ids.len() - complete,
        },
        nodes: &nodes,
        objects: &objects,
        total_objects: total,
        offset: query.offset,
        next_offset: (query.offset.saturating_add(query.limit) < total)
            .then_some(query.offset + query.limit),
        sampling_period_ms: 2000,
    };
    let mut buffer = shared::Buffer(Vec::with_capacity(8192));
    if serde_json::to_writer(&mut buffer, &value).is_err() {
        return crate::admin::plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "catalog response capacity exhausted; reduce page size\n",
        );
    }
    if !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
        // 对象编码之后复验本机授权，撤权或成员范围变更不能交付旧权限下构造的响应。
        return crate::admin::plain(StatusCode::CONFLICT, "catalog authority changed\n");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "private, no-store")
        .header(http::header::ETAG, etag)
        .header(
            "x-naway-sample-age-ms",
            publication
                .as_ref()
                .map_or(0, |value| value.age_ms())
                .to_string(),
        )
        .body(crate::full_body(buffer.0.into()))
        .expect("fixed workspace catalog response")
}

/// 业务作用：对已确认目录复验工作区读取证明，不把旧协议或未声明工作区推断为已授权。
///
/// 参数说明：
/// - `catalog`：与节点事实同代的完整目录。
/// - `workspace`：当前授权工作区身份。
/// - `authority`：本机冻结的工作区读取权威。
///
/// 返回：完整匹配时可读；不支持与权限分歧返回固定低敏状态。
fn authority_status(catalog: &Catalog, workspace: &str, authority: &[u8; 32]) -> &'static str {
    if !catalog.scope_supported {
        return "unsupported";
    }
    match catalog
        .scopes
        .binary_search_by(|scope| scope.workspace.as_str().cmp(workspace))
    {
        Ok(index) if catalog.scopes[index].digest == *authority => "available",
        _ => "authority_mismatch",
    }
}

/// 业务作用：使分页事实的字符串边界进入摘要，避免不同字段组合形成相同输入。
///
/// 参数说明：
/// - `hash`：当前响应的增量分页身份。
/// - `text`：同一授权范围的身份或事实字段。
///
/// 返回：原地更新SHA-256，不生成中间序列化对象。
fn field(hash: &mut Sha256, text: &str) {
    hash.update((text.len() as u64).to_be_bytes());
    hash.update(text.as_bytes());
}
