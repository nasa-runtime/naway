//! 集群对象分布使用逐节点已确认目录，未知节点不能被当作对象缺失。

use super::Entry;
use crate::admin::{AdminState, BoxBody};
use crate::config::model::{AdminAction, AdminResource};
use http::{request::Parts, Response, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) struct Query {
    pub(super) domain: String,
    pub(super) kind: &'static str,
    pub(super) resource: AdminResource,
    pub(super) search: String,
    pub(super) offset: usize,
    pub(super) limit: usize,
}

#[derive(Serialize)]
struct Node<'a> {
    id: &'a str,
    availability: &'static str,
    mode: Option<&'a str>,
    boot_id: Option<&'a str>,
    config_version: Option<u64>,
    config_fingerprint: Option<&'a str>,
    catalog_digest: Option<String>,
    retained_bytes: Option<usize>,
}

#[derive(Serialize)]
struct Variant<'a> {
    description: &'a Entry,
    nodes: Vec<&'a str>,
}

#[derive(Serialize)]
pub(super) struct Object<'a> {
    kind: &'a str,
    id: &'a str,
    parent: &'a str,
    variants: Vec<Variant<'a>>,
    present: usize,
    missing: Vec<&'a str>,
    unknown: Vec<&'a str>,
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
    domain: &'a str,
    availability: &'static str,
    coverage: Coverage,
    directory: &'a crate::admin::cluster::Coverage,
    nodes: &'a [Node<'a>],
    objects: &'a [Object<'a>],
    total_objects: usize,
    offset: usize,
    next_offset: Option<usize>,
    sampling_period_ms: u64,
}

/// 业务作用：解析固定领域与有限分页参数，不接受任意成员地址、路径或未经约束的过滤表达式。
///
/// 参数说明：
/// - `text`：HTTP解析器分离的查询部分。
///
/// 返回：唯一且有界的查询，重复参数、未知参数或非法数字拒绝。
pub(super) fn query(text: Option<&str>) -> Option<Query> {
    let text = text.unwrap_or_default();
    if text.len() > 1024 {
        return None;
    }
    let mut result = Query {
        domain: "routes".into(),
        kind: "route",
        resource: AdminResource::Routes,
        search: String::new(),
        offset: 0,
        limit: 25,
    };
    let mut seen = BTreeSet::new();
    for (key, value) in form_urlencoded::parse(text.as_bytes()) {
        if !seen.insert(key.to_string()) {
            return None;
        }
        match key.as_ref() {
            "domain" => result.domain = value.into_owned(),
            "search" if value.len() <= 64 && !value.chars().any(char::is_control) => {
                result.search = value.to_lowercase()
            }
            "offset" => result.offset = value.parse().ok()?,
            "limit" => result.limit = value.parse().ok()?,
            _ => return None,
        }
    }
    if result.offset > 4096 || !(1..=100).contains(&result.limit) {
        return None;
    }
    (result.kind, result.resource) = match result.domain.as_str() {
        "routes" => ("route", AdminResource::Routes),
        "listeners" => ("listener", AdminResource::Config),
        "upstreams" => ("upstream", AdminResource::Upstreams),
        _ => return None,
    };
    Some(result)
}

/// 业务作用：按平台领域权限聚合当前节点对象，分页绑定全体节点配置向量，不能将单节点目录冒充集群。
///
/// 参数说明：
/// - `state`：已认证且具备Cluster/Read的管理入口。
/// - `request`：固定目录接口的查询和可选If-Match。
///
/// 返回：有界对象分布与逐节点覆盖；领域拒绝403、换代412、超量503或采样中202。
pub(in crate::admin) async fn read(state: &AdminState, request: &Parts) -> Response<BoxBody> {
    let snapshot = state.snap.load_full();
    let identity = match crate::admin::authenticate_admin_request(request, state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    let Some(query) = query(request.uri.query()) else {
        return crate::admin::plain(StatusCode::BAD_REQUEST, "invalid catalog query\n");
    };
    if !identity.allows(AdminResource::Cluster, AdminAction::Read)
        || !identity.allows(query.resource, AdminAction::Read)
    {
        // 集群成员读取权不代表业务对象读取权，工作区专用主体不能借汇聚入口读取平台目录。
        if let Err(error) = crate::admin::record_admin_audit(
            state,
            &identity,
            request,
            query.resource,
            AdminAction::Read,
            "completed",
            Some(StatusCode::FORBIDDEN.as_u16()),
        )
        .await
        {
            // 审计出口故障不改变拒绝结果，避免依赖不可用把领域权限变成可绕过门禁。
            tracing::error!(%error, "catalog permission denial audit failed");
        }
        return crate::admin::plain(
            StatusCode::FORBIDDEN,
            "catalog domain permission required\n",
        );
    }
    let Ok(_permit) = state.catalog.requests.try_acquire() else {
        return crate::admin::plain(StatusCode::TOO_MANY_REQUESTS, "catalog readers exhausted\n");
    };
    let publication = match crate::admin::cluster::current(state, &snapshot) {
        Ok(publication) => publication,
        Err(reason) => return pending(reason),
    };
    let mut nodes = Vec::with_capacity(publication.nodes.len());
    let mut catalogs = Vec::with_capacity(publication.nodes.len());
    let mut hash = Sha256::new();
    // 分页身份由完整节点向量决定，不能额外混入接入Admin版本而让入口切换必然使游标失效。
    hash.update([
        u8::from(publication.coverage.conflicting_ids),
        u8::from(publication.coverage.truncated),
        u8::from(publication.coverage.directory_stale),
        u8::from(publication.coverage.discovery_available),
        u8::from(publication.coverage.limited_to_local),
    ]);
    for text in [&query.domain, &query.search] {
        hash.update((text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    for node in publication.nodes.iter() {
        let facts = node.facts.as_deref();
        let catalog = node.catalog.as_deref().filter(|catalog| {
            matches!(node.availability, "available" | "not_ready")
                && facts.is_some_and(|facts| {
                    facts.config_version == catalog.version
                        && facts.config_fingerprint
                            == catalog.fingerprint.map(|value| format!("{value:016x}"))
                })
        });
        let availability = if !matches!(node.availability, "available" | "not_ready") {
            node.availability
        } else if catalog.is_some_and(|catalog| catalog.capacity) {
            "capacity"
        } else if catalog.is_some() {
            "available"
        } else if node.address.starts_with("gRPC / ") {
            "pending"
        } else {
            "unsupported"
        };
        let value = Node {
            id: &node.id,
            availability,
            mode: facts.map(|facts| facts.mode.as_str()),
            boot_id: facts.map(|facts| facts.boot_id.as_str()),
            config_version: facts.map(|facts| facts.config_version),
            config_fingerprint: facts.and_then(|facts| facts.config_fingerprint.as_deref()),
            catalog_digest: catalog.map(|catalog| {
                format!("{:x}", sha2::digest::Output::<Sha256>::from(catalog.digest))
            }),
            retained_bytes: catalog.map(|catalog| catalog.bytes),
        };
        // 分页身份覆盖每个节点的实际代与完整性，节点失联或换代都会使旧页游标失效。
        for text in [
            value.id,
            value.availability,
            value.mode.unwrap_or_default(),
            value.boot_id.unwrap_or_default(),
            value.config_fingerprint.unwrap_or_default(),
            value.catalog_digest.as_deref().unwrap_or_default(),
        ] {
            hash.update((text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(value.config_version.unwrap_or_default().to_be_bytes());
        catalogs.push(catalog.filter(|catalog| !catalog.capacity));
        nodes.push(value);
    }
    let etag = format!("\"{:x}\"", hash.finalize());
    if request
        .headers
        .get(http::header::IF_MATCH)
        .is_some_and(|value| value.to_str().ok() != Some(etag.as_str()))
    {
        return crate::admin::plain(
            StatusCode::PRECONDITION_FAILED,
            "catalog generation changed\n",
        );
    }
    if query.offset > 0 && !request.headers.contains_key(http::header::IF_MATCH) {
        return crate::admin::plain(
            StatusCode::PRECONDITION_REQUIRED,
            "catalog pagination requires If-Match\n",
        );
    }
    let ids: Vec<_> = nodes.iter().map(|node| node.id).collect();
    let (total, objects) = match objects(&query, &catalogs, &ids, |_| true) {
        Ok(objects) => objects,
        Err(reason) => return crate::admin::plain(StatusCode::SERVICE_UNAVAILABLE, reason),
    };
    let complete = catalogs.iter().filter(|catalog| catalog.is_some()).count();
    let value = View {
        schema_version: 1,
        scope: "cluster",
        domain: &query.domain,
        availability: if complete == nodes.len()
            && !publication.coverage.conflicting_ids
            && !publication.coverage.truncated
            && publication.coverage.discovery_available
            && !publication.coverage.directory_stale
            && !publication.coverage.limited_to_local
        {
            "available"
        } else {
            "partial"
        },
        coverage: Coverage {
            total: nodes.len(),
            complete,
            unknown: nodes.len() - complete,
        },
        directory: &publication.coverage,
        nodes: &nodes,
        objects: &objects,
        total_objects: total,
        offset: query.offset,
        next_offset: (query.offset.saturating_add(query.limit) < total)
            .then_some(query.offset + query.limit),
        sampling_period_ms: 2000,
    };
    let mut buffer = Buffer(Vec::with_capacity(8192));
    if serde_json::to_writer(&mut buffer, &value).is_err() {
        return crate::admin::plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "catalog response capacity exhausted; reduce page size\n",
        );
    }
    if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
        // 编码完成后仍复验授权代，旧主体或旧目录的结果不能越过本机权限撤销。
        return crate::admin::plain(StatusCode::CONFLICT, "catalog authority changed\n");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::ETAG, etag)
        .header("x-naway-sample-age-ms", publication.age_ms().to_string())
        .body(crate::full_body(buffer.0.into()))
        .expect("fixed catalog response")
}

/// 业务作用：表达尚无可读取的成员快照，不返回假空目录作为成功响应。
///
/// 参数说明：
/// - `reason`：固定采样或关闭原因。
///
/// 返回：无历史数据的202状态。
fn pending(reason: &str) -> Response<BoxBody> {
    let mut response = crate::admin::json(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "scope": "cluster", "availability": reason
        }),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(in crate::admin) struct Buffer(pub(in crate::admin) Vec<u8>);

impl std::io::Write for Buffer {
    /// 业务作用：在输出分配前限制目录响应为4MiB，超限不能交付半个分布集合。
    ///
    /// 参数说明：
    /// - `bytes`：当前JSON编码片段。
    ///
    /// 返回：完整接收或容量错误，不进行截断写入。
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (4 * 1024 * 1024usize).saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("catalog response capacity exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：完成纯内存响应编码，不产生外部副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：内存无需刷新，始终成功。
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 业务作用：先按调用方冻结的归属范围筛选，再生成对象分布；未确认节点不能成为缺失证据。
///
/// 参数说明：
/// - `query`：已验证的领域、搜索和分页。
/// - `catalogs`：通过当前授权与配置代复验的目录，其它节点为空。
/// - `ids`：与目录逐项对应的授权节点身份。
/// - `visible`：本次调用可读取的对象归属条件。
///
/// 返回：总对象数与有限当前页；唯一对象超限拒绝，不交付截断清单。
pub(super) fn objects<'a>(
    query: &Query,
    catalogs: &[Option<&'a super::Catalog>],
    ids: &[&'a str],
    visible: impl Fn(&Entry) -> bool,
) -> Result<(usize, Vec<Object<'a>>), &'static str> {
    let mut groups = BTreeMap::<(&str, &str, &str), Vec<(usize, &Entry)>>::new();
    for (index, catalog) in catalogs.iter().enumerate() {
        let Some(catalog) = catalog else {
            continue;
        };
        for entry in catalog
            .entries
            .iter()
            .filter(|entry| entry.kind == query.kind && visible(entry))
        {
            if !query.search.is_empty()
                && ![&entry.id, &entry.parent, &entry.workspace]
                    .into_iter()
                    .any(|text| text.to_lowercase().contains(&query.search))
            {
                continue;
            }
            if groups.len() == 4096 && !groups.contains_key(&entry.key()) {
                return Err("catalog object capacity exhausted; narrow the query\n");
            }
            groups.entry(entry.key()).or_default().push((index, entry));
        }
    }
    let total = groups.len();
    let objects: Vec<_> = groups
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|((kind, parent, id), occurrences)| {
            let mut variants = Vec::<Variant<'_>>::new();
            let present: BTreeSet<_> = occurrences.iter().map(|(index, _)| *index).collect();
            for (index, entry) in &occurrences {
                if let Some(variant) = variants
                    .iter_mut()
                    .find(|variant| variant.description == *entry)
                {
                    variant.nodes.push(ids[*index]);
                } else {
                    variants.push(Variant {
                        description: entry,
                        nodes: vec![ids[*index]],
                    });
                }
            }
            let mut missing = Vec::new();
            let mut unknown = Vec::new();
            for (index, id) in ids.iter().enumerate() {
                if !present.contains(&index) {
                    if catalogs[index].is_some() {
                        missing.push(*id);
                    } else {
                        unknown.push(*id);
                    }
                }
            }
            Object {
                kind,
                id,
                parent,
                variants,
                present: present.len(),
                missing,
                unknown,
            }
        })
        .collect();
    Ok((total, objects))
}
