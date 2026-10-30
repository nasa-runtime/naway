//! 消费者绑定按节点事实和归属读取，未知节点不成为凭据缺失的证明。

use super::{Directory, Entry};
use crate::admin::{AdminIdentity, AdminState, BoxBody};
use crate::config::model::{AdminAction, AdminResource};
use crate::config::GatewaySnapshot;
use http::{request::Parts, Response, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Query {
    search: String,
    offset: usize,
    limit: usize,
}

struct Scope<'a> {
    workspace: &'a str,
    tenant: &'a str,
    environment: &'a str,
    nodes: &'a [String],
    authority: &'a [u8; 32],
}

#[derive(Serialize)]
struct Node<'a> {
    id: &'a str,
    availability: &'static str,
}

#[derive(Serialize)]
struct Variant<'a> {
    binding: &'a Entry,
    nodes: Vec<&'a str>,
}

#[derive(Serialize)]
struct Binding<'a> {
    consumer: &'a str,
    proxy: &'a str,
    route: &'a str,
    ordinal: u32,
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
    workspace: Option<&'a str>,
    availability: &'static str,
    coverage: Coverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<&'a crate::admin::cluster::Coverage>,
    nodes: &'a [Node<'a>],
    bindings: &'a [Binding<'a>],
    total_bindings: usize,
    offset: usize,
    next_offset: Option<usize>,
    sampling_period_ms: u64,
}

/// 业务作用：解析有限的精确文本搜索和分页，重复或未知参数不能被静默覆盖。
///
/// 参数说明：
/// - `text`：原请求查询部分。
///
/// 返回：合法查询；非法字段、控制字符、超量或非数字返回无值。
fn query(text: Option<&str>) -> Option<Query> {
    let text = text.unwrap_or_default();
    if text.len() > 1024 {
        return None;
    }
    let mut query = Query {
        search: String::new(),
        offset: 0,
        limit: 25,
    };
    let mut seen = BTreeSet::new();
    for (name, value) in form_urlencoded::parse(text.as_bytes()) {
        if !seen.insert(name.to_string()) {
            return None;
        }
        match name.as_ref() {
            "search" if value.len() <= 64 && !value.chars().any(char::is_control) => {
                query.search = value.into_owned()
            }
            "offset" => query.offset = value.parse().ok()?,
            "limit" => query.limit = value.parse().ok()?,
            _ => return None,
        }
    }
    (query.offset <= 4096 && (1..=100).contains(&query.limit)).then_some(query)
}

/// 业务作用：在平台集群与消费者双领域权限通过后读取整个声明集群的凭据分布。
///
/// 参数说明：
/// - `state`：共享节点事实及权限状态。
/// - `request`：已进入管理路由的请求头和查询。
///
/// 返回：当前有限分布；缺少任一领域权限返回403并审计，不能回退到本机消费者。
pub(in crate::admin) async fn platform(state: &AdminState, request: &Parts) -> Response<BoxBody> {
    let snapshot = state.snap.load_full();
    let identity = match crate::admin::authenticate_admin_request(request, state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if !identity.allows(AdminResource::Cluster, AdminAction::Read)
        || !identity.allows(AdminResource::Consumers, AdminAction::Read)
    {
        // 集群成员可见性不授予消费者身份读取权，直接调用API也必须经过双门。
        if let Err(error) = crate::admin::record_admin_audit(
            state,
            &identity,
            request,
            AdminResource::Consumers,
            AdminAction::Read,
            "completed",
            Some(403),
        )
        .await
        {
            tracing::error!(%error, "consumer permission denial audit failed");
        }
        return crate::admin::plain(
            StatusCode::FORBIDDEN,
            "consumer domain permission required\n",
        );
    }
    read(state, request, &snapshot, None)
}

/// 业务作用：在工作区读取权与平台成员范围内展示凭据，不继承平台消费者权限。
///
/// 参数说明：
/// - `state`：共享集群事实。
/// - `request`：工作区路径及有限查询。
/// - `identity`：当前认证主体。
/// - `snapshot`：冻结的本机授权快照。
/// - `workspace`：明确选择的工作区。
///
/// 返回：只含同代权限证明匹配的归属；未授权工作区返回404。
pub(in crate::admin) fn workspace(
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
        // 对象归属与主体权限是两个条件，知道工作区名称不能绕过读取授权。
        return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let Some((scope, authority)) = snapshot.ownership.cluster_scope(workspace) else {
        return crate::admin::plain(StatusCode::NOT_FOUND, "not found\n");
    };
    read(
        state,
        request,
        snapshot,
        Some(Scope {
            workspace,
            tenant: &scope.tenant,
            environment: &scope.environment,
            nodes: &scope.cluster_nodes,
            authority,
        }),
    )
}

/// 业务作用：将同一授权范围的节点向量、目录完整性和绑定差异一次编码，不读取文件或外呼节点。
///
/// 参数说明：
/// - `state`：已获权的共享管理入口。
/// - `request`：分页ETag及查询。
/// - `snapshot`：本机权限冻结点。
/// - `scope`：工作区成员和权限证明，平台读取为空。
///
/// 返回：有界分布与稳定ETag；采样中202、换代412、容量不足503，权限换代409。
fn read(
    state: &AdminState,
    request: &Parts,
    snapshot: &Arc<GatewaySnapshot>,
    scope: Option<Scope<'_>>,
) -> Response<BoxBody> {
    let Some(query) = query(request.uri.query()) else {
        return crate::admin::plain(StatusCode::BAD_REQUEST, "invalid consumer query\n");
    };
    let Ok(_permit) = state.catalog.requests.try_acquire() else {
        return crate::admin::plain(StatusCode::TOO_MANY_REQUESTS, "catalog readers exhausted\n");
    };
    let publication = match crate::admin::cluster::current(state, snapshot) {
        Ok(publication) => Some(publication),
        Err(_) if scope.is_some() => None,
        Err(reason) => {
            let mut response = crate::admin::json(
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "scope": "cluster",
                    "availability": reason,
                }),
            );
            response.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            return response;
        }
    };
    let mut ids: Vec<_> = match &scope {
        Some(scope) => scope.nodes.iter().map(String::as_str).collect(),
        None => publication
            .iter()
            .flat_map(|publication| publication.nodes.iter())
            .map(|node| node.id.as_str())
            .collect(),
    };
    ids.sort_unstable();
    ids.dedup();
    let mut nodes = Vec::with_capacity(ids.len());
    let mut directories = Vec::with_capacity(ids.len());
    let mut hash = Sha256::new();
    hash.update(b"naway-consumer-view\0");
    field(&mut hash, &query.search);
    if let Some(scope) = &scope {
        field(&mut hash, scope.workspace);
        hash.update(scope.authority);
    } else if let Some(publication) = &publication {
        hash.update([
            u8::from(publication.coverage.conflicting_ids),
            u8::from(publication.coverage.truncated),
            u8::from(publication.coverage.directory_stale),
            u8::from(publication.coverage.discovery_available),
            u8::from(publication.coverage.limited_to_local),
        ]);
    }
    for id in &ids {
        let mut found = publication
            .iter()
            .flat_map(|publication| publication.nodes.iter())
            .filter(|node| node.id == *id);
        let node = found.next();
        let conflict = found.next().is_some();
        let facts = node.and_then(|node| node.facts.as_deref());
        let directory = node
            .and_then(|node| node.consumers.as_deref())
            .filter(|directory| {
                facts.is_some_and(|facts| {
                    facts.config_version == directory.version
                        && facts.config_fingerprint
                            == directory.fingerprint.map(|value| format!("{value:016x}"))
                })
            });
        let mut availability = match node {
            _ if conflict => "identity_conflict",
            None => "unknown",
            Some(node) if !matches!(node.availability, "available" | "not_ready") => {
                node.availability
            }
            Some(node) if !node.consumers_supported => "unsupported",
            _ if directory.is_some_and(|directory| {
                directory.capacity || directory.bytes > super::MAX_BYTES
            }) =>
            {
                "capacity"
            }
            _ if directory.is_none() => "pending",
            _ => "available",
        };
        if availability == "available" {
            if let Some(scope) = &scope {
                let catalog = node
                    .and_then(|node| node.catalog.as_deref())
                    .filter(|catalog| {
                        facts.is_some_and(|facts| {
                            catalog.version == facts.config_version
                                && facts.config_fingerprint
                                    == catalog.fingerprint.map(|value| format!("{value:016x}"))
                        })
                    });
                availability = match catalog {
                    Some(catalog) if catalog.capacity => "capacity",
                    Some(catalog) if !catalog.scope_supported => "unsupported",
                    Some(catalog) => match catalog
                        .scopes
                        .binary_search_by(|entry| entry.workspace.as_str().cmp(scope.workspace))
                    {
                        Ok(index) if catalog.scopes[index].digest == *scope.authority => {
                            "available"
                        }
                        _ => "authority_mismatch",
                    },
                    None => "pending",
                };
            }
        }
        // 只有当前目录及同代工作区权限都成立，才允许推断其它绑定不存在。
        directories.push(directory.filter(|_| availability == "available"));
        nodes.push(Node {
            id,
            availability,
        });
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
        if let Some(directory) = directory {
            hash.update(directory.digest);
        }
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
            "consumer generation changed\n",
        );
    }
    if query.offset > 0 && conditions.iter().next().is_none() {
        return crate::admin::plain(
            StatusCode::PRECONDITION_REQUIRED,
            "consumer pagination requires If-Match\n",
        );
    }
    let visible = |entry: &Entry| {
        scope.as_ref().is_none_or(|scope| {
            entry.workspace == scope.workspace
                && entry.tenant == scope.tenant
                && entry.environment == scope.environment
        })
    };
    let (total, bindings) = match bindings(&query, &directories, &ids, visible) {
        Ok(value) => value,
        Err(reason) => return crate::admin::plain(StatusCode::SERVICE_UNAVAILABLE, reason),
    };
    let complete = directories.iter().filter(|value| value.is_some()).count();
    let all = complete == ids.len()
        && (scope.is_some()
            || publication.as_ref().is_some_and(|publication| {
                !publication.coverage.conflicting_ids
                    && !publication.coverage.truncated
                    && !publication.coverage.directory_stale
                    && publication.coverage.discovery_available
                    && !publication.coverage.limited_to_local
            }));
    let view = View {
        schema_version: 1,
        scope: if scope.is_some() {
            "workspace_cluster"
        } else {
            "cluster"
        },
        workspace: scope.as_ref().map(|scope| scope.workspace),
        availability: if ids.is_empty() {
            "unconfigured"
        } else if all {
            "available"
        } else {
            "partial"
        },
        coverage: Coverage {
            total: ids.len(),
            complete,
            unknown: ids.len() - complete,
        },
        directory: publication
            .as_ref()
            .filter(|_| scope.is_none())
            .map(|publication| &publication.coverage),
        nodes: &nodes,
        bindings: &bindings,
        total_bindings: total,
        offset: query.offset,
        next_offset: (query.offset.saturating_add(query.limit) < total)
            .then_some(query.offset + query.limit),
        sampling_period_ms: 2000,
    };
    let mut buffer = crate::admin::catalog::read::Buffer(Vec::with_capacity(8192));
    if serde_json::to_writer(&mut buffer, &view).is_err() {
        return crate::admin::plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "consumer response capacity exhausted\n",
        );
    }
    if !Arc::ptr_eq(&state.snap.load_full(), snapshot) {
        // 权限撤销与编码可能并发，交付前必须再次确认本机完整授权代。
        return crate::admin::plain(StatusCode::CONFLICT, "consumer authority changed\n");
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
                .map_or(0, |publication| publication.age_ms())
                .to_string(),
        )
        .body(crate::full_body(buffer.0.into()))
        .expect("fixed consumer response")
}

/// 业务作用：先过滤授权归属再生成有限身份集合，仅为当前页分配变体与节点索引。
///
/// 参数说明：
/// - `query`：有界搜索和页码。
/// - `directories`：已通过代际与权限复验的逐节点目录。
/// - `ids`：与目录位置对应的完整授权成员分母。
/// - `visible`：当前权限可读取的对象归属门。
///
/// 返回：最多4096唯一绑定的总数与当前页；溢出拒绝，不交付假完整集合。
fn bindings<'a>(
    query: &Query,
    directories: &[Option<&'a Directory>],
    ids: &[&'a str],
    visible: impl Fn(&Entry) -> bool,
) -> Result<(usize, Vec<Binding<'a>>), &'static str> {
    let mut distinct = BTreeMap::new();
    for directory in directories.iter().flatten() {
        for entry in directory.entries.iter().filter(|entry| visible(entry)) {
            if ![
                entry.consumer.as_str(),
                entry.proxy.as_str(),
                entry.route.as_str(),
            ]
            .iter()
            .any(|text| text.contains(&query.search))
            {
                continue;
            }
            distinct.insert(entry.key(), entry);
            if distinct.len() > 4096 {
                return Err("consumer identity capacity exhausted; narrow search\n");
            }
        }
    }
    let total = distinct.len();
    let mut bindings = Vec::with_capacity(query.limit.min(total));
    for (key, entry) in distinct.into_iter().skip(query.offset).take(query.limit) {
        let mut binding = Binding {
            consumer: &entry.consumer,
            proxy: &entry.proxy,
            route: &entry.route,
            ordinal: entry.ordinal,
            variants: Vec::new(),
            present: 0,
            missing: Vec::new(),
            unknown: Vec::new(),
        };
        for (directory, id) in directories.iter().zip(ids) {
            let Some(directory) = directory else {
                binding.unknown.push(id);
                continue;
            };
            let found = directory
                .entries
                .binary_search_by(|value| value.key().cmp(&key))
                .ok()
                .map(|index| &directory.entries[index])
                .filter(|value| visible(value));
            if let Some(found) = found {
                binding.present += 1;
                if let Some(variant) = binding
                    .variants
                    .iter_mut()
                    .find(|variant| variant.binding == found)
                {
                    variant.nodes.push(id);
                } else {
                    binding.variants.push(Variant {
                        binding: found,
                        nodes: vec![id],
                    });
                }
            } else {
                binding.missing.push(id);
            }
        }
        bindings.push(binding);
    }
    Ok((total, bindings))
}

/// 业务作用：保留分页摘要的字符串边界，避免不同身份拼接碰撞。
///
/// 参数说明：
/// - `hash`：当前响应身份。
/// - `text`：已限定范围的事实字段。
///
/// 返回：原地推进SHA-256，不构造中间JSON。
fn field(hash: &mut Sha256, text: &str) {
    hash.update((text.len() as u64).to_be_bytes());
    hash.update(text.as_bytes());
}
