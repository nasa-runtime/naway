//! 材料选择只读取同代节点目录和真实声明位置，后续条件查询仍须独立取得完整来源证明。

use super::{authorization::Scope, Error};
use crate::{
    admin::{self, cluster, AdminState, BoxBody},
    config::GatewaySnapshot,
    control::baseline::NodeBaseline,
    tls::targets::Target,
};
use http::{Response, StatusCode};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Serialize)]
struct Member<'a> {
    node_id: &'a str,
    availability: &'static str,
}

#[derive(Serialize)]
struct Logical<'a> {
    target: Target,
    bindings: Vec<&'a str>,
    protocols: Vec<&'a str>,
}

#[derive(Serialize)]
struct Selected<'a> {
    node_id: &'a str,
    availability: &'static str,
    boot_id: Option<&'a str>,
    base_version: Option<u64>,
    base_fingerprint: Option<&'a str>,
    node_baseline: Option<&'a NodeBaseline>,
    targets: Vec<Logical<'a>>,
}

#[derive(Serialize)]
struct View<'a> {
    cluster_id: &'a str,
    scope: &'a str,
    availability: &'static str,
    sampling_period_ms: u64,
    valid_for_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<&'a cluster::Coverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nodes: Option<Vec<Member<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<Selected<'a>>,
}

/// 业务作用：为已获材料读权的主体提供完整节点分母或一个节点的原目标，工作区不借平台目录扩大范围。
///
/// 参数说明：
/// - `state`：共享管理目录与读取并发门。
/// - `snapshot`：本次真实认证冻结的完整配置。
/// - `scope`：当前唯一平台或工作区域。
/// - `cluster_id`：持久材料存储永久绑定的集群。
/// - `selected`：原请求选中的规范节点身份；为空时只返回节点清单。
///
/// 返回：同代且有界的低敏目标；缺目录保持未知，越域节点拒绝，配置换代撤下整份结果。
pub(super) fn read(
    state: &AdminState,
    snapshot: &Arc<GatewaySnapshot>,
    scope: &Scope,
    cluster_id: &str,
    selected: Option<&str>,
) -> Result<Response<BoxBody>, Error> {
    if selected.is_some_and(|id| !crate::config::operations::token(id, 128)) {
        return Err(Error::Invalid);
    }
    let _permit = state
        .catalog
        .requests
        .try_acquire()
        .map_err(|_| Error::Capacity)?;
    let workspace = scope
        .workspace
        .as_deref()
        .map(|id| snapshot.ownership.cluster_scope(id).ok_or(Error::Denied))
        .transpose()?;
    if let (Some(id), Some((workspace, _))) = (selected, workspace) {
        // 先检查本地完整成员权威，再读取远端目录；未知或失联不能成为跨工作区枚举入口。
        if !workspace.cluster_nodes.iter().any(|member| member == id) {
            return Err(Error::Denied);
        }
    }
    let publication = cluster::current(state, snapshot);
    let reason = publication.as_ref().err().copied();
    let publication = publication.ok();
    let mut ids: Vec<&str> = if let Some((workspace, _)) = workspace {
        workspace.cluster_nodes.iter().map(String::as_str).collect()
    } else {
        publication
            .iter()
            .flat_map(|value| value.nodes.iter())
            .map(|node| node.id.as_str())
            .collect()
    };
    ids.sort_unstable();
    ids.dedup();
    if ids.len() > 128 {
        return Err(Error::Capacity);
    }
    if selected.is_some_and(|id| !ids.contains(&id)) && publication.is_some() {
        return Err(Error::Missing);
    }
    let members = ids
        .iter()
        .map(|id| {
            let mut matching = publication
                .iter()
                .flat_map(|value| value.nodes.iter())
                .filter(|node| node.id == *id);
            let node = matching.next();
            let availability = if matching.next().is_some() {
                "identity_conflict"
            } else {
                node.map_or(reason.unwrap_or("unknown"), |node| {
                    availability(node, snapshot, scope, cluster_id)
                })
            };
            (*id, node, availability)
        })
        .collect::<Vec<_>>();
    let node = selected
        .and_then(|id| members.iter().find(|(member, _, _)| *member == id))
        .map(|(id, node, availability)| {
            let current = node.filter(|_| *availability == "available");
            let facts = current.and_then(|node| node.facts.as_deref());
            Selected {
                node_id: id,
                availability,
                boot_id: facts.map(|facts| facts.boot_id.as_str()),
                base_version: facts.map(|facts| facts.config_version),
                base_fingerprint: facts.and_then(|facts| facts.config_fingerprint.as_deref()),
                node_baseline: current
                    .and_then(|node| node.action_baseline.node_baseline.as_deref()),
                targets: current.map_or_else(Vec::new, |node| logical(node, snapshot, scope)),
            }
        });
    let complete = members
        .iter()
        .all(|(_, _, status)| *status == "available" || *status == "not_serving")
        && publication.as_ref().is_some_and(|value| {
            workspace.is_some()
                || (!value.coverage.truncated
                    && !value.coverage.conflicting_ids
                    && !value.coverage.directory_stale
                    && value.coverage.discovery_available
                    && !value.coverage.limited_to_local)
        });
    let view = View {
        cluster_id,
        scope: &scope.key,
        availability: reason.unwrap_or(if ids.is_empty() {
            "unconfigured"
        } else if complete {
            "available"
        } else {
            "partial"
        }),
        sampling_period_ms: 2000,
        valid_for_ms: 6000,
        directory: publication
            .as_ref()
            .filter(|_| workspace.is_none())
            .map(|value| &value.coverage),
        nodes: selected.is_none().then(|| {
            members
                .iter()
                .map(|(id, _, availability)| Member {
                    node_id: id,
                    availability,
                })
                .collect()
        }),
        node,
    };
    let mut bytes = admin::catalog::read::Buffer(Vec::with_capacity(8192));
    serde_json::to_writer(&mut bytes, &view).map_err(|_| Error::Capacity)?;
    // 编码之后再次撤销过期观察；一次慢请求不能延长节点目录及基线的真实有效期。
    let age = publication.as_ref().map_or(0, |value| value.age_ms());
    if !Arc::ptr_eq(snapshot, &state.snap.load_full()) || (publication.is_some() && age >= 6000) {
        return Err(Error::Conflict);
    }
    Response::builder()
        .status(if publication.is_some() {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        })
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-naway-sample-age-ms", age.to_string())
        .body(admin::full_body(bytes.0.into()))
        .map_err(|_| Error::Unavailable)
}

/// 业务作用：共同核对当前节点、目录、持久基线与工作区归属，不把局部事实拼成可选择目标。
///
/// 参数说明：
/// - `node`：当前共享Publication中的一个声明节点。
/// - `snapshot`：调用方已认证的完整本机权限快照。
/// - `scope`：精确材料读取范围。
/// - `cluster`：原材料存储所属集群。
///
/// 返回：固定低敏可用性；任何缺失都不交付旧基线或部分材料目标。
fn availability(
    node: &cluster::Node,
    snapshot: &GatewaySnapshot,
    scope: &Scope,
    cluster: &str,
) -> &'static str {
    if !matches!(node.availability, "available" | "not_ready") {
        return node.availability;
    }
    let Some(facts) = node.facts.as_deref() else {
        return "pending";
    };
    if facts.mode == "admin" {
        return "not_serving";
    }
    if !facts.ready {
        return "not_ready";
    }
    // 配置和安装目录必须来自同一报告代；旧SNI声明位置不得附在新的节点基线上。
    let Some(directory) = node.certificates.as_deref().filter(|value| {
        value.version == facts.config_version
            && value.fingerprint.map(|value| format!("{value:016x}")) == facts.config_fingerprint
    }) else {
        return "pending";
    };
    if directory.capacity || directory.bytes > admin::certificates::MAX_BYTES {
        return "capacity";
    }
    if !node.certificates_supported || directory.targets_digest.is_none() {
        return "unsupported";
    }
    // 没有原持久存储与集群绑定时不能构造提交目标，在线健康不能代替材料受理基线。
    if node.action_baseline.availability != "available"
        || !node
            .action_baseline
            .node_baseline
            .as_ref()
            .is_some_and(|baseline| baseline.valid() && baseline.cluster_id == cluster)
        || !crate::config::operations::token(&node.id, 128)
        || !crate::config::operations::token(&facts.boot_id, 128)
        || facts.config_version == 0
        || facts.config_fingerprint.is_none()
    {
        return "baseline_unavailable";
    }
    if let Some(workspace) = scope.workspace.as_deref() {
        let Some((_, authority)) = snapshot.ownership.cluster_scope(workspace) else {
            return "authority_mismatch";
        };
        let Some(catalog) = node.catalog.as_ref().filter(|catalog| {
            catalog.version == facts.config_version
                && catalog.fingerprint.map(|value| format!("{value:016x}"))
                    == facts.config_fingerprint
        }) else {
            return "pending";
        };
        if catalog.capacity {
            return "capacity";
        }
        if !catalog.scope_supported {
            return "unsupported";
        }
        // 远端必须证明同一工作区权威，平台可见的目录不能替代工作区授权。
        if !catalog
            .scopes
            .iter()
            .any(|entry| entry.workspace == workspace && entry.digest == *authority)
        {
            return "authority_mismatch";
        }
    }
    // 本域未知安装状态保留为未知，不能把尚未观察到的声明解释成没有其它材料目标。
    if directory
        .entries
        .iter()
        .any(|entry| visible(entry, snapshot, scope) && entry.state != "complete")
    {
        return "observations_incomplete";
    }
    "available"
}

/// 业务作用：在检查或展示远端条目之前限定精确工作区归属，另一租户的材料状态不参与本域输出。
///
/// 参数说明：
/// - `entry`：已经通过目录完整性验证的公开条目。
/// - `snapshot`：当前归属与成员权威。
/// - `scope`：唯一授权读取范围。
///
/// 返回：平台可见全部条目；工作区必须同时匹配工作区、租户与环境。
fn visible(entry: &admin::certificates::Entry, snapshot: &GatewaySnapshot, scope: &Scope) -> bool {
    scope.workspace.as_deref().is_none_or(|workspace| {
        snapshot
            .ownership
            .cluster_scope(workspace)
            .is_some_and(|(owner, _)| {
                entry.workspace == workspace
                    && entry.tenant == owner.tenant
                    && entry.environment == owner.environment
            })
    })
}

/// 业务作用：先按工作区精确归属过滤，再合并同一声明的协议与SNI别名，不以叶证书摘要合并不同来源。
///
/// 参数说明：
/// - `node`：已经通过完整可用性门的原节点。
/// - `snapshot`：同代对象归属目录。
/// - `scope`：当前唯一材料范围。
///
/// 返回：最多原目录条数的去重逻辑目标，不包含路径、PEM或受管材料代。
fn logical<'a>(
    node: &'a cluster::Node,
    snapshot: &GatewaySnapshot,
    scope: &Scope,
) -> Vec<Logical<'a>> {
    let mut values = BTreeMap::new();
    for entry in node
        .certificates
        .iter()
        .flat_map(|directory| directory.entries.iter())
    {
        if !visible(entry, snapshot, scope) {
            continue;
        }
        let Some(target) = entry.logical_target() else {
            continue;
        };
        // 原节点成员和证书对象仍须同时属于本域；目录中的文本归属本身不创造授权。
        if crate::control::material::authorization::logical_targets(
            &scope.key,
            snapshot,
            &node.id,
            std::iter::once(&target),
        )
        .is_none()
        {
            continue;
        }
        let key = (
            target.kind as u8,
            target.listener.clone(),
            target.entry.clone(),
        );
        let value = values.entry(key).or_insert_with(|| Logical {
            target,
            bindings: Vec::new(),
            protocols: Vec::new(),
        });
        if !value.bindings.contains(&entry.binding.as_str()) {
            value.bindings.push(entry.binding.as_str());
        }
        if !value.protocols.contains(&entry.protocol.as_str()) {
            value.protocols.push(entry.protocol.as_str());
        }
    }
    values.into_values().collect()
}
