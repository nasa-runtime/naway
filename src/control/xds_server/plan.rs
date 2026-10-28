//! 与 GatewaySnapshot 同代的授权图和有界 Envoy 资源目录。

use super::{projection, security};
use anyhow::{ensure, Context, Result};
use prost::Message;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

pub(crate) const MAX_NODES: usize = 32;
pub(crate) const MAX_RESOURCES: usize = 1024;
pub(crate) const MAX_NODE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

/// 已构建且不可独立发布的管理端计划；私钥不实现 Debug 或 Serialize。
pub struct Plan {
    pub(crate) listen: SocketAddr,
    pub(crate) tls: security::TransportIdentity,
    pub(crate) nodes: BTreeMap<String, Arc<NodePlan>>,
    pub(crate) ttl_ms: u64,
    summary: Summary,
}

/// 单节点共享资源缓存；流只持有自己的投影，不延长其它租户私钥的生命周期。
pub(crate) struct NodePlan {
    pub certificate_sha256: String,
    pub workspace: String,
    pub prefixes: BTreeSet<String>,
    pub allow_sds: bool,
    pub grant_digest: String,
    pub resources: projection::Resources,
}

/// 管理面只暴露固定计数，不展示节点身份、资源原文或密钥摘要。
#[derive(Clone, Serialize)]
pub struct Summary {
    pub nodes: usize,
    pub resources: usize,
    pub encoded_bytes: usize,
    pub resource_ttl_ms: u64,
}

impl Plan {
    /// 业务作用：在唯一快照构建阶段完成投影、租户归属和全部资源预算校验。
    ///
    /// 参数说明：
    /// - `cfg`：已经物化生成路由、尚未发布的原生声明。
    /// - `root`：与候选一致的配置根。
    /// - `ownership`：已验证的对象 owner 图。
    /// - `has_private_guard`：候选是否包含不能表达为标准资源的全局守卫或 Sentinel 规则。
    ///
    /// 返回：关闭时为空；启用时只有所有节点与资源都合法才返回完整计划，否则阻止整个候选发布。
    pub(crate) fn build(
        cfg: &crate::config::model::GatewayConfig,
        root: &Path,
        ownership: &crate::control::ownership::OwnershipCatalog,
        has_private_guard: bool,
    ) -> Result<Option<Arc<Self>>> {
        let Some(server) = &cfg.xds_server else {
            return Ok(None);
        };
        ensure!(
            ownership.enabled(),
            "xDS server requires explicit workspace ownership"
        );
        // 下游的执行引擎不是 Naway；任何隐含私有门禁都必须先拒绝，不能把投影宣称为完整安全复制。
        ensure!(
            !has_private_guard && !cfg.control_plane.xds.enabled,
            "xDS server projection rejects private global guards and xDS-client ownership"
        );
        ensure!(
            !cfg.proxies.is_empty(),
            "xDS server requires explicit native proxies"
        );
        ensure!(
            !server.nodes.is_empty() && server.nodes.len() <= MAX_NODES,
            "xDS node capacity must be 1..=32"
        );
        ensure!(
            server.resource_ttl_ms == 0 || (1000..=300_000).contains(&server.resource_ttl_ms),
            "xDS resource_ttl_ms must be zero or 1000..=300000"
        );
        let listen: SocketAddr = server
            .listen
            .parse()
            .context("xDS server listen must be an IP socket address")?;
        ensure!(listen.port() != 0, "xDS server listen port must be nonzero");
        let tls = security::transport(&server.tls, root)?;
        let mut nodes = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut total_bytes = 0;
        let mut total_count = 0;
        for (id, node) in &server.nodes {
            security::identifier(id)?;
            security::identifier(&node.workspace)?;
            ensure!(
                node.certificate_sha256.len() == 64
                    && node
                        .certificate_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "xDS certificate_sha256 must contain 64 lowercase hex characters"
            );
            ensure!(
                identities.insert(node.certificate_sha256.clone()),
                "xDS client certificate must bind exactly one node"
            );
            ensure!(node.proxies.len() <= 32, "xDS node proxy capacity exceeded");
            ensure!(
                ownership.binding(&node.workspace).is_some(),
                "xDS node workspace does not exist"
            );
            if node.allow_sds {
                // 私钥出站是不可撤回的外部副作用；未配置持久审计时不得建立任何秘密投影。
                ensure!(
                    cfg.admin.audit.enabled && cfg.admin.audit.fsync,
                    "xDS allow_sds requires enabled durable admin audit"
                );
            }
            let mut resources = projection::Resources::new();
            let mut prefixes = BTreeSet::new();
            for proxy_id in &node.proxies {
                security::identifier(proxy_id)?;
                let proxy = cfg
                    .proxies
                    .iter()
                    .find(|p| &p.id == proxy_id)
                    .context("xDS node references unknown proxy")?;
                let owner = ownership
                    .object_owner(&format!("proxy:{proxy_id}"))
                    .context("xDS proxy needs an explicit owner")?;
                ensure!(
                    owner.workspace == node.workspace,
                    "xDS proxy owner is outside node workspace"
                );
                for route in &proxy.routes {
                    ensure!(
                        ownership
                            .route_owner(proxy_id, &route.id)
                            .is_some_and(|o| o.workspace == node.workspace),
                        "xDS route owner is outside node workspace"
                    );
                }
                ensure!(
                    prefixes.insert(format!("proxy/{proxy_id}/")),
                    "xDS node contains duplicate proxy"
                );
                for (kind, entries) in projection::proxy(proxy, root, node.allow_sds)? {
                    resources.entry(kind).or_default().extend(entries);
                }
            }
            let count = resources.values().map(BTreeMap::len).sum::<usize>();
            let bytes = resources
                .values()
                .flat_map(BTreeMap::iter)
                .map(|(name, entry)| {
                    name.len() + entry.value.encoded_len() + entry.version.len() + 128
                })
                .sum::<usize>();
            ensure!(
                count <= MAX_RESOURCES && bytes <= MAX_NODE_BYTES,
                "xDS per-node resource cache capacity exceeded"
            );
            total_bytes += bytes;
            total_count += count;
            ensure!(
                total_bytes <= MAX_TOTAL_BYTES,
                "xDS total snapshot cache capacity exceeded"
            );
            let binding = ownership
                .binding(&node.workspace)
                .context("xDS workspace binding disappeared")?;
            let grant = serde_json::to_vec(&serde_json::json!({
                "certificate": node.certificate_sha256,
                "workspace": binding,
                "prefixes": prefixes,
                "allow_sds": node.allow_sds,
            }))?;
            nodes.insert(
                id.clone(),
                Arc::new(NodePlan {
                    certificate_sha256: node.certificate_sha256.clone(),
                    workspace: node.workspace.clone(),
                    prefixes,
                    allow_sds: node.allow_sds,
                    grant_digest: format!("{:x}", Sha256::digest(grant)),
                    resources,
                }),
            );
        }
        Ok(Some(Arc::new(Self {
            listen,
            tls,
            ttl_ms: server.resource_ttl_ms,
            summary: Summary {
                nodes: nodes.len(),
                resources: total_count,
                encoded_bytes: total_bytes,
                resource_ttl_ms: server.resource_ttl_ms,
            },
            nodes,
        })))
    }

    /// 业务作用：为管理读面提供不含资源内容的容量和失联期限事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本次已构建投影的低敏计数，不包含未发布候选或 SDS 材料。
    pub fn summary(&self) -> Summary {
        self.summary.clone()
    }
}

impl NodePlan {
    /// 业务作用：在查找资源存在性之前复验订阅的命名空间，避免越权探测其它节点资源。
    ///
    /// 参数说明：
    /// - `kind`：请求的固定资源类型。
    /// - `name`：规范资源名称或通配订阅。
    ///
    /// 返回：名称属于已授权 proxy 且 SDS 另有授权时成功，否则失败关闭。
    pub(crate) fn authorize(&self, kind: &str, name: &str) -> Result<(), tonic::Status> {
        if !super::proto::TYPES.contains(&kind) {
            return Err(tonic::Status::invalid_argument(
                "unsupported xDS resource type",
            ));
        }
        if kind == super::proto::SDS && !self.allow_sds {
            return Err(tonic::Status::permission_denied(
                "SDS access is not authorized",
            ));
        }
        if name == "*" {
            return Ok(());
        }
        if name.len() > 512
            || !self.prefixes.iter().any(|prefix| name.starts_with(prefix))
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || name
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(tonic::Status::permission_denied(
                "resource namespace is not authorized",
            ));
        }
        Ok(())
    }
}
