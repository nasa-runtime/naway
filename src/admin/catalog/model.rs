//! 目录摘要来自已编译计划；任意匹配值、URI、凭据和正文不进入节点报告。

use crate::config::GatewaySnapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(in crate::admin) const MAX_OBJECTS: usize = 2048;
pub(in crate::admin) const MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::admin) struct Entry {
    pub kind: String,
    pub id: String,
    pub parent: String,
    pub workspace: String,
    pub tenant: String,
    pub environment: String,
    pub service: String,
    pub order: i32,
    pub flags: u64,
}

pub(in crate::admin) struct Catalog {
    pub version: u64,
    pub fingerprint: Option<u64>,
    pub capacity: bool,
    pub digest: [u8; 32],
    pub entries: Arc<[Entry]>,
    pub scope_supported: bool,
    pub scope_digest: [u8; 32],
    pub scopes: Arc<[super::ScopeAuthority]>,
    pub bytes: usize,
}

impl Entry {
    /// 业务作用：给同类对象建立与声明顺序无关的身份，路由必须连同所属入口区分。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只借用固定字段的排序键，不分配拼接字符串。
    pub(in crate::admin) fn key(&self) -> (&str, &str, &str) {
        (&self.kind, &self.parent, &self.id)
    }

    /// 业务作用：在目录保存前核算对象占有内存，包括字符串的实际分配容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：结构体与所有独立堆字段的字节总和。
    pub(in crate::admin) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + [
                &self.kind,
                &self.id,
                &self.parent,
                &self.workspace,
                &self.tenant,
                &self.environment,
                &self.service,
            ]
            .into_iter()
            .map(|value| value.capacity())
            .sum::<usize>()
    }

    /// 业务作用：限制远端对象描述的字符、身份和固定位，不能借目录传入任意配置或无界标签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅固定对象类型及其有效字段组合可保存。
    pub(in crate::admin) fn valid(&self) -> bool {
        let text = [
            &self.kind,
            &self.id,
            &self.parent,
            &self.workspace,
            &self.tenant,
            &self.environment,
            &self.service,
        ];
        if self.id.is_empty()
            || text
                .into_iter()
                .any(|value| value.len() > 128 || value.chars().any(char::is_control))
        {
            return false;
        }
        match self.kind.as_str() {
            "route" => !self.parent.is_empty() && self.flags < (1 << 20),
            "listener" => {
                self.parent.is_empty()
                    && self.service.is_empty()
                    && self.order == 0
                    && self.flags < 8
            }
            "upstream" => {
                self.parent.is_empty()
                    && self.service.is_empty()
                    && self.order == 0
                    && self.flags == 0
            }
            _ => false,
        }
    }
}

/// 业务作用：对固定公开字段计算确定性摘要，仅用于比较目录描述，不代表完整配置等价。
///
/// 参数说明：
/// - `entries`：已按稳定身份排序的完整对象列表。
/// - `capacity`：是否明确无法提供完整目录。
///
/// 返回：带类型和长度边界的SHA-256摘要，不序列化JSON或读取秘密字段。
pub(in crate::admin) fn digest(entries: &[Entry], capacity: bool) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naway-catalog\0");
    hash.update([u8::from(capacity)]);
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        for value in [
            &entry.kind,
            &entry.id,
            &entry.parent,
            &entry.workspace,
            &entry.tenant,
            &entry.environment,
            &entry.service,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(entry.order.to_be_bytes());
        hash.update(entry.flags.to_be_bytes());
    }
    hash.finalize().into()
}

/// 业务作用：仅从当前不可变执行计划提取路由、HTTP入口和逻辑上游的有限目录。
///
/// 参数说明：
/// - `snapshot`：业务已经采用的完整快照。
///
/// 返回：完整目录或容量不足状态，配置本身不因观测预算而被拒绝。
pub(super) fn collect(snapshot: &GatewaySnapshot) -> Catalog {
    let count = snapshot
        .proxies
        .len()
        .saturating_add(
            snapshot
                .proxies
                .iter()
                .map(|proxy| proxy.router.routes().len())
                .sum::<usize>(),
        )
        .saturating_add(snapshot.upstreams.service_count());
    let mut scopes: Vec<_> = snapshot
        .ownership
        .cluster_authorities()
        .map(|(workspace, digest)| super::ScopeAuthority {
            workspace: workspace.into(),
            digest: *digest,
        })
        .collect();
    let mut entries = Vec::with_capacity(count.min(MAX_OBJECTS));
    let mut capacity = count > MAX_OBJECTS;
    let mut bytes = entries.capacity() * std::mem::size_of::<Entry>()
        + scopes
            .iter()
            .map(super::ScopeAuthority::bytes)
            .sum::<usize>();
    capacity |= bytes > MAX_BYTES;
    if !capacity {
        for proxy in snapshot.proxies.iter() {
            let mut entry = new_entry("listener", &proxy.id, "", snapshot);
            entry.flags = u64::from(proxy.plain_enabled)
                | (u64::from(proxy.tls.is_some()) << 1)
                | (u64::from(proxy.http3.enabled) << 2);
            capacity |= !append(&mut entries, entry, &mut bytes);
            for route in proxy.router.routes() {
                if capacity {
                    break;
                }
                let mut entry = new_entry("route", &route.id, &proxy.id, snapshot);
                entry.order = route.order;
                entry.service = bounded(route.upstream.strip_prefix("lb://").unwrap_or_default());
                for (index, enabled) in [
                    route.internal,
                    route.traffic_limit.is_some(),
                    route.http_cache.is_some(),
                    route.request_validation.is_some(),
                    route.request_transform.is_some(),
                    route.response_transform.is_some(),
                    route.response_contract.is_some(),
                    route.waf.is_some(),
                    route.geoip.is_some(),
                    route.bot.is_some(),
                    route.csrf.is_some(),
                    route.dlp.is_some(),
                    route.graphql_guard.is_some(),
                    route.ws_frame.is_some(),
                    route.opa_authorization.is_some(),
                    route.casbin_authorization.is_some(),
                    route.wasm_plugins.is_some(),
                    route.external_plugins.is_some(),
                    route.forward_proxy.is_some(),
                    route.bff_aggregation.is_some(),
                ]
                .into_iter()
                .enumerate()
                {
                    entry.flags |= u64::from(enabled) << index;
                }
                capacity |= !append(&mut entries, entry, &mut bytes);
            }
            if capacity {
                break;
            }
        }
        if !capacity {
            for name in snapshot.upstreams.declared_service_names() {
                let entry = new_entry("upstream", name, "", snapshot);
                if !append(&mut entries, entry, &mut bytes) {
                    capacity = true;
                    break;
                }
            }
        }
    }
    if capacity {
        // 半份对象目录不能用于推断其它节点缺少对象；超限释放所有条目，只保留明确原因。
        entries = Vec::new();
        scopes = Vec::new();
        bytes = 0;
    }
    entries.sort_by(|left, right| left.key().cmp(&right.key()));
    Catalog {
        version: snapshot.version,
        fingerprint: snapshot.config_fingerprint,
        capacity,
        digest: digest(&entries, capacity),
        entries: entries.into(),
        scope_supported: true,
        scope_digest: super::scope_digest(&scopes),
        scopes: scopes.into(),
        bytes,
    }
}

/// 业务作用：把对象归属绑定到配置目录，缺少归属时保持平台范围，不采信请求声明。
///
/// 参数说明：
/// - `kind`：固定领域类型。
/// - `id`：对象自身稳定身份。
/// - `parent`：路由所属入口，其它对象为空。
/// - `snapshot`：与对象同代的归属权威。
///
/// 返回：不包含对象原始配置的描述；能力位由调用方补充。
fn new_entry(kind: &str, id: &str, parent: &str, snapshot: &GatewaySnapshot) -> Entry {
    let id = bounded(id);
    let parent = bounded(parent);
    let key = match kind {
        "listener" => format!("proxy:{id}"),
        "route" => format!("route:{parent}/{id}"),
        _ => format!("service:{id}"),
    };
    let owner = snapshot.ownership.object_owner(&key);
    Entry {
        kind: kind.into(),
        id,
        parent,
        workspace: bounded(owner.map_or("platform", |owner| owner.workspace.as_str())),
        tenant: bounded(owner.map_or("", |owner| owner.tenant.as_str())),
        environment: bounded(owner.map_or("", |owner| owner.environment.as_str())),
        service: String::new(),
        order: 0,
        flags: 0,
    }
}

/// 业务作用：在复制目录文本前限制长度，过长身份使整个目录进入容量状态而不是悄悄截断。
///
/// 参数说明：
/// - `value`：来自已编译配置的文本。
///
/// 返回：有限副本；超限时返回必定不能通过目录校验的控制字符标记。
fn bounded(value: &str) -> String {
    if value.len() > 128 {
        "\0".into()
    } else {
        value.into()
    }
}

/// 业务作用：先检查每对象与总内存预算再保存，超限不能继续扩大目录。
///
/// 参数说明：
/// - `entries`：尚未发布的有限对象集合。
/// - `entry`：当前候选摘要。
/// - `bytes`：已计入的占有字节。
///
/// 返回：合法且预算足够时保存并累计，否则保持原集合。
fn append(entries: &mut Vec<Entry>, entry: Entry, bytes: &mut usize) -> bool {
    let next = bytes.saturating_add(entry.bytes() - std::mem::size_of::<Entry>());
    if !entry.valid() || entries.len() >= MAX_OBJECTS || next > MAX_BYTES {
        return false;
    }
    *bytes = next;
    entries.push(entry);
    true
}
