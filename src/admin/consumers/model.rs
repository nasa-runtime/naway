//! 配置代内的凭据序号只用于观察，不能代替原文过滤器下标或修改授权。

use crate::config::GatewaySnapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(in crate::admin) const MAX_ENTRIES: usize = 2048;
pub(in crate::admin) const MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::admin) struct Entry {
    pub consumer: String,
    pub proxy: String,
    pub route: String,
    pub ordinal: u32,
    pub source: String,
    pub name: String,
    pub enabled: bool,
    pub plan: String,
    pub workspace: String,
    pub tenant: String,
    pub environment: String,
}

pub(in crate::admin) struct Directory {
    pub version: u64,
    pub fingerprint: Option<u64>,
    pub capacity: bool,
    pub digest: [u8; 32],
    pub entries: Arc<[Entry]>,
    pub bytes: usize,
}

impl Entry {
    /// 业务作用：以完整路由归属和本代凭据序号区分同名 consumer 的不同绑定。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用排序键，不拼接可能存在歧义的身份字符串。
    pub(in crate::admin) fn key(&self) -> (&str, &str, &str, u32) {
        (&self.consumer, &self.proxy, &self.route, self.ordinal)
    }

    /// 业务作用：统一目录摘要、字段校验和堆内存计数所覆盖的公开文本。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只借用固定字段，验证材料不存在于此类型。
    fn texts(&self) -> [&String; 9] {
        [
            &self.consumer,
            &self.proxy,
            &self.route,
            &self.source,
            &self.name,
            &self.plan,
            &self.workspace,
            &self.tenant,
            &self.environment,
        ]
    }

    /// 业务作用：在接收远端绑定前检查有限身份和来源，不能借目录传递任意大字段。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定来源、必需身份和长度全部合法时为真。
    pub(in crate::admin) fn valid(&self) -> bool {
        !self.consumer.is_empty()
            && !self.proxy.is_empty()
            && !self.route.is_empty()
            && !self.name.is_empty()
            && !self.workspace.is_empty()
            && matches!(self.source.as_str(), "header" | "query")
            && [
                &self.proxy,
                &self.route,
                &self.plan,
                &self.workspace,
                &self.tenant,
                &self.environment,
            ]
            .iter()
            .all(|text| text.len() <= 128)
            && self
                .texts()
                .into_iter()
                .all(|text| text.len() <= 256 && !text.chars().any(char::is_control))
    }

    /// 业务作用：按实际分配容量核算目录保留量，不能只数可见字符串长度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：结构体与独立文本堆容量的总字节。
    pub(in crate::admin) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .texts()
                .into_iter()
                .map(|text| text.capacity())
                .sum::<usize>()
    }
}

/// 业务作用：对完整低敏目录计算有类型和长度边界的身份，分片完成前不解释为存在性证明。
///
/// 参数说明：
/// - `entries`：已按完整绑定身份排序的条目。
/// - `capacity`：节点是否明确无法提供完整目录。
///
/// 返回：不经JSON或秘密求值的固定SHA-256。
pub(in crate::admin) fn digest(entries: &[Entry], capacity: bool) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naway-consumer-bindings\0");
    hash.update([u8::from(capacity)]);
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        for text in entry.texts() {
            hash.update((text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(entry.ordinal.to_be_bytes());
        hash.update([u8::from(entry.enabled)]);
    }
    hash.finalize().into()
}

/// 业务作用：从实际执行策略提取消费者凭据、路由生效套餐及归属，文件变化不能污染活动事实。
///
/// 参数说明：
/// - `snapshot`：当前已发布快照。
///
/// 返回：完整有限目录；任一容量或字段边界不满足时释放全部条目并明确capacity。
pub(super) fn collect(snapshot: &GatewaySnapshot) -> Directory {
    let count = snapshot
        .proxies
        .iter()
        .flat_map(|proxy| proxy.router.routes())
        .flat_map(|route| &route.api_keys)
        .filter(|policy| policy.consumer_binding().is_some())
        .take(MAX_ENTRIES + 1)
        .count();
    let mut entries = Vec::with_capacity(count.min(MAX_ENTRIES));
    let mut bytes = entries.capacity() * std::mem::size_of::<Entry>();
    let mut capacity = count > MAX_ENTRIES;
    'proxies: for proxy in snapshot.proxies.iter() {
        if capacity {
            break;
        }
        for route in proxy.router.routes() {
            if !route
                .api_keys
                .iter()
                .any(|policy| policy.consumer_binding().is_some())
            {
                continue;
            }
            if proxy.id.len() > 128 || route.id.len() > 128 {
                capacity = true;
                break 'proxies;
            }
            let owner = snapshot
                .ownership
                .object_owner(&format!("route:{}/{}", proxy.id, route.id));
            for (ordinal, policy) in route.api_keys.iter().enumerate() {
                let Some((consumer, source, name, enabled)) = policy.consumer_binding() else {
                    continue;
                };
                if entries.len() >= MAX_ENTRIES || ordinal > u32::MAX as usize {
                    capacity = true;
                    break 'proxies;
                }
                let plan = route
                    .usage_plan
                    .as_ref()
                    .and_then(|policy| policy.select(Some(consumer)))
                    .map_or("", |plan| plan.id.as_ref());
                let workspace = owner.map_or("platform", |owner| owner.workspace.as_str());
                let tenant = owner.map_or("", |owner| owner.tenant.as_str());
                let environment = owner.map_or("", |owner| owner.environment.as_str());
                if [consumer, name, plan, workspace, tenant, environment]
                    .iter()
                    .any(|text| text.len() > 256)
                {
                    capacity = true;
                    break 'proxies;
                }
                if [plan, workspace, tenant, environment]
                    .iter()
                    .any(|text| text.len() > 128)
                {
                    capacity = true;
                    break 'proxies;
                }
                let entry = Entry {
                    consumer: consumer.into(),
                    proxy: proxy.id.to_string(),
                    route: route.id.to_string(),
                    ordinal: ordinal as u32,
                    source: source.into(),
                    name: name.into(),
                    enabled,
                    plan: plan.into(),
                    workspace: workspace.into(),
                    tenant: tenant.into(),
                    environment: environment.into(),
                };
                let next = bytes.saturating_add(entry.bytes() - std::mem::size_of::<Entry>());
                if !entry.valid() || next > MAX_BYTES {
                    capacity = true;
                    break 'proxies;
                }
                bytes = next;
                entries.push(entry);
            }
        }
    }
    if capacity {
        // 半份凭据清单不能证明其它绑定已被撤销；容量不足时整份目录不可读。
        entries = Vec::new();
        bytes = 0;
    }
    entries.sort_by(|a, b| a.key().cmp(&b.key()));
    Directory {
        version: snapshot.version,
        fingerprint: snapshot.config_fingerprint,
        capacity,
        digest: digest(&entries, capacity),
        entries: entries.into(),
        bytes,
    }
}
