use crate::config::{GatewaySnapshot, TlsRuntimeCfg};
use crate::tls::installed::{CertificateProtocol, InstalledCertificate, InstalledSnapshot};
use crate::tls::material::{CertificateLeaf, CertificateSource, ObservationState};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(in crate::admin) const MAX_ENTRIES: usize = 2048;
pub(in crate::admin) const MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::admin) struct Entry {
    pub listener: String,
    pub protocol: String,
    pub binding: String,
    pub selection_order: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub material_entry: Option<String>,
    pub state: String,
    pub source: String,
    pub leaf: Option<Arc<CertificateLeaf>>,
    pub ocsp_valid_until: Option<i64>,
    pub ocsp_required: bool,
    pub workspace: String,
    pub tenant: String,
    pub environment: String,
}

pub(in crate::admin) struct Directory {
    pub version: u64,
    pub fingerprint: Option<u64>,
    pub capacity: bool,
    pub digest: [u8; 32],
    pub targets_digest: Option<[u8; 32]>,
    pub entries: Arc<[Entry]>,
    pub bytes: usize,
}

impl Entry {
    /// 业务作用：以实际入口、协议和选证名称定位绑定，不把相同证书摘要当作相同监听器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不分配的完整排序键。
    pub(in crate::admin) fn key(&self) -> (&str, &str, &str) {
        (&self.listener, &self.protocol, &self.binding)
    }

    /// 业务作用：统一限定远端可提交的身份字段，目录不承载路径、材料或任意诊断字符串。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：字段长度、状态组合和公开叶证书都满足固定边界时为真。
    pub(in crate::admin) fn valid(&self) -> bool {
        let text_valid = |text: &str, max| text.len() <= max && !text.chars().any(char::is_control);
        !self.listener.is_empty()
            && !self.workspace.is_empty()
            && [
                &self.listener,
                &self.workspace,
                &self.tenant,
                &self.environment,
            ]
            .iter()
            .all(|text| text_valid(text, 128))
            && text_valid(&self.binding, 254)
            && matches!(self.protocol.as_str(), "https" | "http3" | "stream_tls")
            && self.selection_order <= 512
            && self.material_entry.as_ref().is_none_or(|entry| {
                self.state == "complete"
                    && matches!(self.source.as_str(), "file" | "manifest")
                    && self.logical_target().is_some_and(|target| {
                        target.valid() && (entry == "default") == self.binding.is_empty()
                    })
            })
            && matches!(
                self.source.as_str(),
                "" | "file" | "manifest" | "acme" | "sds" | "spire"
            )
            && match self.state.as_str() {
                "complete" => {
                    !self.source.is_empty()
                        && self.leaf.as_ref().is_some_and(|leaf| {
                            leaf.names.len() <= 32
                                && leaf.names.iter().all(|name| {
                                    text_valid(name, 516)
                                        && (name.starts_with("dns:")
                                            || name.starts_with("uri:")
                                            || name.starts_with("ip:"))
                                })
                                && leaf.names.windows(2).all(|pair| pair[0] < pair[1])
                        })
                        && (!self.ocsp_required || self.ocsp_valid_until.is_some())
                }
                "pending" | "waiting" | "unavailable" | "unauthorized" => {
                    self.binding.is_empty()
                        && self.selection_order == 0
                        && self.leaf.is_none()
                        && self.ocsp_valid_until.is_none()
                        && !self.ocsp_required
                }
                _ => false,
            }
    }

    /// 业务作用：借用固定文本集合，供摘要、限额与协议验证共用同一身份边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只包含低敏字段，不对 TLS 计划求值。
    fn texts(&self) -> [&String; 8] {
        [
            &self.listener,
            &self.protocol,
            &self.binding,
            &self.state,
            &self.source,
            &self.workspace,
            &self.tenant,
            &self.environment,
        ]
    }

    /// 业务作用：保守核算条目保留量，即使同节点共享叶证书也不放大接收端预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：结构体、文本和完整公开叶证书的容量总量。
    pub(in crate::admin) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.material_entry.as_ref().map_or(0, String::capacity)
            + self
                .texts()
                .iter()
                .map(|text| text.capacity())
                .sum::<usize>()
            + self.leaf.as_ref().map_or(0, |leaf| {
                std::mem::size_of::<CertificateLeaf>()
                    + leaf.names.capacity() * std::mem::size_of::<String>()
                    + leaf.names.iter().map(String::capacity).sum::<usize>()
            })
    }

    /// 业务作用：从节点明确报告的原声明身份构造材料目标，不从SNI名称或匹配次序推断写入位置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有原声明且协议属于已知TLS入口时返回逻辑目标，缺能力或未知协议为空。
    pub(in crate::admin) fn logical_target(&self) -> Option<crate::tls::targets::Target> {
        use crate::tls::targets::{Kind, Target};
        Some(Target {
            kind: match self.protocol.as_str() {
                "https" | "http3" => Kind::Proxy,
                "stream_tls" => Kind::Stream,
                _ => return None,
            },
            listener: self.listener.clone(),
            entry: self.material_entry.clone()?,
        })
    }
}

/// 业务作用：独立绑定原目录的完整逻辑目标映射，旧目录摘要保持兼容，新增位置不能脱离原公开身份。
///
/// 参数说明：
/// - `directory`：原有公开证书目录的完整摘要。
/// - `entries`：相同顺序的完整条目，包含明确缺席的目标引用。
///
/// 返回：带域、存在位和长度边界的映射摘要，不授予材料文件读取或写入权。
pub(in crate::admin) fn targets_digest(directory: &[u8; 32], entries: &[Entry]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naway-certificate-logical-targets\0");
    hash.update(directory);
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hash.update([u8::from(entry.material_entry.is_some())]);
        if let Some(identity) = &entry.material_entry {
            field(&mut hash, identity);
        }
    }
    hash.finalize().into()
}

/// 业务作用：计算材料目录的独立身份，使配置不变的热换、等待和动态失权也能撤销旧目录。
///
/// 参数说明：
/// - `entries`：已经按完整选证键排序的有限条目。
/// - `capacity`：明确无法提供完整事实的容量状态。
///
/// 返回：带类型、长度和可选值边界的摘要，不经过 JSON 或任何私钥求值。
pub(in crate::admin) fn digest(entries: &[Entry], capacity: bool) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naway-installed-certificates\0");
    hash.update([u8::from(capacity)]);
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        for text in entry.texts() {
            field(&mut hash, text);
        }
        hash.update(entry.selection_order.to_be_bytes());
        hash.update([
            u8::from(entry.ocsp_required),
            u8::from(entry.ocsp_valid_until.is_some()),
        ]);
        if let Some(deadline) = entry.ocsp_valid_until {
            hash.update(deadline.to_be_bytes());
        }
        hash.update([u8::from(entry.leaf.is_some())]);
        if let Some(leaf) = &entry.leaf {
            hash.update(leaf.sha256);
            hash.update(leaf.not_before.to_be_bytes());
            hash.update(leaf.not_after.to_be_bytes());
            hash.update((leaf.names.len() as u64).to_be_bytes());
            for name in &leaf.names {
                field(&mut hash, name);
            }
        }
    }
    hash.finalize().into()
}

/// 业务作用：为摘要中的文本写入长度边界，避免不同字段组合产生相同输入。
///
/// 参数说明：
/// - `hash`：当前目录摘要。
/// - `value`：一个已限制长度的低敏字段。
///
/// 返回：无返回值；只更新摘要，不创建编码副本。
fn field(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

struct Builder<'a> {
    snapshot: &'a GatewaySnapshot,
    installed: BTreeMap<(CertificateProtocol, &'a str), &'a InstalledCertificate>,
    entries: Vec<Entry>,
    bytes: usize,
    capacity: bool,
}

impl Builder<'_> {
    /// 业务作用：只在计划匹配时使用安装事实，配置已发布但监听器尚未交接时保持未知。
    ///
    /// 参数说明：
    /// - `id`：当前配置中的入口标识。
    /// - `protocol`：实际服务协议。
    /// - `tls`：当前已发布的 TLS 来源与授权计划。
    ///
    /// 返回：追加完整绑定或单个未知占位；任一观察预算不足标记整份目录不可用。
    fn listener(&mut self, id: &str, protocol: CertificateProtocol, tls: &TlsRuntimeCfg) {
        if self.capacity {
            return;
        }
        let observation = self
            .installed
            .get(&(protocol, id))
            .filter(|entry| entry.matches(tls))
            .map(|entry| entry.observation.clone());
        let state = observation.as_ref().map(|value| value.state);
        if state == Some(ObservationState::Capacity) {
            // 有效 TLS 仍运行，但半份目录不能成为其它证书已经消失的证明。
            self.capacity = true;
            return;
        }
        let kind = if protocol == CertificateProtocol::StreamTls {
            "stream_certificate"
        } else {
            "certificate"
        };
        let owner = self
            .snapshot
            .ownership
            .object_owner(&format!("{kind}:{id}"));
        let workspace = owner.map_or("platform", |value| value.workspace.as_str());
        let tenant = owner.map_or("", |value| value.tenant.as_str());
        let environment = owner.map_or("", |value| value.environment.as_str());
        if [id, workspace, tenant, environment]
            .iter()
            .any(|value| value.len() > 128)
        {
            self.capacity = true;
            return;
        }
        let template = Entry {
            listener: id.into(),
            protocol: match protocol {
                CertificateProtocol::Https => "https",
                CertificateProtocol::Http3 => "http3",
                CertificateProtocol::StreamTls => "stream_tls",
            }
            .into(),
            binding: String::new(),
            selection_order: 0,
            material_entry: None,
            state: match state {
                Some(ObservationState::Complete) => "complete",
                Some(ObservationState::Waiting) => "waiting",
                Some(ObservationState::Unauthorized) => "unauthorized",
                Some(ObservationState::Unavailable) => "unavailable",
                _ => "pending",
            }
            .into(),
            source: String::new(),
            leaf: None,
            ocsp_valid_until: None,
            ocsp_required: false,
            workspace: workspace.into(),
            tenant: tenant.into(),
            environment: environment.into(),
        };
        if let Some(observation) =
            observation.filter(|value| value.state == ObservationState::Complete)
        {
            for binding in observation.bindings.iter() {
                let mut entry = template.clone();
                entry.binding = binding.name.clone();
                entry.selection_order = binding.selection_order;
                // 声明位置来自已安装的真实resolver；外部身份不可选，目录引用也不能替代后续材料条件复验。
                if matches!(
                    binding.source,
                    CertificateSource::File | CertificateSource::Manifest
                ) && tls.in_memory.is_none()
                    && tls.spire.is_none()
                {
                    entry.material_entry = match binding.declaration {
                        None if binding.name.is_empty() && crate::tls::targets::writable(tls) => {
                            Some("default".into())
                        }
                        Some(index)
                            if tls
                                .certs
                                .get(usize::from(index))
                                .is_some_and(|source| source.private_key_provider.is_none()) =>
                        {
                            Some(format!("sni-{index}"))
                        }
                        _ => None,
                    };
                }
                entry.source = match binding.source {
                    CertificateSource::File => "file",
                    CertificateSource::Manifest => "manifest",
                    CertificateSource::Acme => "acme",
                    CertificateSource::Sds => "sds",
                    CertificateSource::Spire => "spire",
                }
                .into();
                entry.leaf = Some(binding.leaf.clone());
                entry.ocsp_valid_until = binding.ocsp_valid_until;
                entry.ocsp_required = binding.ocsp_required;
                self.push(entry);
                if self.capacity {
                    break;
                }
            }
        } else {
            // 没有安装证明只表示未知或等待，绝不能从磁盘读一张证书填补空缺。
            self.push(template);
        }
    }

    /// 业务作用：在条数与实际向量容量的共同约束下积累低敏绑定。
    ///
    /// 参数说明：
    /// - `entry`：从已安装材料或明确未知状态构造的条目。
    ///
    /// 返回：无返回值；超量标记整份目录不可用，调用方结束时释放所有候选。
    fn push(&mut self, entry: Entry) {
        if self.entries.len() >= MAX_ENTRIES || !entry.valid() {
            self.capacity = true;
            return;
        }
        self.bytes += entry.bytes() - std::mem::size_of::<Entry>();
        self.entries.push(entry);
        if self.bytes + self.entries.capacity() * std::mem::size_of::<Entry>() > MAX_BYTES {
            self.capacity = true;
        }
    }
}

/// 业务作用：将当前配置的入口与已安装材料逐项核对，纯管理节点不凭配置宣称承载 TLS。
///
/// 参数说明：
/// - `snapshot`：当前完整配置和归属权威。
/// - `installed`：控制面发布门读取的监听器事实。
/// - `serves_data`：部署形态是否承载数据面。
///
/// 返回：绑定集合及独立材料摘要；容量不足撤下全量条目，不影响业务 listener。
pub(super) fn collect(
    snapshot: &GatewaySnapshot,
    installed: &InstalledSnapshot,
    serves_data: bool,
) -> Directory {
    let mut builder = Builder {
        snapshot,
        installed: installed
            .entries
            .iter()
            .map(|entry| ((entry.protocol, entry.listener.as_ref()), entry))
            .collect(),
        entries: Vec::new(),
        bytes: 0,
        capacity: installed.capacity,
    };
    if serves_data {
        for proxy in snapshot.proxies.iter() {
            if let Some(tls) = &proxy.tls {
                builder.listener(&proxy.id, CertificateProtocol::Https, tls);
                if proxy.http3.enabled {
                    builder.listener(&proxy.id, CertificateProtocol::Http3, tls);
                }
            }
        }
        for stream in snapshot.stream_listeners.iter() {
            if let Some(tls) = &stream.tls {
                builder.listener(&stream.id, CertificateProtocol::StreamTls, tls);
            }
        }
    }
    if builder.capacity {
        builder.entries = Vec::new();
        builder.bytes = 0;
    } else {
        builder.bytes += builder.entries.capacity() * std::mem::size_of::<Entry>();
    }
    builder
        .entries
        .sort_unstable_by(|left, right| left.key().cmp(&right.key()));
    let digest = digest(&builder.entries, builder.capacity);
    Directory {
        version: snapshot.version,
        fingerprint: snapshot.config_fingerprint,
        capacity: builder.capacity,
        digest,
        targets_digest: Some(targets_digest(&digest, &builder.entries)),
        entries: builder.entries.into(),
        bytes: builder.bytes,
    }
}

/// 业务作用：确认每个 listener 的默认身份或未知占位完整存在，不能用半个选证表证明 SNI 缺失。
///
/// 参数说明：
/// - `entries`：已经按完整键排序并完成逐字段验证的目录。
///
/// 返回：每个入口/协议分组均有默认条目，且绑定状态和归属自洽时为真。
#[cfg(feature = "admin-grpc")]
pub(in crate::admin) fn valid_directory(entries: &[Entry]) -> bool {
    let mut default: Option<&Entry> = None;
    for entry in entries {
        let same = default
            .filter(|value| value.listener == entry.listener && value.protocol == entry.protocol);
        if let Some(default) = same {
            if default.state != "complete"
                || entry.state != "complete"
                || default.workspace != entry.workspace
                || default.tenant != entry.tenant
                || default.environment != entry.environment
            {
                return false;
            }
        } else {
            if !entry.binding.is_empty() {
                return false;
            }
            default = Some(entry);
        }
    }
    true
}
