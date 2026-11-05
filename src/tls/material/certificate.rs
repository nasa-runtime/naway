use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;

use crate::config::TlsRuntimeCfg;
use crate::tls::SniCertResolver;

const MAX_BINDINGS: usize = 512;
const MAX_OBSERVATION_BYTES: usize = 512 * 1024;
const MAX_SAN_NAMES: usize = 32;
const MAX_SAN_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateSource {
    File,
    Manifest,
    Acme,
    Sds,
    Spire,
}

/// 只记录公开叶证书身份；摘要针对实际 DER，不是证书上传接口的 PEM 文件 CAS。
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CertificateLeaf {
    #[serde(serialize_with = "serialize_sha256")]
    pub sha256: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
    pub names: Vec<String>,
}

/// 业务作用：把公开叶证书摘要输出为可核对的十六进制文本，不在读取时分配临时字符串。
///
/// 参数说明：
/// - `digest`：构建期从实际 DER 计算的 SHA-256。
/// - `serializer`：当前有限响应的序列化目标。
///
/// 返回：64 个小写 ASCII 字符；写入失败由序列化目标报告。
fn serialize_sha256<S: serde::Serializer>(
    digest: &[u8; 32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = [0u8; 64];
    for (index, byte) in digest.iter().enumerate() {
        text[index * 2] = HEX[(byte >> 4) as usize];
        text[index * 2 + 1] = HEX[(byte & 15) as usize];
    }
    serializer.serialize_str(std::str::from_utf8(&text).expect("hexadecimal is ASCII"))
}

/// 一条实际选证绑定；空名称表示默认身份，名称中的通配符保留 SNI 匹配语义。
#[derive(Debug, Serialize)]
pub struct CertificateBinding {
    pub name: String,
    /// 通配后缀在 resolver 中的匹配顺序；默认和精确绑定为零，通配从一开始。
    pub selection_order: u32,
    pub source: CertificateSource,
    pub leaf: Arc<CertificateLeaf>,
    pub ocsp_valid_until: Option<i64>,
    pub ocsp_required: bool,
    /// 加载时完整 pair 的原生归属独立于公开叶证书目录，不能通过普通目录扩张为稳定执行收据。
    #[serde(skip)]
    pub provenance: super::MaterialProvenance,
    /// 原配置代中的实际选证声明；默认身份为空，网络目录不使用该内部位置授予执行权。
    #[serde(skip)]
    pub declaration: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Complete,
    Capacity,
    Unavailable,
    Unauthorized,
    Waiting,
}

/// 完整事实或明确的未知原因；容量不足时不保留可误判为完整目录的部分绑定。
#[derive(Debug, Serialize)]
pub struct CertificateSnapshot {
    pub state: ObservationState,
    pub bindings: Arc<[CertificateBinding]>,
}

/// 静态材料直接共享事实，SPIRE 每次控制面读取都复验当前授权来源。
#[derive(Clone)]
pub enum CertificateObservation {
    Static(Arc<CertificateSnapshot>),
    Spire(Arc<crate::tls::spire::SpireTlsSource>),
}

impl CertificateObservation {
    /// 业务作用：读取当前配置实际使用的公开证书身份，不把已撤销的 SPIRE 身份当作仍可握手。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：共享不可变事实；SPIRE 缺失或过期时返回明确失权状态，不返回旧叶证书。
    pub fn snapshot(&self) -> Arc<CertificateSnapshot> {
        match self {
            Self::Static(snapshot) => snapshot.clone(),
            Self::Spire(source) => source
                .current()
                .map(|material| material.observation.clone())
                .unwrap_or_else(|| {
                    static UNAUTHORIZED: OnceLock<Arc<CertificateSnapshot>> = OnceLock::new();
                    UNAUTHORIZED
                        .get_or_init(|| unavailable(ObservationState::Unauthorized))
                        .clone()
                }),
        }
    }

    /// 业务作用：表示已绑定但仍等待首张可用证书的监听入口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无证书绑定的等待事实，不将尚未激活的 TLS 端口报告为正在服务。
    pub fn waiting() -> Self {
        Self::Static(unavailable(ObservationState::Waiting))
    }
}

/// 业务作用：从握手将使用的 DER 提取有界公开身份，观察失败不影响合法 TLS 材料上线。
///
/// 参数说明：
/// - `der`：已加载叶证书的借用字节，不重新读取文件。
///
/// 返回：有效期、摘要和有界 SAN；无法解析或超过观察预算时返回明确状态。
fn leaf(der: &[u8]) -> Result<Arc<CertificateLeaf>, ObservationState> {
    let (_, certificate) =
        x509_parser::parse_x509_certificate(der).map_err(|_| ObservationState::Unavailable)?;
    let mut names = Vec::new();
    if let Some(san) = certificate
        .subject_alternative_name()
        .map_err(|_| ObservationState::Unavailable)?
    {
        // 不截断超限身份，否则管理面会把完整证书误读成仅有部分域名。
        if san.value.general_names.len() > MAX_SAN_NAMES {
            return Err(ObservationState::Capacity);
        }
        for name in &san.value.general_names {
            let text = match name {
                GeneralName::DNSName(value) | GeneralName::URI(value) => {
                    if value.len() > MAX_SAN_BYTES || value.chars().any(char::is_control) {
                        return Err(ObservationState::Capacity);
                    }
                    let prefix = if matches!(name, GeneralName::DNSName(_)) {
                        "dns:"
                    } else {
                        "uri:"
                    };
                    format!("{prefix}{value}")
                }
                GeneralName::IPAddress(bytes) => {
                    let address = match bytes.len() {
                        4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                            <[u8; 4]>::try_from(*bytes).expect("IPv4 SAN length checked"),
                        )),
                        16 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                            <[u8; 16]>::try_from(*bytes).expect("IPv6 SAN length checked"),
                        )),
                        _ => return Err(ObservationState::Unavailable),
                    };
                    format!("ip:{address}")
                }
                // 目录只表达 DNS、URI 和 IP，其他 SAN 类型不转成易混淆的显示文本。
                _ => continue,
            };
            names.push(text);
        }
    }
    names.sort_unstable();
    names.dedup();
    Ok(Arc::new(CertificateLeaf {
        sha256: Sha256::digest(der).into(),
        not_before: certificate.validity().not_before.timestamp(),
        not_after: certificate.validity().not_after.timestamp(),
        names,
    }))
}

/// 业务作用：构造没有部分身份残留的观察失败事实。
///
/// 参数说明：
/// - `state`：区分容量、材料观察失败、失权与等待。
///
/// 返回：共享空绑定事实；调用方仍可保留正常的握手配置。
fn unavailable(state: ObservationState) -> Arc<CertificateSnapshot> {
    Arc::new(CertificateSnapshot {
        state,
        bindings: Arc::from([]),
    })
}

/// 业务作用：为已验证的单身份来源缓存公开事实，供 SDS 与 SPIRE 复用。
///
/// 参数说明：
/// - `der`：与签名身份同源的叶证书。
/// - `source`：公开的材料来源类别。
///
/// 返回：完整默认绑定或明确观察失败状态；不保存 DER 或私钥。
pub(crate) fn single_certificate(
    der: &[u8],
    source: CertificateSource,
) -> Arc<CertificateSnapshot> {
    match leaf(der) {
        Ok(leaf) => Arc::new(CertificateSnapshot {
            state: ObservationState::Complete,
            bindings: Arc::from([CertificateBinding {
                name: String::new(),
                selection_order: 0,
                source,
                leaf,
                ocsp_valid_until: None,
                ocsp_required: false,
                provenance: super::MaterialProvenance::External,
                declaration: None,
            }]),
        }),
        Err(state) => unavailable(state),
    }
}

/// 业务作用：从实际 SNI resolver 收集选证关系，避免重读文件产生与握手身份不同的观察值。
///
/// 参数说明：
/// - `resolver`：已完整验证的默认证书与 SNI 选择表。
/// - `tls`：只用于判断公开来源类别。
///
/// 返回：完整且排序后的绑定集合；任何观察超限或解析错误撤下整份观察值，TLS 配置不受影响。
pub(super) fn observe_resolver(
    resolver: &SniCertResolver,
    tls: &TlsRuntimeCfg,
) -> CertificateObservation {
    let result = collect_resolver(resolver, tls);
    CertificateObservation::Static(match result {
        Ok(bindings) => Arc::new(CertificateSnapshot {
            state: ObservationState::Complete,
            bindings: Arc::from(bindings),
        }),
        Err(state) => unavailable(state),
    })
}

/// 业务作用：在复制绑定文本前执行容量门，并让同一签名身份的多个 SNI 别名共享叶证书事实。
///
/// 参数说明：
/// - `resolver`：握手使用的选择表。
/// - `tls`：默认身份的来源计划。
///
/// 返回：有界完整绑定；失败时不向外发布部分目录。
fn collect_resolver(
    resolver: &SniCertResolver,
    tls: &TlsRuntimeCfg,
) -> Result<Vec<CertificateBinding>, ObservationState> {
    let count = 1usize
        .saturating_add(resolver.exact.len())
        .saturating_add(resolver.wildcards.len());
    if count > MAX_BINDINGS {
        return Err(ObservationState::Capacity);
    }
    let source = if tls.acme.is_some() {
        CertificateSource::Acme
    } else if tls.keypair_manifest_file.is_some() {
        CertificateSource::Manifest
    } else {
        CertificateSource::File
    };
    let mut leaves: HashMap<*const crate::tls::CertifiedIdentity, Arc<CertificateLeaf>> =
        HashMap::new();
    let mut bindings = Vec::with_capacity(count);
    let mut bytes = bindings.capacity() * std::mem::size_of::<CertificateBinding>();
    let mut wildcard_names = std::collections::HashSet::new();
    for (name, identity, source, selection_order) in
        std::iter::once(("", &resolver.default, source, 0))
            .chain(
                resolver
                    .exact
                    .iter()
                    .map(|(name, identity)| (name.as_str(), identity, CertificateSource::File, 0)),
            )
            .chain(
                resolver
                    .wildcards
                    .iter()
                    .enumerate()
                    .map(|(index, (name, identity))| {
                        (
                            name.as_str(),
                            identity,
                            CertificateSource::File,
                            index as u32 + 1,
                        )
                    }),
            )
    {
        if name.len() > 253 || name.chars().any(char::is_control) {
            return Err(ObservationState::Capacity);
        }
        // 同一通配后缀只会选择首次声明的身份，不能把永远无法命中的后续声明冒充活动绑定。
        if selection_order != 0 && !wildcard_names.insert(name) {
            continue;
        }
        let identity_leaf = match leaves.entry(Arc::as_ptr(identity)) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.get().clone(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let value = leaf(identity.active.cert[0].as_ref())?;
                bytes += std::mem::size_of::<CertificateLeaf>()
                    + value.names.capacity() * std::mem::size_of::<String>()
                    + value.names.iter().map(String::capacity).sum::<usize>();
                // 同一签名身份的 SNI 别名共享归属；只计一次真实 Arc 分配，观察预算仍覆盖新增原生证据。
                if let super::MaterialProvenance::Managed(material) = &identity.provenance {
                    bytes += std::mem::size_of::<super::ManagedMaterial>()
                        + 2 * std::mem::size_of::<usize>()
                        + material.generation.capacity();
                }
                entry.insert(value).clone()
            }
        };
        let name = if selection_order != 0 {
            format!("*{name}")
        } else {
            name.to_owned()
        };
        bytes += name.capacity();
        if bytes > MAX_OBSERVATION_BYTES {
            return Err(ObservationState::Capacity);
        }
        bindings.push(CertificateBinding {
            name,
            selection_order,
            source,
            leaf: identity_leaf,
            ocsp_valid_until: identity
                .ocsp_valid_until
                .map(|deadline| deadline.timestamp()),
            ocsp_required: identity.ocsp_valid_until.is_some()
                && identity.expired_fallback.is_none(),
            provenance: identity.provenance.clone(),
            declaration: identity.declaration,
        });
    }
    bindings.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(bindings)
}
