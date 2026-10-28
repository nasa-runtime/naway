//! 固定 HTTPS Schema 来源、签名校验与有界缓存，所有网络工作只发生在候选构建期。

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::{resolve_path, SchemaRegistryDocumentCfg};

const MAX_SCHEMA_REGISTRY_CACHE_ENTRIES: usize = 64;
static SCHEMA_REGISTRY_CACHE: OnceLock<Mutex<HashMap<CacheKey, CachedRegistryDocument>>> =
    OnceLock::new();

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    url: String,
    sha256: String,
    ca_identity: Option<[u8; 32]>,
}

#[derive(PartialEq, Eq)]
pub(super) struct Policy {
    material: [u8; 32],
    signing_key: [u8; 32],
    ca_identity: Option<[u8; 32]>,
    max_bytes: usize,
    timeout_ms: u64,
    cache_ttl_ms: u64,
}

pub(super) struct Document {
    pub(super) bytes: Arc<[u8]>,
    pub(super) policy: Policy,
}

struct Trust {
    certificate: Option<reqwest::Certificate>,
    identity: Option<[u8; 32]>,
}

struct CachedRegistryDocument {
    loaded_at: Instant,
    bytes: Arc<[u8]>,
}

/// 业务作用：规范化显式 schema registry URL，并拒绝降级、凭据、fragment 与异常 authority。
///
/// 参数说明：
/// - `raw`：是配置或远端文档中的 URL。
///
/// 返回：合法 HTTPS URL 返回无 fragment 的规范字符串；其它输入返回错误。
pub(super) fn normalize_registry_url(raw: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(raw).context("schema registry URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("schema registry URL must be credential-free HTTPS without fragment");
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

/// 业务作用：从已验签有界缓存或固定 HTTPS URL取得 schema 原始字节，并在返回前重新复验身份。
///
/// 参数说明：
/// - `cfg`：冻结 URL、摘要、签名和资源门
/// - `config_dir`：解析本地信任材料
/// - `url`：是已规范化的固定地址。
///
/// 返回：当前信任、摘要、签名与预算都通过时返回共享字节和冻结声明；任一失败拒绝候选。
pub(super) fn load_registry_document(
    cfg: &SchemaRegistryDocumentCfg,
    config_dir: &Path,
    url: &str,
) -> Result<Document> {
    if !(1..=4 * 1024 * 1024).contains(&cfg.max_bytes)
        || !(100..=30_000).contains(&cfg.timeout_ms)
        || !(1..=24 * 60 * 60 * 1_000).contains(&cfg.cache_ttl_ms)
    {
        bail!("schema registry byte, timeout, or cache TTL limit is outside safe bounds");
    }
    validate_sha256(cfg.sha256.as_str())?;
    // 缓存不能掩盖当前 CA 的失效或轮换；同一次解析同时提供网络信任和比较身份。
    let trust = read_trust(cfg, config_dir)?;
    let cache_key = CacheKey {
        url: url.to_owned(),
        sha256: cfg.sha256.to_ascii_lowercase(),
        ca_identity: trust.identity,
    };
    let cache = SCHEMA_REGISTRY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = {
        let cache = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("schema registry cache lock is poisoned"))?;
        cache
            .get(&cache_key)
            .filter(|entry| entry.loaded_at.elapsed() <= Duration::from_millis(cfg.cache_ttl_ms))
            .map(|entry| entry.bytes.clone())
    };
    if let Some(bytes) = cached {
        // 复用字节仍须服从本次候选的预算和固定签名；不延长 loaded_at，避免命中无限续期。
        return compile_document(bytes, cfg, config_dir, trust.identity);
    }

    let fetch_cfg = cfg.clone();
    let fetch_url = url.to_string();
    let certificate = trust.certificate;
    // reqwest blocking client 必须在专用控制面线程中运行；候选构建可以等待其有界 deadline，
    // 但不能在 Tokio worker 内创建嵌套 runtime，也不能把网络调用带入请求热路径。
    let bytes =
        std::thread::spawn(move || fetch_registry_document(fetch_cfg, certificate, fetch_url))
            .join()
            .map_err(|_| anyhow::anyhow!("schema registry fetch worker panicked"))??;
    let document = compile_document(bytes, cfg, config_dir, trust.identity)?;

    let mut cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("schema registry cache lock is poisoned"))?;
    if cache.len() >= MAX_SCHEMA_REGISTRY_CACHE_ENTRIES && !cache.contains_key(&cache_key) {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.loaded_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        cache_key,
        CachedRegistryDocument {
            loaded_at: Instant::now(),
            bytes: document.bytes.clone(),
        },
    );
    Ok(document)
}

/// 业务作用：有界读取当前 CA 并冻结真实材料，命中缓存也必须通过当前信任配置校验。
///
/// 参数说明：
/// - `cfg`：可选 CA 来源声明。
/// - `config_dir`：相对路径基准。
///
/// 返回：合法 CA 的解析对象和材料身份；未声明时使用系统信任，读取或格式错误拒绝候选。
fn read_trust(cfg: &SchemaRegistryDocumentCfg, config_dir: &Path) -> Result<Trust> {
    let Some(file) = cfg.ca_file.as_deref() else {
        return Ok(Trust {
            certificate: None,
            identity: None,
        });
    };
    let path = resolve_path(config_dir, file);
    let pem = crate::io::bounded_io::read_file(&path, 1024 * 1024, "schema registry CA")?;
    Ok(Trust {
        certificate: Some(
            crate::tls::trust::http_ca(&pem).context("parse schema registry CA PEM")?,
        ),
        identity: Some(Sha256::digest(&pem).into()),
    })
}

/// 业务作用：统一复验下载与缓存的 Schema，冻结当前签名身份及全部构建预算。
///
/// 参数说明：
/// - `bytes`：本次候选将解析的共享文档原文。
/// - `cfg`：当前候选的签名与资源声明。
/// - `config_dir`：SecretSource 路径基准。
/// - `ca_identity`：同一次 CA 解析产生的材料身份。
///
/// 返回：材料与签名有效且未超当前上限时返回声明与共享正文，否则拒绝候选。
fn compile_document(
    bytes: Arc<[u8]>,
    cfg: &SchemaRegistryDocumentCfg,
    config_dir: &Path,
    ca_identity: Option<[u8; 32]>,
) -> Result<Document> {
    // 先执行当前预算，不能因旧缓存曾接受更大上限而放大本次候选的内存边界。
    if bytes.len() > cfg.max_bytes {
        bail!("schema registry cached or fetched response exceeds max_bytes");
    }
    let (material, signing_key) = verify_registry_document(&bytes, cfg, config_dir)?;
    Ok(Document {
        bytes,
        policy: Policy {
            material,
            signing_key,
            ca_identity,
            max_bytes: cfg.max_bytes,
            timeout_ms: cfg.timeout_ms,
            cache_ttl_ms: cfg.cache_ttl_ms,
        },
    })
}

/// 业务作用：在隔离线程内执行一次无 redirect 的 HTTPS schema GET，并严格限制 CA 和响应字节。
///
/// 参数说明：
/// - `cfg`：是完整 registry 声明
/// - `certificate`：同一次有界读取已解析的可选 CA。
/// - `url`：是固定目标。
///
/// 返回：HTTP 成功且响应未超过上限时返回原始字节；TLS、状态、读取或超限返回错误。
fn fetch_registry_document(
    cfg: SchemaRegistryDocumentCfg,
    certificate: Option<reqwest::Certificate>,
    url: String,
) -> Result<Arc<[u8]>> {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("naway-schema-registry/1")
        .https_only(true);
    if let Some(certificate) = certificate {
        builder = builder.add_root_certificate(certificate);
    }
    let client = builder
        .build()
        .context("build schema registry HTTPS client")?;
    let mut response = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/yaml, application/json",
        )
        .send()
        .context("fetch schema registry document")?;
    if !response.status().is_success() {
        bail!("schema registry returned non-success status");
    }
    if response
        .content_length()
        .is_some_and(|length| length > cfg.max_bytes as u64)
    {
        bail!("schema registry response exceeds max_bytes");
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(cfg.max_bytes as u64) as usize,
    );
    response
        .by_ref()
        .take(cfg.max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read schema registry response")?;
    if bytes.len() > cfg.max_bytes {
        bail!("schema registry response exceeds max_bytes");
    }
    Ok(Arc::from(bytes))
}

/// 业务作用：复验 HTTPS schema 原始字节的固定摘要与 detached Ed25519 signature。
///
/// 参数说明：
/// - `bytes`：是响应原文
/// - `cfg`：提供摘要和 SecretSource
/// - `config_dir`：解析本地来源。
///
/// 返回：两种校验都通过时返回实际文档摘要和固定公钥；格式、摘要、key 或签名不符合则拒绝。
fn verify_registry_document(
    bytes: &[u8],
    cfg: &SchemaRegistryDocumentCfg,
    config_dir: &Path,
) -> Result<([u8; 32], [u8; 32])> {
    validate_sha256(cfg.sha256.as_str())?;
    let digest = Sha256::digest(bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !actual.eq_ignore_ascii_case(cfg.sha256.as_str()) {
        bail!("schema registry response digest does not match pinned sha256");
    }
    let signature = crate::security::secret::resolve_text(
        cfg.signature.as_str(),
        config_dir,
        "schema registry signature",
    )?;
    let public_key = crate::security::secret::resolve_text(
        cfg.public_key.as_str(),
        config_dir,
        "schema registry public key",
    )?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .context("decode schema registry signature")?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .context("decode schema registry public key")?;
    let signature = Signature::from_slice(signature.as_slice())
        .context("schema registry signature must be 64 bytes")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("schema registry public key must be 32 bytes"))?;
    let public_key =
        VerifyingKey::from_bytes(&public_key).context("decode schema registry public key")?;
    public_key
        .verify_strict(bytes, &signature)
        .context("verify schema registry signature")?;
    Ok((digest.into(), public_key.to_bytes()))
}

/// 业务作用：验证固定 SHA-256 十六进制格式，避免摘要比较接受截断或歧义编码。
///
/// 参数说明：
/// - `digest`：是配置声明值。
///
/// 返回：恰好 64 个十六进制字符时成功；其它格式返回错误。
fn validate_sha256(digest: &str) -> Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("schema registry sha256 must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}
