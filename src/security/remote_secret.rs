//! 远程 Secret provider 的构建期拉取、版本门禁、退避与有界 last-known-good 缓存。
//!
//! 远端 I/O 只在 bootstrap 或统一 reload 候选构建阶段发生。成功值被冻结进业务计划；请求路径
//! 仅检查不可变值的有效截止点，不读取配置、磁盘、环境变量或 provider API。

mod policy;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use futures::{stream, StreamExt, TryStreamExt};
use http::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use parking_lot::Mutex;
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::model::{RemoteSecretAdapterCfg, RemoteSecretProviderCfg};

const MAX_PROVIDERS: usize = 32;
const MAX_REMOTE_REFS: usize = 256;
const MAX_SECRET_PATH_BYTES: usize = 512;
const MAX_JSON_POINTER_BYTES: usize = 256;
const MAX_AUTH_PREFIX_BYTES: usize = 64;
const MAX_REMOTE_SECRET_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_PROVIDER_DURATION_MS: u64 = 10 * 60 * 1_000;
const MAX_SECRET_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_LEASE_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_CONCURRENT_FETCHES: usize = 8;
const MAX_CACHE_ENTRIES: usize = 1024;

/// 一次远程解析得到的 secret 与数据面失败闭合截止点。
#[derive(Clone)]
pub(crate) struct ResolvedRemoteSecret {
    value: String,
    not_after: Instant,
}

impl ResolvedRemoteSecret {
    /// 业务作用：向业务计划转移已验证 secret，不暴露 provider 响应或版本元数据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回拥有所有权的 secret 字符串。
    pub(crate) fn value(&self) -> String {
        self.value.clone()
    }

    /// 业务作用：提供远程值允许用于新请求的单调时钟门禁。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 lease 与最大陈旧期中更早的截止点。
    pub(crate) fn not_after(&self) -> Instant {
        self.not_after
    }
}

/// 一轮远程解析的完整结果和后台刷新节奏。
pub(crate) struct RemoteSecretResolution {
    values: HashMap<String, ResolvedRemoteSecret>,
    refresh_interval_ms: Option<u64>,
}

impl RemoteSecretResolution {
    /// 业务作用：按原始 `remote://` 引用取得已验证值，禁止调用方自行回退到引用文本。
    ///
    /// 参数说明：
    /// - `reference`：是配置中出现的完整远程引用。
    ///
    /// 返回：引用已在本轮解析时返回 secret，否则报告候选内部引用不闭合。
    pub(crate) fn get(&self, reference: &str) -> Result<&ResolvedRemoteSecret> {
        self.values
            .get(reference)
            .context("remote secret reference was not resolved")
    }

    /// 业务作用：把已使用 provider 中最短刷新周期交给统一 reload worker。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有远程引用时为空，否则返回有界毫秒周期。
    pub(crate) fn refresh_interval_ms(&self) -> Option<u64> {
        self.refresh_interval_ms
    }
}

#[derive(Clone)]
struct PreparedProvider {
    name: Arc<str>,
    endpoint: Url,
    client: Client,
    authorization: Option<(HeaderName, HeaderValue)>,
    adapter: PreparedAdapter,
    value_pointer: Arc<str>,
    version_pointer: Arc<str>,
    lease_seconds_pointer: Option<Arc<str>>,
    refresh_interval: Duration,
    max_stale: Duration,
    retry_base: Duration,
    retry_max: Duration,
    max_response_bytes: usize,
    envelope: Option<crate::security::external_crypto::ExternalEnvelopePlan>,
    /// 当前信任材料与完整策略身份；与逻辑缓存键分离，不能重置对象的版本水位。
    policy_identity: [u8; 32],
}

#[derive(Clone)]
enum PreparedAdapter {
    GenericJson,
    AwsSecretsManager {
        region: Arc<str>,
        access_key_id: Arc<str>,
        secret_access_key: Arc<[u8]>,
        session_token: HeaderValue,
    },
    AzureKeyVault {
        api_version: Arc<str>,
    },
    GcpSecretManager,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct AwsContainerCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
}

struct RemoteReference {
    raw: String,
    provider: Arc<PreparedProvider>,
    secret_path: String,
}

#[derive(Clone)]
struct CachedSecret {
    value: String,
    version: u64,
    not_after: Instant,
    failures: u32,
    retry_not_before: Instant,
    last_success: Instant,
    /// 只有同一策略可以使用该值执行退避或 LKG 回退。
    policy_identity: [u8; 32],
}

struct FetchedSecret {
    value: String,
    version: u64,
    lease: Option<Duration>,
}

/// 业务作用：判断 SecretSource 是否要求远程 provider 解析。
///
/// 参数说明：
/// - `raw`：是 credential 中的 SecretSource 文本。
///
/// 返回：仅 `remote://` 前缀返回 true。
pub(crate) fn is_remote_reference(raw: &str) -> bool {
    raw.starts_with("remote://")
}

/// 业务作用：并发有界地解析候选使用的全部远程 secret，并冻结统一刷新周期。
///
/// 参数说明：
/// - `providers`：是 provider 目录
/// - `references`：是去重前引用
/// - `config_dir`：是本地认证 SecretSource 的相对路径基准
/// - `crypto_catalog`：提供 envelope 解密所需的共享密码 provider。
///
/// 返回：所有远端响应、版本、lease 与陈旧期合法时返回完整映射；任一首次读取失败则拒绝候选。
pub(crate) fn resolve_all(
    providers: &[RemoteSecretProviderCfg],
    references: impl IntoIterator<Item = String>,
    config_dir: &Path,
    crypto_catalog: &crate::security::external_crypto::ExternalCryptoCatalog,
) -> Result<RemoteSecretResolution> {
    let unique = references
        .into_iter()
        .filter(|reference| is_remote_reference(reference))
        .collect::<HashSet<_>>();
    if unique.len() > MAX_REMOTE_REFS {
        bail!("remote secret reference count exceeds {MAX_REMOTE_REFS}");
    }
    if unique.is_empty() {
        if !providers.is_empty() {
            bail!("secret_providers are configured but no remote secret references use them");
        }
        return Ok(RemoteSecretResolution {
            values: HashMap::new(),
            refresh_interval_ms: None,
        });
    }
    let prepared = prepare_providers(providers, config_dir, crypto_catalog)?;
    let mut used = HashSet::new();
    let mut requests = Vec::with_capacity(unique.len());
    for raw in unique {
        let (provider_name, secret_path) = parse_reference(raw.as_str())?;
        let provider_name = provider_name.to_owned();
        let secret_path = secret_path.to_owned();
        let provider = prepared
            .get(provider_name.as_str())
            .with_context(|| {
                format!("remote secret references unknown provider `{provider_name}`")
            })?
            .clone();
        used.insert(provider_name);
        requests.push(RemoteReference {
            raw,
            provider,
            secret_path,
        });
    }
    if let Some(unused) = prepared.keys().find(|name| !used.contains(name.as_str())) {
        bail!("remote secret provider `{unused}` is not referenced");
    }
    let refresh_interval_ms = requests
        .iter()
        .map(|request| request.provider.refresh_interval.as_millis() as u64)
        .min();
    let join = std::thread::Builder::new()
        .name("naway-secret-prepare".to_owned())
        .spawn(move || -> Result<Vec<(String, ResolvedRemoteSecret)>> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build remote secret prepare runtime")?;
            runtime.block_on(async move {
                stream::iter(requests.into_iter().map(|request| async move {
                    let resolved = resolve_one(&request.provider, request.secret_path.as_str())
                        .await
                        .with_context(|| {
                            format!("remote secret provider `{}` failed", request.provider.name)
                        })?;
                    Ok::<_, anyhow::Error>((request.raw, resolved))
                }))
                .buffer_unordered(MAX_CONCURRENT_FETCHES)
                .try_collect()
                .await
            })
        })
        .context("spawn remote secret prepare thread")?;
    let values = join
        .join()
        .map_err(|_| anyhow::anyhow!("remote secret prepare thread panicked"))??
        .into_iter()
        .collect();
    Ok(RemoteSecretResolution {
        values,
        refresh_interval_ms,
    })
}

/// 业务作用：收集 provider 认证、CA 与 mTLS 文件依赖，使身份轮换触发统一候选重建。
///
/// 参数说明：
/// - `providers`：是完整 provider 目录
/// - `config_dir`：是相对路径基准。
///
/// 返回：返回不含 secret 内容的本地依赖路径列表。
pub(crate) fn dependency_paths(
    providers: &[RemoteSecretProviderCfg],
    config_dir: &Path,
) -> Vec<PathBuf> {
    providers
        .iter()
        .flat_map(|provider| {
            let common = [
                provider.authorization.as_str(),
                provider.ca_certificate.as_str(),
                provider.client_certificate.as_str(),
                provider.client_private_key.as_str(),
            ];
            let adapter = match &provider.adapter {
                RemoteSecretAdapterCfg::AwsSecretsManager {
                    credentials,
                    ..
                } => Some(credentials.as_str()),
                RemoteSecretAdapterCfg::GenericJson
                | RemoteSecretAdapterCfg::AzureKeyVault {
                    ..
                }
                | RemoteSecretAdapterCfg::GcpSecretManager => None,
            };
            common
                .into_iter()
                .chain(adapter)
                .filter_map(|value| crate::security::secret::dependency_path(value, config_dir))
        })
        .collect()
}

/// 业务作用：把 provider 配置编译成固定 TLS、认证 header、JSON 契约和资源预算。
///
/// 参数说明：
/// - `configs`：是声明目录
/// - `config_dir`：是本地 SecretSource 路径基准
/// - `crypto_catalog`：提供可被 envelope 引用的已校验密码 provider。
///
/// 返回：全部 provider 唯一且安全时返回按名称索引的不可变计划，否则拒绝候选。
fn prepare_providers(
    configs: &[RemoteSecretProviderCfg],
    config_dir: &Path,
    crypto_catalog: &crate::security::external_crypto::ExternalCryptoCatalog,
) -> Result<HashMap<String, Arc<PreparedProvider>>> {
    if configs.is_empty() || configs.len() > MAX_PROVIDERS {
        bail!("secret_providers count must be in 1..={MAX_PROVIDERS}");
    }
    let mut providers = HashMap::with_capacity(configs.len());
    for config in configs {
        validate_identifier(config.name.as_str(), "remote secret provider name")?;
        validate_provider_limits(config)?;
        validate_adapter_contract(config)?;
        let endpoint = validate_endpoint(config.endpoint.as_str())?;
        let authorization = build_authorization(config, config_dir)?;
        let adapter = prepare_adapter(config, config_dir)?;
        let envelope = config
            .envelope
            .as_ref()
            .map(|reference| {
                crate::security::external_crypto::build_envelope_plan(reference, crypto_catalog)
            })
            .transpose()?;
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms));
        let mut material = policy::Material::new();
        if !config.ca_certificate.is_empty() {
            let pem = resolve_bootstrap_secret(
                config.ca_certificate.as_str(),
                config_dir,
                &format!("remote secret provider `{}` CA", config.name),
            )?;
            let certificate = crate::tls::trust::http_ca(pem.as_bytes())
                .context("remote secret provider CA is invalid")?;
            builder = builder.add_root_certificate(certificate);
            material.field(Some(pem.as_bytes()));
        } else {
            material.field(None);
        }
        match (
            config.client_certificate.is_empty(),
            config.client_private_key.is_empty(),
        ) {
            (true, true) => {
                material.field(None);
                material.field(None);
            }
            (false, false) => {
                let certificate = resolve_bootstrap_secret(
                    config.client_certificate.as_str(),
                    config_dir,
                    &format!(
                        "remote secret provider `{}` client certificate",
                        config.name
                    ),
                )?;
                let private_key = resolve_bootstrap_secret(
                    config.client_private_key.as_str(),
                    config_dir,
                    &format!(
                        "remote secret provider `{}` client private key",
                        config.name
                    ),
                )?;
                let identity =
                    reqwest::Identity::from_pem(format!("{certificate}\n{private_key}").as_bytes())
                        .context("remote secret provider client identity is invalid")?;
                builder = builder.identity(identity);
                material.field(Some(certificate.as_bytes()));
                material.field(Some(private_key.as_bytes()));
            }
            _ => {
                bail!("remote secret provider mTLS certificate and key must be configured together")
            }
        }
        let mut provider = PreparedProvider {
            name: Arc::from(config.name.as_str()),
            endpoint,
            client: builder
                .build()
                .context("build remote secret provider HTTP client")?,
            authorization,
            adapter,
            value_pointer: Arc::from(config.value_pointer.as_str()),
            version_pointer: Arc::from(config.version_pointer.as_str()),
            lease_seconds_pointer: (!config.lease_seconds_pointer.is_empty())
                .then(|| Arc::from(config.lease_seconds_pointer.as_str())),
            refresh_interval: Duration::from_millis(config.refresh_interval_ms),
            max_stale: Duration::from_millis(config.max_stale_ms),
            retry_base: Duration::from_millis(config.retry_base_ms),
            retry_max: Duration::from_millis(config.retry_max_ms),
            max_response_bytes: config.max_response_bytes,
            envelope,
            policy_identity: [0; 32],
        };
        provider.policy_identity = policy::identity(
            &provider,
            config.connect_timeout_ms,
            config.request_timeout_ms,
            material.finish(),
        );
        if providers
            .insert(config.name.clone(), Arc::new(provider))
            .is_some()
        {
            bail!("duplicate remote secret provider name `{}`", config.name);
        }
    }
    Ok(providers)
}

/// 业务作用：验证 provider 的时间、响应体和退避预算不会产生无界等待或永不过期值。
///
/// 参数说明：
/// - `config`：是单一 provider 声明。
///
/// 返回：全部数值处于安全范围且刷新早于陈旧截止点时成功，否则返回错误。
fn validate_provider_limits(config: &RemoteSecretProviderCfg) -> Result<()> {
    if config.max_response_bytes == 0
        || config.max_response_bytes > MAX_PROVIDER_RESPONSE_BYTES
        || config.connect_timeout_ms == 0
        || config.connect_timeout_ms > MAX_PROVIDER_DURATION_MS
        || config.request_timeout_ms < config.connect_timeout_ms
        || config.request_timeout_ms > MAX_PROVIDER_DURATION_MS
        || config.refresh_interval_ms == 0
        || config.refresh_interval_ms > MAX_SECRET_AGE_MS
        || config.max_stale_ms <= config.refresh_interval_ms
        || config.max_stale_ms > MAX_SECRET_AGE_MS
        || config.retry_base_ms == 0
        || config.retry_base_ms > config.retry_max_ms
        || config.retry_max_ms > config.max_stale_ms
    {
        bail!("remote secret provider resource limits are invalid");
    }
    if config.authorization_prefix.len() > MAX_AUTH_PREFIX_BYTES
        || config
            .authorization_prefix
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        bail!("remote secret provider authorization_prefix is invalid");
    }
    Ok(())
}

/// 业务作用：约束原生云适配器的认证形态和字段边界，使统一 provider 生命周期不会被 wire 差异绕过。
///
/// 参数说明：
/// - `config`：是单一 provider 声明。
///
/// 返回：适配器专属字段、认证来源和通用 JSON Pointer 无歧义时成功，否则拒绝候选。
fn validate_adapter_contract(config: &RemoteSecretProviderCfg) -> Result<()> {
    if !matches!(&config.adapter, RemoteSecretAdapterCfg::GenericJson)
        && (config.value_pointer != "/value"
            || config.version_pointer != "/version"
            || !config.lease_seconds_pointer.is_empty())
    {
        bail!("native remote secret adapters cannot override generic JSON Pointer fields");
    }
    match &config.adapter {
        RemoteSecretAdapterCfg::GenericJson => {
            validate_pointer(config.value_pointer.as_str(), "value_pointer")?;
            validate_pointer(config.version_pointer.as_str(), "version_pointer")?;
            if !config.lease_seconds_pointer.is_empty() {
                validate_pointer(
                    config.lease_seconds_pointer.as_str(),
                    "lease_seconds_pointer",
                )?;
            }
        }
        RemoteSecretAdapterCfg::AwsSecretsManager {
            region,
            credentials,
        } => {
            if region.is_empty()
                || region.len() > 64
                || !region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                bail!("AWS Secrets Manager region is invalid");
            }
            if credentials.is_empty() || is_remote_reference(credentials) {
                bail!("AWS Secrets Manager credentials must use a local SecretSource");
            }
            if !config.authorization.is_empty() || !config.authorization_prefix.is_empty() {
                bail!("AWS Secrets Manager uses SigV4 and cannot declare HTTP authorization");
            }
        }
        RemoteSecretAdapterCfg::AzureKeyVault {
            api_version,
        } => {
            validate_bearer_adapter(config, "Azure Key Vault")?;
            if api_version.is_empty()
                || api_version.len() > 32
                || !api_version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
            {
                bail!("Azure Key Vault api_version is invalid");
            }
        }
        RemoteSecretAdapterCfg::GcpSecretManager => {
            validate_bearer_adapter(config, "Google Secret Manager")?;
        }
    }
    Ok(())
}

/// 业务作用：要求 OAuth 型云适配器只能把本地 workload token 放进标准 Bearer header。
///
/// 参数说明：
/// - `config`：是 provider 声明
/// - `provider_name`：是低敏错误标签。
///
/// 返回：认证来源、header 和前缀符合固定 OAuth 契约时成功，否则拒绝候选。
fn validate_bearer_adapter(config: &RemoteSecretProviderCfg, provider_name: &str) -> Result<()> {
    if config.authorization.is_empty()
        || !config
            .authorization_header
            .eq_ignore_ascii_case("authorization")
        || config.authorization_prefix != "Bearer "
    {
        bail!("{provider_name} requires a local authorization SecretSource with `Bearer ` prefix");
    }
    Ok(())
}

/// 业务作用：把云适配器的本地身份材料编译成不可记录的请求签名计划。
///
/// 参数说明：
/// - `config`：是已通过字段复验的 provider
/// - `config_dir`：是 SecretSource 路径基准。
///
/// 返回：身份仍在有效期内时返回适配器计划；凭据缺失、过期或格式错误时拒绝候选。
fn prepare_adapter(config: &RemoteSecretProviderCfg, config_dir: &Path) -> Result<PreparedAdapter> {
    match &config.adapter {
        RemoteSecretAdapterCfg::GenericJson => Ok(PreparedAdapter::GenericJson),
        RemoteSecretAdapterCfg::AwsSecretsManager {
            region,
            credentials,
        } => {
            let raw = resolve_bootstrap_secret(
                credentials,
                config_dir,
                &format!("remote secret provider `{}` AWS credentials", config.name),
            )?;
            let credentials: AwsContainerCredentials =
                serde_json::from_str(&raw).context("AWS container credentials JSON is invalid")?;
            validate_aws_credential_text(&credentials)?;
            let expiration = DateTime::parse_from_rfc3339(&credentials.expiration)
                .context("AWS container credentials expiration is invalid")?
                .with_timezone(&Utc);
            if expiration
                <= Utc::now() + chrono::Duration::milliseconds(config.request_timeout_ms as i64)
            {
                bail!("AWS container credentials expire before the provider request deadline");
            }
            let mut session_token = HeaderValue::from_str(&credentials.token)
                .context("AWS container credentials token is not a valid header value")?;
            session_token.set_sensitive(true);
            Ok(PreparedAdapter::AwsSecretsManager {
                region: Arc::from(region.as_str()),
                access_key_id: Arc::from(credentials.access_key_id),
                secret_access_key: Arc::from(credentials.secret_access_key.into_bytes()),
                session_token,
            })
        }
        RemoteSecretAdapterCfg::AzureKeyVault {
            api_version,
        } => Ok(PreparedAdapter::AzureKeyVault {
            api_version: Arc::from(api_version.as_str()),
        }),
        RemoteSecretAdapterCfg::GcpSecretManager => Ok(PreparedAdapter::GcpSecretManager),
    }
}

/// 业务作用：限制 AWS 临时凭据字段，避免空值、控制字符或异常长度进入 SigV4 canonical request。
///
/// 参数说明：
/// - `credentials`：是本地容器凭据文档。
///
/// 返回：access key、secret key 与 session token 都是有界单行值时成功。
fn validate_aws_credential_text(credentials: &AwsContainerCredentials) -> Result<()> {
    let access_key_valid = (16..=128).contains(&credentials.access_key_id.len())
        && credentials
            .access_key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric());
    let secret_key_valid = (16..=256).contains(&credentials.secret_access_key.len())
        && !credentials.secret_access_key.bytes().any(|byte| byte == 0);
    let token_valid = !credentials.token.is_empty()
        && credentials.token.len() <= 8192
        && !credentials
            .token
            .bytes()
            .any(|byte| byte.is_ascii_control());
    if !access_key_valid || !secret_key_valid || !token_valid {
        bail!("AWS container credentials contain invalid or oversized fields");
    }
    Ok(())
}

/// 业务作用：固定 provider API origin 和 path 前缀，防 secret 标识改变 scheme、authority 或 query。
///
/// 参数说明：
/// - `raw`：是 provider endpoint。
///
/// 返回：无凭据、query、fragment 的 HTTPS URL 成功，否则拒绝候选。
fn validate_endpoint(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("remote secret provider endpoint is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("remote secret provider endpoint must be a credential-free HTTPS URL");
    }
    Ok(url)
}

/// 业务作用：解析 provider 认证 SecretSource，并把最终 HTTP 值标为 sensitive。
///
/// 参数说明：
/// - `config`：提供 header、前缀和来源
/// - `config_dir`：是相对路径基准。
///
/// 返回：未配置认证时为空；合法认证返回不可记录的 header 对，否则拒绝候选。
fn build_authorization(
    config: &RemoteSecretProviderCfg,
    config_dir: &Path,
) -> Result<Option<(HeaderName, HeaderValue)>> {
    let name: HeaderName = config
        .authorization_header
        .parse()
        .context("remote secret provider authorization header is invalid")?;
    if matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "upgrade"
            | "te"
            | "trailer"
    ) {
        bail!("remote secret provider authorization cannot target a routing or framing header");
    }
    if config.authorization.is_empty() {
        if !config.authorization_prefix.is_empty() {
            bail!("remote secret provider authorization_prefix requires authorization");
        }
        return Ok(None);
    }
    let secret = resolve_bootstrap_secret(
        config.authorization.as_str(),
        config_dir,
        &format!("remote secret provider `{}` authorization", config.name),
    )?;
    if secret.is_empty() {
        bail!("remote secret provider authorization resolves to an empty value");
    }
    let mut value = HeaderValue::from_str(&format!("{}{secret}", config.authorization_prefix))
        .context("remote secret provider authorization is not a valid header value")?;
    value.set_sensitive(true);
    Ok(Some((name, value)))
}

/// 业务作用：解析 provider 自身的 bootstrap 身份，并禁止递归远程依赖形成不可终止的信任环。
///
/// 参数说明：
/// - `raw`：是本地 SecretSource
/// - `config_dir`：是路径基准
/// - `field`：是低敏错误标签。
///
/// 返回：本地来源可读取时返回文本；`remote://` 或读取失败时拒绝候选。
fn resolve_bootstrap_secret(raw: &str, config_dir: &Path, field: &str) -> Result<String> {
    if is_remote_reference(raw) {
        bail!("{field} cannot use a recursive remote SecretSource");
    }
    crate::security::secret::resolve_text(raw, config_dir, field)
}

/// 业务作用：解析 `remote://provider/path`，并禁止空段、父目录和可造成 URL 歧义的字符。
///
/// 参数说明：
/// - `raw`：是完整远程引用。
///
/// 返回：返回 provider 名与受限相对 secret path；非法引用返回错误。
fn parse_reference(raw: &str) -> Result<(&str, &str)> {
    let remainder = raw
        .strip_prefix("remote://")
        .context("remote secret reference must start with remote://")?;
    let (provider, path) = remainder
        .split_once('/')
        .context("remote secret reference requires provider and secret path")?;
    validate_identifier(provider, "remote secret provider reference")?;
    if path.is_empty()
        || path.len() > MAX_SECRET_PATH_BYTES
        || path.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        bail!("remote secret path is invalid");
    }
    Ok((provider, path))
}

/// 业务作用：验证 provider 名为可稳定引用且不会污染日志字段的低敏标识符。
///
/// 参数说明：
/// - `value`：是待验证名称
/// - `field`：是不含 secret 的错误标签。
///
/// 返回：安全 ASCII 标识符成功，否则返回错误。
fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{field} is invalid");
    }
    Ok(())
}

/// 业务作用：验证 JSON Pointer 有界且语法明确，避免把空根或非法转义当作 secret 字段。
///
/// 参数说明：
/// - `pointer`：是配置值
/// - `field`：是错误标签。
///
/// 返回：合法非空 JSON Pointer 成功，否则返回错误。
fn validate_pointer(pointer: &str, field: &str) -> Result<()> {
    if !pointer.starts_with('/')
        || pointer.len() > MAX_JSON_POINTER_BYTES
        || pointer
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
        || pointer.split('/').skip(1).any(|token| {
            let mut chars = token.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
                    return true;
                }
            }
            false
        })
    {
        bail!("remote secret provider {field} is invalid");
    }
    Ok(())
}

/// 业务作用：在退避、版本单调与 LKG 门禁下解析一个远程引用。
///
/// 参数说明：
/// - `provider`：是不可变连接计划
/// - `secret_path`：是受限相对路径。
///
/// 返回：新值或同策略下仍有效的缓存值；新策略必须成功拉取，版本回退、同版异值和过期依赖均失败闭合。
async fn resolve_one(
    provider: &PreparedProvider,
    secret_path: &str,
) -> Result<ResolvedRemoteSecret> {
    let cache_key = cache_key(provider, secret_path);
    let now = Instant::now();
    if let Some(cached) = cache().lock().get(&cache_key).cloned() {
        // 退避只证明旧策略下的依赖失败；新认证、信任或期限策略必须先重新成功取得值。
        if cached.policy_identity == provider.policy_identity
            && now < cached.retry_not_before
            && now < cached.not_after
        {
            return Ok(ResolvedRemoteSecret {
                value: cached.value,
                not_after: cached.not_after,
            });
        }
    }
    let mut fetched = match fetch(provider, secret_path).await {
        Ok(value) => value,
        Err(error) => return fallback_after_failure(provider, cache_key, error),
    };
    if let Some(envelope) = &provider.envelope {
        fetched.value = match envelope
            .decrypt_remote_secret(
                provider.name.as_ref(),
                secret_path,
                fetched.version,
                fetched.value.as_str(),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => return fallback_after_failure(provider, cache_key, error),
        };
    }
    let now = Instant::now();
    let not_after = fetched
        .lease
        .map(|lease| now + lease)
        .unwrap_or(now + provider.max_stale)
        .min(now + provider.max_stale);
    let mut entries = cache().lock();
    if let Some(previous) = entries.get(&cache_key) {
        if fetched.version < previous.version {
            bail!("remote secret provider returned a version rollback");
        }
        if fetched.version == previous.version && fetched.value != previous.value {
            bail!("remote secret provider returned different values for one version");
        }
    }
    let resolved = ResolvedRemoteSecret {
        value: fetched.value.clone(),
        not_after,
    };
    // 配置反复切换 endpoint/path 时缓存键会变化；先清理过期代，再按最近成功时间回收最旧
    // 非活动项，确保控制面 LKG 不会因配置 churn 无界增长。
    entries.retain(|_, cached| now < cached.not_after);
    if entries.len() >= MAX_CACHE_ENTRIES && !entries.contains_key(&cache_key) {
        if let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, cached)| cached.last_success)
            .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
    }
    entries.insert(
        cache_key,
        CachedSecret {
            value: fetched.value,
            version: fetched.version,
            not_after,
            failures: 0,
            retry_not_before: now,
            last_success: now,
            policy_identity: provider.policy_identity,
        },
    );
    Ok(resolved)
}

/// 业务作用：provider 读取失败时执行有界指数退避，并仅在旧值仍满足 lease/陈旧期时回退。
///
/// 参数说明：
/// - `provider`：提供退避边界
/// - `cache_key`：标识事实源
/// - `error`：不含响应 body。
///
/// 返回：仅同策略且仍有效的 LKG 返回成功；策略变化、缓存缺失或过期时拒绝回退。
fn fallback_after_failure(
    provider: &PreparedProvider,
    cache_key: String,
    error: anyhow::Error,
) -> Result<ResolvedRemoteSecret> {
    let now = Instant::now();
    let mut entries = cache().lock();
    let Some(cached) = entries.get_mut(&cache_key) else {
        return Err(error);
    };
    // 新策略未获得自己的成功证据时不能借用旧值，也不能延长旧策略的退避或改变其失败计数。
    if cached.policy_identity != provider.policy_identity {
        return Err(error.context("remote secret cache belongs to a different provider policy"));
    }
    cached.failures = cached.failures.saturating_add(1);
    let exponent = cached.failures.saturating_sub(1).min(20);
    let factor = 1_u32 << exponent;
    let backoff = provider
        .retry_base
        .checked_mul(factor)
        .unwrap_or(provider.retry_max)
        .min(provider.retry_max);
    cached.retry_not_before = now + backoff;
    if now >= cached.not_after {
        return Err(error.context("remote secret last-known-good value expired"));
    }
    tracing::warn!(
        provider = %provider.name,
        retry_ms = backoff.as_millis() as u64,
        error = %error,
        "remote secret refresh failed; retaining bounded last-known-good value"
    );
    Ok(ResolvedRemoteSecret {
        value: cached.value.clone(),
        not_after: cached.not_after,
    })
}

/// 业务作用：向固定 provider URL 发起一次有 deadline、有界且不跟随重定向的 JSON 读取。
///
/// 参数说明：
/// - `provider`：固定 TLS/认证/响应契约
/// - `secret_path`：是已经过语法约束的对象标识。
///
/// 返回：HTTP、媒体类型、JSON、值、版本与 lease 全部合法时返回候选值，否则返回低敏错误。
async fn fetch(provider: &PreparedProvider, secret_path: &str) -> Result<FetchedSecret> {
    let request = build_provider_request(provider, secret_path)?;
    let response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("remote secret provider request failed"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("remote secret provider returned HTTP {status}");
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if !adapter_accepts_media_type(&provider.adapter, content_type) {
        bail!("remote secret provider response is not JSON");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| anyhow::anyhow!("read remote secret provider response failed"))?;
        if body.len().saturating_add(chunk.len()) > provider.max_response_bytes {
            bail!("remote secret provider response exceeds configured limit");
        }
        body.extend_from_slice(&chunk);
    }
    let document: Value =
        serde_json::from_slice(&body).context("remote secret provider response is invalid JSON")?;
    parse_provider_document(provider, &document)
}

/// 业务作用：按适配器构造固定方法、URL、认证和请求体，云 API 差异不能绕开公共 HTTPS client。
///
/// 参数说明：
/// - `provider`：是不可变连接计划
/// - `secret_path`：是远程对象标识。
///
/// 返回：返回尚未发送的 reqwest 请求；路径、云资源名或签名材料不合法时拒绝。
fn build_provider_request(
    provider: &PreparedProvider,
    secret_path: &str,
) -> Result<reqwest::RequestBuilder> {
    match &provider.adapter {
        PreparedAdapter::GenericJson => {
            let url = append_path(&provider.endpoint, secret_path)?;
            Ok(add_provider_authorization(
                provider,
                provider.client.get(url),
            ))
        }
        PreparedAdapter::AwsSecretsManager {
            region,
            access_key_id,
            secret_access_key,
            session_token,
        } => {
            validate_aws_secret_id(secret_path)?;
            let body = serde_json::to_vec(&serde_json::json!({
                "SecretId": secret_path
            }))
            .context("encode AWS Secrets Manager request")?;
            sign_aws_request(
                provider.client.post(provider.endpoint.clone()),
                &provider.endpoint,
                region,
                access_key_id,
                secret_access_key,
                session_token,
                &body,
                Utc::now(),
            )
            .map(|request| request.body(body))
        }
        PreparedAdapter::AzureKeyVault {
            api_version,
        } => {
            let (name, version) = validate_azure_secret_path(secret_path)?;
            let mut url = provider.endpoint.clone();
            {
                let mut segments = url.path_segments_mut().map_err(|_| {
                    anyhow::anyhow!("Azure Key Vault endpoint cannot accept a path")
                })?;
                segments.pop_if_empty();
                segments.push("secrets");
                segments.push(name);
                if let Some(version) = version {
                    segments.push(version);
                }
            }
            url.query_pairs_mut()
                .append_pair("api-version", api_version);
            Ok(add_provider_authorization(
                provider,
                provider.client.get(url),
            ))
        }
        PreparedAdapter::GcpSecretManager => {
            validate_gcp_secret_path(secret_path)?;
            let mut url = append_path(&provider.endpoint, secret_path)?;
            let access_path = format!("{}:access", url.path());
            url.set_path(&access_path);
            Ok(add_provider_authorization(
                provider,
                provider.client.get(url),
            ))
        }
    }
}

/// 业务作用：把公共认证值附加到已确定 origin 的云请求，保持凭据为 sensitive header。
///
/// 参数说明：
/// - `provider`：提供可选认证
/// - `request`：是尚未发送的固定目标请求。
///
/// 返回：返回附加认证后的请求；未配置认证时保持原请求。
fn add_provider_authorization(
    provider: &PreparedProvider,
    request: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    match &provider.authorization {
        Some((name, value)) => request.header(name, value),
        None => request,
    }
}

/// 业务作用：把受限相对路径逐段追加到固定 endpoint，禁止对象标识改变 origin 或 query。
///
/// 参数说明：
/// - `endpoint`：是已验证 HTTPS 前缀
/// - `secret_path`：是分段对象标识。
///
/// 返回：返回保持原 origin 的 URL；不能承载 path 时返回错误。
fn append_path(endpoint: &Url, secret_path: &str) -> Result<Url> {
    let mut url = endpoint.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("remote secret provider endpoint cannot accept path"))?;
        segments.pop_if_empty();
        for segment in secret_path.split('/') {
            segments.push(segment);
        }
    }
    Ok(url)
}

/// 业务作用：限制云 adapter 的响应媒体类型，同时兼容 AWS 的标准 JSON wire 类型。
///
/// 参数说明：
/// - `adapter`：是已编译适配器
/// - `media_type`：是去除参数后的响应类型。
///
/// 返回：该适配器可按 JSON 解析时返回 true。
fn adapter_accepts_media_type(adapter: &PreparedAdapter, media_type: &str) -> bool {
    media_type == "application/json"
        || media_type.ends_with("+json")
        || matches!(adapter, PreparedAdapter::AwsSecretsManager {
            ..
        })
            && media_type == "application/x-amz-json-1.1"
}

/// 业务作用：把通用或云原生响应收敛成统一文本值、单调版本与可选 lease。
///
/// 参数说明：
/// - `provider`：提供适配器及通用 Pointer
/// - `document`：是有界 JSON 响应。
///
/// 返回：值、版本和 lease 完整合法时返回统一结果，否则拒绝本轮候选。
fn parse_provider_document(provider: &PreparedProvider, document: &Value) -> Result<FetchedSecret> {
    match &provider.adapter {
        PreparedAdapter::GenericJson => parse_generic_document(provider, document),
        PreparedAdapter::AwsSecretsManager {
            ..
        } => {
            let raw = if let Some(value) = document.get("SecretString").and_then(Value::as_str) {
                value.to_owned()
            } else {
                let encoded = document
                    .get("SecretBinary")
                    .and_then(Value::as_str)
                    .context("AWS Secrets Manager response has no text secret")?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .context("AWS Secrets Manager binary secret is not Base64")?;
                String::from_utf8(decoded)
                    .context("AWS Secrets Manager binary secret is not UTF-8 text")?
            };
            let version = epoch_number_to_micros(
                document
                    .get("CreatedDate")
                    .context("AWS Secrets Manager response has no CreatedDate")?,
                "AWS Secrets Manager CreatedDate",
            )?;
            Ok(FetchedSecret {
                value: validate_secret_value(&raw)?,
                version,
                lease: None,
            })
        }
        PreparedAdapter::AzureKeyVault {
            ..
        } => {
            let value = document
                .get("value")
                .and_then(Value::as_str)
                .context("Azure Key Vault response has no string value")?;
            let updated = document
                .pointer("/attributes/updated")
                .and_then(Value::as_u64)
                .context("Azure Key Vault response has no updated epoch")?;
            let version = updated
                .checked_mul(1_000_000)
                .context("Azure Key Vault updated epoch is out of range")?;
            Ok(FetchedSecret {
                value: validate_secret_value(value)?,
                version,
                lease: None,
            })
        }
        PreparedAdapter::GcpSecretManager => {
            let encoded = document
                .pointer("/payload/data")
                .and_then(Value::as_str)
                .context("Google Secret Manager response has no payload data")?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .context("Google Secret Manager payload is not Base64")?;
            let raw = String::from_utf8(decoded)
                .context("Google Secret Manager payload is not UTF-8 text")?;
            let version = document
                .get("name")
                .and_then(Value::as_str)
                .and_then(|name| name.rsplit('/').next())
                .and_then(|version| version.parse::<u64>().ok())
                .filter(|version| *version > 0)
                .context("Google Secret Manager response has no numeric version")?;
            Ok(FetchedSecret {
                value: validate_secret_value(&raw)?,
                version,
                lease: None,
            })
        }
    }
}

/// 业务作用：解析通用 JSON Pointer 契约，并维持原有 lease 与刷新周期约束。
///
/// 参数说明：
/// - `provider`：提供 Pointer 和刷新边界
/// - `document`：是有界 JSON 响应。
///
/// 返回：值、单调 u64 版本及可选有效 lease。
fn parse_generic_document(provider: &PreparedProvider, document: &Value) -> Result<FetchedSecret> {
    let value = document
        .pointer(provider.value_pointer.as_ref())
        .and_then(Value::as_str)
        .context("remote secret provider value is missing or not a string")?;
    let value = validate_secret_value(value)?;
    let version = document
        .pointer(provider.version_pointer.as_ref())
        .and_then(Value::as_u64)
        .context("remote secret provider version is missing or not u64")?;
    let lease = provider
        .lease_seconds_pointer
        .as_ref()
        .map(|pointer| {
            let seconds = document
                .pointer(pointer.as_ref())
                .and_then(Value::as_u64)
                .context("remote secret provider lease is missing or not u64")?;
            if seconds == 0 || seconds > MAX_LEASE_SECONDS {
                bail!("remote secret provider lease is outside the supported range");
            }
            let lease = Duration::from_secs(seconds);
            if lease <= provider.refresh_interval {
                bail!("remote secret provider lease must exceed refresh_interval_ms");
            }
            Ok(lease)
        })
        .transpose()?;
    Ok(FetchedSecret {
        value,
        version,
        lease,
    })
}

/// 业务作用：验证 AWS SecretId 的文本边界，避免控制字符或超长名称进入签名请求体。
///
/// 参数说明：
/// - `secret_id`：是 `remote://` 引用中 provider 后的对象名。
///
/// 返回：由安全 ASCII 路径段组成时成功，否则拒绝请求。
fn validate_aws_secret_id(secret_id: &str) -> Result<()> {
    if secret_id.is_empty()
        || secret_id.len() > MAX_SECRET_PATH_BYTES
        || secret_id.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        bail!("AWS Secrets Manager SecretId is invalid");
    }
    Ok(())
}

/// 业务作用：把 Azure secret 引用限制为名称和可选不可变版本，不能注入额外 REST path。
///
/// 参数说明：
/// - `path`：是 provider 后的对象路径。
///
/// 返回：返回已验证 name 与可选 version；段数或字符不符合 Key Vault 契约时失败。
fn validate_azure_secret_path(path: &str) -> Result<(&str, Option<&str>)> {
    let segments = path.split('/').collect::<Vec<_>>();
    if !(1..=2).contains(&segments.len())
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > 127
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("Azure Key Vault secret path is invalid");
    }
    Ok((segments[0], segments.get(1).copied()))
}

/// 业务作用：要求 Google Secret 引用完整声明 project、secret 与 version，禁止访问其它 API resource。
///
/// 参数说明：
/// - `path`：是 provider 后的对象路径。
///
/// 返回：形如 `projects/<id>/secrets/<id>/versions/<number|latest>` 时成功。
fn validate_gcp_secret_path(path: &str) -> Result<()> {
    let segments = path.split('/').collect::<Vec<_>>();
    let identifier = |value: &str| {
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    let valid_version = segments
        .get(5)
        .is_some_and(|value| *value == "latest" || value.parse::<u64>().is_ok_and(|v| v > 0));
    if segments.len() != 6
        || segments[0] != "projects"
        || !identifier(segments[1])
        || segments[2] != "secrets"
        || !identifier(segments[3])
        || segments[4] != "versions"
        || !valid_version
    {
        bail!("Google Secret Manager resource path is invalid");
    }
    Ok(())
}

/// 业务作用：把云 API 的 epoch 数值转换为可执行单调比较的微秒版本。
///
/// 参数说明：
/// - `value`：是 JSON 数值
/// - `field`：是不含 secret 的错误标签。
///
/// 返回：正数且在 u64 微秒范围内时返回版本，否则拒绝响应。
fn epoch_number_to_micros(value: &Value, field: &str) -> Result<u64> {
    let seconds = value
        .as_f64()
        .filter(|value| value.is_finite() && *value > 0.0)
        .with_context(|| format!("{field} is not a positive epoch number"))?;
    let micros = seconds * 1_000_000.0;
    if micros > u64::MAX as f64 {
        bail!("{field} is out of range");
    }
    Ok(micros.round() as u64)
}

/// 业务作用：为 AWS Secrets Manager 请求生成完整 SigV4 header，绑定方法、目标、body、region 与临时凭据。
///
/// 参数说明：
/// - `request`：向固定 endpoint 发送的 POST 请求。
/// - `url`：与请求一致的签名目标 URL。
/// - `region`：本地容器凭据限定的 AWS region。
/// - `access_key_id`：本地凭据中的 access key ID。
/// - `secret_access_key`：本地凭据中的 secret access key。
/// - `session_token`：本地凭据中的可选 session token。
/// - `body`：即将发送的精确 JSON 字节。
/// - `now`：本次签名使用的时间。
///
/// 返回：签名成功返回带敏感认证 header 的请求；时间、host 或 HMAC 初始化失败时拒绝。
#[allow(clippy::too_many_arguments)]
fn sign_aws_request(
    request: reqwest::RequestBuilder,
    url: &Url,
    region: &str,
    access_key_id: &str,
    secret_access_key: &[u8],
    session_token: &HeaderValue,
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<reqwest::RequestBuilder> {
    super::aws_json::sign(
        request,
        url,
        super::aws_json::Scope {
            region,
            operation: super::aws_json::Operation::SecretValue,
        },
        super::aws_json::Credentials {
            access_key_id,
            secret_access_key,
            session_token: Some(session_token),
        },
        body,
        now,
    )
}

/// 业务作用：限制远端 secret 值并统一处理文本挂载常见的单个结尾换行。
///
/// 参数说明：
/// - `raw`：是 JSON 中的 secret 字符串。
///
/// 返回：非空、无 NUL、有界值成功，否则拒绝 provider 响应。
fn validate_secret_value(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > MAX_REMOTE_SECRET_BYTES || raw.contains('\0') {
        bail!("remote secret provider value is empty or exceeds the supported text boundary");
    }
    let value = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(raw)
        .to_owned();
    if value.is_empty() {
        bail!("remote secret provider value is empty after newline normalization");
    }
    Ok(value)
}

/// 业务作用：生成不暴露 provider 路径的进程内缓存键，同时隔离 endpoint 和响应契约变更。
///
/// 参数说明：
/// - `provider`：是已编译计划
/// - `secret_path`：是远端对象标识。
///
/// 返回：返回 SHA-256 十六进制键，不包含 secret 值。
fn cache_key(provider: &PreparedProvider, secret_path: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(provider.name.as_bytes());
    digest.update([0]);
    digest.update(provider.endpoint.as_str().as_bytes());
    digest.update([0]);
    digest.update(provider.value_pointer.as_bytes());
    digest.update([0]);
    digest.update(provider.version_pointer.as_bytes());
    digest.update([0]);
    match &provider.adapter {
        PreparedAdapter::GenericJson => digest.update(b"generic_json"),
        PreparedAdapter::AwsSecretsManager {
            region,
            access_key_id,
            ..
        } => {
            digest.update(b"aws_secrets_manager");
            digest.update([0]);
            digest.update(region.as_bytes());
            digest.update([0]);
            digest.update(access_key_id.as_bytes());
        }
        PreparedAdapter::AzureKeyVault {
            api_version,
        } => {
            digest.update(b"azure_key_vault");
            digest.update([0]);
            digest.update(api_version.as_bytes());
        }
        PreparedAdapter::GcpSecretManager => digest.update(b"gcp_secret_manager"),
    }
    digest.update([0]);
    digest.update(secret_path.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// 业务作用：提供跨 reload 代际共享的有界 LKG 状态，使临时 provider 故障不清空已验证值。
///
/// 参数说明: 无。
///
/// 返回：返回进程级缓存锁；调用方不得在持锁期间执行 I/O。
fn cache() -> &'static Mutex<HashMap<String, CachedSecret>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedSecret>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
