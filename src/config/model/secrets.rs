//! 上游凭据、远程密钥与不导出私钥的密码能力声明。

use super::*;

/// 可复用上游凭据声明。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UpstreamCredentialCfg {
    /// 全局唯一稳定名称，route/service 只保存此引用。
    pub name: String,
    /// 凭据类型：`api_key|bearer|basic|header|query|tls_client_identity`。
    pub kind: String,
    /// API key、Bearer、自定义 header/query 或 Basic password 的 SecretSource。
    #[serde(default)]
    pub value: String,
    /// Basic 用户名；其它类型必须为空。
    #[serde(default)]
    pub username: String,
    /// `api_key|header|query` 的 header/query 名；Bearer/Basic/TLS 必须为空。
    #[serde(default)]
    pub target: String,
    /// 是否允许覆盖 route 自身产生的同名 header；必须显式声明。客户端同名值始终先删除。
    pub overwrite: Option<bool>,
    /// 允许接收该凭据的规范 backend origin 或 `lb://service`，不能为空。
    pub allowed_backends: Vec<String>,
    /// TLS client certificate PEM 的 SecretSource，仅 `tls_client_identity` 使用。
    #[serde(default)]
    pub client_certificate: String,
    /// TLS client private key PEM 的 SecretSource，仅 `tls_client_identity` 使用。
    #[serde(default)]
    pub client_private_key: String,
    /// 已从本地或远程来源解析的普通凭据；不参与反序列化和配置导出。
    #[serde(skip)]
    pub(crate) resolved_value: Option<String>,
    /// 已解析的 TLS 客户端证书；与原始远程引用隔离，避免运行期再次访问 provider。
    #[serde(skip)]
    pub(crate) resolved_client_certificate: Option<String>,
    /// 已解析的 TLS 客户端私钥；不实现公开序列化或调试输出。
    #[serde(skip)]
    pub(crate) resolved_client_private_key: Option<String>,
    /// 远程凭据允许用于新请求的单调时钟截止点；本地来源没有该限制。
    #[serde(skip)]
    pub(crate) resolved_not_after: Option<std::time::Instant>,
}

/// HTTPS keyless/KMS 或 PKCS#11/HSM 密码 provider 的传输、认证与资源预算。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExternalCryptoProviderCfg {
    /// 全局唯一名称，TLS signer 与 envelope secret 按名称引用。
    pub name: String,
    /// 固定 HTTPS operation endpoint；请求 body 中声明 `sign|encrypt|decrypt`，不拼接动态路径。
    #[serde(default)]
    pub endpoint: String,
    /// 可选 PKCS#11/HSM transport；存在时 `endpoint` 与 HTTP 身份字段必须为空。
    #[serde(default)]
    pub pkcs11: Option<Pkcs11CryptoProviderCfg>,
    /// Authorization 值 SecretSource；空值表示由 mTLS/workload 网络身份认证。
    #[serde(default)]
    pub authorization: String,
    /// Authorization 值前缀，Bearer token 通常为 `Bearer `。
    #[serde(default)]
    pub authorization_prefix: String,
    /// 自定义根 CA PEM SecretSource；空值使用平台根。
    #[serde(default)]
    pub ca_certificate: String,
    /// provider mTLS 客户端证书 SecretSource。
    #[serde(default)]
    pub client_certificate: String,
    /// provider mTLS 客户端私钥 SecretSource。
    #[serde(default)]
    pub client_private_key: String,
    /// provider 允许执行的签名算法集合。
    #[serde(default)]
    pub allowed_algorithms: Vec<String>,
    /// 单次 operation deadline。
    #[serde(default = "default_external_crypto_timeout_ms")]
    pub timeout_ms: u64,
    /// 单 provider 同时执行的远程 operation 上限。
    #[serde(default = "default_external_crypto_concurrency")]
    pub max_concurrency: usize,
    /// TLS 同步签名桥接的有界等待队列。
    #[serde(default = "default_external_crypto_queue_capacity")]
    pub queue_capacity: usize,
    /// 连续依赖失败达到该值后打开熔断器。
    #[serde(default = "default_external_crypto_circuit_failures")]
    pub circuit_failure_threshold: u32,
    /// 熔断后拒绝新 operation 的时间。
    #[serde(default = "default_external_crypto_circuit_open_ms")]
    pub circuit_open_ms: u64,
    /// 单个请求 message/ciphertext 的原始字节上限。
    #[serde(default = "default_external_crypto_input_bytes")]
    pub max_input_bytes: usize,
    /// provider JSON 响应体上限。
    #[serde(default = "default_external_crypto_response_bytes")]
    pub max_response_bytes: usize,
}

/// PKCS#11 token 的模块、槽位与登录身份。
///
/// provider 只取得不可导出 private-key object handle 并执行签名，不读取私钥属性；module、token 和
/// key label 都由配置显式固定，避免自动选择主机上的其它 HSM。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Pkcs11CryptoProviderCfg {
    /// PKCS#11 共享库的绝对路径。
    pub module_path: String,
    /// 固定 slot id；与 `token_label` 必须恰好配置一项。
    #[serde(default)]
    pub slot_id: Option<u64>,
    /// 固定 token label；与 `slot_id` 必须恰好配置一项。
    #[serde(default)]
    pub token_label: String,
    /// User PIN 的本地 SecretSource；不得递归使用远程 provider。
    pub user_pin: String,
}

/// TLS 证书对不导出私钥 signer 的引用。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExternalPrivateKeyCfg {
    /// `crypto_providers[]` 中的 provider 名称。
    pub provider: String,
    /// provider 内固定 key identity；只用于请求，不进入日志。
    pub key_id: String,
    /// 该证书允许协商的 TLS signature scheme。
    pub algorithms: Vec<String>,
}

/// 业务作用：限制远程密码 operation 占用握手或后台任务的默认时长。
///
/// 参数说明: 无。
///
/// 返回：返回 3 秒。
pub(super) const fn default_external_crypto_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：限制单 provider 并行调用，防依赖变慢时耗尽连接与线程。
///
/// 参数说明: 无。
///
/// 返回：返回 8 个并发。
pub(super) const fn default_external_crypto_concurrency() -> usize {
    8
}

/// 业务作用：限制等待远程 signer 的 TLS 握手数量。
///
/// 参数说明: 无。
///
/// 返回：返回 64 项。
pub(super) const fn default_external_crypto_queue_capacity() -> usize {
    64
}

/// 业务作用：设置依赖连续失败后打开熔断器的默认门槛。
///
/// 参数说明: 无。
///
/// 返回：返回 5 次。
pub(super) const fn default_external_crypto_circuit_failures() -> u32 {
    5
}

/// 业务作用：限制 signer 依赖故障期间重复外呼的默认熔断窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 10 秒。
pub(super) const fn default_external_crypto_circuit_open_ms() -> u64 {
    10_000
}

/// 业务作用：限制送往外部密码 provider 的单次原始输入。
///
/// 参数说明: 无。
///
/// 返回：返回 64 KiB。
pub(super) const fn default_external_crypto_input_bytes() -> usize {
    64 * 1024
}

/// 业务作用：限制远程密码 provider 返回 JSON 的内存占用。
///
/// 参数说明: 无。
///
/// 返回：返回 64 KiB。
pub(super) const fn default_external_crypto_response_bytes() -> usize {
    64 * 1024
}

/// 固定 HTTPS JSON Secret provider 的连接、认证、响应契约与陈旧期策略。
///
/// provider 只返回 `{value, version, lease}` 语义，不参与业务路由；各云厂商或 Vault 可通过
/// 固定 endpoint、JSON Pointer、工作负载身份文件和 mTLS 映射到同一安全边界。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RemoteSecretProviderCfg {
    /// 全局唯一稳定名称，`remote://<provider>/<secret>` 通过该名称引用。
    pub name: String,
    /// 固定 HTTPS API 前缀；secret path 只作为逐段 percent-encoded 后缀追加。
    pub endpoint: String,
    /// provider API 适配器；默认使用可配置 JSON Pointer 的通用契约。
    #[serde(default)]
    pub adapter: RemoteSecretAdapterCfg,
    /// 发给 provider 的认证值 SecretSource；可指向轮换中的 workload identity 文件。
    #[serde(default)]
    pub authorization: String,
    /// 认证 header 名；默认 `authorization`，Vault 可使用 `x-vault-token`。
    #[serde(default = "default_remote_secret_authorization_header")]
    pub authorization_header: String,
    /// 认证值前缀；Bearer token 通常配置为 `Bearer `，空值表示直接使用 SecretSource 内容。
    #[serde(default)]
    pub authorization_prefix: String,
    /// 自定义 provider CA bundle 的 SecretSource；空值使用平台信任根。
    #[serde(default)]
    pub ca_certificate: String,
    /// provider mTLS 客户端证书 PEM SecretSource，必须与私钥同时配置。
    #[serde(default)]
    pub client_certificate: String,
    /// provider mTLS 客户端私钥 PEM SecretSource，必须与证书同时配置。
    #[serde(default)]
    pub client_private_key: String,
    /// 可选 envelope 解密计划；存在时 JSON `value` 必须是标准 Base64 ciphertext。
    #[serde(default)]
    pub envelope: Option<RemoteSecretEnvelopeCfg>,
    /// JSON 中 secret 字符串的 Pointer。
    #[serde(default = "default_remote_secret_value_pointer")]
    pub value_pointer: String,
    /// JSON 中单调 `u64` 版本的 Pointer；版本回退或同版异值拒绝候选。
    #[serde(default = "default_remote_secret_version_pointer")]
    pub version_pointer: String,
    /// JSON 中可选 lease 秒数的 Pointer；空值表示 provider 不提供 lease。
    #[serde(default)]
    pub lease_seconds_pointer: String,
    /// 后台重新拉取的目标间隔，必须短于最大陈旧期。
    #[serde(default = "default_remote_secret_refresh_interval_ms")]
    pub refresh_interval_ms: u64,
    /// 最近一次成功拉取的值可用于新请求的最长时间。
    #[serde(default = "default_remote_secret_max_stale_ms")]
    pub max_stale_ms: u64,
    /// TCP/TLS 建连 deadline。
    #[serde(default = "default_remote_secret_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// 单次完整 HTTP 请求 deadline。
    #[serde(default = "default_remote_secret_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// provider 响应体硬上限。
    #[serde(default = "default_remote_secret_response_bytes")]
    pub max_response_bytes: usize,
    /// 第一次依赖失败后的退避时长。
    #[serde(default = "default_remote_secret_retry_base_ms")]
    pub retry_base_ms: u64,
    /// 连续失败退避上限。
    #[serde(default = "default_remote_secret_retry_max_ms")]
    pub retry_max_ms: u64,
}

/// 远程 Secret provider 的原生 API 适配器。
///
/// 所有适配器复用同一套 HTTPS、并发、版本单调、lease、退避和 last-known-good 规则；这里只描述
/// 云 API 固有的认证或 wire 差异，不允许适配器改变数据面的 SecretSource 语义。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSecretAdapterCfg {
    /// 通过 `value_pointer`、`version_pointer` 和可选 `lease_seconds_pointer` 读取固定 JSON 契约。
    #[default]
    GenericJson,
    /// AWS Secrets Manager `GetSecretValue`，使用轮换中的容器凭据 JSON 执行 SigV4。
    AwsSecretsManager {
        /// SigV4 credential scope 中的固定 AWS region。
        region: String,
        /// AWS 容器凭据 JSON 的本地 SecretSource。
        credentials: String,
    },
    /// Azure Key Vault Secret REST API，OAuth Bearer 仍由 provider 的 `authorization` 提供。
    AzureKeyVault {
        /// 固定 Key Vault REST API 版本。
        #[serde(default = "default_azure_key_vault_api_version")]
        api_version: String,
    },
    /// Google Secret Manager `versions:access`，OAuth Bearer 仍由 provider 的 `authorization` 提供。
    GcpSecretManager,
}

/// 业务作用：固定 Azure Key Vault 的稳定 REST 契约版本，避免热换时跟随服务端默认值漂移。
///
/// 参数说明: 无。
///
/// 返回：返回受支持的 Key Vault API 版本。
pub(super) fn default_azure_key_vault_api_version() -> String {
    "7.5".to_owned()
}

/// 远程 Secret ciphertext 对不可导出 KEK 的引用。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RemoteSecretEnvelopeCfg {
    /// `crypto_providers[]` 中执行 decrypt 的 provider 名称。
    pub crypto_provider: String,
    /// provider 内固定 KEK identity；只进入受保护请求体，不进入日志。
    pub key_id: String,
    /// 额外 AAD 上下文；运行时还会强制绑定 Secret provider、路径和单调版本。
    #[serde(default)]
    pub aad_context: String,
}

/// 业务作用：提供远程 provider 默认认证 header，避免空名称进入 HTTP 构建期。
///
/// 参数说明: 无。
///
/// 返回：返回标准 `authorization` header 名。
pub(super) fn default_remote_secret_authorization_header() -> String {
    "authorization".to_owned()
}

/// 业务作用：固定远程 secret 值的默认 JSON Pointer 契约。
///
/// 参数说明: 无。
///
/// 返回：返回 `/value`。
pub(super) fn default_remote_secret_value_pointer() -> String {
    "/value".to_owned()
}

/// 业务作用：固定远程 secret 单调版本的默认 JSON Pointer 契约。
///
/// 参数说明: 无。
///
/// 返回：返回 `/version`。
pub(super) fn default_remote_secret_version_pointer() -> String {
    "/version".to_owned()
}

/// 业务作用：给远程 secret 后台刷新提供不产生高频控制面请求的默认周期。
///
/// 参数说明: 无。
///
/// 返回：返回 30 秒。
pub(super) const fn default_remote_secret_refresh_interval_ms() -> u64 {
    30_000
}

/// 业务作用：限制 provider 暂时不可用时旧 secret 可继续服务的默认窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 5 分钟。
pub(super) const fn default_remote_secret_max_stale_ms() -> u64 {
    300_000
}

/// 业务作用：固定远程 provider 建连默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 3 秒。
pub(super) const fn default_remote_secret_connect_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：固定远程 provider 完整请求默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 5 秒。
pub(super) const fn default_remote_secret_request_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：防错误 provider 返回大文档占用候选构建内存。
///
/// 参数说明: 无。
///
/// 返回：返回 64 KiB。
pub(super) const fn default_remote_secret_response_bytes() -> usize {
    64 * 1024
}

/// 业务作用：固定远程 provider 首次失败退避，避免立即重试放大故障。
///
/// 参数说明: 无。
///
/// 返回：返回 1 秒。
pub(super) const fn default_remote_secret_retry_base_ms() -> u64 {
    1_000
}

/// 业务作用：限制远程 provider 连续失败退避，仍给 lease 和陈旧期留出复验机会。
///
/// 参数说明: 无。
///
/// 返回：返回 30 秒。
pub(super) const fn default_remote_secret_retry_max_ms() -> u64 {
    30_000
}
