//! TLS 身份、证书签发、QUIC 与会话信任声明。

use super::*;

#[derive(Debug, Deserialize, Clone)]
/// 下游 TLS listener 的证书、mTLS 与可选 ACME 配置。
pub struct TlsCfg {
    /// TLS 数据面监听地址。
    pub listen: String,
    /// 【默认】证书链 PEM 文件路径(相对 gateway.yml 所在目录或绝对路径);SNI 不匹配 `certs[]` 时兜底用它。
    #[serde(default)]
    pub cert_file: String,
    /// 【默认】私钥 PEM 文件路径(相对 gateway.yml 所在目录或绝对路径)。
    #[serde(default)]
    pub key_file: String,
    /// 可选外部 TLS 签名身份；配置后 `key_file` 必须为空且私钥不会进入进程。
    #[serde(default)]
    pub private_key_provider: Option<ExternalPrivateKeyCfg>,
    /// 可选 SPIRE Workload API 身份；配置后服务端证书和私钥由本地 Agent 流式提供。
    #[serde(default)]
    pub spire: Option<SpireWorkloadCfg>,
    /// 可选 cert/key pair 原子指针 manifest（相对 gateway.yml 或绝对路径）。配置后，网关优先从
    /// manifest 指向的不可变版本目录加载 `cert.pem` + `key.pem`；manifest 尚不存在时兼容回退
    /// `cert_file`/`key_file`，便于从 seed 证书平滑迁移及 ACME 无 seed 首签。
    #[serde(default)]
    pub keypair_manifest_file: Option<String>,
    /// SNI 多证书:按 ClientHello 的 server_name 选证;不匹配则用上面的默认 cert/key 兜底。
    #[serde(default)]
    pub certs: Vec<SniCertCfg>,
    /// 双向 TLS(mTLS):校验客户端证书。缺省 None = 关闭(不要求客户端证书)。
    #[serde(default)]
    pub client_auth: Option<ClientAuthCfg>,
    /// 默认证书的服务端 OCSP staple；SNI 附加证书分别在各自条目声明。
    #[serde(default)]
    pub ocsp_stapling: Option<OcspStaplingCfg>,
    /// 可选共享 session ticket key 集；首项签发、全部项解密，支持跨节点重叠轮换与撤销。
    #[serde(default)]
    pub session_tickets: Option<SessionTicketCfg>,
    /// ACME 自动签发/续期；None 表示完全关闭并只使用静态 cert/key。
    #[serde(default)]
    pub acme: Option<AcmeCfg>,
}

/// HTTP/3/QUIC listener 配置。
///
/// 业务作用：为同一逻辑 TLS listener 声明 UDP/H3 transport 预算与安全策略；路由、过滤器和
/// 上游语义仍复用现有 proxy，不允许用该配置建立第二套路由模型。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Http3Cfg {
    /// 是否为 `tls.listen` 同端口绑定 QUIC/UDP。
    #[serde(default)]
    pub enabled: bool,
    /// QUIC 扩展能力声明：webtransport|connect_udp|datagram|early_data。
    ///
    /// 默认全部关闭；能力必须满足其依赖与资源门，关闭时不会创建相应会话或 DATAGRAM 缓冲。
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// 0-RTT 是否具备跨节点共享的 anti-replay 缓存。多节点集群启用 early_data 时必填。
    #[serde(default)]
    pub early_data_shared_replay_cache: bool,
    /// 本集群是否为多节点部署。用于判定 early_data 的重放防护是否成立。
    #[serde(default)]
    pub multi_node: bool,
    /// readiness 成功后是否在 TCP TLS 响应中发布 `Alt-Svc: h3=...`。
    #[serde(default = "default_true")]
    pub advertise_alt_svc: bool,
    /// Alt-Svc 广告缓存时间；关闭广告时保留但不发送。
    #[serde(default = "default_http3_alt_svc_max_age_seconds")]
    pub alt_svc_max_age_seconds: u32,
    /// QUIC connection 空闲超时；必须非零且不超过运行期统一上限。
    #[serde(default = "default_http3_max_idle_timeout_ms")]
    pub max_idle_timeout_ms: u64,
    /// 当前 proxy 的 QUIC 物理连接上限。
    #[serde(default = "default_http3_max_connections")]
    pub max_connections: usize,
    /// 单个握手来源 IP 允许占用的 QUIC 物理连接上限。
    #[serde(default = "default_http3_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// Quinn endpoint 同时保留的未决 Initial/handshake 数量。
    #[serde(default = "default_http3_max_pending_handshakes")]
    pub max_pending_handshakes: usize,
    /// 每条未决 handshake 在首包之外允许缓冲的 datagram 字节数。
    #[serde(default = "default_http3_max_pending_handshake_bytes")]
    pub max_pending_handshake_bytes: u64,
    /// 单 QUIC connection 允许的客户端双向 request stream 上限。
    #[serde(default = "default_http3_max_bidi_streams_per_connection")]
    pub max_bidi_streams_per_connection: u32,
    /// 单 QUIC connection 允许客户端打开的单向 stream 总上限；其中包含 H3
    /// control/QPACK stream，只有剩余名额可供 WebTransport 使用。
    #[serde(default = "default_http3_max_uni_streams_per_connection")]
    pub max_uni_streams_per_connection: u32,
    /// H3 解码后单次 header section 上限。
    #[serde(default = "default_http3_max_request_header_bytes")]
    pub max_request_header_bytes: usize,
    /// 单 request stream 在网关内允许暂存的 body/发送队列字节上限。
    #[serde(default = "default_http3_max_stream_buffer_bytes")]
    pub max_stream_buffer_bytes: usize,
    /// 单条 QUIC connection 同时存活的 CONNECT-UDP 会话上限。
    #[serde(default = "default_http3_max_connect_udp_sessions")]
    pub max_connect_udp_sessions: usize,
    /// 单个 CONNECT-UDP 会话等待处理的下行 DATAGRAM 数量上限；队列满时按不可靠语义丢弃。
    #[serde(default = "default_http3_max_datagram_queue")]
    pub max_datagram_queue: usize,
    /// CONNECT-UDP 单个 UDP payload 上限；不包含 Quarter Stream ID 与 Context ID。
    #[serde(default = "default_http3_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
    /// 地址验证 Retry 策略。
    #[serde(default)]
    pub retry: Http3RetryCfg,
    /// Retry token 最长有效期（秒）。
    #[serde(default = "default_http3_retry_token_lifetime_seconds")]
    pub retry_token_lifetime_seconds: u64,
    /// Retry token 认证主密钥轮换周期（秒）。
    #[serde(default = "default_http3_retry_token_rotation_seconds")]
    pub retry_token_rotation_seconds: u64,
    /// 是否在 TLS 层接受 0-RTT early data；必须同时声明 `early_data` capability
    /// 且至少一条 route 显式授权，默认关闭。
    #[serde(default)]
    pub zero_rtt: bool,
    /// 有状态 TLS 1.3 恢复代的最长轮换周期；新代发布后旧 session 不能再进入 0-RTT。
    #[serde(default = "default_http3_early_data_session_rotation_seconds")]
    pub early_data_session_rotation_seconds: u64,
}

impl Default for Http3Cfg {
    /// 业务作用：构造 `Http3Cfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            capabilities: Vec::new(),
            early_data_shared_replay_cache: false,
            multi_node: false,
            enabled: false,
            advertise_alt_svc: true,
            alt_svc_max_age_seconds: default_http3_alt_svc_max_age_seconds(),
            max_idle_timeout_ms: default_http3_max_idle_timeout_ms(),
            max_connections: default_http3_max_connections(),
            max_connections_per_ip: default_http3_max_connections_per_ip(),
            max_pending_handshakes: default_http3_max_pending_handshakes(),
            max_pending_handshake_bytes: default_http3_max_pending_handshake_bytes(),
            max_bidi_streams_per_connection: default_http3_max_bidi_streams_per_connection(),
            max_uni_streams_per_connection: default_http3_max_uni_streams_per_connection(),
            max_request_header_bytes: default_http3_max_request_header_bytes(),
            max_stream_buffer_bytes: default_http3_max_stream_buffer_bytes(),
            max_connect_udp_sessions: default_http3_max_connect_udp_sessions(),
            max_datagram_queue: default_http3_max_datagram_queue(),
            max_datagram_bytes: default_http3_max_datagram_bytes(),
            retry: Http3RetryCfg::default(),
            retry_token_lifetime_seconds: default_http3_retry_token_lifetime_seconds(),
            retry_token_rotation_seconds: default_http3_retry_token_rotation_seconds(),
            zero_rtt: false,
            early_data_session_rotation_seconds: default_http3_early_data_session_rotation_seconds(
            ),
        }
    }
}

/// QUIC Retry 地址验证策略。
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Http3RetryCfg {
    /// 不主动要求 Retry；仍受 QUIC anti-amplification 限制。
    Off,
    /// 由 listener 根据地址验证状态和压力决定，作为安全默认。
    #[default]
    Auto,
    /// 所有未验证地址先完成 Retry。
    Always,
}

/// 业务作用：为未显式声明的 `max_idle_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_idle_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `alt_svc_max_age_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_alt_svc_max_age_seconds() -> u32 {
    86_400
}

/// 业务作用：为未显式声明的 `max_connections` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_connections() -> usize {
    100_000
}

/// 业务作用：限制单连接可占用的 CONNECT-UDP socket 数，避免一个 QUIC peer 耗尽文件描述符。
///
/// 参数说明: 无。
///
/// 返回：返回默认会话上限 64。
pub(super) const fn default_http3_max_connect_udp_sessions() -> usize {
    64
}

/// 业务作用：为不可靠 DATAGRAM 提供小型突发吸收队列，同时保持丢包背压有界。
///
/// 参数说明: 无。
///
/// 返回：返回默认队列上限 128。
pub(super) const fn default_http3_max_datagram_queue() -> usize {
    128
}

/// 业务作用：给 CONNECT-UDP payload 设置保守默认值，使常见 QUIC path MTU 无需 IP 分片。
///
/// 参数说明: 无。
///
/// 返回：返回默认 payload 上限 1150 字节。
pub(super) const fn default_http3_max_datagram_bytes() -> usize {
    1_150
}

/// 业务作用：为未显式声明的 `max_connections_per_ip` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_connections_per_ip() -> usize {
    1024
}

/// 业务作用：为未显式声明的 `max_pending_handshakes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_pending_handshakes() -> usize {
    1024
}

/// 业务作用：为未显式声明的 `max_pending_handshake_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_pending_handshake_bytes() -> u64 {
    16 * 1024
}

/// 业务作用：为未显式声明的 `max_bidi_streams_per_connection` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_bidi_streams_per_connection() -> u32 {
    256
}

/// 业务作用：为 H3 控制流与 WebTransport 单向业务流预留共享的连接级容量。
///
/// 参数说明: 无。
///
/// 返回：返回 256 条客户端单向 stream 的默认硬上限。
pub(super) const fn default_http3_max_uni_streams_per_connection() -> u32 {
    256
}

/// 业务作用：为未显式声明的 `max_request_header_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_request_header_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `max_stream_buffer_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_max_stream_buffer_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `retry_token_lifetime_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_retry_token_lifetime_seconds() -> u64 {
    15
}

/// 业务作用：为未显式声明的 `retry_token_rotation_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_http3_retry_token_rotation_seconds() -> u64 {
    3600
}

/// 业务作用：限制可接受 early data 的 TLS 恢复状态存活代次，缩短泄漏 session 的风险窗口。
///
/// 参数说明: 无。
///
/// 返回：返回一小时的默认恢复代轮换周期。
pub(super) const fn default_http3_early_data_session_rotation_seconds() -> u64 {
    3600
}

/// ACME 自动证书配置。
///
/// 账户凭据与私钥只写权限收紧的文件，不进入日志/admin diff。多节点模式必须同时使用 Redis 锁和
/// 运维提供的共享文件卷，避免多节点重复下单或只更新单节点证书。
#[derive(Debug, Deserialize, Clone)]
pub struct AcmeCfg {
    /// 兼容旧配置：无 seed 证书时先启动明文 HTTP-01。现已支持同进程签发后激活 TLS；
    /// 新配置优先使用 `bootstrap_without_seed`。
    #[serde(default)]
    pub bootstrap_http01_only: bool,
    /// 允许 cert/key 不存在时启动；TLS 端口会先绑定但暂不 accept，签发落盘后在同一进程激活。
    #[serde(default)]
    pub bootstrap_without_seed: bool,
    /// ACME directory URL；默认 Let's Encrypt production。
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    /// ACME directory HTTPS 的可选自定义根 CA PEM。用于企业私有 CA/Pebble；不得把测试 CA
    /// 加入系统 trust store。为空时使用平台根证书。
    #[serde(default)]
    pub directory_ca_file: Option<String>,
    /// 证书覆盖的 DNS 名列表；HTTP-01 不允许通配符，DNS-01 支持 `*.example.com`。
    pub domains: Vec<String>,
    /// ACME account contact，例如 `mailto:ops@example.com`。
    #[serde(default)]
    pub contacts: Vec<String>,
    /// `http-01` 或 `dns-01`；其它值构建期拒绝，不能静默降级验证方式。
    #[serde(default = "default_acme_challenge")]
    pub challenge: String,
    /// DNS-01 provider；challenge=dns-01 时必填。提供有界 command provider，凭据由命令自己的
    /// env/file/K8s/Vault SecretSource 获取，网关不把 token 放入日志或 argv。
    #[serde(default)]
    pub dns01: Option<AcmeDns01Cfg>,
    /// ACME account credentials JSON 的 SecretSource 文件路径。
    #[serde(default = "default_acme_account_credentials_file")]
    pub account_credentials_file: String,
    /// 距证书到期不足多少天时续期。
    #[serde(default = "default_acme_renew_before_days")]
    pub renew_before_days: u64,
    /// 后台检查证书到期时间的间隔(ms)。
    #[serde(default = "default_acme_check_interval_ms")]
    pub check_interval_ms: u64,
    /// 签发失败后的退避(ms)，防止紧循环触发 CA rate limit。
    #[serde(default = "default_acme_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    /// 单个 order 从 challenge ready 到证书返回的最大轮询时间(ms)。
    #[serde(default = "default_acme_order_timeout_ms")]
    pub order_timeout_ms: u64,
    /// 无 seed 启动时轮询 cert/key 并激活已绑定 TLS listener 的间隔(ms)。
    #[serde(default = "default_acme_activation_poll_ms")]
    pub activation_poll_ms: u64,
    /// `local`（单节点进程锁）或 `redis`（多节点租约锁）。
    #[serde(default = "default_acme_lock_backend")]
    pub lock_backend: String,
    /// 分布式/本地锁业务 key；Redis 层会追加其配置前缀。
    #[serde(default = "default_acme_lock_key")]
    pub lock_key: String,
    /// `local-file` 或 `shared-file`；Redis 锁要求 shared-file。
    #[serde(default = "default_acme_storage_mode")]
    pub storage_mode: String,
    /// manifest 模式最多保留的完整 keypair 代数；当前指针与未完成原子发布可能引用的版本始终受保护。
    #[serde(default = "default_acme_keypair_retention_generations")]
    pub keypair_retention_generations: usize,
}

/// ACME DNS-01 provider 配置。
///
/// `command` 使用环境变量传递 action/name/value；内建 provider 的凭据只接受 SecretSource，
/// 构建期解析后不会进入日志、argv 或管理面输出。
#[derive(Debug, Deserialize, Clone)]
pub struct AcmeDns01Cfg {
    /// `command`、`cloudflare`、`rfc2136` 或 `vault`。
    #[serde(default = "default_acme_dns01_provider")]
    pub provider: String,
    /// provider 可执行文件路径；直接 exec，不经过 shell。
    #[serde(default)]
    pub command: String,
    /// 固定参数列表；challenge 值不会拼入参数。
    #[serde(default)]
    pub args: Vec<String>,
    /// provider 成功写入 TXT 后等待 DNS 传播的时间(ms)；本地 Pebble 可设 0。
    #[serde(default = "default_acme_dns01_propagation_delay_ms")]
    pub propagation_delay_ms: u64,
    /// present/cleanup 单次命令超时(ms)。
    #[serde(default = "default_acme_dns01_timeout_ms")]
    pub timeout_ms: u64,
    /// 网络 provider 的最大尝试次数，包含首次请求。
    #[serde(default = "default_acme_dns01_retry_attempts")]
    pub retry_attempts: usize,
    /// 可重试失败之间的固定退避；每次等待仍受单操作总 deadline 约束。
    #[serde(default = "default_acme_dns01_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    /// HTTP provider 单次响应体硬上限。
    #[serde(default = "default_acme_dns01_max_response_bytes")]
    pub max_response_bytes: usize,
    /// TXT TTL；RFC2136 与支持 TTL 的 HTTP provider 共用。
    #[serde(default = "default_acme_dns01_ttl_seconds")]
    pub ttl_seconds: u32,
    /// Cloudflare zone id；仅 `cloudflare` 使用。
    #[serde(default)]
    pub cloudflare_zone_id: String,
    /// Cloudflare API token SecretSource；仅 `cloudflare` 使用。
    #[serde(default)]
    pub cloudflare_api_token: String,
    /// Cloudflare API 根地址；默认官方 HTTPS API，主要用于私有兼容网关。
    #[serde(default = "default_acme_cloudflare_api_base")]
    pub cloudflare_api_base: String,
    /// RFC2136 权威 DNS TCP 地址，例如 `10.0.0.53:53`。
    #[serde(default)]
    pub rfc2136_server: String,
    /// RFC2136 UPDATE zone，例如 `example.com`。
    #[serde(default)]
    pub rfc2136_zone: String,
    /// RFC2136 TSIG key name。
    #[serde(default)]
    pub rfc2136_tsig_key_name: String,
    /// Base64 编码的 RFC2136 TSIG HMAC-SHA256 secret SecretSource。
    #[serde(default)]
    pub rfc2136_tsig_secret: String,
    /// Vault API 根地址；必须为 HTTPS。
    #[serde(default)]
    pub vault_endpoint: String,
    /// Vault token SecretSource。
    #[serde(default)]
    pub vault_token: String,
    /// Vault present 操作的相对 API path。
    #[serde(default)]
    pub vault_present_path: String,
    /// Vault cleanup 操作的相对 API path；cleanup 必须按 name/value 幂等删除。
    #[serde(default)]
    pub vault_cleanup_path: String,
    /// 可选 Vault namespace。
    #[serde(default)]
    pub vault_namespace: String,
}

/// mTLS 客户端证书校验配置。
#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthCfg {
    /// `require` 要求受信客户端证书；`optional` 允许无证书但校验已出示证书；
    /// `insecure_fallback` 请求任意证书但只校验私钥持有。默认 `require`。
    #[serde(default = "default_client_auth_mode")]
    pub mode: String,
    /// 受信任的客户端 CA 证书链 PEM 文件路径；SPIRE listener 使用动态 bundle 时留空。
    #[serde(default)]
    pub ca_file: String,
    /// 客户端证书 CRL PEM 文件列表；每个文件可包含多张 CRL。
    #[serde(default)]
    pub crl_files: Vec<String>,
    /// `off|hard_fail|soft_fail`；soft-fail 只放行 CRL 无法判定，明确 revoked 始终拒绝。
    #[serde(default = "default_client_revocation_mode")]
    pub revocation_mode: String,
    /// 是否把超过 CRL `nextUpdate` 的材料视为握手错误。
    #[serde(default = "default_true")]
    pub enforce_crl_expiration: bool,
    /// 可选客户端证书在线 OCSP 复验；在 TLS 链校验成功后、开放业务协议前执行。
    #[serde(default)]
    pub ocsp: Option<ClientCertificateOcspCfg>,
    /// 精确允许的 SPIFFE ID；非空时客户端叶证书必须只有一个 URI SAN 且命中列表。
    #[serde(default)]
    pub allowed_spiffe_ids: Vec<String>,
    /// 允许任意 workload path 的 SPIFFE trust domain；与精确 ID 列表取并集。
    #[serde(default)]
    pub allowed_spiffe_trust_domains: Vec<String>,
}

/// SPIRE Workload API 的 X.509-SVID 选择、资源上限与重连策略。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpireWorkloadCfg {
    /// SPIRE Agent Workload API Unix socket 的绝对路径。
    pub socket_path: String,
    /// 当前 listener 或上游客户端必须使用的精确 SPIFFE ID。
    pub spiffe_id: String,
    /// 多身份场景的可选精确 hint；为空时只按 SPIFFE ID 选择。
    #[serde(default)]
    pub hint: Option<String>,
    /// 明确允许导入的 federation trust domain；未列出的 foreign bundle 永不进入验证器。
    #[serde(default)]
    pub federation_trust_domains: Vec<String>,
    /// 建连和首响应的总 deadline。
    #[serde(default = "default_spire_timeout_ms")]
    pub timeout_ms: u64,
    /// 断流后最短重连退避。
    #[serde(default = "default_spire_reconnect_min_ms")]
    pub reconnect_min_ms: u64,
    /// 断流后最大重连退避。
    #[serde(default = "default_spire_reconnect_max_ms")]
    pub reconnect_max_ms: u64,
    /// 单次完整响应允许的证书、私钥、bundle 与 CRL 总字节上限。
    #[serde(default = "default_spire_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 新身份在发布时至少还需具备的有效时间，避免刚发布即到期。
    #[serde(default = "default_spire_min_validity_seconds")]
    pub min_validity_seconds: u64,
    /// 证书 notBefore 与本机时钟允许的最大偏差。
    #[serde(default = "default_spire_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
}

/// 客户端证书在线 OCSP 的依赖失败与缓存策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateOcspCfg {
    /// `hard_fail|soft_fail`；明确 revoked、unknown 或坏签名在两种模式下都拒绝。
    #[serde(default = "default_client_ocsp_mode")]
    pub mode: String,
    /// 单次 DNS、连接与响应读取的总 deadline。
    #[serde(default = "default_client_ocsp_timeout_ms")]
    pub timeout_ms: u64,
    /// soft-fail 最多可沿用已验证但刚过 freshness 的缓存时长；0 表示不沿用。
    #[serde(default)]
    pub max_stale_seconds: u64,
    /// 响应无 `nextUpdate` 时从 `thisUpdate` 起允许的最长年龄。
    #[serde(default = "default_ocsp_max_age_without_next_update_seconds")]
    pub max_age_without_next_update_seconds: u64,
    /// responder 与网关的允许时钟偏差。
    #[serde(default = "default_ocsp_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
    /// 单 listener 缓存的客户端证书状态上限。
    #[serde(default = "default_client_ocsp_cache_entries")]
    pub max_cache_entries: usize,
    /// 同一 listener 允许的并发 responder 请求数。
    #[serde(default = "default_client_ocsp_concurrency")]
    pub max_concurrency: usize,
    /// 客户端可控 AIA 访问私网 responder 的唯一 allowlist；空值仅允许公网地址。
    #[serde(default)]
    pub allowed_responder_cidrs: Vec<String>,
}

/// 业务作用：客户端证书在线吊销检查默认在 responder 不可用时故障关闭。
///
/// 参数说明: 无。
///
/// 返回：返回 `hard_fail`。
pub(super) fn default_client_ocsp_mode() -> String {
    "hard_fail".to_owned()
}

/// 业务作用：限制客户端握手后等待 OCSP responder 的总时长。
///
/// 参数说明: 无。
///
/// 返回：返回 3 秒。
pub(super) const fn default_client_ocsp_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：限制单 listener 客户端证书 OCSP 缓存的身份数量。
///
/// 参数说明: 无。
///
/// 返回：返回 4096 项。
pub(super) const fn default_client_ocsp_cache_entries() -> usize {
    4096
}

/// 业务作用：限制单 listener 因新客户端证书同时发起的 OCSP 请求。
///
/// 参数说明: 无。
///
/// 返回：返回 8 个并发。
pub(super) const fn default_client_ocsp_concurrency() -> usize {
    8
}

/// TLS session ticket 的共享密钥与有效期策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SessionTicketCfg {
    /// 按顺序排列的 Base64 32-byte SecretSource；首项签发，后续项只用于轮换重叠期解密。
    pub keys: Vec<String>,
    /// 发给客户端的 ticket lifetime hint，也是配置要求的最长轮换窗口。
    #[serde(default = "default_session_ticket_lifetime_seconds")]
    pub lifetime_seconds: u32,
}

/// 服务端证书 OCSP stapling 的本地材料与 freshness 策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OcspStaplingCfg {
    /// DER 编码的完整 OCSPResponse 文件；写入方必须以 rename 原子替换。
    pub response_file: String,
    /// 可选 issuer 证书 PEM；缺省时使用服务端证书链的第二张证书。
    #[serde(default)]
    pub issuer_file: Option<String>,
    /// `optional|required`；required 在材料缺失、无效或过期时拒绝握手。
    #[serde(default = "default_ocsp_stapling_mode")]
    pub mode: String,
    /// 响应没有 `nextUpdate` 时，从 `thisUpdate` 起允许的最长年龄。
    #[serde(default = "default_ocsp_max_age_without_next_update_seconds")]
    pub max_age_without_next_update_seconds: u64,
    /// 允许 responder 与网关时钟偏差的秒数。
    #[serde(default = "default_ocsp_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
    /// 是否从叶证书 AIA 的 OCSP responder 主动获取并原子预刷新 `response_file`。
    #[serde(default)]
    pub fetch_from_aia: bool,
    /// 开启主动获取时的固定刷新间隔；响应到期门禁不依赖刷新成功。
    #[serde(default = "default_ocsp_refresh_interval_seconds")]
    pub refresh_interval_seconds: u64,
    /// 单次 DNS、连接、响应读取共用的 deadline。
    #[serde(default = "default_ocsp_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// AIA responder 若位于私网，必须被这些精确 CIDR 显式授权；空值仅允许公网地址。
    #[serde(default)]
    pub allowed_responder_cidrs: Vec<String>,
}

/// 业务作用：为 OCSP stapling 选择允许启动但不覆盖证书 must-staple 的默认策略。
///
/// 参数说明: 无。
///
/// 返回：返回 `optional`；含 TLS Feature status_request 的证书仍会被强制提升为 required。
pub(super) fn default_ocsp_stapling_mode() -> String {
    "optional".to_owned()
}

/// 业务作用：限制没有 `nextUpdate` 的 OCSP 响应可被重放的最长窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 24 小时。
pub(super) const fn default_ocsp_max_age_without_next_update_seconds() -> u64 {
    24 * 60 * 60
}

/// 业务作用：为 OCSP responder 与网关的轻微时钟漂移提供有界容差。
///
/// 参数说明: 无。
///
/// 返回：返回 5 分钟。
pub(super) const fn default_ocsp_clock_skew_seconds() -> u64 {
    5 * 60
}

/// 业务作用：为主动 OCSP 获取提供早于常见 `nextUpdate` 的保守预刷新周期。
///
/// 参数说明: 无。
///
/// 返回：返回 1 小时。
pub(super) const fn default_ocsp_refresh_interval_seconds() -> u64 {
    60 * 60
}

/// 业务作用：限制单次 OCSP responder 交互占用后台任务的时间。
///
/// 参数说明: 无。
///
/// 返回：返回 5 秒。
pub(super) const fn default_ocsp_request_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：默认关闭客户端证书吊销检查，避免没有 CRL 时产生含糊的软失败语义。
///
/// 参数说明: 无。
///
/// 返回：返回 `off`。
pub(super) fn default_client_revocation_mode() -> String {
    "off".to_owned()
}

/// 业务作用：为显式启用的 session ticket 设置有界 lifetime hint。
///
/// 参数说明: 无。
///
/// 返回：返回 12 小时。
pub(super) const fn default_session_ticket_lifetime_seconds() -> u32 {
    12 * 60 * 60
}

/// 一组 SNI 证书:命中这些 server_name 的握手用这套 cert/key(对齐 nginx 多 `server{ssl_certificate}`)。
#[derive(Debug, Deserialize, Clone)]
pub struct SniCertCfg {
    /// 匹配的 server_name(SNI):精确(`api.foo.com`)或前缀通配(`*.foo.com`)。
    pub server_names: Vec<String>,
    /// 证书链 PEM 文件路径。
    pub cert_file: String,
    /// 私钥 PEM 文件路径。
    #[serde(default)]
    pub key_file: String,
    /// 该 SNI 身份的外部签名引用；配置后本地私钥路径必须为空。
    #[serde(default)]
    pub private_key_provider: Option<ExternalPrivateKeyCfg>,
    /// 该 SNI 证书专属的 OCSP staple；不能复用默认证书的响应。
    #[serde(default)]
    pub ocsp_stapling: Option<OcspStaplingCfg>,
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_spire_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：为未显式声明的 `reconnect_min_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_spire_reconnect_min_ms() -> u64 {
    100
}

/// 业务作用：为未显式声明的 `reconnect_max_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_spire_reconnect_max_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_spire_max_response_bytes() -> usize {
    8 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `min_validity_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_spire_min_validity_seconds() -> u64 {
    30
}

/// 业务作用：为未显式声明的 `clock_skew_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_spire_clock_skew_seconds() -> u64 {
    30
}

/// 业务作用：为未显式声明的 `mode` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_client_auth_mode() -> String {
    "require".to_string()
}

/// 业务作用：默认使用 Let's Encrypt production directory；测试应显式改成 staging/Pebble。
pub(super) fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

/// 业务作用：基础实现使用 HTTP-01。
pub(super) fn default_acme_challenge() -> String {
    "http-01".to_string()
}

/// 业务作用：默认账户 secret 与主配置同目录解析。
pub(super) fn default_acme_account_credentials_file() -> String {
    ".secrets/acme-account.json".to_string()
}

/// 业务作用：默认提前 30 天续期 90 天短证书。
pub(super) fn default_acme_renew_before_days() -> u64 {
    30
}

/// 业务作用：默认每 12 小时检查一次到期时间。
pub(super) fn default_acme_check_interval_ms() -> u64 {
    43_200_000
}

/// 业务作用：默认失败后 5 分钟再试，避免 CA/网络异常时热循环。
pub(super) fn default_acme_retry_backoff_ms() -> u64 {
    300_000
}

/// 业务作用：默认给单个 ACME order 两分钟完成验证与签发。
pub(super) fn default_acme_order_timeout_ms() -> u64 {
    120_000
}

/// 业务作用：默认每 250ms 检查一次 ACME 首签文件，兼顾激活延迟与空闲控制面成本。
pub(super) fn default_acme_activation_poll_ms() -> u64 {
    250
}

/// 业务作用：为未显式声明的 `provider` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_dns01_provider() -> String {
    "command".to_string()
}

/// 业务作用：公网 DNS 默认给 30 秒传播窗口；具体 provider/权威 DNS 可按实际缩短。
pub(super) fn default_acme_dns01_propagation_delay_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_dns01_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `retry_attempts` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_dns01_retry_attempts() -> usize {
    3
}

/// 业务作用：为未显式声明的 `retry_backoff_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_dns01_retry_backoff_ms() -> u64 {
    250
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_dns01_max_response_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `ttl_seconds` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_dns01_ttl_seconds() -> u32 {
    60
}

/// 业务作用：为未显式声明的 `cloudflare_api_base` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_cloudflare_api_base() -> String {
    "https://api.cloudflare.com/client/v4".to_string()
}

/// 业务作用：默认单节点本地锁；多节点必须显式选择 redis。
pub(super) fn default_acme_lock_backend() -> String {
    "local".to_string()
}

/// 业务作用：默认按域名集合共享一个 ACME leader 锁。
pub(super) fn default_acme_lock_key() -> String {
    "gateway:acme:renew".to_string()
}

/// 业务作用：默认本地 SecretSource 文件；多节点需显式声明 shared-file。
pub(super) fn default_acme_storage_mode() -> String {
    "local-file".to_string()
}

/// 业务作用：为未显式声明的 `keypair_retention_generations` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_acme_keypair_retention_generations() -> usize {
    3
}
