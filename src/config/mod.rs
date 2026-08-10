//! 配置加载编排 + 运行期不可变快照。
//!
//! `GatewaySnapshot` 是一次请求要读的全部配置的不可变快照,由 `ArcSwap` 原子换版(无感热更,架构规范 §7)。

pub mod bootstrap;
pub mod model;

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::Serialize;

use crate::access_log::AccessLogRuntime;
use crate::guard::InterfaceGuard;
use crate::net::{self, Cidr};
use crate::proxy_protocol::ProxyProtocolWriteVersion;
use crate::routing::Router;
use crate::tls::{build_upstream_tls_profile, UpstreamTlsProfile};
use crate::upstream::{DynamicUpstreamStore, UpstreamDirectory};
use crate::variable::VariablePlan;
use model::{
    AcmeCfg, AdminAction, AdminApprovalCfg, AdminCfg, AdminResource, AdminRole, AdminRolloutCfg,
    ConfigSourceCfg, ControlPlaneCfg, ControlPlaneModeCfg, DiscoveryCfg, GatewayConfig, GuardFile,
    Http3Cfg, ProxyCfg, ProxyProtocolCfg, ReusableSnippetCfg, RuntimeStateCfg, SentinelFile,
    ServerCfg, ServerLimitsCfg, SnippetsCfg, StreamCfg, TimeoutCfg, XdsResourceOwnerCfg,
    XdsStartupPolicyCfg,
};

/// 一次请求要读的全部配置的不可变快照(路由 + 接口守卫)。换版 = 造新的、`ArcSwap` 原子替换指针。
#[derive(Clone)]
pub struct GatewaySnapshot {
    /// 单调递增的成功配置版本。
    pub version: u64,
    /// **已上线**配置集指纹(P0-3 集群收敛判据)。与 admin `GET /api/config/current` 的 ETag
    /// 不同:那是"当前磁盘文件"的指纹(编辑基线),这里是"这份快照构建时读到的配置集"的指纹。
    /// 构建期算不出时为 None(不阻断上线,只让该节点在集群视图里显示为未知)。
    pub config_fingerprint: Option<u64>,
    /// 配置 schema 版本(§6),用于演进期迁移/告警。
    pub schema_version: u32,
    /// 主数据面监听地址；拓扑变化由 listener supervisor 在快照发布前 prepare 并在发布后换代。
    pub listen: String,
    /// 可选 TLS 数据面监听(明文/TLS 分 socket)。
    pub tls: Option<TlsRuntimeCfg>,
    /// 管理/观测面监听地址；变更时先绑定候选端口，发布后启动新代并优雅停收旧代。
    pub admin_listen: String,
    /// 是否在管理面暴露 `/metrics`。
    pub expose_metrics: bool,
    /// 管理面自身认证策略。随配置快照热更新,但不影响 admin listener 绑定。
    pub admin_auth: AdminAuthRuntimeCfg,
    /// 管理操作审计 bootstrap 计划；writer/client 在进程启动时创建。
    pub admin_audit: AdminAuditRuntimeCfg,
    /// 集群配置渐进发布策略；只由管理面状态机读取。
    pub admin_rollout: AdminRolloutCfg,
    /// 高危管理变更 maker-checker 策略；只由管理面待审批状态机读取。
    pub admin_approval: AdminApprovalCfg,
    /// 控制面候选 gateway.yml 请求体上限。
    pub admin_max_config_body_bytes: usize,
    /// Nacos 等发现后端配置。热路径不直接连接远端,只供 discovery manager reconcile。
    pub discovery: DiscoveryCfg,
    /// Kubernetes Ingress/Gateway API 路由源；只供后台 controller，不进入请求热路径。
    pub kubernetes_routes: model::KubernetesRouteSourceCfg,
    /// 统一配置来源。热路径不用它,只供 reload/config source worker 与 admin 展示。
    pub config_source: ConfigSourceCfg,
    /// xDS bootstrap 与资源域 owner；请求热路径不读取。
    pub control_plane: ControlPlaneCfg,
    /// 运行态共享后端配置。启动装配读取它创建 RateLimiter/DynamicStore 后端。
    pub runtime_state: RuntimeStateCfg,
    /// access log 运行参数。构建期已编译格式/条件表达式。
    pub access_log: AccessLogRuntime,
    /// OpenTelemetry bootstrap 配置。运行期 exporter 常驻，不在请求热路径重建。
    pub telemetry: model::TelemetryCfg,
    /// 热重载 worker 的有界队列/去抖参数；启动时固定，不进入数据面热路径。
    pub reload: model::ReloadCfg,
    /// WS/gRPC 长连接换版与宽限期策略。
    pub long_connections: model::LongConnectionCfg,
    /// 当前快照在构建期实际解析的文件型 SecretSource；reload watcher 据此独立轮换。
    pub secret_files: Arc<[PathBuf]>,
    /// 数据面资源上限,由 main/proxy 在真实执行点使用。
    pub limits: ServerLimitsCfg,
    /// 数据面超时与优雅停机预算。
    pub timeouts: TimeoutCfg,
    /// 旧版单入口兼容 router，指向第一个 proxy 的已编译路由表。
    pub router: Arc<Router>,
    /// 与路由快照同版的静态接口禁用规则。
    pub interface_guard: Arc<InterfaceGuard>,
    /// 已构建的静态/动态上游目录；实例快照内部用 `Arc` 共享。
    pub upstreams: Arc<UpstreamDirectory>,
    /// V2-B 多入口代理。旧 `server.listen + routes` 会兼容成一个 `default` proxy。
    pub proxies: Arc<Vec<ProxyRuntime>>,
    /// V3 L4 stream TCP listener 列表。
    pub stream_listeners: Arc<Vec<StreamRuntime>>,
    /// V7 开发者门户/API 目录；OpenAPI 文档和 operation 摘要均随快照原子换版。
    pub developer_portal: Arc<crate::developer_portal::DeveloperPortalRuntime>,
    /// 与 route 模板同版的变量执行计划；数据面和管理面路由推演共用同一语义。
    pub variables: Arc<VariablePlan>,
    /// gRPC 边缘模式集群中继计划；None = 未配置或显式单机，不绑定 relay 端口、不建 peer 连接。
    pub grpc_edge_cluster: Option<Arc<crate::grpc_edge::GrpcEdgeClusterPlan>>,
}

/// 管理面展示/干跑使用的快照摘要。
///
/// 字段保持低基数,避免把路由 id、服务名等高基数明细直接塞进 metrics 或默认响应。
#[derive(Clone, Serialize)]
pub struct GatewaySnapshotSummary {
    /// 配置快照版本。
    pub version: u64,
    /// 配置 schema 版本。
    pub schema_version: u32,
    /// 所有 proxy 下 route 总数。
    pub routes: usize,
    /// 静态接口守卫规则数。
    pub interface_rules: usize,
    /// 已声明上游服务数。
    pub upstream_services: usize,
    /// 数据面 HTTP proxy listener 数。
    pub proxies: usize,
    /// L4 stream listener 数。
    pub stream_listeners: usize,
    /// V8:启用 gRPC 边缘模式的 route 总数(0 = 纯 L7 透传)。
    pub grpc_edge_routes: usize,
    /// V8:是否配置了边缘集群中继面。
    pub grpc_edge_cluster: bool,
    /// 启用 descriptor 转码的 route 数；0 表示普通 native gRPC 零反射计划。
    pub grpc_transcoding_routes: usize,
    /// 所有 descriptor route 白名单内的 RPC 数，不暴露高基数 method 名称。
    pub grpc_transcoding_methods: usize,
}

/// 单个 TLS listener 的运行期配置；路径已相对主配置解析，域名等字符串已构建期规范化。
#[derive(Clone)]
pub struct TlsRuntimeCfg {
    /// TLS 数据面监听地址。
    pub listen: String,
    /// 默认证书(SNI 不匹配 `certs` 时兜底)。
    pub cert_file: PathBuf,
    /// 默认 PEM 私钥文件；ACME 成功后原子替换它。
    pub key_file: PathBuf,
    /// cert/key pair 的单一原子指针；存在时 TLS loader/watcher 只消费其指向的完整版本。
    pub keypair_manifest_file: Option<PathBuf>,
    /// SNI 多证书(§19):运行期已解析路径 + 小写化 server_names;空 = 只用默认 cert/key。
    pub certs: Vec<SniCertRuntime>,
    /// mTLS 客户端证书校验(§19);None = 不要求客户端证书。
    pub client_auth: Option<ClientAuthRuntime>,
    /// ACME 自动签发/续期策略；None 表示静态证书模式。
    pub acme: Option<AcmeRuntimeCfg>,
    /// SDS 下发且仅驻留内存的证书材料；存在时禁止回退到文件、manifest、SNI 文件或 ACME。
    pub in_memory: Option<Arc<InMemoryTlsMaterial>>,
}

/// SDS listener 使用的进程内 TLS 材料。
///
/// 该类型不实现 `Debug`/`Serialize`，避免私钥或 CA 被配置转储、日志和错误链意外输出。
#[derive(Clone, PartialEq, Eq)]
pub struct InMemoryTlsMaterial {
    /// PEM 证书链；只交给 rustls parser。
    pub certificate_chain: Arc<[u8]>,
    /// PEM 私钥；只交给 rustls parser。
    pub private_key: Arc<[u8]>,
    /// 可选 mTLS 客户端 CA PEM。
    pub client_ca: Option<Arc<[u8]>>,
    /// 存在客户端 CA 时，是否强制客户端出示合法证书。
    pub require_client_certificate: bool,
}

/// 构建期校验后的 HTTP/3/QUIC listener 计划。
///
/// 业务作用：把 feature 门、安全默认和资源硬上限固化进不可变快照，供 listener supervisor
/// prepare UDP endpoint；关闭态为零值计划，不创建 transport task。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Http3RuntimeCfg {
    /// 是否启用 HTTP/3 listener。
    pub enabled: bool,
    /// readiness 后是否发布 Alt-Svc。
    pub advertise_alt_svc: bool,
    /// 已在构建期编码的本 listener Alt-Svc；关闭广告时为 None。
    pub alt_svc_header: Option<http::HeaderValue>,
    /// QUIC connection idle timeout。
    pub max_idle_timeout_ms: u64,
    /// QUIC 物理连接上限。
    pub max_connections: usize,
    /// 单握手来源 IP 的 QUIC 物理连接上限。
    pub max_connections_per_ip: usize,
    /// endpoint 未决 Initial/handshake 数量上限。
    pub max_pending_handshakes: usize,
    /// 单条未决 handshake 的追加 datagram 缓冲上限。
    pub max_pending_handshake_bytes: u64,
    /// 单连接 request stream 上限。
    pub max_bidi_streams_per_connection: u32,
    /// H3 header section 上限。
    pub max_request_header_bytes: usize,
    /// 单 stream 内部 buffer/queue 字节上限。
    pub max_stream_buffer_bytes: usize,
    /// Retry 地址验证策略。
    pub retry: model::Http3RetryCfg,
    /// Retry token 有效期。
    pub retry_token_lifetime_seconds: u64,
    /// Retry token 认证主密钥轮换周期。
    pub retry_token_rotation_seconds: u64,
    /// 首版恒为 false；字段保留是为了显式拒绝危险配置。
    pub zero_rtt: bool,
}

/// 构建期校验并规范化后的 ACME worker 配置。
#[derive(Clone, PartialEq, Eq)]
pub struct AcmeRuntimeCfg {
    /// 允许无 seed 证书启动；TLS socket 先绑定，签发落盘后由同一进程激活。
    pub bootstrap_without_seed: bool,
    /// ACME directory URL（生产、staging 或 Pebble）。
    pub directory_url: String,
    /// ACME directory HTTPS 自定义根 CA；None 使用平台根证书。
    pub directory_ca_file: Option<PathBuf>,
    /// 已小写化、去尾点且去重的 DNS SAN 列表。
    pub domains: Arc<[String]>,
    /// ACME account contact 列表。
    pub contacts: Arc<[String]>,
    /// 构建期固定的 challenge 类型。
    pub challenge: AcmeChallenge,
    /// DNS-01 command provider；HTTP-01 时为空。
    pub dns01: Option<AcmeDns01RuntimeCfg>,
    /// account credentials JSON secret 文件。
    pub account_credentials_file: PathBuf,
    /// 到期前续期窗口（天）。
    pub renew_before_days: u64,
    /// 到期检查间隔(ms)。
    pub check_interval_ms: u64,
    /// 失败退避(ms)。
    pub retry_backoff_ms: u64,
    /// 单订单轮询上限(ms)。
    pub order_timeout_ms: u64,
    /// 首签 cert/key 落盘后的 TLS listener 激活轮询间隔(ms)。
    pub activation_poll_ms: u64,
    /// `local` 或 `redis`。
    pub lock_backend: String,
    /// 业务锁 key。
    pub lock_key: String,
    /// `local-file` 或 `shared-file`。
    pub storage_mode: String,
    /// manifest 模式保留的完整 keypair 代数。
    pub keypair_retention_generations: usize,
}

/// ACME challenge 类型；构建后 worker 不再解析字符串。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AcmeChallenge {
    /// 数据面精确 GET 临时响应。
    Http01,
    /// 通过外部 provider 写 `_acme-challenge` TXT。
    Dns01,
}

/// 构建期校验后的 DNS-01 provider。
#[derive(Clone, PartialEq, Eq)]
pub struct AcmeDns01RuntimeCfg {
    /// 已冻结 provider 类型和凭据；运行期不再读取 SecretSource。
    pub provider: AcmeDns01ProviderRuntime,
    /// present 成功后的 DNS 传播等待(ms)。
    pub propagation_delay_ms: u64,
    /// present/cleanup 单操作总 deadline(ms)。
    pub timeout_ms: u64,
    /// 包含首次调用的最大尝试次数。
    pub retry_attempts: usize,
    /// 重试退避(ms)。
    pub retry_backoff_ms: u64,
    /// HTTP 响应体硬上限。
    pub max_response_bytes: usize,
    /// TXT TTL。
    pub ttl_seconds: u32,
}

/// DNS-01 provider 的已解析运行计划；secret 字段不实现 Debug/Serialize。
#[derive(Clone, PartialEq, Eq)]
pub enum AcmeDns01ProviderRuntime {
    /// 直接 exec，不经 shell。
    Command {
        command: PathBuf,
        args: Arc<[String]>,
    },
    /// Cloudflare DNS Records API。
    Cloudflare {
        api_base: String,
        zone_id: String,
        api_token: String,
    },
    /// RFC2136 TCP UPDATE + HMAC-SHA256 TSIG。
    Rfc2136 {
        server: std::net::SocketAddr,
        zone: String,
        tsig_key_name: String,
        tsig_secret: Arc<[u8]>,
    },
    /// 固定 HTTPS Vault action endpoint。
    Vault {
        endpoint: String,
        token: String,
        namespace: Option<String>,
        present_path: String,
        cleanup_path: String,
    },
}

/// mTLS 运行期配置(§19)。
#[derive(Clone, PartialEq, Eq)]
pub struct ClientAuthRuntime {
    /// true = require(握手必须出示合法客户端证书);false = optional(出示才校验)。
    pub require: bool,
    /// true = 请求客户端证书但不按 CA 信任链拒绝，仍校验握手签名以证明私钥持有。
    pub allow_untrusted: bool,
    /// 受信任的客户端 CA PEM 路径。
    pub ca_file: PathBuf,
}

/// 一组 SNI 证书运行期配置(§19):命中这些 server_name 的握手用这套 cert/key。
#[derive(Clone, PartialEq, Eq)]
pub struct SniCertRuntime {
    /// 小写化的 server_name 列表(精确或 `*.foo.com` 通配)。
    pub server_names: Vec<String>,
    /// 该 SNI 集合对应的证书链 PEM。
    pub cert_file: PathBuf,
    /// 与证书匹配的 PEM 私钥。
    pub key_file: PathBuf,
}

#[derive(Clone)]
/// 代理协议运行期开关及可信来源。
pub struct ProxyProtocolRuntimeCfg {
    /// 是否接受 PROXY 协议。
    pub enabled: bool,
    /// 是否允许 v1 文本格式。
    pub allow_v1: bool,
    /// 是否允许 v2 二进制格式。
    pub allow_v2: bool,
    /// 可信前置直连对端网段:只有落在这里的对端才允许携带 PROXY 头(构建期已解析成 [`Cidr`],运行期零分配匹配)。
    pub accept_from: Arc<Vec<Cidr>>,
    /// 读取前置头的超时（毫秒）。
    pub timeout_ms: u64,
}

#[derive(Clone)]
/// 已完成校验、可直接驱动数据面的代理运行时快照。
pub struct ProxyRuntime {
    /// 稳定代理标识。
    pub id: String,
    /// 明文监听地址。
    pub listen: String,
    /// 是否在 `listen` 上启动明文 HTTP accept；LDS TLS listener 为 false，避免同一地址双绑。
    pub plain_enabled: bool,
    /// 可选 TLS 监听配置。
    pub tls: Option<TlsRuntimeCfg>,
    /// HTTP/3/QUIC listener 计划；启用时 UDP 端口复用 `tls.listen`。
    pub http3: Http3RuntimeCfg,
    /// 该代理允许的 SNI 名称。
    pub server_names: Arc<Vec<String>>,
    /// Gateway API 共享 HTTP/HTTPS socket 的逻辑 listener 选择表。
    pub gateway_listeners: Arc<Vec<GatewayListenerRuntime>>,
    /// PROXY 协议策略。
    pub proxy_protocol: ProxyProtocolRuntimeCfg,
    /// 可信前置代理网段(review L6 / §12):决定是否信任入站 XFF / traceparent。构建期预解析。
    pub trusted_proxies: Arc<Vec<Cidr>>,
    /// 请求及连接资源上限。
    pub limits: ServerLimitsCfg,
    /// 各阶段超时策略。
    pub timeouts: TimeoutCfg,
    /// HTTP→HTTPS 跳转(§19):Some 时,明文入口一律 3xx 跳到 TLS 端口。构建期从 tls.listen 端口派生。
    pub redirect_https: Option<RedirectHttps>,
    /// HSTS 头预编译值(§19):Some(如 `max-age=31536000`)时,TLS 响应带 Strict-Transport-Security。
    pub hsts_header: Option<http::HeaderValue>,
    /// 路由表快照。
    pub router: Arc<Router>,
}

/// 已规范化、可直接执行精确/通配优先级选择的 Gateway API HTTP/HTTPS listener。
#[derive(Clone)]
pub struct GatewayListenerRuntime {
    /// listener 稳定身份，用于比较 SNI 与 Host 是否落到同一权威边界。
    pub id: Arc<str>,
    /// 小写且去尾点的精确或最左通配 hostname；None 是兜底 listener。
    pub hostname: Option<Arc<str>>,
}

/// HTTP→HTTPS 跳转运行期(§19):明文入口收到请求即跳到本 proxy 的 TLS 端口。
#[derive(Clone)]
pub struct RedirectHttps {
    /// 跳转目标端口(取自本 proxy 的 TLS 监听端口)。
    pub to_port: u16,
    /// 跳转状态码(301 或 308)。
    pub status: u16,
}

/// 管理面运行期认证策略。
#[derive(Clone, PartialEq, Eq)]
pub struct AdminAuthRuntimeCfg {
    /// 是否启用认证。
    pub enabled: bool,
    /// 可选 Bearer token 期望值。
    pub bearer_token: Option<Vec<u8>>,
    /// 可选 Basic `user:password` 期望值。
    pub basic_expected: Option<Vec<u8>>,
    /// Basic challenge realm。
    pub realm: String,
    /// 是否允许 `/healthz` 匿名访问。
    pub allow_healthz_unauthenticated: bool,
    /// 是否允许本节点用自己的 admin 凭据抓取同集群其它节点的 `/metrics`。
    /// 默认 false——它让 admin 从"只被访问"变成"会主动外连",是攻击面的实质变化。
    pub allow_cluster_metrics_scrape: bool,
    /// 已规范化的浏览器管理面来源 allowlist（scheme + authority）。
    pub allowed_origins: Vec<String>,
    /// 是否启用 principal 级 RBAC；false 保持旧凭据全权兼容模式。
    pub rbac_enabled: bool,
    /// 已解析 SecretSource 并编译权限位图的主体表。
    pub principals: Arc<[AdminPrincipalRuntime]>,
}

/// 快照内的管理主体；每请求只扫描小型静态表并做常量时间凭据比较。
#[derive(Clone, PartialEq, Eq)]
pub struct AdminPrincipalRuntime {
    /// 审计稳定主体 id。
    pub id: Arc<str>,
    /// 可选 Bearer token 期望值。
    pub bearer_token: Option<Vec<u8>>,
    /// 可选 Basic `user:password` 期望值。
    pub basic_expected: Option<Vec<u8>>,
    /// `resource × action` 固定位图；授权检查不分配、不查 HashMap。
    permissions: u128,
}

/// 管理操作审计的已校验 bootstrap 计划。
#[derive(Clone, PartialEq, Eq)]
pub struct AdminAuditRuntimeCfg {
    /// 是否启用审计。
    pub enabled: bool,
    /// append-only 本地 spool 绝对/规范相对路径。
    pub file: PathBuf,
    /// HMAC key；只保存在快照/审计 worker，不写日志或响应。
    pub signing_key: Arc<str>,
    /// 可选外部持久 sink endpoint。
    pub endpoint: Option<Arc<str>>,
    /// 可选 Authorization header，已标记 sensitive。
    pub authorization: Option<http::HeaderValue>,
    /// 单次外部确认超时。
    pub timeout: std::time::Duration,
    /// 每条本地事件是否 sync_data。
    pub fsync: bool,
    /// 单条 canonical JSON 上限。
    pub max_record_bytes: usize,
    /// 管理查询的内存尾部窗口。
    pub history_limit: usize,
}

impl AdminAuditRuntimeCfg {
    /// 比较会占用进程级资源、因而只能重启切换的审计 bootstrap 配置。
    ///
    /// 审计关闭时，`file` 仍会基于各自配置目录解析为绝对路径，但没有文件被打开、密钥被
    /// 使用或 worker 被创建。把这些休眠字段纳入比较，会让 Nacos 物化目录天然不同的等价
    /// 配置被误判为 bootstrap 变化；因此只有 enabled 状态不同，或双方启用且资源配置不同，
    /// 才要求重启。
    pub(crate) fn same_bootstrap(&self, other: &Self) -> bool {
        self.enabled == other.enabled && (!self.enabled || self == other)
    }
}

impl AdminPrincipalRuntime {
    /// 判断主体是否拥有一项确切权限。
    ///
    /// # 参数
    /// - `resource`: API 所属固定资源域。
    /// - `action`: API 的风险动作；emergency-kill 不会被普通 write 隐式包含。
    pub fn allows(&self, resource: AdminResource, action: AdminAction) -> bool {
        self.permissions & permission_bit(resource, action) != 0
    }

    /// 返回只含授权位的 Copy 值，供请求身份脱离 ArcSwap guard；不会复制任何凭据字节。
    pub(crate) const fn permission_bits(&self) -> u128 {
        self.permissions
    }
}

/// L4 stream TCP listener 运行期配置。
#[derive(Clone)]
pub struct StreamRuntime {
    /// listener 唯一标识。
    pub id: String,
    /// 本地监听地址。
    pub listen: String,
    /// 构建期固定传输协议；协议决定 socket 类型，属于 listener 拓扑。
    pub protocol: StreamProtocolRuntime,
    /// TCP stream TLS 终止配置；证书由 accept loop 的 watcher 原子热换。
    pub tls: Option<TlsRuntimeCfg>,
    /// 下游 stream TLS 握手 deadline；0 仅表示未启用 TLS。
    pub tls_handshake_timeout_ms: u64,
    /// UDP 会话预算；TCP runtime 保留默认值但不读取。
    pub udp: StreamUdpRuntime,
    /// 兼容旧日志展示的默认上游 TCP 地址。
    pub upstream: String,
    /// TLS preread 配置。
    pub preread: StreamPrereadRuntime,
    /// 显式启用的 MQTT 协议治理计划；未开 feature 时该字段不进入制品。
    #[cfg(feature = "mqtt-governance")]
    pub mqtt: Option<Arc<crate::mqtt::MqttPolicy>>,
    /// 显式启用的 Kafka 协议治理计划；未开 feature 时该字段不进入制品。
    #[cfg(feature = "kafka-governance")]
    pub kafka: Option<Arc<crate::kafka::KafkaPolicy>>,
    /// stream route 列表。旧版单 upstream 会被编译成一条 default route。
    pub routes: Arc<Vec<StreamRouteRuntime>>,
    /// PROXY protocol v1/v2 解析策略。
    pub proxy_protocol: ProxyProtocolRuntimeCfg,
    /// 发往上游的 PROXY protocol 头策略。
    pub proxy_protocol_to_upstream: StreamProxyProtocolUpstreamRuntime,
    /// 上游连接超时(ms)。
    pub connect_timeout_ms: u64,
    /// 会话总超时(ms),0 表示不限制。
    pub timeout_ms: u64,
}

/// L4 stream preread 运行期配置。
#[derive(Clone)]
pub struct StreamPrereadRuntime {
    /// 是否启用 TLS ClientHello SNI preread。
    pub ssl_preread: bool,
    /// 是否解析 MQTT CONNECT client id。
    pub mqtt_connect: bool,
    /// preread 超时(ms)。
    pub timeout_ms: u64,
    /// preread 最大字节数。
    pub max_bytes: usize,
}

/// stream 发往上游的 PROXY protocol 头运行期配置。
#[derive(Clone)]
pub struct StreamProxyProtocolUpstreamRuntime {
    /// 是否向上游写 PROXY protocol 头。
    pub enabled: bool,
    /// 写出的 PROXY protocol 版本。
    pub version: ProxyProtocolWriteVersion,
}

/// L4 stream route 运行期配置。
#[derive(Clone)]
pub struct StreamRouteRuntime {
    /// route 唯一标识。
    pub id: String,
    /// SNI 精确值或 `*.` 前缀的 suffix wildcard，已小写化。
    pub sni: Option<String>,
    /// MQTT client id 精确匹配。
    pub mqtt_client_id: Option<String>,
    /// 是否默认路由。
    pub default: bool,
    /// 选中后是否终止下游 TLS；false 保持 ClientHello 及后续字节透传。
    pub terminate_tls: bool,
    /// 上游 TCP 地址。
    pub upstream: String,
    /// 按连接或 UDP session 选择的带权上游；空集合沿用单一 `upstream`。
    pub weighted_upstreams: Arc<[(String, u32)]>,
    /// 直连 stream 上游 TLS profile。`lb://` 路由在选实例后继承 service profile。
    pub upstream_tls: Option<UpstreamTlsProfile>,
}

/// 构建期固定的 L4 socket 协议。
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StreamProtocolRuntime {
    /// Ordered byte stream over TCP, optionally wrapped by downstream/upstream TLS.
    Tcp,
    /// Datagram proxy with a bounded per-peer session table.
    Udp,
}

/// 构建期校验后的 UDP session table 资源预算。
#[derive(Clone, Copy)]
pub struct StreamUdpRuntime {
    /// Milliseconds without a downstream datagram before a peer session is evicted.
    pub idle_timeout_ms: u64,
    /// Hard cap for simultaneously tracked downstream peers on this listener.
    pub max_sessions: usize,
    /// Per-session bounded response queue; full queues drop datagrams instead of blocking peers.
    pub queue_capacity: usize,
    /// Maximum accepted datagram size in either direction; larger datagrams are discarded.
    pub max_datagram_bytes: usize,
}

impl ProxyRuntime {
    /// 直连对端 `ip` 是否为可信前置代理(据此决定是否采信其转发的真实客户端 IP / trace,review L6)。
    /// PROXY protocol 已解析出 `real_peer` 的连接视为独立的可信来源,由调用方另行判定。
    pub fn is_trusted_peer(&self, ip: std::net::IpAddr) -> bool {
        net::any_contains(&self.trusted_proxies, ip)
    }
}

impl GatewaySnapshot {
    /// 按入口 id 找当前版本的 proxy 配置。
    pub fn proxy(&self, id: &str) -> Option<&ProxyRuntime> {
        self.proxies.iter().find(|proxy| proxy.id == id)
    }

    /// 生成当前快照的低基数摘要,供 Admin dry-run 和状态展示使用。
    pub fn summary(&self) -> GatewaySnapshotSummary {
        let (grpc_transcoding_routes, grpc_transcoding_methods) = self
            .proxies
            .iter()
            .map(|proxy| proxy.router.grpc_transcoding_summary())
            .fold((0, 0), |(routes, methods), current| {
                (routes + current.0, methods + current.1)
            });
        GatewaySnapshotSummary {
            version: self.version,
            schema_version: self.schema_version,
            routes: self.proxies.iter().map(|proxy| proxy.router.len()).sum(),
            interface_rules: self.interface_guard.rule_count(),
            upstream_services: self.upstreams.service_count(),
            proxies: self.proxies.len(),
            stream_listeners: self.stream_listeners.len(),
            grpc_edge_routes: self
                .proxies
                .iter()
                .map(|proxy| proxy.router.grpc_edge_route_count())
                .sum(),
            grpc_edge_cluster: self.grpc_edge_cluster.is_some(),
            grpc_transcoding_routes,
            grpc_transcoding_methods,
        }
    }

    /// 启动期已绑定的 listener 拓扑。热更时这些字段变更必须拒绝,避免快照与真实 socket 错位。
    pub fn listen_topology(&self) -> Vec<ProxyListenTopology> {
        self.proxies
            .iter()
            .map(|proxy| ProxyListenTopology {
                id: format!("proxy:{}", proxy.id),
                listen: proxy.listen.clone(),
                plain_enabled: proxy.plain_enabled,
                tls: proxy.tls.clone(),
                http3: proxy.http3.clone(),
                proxy_protocol_enabled: proxy.proxy_protocol.enabled,
                proxy_protocol_accept_from: proxy.proxy_protocol.accept_from.as_ref().clone(),
                proxy_protocol_allow_v1: proxy.proxy_protocol.allow_v1,
                proxy_protocol_allow_v2: proxy.proxy_protocol.allow_v2,
            })
            .chain(
                self.stream_listeners
                    .iter()
                    .map(|stream| ProxyListenTopology {
                        id: format!(
                            "stream:{}:{}",
                            stream.id,
                            match stream.protocol {
                                StreamProtocolRuntime::Tcp => "tcp",
                                StreamProtocolRuntime::Udp => "udp",
                            }
                        ),
                        listen: stream.listen.clone(),
                        plain_enabled: true,
                        tls: stream.tls.clone(),
                        http3: Http3RuntimeCfg::default(),
                        proxy_protocol_enabled: stream.proxy_protocol.enabled,
                        proxy_protocol_accept_from: stream
                            .proxy_protocol
                            .accept_from
                            .as_ref()
                            .clone(),
                        proxy_protocol_allow_v1: stream.proxy_protocol.allow_v1,
                        proxy_protocol_allow_v2: stream.proxy_protocol.allow_v2,
                    }),
            )
            .collect()
    }

    /// 业务作用：校验 service-mesh sidecar profile 的业务 listener 只绑定 loopback，
    /// 防止启动或热更把原本仅供本 Pod/主机访问的代理端口暴露到外部网络。
    ///
    /// 参数说明：无。
    ///
    /// 返回：所有 HTTP/TLS/HTTP3/L4 listener 都是 loopback 时成功，否则返回定位到 listener 的错误。
    pub fn validate_sidecar_listeners(&self) -> Result<()> {
        for topology in self.listen_topology() {
            validate_sidecar_listen(&topology.id, &topology.listen)?;
            if let Some(tls) = topology.tls.as_ref() {
                validate_sidecar_listen(&format!("{}:tls", topology.id), &tls.listen)?;
            }
        }
        Ok(())
    }
}

/// 业务作用：验证一个 sidecar 数据面 socket 地址不会监听非本机接口。
///
/// 参数说明：`listener_id` 用于错误定位；`listen` 是必须可解析为 `SocketAddr` 的监听地址。
///
/// 返回：地址是 IPv4/IPv6 loopback 时成功；解析失败或地址可被外部访问时失败。
fn validate_sidecar_listen(listener_id: &str, listen: &str) -> Result<()> {
    let address = listen.parse::<std::net::SocketAddr>().with_context(|| {
        format!("sidecar listener `{listener_id}` has invalid address `{listen}`")
    })?;
    anyhow::ensure!(
        address.ip().is_loopback(),
        "sidecar listener `{listener_id}` must bind loopback, got `{listen}`"
    );
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
/// 用于 reload 拓扑比较的监听摘要。
pub struct ProxyListenTopology {
    /// 代理标识。
    pub id: String,
    /// 明文监听地址。
    pub listen: String,
    /// 是否实际绑定明文 TCP socket。
    pub plain_enabled: bool,
    /// TLS 监听摘要。
    pub tls: Option<TlsRuntimeCfg>,
    /// HTTP/3/QUIC UDP listener 摘要；参与 prepare/publish 拓扑比较。
    pub http3: Http3RuntimeCfg,
    /// 是否启用 PROXY 协议。
    pub proxy_protocol_enabled: bool,
    /// 可信前置网段。
    pub proxy_protocol_accept_from: Vec<Cidr>,
    /// 是否允许 v1。
    pub proxy_protocol_allow_v1: bool,
    /// 是否允许 v2。
    pub proxy_protocol_allow_v2: bool,
}

impl PartialEq for TlsRuntimeCfg {
    fn eq(&self, other: &Self) -> bool {
        self.listen == other.listen
            && self.cert_file == other.cert_file
            && self.key_file == other.key_file
            && self.keypair_manifest_file == other.keypair_manifest_file
            && self.certs == other.certs
            && self.client_auth == other.client_auth
            && self.acme == other.acme
            && self.in_memory == other.in_memory
    }
}

impl Eq for TlsRuntimeCfg {}

/// 缺省 schema 版本:配置缺 `schema_version` / 写了 `0` 时按此处理。
/// 与 `SUPPORTED` 分开：未来 `SUPPORTED` 升到 2 后，缺省的老配置仍按 **v1** 走 v1→v2 迁移，
/// 而不是被误当成最新版绕过迁移逻辑。
const DEFAULT_SCHEMA_VERSION: u32 = 1;
/// 当前支持的最高配置 schema 版本。新增破坏性配置格式时 +1,并在 `resolve_schema_version` 里实现迁移/拒绝(§6)。
const SUPPORTED_SCHEMA_VERSION: u32 = 1;
/// reload 指纹单文件硬上限。它覆盖主配置、OpenAPI/schema、WASM 与 SecretSource 依赖；
/// 各构建器仍执行更严格的业务上限，这里先防 watcher 因敌意大文件产生无界分配。
const MAX_FINGERPRINT_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SNIPPET_IMPORTS: usize = 32;
/// 单个 snippet import 的硬上限，避免小引用图带入过大控制面文档。
const MAX_SNIPPET_FILE_BYTES: usize = 1024 * 1024;
const MAX_SNIPPET_DEFINITIONS: usize = 256;
const MAX_SNIPPET_FILTERS_PER_DEFINITION: usize = 128;
const MAX_EXPANDED_FILTERS_PER_ROUTE: usize = 512;
const MAX_EXPANDED_FILTER_BYTES_PER_ROUTE: usize = 1024 * 1024;
const MAX_SNIPPET_DEPTH: usize = 16;
/// 所有会进入 `Instant + Duration`、timer wheel 或后台 sleep 的通用运行期时长上限。
/// 一年已经覆盖连接/流/换版治理需求，同时拒绝 `u64::MAX` 一类会在不同平台触发时间溢出的配置。
const MAX_RUNTIME_DURATION_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

/// 读盘 + 解析 + 构建快照(事务化:任一步失败即整体 Err,调用方保留旧快照,§7.2)。
pub fn load_snapshot(cfg_path: &Path, version: u64) -> Result<GatewaySnapshot> {
    load_snapshot_with_dynamic(cfg_path, version, DynamicUpstreamStore::new())
}

/// 读取三份配置文件，并在同一个 build 事务中编译路由/安全规则/上游目录。
///
/// # 参数
/// - `cfg_path`: `gateway.yml` 路径，相对 guard/sentinel/TLS 文件都以其目录解析。
/// - `version`: 由唯一 reload worker 分配的候选版本。
/// - `dynamic_upstreams`: 常驻 Nacos 实例事实源，reload 时不得重建丢状态。
///
/// 返回：完整不可变候选快照；任一文件/语义校验失败返回 `Err`，调用方必须保留旧版。
pub fn load_snapshot_with_dynamic(
    cfg_path: &Path,
    version: u64,
    dynamic_upstreams: Arc<DynamicUpstreamStore>,
) -> Result<GatewaySnapshot> {
    let cfg = load_gateway_config(cfg_path)?;
    build_snapshot_from_config(cfg_path, version, dynamic_upstreams, cfg)
}

/// 从同目录临时候选文件构建 dry-run 快照，但所有相对依赖/profile 都继续以真实 gateway.yml 为基准。
///
/// # 参数
/// - `cfg_path`: 当前真实 gateway.yml；只作为相对依赖/profile 基准，绝不覆盖。
/// - `candidate_path`: 控制面以 create_new 写出的 bounded 临时候选文件。
/// - `version`: dry-run 候选版本。
pub fn load_candidate_snapshot(
    cfg_path: &Path,
    candidate_path: &Path,
    version: u64,
) -> Result<GatewaySnapshot> {
    preflight_config_file(candidate_path, "candidate gateway config")?;
    let dir = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = cfg_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("gateway");
    let profile_pattern = dir.join(format!("{stem}-{{profile}}"));
    let mut cfg: GatewayConfig = nasa::yml::YmlLoader::standard()
        .base_file(candidate_path)
        .profile_file_pattern(profile_pattern.to_string_lossy().to_string())
        .load()
        .with_context(|| format!("load candidate config {}", candidate_path.display()))?;
    expand_config_snippets(&mut cfg, cfg_path, candidate_path)?;
    build_snapshot_from_config(cfg_path, version, DynamicUpstreamStore::new(), cfg)
}

/// 把已解析的主配置与真实同目录 guard/sentinel/secret 编译成不可变快照。
///
/// # 参数
/// - `cfg_path`: 真实 gateway.yml 路径，用作所有相对文件基准。
/// - `version`: 候选快照版本。
/// - `dynamic_upstreams`: 常驻或 dry-run 临时的动态实例事实源。
/// - `cfg`: 已由 nasa::yml 完成 profile/env/占位符解析的主配置。
fn build_snapshot_from_config(
    cfg_path: &Path,
    version: u64,
    dynamic_upstreams: Arc<DynamicUpstreamStore>,
    mut cfg: GatewayConfig,
) -> Result<GatewaySnapshot> {
    let schema_version = resolve_schema_version(cfg.schema_version, "gateway.yml")?;
    let config_dir = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    crate::kubernetes_routes::apply_generated_routes(&mut cfg, config_dir)
        .context("merge Kubernetes generated routes")?;
    let developer_portal =
        crate::developer_portal::DeveloperPortalRuntime::build_and_apply(&mut cfg, config_dir)
            .context("build developer portal and generated OpenAPI routes")?;
    validate_control_plane(&mut cfg.control_plane, &cfg.upstreams, config_dir)
        .context("validate control_plane.xds bootstrap")?;
    validate_xds_owned_native_domains(&cfg)
        .context("validate control_plane.xds native domain isolation")?;
    let secret_files = collect_secret_dependencies(&cfg, config_dir);
    let admin_auth = build_admin_auth(&cfg.admin, config_dir).context("build admin auth/RBAC")?;
    let admin_audit = build_admin_audit(&cfg.admin, config_dir).context("build admin audit")?;
    validate_admin_rollout(
        &cfg.admin.rollout,
        &cfg.config_source,
        &cfg.discovery,
        &admin_auth,
        &admin_audit,
    )
    .context("validate admin rollout")?;
    validate_admin_approval(&cfg.admin.approval, &admin_auth, &admin_audit)
        .context("validate admin approval")?;
    anyhow::ensure!(
        (1024..=16 * 1024 * 1024).contains(&cfg.admin.max_config_body_bytes),
        "admin.max_config_body_bytes must be within 1024..=16777216"
    );
    validate_optional_duration(
        "reload.debounce_ms",
        cfg.reload.debounce_ms,
        MAX_RUNTIME_DURATION_MS,
    )?;
    validate_optional_duration(
        "long_connections.drain_grace_ms",
        cfg.long_connections.drain_grace_ms,
        MAX_RUNTIME_DURATION_MS,
    )?;
    validate_admin_exposure(&cfg.admin.listen, &admin_auth)?;
    let access_log =
        AccessLogRuntime::build(&cfg.access_log, config_dir).context("build access log")?;
    crate::telemetry::validate_config(&cfg.telemetry).context("validate telemetry")?;
    let guard = load_interface_guard(cfg_path, &cfg.interface_guard_file)?;
    let sentinel = load_sentinel_rules(cfg_path, &cfg.sentinel_rules_file)?;
    let variables = VariablePlan::build(&cfg.variables).context("build variables")?;
    let usage_plans =
        crate::routing::UsagePlanCatalog::build(&cfg.usage_plans).context("build usage plans")?;
    let xds_listener_owned = cfg.control_plane.xds.enabled
        && cfg.control_plane.xds.ownership.listeners == XdsResourceOwnerCfg::Xds;
    let (proxies, bootstrap_router, bootstrap_limits, bootstrap_timeouts) = if xds_listener_owned {
        // LDS 拥有 listener 时 bootstrap 只保留治理默认值，绝不能先绑定一份 native 业务入口；
        // 首个完整 LDS/RDS/CDS/EDS/SDS 闭包会经 listener two-phase transaction 激活 socket。
        sentinel.ensure_all_matched(&HashSet::new())?;
        let router =
            Router::build_with_usage_plans(&[], variables.clone(), config_dir, usage_plans.clone())
                .context("build empty xDS bootstrap router")?;
        (
            Vec::new(),
            Arc::new(router),
            ServerLimitsCfg::default(),
            TimeoutCfg::default(),
        )
    } else {
        let proxies = build_proxies(cfg_path, &cfg, &sentinel, variables.clone(), usage_plans)
            .context("build proxies")?;
        let default_proxy = proxies
            .first()
            .cloned()
            .context("gateway must have at least one proxy listener")?;
        (
            proxies,
            default_proxy.router,
            default_proxy.limits,
            default_proxy.timeouts,
        )
    };
    crate::http_cache::validate_runtime_config(&cfg.runtime_state.http_cache)
        .context("validate runtime_state.http_cache")?;
    if proxies
        .iter()
        .any(|proxy| proxy.router.uses_http_cache_l2())
        && !cfg
            .runtime_state
            .http_cache
            .backend
            .trim()
            .eq_ignore_ascii_case("redis")
    {
        bail!("proxy_cache l2=true requires runtime_state.http_cache.backend=redis");
    }
    if proxies.iter().any(|proxy| proxy.router.uses_llm_cache_l2())
        && !cfg
            .runtime_state
            .http_cache
            .backend
            .trim()
            .eq_ignore_ascii_case("redis")
    {
        bail!("llm.semantic_cache l2=true requires runtime_state.http_cache.backend=redis");
    }
    let stream_listeners =
        build_stream_listeners(&cfg.stream, cfg_path).context("build stream listeners")?;
    let upstreams = UpstreamDirectory::build_with_dynamic_at_discovery(
        &cfg.upstreams,
        dynamic_upstreams,
        &cfg.discovery,
        cfg_path,
    )
    .context("build upstream directory")?;
    // V8 边缘集群中继:值校验 + feature 门都在构建期完成,坏配置保留旧快照。
    // 必须在 cfg.discovery 被 move 前读取 nacos 启用位。
    let nacos_enabled = cfg.discovery.nacos.enabled;
    let grpc_edge_cluster = crate::grpc_edge::GrpcEdgeClusterPlan::build(
        cfg.grpc_edge_cluster.as_ref(),
        nacos_enabled,
        config_dir,
    )
    .context("build grpc_edge_cluster")?
    .map(Arc::new);
    let discovery = crate::discovery::build_runtime_config(cfg.discovery, config_dir)
        .context("build discovery runtime config")?;
    Ok(GatewaySnapshot {
        version,
        // 指纹覆盖主配置及其依赖;失败不阻断上线(集群视图显示未知即可)。
        config_fingerprint: config_fingerprint(cfg_path).ok(),
        schema_version,
        listen: proxies
            .first()
            .map(|proxy| proxy.listen.clone())
            .unwrap_or_else(|| "0.0.0.0:0".to_owned()),
        tls: proxies.first().and_then(|proxy| proxy.tls.clone()),
        admin_listen: cfg.admin.listen,
        expose_metrics: cfg.admin.expose_metrics,
        admin_auth,
        admin_audit,
        admin_rollout: cfg.admin.rollout,
        admin_approval: cfg.admin.approval,
        admin_max_config_body_bytes: cfg.admin.max_config_body_bytes,
        discovery,
        kubernetes_routes: cfg.kubernetes_routes,
        config_source: cfg.config_source,
        control_plane: cfg.control_plane,
        runtime_state: cfg.runtime_state,
        access_log,
        telemetry: cfg.telemetry,
        reload: cfg.reload,
        long_connections: cfg.long_connections,
        secret_files: secret_files.into(),
        limits: bootstrap_limits,
        timeouts: bootstrap_timeouts,
        router: bootstrap_router,
        interface_guard: Arc::new(guard),
        upstreams: Arc::new(upstreams),
        proxies: Arc::new(proxies),
        stream_listeners: Arc::new(stream_listeners),
        developer_portal,
        variables,
        grpc_edge_cluster,
    })
}

/// 业务作用：在任何 ADS socket/task 创建前锁定本地 trust root、Node identity、资源预算与
/// 单一 owner，避免未编 feature、明文远端或 native/xDS 双写进入运行期。
///
/// 参数说明：`control_plane` 是待规范化的 bootstrap；`upstreams` 用于核对 `source: xds`；
/// `config_dir` 是证书文件的相对路径基准。
///
/// 返回：合法配置原地规范化文件路径并返回成功；任何越权、未支持阶段或资源风险均 fail closed。
fn validate_control_plane(
    control_plane: &mut ControlPlaneCfg,
    upstreams: &model::UpstreamsCfg,
    config_dir: &Path,
) -> Result<()> {
    let xds = &mut control_plane.xds;
    let owners = &xds.ownership;
    let all_native = [
        owners.listeners,
        owners.routes,
        owners.clusters,
        owners.endpoints,
        owners.secrets,
    ]
    .into_iter()
    .all(|owner| owner == XdsResourceOwnerCfg::Native);

    if !xds.enabled {
        anyhow::ensure!(
            control_plane.mode == ControlPlaneModeCfg::Native,
            "control_plane.mode must be native when control_plane.xds.enabled=false"
        );
        anyhow::ensure!(
            all_native,
            "control_plane.xds ownership must remain native while xDS is disabled"
        );
        anyhow::ensure!(
            !upstreams.services.values().any(|service| {
                service
                    .source
                    .as_deref()
                    .is_some_and(|source| source.eq_ignore_ascii_case("xds"))
            }),
            "upstream source xds requires control_plane.xds.enabled=true"
        );
        return Ok(());
    }

    anyhow::ensure!(
        cfg!(feature = "xds-client"),
        "control_plane.xds.enabled=true requires the `xds-client` feature"
    );
    anyhow::ensure!(
        matches!(
            control_plane.mode,
            ControlPlaneModeCfg::Hybrid | ControlPlaneModeCfg::Xds
        ),
        "enabled xDS requires control_plane.mode=hybrid|xds"
    );
    anyhow::ensure!(
        xds.startup_policy == XdsStartupPolicyCfg::RequireXds,
        "control_plane.xds.startup_policy=signed_last_good is not supported"
    );
    let eds_only = owners.listeners == XdsResourceOwnerCfg::Native
        && owners.routes == XdsResourceOwnerCfg::Native
        && owners.clusters == XdsResourceOwnerCfg::Native
        && owners.endpoints == XdsResourceOwnerCfg::Xds
        && owners.secrets == XdsResourceOwnerCfg::Native;
    let cds_rds = owners.listeners == XdsResourceOwnerCfg::Native
        && owners.routes == XdsResourceOwnerCfg::Xds
        && owners.clusters == XdsResourceOwnerCfg::Xds
        && owners.endpoints == XdsResourceOwnerCfg::Xds
        && owners.secrets == XdsResourceOwnerCfg::Native;
    let full_xds = owners.listeners == XdsResourceOwnerCfg::Xds
        && owners.routes == XdsResourceOwnerCfg::Xds
        && owners.clusters == XdsResourceOwnerCfg::Xds
        && owners.endpoints == XdsResourceOwnerCfg::Xds
        && owners.secrets == XdsResourceOwnerCfg::Xds;
    anyhow::ensure!(
        eds_only || cds_rds || full_xds,
        "xDS ownership must select EDS-only, native-listener policy, or the atomic LDS/RDS/CDS/EDS/SDS profile"
    );
    if full_xds {
        anyhow::ensure!(
            control_plane.mode == ControlPlaneModeCfg::Xds,
            "full LDS/RDS/CDS/EDS/SDS ownership requires control_plane.mode=xds"
        );
    } else {
        anyhow::ensure!(
            control_plane.mode == ControlPlaneModeCfg::Hybrid,
            "partial xDS ownership requires control_plane.mode=hybrid"
        );
    }

    let server = reqwest::Url::parse(xds.server.trim())
        .context("control_plane.xds.server must be an absolute http(s) URI")?;
    anyhow::ensure!(
        matches!(server.scheme(), "http" | "https") && server.host_str().is_some(),
        "control_plane.xds.server must use http or https with an authority"
    );
    anyhow::ensure!(
        server.username().is_empty() && server.password().is_none(),
        "control_plane.xds.server must not embed credentials"
    );
    anyhow::ensure!(
        server.path() == "/" && server.query().is_none() && server.fragment().is_none(),
        "control_plane.xds.server must contain only scheme and authority"
    );
    let loopback = xds_server_is_loopback(&server);
    if server.scheme() == "http" {
        anyhow::ensure!(
            loopback,
            "plaintext xDS is allowed only for a loopback management server"
        );
        anyhow::ensure!(
            xds.tls.ca.file.trim().is_empty()
                && xds.tls.cert.file.trim().is_empty()
                && xds.tls.key.file.trim().is_empty()
                && xds.tls.server_name.trim().is_empty(),
            "control_plane.xds.tls must be empty for loopback plaintext xDS"
        );
    } else {
        anyhow::ensure!(
            !xds.tls.server_name.trim().is_empty(),
            "control_plane.xds.tls.server_name is required for HTTPS xDS"
        );
        validate_xds_identity(&xds.tls.server_name, "control_plane.xds.tls.server_name")?;
        xds.tls.ca.file = normalize_xds_pem_file(
            &xds.tls.ca.file,
            config_dir,
            "control_plane.xds.tls.ca.file",
        )?;
        xds.tls.cert.file = normalize_xds_pem_file(
            &xds.tls.cert.file,
            config_dir,
            "control_plane.xds.tls.cert.file",
        )?;
        xds.tls.key.file = normalize_xds_pem_file(
            &xds.tls.key.file,
            config_dir,
            "control_plane.xds.tls.key.file",
        )?;
    }
    xds.server = xds.server.trim_end_matches('/').to_owned();

    validate_xds_identity(&xds.node.id, "control_plane.xds.node.id")?;
    validate_xds_identity(&xds.node.cluster, "control_plane.xds.node.cluster")?;
    const METADATA_KEYS: &[&str] = &["region", "zone", "network", "namespace"];
    anyhow::ensure!(
        xds.node.metadata.len() <= METADATA_KEYS.len(),
        "control_plane.xds.node.metadata exceeds the fixed allowlist"
    );
    for (key, value) in &xds.node.metadata {
        anyhow::ensure!(
            METADATA_KEYS.contains(&key.as_str()),
            "control_plane.xds.node.metadata key `{key}` is not allowed"
        );
        validate_xds_identity(value, &format!("control_plane.xds.node.metadata.{key}"))?;
    }

    let initial_backoff = parse_xds_duration_ms(
        &xds.reconnect.initial_backoff,
        "control_plane.xds.reconnect.initial_backoff",
    )?;
    let max_backoff = parse_xds_duration_ms(
        &xds.reconnect.max_backoff,
        "control_plane.xds.reconnect.max_backoff",
    )?;
    anyhow::ensure!(
        (10..=60_000).contains(&initial_backoff) && max_backoff >= initial_backoff,
        "control_plane.xds reconnect backoff must be 10..=60000ms and max >= initial"
    );
    anyhow::ensure!(
        xds.reconnect.jitter.is_finite() && (0.0..=1.0).contains(&xds.reconnect.jitter),
        "control_plane.xds.reconnect.jitter must be finite within 0..=1"
    );
    let keepalive_interval = parse_xds_duration_ms(
        &xds.keepalive.interval,
        "control_plane.xds.keepalive.interval",
    )?;
    let keepalive_timeout = parse_xds_duration_ms(
        &xds.keepalive.timeout,
        "control_plane.xds.keepalive.timeout",
    )?;
    anyhow::ensure!(
        (1_000..=3_600_000).contains(&keepalive_interval)
            && (100..=60_000).contains(&keepalive_timeout)
            && keepalive_timeout < keepalive_interval,
        "control_plane.xds keepalive must use interval 1s..=1h and timeout 100ms..60s below interval"
    );
    let warming_timeout = parse_xds_duration_ms(
        &xds.limits.warming_timeout,
        "control_plane.xds.limits.warming_timeout",
    )?;
    anyhow::ensure!(
        (100..=3_600_000).contains(&warming_timeout),
        "control_plane.xds.limits.warming_timeout must be within 100ms..=1h"
    );
    anyhow::ensure!(
        (1024..=64 * 1024 * 1024).contains(&xds.limits.max_response_bytes),
        "control_plane.xds.limits.max_response_bytes must be within 1024..=67108864"
    );
    anyhow::ensure!(
        (1..=100_000).contains(&xds.limits.max_resources_per_type),
        "control_plane.xds.limits.max_resources_per_type must be within 1..=100000"
    );
    anyhow::ensure!(
        (1..=4 * 1024 * 1024).contains(&xds.limits.max_resource_bytes)
            && xds.limits.max_resource_bytes <= xds.limits.max_response_bytes,
        "control_plane.xds.limits.max_resource_bytes must fit within response bytes and be <=4194304"
    );
    anyhow::ensure!(
        (1..=100_000).contains(&xds.limits.max_warming_resources),
        "control_plane.xds.limits.max_warming_resources must be within 1..=100000"
    );
    anyhow::ensure!(
        (1..=1024).contains(&xds.limits.max_apply_queue),
        "control_plane.xds.limits.max_apply_queue must be within 1..=1024"
    );

    let mut xds_services = 0usize;
    for (logical_service, service) in &upstreams.services {
        let source = service.source.as_deref().unwrap_or("static");
        if !source.eq_ignore_ascii_case("xds") {
            continue;
        }
        xds_services = xds_services.saturating_add(1);
        anyhow::ensure!(
            service.instances.is_empty(),
            "xDS-owned service `{logical_service}` must not declare native instances"
        );
        if let Some(cluster) = service.registry_service.as_deref() {
            validate_xds_identity(cluster, "upstreams.services[].registry_service")?;
        }
    }
    if eds_only {
        anyhow::ensure!(
            xds_services > 0,
            "xDS endpoint ownership requires at least one upstream service with source: xds"
        );
    } else {
        anyhow::ensure!(
            xds_services == 0,
            "xDS CDS ownership derives services dynamically; native upstream declarations are forbidden"
        );
    }
    Ok(())
}

/// 业务作用：在构建路由/上游前复验 xDS owner 域没有 native 影子声明，阻止双写或 reload 覆盖。
///
/// 参数说明：`cfg` 已完成 generated routes 合并与 xDS bootstrap 校验。
///
/// 返回：CDS/RDS profile 的 native routes/upstreams 全空时成功；任何影子声明都拒绝整份快照。
fn validate_xds_owned_native_domains(cfg: &GatewayConfig) -> Result<()> {
    if !cfg.control_plane.xds.enabled
        || cfg.control_plane.xds.ownership.routes != XdsResourceOwnerCfg::Xds
    {
        return Ok(());
    }
    // routes/clusters/endpoints 必须作为一个原子依赖闭包交给 xDS；留下任一 native 声明都会
    // 让两个控制面在同一 Snapshot 上竞争，造成 ACK 与真实数据面版本不一致。
    anyhow::ensure!(
        cfg.routes.is_empty()
            && cfg.proxies.iter().all(|proxy| proxy.routes.is_empty())
            && cfg.upstreams.services.is_empty(),
        "xDS-owned routes/clusters require empty native routes and upstreams.services"
    );
    if cfg.control_plane.xds.ownership.listeners == XdsResourceOwnerCfg::Xds {
        // LDS 是整个业务 socket 域的唯一 owner；即使 native listener 没有 route，也不能把它
        // 当作“模板”留下，否则启动期 bind 会早于 xDS 依赖闭包并形成脏路由窗口。
        anyhow::ensure!(
            cfg.server.is_none() && cfg.proxies.is_empty() && cfg.stream.listeners.is_empty(),
            "xDS-owned listeners require empty native server/proxies/stream listeners"
        );
    }
    Ok(())
}

/// 判断 management server authority 是否严格属于本机 loopback。
///
/// 业务作用：只给测试/开发回环端点开放明文 ADS，防止误把生产 xDS 身份暴露到网络。
///
/// 参数说明：`url` 是已解析且含 host 的 xDS server URI。
///
/// 返回：localhost 或 loopback IP 返回 true；其它 host 返回 false。
fn xds_server_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// 校验一个会发给 xDS server 或用于资源映射的稳定标识。
///
/// 业务作用：限制 Node/cluster/metadata 的长度和字符集，避免秘密、控制字符或高熵任意环境值外泄。
///
/// 参数说明：`value` 是标识原值；`field` 用于返回可定位错误。
///
/// 返回：1..=256 bytes 且仅含安全 ASCII 字符时成功，否则拒绝配置。
fn validate_xds_identity(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "{field} cannot be empty");
    anyhow::ensure!(value.len() <= 256, "{field} must be <= 256 bytes");
    anyhow::ensure!(
        value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        }),
        "{field} contains unsupported characters"
    );
    Ok(())
}

/// 解析并检查 xDS bootstrap PEM 文件。
///
/// 业务作用：在启动 transport 前固定证书路径与 1 MiB 上限，拒绝目录、缺失文件和超大 secret。
///
/// 参数说明：`raw` 是配置路径；`config_dir` 是相对基准；`field` 用于错误定位。
///
/// 返回：成功时返回绝对或规范相对 PathBuf 字符串；失败时不创建任何网络资源。
fn normalize_xds_pem_file(raw: &str, config_dir: &Path, field: &str) -> Result<String> {
    anyhow::ensure!(!raw.trim().is_empty(), "{field} cannot be empty");
    let configured = Path::new(raw.trim());
    let path = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        config_dir.join(configured)
    };
    let metadata =
        fs::metadata(&path).with_context(|| format!("read {field} {}", path.display()))?;
    anyhow::ensure!(metadata.is_file(), "{field} must be a regular file");
    anyhow::ensure!(
        metadata.len() <= 1024 * 1024,
        "{field} must be <= 1048576 bytes"
    );
    Ok(path.to_string_lossy().into_owned())
}

/// 解析 xDS 配置中的紧凑 duration 字符串。
///
/// 业务作用：统一接受 `ms/s/m/h` 并在 checked arithmetic 下转换，避免溢出 timer 或不同模块口径漂移。
///
/// 参数说明：`raw` 是 duration；`field` 用于返回可定位错误。
///
/// 返回：成功时返回毫秒；空值、未知单位、零值和溢出返回错误。
fn parse_xds_duration_ms(raw: &str, field: &str) -> Result<u64> {
    let raw = raw.trim();
    let (number, multiplier) = if let Some(number) = raw.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = raw.strip_suffix('s') {
        (number, 1_000_u64)
    } else if let Some(number) = raw.strip_suffix('m') {
        (number, 60_000_u64)
    } else if let Some(number) = raw.strip_suffix('h') {
        (number, 3_600_000_u64)
    } else {
        bail!("{field} must use ms/s/m/h duration syntax");
    };
    let value = number
        .parse::<u64>()
        .with_context(|| format!("{field} contains an invalid integer"))?;
    anyhow::ensure!(value > 0, "{field} must be greater than zero");
    value
        .checked_mul(multiplier)
        .with_context(|| format!("{field} overflows milliseconds"))
}

/// 业务作用：构建管理面运行期认证策略，并在发布前拒绝匿名跨节点抓取或缺少 Cluster/Read 主体的配置。
///
/// 参数说明：`cfg` 是完整 admin 认证/RBAC 配置；`config_dir` 是 SecretSource 相对路径基准。
///
/// 返回：认证、来源门与主体权限全部合法时返回不可变运行态；矛盾配置或密钥解析失败时拒绝候选快照。
fn build_admin_auth(cfg: &AdminCfg, config_dir: &Path) -> Result<AdminAuthRuntimeCfg> {
    let auth = &cfg.auth;
    let mut allowed_origins = Vec::with_capacity(auth.allowed_origins.len());
    for raw in &auth.allowed_origins {
        let uri: http::Uri = raw
            .parse()
            .with_context(|| format!("admin.auth.allowed_origins contains invalid URI `{raw}`"))?;
        anyhow::ensure!(
            uri.path_and_query()
                .map(|path| path.as_str() == "/")
                .unwrap_or(true),
            "admin.auth.allowed_origins entry `{raw}` must contain only scheme and authority"
        );
        let origin = normalize_http_origin(raw).with_context(|| {
            format!("admin.auth.allowed_origins contains invalid origin `{raw}`")
        })?;
        if !allowed_origins.contains(&origin) {
            allowed_origins.push(origin);
        }
    }
    if cfg.rbac.enabled && !auth.enabled {
        bail!("admin.rbac.enabled requires admin.auth.enabled=true");
    }
    if auth.allow_cluster_metrics_scrape && !auth.enabled {
        bail!("admin.auth.allow_cluster_metrics_scrape requires admin.auth.enabled=true");
    }
    if !auth.enabled {
        return Ok(AdminAuthRuntimeCfg {
            enabled: false,
            bearer_token: None,
            basic_expected: None,
            realm: auth.realm.clone(),
            allow_healthz_unauthenticated: auth.allow_healthz_unauthenticated,
            allow_cluster_metrics_scrape: auth.allow_cluster_metrics_scrape,
            allowed_origins,
            rbac_enabled: false,
            principals: Arc::from([]),
        });
    }
    validate_auth_secret("admin.auth.realm", &auth.realm)?;
    let bearer_token = if auth.bearer_token.is_empty() {
        None
    } else {
        let token =
            crate::secret::resolve_text(&auth.bearer_token, config_dir, "admin.auth.bearer_token")?;
        validate_auth_secret("admin.auth.bearer_token", &token)?;
        Some(token.into_bytes())
    };
    let basic_expected = match (auth.basic_user.is_empty(), auth.basic_password.is_empty()) {
        (true, true) => None,
        (false, false) => {
            validate_basic_user("admin.auth.basic_user", &auth.basic_user)?;
            let password = crate::secret::resolve_text(
                &auth.basic_password,
                config_dir,
                "admin.auth.basic_password",
            )?;
            validate_auth_secret("admin.auth.basic_password", &password)?;
            Some(format!("{}:{password}", auth.basic_user).into_bytes())
        }
        _ => bail!("admin.auth basic_user and basic_password must be configured together"),
    };
    let principals = build_admin_principals(cfg, config_dir)?;
    if cfg.rbac.enabled && (bearer_token.is_some() || basic_expected.is_some()) {
        bail!(
            "admin.rbac.enabled forbids legacy admin.auth credentials; bind every credential to admin.rbac.principals"
        );
    }
    if !cfg.rbac.enabled && bearer_token.is_none() && basic_expected.is_none() {
        bail!("admin.auth enabled requires bearer_token or basic_user/basic_password");
    }
    if auth.allow_cluster_metrics_scrape
        && cfg.rbac.enabled
        && !principals
            .iter()
            .any(|principal| principal.allows(AdminResource::Cluster, AdminAction::Read))
    {
        bail!(
            "admin.auth.allow_cluster_metrics_scrape with RBAC requires a principal with cluster read permission"
        );
    }
    Ok(AdminAuthRuntimeCfg {
        enabled: true,
        bearer_token,
        basic_expected,
        realm: auth.realm.clone(),
        allow_healthz_unauthenticated: auth.allow_healthz_unauthenticated,
        allow_cluster_metrics_scrape: auth.allow_cluster_metrics_scrape,
        allowed_origins,
        rbac_enabled: cfg.rbac.enabled,
        principals,
    })
}

/// 校验并解析管理审计配置；RBAC 模式强制启用审计，防止高危动作无留痕。
///
/// # 参数
/// - `cfg`: 完整 admin 配置。
/// - `config_dir`: 相对 spool/SecretSource 路径基准。
fn build_admin_audit(cfg: &AdminCfg, config_dir: &Path) -> Result<AdminAuditRuntimeCfg> {
    let audit = &cfg.audit;
    if cfg.rbac.enabled && !audit.enabled {
        bail!("admin.rbac.enabled requires admin.audit.enabled=true");
    }
    let file = if Path::new(&audit.file).is_absolute() {
        PathBuf::from(&audit.file)
    } else {
        config_dir.join(&audit.file)
    };
    if !audit.enabled {
        return Ok(AdminAuditRuntimeCfg {
            enabled: false,
            file,
            signing_key: Arc::from(""),
            endpoint: None,
            authorization: None,
            timeout: std::time::Duration::from_millis(audit.timeout_ms),
            fsync: audit.fsync,
            max_record_bytes: audit.max_record_bytes,
            history_limit: audit.history_limit,
        });
    }
    if audit.file.trim().is_empty() {
        bail!("admin.audit.file cannot be empty");
    }
    if let Ok(metadata) = fs::symlink_metadata(&file) {
        if metadata.file_type().is_symlink() {
            bail!("admin.audit.file cannot be a symlink");
        }
        if !metadata.is_file() {
            bail!("admin.audit.file must be a regular file");
        }
    }
    let signing_key =
        crate::secret::resolve_text(&audit.signing_key, config_dir, "admin.audit.signing_key")?;
    if !(32..=64 * 1024).contains(&signing_key.len()) {
        bail!("admin.audit.signing_key must resolve to 32..=65536 bytes");
    }
    if !(100..=120_000).contains(&audit.timeout_ms) {
        bail!("admin.audit.timeout_ms must be within 100..=120000");
    }
    if !(1024..=1024 * 1024).contains(&audit.max_record_bytes) {
        bail!("admin.audit.max_record_bytes must be within 1024..=1048576");
    }
    if !(1..=100_000).contains(&audit.history_limit) {
        bail!("admin.audit.history_limit must be within 1..=100000");
    }
    let endpoint = if audit.endpoint.trim().is_empty() {
        if !audit.allow_local_only {
            bail!(
                "admin.audit.endpoint is required; set allow_local_only=true only for explicit single-node development"
            );
        }
        None
    } else {
        let uri: http::Uri = audit
            .endpoint
            .parse()
            .context("admin.audit.endpoint is invalid")?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            bail!("admin.audit.endpoint must be an absolute http/https URI");
        }
        Some(Arc::from(audit.endpoint.as_str()))
    };
    let authorization = if audit.authorization.is_empty() {
        None
    } else {
        if endpoint.is_none() {
            bail!("admin.audit.authorization requires endpoint");
        }
        let value = crate::secret::resolve_text(
            &audit.authorization,
            config_dir,
            "admin.audit.authorization",
        )?;
        let mut value = http::HeaderValue::from_str(&value)
            .context("admin.audit.authorization contains invalid header bytes")?;
        value.set_sensitive(true);
        Some(value)
    };
    Ok(AdminAuditRuntimeCfg {
        enabled: true,
        file,
        signing_key: Arc::from(signing_key),
        endpoint,
        authorization,
        timeout: std::time::Duration::from_millis(audit.timeout_ms),
        fsync: audit.fsync,
        max_record_bytes: audit.max_record_bytes,
        history_limit: audit.history_limit,
    })
}

/// 业务作用：校验集群渐进发布的批次、观察窗和健康阈值，避免控制面进入永不完成或无门槛放量状态。
///
/// 参数说明：`cfg` 是 rollout 声明；`source`/`discovery` 提供原子配置与成员事实；`auth`/`audit` 提供抓取授权与持久审计门禁。
///
/// 返回：全部资源与阈值可安全执行时成功；非法选择器、窗口或浮点值返回构建错误。
fn validate_admin_rollout(
    cfg: &AdminRolloutCfg,
    source: &ConfigSourceCfg,
    discovery: &DiscoveryCfg,
    auth: &AdminAuthRuntimeCfg,
    audit: &AdminAuditRuntimeCfg,
) -> Result<()> {
    anyhow::ensure!(
        (1..=32).contains(&cfg.canary_count),
        "admin.rollout.canary_count must be within 1..=32"
    );
    anyhow::ensure!(
        (5..=3_600).contains(&cfg.observation_seconds),
        "admin.rollout.observation_seconds must be within 5..=3600"
    );
    anyhow::ensure!(
        cfg.max_5xx_ratio.is_finite() && (0.0..=1.0).contains(&cfg.max_5xx_ratio),
        "admin.rollout.max_5xx_ratio must be finite and within 0..=1"
    );
    anyhow::ensure!(
        cfg.max_p99_regression_ratio.is_finite()
            && (1.0..=100.0).contains(&cfg.max_p99_regression_ratio),
        "admin.rollout.max_p99_regression_ratio must be finite and within 1..=100"
    );
    anyhow::ensure!(
        (1..=600_000).contains(&cfg.max_p99_ms),
        "admin.rollout.max_p99_ms must be within 1..=600000"
    );
    if cfg.selector_key.trim().is_empty() {
        anyhow::ensure!(
            cfg.selector_value.trim().is_empty(),
            "admin.rollout.selector_value requires selector_key"
        );
    } else {
        anyhow::ensure!(
            cfg.selector_key.len() <= 128
                && cfg.selector_value.len() <= 256
                && !cfg.selector_key.chars().any(char::is_control)
                && !cfg.selector_value.chars().any(char::is_control),
            "admin.rollout selector key/value exceeds limits or contains control characters"
        );
    }
    if cfg.enabled {
        anyhow::ensure!(
            source.nacos.enabled && !source.nacos.bundle_data_id.trim().is_empty(),
            "admin.rollout.enabled requires config_source.nacos.enabled and an atomic bundle_data_id"
        );
        anyhow::ensure!(
            discovery.nacos.enabled && discovery.nacos.self_register.enabled,
            "admin.rollout.enabled requires discovery.nacos self-registration"
        );
        anyhow::ensure!(
            auth.enabled && auth.allow_cluster_metrics_scrape,
            "admin.rollout.enabled requires authenticated admin peer metrics scraping"
        );
        anyhow::ensure!(
            audit.enabled,
            "admin.rollout.enabled requires admin.audit.enabled=true"
        );
        if cfg.require_approval {
            anyhow::ensure!(
                auth.rbac_enabled,
                "admin.rollout.require_approval requires admin.rbac.enabled=true"
            );
            let approvers = auth
                .principals
                .iter()
                .filter(|principal| principal.allows(AdminResource::Config, AdminAction::Write))
                .count();
            anyhow::ensure!(
                approvers >= 2,
                "admin.rollout.require_approval requires at least two Config/Write principals"
            );
        }
    }
    Ok(())
}

/// 业务作用：校验 maker-checker 的资源边界、容量、时效与双主体授权，避免启用后无人可审批或候选
/// 无限滞留。
///
/// 参数说明：`cfg` 是审批策略；`auth` 是已编译主体权限；`audit` 是持久审计事实。
///
/// 返回：策略可安全执行时成功；资源越界、重复、预算非法或任一资源不足两名写主体时拒绝候选。
fn validate_admin_approval(
    cfg: &AdminApprovalCfg,
    auth: &AdminAuthRuntimeCfg,
    audit: &AdminAuditRuntimeCfg,
) -> Result<()> {
    anyhow::ensure!(
        (30..=86_400).contains(&cfg.ttl_seconds),
        "admin.approval.ttl_seconds must be within 30..=86400"
    );
    anyhow::ensure!(
        (1..=1024).contains(&cfg.max_pending),
        "admin.approval.max_pending must be within 1..=1024"
    );
    let mut seen = Vec::new();
    for resource in &cfg.resources {
        anyhow::ensure!(
            matches!(
                resource,
                AdminResource::Sentinel | AdminResource::Consumers | AdminResource::Certs
            ),
            "admin.approval.resources only supports sentinel, consumers and certs"
        );
        anyhow::ensure!(
            !seen.contains(resource),
            "admin.approval.resources contains a duplicate"
        );
        seen.push(*resource);
    }
    if cfg.enabled {
        anyhow::ensure!(
            !cfg.resources.is_empty(),
            "admin.approval.enabled requires at least one resource"
        );
        anyhow::ensure!(
            auth.enabled && auth.rbac_enabled,
            "admin.approval.enabled requires admin auth and RBAC"
        );
        anyhow::ensure!(
            audit.enabled,
            "admin.approval.enabled requires admin.audit.enabled=true"
        );
        for resource in &cfg.resources {
            let writers = auth
                .principals
                .iter()
                .filter(|principal| principal.allows(*resource, AdminAction::Write))
                .count();
            anyhow::ensure!(
                writers >= 2,
                "admin.approval resource requires at least two principals with Write permission"
            );
        }
    }
    Ok(())
}

/// 解析 RBAC principal SecretSource，并把角色/授权编译成固定权限位图。
///
/// # 参数
/// - `cfg`: 完整 admin 配置；同时用于检测 RBAC 是否启用。
/// - `config_dir`: SecretSource 相对路径基准。
fn build_admin_principals(
    cfg: &AdminCfg,
    config_dir: &Path,
) -> Result<Arc<[AdminPrincipalRuntime]>> {
    if !cfg.rbac.enabled {
        return Ok(Arc::from([]));
    }
    if cfg.rbac.principals.is_empty() {
        bail!("admin.rbac.enabled requires at least one principal");
    }
    if cfg.rbac.principals.len() > 256 {
        bail!("admin.rbac supports at most 256 principals");
    }
    let mut principals = Vec::with_capacity(cfg.rbac.principals.len());
    for principal in &cfg.rbac.principals {
        if principal.id.is_empty()
            || principal.id.len() > 64
            || !principal.id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@')
            })
        {
            bail!(
                "admin.rbac principal id `{}` must be 1..=64 safe ASCII characters",
                principal.id
            );
        }
        if principals
            .iter()
            .any(|existing: &AdminPrincipalRuntime| existing.id.as_ref() == principal.id)
        {
            bail!("duplicate admin.rbac principal id `{}`", principal.id);
        }
        let bearer_token = if principal.bearer_token.is_empty() {
            None
        } else {
            let field = format!("admin.rbac.principals.{}.bearer_token", principal.id);
            let token = crate::secret::resolve_text(&principal.bearer_token, config_dir, &field)?;
            validate_auth_secret(&field, &token)?;
            Some(token.into_bytes())
        };
        let basic_expected = match (
            principal.basic_user.is_empty(),
            principal.basic_password.is_empty(),
        ) {
            (true, true) => None,
            (false, false) => {
                let user_field = format!("admin.rbac.principals.{}.basic_user", principal.id);
                validate_basic_user(&user_field, &principal.basic_user)?;
                let password_field =
                    format!("admin.rbac.principals.{}.basic_password", principal.id);
                let password = crate::secret::resolve_text(
                    &principal.basic_password,
                    config_dir,
                    &password_field,
                )?;
                validate_auth_secret(&password_field, &password)?;
                Some(format!("{}:{password}", principal.basic_user).into_bytes())
            }
            _ => bail!(
                "admin.rbac principal `{}` basic_user/basic_password must be configured together",
                principal.id
            ),
        };
        if bearer_token.is_none() && basic_expected.is_none() {
            bail!(
                "admin.rbac principal `{}` requires bearer_token or basic credentials",
                principal.id
            );
        }
        if principal.roles.is_empty() && principal.grants.is_empty() {
            bail!(
                "admin.rbac principal `{}` requires a role or custom grant",
                principal.id
            );
        }
        let mut permissions = 0_u128;
        for role in &principal.roles {
            add_role_permissions(&mut permissions, *role);
        }
        for grant in &principal.grants {
            if grant.actions.is_empty() {
                bail!(
                    "admin.rbac principal `{}` contains a grant with no actions",
                    principal.id
                );
            }
            for action in &grant.actions {
                permissions |= permission_bit(grant.resource, *action);
            }
        }
        if principals.iter().any(|existing| {
            bearer_token.is_some() && existing.bearer_token.as_ref() == bearer_token.as_ref()
                || basic_expected.is_some()
                    && existing.basic_expected.as_ref() == basic_expected.as_ref()
        }) {
            bail!(
                "admin.rbac principal `{}` reuses another principal credential",
                principal.id
            );
        }
        principals.push(AdminPrincipalRuntime {
            id: Arc::from(principal.id.as_str()),
            bearer_token,
            basic_expected,
            permissions,
        });
    }
    Ok(principals.into())
}

/// 向权限位图加入一个内置角色模板。
///
/// # 参数
/// - `permissions`: 当前主体权限位图，函数原地追加权限并集。
/// - `role`: 架构内置角色。
fn add_role_permissions(permissions: &mut u128, role: AdminRole) {
    let mut allow = |resource, action| *permissions |= permission_bit(resource, action);
    match role {
        AdminRole::Viewer => {
            for resource in AdminResource::ALL {
                allow(resource, AdminAction::Read);
            }
        }
        AdminRole::Operator => {
            for resource in AdminResource::ALL {
                allow(resource, AdminAction::Read);
            }
            for resource in [
                AdminResource::Config,
                AdminResource::Routes,
                AdminResource::Sentinel,
            ] {
                allow(resource, AdminAction::DryRun);
                allow(resource, AdminAction::Write);
            }
        }
        AdminRole::SecuritySre => {
            for resource in AdminResource::ALL {
                allow(resource, AdminAction::Read);
            }
            for resource in [AdminResource::InterfaceGuard, AdminResource::Acl] {
                allow(resource, AdminAction::Write);
                allow(resource, AdminAction::EmergencyKill);
            }
        }
        AdminRole::Admin => {
            for resource in AdminResource::ALL {
                for action in [
                    AdminAction::Read,
                    AdminAction::DryRun,
                    AdminAction::Write,
                    AdminAction::EmergencyKill,
                    AdminAction::Rollback,
                ] {
                    allow(resource, action);
                }
            }
        }
    }
}

/// 生成一个固定权限 bit；13×5=65，使用 `u128` 留出演进余量且避免请求时 HashMap 查询。
const fn permission_bit(resource: AdminResource, action: AdminAction) -> u128 {
    1_u128 << (resource.index() * AdminAction::COUNT + action.index())
}

/// 从 Origin 或 Referer URI 提取规范化的 `scheme://authority`。
pub(crate) fn normalize_http_origin(raw: &str) -> Result<String> {
    let uri: http::Uri = raw.trim().parse().context("parse HTTP origin URI")?;
    let scheme = uri
        .scheme_str()
        .filter(|scheme| {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        })
        .context("origin scheme must be http or https")?;
    let authority = uri.authority().context("origin authority is required")?;
    anyhow::ensure!(
        !authority.as_str().contains('@'),
        "origin authority must not contain userinfo"
    );
    Ok(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.as_str().to_ascii_lowercase()
    ))
}

/// 管理面若绑定到非回环地址，必须显式启用认证，避免默认配置误暴露控制面。
fn validate_admin_exposure(listen: &str, auth: &AdminAuthRuntimeCfg) -> Result<()> {
    let address: std::net::SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid admin.listen `{listen}`"))?;
    if !address.ip().is_loopback() && !auth.enabled {
        bail!(
            "admin.listen `{listen}` is non-loopback; admin.auth.enabled with a credential is required"
        );
    }
    Ok(())
}

/// 校验认证用户名。
///
/// # 参数
/// - `field`: 字段名,用于错误上下文。
/// - `value`: 用户名。
fn validate_basic_user(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.bytes().any(|b| b == b':' || b < 0x20) {
        bail!("{field} is invalid");
    }
    Ok(())
}

/// 校验认证 secret/realm 文本。
///
/// # 参数
/// - `field`: 字段名,用于错误上下文。
/// - `value`: 待校验文本。
fn validate_auth_secret(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.bytes().any(|b| b < 0x20) {
        bail!("{field} is invalid");
    }
    Ok(())
}

/// 业务作用：把 L4 listener 配置编译为不可变运行时，并在发布快照前拒绝
/// 协议/profile/feature 不匹配与越界资源预算。
///
/// 参数说明：`cfg` 是顶层 stream 配置；`cfg_path` 为 TLS 等相对文件提供可信基目录。
///
/// 返回：全部 listener 都通过门禁时返回 runtime 列表；任一 listener 无效时返回错误，
/// 旧快照不受影响。
fn build_stream_listeners(cfg: &StreamCfg, cfg_path: &Path) -> Result<Vec<StreamRuntime>> {
    let mut out = Vec::with_capacity(cfg.listeners.len());
    let mut ids = HashSet::new();
    for listener in &cfg.listeners {
        if listener.id.trim().is_empty() {
            anyhow::bail!("stream listener id must not be empty");
        }
        if !ids.insert(listener.id.clone()) {
            anyhow::bail!("duplicate stream listener id `{}`", listener.id);
        }
        listener
            .listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| {
                format!(
                    "invalid stream `{}` listen `{}`",
                    listener.id, listener.listen
                )
            })?;
        let protocol = match listener.protocol {
            model::StreamProtocolCfg::Tcp => StreamProtocolRuntime::Tcp,
            model::StreamProtocolCfg::Udp => StreamProtocolRuntime::Udp,
        };
        anyhow::ensure!(
            (1..=60_000).contains(&listener.connect_timeout_ms),
            "stream `{}` connect_timeout_ms must be within 1..=60000",
            listener.id
        );
        validate_optional_duration(
            &format!("stream `{}` timeout_ms", listener.id),
            listener.timeout_ms,
            MAX_RUNTIME_DURATION_MS,
        )?;
        if listener.preread.ssl_preread || listener.preread.mqtt_connect {
            anyhow::ensure!(
                (1..=60_000).contains(&listener.preread.timeout_ms),
                "stream `{}` preread.timeout_ms must be within 1..=60000",
                listener.id
            );
            anyhow::ensure!(
                (256..=1024 * 1024).contains(&listener.preread.max_bytes),
                "stream `{}` preread.max_bytes must be within 256..=1048576",
                listener.id
            );
        }
        let tls = listener
            .tls
            .as_ref()
            .map(|tls| build_stream_server_tls(cfg_path, listener, tls))
            .transpose()?;
        let tls_handshake_timeout_ms = listener
            .tls
            .as_ref()
            .map(|tls| tls.handshake_timeout_ms)
            .unwrap_or(0);
        if listener.tls.is_some() && !(1..=60_000).contains(&tls_handshake_timeout_ms) {
            anyhow::bail!(
                "stream `{}` tls.handshake_timeout_ms must be within 1..=60000",
                listener.id
            );
        }
        if protocol == StreamProtocolRuntime::Udp && tls.is_some() {
            anyhow::bail!("stream `{}` UDP cannot terminate TLS", listener.id);
        }
        if protocol == StreamProtocolRuntime::Udp {
            anyhow::ensure!(
                !listener.preread.ssl_preread,
                "stream `{}` UDP cannot enable ssl_preread",
                listener.id
            );
            anyhow::ensure!(
                !listener.preread.mqtt_connect,
                "stream `{}` UDP cannot enable MQTT CONNECT preread",
                listener.id
            );
            anyhow::ensure!(
                !listener.proxy_protocol.enabled && !listener.proxy_protocol_to_upstream.enabled,
                "stream `{}` UDP does not support PROXY protocol",
                listener.id
            );
            anyhow::ensure!(
                (100..=86_400_000).contains(&listener.udp.idle_timeout_ms),
                "stream `{}` udp.idle_timeout_ms must be within 100..=86400000",
                listener.id
            );
            anyhow::ensure!(
                (1..=65_536).contains(&listener.udp.max_sessions),
                "stream `{}` udp.max_sessions must be within 1..=65536",
                listener.id
            );
            anyhow::ensure!(
                (1..=4096).contains(&listener.udp.queue_capacity),
                "stream `{}` udp.queue_capacity must be within 1..=4096",
                listener.id
            );
            anyhow::ensure!(
                (512..=65_507).contains(&listener.udp.max_datagram_bytes),
                "stream `{}` udp.max_datagram_bytes must be within 512..=65507",
                listener.id
            );
        }
        if listener.preread.ssl_preread && listener.preread.mqtt_connect {
            anyhow::bail!(
                "stream `{}` cannot combine ssl_preread passthrough with MQTT CONNECT preread",
                listener.id
            );
        }
        #[cfg(not(feature = "mqtt-governance"))]
        if listener.mqtt.enabled {
            anyhow::bail!(
                "stream `{}` MQTT governance requires binary feature `mqtt-governance`",
                listener.id
            );
        }
        #[cfg(feature = "mqtt-governance")]
        let mqtt = if listener.mqtt.enabled {
            anyhow::ensure!(
                protocol == StreamProtocolRuntime::Tcp,
                "stream `{}` MQTT governance requires protocol=tcp",
                listener.id
            );
            anyhow::ensure!(
                listener.preread.mqtt_connect,
                "stream `{}` MQTT governance requires preread.mqtt_connect=true",
                listener.id
            );
            Some(Arc::new(
                crate::mqtt::MqttPolicy::build(&listener.mqtt)
                    .with_context(|| format!("stream `{}` MQTT governance", listener.id))?,
            ))
        } else {
            None
        };
        #[cfg(not(feature = "kafka-governance"))]
        if listener.kafka.enabled {
            anyhow::bail!(
                "stream `{}` Kafka governance requires binary feature `kafka-governance`",
                listener.id
            );
        }
        #[cfg(feature = "kafka-governance")]
        let kafka = if listener.kafka.enabled {
            anyhow::ensure!(
                protocol == StreamProtocolRuntime::Tcp,
                "stream `{}` Kafka governance requires protocol=tcp",
                listener.id
            );
            anyhow::ensure!(
                !listener.mqtt.enabled && !listener.preread.mqtt_connect,
                "stream `{}` Kafka governance cannot share MQTT governance/preread",
                listener.id
            );
            anyhow::ensure!(
                !listener.preread.ssl_preread,
                "stream `{}` Kafka governance cannot inspect encrypted ssl_preread traffic",
                listener.id
            );
            Some(Arc::new(
                crate::kafka::KafkaPolicy::build(&listener.kafka)
                    .with_context(|| format!("stream `{}` Kafka governance", listener.id))?,
            ))
        } else {
            None
        };
        let routes = build_stream_routes(listener, cfg_path)
            .with_context(|| format!("stream `{}` routes", listener.id))?;
        if routes.iter().any(|route| route.terminate_tls) {
            anyhow::ensure!(
                tls.is_some() && listener.preread.ssl_preread,
                "stream `{}` route TLS termination requires listener tls and ssl_preread",
                listener.id
            );
        } else if tls.is_some() && listener.preread.ssl_preread {
            anyhow::bail!(
                "stream `{}` tls with ssl_preread requires at least one terminate_tls route",
                listener.id
            );
        }
        if routes.iter().any(|route| route.sni.is_some()) && !listener.preread.ssl_preread {
            anyhow::bail!(
                "stream `{}` SNI routes require preread.ssl_preread=true",
                listener.id
            );
        }
        if routes.iter().any(|route| route.mqtt_client_id.is_some())
            && !listener.preread.mqtt_connect
        {
            anyhow::bail!(
                "stream `{}` MQTT routes require preread.mqtt_connect=true",
                listener.id
            );
        }
        if protocol == StreamProtocolRuntime::Udp
            && !listener.reject_all
            && (routes.len() != 1
                || !routes[0].default
                || routes[0].sni.is_some()
                || routes[0].mqtt_client_id.is_some()
                || routes[0].upstream_tls.is_some())
        {
            anyhow::bail!(
                "stream `{}` UDP currently requires exactly one plaintext default route",
                listener.id
            );
        }
        let upstream = routes
            .iter()
            .find(|route| route.default)
            .or_else(|| routes.first())
            .map(|route| route.upstream.clone())
            .unwrap_or_default();
        out.push(StreamRuntime {
            id: listener.id.clone(),
            listen: listener.listen.clone(),
            protocol,
            tls,
            tls_handshake_timeout_ms,
            udp: StreamUdpRuntime {
                idle_timeout_ms: listener.udp.idle_timeout_ms,
                max_sessions: listener.udp.max_sessions,
                queue_capacity: listener.udp.queue_capacity,
                max_datagram_bytes: listener.udp.max_datagram_bytes,
            },
            upstream,
            preread: StreamPrereadRuntime {
                ssl_preread: listener.preread.ssl_preread,
                mqtt_connect: listener.preread.mqtt_connect,
                timeout_ms: listener.preread.timeout_ms,
                max_bytes: listener.preread.max_bytes,
            },
            #[cfg(feature = "mqtt-governance")]
            mqtt,
            #[cfg(feature = "kafka-governance")]
            kafka,
            routes: Arc::new(routes),
            proxy_protocol: build_proxy_protocol(&listener.proxy_protocol)
                .with_context(|| format!("stream `{}` proxy_protocol", listener.id))?,
            proxy_protocol_to_upstream: build_stream_proxy_protocol_to_upstream(
                &listener.proxy_protocol_to_upstream,
            )
            .with_context(|| format!("stream `{}` proxy_protocol_to_upstream", listener.id))?,
            connect_timeout_ms: listener.connect_timeout_ms,
            timeout_ms: listener.timeout_ms,
        });
    }
    Ok(out)
}

/// 业务作用：构建单个 stream listener 的路由表，并区分旧版单上游、显式多路由和
/// 全连接拒绝三种互斥形态，防止空配置意外开放默认转发。
///
/// 参数说明：`listener` 是 stream listener 原始配置；`cfg_path` 为上游 TLS 文件提供可信基目录。
///
/// 返回：配置形态与路由约束均合法时返回运行时路由；冲突、重复或缺少安全默认路由时返回错误。
fn build_stream_routes(
    listener: &model::StreamListenerCfg,
    cfg_path: &Path,
) -> Result<Vec<StreamRouteRuntime>> {
    let mut routes = Vec::new();
    if listener.reject_all {
        anyhow::ensure!(
            listener.routes.is_empty() && listener.upstream.trim().is_empty(),
            "reject_all cannot combine with upstream or routes[]"
        );
        return Ok(routes);
    }
    if listener.routes.is_empty() {
        let upstream = normalize_stream_upstream(&listener.upstream)?;
        if upstream.trim().is_empty() {
            anyhow::bail!("upstream must not be empty when routes[] is empty");
        }
        routes.push(StreamRouteRuntime {
            id: "default".to_string(),
            sni: None,
            mqtt_client_id: None,
            default: true,
            terminate_tls: false,
            upstream,
            weighted_upstreams: Arc::from([]),
            upstream_tls: None,
        });
        return Ok(routes);
    }
    let mut ids = HashSet::new();
    let mut sni_seen = HashSet::new();
    let mut mqtt_seen = HashSet::new();
    let mut default_seen = false;
    for route in &listener.routes {
        if route.id.trim().is_empty() {
            anyhow::bail!("stream route id must not be empty");
        }
        if !ids.insert(route.id.clone()) {
            anyhow::bail!("duplicate stream route id `{}`", route.id);
        }
        let sni = route
            .sni
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(normalize_sni)
            .transpose()?;
        let mqtt_client_id = route
            .mqtt_client_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| {
                anyhow::ensure!(
                    value.len() <= 256 && !value.chars().any(|ch| ch == '\0'),
                    "stream route `{}` mqtt_client_id must be 1..=256 UTF-8 bytes without NUL",
                    route.id
                );
                Ok::<_, anyhow::Error>(value.to_owned())
            })
            .transpose()?;
        if sni.is_some() && mqtt_client_id.is_some() {
            anyhow::bail!(
                "stream route `{}` cannot combine sni and mqtt_client_id matchers",
                route.id
            );
        }
        if let Some(sni) = &sni {
            if !sni_seen.insert(sni.clone()) {
                anyhow::bail!("duplicate stream route sni `{sni}`");
            }
        }
        if let Some(client_id) = &mqtt_client_id {
            if !mqtt_seen.insert(client_id.clone()) {
                anyhow::bail!("duplicate stream route mqtt_client_id `{client_id}`");
            }
        }
        if route.default {
            if default_seen {
                anyhow::bail!("stream routes can have only one default route");
            }
            default_seen = true;
        } else if sni.is_none() && mqtt_client_id.is_none() {
            anyhow::bail!(
                "stream route `{}` requires `sni` or `default: true`",
                route.id
            );
        }
        let weighted_upstreams = route
            .weighted_upstreams
            .iter()
            .map(|backend| {
                Ok::<_, anyhow::Error>((
                    normalize_stream_upstream(&backend.upstream)?,
                    backend.weight,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        if !weighted_upstreams.is_empty() {
            anyhow::ensure!(
                route.tls.is_none()
                    && weighted_upstreams
                        .iter()
                        .all(|(upstream, _)| upstream.starts_with("lb://")),
                "stream route `{}` weighted_upstreams require service-level TLS on lb:// targets",
                route.id
            );
            let total_weight = weighted_upstreams
                .iter()
                .map(|(_, weight)| u64::from(*weight))
                .sum::<u64>();
            anyhow::ensure!(
                total_weight > 0 && total_weight <= u64::from(u32::MAX),
                "stream route `{}` weighted_upstreams require a positive bounded total weight",
                route.id
            );
        }
        routes.push(StreamRouteRuntime {
            id: route.id.clone(),
            sni,
            mqtt_client_id,
            default: route.default,
            terminate_tls: route.terminate_tls,
            upstream: normalize_stream_upstream(&route.upstream)?,
            weighted_upstreams: Arc::from(weighted_upstreams),
            upstream_tls: build_stream_upstream_tls(cfg_path, listener, route)?,
        });
    }
    anyhow::ensure!(
        default_seen || (listener.preread.ssl_preread && routes.iter().all(|route| route.sni.is_some())),
        "stream routes require one `default: true` route unless TLS preread routes cover only explicit SNI"
    );
    Ok(routes)
}

/// 业务作用：把 stream TLS 终止配置编译为与 L7 共用的 rustls server runtime，
/// 保持默认身份、SNI 身份和客户端认证策略一致。
///
/// 参数说明：`cfg_path` 是路径信任根；`listener` 提供业务身份；`tls` 是待编译配置。
///
/// 返回：配置完整时返回可热换 TLS runtime；认证模式或路径语义无效时返回错误。
fn build_stream_server_tls(
    cfg_path: &Path,
    listener: &model::StreamListenerCfg,
    tls: &model::StreamTlsCfg,
) -> Result<TlsRuntimeCfg> {
    let client_auth = tls
        .client_auth
        .as_ref()
        .map(|auth| {
            let (require, allow_untrusted) =
                match auth.mode.trim().to_ascii_lowercase().as_str() {
                "require" => (true, false),
                "optional" => (false, false),
                "insecure_fallback" => (false, true),
                other => anyhow::bail!(
                    "stream `{}` tls.client_auth.mode must be require|optional|insecure_fallback, got `{other}`",
                    listener.id
                ),
            };
            Ok::<_, anyhow::Error>(ClientAuthRuntime {
                require,
                allow_untrusted,
                ca_file: resolve_relative(cfg_path, &auth.ca_file),
            })
        })
        .transpose()?;
    Ok(TlsRuntimeCfg {
        listen: listener.listen.clone(),
        cert_file: resolve_relative(cfg_path, &tls.cert_file),
        key_file: resolve_relative(cfg_path, &tls.key_file),
        keypair_manifest_file: None,
        certs: tls
            .certs
            .iter()
            .map(|cert| SniCertRuntime {
                server_names: cert
                    .server_names
                    .iter()
                    .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
                    .collect(),
                cert_file: resolve_relative(cfg_path, &cert.cert_file),
                key_file: resolve_relative(cfg_path, &cert.key_file),
            })
            .collect(),
        client_auth,
        acme: None,
        in_memory: None,
    })
}

/// 构建 route 级 stream 上游 TLS/mTLS profile。`lb://` 由 service 配置持有 profile，
/// 防止同一实例身份在 L7/L4 间使用两套证书策略却共享健康键。
fn build_stream_upstream_tls(
    cfg_path: &Path,
    listener: &model::StreamListenerCfg,
    route: &model::StreamRouteCfg,
) -> Result<Option<UpstreamTlsProfile>> {
    let Some(tls) = &route.tls else {
        return Ok(None);
    };
    if route.upstream.trim().starts_with("lb://") {
        anyhow::bail!(
            "stream `{}` route `{}` lb:// upstream TLS must be configured on upstreams.services",
            listener.id,
            route.id
        );
    }
    let ca_file = tls
        .ca_file
        .as_deref()
        .map(|path| resolve_relative(cfg_path, path));
    let client_cert = tls
        .client_cert_file
        .as_deref()
        .map(|path| resolve_relative(cfg_path, path));
    let client_key = tls
        .client_key_file
        .as_deref()
        .map(|path| resolve_relative(cfg_path, path));
    build_upstream_tls_profile(
        tls.server_name.as_deref(),
        ca_file.as_deref(),
        client_cert.as_deref(),
        client_key.as_deref(),
    )
    .with_context(|| format!("stream `{}` route `{}` upstream TLS", listener.id, route.id))
    .map(Some)
}

/// 编译 stream 发往上游的 PROXY protocol 配置。
///
/// # 参数
/// - `cfg`: yml 中的 `proxy_protocol_to_upstream`。
fn build_stream_proxy_protocol_to_upstream(
    cfg: &model::StreamProxyProtocolUpstreamCfg,
) -> Result<StreamProxyProtocolUpstreamRuntime> {
    let version = if cfg.version.eq_ignore_ascii_case("v1") {
        ProxyProtocolWriteVersion::V1
    } else if cfg.version.eq_ignore_ascii_case("v2") {
        ProxyProtocolWriteVersion::V2
    } else {
        anyhow::bail!(
            "unsupported upstream PROXY protocol version `{}`",
            cfg.version
        );
    };
    Ok(StreamProxyProtocolUpstreamRuntime {
        enabled: cfg.enabled,
        version,
    })
}

/// 规范化 stream 上游目标。
///
/// # 参数
/// - `raw`: `host:port`、`tcp://host:port` 或 `lb://service`。
fn normalize_stream_upstream(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if let Some(service) = raw.strip_prefix("lb://") {
        validate_stream_lb_service(service)?;
        return Ok(format!("lb://{}", service.trim()));
    }
    let upstream = raw.strip_prefix("tcp://").unwrap_or(raw).trim();
    if upstream.is_empty() {
        return Ok(String::new());
    }
    let authority = upstream
        .parse::<http::uri::Authority>()
        .with_context(|| format!("invalid stream upstream `{raw}`"))?;
    anyhow::ensure!(
        authority.port_u16().is_some(),
        "stream upstream `{raw}` requires an explicit port"
    );
    Ok(authority.as_str().to_owned())
}

/// 校验 stream `lb://service` 的服务名语法。
///
/// # 参数
/// - `service`: `lb://` 后面的逻辑服务名。
fn validate_stream_lb_service(service: &str) -> Result<()> {
    let service = service.trim();
    if service.is_empty()
        || service.bytes().any(|b| {
            b.is_ascii_control() || matches!(b, b'/' | b'?' | b'#' | b' ' | b'\t' | b'\r' | b'\n')
        })
    {
        anyhow::bail!("invalid stream lb service `{service}`");
    }
    Ok(())
}

/// 规范化 SNI 匹配值。
///
/// # 参数
/// - `raw`: 配置中的 SNI host。
fn normalize_sni(raw: &str) -> Result<String> {
    let sni = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if sni.is_empty()
        || sni.len() > 253
        || sni.contains('/')
        || sni.contains('\\')
        || sni.bytes().any(|b| b == 0 || b <= 0x20)
    {
        anyhow::bail!("invalid stream route sni `{raw}`");
    }
    Ok(sni)
}

fn build_proxies(
    cfg_path: &Path,
    cfg: &GatewayConfig,
    sentinel: &SentinelRouteFilters,
    variables: Arc<VariablePlan>,
    usage_plans: Arc<crate::routing::UsagePlanCatalog>,
) -> Result<Vec<ProxyRuntime>> {
    let mut proxies = Vec::new();
    let mut sentinel_matched_routes = HashSet::new();
    if cfg.proxies.is_empty() {
        let server = cfg
            .server
            .as_ref()
            .context("missing `server` or `proxies[]`; configure one data-plane listener")?;
        proxies.push(build_legacy_proxy(
            cfg_path,
            server,
            &cfg.routes,
            sentinel,
            variables.clone(),
            usage_plans.clone(),
            &mut sentinel_matched_routes,
        )?);
    } else {
        for proxy in &cfg.proxies {
            proxies.push(build_proxy(
                cfg_path,
                proxy,
                sentinel,
                variables.clone(),
                usage_plans.clone(),
                &mut sentinel_matched_routes,
            )?);
        }
    }
    ensure_unique_proxy_topology(&proxies)?;
    sentinel.ensure_all_matched(&sentinel_matched_routes)?;
    Ok(proxies)
}

fn build_legacy_proxy(
    cfg_path: &Path,
    server: &ServerCfg,
    routes: &[model::RouteCfg],
    sentinel: &SentinelRouteFilters,
    variables: Arc<VariablePlan>,
    usage_plans: Arc<crate::routing::UsagePlanCatalog>,
    sentinel_matched_routes: &mut HashSet<String>,
) -> Result<ProxyRuntime> {
    build_proxy_from_parts(
        cfg_path,
        "default",
        &server.listen,
        true,
        &server.tls,
        &server.http3,
        &[],
        &[],
        &server.trusted_proxies,
        &ProxyProtocolCfg::default(),
        &server.limits,
        &server.timeouts,
        routes,
        false, // 旧版 server 配置不支持 redirect_https/hsts(用 proxies[] 才有)
        308,
        0,
        sentinel,
        variables,
        usage_plans,
        sentinel_matched_routes,
    )
}

fn build_proxy(
    cfg_path: &Path,
    proxy: &ProxyCfg,
    sentinel: &SentinelRouteFilters,
    variables: Arc<VariablePlan>,
    usage_plans: Arc<crate::routing::UsagePlanCatalog>,
    sentinel_matched_routes: &mut HashSet<String>,
) -> Result<ProxyRuntime> {
    build_proxy_from_parts(
        cfg_path,
        &proxy.id,
        &proxy.listen,
        proxy.plain_enabled,
        &proxy.tls,
        &proxy.http3,
        &proxy.server_names,
        &proxy.gateway_listeners,
        &proxy.trusted_proxies,
        &proxy.proxy_protocol,
        &proxy.limits,
        &proxy.timeouts,
        &proxy.routes,
        proxy.redirect_https,
        proxy.redirect_https_status,
        proxy.hsts_max_age,
        sentinel,
        variables,
        usage_plans,
        sentinel_matched_routes,
    )
}

/// 校验并编译一个 TLS listener 的 ACME 配置。
///
/// # 参数
/// - `cfg_path`: 主配置路径，用于解析 account secret 相对路径。
/// - `proxy_id`: 错误上下文中的 proxy 标识。
/// - `cfg`: yml 反序列化得到的 ACME 配置。
///
/// 返回：只含规范化值和绝对路径的 worker 配置；危险/不完整配置直接拒绝整个候选快照上线。
fn build_acme_runtime(cfg_path: &Path, proxy_id: &str, cfg: &AcmeCfg) -> Result<AcmeRuntimeCfg> {
    let challenge = match cfg.challenge.trim().to_ascii_lowercase().as_str() {
        "http-01" | "http01" => AcmeChallenge::Http01,
        "dns-01" | "dns01" => AcmeChallenge::Dns01,
        other => anyhow::bail!(
            "proxy `{proxy_id}` tls.acme.challenge must be http-01|dns-01; got `{other}`"
        ),
    };
    if cfg.bootstrap_http01_only && challenge != AcmeChallenge::Http01 {
        anyhow::bail!(
            "proxy `{proxy_id}` bootstrap_http01_only is only valid with challenge=http-01; use bootstrap_without_seed for DNS-01"
        );
    }
    if cfg.domains.is_empty() {
        anyhow::bail!("proxy `{proxy_id}` tls.acme.domains must not be empty");
    }
    anyhow::ensure!(
        cfg.renew_before_days <= 3650,
        "proxy `{proxy_id}` tls.acme.renew_before_days must be 0..=3650"
    );
    anyhow::ensure!(
        cfg.domains.len() <= 100,
        "proxy `{proxy_id}` tls.acme.domains supports at most 100 names"
    );
    anyhow::ensure!(
        cfg.contacts.len() <= 32,
        "proxy `{proxy_id}` tls.acme.contacts supports at most 32 entries"
    );
    let mut seen = HashSet::with_capacity(cfg.domains.len());
    let mut domains = Vec::with_capacity(cfg.domains.len());
    for raw in &cfg.domains {
        let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.starts_with("*.") && challenge == AcmeChallenge::Http01 {
            anyhow::bail!(
                "proxy `{proxy_id}` HTTP-01 cannot issue wildcard domain `{domain}`; use a DNS-01 provider"
            );
        }
        if domain.contains('*') && !domain.starts_with("*.") {
            anyhow::bail!("proxy `{proxy_id}` invalid ACME wildcard domain `{domain}`");
        }
        let validation_domain = domain.strip_prefix("*.").unwrap_or(domain.as_str());
        tokio_rustls::rustls::pki_types::ServerName::try_from(validation_domain.to_owned())
            .with_context(|| format!("proxy `{proxy_id}` invalid ACME domain `{domain}`"))?;
        if seen.insert(domain.clone()) {
            domains.push(domain);
        }
    }
    let directory = cfg
        .directory_url
        .parse::<http::Uri>()
        .with_context(|| format!("proxy `{proxy_id}` invalid ACME directory_url"))?;
    if !matches!(directory.scheme_str(), Some("http" | "https")) || directory.authority().is_none()
    {
        anyhow::bail!("proxy `{proxy_id}` ACME directory_url requires http(s) authority");
    }
    let directory_ca_file = cfg
        .directory_ca_file
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(|path| resolve_relative(cfg_path, path));
    if let Some(path) = &directory_ca_file {
        crate::bounded_io::read_file(path, 4 * 1024 * 1024, "ACME directory CA")?;
    }
    if cfg.check_interval_ms == 0
        || cfg.retry_backoff_ms == 0
        || cfg.order_timeout_ms == 0
        || cfg.activation_poll_ms == 0
    {
        anyhow::bail!(
            "proxy `{proxy_id}` ACME check_interval_ms/retry_backoff_ms/order_timeout_ms/activation_poll_ms must be positive"
        );
    }
    for (field, value) in [
        ("check_interval_ms", cfg.check_interval_ms),
        ("retry_backoff_ms", cfg.retry_backoff_ms),
        ("order_timeout_ms", cfg.order_timeout_ms),
        ("activation_poll_ms", cfg.activation_poll_ms),
    ] {
        validate_optional_duration(
            &format!("proxy `{proxy_id}` tls.acme.{field}"),
            value,
            MAX_RUNTIME_DURATION_MS,
        )?;
    }
    let dns01 = match challenge {
        AcmeChallenge::Http01 => {
            if cfg.dns01.is_some() {
                anyhow::bail!(
                    "proxy `{proxy_id}` tls.acme.dns01 is only valid with challenge=dns-01"
                );
            }
            None
        }
        AcmeChallenge::Dns01 => {
            let dns = cfg.dns01.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "proxy `{proxy_id}` challenge=dns-01 requires tls.acme.dns01 provider"
                )
            })?;
            anyhow::ensure!(
                dns.timeout_ms > 0,
                "proxy `{proxy_id}` ACME dns01.timeout_ms must be positive"
            );
            validate_optional_duration(
                &format!("proxy `{proxy_id}` tls.acme.dns01.propagation_delay_ms"),
                dns.propagation_delay_ms,
                MAX_RUNTIME_DURATION_MS,
            )?;
            anyhow::ensure!(
                dns.timeout_ms <= 60 * 60 * 1_000,
                "proxy `{proxy_id}` ACME dns01.timeout_ms must be within 1..=3600000"
            );
            anyhow::ensure!(
                (1..=5).contains(&dns.retry_attempts),
                "proxy `{proxy_id}` ACME dns01.retry_attempts must be within 1..=5"
            );
            anyhow::ensure!(
                dns.retry_backoff_ms <= 30_000,
                "proxy `{proxy_id}` ACME dns01.retry_backoff_ms must be within 0..=30000"
            );
            anyhow::ensure!(
                (1_024..=4 * 1024 * 1024).contains(&dns.max_response_bytes),
                "proxy `{proxy_id}` ACME dns01.max_response_bytes must be within 1024..=4194304"
            );
            anyhow::ensure!(
                (1..=86_400).contains(&dns.ttl_seconds),
                "proxy `{proxy_id}` ACME dns01.ttl_seconds must be within 1..=86400"
            );
            let config_dir = cfg_path.parent().unwrap_or_else(|| Path::new("."));
            let provider = match dns.provider.trim().to_ascii_lowercase().as_str() {
                "command" => {
                    anyhow::ensure!(
                        !dns.command.trim().is_empty(),
                        "proxy `{proxy_id}` ACME dns01.command must not be empty"
                    );
                    anyhow::ensure!(
                        dns.args.len() <= 64,
                        "proxy `{proxy_id}` ACME dns01.args supports at most 64 entries"
                    );
                    AcmeDns01ProviderRuntime::Command {
                        command: resolve_relative(cfg_path, dns.command.trim()),
                        args: dns.args.clone().into(),
                    }
                }
                "cloudflare" => {
                    validate_acme_https_endpoint(
                        proxy_id,
                        "cloudflare_api_base",
                        &dns.cloudflare_api_base,
                    )?;
                    validate_acme_provider_component(
                        proxy_id,
                        "cloudflare_zone_id",
                        &dns.cloudflare_zone_id,
                    )?;
                    let api_token = crate::secret::resolve_text(
                        &dns.cloudflare_api_token,
                        config_dir,
                        "ACME Cloudflare API token",
                    )?;
                    anyhow::ensure!(
                        !api_token.is_empty(),
                        "proxy `{proxy_id}` ACME Cloudflare API token must not be empty"
                    );
                    AcmeDns01ProviderRuntime::Cloudflare {
                        api_base: dns.cloudflare_api_base.trim_end_matches('/').to_owned(),
                        zone_id: dns.cloudflare_zone_id.trim().to_owned(),
                        api_token,
                    }
                }
                "rfc2136" => {
                    let server = dns.rfc2136_server.parse::<std::net::SocketAddr>().with_context(
                        || format!("proxy `{proxy_id}` invalid ACME RFC2136 server"),
                    )?;
                    let zone = normalize_acme_dns_name(proxy_id, "rfc2136_zone", &dns.rfc2136_zone)?;
                    let tsig_key_name = normalize_acme_dns_name(
                        proxy_id,
                        "rfc2136_tsig_key_name",
                        &dns.rfc2136_tsig_key_name,
                    )?;
                    let encoded = crate::secret::resolve_text(
                        &dns.rfc2136_tsig_secret,
                        config_dir,
                        "ACME RFC2136 TSIG secret",
                    )?;
                    let tsig_secret = base64::engine::general_purpose::STANDARD
                        .decode(encoded.trim())
                        .context("decode ACME RFC2136 TSIG secret as Base64")?;
                    anyhow::ensure!(
                        (16..=512).contains(&tsig_secret.len()),
                        "proxy `{proxy_id}` ACME RFC2136 TSIG secret must decode to 16..=512 bytes"
                    );
                    AcmeDns01ProviderRuntime::Rfc2136 {
                        server,
                        zone,
                        tsig_key_name,
                        tsig_secret: tsig_secret.into(),
                    }
                }
                "vault" => {
                    validate_acme_https_endpoint(
                        proxy_id,
                        "vault_endpoint",
                        &dns.vault_endpoint,
                    )?;
                    validate_acme_vault_path(proxy_id, "vault_present_path", &dns.vault_present_path)?;
                    validate_acme_vault_path(proxy_id, "vault_cleanup_path", &dns.vault_cleanup_path)?;
                    let token = crate::secret::resolve_text(
                        &dns.vault_token,
                        config_dir,
                        "ACME Vault token",
                    )?;
                    anyhow::ensure!(
                        !token.is_empty(),
                        "proxy `{proxy_id}` ACME Vault token must not be empty"
                    );
                    anyhow::ensure!(
                        dns.vault_namespace.len() <= 256
                            && !dns.vault_namespace.bytes().any(|byte| byte.is_ascii_control()),
                        "proxy `{proxy_id}` ACME Vault namespace is invalid"
                    );
                    AcmeDns01ProviderRuntime::Vault {
                        endpoint: dns.vault_endpoint.trim_end_matches('/').to_owned(),
                        token,
                        namespace: (!dns.vault_namespace.trim().is_empty())
                            .then(|| dns.vault_namespace.trim().to_owned()),
                        present_path: dns.vault_present_path.trim_start_matches('/').to_owned(),
                        cleanup_path: dns.vault_cleanup_path.trim_start_matches('/').to_owned(),
                    }
                }
                other => anyhow::bail!(
                    "proxy `{proxy_id}` ACME dns01.provider must be command|cloudflare|rfc2136|vault; got `{other}`"
                ),
            };
            Some(AcmeDns01RuntimeCfg {
                provider,
                propagation_delay_ms: dns.propagation_delay_ms,
                timeout_ms: dns.timeout_ms,
                retry_attempts: dns.retry_attempts,
                retry_backoff_ms: dns.retry_backoff_ms,
                max_response_bytes: dns.max_response_bytes,
                ttl_seconds: dns.ttl_seconds,
            })
        }
    };
    let lock_backend = cfg.lock_backend.trim().to_ascii_lowercase();
    if lock_backend != "local" && lock_backend != "redis" {
        anyhow::bail!("proxy `{proxy_id}` ACME lock_backend must be local|redis");
    }
    let storage_mode = cfg.storage_mode.trim().to_ascii_lowercase();
    if storage_mode != "local-file" && storage_mode != "shared-file" {
        anyhow::bail!("proxy `{proxy_id}` ACME storage_mode must be local-file|shared-file");
    }
    if lock_backend == "redis" && storage_mode != "shared-file" {
        anyhow::bail!(
            "proxy `{proxy_id}` distributed ACME requires storage_mode=shared-file so every node observes the issued keypair"
        );
    }
    if cfg.lock_key.trim().is_empty() {
        anyhow::bail!("proxy `{proxy_id}` ACME lock_key must not be empty");
    }
    anyhow::ensure!(
        (2..=64).contains(&cfg.keypair_retention_generations),
        "proxy `{proxy_id}` ACME keypair_retention_generations must be within 2..=64"
    );
    Ok(AcmeRuntimeCfg {
        bootstrap_without_seed: cfg.bootstrap_without_seed || cfg.bootstrap_http01_only,
        directory_url: cfg.directory_url.trim().to_owned(),
        directory_ca_file,
        domains: domains.into(),
        contacts: cfg
            .contacts
            .iter()
            .map(|contact| contact.trim().to_owned())
            .filter(|contact| !contact.is_empty())
            .collect::<Vec<_>>()
            .into(),
        challenge,
        dns01,
        account_credentials_file: resolve_relative(cfg_path, &cfg.account_credentials_file),
        renew_before_days: cfg.renew_before_days,
        check_interval_ms: cfg.check_interval_ms,
        retry_backoff_ms: cfg.retry_backoff_ms,
        order_timeout_ms: cfg.order_timeout_ms,
        activation_poll_ms: cfg.activation_poll_ms,
        lock_backend,
        lock_key: cfg.lock_key.trim().to_owned(),
        storage_mode,
        keypair_retention_generations: cfg.keypair_retention_generations,
    })
}

/// 业务作用：校验内建 ACME HTTP provider 的固定 authority，阻止凭据被明文传输或经 URL 注入外带。
///
/// 参数说明：`proxy_id`/`field` 定位配置；`raw` 是待固定的 endpoint。
///
/// 返回：仅无 userinfo/query/fragment 的 HTTPS 绝对 URL 成功，其它输入拒绝候选快照。
fn validate_acme_https_endpoint(proxy_id: &str, field: &str, raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw.trim())
        .with_context(|| format!("proxy `{proxy_id}` invalid ACME {field}"))?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "proxy `{proxy_id}` ACME {field} must be an HTTPS URL without credentials, query or fragment"
    );
    Ok(())
}

/// 业务作用：限制会进入 Cloudflare URL path 的租户标识，避免路径重解释与无界日志字段。
///
/// 参数说明：`proxy_id`/`field` 定位配置；`raw` 是单个 path component。
///
/// 返回：1..=128 个安全 ASCII 字符时成功，否则拒绝配置。
fn validate_acme_provider_component(proxy_id: &str, field: &str, raw: &str) -> Result<()> {
    let value = raw.trim();
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "proxy `{proxy_id}` ACME {field} is invalid"
    );
    Ok(())
}

/// 业务作用：规范化 RFC2136 zone/key name，使 UPDATE 和 TSIG MAC 使用唯一 wire 表示。
///
/// 参数说明：`proxy_id`/`field` 定位配置；`raw` 是 DNS name。
///
/// 返回：合法有界 DNS name 的小写无尾点形式；空 label、过长 label 或非法字符失败。
fn normalize_acme_dns_name(proxy_id: &str, field: &str, raw: &str) -> Result<String> {
    let value = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            }),
        "proxy `{proxy_id}` ACME {field} is not a valid DNS name"
    );
    Ok(value)
}

/// 业务作用：限制 Vault action path 只能停留在已配置 HTTPS authority 内。
///
/// 参数说明：`proxy_id`/`field` 定位配置；`raw` 是相对 API path。
///
/// 返回：非空、无 traversal/query/fragment 的有界相对路径成功，否则拒绝。
fn validate_acme_vault_path(proxy_id: &str, field: &str, raw: &str) -> Result<()> {
    let value = raw.trim().trim_start_matches('/');
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 1024
            && !value.contains('?')
            && !value.contains('#')
            && value
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != ".."),
        "proxy `{proxy_id}` ACME {field} must be a bounded relative path without traversal"
    );
    Ok(())
}

/// 业务作用：编译 Gateway API HTTPS 逻辑 listener 选择表，保证 SNI 与 Host 比较使用
/// 唯一、规范化且确定的权威边界。
///
/// 参数说明：`proxy_id` 标识错误归属；`listeners` 是控制面生成的 listener 身份与 hostname。
///
/// 返回：配置唯一且 hostname 合法时返回运行期表；重复身份、重复 hostname 或非法通配时拒绝配置。
fn build_gateway_listener_runtime(
    proxy_id: &str,
    listeners: &[model::GatewayListenerCfg],
) -> Result<Vec<GatewayListenerRuntime>> {
    anyhow::ensure!(
        listeners.len() <= 128,
        "proxy `{proxy_id}` exceeds 128 Gateway listeners"
    );
    let mut ids = HashSet::new();
    let mut hostnames = HashSet::new();
    let mut output = Vec::with_capacity(listeners.len());
    for listener in listeners {
        let id = listener.id.trim();
        anyhow::ensure!(
            !id.is_empty() && id.len() <= 253,
            "proxy `{proxy_id}` Gateway listener id is invalid"
        );
        anyhow::ensure!(
            ids.insert(id.to_owned()),
            "proxy `{proxy_id}` has duplicate Gateway listener id `{id}`"
        );
        let hostname = listener
            .hostname
            .as_deref()
            .map(normalize_sni)
            .transpose()?;
        if let Some(hostname) = hostname.as_deref() {
            anyhow::ensure!(
                !hostname.contains('*')
                    || hostname.starts_with("*.") && !hostname[2..].contains('*'),
                "proxy `{proxy_id}` Gateway listener hostname `{hostname}` has invalid wildcard"
            );
        }
        anyhow::ensure!(
            hostnames.insert(hostname.clone()),
            "proxy `{proxy_id}` has duplicate Gateway listener hostname"
        );
        output.push(GatewayListenerRuntime {
            id: Arc::from(id),
            hostname: hostname.map(Arc::from),
        });
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn build_proxy_from_parts(
    cfg_path: &Path,
    id: &str,
    listen: &str,
    plain_enabled: bool,
    tls: &Option<model::TlsCfg>,
    http3: &Http3Cfg,
    server_names: &[String],
    gateway_listeners: &[model::GatewayListenerCfg],
    trusted_proxies: &[String],
    proxy_protocol: &ProxyProtocolCfg,
    limits: &ServerLimitsCfg,
    timeouts: &TimeoutCfg,
    routes: &[model::RouteCfg],
    redirect_https: bool,
    redirect_https_status: u16,
    hsts_max_age: u64,
    sentinel: &SentinelRouteFilters,
    variables: Arc<VariablePlan>,
    usage_plans: Arc<crate::routing::UsagePlanCatalog>,
    sentinel_matched_routes: &mut HashSet<String>,
) -> Result<ProxyRuntime> {
    if id.trim().is_empty() {
        anyhow::bail!("proxy id must not be empty");
    }
    validate_server_limits(id, limits)?;
    validate_timeout_cfg(id, timeouts)?;
    listen
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid proxy `{id}` listen `{listen}`"))?;
    anyhow::ensure!(
        plain_enabled || tls.is_some(),
        "proxy `{id}` plain_enabled=false requires a tls listener"
    );
    let tls = match tls.as_ref() {
        None => None,
        Some(tls) => {
            // 客户端认证模式在构建期收敛，避免未知值把严格校验静默降级。
            let client_auth = match &tls.client_auth {
                None => None,
                Some(ca) => {
                    let (require, allow_untrusted) =
                        match ca.mode.trim().to_ascii_lowercase().as_str() {
                        "require" => (true, false),
                        "optional" => (false, false),
                        "insecure_fallback" => (false, true),
                        other => anyhow::bail!(
                            "proxy `{id}` tls.client_auth.mode must be require|optional|insecure_fallback, got `{other}`"
                        ),
                    };
                    Some(ClientAuthRuntime {
                        require,
                        allow_untrusted,
                        ca_file: resolve_relative(cfg_path, &ca.ca_file),
                    })
                }
            };
            Some(TlsRuntimeCfg {
                listen: tls.listen.clone(),
                cert_file: resolve_relative(cfg_path, &tls.cert_file),
                key_file: resolve_relative(cfg_path, &tls.key_file),
                keypair_manifest_file: tls
                    .keypair_manifest_file
                    .as_deref()
                    .map(|path| resolve_relative(cfg_path, path)),
                certs: tls
                    .certs
                    .iter()
                    .map(|c| SniCertRuntime {
                        // server_name 小写化 + 去尾点,匹配时零分配比较(与 host_allowed 同口径)。
                        server_names: c
                            .server_names
                            .iter()
                            .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
                            .collect(),
                        cert_file: resolve_relative(cfg_path, &c.cert_file),
                        key_file: resolve_relative(cfg_path, &c.key_file),
                    })
                    .collect(),
                client_auth,
                acme: tls
                    .acme
                    .as_ref()
                    .map(|acme| build_acme_runtime(cfg_path, id, acme))
                    .transpose()?,
                in_memory: None,
            })
        }
    };
    if let Some(tls) = &tls {
        tls.listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("invalid proxy `{id}` tls.listen `{}`", tls.listen))?;
    }
    let http3 = build_http3_runtime(id, http3, tls.as_ref(), proxy_protocol, limits)?;
    // HTTP→HTTPS 跳转(§19):派生跳转目标端口 = 本 proxy 的 TLS 监听端口;无 tls 却配 redirect_https → 坏配置拒上线。
    let redirect_https = if redirect_https {
        let tls = tls.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "proxy `{id}` redirect_https=true requires a tls listener to redirect to"
            )
        })?;
        let to_port = tls
            .listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("proxy `{id}` tls.listen for redirect_https"))?
            .port();
        let status = match redirect_https_status {
            301 | 308 => redirect_https_status,
            other => {
                anyhow::bail!("proxy `{id}` redirect_https_status must be 301 or 308, got {other}")
            }
        };
        Some(RedirectHttps { to_port, status })
    } else {
        None
    };
    // HSTS 头预编译(§19):max-age 是数字,拼出的 header 值恒合法。
    let hsts_header = if hsts_max_age > 0 {
        Some(
            http::HeaderValue::from_str(&format!("max-age={hsts_max_age}"))
                .expect("hsts max-age header value is always valid"),
        )
    } else {
        None
    };
    let routes = routes_with_sentinel(routes, sentinel, sentinel_matched_routes);
    let gateway_listeners = build_gateway_listener_runtime(id, gateway_listeners)?;
    let config_dir = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(ProxyRuntime {
        id: id.to_string(),
        listen: listen.to_string(),
        plain_enabled,
        tls,
        http3,
        server_names: Arc::new(server_names.to_vec()),
        gateway_listeners: Arc::new(gateway_listeners),
        proxy_protocol: build_proxy_protocol(proxy_protocol)
            .with_context(|| format!("proxy `{id}` proxy_protocol"))?,
        // 可信前置代理网段构建期解析成 Cidr(review L6),非法即拒配置。
        trusted_proxies: Arc::new(
            net::parse_cidrs(trusted_proxies)
                .with_context(|| format!("proxy `{id}` trusted_proxies"))?,
        ),
        limits: limits.clone(),
        timeouts: timeouts.clone(),
        redirect_https,
        hsts_header,
        router: Arc::new(
            Router::build_with_usage_plans(&routes, variables, config_dir, usage_plans)
                .with_context(|| format!("proxy `{id}` routes"))?,
        ),
    })
}

/// 校验并编译 HTTP/3/QUIC listener 计划。
///
/// 业务作用：在绑定 UDP socket 前拒绝缺 TLS、缺编译 feature、0-RTT、PROXY protocol 语义
/// 分叉和无界预算，确保坏候选不会进入 listener two-phase prepare。
///
/// 参数说明：`proxy_id` 用于错误定位；`cfg` 是声明配置；`tls` 是已规范化 TLS 身份；
/// `proxy_protocol` 是 TCP 前置代理策略；`limits` 是同 proxy 的全局请求资源上限。
///
/// 返回：关闭时返回零值计划；启用且所有安全门通过时返回可直接构造 QUIC transport 的计划，
/// 任一门失败则拒绝整个候选快照并保留 last-known-good。
fn build_http3_runtime(
    proxy_id: &str,
    cfg: &Http3Cfg,
    tls: Option<&TlsRuntimeCfg>,
    proxy_protocol: &ProxyProtocolCfg,
    limits: &ServerLimitsCfg,
) -> Result<Http3RuntimeCfg> {
    if !cfg.enabled {
        return Ok(Http3RuntimeCfg::default());
    }

    #[cfg(not(feature = "http3"))]
    {
        // 默认制品不编译 transport；显式消费只在 feature 形态才使用的参数，保持默认构建
        // `-D warnings` 干净，同时仍在任何 TLS/UDP 副作用前拒绝配置。
        let _ = (tls, proxy_protocol, limits);
        anyhow::bail!(
            "proxy `{proxy_id}` http3.enabled=true requires a binary compiled with feature `http3`"
        );
    }

    #[cfg(feature = "http3")]
    {
        anyhow::ensure!(
            tls.is_some(),
            "proxy `{proxy_id}` http3.enabled=true requires tls; QUIC only permits TLS 1.3"
        );
        // 现有 PROXY protocol parser 是 TCP stream 语义。让 QUIC 悄悄绕过会使同一 proxy 的
        // ACL/rate/audit 得到不同客户端身份，因此在 datagram PROXY v2 profile 落地前拒绝组合。
        anyhow::ensure!(
            !proxy_protocol.enabled,
            "proxy `{proxy_id}` HTTP/3 does not yet support PROXY protocol on QUIC datagrams"
        );
        // Early data 会在连接完全认证前重放请求；首版没有幂等 allowlist/anti-replay ledger，
        // 必须构建期拒绝，不能只在运行时忽略配置制造虚假安全感。
        anyhow::ensure!(
            !cfg.zero_rtt,
            "proxy `{proxy_id}` http3.zero_rtt is not supported; keep it false"
        );
        anyhow::ensure!(
            (1..=31_536_000).contains(&cfg.alt_svc_max_age_seconds),
            "proxy `{proxy_id}` http3.alt_svc_max_age_seconds must be within 1..=31536000"
        );
        validate_optional_duration(
            &format!("proxy `{proxy_id}` http3.max_idle_timeout_ms"),
            cfg.max_idle_timeout_ms,
            MAX_RUNTIME_DURATION_MS,
        )?;
        anyhow::ensure!(
            cfg.max_idle_timeout_ms > 0,
            "proxy `{proxy_id}` http3.max_idle_timeout_ms must be within 1..={MAX_RUNTIME_DURATION_MS}"
        );
        anyhow::ensure!(
            (1..=10_000_000).contains(&cfg.max_connections),
            "proxy `{proxy_id}` http3.max_connections must be within 1..=10000000"
        );
        anyhow::ensure!(
            (1..=10_000_000).contains(&cfg.max_connections_per_ip),
            "proxy `{proxy_id}` http3.max_connections_per_ip must be within 1..=10000000"
        );
        anyhow::ensure!(
            (1..=1_000_000).contains(&cfg.max_pending_handshakes),
            "proxy `{proxy_id}` http3.max_pending_handshakes must be within 1..=1000000"
        );
        anyhow::ensure!(
            (1200..=1024 * 1024).contains(&cfg.max_pending_handshake_bytes),
            "proxy `{proxy_id}` http3.max_pending_handshake_bytes must be within 1200..=1048576"
        );
        anyhow::ensure!(
            (cfg.max_pending_handshakes as u128)
                .saturating_mul(u128::from(cfg.max_pending_handshake_bytes))
                <= 512 * 1024 * 1024,
            "proxy `{proxy_id}` HTTP/3 pending handshake memory budget must not exceed 536870912 bytes"
        );
        anyhow::ensure!(
            (1..=1_000_000).contains(&cfg.max_bidi_streams_per_connection),
            "proxy `{proxy_id}` http3.max_bidi_streams_per_connection must be within 1..=1000000"
        );
        anyhow::ensure!(
            (8 * 1024..=16 * 1024 * 1024).contains(&cfg.max_request_header_bytes),
            "proxy `{proxy_id}` http3.max_request_header_bytes must be within 8192..=16777216"
        );
        anyhow::ensure!(
            cfg.max_request_header_bytes <= limits.max_header_bytes,
            "proxy `{proxy_id}` http3.max_request_header_bytes cannot exceed limits.max_header_bytes"
        );
        anyhow::ensure!(
            (4 * 1024..=1024 * 1024 * 1024).contains(&cfg.max_stream_buffer_bytes),
            "proxy `{proxy_id}` http3.max_stream_buffer_bytes must be within 4096..=1073741824"
        );
        anyhow::ensure!(
            (1..=60).contains(&cfg.retry_token_lifetime_seconds),
            "proxy `{proxy_id}` http3.retry_token_lifetime_seconds must be within 1..=60"
        );
        anyhow::ensure!(
            (60..=86_400).contains(&cfg.retry_token_rotation_seconds),
            "proxy `{proxy_id}` http3.retry_token_rotation_seconds must be within 60..=86400"
        );
        anyhow::ensure!(
            cfg.retry_token_rotation_seconds
                >= cfg.retry_token_lifetime_seconds.saturating_mul(2),
            "proxy `{proxy_id}` http3.retry_token_rotation_seconds must be at least twice retry_token_lifetime_seconds"
        );
        let alt_svc_header = if cfg.advertise_alt_svc {
            let tls_listen: std::net::SocketAddr = tls
                .expect("HTTP/3 TLS presence checked above")
                .listen
                .parse()
                .with_context(|| {
                    format!("proxy `{proxy_id}` HTTP/3 cannot derive Alt-Svc from tls.listen")
                })?;
            Some(
                http::HeaderValue::from_str(&format!(
                    "h3=\":{}\"; ma={}",
                    tls_listen.port(),
                    cfg.alt_svc_max_age_seconds
                ))
                .with_context(|| format!("proxy `{proxy_id}` HTTP/3 Alt-Svc header"))?,
            )
        } else {
            None
        };
        Ok(Http3RuntimeCfg {
            enabled: true,
            advertise_alt_svc: cfg.advertise_alt_svc,
            alt_svc_header,
            max_idle_timeout_ms: cfg.max_idle_timeout_ms,
            max_connections: cfg.max_connections,
            max_connections_per_ip: cfg.max_connections_per_ip,
            max_pending_handshakes: cfg.max_pending_handshakes,
            max_pending_handshake_bytes: cfg.max_pending_handshake_bytes,
            max_bidi_streams_per_connection: cfg.max_bidi_streams_per_connection,
            max_request_header_bytes: cfg.max_request_header_bytes,
            max_stream_buffer_bytes: cfg.max_stream_buffer_bytes,
            retry: cfg.retry,
            retry_token_lifetime_seconds: cfg.retry_token_lifetime_seconds,
            retry_token_rotation_seconds: cfg.retry_token_rotation_seconds,
            zero_rtt: false,
        })
    }
}

fn validate_timeout_cfg(proxy_id: &str, timeouts: &TimeoutCfg) -> Result<()> {
    for (field, value) in [
        (
            "upstream_ttfb_timeout_ms",
            timeouts.upstream_ttfb_timeout_ms,
        ),
        ("header_read_timeout_ms", timeouts.header_read_timeout_ms),
        ("connection_timeout_ms", timeouts.connection_timeout_ms),
        ("stream_idle_timeout_ms", timeouts.stream_idle_timeout_ms),
        (
            "downstream_write_timeout_ms",
            timeouts.downstream_write_timeout_ms,
        ),
        (
            "websocket_idle_timeout_ms",
            timeouts.websocket_idle_timeout_ms,
        ),
        (
            "websocket_max_lifetime_ms",
            timeouts.websocket_max_lifetime_ms,
        ),
        ("drain_timeout_ms", timeouts.drain_timeout_ms),
    ] {
        validate_optional_duration(
            &format!("proxy `{proxy_id}` timeouts.{field}"),
            value,
            MAX_RUNTIME_DURATION_MS,
        )?;
    }
    Ok(())
}

fn validate_server_limits(proxy_id: &str, limits: &ServerLimitsCfg) -> Result<()> {
    anyhow::ensure!(
        limits.max_connections <= 10_000_000,
        "proxy `{proxy_id}` limits.max_connections must be 0..=10000000"
    );
    anyhow::ensure!(
        (1..=32_768).contains(&limits.max_headers),
        "proxy `{proxy_id}` limits.max_headers must be within 1..=32768"
    );
    anyhow::ensure!(
        (8 * 1024..=16 * 1024 * 1024).contains(&limits.max_header_bytes),
        "proxy `{proxy_id}` limits.max_header_bytes must be within 8192..=16777216"
    );
    anyhow::ensure!(
        limits.max_body_bytes == 0 || limits.max_body_bytes <= 1024 * 1024 * 1024 * 1024,
        "proxy `{proxy_id}` limits.max_body_bytes must be 0 or <=1099511627776"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&limits.max_concurrent_streams),
        "proxy `{proxy_id}` limits.max_concurrent_streams must be within 1..=1000000"
    );
    const H2_MAX_FLOW_CONTROL_WINDOW: u32 = 0x7fff_ffff;
    anyhow::ensure!(
        (1..=H2_MAX_FLOW_CONTROL_WINDOW).contains(&limits.h2_initial_stream_window_bytes),
        "proxy `{proxy_id}` limits.h2_initial_stream_window_bytes must be within 1..=2147483647"
    );
    anyhow::ensure!(
        (1..=H2_MAX_FLOW_CONTROL_WINDOW).contains(&limits.h2_initial_connection_window_bytes),
        "proxy `{proxy_id}` limits.h2_initial_connection_window_bytes must be within 1..=2147483647"
    );
    anyhow::ensure!(
        limits.max_path_bytes <= 1024 * 1024,
        "proxy `{proxy_id}` limits.max_path_bytes must be 0..=1048576"
    );
    anyhow::ensure!(
        limits.max_path_segments <= 65_536,
        "proxy `{proxy_id}` limits.max_path_segments must be 0..=65536"
    );
    anyhow::ensure!(
        limits.upstream_pending_limit <= 1_000_000,
        "proxy `{proxy_id}` limits.upstream_pending_limit must be 0..=1000000"
    );
    anyhow::ensure!(
        limits.pool_max_per_upstream <= 65_536,
        "proxy `{proxy_id}` limits.pool_max_per_upstream must be 0..=65536"
    );
    anyhow::ensure!(
        (1..=64).contains(&limits.h2_connection_shards_per_upstream),
        "proxy `{proxy_id}` limits.h2_connection_shards_per_upstream must be within 1..=64"
    );
    anyhow::ensure!(
        limits.pool_max_connections_per_upstream <= 65_536,
        "proxy `{proxy_id}` limits.pool_max_connections_per_upstream must be 0..=65536"
    );
    validate_optional_duration(
        &format!("proxy `{proxy_id}` limits.pool_idle_timeout_ms"),
        limits.pool_idle_timeout_ms,
        MAX_RUNTIME_DURATION_MS,
    )?;
    validate_optional_duration(
        &format!("proxy `{proxy_id}` limits.old_pool_retain_ms"),
        limits.old_pool_retain_ms,
        MAX_RUNTIME_DURATION_MS,
    )?;
    Ok(())
}

fn validate_optional_duration(field: &str, value: u64, max: u64) -> Result<()> {
    anyhow::ensure!(value <= max, "{field} must be 0..={max}");
    Ok(())
}

fn routes_with_sentinel(
    routes: &[model::RouteCfg],
    sentinel: &SentinelRouteFilters,
    sentinel_matched_routes: &mut HashSet<String>,
) -> Vec<model::RouteCfg> {
    routes
        .iter()
        .map(|route| {
            let mut route = route.clone();
            if let Some(extra) = sentinel.by_route.get(&route.id) {
                route.filters.extend(extra.iter().cloned());
                sentinel_matched_routes.insert(route.id.clone());
            }
            route
        })
        .collect()
}

fn build_proxy_protocol(cfg: &ProxyProtocolCfg) -> Result<ProxyProtocolRuntimeCfg> {
    let allow_v1 =
        cfg.versions.is_empty() || cfg.versions.iter().any(|v| v.eq_ignore_ascii_case("v1"));
    let allow_v2 =
        cfg.versions.is_empty() || cfg.versions.iter().any(|v| v.eq_ignore_ascii_case("v2"));
    for v in &cfg.versions {
        if !v.eq_ignore_ascii_case("v1") && !v.eq_ignore_ascii_case("v2") {
            anyhow::bail!("unsupported PROXY protocol version `{v}`");
        }
    }
    if cfg.enabled && !allow_v1 && !allow_v2 {
        anyhow::bail!("no accepted PROXY protocol versions");
    }
    if cfg.enabled && cfg.accept_from.is_empty() {
        anyhow::bail!("enabled listener must configure proxy_protocol.accept_from");
    }
    if cfg.enabled && !(1..=60_000).contains(&cfg.timeout_ms) {
        anyhow::bail!("enabled proxy_protocol.timeout_ms must be within 1..=60000");
    }
    Ok(ProxyProtocolRuntimeCfg {
        enabled: cfg.enabled,
        allow_v1,
        allow_v2,
        // 构建期把 accept_from 解析成 Cidr(替代原先每连接 parse 一次字符串)。
        accept_from: Arc::new(net::parse_cidrs(&cfg.accept_from).context("accept_from")?),
        timeout_ms: cfg.timeout_ms,
    })
}

fn ensure_unique_proxy_topology(proxies: &[ProxyRuntime]) -> Result<()> {
    let mut ids = std::collections::HashSet::with_capacity(proxies.len());
    let mut listens = std::collections::HashSet::with_capacity(proxies.len() * 2);
    for proxy in proxies {
        if !ids.insert(proxy.id.as_str()) {
            anyhow::bail!("duplicate proxy id `{}`", proxy.id);
        }
        if proxy.plain_enabled && !listens.insert(proxy.listen.as_str()) {
            anyhow::bail!("duplicate proxy listen `{}`", proxy.listen);
        }
        if let Some(tls) = &proxy.tls {
            if !listens.insert(tls.listen.as_str()) {
                anyhow::bail!("duplicate proxy tls.listen `{}`", tls.listen);
            }
        }
    }
    Ok(())
}

/// 解析并校验配置 schema 版本(§6):
/// - 缺省 / `0` → 视作 **`DEFAULT_SCHEMA_VERSION`(v1)** 并告警(不阻塞老配置,但提醒显式声明,便于长期迁移);
/// - 高于当前支持版本 → **拒绝**(不带病解析未知格式,交由调用方保留旧快照);
/// - 其它显式低版本原样返回,后续由迁移逻辑处理。
fn resolve_schema_version(raw: Option<u32>, file: &str) -> Result<u32> {
    match raw {
        None => {
            tracing::warn!(
                file,
                "config has no `schema_version`; assuming {DEFAULT_SCHEMA_VERSION}(建议显式声明,便于长期迁移)"
            );
            Ok(DEFAULT_SCHEMA_VERSION)
        }
        Some(0) => {
            tracing::warn!(file, "`schema_version: 0` invalid; assuming {DEFAULT_SCHEMA_VERSION}");
            Ok(DEFAULT_SCHEMA_VERSION)
        }
        Some(v) if v > SUPPORTED_SCHEMA_VERSION => anyhow::bail!(
            "{file}: schema_version {v} is newer than supported {SUPPORTED_SCHEMA_VERSION}; upgrade gateway"
        ),
        Some(v) => Ok(v),
    }
}

pub(crate) fn load_gateway_config(cfg_path: &Path) -> Result<GatewayConfig> {
    // gateway.yml 内既允许普通配置占位符(`${GW_UPSTREAM:http://...}`),也允许 filter DSL 运行期变量
    // (`${remote_addr}` / `${request_id}`)。因此使用 naml 的宽松解析:能解析的配置占位符照常解析,
    // 未命中的运行期变量保留给 gateway 的变量系统解释。
    preflight_config_file(cfg_path, "gateway config")?;
    let mut cfg = loader(cfg_path)
        .preserve_unresolved_placeholders(true)
        .load()
        .with_context(|| format!("load gateway config {}", cfg_path.display()))?;
    expand_config_snippets(&mut cfg, cfg_path, cfg_path)?;
    Ok(cfg)
}

struct SnippetDefinition {
    config: ReusableSnippetCfg,
    source: PathBuf,
}

/// 业务作用：加载并展开主配置的可复用 filter snippet，使后续 Router 只接收普通确定性 DSL。
///
/// 参数说明：`cfg` 是已完成 profile/env 合并的候选；`base_path` 固定相对路径根；`source_path` 用于根定义溯源。
///
/// 返回：全部 import、依赖与 route 引用合法时原地替换 filters；循环、重复展开、越界路径或资源超限返回错误。
fn expand_config_snippets(
    cfg: &mut GatewayConfig,
    base_path: &Path,
    source_path: &Path,
) -> Result<()> {
    let root = base_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .with_context(|| format!("resolve snippet root for {}", base_path.display()))?;
    let root_scope = std::mem::take(&mut cfg.snippets);
    let mut definitions = HashMap::new();
    let mut imported = HashSet::new();
    collect_snippet_scope(
        root_scope,
        &root,
        &root,
        source_path,
        0,
        &mut imported,
        &mut definitions,
    )?;
    let mut snippet_files = imported.into_iter().collect::<Vec<_>>();
    snippet_files.sort();
    cfg.snippet_files = snippet_files;
    for route in &mut cfg.routes {
        route.filters = expand_route_filters(&route.id, &route.filters, &definitions)?;
    }
    for proxy in &mut cfg.proxies {
        for route in &mut proxy.routes {
            route.filters = expand_route_filters(&route.id, &route.filters, &definitions)?;
        }
    }
    Ok(())
}

/// 业务作用：递归读取一个 snippet scope，并把定义连同源文件登记到单一候选 registry。
///
/// 参数说明：`scope` 含当前定义/import；`current_dir` 是本文件目录；`root` 是不可越过的主配置目录。
///
/// 返回：定义成功登记；重复文件/名称、循环、非法路径或容量超限返回错误。
#[allow(clippy::too_many_arguments)]
fn collect_snippet_scope(
    scope: SnippetsCfg,
    current_dir: &Path,
    root: &Path,
    source: &Path,
    depth: usize,
    imported: &mut HashSet<PathBuf>,
    definitions: &mut HashMap<String, SnippetDefinition>,
) -> Result<()> {
    if depth > MAX_SNIPPET_DEPTH {
        bail!(
            "snippet import depth exceeds {MAX_SNIPPET_DEPTH} at {}",
            source.display()
        );
    }
    for (name, config) in scope.definitions {
        validate_snippet_name(&name)?;
        if config.filters.len() > MAX_SNIPPET_FILTERS_PER_DEFINITION
            || config.uses.len() > MAX_SNIPPET_FILTERS_PER_DEFINITION
        {
            bail!(
                "snippet `{name}` in {} exceeds item limit",
                source.display()
            );
        }
        if config.filters.iter().any(|filter| filter.len() > 64 * 1024) {
            bail!(
                "snippet `{name}` in {} contains an oversized filter",
                source.display()
            );
        }
        if definitions.len() >= MAX_SNIPPET_DEFINITIONS {
            bail!("snippet definitions exceed {MAX_SNIPPET_DEFINITIONS}");
        }
        if let Some(previous) = definitions.insert(
            name.clone(),
            SnippetDefinition {
                config,
                source: source.to_path_buf(),
            },
        ) {
            bail!(
                "duplicate snippet `{name}` in {} and {}",
                previous.source.display(),
                source.display()
            );
        }
    }
    for import in scope.imports {
        let relative = Path::new(&import);
        if import.is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            bail!("snippet import `{import}` must be a relative path without parent traversal");
        }
        let path = current_dir.join(relative).canonicalize().with_context(|| {
            format!(
                "resolve snippet import `{import}` from {}",
                source.display()
            )
        })?;
        if !path.starts_with(root) {
            bail!(
                "snippet import {} escapes configuration root",
                path.display()
            );
        }
        if !imported.insert(path.clone()) {
            bail!("snippet import {} is duplicated or cyclic", path.display());
        }
        if imported.len() > MAX_SNIPPET_IMPORTS {
            bail!("snippet imports exceed {MAX_SNIPPET_IMPORTS}");
        }
        let bytes = crate::bounded_io::read_file(&path, MAX_SNIPPET_FILE_BYTES, "snippet import")?;
        let imported_scope: SnippetsCfg = serde_yml::from_slice(&bytes)
            .with_context(|| format!("parse snippet import {}", path.display()))?;
        let directory = path.parent().unwrap_or(root);
        collect_snippet_scope(
            imported_scope,
            directory,
            root,
            &path,
            depth + 1,
            imported,
            definitions,
        )?;
    }
    Ok(())
}

/// 业务作用：校验 snippet 名可安全进入 route DSL 引用和低敏错误上下文。
///
/// 参数说明：`name` 是定义或引用名。
///
/// 返回：1..=128 字节的 ASCII 标识成功，其它返回错误。
fn validate_snippet_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("invalid snippet name `{name}`");
    }
    Ok(())
}

/// 业务作用：把一条 route 的 snippet 引用按声明顺序展开为普通 filters，并阻止同一片段重复生效。
///
/// 参数说明：`route_id` 用于错误定位；`filters` 是 route 原声明；`definitions` 是带来源 registry。
///
/// 返回：有界、无引用的 filter 列表；未知、循环、菱形重复或展开超限返回错误。
fn expand_route_filters(
    route_id: &str,
    filters: &[String],
    definitions: &HashMap<String, SnippetDefinition>,
) -> Result<Vec<String>> {
    let mut output = Vec::new();
    let mut active = Vec::new();
    let mut expanded = HashSet::new();
    for filter in filters {
        if let Some(name) = parse_snippet_reference(filter)? {
            expand_named_snippet(
                route_id,
                name,
                definitions,
                &mut active,
                &mut expanded,
                &mut output,
            )?;
        } else {
            output.push(filter.clone());
        }
        enforce_expanded_snippet_budget(route_id, &output)?;
    }
    Ok(output)
}

/// 业务作用：递归展开单个命名片段，使用 active/expanded 两套集合区分循环与重复应用。
///
/// 参数说明：route/name 确定引用；registry 提供来源；其余集合与 output 属于当前 route 展开事务。
///
/// 返回：成功把依赖和 filters 追加到 output；失败不发布候选快照。
fn expand_named_snippet(
    route_id: &str,
    name: &str,
    definitions: &HashMap<String, SnippetDefinition>,
    active: &mut Vec<String>,
    expanded: &mut HashSet<String>,
    output: &mut Vec<String>,
) -> Result<()> {
    validate_snippet_name(name)?;
    if active.iter().any(|current| current == name) {
        bail!(
            "route `{route_id}` snippet cycle: {} -> {name}",
            active.join(" -> ")
        );
    }
    if !expanded.insert(name.to_owned()) {
        bail!("route `{route_id}` expands snippet `{name}` more than once");
    }
    let definition = definitions
        .get(name)
        .with_context(|| format!("route `{route_id}` references unknown snippet `{name}`"))?;
    active.push(name.to_owned());
    for dependency in &definition.config.uses {
        expand_named_snippet(route_id, dependency, definitions, active, expanded, output)
            .with_context(|| {
                format!(
                    "snippet `{name}` from {} depends on `{dependency}`",
                    definition.source.display()
                )
            })?;
    }
    for filter in &definition.config.filters {
        if let Some(dependency) = parse_snippet_reference(filter)? {
            expand_named_snippet(route_id, dependency, definitions, active, expanded, output)?;
        } else {
            output.push(filter.clone());
        }
        enforce_expanded_snippet_budget(route_id, output)?;
    }
    active.pop();
    Ok(())
}

/// 业务作用：识别 route filter 位置唯一合法的 snippet 引用语法，不把相似普通指令误展开。
///
/// 参数说明：`filter` 是一条原始 filter DSL。
///
/// 返回：`snippet <name>`/`use_snippet <name>` 返回名称；普通 filter 返回 None；畸形引用返回错误。
fn parse_snippet_reference(filter: &str) -> Result<Option<&str>> {
    let mut tokens = filter.split_whitespace();
    let Some(command) = tokens.next() else {
        return Ok(None);
    };
    if !matches!(command, "snippet" | "use_snippet") {
        return Ok(None);
    }
    let name = tokens.next().context("snippet reference requires a name")?;
    if tokens.next().is_some() {
        bail!("snippet reference accepts exactly one name");
    }
    Ok(Some(name))
}

/// 业务作用：限制单 route 展开后的 filter 数量与文本总量，防止小引用图放大候选内存与构建成本。
///
/// 参数说明：`route_id` 用于错误定位；`filters` 是当前已展开前缀。
///
/// 返回：预算内成功；数量或累计字节超限返回错误。
fn enforce_expanded_snippet_budget(route_id: &str, filters: &[String]) -> Result<()> {
    if filters.len() > MAX_EXPANDED_FILTERS_PER_ROUTE
        || filters
            .iter()
            .try_fold(0usize, |total, filter| total.checked_add(filter.len()))
            .is_none_or(|bytes| bytes > MAX_EXPANDED_FILTER_BYTES_PER_ROUTE)
    {
        bail!("route `{route_id}` expanded snippets exceed filter budget");
    }
    Ok(())
}

fn load_interface_guard(main_cfg: &Path, guard_file: &str) -> Result<InterfaceGuard> {
    let path = resolve_relative(main_cfg, guard_file);
    if !path.exists() {
        anyhow::bail!(
            "interface guard file {} does not exist; create an empty guard file or fix `interface_guard_file`",
            path.display()
        );
    }
    preflight_config_file(&path, "interface guard")?;
    let gf: GuardFile = loader(&path)
        .load()
        .with_context(|| format!("load interface guard {}", path.display()))?;
    // 按文件校验守卫配置的 schema 版本(§6):过新即拒绝,保留旧快照。
    resolve_schema_version(gf.schema_version, "interface-guard.yml")?;
    InterfaceGuard::build(gf)
        .with_context(|| format!("build interface guard from {}", path.display()))
}

struct SentinelRouteFilters {
    by_route: HashMap<String, Vec<String>>,
}

impl SentinelRouteFilters {
    fn ensure_all_matched(&self, matched: &HashSet<String>) -> Result<()> {
        for route in self.by_route.keys() {
            if !matched.contains(route) {
                anyhow::bail!("sentinel flow rule references missing route `{route}`");
            }
        }
        Ok(())
    }
}

fn load_sentinel_rules(main_cfg: &Path, sentinel_file: &str) -> Result<SentinelRouteFilters> {
    let path = resolve_relative(main_cfg, sentinel_file);
    if !path.exists() {
        anyhow::bail!(
            "sentinel rules file {} does not exist; create an empty sentinel rules file or fix `sentinel_rules_file`",
            path.display()
        );
    }
    preflight_config_file(&path, "sentinel rules")?;
    let sf: SentinelFile = loader(&path)
        .load()
        .with_context(|| format!("load sentinel rules {}", path.display()))?;
    resolve_schema_version(sf.schema_version, "sentinel-rules.yml")?;
    let mut by_route: HashMap<String, Vec<String>> = HashMap::new();
    for rule in sf.flow {
        if !rule.enabled {
            continue;
        }
        validate_sentinel_token("sentinel flow id", &rule.id)?;
        validate_sentinel_token("sentinel flow route", &rule.route)?;
        validate_sentinel_token("sentinel flow key", &rule.key)?;
        let filter = match (rule.rate.as_ref(), rule.limit) {
            (Some(rate), None) => {
                validate_sentinel_token("sentinel flow rate", rate)?;
                if rule.max_active_keys == 0 {
                    anyhow::bail!(
                        "sentinel flow `{}` max_active_keys must be positive",
                        rule.id
                    );
                }
                let active_keys_fail = match rule.active_keys_fail.as_str() {
                    "open" | "closed" => rule.active_keys_fail.as_str(),
                    other => anyhow::bail!(
                        "sentinel flow `{}` active_keys_fail expects open|closed, got `{other}`",
                        rule.id
                    ),
                };
                format!(
                    "limit_req key={} rate={} burst={} max_active_keys={} active_keys_fail={}",
                    rule.key, rate, rule.burst, rule.max_active_keys, active_keys_fail
                )
            }
            (None, Some(limit)) => {
                if limit == 0 {
                    anyhow::bail!("sentinel flow `{}` limit must be positive", rule.id);
                }
                format!("limit_conn key={} limit={limit}", rule.key)
            }
            (Some(_), Some(_)) => anyhow::bail!(
                "sentinel flow `{}` must configure either `rate` or `limit`, not both",
                rule.id
            ),
            (None, None) => anyhow::bail!(
                "sentinel flow `{}` must configure `rate`(limit_req) or `limit`(limit_conn)",
                rule.id
            ),
        };
        by_route.entry(rule.route).or_default().push(filter);
    }
    for rule in sf.degrade {
        if !rule.enabled {
            continue;
        }
        validate_sentinel_token("sentinel degrade id", &rule.id)?;
        validate_sentinel_token("sentinel degrade route", &rule.route)?;
        if rule.failure_threshold == 0
            || rule.window_ms == 0
            || rule.min_requests == 0
            || rule.break_ms == 0
        {
            anyhow::bail!(
                "sentinel degrade `{}` failure_threshold/window_ms/min_requests/break_ms must be positive",
                rule.id
            );
        }
        http::StatusCode::from_u16(rule.fallback_status).with_context(|| {
            format!(
                "sentinel degrade `{}` invalid fallback_status `{}`",
                rule.id, rule.fallback_status
            )
        })?;
        if rule.fallback_body.trim().is_empty() {
            anyhow::bail!(
                "sentinel degrade `{}` fallback_body must be non-empty",
                rule.id
            );
        }
        let filter = format!(
            "circuit_breaker id={} failure_threshold={} window_ms={} min_requests={} break_ms={} fallback_status={} fallback_body={}",
            rule.id,
            rule.failure_threshold,
            rule.window_ms,
            rule.min_requests,
            rule.break_ms,
            rule.fallback_status,
            rule.fallback_body.replace(' ', "_")
        );
        by_route.entry(rule.route).or_default().push(filter);
    }
    Ok(SentinelRouteFilters { by_route })
}

fn validate_sentinel_token(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        anyhow::bail!("{label} `{value}` must be non-empty and contain no whitespace");
    }
    Ok(())
}

/// 构造 nasa::yml 加载器:主配置 = `path`,profile 文件名按【本文件名】派生
/// (`gateway.yml` → `gateway-{profile}`),避免不同配置文件串用同一 profile。
pub(crate) fn loader(path: &Path) -> nasa::yml::YmlLoader {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    let pattern = dir.join(format!("{stem}-{{profile}}"));
    nasa::yml::YmlLoader::standard()
        .base_file(path)
        .profile_file_pattern(pattern.to_string_lossy().to_string())
}

/// 在交给 naml 按路径解析前执行同一文件句柄的有界预读。
///
/// 这会在常规启动/reload 上阻断超大静态配置；naml 当前仍会为 profile/env 合并重新打开
/// base path，因此依赖层后续还应提供 reader/max-bytes API 来完全消除恶意并发替换竞态。
fn preflight_config_file(path: &Path, kind: &str) -> Result<()> {
    crate::bounded_io::read_file(path, MAX_FINGERPRINT_FILE_BYTES, kind).map(|_| ())
}

/// guard_file 相对主配置文件所在目录解析;绝对路径原样用。
pub(crate) fn resolve_relative(main_cfg: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        main_cfg
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(rel)
    }
}

/// 配置文件内容指纹:用于热重载 worker 跳过编辑器触发的重复事件。
///
/// 指纹只覆盖当前实例的主配置和它声明的 `interface_guard_file`/`sentinel_rules_file`;同目录其它 yml
/// 可能是旁路测试配置或备份文件,不能影响本实例的 reload 判定。事务化配置校验仍由
/// `load_snapshot` 执行,指纹只做去重,不承担完整合法性判断。
pub(crate) fn config_fingerprint(main_cfg: &Path) -> Result<u64> {
    let mut hasher = DefaultHasher::new();
    hash_config_file(&mut hasher, main_cfg)?;

    let cfg = load_gateway_config(main_cfg)?;
    let guard_path = resolve_relative(main_cfg, &cfg.interface_guard_file);
    hash_config_file(&mut hasher, &guard_path)?;
    let sentinel_path = resolve_relative(main_cfg, &cfg.sentinel_rules_file);
    hash_config_file(&mut hasher, &sentinel_path)?;
    let config_dir = main_cfg.parent().unwrap_or_else(|| Path::new("."));
    if let Some(path) = crate::kubernetes_routes::generated_dependency(&cfg, config_dir) {
        hash_optional_config_file(&mut hasher, &path)?;
    }
    for secret_file in collect_secret_dependencies(&cfg, config_dir) {
        hash_config_file(&mut hasher, &secret_file)?;
    }
    for snippet_file in &cfg.snippet_files {
        hash_config_file(&mut hasher, snippet_file)?;
    }

    Ok(hasher.finish())
}

/// 读取声明式配置并返回所有能独立触发 reload 的文件依赖，供 notify watcher 动态对账。
///
/// 主配置本身由 watcher 单独持有；这里覆盖 guard/sentinel、Kubernetes 物化文件以及
/// SecretSource、OpenAPI/Casbin/WASM/外部插件等 route 依赖。只监听其中的精确目标路径，
/// 既保留依赖热更新，又不会把同目录日志和编辑器临时文件误判成配置变更。
pub(crate) fn reload_dependencies(main_cfg: &Path) -> Result<Vec<PathBuf>> {
    let cfg = load_gateway_config(main_cfg)?;
    let config_dir = main_cfg.parent().unwrap_or_else(|| Path::new("."));
    let mut paths = vec![
        resolve_relative(main_cfg, &cfg.interface_guard_file),
        resolve_relative(main_cfg, &cfg.sentinel_rules_file),
    ];
    if let Some(path) = crate::kubernetes_routes::generated_dependency(&cfg, config_dir) {
        paths.push(path);
    }
    paths.extend(collect_secret_dependencies(&cfg, config_dir));
    paths.extend(cfg.snippet_files.iter().cloned());
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// 业务作用：收集当前配置实际依赖的文件型 secret/document，供指纹、reload watcher 与审计同源。
///
/// 参数说明：`cfg` 是已解析配置；`config_dir` 是尚未规范化相对路径的共同基准。
///
/// 返回：去重前的依赖路径集合；调用方按各自需要排序去重，函数不读取文件内容。
fn collect_secret_dependencies(cfg: &model::GatewayConfig, config_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if cfg.control_plane.xds.enabled {
        // xDS trust/identity 虽是不可由远端修改的 bootstrap authority，仍必须进入配置指纹和
        // 文件 watcher；明文 loopback profile 没有 PEM，不能把空路径误当工作目录依赖。
        // HTTPS 内容轮换不改变 owner/path，下一次 ADS reconnect 会有界读取新 PEM。
        paths.extend(
            [
                cfg.control_plane.xds.tls.ca.file.as_str(),
                cfg.control_plane.xds.tls.cert.file.as_str(),
                cfg.control_plane.xds.tls.key.file.as_str(),
            ]
            .into_iter()
            .filter(|path| !path.is_empty())
            .map(PathBuf::from),
        );
    }
    for raw in [
        cfg.admin.auth.bearer_token.as_str(),
        cfg.admin.auth.basic_password.as_str(),
    ] {
        if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
            paths.push(path);
        }
    }
    for principal in &cfg.admin.rbac.principals {
        for raw in [
            principal.bearer_token.as_str(),
            principal.basic_password.as_str(),
        ] {
            if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
                paths.push(path);
            }
        }
    }
    for raw in [
        cfg.admin.audit.signing_key.as_str(),
        cfg.admin.audit.authorization.as_str(),
    ] {
        if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
            paths.push(path);
        }
    }
    for raw in [
        cfg.discovery.nacos.password.as_str(),
        cfg.discovery.consul.token.as_str(),
        cfg.discovery.eureka.password.as_str(),
        cfg.discovery.kubernetes.bearer_token.as_str(),
        cfg.discovery.kubernetes.ca_certificate.as_str(),
    ] {
        if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
            paths.push(path);
        }
    }
    if let Some(path) = crate::secret::dependency_path(
        &cfg.developer_portal.key_applications.authorization_token,
        config_dir,
    ) {
        paths.push(path);
    }
    for proxy in &cfg.proxies {
        let Some(dns) = proxy
            .tls
            .as_ref()
            .and_then(|tls| tls.acme.as_ref())
            .and_then(|acme| acme.dns01.as_ref())
        else {
            continue;
        };
        for raw in [
            dns.cloudflare_api_token.as_str(),
            dns.rfc2136_tsig_secret.as_str(),
            dns.vault_token.as_str(),
        ] {
            if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
                paths.push(path);
            }
        }
    }
    for catalog in &cfg.developer_portal.catalogs {
        let path = Path::new(&catalog.openapi_file);
        paths.push(if path.is_absolute() {
            path.to_path_buf()
        } else {
            config_dir.join(path)
        });
    }
    for route in cfg
        .routes
        .iter()
        .chain(cfg.proxies.iter().flat_map(|proxy| proxy.routes.iter()))
    {
        if let Some(transcoding) = &route.grpc_transcoding {
            let path = Path::new(&transcoding.descriptor_set_file);
            paths.push(if path.is_absolute() {
                path.to_path_buf()
            } else {
                config_dir.join(path)
            });
        }
        for filter in &route.filters {
            paths.extend(crate::secret::filter_dependency_paths(filter, config_dir));
        }
        if let Some(validation) = &route.request_validation {
            for file in [
                validation.head_schema_file.as_deref(),
                validation.body_schema_file.as_deref(),
                validation.openapi_file.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                let path = Path::new(file);
                paths.push(if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    config_dir.join(path)
                });
            }
        }
        if let Some(opa) = &route.opa_authorization {
            paths.extend(crate::opa::dependency_paths(config_dir, opa));
        }
        if let Some(casbin) = &route.casbin_authorization {
            paths.extend(crate::casbin_auth::dependency_paths(config_dir, casbin));
        }
        for plugin in &route.wasm_plugins {
            if let Some(path) = crate::wasm::dependency_path(config_dir, &plugin.module_file) {
                paths.push(path);
            }
        }
        for plugin in &route.external_plugins {
            if let Some(path) = crate::external_plugin::dependency_path(config_dir, plugin) {
                paths.push(path);
            }
        }
        if let Some(dubbo) = &route.dubbo {
            for raw in dubbo.attachments.values() {
                if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
                    paths.push(path);
                }
            }
        }
        if let Some(llm) = &route.llm {
            for model in &llm.models {
                if let Some(path) = crate::secret::dependency_path(&model.api_key, config_dir) {
                    paths.push(path);
                }
            }
            if let Some(cache) = &llm.semantic_cache {
                if let Some(path) =
                    crate::secret::dependency_path(&cache.embedding.api_key, config_dir)
                {
                    paths.push(path);
                }
            }
            if let Some(moderation) = &llm.moderation {
                if let Some(path) = crate::secret::dependency_path(&moderation.api_key, config_dir)
                {
                    paths.push(path);
                }
            }
        }
    }
    for sink in &cfg.access_log.sinks {
        for raw in sink.headers.values() {
            if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn hash_config_file(hasher: &mut DefaultHasher, path: &Path) -> Result<()> {
    // 集群收敛比较的是配置内容，不是每台机器的部署目录。调用方已经按
    // main/guard/sentinel/依赖的固定角色顺序喂入文件；把绝对路径也哈希进去会让
    // 两台内容完全一致、目录不同的节点永久显示 diverged。
    crate::bounded_io::read_file(path, MAX_FINGERPRINT_FILE_BYTES, "config dependency")?
        .hash(hasher);
    Ok(())
}

fn hash_optional_config_file(hasher: &mut DefaultHasher, path: &Path) -> Result<()> {
    match crate::bounded_io::read_optional_file(
        path,
        MAX_FINGERPRINT_FILE_BYTES,
        "optional config dependency",
    )? {
        Some(bytes) => bytes.hash(hasher),
        None => 0_u8.hash(hasher),
    }
    Ok(())
}

#[path = "../../tests/unit/config_mod.rs"]
#[cfg(test)]
mod admin_exposure_tests;
