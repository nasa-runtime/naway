//! 配置的 serde 数据模型(gateway.yml + interface-guard.yml)。

use std::collections::HashMap;

use serde::Deserialize;

// ── 主配置 gateway.yml ──

#[derive(Debug, Deserialize)]
/// `gateway.yml` 顶层 serde 模型；只表达声明式配置，运行期热路径使用构建后的 `GatewaySnapshot`。
pub struct GatewayConfig {
    /// 配置 schema 版本(架构规范 §6):支撑长期演进的迁移/拒绝过新版本。
    /// 缺省(`None`)按 v1 处理并告警,详见 `load_snapshot` 的 `resolve_schema_version`。
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// 旧版单入口配置。新版推荐 `proxies[]`;没有配置 `proxies[]` 时,该字段会兼容生成 default proxy。
    #[serde(default)]
    pub server: Option<ServerCfg>,
    /// 管理/观测面(§14.1):与数据面【端口隔离】,只绑内网,承载 /healthz /readyz(+ 后续 /metrics、admin)。
    #[serde(default)]
    pub admin: AdminCfg,
    /// 多数据面入口(§36.1):每个 proxy 对齐一个 nginx `server{listen ...}`。
    #[serde(default)]
    pub proxies: Vec<ProxyCfg>,
    /// L4 stream 数据面入口(nginx `stream{}` TCP 起步)。
    #[serde(default)]
    pub stream: StreamCfg,
    /// 旧版全局路由。仅当 `proxies[]` 为空时使用,兼容成 default proxy 的 routes。
    #[serde(default)]
    pub routes: Vec<RouteCfg>,
    /// 静态上游定义;`lb://service` 路由从这里选实例。Nacos 等动态注册中心走同一抽象后续接入。
    #[serde(default)]
    pub upstreams: UpstreamsCfg,
    /// 服务发现后端配置。V2-B 接 Nacos watch;其它注册中心后端留到 V7。
    #[serde(default)]
    pub discovery: DiscoveryCfg,
    /// V7 Kubernetes Ingress/Gateway API 路由控制器；远端对象先物化，再走统一快照事务。
    #[serde(default)]
    pub kubernetes_routes: KubernetesRouteSourceCfg,
    /// V7 API 变现/consumer 分级的全局套餐目录。
    #[serde(default)]
    pub usage_plans: UsagePlansCfg,
    /// V7 开发者门户与 OpenAPI API 目录。文档在快照构建期导入并生成普通 route。
    #[serde(default)]
    pub developer_portal: DeveloperPortalCfg,
    /// 统一配置来源。V4 起可从 Nacos 配置中心 watch 网关配置,本地文件仍作为 bootstrap/兜底。
    #[serde(default)]
    pub config_source: ConfigSourceCfg,
    /// 运行态共享后端配置。计数/动态事实源不进入路由 DSL,由运行态面统一装配。
    #[serde(default)]
    pub runtime_state: RuntimeStateCfg,
    /// nginx `set` / `map` / `${...}` 变量系统。构建期编译为 VariablePlan,供 header/filter/后续 upstream 选择复用。
    #[serde(default)]
    pub variables: VariablesCfg,
    /// access log 执行参数。默认非阻塞 bounded queue,队列满丢弃并计数。
    #[serde(default)]
    pub access_log: AccessLogCfg,
    /// V5 OpenTelemetry 链路追踪。导出器/队列属于进程 bootstrap 资源，修改后需重启。
    #[serde(default)]
    pub telemetry: TelemetryCfg,
    /// 热重载控制面资源参数。这些值在启动时创建 worker 时生效，不属于请求热路径。
    #[serde(default)]
    pub reload: ReloadCfg,
    /// WS/gRPC 长连接在配置换版与管理面 drain 时的全局治理策略。
    #[serde(default)]
    pub long_connections: LongConnectionCfg,
    /// V8 gRPC 边缘模式的进程级集群中继面(架构规范 §25.2)。None 或 `mode: none` = 单机,
    /// 不建 peer 连接。V8-0 只做契约校验与快照接线,不启动任何 relay 网络组件。
    #[serde(default)]
    pub grpc_edge_cluster: Option<GrpcEdgeClusterCfg>,
    /// 接口守卫独立配置文件路径(相对主配置目录或绝对);缺省 `interface-guard.yml`。
    #[serde(default = "default_guard_file")]
    pub interface_guard_file: String,
    /// Sentinel 流量防护独立规则文件路径(相对主配置目录或绝对);缺省 `sentinel-rules.yml`。
    #[serde(default = "default_sentinel_rules_file")]
    pub sentinel_rules_file: String,
}

#[derive(Debug, Deserialize, Clone)]
/// 旧版单 HTTP proxy 入口配置；新配置应优先使用 `proxies[]`。
pub struct ServerCfg {
    /// 数据面监听地址(对外流量)。
    pub listen: String,
    /// 可选 TLS 数据面监听。明文与 TLS 是两个 socket,不做同端口 sniffing。
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// 数据面资源上限:请求头/body/h2 stream 等预算必须在执行点生效。
    #[serde(default)]
    pub limits: ServerLimitsCfg,
    /// 数据面超时预算:连接空闲、上游响应头等。
    #[serde(default)]
    pub timeouts: TimeoutCfg,
    /// 可信前置代理网段(据 review L6 / §12);语义同 `ProxyCfg.trusted_proxies`。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

/// 一个数据面入口:独立监听地址、可选 TLS、PROXY protocol、路由表和资源预算。
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyCfg {
    /// 入口唯一标识,用于日志/metrics/reload 拓扑比较。
    pub id: String,
    /// 明文数据面监听地址。
    pub listen: String,
    /// 可选 TLS 监听。明文与 TLS 分 socket。
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// server_name/Host 别名。空表示 default_server。
    #[serde(default)]
    pub server_names: Vec<String>,
    /// 可信前置代理网段(据 review L6 / §12):只有来自这些 CIDR 的直连对端,才信任其
    /// `X-Forwarded-For` / `traceparent` 等入站头(取真实客户端 IP、续用 trace);否则一律用 socket
    /// 对端并重生成 trace,防伪造绕过 IP ACL / 限流 / 审计。空 = 不信任任何 XFF(安全默认)。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// PROXY protocol v1/v2 真实客户端地址解析配置。
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolCfg,
    /// 当前入口的资源上限;缺省继承模型默认值。
    #[serde(default)]
    pub limits: ServerLimitsCfg,
    /// 当前入口的超时预算;缺省继承模型默认值。
    #[serde(default)]
    pub timeouts: TimeoutCfg,
    /// 当前入口下的有序路由表。
    #[serde(default)]
    pub routes: Vec<RouteCfg>,
    /// HTTP→HTTPS 跳转(§19):明文入口收到请求即 3xx 跳到本 proxy 的 TLS 端口
    /// (对齐 nginx `listen 80; return 308 https://$host$request_uri`)。需同时配 `tls`。
    #[serde(default)]
    pub redirect_https: bool,
    /// 跳转状态码,默认 308(永久 + 保持方法);也可 301。仅 `redirect_https=true` 时生效。
    #[serde(default = "default_redirect_https_status")]
    pub redirect_https_status: u16,
    /// HSTS `max-age`(秒);>0 时在【TLS 响应】带 `Strict-Transport-Security`(§19)。
    /// 默认 0=关。HSTS 只在 https 响应上有意义(http 响应带它浏览器会忽略),故只作用于 TLS 入口。
    #[serde(default)]
    pub hsts_max_age: u64,
}

/// PROXY protocol 配置。开启后只信任 `accept_from` 内的直连对端。
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyProtocolCfg {
    /// 是否启用 PROXY protocol 解析。
    #[serde(default)]
    pub enabled: bool,
    /// 接受的协议版本,可写 `v1`/`v2`;空表示二者都接受。
    #[serde(default)]
    pub versions: Vec<String>,
    /// 可信前置 LB/VIP 网段或单 IP。
    #[serde(default)]
    pub accept_from: Vec<String>,
    /// 读取 PROXY 头的超时(ms)。
    #[serde(default = "default_proxy_protocol_timeout_ms")]
    pub timeout_ms: u64,
}

/// L4 stream 配置。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct StreamCfg {
    /// stream listener 列表。每个 listener 独立绑定一个 TCP 端口。
    #[serde(default)]
    pub listeners: Vec<StreamListenerCfg>,
}

/// L4 TCP listener 配置。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamListenerCfg {
    /// listener 唯一标识。
    pub id: String,
    /// 本地监听地址。
    pub listen: String,
    /// L4 传输协议。`tcp` 默认；`udp` 使用按客户端地址隔离的短会话。
    #[serde(default)]
    pub protocol: StreamProtocolCfg,
    /// 可选 stream TLS 终止；与 `preread.ssl_preread` 互斥，因为前者解密、后者透传。
    #[serde(default)]
    pub tls: Option<StreamTlsCfg>,
    /// UDP 短会话资源预算；TCP listener 忽略且必须保持默认值。
    #[serde(default)]
    pub udp: StreamUdpCfg,
    /// 旧版单上游目标。支持 `host:port`、`tcp://host:port` 或 `lb://service`;配置 `routes[]` 时可为空。
    #[serde(default)]
    pub upstream: String,
    /// TLS ClientHello preread 配置,用于不终止 TLS 的 SNI 路由。
    #[serde(default)]
    pub preread: StreamPrereadCfg,
    /// 多 stream route。为空时沿用 listener 级 `upstream` 单路由行为。
    #[serde(default)]
    pub routes: Vec<StreamRouteCfg>,
    /// PROXY protocol v1/v2 真实客户端地址解析配置。
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolCfg,
    /// 发往上游的 PROXY protocol 头配置。默认关闭。
    #[serde(default)]
    pub proxy_protocol_to_upstream: StreamProxyProtocolUpstreamCfg,
    /// 连接上游超时(ms)。
    #[serde(default = "default_stream_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// 会话总超时(ms)。V3 起步用作 copy_bidirectional 的外层超时;0 表示不限制。
    #[serde(default)]
    pub timeout_ms: u64,
}

/// L4 stream preread 配置。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamPrereadCfg {
    /// 是否启用 TLS ClientHello SNI preread。
    #[serde(default)]
    pub ssl_preread: bool,
    /// 解析 MQTT 3.1/3.1.1/5 CONNECT client id，用于精确 route；未开启时零协议解析成本。
    #[serde(default)]
    pub mqtt_connect: bool,
    /// preread 超时(ms)。
    #[serde(default = "default_stream_preread_timeout_ms")]
    pub timeout_ms: u64,
    /// preread 最大字节数。
    #[serde(default = "default_stream_preread_max_bytes")]
    pub max_bytes: usize,
}

impl Default for StreamPrereadCfg {
    fn default() -> Self {
        Self {
            ssl_preread: false,
            mqtt_connect: false,
            timeout_ms: default_stream_preread_timeout_ms(),
            max_bytes: default_stream_preread_max_bytes(),
        }
    }
}

/// L4 stream route。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamRouteCfg {
    /// route 唯一标识。
    pub id: String,
    /// SNI 精确匹配值。为空且 `default=true` 时作为默认路由。
    #[serde(default)]
    pub sni: Option<String>,
    /// MQTT CONNECT client id 精确匹配；与 `sni` 互斥。
    #[serde(default)]
    pub mqtt_client_id: Option<String>,
    /// 是否默认路由。
    #[serde(default)]
    pub default: bool,
    /// 上游目标。支持 `host:port`、`tcp://host:port` 或 `lb://service`。
    pub upstream: String,
    /// 可选 stream 上游 TLS/mTLS profile；`lb://service` 应使用 service 级 `tls`。
    #[serde(default)]
    pub tls: Option<UpstreamTlsCfg>,
}

/// L4 listener 传输协议。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StreamProtocolCfg {
    /// 面向连接的 TCP 字节流。
    #[default]
    Tcp,
    /// 保留报文边界的 UDP 数据报。
    Udp,
}

/// stream TLS 终止配置。证书只在启动/换版时解析，并由 watcher 原子热换。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamTlsCfg {
    /// PEM 证书链文件，相对主配置文件目录解析。
    pub cert_file: String,
    /// 与证书匹配的 PEM 私钥文件，相对主配置文件目录解析。
    pub key_file: String,
    /// 下游 TLS 握手 deadline，防慢 ClientHello 长期占用连接任务。
    #[serde(default = "default_stream_tls_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// 可选 mTLS 客户端 CA，与 L7 `tls.client_auth` 使用同一 require/optional 契约。
    #[serde(default)]
    pub client_auth: Option<ClientAuthCfg>,
}

/// UDP listener 的有界 5-tuple 会话配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamUdpCfg {
    /// 双向都无数据后回收 connected upstream socket。
    #[serde(default = "default_stream_udp_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// 单 listener 最大客户端会话数；满时不再分配 socket。
    #[serde(default = "default_stream_udp_max_sessions")]
    pub max_sessions: usize,
    /// 每会话下行 datagram bounded channel 容量；满时丢当前 datagram，不阻塞 listener。
    #[serde(default = "default_stream_udp_queue_capacity")]
    pub queue_capacity: usize,
    /// 接收单 datagram 缓冲上限；最大 65507，不做 IP fragment/业务消息重组。
    #[serde(default = "default_stream_udp_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
}

impl Default for StreamUdpCfg {
    fn default() -> Self {
        Self {
            idle_timeout_ms: default_stream_udp_idle_timeout_ms(),
            max_sessions: default_stream_udp_max_sessions(),
            queue_capacity: default_stream_udp_queue_capacity(),
            max_datagram_bytes: default_stream_udp_max_datagram_bytes(),
        }
    }
}

const fn default_stream_udp_idle_timeout_ms() -> u64 {
    30_000
}

const fn default_stream_udp_max_sessions() -> usize {
    65_536
}

const fn default_stream_udp_queue_capacity() -> usize {
    64
}

const fn default_stream_udp_max_datagram_bytes() -> usize {
    65_507
}

const fn default_stream_tls_handshake_timeout_ms() -> u64 {
    10_000
}

/// stream 连接上游后写出的 PROXY protocol 头配置。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamProxyProtocolUpstreamCfg {
    /// 是否向上游写 PROXY protocol 头。
    #[serde(default)]
    pub enabled: bool,
    /// 写出版本:`v1` 或 `v2`。
    #[serde(default = "default_stream_proxy_protocol_upstream_version")]
    pub version: String,
}

/// 全局 usage-plan 目录与 consumer→plan 稳定绑定。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct UsagePlansCfg {
    /// 套餐名到固定窗口配额的映射。
    #[serde(default)]
    pub plans: HashMap<String, UsagePlanCfg>,
    /// 已认证 consumer id 到套餐名的稳定绑定。
    #[serde(default)]
    pub consumers: HashMap<String, String>,
}

/// 一个固定窗口请求配额套餐。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UsagePlanCfg {
    /// 每个固定窗口内允许的基础请求数。
    pub requests: u64,
    /// 固定窗口长度，单位毫秒。
    pub window_ms: u64,
    /// 在基础额度之外允许的突发请求数。
    #[serde(default)]
    pub burst: u64,
    /// 本节点为该套餐维护的最大活动 consumer 维度数。
    #[serde(default = "default_usage_plan_max_active_keys")]
    pub max_active_keys: usize,
    /// 维度表达到上限时是否放行；默认 false，配额安全优先。
    #[serde(default)]
    pub active_keys_fail_open: bool,
}

/// V7 开发者门户、API 目录和 OpenAPI 自动路由配置。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct DeveloperPortalCfg {
    /// 总开关；关闭时仍声明 catalog/key application 会被构建期拒绝，避免误以为已发布。
    #[serde(default)]
    pub enabled: bool,
    /// 允许未携带 admin 凭据读取门户页面、catalog 和 OpenAPI 文档。
    #[serde(default)]
    pub public_catalog: bool,
    /// 每份 OpenAPI 原始文件的硬上限。
    #[serde(default = "default_portal_max_document_bytes")]
    pub max_document_bytes: usize,
    /// 导入的 API catalog；每个 operation 物化为普通 gateway route。
    #[serde(default)]
    pub catalogs: Vec<DeveloperCatalogCfg>,
    /// 只创建待审批申请，不在公网请求链直接签发 secret。
    #[serde(default)]
    pub key_applications: DeveloperKeyApplicationsCfg,
}

/// 一份 OpenAPI 文档到一个 HTTP proxy/upstream 的声明式映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeveloperCatalogCfg {
    /// 稳定目录 id，用于 URL 与生成 route id。
    pub id: String,
    /// 门户展示标题；空时读取 OpenAPI `info.title`。
    #[serde(default)]
    pub title: String,
    /// 门户展示描述；空时读取 OpenAPI `info.description`。
    #[serde(default)]
    pub description: String,
    /// OpenAPI 3 JSON/YAML 文件，相对 gateway.yml 解析。
    pub openapi_file: String,
    /// 目标 proxy id；多 proxy 时必填，旧单入口可写 `default`。
    #[serde(default = "default_portal_proxy_id")]
    pub proxy_id: String,
    /// 所有生成 route 的上游 origin (`http(s)://` 或 `lb://`)。
    pub upstream: String,
    /// 附加到每条生成 route 的原生 filter；认证/改写仍走统一 DSL 与构建校验。
    #[serde(default)]
    pub filters: Vec<String>,
    /// 每条生成 route 的 usage-plan 绑定。
    #[serde(default)]
    pub usage_plan: Option<UsagePlanRouteCfg>,
    /// OpenAPI requestBody 校验聚合上限；没有 requestBody 的 operation 保持 head-only。
    #[serde(default = "default_portal_max_validation_body_bytes")]
    pub max_validation_body_bytes: u64,
    /// 生成 route 的顺序。
    #[serde(default)]
    pub order: i32,
}

/// 门户 key 申请入口。它只写一条 pending 申请，真正的 key 签发必须由独立审批面完成。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeveloperKeyApplicationsCfg {
    /// 是否开放开发者 key 申请入口。
    #[serde(default)]
    pub enabled: bool,
    /// 门户专用 Bearer token SecretSource；与 admin/API key 凭据隔离。
    #[serde(default)]
    pub authorization_token: String,
    /// DynamicStore collection，支持 local/file/Redis 后端。
    #[serde(default = "default_portal_key_application_collection")]
    pub collection: String,
    /// 单次 JSON 申请 body 上限。
    #[serde(default = "default_portal_key_application_body_bytes")]
    pub max_body_bytes: usize,
    /// pending key 数量上限；达到上限后拒绝新 applicant，已有 applicant 仍可幂等覆盖。
    #[serde(default = "default_portal_max_pending_applications")]
    pub max_pending: usize,
}

impl Default for DeveloperKeyApplicationsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            authorization_token: String::new(),
            collection: default_portal_key_application_collection(),
            max_body_bytes: default_portal_key_application_body_bytes(),
            max_pending: default_portal_max_pending_applications(),
        }
    }
}

const fn default_portal_max_document_bytes() -> usize {
    8 * 1024 * 1024
}

fn default_portal_proxy_id() -> String {
    "default".to_owned()
}

const fn default_portal_max_validation_body_bytes() -> u64 {
    1024 * 1024
}

fn default_portal_key_application_collection() -> String {
    "developer-key-applications".to_owned()
}

const fn default_portal_key_application_body_bytes() -> usize {
    16 * 1024
}

const fn default_portal_max_pending_applications() -> usize {
    10_000
}

const fn default_usage_plan_max_active_keys() -> usize {
    100_000
}

impl Default for StreamProxyProtocolUpstreamCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            version: default_stream_proxy_protocol_upstream_version(),
        }
    }
}

impl Default for ProxyProtocolCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            versions: Vec::new(),
            accept_from: Vec::new(),
            timeout_ms: default_proxy_protocol_timeout_ms(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
/// 下游 TLS listener 的证书、mTLS 与可选 ACME 配置。
pub struct TlsCfg {
    /// TLS 数据面监听地址。
    pub listen: String,
    /// 【默认】证书链 PEM 文件路径(相对 gateway.yml 所在目录或绝对路径);SNI 不匹配 `certs[]` 时兜底用它。
    pub cert_file: String,
    /// 【默认】私钥 PEM 文件路径(相对 gateway.yml 所在目录或绝对路径)。
    pub key_file: String,
    /// 可选 cert/key pair 原子指针 manifest（相对 gateway.yml 或绝对路径）。配置后，网关优先从
    /// manifest 指向的不可变版本目录加载 `cert.pem` + `key.pem`；manifest 尚不存在时兼容回退
    /// `cert_file`/`key_file`，便于从 seed 证书平滑迁移及 ACME 无 seed 首签。
    #[serde(default)]
    pub keypair_manifest_file: Option<String>,
    /// SNI 多证书(§19):按 ClientHello 的 server_name 选证;不匹配则用上面的默认 cert/key 兜底。
    #[serde(default)]
    pub certs: Vec<SniCertCfg>,
    /// 双向 TLS(mTLS,§19):校验客户端证书。缺省 None = 关闭(不要求客户端证书)。
    #[serde(default)]
    pub client_auth: Option<ClientAuthCfg>,
    /// ACME 自动签发/续期；None 表示完全关闭并只使用静态 cert/key。
    #[serde(default)]
    pub acme: Option<AcmeCfg>,
}

/// ACME 自动证书配置(§19)。
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
    /// DNS-01 provider；challenge=dns-01 时必填。V4 提供有界 command provider，凭据由命令自己的
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
}

/// ACME DNS-01 外部 provider 配置。
///
/// command provider 使用环境变量传递 action/name/value，避免 shell 拼接与 secret 出现在进程 argv。
#[derive(Debug, Deserialize, Clone)]
pub struct AcmeDns01Cfg {
    /// 当前支持 `command`；provider 协议稳定后可扩 Cloudflare/RFC2136 等原生实现。
    #[serde(default = "default_acme_dns01_provider")]
    pub provider: String,
    /// provider 可执行文件路径；直接 exec，不经过 shell。
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
}

/// mTLS 客户端证书校验配置(§19,对齐 nginx `ssl_verify_client` + `ssl_client_certificate`)。
#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthCfg {
    /// `require`(必须出示合法客户端证书,否则握手拒绝)| `optional`(出示了才校验,未出示也放行)。默认 `require`。
    #[serde(default = "default_client_auth_mode")]
    pub mode: String,
    /// 受信任的客户端 CA 证书链 PEM 文件路径(校验客户端证书签名)。
    pub ca_file: String,
}

/// 一组 SNI 证书:命中这些 server_name 的握手用这套 cert/key(§19,对齐 nginx 多 `server{ssl_certificate}`)。
#[derive(Debug, Deserialize, Clone)]
pub struct SniCertCfg {
    /// 匹配的 server_name(SNI):精确(`api.foo.com`)或前缀通配(`*.foo.com`)。
    pub server_names: Vec<String>,
    /// 证书链 PEM 文件路径。
    pub cert_file: String,
    /// 私钥 PEM 文件路径。
    pub key_file: String,
}

/// 单个 HTTP proxy 的资源安全预算。
///
/// 所有字段均来自 yml 且随不可变快照热更；`0` 的关闭语义在字段上显式说明，避免运维调参时
/// 把“无限制”和“禁止”混淆。accept、协议解析与上游发送分别执行对应预算。
#[derive(Debug, Deserialize, Clone)]
pub struct ServerLimitsCfg {
    /// 当前 proxy 的下游 TCP/TLS 物理连接上限。0 表示不限制；accept loop 在达到上限时暂停接收，
    /// 不为排队连接无限创建 task（架构规范 §23）。
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// HTTP/1 头部数量上限。
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    /// HTTP/1 read buffer / HTTP/2 header list 近似上限。
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// 单请求 body 上限,0 表示不限制。
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    /// HTTP/2 单连接最大并发 stream 数。
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    /// HTTP/2 单 stream 初始接收窗口(bytes)。窗口只授予 flow-control credit，不预分配同等
    /// buffer；仍需设上界，避免对端在背压生效前发送过多数据。
    #[serde(default = "default_h2_initial_stream_window_bytes")]
    pub h2_initial_stream_window_bytes: u32,
    /// HTTP/2 单物理连接初始接收窗口(bytes)。默认 1 MiB，减少多 stream 小帧下过密的
    /// WINDOW_UPDATE，同时保持明确的连接级内存/在途字节边界。
    #[serde(default = "default_h2_initial_connection_window_bytes")]
    pub h2_initial_connection_window_bytes: u32,
    /// 参与路由/ACL/guard 的 path 最大字节数。0 表示不限制。
    #[serde(default = "default_max_path_bytes")]
    pub max_path_bytes: usize,
    /// path 最大 segment 数。0 表示不限制；用于阻断超深路径的 CPU 放大。
    #[serde(default = "default_max_path_segments")]
    pub max_path_segments: usize,
    /// 每个上游实例允许的在途请求数。0 表示不限制；满时快速返回 503，不在内存中排队。
    #[serde(default = "default_upstream_pending_limit")]
    pub upstream_pending_limit: usize,
    /// Hyper 每 authority 最多保留的 idle 连接数；0 表示不保留 idle 连接。
    #[serde(default = "default_pool_max_per_upstream")]
    pub pool_max_per_upstream: usize,
    /// 每个 h2/h2c 上游身份的独立连接池分片数。每个分片仍在单连接内多路复用 stream，
    /// 但不同分片不争用 h2 crate 的同一内部 stream mutex；物理连接上限更小时自动下调。
    #[serde(default = "default_h2_connection_shards_per_upstream")]
    pub h2_connection_shards_per_upstream: usize,
    /// 每个结构化上游身份允许的物理 socket 总数。connector 在真正 dial 前占用名额，
    /// transport Drop 时归还；0 表示不限制。
    #[serde(default = "default_pool_max_connections_per_upstream")]
    pub pool_max_connections_per_upstream: usize,
    /// 一个上游 client/pool generation 最多承载的请求数。达到上限后新请求切到新 generation，
    /// 旧 generation 只 drain 已在途请求；0 表示不按请求数轮换。
    #[serde(default = "default_keepalive_requests")]
    pub keepalive_requests: u64,
    /// 上游 idle 连接保留时间(ms)。0 表示不设 idle 超时。
    #[serde(default = "default_pool_idle_timeout_ms")]
    pub pool_idle_timeout_ms: u64,
    /// TLS profile/池参数换版后，旧 client cache 最长保留时间(ms)。在途请求持有自己的 client clone，
    /// cache 淘汰不会中断在途响应。0 表示下一次清理即淘汰未命中的旧池。
    #[serde(default = "default_old_pool_retain_ms")]
    pub old_pool_retain_ms: u64,
}

impl Default for ServerLimitsCfg {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_headers: default_max_headers(),
            max_header_bytes: default_max_header_bytes(),
            max_body_bytes: default_max_body_bytes(),
            max_concurrent_streams: default_max_concurrent_streams(),
            h2_initial_stream_window_bytes: default_h2_initial_stream_window_bytes(),
            h2_initial_connection_window_bytes: default_h2_initial_connection_window_bytes(),
            max_path_bytes: default_max_path_bytes(),
            max_path_segments: default_max_path_segments(),
            upstream_pending_limit: default_upstream_pending_limit(),
            pool_max_per_upstream: default_pool_max_per_upstream(),
            h2_connection_shards_per_upstream: default_h2_connection_shards_per_upstream(),
            pool_max_connections_per_upstream: default_pool_max_connections_per_upstream(),
            keepalive_requests: default_keepalive_requests(),
            pool_idle_timeout_ms: default_pool_idle_timeout_ms(),
            old_pool_retain_ms: default_old_pool_retain_ms(),
        }
    }
}

/// 单个 HTTP proxy 的分层超时策略。
///
/// 普通 HTTP body、WS 隧道与整个物理连接分别计时，避免一个 total timeout 误杀合法长流。
#[derive(Debug, Deserialize, Clone)]
pub struct TimeoutCfg {
    /// 上游响应头超时(ms,TTFB),0 表示不限制。
    #[serde(default = "default_upstream_ttfb_timeout_ms")]
    pub upstream_ttfb_timeout_ms: u64,
    /// 读完整请求头的最长时间(ms,slowloris「只连不发头」防护),0 表示不限制。
    /// ★据 §15.9 全外部配置化,取代原先硬编码的 30s。
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    /// 单连接【总】超时(ms),0 表示不限制。**默认 0(关闭)**:它会硬砍整条连接,
    /// 对 SSE / h2 长流 / 大文件下载会误杀(§23「total_timeout 默认对 streaming 关闭,否则长流被误杀」);
    /// 仅在明确需要「最大连接寿命」时才配。慢客户端防护应走 `header_read_timeout_ms` + 后续 stream_idle_timeout。
    #[serde(default = "default_connection_timeout_ms")]
    pub connection_timeout_ms: u64,
    /// HTTP request/upstream-response body/trailer 两帧之间的最大空闲时间(ms),0 表示关闭。用于慢体
    /// 上传及 SSE/gRPC 上游卡死兜底；下游停止读取由 `downstream_write_timeout_ms` 处理。
    #[serde(default = "default_stream_idle_timeout_ms")]
    pub stream_idle_timeout_ms: u64,
    /// 下游 socket 单次 write/flush/shutdown 持续 Pending 的上限(ms)，0 表示关闭。用于客户端停止
    /// 读取时释放响应流与上游连接；它只在有待写字节时计时，不会误杀空闲但无输出的 SSE/gRPC。
    #[serde(default = "default_downstream_write_timeout_ms")]
    pub downstream_write_timeout_ms: u64,
    /// WebSocket 隧道任一方向最后一次字节活动后的最大空闲时间(ms)，0 表示关闭。
    #[serde(default = "default_websocket_idle_timeout_ms")]
    pub websocket_idle_timeout_ms: u64,
    /// WebSocket 隧道从升级完成起的最长存活时间(ms)，0 表示关闭。
    #[serde(default = "default_websocket_max_lifetime_ms")]
    pub websocket_max_lifetime_ms: u64,
    /// SIGTERM 后等待在途请求完成的最长时间(ms)。
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
}

impl Default for TimeoutCfg {
    fn default() -> Self {
        Self {
            upstream_ttfb_timeout_ms: default_upstream_ttfb_timeout_ms(),
            header_read_timeout_ms: default_header_read_timeout_ms(),
            connection_timeout_ms: default_connection_timeout_ms(),
            stream_idle_timeout_ms: default_stream_idle_timeout_ms(),
            downstream_write_timeout_ms: default_downstream_write_timeout_ms(),
            websocket_idle_timeout_ms: default_websocket_idle_timeout_ms(),
            websocket_max_lifetime_ms: default_websocket_max_lifetime_ms(),
            drain_timeout_ms: default_drain_timeout_ms(),
        }
    }
}

/// 管理/观测面配置(§14.1:与数据面端口隔离,默认只绑内网回环,绝不暴露到数据面端口)。
#[derive(Debug, Deserialize, Clone)]
pub struct AdminCfg {
    /// 管理面监听地址;默认 `127.0.0.1:18080`(只内网可达)。属 bootstrap 层,热更不重绑(§6)。
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// 是否在管理面暴露 `/metrics`(Prometheus);默认 true。metrics 细节属 V2-B。
    #[serde(default = "default_true")]
    pub expose_metrics: bool,
    /// 管理面自身认证(V4):保护 `/readyz`、`/metrics` 与 `/admin/**`;`/healthz` 默认可匿名给容器 liveness。
    #[serde(default)]
    pub auth: AdminAuthCfg,
    /// V5 控制面细粒度授权；关闭时保持 V4 “已认证即管理员”兼容语义。
    #[serde(default)]
    pub rbac: AdminRbacCfg,
    /// V5 管理操作持久、防篡改审计。
    #[serde(default)]
    pub audit: AdminAuditCfg,
    /// UI/API 候选配置 dry-run 的请求体上限；只影响控制面，不改变数据面 body 策略。
    #[serde(default = "default_admin_max_config_body_bytes")]
    pub max_config_body_bytes: usize,
}

impl Default for AdminCfg {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            expose_metrics: true,
            auth: AdminAuthCfg::default(),
            rbac: AdminRbacCfg::default(),
            audit: AdminAuditCfg::default(),
            max_config_body_bytes: default_admin_max_config_body_bytes(),
        }
    }
}

/// 管理面认证配置。
#[derive(Debug, Deserialize, Clone)]
pub struct AdminAuthCfg {
    /// 是否启用管理面认证。默认 false,保持本机内网部署与历史测试兼容;生产暴露 admin/UI 前必须开启。
    #[serde(default)]
    pub enabled: bool,
    /// Bearer token。非空时接受 `Authorization: Bearer <token>`。
    #[serde(default)]
    pub bearer_token: String,
    /// Basic 用户名。与 `basic_password` 同时非空时接受 `Authorization: Basic ...`。
    #[serde(default)]
    pub basic_user: String,
    /// Basic 密码。与 `basic_user` 同时非空时启用 Basic。
    #[serde(default)]
    pub basic_password: String,
    /// Basic challenge realm。
    #[serde(default = "default_admin_auth_realm")]
    pub realm: String,
    /// 是否允许 `/healthz` 匿名访问。默认 true,避免容器 liveness 被凭据轮换误伤。
    #[serde(default = "default_true")]
    pub allow_healthz_unauthenticated: bool,
    /// 允许发起管理面状态变更请求的浏览器 Origin。空列表表示拒绝所有带 Origin/Referer 的写请求；
    /// CLI/服务间请求通常不带这两个浏览器来源头，不受影响。
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// 是否允许本节点用**自己这份 admin 凭据**去抓取同集群其它节点的 `/metrics`(C5)。
    ///
    /// 默认 **false**,必须显式开启。为什么不默认开:
    /// - 它让 admin 从"只被访问"变成"会主动外连",是**攻击面的实质变化**——被打穿的
    ///   admin 可以借它探测内网,必须由运维明示接受;
    /// - 它假设集群各节点**同构配置**(同一份凭据)。该假设在自动化部署下通常成立,
    ///   但不成立时抓取只会 401、不会静默串权,失败如实计入响应而不是伪造零值。
    ///
    /// 凭据只从进程内已解析的配置取,**不接受请求携带的任何凭证**——否则控制面就成了
    /// 一个可被借用的跳板(调用方带什么凭据,网关就拿什么去连内网别的机器)。
    #[serde(default)]
    pub allow_cluster_metrics_scrape: bool,
}

impl Default for AdminAuthCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            bearer_token: String::new(),
            basic_user: String::new(),
            basic_password: String::new(),
            realm: default_admin_auth_realm(),
            allow_healthz_unauthenticated: true,
            allowed_origins: Vec::new(),
            allow_cluster_metrics_scrape: false,
        }
    }
}

/// V5 管理面 RBAC bootstrap 配置。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AdminRbacCfg {
    /// 是否启用 principal 级授权；启用后旧 `admin.auth` 单凭据不能旁路 principal 绑定。
    #[serde(default)]
    pub enabled: bool,
    /// 静态 principal 列表；凭据支持 SecretSource，角色/授权变更随快照热更。
    #[serde(default)]
    pub principals: Vec<AdminPrincipalCfg>,
}

/// 一个可认证的管理端主体及其角色/附加授权。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminPrincipalCfg {
    /// 审计稳定主体 id；不能从请求头直接指定。
    pub id: String,
    /// 此 principal 的 Bearer token SecretSource。
    #[serde(default)]
    pub bearer_token: String,
    /// 此 principal 的 Basic 用户名。
    #[serde(default)]
    pub basic_user: String,
    /// 此 principal 的 Basic 密码 SecretSource。
    #[serde(default)]
    pub basic_password: String,
    /// 内置角色，可组合取权限并集。
    #[serde(default)]
    pub roles: Vec<AdminRole>,
    /// 面向自定义运维分工的附加授权，不会撤销内置角色权限。
    #[serde(default)]
    pub grants: Vec<AdminGrantCfg>,
}

/// 一条自定义 RBAC 授权，表达固定资源域上的动作集合。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminGrantCfg {
    /// 受控资源域。
    pub resource: AdminResource,
    /// 允许动作；空列表在构建期拒绝，防止看似配置但实际无效。
    pub actions: Vec<AdminAction>,
}

/// 架构内置角色；角色只提供权限模板，认证仍绑定到具体 principal。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AdminRole {
    /// 所有资源只读。
    Viewer,
    /// 路由/流控配置的 read、dry-run 与 write。
    Operator,
    /// 接口守卫/ACL/黑名单及 emergency-kill。
    SecuritySre,
    /// 全部资源与动作。
    Admin,
}

/// 管理面资源域；值固定，因此可在快照构建期编译为低成本权限位图。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AdminResource {
    /// 完整配置 bundle、历史与发布状态。
    Config,
    /// HTTP 路由。
    Routes,
    /// 接口守卫与动态 disable。
    InterfaceGuard,
    /// Sentinel 限流/熔断规则。
    Sentinel,
    /// ACL 与黑白名单。
    Acl,
    /// Secret 引用与轮换。
    Secrets,
    /// 消费者与 API key。
    Consumers,
    /// TLS/ACME 证书。
    Certs,
    /// 集群成员、节点操作与指标。
    Cluster,
    /// HTTP response cache。
    Cache,
    /// 长连接 drain/关闭。
    Connections,
    /// 上游服务发现视图。
    Upstreams,
    /// 防篡改操作审计。
    Audit,
}

impl AdminResource {
    /// 固定资源域全集；用于内置角色构建，不依赖用户输入产生动态 label。
    pub const ALL: [Self; 13] = [
        Self::Config,
        Self::Routes,
        Self::InterfaceGuard,
        Self::Sentinel,
        Self::Acl,
        Self::Secrets,
        Self::Consumers,
        Self::Certs,
        Self::Cluster,
        Self::Cache,
        Self::Connections,
        Self::Upstreams,
        Self::Audit,
    ];

    /// 转换为权限位图中的稳定资源序号。
    pub const fn index(self) -> u32 {
        self as u32
    }
}

/// 管理动作按风险递增；emergency-kill 与普通 write 始终分开授权。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AdminAction {
    /// 读取状态或配置。
    Read,
    /// build-only 校验、diff 或 explain。
    DryRun,
    /// 常规配置/运行态写入。
    Write,
    /// 秒级封杀接口、IP 或主动关闭连接。
    EmergencyKill,
    /// 配置回滚。
    Rollback,
}

impl AdminAction {
    /// 每个资源域预留的动作槽数。
    pub const COUNT: u32 = 5;

    /// 转换为权限位图中的稳定动作序号。
    pub const fn index(self) -> u32 {
        self as u32
    }
}

/// 管理操作审计的持久化/外部确认配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminAuditCfg {
    /// 是否启用审计；RBAC 启用时必须同时启用。
    #[serde(default)]
    pub enabled: bool,
    /// 本地 append-only hash-chain spool；相对路径以 gateway.yml 目录为基准。
    #[serde(default = "default_admin_audit_file")]
    pub file: String,
    /// HMAC-SHA256 SecretSource；至少 32 bytes，用于检测离线修改/重排。
    #[serde(default)]
    pub signing_key: String,
    /// 可选外部持久审计 HTTP endpoint；每个写动作在副作用前等待 2xx 确认。
    #[serde(default)]
    pub endpoint: String,
    /// 外部 endpoint 的 Authorization header SecretSource。
    #[serde(default)]
    pub authorization: String,
    /// 外部确认超时。
    #[serde(default = "default_admin_audit_timeout_ms")]
    pub timeout_ms: u64,
    /// 是否每条本地记录 `sync_data`；生产默认 true，避免 OS page cache 丢审计。
    #[serde(default = "default_true")]
    pub fsync: bool,
    /// 单条 canonical JSON 上限。
    #[serde(default = "default_admin_audit_max_record_bytes")]
    pub max_record_bytes: usize,
    /// `/api/audit` 内存保留条数；完整历史仍在持久 spool/外部 sink。
    #[serde(default = "default_admin_audit_history_limit")]
    pub history_limit: usize,
    /// 仅用于开发/单机：显式允许没有外部持久 sink；生产不应开启。
    #[serde(default)]
    pub allow_local_only: bool,
}

impl Default for AdminAuditCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            file: default_admin_audit_file(),
            signing_key: String::new(),
            endpoint: String::new(),
            authorization: String::new(),
            timeout_ms: default_admin_audit_timeout_ms(),
            fsync: true,
            max_record_bytes: default_admin_audit_max_record_bytes(),
            history_limit: default_admin_audit_history_limit(),
            allow_local_only: false,
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
/// 非阻塞 access log 的有界队列、格式、条件与采样配置。
pub struct AccessLogCfg {
    /// 是否启用 access log。关闭后热路径仍构造最小 logger,但直接丢弃记录。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 非阻塞队列长度;队列满丢弃并累加 `gw_log_dropped_total`。0 按默认 4096 处理。
    #[serde(default = "default_access_log_queue_size")]
    pub queue_size: usize,
    /// 自定义单行格式,支持 nginx 风格 `$status` 与 `${status}` 变量。为空时输出默认 structured fields。
    #[serde(default, alias = "log_format")]
    pub format: Option<String>,
    /// 条件日志表达式,如 `$status >= 500`。未配置则全量输出。
    #[serde(default, rename = "if", alias = "condition")]
    pub condition: Option<String>,
    /// 稳定采样率,范围 0.0..=1.0,按 request_id hash 决定是否输出。
    #[serde(default = "default_access_log_sample")]
    pub sample: f64,
    /// V5 独立日志出口。空列表保持兼容，自动创建一个 `tracing` sink。
    #[serde(default)]
    pub sinks: Vec<AccessLogSinkCfg>,
}

/// 单个 access-log sink 的 bootstrap 配置。
///
/// 每个 sink 都有自己的 bounded queue/batch/timeout。连接拓扑和凭据在进程启动时创建，热更
/// 必须重启；format/condition/sample 仍可随快照热更。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessLogSinkCfg {
    /// 低基数唯一 id，只允许 ASCII 字母、数字、点、下划线、短横线。
    pub id: String,
    /// `tracing` / `http` / `elasticsearch` / `loki` / `kafka`。
    #[serde(rename = "type")]
    pub kind: AccessLogSinkKind,
    /// 是否启动该 sink；关闭项不创建 channel/client。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 本 sink 独立队列长度；满载只丢本 sink 的记录。
    #[serde(default = "default_access_log_sink_queue_size")]
    pub queue_size: usize,
    /// 单批最多记录数。
    #[serde(default = "default_access_log_sink_batch_size")]
    pub batch_size: usize,
    /// 首条记录到达后的最大聚批等待。
    #[serde(default = "default_access_log_sink_batch_delay_ms")]
    pub batch_delay_ms: u64,
    /// HTTP/Kafka 单批投递超时。
    #[serde(default = "default_access_log_sink_timeout_ms")]
    pub timeout_ms: u64,
    /// HTTP/Elasticsearch/Loki 完整 endpoint。Elasticsearch 应指向 `_bulk`。
    #[serde(default)]
    pub endpoint: String,
    /// HTTP 类 sink 的静态 header；值支持 `env://`/`file://` SecretSource。
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Elasticsearch index；只用于 `elasticsearch`。
    #[serde(default)]
    pub index: String,
    /// Kafka broker 列表；只用于 `kafka`。
    #[serde(default)]
    pub bootstrap_servers: String,
    /// Kafka topic；只用于 `kafka`。
    #[serde(default)]
    pub topic: String,
    /// Kafka producer lane，默认 `default`。
    #[serde(default = "default_access_log_kafka_lane")]
    pub lane: String,
    /// 单条结构化记录最大字节数，避免异常字段放大 sink 内存/消息。
    #[serde(default = "default_access_log_sink_max_event_bytes")]
    pub max_event_bytes: usize,
}

/// V5 access-log sink 类型。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogSinkKind {
    /// 输出到既有 nasa/tracing 日志管线。
    Tracing,
    /// JSON array POST 到通用 HTTP endpoint。
    Http,
    /// NDJSON bulk POST 到 Elasticsearch `_bulk` endpoint。
    Elasticsearch,
    /// Loki push JSON。
    Loki,
    /// 原始 JSON 逐条投递 Kafka topic（需 feature `log-kafka`）。
    Kafka,
}

/// OpenTelemetry OTLP trace 导出与 W3C/B3 传播配置。
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct TelemetryCfg {
    /// 是否把已采样 span 导出到 OTLP collector。关闭时仍生成合规 trace-id 并向上游传播。
    #[serde(default)]
    pub enabled: bool,
    /// OTLP/HTTP collector 基地址；exporter 按协议写 `/v1/traces`。
    #[serde(default = "default_otel_endpoint")]
    pub endpoint: String,
    /// OTel resource `service.name`。
    #[serde(default = "default_otel_service_name")]
    pub service_name: String,
    /// root trace 头采样率。可信远端父的 sampled 位由 ParentBased 语义继承。
    #[serde(default = "default_otel_sample_ratio")]
    pub sample_ratio: f64,
    /// BatchSpanProcessor 有界队列容量；满时 SDK fail-open 丢 span，不反压数据面。
    #[serde(default = "default_otel_queue_size")]
    pub queue_size: usize,
    /// 单次 OTLP 导出的最大 span 数，不得大于 `queue_size`。
    #[serde(default = "default_otel_batch_size")]
    pub batch_size: usize,
    /// 后台批量导出最大聚合等待时间。
    #[serde(default = "default_otel_scheduled_delay_ms")]
    pub scheduled_delay_ms: u64,
    /// 单次 collector 请求超时；只约束后台 exporter，不进入请求预算。
    #[serde(default = "default_otel_export_timeout_ms")]
    pub export_timeout_ms: u64,
    /// 是否兼容提取 B3 single/multi header，并向上游额外注入 single `b3`。
    #[serde(default = "default_true")]
    pub b3_compat: bool,
}

impl Default for TelemetryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            service_name: default_otel_service_name(),
            sample_ratio: default_otel_sample_ratio(),
            queue_size: default_otel_queue_size(),
            batch_size: default_otel_batch_size(),
            scheduled_delay_ms: default_otel_scheduled_delay_ms(),
            export_timeout_ms: default_otel_export_timeout_ms(),
            b3_compat: true,
        }
    }
}

/// 请求变量白名单、命名变量和映射表配置。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct VariablesCfg {
    /// 命名变量,如 `tenant: "${header.X-Tenant}"`。变量名在模板中写 `${tenant}`。
    #[serde(default)]
    pub set: HashMap<String, String>,
    /// nginx `map` 等价表,模板中写 `${map.<name>}`。
    #[serde(default)]
    pub maps: Vec<VariableMapCfg>,
    /// 允许被 `${header.X}` 读取的请求头;可显式写 `"*"` 放开。
    #[serde(default)]
    pub allow_headers: Vec<String>,
    /// 允许被 `${query.k}` 读取的 query 参数;可显式写 `"*"` 放开。
    #[serde(default)]
    pub allow_queries: Vec<String>,
}

/// 一张由请求变量驱动的确定性字符串映射表。
#[derive(Debug, Deserialize, Clone)]
pub struct VariableMapCfg {
    /// 映射表唯一名称，通过 `${map.<name>}` 引用。
    pub name: String,
    /// 作为查表键的变量模板。
    pub source: String,
    /// 没有条目命中时返回的值。
    #[serde(default)]
    pub default: String,
    /// `exact`(默认) / `prefix` / `glob` / `cidr`;`regex` 仍按架构要求默认关闭。
    #[serde(default = "default_variable_match_type")]
    pub match_type: String,
    /// 匹配键到替换值的有界静态条目。
    #[serde(default)]
    pub entries: HashMap<String, String>,
}

impl Default for AccessLogCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            queue_size: default_access_log_queue_size(),
            format: None,
            condition: None,
            sample: default_access_log_sample(),
            sinks: Vec::new(),
        }
    }
}

/// 热重载 worker 的有界队列与去抖参数。
///
/// 这是 bootstrap 执行配置：修改后需要重启进程才能重建 channel，避免热更时同时存在
/// 新旧两个 reload worker。
#[derive(Debug, Deserialize, Clone)]
pub struct ReloadCfg {
    /// `notify`/SIGHUP/Nacos 共用事件队列容量。0 按 1 处理，始终保持有界。
    #[serde(default = "default_reload_channel_capacity")]
    pub channel_capacity: usize,
    /// 收到首个变更事件后的聚合窗口(ms)。0 表示不等待，仍会排空已入队的重复事件。
    #[serde(default = "default_reload_debounce_ms")]
    pub debounce_ms: u64,
}

impl Default for ReloadCfg {
    fn default() -> Self {
        Self {
            channel_capacity: default_reload_channel_capacity(),
            debounce_ms: default_reload_debounce_ms(),
        }
    }
}

/// 进程级 WS/gRPC 长连接换版治理。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LongConnectionCfg {
    /// 成功发布新快照后，是否自动 drain 所有持有旧版本的 WS/gRPC 长连接。
    #[serde(default)]
    pub drain_on_config_change: bool,
    /// 自动/管理面 stale drain 的宽限期(ms)；期间在途帧可继续完成，0 表示立即关闭。
    #[serde(default)]
    pub drain_grace_ms: u64,
}

// ── V8 gRPC 边缘模式(架构规范 §25.2 / 验收记录 V8) ──

/// route 级 gRPC 边缘模式配置。
///
/// 这是【默认关闭的叠加模式】:缺省或 `enabled: false` 时,本 route 对 gRPC 的行为
/// 完全等同普通 L7 透传(A10 兼容契约);只有显式开启才让 subscribe/publish/push
/// action header 触发网关自响应。字段默认值与 架构规范 §25.2 配置草案一致。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeCfg {
    /// 总开关。false = 本 route 就是普通 gRPC L7 透传;true 且二进制未编 `grpc-edge`
    /// feature 时,快照构建 fail fast(不上线、保留旧快照)。
    #[serde(default)]
    pub enabled: bool,
    /// 本 route 允许的 edge action 列表(平面隔离):公网面只放 `subscribe`,
    /// 内网发布面只放 `publish`/`push`。enabled=true 时不允许为空。
    #[serde(default)]
    pub allowed_actions: Vec<GrpcEdgeActionCfg>,
    /// 携带 action 的请求头名。
    #[serde(default = "default_grpc_edge_action_header")]
    pub action_header: String,
    /// 携带 group id 的请求头名。
    #[serde(default = "default_grpc_edge_group_header")]
    pub group_header: String,
    /// 定向单播携带目标 user 的请求头名。
    #[serde(default = "default_grpc_edge_target_header")]
    pub target_header: String,
    /// 鉴权等级:`required` = 终端用户须先过 route 鉴权(§20);`service` = 发布面服务凭证
    /// (mTLS SAN / 服务 JWT)。构建期强制 subscribe=required、publish/push=service，
    /// 防止同 route 混用终端与发布凭证。
    #[serde(default)]
    pub auth: GrpcEdgeAuthCfg,
    /// 每订阅流的有界发送队列。
    #[serde(default)]
    pub send_queue: GrpcEdgeSendQueueCfg,
    /// 发布面 PublishStream 单流四门(lifetime/messages/rate/bytes,§25.2.3)。
    #[serde(default)]
    pub publish_stream: GrpcEdgePublishStreamCfg,
    /// 投递语义。v1 只有 at_most_once;不丢语义走后端有序日志 + 普通 L7 backfill。
    #[serde(default)]
    pub delivery: GrpcEdgeDeliveryCfg,
    /// 发布面消息编码约束。v1 只有 identity:逐消息压缩会破坏"一份字节全订阅者复用"。
    #[serde(default)]
    pub encoding: GrpcEdgeEncodingCfg,
    /// 【兼容别名,已废弃】单条 protobuf message body(不含 5 字节前缀)字节上限。
    /// V8-0R 起权威位置是 `limits.max_msg_bytes`;两处同时设置且不相等时构建期报错,
    /// 只设旧位仍然生效(一次性迁移路径,§25.2.9)。
    #[serde(default)]
    pub max_msg_bytes: Option<usize>,
    /// V8-0R:每 action 的精确 gRPC `:path`(§25.2.3)。edge 不能只靠可伪造 header 触发,
    /// 必须同时命中精确方法;allowed_actions 里的每个 action 都要有对应 method。
    #[serde(default)]
    pub methods: GrpcEdgeMethodsCfg,
    /// V8-0R:tenant/user 身份从已验证 principal 的 claim 映射(§25.2.3 相位 4),
    /// 客户端自报 header 永不是权威身份。
    #[serde(default)]
    pub identity: GrpcEdgeIdentityCfg,
    /// V8-0R:双维队列之外的节点级预算与基数上限(§25.2.5),拒绝高基数内存攻击。
    #[serde(default)]
    pub limits: GrpcEdgeLimitsCfg,
    /// V8-8:浏览器 WS→内部 gRPC 边缘桥接入口路径(如 `/edge/ws`)。
    ///
    /// 设了才开桥;要求本 route 允许 subscribe。桥接只换**传输外壳**——鉴权、身份、
    /// group 索引、队列预算、治理关闭全部复用同一条订阅路径,每条广播以一个
    /// binary 帧原样送出与 native gRPC 订阅者**字节一致**的 `[5B prefix + payload]`。
    #[serde(default)]
    pub ws_bridge_path: Option<String>,
    /// V8-9:发布/订阅**授权**策略(§25.2.3 相位 4 之后、任何执行之前)。
    ///
    /// 为什么必须单列一段:相位 4 只解决了「你是谁」——身份一律取自已验证 principal,
    /// 客户端自报 header 永不作数。但 `group`/`target` 是**客户端给的**,此前只校验
    /// 长度与字符集,于是同一租户内**任何已认证用户都能订阅任意 group、任何已认证
    /// 服务都能向任意 group 发布**。这一段回答「你能碰哪个 group」。
    ///
    /// enabled route 必须显式声明本段；缺失会在构建期拒绝，避免升级后继续沿用
    /// 隐式全放行。只有显式列出的模式放行，未列出的 action 一律拒绝；
    /// 空列表 = 全拒。确需公开放行也必须写出 "*"，让意图可审计。
    #[serde(default)]
    pub authz: Option<GrpcEdgeAuthzCfg>,
}

/// V8-9 发布/订阅授权策略(§25.2.3)。
///
/// 三个 action 各自独立:订阅面通常按用户收敛(只能订自己的),发布面通常按业务域收敛。
/// 未声明的 action 列表为空,即该 action 在本 route 上被全部拒绝——**空 ≠ 不限制**,
/// 否则"配了策略却漏写一个 action"会静默变成完全开放。
///
/// 模式语法:字面量、末尾 `*`(吞掉剩余)、以及 `%{user}` / `%{tenant}` 两个变量
/// (均取自**已验证** principal,客户端 header 永不参与)。例:
/// `subscribe_groups: ["user.%{user}", "room.*"]` = 只能订自己的私有流与任意房间。
///
/// **注意变量前缀是 `%{}` 而不是 `${}`**:gateway.yml 加载器会先把 `${NAME}` 按环境变量
/// 展开,授权规则若用 `${user}`,在存在同名环境变量的机器上会被静默替换成该值,
/// 导致同一份配置在不同机器上放行范围不同。模式里出现 `${` 会在构建期直接报错。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeAuthzCfg {
    /// 允许 subscribe 的 group 模式列表。
    #[serde(default)]
    pub subscribe_groups: Vec<String>,
    /// 允许 publish/publish_stream 的 group 模式列表。
    #[serde(default)]
    pub publish_groups: Vec<String>,
    /// 允许 push 的目标 user 模式列表。
    #[serde(default)]
    pub push_targets: Vec<String>,
}

/// 每 action 的精确 gRPC 方法路径(如 `/naway.edge.v1.NawayEdge/Subscribe`)。
///
/// route 可改路径,但不能用宽泛前缀把普通业务 RPC 误判成 edge(§25.2.2)。
/// `publish_stream` 归属 publish action:只有 allowed_actions 含 publish 才可声明。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeMethodsCfg {
    /// Subscribe 方法路径;allowed_actions 含 subscribe 时必填。
    #[serde(default)]
    pub subscribe: Option<String>,
    /// unary Publish 方法路径;allowed_actions 含 publish 时必填。
    #[serde(default)]
    pub publish: Option<String>,
    /// client-streaming PublishStream 方法路径;可选,仅允许 publish 时可声明。
    #[serde(default)]
    pub publish_stream: Option<String>,
    /// unary Push 方法路径;allowed_actions 含 push 时必填。
    #[serde(default)]
    pub push: Option<String>,
}

/// tenant/user 身份的 claim 映射(§25.2.3:身份只来自已验证 principal)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeIdentityCfg {
    /// 租户 claim 名;None = 单租户部署,内部统一落 default tenant。
    #[serde(default)]
    pub tenant_claim: Option<String>,
    /// 用户 claim 名(默认 JWT `sub`)。subscribe/push 的 user 索引键来自它。
    #[serde(default = "default_grpc_edge_user_claim")]
    pub user_claim: String,
}

impl Default for GrpcEdgeIdentityCfg {
    fn default() -> Self {
        Self {
            tenant_claim: None,
            user_claim: default_grpc_edge_user_claim(),
        }
    }
}

/// 节点级预算与基数上限(§25.2.5/§25.2.9)。
///
/// 仅有每队列上限不足以有界:`流数 × 队深 × 消息大小` 的乘积必须再被节点级
/// payload/引用/任务预算钉死;group/user/session 基数上限拒绝高基数内存攻击。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeLimitsCfg {
    /// 单条 protobuf message body(不含 5 字节前缀)字节上限;V8-2 解码器读出 prefix
    /// length 后须在分配重组缓冲前执行该限制。
    #[serde(default)]
    pub max_msg_bytes: Option<usize>,
    /// tenant/group/user 等业务 ID 的字节上限。
    #[serde(default = "default_grpc_edge_max_id_bytes")]
    pub max_id_bytes: usize,
    /// 本节点 edge 订阅流总数上限。
    #[serde(default = "default_grpc_edge_max_streams_per_node")]
    pub max_streams_per_node: usize,
    /// 本节点 group 总数上限。
    #[serde(default = "default_grpc_edge_max_groups_per_node")]
    pub max_groups_per_node: usize,
    /// 单 group 成员数上限。
    #[serde(default = "default_grpc_edge_max_members_per_group")]
    pub max_members_per_group: usize,
    /// 单 user 并发 session 上限(多端在线)。
    #[serde(default = "default_grpc_edge_max_sessions_per_user")]
    pub max_sessions_per_user: usize,
    /// 节点唯一 payload 驻留字节预算(所有队列共享同一份 payload 只计一次)。
    #[serde(default = "default_grpc_edge_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// 全节点队列引用总数预算(`Bytes` clone 便宜,但队列元数据与滞留不免费)。
    #[serde(default = "default_grpc_edge_max_queue_refs")]
    pub max_queue_refs: usize,
    /// 并发 fanout job 上限;大群广播分片入队,不允许一次 O(N) 独占 runtime worker。
    #[serde(default = "default_grpc_edge_max_fanout_jobs")]
    pub max_fanout_jobs: usize,
}

impl Default for GrpcEdgeLimitsCfg {
    fn default() -> Self {
        Self {
            max_msg_bytes: None,
            max_id_bytes: default_grpc_edge_max_id_bytes(),
            max_streams_per_node: default_grpc_edge_max_streams_per_node(),
            max_groups_per_node: default_grpc_edge_max_groups_per_node(),
            max_members_per_group: default_grpc_edge_max_members_per_group(),
            max_sessions_per_user: default_grpc_edge_max_sessions_per_user(),
            max_payload_bytes: default_grpc_edge_max_payload_bytes(),
            max_queue_refs: default_grpc_edge_max_queue_refs(),
            max_fanout_jobs: default_grpc_edge_max_fanout_jobs(),
        }
    }
}

/// edge action 枚举(serde 小写形态即 header 契约里的取值)。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeActionCfg {
    /// 终端订阅:挂起服务端流并登记进 group 索引。
    Subscribe,
    /// 后端群播:向 group 全体订阅流散出一份负载。
    Publish,
    /// 后端定向单播:向指定 user 的全部在线流投递。
    Push,
}

/// 鉴权等级。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeAuthCfg {
    /// 终端用户面:必须先过 route 级鉴权,身份取已认证 consumer,不裸信 header。
    #[default]
    Required,
    /// 发布面:服务级凭证(mTLS SAN / 服务 JWT),与终端鉴权分池。
    Service,
}

/// 每订阅流有界发送队列配置(消息数 + 逻辑字节双维;单一维度不足以有界,§25.2.5)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeSendQueueCfg {
    /// 队列消息数上限;满时按 `overflow` 策略处理,绝不无界积压(§23 资源纪律)。
    #[serde(default = "default_grpc_edge_send_queue_max_messages")]
    pub max_messages: usize,
    /// 队列逻辑字节上限(帧全长 = 5 字节前缀 + body 计费);大消息 × 流数的聚合
    /// OOM 只有 messages+bytes 双维同时限制才封得住。
    #[serde(default = "default_grpc_edge_send_queue_max_bytes")]
    pub max_bytes: usize,
    /// 队满策略。
    #[serde(default)]
    pub overflow: GrpcEdgeOverflowCfg,
}

impl Default for GrpcEdgeSendQueueCfg {
    fn default() -> Self {
        Self {
            max_messages: default_grpc_edge_send_queue_max_messages(),
            max_bytes: default_grpc_edge_send_queue_max_bytes(),
            overflow: GrpcEdgeOverflowCfg::default(),
        }
    }
}

/// 发布面 PublishStream 单流四门(§25.2.3,V8-2 后半)。
///
/// 执行语义(v1):`max_msgs_per_sec` 是背压节流——无令牌即暂停读请求体,经 HTTP/2
/// 流控传导到发布方,不丢消息不断流;其余三门到界即**优雅轮转**——停止读取、返回
/// 已聚合 summary + OK,发布方凭 `messages` 字段判断进度并重建流。仅发布面
/// PublishStream 方法生效,unary Publish/Push 恒为恰一条(§25.2.3)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgePublishStreamCfg {
    /// 单流生命周期上限(ms);长发布管道靠周期轮转保持有界,不允许无限流。
    #[serde(default = "default_grpc_edge_publish_stream_max_lifetime_ms")]
    pub max_lifetime_ms: u64,
    /// 单流累计消息数上限。
    #[serde(default = "default_grpc_edge_publish_stream_max_messages")]
    pub max_messages: u64,
    /// 每秒消息数节流(令牌桶容量=速率,连续补充)。
    #[serde(default = "default_grpc_edge_publish_stream_max_msgs_per_sec")]
    pub max_msgs_per_sec: u64,
    /// 单流累计字节上限(帧全长 = 5 字节前缀 + body 计费,与队列口径一致)。
    #[serde(default = "default_grpc_edge_publish_stream_max_total_bytes")]
    pub max_total_bytes: u64,
}

impl Default for GrpcEdgePublishStreamCfg {
    fn default() -> Self {
        Self {
            max_lifetime_ms: default_grpc_edge_publish_stream_max_lifetime_ms(),
            max_messages: default_grpc_edge_publish_stream_max_messages(),
            max_msgs_per_sec: default_grpc_edge_publish_stream_max_msgs_per_sec(),
            max_total_bytes: default_grpc_edge_publish_stream_max_total_bytes(),
        }
    }
}

/// 有界队列溢出策略(§25.2.5/§25.2.8)。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeOverflowCfg {
    /// 丢最旧、保最新(订阅队列默认)。语义由自有 EdgeRing 在同一临界区弹旧入新实现,
    /// 普通 Tokio mpsc/PollSender 无法冒充(§25.2.5)。
    #[default]
    DropOldest,
    /// 拒绝新消息、保留既有 FIFO(relay 默认:偷偷删除更早消息再宣称 FIFO 是撒谎)。
    DropNew,
    /// 按业务 key 只保留最新一帧；V8-3 的 opaque payload 尚无 key envelope，当前构建期拒绝。
    LatestByKey,
    /// 直接断开慢客户端(发 grpc-status 关闭)。
    CloseSlow,
}

/// 投递语义。v1 只允许 at_most_once,枚举保留演进空间。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeDeliveryCfg {
    /// 至多一次:队满/peer 失联即丢并计数;不丢语义由后端 backfill 承担。
    #[default]
    AtMostOnce,
}

/// 发布面编码约束。v1 只允许 identity。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeEncodingCfg {
    /// 明文 gRPC framing:一份 `[前缀+消息体]` 切片可原样复用给全部订阅者与 relay。
    #[default]
    Identity,
}

/// 进程级集群中继面配置(方案 B:一次收单 + naway↔naway hop=1 中继,零 MQ/零 Redis)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeClusterCfg {
    /// relay 双向 TLS；非 loopback 集群必须启用。
    #[serde(default)]
    pub tls: GrpcEdgeRelayTlsCfg,
    /// `relay` = 多节点中继(需要 `grpc-edge` feature);`none` = 显式单机,忽略其余字段。
    #[serde(default)]
    pub mode: GrpcEdgeClusterModeCfg,
    /// `mode: redis_pubsub` 的独立连接与 channel 参数；与 relay 网络面严格互斥。
    #[serde(default)]
    pub redis_pubsub: GrpcEdgeRedisPubSubCfg,
    /// `mode: redis_stream` 的独立 XREAD 与游标参数。
    #[serde(default)]
    pub redis_stream: GrpcEdgeRedisStreamCfg,
    /// 集群身份;relay 握手交换并校验,跨 cluster 连接一律拒绝(§25.2.6)。relay 模式必填。
    #[serde(default)]
    pub cluster_id: String,
    /// 本节点身份(如 `${POD_UID}`);relay 握手交换,重复 node_id 拒绝、
    /// 较小 node_id 发起唯一连接。relay 模式必填。
    #[serde(default)]
    pub node_id: String,
    /// peer 成员来源。
    #[serde(default)]
    pub membership: GrpcEdgeMembershipCfg,
    /// `membership: static` 时的 peer relay endpoint 列表(host:port);nacos 模式必须留空。
    #[serde(default)]
    pub static_peers: Vec<String>,
    /// 内部 relay 监听地址(host:port),仅接受 peer 身份;relay 模式必填。
    #[serde(default)]
    pub relay_listen: String,
    /// peer 身份鉴别方式(§25.2.6:优先 mTLS;mTLS 证书 schema 归 V8-3 后半,
    /// 当前实现 cluster_secret,配 mtls 构建期 fail-fast 而非静默降级)。
    #[serde(default)]
    pub peer_auth: GrpcEdgePeerAuthCfg,
    /// `peer_auth: cluster_secret` 的共享凭证(SecretSource:literal/env/file/...);
    /// 该模式下必填非空。数据面只持有构建期已解析值,请求路径不读环境/磁盘。
    #[serde(default)]
    pub cluster_secret: String,
    /// 每 peer 有界中继队列(消息数 + 字节双维)。
    #[serde(default)]
    pub relay_queue: GrpcEdgeRelayQueueCfg,
    /// ingress 聚合 peer enqueue-ack 的固定 deadline(ms);超时记 unknown、不自动重试
    /// (§25.2.6 背压与回执)。对应 §25.2.9 示例 `ack_deadline: 100ms`,本仓统一 `_ms` 整数。
    #[serde(default = "default_grpc_edge_ack_deadline_ms")]
    pub ack_deadline_ms: u64,
    /// 全网状中继的节点数硬门(§25.2.2 建议 <=32)。静态 peers 超门直接拒绝;
    /// 更大集群必须等 V8-5 interest/group-owner 路由,不允许 O(N²) 盲广播。
    #[serde(default = "default_grpc_edge_full_mesh_max_nodes")]
    pub full_mesh_max_nodes: usize,
    /// 兴趣路由策略(§25.2.6):`auto` = 小集群广播、超门后由 V8-5 interest 接管,
    /// hint 缺失/过期一律 fail-open 广播;`broadcast_all` = 显式永远广播(仅小集群)。
    #[serde(default)]
    pub interest_route: GrpcEdgeInterestRouteCfg,
    /// 顺序承诺(§25.2.6):默认仅"同 publisher stream → 同 ingress → 同目标队列"FIFO;
    /// `group_owner` 通过确定性 owner + 分片串行锁承诺跨发布者的 group 严格序。
    #[serde(default)]
    pub ordering: GrpcEdgeOrderingCfg,
    /// 用户会话语义(§25.2.7):默认多端在线,probe 等全部节点到 deadline;
    /// `single_session` 必须显式配置；relay owner 以全 mesh fencing token 踢旧 session。
    #[serde(default)]
    pub session_mode: GrpcEdgeSessionModeCfg,
    /// 定向单播指路条。`none` = broadcast-probe(默认,零外部依赖);
    /// `redis` = 大集群可选加速,需要 `redis-runtime` feature。
    #[serde(default)]
    pub session_registry: GrpcEdgeSessionRegistryCfg,
    /// `session_registry: redis` 的连接与租约参数(V8-7);`none` 时整段忽略。
    #[serde(default)]
    pub session_directory: GrpcEdgeSessionDirectoryCfg,
    /// relay **收包散出**使用的节点级预算(§25.2.9)。
    ///
    /// 为什么单列一段:relay 收到的 record 来自对端节点,**不经本地路由匹配**,因此没有
    /// route 计划可依。此前这里硬编码 `GrpcEdgeLimitsCfg::default()`,后果是运维把某条
    /// route 的 `grpc_edge.limits` 调大之后,**本地发布放宽了而经 peer 中继的同一条消息
    /// 仍按默认值被拒**——同一业务动作在本节点和跨节点表现不同,且没有任何配置能改。
    ///
    /// 刻意**不**从各 route 的 limits 取并集:那是隐式推导,改一条 route 会静默改变整个
    /// 集群面的准入,审查时看不出来。要放宽 relay 面必须在集群块里写明。
    /// 默认值与 route 默认一致,不配置即维持既有行为。
    ///
    /// 注意 `max_msg_bytes` 在此段无效:relay record 的尺寸已由协议硬上限
    /// `RELAY_MAX_PAYLOAD_BYTES` 在解码层钉死,不允许配置放宽。
    #[serde(default)]
    pub fanout_limits: GrpcEdgeLimitsCfg,
}

/// V8-7 SessionDirectory(redis)连接与租约参数(§25.2.7)。
///
/// 目录只做寻址加速:miss/超时/脏条目一律回落 broadcast-probe,正确性不依赖它。
/// 因此 TTL 只需覆盖"续租任务两三个周期"的量级,不必追求与连接寿命等长。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeSessionDirectoryCfg {
    /// Redis URL,如 `redis://:password@127.0.0.1:6379`。`session_registry=redis` 时必填。
    #[serde(default)]
    pub url: String,
    /// nadis 协议命名空间。
    #[serde(default = "default_edge_directory_namespace")]
    pub namespace: String,
    /// nadis 兼容 profile。
    #[serde(default = "default_edge_directory_profile")]
    pub profile: String,
    /// 目录 key 前缀(完整 key = `{prefix}:{cluster_id}:{tenant}:{user}`)。
    #[serde(default = "default_edge_directory_prefix")]
    pub prefix: String,
    /// 租约 key TTL(ms);进程崩溃来不及 unbind 时由它兜底回收。
    #[serde(default = "default_edge_directory_ttl_ms")]
    pub ttl_ms: u64,
    /// 单条目录命令硬超时(ms);目录慢绝不能拖慢 push 主路径。
    #[serde(default = "default_edge_directory_command_timeout_ms")]
    pub command_timeout_ms: u64,
}

/// Redis Pub/Sub 集群散出参数。该模式没有持久化、背压或远端 ACK。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeRedisPubSubCfg {
    /// Redis/Valkey URL。
    #[serde(default)]
    pub url: String,
    /// nadis 协议命名空间。
    #[serde(default = "default_edge_directory_namespace")]
    pub namespace: String,
    /// nadis 兼容 profile。
    #[serde(default = "default_edge_directory_profile")]
    pub profile: String,
    /// 广播 channel；为空时派生为 `naway:edge:{cluster_id}`。
    #[serde(default)]
    pub channel: String,
    /// PUBLISH/重连命令硬超时(ms)。
    #[serde(default = "default_edge_redis_pubsub_command_timeout_ms")]
    pub command_timeout_ms: u64,
    /// 订阅断线后的重连退避(ms)。
    #[serde(default = "default_edge_redis_pubsub_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for GrpcEdgeRedisPubSubCfg {
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_edge_directory_namespace(),
            profile: default_edge_directory_profile(),
            channel: String::new(),
            command_timeout_ms: default_edge_redis_pubsub_command_timeout_ms(),
            reconnect_backoff_ms: default_edge_redis_pubsub_reconnect_backoff_ms(),
        }
    }
}

fn default_edge_redis_pubsub_command_timeout_ms() -> u64 {
    1_000
}

fn default_edge_redis_pubsub_reconnect_backoff_ms() -> u64 {
    500
}

/// Redis Stream 广播参数。每个 Naway 节点使用独立 XREAD 游标；绝不使用共享消费组。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeRedisStreamCfg {
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_edge_directory_namespace")]
    pub namespace: String,
    #[serde(default = "default_edge_directory_profile")]
    pub profile: String,
    /// Stream key；为空时派生为 `naway:edge:{cluster_id}`。
    #[serde(default)]
    pub stream: String,
    /// 每节点游标 key 前缀，完整 key 追加 cluster_id/node_id。
    #[serde(default = "default_edge_redis_stream_cursor_prefix")]
    pub cursor_prefix: String,
    /// 每次 XREAD 的 COUNT。
    #[serde(default = "default_edge_redis_stream_batch_size")]
    pub batch_size: usize,
    /// XREAD BLOCK 毫秒。
    #[serde(default = "default_edge_redis_stream_block_ms")]
    pub block_ms: u64,
    /// XADD/游标命令硬超时(ms)。
    #[serde(default = "default_edge_redis_pubsub_command_timeout_ms")]
    pub command_timeout_ms: u64,
    /// 读循环错误后的退避(ms)。
    #[serde(default = "default_edge_redis_pubsub_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for GrpcEdgeRedisStreamCfg {
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_edge_directory_namespace(),
            profile: default_edge_directory_profile(),
            stream: String::new(),
            cursor_prefix: default_edge_redis_stream_cursor_prefix(),
            batch_size: default_edge_redis_stream_batch_size(),
            block_ms: default_edge_redis_stream_block_ms(),
            command_timeout_ms: default_edge_redis_pubsub_command_timeout_ms(),
            reconnect_backoff_ms: default_edge_redis_pubsub_reconnect_backoff_ms(),
        }
    }
}

fn default_edge_redis_stream_cursor_prefix() -> String {
    "naway:edge:cursor".to_string()
}

fn default_edge_redis_stream_batch_size() -> usize {
    100
}

fn default_edge_redis_stream_block_ms() -> u64 {
    500
}

impl Default for GrpcEdgeSessionDirectoryCfg {
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_edge_directory_namespace(),
            profile: default_edge_directory_profile(),
            prefix: default_edge_directory_prefix(),
            ttl_ms: default_edge_directory_ttl_ms(),
            command_timeout_ms: default_edge_directory_command_timeout_ms(),
        }
    }
}

fn default_edge_directory_namespace() -> String {
    "naway".to_string()
}

fn default_edge_directory_profile() -> String {
    "RustV2".to_string()
}

fn default_edge_directory_prefix() -> String {
    "naway:edge:sess".to_string()
}

fn default_edge_directory_ttl_ms() -> u64 {
    60_000
}

fn default_edge_directory_command_timeout_ms() -> u64 {
    100
}

/// 每 peer 有界中继队列(默认比订阅队列深:一个 peer 背后是整节点的订阅者集合)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeRelayQueueCfg {
    /// 队列消息数上限。
    #[serde(default = "default_grpc_edge_relay_queue_max_messages")]
    pub max_messages: usize,
    /// 队列逻辑字节上限(RelayRecord 全长计费)。
    #[serde(default = "default_grpc_edge_relay_queue_max_bytes")]
    pub max_bytes: usize,
    /// 队满策略;relay 默认 `drop_new`(§25.2.5),`close_slow` 对 peer 无意义、构建期拒绝。
    #[serde(default = "default_grpc_edge_relay_overflow")]
    pub overflow: GrpcEdgeOverflowCfg,
}

impl Default for GrpcEdgeRelayQueueCfg {
    fn default() -> Self {
        Self {
            max_messages: default_grpc_edge_relay_queue_max_messages(),
            max_bytes: default_grpc_edge_relay_queue_max_bytes(),
            overflow: default_grpc_edge_relay_overflow(),
        }
    }
}

/// 兴趣路由策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeInterestRouteCfg {
    /// 自动传播各节点当前 tenant/group 兴趣，只向明确有兴趣的 peer 发送业务 payload。
    /// hint 未就绪、版本断档或过期时 fail-open 广播，优化面不参与正确性。
    #[default]
    Auto,
    /// 显式声明永远向全部 peer 广播；仅允许小集群使用。
    BroadcastAll,
}

/// 跨节点顺序承诺。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeOrderingCfg {
    /// 尽力而为,无任何顺序承诺。
    BestEffort,
    /// 默认:同 publisher stream 经同 ingress 到同目标队列保持 FIFO。
    #[default]
    IngressFifo,
    /// group 严格序:rendezvous-hash group owner 统一定序(V8-5 落地)。
    GroupOwner,
}

/// 用户会话语义。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeSessionModeCfg {
    /// 多端在线:定向 push 等全部节点到 deadline,不首命中即返回。
    #[default]
    MultiSession,
    /// 单端登录:登录阶段踢旧 session;必须显式配置。
    SingleSession,
}

/// 中继面模式。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeClusterModeCfg {
    /// 多节点中继(默认:配置了本段即视为要集群)。
    #[default]
    Relay,
    /// Redis Pub/Sub 广播；不启动 relay listener/peer discovery/session directory。
    RedisPubsub,
    /// Redis Stream 广播；每节点独立 XREAD 游标，历史裁剪完全由业务侧负责。
    RedisStream,
    /// 显式单机;等同不配置本段。
    None,
}

/// peer 成员来源。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeMembershipCfg {
    /// 复用 §9 Nacos 自注册 watch；运行时归 V8-5，当前构建期拒绝。
    #[default]
    Nacos,
    /// 静态 peer 列表(all-in-one/无注册中心部署)。
    Static,
}

/// peer 身份鉴别方式。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgePeerAuthCfg {
    /// 双向 TLS(默认,§25.2.6 优先):证书身份即节点身份,握手期校验。
    #[default]
    Mtls,
    /// 集群共享 secret(SecretSource,§19/§20);无 mTLS 基建的过渡形态,V8-3 落地校验。
    ClusterSecret,
}

/// 定向单播指路条后端。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeSessionRegistryCfg {
    /// broadcast-probe:无外部依赖,正确性不靠指路条。
    #[default]
    None,
    /// Redis user→node 指路条,仅作探测加速;失效自动回落 probe。
    Redis,
}

fn default_grpc_edge_action_header() -> String {
    "x-naway-edge-action".to_string()
}

fn default_grpc_edge_group_header() -> String {
    "x-naway-group".to_string()
}

fn default_grpc_edge_target_header() -> String {
    "x-naway-target-user".to_string()
}

fn default_grpc_edge_user_claim() -> String {
    "sub".to_string()
}

fn default_grpc_edge_max_id_bytes() -> usize {
    128
}

fn default_grpc_edge_max_streams_per_node() -> usize {
    200_000
}

fn default_grpc_edge_max_groups_per_node() -> usize {
    100_000
}

fn default_grpc_edge_max_members_per_group() -> usize {
    100_000
}

fn default_grpc_edge_max_sessions_per_user() -> usize {
    8
}

fn default_grpc_edge_max_payload_bytes() -> usize {
    536_870_912
}

fn default_grpc_edge_max_queue_refs() -> usize {
    4_000_000
}

fn default_grpc_edge_max_fanout_jobs() -> usize {
    4_096
}

fn default_grpc_edge_send_queue_max_messages() -> usize {
    256
}

fn default_grpc_edge_send_queue_max_bytes() -> usize {
    4_194_304
}

fn default_grpc_edge_publish_stream_max_lifetime_ms() -> u64 {
    3_600_000
}

fn default_grpc_edge_publish_stream_max_messages() -> u64 {
    1_000_000
}

fn default_grpc_edge_publish_stream_max_msgs_per_sec() -> u64 {
    10_000
}

fn default_grpc_edge_publish_stream_max_total_bytes() -> u64 {
    4_294_967_296
}

fn default_grpc_edge_relay_queue_max_messages() -> usize {
    1_024
}

fn default_grpc_edge_relay_queue_max_bytes() -> usize {
    67_108_864
}

fn default_grpc_edge_relay_overflow() -> GrpcEdgeOverflowCfg {
    GrpcEdgeOverflowCfg::DropNew
}

fn default_grpc_edge_ack_deadline_ms() -> u64 {
    100
}

fn default_grpc_edge_full_mesh_max_nodes() -> usize {
    32
}

/// 所有服务发现后端的进程级配置。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DiscoveryCfg {
    /// Nacos watch 后端。
    #[serde(default)]
    pub nacos: NacosDiscoveryCfg,
    /// V7 Consul Health API 轮询后端。
    #[serde(default)]
    pub consul: ConsulDiscoveryCfg,
    /// V7 Eureka JSON API 轮询后端。
    #[serde(default)]
    pub eureka: EurekaDiscoveryCfg,
    /// V7 系统 DNS A/AAAA 解析后端。
    #[serde(default)]
    pub dns: DnsDiscoveryCfg,
    /// V7 Kubernetes Endpoints API 轮询后端。
    #[serde(default)]
    pub kubernetes: KubernetesDiscoveryCfg,
}

/// Consul `/v1/health/service/:name` 发现配置。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsulDiscoveryCfg {
    /// 是否启动 Consul 发现 worker。
    #[serde(default)]
    pub enabled: bool,
    /// Consul HTTP(S) 根地址，例如 `http://127.0.0.1:8500`。
    #[serde(default)]
    pub base_url: String,
    /// ACL token SecretSource。
    #[serde(default)]
    pub token: String,
    /// 可选 Consul datacenter 查询参数。
    #[serde(default)]
    pub datacenter: String,
    /// 可选 service tag 过滤条件。
    #[serde(default)]
    pub tag: String,
    /// 是否只接收 passing 健康实例。
    #[serde(default = "default_true")]
    pub passing_only: bool,
    /// 相邻轮询的最小间隔，单位毫秒。
    #[serde(default = "default_registry_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// 单次 HTTP 请求 deadline，单位毫秒。
    #[serde(default = "default_registry_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// 注册中心失联后保留最后一次实例快照的时间。
    #[serde(default = "default_registry_stale_ttl_ms")]
    pub stale_ttl_ms: u64,
    /// 单次响应允许读取的最大字节数。
    #[serde(default = "default_registry_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 单个逻辑服务允许发布的最大实例数。
    #[serde(default = "default_registry_max_instances")]
    pub max_instances: usize,
}

impl Default for ConsulDiscoveryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            token: String::new(),
            datacenter: String::new(),
            tag: String::new(),
            passing_only: true,
            poll_interval_ms: default_registry_poll_interval_ms(),
            request_timeout_ms: default_registry_request_timeout_ms(),
            stale_ttl_ms: default_registry_stale_ttl_ms(),
            max_response_bytes: default_registry_max_response_bytes(),
            max_instances: default_registry_max_instances(),
        }
    }
}

/// Eureka `/eureka/apps/:app` JSON 发现配置。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EurekaDiscoveryCfg {
    /// 是否启动 Eureka 发现 worker。
    #[serde(default)]
    pub enabled: bool,
    /// Eureka HTTP(S) 根地址。
    #[serde(default)]
    pub base_url: String,
    /// 可选 HTTP Basic 用户名。
    #[serde(default)]
    pub username: String,
    /// Basic 密码 SecretSource。
    #[serde(default)]
    pub password: String,
    /// 相邻轮询的最小间隔，单位毫秒。
    #[serde(default = "default_registry_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// 单次 HTTP 请求 deadline，单位毫秒。
    #[serde(default = "default_registry_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// 失联后保留最后一次实例快照的时间。
    #[serde(default = "default_registry_stale_ttl_ms")]
    pub stale_ttl_ms: u64,
    /// 单次响应允许读取的最大字节数。
    #[serde(default = "default_registry_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 单个逻辑服务允许发布的最大实例数。
    #[serde(default = "default_registry_max_instances")]
    pub max_instances: usize,
}

impl Default for EurekaDiscoveryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            username: String::new(),
            password: String::new(),
            poll_interval_ms: default_registry_poll_interval_ms(),
            request_timeout_ms: default_registry_request_timeout_ms(),
            stale_ttl_ms: default_registry_stale_ttl_ms(),
            max_response_bytes: default_registry_max_response_bytes(),
            max_instances: default_registry_max_instances(),
        }
    }
}

/// 系统 DNS resolver 轮询配置。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsDiscoveryCfg {
    /// 是否启动 DNS 发现 worker。
    #[serde(default)]
    pub enabled: bool,
    /// 相邻解析的最小间隔，单位毫秒。
    #[serde(default = "default_registry_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// 单次解析 deadline，单位毫秒。
    #[serde(default = "default_registry_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// 解析失败后保留最后一次地址集的时间。
    #[serde(default = "default_registry_stale_ttl_ms")]
    pub stale_ttl_ms: u64,
    /// 单个逻辑服务允许发布的最大 A/AAAA 地址数。
    #[serde(default = "default_dns_max_addresses")]
    pub max_addresses: usize,
}

impl Default for DnsDiscoveryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_ms: default_registry_poll_interval_ms(),
            request_timeout_ms: default_registry_request_timeout_ms(),
            stale_ttl_ms: default_registry_stale_ttl_ms(),
            max_addresses: default_dns_max_addresses(),
        }
    }
}

/// Kubernetes core/v1 Endpoints 发现配置。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KubernetesDiscoveryCfg {
    /// 是否启动 Kubernetes Endpoints 发现 worker。
    #[serde(default)]
    pub enabled: bool,
    /// API server，例如 `https://kubernetes.default.svc`。
    #[serde(default)]
    pub api_server: String,
    /// 未在 service 上指定 namespace 时使用的默认值。
    #[serde(default = "default_kubernetes_namespace")]
    pub namespace: String,
    /// ServiceAccount bearer token SecretSource。
    #[serde(default)]
    pub bearer_token: String,
    /// API server CA PEM SecretSource；空表示使用平台根证书。
    #[serde(default)]
    pub ca_certificate: String,
    /// 相邻 API 轮询的最小间隔，单位毫秒。
    #[serde(default = "default_registry_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// 单次 Kubernetes API 请求 deadline，单位毫秒。
    #[serde(default = "default_registry_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// API 失联后保留最后一次实例快照的时间。
    #[serde(default = "default_registry_stale_ttl_ms")]
    pub stale_ttl_ms: u64,
    /// 单次 API 响应允许读取的最大字节数。
    #[serde(default = "default_registry_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 单个逻辑服务允许发布的最大实例数。
    #[serde(default = "default_registry_max_instances")]
    pub max_instances: usize,
}

/// Kubernetes Ingress v1 / Gateway API v1 路由源。
///
/// API server、ServiceAccount token 与 CA 复用 `discovery.kubernetes`，避免同一进程维护两套
/// bootstrap 凭据。控制器只产生有限的 route/service JSON 候选，最终仍由标准 snapshot
/// builder 校验并原子发布。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KubernetesRouteSourceCfg {
    /// 是否启动 Kubernetes 路由物化 worker。
    #[serde(default)]
    pub enabled: bool,
    /// 生成路由挂载的 HTTP proxy id；旧式 `server + routes` 对应 `default`。
    #[serde(default = "default_kubernetes_route_target_proxy")]
    pub target_proxy: String,
    /// 控制器写入 gateway.yml 同目录的文件名。只允许单个普通文件名，禁止目录穿越。
    #[serde(default = "default_kubernetes_route_materialized_file")]
    pub materialized_file: String,
    /// 是否读取 networking.k8s.io/v1 Ingress。
    #[serde(default = "default_true")]
    pub ingress_enabled: bool,
    /// 允许的 ingressClassName/旧 annotation；空集合表示不接管任何 Ingress。
    #[serde(default = "default_kubernetes_ingress_classes")]
    pub ingress_classes: Vec<String>,
    /// 是否读取 gateway.networking.k8s.io/v1 GatewayClass/Gateway/HTTPRoute。
    #[serde(default = "default_true")]
    pub gateway_api_enabled: bool,
    /// 本控制器的 GatewayClass `spec.controllerName`。
    #[serde(default = "default_kubernetes_gateway_controller_name")]
    pub gateway_controller_name: String,
    /// namespace allowlist；空表示全部 namespace。
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// 相邻 API 轮询的最小间隔，单位毫秒。
    #[serde(default = "default_registry_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// 单次 Kubernetes API 请求 deadline，单位毫秒。
    #[serde(default = "default_registry_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// API 失联时保留上次已验证路由的时间；到期物化空集合并触发标准 reload。
    #[serde(default = "default_registry_stale_ttl_ms")]
    pub stale_ttl_ms: u64,
    /// 单次 API 响应允许读取的最大字节数。
    #[serde(default = "default_registry_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 单轮最多接管的 Ingress/HTTPRoute 对象数。
    #[serde(default = "default_kubernetes_route_max_objects")]
    pub max_objects: usize,
    /// 最终生成 route 数硬预算。
    #[serde(default = "default_kubernetes_route_max_routes")]
    pub max_routes: usize,
}

impl Default for KubernetesRouteSourceCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            target_proxy: default_kubernetes_route_target_proxy(),
            materialized_file: default_kubernetes_route_materialized_file(),
            ingress_enabled: true,
            ingress_classes: default_kubernetes_ingress_classes(),
            gateway_api_enabled: true,
            gateway_controller_name: default_kubernetes_gateway_controller_name(),
            namespaces: Vec::new(),
            poll_interval_ms: default_registry_poll_interval_ms(),
            request_timeout_ms: default_registry_request_timeout_ms(),
            stale_ttl_ms: default_registry_stale_ttl_ms(),
            max_response_bytes: default_registry_max_response_bytes(),
            max_objects: default_kubernetes_route_max_objects(),
            max_routes: default_kubernetes_route_max_routes(),
        }
    }
}

impl Default for KubernetesDiscoveryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            api_server: String::new(),
            namespace: default_kubernetes_namespace(),
            bearer_token: String::new(),
            ca_certificate: String::new(),
            poll_interval_ms: default_registry_poll_interval_ms(),
            request_timeout_ms: default_registry_request_timeout_ms(),
            stale_ttl_ms: default_registry_stale_ttl_ms(),
            max_response_bytes: default_registry_max_response_bytes(),
            max_instances: default_registry_max_instances(),
        }
    }
}

const fn default_registry_poll_interval_ms() -> u64 {
    5_000
}
const fn default_registry_request_timeout_ms() -> u64 {
    2_000
}
const fn default_registry_stale_ttl_ms() -> u64 {
    30_000
}
const fn default_registry_max_response_bytes() -> usize {
    4 * 1024 * 1024
}
const fn default_registry_max_instances() -> usize {
    1_024
}
const fn default_dns_max_addresses() -> usize {
    256
}
fn default_kubernetes_namespace() -> String {
    "default".to_owned()
}
fn default_kubernetes_route_target_proxy() -> String {
    "default".to_owned()
}
fn default_kubernetes_route_materialized_file() -> String {
    ".gateway-kubernetes-routes.json".to_owned()
}
fn default_kubernetes_ingress_classes() -> Vec<String> {
    vec!["gateway".to_owned()]
}
fn default_kubernetes_gateway_controller_name() -> String {
    "gateway.rust.dev/controller".to_owned()
}
const fn default_kubernetes_route_max_objects() -> usize {
    4_096
}
const fn default_kubernetes_route_max_routes() -> usize {
    4_096
}

/// 控制面配置文档来源。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ConfigSourceCfg {
    /// Nacos 配置中心统一配置来源。启用后由 reload worker watch 远端三份配置并 build-then-swap。
    #[serde(default)]
    pub nacos: NacosConfigSourceCfg,
}

/// Nacos 配置中心三文档或原子 bundle 的 bootstrap 配置。
#[derive(Debug, Deserialize, Clone)]
pub struct NacosConfigSourceCfg {
    /// 是否启用 Nacos 配置中心 watch。默认 false,本地文件继续作为 bootstrap 与单机模式。
    #[serde(default)]
    pub enabled: bool,
    /// Nacos server 地址,如 `"127.0.0.1:8848"` 或逗号分隔多地址。
    #[serde(default)]
    pub server_addr: String,
    /// Nacos namespace ID;public 空间留空。
    #[serde(default)]
    pub namespace: String,
    /// Nacos group。
    #[serde(default = "default_nacos_group")]
    pub group: String,
    /// Nacos 端来源标识。
    #[serde(default = "default_nacos_app_name")]
    pub app_name: String,
    /// Nacos 鉴权用户名。
    #[serde(default)]
    pub username: String,
    /// Nacos 鉴权密码。
    #[serde(default)]
    pub password: String,
    /// 主配置 dataId。内容应是完整 `gateway.yml`。
    #[serde(default = "default_nacos_gateway_data_id")]
    pub gateway_data_id: String,
    /// 接口守卫 dataId。内容应是完整 `interface-guard.yml`。
    #[serde(default = "default_nacos_interface_guard_data_id")]
    pub interface_guard_data_id: String,
    /// Sentinel 规则 dataId。内容应是完整 `sentinel-rules.yml`。
    #[serde(default = "default_nacos_sentinel_rules_data_id")]
    pub sentinel_rules_data_id: String,
    /// 可选单 dataId 原子 bundle：JSON 同时携带 gateway/interface-guard/sentinel 三份
    /// 完整文档与 bundle_version。非空时 watcher/回滚只 CAS 该 dataId，不再消费三个
    /// 独立 dataId；空字符串保留旧兼容模式。
    #[serde(default)]
    pub bundle_data_id: String,
    /// 远端配置私有物化目录。相对本地 bootstrap gateway.yml 所在目录;不会覆盖 operator 手写文件。
    #[serde(default = "default_nacos_materialized_dir")]
    pub materialized_dir: String,
    /// watch/connect 失败后的重连退避。
    #[serde(default = "default_nacos_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for NacosConfigSourceCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: String::new(),
            namespace: String::new(),
            group: default_nacos_group(),
            app_name: default_nacos_app_name(),
            username: String::new(),
            password: String::new(),
            gateway_data_id: default_nacos_gateway_data_id(),
            interface_guard_data_id: default_nacos_interface_guard_data_id(),
            sentinel_rules_data_id: default_nacos_sentinel_rules_data_id(),
            bundle_data_id: String::new(),
            materialized_dir: default_nacos_materialized_dir(),
            reconnect_backoff_ms: default_nacos_reconnect_backoff_ms(),
        }
    }
}

/// 可跨节点共享的限流、动态集合、熔断和缓存运行态配置。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuntimeStateCfg {
    /// 高频限流计数后端。默认 local,单机完整可用;集群共享限流显式切 redis。
    #[serde(default)]
    pub rate_limiter: RateLimiterBackendCfg,
    /// 低频动态事实源后端。黑名单、临时禁用等运行态集合复用它。
    #[serde(default)]
    pub store: DynamicStoreBackendCfg,
    /// IP 黑名单数据面缓存配置。
    #[serde(default)]
    pub blacklist: BlacklistCfg,
    /// 集群级接口禁用动态覆盖。用于紧急 disable 全网互通,热路径只读本地缓存。
    #[serde(default)]
    pub interface_disable: InterfaceDisableCfg,
    /// 熔断滑动窗口统计后端(§10.6 R3)。默认本地各自统计;显式开启后跨节点共享统计。
    #[serde(default)]
    pub circuit_breaker: CircuitStatsBackendCfg,
    /// HMAC 防重放守卫后端(§20)。默认本地各自去重;`redis` 跨节点 `SET NX PX` 去重。
    #[serde(default)]
    pub replay_guard: ReplayGuardBackendCfg,
    /// V5 HTTP 响应缓存的共享 L2 后端。默认 local/off，保持网关零外部依赖；
    /// route 只有显式 `proxy_cache ... l2=true` 才会访问这里配置的 Redis。
    #[serde(default)]
    pub http_cache: HttpCacheBackendCfg,
}

/// HTTP 响应缓存 L2 后端配置。
///
/// 连接参数属于 bootstrap 资源：数据面 route/TTL 可热更，但 Redis URL、协议 profile、key
/// 前缀或失效频道变更需要重启，避免换连接时旧订阅与新写入形成短暂双事实源。
#[derive(Debug, Deserialize, Clone)]
pub struct HttpCacheBackendCfg {
    /// `local`/`off` 表示只有 route 自带 L1；`redis` 打开跨节点 L2。
    #[serde(default = "default_http_cache_backend")]
    pub backend: String,
    /// Redis 连接参数。仅 `backend: redis` 时使用。
    #[serde(default)]
    pub redis: RedisRuntimeCfg,
    /// Redis data/generation key 前缀。实际 key 只含 SHA-256 摘要，不暴露 Vary 原值。
    #[serde(default = "default_http_cache_redis_prefix")]
    pub prefix: String,
    /// route generation 失效广播频道。
    #[serde(default = "default_http_cache_invalidation_channel")]
    pub invalidation_channel: String,
    /// Pub/Sub 断线漏事件的 generation 对账周期(ms)。0 不允许，避免永久脏 L1。
    #[serde(default = "default_http_cache_reconcile_interval_ms")]
    pub reconcile_interval_ms: u64,
}

impl Default for HttpCacheBackendCfg {
    fn default() -> Self {
        Self {
            backend: default_http_cache_backend(),
            redis: RedisRuntimeCfg::default(),
            prefix: default_http_cache_redis_prefix(),
            invalidation_channel: default_http_cache_invalidation_channel(),
            reconcile_interval_ms: default_http_cache_reconcile_interval_ms(),
        }
    }
}

/// HMAC 防重放守卫后端配置(§20 `SET NX PX` ReplayGuard)。
#[derive(Debug, Deserialize, Clone)]
pub struct ReplayGuardBackendCfg {
    /// 后端类型:`local`(单进程内存去重)或 `redis`(跨节点 `SET NX PX`)。默认 local。
    #[serde(default = "default_replay_guard_backend")]
    pub backend: String,
    /// Redis 后端异常时策略:`open` 视为 fresh 放行(签名仍已验,只放开窄重放窗口)、`closed` 视为重放拒绝。
    /// 默认 `open`——对齐「核心绝不硬依赖 Redis」,Redis 抖动不阻断已签名请求。
    #[serde(default = "default_replay_guard_fail_mode")]
    pub fail_mode: String,
}

impl Default for ReplayGuardBackendCfg {
    fn default() -> Self {
        Self {
            backend: default_replay_guard_backend(),
            fail_mode: default_replay_guard_fail_mode(),
        }
    }
}

/// 防重放后端默认类型:本地内存去重,零外部依赖。
fn default_replay_guard_backend() -> String {
    "local".to_string()
}

/// 防重放后端默认失败策略:fail-open(不硬依赖 Redis)。
fn default_replay_guard_fail_mode() -> String {
    "open".to_string()
}

/// 熔断统计后端配置(§10.6 line1142「本地各自熔断 vs 共享统计」)。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CircuitStatsBackendCfg {
    /// 是否把熔断滑动窗口统计【共享到 Redis】,让开闭决策依据集群聚合错误率(更准),而非仅本节点(快)。
    ///
    /// 默认 `false` = 每节点本地各自统计(零依赖、低延迟,单机/集群都可用)。
    /// `true` = 复用 `rate_limiter.redis` 连接,把成功/失败计入 Redis 分桶滑动窗口,各节点读集群聚合值决定跳闸。
    /// **显式开关**:不随 `rate_limiter.backend=redis` 隐式生效,避免改限流后端时意外改变熔断语义。
    #[serde(default)]
    pub shared: bool,
}

/// 高频请求限流计数器后端。
#[derive(Debug, Deserialize, Clone)]
pub struct RateLimiterBackendCfg {
    /// 后端类型:`local`(单进程令牌桶) 或 `redis`(nadis Lua 原子令牌桶)。
    #[serde(default = "default_rate_limiter_backend")]
    pub backend: String,
    /// Redis 后端异常时的策略:`open` 放行保可用,`closed` 拒绝保后端。
    #[serde(default = "default_rate_limiter_fail_mode")]
    pub fail_mode: String,
    /// Redis 连接参数。仅 `backend: redis` 时使用。
    #[serde(default)]
    pub redis: RedisRuntimeCfg,
}

impl Default for RateLimiterBackendCfg {
    fn default() -> Self {
        Self {
            backend: default_rate_limiter_backend(),
            fail_mode: default_rate_limiter_fail_mode(),
            redis: RedisRuntimeCfg::default(),
        }
    }
}

/// 低频动态键值集合后端。
#[derive(Debug, Deserialize, Clone)]
pub struct DynamicStoreBackendCfg {
    /// 后端类型:`file` 或 `redis`。默认 file,零外部依赖。
    #[serde(default = "default_dynamic_store_backend")]
    pub backend: String,
    /// file 后端配置。
    #[serde(default)]
    pub file: FileStoreCfg,
    /// Redis 后端配置。仅 `backend: redis` 时使用。
    #[serde(default)]
    pub redis: RedisStoreCfg,
}

impl Default for DynamicStoreBackendCfg {
    fn default() -> Self {
        Self {
            backend: default_dynamic_store_backend(),
            file: FileStoreCfg::default(),
            redis: RedisStoreCfg::default(),
        }
    }
}

/// 本地文件动态集合后端。
#[derive(Debug, Deserialize, Clone)]
pub struct FileStoreCfg {
    /// 运行态文件根目录;相对路径按 gateway.yml 所在目录解析。
    #[serde(default = "default_dynamic_store_file_root")]
    pub root: String,
}

impl Default for FileStoreCfg {
    fn default() -> Self {
        Self {
            root: default_dynamic_store_file_root(),
        }
    }
}

/// Redis 动态集合后端连接与命名配置。
#[derive(Debug, Deserialize, Clone)]
pub struct RedisStoreCfg {
    /// Redis URL,如 `redis://:password@127.0.0.1:6379`。
    #[serde(default)]
    pub url: String,
    /// nadis 协议命名空间。
    #[serde(default = "default_runtime_redis_namespace")]
    pub namespace: String,
    /// nadis 兼容 profile。
    #[serde(default = "default_runtime_redis_profile")]
    pub profile: String,
    /// 动态集合 Redis key 前缀。
    #[serde(default = "default_dynamic_store_redis_prefix")]
    pub prefix: String,
}

impl Default for RedisStoreCfg {
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_runtime_redis_namespace(),
            profile: default_runtime_redis_profile(),
            prefix: default_dynamic_store_redis_prefix(),
        }
    }
}

/// IP 黑名单本地缓存与自动拉黑配置。
#[derive(Debug, Deserialize, Clone)]
pub struct BlacklistCfg {
    /// 是否启用 IP 黑名单缓存。
    #[serde(default)]
    pub enabled: bool,
    /// DynamicStore collection 名。
    #[serde(default = "default_blacklist_collection")]
    pub collection: String,
    /// 刷新间隔(ms)。
    #[serde(default = "default_blacklist_refresh_interval_ms")]
    pub refresh_interval_ms: u64,
    /// 自动拉黑策略。默认关闭;启用后由数据面在限流拒绝等信号上写入临时黑名单。
    #[serde(default)]
    pub auto_ban: AutoBanCfg,
}

impl Default for BlacklistCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            collection: default_blacklist_collection(),
            refresh_interval_ms: default_blacklist_refresh_interval_ms(),
            auto_ban: AutoBanCfg::default(),
        }
    }
}

/// 集群级接口禁用覆盖的本地缓存配置。
#[derive(Debug, Deserialize, Clone)]
pub struct InterfaceDisableCfg {
    /// 是否启用动态接口禁用覆盖。
    #[serde(default)]
    pub enabled: bool,
    /// DynamicStore collection 名。
    #[serde(default = "default_interface_disable_collection")]
    pub collection: String,
    /// 刷新间隔(ms)。Redis 后端有 watch 时事件驱动,该间隔作为兜底。
    #[serde(default = "default_interface_disable_refresh_interval_ms")]
    pub refresh_interval_ms: u64,
}

impl Default for InterfaceDisableCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            collection: default_interface_disable_collection(),
            refresh_interval_ms: default_interface_disable_refresh_interval_ms(),
        }
    }
}

/// 由限流拒绝信号驱动的临时 IP 自动拉黑策略。
#[derive(Debug, Deserialize, Clone)]
pub struct AutoBanCfg {
    /// 是否启用自动拉黑。
    #[serde(default)]
    pub enabled: bool,
    /// 同一 IP 在窗口内被 limit_req 拒绝达到该次数后拉黑。
    #[serde(default = "default_auto_ban_limit_req_rejections")]
    pub limit_req_rejections: u64,
    /// 统计窗口(ms)。
    #[serde(default = "default_auto_ban_window_ms")]
    pub window_ms: u64,
    /// 拉黑 TTL(ms),到期后后台刷新自动解封。
    #[serde(default = "default_auto_ban_ttl_ms")]
    pub ban_ttl_ms: u64,
    /// 解封后短期豁免窗口(ms,§18「ban/unban 抖动」)。手工解封某 IP 后,本节点在该窗口内
    /// **不再自动拉黑**它,避免刚解封又被限流信号立刻 auto-ban 的抖动。0 = 关闭(默认)。
    #[serde(default)]
    pub unban_exempt_ms: u64,
}

impl Default for AutoBanCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            limit_req_rejections: default_auto_ban_limit_req_rejections(),
            window_ms: default_auto_ban_window_ms(),
            ban_ttl_ms: default_auto_ban_ttl_ms(),
            unban_exempt_ms: 0,
        }
    }
}

/// 运行态组件复用的 Redis 连接参数。
#[derive(Debug, Deserialize, Clone)]
pub struct RedisRuntimeCfg {
    /// Redis URL,如 `redis://:password@127.0.0.1:6379`。
    #[serde(default)]
    pub url: String,
    /// nadis 协议命名空间,隔离协议 marker 与运行态 key。
    #[serde(default = "default_runtime_redis_namespace")]
    pub namespace: String,
    /// nadis 兼容 profile:`RustV2` 或 `LegacyV1`。新部署默认 RustV2。
    #[serde(default = "default_runtime_redis_profile")]
    pub profile: String,
}

impl Default for RedisRuntimeCfg {
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_runtime_redis_namespace(),
            profile: default_runtime_redis_profile(),
        }
    }
}

/// Nacos 服务发现与网关自注册配置。
#[derive(Debug, Deserialize, Clone)]
pub struct NacosDiscoveryCfg {
    /// 是否启用 Nacos 动态服务发现。未启用时 `source: nacos` 服务会保持无实例并使 critical readyz 失败。
    #[serde(default)]
    pub enabled: bool,
    /// Nacos server 地址,如 `"127.0.0.1:8848"` 或逗号分隔多地址。
    #[serde(default)]
    pub server_addr: String,
    /// Nacos namespace ID;public 空间留空。
    #[serde(default)]
    pub namespace: String,
    /// Nacos group。
    #[serde(default = "default_nacos_group")]
    pub group: String,
    /// Nacos 端来源标识。
    #[serde(default = "default_nacos_app_name")]
    pub app_name: String,
    /// 可选对外 IP,用于后续网关自注册;发现侧不强依赖。
    #[serde(default)]
    pub discovery_ip: Option<String>,
    /// 网关节点自注册配置。默认关闭。
    #[serde(default)]
    pub self_register: GatewaySelfRegisterCfg,
    /// Nacos 鉴权用户名。
    #[serde(default)]
    pub username: String,
    /// Nacos 鉴权密码。
    #[serde(default)]
    pub password: String,
    /// subscribe_channel 的 discover 轮询兜底间隔。
    #[serde(default = "default_nacos_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// watch 中断后 last-known-good 可被视为 fresh 的时间;超出后 readyz 对 critical 服务降级。
    #[serde(default = "default_nacos_stale_ttl_ms")]
    pub stale_ttl_ms: u64,
    /// watch/connect 失败后的重连退避。
    #[serde(default = "default_nacos_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

/// 网关节点自注册到 Nacos 的配置。
#[derive(Debug, Deserialize, Clone)]
pub struct GatewaySelfRegisterCfg {
    /// 是否把本 gateway 节点注册到 Nacos。
    #[serde(default)]
    pub enabled: bool,
    /// 注册服务名。为空时使用 `discovery.nacos.app_name`。
    #[serde(default)]
    pub service_name: String,
    /// 对外 IP。为空时优先用 `discovery.nacos.discovery_ip`,再尝试使用数据面 listen IP。
    #[serde(default)]
    pub ip: Option<String>,
    /// 对外端口。0 表示使用默认数据面 proxy listen 端口。
    #[serde(default)]
    pub port: u16,
    /// 注册实例权重。
    #[serde(default = "default_self_register_weight")]
    pub weight: f64,
    /// 是否注册为临时实例。
    #[serde(default = "default_true")]
    pub ephemeral: bool,
    /// 可选 Nacos cluster。
    #[serde(default)]
    pub cluster: Option<String>,
    /// 自定义 metadata。
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// 优雅停机显式 deregister 超时。
    #[serde(default = "default_self_register_deregister_timeout_ms")]
    pub deregister_timeout_ms: u64,
}

impl Default for GatewaySelfRegisterCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: String::new(),
            ip: None,
            port: 0,
            weight: default_self_register_weight(),
            ephemeral: true,
            cluster: None,
            metadata: HashMap::new(),
            deregister_timeout_ms: default_self_register_deregister_timeout_ms(),
        }
    }
}

impl Default for NacosDiscoveryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            server_addr: String::new(),
            namespace: String::new(),
            group: default_nacos_group(),
            app_name: default_nacos_app_name(),
            discovery_ip: None,
            self_register: GatewaySelfRegisterCfg::default(),
            username: String::new(),
            password: String::new(),
            poll_interval_ms: default_nacos_poll_interval_ms(),
            stale_ttl_ms: default_nacos_stale_ttl_ms(),
            reconnect_backoff_ms: default_nacos_reconnect_backoff_ms(),
        }
    }
}

/// 一条 HTTP 路由及其断言、过滤器、后端和资源预算。
#[derive(Debug, Deserialize, Clone)]
pub struct RouteCfg {
    /// route 唯一标识,用于日志、指标和动态规则关联。
    pub id: String,
    /// R1:直连上游 `http://host:port`;R2:`lb://service`(交 nasa::discovery 解析)。
    #[serde(default)]
    pub uri: String,
    /// route 后端类型。`serve.static` 与 `uri` 二选一,用于本地静态/SPA 托管。
    #[serde(default)]
    pub serve: Option<RouteServeCfg>,
    /// 路由断言 DSL 列表。
    #[serde(default)]
    pub predicates: Vec<String>,
    /// route filter DSL 列表。
    #[serde(default)]
    pub filters: Vec<String>,
    /// V5 请求契约校验。未配置时保持纯流式快路径；body 校验必须携带显式有界上限。
    #[serde(default)]
    pub request_validation: Option<RequestValidationCfg>,
    /// V7 GraphQL 查询预算守卫。未配置时普通 HTTP route 不读取或解析请求体。
    #[serde(default)]
    pub graphql_guard: Option<GraphqlGuardCfg>,
    /// V7 degraphql：把声明式 REST GET 映射为固定 GraphQL POST；查询在构建期解析计费。
    #[serde(default)]
    pub degraphql: Option<DegraphqlCfg>,
    /// V7 OPA 外部策略授权。认证身份只来自已经通过的 JWT/API-Key/Basic，不信任客户端身份头。
    #[serde(default)]
    pub opa_authorization: Option<OpaAuthorizationCfg>,
    /// V7 内嵌 Casbin RBAC/ABAC 授权。model/policy 在快照构建期读取并编译，
    /// 数据面不做文件 I/O，也不信任客户端自报的主体头。
    #[serde(default)]
    pub casbin_authorization: Option<CasbinAuthorizationCfg>,
    /// V7 Proxy-Wasm 头部插件链。模块在快照构建期编译，请求期只执行已编译代码；
    /// 数组顺序就是同一 phase 的执行顺序。
    #[serde(default)]
    pub wasm_plugins: Vec<WasmPluginCfg>,
    /// V7 外部 HTTP 头部插件链。插件只接收显式 allowlist 的 head 元数据，业务 body
    /// 永不离开网关；数组顺序就是同一 phase 的执行顺序。
    #[serde(default)]
    pub external_plugins: Vec<ExternalPluginCfg>,
    /// V7 BFF 有界扇出聚合。它是终端后端，与 uri/serve/llm/mock 互斥。
    #[serde(default)]
    pub bff_aggregation: Option<BffAggregationCfg>,
    /// V7 HTTP→Dubbo2 generic `$invoke` 终端后端。
    #[serde(default)]
    pub dubbo: Option<DubboRouteCfg>,
    /// V7 typed API mock。适合从 OpenAPI example 物化后的稳定响应；与其它后端互斥。
    #[serde(default)]
    pub mock_response: Option<MockResponseCfg>,
    /// V7 chaos 故障注入。采样命中后先延迟、再可选返回固定错误，不读取请求 body。
    #[serde(default)]
    pub fault_injection: Option<FaultInjectionCfg>,
    /// V7 usage-plan 绑定。consumer 优先使用全局映射，未映射时可落到 default_plan。
    #[serde(default)]
    pub usage_plan: Option<UsagePlanRouteCfg>,
    /// V6 AI/LLM 统一 OpenAI-compatible 入口。存在时 route 不再使用顶层 `uri`，而由
    /// `models[]` 声明主模型与有序 fallback 后端。
    #[serde(default)]
    pub llm: Option<LlmRouteCfg>,
    /// V8 gRPC 边缘模式(架构规范 §25.2)。缺省/`enabled: false` 时本 route 保持
    /// Nginx/Envoy 式 L7 透传,一个字节不多碰;显式开启才进入 header 驱动的
    /// subscribe/publish 自响应。V8-0 仅做构建期契约校验与快照接线,数据面 no-op。
    #[serde(default)]
    pub grpc_edge: Option<GrpcEdgeCfg>,
    /// 该 route 的 SSE/gRPC 响应帧间空闲超时(ms)。None 继承 proxy
    /// `timeouts.stream_idle_timeout_ms`；显式 0 表示关闭。
    #[serde(default)]
    pub long_stream_idle_timeout_ms: Option<u64>,
    /// 该 route 的 SSE/gRPC 最长存活时间(ms)；0 表示不限制。超时时 gRPC 发
    /// status 14 trailer，SSE 结束 body，两者都释放旧快照与上游连接。
    #[serde(default)]
    pub long_stream_max_lifetime_ms: u64,
    /// 路由优先级(据 review L5 / §4.2):数值【小】者优先;同值按配置书写顺序(SCG 有序语义)。
    /// 用于在 yaml 不便重排时显式定序,如 `/api/admin/**`(order:-10)优先于 `/api/**`(order:0)兜底。
    #[serde(default)]
    pub order: i32,
}

/// 一个 route 绑定的 Proxy-Wasm ABI v0.2.1 插件。
///
/// V7 首个完整执行面只开放 request/response headers：不向客体映射业务 body，
/// 不挂 WASI，也不给文件、socket、时钟以外的环境能力。这使默认数据面仍保持流式，
/// 插件的每份额外拷贝都被限定在显式选用的 header 慢路径。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmPluginCfg {
    /// 稳定插件 id，仅用于构建报错和低基数日志。
    pub id: String,
    /// `.wasm` 文件，相对于 gateway.yml 所在目录。
    pub module_file: String,
    /// 执行相位。
    pub phase: WasmPluginPhaseCfg,
    /// 传给 `proxy_on_configure` 的 JSON 值；构建期序列化并执行 64KiB 硬上限。
    #[serde(default)]
    pub config: serde_json::Value,
    /// 插件 trap/超时/越界时是否跳过本插件。默认 false，安全故障关闭。
    #[serde(default)]
    pub fail_open: bool,
    /// wasm 文件最大字节数。
    #[serde(default = "default_wasm_max_module_bytes")]
    pub max_module_bytes: usize,
    /// 单次实例线性内存上限。
    #[serde(default = "default_wasm_max_memory_bytes")]
    pub max_memory_bytes: usize,
    /// 单次调用可消耗的 Wasmtime fuel。
    #[serde(default = "default_wasm_max_fuel")]
    pub max_fuel: u64,
    /// 单次调用墙钟上限；epoch 中断防止 host call/非预期路径绕过 fuel 预算。
    #[serde(default = "default_wasm_timeout_ms")]
    pub timeout_ms: u64,
    /// 单次调用允许的 header/local-response 变更次数。
    #[serde(default = "default_wasm_max_mutations")]
    pub max_mutations: usize,
    /// 插件可见并可交付的整份 header map 上限。
    #[serde(default = "default_wasm_max_header_bytes")]
    pub max_header_bytes: usize,
    /// `proxy_send_local_response` 响应体上限；本地响应是插件唯一可生成的 body。
    #[serde(default = "default_wasm_max_local_response_body_bytes")]
    pub max_local_response_body_bytes: usize,
}

/// 一个 route 绑定的外部 HTTP 头部插件。
///
/// 插件 endpoint 收到固定 JSON contract，返回 `continue` 头部变更或有界
/// `local_response`。所有可见头和可修改头都必须显式声明；认证凭据只通过独立的
/// `authorization` SecretSource 注入，不会混入业务请求头集合。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExternalPluginCfg {
    /// 稳定插件 id，仅用于配置错误和结构化日志，不进入 Prometheus label。
    pub id: String,
    /// `http(s)://host[:port]` 或 `lb://service` origin。
    pub target: String,
    /// endpoint 固定绝对 path，不允许 query。
    #[serde(default = "default_external_plugin_path")]
    pub path: String,
    /// 执行相位。
    pub phase: ExternalPluginPhaseCfg,
    /// response head + body 的共同 deadline。
    #[serde(default = "default_external_plugin_timeout_ms")]
    pub timeout_ms: u64,
    /// transport、非 2xx 或畸形响应时是否丢弃本插件结果并继续；默认故障关闭。
    #[serde(default)]
    pub fail_open: bool,
    /// 发给插件 endpoint 的完整 Authorization 值；支持 SecretSource，默认不发送。
    #[serde(default)]
    pub authorization: String,
    /// 插件可以读取的请求头 allowlist。响应相位只快照这些头，不 clone 整份请求 head。
    #[serde(default)]
    pub include_request_headers: Vec<String>,
    /// 响应相位插件可以读取的响应头 allowlist；请求相位必须为空。
    #[serde(default)]
    pub include_response_headers: Vec<String>,
    /// `continue.set_headers/remove_headers` 可以修改的当前相位头 allowlist。
    #[serde(default)]
    pub mutation_headers: Vec<String>,
    /// 单个可见/返回 header value 的 UTF-8 字节上限。
    #[serde(default = "default_external_plugin_max_header_value_bytes")]
    pub max_header_value_bytes: usize,
    /// 发给插件的 JSON 硬上限；转义扩张也在有界 writer 内检查。
    #[serde(default = "default_external_plugin_max_input_bytes")]
    pub max_input_bytes: usize,
    /// 插件响应 body 硬上限。
    #[serde(default = "default_external_plugin_max_response_bytes")]
    pub max_response_bytes: usize,
    /// `local_response.body` UTF-8 字节硬上限。
    #[serde(default = "default_external_plugin_max_local_response_body_bytes")]
    pub max_local_response_body_bytes: usize,
}

/// 外部 HTTP 插件执行相位。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPluginPhaseCfg {
    /// 本地认证/OPA/Casbin/Proxy-Wasm 之后，请求体校验之前。
    RequestHeaders,
    /// 内部跳转、error_page 和声明式响应过滤之后，Proxy-Wasm/压缩之前。
    ResponseHeaders,
}

fn default_external_plugin_path() -> String {
    "/v1/plugin".to_owned()
}

const fn default_external_plugin_timeout_ms() -> u64 {
    200
}

const fn default_external_plugin_max_header_value_bytes() -> usize {
    16 * 1024
}

const fn default_external_plugin_max_input_bytes() -> usize {
    256 * 1024
}

const fn default_external_plugin_max_response_bytes() -> usize {
    256 * 1024
}

const fn default_external_plugin_max_local_response_body_bytes() -> usize {
    64 * 1024
}

/// 一条 BFF 聚合 route 的资源预算与子请求列表。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BffAggregationCfg {
    /// 有序子请求列表；每个 target id 对应聚合 JSON 的一个键。
    pub targets: Vec<BffTargetCfg>,
    /// 聚合 JSON 最大编码字节数。
    #[serde(default = "default_bff_max_total_response_bytes")]
    pub max_total_response_bytes: usize,
    /// 所有 fan-out 的共同总 deadline。
    #[serde(default = "default_bff_total_timeout_ms")]
    pub total_timeout_ms: u64,
}

/// BFF 中一个只读 HTTP 子请求。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BffTargetCfg {
    /// 合并结果中的稳定 key。
    pub id: String,
    /// `http(s)://` 或 `lb://service`。
    pub uri: String,
    /// 固定 origin path；不接受 query/模板，避免客户端参数越权扇出。
    #[serde(default = "default_bff_path")]
    pub path: String,
    /// 单子请求 deadline。
    #[serde(default = "default_bff_target_timeout_ms")]
    pub timeout_ms: u64,
    /// 单子响应 body 上限。
    #[serde(default = "default_bff_max_target_response_bytes")]
    pub max_response_bytes: usize,
    /// true：失败使整个聚合失败；false：结果 key 为 null，并在 `_errors` 给固定状态。
    #[serde(default = "default_true")]
    pub required: bool,
    /// 从已认证下游 head 转发的非敏感 header allowlist；默认空。
    #[serde(default)]
    pub forward_headers: Vec<String>,
}

/// HTTP JSON→Dubbo2 generic invocation。service/method/type 全由 route 固定，客户端只提供
/// `arguments`，避免把公网输入升级成任意 RPC 调用器。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DubboRouteCfg {
    /// Dubbo service interface 全限定名。
    pub interface: String,
    /// 实际业务 method；wire method 固定为 `$invoke`。
    pub method: String,
    /// 与 arguments 一一对应的 Java 参数类型名。
    #[serde(default)]
    pub parameter_types: Vec<String>,
    /// Dubbo service version。
    #[serde(default)]
    pub version: String,
    /// Dubbo service group。
    #[serde(default)]
    pub group: String,
    /// wire serialization；首个原生闭环显式支持 Dubbo JSON id=6。
    #[serde(default)]
    pub serialization: DubboSerializationCfg,
    /// 下游 JSON body 上限。
    #[serde(default = "default_dubbo_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
    /// Dubbo response frame body 上限。
    #[serde(default = "default_dubbo_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    /// TCP connect 上限。
    #[serde(default = "default_dubbo_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// write + response header/body 总 deadline。
    #[serde(default = "default_dubbo_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// 每个 endpoint 的空闲连接上限；0 禁用复用。
    #[serde(default = "default_dubbo_max_idle_connections")]
    pub max_idle_connections: usize,
    /// 固定 Dubbo attachments；值支持 SecretSource，构建期解析。
    #[serde(default)]
    pub attachments: HashMap<String, String>,
}

/// Dubbo2 wire 序列化类型。
#[derive(Debug, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum DubboSerializationCfg {
    /// Dubbo serialization id 6；provider 必须显式支持 `json`。
    #[default]
    Json,
}

const fn default_dubbo_max_request_body_bytes() -> u64 {
    1024 * 1024
}

const fn default_dubbo_max_response_body_bytes() -> usize {
    4 * 1024 * 1024
}

const fn default_dubbo_connect_timeout_ms() -> u64 {
    1000
}

const fn default_dubbo_request_timeout_ms() -> u64 {
    3000
}

const fn default_dubbo_max_idle_connections() -> usize {
    8
}

/// 构建期编译为固定响应的 API mock。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MockResponseCfg {
    /// 固定 HTTP 状态码。
    #[serde(default = "default_mock_status")]
    pub status: u16,
    /// 构建期验证并编译的固定响应头。
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// 固定 UTF-8 响应体。
    #[serde(default)]
    pub body: String,
}

/// route 级显式 chaos 注入。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FaultInjectionCfg {
    /// 0..=10000 basis points；10000 表示每次命中。
    pub percentage_bps: u16,
    /// 命中后异步延迟，不阻塞 Tokio worker。
    #[serde(default)]
    pub delay_ms: u64,
    /// 延迟后返回的固定错误；空表示只注入延迟后继续原后端。
    #[serde(default)]
    pub abort_status: Option<u16>,
    /// 注入固定错误时返回的 UTF-8 body。
    #[serde(default)]
    pub abort_body: String,
}

/// route 对全局 usage-plan 目录的绑定。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UsagePlanRouteCfg {
    /// 未出现在 `usage_plans.consumers` 的身份所用套餐；空表示不允许未映射 consumer。
    #[serde(default)]
    pub default_plan: Option<String>,
    /// true 时没有可信 consumer 直接 401；false 时匿名身份可使用 default_plan。
    #[serde(default = "default_true")]
    pub require_consumer: bool,
}

const fn default_bff_max_total_response_bytes() -> usize {
    4 * 1024 * 1024
}
const fn default_bff_total_timeout_ms() -> u64 {
    2_000
}
fn default_bff_path() -> String {
    "/".to_owned()
}
const fn default_bff_target_timeout_ms() -> u64 {
    1_000
}
const fn default_bff_max_target_response_bytes() -> usize {
    1024 * 1024
}
const fn default_mock_status() -> u16 {
    200
}

/// Proxy-Wasm 头部回调相位。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WasmPluginPhaseCfg {
    /// 认证与 OPA 通过后、请求体校验/限流/上游前。
    RequestHeaders,
    /// 内部跳转与 error_page 完成后、压缩/限速前。
    ResponseHeaders,
}

/// route 级内嵌 Casbin 决策配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CasbinAuthorizationCfg {
    /// Casbin PERM model CONF，相对于 gateway.yml 所在目录。
    pub model_file: String,
    /// Casbin CSV policy，相对于 gateway.yml 所在目录。
    pub policy_file: String,
    /// 按 model `[request_definition] r = ...` 顺序组装的参数。默认
    /// `[consumer, path, method]`；可用 route_id/client_ip/scheme/header:X-Resource 支持域与 ABAC。
    #[serde(default = "default_casbin_arguments")]
    pub arguments: Vec<String>,
    /// 是否强制已认证 consumer。false 时缺失主体统一传 `anonymous`。
    #[serde(default = "default_true")]
    pub require_identity: bool,
    /// 单个动态参数的 UTF-8 字节上限，防止超大 header/path 放大策略引擎。
    #[serde(default = "default_casbin_max_argument_bytes")]
    pub max_argument_bytes: usize,
    /// 一次 enforce 所有参数的合计字节上限。
    #[serde(default = "default_casbin_max_input_bytes")]
    pub max_input_bytes: usize,
    /// 只在 Casbin 内部执行异常时放行；明确 deny、缺主体或 input 超限永不 fail-open。
    #[serde(default)]
    pub fail_open: bool,
}

fn default_casbin_arguments() -> Vec<String> {
    vec![
        "consumer".to_owned(),
        "path".to_owned(),
        "method".to_owned(),
    ]
}

const fn default_casbin_max_argument_bytes() -> usize {
    4096
}

const fn default_casbin_max_input_bytes() -> usize {
    16 * 1024
}

const fn default_wasm_max_module_bytes() -> usize {
    16 * 1024 * 1024
}

const fn default_wasm_max_memory_bytes() -> usize {
    8 * 1024 * 1024
}

const fn default_wasm_max_fuel() -> u64 {
    10_000_000
}

const fn default_wasm_timeout_ms() -> u64 {
    10
}

const fn default_wasm_max_mutations() -> usize {
    64
}

const fn default_wasm_max_header_bytes() -> usize {
    64 * 1024
}

const fn default_wasm_max_local_response_body_bytes() -> usize {
    64 * 1024
}

/// V6 路由级 AI/LLM 代理配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmRouteCfg {
    /// 可接受的 JSON 请求体硬上限；LLM 格式转换需要显式有界缓冲。
    #[serde(default = "default_llm_max_body_bytes")]
    pub max_body_bytes: u64,
    /// tokenizer-independent prompt 估算硬上限；超出在调用模型前返回 413。
    #[serde(default = "default_llm_max_prompt_tokens")]
    pub max_prompt_tokens: u64,
    /// completion 允许上限；请求未声明 `max_tokens` 时也会注入该值，防无限输出。
    #[serde(default = "default_llm_max_completion_tokens")]
    pub max_completion_tokens: u64,
    /// 可选共享 token 配额；一次原子预留 prompt 估算 + completion 上限。
    #[serde(default)]
    pub token_quota: Option<LlmTokenQuotaCfg>,
    /// Prompt 注入/越权短语护栏。
    #[serde(default)]
    pub guardrails: LlmGuardrailsCfg,
    /// 可选精确 + embedding 语义缓存。未配置时不会计算缓存键、聚合额外响应或访问 Redis。
    #[serde(default)]
    pub semantic_cache: Option<LlmSemanticCacheCfg>,
    /// 多模型首选策略；无论策略如何，连接错误/超时/5xx 仍按剩余模型降级。
    #[serde(default)]
    pub selection: LlmSelectionCfg,
    /// 依次尝试的模型；首项是主模型，后续项只在连接错误、超时或 5xx 时 fallback。
    pub models: Vec<LlmModelCfg>,
}

/// V6 LLM 精确/语义两级缓存。
///
/// 缓存只接管非流式成功 JSON 响应；SSE 不会被聚合成伪流。语义查询必须配置真实 embedding
/// 服务，不使用字符串距离冒充语义相似度。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmSemanticCacheCfg {
    /// 缓存存活时间(ms)。L1 entry 自带单调时钟截止时间，L2 同时设置 Redis TTL。
    #[serde(default = "default_llm_cache_ttl_ms")]
    pub ttl_ms: u64,
    /// 单 route L1 与每个 L2 scope 的最大 entry 数。
    #[serde(default = "default_llm_cache_max_entries")]
    pub max_entries: u64,
    /// 允许缓存的模型响应最大字节数；更大的响应透明返回但不回填。
    #[serde(default = "default_llm_cache_max_response_bytes")]
    pub max_response_bytes: u64,
    /// 余弦相似度命中阈值，范围 0.0..=1.0。
    #[serde(default = "default_llm_cache_similarity_threshold")]
    pub similarity_threshold: f32,
    /// 一次语义查询最多比较的最近候选数，防止线性扫描无界。
    #[serde(default = "default_llm_cache_max_candidates")]
    pub max_candidates: usize,
    /// 是否使用 `runtime_state.http_cache` 的 Redis 作为跨节点 L2。
    #[serde(default)]
    pub l2: bool,
    /// 缓存隔离维度。默认 consumer，避免不同认证租户共享相似 prompt 的响应。
    #[serde(default)]
    pub scope: LlmCacheScopeCfg,
    /// OpenAI-compatible embedding 服务。
    pub embedding: LlmEmbeddingCfg,
}

/// LLM 语义缓存隔离维度。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmCacheScopeCfg {
    /// 整条 route 共享。只适合明确允许公共响应复用的匿名/公共知识场景。
    Route,
    /// 按已验证 consumer 隔离；匿名请求使用固定 anonymous scope。
    #[default]
    Consumer,
    /// 按已验证 API-Key 的 SHA-256 指纹隔离，原始 key 不进入缓存键。
    ApiKey,
}

/// OpenAI-compatible embedding 后端配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmEmbeddingCfg {
    /// embedding 服务地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// 发给 embedding 服务的模型名。
    pub model: String,
    /// API path；空时使用 `/v1/embeddings`。
    #[serde(default)]
    pub path: String,
    /// provider API key SecretSource；空表示不注入凭据。
    #[serde(default)]
    pub api_key: String,
    /// 接受的最大向量维度；provider 返回更大向量时 fail-open 跳过缓存。
    #[serde(default = "default_llm_embedding_max_dimensions")]
    pub max_dimensions: usize,
}

/// 单个 LLM 模型后端。客户端始终使用 OpenAI Chat Completions 契约，gateway 在构建好的
/// provider adapter 中完成必要格式转换。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmModelCfg {
    /// 配置内稳定、低基数模型 id，用于 metrics/日志；不接受请求动态值。
    pub id: String,
    /// `openai` 或 `anthropic`。
    pub provider: LlmProviderCfg,
    /// 模型后端地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// 发给 provider 的真实模型名。
    pub model: String,
    /// provider API path；空时使用 provider 安全默认值。
    #[serde(default)]
    pub path: String,
    /// provider API key SecretSource；空表示不注入凭据，适合本地 vLLM/Ollama。
    #[serde(default)]
    pub api_key: String,
    /// Anthropic API 版本；OpenAI provider 必须留空。
    #[serde(default)]
    pub anthropic_version: String,
    /// 每百万 prompt token 的微美元成本，用于低基数成本观测；0 表示未知。
    #[serde(default)]
    pub input_cost_microusd_per_million: u64,
    /// 每百万 completion token 的微美元成本；0 表示未知。
    #[serde(default)]
    pub output_cost_microusd_per_million: u64,
    /// 此模型提供的固定能力标签，如 `vision`/`tools`/`json`；只接受安全 ASCII token。
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// `selection.strategy=weighted` 的相对权重；0 表示不参与首选但仍可作为 fallback。
    #[serde(default = "default_llm_model_weight")]
    pub weight: u32,
}

/// 多模型选择策略。required_capabilities 在所有策略前先过滤不满足能力的模型。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct LlmSelectionCfg {
    /// `ordered` / `cost` / `latency` / `weighted`。
    #[serde(default)]
    pub strategy: LlmSelectionStrategyCfg,
    /// route 固定要求的能力集合，最多 16 项。
    #[serde(default)]
    pub required_capabilities: Vec<String>,
}

/// V6 模型首选排序策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmSelectionStrategyCfg {
    /// 按配置书写顺序，首项主模型。
    #[default]
    Ordered,
    /// 按 input+output 配置单价从低到高。
    Cost,
    /// 按本进程成功响应头延迟 EWMA 从低到高；无样本时保持配置顺序。
    Latency,
    /// 按配置权重为请求稳定选择首模型，其余保持 fallback 顺序。
    Weighted,
}

/// LLM token bucket 配额。与 QPS 共用 §17 RateLimiter，但 `cost` 是本次 token 预留值。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmTokenQuotaCfg {
    /// 每个窗口回填的 token 数。
    pub tokens: u64,
    /// 配额窗口毫秒。
    pub window_ms: u64,
    /// 允许额外突发的 token 数。
    #[serde(default)]
    pub burst: u64,
    /// `route` / `consumer` / `api_key`。
    #[serde(default)]
    pub dimension: LlmQuotaDimensionCfg,
    /// 当前规则最多保留的活跃维度数。
    #[serde(default = "default_llm_quota_max_active_keys")]
    pub max_active_keys: usize,
    /// 维度表达到上限时是否 fail-open；默认 false（配额安全优先）。
    #[serde(default)]
    pub active_keys_fail_open: bool,
}

/// LLM token 配额维度。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmQuotaDimensionCfg {
    /// 每 route 共享。
    #[default]
    Route,
    /// 使用已验证的 consumer 身份；匿名请求使用固定 anonymous 桶。
    Consumer,
    /// 使用已验证 API-Key 的 SHA-256 指纹；不把原 key 放进内存 key/Redis key。
    ApiKey,
}

/// Prompt 护栏配置。这里只提供确定、可审计的字符串规则，不假装使用了不存在的 ML 分类器。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct LlmGuardrailsCfg {
    /// 统一前置的可信 system prompt；空表示不装饰。只在 LLM 显式慢路径产生一次必要 JSON 重编码。
    #[serde(default)]
    pub system_prompt: String,
    /// ASCII 大小写不敏感的禁止子串，最多 64 条、每条最多 256 字节。
    #[serde(default)]
    pub blocked_substrings: Vec<String>,
    /// 非流式统一响应的禁止子串；命中后不把 provider body 发给下游。
    #[serde(default)]
    pub blocked_response_substrings: Vec<String>,
}

/// V6 首批支持的模型协议适配器。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProviderCfg {
    /// OpenAI Chat Completions 兼容协议，也用于 vLLM/Ollama 的兼容入口。
    Openai,
    /// Anthropic Messages API。
    Anthropic,
}

fn default_llm_max_body_bytes() -> u64 {
    1024 * 1024
}

fn default_llm_max_prompt_tokens() -> u64 {
    128 * 1024
}

fn default_llm_max_completion_tokens() -> u64 {
    8 * 1024
}

fn default_llm_quota_max_active_keys() -> usize {
    100_000
}

fn default_llm_cache_ttl_ms() -> u64 {
    300_000
}

fn default_llm_cache_max_entries() -> u64 {
    10_000
}

fn default_llm_cache_max_response_bytes() -> u64 {
    1024 * 1024
}

fn default_llm_cache_similarity_threshold() -> f32 {
    0.92
}

fn default_llm_cache_max_candidates() -> usize {
    128
}

fn default_llm_embedding_max_dimensions() -> usize {
    4096
}

fn default_llm_model_weight() -> u32 {
    100
}

/// 路由级 OpenAPI / JSON Schema 请求校验配置。
///
/// `head_schema` 校验一个稳定 envelope：`method`/`path`/`query`/`headers`/
/// `path_params`。query/header 的每个值都是字符串数组，既保留重复值，也避免静默选择
/// 第一个值造成参数污染。`body_schema` 只校验 JSON body。两者都在 build-then-swap
/// 阶段编译；请求热路径不会重新解析 schema。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RequestValidationCfg {
    /// 内联 head JSON Schema；与 `head_schema_file` 二选一。
    #[serde(default)]
    pub head_schema: Option<serde_json::Value>,
    /// head JSON/YAML Schema 文件；相对路径按 `gateway.yml` 所在目录解析。
    #[serde(default)]
    pub head_schema_file: Option<String>,
    /// 内联 JSON body Schema；与 `body_schema_file` 二选一。
    #[serde(default)]
    pub body_schema: Option<serde_json::Value>,
    /// body JSON/YAML Schema 文件；相对路径按 `gateway.yml` 所在目录解析。
    #[serde(default)]
    pub body_schema_file: Option<String>,
    /// OpenAPI 3 JSON/YAML 文件。设置时由 `operation_id` 定位 operation，并与显式 schema 互斥。
    #[serde(default)]
    pub openapi_file: Option<String>,
    /// OpenAPI operationId；使用 `openapi_file` 时必填。
    #[serde(default)]
    pub operation_id: Option<String>,
    /// OpenAPI path template；与 `operation_method` 成对，用于没有 operationId 的门户导入。
    #[serde(default)]
    pub operation_path: Option<String>,
    /// OpenAPI method；与 `operation_path` 成对，和 `operation_id` 二选一。
    #[serde(default)]
    pub operation_method: Option<String>,
    /// body 收集硬上限。存在 body schema 时必须在 1..=16MiB 内显式设置。
    #[serde(default)]
    pub max_body_bytes: u64,
    /// 显式 body schema 的空 body 语义；缺省为 required。OpenAPI 来源默认服从 requestBody.required。
    #[serde(default)]
    pub body_required: Option<bool>,
}

/// V7 route 级 GraphQL 查询深度/复杂度守卫。
///
/// 该配置只接受 GraphQL-over-HTTP 的 GET query、POST `application/json` 与 POST
/// `application/graphql` 基础形态。multipart upload、subscription transport 和
/// degraphql 不属于第一切片；不能用宽松解析把这些尚未实现的协议伪装成已支持。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GraphqlGuardCfg {
    /// POST envelope/raw query 的最大实体字节数。读取严格有界，超过返回 413。
    #[serde(default = "default_graphql_max_body_bytes")]
    pub max_body_bytes: u64,
    /// 解码后 GraphQL query 文本的最大 UTF-8 字节数，GET/POST 使用同一上限。
    #[serde(default = "default_graphql_max_query_bytes")]
    pub max_query_bytes: usize,
    /// lexer 最多产生的 token 数，用独立 CPU/AST 预算防止短 token 洪泛。
    #[serde(default = "default_graphql_max_tokens")]
    pub max_tokens: usize,
    /// 根字段深度计为 1；任一可达选择路径超过该值即在上游前拒绝。
    #[serde(default = "default_graphql_max_depth")]
    pub max_depth: usize,
    /// 每个字段成本为 1，fragment 每次 spread 都重新计费；超过即拒绝。
    #[serde(default = "default_graphql_max_complexity")]
    pub max_complexity: usize,
    /// 是否允许 `__schema`/`__type`/`__typename` 等 introspection 字段。
    #[serde(default)]
    pub allow_introspection: bool,
}

/// REST→GraphQL 声明式映射。GraphQL 文档固定在配置中，客户端只能提供有界 variables，
/// 不能把任意 query 注入受信上游。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DegraphqlCfg {
    /// 固定 GraphQL query/mutation 文档。
    pub query: String,
    /// 多 operation 文档的选择名；单 operation 可留空。
    #[serde(default)]
    pub operation_name: Option<String>,
    /// GraphQL 上游 path，不带 query/fragment。
    #[serde(default = "default_degraphql_upstream_path")]
    pub upstream_path: String,
    /// REST path 模板；存在 path variable 时必填，并应与 route `PathTemplate` 一致。
    #[serde(default)]
    pub rest_path_template: String,
    /// GraphQL variables 名到不可信 REST 输入的显式映射。
    #[serde(default)]
    pub variables: HashMap<String, DegraphqlVariableCfg>,
    /// 生成 JSON envelope 的硬上限。
    #[serde(default = "default_degraphql_max_body_bytes")]
    pub max_body_bytes: usize,
}

/// 一个 degraphql variable 的来源和 JSON 标量类型。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DegraphqlVariableCfg {
    /// REST 输入来源。
    pub source: DegraphqlVariableSourceCfg,
    /// path/query/header 字段名；literal 来源必须为空。
    #[serde(default)]
    pub name: String,
    /// literal 来源的固定 JSON 值。
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    /// 不可信文本到 GraphQL variable JSON 的转换类型。
    #[serde(default)]
    pub kind: DegraphqlVariableKindCfg,
    /// 缺失时是否 400；false 时省略该 variable。
    #[serde(default = "default_true")]
    pub required: bool,
    /// 单值输入的 UTF-8 字节上限。
    #[serde(default = "default_degraphql_max_value_bytes")]
    pub max_value_bytes: usize,
}

/// degraphql variable 从 REST 请求的哪个位置取值。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DegraphqlVariableSourceCfg {
    /// 从已匹配 REST path template 的参数取值。
    Path,
    /// 从 query 参数取第一个值。
    Query,
    /// 从显式命名的 HTTP header 取值。
    Header,
    /// 使用配置中的固定 JSON 值。
    Literal,
}

/// 将不可信 REST 文本转换为 GraphQL variable JSON 时使用的标量类型。
#[derive(Debug, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum DegraphqlVariableKindCfg {
    /// 保持为 JSON string。
    #[default]
    String,
    /// 严格解析为有符号整数。
    Integer,
    /// 严格解析为有限浮点数。
    Number,
    /// 严格解析为布尔值。
    Boolean,
}

fn default_degraphql_upstream_path() -> String {
    "/graphql".to_owned()
}

const fn default_degraphql_max_body_bytes() -> usize {
    256 * 1024
}

const fn default_degraphql_max_value_bytes() -> usize {
    16 * 1024
}

impl Default for GraphqlGuardCfg {
    fn default() -> Self {
        Self {
            max_body_bytes: default_graphql_max_body_bytes(),
            max_query_bytes: default_graphql_max_query_bytes(),
            max_tokens: default_graphql_max_tokens(),
            max_depth: default_graphql_max_depth(),
            max_complexity: default_graphql_max_complexity(),
            allow_introspection: false,
        }
    }
}

fn default_graphql_max_body_bytes() -> u64 {
    256 * 1024
}

fn default_graphql_max_query_bytes() -> usize {
    128 * 1024
}

fn default_graphql_max_tokens() -> usize {
    32 * 1024
}

fn default_graphql_max_depth() -> usize {
    16
}

fn default_graphql_max_complexity() -> usize {
    1_000
}

/// V7 route 级 OPA REST decision 配置。
///
/// 第一切片固定调用 OPA Data API 风格 `POST`，request body 为 `{ "input": ... }`；
/// `target` 只声明上游 base，`path` 显式声明 policy document 路径。业务请求 body 永不读取或
/// 转发给策略服务，避免授权外呼破坏主管线的流式语义。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaAuthorizationCfg {
    /// OPA 上游 base：`http(s)://host[:port]` 或 `lb://service`。
    pub target: String,
    /// OPA Data API 路径，例如 `/v1/data/gateway/authz`；必须显式填写。
    pub path: String,
    /// response head + body 的总决策 deadline，毫秒。
    #[serde(default = "default_opa_timeout_ms")]
    pub timeout_ms: u64,
    /// OPA transport/5xx/畸形响应时是否放行；默认 fail-closed。
    #[serde(default)]
    pub fail_open: bool,
    /// OPA 服务凭据的完整 Authorization header 值；支持 SecretSource，空表示不发送。
    #[serde(default)]
    pub authorization: String,
    /// 作为不可信请求属性加入 input 的 header allowlist；敏感凭据类 header 永远拒绝。
    #[serde(default)]
    pub include_headers: Vec<String>,
    /// 单个 allowlist header value 的最大字节数。
    #[serde(default = "default_opa_max_header_value_bytes")]
    pub max_header_value_bytes: usize,
    /// 序列化后 OPA JSON input 的严格最大字节数。
    #[serde(default = "default_opa_max_input_bytes")]
    pub max_input_bytes: usize,
    /// OPA response body 的严格最大字节数。
    #[serde(default = "default_opa_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 为 true 时必须能从已通过认证链得到稳定 consumer，否则本地 403，不外呼 OPA。
    #[serde(default)]
    pub require_identity: bool,
    /// 可选本节点 decision L1。存在即启用；错误和 unavailable 永不缓存。
    #[serde(default)]
    pub cache: Option<OpaDecisionCacheCfg>,
}

/// OPA decision L1 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaDecisionCacheCfg {
    /// allow/deny decision TTL，毫秒。
    #[serde(default = "default_opa_cache_ttl_ms")]
    pub ttl_ms: u64,
    /// 每 route 最大 decision entry 数，TinyLFU 到顶淘汰。
    #[serde(default = "default_opa_cache_max_entries")]
    pub max_entries: u64,
    /// 外部 Rego/data 的运维版本；启用 cache 时必须非空，策略发布必须同步变更。
    pub policy_revision: String,
}

fn default_opa_timeout_ms() -> u64 {
    500
}

fn default_opa_max_header_value_bytes() -> usize {
    4 * 1024
}

fn default_opa_max_input_bytes() -> usize {
    64 * 1024
}

fn default_opa_max_response_bytes() -> usize {
    64 * 1024
}

fn default_opa_cache_ttl_ms() -> u64 {
    1_000
}

fn default_opa_cache_max_entries() -> u64 {
    10_000
}

/// route 本地服务后端配置集合。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RouteServeCfg {
    /// 静态文件/SPA 后端配置。
    #[serde(default)]
    pub r#static: Option<StaticServeCfg>,
}

/// 静态文件/SPA 后端配置,对齐 nginx `root`/`try_files`/`index` 主流用法。
#[derive(Debug, Deserialize, Clone)]
pub struct StaticServeCfg {
    /// 静态文件根目录。相对路径按 `gateway.yml` 所在目录解析。
    pub root: String,
    /// 依次尝试的文件模板。默认 `["${uri}", "${uri}/index.html"]`;末项可显式写 `/index.html` 做 SPA 回落。
    #[serde(default)]
    pub try_files: Vec<String>,
    /// 目录请求的索引文件列表,默认 `["index.html"]`。
    #[serde(default)]
    pub index: Vec<String>,
    /// 响应 `Cache-Control` 值。为空则不写。
    #[serde(default)]
    pub cache_control: Option<String>,
    /// nginx `expires` 语法糖,如 `1h`/`7d`/`3600s`;为空或 off 表示不写 Expires。
    #[serde(default)]
    pub expires: Option<String>,
    /// 未识别扩展名时使用的 Content-Type,默认 `application/octet-stream`。
    #[serde(default)]
    pub default_type: Option<String>,
    /// 自定义扩展名到 Content-Type 的映射,等价 nginx `types{}` 常用形态。
    #[serde(default)]
    pub types: HashMap<String, String>,
    /// 是否允许访问点文件/点目录。默认 false,防 `.env`/`.git` 暴露。
    #[serde(default)]
    pub allow_dotfiles: bool,
    /// 是否生成弱 ETag。默认 true。
    #[serde(default = "default_true")]
    pub etag: bool,
    /// 是否支持单段 HTTP Range。默认 true,用于大文件/媒体断点下载。
    #[serde(default = "default_true")]
    pub range: bool,
}

/// 上游逻辑服务目录与进程级预热扫描参数。
#[derive(Debug, Deserialize)]
pub struct UpstreamsCfg {
    /// service name -> static instances. 示例:`routes[].uri = "lb://order"` 命中 `services.order`。
    #[serde(default)]
    pub services: HashMap<String, StaticServiceCfg>,
    /// V7 新实例连接预热扫描间隔。后台只扫描配置快照/RCU 发现表，不进入请求热路径。
    #[serde(default = "default_prewarm_scan_interval_ms")]
    pub prewarm_scan_interval_ms: u64,
}

impl Default for UpstreamsCfg {
    fn default() -> Self {
        Self {
            services: HashMap::new(),
            prewarm_scan_interval_ms: default_prewarm_scan_interval_ms(),
        }
    }
}

/// 一个逻辑服务的实例来源、负载均衡、重试、健康和 TLS 策略。
#[derive(Debug, Deserialize, Clone)]
pub struct StaticServiceCfg {
    /// 是否属于全局 readiness 的关键依赖;非关键上游全挂不摘除整个网关节点。
    #[serde(default)]
    pub critical: bool,
    /// 静态来源的实例列表；动态来源必须留空。
    #[serde(default)]
    pub instances: Vec<StaticInstanceCfg>,
    /// 上游实例来源：`static`(默认)、`nacos`、`consul`、`eureka`、`dns` 或 `kubernetes`。
    #[serde(default)]
    pub source: Option<String>,
    /// Nacos 中的服务名;缺省使用 `services` map 的 key。
    #[serde(default)]
    pub nacos_service: Option<String>,
    /// V7 非 Nacos 注册中心中的物理服务名/DNS host；缺省使用 map key。
    #[serde(default)]
    pub registry_service: Option<String>,
    /// K8s service namespace；缺省使用 `discovery.kubernetes.namespace`。
    #[serde(default)]
    pub registry_namespace: Option<String>,
    /// DNS 固定端口；Kubernetes Ingress/Gateway API 的数字 Service port 也使用该字段。
    #[serde(default)]
    pub registry_port: Option<u16>,
    /// K8s Endpoints 端口名；空时要求响应仅有一个端口。
    #[serde(default)]
    pub registry_port_name: Option<String>,
    /// Nacos 实例缺少 metadata URI 时拼接上游 URI 使用的 scheme,默认 `http`。
    #[serde(default)]
    pub scheme: Option<String>,
    /// Nacos cluster 过滤;空 = 全部 cluster。
    #[serde(default)]
    pub clusters: Vec<String>,
    /// 上游负载均衡策略。V2-B 先解析并支持 `round_robin`/`first`/`least_conn` 的配置形态。
    #[serde(default)]
    pub lb_policy: Option<String>,
    /// 兼容 架构规范 示例里的 `lb: least_conn`。
    #[serde(default)]
    pub lb: Option<String>,
    /// 上游 HTTP 协议(据 review L1 / §5):`auto`(默认,按 scheme + gRPC content-type 判)| `h1` | `h2` | `h2c`。
    /// gRPC 上游应配 `h2`(TLS)/`h2c`(明文),否则会退化成 h1 多连接、丢多路复用。
    #[serde(default)]
    pub protocol: Option<String>,
    /// HTTP 上游 TLS profile(§36 `proxy_ssl_*`):自定义信任 CA、SNI/server_name 与客户端证书。
    /// 仅影响本 service 的 `https://` 实例;`http://` 实例配置该段会在构建期拒绝。
    #[serde(default)]
    pub tls: Option<UpstreamTlsCfg>,
    /// 换下一个上游实例的触发条件(nginx proxy_next_upstream 子集):
    /// `error` / `timeout` / `http_502` / `http_503` / `http_504` / `non_idempotent`。
    /// 缺省采用保守默认:仅 GET/HEAD 空 body 时对 error/timeout/502/503/504 换实例。
    #[serde(default)]
    pub next_upstream: Option<Vec<String>>,
    /// 单请求最多尝试几个实例,用于重试预算防风暴。默认 3;0 表示不限制直到候选耗尽。
    #[serde(default = "default_next_upstream_tries")]
    pub next_upstream_tries: usize,
    /// 每次换实例前等待的退避时间(ms)。默认 0。
    #[serde(default)]
    pub next_upstream_backoff_ms: u64,
    /// 被动摘除:窗口内失败次数达到该值后临时摘除实例。0 表示关闭。
    #[serde(default = "default_max_fails")]
    pub max_fails: u32,
    /// 被动摘除窗口/摘除时长(ms),对齐 nginx `fail_timeout` 心智。
    #[serde(default = "default_fail_timeout_ms")]
    pub fail_timeout_ms: u64,
    /// 主动健康探测(§5.1):缺省 = 关闭。配置后后台任务按间隔 TCP/HTTP 探测每个实例,
    /// 连续成功/失败达阈值翻转健康态;不健康实例不进入 LB 候选(与被动摘除叠加,双保险)。
    #[serde(default)]
    pub health_check: Option<HealthCheckCfg>,
    /// 新静态/发现实例进入目录后，使用真实业务连接池主动建立空闲连接。None = 关闭。
    #[serde(default)]
    pub prewarm: Option<UpstreamPrewarmCfg>,
}

/// 上游 Hyper 连接池预热策略。预热只发送 HEAD 且不携带下游 head/body/身份。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPrewarmCfg {
    /// 每个实例期望建立的连接数；HTTP/2 不超过 listener 的 h2 pool 分片数，每条仍是 mux。
    #[serde(default = "default_prewarm_connections")]
    pub connections: usize,
    /// 固定 HEAD path，可指向轻量 `/healthz`；不能含 authority/fragment。
    #[serde(default = "default_prewarm_path")]
    pub path: String,
    /// 每批预热等待 response head 的 deadline。
    #[serde(default = "default_prewarm_timeout_ms")]
    pub timeout_ms: u64,
}

/// 主动健康探测配置(nginx `health_check` / Envoy active health check 心智)。
#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheckCfg {
    /// 探测类型:`tcp`、`http` 或 V7 `udp`。UDP 发送一个有界 payload 并等待响应。
    #[serde(default = "default_health_check_type")]
    pub r#type: String,
    /// http 探测路径,默认 `/`。tcp 探测忽略。
    #[serde(default = "default_health_check_path")]
    pub path: String,
    /// 探测间隔(ms),默认 5000。
    #[serde(default = "default_health_check_interval_ms")]
    pub interval_ms: u64,
    /// 单次探测超时(ms),默认 2000。
    #[serde(default = "default_health_check_timeout_ms")]
    pub timeout_ms: u64,
    /// 连续成功多少次判「健康」(重新放回候选),默认 1。
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    /// 连续失败多少次判「不健康」(移出候选),默认 3。
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// http 探测期望状态码;缺省接受任意 2xx。
    #[serde(default)]
    pub expected_status: Option<u16>,
    /// UDP 探测发送的 UTF-8 payload；`type != udp` 时必须为空。
    #[serde(default)]
    pub udp_payload: String,
    /// 可选 UDP 精确响应；为空时任意非空响应表示健康。
    #[serde(default)]
    pub udp_expected_response: Option<String>,
}

/// 一个静态上游实例及其调度属性。
#[derive(Debug, Deserialize, Clone)]
pub struct StaticInstanceCfg {
    /// 上游实例 base URI,如 `http://127.0.0.1:9001`。
    pub uri: String,
    /// 本地静态健康标记;动态健康检查后续会覆盖到同一抽象。
    #[serde(default = "default_true")]
    pub healthy: bool,
    /// 带权轮询权重;默认策略按 nginx upstream 心智使用 weighted round-robin。
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 手工下线:保留配置,但永不进入候选。
    #[serde(default)]
    pub down: bool,
    /// 备用实例:只有主实例全不可用时才进入候选。
    #[serde(default)]
    pub backup: bool,
    /// 慢启动时长(ms):实例新加入/恢复后有效权重在该时长内线性爬满。
    #[serde(default)]
    pub slow_start_ms: u64,
}

/// HTTP 上游 TLS 配置,对齐 nginx `proxy_ssl_*` 的高频子集。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct UpstreamTlsCfg {
    /// 覆盖发往上游的 TLS SNI 与证书校验名,等价 nginx `proxy_ssl_name`。
    #[serde(default, alias = "proxy_ssl_name")]
    pub server_name: Option<String>,
    /// 自定义上游服务端 CA PEM,等价 nginx `proxy_ssl_trusted_certificate`;为空使用系统根证书。
    #[serde(default, alias = "proxy_ssl_trusted_certificate")]
    pub ca_file: Option<String>,
    /// 发给上游的客户端证书 PEM,等价 nginx `proxy_ssl_certificate`。
    #[serde(default, alias = "proxy_ssl_certificate")]
    pub client_cert_file: Option<String>,
    /// 发给上游的客户端私钥 PEM,等价 nginx `proxy_ssl_certificate_key`。
    #[serde(default, alias = "proxy_ssl_certificate_key")]
    pub client_key_file: Option<String>,
}

fn default_guard_file() -> String {
    "interface-guard.yml".to_string()
}

fn default_sentinel_rules_file() -> String {
    "sentinel-rules.yml".to_string()
}

fn default_admin_listen() -> String {
    "127.0.0.1:18080".to_string()
}

fn default_admin_auth_realm() -> String {
    "gateway-admin".to_string()
}

fn default_admin_audit_file() -> String {
    ".gateway-audit/audit.jsonl".to_string()
}

fn default_admin_audit_timeout_ms() -> u64 {
    3_000
}

fn default_admin_audit_max_record_bytes() -> usize {
    64 * 1024
}

fn default_admin_audit_history_limit() -> usize {
    1_024
}

fn default_admin_max_config_body_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_nacos_gateway_data_id() -> String {
    "gateway.yml".to_string()
}

fn default_nacos_interface_guard_data_id() -> String {
    "interface-guard.yml".to_string()
}

fn default_nacos_sentinel_rules_data_id() -> String {
    "sentinel-rules.yml".to_string()
}

fn default_nacos_materialized_dir() -> String {
    ".gateway-nacos-config".to_string()
}

fn default_max_headers() -> usize {
    100
}

/// 默认每个 proxy 最多 10k 条物理下游连接；可按 listener 热调。
fn default_max_connections() -> usize {
    10_000
}

fn default_max_header_bytes() -> usize {
    64 * 1024
}

fn default_max_body_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_max_concurrent_streams() -> u32 {
    256
}

/// RFC 9113 的标准初始 stream window；保持单 stream 背压粒度。
fn default_h2_initial_stream_window_bytes() -> u32 {
    65_535
}

/// 连接级窗口放大到 1 MiB，让并发小 stream 共享 credit 时减少 WINDOW_UPDATE 频率。
fn default_h2_initial_connection_window_bytes() -> u32 {
    1024 * 1024
}

/// 默认 path 上限 8 KiB，与常见代理请求目标预算同量级。
fn default_max_path_bytes() -> usize {
    8 * 1024
}

/// 默认最多 128 个非空 path segment，避免超深路径放大匹配成本。
fn default_max_path_segments() -> usize {
    128
}

/// 默认每个完整 `health_key` 最多 1024 个在途上游请求。
fn default_upstream_pending_limit() -> usize {
    1_024
}

/// 默认每个 Hyper authority 最多保留 64 条 idle 连接。
fn default_pool_max_per_upstream() -> usize {
    64
}

/// 默认用 16 条独立 mux 连接分摊高并发 h2 stream 锁竞争。单连接会把所有 stream 串到 h2
/// 内部锁；过多连接又增加调度和 TLS 成本。当前同机 300k/64 对照为 8=36.95k、
/// 16=40.15k、32=36.97k RPS；具体部署仍可按 CPU 拓扑热更，并受物理连接硬上限自动钳制。
fn default_h2_connection_shards_per_upstream() -> usize {
    16
}

/// 默认每个结构化上游身份最多 128 条物理 socket；h2 多路复用通常远低于此数。
fn default_pool_max_connections_per_upstream() -> usize {
    128
}

/// 默认每个 pool generation 处理 1000 个请求后轮换，给长期连接可预期的回收边界。
fn default_keepalive_requests() -> u64 {
    1_000
}

/// 默认上游 idle 连接保留 60 秒。
fn default_pool_idle_timeout_ms() -> u64 {
    60_000
}

/// 默认换版后旧 client cache 保留 60 秒，给旧快照请求完成 drain。
fn default_old_pool_retain_ms() -> u64 {
    60_000
}

fn default_upstream_ttfb_timeout_ms() -> u64 {
    30_000
}

fn default_header_read_timeout_ms() -> u64 {
    30_000
}

// ★默认 0 = 关闭(§23):不用「连接总超时」硬砍长流;慢客户端防护走 header_read_timeout。
fn default_connection_timeout_ms() -> u64 {
    0
}

fn default_stream_idle_timeout_ms() -> u64 {
    60_000
}

/// 默认下游连续写阻塞 30 秒后关闭连接，防停止读取的客户端无限占用 response/upstream。
fn default_downstream_write_timeout_ms() -> u64 {
    30_000
}

/// 默认 WebSocket 60 秒无任何字节活动即优雅关闭。
fn default_websocket_idle_timeout_ms() -> u64 {
    60_000
}

/// 默认 WebSocket 最长存活 24 小时，定期释放旧快照与运行态引用。
fn default_websocket_max_lifetime_ms() -> u64 {
    86_400_000
}

fn default_drain_timeout_ms() -> u64 {
    30_000
}

fn default_proxy_protocol_timeout_ms() -> u64 {
    3_000
}

fn default_redirect_https_status() -> u16 {
    308
}

fn default_client_auth_mode() -> String {
    "require".to_string()
}

fn default_stream_connect_timeout_ms() -> u64 {
    5_000
}

fn default_stream_preread_timeout_ms() -> u64 {
    3_000
}

fn default_stream_preread_max_bytes() -> usize {
    8 * 1024
}

fn default_stream_proxy_protocol_upstream_version() -> String {
    "v1".to_string()
}

/// 默认使用 Let's Encrypt production directory；测试应显式改成 staging/Pebble。
fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

/// V4 基础实现使用 HTTP-01。
fn default_acme_challenge() -> String {
    "http-01".to_string()
}

/// 默认账户 secret 与主配置同目录解析。
fn default_acme_account_credentials_file() -> String {
    ".secrets/acme-account.json".to_string()
}

/// 默认提前 30 天续期 90 天短证书。
fn default_acme_renew_before_days() -> u64 {
    30
}

/// 默认每 12 小时检查一次到期时间。
fn default_acme_check_interval_ms() -> u64 {
    43_200_000
}

/// 默认失败后 5 分钟再试，避免 CA/网络异常时热循环。
fn default_acme_retry_backoff_ms() -> u64 {
    300_000
}

/// 默认给单个 ACME order 两分钟完成验证与签发。
fn default_acme_order_timeout_ms() -> u64 {
    120_000
}

/// 默认每 250ms 检查一次 ACME 首签文件，兼顾激活延迟与空闲控制面成本。
fn default_acme_activation_poll_ms() -> u64 {
    250
}

fn default_acme_dns01_provider() -> String {
    "command".to_string()
}

/// 公网 DNS 默认给 30 秒传播窗口；具体 provider/权威 DNS 可按实际缩短。
fn default_acme_dns01_propagation_delay_ms() -> u64 {
    30_000
}

fn default_acme_dns01_timeout_ms() -> u64 {
    30_000
}

/// 默认单节点本地锁；多节点必须显式选择 redis。
fn default_acme_lock_backend() -> String {
    "local".to_string()
}

/// 默认按域名集合共享一个 ACME leader 锁。
fn default_acme_lock_key() -> String {
    "gateway:acme:renew".to_string()
}

/// 默认本地 SecretSource 文件；多节点需显式声明 shared-file。
fn default_acme_storage_mode() -> String {
    "local-file".to_string()
}

fn default_rate_limiter_backend() -> String {
    "local".to_string()
}

fn default_rate_limiter_fail_mode() -> String {
    "open".to_string()
}

fn default_dynamic_store_backend() -> String {
    "file".to_string()
}

fn default_dynamic_store_file_root() -> String {
    "runtime-state".to_string()
}

fn default_dynamic_store_redis_prefix() -> String {
    "gw:dynamic".to_string()
}

fn default_blacklist_collection() -> String {
    "acl_blacklist".to_string()
}

fn default_blacklist_refresh_interval_ms() -> u64 {
    1_000
}

fn default_interface_disable_collection() -> String {
    "interface_disable".to_string()
}

fn default_interface_disable_refresh_interval_ms() -> u64 {
    1_000
}

fn default_auto_ban_limit_req_rejections() -> u64 {
    10
}

fn default_auto_ban_window_ms() -> u64 {
    60_000
}

fn default_auto_ban_ttl_ms() -> u64 {
    300_000
}

fn default_runtime_redis_namespace() -> String {
    "nate".to_string()
}

fn default_runtime_redis_profile() -> String {
    "RustV2".to_string()
}

fn default_http_cache_backend() -> String {
    "local".to_string()
}

fn default_http_cache_redis_prefix() -> String {
    "gw:http-cache:v1".to_string()
}

fn default_http_cache_invalidation_channel() -> String {
    "gw:http-cache:invalidate:v1".to_string()
}

fn default_http_cache_reconcile_interval_ms() -> u64 {
    5_000
}

fn default_variable_match_type() -> String {
    "exact".to_string()
}

fn default_weight() -> u32 {
    1
}

fn default_next_upstream_tries() -> usize {
    3
}

fn default_max_fails() -> u32 {
    1
}

fn default_fail_timeout_ms() -> u64 {
    10_000
}

fn default_health_check_type() -> String {
    "tcp".to_string()
}

fn default_health_check_path() -> String {
    "/".to_string()
}

fn default_health_check_interval_ms() -> u64 {
    5_000
}

fn default_health_check_timeout_ms() -> u64 {
    2_000
}

const fn default_prewarm_scan_interval_ms() -> u64 {
    1_000
}

const fn default_prewarm_connections() -> usize {
    1
}

fn default_prewarm_path() -> String {
    "/".to_owned()
}

const fn default_prewarm_timeout_ms() -> u64 {
    1_000
}

fn default_healthy_threshold() -> u32 {
    1
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_access_log_queue_size() -> usize {
    4096
}

fn default_access_log_sample() -> f64 {
    1.0
}

fn default_access_log_sink_queue_size() -> usize {
    1024
}

fn default_access_log_sink_batch_size() -> usize {
    100
}

fn default_access_log_sink_batch_delay_ms() -> u64 {
    200
}

fn default_access_log_sink_timeout_ms() -> u64 {
    3000
}

fn default_access_log_sink_max_event_bytes() -> usize {
    256 * 1024
}

fn default_access_log_kafka_lane() -> String {
    "default".to_string()
}

fn default_otel_endpoint() -> String {
    "http://127.0.0.1:4318".to_string()
}

fn default_otel_service_name() -> String {
    "nate".to_string()
}

fn default_otel_sample_ratio() -> f64 {
    1.0
}

fn default_otel_queue_size() -> usize {
    2048
}

fn default_otel_batch_size() -> usize {
    512
}

fn default_otel_scheduled_delay_ms() -> u64 {
    5_000
}

fn default_otel_export_timeout_ms() -> u64 {
    3_000
}

fn default_reload_channel_capacity() -> usize {
    16
}

fn default_reload_debounce_ms() -> u64 {
    300
}

fn default_nacos_group() -> String {
    "DEFAULT_GROUP".to_string()
}

fn default_nacos_app_name() -> String {
    "nate".to_string()
}

fn default_nacos_poll_interval_ms() -> u64 {
    5_000
}

fn default_nacos_stale_ttl_ms() -> u64 {
    30_000
}

fn default_nacos_reconnect_backoff_ms() -> u64 {
    1_000
}

fn default_self_register_weight() -> f64 {
    1.0
}

fn default_self_register_deregister_timeout_ms() -> u64 {
    3_000
}

// ── 接口守卫 interface-guard.yml ──

/// `interface-guard.yml` 的顶层文档。
#[derive(Debug, Deserialize, Default)]
pub struct GuardFile {
    /// 配置 schema 版本(§6);按文件分别记录,缺省按 v1 处理并告警。
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// 未单独配 response 的规则用的默认响应。
    #[serde(default)]
    pub default_response: Option<RespCfg>,
    /// 按配置顺序编译的接口阻断规则。
    #[serde(default)]
    pub rules: Vec<GuardRuleCfg>,
}

/// `sentinel-rules.yml` 的顶层限流与熔断规则文档。
#[derive(Debug, Deserialize, Default)]
pub struct SentinelFile {
    /// 配置 schema 版本(§6);按文件分别记录,缺省按 v1 处理并告警。
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// Sentinel FlowRule 列表。V3 起步先编译到 `limit_req` / `limit_conn` 两种已落地动作。
    #[serde(default)]
    pub flow: Vec<SentinelFlowRuleCfg>,
    /// Sentinel DegradeRule 列表。V3 起步编译为 route 资源级 circuit breaker。
    #[serde(default)]
    pub degrade: Vec<SentinelDegradeRuleCfg>,
}

/// 一条编译为 `limit_req` 或 `limit_conn` 的 Sentinel 流控规则。
#[derive(Debug, Deserialize, Clone)]
pub struct SentinelFlowRuleCfg {
    /// 规则 id,用于错误定位和后续 Admin UI 编排。
    pub id: String,
    /// false 时忽略该规则,保留配置但不生效。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 绑定的 route id。V3 起步按 route 精确绑定,后续可扩展 path/resource 维度。
    pub route: String,
    /// 限制维度,同 `limit_req`/`limit_conn`:`global|ip|route|header:<name>|query:<name>`。
    #[serde(default = "default_sentinel_key")]
    pub key: String,
    /// QPS/QPM 等速率,存在时编译为 `limit_req`。
    #[serde(default)]
    pub rate: Option<String>,
    /// `limit_req` burst,默认 0。
    #[serde(default)]
    pub burst: u64,
    /// 同一规则最多保留的活跃维度桶，防高基数维度爆破。
    #[serde(default = "default_sentinel_max_active_keys")]
    pub max_active_keys: usize,
    /// 达到维度上限时 `open` 放行或 `closed` 拒绝；两者都不再创建新桶。
    #[serde(default = "default_sentinel_active_keys_fail")]
    pub active_keys_fail: String,
    /// 并发上限,存在时编译为 `limit_conn`。
    #[serde(default)]
    pub limit: Option<u64>,
}

fn default_sentinel_max_active_keys() -> usize {
    100_000
}

fn default_sentinel_active_keys_fail() -> String {
    "open".to_string()
}

/// 一条编译为 route 级滑动窗口熔断器的 Sentinel 降级规则。
#[derive(Debug, Deserialize, Clone)]
pub struct SentinelDegradeRuleCfg {
    /// 规则 id,用于错误定位和后续 Admin UI 编排。
    pub id: String,
    /// false 时忽略该规则,保留配置但不生效。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 绑定的 route id。
    pub route: String,
    /// 滑动窗口内失败次数阈值。
    pub failure_threshold: u64,
    /// 统计窗口(ms),默认 10000。
    #[serde(default = "default_circuit_window_ms")]
    pub window_ms: u64,
    /// 最少请求数,默认 1。
    #[serde(default = "default_circuit_min_requests")]
    pub min_requests: u64,
    /// Open 持续时间(ms),默认 30000。
    #[serde(default = "default_circuit_break_ms")]
    pub break_ms: u64,
    /// fallback HTTP 状态码,默认 503。
    #[serde(default = "default_circuit_fallback_status")]
    pub fallback_status: u16,
    /// fallback 短文本 body。空则用 `circuit open`。
    #[serde(default = "default_circuit_fallback_body")]
    pub fallback_body: String,
}

fn default_sentinel_key() -> String {
    "ip".to_string()
}

fn default_circuit_window_ms() -> u64 {
    10_000
}

fn default_circuit_min_requests() -> u64 {
    1
}

fn default_circuit_break_ms() -> u64 {
    30_000
}

fn default_circuit_fallback_status() -> u16 {
    503
}

fn default_circuit_fallback_body() -> String {
    "circuit open".to_string()
}

/// 一条接口紧急下线规则。
#[derive(Debug, Deserialize, Clone)]
pub struct GuardRuleCfg {
    /// 规则唯一 id，用于诊断和管理面展示。
    pub id: String,
    /// 是否编译该规则。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// path 与 method 匹配条件。
    #[serde(rename = "match")]
    pub matcher: GuardMatchCfg,
    /// 规则专属响应；为空时继承文档级默认响应。
    #[serde(default)]
    pub response: Option<RespCfg>,
}

/// 接口守卫/静态匹配类型(§8.1/§4.2)。默认 `Glob` 以兼容既有 `path: /api/**` 配置;
/// `Exact`/`Prefix` 提供精确与前缀语义。Regex 默认禁用(§4.2),此处不提供。
///
/// WHY 显式类型:早期版本无 `type` 字段、把所有 path 一律编译成 glob。运维按 §8.1
/// 写 `type: Prefix path: /api/export/` 时,`type` 被静默忽略、`/api/export/` 作为无通配 glob
/// 只精确匹配自身 → `/api/export/users` 不被拦截,「一票否决」的接口关闭对整棵子树失效(fail-open)。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuardMatchType {
    /// path 必须逐字相等。
    #[serde(alias = "exact")]
    Exact,
    /// path 必须以配置值开头。
    #[serde(alias = "prefix")]
    Prefix,
    /// 使用 `*`/`**` 字段感知 glob。
    #[default]
    #[serde(alias = "glob")]
    Glob,
}

/// 接口守卫的一组 path 与 method 匹配条件。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GuardMatchCfg {
    /// 匹配类型(§8.1):`Exact`/`Prefix`/`Glob`(默认 `Glob`)。未知类型或未知字段直接 build 期报错,
    /// 不再静默按 glob 处理,避免应急下线规则 fail-open。
    #[serde(rename = "type", default)]
    pub match_type: GuardMatchType,
    /// 匹配路径:`Glob` 时为 `/api/export/**`(** 多段,* 单段);`Exact`/`Prefix` 时为普通路径串。
    pub path: String,
    /// 命中的方法;空 = 所有方法。
    #[serde(default)]
    pub methods: Vec<String>,
}

/// 接口守卫命中后的固定 HTTP 响应。
#[derive(Debug, Deserialize, Clone)]
pub struct RespCfg {
    /// HTTP 状态码。
    #[serde(default = "default_status")]
    pub status: u16,
    /// 附加响应头。
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// UTF-8 响应体。
    #[serde(default)]
    pub body: String,
}

fn default_true() -> bool {
    true
}

fn default_status() -> u16 {
    503
}

/// gRPC edge relay 双向 TLS 配置。
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrpcEdgeRelayTlsCfg {
    /// 是否启用 relay mTLS。
    pub enabled: bool,
    /// 所有 relay 节点证书覆盖的固定 DNS 身份。
    pub server_name: String,
    /// relay 专用 CA PEM 绝对路径。
    pub ca_file: String,
    /// 本节点证书链 PEM 绝对路径。
    pub cert_file: String,
    /// 本节点私钥 PEM 绝对路径。
    pub key_file: String,
    /// 单次 TLS 握手硬超时。
    pub handshake_timeout_ms: u64,
}

impl Default for GrpcEdgeRelayTlsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: "relay.naway.internal".to_string(),
            ca_file: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            handshake_timeout_ms: 5_000,
        }
    }
}
