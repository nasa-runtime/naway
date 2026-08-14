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
    /// 可复用 route filter 片段；所有 import 与引用在候选构建期展开，运行态不保留解释器。
    #[serde(default)]
    pub snippets: SnippetsCfg,
    /// 展开期规范化的 snippet import 依赖，仅供指纹与 reload watcher 使用。
    #[serde(skip)]
    pub(crate) snippet_files: Vec<std::path::PathBuf>,
    /// 静态上游定义；`lb://service` 路由从这里选实例，Nacos 等动态注册中心通过同一发现抽象补充实例。
    #[serde(default)]
    pub upstreams: UpstreamsCfg,
    /// 可复用上游凭据对象；route/service 只能按名称引用且必须通过 backend allowlist。
    #[serde(default)]
    pub upstream_credentials: Vec<UpstreamCredentialCfg>,
    /// 远程 Secret provider 目录；只在候选构建和后台刷新阶段访问，数据面不得发起读取。
    #[serde(default)]
    pub secret_providers: Vec<RemoteSecretProviderCfg>,
    /// 不导出私钥的远程加解密/签名 provider 目录。
    #[serde(default)]
    pub crypto_providers: Vec<ExternalCryptoProviderCfg>,
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
    /// 可选 xDS 控制面入口。bootstrap 永久拥有 server/identity/trust/ownership 与资源预算。
    #[serde(default)]
    pub control_plane: ControlPlaneCfg,
    /// 运行态共享后端配置。计数/动态事实源不进入路由 DSL,由运行态面统一装配。
    #[serde(default)]
    pub runtime_state: RuntimeStateCfg,
    /// nginx `set` / `map` / `${...}` 变量系统。构建期编译为 VariablePlan,供 header/filter/后续 upstream 选择复用。
    #[serde(default)]
    pub variables: VariablesCfg,
    /// access log 执行参数。默认非阻塞 bounded queue,队列满丢弃并计数。
    #[serde(default)]
    pub access_log: AccessLogCfg,
    /// OpenTelemetry 链路追踪。导出器/队列属于进程 bootstrap 资源，修改后需重启。
    #[serde(default)]
    pub telemetry: TelemetryCfg,
    /// 热重载控制面资源参数。这些值在启动时创建 worker 时生效，不属于请求热路径。
    #[serde(default)]
    pub reload: ReloadCfg,
    /// WS/gRPC 长连接在配置换版与管理面 drain 时的全局治理策略。
    #[serde(default)]
    pub long_connections: LongConnectionCfg,
    /// gRPC 边缘模式的进程级集群中继面(架构规范 §25.2)。None 或 `mode: none` = 单机,
    /// 不建 peer 连接；只保留单机 EdgeHub，不启动 relay 网络组件。
    #[serde(default)]
    pub grpc_edge_cluster: Option<GrpcEdgeClusterCfg>,
    /// 接口守卫独立配置文件路径(相对主配置目录或绝对);缺省 `interface-guard.yml`。
    #[serde(default = "default_guard_file")]
    pub interface_guard_file: String,
    /// Sentinel 流量防护独立规则文件路径(相对主配置目录或绝对);缺省 `sentinel-rules.yml`。
    #[serde(default = "default_sentinel_rules_file")]
    pub sentinel_rules_file: String,
}

/// 进程级控制面模式与 xDS bootstrap 配置。
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneCfg {
    /// 配置事实源模式；默认 native，不启动任何 xDS task。
    #[serde(default)]
    pub mode: ControlPlaneModeCfg,
    /// 可选 xDS v3 client 配置。
    #[serde(default)]
    pub xds: XdsCfg,
}

/// 配置事实源的进程级所有权模式。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneModeCfg {
    /// file/Nacos/admin 继续拥有全部资源。
    #[default]
    Native,
    /// xDS 拥有声明为 xDS 的完整资源域。
    Xds,
    /// native 与 xDS 按资源域整块分权，禁止同域 merge。
    Hybrid,
}

/// xDS v3 client bootstrap 配置；所有字段只允许本地配置修改。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsCfg {
    /// 显式总开关；未编 `xds-client` 时 true 必须在构建期失败。
    #[serde(default)]
    pub enabled: bool,
    /// ADS 传输 variant。
    #[serde(default)]
    pub transport: XdsTransportCfg,
    /// management server URI；生产非 loopback 必须为 HTTPS+mTLS。
    #[serde(default)]
    pub server: String,
    /// 稳定 Node identity 与固定 allowlist metadata。
    #[serde(default)]
    pub node: XdsNodeCfg,
    /// xDS 自身 TLS/mTLS 信任与身份；远端资源永远不能修改。
    #[serde(default)]
    pub tls: XdsTlsCfg,
    /// 启动时 xDS 不可达的策略。
    #[serde(default)]
    pub startup_policy: XdsStartupPolicyCfg,
    /// 断线重连退避。
    #[serde(default)]
    pub reconnect: XdsReconnectCfg,
    /// HTTP/2 keepalive 参数。
    #[serde(default)]
    pub keepalive: XdsKeepaliveCfg,
    /// decode/translate/warming/apply 的硬预算。
    #[serde(default)]
    pub limits: XdsLimitsCfg,
    /// listeners/routes/clusters/endpoints/secrets 的整域 owner。
    #[serde(default)]
    pub ownership: XdsOwnershipCfg,
}

impl Default for XdsCfg {
    /// 业务作用：提供完全关闭、无 transport task 的 xDS 安全默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：native owner、ADS SotW 与规范硬预算；`enabled=false`。
    fn default() -> Self {
        Self {
            enabled: false,
            transport: XdsTransportCfg::default(),
            server: String::new(),
            node: XdsNodeCfg::default(),
            tls: XdsTlsCfg::default(),
            startup_policy: XdsStartupPolicyCfg::default(),
            reconnect: XdsReconnectCfg::default(),
            keepalive: XdsKeepaliveCfg::default(),
            limits: XdsLimitsCfg::default(),
            ownership: XdsOwnershipCfg::default(),
        }
    }
}

/// xDS ADS 传输 variant。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdsTransportCfg {
    /// v3 AggregatedDiscoveryService SotW bidi stream。
    #[default]
    AdsSotwV3,
    /// v3 Delta ADS；按资源 version/removed/TTL 做增量缓存。
    AdsDeltaV3,
}

/// xDS 启动不可达时的唯一降级策略。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdsStartupPolicyCfg {
    /// xDS-owned 资源未取得有效版本时 readiness 保持 503。
    #[default]
    RequireXds,
    /// 仅允许经过签名、有效期和完整校验的磁盘 LKG；该策略尚未启用，配置校验会拒绝。
    SignedLastGood,
}

/// xDS Node identity；metadata 只能使用构建期固定 allowlist key。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsNodeCfg {
    /// 节点稳定唯一 id。
    #[serde(default)]
    pub id: String,
    /// 节点所属逻辑 gateway cluster。
    #[serde(default)]
    pub cluster: String,
    /// 允许发给 management server 的低敏、低基数 metadata。
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// 一个文件型 xDS SecretSource；不接受远端覆盖或明文内联私钥。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsSecretFileCfg {
    /// PEM 文件路径；相对 gateway.yml 目录解析。
    #[serde(default)]
    pub file: String,
}

/// xDS management server 的 TLS/mTLS bootstrap 身份。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsTlsCfg {
    /// 服务端 CA PEM。
    #[serde(default)]
    pub ca: XdsSecretFileCfg,
    /// 客户端证书链 PEM。
    #[serde(default)]
    pub cert: XdsSecretFileCfg,
    /// 客户端私钥 PEM。
    #[serde(default)]
    pub key: XdsSecretFileCfg,
    /// TLS SNI 与证书校验名。
    #[serde(default)]
    pub server_name: String,
}

/// xDS 断线重连的指数退避参数。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsReconnectCfg {
    /// 初始退避；使用 `200ms`/`2s` 形式。
    #[serde(default = "default_xds_initial_backoff")]
    pub initial_backoff: String,
    /// 最大退避。
    #[serde(default = "default_xds_max_backoff")]
    pub max_backoff: String,
    /// 对称 jitter 比例，范围 0..=1。
    #[serde(default = "default_xds_jitter")]
    pub jitter: f64,
}

impl Default for XdsReconnectCfg {
    /// 业务作用：提供避免 management server 重连风暴的保守退避默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：200ms 初始、30s 上限与 20% jitter。
    fn default() -> Self {
        Self {
            initial_backoff: default_xds_initial_backoff(),
            max_backoff: default_xds_max_backoff(),
            jitter: default_xds_jitter(),
        }
    }
}

/// ADS HTTP/2 keepalive 参数。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsKeepaliveCfg {
    /// 空闲 PING 周期。
    #[serde(default = "default_xds_keepalive_interval")]
    pub interval: String,
    /// PING ACK deadline。
    #[serde(default = "default_xds_keepalive_timeout")]
    pub timeout: String,
}

impl Default for XdsKeepaliveCfg {
    /// 业务作用：提供低频保活且能有界发现半开连接的默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：30s interval 与 5s timeout。
    fn default() -> Self {
        Self {
            interval: default_xds_keepalive_interval(),
            timeout: default_xds_keepalive_timeout(),
        }
    }
}

/// xDS decode、缓存、warming 与 apply channel 的资源硬上限。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsLimitsCfg {
    /// 单个 DiscoveryResponse 解码上限。
    #[serde(default = "default_xds_max_response_bytes")]
    pub max_response_bytes: usize,
    /// 单 type SotW 资源数或 Delta 单次变更数上限。
    #[serde(default = "default_xds_max_resources_per_type")]
    pub max_resources_per_type: usize,
    /// 单个 Any payload 上限。
    #[serde(default = "default_xds_max_resource_bytes")]
    pub max_resource_bytes: usize,
    /// 单 type accepted/warming cache 资源与 named tombstone 上限。
    #[serde(default = "default_xds_max_warming_resources")]
    pub max_warming_resources: usize,
    /// transport→apply 有界 channel 容量。
    #[serde(default = "default_xds_max_apply_queue")]
    pub max_apply_queue: usize,
    /// 依赖 warming deadline。
    #[serde(default = "default_xds_warming_timeout")]
    pub warming_timeout: String,
}

impl Default for XdsLimitsCfg {
    /// 业务作用：固定 xDS 敌意/异常控制面输入的默认内存和队列边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与 §7.6 bootstrap 示例一致的硬上限。
    fn default() -> Self {
        Self {
            max_response_bytes: default_xds_max_response_bytes(),
            max_resources_per_type: default_xds_max_resources_per_type(),
            max_resource_bytes: default_xds_max_resource_bytes(),
            max_warming_resources: default_xds_max_warming_resources(),
            max_apply_queue: default_xds_max_apply_queue(),
            warming_timeout: default_xds_warming_timeout(),
        }
    }
}

/// 一个 xDS 资源域的唯一 owner。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdsResourceOwnerCfg {
    /// file/Nacos/admin owner。
    #[default]
    Native,
    /// xDS owner；native 控制面不得写同域影子配置。
    Xds,
}

/// 五个资源域的整块所有权声明。
#[derive(Debug, Deserialize, Clone, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct XdsOwnershipCfg {
    /// listener topology owner。
    #[serde(default)]
    pub listeners: XdsResourceOwnerCfg,
    /// route owner。
    #[serde(default)]
    pub routes: XdsResourceOwnerCfg,
    /// cluster policy owner。
    #[serde(default)]
    pub clusters: XdsResourceOwnerCfg,
    /// endpoint table owner。
    #[serde(default)]
    pub endpoints: XdsResourceOwnerCfg,
    /// TLS secret owner。
    #[serde(default)]
    pub secrets: XdsResourceOwnerCfg,
}

/// 业务作用：提供 xDS 首次重连退避默认值。
/// 参数说明: 无。
/// 返回：`200ms` duration 字符串。
fn default_xds_initial_backoff() -> String {
    "200ms".to_owned()
}

/// 业务作用：限制 xDS 指数退避上界，避免断线后永久沉默。
/// 参数说明: 无。
/// 返回：`30s` duration 字符串。
fn default_xds_max_backoff() -> String {
    "30s".to_owned()
}

/// 业务作用：提供抑制 xDS 客户端同步重连风暴的默认 jitter。
/// 参数说明: 无。
/// 返回：20% 对称 jitter 比例。
const fn default_xds_jitter() -> f64 {
    0.2
}

/// 业务作用：提供 ADS HTTP/2 空闲保活周期。
/// 参数说明: 无。
/// 返回：`30s` duration 字符串。
fn default_xds_keepalive_interval() -> String {
    "30s".to_owned()
}

/// 业务作用：限定 ADS keepalive ACK 等待时间。
/// 参数说明: 无。
/// 返回：`5s` duration 字符串。
fn default_xds_keepalive_timeout() -> String {
    "5s".to_owned()
}

/// 业务作用：限制单个 xDS response 的解码内存。
/// 参数说明: 无。
/// 返回：16 MiB 默认上限。
const fn default_xds_max_response_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：限制单 type SotW 资源或 Delta 单次变更数量。
/// 参数说明: 无。
/// 返回：100000 条默认上限。
const fn default_xds_max_resources_per_type() -> usize {
    100_000
}

/// 业务作用：限制单个 xDS Any payload 的内存占用。
/// 参数说明: 无。
/// 返回：1 MiB 默认上限。
const fn default_xds_max_resource_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制 accepted/warming cache 与 named deletion evidence 的驻留规模。
/// 参数说明: 无。
/// 返回：100000 条默认上限。
const fn default_xds_max_warming_resources() -> usize {
    100_000
}

/// 业务作用：限制 transport 到 apply single-writer 的在途候选数。
/// 参数说明: 无。
/// 返回：64 个候选的默认上限。
const fn default_xds_max_apply_queue() -> usize {
    64
}

/// 业务作用：限定 xDS 依赖 warming 的最长等待时间。
/// 参数说明: 无。
/// 返回：`30s` duration 字符串。
fn default_xds_warming_timeout() -> String {
    "30s".to_owned()
}

#[derive(Debug, Deserialize, Clone)]
/// 旧版单 HTTP proxy 入口配置；新配置应优先使用 `proxies[]`。
pub struct ServerCfg {
    /// 数据面监听地址(对外流量)。
    pub listen: String,
    /// 可选 TLS 数据面监听。明文与 TLS 是两个 socket,不做同端口 sniffing。
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// V9 HTTP/3/QUIC；UDP 端口固定复用 `tls.listen` 的数值端口。
    #[serde(default)]
    pub http3: Http3Cfg,
    /// 数据面资源上限:请求头/body/h2 stream 等预算必须在执行点生效。
    #[serde(default)]
    pub limits: ServerLimitsCfg,
    /// 数据面超时预算:连接空闲、上游响应头等。
    #[serde(default)]
    pub timeouts: TimeoutCfg,
    /// 可信前置代理网段；语义同 `ProxyCfg.trusted_proxies`。
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
    /// 是否实际绑定明文 listener。默认 true；false 只用于独立 TLS-only proxy，且必须配置 tls。
    #[serde(default = "default_true")]
    pub plain_enabled: bool,
    /// 可选 TLS 监听。明文与 TLS 分 socket。
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// V9 HTTP/3/QUIC；关闭时不建立 UDP listener，也不改变 h1/h2 行为。
    #[serde(default)]
    pub http3: Http3Cfg,
    /// server_name/Host 别名。空表示 default_server。
    #[serde(default)]
    pub server_names: Vec<String>,
    /// Gateway API 共享 HTTP/HTTPS socket 上的逻辑 listener。请求管线先按 Host 选择
    /// listener 隔离路由；HTTPS 再与 TLS SNI 的选择结果比较，不一致时返回 421。
    #[serde(default)]
    pub gateway_listeners: Vec<GatewayListenerCfg>,
    /// 可信前置代理网段：只有来自这些 CIDR 的直连对端，才信任其
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

/// Gateway API HTTP/HTTPS socket 上参与 Host 路由隔离与 SNI 权威判断的逻辑 listener。
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayListenerCfg {
    /// listener 的稳定身份；同一 proxy 内必须唯一。
    pub id: String,
    /// 可选 listener hostname；支持精确 DNS 名和最左 `*.` 通配，空值是兜底 listener。
    #[serde(default)]
    pub hostname: Option<String>,
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
    /// MQTT 协议治理 profile；默认关闭时仍是 wire-transparent TCP。
    #[serde(default)]
    pub mqtt: StreamMqttCfg,
    /// Kafka 协议治理 profile；默认关闭时仍是 wire-transparent TCP。
    #[serde(default)]
    pub kafka: StreamKafkaCfg,
    /// 多 stream route。为空时沿用 listener 级 `upstream` 单路由行为。
    #[serde(default)]
    pub routes: Vec<StreamRouteCfg>,
    /// 显式声明该 listener 不含任何可转发路由，所有连接在匹配阶段关闭；用于保留已接纳但
    /// 暂无合法 Route 的受控 socket，不能与 `upstream` 或 `routes` 同时配置。
    #[serde(default)]
    pub reject_all: bool,
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

/// MQTT 3.1.1/5.0 受限协议治理配置。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamMqttCfg {
    /// 是否启用 MQTT frame 解析、ACL 与 QoS 状态跟踪。
    #[serde(default)]
    pub enabled: bool,
    /// 该 listener 同时允许的 MQTT 连接数，包含 CONNECT preread/TLS 阶段。
    #[serde(default = "default_stream_mqtt_max_connections")]
    pub max_connections: usize,
    /// 单个 MQTT Control Packet 的 wire 字节上限。
    #[serde(default = "default_stream_mqtt_max_packet_bytes")]
    pub max_packet_bytes: usize,
    /// 从收到 fixed-header 首字节起到整枚 packet 完整的 deadline；纯 idle 不计时。
    #[serde(default = "default_stream_mqtt_packet_timeout_ms")]
    pub packet_timeout_ms: u64,
    /// listener 内所有活跃 MQTT 连接可同时占用的双向 packet buffer 预算。
    #[serde(default = "default_stream_mqtt_max_buffered_bytes")]
    pub max_buffered_bytes: usize,
    /// Topic Name/Topic Filter 的 UTF-8 字节上限。
    #[serde(default = "default_stream_mqtt_max_topic_bytes")]
    pub max_topic_bytes: usize,
    /// 单连接已生效与待 SUBACK 的去重订阅总数上限。
    #[serde(default = "default_stream_mqtt_max_subscriptions")]
    pub max_subscriptions: usize,
    /// 单连接两个方向的 QoS publish 与待 ACK 控制包总数上限。
    #[serde(default = "default_stream_mqtt_max_inflight_messages")]
    pub max_inflight_messages: usize,
    /// 允许的 client id 精确集合；空集合表示不额外限制 client id。
    #[serde(default)]
    pub client_id_allow: Vec<String>,
    /// 允许 client PUBLISH 的 MQTT Topic Filter；空集合表示拒绝所有 publish。
    #[serde(default)]
    pub publish_topic_allow: Vec<String>,
    /// 允许 SUBSCRIBE/UNSUBSCRIBE 的 MQTT Topic Filter 边界；空集合表示拒绝全部。
    #[serde(default)]
    pub subscribe_topic_allow: Vec<String>,
}

impl Default for StreamMqttCfg {
    /// 业务作用：保持 MQTT 治理默认关闭，同时为显式开启提供有界资源基线。
    ///
    /// 参数说明：无。
    ///
    /// 返回：默认关闭的 profile；不会让透明 stream 进入 MQTT parser。
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: default_stream_mqtt_max_connections(),
            max_packet_bytes: default_stream_mqtt_max_packet_bytes(),
            packet_timeout_ms: default_stream_mqtt_packet_timeout_ms(),
            max_buffered_bytes: default_stream_mqtt_max_buffered_bytes(),
            max_topic_bytes: default_stream_mqtt_max_topic_bytes(),
            max_subscriptions: default_stream_mqtt_max_subscriptions(),
            max_inflight_messages: default_stream_mqtt_max_inflight_messages(),
            client_id_allow: Vec::new(),
            publish_topic_allow: Vec::new(),
            subscribe_topic_allow: Vec::new(),
        }
    }
}

/// Kafka client data-plane 受限协议治理配置。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamKafkaCfg {
    /// 是否启用 Kafka frame、ACL、correlation 与 broker endpoint rewrite。
    #[serde(default)]
    pub enabled: bool,
    /// listener 同时允许的受治理 Kafka 连接数，包含 TLS 阶段。
    #[serde(default = "default_stream_kafka_max_connections")]
    pub max_connections: usize,
    /// 单枚 Kafka request/response 的完整 wire 字节上限，包含四字节长度前缀。
    #[serde(default = "default_stream_kafka_max_frame_bytes")]
    pub max_frame_bytes: usize,
    /// 从长度前缀首字节到完整 frame 的 deadline；纯 idle 不计时。
    #[serde(default = "default_stream_kafka_frame_timeout_ms")]
    pub frame_timeout_ms: u64,
    /// listener 所有连接双向 frame buffer 的悲观聚合预留上限。
    #[serde(default = "default_stream_kafka_max_buffered_bytes")]
    pub max_buffered_bytes: usize,
    /// 单连接尚未收到 response 的 correlation id 数量上限。
    #[serde(default = "default_stream_kafka_max_inflight_requests")]
    pub max_inflight_requests: usize,
    /// request header 中 client id 的 UTF-8 字节上限。
    #[serde(default = "default_stream_kafka_max_client_id_bytes")]
    pub max_client_id_bytes: usize,
    /// topic 名 UTF-8 字节上限。
    #[serde(default = "default_stream_kafka_max_topic_bytes")]
    pub max_topic_bytes: usize,
    /// consumer group id UTF-8 字节上限。
    #[serde(default = "default_stream_kafka_max_group_bytes")]
    pub max_group_bytes: usize,
    /// 任一协议数组可包含的最大元素数。
    #[serde(default = "default_stream_kafka_max_array_items")]
    pub max_array_items: usize,
    /// 允许的 client id 精确集合；空集合表示不额外限制。
    #[serde(default)]
    pub client_id_allow: Vec<String>,
    /// 允许访问的 topic 精确集合；空集合拒绝所有 topic API。
    #[serde(default)]
    pub topic_allow: Vec<String>,
    /// 允许访问的 consumer group 精确集合；空集合拒绝所有 group API。
    #[serde(default)]
    pub group_allow: Vec<String>,
    /// 允许的 SASL mechanism 精确集合；空集合拒绝 SASL handshake。
    #[serde(default)]
    pub sasl_mechanism_allow: Vec<String>,
    /// broker 在 Metadata/FindCoordinator 中返回的 endpoint 改写表。
    #[serde(default)]
    pub broker_rewrite: Vec<KafkaBrokerRewriteCfg>,
}

impl Default for StreamKafkaCfg {
    /// 业务作用：保持 Kafka 治理默认关闭，同时提供总量可证明有界的连接/frame 基线。
    ///
    /// 参数说明：无。
    ///
    /// 返回：默认关闭的 profile；不会让透明 stream 进入 Kafka parser。
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: default_stream_kafka_max_connections(),
            max_frame_bytes: default_stream_kafka_max_frame_bytes(),
            frame_timeout_ms: default_stream_kafka_frame_timeout_ms(),
            max_buffered_bytes: default_stream_kafka_max_buffered_bytes(),
            max_inflight_requests: default_stream_kafka_max_inflight_requests(),
            max_client_id_bytes: default_stream_kafka_max_client_id_bytes(),
            max_topic_bytes: default_stream_kafka_max_topic_bytes(),
            max_group_bytes: default_stream_kafka_max_group_bytes(),
            max_array_items: default_stream_kafka_max_array_items(),
            client_id_allow: Vec::new(),
            topic_allow: Vec::new(),
            group_allow: Vec::new(),
            sasl_mechanism_allow: Vec::new(),
            broker_rewrite: Vec::new(),
        }
    }
}

/// Kafka broker endpoint 的精确地址改写项。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KafkaBrokerRewriteCfg {
    /// broker response 中声明的原 host。
    pub from_host: String,
    /// broker response 中声明的原 port。
    pub from_port: u16,
    /// client 应连接的代理 host。
    pub to_host: String,
    /// client 应连接的代理 port。
    pub to_port: u16,
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
    /// 是否在选中该路由后终止下游 TLS；仅与 listener TLS 身份和 SNI preread 同时使用。
    #[serde(default)]
    pub terminate_tls: bool,
    /// 上游目标。支持 `host:port`、`tcp://host:port` 或 `lb://service`。
    pub upstream: String,
    /// 按连接或 UDP session 选择的带权上游集合；非空时覆盖单一 `upstream`，零权重项不接收流量。
    #[serde(default)]
    pub weighted_upstreams: Vec<StreamWeightedUpstreamCfg>,
    /// 可选 stream 上游 TLS/mTLS profile；`lb://service` 应使用 service 级 `tls`。
    #[serde(default)]
    pub tls: Option<UpstreamTlsCfg>,
}

/// L4 route 的单个带权上游。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamWeightedUpstreamCfg {
    /// 上游目标；Gateway API 生成配置使用 `lb://service`。
    pub upstream: String,
    /// 相对权重；零表示保留声明但不参与选择。
    pub weight: u32,
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
    #[serde(default)]
    pub cert_file: String,
    /// 与证书匹配的 PEM 私钥文件，相对主配置文件目录解析。
    #[serde(default)]
    pub key_file: String,
    /// 可选外部 TLS 签名身份；配置后 `key_file` 必须为空。
    #[serde(default)]
    pub private_key_provider: Option<ExternalPrivateKeyCfg>,
    /// 可选 SPIRE Workload API 身份；配置后文件身份、外部 signer 与 SNI 身份必须为空。
    #[serde(default)]
    pub spire: Option<SpireWorkloadCfg>,
    /// 同一 stream socket 上按 SNI 选择的额外证书身份。
    #[serde(default)]
    pub certs: Vec<SniCertCfg>,
    /// 下游 TLS 握手 deadline，防慢 ClientHello 长期占用连接任务。
    #[serde(default = "default_stream_tls_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// 可选 mTLS 客户端 CA，与 L7 `tls.client_auth` 使用同一 require/optional 契约。
    #[serde(default)]
    pub client_auth: Option<ClientAuthCfg>,
    /// 默认证书的服务端 OCSP staple；SNI 附加证书分别在各自条目声明。
    #[serde(default)]
    pub ocsp_stapling: Option<OcspStaplingCfg>,
    /// 可选共享 session ticket key 集；语义与 HTTP TLS listener 一致。
    #[serde(default)]
    pub session_tickets: Option<SessionTicketCfg>,
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
    /// SNI 多证书(§19):按 ClientHello 的 server_name 选证;不匹配则用上面的默认 cert/key 兜底。
    #[serde(default)]
    pub certs: Vec<SniCertCfg>,
    /// 双向 TLS(mTLS,§19):校验客户端证书。缺省 None = 关闭(不要求客户端证书)。
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

const fn default_http3_max_idle_timeout_ms() -> u64 {
    30_000
}

const fn default_http3_alt_svc_max_age_seconds() -> u32 {
    86_400
}

const fn default_http3_max_connections() -> usize {
    100_000
}

/// 业务作用：限制单连接可占用的 CONNECT-UDP socket 数，避免一个 QUIC peer 耗尽文件描述符。
///
/// 参数说明：无。
///
/// 返回：返回默认会话上限 64。
const fn default_http3_max_connect_udp_sessions() -> usize {
    64
}

/// 业务作用：为不可靠 DATAGRAM 提供小型突发吸收队列，同时保持丢包背压有界。
///
/// 参数说明：无。
///
/// 返回：返回默认队列上限 128。
const fn default_http3_max_datagram_queue() -> usize {
    128
}

/// 业务作用：给 CONNECT-UDP payload 设置保守默认值，使常见 QUIC path MTU 无需 IP 分片。
///
/// 参数说明：无。
///
/// 返回：返回默认 payload 上限 1150 字节。
const fn default_http3_max_datagram_bytes() -> usize {
    1_150
}

const fn default_http3_max_connections_per_ip() -> usize {
    1024
}

const fn default_http3_max_pending_handshakes() -> usize {
    1024
}

const fn default_http3_max_pending_handshake_bytes() -> u64 {
    16 * 1024
}

const fn default_http3_max_bidi_streams_per_connection() -> u32 {
    256
}

/// 业务作用：为 H3 控制流与 WebTransport 单向业务流预留共享的连接级容量。
///
/// 参数说明：无。
///
/// 返回：返回 256 条客户端单向 stream 的默认硬上限。
const fn default_http3_max_uni_streams_per_connection() -> u32 {
    256
}

const fn default_http3_max_request_header_bytes() -> usize {
    64 * 1024
}

const fn default_http3_max_stream_buffer_bytes() -> usize {
    1024 * 1024
}

const fn default_http3_retry_token_lifetime_seconds() -> u64 {
    15
}

const fn default_http3_retry_token_rotation_seconds() -> u64 {
    3600
}

/// 业务作用：限制可接受 early data 的 TLS 恢复状态存活代次，缩短泄漏 session 的风险窗口。
///
/// 参数说明: 无。
///
/// 返回：返回一小时的默认恢复代轮换周期。
const fn default_http3_early_data_session_rotation_seconds() -> u64 {
    3600
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
/// 参数说明：无。
///
/// 返回：返回 `hard_fail`。
fn default_client_ocsp_mode() -> String {
    "hard_fail".to_owned()
}

/// 业务作用：限制客户端握手后等待 OCSP responder 的总时长。
///
/// 参数说明：无。
///
/// 返回：返回 3 秒。
const fn default_client_ocsp_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：限制单 listener 客户端证书 OCSP 缓存的身份数量。
///
/// 参数说明：无。
///
/// 返回：返回 4096 项。
const fn default_client_ocsp_cache_entries() -> usize {
    4096
}

/// 业务作用：限制单 listener 因新客户端证书同时发起的 OCSP 请求。
///
/// 参数说明：无。
///
/// 返回：返回 8 个并发。
const fn default_client_ocsp_concurrency() -> usize {
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
/// 参数说明：无。
///
/// 返回：返回 `optional`；含 TLS Feature status_request 的证书仍会被强制提升为 required。
fn default_ocsp_stapling_mode() -> String {
    "optional".to_owned()
}

/// 业务作用：限制没有 `nextUpdate` 的 OCSP 响应可被重放的最长窗口。
///
/// 参数说明：无。
///
/// 返回：返回 24 小时。
const fn default_ocsp_max_age_without_next_update_seconds() -> u64 {
    24 * 60 * 60
}

/// 业务作用：为 OCSP responder 与网关的轻微时钟漂移提供有界容差。
///
/// 参数说明：无。
///
/// 返回：返回 5 分钟。
const fn default_ocsp_clock_skew_seconds() -> u64 {
    5 * 60
}

/// 业务作用：为主动 OCSP 获取提供早于常见 `nextUpdate` 的保守预刷新周期。
///
/// 参数说明：无。
///
/// 返回：返回 1 小时。
const fn default_ocsp_refresh_interval_seconds() -> u64 {
    60 * 60
}

/// 业务作用：限制单次 OCSP responder 交互占用后台任务的时间。
///
/// 参数说明：无。
///
/// 返回：返回 5 秒。
const fn default_ocsp_request_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：默认关闭客户端证书吊销检查，避免没有 CRL 时产生含糊的软失败语义。
///
/// 参数说明: 无。
///
/// 返回：返回 `off`。
fn default_client_revocation_mode() -> String {
    "off".to_owned()
}

/// 业务作用：为显式启用的 session ticket 设置有界 lifetime hint。
///
/// 参数说明: 无。
///
/// 返回：返回 12 小时。
const fn default_session_ticket_lifetime_seconds() -> u32 {
    12 * 60 * 60
}

/// 一组 SNI 证书:命中这些 server_name 的握手用这套 cert/key(§19,对齐 nginx 多 `server{ssl_certificate}`)。
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
    /// 集群配置渐进发布策略；关闭时保持一次 CAS 全量发布的兼容行为。
    #[serde(default)]
    pub rollout: AdminRolloutCfg,
    /// 高危管理变更的 maker-checker 策略；关闭时保持直接执行兼容行为。
    #[serde(default)]
    pub approval: AdminApprovalCfg,
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
            rollout: AdminRolloutCfg::default(),
            approval: AdminApprovalCfg::default(),
            max_config_body_bytes: default_admin_max_config_body_bytes(),
        }
    }
}

/// 高危管理变更的双人复核策略。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminApprovalCfg {
    /// 是否把指定资源的写操作先登记为待审批候选。
    #[serde(default)]
    pub enabled: bool,
    /// 需要复核的资源域；仅允许 Sentinel、Consumers 与 Certs。
    #[serde(default = "default_admin_approval_resources")]
    pub resources: Vec<AdminResource>,
    /// 待审批候选有效期，过期候选永不执行。
    #[serde(default = "default_admin_approval_ttl_seconds")]
    pub ttl_seconds: u64,
    /// 单进程待审批候选上限；达到上限时拒绝新提交。
    #[serde(default = "default_admin_approval_max_pending")]
    pub max_pending: usize,
}

impl Default for AdminApprovalCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            resources: default_admin_approval_resources(),
            ttl_seconds: default_admin_approval_ttl_seconds(),
            max_pending: default_admin_approval_max_pending(),
        }
    }
}

/// 集群配置金丝雀发布与健康门控策略。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminRolloutCfg {
    /// 是否把 Nacos 配置发布改为先 canary、再全量的状态机。
    #[serde(default)]
    pub enabled: bool,
    /// 从符合 selector 的启用成员中选取的节点数。
    #[serde(default = "default_admin_rollout_canary_count")]
    pub canary_count: usize,
    /// 可选成员 metadata 键；空值表示按稳定 node_id 选择所有启用成员中的前 N 个。
    #[serde(default)]
    pub selector_key: String,
    /// selector_key 非空时要求 metadata 精确等于该值。
    #[serde(default)]
    pub selector_value: String,
    /// canary 换版并取得首个健康样本后的观察窗口。
    #[serde(default = "default_admin_rollout_observation_seconds")]
    pub observation_seconds: u64,
    /// 观察窗内 canary 请求 5xx 比例绝对上限。
    #[serde(default = "default_admin_rollout_max_5xx_ratio")]
    pub max_5xx_ratio: f64,
    /// canary p99 相对基线的最大倍率；没有基线流量时只使用绝对上限。
    #[serde(default = "default_admin_rollout_max_p99_regression_ratio")]
    pub max_p99_regression_ratio: f64,
    /// canary 请求端到端 p99 绝对上限。
    #[serde(default = "default_admin_rollout_max_p99_ms")]
    pub max_p99_ms: u64,
    /// 是否要求另一名具备 Config/Write 权限的主体确认后才从 canary 放量。
    #[serde(default)]
    pub require_approval: bool,
}

impl Default for AdminRolloutCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            canary_count: default_admin_rollout_canary_count(),
            selector_key: String::new(),
            selector_value: String::new(),
            observation_seconds: default_admin_rollout_observation_seconds(),
            max_5xx_ratio: default_admin_rollout_max_5xx_ratio(),
            max_p99_regression_ratio: default_admin_rollout_max_p99_regression_ratio(),
            max_p99_ms: default_admin_rollout_max_p99_ms(),
            require_approval: false,
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
    /// 是否允许本节点用**自己这份 admin 凭据**去抓取同集群其它节点的 `/metrics`。
    ///
    /// 默认 **false**,必须显式开启。为什么不默认开:
    /// - 它让 admin 从"只被访问"变成"会主动外连",是**攻击面的实质变化**——被打穿的
    ///   admin 可以借它探测内网,必须由运维明示接受;
    /// - 它假设集群各节点**同构配置**(同一份凭据)。该假设在自动化部署下通常成立,
    ///   但不成立时抓取只会 401、不会静默串权,失败如实计入响应而不是伪造零值。
    ///
    /// 凭据只从进程内已解析的配置取,**不接受请求携带的任何凭证**——否则控制面就成了
    /// 一个可被借用的跳板(调用方带什么凭据,网关就拿什么去连内网别的机器)。
    /// 开启时必须同时启用 `admin.auth`；RBAC 模式还必须至少有一个 Cluster/Read principal。
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

/// 可复用 filter snippet 的根配置；import 只能位于主配置目录内。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct SnippetsCfg {
    /// 相对当前文件的 snippet 文档列表。
    #[serde(default)]
    pub imports: Vec<String>,
    /// 当前文件定义的命名片段。
    #[serde(default)]
    pub definitions: HashMap<String, ReusableSnippetCfg>,
}

/// 一个命名 snippet；先展开显式依赖，再按顺序追加 filter。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ReusableSnippetCfg {
    /// 依赖的其它 snippet 名称。
    #[serde(default, rename = "use", alias = "uses")]
    pub uses: Vec<String>,
    /// 最终插入 route 的 filter DSL。
    #[serde(default)]
    pub filters: Vec<String>,
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
    /// naml watcher、SIGHUP 与 Nacos 共用事件队列容量。0 按 1 处理，始终保持有界。
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
    /// 权威位置是 `limits.max_msg_bytes`;两处同时设置且不相等时构建期报错,
    /// 只设旧位仍然生效(一次性迁移路径,§25.2.9)。
    #[serde(default)]
    pub max_msg_bytes: Option<usize>,
    /// 每 action 的精确 gRPC `:path`(§25.2.3)。edge 不能只靠可伪造 header 触发,
    /// 必须同时命中精确方法;allowed_actions 里的每个 action 都要有对应 method。
    #[serde(default)]
    pub methods: GrpcEdgeMethodsCfg,
    /// tenant/user 身份从已验证 principal 的 claim 映射(§25.2.3 相位 4),
    /// 客户端自报 header 永不是权威身份。
    #[serde(default)]
    pub identity: GrpcEdgeIdentityCfg,
    /// 双维队列之外的节点级预算与基数上限(§25.2.5),拒绝高基数内存攻击。
    #[serde(default)]
    pub limits: GrpcEdgeLimitsCfg,
    /// 浏览器 WS→内部 gRPC 边缘桥接入口路径（如 `/edge/ws`）。
    ///
    /// 设了才开桥;要求本 route 允许 subscribe。桥接只换**传输外壳**——鉴权、身份、
    /// group 索引、队列预算、治理关闭全部复用同一条订阅路径,每条广播以一个
    /// binary 帧原样送出与 native gRPC 订阅者**字节一致**的 `[5B prefix + payload]`。
    #[serde(default)]
    pub ws_bridge_path: Option<String>,
    /// 发布/订阅授权策略；在身份相位之后、任何执行副作用之前判定。
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

/// 发布/订阅授权策略（§25.2.3）。
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
    /// 单条 protobuf message body（不含 5 字节前缀）字节上限；解码器读出 prefix
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

/// 发布面 PublishStream 单流四门（§25.2.3）。
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
    /// 按 `FramePush.coalesce_key` 只保留每个业务 key 的最新一帧；空键按 drop_new 处理。
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
    /// peer 身份鉴别方式（§25.2.6）：默认 mTLS，在 TLS 握手期验证节点证书；
    /// `cluster_secret` 仅作为缺少 mTLS 基建时的兼容形态。
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
    /// 全网状中继的节点数硬门。静态 peers 或 Nacos 成员超门直接拒绝；
    /// `auto` 只降低无关 group 的 payload 流量，不改变全网状连接数量。
    #[serde(default = "default_grpc_edge_full_mesh_max_nodes")]
    pub full_mesh_max_nodes: usize,
    /// 兴趣路由策略：`auto` 使用 revision 快照过滤明确无兴趣的 peer，hint 缺失、断档或过期
    /// 一律 fail-open 广播；`broadcast_all` 显式永远广播且仅允许建议规模内的小集群。
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
    /// `session_registry: redis` 的连接与租约参数；`none` 时整段忽略。
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

/// SessionDirectory（Redis）连接与租约参数（§25.2.7）。
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
    /// group 严格序：由 rendezvous-hash group owner 统一定序。
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
    /// 复用 §9 Nacos 自注册 watch 驱动运行时成员对账。
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
    /// 集群共享 secret（SecretSource，§19/§20）；仅作为无 mTLS 基建时的过渡认证形态。
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
    /// 是否读取 Gateway API Experimental Channel 与 MCS 资源；制品必须带 `gateway-api-experimental`。
    #[serde(default)]
    pub gateway_api_experimental: bool,
    /// 是否读取 `inference.networking.k8s.io/v1` InferencePool，并把 EPP 决策接入 HTTPRoute。
    /// 制品必须带 `inference-gateway`，关闭时不会请求 Inference Extension CRD 或 Pod LIST。
    #[serde(default)]
    pub inference_gateway_enabled: bool,
    /// 固定的 Gateway API Inference Extension CRD 与 conformance contract 版本。
    #[serde(default = "default_kubernetes_inference_extension_version")]
    pub inference_extension_version: String,
    /// 是否已有外部透明流量捕获把 Service/ServiceImport parent 流量送入 Naway。
    /// false 时 mesh parent 明确发布不接纳状态，不能只因 CRD 可解析就宣称已编程。
    #[serde(default)]
    pub gateway_mesh_interception_ready: bool,
    /// Mesh Profile 专用 listener 的绑定地址；应与公网 Gateway listener 隔离，
    /// 只允许透明流量捕获组件访问。
    #[serde(default = "default_kubernetes_gateway_mesh_bind_address")]
    pub gateway_mesh_bind_address: String,
    /// Mesh Profile 专用 listener 端口；外部透明流量捕获必须把 Service 流量送到该端口。
    #[serde(default = "default_kubernetes_gateway_mesh_port")]
    pub gateway_mesh_port: u16,
    /// 本控制器的 GatewayClass `spec.controllerName`。
    #[serde(default = "default_kubernetes_gateway_controller_name")]
    pub gateway_controller_name: String,
    /// 固定的 Gateway API CRD/conformance contract 版本。
    #[serde(default = "default_kubernetes_gateway_api_version")]
    pub gateway_api_version: String,
    /// Gateway API HTTP/HTTPS listener 物化为数据面 socket 时使用的本地绑定地址。
    #[serde(default = "default_kubernetes_gateway_bind_address")]
    pub gateway_bind_address: String,
    /// Gateway API TLS/TCP/UDP listener 物化为 stream socket 时使用的本地绑定地址。
    /// 默认与 `gateway_bind_address` 相同；同一端口同时承载 TLS 终止和 TLS passthrough
    /// 时必须显式隔离地址，避免两个 listener 竞争同一 socket。
    #[serde(default = "default_kubernetes_gateway_stream_bind_address")]
    pub gateway_stream_bind_address: String,
    /// 可选的逐 Gateway stream 地址池；非空时按稳定对象顺序为每个含 TLS/TCP/UDP listener
    /// 的 Gateway 分配独立地址，地址不足的 Gateway 失败闭合。
    #[serde(default)]
    pub gateway_stream_bind_addresses: Vec<String>,
    /// GRPCRoute 后端的固定 HTTP/2 transport；可选 `h2c` 或 `h2`。
    #[serde(default = "default_kubernetes_grpc_backend_protocol")]
    pub grpc_backend_protocol: String,
    /// 是否通过 status subresource 发布本控制器拥有的 condition。
    #[serde(default)]
    pub status_updates_enabled: bool,
    /// 是否用 finalizer 保证删除对象先退出数据面候选，再允许 API server 完成删除。
    #[serde(default)]
    pub finalizers_enabled: bool,
    /// LIST 成功后是否用 watch 提前唤醒下一轮完整 relist。
    #[serde(default = "default_true")]
    pub watch_enabled: bool,
    /// 单轮 watch 的服务端超时秒数；超时后重新 LIST，避免永久依赖断裂连接。
    #[serde(default = "default_kubernetes_watch_timeout_seconds")]
    pub watch_timeout_seconds: u32,
    /// 删除对象退出候选后，等待 reload 发布确认的最长时间。
    #[serde(default = "default_kubernetes_deletion_drain_timeout_ms")]
    pub deletion_drain_timeout_ms: u64,
    /// 单轮允许提交的 status/finalizer mutation 总数。
    #[serde(default = "default_kubernetes_max_status_updates")]
    pub max_status_updates: usize,
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
            gateway_api_experimental: false,
            inference_gateway_enabled: false,
            inference_extension_version: default_kubernetes_inference_extension_version(),
            gateway_mesh_interception_ready: false,
            gateway_mesh_bind_address: default_kubernetes_gateway_mesh_bind_address(),
            gateway_mesh_port: default_kubernetes_gateway_mesh_port(),
            gateway_controller_name: default_kubernetes_gateway_controller_name(),
            gateway_api_version: default_kubernetes_gateway_api_version(),
            gateway_bind_address: default_kubernetes_gateway_bind_address(),
            gateway_stream_bind_address: default_kubernetes_gateway_stream_bind_address(),
            gateway_stream_bind_addresses: Vec::new(),
            grpc_backend_protocol: default_kubernetes_grpc_backend_protocol(),
            status_updates_enabled: false,
            finalizers_enabled: false,
            watch_enabled: true,
            watch_timeout_seconds: default_kubernetes_watch_timeout_seconds(),
            deletion_drain_timeout_ms: default_kubernetes_deletion_drain_timeout_ms(),
            max_status_updates: default_kubernetes_max_status_updates(),
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

/// 业务作用：为 Gateway API 生成的 L4 listener 提供安全的全接口默认绑定地址。
/// 参数说明: 无。
/// 返回：返回 IPv4 未指定地址；部署方可显式收窄到 Pod IP 或 loopback。
fn default_kubernetes_gateway_bind_address() -> String {
    "0.0.0.0".to_owned()
}

/// 业务作用：把 Mesh Profile listener 默认限制在本机，避免来源 namespace header
/// 被外部客户端伪造后取得 consumer Route 权限。
///
/// 参数说明: 无。
///
/// 返回：返回 IPv4 loopback 地址；跨 network namespace 部署必须显式配置受保护地址。
fn default_kubernetes_gateway_mesh_bind_address() -> String {
    "127.0.0.1".to_owned()
}

/// 业务作用：为透明流量捕获提供独立且稳定的 Mesh Profile 接收端口。
///
/// 参数说明: 无。
///
/// 返回：返回默认端口 15001。
const fn default_kubernetes_gateway_mesh_port() -> u16 {
    15_001
}

/// 业务作用：为 Gateway API 生成的 stream listener 提供向后兼容的全接口默认绑定地址。
/// 参数说明: 无。
/// 返回：返回 IPv4 未指定地址；需要同端口隔离 L7 与 L4 时由部署方显式配置独立地址。
fn default_kubernetes_gateway_stream_bind_address() -> String {
    "0.0.0.0".to_owned()
}

/// 业务作用：固定 controller 编译与 conformance 声明使用的 Gateway API 版本。
/// 参数说明: 无。
/// 返回：返回当前实现支持的稳定版本 `v1.5.1`。
fn default_kubernetes_gateway_api_version() -> String {
    "v1.5.1".to_owned()
}

/// 业务作用：固定控制器实现与一致性声明共同采用的 Inference Extension 合同版本。
///
/// 参数说明: 无。
///
/// 返回：返回当前支持的 `v1.5.0` 合同版本。
fn default_kubernetes_inference_extension_version() -> String {
    "v1.5.0".to_owned()
}

/// 业务作用：固定未启用 TLS backend policy 时 GRPCRoute 的明文 HTTP/2 transport。
/// 参数说明: 无。
/// 返回：返回 `h2c`，避免 native gRPC 被自动协议选择降级到 HTTP/1.1。
fn default_kubernetes_grpc_backend_protocol() -> String {
    "h2c".to_owned()
}

/// 业务作用：限制单次 Kubernetes watch 占用连接的时间，周期性 relist 修复漏事件。
/// 参数说明: 无。
/// 返回：返回 30 秒服务端 watch 超时。
const fn default_kubernetes_watch_timeout_seconds() -> u32 {
    30
}

/// 业务作用：限定删除 finalizer 等待数据面发布确认的最长时长。
/// 参数说明: 无。
/// 返回：返回 5 秒；超时保留 finalizer，由下一轮继续恢复。
const fn default_kubernetes_deletion_drain_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：限制单轮控制面外部写操作，防止异常对象集合放大 API server 压力。
/// 参数说明: 无。
/// 返回：返回 4096 个 mutation 的硬配置默认值。
const fn default_kubernetes_max_status_updates() -> usize {
    4_096
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
    /// 后端类型:`file`、`redis` 或 `nacos`。默认 file,零外部依赖。
    #[serde(default = "default_dynamic_store_backend")]
    pub backend: String,
    /// file 后端配置。
    #[serde(default)]
    pub file: FileStoreCfg,
    /// Redis 后端配置。仅 `backend: redis` 时使用。
    #[serde(default)]
    pub redis: RedisStoreCfg,
    /// Nacos 配置中心后端。仅 `backend: nacos` 时使用。
    #[serde(default)]
    pub nacos: NacosStoreCfg,
}

impl Default for DynamicStoreBackendCfg {
    fn default() -> Self {
        Self {
            backend: default_dynamic_store_backend(),
            file: FileStoreCfg::default(),
            redis: RedisStoreCfg::default(),
            nacos: NacosStoreCfg::default(),
        }
    }
}

/// Nacos-backed DynamicStore 的连接、命名与文档资源配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NacosStoreCfg {
    /// Nacos server 地址。
    #[serde(default)]
    pub server_addr: String,
    /// Nacos namespace ID；public 空间留空。
    #[serde(default)]
    pub namespace: String,
    /// Nacos group。
    #[serde(default = "default_nacos_group")]
    pub group: String,
    /// Nacos app name。
    #[serde(default = "default_nacos_app_name")]
    pub app_name: String,
    /// 可选 Nacos 用户名。
    #[serde(default)]
    pub username: String,
    /// 可选 Nacos 密码。
    #[serde(default)]
    pub password: String,
    /// 每个 collection 对应的 dataId 前缀。
    #[serde(default = "default_dynamic_store_nacos_prefix")]
    pub data_id_prefix: String,
    /// 单 collection JSON 文档硬上限；CAS 前和 watch 后都复验。
    #[serde(default = "default_dynamic_store_nacos_max_document_bytes")]
    pub max_document_bytes: u64,
}

impl Default for NacosStoreCfg {
    /// 业务作用：提供零外部依赖的 Nacos store 占位配置，只有显式选择 backend=nacos 后才要求地址。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回 public namespace、规范 group/app/prefix 与有界文档上限的默认值。
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            namespace: String::new(),
            group: default_nacos_group(),
            app_name: default_nacos_app_name(),
            username: String::new(),
            password: String::new(),
            data_id_prefix: default_dynamic_store_nacos_prefix(),
            max_document_bytes: default_dynamic_store_nacos_max_document_bytes(),
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

/// Gateway API RequestRedirect 的运行期无关声明。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GatewayRedirectCfg {
    /// 覆盖目标 scheme；为空时保留入站 scheme。
    #[serde(default)]
    pub scheme: Option<String>,
    /// 覆盖目标 hostname；为空时保留入站 authority host。
    #[serde(default)]
    pub hostname: Option<String>,
    /// 覆盖目标端口；为空时按目标 scheme 和原 authority 决定。
    #[serde(default)]
    pub port: Option<u16>,
    /// Gateway API 允许的重定向状态码。
    #[serde(default = "default_gateway_redirect_status_code")]
    pub status_code: u16,
    /// 把完整请求 path 替换为固定 origin path。
    #[serde(default)]
    pub replace_full_path: Option<String>,
    /// 只替换本 route 匹配的 path 前缀，保留剩余后缀。
    #[serde(default)]
    pub replace_prefix_match: Option<String>,
    /// 构建期固定的原匹配前缀；仅与 `replace_prefix_match` 同时存在。
    #[serde(default)]
    pub matched_prefix: Option<String>,
}

/// 业务作用：为 Gateway API RequestRedirect 提供保持方法语义的默认状态码。
/// 参数说明: 无。
/// 返回：返回 302，与 Gateway API 未声明 statusCode 时的默认行为一致。
const fn default_gateway_redirect_status_code() -> u16 {
    302
}

/// route 级内置 API WAF 配置。
///
/// 未配置时请求保持流式快路径；仅 `inspect_body: true` 会为 JSON/XML 请求启用有界聚合。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WafCfg {
    /// 处置模式：`enforce` 拦截，`monitor` 只记录低基数命中结果后继续转发。
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// 是否检查 JSON/XML 请求体；false 时只检查 method、URI 与 headers。
    #[serde(default)]
    pub inspect_body: bool,
    /// 请求体聚合上限；超过后故障关闭，不允许绕过检查进入上游。
    #[serde(default = "default_waf_body_bytes")]
    pub max_body_bytes: u64,
    /// 单个 URI/header/结构化字符串允许扫描的最大字节数；超过后按异常输入处理。
    #[serde(default = "default_waf_value_bytes")]
    pub max_value_bytes: usize,
    /// 启用的固定规则 id；空数组表示启用全部内置规则。
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    /// 按规则与精确 target 配置的例外；不支持通配符，避免例外范围无意扩大。
    #[serde(default)]
    pub exclusions: Vec<WafExclusionCfg>,
    /// 可选外部 literal 规则包；候选发布前必须同时通过摘要、签名、格式和资源预算校验。
    #[serde(default)]
    pub rule_pack: Option<WafRulePackCfg>,
    /// JSON 最大嵌套深度。
    #[serde(default = "default_waf_structured_depth")]
    pub max_json_depth: usize,
    /// 单个 JSON document 最大 value 节点数。
    #[serde(default = "default_waf_structured_nodes")]
    pub max_json_nodes: usize,
    /// XML 最大元素嵌套深度。
    #[serde(default = "default_waf_structured_depth")]
    pub max_xml_depth: usize,
    /// 单个 XML document 最大事件节点数。
    #[serde(default = "default_waf_structured_nodes")]
    pub max_xml_nodes: usize,
    /// 单个 XML document 最大属性总数。
    #[serde(default = "default_waf_xml_attributes")]
    pub max_xml_attributes: usize,
}

/// 一条 WAF 精确例外。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WafExclusionCfg {
    /// 被豁免的固定规则 id。
    pub rule: String,
    /// 精确 target：`path`、`query`、`body` 或 `header:<lowercase-name>`。
    pub target: String,
}

/// 外部 WAF literal 规则包的真实性与资源边界。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WafRulePackCfg {
    /// 本地 JSON 规则包；相对主配置目录解析并纳入统一 dependency watcher。
    pub source: String,
    /// 原始 JSON 字节的 SHA-256 十六进制摘要。
    pub sha256: String,
    /// 原始 JSON 字节的 detached Ed25519 signature，使用 Base64 SecretSource。
    pub signature: String,
    /// 32 字节 Ed25519 public key，使用 Base64 SecretSource。
    pub public_key: String,
    /// 规则包原始字节硬上限。
    #[serde(default = "default_waf_rule_pack_bytes")]
    pub max_pack_bytes: usize,
    /// 规则条目硬上限。
    #[serde(default = "default_waf_rule_pack_rules")]
    pub max_rules: usize,
    /// 全部规则 literal 数量硬上限。
    #[serde(default = "default_waf_rule_pack_patterns")]
    pub max_patterns: usize,
    /// 同步候选构建允许消耗的最长 wall time。
    #[serde(default = "default_waf_rule_pack_compile_ms")]
    pub max_compile_ms: u64,
}

/// route 级 Bot 识别、行为评分与挑战策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BotCfg {
    /// 处置模式：`enforce|monitor`。
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// User-Agent allowlist glob；非空时不匹配的请求进入挑战。
    #[serde(default)]
    pub allowed_user_agents: Vec<String>,
    /// User-Agent denylist glob。
    #[serde(default)]
    pub denied_user_agents: Vec<String>,
    /// 必须存在且只有一个合法值的 header 名。
    #[serde(default)]
    pub required_headers: Vec<String>,
    /// 出现即计为自动化信号的 header 名。
    #[serde(default = "default_bot_automation_headers")]
    pub automation_headers: Vec<String>,
    /// 参与稳定客户端指纹的 header 名；User-Agent 始终参与且原值不会进入日志或限流 key。
    #[serde(default = "default_bot_fingerprint_headers")]
    pub fingerprint_headers: Vec<String>,
    /// 明确拒绝的 SHA-256 指纹，使用 64 位小写十六进制字符串。
    #[serde(default)]
    pub denied_fingerprints: Vec<String>,
    /// 缺少或非法 User-Agent 的行为分数。
    #[serde(default = "default_bot_signal_score")]
    pub missing_user_agent_score: u32,
    /// 浏览器 User-Agent 与基础浏览器 header 不一致时的行为分数。
    #[serde(default = "default_bot_browser_mismatch_score")]
    pub browser_header_mismatch_score: u32,
    /// 每个已出现 automation header 的行为分数。
    #[serde(default = "default_bot_signal_score")]
    pub automation_header_score: u32,
    /// 累积分数达到该阈值时进入挑战。
    #[serde(default = "default_bot_score_threshold")]
    pub score_threshold: u32,
    /// 通过 HMAC 请求签名复验后才可信的搜索机器人声明。
    #[serde(default)]
    pub trusted_search_bots: Vec<TrustedSearchBotCfg>,
    /// 可选的客户端指纹速率信号，复用进程级有界 RateLimiter。
    #[serde(default)]
    pub rate: Option<BotRateCfg>,
    /// 挑战响应状态码，必须是 4xx；速率拒绝固定使用 429。
    #[serde(default = "default_bot_challenge_status")]
    pub challenge_status: u16,
    /// `WWW-Authenticate` 的安全 realm，只允许短 ASCII token。
    #[serde(default = "default_bot_challenge_realm")]
    pub challenge_realm: String,
}

/// 一个需要逐请求签名复验的可信搜索机器人声明。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrustedSearchBotCfg {
    /// 稳定、低基数的声明名称，仅用于配置错误定位。
    pub name: String,
    /// 声称该身份的 User-Agent glob；匹配后签名失败会故障关闭。
    pub user_agents: Vec<String>,
    /// HMAC-SHA256 SecretSource，构建期解析且至少 32 bytes。
    pub signature_secret: String,
    /// Base64URL 无填充签名 header。
    #[serde(default = "default_bot_signature_header")]
    pub signature_header: String,
    /// Unix 秒时间戳 header。
    #[serde(default = "default_bot_timestamp_header")]
    pub timestamp_header: String,
    /// 签名时间戳允许的最大绝对偏差。
    #[serde(default = "default_bot_signature_skew_secs")]
    pub max_clock_skew_secs: u64,
}

/// Bot 客户端指纹速率信号。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BotRateCfg {
    /// 窗口内允许的请求数。
    pub limit: u64,
    /// 统计窗口毫秒数。
    pub window_ms: u64,
    /// 基础额度外允许的突发请求数。
    #[serde(default)]
    pub burst: u64,
    /// 单规则最多维护的活动客户端指纹数。
    #[serde(default = "default_bot_max_active_keys")]
    pub max_active_keys: usize,
    /// 活动指纹表耗尽时是否放行新指纹；默认故障关闭。
    #[serde(default)]
    pub active_keys_fail_open: bool,
}

/// route 级浏览器 CSRF 来源与 token 策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CsrfCfg {
    /// 处置模式：`enforce|monitor`。
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// 需要 CSRF 门禁的 HTTP 方法；默认覆盖常见状态变更方法。
    #[serde(default = "default_csrf_methods")]
    pub methods: Vec<String>,
    /// 允许的精确 `scheme://authority`；`same-origin` 表示与当前请求一致。
    #[serde(default = "default_csrf_allowed_origins")]
    pub allowed_origins: Vec<String>,
    /// Origin 缺失时是否允许用 Referer 的 origin 复验。
    #[serde(default = "default_true")]
    pub allow_referer_fallback: bool,
    /// Origin 与 Referer 均缺失时是否显式放行；默认故障关闭。
    #[serde(default)]
    pub allow_missing_origin: bool,
    /// token 模式：`double_submit|signed`。
    #[serde(default = "default_csrf_token_mode")]
    pub token_mode: String,
    /// 必须使用 `__Host-` 前缀的 CSRF cookie 名。
    #[serde(default = "default_csrf_cookie_name")]
    pub cookie_name: String,
    /// 客户端回传 CSRF token 的单值 header 名。
    #[serde(default = "default_csrf_header_name")]
    pub header_name: String,
    /// `signed` 模式的 HMAC-SHA256 SecretSource；double-submit 模式必须为空。
    #[serde(default)]
    pub token_secret: String,
    /// signed token 最大年龄。
    #[serde(default = "default_csrf_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// 是否在未受保护方法的响应中签发新 token header 与 cookie。
    #[serde(default = "default_true")]
    pub issue_on_safe_methods: bool,
}

/// route 级 PII、凭据与 secret 检测、遮蔽和阻断策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DlpCfg {
    /// 命中动作：`block|redact|monitor`。
    #[serde(default = "default_dlp_action")]
    pub action: String,
    /// 启用的固定规则名；空数组表示启用全部内置规则。
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    /// 要检查的请求 header 精确名称。
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// 要检查的响应 header 精确名称。
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// 是否解码并检查 query 参数名和值。
    #[serde(default = "default_true")]
    pub inspect_query: bool,
    /// 是否检查 access log 会记录的 path，并在命中时用固定路径替代。
    #[serde(default = "default_true")]
    pub protect_log_path: bool,
    /// 是否有界聚合并检查请求 body。
    #[serde(default)]
    pub inspect_request_body: bool,
    /// 是否有界聚合并检查响应 body。
    #[serde(default)]
    pub inspect_response_body: bool,
    /// body 检查允许的 media type 精确值或 `application/*+json`。
    #[serde(default = "default_dlp_body_media_types")]
    pub body_media_types: Vec<String>,
    /// 单方向 body 聚合硬上限。
    #[serde(default = "default_dlp_body_bytes")]
    pub max_body_bytes: u64,
    /// redact 动作写入字段或值的固定替代文本。
    #[serde(default = "default_dlp_replacement")]
    pub replacement: String,
    /// 按固定 rule 与精确 target 配置的例外。
    #[serde(default)]
    pub exclusions: Vec<DlpExclusionCfg>,
}

/// 一条 DLP 精确例外。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DlpExclusionCfg {
    /// 被豁免的固定规则名。
    pub rule: String,
    /// 精确 target：header/query 带名称，body 与 path_log 使用固定名。
    pub target: String,
}

/// 业务作用：为敏感数据策略提供故障关闭的默认处置。
///
/// 参数说明：无。
///
/// 返回：返回 `block`。
fn default_dlp_action() -> String {
    "block".to_owned()
}

/// 业务作用：限制默认 DLP body 慢路径只处理结构明确、可安全重放的 media type。
///
/// 参数说明：无。
///
/// 返回：返回 JSON 与 URL encoded form 的固定 media type 列表。
fn default_dlp_body_media_types() -> Vec<String> {
    vec![
        "application/json".to_owned(),
        "application/*+json".to_owned(),
        "application/x-www-form-urlencoded".to_owned(),
    ]
}

/// 业务作用：约束显式 DLP body 慢路径的默认并发内存占用。
///
/// 参数说明：无。
///
/// 返回：返回一 MiB。
const fn default_dlp_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：提供不包含命中原值的默认遮蔽文本。
///
/// 参数说明：无。
///
/// 返回：返回固定 `[REDACTED]`。
fn default_dlp_replacement() -> String {
    "[REDACTED]".to_owned()
}

/// 业务作用：提供默认 CSRF 状态变更方法集合。
///
/// 参数说明：无。
///
/// 返回：返回 POST、PUT、PATCH 与 DELETE。
fn default_csrf_methods() -> Vec<String> {
    ["POST", "PUT", "PATCH", "DELETE"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// 业务作用：默认只信任与当前请求 scheme 和 authority 相同的浏览器来源。
///
/// 参数说明：无。
///
/// 返回：返回 `same-origin` 唯一规则。
fn default_csrf_allowed_origins() -> Vec<String> {
    vec!["same-origin".to_owned()]
}

/// 业务作用：提供不依赖服务端状态的默认 CSRF token 模式。
///
/// 参数说明：无。
///
/// 返回：返回 `double_submit`。
fn default_csrf_token_mode() -> String {
    "double_submit".to_owned()
}

/// 业务作用：提供符合浏览器 host-only 安全约束的默认 CSRF cookie 名。
///
/// 参数说明：无。
///
/// 返回：返回带 `__Host-` 前缀的固定名称。
fn default_csrf_cookie_name() -> String {
    "__Host-naway-csrf".to_owned()
}

/// 业务作用：提供 CSRF token 回传的默认 header 名。
///
/// 参数说明：无。
///
/// 返回：返回 `x-csrf-token`。
fn default_csrf_header_name() -> String {
    "x-csrf-token".to_owned()
}

/// 业务作用：限制服务端签名 CSRF token 的默认有效期。
///
/// 参数说明：无。
///
/// 返回：返回两小时对应的秒数。
const fn default_csrf_token_ttl_secs() -> u64 {
    2 * 60 * 60
}

/// 业务作用：提供默认的常见自动化声明 header，只把其出现作为可组合信号而非单独身份事实。
///
/// 参数说明：无。
///
/// 返回：返回 Playwright、Puppeteer 与 WebDriver 常用的固定 header 名。
fn default_bot_automation_headers() -> Vec<String> {
    vec![
        "x-playwright".to_owned(),
        "x-puppeteer".to_owned(),
        "webdriver".to_owned(),
    ]
}

/// 业务作用：选择不含凭据且跨请求稳定的默认浏览器指纹字段。
///
/// 参数说明：无。
///
/// 返回：返回 Accept、语言和 Client Hints 的固定 header 名。
fn default_bot_fingerprint_headers() -> Vec<String> {
    vec![
        "accept".to_owned(),
        "accept-language".to_owned(),
        "sec-ch-ua".to_owned(),
        "sec-ch-ua-platform".to_owned(),
    ]
}

/// 业务作用：为单个确定自动化信号设置默认风险分值。
///
/// 参数说明：无。
///
/// 返回：返回 4，使一个强信号默认达到挑战阈值。
const fn default_bot_signal_score() -> u32 {
    4
}

/// 业务作用：为浏览器声明与 header 形态不一致设置较低的组合分值。
///
/// 参数说明：无。
///
/// 返回：返回 2，避免单个弱信号直接阻断。
const fn default_bot_browser_mismatch_score() -> u32 {
    2
}

/// 业务作用：提供 Bot 行为评分的默认挑战门槛。
///
/// 参数说明：无。
///
/// 返回：返回 4。
const fn default_bot_score_threshold() -> u32 {
    4
}

/// 业务作用：提供 Bot 挑战的默认 HTTP 状态。
///
/// 参数说明：无。
///
/// 返回：返回 403。
const fn default_bot_challenge_status() -> u16 {
    403
}

/// 业务作用：提供不暴露 route 或策略细节的默认挑战 realm。
///
/// 参数说明：无。
///
/// 返回：返回固定 realm。
fn default_bot_challenge_realm() -> String {
    "verification-required".to_owned()
}

/// 业务作用：提供可信机器人签名 header 的默认名称。
///
/// 参数说明：无。
///
/// 返回：返回固定小写 header 名。
fn default_bot_signature_header() -> String {
    "x-naway-bot-signature".to_owned()
}

/// 业务作用：提供可信机器人签名时间戳 header 的默认名称。
///
/// 参数说明：无。
///
/// 返回：返回固定小写 header 名。
fn default_bot_timestamp_header() -> String {
    "x-naway-bot-timestamp".to_owned()
}

/// 业务作用：限制可信机器人签名的默认重放时间窗口。
///
/// 参数说明：无。
///
/// 返回：返回 60 秒。
const fn default_bot_signature_skew_secs() -> u64 {
    60
}

/// 业务作用：限制本地或共享限流器为单条 Bot 规则维护的默认客户端基数。
///
/// 参数说明：无。
///
/// 返回：返回十万个活动指纹。
const fn default_bot_max_active_keys() -> usize {
    100_000
}

/// route 级 GeoIP、ASN 与匿名网络策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GeoIpCfg {
    /// GeoIP2/GeoLite2 Country、City 或 Enterprise MMDB；配置国家规则时必填。
    #[serde(default)]
    pub country_database_file: Option<String>,
    /// GeoIP2/GeoLite2 ASN MMDB；配置 ASN 规则时必填。
    #[serde(default)]
    pub asn_database_file: Option<String>,
    /// GeoIP2 Anonymous-IP MMDB；配置匿名网络规则时必填。
    #[serde(default)]
    pub anonymous_database_file: Option<String>,
    /// 允许的 ISO 3166-1 alpha-2 国家代码；非空时形成 allowlist。
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    /// 拒绝的 ISO 3166-1 alpha-2 国家代码。
    #[serde(default)]
    pub denied_countries: Vec<String>,
    /// 允许的 Autonomous System Number；非空时形成 allowlist。
    #[serde(default)]
    pub allowed_asns: Vec<u32>,
    /// 拒绝的 Autonomous System Number。
    #[serde(default)]
    pub denied_asns: Vec<u32>,
    /// 要拒绝的匿名网络 trait 固定名。
    #[serde(default)]
    pub denied_anonymous_traits: Vec<String>,
    /// 规则需要字段但数据库没有该地址记录时的动作：`allow|deny`。
    #[serde(default = "default_geoip_missing_action")]
    pub on_not_found: String,
    /// MMDB 查询或 record 解码失败时的动作：`allow|deny`。
    #[serde(default = "default_geoip_error_action")]
    pub on_lookup_error: String,
    /// 数据库 build epoch 超过允许年龄时的动作：`reject|allow|deny`。
    #[serde(default = "default_geoip_stale_action")]
    pub on_stale: String,
    /// MMDB build epoch 的最大允许年龄；每次候选构建都会重新核对。
    #[serde(default = "default_geoip_database_age_secs")]
    pub max_database_age_secs: u64,
}

/// 业务作用：为 GeoIP 无记录提供故障关闭的默认动作。
///
/// 参数说明：无。
///
/// 返回：返回 `deny`，避免未知地址被伪装成允许国家或 ASN。
fn default_geoip_missing_action() -> String {
    "deny".to_owned()
}

/// 业务作用：为 MMDB 查询或 record 解码失败提供故障关闭的默认动作。
///
/// 参数说明：无。
///
/// 返回：返回 `deny`，使损坏或类型漂移的 record 不会绕过策略。
fn default_geoip_error_action() -> String {
    "deny".to_owned()
}

/// 业务作用：为过期 GeoIP 数据库提供 last-known-good 安全默认。
///
/// 参数说明：无。
///
/// 返回：返回 `reject`，候选换版失败并继续使用上一份有效快照。
fn default_geoip_stale_action() -> String {
    "reject".to_owned()
}

/// 业务作用：为 GeoIP 数据 freshness 设置覆盖常见月度更新周期的默认窗口。
///
/// 参数说明：无。
///
/// 返回：返回 45 天对应的秒数。
const fn default_geoip_database_age_secs() -> u64 {
    45 * 24 * 60 * 60
}

/// 业务作用：为 WAF 提供故障关闭的默认处置模式。
///
/// 参数说明：无。
///
/// 返回：返回 `enforce`，使新增策略默认拦截确定命中的攻击输入。
fn default_waf_mode() -> String {
    "enforce".to_owned()
}

/// 业务作用：约束显式 WAF 请求体慢路径的默认并发内存占用。
///
/// 参数说明：无。
///
/// 返回：返回 1 MiB 请求体聚合上限。
const fn default_waf_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：约束单个 URI、header 或结构化字符串的扫描成本。
///
/// 参数说明：无。
///
/// 返回：返回 64 KiB 单值扫描上限。
const fn default_waf_value_bytes() -> usize {
    64 * 1024
}

/// 业务作用：限制 JSON/XML 解析的默认嵌套深度，避免深层输入耗尽栈或解析预算。
///
/// 参数说明：无。
///
/// 返回：返回 64 层结构化数据深度上限。
const fn default_waf_structured_depth() -> usize {
    64
}

/// 业务作用：限制单个 JSON/XML document 的默认结构规模。
///
/// 参数说明：无。
///
/// 返回：返回十万个结构节点上限。
const fn default_waf_structured_nodes() -> usize {
    100_000
}

/// 业务作用：限制 XML 属性解析总量，防止宽元素制造无界 CPU 消耗。
///
/// 参数说明：无。
///
/// 返回：返回一万个 XML 属性上限。
const fn default_waf_xml_attributes() -> usize {
    10_000
}

/// 业务作用：限制外部 WAF 规则包在候选构建阶段的单文件内存占用。
///
/// 参数说明：无。
///
/// 返回：返回 4 MiB 原始 JSON 上限。
const fn default_waf_rule_pack_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制外部 WAF 规则包可增加的规则扫描规模。
///
/// 参数说明：无。
///
/// 返回：返回 1024 条规则上限。
const fn default_waf_rule_pack_rules() -> usize {
    1024
}

/// 业务作用：限制外部 WAF 规则包可增加的 literal 总量。
///
/// 参数说明：无。
///
/// 返回：返回 16384 个 literal 上限。
const fn default_waf_rule_pack_patterns() -> usize {
    16_384
}

/// 业务作用：为有界 JSON 解析和 literal 索引构建提供确定的默认时间门。
///
/// 参数说明：无。
///
/// 返回：返回 2000 毫秒候选构建上限。
const fn default_waf_rule_pack_compile_ms() -> u64 {
    2_000
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
    /// 发给该 route 后端的命名 header/query 凭据引用。
    #[serde(default)]
    pub upstream_credentials: Vec<String>,
    /// 已完成全局引用和 backend 归属校验的凭据声明，不直接从 YAML 反序列化。
    #[serde(skip)]
    pub(crate) resolved_upstream_credentials: Vec<UpstreamCredentialCfg>,
    /// 是否在普通反向代理时保留下游 Host/authority；Gateway API/Ingress 需要开启，
    /// 手写 nginx 风格 route 默认仍使用上游 authority。
    #[serde(default)]
    pub preserve_host: bool,
    /// Gateway API RequestRedirect；存在时该 route 是终端响应，不允许再声明上游后端。
    #[serde(default)]
    pub gateway_redirect: Option<GatewayRedirectCfg>,
    /// V9 显式 hedged request；只用于固定 `lb://`、GET/HEAD、可证明为空 body 的请求。
    #[serde(default)]
    pub hedge: Option<HedgeCfg>,
    /// V5 请求契约校验。未配置时保持纯流式快路径；body 校验必须携带显式有界上限。
    #[serde(default)]
    pub request_validation: Option<RequestValidationCfg>,
    /// 下游请求实体的声明式有界转换；未配置时请求 body 保持原始流。
    #[serde(default)]
    pub request_transform: Option<BodyTransformCfg>,
    /// 上游响应实体的声明式有界转换；在响应插件之后、契约校验之前执行。
    #[serde(default)]
    pub response_transform: Option<BodyTransformCfg>,
    /// 最终下游响应的 OpenAPI 契约；默认 observe，不会阻断业务响应。
    #[serde(default)]
    pub response_contract: Option<ResponseContractCfg>,
    /// 内置 API WAF。未配置时不扫描 URI/header，也不读取请求体。
    #[serde(default)]
    pub waf: Option<WafCfg>,
    /// 本地 MMDB 驱动的国家、ASN 与匿名网络策略；未配置时不执行任何地址查询。
    #[serde(default)]
    pub geoip: Option<GeoIpCfg>,
    /// 可组合 User-Agent、指纹、行为、速率与签名复验的 Bot 策略。
    #[serde(default)]
    pub bot: Option<BotCfg>,
    /// 浏览器状态变更请求的 Origin/Referer 与双提交或服务端签名 token 门禁。
    #[serde(default)]
    pub csrf: Option<CsrfCfg>,
    /// 请求、响应与 access log path 的 PII/secret 检测、遮蔽或阻断策略。
    #[serde(default)]
    pub dlp: Option<DlpCfg>,
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
    /// Envoy External Processing 双向流；未配置时不编码 protobuf，也不建立扩展服务连接。
    #[serde(default)]
    pub ext_proc: Option<ExtProcCfg>,
    /// InferencePool 数据面约束；只允许 Kubernetes 控制器为已验证的池后端生成。
    #[serde(default)]
    pub inference_pool: Option<InferencePoolRouteCfg>,
    /// V7 BFF 有界扇出聚合。它是终端后端，与 uri/serve/llm/mock 互斥。
    #[serde(default)]
    pub bff_aggregation: Option<BffAggregationCfg>,
    /// HTTP→Dubbo2 generic `$invoke` 终端后端。
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
    /// 双向带宽整形与成本型限额。未配置时该 route 不做任何额外整形,
    /// 保持既有 `limit_rate`/`limit_req` 行为不变。
    #[serde(default)]
    pub traffic_limit: Option<TrafficLimitCfg>,
    /// 受控动态正向代理(HTTP CONNECT)。未配置时该 route 拒绝 CONNECT,
    /// 不存在"默认放行"的形态。
    #[serde(default)]
    pub forward_proxy: Option<ForwardProxyCfg>,
    /// WebTransport 终端代理。客户端 session 只有在整条 route 治理通过且上游 session
    /// 已建立后才会收到成功响应。
    #[serde(default)]
    pub webtransport: Option<WebTransportCfg>,
    /// 允许真实 QUIC 0-RTT 执行本 route。只有可证明无认证副作用的安全方法
    /// 才能开启，且每个 early request 必须携带一次性 nonce。
    #[serde(default)]
    pub early_data: Option<EarlyDataRouteCfg>,
    /// WebSocket 帧级治理。未配置时保持透明隧道,不做任何额外聚合。
    #[serde(default)]
    pub ws_frame: Option<WsFrameCfg>,
    /// V6 AI/LLM 统一 OpenAI-compatible 入口。存在时 route 不再使用顶层 `uri`，而由
    /// `models[]` 声明主模型与有序 fallback 后端。
    #[serde(default)]
    pub llm: Option<LlmRouteCfg>,
    /// V8 gRPC 边缘模式(架构规范 §25.2)。缺省/`enabled: false` 时本 route 保持
    /// Nginx/Envoy 式 L7 透传,一个字节不多碰;显式开启才进入 header 驱动的
    /// subscribe/publish 自响应；命中 edge route 后进入已编译的实时散出数据面。
    #[serde(default)]
    pub grpc_edge: Option<GrpcEdgeCfg>,
    /// 可选 descriptor 驱动 gRPC-JSON/Connect JSON 慢路径。未配置时普通 native gRPC
    /// 不读取 descriptor、不解析 protobuf message，也不增加 reflection 依赖。
    #[serde(default)]
    pub grpc_transcoding: Option<GrpcTranscodingCfg>,
    /// 该 route 的 SSE/gRPC 响应帧间空闲超时(ms)。None 继承 proxy
    /// `timeouts.stream_idle_timeout_ms`；显式 0 表示关闭。
    #[serde(default)]
    pub long_stream_idle_timeout_ms: Option<u64>,
    /// 单次下游 HTTP 请求到完整响应结束的总时限(ms)。None 使用实现默认；Some(0)
    /// 显式关闭。Gateway API HTTPRoute `timeouts.request` 物化到该字段。
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
    /// 单次上游 attempt 从开始发送到完整响应结束的时限(ms)。None 使用实现默认；
    /// Some(0) 显式关闭。Gateway API HTTPRoute `timeouts.backendRequest` 物化到该字段。
    #[serde(default)]
    pub backend_request_timeout_ms: Option<u64>,
    /// 该 route 的 SSE/gRPC 最长存活时间(ms)；0 表示不限制。超时时 gRPC 发
    /// status 14 trailer，SSE 结束 body，两者都释放旧快照与上游连接。
    #[serde(default)]
    pub long_stream_max_lifetime_ms: u64,
    /// 路由优先级(据 review L5 / §4.2):数值【小】者优先;同值按配置书写顺序(SCG 有序语义)。
    /// 用于在 yaml 不便重排时显式定序,如 `/api/admin/**`(order:-10)优先于 `/api/**`(order:0)兜底。
    #[serde(default)]
    pub order: i32,
}

/// InferencePool 后端的请求期 EPP 选择约束。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InferencePoolRouteCfg {
    /// 单次 EPP 决策允许返回的 endpoint 数量上限，防止 header 或 metadata 扩大选择扫描成本。
    #[serde(default = "default_inference_pool_max_selected_endpoints")]
    pub max_selected_endpoints: usize,
}

/// 业务作用：限制 EPP 单次可交给负载均衡器的 endpoint 子集规模。
///
/// 参数说明: 无。
///
/// 返回：默认允许六十四个候选 endpoint。
const fn default_inference_pool_max_selected_endpoints() -> usize {
    64
}

/// route 级 descriptor 驱动 protobuf JSON 转码契约。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcTranscodingCfg {
    /// 受信本地 `FileDescriptorSet` 文件；相对路径以 `gateway.yml` 所在目录解析。
    pub descriptor_set_file: String,
    /// 允许暴露的 protobuf service full name；必须显式列出，空数组会 fail closed。
    pub services: Vec<String>,
    /// 可选 method full name 白名单；空表示允许上述 service 的全部 method。
    #[serde(default)]
    pub methods: Vec<String>,
    /// 是否启用 `google.api.http` path/query/body 映射。
    #[serde(default)]
    pub google_http: bool,
    /// 是否启用 Connect unary/streaming JSON。
    #[serde(default = "default_true")]
    pub connect_json: bool,
    /// JSON 中出现 descriptor 未声明字段时是否拒绝；安全默认不静默丢字段。
    #[serde(default = "default_true")]
    pub reject_unknown_fields: bool,
    /// descriptor 文件有界读取上限。
    #[serde(default = "default_grpc_descriptor_bytes")]
    pub max_descriptor_bytes: usize,
    /// 单条输入 protobuf message 解码后的最大字节数。
    #[serde(default = "default_grpc_input_message_bytes")]
    pub max_input_message_bytes: usize,
    /// 单条输出 protobuf message 解码前允许的最大字节数。
    #[serde(default = "default_grpc_output_message_bytes")]
    pub max_output_message_bytes: usize,
    /// 单条 JSON document 的最大字节数；不能超过对应 protobuf message 上限。
    #[serde(default = "default_grpc_json_bytes")]
    pub max_json_bytes: usize,
    /// 单个 streaming RPC 允许转换的最大消息数，防止无限流永久占用 descriptor 慢路径。
    #[serde(default = "default_grpc_stream_messages")]
    pub max_stream_messages: u64,
    /// 单 stream codec 可保留的未完成 envelope/JSON 字节上限。
    #[serde(default = "default_grpc_stream_buffer_bytes")]
    pub max_stream_buffer_bytes: usize,
}

/// 业务作用：提供 descriptor 文件的默认有界读取预算，避免控制面按文件长度无界分配。
///
/// 参数说明: 无。
///
/// 返回：16 MiB descriptor 上限。
fn default_grpc_descriptor_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：提供单条 gRPC 输入消息的默认转码预算。
///
/// 参数说明: 无。
///
/// 返回：4 MiB 输入消息上限。
fn default_grpc_input_message_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：提供单条 gRPC 输出消息的默认转码预算。
///
/// 参数说明: 无。
///
/// 返回：4 MiB 输出消息上限。
fn default_grpc_output_message_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：提供单条 protobuf JSON document 的默认转码预算。
///
/// 参数说明: 无。
///
/// 返回：4 MiB JSON 上限。
fn default_grpc_json_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制单个长流可转换的消息总数，避免未设业务 deadline 时无限占用慢路径状态。
///
/// 参数说明: 无。
///
/// 返回：默认最多一百万条消息。
fn default_grpc_stream_messages() -> u64 {
    1_000_000
}

/// 业务作用：限制 streaming codec 为跨 DATA frame 拼接保留的未完成数据。
///
/// 参数说明: 无。
///
/// 返回：默认 4 MiB stream 暂存上限。
fn default_grpc_stream_buffer_bytes() -> usize {
    4 * 1024 * 1024
}

/// route 级有界 hedged request 策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HedgeCfg {
    /// 操作者必须显式确认该 route 只承载允许重复执行的业务语义；false 会构建失败。
    #[serde(default)]
    pub idempotent: bool,
    /// 主请求尚未得到成功响应时，启动第二实例副本前的等待时间。
    #[serde(default = "default_hedge_delay_ms")]
    pub delay_ms: u64,
    /// 总 attempt 数；V9 首版固定为 2，避免配置制造扇出风暴。
    #[serde(default = "default_hedge_max_attempts")]
    pub max_attempts: usize,
}

/// 业务作用：提供能吸收常见尾延迟、又不会立即制造双倍请求的默认 hedge 延迟。
///
/// 参数说明：无。
///
/// 返回：默认延迟 25ms。
const fn default_hedge_delay_ms() -> u64 {
    25
}

/// 业务作用：把 V9 首版 hedge 扇出硬限制为一个主请求加一个副本。
///
/// 参数说明：无。
///
/// 返回：固定总 attempt 数 2。
const fn default_hedge_max_attempts() -> usize {
    2
}

/// 一个 route 绑定的 Proxy-Wasm ABI v0.2.1 插件。
///
/// 只有显式选择 request/response body 相位才会进入有界聚合慢路径；header 相位与未配置
/// route 仍保持流式。运行时不挂 WASI，也不给文件、socket 或环境变量能力。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmPluginCfg {
    /// 稳定插件 id，仅用于构建报错和低基数日志。
    pub id: String,
    /// 本地 `.wasm` 文件，相对于 gateway.yml 所在目录；与 `module_source` 必须二选一。
    #[serde(default)]
    pub module_file: String,
    /// 受验证的 HTTPS 或 OCI 远程模块；候选快照构建期获取，不进入请求路径。
    #[serde(default)]
    pub module_source: Option<WasmModuleSourceCfg>,
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
    /// request/response body 相位可聚合、读取和改写的 data 字节上限。
    #[serde(default = "default_wasm_max_body_bytes")]
    pub max_body_bytes: usize,
    /// `proxy_send_local_response` 响应体上限；本地响应是插件唯一可生成的 body。
    #[serde(default = "default_wasm_max_local_response_body_bytes")]
    pub max_local_response_body_bytes: usize,
    /// 客体可使用的固定 HTTP/gRPC callout 上游白名单。
    #[serde(default)]
    pub callout_clusters: Vec<WasmCalloutClusterCfg>,
    /// 单次 invocation 可登记的 callout 总数。
    #[serde(default = "default_wasm_max_callouts")]
    pub max_callouts: usize,
    /// 单个 callout 响应体可进入客体内存的字节上限。
    #[serde(default = "default_wasm_max_callout_response_bytes")]
    pub max_callout_response_bytes: usize,
    /// 固定租户/业务命名空间；运行时叠加 route、插件 id 与模块摘要实现版本隔离。
    #[serde(default)]
    pub shared_namespace: String,
    /// shared-data key 数量硬上限。
    #[serde(default = "default_wasm_max_shared_entries")]
    pub max_shared_entries: usize,
    /// shared data、property 与 queue payload 合计驻留字节硬上限。
    #[serde(default = "default_wasm_max_shared_bytes")]
    pub max_shared_bytes: usize,
    /// 可注册 shared queue 数量硬上限。
    #[serde(default = "default_wasm_max_shared_queues")]
    pub max_shared_queues: usize,
    /// 单条 shared queue 消息数硬上限。
    #[serde(default = "default_wasm_max_queue_entries")]
    pub max_queue_entries: usize,
    /// 可定义内部 metric 数量硬上限。
    #[serde(default = "default_wasm_max_metrics")]
    pub max_metrics: usize,
}

/// Proxy-Wasm 远程制品来源与供应链验证声明。
///
/// `sha256` 固定最终 wasm 原始字节；OCI tag 还必须固定 `manifest_sha256`。远程模块必须
/// 配置 detached Ed25519 signature、签名 in-toto statement，或同时配置两者。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmModuleSourceCfg {
    /// 固定 HTTPS URL，或 `oci://registry/repository:tag|@sha256:...` reference。
    pub reference: String,
    /// 最终 wasm 原始字节的 SHA-256 十六进制摘要。
    pub sha256: String,
    /// OCI manifest 摘要；使用 tag 时必填，使用 digest reference 时可省略但不得冲突。
    #[serde(default)]
    pub manifest_sha256: String,
    /// HTTP Authorization 完整值；支持 SecretSource，不会发送给模块来源以外的目标。
    #[serde(default)]
    pub authorization: String,
    /// 附加 TLS 根证书 PEM；支持 SecretSource，平台根证书仍保留。
    #[serde(default)]
    pub ca_certificate: String,
    /// 内容寻址离线缓存目录；相对路径以 gateway.yml 所在目录解析，空值关闭磁盘缓存。
    #[serde(default)]
    pub cache_dir: String,
    /// connect、response head 与完整 body 共用的固定 deadline。
    #[serde(default = "default_wasm_source_timeout_ms")]
    pub timeout_ms: u64,
    /// detached Ed25519 signature 的 Base64 SecretSource；必须与 `public_key` 同时配置。
    #[serde(default)]
    pub signature: String,
    /// detached signature 对应的 32-byte Ed25519 public key Base64 SecretSource。
    #[serde(default)]
    pub public_key: String,
    /// 可选签名 in-toto statement；存在时同时验证 statement 签名、subject 摘要和 provenance。
    #[serde(default)]
    pub attestation: Option<WasmAttestationCfg>,
}

/// 签名 in-toto Statement v1 的最小可信约束。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmAttestationCfg {
    /// 原始 JSON statement SecretSource；detached signature 精确覆盖这些 UTF-8 字节。
    pub statement: String,
    /// statement detached Ed25519 signature 的 Base64 SecretSource。
    pub signature: String,
    /// statement signer 的 32-byte Ed25519 public key Base64 SecretSource。
    pub public_key: String,
    /// 必须精确匹配 statement `predicateType` 的受信类型。
    pub predicate_type: String,
    /// 必须精确匹配 statement `predicate.builder.id` 的受信构建者身份。
    pub builder_id: String,
    /// 可选 subject name；空值只要求至少一个 subject 的 SHA-256 匹配模块。
    #[serde(default)]
    pub subject_name: String,
}

/// 业务作用：为远程 Wasm 获取提供足够实际部署、又能限制挂起时间的默认 deadline。
///
/// 参数说明：无。
///
/// 返回：默认十秒 deadline。
const fn default_wasm_source_timeout_ms() -> u64 {
    10_000
}

/// Proxy-Wasm callout 的固定上游能力声明。
///
/// 客体只能引用 `name`，不能提供 URL 或直接打开 socket；实际 origin 与 TLS 信任材料在
/// 候选快照构建期固定，从而把网络权限收敛为可审计白名单。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WasmCalloutClusterCfg {
    /// 客体在 `proxy_http_call`/`proxy_grpc_call` 中使用的稳定名称。
    pub name: String,
    /// 固定 `http://` 或 `https://` origin，不允许 path、query、fragment 或 userinfo。
    pub origin: String,
    /// 自定义 CA certificate bundle 的 SecretSource；空时使用平台根证书。
    #[serde(default)]
    pub ca_certificate: String,
    /// 是否显式允许明文 HTTP；默认只接受 HTTPS。
    #[serde(default)]
    pub allow_cleartext: bool,
    /// 对受控明文 origin 强制使用 HTTP/2 prior knowledge；主要用于内网 h2c gRPC 服务。
    #[serde(default)]
    pub http2_prior_knowledge: bool,
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

/// route 绑定的 Envoy External Processing 双向流契约。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExtProcCfg {
    /// `http(s)://host[:port]` 或 `lb://service` 扩展服务。
    pub target: String,
    /// 依赖连接、超时或服务不可用时是否继续；协议拒绝与非法 mutation 永不放行。
    #[serde(default)]
    pub fail_open: bool,
    /// 可选 gRPC Authorization metadata；支持 SecretSource，且不会进入下游可见头。
    #[serde(default)]
    pub authorization: String,
    /// 是否把 request headers 发送给处理器。
    #[serde(default = "default_true")]
    pub request_headers: bool,
    /// 是否把 response headers 发送给处理器。
    #[serde(default = "default_true")]
    pub response_headers: bool,
    /// request body 的传递方式。
    #[serde(default)]
    pub request_body: ExtProcBodyModeCfg,
    /// response body 的传递方式。
    #[serde(default)]
    pub response_body: ExtProcBodyModeCfg,
    /// 是否发送 request trailers。
    #[serde(default)]
    pub request_trailers: bool,
    /// 是否发送 response trailers。
    #[serde(default)]
    pub response_trailers: bool,
    /// 单个 phase 等待匹配响应的 deadline。
    #[serde(default = "default_ext_proc_message_timeout_ms")]
    pub message_timeout_ms: u64,
    /// 整条处理流的总生命周期上限。
    #[serde(default = "default_ext_proc_total_timeout_ms")]
    pub total_timeout_ms: u64,
    /// 单条 protobuf payload 的编码后字节上限。
    #[serde(default = "default_ext_proc_max_message_bytes")]
    pub max_message_bytes: usize,
    /// 一条业务请求在扩展流双向累计传输的字节上限。
    #[serde(default = "default_ext_proc_max_total_bytes")]
    pub max_total_bytes: usize,
    /// buffered body 的聚合上限，也是 streamed body 的累计上限。
    #[serde(default = "default_ext_proc_max_body_bytes")]
    pub max_body_bytes: usize,
    /// 单 route 可同时占用的处理流数量；满额立即执行依赖失败策略。
    #[serde(default = "default_ext_proc_max_in_flight")]
    pub max_in_flight: usize,
    /// 连续依赖失败达到该值后打开 circuit；成功响应会清零。
    #[serde(default = "default_ext_proc_failure_threshold")]
    pub failure_threshold: u32,
    /// circuit 打开后允许下一次探测前的冷却时间。
    #[serde(default = "default_ext_proc_reset_timeout_ms")]
    pub reset_timeout_ms: u64,
    /// 处理器可 set/remove 的普通 header allowlist。
    #[serde(default)]
    pub mutation_headers: Vec<String>,
    /// 允许写入当前请求动态 metadata 的顶层 namespace allowlist。
    #[serde(default)]
    pub writable_metadata_namespaces: Vec<String>,
}

/// External Processing body 的交付模式。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExtProcBodyModeCfg {
    /// 不发送 body，也不允许 body mutation。
    #[default]
    None,
    /// 聚合到显式上限后发送单条完整 body。
    Buffered,
    /// 按原始 DATA frame 顺序发送，并逐条等待匹配响应形成背压。
    Streamed,
}

/// 业务作用：限制扩展处理器单个 phase 占用请求任务的时间。
///
/// 参数说明：无。
///
/// 返回：默认 200ms。
const fn default_ext_proc_message_timeout_ms() -> u64 {
    200
}

/// 业务作用：限制一条 External Processing 双向流的总生命周期。
///
/// 参数说明：无。
///
/// 返回：默认 30 秒。
const fn default_ext_proc_total_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：限制单条 protobuf 消息，避免处理器制造超大分配。
///
/// 参数说明：无。
///
/// 返回：默认 1 MiB。
const fn default_ext_proc_max_message_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制单请求扩展流的双向累计流量。
///
/// 参数说明：无。
///
/// 返回：默认 16 MiB。
const fn default_ext_proc_max_total_bytes() -> usize {
    16 * 1024 * 1024
}

/// 业务作用：限制显式进入扩展处理路径的业务实体总量。
///
/// 参数说明：无。
///
/// 返回：默认 8 MiB。
const fn default_ext_proc_max_body_bytes() -> usize {
    8 * 1024 * 1024
}

/// 业务作用：为单 route 提供有界 External Processing 在途预算。
///
/// 参数说明：无。
///
/// 返回：默认 64 条并发流。
const fn default_ext_proc_max_in_flight() -> usize {
    64
}

/// 业务作用：限制依赖连续失败后仍继续尝试建流的次数。
///
/// 参数说明：无。
///
/// 返回：默认连续五次失败后打开 circuit。
const fn default_ext_proc_failure_threshold() -> u32 {
    5
}

/// 业务作用：为已打开的扩展依赖 circuit 提供有界恢复探测间隔。
///
/// 参数说明：无。
///
/// 返回：默认一秒。
const fn default_ext_proc_reset_timeout_ms() -> u64 {
    1_000
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
    /// wire serialization；`json` 使用 id=6，`hessian2` 使用 id=2 且需要对应制品 feature。
    #[serde(default)]
    pub serialization: DubboSerializationCfg,
    /// 下游 JSON body 上限。
    #[serde(default = "default_dubbo_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
    /// 编码后 Dubbo request frame body 上限，独立约束序列化膨胀。
    #[serde(default = "default_dubbo_max_request_frame_bytes")]
    pub max_request_frame_bytes: usize,
    /// Dubbo response frame body 上限。
    #[serde(default = "default_dubbo_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    /// Hessian2 单值最大字符串 UTF-8 字节数。
    #[serde(default = "default_dubbo_max_hessian_string_bytes")]
    pub max_hessian_string_bytes: usize,
    /// Hessian2 单值最大 binary 字节数；HTTP JSON 使用标准 Base64 表示 binary。
    #[serde(default = "default_dubbo_max_hessian_binary_bytes")]
    pub max_hessian_binary_bytes: usize,
    /// Hessian2 单 frame 可遍历的 collection/object 字段总数。
    #[serde(default = "default_dubbo_max_hessian_collection_items")]
    pub max_hessian_collection_items: usize,
    /// Hessian2 collection/object 最大递归深度。
    #[serde(default = "default_dubbo_max_hessian_depth")]
    pub max_hessian_depth: usize,
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
    /// Dubbo serialization id 2；使用 provider 默认 Hessian2 泛化调用协议。
    Hessian2,
}

/// 业务作用：提供下游 Dubbo JSON envelope 的保守默认字节门。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 请求体上限。
const fn default_dubbo_max_request_body_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：提供序列化后 Dubbo request frame 的独立默认上限，隔离编码膨胀。
///
/// 参数说明: 无。
///
/// 返回：返回 4 MiB frame body 上限。
const fn default_dubbo_max_request_frame_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：提供 Dubbo response frame 的默认读取硬门。
///
/// 参数说明: 无。
///
/// 返回：返回 4 MiB frame body 上限。
const fn default_dubbo_max_response_body_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制单个 Hessian2 字符串的默认 UTF-8 字节数。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 单字符串上限。
const fn default_dubbo_max_hessian_string_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制单个 Hessian2 binary 的默认真实字节数。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB 单 binary 上限。
const fn default_dubbo_max_hessian_binary_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制单个 Hessian2 frame 内 collection/object 的默认累计元素数。
///
/// 参数说明: 无。
///
/// 返回：返回 65,536 个元素的累计上限。
const fn default_dubbo_max_hessian_collection_items() -> usize {
    65_536
}

/// 业务作用：限制 Hessian2 collection/object 的默认递归深度。
///
/// 参数说明: 无。
///
/// 返回：返回 32 层递归上限。
const fn default_dubbo_max_hessian_depth() -> usize {
    32
}

/// 业务作用：提供 Dubbo TCP 建连的默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 1000 毫秒。
const fn default_dubbo_connect_timeout_ms() -> u64 {
    1000
}

/// 业务作用：提供一次 Dubbo 写入与完整响应读取的默认总 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 3000 毫秒。
const fn default_dubbo_request_timeout_ms() -> u64 {
    3000
}

/// 业务作用：提供每个 Dubbo endpoint 的默认空闲连接容量。
///
/// 参数说明: 无。
///
/// 返回：返回 8 条空闲连接。
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

/// Proxy-Wasm HTTP 回调相位。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WasmPluginPhaseCfg {
    /// 认证与 OPA 通过后、请求体校验/限流/上游前。
    RequestHeaders,
    /// 请求头插件提交后、外部策略与上游转发前；显式有界聚合完整请求 body。
    RequestBody,
    /// 请求 body 逐 DATA frame 回调；每次只暴露当前 frame，并以 body poll 自然施加背压。
    RequestBodyStream,
    /// 内部跳转与 error_page 完成后、压缩/限速前。
    ResponseHeaders,
    /// 响应头插件提交后、压缩/限速前；显式有界聚合完整响应 body。
    ResponseBody,
    /// 响应 body 逐 DATA frame 回调；不聚合完整响应，适合长流与无限流。
    ResponseBodyStream,
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

const fn default_wasm_max_body_bytes() -> usize {
    1024 * 1024
}

const fn default_wasm_max_local_response_body_bytes() -> usize {
    64 * 1024
}

/// 业务作用：限制单次 Proxy-Wasm invocation 可登记的异步 callout 数量，避免客体制造出站扇出。
///
/// 参数说明: 无。
///
/// 返回：默认最多 4 个受控 callout。
const fn default_wasm_max_callouts() -> usize {
    4
}

/// 业务作用：限制单个 callout 响应可进入客体内存的字节数。
///
/// 参数说明: 无。
///
/// 返回：默认 1 MiB 响应上限。
const fn default_wasm_max_callout_response_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制插件命名空间内可同时存在的 shared-data key 数量。
///
/// 参数说明: 无。
///
/// 返回：默认 1024 个条目。
const fn default_wasm_max_shared_entries() -> usize {
    1024
}

/// 业务作用：限制插件命名空间内 shared data、property 与 queue payload 的合计驻留字节。
///
/// 参数说明: 无。
///
/// 返回：默认 4 MiB 驻留上限。
const fn default_wasm_max_shared_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：限制单个插件命名空间可注册的 shared queue 数量。
///
/// 参数说明: 无。
///
/// 返回：默认 64 条队列。
const fn default_wasm_max_shared_queues() -> usize {
    64
}

/// 业务作用：限制单条 shared queue 的待消费消息数，防止慢消费者造成无界堆积。
///
/// 参数说明: 无。
///
/// 返回：默认 1024 条消息。
const fn default_wasm_max_queue_entries() -> usize {
    1024
}

/// 业务作用：限制插件可定义的内部 metric 数量，控制指标名称基数。
///
/// 参数说明: 无。
///
/// 返回：默认 256 个 metric。
const fn default_wasm_max_metrics() -> usize {
    256
}

/// 路由级 AI/LLM 代理配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmRouteCfg {
    /// 下游与上游共同使用的独立 API 契约；不同类型不会经 Chat Completions 适配器转换。
    #[serde(default)]
    pub api_type: LlmApiTypeCfg,
    /// 可接受的 JSON 请求体硬上限；LLM 格式转换需要显式有界缓冲。
    #[serde(default = "default_llm_max_body_bytes")]
    pub max_body_bytes: u64,
    /// tokenizer-independent prompt 估算硬上限；超出在调用模型前返回 413。
    #[serde(default = "default_llm_max_prompt_tokens")]
    pub max_prompt_tokens: u64,
    /// completion 允许上限；请求未声明 `max_tokens` 时也会注入该值，防无限输出。
    #[serde(default = "default_llm_max_completion_tokens")]
    pub max_completion_tokens: u64,
    /// 非流式 provider response 聚合硬上限；SSE/JSONL 使用累计字节门，Realtime 用作单消息硬门。
    #[serde(default = "default_llm_max_response_bytes")]
    pub max_response_bytes: u64,
    /// SSE、JSONL 或 WebSocket 单帧硬上限。
    #[serde(default = "default_llm_max_stream_frame_bytes")]
    pub max_stream_frame_bytes: u64,
    /// 单次 provider 请求或长连接最长持续时间；到期停止转发，单位毫秒。
    #[serde(default = "default_llm_max_duration_ms")]
    pub max_duration_ms: u64,
    /// 请求可选择模型的估算费用上限，单位微美元；`u64::MAX` 保留兼容的仅观测模式，
    /// 其它值在价格未知或估算超限时于 provider I/O 前拒绝。
    #[serde(default = "default_llm_max_cost_microusd")]
    pub max_cost_microusd: u64,
    /// 可选共享 token 配额；一次原子预留 prompt 估算 + completion 上限。
    #[serde(default)]
    pub token_quota: Option<LlmTokenQuotaCfg>,
    /// Prompt 注入/越权短语护栏。
    #[serde(default)]
    pub guardrails: LlmGuardrailsCfg,
    /// 可选外部 OpenAI-compatible moderation；在缓存、配额预留和模型调用前执行。
    #[serde(default)]
    pub moderation: Option<LlmModerationCfg>,
    /// 可选精确 + embedding 语义缓存。未配置时不会计算缓存键、聚合额外响应或访问 Redis。
    #[serde(default)]
    pub semantic_cache: Option<LlmSemanticCacheCfg>,
    /// 多模型首选策略；无论策略如何，连接错误/超时/5xx 仍按剩余模型降级。
    #[serde(default)]
    pub selection: LlmSelectionCfg,
    /// 依次尝试的模型；首项是主模型，后续项只在连接错误、超时或 5xx 时 fallback。
    pub models: Vec<LlmModelCfg>,
}

/// AI route 的 wire/API 类型；每个变体拥有独立 content-type、流协议与预算语义。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmApiTypeCfg {
    /// OpenAI Chat Completions JSON/SSE。
    #[default]
    ChatCompletions,
    /// OpenAI Responses JSON/SSE。
    Responses,
    /// 向量 embedding JSON。
    Embeddings,
    /// 文档重排 JSON。
    Rerank,
    /// 图片生成或编辑；JSON 或 route 固定的 multipart 原生请求。
    Image,
    /// 语音生成、转写或翻译；JSON 或 route 固定的 multipart 原生请求。
    Audio,
    /// 视频生成；JSON 或 route 固定的 multipart 原生请求。
    Video,
    /// 异步批处理 JSON。
    Batch,
    /// 文件上传/读取原生协议。
    File,
    /// WebSocket Realtime 双向事件协议。
    Realtime,
}

/// 外部 OpenAI-compatible moderation 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmModerationCfg {
    /// moderation 服务地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// moderation model 名称，例如 `omni-moderation-latest`；必须显式配置以保持策略可审计。
    pub model: String,
    /// API path；空时使用 `/v1/moderations`。
    #[serde(default)]
    pub path: String,
    /// provider API key SecretSource；空表示不注入凭据。
    #[serde(default)]
    pub api_key: String,
    /// 一次 moderation 调用总超时(ms)。
    #[serde(default = "default_llm_moderation_timeout_ms")]
    pub timeout_ms: u64,
    /// 序列化 moderation request 的硬上限。
    #[serde(default = "default_llm_moderation_max_request_bytes")]
    pub max_request_bytes: u64,
    /// moderation response 的聚合硬上限。
    #[serde(default = "default_llm_moderation_max_response_bytes")]
    pub max_response_bytes: u64,
    /// 依赖超时、非 2xx 或坏响应时的 `closed|open` 策略；明确 flagged 永远拒绝。
    #[serde(default)]
    pub fail_mode: LlmModerationFailModeCfg,
}

/// 外部 moderation 依赖失败策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmModerationFailModeCfg {
    /// 依赖不可判定时拒绝模型请求，安全优先。
    #[default]
    Closed,
    /// 仅依赖故障时继续；明确 `flagged=true` 仍拒绝。
    Open,
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

/// 单个 AI 模型后端。route 的 `api_type` 冻结 wire 契约；只有显式支持无损转换的 Chat
/// provider adapter 会重写实体，其它 API 保持 provider 原生协议。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LlmModelCfg {
    /// 配置内稳定、低基数模型 id，用于 metrics/日志；不接受请求动态值。
    pub id: String,
    /// 固定 wire provider；可选值由 `LlmProviderCfg` 定义，不能由请求动态选择。
    pub provider: LlmProviderCfg,
    /// 模型后端地址，支持 `http(s)://` 与 `lb://service`。
    pub uri: String,
    /// 发给 provider 的真实模型名。
    pub model: String,
    /// provider API path；空时使用 provider 安全默认值。
    #[serde(default)]
    pub path: String,
    /// Google SSE API path；空时由 `model` 生成
    /// `/v1beta/models/{model}:streamGenerateContent?alt=sse`。其它 provider 必须留空。
    #[serde(default)]
    pub stream_path: String,
    /// provider API key SecretSource；空表示不注入凭据，适合本地 vLLM/Ollama。
    #[serde(default)]
    pub api_key: String,
    /// 远程 Secret provider 在候选构建期物化的 API key；不参与配置序列化。
    #[serde(skip, default)]
    pub resolved_api_key: Option<String>,
    /// Anthropic API 版本；OpenAI provider 必须留空。
    #[serde(default)]
    pub anthropic_version: String,
    /// Azure API 版本或其它 provider 明确版本；会进入固定 path/query，客户端不能覆盖。
    #[serde(default)]
    pub api_version: String,
    /// 云 provider 固定 region；Bedrock SigV4 scope 与 Vertex endpoint 均由此字段冻结。
    #[serde(default)]
    pub region: String,
    /// Vertex AI 固定 project；只用于构建可信 API path。
    #[serde(default)]
    pub project: String,
    /// AWS access key id SecretSource；仅 Bedrock SigV4 使用。
    #[serde(default)]
    pub aws_access_key_id: String,
    /// 远程 Secret provider 在候选构建期物化的 AWS access key id。
    #[serde(skip, default)]
    pub resolved_aws_access_key_id: Option<String>,
    /// AWS secret access key SecretSource；仅 Bedrock SigV4 使用。
    #[serde(default)]
    pub aws_secret_access_key: String,
    /// 远程 Secret provider 在候选构建期物化的 AWS secret access key。
    #[serde(skip, default)]
    pub resolved_aws_secret_access_key: Option<String>,
    /// AWS 临时 session token SecretSource；仅 Bedrock SigV4 使用，可为空。
    #[serde(default)]
    pub aws_session_token: String,
    /// 远程 Secret provider 在候选构建期物化的 AWS session token。
    #[serde(skip, default)]
    pub resolved_aws_session_token: Option<String>,
    /// 组合云凭据的最早有效截止点；reload 调度不得让其中任一项过期后继续使用旧快照。
    #[serde(skip, default)]
    pub resolved_not_after: Option<std::time::Instant>,
    /// 是否直接使用 provider 原生 request/response，不执行跨 provider 字段转换。
    #[serde(default)]
    pub native_passthrough: bool,
    /// 每百万 prompt token 的微美元成本，用于低基数成本观测；0 表示未知。
    #[serde(default)]
    pub input_cost_microusd_per_million: u64,
    /// 每百万 completion token 的微美元成本；0 表示未知。
    #[serde(default)]
    pub output_cost_microusd_per_million: u64,
    /// image/audio/video/batch/file 等非 token 计价请求的保守固定费用，单位微美元。
    #[serde(default)]
    pub fixed_cost_microusd: u64,
    /// 此模型提供的固定能力标签，如 `multimodal`、`tools`、`structured_output`、加速器、
    /// 拓扑位置、prefix-cache、队列或 LoRA 状态；只接受安全 ASCII token。
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// 冻结 catalog 中的预期首 token 延迟；joint 策略在运行样本不足时使用，单位毫秒。
    #[serde(default)]
    pub expected_first_token_latency_ms: u64,
    /// `selection.strategy=weighted` 的相对权重；0 表示不参与首选但仍可作为 fallback。
    #[serde(default = "default_llm_model_weight")]
    pub weight: u32,
}

/// 多模型选择策略。required_capabilities 在所有策略前先过滤不满足能力的模型。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct LlmSelectionCfg {
    /// `ordered` / `cost` / `latency` / `weighted` / `joint`。
    #[serde(default)]
    pub strategy: LlmSelectionStrategyCfg,
    /// route 固定要求的能力集合，最多 16 项。
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// joint 策略的软偏好能力；命中项越多，语义得分越高。
    #[serde(default)]
    pub preferred_capabilities: Vec<String>,
    /// joint 策略允许的首 token 延迟上界；模型声明值或运行 EWMA 超过时不作为首选。
    #[serde(default)]
    pub max_first_token_latency_ms: u64,
    /// 可选 shadow 模型 id；只接收按比例采样的副本，结果永不进入主响应或 fallback。
    #[serde(default)]
    pub shadow_model: String,
    /// shadow 采样万分比，范围 0..=10000。
    #[serde(default)]
    pub shadow_basis_points: u16,
    /// 灰度候选模型 id；命中采样时提升为首选，失败仍回落到正常模型顺序。
    #[serde(default)]
    pub rollout_model: String,
    /// 灰度请求万分比，范围 0..=10000。
    #[serde(default)]
    pub rollout_basis_points: u16,
}

/// 模型首选排序策略。
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
    /// 同时按能力、SLO、估算费用和本进程语义亲和度计算首选顺序。
    Joint,
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

/// LLM 模型协议适配器。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProviderCfg {
    /// OpenAI Chat Completions 兼容协议，也用于 vLLM/Ollama 的兼容入口。
    Openai,
    /// Anthropic Messages API。
    Anthropic,
    /// Google Gemini Developer API `generateContent` / `streamGenerateContent`。
    Google,
    /// Azure OpenAI / Microsoft Foundry OpenAI-compatible API。
    AzureOpenai,
    /// AWS Bedrock 原生或 OpenAI-compatible API。
    Bedrock,
    /// Google Vertex AI Gemini API。
    VertexAi,
    /// Cohere v2 native API。
    Cohere,
    /// Mistral API。
    Mistral,
    /// Hugging Face Inference Providers / Endpoint API。
    HuggingFace,
    /// xAI API。
    Xai,
    /// Alibaba Cloud Model Studio / DashScope API。
    Dashscope,
    /// DeepSeek OpenAI-compatible API。
    Deepseek,
    /// Ollama native 或 OpenAI-compatible API。
    Ollama,
    /// vLLM native/OpenAI-compatible API。
    Vllm,
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

fn default_llm_max_response_bytes() -> u64 {
    16 * 1024 * 1024
}

fn default_llm_max_stream_frame_bytes() -> u64 {
    1024 * 1024
}

fn default_llm_max_duration_ms() -> u64 {
    120_000
}

fn default_llm_max_cost_microusd() -> u64 {
    u64::MAX
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

fn default_llm_moderation_timeout_ms() -> u64 {
    2_000
}

fn default_llm_moderation_max_request_bytes() -> u64 {
    1024 * 1024
}

fn default_llm_moderation_max_response_bytes() -> u64 {
    1024 * 1024
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

/// 路由级 OpenAPI 响应契约配置。
///
/// schema 在候选快照构建期按 operation、status 和 media type 全部编译。`observe`
/// 以透传包装体记录结果；`block` 与 `replace_error` 才会在写下游前有界收集实体。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResponseContractCfg {
    /// OpenAPI 3 JSON/YAML 文件；路径相对主配置目录解析。
    pub openapi_file: String,
    /// OpenAPI operationId；与 `operation_path` + `operation_method` 二选一。
    #[serde(default)]
    pub operation_id: Option<String>,
    /// OpenAPI path template；与 `operation_method` 成对。
    #[serde(default)]
    pub operation_path: Option<String>,
    /// OpenAPI method；与 `operation_path` 成对。
    #[serde(default)]
    pub operation_method: Option<String>,
    /// 响应不符合契约时的动作；缺省只观察。
    #[serde(default)]
    pub mode: ResponseContractModeCfg,
    /// 可检查的实体字节上限，必须在 1..=16MiB 内显式设置。
    pub max_body_bytes: u64,
    /// `replace_error` 使用的固定状态码。
    #[serde(default = "default_response_contract_replacement_status")]
    pub replacement_status: u16,
    /// `replace_error` 使用的固定低敏响应文本。
    #[serde(default = "default_response_contract_replacement_body")]
    pub replacement_body: String,
    /// 显式受信本地 schema catalog；只有列出的文档才允许被外部 `$ref` 引用。
    #[serde(default)]
    pub catalog_files: Vec<String>,
    /// 显式 HTTPS schema registry 文档；URL、摘要和 detached 签名共同冻结内容身份。
    #[serde(default)]
    pub registry_documents: Vec<SchemaRegistryDocumentCfg>,
}

/// 一个可进入响应契约 catalog 的签名 HTTPS schema 文档。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SchemaRegistryDocumentCfg {
    /// 固定 HTTPS URL，不允许 redirect 或运行期派生 authority。
    pub url: String,
    /// 原始响应字节的 SHA-256 十六进制摘要。
    pub sha256: String,
    /// detached Ed25519 signature SecretSource，内容为 Base64。
    pub signature: String,
    /// Ed25519 public key SecretSource，内容为 32-byte Base64。
    pub public_key: String,
    /// 可选自定义 CA PEM 文件，路径相对主配置目录解析。
    #[serde(default)]
    pub ca_file: Option<String>,
    /// 单文档响应硬上限。
    #[serde(default = "default_schema_registry_max_bytes")]
    pub max_bytes: usize,
    /// 单次 HTTPS 请求总 deadline。
    #[serde(default = "default_schema_registry_timeout_ms")]
    pub timeout_ms: u64,
    /// 已验签进程内缓存的最长复用时间。
    #[serde(default = "default_schema_registry_cache_ttl_ms")]
    pub cache_ttl_ms: u64,
}

/// 响应契约不符合时的数据面动作。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseContractModeCfg {
    /// 原响应立即透传，在流结束后记录校验结论。
    #[default]
    Observe,
    /// 写下游前完成有界校验，不符合契约时返回固定 502。
    Block,
    /// 写下游前完成有界校验，不符合契约时返回配置的低敏错误响应。
    ReplaceError,
}

/// 声明式实体转换配置。
///
/// JSON 操作只接受精确 JSON Pointer，不支持 wildcard 或脚本。XML/SOAP 输入先按
/// namespace-aware 路径提取为 JSON，输出则从 JSON Pointer 映射到固定 XML 元素路径。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BodyTransformCfg {
    /// 输入实体格式。
    #[serde(default)]
    pub input: BodyFormatCfg,
    /// 输出实体格式。
    #[serde(default)]
    pub output: BodyFormatCfg,
    /// 输入实体的聚合硬上限，必须在 1..=16MiB 内。
    pub max_body_bytes: u64,
    /// 序列化后实体的硬上限，必须在 1..=16MiB 内。
    pub max_output_bytes: u64,
    /// 对中间 JSON 值按声明顺序执行的确定性字段操作。
    #[serde(default)]
    pub operations: Vec<JsonTransformOperationCfg>,
    /// XML prefix 到 namespace URI 的固定映射。
    #[serde(default)]
    pub namespaces: std::collections::BTreeMap<String, String>,
    /// XML/SOAP 输入到中间 JSON 的精确字段映射。
    #[serde(default)]
    pub xml_extract: Vec<XmlFieldMappingCfg>,
    /// 中间 JSON 到 XML/SOAP 输出的固定结构。
    #[serde(default)]
    pub xml_emit: Option<XmlEmitCfg>,
    /// SOAP 输入必须匹配或 SOAP 输出需要设置的固定 SOAPAction。
    #[serde(default)]
    pub soap_action: Option<String>,
    /// SOAP Fault 命中时修改 HTTP status 的固定映射，仅响应转换可用。
    #[serde(default)]
    pub soap_fault: Option<SoapFaultMappingCfg>,
    /// XML 最大元素深度。
    #[serde(default = "default_transform_xml_depth")]
    pub max_xml_depth: usize,
    /// XML 最大节点事件数。
    #[serde(default = "default_transform_xml_nodes")]
    pub max_xml_nodes: usize,
    /// 单元素最大属性数。
    #[serde(default = "default_transform_xml_attributes")]
    pub max_xml_attributes: usize,
    /// XML 文本总字节上限。
    #[serde(default = "default_transform_xml_text_bytes")]
    pub max_xml_text_bytes: usize,
}

/// 实体转换支持的受限格式。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BodyFormatCfg {
    /// JSON 或 `application/*+json`。
    #[default]
    Json,
    /// 普通 XML。
    Xml,
    /// SOAP 1.1/1.2 envelope。
    Soap,
}

/// 中间 JSON 值上的确定性字段操作。
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum JsonTransformOperationCfg {
    /// 把现有字段移动到新位置；目标必须尚不存在。
    Rename { from: String, to: String },
    /// 在尚不存在的位置增加固定值。
    Add {
        path: String,
        value: serde_json::Value,
    },
    /// 删除现有字段；字段不存在时保持幂等。
    Remove { path: String },
    /// 只在字段不存在时写入固定默认值。
    Default {
        path: String,
        value: serde_json::Value,
    },
    /// 要求字段存在且属于指定 JSON 类型。
    TypeCheck {
        path: String,
        expected: JsonValueTypeCfg,
    },
}

/// JSON 字段类型约束。
#[derive(Debug, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JsonValueTypeCfg {
    Null,
    Boolean,
    Number,
    Integer,
    String,
    Array,
    Object,
}

/// XML/SOAP 输入字段到中间 JSON Pointer 的映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct XmlFieldMappingCfg {
    /// namespace-aware 元素路径，例如 `/soap:Envelope/soap:Body/m:Get/m:id`。
    pub from: String,
    /// 中间 JSON 的精确 JSON Pointer。
    pub to: String,
    /// 路径未命中时是否拒绝本次转换。
    #[serde(default)]
    pub required: bool,
    /// 提取文本需要转换成的 JSON 类型；缺省为 string。
    #[serde(default)]
    pub value_type: XmlValueTypeCfg,
}

/// XML 文本到 JSON 值的受限转换类型。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XmlValueTypeCfg {
    #[default]
    String,
    Integer,
    Number,
    Boolean,
}

/// XML/SOAP 输出的固定根和字段映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct XmlEmitCfg {
    /// 输出根元素的 QName；SOAP 输出时这是 Body 内的业务根元素。
    pub root: String,
    /// 中间 JSON Pointer 到输出元素路径的映射。
    #[serde(default)]
    pub fields: Vec<XmlEmitFieldCfg>,
}

/// 中间 JSON 字段到固定 XML 元素路径的映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct XmlEmitFieldCfg {
    /// 中间 JSON 的精确 JSON Pointer。
    pub from: String,
    /// 相对 `xml_emit.root` 的 QName 路径，使用 `/` 分隔。
    pub to: String,
    /// 输入字段不存在时是否拒绝转换。
    #[serde(default)]
    pub required: bool,
}

/// SOAP Fault 到 HTTP 状态的固定映射。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SoapFaultMappingCfg {
    /// namespace-aware Fault 元素路径。
    pub path: String,
    /// Fault 命中后写入的 HTTP 状态码。
    pub status: u16,
}

/// 业务作用：提供响应契约替换错误的安全默认状态，避免无配置时伪装成上游成功。
///
/// 参数说明：无。
///
/// 返回：返回 502。
const fn default_response_contract_replacement_status() -> u16 {
    502
}

/// 业务作用：为远端 schema 文档设置单次读取上限，限制控制面候选内存。
///
/// 参数说明：无。
///
/// 返回：返回 1 MiB 默认上限。
const fn default_schema_registry_max_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：为显式 HTTPS schema registry 设置有限请求 deadline。
///
/// 参数说明：无。
///
/// 返回：返回 3000 毫秒默认值。
const fn default_schema_registry_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：限制已验签 schema 缓存复用时间，使远端撤换在下一次候选构建时可重新取证。
///
/// 参数说明：无。
///
/// 返回：返回 60000 毫秒默认值。
const fn default_schema_registry_cache_ttl_ms() -> u64 {
    60_000
}

/// 业务作用：提供不暴露 schema、字段名或上游实体的固定替换错误文本。
///
/// 参数说明：无。
///
/// 返回：返回稳定的低敏错误消息。
fn default_response_contract_replacement_body() -> String {
    "upstream response does not satisfy contract".to_string()
}

/// 业务作用：限制 XML 转换的默认嵌套层级，避免深层文档放大解析栈和路径状态。
///
/// 参数说明：无。
///
/// 返回：返回 64 层默认上限。
const fn default_transform_xml_depth() -> usize {
    64
}

/// 业务作用：限制单次 XML 转换处理的节点事件总量。
///
/// 参数说明：无。
///
/// 返回：返回 100000 个事件默认上限。
const fn default_transform_xml_nodes() -> usize {
    100_000
}

/// 业务作用：限制单元素属性数量，避免属性洪泛消耗解析资源。
///
/// 参数说明：无。
///
/// 返回：返回 128 个属性默认上限。
const fn default_transform_xml_attributes() -> usize {
    128
}

/// 业务作用：限制 XML 文本累计字节，避免小结构携带超大文本绕过节点预算。
///
/// 参数说明：无。
///
/// 返回：返回 16 MiB 默认上限。
const fn default_transform_xml_text_bytes() -> usize {
    16 * 1024 * 1024
}

/// V7 route 级 GraphQL 查询深度/复杂度守卫。
///
/// 支持 GraphQL-over-HTTP GET/JSON/raw query、multipart upload，以及显式放行的
/// `graphql-transport-ws`/legacy `graphql-ws` 透明升级。degraphql 是独立的固定查询映射。
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
    /// 是否允许 GraphQL WebSocket subscription transport 透明转发。
    ///
    /// WebSocket 消息不会被本 HTTP query guard 重写或拆包；开启表示上游 GraphQL server
    /// 负责每条 subscription 的解析/复杂度门，网关仍执行握手前 auth/rate/连接预算。
    #[serde(default)]
    pub allow_websocket_subscriptions: bool,
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
            allow_websocket_subscriptions: false,
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

/// Route 级 OPA decision 配置。
///
/// 默认调用 OPA Data API；`engine=embedded` 时从签名 bundle 构建本地 Rego 引擎。
/// request body 与完整 JWT claims 都必须在 `input` 中显式开启，未开启时保持 head-only 流式路径。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaAuthorizationCfg {
    /// 求值引擎；默认 external。
    #[serde(default)]
    pub engine: OpaEngineCfg,
    /// OPA 上游 base：`http(s)://host[:port]` 或 `lb://service`。
    #[serde(default)]
    pub target: String,
    /// OPA Data API 路径，例如 `/v1/data/gateway/authz`；必须显式填写。
    #[serde(default)]
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
    /// 可选签名标准 OPA bundle；embedded 引擎必须配置。
    #[serde(default)]
    pub bundle: Option<OpaBundleCfg>,
    /// 输入扩展；默认不读取 body、不暴露完整 claims。
    #[serde(default)]
    pub input: OpaInputCfg,
    /// OPA allow 结果可携带的受控副作用。
    #[serde(default)]
    pub obligations: OpaObligationsCfg,
    /// 外部依赖首次失败后的退避，毫秒。
    #[serde(default = "default_opa_backoff_initial_ms")]
    pub backoff_initial_ms: u64,
    /// 外部依赖连续失败的最大退避，毫秒。
    #[serde(default = "default_opa_backoff_max_ms")]
    pub backoff_max_ms: u64,
}

/// OPA 求值引擎。
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpaEngineCfg {
    /// 通过 HTTP 调用独立 OPA。
    #[default]
    External,
    /// 在进程内执行签名 bundle 中的 Rego。
    Embedded,
}

/// 签名 OPA bundle 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaBundleCfg {
    /// 本地 `.tar.gz` bundle；相对主配置目录解析并纳入 dependency watcher。
    pub source: String,
    /// detached Ed25519 signature 的 Base64 SecretSource，签名覆盖压缩 bundle 原始字节。
    pub signature: String,
    /// 32 字节 Ed25519 public key 的 Base64 SecretSource。
    pub public_key: String,
    /// Rego query，例如 `data.gateway.authz`。
    #[serde(default = "default_opa_bundle_query")]
    pub query: String,
    /// 压缩 bundle 最大字节数。
    #[serde(default = "default_opa_bundle_max_bytes")]
    pub max_bundle_bytes: usize,
    /// 所有 archive regular file 解压后累计最大字节数。
    #[serde(default = "default_opa_bundle_max_expanded_bytes")]
    pub max_expanded_bytes: usize,
    /// archive regular file 数量硬上限。
    #[serde(default = "default_opa_bundle_max_files")]
    pub max_files: usize,
}

/// OPA request input 显式扩展。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaInputCfg {
    /// 是否把完整请求 body 加入 input 并原样重放给后续管线。
    #[serde(default)]
    pub include_body: bool,
    /// body 聚合硬上限。
    #[serde(default = "default_opa_input_max_body_bytes")]
    pub max_body_bytes: usize,
    /// 可聚合的 Content-Type allowlist；按去参数 media type 精确匹配。
    #[serde(default = "default_opa_input_content_types")]
    pub content_types: Vec<String>,
    /// 是否加入网关已经验签、时效与 issuer/audience 均通过的完整 JWT claims。
    #[serde(default)]
    pub include_jwt_claims: bool,
}

impl Default for OpaInputCfg {
    /// 业务作用：提供不读取 body/claims 的安全输入基线，并保留显式启用时的有限默认预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回 head-only 输入配置；body 上限与 media type 仅在 `include_body=true` 时生效。
    fn default() -> Self {
        Self {
            include_body: false,
            max_body_bytes: default_opa_input_max_body_bytes(),
            content_types: default_opa_input_content_types(),
            include_jwt_claims: false,
        }
    }
}

/// OPA obligations 白名单与资源门。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaObligationsCfg {
    /// OPA 可设置/删除的 request header 名称。
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// OPA 可设置/删除的 response header 名称。
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// 可接受的审计 metadata key。
    #[serde(default)]
    pub audit_metadata: Vec<String>,
    /// 单次 decision obligation 条目硬上限。
    #[serde(default = "default_opa_obligation_max_entries")]
    pub max_entries: usize,
    /// 单个 header/audit value 最大字节数。
    #[serde(default = "default_opa_obligation_max_value_bytes")]
    pub max_value_bytes: usize,
    /// 全部 obligation 名称和值累计最大字节数。
    #[serde(default = "default_opa_obligation_max_bytes")]
    pub max_bytes: usize,
}

impl Default for OpaObligationsCfg {
    /// 业务作用：默认不给 OPA 任何 header/audit 副作用权限，同时建立非零资源硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回空 allowlist；即使策略返回 obligation 也会整体拒绝。
    fn default() -> Self {
        Self {
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit_metadata: Vec::new(),
            max_entries: default_opa_obligation_max_entries(),
            max_value_bytes: default_opa_obligation_max_value_bytes(),
            max_bytes: default_opa_obligation_max_bytes(),
        }
    }
}

/// OPA decision L1 配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpaDecisionCacheCfg {
    /// allow decision TTL，毫秒。
    #[serde(default = "default_opa_cache_ttl_ms")]
    pub ttl_ms: u64,
    /// deny decision TTL，毫秒；通常短于 allow。
    #[serde(default = "default_opa_cache_deny_ttl_ms")]
    pub deny_ttl_ms: u64,
    /// 每 route 最大 decision entry 数，TinyLFU 到顶淘汰。
    #[serde(default = "default_opa_cache_max_entries")]
    pub max_entries: u64,
    /// 外部 Rego/data 的运维版本；签名 bundle 模式自动使用 manifest revision/digest。
    #[serde(default)]
    pub policy_revision: String,
    /// 是否合并本节点同 key 并发 miss。
    #[serde(default = "default_true")]
    pub singleflight: bool,
    /// follower 最长等待时间，毫秒。
    #[serde(default = "default_opa_singleflight_wait_ms")]
    pub singleflight_wait_ms: u64,
    /// 每 route 同时活跃的不同 miss key 硬上限。
    #[serde(default = "default_opa_singleflight_max_keys")]
    pub singleflight_max_keys: usize,
    /// 是否把已验证 decision 写入 DynamicStore 供节点间复用。
    #[serde(default)]
    pub distributed: bool,
    /// 跨节点 decision collection。
    #[serde(default = "default_opa_distributed_collection")]
    pub distributed_collection: String,
    /// 跨节点 collection 最大 entry 数。
    #[serde(default = "default_opa_distributed_max_entries")]
    pub distributed_max_entries: usize,
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

fn default_opa_cache_deny_ttl_ms() -> u64 {
    250
}

fn default_opa_singleflight_wait_ms() -> u64 {
    1_000
}

fn default_opa_singleflight_max_keys() -> usize {
    1_024
}

fn default_opa_distributed_collection() -> String {
    "opa_decisions".to_string()
}

fn default_opa_distributed_max_entries() -> usize {
    100_000
}

fn default_opa_bundle_query() -> String {
    "data.gateway.authz".to_string()
}

fn default_opa_bundle_max_bytes() -> usize {
    8 * 1024 * 1024
}

fn default_opa_bundle_max_expanded_bytes() -> usize {
    32 * 1024 * 1024
}

fn default_opa_bundle_max_files() -> usize {
    256
}

fn default_opa_input_max_body_bytes() -> usize {
    64 * 1024
}

fn default_opa_input_content_types() -> Vec<String> {
    vec!["application/json".to_string()]
}

fn default_opa_obligation_max_entries() -> usize {
    32
}

fn default_opa_obligation_max_value_bytes() -> usize {
    4 * 1024
}

fn default_opa_obligation_max_bytes() -> usize {
    32 * 1024
}

fn default_opa_backoff_initial_ms() -> u64 {
    100
}

fn default_opa_backoff_max_ms() -> u64 {
    5_000
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
/// 参数说明：无。
///
/// 返回：返回 3 秒。
const fn default_external_crypto_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：限制单 provider 并行调用，防依赖变慢时耗尽连接与线程。
///
/// 参数说明：无。
///
/// 返回：返回 8 个并发。
const fn default_external_crypto_concurrency() -> usize {
    8
}

/// 业务作用：限制等待远程 signer 的 TLS 握手数量。
///
/// 参数说明：无。
///
/// 返回：返回 64 项。
const fn default_external_crypto_queue_capacity() -> usize {
    64
}

/// 业务作用：设置依赖连续失败后打开熔断器的默认门槛。
///
/// 参数说明：无。
///
/// 返回：返回 5 次。
const fn default_external_crypto_circuit_failures() -> u32 {
    5
}

/// 业务作用：限制 signer 依赖故障期间重复外呼的默认熔断窗口。
///
/// 参数说明：无。
///
/// 返回：返回 10 秒。
const fn default_external_crypto_circuit_open_ms() -> u64 {
    10_000
}

/// 业务作用：限制送往外部密码 provider 的单次原始输入。
///
/// 参数说明：无。
///
/// 返回：返回 64 KiB。
const fn default_external_crypto_input_bytes() -> usize {
    64 * 1024
}

/// 业务作用：限制远程密码 provider 返回 JSON 的内存占用。
///
/// 参数说明：无。
///
/// 返回：返回 64 KiB。
const fn default_external_crypto_response_bytes() -> usize {
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
fn default_azure_key_vault_api_version() -> String {
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
fn default_remote_secret_authorization_header() -> String {
    "authorization".to_owned()
}

/// 业务作用：固定远程 secret 值的默认 JSON Pointer 契约。
///
/// 参数说明: 无。
///
/// 返回：返回 `/value`。
fn default_remote_secret_value_pointer() -> String {
    "/value".to_owned()
}

/// 业务作用：固定远程 secret 单调版本的默认 JSON Pointer 契约。
///
/// 参数说明: 无。
///
/// 返回：返回 `/version`。
fn default_remote_secret_version_pointer() -> String {
    "/version".to_owned()
}

/// 业务作用：给远程 secret 后台刷新提供不产生高频控制面请求的默认周期。
///
/// 参数说明: 无。
///
/// 返回：返回 30 秒。
const fn default_remote_secret_refresh_interval_ms() -> u64 {
    30_000
}

/// 业务作用：限制 provider 暂时不可用时旧 secret 可继续服务的默认窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 5 分钟。
const fn default_remote_secret_max_stale_ms() -> u64 {
    300_000
}

/// 业务作用：固定远程 provider 建连默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 3 秒。
const fn default_remote_secret_connect_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：固定远程 provider 完整请求默认 deadline。
///
/// 参数说明: 无。
///
/// 返回：返回 5 秒。
const fn default_remote_secret_request_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：防错误 provider 返回大文档占用候选构建内存。
///
/// 参数说明: 无。
///
/// 返回：返回 64 KiB。
const fn default_remote_secret_response_bytes() -> usize {
    64 * 1024
}

/// 业务作用：固定远程 provider 首次失败退避，避免立即重试放大故障。
///
/// 参数说明: 无。
///
/// 返回：返回 1 秒。
const fn default_remote_secret_retry_base_ms() -> u64 {
    1_000
}

/// 业务作用：限制远程 provider 连续失败退避，仍给 lease 和陈旧期留出复验机会。
///
/// 参数说明: 无。
///
/// 返回：返回 30 秒。
const fn default_remote_secret_retry_max_ms() -> u64 {
    30_000
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
    /// 绑定到本逻辑服务连接池身份的命名 TLS client credential 引用。
    #[serde(default)]
    pub upstream_credentials: Vec<String>,
    /// 上游实例来源：`static`(默认)、`nacos`、`consul`、`eureka`、`dns`、`kubernetes` 或 `xds`。
    #[serde(default)]
    pub source: Option<String>,
    /// Nacos 中的服务名;缺省使用 `services` map 的 key。
    #[serde(default)]
    pub nacos_service: Option<String>,
    /// V7 非 Nacos 注册中心中的物理服务名/DNS host；缺省使用 map key。
    #[serde(default)]
    pub registry_service: Option<String>,
    /// Kubernetes discovery 是否按 MCS `ServiceImport` 的 EndpointSlice label 获取跨集群端点。
    #[serde(default)]
    pub registry_service_import: bool,
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
    /// 一致性哈希键来源:`consumer` / `remote_addr` / `header:<name>` / `cookie:<name>` / `var:<name>`。
    /// `ring_hash`/`maglev` 必须声明;`ip_hash` 会自动展开为 `ring_hash` + `remote_addr`。
    /// 只接受受控来源,拒绝任意高基数字段污染哈希环与跨节点共享状态。
    #[serde(default)]
    pub hash_on: Option<String>,
    /// ring-hash 每单位权重生成的虚拟节点数;默认 100,构建期钳制到硬上限。
    #[serde(default)]
    pub hash_ring_replicas: Option<u32>,
    /// Maglev 查找表期望长度;构建期归一到不小于它的质数并受硬上限约束。
    #[serde(default)]
    pub hash_table_size: Option<usize>,
    /// 服务级会话保持;route 级策略优先(Gateway API 语义)。
    #[serde(default)]
    pub session_affinity: Option<SessionAffinityCfg>,
    /// V9 zone-aware locality/failover；未配置时保持既有全实例 LB 语义。
    #[serde(default)]
    pub locality: Option<UpstreamLocalityCfg>,
    /// 后端负载反馈:让 `weighted_least_request` 按真实延迟或后端自报利用率择优。
    /// 未配置时保持纯在途请求数比较,不采集任何反馈、不产生额外状态。
    #[serde(default)]
    pub load_feedback: Option<LoadFeedbackCfg>,
    /// backend 级 retry budget;未配置时重试只受 `next_upstream_tries` 约束。
    #[serde(default)]
    pub retry_budget: Option<RetryBudgetCfg>,
    /// 自适应并发:按 minRTT 与采样延迟动态调节该服务的在途上限。
    #[serde(default)]
    pub adaptive_concurrency: Option<AdaptiveConcurrencyCfg>,
    /// 上游 HTTP 协议：`auto`(默认，按 scheme + gRPC content-type 判) | `h1` | `h2` | `h2c` | `h3`。
    /// `h3` 要求 `https://` 实例和 `http3` feature，不满足时构建期 fail closed，不静默退化。
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
    /// 主动健康探测(§5.1):缺省 = 关闭。配置后后台任务按间隔 TCP/HTTP/gRPC/UDP 探测每个实例,
    /// 连续成功/失败达阈值翻转健康态;不健康实例不进入 LB 候选(与被动摘除叠加,双保险)。
    #[serde(default)]
    pub health_check: Option<HealthCheckCfg>,
    /// 新静态/发现实例进入目录后，使用真实业务连接池主动建立空闲连接。None = 关闭。
    #[serde(default)]
    pub prewarm: Option<UpstreamPrewarmCfg>,
}

/// backend 级 retry budget 配置。
///
/// route 的 `next_upstream` 决定「这次失败能不能重试」;本预算决定「当前整体还能不能
/// 再发重试」。两者都通过才真正发起重试,缺一不可。
#[derive(Debug, Deserialize, Clone)]
pub struct RetryBudgetCfg {
    /// 是否启用;默认 false 保持既有「只受 next_upstream_tries 约束」的行为。
    #[serde(default)]
    pub enabled: bool,
    /// 活动重试数占滚动请求数的百分比(1..=100),默认 20。
    #[serde(default)]
    pub budget_percent: Option<u32>,
    /// 无论比例如何都允许的最小并发重试数,默认 3;保证低流量服务仍能重试。
    #[serde(default)]
    pub min_retry_concurrency: Option<u64>,
    /// 每个滚动窗口至少允许的重试总数；用于表达 Gateway API `minRetryRate`。
    #[serde(default)]
    pub min_retries_per_window: Option<u64>,
    /// 滚动统计窗口(ms),默认 10000。
    #[serde(default)]
    pub window_ms: Option<u64>,
}

/// 自适应并发配置。
#[derive(Debug, Deserialize, Clone)]
pub struct AdaptiveConcurrencyCfg {
    /// 是否启用;默认 false。
    #[serde(default)]
    pub enabled: bool,
    /// 在途上限下界,默认 4;再拥塞也保留该并发,避免把后端彻底饿死。
    #[serde(default)]
    pub min_concurrency: Option<u64>,
    /// 在途上限上界,默认 1024。
    #[serde(default)]
    pub max_concurrency: Option<u64>,
    /// 采样窗口(ms),默认 1000。
    #[serde(default)]
    pub sample_window_ms: Option<u64>,
    /// minRTT 重标定周期(ms),默认 30000。
    #[serde(default)]
    pub min_rtt_window_ms: Option<u64>,
    /// 标定周期抖动万分比,默认 1000;避免多节点同时标定造成同步震荡。
    #[serde(default)]
    pub jitter_bp: Option<u32>,
    /// 超上限时允许排队的请求数,默认 0(直接拒绝不排队)。
    #[serde(default)]
    pub queue_limit: Option<u64>,
    /// 排队最长等待(ms),默认 100;超时按过载拒绝。
    #[serde(default)]
    pub queue_deadline_ms: Option<u64>,
}

/// 后端负载反馈配置。
///
/// 反馈只影响**同一候选层内部的择优顺序**,不参与健康裁决:任何缺失、过期、越界或
/// 格式非法的报告都只让该实例回落基础算法,绝不会把它判成不可用。
#[derive(Debug, Deserialize, Clone)]
pub struct LoadFeedbackCfg {
    /// 反馈口径:`none`(默认)、`latency_ewma`、`utilization`。
    #[serde(default)]
    pub mode: Option<String>,
    /// 反馈最大有效期(ms),默认 30000;超期即视为无反馈。
    #[serde(default)]
    pub freshness_ms: Option<u64>,
    /// 参与比较所需最小样本数,默认 3;防止冷启动实例被单次采样定性。
    #[serde(default)]
    pub min_samples: Option<u64>,
    /// EWMA 平滑系数万分比(1..=10000),默认 2000。越小越平滑。
    #[serde(default)]
    pub smoothing_bp: Option<u32>,
    /// panic 阈值万分比(0..=10000),默认 5000:有新鲜反馈的候选占比低于它时,
    /// 整服务停用反馈回退基础算法,避免把全部流量压到少数「有数据」的实例上。
    #[serde(default)]
    pub panic_threshold_bp: Option<u32>,
    /// ORCA 报告响应头名,默认 `endpoint-load-metrics`(仅 `utilization` 使用)。
    #[serde(default)]
    pub orca_header: Option<String>,
}

/// 会话保持配置:网关生成 cookie,或复用客户端提供的请求头。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SessionAffinityCfg {
    /// 载体:`cookie`(默认)或 `header`。
    #[serde(default)]
    pub mode: Option<String>,
    /// cookie 名或请求头名;缺省 cookie 模式为 `naway_affinity`。
    #[serde(default)]
    pub name: Option<String>,
    /// cookie 有效期(秒);0 或缺省表示会话 cookie(浏览器关闭即失效)。
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// 会话从首次建立起的绝对有效期（秒）；0 或缺省表示不由网关校验绝对期限。
    #[serde(default)]
    pub absolute_timeout_seconds: Option<u64>,
    /// 相邻两次有效请求之间允许的最大空闲期（秒）；0 或缺省表示不校验空闲期限。
    #[serde(default)]
    pub idle_timeout_seconds: Option<u64>,
    /// cookie 是否为持久 cookie；开启时必须配置 `absolute_timeout_seconds`，且
    /// `Max-Age` 按剩余绝对期限递减，不能因响应再次下发而延长会话。
    #[serde(default)]
    pub permanent_cookie: Option<bool>,
    /// cookie `Path`,缺省 `/`。
    #[serde(default)]
    pub path: Option<String>,
    /// 是否省略 cookie `Path`；用于 backend 级策略覆盖多个不同路径时避免缩小作用域。
    #[serde(default)]
    pub omit_path: Option<bool>,
    /// cookie `Domain`;缺省不下发该属性(仅当前 host 生效,范围最小)。
    #[serde(default)]
    pub domain: Option<String>,
    /// cookie `SameSite`:`Lax`(默认)/`Strict`/`None`。`None` 必须同时 `secure=true`。
    #[serde(default)]
    pub same_site: Option<String>,
    /// 是否下发 `Secure`,**缺省 true**;明文调试场景才需显式关掉。
    #[serde(default)]
    pub secure: Option<bool>,
    /// 是否下发 `HttpOnly`,**缺省 true**,防止脚本读取亲和令牌。
    #[serde(default)]
    pub http_only: Option<bool>,
}

/// 上游 zone-aware locality 与显式跨区故障转移策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UpstreamLocalityCfg {
    /// 本 Naway 数据面所在的可信 zone；仅与配置/发现 metadata 比较。
    pub local_zone: String,
    /// locality 调度模式:
    /// - `failover`(默认):严格按顺序,本区有容量就绝不外泄,跨区只作故障转移;
    /// - `weighted`:全部已声明 zone 同级参与,按「zone 权重 × 该 zone 健康实例数」分份额。
    ///
    /// 两者语义完全不同,必须显式选择:把 weighted 当默认会让本区优先的部署突然开始跨区分流。
    #[serde(default)]
    pub mode: Option<String>,
    /// 本区无健康容量时按数组顺序选择的跨区 failover zone。
    #[serde(default)]
    pub failover_zones: Vec<String>,
    /// 是否在已列 zone 全无健康容量后允许 zone 缺失/未列实例。默认 false。
    #[serde(default)]
    pub allow_unlisted: bool,
    /// zone → 相对权重。声明后同一优先级内按「权重 × 该 zone 健康实例数」分配份额,
    /// 而不是把本区之外的流量一刀切。未列 zone 取默认权重 1。
    #[serde(default)]
    pub zone_weights: std::collections::HashMap<String, u32>,
    /// 降级 zone:与本区同优先级参与,但份额按 `degraded_weight_percent` 打折。
    /// 用于「机房可用但已知劣化」这类既不该全量、也不该完全摘除的状态。
    #[serde(default)]
    pub degraded_zones: Vec<String>,
    /// 降级 zone 的份额百分比(1..=100),默认 20。
    #[serde(default)]
    pub degraded_weight_percent: Option<u32>,
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
    /// 探测类型:`tcp`、`http`、`grpc` 或 `udp`。gRPC 调用标准 Health/Check。
    #[serde(default = "default_health_check_type")]
    pub r#type: String,
    /// http 探测路径,默认 `/`。tcp 探测忽略。
    #[serde(default = "default_health_check_path")]
    pub path: String,
    /// 探测间隔(ms),默认 5000。
    #[serde(default = "default_health_check_interval_ms")]
    pub interval_ms: u64,
    /// 每轮探测间隔的对称随机化上限(ms)；默认 0，且不得超过 interval 的一半。
    #[serde(default)]
    pub jitter_ms: u64,
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
    /// gRPC Health/Check 的 service 名；空字符串表示检查服务器整体状态。
    #[serde(default)]
    pub grpc_service: String,
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
    /// 可信静态 locality zone；只在所属 service 配置 `locality` 时参与选择。
    #[serde(default)]
    pub zone: Option<String>,
}

/// HTTP 上游 TLS 配置,对齐 nginx `proxy_ssl_*` 的高频子集。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct UpstreamTlsCfg {
    /// 覆盖发往上游的 TLS SNI 与证书校验名,等价 nginx `proxy_ssl_name`。
    #[serde(default, alias = "proxy_ssl_name")]
    pub server_name: Option<String>,
    /// 只加密传输而不认证服务端证书；仅适用于身份已由受控服务发现边界约束的动态自签名端点。
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// 自定义上游服务端 CA PEM,等价 nginx `proxy_ssl_trusted_certificate`;为空使用系统根证书。
    #[serde(default, alias = "proxy_ssl_trusted_certificate")]
    pub ca_file: Option<String>,
    /// 内联 PEM CA bundle；用于受控发现源原子物化动态信任材料，不能与 `ca_file` 同时设置。
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// 显式证书 SAN allowlist，元素使用 `dns:<name>` 或 `uri:<absolute-uri>`；非空时
    /// 证书至少匹配一项，`server_name` 只承担 SNI 选择而不作为认证名。
    #[serde(default)]
    pub subject_alt_names: Vec<String>,
    /// 发给上游的客户端证书 PEM,等价 nginx `proxy_ssl_certificate`。
    #[serde(default, alias = "proxy_ssl_certificate")]
    pub client_cert_file: Option<String>,
    /// 发给上游的客户端私钥 PEM,等价 nginx `proxy_ssl_certificate_key`。
    #[serde(default, alias = "proxy_ssl_certificate_key")]
    pub client_key_file: Option<String>,
    /// 内联客户端证书链；只允许受控发现源原子物化，必须与内联私钥成对出现。
    #[serde(default)]
    pub client_cert_pem: Option<String>,
    /// 内联客户端私钥；不进入日志或错误上下文，必须与内联证书链成对出现。
    #[serde(default)]
    pub client_key_pem: Option<String>,
    /// 可选 SPIRE Workload API 客户端身份；与文件或内联客户端证书互斥。
    #[serde(default)]
    pub spire: Option<SpireWorkloadCfg>,
    /// 远程身份允许创建新上游请求的截止点；仅由候选构建器写入。
    #[serde(skip)]
    pub(crate) client_identity_not_after: Option<std::time::Instant>,
}

const fn default_spire_timeout_ms() -> u64 {
    3_000
}

const fn default_spire_reconnect_min_ms() -> u64 {
    100
}

const fn default_spire_reconnect_max_ms() -> u64 {
    5_000
}

const fn default_spire_max_response_bytes() -> usize {
    8 * 1024 * 1024
}

const fn default_spire_min_validity_seconds() -> u64 {
    30
}

const fn default_spire_clock_skew_seconds() -> u64 {
    30
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

const fn default_admin_rollout_canary_count() -> usize {
    1
}

const fn default_admin_rollout_observation_seconds() -> u64 {
    60
}

fn default_admin_rollout_max_5xx_ratio() -> f64 {
    0.01
}

fn default_admin_rollout_max_p99_regression_ratio() -> f64 {
    1.5
}

const fn default_admin_rollout_max_p99_ms() -> u64 {
    2_000
}

/// 业务作用：提供 maker-checker 默认覆盖的高危资源集合。
///
/// 参数说明：无。
///
/// 返回：返回流量防护、消费者凭据和证书三个资源域。
fn default_admin_approval_resources() -> Vec<AdminResource> {
    vec![
        AdminResource::Sentinel,
        AdminResource::Consumers,
        AdminResource::Certs,
    ]
}

/// 业务作用：提供待审批候选的默认有效期。
///
/// 参数说明：无。
///
/// 返回：返回 900 秒。
const fn default_admin_approval_ttl_seconds() -> u64 {
    900
}

/// 业务作用：提供待审批队列的默认硬上限。
///
/// 参数说明：无。
///
/// 返回：返回 64 条。
const fn default_admin_approval_max_pending() -> usize {
    64
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

/// 业务作用：给单 listener MQTT 会话设置默认并发硬门。
///
/// 参数说明：无。
///
/// 返回：默认最多 256 条正在握手或已建立的 MQTT 连接。
fn default_stream_mqtt_max_connections() -> usize {
    256
}

/// 业务作用：限制一枚 MQTT Control Packet 导致的单次分配。
///
/// 参数说明：无。
///
/// 返回：默认 1 MiB wire packet 上限。
fn default_stream_mqtt_max_packet_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制已开始 MQTT packet 的慢速传输，同时不误杀没有发包的长时间 idle 连接。
///
/// 参数说明：无。
///
/// 返回：fixed-header 首字节到完整 packet 默认 10 秒 deadline。
fn default_stream_mqtt_packet_timeout_ms() -> u64 {
    10_000
}

/// 业务作用：给 listener 内所有 MQTT packet buffer 设置可预留的聚合内存硬门。
///
/// 参数说明：无。
///
/// 返回：默认 512 MiB，按每连接两个方向各一枚最大 packet 做悲观预留。
fn default_stream_mqtt_max_buffered_bytes() -> usize {
    512 * 1024 * 1024
}

/// 业务作用：收紧 broker 协议理论上限，避免 topic 成为大字符串攻击面。
///
/// 参数说明：无。
///
/// 返回：默认 1024 字节 Topic Name/Filter 上限。
fn default_stream_mqtt_max_topic_bytes() -> usize {
    1_024
}

/// 业务作用：约束每条 MQTT 连接保留的订阅集合。
///
/// 参数说明：无。
///
/// 返回：默认最多 1024 个去重 topic filter。
fn default_stream_mqtt_max_subscriptions() -> usize {
    1_024
}

/// 业务作用：限制 QoS 与订阅控制流程的 packet-id 状态量。
///
/// 参数说明：无。
///
/// 返回：默认最多 128 个双向在途交换。
fn default_stream_mqtt_max_inflight_messages() -> usize {
    128
}

/// 业务作用：限制单 listener 的 Kafka 长连接任务与悲观 frame buffer 预留总量。
///
/// 参数说明：无。
///
/// 返回：默认 256 条连接。
fn default_stream_kafka_max_connections() -> usize {
    256
}

/// 业务作用：限制单枚 Kafka frame 的分配；默认与常见 1 MiB record batch 保持同量级。
///
/// 参数说明：无。
///
/// 返回：默认 1 MiB wire 上限。
fn default_stream_kafka_max_frame_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制已经开始传输的慢 Kafka frame，不影响纯 idle 长连接。
///
/// 参数说明：无。
///
/// 返回：默认 10 秒。
fn default_stream_kafka_frame_timeout_ms() -> u64 {
    10_000
}

/// 业务作用：限制 listener 内所有 Kafka 双向 frame buffer 的聚合预留。
///
/// 参数说明：无。
///
/// 返回：默认 512 MiB。
fn default_stream_kafka_max_buffered_bytes() -> usize {
    512 * 1024 * 1024
}

/// 业务作用：限制单连接 correlation map，防止只发 request 不读 response 的状态堆积。
///
/// 参数说明：无。
///
/// 返回：默认 128 个在途请求。
fn default_stream_kafka_max_inflight_requests() -> usize {
    128
}

/// 业务作用：限制 Kafka request header 的 client id 字符串。
///
/// 参数说明：无。
///
/// 返回：默认 256 字节。
fn default_stream_kafka_max_client_id_bytes() -> usize {
    256
}

/// 业务作用：收紧 Kafka topic 名攻击面，同时覆盖 broker 的常见 topic 长度上限。
///
/// 参数说明：无。
///
/// 返回：默认 249 字节。
fn default_stream_kafka_max_topic_bytes() -> usize {
    249
}

/// 业务作用：限制 consumer group id 的协议字符串分配。
///
/// 参数说明：无。
///
/// 返回：默认 255 字节。
fn default_stream_kafka_max_group_bytes() -> usize {
    255
}

/// 业务作用：限制 topic/partition/member 等 Kafka 数组的循环与状态规模。
///
/// 参数说明：无。
///
/// 返回：默认每数组最多 4096 项。
fn default_stream_kafka_max_array_items() -> usize {
    4096
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

fn default_acme_dns01_retry_attempts() -> usize {
    3
}

fn default_acme_dns01_retry_backoff_ms() -> u64 {
    250
}

fn default_acme_dns01_max_response_bytes() -> usize {
    1024 * 1024
}

fn default_acme_dns01_ttl_seconds() -> u32 {
    60
}

fn default_acme_cloudflare_api_base() -> String {
    "https://api.cloudflare.com/client/v4".to_string()
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

fn default_acme_keypair_retention_generations() -> usize {
    3
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

fn default_dynamic_store_nacos_prefix() -> String {
    "naway.dynamic".to_string()
}

fn default_dynamic_store_nacos_max_document_bytes() -> u64 {
    1024 * 1024
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

/// 业务作用：提供共享运行态 Redis key 的默认品牌 namespace，隔离不同网关产品的状态。
///
/// 参数说明：无。
///
/// 返回：返回 `naway`；部署可通过显式配置覆盖。
fn default_runtime_redis_namespace() -> String {
    "naway".to_string()
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

/// 业务作用：提供 OpenTelemetry resource 的默认服务名，使 Naway 信号可被稳定归类。
///
/// 参数说明：无。
///
/// 返回：返回 `naway`；部署可通过 telemetry 配置覆盖。
fn default_otel_service_name() -> String {
    "naway".to_string()
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

/// 业务作用：提供 Nacos discovery 与配置客户端的默认应用名，保持注册和配置身份一致。
///
/// 参数说明：无。
///
/// 返回：返回 `naway`；部署可通过 Nacos 配置覆盖。
fn default_nacos_app_name() -> String {
    "naway".to_string()
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

/// route 级双向带宽与成本型限额配置。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TrafficLimitCfg {
    /// 限额维度键。与 `limit_req` 使用同一套 DSL(global/ip/route/header:<n>/query:<n>),
    /// 保证同一 route 上两种限流对"谁是同一个调用方"的理解一致。
    #[serde(default = "default_traffic_limit_key")]
    pub key: String,
    /// 请求方向带宽整形。
    #[serde(default)]
    pub request_bandwidth: Option<BandwidthCfg>,
    /// 响应方向带宽整形。与 route filter 的 `limit_rate` 的区别是本策略按维度跨流共享。
    #[serde(default)]
    pub response_bandwidth: Option<BandwidthCfg>,
    /// 多窗口限额。
    #[serde(default)]
    pub quota: Option<QuotaCfg>,
    /// 计数不可用时的处置:fail_open|fail_closed。必须显式选择。
    #[serde(default = "default_traffic_limit_fail_mode")]
    pub fail_mode: String,
}

/// 业务作用：为流量治理选择不会跨调用方聚合的默认维度。
///
/// 参数说明：无。
///
/// 返回：返回客户端 IP 维度配置名。
fn default_traffic_limit_key() -> String {
    "ip".to_string()
}

/// 业务作用：定义本地流量计数不可用时的兼容处置，避免反序列化缺省值含义漂移。
///
/// 参数说明：无。
///
/// 返回：返回 `fail_open`；需要强制保护的路由必须显式配置 `fail_closed`。
fn default_traffic_limit_fail_mode() -> String {
    "fail_open".to_string()
}

/// 单方向带宽配置。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BandwidthCfg {
    /// 稳态速率(字节/秒)。
    pub bytes_per_second: u64,
    /// 突发容量(字节)。
    #[serde(default)]
    pub burst_bytes: u64,
    /// 前 N 字节不整形。
    #[serde(default)]
    pub after_bytes: u64,
}

/// 多窗口限额配置。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct QuotaCfg {
    /// 算法:fixed_window|sliding_window|leaky_bucket。
    #[serde(default = "default_quota_algorithm")]
    pub algorithm: String,
    /// 并行窗口集合;全部通过才放行。
    pub windows: Vec<QuotaWindowCfg>,
    /// 超额动作:reject|delay。
    #[serde(default = "default_quota_overflow")]
    pub overflow: String,
    /// `overflow: delay` 时的最大排队请求数。
    #[serde(default = "default_quota_max_queue")]
    pub max_queue: u64,
    /// `overflow: delay` 时的单请求最长等待(ms)。
    #[serde(default = "default_quota_max_wait_ms")]
    pub max_wait_ms: u64,
    /// 成本来源:per_request|response_bytes|grpc_messages|graphql_cost|trusted_usage。
    #[serde(default = "default_quota_cost_source")]
    pub cost_source: String,
    /// 准入期预留额度(成本型来源使用)。
    #[serde(default = "default_quota_reserve")]
    pub reserve: u64,
    /// `response_bytes` 下每多少字节记 1 个额度。
    #[serde(default = "default_quota_bytes_per_unit")]
    pub bytes_per_unit: u64,
    /// 结算硬上限,防止上游返回异常用量击穿账本。
    #[serde(default = "default_quota_max_actual")]
    pub max_actual: u64,
}

/// 单个限额窗口配置。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct QuotaWindowCfg {
    /// 窗口内额度。
    pub limit: u64,
    /// 窗口长度(ms)。
    pub window_ms: u64,
    /// 突发额度;漏桶算法忽略该值。
    #[serde(default)]
    pub burst: u64,
}

/// 业务作用：为未指定算法的多窗口额度选择能平滑窗口边界的默认实现。
///
/// 参数说明：无。
///
/// 返回：返回 `sliding_window`。
fn default_quota_algorithm() -> String {
    "sliding_window".to_string()
}

/// 业务作用：定义额度耗尽时不隐式积压请求的默认动作。
///
/// 参数说明：无。
///
/// 返回：返回 `reject`。
fn default_quota_overflow() -> String {
    "reject".to_string()
}

/// 业务作用：限制显式延迟模式的默认排队请求数，避免过载时形成无界内存队列。
///
/// 参数说明：无。
///
/// 返回：返回默认队列上限 128。
const fn default_quota_max_queue() -> u64 {
    128
}

/// 业务作用：限制额度等待的默认时长，避免请求长期占用连接与并发槽。
///
/// 参数说明：无。
///
/// 返回：返回 1000 毫秒。
const fn default_quota_max_wait_ms() -> u64 {
    1_000
}

/// 业务作用：为未声明成本来源的额度规则提供一次请求一次计费的确定语义。
///
/// 参数说明：无。
///
/// 返回：返回 `per_request`。
fn default_quota_cost_source() -> String {
    "per_request".to_string()
}

/// 业务作用：为需要事后结算的成本来源预留最小准入额度。
///
/// 参数说明：无。
///
/// 返回：返回 1 个额度单位。
const fn default_quota_reserve() -> u64 {
    1
}

/// 业务作用：定义响应字节成本到额度单位的默认换算粒度。
///
/// 参数说明：无。
///
/// 返回：返回每 1024 字节一个额度单位。
const fn default_quota_bytes_per_unit() -> u64 {
    1_024
}

/// 业务作用：限制单请求事后结算的默认最大成本，防止异常响应击穿额度账本。
///
/// 参数说明：无。
///
/// 返回：返回一百万个额度单位。
const fn default_quota_max_actual() -> u64 {
    1_000_000
}

/// route 级受控正向代理配置。
///
/// 所有 allowlist 都必须显式给出:没有"留空即全放行"的语义。正向代理把网关的
/// 网络位置交给调用方使用,一个默认放行的配置就是可被立刻利用的内网入口。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ForwardProxyCfg {
    /// 允许 CONNECT 的目标端口。不得为空。
    pub allowed_ports: Vec<u16>,
    /// 允许的目标域名,支持 `*.example.com` 形式的子域通配;不接受裸 `*`。
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// 允许的目标 CIDR。
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// 是否允许目标解析到私网地址。环回、链路本地与元数据地址即使开启也永远拒绝。
    #[serde(default)]
    pub allow_private: bool,
    /// 隧道空闲上限(ms);0 表示不限制。
    #[serde(default = "default_connect_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// 隧道绝对寿命上限(ms);0 表示不限制。
    #[serde(default)]
    pub max_lifetime_ms: u64,
    /// 单条隧道允许搬运的最大字节数;0 表示不限制。
    #[serde(default)]
    pub max_bytes: u64,
    /// 建连超时(ms)。
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

/// route 级 WebTransport 真上游代理配置。
///
/// 该后端只接受 HTTP/3 extended CONNECT，普通 HTTP 请求不会被静默转成 WebTransport。
/// 上游 URL 和信任根都在候选快照构建期冻结，客户端不能借请求字段改写拨号目标。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebTransportCfg {
    /// 固定 HTTPS WebTransport 上游 URL，包含上游 session path。
    pub upstream: String,
    /// 允许建立 session 的浏览器 Origin 精确集合；不得为空或包含通配符。
    pub allowed_origins: Vec<String>,
    /// 可选自定义 CA PEM；为空时使用系统信任根。相对路径按主配置目录解析并纳入热更新依赖。
    #[serde(default)]
    pub ca_file: Option<String>,
    /// 建立上游 QUIC 与 WebTransport session 的总时限。
    #[serde(default = "default_webtransport_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// 单 session 同时转发的双向 stream 上限。
    #[serde(default = "default_webtransport_max_bidi_streams")]
    pub max_bidi_streams: u64,
    /// 单 session 同时转发的单向 stream 上限。
    #[serde(default = "default_webtransport_max_uni_streams")]
    pub max_uni_streams: u64,
    /// 单方向等待转发的 DATAGRAM 数量上限；队列满时按不可靠语义丢弃。
    #[serde(default = "default_webtransport_max_datagram_queue")]
    pub max_datagram_queue: u64,
    /// 单个 WebTransport DATAGRAM payload 上限。
    #[serde(default = "default_webtransport_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
    /// session 两个方向合计允许转发的最大字节数；0 表示不限制。
    #[serde(default)]
    pub max_bytes: u64,
    /// session 无 stream/datagram 活动后的回收时限。
    #[serde(default = "default_webtransport_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// session 从建立起的最长存活时间；0 表示不额外限制。
    #[serde(default)]
    pub max_lifetime_ms: u64,
}

/// route 级 QUIC 0-RTT 安全契约。
///
/// 业务作用：仅对显式、无凭据且无认证副作用的读路由开放 early data；
/// listener 级 TLS 恢复与共享 anti-replay 是另一道必须同时成立的门禁。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlyDataRouteCfg {
    /// 是否显式允许本 route 接收 0-RTT；默认关闭。
    #[serde(default)]
    pub enabled: bool,
    /// 一次性 nonce 在 anti-replay 账本中的保留时间。
    #[serde(default = "default_early_data_replay_window_ms")]
    pub replay_window_ms: u64,
}

/// 业务作用：为 0-RTT 重放去重提供短且可容忍跨节点延迟的默认窗口。
///
/// 参数说明：无。
///
/// 返回：返回 10 秒的默认 anti-replay 保留时间。
const fn default_early_data_replay_window_ms() -> u64 {
    10_000
}

/// 业务作用：限制 WebTransport 上游握手占用会话准入资源的时间。
///
/// 参数说明：无。
///
/// 返回：返回 5 秒默认建连时限。
const fn default_webtransport_connect_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：为单个 WebTransport session 提供保守的双向 stream 并发上限。
///
/// 参数说明：无。
///
/// 返回：返回 64 条双向 stream。
const fn default_webtransport_max_bidi_streams() -> u64 {
    64
}

/// 业务作用：为单个 WebTransport session 提供保守的单向 stream 并发上限。
///
/// 参数说明：无。
///
/// 返回：返回 64 条单向 stream。
const fn default_webtransport_max_uni_streams() -> u64 {
    64
}

/// 业务作用：为 WebTransport 不可靠消息提供小型突发队列且保持内存有界。
///
/// 参数说明：无。
///
/// 返回：返回每方向 128 个 DATAGRAM。
const fn default_webtransport_max_datagram_queue() -> u64 {
    128
}

/// 业务作用：限制 WebTransport 单个 DATAGRAM，避免 QUIC path 分片与大包内存放大。
///
/// 参数说明：无。
///
/// 返回：返回 1150 字节 payload 上限。
const fn default_webtransport_max_datagram_bytes() -> usize {
    1_150
}

/// 业务作用：回收没有任何业务活动的 WebTransport session。
///
/// 参数说明：无。
///
/// 返回：返回 60 秒默认空闲时限。
const fn default_webtransport_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：为 CONNECT 隧道提供默认空闲回收期限，避免无流量连接永久占用资源。
///
/// 参数说明：无。
///
/// 返回：返回 60000 毫秒。
const fn default_connect_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：限制 CONNECT 目标建连的默认等待时间，避免不可达目标长期占用准入资源。
///
/// 参数说明：无。
///
/// 返回：返回 5000 毫秒。
const fn default_connect_timeout_ms() -> u64 {
    5_000
}

/// route 级 WebSocket 帧级治理配置。
///
/// 缺省即透明模式:不解析帧、不聚合消息,与既有行为完全一致。只有显式配置本块
/// 才进入 frame-aware 模式,相应的解析与聚合开销也只落在该 route 上。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WsFrameCfg {
    /// 单帧载荷上限(字节)。
    #[serde(default = "default_ws_max_frame_bytes")]
    pub max_frame_bytes: u64,
    /// 单条消息(所有分片之和)上限(字节)。
    #[serde(default = "default_ws_max_message_bytes")]
    pub max_message_bytes: u64,
    /// 单条消息允许的最大分片数;用于挡住分片炸弹。
    #[serde(default = "default_ws_max_fragments")]
    pub max_fragments: u32,
    /// 交给插件的载荷上限(字节);超出部分不进插件视野。
    #[serde(default = "default_ws_max_plugin_payload_bytes")]
    pub max_plugin_payload_bytes: usize,
    /// 单个插件处理一帧的时限(ms);超时按放行处理并计数。
    #[serde(default = "default_ws_plugin_timeout_ms")]
    pub plugin_timeout_ms: u64,
    /// permessage-deflate 允许的最大解压比。
    #[serde(default = "default_ws_max_decompress_ratio")]
    pub max_decompress_ratio: u32,
    /// 违规处置动作:drop|policy_close|upstream_close。
    #[serde(default = "default_ws_on_violation")]
    pub on_violation: String,
}

/// 业务作用：给帧级治理设置默认单帧硬上限，阻止对端声明无界载荷。
///
/// 参数说明：无。
///
/// 返回：返回 1 MiB。
const fn default_ws_max_frame_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：给分片消息设置默认聚合上限，约束跨帧状态占用。
///
/// 参数说明：无。
///
/// 返回：返回 8 MiB。
const fn default_ws_max_message_bytes() -> u64 {
    8 * 1024 * 1024
}

/// 业务作用：限制单条消息的默认分片数量，阻止小分片放大解析与状态成本。
///
/// 参数说明：无。
///
/// 返回：返回 256 个分片。
const fn default_ws_max_fragments() -> u32 {
    256
}

/// 业务作用：限制默认插件可见载荷，避免插件链复制过大的业务消息。
///
/// 参数说明：无。
///
/// 返回：返回 64 KiB。
const fn default_ws_max_plugin_payload_bytes() -> usize {
    64 * 1024
}

/// 业务作用：约束单次帧插件默认执行期限，避免插件挂住长连接。
///
/// 参数说明：无。
///
/// 返回：返回 100 毫秒。
const fn default_ws_plugin_timeout_ms() -> u64 {
    100
}

/// 业务作用：限制压缩消息默认解压倍率，降低压缩炸弹风险。
///
/// 参数说明：无。
///
/// 返回：返回 100 倍。
const fn default_ws_max_decompress_ratio() -> u32 {
    100
}

/// 业务作用：定义帧级违规的默认协议化关闭动作，避免静默丢弃导致双方状态分叉。
///
/// 参数说明：无。
///
/// 返回：返回 `policy_close`。
fn default_ws_on_violation() -> String {
    "policy_close".to_string()
}
