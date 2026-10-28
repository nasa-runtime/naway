//! 网关根配置与功能域装配。

use super::*;

#[derive(Debug, Deserialize)]
/// `gateway.yml` 顶层 serde 模型；只表达声明式配置，运行期热路径使用构建后的 `GatewaySnapshot`。
pub struct GatewayConfig {
    /// NASA 进程日志配置；naml 展开目录占位符，文件输出与进程同寿命。
    #[serde(default)]
    pub log: Option<nasa::log::LogConfig>,
    /// 独立 xDS 管理端的传输身份、节点授权和已发布原生对象投影范围。
    #[serde(default)]
    pub xds_server: Option<crate::config::xds_server::ServerCfg>,
    /// 显式配置兼容来源；仅生成指定空 listener 的原生路由，来源文件也参与候选指纹。
    #[serde(default)]
    pub scg_imports: Vec<crate::config::scg::SourceCfg>,
    /// 控制面对象归属、跨域引用授权与工作区委派；关闭时不得携带未生效的声明。
    #[serde(default)]
    pub ownership: crate::control::ownership::config::OwnershipCfg,
    /// 多来源配置联邦；来源身份、命名空间和能力只能由本地权威声明。
    #[serde(default)]
    pub providers: crate::config::providers::ProvidersCfg,
    /// 配置 schema 版本:支撑长期演进的迁移/拒绝过新版本。
    /// 缺省(`None`)按 v1 处理并告警,详见 `load_snapshot` 的 `resolve_schema_version`。
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// 旧版单入口配置。新版推荐 `proxies[]`;没有配置 `proxies[]` 时,该字段会兼容生成 default proxy。
    #[serde(default)]
    pub server: Option<ServerCfg>,
    /// 管理与观测面：与数据面端口隔离，承载健康、就绪、指标、管理 API 与 Console；应绑定内网。
    #[serde(default)]
    pub admin: AdminCfg,
    /// 多数据面入口:每个 proxy 对齐一个 nginx `server{listen ...}`。
    #[serde(default)]
    pub proxies: Vec<ProxyCfg>,
    /// L4 TCP/UDP 数据面入口，各入口独立声明传输、路由与资源上限。
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
    /// 服务发现后端配置，统一装配 Nacos、Consul、Eureka、DNS 与 Kubernetes 实例目录。
    #[serde(default)]
    pub discovery: DiscoveryCfg,
    /// Kubernetes Ingress/Gateway API 路由控制器；远端对象先物化，再走统一快照事务。
    #[serde(default)]
    pub kubernetes_routes: KubernetesRouteSourceCfg,
    /// API 变现/consumer 分级的全局套餐目录。
    #[serde(default)]
    pub usage_plans: UsagePlansCfg,
    /// 开发者门户与 OpenAPI API 目录。文档在快照构建期导入并生成普通 route。
    #[serde(default)]
    pub developer_portal: DeveloperPortalCfg,
    /// 统一配置来源；可从 Nacos 配置中心观察网关配置，本地文件提供 bootstrap 与配置的回退边界。
    #[serde(default)]
    pub config_source: ConfigSourceCfg,
    /// 可选 xDS 控制面入口。bootstrap 永久拥有 server/identity/trust/ownership 与资源预算。
    #[serde(default)]
    pub control_plane: ControlPlaneCfg,
    /// 运行态共享后端配置。计数/动态事实源不进入路由 DSL,由运行态面统一装配。
    #[serde(default)]
    pub runtime_state: RuntimeStateCfg,
    /// nginx `set` / `map` / `${...}` 变量系统；构建期编译为 VariablePlan，供请求处理和上游选择复用。
    #[serde(default)]
    pub variables: VariablesCfg,
    /// access log 执行参数。默认非阻塞 bounded queue,队列满丢弃并计数。
    #[serde(default)]
    pub access_log: AccessLogCfg,
    /// OpenTelemetry 观测配置；导出器与队列按运行代际交接，候选准备成功后才替换活动代际。
    #[serde(default)]
    pub telemetry: TelemetryCfg,
    /// 热重载控制面资源参数。这些值在启动时创建 worker 时生效，不属于请求热路径。
    #[serde(default)]
    pub reload: ReloadCfg,
    /// WS/gRPC 长连接在配置换版与管理面 drain 时的全局治理策略。
    #[serde(default)]
    pub long_connections: LongConnectionCfg,
    /// gRPC 边缘模式的进程级集群中继面。None 或 `mode: none` = 单机,
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

/// 业务作用：为未显式声明的 `interface_guard_file` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_guard_file() -> String {
    "interface-guard.yml".to_string()
}

/// 业务作用：为未显式声明的 `sentinel_rules_file` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_sentinel_rules_file() -> String {
    "sentinel-rules.yml".to_string()
}
