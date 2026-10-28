//! 注册中心、Kubernetes 与网关成员发现声明。

use super::*;

/// 所有服务发现后端的进程级配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCfg {
    /// 服务发现总开关；false 屏蔽全部注册后端及自注册，不影响静态上游和静态集群成员。
    /// 缺省 true 仅允许后端各自的开关生效；所有后端仍默认关闭。切换总开关需要重启。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Nacos watch 后端。
    #[serde(default)]
    pub nacos: NacosDiscoveryCfg,
    /// Consul Health API 轮询后端。
    #[serde(default)]
    pub consul: ConsulDiscoveryCfg,
    /// Eureka JSON API 轮询后端。
    #[serde(default)]
    pub eureka: EurekaDiscoveryCfg,
    /// 系统 DNS A/AAAA 解析后端。
    #[serde(default)]
    pub dns: DnsDiscoveryCfg,
    /// Kubernetes Endpoints API 轮询后端。
    #[serde(default)]
    pub kubernetes: KubernetesDiscoveryCfg,
}

impl Default for DiscoveryCfg {
    /// 业务作用：保持未配置发现后端时的无中心启动，同时允许显式声明的后端独立启用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：总开关允许后端声明生效，各后端与自注册仍全部关闭。
    fn default() -> Self {
        Self {
            enabled: true,
            nacos: NacosDiscoveryCfg::default(),
            consul: ConsulDiscoveryCfg::default(),
            eureka: EurekaDiscoveryCfg::default(),
            dns: DnsDiscoveryCfg::default(),
            kubernetes: KubernetesDiscoveryCfg::default(),
        }
    }
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
    /// 业务作用：构造 `ConsulDiscoveryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `EurekaDiscoveryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `DnsDiscoveryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `KubernetesRouteSourceCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `KubernetesDiscoveryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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

/// 业务作用：为未显式声明的 `poll_interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_registry_poll_interval_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `request_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_registry_request_timeout_ms() -> u64 {
    2_000
}

/// 业务作用：为未显式声明的 `stale_ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_registry_stale_ttl_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `max_response_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_registry_max_response_bytes() -> usize {
    4 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_instances` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_registry_max_instances() -> usize {
    1_024
}

/// 业务作用：为未显式声明的 `max_addresses` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_dns_max_addresses() -> usize {
    256
}

/// 业务作用：为未显式声明的 `namespace` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_kubernetes_namespace() -> String {
    "default".to_owned()
}

/// 业务作用：为未显式声明的 `target_proxy` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_kubernetes_route_target_proxy() -> String {
    "default".to_owned()
}

/// 业务作用：为未显式声明的 `materialized_file` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_kubernetes_route_materialized_file() -> String {
    ".gateway-kubernetes-routes.json".to_owned()
}

/// 业务作用：为 Gateway API 生成的 L4 listener 提供安全的全接口默认绑定地址。
///
/// 参数说明: 无。
///
/// 返回：返回 IPv4 未指定地址；部署方可显式收窄到 Pod IP 或 loopback。
pub(super) fn default_kubernetes_gateway_bind_address() -> String {
    "0.0.0.0".to_owned()
}

/// 业务作用：把 Mesh Profile listener 默认限制在本机，避免来源 namespace header
/// 被外部客户端伪造后取得 consumer Route 权限。
///
/// 参数说明: 无。
///
/// 返回：返回 IPv4 loopback 地址；跨 network namespace 部署必须显式配置受保护地址。
pub(super) fn default_kubernetes_gateway_mesh_bind_address() -> String {
    "127.0.0.1".to_owned()
}

/// 业务作用：为透明流量捕获提供独立且稳定的 Mesh Profile 接收端口。
///
/// 参数说明: 无。
///
/// 返回：返回默认端口 15001。
pub(super) const fn default_kubernetes_gateway_mesh_port() -> u16 {
    15_001
}

/// 业务作用：为 Gateway API 生成的 stream listener 提供向后兼容的全接口默认绑定地址。
///
/// 参数说明: 无。
///
/// 返回：返回 IPv4 未指定地址；需要同端口隔离 L7 与 L4 时由部署方显式配置独立地址。
pub(super) fn default_kubernetes_gateway_stream_bind_address() -> String {
    "0.0.0.0".to_owned()
}

/// 业务作用：固定 controller 编译与 conformance 声明使用的 Gateway API 版本。
///
/// 参数说明: 无。
///
/// 返回：返回当前实现支持的稳定版本 `v1.5.1`。
pub(super) fn default_kubernetes_gateway_api_version() -> String {
    "v1.5.1".to_owned()
}

/// 业务作用：固定控制器实现与一致性声明共同采用的 Inference Extension 合同版本。
///
/// 参数说明: 无。
///
/// 返回：返回当前支持的 `v1.5.0` 合同版本。
pub(super) fn default_kubernetes_inference_extension_version() -> String {
    "v1.5.0".to_owned()
}

/// 业务作用：固定未启用 TLS backend policy 时 GRPCRoute 的明文 HTTP/2 transport。
///
/// 参数说明: 无。
///
/// 返回：返回 `h2c`，避免 native gRPC 被自动协议选择降级到 HTTP/1.1。
pub(super) fn default_kubernetes_grpc_backend_protocol() -> String {
    "h2c".to_owned()
}

/// 业务作用：限制单次 Kubernetes watch 占用连接的时间，周期性 relist 补齐遗漏事件。
///
/// 参数说明: 无。
///
/// 返回：返回 30 秒服务端 watch 超时。
pub(super) const fn default_kubernetes_watch_timeout_seconds() -> u32 {
    30
}

/// 业务作用：限定删除 finalizer 等待数据面发布确认的最长时长。
///
/// 参数说明: 无。
///
/// 返回：返回 5 秒；超时保留 finalizer，由下一轮继续恢复。
pub(super) const fn default_kubernetes_deletion_drain_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：限制单轮控制面外部写操作，防止异常对象集合放大 API server 压力。
///
/// 参数说明: 无。
///
/// 返回：返回 4096 个 mutation 的硬配置默认值。
pub(super) const fn default_kubernetes_max_status_updates() -> usize {
    4_096
}

/// 业务作用：为未显式声明的 `ingress_classes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_kubernetes_ingress_classes() -> Vec<String> {
    vec!["gateway".to_owned()]
}

/// 业务作用：为未显式声明的 `gateway_controller_name` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_kubernetes_gateway_controller_name() -> String {
    "gateway.rust.dev/controller".to_owned()
}

/// 业务作用：为未显式声明的 `max_objects` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_kubernetes_route_max_objects() -> usize {
    4_096
}

/// 业务作用：为未显式声明的 `max_routes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_kubernetes_route_max_routes() -> usize {
    4_096
}

/// Nacos 服务发现与网关自注册配置。
#[derive(Debug, Deserialize, Clone)]
pub struct NacosDiscoveryCfg {
    /// 是否启用 Nacos 动态服务发现；还需总开关允许。动态服务引用已关闭的后端时拒绝构建。
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
    /// 业务作用：构造 `GatewaySelfRegisterCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `NacosDiscoveryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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

/// 业务作用：为未显式声明的 `poll_interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_poll_interval_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `stale_ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_nacos_stale_ttl_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `weight` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_self_register_weight() -> f64 {
    1.0
}

/// 业务作用：为未显式声明的 `deregister_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_self_register_deregister_timeout_ms() -> u64 {
    3_000
}
