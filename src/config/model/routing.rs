//! 路由、变量、可复用片段及重试声明。

use super::*;

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
///
/// 参数说明: 无。
///
/// 返回：返回 302，与 Gateway API 未声明 statusCode 时的默认行为一致。
pub(super) const fn default_gateway_redirect_status_code() -> u16 {
    302
}

/// 一条 HTTP 路由及其断言、过滤器、后端和资源预算。
#[derive(Debug, Deserialize, Clone)]
pub struct RouteCfg {
    /// route 唯一标识,用于日志、指标和动态规则关联。
    pub id: String,
    /// 可选路由层级；根匹配公开属性，子层只在父策略成功后参与选择。
    #[serde(default)]
    pub layer: Option<crate::config::layers::LayerCfg>,
    /// 固定脚本的记录协议后端；必须与显式 CGI service 协议一致。
    #[serde(default)]
    pub cgi: Option<crate::config::cgi::CgiCfg>,
    /// WebDAV 的显式方法、目录能力和资源预算；不改变其它路由的静态服务权限。
    #[serde(default)]
    pub webdav: Option<crate::config::webdav::WebDavCfg>,
    /// 静态文件的有界容器点播；缺省不解释媒体查询参数。
    #[serde(default)]
    pub media: Option<crate::config::media::MediaCfg>,
    /// 直连上游 `http://host:port`，或通过 `lb://service` 从共享服务目录选择实例。
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
    /// 展开前的直接策略引用供权限图复验；不能由远端或手写文档伪造。
    #[serde(skip)]
    pub(crate) resolved_snippets: Vec<String>,
    /// 来源证据的最早单调期限；后台撤路受阻时，新请求仍不能使用过期授权。
    #[cfg(feature = "config-providers")]
    #[serde(skip)]
    pub(crate) provider_deadline: Option<std::time::Instant>,
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
    /// 显式 hedged request；只用于固定 `lb://`、GET/HEAD、可证明为空 body 的请求。
    #[serde(default)]
    pub hedge: Option<HedgeCfg>,
    /// 请求契约校验。未配置时保持纯流式快路径；body 校验必须携带显式有界上限。
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
    /// GraphQL 查询预算守卫。未配置时普通 HTTP route 不读取或解析请求体。
    #[serde(default)]
    pub graphql_guard: Option<GraphqlGuardCfg>,
    /// degraphql：把声明式 REST GET 映射为固定 GraphQL POST；查询在构建期解析计费。
    #[serde(default)]
    pub degraphql: Option<DegraphqlCfg>,
    /// OPA 外部策略授权。认证身份只来自已经通过的 JWT/API-Key/Basic，不信任客户端身份头。
    #[serde(default)]
    pub opa_authorization: Option<OpaAuthorizationCfg>,
    /// 内嵌 Casbin RBAC/ABAC 授权。model/policy 在快照构建期读取并编译，
    /// 数据面不做文件 I/O，也不信任客户端自报的主体头。
    #[serde(default)]
    pub casbin_authorization: Option<CasbinAuthorizationCfg>,
    /// Proxy-Wasm 头部插件链。模块在快照构建期编译，请求期只执行已编译代码；
    /// 数组顺序就是同一 phase 的执行顺序。
    #[serde(default)]
    pub wasm_plugins: Vec<WasmPluginCfg>,
    /// 独立沙箱的有界脚本；头部、完整实体与逐帧阶段按声明分别执行。
    #[serde(default)]
    pub script_plugins: Vec<crate::config::scripts::ScriptCfg>,
    /// 外部 HTTP 头部插件链。插件只接收显式 allowlist 的 head 元数据，业务 body
    /// 永不离开网关；数组顺序就是同一 phase 的执行顺序。
    #[serde(default)]
    pub external_plugins: Vec<ExternalPluginCfg>,
    /// Envoy External Processing 双向流；未配置时不编码 protobuf，也不建立扩展服务连接。
    #[serde(default)]
    pub ext_proc: Option<ExtProcCfg>,
    /// InferencePool 数据面约束；只允许 Kubernetes 控制器为已验证的池后端生成。
    #[serde(default)]
    pub inference_pool: Option<InferencePoolRouteCfg>,
    /// BFF 有界扇出聚合。它是终端后端，与 uri/serve/llm/mock 互斥。
    #[serde(default)]
    pub bff_aggregation: Option<BffAggregationCfg>,
    /// HTTP→Dubbo2 generic `$invoke` 终端后端。
    #[serde(default)]
    pub dubbo: Option<DubboRouteCfg>,
    /// typed API mock。适合从 OpenAPI example 物化后的稳定响应；与其它后端互斥。
    #[serde(default)]
    pub mock_response: Option<MockResponseCfg>,
    /// chaos 故障注入。采样命中后先延迟、再可选返回固定错误，不读取请求 body。
    #[serde(default)]
    pub fault_injection: Option<FaultInjectionCfg>,
    /// usage-plan 绑定。consumer 优先使用全局映射，未映射时可落到 default_plan。
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
    /// AI/LLM 统一 OpenAI-compatible 入口。存在时 route 不再使用顶层 `uri`，而由
    /// `models[]` 声明主模型与有序 fallback 后端。
    #[serde(default)]
    pub llm: Option<LlmRouteCfg>,
    /// MCP 或 A2A 独立终端入口；必须编译 agent-protocols，不能回落普通 HTTP 代理。
    #[serde(default)]
    pub agent: Option<crate::ai::agent::config::AgentCfg>,
    /// gRPC 边缘模式。缺省/`enabled: false` 时本 route 保持
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
    /// 路由优先级：数值【小】者优先;同值按配置书写顺序(SCG 有序语义)。
    /// 用于在 yaml 不便重排时显式定序,如 `/api/admin/**`(order:-10)优先于 `/api/**`(order:0)兜底。
    #[serde(default)]
    pub order: i32,
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
    /// 总 attempt 数；固定为 2，避免配置制造扇出风暴。
    #[serde(default = "default_hedge_max_attempts")]
    pub max_attempts: usize,
}

/// 业务作用：提供能吸收常见尾延迟、又不会立即制造双倍请求的默认 hedge 延迟。
///
/// 参数说明: 无。
///
/// 返回：默认延迟 25ms。
pub(super) const fn default_hedge_delay_ms() -> u64 {
    25
}

/// 业务作用：把 hedge 扇出硬限制为一个主请求加一个副本。
///
/// 参数说明: 无。
///
/// 返回：固定总 attempt 数 2。
pub(super) const fn default_hedge_max_attempts() -> usize {
    2
}

/// 业务作用：为未显式声明的 `match_type` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_variable_match_type() -> String {
    "exact".to_string()
}
