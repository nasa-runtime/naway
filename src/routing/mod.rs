//! 路由表:predicates 全命中 → 命中 route → 指向上游 + nginx/Higress 风格 filter 计划。

pub mod circuit;
pub mod sentinel;
use circuit::parse_circuit_breaker;
pub use circuit::CircuitBreakerPolicy;
use sentinel::parse_limit_req;
pub use sentinel::LimitReqPolicy;
pub(crate) mod layers;
pub(crate) mod traffic;
pub mod variable;

pub mod predicate;
mod semantic;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;
use http::Method;
use hyper::{Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use crate::ai::llm::LlmRoutePolicy;
use crate::cache::http::HttpCachePolicy;
use crate::config::model::{
    BffAggregationCfg, FaultInjectionCfg, GatewayRedirectCfg, HedgeCfg, InferencePoolRouteCfg,
    MockResponseCfg, RouteCfg,
};
use crate::extensions::degraphql::DegraphqlPlan;
use crate::extensions::ext_proc::ExtProcPlan;
use crate::extensions::external_plugin::ExternalPluginChain;
use crate::extensions::graphql::GraphqlGuardPolicy;
use crate::extensions::wasm::WasmPluginChain;
use crate::io::net::Cidr;
use crate::io::static_serve::StaticServe;
use crate::protocols::dubbo::DubboPlan;
use crate::proxy::request_validation::RequestValidationPlan;
use crate::proxy::response_contract::{BodyTransformPlan, ResponseContractPlan};
use crate::routing::variable::{ValueTemplate, VariablePhase, VariablePlan};
use crate::security::auth::{basic_authorization_matches, constant_time_eq, escape_header_quote};
use crate::security::bot::BotPolicy;
use crate::security::casbin_auth::CasbinPolicy;
use crate::security::csrf::CsrfPolicy;
use crate::security::dlp::DlpPolicy;
use crate::security::enterprise_identity::{EnterpriseAuthPolicy, EnterpriseAuthResult};
use crate::security::geoip::{GeoIpCatalog, GeoIpPolicy};
use crate::security::opa::OpaPolicy;
use crate::security::upstream_credential::UpstreamCredentialPlan;
use crate::security::waf::WafPolicy;
use predicate::{parse_predicate, parse_strip_prefix, Predicate};

/// `sub_filter` 单个匹配串的最大长度,避免配置把流式回看窗口撑成大内存。
const MAX_SUB_FILTER_NEEDLE_BYTES: usize = 8192;
/// `sub_filter` 单个替换串的最大长度,避免一次命中制造过大的 data frame。
const MAX_SUB_FILTER_REPLACEMENT_BYTES: usize = 65536;
/// HMAC 签名默认允许的客户端时间偏差,单位毫秒。
const DEFAULT_HMAC_SKEW_MS: u64 = 300_000;
/// HMAC 签名允许配置的最大时间偏差,避免误配成永久有效签名。
const MAX_HMAC_SKEW_MS: u64 = 86_400_000;
/// 小于该值的时间戳按 Unix 秒处理,否则按 Unix 毫秒处理。
const HMAC_UNIX_SECONDS_THRESHOLD: i128 = 10_000_000_000;
/// JWT `exp` / `nbf` 默认允许的时钟偏差,单位秒。
const DEFAULT_JWT_LEEWAY_SECS: i64 = 60;
/// JWT `leeway_secs` 最大值,避免误配成长期接受过期 token。
const MAX_JWT_LEEWAY_SECS: i64 = 3600;
/// 远端 JWKS/discovery 单文档最大字节数。
const MAX_JWT_METADATA_BYTES: usize = 1024 * 1024;
/// 单个 JWKS 最大 key 数，避免不可信 IdP 响应扩张快照状态。
const MAX_JWKS_KEYS: usize = 128;
/// `kid` 与 identity claim/header 配置的最大长度。
const MAX_JWT_IDENTITY_BYTES: usize = 256;
/// compact JWT 默认最大字节数，覆盖常见 OIDC token 且限制请求头解析成本。
const DEFAULT_JWT_TOKEN_BYTES: usize = 16 * 1024;
/// compact JWT 可配置硬上限，避免超大 claims/signature 占用数据面内存。
const MAX_JWT_TOKEN_BYTES: usize = 64 * 1024;
/// JWKS/OIDC metadata 默认总超时。
const DEFAULT_JWKS_TIMEOUT_MS: u64 = 1_000;
/// JWKS/OIDC metadata 最大总超时，避免身份依赖长期占住请求任务。
const MAX_JWKS_TIMEOUT_MS: u64 = 60_000;
/// OIDC token/userinfo/introspection 单响应最大实体。
const MAX_OIDC_RESPONSE_BYTES: usize = 1024 * 1024;
/// OIDC 登录前 state/PKCE 暂存上限。
const DEFAULT_OIDC_MAX_PENDING: usize = 1024;
/// OIDC 活跃浏览器 session 默认上限。
const DEFAULT_OIDC_MAX_SESSIONS: usize = 10_000;
/// ext_authz 默认外呼超时,单位毫秒。它是 yml filter 的可覆盖默认值,不是不可调硬编码。
const DEFAULT_EXT_AUTHZ_TIMEOUT_MS: u64 = 500;
/// ext_authz 允许配置的最大外呼超时,避免鉴权服务拖住主数据面。
const MAX_EXT_AUTHZ_TIMEOUT_MS: u64 = 60_000;
/// route 级长流 timer 的最大可配置时长，避免极端 `u64` 在 `Instant + Duration` 溢出。
const MAX_LONG_STREAM_DURATION_MS: u64 = 365 * 24 * 60 * 60 * 1_000;
/// 未显式配置时每条限流规则允许的活跃维度桶数；可由 `max_active_keys=` 覆盖。
const DEFAULT_LIMIT_REQ_MAX_ACTIVE_KEYS: usize = 100_000;
/// mirror body tee 默认最大字节数。
const DEFAULT_MIRROR_MAX_BODY_BYTES: u64 = 64 * 1024;
/// mirror body tee 最大允许字节数,防止误配把镜像变成大 body 聚合慢路径。
const MAX_MIRROR_BODY_BYTES: u64 = 1024 * 1024;
/// 响应压缩默认最小实体长度；未知长度的流仍可压缩，避免为判长而聚合 body。
const DEFAULT_COMPRESSION_MIN_LENGTH: u64 = 1024;
/// 流式 codec 单次最多向 Hyper 交付的压缩字节数，限制每请求暂存内存。
const DEFAULT_COMPRESSION_CHUNK_BYTES: usize = 16 * 1024;
/// 单个压缩输出 frame 的允许上限，防止配置把每个并发请求的暂存块放大到无界。
const MAX_COMPRESSION_CHUNK_BYTES: usize = 1024 * 1024;
/// 每条 route 最多声明的可压缩 MIME 匹配项，限制热路径线性扫描成本。
const MAX_COMPRESSION_CONTENT_TYPES: usize = 64;
/// 公共响应缓存默认 TTL，毫秒。
const DEFAULT_HTTP_CACHE_TTL_MS: u64 = 60_000;
/// 每条 cache route 默认允许的 L1 entry 数。
const DEFAULT_HTTP_CACHE_MAX_ENTRIES: u64 = 10_000;
/// cache miss 默认最多复制 1MiB 未压缩实体；超过后透明转发但不回填。
const DEFAULT_HTTP_CACHE_MAX_BODY_BYTES: u64 = 1024 * 1024;
/// 单 route 缓存 body 上限的硬保护，避免显式慢路径吃掉无界内存。
const MAX_HTTP_CACHE_BODY_BYTES: u64 = 16 * 1024 * 1024;
/// 同 key cache miss follower 的默认有界等待；route 可显式覆盖。
const DEFAULT_HTTP_CACHE_SINGLEFLIGHT_WAIT_MS: u64 = 1_000;
/// 每 route 默认最多维护的不同 miss key leader 数；满载 fail-open 回源。
const DEFAULT_HTTP_CACHE_MAX_INFLIGHT: usize = 1_024;
/// 不同 key 的 fresh TTL 默认最多缩短 10%，分散批量配置同时过期；同 key 仍由 single-flight 保护。
const DEFAULT_HTTP_CACHE_TTL_JITTER_PERCENT: u8 = 10;

/// 一条路由 = 断言集合(全命中)+ 上游 + StripPrefix 段数。
pub struct Route {
    /// route 唯一标识,用于日志、指标、动态规则关联。
    pub id: String,
    /// 与数据面记录/长连接注册表共享的 route id。
    ///
    /// `id` 保留给构建期校验和需要 owned String 的低频控制面；请求命中后 clone 本字段只增加
    /// 引用计数，不能为 access log、trace 和每条 gRPC stream 重复复制同一段 UTF-8。
    pub id_shared: Arc<str>,
    /// 只属于本配置代的入口事实，旧响应结束不能写入热更后的路由归属。
    pub(crate) traffic: Arc<crate::observability::http_stream::routes::Counters>,
    /// 实际选择优先级同时进入管理语义，不能只保留排序结果而丢失候选差异。
    pub(crate) order: i32,
    /// 只读层级声明参与管理解释与语义差异，不从数据面头反向构造。
    pub(crate) layer: Option<Arc<crate::config::layers::LayerCfg>>,
    /// 记录协议仅在显式制品中进入数据面。
    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
    pub(crate) cgi: Option<Arc<crate::protocols::cgi::Plan>>,
    /// 显式文件协议计划，关闭制品能力时不进入路由结构。
    #[cfg(feature = "webdav")]
    pub(crate) webdav: Option<Arc<crate::io::webdav::Plan>>,
    /// 仅动态来源路由具有证据期限；到期不得等待控制面构建成功后才停止接收新请求。
    #[cfg(feature = "config-providers")]
    pub(crate) provider_deadline: Option<std::time::Instant>,
    /// `http://host:port` 直连，或通过 `lb://service` 从共享目录选择实例。
    pub upstream: String,
    /// `uri` 的编译模板。静态路由走 `upstream` 快路径;包含变量时运行期按请求上下文求值。
    pub upstream_template: ValueTemplate,
    /// 路由断言集合,所有断言命中才选择本 route。
    pub predicates: Vec<Predicate>,
    /// 是否为内部 route。内部 route 只能被 error_page/reroute/X-Accel 类内部跳转命中。
    pub internal: bool,
    /// `StripPrefix` 要剥离的 path 段数。
    pub strip_prefix: usize,
    /// `rewrite` 前缀改写规则。
    pub rewrite_prefix: Option<RewritePrefix>,
    /// Gateway API ReplaceFullPath；存在时完整替换 path，但仍保留原 query。
    pub gateway_rewrite_full_path: Option<String>,
    /// 是否保留已通过入站校验的原始 Host/authority，不用当次上游实例地址覆盖。
    pub preserve_host: bool,
    /// 是否透传下游请求头,对应 nginx `proxy_pass_request_headers`。
    pub pass_request_headers: bool,
    /// 是否透传下游请求体,对应 nginx `proxy_pass_request_body`。
    pub pass_request_body: bool,
    /// 有界 hedged request；None 保持单请求/既有 retry 路径，不增加任何 timer 或副本。
    pub(crate) hedge: Option<HedgePolicy>,
    /// 上游请求头设置规则集合。
    pub request_headers: Vec<RequestHeaderOp>,
    /// 当前 route/backend 专属的已解析 header/query 凭据。
    pub(crate) upstream_credentials: Option<Arc<UpstreamCredentialPlan>>,
    /// 下游响应头过滤规则集合。
    pub response_headers: Vec<ResponseHeaderOp>,
    /// `sub_filter` 响应体流式替换规则。存在时仅包当前 route 的响应 body。
    pub sub_filters: Vec<SubFilterRule>,
    /// gzip/brotli 响应压缩策略。不存在时该 route 完全不介入内容编码。
    pub compression: Option<CompressionPolicy>,
    /// 普通HTTP请求在认证后解码，正文安全检查始终消费解码表示。
    pub(crate) request_decompression: Option<crate::io::request_decompression::Policy>,
    /// 公共 HTTP 响应 L1/L2 缓存；不存在时不构造 key、不复制 body。
    pub(crate) http_cache: Option<Arc<HttpCachePolicy>>,
    /// 请求 OpenAPI/JSON Schema 显式慢路径；不存在时不构造 JSON、不读取 body。
    pub(crate) request_validation: Option<RequestValidationPlan>,
    /// 请求实体声明式转换；不存在时保持原始 body 流。
    pub(crate) request_transform: Option<Arc<BodyTransformPlan>>,
    /// 响应实体声明式转换；不存在时保持上游或插件产生的 body。
    pub(crate) response_transform: Option<Arc<BodyTransformPlan>>,
    /// 最终下游响应 OpenAPI 契约；不存在时不读取或观察响应 body。
    pub(crate) response_contract: Option<Arc<ResponseContractPlan>>,
    /// 内置 API WAF；不存在时请求 head 与 body 都不增加扫描成本。
    pub(crate) waf: Option<Arc<WafPolicy>>,
    /// 本地 MMDB 驱动的客户端国家、ASN 与匿名网络策略。
    pub(crate) geoip: Option<Arc<GeoIpPolicy>>,
    /// 可组合行为、指纹、速率与逐请求签名复验的 Bot 策略。
    pub(crate) bot: Option<Arc<BotPolicy>>,
    /// 浏览器状态变更请求的来源与 token 门禁。
    pub(crate) csrf: Option<Arc<CsrfPolicy>>,
    /// 请求、响应与日志 path 的 PII/secret 策略。
    pub(crate) dlp: Option<Arc<DlpPolicy>>,
    /// GraphQL query depth/complexity guard；不存在时不读取或解析普通代理 body。
    pub(crate) graphql_guard: Option<GraphqlGuardPolicy>,
    /// 双向带宽整形与成本型限额策略。
    pub(crate) traffic_limit: Option<Arc<TrafficLimitPolicy>>,
    /// 受控正向代理策略;None 表示该 route 不接受 CONNECT。
    pub(crate) forward_proxy: Option<Arc<crate::protocols::forward_proxy::ForwardProxyPolicy>>,
    /// WebTransport 真上游策略；None 表示 extended CONNECT 不会建立 session。
    pub(crate) webtransport: Option<Arc<crate::protocols::masque::WebTransportPolicy>>,
    /// 显式的 0-RTT 读路由计划；None 表示任何 early request 都必须返回 425。
    pub(crate) early_data: Option<crate::protocols::masque::EarlyDataRoutePolicy>,
    /// WebSocket 帧级治理策略;None 表示保持透明隧道。
    pub(crate) ws_frame: Option<Arc<crate::protocols::ws_frame::FramePolicy>>,
    /// REST→GraphQL 固定文档映射；不存在时普通 route 无 variables 编码成本。
    pub(crate) degraphql: Option<Arc<DegraphqlPlan>>,
    /// OPA 外部授权；不存在时普通 route 不编码 policy input、不访问 decision cache。
    pub(crate) opa_authorization: Option<Arc<OpaPolicy>>,
    /// 内嵌 Casbin RBAC/ABAC；快照内只读，请求期无文件 I/O。
    pub(crate) casbin_authorization: Option<Arc<CasbinPolicy>>,
    /// Proxy-Wasm request/response header 插件链；不存在时数据面无沙箱调度成本。
    pub(crate) wasm_plugins: Option<Arc<WasmPluginChain>>,
    /// 源码与预算已冻结的脚本链；关闭 feature 后不保留数据面字段。
    #[cfg(feature = "lua-scripts")]
    pub(crate) script_plugins: Option<Arc<crate::extensions::scripts::Chain>>,
    /// 外部 HTTP request/response header 插件链；不存在时不编码 JSON、不发子请求。
    pub(crate) external_plugins: Option<Arc<ExternalPluginChain>>,
    /// Envoy External Processing 双向流计划；不存在时请求路径不编码 protobuf。
    #[cfg_attr(not(feature = "ext-proc"), allow(dead_code))]
    pub(crate) ext_proc: Option<Arc<ExtProcPlan>>,
    /// InferencePool 的 EPP 选择门；不存在时普通 `lb://` 路由不解析 endpoint 决策。
    pub(crate) inference_pool: Option<InferencePoolPolicy>,
    /// BFF 并发只读子请求计划；终端慢路径，普通 route 为 None。
    pub(crate) bff_aggregation: Option<Arc<BffAggregationPolicy>>,
    /// HTTP→Dubbo2 generic invocation；不存在时不聚合 JSON、不建立原始 TCP RPC 连接。
    pub(crate) dubbo: Option<Arc<DubboPlan>>,
    /// typed mock 固定响应；body 使用 Bytes，单请求只 clone 引用计数句柄。
    pub(crate) mock_response: Option<MockResponsePolicy>,
    /// 显式 chaos 策略；采样不读取/复制 body。
    pub(crate) fault_injection: Option<FaultInjectionPolicy>,
    /// consumer usage-plan 配额；全局 catalog 已解析为共享只读 plan。
    pub(crate) usage_plan: Option<UsagePlanPolicy>,
    /// 多模型 LLM 统一协议计划；不存在时普通代理路径没有 JSON/token 处理开销。
    pub(crate) llm: Option<Arc<LlmRoutePolicy>>,
    /// 显式 Agent 协议终端；未编译对应制品时配置构建必须拒绝。
    pub(crate) agent: Option<Arc<crate::ai::agent::Plan>>,
    /// gRPC 边缘模式已编译计划；None = 普通 L7 透传（默认）。
    /// 订阅/发布分支读取该计划，静态 relay 由进程级集群计划接线。
    pub(crate) grpc_edge: Option<Arc<crate::edge::config::GrpcEdgePlan>>,
    /// descriptor 驱动 JSON 转码慢路径；None 时 native gRPC 不读取反射计划。
    pub(crate) grpc_transcoding:
        Option<Arc<crate::protocols::grpc_transcoding::GrpcTranscodingPlan>>,
    /// 上游写成功后要推进 generation 的同 proxy 缓存 route id；最多 8 个，避免控制面 I/O 无界。
    pub(crate) cache_invalidations: Vec<String>,
    /// CORS 策略,命中预检请求时可直接短路。
    pub cors: Option<CorsPolicy>,
    /// 上游不可用时是否附加 fallback 标记响应头。
    pub fallback_headers: bool,
    /// allow/deny 访问控制规则。
    pub access_rules: Vec<AccessRule>,
    /// Referer 校验规则,对应 nginx `valid_referers` 基础子集。
    pub referer: Option<RefererPolicy>,
    /// route 命中后允许的方法集合,对应 nginx `limit_except` 基础子集。
    pub limit_except: Option<Vec<Method>>,
    /// HTTP Basic 鉴权策略,对应 nginx `auth_basic` 基础形态。
    pub basic_auth: Option<BasicAuthPolicy>,
    /// 具有严格一次性计数消费的 Digest 策略，不从普通请求头推导认证成功。
    pub(crate) digest_auth: Option<crate::security::digest::Policy>,
    /// API-Key 鉴权策略集合。多条策略之间视为同一种认证方式的 OR。
    pub api_keys: Vec<ApiKeyPolicy>,
    /// HMAC-SHA256 请求签名策略集合。多条策略之间视为同一种认证方式的 OR。
    pub hmac_auth: Vec<HmacAuthPolicy>,
    /// JWT HS256 鉴权策略集合。多条策略之间视为同一种认证方式的 OR。
    pub jwt_auth: Vec<JwtAuthPolicy>,
    /// OAuth2/OIDC Authorization Code RP；存在时浏览器会话是本地认证的唯一身份来源。
    oidc_rp: Option<Arc<OidcRpPolicy>>,
    /// 可选 SAML/LDAP 企业身份策略；同协议策略之间按 OR，作为独立认证方式参与 satisfy。
    pub(crate) enterprise_auth: Vec<EnterpriseAuthPolicy>,
    /// ext_authz / auth_request 外部鉴权策略集合。多条策略之间视为同一种认证方式的 OR。
    pub ext_authz: Vec<ExtAuthzPolicy>,
    /// 多认证策略组合方式,对应 nginx `satisfy any/all` 的数据面鉴权子集。
    pub satisfy: SatisfyMode,
    /// nginx `if` 安全子集:条件命中后执行固定 `return` 短路。
    pub conditional_returns: Vec<ConditionalReturn>,
    /// `limit_req` 请求速率规则。
    pub limit_req: Vec<LimitReqPolicy>,
    /// `limit_conn` 并发规则。
    pub limit_conn: Vec<LimitConnPolicy>,
    /// `limit_rate` 响应字节限速规则。
    pub limit_rate: Option<LimitRatePolicy>,
    /// 熔断/降级规则。
    pub circuit_breakers: Vec<CircuitBreakerPolicy>,
    /// `error_page` 状态映射规则。
    pub error_pages: Vec<ErrorPagePolicy>,
    /// 是否让 `error_page` 接管上游错误响应,对应 nginx `proxy_intercept_errors`。
    pub proxy_intercept_errors: bool,
    /// 是否处理上游 `X-Accel-Redirect` 响应头并转入 internal route。
    pub x_accel_redirect: bool,
    /// route 级固定响应,对应 nginx `return` 风格短路。
    pub direct_response: Option<DirectResponse>,
    /// Gateway API 动态重定向；按当前请求保留或替换 authority/path/query。
    pub gateway_redirect: Option<GatewayRedirectPolicy>,
    /// 本地静态文件/SPA 后端。存在时不走上游代理。
    pub static_serve: Option<StaticServe>,
    /// `mirror` 流量镜像规则。当前基础版只镜像 head/空 body,不阻塞主链路。
    pub mirrors: Vec<MirrorPolicy>,
    /// 当前快照的变量计划,供 route 级模板渲染。
    pub variables: Arc<VariablePlan>,
    /// SSE/gRPC 响应 idle 覆盖；None 继承 proxy 全局值。
    pub long_stream_idle_timeout_ms: Option<u64>,
    /// 单次下游请求的总 deadline；None 使用 proxy 既有阶段超时，Some(0) 显式关闭。
    pub request_timeout_ms: Option<u64>,
    /// 单次上游 attempt 的总 deadline；None 使用 proxy 既有阶段超时，Some(0) 显式关闭。
    pub backend_request_timeout_ms: Option<u64>,
    /// SSE/gRPC 响应最长存活时间(ms)；0 不限制。
    pub long_stream_max_lifetime_ms: u64,
}

/// 已编译的 InferencePool 请求期选择边界。
#[derive(Clone, Copy)]
pub(crate) struct InferencePoolPolicy {
    /// 单次 EPP 决策可携带的最大 endpoint 数。
    #[cfg(feature = "inference-gateway")]
    pub(crate) max_selected_endpoints: usize,
}

impl InferencePoolPolicy {
    /// 业务作用：把控制器生成的 InferencePool 标记与标准 ext_proc 计划绑定，确保 EPP
    /// 决策只能在完整请求体处理后生效，并保留响应阶段的实际 endpoint 回报能力。
    ///
    /// 参数说明：
    /// - `cfg`：是池选择预算
    /// - `route`：提供后端与 ext_proc 原始声明
    /// - `ext_proc`：表示标准协议计划已经通过通用构建校验。
    ///
    /// 返回：全部协议相位和权限满足 Inference Extension 合同时返回计划，否则拒绝候选。
    fn build(
        cfg: &InferencePoolRouteCfg,
        route: &RouteCfg,
        ext_proc: Option<&Arc<ExtProcPlan>>,
    ) -> Result<Self> {
        #[cfg(not(feature = "inference-gateway"))]
        {
            let _ = (cfg, route, ext_proc);
            bail!("inference_pool requires the inference-gateway feature");
        }
        #[cfg(feature = "inference-gateway")]
        {
            anyhow::ensure!(
                (1..=256).contains(&cfg.max_selected_endpoints),
                "inference_pool.max_selected_endpoints must be within 1..=256"
            );
            anyhow::ensure!(
                route.uri.starts_with("lb://"),
                "inference_pool requires a fixed lb:// backend"
            );
            let raw = route
                .ext_proc
                .as_ref()
                .context("inference_pool requires ext_proc")?;
            anyhow::ensure!(
                ext_proc.is_some(),
                "inference_pool ext_proc plan is unavailable"
            );
            anyhow::ensure!(
                raw.request_headers
                    && raw.request_body == crate::config::model::ExtProcBodyModeCfg::Buffered
                    && !raw.request_trailers
                    && raw.response_headers
                    && raw.response_body == crate::config::model::ExtProcBodyModeCfg::None
                    && !raw.response_trailers,
                "inference_pool requires request headers, buffered request body, response headers, and no trailer or response body processing"
            );
            anyhow::ensure!(
                raw.mutation_headers
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case("x-gateway-destination-endpoint")),
                "inference_pool ext_proc must authorize x-gateway-destination-endpoint"
            );
            anyhow::ensure!(
                raw.writable_metadata_namespaces
                    .iter()
                    .any(|namespace| namespace == "envoy.lb"),
                "inference_pool ext_proc must authorize envoy.lb metadata"
            );
            Ok(Self {
                max_selected_endpoints: cfg.max_selected_endpoints,
            })
        }
    }
}

/// 构建期已验证的 hedged request 执行计划。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct HedgePolicy {
    /// 启动第二实例副本前的固定延迟。
    pub delay: Duration,
}

impl HedgePolicy {
    /// 业务作用：把 route hedging 声明收敛为严格有界的执行计划，阻止动态 URI、隐式幂等
    /// 或多副本扇出进入数据面。
    ///
    /// 参数说明：
    /// - `cfg`：是 route 声明
    /// - `route_id`：用于错误定位
    /// - `upstream`：是声明的终端 URI。
    ///
    /// 返回：安全门全部满足时返回双 attempt 计划，否则拒绝整份候选快照。
    fn build(cfg: &HedgeCfg, route_id: &str, upstream: &str) -> Result<Self> {
        anyhow::ensure!(
            cfg.idempotent,
            "route `{route_id}` hedge requires explicit idempotent=true"
        );
        anyhow::ensure!(
            cfg.max_attempts == 2,
            "route `{route_id}` hedge.max_attempts must equal 2"
        );
        anyhow::ensure!(
            (1..=60_000).contains(&cfg.delay_ms),
            "route `{route_id}` hedge.delay_ms must be within 1..=60000"
        );
        anyhow::ensure!(
            upstream.starts_with("lb://")
                && upstream.len() > "lb://".len()
                && !upstream.contains("${"),
            "route `{route_id}` hedge requires a fixed lb:// service URI"
        );
        Ok(Self {
            delay: Duration::from_millis(cfg.delay_ms),
        })
    }
}

/// 已编译路由表。数据面只顺序匹配断言,不再解析配置字符串。
pub struct Router {
    routes: Vec<Arc<Route>>,
    /// 整个 proxy 是否存在响应压缩 route。构建期汇总后，请求入口只读一个 bool；全无压缩的
    /// 常见反代/gRPC proxy 不再为每个请求扫描 `Accept-Encoding`，也不 clone HeaderMap。
    has_response_compression: bool,
    /// 仅启用 Digest 的入口需要保留规范化前的 URI。
    pub(crate) has_digest_auth: bool,
    /// 构建期编译的灰度组。请求匹配只做借用查表和整数哈希，不构造候选 Vec。
    weighted_groups: HashMap<String, WeightedRouteGroup>,
    pub(crate) layers: Option<layers::Plan>,
}

/// 一个 Weight 组在有序 route 表中的成员与总份额。
struct WeightedRouteGroup {
    members: Vec<(usize, u32)>,
    total_weight: u64,
}

impl Router {
    /// 业务作用：从 yml 路由声明构建使用默认套餐目录的有序数据面路由表。
    ///
    /// 参数说明：
    /// - `cfgs`：是 route 列表
    /// - `variables`：是已编译变量计划
    /// - `config_dir`：是主配置目录，用于解析公开资源的相对路径。
    ///
    /// 返回：所有声明通过构建期门禁时返回不可变路由表，否则拒绝候选配置。
    pub fn build(
        cfgs: &[RouteCfg],
        variables: Arc<VariablePlan>,
        config_dir: &Path,
    ) -> Result<Router> {
        let usage_plans = UsagePlanCatalog::build(&crate::config::model::UsagePlansCfg::default())?;
        Self::build_with_usage_plans(cfgs, variables, config_dir, usage_plans)
    }

    /// 业务作用：使用已编译的全局套餐目录构建路由表，供不拥有本地 listener 拓扑的调用方复用。
    ///
    /// 套餐目录由整个配置快照共享；route 只持有不可变 `Arc`，避免在每个请求上解析
    /// plan id、复制 consumer 映射或获取配置锁。
    ///
    /// 参数说明：
    /// - `cfgs`：是 route 列表
    /// - `variables`：是变量计划
    /// - `config_dir`：是主配置目录
    /// - `usage_plans`：是当前快照的套餐目录。
    ///
    /// 返回：构建成功返回路由表；任何 route 违反协议或安全约束时返回错误。
    pub(crate) fn build_with_usage_plans(
        cfgs: &[RouteCfg],
        variables: Arc<VariablePlan>,
        config_dir: &Path,
        usage_plans: Arc<UsagePlanCatalog>,
    ) -> Result<Router> {
        Self::build_with_usage_plans_and_self_addrs(cfgs, variables, config_dir, usage_plans, &[])
    }

    /// 业务作用：使用完整本地 listener 拓扑构建路由表，使 CONNECT route 在放宽私网访问时
    /// 仍不能回连数据面或管理面。
    ///
    /// 参数说明：
    /// - `cfgs`：是 route 列表
    /// - `variables`：是变量计划
    /// - `config_dir`：是主配置目录
    /// - `usage_plans`：是套餐目录
    /// - `self_addrs`：是当前候选快照的全部本地监听地址。
    ///
    /// 返回：构建成功返回带自访问门禁的路由表；配置矛盾或边界非法时返回错误。
    pub(crate) fn build_with_usage_plans_and_self_addrs(
        cfgs: &[RouteCfg],
        variables: Arc<VariablePlan>,
        config_dir: &Path,
        usage_plans: Arc<UsagePlanCatalog>,
        self_addrs: &[std::net::SocketAddr],
    ) -> Result<Router> {
        let layer_topology = layers::Topology::build(cfgs)?;
        let mut ordered: Vec<(i32, Arc<Route>)> = Vec::with_capacity(cfgs.len());
        let mut geoip_catalog = GeoIpCatalog::default();
        for c in cfgs {
            let branch = c.layer.as_ref().is_some_and(|layer| layer.branch);
            if c.long_stream_idle_timeout_ms
                .is_some_and(|value| value > MAX_LONG_STREAM_DURATION_MS)
            {
                bail!(
                    "route `{}` long_stream_idle_timeout_ms must be 0..={MAX_LONG_STREAM_DURATION_MS}",
                    c.id
                );
            }
            if c.long_stream_max_lifetime_ms > MAX_LONG_STREAM_DURATION_MS {
                bail!(
                    "route `{}` long_stream_max_lifetime_ms must be 0..={MAX_LONG_STREAM_DURATION_MS}",
                    c.id
                );
            }
            let mut predicates = Vec::new();
            for p in &c.predicates {
                predicates.push(parse_predicate(p).with_context(|| format!("route `{}`", c.id))?);
            }
            // 规则数硬上限:每请求都要线性扫描全部断言,条数必须有界;
            // 超限说明该用一条更精确的 Path/Host 而不是堆 header 规则。
            const MAX_PREDICATES_PER_ROUTE: usize = 32;
            const MAX_HEADER_PREDICATES_PER_ROUTE: usize = 16;
            anyhow::ensure!(
                predicates.len() <= MAX_PREDICATES_PER_ROUTE,
                "route `{}` declares {} predicates, exceeding the {MAX_PREDICATES_PER_ROUTE} cap",
                c.id,
                predicates.len()
            );
            let header_predicates = predicates
                .iter()
                .filter(|predicate| matches!(predicate, Predicate::Header {
                    ..
                }))
                .count();
            anyhow::ensure!(
                header_predicates <= MAX_HEADER_PREDICATES_PER_ROUTE,
                "route `{}` declares {header_predicates} Header predicates, exceeding the \
                 {MAX_HEADER_PREDICATES_PER_ROUTE} cap",
                c.id
            );
            let mut internal = false;
            if let Some(cgi) = &c.cgi {
                cgi.validate()?;
            }
            if let Some(webdav) = &c.webdav {
                webdav.validate()?;
            }
            if let Some(media) = &c.media {
                media.validate()?;
            }
            #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
            let cgi = c
                .cgi
                .as_ref()
                .map(crate::protocols::cgi::Plan::build)
                .transpose()?;
            let upstream_template = variables
                .compile_template(&c.uri)
                .with_context(|| format!("route `{}` uri", c.id))?;
            let llm = c
                .llm
                .as_ref()
                .map(|cfg| LlmRoutePolicy::build(cfg, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` llm", c.id))?
                .map(Arc::new);
            let agent = crate::ai::agent::Plan::build(c.agent.as_ref(), config_dir)
                .with_context(|| format!("route `{}` agent", c.id))?;
            // gRPC 边缘模式:构建期定型 + 拒绝矩阵。未开启恒为 None,数据面零感知。
            let grpc_edge = crate::edge::config::GrpcEdgePlan::build(c.grpc_edge.as_ref(), &c.id)
                .with_context(|| format!("route `{}` grpc_edge", c.id))?
                .map(Arc::new);
            let grpc_transcoding = crate::protocols::grpc_transcoding::GrpcTranscodingPlan::build(
                c.grpc_transcoding.as_ref(),
                config_dir,
                c.id.as_str(),
            )
            .with_context(|| format!("route `{}` grpc_transcoding", c.id))?
            .map(Arc::new);
            let bff_aggregation = c
                .bff_aggregation
                .as_ref()
                .map(BffAggregationPolicy::build)
                .transpose()
                .with_context(|| format!("route `{}` bff_aggregation", c.id))?
                .map(Arc::new);
            let dubbo = c
                .dubbo
                .as_ref()
                .map(|cfg| DubboPlan::build(cfg, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` dubbo", c.id))?
                .map(Arc::new);
            let mock_response = c
                .mock_response
                .as_ref()
                .map(MockResponsePolicy::build)
                .transpose()
                .with_context(|| format!("route `{}` mock_response", c.id))?;
            let fault_injection = c
                .fault_injection
                .as_ref()
                .map(FaultInjectionPolicy::build)
                .transpose()
                .with_context(|| format!("route `{}` fault_injection", c.id))?;
            let usage_plan = c
                .usage_plan
                .as_ref()
                .map(|binding| usage_plans.bind(binding, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` usage_plan", c.id))?;
            let static_serve = c
                .serve
                .as_ref()
                .and_then(|serve| serve.r#static.as_ref())
                .map(|static_cfg| {
                    if !c.uri.trim().is_empty() {
                        bail!("route cannot set both `uri` and `serve.static`");
                    }
                    let backend = StaticServe::build(static_cfg, config_dir, variables.as_ref())?;
                    #[cfg(feature = "media-streaming")]
                    let backend = {
                        let mut backend = backend;
                        if let Some(media) = &c.media {
                            backend.enable_media(media)?;
                        }
                        backend
                    };
                    Ok::<_, anyhow::Error>(backend)
                })
                .transpose()
                .with_context(|| format!("route `{}` serve.static", c.id))?;
            #[cfg(feature = "webdav")]
            let webdav = c
                .webdav
                .as_ref()
                .map(|cfg| {
                    crate::io::webdav::Plan::build(
                        cfg,
                        c.serve.as_ref().and_then(|serve| serve.r#static.as_ref()),
                        config_dir,
                        &c.uri,
                    )
                })
                .transpose()
                .with_context(|| format!("route `{}` webdav", c.id))?;
            let gateway_redirect = c
                .gateway_redirect
                .as_ref()
                .map(GatewayRedirectPolicy::build)
                .transpose()
                .with_context(|| format!("route `{}` gateway_redirect", c.id))?;
            // CONNECT route 自成一类后端:它没有固定上游,目标由请求方指定并逐次校验。
            // 把它并进普通反代会让"方法匹配"被误当成无约束隧道,正是必须避免的建模错误。
            let terminal_backends = usize::from(!c.uri.trim().is_empty())
                + usize::from(static_serve.is_some())
                + usize::from(llm.is_some())
                + usize::from(agent.is_some())
                + usize::from(bff_aggregation.is_some())
                + usize::from(mock_response.is_some())
                + usize::from(gateway_redirect.is_some())
                + usize::from(c.forward_proxy.is_some())
                + usize::from(c.webtransport.is_some());
            if terminal_backends != usize::from(!branch) {
                bail!(
                    "route `{}` requires one terminal backend for a leaf or ordinary route, and none for a branch",
                    c.id
                );
            }
            if c.forward_proxy.is_some() {
                // 正向代理 route 必须显式只匹配 CONNECT。否则一条没有上游的 route
                // 会把普通请求也吸进来,而这些请求既无后端也不该走隧道语义。
                let connect_only = c.predicates.iter().any(|raw| {
                    raw.trim().strip_prefix("Method=").is_some_and(|methods| {
                        !methods.trim().is_empty()
                            && methods
                                .split(',')
                                .all(|method| method.trim().eq_ignore_ascii_case("CONNECT"))
                    })
                });
                if !connect_only {
                    bail!(
                        "route `{}` forward_proxy 必须显式声明 `Method=CONNECT` 断言",
                        c.id
                    );
                }
            }
            if c.webtransport.is_some() {
                // WebTransport 是 extended CONNECT 终端；显式方法门避免普通请求落到没有 HTTP
                // response backend 的 route，也避免宽 route 绕过 session 专属治理。
                let connect_only = c.predicates.iter().any(|raw| {
                    raw.trim().strip_prefix("Method=").is_some_and(|methods| {
                        !methods.trim().is_empty()
                            && methods
                                .split(',')
                                .all(|method| method.trim().eq_ignore_ascii_case("CONNECT"))
                    })
                });
                if !connect_only {
                    bail!(
                        "route `{}` webtransport 必须显式声明 `Method=CONNECT` 断言",
                        c.id
                    );
                }
            }
            if grpc_edge.is_some() && (c.uri.trim().is_empty() || dubbo.is_some()) {
                // 边缘 route 的非 edge 消息仍要正常 L7 转发到后端( 连接模型),
                // 因此必须是 HTTP upstream 后端;llm/serve.static/mock/bff/dubbo 均不兼容。
                bail!(
                    "route `{}` grpc_edge requires an HTTP upstream `uri` and cannot combine with llm/serve.static/mock_response/bff_aggregation/dubbo",
                    c.id
                );
            }
            if grpc_transcoding.is_some()
                && (c.uri.trim().is_empty()
                    || grpc_edge.is_some()
                    || dubbo.is_some()
                    || llm.is_some()
                    || static_serve.is_some()
                    || bff_aggregation.is_some()
                    || mock_response.is_some())
            {
                bail!(
                    "route `{}` grpc_transcoding requires one HTTP upstream and cannot combine with grpc_edge or terminal protocol backends",
                    c.id
                );
            }
            if dubbo.is_some()
                && (!predicates.iter().any(
                    |predicate| matches!(predicate, Predicate::Method(methods) if methods.as_slice() == [Method::POST])
                )
                    || c.uri.contains("${"))
            {
                bail!(
                    "route `{}` dubbo requires a fixed uri and exact Method=POST predicate",
                    c.id
                );
            }
            for (field, timeout) in [
                ("request_timeout_ms", c.request_timeout_ms),
                ("backend_request_timeout_ms", c.backend_request_timeout_ms),
            ] {
                if let Some(timeout) = timeout {
                    anyhow::ensure!(
                        timeout <= 31_536_000_000,
                        "route `{}` {field} exceeds 365 days",
                        c.id
                    );
                }
            }
            if let (Some(request), Some(backend)) =
                (c.request_timeout_ms, c.backend_request_timeout_ms)
            {
                anyhow::ensure!(
                    request == 0 || backend <= request,
                    "route `{}` backend_request_timeout_ms cannot exceed request_timeout_ms",
                    c.id
                );
            }
            let mut strip_prefix = 0;
            let mut rewrite_prefix = None;
            let mut gateway_rewrite_full_path = None;
            let mut pass_request_headers = true;
            let mut pass_request_body = true;
            let mut request_headers = Vec::new();
            let mut response_headers = Vec::new();
            let mut sub_filters = Vec::new();
            let mut compression = None;
            let mut compression_defined = false;
            let mut request_decompression = None;
            let mut request_decompression_defined = false;
            let mut http_cache = None;
            let mut http_cache_defined = false;
            let mut cache_invalidations = Vec::new();
            let mut cors = None;
            let mut fallback_headers = false;
            let mut access_rules = Vec::new();
            let mut referer = None;
            let mut limit_except = None;
            let mut basic_auth = None;
            let mut digest_auth = None;
            let mut digest_declared = false;
            let mut api_keys = Vec::new();
            let mut hmac_auth = Vec::new();
            let mut jwt_auth = Vec::new();
            let mut oidc_rp = None;
            let mut enterprise_auth = Vec::new();
            let mut ext_authz = Vec::new();
            let mut satisfy = SatisfyMode::All;
            let mut conditional_returns = Vec::new();
            let mut limit_req = Vec::new();
            let mut limit_conn = Vec::new();
            let mut limit_rate = None;
            let mut circuit_breakers = Vec::new();
            let mut error_pages = Vec::new();
            let mut proxy_intercept_errors = true;
            let mut x_accel_redirect = false;
            let mut direct_response = None;
            let mut mirrors = Vec::new();
            for f in &c.filters {
                if let Some(n) = parse_strip_prefix(f)? {
                    anyhow::ensure!(!branch, "route branch cannot rewrite request path");
                    strip_prefix = n;
                    continue;
                }
                // 声明中可能包含秘密值；错误上下文只保留操作名，不能把原始认证参数写入拒绝记录。
                let filter =
                    parse_filter(f, variables.as_ref(), config_dir).with_context(|| {
                        format!(
                            "route `{}` filter `{}`",
                            c.id,
                            f.split_whitespace().next().unwrap_or("")
                        )
                    })?;
                if branch {
                    layers::policy::branch_filter(&filter)?;
                }
                match filter {
                    ParsedFilter::None => {}
                    ParsedFilter::Internal => internal = true,
                    ParsedFilter::ProxySetHeader(op) => {
                        request_headers.push(RequestHeaderOp::Set(op))
                    }
                    ParsedFilter::GatewayRequestHeader(op) => request_headers.push(op),
                    ParsedFilter::PassRequestHeaders(pass) => pass_request_headers = pass,
                    ParsedFilter::PassRequestBody(pass) => pass_request_body = pass,
                    ParsedFilter::AddHeader(op) => response_headers.push(ResponseHeaderOp::Add(op)),
                    ParsedFilter::GatewayResponseHeader(op) => response_headers.push(op),
                    ParsedFilter::HideHeader(name) => {
                        response_headers.push(ResponseHeaderOp::Hide(name))
                    }
                    ParsedFilter::ProxyRedirect(rule) => {
                        response_headers.push(ResponseHeaderOp::ProxyRedirect(rule))
                    }
                    ParsedFilter::CookieRewrite(rule) => {
                        response_headers.push(ResponseHeaderOp::CookieRewrite(rule))
                    }
                    ParsedFilter::DedupeHeader(op) => {
                        response_headers.push(ResponseHeaderOp::Dedupe(op))
                    }
                    ParsedFilter::SubFilter(rule) => sub_filters.push(rule),
                    ParsedFilter::Compression(policy) => {
                        if compression_defined {
                            bail!(
                                "route `{}` declares response compression more than once",
                                c.id
                            );
                        }
                        compression_defined = true;
                        compression = policy;
                    }
                    ParsedFilter::RequestDecompression(policy) => {
                        anyhow::ensure!(
                            !request_decompression_defined,
                            "route `{}` repeats request_decompression",
                            c.id
                        );
                        request_decompression_defined = true;
                        request_decompression = policy;
                    }
                    ParsedFilter::ProxyCache(policy) => {
                        if http_cache_defined {
                            bail!("route `{}` declares proxy_cache more than once", c.id);
                        }
                        http_cache_defined = true;
                        http_cache = policy;
                    }
                    ParsedFilter::ProxyCachePurge(routes) => {
                        cache_invalidations.extend(routes);
                    }
                    ParsedFilter::Cors(policy) => cors = Some(policy),
                    ParsedFilter::FallbackHeaders => fallback_headers = true,
                    ParsedFilter::Access(rule) => access_rules.push(rule),
                    ParsedFilter::ValidReferers(policy) => referer = Some(policy),
                    ParsedFilter::LimitExcept(methods) => limit_except = Some(methods),
                    ParsedFilter::BasicAuth(policy) => basic_auth = policy,
                    ParsedFilter::DigestAuth(policy) => {
                        anyhow::ensure!(!digest_declared, "route `{}` repeats auth_digest", c.id);
                        digest_declared = true;
                        digest_auth = policy;
                    }
                    ParsedFilter::ApiKey(policy) => api_keys.push(policy),
                    ParsedFilter::HmacAuth(policy) => hmac_auth.push(policy),
                    ParsedFilter::JwtAuth(policy) => jwt_auth.push(policy),
                    ParsedFilter::OidcRp(policy) => {
                        if oidc_rp.is_some() {
                            bail!("route `{}` declares oidc_rp more than once", c.id);
                        }
                        oidc_rp = Some(Arc::new(*policy));
                    }
                    ParsedFilter::EnterpriseAuth(policy) => enterprise_auth.push(policy),
                    ParsedFilter::ExtAuthz(policy) => ext_authz.push(policy),
                    ParsedFilter::Satisfy(mode) => satisfy = mode,
                    ParsedFilter::ConditionalReturn(rule) => conditional_returns.push(rule),
                    ParsedFilter::LimitReq(policy) => limit_req.push(policy),
                    ParsedFilter::LimitConn(policy) => limit_conn.push(policy),
                    ParsedFilter::LimitRate(policy) => limit_rate = Some(policy),
                    ParsedFilter::CircuitBreaker(policy) => circuit_breakers.push(policy),
                    ParsedFilter::ErrorPage(policy) => error_pages.push(policy),
                    ParsedFilter::ProxyInterceptErrors(enabled) => proxy_intercept_errors = enabled,
                    ParsedFilter::XAccelRedirect(enabled) => x_accel_redirect = enabled,
                    ParsedFilter::Return(resp) => direct_response = Some(resp),
                    ParsedFilter::RewritePrefix(rewrite) => rewrite_prefix = Some(rewrite),
                    ParsedFilter::GatewayRewriteFullPath(path) => {
                        gateway_rewrite_full_path = Some(path)
                    }
                    ParsedFilter::Mirror(policy) => mirrors.push(policy),
                }
            }
            anyhow::ensure!(
                gateway_rewrite_full_path.is_none() || rewrite_prefix.is_none(),
                "route `{}` cannot combine full-path and prefix rewrite",
                c.id
            );
            // Digest 计数只能授权一个公开动作；免认证内部跳转和复用凭据的层级执行不能借其身份。
            if digest_auth.is_some() {
                anyhow::ensure!(!internal && c.layer.is_none() && c.forward_proxy.is_none() && !matches!(satisfy, SatisfyMode::Any)
                    && basic_auth.is_none() && jwt_auth.is_empty() && oidc_rp.is_none() && enterprise_auth.is_empty(),
                    "route `{}` auth_digest requires a public unlayered origin route, satisfy=all and no competing Authorization scheme", c.id);
                anyhow::ensure!(api_keys.iter().all(|key| !matches!(&key.source, ApiKeySource::Header(header) if header == http::header::AUTHORIZATION)),
                    "route `{}` auth_digest cannot share Authorization with api_key", c.id);
            }
            let mut owned_identity_headers = HashSet::new();
            for header in jwt_auth
                .iter()
                .flat_map(|policy: &JwtAuthPolicy| policy.identity_headers.iter())
                .map(|mapping| &mapping.header)
                .chain(
                    enterprise_auth
                        .iter()
                        .flat_map(EnterpriseAuthPolicy::owned_headers),
                )
                .chain(
                    oidc_rp
                        .iter()
                        .flat_map(|policy| policy.identity_headers.iter())
                        .map(|mapping| &mapping.header),
                )
            {
                if !owned_identity_headers.insert(header.clone()) {
                    bail!(
                        "route `{}` assigns enterprise identity header `{header}` more than once",
                        c.id
                    );
                }
            }
            if oidc_rp.is_some()
                && ((basic_auth.is_some() || digest_auth.is_some())
                    || !api_keys.is_empty()
                    || !hmac_auth.is_empty()
                    || !jwt_auth.is_empty()
                    || !enterprise_auth.is_empty())
            {
                bail!(
                    "route `{}` oidc_rp cannot be combined with header-based local authentication",
                    c.id
                );
            }
            let hedge = c
                .hedge
                .as_ref()
                .map(|cfg| HedgePolicy::build(cfg, c.id.as_str(), c.uri.trim()))
                .transpose()?;
            if hedge.is_some() && pass_request_body {
                bail!(
                    "route `{}` hedge requires ProxyPassRequestBody=false so every duplicate is provably bodyless",
                    c.id
                );
            }
            if hedge.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot enable hedge because internal replay bypasses the public request gate",
                    c.id
                );
            }
            cache_invalidations.sort();
            cache_invalidations.dedup();
            if cache_invalidations.len() > 8 {
                bail!(
                    "route `{}` proxy_cache_purge supports at most 8 unique targets",
                    c.id
                );
            }
            if http_cache.is_some()
                && ((basic_auth.is_some() || digest_auth.is_some())
                    || !api_keys.is_empty()
                    || !hmac_auth.is_empty()
                    || !jwt_auth.is_empty()
                    || !enterprise_auth.is_empty()
                    || !ext_authz.is_empty())
            {
                bail!(
                    "route `{}` public proxy_cache cannot be combined with authentication until an explicit tenant/user scope is configured",
                    c.id
                );
            }
            if http_cache.is_some()
                && response_headers
                    .iter()
                    .any(ResponseHeaderOp::needs_request_context)
            {
                bail!(
                    "route `{}` public proxy_cache cannot cache request-dependent response headers; make the header static or disable cache",
                    c.id
                );
            }
            if let (Some(cache), Some(cors)) = (&http_cache, &cors) {
                if cors.allow_origin.varies_by_origin(cors.allow_credentials)
                    && !cache.covers_vary(&http::header::ORIGIN)
                {
                    bail!(
                        "route `{}` proxy_cache with echo CORS requires vary=Origin to prevent cross-origin cache leakage",
                        c.id
                    );
                }
            }
            if http_cache
                .as_ref()
                .is_some_and(|cache| cache.stale_enabled())
                && (direct_response.is_some()
                    || static_serve.is_some()
                    || !error_pages.is_empty()
                    || x_accel_redirect
                    || !mirrors.is_empty())
            {
                bail!(
                    "route `{}` stale-while-revalidate cannot be combined with return/static/error_page/x_accel_redirect/mirror because background replay would not be equivalent",
                    c.id
                );
            }
            let request_validation = c
                .request_validation
                .as_ref()
                .map(|cfg| RequestValidationPlan::build(cfg, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` request_validation", c.id))?;
            let request_transform = c
                .request_transform
                .as_ref()
                .map(|cfg| BodyTransformPlan::build(cfg, c.id.as_str(), "request"))
                .transpose()
                .with_context(|| format!("route `{}` request_transform", c.id))?
                .map(Arc::new);
            let response_transform = c
                .response_transform
                .as_ref()
                .map(|cfg| BodyTransformPlan::build(cfg, c.id.as_str(), "response"))
                .transpose()
                .with_context(|| format!("route `{}` response_transform", c.id))?
                .map(Arc::new);
            let response_contract = c
                .response_contract
                .as_ref()
                .map(|cfg| ResponseContractPlan::build(cfg, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` response_contract", c.id))?
                .map(Arc::new);
            let waf = c
                .waf
                .as_ref()
                .map(|cfg| WafPolicy::build(cfg, config_dir))
                .transpose()
                .with_context(|| format!("route `{}` waf", c.id))?
                .map(Arc::new);
            let geoip = c
                .geoip
                .as_ref()
                .map(|cfg| GeoIpPolicy::build(cfg, config_dir, &mut geoip_catalog))
                .transpose()
                .with_context(|| format!("route `{}` geoip", c.id))?
                .map(Arc::new);
            let bot = c
                .bot
                .as_ref()
                .map(|cfg| BotPolicy::build(cfg, config_dir))
                .transpose()
                .with_context(|| format!("route `{}` bot", c.id))?
                .map(Arc::new);
            let csrf = c
                .csrf
                .as_ref()
                .map(|cfg| CsrfPolicy::build(cfg, config_dir))
                .transpose()
                .with_context(|| format!("route `{}` csrf", c.id))?
                .map(Arc::new);
            let dlp = c
                .dlp
                .as_ref()
                .map(DlpPolicy::build)
                .transpose()
                .with_context(|| format!("route `{}` dlp", c.id))?
                .map(Arc::new);
            let graphql_guard = c
                .graphql_guard
                .as_ref()
                .map(|cfg| GraphqlGuardPolicy::build(cfg, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` graphql_guard", c.id))?;
            let traffic_limit = c
                .traffic_limit
                .as_ref()
                .map(|cfg| build_traffic_limit(cfg, &c.uri))
                .transpose()
                .with_context(|| format!("route `{}` traffic_limit", c.id))?
                .map(Arc::new);
            let forward_proxy = c
                .forward_proxy
                .as_ref()
                .map(
                    |cfg| -> Result<crate::protocols::forward_proxy::ForwardProxyPolicy> {
                        let mut policy =
                            crate::protocols::forward_proxy::ForwardProxyPolicy::build(
                                &cfg.allowed_ports,
                                &cfg.allowed_hosts,
                                &cfg.allowed_cidrs,
                                cfg.allow_private,
                            )?;
                        policy.idle_timeout_ms = cfg.idle_timeout_ms;
                        policy.max_lifetime_ms = cfg.max_lifetime_ms;
                        policy.max_bytes = cfg.max_bytes;
                        policy.connect_timeout_ms = cfg.connect_timeout_ms;
                        policy.set_self_addrs(self_addrs.to_vec());
                        Ok(policy)
                    },
                )
                .transpose()
                .with_context(|| format!("route `{}` forward_proxy", c.id))?
                .map(Arc::new);
            let webtransport = c
                .webtransport
                .as_ref()
                .map(|cfg| crate::protocols::masque::WebTransportPolicy::build(cfg, config_dir))
                .transpose()
                .with_context(|| format!("route `{}` webtransport", c.id))?
                .map(Arc::new);
            let early_data = c
                .early_data
                .as_ref()
                .map(crate::protocols::masque::EarlyDataRoutePolicy::build)
                .transpose()
                .with_context(|| format!("route `{}` early_data", c.id))?
                .flatten();
            let ws_frame = c
                .ws_frame
                .as_ref()
                .map(|cfg| crate::protocols::ws_frame::FramePolicy::build(cfg, config_dir))
                .transpose()
                .with_context(|| format!("route `{}` ws_frame", c.id))?
                .map(Arc::new);
            let degraphql = c
                .degraphql
                .as_ref()
                .map(|cfg| {
                    DegraphqlPlan::build(
                        cfg,
                        graphql_guard.as_ref(),
                        predicates.as_slice(),
                        c.id.as_str(),
                    )
                })
                .transpose()
                .with_context(|| format!("route `{}` degraphql", c.id))?
                .map(Arc::new);
            let opa_authorization = c
                .opa_authorization
                .as_ref()
                .map(|cfg| OpaPolicy::build(cfg, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` opa_authorization", c.id))?
                .map(Arc::new);
            let casbin_authorization = c
                .casbin_authorization
                .as_ref()
                .map(|cfg| CasbinPolicy::build(cfg, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` casbin_authorization", c.id))?
                .map(Arc::new);
            let wasm_plugins = (!c.wasm_plugins.is_empty())
                .then(|| WasmPluginChain::build(&c.wasm_plugins, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` wasm_plugins", c.id))?
                .map(Arc::new);
            for script in &c.script_plugins {
                script.validate()?;
            }
            anyhow::ensure!(
                c.script_plugins.len() + c.wasm_plugins.len() <= 16,
                "combined script and Wasm plugin count exceeds 16"
            );
            #[cfg(feature = "lua-scripts")]
            let script_plugins = (!c.script_plugins.is_empty())
                .then(|| {
                    // 客体不能读取或覆盖认证凭据与签名字段；这些名称可能由业务配置而不是固定协议定义。
                    let mut protected_headers = owned_identity_headers.clone();
                    for policy in &api_keys {
                        if let ApiKeySource::Header(name) = &policy.source {
                            protected_headers.insert(name.clone());
                        }
                    }
                    for policy in &jwt_auth {
                        if let JwtTokenSource::Header(name) = &policy.source {
                            protected_headers.insert(name.clone());
                        }
                    }
                    for policy in &hmac_auth {
                        protected_headers.insert(policy.signature_header.clone());
                        protected_headers.insert(policy.timestamp_header.clone());
                        protected_headers.extend(policy.nonce_header.iter().cloned());
                        protected_headers.extend(policy.signed_headers.iter().cloned());
                    }
                    crate::extensions::scripts::Chain::build(
                        &c.script_plugins,
                        config_dir,
                        &c.id,
                        &protected_headers,
                    )
                })
                .transpose()?
                .map(Arc::new);
            let external_plugins = (!c.external_plugins.is_empty())
                .then(|| ExternalPluginChain::build(&c.external_plugins, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` external_plugins", c.id))?
                .map(Arc::new);
            let ext_proc = c
                .ext_proc
                .as_ref()
                .map(|cfg| {
                    ExtProcPlan::build(
                        cfg,
                        config_dir,
                        c.id.as_str(),
                        &owned_identity_headers,
                        c.inference_pool.is_some(),
                    )
                })
                .transpose()
                .with_context(|| format!("route `{}` ext_proc", c.id))?
                .map(Arc::new);
            let inference_pool = c
                .inference_pool
                .as_ref()
                .map(|cfg| InferencePoolPolicy::build(cfg, c, ext_proc.as_ref()))
                .transpose()
                .with_context(|| format!("route `{}` inference_pool", c.id))?;
            if graphql_guard.is_some()
                && (llm.is_some()
                    || static_serve.is_some()
                    || bff_aggregation.is_some()
                    || mock_response.is_some()
                    || direct_response.is_some()
                    || !conditional_returns.is_empty())
            {
                bail!(
                    "route `{}` graphql_guard requires an HTTP upstream and cannot combine with llm/serve.static/return/if-return",
                    c.id
                );
            }
            if traffic_limit.as_ref().is_some_and(|policy| {
                matches!(
                    policy.cost_source,
                    crate::runtime::traffic_limit::CostSource::GraphqlCost
                )
            }) {
                // 成本必须对应真正发送的查询；握手没有消息成本，解析后的正文改写会使证据失效。
                anyhow::ensure!(
                    graphql_guard.is_some()
                        && !c.graphql_guard.as_ref().is_some_and(|guard| {
                            guard.allow_websocket_subscriptions
                        })
                        && request_transform.is_none()
                        && pass_request_body
                        && !internal
                        && error_pages.is_empty()
                        && !x_accel_redirect,
                    "route `{}` graphql_cost requires graphql_guard, unchanged forwarded body and no WebSocket subscriptions or internal redirects",
                    c.id
                );
            }
            if let Some(plan) = traffic_limit
                .as_ref()
                .and_then(|policy| policy.usage.as_ref())
            {
                // 内部改投与多个终端会改变计费权威；完整候选必须先绑定唯一、实际执行的来源。
                anyhow::ensure!(
                    agent.is_none() && dubbo.is_none() && grpc_edge.is_none()
                        && c.cgi.is_none() && c.webdav.is_none() && c.media.is_none()
                        && static_serve.is_none() && bff_aggregation.is_none()
                        && mock_response.is_none() && direct_response.is_none()
                        && conditional_returns.is_empty() && !internal
                        && error_pages.is_empty() && !x_accel_redirect && mirrors.is_empty(),
                    "route `{}` trusted_usage requires one upstream authority without local terminals, mirrors or internal redirects", c.id
                );
                match plan.source {
                    crate::runtime::traffic_limit::usage::Source::ProviderTokens => {
                        anyhow::ensure!(
                            llm.as_ref().is_some_and(|policy| policy.api_type
                                == crate::ai::llm::LlmApiType::ChatCompletions)
                                && c.llm.as_ref().is_some_and(|raw| raw
                                    .models
                                    .iter()
                                    .all(|model| !model.native_passthrough)),
                            "route `{}` provider_tokens requires parsed Chat Completions models",
                            c.id
                        );
                    }
                    crate::runtime::traffic_limit::usage::Source::ResponseHeader(_) => {
                        anyhow::ensure!(llm.is_none(),
                            "route `{}` response_header requires an HTTP upstream; LLM uses provider_tokens", c.id);
                    }
                }
            }
            if degraphql.is_some()
                && (request_validation.is_some()
                    || request_transform.is_some()
                    || http_cache.is_some()
                    || internal
                    || llm.is_some()
                    || static_serve.is_some()
                    || bff_aggregation.is_some()
                    || mock_response.is_some()
                    || direct_response.is_some()
                    || !conditional_returns.is_empty()
                    || !mirrors.is_empty()
                    || strip_prefix > 0
                    || rewrite_prefix.is_some()
                    || gateway_rewrite_full_path.is_some())
            {
                bail!(
                    "route `{}` degraphql cannot combine with validation/cache/internal/terminal backends/mirror/path rewrite",
                    c.id
                );
            }
            if grpc_transcoding.is_some()
                && (request_validation.is_some()
                    || request_transform.is_some()
                    || response_transform.is_some()
                    || response_contract.is_some()
                    || graphql_guard.is_some()
                    || degraphql.is_some()
                    || http_cache.is_some()
                    || hedge.is_some()
                    || internal
                    || !mirrors.is_empty()
                    || !pass_request_body
                    || strip_prefix > 0
                    || rewrite_prefix.is_some()
                    || gateway_rewrite_full_path.is_some()
                    || direct_response.is_some()
                    || !conditional_returns.is_empty())
            {
                // descriptor 转码必须唯一拥有 request/response body 和 RPC path；若先后叠加另一条
                // 聚合/重写管线，会让 schema、鉴权后的 payload 与真正发往上游的字节失配。
                bail!(
                    "route `{}` grpc_transcoding cannot combine with body-owning validation/GraphQL/cache/hedge/mirror/internal/return or path/body rewrite",
                    c.id
                );
            }
            if dubbo.is_some()
                && (request_validation.is_some()
                    || request_transform.is_some()
                    || graphql_guard.is_some()
                    || degraphql.is_some()
                    || http_cache.is_some()
                    || !mirrors.is_empty()
                    || strip_prefix > 0
                    || rewrite_prefix.is_some()
                    || gateway_rewrite_full_path.is_some()
                    || !pass_request_body)
            {
                bail!(
                    "route `{}` dubbo cannot combine with validation/GraphQL/cache/mirror/path rewrite/body-off",
                    c.id
                );
            }
            if opa_authorization.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare opa_authorization because internal reroutes do not execute the public authorization pipeline",
                    c.id
                );
            }
            if casbin_authorization.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare casbin_authorization because internal reroutes do not execute the public authorization pipeline",
                    c.id
                );
            }
            if opa_authorization.is_some() && http_cache.is_some() {
                bail!(
                    "route `{}` cannot combine opa_authorization with public proxy_cache until the authorization input is part of the response cache scope",
                    c.id
                );
            }
            if casbin_authorization.is_some() && http_cache.is_some() {
                bail!(
                    "route `{}` cannot combine casbin_authorization with public proxy_cache until authorization input participates in cache scope",
                    c.id
                );
            }
            if wasm_plugins.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare wasm_plugins because internal reroutes do not execute the public pre chain",
                    c.id
                );
            }
            if wasm_plugins.is_some() && http_cache.is_some() {
                bail!(
                    "route `{}` cannot combine wasm_plugins with public proxy_cache until plugin revision and mutations participate in cache scope",
                    c.id
                );
            }
            if external_plugins.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare external_plugins because internal reroutes do not execute the public pre chain",
                    c.id
                );
            }
            if external_plugins.is_some() && http_cache.is_some() {
                bail!(
                    "route `{}` cannot combine external_plugins with public proxy_cache until plugin revision and mutations participate in cache scope",
                    c.id
                );
            }
            if ext_proc.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare ext_proc because internal reroutes do not execute the public extension pipeline",
                    c.id
                );
            }
            if ext_proc.is_some() && http_cache.is_some() {
                bail!(
                    "route `{}` cannot combine ext_proc with public proxy_cache until processor identity and mutations participate in cache scope",
                    c.id
                );
            }
            if inference_pool.is_some()
                && (internal
                    || static_serve.is_some()
                    || bff_aggregation.is_some()
                    || mock_response.is_some()
                    || direct_response.is_some()
                    || llm.is_some()
                    || !mirrors.is_empty()
                    || hedge.is_some())
            {
                bail!(
                    "route `{}` inference_pool requires one ordinary HTTP upstream without internal, terminal, mirror, hedge, or llm modes",
                    c.id
                );
            }
            if opa_authorization
                .as_ref()
                .is_some_and(|policy| policy.requires_identity())
                && basic_auth.is_none()
                && digest_auth.is_none()
                && jwt_auth.is_empty()
                && enterprise_auth.is_empty()
                && !api_keys.iter().any(|policy| policy.consumer.is_some())
            {
                bail!(
                    "route `{}` opa_authorization require_identity=true needs Basic, Digest, JWT, or API-Key with consumer",
                    c.id
                );
            }
            if casbin_authorization
                .as_ref()
                .is_some_and(|policy| policy.requires_identity())
                && basic_auth.is_none()
                && digest_auth.is_none()
                && jwt_auth.is_empty()
                && enterprise_auth.is_empty()
                && !api_keys.iter().any(|policy| policy.consumer.is_some())
                && c.layer
                    .as_ref()
                    .is_none_or(|layer| layer.parent_ref.is_none())
            {
                bail!(
                    "route `{}` casbin_authorization require_identity=true needs Basic, Digest, JWT, or API-Key with consumer",
                    c.id
                );
            }
            if usage_plan
                .as_ref()
                .is_some_and(|policy| policy.require_consumer)
                && basic_auth.is_none()
                && digest_auth.is_none()
                && jwt_auth.is_empty()
                && enterprise_auth.is_empty()
                && !api_keys.iter().any(|policy| policy.consumer.is_some())
                && c.layer
                    .as_ref()
                    .is_none_or(|layer| layer.parent_ref.is_none())
            {
                bail!(
                    "route `{}` usage_plan require_consumer=true needs Basic, Digest, JWT, or API-Key with consumer",
                    c.id
                );
            }
            if agent.is_some() {
                // Agent 自己持有会话和工具授权边界；通用重路由、缓存与重复外呼不能绕过动作级门禁。
                anyhow::ensure!(request_validation.is_none() && request_transform.is_none() && response_transform.is_none()
                    && response_contract.is_none() && http_cache.is_none() && graphql_guard.is_none() && degraphql.is_none()
                    && direct_response.is_none() && conditional_returns.is_empty() && mirrors.is_empty() && hedge.is_none()
                    && !x_accel_redirect && error_pages.is_empty() && !internal && ext_proc.is_none()
                    && wasm_plugins.is_none() && external_plugins.is_none() && pass_request_body && pass_request_headers
                    && request_headers.is_empty() && response_headers.is_empty() && c.resolved_upstream_credentials.is_empty(),
                    "route `{}` agent cannot combine body-owning filters, cache, reroute, mirror, hedge or internal return", c.id);
                anyhow::ensure!(
                    (basic_auth.is_some() || digest_auth.is_some())
                        || !jwt_auth.is_empty()
                        || !enterprise_auth.is_empty()
                        || api_keys.iter().any(|policy| policy.consumer.is_some())
                        || oidc_rp.is_some()
                        || c.layer
                            .as_ref()
                            .is_some_and(|layer| layer.parent_ref.is_some()),
                    "route `{}` agent requires a locally verified subject",
                    c.id
                );
            }
            if c.llm.as_ref().is_some_and(|llm| llm.governance.is_some()) {
                // 治理结果已经受身份、来源和输出策略裁决，后置内容改写或共享缓存不能改变其安全含义。
                anyhow::ensure!(wasm_plugins.is_none() && external_plugins.is_none() && ext_proc.is_none()
                    && http_cache.is_none() && mirrors.is_empty() && hedge.is_none() && !internal
                    && !x_accel_redirect && error_pages.is_empty() && pass_request_body && pass_request_headers
                    && request_headers.is_empty() && response_headers.is_empty() && c.resolved_upstream_credentials.is_empty(),
                    "route `{}` AI governance cannot combine plugins, shared cache, reroute, header mutation or duplicated calls", c.id);
                anyhow::ensure!(
                    (basic_auth.is_some() || digest_auth.is_some())
                        || !jwt_auth.is_empty()
                        || !enterprise_auth.is_empty()
                        || api_keys.iter().any(|policy| policy.consumer.is_some())
                        || oidc_rp.is_some()
                        || c.layer
                            .as_ref()
                            .is_some_and(|layer| layer.parent_ref.is_some()),
                    "route `{}` AI governance requires a locally verified subject",
                    c.id
                );
            }
            if llm.is_some()
                && (request_validation.is_some()
                    || request_transform.is_some()
                    || response_transform.is_some()
                    || response_contract.is_some())
            {
                bail!(
                    "route `{}` llm cannot combine generic validation/transform/response contract; the unified LLM contract owns its body lifecycle",
                    c.id
                );
            }
            if bff_aggregation.is_some()
                && (request_validation.is_some()
                    || request_transform.is_some()
                    || graphql_guard.is_some()
                    || http_cache.is_some()
                    || !mirrors.is_empty()
                    || !circuit_breakers.is_empty()
                    || x_accel_redirect
                    || !error_pages.is_empty())
            {
                bail!(
                    "route `{}` bff_aggregation cannot combine request/body validation, GraphQL, cache, mirror, or internal response reroute",
                    c.id
                );
            }
            if mock_response.is_some()
                && (request_validation.is_some()
                    || request_transform.is_some()
                    || graphql_guard.is_some()
                    || http_cache.is_some()
                    || !mirrors.is_empty()
                    || x_accel_redirect
                    || !error_pages.is_empty())
            {
                bail!(
                    "route `{}` mock_response cannot combine validation/cache/mirror/internal response reroute",
                    c.id
                );
            }
            if llm.is_some()
                && (http_cache.is_some()
                    || direct_response.is_some()
                    || static_serve.is_some()
                    || !mirrors.is_empty()
                    || x_accel_redirect
                    || !error_pages.is_empty())
            {
                bail!(
                    "route `{}` llm cannot combine proxy_cache/return/static/mirror/x_accel_redirect/error_page; LLM routes use their own model fallback and semantic cache pipeline",
                    c.id
                );
            }
            if llm
                .as_ref()
                .and_then(|policy| policy.token_quota.as_ref())
                .is_some_and(|quota| {
                    quota.dimension == crate::config::model::LlmQuotaDimensionCfg::ApiKey
                })
                && api_keys.is_empty()
                && c.layer
                    .as_ref()
                    .is_none_or(|layer| layer.parent_ref.is_none())
            {
                bail!(
                    "route `{}` llm.token_quota.dimension=api_key requires at least one api_key auth filter",
                    c.id
                );
            }
            if llm
                .as_ref()
                .and_then(|policy| policy.semantic_cache.as_ref())
                .is_some_and(|cache| cache.scope == crate::config::model::LlmCacheScopeCfg::ApiKey)
                && api_keys.is_empty()
                && c.layer
                    .as_ref()
                    .is_none_or(|layer| layer.parent_ref.is_none())
            {
                bail!(
                    "route `{}` llm.semantic_cache.scope=api_key requires at least one api_key auth filter",
                    c.id
                );
            }
            if http_cache.is_some()
                && request_validation
                    .as_ref()
                    .is_some_and(RequestValidationPlan::validates_body)
            {
                bail!(
                    "route `{}` cannot combine proxy_cache with request body schema because the body is not part of the public cache key",
                    c.id
                );
            }
            if http_cache.is_some() && request_transform.is_some() {
                bail!(
                    "route `{}` cannot combine proxy_cache with request_transform because the transformed body is not part of the public cache key",
                    c.id
                );
            }
            if request_validation.is_some() && (c.long_stream_max_lifetime_ms > 0) {
                bail!(
                    "route `{}` request_validation cannot be combined with long_stream_max_lifetime_ms; schema buffering is a finite HTTP slow path",
                    c.id
                );
            }
            if (request_transform.is_some()
                || response_transform.is_some()
                || response_contract.is_some())
                && c.long_stream_max_lifetime_ms > 0
            {
                bail!(
                    "route `{}` body transformation/response contract cannot combine with long_stream_max_lifetime_ms",
                    c.id
                );
            }
            if request_transform.is_some() && (!pass_request_body || internal) {
                bail!(
                    "route `{}` request_transform requires a public route with proxy_pass_request_body enabled",
                    c.id
                );
            }
            if (request_transform.is_some()
                || response_transform.is_some()
                || response_contract.is_some())
                && (forward_proxy.is_some() || webtransport.is_some() || ws_frame.is_some())
            {
                bail!(
                    "route `{}` body transformation/response contract cannot combine with CONNECT, WebTransport, or WebSocket tunnel semantics",
                    c.id
                );
            }
            if waf.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare waf because internal reroutes do not execute the public security pipeline",
                    c.id
                );
            }
            if geoip.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare geoip because internal reroutes do not execute the public security pipeline",
                    c.id
                );
            }
            if bot.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare bot because internal reroutes do not execute the public security pipeline",
                    c.id
                );
            }
            if csrf.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare csrf because internal reroutes do not execute the public security pipeline",
                    c.id
                );
            }
            if dlp.is_some() && internal {
                bail!(
                    "route `{}` internal route cannot declare dlp because internal reroutes do not execute the public security pipeline",
                    c.id
                );
            }
            if dlp
                .as_ref()
                .is_some_and(|policy| policy.inspects_request_body())
                && (!pass_request_body || c.long_stream_max_lifetime_ms > 0)
            {
                bail!(
                    "route `{}` dlp inspect_request_body cannot combine with proxy_pass_request_body=off or long_stream_max_lifetime_ms",
                    c.id
                );
            }
            if dlp
                .as_ref()
                .is_some_and(|policy| policy.inspects_response_body())
                && c.long_stream_max_lifetime_ms > 0
            {
                bail!(
                    "route `{}` dlp inspect_response_body cannot combine with long_stream_max_lifetime_ms",
                    c.id
                );
            }
            if dlp
                .as_ref()
                .is_some_and(|policy| policy.inspects_response_body())
                && http_cache.is_some()
            {
                // cache fill 包装在响应治理前建立；允许该组合会把遮蔽前字节写入共享缓存，
                // 即使每次下游发送仍再次遮蔽，也已经违反敏感数据不得持久化的不变量。
                bail!(
                    "route `{}` dlp inspect_response_body cannot combine with proxy_cache",
                    c.id
                );
            }
            if waf.as_ref().is_some_and(|policy| policy.inspects_body())
                && (!pass_request_body || c.long_stream_max_lifetime_ms > 0)
            {
                // body WAF 必须在有限请求上独占一次有界聚合；关闭 body 转发或声明长流时继续
                // 接受该组合，会让检查对象与真正业务语义不一致。
                bail!(
                    "route `{}` waf inspect_body cannot combine with proxy_pass_request_body=off or long_stream_max_lifetime_ms",
                    c.id
                );
            }
            let upstream_credentials = UpstreamCredentialPlan::build(
                c.resolved_upstream_credentials.as_slice(),
                config_dir,
                request_headers.as_slice(),
                c.id.as_str(),
            )
            .with_context(|| format!("route `{}` upstream credentials", c.id))?;
            if early_data.is_some() {
                let method_sets = predicates
                    .iter()
                    .filter_map(|predicate| match predicate {
                        Predicate::Method(methods) => Some(methods.as_slice()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    method_sets.len() == 1
                        && !method_sets[0].is_empty()
                        && method_sets[0].iter().all(|method| matches!(
                            *method,
                            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
                        )),
                    "route `{}` early_data requires exactly one Method predicate containing only GET, HEAD, OPTIONS, or TRACE",
                    c.id
                );
                anyhow::ensure!(
                    !c.uri.trim().is_empty() && !c.uri.contains("${") && static_serve.is_none(),
                    "route `{}` early_data requires a fixed HTTP upstream URI",
                    c.id
                );
                anyhow::ensure!(
                    !pass_request_body,
                    "route `{}` early_data requires `proxy_pass_request_body off` so replayable bytes cannot reach the upstream",
                    c.id
                );
                anyhow::ensure!(
                    request_headers.is_empty() && upstream_credentials.is_none(),
                    "route `{}` early_data cannot inject request headers or upstream credentials",
                    c.id
                );
                anyhow::ensure!(
                    basic_auth.is_none()
                && digest_auth.is_none()
                        && api_keys.is_empty()
                        && hmac_auth.is_empty()
                        && jwt_auth.is_empty()
                        && oidc_rp.is_none()
                        && enterprise_auth.is_empty()
                        && ext_authz.is_empty()
                        && opa_authorization.is_none()
                        && casbin_authorization.is_none()
                        && csrf.is_none(),
                    "route `{}` early_data cannot combine with authentication, authorization, or CSRF state",
                    c.id
                );
                anyhow::ensure!(
                    request_validation.is_none()
                        && request_transform.is_none()
                        && response_transform.is_none()
                        && response_contract.is_none()
                        && graphql_guard.is_none()
                        && degraphql.is_none()
                        && wasm_plugins.is_none()
                        && external_plugins.is_none()
                        && llm.is_none()
                        && grpc_edge.is_none()
                        && grpc_transcoding.is_none()
                        && dubbo.is_none()
                        && bff_aggregation.is_none()
                        && forward_proxy.is_none()
                        && webtransport.is_none()
                        && mirrors.is_empty()
                        && cache_invalidations.is_empty(),
                    "route `{}` early_data cannot combine with body-owning, external-call, tunnel, mirror, or write-side-effect filters",
                    c.id
                );
            }
            let signature = predicates_signature(&predicates);
            if request_decompression.is_some() {
                // 普通实体只能由公共请求管线解码一次，专用协议、内部及层级入口不得继承错误的表示边界。
                anyhow::ensure!(!branch && c.layer.is_none() && !internal
                    && c.cgi.is_none() && c.media.is_none() && c.webdav.is_none() && static_serve.is_none()
                    && gateway_redirect.is_none() && mock_response.is_none() && direct_response.is_none()
                    && llm.is_none() && agent.is_none() && grpc_edge.is_none() && grpc_transcoding.is_none()
                    && dubbo.is_none() && bff_aggregation.is_none() && forward_proxy.is_none() && webtransport.is_none()
                    && early_data.is_none() && pass_request_body && pass_request_headers,
                    "request_decompression requires ordinary public HTTP forwarding without special terminals or discarded request entity");
                anyhow::ensure!(request_headers.iter().all(|operation| {
                    let name = match operation {
                        RequestHeaderOp::Set(value) | RequestHeaderOp::Add(value) => &value.name,
                        RequestHeaderOp::Remove(name) => name,
                    };
                    !matches!(name.as_str(), "content-encoding" | "content-length" | "transfer-encoding" | "content-md5" | "digest" | "content-digest" | "repr-digest" | "trailer")
                }), "request_decompression entity headers cannot be overridden by request header policies");
            }
            if !c.script_plugins.is_empty() {
                // 扩展只属于普通公开代理路由；不允许绕过专用协议、层级身份、内部跳转及缓存的所有权边界。
                anyhow::ensure!(!branch && c.layer.is_none() && !internal && !x_accel_redirect && error_pages.is_empty()
                    && c.cgi.is_none() && c.media.is_none() && c.webdav.is_none() && static_serve.is_none()
                    && gateway_redirect.is_none() && mock_response.is_none() && direct_response.is_none()
                    && conditional_returns.is_empty() && llm.is_none() && agent.is_none() && grpc_edge.is_none()
                    && grpc_transcoding.is_none() && dubbo.is_none() && bff_aggregation.is_none()
                    && forward_proxy.is_none() && webtransport.is_none() && early_data.is_none()
                    && mirrors.is_empty() && hedge.is_none() && http_cache.is_none() && cache_invalidations.is_empty()
                    && c.inference_pool.is_none() && ext_proc.is_none() && external_plugins.is_none()
                    && degraphql.is_none() && pass_request_body && pass_request_headers,
                    "script_plugins require ordinary public HTTP forwarding without layered/special terminals, shared cache, alternate execution or external processors");
                // 每个方向只允许一个运行时拥有实体；头部扩展可跨语言串联，数量与工作集仍共享硬门。
                let request_script_body = c.script_plugins.iter().any(|p| {
                    matches!(
                        p.phase,
                        crate::config::scripts::Phase::RequestBody
                            | crate::config::scripts::Phase::RequestBodyStream
                    )
                });
                let response_script_body = c.script_plugins.iter().any(|p| {
                    matches!(
                        p.phase,
                        crate::config::scripts::Phase::ResponseBody
                            | crate::config::scripts::Phase::ResponseBodyStream
                    )
                });
                anyhow::ensure!(
                    !wasm_plugins
                        .as_ref()
                        .is_some_and(|chain| (request_script_body
                            && (chain.has_request_body() || chain.has_request_body_stream()))
                            || (response_script_body
                                && (chain.has_response_body()
                                    || chain.has_response_body_stream()))),
                    "script and Wasm cannot both own the same body direction"
                );
                anyhow::ensure!(
                    !request_script_body || request_transform.is_none(),
                    "request body script conflicts with request transform"
                );
                anyhow::ensure!(
                    !response_script_body
                        || (response_transform.is_none() && sub_filters.is_empty()),
                    "response body script conflicts with response transforms"
                );
            }
            if c.cgi.is_some() {
                // 固定脚本入口不能被其它终端、URI/body 变换、镜像或升级机制改变执行目标。
                anyhow::ensure!(c.uri.starts_with("lb://") && upstream_template.static_literal().is_some()
                    && static_serve.is_none() && gateway_redirect.is_none() && mock_response.is_none()
                    && llm.is_none() && agent.is_none() && grpc_edge.is_none() && grpc_transcoding.is_none()
                    && dubbo.is_none() && bff_aggregation.is_none() && forward_proxy.is_none() && webtransport.is_none()
                    && early_data.is_none() && mirrors.is_empty() && c.hedge.is_none()
                    && request_transform.is_none() && c.degraphql.is_none() && pass_request_body
                    && c.ext_proc.is_none() && c.wasm_plugins.is_empty() && c.external_plugins.is_empty()
                    && c.dlp.as_ref().is_none_or(|policy| policy.action != "redact")
                    && strip_prefix == 0 && rewrite_prefix.is_none() && gateway_rewrite_full_path.is_none()
                    && c.upstream_credentials.is_empty(), "CGI route requires a fixed service and unmodified request entity/path without alternative terminals or callout mirroring");
                anyhow::ensure!(
                    request_headers.iter().all(|operation| {
                        let name = match operation {
                            RequestHeaderOp::Set(value) | RequestHeaderOp::Add(value) => {
                                &value.name
                            }
                            RequestHeaderOp::Remove(name) => name,
                        };
                        !matches!(name.as_str(), "content-length" | "transfer-encoding")
                    }),
                    "CGI entity framing cannot be changed by request header policies"
                );
            }
            if c.media.is_some() {
                // 媒体索引与实体必须作为同一表示输出，不能被其它终端、共享缓存或正文插件重新解释。
                anyhow::ensure!(static_serve.is_some() && c.webdav.is_none() && c.cgi.is_none() && !branch && !internal
                    && gateway_redirect.is_none() && mock_response.is_none() && direct_response.is_none()
                    && llm.is_none() && agent.is_none() && grpc_edge.is_none() && grpc_transcoding.is_none()
                    && dubbo.is_none() && bff_aggregation.is_none() && forward_proxy.is_none() && webtransport.is_none()
                    && early_data.is_none() && mirrors.is_empty() && hedge.is_none() && c.inference_pool.is_none()
                    && request_validation.is_none() && request_transform.is_none() && response_transform.is_none()
                    && response_contract.is_none() && degraphql.is_none() && graphql_guard.is_none()
                    && c.ext_proc.is_none() && wasm_plugins.is_none() && external_plugins.is_none()
                    && c.dlp.as_ref().is_none_or(|policy| policy.action != "redact")
                    && strip_prefix == 0 && rewrite_prefix.is_none() && gateway_rewrite_full_path.is_none()
                    && http_cache.is_none() && cache_invalidations.is_empty() && !x_accel_redirect && error_pages.is_empty()
                    && sub_filters.is_empty() && compression.is_none() && response_headers.is_empty(),
                    "media requires an exact static backend without alternate terminals, entity mutation, compression or shared proxy cache");
                anyhow::ensure!(
                    request_headers.iter().all(|operation| {
                        let name = match operation {
                            RequestHeaderOp::Set(value) | RequestHeaderOp::Add(value) => {
                                &value.name
                            }
                            RequestHeaderOp::Remove(name) => name,
                        };
                        !matches!(
                            name.as_str(),
                            "range"
                                | "if-range"
                                | "if-none-match"
                                | "if-modified-since"
                                | "accept-encoding"
                        )
                    }),
                    "media conditional and representation headers cannot be changed by policies"
                );
            }
            if c.webdav.is_some() {
                // DAV 的资源归属、条件头和实体 framing 必须由唯一协议计划决定，不能在执行前后被其它终端改变。
                anyhow::ensure!(c.cgi.is_none() && !branch && !internal
                    && (static_serve.is_some() || (!c.uri.is_empty() && upstream_template.static_literal().is_some()))
                    && gateway_redirect.is_none() && mock_response.is_none() && direct_response.is_none()
                    && llm.is_none() && agent.is_none() && grpc_edge.is_none() && grpc_transcoding.is_none()
                    && dubbo.is_none() && bff_aggregation.is_none() && forward_proxy.is_none() && webtransport.is_none()
                    && early_data.is_none() && mirrors.is_empty() && hedge.is_none() && c.inference_pool.is_none()
                    && request_validation.is_none() && request_transform.is_none() && response_transform.is_none()
                    && response_contract.is_none() && degraphql.is_none() && graphql_guard.is_none()
                    && c.ext_proc.is_none() && wasm_plugins.is_none() && external_plugins.is_none()
                    && c.dlp.as_ref().is_none_or(|policy| policy.action != "redact")
                    && strip_prefix == 0 && rewrite_prefix.is_none() && gateway_rewrite_full_path.is_none()
                    && http_cache.is_none() && cache_invalidations.is_empty() && !x_accel_redirect && error_pages.is_empty()
                    && sub_filters.is_empty() && compression.is_none() && response_headers.is_empty()
                    && pass_request_body && pass_request_headers && c.resolved_upstream_credentials.is_empty(),
                    "WebDAV requires one exact resource backend without body/path/response mutation, plugins, shared cache or alternate execution");
                anyhow::ensure!(
                    request_headers.iter().all(|operation| {
                        let name = match operation {
                            RequestHeaderOp::Set(value) | RequestHeaderOp::Add(value) => {
                                &value.name
                            }
                            RequestHeaderOp::Remove(name) => name,
                        };
                        !matches!(
                            name.as_str(),
                            "host"
                                | "destination"
                                | "if"
                                | "depth"
                                | "overwrite"
                                | "lock-token"
                                | "timeout"
                                | "content-length"
                                | "transfer-encoding"
                                | "content-type"
                                | "content-encoding"
                                | "accept-encoding"
                                | "if-match"
                                | "if-none-match"
                                | "if-modified-since"
                                | "if-unmodified-since"
                                | "range"
                                | "if-range"
                                | "connection"
                                | "trailer"
                                | "te"
                                | "upgrade"
                        )
                    }),
                    "WebDAV resource, condition and entity headers cannot be changed by policies"
                );
            }
            let has_weight = predicates
                .iter()
                .any(|predicate| matches!(predicate, Predicate::Weight {
                    ..
                }));
            // 子层只参与同父级的受信上下文选择；公开入口冲突检查不能把父子或互斥 claim 当成同一入口。
            if let Some((_, existing)) = (!has_weight
                && !layer_topology
                    .as_ref()
                    .is_some_and(|plan| plan.is_child(&c.id)))
            .then(|| {
                ordered.iter().find(|(order, route)| {
                    !layer_topology
                        .as_ref()
                        .is_some_and(|plan| plan.is_child(&route.id))
                        && *order == c.order
                        && predicates_signature(&route.predicates) == signature
                })
            })
            .flatten()
            {
                bail!(
                    "route `{}` conflicts with route `{}` at same order {} and same predicates",
                    c.id,
                    existing.id,
                    c.order
                );
            }
            ordered.push((
                c.order,
                Arc::new(Route {
                    id: c.id.clone(),
                    id_shared: Arc::from(c.id.as_str()),
                    traffic: Arc::default(),
                    order: c.order,
                    layer: c.layer.clone().map(Arc::new),
                    #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
                    cgi,
                    #[cfg(feature = "webdav")]
                    webdav,
                    #[cfg(feature = "config-providers")]
                    provider_deadline: c.provider_deadline,
                    upstream: c.uri.clone(),
                    upstream_template,
                    predicates,
                    internal,
                    strip_prefix,
                    rewrite_prefix,
                    gateway_rewrite_full_path,
                    preserve_host: c.preserve_host,
                    pass_request_headers,
                    pass_request_body,
                    hedge,
                    request_headers,
                    upstream_credentials,
                    response_headers,
                    sub_filters,
                    compression,
                    request_decompression,
                    http_cache,
                    request_validation,
                    request_transform,
                    response_transform,
                    response_contract,
                    waf,
                    geoip,
                    bot,
                    csrf,
                    dlp,
                    graphql_guard,
                    degraphql,
                    opa_authorization,
                    casbin_authorization,
                    wasm_plugins,
                    #[cfg(feature = "lua-scripts")]
                    script_plugins,
                    external_plugins,
                    ext_proc,
                    inference_pool,
                    bff_aggregation,
                    dubbo,
                    mock_response,
                    fault_injection,
                    usage_plan,
                    llm,
                    agent,
                    grpc_edge,
                    grpc_transcoding,
                    cache_invalidations,
                    cors,
                    fallback_headers,
                    access_rules,
                    referer,
                    limit_except,
                    basic_auth,
                    digest_auth,
                    api_keys,
                    hmac_auth,
                    jwt_auth,
                    oidc_rp,
                    enterprise_auth,
                    ext_authz,
                    satisfy,
                    conditional_returns,
                    limit_req,
                    limit_conn,
                    limit_rate,
                    traffic_limit,
                    forward_proxy,
                    webtransport,
                    early_data,
                    ws_frame,
                    circuit_breakers,
                    error_pages,
                    proxy_intercept_errors,
                    x_accel_redirect,
                    direct_response,
                    gateway_redirect,
                    static_serve,
                    mirrors,
                    variables: variables.clone(),
                    long_stream_idle_timeout_ms: c.long_stream_idle_timeout_ms,
                    request_timeout_ms: c.request_timeout_ms,
                    backend_request_timeout_ms: c.backend_request_timeout_ms,
                    long_stream_max_lifetime_ms: c.long_stream_max_lifetime_ms,
                }),
            ));
        }
        // 按 order 稳定排序，数值小者优先；同 order 保持配置书写顺序。
        ordered.sort_by_key(|(order, _)| *order);
        let weighted_groups = compile_weighted_groups(ordered.as_slice())?;
        let routes = ordered
            .into_iter()
            .map(|(_, route)| route)
            .collect::<Vec<_>>();
        for route in &routes {
            for target in &route.cache_invalidations {
                let target_route = routes
                    .iter()
                    .find(|candidate| candidate.id == *target)
                    .with_context(|| {
                        format!(
                            "route `{}` proxy_cache_purge target `{target}` does not exist in the same proxy",
                            route.id
                        )
                    })?;
                if target_route.http_cache.is_none() {
                    bail!(
                        "route `{}` proxy_cache_purge target `{target}` has no proxy_cache",
                        route.id
                    );
                }
            }
        }
        let has_response_compression = routes.iter().any(|route| route.compression.is_some());
        let has_digest_auth = routes.iter().any(|route| route.digest_auth.is_some());
        let layers = layer_topology
            .map(|topology| layers::Plan::build(topology, cfgs, &routes))
            .transpose()?;
        Ok(Router {
            routes,
            has_response_compression,
            has_digest_auth,
            weighted_groups,
            layers,
        })
    }

    /// 业务作用：顺序匹配,第一个全命中的路由胜出。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求的 head parts。
    pub fn match_route(&self, parts: &Parts) -> Option<Arc<Route>> {
        self.match_route_with_key(parts, b"")
    }

    /// 业务作用：只选择公开根入口或普通路由，子层必须先经过父层安全策略才能进入。
    ///
    /// 参数说明：
    /// - `parts`：是规范化公开请求
    /// - `request_key`：是本次请求的稳定灰度键。
    ///
    /// 返回：首个满足入口约束的路由或权重组成员；无匹配为 None，不执行策略或后端。
    ///
    /// Weight route 在 build 阶段已保证同组具有相同 order 与非权重 predicates。运行时先按
    /// 原有顺序找到首个可用组，再用 `group + request_key` 的稳定哈希落桶；相同 key 在配置
    /// 不变时始终落到同一成员。遍历与查表均借用快照内存，不在热路径分配候选集合。
    pub fn match_route_with_key(&self, parts: &Parts, request_key: &[u8]) -> Option<Arc<Route>> {
        for route in &self.routes {
            if route.internal
                || self
                    .layers
                    .as_ref()
                    .is_some_and(|plan| plan.topology.is_child(&route.id))
                || !route
                    .predicates
                    .iter()
                    .filter(|predicate| !matches!(predicate, Predicate::Weight {
                        ..
                    }))
                    .all(|predicate| predicate.matches(parts))
            {
                continue;
            }
            let Some((group, _)) = route_weight(route.as_ref()) else {
                return Some(route.clone());
            };
            let compiled = self
                .weighted_groups
                .get(group)
                .expect("validated Weight group remains compiled");
            let mut bucket =
                stable_weight_hash(group.as_bytes(), request_key) % compiled.total_weight;
            for (index, weight) in &compiled.members {
                let weight = u64::from(*weight);
                if bucket < weight {
                    return Some(self.routes[*index].clone());
                }
                bucket -= weight;
            }
            unreachable!("positive validated Weight total must select one member");
        }
        None
    }

    /// 业务作用：顺序匹配内部 route,仅供 error_page/reroute/X-Accel 类内部跳转使用。
    ///
    /// 参数说明：
    /// - `parts`: 内部重写后的请求 head。
    pub fn match_internal_route(&self, parts: &Parts) -> Option<Arc<Route>> {
        self.routes
            .iter()
            .find(|r| r.internal && r.predicates.iter().all(|p| p.matches(parts)))
            .cloned()
    }

    /// 业务作用：返回静态 `lb://service` 引用,供 admin 发现视图展示 service 被哪些 route 使用。
    ///
    /// 动态 upstream 模板运行期才可求值,此处不猜测,避免把 header/query 驱动的路由误归属到某个 service。
    pub fn upstream_service_refs(&self) -> Vec<(String, String)> {
        self.routes
            .iter()
            .filter_map(|route| {
                route
                    .upstream_template
                    .static_literal()
                    .and_then(|upstream| upstream.strip_prefix("lb://"))
                    .filter(|service| !service.is_empty())
                    .map(|service| (service.to_string(), route.id.clone()))
            })
            .collect()
    }

    /// 业务作用：当前不可变 route slice。只供低频管理/失效对账遍历，不暴露可变入口。
    pub(crate) fn routes(&self) -> &[Arc<Route>] {
        &self.routes
    }

    /// 业务作用：按稳定 id 定位 route；管理面 PURGE/失效消息使用，非请求匹配热路径。
    pub(crate) fn route_by_id(&self, route_id: &str) -> Option<&Arc<Route>> {
        self.routes.iter().find(|route| route.id == route_id)
    }

    /// 业务作用：是否至少一条 route 启用响应压缩。
    ///
    /// internal reroute 也来自同一 Router，因此用 proxy 级汇总而不是只看首条命中 route，避免
    /// `error_page`/`X-Accel-Redirect` 跳到压缩 route 后丢失原客户端协商能力。
    #[inline]
    pub(crate) fn has_response_compression(&self) -> bool {
        self.has_response_compression
    }

    /// 业务作用：是否有 route 显式要求 Redis L2；快照构建期用来交叉校验 runtime backend。
    pub(crate) fn uses_http_cache_l2(&self) -> bool {
        self.routes.iter().any(|route| {
            route
                .http_cache
                .as_ref()
                .is_some_and(|policy| policy.l2_enabled())
        })
    }

    /// 业务作用：统计启用 gRPC 边缘模式的 route 数，供管理面展示快照接线情况。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已编译 edge route 数；0 表示当前快照全部走普通 L7。
    pub(crate) fn grpc_edge_route_count(&self) -> usize {
        self.routes
            .iter()
            .filter(|route| route.grpc_edge.is_some())
            .count()
    }

    /// 业务作用：统计启用 descriptor 转码的 route 与允许 RPC 数量，供快照摘要证明 feature
    /// 接线而不暴露 service/method 名称。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`(route 数, method 数)`；未配置时均为零。
    pub(crate) fn grpc_transcoding_summary(&self) -> (usize, usize) {
        self.routes.iter().fold((0, 0), |(routes, methods), route| {
            route
                .grpc_transcoding
                .as_ref()
                .map_or((routes, methods), |plan| {
                    (routes + 1, methods + plan.method_count())
                })
        })
    }

    /// 业务作用：是否有 LLM route 显式要求 Redis 语义缓存；与 HTTP cache 共用 bootstrap Redis 连接。
    pub(crate) fn uses_llm_cache_l2(&self) -> bool {
        self.routes.iter().any(|route| {
            route
                .llm
                .as_ref()
                .and_then(|policy| policy.semantic_cache.as_ref())
                .is_some_and(|cache| cache.l2_enabled)
        })
    }

    /// 业务作用：汇总本 listener 下 WebTransport route 声明的最大 stream 并发预算，
    /// 供 QUIC transport 在发布前核对底层 `MAX_STREAMS` 硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回所有 WebTransport route 中最大的双向与单向 stream 上限；
    /// 未配置 WebTransport 时返回 `(0, 0)`。
    pub(crate) fn webtransport_stream_budget(&self) -> (u64, u64) {
        self.routes
            .iter()
            .filter_map(|route| route.webtransport.as_ref())
            .fold((0, 0), |(bidi, uni), policy| {
                (
                    bidi.max(policy.budget.max_bidi_streams),
                    uni.max(policy.budget.max_uni_streams),
                )
            })
    }

    /// 业务作用：判断 listener 的路由表是否真正消费 0-RTT，供 TLS 能力声明与
    /// route 显式授权做双向一致性校验。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少一条 route 含有已启用 early-data 计划时返回 `true`。
    pub(crate) fn uses_early_data(&self) -> bool {
        self.routes.iter().any(|route| route.early_data.is_some())
    }

    /// 业务作用：返回当前快照的路由数量，供健康检查和运行状态展示。
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// 业务作用：判断路由表是否为空。
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Route {
    /// 业务作用：为管理面语义 diff 产生稳定、低敏的 route 结构摘要。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：包含断言签名、upstream、rewrite 和已启用 filter 名称；不包含 API key、token、证书或其它 SecretSource 解析值。
    pub(crate) fn admin_semantic_json(&self) -> serde_json::Value {
        let value = serde_json::json!({
            "id": self.id,
            "order": self.order,
            "upstream": self.upstream,
            "internal": self.internal,
            "predicates": self.predicates.iter().map(Predicate::signature).collect::<Vec<_>>(),
            "strip_prefix": self.strip_prefix,
            "rewrite_prefix": self.rewrite_prefix.as_ref().map(|rewrite| serde_json::json!({
                "from": rewrite.from,
                "to": rewrite.to,
            })),
            "rewrite_full_path": self.gateway_rewrite_full_path,
            "preserve_host": self.preserve_host,
            "filters": self.admin_filter_chain(),
            "layer": self.layer.as_ref().map(|layer| serde_json::json!({
                "parent_ref": layer.parent_ref,
                "branch": layer.branch,
                "match_count": layer.matches.len(),
                "context_names": layer.context.keys().collect::<Vec<_>>(),
                "policy_fingerprint": nasa::crypto::sha256(&serde_json::to_string(layer.as_ref()).expect("serializable layer configuration")),
            })),
        });
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        let value = {
            let mut value = value;
            if let Some(cgi) = &self.cgi {
                value["cgi"] = cgi.semantic();
            }
            value
        };
        #[cfg(feature = "webdav")]
        let value = {
            let mut value = value;
            if let Some(webdav) = &self.webdav {
                value["webdav"] = webdav.semantic();
            }
            value
        };
        #[cfg(feature = "media-streaming")]
        let value = {
            let mut value = value;
            if let Some(media) = self
                .static_serve
                .as_ref()
                .and_then(StaticServe::media_semantic)
            {
                value["media"] = media;
            }
            value
        };
        #[cfg(feature = "lua-scripts")]
        let value = {
            let mut value = value;
            if let Some(scripts) = &self.script_plugins {
                value["script_plugins"] = scripts.semantic();
            }
            value
        };
        value
    }

    /// 业务作用：按数据面执行类别输出不含密钥的 filter 链，供路由推演和审查展示。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回已实际编译进 route 的功能名称；同类多条策略只显示一次，并按固定顺序产生结果。
    pub(crate) fn admin_filter_chain(&self) -> Vec<&'static str> {
        let mut filters = Vec::new();
        let mut push = |enabled: bool, name| {
            if enabled {
                filters.push(name);
            }
        };
        push(!self.access_rules.is_empty(), "access");
        push(self.referer.is_some(), "referer");
        push(self.limit_except.is_some(), "limit_except");
        push(self.basic_auth.is_some(), "basic_auth");
        push(self.digest_auth.is_some(), "digest_auth");
        push(!self.api_keys.is_empty(), "api_key");
        push(!self.hmac_auth.is_empty(), "hmac_auth");
        push(!self.jwt_auth.is_empty(), "jwt_auth");
        push(self.oidc_rp.is_some(), "oidc_rp");
        push(!self.enterprise_auth.is_empty(), "enterprise_auth");
        push(!self.ext_authz.is_empty(), "ext_authz");
        push(self.opa_authorization.is_some(), "opa");
        push(self.casbin_authorization.is_some(), "casbin");
        push(!self.limit_req.is_empty(), "limit_req");
        push(!self.limit_conn.is_empty(), "limit_conn");
        push(!self.circuit_breakers.is_empty(), "circuit_breaker");
        push(self.request_validation.is_some(), "request_validation");
        push(self.request_transform.is_some(), "request_transform");
        push(self.response_transform.is_some(), "response_transform");
        push(self.response_contract.is_some(), "response_contract");
        push(self.waf.is_some(), "waf");
        push(self.geoip.is_some(), "geoip");
        push(self.bot.is_some(), "bot");
        push(self.csrf.is_some(), "csrf");
        push(self.dlp.is_some(), "dlp");
        push(self.graphql_guard.is_some(), "graphql_guard");
        push(self.usage_plan.is_some(), "usage_plan");
        push(self.wasm_plugins.is_some(), "wasm");
        #[cfg(feature = "lua-scripts")]
        push(self.script_plugins.is_some(), "lua");
        push(self.external_plugins.is_some(), "external_plugin");
        push(self.http_cache.is_some(), "http_cache");
        push(self.compression.is_some(), "compression");
        push(
            self.request_decompression.is_some(),
            "request_decompression",
        );
        push(!self.mirrors.is_empty(), "mirror");
        push(self.grpc_edge.is_some(), "grpc_edge");
        push(self.grpc_transcoding.is_some(), "grpc_transcoding");
        push(self.webtransport.is_some(), "webtransport");
        push(self.early_data.is_some(), "early_data");
        filters
    }

    /// 业务作用：按本 route 的 allow/deny 规则判断客户端 IP 是否允许访问。
    ///
    /// 参数说明：
    /// - `ip`: 真实客户端 IP。
    pub fn permits_ip(&self, ip: IpAddr) -> bool {
        for rule in &self.access_rules {
            if rule.matches(ip) {
                return rule.action == AccessAction::Allow;
            }
        }
        true
    }

    /// 业务作用：按 `valid_referers` 判断请求 Referer 是否允许。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    pub fn permits_referer(&self, parts: &Parts) -> bool {
        self.referer
            .as_ref()
            .map(|policy| policy.matches(parts))
            .unwrap_or(true)
    }

    /// 业务作用：按 `limit_except` 判断请求方法是否允许。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    pub fn permits_method(&self, parts: &Parts) -> bool {
        self.limit_except
            .as_ref()
            .map(|methods| methods.contains(&parts.method))
            .unwrap_or(true)
    }

    /// 业务作用：按 数据面同步鉴权子链判断请求是否通过认证。
    ///
    /// ext_authz 需要异步外呼，由代理层拿 [`SyncAuthState`] 后继续执行；本函数仅处理纯同步策略。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    pub fn permits_auth(&self, parts: &Parts) -> bool {
        self.ext_authz.is_empty() && self.sync_auth_state(parts).ok
    }

    /// 业务作用：计算本地认证组合；Digest 只承认已完成严格重放登记的请求凭证。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    pub fn sync_auth_state(&self, parts: &Parts) -> SyncAuthState {
        let has_basic = self.basic_auth.is_some();
        let has_digest = self.digest_auth.is_some();
        let digest_ok = self
            .digest_auth
            .as_ref()
            .and_then(|policy| policy.consumer(parts))
            .is_some();
        let has_api_key = !self.api_keys.is_empty();
        let has_hmac = !self.hmac_auth.is_empty();
        let has_jwt = !self.jwt_auth.is_empty();
        let has_enterprise = !self.enterprise_auth.is_empty();
        if !has_basic && !has_digest && !has_api_key && !has_hmac && !has_jwt && !has_enterprise {
            return SyncAuthState {
                configured: false,
                ok: true,
            };
        }
        let basic_ok = self
            .basic_auth
            .as_ref()
            .map(|policy| policy.matches(parts))
            .unwrap_or(false);
        let api_key_ok = self.api_keys.iter().any(|policy| policy.matches(parts));
        let hmac_ok = self.hmac_auth.iter().any(|policy| policy.matches(parts));
        let jwt_ok = self.jwt_auth.iter().any(|policy| policy.matches(parts));
        let enterprise_ok = false;
        let ok = match self.satisfy {
            SatisfyMode::All => {
                (!has_basic || basic_ok)
                    && (!has_digest || digest_ok)
                    && (!has_api_key || api_key_ok)
                    && (!has_hmac || hmac_ok)
                    && (!has_jwt || jwt_ok)
                    && (!has_enterprise || enterprise_ok)
            }
            SatisfyMode::Any => {
                (has_basic && basic_ok)
                    || (has_digest && digest_ok)
                    || (has_api_key && api_key_ok)
                    || (has_hmac && hmac_ok)
                    || (has_jwt && jwt_ok)
                    || (has_enterprise && enterprise_ok)
            }
        };
        SyncAuthState {
            configured: true,
            ok,
        }
    }

    /// 业务作用：执行包含远端 JWKS/OIDC 刷新的完整本地认证组合，供数据面在 ext_authz 前冻结可信身份。
    ///
    /// 参数说明：
    /// - `parts`：尚未接受外部鉴权头注入的原始请求 head。
    /// - `saml_response`：代理按路由预算提取的可选 SAML HTTP-POST 凭据。
    /// - `body`：代理按共同鉴权预算聚合并保留的原始请求正文。
    ///
    /// 返回：返回本地认证是否配置及 satisfy 组合结果；远端元数据不可用、过期或 token 非法均按未通过处理。
    pub(crate) async fn resolved_auth_state(
        &self,
        parts: &Parts,
        saml_response: Option<&str>,
        body: Option<&[u8]>,
    ) -> ResolvedAuthState {
        let has_basic = self.basic_auth.is_some();
        let has_digest = self.digest_auth.is_some();
        let digest_ok = self
            .digest_auth
            .as_ref()
            .and_then(|policy| policy.consumer(parts))
            .is_some();
        let has_api_key = !self.api_keys.is_empty();
        let has_hmac = !self.hmac_auth.is_empty();
        let has_jwt = !self.jwt_auth.is_empty();
        let has_enterprise = !self.enterprise_auth.is_empty();
        if !has_basic && !has_digest && !has_api_key && !has_hmac && !has_jwt && !has_enterprise {
            return ResolvedAuthState {
                configured: false,
                ok: true,
                consumer: None,
                jwt_claims: None,
                identity_headers: Vec::new(),
            };
        }
        let basic_ok = self
            .basic_auth
            .as_ref()
            .is_some_and(|policy| policy.matches(parts));
        let api_key_ok = self.api_keys.iter().any(|policy| policy.matches(parts));
        let hmac_ok = self
            .hmac_auth
            .iter()
            .any(|policy| policy.matches_body(parts, body));
        let mut verified_jwt = None;
        for policy in &self.jwt_auth {
            let Some(token) = policy.token(parts) else {
                continue;
            };
            if let Some(payload) = policy.verified_payload_resolved(token).await {
                verified_jwt = Some((policy, payload));
                break;
            }
        }
        let jwt_ok = verified_jwt.is_some();
        let mut enterprise_consumer = None;
        let mut enterprise_headers = Vec::new();
        let mut enterprise_ok = false;
        for policy in &self.enterprise_auth {
            match policy.authenticate(parts, saml_response).await {
                EnterpriseAuthResult::Authenticated {
                    consumer,
                    headers,
                } => {
                    enterprise_ok = true;
                    enterprise_consumer = Some(consumer);
                    enterprise_headers = headers;
                    break;
                }
                EnterpriseAuthResult::Missing | EnterpriseAuthResult::Rejected => {}
            }
        }
        let ok = match self.satisfy {
            SatisfyMode::All => {
                (!has_basic || basic_ok)
                    && (!has_digest || digest_ok)
                    && (!has_api_key || api_key_ok)
                    && (!has_hmac || hmac_ok)
                    && (!has_jwt || jwt_ok)
                    && (!has_enterprise || enterprise_ok)
            }
            SatisfyMode::Any => {
                (has_basic && basic_ok)
                    || (has_digest && digest_ok)
                    || (has_api_key && api_key_ok)
                    || (has_hmac && hmac_ok)
                    || (has_jwt && jwt_ok)
                    || (has_enterprise && enterprise_ok)
            }
        };
        let consumer = ok
            .then(|| {
                verified_jwt
                    .as_ref()
                    .and_then(|(_, payload)| bounded_jwt_claim(payload, "sub"))
                    .or_else(|| {
                        self.api_keys.iter().find_map(|policy| {
                            policy
                                .matches(parts)
                                .then(|| policy.consumer.clone())
                                .flatten()
                        })
                    })
                    .or_else(|| {
                        self.basic_auth.as_ref().and_then(|policy| {
                            policy.matches(parts).then(|| policy.consumer.clone())
                        })
                    })
            })
            .flatten()
            .or_else(|| {
                (ok && enterprise_ok)
                    .then_some(enterprise_consumer)
                    .flatten()
            });
        let consumer = consumer.or_else(|| {
            ok.then(|| {
                self.digest_auth
                    .as_ref()
                    .and_then(|policy| policy.consumer(parts))
            })
            .flatten()
        });
        let jwt_claims = ok
            .then(|| verified_jwt.as_ref().map(|(_, payload)| payload.clone()))
            .flatten();
        let mut identity_headers = Vec::new();
        if ok {
            if let Some((policy, payload)) = &verified_jwt {
                for mapping in policy.identity_headers.iter() {
                    let Some(value) = payload
                        .get(mapping.claim.as_ref())
                        .and_then(|value| value.as_str())
                    else {
                        continue;
                    };
                    if value.is_empty()
                        || value.len() > MAX_JWT_IDENTITY_BYTES
                        || value.bytes().any(|byte| byte.is_ascii_control())
                    {
                        continue;
                    }
                    if let Ok(value) = HeaderValue::from_str(value) {
                        identity_headers.push((mapping.header.clone(), value));
                    }
                }
            }
            if enterprise_ok {
                identity_headers.extend(enterprise_headers);
            }
        }
        ResolvedAuthState {
            configured: true,
            ok,
            consumer,
            jwt_claims,
            identity_headers,
        }
    }

    /// 业务作用：判断本 route 是否启用标准 SAML HTTP-POST body binding，并汇总一次读取所需硬上限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少一个 body-binding SAML policy 时返回不超过协议上限的最大 form 字节数，否则 None。
    pub(crate) fn saml_form_body_limit(&self) -> Option<usize> {
        self.enterprise_auth
            .iter()
            .filter_map(EnterpriseAuthPolicy::saml_form_body_limit)
            .max()
    }

    /// 业务作用：汇总 HMAC 与 ext_authz 显式 body 慢路径的共同硬上限，确保原请求最多聚合一次。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少一项需要实体时返回所有声明上限中的最小值；未启用 body 鉴权返回 None。
    pub(crate) fn auth_body_limit(&self) -> Option<u64> {
        self.hmac_auth
            .iter()
            .filter_map(|policy| policy.body_max_bytes)
            .chain(
                self.ext_authz
                    .iter()
                    .filter_map(|policy| policy.body_max_bytes),
            )
            .min()
    }

    /// 业务作用：在代理本地认证阶段执行本 route 的浏览器 OIDC RP，并保持未配置 route 的零成本旁路。
    ///
    /// 参数说明：
    /// - `parts`：是客户端原始请求 head，尚未经过 ext_authz 修改。
    ///
    /// 返回：未配置时返回 None；已配置时返回可信 session 身份，或必须立即短路的登录/回调/失败响应。
    pub(crate) async fn oidc_rp_authenticate(&self, parts: &Parts) -> Option<OidcRpDecision> {
        Some(self.oidc_rp.as_ref()?.authenticate(parts).await)
    }

    /// 业务作用：先删除所有由网关拥有的身份头，再提交认证阶段冻结的可信身份值。
    ///
    /// 参数说明：
    /// - `parts`：是可能已被 ext_authz 修改的请求 head
    /// - `identity_headers`：只来自外呼前冻结的本地认证结果。
    ///
    /// 返回：无；客户端或 ext_authz 的同名值先被删除，只有已验证 JWT/SAML/LDAP 值会重新注入。
    pub(crate) fn apply_identity_headers(
        &self,
        parts: &mut Parts,
        identity_headers: &[(HeaderName, HeaderValue)],
    ) {
        for policy in &self.jwt_auth {
            for mapping in policy.identity_headers.iter() {
                parts.headers.remove(&mapping.header);
            }
        }
        if let Some(policy) = &self.oidc_rp {
            for mapping in policy.identity_headers.iter() {
                parts.headers.remove(&mapping.header);
            }
        }
        for policy in &self.enterprise_auth {
            for header in policy.owned_headers() {
                parts.headers.remove(header);
            }
        }
        for (name, value) in identity_headers {
            parts.headers.insert(name.clone(), value.clone());
        }
    }

    /// 业务作用：提取已通过认证请求的长连接 consumer 标识。
    ///
    /// 只应在鉴权链已放行且请求将升级/进入 gRPC 长流时调用。优先级为 JWT `sub`、显式
    /// API-Key `consumer=`、Basic user；HMAC/ext_authz 未声明稳定主体时返回 None。
    pub fn authenticated_long_connection_consumer(&self, parts: &Parts) -> Option<Arc<str>> {
        self.authenticated_consumer(parts)
    }

    /// 业务作用：提取已认证且已按路由归属冻结的 consumer，供 LLM 配额和长连接共享身份。
    ///
    /// 参数说明：
    /// - `parts`：是认证管线处理后的请求；未经过管线时只解析本地凭据。
    ///
    /// 返回：可信工作区主体或本地认证主体；无稳定身份返回 None。
    pub fn authenticated_consumer(&self, parts: &Parts) -> Option<Arc<str>> {
        if let Some(consumer) = parts
            .extensions
            .get::<crate::control::ownership::Consumer>()
        {
            return consumer.0.clone();
        }
        self.jwt_auth
            .iter()
            .find_map(|policy| policy.authenticated_subject(parts))
            .or_else(|| {
                self.api_keys.iter().find_map(|policy| {
                    policy
                        .matches(parts)
                        .then(|| policy.consumer.clone())
                        .flatten()
                })
            })
            .or_else(|| {
                self.basic_auth
                    .as_ref()
                    .and_then(|policy| policy.matches(parts).then(|| policy.consumer.clone()))
            })
    }

    /// 业务作用：edge:从任一命中的 JWT 策略提取指定 claim(tenant/user 身份只来自
    /// 已验证 principal 的 claim,客户端自报 header 永不是权威身份)。
    pub fn authenticated_edge_claim(&self, parts: &Parts, claim: &str) -> Option<Arc<str>> {
        self.jwt_auth
            .iter()
            .find_map(|policy| policy.authenticated_claim(parts, claim))
    }

    /// 业务作用：返回命中 API-Key 策略的稳定 SHA-256 指纹，供受信额度身份使用；原始 key 永不
    /// 拼入进程 HashMap/Redis key，也不进入日志或 metrics label。
    ///
    /// 参数说明：
    /// - `parts`：凭据未经外部授权或插件改写的请求。
    ///
    /// 返回：匹配成功时复制已编译指纹；凭据缺失或不匹配返回 None。
    pub fn authenticated_api_key_fingerprint(&self, parts: &Parts) -> Option<String> {
        self.authenticated_api_key_identity(parts)
            .map(|identity| identity.to_string())
    }

    /// 业务作用：借用构建期预计算的凭据指纹，认证后冻结身份无需重复摘要或字符串编码。
    ///
    /// 参数说明：
    /// - `parts`：本地认证原始请求，必须在外部授权或插件改写前读取。
    ///
    /// 返回：命中本地 API-Key 策略时共享其指纹；凭据缺失或不匹配返回 None。
    pub(crate) fn authenticated_api_key_identity(&self, parts: &Parts) -> Option<Arc<str>> {
        let policy = self.api_keys.iter().find(|policy| policy.matches(parts))?;
        Some(policy.fingerprint.clone())
    }

    /// 业务作用：当前 route 是否配置了异步 ext_authz 外部鉴权策略。
    pub fn has_ext_authz(&self) -> bool {
        !self.ext_authz.is_empty()
    }

    /// 业务作用：本 route 是否配置了任一开启防重放的 HMAC 策略。
    pub fn has_hmac_replay(&self) -> bool {
        self.hmac_auth.iter().any(HmacAuthPolicy::replay_enabled)
    }

    /// 业务作用：在路由归属与工作区预算内登记签名有效的 nonce，避免同名路由跨域污染防重放事实。
    ///
    /// 只有签名先有效才消费 nonce(`matches` 已含签名 + 时间戳 + nonce 存在校验),避免无效请求污染去重表。
    /// 消费一个 fresh nonce 无副作用;返回 `true` 表示检测到重放,调用方应拒绝。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    /// - `guard`: 防重放守卫后端(local/redis)。
    /// - `body`: 已按签名协议有界读取的请求实体。
    ///
    /// 返回：nonce 已消费、容量不足或后端拒绝时为 true；没有需要拒绝的有效签名为 false。
    pub async fn hmac_replay_detected(
        &self,
        parts: &Parts,
        body: Option<&[u8]>,
        guard: &dyn crate::runtime::state::ReplayGuard,
    ) -> bool {
        for policy in &self.hmac_auth {
            if policy.replay_enabled() && policy.matches_body(parts, body) {
                if let Some(nonce) = policy.nonce_value(parts) {
                    // 归属域来自配置扩展；原始 nonce 只进入摘要，不能选择其它路由的账本。
                    let scope = parts
                        .extensions
                        .get::<crate::control::ownership::RequestScope>()
                        .map_or(self.id.as_str(), |scope| scope.0.as_str());
                    let key = format!("{scope}:{}", nasa::crypto::sha256(nonce));
                    if !guard
                        .check_and_set_scoped(&key, policy.replay_ttl(), parts.extensions.get())
                        .await
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// 业务作用：返回认证失败响应的 `WWW-Authenticate` challenge 值。
    ///
    /// 参数说明：
    /// - `_parts`：保留的下游请求 head 参数；challenge 只由当前路由的认证策略决定。
    pub fn auth_challenge(&self, _parts: &Parts) -> Option<String> {
        self.basic_auth
            .as_ref()
            .map(BasicAuthPolicy::challenge_value)
    }

    /// 业务作用：按 nginx `if` 安全子集判断是否需要固定响应短路。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    /// - `client_ip`: 已解析真实客户端 IP。
    /// - `downstream_proto`: 下游协议 scheme。
    /// - `request_id`: 网关生成的 request id。
    pub fn conditional_return(
        &self,
        parts: &Parts,
        client_ip: IpAddr,
        downstream_proto: &'static str,
        request_id: &str,
    ) -> Option<DirectResponse> {
        let eval_ctx = crate::routing::variable::EvalContext {
            parts,
            client_ip,
            downstream_proto,
            request_id,
            route_id: self.id.as_str(),
            response_status: None,
        };
        self.conditional_returns
            .iter()
            .find(|rule| rule.matches(&eval_ctx, self.variables.as_ref()))
            .map(|rule| rule.response.clone())
    }
}

/// Gateway API 与 nginx 请求头变更的统一执行操作。
#[derive(Clone, PartialEq, Eq)]
pub enum RequestHeaderOp {
    /// 替换全部同名值；对应 nginx `proxy_set_header` 与 Gateway API `set`。
    Set(RequestHeaderSet),
    /// 在既有值之后追加一项；对应 Gateway API `add`。
    Add(RequestHeaderSet),
    /// 删除全部同名值；对应 Gateway API `remove`。
    Remove(HeaderName),
}

/// 请求头设置规则,对应 nginx `proxy_set_header`。
#[derive(Clone, PartialEq, Eq)]
pub struct RequestHeaderSet {
    /// 待写入的上游请求头名。
    pub name: HeaderName,
    /// 已编译 header value 模板。
    pub value: ValueTemplate,
}

/// 响应头追加规则,对应 nginx `add_header`。
#[derive(PartialEq, Eq)]
pub struct ResponseHeaderSet {
    /// 待追加的下游响应头名。
    pub name: HeaderName,
    /// 已编译 header value 模板。
    pub value: ValueTemplate,
}

/// 响应头过滤操作。
#[derive(PartialEq, Eq)]
pub enum ResponseHeaderOp {
    /// 追加响应头。
    Add(ResponseHeaderSet),
    /// 替换全部同名响应头。
    Set(ResponseHeaderSet),
    /// 移除指定响应头。
    Hide(HeaderName),
    /// 改写上游重定向头。
    ProxyRedirect(ProxyRedirectRule),
    /// 改写 Set-Cookie 属性。
    CookieRewrite(CookieRewriteRule),
    /// 去重重复响应头。
    Dedupe(DedupeResponseHeader),
}

/// nginx `sub_filter` 的单条流式替换规则。
#[derive(Clone, PartialEq, Eq)]
pub struct SubFilterRule {
    /// 要查找的原始字节串。基础按 bytes 匹配,不做字符集转换。
    pub needle: Vec<u8>,
    /// 替换后的字节串。允许为空,用于删除命中的片段。
    pub replacement: Vec<u8>,
}

/// HTTP 内容编码算法；配置编译后数据面只比较这个小枚举，不重复解析字符串。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentCoding {
    /// RFC 9110 `gzip` 内容编码。
    Gzip,
    /// RFC 7932 `br`(Brotli)内容编码。
    Brotli,
}

impl ContentCoding {
    /// 业务作用：返回写入 `Content-Encoding` 和匹配 `Accept-Encoding` 的标准 token。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
        }
    }
}

/// route 级响应压缩策略。
///
/// 所有字符串与数值都在快照构建期完成校验；单请求只做 header 借用扫描、MIME
/// 匹配和小枚举选择。未知 `Content-Length` 的响应不会为判定阈值而聚合 body。
#[derive(PartialEq, Eq)]
pub struct CompressionPolicy {
    /// 服务端允许的算法及相同客户端 q 值时的优先顺序。
    pub(crate) algorithms: Vec<ContentCoding>,
    /// 已知实体小于该值时直通；未知长度仍流式压缩。
    pub(crate) min_length: u64,
    /// build 期编译的 MIME 匹配器，避免每请求拆配置字符串。
    content_types: Vec<CompressionContentType>,
    /// gzip 压缩级别，范围 0..=9。
    pub(crate) gzip_level: i32,
    /// Brotli quality，范围 0..=11。
    pub(crate) brotli_quality: i32,
    /// codec 每次交付给 Hyper 的最大输出 frame 大小。
    pub(crate) chunk_bytes: usize,
}

impl CompressionPolicy {
    /// 业务作用：判断响应媒体类型是否允许压缩。
    ///
    /// 参数说明：
    /// - `content_type`: 响应 `Content-Type` 的原始值；函数只借用并忽略 `; charset=...` 参数。
    pub(crate) fn permits_content_type(&self, content_type: Option<&str>) -> bool {
        let Some(media_type) = content_type
            .and_then(|raw| raw.split(';').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return false;
        };
        self.content_types
            .iter()
            .any(|matcher| matcher.matches(media_type))
    }
}

/// build 期编译的可压缩 MIME 匹配器。
#[derive(PartialEq, Eq)]
enum CompressionContentType {
    /// `*`：运维显式选择压缩所有带 Content-Type 的实体。
    Any,
    /// `text/*` 一类主类型前缀。
    Prefix(Box<str>),
    /// 完整媒体类型，如 `application/json`。
    Exact(Box<str>),
}

impl CompressionContentType {
    /// 业务作用：对一个已去除参数的媒体类型做 ASCII 大小写无关匹配。
    ///
    /// 参数说明：
    /// - `media_type`: 例如 `text/plain`，来自响应头借用，不分配新字符串。
    fn matches(&self, media_type: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Prefix(prefix) => media_type
                .get(..prefix.len())
                .map(|head| head.eq_ignore_ascii_case(prefix))
                .unwrap_or(false),
            Self::Exact(expected) => media_type.eq_ignore_ascii_case(expected),
        }
    }
}

impl ResponseHeaderOp {
    /// 业务作用：响应阶段是否需要保留请求上下文。
    ///
    /// 动态 `add_header` 需要原始请求变量;纯静态响应头操作不让热路径额外 clone `Parts`。
    pub fn needs_request_context(&self) -> bool {
        match self {
            Self::Add(set) | Self::Set(set) => set.value.static_literal().is_none(),
            Self::Hide(_) | Self::ProxyRedirect(_) | Self::CookieRewrite(_) | Self::Dedupe(_) => {
                false
            }
        }
    }
}

/// nginx `proxy_redirect from to` 的已编译规则。
#[derive(PartialEq, Eq)]
pub struct ProxyRedirectRule {
    /// 上游返回的 URL 前缀。
    pub from: String,
    /// 下游可见的替换前缀。
    pub to: String,
}

/// nginx `proxy_cookie_domain/path/flags` 的已编译规则。
#[derive(PartialEq, Eq)]
pub enum CookieRewriteRule {
    /// 改写 Set-Cookie 的 Domain 属性。
    Domain {
        /// 原 Domain 值。
        from: String,
        /// 新 Domain 值。
        to: String,
    },
    /// 改写 Set-Cookie 的 Path 属性。
    Path {
        /// 原 Path 值。
        from: String,
        /// 新 Path 值。
        to: String,
    },
    /// 改写 Set-Cookie 的安全 flags。
    Flags(CookieFlagsRule),
}

/// nginx `proxy_cookie_flags` 的已编译规则。
#[derive(PartialEq, Eq)]
pub struct CookieFlagsRule {
    /// cookie 名;`*` 表示所有 Set-Cookie。
    pub cookie: String,
    /// 是否追加 Secure。
    pub add_secure: bool,
    /// 是否移除 Secure。
    pub remove_secure: bool,
    /// 是否追加 HttpOnly。
    pub add_http_only: bool,
    /// 是否移除 HttpOnly。
    pub remove_http_only: bool,
    /// 设置 SameSite 值。
    pub same_site: Option<String>,
    /// 是否移除 SameSite。
    pub remove_same_site: bool,
}

/// 重复响应头去重规则,兼容 SCG `DedupeResponseHeader` 中可零拷贝实现的语义。
#[derive(PartialEq, Eq)]
pub struct DedupeResponseHeader {
    /// 待去重的响应头名。
    pub name: HeaderName,
    /// 保留首个还是最后一个值。
    pub mode: DedupeMode,
}

/// nginx `mirror` 流量镜像规则。
#[derive(Clone, PartialEq)]
pub struct MirrorPolicy {
    /// 镜像目标 upstream,支持 `lb://service` 或静态 `http(s)://host`。
    pub target: String,
    /// 采样率,范围 0.0..=1.0。默认 1.0。
    pub sample: f64,
    /// 是否镜像请求体。默认 false,保持主链路流式快路径。
    pub body: bool,
    /// `body=true` 时允许收集的最大请求体字节数。
    pub max_body_bytes: u64,
}

/// 重复响应头的保留策略。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DedupeMode {
    /// 保留第一个出现的 header value。
    RetainFirst,
    /// 保留最后一个出现的 header value。
    RetainLast,
    /// 保留唯一值;重复值只输出一次。
    RetainUnique,
}

/// CORS 规则的已编译形态。
#[derive(Clone, PartialEq, Eq)]
pub struct CorsPolicy {
    /// Access-Control-Allow-Origin 策略。
    pub allow_origin: CorsAllowOrigin,
    /// Access-Control-Allow-Methods 值。
    pub allow_methods: Option<String>,
    /// Access-Control-Allow-Headers 值。
    pub allow_headers: Option<String>,
    /// Access-Control-Expose-Headers 值。
    pub expose_headers: Option<String>,
    /// Access-Control-Max-Age 秒数。
    pub max_age_seconds: Option<u64>,
    /// 是否允许携带凭证。
    pub allow_credentials: bool,
}

/// CORS allow-origin 模式。
#[derive(Clone, PartialEq, Eq)]
pub enum CorsAllowOrigin {
    /// 返回通配符 `*`。
    Any,
    /// 回显请求 `Origin`。
    Echo,
    /// 返回固定 origin。
    Static(String),
    /// 按 Gateway API 的精确或左侧通配 origin 列表匹配，并回显通过校验的请求 Origin。
    Gateway(Vec<CorsOriginPattern>),
}

/// Gateway API CORS origin 的规范化匹配计划。
#[derive(Clone, PartialEq, Eq)]
pub struct CorsOriginPattern {
    scheme: String,
    host: CorsOriginHost,
    port: u16,
}

/// Gateway API CORS origin 的主机匹配边界。
#[derive(Clone, PartialEq, Eq)]
enum CorsOriginHost {
    Exact(String),
    WildcardSuffix(String),
}

impl CorsAllowOrigin {
    /// 业务作用：为当前请求选择可安全写入 CORS 响应的 origin，Gateway API 列表只回显已匹配值。
    ///
    /// 参数说明：
    /// - `request_origin`：是下游原始 `Origin`
    /// - `allow_credentials`：决定通配符能否直接返回。
    ///
    /// 返回：匹配时返回响应值；缺少或未授权的 origin 返回 `None`，调用方不得发布 CORS 头。
    pub(crate) fn response_value(
        &self,
        request_origin: Option<&HeaderValue>,
        allow_credentials: bool,
    ) -> Option<HeaderValue> {
        match self {
            Self::Any if allow_credentials => request_origin.cloned(),
            Self::Any => Some(HeaderValue::from_static("*")),
            Self::Echo => request_origin.cloned(),
            Self::Static(origin) => HeaderValue::from_str(origin).ok(),
            Self::Gateway(patterns) => {
                let origin = request_origin?;
                patterns
                    .iter()
                    .any(|pattern| pattern.matches(origin))
                    .then(|| origin.clone())
            }
        }
    }

    /// 业务作用：判断 CORS 响应是否随请求 `Origin` 变化，供缓存隔离和 `Vary` 发布共用。
    ///
    /// 参数说明：
    /// - `allow_credentials`：决定全 origin 通配符是否必须改为回显。
    ///
    /// 返回：动态回显或列表匹配返回 `true`，固定响应返回 `false`。
    pub(crate) fn varies_by_origin(&self, allow_credentials: bool) -> bool {
        matches!(self, Self::Echo | Self::Gateway(_))
            || matches!(self, Self::Any) && allow_credentials
    }
}

impl CorsOriginPattern {
    /// 业务作用：匹配一个规范化 Gateway API origin，避免把路径、用户信息或错误端口当成同源。
    ///
    /// 参数说明：
    /// - `request_origin`：是浏览器提供的原始 `Origin` header。
    ///
    /// 返回：scheme、规范化端口与主机规则全部命中时返回 `true`；非法 header 一律不匹配。
    fn matches(&self, request_origin: &HeaderValue) -> bool {
        let Ok(raw) = request_origin.to_str() else {
            return false;
        };
        let Ok((scheme, host, port)) = parse_cors_request_origin(raw) else {
            return false;
        };
        if scheme != self.scheme || port != self.port {
            return false;
        }
        match &self.host {
            CorsOriginHost::Exact(expected) => host == *expected,
            CorsOriginHost::WildcardSuffix(suffix) => {
                host.len() > suffix.len() && host.ends_with(suffix)
            }
        }
    }
}

/// path 前缀改写规则,对应轻量 `rewrite` 子集。
#[derive(Clone)]
pub struct RewritePrefix {
    /// 需要匹配的原始前缀。
    pub from: String,
    /// 替换后的目标前缀。
    pub to: String,
}

/// Gateway API RequestRedirect 的已验证执行计划。
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayRedirectPolicy {
    scheme: Option<String>,
    hostname: Option<String>,
    port: Option<u16>,
    status: StatusCode,
    replace_full_path: Option<String>,
    replace_prefix_match: Option<String>,
    matched_prefix: Option<String>,
}

impl GatewayRedirectPolicy {
    /// 业务作用：把控制面重定向声明编译为不会产生非法 Location 或歧义 path 变换的计划。
    ///
    /// 参数说明：
    /// - `cfg`：是 Gateway API RequestRedirect 映射后的声明。
    ///
    /// 返回：字段组合、scheme、authority、状态码与 path 均合法时返回计划，否则拒绝候选快照。
    fn build(cfg: &GatewayRedirectCfg) -> Result<Self> {
        anyhow::ensure!(
            cfg.scheme
                .as_deref()
                .is_none_or(|scheme| matches!(scheme, "http" | "https")),
            "gateway_redirect.scheme must be http or https"
        );
        if let Some(hostname) = cfg.hostname.as_deref() {
            validate_redirect_hostname(hostname)?;
        }
        anyhow::ensure!(
            cfg.port.is_none_or(|port| port > 0),
            "gateway_redirect.port cannot be zero"
        );
        let status = StatusCode::from_u16(cfg.status_code)
            .context("gateway_redirect.status_code is invalid")?;
        anyhow::ensure!(
            matches!(cfg.status_code, 301 | 302 | 303 | 307 | 308),
            "gateway_redirect.status_code must be 301, 302, 303, 307, or 308"
        );
        anyhow::ensure!(
            !(cfg.replace_full_path.is_some() && cfg.replace_prefix_match.is_some()),
            "gateway_redirect path modifier must choose full path or prefix replacement"
        );
        anyhow::ensure!(
            cfg.replace_prefix_match.is_some() == cfg.matched_prefix.is_some(),
            "gateway_redirect prefix replacement requires matched_prefix"
        );
        for (field, value) in [
            ("replace_full_path", cfg.replace_full_path.as_deref()),
            ("replace_prefix_match", cfg.replace_prefix_match.as_deref()),
            ("matched_prefix", cfg.matched_prefix.as_deref()),
        ] {
            if let Some(value) = value {
                anyhow::ensure!(
                    value.starts_with('/')
                        && value.len() <= 2048
                        && !value.bytes().any(|byte| byte <= 0x20 || byte == b'#'),
                    "gateway_redirect.{field} must be a valid origin path within 2048 bytes"
                );
            }
        }
        Ok(Self {
            scheme: cfg.scheme.clone(),
            hostname: cfg.hostname.clone(),
            port: cfg.port,
            status,
            replace_full_path: cfg.replace_full_path.clone(),
            replace_prefix_match: cfg.replace_prefix_match.clone(),
            matched_prefix: cfg.matched_prefix.clone(),
        })
    }

    /// 业务作用：基于当前请求生成最终 Location，同时严格保留未被策略覆盖的 path/query 信息。
    ///
    /// 参数说明：
    /// - `parts`：提供规范化 URI 与 authority
    /// - `downstream_proto`：是可信监听协议。
    ///
    /// 返回：authority 与 Location 可编码时返回状态码和目标；缺失或非法 Host 时拒绝本次重定向。
    pub fn location(&self, parts: &Parts, downstream_proto: &str) -> Result<(StatusCode, String)> {
        let inbound_authority = parts
            .uri
            .authority()
            .map(http::uri::Authority::as_str)
            .or_else(|| {
                parts
                    .headers
                    .get(http::header::HOST)
                    .and_then(|value| value.to_str().ok())
            })
            .context("gateway redirect request has no valid authority")?;
        let parsed_authority = inbound_authority
            .parse::<http::uri::Authority>()
            .context("gateway redirect request authority is invalid")?;
        let scheme = self.scheme.as_deref().unwrap_or(downstream_proto);
        anyhow::ensure!(
            matches!(scheme, "http" | "https"),
            "gateway redirect downstream scheme is unsupported"
        );
        let hostname = self
            .hostname
            .as_deref()
            .unwrap_or_else(|| parsed_authority.host());
        validate_redirect_hostname(hostname)?;
        let port = self.port.or_else(|| {
            self.scheme
                .is_none()
                .then(|| parsed_authority.port_u16())
                .flatten()
        });
        let authority = match port {
            Some(port) => format_authority(hostname, port),
            None => hostname.to_owned(),
        };
        let path = if let Some(replacement) = self.replace_full_path.as_deref() {
            replacement.to_owned()
        } else if let (Some(from), Some(to)) = (
            self.matched_prefix.as_deref(),
            self.replace_prefix_match.as_deref(),
        ) {
            let suffix = parts
                .uri
                .path()
                .strip_prefix(from)
                .context("gateway redirect path no longer matches compiled prefix")?;
            format!("{to}{suffix}")
        } else {
            parts.uri.path().to_owned()
        };
        let query = parts
            .uri
            .query()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        let location = format!("{scheme}://{authority}{path}{query}");
        HeaderValue::from_str(&location).context("gateway redirect Location is invalid")?;
        Ok((self.status, location))
    }
}

/// 业务作用：校验重定向目标 hostname，阻断 userinfo、path 与控制字符注入 Location。
///
/// 参数说明：
/// - `hostname`：是不含端口的 DNS 名、IPv4 或方括号 IPv6。
///
/// 返回：可安全组成 HTTP authority 时成功，否则返回错误。
fn validate_redirect_hostname(hostname: &str) -> Result<()> {
    anyhow::ensure!(
        !hostname.is_empty()
            && hostname.len() <= 253
            && !hostname
                .bytes()
                .any(|byte| byte <= 0x20 || matches!(byte, b'/' | b'@' | b'#' | b'?')),
        "gateway redirect hostname is invalid"
    );
    let authority = format_authority(hostname, 443);
    authority
        .parse::<http::uri::Authority>()
        .context("gateway redirect hostname is not a valid authority")?;
    Ok(())
}

/// 业务作用：在不破坏 IPv6 方括号语义的前提下拼出带端口 authority。
///
/// 参数说明：
/// - `hostname`：已通过目标主机校验
/// - `port`：是非零 TCP 端口。
///
/// 返回：返回可供 URI 使用的 authority 文本。
fn format_authority(hostname: &str, port: u16) -> String {
    if hostname.contains(':') && !hostname.starts_with('[') {
        format!("[{hostname}]:{port}")
    } else {
        format!("{hostname}:{port}")
    }
}

/// 一个已编译 BFF 聚合计划。全部预算在快照构建期固定，执行时不再解析配置字符串。
pub(crate) struct BffAggregationPolicy {
    pub targets: Arc<[BffTargetPolicy]>,
    pub max_total_response_bytes: usize,
    pub total_timeout: Duration,
}

/// BFF 单子请求的不可变计划。
pub(crate) struct BffTargetPolicy {
    pub id: Arc<str>,
    pub uri: Arc<str>,
    pub path: Arc<str>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub required: bool,
    pub forward_headers: Arc<[HeaderName]>,
}

impl BffAggregationPolicy {
    /// 业务作用：编译有限的只读聚合目标、并发和响应预算，禁止任意目标或无界扇出。
    fn build(cfg: &BffAggregationCfg) -> Result<Self> {
        anyhow::ensure!(
            (1..=16).contains(&cfg.targets.len()),
            "targets must contain 1..=16 entries"
        );
        anyhow::ensure!(
            (1024..=16 * 1024 * 1024).contains(&cfg.max_total_response_bytes),
            "max_total_response_bytes must be within 1024..=16777216"
        );
        anyhow::ensure!(
            (10..=60_000).contains(&cfg.total_timeout_ms),
            "total_timeout_ms must be within 10..=60000"
        );
        let mut ids = std::collections::HashSet::with_capacity(cfg.targets.len());
        let mut targets = Vec::with_capacity(cfg.targets.len());
        for target in &cfg.targets {
            validate_bff_id(&target.id)?;
            anyhow::ensure!(
                ids.insert(target.id.clone()),
                "duplicate target id `{}`",
                target.id
            );
            validate_bff_uri(&target.uri)?;
            anyhow::ensure!(
                target.path.starts_with('/')
                    && target.path.len() <= 2048
                    && !target.path.contains('?')
                    && !target.path.contains('#')
                    && !target.path.bytes().any(|byte| byte < 0x20),
                "target `{}` path must be a fixed origin path without query/fragment",
                target.id
            );
            anyhow::ensure!(
                (10..=60_000).contains(&target.timeout_ms),
                "target `{}` timeout_ms must be within 10..=60000",
                target.id
            );
            anyhow::ensure!(
                target.timeout_ms <= cfg.total_timeout_ms,
                "target `{}` timeout_ms cannot exceed total_timeout_ms",
                target.id
            );
            anyhow::ensure!(
                (1..=4 * 1024 * 1024).contains(&target.max_response_bytes),
                "target `{}` max_response_bytes must be within 1..=4194304",
                target.id
            );
            anyhow::ensure!(
                target.forward_headers.len() <= 32,
                "target `{}` forward_headers supports at most 32 entries",
                target.id
            );
            let mut headers = Vec::with_capacity(target.forward_headers.len());
            for raw in &target.forward_headers {
                let name = raw.parse::<HeaderName>().with_context(|| {
                    format!("target `{}` invalid forward header `{raw}`", target.id)
                })?;
                anyhow::ensure!(
                    !is_sensitive_bff_header(&name),
                    "target `{}` cannot forward sensitive/hop-by-hop header `{name}`",
                    target.id
                );
                if !headers.contains(&name) {
                    headers.push(name);
                }
            }
            targets.push(BffTargetPolicy {
                id: Arc::from(target.id.as_str()),
                uri: Arc::from(target.uri.trim_end_matches('/')),
                path: Arc::from(target.path.as_str()),
                timeout: Duration::from_millis(target.timeout_ms),
                max_response_bytes: target.max_response_bytes,
                required: target.required,
                forward_headers: headers.into(),
            });
        }
        Ok(Self {
            targets: targets.into(),
            max_total_response_bytes: cfg.max_total_response_bytes,
            total_timeout: Duration::from_millis(cfg.total_timeout_ms),
        })
    }
}

/// 业务作用：限制聚合目标标识，使输出字段和诊断归因具有稳定边界。
fn validate_bff_id(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                })
            && value != "_errors",
        "BFF target id must be 1..=64 safe ASCII and cannot be `_errors`"
    );
    Ok(())
}

/// 业务作用：验证固定聚合后端，阻止客户端输入控制外部请求目的地。
fn validate_bff_uri(raw: &str) -> Result<()> {
    if let Some(service) = raw.strip_prefix("lb://") {
        anyhow::ensure!(
            !service.is_empty()
                && service.len() <= 128
                && service.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                }),
            "invalid BFF lb service `{service}`"
        );
        return Ok(());
    }
    let uri: http::Uri = raw.parse().context("BFF target uri is invalid")?;
    anyhow::ensure!(
        matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.authority().is_some()
            && uri.path() == "/"
            && uri.query().is_none(),
        "BFF target uri must contain only http(s) scheme and authority; use path separately"
    );
    Ok(())
}

/// 业务作用：识别聚合请求不能透传或覆盖的敏感头，避免凭据跨后端泄漏。
fn is_sensitive_bff_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "x-api-key"
            | "connection"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "te"
            | "trailer"
    )
}

/// 已编译 mock 响应。HeaderMap clone 共享 HeaderValue backing，body clone 只增 Bytes 引用计数。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MockResponsePolicy {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl MockResponsePolicy {
    /// 业务作用：冻结 mock 的状态码、头部和实体，拒绝不合法的静态响应合同。
    fn build(cfg: &MockResponseCfg) -> Result<Self> {
        let status = StatusCode::from_u16(cfg.status).context("invalid mock status")?;
        anyhow::ensure!(
            !status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS,
            "mock status cannot be informational/101"
        );
        anyhow::ensure!(
            cfg.body.len() <= 1024 * 1024,
            "mock body exceeds 1MiB hard limit"
        );
        anyhow::ensure!(
            cfg.headers.len() <= 64,
            "mock headers supports at most 64 entries"
        );
        if matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
            anyhow::ensure!(
                cfg.body.is_empty(),
                "mock 204/304 response cannot contain a body"
            );
        }
        let mut headers = http::HeaderMap::with_capacity(cfg.headers.len());
        for (raw_name, raw_value) in &cfg.headers {
            let name = raw_name
                .parse::<HeaderName>()
                .with_context(|| format!("invalid mock header `{raw_name}`"))?;
            anyhow::ensure!(
                !matches!(
                    name.as_str(),
                    "connection" | "transfer-encoding" | "content-length"
                ),
                "mock cannot set framing/hop-by-hop header `{name}`"
            );
            let value = raw_value
                .parse::<HeaderValue>()
                .with_context(|| format!("invalid mock header value for `{name}`"))?;
            headers.insert(name, value);
        }
        Ok(Self {
            status,
            headers,
            body: Bytes::copy_from_slice(cfg.body.as_bytes()),
        })
    }
}

/// 编译后的 chaos 注入策略。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FaultInjectionPolicy {
    pub percentage_bps: u16,
    pub delay: Duration,
    pub abort_status: Option<StatusCode>,
    pub abort_body: Bytes,
}

impl FaultInjectionPolicy {
    /// 业务作用：编译有界延迟和错误采样策略，拒绝不可执行的故障注入参数。
    fn build(cfg: &FaultInjectionCfg) -> Result<Self> {
        anyhow::ensure!(
            (1..=10_000).contains(&cfg.percentage_bps),
            "percentage_bps must be within 1..=10000"
        );
        anyhow::ensure!(cfg.delay_ms <= 60_000, "delay_ms must be <= 60000");
        anyhow::ensure!(
            cfg.abort_body.len() <= 64 * 1024,
            "abort_body exceeds 64KiB"
        );
        let abort_status = cfg
            .abort_status
            .map(StatusCode::from_u16)
            .transpose()
            .context("invalid abort_status")?;
        anyhow::ensure!(
            abort_status.is_none_or(|status| status.is_client_error() || status.is_server_error()),
            "abort_status must be 4xx or 5xx"
        );
        anyhow::ensure!(
            cfg.delay_ms > 0 || abort_status.is_some(),
            "fault_injection requires delay_ms or abort_status"
        );
        Ok(Self {
            percentage_bps: cfg.percentage_bps,
            delay: Duration::from_millis(cfg.delay_ms),
            abort_status,
            abort_body: Bytes::copy_from_slice(cfg.abort_body.as_bytes()),
        })
    }
}

/// 全局 usage-plan 目录。每个 plan 只构建一份 `Arc`，各 route binding 共享其窗口参数。
pub(crate) struct UsagePlanCatalog {
    plans: HashMap<Arc<str>, Arc<UsagePlan>>,
    consumers: Arc<HashMap<Arc<str>, Arc<UsagePlan>>>,
}

/// 已编译的固定窗口套餐。
#[derive(PartialEq, Eq)]
pub(crate) struct UsagePlan {
    pub id: Arc<str>,
    pub limit: u64,
    pub window: Duration,
    pub burst: u64,
    pub max_active_keys: usize,
    pub active_keys_fail_open: bool,
}

/// route 对全局 catalog 的只读绑定。
#[derive(PartialEq, Eq)]
pub(crate) struct UsagePlanPolicy {
    consumers: Arc<HashMap<Arc<str>, Arc<UsagePlan>>>,
    default: Option<Arc<UsagePlan>>,
    pub require_consumer: bool,
}

impl UsagePlanCatalog {
    /// 业务作用：在快照发布前冻结套餐与 consumer/group 绑定，拒绝未显式裁决的重叠套餐。
    ///
    /// 参数说明：
    /// - `cfg`：提供套餐、consumer 显式绑定与 group 成员关系。
    ///
    /// 返回：共享只读目录；引用、容量或套餐冲突时拒绝整个候选。
    pub(crate) fn build(cfg: &crate::config::model::UsagePlansCfg) -> Result<Arc<Self>> {
        anyhow::ensure!(
            cfg.plans.len() <= 128,
            "usage_plans supports at most 128 plans"
        );
        anyhow::ensure!(
            cfg.consumers.len() <= 100_000,
            "usage_plans supports at most 100000 consumer bindings"
        );
        let mut plans = HashMap::with_capacity(cfg.plans.len());
        for (id, cfg) in &cfg.plans {
            validate_usage_token(id, "plan id")?;
            anyhow::ensure!(cfg.requests > 0, "usage plan `{id}` requests must be > 0");
            anyhow::ensure!(
                (100..=365 * 24 * 60 * 60 * 1000_u64).contains(&cfg.window_ms),
                "usage plan `{id}` window_ms is outside 100ms..=365d"
            );
            anyhow::ensure!(
                (1..=1_000_000).contains(&cfg.max_active_keys),
                "usage plan `{id}` max_active_keys must be within 1..=1000000"
            );
            let key: Arc<str> = Arc::from(id.as_str());
            plans.insert(
                key.clone(),
                Arc::new(UsagePlan {
                    id: key,
                    limit: cfg.requests,
                    window: Duration::from_millis(cfg.window_ms),
                    burst: cfg.burst,
                    max_active_keys: cfg.max_active_keys,
                    active_keys_fail_open: cfg.active_keys_fail_open,
                }),
            );
        }
        anyhow::ensure!(cfg.groups.len() <= 256, "consumer group capacity exceeded");
        let mut assignments = std::collections::BTreeMap::new();
        let mut memberships = 0_usize;
        for (id, group) in &cfg.groups {
            validate_usage_token(id, "consumer group")?;
            memberships = memberships.saturating_add(group.consumers.len());
            anyhow::ensure!(
                !group.consumers.is_empty() && memberships <= 100_000,
                "consumer group membership budget exceeded"
            );
            if let Some(plan) = &group.plan {
                anyhow::ensure!(
                    plans.contains_key(plan.as_str()),
                    "group references unknown usage plan"
                );
            }
            for consumer in &group.consumers {
                validate_usage_token(consumer, "group consumer")?;
                if cfg.consumers.contains_key(consumer) {
                    continue;
                }
                if let Some(plan) = &group.plan {
                    // consumer 显式绑定优先于 group；多个 group 的不同套餐没有安全默认值，必须明确选择。
                    if let Some(prior) = assignments.insert(consumer, plan) {
                        anyhow::ensure!(
                            prior == plan,
                            "consumer belongs to groups with conflicting plans"
                        );
                    }
                }
            }
        }
        assignments.extend(cfg.consumers.iter());
        anyhow::ensure!(
            assignments.len() <= 100_000,
            "expanded consumer plan capacity exceeded"
        );
        let mut consumers = HashMap::with_capacity(assignments.len());
        for (consumer, plan_id) in assignments {
            anyhow::ensure!(
                !consumer.is_empty()
                    && consumer.len() <= 256
                    && !consumer.bytes().any(|byte| byte < 0x20),
                "usage plan consumer must be 1..=256 bytes without controls"
            );
            let plan = plans
                .get(plan_id.as_str())
                .with_context(|| {
                    format!("consumer `{consumer}` references unknown usage plan `{plan_id}`")
                })?
                .clone();
            consumers.insert(Arc::from(consumer.as_str()), plan);
        }
        Ok(Arc::new(Self {
            plans,
            consumers: Arc::new(consumers),
        }))
    }

    /// 业务作用：将路由套餐引用绑定到已验证目录，避免请求期解析不可信套餐名。
    ///
    /// 参数说明：
    /// - `cfg`：为路由套餐声明
    /// - `route_id`：用于定位无效引用。
    ///
    /// 返回：固定绑定和匿名请求边界；套餐不存在时拒绝候选。
    fn bind(
        &self,
        cfg: &crate::config::model::UsagePlanRouteCfg,
        route_id: &str,
    ) -> Result<UsagePlanPolicy> {
        let default = cfg
            .default_plan
            .as_deref()
            .map(|id| {
                self.plans.get(id).cloned().with_context(|| {
                    format!("route `{route_id}` references unknown default usage plan `{id}`")
                })
            })
            .transpose()?;
        anyhow::ensure!(
            cfg.require_consumer || default.is_some(),
            "route `{route_id}` anonymous usage_plan requires default_plan"
        );
        Ok(UsagePlanPolicy {
            consumers: self.consumers.clone(),
            default,
            require_consumer: cfg.require_consumer,
        })
    }
}

impl UsagePlanPolicy {
    /// 业务作用：选择已验证 consumer 的套餐；None 表示该身份未映射且无 default。
    pub(crate) fn select(&self, consumer: Option<&str>) -> Option<&Arc<UsagePlan>> {
        consumer
            .and_then(|consumer| self.consumers.get(consumer))
            .or(self.default.as_ref())
    }
}

/// 业务作用：限制用量套餐和主体映射中的标识，避免高基数或含糊键进入额度目录。
fn validate_usage_token(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "{label} must be 1..=64 safe ASCII bytes"
    );
    Ok(())
}

/// route 级固定响应,对应 nginx `return` 风格能力。
#[derive(Clone, PartialEq, Eq)]
pub struct DirectResponse {
    /// 响应状态码。
    pub status: StatusCode,
    /// 可选响应体;为空时使用状态 reason。
    pub value: Option<String>,
}

/// `auth_basic` 已编译策略。
///
/// 数据面只读取 `Authorization` header 并做常量时间字节比较;用户名/密码不暴露为 public 字段。
#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuthPolicy {
    /// 展示给客户端的 Basic realm。
    realm: String,
    /// 认证成功后的 consumer 标识；不含密码。
    consumer: Arc<str>,
    /// 构建期拼好的 `username:password` 字节串。
    expected: Vec<u8>,
}

/// API-Key 已编译策略。
///
/// 数据面只读取一个 header 或 query 参数,并与构建期保存的 key 做常量时间比较。
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKeyPolicy {
    /// SHA-256 前128位的稳定十六进制身份；构建期生成，不保存原始秘密于账本键。
    fingerprint: Arc<str>,
    /// API-Key 来源。
    source: ApiKeySource,
    /// 构建期保存的明文 SecretSource 结果或管理面生成的不可逆摘要。
    expected: ApiKeyExpected,
    /// 可选稳定 consumer 名；绝不使用原始 API key 作为管理面标识。
    consumer: Option<Arc<str>>,
}

/// API-Key 的构建期校验材料；摘要模式使 Console 创建 key 后无需把原值写回配置事实源。
#[derive(Clone, PartialEq, Eq)]
enum ApiKeyExpected {
    /// 兼容既有声明式 SecretSource，运行态以常量时间直接比较。
    Plain(Vec<u8>),
    /// 管理面生成 key 的 SHA-256，原值只在创建响应中出现一次。
    Sha256([u8; 32]),
}

/// HMAC-SHA256 已编译策略。
#[derive(Clone, PartialEq, Eq)]
pub struct HmacAuthPolicy {
    /// 构建期从 SecretSource 解析的共享密钥；随所属不可变路由快照交接。
    secret: String,
    /// 客户端提交小写或大写 hex 签名的请求头。
    signature_header: HeaderName,
    /// 客户端提交 Unix 秒/毫秒时间戳的请求头。
    timestamp_header: HeaderName,
    /// 可选 nonce 请求头;配置后必须参与签名。
    nonce_header: Option<HeaderName>,
    /// 额外参与签名的请求头,按配置顺序进入 canonical string。
    signed_headers: Vec<HeaderName>,
    /// 允许的客户端时间偏差,单位毫秒。
    max_skew_ms: u64,
    /// 是否开启防重放：开启后签名有效的请求还须 nonce 唯一（经 ReplayGuard `SET NX PX` 去重）。
    /// 需配 `nonce_header`;去重窗口 = `max_skew_ms`(超窗时间戳本就被拒,nonce 可遗忘)。
    replay_protection: bool,
    /// 显式启用 body SHA-256 时的实体硬上限；None 保持原有纯 head canonical contract。
    body_max_bytes: Option<u64>,
}

/// 已编译 JWT/JWKS/OIDC 策略。
#[derive(Clone, PartialEq, Eq)]
pub struct JwtAuthPolicy {
    /// 固定算法与 key 来源；header `alg` 必须精确一致。
    verifier: JwtVerifier,
    /// 唯一允许的 JWS 算法。
    algorithm: Algorithm,
    /// token 来源。
    source: JwtTokenSource,
    /// 可选 issuer 精确匹配。
    issuer: Option<String>,
    /// 可选 audience 匹配;payload aud 可为字符串或字符串数组。
    audience: Option<String>,
    /// 多 audience token 必须精确匹配的 `azp`。
    authorized_party: Option<String>,
    /// 可选固定 nonce；适合由上游登录流程把请求 nonce 固化到 route generation 的场景。
    nonce: Option<String>,
    /// `exp`/`nbf` 允许的时钟偏差,单位秒。
    leeway_secs: i64,
    /// compact token 最大字节数。
    max_token_bytes: usize,
    /// discovery profile 要求 exp/iat/iss/aud/sub，不能退化为只验签 bearer。
    require_oidc_claims: bool,
    /// 验证成功后由网关生成的 claim→header 映射。
    identity_headers: Arc<Vec<JwtIdentityHeader>>,
    /// 可选 JWE 外层；解密结果必须继续通过本策略的 JWS 与 claims 验证。
    #[cfg(feature = "enterprise-jwe")]
    jwe: Option<Arc<JweLayer>>,
}

#[cfg(feature = "enterprise-jwe")]
struct JweLayer {
    decrypter: josekit::jwe::alg::rsaes::RsaesJweDecrypter,
    /// 构建时实际读取的密钥材料身份，只供配置比较，不代替解密或签名验证。
    key_identity: [u8; 32],
    max_compact_bytes: usize,
}

#[derive(Clone)]
enum JwtVerifier {
    Hs256(Arc<str>),
    /// 静态验证器与同一次构建读取的材料身份；不在认证路径计算摘要。
    Static(Arc<DecodingKey>, [u8; 32]),
    Remote(Arc<RemoteJwks>),
}

#[derive(Clone, PartialEq, Eq)]
struct JwtIdentityHeader {
    claim: Arc<str>,
    header: HeaderName,
}

/// OAuth2/OIDC Authorization Code RP 的已编译策略与有界会话状态。
pub(crate) struct OidcRpPolicy {
    authorization_endpoint: Arc<str>,
    token_endpoint: Arc<str>,
    userinfo_endpoint: Option<Arc<str>>,
    introspection_endpoint: Option<Arc<str>>,
    issuer: Arc<str>,
    client_id: Arc<str>,
    client_secret: Arc<str>,
    client_auth: OidcClientAuth,
    scope: Arc<str>,
    redirect_uri: Arc<str>,
    callback_path: Arc<str>,
    logout_path: Arc<str>,
    post_logout_uri: Arc<str>,
    cookie_name: Arc<str>,
    session_ttl: Duration,
    pending_ttl: Duration,
    max_pending: usize,
    max_sessions: usize,
    timeout: Duration,
    client: reqwest::Client,
    /// HTTP client 的实际自定义 CA 身份；None 保留平台默认信任。
    ca_identity: Option<[u8; 32]>,
    id_token_verifier: JwtAuthPolicy,
    identity_headers: Arc<Vec<JwtIdentityHeader>>,
    pending: parking_lot::Mutex<HashMap<String, OidcPendingLogin>>,
    sessions: parking_lot::Mutex<HashMap<String, OidcSession>>,
}

impl OidcRpPolicy {
    /// 业务作用：将复用的 OIDC RP 收紧到门户独占入口与预算，避免 DSL 重复参数覆盖固定身份边界。
    ///
    /// 参数说明：
    /// - `origins`：是批准的门户 HTTPS origin
    /// - `capacity`：是管理会话硬上限。
    /// - `ttl`：是管理会话硬上限。
    ///
    /// 返回：回调、注销、Cookie 和 origin 均匹配时收紧资源；不匹配拒绝候选。
    pub(crate) fn bind_portal(
        &mut self,
        origins: &[String],
        capacity: usize,
        ttl: Duration,
    ) -> Result<()> {
        let redirect = reqwest::Url::parse(&self.redirect_uri)?;
        anyhow::ensure!(
            self.callback_path.as_ref() == "/api/developer/account/callback"
                && self.logout_path.as_ref() == "/api/developer/account/logout"
                && self.cookie_name.as_ref() == "naway_portal_oidc"
                && origins.contains(&redirect.origin().ascii_serialization()),
            "portal OIDC requires dedicated callback, logout, cookie and trusted redirect origin"
        );
        self.max_pending = self.max_pending.min(capacity);
        self.max_sessions = self.max_sessions.min(capacity);
        self.session_ttl = self.session_ttl.min(ttl);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OidcClientAuth {
    SecretBasic,
    SecretPost,
}

struct OidcPendingLogin {
    workspace_lease: Option<crate::control::ownership::state::Lease>,
    nonce: String,
    verifier: String,
    browser_binding: String,
    return_uri: String,
    expires_at: Instant,
}

#[derive(Clone)]
struct OidcSession {
    _workspace_lease: Option<crate::control::ownership::state::Lease>,
    consumer: Arc<str>,
    claims: serde_json::Value,
    identity_headers: Vec<(HeaderName, HeaderValue)>,
    expires_at: Instant,
}

/// OIDC RP 在认证相位返回的两类结果。
pub(crate) enum OidcRpDecision {
    /// 会话已验证，可冻结为本地可信身份。
    Authenticated {
        consumer: Arc<str>,
        claims: serde_json::Value,
        identity_headers: Vec<(HeaderName, HeaderValue)>,
    },
    /// 登录跳转、回调、退出或失败响应已经完成，主代理链必须立即短路。
    Response(Response<crate::BoxBody>),
}

struct RemoteJwks {
    endpoint: RemoteJwksEndpoint,
    issuer: Arc<str>,
    algorithm: Algorithm,
    client: reqwest::Client,
    /// 记录构建时实际读取的 CA，路径相同不代表信任材料未改变。
    ca_identity: Option<[u8; 32]>,
    timeout: Duration,
    min_ttl: Duration,
    max_ttl: Duration,
    stale_ttl: Duration,
    negative_ttl: Duration,
    state: RwLock<RemoteJwksState>,
    refresh: AsyncMutex<()>,
}

#[derive(PartialEq, Eq)]
enum RemoteJwksEndpoint {
    Direct(Arc<str>),
    Discovery(Arc<str>),
}

struct RemoteJwksState {
    keys: HashMap<String, Arc<DecodingKey>>,
    expires_at: Instant,
    stale_until: Instant,
    negative: HashMap<String, Instant>,
    next_retry: Instant,
}

// Discovery 包含 authorization_endpoint、token_endpoint 等标准元数据；只使用固定 issuer/JWKS
// 字段，其余元数据不参与目标选择，不能因正常附加字段而拒绝整个 IdP 文档。
#[derive(serde::Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// ext_authz / nginx auth_request 基础版已编译策略。
///
/// 策略只构造一个无请求体的鉴权子请求;原始下游 body 继续留给主链路流式转发。
#[derive(Clone, PartialEq, Eq)]
pub struct ExtAuthzPolicy {
    /// 鉴权服务目标。支持 `http(s)://host[:port][/path]` 或 `lb://service`。
    pub target: String,
    /// `lb://service` 或目标未带 path 时使用的鉴权路径;必须以 `/` 开头,可带 query。
    pub path: Option<String>,
    /// 鉴权子请求方法。基础版允许 GET/HEAD/POST,但 body 始终为空。
    pub method: Method,
    /// 鉴权外呼超时,单位毫秒;0 表示关闭超时。
    pub timeout_ms: u64,
    /// 鉴权服务不可达/超时时是否放行。默认 fail-closed。
    pub fail_open: bool,
    /// 显式转发给鉴权服务的原始请求实体硬上限；None 时保持无 body 子请求。
    pub body_max_bytes: Option<u64>,
    /// 明确 allow/deny 决策的本地缓存 TTL；None 时不缓存。
    pub cache_ttl: Option<Duration>,
    /// 单策略最多保留的决策数；缓存关闭时为零。
    pub cache_max_entries: usize,
    /// 连续依赖故障达到该值后打开独立熔断；零表示关闭。
    pub circuit_failure_threshold: u32,
    /// 熔断保持时间；到期只允许一个 half-open 探测。
    pub circuit_open: Duration,
    /// 允许从原始请求复制给鉴权服务的 header 名列表。
    pub request_headers: Vec<HeaderName>,
    /// 鉴权通过后允许从鉴权响应复制回主上游请求的 header 名列表。
    pub upstream_headers: Vec<HeaderName>,
}

/// API-Key 来源。
#[derive(Clone, PartialEq, Eq)]
enum ApiKeySource {
    /// 从请求头读取。
    Header(HeaderName),
    /// 从 query 参数读取。
    Query(String),
}

/// JWT token 来源。
#[derive(Clone, PartialEq, Eq)]
enum JwtTokenSource {
    /// 从 `Authorization: Bearer <token>` 读取。
    Bearer,
    /// 从指定 header 读取原始 token。
    Header(HeaderName),
}

/// 多认证策略组合方式。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SatisfyMode {
    /// 所有已配置认证方式都必须通过。
    All,
    /// 任一已配置认证方式通过即可。
    Any,
}

/// 同步鉴权子链的组合结果。
#[derive(Clone, Copy)]
pub struct SyncAuthState {
    /// 是否配置了 Basic/API-Key/HMAC/JWT 任一同步鉴权方式。
    pub configured: bool,
    /// 同步鉴权组合结果是否通过。
    pub ok: bool,
}

/// 异步本地认证完成后的请求局部结果。
pub(crate) struct ResolvedAuthState {
    /// 是否配置了任一本地认证方式。
    pub configured: bool,
    /// satisfy 组合是否通过。
    pub ok: bool,
    /// 认证成功后冻结的稳定主体。
    pub consumer: Option<Arc<str>>,
    /// 认证成功后冻结的完整 JWT claims。
    pub jwt_claims: Option<serde_json::Value>,
    /// SAML/LDAP 成功后待提交的网关身份头。
    pub identity_headers: Vec<(HeaderName, HeaderValue)>,
}

impl BasicAuthPolicy {
    /// 业务作用：判断请求是否携带正确 Basic 凭据。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    fn matches(&self, parts: &Parts) -> bool {
        basic_authorization_matches(&parts.headers, self.expected.as_slice())
    }

    /// 业务作用：生成 `WWW-Authenticate` 响应头值。
    fn challenge_value(&self) -> String {
        format!("Basic realm=\"{}\"", escape_header_quote(&self.realm))
    }
}

impl ApiKeyPolicy {
    /// 业务作用：验证请求携带的 API-Key，并统一兼容 SecretSource 明文和 Console 不可逆摘要两种事实。
    ///
    /// 参数说明：
    /// - `parts`：是下游请求 head。
    ///
    /// 返回：指定 header/query 的单值与期望材料常量时间一致时返回 true；缺失、编码非法或摘要不一致
    /// 均返回 false。
    fn matches(&self, parts: &Parts) -> bool {
        let value = match &self.source {
            ApiKeySource::Header(name) => parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok()),
            ApiKeySource::Query(name) => {
                query_param_raw(parts.uri.query().unwrap_or_default(), name)
            }
        };
        value.is_some_and(|value| match &self.expected {
            ApiKeyExpected::Plain(expected) => {
                constant_time_eq(value.as_bytes(), expected.as_slice())
            }
            ApiKeyExpected::Sha256(expected) => {
                let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
                constant_time_eq(actual.as_slice(), expected.as_slice())
            }
        })
    }
}

impl HmacAuthPolicy {
    /// 业务作用：验证不读取实体的兼容 HMAC-SHA256 请求；body 策略必须走有界认证慢路径。
    ///
    /// 参数说明：
    /// - `parts`：是下游请求 head。
    ///
    /// 返回：未启用 body 签名且 canonical contract 匹配时返回 true；其它情况返回 false。
    fn matches(&self, parts: &Parts) -> bool {
        self.matches_body(parts, None)
    }

    /// 业务作用：按策略声明决定是否把已聚合原始实体的 SHA-256 纳入 HMAC canonical contract。
    ///
    /// 参数说明：
    /// - `parts`：是请求 head
    /// - `body`：仅由有界认证慢路径提供，未启用 body 签名时忽略。
    ///
    /// 返回：时间、nonce、header、可选 body 摘要和签名全部匹配时返回 true。
    fn matches_body(&self, parts: &Parts, body: Option<&[u8]>) -> bool {
        let Some(signature) = header_str(parts, &self.signature_header) else {
            return false;
        };
        let Some(timestamp) = header_str(parts, &self.timestamp_header) else {
            return false;
        };
        if !timestamp_within_skew(timestamp, self.max_skew_ms) {
            return false;
        }
        let nonce = match &self.nonce_header {
            Some(name) => match header_str(parts, name) {
                Some(value) => Some(value),
                None => return false,
            },
            None => None,
        };
        let Some(canonical) = self.canonical_request(parts, timestamp, nonce, body) else {
            return false;
        };
        nasa::crypto::hmac_sha256_verify(&canonical, &self.secret, signature.trim())
    }

    /// 业务作用：构造稳定 HMAC canonical string，并在显式启用时追加原始实体 SHA-256。
    ///
    /// 参数说明：
    /// - `parts`：是请求 head
    /// - `timestamp`：是签名字段
    /// - `nonce`：是签名字段
    /// - `body`：是有界收集的原始实体。
    ///
    /// 返回：所需 header/body 完整时返回 canonical 文本；缺少声明字段时返回 None。
    fn canonical_request(
        &self,
        parts: &Parts,
        timestamp: &str,
        nonce: Option<&str>,
        body: Option<&[u8]>,
    ) -> Option<String> {
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or_else(|| parts.uri.path());
        let mut canonical = String::new();
        canonical.push_str(parts.method.as_str());
        canonical.push('\n');
        canonical.push_str(path_and_query);
        canonical.push('\n');
        canonical.push_str(timestamp.trim());
        canonical.push('\n');
        canonical.push_str(nonce.unwrap_or_default().trim());
        canonical.push('\n');
        for name in &self.signed_headers {
            let value = header_str(parts, name)?.trim();
            canonical.push_str(name.as_str());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\n');
        }
        if self.body_max_bytes.is_some() {
            let digest = Sha256::digest(body?);
            canonical.push_str("body-sha256:");
            use std::fmt::Write as _;
            for byte in digest {
                write!(&mut canonical, "{byte:02x}").ok()?;
            }
            canonical.push('\n');
        }
        Some(canonical)
    }

    /// 业务作用：是否开启防重放(需已配 nonce_header)。
    fn replay_enabled(&self) -> bool {
        self.replay_protection && self.nonce_header.is_some()
    }

    /// 业务作用：读取请求里的 nonce 值(仅当配置了 nonce_header)。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    fn nonce_value<'a>(&self, parts: &'a Parts) -> Option<&'a str> {
        let name = self.nonce_header.as_ref()?;
        header_str(parts, name)
    }

    /// 业务作用：防重放去重的时间窗口(= 允许的时间戳偏差,超窗时间戳本就被拒)。
    fn replay_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.max_skew_ms.max(1))
    }
}

impl JwtAuthPolicy {
    /// 业务作用：使用当前已缓存 key 同步判断 JWT；静态 key 与热 JWKS 命中不发生网络 I/O。
    ///
    /// 参数说明：
    /// - `parts`：是下游请求 head。
    ///
    /// 返回：token 签名、算法与 claims 全部通过时返回 true；远端 key 尚未拉取时返回 false。
    fn matches(&self, parts: &Parts) -> bool {
        self.verified_payload_from_parts(parts).is_some()
    }

    /// 业务作用：从 route 固定 token source 提取 compact JWT，不读取 query/cookie 等未声明位置。
    ///
    /// 参数说明：
    /// - `parts`：是下游请求 head。
    ///
    /// 返回：Bearer 或指定 header 中的非空 token；缺失/非法 UTF-8 返回 None。
    fn token<'a>(&self, parts: &'a Parts) -> Option<&'a str> {
        match &self.source {
            JwtTokenSource::Bearer => bearer_token(parts),
            JwtTokenSource::Header(name) => header_str(parts, name).map(str::trim),
        }
    }

    /// 业务作用：从请求执行同步签名与 claims 验证，供认证后身份/claims 提取复用同一信任边界。
    ///
    /// 参数说明：
    /// - `parts`：是已经完成远端 key 解析的请求 head。
    ///
    /// 返回：合法 JWT payload object；缺失 token 或验证失败返回 None。
    fn verified_payload_from_parts(&self, parts: &Parts) -> Option<serde_json::Value> {
        self.verified_payload(self.token(parts)?)
    }

    /// 业务作用：使用本地 key 状态验证 compact JWS，并拒绝 token 自带的远端 key 指针。
    ///
    /// 参数说明：
    /// - `token`：是未经信任的 compact serialization。
    ///
    /// 返回：算法、签名与 claims 均通过时返回 JSON object；任何错误返回 None。
    fn verified_payload(&self, token: &str) -> Option<serde_json::Value> {
        let token = self.prepare_signed_token(token)?;
        let token = token.as_ref();
        let header = self.validate_header(token)?;
        let payload = match &self.verifier {
            JwtVerifier::Hs256(secret) => verify_hs256_token(token, secret.as_ref())?,
            JwtVerifier::Static(key, _) => self.verify_asymmetric(token, key)?,
            JwtVerifier::Remote(remote) => {
                let kid = header.kid.as_deref()?;
                let key = remote.cached_key(kid)?;
                self.verify_asymmetric(token, &key)?
            }
        };
        self.claims_match(&payload).then_some(payload)
    }

    /// 业务作用：为 remote verifier 执行单飞 refresh/rotation，再复用统一签名与 claims 校验。
    ///
    /// 参数说明：
    /// - `token`：是未经信任的 compact serialization。
    ///
    /// 返回：可用 key 验证成功返回 payload；依赖、kid、算法或 claims 错误返回 None。
    async fn verified_payload_resolved(&self, token: &str) -> Option<serde_json::Value> {
        let token = self.prepare_signed_token(token)?;
        let token = token.as_ref();
        let header = self.validate_header(token)?;
        let payload = match &self.verifier {
            JwtVerifier::Remote(remote) => {
                let kid = header.kid.as_deref()?;
                let key = remote.resolve_key(kid).await.ok().flatten()?;
                self.verify_asymmetric(token, &key)?
            }
            _ => return self.verified_payload(token),
        };
        self.claims_match(&payload).then_some(payload)
    }

    /// 业务作用：在配置 JWE 时先严格解密 compact envelope，再把 plaintext 作为嵌套 JWS 验证输入。
    ///
    /// 参数说明：
    /// - `token`：是客户端提交的 JWS 或 JWE compact serialization。
    ///
    /// 返回：未启用 JWE 时借用原 token；启用时仅接受 RSA-OAEP-256/A256GCM、`cty=JWT` 且无动态 key/zip 的有界 UTF-8 plaintext。
    fn prepare_signed_token<'a>(&self, token: &'a str) -> Option<Cow<'a, str>> {
        #[cfg(feature = "enterprise-jwe")]
        if let Some(layer) = &self.jwe {
            if token.len() > layer.max_compact_bytes || token.split('.').count() != 5 {
                return None;
            }
            let (plaintext, header) =
                josekit::jwe::deserialize_compact(token, &layer.decrypter).ok()?;
            if header.algorithm() != Some("RSA-OAEP-256")
                || header.content_encryption() != Some("A256GCM")
                || header.content_type() != Some("JWT")
                || header.compression().is_some()
                || header.jwk_set_url().is_some()
                || header.jwk().is_some()
                || header.x509_url().is_some()
                || header.x509_certificate_chain().is_some()
                || header
                    .critical()
                    .is_some_and(|critical| !critical.is_empty())
                || plaintext.len() > self.max_token_bytes
            {
                return None;
            }
            return String::from_utf8(plaintext).ok().map(Cow::Owned);
        }
        Some(Cow::Borrowed(token))
    }

    /// 业务作用：固定 JWS header 信任边界，只接受 route 声明算法并拒绝 `jku/x5u/jwk/x5c/crit`。
    ///
    /// 参数说明：
    /// - `token`：是 compact JWT。
    ///
    /// 返回：长度、段数和 header 合法时返回解析结果；动态 key 指针或算法混淆返回 None。
    fn validate_header(&self, token: &str) -> Option<jsonwebtoken::Header> {
        if token.is_empty() || token.len() > self.max_token_bytes || token.split('.').count() != 3 {
            return None;
        }
        let header = jsonwebtoken::decode_header(token).ok()?;
        if header.alg != self.algorithm
            || header.jku.is_some()
            || header.x5u.is_some()
            || header.jwk.is_some()
            || header.x5c.is_some()
            || header.crit.as_ref().is_some_and(|crit| !crit.is_empty())
        {
            return None;
        }
        Some(header)
    }

    /// 业务作用：用固定 family 的静态/JWKS key 验证 RS256/ES256，不让库自动选择其它算法或 claims 语义。
    ///
    /// 参数说明：
    /// - `token`：是 compact JWT
    /// - `key`：已通过 PEM/JWK key type 与 alg pinning。
    ///
    /// 返回：密码学签名有效时返回 payload；库错误或 payload 非 object 返回 None。
    fn verify_asymmetric(&self, token: &str, key: &DecodingKey) -> Option<serde_json::Value> {
        let mut validation = Validation::new(self.algorithm);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let payload = jsonwebtoken::decode::<serde_json::Value>(token, key, &validation)
            .ok()?
            .claims;
        payload.is_object().then_some(payload)
    }

    /// 业务作用：从签名、时效与 issuer/audience 均有效的 JWT 中提取有界 `sub`。
    ///
    /// 参数说明：
    /// - `parts`：是下游请求 head。
    ///
    /// 返回：合法非空 `sub` 返回共享字符串，否则返回 None。
    fn authenticated_subject(&self, parts: &Parts) -> Option<Arc<str>> {
        self.authenticated_claim(parts, "sub")
    }

    /// 业务作用：从已验证 payload 提取边缘路由声明的字符串 claim，禁止客户端身份头替代 JWT 权威。
    ///
    /// 参数说明：
    /// - `parts`：是请求 head
    /// - `claim`：是配置固定字段名。
    ///
    /// 返回：非空、≤256 字节、无控制字符的字符串返回共享值，否则返回 None。
    fn authenticated_claim(&self, parts: &Parts, claim: &str) -> Option<Arc<str>> {
        let payload = self.verified_payload_from_parts(parts)?;
        bounded_jwt_claim(&payload, claim)
    }

    /// 业务作用：执行公共 JWT 与 OIDC claims 约束，包含时间、issuer、audience/azp、nonce 与主体。
    ///
    /// 参数说明：
    /// - `payload`：是密码学签名已通过的 JSON object。
    ///
    /// 返回：全部声明满足 route pinning 时返回 true；缺失必需项、类型错误或时间越界返回 false。
    fn claims_match(&self, payload: &serde_json::Value) -> bool {
        let Some(now) = unix_now_secs() else {
            return false;
        };
        let exp = payload.get("exp").and_then(json_i64);
        if self.require_oidc_claims && exp.is_none() {
            return false;
        }
        if exp.is_some_and(|exp| now > exp.saturating_add(self.leeway_secs)) {
            return false;
        }
        if let Some(nbf) = payload.get("nbf").and_then(json_i64) {
            if now.saturating_add(self.leeway_secs) < nbf {
                return false;
            }
        }
        let issued_at = payload.get("iat").and_then(json_i64);
        if self.require_oidc_claims && issued_at.is_none() {
            return false;
        }
        if issued_at.is_some_and(|iat| iat > now.saturating_add(self.leeway_secs)) {
            return false;
        }
        if let Some(issuer) = &self.issuer {
            if payload.get("iss").and_then(|value| value.as_str()) != Some(issuer.as_str()) {
                return false;
            }
        } else if self.require_oidc_claims {
            return false;
        }
        if let Some(audience) = &self.audience {
            if !jwt_audience_matches(payload.get("aud"), audience) {
                return false;
            }
        } else if self.require_oidc_claims {
            return false;
        }
        if let Some(azp) = &self.authorized_party {
            if payload.get("azp").and_then(|value| value.as_str()) != Some(azp.as_str()) {
                return false;
            }
        } else if jwt_audience_count(payload.get("aud")) > 1 {
            return false;
        }
        if let Some(nonce) = &self.nonce {
            if payload.get("nonce").and_then(|value| value.as_str()) != Some(nonce.as_str()) {
                return false;
            }
        }
        if self.require_oidc_claims
            && payload
                .get("sub")
                .and_then(|value| value.as_str())
                .is_none_or(str::is_empty)
        {
            return false;
        }
        true
    }
}

impl OidcRpPolicy {
    /// 业务作用：执行 OIDC 浏览器入口的 session、回调、退出或登录跳转，只有已验证 IdP 结果能形成身份。
    ///
    /// 参数说明：
    /// - `parts`：是尚未注入身份头的原始请求 head。
    ///
    /// 返回：有效 session 返回可信身份；回调/退出/登录和任何失败返回应立即短路的响应。
    pub(crate) async fn authenticate(&self, parts: &Parts) -> OidcRpDecision {
        self.prune_expired();
        if parts.uri.path() == self.logout_path.as_ref() {
            return self.logout(parts);
        }
        if parts.uri.path() == self.callback_path.as_ref() {
            return self.callback(parts).await;
        }
        if let Some(session_id) = oidc_cookie(parts, self.cookie_name.as_ref()) {
            if let Some(session) = self.sessions.lock().get(session_id).cloned() {
                if Instant::now() < session.expires_at {
                    return OidcRpDecision::Authenticated {
                        consumer: session.consumer,
                        claims: session.claims,
                        identity_headers: session.identity_headers,
                    };
                }
            }
            self.sessions.lock().remove(session_id);
        }
        self.begin_login(parts)
    }

    /// 业务作用：建立一次绑定浏览器、state、nonce 与 PKCE verifier 的短期授权事务。
    ///
    /// 参数说明：
    /// - `parts`：提供原始 origin-form URI，成功登录后只允许返回该本地 URI。
    ///
    /// 返回：容量与随机源可用时返回 302 到固定授权 endpoint；失败返回 503，绝不匿名放行。
    fn begin_login(&self, parts: &Parts) -> OidcRpDecision {
        let mut pending = self.pending.lock();
        if pending.len() >= self.max_pending {
            return OidcRpDecision::Response(crate::text_status(
                503,
                "OIDC login capacity reached",
            ));
        }
        // 授权跳转前取得归属名额；认证中的临时事务不能挤占其它工作区的会话空间。
        let workspace_lease = match parts
            .extensions
            .get::<crate::control::ownership::state::Budget>()
            .map(|budget| budget.acquire())
            .transpose()
        {
            Ok(lease) => lease,
            Err(_) => {
                return OidcRpDecision::Response(crate::text_status(
                    503,
                    "workspace identity capacity reached",
                ))
            }
        };
        let state = match oidc_random_token() {
            Ok(value) => value,
            Err(_) => {
                return OidcRpDecision::Response(crate::text_status(
                    503,
                    "OIDC random source unavailable",
                ))
            }
        };
        let nonce = match oidc_random_token() {
            Ok(value) => value,
            Err(_) => {
                return OidcRpDecision::Response(crate::text_status(
                    503,
                    "OIDC random source unavailable",
                ))
            }
        };
        let verifier = match oidc_random_token() {
            Ok(value) => value,
            Err(_) => {
                return OidcRpDecision::Response(crate::text_status(
                    503,
                    "OIDC random source unavailable",
                ))
            }
        };
        let browser_binding = match oidc_random_token() {
            Ok(value) => value,
            Err(_) => {
                return OidcRpDecision::Response(crate::text_status(
                    503,
                    "OIDC random source unavailable",
                ))
            }
        };
        let return_uri = parts
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .filter(|value| valid_oidc_local_path(value))
            .unwrap_or("/")
            .to_string();
        use sha2::Digest as _;
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()));
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client_id.as_ref())
            .append_pair("redirect_uri", self.redirect_uri.as_ref())
            .append_pair("scope", self.scope.as_ref())
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .finish();
        let location = format!("{}?{query}", self.authorization_endpoint);
        pending.insert(
            state,
            OidcPendingLogin {
                workspace_lease,
                nonce,
                verifier,
                browser_binding: browser_binding.clone(),
                return_uri,
                expires_at: Instant::now() + self.pending_ttl,
            },
        );
        let state_cookie = format!(
            "{}_state={}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
            self.cookie_name,
            browser_binding,
            self.pending_ttl.as_secs()
        );
        OidcRpDecision::Response(oidc_redirect(&location, Some(&state_cookie)))
    }

    /// 业务作用：消费一次性授权码回调，复验浏览器绑定/state/nonce/PKCE、token、可选 introspection
    /// 与 userinfo 后建立受保护 session。
    ///
    /// 参数说明：
    /// - `parts`：必须是固定 callback path 的 GET 请求。
    ///
    /// 返回：全部证据通过返回 303 到原本地 URI并设置 session cookie；任何缺失或依赖失败返回 401/502。
    async fn callback(&self, parts: &Parts) -> OidcRpDecision {
        if parts.method != Method::GET {
            return OidcRpDecision::Response(crate::text_status(405, "OIDC callback requires GET"));
        }
        let query = parts.uri.query().unwrap_or_default();
        let Some(state) = oidc_unique_query_param(query, "state") else {
            return OidcRpDecision::Response(crate::text_status(400, "invalid OIDC state"));
        };
        let Some(code) = oidc_unique_query_param(query, "code") else {
            return OidcRpDecision::Response(crate::text_status(400, "invalid OIDC code"));
        };
        if state.len() > 256 || code.is_empty() || code.len() > 8_192 {
            return OidcRpDecision::Response(crate::text_status(400, "invalid OIDC callback"));
        }
        // state 一旦出现就从表中取走；后续 token/nonce 失败也不能重放同一授权事务。
        let Some(pending) = self.pending.lock().remove(&state) else {
            return OidcRpDecision::Response(crate::text_status(401, "expired OIDC state"));
        };
        if Instant::now() >= pending.expires_at {
            return OidcRpDecision::Response(crate::text_status(401, "expired OIDC state"));
        }
        let state_cookie_name = format!("{}_state", self.cookie_name);
        let browser_binding = oidc_cookie(parts, &state_cookie_name);
        if browser_binding.is_none_or(|value| {
            !constant_time_eq(value.as_bytes(), pending.browser_binding.as_bytes())
        }) {
            return OidcRpDecision::Response(crate::text_status(
                401,
                "OIDC browser binding mismatch",
            ));
        }
        let session = match self.exchange_code(&code, &pending).await {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(%error, "OIDC authorization code exchange rejected");
                return OidcRpDecision::Response(crate::text_status(
                    502,
                    "OIDC identity provider unavailable or rejected response",
                ));
            }
        };
        let session_id = match oidc_random_token() {
            Ok(value) => value,
            Err(_) => {
                return OidcRpDecision::Response(crate::text_status(
                    503,
                    "OIDC random source unavailable",
                ))
            }
        };
        let max_age = session
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs();
        let mut sessions = self.sessions.lock();
        if sessions.len() >= self.max_sessions {
            return OidcRpDecision::Response(crate::text_status(
                503,
                "OIDC session capacity reached",
            ));
        }
        sessions.insert(session_id.clone(), session);
        drop(sessions);
        let session_cookie = format!(
            "{}={}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
            self.cookie_name, session_id, max_age
        );
        let clear_state = format!(
            "{}_state=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            self.cookie_name
        );
        let mut response = oidc_redirect(&pending.return_uri, Some(&session_cookie));
        if let Ok(value) = HeaderValue::from_str(&clear_state) {
            response
                .headers_mut()
                .append(http::header::SET_COOKIE, value);
        }
        *response.status_mut() = StatusCode::SEE_OTHER;
        OidcRpDecision::Response(response)
    }

    /// 业务作用：以固定 token endpoint 和客户端认证交换授权码，并把 token/introspection/userinfo
    /// 证据合并成受限 session 身份。
    ///
    /// 参数说明：
    /// - `code`：是一次性回调码
    /// - `pending`：冻结 nonce、verifier 和原始本地 URI。
    ///
    /// 返回：全部远端与 claims 证据通过时返回 session；任何协议、签名、issuer/audience/sub 失败返回错误。
    async fn exchange_code(&self, code: &str, pending: &OidcPendingLogin) -> Result<OidcSession> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", self.redirect_uri.to_string()),
            ("client_id", self.client_id.to_string()),
            ("code_verifier", pending.verifier.clone()),
        ];
        let mut request = self.client.post(self.token_endpoint.as_ref());
        match self.client_auth {
            OidcClientAuth::SecretBasic => {
                request =
                    request.basic_auth(self.client_id.as_ref(), Some(self.client_secret.as_ref()));
            }
            OidcClientAuth::SecretPost => {
                form.push(("client_secret", self.client_secret.to_string()));
            }
        }
        let token: OidcTokenResponse =
            fetch_oidc_json(request.form(&form), self.timeout, "token").await?;
        anyhow::ensure!(
            !token.access_token.is_empty() && token.access_token.len() <= MAX_JWT_TOKEN_BYTES,
            "OIDC access token is empty or exceeds limit"
        );
        anyhow::ensure!(
            !token.id_token.is_empty() && token.id_token.len() <= MAX_JWT_TOKEN_BYTES,
            "OIDC ID token is empty or exceeds limit"
        );
        anyhow::ensure!(
            token.token_type.eq_ignore_ascii_case("bearer"),
            "OIDC token_type is not Bearer"
        );
        let mut claims = self
            .id_token_verifier
            .verified_payload_resolved(&token.id_token)
            .await
            .context("OIDC ID token verification failed")?;
        anyhow::ensure!(
            claims.get("nonce").and_then(|value| value.as_str()) == Some(pending.nonce.as_str()),
            "OIDC ID token nonce mismatch"
        );
        let subject = bounded_jwt_claim(&claims, "sub").context("OIDC ID token sub is invalid")?;
        if let Some(endpoint) = &self.introspection_endpoint {
            self.verify_introspection(endpoint, &token.access_token, subject.as_ref())
                .await?;
        }
        if let Some(endpoint) = &self.userinfo_endpoint {
            let userinfo: serde_json::Value = fetch_oidc_json(
                self.client
                    .get(endpoint.as_ref())
                    .bearer_auth(&token.access_token),
                self.timeout,
                "userinfo",
            )
            .await?;
            anyhow::ensure!(
                userinfo.get("sub").and_then(|value| value.as_str()) == Some(subject.as_ref()),
                "OIDC userinfo sub mismatch"
            );
            merge_oidc_userinfo(&mut claims, userinfo)?;
        }
        let identity_headers = oidc_identity_headers(&claims, &self.identity_headers);
        let now_unix = unix_now_secs().context("system clock is before Unix epoch")?;
        let token_remaining = claims
            .get("exp")
            .and_then(json_i64)
            .and_then(|exp| exp.checked_sub(now_unix))
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Duration::from_secs(seconds as u64))
            .context("OIDC ID token is expired")?;
        let advertised = token
            .expires_in
            .map(Duration::from_secs)
            .unwrap_or(self.session_ttl);
        let ttl = self.session_ttl.min(token_remaining).min(advertised);
        anyhow::ensure!(!ttl.is_zero(), "OIDC session TTL is zero");
        Ok(OidcSession {
            // 回调已经消费 pending，身份验证完成后由同一名额承接 session，不产生容量空窗。
            _workspace_lease: pending.workspace_lease.clone(),
            consumer: subject,
            claims,
            identity_headers,
            expires_at: Instant::now() + ttl,
        })
    }

    /// 业务作用：调用固定 introspection endpoint 复验 access token 仍 active 且 issuer/audience/sub
    /// 与已验证 ID token 一致。
    ///
    /// 参数说明：
    /// - `endpoint`：是构建期固定 HTTPS URL
    /// - `token`：是 token endpoint 返回值
    /// - `subject`：来自已验签 ID token。
    ///
    /// 返回：所有字段严格匹配时成功；不活跃、身份不一致或依赖失败均返回错误。
    async fn verify_introspection(&self, endpoint: &str, token: &str, subject: &str) -> Result<()> {
        let mut form = vec![("token", token.to_string())];
        let mut request = self.client.post(endpoint);
        match self.client_auth {
            OidcClientAuth::SecretBasic => {
                request =
                    request.basic_auth(self.client_id.as_ref(), Some(self.client_secret.as_ref()));
            }
            OidcClientAuth::SecretPost => {
                form.push(("client_id", self.client_id.to_string()));
                form.push(("client_secret", self.client_secret.to_string()));
            }
        }
        let value: serde_json::Value =
            fetch_oidc_json(request.form(&form), self.timeout, "introspection").await?;
        anyhow::ensure!(
            value.get("active").and_then(|value| value.as_bool()) == Some(true),
            "OIDC introspection token is inactive"
        );
        anyhow::ensure!(
            value.get("iss").and_then(|value| value.as_str()) == Some(self.issuer.as_ref()),
            "OIDC introspection issuer mismatch"
        );
        anyhow::ensure!(
            jwt_audience_matches(value.get("aud"), self.client_id.as_ref()),
            "OIDC introspection audience mismatch"
        );
        anyhow::ensure!(
            value.get("sub").and_then(|value| value.as_str()) == Some(subject),
            "OIDC introspection subject mismatch"
        );
        Ok(())
    }

    /// 业务作用：撤销当前浏览器 session，并只重定向到构建期固定的本地退出后 URI。
    ///
    /// 参数说明：
    /// - `parts`：提供可选 session cookie。
    ///
    /// 返回：返回 303 并清除 session/state cookie；不存在 session 也保持幂等。
    fn logout(&self, parts: &Parts) -> OidcRpDecision {
        if let Some(session_id) = oidc_cookie(parts, self.cookie_name.as_ref()) {
            self.sessions.lock().remove(session_id);
        }
        let clear_session = format!(
            "{}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            self.cookie_name
        );
        let clear_state = format!(
            "{}_state=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            self.cookie_name
        );
        let mut response = oidc_redirect(self.post_logout_uri.as_ref(), Some(&clear_session));
        if let Ok(value) = HeaderValue::from_str(&clear_state) {
            response
                .headers_mut()
                .append(http::header::SET_COOKIE, value);
        }
        *response.status_mut() = StatusCode::SEE_OTHER;
        OidcRpDecision::Response(response)
    }

    /// 业务作用：回收过期登录事务和 session，确保长期运行下内存仍受配置容量约束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；只删除当前单调时钟已到期记录。
    fn prune_expired(&self) {
        let now = Instant::now();
        self.pending
            .lock()
            .retain(|_, pending| now < pending.expires_at);
        self.sessions
            .lock()
            .retain(|_, session| now < session.expires_at);
    }
}

#[derive(serde::Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    id_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// 业务作用：有界读取固定 IdP endpoint 的 JSON 响应，统一执行总 deadline、status、media 和实体上限。
///
/// 参数说明：
/// - `request`：已由固定 HTTPS client 构建
/// - `timeout`：覆盖 head/body
/// - `kind`：仅用于低敏错误。
///
/// 返回：合法 JSON 解码为 T；网络、非 2xx、媒体类型、长度、超时或 schema 错误返回失败。
async fn fetch_oidc_json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
    timeout: Duration,
    kind: &str,
) -> Result<T> {
    use futures::StreamExt as _;

    tokio::time::timeout(timeout, async {
        let response = request.send().await?;
        if !response.status().is_success() {
            bail!("OIDC {kind} endpoint returned HTTP {}", response.status());
        }
        let media = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or_default()
            .trim();
        if !media.eq_ignore_ascii_case("application/json") && !media.ends_with("+json") {
            bail!("OIDC {kind} endpoint did not return JSON");
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_OIDC_RESPONSE_BYTES as u64)
        {
            bail!("OIDC {kind} response exceeds body limit");
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("read OIDC {kind} response"))?;
            if body.len().saturating_add(chunk.len()) > MAX_OIDC_RESPONSE_BYTES {
                bail!("OIDC {kind} response exceeds body limit");
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).with_context(|| format!("decode OIDC {kind} JSON"))
    })
    .await
    .with_context(|| format!("OIDC {kind} total timeout"))?
}

/// 业务作用：将受信 userinfo 的补充 claim 合入已验签 ID token，同时禁止覆盖核心权威字段。
///
/// 参数说明：
/// - `claims`：是已验签 token object
/// - `userinfo`：已从固定 HTTPS endpoint 有界取得且 sub 已匹配。
///
/// 返回：两个值均为 object 时合并非核心字段；类型错误返回失败。
fn merge_oidc_userinfo(claims: &mut serde_json::Value, userinfo: serde_json::Value) -> Result<()> {
    let claims = claims
        .as_object_mut()
        .context("OIDC ID token claims are not an object")?;
    let userinfo = userinfo
        .as_object()
        .context("OIDC userinfo is not an object")?;
    for (key, value) in userinfo {
        if matches!(
            key.as_str(),
            "iss" | "aud" | "azp" | "sub" | "nonce" | "exp" | "iat"
        ) {
            continue;
        }
        claims.insert(key.clone(), value.clone());
    }
    Ok(())
}

/// 业务作用：只从已验证 OIDC claims 生成配置声明的身份头，非法或非字符串 claim 不注入。
///
/// 参数说明：
/// - `claims`：是 token/userinfo 合并后的受信 object
/// - `mappings`：已在构建期校验 header 名。
///
/// 返回：返回长度和 header 编码均合法的身份头集合。
fn oidc_identity_headers(
    claims: &serde_json::Value,
    mappings: &[JwtIdentityHeader],
) -> Vec<(HeaderName, HeaderValue)> {
    mappings
        .iter()
        .filter_map(|mapping| {
            let value = claims.get(mapping.claim.as_ref())?.as_str()?;
            if value.is_empty()
                || value.len() > MAX_JWT_IDENTITY_BYTES
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return None;
            }
            HeaderValue::from_str(value)
                .ok()
                .map(|value| (mapping.header.clone(), value))
        })
        .collect()
}

/// 业务作用：生成 OAuth state/nonce/verifier/session 的 256 位不可预测 URL-safe token。
///
/// 参数说明: 无。
///
/// 返回：系统随机源可用时返回无 padding Base64URL；失败返回错误并阻止登录。
fn oidc_random_token() -> Result<String> {
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).context("OIDC random source failed")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random))
}

/// 业务作用：从所有 Cookie header 中提取唯一指定 cookie，拒绝重复同名值造成解析歧义。
///
/// 参数说明：
/// - `parts`：是原始请求 head
/// - `name`：是构建期安全 cookie 名。
///
/// 返回：恰好一个非空且有界值时返回借用；缺失、重复或非法返回 None。
fn oidc_cookie<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header in parts.headers.get_all(http::header::COOKIE) {
        let raw = header.to_str().ok()?;
        for item in raw.split(';') {
            let Some((key, value)) = item.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() || value.is_empty() || value.len() > 256 {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

/// 业务作用：读取回调 query 中恰好一个参数并按标准 form 规则解码，重复值一律拒绝。
///
/// 参数说明：
/// - `query`：是原始 query
/// - `name`：固定为 state 或 code。
///
/// 返回：唯一值返回 owned String；缺失、重复或解码结果含控制字符时返回 None。
fn oidc_unique_query_param(query: &str, name: &str) -> Option<String> {
    let mut found = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == name {
            if found.is_some() || value.bytes().any(|byte| byte.is_ascii_control()) {
                return None;
            }
            found = Some(value.into_owned());
        }
    }
    found
}

/// 业务作用：构造只指向构建期固定 IdP URL 或已保存本地 origin URI 的重定向响应。
///
/// 参数说明：
/// - `location`：已由安全来源生成
/// - `cookie`：是可选受保护 Set-Cookie 值。
///
/// 返回：header 可编码时返回 302；防御性编码失败返回 500。
fn oidc_redirect(location: &str, cookie: Option<&str>) -> Response<crate::BoxBody> {
    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::LOCATION, location);
    if let Some(cookie) = cookie {
        builder = builder.header(http::header::SET_COOKIE, cookie);
    }
    builder
        .body(crate::full_body(Bytes::new()))
        .unwrap_or_else(|_| crate::text_status(500, "cannot build OIDC redirect"))
}

/// 业务作用：从已验签 payload 提取可作为授权主体或身份头来源的有界字符串 claim。
///
/// 参数说明：
/// - `payload`：是完成签名与 claims 门的 JSON object
/// - `claim`：是 route 固定字段名。
///
/// 返回：非空、长度受限且无控制字符时返回共享值；其它类型或非法文本返回 None。
fn bounded_jwt_claim(payload: &serde_json::Value, claim: &str) -> Option<Arc<str>> {
    let value = payload.get(claim)?.as_str()?.trim();
    (!value.is_empty()
        && value.len() <= MAX_JWT_IDENTITY_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| Arc::from(value))
}

/// 业务作用：验证兼容 HS256 token，并与 asymmetric 路径共用外层 header 与 claims 门。
///
/// 参数说明：
/// - `token`：是 compact JWT
/// - `secret`：是构建期解析并冻结的 route secret。
///
/// 返回：签名正确且 payload 是 JSON object 时返回 payload；格式或签名错误返回 None。
fn verify_hs256_token(token: &str, secret: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if header_b64.is_empty() || payload_b64.is_empty() || signature_b64.is_empty() {
        return None;
    }
    let signature = nasa::crypto::base64_url_decode(signature_b64).ok()?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_hex = hex_lower_bytes(signature.as_slice());
    if !nasa::crypto::hmac_sha256_verify(&signing_input, secret, &signature_hex) {
        return None;
    }
    let payload = decode_jwt_json(payload_b64)?;
    payload.is_object().then_some(payload)
}

impl RemoteJwks {
    /// 业务作用：从当前未过期或 stale 窗内状态读取 key，供认证后身份提取保持同步且零网络 I/O。
    ///
    /// 参数说明：
    /// - `kid`：是已通过长度检查的受信查找键。
    ///
    /// 返回：fresh key 或仍在 stale 窗内的已知 key；未知/过期返回 None。
    fn cached_key(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        let now = Instant::now();
        let state = self.state.read();
        (now < state.stale_until)
            .then(|| state.keys.get(kid).cloned())
            .flatten()
    }

    /// 业务作用：按 kid 解析可轮换 JWKS key，使用单飞 refresh、负缓存、退避和有界 stale 策略抑制风暴。
    ///
    /// 参数说明：
    /// - `kid`：来自已验证 JWS header，必须精确匹配固定 endpoint 返回的 key。
    ///
    /// 返回：fresh/允许 stale 的 key 返回 Some；未知 kid 返回 None；网络/协议错误返回错误并 fail closed。
    async fn resolve_key(&self, kid: &str) -> Result<Option<Arc<DecodingKey>>> {
        if kid.is_empty()
            || kid.len() > MAX_JWT_IDENTITY_BYTES
            || kid.bytes().any(|byte| byte.is_ascii_control())
        {
            return Ok(None);
        }
        let now = Instant::now();
        {
            let state = self.state.read();
            if now < state.expires_at {
                if let Some(key) = state.keys.get(kid) {
                    return Ok(Some(key.clone()));
                }
                if state
                    .negative
                    .get(kid)
                    .is_some_and(|expires| now < *expires)
                {
                    return Ok(None);
                }
            }
        }
        let _refresh = self.refresh.lock().await;
        let now = Instant::now();
        {
            let state = self.state.read();
            if now < state.expires_at {
                if let Some(key) = state.keys.get(kid) {
                    return Ok(Some(key.clone()));
                }
                if state
                    .negative
                    .get(kid)
                    .is_some_and(|expires| now < *expires)
                {
                    return Ok(None);
                }
            }
            if now < state.next_retry {
                return if now < state.stale_until {
                    Ok(state.keys.get(kid).cloned())
                } else {
                    bail!("JWKS refresh is in backoff and stale window expired")
                };
            }
        }

        match self.fetch_keys().await {
            Ok((keys, ttl)) => {
                let mut state = self.state.write();
                let now = Instant::now();
                state.keys = keys;
                state.expires_at = now + ttl;
                state.stale_until = state.expires_at + self.stale_ttl;
                state.next_retry = now;
                state.negative.clear();
                if let Some(key) = state.keys.get(kid) {
                    return Ok(Some(key.clone()));
                }
                state
                    .negative
                    .insert(kid.to_string(), now + self.negative_ttl);
                Ok(None)
            }
            Err(error) => {
                let mut state = self.state.write();
                let now = Instant::now();
                state.next_retry = now + self.min_ttl.min(Duration::from_secs(5));
                // 已知 key 仅能在显式 stale 窗内兜底；未知 kid 永不因依赖故障猜测或复用其它 key。
                if now < state.stale_until {
                    if let Some(key) = state.keys.get(kid) {
                        tracing::warn!(%error, "JWKS refresh failed; use bounded stale key");
                        return Ok(Some(key.clone()));
                    }
                }
                Err(error)
            }
        }
    }

    /// 业务作用：从固定 HTTPS JWKS 或 issuer-pinned discovery 获取完整 key 集并编译匹配算法的验证器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：至少一个唯一 kid 的匹配 key 与有界 TTL；issuer/URL/media/大小/key type/alg 错误返回失败。
    async fn fetch_keys(&self) -> Result<(HashMap<String, Arc<DecodingKey>>, Duration)> {
        let jwks_uri = match &self.endpoint {
            RemoteJwksEndpoint::Direct(uri) => uri.to_string(),
            RemoteJwksEndpoint::Discovery(uri) => {
                let (document, _) =
                    fetch_bounded_json::<OidcDiscoveryDocument>(&self.client, uri, self.timeout)
                        .await?;
                if document.issuer != self.issuer.as_ref() {
                    bail!("OIDC discovery issuer does not match pinned issuer");
                }
                validate_https_url(&document.jwks_uri, "OIDC jwks_uri")?;
                if uri_authority(uri)? != uri_authority(&document.jwks_uri)? {
                    bail!("OIDC discovery jwks_uri must use the pinned discovery authority");
                }
                document.jwks_uri
            }
        };
        let (set, advertised_ttl) =
            fetch_bounded_json::<jsonwebtoken::jwk::JwkSet>(&self.client, &jwks_uri, self.timeout)
                .await?;
        if set.keys.is_empty() || set.keys.len() > MAX_JWKS_KEYS {
            bail!("JWKS key count must be within 1..={MAX_JWKS_KEYS}");
        }
        let mut keys = HashMap::with_capacity(set.keys.len());
        for jwk in set.keys {
            let Some(kid) = jwk.common.key_id.as_deref() else {
                continue;
            };
            if kid.is_empty()
                || kid.len() > MAX_JWT_IDENTITY_BYTES
                || jwk.common.x509_url.is_some()
                || jwk.common.key_algorithm.as_ref().is_none_or(|algorithm| {
                    algorithm.to_string() != format!("{:?}", self.algorithm)
                })
                || jwk
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| usage != &jsonwebtoken::jwk::PublicKeyUse::Signature)
                || jwk
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|operations| {
                        !operations.contains(&jsonwebtoken::jwk::KeyOperations::Verify)
                    })
                || !jwk_type_matches_algorithm(&jwk, self.algorithm)
            {
                continue;
            }
            let key = DecodingKey::from_jwk(&jwk).context("compile JWKS public key")?;
            if keys.insert(kid.to_string(), Arc::new(key)).is_some() {
                bail!("JWKS contains duplicate kid `{kid}`");
            }
        }
        if keys.is_empty() {
            bail!("JWKS contains no key matching the pinned algorithm");
        }
        Ok((keys, advertised_ttl.clamp(self.min_ttl, self.max_ttl)))
    }
}

/// 业务作用：有界下载 JSON identity metadata，先验证 HTTPS/status/media/Content-Length，再流式限制实体。
///
/// 参数说明：
/// - `client`：是无重定向客户端
/// - `url`：是固定 endpoint
/// - `timeout`：是 head+body 总期限。
///
/// 返回：返回严格 JSON 文档与 Cache-Control max-age；任何网络、协议、大小或解析错误返回失败。
async fn fetch_bounded_json<T>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> Result<(T, Duration)>
where
    T: serde::de::DeserializeOwned,
{
    use futures::StreamExt as _;

    validate_https_url(url, "identity metadata URL")?;
    tokio::time::timeout(timeout, async {
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            bail!("identity metadata returned HTTP {}", response.status());
        }
        let media_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or_default().trim())
            .unwrap_or_default();
        if !media_type.eq_ignore_ascii_case("application/json") && !media_type.ends_with("+json") {
            bail!("identity metadata response is not JSON");
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWT_METADATA_BYTES as u64)
        {
            bail!("identity metadata exceeds body limit");
        }
        let ttl =
            parse_cache_control_max_age(response.headers()).unwrap_or(Duration::from_secs(300));
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("read identity metadata body")?;
            if body.len().saturating_add(chunk.len()) > MAX_JWT_METADATA_BYTES {
                bail!("identity metadata exceeds body limit");
            }
            body.extend_from_slice(&chunk);
        }
        let document = serde_json::from_slice(&body).context("decode identity metadata JSON")?;
        Ok((document, ttl))
    })
    .await
    .context("identity metadata total timeout")?
}

/// 业务作用：解析响应的 `Cache-Control: max-age`，其余 directive 不参与 key 生命周期。
///
/// 参数说明：
/// - `headers`：是 JWKS/discovery 响应头。
///
/// 返回：合法秒数返回 Duration；缺失、重复或非法值返回 None 并使用 route 默认值。
fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    let mut max_age = None;
    for directive in value.split(',').map(str::trim) {
        let Some(raw) = directive.strip_prefix("max-age=") else {
            continue;
        };
        if max_age.is_some() {
            return None;
        }
        max_age = Some(Duration::from_secs(raw.trim_matches('"').parse().ok()?));
    }
    max_age
}

/// 业务作用：固定 identity metadata URL 为 HTTPS origin，拒绝凭据、缺 authority 与非根绝对 URI。
///
/// 参数说明：
/// - `url`：是配置或 discovery 返回值
/// - `field`：用于错误定位。
///
/// 返回：安全 HTTPS URL 成功；其它 scheme、userinfo 或非法 URI 返回错误。
fn validate_https_url(url: &str, field: &str) -> Result<()> {
    let uri = url
        .parse::<http::Uri>()
        .with_context(|| format!("{field} is not a valid URI"))?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        bail!("{field} must be an HTTPS URL without userinfo");
    }
    Ok(())
}

/// 业务作用：提取 HTTPS URI authority，供 discovery issuer/JWKS 主机固定比较。
///
/// 参数说明：
/// - `url`：已经过 HTTPS URL 基础验证。
///
/// 返回：返回规范 authority 文本；缺失时返回错误。
fn uri_authority(url: &str) -> Result<String> {
    Ok(url
        .parse::<http::Uri>()?
        .authority()
        .context("identity metadata URI is missing authority")?
        .as_str()
        .to_ascii_lowercase())
}

/// 业务作用：固定 JWK key type 与算法 family，阻止 RSA/EC 算法混淆。
///
/// 参数说明：
/// - `jwk`：是未信任 key
/// - `algorithm`：只允许 RS256 或 ES256。
///
/// 返回：算法对应 RSA 或 P-256 EC 参数时返回 true。
fn jwk_type_matches_algorithm(jwk: &jsonwebtoken::jwk::Jwk, algorithm: Algorithm) -> bool {
    match (algorithm, &jwk.algorithm) {
        (Algorithm::RS256, jsonwebtoken::jwk::AlgorithmParameters::RSA(_)) => true,
        (Algorithm::ES256, jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(parameters)) => {
            parameters.curve == jsonwebtoken::jwk::EllipticCurve::P256
        }
        _ => false,
    }
}

/// nginx `if` 安全子集的固定返回规则。
///
/// 表达式是有界的字符串比较计划，不支持 rewrite 循环、正则脚本、括号或子请求。
#[derive(Clone, PartialEq, Eq)]
pub struct ConditionalReturn {
    /// 构建期已编译的条件表达式。
    condition: ConditionExpr,
    /// 条件命中后的固定响应。
    response: DirectResponse,
}

/// `if` 安全子集支持的比较符。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConditionOp {
    /// 字符串相等。
    Eq,
    /// 字符串不相等。
    NotEq,
    /// 左侧以右侧字符串开头。
    StartsWith,
    /// 左侧以右侧字符串结尾。
    EndsWith,
    /// 左侧包含右侧字符串。
    Contains,
}

/// 一个已编译的原子比较。
#[derive(Clone, PartialEq, Eq)]
struct ConditionComparison {
    left: ValueTemplate,
    op: ConditionOp,
    right: ValueTemplate,
}

/// 析取后的析取范式：外层是 OR，每个分组内是 AND。
#[derive(Clone, PartialEq, Eq)]
struct ConditionExpr {
    any: Vec<Vec<ConditionComparison>>,
}

impl ConditionalReturn {
    /// 业务作用：按 AND 高于 OR 的固定优先级判断请求是否应短路返回。
    ///
    /// 参数说明：
    /// - `ctx`：是当前请求变量上下文
    /// - `variables`：是 route 的变量计划。
    ///
    /// 返回：任一 OR 分组内的全部比较命中时返回 true。
    fn matches(
        &self,
        ctx: &crate::routing::variable::EvalContext<'_>,
        variables: &VariablePlan,
    ) -> bool {
        self.condition.any.iter().any(|all| {
            all.iter().all(|comparison| {
                let left = comparison.left.render(ctx, variables);
                let right = comparison.right.render(ctx, variables);
                match comparison.op {
                    ConditionOp::Eq => left == right,
                    ConditionOp::NotEq => left != right,
                    ConditionOp::StartsWith => left.starts_with(&right),
                    ConditionOp::EndsWith => left.ends_with(&right),
                    ConditionOp::Contains => left.contains(&right),
                }
            })
        })
    }
}

/// IP 访问控制规则。
#[derive(PartialEq, Eq)]
pub struct AccessRule {
    /// 命中后的允许/拒绝动作。
    pub action: AccessAction,
    /// IP 匹配器。保持私有,避免外部绕过构建期 CIDR 校验。
    matcher: AccessMatcher,
}

/// nginx `valid_referers` 的基础策略。
#[derive(PartialEq, Eq)]
pub struct RefererPolicy {
    /// 是否允许缺失 Referer。
    allow_none: bool,
    /// 是否允许被代理/防火墙裁掉 scheme 的 Referer。
    allow_blocked: bool,
    /// 是否允许 Referer host 等于当前请求 Host,对应 nginx `server_names`。
    allow_server_names: bool,
    /// 允许的来源 host 模式。
    hosts: Vec<RefererHost>,
}

/// Referer host 匹配模式。
#[derive(PartialEq, Eq)]
enum RefererHost {
    /// 精确 host。
    Exact(String),
    /// 后缀 host,对应 `*.example.com`。
    Suffix(String),
}

impl RefererPolicy {
    /// 业务作用：判断请求 Referer 是否命中策略。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    fn matches(&self, parts: &Parts) -> bool {
        let Some(raw) = parts
            .headers
            .get(http::header::REFERER)
            .and_then(|value| value.to_str().ok())
        else {
            return self.allow_none;
        };
        if is_blocked_referer(raw) {
            return self.allow_blocked;
        }
        let Some(host) = referer_host(raw) else {
            return false;
        };
        self.hosts.iter().any(|host_rule| host_rule.matches(&host))
            || (self.allow_server_names
                && request_host(parts)
                    .map(|request_host| request_host == host)
                    .unwrap_or(false))
    }
}

impl RefererHost {
    /// 业务作用：判断 host 是否命中当前模式。
    ///
    /// 参数说明：
    /// - `host`: 已规范化的小写 host。
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Suffix(suffix) => host.ends_with(suffix),
        }
    }
}

/// `limit_conn` 并发限制规则。释放绑定响应 body 生命周期,避免流式响应提前归还名额。
#[derive(Clone, PartialEq, Eq)]
pub struct LimitConnPolicy {
    /// 并发维度,与 `limit_req` 共用低成本维度集合。
    pub key: LimitReqKey,
    /// 同一维度允许同时占用的请求/长连接数量。
    pub limit: u64,
}

/// nginx `limit_rate` 响应带宽限制。只包响应 body,不缓冲完整响应。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LimitRatePolicy {
    /// 限速字节/秒。
    pub bytes_per_second: u64,
    /// 前 N 字节不限速,对齐 nginx `limit_rate_after`。
    pub after_bytes: u64,
}

/// nginx `error_page` 形态:状态码集合 -> 固定响应或内部 reroute。
#[derive(Clone, PartialEq, Eq)]
pub struct ErrorPagePolicy {
    /// 触发映射的源状态码集合。
    pub statuses: Vec<StatusCode>,
    /// 命中后的动作。
    pub action: ErrorPageAction,
}

/// error_page 命中后的动作。
#[derive(Clone, PartialEq, Eq)]
pub enum ErrorPageAction {
    /// 固定响应。
    Response(DirectResponse),
    /// 内部重路由目标 path。
    Reroute(String),
}

impl ErrorPagePolicy {
    /// 业务作用：当前 error_page 规则是否执行内部重路由。
    pub fn is_reroute(&self) -> bool {
        matches!(self.action, ErrorPageAction::Reroute(_))
    }
}

/// `limit_req` 支持的低成本维度。`HeaderName` 在构建期校验,运行期零解析。
#[derive(Clone, PartialEq, Eq)]
pub enum LimitReqKey {
    /// 所有请求共享同一桶,用于全局保护后端。
    Global,
    /// 按可信代理链与连接元数据计算出的真实客户端 IP 分桶。
    Ip,
    /// 按当前 route id 分桶。
    Route,
    /// 按指定请求头值分桶;缺失头落入 `<missing>` 桶。
    Header(HeaderName),
    /// 按指定 query 参数值分桶;缺失参数落入 `<missing>` 桶。
    Query(String),
}

/// 访问控制动作。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccessAction {
    /// 允许访问。
    Allow,
    /// 拒绝访问。
    Deny,
}

#[derive(PartialEq, Eq)]
enum AccessMatcher {
    All,
    Cidr(Cidr),
}

impl AccessRule {
    /// 业务作用：按已编译访问规则判定当前地址，运行期不重新解析网段或表达式。
    fn matches(&self, ip: IpAddr) -> bool {
        match &self.matcher {
            AccessMatcher::All => true,
            AccessMatcher::Cidr(cidr) => cidr.contains(ip),
        }
    }
}

enum ParsedFilter {
    None,
    Internal,
    ProxySetHeader(RequestHeaderSet),
    GatewayRequestHeader(RequestHeaderOp),
    PassRequestHeaders(bool),
    PassRequestBody(bool),
    AddHeader(ResponseHeaderSet),
    GatewayResponseHeader(ResponseHeaderOp),
    HideHeader(HeaderName),
    ProxyRedirect(ProxyRedirectRule),
    CookieRewrite(CookieRewriteRule),
    DedupeHeader(DedupeResponseHeader),
    SubFilter(SubFilterRule),
    Compression(Option<CompressionPolicy>),
    RequestDecompression(Option<crate::io::request_decompression::Policy>),
    ProxyCache(Option<Arc<HttpCachePolicy>>),
    ProxyCachePurge(Vec<String>),
    Cors(CorsPolicy),
    FallbackHeaders,
    Access(AccessRule),
    ValidReferers(RefererPolicy),
    LimitExcept(Vec<Method>),
    BasicAuth(Option<BasicAuthPolicy>),
    DigestAuth(Option<crate::security::digest::Policy>),
    ApiKey(ApiKeyPolicy),
    HmacAuth(HmacAuthPolicy),
    JwtAuth(JwtAuthPolicy),
    OidcRp(Box<OidcRpPolicy>),
    EnterpriseAuth(EnterpriseAuthPolicy),
    ExtAuthz(ExtAuthzPolicy),
    Satisfy(SatisfyMode),
    ConditionalReturn(ConditionalReturn),
    LimitReq(LimitReqPolicy),
    LimitConn(LimitConnPolicy),
    LimitRate(LimitRatePolicy),
    CircuitBreaker(CircuitBreakerPolicy),
    ErrorPage(ErrorPagePolicy),
    ProxyInterceptErrors(bool),
    XAccelRedirect(bool),
    Return(DirectResponse),
    RewritePrefix(RewritePrefix),
    GatewayRewriteFullPath(String),
    Mirror(MirrorPolicy),
}

/// 业务作用：把单条原生过滤声明编译为确定操作，未知指令必须在构建期拒绝。
fn parse_filter(spec: &str, variables: &VariablePlan, config_dir: &Path) -> Result<ParsedFilter> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Ok(ParsedFilter::None);
    }
    if trimmed == "internal" {
        return Ok(ParsedFilter::Internal);
    }
    if trimmed.starts_with("proxy_set_header ") {
        let op = parse_request_header_set(trimmed, "proxy_set_header", variables)?;
        return Ok(ParsedFilter::ProxySetHeader(op));
    }
    for (command, mode) in [
        ("gateway_request_header_set_b64", HeaderMutationMode::Set),
        ("gateway_request_header_add_b64", HeaderMutationMode::Add),
    ] {
        if starts_filter(trimmed, command) {
            return parse_gateway_literal_request_header(trimmed, command, mode)
                .map(ParsedFilter::GatewayRequestHeader);
        }
    }
    for (command, mode) in [
        ("gateway_request_header_set", HeaderMutationMode::Set),
        ("gateway_request_header_add", HeaderMutationMode::Add),
        ("gateway_request_header_remove", HeaderMutationMode::Remove),
    ] {
        if trimmed.starts_with(command) {
            return parse_gateway_request_header(trimmed, command, mode, variables)
                .map(ParsedFilter::GatewayRequestHeader);
        }
    }
    if trimmed.starts_with("add_header ") {
        let op = parse_response_header_set(trimmed, "add_header", variables)?;
        return Ok(ParsedFilter::AddHeader(op));
    }
    for (command, mode) in [
        ("gateway_response_header_set_b64", HeaderMutationMode::Set),
        ("gateway_response_header_add_b64", HeaderMutationMode::Add),
    ] {
        if starts_filter(trimmed, command) {
            return parse_gateway_literal_response_header(trimmed, command, mode)
                .map(ParsedFilter::GatewayResponseHeader);
        }
    }
    for (command, mode) in [
        ("gateway_response_header_set", HeaderMutationMode::Set),
        ("gateway_response_header_add", HeaderMutationMode::Add),
        ("gateway_response_header_remove", HeaderMutationMode::Remove),
    ] {
        if trimmed.starts_with(command) {
            return parse_gateway_response_header(trimmed, command, mode, variables)
                .map(ParsedFilter::GatewayResponseHeader);
        }
    }
    if trimmed.starts_with("proxy_hide_header ") {
        let name = trimmed
            .trim_start_matches("proxy_hide_header ")
            .trim()
            .parse::<HeaderName>()
            .with_context(|| format!("invalid proxy_hide_header `{trimmed}`"))?;
        return Ok(ParsedFilter::HideHeader(name));
    }
    if trimmed.starts_with("proxy_redirect ") {
        return parse_proxy_redirect(trimmed).map(|rule| match rule {
            Some(rule) => ParsedFilter::ProxyRedirect(rule),
            None => ParsedFilter::None,
        });
    }
    if trimmed.starts_with("proxy_cookie_domain ") {
        return parse_proxy_cookie_rewrite(trimmed, "proxy_cookie_domain", true)
            .map(ParsedFilter::CookieRewrite);
    }
    if trimmed.starts_with("proxy_cookie_path ") {
        return parse_proxy_cookie_rewrite(trimmed, "proxy_cookie_path", false)
            .map(ParsedFilter::CookieRewrite);
    }
    if trimmed.starts_with("proxy_cookie_flags ") {
        return parse_proxy_cookie_flags(trimmed).map(ParsedFilter::CookieRewrite);
    }
    if starts_filter(trimmed, "DedupeResponseHeader") {
        return parse_dedupe_response_header(trimmed).map(ParsedFilter::DedupeHeader);
    }
    if starts_filter(trimmed, "sub_filter") {
        return parse_sub_filter(trimmed).map(ParsedFilter::SubFilter);
    }
    if starts_filter(trimmed, "compression") {
        return parse_compression(trimmed, "compression", None).map(ParsedFilter::Compression);
    }
    if starts_filter(trimmed, "request_decompression") {
        return crate::io::request_decompression::parse(filter_args(
            trimmed,
            "request_decompression",
        ))
        .map(ParsedFilter::RequestDecompression);
    }
    if starts_filter(trimmed, "gzip") {
        return parse_compression(trimmed, "gzip", Some(ContentCoding::Gzip))
            .map(ParsedFilter::Compression);
    }
    if starts_filter(trimmed, "brotli") {
        return parse_compression(trimmed, "brotli", Some(ContentCoding::Brotli))
            .map(ParsedFilter::Compression);
    }
    if starts_filter(trimmed, "proxy_cache") {
        return parse_proxy_cache(trimmed).map(ParsedFilter::ProxyCache);
    }
    if starts_filter(trimmed, "proxy_cache_purge")
        || starts_filter(trimmed, "proxy_cache_invalidate")
    {
        return parse_proxy_cache_purge(trimmed).map(ParsedFilter::ProxyCachePurge);
    }
    if starts_filter(trimmed, "FallbackHeaders") {
        return parse_fallback_headers(trimmed).map(|()| ParsedFilter::FallbackHeaders);
    }
    if starts_filter(trimmed, "gateway_cors_b64") {
        return parse_gateway_cors(trimmed).map(ParsedFilter::Cors);
    }
    if starts_filter(trimmed, "Cors") || starts_filter(trimmed, "cors") {
        return parse_cors(trimmed).map(ParsedFilter::Cors);
    }
    if trimmed.starts_with("proxy_pass_request_headers ") {
        return parse_on_off_directive(trimmed, "proxy_pass_request_headers")
            .map(ParsedFilter::PassRequestHeaders);
    }
    if trimmed.starts_with("proxy_pass_request_body ") {
        return parse_on_off_directive(trimmed, "proxy_pass_request_body")
            .map(ParsedFilter::PassRequestBody);
    }
    if trimmed.starts_with("allow ") {
        return parse_access_rule(trimmed, "allow", AccessAction::Allow).map(ParsedFilter::Access);
    }
    if trimmed.starts_with("deny ") {
        return parse_access_rule(trimmed, "deny", AccessAction::Deny).map(ParsedFilter::Access);
    }
    if starts_filter(trimmed, "valid_referers") {
        return parse_valid_referers(trimmed).map(ParsedFilter::ValidReferers);
    }
    if starts_filter(trimmed, "limit_except") {
        return parse_limit_except(trimmed).map(ParsedFilter::LimitExcept);
    }
    if starts_filter(trimmed, "auth_basic") {
        return parse_auth_basic(trimmed, config_dir).map(ParsedFilter::BasicAuth);
    }
    if starts_filter(trimmed, "auth_digest") {
        return crate::security::digest::parse(filter_args(trimmed, "auth_digest"), config_dir)
            .map(ParsedFilter::DigestAuth);
    }
    if starts_filter(trimmed, "api_key") {
        return parse_api_key(trimmed, config_dir).map(ParsedFilter::ApiKey);
    }
    if starts_filter(trimmed, "hmac_auth") {
        return parse_hmac_auth(trimmed, "hmac_auth", config_dir).map(ParsedFilter::HmacAuth);
    }
    if starts_filter(trimmed, "hmac_sha256") {
        return parse_hmac_auth(trimmed, "hmac_sha256", config_dir).map(ParsedFilter::HmacAuth);
    }
    if starts_filter(trimmed, "jwt_auth") {
        return parse_jwt_auth(trimmed, "jwt_auth", config_dir).map(ParsedFilter::JwtAuth);
    }
    if starts_filter(trimmed, "jwt_hs256") {
        return parse_jwt_auth(trimmed, "jwt_hs256", config_dir).map(ParsedFilter::JwtAuth);
    }
    if starts_filter(trimmed, "oidc_rp") {
        return parse_oidc_rp(trimmed, config_dir)
            .map(|policy| ParsedFilter::OidcRp(Box::new(policy)));
    }
    if starts_filter(trimmed, "saml_auth") {
        return crate::security::enterprise_identity::parse_saml_auth(trimmed, config_dir)
            .map(ParsedFilter::EnterpriseAuth);
    }
    if starts_filter(trimmed, "ldap_auth") {
        return crate::security::enterprise_identity::parse_ldap_auth(trimmed, config_dir)
            .map(ParsedFilter::EnterpriseAuth);
    }
    if starts_filter(trimmed, "ext_authz") {
        return parse_ext_authz(trimmed, "ext_authz").map(ParsedFilter::ExtAuthz);
    }
    if starts_filter(trimmed, "auth_request") {
        return parse_ext_authz(trimmed, "auth_request").map(ParsedFilter::ExtAuthz);
    }
    if starts_filter(trimmed, "satisfy") {
        return parse_satisfy(trimmed).map(ParsedFilter::Satisfy);
    }
    if starts_filter(trimmed, "if") {
        return parse_if_return(trimmed, variables).map(ParsedFilter::ConditionalReturn);
    }
    if starts_filter(trimmed, "limit_req") {
        return parse_limit_req(trimmed).map(ParsedFilter::LimitReq);
    }
    if starts_filter(trimmed, "limit_conn") {
        return parse_limit_conn(trimmed).map(ParsedFilter::LimitConn);
    }
    if starts_filter(trimmed, "LimitRate") || starts_filter(trimmed, "limit_rate") {
        return parse_limit_rate(trimmed).map(ParsedFilter::LimitRate);
    }
    if starts_filter(trimmed, "circuit_breaker") {
        return parse_circuit_breaker(trimmed).map(ParsedFilter::CircuitBreaker);
    }
    if starts_filter(trimmed, "error_page") {
        return parse_error_page(trimmed).map(ParsedFilter::ErrorPage);
    }
    if trimmed.starts_with("proxy_intercept_errors ") {
        return parse_on_off_directive(trimmed, "proxy_intercept_errors")
            .map(ParsedFilter::ProxyInterceptErrors);
    }
    if trimmed.starts_with("x_accel_redirect ") {
        return parse_on_off_directive(trimmed, "x_accel_redirect")
            .map(ParsedFilter::XAccelRedirect);
    }
    if trimmed.starts_with("proxy_x_accel_redirect ") {
        return parse_on_off_directive(trimmed, "proxy_x_accel_redirect")
            .map(ParsedFilter::XAccelRedirect);
    }
    if trimmed.starts_with("return ") {
        return parse_return(trimmed).map(ParsedFilter::Return);
    }
    if trimmed.starts_with("rewrite ") {
        return parse_rewrite_prefix(trimmed).map(ParsedFilter::RewritePrefix);
    }
    if starts_filter(trimmed, "gateway_rewrite_full_path") {
        return parse_gateway_rewrite_full_path(trimmed).map(ParsedFilter::GatewayRewriteFullPath);
    }
    if starts_filter(trimmed, "mirror") {
        return parse_mirror(trimmed).map(ParsedFilter::Mirror);
    }
    bail!("unsupported filter `{trimmed}`");
}

/// 业务作用：解析 nginx `on|off` 风格开关指令。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
/// - `cmd`: 指令名,用于截取参数和错误上下文。
fn parse_on_off_directive(spec: &str, cmd: &str) -> Result<bool> {
    let raw = spec.trim_start_matches(cmd).trim();
    match raw {
        "on" | "true" => Ok(true),
        "off" | "false" => Ok(false),
        other => bail!("{cmd} expects on/off, got `{other}`"),
    }
}

/// 业务作用：计算路由公开断言的稳定身份，供冲突检测与共享匹配组判断。
fn predicates_signature(predicates: &[Predicate]) -> String {
    let mut parts = predicates
        .iter()
        .map(Predicate::signature)
        .collect::<Vec<_>>();
    parts.sort_unstable();
    parts.join("|")
}

/// 业务作用：编译并交叉校验所有 Weight 路由。
///
/// 同组必须拥有完全相同的非权重断言和 order，才能把“先顺序匹配、再组内分桶”的语义
/// 固定下来；否则配置书写顺序会悄悄改变灰度覆盖范围。组和成员都有硬上限，避免配置把每
/// 请求的灰度选择放大为无界扫描。
fn compile_weighted_groups(
    routes: &[(i32, Arc<Route>)],
) -> Result<HashMap<String, WeightedRouteGroup>> {
    const MAX_WEIGHT_GROUPS: usize = 256;
    const MAX_MEMBERS_PER_GROUP: usize = 32;

    struct BuildingGroup {
        order: i32,
        predicate_signature: String,
        members: Vec<(usize, u32)>,
        total_weight: u64,
    }

    let mut groups: HashMap<String, BuildingGroup> = HashMap::new();
    for (index, (order, route)) in routes.iter().enumerate() {
        let weights = route
            .predicates
            .iter()
            .filter_map(|predicate| match predicate {
                Predicate::Weight {
                    group,
                    weight,
                } => Some((group.as_str(), *weight)),
                _ => None,
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            weights.len() <= 1,
            "route `{}` may declare at most one Weight predicate",
            route.id
        );
        let Some((group, weight)) = weights.first().copied() else {
            continue;
        };
        anyhow::ensure!(
            !route.internal,
            "route `{}` internal routes cannot use Weight",
            route.id
        );
        let signature = non_weight_predicates_signature(route.predicates.as_slice());
        if let Some(compiled) = groups.get_mut(group) {
            anyhow::ensure!(
                compiled.order == *order && compiled.predicate_signature == signature,
                "Weight group `{group}` must use the same order and non-Weight predicates"
            );
            anyhow::ensure!(
                compiled.members.len() < MAX_MEMBERS_PER_GROUP,
                "Weight group `{group}` supports at most {MAX_MEMBERS_PER_GROUP} routes"
            );
            compiled.total_weight = compiled
                .total_weight
                .checked_add(u64::from(weight))
                .context("Weight group total overflow")?;
            compiled.members.push((index, weight));
        } else {
            anyhow::ensure!(
                groups.len() < MAX_WEIGHT_GROUPS,
                "router supports at most {MAX_WEIGHT_GROUPS} Weight groups"
            );
            groups.insert(
                group.to_owned(),
                BuildingGroup {
                    order: *order,
                    predicate_signature: signature,
                    members: vec![(index, weight)],
                    total_weight: u64::from(weight),
                },
            );
        }
    }
    groups
        .into_iter()
        .map(|(name, group)| {
            anyhow::ensure!(
                group.members.len() >= 2,
                "Weight group `{name}` requires at least two routes"
            );
            anyhow::ensure!(
                group.total_weight > 0,
                "Weight group `{name}` total weight must be positive"
            );
            Ok((
                name,
                WeightedRouteGroup {
                    members: group.members,
                    total_weight: group.total_weight,
                },
            ))
        })
        .collect()
}

/// 业务作用：提取并验证路由权重声明，不让同一路由同时具有含糊的权重值。
fn route_weight(route: &Route) -> Option<(&str, u32)> {
    route
        .predicates
        .iter()
        .find_map(|predicate| match predicate {
            Predicate::Weight {
                group,
                weight,
            } => Some((group.as_str(), *weight)),
            _ => None,
        })
}

/// 业务作用：计算去除权重后的匹配域身份，使加权路由只在相同公开条件下分组。
fn non_weight_predicates_signature(predicates: &[Predicate]) -> String {
    let mut parts = predicates
        .iter()
        .filter(|predicate| !matches!(predicate, Predicate::Weight {
            ..
        }))
        .map(Predicate::signature)
        .collect::<Vec<_>>();
    parts.sort_unstable();
    parts.join("|")
}

/// 业务作用：FNV-1a 足以做非安全流量分桶：输入是网关生成的 request-id，不承担认证或签名职责。
/// 分段喂入避免 `group + key` 临时字符串分配；固定分隔字节防连接歧义。
fn stable_weight_hash(group: &[u8], request_key: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in group
        .iter()
        .copied()
        .chain(std::iter::once(0xff))
        .chain(request_key.iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// 业务作用：识别过滤器名称与参数的边界，避免名称前缀误匹配其它指令。
fn starts_filter(spec: &str, name: &str) -> bool {
    spec == name
        || spec
            .strip_prefix(name)
            .map(|rest| {
                rest.starts_with('=')
                    || rest
                        .chars()
                        .next()
                        .map(char::is_whitespace)
                        .unwrap_or(false)
            })
            .unwrap_or(false)
}

#[derive(Clone, Copy)]
enum HeaderMutationMode {
    Set,
    Add,
    Remove,
}

/// 业务作用：解码 Gateway API 生成的请求头字面量，使外部 `${...}` 文本不会获得配置变量能力。
///
/// 参数说明：
/// - `spec`：含 header 名和 URL-safe Base64 值
/// - `command`：是固定内部命令
/// - `mode`：只能为 add 或 set。
///
/// 返回：UTF-8 与 HeaderValue 均合法时返回字面量操作，否则拒绝候选快照。
fn parse_gateway_literal_request_header(
    spec: &str,
    command: &str,
    mode: HeaderMutationMode,
) -> Result<RequestHeaderOp> {
    let set = parse_gateway_literal_header(spec, command)?;
    Ok(match mode {
        HeaderMutationMode::Set => RequestHeaderOp::Set(RequestHeaderSet {
            name: set.name,
            value: set.value,
        }),
        HeaderMutationMode::Add => RequestHeaderOp::Add(RequestHeaderSet {
            name: set.name,
            value: set.value,
        }),
        HeaderMutationMode::Remove => bail!("literal remove does not carry a value"),
    })
}

/// 业务作用：解码 Gateway API 生成的响应头字面量，并保留协议定义的 add/set 差异。
///
/// 参数说明：
/// - `spec`：含 header 名和 URL-safe Base64 值
/// - `command`：是固定内部命令
/// - `mode`：只能为 add 或 set。
///
/// 返回：UTF-8 与 HeaderValue 均合法时返回字面量操作，否则拒绝候选快照。
fn parse_gateway_literal_response_header(
    spec: &str,
    command: &str,
    mode: HeaderMutationMode,
) -> Result<ResponseHeaderOp> {
    let set = parse_gateway_literal_header(spec, command)?;
    let set = ResponseHeaderSet {
        name: set.name,
        value: set.value,
    };
    Ok(match mode {
        HeaderMutationMode::Set => ResponseHeaderOp::Set(set),
        HeaderMutationMode::Add => ResponseHeaderOp::Add(set),
        HeaderMutationMode::Remove => bail!("literal remove does not carry a value"),
    })
}

/// 业务作用：解析内部 Base64 header 载荷并一次完成名称、UTF-8 与 HTTP 值校验。
///
/// 参数说明：
/// - `spec`：是完整命令
/// - `command`：用于安全截取参数和错误上下文。
///
/// 返回：成功时返回可直接复用的 header 名和纯字面量模板。
fn parse_gateway_literal_header(spec: &str, command: &str) -> Result<RequestHeaderSet> {
    let rest = spec
        .strip_prefix(command)
        .context("gateway literal header command mismatch")?
        .trim();
    let (name, encoded) = rest
        .split_once(char::is_whitespace)
        .with_context(|| format!("{command} requires header name and Base64 value"))?;
    anyhow::ensure!(
        !encoded.trim().is_empty() && !encoded.trim().chars().any(char::is_whitespace),
        "{command} requires one Base64 value"
    );
    let name = name
        .parse::<HeaderName>()
        .with_context(|| format!("invalid header name `{name}`"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .with_context(|| format!("{command} value is not URL-safe Base64"))?;
    let value = std::str::from_utf8(&decoded).context("Gateway header value must be UTF-8")?;
    HeaderValue::from_str(value).context("Gateway header value is invalid")?;
    Ok(RequestHeaderSet {
        name,
        value: ValueTemplate::literal(value),
    })
}

/// 业务作用：解析 Gateway API 请求头 add/set/remove，并在构建期固定 header 名与值模板。
///
/// 参数说明：
/// - `spec`：是完整 filter
/// - `command`：是已命中的命令
/// - `mode`：决定变更语义
/// - `variables`：用于编译允许的 Naway value 模板。
///
/// 返回：语法和 HeaderValue 合法时返回统一请求头操作，否则拒绝候选快照。
fn parse_gateway_request_header(
    spec: &str,
    command: &str,
    mode: HeaderMutationMode,
    variables: &VariablePlan,
) -> Result<RequestHeaderOp> {
    let rest = spec
        .strip_prefix(command)
        .context("gateway request header command mismatch")?
        .trim();
    if matches!(mode, HeaderMutationMode::Remove) {
        anyhow::ensure!(
            !rest.is_empty() && !rest.chars().any(char::is_whitespace),
            "{command} requires exactly one header name"
        );
        return rest
            .parse::<HeaderName>()
            .with_context(|| format!("invalid header name `{rest}`"))
            .map(RequestHeaderOp::Remove);
    }
    let set = parse_request_header_set(spec, command, variables)?;
    Ok(match mode {
        HeaderMutationMode::Set => RequestHeaderOp::Set(set),
        HeaderMutationMode::Add => RequestHeaderOp::Add(set),
        HeaderMutationMode::Remove => unreachable!("remove handled above"),
    })
}

/// 业务作用：解析 Gateway API 响应头 add/set/remove，并复用统一响应过滤执行点。
///
/// 参数说明：
/// - `spec`：是完整 filter
/// - `command`：是已命中的命令
/// - `mode`：决定变更语义
/// - `variables`：用于编译允许的 Naway value 模板。
///
/// 返回：语法和 HeaderValue 合法时返回响应头操作，否则拒绝候选快照。
fn parse_gateway_response_header(
    spec: &str,
    command: &str,
    mode: HeaderMutationMode,
    variables: &VariablePlan,
) -> Result<ResponseHeaderOp> {
    let rest = spec
        .strip_prefix(command)
        .context("gateway response header command mismatch")?
        .trim();
    if matches!(mode, HeaderMutationMode::Remove) {
        anyhow::ensure!(
            !rest.is_empty() && !rest.chars().any(char::is_whitespace),
            "{command} requires exactly one header name"
        );
        return rest
            .parse::<HeaderName>()
            .with_context(|| format!("invalid header name `{rest}`"))
            .map(ResponseHeaderOp::Hide);
    }
    let set = parse_response_header_set(spec, command, variables)?;
    Ok(match mode {
        HeaderMutationMode::Set => ResponseHeaderOp::Set(set),
        HeaderMutationMode::Add => ResponseHeaderOp::Add(set),
        HeaderMutationMode::Remove => unreachable!("remove handled above"),
    })
}

/// 业务作用：编译请求头设置规则，名称和值在快照构建期完成合法性检查。
fn parse_request_header_set(
    spec: &str,
    cmd: &str,
    variables: &VariablePlan,
) -> Result<RequestHeaderSet> {
    let rest = spec.trim_start_matches(cmd).trim();
    let (name, value) = rest
        .split_once(char::is_whitespace)
        .with_context(|| format!("{cmd} requires header name and value"))?;
    let name = name
        .trim()
        .parse::<HeaderName>()
        .with_context(|| format!("invalid header name `{name}`"))?;
    let value = variables.compile_template(value.trim())?;
    if let Some(literal) = value.static_literal() {
        http::HeaderValue::from_str(literal)
            .with_context(|| format!("{cmd} invalid header value `{literal}`"))?;
    }
    Ok(RequestHeaderSet {
        name,
        value,
    })
}

/// 业务作用：编译响应头设置规则，保持协议头和静态值的约束。
fn parse_response_header_set(
    spec: &str,
    cmd: &str,
    variables: &VariablePlan,
) -> Result<ResponseHeaderSet> {
    let rest = spec.trim_start_matches(cmd).trim();
    let (name, value) = rest
        .split_once(char::is_whitespace)
        .with_context(|| format!("{cmd} requires header name and value"))?;
    let name = name
        .trim()
        .parse::<HeaderName>()
        .with_context(|| format!("invalid header name `{name}`"))?;
    let value = variables.compile_template_for_phase(value.trim(), VariablePhase::Response)?;
    if let Some(literal) = value.static_literal() {
        http::HeaderValue::from_str(literal)
            .with_context(|| format!("{cmd} invalid header value `{literal}`"))?;
    }
    Ok(ResponseHeaderSet {
        name,
        value,
    })
}

/// 业务作用：解析 nginx `mirror` 基础规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,如 `mirror lb://shadow` 或 `mirror uri=lb://shadow body=off`。
fn parse_mirror(spec: &str) -> Result<MirrorPolicy> {
    let rest = filter_args(spec, "mirror").trim();
    if rest.eq_ignore_ascii_case("off") {
        bail!("mirror off should be removed from generated config");
    }
    let mut target = None;
    let mut sample = 1.0_f64;
    let mut body = false;
    let mut max_body_bytes = DEFAULT_MIRROR_MAX_BODY_BYTES;
    for (idx, token) in rest.split_whitespace().enumerate() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "uri" | "target" => target = Some(value.trim().to_string()),
                "sample" | "sample_rate" => {
                    sample = value
                        .trim()
                        .parse::<f64>()
                        .with_context(|| format!("mirror invalid sample `{value}`"))?;
                    if !(0.0..=1.0).contains(&sample) {
                        bail!("mirror sample must be in 0.0..=1.0");
                    }
                }
                "body" | "mirror_body" => match value {
                    "off" | "false" => body = false,
                    "on" | "true" => body = true,
                    other => bail!("unsupported mirror body option `{other}`"),
                },
                "max_body_bytes" | "body_max_bytes" => {
                    max_body_bytes = parse_byte_size(value)
                        .with_context(|| format!("mirror invalid max_body_bytes `{value}`"))?;
                    if max_body_bytes == 0 || max_body_bytes > MAX_MIRROR_BODY_BYTES {
                        bail!("mirror max_body_bytes must be within 1..={MAX_MIRROR_BODY_BYTES}");
                    }
                }
                other => bail!("unsupported mirror option `{other}`"),
            }
        } else if idx == 0 {
            target = Some(token.trim().to_string());
        } else {
            bail!("unsupported mirror token `{token}`");
        }
    }
    let target = target.context("mirror requires target upstream")?;
    if target.trim().is_empty() {
        bail!("mirror target must not be empty");
    }
    Ok(MirrorPolicy {
        target,
        sample,
        body,
        max_body_bytes,
    })
}

/// 业务作用：解析 nginx `proxy_redirect` 规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,如 `proxy_redirect http://upstream /gw` 或 `proxy_redirect off`。
fn parse_proxy_redirect(spec: &str) -> Result<Option<ProxyRedirectRule>> {
    let rest = spec.trim_start_matches("proxy_redirect ").trim();
    if rest == "off" {
        return Ok(None);
    }
    let (from, to) = rest
        .split_once(char::is_whitespace)
        .with_context(|| "proxy_redirect requires `from to` or `off`")?;
    let from = from.trim();
    let to = to.trim();
    if from.is_empty() || to.is_empty() {
        bail!("proxy_redirect requires non-empty `from` and `to`");
    }
    HeaderValue::from_str(to)
        .with_context(|| format!("proxy_redirect invalid replacement `{to}`"))?;
    Ok(Some(ProxyRedirectRule {
        from: from.to_string(),
        to: to.to_string(),
    }))
}

/// 业务作用：解析 nginx `proxy_cookie_domain` / `proxy_cookie_path` 规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
/// - `cmd`: 指令名,用于截取参数和错误上下文。
/// - `domain`: true 表示解析 Domain 改写,false 表示解析 Path 改写。
fn parse_proxy_cookie_rewrite(spec: &str, cmd: &str, domain: bool) -> Result<CookieRewriteRule> {
    let rest = spec.trim_start_matches(cmd).trim();
    let (from, to) = rest
        .split_once(char::is_whitespace)
        .with_context(|| format!("{cmd} requires `from to`"))?;
    let from = from.trim();
    let to = to.trim();
    validate_cookie_attr_value(cmd, "from", from)?;
    validate_cookie_attr_value(cmd, "to", to)?;
    if domain {
        Ok(CookieRewriteRule::Domain {
            from: from.to_string(),
            to: to.to_string(),
        })
    } else {
        Ok(CookieRewriteRule::Path {
            from: from.to_string(),
            to: to.to_string(),
        })
    }
}

/// 业务作用：校验 cookie 属性改写值。
///
/// 参数说明：
/// - `cmd`: 指令名。
/// - `field`: `from` 或 `to`,用于错误上下文。
/// - `value`: 待校验属性值。
fn validate_cookie_attr_value(cmd: &str, field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.bytes().any(|b| b == b';' || b < 0x20) {
        bail!("{cmd} invalid {field} value `{value}`");
    }
    HeaderValue::from_str(value)
        .with_context(|| format!("{cmd} invalid {field} value `{value}`"))?;
    Ok(())
}

/// 业务作用：解析 nginx `proxy_cookie_flags` 规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
fn parse_proxy_cookie_flags(spec: &str) -> Result<CookieRewriteRule> {
    let rest = spec.trim_start_matches("proxy_cookie_flags ").trim();
    let mut tokens = rest.split_whitespace();
    let cookie = tokens
        .next()
        .context("proxy_cookie_flags requires cookie name and flags")?;
    validate_cookie_flag_cookie(cookie)?;
    let mut rule = CookieFlagsRule {
        cookie: cookie.to_string(),
        add_secure: false,
        remove_secure: false,
        add_http_only: false,
        remove_http_only: false,
        same_site: None,
        remove_same_site: false,
    };
    let mut saw_flag = false;
    for token in tokens {
        saw_flag = true;
        let lower = token.to_ascii_lowercase();
        match lower.as_str() {
            "secure" => rule.add_secure = true,
            "nosecure" => rule.remove_secure = true,
            "httponly" => rule.add_http_only = true,
            "nohttponly" => rule.remove_http_only = true,
            "nosamesite" => rule.remove_same_site = true,
            _ => {
                if let Some(value) = lower.strip_prefix("samesite=") {
                    let value = match value {
                        "lax" => "Lax",
                        "strict" => "Strict",
                        "none" => "None",
                        other => bail!("proxy_cookie_flags unsupported SameSite `{other}`"),
                    };
                    rule.same_site = Some(value.to_string());
                } else {
                    bail!("unsupported proxy_cookie_flags token `{token}`");
                }
            }
        }
    }
    if !saw_flag {
        bail!("proxy_cookie_flags requires at least one flag");
    }
    if rule.add_secure && rule.remove_secure {
        bail!("proxy_cookie_flags cannot set both secure and nosecure");
    }
    if rule.add_http_only && rule.remove_http_only {
        bail!("proxy_cookie_flags cannot set both httponly and nohttponly");
    }
    if rule.same_site.is_some() && rule.remove_same_site {
        bail!("proxy_cookie_flags cannot set both samesite and nosamesite");
    }
    Ok(CookieRewriteRule::Flags(rule))
}

/// 业务作用：校验 `proxy_cookie_flags` 的 cookie 匹配名。
///
/// 参数说明：
/// - `cookie`: cookie 名或 `*`。
fn validate_cookie_flag_cookie(cookie: &str) -> Result<()> {
    if cookie.is_empty()
        || cookie.bytes().any(|b| b <= 0x20 || b == b';' || b == b'=')
        || cookie.starts_with('~')
    {
        bail!("proxy_cookie_flags invalid cookie name `{cookie}`");
    }
    Ok(())
}

/// 业务作用：验证固定终端响应的状态与内容，非法重定向值不能进入数据面。
fn parse_return(spec: &str) -> Result<DirectResponse> {
    let rest = spec.trim_start_matches("return ").trim();
    let (status, value) = rest
        .split_once(char::is_whitespace)
        .map(|(s, v)| (s, Some(v.trim().to_string())))
        .unwrap_or((rest, None));
    let status_u16 = status
        .parse::<u16>()
        .with_context(|| format!("invalid return status `{status}`"))?;
    let status = StatusCode::from_u16(status_u16)
        .with_context(|| format!("invalid return status `{status_u16}`"))?;
    // 重定向的 value 会在运行时作为 Location 响应头，必须在构建期校验为合法 header 值，
    //   否则 direct_response 的 `.expect` 会在该请求上 panic（如非 ASCII 或含控制字符的 Location）。
    if status.is_redirection() {
        if let Some(v) = &value {
            http::HeaderValue::from_str(v).with_context(|| {
                format!("invalid `return {status_u16}` redirect location `{v}`")
            })?;
        }
    }
    Ok(DirectResponse {
        status,
        value,
    })
}

/// 业务作用：编译响应头去重字段及保留策略，不隐式修改其它多值头。
fn parse_dedupe_response_header(spec: &str) -> Result<DedupeResponseHeader> {
    let rest = filter_args(spec, "DedupeResponseHeader");
    if rest.is_empty() {
        bail!(
            "DedupeResponseHeader requires `Header-Name[,RETAIN_FIRST|RETAIN_LAST|RETAIN_UNIQUE]`"
        );
    }
    let (name, mode) = rest
        .split_once(',')
        .map(|(name, mode)| (name.trim(), mode.trim()))
        .unwrap_or((rest, "RETAIN_FIRST"));
    if name.is_empty() {
        bail!("DedupeResponseHeader requires header name");
    }
    Ok(DedupeResponseHeader {
        name: name
            .parse::<HeaderName>()
            .with_context(|| format!("invalid DedupeResponseHeader name `{name}`"))?,
        mode: parse_dedupe_mode(mode)?,
    })
}

/// 业务作用：解析明确的头部去重模式，未知策略在构建期拒绝。
fn parse_dedupe_mode(raw: &str) -> Result<DedupeMode> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "" | "FIRST" | "RETAIN_FIRST" => Ok(DedupeMode::RetainFirst),
        "LAST" | "RETAIN_LAST" => Ok(DedupeMode::RetainLast),
        "UNIQUE" | "RETAIN_UNIQUE" => Ok(DedupeMode::RetainUnique),
        other => bail!(
            "unsupported DedupeResponseHeader mode `{other}` (RETAIN_FIRST|RETAIN_LAST|RETAIN_UNIQUE)"
        ),
    }
}

/// 业务作用：解析 nginx `sub_filter` 基础规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,如 `sub_filter upstream gateway`。
fn parse_sub_filter(spec: &str) -> Result<SubFilterRule> {
    let rest = filter_args(spec, "sub_filter");
    let (needle, replacement) = rest
        .split_once(char::is_whitespace)
        .with_context(|| "sub_filter requires `from to`")?;
    let needle = unquote_token(needle.trim()).as_bytes().to_vec();
    let replacement = unquote_token(replacement.trim()).as_bytes().to_vec();
    if needle.is_empty() {
        bail!("sub_filter from must not be empty");
    }
    if needle.len() > MAX_SUB_FILTER_NEEDLE_BYTES {
        bail!("sub_filter from exceeds {MAX_SUB_FILTER_NEEDLE_BYTES} bytes");
    }
    if replacement.len() > MAX_SUB_FILTER_REPLACEMENT_BYTES {
        bail!("sub_filter to exceeds {MAX_SUB_FILTER_REPLACEMENT_BYTES} bytes");
    }
    Ok(SubFilterRule {
        needle,
        replacement,
    })
}

/// 业务作用：解析 route 级响应压缩配置。
///
/// 支持统一形式
/// `compression algorithms=br,gzip min_length=1k types=text/*,application/json
/// gzip_level=6 brotli_quality=5 chunk_bytes=16k`，并接受 nginx 心智兼容别名
/// `gzip on ...` / `brotli on ...`。同一 route 只能声明一次，避免多个指令的覆盖顺序含糊。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
/// - `command`: 已命中的指令名(`compression`、`gzip` 或 `brotli`)。
/// - `forced_coding`: 别名强制的单一算法；统一形式传 `None`。
fn parse_compression(
    spec: &str,
    command: &str,
    forced_coding: Option<ContentCoding>,
) -> Result<Option<CompressionPolicy>> {
    let rest = filter_args(spec, command);
    let mut enabled = true;
    let mut algorithms = forced_coding
        .map(|coding| vec![coding])
        .unwrap_or_else(|| vec![ContentCoding::Brotli, ContentCoding::Gzip]);
    let mut min_length = DEFAULT_COMPRESSION_MIN_LENGTH;
    let mut content_types = default_compression_content_types();
    let mut gzip_level = 6_i32;
    let mut brotli_quality = 5_i32;
    let mut chunk_bytes = DEFAULT_COMPRESSION_CHUNK_BYTES;

    for (index, token) in rest.split_whitespace().enumerate() {
        if index == 0 && !token.contains('=') {
            enabled = parse_bool(token)
                .with_context(|| format!("{command} first argument must be on/off"))?;
            continue;
        }
        let (key, value) = token
            .split_once('=')
            .with_context(|| format!("unsupported {command} option `{token}`"))?;
        match key {
            "algorithms" => {
                if forced_coding.is_some() {
                    bail!("{command} alias cannot override algorithms; use `compression`");
                }
                algorithms = parse_compression_algorithms(value)?;
            }
            "min_length" | "min_bytes" => min_length = parse_byte_size(value)?,
            "types" | "content_types" => {
                content_types = parse_compression_content_types(value)?;
            }
            "gzip_level" => {
                gzip_level = value
                    .parse::<i32>()
                    .with_context(|| format!("invalid gzip_level `{value}`"))?;
                if !(0..=9).contains(&gzip_level) {
                    bail!("gzip_level must be within 0..=9");
                }
            }
            "brotli_quality" | "br_quality" => {
                brotli_quality = value
                    .parse::<i32>()
                    .with_context(|| format!("invalid brotli_quality `{value}`"))?;
                if !(0..=11).contains(&brotli_quality) {
                    bail!("brotli_quality must be within 0..=11");
                }
            }
            "chunk_bytes" => {
                let parsed = parse_byte_size(value)?;
                if parsed < 1024 || parsed > MAX_COMPRESSION_CHUNK_BYTES as u64 {
                    bail!(
                        "compression chunk_bytes must be within 1KiB..={MAX_COMPRESSION_CHUNK_BYTES}"
                    );
                }
                chunk_bytes = parsed as usize;
            }
            other => bail!("unsupported {command} option `{other}`"),
        }
    }
    if !enabled {
        if rest.split_whitespace().count() > 1 {
            bail!("{command} off cannot be combined with other options");
        }
        return Ok(None);
    }
    Ok(Some(CompressionPolicy {
        algorithms,
        min_length,
        content_types,
        gzip_level,
        brotli_quality,
        chunk_bytes,
    }))
}

/// 业务作用：解析服务端允许的内容编码列表并保留配置顺序。
///
/// 参数说明：
/// - `raw`: 逗号分隔的 `br` / `brotli` / `gzip` 列表。
fn parse_compression_algorithms(raw: &str) -> Result<Vec<ContentCoding>> {
    let mut algorithms = Vec::with_capacity(2);
    for item in raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let coding = match item {
            "br" | "brotli" => ContentCoding::Brotli,
            "gzip" => ContentCoding::Gzip,
            other => bail!("unsupported compression algorithm `{other}`"),
        };
        if !algorithms.contains(&coding) {
            algorithms.push(coding);
        }
    }
    if algorithms.is_empty() {
        bail!("compression algorithms must not be empty");
    }
    Ok(algorithms)
}

/// 业务作用：生成缺省可压缩 MIME 集合。
///
/// 默认排除图片、视频、归档和 `text/event-stream`；这些格式通常已压缩或对首帧延迟敏感。
/// 运维可用 `types=*` 明确覆盖。
fn default_compression_content_types() -> Vec<CompressionContentType> {
    [
        "text/*",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/rss+xml",
        "application/wasm",
        "image/svg+xml",
    ]
    .into_iter()
    .map(|value| {
        parse_compression_content_type(value).expect("built-in compression MIME must be valid")
    })
    .collect()
}

/// 业务作用：解析逗号分隔的 MIME 匹配列表。
///
/// 参数说明：
/// - `raw`: `types=` 的原始值；支持 `*`、`type/*` 和完整 `type/subtype`。
fn parse_compression_content_types(raw: &str) -> Result<Vec<CompressionContentType>> {
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        bail!("compression content types must not be empty");
    }
    if values.len() > MAX_COMPRESSION_CONTENT_TYPES {
        bail!("compression content types exceed {MAX_COMPRESSION_CONTENT_TYPES} entries");
    }
    values
        .into_iter()
        .map(parse_compression_content_type)
        .collect()
}

/// 业务作用：编译单个 MIME 匹配项。
///
/// 参数说明：
/// - `raw`: 已去空白的 `*`、`type/*` 或 `type/subtype`。
fn parse_compression_content_type(raw: &str) -> Result<CompressionContentType> {
    if raw == "*" {
        return Ok(CompressionContentType::Any);
    }
    if raw.len() > 128
        || !raw.is_ascii()
        || raw.bytes().any(|byte| byte.is_ascii_whitespace())
        || !raw.contains('/')
    {
        bail!("invalid compression content type `{raw}`");
    }
    if let Some(prefix) = raw.strip_suffix('*') {
        if !prefix.ends_with('/') || prefix[..prefix.len() - 1].contains('/') {
            bail!("invalid compression content type wildcard `{raw}`");
        }
        return Ok(CompressionContentType::Prefix(prefix.into()));
    }
    if raw.contains('*') {
        bail!("compression content type wildcard must be `type/*`, got `{raw}`");
    }
    Ok(CompressionContentType::Exact(raw.into()))
}

/// 业务作用：解析 公共 HTTP L1/L2 响应缓存策略。
///
/// 参数说明：
/// - `spec`: `proxy_cache public=true ttl_ms=60000 max_body_bytes=1m max_entries=10000
///   statuses=200,301,404 vary=Accept-Language l2=true`；`proxy_cache off` 关闭。
fn parse_proxy_cache(spec: &str) -> Result<Option<Arc<HttpCachePolicy>>> {
    let rest = filter_args(spec, "proxy_cache");
    if rest.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let mut public = false;
    let mut ttl_ms = DEFAULT_HTTP_CACHE_TTL_MS;
    let mut max_body_bytes = DEFAULT_HTTP_CACHE_MAX_BODY_BYTES;
    let mut max_entries = DEFAULT_HTTP_CACHE_MAX_ENTRIES;
    let mut statuses = vec![StatusCode::OK];
    let mut vary_headers = Vec::new();
    let mut l2_enabled = false;
    let mut singleflight_enabled = true;
    let mut singleflight_wait_ms = DEFAULT_HTTP_CACHE_SINGLEFLIGHT_WAIT_MS;
    let mut max_inflight = DEFAULT_HTTP_CACHE_MAX_INFLIGHT;
    let mut stale_while_revalidate_ms = 0u64;
    let mut ttl_jitter_percent = DEFAULT_HTTP_CACHE_TTL_JITTER_PERCENT;
    for token in rest.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .with_context(|| format!("unsupported proxy_cache option `{token}`"))?;
        match key {
            "public" | "public_cache" => public = parse_bool(value)?,
            "ttl_ms" => {
                ttl_ms = value
                    .parse::<u64>()
                    .with_context(|| format!("invalid proxy_cache ttl_ms `{value}`"))?;
                if ttl_ms == 0 || ttl_ms > 7 * 24 * 60 * 60 * 1000 {
                    bail!("proxy_cache ttl_ms must be within 1..=604800000");
                }
            }
            "max_body_bytes" => {
                max_body_bytes = parse_byte_size(value)?;
                if max_body_bytes == 0 || max_body_bytes > MAX_HTTP_CACHE_BODY_BYTES {
                    bail!(
                        "proxy_cache max_body_bytes must be within 1..={MAX_HTTP_CACHE_BODY_BYTES}"
                    );
                }
            }
            "max_entries" => {
                max_entries = value
                    .parse::<u64>()
                    .with_context(|| format!("invalid proxy_cache max_entries `{value}`"))?;
                if max_entries == 0 || max_entries > 1_000_000 {
                    bail!("proxy_cache max_entries must be within 1..=1000000");
                }
            }
            "l2" | "redis" => {
                l2_enabled = match value.to_ascii_lowercase().as_str() {
                    "redis" => true,
                    _ => parse_bool(value)
                        .with_context(|| format!("invalid proxy_cache {key} `{value}`"))?,
                };
            }
            "singleflight" | "collapse" => {
                singleflight_enabled = parse_bool(value)
                    .with_context(|| format!("invalid proxy_cache {key} `{value}`"))?;
            }
            "singleflight_wait_ms" | "collapse_wait_ms" => {
                singleflight_wait_ms = value.parse::<u64>().with_context(|| {
                    format!("invalid proxy_cache singleflight_wait_ms `{value}`")
                })?;
                if !(1..=30_000).contains(&singleflight_wait_ms) {
                    bail!("proxy_cache singleflight_wait_ms must be within 1..=30000");
                }
            }
            "max_inflight" => {
                max_inflight = value
                    .parse::<usize>()
                    .with_context(|| format!("invalid proxy_cache max_inflight `{value}`"))?;
                if max_inflight == 0 || max_inflight > 100_000 {
                    bail!("proxy_cache max_inflight must be within 1..=100000");
                }
            }
            "stale_while_revalidate_ms" | "stale_ms" => {
                stale_while_revalidate_ms = value.parse::<u64>().with_context(|| {
                    format!("invalid proxy_cache stale_while_revalidate_ms `{value}`")
                })?;
                if stale_while_revalidate_ms > 7 * 24 * 60 * 60 * 1000 {
                    bail!("proxy_cache stale_while_revalidate_ms must be within 0..=604800000");
                }
            }
            "ttl_jitter_percent" => {
                ttl_jitter_percent = value
                    .parse::<u8>()
                    .with_context(|| format!("invalid proxy_cache ttl_jitter_percent `{value}`"))?;
                if ttl_jitter_percent > 50 {
                    bail!("proxy_cache ttl_jitter_percent must be within 0..=50");
                }
            }
            "statuses" => {
                statuses = value
                    .split(',')
                    .filter(|item| !item.is_empty())
                    .map(|item| {
                        let code = item
                            .parse::<u16>()
                            .with_context(|| format!("invalid proxy_cache status `{item}`"))?;
                        StatusCode::from_u16(code)
                            .with_context(|| format!("invalid proxy_cache status `{item}`"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                statuses.sort_unstable();
                statuses.dedup();
                if statuses.is_empty() || statuses.len() > 16 {
                    bail!("proxy_cache statuses must contain 1..=16 values");
                }
                if statuses.iter().any(|status| {
                    status.is_informational()
                        || *status == StatusCode::SWITCHING_PROTOCOLS
                        || *status == StatusCode::PARTIAL_CONTENT
                        || *status == StatusCode::NOT_MODIFIED
                }) {
                    bail!(
                        "proxy_cache statuses cannot contain 1xx/101/206/304 until upgrade/range/conditional variants are keyed explicitly"
                    );
                }
            }
            "vary" => {
                vary_headers = value
                    .split(',')
                    .filter(|item| !item.is_empty())
                    .map(|item| {
                        item.parse::<HeaderName>()
                            .with_context(|| format!("invalid proxy_cache vary header `{item}`"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                vary_headers.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
                vary_headers.dedup();
                if vary_headers.len() > 16 {
                    bail!("proxy_cache vary supports at most 16 headers");
                }
                for name in &vary_headers {
                    if name == http::header::ACCEPT_ENCODING
                        || name == http::header::AUTHORIZATION
                        || name == http::header::COOKIE
                    {
                        bail!(
                            "proxy_cache vary `{name}` is forbidden in public cache (Accept-Encoding is handled after the uncompressed cache; auth/cookie requests bypass)"
                        );
                    }
                }
            }
            other => bail!("unsupported proxy_cache option `{other}`"),
        }
    }
    if !public {
        bail!("proxy_cache requires explicit public=true");
    }
    if stale_while_revalidate_ms > 0 && !singleflight_enabled {
        bail!("proxy_cache stale_while_revalidate_ms requires singleflight=true");
    }
    Ok(Some(Arc::new(HttpCachePolicy::new(
        Duration::from_millis(ttl_ms),
        max_body_bytes as usize,
        max_entries,
        statuses,
        vary_headers,
        l2_enabled,
        singleflight_enabled,
        Duration::from_millis(singleflight_wait_ms),
        max_inflight,
        Duration::from_millis(stale_while_revalidate_ms),
        ttl_jitter_percent,
    ))))
}

/// 业务作用：解析写路由的 cache generation 失效目标。
///
/// 形式：`proxy_cache_purge routes=product-list,product-detail`，别名
/// `proxy_cache_invalidate route=product-list`。目标必须位于同一个 proxy 且声明了
/// `proxy_cache`，Router 全部构建后再做前向引用校验。
fn parse_proxy_cache_purge(spec: &str) -> Result<Vec<String>> {
    let command = if starts_filter(spec, "proxy_cache_purge") {
        "proxy_cache_purge"
    } else {
        "proxy_cache_invalidate"
    };
    let rest = filter_args(spec, command);
    let (key, value) = rest
        .split_once('=')
        .with_context(|| format!("{command} requires `routes=id[,id...]`"))?;
    if key.trim() != "route" && key.trim() != "routes" {
        bail!("{command} supports only route=/routes=");
    }
    let mut targets = Vec::new();
    for raw in value.split(',') {
        let target = raw.trim();
        if target.is_empty()
            || target.len() > 256
            || target
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            bail!("{command} target must contain 1..=256 non-whitespace bytes");
        }
        if !targets.iter().any(|existing| existing == target) {
            targets.push(target.to_string());
        }
    }
    if targets.is_empty() || targets.len() > 8 {
        bail!("{command} requires 1..=8 unique route targets");
    }
    Ok(targets)
}

/// 业务作用：冻结降级响应允许附加的上下文头，避免运行期解释动态权限。
fn parse_fallback_headers(spec: &str) -> Result<()> {
    let rest = filter_args(spec, "FallbackHeaders");
    match rest {
        "" | "on" | "true" | "default" => Ok(()),
        other => bail!("unsupported FallbackHeaders policy `{other}` (supported: default/on)"),
    }
}

/// 业务作用：把允许或拒绝声明编译为地址匹配规则，保持顺序裁决语义。
fn parse_access_rule(spec: &str, cmd: &str, action: AccessAction) -> Result<AccessRule> {
    let raw = spec.trim_start_matches(cmd).trim();
    if raw == "all" {
        return Ok(AccessRule {
            action,
            matcher: AccessMatcher::All,
        });
    }
    Ok(AccessRule {
        action,
        matcher: AccessMatcher::Cidr(Cidr::parse(raw)?),
    })
}

/// 业务作用：解析 nginx `valid_referers` 基础规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
fn parse_valid_referers(spec: &str) -> Result<RefererPolicy> {
    let rest = filter_args(spec, "valid_referers").trim();
    if rest.is_empty() {
        bail!("valid_referers requires at least one token");
    }
    let mut allow_none = false;
    let mut allow_blocked = false;
    let mut allow_server_names = false;
    let mut hosts = Vec::new();
    for token in rest.split_whitespace() {
        match token {
            "none" => allow_none = true,
            "blocked" => allow_blocked = true,
            "server_names" => allow_server_names = true,
            raw => hosts.push(parse_referer_host(raw)?),
        }
    }
    if hosts.is_empty() && !allow_none && !allow_blocked && !allow_server_names {
        bail!("valid_referers requires host, `none`, `blocked`, or `server_names`");
    }
    Ok(RefererPolicy {
        allow_none,
        allow_blocked,
        allow_server_names,
        hosts,
    })
}

/// 业务作用：解析 Referer host 模式。
///
/// 参数说明：
/// - `raw`: host 模式,如 `example.com` 或 `*.example.com`。
fn parse_referer_host(raw: &str) -> Result<RefererHost> {
    let host = raw.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('/') {
        bail!("invalid valid_referers host `{raw}`");
    }
    if let Some(rest) = host.strip_prefix("*.") {
        if rest.is_empty() {
            bail!("invalid valid_referers wildcard `{raw}`");
        }
        Ok(RefererHost::Suffix(format!(".{rest}")))
    } else if host.contains('*') || host.contains('?') {
        bail!("valid_referers only supports exact host or leading wildcard `*.example.com`");
    } else {
        Ok(RefererHost::Exact(host))
    }
}

/// 业务作用：从 Referer URL 中提取小写 host。
///
/// 参数说明：
/// - `raw`: Referer header 原始值。
fn referer_host(raw: &str) -> Option<String> {
    let uri = raw.parse::<http::Uri>().ok()?;
    let host = uri.host()?;
    normalize_host(host)
}

/// 业务作用：判断 Referer 是否属于 nginx `blocked` 语义。
///
/// 参数说明：
/// - `raw`: Referer header 原始值。
fn is_blocked_referer(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    !lower.starts_with("http://") && !lower.starts_with("https://")
}

/// 业务作用：提取当前请求 Host,用于 `valid_referers server_names`。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
fn request_host(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_host)
}

/// 业务作用：规范化 host:去端口、去尾点、小写。
///
/// 参数说明：
/// - `raw`: Host 或 URI host 原始文本。
fn normalize_host(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_end_matches('.');
    if raw.is_empty() {
        return None;
    }
    let host = if let Some(rest) = raw.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else {
        raw.split_once(':').map(|(host, _)| host).unwrap_or(raw)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// 业务作用：解析 nginx `limit_except` 基础规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
fn parse_limit_except(spec: &str) -> Result<Vec<Method>> {
    let rest = filter_args(spec, "limit_except").trim();
    if rest.is_empty() {
        bail!("limit_except requires at least one method");
    }
    let mut methods = Vec::new();
    for token in rest.split(|ch: char| ch == ',' || ch.is_whitespace()) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        methods.push(
            token
                .parse::<Method>()
                .with_context(|| format!("limit_except invalid method `{token}`"))?,
        );
    }
    if methods.is_empty() {
        bail!("limit_except requires at least one method");
    }
    Ok(methods)
}

/// 业务作用：解析 `auth_basic` 基础认证规则，冻结用户名、凭据与对外 challenge realm。
///
/// 参数说明：
/// - `spec`：是 route filter 原始字符串，例如 `auth_basic user=admin password=secret realm=ops`
/// - `config_dir`：用于解析 SecretSource 相对路径。
///
/// 返回：规则关闭时返回 None；配置合法时返回认证策略；缺少凭据、未知选项或非法 realm 时拒绝候选。
fn parse_auth_basic(spec: &str, config_dir: &Path) -> Result<Option<BasicAuthPolicy>> {
    let rest = filter_args(spec, "auth_basic").trim();
    if rest.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if rest.is_empty() {
        bail!("auth_basic requires `user=<name> password=<secret> [realm=<realm>]`");
    }
    let mut user = None;
    let mut password = None;
    let mut realm = "naway".to_string();
    let mut positional = Vec::new();
    for token in rest.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            let value = unquote_token(value.trim()).to_string();
            match key {
                "user" | "username" => user = Some(value),
                "password" | "pass" => password = Some(value),
                "realm" => realm = value,
                other => bail!("auth_basic unsupported option `{other}`"),
            }
        } else {
            positional.push(unquote_token(token).to_string());
        }
    }
    if user.is_none() && !positional.is_empty() {
        user = Some(positional.remove(0));
    }
    if password.is_none() && !positional.is_empty() {
        password = Some(positional.remove(0));
    }
    if !positional.is_empty() {
        bail!("auth_basic unexpected positional token `{}`", positional[0]);
    }
    let user = user.context("auth_basic requires user")?;
    let password = password.context("auth_basic requires password")?;
    let password =
        crate::security::secret::resolve_text(&password, config_dir, "auth_basic password")?;
    validate_basic_auth_user(&user)?;
    validate_basic_auth_secret("password", &password)?;
    validate_basic_auth_secret("realm", &realm)?;
    let challenge = format!("Basic realm=\"{}\"", escape_header_quote(&realm));
    HeaderValue::from_str(&challenge)
        .with_context(|| format!("auth_basic invalid challenge `{challenge}`"))?;
    Ok(Some(BasicAuthPolicy {
        expected: format!("{user}:{password}").into_bytes(),
        realm,
        consumer: Arc::from(user),
    }))
}

/// 业务作用：把 route 的 `api_key` 声明编译为固定来源和校验材料，拒绝混合明文/摘要或不完整规则。
///
/// 参数说明：
/// - `spec`：是 route filter 原始字符串
/// - `config_dir`：限定 SecretSource 相对路径。
///
/// 返回：合法声明返回可共享策略；来源、consumer、SecretSource 或 SHA-256 非法时拒绝整个候选。
fn parse_api_key(spec: &str, config_dir: &Path) -> Result<ApiKeyPolicy> {
    let rest = filter_args(spec, "api_key").trim();
    if rest.is_empty() {
        bail!("api_key requires `header=<name>|query=<name> value=<secret>|sha256=<digest>`");
    }
    let mut source = None;
    let mut value = None;
    let mut sha256 = None;
    let mut consumer = None;
    for token in rest.split_whitespace() {
        let (key, raw_value) = token
            .split_once('=')
            .with_context(|| format!("api_key option `{token}` must be key=value"))?;
        let raw_value = unquote_token(raw_value.trim());
        match key {
            "header" => {
                let name = raw_value
                    .parse::<HeaderName>()
                    .with_context(|| format!("api_key invalid header `{raw_value}`"))?;
                source = Some(ApiKeySource::Header(name));
            }
            "query" => {
                validate_query_key_name(raw_value)?;
                source = Some(ApiKeySource::Query(raw_value.to_string()));
            }
            "value" | "key" | "secret" => value = Some(raw_value.to_string()),
            "sha256" => sha256 = Some(raw_value.to_string()),
            "consumer" => consumer = Some(raw_value.to_string()),
            other => bail!("api_key unsupported option `{other}`"),
        }
    }
    let source = source.context("api_key requires header or query source")?;
    anyhow::ensure!(
        value.is_some() ^ sha256.is_some(),
        "api_key requires exactly one of value or sha256"
    );
    let expected = if let Some(value) = value {
        let value = crate::security::secret::resolve_text(&value, config_dir, "api_key value")?;
        validate_basic_auth_secret("api_key value", &value)?;
        ApiKeyExpected::Plain(value.into_bytes())
    } else {
        ApiKeyExpected::Sha256(parse_api_key_sha256(
            sha256.as_deref().expect("exclusive option checked"),
        )?)
    };
    if let Some(consumer) = &consumer {
        validate_basic_auth_user(consumer)?;
    }
    let digest: [u8; 32] = match &expected {
        ApiKeyExpected::Plain(value) => Sha256::digest(value).into(),
        ApiKeyExpected::Sha256(digest) => *digest,
    };
    let mut fingerprint = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in &digest[..16] {
        write!(&mut fingerprint, "{byte:02x}").expect("SHA-256 hex formatting");
    }
    Ok(ApiKeyPolicy {
        fingerprint: Arc::from(fingerprint),
        source,
        expected,
        consumer: consumer.map(Arc::from),
    })
}

/// 业务作用：解析管理面生成 API-Key 的固定长度 SHA-256，避免宽松 hex 语义产生不同配置解释。
///
/// 参数说明：
/// - `value`：必须是 64 个 ASCII 十六进制字符。
///
/// 返回：严格解码为 32 字节；长度或任一字符非法时拒绝候选。
fn parse_api_key_sha256(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        value.len() == 64,
        "api_key sha256 must contain 64 hex characters"
    );
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).expect("hex pair is an ASCII slice");
        digest[index] = u8::from_str_radix(pair, 16)
            .with_context(|| format!("api_key sha256 contains invalid hex at byte {index}"))?;
    }
    Ok(digest)
}

/// 业务作用：解析 HMAC-SHA256 签名规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,如 `hmac_auth secret=s signature_header=X-Signature`。
/// - `cmd`: 实际命中的指令名。
/// - `config_dir`：共享密钥 SecretSource 相对路径解析根。
fn parse_hmac_auth(spec: &str, cmd: &str, config_dir: &Path) -> Result<HmacAuthPolicy> {
    let rest = filter_args(spec, cmd).trim();
    if rest.is_empty() {
        bail!(
            "{cmd} requires `secret=<secret> [signature_header=X-Signature] [timestamp_header=X-Timestamp]`"
        );
    }
    let mut secret = None;
    let mut signature_header = parse_hmac_header_name("X-Signature", "signature_header")?;
    let mut timestamp_header = parse_hmac_header_name("X-Timestamp", "timestamp_header")?;
    let mut nonce_header = None;
    let mut signed_headers = Vec::new();
    let mut max_skew_ms = DEFAULT_HMAC_SKEW_MS;
    let mut replay_protection = false;
    let mut include_body = false;
    let mut body_max_bytes = None;
    for token in rest.split_whitespace() {
        let (key, raw_value) = token
            .split_once('=')
            .with_context(|| format!("{cmd} option `{token}` must be key=value"))?;
        let raw_value = unquote_token(raw_value.trim());
        match key {
            "secret" | "key" => secret = Some(raw_value.to_string()),
            "signature_header" | "sig_header" | "signature" => {
                signature_header = parse_hmac_header_name(raw_value, "signature_header")?;
            }
            "timestamp_header" | "ts_header" | "timestamp" => {
                timestamp_header = parse_hmac_header_name(raw_value, "timestamp_header")?;
            }
            "nonce_header" | "nonce" => {
                if raw_value.eq_ignore_ascii_case("off") {
                    nonce_header = None;
                } else {
                    nonce_header = Some(parse_hmac_header_name(raw_value, "nonce_header")?);
                }
            }
            "signed_headers" | "headers" => {
                signed_headers = parse_hmac_signed_headers(raw_value)?;
            }
            "skew_ms" | "max_skew_ms" => {
                max_skew_ms = raw_value
                    .parse::<u64>()
                    .with_context(|| format!("{cmd} invalid skew_ms `{raw_value}`"))?;
                if max_skew_ms > MAX_HMAC_SKEW_MS {
                    bail!("{cmd} skew_ms must be <= {MAX_HMAC_SKEW_MS}");
                }
            }
            "algorithm" | "alg" => {
                if !matches!(
                    raw_value.to_ascii_lowercase().as_str(),
                    "sha256" | "hmac-sha256"
                ) {
                    bail!("{cmd} only supports HMAC-SHA256");
                }
            }
            "body" | "include_body" => {
                include_body = parse_bool(raw_value)?;
            }
            "max_body_bytes" | "body_max_bytes" => {
                let value = parse_byte_size(raw_value)
                    .with_context(|| format!("{cmd} invalid max_body_bytes `{raw_value}`"))?;
                if value == 0 || value > 16 * 1024 * 1024 {
                    bail!("{cmd} max_body_bytes must be within 1..=16777216");
                }
                body_max_bytes = Some(value);
            }
            "replay" | "replay_protection" | "anti_replay" => {
                replay_protection = parse_bool(raw_value)?;
            }
            other => bail!("{cmd} unsupported option `{other}`"),
        }
    }
    let secret = secret.with_context(|| format!("{cmd} requires secret"))?;
    let secret = crate::security::secret::resolve_text(&secret, config_dir, "hmac secret")?;
    validate_basic_auth_secret("hmac secret", &secret)?;
    // 防重放依赖 nonce 去重:开启但没配 nonce_header 无从去重,构建期拒绝,防上线后静默失效。
    if replay_protection && nonce_header.is_none() {
        bail!("{cmd} replay=on requires nonce_header to dedup one-time nonces");
    }
    if include_body != body_max_bytes.is_some() {
        bail!("{cmd} body=on requires max_body_bytes and body=off forbids it");
    }
    Ok(HmacAuthPolicy {
        secret,
        signature_header,
        timestamp_header,
        nonce_header,
        signed_headers,
        max_skew_ms,
        replay_protection,
        body_max_bytes,
    })
}

/// 业务作用：解析 HMAC 使用的请求头名。
///
/// 参数说明：
/// - `raw`: 配置中的 header 名。
/// - `field`: 字段名,用于错误上下文。
fn parse_hmac_header_name(raw: &str, field: &str) -> Result<HeaderName> {
    raw.parse::<HeaderName>()
        .with_context(|| format!("hmac_auth invalid {field} `{raw}`"))
}

/// 业务作用：解析参与 HMAC 签名的额外请求头列表。
///
/// 参数说明：
/// - `raw`: 逗号分隔的 header 名列表。
fn parse_hmac_signed_headers(raw: &str) -> Result<Vec<HeaderName>> {
    let mut headers = Vec::new();
    for item in raw.split(',') {
        let name = item.trim();
        if name.is_empty() {
            continue;
        }
        headers.push(parse_hmac_header_name(name, "signed_headers")?);
    }
    Ok(headers)
}

/// 业务作用：把浏览器 OAuth2/OIDC Authorization Code 配置编译为固定 endpoint、PKCE 和有界会话策略。
///
/// 参数说明：
/// - `spec`：是 route filter 原文
/// - `config_dir`：是 client secret 与 CA 的 SecretSource 相对目录。
///
/// 返回：所有信任锚点、重定向和资源上限合法时返回 RP 策略；弱 URL、跨 IdP authority、开放重定向
/// 或无界容量在快照构建阶段返回错误。
pub(crate) fn parse_oidc_rp(spec: &str, config_dir: &Path) -> Result<OidcRpPolicy> {
    let cmd = "oidc_rp";
    let rest = filter_args(spec, cmd).trim();
    if rest.is_empty() {
        bail!("oidc_rp requires issuer, discovery_url, authorization_endpoint, token_endpoint, client_id, client_secret, and redirect_uri");
    }
    let mut issuer = None;
    let mut discovery_url = None;
    let mut authorization_endpoint = None;
    let mut token_endpoint = None;
    let mut userinfo_endpoint = None;
    let mut introspection_endpoint = None;
    let mut client_id = None;
    let mut client_secret = None;
    let mut client_auth = OidcClientAuth::SecretBasic;
    let mut redirect_uri = None;
    let mut callback_path = None;
    let mut logout_path = "/_oidc/logout".to_string();
    let mut post_logout_uri = "/".to_string();
    let mut cookie_name = "naway_oidc".to_string();
    let mut scope = "openid profile email".to_string();
    let mut ca_certificate = None;
    let mut algorithm = Algorithm::RS256;
    let mut identity_headers = Vec::new();
    let mut timeout_ms = DEFAULT_JWKS_TIMEOUT_MS;
    let mut session_ttl_secs = 3_600_u64;
    let mut pending_ttl_secs = 300_u64;
    let mut max_pending = DEFAULT_OIDC_MAX_PENDING;
    let mut max_sessions = DEFAULT_OIDC_MAX_SESSIONS;
    for token in rest.split_whitespace() {
        let (key, raw_value) = token
            .split_once('=')
            .with_context(|| format!("oidc_rp option `{token}` must be key=value"))?;
        let raw_value = unquote_token(raw_value.trim());
        match key {
            "issuer" => issuer = Some(raw_value.to_string()),
            "discovery_url" | "oidc_discovery" => discovery_url = Some(raw_value.to_string()),
            "authorization_endpoint" | "authorize_url" => {
                authorization_endpoint = Some(raw_value.to_string())
            }
            "token_endpoint" | "token_url" => token_endpoint = Some(raw_value.to_string()),
            "userinfo_endpoint" | "userinfo_url" => userinfo_endpoint = Some(raw_value.to_string()),
            "introspection_endpoint" | "introspection_url" => {
                introspection_endpoint = Some(raw_value.to_string())
            }
            "client_id" => client_id = Some(raw_value.to_string()),
            "client_secret" => client_secret = Some(raw_value.to_string()),
            "client_auth" => {
                client_auth = match raw_value.to_ascii_lowercase().as_str() {
                    "secret_basic" | "client_secret_basic" | "basic" => OidcClientAuth::SecretBasic,
                    "secret_post" | "client_secret_post" | "post" => OidcClientAuth::SecretPost,
                    _ => bail!(
                        "oidc_rp client_auth must be client_secret_basic or client_secret_post"
                    ),
                }
            }
            "redirect_uri" => redirect_uri = Some(raw_value.to_string()),
            "callback_path" => callback_path = Some(raw_value.to_string()),
            "logout_path" => logout_path = raw_value.to_string(),
            "post_logout_uri" => post_logout_uri = raw_value.to_string(),
            "cookie_name" => cookie_name = raw_value.to_string(),
            "scope" | "scopes" => scope = raw_value.replace(',', " "),
            "ca_certificate" | "ca_pem" | "ca_file" => ca_certificate = Some(raw_value.to_string()),
            "algorithm" | "alg" => {
                algorithm = parse_jwt_algorithm(raw_value, cmd)?;
                if !matches!(algorithm, Algorithm::RS256 | Algorithm::ES256) {
                    bail!("oidc_rp algorithm must be RS256 or ES256");
                }
            }
            "identity_headers" | "claim_headers" => {
                identity_headers = parse_jwt_identity_headers(raw_value, cmd)?
            }
            "timeout_ms" => {
                timeout_ms = raw_value
                    .parse::<u64>()
                    .with_context(|| format!("oidc_rp invalid timeout_ms `{raw_value}`"))?;
            }
            "session_ttl_secs" => {
                session_ttl_secs = raw_value
                    .parse::<u64>()
                    .with_context(|| format!("oidc_rp invalid session_ttl_secs `{raw_value}`"))?;
            }
            "pending_ttl_secs" => {
                pending_ttl_secs = raw_value
                    .parse::<u64>()
                    .with_context(|| format!("oidc_rp invalid pending_ttl_secs `{raw_value}`"))?;
            }
            "max_pending" => {
                max_pending = raw_value
                    .parse::<usize>()
                    .with_context(|| format!("oidc_rp invalid max_pending `{raw_value}`"))?;
            }
            "max_sessions" => {
                max_sessions = raw_value
                    .parse::<usize>()
                    .with_context(|| format!("oidc_rp invalid max_sessions `{raw_value}`"))?;
            }
            other => bail!("oidc_rp unsupported option `{other}`"),
        }
    }
    let issuer = issuer.context("oidc_rp requires issuer")?;
    let discovery_url = discovery_url.context("oidc_rp requires discovery_url")?;
    let authorization_endpoint =
        authorization_endpoint.context("oidc_rp requires authorization_endpoint")?;
    let token_endpoint = token_endpoint.context("oidc_rp requires token_endpoint")?;
    let client_id = client_id.context("oidc_rp requires client_id")?;
    let client_secret_source = client_secret.context("oidc_rp requires client_secret")?;
    let redirect_uri = redirect_uri.context("oidc_rp requires redirect_uri")?;
    if client_id.is_empty()
        || client_id.len() > 512
        || client_id.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("oidc_rp client_id must be non-empty, bounded, and free of control characters");
    }
    validate_oidc_idp_endpoint(&issuer, &issuer, "issuer")?;
    for (field, endpoint) in [
        ("discovery_url", Some(&discovery_url)),
        ("authorization_endpoint", Some(&authorization_endpoint)),
        ("token_endpoint", Some(&token_endpoint)),
        ("userinfo_endpoint", userinfo_endpoint.as_ref()),
        ("introspection_endpoint", introspection_endpoint.as_ref()),
    ] {
        if let Some(endpoint) = endpoint {
            validate_oidc_idp_endpoint(endpoint, &issuer, field)?;
        }
    }
    validate_https_url(&redirect_uri, "oidc_rp redirect_uri")?;
    let redirect = redirect_uri.parse::<http::Uri>()?;
    if redirect.query().is_some() {
        bail!("oidc_rp redirect_uri must not contain a query");
    }
    let callback_path = callback_path.unwrap_or_else(|| redirect.path().to_string());
    if !valid_oidc_local_path(&callback_path) || callback_path != redirect.path() {
        bail!("oidc_rp callback_path must equal the local path in redirect_uri");
    }
    if !valid_oidc_local_path(&logout_path) || !valid_oidc_local_path(&post_logout_uri) {
        bail!("oidc_rp logout_path and post_logout_uri must be bounded local origin-form URIs");
    }
    if callback_path == logout_path {
        bail!("oidc_rp callback_path and logout_path must be different");
    }
    if cookie_name.is_empty()
        || cookie_name.len() > 128
        || !cookie_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        bail!("oidc_rp cookie_name is invalid");
    }
    let scopes = scope.split_whitespace().collect::<HashSet<_>>();
    if !scopes.contains("openid") || scopes.len() > 32 || scope.len() > 1_024 {
        bail!("oidc_rp scope must be bounded and include openid");
    }
    if !(1..=MAX_JWKS_TIMEOUT_MS).contains(&timeout_ms) {
        bail!("oidc_rp timeout_ms must be in 1..={MAX_JWKS_TIMEOUT_MS}");
    }
    if !(60..=86_400).contains(&session_ttl_secs) {
        bail!("oidc_rp session_ttl_secs must be in 60..=86400");
    }
    if !(30..=900).contains(&pending_ttl_secs) {
        bail!("oidc_rp pending_ttl_secs must be in 30..=900");
    }
    if !(1..=10_000).contains(&max_pending) || !(1..=1_000_000).contains(&max_sessions) {
        bail!("oidc_rp max_pending or max_sessions is outside its bounded range");
    }
    let client_secret = crate::security::secret::resolve_text(
        &client_secret_source,
        config_dir,
        "OIDC client secret",
    )?;
    validate_basic_auth_secret("OIDC client secret", &client_secret)?;
    let mut verifier_spec = format!(
        "jwt_auth alg={} oidc_discovery={} issuer={} audience={} timeout_ms={}",
        match algorithm {
            Algorithm::RS256 => "RS256",
            Algorithm::ES256 => "ES256",
            _ => unreachable!("OIDC algorithm was constrained above"),
        },
        discovery_url,
        issuer,
        client_id,
        timeout_ms
    );
    if let Some(source) = &ca_certificate {
        verifier_spec.push_str(" ca_certificate=");
        verifier_spec.push_str(source);
    }
    let id_token_verifier = parse_jwt_auth(&verifier_spec, "jwt_auth", config_dir)?;
    let mut client_builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true);
    let mut ca_identity = None;
    if let Some(source) = ca_certificate {
        let pem = crate::security::secret::resolve_text(&source, config_dir, "OIDC IdP CA")?;
        ca_identity = Some(Sha256::digest(pem.as_bytes()).into());
        let certificate =
            crate::tls::trust::http_ca(pem.as_bytes()).context("parse OIDC IdP CA PEM")?;
        client_builder = client_builder.add_root_certificate(certificate);
    }
    Ok(OidcRpPolicy {
        authorization_endpoint: Arc::from(authorization_endpoint),
        token_endpoint: Arc::from(token_endpoint),
        userinfo_endpoint: userinfo_endpoint.map(Arc::from),
        introspection_endpoint: introspection_endpoint.map(Arc::from),
        issuer: Arc::from(issuer),
        client_id: Arc::from(client_id),
        client_secret: Arc::from(client_secret),
        client_auth,
        scope: Arc::from(scope),
        redirect_uri: Arc::from(redirect_uri),
        callback_path: Arc::from(callback_path),
        logout_path: Arc::from(logout_path),
        post_logout_uri: Arc::from(post_logout_uri),
        cookie_name: Arc::from(cookie_name),
        session_ttl: Duration::from_secs(session_ttl_secs),
        pending_ttl: Duration::from_secs(pending_ttl_secs),
        max_pending,
        max_sessions,
        timeout: Duration::from_millis(timeout_ms),
        client: client_builder.build().context("build OIDC RP client")?,
        ca_identity,
        id_token_verifier,
        identity_headers: Arc::new(identity_headers),
        pending: parking_lot::Mutex::new(HashMap::new()),
        sessions: parking_lot::Mutex::new(HashMap::new()),
    })
}

/// 业务作用：把所有 IdP 网络端点固定到配置 issuer 的 HTTPS authority，阻止重定向或 endpoint SSRF。
///
/// 参数说明：
/// - `endpoint`：是待验证地址
/// - `issuer`：是信任锚点
/// - `field`：用于错误定位。
///
/// 返回：HTTPS 且 authority 与 issuer 相同返回成功；其它地址返回错误。
fn validate_oidc_idp_endpoint(endpoint: &str, issuer: &str, field: &str) -> Result<()> {
    validate_https_url(endpoint, &format!("oidc_rp {field}"))?;
    if endpoint.parse::<http::Uri>()?.query().is_some() {
        bail!("oidc_rp {field} must not contain a query");
    }
    if uri_authority(endpoint)? != uri_authority(issuer)? {
        bail!("oidc_rp {field} must use the issuer authority");
    }
    Ok(())
}

/// 业务作用：限制 OIDC 回调、退出和登录后返回值为本地 origin-form URI，杜绝开放重定向。
///
/// 参数说明：
/// - `value`：是配置或已保存的本地 URI。
///
/// 返回：以单斜杠开头、无控制字符且长度不超过 8192 字节时返回 true。
fn valid_oidc_local_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 8_192
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value.parse::<http::Uri>().is_ok()
}

/// 业务作用：把 JWT/JWKS/OIDC route DSL 编译为算法与 endpoint 均固定的认证策略。
///
/// 参数说明：
/// - `spec`：是 route filter 原文
/// - `cmd`：是实际指令名
/// - `config_dir`：是 SecretSource 相对目录。
///
/// 返回：返回可直接用于数据面的验证器；算法/key 来源冲突、弱 URL、无界参数或非法身份映射会拒绝快照。
fn parse_jwt_auth(spec: &str, cmd: &str, config_dir: &Path) -> Result<JwtAuthPolicy> {
    let rest = filter_args(spec, cmd).trim();
    if rest.is_empty() {
        bail!("{cmd} requires `secret=<hs256-secret>`");
    }
    let mut secret = None;
    let mut generic_key = None;
    let mut public_key = None;
    let mut jwks_url = None;
    let mut discovery_url = None;
    let mut ca_certificate = None;
    let mut jwe_private_key = None;
    let mut jwe_max_compact_bytes = None;
    let mut jwe_options_configured = false;
    let mut algorithm = Algorithm::HS256;
    let mut source = JwtTokenSource::Bearer;
    let mut issuer = None;
    let mut audience = None;
    let mut authorized_party = None;
    let mut nonce = None;
    let mut leeway_secs = DEFAULT_JWT_LEEWAY_SECS;
    let mut max_token_bytes = DEFAULT_JWT_TOKEN_BYTES;
    let mut timeout_ms = DEFAULT_JWKS_TIMEOUT_MS;
    let mut min_ttl_secs = 30_u64;
    let mut max_ttl_secs = 3_600_u64;
    let mut stale_ttl_secs = 300_u64;
    let mut negative_ttl_secs = 30_u64;
    let mut identity_headers = Vec::new();
    for token in rest.split_whitespace() {
        let (key, raw_value) = token
            .split_once('=')
            .with_context(|| format!("{cmd} option `{token}` must be key=value"))?;
        let raw_value = unquote_token(raw_value.trim());
        match key {
            "secret" | "hs256_secret" => secret = Some(raw_value.to_string()),
            "key" => generic_key = Some(raw_value.to_string()),
            "public_key" | "public_key_pem" => public_key = Some(raw_value.to_string()),
            "jwks_url" | "jwks_uri" => jwks_url = Some(raw_value.to_string()),
            "oidc_discovery" | "discovery_url" => discovery_url = Some(raw_value.to_string()),
            "ca_certificate" | "ca_pem" | "ca_file" => ca_certificate = Some(raw_value.to_string()),
            "jwe_private_key" | "jwe_key" => {
                jwe_private_key = Some(raw_value.to_string());
                jwe_options_configured = true;
            }
            "jwe_alg" => {
                jwe_options_configured = true;
                if raw_value != "RSA-OAEP-256" {
                    bail!("{cmd} jwe_alg must be RSA-OAEP-256");
                }
            }
            "jwe_enc" => {
                jwe_options_configured = true;
                if raw_value != "A256GCM" {
                    bail!("{cmd} jwe_enc must be A256GCM");
                }
            }
            "jwe_max_compact_bytes" => {
                jwe_options_configured = true;
                let parsed = raw_value.parse::<usize>().with_context(|| {
                    format!("{cmd} invalid jwe_max_compact_bytes `{raw_value}`")
                })?;
                if !(1_024..=256 * 1024).contains(&parsed) {
                    bail!("{cmd} jwe_max_compact_bytes must be in 1024..=262144");
                }
                jwe_max_compact_bytes = Some(parsed);
            }
            "header" | "token_header" => {
                if raw_value.eq_ignore_ascii_case("authorization")
                    || raw_value.eq_ignore_ascii_case("bearer")
                {
                    source = JwtTokenSource::Bearer;
                } else {
                    source =
                        JwtTokenSource::Header(raw_value.parse::<HeaderName>().with_context(
                            || format!("{cmd} invalid token header `{raw_value}`"),
                        )?);
                }
            }
            "issuer" | "iss" => issuer = Some(raw_value.to_string()),
            "audience" | "aud" => audience = Some(raw_value.to_string()),
            "authorized_party" | "azp" => authorized_party = Some(raw_value.to_string()),
            "nonce" => nonce = Some(raw_value.to_string()),
            "leeway_secs" | "clock_skew_secs" => {
                leeway_secs = raw_value
                    .parse::<i64>()
                    .with_context(|| format!("{cmd} invalid leeway_secs `{raw_value}`"))?;
                if !(0..=MAX_JWT_LEEWAY_SECS).contains(&leeway_secs) {
                    bail!("{cmd} leeway_secs must be in 0..={MAX_JWT_LEEWAY_SECS}");
                }
            }
            "max_token_bytes" => {
                max_token_bytes = raw_value
                    .parse::<usize>()
                    .with_context(|| format!("{cmd} invalid max_token_bytes `{raw_value}`"))?;
                if !(256..=MAX_JWT_TOKEN_BYTES).contains(&max_token_bytes) {
                    bail!("{cmd} max_token_bytes must be in 256..={MAX_JWT_TOKEN_BYTES}");
                }
            }
            "timeout_ms" => {
                timeout_ms = raw_value
                    .parse::<u64>()
                    .with_context(|| format!("{cmd} invalid timeout_ms `{raw_value}`"))?;
                if !(1..=MAX_JWKS_TIMEOUT_MS).contains(&timeout_ms) {
                    bail!("{cmd} timeout_ms must be in 1..={MAX_JWKS_TIMEOUT_MS}");
                }
            }
            "jwks_min_ttl_secs" | "min_ttl_secs" => {
                min_ttl_secs = parse_jwt_ttl(raw_value, cmd, key, 86_400)?
            }
            "jwks_max_ttl_secs" | "max_ttl_secs" => {
                max_ttl_secs = parse_jwt_ttl(raw_value, cmd, key, 86_400)?
            }
            "stale_ttl_secs" | "stale_secs" => {
                stale_ttl_secs = parse_jwt_ttl(raw_value, cmd, key, 86_400)?
            }
            "negative_ttl_secs" => negative_ttl_secs = parse_jwt_ttl(raw_value, cmd, key, 3_600)?,
            "identity_headers" | "claim_headers" => {
                identity_headers = parse_jwt_identity_headers(raw_value, cmd)?
            }
            "algorithm" | "alg" => algorithm = parse_jwt_algorithm(raw_value, cmd)?,
            other => bail!("{cmd} unsupported option `{other}`"),
        }
    }
    for (field, value) in [
        ("issuer", issuer.as_deref()),
        ("audience", audience.as_deref()),
        ("authorized_party", authorized_party.as_deref()),
    ] {
        if value.is_some_and(str::is_empty) {
            bail!("{cmd} {field} must not be empty");
        }
    }
    if min_ttl_secs > max_ttl_secs {
        bail!("{cmd} jwks_min_ttl_secs must not exceed jwks_max_ttl_secs");
    }
    if let JwtTokenSource::Header(token_header) = &source {
        if identity_headers
            .iter()
            .any(|mapping: &JwtIdentityHeader| mapping.header == *token_header)
        {
            bail!("{cmd} token header cannot also be an identity output header");
        }
    }

    if let Some(value) = generic_key {
        if algorithm == Algorithm::HS256 {
            secret.get_or_insert(value);
        } else {
            public_key.get_or_insert(value);
        }
    }
    let remote_count = usize::from(jwks_url.is_some()) + usize::from(discovery_url.is_some());
    let require_oidc_claims = discovery_url.is_some();
    let verifier = match algorithm {
        Algorithm::HS256 => {
            if public_key.is_some()
                || remote_count != 0
                || ca_certificate.is_some()
                || require_oidc_claims
            {
                bail!("{cmd} HS256 accepts only secret/key and cannot use PEM/JWKS/OIDC options");
            }
            let secret = secret.with_context(|| format!("{cmd} HS256 requires secret"))?;
            let secret = crate::security::secret::resolve_text(&secret, config_dir, "jwt secret")?;
            validate_basic_auth_secret("jwt secret", &secret)?;
            JwtVerifier::Hs256(Arc::from(secret))
        }
        Algorithm::RS256 | Algorithm::ES256 => {
            if secret.is_some() {
                bail!("{cmd} asymmetric algorithms do not accept secret/hs256_secret");
            }
            if usize::from(public_key.is_some()) + remote_count != 1 {
                bail!("{cmd} requires exactly one of public_key, jwks_url, or oidc_discovery");
            }
            if let Some(public_key) = public_key {
                if ca_certificate.is_some() {
                    bail!("{cmd} ca_certificate is only valid with JWKS/OIDC");
                }
                let pem = crate::security::secret::resolve_text(
                    &public_key,
                    config_dir,
                    "jwt public key",
                )?;
                let key = if algorithm == Algorithm::RS256 {
                    DecodingKey::from_rsa_pem(pem.as_bytes())
                } else {
                    DecodingKey::from_ec_pem(pem.as_bytes())
                }
                .with_context(|| format!("{cmd} invalid public key PEM"))?;
                JwtVerifier::Static(Arc::new(key), Sha256::digest(pem.as_bytes()).into())
            } else {
                let issuer_value = issuer
                    .as_deref()
                    .context("remote JWKS/OIDC requires issuer pinning")?;
                if require_oidc_claims && audience.is_none() {
                    bail!("{cmd} OIDC discovery requires audience");
                }
                if require_oidc_claims {
                    validate_https_url(issuer_value, "OIDC issuer")?;
                }
                let endpoint = if let Some(url) = discovery_url {
                    validate_https_url(&url, "OIDC discovery URL")?;
                    if uri_authority(&url)? != uri_authority(issuer_value)? {
                        bail!("{cmd} OIDC discovery URL must use the pinned issuer authority");
                    }
                    RemoteJwksEndpoint::Discovery(Arc::from(url))
                } else {
                    let url = jwks_url.expect("remote_count guarantees a JWKS URL");
                    validate_https_url(&url, "JWKS URL")?;
                    RemoteJwksEndpoint::Direct(Arc::from(url))
                };
                let mut client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .https_only(true);
                let mut ca_identity = None;
                if let Some(source) = ca_certificate {
                    let pem = crate::security::secret::resolve_text(
                        &source,
                        config_dir,
                        "JWT identity metadata CA",
                    )?;
                    let certificate = crate::tls::trust::http_ca(pem.as_bytes())
                        .context("parse JWT identity metadata CA PEM")?;
                    ca_identity = Some(Sha256::digest(pem.as_bytes()).into());
                    client = client.add_root_certificate(certificate);
                }
                let now = Instant::now();
                JwtVerifier::Remote(Arc::new(RemoteJwks {
                    endpoint,
                    issuer: Arc::from(issuer_value),
                    algorithm,
                    ca_identity,
                    client: client
                        .build()
                        .context("build JWT identity metadata client")?,
                    timeout: Duration::from_millis(timeout_ms),
                    min_ttl: Duration::from_secs(min_ttl_secs),
                    max_ttl: Duration::from_secs(max_ttl_secs),
                    stale_ttl: Duration::from_secs(stale_ttl_secs),
                    negative_ttl: Duration::from_secs(negative_ttl_secs),
                    state: RwLock::new(RemoteJwksState {
                        keys: HashMap::new(),
                        expires_at: now,
                        stale_until: now,
                        negative: HashMap::new(),
                        next_retry: now,
                    }),
                    refresh: AsyncMutex::new(()),
                }))
            }
        }
        _ => unreachable!("parse_jwt_algorithm only permits three algorithms"),
    };
    let nonce = nonce
        .map(|value| crate::security::secret::resolve_text(&value, config_dir, "OIDC nonce"))
        .transpose()?;
    if nonce.as_ref().is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_JWT_IDENTITY_BYTES
            || value.bytes().any(|byte| byte.is_ascii_control())
    }) {
        bail!("{cmd} nonce must be non-empty, bounded, and free of control characters");
    }
    #[cfg(feature = "enterprise-jwe")]
    let jwe = jwe_private_key
        .map(|source| -> Result<Arc<JweLayer>> {
            let pem =
                crate::security::secret::resolve_text(&source, config_dir, "JWE private key")?;
            let decrypter = josekit::jwe::RSA_OAEP_256
                .decrypter_from_pem(pem.as_bytes())
                .context("compile JWE RSA-OAEP-256 private key")?;
            Ok(Arc::new(JweLayer {
                decrypter,
                key_identity: Sha256::digest(pem.as_bytes()).into(),
                max_compact_bytes: jwe_max_compact_bytes.unwrap_or(MAX_JWT_TOKEN_BYTES),
            }))
        })
        .transpose()?;
    #[cfg(feature = "enterprise-jwe")]
    if jwe_options_configured && jwe.is_none() {
        bail!("{cmd} JWE options require jwe_private_key");
    }
    #[cfg(not(feature = "enterprise-jwe"))]
    if jwe_options_configured {
        let _ = (jwe_private_key, jwe_max_compact_bytes);
        bail!("{cmd} JWE options require the enterprise-jwe feature");
    }
    Ok(JwtAuthPolicy {
        verifier,
        algorithm,
        source,
        issuer,
        audience,
        authorized_party,
        nonce,
        leeway_secs,
        max_token_bytes,
        require_oidc_claims,
        identity_headers: Arc::new(identity_headers),
        #[cfg(feature = "enterprise-jwe")]
        jwe,
    })
}

/// 业务作用：把配置中的 JWS 算法限制到经过实现和 key-type 约束的集合。
///
/// 参数说明：
/// - `raw`：是算法文本
/// - `cmd`：用于错误定位。
///
/// 返回：返回 HS256、RS256 或 ES256；其它算法在构建期拒绝。
fn parse_jwt_algorithm(raw: &str, cmd: &str) -> Result<Algorithm> {
    match raw.to_ascii_uppercase().as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "RS256" => Ok(Algorithm::RS256),
        "ES256" => Ok(Algorithm::ES256),
        _ => bail!("{cmd} algorithm must be one of HS256, RS256, ES256"),
    }
}

/// 业务作用：解析 JWKS 生命周期秒数并施加非零硬上限，防止配置形成永久 key 或刷新风暴。
///
/// 参数说明：
/// - `raw`：是秒数字符串
/// - `cmd`：用于错误定位
/// - `field`：用于错误定位
/// - `maximum`：是字段硬上限。
///
/// 返回：范围内秒数；零、超限或非数字返回错误。
fn parse_jwt_ttl(raw: &str, cmd: &str, field: &str, maximum: u64) -> Result<u64> {
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("{cmd} invalid {field} `{raw}`"))?;
    if !(1..=maximum).contains(&value) {
        bail!("{cmd} {field} must be in 1..={maximum}");
    }
    Ok(value)
}

/// 业务作用：编译受信 JWT claim 到上游身份 header 的显式 allowlist，并拒绝凭据/传输控制头。
///
/// 参数说明：
/// - `raw`：是逗号分隔的 `claim:Header-Name`
/// - `cmd`：用于错误定位。
///
/// 返回：返回去重后的映射；非法 claim、重复 header 或安全敏感 header 返回错误。
fn parse_jwt_identity_headers(raw: &str, cmd: &str) -> Result<Vec<JwtIdentityHeader>> {
    let mut mappings = Vec::new();
    let mut headers = HashSet::new();
    for item in raw.split(',') {
        let (claim, header) = item.split_once(':').with_context(|| {
            format!("{cmd} identity_headers item `{item}` must be claim:Header")
        })?;
        if claim.is_empty()
            || claim.len() > 64
            || !claim
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            bail!("{cmd} invalid identity claim `{claim}`");
        }
        let header = header
            .parse::<HeaderName>()
            .with_context(|| format!("{cmd} invalid identity header `{header}`"))?;
        if is_forbidden_identity_header(&header) {
            bail!("{cmd} cannot generate security/framing header `{header}` from a JWT claim");
        }
        if !headers.insert(header.clone()) {
            bail!("{cmd} duplicate identity header `{header}`");
        }
        mappings.push(JwtIdentityHeader {
            claim: Arc::from(claim),
            header,
        });
    }
    if mappings.is_empty() || mappings.len() > 16 {
        bail!("{cmd} identity_headers must contain 1..=16 mappings");
    }
    Ok(mappings)
}

/// 业务作用：识别不能由身份 claim 覆盖的凭据、路由与 HTTP framing header。
///
/// 参数说明：
/// - `name`：是已经完成语法校验的 header 名。
///
/// 返回：安全敏感 header 返回 true，普通业务身份 header 返回 false。
pub(crate) fn is_forbidden_identity_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "content-length"
    )
}

/// 业务作用：解析 ext_authz / nginx auth_request 基础规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,如 `ext_authz uri=lb://auth path=/check`。
/// - `cmd`: 实际命中的指令名。
fn parse_ext_authz(spec: &str, cmd: &str) -> Result<ExtAuthzPolicy> {
    let rest = filter_args(spec, cmd).trim();
    if rest.is_empty() {
        bail!("{cmd} requires `uri=<http(s)://...|lb://service> [path=/check]`");
    }
    let mut target = None;
    let mut path = None;
    let mut method = Method::GET;
    let mut timeout_ms = DEFAULT_EXT_AUTHZ_TIMEOUT_MS;
    let mut fail_open = false;
    let mut include_body = false;
    let mut body_max_bytes = None;
    let mut cache_ttl_ms = 0_u64;
    let mut cache_max_entries = 0_usize;
    let mut circuit_failure_threshold = 0_u32;
    let mut circuit_open_ms = 0_u64;
    // WHY:默认只给 auth 服务最常用的 Bearer 凭据,避免把 Cookie/PII/header 全量裸转发给外部服务。
    let mut request_headers = vec![http::header::AUTHORIZATION];
    let mut upstream_headers = Vec::new();
    for (idx, token) in rest.split_whitespace().enumerate() {
        if let Some((key, raw_value)) = token.split_once('=') {
            let raw_value = unquote_token(raw_value.trim());
            match key {
                "uri" | "target" | "url" => target = Some(raw_value.to_string()),
                "path" => path = Some(parse_ext_authz_path(raw_value)?),
                "method" => method = parse_ext_authz_method(raw_value)?,
                "timeout_ms" => {
                    timeout_ms = raw_value
                        .parse::<u64>()
                        .with_context(|| format!("{cmd} invalid timeout_ms `{raw_value}`"))?;
                    if timeout_ms > MAX_EXT_AUTHZ_TIMEOUT_MS {
                        bail!("{cmd} timeout_ms must be <= {MAX_EXT_AUTHZ_TIMEOUT_MS}");
                    }
                }
                "fail_open" | "failure_mode_allow" => fail_open = parse_bool(raw_value)?,
                "body" | "include_body" | "send_body" => include_body = parse_bool(raw_value)?,
                "max_body_bytes" | "body_max_bytes" => {
                    let value = parse_byte_size(raw_value)
                        .with_context(|| format!("{cmd} invalid max_body_bytes `{raw_value}`"))?;
                    if value == 0 || value > 16 * 1024 * 1024 {
                        bail!("{cmd} max_body_bytes must be within 1..=16777216");
                    }
                    body_max_bytes = Some(value);
                }
                "cache_ttl_ms" => {
                    cache_ttl_ms = raw_value
                        .parse::<u64>()
                        .with_context(|| format!("{cmd} invalid cache_ttl_ms `{raw_value}`"))?;
                }
                "cache_max_entries" => {
                    cache_max_entries = raw_value.parse::<usize>().with_context(|| {
                        format!("{cmd} invalid cache_max_entries `{raw_value}`")
                    })?;
                }
                "circuit_failure_threshold" | "circuit_failures" => {
                    circuit_failure_threshold = raw_value.parse::<u32>().with_context(|| {
                        format!("{cmd} invalid circuit_failure_threshold `{raw_value}`")
                    })?;
                }
                "circuit_open_ms" => {
                    circuit_open_ms = raw_value
                        .parse::<u64>()
                        .with_context(|| format!("{cmd} invalid circuit_open_ms `{raw_value}`"))?;
                }
                "headers" | "request_headers" | "allow_headers" => {
                    request_headers = parse_ext_authz_header_list(raw_value, "request_headers")?;
                }
                "upstream_headers" | "response_headers" | "copy_headers" => {
                    upstream_headers = parse_ext_authz_header_list(raw_value, "upstream_headers")?;
                }
                other => bail!("{cmd} unsupported option `{other}`"),
            }
        } else if idx == 0 {
            target = Some(unquote_token(token).to_string());
        } else {
            bail!("{cmd} unexpected positional token `{token}`");
        }
    }
    let target = target.with_context(|| format!("{cmd} requires uri/target"))?;
    validate_ext_authz_target(&target, path.as_deref(), cmd)?;
    if include_body != body_max_bytes.is_some() {
        bail!("{cmd} body=on requires max_body_bytes and body=off forbids it");
    }
    if include_body && method != Method::POST {
        bail!("{cmd} body=on requires method=POST");
    }
    if (cache_ttl_ms == 0) != (cache_max_entries == 0)
        || cache_ttl_ms > 60_000
        || cache_max_entries > 100_000
    {
        bail!("{cmd} cache requires cache_ttl_ms=1..60000 and cache_max_entries=1..100000");
    }
    if (circuit_failure_threshold == 0) != (circuit_open_ms == 0)
        || circuit_failure_threshold > 100
        || (circuit_open_ms != 0 && !(10..=300_000).contains(&circuit_open_ms))
    {
        bail!("{cmd} circuit requires threshold=1..100 and circuit_open_ms=10..300000");
    }
    Ok(ExtAuthzPolicy {
        target,
        path,
        method,
        timeout_ms,
        fail_open,
        body_max_bytes,
        cache_ttl: (cache_ttl_ms != 0).then(|| Duration::from_millis(cache_ttl_ms)),
        cache_max_entries,
        circuit_failure_threshold,
        circuit_open: Duration::from_millis(circuit_open_ms),
        request_headers,
        upstream_headers,
    })
}

/// 业务作用：校验 ext_authz 目标 URI。
///
/// 参数说明：
/// - `target`: 配置中的 `uri` / `target`。
/// - `path`: 可选外置 path。
/// - `cmd`: 指令名,用于错误上下文。
fn validate_ext_authz_target(target: &str, path: Option<&str>, cmd: &str) -> Result<()> {
    if let Some(service) = target.strip_prefix("lb://") {
        if service.trim().is_empty() || service.contains('/') {
            bail!("{cmd} lb:// target must be `lb://service`; put path in `path=`");
        }
        return Ok(());
    }
    let uri = target
        .parse::<http::Uri>()
        .with_context(|| format!("{cmd} invalid target uri `{target}`"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    if scheme != "http" && scheme != "https" {
        bail!("{cmd} target only supports http/https/lb");
    }
    if uri.authority().is_none() {
        bail!("{cmd} target uri requires authority");
    }
    if path.is_none() {
        let path_and_query = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        parse_ext_authz_path(path_and_query)?;
    }
    Ok(())
}

/// 业务作用：解析 ext_authz 子请求方法。
///
/// 参数说明：
/// - `raw`: 配置中的 method。
fn parse_ext_authz_method(raw: &str) -> Result<Method> {
    let method = raw
        .parse::<Method>()
        .with_context(|| format!("ext_authz invalid method `{raw}`"))?;
    if method != Method::GET && method != Method::HEAD && method != Method::POST {
        bail!("ext_authz method only supports GET/HEAD/POST with empty body");
    }
    Ok(method)
}

/// 业务作用：解析 ext_authz path,允许携带 query。
///
/// 参数说明：
/// - `raw`: path 或 path?query。
fn parse_ext_authz_path(raw: &str) -> Result<String> {
    if raw.is_empty() || !raw.starts_with('/') || raw.bytes().any(|b| b <= 0x20) {
        bail!("ext_authz path must start with `/` and contain no spaces/control chars");
    }
    raw.parse::<http::Uri>()
        .with_context(|| format!("ext_authz invalid path `{raw}`"))?;
    Ok(raw.to_string())
}

/// 业务作用：解析 ext_authz header allowlist。
///
/// 参数说明：
/// - `raw`: 逗号分隔 header 名列表。
/// - `field`: 字段名,用于错误上下文。
fn parse_ext_authz_header_list(raw: &str, field: &str) -> Result<Vec<HeaderName>> {
    let mut headers = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let name = item
            .parse::<HeaderName>()
            .with_context(|| format!("ext_authz invalid {field} header `{item}`"))?;
        if !ext_authz_header_is_safe(&name) {
            bail!("ext_authz {field} cannot include hop-by-hop/body header `{item}`");
        }
        if !headers.contains(&name) {
            headers.push(name);
        }
    }
    Ok(headers)
}

/// 业务作用：判断 header 是否允许进入 ext_authz allowlist。
///
/// 参数说明：
/// - `name`: 已解析 header 名。
fn ext_authz_header_is_safe(name: &HeaderName) -> bool {
    let name = name.as_str();
    !name.starts_with("x-forwarded-")
        && !name.starts_with("x-original-")
        && !matches!(
            name,
            "host"
                | "connection"
                | "content-length"
                | "transfer-encoding"
                | "expect"
                | "te"
                | "upgrade"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "x-real-ip"
                | "x-request-id"
                | "x-gateway-route-id"
        )
}

/// 业务作用：取请求头的 UTF-8 文本值。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
/// - `name`: 请求头名。
fn header_str<'a>(parts: &'a Parts, name: &HeaderName) -> Option<&'a str> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// 业务作用：从 `Authorization: Bearer` 中提取 token。
///
/// 参数说明：
/// - `parts`: 下游请求 head。
fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let mut tokens = value.trim().splitn(2, char::is_whitespace);
    let scheme = tokens.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    tokens
        .next()
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// 业务作用：解码 JWT base64url JSON 段。
///
/// 参数说明：
/// - `encoded`: JWT header 或 payload 的 base64url 段。
fn decode_jwt_json(encoded: &str) -> Option<serde_json::Value> {
    let bytes = nasa::crypto::base64_url_decode(encoded).ok()?;
    serde_json::from_slice(bytes.as_slice()).ok()
}

/// 业务作用：把字节串转为小写 hex。
///
/// 参数说明：
/// - `bytes`: 输入字节串。
fn hex_lower_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 业务作用：取当前 Unix 秒。
fn unix_now_secs() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
}

/// 业务作用：从 JSON number 读取 i64。
///
/// 参数说明：
/// - `value`: JSON claim 值。
fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
}

/// 业务作用：判断 JWT audience 是否匹配期望值。
///
/// 参数说明：
/// - `claim`: payload 中的 `aud` claim。
/// - `expected`: 配置中的 audience。
fn jwt_audience_matches(claim: Option<&serde_json::Value>, expected: &str) -> bool {
    match claim {
        Some(serde_json::Value::String(value)) => value == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

/// 业务作用：计算 JWT `aud` 的有效字符串成员数，供 OIDC `azp` 歧义门判断。
///
/// 参数说明：
/// - `claim`：是 payload 中尚未信任的 `aud` 值。
///
/// 返回：字符串返回一，纯字符串数组返回成员数；缺失或类型不合法返回零。
fn jwt_audience_count(claim: Option<&serde_json::Value>) -> usize {
    match claim {
        Some(serde_json::Value::String(_)) => 1,
        Some(serde_json::Value::Array(values))
            if values.iter().all(serde_json::Value::is_string) =>
        {
            values.len()
        }
        _ => 0,
    }
}

/// 业务作用：判断 HMAC 时间戳是否处于允许偏差内。
///
/// 参数说明：
/// - `raw`: 请求头里的 Unix 秒或毫秒时间戳。
/// - `max_skew_ms`: 最大允许偏差,单位毫秒。
fn timestamp_within_skew(raw: &str, max_skew_ms: u64) -> bool {
    let Some(timestamp_ms) = parse_hmac_timestamp_ms(raw) else {
        return false;
    };
    if timestamp_ms <= 0 {
        return false;
    }
    let Some(now_ms) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as i128)
    else {
        return false;
    };
    let delta = if now_ms >= timestamp_ms {
        now_ms - timestamp_ms
    } else {
        timestamp_ms - now_ms
    };
    delta <= i128::from(max_skew_ms)
}

/// 业务作用：解析 HMAC 时间戳为 Unix 毫秒。
///
/// 参数说明：
/// - `raw`: Unix 秒或毫秒时间戳文本。
fn parse_hmac_timestamp_ms(raw: &str) -> Option<i128> {
    let value = raw.trim().parse::<i128>().ok()?;
    if value >= HMAC_UNIX_SECONDS_THRESHOLD {
        Some(value)
    } else {
        value.checked_mul(1000)
    }
}

/// 业务作用：解析 nginx `satisfy any|all` 的数据面鉴权子集。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串。
fn parse_satisfy(spec: &str) -> Result<SatisfyMode> {
    match filter_args(spec, "satisfy").trim() {
        "all" => Ok(SatisfyMode::All),
        "any" => Ok(SatisfyMode::Any),
        other => bail!("satisfy expects any|all, got `{other}`"),
    }
}

/// 业务作用：校验 Basic 用户名。
///
/// 参数说明：
/// - `user`: 配置中的用户名。
fn validate_basic_auth_user(user: &str) -> Result<()> {
    if user.is_empty() || user.bytes().any(|b| b == b':' || b < 0x20) {
        bail!("auth_basic invalid user");
    }
    Ok(())
}

/// 业务作用：校验 Basic 密码或 realm。
///
/// 参数说明：
/// - `field`: 字段名,用于错误上下文。
/// - `value`: 待校验文本。
fn validate_basic_auth_secret(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.bytes().any(|b| b < 0x20) {
        bail!("auth_basic invalid {field}");
    }
    Ok(())
}

/// 业务作用：校验 API-Key query 参数名。
///
/// 参数说明：
/// - `name`: query 参数名。
fn validate_query_key_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        bail!("api_key invalid query name `{name}`");
    }
    if name.bytes().any(|b| b == b'&' || b == b'=' || b < 0x20) {
        bail!("api_key invalid query name `{name}`");
    }
    Ok(())
}

/// 业务作用：把 nginx `if` 安全子集编译成有界、无脚本能力的短路返回计划。
///
/// 参数说明：
/// - `spec`：是 route filter 原始字符串
/// - `variables`：用于构建期编译比较两侧模板。
///
/// 返回：语法、操作符、复杂度和响应均合法时返回固定执行计划，否则拒绝候选快照。
fn parse_if_return(spec: &str, variables: &VariablePlan) -> Result<ConditionalReturn> {
    let rest = filter_args(spec, "if");
    let tokens = rest.split_whitespace().collect::<Vec<_>>();
    if tokens.len() < 5 {
        bail!("if requires `<expression> return <status> [body]`");
    }
    anyhow::ensure!(tokens.len() <= 68, "if expression exceeds token limit");
    let return_index = tokens
        .iter()
        .position(|token| *token == "return")
        .context("if only supports a final `return` action")?;
    anyhow::ensure!(return_index > 0, "if expression is empty");
    anyhow::ensure!(return_index + 1 < tokens.len(), "if return requires status");

    let expression_tokens = &tokens[..return_index];
    let mut any = vec![Vec::new()];
    let mut cursor = 0;
    let mut comparisons = 0usize;
    while cursor < expression_tokens.len() {
        anyhow::ensure!(
            cursor + 2 < expression_tokens.len(),
            "if comparison requires `<left> <operator> <right>`"
        );
        let left = variables.compile_template(unquote_token(expression_tokens[cursor]))?;
        let op = match expression_tokens[cursor + 1] {
            "=" | "==" => ConditionOp::Eq,
            "!=" => ConditionOp::NotEq,
            "^=" => ConditionOp::StartsWith,
            "$=" => ConditionOp::EndsWith,
            "*=" => ConditionOp::Contains,
            other => bail!("if unsupported operator `{other}`"),
        };
        let right = variables.compile_template(unquote_token(expression_tokens[cursor + 2]))?;
        any.last_mut()
            .expect("condition expression always has one group")
            .push(ConditionComparison {
                left,
                op,
                right,
            });
        comparisons += 1;
        anyhow::ensure!(comparisons <= 16, "if expression exceeds comparison limit");
        cursor += 3;
        if cursor == expression_tokens.len() {
            break;
        }
        match expression_tokens[cursor] {
            "&&" => {}
            "||" => any.push(Vec::new()),
            other => bail!("if expected `&&` or `||`, got `{other}`"),
        }
        cursor += 1;
        anyhow::ensure!(
            cursor < expression_tokens.len(),
            "if expression ends with connector"
        );
    }

    let status = parse_status_code(tokens[return_index + 1], "if return status")?;
    let value = if tokens.len() > return_index + 2 {
        Some(unquote_token(&tokens[return_index + 2..].join(" ")).to_string())
    } else {
        None
    };
    if status.is_redirection() {
        if let Some(location) = &value {
            HeaderValue::from_str(location)
                .with_context(|| format!("if return invalid redirect location `{location}`"))?;
        }
    }
    Ok(ConditionalReturn {
        condition: ConditionExpr {
            any,
        },
        response: DirectResponse {
            status,
            value,
        },
    })
}

/// 业务作用：去掉单个 token 外层的成对引号,方便表达空串或含特殊字符的静态值。
///
/// 参数说明：
/// - `value`: 通过空白分词取得的原始 token。
fn unquote_token(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// 业务作用：从原始 query 中读取未解码参数值。
///
/// 参数说明：
/// - `query`: URI 中 `?` 后的原始 query。
/// - `name`: 待读取的参数名。
fn query_param_raw<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            Some(value)
        } else {
            None
        }
    })
}

/// 业务作用：冻结并发上限与维度，释放责任由响应生命周期承担。
fn parse_limit_conn(spec: &str) -> Result<LimitConnPolicy> {
    let rest = filter_args(spec, "limit_conn");
    if rest.is_empty() {
        bail!("limit_conn requires `key=<dimension> limit=<N>`");
    }
    let mut key = None;
    let mut limit = None;
    for token in rest.split_whitespace() {
        if let Some((name, value)) = token.split_once('=') {
            match name {
                "key" | "dimension" | "by" => key = Some(parse_limit_key(value)?),
                "limit" | "conn" | "connections" | "number" => {
                    limit = Some(
                        value
                            .parse::<u64>()
                            .with_context(|| format!("limit_conn invalid limit `{value}`"))?,
                    );
                }
                other => bail!("unsupported limit_conn option `{other}`"),
            }
            continue;
        }
        if let Ok(n) = token.parse::<u64>() {
            limit = Some(n);
        } else if key.is_none() {
            key = Some(parse_limit_key(token)?);
        } else {
            bail!("unsupported limit_conn positional option `{token}`");
        }
    }
    let limit = limit.context("limit_conn requires `limit=<N>`")?;
    if limit == 0 {
        bail!("limit_conn limit must be positive");
    }
    Ok(LimitConnPolicy {
        key: key.unwrap_or(LimitReqKey::Ip),
        limit,
    })
}

/// 业务作用：解析 nginx `limit_rate` / `LimitRate` 响应限速规则。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,支持 `LimitRate=1m,after=10m` 或 `limit_rate rate=1m after=10m`。
fn parse_limit_rate(spec: &str) -> Result<LimitRatePolicy> {
    let name = if starts_filter(spec, "LimitRate") {
        "LimitRate"
    } else {
        "limit_rate"
    };
    let rest = filter_args(spec, name);
    if rest.is_empty() {
        bail!("limit_rate requires `rate=<bytes/s>` or `LimitRate=<bytes/s>`");
    }
    let mut rate = None;
    let mut after = 0_u64;
    for token in rest.split(|c: char| c.is_whitespace() || c == ',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "rate" | "bytes_per_second" | "bytes_per_sec" => {
                    rate = Some(parse_byte_size(value)?);
                }
                "after" | "limit_rate_after" => after = parse_byte_size(value)?,
                other => bail!("unsupported limit_rate option `{other}`"),
            }
        } else if rate.is_none() {
            rate = Some(parse_byte_size(token)?);
        } else {
            bail!("unsupported limit_rate positional option `{token}`");
        }
    }
    let bytes_per_second = rate.context("limit_rate requires positive rate")?;
    if bytes_per_second == 0 {
        bail!("limit_rate rate must be positive");
    }
    Ok(LimitRatePolicy {
        bytes_per_second,
        after_bytes: after,
    })
}

/// 业务作用：解析受支持的限额维度，拒绝任意表达式生成无界或不可信的身份键。
fn parse_limit_key(raw: &str) -> Result<LimitReqKey> {
    let value = raw.trim();
    match value {
        "global" => Ok(LimitReqKey::Global),
        "ip" | "remote_addr" | "$remote_addr" | "${remote_addr}" => Ok(LimitReqKey::Ip),
        "route" => Ok(LimitReqKey::Route),
        _ => {
            if let Some(name) = value
                .strip_prefix("header:")
                .or_else(|| value.strip_prefix("header."))
            {
                let name = name
                    .parse::<HeaderName>()
                    .with_context(|| format!("limit_req invalid header dimension `{name}`"))?;
                return Ok(LimitReqKey::Header(name));
            }
            if let Some(name) = value
                .strip_prefix("query:")
                .or_else(|| value.strip_prefix("query."))
            {
                if name.is_empty() || name.len() > 128 {
                    bail!("limit_req invalid query dimension `{name}`");
                }
                return Ok(LimitReqKey::Query(name.to_string()));
            }
            bail!(
                "unsupported limit_req key `{value}` (global|ip|route|header:<name>|query:<name>)"
            )
        }
    }
}

/// 业务作用：解析 `error_page` 响应映射。
///
/// 参数说明：
/// - `spec`: route filter 原始字符串,如 `error_page statuses=500 status=200 body=fallback`
///   或 `error_page statuses=500 reroute=/__error`。
fn parse_error_page(spec: &str) -> Result<ErrorPagePolicy> {
    let rest = filter_args(spec, "error_page");
    if rest.is_empty() {
        bail!(
            "error_page requires `statuses=<codes> status=<code> body=<text>` or `reroute=/path`"
        );
    }
    let mut statuses = Vec::new();
    let mut response_status = None;
    let mut body = None;
    let mut reroute = None;
    for token in rest.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "status" | "response_status" => {
                    response_status = Some(parse_status_code(value, "error_page status")?);
                }
                "body" | "response_body" => body = Some(value.to_string()),
                "reroute" | "internal_redirect" => {
                    validate_internal_reroute_target(value)?;
                    reroute = Some(value.to_string());
                }
                "statuses" | "codes" | "from" => {
                    statuses.extend(parse_status_list(value, "error_page statuses")?);
                }
                other => bail!("unsupported error_page option `{other}`"),
            }
            continue;
        }
        statuses.extend(parse_status_list(token, "error_page status")?);
    }
    if statuses.is_empty() {
        bail!("error_page requires at least one source status");
    }
    statuses.sort_unstable();
    statuses.dedup();
    if let Some(target) = reroute {
        if response_status.is_some() || body.is_some() {
            bail!("error_page reroute cannot be combined with status/body");
        }
        return Ok(ErrorPagePolicy {
            statuses,
            action: ErrorPageAction::Reroute(target),
        });
    }
    let response_status = response_status.unwrap_or_else(|| statuses[0]);
    let body = body.unwrap_or_else(|| {
        response_status
            .canonical_reason()
            .unwrap_or("error")
            .to_string()
    });
    validate_header_value("error_page content-type", "text/plain; charset=utf-8")?;
    Ok(ErrorPagePolicy {
        statuses,
        action: ErrorPageAction::Response(DirectResponse {
            status: response_status,
            value: Some(body),
        }),
    })
}

/// 业务作用：校验内部重路由目标。
///
/// 参数说明：
/// - `target`: `error_page reroute=` 目标 path。
fn validate_internal_reroute_target(target: &str) -> Result<()> {
    if !target.starts_with('/') {
        bail!("error_page reroute target must start with `/`");
    }
    if target.bytes().any(|b| b == 0 || b < 0x20) {
        bail!("error_page reroute target contains control character");
    }
    target
        .parse::<http::Uri>()
        .with_context(|| format!("invalid error_page reroute target `{target}`"))?;
    Ok(())
}

/// 业务作用：解析逗号分隔的 HTTP 状态码列表。
///
/// 参数说明：
/// - `raw`: 逗号分隔状态码。
/// - `label`: 错误上下文标签。
fn parse_status_list(raw: &str, label: &str) -> Result<Vec<StatusCode>> {
    raw.split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| parse_status_code(item.trim(), label))
        .collect()
}

/// 业务作用：解析单个 HTTP 状态码。
///
/// 参数说明：
/// - `raw`: 状态码文本。
/// - `label`: 错误上下文标签。
fn parse_status_code(raw: &str, label: &str) -> Result<StatusCode> {
    let status = raw
        .parse::<u16>()
        .with_context(|| format!("{label} invalid status `{raw}`"))?;
    StatusCode::from_u16(status).with_context(|| format!("{label} invalid status `{status}`"))
}

/// 业务作用：把速率文本转换为明确的容量与时间单位，拒绝零值和溢出。
fn parse_limit_req_rate(raw: &str) -> Result<(u64, Duration)> {
    let value = raw.trim();
    for (suffix, window) in [
        ("r/s", Duration::from_secs(1)),
        ("/s", Duration::from_secs(1)),
        ("r/m", Duration::from_secs(60)),
        ("/m", Duration::from_secs(60)),
        ("r/min", Duration::from_secs(60)),
        ("/min", Duration::from_secs(60)),
        ("r/h", Duration::from_secs(3600)),
        ("/h", Duration::from_secs(3600)),
    ] {
        if let Some(n) = value.strip_suffix(suffix) {
            let limit = n
                .parse::<u64>()
                .with_context(|| format!("limit_req invalid rate `{raw}`"))?;
            return Ok((limit, window));
        }
    }
    let limit = value
        .parse::<u64>()
        .with_context(|| format!("limit_req invalid rate `{raw}`"))?;
    Ok((limit, Duration::from_secs(1)))
}

/// 业务作用：解析字节大小,支持 `k/m/g` 后缀。
///
/// 参数说明：
/// - `raw`: 字节大小文本,例如 `1024` / `1m`。
fn parse_byte_size(raw: &str) -> Result<u64> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("empty byte size");
    }
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b'k') | Some(b'K') => (&value[..value.len() - 1], 1024_u64),
        Some(b'm') | Some(b'M') => (&value[..value.len() - 1], 1024_u64 * 1024),
        Some(b'g') | Some(b'G') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        _ => (value, 1_u64),
    };
    let number = digits
        .parse::<u64>()
        .with_context(|| format!("invalid byte size `{raw}`"))?;
    number
        .checked_mul(multiplier)
        .with_context(|| format!("byte size `{raw}` overflows u64"))
}

/// 业务作用：编译跨站来源、方法和凭据合同，拒绝会产生含糊授权的组合。
fn parse_cors(spec: &str) -> Result<CorsPolicy> {
    let mut policy = CorsPolicy {
        allow_origin: CorsAllowOrigin::Any,
        allow_methods: Some("GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD".to_string()),
        allow_headers: Some("*".to_string()),
        expose_headers: None,
        max_age_seconds: Some(86_400),
        allow_credentials: false,
    };
    let rest = filter_args(spec, "Cors");
    if rest.is_empty() {
        return Ok(policy);
    }
    for token in rest.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .with_context(|| format!("Cors option `{token}` must be key=value"))?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "allow_origin" | "origin" => {
                policy.allow_origin = match value {
                    "*" => CorsAllowOrigin::Any,
                    "echo" | "$origin" | "${origin}" => CorsAllowOrigin::Echo,
                    other => {
                        HeaderValue::from_str(other)
                            .with_context(|| format!("Cors invalid allow_origin `{other}`"))?;
                        CorsAllowOrigin::Static(other.to_string())
                    }
                };
            }
            "allow_methods" | "methods" => {
                validate_header_value("Cors allow_methods", value)?;
                policy.allow_methods = Some(value.to_string());
            }
            "allow_headers" | "headers" => {
                validate_header_value("Cors allow_headers", value)?;
                policy.allow_headers = Some(value.to_string());
            }
            "expose_headers" | "expose" => {
                validate_header_value("Cors expose_headers", value)?;
                policy.expose_headers = Some(value.to_string());
            }
            "max_age" => {
                policy.max_age_seconds = Some(
                    value
                        .parse::<u64>()
                        .with_context(|| format!("Cors invalid max_age `{value}`"))?,
                );
            }
            "allow_credentials" | "credentials" => {
                policy.allow_credentials = parse_bool(value)
                    .with_context(|| format!("Cors invalid allow_credentials `{value}`"))?;
            }
            other => bail!("unsupported Cors option `{other}`"),
        }
    }
    if policy.allow_credentials && matches!(policy.allow_origin, CorsAllowOrigin::Any) {
        bail!("Cors allow_credentials=true cannot be used with allow_origin=*");
    }
    Ok(policy)
}

/// 业务作用：解码控制器生成的 Gateway API CORS 策略，并在数据面快照构建前再次执行安全校验。
///
/// 参数说明：
/// - `spec`：是 `gateway_cors_b64 <base64url-json>` 形式的内部生成配置。
///
/// 返回：字段、数量、origin、method 和 header 全部合法时返回编译策略；畸形输入拒绝整个候选快照。
fn parse_gateway_cors(spec: &str) -> Result<CorsPolicy> {
    let encoded = filter_args(spec, "gateway_cors_b64").trim();
    anyhow::ensure!(!encoded.is_empty(), "gateway_cors_b64 payload is empty");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("gateway_cors_b64 payload is not base64url")?;
    anyhow::ensure!(
        bytes.len() <= 32 * 1024,
        "gateway CORS payload is too large"
    );
    let document = serde_json::from_slice::<serde_json::Value>(&bytes)
        .context("gateway CORS payload is not JSON")?;
    let object = document
        .as_object()
        .context("gateway CORS payload must be an object")?;
    for key in object.keys() {
        anyhow::ensure!(
            matches!(
                key.as_str(),
                "allow_origins"
                    | "allow_methods"
                    | "allow_headers"
                    | "expose_headers"
                    | "allow_credentials"
                    | "max_age"
            ),
            "gateway CORS payload contains unknown field `{key}`"
        );
    }

    let allow_credentials = object
        .get("allow_credentials")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let origin_values = gateway_cors_string_list(object, "allow_origins", 64)?;
    anyhow::ensure!(
        !(origin_values.iter().any(|origin| origin == "*") && origin_values.len() > 1),
        "gateway CORS allow_origins cannot combine `*` with other origins"
    );
    let allow_origin = if origin_values.as_slice() == ["*"] {
        // Gateway API 允许无凭据请求直接返回 `*`，但实际请求是否携带 Cookie/Authorization
        // 只能在请求期确定。统一回显已提供的 Origin 同时覆盖有/无凭据两类请求，并通过
        // `Vary: Origin` 保持共享缓存隔离。
        CorsAllowOrigin::Echo
    } else {
        CorsAllowOrigin::Gateway(
            origin_values
                .iter()
                .map(|origin| parse_gateway_cors_origin(origin))
                .collect::<Result<Vec<_>>>()?,
        )
    };

    let allow_methods = gateway_cors_method_list(object, "allow_methods", 9)?;
    let allow_headers = gateway_cors_header_list(object, "allow_headers", 64)?;
    let expose_headers = gateway_cors_header_list(object, "expose_headers", 64)?;
    let max_age_seconds = match object.get("max_age") {
        Some(value) => {
            let seconds = value
                .as_u64()
                .context("gateway CORS max_age must be an integer")?;
            anyhow::ensure!(
                seconds > 0 && seconds <= i32::MAX as u64,
                "gateway CORS max_age is out of range"
            );
            Some(seconds)
        }
        None => Some(5),
    };
    Ok(CorsPolicy {
        allow_origin,
        allow_methods: (!allow_methods.is_empty()).then(|| allow_methods.join(",")),
        allow_headers: (!allow_headers.is_empty()).then(|| allow_headers.join(",")),
        expose_headers: (!expose_headers.is_empty()).then(|| expose_headers.join(",")),
        max_age_seconds,
        allow_credentials,
    })
}

/// 业务作用：读取 Gateway CORS 的有界字符串数组，统一拒绝缺失类型和空白元素。
///
/// 参数说明：
/// - `object`：是内部策略对象
/// - `field`：是字段名
/// - `max_items`：是协议硬上限。
///
/// 返回：字段缺省时返回空列表；类型、数量与元素合法时返回拥有所有权的字符串。
fn gateway_cors_string_list(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    max_items: usize,
) -> Result<Vec<String>> {
    let Some(value) = object.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .with_context(|| format!("gateway CORS {field} must be an array"))?;
    anyhow::ensure!(
        values.len() <= max_items,
        "gateway CORS {field} exceeds {max_items} items"
    );
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value
            .as_str()
            .with_context(|| format!("gateway CORS {field} entry must be a string"))?;
        anyhow::ensure!(
            !value.is_empty() && value.len() <= 4096,
            "gateway CORS {field} entry has invalid length"
        );
        output.push(value.to_owned());
    }
    Ok(output)
}

/// 业务作用：校验并合并 Gateway CORS method 列表，确保凭证分支不会发布畸形 header。
///
/// 参数说明：
/// - `object`：描述待读取数组及协议上限。
/// - `field`：描述待读取数组及协议上限。
/// - `max_items`：描述待读取数组及协议上限。
///
/// 返回：合法 method 列表；`*` 与其它值并存或非法 token 时失败。
fn gateway_cors_method_list(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    max_items: usize,
) -> Result<Vec<String>> {
    let methods = gateway_cors_string_list(object, field, max_items)?;
    anyhow::ensure!(
        !(methods.iter().any(|method| method == "*") && methods.len() > 1),
        "gateway CORS {field} cannot combine `*` with other methods"
    );
    for method in &methods {
        if method != "*" {
            http::Method::from_bytes(method.as_bytes())
                .with_context(|| format!("gateway CORS method `{method}` is invalid"))?;
        }
    }
    Ok(methods)
}

/// 业务作用：校验并规范化 Gateway CORS header 名列表，避免响应分隔符注入。
///
/// 参数说明：
/// - `object`：描述待读取数组及协议上限。
/// - `field`：描述待读取数组及协议上限。
/// - `max_items`：描述待读取数组及协议上限。
///
/// 返回：合法且转为小写的 header 列表；`*` 与其它值并存或非法名称时失败。
fn gateway_cors_header_list(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    max_items: usize,
) -> Result<Vec<String>> {
    let mut headers = gateway_cors_string_list(object, field, max_items)?;
    anyhow::ensure!(
        !(headers.iter().any(|header| header == "*") && headers.len() > 1),
        "gateway CORS {field} cannot combine `*` with other headers"
    );
    for header in &mut headers {
        if header != "*" {
            *header = HeaderName::from_bytes(header.as_bytes())
                .with_context(|| format!("gateway CORS header `{header}` is invalid"))?
                .as_str()
                .to_owned();
        }
    }
    Ok(headers)
}

/// 业务作用：把 Gateway API origin 规范化为 scheme、默认端口和精确/左侧通配主机计划。
///
/// 参数说明：
/// - `origin`：CRD 中单个 allowOrigins 值，通配符 * 已由调用方单独处理。
///
/// 返回：符合 HTTP(S) origin 语法时返回匹配计划；路径、凭据和非法通配符一律拒绝。
pub(crate) fn parse_gateway_cors_origin(origin: &str) -> Result<CorsOriginPattern> {
    let (scheme, authority) = origin
        .split_once("://")
        .with_context(|| format!("gateway CORS origin `{origin}` lacks scheme"))?;
    anyhow::ensure!(
        matches!(scheme, "http" | "https"),
        "gateway CORS origin `{origin}` has unsupported scheme"
    );
    anyhow::ensure!(
        !authority.is_empty()
            && !authority.contains('/')
            && !authority.contains('?')
            && !authority.contains('#')
            && !authority.contains('@'),
        "gateway CORS origin `{origin}` must contain only an authority"
    );
    if let Some(wildcard) = authority.strip_prefix("*.") {
        anyhow::ensure!(
            !wildcard.contains('*') && !wildcard.starts_with('.') && !wildcard.ends_with('.'),
            "gateway CORS origin `{origin}` has invalid wildcard hostname"
        );
        let (host, port) = split_cors_dns_authority(wildcard, scheme)?;
        anyhow::ensure!(
            host.contains('.'),
            "gateway CORS wildcard origin `{origin}` requires a DNS suffix"
        );
        return Ok(CorsOriginPattern {
            scheme: scheme.to_owned(),
            host: CorsOriginHost::WildcardSuffix(format!(".{host}")),
            port,
        });
    }
    let (normalized_scheme, host, port) = parse_cors_request_origin(origin)?;
    Ok(CorsOriginPattern {
        scheme: normalized_scheme,
        host: CorsOriginHost::Exact(host),
        port,
    })
}

/// 业务作用：解析无路径的 DNS authority，并补齐 HTTP(S) 默认端口供通配 origin 比较。
///
/// 参数说明：
/// - `authority`：不含 scheme
/// - `scheme`：已由调用方验证为 `http` 或 `https`。
///
/// 返回：返回小写 DNS host 与有效端口；非法端口、空 host 或 IP 通配输入失败。
fn split_cors_dns_authority(authority: &str, scheme: &str) -> Result<(String, u16)> {
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let port = port
                .parse::<u16>()
                .with_context(|| format!("gateway CORS origin port `{port}` is invalid"))?;
            anyhow::ensure!(port > 0, "gateway CORS origin port must be non-zero");
            (host, port)
        }
        _ => (
            authority,
            if scheme == "http" {
                80
            } else {
                443
            },
        ),
    };
    anyhow::ensure!(
        !host.is_empty()
            && host
                .bytes()
                .all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')
                }),
        "gateway CORS wildcard host is invalid"
    );
    Ok((host.to_ascii_lowercase(), port))
}

/// 业务作用：规范化请求 `Origin`，让显式默认端口与省略默认端口按同一 origin 比较。
///
/// 参数说明：
/// - `origin`：是 CRD 精确 origin 或下游浏览器 `Origin` 值。
///
/// 返回：合法、无路径、无凭据的 HTTP(S) origin 返回 `(scheme, host, port)`；其它输入失败。
fn parse_cors_request_origin(origin: &str) -> Result<(String, String, u16)> {
    let (_, authority) = origin
        .split_once("://")
        .with_context(|| format!("CORS origin `{origin}` lacks scheme"))?;
    anyhow::ensure!(
        !authority.is_empty()
            && !authority.contains('/')
            && !authority.contains('?')
            && !authority.contains('#')
            && !authority.contains('@'),
        "CORS origin `{origin}` must contain only an authority"
    );
    let parsed = reqwest::Url::parse(origin)
        .with_context(|| format!("CORS origin `{origin}` is invalid"))?;
    let scheme = parsed.scheme();
    anyhow::ensure!(
        matches!(scheme, "http" | "https"),
        "CORS origin `{origin}` has unsupported scheme"
    );
    let host = parsed
        .host_str()
        .with_context(|| format!("CORS origin `{origin}` lacks host"))?
        .to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .with_context(|| format!("CORS origin `{origin}` lacks port"))?;
    Ok((scheme.to_owned(), host, port))
}

/// 业务作用：按指令分隔规则提取参数，避免把相似名称或缺失参数当作合法声明。
fn filter_args<'a>(spec: &'a str, name: &str) -> &'a str {
    let rest = spec
        .strip_prefix(name)
        .or_else(|| spec.strip_prefix(&name.to_ascii_lowercase()))
        .unwrap_or_default()
        .trim_start();
    rest.strip_prefix('=').unwrap_or(rest).trim()
}

/// 业务作用：在构建期验证静态头值，控制字符不得进入请求或响应协议。
fn validate_header_value(label: &str, value: &str) -> Result<()> {
    HeaderValue::from_str(value)
        .with_context(|| format!("{label} invalid header value `{value}`"))?;
    Ok(())
}

/// 业务作用：只接受明确的布尔声明，拒绝拼写错误被静默当作关闭。
fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" | "on" | "1" | "yes" => Ok(true),
        "false" | "off" | "0" | "no" => Ok(false),
        other => bail!("expected boolean, got `{other}`"),
    }
}

/// 业务作用：编译字面路径前缀改写，保持匹配边界与目标路径合法性。
fn parse_rewrite_prefix(spec: &str) -> Result<RewritePrefix> {
    let rest = spec.trim_start_matches("rewrite ").trim();
    let (from, to) = rest
        .split_once(char::is_whitespace)
        .with_context(|| "rewrite requires `from to`")?;
    let from = from.trim();
    if contains_regex_meta(from) {
        bail!("rewrite regex is unsupported; use a plain prefix or PathGlob/PathExact predicates");
    }
    Ok(RewritePrefix {
        from: from.to_string(),
        to: to.trim().to_string(),
    })
}

/// 业务作用：解析 Gateway API ReplaceFullPath 的内部 filter，并在构建期固定安全 origin path。
///
/// 参数说明：
/// - `spec`：是 `gateway_rewrite_full_path /path` 形式的生成配置。
///
/// 返回：path 合法时返回完整替换值；空白、query、fragment、控制字符或超长值返回错误。
fn parse_gateway_rewrite_full_path(spec: &str) -> Result<String> {
    let path = filter_args(spec, "gateway_rewrite_full_path").trim();
    anyhow::ensure!(
        path.starts_with('/')
            && path.len() <= 2048
            && !path
                .bytes()
                .any(|byte| byte <= 0x20 || matches!(byte, b'?' | b'#')),
        "gateway_rewrite_full_path requires a valid origin path within 2048 bytes"
    );
    Ok(path.to_owned())
}

/// 业务作用：识别不能按字面前缀解释的正则元字符，避免误承诺不支持的改写语义。
fn contains_regex_meta(value: &str) -> bool {
    value.as_bytes().iter().any(|b| {
        matches!(
            b,
            b'^' | b'$' | b'(' | b')' | b'[' | b']' | b'+' | b'{' | b'}' | b'|' | b'*' | b'?'
        )
    })
}

/// 业务作用：去掉 path 前 n 段:`/api/order/1` strip 2 → `/1`;段数不足则回退到 `/`。
///
/// `n=0` 是普通代理默认热路径，直接借用原始规范化 path，不为随后 URI 组装预先复制一次。
/// 真正配置 StripPrefix 时才构造 owned 结果。
pub fn strip_n_segments(path: &str, n: usize) -> Cow<'_, str> {
    if n == 0 {
        return Cow::Borrowed(path);
    }
    // path 形如 `/a/b/c`;split('/') 首元素是空串。
    let mut segs = path.split('/').filter(|s| !s.is_empty());
    for _ in 0..n {
        if segs.next().is_none() {
            break;
        }
    }
    let rest: Vec<&str> = segs.collect();
    if rest.is_empty() {
        Cow::Borrowed("/")
    } else {
        Cow::Owned(format!("/{}", rest.join("/")))
    }
}

/// route 级双向带宽与成本型限额的编译产物。
///
/// 全部在快照构建期完成解析与校验:数据面拿到的是可直接使用的策略对象,
/// 请求路径上不再做任何字符串解析,配置错误也不会拖到运行期才暴露。
#[derive(PartialEq, Eq)]
pub struct TrafficLimitPolicy {
    /// 持久开始确认必须先于额度与上游副作用，结束事件沿用同一个有限名额。
    pub(crate) events: bool,
    /// 共享后端选择；只有带宽而没有窗口时仍保持远端调度语义。
    #[cfg(feature = "redis-runtime")]
    pub(crate) redis_backend: bool,
    /// 显式声明共享账本时保存预编码参数，不经过请求次数批领层。
    #[cfg(feature = "redis-runtime")]
    pub(crate) redis_quota: Option<Arc<crate::runtime::traffic_limit::redis::Policy>>,
    /// 逐帧只编码字节数，其余远端方向参数在构建期冻结。
    #[cfg(feature = "redis-runtime")]
    pub(crate) redis_request: Option<Arc<crate::runtime::traffic_limit::redis::bandwidth::Policy>>,
    /// 响应方向独立于请求方向的共享时间债务。
    #[cfg(feature = "redis-runtime")]
    pub(crate) redis_response: Option<Arc<crate::runtime::traffic_limit::redis::bandwidth::Policy>>,
    /// 构建期确定的共享边界，不从客户端声明推导服务或工作区。
    pub(crate) scope: traffic::Scope,
    /// 完整候选的跨入口一致性与归属验证通过后填入；请求路径只借用此身份。
    pub(crate) bound_scope: std::sync::OnceLock<Arc<traffic::BoundScope>>,
    /// 编译后策略语义指纹；热更新改变限额定义时隔离旧窗口，未变化时继续沿用账本。
    pub state_key: u64,
    /// 普通请求维度或冻结的 consumer/API-Key 身份，不把客户端声明当作认证事实。
    pub(crate) key: traffic::Key,
    /// 请求方向带宽策略。
    pub request_bandwidth: Option<crate::runtime::traffic_limit::BandwidthPolicy>,
    /// 响应方向带宽策略。
    pub response_bandwidth: Option<crate::runtime::traffic_limit::BandwidthPolicy>,
    /// 多窗口限额策略。
    pub quota: Option<crate::runtime::traffic_limit::QuotaPolicy>,
    /// 成本来源。
    pub cost_source: crate::runtime::traffic_limit::CostSource,
    /// 只接受构建期声明且已绑定真实上游入口的用量来源。
    pub(crate) usage: Option<Arc<crate::runtime::traffic_limit::usage::Plan>>,
    /// 计数不可用时的处置。
    pub fail_mode: crate::runtime::traffic_limit::QuotaFailMode,
}

/// 业务作用：把 route 的 traffic_limit 配置编译成数据面策略。
///
/// 参数说明：
/// - `cfg`: route 上的原始配置。
/// - `upstream`：路由固定目标；service 作用域只允许静态 lb://service。
///
/// 返回：编译后的策略;任一取值非法时返回错误,阻止该快照生效——
/// 带宽为 0 或 delay 队列无界这类配置一旦放行,表现分别是连接挂死和内存耗尽,
/// 都必须在配置期拦住。
fn build_traffic_limit(
    cfg: &crate::config::model::TrafficLimitCfg,
    upstream: &str,
) -> Result<TrafficLimitPolicy> {
    use crate::runtime::traffic_limit::{
        BandwidthPolicy, CostSource, LimitAlgorithm, LimitWindow, OverflowAction, QuotaFailMode,
        QuotaPolicy,
    };

    let key = traffic::Key::parse(&cfg.key)?;
    anyhow::ensure!(
        !cfg.events || cfg.quota.is_some(),
        "traffic_limit.events requires a quota cost source"
    );
    let scope = traffic::Scope::parse(&cfg.scope, upstream)?;
    let build_bandwidth = |raw: &crate::config::model::BandwidthCfg| -> Result<BandwidthPolicy> {
        let policy = BandwidthPolicy {
            bytes_per_second: raw.bytes_per_second,
            burst_bytes: raw.burst_bytes,
            after_bytes: raw.after_bytes,
            max_wait: Duration::from_millis(raw.max_wait_ms),
        };
        policy.validate()?;
        Ok(policy)
    };
    let request_bandwidth = cfg
        .request_bandwidth
        .as_ref()
        .map(&build_bandwidth)
        .transpose()
        .context("traffic_limit.request_bandwidth")?;
    let response_bandwidth = cfg
        .response_bandwidth
        .as_ref()
        .map(&build_bandwidth)
        .transpose()
        .context("traffic_limit.response_bandwidth")?;

    let mut cost_source = CostSource::PerRequest(1);
    let mut usage = None;
    let quota = match cfg.quota.as_ref() {
        None => None,
        Some(raw) => {
            let algorithm = LimitAlgorithm::parse(&raw.algorithm)?;
            let overflow = match raw.overflow.trim().to_ascii_lowercase().as_str() {
                "reject" => OverflowAction::Reject,
                "delay" => OverflowAction::Delay {
                    max_queue: raw.max_queue,
                    max_wait_ms: raw.max_wait_ms,
                },
                other => bail!("未知 overflow 动作 `{other}`,可选 reject|delay"),
            };
            let windows = raw
                .windows
                .iter()
                .map(|window| LimitWindow {
                    limit: window.limit,
                    window: Duration::from_millis(window.window_ms),
                    burst: window.burst,
                })
                .collect::<Vec<_>>();
            let policy = QuotaPolicy {
                algorithm,
                windows,
                overflow,
            };
            policy.validate().context("traffic_limit.quota")?;
            cost_source = match raw.cost_source.trim().to_ascii_lowercase().as_str() {
                "per_request" => CostSource::PerRequest(raw.reserve.max(1)),
                "response_bytes" => CostSource::ResponseBytes {
                    reserve: raw.reserve,
                    bytes_per_unit: raw.bytes_per_unit.max(1),
                },
                "grpc_messages" => CostSource::GrpcMessages {
                    reserve: raw.reserve,
                },
                "graphql_cost" => CostSource::GraphqlCost,
                "trusted_usage" => {
                    let declared = raw
                        .usage
                        .as_ref()
                        .context("trusted_usage requires quota.usage")?;
                    usage = Some(crate::runtime::traffic_limit::usage::Plan::build(
                        &declared.source,
                        &declared.header,
                        raw.reserve,
                        raw.max_actual,
                    )?);
                    CostSource::TrustedUsage {
                        reserve: raw.reserve,
                        max_actual: raw.max_actual,
                    }
                }
                other => bail!("未知 cost_source `{other}`"),
            };
            anyhow::ensure!(
                raw.usage.is_none() || usage.is_some(),
                "quota.usage requires cost_source=trusted_usage"
            );
            Some(policy)
        }
    };

    #[cfg(feature = "redis-runtime")]
    let mut redis_quota = None;
    #[cfg(feature = "redis-runtime")]
    let (mut redis_request, mut redis_response) = (None, None);
    match cfg.backend.as_str() {
        "" | "local" => {}
        "redis" => {
            #[cfg(not(feature = "redis-runtime"))]
            bail!("traffic_limit backend=redis requires redis-runtime");
            #[cfg(feature = "redis-runtime")]
            {
                if let Some(quota) = quota.as_ref() {
                    let compiled = match cost_source {
                        CostSource::ResponseBytes {
                            reserve,
                            ..
                        }
                        | CostSource::GrpcMessages {
                            reserve,
                        }
                        | CostSource::TrustedUsage {
                            reserve,
                            ..
                        } => {
                            let raw = cfg.quota.as_ref().expect("compiled quota source");
                            crate::runtime::traffic_limit::redis::Policy::build_response(
                                quota,
                                reserve,
                                raw.max_actual,
                                raw.settlement_idle_ms,
                            )?
                        }
                        _ => crate::runtime::traffic_limit::redis::Policy::build(quota)?,
                    };
                    redis_quota = Some(Arc::new(compiled));
                }
                let encode = |value: BandwidthPolicy| {
                    crate::runtime::traffic_limit::redis::bandwidth::Policy::build(&value)
                        .map(Arc::new)
                };
                redis_request = request_bandwidth.map(encode).transpose()?;
                redis_response = response_bandwidth.map(encode).transpose()?;
                if let CostSource::PerRequest(cost) = cost_source {
                    anyhow::ensure!(
                        cost <= crate::runtime::traffic_limit::redis::MAX_COST,
                        "Redis traffic per-request cost exceeds exact integer bound"
                    );
                }
            }
        }
        _ => bail!("traffic_limit backend must be local|redis"),
    }
    // 状态键覆盖完整声明，使窗口数量相同但额度、周期或算法变化时也不会沿用旧账本。
    // 同一配置重载得到同一键，避免借热更新反复获得一份全新额度。
    // 计量开关不改变额度语义，切换可观测性不能清空仍有效的共享债务。
    let mut accounting_policy = cfg.clone();
    accounting_policy.events = false;
    let state_key = crate::upstream::hash::stable_hash(format!("{accounting_policy:?}").as_bytes());
    Ok(TrafficLimitPolicy {
        events: cfg.events,
        #[cfg(feature = "redis-runtime")]
        redis_backend: cfg.backend == "redis",
        #[cfg(feature = "redis-runtime")]
        redis_quota,
        #[cfg(feature = "redis-runtime")]
        redis_request,
        #[cfg(feature = "redis-runtime")]
        redis_response,
        scope,
        bound_scope: std::sync::OnceLock::new(),
        state_key,
        key,
        request_bandwidth,
        response_bandwidth,
        quota,
        cost_source,
        usage,
        fail_mode: QuotaFailMode::parse(&cfg.fail_mode)?,
    })
}
