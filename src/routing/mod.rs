//! 路由表:predicates 全命中 → 命中 route → 指向上游 + nginx/Higress 风格 filter 计划。

pub mod predicate;

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;
use http::Method;
use hyper::StatusCode;
use sha2::{Digest, Sha256};

use crate::auth::{basic_authorization_matches, constant_time_eq, escape_header_quote};
use crate::casbin_auth::CasbinPolicy;
use crate::config::model::{BffAggregationCfg, FaultInjectionCfg, MockResponseCfg, RouteCfg};
use crate::degraphql::DegraphqlPlan;
use crate::dubbo::DubboPlan;
use crate::external_plugin::ExternalPluginChain;
use crate::graphql::GraphqlGuardPolicy;
use crate::http_cache::HttpCachePolicy;
use crate::llm::LlmRoutePolicy;
use crate::net::Cidr;
use crate::opa::OpaPolicy;
use crate::proxy::request_validation::RequestValidationPlan;
use crate::static_serve::StaticServe;
use crate::variable::{ValueTemplate, VariablePlan};
use crate::wasm::WasmPluginChain;
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
/// V5 响应压缩默认最小实体长度；未知长度的流仍可压缩，避免为判长而聚合 body。
const DEFAULT_COMPRESSION_MIN_LENGTH: u64 = 1024;
/// V5 流式 codec 单次最多向 Hyper 交付的压缩字节数，限制每请求暂存内存。
const DEFAULT_COMPRESSION_CHUNK_BYTES: usize = 16 * 1024;
/// 单个压缩输出 frame 的允许上限，防止配置把每个并发请求的暂存块放大到无界。
const MAX_COMPRESSION_CHUNK_BYTES: usize = 1024 * 1024;
/// 每条 route 最多声明的可压缩 MIME 匹配项，限制热路径线性扫描成本。
const MAX_COMPRESSION_CONTENT_TYPES: usize = 64;
/// V5 公共响应缓存默认 TTL，毫秒。
const DEFAULT_HTTP_CACHE_TTL_MS: u64 = 60_000;
/// V5 每条 cache route 默认允许的 L1 entry 数。
const DEFAULT_HTTP_CACHE_MAX_ENTRIES: u64 = 10_000;
/// V5 cache miss 默认最多复制 1MiB 未压缩实体；超过后透明转发但不回填。
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
    /// R1:`http://host:port` 直连;R2:`lb://service`。
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
    /// 是否透传下游请求头,对应 nginx `proxy_pass_request_headers`。
    pub pass_request_headers: bool,
    /// 是否透传下游请求体,对应 nginx `proxy_pass_request_body`。
    pub pass_request_body: bool,
    /// 上游请求头设置规则集合。
    pub request_headers: Vec<RequestHeaderSet>,
    /// 下游响应头过滤规则集合。
    pub response_headers: Vec<ResponseHeaderOp>,
    /// V3 `sub_filter` 响应体流式替换规则。存在时仅包当前 route 的响应 body。
    pub sub_filters: Vec<SubFilterRule>,
    /// V5 gzip/brotli 响应压缩策略。不存在时该 route 完全不介入内容编码。
    pub compression: Option<CompressionPolicy>,
    /// V5 公共 HTTP 响应 L1/L2 缓存；不存在时不构造 key、不复制 body。
    pub(crate) http_cache: Option<Arc<HttpCachePolicy>>,
    /// V5 请求 OpenAPI/JSON Schema 显式慢路径；不存在时不构造 JSON、不读取 body。
    pub(crate) request_validation: Option<RequestValidationPlan>,
    /// V7 GraphQL query depth/complexity guard；不存在时不读取或解析普通代理 body。
    pub(crate) graphql_guard: Option<GraphqlGuardPolicy>,
    /// V7 REST→GraphQL 固定文档映射；不存在时普通 route 无 variables 编码成本。
    pub(crate) degraphql: Option<Arc<DegraphqlPlan>>,
    /// V7 OPA 外部授权；不存在时普通 route 不编码 policy input、不访问 decision cache。
    pub(crate) opa_authorization: Option<Arc<OpaPolicy>>,
    /// V7 内嵌 Casbin RBAC/ABAC；快照内只读，请求期无文件 I/O。
    pub(crate) casbin_authorization: Option<Arc<CasbinPolicy>>,
    /// V7 Proxy-Wasm request/response header 插件链；不存在时数据面无沙箱调度成本。
    pub(crate) wasm_plugins: Option<Arc<WasmPluginChain>>,
    /// V7 外部 HTTP request/response header 插件链；不存在时不编码 JSON、不发子请求。
    pub(crate) external_plugins: Option<Arc<ExternalPluginChain>>,
    /// V7 BFF 并发只读子请求计划；终端慢路径，普通 route 为 None。
    pub(crate) bff_aggregation: Option<Arc<BffAggregationPolicy>>,
    /// V7 HTTP→Dubbo2 generic invocation；不存在时不聚合 JSON、不建立原始 TCP RPC 连接。
    pub(crate) dubbo: Option<Arc<DubboPlan>>,
    /// V7 typed mock 固定响应；body 使用 Bytes，单请求只 clone 引用计数句柄。
    pub(crate) mock_response: Option<MockResponsePolicy>,
    /// V7 显式 chaos 策略；采样不读取/复制 body。
    pub(crate) fault_injection: Option<FaultInjectionPolicy>,
    /// V7 consumer usage-plan 配额；全局 catalog 已解析为共享只读 plan。
    pub(crate) usage_plan: Option<UsagePlanPolicy>,
    /// V6 多模型 LLM 统一协议计划；不存在时普通代理路径没有 JSON/token 处理开销。
    pub(crate) llm: Option<Arc<LlmRoutePolicy>>,
    /// V8 gRPC 边缘模式已编译计划;None = 普通 L7 透传(默认)。V8-1/V8-2
    /// 订阅/发布分支读取该计划，静态 relay 由进程级集群计划接线。
    pub(crate) grpc_edge: Option<Arc<crate::grpc_edge::GrpcEdgePlan>>,
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
    /// V4 HTTP Basic 鉴权策略,对应 nginx `auth_basic` 基础形态。
    pub basic_auth: Option<BasicAuthPolicy>,
    /// V4 API-Key 鉴权策略集合。多条策略之间视为同一种认证方式的 OR。
    pub api_keys: Vec<ApiKeyPolicy>,
    /// V4 HMAC-SHA256 请求签名策略集合。多条策略之间视为同一种认证方式的 OR。
    pub hmac_auth: Vec<HmacAuthPolicy>,
    /// V4 JWT HS256 鉴权策略集合。多条策略之间视为同一种认证方式的 OR。
    pub jwt_auth: Vec<JwtAuthPolicy>,
    /// V4 ext_authz / auth_request 外部鉴权策略集合。多条策略之间视为同一种认证方式的 OR。
    pub ext_authz: Vec<ExtAuthzPolicy>,
    /// V4 多认证策略组合方式,对应 nginx `satisfy any/all` 的数据面鉴权子集。
    pub satisfy: SatisfyMode,
    /// V3 nginx `if` 安全子集:条件命中后执行固定 `return` 短路。
    pub conditional_returns: Vec<ConditionalReturn>,
    /// V3 `limit_req` 请求速率规则。
    pub limit_req: Vec<LimitReqPolicy>,
    /// V3 `limit_conn` 并发规则。
    pub limit_conn: Vec<LimitConnPolicy>,
    /// V3 `limit_rate` 响应字节限速规则。
    pub limit_rate: Option<LimitRatePolicy>,
    /// V3 熔断/降级规则。
    pub circuit_breakers: Vec<CircuitBreakerPolicy>,
    /// V3 `error_page` 状态映射规则。
    pub error_pages: Vec<ErrorPagePolicy>,
    /// 是否让 `error_page` 接管上游错误响应,对应 nginx `proxy_intercept_errors`。
    pub proxy_intercept_errors: bool,
    /// 是否处理上游 `X-Accel-Redirect` 响应头并转入 internal route。
    pub x_accel_redirect: bool,
    /// route 级固定响应,对应 nginx `return` 风格短路。
    pub direct_response: Option<DirectResponse>,
    /// 本地静态文件/SPA 后端。存在时不走上游代理。
    pub static_serve: Option<StaticServe>,
    /// V3 `mirror` 流量镜像规则。当前基础版只镜像 head/空 body,不阻塞主链路。
    pub mirrors: Vec<MirrorPolicy>,
    /// 当前快照的变量计划,供 route 级模板渲染。
    pub variables: Arc<VariablePlan>,
    /// SSE/gRPC 响应 idle 覆盖；None 继承 proxy 全局值。
    pub long_stream_idle_timeout_ms: Option<u64>,
    /// SSE/gRPC 响应最长存活时间(ms)；0 不限制。
    pub long_stream_max_lifetime_ms: u64,
}

/// 已编译路由表。数据面只顺序匹配断言,不再解析配置字符串。
pub struct Router {
    routes: Vec<Arc<Route>>,
    /// 整个 proxy 是否存在响应压缩 route。构建期汇总后，请求入口只读一个 bool；全无压缩的
    /// 常见反代/gRPC proxy 不再为每个请求扫描 `Accept-Encoding`，也不 clone HeaderMap。
    has_response_compression: bool,
    /// 构建期编译的灰度组。请求匹配只做借用查表和整数哈希，不构造候选 Vec。
    weighted_groups: HashMap<String, WeightedRouteGroup>,
}

/// 一个 Weight 组在有序 route 表中的成员与总份额。
struct WeightedRouteGroup {
    members: Vec<(usize, u32)>,
    total_weight: u64,
}

impl Router {
    /// 从 yml 的 RouteCfg 列表构建(顺序即优先级)。
    ///
    /// # 参数
    /// - `cfgs`: 配置文件中的 route 列表。
    /// - `variables`: 已编译的变量计划,供 route URI 与 header 模板复用。
    /// - `config_dir`: `gateway.yml` 所在目录,用于解析静态 root 相对路径。
    pub fn build(
        cfgs: &[RouteCfg],
        variables: Arc<VariablePlan>,
        config_dir: &Path,
    ) -> Result<Router> {
        let usage_plans = UsagePlanCatalog::build(&crate::config::model::UsagePlansCfg::default())?;
        Self::build_with_usage_plans(cfgs, variables, config_dir, usage_plans)
    }

    /// 使用已编译的全局套餐目录构建路由表。
    ///
    /// 套餐目录由整个配置快照共享；route 只持有不可变 `Arc`，避免在每个请求上解析
    /// plan id、复制 consumer 映射或获取配置锁。
    pub(crate) fn build_with_usage_plans(
        cfgs: &[RouteCfg],
        variables: Arc<VariablePlan>,
        config_dir: &Path,
        usage_plans: Arc<UsagePlanCatalog>,
    ) -> Result<Router> {
        let mut ordered: Vec<(i32, Arc<Route>)> = Vec::with_capacity(cfgs.len());
        for c in cfgs {
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
            // P0-1 规则数硬上限:每请求都要线性扫描全部断言,条数必须有界;
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
                .filter(|predicate| matches!(predicate, Predicate::Header { .. }))
                .count();
            anyhow::ensure!(
                header_predicates <= MAX_HEADER_PREDICATES_PER_ROUTE,
                "route `{}` declares {header_predicates} Header predicates, exceeding the \
                 {MAX_HEADER_PREDICATES_PER_ROUTE} cap",
                c.id
            );
            let mut internal = false;
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
            // V8 gRPC 边缘模式:构建期定型 + 拒绝矩阵。未开启恒为 None,数据面零感知。
            let grpc_edge = crate::grpc_edge::GrpcEdgePlan::build(c.grpc_edge.as_ref(), &c.id)
                .with_context(|| format!("route `{}` grpc_edge", c.id))?
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
                    StaticServe::build(static_cfg, config_dir, variables.as_ref())
                })
                .transpose()
                .with_context(|| format!("route `{}` serve.static", c.id))?;
            let terminal_backends = usize::from(!c.uri.trim().is_empty())
                + usize::from(static_serve.is_some())
                + usize::from(llm.is_some())
                + usize::from(bff_aggregation.is_some())
                + usize::from(mock_response.is_some());
            if terminal_backends != 1 {
                bail!(
                    "route `{}` requires exactly one of uri/serve.static/llm/bff_aggregation/mock_response",
                    c.id
                );
            }
            if grpc_edge.is_some() && (c.uri.trim().is_empty() || dubbo.is_some()) {
                // 边缘 route 的非 edge 消息仍要正常 L7 转发到后端(§25.2 连接模型),
                // 因此必须是 HTTP upstream 后端;llm/serve.static/mock/bff/dubbo 均不兼容。
                bail!(
                    "route `{}` grpc_edge requires an HTTP upstream `uri` and cannot combine with llm/serve.static/mock_response/bff_aggregation/dubbo",
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
            let mut strip_prefix = 0;
            let mut rewrite_prefix = None;
            let mut pass_request_headers = true;
            let mut pass_request_body = true;
            let mut request_headers = Vec::new();
            let mut response_headers = Vec::new();
            let mut sub_filters = Vec::new();
            let mut compression = None;
            let mut compression_defined = false;
            let mut http_cache = None;
            let mut http_cache_defined = false;
            let mut cache_invalidations = Vec::new();
            let mut cors = None;
            let mut fallback_headers = false;
            let mut access_rules = Vec::new();
            let mut referer = None;
            let mut limit_except = None;
            let mut basic_auth = None;
            let mut api_keys = Vec::new();
            let mut hmac_auth = Vec::new();
            let mut jwt_auth = Vec::new();
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
                    strip_prefix = n;
                    continue;
                }
                match parse_filter(f, variables.as_ref(), config_dir)
                    .with_context(|| format!("route `{}` filter `{f}`", c.id))?
                {
                    ParsedFilter::None => {}
                    ParsedFilter::Internal => internal = true,
                    ParsedFilter::ProxySetHeader(op) => request_headers.push(op),
                    ParsedFilter::PassRequestHeaders(pass) => pass_request_headers = pass,
                    ParsedFilter::PassRequestBody(pass) => pass_request_body = pass,
                    ParsedFilter::AddHeader(op) => response_headers.push(ResponseHeaderOp::Add(op)),
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
                    ParsedFilter::ApiKey(policy) => api_keys.push(policy),
                    ParsedFilter::HmacAuth(policy) => hmac_auth.push(policy),
                    ParsedFilter::JwtAuth(policy) => jwt_auth.push(policy),
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
                    ParsedFilter::Mirror(policy) => mirrors.push(policy),
                }
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
                && (basic_auth.is_some()
                    || !api_keys.is_empty()
                    || !hmac_auth.is_empty()
                    || !jwt_auth.is_empty()
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
                if matches!(cors.allow_origin, CorsAllowOrigin::Echo)
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
            let graphql_guard = c
                .graphql_guard
                .as_ref()
                .map(|cfg| GraphqlGuardPolicy::build(cfg, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` graphql_guard", c.id))?;
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
            let external_plugins = (!c.external_plugins.is_empty())
                .then(|| ExternalPluginChain::build(&c.external_plugins, config_dir, c.id.as_str()))
                .transpose()
                .with_context(|| format!("route `{}` external_plugins", c.id))?
                .map(Arc::new);
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
            if degraphql.is_some()
                && (request_validation.is_some()
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
                    || rewrite_prefix.is_some())
            {
                bail!(
                    "route `{}` degraphql cannot combine with validation/cache/internal/terminal backends/mirror/path rewrite",
                    c.id
                );
            }
            if dubbo.is_some()
                && (request_validation.is_some()
                    || graphql_guard.is_some()
                    || degraphql.is_some()
                    || http_cache.is_some()
                    || !mirrors.is_empty()
                    || strip_prefix > 0
                    || rewrite_prefix.is_some()
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
            if opa_authorization
                .as_ref()
                .is_some_and(|policy| policy.requires_identity())
                && basic_auth.is_none()
                && jwt_auth.is_empty()
                && !api_keys.iter().any(|policy| policy.consumer.is_some())
            {
                bail!(
                    "route `{}` opa_authorization require_identity=true needs Basic, JWT, or API-Key with consumer",
                    c.id
                );
            }
            if casbin_authorization
                .as_ref()
                .is_some_and(|policy| policy.requires_identity())
                && basic_auth.is_none()
                && jwt_auth.is_empty()
                && !api_keys.iter().any(|policy| policy.consumer.is_some())
            {
                bail!(
                    "route `{}` casbin_authorization require_identity=true needs Basic, JWT, or API-Key with consumer",
                    c.id
                );
            }
            if usage_plan
                .as_ref()
                .is_some_and(|policy| policy.require_consumer)
                && basic_auth.is_none()
                && jwt_auth.is_empty()
                && !api_keys.iter().any(|policy| policy.consumer.is_some())
            {
                bail!(
                    "route `{}` usage_plan require_consumer=true needs Basic, JWT, or API-Key with consumer",
                    c.id
                );
            }
            if llm.is_some() && request_validation.is_some() {
                bail!(
                    "route `{}` llm cannot combine request_validation; the unified LLM contract already owns the bounded JSON body",
                    c.id
                );
            }
            if bff_aggregation.is_some()
                && (request_validation.is_some()
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
                    "route `{}` llm cannot combine proxy_cache/return/static/mirror/x_accel_redirect/error_page; V6 uses its own model fallback and semantic cache pipeline",
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
            if request_validation.is_some() && (c.long_stream_max_lifetime_ms > 0) {
                bail!(
                    "route `{}` request_validation cannot be combined with long_stream_max_lifetime_ms; schema buffering is a finite HTTP slow path",
                    c.id
                );
            }
            let signature = predicates_signature(&predicates);
            let has_weight = predicates
                .iter()
                .any(|predicate| matches!(predicate, Predicate::Weight { .. }));
            if let Some((_, existing)) = (!has_weight)
                .then(|| {
                    ordered.iter().find(|(order, route)| {
                        *order == c.order && predicates_signature(&route.predicates) == signature
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
                    upstream: c.uri.clone(),
                    upstream_template,
                    predicates,
                    internal,
                    strip_prefix,
                    rewrite_prefix,
                    pass_request_headers,
                    pass_request_body,
                    request_headers,
                    response_headers,
                    sub_filters,
                    compression,
                    http_cache,
                    request_validation,
                    graphql_guard,
                    degraphql,
                    opa_authorization,
                    casbin_authorization,
                    wasm_plugins,
                    external_plugins,
                    bff_aggregation,
                    dubbo,
                    mock_response,
                    fault_injection,
                    usage_plan,
                    llm,
                    grpc_edge,
                    cache_invalidations,
                    cors,
                    fallback_headers,
                    access_rules,
                    referer,
                    limit_except,
                    basic_auth,
                    api_keys,
                    hmac_auth,
                    jwt_auth,
                    ext_authz,
                    satisfy,
                    conditional_returns,
                    limit_req,
                    limit_conn,
                    limit_rate,
                    circuit_breakers,
                    error_pages,
                    proxy_intercept_errors,
                    x_accel_redirect,
                    direct_response,
                    static_serve,
                    mirrors,
                    variables: variables.clone(),
                    long_stream_idle_timeout_ms: c.long_stream_idle_timeout_ms,
                    long_stream_max_lifetime_ms: c.long_stream_max_lifetime_ms,
                }),
            ));
        }
        // ★L5:按 order 稳定排序(数值小者优先);同 order 保持配置书写顺序(SCG 有序语义)。
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
        Ok(Router {
            routes,
            has_response_compression,
            weighted_groups,
        })
    }

    /// 顺序匹配,第一个全命中的路由胜出。
    ///
    /// # 参数
    /// - `parts`: 下游请求的 head parts。
    pub fn match_route(&self, parts: &Parts) -> Option<Arc<Route>> {
        self.match_route_with_key(parts, b"")
    }

    /// 使用请求稳定键执行普通匹配与成组权重灰度。
    ///
    /// Weight route 在 build 阶段已保证同组具有相同 order 与非权重 predicates。运行时先按
    /// 原有顺序找到首个可用组，再用 `group + request_key` 的稳定哈希落桶；相同 key 在配置
    /// 不变时始终落到同一成员。遍历与查表均借用快照内存，不在热路径分配候选集合。
    pub fn match_route_with_key(&self, parts: &Parts, request_key: &[u8]) -> Option<Arc<Route>> {
        for route in &self.routes {
            if route.internal
                || !route
                    .predicates
                    .iter()
                    .filter(|predicate| !matches!(predicate, Predicate::Weight { .. }))
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

    /// 顺序匹配内部 route,仅供 error_page/reroute/X-Accel 类内部跳转使用。
    ///
    /// # 参数
    /// - `parts`: 内部重写后的请求 head。
    pub fn match_internal_route(&self, parts: &Parts) -> Option<Arc<Route>> {
        self.routes
            .iter()
            .find(|r| r.internal && r.predicates.iter().all(|p| p.matches(parts)))
            .cloned()
    }

    /// 返回静态 `lb://service` 引用,供 admin 发现视图展示 service 被哪些 route 使用。
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

    /// 当前不可变 route slice。只供低频管理/失效对账遍历，不暴露可变入口。
    #[cfg(feature = "redis-runtime")]
    pub(crate) fn routes(&self) -> &[Arc<Route>] {
        &self.routes
    }

    /// 按稳定 id 定位 route；管理面 PURGE/失效消息使用，非请求匹配热路径。
    pub(crate) fn route_by_id(&self, route_id: &str) -> Option<&Arc<Route>> {
        self.routes.iter().find(|route| route.id == route_id)
    }

    /// 是否至少一条 route 启用响应压缩。
    ///
    /// internal reroute 也来自同一 Router，因此用 proxy 级汇总而不是只看首条命中 route，避免
    /// `error_page`/`X-Accel-Redirect` 跳到压缩 route 后丢失原客户端协商能力。
    #[inline]
    pub(crate) fn has_response_compression(&self) -> bool {
        self.has_response_compression
    }

    /// 是否有 route 显式要求 Redis L2；快照构建期用来交叉校验 runtime backend。
    pub(crate) fn uses_http_cache_l2(&self) -> bool {
        self.routes.iter().any(|route| {
            route
                .http_cache
                .as_ref()
                .is_some_and(|policy| policy.l2_enabled())
        })
    }

    /// V8:统计启用 gRPC 边缘模式的 route 数。
    ///
    /// 供管理面快照摘要展示"edge 接线情况"(0 = 纯 L7);同时让快照接线在 V8-0
    /// 就有真实读取方,不留 dead field。
    pub(crate) fn grpc_edge_route_count(&self) -> usize {
        self.routes
            .iter()
            .filter(|route| route.grpc_edge.is_some())
            .count()
    }

    /// 是否有 LLM route 显式要求 Redis 语义缓存；与 HTTP cache 共用 bootstrap Redis 连接。
    pub(crate) fn uses_llm_cache_l2(&self) -> bool {
        self.routes.iter().any(|route| {
            route
                .llm
                .as_ref()
                .and_then(|policy| policy.semantic_cache.as_ref())
                .is_some_and(|cache| cache.l2_enabled)
        })
    }

    /// 返回当前路由数量,主要用于健康检查和单测断言。
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// 判断路由表是否为空。
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Route {
    /// 按本 route 的 allow/deny 规则判断客户端 IP 是否允许访问。
    ///
    /// # 参数
    /// - `ip`: 真实客户端 IP。
    pub fn permits_ip(&self, ip: IpAddr) -> bool {
        for rule in &self.access_rules {
            if rule.matches(ip) {
                return rule.action == AccessAction::Allow;
            }
        }
        true
    }

    /// 按 `valid_referers` 判断请求 Referer 是否允许。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    pub fn permits_referer(&self, parts: &Parts) -> bool {
        self.referer
            .as_ref()
            .map(|policy| policy.matches(parts))
            .unwrap_or(true)
    }

    /// 按 `limit_except` 判断请求方法是否允许。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    pub fn permits_method(&self, parts: &Parts) -> bool {
        self.limit_except
            .as_ref()
            .map(|methods| methods.contains(&parts.method))
            .unwrap_or(true)
    }

    /// 按 V4 数据面同步鉴权子链判断请求是否通过认证。
    ///
    /// ext_authz 需要异步外呼,由代理层拿 [`SyncAuthState`] 后继续执行;本函数保留给纯同步策略和单测使用。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    pub fn permits_auth(&self, parts: &Parts) -> bool {
        self.ext_authz.is_empty() && self.sync_auth_state(parts).ok
    }

    /// 计算 Basic/API-Key/HMAC/JWT 这组同步鉴权策略的组合结果。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    pub fn sync_auth_state(&self, parts: &Parts) -> SyncAuthState {
        let has_basic = self.basic_auth.is_some();
        let has_api_key = !self.api_keys.is_empty();
        let has_hmac = !self.hmac_auth.is_empty();
        let has_jwt = !self.jwt_auth.is_empty();
        if !has_basic && !has_api_key && !has_hmac && !has_jwt {
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
        let ok = match self.satisfy {
            SatisfyMode::All => {
                (!has_basic || basic_ok)
                    && (!has_api_key || api_key_ok)
                    && (!has_hmac || hmac_ok)
                    && (!has_jwt || jwt_ok)
            }
            SatisfyMode::Any => {
                (has_basic && basic_ok)
                    || (has_api_key && api_key_ok)
                    || (has_hmac && hmac_ok)
                    || (has_jwt && jwt_ok)
            }
        };
        SyncAuthState {
            configured: true,
            ok,
        }
    }

    /// 提取已通过认证请求的长连接 consumer 标识。
    ///
    /// 只应在鉴权链已放行且请求将升级/进入 gRPC 长流时调用。优先级为 JWT `sub`、显式
    /// API-Key `consumer=`、Basic user；HMAC/ext_authz 未声明稳定主体时返回 None。
    pub fn authenticated_long_connection_consumer(&self, parts: &Parts) -> Option<Arc<str>> {
        self.authenticated_consumer(parts)
    }

    /// 提取已通过认证请求的稳定 consumer；LLM 配额与长连接维度共用同一可信身份来源。
    pub fn authenticated_consumer(&self, parts: &Parts) -> Option<Arc<str>> {
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

    /// V8 edge:从任一命中的 JWT 策略提取指定 claim(§25.2.3:tenant/user 身份只来自
    /// 已验证 principal 的 claim,客户端自报 header 永不是权威身份)。
    pub fn authenticated_edge_claim(&self, parts: &Parts, claim: &str) -> Option<Arc<str>> {
        self.jwt_auth
            .iter()
            .find_map(|policy| policy.authenticated_claim(parts, claim))
    }

    /// 返回命中 API-Key 策略的稳定 SHA-256 指纹。指纹只用于 LLM 配额 key；原始 key 永不
    /// 拼入进程 HashMap/Redis key，也不进入日志或 metrics label。
    pub fn authenticated_api_key_fingerprint(&self, parts: &Parts) -> Option<String> {
        let policy = self.api_keys.iter().find(|policy| policy.matches(parts))?;
        let digest = Sha256::digest(policy.expected.as_slice());
        let mut encoded = String::with_capacity(32);
        use std::fmt::Write as _;
        for byte in &digest[..16] {
            write!(&mut encoded, "{byte:02x}").expect("writing SHA-256 hex to String cannot fail");
        }
        Some(encoded)
    }

    /// 当前 route 是否配置了异步 ext_authz 外部鉴权策略。
    pub fn has_ext_authz(&self) -> bool {
        !self.ext_authz.is_empty()
    }

    /// 本 route 是否配置了任一开启防重放的 HMAC 策略(§20)。
    pub fn has_hmac_replay(&self) -> bool {
        self.hmac_auth.iter().any(HmacAuthPolicy::replay_enabled)
    }

    /// 检测 HMAC 重放:对每个【开启防重放且签名有效】的策略,消费其 nonce;nonce 已用过则判重放。
    ///
    /// 只有签名先有效才消费 nonce(`matches` 已含签名 + 时间戳 + nonce 存在校验),避免无效请求污染去重表。
    /// 消费一个 fresh nonce 无副作用;返回 `true` 表示检测到重放,调用方应拒绝。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    /// - `guard`: 防重放守卫后端(local/redis)。
    pub async fn hmac_replay_detected(
        &self,
        parts: &Parts,
        guard: &dyn crate::runtime_state::ReplayGuard,
    ) -> bool {
        for policy in &self.hmac_auth {
            if policy.replay_enabled() && policy.matches(parts) {
                if let Some(nonce) = policy.nonce_value(parts) {
                    // 按 route id + nonce 生成去重 key,避免不同 route 的 nonce 相互撞车。
                    let key = format!("{}:{}", self.id, nonce);
                    if !guard.check_and_set(&key, policy.replay_ttl()).await {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// 返回认证失败响应的 `WWW-Authenticate` challenge 值。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head;当前只用于保持 API 与其它 route 判断一致。
    pub fn auth_challenge(&self, _parts: &Parts) -> Option<String> {
        self.basic_auth
            .as_ref()
            .map(BasicAuthPolicy::challenge_value)
    }

    /// 按 nginx `if` 安全子集判断是否需要固定响应短路。
    ///
    /// # 参数
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
        let eval_ctx = crate::variable::EvalContext {
            parts,
            client_ip,
            downstream_proto,
            request_id,
            route_id: self.id.as_str(),
        };
        self.conditional_returns
            .iter()
            .find(|rule| rule.matches(&eval_ctx, self.variables.as_ref()))
            .map(|rule| rule.response.clone())
    }
}

/// 请求头设置规则,对应 nginx `proxy_set_header`。
#[derive(Clone)]
pub struct RequestHeaderSet {
    /// 待写入的上游请求头名。
    pub name: HeaderName,
    /// 已编译 header value 模板。
    pub value: ValueTemplate,
}

/// 响应头追加规则,对应 nginx `add_header`。
pub struct ResponseHeaderSet {
    /// 待追加的下游响应头名。
    pub name: HeaderName,
    /// 已编译 header value 模板。
    pub value: ValueTemplate,
}

/// 响应头过滤操作。
pub enum ResponseHeaderOp {
    /// 追加响应头。
    Add(ResponseHeaderSet),
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
#[derive(Clone)]
pub struct SubFilterRule {
    /// 要查找的原始字节串。V3 基础按 bytes 匹配,不做字符集转换。
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
    /// 返回写入 `Content-Encoding` 和匹配 `Accept-Encoding` 的标准 token。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
        }
    }
}

/// V5 route 级响应压缩策略。
///
/// 所有字符串与数值都在快照构建期完成校验；单请求只做 header 借用扫描、MIME
/// 匹配和小枚举选择。未知 `Content-Length` 的响应不会为判定阈值而聚合 body。
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
    /// 判断响应媒体类型是否允许压缩。
    ///
    /// # 参数
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
enum CompressionContentType {
    /// `*`：运维显式选择压缩所有带 Content-Type 的实体。
    Any,
    /// `text/*` 一类主类型前缀。
    Prefix(Box<str>),
    /// 完整媒体类型，如 `application/json`。
    Exact(Box<str>),
}

impl CompressionContentType {
    /// 对一个已去除参数的媒体类型做 ASCII 大小写无关匹配。
    ///
    /// # 参数
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
    /// 响应阶段是否需要保留请求上下文。
    ///
    /// 动态 `add_header` 需要原始请求变量;纯静态响应头操作不让热路径额外 clone `Parts`。
    pub fn needs_request_context(&self) -> bool {
        match self {
            Self::Add(set) => set.value.static_literal().is_none(),
            Self::Hide(_) | Self::ProxyRedirect(_) | Self::CookieRewrite(_) | Self::Dedupe(_) => {
                false
            }
        }
    }
}

/// nginx `proxy_redirect from to` 的已编译规则。
pub struct ProxyRedirectRule {
    /// 上游返回的 URL 前缀。
    pub from: String,
    /// 下游可见的替换前缀。
    pub to: String,
}

/// nginx `proxy_cookie_domain/path/flags` 的已编译规则。
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
pub struct DedupeResponseHeader {
    /// 待去重的响应头名。
    pub name: HeaderName,
    /// 保留首个还是最后一个值。
    pub mode: DedupeMode,
}

/// nginx `mirror` 流量镜像规则。
#[derive(Clone)]
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
#[derive(Clone, Copy)]
pub enum DedupeMode {
    /// 保留第一个出现的 header value。
    RetainFirst,
    /// 保留最后一个出现的 header value。
    RetainLast,
    /// 保留唯一值;重复值只输出一次。
    RetainUnique,
}

/// CORS 规则的已编译形态。
#[derive(Clone)]
pub struct CorsPolicy {
    /// Access-Control-Allow-Origin 策略。
    pub allow_origin: CorsAllowOrigin,
    /// Access-Control-Allow-Methods 值。
    pub allow_methods: String,
    /// Access-Control-Allow-Headers 值。
    pub allow_headers: String,
    /// Access-Control-Expose-Headers 值。
    pub expose_headers: Option<String>,
    /// Access-Control-Max-Age 秒数。
    pub max_age_seconds: Option<u64>,
    /// 是否允许携带凭证。
    pub allow_credentials: bool,
}

/// CORS allow-origin 模式。
#[derive(Clone)]
pub enum CorsAllowOrigin {
    /// 返回通配符 `*`。
    Any,
    /// 回显请求 `Origin`。
    Echo,
    /// 返回固定 origin。
    Static(String),
}

/// path 前缀改写规则,对应轻量 `rewrite` 子集。
#[derive(Clone)]
pub struct RewritePrefix {
    /// 需要匹配的原始前缀。
    pub from: String,
    /// 替换后的目标前缀。
    pub to: String,
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

fn validate_bff_id(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') })
            && value != "_errors",
        "BFF target id must be 1..=64 safe ASCII and cannot be `_errors`"
    );
    Ok(())
}

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
#[derive(Clone)]
pub(crate) struct MockResponsePolicy {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl MockResponsePolicy {
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
#[derive(Clone)]
pub(crate) struct FaultInjectionPolicy {
    pub percentage_bps: u16,
    pub delay: Duration,
    pub abort_status: Option<StatusCode>,
    pub abort_body: Bytes,
}

impl FaultInjectionPolicy {
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
pub(crate) struct UsagePlan {
    pub id: Arc<str>,
    pub limit: u64,
    pub window: Duration,
    pub burst: u64,
    pub max_active_keys: usize,
    pub active_keys_fail_open: bool,
}

/// route 对全局 catalog 的只读绑定。
pub(crate) struct UsagePlanPolicy {
    consumers: Arc<HashMap<Arc<str>, Arc<UsagePlan>>>,
    default: Option<Arc<UsagePlan>>,
    pub require_consumer: bool,
}

impl UsagePlanCatalog {
    /// 构建全局套餐与 consumer 绑定。所有引用在快照发布前解析，运行期不查字符串 plan id。
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
        let mut consumers = HashMap::with_capacity(cfg.consumers.len());
        for (consumer, plan_id) in &cfg.consumers {
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
    /// 选择已验证 consumer 的套餐；None 表示该身份未映射且无 default。
    pub(crate) fn select(&self, consumer: Option<&str>) -> Option<&Arc<UsagePlan>> {
        consumer
            .and_then(|consumer| self.consumers.get(consumer))
            .or(self.default.as_ref())
    }
}

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
#[derive(Clone)]
pub struct DirectResponse {
    /// 响应状态码。
    pub status: StatusCode,
    /// 可选响应体;为空时使用状态 reason。
    pub value: Option<String>,
}

/// V4 `auth_basic` 已编译策略。
///
/// 数据面只读取 `Authorization` header 并做常量时间字节比较;用户名/密码不暴露为 public 字段。
#[derive(Clone)]
pub struct BasicAuthPolicy {
    /// 展示给客户端的 Basic realm。
    realm: String,
    /// 认证成功后的 consumer 标识；不含密码。
    consumer: Arc<str>,
    /// 构建期拼好的 `username:password` 字节串。
    expected: Vec<u8>,
}

/// V4 API-Key 已编译策略。
///
/// 数据面只读取一个 header 或 query 参数,并与构建期保存的 key 做常量时间比较。
#[derive(Clone)]
pub struct ApiKeyPolicy {
    /// API-Key 来源。
    source: ApiKeySource,
    /// 构建期保存的期望 key 字节串。
    expected: Vec<u8>,
    /// 可选稳定 consumer 名；绝不使用原始 API key 作为管理面标识。
    consumer: Option<Arc<str>>,
}

/// V4 HMAC-SHA256 已编译策略。
///
/// 基础版只签 method/path/query/timestamp/nonce/header,不读取请求体,避免破坏流式转发的低拷贝边界。
#[derive(Clone)]
pub struct HmacAuthPolicy {
    /// 共享密钥;V4 基础版仍来自 route 配置,SecretStore 热更后续补齐。
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
    /// 是否开启防重放(§20):开启后签名有效的请求还须 nonce 唯一(经 ReplayGuard `SET NX PX` 去重)。
    /// 需配 `nonce_header`;去重窗口 = `max_skew_ms`(超窗时间戳本就被拒,nonce 可遗忘)。
    replay_protection: bool,
}

/// V4 JWT HS256 已编译策略。
///
/// 基础版只读取 token header 并校验 HS256 + 常见 claims,不做 JWKS/OIDC 网络拉取。
#[derive(Clone)]
pub struct JwtAuthPolicy {
    /// HS256 共享密钥。
    secret: String,
    /// token 来源。
    source: JwtTokenSource,
    /// 可选 issuer 精确匹配。
    issuer: Option<String>,
    /// 可选 audience 匹配;payload aud 可为字符串或字符串数组。
    audience: Option<String>,
    /// `exp`/`nbf` 允许的时钟偏差,单位秒。
    leeway_secs: i64,
}

/// V4 ext_authz / nginx auth_request 基础版已编译策略。
///
/// 策略只构造一个无请求体的鉴权子请求;原始下游 body 继续留给主链路流式转发。
#[derive(Clone)]
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
    /// 允许从原始请求复制给鉴权服务的 header 名列表。
    pub request_headers: Vec<HeaderName>,
    /// 鉴权通过后允许从鉴权响应复制回主上游请求的 header 名列表。
    pub upstream_headers: Vec<HeaderName>,
}

/// API-Key 来源。
#[derive(Clone)]
enum ApiKeySource {
    /// 从请求头读取。
    Header(HeaderName),
    /// 从 query 参数读取。
    Query(String),
}

/// JWT token 来源。
#[derive(Clone)]
enum JwtTokenSource {
    /// 从 `Authorization: Bearer <token>` 读取。
    Bearer,
    /// 从指定 header 读取原始 token。
    Header(HeaderName),
}

/// V4 多认证策略组合方式。
#[derive(Clone, Copy)]
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

impl BasicAuthPolicy {
    /// 判断请求是否携带正确 Basic 凭据。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    fn matches(&self, parts: &Parts) -> bool {
        basic_authorization_matches(&parts.headers, self.expected.as_slice())
    }

    /// 生成 `WWW-Authenticate` 响应头值。
    fn challenge_value(&self) -> String {
        format!("Basic realm=\"{}\"", escape_header_quote(&self.realm))
    }
}

impl ApiKeyPolicy {
    /// 判断请求是否携带正确 API-Key。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
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
        value
            .map(|value| constant_time_eq(value.as_bytes(), self.expected.as_slice()))
            .unwrap_or(false)
    }
}

impl HmacAuthPolicy {
    /// 判断请求是否携带正确 HMAC-SHA256 签名。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    fn matches(&self, parts: &Parts) -> bool {
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
        let Some(canonical) = self.canonical_request(parts, timestamp, nonce) else {
            return false;
        };
        nasa::crypto::hmac_sha256_verify(&canonical, &self.secret, signature.trim())
    }

    /// 构造低拷贝 HMAC canonical string。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    /// - `timestamp`: 时间戳 header 原始文本。
    /// - `nonce`: 可选 nonce header 原始文本。
    fn canonical_request(
        &self,
        parts: &Parts,
        timestamp: &str,
        nonce: Option<&str>,
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
        Some(canonical)
    }

    /// 是否开启防重放(需已配 nonce_header)。
    fn replay_enabled(&self) -> bool {
        self.replay_protection && self.nonce_header.is_some()
    }

    /// 读取请求里的 nonce 值(仅当配置了 nonce_header)。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    fn nonce_value<'a>(&self, parts: &'a Parts) -> Option<&'a str> {
        let name = self.nonce_header.as_ref()?;
        header_str(parts, name)
    }

    /// 防重放去重的时间窗口(= 允许的时间戳偏差,超窗时间戳本就被拒)。
    fn replay_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.max_skew_ms.max(1))
    }
}

impl JwtAuthPolicy {
    /// 判断请求是否携带可接受的 JWT。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    fn matches(&self, parts: &Parts) -> bool {
        let Some(token) = self.token(parts) else {
            return false;
        };
        self.verify_token(token)
    }

    /// 从请求中提取 JWT token。
    ///
    /// # 参数
    /// - `parts`: 下游请求 head。
    fn token<'a>(&self, parts: &'a Parts) -> Option<&'a str> {
        match &self.source {
            JwtTokenSource::Bearer => bearer_token(parts),
            JwtTokenSource::Header(name) => header_str(parts, name).map(str::trim),
        }
    }

    /// 校验 JWT HS256 签名与基础 claims。
    ///
    /// # 参数
    /// - `token`: JWT compact serialization。
    fn verify_token(&self, token: &str) -> bool {
        self.verified_payload(token).is_some()
    }

    /// 验证 token 并返回 payload；仅长连接登记需读取 `sub`，普通鉴权仍只取 bool。
    fn verified_payload(&self, token: &str) -> Option<serde_json::Value> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        if header_b64.is_empty() || payload_b64.is_empty() || signature_b64.is_empty() {
            return None;
        }
        let header = decode_jwt_json(header_b64)?;
        if header.get("alg").and_then(|value| value.as_str()) != Some("HS256") {
            return None;
        }
        let signature = nasa::crypto::base64_url_decode(signature_b64).ok()?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature_hex = hex_lower_bytes(signature.as_slice());
        if !nasa::crypto::hmac_sha256_verify(&signing_input, &self.secret, &signature_hex) {
            return None;
        }
        let payload = decode_jwt_json(payload_b64)?;
        self.claims_match(&payload).then_some(payload)
    }

    /// 从签名、时效和 iss/aud 均有效的 JWT 中提取有界 `sub`。
    fn authenticated_subject(&self, parts: &Parts) -> Option<Arc<str>> {
        self.authenticated_claim(parts, "sub")
    }

    /// 提取任意已验证 claim(V8 edge 身份映射复用;校验规则与 `sub` 完全相同)。
    ///
    /// # 参数
    /// - `claim`: payload 字段名;只接受非空、≤256 字节、无控制字符的字符串值。
    fn authenticated_claim(&self, parts: &Parts, claim: &str) -> Option<Arc<str>> {
        let payload = self.verified_payload(self.token(parts)?)?;
        let value = payload.get(claim)?.as_str()?.trim();
        (!value.is_empty()
            && value.len() <= 256
            && !value.bytes().any(|byte| byte.is_ascii_control()))
        .then(|| Arc::from(value))
    }

    /// 校验 JWT payload claims。
    ///
    /// # 参数
    /// - `payload`: JWT payload JSON。
    fn claims_match(&self, payload: &serde_json::Value) -> bool {
        let Some(now) = unix_now_secs() else {
            return false;
        };
        if let Some(exp) = payload.get("exp").and_then(json_i64) {
            if now > exp.saturating_add(self.leeway_secs) {
                return false;
            }
        }
        if let Some(nbf) = payload.get("nbf").and_then(json_i64) {
            if now.saturating_add(self.leeway_secs) < nbf {
                return false;
            }
        }
        if let Some(issuer) = &self.issuer {
            if payload.get("iss").and_then(|value| value.as_str()) != Some(issuer.as_str()) {
                return false;
            }
        }
        if let Some(audience) = &self.audience {
            if !jwt_audience_matches(payload.get("aud"), audience) {
                return false;
            }
        }
        true
    }
}

/// nginx `if` 安全子集的固定返回规则。
///
/// 只支持变量模板之间的 `=` / `!=` 判断和 `return` 动作;不支持 rewrite 循环、正则脚本或子请求。
#[derive(Clone)]
pub struct ConditionalReturn {
    /// 左侧已编译取值模板。
    left: ValueTemplate,
    /// 条件比较操作。
    op: ConditionOp,
    /// 右侧已编译取值模板。
    right: ValueTemplate,
    /// 条件命中后的固定响应。
    response: DirectResponse,
}

/// `if` 安全子集支持的比较符。
#[derive(Clone, Copy)]
enum ConditionOp {
    /// 字符串相等。
    Eq,
    /// 字符串不相等。
    NotEq,
}

impl ConditionalReturn {
    /// 判断当前请求是否命中条件。
    ///
    /// # 参数
    /// - `ctx`: 当前请求变量上下文。
    /// - `variables`: route 使用的变量计划。
    fn matches(&self, ctx: &crate::variable::EvalContext<'_>, variables: &VariablePlan) -> bool {
        let left = self.left.render(ctx, variables);
        let right = self.right.render(ctx, variables);
        match self.op {
            ConditionOp::Eq => left == right,
            ConditionOp::NotEq => left != right,
        }
    }
}

/// IP 访问控制规则。
pub struct AccessRule {
    /// 命中后的允许/拒绝动作。
    pub action: AccessAction,
    /// IP 匹配器。保持私有,避免外部绕过构建期 CIDR 校验。
    matcher: AccessMatcher,
}

/// nginx `valid_referers` 的基础策略。
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
enum RefererHost {
    /// 精确 host。
    Exact(String),
    /// 后缀 host,对应 `*.example.com`。
    Suffix(String),
}

impl RefererPolicy {
    /// 判断请求 Referer 是否命中策略。
    ///
    /// # 参数
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
    /// 判断 host 是否命中当前模式。
    ///
    /// # 参数
    /// - `host`: 已规范化的小写 host。
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Suffix(suffix) => host.ends_with(suffix),
        }
    }
}

/// V3 `limit_req` 流控规则的已编译形态。数据面只求维度值并调用 `RateLimiter`,不再解析 DSL。
#[derive(Clone)]
pub struct LimitReqPolicy {
    /// 限流维度,如真实客户端 IP、指定请求头、query 参数或 route。
    pub key: LimitReqKey,
    /// 一个窗口内的稳定放行量,由 `rate=<N>r/s|r/m|r/h` 编译得到。
    pub limit: u64,
    /// 限流窗口,与 `limit` 共同表达补充速率。
    pub window: Duration,
    /// 额外突发容量,对齐 nginx `limit_req burst=` 的运维心智。
    pub burst: u64,
    /// 本规则允许同时存在的维度桶上限，防止轮换 IP/header/query 值打爆本地内存或 Redis key。
    pub max_active_keys: usize,
    /// 达到维度上限时是否 fail-open；false 表示 fail-closed 返回 429。
    pub active_keys_fail_open: bool,
}

/// V3 `limit_conn` 并发限制规则。释放绑定响应 body 生命周期,避免流式响应提前归还名额。
#[derive(Clone)]
pub struct LimitConnPolicy {
    /// 并发维度,与 `limit_req` 共用低成本维度集合。
    pub key: LimitReqKey,
    /// 同一维度允许同时占用的请求/长连接数量。
    pub limit: u64,
}

/// V3 nginx `limit_rate` 响应带宽限制。只包响应 body,不缓冲完整响应。
#[derive(Clone, Copy)]
pub struct LimitRatePolicy {
    /// 限速字节/秒。
    pub bytes_per_second: u64,
    /// 前 N 字节不限速,对齐 nginx `limit_rate_after`。
    pub after_bytes: u64,
}

/// V3 Sentinel 熔断规则。V3 起步按 route 资源统计 5xx/网关错误,Open 时直接走 fallback。
#[derive(Clone)]
pub struct CircuitBreakerPolicy {
    /// 规则 id,用于状态 key 与日志定位。
    pub id: String,
    /// 滑动窗口内失败次数达到该阈值后打开熔断。
    pub failure_threshold: u64,
    /// 统计窗口。
    pub window: Duration,
    /// 窗口内至少有多少请求才允许打开熔断,避免低流量偶发错误过敏。
    pub min_requests: u64,
    /// Open 持续时长;到期进入 Half-Open,放一个探测请求。
    pub break_duration: Duration,
    /// 熔断打开时返回的状态码。
    pub fallback_status: StatusCode,
    /// 熔断打开时返回的短文本 body。
    pub fallback_body: String,
}

/// V3/V4 nginx `error_page` 形态:状态码集合 -> 固定响应或内部 reroute。
#[derive(Clone)]
pub struct ErrorPagePolicy {
    /// 触发映射的源状态码集合。
    pub statuses: Vec<StatusCode>,
    /// 命中后的动作。
    pub action: ErrorPageAction,
}

/// error_page 命中后的动作。
#[derive(Clone)]
pub enum ErrorPageAction {
    /// 固定响应。
    Response(DirectResponse),
    /// 内部重路由目标 path。
    Reroute(String),
}

impl ErrorPagePolicy {
    /// 当前 error_page 规则是否执行内部重路由。
    pub fn is_reroute(&self) -> bool {
        matches!(self.action, ErrorPageAction::Reroute(_))
    }
}

/// `limit_req` 支持的低成本维度。`HeaderName` 在构建期校验,运行期零解析。
#[derive(Clone)]
pub enum LimitReqKey {
    /// 所有请求共享同一桶,用于全局保护后端。
    Global,
    /// 按 §12 计算出的真实客户端 IP 分桶。
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

enum AccessMatcher {
    All,
    Cidr(Cidr),
}

impl AccessRule {
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
    PassRequestHeaders(bool),
    PassRequestBody(bool),
    AddHeader(ResponseHeaderSet),
    HideHeader(HeaderName),
    ProxyRedirect(ProxyRedirectRule),
    CookieRewrite(CookieRewriteRule),
    DedupeHeader(DedupeResponseHeader),
    SubFilter(SubFilterRule),
    Compression(Option<CompressionPolicy>),
    ProxyCache(Option<Arc<HttpCachePolicy>>),
    ProxyCachePurge(Vec<String>),
    Cors(CorsPolicy),
    FallbackHeaders,
    Access(AccessRule),
    ValidReferers(RefererPolicy),
    LimitExcept(Vec<Method>),
    BasicAuth(Option<BasicAuthPolicy>),
    ApiKey(ApiKeyPolicy),
    HmacAuth(HmacAuthPolicy),
    JwtAuth(JwtAuthPolicy),
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
    Mirror(MirrorPolicy),
}

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
    if trimmed.starts_with("add_header ") {
        let op = parse_response_header_set(trimmed, "add_header", variables)?;
        return Ok(ParsedFilter::AddHeader(op));
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
    if starts_filter(trimmed, "mirror") {
        return parse_mirror(trimmed).map(ParsedFilter::Mirror);
    }
    bail!("unsupported filter `{trimmed}`");
}

/// 解析 nginx `on|off` 风格开关指令。
///
/// # 参数
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

fn predicates_signature(predicates: &[Predicate]) -> String {
    let mut parts = predicates
        .iter()
        .map(Predicate::signature)
        .collect::<Vec<_>>();
    parts.sort_unstable();
    parts.join("|")
}

/// 编译并交叉校验所有 Weight 路由。
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
                Predicate::Weight { group, weight } => Some((group.as_str(), *weight)),
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

fn route_weight(route: &Route) -> Option<(&str, u32)> {
    route
        .predicates
        .iter()
        .find_map(|predicate| match predicate {
            Predicate::Weight { group, weight } => Some((group.as_str(), *weight)),
            _ => None,
        })
}

fn non_weight_predicates_signature(predicates: &[Predicate]) -> String {
    let mut parts = predicates
        .iter()
        .filter(|predicate| !matches!(predicate, Predicate::Weight { .. }))
        .map(Predicate::signature)
        .collect::<Vec<_>>();
    parts.sort_unstable();
    parts.join("|")
}

/// FNV-1a 足以做非安全流量分桶：输入是网关生成的 request-id，不承担认证或签名职责。
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
    Ok(RequestHeaderSet { name, value })
}

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
    let value = variables.compile_template(value.trim())?;
    if let Some(literal) = value.static_literal() {
        http::HeaderValue::from_str(literal)
            .with_context(|| format!("{cmd} invalid header value `{literal}`"))?;
    }
    Ok(ResponseHeaderSet { name, value })
}

/// 解析 nginx `mirror` 基础规则。
///
/// # 参数
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

/// 解析 nginx `proxy_redirect` 规则。
///
/// # 参数
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

/// 解析 nginx `proxy_cookie_domain` / `proxy_cookie_path` 规则。
///
/// # 参数
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

/// 校验 cookie 属性改写值。
///
/// # 参数
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

/// 解析 nginx `proxy_cookie_flags` 规则。
///
/// # 参数
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

/// 校验 `proxy_cookie_flags` 的 cookie 匹配名。
///
/// # 参数
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
    // ★重定向的 value 会在运行时作为 Location 响应头,必须在【构建期】校验为合法 header 值,
    //   否则 direct_response 的 `.expect()` 会在该请求上 panic(据 review F2:非 ASCII/控制字符 Location)。
    if status.is_redirection() {
        if let Some(v) = &value {
            http::HeaderValue::from_str(v).with_context(|| {
                format!("invalid `return {status_u16}` redirect location `{v}`")
            })?;
        }
    }
    Ok(DirectResponse { status, value })
}

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

/// 解析 nginx `sub_filter` 基础规则。
///
/// # 参数
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

/// 解析 V5 route 级响应压缩配置。
///
/// 支持统一形式
/// `compression algorithms=br,gzip min_length=1k types=text/*,application/json
/// gzip_level=6 brotli_quality=5 chunk_bytes=16k`，并接受 nginx 心智兼容别名
/// `gzip on ...` / `brotli on ...`。同一 route 只能声明一次，避免多个指令的覆盖顺序含糊。
///
/// # 参数
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

/// 解析服务端允许的内容编码列表并保留配置顺序。
///
/// # 参数
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

/// 生成缺省可压缩 MIME 集合。
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

/// 解析逗号分隔的 MIME 匹配列表。
///
/// # 参数
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

/// 编译单个 MIME 匹配项。
///
/// # 参数
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

/// 解析 V5 公共 HTTP L1/L2 响应缓存策略。
///
/// # 参数
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

/// 解析写路由的 cache generation 失效目标。
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

fn parse_fallback_headers(spec: &str) -> Result<()> {
    let rest = filter_args(spec, "FallbackHeaders");
    match rest {
        "" | "on" | "true" | "default" => Ok(()),
        other => bail!("unsupported FallbackHeaders policy `{other}` (supported: default/on)"),
    }
}

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

/// 解析 nginx `valid_referers` 基础规则。
///
/// # 参数
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

/// 解析 Referer host 模式。
///
/// # 参数
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

/// 从 Referer URL 中提取小写 host。
///
/// # 参数
/// - `raw`: Referer header 原始值。
fn referer_host(raw: &str) -> Option<String> {
    let uri = raw.parse::<http::Uri>().ok()?;
    let host = uri.host()?;
    normalize_host(host)
}

/// 判断 Referer 是否属于 nginx `blocked` 语义。
///
/// # 参数
/// - `raw`: Referer header 原始值。
fn is_blocked_referer(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    !lower.starts_with("http://") && !lower.starts_with("https://")
}

/// 提取当前请求 Host,用于 `valid_referers server_names`。
///
/// # 参数
/// - `parts`: 下游请求 head。
fn request_host(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_host)
}

/// 规范化 host:去端口、去尾点、小写。
///
/// # 参数
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

/// 解析 nginx `limit_except` 基础规则。
///
/// # 参数
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

/// 解析 V4 `auth_basic` 基础规则。
///
/// # 参数
/// - `spec`: route filter 原始字符串,如 `auth_basic user=admin password=secret realm=ops`。
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
    let mut realm = "nate".to_string();
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
    let password = crate::secret::resolve_text(&password, config_dir, "auth_basic password")?;
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

/// 解析 V4 `api_key` 基础规则。
///
/// # 参数
/// - `spec`: route filter 原始字符串,如 `api_key header=X-Api-Key value=secret`。
fn parse_api_key(spec: &str, config_dir: &Path) -> Result<ApiKeyPolicy> {
    let rest = filter_args(spec, "api_key").trim();
    if rest.is_empty() {
        bail!("api_key requires `header=<name>|query=<name> value=<secret>`");
    }
    let mut source = None;
    let mut value = None;
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
            "consumer" => consumer = Some(raw_value.to_string()),
            other => bail!("api_key unsupported option `{other}`"),
        }
    }
    let source = source.context("api_key requires header or query source")?;
    let value = value.context("api_key requires value")?;
    let value = crate::secret::resolve_text(&value, config_dir, "api_key value")?;
    validate_basic_auth_secret("api_key value", &value)?;
    if let Some(consumer) = &consumer {
        validate_basic_auth_user(consumer)?;
    }
    Ok(ApiKeyPolicy {
        source,
        expected: value.into_bytes(),
        consumer: consumer.map(Arc::from),
    })
}

/// 解析 V4 HMAC-SHA256 签名规则。
///
/// # 参数
/// - `spec`: route filter 原始字符串,如 `hmac_auth secret=s signature_header=X-Signature`。
/// - `cmd`: 实际命中的指令名。
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
                    bail!("{cmd} only supports HMAC-SHA256 in V4 basic mode");
                }
            }
            "body" | "include_body" => {
                if parse_bool(raw_value)? {
                    bail!(
                        "{cmd} body signing is not supported in V4 basic mode; use header/path/query signing to keep the data plane streaming"
                    );
                }
            }
            "replay" | "replay_protection" | "anti_replay" => {
                replay_protection = parse_bool(raw_value)?;
            }
            other => bail!("{cmd} unsupported option `{other}`"),
        }
    }
    let secret = secret.with_context(|| format!("{cmd} requires secret"))?;
    let secret = crate::secret::resolve_text(&secret, config_dir, "hmac secret")?;
    validate_basic_auth_secret("hmac secret", &secret)?;
    // 防重放依赖 nonce 去重:开启但没配 nonce_header 无从去重,构建期拒绝,防上线后静默失效。
    if replay_protection && nonce_header.is_none() {
        bail!("{cmd} replay=on requires nonce_header to dedup one-time nonces");
    }
    Ok(HmacAuthPolicy {
        secret,
        signature_header,
        timestamp_header,
        nonce_header,
        signed_headers,
        max_skew_ms,
        replay_protection,
    })
}

/// 解析 HMAC 使用的请求头名。
///
/// # 参数
/// - `raw`: 配置中的 header 名。
/// - `field`: 字段名,用于错误上下文。
fn parse_hmac_header_name(raw: &str, field: &str) -> Result<HeaderName> {
    raw.parse::<HeaderName>()
        .with_context(|| format!("hmac_auth invalid {field} `{raw}`"))
}

/// 解析参与 HMAC 签名的额外请求头列表。
///
/// # 参数
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

/// 解析 V4 JWT HS256 鉴权规则。
///
/// # 参数
/// - `spec`: route filter 原始字符串,如 `jwt_auth secret=s issuer=gw audience=api`。
/// - `cmd`: 实际命中的指令名。
fn parse_jwt_auth(spec: &str, cmd: &str, config_dir: &Path) -> Result<JwtAuthPolicy> {
    let rest = filter_args(spec, cmd).trim();
    if rest.is_empty() {
        bail!("{cmd} requires `secret=<hs256-secret>`");
    }
    let mut secret = None;
    let mut source = JwtTokenSource::Bearer;
    let mut issuer = None;
    let mut audience = None;
    let mut leeway_secs = DEFAULT_JWT_LEEWAY_SECS;
    for token in rest.split_whitespace() {
        let (key, raw_value) = token
            .split_once('=')
            .with_context(|| format!("{cmd} option `{token}` must be key=value"))?;
        let raw_value = unquote_token(raw_value.trim());
        match key {
            "secret" | "key" | "hs256_secret" => secret = Some(raw_value.to_string()),
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
            "leeway_secs" | "clock_skew_secs" => {
                leeway_secs = raw_value
                    .parse::<i64>()
                    .with_context(|| format!("{cmd} invalid leeway_secs `{raw_value}`"))?;
                if !(0..=MAX_JWT_LEEWAY_SECS).contains(&leeway_secs) {
                    bail!("{cmd} leeway_secs must be in 0..={MAX_JWT_LEEWAY_SECS}");
                }
            }
            "algorithm" | "alg" => {
                if !raw_value.eq_ignore_ascii_case("HS256") {
                    bail!("{cmd} only supports HS256 in V4 basic mode");
                }
            }
            other => bail!("{cmd} unsupported option `{other}`"),
        }
    }
    let secret = secret.with_context(|| format!("{cmd} requires secret"))?;
    let secret = crate::secret::resolve_text(&secret, config_dir, "jwt secret")?;
    validate_basic_auth_secret("jwt secret", &secret)?;
    if issuer.as_deref() == Some("") || audience.as_deref() == Some("") {
        bail!("{cmd} issuer/audience must not be empty");
    }
    Ok(JwtAuthPolicy {
        secret,
        source,
        issuer,
        audience,
        leeway_secs,
    })
}

/// 解析 V4 ext_authz / nginx auth_request 基础规则。
///
/// # 参数
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
                "headers" | "request_headers" | "allow_headers" => {
                    request_headers = parse_ext_authz_header_list(raw_value, "request_headers")?;
                }
                "upstream_headers" | "response_headers" | "copy_headers" => {
                    upstream_headers = parse_ext_authz_header_list(raw_value, "upstream_headers")?;
                }
                "body" | "send_body" => {
                    if parse_bool(raw_value)? {
                        bail!(
                            "{cmd} body forwarding is not supported in V4 basic mode; use body=off"
                        );
                    }
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
    Ok(ExtAuthzPolicy {
        target,
        path,
        method,
        timeout_ms,
        fail_open,
        request_headers,
        upstream_headers,
    })
}

/// 校验 ext_authz 目标 URI。
///
/// # 参数
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

/// 解析 ext_authz 子请求方法。
///
/// # 参数
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

/// 解析 ext_authz path,允许携带 query。
///
/// # 参数
/// - `raw`: path 或 path?query。
fn parse_ext_authz_path(raw: &str) -> Result<String> {
    if raw.is_empty() || !raw.starts_with('/') || raw.bytes().any(|b| b <= 0x20) {
        bail!("ext_authz path must start with `/` and contain no spaces/control chars");
    }
    raw.parse::<http::Uri>()
        .with_context(|| format!("ext_authz invalid path `{raw}`"))?;
    Ok(raw.to_string())
}

/// 解析 ext_authz header allowlist。
///
/// # 参数
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

/// 判断 header 是否允许进入 ext_authz allowlist。
///
/// # 参数
/// - `name`: 已解析 header 名。
fn ext_authz_header_is_safe(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
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
    )
}

/// 取请求头的 UTF-8 文本值。
///
/// # 参数
/// - `parts`: 下游请求 head。
/// - `name`: 请求头名。
fn header_str<'a>(parts: &'a Parts, name: &HeaderName) -> Option<&'a str> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// 从 `Authorization: Bearer` 中提取 token。
///
/// # 参数
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

/// 解码 JWT base64url JSON 段。
///
/// # 参数
/// - `encoded`: JWT header 或 payload 的 base64url 段。
fn decode_jwt_json(encoded: &str) -> Option<serde_json::Value> {
    let bytes = nasa::crypto::base64_url_decode(encoded).ok()?;
    serde_json::from_slice(bytes.as_slice()).ok()
}

/// 把字节串转为小写 hex。
///
/// # 参数
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

/// 取当前 Unix 秒。
fn unix_now_secs() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
}

/// 从 JSON number 读取 i64。
///
/// # 参数
/// - `value`: JSON claim 值。
fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
}

/// 判断 JWT audience 是否匹配期望值。
///
/// # 参数
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

/// 判断 HMAC 时间戳是否处于允许偏差内。
///
/// # 参数
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

/// 解析 HMAC 时间戳为 Unix 毫秒。
///
/// # 参数
/// - `raw`: Unix 秒或毫秒时间戳文本。
fn parse_hmac_timestamp_ms(raw: &str) -> Option<i128> {
    let value = raw.trim().parse::<i128>().ok()?;
    if value >= HMAC_UNIX_SECONDS_THRESHOLD {
        Some(value)
    } else {
        value.checked_mul(1000)
    }
}

/// 解析 nginx `satisfy any|all` 的数据面鉴权子集。
///
/// # 参数
/// - `spec`: route filter 原始字符串。
fn parse_satisfy(spec: &str) -> Result<SatisfyMode> {
    match filter_args(spec, "satisfy").trim() {
        "all" => Ok(SatisfyMode::All),
        "any" => Ok(SatisfyMode::Any),
        other => bail!("satisfy expects any|all, got `{other}`"),
    }
}

/// 校验 Basic 用户名。
///
/// # 参数
/// - `user`: 配置中的用户名。
fn validate_basic_auth_user(user: &str) -> Result<()> {
    if user.is_empty() || user.bytes().any(|b| b == b':' || b < 0x20) {
        bail!("auth_basic invalid user");
    }
    Ok(())
}

/// 校验 Basic 密码或 realm。
///
/// # 参数
/// - `field`: 字段名,用于错误上下文。
/// - `value`: 待校验文本。
fn validate_basic_auth_secret(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.bytes().any(|b| b < 0x20) {
        bail!("auth_basic invalid {field}");
    }
    Ok(())
}

/// 校验 API-Key query 参数名。
///
/// # 参数
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

/// 解析 nginx `if` 的安全子集。
///
/// # 参数
/// - `spec`: route filter 原始字符串,如 `if ${header.X-Mode} = block return 451 blocked`。
/// - `variables`: 当前快照变量计划,用于构建期编译左右模板。
fn parse_if_return(spec: &str, variables: &VariablePlan) -> Result<ConditionalReturn> {
    let rest = filter_args(spec, "if");
    let tokens = rest.split_whitespace().collect::<Vec<_>>();
    if tokens.len() < 5 {
        bail!("if requires `<left> (=|!=) <right> return <status> [body]`");
    }
    let left = variables.compile_template(unquote_token(tokens[0]))?;
    let op = match tokens[1] {
        "=" | "==" => ConditionOp::Eq,
        "!=" => ConditionOp::NotEq,
        other => bail!("if unsupported operator `{other}` (=|!= only)"),
    };
    let right = variables.compile_template(unquote_token(tokens[2]))?;
    if tokens[3] != "return" {
        bail!("if only supports `return` action in V3 basic mode");
    }
    let status = parse_status_code(tokens[4], "if return status")?;
    let value = if tokens.len() > 5 {
        Some(unquote_token(&tokens[5..].join(" ")).to_string())
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
        left,
        op,
        right,
        response: DirectResponse { status, value },
    })
}

/// 去掉单个 token 外层的成对引号,方便表达空串或含特殊字符的静态值。
///
/// # 参数
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

/// 从原始 query 中读取未解码参数值。
///
/// # 参数
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

fn parse_limit_req(spec: &str) -> Result<LimitReqPolicy> {
    let rest = filter_args(spec, "limit_req");
    if rest.is_empty() {
        bail!("limit_req requires `key=<dimension> rate=<N>r/s`");
    }
    let mut key = None;
    let mut rate = None;
    let mut burst = 0_u64;
    let mut max_active_keys = DEFAULT_LIMIT_REQ_MAX_ACTIVE_KEYS;
    let mut active_keys_fail_open = true;
    for token in rest.split_whitespace() {
        if token == "nodelay" {
            continue;
        }
        let (name, value) = token
            .split_once('=')
            .with_context(|| format!("limit_req option `{token}` must be key=value"))?;
        match name {
            "key" | "dimension" | "by" => key = Some(parse_limit_key(value)?),
            "rate" | "qps" => rate = Some(parse_limit_req_rate(value)?),
            "burst" => {
                burst = value
                    .parse::<u64>()
                    .with_context(|| format!("limit_req invalid burst `{value}`"))?;
            }
            "max_active_keys" => {
                max_active_keys = value
                    .parse::<usize>()
                    .with_context(|| format!("limit_req invalid max_active_keys `{value}`"))?;
                if max_active_keys == 0 {
                    bail!("limit_req max_active_keys must be positive");
                }
            }
            "active_keys_fail" | "key_overflow" => match value {
                "open" | "allow" => active_keys_fail_open = true,
                "closed" | "close" | "reject" => active_keys_fail_open = false,
                _ => bail!("limit_req active_keys_fail expects open|closed, got `{value}`"),
            },
            other => bail!("unsupported limit_req option `{other}`"),
        }
    }
    let (limit, window) = rate.context("limit_req requires `rate=<N>r/s`")?;
    if limit == 0 {
        bail!("limit_req rate must be positive");
    }
    Ok(LimitReqPolicy {
        key: key.unwrap_or(LimitReqKey::Ip),
        limit,
        window,
        burst,
        max_active_keys,
        active_keys_fail_open,
    })
}

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

/// 解析 nginx `limit_rate` / `LimitRate` 响应限速规则。
///
/// # 参数
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

fn parse_circuit_breaker(spec: &str) -> Result<CircuitBreakerPolicy> {
    let rest = filter_args(spec, "circuit_breaker");
    if rest.is_empty() {
        bail!("circuit_breaker requires `id=<id> failure_threshold=<N>`");
    }
    let mut id = None;
    let mut failure_threshold = None;
    let mut window_ms = 10_000_u64;
    let mut min_requests = 1_u64;
    let mut break_ms = 30_000_u64;
    let mut fallback_status = StatusCode::SERVICE_UNAVAILABLE;
    let mut fallback_body = "circuit open".to_string();
    for token in rest.split_whitespace() {
        let (name, value) = token
            .split_once('=')
            .with_context(|| format!("circuit_breaker option `{token}` must be key=value"))?;
        match name {
            "id" => {
                if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                    bail!(
                        "circuit_breaker id `{value}` must be non-empty and contain no whitespace"
                    );
                }
                id = Some(value.to_string());
            }
            "failure_threshold" | "failures" | "threshold" => {
                failure_threshold = Some(value.parse::<u64>().with_context(|| {
                    format!("circuit_breaker invalid failure_threshold `{value}`")
                })?);
            }
            "window_ms" => {
                window_ms = value
                    .parse::<u64>()
                    .with_context(|| format!("circuit_breaker invalid window_ms `{value}`"))?;
            }
            "min_requests" => {
                min_requests = value
                    .parse::<u64>()
                    .with_context(|| format!("circuit_breaker invalid min_requests `{value}`"))?;
            }
            "break_ms" | "open_ms" => {
                break_ms = value
                    .parse::<u64>()
                    .with_context(|| format!("circuit_breaker invalid break_ms `{value}`"))?;
            }
            "fallback_status" | "status" => {
                let code = value.parse::<u16>().with_context(|| {
                    format!("circuit_breaker invalid fallback_status `{value}`")
                })?;
                fallback_status = StatusCode::from_u16(code)
                    .with_context(|| format!("circuit_breaker invalid fallback_status `{code}`"))?;
            }
            "fallback_body" | "body" => {
                fallback_body = value.replace('_', " ");
            }
            other => bail!("unsupported circuit_breaker option `{other}`"),
        }
    }
    let failure_threshold =
        failure_threshold.context("circuit_breaker requires `failure_threshold=<N>`")?;
    if failure_threshold == 0 {
        bail!("circuit_breaker failure_threshold must be positive");
    }
    if !(1..=MAX_LONG_STREAM_DURATION_MS).contains(&window_ms)
        || !(1..=MAX_LONG_STREAM_DURATION_MS).contains(&break_ms)
        || min_requests == 0
    {
        bail!(
            "circuit_breaker window_ms/break_ms must be within 1..={MAX_LONG_STREAM_DURATION_MS} and min_requests must be positive"
        );
    }
    Ok(CircuitBreakerPolicy {
        id: id.unwrap_or_else(|| "default".to_string()),
        failure_threshold,
        window: Duration::from_millis(window_ms),
        min_requests,
        break_duration: Duration::from_millis(break_ms),
        fallback_status,
        fallback_body,
    })
}

/// 解析 `error_page` 响应映射。
///
/// # 参数
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

/// 校验内部重路由目标。
///
/// # 参数
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

/// 解析逗号分隔的 HTTP 状态码列表。
///
/// # 参数
/// - `raw`: 逗号分隔状态码。
/// - `label`: 错误上下文标签。
fn parse_status_list(raw: &str, label: &str) -> Result<Vec<StatusCode>> {
    raw.split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| parse_status_code(item.trim(), label))
        .collect()
}

/// 解析单个 HTTP 状态码。
///
/// # 参数
/// - `raw`: 状态码文本。
/// - `label`: 错误上下文标签。
fn parse_status_code(raw: &str, label: &str) -> Result<StatusCode> {
    let status = raw
        .parse::<u16>()
        .with_context(|| format!("{label} invalid status `{raw}`"))?;
    StatusCode::from_u16(status).with_context(|| format!("{label} invalid status `{status}`"))
}

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

/// 解析字节大小,支持 `k/m/g` 后缀。
///
/// # 参数
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

fn parse_cors(spec: &str) -> Result<CorsPolicy> {
    let mut policy = CorsPolicy {
        allow_origin: CorsAllowOrigin::Any,
        allow_methods: "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD".to_string(),
        allow_headers: "*".to_string(),
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
                policy.allow_methods = value.to_string();
            }
            "allow_headers" | "headers" => {
                validate_header_value("Cors allow_headers", value)?;
                policy.allow_headers = value.to_string();
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

fn filter_args<'a>(spec: &'a str, name: &str) -> &'a str {
    let rest = spec
        .strip_prefix(name)
        .or_else(|| spec.strip_prefix(&name.to_ascii_lowercase()))
        .unwrap_or_default()
        .trim_start();
    rest.strip_prefix('=').unwrap_or(rest).trim()
}

fn validate_header_value(label: &str, value: &str) -> Result<()> {
    HeaderValue::from_str(value)
        .with_context(|| format!("{label} invalid header value `{value}`"))?;
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" | "on" | "1" | "yes" => Ok(true),
        "false" | "off" | "0" | "no" => Ok(false),
        other => bail!("expected boolean, got `{other}`"),
    }
}

fn parse_rewrite_prefix(spec: &str) -> Result<RewritePrefix> {
    let rest = spec.trim_start_matches("rewrite ").trim();
    let (from, to) = rest
        .split_once(char::is_whitespace)
        .with_context(|| "rewrite requires `from to`")?;
    let from = from.trim();
    if contains_regex_meta(from) {
        bail!(
            "rewrite regex is disabled in V2; use a plain prefix or PathGlob/PathExact predicates"
        );
    }
    Ok(RewritePrefix {
        from: from.to_string(),
        to: to.trim().to_string(),
    })
}

fn contains_regex_meta(value: &str) -> bool {
    value.as_bytes().iter().any(|b| {
        matches!(
            b,
            b'^' | b'$' | b'(' | b')' | b'[' | b']' | b'+' | b'{' | b'}' | b'|' | b'*' | b'?'
        )
    })
}

/// 去掉 path 前 n 段:`/api/order/1` strip 2 → `/1`;段数不足则回退到 `/`。
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

#[path = "../../tests/unit/routing_mod.rs"]
#[cfg(test)]
mod tests;
