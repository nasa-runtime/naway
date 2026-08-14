//! 反向代理数据面。
//!
//! 一次请求入口 `load()` 一份配置快照(整条管线共用同一版本 → 无感语义),
//! 顺序 = 接口守卫(短路)→ 路由 → 流式转发上游(`forward` 子模块)。

pub(crate) mod forward;
mod grpc_browser;
#[cfg(feature = "http3")]
mod http3_upstream;
pub(crate) mod request_validation;
pub(crate) mod response_contract;

// V8 回执字段号别名:对外 wire 契约的一部分,禁止在调用点写裸数字
// (见 `edge_hub::summary_field` 与 proto/naway/edge/v1/edge.proto)。
#[cfg(feature = "grpc-edge")]
use crate::edge_hub::summary_field as field;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use arc_swap::{ArcSwap, ArcSwapOption};
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt as FuturesStreamExt};
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
};
use http::request::Parts;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::{Mutex, RwLock as ParkingRwLock};
use sha2::{Digest, Sha256};

use crate::access_log::{AccessLogger, AccessMethod, AccessPath, AccessRecord};
use crate::blacklist::BlacklistCache;
use crate::bot::BotDecision;
use crate::casbin_auth::{CasbinDecision, CasbinInputError};
use crate::compression::{apply_response_compression, AcceptedEncodings};
use crate::config::{GatewayListenerRuntime, GatewaySnapshot};
use crate::conn_registry::{CloseNotified, ConnGuard, ConnectionRegistry, LongProto};
use crate::dlp::{DlpBodyOutcome, DlpHeadOutcome};
#[cfg(feature = "ext-proc")]
use crate::ext_proc::{ExtProcAction, ExtProcError, ExtProcPhase, SharedExtProcSession};
use crate::graphql::{GraphqlGuardResult, GraphqlOutcome};
use crate::guard::DynamicInterfaceGuardCache;
use crate::http_cache::{
    CacheLookup, CacheMiss, HttpCacheFill, HttpCacheHit, SwappableHttpCacheRuntime,
};
use crate::metrics::{
    CasbinDecisionMetric, DegraphqlMetric, DlpMetric, DubboMetric, ExternalPluginMetric,
    LlmModerationMetric, Metrics, OpaCacheMetric, OpaDecisionMetric, OpaRequestMetric,
    UsagePlanMetric, WafMetric, WasmExecutionMetric,
};
use crate::opa::{OpaDecision, OpaFlightRole, OpaInputError, OpaObligations, OpaRequestContext};
use crate::proxy::request_validation::ValidationOutcome;
use crate::proxy_protocol::ConnInfo;
use crate::routing::{
    CircuitBreakerPolicy, CorsPolicy, DedupeMode, DedupeResponseHeader, DirectResponse,
    ErrorPageAction, ErrorPagePolicy, LimitRatePolicy, LimitReqKey, MockResponsePolicy,
    ResponseHeaderOp, Route, SatisfyMode, SubFilterRule,
};
use crate::runtime_state::{
    CircuitStats, ConnLimiter, DynamicStore, RateLimitRequest, RateLimitReservation, RateLimiter,
    ReplayGuard, SwappableDynamicStore,
};
use crate::upstream::{PassiveHealthPolicy, UpstreamProtocol};
use crate::variable::EvalContext;
use crate::waf::WafBodyOutcome;
use crate::{full_body, text_status, BoxBody};
use tokio::time::Sleep;

const MAX_INTERNAL_REROUTES: usize = 3;
const GATEWAY_LISTENER_HEADER: HeaderName = HeaderName::from_static("x-naway-gateway-listener");
const MESH_SOURCE_NAMESPACE_HEADER: HeaderName =
    HeaderName::from_static("x-naway-mesh-source-namespace");
const LIMIT_CONN_TTL: Duration = Duration::from_secs(120);
const LIMIT_CONN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// auto-ban 计数表的硬上限。到达上限时先清理过期项；若仍满，则不再为新 IP 分配状态。
/// 内部内存安全阈值(非流控行为),故不进 yml(§15.9)。取值远大于常态活跃 IP 数,正常流量永不触发。
const AUTO_BAN_COUNTS_MAX_ENTRIES: usize = 100_000;
/// 与既有 nasa Snowflake 合同一致的业务纪元（2024-01-01T00:00:00Z）。
const REQUEST_ID_BASE_TIME_MS: u64 = 1_704_038_400_000;
const REQUEST_ID_WORKER_BITS: u32 = 6;
const REQUEST_ID_SEQUENCE_BITS: u32 = 6;
const REQUEST_ID_MAX_SEQUENCE: u64 = (1 << REQUEST_ID_SEQUENCE_BITS) - 1;

/// 下游连接固定客户端地址的预编码 HTTP header。
///
/// PROXY protocol 的 `real_peer` 和普通 TCP 的 socket peer 在连接建立后不会变化，因此可把
/// `HeaderValue` 的解析/owned buffer 构造摊薄到每连接一次。受信任 HTTP 代理仍可能在同一 H2
/// 连接的不同 stream 上发送不同 XFF；请求入口会再次比较最终权威 `client_ip`，只有相等才复用。
/// clone 仅共享 HeaderValue 的不可变字节，不复制 IP 文本，也不触碰 request/body frame。
#[derive(Clone)]
pub struct ConnectionClientIpHeader {
    ip: IpAddr,
    value: HeaderValue,
}

impl ConnectionClientIpHeader {
    /// 从已完成 PROXY protocol 校验的连接信息构造缓存。
    pub fn new(conn: &ConnInfo) -> Self {
        let ip = conn.real_peer.ip();
        // 本构造器每条 downstream connection 只执行一次；IpAddr Display 只可能产生合法的
        // ASCII header value。这里保留安全检查，不使用 unchecked HeaderValue 构造。
        let text = ip.to_string();
        let value = HeaderValue::from_bytes(text.as_bytes())
            .expect("IpAddr display must be a valid HTTP header value");
        Self { ip, value }
    }

    #[inline]
    fn into_value_for(self, client_ip: IpAddr) -> Option<HeaderValue> {
        (self.ip == client_ip).then_some(self.value)
    }
}

/// 固定 16 字节的小写十六进制请求 ID。
///
/// ID 在栈上从 Snowflake `u64` 直接编码；默认关闭 access log 时整条请求路径无需先分配一个
/// `String`。只有异步 SWR 或真正写 access log 时才按其所有权要求复制为 `String`。所有转发、
/// 路由哈希和 header 构造都只借用这 16 字节；上游 body 不受影响。
#[derive(Clone, Copy)]
struct RequestId([u8; 16]);

/// 本地认证完成后、任何外部授权响应头注入前冻结的请求身份。
#[derive(Default)]
struct AuthorizationIdentity {
    authenticated: bool,
    consumer: Option<Arc<str>>,
    jwt_claims: Option<serde_json::Value>,
}

impl RequestId {
    #[inline]
    fn from_u64(mut value: u64) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [b'0'; 16];
        for byte in encoded.iter_mut().rev() {
            *byte = HEX[(value & 0x0f) as usize];
            value >>= 4;
        }
        Self(encoded)
    }

    #[inline]
    fn as_str(&self) -> &str {
        // SAFETY:from_u64 只从固定 ASCII HEX 表写满全部 16 字节，始终是合法 UTF-8。
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl Deref for RequestId {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// 无锁 Snowflake 请求 ID 生成器。
///
/// 原实现每个请求都进入 `nasa::base::Snowflake` 的全局 `std::sync::Mutex`，把所有 Tokio
/// worker 串行在一个极短临界区。这里把 `(logical_millis, sequence)` 压进单个 `AtomicU64`：
/// 一次 CAS 同时保证唯一性与单调性；同毫秒超过 64 个请求时推进逻辑毫秒，不阻塞、不睡眠。
/// worker 位仍由进程 pid 派生，最终 64-bit 布局与原 6-bit worker/6-bit sequence 合同一致。
struct RequestIdGenerator {
    /// 高位 logical millis，低 6 位 sequence；只承担发号，不发布其他内存。
    state: AtomicU64,
    shifted_worker_id: u64,
}

impl RequestIdGenerator {
    fn new(worker_id: u64) -> Self {
        debug_assert!(worker_id < (1 << REQUEST_ID_WORKER_BITS));
        Self {
            state: AtomicU64::new(0),
            shifted_worker_id: worker_id << REQUEST_ID_SEQUENCE_BITS,
        }
    }

    #[inline]
    fn generate(&self) -> u64 {
        let wall_millis = request_id_logical_millis();
        let mut observed = self.state.load(Ordering::Relaxed);
        loop {
            let last_millis = observed >> REQUEST_ID_SEQUENCE_BITS;
            let last_sequence = observed & REQUEST_ID_MAX_SEQUENCE;
            let (next_millis, next_sequence) = if wall_millis > last_millis {
                (wall_millis, 0)
            } else if last_sequence < REQUEST_ID_MAX_SEQUENCE {
                (last_millis, last_sequence + 1)
            } else {
                // 保持 worker/sequence 位宽，不让 sequence carry 污染 worker id。
                (last_millis.saturating_add(1), 0)
            };
            let next_state = (next_millis << REQUEST_ID_SEQUENCE_BITS) | next_sequence;
            match self.state.compare_exchange_weak(
                observed,
                next_state,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return (next_millis << (REQUEST_ID_WORKER_BITS + REQUEST_ID_SEQUENCE_BITS))
                        | self.shifted_worker_id
                        | next_sequence;
                }
                Err(actual) => observed = actual,
            }
        }
    }
}

#[inline]
fn request_id_logical_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(REQUEST_ID_BASE_TIME_MS)
        .saturating_sub(REQUEST_ID_BASE_TIME_MS)
}

/// 普通 HTTP/HTTPS 上游 client；H2 模式额外携带每 shard 的冷启动单飞门。
pub(super) type UpstreamHttpClient = forward::UpstreamHttpClient;
/// 明文 HTTP/2 prior-knowledge client；与普通 client 隔离并使用相同冷启动单飞语义。
pub(super) type UpstreamH2cClient = forward::UpstreamH2cClient;

/// 普通 HTTP/HTTPS client cache 项。
pub(super) struct CachedUpstreamHttpClient {
    /// 独立 Hyper client 分片。h1 固定 1；auto/h2 按配置拆分，避免共享一条 h2 connection 锁。
    pub clients: Vec<UpstreamHttpClient>,
    /// 相对进程池时钟的最后命中毫秒；原子更新使共享读 guard 下无需升级独占锁。
    pub last_used_ms: AtomicU64,
    /// 本 generation 已分配给请求的次数；CAS 严格封住 `keepalive_requests` 边界。
    pub requests_served: AtomicU64,
}

/// h2c prior-knowledge client cache 项。
pub(super) struct CachedUpstreamH2cClient {
    /// 与连接 generation 完整对应的结构化 key。热缓存先逐字段比较它，避免稳定流量重复
    /// 进入 `RwLock<HashMap>` 做 SipHash；字段只含共享 `Arc<str>` 与 Copy 池参数。
    pub key: UpstreamH2cClientCacheKey,
    /// 已强制 `http2_only` 的独立 Hyper client 分片。
    pub clients: Vec<UpstreamH2cClient>,
    /// 相对进程池时钟的最后命中毫秒；共享读路径只做 relaxed store。
    pub last_used_ms: AtomicU64,
    /// 本 h2c generation 已分配给请求的次数。
    pub requests_served: AtomicU64,
}

/// 最近首次创建的上游 pending 计数器。
///
/// 单实例静态服务是最常见数据面形态；把它的共享计数器放进 ArcSwap 后，请求只做一次
/// pointer/string 身份比较和 Arc clone，不再每次对完整 URI 做 DashMap hash + shard read lock。
/// 多上游 miss 仍回退权威 DashMap，且只有真正插入新 identity 时更新 hot entry，避免交替流量
/// 为缓存包装器持续分配。计数器本身仍由 map 与响应 body 共享，严格 pending 上限不变。
pub(super) struct CachedUpstreamPendingCounter {
    /// TLS profile 已纳入的完整实例身份。
    pub health_key: Arc<str>,
    /// 跨快照/response body 共享的严格在途计数。
    pub counter: Arc<AtomicU64>,
}

/// 若最近 pending counter 已不属于新快照，则以 pointer CAS 撤下其额外 owner。
///
/// 该函数只在 reload reconcile 调用；拆出纯同步边界便于回归“active 保留、inactive 释放”，
/// 防止未来性能缓存让权威 identity map 失去有界 GC。并发替换 hot slot 时 CAS 会保留新值。
fn clear_inactive_pending_hot(
    hot_slot: &ArcSwapOption<CachedUpstreamPendingCounter>,
    active_identities: &HashSet<Arc<str>>,
) {
    let hot = hot_slot.load();
    if hot
        .as_ref()
        .is_some_and(|entry| !active_identities.contains(entry.health_key.as_ref()))
    {
        drop(hot_slot.compare_and_swap(&hot, None));
    }
}

/// 物理连接预算 cache 项。只有 map 是最后一个 Arc owner 时才可回收，避免旧 transport 仍存活时
/// 同 identity 重建第二个计数器并突破硬上限。
pub(super) struct CachedPhysicalConnectionBudget {
    /// connector/transport 共享的严格计数器。
    pub budget: Arc<forward::PhysicalConnectionBudget>,
    /// 最近一次被该 identity 命中的时间。
    pub last_used: Instant,
}

/// 普通 HTTP/HTTPS client 的结构化 cache key。
///
/// 请求热路径构造它只会 clone 可选 `Arc<str>`，不会为 `format!` 分配字符串（§15.7）。
#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct UpstreamHttpClientCacheKey {
    /// 完整实例身份；包含 URI 与 TLS profile，防不同 authority/profile 共享物理预算。
    pub health_key: Arc<str>,
    /// h1/auto/h2 连接池必须分开，避免协议策略串池。
    pub protocol: UpstreamProtocol,
    /// TCP connect timeout；CDS 热更后必须换代 connector，不能复用旧拨号策略。
    pub connect_timeout_ms: u64,
    /// 自定义 TLS profile 的非敏感指纹；None 表示系统根证书默认 profile。
    pub profile_key: Option<Arc<str>>,
    /// 每 authority 最多保留的 idle 连接数。
    pub max_idle_per_upstream: usize,
    /// auto/h2 client 的独立连接池分片数。
    pub h2_connection_shards_per_upstream: usize,
    /// H2 stream 初始 flow-control window；纳入 key，热更后建立新 transport。
    pub h2_initial_stream_window_bytes: u32,
    /// H2 connection 初始 flow-control window；纳入 key，热更后建立新 transport。
    pub h2_initial_connection_window_bytes: u32,
    /// 该结构化上游身份的物理 socket 总上限。
    pub max_connections_per_upstream: usize,
    /// 单 generation 请求数上限；0 表示不轮换。
    pub keepalive_requests: u64,
    /// idle 连接回收超时(ms)。
    pub idle_timeout_ms: u64,
}

/// h2c client 的结构化 cache key；没有 TLS profile，字段全部 Copy。
#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct UpstreamH2cClientCacheKey {
    /// 完整实例身份；即使 authority 相同，不同服务/TLS 身份也不串预算。
    pub health_key: Arc<str>,
    /// TCP connect timeout；纳入 generation key 避免新旧 CDS 语义串池。
    pub connect_timeout_ms: u64,
    /// 每 authority 最多保留的 idle h2c 连接数。
    pub max_idle_per_upstream: usize,
    /// 独立 h2c 连接池分片数。
    pub h2_connection_shards_per_upstream: usize,
    /// H2 stream 初始 flow-control window；纳入 key，避免新旧策略串池。
    pub h2_initial_stream_window_bytes: u32,
    /// H2 connection 初始 flow-control window；纳入 key，避免新旧策略串池。
    pub h2_initial_connection_window_bytes: u32,
    /// 该结构化上游身份的物理 socket 总上限。
    pub max_connections_per_upstream: usize,
    /// 单 generation 请求数上限；0 表示不轮换。
    pub keepalive_requests: u64,
    /// idle h2c 连接回收超时(ms)。
    pub idle_timeout_ms: u64,
}

/// 已完成/正在执行的一次性预热身份。字段覆盖真实 Hyper client cache key、预热 path 和
/// 目标连接数；reload 改任一池参数都会产生新 key，旧连接只自然 drain。
#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct PrewarmedUpstreamKey {
    pub health_key: Arc<str>,
    pub protocol: UpstreamProtocol,
    pub connect_timeout_ms: u64,
    pub path: Arc<str>,
    pub connections: usize,
    pub max_idle_per_upstream: usize,
    pub h2_connection_shards_per_upstream: usize,
    /// 预热目标 H2 stream 初始 flow-control window。
    pub h2_initial_stream_window_bytes: u32,
    /// 预热目标 H2 connection 初始 flow-control window。
    pub h2_initial_connection_window_bytes: u32,
    pub max_connections_per_upstream: usize,
    pub keepalive_requests: u64,
    pub idle_timeout_ms: u64,
}

/// 普通 HTTP/HTTPS client cache：`TLS profile + pool policy` -> client。
type UpstreamHttpClientPool = HashMap<UpstreamHttpClientCacheKey, CachedUpstreamHttpClient>;
/// h2c client cache：`pool policy` -> client。
type UpstreamH2cClientPool = HashMap<UpstreamH2cClientCacheKey, Arc<CachedUpstreamH2cClient>>;

/// HTTP/3 client 的结构化 cache key；identity/TLS/transport 任一变化都建立新 generation。
#[cfg(feature = "http3")]
#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct UpstreamH3ClientCacheKey {
    pub health_key: Arc<str>,
    pub profile_key: Arc<str>,
    pub max_response_header_bytes: usize,
    pub stream_receive_window_bytes: u32,
    pub connection_receive_window_bytes: u32,
    pub max_connections_per_upstream: usize,
    pub idle_timeout_ms: u64,
}

/// HTTP/3 client cache：结构化上游 generation -> multiplex QUIC client。
#[cfg(feature = "http3")]
type UpstreamH3ClientPool =
    HashMap<UpstreamH3ClientCacheKey, Arc<http3_upstream::UpstreamH3Client>>;

/// 下游物理连接的类型擦除 RAII lease。
///
/// listener/main 持有具体连接预算类型，而 WebSocket 隧道位于 library 数据面。该句柄只共享一份
/// `Arc`，使 HTTP Upgrade 后预算、活跃指标和 socket 生命周期一同转移到隧道 task；普通 H1/H2
/// 请求仍由 Hyper connection future 持有原 lease。内部 guard 不暴露方法，避免数据面绕过唯一
/// Drop 归还路径或复制计数。
#[derive(Clone)]
pub struct DownstreamConnectionLease {
    _guard: Arc<dyn Send + Sync>,
}

impl DownstreamConnectionLease {
    /// 擦除一个由 listener 创建的连接生命周期 guard。
    pub fn new<T>(guard: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        Self {
            _guard: Arc::new(guard),
        }
    }
}

/// 网关代理:持有原子配置快照 + 常驻上游 hyper 连接池(与配置版本解耦)。
pub struct GatewayProxy {
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// ACME HTTP-01 临时响应表；所有明文 proxy 共用，正常业务 path 只做固定前缀判断。
    acme_http01: Arc<crate::acme::Http01ChallengeStore>,
    /// 普通 h1/h2/HTTPS client cache。cache key 含 TLS profile + 显式池参数；Hyper 内部再按
    /// scheme/authority 分池，因此 `pool_max_idle_per_host` 的执行边界就是每 Upstream authority。
    pub(super) http_clients: ParkingRwLock<UpstreamHttpClientPool>,
    /// h2c prior-knowledge 专用 client cache（必须 `http2_only`，不能与 auto client 混用）。
    pub(super) h2c_clients: ParkingRwLock<UpstreamH2cClientPool>,
    /// 最近命中的 h2c client generation。稳定的单/少量上游是数据面的主流形态；ArcSwap
    /// 读路径不阻塞 reload，也不争用 `h2c_clients` 的读者计数 cache line。key 不一致时
    /// 仍回退完整 map，故多上游、池参数热更和 keepalive generation 轮换语义不变。
    pub(super) h2c_client_hot: ArcSwapOption<CachedUpstreamH2cClient>,
    /// H3 client cache 与 Hyper pool 隔离；关闭 `http3` feature 时字段和锁均不存在。
    #[cfg(feature = "http3")]
    h3_clients: ParkingRwLock<UpstreamH3ClientPool>,
    /// 结构化上游身份 -> 跨 client generation 共享的物理 socket 预算。reload/keepalive 轮换不能
    /// 创建一份新计数器，否则新旧池重叠期会突破总上限。
    pub(super) upstream_connection_budgets:
        Mutex<HashMap<(Arc<str>, UpstreamProtocol), CachedPhysicalConnectionBudget>>,
    /// 后台预热去重集合；只在低频扫描持锁，请求热路径从不访问。
    pub(super) prewarmed_upstreams: Mutex<HashSet<PrewarmedUpstreamKey>>,
    pub(super) metrics: Arc<Metrics>,
    access_log: AccessLogger,
    /// 长连接注册表(§6.1 / review L2):WS/gRPC-stream 登记于此,支持按维度优雅关闭既有连接。
    pub(super) conn_registry: Arc<ConnectionRegistry>,
    /// V8 边缘订阅索引(§25.2.5):常驻进程、不进 Snapshot。构造期急切创建(两张空
    /// DashMap,零流量零成本),admin /metrics 据此渲染低基数 gauge。未编 feature 时
    /// 字段不存在,默认路径零成本。
    #[cfg(feature = "grpc-edge")]
    edge_hub: Arc<crate::edge_hub::EdgeHub>,
    /// 集群中继句柄：仅 `grpc_edge_cluster.mode=relay` 时由 main 启动后注入；
    /// 单机恒空；ArcSwapOption 允许 reload 原子交换 relay generation。
    #[cfg(feature = "grpc-edge")]
    edge_relay: Arc<arc_swap::ArcSwapOption<crate::edge_relay::EdgeRelay>>,
    /// Redis Pub/Sub 集群总线；与 edge_relay 在配置构建期严格互斥。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_redis_bus: Arc<arc_swap::ArcSwapOption<crate::edge_redis_bus::EdgeRedisBus>>,
    /// Redis Stream XREAD 集群总线；与 relay/PubSub 在配置构建期严格互斥。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_redis_stream: Arc<arc_swap::ArcSwapOption<crate::edge_redis_bus::EdgeRedisStreamBus>>,
    /// 可选 SessionDirectory 指路条：仅 `session_registry=redis` 且编译 `redis-runtime` 时注入；
    /// 恒空即走 broadcast-probe，push 热路径只多一次 OnceLock 原子读。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_directory: std::sync::OnceLock<Arc<crate::edge_directory::SessionDirectory>>,
    /// WS 活动时间的进程级粗粒度单调时钟。一个后台 tick 替代每次隧道读写的系统时钟读取；
    /// 每连接仍维护独立时间戳，管理语义不共享、不串扰。
    pub(super) ws_activity_clock: Arc<AtomicU64>,
    /// 请求 ID 生成器：无锁 Snowflake，避免所有 worker 争用一个标准 Mutex。
    request_ids: RequestIdGenerator,
    /// 实例 health_key -> 在途请求数。TLS profile 属于实例身份的一部分,同 URI 不得串计数。
    upstream_inflight: DashMap<Arc<str>, Arc<AtomicU64>>,
    /// 服务名 -> retry budget 运行态。常驻 proxy,不随配置换版重置:
    /// 换版瞬间清零预算会让正在发生的故障恰好失去全部重试保护。
    upstream_retry_budget: DashMap<String, Arc<crate::admission::RetryBudgetState>>,
    /// 服务名 -> 自适应并发运行态。同样常驻:重置会把已经学到的 minRTT 与
    /// 收敛好的上限一起丢掉,reload 后必然出现一段过冲。
    upstream_admission: DashMap<String, Arc<crate::admission::AdaptiveConcurrencyState>>,
    /// route+维度 -> 共享带宽桶注册表。带宽必须跨并发流共享,
    /// 否则同一调用方多开几条流就能成倍突破配额。
    traffic_bandwidth: crate::traffic_limit::BandwidthRegistry,
    /// route+维度 -> 多窗口限额运行态。常驻 proxy:换版清零等于给超额流量开一次免费窗口。
    traffic_quota: DashMap<String, Arc<crate::traffic_limit::QuotaState>>,
    /// 实例 health_key -> 负载反馈状态(EWMA 延迟 / ORCA 利用率)。
    ///
    /// 条目在选择成功时创建并由该请求固定持有。目录换代后 `retain` 撤下旧身份；
    /// 迟到响应只更新已脱离权威表的旧 `Arc`，不会按同名 key 重建条目，也不会污染
    /// 后续目录为同名实例创建的新对象。
    upstream_load: DashMap<Arc<str>, Arc<crate::lb_load::InstanceLoad>>,
    /// 实例 health_key -> 受 `limits.upstream_pending_limit` 约束的在途上游请求数。
    /// 与 least_conn 分表，避免 LB 统计和过载保护相互污染。
    upstream_pending: DashMap<Arc<str>, Arc<AtomicU64>>,
    /// 单实例 pending 计数器的无锁最近项；miss 仍以 `upstream_pending` 为权威来源。
    pub(super) upstream_pending_hot: ArcSwapOption<CachedUpstreamPendingCounter>,
    /// round_robin 策略的每服务轮询计数(与 inflight 分开;快照重建不重置,故常驻 proxy)。
    upstream_rr: DashMap<String, AtomicU64>,
    /// V4 `limit_conn` 并发槽后端。local 单机可用,Redis 后端跨节点共享。
    conn_limiter: Arc<dyn ConnLimiter>,
    /// V3 Sentinel 熔断【开闭状态机】:规则 key -> open_until/half_open。常驻于 proxy,不随配置快照重建丢状态。
    /// 状态机本地维护;滑动窗口【统计】交给 `circuit_stats`(§10.6 R3:local 各自 / redis 集群共享)。
    circuit_states: Arc<Mutex<HashMap<String, CircuitState>>>,
    /// V3/§10.6 熔断滑动窗口统计后端。local 每节点各自;redis 跨节点共享聚合错误率(更准)。可热替换。
    circuit_stats: Arc<dyn CircuitStats>,
    /// §20 HMAC 防重放守卫后端。local 每节点各自去重;redis 跨节点 `SET NX PX`。可热替换。
    replay_guard: Arc<dyn ReplayGuard>,
    /// ext_authz 每后端独立的有界决策缓存与连续故障熔断状态；策略指纹变化会原地清空旧 owner 域。
    ext_authz_runtime: Mutex<HashMap<String, ExtAuthzBackendState>>,
    /// V3 Sentinel `limit_req` 后端。local 用于单机/降级,Redis 用于集群共享计数。
    rate_limiter: Arc<dyn RateLimiter>,
    /// V3 动态事实源。auto-ban/admin 等低频运行态写入走这里,不进入正常请求热路径。
    dynamic_store: Arc<SwappableDynamicStore>,
    /// V3 动态 IP 黑名单缓存。请求热路径只查本地 HashSet,后台从 DynamicStore 刷新。
    blacklist: Arc<BlacklistCache>,
    /// V4 动态接口禁用缓存。请求热路径只查本地已编译 matcher。
    interface_disable: Arc<DynamicInterfaceGuardCache>,
    /// V5 HTTP cache 的可选 Redis L2。local backend 的方法均为零网络空操作。
    http_cache_runtime: Arc<SwappableHttpCacheRuntime>,
    /// V5 进程级 OpenTelemetry provider；server/client span 只处理 head，不接触 body。
    telemetry: Arc<crate::telemetry::SwappableTelemetryRuntime>,
    /// V6 model 成功 TTFB EWMA。route/model 都来自有界配置；热更历史仍设 4096 项硬上限。
    llm_model_latency: Mutex<HashMap<String, HashMap<Arc<str>, u64>>>,
    /// auto-ban 本地计数:IP -> 当前窗口内被 limit_req 拒绝次数。
    auto_ban_counts: Mutex<HashMap<IpAddr, AutoBanState>>,
    /// 被动健康检查状态:health_key -> 连续失败/临时摘除截止时间。常驻于 proxy,不随配置快照换版丢失。
    upstream_failures: Mutex<HashMap<String, UpstreamFailureState>>,
    /// 失败表项数的无锁镜像；0 是正常成功热路径，避免每个 2xx 都争用失败表 Mutex。
    upstream_failure_entries: AtomicU64,
    /// 主动健康探测器(§5.1):后台任务写不健康集合,选实例时并入 excluded。常驻,不随快照换版。
    pub(super) active_health: Arc<crate::health::ActiveHealthChecker>,
}

/// 可由 reload worker 原子替换或长期复用的数据面运行态依赖。
pub struct ProxyRuntimeState {
    /// 高频请求限流后端。
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// 并发请求/连接限制器。
    pub conn_limiter: Arc<dyn ConnLimiter>,
    /// 熔断滑动窗口统计后端。
    pub circuit_stats: Arc<dyn CircuitStats>,
    /// HMAC nonce 防重放后端。
    pub replay_guard: Arc<dyn ReplayGuard>,
    /// 可热替换的低频动态集合事实源。
    pub dynamic_store: Arc<SwappableDynamicStore>,
    /// IP 黑名单本地只读缓存。
    pub blacklist: Arc<BlacklistCache>,
    /// 集群接口禁用本地只读缓存。
    pub interface_disable: Arc<DynamicInterfaceGuardCache>,
    /// HTTP response cache L2 与失效总线。
    pub http_cache: Arc<SwappableHttpCacheRuntime>,
    /// W3C/B3 传播与 OTLP exporter。
    pub telemetry: Arc<crate::telemetry::SwappableTelemetryRuntime>,
}

struct UpstreamFailureState {
    fails: u32,
    ejected_until: Option<Instant>,
}

struct CircuitState {
    open_until: Option<Instant>,
    half_open_probe: bool,
}

struct ExtAuthzBackendState {
    policy_fingerprint: [u8; 32],
    consecutive_failures: u32,
    open_until: Option<Instant>,
    half_open_probe: bool,
    cache: HashMap<[u8; 32], ExtAuthzCachedDecision>,
}

#[derive(Clone)]
struct ExtAuthzCachedDecision {
    allowed: bool,
    status: StatusCode,
    challenge: Option<HeaderValue>,
    upstream_headers: Vec<(HeaderName, HeaderValue)>,
    expires_at: Instant,
}

struct CircuitPermit {
    key: String,
    half_open: bool,
    policy: CircuitBreakerPolicy,
    /// Half-Open 探测必须用 RAII 释放：下游断连会取消整个 handler future，未必能走到
    /// `record_circuit_result`/`cancel_circuit_permits`。若无 Drop 兜底，探测位会永久卡住，
    /// 此后所有请求都被当作“已有探测在途”拒绝。
    states: Arc<Mutex<HashMap<String, CircuitState>>>,
    release_half_open_on_drop: bool,
}

impl Drop for CircuitPermit {
    fn drop(&mut self) {
        if !self.release_half_open_on_drop || !self.half_open {
            return;
        }
        // parking_lot 无 poisoning 分支；Drop 只做一次短临界区状态归还，不会 await。
        let mut states = self.states.lock();
        if let Some(state) = states.get_mut(&self.key) {
            state.half_open_probe = false;
        }
    }
}

struct AutoBanState {
    window_start: Instant,
    rejections: u64,
}

/// 记录一次 429 并判断是否达到自动封禁阈值。
///
/// 新 IP 只有在计数表仍有容量时才会获得 entry；这使 distinct-IP 洪泛下的内存占用具有
/// 真正的硬上界。已有 IP 仍可继续累计并触发封禁，过期 entry 会在表满时被回收。
fn record_auto_ban_rejection(
    counts: &mut HashMap<IpAddr, AutoBanState>,
    client_ip: IpAddr,
    now: Instant,
    threshold: u64,
    window: Duration,
    max_entries: usize,
) -> bool {
    if !counts.contains_key(&client_ip) && counts.len() >= max_entries {
        counts.retain(|_, state| now.saturating_duration_since(state.window_start) <= window);
        if counts.len() >= max_entries {
            return false;
        }
    }

    let state = counts.entry(client_ip).or_insert(AutoBanState {
        window_start: now,
        rejections: 0,
    });
    if now.saturating_duration_since(state.window_start) > window {
        state.window_start = now;
        state.rejections = 0;
    }
    state.rejections = state.rejections.saturating_add(1);
    if state.rejections >= threshold {
        counts.remove(&client_ip);
        true
    } else {
        false
    }
}

/// 单次内部重路由执行上下文。
struct InternalRerouteRequest<'a> {
    /// 当前入口运行配置,用于查内部路由表。
    proxy: &'a crate::config::ProxyRuntime,
    /// 原始下游请求 head,用于继承 method/header 与变量上下文。
    original_parts: &'a Parts,
    /// 内部重路由目标 path。
    target: &'a str,
    /// 已计算的真实客户端 IP。
    client_ip: IpAddr,
    /// 下游协议 scheme。
    downstream_proto: &'static str,
    /// 当前请求 ID。
    request_id: &'a str,
    /// 原始上游 trace,用于 access log 保留真实失败上游。
    upstream_trace: Option<forward::UpstreamTrace>,
}

/// 单次 LLM 转发所需的已认证请求上下文；使用结构体避免 provider fallback 调用点参数错位。
struct LlmForwardRequest<'a> {
    snap: &'a GatewaySnapshot,
    proxy: &'a crate::config::ProxyRuntime,
    route: &'a Route,
    parts: Parts,
    body: forward::ForwardBody,
    client_ip: IpAddr,
    trusted_inbound: bool,
    client_cert_verified: bool,
    downstream_proto: &'static str,
    request_id: &'a str,
    trace: &'a crate::telemetry::ServerTrace,
    downstream_upgrade: DownstreamUpgrade,
    limit_conn_guards: Vec<LimitConnGuard>,
}

/// BFF fan-out 只借用当前不可变快照和请求 head；原下游 body 不进入子请求，也不会被聚合。
struct BffForwardRequest<'a> {
    snap: &'a GatewaySnapshot,
    proxy: &'a crate::config::ProxyRuntime,
    route: &'a Route,
    parts: Parts,
    client_ip: IpAddr,
    trusted_inbound: bool,
    client_cert_verified: bool,
    downstream_proto: &'static str,
    request_id: &'a str,
    trace: &'a crate::telemetry::ServerTrace,
}

#[derive(Clone, Copy)]
enum BffTargetFailure {
    Timeout,
    Unavailable,
    Status,
    TooLarge,
    InvalidJson,
}

impl BffTargetFailure {
    const fn code(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Status => "status",
            Self::TooLarge => "too_large",
            Self::InvalidJson => "invalid_json",
        }
    }

    const fn response_status(self) -> StatusCode {
        match self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Unavailable | Self::Status | Self::TooLarge | Self::InvalidJson => {
                StatusCode::BAD_GATEWAY
            }
        }
    }
}

/// 一次 LLM cache miss 后保留到 provider 成功的最小回填上下文。prompt/raw body 已经完成摘要，
/// 不再持有第二份请求 JSON；embedding 缺失时仍可回填精确缓存。
struct LlmCacheFill {
    policy: Arc<crate::llm::LlmSemanticCache>,
    scope: String,
    exact_digest: [u8; 32],
    params_digest: [u8; 32],
    vector: Option<Arc<[f32]>>,
}

/// LLM 显式慢路径读取 body 的稳定错误分类。
enum LlmBodyError {
    /// 超过 route 配置硬上限。
    TooLarge,
    /// body frame/trailer/JSON 读取失败。
    Invalid(anyhow::Error),
}

/// 区分本地契约拒绝与真实上游结果，避免 400/413 污染 Sentinel 熔断窗口。
enum LlmForwardOutcome {
    /// 至少尝试过一个 provider；状态可参与熔断统计。
    Upstream(Response<BoxBody>),
    /// 在任何上游 I/O 前由 gateway 拒绝。
    Local(Response<BoxBody>),
}

impl GatewayProxy {
    /// 组装共享数据面；构造过程不启动 listener，所有依赖均已在 build 阶段验证。
    pub fn new(
        snap: Arc<ArcSwap<GatewaySnapshot>>,
        metrics: Arc<Metrics>,
        access_log: AccessLogger,
        conn_registry: Arc<ConnectionRegistry>,
        runtime_state: ProxyRuntimeState,
        active_health: Arc<crate::health::ActiveHealthChecker>,
    ) -> Arc<Self> {
        // worker id 继续按 pid 低 6 位派生，与原 Snowflake 布局兼容；发号状态本身使用 CAS。
        let request_ids = RequestIdGenerator::new(u64::from(std::process::id()) & 0x3f);
        Arc::new(Self {
            snap,
            acme_http01: crate::acme::Http01ChallengeStore::new(),
            http_clients: ParkingRwLock::new(HashMap::new()),
            h2c_clients: ParkingRwLock::new(HashMap::new()),
            h2c_client_hot: ArcSwapOption::empty(),
            #[cfg(feature = "http3")]
            h3_clients: ParkingRwLock::new(HashMap::new()),
            upstream_connection_budgets: Mutex::new(HashMap::new()),
            prewarmed_upstreams: Mutex::new(HashSet::new()),
            metrics,
            access_log,
            conn_registry,
            #[cfg(feature = "grpc-edge")]
            edge_hub: crate::edge_hub::EdgeHub::new(),
            #[cfg(feature = "grpc-edge")]
            edge_relay: Arc::new(arc_swap::ArcSwapOption::empty()),
            #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
            edge_redis_bus: Arc::new(arc_swap::ArcSwapOption::empty()),
            #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
            edge_redis_stream: Arc::new(arc_swap::ArcSwapOption::empty()),
            #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
            edge_directory: std::sync::OnceLock::new(),
            ws_activity_clock: forward::start_ws_activity_clock(),
            request_ids,
            upstream_inflight: DashMap::new(),
            traffic_bandwidth: crate::traffic_limit::BandwidthRegistry::default(),
            traffic_quota: DashMap::new(),
            upstream_load: DashMap::new(),
            upstream_retry_budget: DashMap::new(),
            upstream_admission: DashMap::new(),
            upstream_pending: DashMap::new(),
            upstream_pending_hot: ArcSwapOption::empty(),
            upstream_rr: DashMap::new(),
            conn_limiter: runtime_state.conn_limiter,
            circuit_states: Arc::new(Mutex::new(HashMap::new())),
            circuit_stats: runtime_state.circuit_stats,
            replay_guard: runtime_state.replay_guard,
            ext_authz_runtime: Mutex::new(HashMap::new()),
            rate_limiter: runtime_state.rate_limiter,
            dynamic_store: runtime_state.dynamic_store,
            blacklist: runtime_state.blacklist,
            interface_disable: runtime_state.interface_disable,
            http_cache_runtime: runtime_state.http_cache,
            telemetry: runtime_state.telemetry,
            llm_model_latency: Mutex::new(HashMap::new()),
            auto_ban_counts: Mutex::new(HashMap::new()),
            upstream_failures: Mutex::new(HashMap::new()),
            upstream_failure_entries: AtomicU64::new(0),
            active_health,
        })
    }

    /// 返回 ACME worker 与数据面共用的 HTTP-01 challenge 表。
    ///
    /// 返回：只 clone 一个 `Arc`；worker 发布/撤下 token 后所有 proxy 立即可见。
    pub fn acme_http01_store(&self) -> Arc<crate::acme::Http01ChallengeStore> {
        self.acme_http01.clone()
    }

    /// 配置换版后低频对账常驻上游 identity 表。
    ///
    /// 只删除已不在新快照、计数为 0 且 map 是唯一 `Arc` owner 的 entry；旧请求/body/
    /// transport 仍持有 handle 时必须保留，避免同 identity 重建第二个计数器突破上限。
    /// 扫描只发生在 reload reconcile，不进入每请求成功路径。
    pub fn reconcile_runtime_identities(&self, snap: &GatewaySnapshot) {
        let (active_services, active_identities) = snap.upstreams.runtime_identities();

        // hot wrapper 会额外持有 counter Arc；identity 已下线时必须先撤掉该 owner，否则下面
        // `retain_identity_counter` 会把它误认为仍有在途 response body 而永久保留旧 key。
        // CAS 只撤掉刚刚观察到的 inactive 项，不覆盖并发请求新发布的 active identity。
        // 权威 DashMap/AtomicU64 从不依赖这个缓存；occupied 分支会在 slot 为空时低频补发。
        clear_inactive_pending_hot(&self.upstream_pending_hot, &active_identities);

        let inflight_len = {
            self.upstream_inflight.retain(|identity, counter| {
                retain_identity_counter(&active_identities, identity, counter)
            });
            self.upstream_inflight.len()
        };
        let pending_len = {
            self.upstream_pending.retain(|identity, counter| {
                retain_identity_counter(&active_identities, identity, counter)
            });
            self.upstream_pending.len()
        };
        // 负载反馈随实例身份一起退场:实例不在当前目录就不该再有调度参考量,
        // 否则同名实例重新出现时会继承上一代的延迟/利用率历史。
        self.upstream_load
            .retain(|identity, _| active_identities.contains(identity.as_ref()));
        // 准入状态按**服务**保留:服务还在就继承既有预算与已收敛的并发上限,
        // 服务被删除才回收。这正是「reload 保守继承」的落点。
        self.upstream_retry_budget
            .retain(|service, _| active_services.contains(service));
        self.upstream_admission
            .retain(|service, _| active_services.contains(service));
        let rr_len = {
            self.upstream_rr
                .retain(|service, _| active_services.contains(service));
            self.upstream_rr.len()
        };
        let upstream_failure_entries = {
            let mut failures = self.upstream_failures.lock();
            failures.retain(|identity, _| active_identities.contains(identity.as_str()));
            failures.len() as u64
        };
        self.upstream_failure_entries
            .store(upstream_failure_entries, Ordering::Release);

        // 先从 client cache 移除无效 identity；在途 request 的 client clone 仍可自然 drain。每把锁都单独
        // 持有，避免与请求路径的 budget→client 顺序形成反向锁嵌套。
        self.http_clients
            .write()
            .retain(|key, _| active_identities.contains(key.health_key.as_ref()));
        self.h2c_clients
            .write()
            .retain(|key, _| active_identities.contains(key.health_key.as_ref()));
        #[cfg(feature = "http3")]
        self.h3_clients
            .write()
            .retain(|key, _| active_identities.contains(key.health_key.as_ref()));
        // ArcSwap 热入口也不能无限持有已从配置/发现目录消失的 generation。先借用检查、再在
        // guard 离开作用域后清空；并发请求已经 clone 的 client/transport 仍按 body 生命周期
        // 自然 drain，不会因控制面清理中断在途 frame。
        let hot_h2c_is_stale = self
            .h2c_client_hot
            .load()
            .as_ref()
            .is_some_and(|entry| !active_identities.contains(entry.key.health_key.as_ref()));
        if hot_h2c_is_stale {
            self.h2c_client_hot.store(None);
        }
        let budget_len = {
            let mut budgets = self.upstream_connection_budgets.lock();
            budgets.retain(|(identity, _), entry| {
                active_identities.contains(identity.as_ref())
                    || Arc::strong_count(&entry.budget) > 1
            });
            budgets.len()
        };
        self.metrics
            .set_upstream_identity_entries(inflight_len, pending_len, rr_len, budget_len);
    }

    /// hyper service 入口。返回 `Infallible`:网关自身永远给出一个响应(错误也转成 5xx),不把错误抛回连接层。
    pub async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        conn: ConnInfo,
        downstream_proto: &'static str,
        proxy_id: Arc<str>,
    ) -> Result<Response<BoxBody>, Infallible> {
        self.handle_inner(
            req.map(box_incoming_body),
            conn,
            downstream_proto,
            proxy_id,
            None,
            None,
        )
        .await
    }

    /// 使用连接级预编码客户端 IP header 的 Hyper service 入口。
    ///
    /// 业务作用：复用已验证连接地址的预编码 header 启动完整请求管线，同时仍在每个 stream
    /// 重新执行 trusted XFF 边界校验，避免 H2 多租户复用越权继承客户端身份。
    ///
    /// 参数说明：`req` 是原始下游请求；`conn` 是已验证连接元数据；`downstream_proto` 与
    /// `proxy_id` 固化入口；`client_ip_header` 只能由同一 `conn` 构造。
    ///
    /// 返回：始终返回一个下游响应；业务失败转换为对应 4xx/5xx，不向 Hyper 连接层传播错误。
    ///
    /// 该入口供 accept loop 使用；保留 [`Self::handle`] 让已有嵌入方无需构造缓存。缓存只能由
    /// [`ConnectionClientIpHeader::new`] 从同一 `ConnInfo` 创建，入口仍在可信 XFF 解析之后核对
    /// 最终 IP，不能让连接级优化越过每请求信任边界。强制跨 crate 内联只用于让 main 在 Box
    /// 分配目标中直接构造约 10KiB 的状态机，避免先按值返回到栈上再整块搬运；不改变 poll 边界。
    #[inline(always)]
    pub fn handle_with_connection_ip_header(
        self: Arc<Self>,
        req: Request<Incoming>,
        conn: ConnInfo,
        downstream_proto: &'static str,
        proxy_id: Arc<str>,
        client_ip_header: ConnectionClientIpHeader,
        listener_snapshot: Arc<GatewaySnapshot>,
    ) -> impl Future<Output = Result<Response<BoxBody>, Infallible>> + Send {
        self.handle_inner(
            req.map(box_incoming_body),
            conn,
            downstream_proto,
            proxy_id,
            Some(client_ip_header),
            Some(listener_snapshot),
        )
    }

    /// 业务作用：接收 H3 adapter 产生的 `BoxBody` 并执行与 h1/h2 完全相同的信任、路由、治理和
    /// 上游管线，防止 QUIC listener 形成可绕过鉴权/限流的第二套数据面。
    ///
    /// 参数说明：`req` 持有 H3 request stream；`conn` 固化已验证的 QUIC peer；
    /// `downstream_proto` 必须为 `https`；`proxy_id` 标识逻辑 listener。
    ///
    /// 返回：始终生成一个下游响应；所有错误保持既有 4xx/5xx 映射，不泄漏为 H3 task panic。
    pub fn handle_boxed(
        self: Arc<Self>,
        req: Request<BoxBody>,
        conn: ConnInfo,
        downstream_proto: &'static str,
        proxy_id: Arc<str>,
    ) -> impl Future<Output = Result<Response<BoxBody>, Infallible>> + Send {
        self.handle_inner(req, conn, downstream_proto, proxy_id, None, None)
    }

    /// 业务作用：在单一不可变 Snapshot 上执行请求信任边界、治理、路由、流式上游转发与
    /// 响应收尾，保证 reload 不会让同一请求混用两个配置版本。
    ///
    /// 参数说明：`req`/`conn` 是下游请求与可信连接元数据；`downstream_proto`/`proxy_id`
    /// 标识入口；`connection_client_ip_header` 是可选的同连接预编码客户端地址。
    ///
    /// 返回：所有分支都生成一个响应；拒绝、超时和上游失败被稳定映射为响应并完成指标/审计。
    async fn handle_inner(
        self: Arc<Self>,
        mut req: Request<BoxBody>,
        conn: ConnInfo,
        downstream_proto: &'static str,
        proxy_id: Arc<str>,
        connection_client_ip_header: Option<ConnectionClientIpHeader>,
        listener_snapshot: Option<Arc<GatewaySnapshot>>,
    ) -> Result<Response<BoxBody>, Infallible> {
        let started = Instant::now();
        self.metrics.inc_request();
        let request_id = self.next_request_id();
        let downstream_version = req.version();
        let websocket_upgrade = is_h1_websocket_upgrade(&req);
        let sse_request = accepts_event_stream(req.headers());
        let connect_udp_request = req
            .extensions()
            .get::<crate::masque::ConnectUdpRequest>()
            .is_some();
        let webtransport_request = req
            .extensions()
            .get::<crate::masque::WebTransportRequest>()
            .is_some();
        let early_data_request = req
            .extensions()
            .get::<crate::masque::EarlyDataRequest>()
            .is_some();
        let early_data_request_body = req
            .extensions()
            .get::<crate::masque::EarlyDataRequestBody>()
            .is_some();
        // CONNECT 与 WebSocket 一样需要在响应后接管裸 socket,因此同样要在这里取走升级权。
        // 取升级权本身不放行任何目标:allowlist 与 SSRF 判定全部在隧道建立前执行。
        let connect_request = req.method() == Method::CONNECT;
        let mut downstream_upgrade = if websocket_upgrade
            || (connect_request && !connect_udp_request && !webtransport_request)
        {
            // OnUpgrade 把真实 socket 移交给独立隧道 task；连接预算 lease 必须一起移动，否则
            // Hyper HTTP future 在 101 后结束会提前归还 max_connections 名额并把指标减为 0。
            let connection_lease = req.extensions_mut().remove::<DownstreamConnectionLease>();
            Some((hyper::upgrade::on(&mut req), connection_lease))
        } else {
            None
        };

        // ★整条管线共用这一份快照★ —— 换版对在途请求透明(无感,架构规范 §7.4)。
        let current = self.snap.load_full();
        // listener 被删除时，旧 accept loop 已先停收；只有删除前已建立的物理连接可退回其
        // generation 完成排空。只要同 id 仍存在就必须使用 current，不能让 keep-alive 钉住旧策略。
        let snap = if current.proxy(&proxy_id).is_some() {
            current
        } else if listener_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.proxy(&proxy_id).is_some())
        {
            listener_snapshot.expect("checked listener drain snapshot")
        } else {
            current
        };
        // 关闭态在 producer 侧短路，避免先构造完整记录、写 bounded queue，再由 worker 丢弃。
        // bool 来自本请求唯一快照，reload 前后不会出现半个请求采用两套日志策略。
        let access_log_enabled = snap.access_log.enabled();
        // 只在日志 producer 确实启用时保留原始 method/URI。clone 只共享 http crate 内部存储，
        // 但关闭态连引用计数/enum 构造也无需支付；body 仍在下方直接 move，不发生复制或聚合。
        let mut access_log_head = access_log_enabled.then(|| {
            (
                AccessMethod::Http(req.method().clone()),
                AccessPath::Http(req.uri().clone()),
            )
        });
        let proxy_runtime = match snap.proxy(&proxy_id) {
            Some(proxy) => proxy,
            None => {
                let resp = text_status(503, "proxy listener unavailable");
                self.metrics.inc_response(resp.status().as_u16());
                self.metrics.observe_request_duration(started.elapsed());
                return Ok(resp);
            }
        };
        let (mut parts, body) = req.into_parts();
        // HTTP/2/HTTP/3 的 `:authority` 与 HTTP/1 Host 是同一业务权威；先统一为内部
        // Host，后续路由、重写、审计和 preserve_host 才不会因下游协议不同而改变语义。
        let authority_host_valid = canonicalize_request_authority(&mut parts);
        // 客户端提供的同名 header 永远不可信；先清除，再由当前 socket 的不可变 listener
        // 表根据 Host 盖章。Router 只用这枚内部标记隔离共享端口，命中后立即移除，不发送给上游。
        parts.headers.remove(&GATEWAY_LISTENER_HEADER);
        if let Some(listener_id) = gateway_request_hostname(&parts).and_then(|hostname| {
            select_gateway_listener(&hostname, proxy_runtime.gateway_listeners.as_slice())
        }) {
            parts.headers.insert(
                GATEWAY_LISTENER_HEADER.clone(),
                HeaderValue::from_str(listener_id)
                    .expect("validated Gateway listener id is a legal header value"),
            );
        }
        // TLS SNI 与 HTTP Host 必须落在同一 Gateway listener。H2 允许客户端在证书覆盖范围内
        // 合并连接，但不能借此越过 listener 的 hostname、证书与路由隔离边界。
        let gateway_misdirected = downstream_proto == "https"
            && gateway_tls_listener_mismatch(
                &parts,
                conn.tls_server_name.as_deref(),
                proxy_runtime.gateway_listeners.as_slice(),
            );
        // Proxy-Wasm request_headers 的 end_of_stream 只从 Hyper 已知的 body 状态取值；
        // 未知/chunked 保守传 false，不为了判定空 body 去 poll 或聚合流。
        let request_end_of_stream = body.is_end_stream();
        // h1/h2/H3 都在 listener adapter 只做一次类型擦除，不读取、不聚合 body；只有命中
        // 显式 schema/mirror 慢路径时才会把它替换为复用聚合 Bytes 的 body。
        let mut forward_body = Some(body);
        // 只有本 proxy 至少存在一条压缩 route 才解析协商头。这个 proxy 级构建期 bit 同时
        // 覆盖 internal reroute 目标；普通反代/gRPC proxy 的默认热路径只做一次可预测 bool
        // 分支，不扫描 HeaderMap、不分配，也不会为了基准关闭真实压缩能力。
        let accepted_encodings = proxy_runtime
            .router
            .has_response_compression()
            .then(|| AcceptedEncodings::parse(&parts.headers));
        let response_method = parts.method.clone();
        // 只看 HTTP/2 head 判定原生 gRPC；不解析/缓存 body，且排除 `application/grpc-web`。
        let grpc_request = is_native_grpc(&parts);
        // 路由、ACL、guard 与最终上游必须看到同一份安全 path。原始 path 已在上面留给 access log；
        // 这里合并重复 `/`，并拒绝 dot/encoded slash/双重编码、超长和超深路径（§4.2）。
        let path_valid = normalize_request_path(&mut parts, &proxy_runtime.limits);
        let request_origin = parts.headers.get(http::header::ORIGIN).cloned();
        // 计算真实客户端 IP 与审计 peer(review L6):
        // - PROXY protocol 已解析出 real_peer → 直接可信;
        // - 否则直连对端在 trusted_proxies 内 → 信任其 XFF,取链上真实客户端;
        // - 都不满足 → 用 socket 对端(忽略可伪造的 XFF)。
        let trusted_inbound =
            conn.via_proxy_protocol || proxy_runtime.is_trusted_peer(conn.tcp_peer.ip());
        let client_ip = if conn.via_proxy_protocol {
            conn.real_peer.ip()
        } else if trusted_inbound {
            client_ip_from_forwarded(&parts, proxy_runtime.trusted_proxies.as_slice())
                .unwrap_or_else(|| conn.tcp_peer.ip())
        } else {
            conn.tcp_peer.ip()
        };
        // trusted XFF 可使同一 H2 connection 的每个 stream 拥有不同 client_ip；只有最终
        // 权威地址仍等于 connection real_peer 时才移动预编码值进入转发上下文。普通直连与
        // PROXY protocol 命中该快路，代理 multiplex 不同租户时自动回退逐请求构造。
        let connection_client_ip_header =
            connection_client_ip_header.and_then(|cached| cached.into_value_for(client_ip));
        // server span 在信任边界确定后创建：只采信 trusted proxy 的远端上下文；HeaderMap 原地
        // 规范化为当前 server span，不 clone 请求 head/body。trace-id 以 Arc 与 access log 共享。
        let mut server_trace = self.telemetry.begin_server(
            &mut parts.headers,
            trusted_inbound,
            &parts.method,
            parts.uri.path(),
            downstream_proto,
            client_ip,
        );
        // HTTP-01 必须先于 80→443 redirect/ACL/黑名单短路，否则 CA 无法取到验证 token。
        // 只有 worker 已发布的精确 token 才绕过，未知 challenge path 仍走正常安全管线。
        // ACME/redirect 响应只在极少数请求命中；装箱让两个 128B Response 不再常驻整个异步
        // 状态机，未命中热路径只保留空指针且不分配。
        let acme_challenge = self.acme_http01.response(&parts).map(Box::new);
        if acme_challenge.is_none() && self.blacklist.is_blocked(client_ip) {
            self.metrics.inc_blacklist_denied();
            let mut resp = text_status(403, "forbidden");
            server_trace.finish(resp.status().as_u16(), None, None, 0);
            self.finish_access(access_log_enabled, || {
                let (method, path) = access_log_head.expect("enabled access log has request head");
                AccessRecord {
                    method,
                    path,
                    request_id: request_id.as_str().to_owned(),
                    trace_id: Some(server_trace.trace_id()),
                    route_id: None,
                    upstream: None,
                    upstream_attempts: 0,
                    status: resp.status().as_u16(),
                    elapsed: started.elapsed(),
                    // peer 只供 access log 消费；`finish_access` 关闭态不会执行闭包。把 SocketAddr/IP
                    // 格式化留在 producer 闭包里，避免关闭日志的 H2 每条 stream 重复分配 String。
                    peer: audit_peer(&conn, client_ip, trusted_inbound),
                    bytes_downstream_to_upstream: None,
                    bytes_upstream_to_downstream: None,
                }
            });
            self.metrics.inc_response(resp.status().as_u16());
            self.metrics.observe_request_duration(started.elapsed());
            apply_http3_advertisement(
                &mut resp,
                &proxy_runtime.http3,
                downstream_proto,
                downstream_version,
            );
            return Ok(resp);
        }
        let mut route_id = None;
        let mut matched_route = None;
        let mut response_filter_parts = None;
        // 仅 response Proxy-Wasm route 保留已经过 request plugin 的 head 快照。
        // body 始终留在 ForwardBody 流里，不被插件路径复制。
        let mut wasm_response_request = None;
        // 外部响应插件只快照其 request-header allowlist 并集，不 clone 整份请求 head/body。
        let mut external_response_request = None;
        // 每个显式 ext_proc route 只建立一条双向流，request/response phase 共用同一协议状态。
        let mut ext_proc_session: Option<crate::ext_proc::SharedExtProcSession> = None;
        // EPP 子集只在处理器完成完整请求裁决后生成，并借用到同一次上游转发结束。
        let mut inference_selection: Option<forward::InferenceEndpointSelection> = None;
        // OPA response obligations 只有 allow 且整组通过白名单/资源复验后才写入；在响应插件完成后应用。
        let mut opa_response_obligations: Option<OpaObligations> = None;
        let mut internal_reroute_parts = None;
        let mut long_connection_consumer = None;
        let mut limit_conn_guards = Vec::new();
        // 响应方向整形器在准入期就取好共享桶:此时才有 route 与维度,
        // 而响应阶段拿不到原始请求头,晚了就算不出维度键。
        let mut response_bandwidth_shaper: Option<crate::traffic_limit::FrameShaper> = None;
        // 成本型限额的预留凭据必须跟随响应 body 生命周期；只有实际交付的数据帧
        // 才能形成可信事实，客户端中途取消时由 Drop 以已交付量完成结算。
        let mut response_cost_settlement: Option<TrafficSettlement> = None;
        let mut circuit_permits = Vec::new();
        // 只在安全可缓存 GET 的 L1 miss 上持有；hit/绕过保持 None，默认快路径零分配。
        let mut response_cache_key = None;
        // SWR 命中时只暂存 leader guard；立刻派生有界刷新任务，当前 stale response 不等待 Redis/上游。
        let mut stale_cache_refresh = None;
        // 熔断信号必须取自【上游真实结果】,不能取最终下游响应:error_page 会把上游 5xx 改写成 200
        // (§36.3②),CORS 预检/静态/直接响应等短路分支根本没打上游。只有真正转发上游的分支才把
        // 本值置 Some(是否成功);短路分支保持 None,record 阶段据此选择「记账」还是「撤销半开占用」。
        let mut upstream_circuit_outcome: Option<bool> = None;
        // 写后 cache 失效必须依据【真实上游状态】而非 error_page 改写后的下游状态；只记录成功
        // 收到的 response head，连接错误/合成响应保持 None。
        let mut upstream_write_status: Option<StatusCode> = None;

        // 0. ★HTTP→HTTPS 跳转(§19)★:明文入口配了 redirect_https → 一律 3xx 跳到 TLS 端口,
        //    先于守卫/路由(对齐 nginx `server{listen 80; return 308 https://...}` 语义,http server 只做跳转)。
        let https_redirect = if downstream_proto == "http" {
            proxy_runtime
                .redirect_https
                .as_ref()
                .map(|redirect| Box::new(https_redirect_response(&parts, redirect)))
        } else {
            None
        };
        // 1. ★接口级拦截★:命中即直接返回配置的 response,零上游成本(§8)。
        let mut resp = if let Some(challenge) = acme_challenge {
            *challenge
        } else if let Some(redirect) = https_redirect {
            *redirect
        } else if !authority_host_valid {
            text_status(400, "invalid authority")
        } else if gateway_misdirected {
            self.metrics.inc_no_route();
            text_status(421, "misdirected request")
        } else if !path_valid {
            text_status(400, "invalid path")
        } else if let Some((resp, rule_id)) = self.interface_disable.check(&parts) {
            tracing::debug!(rule = %rule_id, path = parts.uri.path(), "interface dynamically disabled");
            self.metrics.inc_interface_blocked();
            resp
        } else if let Some((resp, rule_id)) = snap.interface_guard.check(&parts) {
            tracing::debug!(rule = rule_id, path = parts.uri.path(), "interface blocked");
            self.metrics.inc_interface_blocked();
            resp
        } else if !host_allowed(&parts, proxy_runtime.server_names.as_slice()) {
            self.metrics.inc_no_route();
            text_status(404, "no matching host")
        } else {
            // 2. 路由匹配。
            let route = match proxy_runtime
                .router
                .match_route_with_key(&parts, request_id.as_bytes())
            {
                Some(r) => r,
                None => {
                    self.metrics.inc_no_route();
                    let mut resp = if early_data_request {
                        // 早期请求没有显式授权 route 时必须要求客户端在握手后重试；普通 404
                        // 会让客户端误以为重放安全门已经完成，并掩盖实际拒绝原因。
                        self.metrics
                            .inc_early_data(Some(crate::masque::EarlyDataDenial::NotEnabled));
                        let mut response = text_status(StatusCode::TOO_EARLY.as_u16(), "too early");
                        response.headers_mut().insert(
                            http::header::CACHE_CONTROL,
                            HeaderValue::from_static("no-store"),
                        );
                        response
                    } else {
                        text_status(404, "no matching route")
                    };
                    server_trace.finish(resp.status().as_u16(), None, None, 0);
                    self.finish_access(access_log_enabled, || {
                        let (method, path) =
                            access_log_head.expect("enabled access log has request head");
                        AccessRecord {
                            method,
                            path,
                            request_id: request_id.as_str().to_owned(),
                            trace_id: Some(server_trace.trace_id()),
                            route_id: None,
                            upstream: None,
                            upstream_attempts: 0,
                            status: resp.status().as_u16(),
                            elapsed: started.elapsed(),
                            peer: audit_peer(&conn, client_ip, trusted_inbound),
                            bytes_downstream_to_upstream: None,
                            bytes_upstream_to_downstream: None,
                        }
                    });
                    self.metrics.inc_response(resp.status().as_u16());
                    self.metrics.observe_request_duration(started.elapsed());
                    apply_http3_advertisement(
                        &mut resp,
                        &proxy_runtime.http3,
                        downstream_proto,
                        downstream_version,
                    );
                    return Ok(resp);
                }
            };
            // 内部 listener 标记的唯一职责是 Router 匹配；在任何认证、插件、缓存或上游
            // 处理前移除，避免内部拓扑身份越过网关边界或被业务策略误用。
            parts.headers.remove(&GATEWAY_LISTENER_HEADER);
            // 源 namespace 只由受保护的 Mesh listener 用于 consumer Route 选择；命中后立即
            // 清除，避免该控制身份被转发给后端或被后续业务插件当作普通用户输入。
            parts.headers.remove(&MESH_SOURCE_NAMESPACE_HEADER);
            if route.inference_pool.is_some() {
                // 客户端不得预置 EPP 控制头；先清除再进入授权 ext_proc，相同名称只有处理器
                // mutation 才能重新产生，避免用户输入取得 endpoint 选择权威。
                parts.headers.remove("x-gateway-destination-endpoint");
            }
            route_id = Some(route.id_shared.clone());
            matched_route = Some(route.clone());
            let mut authorization_identity = AuthorizationIdentity::default();
            if route.x_accel_redirect || route.error_pages.iter().any(ErrorPagePolicy::is_reroute) {
                internal_reroute_parts = Some(Box::new(parts.clone()));
            }
            if route
                .response_headers
                .iter()
                .any(ResponseHeaderOp::needs_request_context)
            {
                response_filter_parts = Some(Box::new(parts.clone()));
            }
            if let Some(uri) = route
                .dlp
                .as_ref()
                .and_then(|policy| policy.sanitized_log_uri(&parts.uri))
            {
                // access log path 在任何 DLP 命中日志之前替换，后续拒绝、插件或上游分支都只能
                // 看到固定占位路径，不能因早退把敏感 path 原值写回审计。
                if let Some((_, path)) = access_log_head.as_mut() {
                    *path = AccessPath::Http(uri);
                }
            }

            if let Some(response) = self
                .enforce_early_data(
                    &route,
                    &mut parts,
                    early_data_request,
                    early_data_request_body,
                    proxy_runtime.id.as_str(),
                )
                .await
            {
                response
            } else if !route.permits_ip(client_ip) || !route.permits_referer(&parts) {
                self.metrics.inc_acl_denied();
                text_status(403, "forbidden")
            } else if !route.permits_method(&parts) {
                text_status(405, "method not allowed")
            } else if let Some(resp) = enforce_waf_head(&route, &parts, self.metrics.as_ref()) {
                resp
            } else if let Some(resp) = enforce_geoip(&route, client_ip, self.metrics.as_ref()) {
                resp
            } else if let Some(resp) = self.enforce_bot(&parts, &route, client_ip).await {
                resp
            } else if let Some(resp) =
                enforce_csrf(&route, &parts, downstream_proto, self.metrics.as_ref())
            {
                resp
            } else if let Some(resp) = enforce_dlp_request_head(
                &route,
                &mut parts,
                &mut internal_reroute_parts,
                &mut response_filter_parts,
                self.metrics.as_ref(),
            ) {
                resp
            } else if let Some(resp) = self
                .enforce_auth_chain(
                    &snap,
                    proxy_runtime,
                    &route,
                    &mut parts,
                    &mut forward_body,
                    client_ip,
                    trusted_inbound,
                    downstream_proto,
                    &request_id,
                    &server_trace,
                    &mut authorization_identity,
                    (websocket_upgrade || grpc_request || sse_request || connect_request)
                        .then_some(&mut long_connection_consumer),
                )
                .await
            {
                resp
            } else if let Some(resp) = self
                .enforce_opa_authorization(
                    &snap,
                    proxy_runtime,
                    &route,
                    &mut parts,
                    &mut forward_body,
                    authorization_identity.authenticated,
                    authorization_identity.consumer.as_deref(),
                    authorization_identity.jwt_claims.as_ref(),
                    client_ip,
                    downstream_proto,
                    &request_id,
                    &server_trace,
                    &mut opa_response_obligations,
                )
                .await
            {
                resp
            } else if let Some(resp) = enforce_casbin_authorization(
                &route,
                &parts,
                authorization_identity.authenticated,
                authorization_identity.consumer.as_deref(),
                client_ip,
                downstream_proto,
                self.metrics.as_ref(),
            ) {
                resp
            } else if let Some(resp) =
                enforce_waf_body(&route, &parts, &mut forward_body, self.metrics.as_ref()).await
            {
                resp
            } else if let Some(resp) = enforce_dlp_request_body(
                &route,
                &mut parts,
                &mut forward_body,
                self.metrics.as_ref(),
            )
            .await
            {
                resp
            } else if let Some(resp) = enforce_wasm_request_headers(
                &route,
                &mut parts,
                downstream_proto,
                request_end_of_stream,
                &mut wasm_response_request,
                self.metrics.as_ref(),
            )
            .await
            {
                resp
            } else if let Some(resp) = enforce_wasm_request_body(
                &route,
                &mut parts,
                &mut forward_body,
                downstream_proto,
                &mut wasm_response_request,
                self.metrics.as_ref(),
            )
            .await
            {
                resp
            } else if let Some(resp) = self
                .enforce_external_request_headers(
                    &snap,
                    proxy_runtime,
                    &route,
                    &mut parts,
                    downstream_proto,
                    &request_id,
                    &server_trace,
                    &mut external_response_request,
                )
                .await
            {
                resp
            } else if let Some(resp) = self
                .enforce_ext_proc_request(
                    &snap,
                    proxy_runtime,
                    &route,
                    &mut parts,
                    &mut forward_body,
                    request_end_of_stream,
                    downstream_proto,
                    &request_id,
                    &server_trace,
                    &mut ext_proc_session,
                )
                .await
            {
                resp
            } else if let Some(resp) = self
                .enforce_inference_pool_request(
                    &route,
                    &mut parts,
                    &ext_proc_session,
                    &mut inference_selection,
                )
                .await
            {
                resp
            } else if let Some(resp) = transform_degraphql(
                &route,
                &mut parts,
                &mut forward_body,
                request_end_of_stream,
                self.metrics.as_ref(),
            ) {
                resp
            } else if let Some(resp) =
                enforce_graphql_guard(&route, &parts, &mut forward_body, self.metrics.as_ref())
                    .await
            {
                resp
            } else if let Some(resp) =
                validate_route_request(&route, &parts, &mut forward_body, self.metrics.as_ref())
                    .await
            {
                resp
            } else if let Some(resp) = transform_route_request(
                &route,
                &mut parts,
                &mut forward_body,
                self.metrics.as_ref(),
            )
            .await
            {
                resp
            } else if let Some(direct) =
                route.conditional_return(&parts, client_ip, downstream_proto, &request_id)
            {
                direct_response(&direct)
            } else if let Some(resp) = self
                .enforce_usage_plan(&route, authorization_identity.consumer.as_deref())
                .await
            {
                resp
            } else if let Some(resp) = self.enforce_limit_req(&parts, &route, client_ip).await {
                resp
            } else if let Some(resp) = self
                .enforce_limit_conn(&parts, &route, client_ip, &mut limit_conn_guards)
                .await
            {
                resp
            } else if let Some(resp) = self
                .enforce_traffic_limit(
                    &parts,
                    &route,
                    client_ip,
                    &mut forward_body,
                    &mut response_bandwidth_shaper,
                    &mut response_cost_settlement,
                )
                .await
            {
                resp
            } else if webtransport_request {
                // session 只有在普通 route 的认证、授权、WAF 与配额全部通过后才取得执行计划；
                // HTTP/3 adapter 还必须先连通固定上游，才能向客户端发送成功响应。
                self.prepare_webtransport(
                    &parts,
                    &route,
                    client_ip,
                    long_connection_consumer.clone(),
                    snap.version,
                )
            } else if connect_udp_request {
                // extended CONNECT 先完整经过与普通请求相同的安全管线，只有这里才把已匹配
                // route 的正向代理策略与逐次 DNS 结果交回 QUIC adapter。2xx 之前不创建 UDP socket。
                self.prepare_connect_udp(
                    &parts,
                    &route,
                    client_ip,
                    long_connection_consumer.clone(),
                    snap.version,
                )
                .await
            } else if connect_request {
                // CONNECT 是终端语义:它不进反代/缓存/上游选择,而是自成一条隧道路径。
                // 放在认证与限流之后,保证正向代理同样受身份与配额治理。
                self.handle_connect(&parts, &route, client_ip, &mut downstream_upgrade)
                    .await
            } else if let Some(resp) = lookup_route_cache(
                &route,
                &parts,
                proxy_runtime.id.as_str(),
                downstream_proto,
                &mut response_cache_key,
                &mut stale_cache_refresh,
                self.http_cache_runtime.as_ref(),
                self.metrics.as_ref(),
            )
            .await
            {
                if let Some(miss) = stale_cache_refresh.take() {
                    self.spawn_http_cache_revalidation(
                        snap.clone(),
                        proxy_id.clone(),
                        route.clone(),
                        parts.clone(),
                        miss,
                        client_ip,
                        trusted_inbound,
                        conn.client_cert_verified,
                        downstream_proto,
                        request_id.as_str().to_owned(),
                        request_origin.clone(),
                    );
                }
                resp
            } else if let Some(resp) = self.enforce_circuit_breakers(&route, &mut circuit_permits) {
                resp
            } else if is_cors_preflight(&parts, &route) {
                cors_preflight_response(route.cors.as_ref().expect("checked cors"), &parts)
            } else if let Some(response) =
                enforce_fault_injection(&route, &request_id, self.metrics.as_ref()).await
            {
                response
            } else if let Some(direct) = &route.direct_response {
                direct_response(direct)
            } else if let Some(redirect) = &route.gateway_redirect {
                match redirect.location(&parts, downstream_proto) {
                    Ok((status, location)) => gateway_redirect_response(status, &location),
                    Err(error) => {
                        tracing::warn!(route = %route.id, %error, "reject invalid Gateway API redirect request");
                        text_status(400, "invalid redirect authority")
                    }
                }
            } else if route
                .grpc_edge
                .as_ref()
                .is_some_and(|plan| plan.ws_bridge_path.as_deref() == Some(parts.uri.path()))
            {
                // WS 桥接只换传输外壳，鉴权/身份/索引/治理仍走同一条订阅路径；
                // 未配 ws_bridge_path 的 route 完全不进这里。
                self.handle_edge_ws_bridge(
                    &route,
                    &parts,
                    &mut downstream_upgrade,
                    client_ip,
                    long_connection_consumer.clone(),
                    snap.version,
                    proxy_runtime,
                )
                .await
            } else if let Some(edge_action) = route
                .grpc_edge
                .as_ref()
                .and_then(|plan| plan.match_method(parts.uri.path()))
            {
                // V8 边缘模式:仅在 route 显式启用且精确方法命中时进入自响应;同 route 的
                // 其余 RPC(含未命中方法的 gRPC)继续走下面的普通转发,一字节不受影响。
                self.handle_grpc_edge(
                    &route,
                    edge_action,
                    &parts,
                    &mut forward_body,
                    grpc_request,
                    client_ip,
                    long_connection_consumer.clone(),
                    snap.version,
                    proxy_runtime,
                )
                .await
            } else if route.bff_aggregation.is_some() {
                self.forward_bff(BffForwardRequest {
                    snap: &snap,
                    proxy: proxy_runtime,
                    route: &route,
                    parts,
                    client_ip,
                    trusted_inbound,
                    client_cert_verified: conn.client_cert_verified,
                    downstream_proto,
                    request_id: &request_id,
                    trace: &server_trace,
                })
                .await
            } else if let Some(mock) = &route.mock_response {
                self.metrics.inc_mock_response();
                mock_response(mock)
            } else if let Some(static_serve) = &route.static_serve {
                let eval_ctx = EvalContext {
                    parts: &parts,
                    client_ip,
                    downstream_proto,
                    request_id: &request_id,
                    route_id: route.id.as_str(),
                    response_status: None,
                };
                static_serve
                    .serve(&parts, route.variables.as_ref(), &eval_ctx)
                    .await
            } else if let Some(plan) = &route.dubbo {
                let media_type_ok = parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(';').next())
                    .is_some_and(|value| {
                        let value = value.trim().to_ascii_lowercase();
                        value == "application/json"
                            || (value.starts_with("application/") && value.ends_with("+json"))
                    });
                if !media_type_ok {
                    self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                    text_status(415, "Dubbo invocation content-type must be JSON")
                } else if too_large(&parts, plan.max_request_body_bytes()) {
                    self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                    text_status(413, "Dubbo invocation body is too large")
                } else {
                    let collected = crate::proxy::request_validation::collect_bounded(
                        forward_body
                            .take()
                            .expect("Dubbo request body remains available before forward"),
                        plan.max_request_body_bytes(),
                    )
                    .await;
                    match collected {
                        Err(crate::proxy::request_validation::CollectError::TooLarge) => {
                            self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                            text_status(413, "Dubbo invocation body is too large")
                        }
                        Err(crate::proxy::request_validation::CollectError::Read) => {
                            self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                            text_status(400, "Dubbo invocation body read failed")
                        }
                        Ok(collected) if collected.has_trailers() => {
                            self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                            text_status(400, "Dubbo invocation trailers are not supported")
                        }
                        Ok(collected) => match plan.parse_http_body(&collected.bytes) {
                            Err(crate::dubbo::DubboError::InvalidInput(message)) => {
                                self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                                text_status(400, message)
                            }
                            Err(_) => {
                                self.metrics.inc_dubbo(DubboMetric::InvalidInput);
                                text_status(400, "invalid Dubbo invocation")
                            }
                            Ok(invocation) => match self
                                .send_dubbo_request(&snap, proxy_runtime, &route, &invocation)
                                .await
                            {
                                Ok(response) => {
                                    upstream_circuit_outcome =
                                        Some(circuit_success(response.status()));
                                    upstream_write_status = Some(response.status());
                                    response
                                }
                                Err(error) => {
                                    if error.is_upstream_error() {
                                        self.metrics.inc_upstream_error();
                                    }
                                    upstream_circuit_outcome =
                                        Some(circuit_success(error.status()));
                                    tracing::warn!(route = %route.id, %error, "Dubbo upstream error");
                                    text_status(error.status().as_u16(), error.message())
                                }
                            },
                        },
                    }
                }
            } else if route.llm.is_some() {
                // LLM 分支的 future 约 8KiB，且只有显式 LLM route 会执行；在冷分支装箱可避免
                // 它把所有普通 HTTP/gRPC 请求的统一 service future 撑大，普通转发不新增分配。
                match Box::pin(
                    self.forward_llm(LlmForwardRequest {
                        snap: &snap,
                        proxy: proxy_runtime,
                        route: &route,
                        parts,
                        body: forward_body
                            .take()
                            .expect("LLM request body remains available before forward"),
                        client_ip,
                        trusted_inbound,
                        client_cert_verified: conn.client_cert_verified,
                        downstream_proto,
                        request_id: &request_id,
                        trace: &server_trace,
                        downstream_upgrade: if route.llm.as_ref().is_some_and(|policy| {
                            policy.api_type == crate::llm::LlmApiType::Realtime
                        }) {
                            downstream_upgrade.take()
                        } else {
                            None
                        },
                        limit_conn_guards: if route.llm.as_ref().is_some_and(|policy| {
                            policy.api_type == crate::llm::LlmApiType::Realtime
                        }) {
                            std::mem::take(&mut limit_conn_guards)
                        } else {
                            Vec::new()
                        },
                    }),
                )
                .await
                {
                    LlmForwardOutcome::Upstream(response) => {
                        upstream_circuit_outcome = Some(circuit_success(response.status()));
                        upstream_write_status = Some(response.status());
                        response
                    }
                    LlmForwardOutcome::Local(response) => response,
                }
            } else if too_large(&parts, proxy_runtime.limits.max_body_bytes) {
                text_status(413, "request body too large")
            } else {
                if response_cache_key.is_some() {
                    // L1 固定保存未压缩表示；不把客户端 Accept-Encoding 发给上游，避免
                    // 上游先压缩后导致缓存按 wire 编码分裂或额外转码。
                    parts.headers.remove(http::header::ACCEPT_ENCODING);
                }
                let limit_conn_guards_for_forward = if websocket_upgrade {
                    std::mem::take(&mut limit_conn_guards)
                } else {
                    Vec::new()
                };
                // 3. 流式转发上游。
                match self
                    .forward(forward::ForwardRequest {
                        snap: &snap,
                        proxy: proxy_runtime,
                        route: &route,
                        parts,
                        body: forward_body
                            .take()
                            .expect("request body remains available before forward"),
                        upstream_override: None,
                        path_override: None,
                        inference_endpoints: inference_selection.as_ref(),
                        client_ip,
                        client_ip_header: connection_client_ip_header,
                        trusted_inbound,
                        client_cert_verified: conn.client_cert_verified,
                        downstream_proto,
                        request_id: &request_id,
                        consumer: long_connection_consumer.clone(),
                        downstream_upgrade,
                        limit_conn_guards: limit_conn_guards_for_forward,
                        websocket_max_lifetime_ms: None,
                        websocket_frame_limits: None,
                        trace: Some(&server_trace),
                    })
                    .await
                {
                    Ok(resp) => {
                        // 在 error_page 改写前捕获上游真实状态,作为熔断判定信号(见上 upstream_circuit_outcome)。
                        upstream_circuit_outcome = Some(circuit_success(resp.status()));
                        upstream_write_status = Some(resp.status());
                        resp
                    }
                    Err(e) => {
                        if e.is_upstream_error() {
                            self.metrics.inc_upstream_error();
                        }
                        // 连接失败/超时/协议错都是熔断意义上的失败(502/503/504),必须计入。
                        upstream_circuit_outcome = Some(circuit_success(e.status()));
                        tracing::warn!(route = %route.id, error = %e, "upstream error");
                        let mut resp = text_status(e.status().as_u16(), e.message());
                        if route.fallback_headers {
                            apply_fallback_headers(&mut resp, e.fallback_reason());
                        }
                        resp
                    }
                }
            }
        };

        let mut response_route = matched_route.clone();
        if let Some(route) = response_route.clone() {
            if route.x_accel_redirect {
                if let Some(target) = x_accel_redirect_target(&resp) {
                    let upstream_trace = resp.extensions().get::<forward::UpstreamTrace>().cloned();
                    match internal_reroute_parts.as_deref() {
                        Some(original_parts) => {
                            match self
                                .serve_internal_reroute(InternalRerouteRequest {
                                    proxy: proxy_runtime,
                                    original_parts,
                                    target,
                                    client_ip,
                                    downstream_proto,
                                    request_id: &request_id,
                                    upstream_trace,
                                })
                                .await
                            {
                                Ok((rerouted, reroute_route)) => {
                                    resp = rerouted;
                                    route_id = Some(reroute_route.id_shared.clone());
                                    response_route = Some(reroute_route);
                                }
                                Err(fallback) => {
                                    resp = fallback;
                                }
                            }
                        }
                        None => resp = text_status(500, "internal reroute context unavailable"),
                    }
                }
            }
        }
        for _ in 0..MAX_INTERNAL_REROUTES {
            let Some(route) = response_route.clone() else {
                break;
            };
            let Some(policy) = select_error_page_policy(&resp, &route) else {
                break;
            };
            match &policy.action {
                ErrorPageAction::Response(_) => {
                    resp = apply_error_page_response(resp, policy);
                    break;
                }
                ErrorPageAction::Reroute(target) => {
                    let upstream_trace = resp.extensions().get::<forward::UpstreamTrace>().cloned();
                    let Some(original_parts) = internal_reroute_parts.as_deref() else {
                        resp = text_status(500, "internal reroute context unavailable");
                        break;
                    };
                    match self
                        .serve_internal_reroute(InternalRerouteRequest {
                            proxy: proxy_runtime,
                            original_parts,
                            target,
                            client_ip,
                            downstream_proto,
                            request_id: &request_id,
                            upstream_trace,
                        })
                        .await
                    {
                        Ok((rerouted, reroute_route)) => {
                            resp = rerouted;
                            route_id = Some(reroute_route.id_shared.clone());
                            response_route = Some(reroute_route);
                        }
                        Err(fallback) => {
                            resp = fallback;
                            break;
                        }
                    }
                }
            }
        }
        if upstream_write_status.is_some_and(|status| status.is_success())
            && !matches!(
                response_method,
                Method::GET | Method::HEAD | Method::OPTIONS
            )
        {
            if let Some(route) = matched_route.as_ref() {
                self.invalidate_caches_after_write(proxy_runtime, route)
                    .await;
            }
        }
        if let Some(route) = &response_route {
            let cache_hit = resp.extensions().get::<HttpCacheHit>().is_some();
            if !cache_hit {
                apply_response_filters(
                    &mut resp,
                    route,
                    request_origin.as_ref(),
                    response_filter_parts.as_deref(),
                    client_ip,
                    downstream_proto,
                    &request_id,
                );
                if !route.sub_filters.is_empty() {
                    resp = wrap_sub_filter_response(resp, route.sub_filters.clone());
                }
                // internal reroute/error_page 换 route 后不把目标响应写进原 route key，避免串缓存。
                if matched_route
                    .as_ref()
                    .map(|matched| Arc::ptr_eq(matched, route))
                    .unwrap_or(false)
                {
                    if let (Some(policy), Some(key)) =
                        (&route.http_cache, response_cache_key.take())
                    {
                        resp = policy.wrap_fill(
                            resp,
                            key,
                            self.http_cache_runtime.clone(),
                            self.metrics.clone(),
                        );
                    }
                }
            }
            if let (Some(matched), Some(request_head)) =
                (matched_route.as_ref(), external_response_request.take())
            {
                if matched.external_plugins.is_some() {
                    if let Some(local) = self
                        .enforce_external_response_headers(
                            &snap,
                            proxy_runtime,
                            matched,
                            &mut resp,
                            request_head.as_ref(),
                            &request_id,
                            &server_trace,
                        )
                        .await
                    {
                        resp = local;
                    }
                }
            }
            if let Some(matched) = matched_route.as_ref() {
                resp = self
                    .enforce_ext_proc_response(
                        matched,
                        resp,
                        &mut ext_proc_session,
                        &response_method,
                    )
                    .await;
            }
            if let (Some(matched), Some(request_head)) =
                (matched_route.as_ref(), wasm_response_request.take())
            {
                if let Some(chain) = &matched.wasm_plugins {
                    let request_head = *request_head;
                    let end_of_stream = resp.body().is_end_stream();
                    let mut local_response = false;
                    match chain
                        .execute_response(&mut resp, request_head.clone(), end_of_stream)
                        .await
                    {
                        Ok(execution) => {
                            for _ in 0..execution.failed_open {
                                self.metrics
                                    .inc_wasm_execution(WasmExecutionMetric::FailOpen);
                            }
                            if let Some(local) = execution.local_response {
                                self.metrics
                                    .inc_wasm_execution(WasmExecutionMetric::LocalResponse);
                                resp = local;
                                local_response = true;
                            } else {
                                self.metrics
                                    .inc_wasm_execution(WasmExecutionMetric::Continue);
                            }
                        }
                        Err(error) => {
                            self.metrics.inc_wasm_execution(WasmExecutionMetric::Error);
                            tracing::warn!(route = %matched.id, %error, "Proxy-Wasm response plugin failed closed");
                            resp = text_status(500, "Proxy-Wasm response plugin failed");
                            local_response = true;
                        }
                    }
                    if !local_response && chain.has_response_body() {
                        let (mut response_parts, response_body) = resp.into_parts();
                        match collect_wasm_box_body(response_body, chain.response_body_limit())
                            .await
                        {
                            Ok(collected) => match chain
                                .execute_response_body(
                                    &mut response_parts.headers,
                                    collected.bytes,
                                    request_head,
                                )
                                .await
                            {
                                Ok(execution) => {
                                    for _ in 0..execution.failed_open {
                                        self.metrics
                                            .inc_wasm_execution(WasmExecutionMetric::FailOpen);
                                    }
                                    if let Some(local) = execution.local_response {
                                        self.metrics
                                            .inc_wasm_execution(WasmExecutionMetric::LocalResponse);
                                        resp = local;
                                    } else {
                                        self.metrics
                                            .inc_wasm_execution(WasmExecutionMetric::Continue);
                                        let bytes = execution.body.unwrap_or_default();
                                        normalize_content_length(
                                            &mut response_parts.headers,
                                            bytes.len(),
                                        );
                                        resp = Response::from_parts(
                                            response_parts,
                                            replay_wasm_body(bytes, collected.trailers),
                                        );
                                    }
                                }
                                Err(error) => {
                                    self.metrics.inc_wasm_execution(WasmExecutionMetric::Error);
                                    tracing::warn!(route = %matched.id, %error, "Proxy-Wasm response body plugin failed closed");
                                    resp =
                                        text_status(500, "Proxy-Wasm response body plugin failed");
                                }
                            },
                            Err(WasmBodyError::TooLarge) => {
                                self.metrics.inc_wasm_execution(WasmExecutionMetric::Error);
                                resp = text_status(500, "Proxy-Wasm response body exceeds limit");
                            }
                            Err(WasmBodyError::Read(error)) => {
                                self.metrics.inc_wasm_execution(WasmExecutionMetric::Error);
                                tracing::warn!(route = %matched.id, %error, "read Proxy-Wasm response body failed");
                                resp = text_status(500, "Proxy-Wasm response body read failed");
                            }
                        }
                    } else if !local_response && chain.has_response_body_stream() {
                        let (mut response_parts, response_body) = resp.into_parts();
                        match chain
                            .wrap_response_body_stream(
                                &mut response_parts.headers,
                                response_body,
                                request_head,
                            )
                            .await
                        {
                            Ok(stream) => {
                                self.metrics
                                    .inc_wasm_execution(WasmExecutionMetric::Continue);
                                resp = Response::from_parts(response_parts, stream);
                            }
                            Err(error) => {
                                self.metrics.inc_wasm_execution(WasmExecutionMetric::Error);
                                tracing::warn!(route = %matched.id, %error, "Proxy-Wasm response streaming lifecycle failed closed");
                                resp =
                                    text_status(500, "Proxy-Wasm response streaming plugin failed");
                            }
                        }
                    }
                }
            }
            if let Some(obligations) = opa_response_obligations.take() {
                // obligations 已在 decision 整体解析时验证；放在响应插件之后，避免插件覆盖安全策略，
                // 又必须早于压缩以免任何 framing header 有机会参与（framing 名称本身也永久禁用）。
                obligations.apply_response(resp.headers_mut());
            }
            let mut contract_eligible = true;
            if let Some(transform) = &route.response_transform {
                match transform.transform_response(resp).await {
                    Ok(transformed) => {
                        self.metrics
                            .inc_body_transform(crate::metrics::BodyTransformMetric::Transformed);
                        resp = transformed;
                    }
                    Err(outcome) => {
                        crate::proxy::response_contract::record_transform_failure(
                            self.metrics.as_ref(),
                            &outcome,
                        );
                        let message = match outcome {
                            crate::proxy::response_contract::TransformOutcome::TooLarge => {
                                "upstream response transform exceeds limit"
                            }
                            crate::proxy::response_contract::TransformOutcome::ReadFailed => {
                                "upstream response transform read failed"
                            }
                            crate::proxy::response_contract::TransformOutcome::Invalid(message) => {
                                tracing::warn!(route = %route.id, reason = message, "response body transform rejected input");
                                "upstream response transform failed"
                            }
                            crate::proxy::response_contract::TransformOutcome::Transformed {
                                ..
                            } => unreachable!("successful response transform is handled above"),
                        };
                        // 原实体已经被消费或判定不安全，契约不能再检查本地替代错误并覆盖失败原因。
                        contract_eligible = false;
                        resp = text_status(502, message);
                    }
                }
            }
            if contract_eligible {
                if let Some(contract) = &route.response_contract {
                    resp = contract
                        .enforce(resp, &response_method, self.metrics.clone())
                        .await;
                }
            }
            resp = enforce_dlp_response(route, resp, self.metrics.as_ref()).await;
            if let Some((route, policy)) = matched_route
                .as_ref()
                .and_then(|route| route.csrf.as_ref().map(|policy| (route, policy)))
            {
                if policy.should_issue(&response_method, resp.status()) {
                    // token 必须在响应插件和缓存包装之后签发，防止插件覆盖安全 header，也避免
                    // 每客户端 token 被写入共享缓存；签发失败不能返回一个假装可继续的成功响应。
                    if let Err(error) =
                        policy.issue_response_token(resp.headers_mut(), route.id.as_str())
                    {
                        tracing::error!(route = %route.id, %error, "issue CSRF token failed");
                        resp = text_status(500, "CSRF token issuance failed");
                    }
                }
            }
            if let Some(policy) = &route.compression {
                resp = apply_response_compression(
                    resp,
                    policy,
                    accepted_encodings.expect("compression route requires parsed negotiation"),
                    &response_method,
                    self.metrics.as_ref(),
                );
            }
            if let Some(policy) = route.limit_rate {
                resp = wrap_limit_rate_response(resp, policy);
            }
            if let Some(shaper) = response_bandwidth_shaper.take() {
                resp = resp.map(|body| {
                    ShapedBody {
                        inner: Box::pin(body),
                        shaper,
                        pending: None,
                        sleep: None,
                    }
                    .boxed()
                });
            }
            if let Some(mut settlement) = response_cost_settlement.take() {
                settlement.validate_response_headers(resp.headers());
                resp = resp.map(|body| {
                    SettledTrafficBody {
                        inner: Box::pin(body),
                        settlement: Some(settlement),
                    }
                    .boxed()
                });
            }
        }
        if !circuit_permits.is_empty() {
            match upstream_circuit_outcome {
                // 真正打了上游:按上游真实结果推进熔断状态机。
                Some(success) => self.record_circuit_result(circuit_permits, success).await,
                // 未打上游(CORS 预检/静态/直接响应/413 等短路):不记账,只释放本次占用的半开探测名额,
                // 否则短路响应会污染窗口、并把一次「其实没测上游」误当成半开探测成功。
                None => self.cancel_circuit_permits(circuit_permits),
            }
        }
        if grpc_request
            && resp
                .extensions()
                .get::<forward::GrpcDrainAttached>()
                .is_none()
            && is_native_grpc_response(&resp)
        {
            if let Some(route) = &response_route {
                resp = wrap_grpc_drain_response(
                    resp,
                    &self.conn_registry,
                    route.id_shared.clone(),
                    client_ip,
                    long_connection_consumer.clone(),
                    snap.version,
                    route.long_stream_max_lifetime_ms,
                );
            }
        } else if is_sse_response(&resp) {
            if let Some(route) = &response_route {
                resp = wrap_sse_drain_response(
                    resp,
                    &self.conn_registry,
                    route.id_shared.clone(),
                    client_ip,
                    long_connection_consumer.clone(),
                    snap.version,
                    route
                        .long_stream_idle_timeout_ms
                        .unwrap_or(proxy_runtime.timeouts.stream_idle_timeout_ms),
                    route.long_stream_max_lifetime_ms,
                );
            }
        }
        resp = wrap_limit_conn_response(resp, limit_conn_guards);
        // ★HSTS(§19)★:只在 TLS 响应带 Strict-Transport-Security(http 响应带它浏览器会忽略);不覆盖上游/路由已设的。
        if downstream_proto == "https" {
            if let Some(hsts) = &proxy_runtime.hsts_header {
                if !resp
                    .headers()
                    .contains_key(http::header::STRICT_TRANSPORT_SECURITY)
                {
                    resp.headers_mut()
                        .insert(http::header::STRICT_TRANSPORT_SECURITY, hsts.clone());
                }
            }
        }
        apply_http3_advertisement(
            &mut resp,
            &proxy_runtime.http3,
            downstream_proto,
            downstream_version,
        );
        let upstream_trace = resp.extensions().get::<forward::UpstreamTrace>().cloned();
        // 会话保持载体在全部 post filter 之后、写下游之前下发:此时最终实例已确定,
        // 且不会被后续 header 规则覆盖。未配置会话保持的服务不产生任何额外 header。
        if let Some(trace) = upstream_trace.as_ref() {
            forward::apply_session_affinity(&mut resp, &snap, trace);
        }
        let status = resp.status();
        let upstream_attempts = upstream_trace
            .as_ref()
            .map(|trace| trace.attempts)
            .unwrap_or(0);
        server_trace.finish(
            status.as_u16(),
            route_id.as_deref(),
            upstream_trace
                .as_ref()
                .map(|trace| trace.final_upstream.as_ref()),
            upstream_attempts,
        );
        self.metrics.inc_response(status.as_u16());
        self.metrics.observe_request_duration(started.elapsed());
        self.finish_access(access_log_enabled, || {
            let (method, path) = access_log_head.expect("enabled access log has request head");
            AccessRecord {
                method,
                path,
                request_id: request_id.as_str().to_owned(),
                trace_id: Some(server_trace.trace_id()),
                route_id,
                upstream: upstream_trace
                    .as_ref()
                    .map(|trace| trace.final_upstream.clone()),
                upstream_attempts,
                status: status.as_u16(),
                elapsed: started.elapsed(),
                peer: audit_peer(&conn, client_ip, trusted_inbound),
                bytes_downstream_to_upstream: None,
                bytes_upstream_to_downstream: None,
            }
        });
        Ok(resp)
    }

    /// 业务作用：在任何认证、插件、配额或上游副作用前裁决真实 QUIC early data，并用
    /// 一次性 nonce 账本阻止同一请求在有效窗口内再次执行。
    ///
    /// 参数说明：`route` 是当前快照命中的路由；`parts` 是待转发请求头；`transport_early`
    /// 只来自 Quinn 接收流；`transport_body` 表示 adapter 已看到 DATA 或 trailers；`proxy_id`
    /// 隔离不同 listener 下可能同名的 route。
    ///
    /// 返回：普通 1-RTT 或全部门禁通过时返回 `None` 并继续管线；early data 不满足条件时
    /// 返回不可缓存的 425 响应，且不会读取请求 body 或触发任何外部调用。
    async fn enforce_early_data(
        &self,
        route: &Route,
        parts: &mut Parts,
        transport_early: bool,
        transport_body: bool,
        proxy_id: &str,
    ) -> Option<Response<BoxBody>> {
        const EARLY_DATA_HEADER: &str = "early-data";
        const NONCE_HEADER: &str = "x-naway-early-data-nonce";

        let indicator = {
            let mut values = parts.headers.get_all(EARLY_DATA_HEADER).iter();
            let first = values.next().cloned();
            let repeated = values.next().is_some();
            (first, repeated)
        };
        let nonce = {
            let mut values = parts.headers.get_all(NONCE_HEADER).iter();
            let first = values.next().cloned();
            let repeated = values.next().is_some();
            (first, repeated)
        };
        // 两个字段只用于本 listener 的 transport 门禁；无论是否为 early stream 都必须在
        // 进入插件和上游前删除，防止客户端伪造内部证据或让上游误判请求安全级别。
        parts.headers.remove(EARLY_DATA_HEADER);
        parts.headers.remove(NONCE_HEADER);
        if !transport_early {
            return None;
        }

        let denial = if route.early_data.is_none() {
            Some(crate::masque::EarlyDataDenial::NotEnabled)
        } else if !matches!(
            parts.method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        ) {
            Some(crate::masque::EarlyDataDenial::NonIdempotentMethod)
        } else if [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "x-amz-security-token",
            "x-goog-api-key",
        ]
        .iter()
        .any(|name| parts.headers.contains_key(*name))
        {
            Some(crate::masque::EarlyDataDenial::SensitiveCredential)
        } else if transport_body || parts.headers.contains_key(http::header::TRANSFER_ENCODING) || {
            let mut lengths = parts.headers.get_all(http::header::CONTENT_LENGTH).iter();
            match (lengths.next(), lengths.next()) {
                (None, None) => false,
                (Some(value), None) => {
                    value.to_str().ok().and_then(|raw| raw.parse::<u64>().ok()) != Some(0)
                }
                _ => true,
            }
        } {
            Some(crate::masque::EarlyDataDenial::RequestBody)
        } else if indicator.0.is_none() {
            Some(crate::masque::EarlyDataDenial::MissingIndicator)
        } else if indicator.1
            || indicator
                .0
                .as_ref()
                .is_none_or(|value| value.as_bytes() != b"1")
        {
            Some(crate::masque::EarlyDataDenial::InvalidIndicator)
        } else if nonce.0.is_none() {
            Some(crate::masque::EarlyDataDenial::MissingNonce)
        } else if nonce.1 {
            Some(crate::masque::EarlyDataDenial::InvalidNonce)
        } else {
            None
        };

        let decoded_nonce = if denial.is_none() {
            nonce.0.as_ref().and_then(|value| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(value.as_bytes())
                    .ok()
                    .filter(|decoded| decoded.len() == 32)
            })
        } else {
            None
        };
        let mut denial = denial.or_else(|| {
            decoded_nonce
                .is_none()
                .then_some(crate::masque::EarlyDataDenial::InvalidNonce)
        });

        if denial.is_none() {
            let mut hasher = Sha256::new();
            for field in [
                proxy_id.as_bytes(),
                route.id.as_bytes(),
                parts.method.as_str().as_bytes(),
                parts
                    .headers
                    .get(http::header::HOST)
                    .map(HeaderValue::as_bytes)
                    .unwrap_or_default(),
                parts
                    .uri
                    .path_and_query()
                    .map(|value| value.as_str().as_bytes())
                    .unwrap_or_else(|| parts.uri.path().as_bytes()),
                decoded_nonce
                    .as_deref()
                    .expect("nonce presence checked before replay lookup"),
            ] {
                hasher.update((field.len() as u64).to_be_bytes());
                hasher.update(field);
            }
            let digest = hasher.finalize();
            let mut replay_key = String::with_capacity(64);
            use std::fmt::Write as _;
            for byte in digest {
                write!(&mut replay_key, "{byte:02x}")
                    .expect("writing SHA-256 hex to String cannot fail");
            }
            let replay_window = route
                .early_data
                .as_ref()
                .expect("early-data route checked before replay lookup")
                .replay_window();
            // 去重占位必须在任何业务副作用前提交；账本不可用时配置层要求失败闭合，不能以
            // 可用性为由执行一份没有重放证据的请求。
            if !self
                .replay_guard
                .check_and_set(&replay_key, replay_window)
                .await
            {
                denial = Some(crate::masque::EarlyDataDenial::Replayed);
            }
        }

        self.metrics.inc_early_data(denial);
        if denial.is_none() {
            return None;
        }
        let mut response = text_status(StatusCode::TOO_EARLY.as_u16(), "too early");
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        Some(response)
    }

    /// 执行 V6 多模型统一入口：一次有界读取/解析，下游凭据隔离，然后按配置顺序 fallback。
    async fn forward_bff(&self, ctx: BffForwardRequest<'_>) -> Response<BoxBody> {
        if ctx.parts.method != Method::GET {
            self.metrics.inc_bff_request("error");
            return text_status(405, "BFF aggregation only supports GET");
        }
        let policy = ctx
            .route
            .bff_aggregation
            .as_ref()
            .expect("forward_bff is called only for a BFF route");
        let mut futures = FuturesUnordered::new();
        for target in policy.targets.iter() {
            // 从空 Parts 开始，只复制显式 allowlist header。直接 clone 下游 Parts 再 clear 会先
            // clone 整份 HeaderMap（包括敏感大 header），违背 BFF 的最小披露与少拷贝目标。
            let (mut child_parts, _) = Request::new(()).into_parts();
            child_parts.method = Method::GET;
            child_parts.version = ctx.parts.version;
            child_parts.uri = target
                .path
                .parse()
                .expect("BFF path validated during snapshot build");
            for name in target.forward_headers.iter() {
                for value in ctx.parts.headers.get_all(name).iter() {
                    child_parts.headers.append(name.clone(), value.clone());
                }
            }
            let future = async move {
                let attempt = self
                    .forward(forward::ForwardRequest {
                        snap: ctx.snap,
                        proxy: ctx.proxy,
                        route: ctx.route,
                        parts: child_parts,
                        body: full_body(Bytes::new()),
                        upstream_override: Some(target.uri.as_ref()),
                        path_override: Some(target.path.as_ref()),
                        inference_endpoints: None,
                        client_ip: ctx.client_ip,
                        client_ip_header: None,
                        trusted_inbound: ctx.trusted_inbound,
                        client_cert_verified: ctx.client_cert_verified,
                        downstream_proto: ctx.downstream_proto,
                        request_id: ctx.request_id,
                        consumer: None,
                        downstream_upgrade: None,
                        limit_conn_guards: Vec::new(),
                        websocket_max_lifetime_ms: None,
                        websocket_frame_limits: None,
                        trace: Some(ctx.trace),
                    })
                    .await
                    .map_err(|_| BffTargetFailure::Unavailable);
                let value = match attempt {
                    Ok(response) => {
                        collect_bff_json_response(response, target.max_response_bytes).await
                    }
                    Err(error) => Err(error),
                };
                (target, value)
            };
            futures.push(async move {
                match tokio::time::timeout(target.timeout, future).await {
                    Ok(result) => result,
                    Err(_) => (target, Err(BffTargetFailure::Timeout)),
                }
            });
        }

        let aggregate = async {
            let mut values = BTreeMap::<String, serde_json::Value>::new();
            let mut errors = BTreeMap::<String, serde_json::Value>::new();
            while let Some((target, result)) = futures.next().await {
                match result {
                    Ok(value) => {
                        self.metrics.inc_bff_target(true);
                        values.insert(target.id.to_string(), value);
                    }
                    Err(error) => {
                        self.metrics.inc_bff_target(false);
                        if target.required {
                            return Err(error);
                        }
                        values.insert(target.id.to_string(), serde_json::Value::Null);
                        errors.insert(
                            target.id.to_string(),
                            serde_json::Value::String(error.code().to_owned()),
                        );
                    }
                }
            }
            if !errors.is_empty() {
                values.insert(
                    "_errors".to_owned(),
                    serde_json::to_value(errors)
                        .expect("BTreeMap JSON serialization is infallible"),
                );
            }
            let mut writer = BffBoundedWriter::new(policy.max_total_response_bytes);
            serde_json::to_writer(&mut writer, &values).map_err(|_| BffTargetFailure::TooLarge)?;
            Ok::<Bytes, BffTargetFailure>(Bytes::from(writer.finish()))
        };
        match tokio::time::timeout(policy.total_timeout, aggregate).await {
            Ok(Ok(body)) => {
                self.metrics.inc_bff_request("success");
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("x-gateway-bff", "aggregated")
                    .body(full_body(body))
                    .expect("fixed BFF response")
            }
            Ok(Err(error)) => {
                self.metrics.inc_bff_request("error");
                text_status(error.response_status().as_u16(), "BFF aggregation failed")
            }
            Err(_) => {
                self.metrics.inc_bff_request("timeout");
                text_status(504, "BFF aggregation timed out")
            }
        }
    }

    async fn forward_llm(&self, mut ctx: LlmForwardRequest<'_>) -> LlmForwardOutcome {
        let policy = ctx
            .route
            .llm
            .as_ref()
            .expect("forward_llm is called only for an LLM route");
        if policy.api_type != crate::llm::LlmApiType::ChatCompletions {
            return self.forward_native_ai(ctx, policy).await;
        }
        if content_length_exceeds(&ctx.parts, policy.max_body_bytes) {
            return LlmForwardOutcome::Local(text_status(413, "LLM request body too large"));
        }
        let body = std::mem::replace(&mut ctx.body, full_body(Bytes::new()));
        let raw = match collect_llm_body(body, policy.max_body_bytes).await {
            Ok(raw) => raw,
            Err(LlmBodyError::TooLarge) => {
                return LlmForwardOutcome::Local(text_status(413, "LLM request body too large"));
            }
            Err(LlmBodyError::Invalid(error)) => {
                tracing::debug!(route = %ctx.route.id, %error, "invalid LLM request body");
                return LlmForwardOutcome::Local(text_status(400, "invalid LLM request body"));
            }
        };
        let mut request = match crate::llm::ParsedLlmRequest::parse(raw) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(route = %ctx.route.id, %error, "invalid unified LLM request");
                return LlmForwardOutcome::Local(text_status(400, "invalid LLM request"));
            }
        };
        if policy.blocked_prompt(&request).is_some() {
            // 不把完整 prompt 或命中片段写日志；route 是低基数配置值，足够关联规则排查。
            tracing::warn!(route = %ctx.route.id, "LLM prompt blocked by configured guardrail");
            return LlmForwardOutcome::Local(text_status(403, "LLM prompt blocked by guardrail"));
        }
        // 只在客户端原始 messages 通过护栏后注入可信 system prompt，避免固定安全模板中的
        // 防御性措辞被用户输入规则反向命中；注入后再执行总 token 上限。
        if let Err(error) = policy.decorate_prompt(&mut request) {
            tracing::debug!(route = %ctx.route.id, %error, "LLM system prompt decoration failed");
            return LlmForwardOutcome::Local(text_status(400, "invalid LLM prompt decoration"));
        }
        if request.prompt_tokens > policy.max_prompt_tokens {
            return LlmForwardOutcome::Local(text_status(413, "LLM prompt token limit exceeded"));
        }
        let reserved_tokens = match request.reserve_tokens(policy.max_completion_tokens) {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::debug!(route = %ctx.route.id, %error, "invalid LLM completion token limit");
                return LlmForwardOutcome::Local(text_status(400, "invalid LLM max_tokens"));
            }
        };
        if let Some(moderation) = policy.moderation.as_ref() {
            let moderation_body = match moderation.body(&request) {
                Ok(body) => body,
                Err(error) => {
                    tracing::debug!(route = %ctx.route.id, %error, "LLM moderation request cannot represent prompt");
                    self.metrics.inc_llm_moderation(LlmModerationMetric::Error);
                    return LlmForwardOutcome::Local(text_status(
                        400,
                        "LLM prompt is unsupported by moderation policy",
                    ));
                }
            };
            match self
                .call_llm_moderation(&ctx, moderation.as_ref(), moderation_body)
                .await
            {
                Ok(true) => {
                    self.metrics
                        .inc_llm_moderation(LlmModerationMetric::Blocked);
                    tracing::warn!(route = %ctx.route.id, "LLM prompt blocked by external moderation");
                    return LlmForwardOutcome::Local(text_status(
                        403,
                        "LLM prompt blocked by moderation",
                    ));
                }
                Ok(false) => self
                    .metrics
                    .inc_llm_moderation(LlmModerationMetric::Allowed),
                Err(error)
                    if moderation.fail_mode
                        == crate::config::model::LlmModerationFailModeCfg::Open =>
                {
                    // fail-open 只处理依赖不可判定；明确 flagged 已在上一个分支永久拒绝，
                    // 因此外部服务不能用错误响应把已判定的拦截降级成放行。
                    self.metrics
                        .inc_llm_moderation(LlmModerationMetric::FailOpen);
                    tracing::warn!(route = %ctx.route.id, %error, "LLM moderation unavailable; fail-open policy continues");
                }
                Err(error) => {
                    self.metrics.inc_llm_moderation(LlmModerationMetric::Error);
                    tracing::warn!(route = %ctx.route.id, %error, "LLM moderation unavailable; fail-closed policy rejects");
                    return LlmForwardOutcome::Local(text_status(
                        503,
                        "LLM moderation unavailable",
                    ));
                }
            }
        }
        let quota_key = if let Some(quota) = &policy.token_quota {
            let dimension = match quota.dimension {
                crate::config::model::LlmQuotaDimensionCfg::Route => ctx.route.id.clone(),
                crate::config::model::LlmQuotaDimensionCfg::Consumer => ctx
                    .route
                    .authenticated_consumer(&ctx.parts)
                    .unwrap_or_else(|| Arc::from("anonymous"))
                    .to_string(),
                crate::config::model::LlmQuotaDimensionCfg::ApiKey => {
                    let Some(fingerprint) = ctx.route.authenticated_api_key_fingerprint(&ctx.parts)
                    else {
                        return LlmForwardOutcome::Local(text_status(
                            401,
                            "authenticated API key required for LLM quota",
                        ));
                    };
                    fingerprint
                }
            };
            let scope = format!("llm:{}", ctx.route.id);
            let key = format!("{}:{:016x}", scope, stable_hash64(dimension.as_bytes()));
            Some((scope, key))
        } else {
            None
        };

        let mut cache_fill = None;
        if !request.stream {
            if let Some(cache) = policy.semantic_cache.clone() {
                let scope_identity = match cache.scope {
                    crate::config::model::LlmCacheScopeCfg::Route => ctx.route.id.clone(),
                    crate::config::model::LlmCacheScopeCfg::Consumer => ctx
                        .route
                        .authenticated_consumer(&ctx.parts)
                        .unwrap_or_else(|| Arc::from("anonymous"))
                        .to_string(),
                    crate::config::model::LlmCacheScopeCfg::ApiKey => {
                        let Some(fingerprint) =
                            ctx.route.authenticated_api_key_fingerprint(&ctx.parts)
                        else {
                            return LlmForwardOutcome::Local(text_status(
                                401,
                                "authenticated API key required for LLM cache scope",
                            ));
                        };
                        fingerprint
                    }
                };
                // route 与身份按长度分隔后摘要；Redis/L1 key 不包含原 consumer/API key/prompt。
                let mut scope_hasher = Sha256::new();
                scope_hasher.update(b"gw-llm-cache-scope-v1\0");
                scope_hasher.update(policy.cache_salt);
                scope_hasher.update((ctx.route.id.len() as u64).to_be_bytes());
                scope_hasher.update(ctx.route.id.as_bytes());
                scope_hasher.update((scope_identity.len() as u64).to_be_bytes());
                scope_hasher.update(scope_identity.as_bytes());
                let scope_digest: [u8; 32] = scope_hasher.finalize().into();
                let scope = crate::llm::digest_hex(&scope_digest);
                let exact_digest = request.exact_cache_digest(&scope_digest);
                if let Some(entry) = cache.lookup_exact(&exact_digest).await {
                    self.metrics.inc_llm_cache_hit(false, false);
                    return LlmForwardOutcome::Local(llm_cached_response(
                        policy, entry, "exact-l1",
                    ));
                }
                let exact_hex = crate::llm::digest_hex(&exact_digest);
                if cache.l2_enabled {
                    match self
                        .http_cache_runtime
                        .llm_cache_get_exact(
                            scope.as_str(),
                            exact_hex.as_str(),
                            cache.max_response_bytes.saturating_add(512),
                        )
                        .await
                    {
                        Ok(Some(encoded)) => {
                            match crate::llm::decode_l2_response(encoded, cache.max_response_bytes)
                            {
                                Ok((model_id, body)) => {
                                    let entry = cache
                                        .insert(
                                            exact_digest,
                                            [0; 32],
                                            Arc::from([]),
                                            body,
                                            model_id,
                                        )
                                        .await;
                                    self.metrics.inc_llm_cache_hit(false, true);
                                    return LlmForwardOutcome::Local(llm_cached_response(
                                        policy, entry, "exact-l2",
                                    ));
                                }
                                Err(error) => {
                                    tracing::warn!(route = %ctx.route.id, %error, "discard malformed LLM exact L2 entry");
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::debug!(route = %ctx.route.id, %error, "LLM exact L2 lookup failed; continue as miss");
                        }
                    }
                }

                let params_digest = match request.semantic_params_digest(&scope_digest) {
                    Ok(digest) => digest,
                    Err(error) => {
                        tracing::debug!(route = %ctx.route.id, %error, "LLM semantic parameter hashing failed; exact cache remains available");
                        [0; 32]
                    }
                };
                let vector = match self
                    .fetch_llm_embedding(&ctx, &request, cache.as_ref())
                    .await
                {
                    Ok(vector) => Some(vector),
                    Err(error) => {
                        // Cache is an optimization: embedding failure must not upgrade into route failure.
                        tracing::warn!(route = %ctx.route.id, %error, "LLM embedding unavailable; bypass semantic cache");
                        None
                    }
                };
                if let Some(vector) = vector.as_ref() {
                    if let Some(entry) = cache.lookup_semantic(&params_digest, vector.as_ref()) {
                        self.metrics.inc_llm_cache_hit(true, false);
                        return LlmForwardOutcome::Local(llm_cached_response(
                            policy,
                            entry,
                            "semantic-l1",
                        ));
                    }
                    if cache.l2_enabled {
                        match self
                            .http_cache_runtime
                            .llm_cache_candidates(
                                scope.as_str(),
                                cache.max_candidates(),
                                cache.embedding.max_dimensions,
                            )
                            .await
                        {
                            Ok(candidates) => {
                                if let Some((matched_digest, matched_vector)) =
                                    crate::llm::best_l2_candidate(
                                        &candidates,
                                        &params_digest,
                                        vector.as_ref(),
                                        cache.threshold(),
                                    )
                                {
                                    let matched_hex = crate::llm::digest_hex(&matched_digest);
                                    match self
                                        .http_cache_runtime
                                        .llm_cache_get_exact(
                                            scope.as_str(),
                                            matched_hex.as_str(),
                                            cache.max_response_bytes.saturating_add(512),
                                        )
                                        .await
                                    {
                                        Ok(Some(encoded)) => {
                                            match crate::llm::decode_l2_response(
                                                encoded,
                                                cache.max_response_bytes,
                                            ) {
                                                Ok((model_id, body)) => {
                                                    let entry = cache
                                                        .insert(
                                                            matched_digest,
                                                            params_digest,
                                                            matched_vector,
                                                            body,
                                                            model_id,
                                                        )
                                                        .await;
                                                    self.metrics.inc_llm_cache_hit(true, true);
                                                    return LlmForwardOutcome::Local(
                                                        llm_cached_response(
                                                            policy,
                                                            entry,
                                                            "semantic-l2",
                                                        ),
                                                    );
                                                }
                                                Err(error) => {
                                                    tracing::warn!(route = %ctx.route.id, %error, "discard malformed LLM semantic L2 response")
                                                }
                                            }
                                        }
                                        Ok(None) => {}
                                        Err(error) => {
                                            tracing::debug!(route = %ctx.route.id, %error, "LLM semantic L2 response lookup failed")
                                        }
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::debug!(route = %ctx.route.id, %error, "LLM semantic L2 index lookup failed; continue as miss")
                            }
                        }
                    }
                }
                cache_fill = Some(LlmCacheFill {
                    policy: cache,
                    scope,
                    exact_digest,
                    params_digest,
                    vector,
                });
            }
        }

        let mut quota_reservation = None;
        if let (Some(quota), Some((scope, key))) = (&policy.token_quota, quota_key.as_ref()) {
            let reservation_id = format!("llm:{}:{}", ctx.route.id, ctx.request_id);
            let max_actual = policy
                .max_prompt_tokens
                .saturating_add(policy.max_completion_tokens);
            let reserved = self
                .rate_limiter
                .reserve(
                    RateLimitRequest {
                        scope,
                        key,
                        cost: reserved_tokens,
                        limit: quota.limit,
                        window: quota.window,
                        burst: quota.burst,
                        max_active_keys: quota.max_active_keys,
                        active_keys_fail_open: quota.active_keys_fail_open,
                    },
                    reservation_id.as_str(),
                    max_actual,
                )
                .await;
            if !reserved.decision.allowed {
                self.metrics.inc_rate_limited();
                return LlmForwardOutcome::Local(rate_limited_response(
                    reserved.decision.remaining,
                ));
            }
            quota_reservation = reserved.reservation;
        }

        let mut attempted_upstream = false;
        let consumer_metric = llm_consumer_metric_label(ctx.route, &ctx.parts);
        let request_capabilities = request.required_capabilities();
        let completion_tokens = request.max_completion_tokens.unwrap_or_default();
        let mut model_order = self.llm_model_order(ctx.route.id.as_str(), policy, ctx.request_id);
        model_order.retain(|index| {
            let model = &policy.models()[*index];
            model.supports_capabilities(request_capabilities.as_slice())
                && (policy.max_cost_microusd == u64::MAX
                    || model
                        .estimated_cost_microusd(request.prompt_tokens, completion_tokens)
                        .is_some_and(|cost| cost <= policy.max_cost_microusd))
        });
        if model_order.is_empty() {
            refund_llm_reservation(&mut quota_reservation).await;
            return LlmForwardOutcome::Local(text_status(
                400,
                "LLM request has no model satisfying capability, SLO, and cost policy",
            ));
        }
        if let Some((shadow_index, basis_points)) = policy.shadow {
            let shadow = &policy.models()[shadow_index];
            let sample_key = format!("{}:shadow:{}", ctx.request_id, shadow.id);
            let sampled = stable_hash64(sample_key.as_bytes()) % 10_000 < u64::from(basis_points);
            let cost_allowed = policy.max_cost_microusd == u64::MAX
                || shadow
                    .estimated_cost_microusd(request.prompt_tokens, completion_tokens)
                    .is_some_and(|cost| cost <= policy.max_cost_microusd);
            if sampled
                && cost_allowed
                && shadow.supports_capabilities(request_capabilities.as_slice())
            {
                match request.body_for(shadow) {
                    Ok(body) => {
                        let mut parts = ctx.parts.clone();
                        shadow.prepare_headers(&mut parts, request.stream);
                        let signed = shadow.sign_bedrock_request(
                            &mut parts,
                            body.as_ref(),
                            shadow.path_for(request.stream),
                            chrono::Utc::now(),
                        );
                        if let Err(error) = signed.and_then(|()| {
                            self.spawn_llm_shadow_request(
                                ctx.snap,
                                ctx.proxy,
                                ctx.route,
                                parts,
                                body,
                                shadow.upstream.as_ref(),
                                shadow.path_for(request.stream),
                                ctx.client_ip,
                                ctx.trusted_inbound,
                                ctx.client_cert_verified,
                                ctx.downstream_proto,
                                ctx.request_id,
                                ctx.trace,
                                policy.max_duration,
                                shadow.id.clone(),
                            )
                            .map_err(|error| anyhow::anyhow!(error.to_string()))
                        }) {
                            tracing::debug!(route = %ctx.route.id, model = %shadow.id, %error, "LLM shadow evaluation was skipped");
                        }
                    }
                    Err(error) => {
                        tracing::debug!(route = %ctx.route.id, model = %shadow.id, %error, "LLM shadow request cannot be represented");
                    }
                }
            }
        }
        let model_count = model_order.len();
        for (attempt, model_index) in model_order.into_iter().enumerate() {
            let model = &policy.models()[model_index];
            let body = match request.body_for(model) {
                Ok(body) => body,
                Err(error) => {
                    tracing::debug!(route = %ctx.route.id, model = %model.id, %error, "LLM provider request conversion failed");
                    refund_llm_reservation(&mut quota_reservation).await;
                    return LlmForwardOutcome::Local(text_status(
                        400,
                        "LLM request is unsupported by selected provider",
                    ));
                }
            };
            let mut parts = ctx.parts.clone();
            model.prepare_headers(&mut parts, request.stream);
            if let Err(error) = model.sign_bedrock_request(
                &mut parts,
                body.as_ref(),
                model.path_for(request.stream),
                chrono::Utc::now(),
            ) {
                tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "LLM provider signing failed");
                refund_llm_reservation(&mut quota_reservation).await;
                return LlmForwardOutcome::Local(text_status(
                    500,
                    "LLM provider authentication failed",
                ));
            }
            attempted_upstream = true;
            let model_started = Instant::now();
            let response = self
                .forward(forward::ForwardRequest {
                    snap: ctx.snap,
                    proxy: ctx.proxy,
                    route: ctx.route,
                    parts,
                    body: full_body(body),
                    upstream_override: Some(model.upstream.as_ref()),
                    path_override: Some(model.path_for(request.stream)),
                    inference_endpoints: None,
                    client_ip: ctx.client_ip,
                    client_ip_header: None,
                    trusted_inbound: ctx.trusted_inbound,
                    client_cert_verified: ctx.client_cert_verified,
                    downstream_proto: ctx.downstream_proto,
                    request_id: ctx.request_id,
                    consumer: None,
                    downstream_upgrade: None,
                    limit_conn_guards: Vec::new(),
                    websocket_max_lifetime_ms: None,
                    websocket_frame_limits: None,
                    trace: Some(ctx.trace),
                })
                .await;
            let mut response = match response {
                Ok(response) => response,
                Err(error) => {
                    self.metrics.inc_upstream_error();
                    tracing::warn!(
                        route = %ctx.route.id,
                        model = %model.id,
                        attempt = attempt + 1,
                        %error,
                        "LLM model transport failed"
                    );
                    if attempt + 1 < model_count {
                        continue;
                    }
                    refund_llm_reservation(&mut quota_reservation).await;
                    return LlmForwardOutcome::Upstream(text_status(
                        error.status().as_u16(),
                        error.message(),
                    ));
                }
            };
            if response.status().is_success() {
                self.observe_llm_model_latency(
                    ctx.route.id.as_str(),
                    model.id.clone(),
                    model_started.elapsed(),
                );
            }
            if response.status().is_server_error() && attempt + 1 < model_count {
                // 有界排空小错误体可复用 h1 连接；超过预算立即 drop，不能为了 fallback collect
                // 一个不可信 5xx body。h2 Drop 会按协议取消当前 stream，不影响连接其它 stream。
                drain_llm_fallback_response(response).await;
                continue;
            }
            if !response.status().is_success() {
                // 只有明确收到 provider 非成功响应才确认没有可计费成功结果；中断的成功流或
                // 坏成功 body usage 不可知，必须继续保留保守预留。
                refund_llm_reservation(&mut quota_reservation).await;
            }
            let (usage, response_body) = if !request.stream && response.status().is_success() {
                let converted = if model.native_passthrough {
                    inspect_native_llm_response(response, policy.max_response_bytes).await
                } else {
                    match model.provider {
                        crate::llm::LlmProvider::Anthropic => {
                            convert_anthropic_response(response, policy.max_response_bytes).await
                        }
                        crate::llm::LlmProvider::Google | crate::llm::LlmProvider::VertexAi => {
                            convert_google_response(response, policy.max_response_bytes).await
                        }
                        crate::llm::LlmProvider::Openai
                        | crate::llm::LlmProvider::AzureOpenai
                        | crate::llm::LlmProvider::Bedrock
                        | crate::llm::LlmProvider::Mistral
                        | crate::llm::LlmProvider::HuggingFace
                        | crate::llm::LlmProvider::Xai
                        | crate::llm::LlmProvider::Dashscope
                        | crate::llm::LlmProvider::Deepseek
                        | crate::llm::LlmProvider::Ollama
                        | crate::llm::LlmProvider::Vllm => {
                            inspect_openai_response(response, policy.max_response_bytes).await
                        }
                        crate::llm::LlmProvider::Cohere => {
                            unreachable!("Cohere Chat requires native passthrough")
                        }
                    }
                };
                match converted {
                    Ok((converted, usage, body)) => {
                        response = converted;
                        (usage, Some(body))
                    }
                    Err(error) => {
                        tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "invalid LLM provider response");
                        return LlmForwardOutcome::Upstream(text_status(
                            502,
                            "invalid LLM provider response",
                        ));
                    }
                }
            } else {
                (None, None)
            };
            if let Some(usage) = usage {
                self.metrics.observe_llm_usage(
                    ctx.route.id.as_str(),
                    model.id.as_ref(),
                    consumer_metric.as_str(),
                    usage.prompt_tokens,
                    usage.completion_tokens,
                    model.input_cost_microusd_per_million,
                    model.output_cost_microusd_per_million,
                );
                if let Some(reservation) = quota_reservation.take() {
                    let actual = usage.prompt_tokens.saturating_add(usage.completion_tokens);
                    if let Err(error) = reservation.settle(actual).await {
                        tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "LLM token quota settlement failed; conservative reservation retained");
                    }
                }
            }
            if let Some(body) = response_body.as_ref() {
                match policy.blocked_response(body.as_ref()) {
                    Ok(true) => {
                        tracing::warn!(route = %ctx.route.id, model = %model.id, "LLM response blocked by configured output guardrail");
                        return LlmForwardOutcome::Upstream(text_status(
                            403,
                            "LLM response blocked by guardrail",
                        ));
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "LLM output guardrail could not inspect provider response");
                        return LlmForwardOutcome::Upstream(text_status(
                            502,
                            "invalid LLM provider response",
                        ));
                    }
                }
            }
            response.headers_mut().insert(
                "x-gateway-llm-model",
                HeaderValue::from_str(model.id.as_ref())
                    .expect("LLM model id was validated as an HTTP-safe ASCII token"),
            );
            if request.stream && response.status().is_success() {
                let accounting = LlmStreamAccounting {
                    metrics: self.metrics.clone(),
                    route: Arc::from(ctx.route.id.as_str()),
                    model: model.id.clone(),
                    consumer: Arc::from(consumer_metric.as_str()),
                    input_cost_microusd_per_million: model.input_cost_microusd_per_million,
                    output_cost_microusd_per_million: model.output_cost_microusd_per_million,
                    reservation: quota_reservation.take(),
                };
                response = if model.native_passthrough {
                    wrap_native_llm_stream_response(
                        response,
                        accounting,
                        policy.max_response_bytes,
                        policy.max_stream_frame_bytes,
                        policy.max_duration,
                    )
                } else {
                    match model.provider {
                        crate::llm::LlmProvider::Anthropic => {
                            wrap_anthropic_sse_response(response, accounting)
                        }
                        crate::llm::LlmProvider::Google | crate::llm::LlmProvider::VertexAi => {
                            wrap_google_sse_response(response, accounting)
                        }
                        crate::llm::LlmProvider::Openai
                        | crate::llm::LlmProvider::AzureOpenai
                        | crate::llm::LlmProvider::Bedrock
                        | crate::llm::LlmProvider::Mistral
                        | crate::llm::LlmProvider::HuggingFace
                        | crate::llm::LlmProvider::Xai
                        | crate::llm::LlmProvider::Dashscope
                        | crate::llm::LlmProvider::Deepseek
                        | crate::llm::LlmProvider::Ollama
                        | crate::llm::LlmProvider::Vllm => {
                            wrap_openai_sse_usage_response(response, accounting)
                        }
                        crate::llm::LlmProvider::Cohere => {
                            unreachable!("Cohere Chat requires native passthrough")
                        }
                    }
                };
            }
            if let (Some(fill), Some(body)) = (cache_fill.take(), response_body) {
                if body.len() <= fill.policy.max_response_bytes {
                    let vector = fill.vector.clone().unwrap_or_else(|| Arc::from([]));
                    fill.policy
                        .insert(
                            fill.exact_digest,
                            fill.params_digest,
                            vector,
                            body.clone(),
                            model.id.clone(),
                        )
                        .await;
                    if fill.policy.l2_enabled {
                        match crate::llm::encode_l2_response(model.id.as_ref(), body.as_ref()) {
                            Ok(encoded_response) => {
                                let encoded_candidate = fill
                                    .vector
                                    .as_ref()
                                    .map(|vector| {
                                        crate::llm::encode_l2_candidate(
                                            fill.exact_digest,
                                            fill.params_digest,
                                            vector.as_ref(),
                                        )
                                    })
                                    .transpose();
                                match encoded_candidate {
                                    Ok(encoded_candidate) => {
                                        let runtime = self.http_cache_runtime.clone();
                                        let scope = fill.scope;
                                        let digest = crate::llm::digest_hex(&fill.exact_digest);
                                        let ttl = fill.policy.ttl();
                                        let max_entries = fill.policy.max_entries();
                                        tokio::spawn(async move {
                                            if let Err(error) = runtime
                                                .llm_cache_store(
                                                    scope.as_str(),
                                                    digest.as_str(),
                                                    encoded_response.as_ref(),
                                                    encoded_candidate.as_deref(),
                                                    ttl,
                                                    max_entries,
                                                )
                                                .await
                                            {
                                                tracing::warn!(%error, "LLM Redis cache fill failed");
                                            }
                                        });
                                    }
                                    Err(error) => {
                                        tracing::warn!(route = %ctx.route.id, %error, "encode LLM semantic cache candidate failed")
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::warn!(route = %ctx.route.id, %error, "encode LLM exact cache response failed")
                            }
                        }
                    }
                }
            }
            return LlmForwardOutcome::Upstream(response);
        }

        let response = text_status(503, "no compatible LLM model available");
        if attempted_upstream {
            LlmForwardOutcome::Upstream(response)
        } else {
            LlmForwardOutcome::Local(response)
        }
    }

    /// 业务作用：转发非 Chat 的独立 AI API，保持 provider 原生字段与响应不变，同时在任何
    /// provider I/O 前执行 content-type、能力、费用和资源预算门。
    ///
    /// 参数说明：`ctx` 持有已认证请求、升级权与不可变快照；`policy` 是 route 冻结的 API/model 计划。
    ///
    /// 返回：本地契约拒绝返回 Local；已经尝试 provider 后返回 Upstream，并仅对 transport、超时或
    /// 5xx 使用剩余模型 fallback。
    async fn forward_native_ai(
        &self,
        mut ctx: LlmForwardRequest<'_>,
        policy: &crate::llm::LlmRoutePolicy,
    ) -> LlmForwardOutcome {
        if policy.api_type == crate::llm::LlmApiType::Realtime {
            return self.forward_realtime_ai(ctx, policy).await;
        }
        if ctx.downstream_upgrade.is_some() {
            return LlmForwardOutcome::Local(text_status(
                400,
                "WebSocket upgrade is only valid for realtime AI routes",
            ));
        }
        if content_length_exceeds(&ctx.parts, policy.max_body_bytes) {
            return LlmForwardOutcome::Local(text_status(413, "AI request body too large"));
        }
        let media_type = ctx
            .parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .map(str::to_ascii_lowercase);
        let multipart = media_type
            .as_deref()
            .is_some_and(|value| value.starts_with("multipart/"));
        let json = media_type
            .as_deref()
            .is_some_and(|value| value == "application/json" || value.ends_with("+json"));
        let content_type_allowed = match policy.api_type {
            crate::llm::LlmApiType::Responses
            | crate::llm::LlmApiType::Embeddings
            | crate::llm::LlmApiType::Rerank
            | crate::llm::LlmApiType::Batch => json,
            crate::llm::LlmApiType::Image
            | crate::llm::LlmApiType::Audio
            | crate::llm::LlmApiType::Video
            | crate::llm::LlmApiType::File => json || multipart,
            crate::llm::LlmApiType::ChatCompletions | crate::llm::LlmApiType::Realtime => false,
        };
        if !content_type_allowed {
            return LlmForwardOutcome::Local(text_status(
                415,
                "content type is not valid for this AI API",
            ));
        }
        let body = std::mem::replace(&mut ctx.body, full_body(Bytes::new()));
        let raw = match collect_llm_body(body, policy.max_body_bytes).await {
            Ok(raw) => raw,
            Err(LlmBodyError::TooLarge) => {
                return LlmForwardOutcome::Local(text_status(413, "AI request body too large"));
            }
            Err(LlmBodyError::Invalid(error)) => {
                tracing::debug!(route = %ctx.route.id, %error, "invalid native AI request body");
                return LlmForwardOutcome::Local(text_status(400, "invalid AI request body"));
            }
        };
        let document = if json {
            match serde_json::from_slice::<serde_json::Value>(raw.as_ref()) {
                Ok(value) if value.is_object() => Some(value),
                Ok(_) => {
                    return LlmForwardOutcome::Local(text_status(
                        400,
                        "AI JSON request must be an object",
                    ));
                }
                Err(error) => {
                    tracing::debug!(route = %ctx.route.id, %error, "native AI request is not JSON");
                    return LlmForwardOutcome::Local(text_status(400, "invalid AI JSON request"));
                }
            }
        } else {
            None
        };
        let stream = document
            .as_ref()
            .and_then(|value| value.get("stream"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let mut capabilities = document
            .as_ref()
            .map(crate::llm::native_required_capabilities)
            .unwrap_or_else(|| vec!["multimodal"]);
        capabilities.sort_unstable();
        capabilities.dedup();
        let prompt_tokens = ((raw.len() as u64).saturating_add(3) / 4).max(1);
        let completion_tokens = document
            .as_ref()
            .map(crate::llm::native_completion_tokens)
            .unwrap_or_default();
        let mut order = self.llm_model_order(ctx.route.id.as_str(), policy, ctx.request_id);
        order.retain(|index| {
            let model = &policy.models()[*index];
            model.supports_capabilities(capabilities.as_slice())
                && (policy.max_cost_microusd == u64::MAX
                    || model
                        .estimated_cost_microusd(prompt_tokens, completion_tokens)
                        .is_some_and(|cost| cost <= policy.max_cost_microusd))
        });
        if order.is_empty() {
            return LlmForwardOutcome::Local(text_status(
                400,
                "AI request has no model satisfying capability, SLO, and cost policy",
            ));
        }
        if let Some((shadow_index, basis_points)) = policy.shadow {
            let shadow = &policy.models()[shadow_index];
            let sample_key = format!("{}:shadow:{}", ctx.request_id, shadow.id);
            let sampled = stable_hash64(sample_key.as_bytes()) % 10_000 < u64::from(basis_points);
            let cost_allowed = policy.max_cost_microusd == u64::MAX
                || shadow
                    .estimated_cost_microusd(prompt_tokens, completion_tokens)
                    .is_some_and(|cost| cost <= policy.max_cost_microusd);
            if sampled && cost_allowed && shadow.supports_capabilities(capabilities.as_slice()) {
                let shadow_body = match document.as_ref() {
                    Some(document) => shadow.native_json_body(document, &raw),
                    None => Ok(raw.clone()),
                };
                match shadow_body {
                    Ok(body) if body.len() <= policy.max_body_bytes => {
                        let mut parts = ctx.parts.clone();
                        shadow.prepare_headers(&mut parts, stream);
                        let signed = shadow.sign_bedrock_request(
                            &mut parts,
                            body.as_ref(),
                            shadow.path_for(stream),
                            chrono::Utc::now(),
                        );
                        if let Err(error) = signed.and_then(|()| {
                            self.spawn_llm_shadow_request(
                                ctx.snap,
                                ctx.proxy,
                                ctx.route,
                                parts,
                                body,
                                shadow.upstream.as_ref(),
                                shadow.path_for(stream),
                                ctx.client_ip,
                                ctx.trusted_inbound,
                                ctx.client_cert_verified,
                                ctx.downstream_proto,
                                ctx.request_id,
                                ctx.trace,
                                policy.max_duration,
                                shadow.id.clone(),
                            )
                            .map_err(|error| anyhow::anyhow!(error.to_string()))
                        }) {
                            tracing::debug!(route = %ctx.route.id, model = %shadow.id, %error, "AI shadow evaluation was skipped");
                        }
                    }
                    Ok(_) => {
                        tracing::debug!(route = %ctx.route.id, model = %shadow.id, "AI shadow request exceeds route body budget");
                    }
                    Err(error) => {
                        tracing::debug!(route = %ctx.route.id, model = %shadow.id, %error, "AI shadow request cannot be represented");
                    }
                }
            }
        }
        let model_count = order.len();
        for (attempt, model_index) in order.into_iter().enumerate() {
            let model = &policy.models()[model_index];
            let body = match document.as_ref() {
                Some(document) => match model.native_json_body(document, &raw) {
                    Ok(body) if body.len() <= policy.max_body_bytes => body,
                    Ok(_) => {
                        return LlmForwardOutcome::Local(text_status(
                            413,
                            "provider AI request body too large",
                        ));
                    }
                    Err(error) => {
                        tracing::debug!(route = %ctx.route.id, model = %model.id, %error, "native AI request cannot be represented");
                        return LlmForwardOutcome::Local(text_status(
                            400,
                            "AI request is unsupported by selected provider",
                        ));
                    }
                },
                None => raw.clone(),
            };
            let mut parts = ctx.parts.clone();
            model.prepare_headers(&mut parts, stream);
            if let Err(error) = model.sign_bedrock_request(
                &mut parts,
                body.as_ref(),
                model.path_for(stream),
                chrono::Utc::now(),
            ) {
                tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "AI provider signing failed");
                return LlmForwardOutcome::Local(text_status(
                    500,
                    "AI provider authentication failed",
                ));
            }
            let started = Instant::now();
            let future = self.forward(forward::ForwardRequest {
                snap: ctx.snap,
                proxy: ctx.proxy,
                route: ctx.route,
                parts,
                body: full_body(body),
                upstream_override: Some(model.upstream.as_ref()),
                path_override: Some(model.path_for(stream)),
                inference_endpoints: None,
                client_ip: ctx.client_ip,
                client_ip_header: None,
                trusted_inbound: ctx.trusted_inbound,
                client_cert_verified: ctx.client_cert_verified,
                downstream_proto: ctx.downstream_proto,
                request_id: ctx.request_id,
                consumer: None,
                downstream_upgrade: None,
                limit_conn_guards: Vec::new(),
                websocket_max_lifetime_ms: None,
                websocket_frame_limits: None,
                trace: Some(ctx.trace),
            });
            let mut response = match tokio::time::timeout(policy.max_duration, future).await {
                Err(_) if attempt + 1 < model_count => continue,
                Err(_) => {
                    return LlmForwardOutcome::Upstream(text_status(
                        504,
                        "AI provider request timed out",
                    ));
                }
                Ok(Err(error)) if attempt + 1 < model_count => {
                    tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "AI provider transport failed; trying fallback");
                    continue;
                }
                Ok(Err(error)) => {
                    self.metrics.inc_upstream_error();
                    return LlmForwardOutcome::Upstream(text_status(
                        error.status().as_u16(),
                        error.message(),
                    ));
                }
                Ok(Ok(response)) => response,
            };
            if response.status().is_server_error() && attempt + 1 < model_count {
                drain_llm_fallback_response(response).await;
                continue;
            }
            if response.status().is_success() {
                self.observe_llm_model_latency(
                    ctx.route.id.as_str(),
                    model.id.clone(),
                    started.elapsed(),
                );
                if stream {
                    response = wrap_native_llm_stream_response(
                        response,
                        LlmStreamAccounting {
                            metrics: self.metrics.clone(),
                            route: Arc::from(ctx.route.id.as_str()),
                            model: model.id.clone(),
                            consumer: Arc::from(llm_consumer_metric_label(ctx.route, &ctx.parts)),
                            input_cost_microusd_per_million: model.input_cost_microusd_per_million,
                            output_cost_microusd_per_million: model
                                .output_cost_microusd_per_million,
                            reservation: None,
                        },
                        policy.max_response_bytes,
                        policy.max_stream_frame_bytes,
                        policy.max_duration.saturating_sub(started.elapsed()),
                    );
                } else {
                    response = match inspect_native_llm_response(
                        response,
                        policy.max_response_bytes,
                    )
                    .await
                    {
                        Ok((response, _, _)) => response,
                        Err(error) => {
                            tracing::warn!(route = %ctx.route.id, model = %model.id, %error, "invalid native AI provider response");
                            return LlmForwardOutcome::Upstream(text_status(
                                502,
                                "invalid AI provider response",
                            ));
                        }
                    };
                }
            }
            response.headers_mut().insert(
                "x-gateway-llm-model",
                HeaderValue::from_str(model.id.as_ref())
                    .expect("AI model id is a validated HTTP-safe token"),
            );
            return LlmForwardOutcome::Upstream(response);
        }
        LlmForwardOutcome::Local(text_status(503, "no compatible AI model available"))
    }

    /// 业务作用：把 Realtime WebSocket 升级权只交给经能力、费用与 rollout 选择的固定 provider，
    /// 不允许请求体、query 或客户端认证材料改写模型身份。
    ///
    /// 参数说明：`ctx` 持有唯一升级 future 与连接 guard；`policy` 是 Realtime 专属 route 计划。
    ///
    /// 返回：握手契约或 admission 不满足时返回 Local；已尝试固定 provider 后返回 Upstream。
    async fn forward_realtime_ai(
        &self,
        mut ctx: LlmForwardRequest<'_>,
        policy: &crate::llm::LlmRoutePolicy,
    ) -> LlmForwardOutcome {
        if ctx.parts.method != Method::GET || ctx.downstream_upgrade.is_none() {
            return LlmForwardOutcome::Local(text_status(
                426,
                "realtime AI route requires WebSocket upgrade",
            ));
        }
        let Some(model_index) = self
            .llm_model_order(ctx.route.id.as_str(), policy, ctx.request_id)
            .into_iter()
            .find(|index| {
                let model = &policy.models()[*index];
                policy.max_cost_microusd == u64::MAX
                    || model
                        .estimated_cost_microusd(0, 0)
                        .is_some_and(|cost| cost <= policy.max_cost_microusd)
            })
        else {
            return LlmForwardOutcome::Local(text_status(
                400,
                "realtime AI request exceeds cost policy",
            ));
        };
        let model = &policy.models()[model_index];
        let mut parts = ctx.parts;
        model.prepare_headers(&mut parts, true);
        let consumer = ctx.route.authenticated_consumer(&parts);
        let future = self.forward(forward::ForwardRequest {
            snap: ctx.snap,
            proxy: ctx.proxy,
            route: ctx.route,
            parts,
            body: ctx.body,
            upstream_override: Some(model.upstream.as_ref()),
            path_override: Some(model.path_for(true)),
            inference_endpoints: None,
            client_ip: ctx.client_ip,
            client_ip_header: None,
            trusted_inbound: ctx.trusted_inbound,
            client_cert_verified: ctx.client_cert_verified,
            downstream_proto: ctx.downstream_proto,
            request_id: ctx.request_id,
            consumer,
            downstream_upgrade: ctx.downstream_upgrade.take(),
            limit_conn_guards: std::mem::take(&mut ctx.limit_conn_guards),
            websocket_max_lifetime_ms: Some(
                policy.max_duration.as_millis().min(u128::from(u64::MAX)) as u64,
            ),
            websocket_frame_limits: Some((
                policy.max_stream_frame_bytes as u64,
                policy.max_response_bytes as u64,
            )),
            trace: Some(ctx.trace),
        });
        match tokio::time::timeout(policy.max_duration, future).await {
            Ok(Ok(mut response)) => {
                response.headers_mut().insert(
                    "x-gateway-llm-model",
                    HeaderValue::from_str(model.id.as_ref())
                        .expect("AI model id is a validated HTTP-safe token"),
                );
                LlmForwardOutcome::Upstream(response)
            }
            Ok(Err(error)) => {
                LlmForwardOutcome::Upstream(text_status(error.status().as_u16(), error.message()))
            }
            Err(_) => LlmForwardOutcome::Upstream(text_status(
                504,
                "realtime AI provider handshake timed out",
            )),
        }
    }

    /// 业务作用：在模型、缓存与配额 admission 前调用 external moderation，并把响应收敛为单一 flagged 判定。
    ///
    /// 参数说明：`ctx` 提供当前不可变快照和安全网络上下文，`policy` 是已编译 moderation 计划，`body` 是有界 text-only JSON。
    ///
    /// 返回：成功且响应合法时返回 flagged；超时、transport、非 2xx、响应超限或坏 JSON 返回错误，调用方按 route fail policy 决策。
    async fn call_llm_moderation(
        &self,
        ctx: &LlmForwardRequest<'_>,
        policy: &crate::llm::LlmModerationPolicy,
        body: Bytes,
    ) -> anyhow::Result<bool> {
        let mut parts = ctx.parts.clone();
        policy.prepare_headers(&mut parts);
        let future = self.forward(forward::ForwardRequest {
            snap: ctx.snap,
            proxy: ctx.proxy,
            route: ctx.route,
            parts,
            body: full_body(body),
            upstream_override: Some(policy.upstream.as_ref()),
            path_override: Some(policy.path.as_ref()),
            inference_endpoints: None,
            client_ip: ctx.client_ip,
            client_ip_header: None,
            trusted_inbound: ctx.trusted_inbound,
            client_cert_verified: ctx.client_cert_verified,
            downstream_proto: ctx.downstream_proto,
            request_id: ctx.request_id,
            consumer: None,
            downstream_upgrade: None,
            limit_conn_guards: Vec::new(),
            websocket_max_lifetime_ms: None,
            websocket_frame_limits: None,
            trace: Some(ctx.trace),
        });
        let response = tokio::time::timeout(policy.timeout, future)
            .await
            .context("LLM moderation timeout")?
            .map_err(|error| anyhow::anyhow!(error.message().to_string()))?;
        if !response.status().is_success() {
            anyhow::bail!("LLM moderation returned status {}", response.status());
        }
        let (_, body) = response.into_parts();
        let body = collect_llm_boxed_body(body, policy.max_response_bytes)
            .await
            .map_err(|error| match error {
                LlmBodyError::TooLarge => anyhow::anyhow!("LLM moderation response exceeds limit"),
                LlmBodyError::Invalid(error) => error,
            })?;
        crate::llm::moderation_flagged(body.as_ref())
    }

    /// 为一次请求生成最多 16 个模型下标。Vec 是 LLM 显式 JSON 慢路径的小型必要分配；模型对象、
    /// URI、凭据与 provider adapter 全部仍借用不可变快照。
    fn llm_model_order(
        &self,
        route_id: &str,
        policy: &crate::llm::LlmRoutePolicy,
        request_id: &str,
    ) -> Vec<usize> {
        let models = policy.models();
        let mut order = (0..models.len()).collect::<Vec<_>>();
        match policy.selection {
            crate::llm::LlmSelectionStrategy::Ordered | crate::llm::LlmSelectionStrategy::Cost => {}
            crate::llm::LlmSelectionStrategy::Latency => {
                let latencies = self.llm_model_latency.lock();
                let route = latencies.get(route_id);
                // 未采样模型优先，保证有限探索；全部有样本后按 EWMA 升序。stable sort 保留同值配置序。
                order.sort_by_key(|index| {
                    let latency = route.and_then(|values| values.get(models[*index].id.as_ref()));
                    (latency.is_some(), latency.copied().unwrap_or(0))
                });
            }
            crate::llm::LlmSelectionStrategy::Weighted => {
                let total = models
                    .iter()
                    .fold(0_u64, |sum, model| sum.saturating_add(model.weight as u64));
                if total > 0 {
                    let mut slot = stable_hash64(request_id.as_bytes()) % total;
                    let mut selected = 0;
                    for (index, model) in models.iter().enumerate() {
                        if slot < model.weight as u64 {
                            selected = index;
                            break;
                        }
                        slot = slot.saturating_sub(model.weight as u64);
                    }
                    order.remove(selected);
                    order.insert(0, selected);
                }
            }
            crate::llm::LlmSelectionStrategy::Joint => {
                let latencies = self.llm_model_latency.lock();
                let route = latencies.get(route_id);
                order.sort_by_key(|index| {
                    let model = &models[*index];
                    let observed_us = route
                        .and_then(|values| values.get(model.id.as_ref()))
                        .copied();
                    let declared_us = model
                        .expected_first_token_latency
                        .map(|value| value.as_micros().min(u128::from(u64::MAX)) as u64);
                    let latency_us = observed_us.or(declared_us);
                    let outside_slo = policy.max_first_token_latency.is_some_and(|slo| {
                        latency_us.is_some_and(|latency| latency > slo.as_micros() as u64)
                    });
                    let missing_preferred = policy
                        .preferred_capabilities
                        .iter()
                        .filter(|required| {
                            !model
                                .capabilities
                                .iter()
                                .any(|value| value.as_ref() == required.as_ref())
                        })
                        .count();
                    let price = model
                        .input_cost_microusd_per_million
                        .saturating_add(model.output_cost_microusd_per_million);
                    (
                        outside_slo,
                        missing_preferred,
                        price == 0,
                        price,
                        latency_us.is_none(),
                        latency_us.unwrap_or(0),
                    )
                });
            }
        }
        if let Some((shadow, _)) = policy.shadow {
            // Shadow 模型只有独立后台评估权，永远不能因主模型失败进入 fallback 或成为 rollout。
            order.retain(|index| *index != shadow);
        }
        if let Some((rollout, basis_points)) = policy.rollout {
            if stable_hash64(request_id.as_bytes()) % 10_000 < u64::from(basis_points) {
                if let Some(position) = order.iter().position(|index| *index == rollout) {
                    order.remove(position);
                    order.insert(0, rollout);
                }
            }
        }
        order
    }

    /// 更新成功 response-head 延迟 EWMA(alpha=1/4)。只保存配置 route/model，且跨热更历史最多
    /// 4096 组；达到上限的新身份不再学习，选择会按“未采样”安全退回配置顺序。
    fn observe_llm_model_latency(&self, route_id: &str, model_id: Arc<str>, elapsed: Duration) {
        const MAX_LLM_LATENCY_SERIES: usize = 4096;
        let sample = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        let mut latencies = self.llm_model_latency.lock();
        let series = latencies.values().map(HashMap::len).sum::<usize>();
        let exists = latencies
            .get(route_id)
            .is_some_and(|models| models.contains_key(model_id.as_ref()));
        if !exists && series >= MAX_LLM_LATENCY_SERIES {
            return;
        }
        let value = latencies
            .entry(route_id.to_string())
            .or_default()
            .entry(model_id)
            .or_insert(sample);
        *value = value.saturating_mul(3).saturating_add(sample) / 4;
    }

    /// 调用一次 OpenAI-compatible embedding 服务。请求只携带统一 prompt 文本与 embedding
    /// provider 凭据；下游 Authorization/Cookie/API-Key 已在 `prepare_headers` 中清除。
    ///
    /// Cache 是优化而非可用性依赖，所以所有 transport/status/协议错误都上抛给调用方按 miss
    /// 处理。响应有独立 4MiB 聚合上限，向量还会继续经过维度与 finite/范数校验。
    async fn fetch_llm_embedding(
        &self,
        ctx: &LlmForwardRequest<'_>,
        request: &crate::llm::ParsedLlmRequest,
        cache: &crate::llm::LlmSemanticCache,
    ) -> anyhow::Result<Arc<[f32]>> {
        let body = request.embedding_body(&cache.embedding)?;
        let mut parts = ctx.parts.clone();
        parts.method = Method::POST;
        cache.embedding.prepare_headers(&mut parts);
        let response = self
            .forward(forward::ForwardRequest {
                snap: ctx.snap,
                proxy: ctx.proxy,
                route: ctx.route,
                parts,
                body: full_body(body),
                upstream_override: Some(cache.embedding.upstream.as_ref()),
                path_override: Some(cache.embedding.path.as_ref()),
                inference_endpoints: None,
                client_ip: ctx.client_ip,
                client_ip_header: None,
                trusted_inbound: ctx.trusted_inbound,
                client_cert_verified: ctx.client_cert_verified,
                downstream_proto: ctx.downstream_proto,
                request_id: ctx.request_id,
                consumer: None,
                downstream_upgrade: None,
                limit_conn_guards: Vec::new(),
                websocket_max_lifetime_ms: None,
                websocket_frame_limits: None,
                trace: Some(ctx.trace),
            })
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        anyhow::ensure!(
            response.status().is_success(),
            "embedding provider returned {}",
            response.status()
        );
        let (_, body) = response.into_parts();
        let body = collect_llm_boxed_body(body, crate::llm::MAX_LLM_EMBEDDING_RESPONSE_BYTES)
            .await
            .map_err(|error| match error {
                LlmBodyError::TooLarge => anyhow::anyhow!("embedding response exceeds limit"),
                LlmBodyError::Invalid(error) => error,
            })?;
        crate::llm::parse_embedding(body.as_ref(), cache.embedding.max_dimensions)
    }

    /// 成功写请求后的 route generation 失效。
    ///
    /// 这里有意在返回成功 response head 前 await：否则客户端收到写成功后立刻 GET，可能仍命中旧
    /// L1/L2。Redis 失败不能把已成功的非幂等写改成 5xx（客户端重试会造成二次写），因此只记错误
    /// 并依赖原 TTL；local route 则同步清 L1。每条写 route 最多 8 个目标，构建期已有硬上限。
    async fn invalidate_caches_after_write(
        &self,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
    ) {
        for target_id in &route.cache_invalidations {
            let Some(target) = proxy.router.route_by_id(target_id) else {
                // Router build 已验证；运行时走到这里只可能是内部不变量被破坏。
                tracing::error!(route = %route.id, target = %target_id, "cache invalidation target disappeared from immutable router");
                self.metrics.inc_http_cache_invalidation_error();
                continue;
            };
            let Some(policy) = target.http_cache.as_ref() else {
                tracing::error!(route = %route.id, target = %target_id, "cache invalidation target lost proxy_cache policy");
                self.metrics.inc_http_cache_invalidation_error();
                continue;
            };
            match self
                .http_cache_runtime
                .purge_route(&proxy.id, target_id, policy.as_ref())
                .await
            {
                Ok(_) => self.metrics.inc_http_cache_invalidation_ok(),
                Err(error) => {
                    self.metrics.inc_http_cache_invalidation_error();
                    tracing::warn!(route = %route.id, target = %target_id, %error, "write succeeded but HTTP cache invalidation failed");
                }
            }
        }
    }

    /// 派生一次 stale-while-revalidate 刷新。
    ///
    /// stale 响应已在主请求返回，本任务才等待 Redis fill lock/访问上游。刷新 body 逐帧排空，
    /// 不 `collect()`、不保留第二份完整响应；真正缓存复制仍只发生在 `CacheFillBody` 的配置上限内。
    #[allow(clippy::too_many_arguments)]
    fn spawn_http_cache_revalidation(
        self: &Arc<Self>,
        snap: Arc<GatewaySnapshot>,
        proxy_id: Arc<str>,
        route: Arc<Route>,
        mut parts: Parts,
        miss: CacheMiss,
        client_ip: IpAddr,
        trusted_inbound: bool,
        client_cert_verified: bool,
        downstream_proto: &'static str,
        request_id: String,
        request_origin: Option<HeaderValue>,
    ) {
        // 这些 route 的前台响应还有额外控制流/副作用，不能用精简后台管线伪装等价刷新。
        // guard 在此 Drop 会立即释放 leader；entry 最终过 stale window 后由正常前台路径重建。
        if route.direct_response.is_some()
            || route.gateway_redirect.is_some()
            || route.static_serve.is_some()
            || !route.error_pages.is_empty()
            || route.x_accel_redirect
            || !route.mirrors.is_empty()
        {
            return;
        }
        let Some(policy) = route.http_cache.clone() else {
            return;
        };
        let gateway = self.clone();
        tokio::spawn(async move {
            let Some(miss) = policy
                .prepare_revalidation(
                    miss,
                    proxy_id.as_ref(),
                    route.id.as_str(),
                    gateway.http_cache_runtime.as_ref(),
                    gateway.metrics.as_ref(),
                )
                .await
            else {
                return;
            };
            let Some(proxy) = snap.proxy(proxy_id.as_ref()) else {
                gateway.metrics.inc_http_cache_revalidation_error();
                return;
            };
            // 缓存保存 identity 表示；与前台 miss 相同，不能让 Accept-Encoding 使上游先压缩。
            parts.headers.remove(http::header::ACCEPT_ENCODING);
            // 后台刷新脱离原 handler 生命周期，单独创建一个以原 server span 为父的内部
            // server span；这样 stale 请求可以先结束，刷新 client span 仍保持正确父子关系。
            let mut refresh_trace = gateway.telemetry.begin_server(
                &mut parts.headers,
                true,
                &parts.method,
                parts.uri.path(),
                downstream_proto,
                client_ip,
            );
            let response = gateway
                .forward(forward::ForwardRequest {
                    snap: &snap,
                    proxy,
                    route: &route,
                    parts,
                    body: full_body(Bytes::new()),
                    upstream_override: None,
                    path_override: None,
                    inference_endpoints: None,
                    client_ip,
                    client_ip_header: None,
                    trusted_inbound,
                    client_cert_verified,
                    downstream_proto,
                    request_id: &request_id,
                    consumer: None,
                    downstream_upgrade: None,
                    limit_conn_guards: Vec::new(),
                    websocket_max_lifetime_ms: None,
                    websocket_frame_limits: None,
                    trace: Some(&refresh_trace),
                })
                .await;
            let mut response = match response {
                Ok(response) => response,
                Err(error) => {
                    refresh_trace.finish(error.status().as_u16(), Some(route.id.as_str()), None, 1);
                    gateway.metrics.inc_http_cache_revalidation_error();
                    tracing::warn!(route = %route.id, %error, "HTTP cache background revalidation upstream failed");
                    return;
                }
            };
            let refresh_upstream = response
                .extensions()
                .get::<forward::UpstreamTrace>()
                .cloned();
            let refresh_status = response.status().as_u16();
            apply_response_filters(
                &mut response,
                &route,
                request_origin.as_ref(),
                None,
                client_ip,
                downstream_proto,
                &request_id,
            );
            if !route.sub_filters.is_empty() {
                response = wrap_sub_filter_response(response, route.sub_filters.clone());
            }
            response = policy.wrap_fill(
                response,
                miss,
                gateway.http_cache_runtime.clone(),
                gateway.metrics.clone(),
            );
            let fill_started = response.extensions().get::<HttpCacheFill>().is_some();
            while let Some(frame) = response.body_mut().frame().await {
                if let Err(error) = frame {
                    refresh_trace.finish(
                        502,
                        Some(route.id.as_str()),
                        refresh_upstream
                            .as_ref()
                            .map(|trace| trace.final_upstream.as_ref()),
                        refresh_upstream
                            .as_ref()
                            .map(|trace| trace.attempts)
                            .unwrap_or(1),
                    );
                    gateway.metrics.inc_http_cache_revalidation_error();
                    tracing::warn!(route = %route.id, %error, "HTTP cache background revalidation body failed");
                    return;
                }
                // data/trailer frame 在本轮立即释放；CacheFillBody 自己只保留受 max_body_bytes
                // 限制的一份 BytesMut，后台 drain 不再复制 payload。
            }
            refresh_trace.finish(
                refresh_status,
                Some(route.id.as_str()),
                refresh_upstream
                    .as_ref()
                    .map(|trace| trace.final_upstream.as_ref()),
                refresh_upstream
                    .as_ref()
                    .map(|trace| trace.attempts)
                    .unwrap_or(1),
            );
            if fill_started {
                gateway.metrics.inc_http_cache_revalidation_ok();
            } else {
                gateway.metrics.inc_http_cache_revalidation_skipped();
            }
        });
    }

    fn next_request_id(&self) -> RequestId {
        // 无锁 Snowflake ID 的十六进制展开(review L3)，贯穿下游→上游全链路。
        RequestId::from_u64(self.request_ids.generate())
    }

    fn finish_access(&self, enabled: bool, build_record: impl FnOnce() -> AccessRecord) {
        // 闭包是关键：只在启用态才 materialize record。不能把 `AccessRecord` 作为参数后再判断，
        // 因为 Rust 会在调用前完成 trace-id、route/upstream 和审计字段的 clone/格式化。
        if enabled {
            self.access_log.log(build_record());
        }
    }

    /// 执行 `error_page reroute=` 的内部 route 渲染。
    ///
    async fn serve_internal_reroute(
        &self,
        req: InternalRerouteRequest<'_>,
    ) -> Result<(Response<BoxBody>, Arc<Route>), Response<BoxBody>> {
        let mut parts = req.original_parts.clone();
        let uri = req
            .target
            .parse::<http::Uri>()
            .map_err(|_| text_status(500, "invalid internal reroute target"))?;
        parts.uri = uri;
        let Some(route) = req.proxy.router.match_internal_route(&parts) else {
            return Err(text_status(500, "internal reroute target not found"));
        };
        let mut resp = if let Some(direct) = &route.direct_response {
            direct_response(direct)
        } else if let Some(static_serve) = &route.static_serve {
            let eval_ctx = EvalContext {
                parts: &parts,
                client_ip: req.client_ip,
                downstream_proto: req.downstream_proto,
                request_id: req.request_id,
                route_id: route.id.as_str(),
                response_status: None,
            };
            static_serve
                .serve(&parts, route.variables.as_ref(), &eval_ctx)
                .await
        } else {
            return Err(text_status(500, "internal reroute target unsupported"));
        };
        if let Some(trace) = req.upstream_trace {
            resp.extensions_mut().insert(trace);
        }
        Ok((resp, route))
    }

    /// 业务作用：执行本地认证与 `ext_authz` 组合，并在外部响应头进入请求前冻结可信身份。
    ///
    /// 参数说明：`snap`/`proxy` 提供外部鉴权运行环境，`route` 是命中路由，`parts`/`forward_body`
    /// 是可变请求且仅在标准 SAML POST binding 时有界读取并原样重放；`client_ip`/`trusted_inbound`/
    /// `downstream_proto` 是连接信任上下文，`request_id`/`trace` 关联外呼，`identity` 接收冻结身份，
    /// `long_connection_consumer` 可接收长流主体。
    ///
    /// 返回：认证链放行返回 None 并完成身份头清洗/可信注入；凭据、重放或外部依赖失败返回拒绝响应。
    #[allow(clippy::too_many_arguments)]
    async fn enforce_auth_chain(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        parts: &mut Parts,
        forward_body: &mut Option<forward::ForwardBody>,
        client_ip: IpAddr,
        trusted_inbound: bool,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
        identity: &mut AuthorizationIdentity,
        long_connection_consumer: Option<&mut Option<Arc<str>>>,
    ) -> Option<Response<BoxBody>> {
        let auth_body = match collect_auth_body(route, parts, forward_body).await {
            Ok(body) => body,
            Err(response) => return Some(response),
        };
        // 防重放必须先于 satisfy：有效签名的 nonce 一旦复用就不能借另一种认证方式绕过。
        // 仅在签名本身有效后消费 nonce，避免攻击者用垃圾输入污染去重状态。
        if route.has_hmac_replay()
            && route
                .hmac_replay_detected(parts, auth_body.as_deref(), self.replay_guard.as_ref())
                .await
        {
            return Some(text_status(401, "hmac replay detected"));
        }
        let oidc = match route.oidc_rp_authenticate(parts).await {
            Some(crate::routing::OidcRpDecision::Response(response)) => return Some(response),
            Some(crate::routing::OidcRpDecision::Authenticated {
                consumer,
                claims,
                identity_headers,
            }) => Some((consumer, claims, identity_headers)),
            None => None,
        };
        let saml_response = match extract_saml_post_response(route, parts, forward_body).await {
            Ok(response) => response,
            Err(response) => return Some(response),
        };
        let resolved = route
            .resolved_auth_state(parts, saml_response.as_deref(), auth_body.as_deref())
            .await;
        let local_configured = resolved.configured || oidc.is_some();
        let local_ok = oidc.is_some() || resolved.ok;
        let authenticated = local_configured && local_ok;
        let (oidc_consumer, oidc_claims, oidc_identity_headers) = oidc
            .map(|(consumer, claims, headers)| (Some(consumer), Some(claims), headers))
            .unwrap_or_default();
        // 身份只从外部鉴权尚未触碰的原始请求冻结；后续绝不重新解释被注入的凭据头。
        let frozen = AuthorizationIdentity {
            authenticated,
            consumer: oidc_consumer.or(resolved.consumer),
            jwt_claims: oidc_claims.or(resolved.jwt_claims),
        };
        let mut generated_identity_headers = resolved.identity_headers;
        generated_identity_headers.extend(oidc_identity_headers);
        if !route.has_ext_authz() {
            if !local_ok {
                return Some(auth_failed_response(route.auth_challenge(parts).as_deref()));
            }
            route.apply_identity_headers(parts, &generated_identity_headers);
            if let Some(output) = long_connection_consumer {
                *output = frozen.consumer.clone();
            }
            *identity = frozen;
            return None;
        }
        match route.satisfy {
            SatisfyMode::All if local_configured && !local_ok => {
                // `all` 语义不能通过发起外呼掩盖本地凭据失败，先拒绝也避免无意义依赖流量。
                return Some(auth_failed_response(route.auth_challenge(parts).as_deref()));
            }
            SatisfyMode::Any if local_configured && local_ok => {
                route.apply_identity_headers(parts, &generated_identity_headers);
                if let Some(output) = long_connection_consumer {
                    *output = frozen.consumer.clone();
                }
                *identity = frozen;
                return None;
            }
            _ => {}
        }
        let decision = self
            .authorize_ext_authz(
                snap,
                proxy,
                route,
                parts,
                client_ip,
                trusted_inbound,
                downstream_proto,
                request_id,
                trace,
                auth_body.as_ref(),
            )
            .await;
        match decision {
            forward::ExtAuthzDecision::Allowed => {
                // 网关拥有的 JWT identity header 在外部注入完成后重建，确保客户端和 ext_authz
                // 都不能覆盖受信 claim；没有合法 JWT 时同名头仍会被彻底删除。
                route.apply_identity_headers(parts, &generated_identity_headers);
                if let Some(output) = long_connection_consumer {
                    *output = frozen.consumer.clone();
                }
                *identity = frozen;
                None
            }
            forward::ExtAuthzDecision::Denied { status, challenge } => {
                Some(auth_denied_response(status, challenge.as_ref()))
            }
            forward::ExtAuthzDecision::Unavailable => {
                Some(text_status(503, "ext authz unavailable"))
            }
        }
    }

    /// 执行 V7 外部 HTTP request_headers 插件链。
    ///
    /// 业务作用：在请求进入上游前按顺序提交外部插件 head 变更，并仅为配置了 response
    /// phase 的链保存 allowlist 快照；失败模式保持插件级 fail-open/fail-closed 契约。
    ///
    /// 链内每个插件先完整解析/校验 delta，再原子修改当前 head；fail-open 只丢弃本插件，
    /// 不会泄漏半套变更。业务 body 始终留在 `ForwardBody`，此函数只编码 allowlist head。
    #[allow(clippy::too_many_arguments)]
    async fn enforce_external_request_headers(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        parts: &mut Parts,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
        response_snapshot: &mut Option<Box<crate::external_plugin::ExternalRequestHeadSnapshot>>,
    ) -> Option<Response<BoxBody>> {
        let Some(chain) = &route.external_plugins else {
            return None;
        };
        for plugin in chain.request_plugins() {
            let payload = match plugin.encode_request(parts, downstream_proto, route.id.as_str()) {
                Ok(payload) => payload,
                Err(error) => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::InvalidInput);
                    tracing::warn!(route = %route.id, plugin = plugin.id(), ?error, "external request plugin input rejected");
                    return Some(match error {
                        crate::external_plugin::ExternalPluginInputError::InvalidHeader
                        | crate::external_plugin::ExternalPluginInputError::TooLarge => {
                            text_status(431, "external plugin input is too large or invalid")
                        }
                        crate::external_plugin::ExternalPluginInputError::Encode => {
                            text_status(500, "external plugin input encoding failed")
                        }
                    });
                }
            };
            match self
                .call_external_plugin(snap, proxy, route, plugin, payload, request_id, trace)
                .await
            {
                Ok(crate::external_plugin::ExternalPluginAction::Continue(changes)) => {
                    changes.apply_request(parts);
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::Continue);
                }
                Ok(crate::external_plugin::ExternalPluginAction::LocalResponse(response)) => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::LocalResponse);
                    return Some(response);
                }
                Err(error) if plugin.fail_open() => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::FailOpen);
                    tracing::warn!(route = %route.id, plugin = plugin.id(), %error, "external request plugin failed open");
                }
                Err(error) => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::Error);
                    tracing::warn!(route = %route.id, plugin = plugin.id(), %error, "external request plugin failed closed");
                    return Some(text_status(500, "external request plugin failed"));
                }
            }
        }
        *response_snapshot = chain
            .capture_request_head(parts, downstream_proto)
            .map(Box::new);
        None
    }

    /// 执行 V7 外部 HTTP response_headers 插件链。只修改 response head；body 保持原流，
    /// 除非插件显式返回有界 local_response，此时丢弃原 body 会自然取消上游读取。
    #[allow(clippy::too_many_arguments)]
    async fn enforce_external_response_headers(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        response: &mut Response<BoxBody>,
        request: &crate::external_plugin::ExternalRequestHeadSnapshot,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> Option<Response<BoxBody>> {
        let chain = route
            .external_plugins
            .as_ref()
            .expect("response external plugin requires a built chain");
        for plugin in chain.response_plugins() {
            let payload = match plugin.encode_response(request, response, route.id.as_str()) {
                Ok(payload) => payload,
                Err(error) => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::InvalidInput);
                    tracing::warn!(route = %route.id, plugin = plugin.id(), ?error, "external response plugin input rejected");
                    return Some(text_status(500, "external response plugin input invalid"));
                }
            };
            match self
                .call_external_plugin(snap, proxy, route, plugin, payload, request_id, trace)
                .await
            {
                Ok(crate::external_plugin::ExternalPluginAction::Continue(changes)) => {
                    changes.apply_response(response);
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::Continue);
                }
                Ok(crate::external_plugin::ExternalPluginAction::LocalResponse(local)) => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::LocalResponse);
                    return Some(local);
                }
                Err(error) if plugin.fail_open() => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::FailOpen);
                    tracing::warn!(route = %route.id, plugin = plugin.id(), %error, "external response plugin failed open");
                }
                Err(error) => {
                    self.metrics
                        .inc_external_plugin(ExternalPluginMetric::Error);
                    tracing::warn!(route = %route.id, plugin = plugin.id(), %error, "external response plugin failed closed");
                    return Some(text_status(500, "external response plugin failed"));
                }
            }
        }
        None
    }

    /// 业务作用：为 route 建立一条 External Processing 双向流，并按声明顺序处理 request
    /// headers/body/trailers；任何 mutation 都在完整权限复验后才原子写入请求。
    ///
    /// 参数说明：快照与 route 固定扩展目标；`parts`/`body` 是当前请求唯一所有权；
    /// `session_out` 把同一协议流交给响应阶段继续使用。
    ///
    /// 返回：继续代理返回 None；即时响应、输入越界或 fail-closed 错误返回本地响应。
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "ext-proc")]
    async fn enforce_ext_proc_request(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        parts: &mut Parts,
        body: &mut Option<forward::ForwardBody>,
        request_end_of_stream: bool,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
        session_out: &mut Option<SharedExtProcSession>,
    ) -> Option<Response<BoxBody>> {
        let Some(plan) = &route.ext_proc else {
            return None;
        };
        let mut permit = match plan.acquire() {
            Ok(permit) => permit,
            Err(error) if plan.fail_open() && error.may_fail_open() => {
                tracing::warn!(route = %route.id, %error, "ext_proc admission failed open");
                return None;
            }
            Err(error) => {
                tracing::warn!(route = %route.id, %error, "ext_proc admission failed closed");
                return Some(text_status(503, "external processor unavailable"));
            }
        };
        let wire = match self.open_ext_proc_stream(snap, proxy, route, plan, request_id, trace) {
            Ok(wire) => wire,
            Err(error) => {
                if error.may_fail_open() {
                    permit.record_dependency_failure();
                }
                if plan.fail_open() && error.may_fail_open() {
                    tracing::warn!(route = %route.id, %error, "ext_proc stream creation failed open");
                    return None;
                }
                tracing::warn!(route = %route.id, %error, "ext_proc stream creation failed closed");
                return Some(text_status(503, "external processor unavailable"));
            }
        };
        let session = plan.start_session(wire, permit);
        *session_out = Some(session.clone());
        let (
            request_headers,
            request_body,
            request_trailers,
            response_headers,
            response_body,
            response_trailers,
        ) = plan.phases();
        let has_response_phase = response_headers
            || response_body != crate::config::model::ExtProcBodyModeCfg::None
            || response_trailers;
        if plan.pipelines_buffered_request_body() {
            let current = body
                .take()
                .expect("request body is owned exactly once by the filter pipeline");
            let collected = match collect_wasm_box_body(current, plan.max_body_bytes()).await {
                Ok(collected) => collected,
                Err(WasmBodyError::TooLarge) => {
                    return Some(text_status(
                        413,
                        "external processor request body exceeds limit",
                    ));
                }
                Err(WasmBodyError::Read(error)) => {
                    tracing::warn!(route = %route.id, %error, "read inference EPP request body failed");
                    return Some(text_status(400, "invalid request body"));
                }
            };
            let mut bytes = collected.bytes;
            let head_uri = ext_proc_request_uri(parts, downstream_proto);
            let actions = {
                let mut state = session.lock().await;
                state
                    .process_pipelined_request(
                        (
                            &parts.method,
                            &head_uri,
                            &parts.headers,
                            request_end_of_stream,
                        ),
                        &bytes,
                    )
                    .await
            };
            let (header_action, body_action) = match actions {
                Ok(actions) => actions,
                Err(error) => {
                    let mut state = session.lock().await;
                    if state.apply_failure(&error) {
                        // 依赖故障放行仍必须重建已经有界读取的原请求体，不能把空实体交给池后端。
                        normalize_content_length(&mut parts.headers, bytes.len());
                        *body = Some(replay_wasm_body(bytes, collected.trailers));
                        tracing::warn!(route = %route.id, %error, "inference EPP request failed open");
                        return None;
                    }
                    tracing::warn!(route = %route.id, %error, "inference EPP request failed closed");
                    return Some(text_status(500, "external processor rejected request"));
                }
            };
            match header_action {
                ExtProcAction::Continue(changes) => {
                    changes.apply_headers(&mut parts.headers);
                    bytes = changes.apply_body(bytes);
                }
                ExtProcAction::Immediate(response) => {
                    session.lock().await.finish_after_immediate();
                    return Some(response);
                }
            }
            if let Some(action) = body_action {
                match action {
                    ExtProcAction::Continue(changes) => {
                        changes.apply_headers(&mut parts.headers);
                        bytes = changes.apply_body(bytes);
                    }
                    ExtProcAction::Immediate(response) => {
                        session.lock().await.finish_after_immediate();
                        return Some(response);
                    }
                }
            }
            normalize_content_length(&mut parts.headers, bytes.len());
            *body = Some(replay_wasm_body(bytes, collected.trailers));
            if !has_response_phase {
                session.lock().await.finish();
            }
            return None;
        }
        let mut replaced_tail = false;
        if request_headers {
            let head_uri = ext_proc_request_uri(parts, downstream_proto);
            let action = {
                let mut session = session.lock().await;
                session
                    .process(
                        ExtProcPhase::RequestHeaders,
                        Some((
                            &parts.method,
                            &head_uri,
                            &parts.headers,
                            request_end_of_stream
                                && request_body == crate::config::model::ExtProcBodyModeCfg::None
                                && !request_trailers,
                        )),
                        None,
                        None,
                    )
                    .await
            };
            match action {
                Ok(ExtProcAction::Continue(changes)) => {
                    changes.apply_headers(&mut parts.headers);
                    if changes.replaces_body() {
                        let bytes = changes.apply_body(Bytes::new());
                        normalize_content_length(&mut parts.headers, bytes.len());
                        *body = Some(full_body(bytes));
                        replaced_tail = true;
                    }
                }
                Ok(ExtProcAction::Immediate(response)) => {
                    session.lock().await.finish_after_immediate();
                    return Some(response);
                }
                Err(error) => {
                    let mut session = session.lock().await;
                    if session.apply_failure(&error) {
                        tracing::warn!(route = %route.id, %error, "ext_proc request headers failed open");
                        return None;
                    }
                    tracing::warn!(route = %route.id, %error, "ext_proc request headers failed closed");
                    return Some(text_status(500, "external processor rejected request"));
                }
            }
        }
        if replaced_tail {
            if !has_response_phase {
                session.lock().await.finish();
            }
            return None;
        }
        match request_body {
            crate::config::model::ExtProcBodyModeCfg::Streamed => {
                let current = body
                    .take()
                    .expect("request body is owned exactly once by the filter pipeline");
                parts.headers.remove(http::header::CONTENT_LENGTH);
                *body = Some(wrap_ext_proc_body(
                    current,
                    session,
                    ExtProcPhase::RequestBody,
                    request_trailers,
                    plan.max_body_bytes(),
                    !has_response_phase,
                ));
            }
            crate::config::model::ExtProcBodyModeCfg::Buffered
            | crate::config::model::ExtProcBodyModeCfg::None
                if request_body == crate::config::model::ExtProcBodyModeCfg::Buffered
                    || request_trailers =>
            {
                let current = body
                    .take()
                    .expect("request body is owned exactly once by the filter pipeline");
                let collected = match collect_wasm_box_body(current, plan.max_body_bytes()).await {
                    Ok(collected) => collected,
                    Err(WasmBodyError::TooLarge) => {
                        return Some(text_status(
                            413,
                            "external processor request body exceeds limit",
                        ));
                    }
                    Err(WasmBodyError::Read(error)) => {
                        tracing::warn!(route = %route.id, %error, "read ext_proc request body failed");
                        return Some(text_status(400, "invalid request body"));
                    }
                };
                let mut bytes = collected.bytes;
                if request_body == crate::config::model::ExtProcBodyModeCfg::Buffered {
                    let action = {
                        let mut session = session.lock().await;
                        session
                            .process(
                                ExtProcPhase::RequestBody,
                                None,
                                Some((&bytes, collected.trailers.is_none() || !request_trailers)),
                                None,
                            )
                            .await
                    };
                    match action {
                        Ok(ExtProcAction::Continue(changes)) => {
                            changes.apply_headers(&mut parts.headers);
                            bytes = changes.apply_body(bytes);
                        }
                        Ok(ExtProcAction::Immediate(response)) => {
                            session.lock().await.finish_after_immediate();
                            return Some(response);
                        }
                        Err(error) => {
                            let mut session = session.lock().await;
                            if !session.apply_failure(&error) {
                                tracing::warn!(route = %route.id, %error, "ext_proc request body failed closed");
                                return Some(text_status(
                                    500,
                                    "external processor rejected request",
                                ));
                            }
                        }
                    }
                }
                let mut trailers = collected.trailers;
                if request_trailers {
                    if let Some(current) = trailers.as_mut() {
                        let action = {
                            let mut session = session.lock().await;
                            session
                                .process(ExtProcPhase::RequestTrailers, None, None, Some(current))
                                .await
                        };
                        match action {
                            Ok(ExtProcAction::Continue(changes)) => {
                                changes.apply_headers(current);
                            }
                            Ok(ExtProcAction::Immediate(response)) => {
                                session.lock().await.finish_after_immediate();
                                return Some(response);
                            }
                            Err(error) => {
                                let mut session = session.lock().await;
                                if !session.apply_failure(&error) {
                                    tracing::warn!(route = %route.id, %error, "ext_proc request trailers failed closed");
                                    return Some(text_status(
                                        500,
                                        "external processor rejected request",
                                    ));
                                }
                            }
                        }
                    }
                }
                normalize_content_length(&mut parts.headers, bytes.len());
                *body = Some(replay_wasm_body(bytes, trailers));
                if !has_response_phase {
                    session.lock().await.finish();
                }
            }
            crate::config::model::ExtProcBodyModeCfg::None => {
                if !has_response_phase {
                    session.lock().await.finish();
                }
            }
            crate::config::model::ExtProcBodyModeCfg::Buffered => unreachable!(),
        }
        None
    }

    /// 业务作用：为未携带 `ext-proc` feature 的制品保留统一请求管线；配置层已经拒绝启用。
    ///
    /// 参数说明：参数只用于保持跨 feature 签名一致。
    ///
    /// 返回：始终继续普通代理。
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(feature = "ext-proc"))]
    async fn enforce_ext_proc_request(
        &self,
        _snap: &GatewaySnapshot,
        _proxy: &crate::config::ProxyRuntime,
        _route: &Route,
        _parts: &mut Parts,
        _body: &mut Option<forward::ForwardBody>,
        _request_end_of_stream: bool,
        _downstream_proto: &'static str,
        _request_id: &str,
        _trace: &crate::telemetry::ServerTrace,
        _session_out: &mut Option<crate::ext_proc::SharedExtProcSession>,
    ) -> Option<Response<BoxBody>> {
        None
    }

    /// 业务作用：把 EPP 的 header 或动态 metadata 决策收敛为数据面可执行的 endpoint
    /// 子集；正常协议流缺少决策时停止请求，只有依赖故障进入 `FailOpen` 才退回普通 LB。
    ///
    /// 参数说明：`route` 提供数量硬门；`parts` 持有 EPP mutation；`session` 表明正常或
    /// 放行状态；`selection_out` 接收仅供本次 forward 使用的不可变子集。
    ///
    /// 返回：决策合法或允许退回普通 LB 时返回 None；缺失、冲突或非法目标返回本地 500。
    #[cfg(feature = "inference-gateway")]
    async fn enforce_inference_pool_request(
        &self,
        route: &Route,
        parts: &mut Parts,
        session: &Option<SharedExtProcSession>,
        selection_out: &mut Option<forward::InferenceEndpointSelection>,
    ) -> Option<Response<BoxBody>> {
        let policy = route.inference_pool?;
        let header_values = parts
            .headers
            .get_all("x-gateway-destination-endpoint")
            .iter()
            .map(|value| value.to_str().map(str::to_owned))
            .collect::<std::result::Result<Vec<_>, _>>();
        parts.headers.remove("x-gateway-destination-endpoint");
        let header_value = match header_values {
            Ok(values) if values.len() <= 1 => values.into_iter().next(),
            Ok(_) | Err(_) => {
                return Some(text_status(
                    500,
                    "endpoint picker returned invalid selection",
                ));
            }
        };
        let Some(session) = session else {
            // 请求阶段没有建立会话只可能来自 ext_proc 已批准的依赖故障放行；此时按池目录
            // 自行选择，不能把任何残留控制头交给上游。
            return None;
        };
        let state = session.lock().await;
        if state.bypassed() {
            return None;
        }
        let metadata = state.metadata();
        drop(state);
        let metadata_value = metadata
            .string("envoy.lb", "x-gateway-destination-endpoint")
            .map(str::to_owned);
        let raw = match (header_value, metadata_value) {
            (Some(header), Some(metadata)) if header != metadata => {
                return Some(text_status(
                    500,
                    "endpoint picker returned conflicting selection",
                ));
            }
            (Some(header), _) => header,
            (_, Some(metadata)) => metadata,
            (None, None) => {
                return Some(text_status(500, "endpoint picker returned no selection"));
            }
        };
        match forward::InferenceEndpointSelection::parse(
            raw.as_str(),
            policy.max_selected_endpoints,
        ) {
            Ok(selection) => {
                *selection_out = Some(selection);
                None
            }
            Err(error) => {
                tracing::warn!(route = %route.id, %error, "endpoint picker returned invalid selection");
                Some(text_status(
                    500,
                    "endpoint picker returned invalid selection",
                ))
            }
        }
    }

    /// 业务作用：在未携带 Inference Gateway 能力的制品中保留统一调用形态；配置构建期会
    /// 拒绝任何 InferencePool route。
    ///
    /// 参数说明：所有参数只用于保持 feature 间签名一致。
    ///
    /// 返回：始终继续普通请求管线。
    #[cfg(not(feature = "inference-gateway"))]
    async fn enforce_inference_pool_request(
        &self,
        _route: &Route,
        _parts: &mut Parts,
        _session: &Option<crate::ext_proc::SharedExtProcSession>,
        _selection_out: &mut Option<forward::InferenceEndpointSelection>,
    ) -> Option<Response<BoxBody>> {
        None
    }

    /// 业务作用：在上游响应进入其它可变换 filter 前继续同一 External Processing 流，处理
    /// response headers/body/trailers 并在最终相位半关闭发送方向。
    ///
    /// 参数说明：`route` 固定处理计划；`response` 是当前响应唯一所有权；`session` 来自请求阶段；
    /// `request_method` 只用于构造标准响应 phase 输入占位。
    ///
    /// 返回：成功或依赖 fail-open 返回处理后的响应；协议、越权或资源错误返回 500。
    #[cfg(feature = "ext-proc")]
    async fn enforce_ext_proc_response(
        &self,
        route: &Route,
        mut response: Response<BoxBody>,
        session: &mut Option<SharedExtProcSession>,
        request_method: &Method,
    ) -> Response<BoxBody> {
        let Some(plan) = &route.ext_proc else {
            return response;
        };
        let Some(shared) = session.as_ref().cloned() else {
            return response;
        };
        if let Some(immediate) = shared.lock().await.take_pending_immediate() {
            return immediate;
        }
        if shared.lock().await.bypassed() {
            return response;
        }
        if route.inference_pool.is_some() {
            let served = response
                .extensions()
                .get::<forward::UpstreamTrace>()
                .and_then(|trace| trace.final_upstream.parse::<http::Uri>().ok())
                .and_then(|uri| uri.authority().map(ToString::to_string));
            let Some(served) = served else {
                // 正常 EPP 响应相位必须绑定到真实上游 reservation；缺少该事实时停止扩展
                // 交互，避免把请求阶段建议伪装成实际承载 endpoint。
                return text_status(500, "served endpoint is unavailable");
            };
            if let Err(error) = shared
                .lock()
                .await
                .set_destination_endpoint_served(served.as_str())
            {
                tracing::warn!(route = %route.id, %error, "record served endpoint failed");
                return text_status(500, "served endpoint is unavailable");
            }
        }
        let (_, _, _, response_headers, response_body, response_trailers) = plan.phases();
        let mut replaced_tail = false;
        if response_headers {
            let placeholder = http::Uri::from_static("/");
            let end = response.body().is_end_stream()
                && response_body == crate::config::model::ExtProcBodyModeCfg::None
                && !response_trailers;
            let action = {
                let mut state = shared.lock().await;
                state
                    .process(
                        ExtProcPhase::ResponseHeaders,
                        Some((request_method, &placeholder, response.headers(), end)),
                        None,
                        None,
                    )
                    .await
            };
            match action {
                Ok(ExtProcAction::Continue(changes)) => {
                    changes.apply_headers(response.headers_mut());
                    if changes.replaces_body() {
                        let bytes = changes.apply_body(Bytes::new());
                        normalize_content_length(response.headers_mut(), bytes.len());
                        *response.body_mut() = full_body(bytes);
                        replaced_tail = true;
                    }
                }
                Ok(ExtProcAction::Immediate(_)) => {
                    unreachable!("response phases cannot return immediate response")
                }
                Err(error) => {
                    let mut state = shared.lock().await;
                    if state.apply_failure(&error) {
                        tracing::warn!(route = %route.id, %error, "ext_proc response headers failed open");
                        return response;
                    }
                    tracing::warn!(route = %route.id, %error, "ext_proc response headers failed closed");
                    return text_status(500, "external processor rejected response");
                }
            }
        }
        if replaced_tail {
            shared.lock().await.finish();
            return response;
        }
        match response_body {
            crate::config::model::ExtProcBodyModeCfg::Streamed => {
                response.headers_mut().remove(http::header::CONTENT_LENGTH);
                let (parts, body) = response.into_parts();
                Response::from_parts(
                    parts,
                    wrap_ext_proc_body(
                        body,
                        shared,
                        ExtProcPhase::ResponseBody,
                        response_trailers,
                        plan.max_body_bytes(),
                        true,
                    ),
                )
            }
            crate::config::model::ExtProcBodyModeCfg::Buffered
            | crate::config::model::ExtProcBodyModeCfg::None
                if response_body == crate::config::model::ExtProcBodyModeCfg::Buffered
                    || response_trailers =>
            {
                let (mut parts, body) = response.into_parts();
                let collected = match collect_wasm_box_body(body, plan.max_body_bytes()).await {
                    Ok(collected) => collected,
                    Err(WasmBodyError::TooLarge) => {
                        return text_status(500, "external processor response body exceeds limit");
                    }
                    Err(WasmBodyError::Read(error)) => {
                        tracing::warn!(route = %route.id, %error, "read ext_proc response body failed");
                        return text_status(500, "external processor response body read failed");
                    }
                };
                let mut bytes = collected.bytes;
                if response_body == crate::config::model::ExtProcBodyModeCfg::Buffered {
                    let action = {
                        let mut state = shared.lock().await;
                        state
                            .process(
                                ExtProcPhase::ResponseBody,
                                None,
                                Some((&bytes, collected.trailers.is_none() || !response_trailers)),
                                None,
                            )
                            .await
                    };
                    match action {
                        Ok(ExtProcAction::Continue(changes)) => {
                            changes.apply_headers(&mut parts.headers);
                            bytes = changes.apply_body(bytes);
                        }
                        Ok(ExtProcAction::Immediate(_)) => {
                            unreachable!("response phases cannot return immediate response")
                        }
                        Err(error) => {
                            let mut state = shared.lock().await;
                            if !state.apply_failure(&error) {
                                tracing::warn!(route = %route.id, %error, "ext_proc response body failed closed");
                                return text_status(500, "external processor rejected response");
                            }
                        }
                    }
                }
                let mut trailers = collected.trailers;
                if response_trailers {
                    if let Some(current) = trailers.as_mut() {
                        let action = {
                            let mut state = shared.lock().await;
                            state
                                .process(ExtProcPhase::ResponseTrailers, None, None, Some(current))
                                .await
                        };
                        match action {
                            Ok(ExtProcAction::Continue(changes)) => changes.apply_headers(current),
                            Ok(ExtProcAction::Immediate(_)) => {
                                unreachable!("response phases cannot return immediate response")
                            }
                            Err(error) => {
                                let mut state = shared.lock().await;
                                if !state.apply_failure(&error) {
                                    tracing::warn!(route = %route.id, %error, "ext_proc response trailers failed closed");
                                    return text_status(
                                        500,
                                        "external processor rejected response",
                                    );
                                }
                            }
                        }
                    }
                }
                normalize_content_length(&mut parts.headers, bytes.len());
                let metadata = shared.lock().await.metadata();
                parts.extensions.insert(metadata);
                shared.lock().await.finish();
                Response::from_parts(parts, replay_wasm_body(bytes, trailers))
            }
            crate::config::model::ExtProcBodyModeCfg::None => {
                let metadata = shared.lock().await.metadata();
                response.extensions_mut().insert(metadata);
                shared.lock().await.finish();
                response
            }
            crate::config::model::ExtProcBodyModeCfg::Buffered => unreachable!(),
        }
    }

    /// 业务作用：为未携带 `ext-proc` feature 的制品保留统一响应管线。
    ///
    /// 参数说明：`response` 原样返回，其余参数只保持跨 feature 签名一致。
    ///
    /// 返回：未修改响应。
    #[cfg(not(feature = "ext-proc"))]
    async fn enforce_ext_proc_response(
        &self,
        _route: &Route,
        response: Response<BoxBody>,
        _session: &mut Option<crate::ext_proc::SharedExtProcSession>,
        _request_method: &Method,
    ) -> Response<BoxBody> {
        response
    }

    /// 业务作用：向启动接线与管理面暴露进程唯一 EdgeHub，使数据面与 metrics 读取同一份事实。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回共享 Hub 句柄，不复制订阅索引。
    #[cfg(feature = "grpc-edge")]
    pub fn grpc_edge_hub(&self) -> Arc<crate::edge_hub::EdgeHub> {
        self.edge_hub.clone()
    }

    /// 业务作用：在热更提交点原子发布当前集群中继 generation，使后续请求不再进入旧代。
    ///
    /// 参数说明：`relay` 是已完成 listener/成员计划准备的候选代。
    ///
    /// 返回：无返回值；原子交换后旧代排干由 reload 提交路径负责。
    #[cfg(feature = "grpc-edge")]
    pub fn attach_edge_relay(&self, relay: Arc<crate::edge_relay::EdgeRelay>) {
        self.edge_relay.store(Some(relay));
    }

    /// 业务作用：向管理面与 reload 暴露 relay 原子 slot，保证观测、发布和回滚共享同一权威。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回 slot 的共享句柄，调用方不得绕过准备阶段写入未就绪 relay。
    #[cfg(feature = "grpc-edge")]
    pub fn edge_relay_slot(&self) -> Arc<arc_swap::ArcSwapOption<crate::edge_relay::EdgeRelay>> {
        self.edge_relay.clone()
    }

    /// 业务作用：读取当前已发布 relay generation，供启动接线和低频控制路径执行一致语义。
    ///
    /// 参数说明：无。
    ///
    /// 返回：已发布时返回 relay；单机或 Redis bus 模式返回 `None`。
    #[cfg(feature = "grpc-edge")]
    pub fn current_edge_relay(&self) -> Option<Arc<crate::edge_relay::EdgeRelay>> {
        self.edge_relay.load_full()
    }

    /// 业务作用：原子发布 Redis Pub/Sub 集群总线代。
    ///
    /// 参数说明：`bus` 是已建连并完成订阅的候选代。
    ///
    /// 返回：无返回值；后续请求只能选新代。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_redis_bus(&self, bus: Arc<crate::edge_redis_bus::EdgeRedisBus>) {
        self.edge_redis_bus.store(Some(bus));
    }

    /// 业务作用：向管理观测面共享 Pub/Sub 原子 slot，使 metrics 跟随热换代而非固定初始句柄。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回 Proxy 持有的唯一当前代 slot。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn edge_redis_bus_slot(
        &self,
    ) -> Arc<arc_swap::ArcSwapOption<crate::edge_redis_bus::EdgeRedisBus>> {
        self.edge_redis_bus.clone()
    }

    /// 业务作用：原子发布 Redis Stream 集群总线代。
    ///
    /// 参数说明：`bus` 是已建连并完成 XREAD 订阅的候选代。
    ///
    /// 返回：无返回值；后续请求只能选新代。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_redis_stream(&self, bus: Arc<crate::edge_redis_bus::EdgeRedisStreamBus>) {
        self.edge_redis_stream.store(Some(bus));
    }

    /// 业务作用：向管理观测面共享 Redis Stream 原子 slot，使 metrics 只读取当前发布代。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回 Proxy 持有的唯一当前代 slot。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn edge_redis_stream_slot(
        &self,
    ) -> Arc<arc_swap::ArcSwapOption<crate::edge_redis_bus::EdgeRedisStreamBus>> {
        self.edge_redis_stream.clone()
    }

    /// 业务作用：清除已失去配置 owner 的 relay slot。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回切换前的 relay 代，供提交方排空。
    #[cfg(feature = "grpc-edge")]
    pub fn clear_edge_relay(&self) -> Option<Arc<crate::edge_relay::EdgeRelay>> {
        self.edge_relay.swap(None)
    }

    /// 业务作用：清除已失去配置 owner 的 Pub/Sub slot。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回切换前的总线代，供提交方取消。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn clear_edge_redis_bus(&self) -> Option<Arc<crate::edge_redis_bus::EdgeRedisBus>> {
        self.edge_redis_bus.swap(None)
    }

    /// 业务作用：清除已失去配置 owner 的 Stream slot。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回切换前的总线代，供提交方取消。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn clear_edge_redis_stream(
        &self,
    ) -> Option<Arc<crate::edge_redis_bus::EdgeRedisStreamBus>> {
        self.edge_redis_stream.swap(None)
    }

    /// 业务作用：统一选择 relay 或 Redis 的 single-session 权威并完成 fencing claim。
    ///
    /// 参数说明：`tenant`/`user` 是已经通过认证映射与长度门的订阅身份。
    ///
    /// 返回：未启用 single-session 时返回 `Ok(None)`；全网 fencing 成功返回 token；
    /// 控制面缺席、失权或 ACK 不完整时返回静态错误并禁止登记新订阅。
    #[cfg(feature = "grpc-edge")]
    async fn claim_edge_single_session(
        &self,
        tenant: Arc<str>,
        user: Arc<str>,
    ) -> Result<Option<u64>, &'static str> {
        if let Some(relay) = self.edge_relay.load_full().filter(|relay| {
            relay.session_mode() == crate::config::model::GrpcEdgeSessionModeCfg::SingleSession
        }) {
            return relay.claim_single_session(tenant, user).await.map(Some);
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self
            .edge_redis_bus
            .load_full()
            .filter(|bus| bus.single_session_enabled())
        {
            return bus.claim_single_session(tenant, user).await.map(Some);
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self
            .edge_redis_stream
            .load_full()
            .filter(|bus| bus.single_session_enabled())
        {
            return bus.claim_single_session(tenant, user).await.map(Some);
        }
        Ok(None)
    }

    /// 业务作用：统一选择 relay owner 或 Redis 排序权威执行强顺序群播。
    ///
    /// 参数说明：`limits` 是入口 route 预算；`tenant`/`group` 是作用域；`frame` 是完整 gRPC 帧；
    /// `reassembled` 是本入口跨 DATA 重组字节。
    ///
    /// 返回：未配置 `group_owner` 时返回 `None` 让调用方走 local-first；启用时返回强路径结果，
    /// 权威不可用或本地回执超时必须作为错误上送，不能静默降级。
    #[cfg(feature = "grpc-edge")]
    async fn publish_edge_group_owned(
        &self,
        limits: &crate::grpc_edge::GrpcEdgeLimitsPlan,
        tenant: Arc<str>,
        group: Arc<str>,
        frame: Bytes,
        reassembled: u64,
    ) -> Option<
        Result<
            (
                crate::edge_hub::LocalFanoutOutcome,
                crate::edge_relay::PeerBroadcastSummary,
            ),
            &'static str,
        >,
    > {
        if let Some(relay) = self
            .edge_relay
            .load_full()
            .filter(|relay| relay.group_owner_enabled())
        {
            return Some(
                relay
                    .publish_group_owned(limits, tenant, group, frame, reassembled)
                    .await,
            );
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self
            .edge_redis_bus
            .load_full()
            .filter(|bus| bus.group_owner_enabled())
        {
            return Some(
                bus.publish_group_owned(limits, tenant, group, frame, reassembled)
                    .await,
            );
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self
            .edge_redis_stream
            .load_full()
            .filter(|bus| bus.group_owner_enabled())
        {
            return Some(
                bus.publish_group_owned(limits, tenant, group, frame, reassembled)
                    .await,
            );
        }
        None
    }

    /// 业务作用：注入可选 SessionDirectory，让跨节点 push 优先使用可信在线位置。
    ///
    /// 参数说明：`directory` 是已连接的进程级目录句柄。
    ///
    /// 返回：无；首次注入生效，重复调用保持原句柄。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_directory(&self, directory: Arc<crate::edge_directory::SessionDirectory>) {
        let _ = self.edge_directory.set(directory);
    }

    /// 业务作用：执行 WS 桥接握手与订阅登记，让浏览器复用 native edge 的身份、授权和 fencing 语义。
    ///
    /// 参数说明：`route`/`parts` 提供已匹配配置与请求 head，`downstream_upgrade` 转移升级权；
    /// `client_ip`/`consumer` 是可信身份上下文，`snapshot_version`/`proxy_runtime` 提供治理登记。
    ///
    /// 返回：成功返回 101 并启动有界桥接；任一握手、授权、claim 或预算门失败返回对应 4xx/5xx，
    /// 且不会留下订阅或连接注册残影。
    ///
    /// 相位序与 native subscribe 完全一致(§25.2.3):鉴权已由上游 auth chain 执行,
    /// 这里只做 ①WS 升级头合法性 ②group 来自 query ③身份仅取已验证 principal
    /// ④EdgeHub 准入登记 ⑤101 + 后台桥接循环。任何失败都发生在登记之前。
    #[allow(clippy::too_many_arguments)]
    async fn handle_edge_ws_bridge(
        &self,
        route: &Arc<Route>,
        parts: &Parts,
        downstream_upgrade: &mut DownstreamUpgrade,
        client_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
        proxy_runtime: &crate::config::ProxyRuntime,
    ) -> Response<BoxBody> {
        #[cfg(not(feature = "grpc-edge"))]
        {
            let _ = (
                route,
                parts,
                downstream_upgrade,
                client_ip,
                consumer,
                snapshot_version,
                proxy_runtime,
            );
            text_status(500, "grpc edge mode requires the grpc-edge feature")
        }
        #[cfg(feature = "grpc-edge")]
        {
            use crate::edge_ws_bridge as bridge;

            let plan = route
                .grpc_edge
                .as_ref()
                .expect("ws bridge branch requires a compiled plan");
            let Some(client_key) = bridge::upgrade_key(parts) else {
                return text_status(400, "edge ws bridge requires a valid websocket upgrade");
            };
            // 升级句柄由管线在识别 WS 时就取好(与既有隧道路径同源);连接预算 lease
            // 随之移交桥接任务,避免 101 后 hyper future 结束提前归还名额。
            let Some((upgrade, connection_lease)) = downstream_upgrade.take() else {
                return text_status(400, "edge ws bridge requires an upgradable connection");
            };
            let Some(group) = bridge::query_param(parts.uri.query(), "group") else {
                return text_status(400, "edge ws bridge requires a group query parameter");
            };
            if group.is_empty() || group.len() > plan.limits.max_id_bytes {
                return text_status(400, "edge ws bridge group is out of bounds");
            }
            // 身份只来自已验证 principal,与 native subscribe 同一条规则。
            let Some(principal) = route
                .authenticated_edge_claim(parts, &plan.identity.user_claim)
                .or(consumer)
            else {
                return text_status(401, "edge ws bridge requires an authenticated principal");
            };
            let tenant: Arc<str> = match plan.identity.tenant_claim.as_deref() {
                Some(claim) => match route.authenticated_edge_claim(parts, claim) {
                    Some(tenant) => tenant,
                    None => return text_status(401, "edge ws bridge tenant claim is missing"),
                },
                None => Arc::from("default"),
            };
            if principal.len() > plan.limits.max_id_bytes || tenant.len() > plan.limits.max_id_bytes
            {
                return text_status(400, "edge ws bridge identity exceeds max_id_bytes");
            }
            // 桥接只换传输外壳，授权判据必须与 native subscribe 完全一致——
            // 少这一段就等于给出一条绕过 group 策略的旁路。HTTP 语义下用 403。
            if let Some(authz) = plan.authz.as_ref() {
                if !authz.allows(
                    crate::grpc_edge::GrpcEdgeAction::Subscribe,
                    group,
                    &principal,
                    &tenant,
                ) {
                    return text_status(403, "edge ws bridge scope is not allowed for principal");
                }
            }
            let single_token = match self
                .claim_edge_single_session(tenant.clone(), principal.clone())
                .await
            {
                Ok(token) => token,
                Err(reason) => return text_status(503, reason),
            };
            let subscription_result = match single_token {
                Some(token) => self.edge_hub.subscribe_single(
                    plan,
                    tenant,
                    principal.clone(),
                    Arc::from(group),
                    token,
                ),
                None => self
                    .edge_hub
                    .subscribe(plan, tenant, principal.clone(), Arc::from(group)),
            };
            let subscription = match subscription_result {
                Ok(subscription) => subscription,
                // 预算耗尽:HTTP 语义下用 503,浏览器据此退避重连。
                Err(err) => return text_status(503, err.reason()),
            };
            let Some(accept) = bridge::accept_key(&client_key) else {
                return text_status(400, "edge ws bridge key is invalid");
            };
            let guard = self.conn_registry.register(
                route.id_shared.clone(),
                client_ip,
                Some(principal),
                snapshot_version,
                LongProto::Ws,
            );
            let idle = Duration::from_millis(
                route
                    .long_stream_idle_timeout_ms
                    .unwrap_or(proxy_runtime.timeouts.stream_idle_timeout_ms),
            );
            let lifetime = Duration::from_millis(route.long_stream_max_lifetime_ms);
            let mut response = Response::builder().status(101);
            for (name, value) in bridge::handshake_headers(&accept).expect("valid accept header") {
                response = response.header(name, value);
            }
            let response = response
                .body(crate::full_body(bytes::Bytes::new()))
                .expect("build ws bridge handshake");
            // hyper 在 101 发出后完成升级;桥接任务持有订阅、注册表守卫与连接 lease,
            // 结束即摘索引并归还名额。
            tokio::spawn(async move {
                let _lease = connection_lease;
                match upgrade.await {
                    Ok(upgraded) => {
                        bridge::run_bridge(upgraded, subscription, guard, idle, lifetime).await;
                    }
                    Err(error) => {
                        // 升级失败(客户端提前断开):立即摘索引,不留幽灵订阅。
                        tracing::debug!(error = %error, "edge ws bridge upgrade failed");
                        drop(subscription);
                        drop(guard);
                    }
                }
            });
            response
        }
    }

    /// 业务作用：分发 native gRPC edge Subscribe/Publish/PublishStream/Push，并在四重门后自响应。
    ///
    /// 参数说明：`route`/`action`/`parts` 是精确方法匹配结果，`forward_body` 提供有界请求流；
    /// `grpc_request`/`client_ip`/`consumer` 是协议和可信身份上下文，版本/runtime 用于治理登记。
    ///
    /// 返回：成功返回合法 gRPC response/trailer；协议、授权、预算、mesh 或 fencing 失败映射为固定状态，
    /// edge 端点绝不静默退化成普通上游转发。
    #[allow(clippy::too_many_arguments)]
    async fn handle_grpc_edge(
        &self,
        route: &Arc<Route>,
        action: crate::grpc_edge::GrpcEdgeAction,
        parts: &Parts,
        forward_body: &mut Option<forward::ForwardBody>,
        grpc_request: bool,
        client_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
        proxy_runtime: &crate::config::ProxyRuntime,
    ) -> Response<BoxBody> {
        #[cfg(not(feature = "grpc-edge"))]
        {
            // 构建期 fail-fast 保证无 feature 二进制不可能持有 edge 计划;此臂仅为类型完备。
            let _ = (
                route,
                action,
                parts,
                forward_body,
                grpc_request,
                client_ip,
                consumer,
                snapshot_version,
                proxy_runtime,
            );
            text_status(500, "grpc edge mode requires the grpc-edge feature")
        }
        #[cfg(feature = "grpc-edge")]
        {
            use crate::edge_hub::{self, GrpcDecodeError, SingleMessageError};
            use crate::grpc_edge::GrpcEdgeAction;

            let plan = route
                .grpc_edge
                .as_ref()
                .expect("edge branch requires a compiled plan");
            // 相位 1:必须是原生 HTTP/2 gRPC;边缘端点不接受任何降级形态(§25.2.3)。
            if !grpc_request {
                return text_status(400, "edge endpoint requires native HTTP/2 gRPC");
            }
            // 相位 3:方法→action 已由精确 :path 决定,这里校验平面 allowed_actions。
            let allowed = match action {
                GrpcEdgeAction::Subscribe => plan.allow_subscribe,
                GrpcEdgeAction::Publish | GrpcEdgeAction::PublishStream => plan.allow_publish,
                GrpcEdgeAction::Push => plan.allow_push,
            };
            if !allowed {
                return grpc_edge_status("7", "edge-action-not-allowed-on-this-plane");
            }
            // 相位 2:单值、可见 ASCII、有界的 edge 元数据;action header 只是 v1 二次确认,
            // 与方法冲突即拒(不能用可伪造 header 覆盖方法语义)。
            let max_id = plan.limits.max_id_bytes;
            let action_meta = match single_edge_metadata(parts, &plan.action_header, 32) {
                Ok(Some(value)) => value,
                Ok(None) => return grpc_edge_status("3", "edge-action-header-required"),
                Err(msg) => return grpc_edge_status("3", msg),
            };
            if action_meta != action.header_value() {
                return grpc_edge_status("3", "edge-action-header-conflicts-with-method");
            }
            let group = match single_edge_metadata(parts, &plan.group_header, max_id) {
                Ok(value) => value,
                Err(msg) => return grpc_edge_status("3", msg),
            };
            let target = match single_edge_metadata(parts, &plan.target_header, max_id) {
                Ok(value) => value,
                Err(msg) => return grpc_edge_status("3", msg),
            };
            // 相位 2:v1 编码恒 identity(§25.2.3);显式声明其它 grpc-encoding 直接拒。
            // 逐消息压缩位另由解帧器强制——仅查 header 不够,两道都要。
            if parts
                .headers
                .get_all("grpc-encoding")
                .iter()
                .any(|value| value.as_bytes() != b"identity")
            {
                return grpc_edge_status("3", "grpc-encoding-must-be-identity");
            }
            // 相位 2 交叉校验:group/target 与 action 的搭配矩阵(§25.2.3)。
            // scope = subscribe/publish 的 group id,或 push 的目标 user。
            let scope: &str = match action {
                GrpcEdgeAction::Subscribe
                | GrpcEdgeAction::Publish
                | GrpcEdgeAction::PublishStream => {
                    if target.is_some() {
                        return grpc_edge_status(
                            "3",
                            if action == GrpcEdgeAction::Subscribe {
                                "target-header-invalid-on-subscribe"
                            } else {
                                "target-header-invalid-on-publish"
                            },
                        );
                    }
                    match group {
                        Some(group) => group,
                        None => {
                            return grpc_edge_status(
                                "3",
                                if action == GrpcEdgeAction::Subscribe {
                                    "subscribe-requires-group-header"
                                } else {
                                    "publish-requires-group-header"
                                },
                            )
                        }
                    }
                }
                GrpcEdgeAction::Push => {
                    if group.is_some() {
                        return grpc_edge_status("3", "group-header-invalid-on-push");
                    }
                    match target {
                        Some(target) => target,
                        None => return grpc_edge_status("3", "push-requires-target-header"),
                    }
                }
            };
            // 相位 4:身份只来自已验证 principal——JWT claim 优先,非 JWT 认证回落到
            // 已认证 consumer;两者皆无 → UNAUTHENTICATED。客户端自报 header 永不参与。
            // subscribe 用 principal 做订阅者身份;publish/push 只做"必须有已验证发布方"
            // 的门(发布面服务凭证,§25.2.3 相位 4 认证先于一切执行)。
            let principal: Arc<str> = match route
                .authenticated_edge_claim(parts, &plan.identity.user_claim)
                .or(consumer)
            {
                Some(principal) => principal,
                None => {
                    return grpc_edge_status(
                        "16",
                        match action {
                            GrpcEdgeAction::Subscribe => {
                                "subscribe-requires-authenticated-principal"
                            }
                            GrpcEdgeAction::Publish | GrpcEdgeAction::PublishStream => {
                                "publish-requires-authenticated-principal"
                            }
                            GrpcEdgeAction::Push => "push-requires-authenticated-principal",
                        },
                    )
                }
            };
            let tenant: Arc<str> = match plan.identity.tenant_claim.as_deref() {
                Some(claim) => match route.authenticated_edge_claim(parts, claim) {
                    Some(tenant) => tenant,
                    None => return grpc_edge_status("16", "tenant-claim-missing-from-principal"),
                },
                None => Arc::from("default"),
            };
            if principal.len() > max_id || tenant.len() > max_id {
                return grpc_edge_status("3", "identity-exceeds-max-id-bytes");
            }
            // 相位 4.5 执行授权；相位 4 只回答了「你是谁」，`scope`（group 或 push target）
            // 是**客户端给的**,此前只过了长度与字符集。这里回答「你能碰哪个 group」。
            //
            // 位置是安全语义的一部分:必须在身份确定之后、任何订阅登记/散出/入队之前。
            // 放行前不产生任何可观察副作用,被拒的探测请求就无法从资源占用或时序上
            // 反推某个 group 是否存在。文案统一为 7 PERMISSION_DENIED,不回显 group,
            // 避免把"这个 group 存在但你没权限"与"不存在"区分开。
            if let Some(authz) = plan.authz.as_ref() {
                if !authz.allows(action, scope, &principal, &tenant) {
                    return grpc_edge_status("7", "edge-scope-not-allowed-for-principal");
                }
            }
            // PublishStream 在此分流——增量解码逐条散出，不适用下方
            // "恰一条 + EOS"的 unary 读取契约(§25.2.3 四门执行语义)。
            if action == GrpcEdgeAction::PublishStream {
                let Some(body) = forward_body.take() else {
                    return text_status(500, "edge request body already consumed");
                };
                let group: Arc<str> = Arc::from(scope);
                let guard = self.conn_registry.register(
                    route.id_shared.clone(),
                    client_ip,
                    Some(principal.clone()),
                    snapshot_version,
                    LongProto::GrpcStream,
                );
                return self
                    .run_publish_stream(plan, tenant, group, body, guard)
                    .await;
            }
            // 相位 6 前置:有界读取恰好一个 message + EOS(SubReq 与 unary FramePush
            // 同一契约);任何失败都发生在登记 session / 散出之前。
            let Some(body) = forward_body.take() else {
                return text_status(500, "edge request body already consumed");
            };
            let read = edge_hub::read_single_message(
                body,
                plan.limits.max_msg_bytes,
                edge_hub::SUBSCRIBE_READ_DEADLINE,
            )
            .await;
            let (frame, reassembled) = match read {
                Ok(ok) => ok,
                Err(SingleMessageError::Decode(GrpcDecodeError::MessageTooLarge { .. })) => {
                    return grpc_edge_status(
                        "8",
                        match action {
                            GrpcEdgeAction::Subscribe => "subscribe-request-exceeds-max-msg-bytes",
                            GrpcEdgeAction::Push => "push-request-exceeds-max-msg-bytes",
                            _ => "publish-request-exceeds-max-msg-bytes",
                        },
                    )
                }
                Err(SingleMessageError::Transport(_)) => {
                    return grpc_edge_status(
                        "14",
                        match action {
                            GrpcEdgeAction::Subscribe => "client-transport-failed-during-subscribe",
                            GrpcEdgeAction::Push => "client-transport-failed-during-push",
                            _ => "client-transport-failed-during-publish",
                        },
                    )
                }
                Err(_) => {
                    return grpc_edge_status(
                        "3",
                        match action {
                            GrpcEdgeAction::Subscribe => "subscribe-requires-exactly-one-message",
                            GrpcEdgeAction::Push => "push-requires-exactly-one-message",
                            _ => "publish-requires-exactly-one-message",
                        },
                    )
                }
            };
            // 相位 6 按 action 执行订阅自响应或本地散出；跨节点投递再交给 relay。
            match action {
                GrpcEdgeAction::Subscribe => {
                    // SubReq payload 对网关 opaque(§25.2.2);v1 订阅语义全在 metadata,
                    // 已读出的 frame 弃用即可。准入 + 登记(EdgeHub 索引 + §6.1 注册表),
                    // 然后自响应。
                    let hub = self.edge_hub.clone();
                    let single_token = match self
                        .claim_edge_single_session(tenant.clone(), principal.clone())
                        .await
                    {
                        Ok(token) => token,
                        Err(reason) => return grpc_edge_status("14", reason),
                    };
                    let subscription_result = match single_token {
                        Some(token) => hub.subscribe_single(
                            plan,
                            tenant.clone(),
                            principal.clone(),
                            Arc::from(scope),
                            token,
                        ),
                        None => {
                            hub.subscribe(plan, tenant.clone(), principal.clone(), Arc::from(scope))
                        }
                    };
                    let subscription = match subscription_result {
                        Ok(subscription) => subscription,
                        Err(err) => return grpc_edge_status("8", err.reason()),
                    };
                    #[cfg(feature = "redis-runtime")]
                    let principal_for_lease = principal.clone();
                    let guard = self.conn_registry.register(
                        route.id_shared.clone(),
                        client_ip,
                        Some(principal),
                        snapshot_version,
                        LongProto::GrpcStream,
                    );
                    let idle_ms = route
                        .long_stream_idle_timeout_ms
                        .unwrap_or(proxy_runtime.timeouts.stream_idle_timeout_ms);
                    // 先取 stream_id 再交出 subscription，确保目录租约与订阅流同生共死。
                    #[cfg(feature = "redis-runtime")]
                    let stream_id = subscription.stream_id();
                    let body = crate::edge_hub::EdgeSubscribeBody::new(
                        subscription,
                        guard,
                        idle_ms,
                        route.long_stream_max_lifetime_ms,
                    );
                    #[cfg(feature = "redis-runtime")]
                    let body =
                        match self.edge_directory.get() {
                            Some(directory) => body.with_directory_lease(Arc::new(
                                directory.lease(tenant, principal_for_lease, stream_id),
                            )),
                            None => body,
                        };
                    // 成功响应:200 + application/grpc,初始 HEADERS 不带 grpc-status
                    // (§25.2.3);后续帧与收尾 trailer 全部由 channel-backed body 产出。
                    Response::builder()
                        .status(200)
                        .header(
                            http::header::CONTENT_TYPE,
                            HeaderValue::from_static("application/grpc"),
                        )
                        .body(body.boxed())
                        .expect("build edge subscribe response")
                }
                GrpcEdgeAction::Publish => {
                    // 群播本地散出:唯一 payload 记账一次,N 个订阅队列只复制共享引用。
                    // 空组不是错误(订阅天然竞态),诚实回 accepted=0。集群模式再向全部
                    // peers 中继同一份 payload(引用计数,零复制),固定 deadline 聚合回执。
                    let group: Arc<str> = Arc::from(scope);
                    let (outcome, peers) = if let Some(result) = self
                        .publish_edge_group_owned(
                            &plan.limits,
                            tenant.clone(),
                            group.clone(),
                            frame.clone(),
                            reassembled,
                        )
                        .await
                    {
                        match result {
                            Ok(result) => result,
                            Err(reason) => return grpc_edge_status("14", reason),
                        }
                    } else {
                        let peer_broadcast = self.broadcast_publish_across_cluster(
                            tenant.clone(),
                            group.clone(),
                            frame.clone(),
                        );
                        let outcome = match self
                            .edge_hub
                            .publish_group(&plan.limits, tenant, group, frame, reassembled)
                            .await
                        {
                            Ok(outcome) => outcome,
                            Err(err) => return grpc_edge_status("8", err.reason()),
                        };
                        let peers = match peer_broadcast {
                            Some(pending) => pending.await,
                            None => crate::edge_relay::PeerBroadcastSummary::default(),
                        };
                        (outcome, peers)
                    };
                    // PublishSummary(§25.2.8 诚实口径):accepted=入队份数(绝不叫
                    // delivered,入队≠终端已消费);dropped=本帧未入队份数(drop_new/
                    // 已关环 + queue_refs 预算拒绝);closed_slow=本次触发断流的成员数;
                    // messages=已处理消息数(unary 恒 1,流式续传凭它判断进度);
                    // 5/6/7=peer 聚合(接受份数/拒绝 peer 数/断线或无回执 peer 数)。
                    edge_unary_summary(&[
                        (field::ACCEPTED, u64::from(outcome.accepted)),
                        (
                            field::DROPPED,
                            outcome.dropped_new + u64::from(outcome.dropped_budget),
                        ),
                        (field::CLOSED_SLOW, u64::from(outcome.closed_slow)),
                        (field::MESSAGES, 1),
                        (field::PEERS_ACCEPTED, peers.accepted_copies),
                        (field::PEERS_REJECTED, u64::from(peers.peers_rejected)),
                        (field::PEERS_UNKNOWN, u64::from(peers.peers_unknown)),
                    ])
                }
                GrpcEdgeAction::Push => {
                    // 定向单播:目标 user 的全部在线 session 各一份(multi_session,
                    // §25.2.7)。session_registry=none 时向全部静态 peers 做一次 hop=1
                    // broadcast-probe;各节点只查本地索引,不会再次 relay。
                    // 配置指路条时先 locate 定向投递；脏条目回落一次全量 probe。
                    let user: Arc<str> = Arc::from(scope);
                    let peers = self
                        .push_across_cluster(tenant.clone(), user.clone(), frame.clone())
                        .await;
                    let outcome = match self
                        .edge_hub
                        .push_user(&plan.limits, tenant, user, frame, reassembled)
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => return grpc_edge_status("8", err.reason()),
                    };
                    // broadcast-probe 全体未命中(§25.2.7):目标不在线不是错误,但必须
                    // 全部本地与 peer 均未命中必须计数，避免业务无响应却没有可观测证据。
                    if outcome.accepted == 0 && peers.accepted_copies == 0 {
                        if let Some(relay) = self.edge_relay.load_full() {
                            relay.note_probe_miss();
                        }
                    }
                    // PushSummary：1=本地实际入队 session；5=peer 实际入队份数；
                    // 6/7=拒绝/未知 peer。入队不等于终端已消费。
                    edge_unary_summary(&[
                        (field::ACCEPTED, u64::from(outcome.accepted)),
                        (field::PEERS_ACCEPTED, peers.accepted_copies),
                        (field::PEERS_REJECTED, u64::from(peers.peers_rejected)),
                        (field::PEERS_UNKNOWN, u64::from(peers.peers_unknown)),
                    ])
                }
                // 已在身份门后分流进 run_publish_stream;此臂静态不可达,仅为穷尽性。
                GrpcEdgeAction::PublishStream => {
                    text_status(500, "publish-stream dispatched above")
                }
            }
        }
    }

    /// 业务作用：把一条 push 送到集群其余节点，并聚合 peer 接受、拒绝与未知结果。
    ///
    /// 无 relay（单机）→ 全零；无指路条 → 全量 broadcast-probe；
    /// 有指路条 → `locate` 后只打被寻址的 peer;**脏目录**(命中却零投递)再回落
    /// 一次全量 probe——目录只省 probe,不改变投递结果(§25.2.7:目录不是单点)。
    #[cfg(feature = "grpc-edge")]
    async fn push_across_cluster(
        &self,
        tenant: Arc<str>,
        user: Arc<str>,
        frame: bytes::Bytes,
    ) -> crate::edge_relay::PeerBroadcastSummary {
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self.edge_redis_stream.load_full() {
            return bus.broadcast_push(&tenant, &user, frame).await;
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self.edge_redis_bus.load_full() {
            return bus.broadcast_push(&tenant, &user, frame).await;
        }
        let Some(relay) = self.edge_relay.load_full() else {
            return crate::edge_relay::PeerBroadcastSummary::default();
        };
        #[cfg(feature = "redis-runtime")]
        if let Some(directory) = self.edge_directory.get() {
            if let Some(mut nodes) = directory.locate(&tenant, &user).await {
                // 本地那份由调用方直接散出,目录里的本节点条目不该再发一条 relay。
                nodes.remove(directory.node_id().as_ref());
                if nodes.is_empty() {
                    // 只在本地在线:完全跳过 probe(命中的最大收益)。
                    return crate::edge_relay::PeerBroadcastSummary::default();
                }
                let targeted = relay
                    .push_to_nodes(tenant.clone(), user.clone(), frame.clone(), nodes)
                    .await;
                if targeted.accepted_copies > 0 {
                    return targeted;
                }
                // 脏条目:节点已不在线/user 已迁移。回落一次全量 probe 并计数。
                directory.note_fallback();
                return relay.broadcast_push(tenant, user, frame).await;
            }
            // miss/目录不可用:回落 broadcast-probe(正确性不依赖目录)。
            directory.note_fallback();
        }
        relay.broadcast_push(tenant, user, frame).await
    }

    /// 为 unary Publish 与 PublishStream 提供统一的集群传输选择。
    #[cfg(feature = "grpc-edge")]
    fn broadcast_publish_across_cluster(
        &self,
        tenant: Arc<str>,
        group: Arc<str>,
        frame: bytes::Bytes,
    ) -> Option<futures::future::BoxFuture<'static, crate::edge_relay::PeerBroadcastSummary>> {
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self.edge_redis_stream.load_full() {
            return Some(Box::pin(async move {
                bus.broadcast_publish(&tenant, &group, frame).await
            }));
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(bus) = self.edge_redis_bus.load_full() {
            return Some(Box::pin(async move {
                bus.broadcast_publish(&tenant, &group, frame).await
            }));
        }
        self.edge_relay.load_full().map(|relay| {
            Box::pin(async move { relay.broadcast_publish(tenant, group, frame).await })
                as futures::future::BoxFuture<'static, crate::edge_relay::PeerBroadcastSummary>
        })
    }

    /// 业务作用：执行 PublishStream 增量散出主循环，并在单流四门内汇总可续传进度。
    ///
    /// 逐消息:解帧 → 节流令牌 → `publish_group` 本地散出,聚合 accepted/dropped/
    /// closed_slow/messages。rate=背压节流(无令牌即暂停读体,H2 流控传导到发布方);
    /// lifetime/累计消息/累计字节到界=**优雅轮转**(停读、返聚合 summary+OK,发布方
    /// 凭 `messages` 字段判断进度重建流);节点预算耗尽=8;framing 错=3;传输错=14。
    /// 到界后已解出未散出的消息按 at-most-once 丢弃,发布方按 summary 续传补偿。
    #[cfg(feature = "grpc-edge")]
    async fn run_publish_stream<B>(
        &self,
        plan: &crate::grpc_edge::GrpcEdgePlan,
        tenant: Arc<str>,
        group: Arc<str>,
        body: B,
        guard: crate::conn_registry::ConnGuard,
    ) -> Response<BoxBody>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Unpin,
        B::Error: Into<crate::resp::BoxError>,
    {
        use crate::edge_hub::{GrpcDecodeError, GrpcMessageDecoder, StreamRateGate};
        use futures::stream::FuturesUnordered;
        use futures::{FutureExt, StreamExt};

        let gates = &plan.publish_stream;
        let deadline = tokio::time::Instant::now() + gates.max_lifetime;
        let mut rate = StreamRateGate::new(gates.max_msgs_per_sec);
        let mut decoder = GrpcMessageDecoder::new(plan.limits.max_msg_bytes);
        let mut pending: Vec<bytes::Bytes> = Vec::new();
        let mut body = std::pin::pin!(body);
        // 聚合 summary(u64 累计;单流消息数被 max_messages 钉死,不会回绕)。
        let mut messages: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut accepted: u64 = 0;
        let mut dropped: u64 = 0;
        let mut closed_slow: u64 = 0;
        // 已上报给 hub 的重组字节水位(逐消息报增量,计数器口径不重不漏)。
        let mut reported_reassembly: u64 = 0;
        let mut clean_eos = false;
        let mut draining = false;
        let mut close_wait = Box::pin(guard.closed());
        // 集群中继:逐消息广播挂进 FuturesUnordered 异步聚合,不阻塞散出节奏;
        // 每个 future 内部以 ack_deadline 自我了结,总量被队列/在途上限钉死。
        let mut peer_pending = FuturesUnordered::new();
        let mut peer_copies: u64 = 0;
        let mut peers_rejected: u64 = 0;
        let mut peers_unknown: u64 = 0;

        'stream: loop {
            let next_result = tokio::select! {
                biased;
                () = close_wait.as_mut() => {
                    draining = true;
                    break 'stream;
                }
                result = tokio::time::timeout_at(
                    deadline,
                    std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)),
                ) => result,
            };
            let next = match next_result {
                // lifetime 到界:优雅轮转,已聚合部分如实返回。
                Err(_) => break 'stream,
                Ok(None) => {
                    clean_eos = true;
                    break 'stream;
                }
                Ok(Some(Err(_))) => {
                    return grpc_edge_status("14", "client-transport-failed-during-publish")
                }
                Ok(Some(Ok(frame))) => frame,
            };
            let mut chunk = match next.into_data() {
                Ok(chunk) => chunk,
                // 请求侧不该有 trailers;出现即协议错误(§25.2.3)。
                Err(_trailers) => {
                    return grpc_edge_status("3", "publish-stream-unexpected-request-trailers")
                }
            };
            if let Err(err) = decoder.feed(&mut chunk, &mut pending) {
                return match err {
                    GrpcDecodeError::MessageTooLarge { .. } => {
                        grpc_edge_status("8", "publish-request-exceeds-max-msg-bytes")
                    }
                    _ => grpc_edge_status("3", "publish-stream-invalid-grpc-framing"),
                };
            }
            for frame in pending.drain(..) {
                let frame_len = frame.len() as u64;
                // 累计门在散出之前判定:到界即停,不把越界消息散出去。
                if messages >= gates.max_messages || total_bytes + frame_len > gates.max_total_bytes
                {
                    break 'stream;
                }
                // 节流(背压点);等待期间 lifetime 照常生效。
                let rate_result = tokio::select! {
                    biased;
                    () = close_wait.as_mut() => {
                        draining = true;
                        break 'stream;
                    }
                    result = tokio::time::timeout_at(deadline, rate.acquire()) => result,
                };
                if rate_result.is_err() {
                    break 'stream;
                }
                let reassembled_total = decoder.reassembled_bytes();
                let delta = reassembled_total - reported_reassembly;
                reported_reassembly = reassembled_total;
                // 集群模式:同一 payload 引用先留一份给中继,再 move 进本地散出。
                let (outcome, peer_broadcast) = if let Some(result) = self
                    .publish_edge_group_owned(
                        &plan.limits,
                        tenant.clone(),
                        group.clone(),
                        frame.clone(),
                        delta,
                    )
                    .await
                {
                    match result {
                        Ok((outcome, peers)) => {
                            peer_copies += peers.accepted_copies;
                            peers_rejected += u64::from(peers.peers_rejected);
                            peers_unknown += u64::from(peers.peers_unknown);
                            (outcome, None)
                        }
                        Err(reason) => return grpc_edge_status("14", reason),
                    }
                } else {
                    let peer_broadcast = self.broadcast_publish_across_cluster(
                        tenant.clone(),
                        group.clone(),
                        frame.clone(),
                    );
                    let outcome = match self
                        .edge_hub
                        .publish_group(&plan.limits, tenant.clone(), group.clone(), frame, delta)
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => return grpc_edge_status("8", err.reason()),
                    };
                    (outcome, peer_broadcast)
                };
                messages += 1;
                total_bytes += frame_len;
                accepted += u64::from(outcome.accepted);
                dropped += outcome.dropped_new + u64::from(outcome.dropped_budget);
                closed_slow += u64::from(outcome.closed_slow);
                #[cfg(feature = "redis-runtime")]
                let peer_broadcast = {
                    let mut pending_broadcast = peer_broadcast;
                    // Redis Pub/Sub 没有 relay 的有序 per-peer enqueue queue。若把同一
                    // PublishStream 的多个 PUBLISH future 并发轮询，Redis 到达顺序没有契约；
                    // 因此该模式逐条等待命令完成，同时把有限背压传回 gRPC 发布流。
                    if self.edge_redis_bus.load().is_some()
                        || self.edge_redis_stream.load().is_some()
                    {
                        if let Some(pending) = pending_broadcast.take() {
                            let summary = pending.await;
                            peer_copies += summary.accepted_copies;
                            peers_rejected += u64::from(summary.peers_rejected);
                            peers_unknown += u64::from(summary.peers_unknown);
                        }
                    }
                    pending_broadcast
                };
                if let Some(pending) = peer_broadcast {
                    peer_pending.push(pending);
                }
                // 机会式排干已完成的 peer 聚合,不为它阻塞散出节奏。
                while let Some(Some(summary)) = peer_pending.next().now_or_never() {
                    peer_copies += summary.accepted_copies;
                    peers_rejected += u64::from(summary.peers_rejected);
                    peers_unknown += u64::from(summary.peers_unknown);
                }
            }
        }
        // 正常 EOS 必须停在完整帧边界;半帧截断按协议错报 3(§25.2.4)。
        if clean_eos && decoder.finish().is_err() {
            return grpc_edge_status("3", "publish-stream-invalid-grpc-framing");
        }
        // 排干剩余 peer 聚合:每个 future 内部以 ack_deadline 自我了结,
        // 此处等待被"最后一条消息的 deadline"钉死,不会悬挂。
        while let Some(summary) = peer_pending.next().await {
            peer_copies += summary.accepted_copies;
            peers_rejected += u64::from(summary.peers_rejected);
            peers_unknown += u64::from(summary.peers_unknown);
        }
        if draining {
            let message = if guard.ws_close_code() == 1008 {
                "gateway-policy-violation"
            } else {
                "gateway-draining"
            };
            return grpc_edge_status("14", message);
        }
        edge_unary_summary(&[
            (field::ACCEPTED, accepted),
            (field::DROPPED, dropped),
            (field::CLOSED_SLOW, closed_slow),
            (field::MESSAGES, messages),
            (field::PEERS_ACCEPTED, peer_copies),
            (field::PEERS_REJECTED, peers_rejected),
            (field::PEERS_UNKNOWN, peers_unknown),
        ])
    }

    #[allow(clippy::too_many_arguments)]
    async fn call_external_plugin(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        plugin: &crate::external_plugin::ExternalPlugin,
        payload: crate::external_plugin::ExternalPluginPayload,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> anyhow::Result<crate::external_plugin::ExternalPluginAction> {
        let started = Instant::now();
        let response = self
            .send_external_plugin_request(snap, proxy, route, plugin, payload, request_id, trace)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !response.status().is_success()
            || !crate::external_plugin::response_is_json(response.headers())
        {
            anyhow::bail!(
                "invalid response head with status {}",
                response.status().as_u16()
            );
        }
        let remaining = plugin
            .timeout()
            .checked_sub(started.elapsed())
            .filter(|duration| !duration.is_zero())
            .context("external plugin total deadline expired")?;
        let (parts, body) = response.into_parts();
        let body = tokio::time::timeout(
            remaining,
            crate::external_plugin::collect_response(
                body,
                &parts.headers,
                plugin.max_response_bytes(),
            ),
        )
        .await
        .context("external plugin response-body timeout")??;
        plugin.parse_action(&body)
    }

    /// 执行 V7 OPA 授权。业务 body 始终留在 `forward_body`，这里只读取请求 head。
    ///
    /// 顺序固定在认证之后、GraphQL/限流/cache/circuit/upstream 之前：OPA 的 consumer 只能来自
    /// 已放行的认证链，deny 又不会占用后续资源。CORS preflight 没有业务 operation，继续交 CORS
    /// filter；不能因 require_identity 把浏览器 capability probe 拒掉。
    #[allow(clippy::too_many_arguments)]
    async fn enforce_opa_authorization(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        parts: &mut Parts,
        forward_body: &mut Option<forward::ForwardBody>,
        authenticated: bool,
        consumer: Option<&str>,
        jwt_claims: Option<&serde_json::Value>,
        client_ip: IpAddr,
        downstream_proto: &'static str,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
        response_obligations: &mut Option<OpaObligations>,
    ) -> Option<Response<BoxBody>> {
        let Some(policy) = &route.opa_authorization else {
            return None;
        };
        if is_cors_preflight(parts, route) {
            return None;
        }
        let mut request_body = None;
        if policy.includes_body() {
            if !policy.permits_body_content_type(&parts.headers) {
                self.metrics
                    .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                return Some(text_status(
                    415,
                    "OPA request body media type is not allowed",
                ));
            }
            let current = forward_body
                .take()
                .expect("OPA request body is owned exactly once by the authorization pipeline");
            let collected = match collect_wasm_forward_body(current, policy.max_body_bytes()).await
            {
                Ok(collected) => collected,
                Err(WasmBodyError::TooLarge) => {
                    self.metrics
                        .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                    return Some(text_status(413, "OPA request body exceeds limit"));
                }
                Err(WasmBodyError::Read(error)) => {
                    self.metrics
                        .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                    tracing::warn!(route = %route.id, %error, "read OPA request body failed");
                    return Some(text_status(400, "invalid OPA request body"));
                }
            };
            // 同一已验证字节同时进入 policy input 与后续业务管线；先重建 body，任何后续短路都不会
            // 留下半消费状态，成功路径也不会把策略读取变成上游 body 丢失。
            *forward_body = Some(replay_wasm_body(
                collected.bytes.clone(),
                collected.trailers,
            ));
            match serde_json::from_slice::<serde_json::Value>(&collected.bytes) {
                Ok(value) => request_body = Some(value),
                Err(error) => {
                    self.metrics
                        .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                    tracing::debug!(route = %route.id, %error, "OPA request body JSON is invalid");
                    return Some(text_status(400, "OPA request body must be valid JSON"));
                }
            }
        }
        // `authenticated`/`consumer` 已在 ext_authz 之前从同步认证链冻结；本阶段不重新
        // 解释任何可能被外部授权服务注入的 header，更不会读取客户端 X-Auth-User。
        let input = OpaRequestContext::new(
            parts,
            client_ip,
            downstream_proto,
            route.id.as_str(),
            authenticated,
            consumer,
            policy.includes_jwt_claims().then_some(jwt_claims).flatten(),
            request_body.as_ref(),
        );
        let cache_key = match policy.input_cache_key(&input) {
            Ok(key) => key,
            Err(OpaInputError::MissingIdentity) => {
                self.metrics.inc_opa_decision(OpaDecisionMetric::Deny);
                return Some(text_status(403, "OPA authorization requires identity"));
            }
            Err(OpaInputError::InvalidHeader | OpaInputError::TooLarge) => {
                self.metrics
                    .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                return Some(text_status(431, "OPA authorization input is too large"));
            }
            Err(OpaInputError::Encode) => {
                self.metrics
                    .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                return Some(text_status(500, "OPA authorization input encoding failed"));
            }
        };
        if policy.cache_enabled() {
            if let Some(decision) = policy.cached_decision(&cache_key).await {
                self.metrics.inc_opa_cache(OpaCacheMetric::Hit);
                return self.apply_opa_decision(
                    decision,
                    parts,
                    response_obligations,
                    route.id.as_str(),
                );
            }
            if let Some(decision) = self.lookup_distributed_opa(policy, &cache_key).await {
                self.metrics.inc_opa_cache(OpaCacheMetric::Hit);
                policy.store_decision(cache_key, decision.clone()).await;
                return self.apply_opa_decision(
                    decision,
                    parts,
                    response_obligations,
                    route.id.as_str(),
                );
            }
            self.metrics.inc_opa_cache(OpaCacheMetric::Miss);
        }
        let _flight_guard = match policy.acquire_flight(cache_key) {
            OpaFlightRole::Leader(guard) => Some(guard),
            OpaFlightRole::Follower(flight) => {
                if !policy.wait_flight(&flight).await {
                    tracing::warn!(route = %route.id, "OPA single-flight follower timed out");
                    return self.opa_unavailable(policy);
                }
                if let Some(decision) = policy.cached_decision(&cache_key).await {
                    self.metrics.inc_opa_cache(OpaCacheMetric::Hit);
                    return self.apply_opa_decision(
                        decision,
                        parts,
                        response_obligations,
                        route.id.as_str(),
                    );
                }
                if let Some(decision) = self.lookup_distributed_opa(policy, &cache_key).await {
                    policy.store_decision(cache_key, decision.clone()).await;
                    return self.apply_opa_decision(
                        decision,
                        parts,
                        response_obligations,
                        route.id.as_str(),
                    );
                }
                // leader 未产生可缓存的明确结果，follower 不立刻重试依赖，避免失败风暴重新形成。
                return self.opa_unavailable(policy);
            }
            OpaFlightRole::Bypass => None,
        };
        if policy.backoff_active() {
            return self.opa_unavailable(policy);
        }
        let payload = match policy.encode_input(cache_key, &input) {
            Ok(payload) => payload,
            Err(OpaInputError::MissingIdentity) => {
                self.metrics.inc_opa_decision(OpaDecisionMetric::Deny);
                return Some(text_status(403, "OPA authorization requires identity"));
            }
            Err(OpaInputError::InvalidHeader | OpaInputError::TooLarge) => {
                self.metrics
                    .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                return Some(text_status(431, "OPA authorization input is too large"));
            }
            Err(OpaInputError::Encode) => {
                self.metrics
                    .inc_opa_decision(OpaDecisionMetric::InvalidInput);
                return Some(text_status(500, "OPA authorization input encoding failed"));
            }
        };
        let cache_key = payload.cache_key;
        let decision = match if policy.is_external() {
            self.evaluate_external_opa(snap, proxy, route, policy, payload, request_id, trace)
                .await
        } else {
            policy.evaluate_embedded(&payload)
        } {
            Ok(decision) => decision,
            Err(error) => {
                self.metrics.inc_opa_request(OpaRequestMetric::Error);
                policy.record_failure();
                tracing::warn!(route = %route.id, error = %error, "OPA authorization dependency failed");
                return self.opa_unavailable(policy);
            }
        };
        self.metrics.inc_opa_request(OpaRequestMetric::Success);
        policy.record_success();
        policy.store_decision(cache_key, decision.clone()).await;
        self.store_distributed_opa(policy, &cache_key, &decision)
            .await;
        self.apply_opa_decision(decision, parts, response_obligations, route.id.as_str())
    }

    /// 业务作用：执行一次外部 OPA Data API 求值，把 transport/head/body/protocol 全部纳入同一总 deadline。
    ///
    /// 参数说明：`snap/proxy/route/policy` 固定上游计划，`payload` 是有界 input，`request_id/trace` 关联子请求。
    ///
    /// 返回：仅合法 2xx JSON 与完整 decision 返回成功；网络、超时、media type、大小或 obligation 错误返回 dependency failure。
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_external_opa(
        &self,
        snap: &GatewaySnapshot,
        proxy: &crate::config::ProxyRuntime,
        route: &Route,
        policy: &crate::opa::OpaPolicy,
        payload: crate::opa::OpaInputPayload,
        request_id: &str,
        trace: &crate::telemetry::ServerTrace,
    ) -> anyhow::Result<OpaDecision> {
        let started = Instant::now();
        let response = self
            .send_opa_request(snap, proxy, route, policy, payload, request_id, trace)
            .await
            .context("send OPA authorization request")?;
        if !response.status().is_success() || !crate::opa::response_is_json(response.headers()) {
            anyhow::bail!(
                "OPA authorization returned invalid status/media type: {}",
                response.status()
            );
        }
        let remaining = policy
            .timeout()
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .context("OPA authorization response deadline elapsed")?;
        let (response_parts, response_body) = response.into_parts();
        let body = tokio::time::timeout(
            remaining,
            crate::opa::collect_response(
                response_body,
                &response_parts.headers,
                policy.max_response_bytes(),
            ),
        )
        .await
        .context("OPA authorization response body timeout")??;
        policy.parse_decision(&body)
    }

    /// 业务作用：查询可选跨节点 OPA decision cache，并在本地复验 revision、expiry 与 obligations。
    ///
    /// 参数说明：`policy` 提供 collection/contract，`key` 是不含原始输入的 SHA-256 摘要。
    ///
    /// 返回：合法命中返回 decision；miss/过期/后端错误/坏值统一返回 None，坏值会尽力删除且不影响授权安全默认。
    async fn lookup_distributed_opa(
        &self,
        policy: &crate::opa::OpaPolicy,
        key: &[u8; 32],
    ) -> Option<OpaDecision> {
        let (collection, _) = policy.distributed_cache()?;
        let store_key = policy.distributed_key(key);
        let encoded = match self.dynamic_store.get(collection, &store_key).await {
            Ok(Some(encoded)) => encoded,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "OPA distributed decision cache lookup failed");
                return None;
            }
        };
        match policy.decode_distributed_decision(&encoded) {
            Ok(Some(decision)) => Some(decision),
            Ok(None) => {
                let _ = self.dynamic_store.delete(collection, &store_key).await;
                None
            }
            Err(error) => {
                // 坏值不能进入 L1；先失效再继续真实求值，避免共享后端中的污染持续命中。
                tracing::warn!(%error, "discard invalid OPA distributed decision cache entry");
                let _ = self.dynamic_store.delete(collection, &store_key).await;
                None
            }
        }
    }

    /// 业务作用：把明确且已验证的 OPA decision 有界写入跨节点 DynamicStore，容量满或后端故障不改变当前授权结果。
    ///
    /// 参数说明：`policy` 提供 revision/TTL/collection，`key` 是输入摘要，`decision` 是已确认结果。
    ///
    /// 返回：无；未启用、编码失败、容量满或写失败只跳过共享缓存，绝不把 dependency cache 变成放行条件。
    async fn store_distributed_opa(
        &self,
        policy: &crate::opa::OpaPolicy,
        key: &[u8; 32],
        decision: &OpaDecision,
    ) {
        let Some((collection, max_entries)) = policy.distributed_cache() else {
            return;
        };
        let encoded = match policy.encode_distributed_decision(decision) {
            Ok(encoded) => encoded,
            Err(error) => {
                tracing::warn!(%error, "encode OPA distributed decision cache entry failed");
                return;
            }
        };
        let store_key = policy.distributed_key(key);
        if let Err(error) = self
            .dynamic_store
            .put_if_capacity(collection, &store_key, &encoded, max_entries)
            .await
        {
            tracing::warn!(%error, "OPA distributed decision cache write failed");
        }
    }

    /// 业务作用：映射明确 OPA allow/deny，并以原子顺序提交已验证 request/response/audit obligations。
    ///
    /// 参数说明：`decision` 是合法结果，`parts` 接收 request mutation，`response_obligations` 延迟响应 mutation，`route_id` 定位审计。
    ///
    /// 返回：allow 返回 None 并完成副作用提交；deny 返回 403，绝不执行 obligations。
    fn apply_opa_decision(
        &self,
        decision: OpaDecision,
        parts: &mut Parts,
        response_obligations: &mut Option<OpaObligations>,
        route_id: &str,
    ) -> Option<Response<BoxBody>> {
        match decision {
            OpaDecision::Allow { obligations } => {
                // 整组 obligations 已经先验证；request 与延迟 response 状态在放行点一次提交，
                // 不允许坏条目造成一半 header 已改变、一半失败的中间态。
                obligations.apply_request(&mut parts.headers);
                if !obligations.audit_metadata().is_empty() {
                    tracing::info!(route = route_id, metadata = ?obligations.audit_metadata(), "OPA audit obligation");
                }
                *response_obligations = Some(obligations);
                self.metrics.inc_opa_decision(OpaDecisionMetric::Allow);
                None
            }
            OpaDecision::Deny => {
                self.metrics.inc_opa_decision(OpaDecisionMetric::Deny);
                Some(text_status(403, "OPA policy denied request"))
            }
        }
    }

    /// 统一处理 OPA transport/protocol failure。fail-open 只覆盖外部依赖错误，不覆盖本地
    /// input 资源上限和 require_identity，避免攻击者用超大 header 主动触发绕过。
    fn opa_unavailable(&self, policy: &crate::opa::OpaPolicy) -> Option<Response<BoxBody>> {
        if policy.fail_open() {
            self.metrics.inc_opa_decision(OpaDecisionMetric::FailOpen);
            None
        } else {
            self.metrics
                .inc_opa_decision(OpaDecisionMetric::Unavailable);
            Some(text_status(503, "OPA authorization unavailable"))
        }
    }

    /// 取某服务的下一个 round_robin 序号(单调递增、wrapping);选择逻辑对候选数取模。
    pub(super) fn upstream_rr_next(&self, service: &str) -> u64 {
        // 命中稳态只拿 DashMap shard 共享读 guard，并在 entry 内做 relaxed 原子递增；服务首次
        // 出现才走 entry 写路径。游标仅用于分流顺序，不发布其它内存，因此不需要更强 ordering。
        if let Some(counter) = self.upstream_rr.get(service) {
            return counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.upstream_rr
            .entry(service.to_owned())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn ejected_upstreams(&self, policy: PassiveHealthPolicy) -> Vec<String> {
        if !policy.enabled() {
            return Vec::new();
        }
        // 从未失败是绝对常态。失败写路径先在 Mutex 内插入完整状态，再用 Release 发布非零
        // entry 数；这里 Acquire 观察到 0 时可以确定当前没有已线性化的摘除事实，不必为每个
        // 正常 RPC 争用失败表、读取 Instant、执行 retain/扫描。若一次失败正与本次选择并发且
        // 尚未完成发布，本请求在线性化顺序上仍早于该失败，允许继续使用旧健康快照。
        if self.upstream_failure_entries.load(Ordering::Acquire) == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        let mut map = self.upstream_failures.lock();
        map.retain(|_, state| {
            state
                .ejected_until
                .map(|until| until > now)
                .unwrap_or(state.fails > 0)
        });
        self.upstream_failure_entries
            .store(map.len() as u64, Ordering::Release);
        map.iter()
            .filter_map(|(health_key, state)| {
                state
                    .ejected_until
                    .filter(|until| *until > now)
                    .map(|_| health_key.clone())
            })
            .collect()
    }

    /// 业务作用：取得服务的 retry budget 运行态,首次访问时创建。
    ///
    /// 参数说明：`service` 是逻辑服务名。
    ///
    /// 返回：该服务的共享预算状态。
    pub(super) fn retry_budget_state(
        &self,
        service: &str,
    ) -> Arc<crate::admission::RetryBudgetState> {
        if let Some(state) = self.upstream_retry_budget.get(service) {
            return state.clone();
        }
        self.upstream_retry_budget
            .entry(service.to_string())
            .or_default()
            .clone()
    }

    /// 业务作用：取得 route+维度 的共享带宽桶。
    ///
    /// 参数说明：
    /// - `scope`: route 作用域标识。
    /// - `dimension`: 限额维度值。
    ///
    /// 返回：共享桶;维度表已满时返回 `None`,由调用方按 fail-open 放行。
    pub(super) fn traffic_bandwidth_bucket(
        &self,
        scope: &str,
        dimension: &str,
    ) -> Option<Arc<crate::traffic_limit::BandwidthBucket>> {
        self.traffic_bandwidth.bucket(scope, dimension)
    }

    /// 业务作用：取得 route+维度 的多窗口限额运行态。
    ///
    /// 参数说明：
    /// - `key`: 已包含 route 与维度的复合键。
    ///
    /// 返回：共享限额状态;维度表已达上限时返回 `None`,避免高基数 key 打爆内存。
    pub(super) fn traffic_quota_state(
        &self,
        key: &str,
    ) -> Option<Arc<crate::traffic_limit::QuotaState>> {
        if let Some(state) = self.traffic_quota.get(key) {
            return Some(state.clone());
        }
        if self.traffic_quota.len() >= crate::traffic_limit::MAX_ACTIVE_KEYS {
            // 只有超过最长窗口影响周期的账本才可回收；按 `Arc` 引用数清理会让攻击者
            // 填满维度表后重置仍有效的额度，形成可重复绕过。
            let now_ms = crate::lb_load::monotonic_ms();
            self.traffic_quota
                .retain(|_, state| !state.evictable(now_ms));
            if self.traffic_quota.len() >= crate::traffic_limit::MAX_ACTIVE_KEYS {
                return None;
            }
        }
        Some(
            self.traffic_quota
                .entry(key.to_string())
                .or_default()
                .clone(),
        )
    }

    /// 业务作用：取得服务的自适应并发运行态,首次访问时按策略下界初始化。
    ///
    /// 参数说明：`service` 是逻辑服务名;`policy` 提供初始上下界。
    ///
    /// 返回：该服务的共享并发状态。
    pub(super) fn admission_state(
        &self,
        service: &str,
        policy: &crate::admission::AdaptiveConcurrencyPolicy,
    ) -> Arc<crate::admission::AdaptiveConcurrencyState> {
        if let Some(state) = self.upstream_admission.get(service) {
            state.reconcile_policy(policy);
            return state.clone();
        }
        let state = self
            .upstream_admission
            .entry(service.to_string())
            .or_insert_with(|| Arc::new(crate::admission::AdaptiveConcurrencyState::new(policy)))
            .clone();
        state.reconcile_policy(policy);
        state
    }

    /// 业务作用：为当前目录中的实例准备反馈条目,并返回它。
    ///
    /// 只在选择成功后调用:此刻实例必定属于当前目录,因此条目创建是安全的。
    /// 表容量有硬上限,超限后不再新建条目(既有条目继续工作),防止发现抖动撑爆状态表。
    ///
    /// 参数说明：`health_key` 是实例稳定身份。
    ///
    /// 返回：反馈条目;表已满且该实例尚无条目时返回 `None`。
    pub(super) fn upstream_load_entry(
        &self,
        health_key: &Arc<str>,
    ) -> Option<Arc<crate::lb_load::InstanceLoad>> {
        if let Some(entry) = self.upstream_load.get(health_key.as_ref()) {
            return Some(entry.clone());
        }
        if self.upstream_load.len() >= crate::lb_load::MAX_TRACKED_INSTANCES {
            return None;
        }
        Some(
            self.upstream_load
                .entry(health_key.clone())
                .or_default()
                .clone(),
        )
    }

    /// 业务作用：只读方式取得实例当前反馈分数,供 P2C 比较与 panic 判定。
    ///
    /// 参数说明：`health_key` 是实例身份；`policy` 是服务反馈策略；`now_ms` 是本轮统一时刻。
    ///
    /// 返回：反馈新鲜且样本足够时返回分数,否则返回 `None`。
    pub(super) fn upstream_load_score(
        &self,
        health_key: &str,
        policy: &crate::lb_load::LoadFeedbackPolicy,
        now_ms: u64,
    ) -> Option<u64> {
        self.upstream_load
            .get(health_key)
            .and_then(|entry| entry.score(policy, now_ms))
    }

    pub(super) fn record_upstream_success(&self, health_key: &str) {
        // 从未失败是绝对常态；一个 relaxed read 足以作为性能 hint。若它与刚插入的失败并发
        // 而短暂读到 0，本次成功至多晚清一次，下一请求会观察到 Release 发布后的非零值。
        if self.upstream_failure_entries.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut map = self.upstream_failures.lock();
        if map.remove(health_key).is_some() {
            self.upstream_failure_entries.fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub(super) fn record_upstream_failure(&self, health_key: &str, policy: PassiveHealthPolicy) {
        if !policy.enabled() {
            return;
        }
        let now = Instant::now();
        let mut map = self.upstream_failures.lock();
        // 失败窗口内同一实例可能连续命中；借用查询避免每次失败复制完整 health_key。
        if !map.contains_key(health_key) {
            map.insert(
                health_key.to_owned(),
                UpstreamFailureState {
                    fails: 0,
                    ejected_until: None,
                },
            );
            self.upstream_failure_entries
                .fetch_add(1, Ordering::Release);
        }
        let state = map
            .get_mut(health_key)
            .expect("upstream failure state inserted above");
        if state
            .ejected_until
            .map(|until| until <= now)
            .unwrap_or(false)
        {
            state.ejected_until = None;
            state.fails = 0;
        }
        state.fails = state.fails.saturating_add(1);
        if state.fails >= policy.max_fails {
            state.ejected_until = Some(now + Duration::from_millis(policy.fail_timeout_ms));
            state.fails = 0;
            tracing::warn!(
                upstream = health_key,
                fail_timeout_ms = policy.fail_timeout_ms,
                "upstream passively ejected"
            );
        }
    }

    /// 业务作用：在身份与上游副作用前组合 Bot head 判断和共享有界速率信号。
    ///
    /// 参数说明：`parts` 是请求 head；`route` 是已匹配路由；`client_ip` 是权威客户端地址。
    ///
    /// 返回：enforce 拒绝时返回固定挑战响应；允许、可信、monitor 或未配置时返回 `None`。
    async fn enforce_bot(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
    ) -> Option<Response<BoxBody>> {
        let policy = route.bot.as_ref()?;
        let mut decision = policy.evaluate_head(parts, client_ip);
        if decision != BotDecision::Trusted && (!decision.denied() || policy.monitor()) {
            if let Some(rate) = policy.rate.as_ref() {
                let scope = format!("bot:{}", route.id);
                let dimension = policy.rate_key(parts, client_ip);
                let key = format!("{scope}:{dimension}");
                let rate_decision = self
                    .rate_limiter
                    .allow(RateLimitRequest {
                        scope: &scope,
                        key: &key,
                        cost: 1,
                        limit: rate.limit,
                        window: rate.window,
                        burst: rate.burst,
                        max_active_keys: rate.max_active_keys,
                        active_keys_fail_open: rate.active_keys_fail_open,
                    })
                    .await;
                if !rate_decision.allowed && !decision.denied() {
                    decision = BotDecision::RateDenied;
                }
            }
        }

        let monitored = decision.denied() && policy.monitor();
        self.metrics.inc_bot(decision, monitored);
        if !decision.denied() {
            return None;
        }
        if monitored {
            tracing::warn!(
                route = %route.id,
                reason = decision.reason(),
                "request matched Bot monitor policy"
            );
            return None;
        }

        // Bot 挑战必须发生在认证、插件和上游副作用之前；响应只携带固定 scheme/realm，
        // 不回显 User-Agent、指纹、IP 或命中字段。
        tracing::warn!(
            route = %route.id,
            reason = decision.reason(),
            "request challenged by Bot policy"
        );
        let status = if decision == BotDecision::RateDenied {
            self.metrics.inc_rate_limited();
            429
        } else {
            policy.challenge_status
        };
        let mut response = text_status(status, "request requires bot verification");
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, policy.challenge_header.clone());
        if decision == BotDecision::RateDenied {
            if let Ok(value) = HeaderValue::from_str(policy.retry_after_secs().to_string().as_str())
            {
                response.headers_mut().insert(RETRY_AFTER, value);
            }
        }
        Some(response)
    }

    /// 业务作用：按 route 声明的每条请求限流规则执行共享后端准入，并在首个拒绝处停止业务处理。
    ///
    /// 参数说明：`parts` 是请求 head；`route` 是已匹配路由；`client_ip` 是权威客户端地址。
    ///
    /// 返回：任一规则拒绝时返回 429；全部允许或未配置规则时返回 `None`。
    async fn enforce_limit_req(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
    ) -> Option<Response<BoxBody>> {
        for (idx, policy) in route.limit_req.iter().enumerate() {
            let dimension = limit_req_dimension(parts, route, client_ip, &policy.key);
            let scope = format!("limit_req:{}:{}", route.id, idx);
            let key = format!("{}:{:016x}", scope, stable_hash64(dimension.as_bytes()));
            let decision = self
                .rate_limiter
                .allow(RateLimitRequest {
                    scope: &scope,
                    key: &key,
                    cost: 1,
                    limit: policy.limit,
                    window: policy.window,
                    burst: policy.burst,
                    max_active_keys: policy.max_active_keys,
                    active_keys_fail_open: policy.active_keys_fail_open,
                })
                .await;
            if !decision.allowed {
                self.metrics.inc_rate_limited();
                self.maybe_auto_ban(client_ip).await;
                return Some(rate_limited_response(decision.remaining));
            }
        }
        None
    }

    /// 执行 V7 consumer Usage Plan 配额。
    ///
    /// consumer 来自认证前冻结、且已被本地 Basic/JWT/API-Key 校验过的身份快照，不能被
    /// 后续外部插件改写。限流 key 只保留固定 scope 与 64-bit 指纹：原始租户标识既不会
    /// 发送到 Redis，也不会出现在日志/指标中。`Arc<UsagePlan>` 由配置快照共享，热路径
    /// 不复制全局 consumer 表，也不重新解析窗口参数。
    async fn enforce_usage_plan(
        &self,
        route: &Route,
        consumer: Option<&str>,
    ) -> Option<Response<BoxBody>> {
        let policy = route.usage_plan.as_ref()?;
        if policy.require_consumer && consumer.is_none() {
            self.metrics.inc_usage_plan(UsagePlanMetric::Unmapped);
            return Some(auth_failed_response(None));
        }
        let Some(plan) = policy.select(consumer) else {
            self.metrics.inc_usage_plan(UsagePlanMetric::Unmapped);
            return Some(text_status(403, "consumer has no usage plan"));
        };

        let scope = format!("usage_plan:{}:{}", route.id, plan.id);
        let identity = consumer.unwrap_or("anonymous");
        let key = format!("{}:{:016x}", scope, stable_hash64(identity.as_bytes()));
        let decision = self
            .rate_limiter
            .allow(RateLimitRequest {
                scope: &scope,
                key: &key,
                cost: 1,
                limit: plan.limit,
                window: plan.window,
                burst: plan.burst,
                max_active_keys: plan.max_active_keys,
                active_keys_fail_open: plan.active_keys_fail_open,
            })
            .await;
        if decision.allowed {
            self.metrics.inc_usage_plan(UsagePlanMetric::Allowed);
            None
        } else {
            self.metrics.inc_usage_plan(UsagePlanMetric::Limited);
            self.metrics.inc_rate_limited();
            Some(rate_limited_response(decision.remaining))
        }
    }

    async fn maybe_auto_ban(&self, client_ip: IpAddr) {
        let cfg = {
            let snap = self.snap.load();
            snap.runtime_state.blacklist.clone()
        };
        if !cfg.enabled || !cfg.auto_ban.enabled {
            return;
        }
        // §18 解封豁免:刚被手工解封的 IP 在豁免窗口内不再自动拉黑,避免 ban/unban 抖动。
        if self.blacklist.is_exempt(client_ip) {
            return;
        }
        let now = Instant::now();
        let threshold = cfg.auto_ban.limit_req_rejections;
        let window = Duration::from_millis(cfg.auto_ban.window_ms);
        let should_ban = {
            let mut counts = self.auto_ban_counts.lock();
            record_auto_ban_rejection(
                &mut counts,
                client_ip,
                now,
                threshold,
                window,
                AUTO_BAN_COUNTS_MAX_ENTRIES,
            )
        };
        if !should_ban {
            return;
        }
        let expire_at_unix_ms =
            unix_now_ms().saturating_add(cfg.auto_ban.ban_ttl_ms.min(i64::MAX as u64) as i64);
        let value = serde_json::json!({
            "source": "auto_limit_req",
            "expire_at_unix_ms": expire_at_unix_ms,
        })
        .to_string();
        let key = client_ip.to_string();
        if let Err(e) = self
            .dynamic_store
            .put(&cfg.collection, &key, value.as_bytes())
            .await
        {
            tracing::warn!(ip = %client_ip, error = %e, "auto-ban dynamic store write failed");
            return;
        }
        if let Err(e) = self
            .blacklist
            .refresh_from_store(self.dynamic_store.as_ref(), &cfg.collection)
            .await
        {
            tracing::warn!(ip = %client_ip, error = %e, "auto-ban blacklist refresh failed");
        }
        let closed = self.conn_registry.close_by_ip(client_ip);
        // §18 审计:记录自动拉黑事件(who/when/why/source),供 /admin/blacklist/audit 查询。
        self.blacklist
            .record_ban(client_ip, "auto_limit_req", cfg.auto_ban.ban_ttl_ms);
        tracing::warn!(
            ip = %client_ip,
            ttl_ms = cfg.auto_ban.ban_ttl_ms,
            closed,
            "client auto-banned after limit_req rejections"
        );
    }

    async fn enforce_limit_conn(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
        acquired: &mut Vec<LimitConnGuard>,
    ) -> Option<Response<BoxBody>> {
        for (idx, policy) in route.limit_conn.iter().enumerate() {
            let dimension = limit_dimension(parts, route, client_ip, &policy.key);
            let key = format!(
                "limit_conn:{}:{}:{:016x}",
                route.id,
                idx,
                stable_hash64(dimension.as_bytes())
            );
            let Some(guard) = self.acquire_limit_conn_slot(key, policy.limit).await else {
                acquired.clear();
                self.metrics.inc_conn_limited();
                return Some(conn_limited_response(policy.limit));
            };
            acquired.push(guard);
        }
        None
    }

    /// 业务作用：处理 HTTP CONNECT,在通过全部目标校验后建立受控正向代理隧道。
    ///
    /// 校验顺序是安全要求而非风格问题:
    /// 1. route 未显式声明 `forward_proxy` 一律 405——**没有默认放行的正向代理**;
    /// 2. authority 语法 → 端口/域名 allowlist(无 I/O),挡住绝大多数尝试;
    /// 3. 每次连接重新解析 DNS,逐个校验解析结果;
    /// 4. **按已校验的 IP 直连**,而不是把主机名再交给系统解析一次。
    ///
    /// 第 4 步是 DNS rebinding 防御的闭合点:按主机名连接会触发第二次解析,
    /// 攻击者只要让两次解析给出不同答案,前面所有校验都白做。
    ///
    /// 参数说明：
    /// - `parts`: 请求 head,authority 取自请求行。
    /// - `route`: 已匹配 route。
    /// - `client_ip`: 真实客户端 IP,用于审计。
    /// - `downstream_upgrade`: 下游升级权;成功后移交隧道 task。
    ///
    /// 返回：允许时返回 200(CONNECT 成功语义,不是 101);任何一步不通过都返回
    /// 明确的 4xx 并记录低基数拒绝原因,隧道建立前始终 fail-closed。
    async fn handle_connect(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
        downstream_upgrade: &mut Option<(
            hyper::upgrade::OnUpgrade,
            Option<DownstreamConnectionLease>,
        )>,
    ) -> Response<BoxBody> {
        use crate::forward_proxy::{ConnectTarget, DenyReason};

        let Some(policy) = route.forward_proxy.as_ref() else {
            // 未声明正向代理的 route 收到 CONNECT:这不是配置疏漏就是探测,
            // 一律拒绝,绝不退化成"当作普通请求处理"。
            tracing::debug!(route = %route.id, %client_ip, "CONNECT rejected: route has no forward_proxy");
            return text_status(405, "CONNECT not allowed on this route");
        };

        let deny = |reason: DenyReason, route_id: &str| -> Response<BoxBody> {
            tracing::warn!(
                route = %route_id,
                %client_ip,
                reason = reason.as_str(),
                "CONNECT target rejected"
            );
            match reason {
                DenyReason::MalformedAuthority => text_status(400, "malformed CONNECT authority"),
                _ => text_status(403, "CONNECT target not allowed"),
            }
        };

        // CONNECT 的目标在请求行的 authority 里,不在 Host 头。用 Host 会让客户端
        // 有两个可控来源去指定目标,校验哪个都可能被另一个绕开。
        let authority = match parts.uri.authority() {
            Some(authority) => authority.as_str().to_string(),
            None => return deny(DenyReason::MalformedAuthority, &route.id),
        };
        let target = match ConnectTarget::parse(&authority) {
            Ok(target) => target,
            Err(reason) => return deny(reason, &route.id),
        };
        if let Err(reason) = policy.check_authority(&target) {
            return deny(reason, &route.id);
        }
        let addrs = match policy.resolve_checked(&target).await {
            Ok(addrs) => addrs,
            Err(reason) => return deny(reason, &route.id),
        };

        // 只连已校验的 IP。这里刻意不使用 (host, port) 形式的连接接口。
        let mut upstream = None;
        for addr in &addrs {
            match tokio::time::timeout(
                policy.connect_timeout(),
                tokio::net::TcpStream::connect(*addr),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    upstream = Some(stream);
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        let Some(upstream) = upstream else {
            tracing::warn!(route = %route.id, %client_ip, host = %target.host, "CONNECT upstream unreachable");
            return text_status(502, "CONNECT upstream unreachable");
        };

        let Some((upgrade, connection_lease)) = downstream_upgrade.take() else {
            return text_status(500, "CONNECT upgrade unavailable");
        };

        let route_id: Arc<str> = Arc::from(route.id.as_str());
        let registry = self.conn_registry.clone();
        let activity_clock = self.ws_activity_clock.clone();
        let idle_timeout_ms = policy.idle_timeout_ms;
        let max_lifetime_ms = policy.max_lifetime_ms;
        let max_bytes = policy.max_bytes;
        let host = target.host.clone();
        let port = target.port;
        tokio::spawn(async move {
            // 200 之后 Hyper 的 HTTP future 就结束了,连接预算必须由隧道 task 持有到收尾,
            // 否则 max_connections 名额会被提前归还,指标也会与真实 socket 数脱节。
            let _connection_lease = connection_lease;
            let downstream = match upgrade.await {
                Ok(downstream) => downstream,
                Err(error) => {
                    tracing::debug!(route = %route_id, %error, "CONNECT downstream upgrade failed");
                    return;
                }
            };
            let activity = forward::WsActivity::new(activity_clock);
            // 字节预算由两个方向共享:限制的是这条隧道的总搬运量。
            let budget = Arc::new(AtomicU64::new(0));
            let mut downstream = forward::ActivityIo::new(
                forward::BudgetIo::new(
                    hyper_util::rt::TokioIo::new(downstream),
                    budget.clone(),
                    max_bytes,
                ),
                activity.clone(),
            );
            let mut upstream = forward::ActivityIo::new(
                forward::BudgetIo::new(upstream, budget, max_bytes),
                activity.clone(),
            );
            // 隧道纳入统一长连接治理:撤权、drain 与 shutdown 走与 WebSocket 相同的通道。
            let guard = registry.register(
                route_id.clone(),
                client_ip,
                None,
                0,
                crate::conn_registry::LongProto::Ws,
            );
            let close = guard.closed();
            tokio::pin!(close);
            tokio::select! {
                result = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {
                    match result {
                        Ok((to_upstream, to_downstream)) => tracing::debug!(
                            route = %route_id, %host, port, to_upstream, to_downstream,
                            "CONNECT tunnel closed"
                        ),
                        Err(error) => tracing::debug!(route = %route_id, %error, "CONNECT tunnel error"),
                    }
                }
                _ = &mut close => {
                    tracing::debug!(route = %route_id, "CONNECT tunnel closed by registry");
                }
                _ = forward::wait_for_ws_inactivity(activity, idle_timeout_ms), if idle_timeout_ms > 0 => {
                    tracing::debug!(route = %route_id, idle_timeout_ms, "CONNECT tunnel idle timeout");
                }
                _ = tokio::time::sleep(Duration::from_millis(max_lifetime_ms)), if max_lifetime_ms > 0 => {
                    tracing::debug!(route = %route_id, max_lifetime_ms, "CONNECT tunnel max lifetime reached");
                }
            }
        });

        // CONNECT 成功用 200,不是 101:101 是 Upgrade 语义,CONNECT 不走 Upgrade 协商。
        Response::builder()
            .status(StatusCode::OK)
            .body(forward::empty_body())
            .expect("build CONNECT response")
    }

    /// 业务作用：为 HTTP/3 CONNECT-UDP 生成已授权、已复验 DNS 的不可变隧道计划。
    ///
    /// 参数说明：`parts` 是已完成路径规范化与安全治理的请求 head；`route` 是本请求唯一快照
    /// 命中的终端 route；`client_ip` 只用于低敏拒绝日志；`consumer` 与 `snapshot_version`
    /// 用于既有长连接治理，不进入公开日志。
    ///
    /// 返回：允许时返回携带 [`crate::masque::ConnectUdpPlan`] 的 200 响应；路径、allowlist、
    /// SSRF 或解析门失败时返回明确 4xx，且不创建 socket、不产生目标流量。
    async fn prepare_connect_udp(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
    ) -> Response<BoxBody> {
        use crate::forward_proxy::DenyReason;

        let Some(policy) = route.forward_proxy.as_ref() else {
            return text_status(405, "CONNECT-UDP not allowed on this route");
        };
        let deny = |reason: DenyReason| {
            tracing::warn!(
                route = %route.id,
                %client_ip,
                reason = reason.as_str(),
                "CONNECT-UDP target rejected"
            );
            match reason {
                DenyReason::MalformedAuthority => text_status(400, "malformed CONNECT-UDP target"),
                _ => text_status(403, "CONNECT-UDP target not allowed"),
            }
        };
        let target = match crate::masque::parse_connect_udp_path(parts.uri.path()) {
            Ok(target) => target,
            Err(reason) => return deny(reason),
        };
        let addresses = match crate::masque::resolve_connect_udp(policy, &target).await {
            Ok(addresses) => addresses,
            Err(reason) => return deny(reason),
        };
        let plan = crate::masque::ConnectUdpPlan {
            route_id: route.id_shared.clone(),
            target,
            addresses: addresses.into(),
            policy: policy.clone(),
            guard: Arc::new(self.conn_registry.register(
                route.id_shared.clone(),
                client_ip,
                consumer,
                snapshot_version,
                crate::conn_registry::LongProto::ConnectUdp,
            )),
        };
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("capsule-protocol", "?1")
            .body(full_body(Bytes::new()))
            .expect("fixed CONNECT-UDP response");
        response.extensions_mut().insert(plan);
        response
    }

    /// 业务作用：为 HTTP/3 WebTransport 生成已授权、Origin 复验后的不可变 session 计划。
    ///
    /// 参数说明：`parts` 是已完成公共安全管线的 CONNECT head；`route` 是本请求唯一快照命中的
    /// 终端 route；`client_ip`、`consumer` 与 `snapshot_version` 用于长连接撤权与 drain。
    ///
    /// 返回：允许时返回携带 [`crate::masque::WebTransportPlan`] 的内部 200 响应；route 类型或
    /// Origin 不合法时返回 4xx，且不建立上游 QUIC、不向客户端确认 session。
    fn prepare_webtransport(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
        consumer: Option<Arc<str>>,
        snapshot_version: u64,
    ) -> Response<BoxBody> {
        let Some(policy) = route.webtransport.as_ref() else {
            return text_status(405, "WebTransport not allowed on this route");
        };
        let origin = match policy.authorize_origin(&parts.headers) {
            Ok(origin) => origin,
            Err(error) => {
                tracing::warn!(
                    route = %route.id,
                    %client_ip,
                    error = %error,
                    "WebTransport Origin rejected"
                );
                return text_status(403, "WebTransport Origin not allowed");
            }
        };
        let plan = crate::masque::WebTransportPlan {
            route_id: route.id_shared.clone(),
            origin,
            policy: policy.clone(),
            guard: Arc::new(self.conn_registry.register(
                route.id_shared.clone(),
                client_ip,
                consumer,
                snapshot_version,
                crate::conn_registry::LongProto::WebTransport,
            )),
        };
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(full_body(Bytes::new()))
            .expect("fixed WebTransport plan response");
        response.extensions_mut().insert(plan);
        response
    }

    /// 业务作用：执行 route 级双向带宽整形与多窗口成本型限额。
    ///
    /// 三件事在同一处完成,因为它们共享同一个维度键——分开算会出现"限额按 consumer、
    /// 带宽按 IP"这类错配,同一个调用方被当成两个主体治理。
    ///
    /// 参数说明：
    /// - `parts`: 请求头,用于解析维度键。
    /// - `route`: 已匹配 route。
    /// - `client_ip`: 经可信代理链与连接元数据判定的真实客户端 IP。
    /// - `forward_body`: 待转发的请求体;命中请求方向带宽策略时就地包上整形器。
    /// - `response_shaper`: 输出参数,命中响应方向策略时写入整形器。
    /// - `response_settlement`: 输出参数，命中事实成本策略时写入随响应生命周期结算的凭据。
    ///
    /// 返回：需要短路时返回 429 响应(携带标准限额头);放行返回 `None`。
    async fn enforce_traffic_limit(
        &self,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
        forward_body: &mut Option<BoxBody>,
        response_shaper: &mut Option<crate::traffic_limit::FrameShaper>,
        response_settlement: &mut Option<TrafficSettlement>,
    ) -> Option<Response<BoxBody>> {
        use crate::traffic_limit::{FrameShaper, OverflowAction, QuotaFailMode};

        let policy = route.traffic_limit.as_ref()?;
        let dimension = limit_dimension(parts, route, client_ip, &policy.key);
        let scope = format!("traffic:{}", route.id);

        // —— 限额判定必须早于带宽整形 ——
        // 反过来会先为一个即将被拒的请求占用带宽额度,超额流量照样消耗了配额。
        if let Some(quota) = policy.quota.as_ref() {
            let key = format!(
                "{scope}:{:016x}:{:016x}",
                policy.state_key,
                stable_hash64(dimension.as_bytes())
            );
            let Some(state) = self.traffic_quota_state(&key) else {
                // 维度表已满 = 计数不可用。这里不猜,按策略显式声明的模式处理。
                return match policy.fail_mode {
                    QuotaFailMode::FailOpen => None,
                    QuotaFailMode::FailClosed => {
                        self.metrics.inc_rate_limited();
                        Some(quota_limited_response(
                            &crate::traffic_limit::QuotaDecision {
                                allowed: false,
                                remaining: 0,
                                limit: 0,
                                reset_after: Duration::from_secs(1),
                                retry_after: Duration::from_secs(1),
                            },
                        ))
                    }
                };
            };
            let cost = policy.cost_source.admission_cost();
            let (mut decision, mut reservation) = state.check_with_reservation(quota, cost);
            if !decision.allowed {
                match quota.overflow {
                    OverflowAction::Reject => {
                        self.metrics.inc_rate_limited();
                        return Some(quota_limited_response(&decision));
                    }
                    OverflowAction::Delay {
                        max_queue,
                        max_wait_ms,
                    } => {
                        // 排队名额本身有界:拿不到就立刻拒绝。无界排队会把过载从
                        // "快速失败"变成"内存耗尽",后者在生产上不可恢复。
                        let Some(_slot) = state.enqueue(max_queue) else {
                            self.metrics.inc_rate_limited();
                            return Some(quota_limited_response(&decision));
                        };
                        let deadline = Instant::now() + Duration::from_millis(max_wait_ms);
                        loop {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                self.metrics.inc_rate_limited();
                                return Some(quota_limited_response(&decision));
                            }
                            // 轮询步长取"建议等待"与剩余时间的较小值,并设 1ms 下界,
                            // 避免 retry_after 为 0 时退化成忙等把 CPU 打满。
                            let step = decision
                                .retry_after
                                .max(Duration::from_millis(1))
                                .min(remaining)
                                .min(Duration::from_millis(50));
                            tokio::time::sleep(step).await;
                            let (next_decision, next_reservation) =
                                state.check_with_reservation(quota, cost);
                            decision = next_decision;
                            reservation = next_reservation;
                            if decision.allowed {
                                break;
                            }
                        }
                    }
                }
            }
            if let Some(reservation) = reservation {
                *response_settlement = TrafficSettlement::new(
                    state,
                    quota.clone(),
                    policy.cost_source.clone(),
                    reservation,
                );
            }
        }

        // —— 带宽整形 ——
        // 取桶失败(维度表满)时按 fail-open 放行:带宽整形短暂失效的代价,
        // 远小于因为记不下一个计数器就拒绝正常流量。
        if let Some(bandwidth) = policy.request_bandwidth.as_ref() {
            if let Some(bucket) = self.traffic_bandwidth_bucket(&format!("{scope}:req"), &dimension)
            {
                if let Some(body) = forward_body.take() {
                    *forward_body = Some(
                        ShapedBody {
                            inner: Box::pin(body),
                            shaper: FrameShaper::new(bucket, *bandwidth),
                            pending: None,
                            sleep: None,
                        }
                        .boxed(),
                    );
                }
            }
        }
        if let Some(bandwidth) = policy.response_bandwidth.as_ref() {
            if let Some(bucket) =
                self.traffic_bandwidth_bucket(&format!("{scope}:resp"), &dimension)
            {
                *response_shaper = Some(FrameShaper::new(bucket, *bandwidth));
            }
        }
        None
    }

    async fn acquire_limit_conn_slot(&self, key: String, limit: u64) -> Option<LimitConnGuard> {
        let decision = self.conn_limiter.acquire(&key, limit, LIMIT_CONN_TTL).await;
        if !decision.allowed {
            return None;
        }
        let refresh_task = if decision.release_required {
            Some(spawn_limit_conn_refresh(
                self.conn_limiter.clone(),
                key.clone(),
            ))
        } else {
            None
        };
        Some(LimitConnGuard {
            key,
            limiter: self.conn_limiter.clone(),
            release_required: decision.release_required,
            refresh_task,
        })
    }

    fn enforce_circuit_breakers(
        &self,
        route: &Route,
        permits: &mut Vec<CircuitPermit>,
    ) -> Option<Response<BoxBody>> {
        for (idx, policy) in route.circuit_breakers.iter().enumerate() {
            let key = circuit_key(route, idx, policy);
            match self.acquire_circuit_permit(key, policy) {
                CircuitGate::Allowed(permit) => permits.push(permit),
                CircuitGate::Rejected => {
                    self.cancel_circuit_permits(std::mem::take(permits));
                    self.metrics.inc_circuit_rejected();
                    return Some(circuit_fallback_response(policy));
                }
            }
        }
        None
    }

    fn acquire_circuit_permit(&self, key: String, policy: &CircuitBreakerPolicy) -> CircuitGate {
        let now = Instant::now();
        let mut states = self.circuit_states.lock();
        let state = states.entry(key.clone()).or_insert_with(|| CircuitState {
            open_until: None,
            half_open_probe: false,
        });
        if let Some(until) = state.open_until {
            if until > now {
                return CircuitGate::Rejected;
            }
            // Open 到期 → Half-Open:只放行【一个】探测请求(窗口统计的清零留到探测成功时,见 record)。
            // WHY 不在此清空 open_until:探测在途期间到达的并发请求必须仍从本分支走、被 half_open_probe 拒绝。
            // 若此处提前置 None,后续并发请求会看到 open_until==None、落到下方 Closed 分支被当作正常请求【全部放行】,
            // 正是 Half-Open 要防的惊群(§10.6)。open_until 由 record_circuit_result 在探测成功时清空、失败时续期;
            // 探测被取消时 cancel_circuit_permits 只清 half_open_probe,open_until 保留,使下一请求成为新探测。
            if state.half_open_probe {
                return CircuitGate::Rejected;
            }
            state.half_open_probe = true;
            return CircuitGate::Allowed(CircuitPermit {
                key,
                half_open: true,
                policy: policy.clone(),
                states: self.circuit_states.clone(),
                release_half_open_on_drop: true,
            });
        }
        CircuitGate::Allowed(CircuitPermit {
            key,
            half_open: false,
            policy: policy.clone(),
            states: self.circuit_states.clone(),
            release_half_open_on_drop: false,
        })
    }

    /// 记录本次请求结果,推进熔断状态机。
    ///
    /// **统计与状态机分离**(§10.6 R3):滑动窗口统计走 `circuit_stats`(local 各自 / redis 集群共享),
    /// open/half-open 仍为本节点本地状态。故先 `await` 统计后端拿窗口聚合值,再本地判定是否跳闸。
    /// 半开探测结果直接决定闭/开(不看窗口),成功时顺带清空窗口,避免恢复后陈旧失败样本立即再次跳闸。
    ///
    /// # 参数
    /// - `permits`: 本请求获得的熔断放行凭证(可能多条规则)。
    /// - `success`: 本次请求是否成功(非 5xx)。
    async fn record_circuit_result(&self, permits: Vec<CircuitPermit>, success: bool) {
        for mut permit in permits {
            if permit.half_open {
                // 探测成功清空共享窗口再置闭;失败则重新 Open 一个 break 周期。
                if success {
                    self.circuit_stats.reset(&permit.key).await;
                }
                let now = Instant::now();
                let mut states = self.circuit_states.lock();
                let state = states
                    .entry(permit.key.clone())
                    .or_insert_with(|| CircuitState {
                        open_until: None,
                        half_open_probe: false,
                    });
                state.half_open_probe = false;
                state.open_until = if success {
                    None
                } else {
                    Some(now + permit.policy.break_duration)
                };
                // 状态机已确定落到 Closed/Open；解除 Drop 的取消兜底，避免正常返回重复修改。
                permit.release_half_open_on_drop = false;
                continue;
            }
            // Closed 态:把结果计入(本地或集群共享)滑动窗口,拿聚合值判是否跳闸。
            let window = self
                .circuit_stats
                .record(&permit.key, success, permit.policy.window)
                .await;
            if window.total >= permit.policy.min_requests
                && window.failures >= permit.policy.failure_threshold
            {
                let now = Instant::now();
                let mut states = self.circuit_states.lock();
                let state = states
                    .entry(permit.key.clone())
                    .or_insert_with(|| CircuitState {
                        open_until: None,
                        half_open_probe: false,
                    });
                state.open_until = Some(now + permit.policy.break_duration);
            }
        }
    }

    fn cancel_circuit_permits(&self, mut permits: Vec<CircuitPermit>) {
        if !permits.iter().any(|permit| permit.half_open) {
            return;
        }
        let mut states = self.circuit_states.lock();
        for permit in &mut permits {
            if permit.half_open {
                if let Some(state) = states.get_mut(&permit.key) {
                    state.half_open_probe = false;
                }
                permit.release_half_open_on_drop = false;
            }
        }
    }
}

fn retain_identity_counter(
    active: &std::collections::HashSet<Arc<str>>,
    identity: &Arc<str>,
    counter: &Arc<AtomicU64>,
) -> bool {
    active.contains(identity.as_ref())
        || counter.load(std::sync::atomic::Ordering::Acquire) != 0
        || Arc::strong_count(counter) > 1
}

enum CircuitGate {
    Allowed(CircuitPermit),
    Rejected,
}

fn rate_limited_response(remaining: u64) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-ratelimit-remaining", remaining.to_string())
        .body(full_body(Bytes::from_static(b"rate limited")))
        .expect("build rate limit response")
}

/// 业务作用：构造带标准限额响应头的 429。
///
/// 参数说明：`decision` 为限额判定结果,决定 `RateLimit-*` 与 `Retry-After` 的取值。
///
/// 返回：429 响应。
fn quota_limited_response(decision: &crate::traffic_limit::QuotaDecision) -> Response<BoxBody> {
    let mut resp = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from_static(b"rate limited")))
        .expect("build quota limit response");
    crate::traffic_limit::write_rate_limit_headers(resp.headers_mut(), decision);
    resp
}

fn conn_limited_response(limit: u64) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-limit-conn-limit", limit.to_string())
        .body(full_body(Bytes::from_static(b"too many connections")))
        .expect("build connection limit response")
}

fn circuit_key(route: &Route, idx: usize, policy: &CircuitBreakerPolicy) -> String {
    format!("circuit:{}:{}:{}", route.id, idx, policy.id)
}

fn circuit_success(status: StatusCode) -> bool {
    !status.is_server_error()
}

fn circuit_fallback_response(policy: &CircuitBreakerPolicy) -> Response<BoxBody> {
    Response::builder()
        .status(policy.fallback_status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-gateway-circuit", "open")
        .body(full_body(Bytes::from(policy.fallback_body.clone())))
        .expect("build circuit fallback response")
}

fn limit_req_dimension(
    parts: &Parts,
    route: &Route,
    client_ip: IpAddr,
    key: &LimitReqKey,
) -> String {
    limit_dimension(parts, route, client_ip, key)
}

fn limit_dimension(parts: &Parts, route: &Route, client_ip: IpAddr, key: &LimitReqKey) -> String {
    match key {
        LimitReqKey::Global => "global".to_string(),
        LimitReqKey::Ip => client_ip.to_string(),
        LimitReqKey::Route => route.id.clone(),
        LimitReqKey::Header(name) => parts
            .headers
            .get(name)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_else(|| "<missing>".to_string()),
        LimitReqKey::Query(name) => query_param_raw(parts.uri.query().unwrap_or_default(), name)
            .unwrap_or("<missing>")
            .to_string(),
    }
}

pub(super) struct LimitConnGuard {
    key: String,
    limiter: Arc<dyn ConnLimiter>,
    release_required: bool,
    refresh_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for LimitConnGuard {
    fn drop(&mut self) {
        if let Some(task) = self.refresh_task.take() {
            task.abort();
        }
        if !self.release_required {
            return;
        }
        let limiter = self.limiter.clone();
        let key = self.key.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    limiter.release(&key).await;
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "limit_conn guard dropped outside tokio runtime; release skipped");
            }
        }
    }
}

/// 周期刷新 Redis `limit_conn` 槽位 TTL,避免长连接超过崩溃兜底 TTL 时被提前释放。
///
/// # 参数
/// - `limiter`: 当前并发限制后端。
/// - `key`: 已占用的并发限制 key。
fn spawn_limit_conn_refresh(
    limiter: Arc<dyn ConnLimiter>,
    key: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(LIMIT_CONN_REFRESH_INTERVAL);
        loop {
            tick.tick().await;
            limiter.refresh(&key, LIMIT_CONN_TTL).await;
        }
    })
}

pub(super) fn wrap_limit_conn_response(
    resp: Response<BoxBody>,
    guards: Vec<LimitConnGuard>,
) -> Response<BoxBody> {
    if guards.is_empty() {
        return resp;
    }
    resp.map(|body| {
        LimitConnBody {
            inner: Box::pin(body),
            _guards: guards,
        }
        .boxed()
    })
}

/// 在鉴权/限流之后、熔断/上游之前查询 route 公共响应 L1。
///
/// # 参数
/// - `route`: 当前命中 route；没有 proxy_cache 时立即返回 None。
/// - `parts`: 尚未移入上游请求的规范化请求 head。
/// - `miss_key`: 安全可缓存 GET 未命中时写入 key/leader guard，供响应 EOF 有界回填。
/// - `metrics`: 共享低基数 hit/miss 计数器。
#[allow(clippy::too_many_arguments)]
async fn lookup_route_cache(
    route: &Route,
    parts: &Parts,
    proxy_id: &str,
    downstream_proto: &str,
    miss_key: &mut Option<CacheMiss>,
    stale_refresh: &mut Option<CacheMiss>,
    runtime: &SwappableHttpCacheRuntime,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let policy = route.http_cache.as_ref()?;
    let digest = policy.request_key(parts, proxy_id, route.id.as_str(), downstream_proto)?;
    match policy
        .lookup(digest, parts, proxy_id, route.id.as_str(), runtime, metrics)
        .await
    {
        CacheLookup::Hit(response) => {
            metrics.inc_http_cache_hit();
            Some(response)
        }
        CacheLookup::Stale(response, refresh) => {
            metrics.inc_http_cache_hit();
            metrics.inc_http_cache_stale();
            *stale_refresh = refresh;
            Some(response)
        }
        CacheLookup::Miss(key) => {
            metrics.inc_http_cache_miss();
            // HEAD 与 GET 共享已有表示，但 HEAD miss 的空 body 绝不能回填到 GET key。
            if parts.method == Method::GET {
                *miss_key = Some(key);
            }
            None
        }
    }
}

/// 用 `limit_rate` 策略包裹响应 body。
///
/// # 参数
/// - `resp`: 上游或网关自产响应。
/// - `policy`: route 上编译出的字节限速策略。
fn wrap_limit_rate_response(resp: Response<BoxBody>, policy: LimitRatePolicy) -> Response<BoxBody> {
    resp.map(|body| {
        LimitRateBody {
            inner: Box::pin(body),
            bytes_per_second: policy.bytes_per_second,
            after_remaining: policy.after_bytes,
            pending: None,
            sleep: None,
        }
        .boxed()
    })
}

/// 用 `sub_filter` 策略包裹响应 body。
///
/// # 参数
/// - `resp`: 上游或网关自产响应。
/// - `rules`: route 上编译出的流式替换规则。
fn wrap_sub_filter_response(
    mut resp: Response<BoxBody>,
    rules: Vec<SubFilterRule>,
) -> Response<BoxBody> {
    if rules.is_empty()
        || response_must_not_have_body(resp.status())
        || resp.status() == StatusCode::SWITCHING_PROTOCOLS
        || has_non_identity_content_encoding(resp.headers())
    {
        return resp;
    }
    resp.headers_mut().remove(http::header::CONTENT_LENGTH);
    let keep_tail = rules
        .iter()
        .map(|rule| rule.needle.len().saturating_sub(1))
        .max()
        .unwrap_or(0);
    resp.map(|body| {
        SubFilterBody {
            inner: Box::pin(body),
            rules,
            keep_tail,
            buffer: Vec::new(),
            pending: VecDeque::new(),
            done: false,
        }
        .boxed()
    })
}

/// nginx `sub_filter` 的流式 body wrapper。
///
/// 只保留最长匹配串减一的尾部,用于识别跨 chunk 命中的字符串;不会把完整响应体读入内存。
struct SubFilterBody {
    /// 被包裹的原始响应 body。
    inner: Pin<Box<BoxBody>>,
    /// 按配置顺序保存的替换规则。
    rules: Vec<SubFilterRule>,
    /// 为跨 chunk 匹配保留的最大尾部长度。
    keep_tail: usize,
    /// 当前尚未确定可输出的尾部缓冲。
    buffer: Vec<u8>,
    /// 已生成但尚未被下游 poll 走的输出 frame。
    pending: VecDeque<Frame<Bytes>>,
    /// 内层 body 已结束且尾缓冲已刷新。
    done: bool,
}

impl SubFilterBody {
    /// 追加一个 data frame 并尝试产出已可确定的前缀。
    ///
    /// # 参数
    /// - `data`: 从上游或前一个 body wrapper 读到的数据帧。
    fn ingest_data(&mut self, data: Bytes) {
        self.buffer.extend_from_slice(&data);
        self.flush_decided(self.keep_tail);
    }

    /// 在 EOF 或 trailers 前刷新全部尾缓冲。
    fn flush_all(&mut self) {
        self.flush_decided(0);
    }

    /// 刷新当前缓冲区中不会再受后续 chunk 影响的前缀。
    ///
    /// # 参数
    /// - `keep_tail`: 本次刷新后需要保留的尾部字节数。
    fn flush_decided(&mut self, keep_tail: usize) {
        let (out, consumed) = rewrite_decided_prefix(&self.buffer, keep_tail, &self.rules);
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        if !out.is_empty() {
            self.pending.push_back(Frame::data(Bytes::from(out)));
        }
    }
}

impl Body for SubFilterBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Poll::Ready(Some(Ok(frame)));
            }
            if self.done {
                return Poll::Ready(None);
            }
            match self.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        self.ingest_data(data.clone());
                    } else {
                        self.flush_all();
                        self.pending.push_back(frame);
                    }
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => {
                    self.flush_all();
                    self.done = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.pending.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 改写缓冲区中已经可以确定的前缀。
///
/// # 参数
/// - `buffer`: 当前跨 chunk 累积缓冲。
/// - `keep_tail`: 需要留给未来 chunk 继续判定的尾部长度。
/// - `rules`: route 上的 `sub_filter` 规则,按配置顺序匹配。
fn rewrite_decided_prefix(
    buffer: &[u8],
    keep_tail: usize,
    rules: &[SubFilterRule],
) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(buffer.len().saturating_sub(keep_tail));
    let mut consumed = 0;
    while buffer.len().saturating_sub(consumed) > keep_tail {
        if let Some(rule) = rules
            .iter()
            .find(|rule| buffer[consumed..].starts_with(&rule.needle))
        {
            out.extend_from_slice(&rule.replacement);
            consumed += rule.needle.len();
        } else {
            out.push(buffer[consumed]);
            consumed += 1;
        }
    }
    (out, consumed)
}

/// 判断状态码是否语义上不能携带响应体。
///
/// # 参数
/// - `status`: 当前响应状态码。
fn response_must_not_have_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

/// 判断响应是否带非 identity 内容编码。
///
/// 压缩/未知编码的响应不能做字节串替换,否则会破坏编码后的实体内容。
///
/// # 参数
/// - `headers`: 当前响应头集合。
fn has_non_identity_content_encoding(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .any(|value| {
            value
                .to_str()
                .map(|raw| {
                    raw.split(',').any(|coding| {
                        let coding = coding.trim();
                        !coding.is_empty() && !coding.eq_ignore_ascii_case("identity")
                    })
                })
                .unwrap_or(true)
        })
}

/// 响应限速 body wrapper。
///
/// 只持有一个待延迟的 frame,不缓存完整响应;当前不拆分大 frame,避免额外复制。
struct LimitRateBody {
    inner: Pin<Box<BoxBody>>,
    bytes_per_second: u64,
    after_remaining: u64,
    pending: Option<Frame<Bytes>>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl LimitRateBody {
    /// 计算当前 frame 需要延迟多久。
    ///
    /// # 参数
    /// - `frame`: 从上游 body 读到的 frame;只有 data frame 计入字节限速。
    fn delay_for_frame(&mut self, frame: &Frame<Bytes>) -> Duration {
        let Some(data) = frame.data_ref() else {
            return Duration::ZERO;
        };
        let len = data.len() as u64;
        if len == 0 {
            return Duration::ZERO;
        }
        let limited = if self.after_remaining >= len {
            self.after_remaining -= len;
            return Duration::ZERO;
        } else {
            let limited = len - self.after_remaining;
            self.after_remaining = 0;
            limited
        };
        let nanos = (limited as u128)
            .saturating_mul(1_000_000_000_u128)
            .div_ceil(self.bytes_per_second.max(1) as u128);
        Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
    }
}

impl Body for LimitRateBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.pending.is_some() {
            let sleep = self.sleep.as_mut().expect("limit_rate pending sleep");
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            return Poll::Ready(self.pending.take().map(Ok));
        }
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let delay = self.delay_for_frame(&frame);
                if delay.is_zero() {
                    return Poll::Ready(Some(Ok(frame)));
                }
                self.pending = Some(frame);
                self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream() && self.pending.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 受共享带宽桶整形的 body。请求与响应两个方向共用同一实现。
/// 逐帧延迟响应数据且不聚合实体的带宽整形 body。
struct ShapedBody {
    /// 原始流式响应体。
    inner: Pin<Box<BoxBody>>,
    /// 当前 route+维度共享桶的帧级调度器。
    shaper: crate::traffic_limit::FrameShaper,
    /// 已扣带宽额度、等待发送时刻的数据帧。
    pending: Option<Frame<Bytes>>,
    /// pending frame 对应的单次等待计时器。
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

/// 响应事实成本的计量方式。
enum TrafficObservation {
    /// 统计实际交付的响应 data frame 字节。
    ResponseBytes(u64),
    /// 统计完整交付的 gRPC message。
    GrpcMessages(GrpcMessageCounter),
}

/// gRPC 五字节 envelope 的跨 frame 增量计数器。
#[derive(Default)]
struct GrpcMessageCounter {
    /// 跨 data frame 暂存的不完整五字节 gRPC envelope header。
    header: [u8; 5],
    /// `header` 中当前有效字节数。
    header_len: usize,
    /// 当前消息尚未交付的 payload 字节数；None 表示正在读取下一个 header。
    payload_remaining: Option<u32>,
    /// 已完整交付给下游的 gRPC message 数。
    completed: u64,
    /// envelope 非法后停止信任后续字节，避免错误返还账本额度。
    invalid: bool,
}

impl GrpcMessageCounter {
    /// 业务作用：消费一个响应 data frame，并只在完整 gRPC message 已交付时增加事实计数。
    ///
    /// 参数说明：`data` 是即将交给下游的响应字节。
    ///
    /// 返回：无；畸形 envelope 后停止计数，避免把任意字节误当成 usage。
    fn observe(&mut self, mut data: &[u8]) {
        if self.invalid {
            return;
        }
        while !data.is_empty() {
            if let Some(remaining) = self.payload_remaining {
                let consumed = data.len().min(remaining as usize);
                data = &data[consumed..];
                let remaining = remaining - consumed as u32;
                if remaining == 0 {
                    self.completed = self.completed.saturating_add(1);
                    self.payload_remaining = None;
                } else {
                    self.payload_remaining = Some(remaining);
                }
                continue;
            }
            let needed = 5usize.saturating_sub(self.header_len);
            let consumed = data.len().min(needed);
            self.header[self.header_len..self.header_len + consumed]
                .copy_from_slice(&data[..consumed]);
            self.header_len += consumed;
            data = &data[consumed..];
            if self.header_len < 5 {
                continue;
            }
            // 压缩标志只有 0/1。未知值说明响应不再是可安全计量的 gRPC envelope，
            // 停止解析比继续错位计数更保守。
            if self.header[0] > 1 {
                self.invalid = true;
                return;
            }
            let payload_len = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]);
            self.header_len = 0;
            if payload_len == 0 {
                self.completed = self.completed.saturating_add(1);
            } else {
                self.payload_remaining = Some(payload_len);
            }
        }
    }
}

/// 一次成本型限额的响应期结算上下文。
struct TrafficSettlement {
    /// route+维度共享额度账本。
    state: Arc<crate::traffic_limit::QuotaState>,
    /// 准入和结算必须共用的不可变额度策略。
    policy: crate::traffic_limit::QuotaPolicy,
    /// 响应事实到额度单位的换算口径。
    source: crate::traffic_limit::CostSource,
    /// 尚未完成最终结算的准入预留凭据。
    reservation: Option<crate::traffic_limit::QuotaReservation>,
    /// 已从实际交付帧累计的可信事实。
    observation: TrafficObservation,
    /// 响应协议与成本来源一致时为 true；不一致时只保留准入预留。
    trustworthy_response: bool,
}

impl TrafficSettlement {
    /// 业务作用：把准入预留与支持的可信响应计量方式绑定，供 body 生命周期完成最终结算。
    ///
    /// 参数说明：`state` 是共享账本；`policy` 是准入策略；`source` 是成本来源；
    /// `reservation` 是本次成功扣账凭据。
    ///
    /// 返回：需要响应期事实的来源返回结算上下文；固定请求成本返回 `None`。
    fn new(
        state: Arc<crate::traffic_limit::QuotaState>,
        policy: crate::traffic_limit::QuotaPolicy,
        source: crate::traffic_limit::CostSource,
        reservation: crate::traffic_limit::QuotaReservation,
    ) -> Option<Self> {
        let observation = match &source {
            crate::traffic_limit::CostSource::PerRequest(_) => return None,
            crate::traffic_limit::CostSource::ResponseBytes { .. } => {
                TrafficObservation::ResponseBytes(0)
            }
            crate::traffic_limit::CostSource::GrpcMessages { .. } => {
                TrafficObservation::GrpcMessages(GrpcMessageCounter::default())
            }
            // 这两种来源在构建期已拒绝，保留失败闭合分支防止后续新增调用旁路门禁。
            crate::traffic_limit::CostSource::GraphqlCost { .. }
            | crate::traffic_limit::CostSource::TrustedUsage { .. } => return None,
        };
        Some(Self {
            state,
            policy,
            source,
            reservation: Some(reservation),
            observation,
            trustworthy_response: true,
        })
    }

    /// 业务作用：复验响应协议是否与声明的事实计量来源一致，防止把普通 HTTP body
    /// 按 gRPC envelope 误解析后返还配额。
    ///
    /// 参数说明：`headers` 是最终响应头。
    ///
    /// 返回：无；协议不匹配时保留准入预留，不做事实返还。
    fn validate_response_headers(&mut self, headers: &HeaderMap) {
        if matches!(&self.observation, TrafficObservation::GrpcMessages(_)) {
            self.trustworthy_response = headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .is_some_and(|mime| mime.trim().starts_with("application/grpc"))
                });
        }
    }

    /// 业务作用：登记一个即将交付给下游的数据帧，形成响应字节或完整 gRPC message 事实。
    ///
    /// 参数说明：`data` 是响应 body 的 data frame。
    ///
    /// 返回：无；计数使用饱和运算。
    fn observe(&mut self, data: &[u8]) {
        match &mut self.observation {
            TrafficObservation::ResponseBytes(bytes) => {
                *bytes = bytes.saturating_add(data.len() as u64);
            }
            TrafficObservation::GrpcMessages(counter) => counter.observe(data),
        }
    }

    /// 业务作用：以已观测事实完成一次且仅一次账本结算。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；重复调用不产生副作用。
    fn finish(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let observed = match &self.observation {
            TrafficObservation::ResponseBytes(bytes) => *bytes,
            TrafficObservation::GrpcMessages(counter) => counter.completed,
        };
        let actual = if self.trustworthy_response {
            self.source.settle_cost(observed)
        } else {
            self.source.admission_cost()
        };
        self.state.settle(&self.policy, reservation, actual);
    }
}

impl Drop for TrafficSettlement {
    /// 业务作用：在客户端取消、响应错误或包装体提前销毁时结算已实际交付的成本，避免预留泄漏。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；已结算凭据不会重复扣账。
    fn drop(&mut self) {
        self.finish();
    }
}

/// 在不缓冲响应的前提下计量事实成本，并在 EOF、错误或取消时结算已交付部分。
struct SettledTrafficBody {
    /// 原始流式响应体。
    inner: Pin<Box<BoxBody>>,
    /// 尚未完成的成本结算上下文；EOF、错误或 Drop 后取空。
    settlement: Option<TrafficSettlement>,
}

impl Body for SettledTrafficBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：透传响应帧并在交付 data frame 前登记事实成本，终止路径立即结算。
    ///
    /// 参数说明：`cx` 是异步 body 轮询上下文。
    ///
    /// 返回：底层 body 的下一帧；EOF 或错误时结算当前已交付事实。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = self.inner.as_mut().poll_frame(cx);
        match polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(settlement), Some(data)) = (self.settlement.as_mut(), frame.data_ref())
                {
                    settlement.observe(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                if let Some(mut settlement) = self.settlement.take() {
                    settlement.finish();
                }
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Some(mut settlement) = self.settlement.take() {
                    settlement.finish();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：报告底层响应是否已结束，同时确保结算包装不改变流结束语义。
    ///
    /// 参数说明：无。
    ///
    /// 返回：底层已结束时返回 `true`。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// 业务作用：透传底层响应体大小提示，不因计量包装改变 framing 决策。
    ///
    /// 参数说明：无。
    ///
    /// 返回：底层 body 的大小提示。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Body for ShapedBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：逐帧执行共享响应带宽整形，同时保留底层 body 的流式背压与 trailer 顺序。
    ///
    /// 参数说明：`cx` 是异步 body 轮询上下文。
    ///
    /// 返回：额度就绪时返回下一帧；需要等待时返回 Pending；底层错误与结束原样传播。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.pending.is_some() {
            let sleep = self.sleep.as_mut().expect("shaped body pending sleep");
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            return Poll::Ready(self.pending.take().map(Ok));
        }
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 只有 data frame 计入带宽;trailer 参与计费会让限速随协议细节漂移。
                let len = frame.data_ref().map(|data| data.len() as u64).unwrap_or(0);
                let delay = self.shaper.delay_for(len);
                if delay.is_zero() {
                    return Poll::Ready(Some(Ok(frame)));
                }
                // 帧先扣配额再延后投递:桶已在 delay_for 里推进,
                // 这一帧的额度不会被并发流重复取走。
                self.pending = Some(frame);
                self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            other => other,
        }
    }

    /// 业务作用：报告整形 body 是否已无底层帧和待发送帧，避免过早结束丢失已扣额度的数据。
    ///
    /// 参数说明：无。
    ///
    /// 返回：底层结束且没有 pending frame 时返回 true。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream() && self.pending.is_none()
    }

    /// 业务作用：透传响应实体大小提示，整形只改变时序而不改变字节数量。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回底层 body 的大小提示。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct LimitConnBody {
    inner: Pin<Box<BoxBody>>,
    _guards: Vec<LimitConnGuard>,
}

impl Body for LimitConnBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// V8 edge:trailers-only 错误响应(HTTP 200 + `grpc-status`/`grpc-message` 头,空 body)。
///
/// message 使用 kebab 短语,天然满足 gRPC message 的 percent-encoding 约束,
/// 无需运行期转义;高基数细节只进结构化日志,不进这里。
#[cfg(feature = "grpc-edge")]
fn grpc_edge_status(status: &'static str, message: &'static str) -> Response<BoxBody> {
    Response::builder()
        .status(200)
        .header(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        )
        .header("grpc-status", HeaderValue::from_static(status))
        .header("grpc-message", HeaderValue::from_static(message))
        .body(crate::full_body(bytes::Bytes::new()))
        .expect("build grpc trailers-only response")
}

/// edge unary 自响应回执（Publish→PublishSummary / Push→PushSummary）。
/// 恰一帧手工编码的平坦 varint protobuf + `grpc-status: 0` trailer;初始 HEADERS
/// 不带 grpc-status(§25.2.3 成功路径)。
#[cfg(feature = "grpc-edge")]
fn edge_unary_summary(fields: &[(u32, u64)]) -> Response<BoxBody> {
    let body = crate::edge_hub::UnaryGrpcResponseBody::new(
        crate::edge_hub::encode_flat_grpc_message(fields),
    );
    Response::builder()
        .status(200)
        .header(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        )
        .body(body.boxed())
        .expect("build edge unary response")
}

/// V8 edge:读取单值元数据(§25.2.3 相位 2)。
///
/// 重复出现、非可见 ASCII、空值或超长一律拒绝;错误文案为低基数 kebab 短语。
#[cfg(feature = "grpc-edge")]
fn single_edge_metadata<'h>(
    parts: &'h Parts,
    name: &http::header::HeaderName,
    max_len: usize,
) -> Result<Option<&'h str>, &'static str> {
    let mut values = parts.headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("duplicate-edge-metadata-header");
    }
    let value = first
        .to_str()
        .map_err(|_| "edge-metadata-must-be-visible-ascii")?;
    if value.is_empty() || value.len() > max_len {
        return Err("edge-metadata-length-out-of-bounds");
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err("edge-metadata-must-be-visible-ascii");
    }
    Ok(Some(value))
}

/// 判断请求是否是原生 HTTP/2 gRPC，而不是名字相近的 gRPC-Web。
///
/// # 参数
/// - `parts`: 下游请求 head。
///
/// 返回：HTTP/2 且 media type 为 `application/grpc` 或 `application/grpc+*` 时为 true。
fn is_native_grpc(parts: &Parts) -> bool {
    parts.version == http::Version::HTTP_2 && has_native_grpc_content_type(&parts.headers)
}

/// 判断响应是否仍是可用 gRPC stream；网关自产普通错误响应不会被登记成长连接。
///
/// # 参数
/// - `resp`: 已完成路由 post-filter 的下游响应。
///
/// 返回：HTTP/2 且 Content-Type 为原生 gRPC 时为 true。
fn is_native_grpc_response(resp: &Response<BoxBody>) -> bool {
    resp.version() == http::Version::HTTP_2 && has_native_grpc_content_type(resp.headers())
}

/// 请求 Accept 是否显式包含 SSE media type，用于在响应头到达前保留已认证 consumer。
fn accepts_event_stream(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|media| {
            media
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// 响应 Content-Type 是否为 SSE。
fn is_sse_response(resp: &Response<BoxBody>) -> bool {
    resp.headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// 借用 Content-Type 判断原生 gRPC media type，不创建小写副本或临时字符串。
///
/// # 参数
/// - `headers`: 请求或响应头。
///
/// 返回：media type 精确为 `application/grpc` 或紧跟 `+` 后缀时为 true；非法 UTF-8 为 false。
fn has_native_grpc_content_type(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(|media_type| {
            media_type == "application/grpc"
                || media_type
                    .strip_prefix("application/grpc")
                    .map(|suffix| suffix.starts_with('+'))
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// 为 gRPC 响应登记长流，并包一层可由注册表触发的 trailer 结束语义。
///
/// # 参数
/// - `resp`: 原始 gRPC 流式响应；body 帧保持原样透传。
/// - `registry`: 进程常驻长连接注册表。
/// - `route_id`: 当前命中路由，用于接口下线时按路由 drain。
/// - `client_ip`: 真实客户端 IP，用于黑名单/应急封禁按 IP drain。
/// - `snapshot_version`: 建流时快照版本，用于关闭 stale 长流。
///
/// 返回：head 不变、body 被透明包装的响应。包装只在注册表关闭时丢弃未读上游 body并发送 status 14。
fn wrap_grpc_drain_response(
    resp: Response<BoxBody>,
    registry: &Arc<ConnectionRegistry>,
    route_id: Arc<str>,
    client_ip: IpAddr,
    consumer: Option<Arc<str>>,
    snapshot_version: u64,
    max_lifetime_ms: u64,
) -> Response<BoxBody> {
    let guard = registry.register(
        route_id,
        client_ip,
        consumer,
        snapshot_version,
        LongProto::GrpcStream,
    );
    let close_wait = guard.closed();
    resp.map(|body| {
        GrpcDrainBody {
            // `BoxBody` 已经 pin 住真正 body；避免为透明 wrapper 再做一次无意义堆分配。
            inner: Some(body),
            guard: Some(guard),
            close_wait,
            lifetime: (max_lifetime_ms > 0)
                .then(|| Box::pin(tokio::time::sleep(Duration::from_millis(max_lifetime_ms)))),
            done: false,
        }
        .boxed()
    })
}

/// gRPC 长流的透明响应 body；注册表关闭时优先生成可被客户端稳定读取的 status 14 trailer。
///
/// 正常路径只委托原 body 的 `poll_frame`，不合并 Data 帧、不吞上游 trailer。关闭路径先 Drop 上游 body
/// 传播取消，再产生一帧固定小 trailer；因此内存与消息大小无关。
struct GrpcDrainBody {
    /// 尚未被关闭/自然结束的原始上游 body。
    inner: Option<BoxBody>,
    /// 注册表 RAII 守卫；自然结束、错误、关闭或下游取消都会注销。
    guard: Option<ConnGuard>,
    /// 对当前连接专属的无装箱关闭等待器。
    close_wait: CloseNotified,
    /// route 级最长存活 timer；None 表示不限制。
    lifetime: Option<Pin<Box<Sleep>>>,
    /// true 表示 trailer 已发或原 body 已结束，后续 poll 必须返回 None。
    done: bool,
}

impl Body for GrpcDrainBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 透明转发上游帧；close 就绪时终止上游并返回一次 `grpc-status=14` trailer。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        let max_age_reached = self
            .lifetime
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready());
        if max_age_reached || Pin::new(&mut self.close_wait).poll(cx).is_ready() {
            let policy_violation = self
                .guard
                .as_ref()
                .map(ConnGuard::ws_close_code)
                .unwrap_or(1001)
                == 1008;
            // 先丢弃上游 body，把 h2 取消尽快传播到 upstream；再让客户端收到明确 gRPC status。
            self.inner.take();
            self.guard.take();
            self.done = true;
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("14"));
            trailers.insert(
                "grpc-message",
                if max_age_reached {
                    HeaderValue::from_static("gateway%20max%20age")
                } else if policy_violation {
                    HeaderValue::from_static("gateway%20policy%20violation")
                } else {
                    HeaderValue::from_static("gateway%20draining")
                },
            );
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        let poll =
            Pin::new(self.inner.as_mut().expect("gRPC body exists until done")).poll_frame(cx);
        if matches!(&poll, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.guard.take();
            self.inner.take();
            self.done = true;
        }
        poll
    }

    /// 已终止时明确结束；正常流委托上游提示。
    fn is_end_stream(&self) -> bool {
        self.done
            || self
                .inner
                .as_ref()
                .map(|body| body.is_end_stream())
                .unwrap_or(true)
    }

    /// 关闭可能提前截断流，不能继续承诺上游的精确长度。
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 为 SSE 响应登记长连接并执行 route 级 idle/max-age。不缓存/重组 event 字节；
/// 策略关闭只结束 body，由 EventSource 客户端按标准重连语义处理。
#[allow(clippy::too_many_arguments)]
fn wrap_sse_drain_response(
    resp: Response<BoxBody>,
    registry: &Arc<ConnectionRegistry>,
    route_id: Arc<str>,
    client_ip: IpAddr,
    consumer: Option<Arc<str>>,
    snapshot_version: u64,
    idle_timeout_ms: u64,
    max_lifetime_ms: u64,
) -> Response<BoxBody> {
    let guard = registry.register(
        route_id,
        client_ip,
        consumer,
        snapshot_version,
        LongProto::Sse,
    );
    let close_wait = guard.closed();
    resp.map(|body| {
        SseDrainBody {
            // BoxBody 已经 pin 住底层 body；直接保存句柄，避免 SSE 再套一层 Pin<Box<_>>。
            inner: Some(body),
            guard: Some(guard),
            close_wait,
            idle: (idle_timeout_ms > 0)
                .then(|| Box::pin(tokio::time::sleep(Duration::from_millis(idle_timeout_ms)))),
            idle_timeout: Duration::from_millis(idle_timeout_ms),
            lifetime: (max_lifetime_ms > 0)
                .then(|| Box::pin(tokio::time::sleep(Duration::from_millis(max_lifetime_ms)))),
            done: false,
        }
        .boxed()
    })
}

struct SseDrainBody {
    inner: Option<BoxBody>,
    guard: Option<ConnGuard>,
    close_wait: CloseNotified,
    idle: Option<Pin<Box<Sleep>>>,
    idle_timeout: Duration,
    lifetime: Option<Pin<Box<Sleep>>>,
    done: bool,
}

impl Body for SseDrainBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        let idle_reached = self
            .idle
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready());
        let max_age_reached = self
            .lifetime
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready());
        if idle_reached || max_age_reached || Pin::new(&mut self.close_wait).poll(cx).is_ready() {
            self.inner.take();
            self.guard.take();
            self.done = true;
            return Poll::Ready(None);
        }
        let poll =
            Pin::new(self.inner.as_mut().expect("SSE body exists until done")).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(_))) => {
                let timeout = self.idle_timeout;
                if let Some(idle) = self.idle.as_mut() {
                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
            }
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                self.guard.take();
                self.inner.take();
                self.done = true;
            }
            Poll::Pending => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.done
            || self
                .inner
                .as_ref()
                .map(|body| body.is_end_stream())
                .unwrap_or(true)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn query_param_raw<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            Some(v)
        } else {
            None
        }
    })
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// 从网关固定宽度 Snowflake request-id 提取 H2 shard 提示。
///
/// request-id 的末两个十六进制字符保留原 Snowflake 低 8 位，其中 sequence 会随请求连续
/// 变化，足以均匀覆盖允许的 1..=64 shards。直接解码两个栈上字节比再次扫描 16 字节做 FNV
/// 更便宜；若内部调用传入非标准 ID，则回退完整稳定哈希，保持确定性而不信任畸形输入。
#[inline]
fn request_id_shard_hint(request_id: &str) -> u64 {
    let bytes = request_id.as_bytes();
    if bytes.len() == 16 {
        if let (Some(high), Some(low)) = (hex_nibble(bytes[14]), hex_nibble(bytes[15])) {
            return u64::from((high << 4) | low);
        }
    }
    stable_hash64(bytes)
}

#[inline]
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn direct_response(cfg: &DirectResponse) -> Response<BoxBody> {
    let mut builder = Response::builder().status(cfg.status);
    if cfg.status.is_redirection() {
        if let Some(value) = &cfg.value {
            builder = builder.header(http::header::LOCATION, value);
        }
        return builder
            .body(full_body(Bytes::new()))
            .expect("build redirect response");
    }
    builder
        .body(full_body(Bytes::from(
            cfg.value.clone().unwrap_or_default(),
        )))
        .expect("build direct response")
}

/// 业务作用：把已验证的 Gateway API RequestRedirect 计划转换为无 body 的 HTTP 响应。
///
/// 参数说明：`status` 是构建期允许的重定向状态；`location` 已由请求上下文生成并校验。
///
/// 返回：返回带唯一 Location 头的终端响应，不访问上游也不读取请求 body。
fn gateway_redirect_response(status: StatusCode, location: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(http::header::LOCATION, location)
        .body(full_body(Bytes::new()))
        .expect("validated Gateway redirect response")
}

fn mock_response(cfg: &MockResponsePolicy) -> Response<BoxBody> {
    let mut response = Response::new(full_body(cfg.body.clone()));
    *response.status_mut() = cfg.status;
    *response.headers_mut() = cfg.headers.clone();
    response
}

async fn enforce_fault_injection(
    route: &Route,
    request_id: &str,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let policy = route.fault_injection.as_ref()?;
    let mut hasher = Sha256::new();
    hasher.update((route.id.len() as u64).to_le_bytes());
    hasher.update(route.id.as_bytes());
    hasher.update((request_id.len() as u64).to_le_bytes());
    hasher.update(request_id.as_bytes());
    let digest = hasher.finalize();
    let slot = u16::from_le_bytes([digest[0], digest[1]]) as u32 * 10_000 / 65_536;
    if slot >= u32::from(policy.percentage_bps) {
        return None;
    }
    if !policy.delay.is_zero() {
        metrics.inc_fault_injection(false);
        // Tokio timer yields the worker; no thread sleep and no request-body buffering is introduced.
        tokio::time::sleep(policy.delay).await;
    }
    policy.abort_status.map(|status| {
        metrics.inc_fault_injection(true);
        Response::builder()
            .status(status)
            .header("x-gateway-fault-injected", "abort")
            .body(full_body(policy.abort_body.clone()))
            .expect("validated fault response")
    })
}

async fn collect_bff_json_response(
    mut response: Response<BoxBody>,
    max_bytes: usize,
) -> Result<serde_json::Value, BffTargetFailure> {
    if !response.status().is_success() {
        return Err(BffTargetFailure::Status);
    }
    let json_media_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().starts_with("application/")
                    && value.to_ascii_lowercase().ends_with("+json")
        });
    if !json_media_type {
        return Err(BffTargetFailure::InvalidJson);
    }
    if response
        .body()
        .size_hint()
        .upper()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BffTargetFailure::TooLarge);
    }
    let mut first = None::<Bytes>;
    let mut combined = None::<BytesMut>;
    let mut total = 0_usize;
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| BffTargetFailure::Unavailable)?;
        if frame.is_trailers() {
            return Err(BffTargetFailure::InvalidJson);
        }
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        total = total
            .checked_add(data.len())
            .filter(|total| *total <= max_bytes)
            .ok_or(BffTargetFailure::TooLarge)?;
        match (&mut first, &mut combined) {
            (slot @ None, None) => *slot = Some(data),
            (Some(previous), slot @ None) => {
                // 单 frame 是常见 JSON 响应，直接复用上游 Bytes；只有第二 frame 出现才做
                // 一次必要合并，capacity 受 target.max_response_bytes 硬约束。
                let mut buffer = BytesMut::with_capacity(total);
                buffer.extend_from_slice(previous.as_ref());
                buffer.extend_from_slice(data.as_ref());
                *slot = Some(buffer);
            }
            (_, Some(buffer)) => buffer.extend_from_slice(data.as_ref()),
        }
    }
    let bytes = combined.map(BytesMut::freeze).or(first).unwrap_or_default();
    serde_json::from_slice(bytes.as_ref()).map_err(|_| BffTargetFailure::InvalidJson)
}

struct BffBoundedWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl BffBoundedWriter {
    fn new(max: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max.min(64 * 1024)),
            max,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for BffBoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > self.max {
            return Err(std::io::Error::other(
                "BFF aggregate exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 构建鉴权失败响应。
///
/// # 参数
/// - `challenge`: 可选 `WWW-Authenticate` 响应头值。
fn auth_failed_response(challenge: Option<&str>) -> Response<BoxBody> {
    build_auth_denied_response(StatusCode::UNAUTHORIZED, challenge)
}

/// 构建鉴权拒绝响应。
///
/// # 参数
/// - `status`: 401 或 403。
/// - `challenge`: 可选 `WWW-Authenticate` 响应头值。
fn auth_denied_response(status: StatusCode, challenge: Option<&HeaderValue>) -> Response<BoxBody> {
    build_auth_denied_response(status, challenge.and_then(|value| value.to_str().ok()))
}

/// 构建鉴权拒绝响应的通用实现。
///
/// # 参数
/// - `status`: 401 或 403。
/// - `challenge`: 可选 `WWW-Authenticate` 文本。
fn build_auth_denied_response(status: StatusCode, challenge: Option<&str>) -> Response<BoxBody> {
    let mut builder = Response::builder().status(status);
    if let Some(challenge) = challenge {
        builder = builder.header(http::header::WWW_AUTHENTICATE, challenge);
    }
    let body = if status == StatusCode::FORBIDDEN {
        Bytes::from_static(b"forbidden")
    } else {
        Bytes::from_static(b"unauthorized")
    };
    builder
        .body(full_body(body))
        .expect("build auth failed response")
}

/// 构造 HTTP→HTTPS 跳转响应(§19):`Location: https://{host}[:{to_port}]{path?query}`,状态 301/308,空 body。
/// Host 取自入站 Host 头(去掉端口与 userinfo);目标端口 443 时省略端口(标准 https)。
fn https_redirect_response(
    parts: &Parts,
    redirect: &crate::config::RedirectHttps,
) -> Response<BoxBody> {
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.rsplit_once('@').map(|(_, h)| h).unwrap_or(h)) // 去 userinfo(极少见)
        .map(|h| h.split(':').next().unwrap_or(h)) // 去端口
        .unwrap_or("");
    let path_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let location = if redirect.to_port == 443 {
        format!("https://{host}{path_query}")
    } else {
        format!("https://{host}:{}{path_query}", redirect.to_port)
    };
    let mut builder = Response::builder().status(redirect.status);
    // location 由已校验的 Host 头 + 已规范化的本地 path 拼成;万一含非法 header 字符则退化为无 Location 的 3xx。
    if let Ok(value) = http::header::HeaderValue::from_str(&location) {
        builder = builder.header(http::header::LOCATION, value);
    }
    builder
        .body(full_body(Bytes::new()))
        .expect("build https redirect response")
}

fn apply_response_filters(
    resp: &mut Response<BoxBody>,
    route: &Route,
    request_origin: Option<&HeaderValue>,
    request_parts: Option<&Parts>,
    client_ip: IpAddr,
    downstream_proto: &'static str,
    request_id: &str,
) {
    let response_status = resp.status();
    for op in &route.response_headers {
        match op {
            ResponseHeaderOp::Add(set) => {
                let value = render_response_header_value(
                    set,
                    route,
                    request_parts,
                    client_ip,
                    downstream_proto,
                    request_id,
                    response_status,
                );
                if let Ok(value) = http::header::HeaderValue::from_str(&value) {
                    resp.headers_mut().append(set.name.clone(), value);
                } else {
                    tracing::warn!(header = %set.name, "skip invalid response header value");
                }
            }
            ResponseHeaderOp::Set(set) => {
                let value = render_response_header_value(
                    set,
                    route,
                    request_parts,
                    client_ip,
                    downstream_proto,
                    request_id,
                    response_status,
                );
                if let Ok(value) = http::header::HeaderValue::from_str(&value) {
                    resp.headers_mut().insert(set.name.clone(), value);
                } else {
                    tracing::warn!(header = %set.name, "skip invalid response header value");
                }
            }
            ResponseHeaderOp::Hide(name) => {
                resp.headers_mut().remove(name);
            }
            ResponseHeaderOp::ProxyRedirect(rule) => {
                apply_proxy_redirect(resp.headers_mut(), rule);
            }
            ResponseHeaderOp::CookieRewrite(rule) => {
                apply_cookie_rewrite(resp.headers_mut(), rule);
            }
            ResponseHeaderOp::Dedupe(rule) => {
                dedupe_response_header(resp, rule);
            }
        }
    }
    if let Some(cors) = &route.cors {
        apply_cors_headers(resp, cors, request_origin, request_parts, false);
    }
}

/// 业务作用：在响应相位渲染头部模板，使响应状态等事实不会泄漏到请求相位。
///
/// 参数说明：`set` 是头部规则；`route` 提供变量计划；`request_parts` 是原始请求；
/// `client_ip` 是真实客户端地址；`downstream_proto` 是下游 scheme；`request_id` 是权威请求标识；
/// `response_status` 是当前已确定的响应状态。
///
/// 返回：静态值直接复用；动态值按响应相位上下文渲染。
fn render_response_header_value(
    set: &crate::routing::ResponseHeaderSet,
    route: &Route,
    request_parts: Option<&Parts>,
    client_ip: IpAddr,
    downstream_proto: &'static str,
    request_id: &str,
    response_status: StatusCode,
) -> String {
    if let Some(literal) = set.value.static_literal() {
        return literal.to_string();
    }
    let Some(parts) = request_parts else {
        return String::new();
    };
    let eval_ctx = crate::variable::EvalContext {
        parts,
        client_ip,
        downstream_proto,
        request_id,
        route_id: route.id.as_str(),
        response_status: Some(response_status),
    };
    set.value.render(&eval_ctx, route.variables.as_ref())
}

/// 应用 nginx `proxy_redirect` 头改写。
///
/// # 参数
/// - `headers`: 待修改的下游响应头集合。
/// - `rule`: 构建期解析出的前缀替换规则。
fn apply_proxy_redirect(headers: &mut http::HeaderMap, rule: &crate::routing::ProxyRedirectRule) {
    rewrite_header_prefix(headers, http::header::LOCATION, &rule.from, &rule.to);
    rewrite_header_contains(
        headers,
        HeaderName::from_static("refresh"),
        &rule.from,
        &rule.to,
    );
}

/// 对单个响应头做前缀替换。
///
/// # 参数
/// - `headers`: 待修改的响应头集合。
/// - `name`: 目标响应头名。
/// - `from`: 需要匹配的旧前缀。
/// - `to`: 替换后的新前缀。
fn rewrite_header_prefix(headers: &mut http::HeaderMap, name: HeaderName, from: &str, to: &str) {
    let Some(current) = headers.get(&name).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let Some(rest) = current.strip_prefix(from) else {
        return;
    };
    let next = format!("{to}{rest}");
    if let Ok(value) = HeaderValue::from_str(&next) {
        headers.insert(name, value);
    }
}

/// 对单个响应头做一次包含替换。
///
/// `Refresh` 头常见格式是 `0; url=<URL>`,URL 不一定在开头,因此使用一次包含替换。
///
/// # 参数
/// - `headers`: 待修改的响应头集合。
/// - `name`: 目标响应头名。
/// - `from`: 需要替换的旧片段。
/// - `to`: 替换后的新片段。
fn rewrite_header_contains(headers: &mut http::HeaderMap, name: HeaderName, from: &str, to: &str) {
    let Some(current) = headers.get(&name).and_then(|v| v.to_str().ok()) else {
        return;
    };
    if !current.contains(from) {
        return;
    }
    let next = current.replacen(from, to, 1);
    if let Ok(value) = HeaderValue::from_str(&next) {
        headers.insert(name, value);
    }
}

/// 应用 `proxy_cookie_domain/path` 改写。
///
/// # 参数
/// - `headers`: 待修改的下游响应头集合。
/// - `rule`: 构建期解析出的 cookie 属性改写规则。
fn apply_cookie_rewrite(headers: &mut http::HeaderMap, rule: &crate::routing::CookieRewriteRule) {
    let values = headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return;
    }
    headers.remove(http::header::SET_COOKIE);
    for value in values {
        let next = value
            .to_str()
            .ok()
            .map(|raw| rewrite_set_cookie(raw, rule))
            .and_then(|raw| HeaderValue::from_str(&raw).ok())
            .unwrap_or(value);
        headers.append(http::header::SET_COOKIE, next);
    }
}

/// 改写单条 Set-Cookie 的 Domain 或 Path 属性。
///
/// # 参数
/// - `raw`: 单条 Set-Cookie header value。
/// - `rule`: cookie 属性改写规则。
fn rewrite_set_cookie(raw: &str, rule: &crate::routing::CookieRewriteRule) -> String {
    let (attr, from, to, domain) = match rule {
        crate::routing::CookieRewriteRule::Domain { from, to } => ("domain", from, to, true),
        crate::routing::CookieRewriteRule::Path { from, to } => ("path", from, to, false),
        crate::routing::CookieRewriteRule::Flags(rule) => return rewrite_cookie_flags(raw, rule),
    };
    raw.split(';')
        .map(|part| rewrite_cookie_part(part, attr, from, to, domain))
        .collect::<Vec<_>>()
        .join(";")
}

/// 改写单条 Set-Cookie 的 flags。
///
/// # 参数
/// - `raw`: 单条 Set-Cookie header value。
/// - `rule`: cookie flags 改写规则。
fn rewrite_cookie_flags(raw: &str, rule: &crate::routing::CookieFlagsRule) -> String {
    let mut parts = raw.split(';').map(|part| part.trim()).collect::<Vec<_>>();
    if parts.is_empty() || !cookie_name_matches(parts[0], rule.cookie.as_str()) {
        return raw.to_string();
    }
    let mut out = Vec::with_capacity(parts.len() + 3);
    out.push(parts.remove(0).to_string());
    let mut has_secure = false;
    let mut has_http_only = false;
    let mut has_same_site = false;
    for part in parts {
        if part.eq_ignore_ascii_case("secure") {
            has_secure = true;
            if !rule.remove_secure {
                out.push("Secure".to_string());
            }
            continue;
        }
        if part.eq_ignore_ascii_case("httponly") {
            has_http_only = true;
            if !rule.remove_http_only {
                out.push("HttpOnly".to_string());
            }
            continue;
        }
        if part
            .split_once('=')
            .map(|(name, _)| name.eq_ignore_ascii_case("samesite"))
            .unwrap_or(false)
        {
            has_same_site = true;
            if !rule.remove_same_site {
                if let Some(value) = &rule.same_site {
                    out.push(format!("SameSite={value}"));
                } else {
                    out.push(part.to_string());
                }
            }
            continue;
        }
        out.push(part.to_string());
    }
    if rule.add_secure && !has_secure {
        out.push("Secure".to_string());
    }
    if rule.add_http_only && !has_http_only {
        out.push("HttpOnly".to_string());
    }
    if let Some(value) = &rule.same_site {
        if !has_same_site {
            out.push(format!("SameSite={value}"));
        }
    }
    out.join("; ")
}

/// 判断 Set-Cookie 名是否命中 flags 规则。
///
/// # 参数
/// - `cookie_pair`: Set-Cookie 第一个 `name=value` 片段。
/// - `expected`: 规则里的 cookie 名或 `*`。
fn cookie_name_matches(cookie_pair: &str, expected: &str) -> bool {
    if expected == "*" {
        return true;
    }
    cookie_pair
        .split_once('=')
        .map(|(name, _)| name.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

/// 改写 Set-Cookie 中的单个属性片段。
///
/// # 参数
/// - `part`: `;` 分隔后的片段,可能是 cookie 本体或属性。
/// - `attr`: 目标属性名。
/// - `from`: 需要匹配的旧值。
/// - `to`: 替换后的新值。
/// - `domain`: 是否按 domain 规则做大小写不敏感匹配。
fn rewrite_cookie_part(part: &str, attr: &str, from: &str, to: &str, domain: bool) -> String {
    let trimmed = part.trim_start();
    let leading = &part[..part.len() - trimmed.len()];
    let Some((name, value)) = trimmed.split_once('=') else {
        return part.to_string();
    };
    if !name.eq_ignore_ascii_case(attr) {
        return part.to_string();
    }
    let matched = if domain {
        value.eq_ignore_ascii_case(from)
    } else {
        value == from
    };
    if !matched {
        return part.to_string();
    }
    format!("{leading}{name}={to}")
}

/// 选择当前响应命中的 `error_page` 策略。
///
/// # 参数
/// - `resp`: 上游或网关自产的响应。
/// - `route`: 当前命中 route,提供 error_page 策略集合。
fn select_error_page_policy<'a>(
    resp: &Response<BoxBody>,
    route: &'a Route,
) -> Option<&'a ErrorPagePolicy> {
    if !route.proxy_intercept_errors && resp.extensions().get::<forward::UpstreamTrace>().is_some()
    {
        return None;
    }
    route
        .error_pages
        .iter()
        .find(|policy| policy.statuses.contains(&resp.status()))
}

/// 读取并校验上游 `X-Accel-Redirect` 目标。
///
/// # 参数
/// - `resp`: 上游响应。
fn x_accel_redirect_target(resp: &Response<BoxBody>) -> Option<&str> {
    let value = resp
        .headers()
        .get("x-accel-redirect")
        .and_then(|value| value.to_str().ok())?
        .trim();
    if !value.starts_with('/') || value.bytes().any(|b| b == 0 || b < 0x20) {
        return Some("");
    }
    Some(value)
}

/// 应用 `error_page` 固定响应映射。
///
/// # 参数
/// - `resp`: 上游或网关自产的原始响应。
/// - `policy`: 已命中的 error_page 策略。调用方保证它是固定响应动作。
fn apply_error_page_response(
    resp: Response<BoxBody>,
    policy: &ErrorPagePolicy,
) -> Response<BoxBody> {
    let ErrorPageAction::Response(response) = &policy.action else {
        return resp;
    };
    let upstream_trace = resp.extensions().get::<forward::UpstreamTrace>().cloned();
    let mut mapped = Response::builder()
        .status(response.status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(
            response
                .value
                .clone()
                .unwrap_or_else(|| response.status.canonical_reason().unwrap_or("error").into()),
        )))
        .expect("build error_page response");
    if let Some(trace) = upstream_trace {
        mapped.extensions_mut().insert(trace);
    }
    mapped
}

/// 业务作用：识别可由当前 route 本地终止的 CORS preflight，避免把浏览器协商请求误发给后端。
///
/// 参数说明：`parts` 是下游请求头部；`route` 提供已编译 CORS 策略。
///
/// 返回：仅配置 CORS 且同时具备 OPTIONS、Origin 和请求方法头时返回 `true`。
fn is_cors_preflight(parts: &Parts, route: &Route) -> bool {
    route.cors.is_some()
        && parts.method == http::Method::OPTIONS
        && parts.headers.contains_key(http::header::ORIGIN)
        && parts
            .headers
            .contains_key(HeaderName::from_static("access-control-request-method"))
}

/// 业务作用：本地生成 CORS preflight 响应，并只对已授权 origin 发布协商头。
///
/// 参数说明：`cors` 是 route 策略；`request` 提供 Origin、请求方法和请求 header。
///
/// 返回：返回 204 空响应；origin 未授权时仍不泄露任何 CORS 许可头。
fn cors_preflight_response(cors: &CorsPolicy, request: &Parts) -> Response<BoxBody> {
    let mut resp = Response::builder()
        .status(204)
        .body(full_body(Bytes::new()))
        .expect("build cors preflight response");
    apply_cors_headers(
        &mut resp,
        cors,
        request.headers.get(http::header::ORIGIN),
        Some(request),
        true,
    );
    resp
}

/// 业务作用：按已编译 CORS 策略发布实际请求或 preflight 响应头，并维持缓存隔离。
///
/// 参数说明：`resp` 是待返回响应；`cors` 是策略；`request_origin` 是已保存的 Origin；
/// `request_parts` 提供 preflight 动态通配值；`preflight` 区分两类响应字段。
///
/// 返回：无返回值；未授权 origin 不修改响应，授权时原地写入有界合法 header。
fn apply_cors_headers(
    resp: &mut Response<BoxBody>,
    cors: &CorsPolicy,
    request_origin: Option<&HeaderValue>,
    request_parts: Option<&Parts>,
    preflight: bool,
) {
    let Some(origin) = cors
        .allow_origin
        .response_value(request_origin, cors.allow_credentials)
    else {
        return;
    };
    let dynamic_expose =
        (!preflight && cors.allow_credentials && cors.expose_headers.as_deref() == Some("*"))
            .then(|| cors_exposed_response_headers(resp.headers()));
    let headers = resp.headers_mut();
    headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        origin,
    );
    if cors.allow_origin.varies_by_origin(cors.allow_credentials) {
        append_vary_header(headers, "Origin");
    }
    if cors.allow_credentials {
        headers.insert(
            HeaderName::from_static("access-control-allow-credentials"),
            HeaderValue::from_static("true"),
        );
    }
    if preflight {
        if let Some(methods) = &cors.allow_methods {
            let value = if cors.allow_credentials && methods == "*" {
                request_parts
                    .and_then(|parts| {
                        parts
                            .headers
                            .get(HeaderName::from_static("access-control-request-method"))
                    })
                    .cloned()
            } else {
                HeaderValue::from_str(methods).ok()
            };
            if let Some(value) = value {
                headers.insert(
                    HeaderName::from_static("access-control-allow-methods"),
                    value,
                );
            }
            if cors.allow_credentials && methods == "*" {
                append_vary_header(headers, "Access-Control-Request-Method");
            }
        }
        if let Some(allowed_headers) = &cors.allow_headers {
            let value = if cors.allow_credentials && allowed_headers == "*" {
                request_parts
                    .and_then(|parts| {
                        parts
                            .headers
                            .get(HeaderName::from_static("access-control-request-headers"))
                    })
                    .cloned()
            } else {
                HeaderValue::from_str(allowed_headers).ok()
            };
            if let Some(value) = value {
                headers.insert(
                    HeaderName::from_static("access-control-allow-headers"),
                    value,
                );
            }
            if cors.allow_credentials && allowed_headers == "*" {
                append_vary_header(headers, "Access-Control-Request-Headers");
            }
        }
        if let Some(max_age) = cors.max_age_seconds {
            if let Ok(value) = HeaderValue::from_str(&max_age.to_string()) {
                headers.insert(HeaderName::from_static("access-control-max-age"), value);
            }
        }
    } else if let Some(expose) = &cors.expose_headers {
        let value = dynamic_expose.as_deref().unwrap_or(expose);
        if !value.is_empty() {
            if let Ok(value) = HeaderValue::from_str(value) {
                headers.insert(
                    HeaderName::from_static("access-control-expose-headers"),
                    value,
                );
            }
        }
    }
}

/// 业务作用：为凭证请求的 `exposeHeaders: ["*"]` 构造实际响应 header 白名单。
///
/// 参数说明：`headers` 是写入 CORS 字段前的响应 header 集合。
///
/// 返回：返回排序去重且至多 64 项、8192 字节的名称列表；敏感 cookie header 不发布。
fn cors_exposed_response_headers(headers: &http::HeaderMap) -> String {
    let mut names = headers
        .keys()
        .map(HeaderName::as_str)
        .filter(|name| {
            !matches!(
                *name,
                "set-cookie" | "set-cookie2" | "access-control-expose-headers"
            )
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names.truncate(64);
    let mut output = String::new();
    for name in names {
        let extra = name.len() + usize::from(!output.is_empty());
        if output.len().saturating_add(extra) > 8192 {
            break;
        }
        if !output.is_empty() {
            output.push(',');
        }
        output.push_str(name);
    }
    output
}

/// 业务作用：把动态 CORS 请求维度加入 `Vary`，防止共享缓存跨 origin 或预检维度复用许可。
///
/// 参数说明：`headers` 是响应 header；`dimension` 是受控的标准请求 header 名。
///
/// 返回：无返回值；已存在时保持原值，否则追加一个独立 `Vary` 字段。
fn append_vary_header(headers: &mut http::HeaderMap, dimension: &'static str) {
    let name = http::header::VARY;
    let present = headers
        .get_all(&name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(dimension))
        });
    if !present {
        headers.append(name, HeaderValue::from_static(dimension));
    }
}

fn apply_fallback_headers(resp: &mut Response<BoxBody>, reason: &'static str) {
    resp.headers_mut().insert(
        HeaderName::from_static("x-gateway-fallback"),
        HeaderValue::from_static("true"),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-gateway-fallback-reason"),
        HeaderValue::from_static(reason),
    );
}

fn dedupe_response_header(resp: &mut Response<BoxBody>, rule: &DedupeResponseHeader) {
    let values = resp
        .headers()
        .get_all(&rule.name)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if values.len() <= 1 {
        return;
    }
    resp.headers_mut().remove(&rule.name);
    match rule.mode {
        DedupeMode::RetainFirst => {
            if let Some(value) = values.into_iter().next() {
                resp.headers_mut().append(rule.name.clone(), value);
            }
        }
        DedupeMode::RetainLast => {
            if let Some(value) = values.into_iter().last() {
                resp.headers_mut().append(rule.name.clone(), value);
            }
        }
        DedupeMode::RetainUnique => {
            let mut seen = Vec::<HeaderValue>::new();
            for value in values {
                if seen.contains(&value) {
                    continue;
                }
                seen.push(value.clone());
                resp.headers_mut().append(rule.name.clone(), value);
            }
        }
    }
}

/// 从 `X-Forwarded-For` 取真实客户端 IP(仅当直连对端可信时调用,review L6):
/// 从右往左跳过 `trusted_proxies` 内的地址,取第一个非可信地址为真实客户端;
/// 无法解析 / 全是可信代理 → `None`(调用方回退到 socket 对端)。
fn client_ip_from_forwarded(
    parts: &http::request::Parts,
    trusted: &[crate::net::Cidr],
) -> Option<IpAddr> {
    let xff = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?;
    for entry in xff.rsplit(',') {
        if let Ok(ip) = entry.trim().parse::<IpAddr>() {
            if !crate::net::any_contains(trusted, ip) {
                return Some(ip);
            }
        }
    }
    None
}

fn audit_peer(conn: &ConnInfo, client_ip: IpAddr, trusted_inbound: bool) -> String {
    if conn.via_proxy_protocol {
        return conn.real_peer.to_string();
    }
    if trusted_inbound && client_ip != conn.tcp_peer.ip() {
        return client_ip.to_string();
    }
    conn.tcp_peer.to_string()
}

fn host_allowed(parts: &http::request::Parts, server_names: &[String]) -> bool {
    if server_names.is_empty() {
        return true;
    }
    let Some(host) = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(normalize_host)
    else {
        return false;
    };
    server_names.iter().any(|name| {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = name.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == name
        }
    })
}

/// 业务作用：判断 TLS 连接 SNI 与当前请求 authority 是否选择了不同的 Gateway HTTPS
/// listener，阻止 HTTP/2 连接合并绕过 listener 隔离。
///
/// 参数说明：`parts` 提供可信解析后的请求头；`tls_server_name` 来自 rustls 握手；
/// `listeners` 是同一 socket 已裁决冲突的逻辑 listener 表。
///
/// 返回：两侧都可执行 listener 选择且身份不同时返回 true；未携带 SNI/Host 或未启用表时返回 false。
fn gateway_tls_listener_mismatch(
    parts: &http::request::Parts,
    tls_server_name: Option<&str>,
    listeners: &[GatewayListenerRuntime],
) -> bool {
    if listeners.is_empty() {
        return false;
    }
    let Some(sni) = tls_server_name.map(normalize_host) else {
        return false;
    };
    let Some(host) = gateway_request_hostname(parts) else {
        return false;
    };
    select_gateway_listener(&sni, listeners) != select_gateway_listener(&host, listeners)
}

/// 业务作用：把 HTTP/2/HTTP/3 `:authority` 规范成统一的内部 Host，保证路由选择与
/// preserve_host 在所有下游 HTTP 版本上使用同一权威语义。
///
/// 参数说明：`parts` 是 Hyper 已解析的请求 head；显式 Host 优先，不会被 URI authority 覆盖。
///
/// 返回：已有 Host、无 authority 或成功写入合法 Host 时返回 true；authority 无法编码为
/// header value 时返回 false，调用方必须在进入业务路由前拒绝请求。
fn canonicalize_request_authority(parts: &mut http::request::Parts) -> bool {
    if parts.headers.contains_key(http::header::HOST) {
        return true;
    }
    let Some(authority) = parts.uri.authority() else {
        return true;
    };
    let Ok(host) = HeaderValue::from_str(authority.as_str()) else {
        return false;
    };
    parts.headers.insert(http::header::HOST, host);
    true
}

/// 业务作用：从 HTTP Host 或 HTTP/2 authority 提取规范化 Gateway listener 选择名，
/// 让明文隔离与 HTTPS 421 使用同一 authority 语义。
///
/// 参数说明：`parts` 是 Hyper 已解析且通过基础头部预算的请求 head。
///
/// 返回：存在合法 UTF-8 authority 时返回小写去尾点 hostname；缺失或坏值返回 None。
fn gateway_request_hostname(parts: &http::request::Parts) -> Option<String> {
    parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(normalize_host)
        .or_else(|| {
            parts
                .uri
                .authority()
                .map(|authority| normalize_host(authority.as_str()))
        })
}

/// 业务作用：按 Gateway API 的精确 hostname、最长 wildcard、无 hostname 兜底顺序选择
/// 同一 HTTP/HTTPS socket 上的唯一逻辑 listener。
///
/// 参数说明：`hostname` 已规范化；`listeners` 已在配置构建期保证 id 与 hostname 唯一。
///
/// 返回：命中时返回 listener 稳定身份；没有 hostname-less 兜底且无名称匹配时返回 None。
fn select_gateway_listener<'a>(
    hostname: &str,
    listeners: &'a [GatewayListenerRuntime],
) -> Option<&'a str> {
    if let Some(listener) = listeners.iter().find(|listener| {
        listener.hostname.as_deref().is_some_and(|candidate| {
            !candidate.starts_with("*.") && candidate.eq_ignore_ascii_case(hostname)
        })
    }) {
        return Some(listener.id.as_ref());
    }
    if let Some(listener) = listeners
        .iter()
        .filter_map(|listener| {
            let candidate = listener.hostname.as_deref()?;
            let suffix = candidate.strip_prefix("*.")?;
            hostname
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
                .then_some((suffix.len(), listener))
        })
        .max_by_key(|(suffix_len, _)| *suffix_len)
        .map(|(_, listener)| listener)
    {
        return Some(listener.id.as_ref());
    }
    listeners
        .iter()
        .find(|listener| listener.hostname.is_none())
        .map(|listener| listener.id.as_ref())
}

fn normalize_host(raw: &str) -> String {
    raw.rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(raw)
        .split(':')
        .next()
        .unwrap_or(raw)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// 把 Hyper 下游 body 擦除为 H3 可共用的流式类型。
///
/// 业务作用：统一 h1/h2 与 HTTP/3 请求管线；错误类型擦除不读取、不复制、不聚合 DATA，背压和
/// trailers 仍由原 body 逐 frame 驱动。
///
/// 参数说明：`body` 是当前 Hyper request stream 的唯一所有权。
///
/// 返回：可直接进入统一治理/forward 管线的 `BoxBody`。
fn box_incoming_body(body: Incoming) -> BoxBody {
    body.map_err(|error| Box::new(error) as crate::BoxError)
        .boxed()
}

/// 在 TLS h1/h2 响应上发布当前 generation 已就绪的 HTTP/3 authority。
///
/// 业务作用：浏览器只有收到 Alt-Svc 才会发现同端口 QUIC；由网关覆盖上游广告可防止 upstream
/// 把客户端引到错误 authority。H3 自身响应不重复广告，禁用广告时发送 `clear` 撤销客户端缓存。
///
/// 参数说明：`response` 是即将下发的统一响应；`http3` 是同快照 H3 发布计划；
/// `downstream_proto`/`downstream_version` 标识本次真实下游 transport。
///
/// 返回：无；TLS h1/h2 在启用广告时插入本 authority，否则插入 `clear`；H3 响应不带该头。
fn apply_http3_advertisement(
    response: &mut Response<BoxBody>,
    http3: &crate::config::Http3RuntimeCfg,
    downstream_proto: &'static str,
    downstream_version: http::Version,
) {
    if downstream_proto != "https" {
        return;
    }
    // upstream Alt-Svc 的 authority 属于后端，绝不能透传给网关客户端；即使 H3
    // 关闭，也要覆盖为 clear，才能撤销浏览器仍缓存的上一 generation authority。
    response.headers_mut().remove(http::header::ALT_SVC);
    if downstream_version == http::Version::HTTP_3 {
        return;
    }
    let value = http3
        .enabled
        .then(|| http3.alt_svc_header.clone())
        .flatten()
        .unwrap_or_else(|| http::HeaderValue::from_static("clear"));
    response.headers_mut().insert(http::header::ALT_SVC, value);
}

fn is_h1_websocket_upgrade<B>(req: &Request<B>) -> bool {
    if req.version() != http::Version::HTTP_11 || req.method() != http::Method::GET {
        return false;
    }
    let has_upgrade = req
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let has_connection_upgrade = req
        .headers()
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    has_upgrade && has_connection_upgrade
}

/// 校验并规范化请求 path。
///
/// 安全策略（架构规范 §4.2）：
/// - 拒绝 NUL、反斜杠、非法/危险 percent encoding、dot segment、超长和超深 path；
/// - 拒绝 `%25`，避免后端二次解码把 `%252e`/`%252f` 重新解释成绕过字符；
/// - 合并重复 `/`，保留 query 与 trailing slash；规范化结果同时供匹配和上游转发使用。
///
/// # 参数
/// - `parts`: 当前请求 head；成功时可能原地替换其中的 URI path-and-query。
/// - `limits`: 当前 proxy 快照的 path 字节数与 segment 预算。
///
/// 返回：path 安全且规范化成功为 true；任何编码/预算/URI 重建错误均为 false，调用方返回 400。
fn normalize_request_path(
    parts: &mut http::request::Parts,
    limits: &crate::config::model::ServerLimitsCfg,
) -> bool {
    let path = parts.uri.path();
    if limits.max_path_bytes > 0 && path.len() > limits.max_path_bytes {
        return false;
    }
    let repeated_slash = match scan_plain_path(path, limits.max_path_segments) {
        PlainPathScan::Valid { repeated_slash } => repeated_slash,
        PlainPathScan::Invalid => return false,
        PlainPathScan::Encoded => {
            // 编码 path 比普通路径少见，继续走经过完整回归的严格校验：segment 预算、非法
            // `%HH`、encoded slash/backslash/dot/NUL 与 `%25` 双重解码入口一个都不能跳过。
            if (limits.max_path_segments > 0
                && path
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .count()
                    > limits.max_path_segments)
                || !validate_path(path)
            {
                return false;
            }
            path.as_bytes().windows(2).any(|pair| pair == b"//")
        }
    };

    if !repeated_slash {
        return true;
    }

    let mut normalized = String::with_capacity(path.len());
    let mut previous_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if previous_slash {
                continue;
            }
            previous_slash = true;
        } else {
            previous_slash = false;
        }
        normalized.push(ch);
    }
    if normalized.is_empty() {
        normalized.push('/');
    }
    if let Some(query) = parts.uri.query() {
        // 在同一缓冲区追加 query，避免 `format!` 为规范化 URI 再复制一遍 path（§15.7）。
        normalized.reserve(1 + query.len());
        normalized.push('?');
        normalized.push_str(query);
    }
    let Ok(path_and_query) = normalized.parse::<http::uri::PathAndQuery>() else {
        return false;
    };
    let mut uri_parts = parts.uri.clone().into_parts();
    uri_parts.path_and_query = Some(path_and_query);
    match http::Uri::from_parts(uri_parts) {
        Ok(uri) => {
            parts.uri = uri;
            true
        }
        Err(_) => false,
    }
}

/// 普通未编码 path 的单遍安全扫描结果。
enum PlainPathScan {
    /// path 合法；同时返回是否需要合并重复 `/`。
    Valid { repeated_slash: bool },
    /// 发现 `%`，调用方必须回落到完整 percent-decoder 防护。
    Encoded,
    /// NUL、反斜杠、`.`/`..` segment 或 segment 预算超限。
    Invalid,
}

/// 对绝大多数无 percent encoding 的请求一次完成危险字节、dot segment、深度和重复 `/` 检查。
///
/// 这里只借用 URI 自带字节，不分配、不解码。非 ASCII UTF-8 原样属于普通 segment；看到 `%`
/// 立即返回 [`PlainPathScan::Encoded`]，由旧的严格验证器处理，避免性能分支重新实现安全语义。
fn scan_plain_path(path: &str, max_segments: usize) -> PlainPathScan {
    let bytes = path.as_bytes();
    let mut segment_start = 0;
    let mut segments = 0_usize;
    let mut repeated_slash = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            0 | b'\\' => return PlainPathScan::Invalid,
            b'%' => return PlainPathScan::Encoded,
            b'/' => {
                if index > segment_start {
                    let segment = &bytes[segment_start..index];
                    if segment == b"." || segment == b".." {
                        return PlainPathScan::Invalid;
                    }
                    segments += 1;
                    if max_segments > 0 && segments > max_segments {
                        return PlainPathScan::Invalid;
                    }
                }
                repeated_slash |= index > 0 && bytes[index - 1] == b'/';
                segment_start = index + 1;
            }
            _ => {}
        }
    }
    if segment_start < bytes.len() {
        let segment = &bytes[segment_start..];
        if segment == b"." || segment == b".." {
            return PlainPathScan::Invalid;
        }
        segments += 1;
        if max_segments > 0 && segments > max_segments {
            return PlainPathScan::Invalid;
        }
    }
    PlainPathScan::Valid { repeated_slash }
}

/// 校验 path 中不允许进入路由或上游的危险字符与 segment。
///
/// # 参数
/// - `path`: 尚未合并重复斜杠的原始 URI path（不含 query）。
///
/// 返回：满足单次解码与 segment 安全策略为 true；危险或非法编码为 false。
fn validate_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.iter().any(|b| *b == 0 || *b == b'\\') {
        return false;
    }
    for seg in path.split('/') {
        if seg == ".." || seg == "." || seg.eq_ignore_ascii_case("%2e") {
            return false;
        }
    }
    !contains_dangerous_percent_encoding(bytes)
}

/// 扫描一次 percent encoding，拒绝分隔符、dot、NUL 与可触发二次解码的 `%25`。
///
/// # 参数
/// - `bytes`: 原始 path 字节；非 ASCII UTF-8 字节原样跳过，仅解释 `%HH`。
///
/// 返回：发现危险/截断/非十六进制编码为 true，否则 false。
fn contains_dangerous_percent_encoding(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if i + 2 >= bytes.len() {
            return true;
        }
        let Some(hi) = hex(bytes[i + 1]) else {
            return true;
        };
        let Some(lo) = hex(bytes[i + 2]) else {
            return true;
        };
        match (hi << 4) | lo {
            // `%25` 会在二次解码后重新变成 `%`，可把 `%252e%252e`/`%252f` 伪装到上游。
            0x00 | 0x25 | 0x2f | 0x5c | 0x2e => return true,
            _ => i += 3,
        }
    }
    false
}

/// 把一个 ASCII 十六进制字符转成半字节。
///
/// # 参数
/// - `b`: 待解析的单个 path 字节。
///
/// 返回：合法 0-9/a-f/A-F 返回 0..15；其它字符返回 None。
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn too_large(parts: &http::request::Parts, max_body_bytes: u64) -> bool {
    if max_body_bytes == 0 {
        return false;
    }
    parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|len| len > max_body_bytes)
        .unwrap_or(false)
}

fn content_length_exceeds(parts: &Parts, max_body_bytes: usize) -> bool {
    parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > max_body_bytes as u64)
}

/// 有界读取 LLM JSON body。单 data frame 直接返回原 `Bytes`；只有第二帧出现才分配
/// `BytesMut` 并复制已有/后续 frame。Trailer 不属于统一 JSON 契约，明确拒绝而非静默丢弃。
async fn collect_llm_body(
    body: forward::ForwardBody,
    max_body_bytes: usize,
) -> Result<Bytes, LlmBodyError> {
    collect_llm_boxed_body(body, max_body_bytes).await
}

async fn collect_llm_boxed_body(
    mut body: BoxBody,
    max_body_bytes: usize,
) -> Result<Bytes, LlmBodyError> {
    let mut total = 0_usize;
    let mut single: Option<Bytes> = None;
    let mut merged: Option<BytesMut> = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            LlmBodyError::Invalid(anyhow::anyhow!("read LLM body frame: {error}"))
        })?;
        let data = frame.into_data().map_err(|_| {
            LlmBodyError::Invalid(anyhow::anyhow!("LLM JSON body cannot contain trailers"))
        })?;
        total = total
            .checked_add(data.len())
            .ok_or(LlmBodyError::TooLarge)?;
        if total > max_body_bytes {
            return Err(LlmBodyError::TooLarge);
        }
        if let Some(buffer) = merged.as_mut() {
            buffer.extend_from_slice(data.as_ref());
        } else if single.is_none() {
            single = Some(data);
        } else {
            let first = single.take().expect("single LLM frame was present");
            let mut buffer = BytesMut::with_capacity(total);
            buffer.extend_from_slice(first.as_ref());
            buffer.extend_from_slice(data.as_ref());
            merged = Some(buffer);
        }
    }
    Ok(merged.map(BytesMut::freeze).or(single).unwrap_or_default())
}

/// 在进入下一模型前最多排空 64KiB/250ms 的错误体。预算耗尽就 drop response，避免 fallback
/// 因不可信 5xx body 形成内存或延迟放大器。
async fn drain_llm_fallback_response(response: Response<BoxBody>) {
    const MAX_DRAIN_BYTES: usize = 64 * 1024;
    let (_, mut body) = response.into_parts();
    let _ = tokio::time::timeout(Duration::from_millis(250), async {
        let mut drained = 0_usize;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                break;
            };
            let Ok(data) = frame.into_data() else {
                break;
            };
            drained = drained.saturating_add(data.len());
            if drained > MAX_DRAIN_BYTES {
                break;
            }
        }
    })
    .await;
}

/// 业务作用：只在确认没有可计费 provider 成功结果时退回 LLM 保守预留，并保持失败时额度不被放大。
///
/// 参数说明：`reservation` 是当前请求尚未结算的可选后端绑定句柄。
///
/// 返回：无；存在句柄时消费并幂等退款，后端失败只记录错误且保留原扣减。
async fn refund_llm_reservation(reservation: &mut Option<RateLimitReservation>) {
    let Some(reservation) = reservation.take() else {
        return;
    };
    if let Err(error) = reservation.refund().await {
        tracing::warn!(%error, "LLM token quota refund failed; conservative reservation retained");
    }
}

/// 聚合有显式 16MiB 上限的 Anthropic 非流式 JSON，并保留原响应状态/version/extensions。
async fn convert_anthropic_response(
    response: Response<BoxBody>,
    max_response_bytes: usize,
) -> anyhow::Result<(Response<BoxBody>, Option<crate::llm::LlmUsage>, Bytes)> {
    let (mut parts, body) = response.into_parts();
    let body = collect_llm_boxed_body(body, max_response_bytes)
        .await
        .map_err(|error| match error {
            LlmBodyError::TooLarge => anyhow::anyhow!("Anthropic response exceeds limit"),
            LlmBodyError::Invalid(error) => error,
        })?;
    let (body, usage) = crate::llm::anthropic_response_to_openai(body.as_ref())?;
    parts.headers.remove(http::header::CONTENT_LENGTH);
    parts.headers.remove(http::header::CONTENT_ENCODING);
    parts.headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok((
        Response::from_parts(parts, full_body(body.clone())),
        Some(usage),
        body,
    ))
}

/// 业务作用：有界聚合 Google unary JSON，转换为统一响应并保留 provider 最终 usage 供配额结算。
///
/// 参数说明：`response` 是状态已确认成功的 Google provider 响应。
///
/// 返回：合法 text-only `GenerateContentResponse` 返回重建后的响应、可选 usage 与统一 body；超限或协议畸形返回错误且不向下游泄漏原 body。
async fn convert_google_response(
    response: Response<BoxBody>,
    max_response_bytes: usize,
) -> anyhow::Result<(Response<BoxBody>, Option<crate::llm::LlmUsage>, Bytes)> {
    let (mut parts, body) = response.into_parts();
    let body = collect_llm_boxed_body(body, max_response_bytes)
        .await
        .map_err(|error| match error {
            LlmBodyError::TooLarge => anyhow::anyhow!("Google response exceeds limit"),
            LlmBodyError::Invalid(error) => error,
        })?;
    let (body, usage) = crate::llm::google_response_to_openai(body.as_ref())?;
    parts.headers.remove(http::header::CONTENT_LENGTH);
    parts.headers.remove(http::header::CONTENT_ENCODING);
    parts.headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok((
        Response::from_parts(parts, full_body(body.clone())),
        usage,
        body,
    ))
}

/// OpenAI 非流式响应也做同一有界读取，读取真实 usage 后把原 `Bytes` 直接放回响应；单 frame
/// 情况不复制 payload。这样可观测与低拷贝边界同时成立。
async fn inspect_openai_response(
    response: Response<BoxBody>,
    max_response_bytes: usize,
) -> anyhow::Result<(Response<BoxBody>, Option<crate::llm::LlmUsage>, Bytes)> {
    let (mut parts, body) = response.into_parts();
    let body = collect_llm_boxed_body(body, max_response_bytes)
        .await
        .map_err(|error| match error {
            LlmBodyError::TooLarge => anyhow::anyhow!("OpenAI response exceeds limit"),
            LlmBodyError::Invalid(error) => error,
        })?;
    let usage = crate::llm::openai_usage(body.as_ref())?;
    parts.headers.remove(http::header::CONTENT_LENGTH);
    Ok((
        Response::from_parts(parts, full_body(body.clone())),
        usage,
        body,
    ))
}

/// 业务作用：有界聚合 provider 原生非流式响应而不改写其 usage、finish、tool 或多模态字段。
///
/// 参数说明：`response` 是成功的 provider 响应；`max_response_bytes` 是 route 冻结的累计字节门。
///
/// 返回：在预算内时原样重建响应并返回 body；超限或读取失败时返回错误且不泄漏部分实体。
async fn inspect_native_llm_response(
    response: Response<BoxBody>,
    max_response_bytes: usize,
) -> anyhow::Result<(Response<BoxBody>, Option<crate::llm::LlmUsage>, Bytes)> {
    let (mut parts, body) = response.into_parts();
    let body = collect_llm_boxed_body(body, max_response_bytes)
        .await
        .map_err(|error| match error {
            LlmBodyError::TooLarge => anyhow::anyhow!("native provider response exceeds limit"),
            LlmBodyError::Invalid(error) => error,
        })?;
    parts.headers.remove(http::header::CONTENT_LENGTH);
    Ok((
        Response::from_parts(parts, full_body(body.clone())),
        None,
        body,
    ))
}

fn llm_consumer_metric_label(route: &Route, parts: &Parts) -> String {
    let Some(consumer) = route.authenticated_consumer(parts) else {
        return "anonymous".to_string();
    };
    let digest = Sha256::digest(consumer.as_bytes());
    let mut encoded = String::with_capacity(16);
    use std::fmt::Write as _;
    for byte in &digest[..8] {
        write!(&mut encoded, "{byte:02x}").expect("writing SHA-256 hex to String cannot fail");
    }
    encoded
}

/// 从共享 cache entry 构造统一 JSON 响应。`Bytes::clone` 只增加引用计数；响应过滤/压缩在外层
/// 正常执行，因此缓存保存的是与真实 provider 路径一致的未压缩统一表示。
fn llm_cached_response(
    policy: &crate::llm::LlmRoutePolicy,
    entry: Arc<crate::llm::LlmCacheEntry>,
    cache_status: &'static str,
) -> Response<BoxBody> {
    match policy.blocked_response(entry.body.as_ref()) {
        Ok(true) => return text_status(403, "LLM response blocked by guardrail"),
        Err(_) => return text_status(502, "invalid LLM cached response"),
        Ok(false) => {}
    }
    let mut response = Response::new(full_body(entry.body.clone()));
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        "x-gateway-llm-model",
        HeaderValue::from_str(entry.model_id.as_ref())
            .expect("cached LLM model id was validated as an HTTP-safe ASCII token"),
    );
    response.headers_mut().insert(
        "x-gateway-llm-cache",
        HeaderValue::from_static(cache_status),
    );
    response
}

/// 流式 provider 共用的低基数 usage/cost 观测与原后端配额结算上下文。
struct LlmStreamAccounting {
    metrics: Arc<Metrics>,
    route: Arc<str>,
    model: Arc<str>,
    consumer: Arc<str>,
    input_cost_microusd_per_million: u64,
    output_cost_microusd_per_million: u64,
    reservation: Option<RateLimitReservation>,
}

/// 业务作用：为 provider 原生流附加累计字节、单帧与持续时间门，同时完全保留 frame 内容和顺序。
///
/// 参数说明：`response` 是已成功建立的原生流；`accounting` 持有保守配额预留；其余参数是 route
/// 构建期冻结的资源预算。
///
/// 返回：返回透明流式响应；任一预算越界时 body 产生错误并停止读取上游。
fn wrap_native_llm_stream_response(
    response: Response<BoxBody>,
    accounting: LlmStreamAccounting,
    max_response_bytes: usize,
    max_frame_bytes: usize,
    max_duration: Duration,
) -> Response<BoxBody> {
    response.map(|body| {
        NativeLlmStreamBody {
            inner: body,
            remaining: max_response_bytes,
            max_frame_bytes,
            deadline: Box::pin(tokio::time::sleep(max_duration)),
            done: false,
            _accounting: accounting,
        }
        .boxed()
    })
}

struct NativeLlmStreamBody {
    inner: BoxBody,
    remaining: usize,
    max_frame_bytes: usize,
    deadline: Pin<Box<Sleep>>,
    done: bool,
    _accounting: LlmStreamAccounting,
}

impl Body for NativeLlmStreamBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：逐帧保持 provider 原生 payload，同时在交付下游前执行三重流预算门。
    ///
    /// 参数说明：`cx` 是下游背压驱动的任务上下文。
    ///
    /// 返回：预算内原样返回 frame；超时、单帧或累计超限返回一次错误并终止流。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            self.done = true;
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "native LLM stream duration limit exceeded",
            )))));
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if data.len() > self.max_frame_bytes || data.len() > self.remaining {
                        self.done = true;
                        return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                            "native LLM stream byte limit exceeded",
                        )))));
                    }
                    self.remaining -= data.len();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：向下游暴露当前原生流是否已经终止，保持 Hyper 对 trailer 与连接复用的判断。
    ///
    /// 参数说明：无。
    ///
    /// 返回：本地预算门结束或内层 body 结束时为 true。
    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    /// 业务作用：透传上游大小提示并用 route 剩余预算收紧上界。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回不超过剩余累计字节预算的 SizeHint。
    fn size_hint(&self) -> SizeHint {
        let inner = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().min(self.remaining as u64));
        hint.set_upper(
            inner
                .upper()
                .unwrap_or(self.remaining as u64)
                .min(self.remaining as u64),
        );
        hint
    }
}

/// 业务作用：透明转发 OpenAI SSE，同时在有界窗口解析最终 usage 并结算绑定原后端的 reservation。
///
/// 参数说明：`response` 是成功的 OpenAI SSE；`accounting` 固化低基数观测、成本和结算事实。
///
/// 返回：返回保持原 DATA allocation/背压的响应；窗口异常停止观测但不破坏 provider 业务流。
fn wrap_openai_sse_usage_response(
    response: Response<BoxBody>,
    accounting: LlmStreamAccounting,
) -> Response<BoxBody> {
    let LlmStreamAccounting {
        metrics,
        route,
        model,
        consumer,
        input_cost_microusd_per_million,
        output_cost_microusd_per_million,
        reservation,
    } = accounting;
    response.map(|body| {
        OpenAiSseUsageBody {
            inner: Box::pin(body),
            pending: BytesMut::new(),
            inspection_enabled: true,
            usage_recorded: false,
            metrics,
            route,
            model,
            consumer,
            input_cost_microusd_per_million,
            output_cost_microusd_per_million,
            reservation,
        }
        .boxed()
    })
}

struct OpenAiSseUsageBody {
    inner: Pin<Box<BoxBody>>,
    pending: BytesMut,
    inspection_enabled: bool,
    usage_recorded: bool,
    metrics: Arc<Metrics>,
    route: Arc<str>,
    model: Arc<str>,
    consumer: Arc<str>,
    input_cost_microusd_per_million: u64,
    output_cost_microusd_per_million: u64,
    reservation: Option<RateLimitReservation>,
}

impl OpenAiSseUsageBody {
    fn inspect(&mut self, data: &[u8]) {
        const MAX_EVENT_BYTES: usize = 64 * 1024;
        if !self.inspection_enabled || self.usage_recorded {
            return;
        }
        if self.pending.len().saturating_add(data.len()) > MAX_EVENT_BYTES {
            self.pending.clear();
            self.inspection_enabled = false;
            return;
        }
        self.pending.extend_from_slice(data);
        while let Some((end, delimiter_len)) = sse_event_boundary(self.pending.as_ref()) {
            let event = self.pending.split_to(end + delimiter_len);
            let Ok(event) = std::str::from_utf8(&event[..end]) else {
                self.inspection_enabled = false;
                self.pending.clear();
                return;
            };
            for line in event.lines() {
                let Some(data) = line.trim_end_matches('\r').strip_prefix("data:") else {
                    continue;
                };
                let data = data.trim();
                if data == "[DONE]" {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<serde_json::Value>(data) else {
                    continue;
                };
                let Some(prompt_tokens) = value
                    .pointer("/usage/prompt_tokens")
                    .and_then(serde_json::Value::as_u64)
                else {
                    continue;
                };
                let Some(completion_tokens) = value
                    .pointer("/usage/completion_tokens")
                    .and_then(serde_json::Value::as_u64)
                else {
                    continue;
                };
                self.metrics.observe_llm_usage(
                    self.route.as_ref(),
                    self.model.as_ref(),
                    self.consumer.as_ref(),
                    prompt_tokens,
                    completion_tokens,
                    self.input_cost_microusd_per_million,
                    self.output_cost_microusd_per_million,
                );
                if let Some(reservation) = self.reservation.take() {
                    reservation.settle_spawn(prompt_tokens.saturating_add(completion_tokens));
                }
                self.usage_recorded = true;
                return;
            }
        }
    }
}

impl Body for OpenAiSseUsageBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    self.inspect(data.as_ref());
                    // 原 Bytes 原样返回；观测副本有界且不会改变 SSE 分帧/背压。
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 业务作用：把 Google `streamGenerateContent` SSE 在线转换为 OpenAI Chat Completions SSE，并保留下游背压。
///
/// 参数说明：`response` 是成功的 Google SSE 响应；`accounting` 固化低基数观测与原后端结算事实。
///
/// 返回：响应头改为统一 SSE，body 每次只缓存一个 64KiB 有界 event；协议错误通过 body error 失败闭合。
fn wrap_google_sse_response(
    response: Response<BoxBody>,
    accounting: LlmStreamAccounting,
) -> Response<BoxBody> {
    let LlmStreamAccounting {
        metrics,
        route,
        model,
        consumer,
        input_cost_microusd_per_million,
        output_cost_microusd_per_million,
        reservation,
    } = accounting;
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(http::header::CONTENT_LENGTH);
    parts.headers.remove(http::header::CONTENT_ENCODING);
    parts.headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    Response::from_parts(
        parts,
        GoogleSseBody {
            inner: Some(Box::pin(body)),
            pending: BytesMut::new(),
            trailers: None,
            provider_eof: false,
            done_sent: false,
            finish_seen: false,
            role_sent: false,
            response_id: Arc::from("google"),
            provider_model: model.clone(),
            pending_usage: None,
            usage_recorded: false,
            metrics,
            route,
            metric_model: model,
            consumer,
            input_cost_microusd_per_million,
            output_cost_microusd_per_million,
            reservation,
        }
        .boxed(),
    )
}

struct GoogleSseBody {
    inner: Option<Pin<Box<BoxBody>>>,
    pending: BytesMut,
    trailers: Option<http::HeaderMap>,
    provider_eof: bool,
    done_sent: bool,
    finish_seen: bool,
    role_sent: bool,
    response_id: Arc<str>,
    provider_model: Arc<str>,
    pending_usage: Option<crate::llm::LlmUsage>,
    usage_recorded: bool,
    metrics: Arc<Metrics>,
    route: Arc<str>,
    metric_model: Arc<str>,
    consumer: Arc<str>,
    input_cost_microusd_per_million: u64,
    output_cost_microusd_per_million: u64,
    reservation: Option<RateLimitReservation>,
}

impl GoogleSseBody {
    const MAX_EVENT_BYTES: usize = 64 * 1024;

    /// 业务作用：消费一个完整 Google SSE event，并生成至多一个统一 OpenAI chunk。
    ///
    /// 参数说明：无。
    ///
    /// 返回：event 尚不完整或只有 usage 时返回 None；text/finish 候选返回 chunk；安全拦截、非文本 part 与畸形 JSON 返回错误。
    fn convert_one(&mut self) -> anyhow::Result<Option<Bytes>> {
        let Some((end, delimiter_len)) = sse_event_boundary(self.pending.as_ref()) else {
            return Ok(None);
        };
        let event = self.pending.split_to(end + delimiter_len);
        let event = std::str::from_utf8(&event[..end]).context("Google SSE event is not UTF-8")?;
        let mut data = None;
        for line in event.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(value) = line.strip_prefix("data:") {
                if data.replace(value.trim()).is_some() {
                    anyhow::bail!("Google SSE event contains multiple data lines");
                }
            }
        }
        let Some(data) = data else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_str(data).context("Google SSE data is not JSON")?;
        if let Some(reason) = value
            .pointer("/promptFeedback/blockReason")
            .and_then(serde_json::Value::as_str)
        {
            anyhow::bail!("Google blocked streaming prompt with reason `{reason}`");
        }
        if let Some(id) = value.get("responseId").and_then(serde_json::Value::as_str) {
            self.response_id = Arc::from(id);
        }
        if let Some(model) = value
            .get("modelVersion")
            .and_then(serde_json::Value::as_str)
        {
            self.provider_model = Arc::from(model);
        }
        if let Some(usage) = crate::llm::google_usage(&value)? {
            self.pending_usage = Some(usage);
        }
        let Some(candidates) = value.get("candidates") else {
            if self.finish_seen {
                if let Some(usage) = self.pending_usage.take() {
                    self.record_usage(usage);
                }
            }
            return Ok(None);
        };
        let candidates = candidates
            .as_array()
            .context("Google SSE candidates must be an array")?;
        if candidates.len() > 1 {
            anyhow::bail!("Google streaming adapter received multiple candidates");
        }
        let Some(candidate) = candidates.first() else {
            return Ok(None);
        };
        let candidate = candidate
            .as_object()
            .context("Google SSE candidate must be an object")?;
        if candidate
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|index| index != 0)
        {
            anyhow::bail!("Google streaming candidate index must be zero");
        }
        let mut text = String::new();
        if let Some(parts) = candidate
            .get("content")
            .and_then(serde_json::Value::as_object)
            .and_then(|content| content.get("parts"))
        {
            for part in parts
                .as_array()
                .context("Google SSE content.parts must be an array")?
            {
                let part = part
                    .as_object()
                    .context("Google SSE candidate part must be an object")?;
                if part.len() != 1 || !part.contains_key("text") {
                    anyhow::bail!("Google SSE adapter received a non-text candidate part");
                }
                text.push_str(
                    part.get("text")
                        .and_then(serde_json::Value::as_str)
                        .context("Google SSE text part requires string text")?,
                );
            }
        }
        let finish = candidate
            .get("finishReason")
            .and_then(serde_json::Value::as_str);
        if finish.is_some() {
            self.finish_seen = true;
            if let Some(usage) = self.pending_usage.take() {
                self.record_usage(usage);
            }
        }
        if text.is_empty() && finish.is_none() && self.role_sent {
            return Ok(None);
        }
        let mut delta = serde_json::Map::new();
        if !self.role_sent {
            delta.insert(
                "role".to_string(),
                serde_json::Value::String("assistant".to_string()),
            );
            self.role_sent = true;
        }
        if !text.is_empty() {
            delta.insert("content".to_string(), serde_json::Value::String(text));
        }
        Ok(Some(openai_sse_chunk(
            self.response_id.as_ref(),
            self.provider_model.as_ref(),
            serde_json::Value::Object(delta),
            finish.map_or(serde_json::Value::Null, |reason| {
                serde_json::Value::String(
                    crate::llm::google_finish_reason(Some(reason)).to_string(),
                )
            }),
        )?))
    }

    /// 业务作用：把 Google 最终 usage 只记录一次，避免重复 SSE metadata 造成成本指标重复累计。
    ///
    /// 参数说明：`usage` 是完整解析的 provider token 事实。
    ///
    /// 返回：无；首次调用更新低基数 usage/cost 指标，重复调用不产生副作用。
    fn record_usage(&mut self, usage: crate::llm::LlmUsage) {
        if self.usage_recorded {
            return;
        }
        self.usage_recorded = true;
        self.metrics.observe_llm_usage(
            self.route.as_ref(),
            self.metric_model.as_ref(),
            self.consumer.as_ref(),
            usage.prompt_tokens,
            usage.completion_tokens,
            self.input_cost_microusd_per_million,
            self.output_cost_microusd_per_million,
        );
        if let Some(reservation) = self.reservation.take() {
            reservation.settle_spawn(usage.prompt_tokens.saturating_add(usage.completion_tokens));
        }
    }
}

impl Body for GoogleSseBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.provider_eof {
                if self.finish_seen && !self.done_sent {
                    self.done_sent = true;
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                        b"data: [DONE]\n\n",
                    )))));
                }
                if let Some(trailers) = self.trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                return Poll::Ready(None);
            }
            match self.convert_one() {
                Ok(Some(output)) => return Poll::Ready(Some(Ok(Frame::data(output)))),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        route = %self.route,
                        model = %self.metric_model,
                        %error,
                        "Google SSE response rejected; retain conservative usage reservation"
                    );
                    self.provider_eof = true;
                    self.finish_seen = false;
                    self.inner.take();
                    return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error.to_string(),
                    )))));
                }
            }
            let Some(inner) = self.inner.as_mut() else {
                self.provider_eof = true;
                continue;
            };
            match inner.as_mut().poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if self.pending.len().saturating_add(data.len()) > Self::MAX_EVENT_BYTES {
                            self.provider_eof = true;
                            self.finish_seen = false;
                            self.inner.take();
                            return Poll::Ready(Some(Err(llm_stream_error(
                                "Google SSE event exceeds 64KiB",
                            ))));
                        }
                        self.pending.extend_from_slice(data.as_ref());
                    }
                    Err(frame) => {
                        self.trailers = frame.into_trailers().ok();
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    self.provider_eof = true;
                    self.finish_seen = false;
                    self.inner.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.inner.take();
                    if !self.pending.iter().all(u8::is_ascii_whitespace) {
                        self.provider_eof = true;
                        self.finish_seen = false;
                        return Poll::Ready(Some(Err(llm_stream_error(
                            "Google SSE ended with an incomplete event",
                        ))));
                    }
                    if !self.finish_seen {
                        self.provider_eof = true;
                        return Poll::Ready(Some(Err(llm_stream_error(
                            "Google SSE ended before finishReason",
                        ))));
                    }
                    self.provider_eof = true;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.provider_eof && self.done_sent && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 业务作用：把 Anthropic Messages SSE 在线转换为 OpenAI Chat Completions SSE，并按最终 usage 结算。
///
/// 参数说明：`response` 是成功的 Anthropic SSE；`accounting` 固化低基数观测、成本和结算事实。
///
/// 返回：返回保持下游背压的转换响应；只缓存一个 64KiB event，trailers 在已转换事件后交付。
fn wrap_anthropic_sse_response(
    response: Response<BoxBody>,
    accounting: LlmStreamAccounting,
) -> Response<BoxBody> {
    let LlmStreamAccounting {
        metrics,
        route,
        model,
        consumer,
        input_cost_microusd_per_million,
        output_cost_microusd_per_million,
        reservation,
    } = accounting;
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(http::header::CONTENT_LENGTH);
    parts.headers.remove(http::header::CONTENT_ENCODING);
    parts.headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    Response::from_parts(
        parts,
        AnthropicSseBody {
            inner: Some(Box::pin(body)),
            pending: BytesMut::new(),
            trailers: None,
            done: false,
            message_id: Arc::from("anthropic"),
            provider_model: model.clone(),
            usage: crate::llm::LlmUsage::default(),
            usage_recorded: false,
            metrics,
            route,
            metric_model: model,
            consumer,
            input_cost_microusd_per_million,
            output_cost_microusd_per_million,
            reservation,
        }
        .boxed(),
    )
}

struct AnthropicSseBody {
    inner: Option<Pin<Box<BoxBody>>>,
    pending: BytesMut,
    trailers: Option<http::HeaderMap>,
    done: bool,
    message_id: Arc<str>,
    provider_model: Arc<str>,
    usage: crate::llm::LlmUsage,
    usage_recorded: bool,
    metrics: Arc<Metrics>,
    route: Arc<str>,
    metric_model: Arc<str>,
    consumer: Arc<str>,
    input_cost_microusd_per_million: u64,
    output_cost_microusd_per_million: u64,
    reservation: Option<RateLimitReservation>,
}

impl AnthropicSseBody {
    const MAX_EVENT_BYTES: usize = 64 * 1024;

    /// 消费 pending 中一个完整 SSE event。`Ok(None)` 表示只有 ping/边界事件，无下游输出。
    fn convert_one(&mut self) -> anyhow::Result<Option<Bytes>> {
        let Some((end, delimiter_len)) = sse_event_boundary(self.pending.as_ref()) else {
            return Ok(None);
        };
        let event = self.pending.split_to(end + delimiter_len);
        let event =
            std::str::from_utf8(&event[..end]).context("Anthropic SSE event is not UTF-8")?;
        let mut event_name = "message";
        let mut data = None;
        for line in event.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(value) = line.strip_prefix("event:") {
                event_name = value.trim();
            } else if let Some(value) = line.strip_prefix("data:") {
                // Anthropic 事件 JSON 是单 data line；重复 data line 明确拒绝，避免静默拼错 JSON。
                if data.replace(value.trim()).is_some() {
                    anyhow::bail!("Anthropic SSE event contains multiple data lines");
                }
            }
        }
        let Some(data) = data else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_str(data).context("Anthropic SSE data is not JSON")?;
        match event_name {
            "message_start" => {
                if let Some(id) = value
                    .pointer("/message/id")
                    .and_then(serde_json::Value::as_str)
                {
                    self.message_id = Arc::from(id);
                }
                if let Some(model) = value
                    .pointer("/message/model")
                    .and_then(serde_json::Value::as_str)
                {
                    self.provider_model = Arc::from(model);
                }
                self.usage.prompt_tokens = value
                    .pointer("/message/usage/input_tokens")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                Ok(Some(openai_sse_chunk(
                    self.message_id.as_ref(),
                    self.provider_model.as_ref(),
                    serde_json::json!({"role":"assistant"}),
                    serde_json::Value::Null,
                )?))
            }
            "content_block_start" => {
                if value
                    .pointer("/content_block/type")
                    .and_then(serde_json::Value::as_str)
                    != Some("text")
                {
                    anyhow::bail!(
                        "Anthropic SSE adapter cannot losslessly represent non-text content block"
                    );
                }
                Ok(None)
            }
            "content_block_delta" => {
                if value
                    .pointer("/delta/type")
                    .and_then(serde_json::Value::as_str)
                    != Some("text_delta")
                {
                    anyhow::bail!(
                        "Anthropic SSE adapter cannot losslessly represent non-text delta"
                    );
                }
                let Some(text) = value
                    .pointer("/delta/text")
                    .and_then(serde_json::Value::as_str)
                else {
                    return Ok(None);
                };
                Ok(Some(openai_sse_chunk(
                    self.message_id.as_ref(),
                    self.provider_model.as_ref(),
                    serde_json::json!({"content":text}),
                    serde_json::Value::Null,
                )?))
            }
            "message_delta" => {
                self.usage.completion_tokens = value
                    .pointer("/usage/output_tokens")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(self.usage.completion_tokens);
                let finish = match value
                    .pointer("/delta/stop_reason")
                    .and_then(serde_json::Value::as_str)
                {
                    Some("max_tokens") => "length",
                    Some("tool_use") => {
                        anyhow::bail!("Anthropic SSE adapter cannot losslessly represent tool_use")
                    }
                    _ => "stop",
                };
                Ok(Some(openai_sse_chunk(
                    self.message_id.as_ref(),
                    self.provider_model.as_ref(),
                    serde_json::json!({}),
                    serde_json::Value::String(finish.to_string()),
                )?))
            }
            "message_stop" => {
                self.record_usage();
                self.done = true;
                Ok(Some(Bytes::from_static(b"data: [DONE]\n\n")))
            }
            "error" => anyhow::bail!("Anthropic SSE provider emitted error event"),
            "ping" | "content_block_stop" => Ok(None),
            _ => anyhow::bail!("Anthropic SSE provider emitted unsupported event"),
        }
    }

    fn record_usage(&mut self) {
        if self.usage_recorded {
            return;
        }
        self.usage_recorded = true;
        self.metrics.observe_llm_usage(
            self.route.as_ref(),
            self.metric_model.as_ref(),
            self.consumer.as_ref(),
            self.usage.prompt_tokens,
            self.usage.completion_tokens,
            self.input_cost_microusd_per_million,
            self.output_cost_microusd_per_million,
        );
        if let Some(reservation) = self.reservation.take() {
            reservation.settle_spawn(
                self.usage
                    .prompt_tokens
                    .saturating_add(self.usage.completion_tokens),
            );
        }
    }
}

impl Body for AnthropicSseBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.done {
                if let Some(trailers) = self.trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                self.inner.take();
                return Poll::Ready(None);
            }
            match self.convert_one() {
                Ok(Some(output)) => return Poll::Ready(Some(Ok(Frame::data(output)))),
                Ok(None) => {}
                Err(error) => {
                    self.done = true;
                    self.inner.take();
                    return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error.to_string(),
                    )))));
                }
            }
            let Some(inner) = self.inner.as_mut() else {
                self.done = true;
                continue;
            };
            match inner.as_mut().poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if self.pending.len().saturating_add(data.len()) > Self::MAX_EVENT_BYTES {
                            self.done = true;
                            self.inner.take();
                            return Poll::Ready(Some(Err(llm_stream_error(
                                "Anthropic SSE event exceeds 64KiB",
                            ))));
                        }
                        // 协议转换需要跨 frame 拼一个 event；只在这个显式流式慢路径复制当前
                        // 未完成 event，窗口硬限 64KiB，完成后立即 split/reuse allocation。
                        self.pending.extend_from_slice(data.as_ref());
                    }
                    Err(frame) => {
                        self.trailers = frame.into_trailers().ok();
                        self.inner.take();
                        if self.pending.iter().all(u8::is_ascii_whitespace) {
                            self.done = true;
                        } else {
                            return Poll::Ready(Some(Err(llm_stream_error(
                                "Anthropic SSE ended with an incomplete event",
                            ))));
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    self.inner.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.inner.take();
                    if self.pending.iter().all(u8::is_ascii_whitespace) {
                        self.done = true;
                        return Poll::Ready(Some(Err(llm_stream_error(
                            "Anthropic SSE ended before message_stop",
                        ))));
                    } else {
                        self.done = true;
                        return Poll::Ready(Some(Err(llm_stream_error(
                            "Anthropic SSE ended with an incomplete event",
                        ))));
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn sse_event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    for index in 0..bytes.len() {
        if bytes[index..].starts_with(b"\n\n") {
            return Some((index, 2));
        }
        if bytes[index..].starts_with(b"\r\n\r\n") {
            return Some((index, 4));
        }
    }
    None
}

fn openai_sse_chunk(
    id: &str,
    model: &str,
    delta: serde_json::Value,
    finish_reason: serde_json::Value,
) -> anyhow::Result<Bytes> {
    let value = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        "model": model,
        "choices": [{"index":0,"delta":delta,"finish_reason":finish_reason}],
    });
    let json = serde_json::to_vec(&value).context("encode OpenAI SSE chunk")?;
    let mut output = Vec::with_capacity(6 + json.len() + 2);
    output.extend_from_slice(b"data: ");
    output.extend_from_slice(&json);
    output.extend_from_slice(b"\n\n");
    Ok(Bytes::from(output))
}

fn llm_stream_error(message: &'static str) -> crate::BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

/// 执行已在快照构建期编译的 Casbin 决策。
///
/// consumer 来自 ext_authz 之前冻结的本地认证结果；header 参数即使被显式配置，
/// 也只是 ABAC 的不可信请求属性，不会升级为 principal。
fn enforce_casbin_authorization(
    route: &Route,
    parts: &Parts,
    authenticated: bool,
    consumer: Option<&str>,
    client_ip: IpAddr,
    scheme: &str,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let policy = route.casbin_authorization.as_ref()?;
    match policy.enforce(
        parts,
        authenticated,
        consumer,
        route.id.as_str(),
        client_ip,
        scheme,
    ) {
        Ok(CasbinDecision::Allow) => {
            metrics.inc_casbin_decision(CasbinDecisionMetric::Allow);
            None
        }
        Ok(CasbinDecision::Deny) => {
            metrics.inc_casbin_decision(CasbinDecisionMetric::Deny);
            Some(text_status(403, "forbidden by Casbin policy"))
        }
        Ok(CasbinDecision::Error(error)) if policy.fail_open() => {
            metrics.inc_casbin_decision(CasbinDecisionMetric::FailOpen);
            tracing::warn!(route = %route.id, %error, "Casbin enforcement failed open");
            None
        }
        Ok(CasbinDecision::Error(error)) => {
            metrics.inc_casbin_decision(CasbinDecisionMetric::Error);
            tracing::warn!(route = %route.id, %error, "Casbin enforcement failed closed");
            Some(text_status(500, "Casbin policy evaluation failed"))
        }
        Err(CasbinInputError::MissingIdentity) => {
            metrics.inc_casbin_decision(CasbinDecisionMetric::InvalidInput);
            Some(text_status(403, "authenticated identity required"))
        }
        Err(CasbinInputError::TooLarge | CasbinInputError::InvalidHeader) => {
            metrics.inc_casbin_decision(CasbinDecisionMetric::InvalidInput);
            Some(text_status(
                431,
                "Casbin authorization input too large or invalid",
            ))
        }
    }
}

/// 执行 V7 Proxy-Wasm request head 链，并在成功后为 response phase 捕获请求 head。
///
/// 业务作用：在上游转发前提交沙箱插件的原子 head 变更，并为后续 response phase 保存
/// 有界请求快照；任何 fail-closed 错误都在进入上游前终止。
///
/// 失败模式是 plugin 级的：fail-open 已在沙箱链内丢弃该 plugin 的未提交变更；
/// 能到达这里的 `Err` 必定是 fail-closed，因此返回 500，不让未执行的安全插件被绕过。
async fn enforce_wasm_request_headers(
    route: &Route,
    parts: &mut Parts,
    scheme: &str,
    end_of_stream: bool,
    response_snapshot: &mut Option<Box<crate::wasm::WasmRequestHeadSnapshot>>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(chain) = &route.wasm_plugins else {
        return None;
    };
    match chain.execute_request(parts, scheme, end_of_stream).await {
        Ok(execution) => {
            for _ in 0..execution.failed_open {
                metrics.inc_wasm_execution(WasmExecutionMetric::FailOpen);
            }
            if let Some(local) = execution.local_response {
                metrics.inc_wasm_execution(WasmExecutionMetric::LocalResponse);
                Some(local)
            } else {
                metrics.inc_wasm_execution(WasmExecutionMetric::Continue);
                *response_snapshot = chain.capture_request_head(parts, scheme).map(Box::new);
                None
            }
        }
        Err(error) => {
            metrics.inc_wasm_execution(WasmExecutionMetric::Error);
            tracing::warn!(route = %route.id, %error, "Proxy-Wasm request plugin failed closed");
            Some(text_status(500, "Proxy-Wasm request plugin failed"))
        }
    }
}

/// 业务作用：只为显式配置标准 SAML HTTP-POST binding 的 route 有界读取 form，并保留原请求体。
///
/// 参数说明：`route` 提供构建期协议上限，`parts` 用于核对 POST/media type/声明长度，`body` 是
/// 请求体唯一所有权槽。
///
/// 业务作用：为 HMAC body hash 与 ext_authz body 转发只执行一次有界聚合，并把原字节和 trailers 放回主链。
///
/// 参数说明：`route` 决定是否启用及共同上限；`parts` 用于提前拒绝已知超长实体；`body` 是请求体所有权槽。
///
/// 返回：未启用返回 None；成功返回共享原始字节并恢复可重放 body；超限或读取失败返回本地拒绝响应。
async fn collect_auth_body(
    route: &Route,
    parts: &Parts,
    body: &mut Option<forward::ForwardBody>,
) -> Result<Option<Bytes>, Response<BoxBody>> {
    let Some(limit) = route.auth_body_limit() else {
        return Ok(None);
    };
    if too_large(parts, limit) {
        return Err(text_status(
            413,
            "authentication body exceeds configured limit",
        ));
    }
    let current = body
        .take()
        .expect("body authentication owns the request body before later body phases");
    let collected = match crate::proxy::request_validation::collect_bounded(current, limit).await {
        Ok(collected) => collected,
        Err(crate::proxy::request_validation::CollectError::TooLarge) => {
            return Err(text_status(
                413,
                "authentication body exceeds configured limit",
            ));
        }
        Err(crate::proxy::request_validation::CollectError::Read) => {
            return Err(text_status(400, "authentication body read failed"));
        }
    };
    let bytes = collected.bytes.clone();
    *body = Some(crate::proxy::request_validation::buffered_body(collected));
    Ok(Some(bytes))
}

/// 返回：没有适用 form 时返回 None；唯一 `SAMLResponse` 返回解码文本且 body 原样放回；超限、
/// 读取失败或重复凭据返回本地拒绝响应。
async fn extract_saml_post_response(
    route: &Route,
    parts: &Parts,
    body: &mut Option<forward::ForwardBody>,
) -> Result<Option<String>, Response<BoxBody>> {
    let Some(max_form_bytes) = route.saml_form_body_limit() else {
        return Ok(None);
    };
    let is_form_post = parts.method == Method::POST
        && parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| {
                value
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
    if !is_form_post {
        return Ok(None);
    }
    let max_form_bytes = u64::try_from(max_form_bytes).unwrap_or(u64::MAX);
    if too_large(parts, max_form_bytes) {
        return Err(text_status(413, "SAML form exceeds configured limit"));
    }
    let current = body
        .take()
        .expect("SAML authentication owns the request body before other body phases");
    let collected =
        match crate::proxy::request_validation::collect_bounded(current, max_form_bytes).await {
            Ok(collected) => collected,
            Err(crate::proxy::request_validation::CollectError::TooLarge) => {
                return Err(text_status(413, "SAML form exceeds configured limit"));
            }
            Err(crate::proxy::request_validation::CollectError::Read) => {
                return Err(text_status(400, "invalid SAML form body"));
            }
        };
    let bytes = collected.bytes.clone();
    *body = Some(crate::proxy::request_validation::buffered_body(collected));
    let mut response = None;
    for (name, value) in form_urlencoded::parse(bytes.as_ref()) {
        if name != "SAMLResponse" {
            continue;
        }
        if response.replace(value.into_owned()).is_some() {
            return Err(text_status(400, "duplicate SAMLResponse form field"));
        }
    }
    Ok(response)
}

struct WasmCollectedBody {
    bytes: Bytes,
    trailers: Option<http::HeaderMap>,
}

enum WasmBodyError {
    TooLarge,
    Read(anyhow::Error),
}

/// 业务作用：显式选择 request_body phase 时有界收集 body、执行插件并重建可转发 body。
///
/// 参数说明：`route`/`parts` 是当前路由与请求 head，`body` 是唯一所有权槽，`scheme` 是可信入口协议，
/// `response_snapshot` 保存 body 插件提交后的请求视图，`metrics` 记录每 phase 结果。
///
/// 返回：继续转发返回 `None` 并把 body 放回；local response、超限或 fail-closed 返回响应且不留半完成 body。
async fn enforce_wasm_request_body(
    route: &Route,
    parts: &mut Parts,
    body: &mut Option<forward::ForwardBody>,
    scheme: &str,
    response_snapshot: &mut Option<Box<crate::wasm::WasmRequestHeadSnapshot>>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(chain) = &route.wasm_plugins else {
        return None;
    };
    if chain.has_request_body_stream() {
        let current = body
            .take()
            .expect("request body is owned exactly once by Wasm/validation/forward pipeline");
        return match chain.wrap_request_body_stream(parts, current, scheme).await {
            Ok(stream) => {
                *body = Some(stream);
                *response_snapshot = chain.capture_request_head(parts, scheme).map(Box::new);
                None
            }
            Err(error) => {
                metrics.inc_wasm_execution(WasmExecutionMetric::Error);
                tracing::warn!(route = %route.id, %error, "Proxy-Wasm request streaming lifecycle failed closed");
                Some(text_status(
                    500,
                    "Proxy-Wasm request streaming plugin failed",
                ))
            }
        };
    }
    if !chain.has_request_body() {
        return None;
    }
    let current = body
        .take()
        .expect("request body is owned exactly once by Wasm/validation/forward pipeline");
    let collected = match collect_wasm_forward_body(current, chain.request_body_limit()).await {
        Ok(collected) => collected,
        Err(WasmBodyError::TooLarge) => {
            metrics.inc_wasm_execution(WasmExecutionMetric::Error);
            return Some(text_status(413, "Proxy-Wasm request body exceeds limit"));
        }
        Err(WasmBodyError::Read(error)) => {
            metrics.inc_wasm_execution(WasmExecutionMetric::Error);
            tracing::warn!(route = %route.id, %error, "read Proxy-Wasm request body failed");
            return Some(text_status(400, "invalid request body"));
        }
    };
    match chain
        .execute_request_body(parts, collected.bytes, scheme)
        .await
    {
        Ok(execution) => {
            for _ in 0..execution.failed_open {
                metrics.inc_wasm_execution(WasmExecutionMetric::FailOpen);
            }
            if let Some(local) = execution.local_response {
                metrics.inc_wasm_execution(WasmExecutionMetric::LocalResponse);
                Some(local)
            } else {
                metrics.inc_wasm_execution(WasmExecutionMetric::Continue);
                let bytes = execution.body.unwrap_or_default();
                normalize_content_length(&mut parts.headers, bytes.len());
                *body = Some(replay_wasm_body(bytes, collected.trailers));
                *response_snapshot = chain.capture_request_head(parts, scheme).map(Box::new);
                None
            }
        }
        Err(error) => {
            metrics.inc_wasm_execution(WasmExecutionMetric::Error);
            tracing::warn!(route = %route.id, %error, "Proxy-Wasm request body plugin failed closed");
            Some(text_status(500, "Proxy-Wasm request body plugin failed"))
        }
    }
}

/// 业务作用：把 Incoming/BoxBody 统一转换为有界 frame 收集器，同时保留合法 trailers。
///
/// 参数说明：`body` 是请求体唯一所有权，`max_body_bytes` 是 route 插件链显式聚合上限。
///
/// 返回：成功返回 data 与最多一份 trailers；越界或读取失败分类返回。
async fn collect_wasm_forward_body(
    body: forward::ForwardBody,
    max_body_bytes: usize,
) -> Result<WasmCollectedBody, WasmBodyError> {
    collect_wasm_box_body(body, max_body_bytes).await
}

/// 业务作用：逐 frame 收集 Proxy-Wasm body，在复制下一片前执行累计字节硬门并保留 trailers。
///
/// 参数说明：`body` 是统一 boxed body，`max_body_bytes` 为非零聚合上限。
///
/// 返回：单 data frame 保持原 Bytes；多 frame 才合并；多份 trailers 或读错返回 Read。
async fn collect_wasm_box_body(
    mut body: BoxBody,
    max_body_bytes: usize,
) -> Result<WasmCollectedBody, WasmBodyError> {
    let mut total = 0usize;
    let mut single: Option<Bytes> = None;
    let mut merged: Option<BytesMut> = None;
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            WasmBodyError::Read(anyhow::anyhow!("read Proxy-Wasm body frame: {error}"))
        })?;
        if frame.is_data() {
            let data = frame
                .into_data()
                .expect("is_data guarantees data conversion");
            total = total
                .checked_add(data.len())
                .ok_or(WasmBodyError::TooLarge)?;
            if total > max_body_bytes {
                return Err(WasmBodyError::TooLarge);
            }
            if let Some(buffer) = merged.as_mut() {
                buffer.extend_from_slice(&data);
            } else if single.is_none() {
                single = Some(data);
            } else {
                let first = single.take().expect("single frame existed");
                let mut buffer = BytesMut::with_capacity(total);
                buffer.extend_from_slice(&first);
                buffer.extend_from_slice(&data);
                merged = Some(buffer);
            }
        } else if frame.is_trailers() {
            if trailers.is_some() {
                return Err(WasmBodyError::Read(anyhow::anyhow!(
                    "Proxy-Wasm body contains multiple trailer frames"
                )));
            }
            trailers = frame.into_trailers().ok();
        }
    }
    Ok(WasmCollectedBody {
        bytes: merged.map(BytesMut::freeze).or(single).unwrap_or_default(),
        trailers,
    })
}

#[cfg(feature = "ext-proc")]
/// 业务作用：为 External Processing request_headers 补齐下游 scheme/authority，使标准处理器收到
/// 完整伪头，同时不信任任何处理器返回的目标重写。
///
/// 参数说明：`parts` 是当前请求 head；`scheme` 来自已建立的 listener transport。
///
/// 返回：Host 合法时返回 absolute URI；缺失或非法时保留原 URI，由普通请求校验继续裁决。
fn ext_proc_request_uri(parts: &Parts, scheme: &'static str) -> http::Uri {
    if parts.uri.scheme().is_some() && parts.uri.authority().is_some() {
        return parts.uri.clone();
    }
    let Some(authority) = parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return parts.uri.clone();
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |value| value.as_str());
    format!("{scheme}://{authority}{path}")
        .parse()
        .unwrap_or_else(|_| parts.uri.clone())
}

#[cfg(feature = "ext-proc")]
/// 业务作用：把 STREAMED body 逐 DATA frame 送入同一 External Processing 流，并用容量为一的
/// channel 把处理器响应背压传回 HTTP 管线；trailers 保持末尾顺序且可独立变更。
///
/// 参数说明：`body` 是当前方向唯一所有权；`session` 共享双向协议状态；`phase` 固定方向；
/// `send_trailers` 控制 trailer phase；`max_body_bytes` 限制输入和处理后输出；`finish` 表示流末关闭。
///
/// 返回：可继续流式消费的 BoxBody；协议、越权和 fail-closed 依赖错误通过 body error 终止连接。
fn wrap_ext_proc_body(
    mut body: BoxBody,
    session: SharedExtProcSession,
    phase: ExtProcPhase,
    send_trailers: bool,
    max_body_bytes: usize,
    finish: bool,
) -> BoxBody {
    let (mut sender, output) = http_body_util::channel::Channel::<Bytes, crate::BoxError>::new(1);
    tokio::spawn(async move {
        let mut input_total = 0usize;
        let mut output_total = 0usize;
        let mut pending: Option<Bytes> = None;
        let mut saw_trailers = false;
        while let Some(frame) = body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => {
                    sender.abort(error);
                    return;
                }
            };
            if frame.is_data() {
                if saw_trailers {
                    sender.abort(Box::new(std::io::Error::other(
                        "body data appeared after trailers",
                    )));
                    return;
                }
                let data = frame
                    .into_data()
                    .expect("is_data guarantees data conversion");
                input_total = match input_total.checked_add(data.len()) {
                    Some(total) if total <= max_body_bytes => total,
                    _ => {
                        sender.abort(Box::new(std::io::Error::other(
                            "external processor streamed body exceeds limit",
                        )));
                        return;
                    }
                };
                if let Some(previous) = pending.replace(data) {
                    match process_ext_proc_stream_data(&session, phase, previous, false).await {
                        Ok(Some(processed)) => {
                            output_total = match output_total.checked_add(processed.len()) {
                                Some(total) if total <= max_body_bytes => total,
                                _ => {
                                    sender.abort(Box::new(std::io::Error::other(
                                        "external processor streamed output exceeds limit",
                                    )));
                                    return;
                                }
                            };
                            if sender.send_data(processed).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => {
                            sender.abort(Box::new(std::io::Error::other(
                                "external processor selected an immediate response",
                            )));
                            return;
                        }
                        Err(error) => {
                            sender.abort(Box::new(error));
                            return;
                        }
                    }
                }
            } else if frame.is_trailers() {
                if saw_trailers {
                    sender.abort(Box::new(std::io::Error::other(
                        "multiple trailer frames are not allowed",
                    )));
                    return;
                }
                saw_trailers = true;
                let mut trailers = frame
                    .into_trailers()
                    .expect("is_trailers guarantees trailer conversion");
                if let Some(previous) = pending.take() {
                    match process_ext_proc_stream_data(&session, phase, previous, false).await {
                        Ok(Some(processed)) => {
                            output_total = match output_total.checked_add(processed.len()) {
                                Some(total) if total <= max_body_bytes => total,
                                _ => {
                                    sender.abort(Box::new(std::io::Error::other(
                                        "external processor streamed output exceeds limit",
                                    )));
                                    return;
                                }
                            };
                            if sender.send_data(processed).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => {
                            sender.abort(Box::new(std::io::Error::other(
                                "external processor selected an immediate response",
                            )));
                            return;
                        }
                        Err(error) => {
                            sender.abort(Box::new(error));
                            return;
                        }
                    }
                }
                if send_trailers {
                    let trailer_phase = match phase {
                        ExtProcPhase::RequestBody => ExtProcPhase::RequestTrailers,
                        ExtProcPhase::ResponseBody => ExtProcPhase::ResponseTrailers,
                        _ => {
                            sender.abort(Box::new(std::io::Error::other(
                                "invalid external processor streamed phase",
                            )));
                            return;
                        }
                    };
                    if let Err(error) =
                        process_ext_proc_stream_trailers(&session, trailer_phase, &mut trailers)
                            .await
                    {
                        sender.abort(Box::new(error));
                        return;
                    }
                }
                if sender.send_trailers(trailers).await.is_err() {
                    return;
                }
            }
        }
        if !saw_trailers {
            let final_chunk = pending.take().unwrap_or_default();
            match process_ext_proc_stream_data(&session, phase, final_chunk, true).await {
                Ok(Some(processed)) => {
                    if output_total
                        .checked_add(processed.len())
                        .is_none_or(|total| total > max_body_bytes)
                    {
                        sender.abort(Box::new(std::io::Error::other(
                            "external processor streamed output exceeds limit",
                        )));
                        return;
                    }
                    if !processed.is_empty() && sender.send_data(processed).await.is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    sender.abort(Box::new(std::io::Error::other(
                        "external processor selected an immediate response",
                    )));
                    return;
                }
                Err(error) => {
                    sender.abort(Box::new(error));
                    return;
                }
            }
        }
        if finish {
            session.lock().await.finish();
        }
    });
    output.boxed()
}

#[cfg(feature = "ext-proc")]
/// 业务作用：处理一个 streamed DATA chunk，并把依赖 fail-open 精确降级为原 chunk 透传。
///
/// 参数说明：共享会话、body phase、原始 chunk 与 end_of_stream 标志均来自 wrapper 的有序状态机。
///
/// 返回：Some 为应发送 chunk；None 表示已登记即时响应；fail-closed 错误终止 body。
async fn process_ext_proc_stream_data(
    session: &SharedExtProcSession,
    phase: ExtProcPhase,
    original: Bytes,
    end_of_stream: bool,
) -> Result<Option<Bytes>, ExtProcError> {
    let mut state = session.lock().await;
    if state.bypassed() {
        return Ok(Some(original));
    }
    match state
        .process(phase, None, Some((&original, end_of_stream)), None)
        .await
    {
        Ok(ExtProcAction::Continue(changes)) => Ok(Some(changes.apply_body(original))),
        Ok(ExtProcAction::Immediate(response)) => {
            state.set_pending_immediate(response)?;
            Ok(None)
        }
        Err(error) if state.apply_failure(&error) => Ok(Some(original)),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "ext-proc")]
/// 业务作用：处理 streamed body 末尾 trailers，并保证依赖 fail-open 时原 trailers 不变。
///
/// 参数说明：`session` 是同一协议流；`phase` 固定 trailer 方向；`trailers` 原子承接已验证 delta。
///
/// 返回：成功或允许绕过返回 Ok；即时响应、协议错序和 fail-closed 依赖返回错误。
async fn process_ext_proc_stream_trailers(
    session: &SharedExtProcSession,
    phase: ExtProcPhase,
    trailers: &mut HeaderMap,
) -> Result<(), ExtProcError> {
    let mut state = session.lock().await;
    if state.bypassed() {
        return Ok(());
    }
    match state.process(phase, None, None, Some(trailers)).await {
        Ok(ExtProcAction::Continue(changes)) => {
            changes.apply_headers(trailers);
            Ok(())
        }
        Ok(ExtProcAction::Immediate(response)) => {
            state.set_pending_immediate(response)?;
            Err(ExtProcError::protocol(anyhow::anyhow!(
                "ext_proc immediate response stopped streamed trailers"
            )))
        }
        Err(error) if state.apply_failure(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

/// 业务作用：把插件处理后的完整 data 与原 trailers 重建成有界下游/上游 body。
///
/// 参数说明：`bytes` 是最终 data，`trailers` 是收集时保留的单份 trailers。
///
/// 返回：无 trailers 时返回零额外流对象的 full body；有 trailers 时按 data→trailers 顺序重放。
fn replay_wasm_body(bytes: Bytes, trailers: Option<http::HeaderMap>) -> BoxBody {
    let Some(trailers) = trailers else {
        return full_body(bytes);
    };
    let frames: Vec<Result<Frame<Bytes>, crate::BoxError>> =
        vec![Ok(Frame::data(bytes)), Ok(Frame::trailers(trailers))];
    BodyExt::boxed(http_body_util::StreamBody::new(futures::stream::iter(
        frames,
    )))
}

/// 业务作用：body phase 可能改写长度，提交前重建唯一可信 Content-Length，避免上游/下游读半帧。
///
/// 参数说明：`headers` 是当前 head，`length` 是最终 data 字节数（不含 trailers）。
///
/// 返回：无返回值；旧 Content-Length 被原子覆盖。
fn normalize_content_length(headers: &mut http::HeaderMap, length: usize) {
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, value);
    } else {
        headers.remove(http::header::CONTENT_LENGTH);
    }
}

/// 业务作用：body 被遮蔽后删除已不再对应最终实体的摘要、validator 与 range header。
///
/// 参数说明：`headers` 是请求或响应 head。
///
/// 返回：无；只移除固定 body 完整性与范围字段，调用方随后写入新的 Content-Length。
fn strip_body_integrity_headers(headers: &mut http::HeaderMap) {
    for name in [
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "etag",
        "content-range",
        "accept-ranges",
    ] {
        headers.remove(name);
    }
}

/// 业务作用：执行 route WAF 的请求行/header 门禁，在昂贵认证与外部调用前短路确定攻击输入。
///
/// 参数说明：
/// - `route`：当前已匹配 route。
/// - `parts`：尚未交给插件改写的原始请求 head。
/// - `metrics`：共享低基数指标。
///
/// 返回：enforce 模式命中时返回 403；monitor 或未命中返回 `None` 并继续主管线。
fn enforce_waf_head(route: &Route, parts: &Parts, metrics: &Metrics) -> Option<Response<BoxBody>> {
    let policy = route.waf.as_ref()?;
    let matched = policy.inspect_head(parts)?;
    if policy.enforces() {
        // WAF 拒绝必须发生在任何上游、插件和缓存副作用之前，避免恶意输入穿过部分管线。
        metrics.inc_waf(WafMetric::Blocked);
        tracing::warn!(
            route = %route.id,
            rule = %matched.rule,
            target = %matched.target,
            "request blocked by WAF"
        );
        Some(text_status(403, "request blocked by WAF"))
    } else {
        metrics.inc_waf(WafMetric::Monitored);
        tracing::warn!(
            route = %route.id,
            rule = %matched.rule,
            target = %matched.target,
            "request matched WAF monitor rule"
        );
        None
    }
}

/// 业务作用：用 listener 已验证的客户端 IP 执行 route 国家、ASN 与匿名网络门禁。
///
/// 参数说明：
/// - `route`：当前已匹配 route。
/// - `client_ip`：经 trusted-proxy 规则确定的权威客户端地址。
/// - `metrics`：共享低基数指标。
///
/// 返回：策略拒绝时返回 403；允许或未配置时返回 `None`，且日志不包含 IP、国家或 ASN。
fn enforce_geoip(route: &Route, client_ip: IpAddr, metrics: &Metrics) -> Option<Response<BoxBody>> {
    let policy = route.geoip.as_ref()?;
    let decision = policy.evaluate(client_ip);
    metrics.inc_geoip(decision);
    if decision.allowed() {
        if decision.reason() != "allowed" {
            tracing::warn!(
                route = %route.id,
                reason = decision.reason(),
                "GeoIP policy explicitly allowed an incomplete lookup"
            );
        }
        None
    } else {
        // GeoIP 拒绝发生在认证、插件和上游副作用之前，且不得用客户端自报位置覆盖。
        tracing::warn!(
            route = %route.id,
            reason = decision.reason(),
            "request denied by GeoIP policy"
        );
        Some(text_status(403, "request denied by GeoIP policy"))
    }
}

/// 业务作用：在认证、插件和上游副作用前执行浏览器来源与 CSRF token 双门禁。
///
/// 参数说明：`route` 是已匹配路由；`parts` 是请求 head；`downstream_scheme` 来自 listener；
/// `metrics` 是共享低基数指标。
///
/// 返回：enforce 拒绝时返回 403；安全方法、验证通过、monitor 或未配置时返回 `None`。
fn enforce_csrf(
    route: &Route,
    parts: &Parts,
    downstream_scheme: &str,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let policy = route.csrf.as_ref()?;
    let decision = policy.evaluate(parts, downstream_scheme, route.id.as_str());
    let monitored = decision.denied() && policy.monitor();
    metrics.inc_csrf(decision, monitored);
    if !decision.denied() {
        return None;
    }
    if monitored {
        tracing::warn!(
            route = %route.id,
            reason = decision.reason(),
            "request matched CSRF monitor policy"
        );
        return None;
    }

    // CSRF 拒绝不得回显 Origin、Referer、cookie 或 token，也不能进入认证/插件/上游阶段。
    tracing::warn!(
        route = %route.id,
        reason = decision.reason(),
        "request denied by CSRF policy"
    );
    Some(text_status(403, "request denied by CSRF policy"))
}

/// 业务作用：在认证、插件和上游副作用前检查或遮蔽请求 header/query。
///
/// 参数说明：`route` 是已匹配路由；`parts` 是可按显式 redact 策略修改的请求 head；
/// `internal_reroute_parts` 与 `response_filter_parts` 是早期冻结的可选请求快照；`metrics` 是共享指标。
///
/// 返回：block 命中返回 403；允许、monitor、redact 或未配置时返回 `None`。
fn enforce_dlp_request_head(
    route: &Route,
    parts: &mut Parts,
    internal_reroute_parts: &mut Option<Box<Parts>>,
    response_filter_parts: &mut Option<Box<Parts>>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let policy = route.dlp.as_ref()?;
    match policy.inspect_request_head(parts) {
        DlpHeadOutcome::Allowed => None,
        DlpHeadOutcome::Monitored(matched) => {
            metrics.inc_dlp(DlpMetric::Monitored);
            log_dlp_match(route, matched, "request DLP monitor match");
            None
        }
        DlpHeadOutcome::Redacted(matched) => {
            // error_page/reroute 与响应过滤器不得继续持有遮蔽前的 URI/header，否则原值可能
            // 在后续内部请求或插件阶段重新出现。只更新原本已需要的快照，不扩大 clone 热路径。
            if internal_reroute_parts.is_some() {
                *internal_reroute_parts = Some(Box::new(parts.clone()));
            }
            if response_filter_parts.is_some() {
                *response_filter_parts = Some(Box::new(parts.clone()));
            }
            metrics.inc_dlp(DlpMetric::Redacted);
            log_dlp_match(route, matched, "request DLP field redacted");
            None
        }
        DlpHeadOutcome::Blocked(matched) => {
            // 原 head 不得进入认证、插件或上游；日志只使用固定 rule/target。
            metrics.inc_dlp(DlpMetric::Blocked);
            log_dlp_match(route, matched, "request blocked by DLP");
            Some(text_status(403, "request blocked by DLP"))
        }
    }
}

/// 业务作用：在身份授权后、插件和上游前执行显式有界请求 body DLP 慢路径。
///
/// 参数说明：`route` 是已匹配路由；`parts` 接收 redact 后的实体长度；`body` 是请求体唯一槽；
/// `metrics` 是共享低基数指标。
///
/// 返回：block/资源/解析失败返回本地响应；允许、monitor、redact 或未配置时归还 body 并返回 `None`。
async fn enforce_dlp_request_body(
    route: &Route,
    parts: &mut Parts,
    body: &mut Option<forward::ForwardBody>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(policy) = &route.dlp else {
        return None;
    };
    if !policy.inspects_request_body() {
        return None;
    }
    let current = body
        .take()
        .expect("request body is owned exactly once by DLP/forward pipeline");
    match policy.inspect_request_body(parts, current).await {
        DlpBodyOutcome::Allowed(allowed) => {
            *body = Some(allowed);
            None
        }
        DlpBodyOutcome::Monitored(allowed, matched) => {
            *body = Some(allowed);
            metrics.inc_dlp(DlpMetric::Monitored);
            log_dlp_match(route, matched, "request body DLP monitor match");
            None
        }
        DlpBodyOutcome::Redacted(redacted, matched) => {
            strip_body_integrity_headers(&mut parts.headers);
            if let Some(length) = redacted.size_hint().exact() {
                normalize_content_length(&mut parts.headers, length as usize);
            }
            *body = Some(redacted);
            metrics.inc_dlp(DlpMetric::Redacted);
            log_dlp_match(route, matched, "request body redacted by DLP");
            None
        }
        DlpBodyOutcome::Blocked(matched) => {
            // 已消费的敏感实体不可交回后续插件或上游，避免半遮蔽或旁路发送。
            metrics.inc_dlp(DlpMetric::Blocked);
            log_dlp_match(route, matched, "request body blocked by DLP");
            Some(text_status(403, "request blocked by DLP"))
        }
        DlpBodyOutcome::TooLarge => {
            metrics.inc_dlp(DlpMetric::TooLarge);
            Some(text_status(413, "DLP request body is too large"))
        }
        DlpBodyOutcome::ReadFailed => {
            metrics.inc_dlp(DlpMetric::BodyReadError);
            Some(text_status(400, "DLP request body read failed"))
        }
        DlpBodyOutcome::Invalid => {
            metrics.inc_dlp(DlpMetric::Invalid);
            Some(text_status(400, "DLP request body cannot be inspected"))
        }
    }
}

/// 业务作用：在响应插件后、压缩与下游发送前检查或遮蔽响应 header/body。
///
/// 参数说明：`route` 是最终响应 route；`response` 是尚未写下游的完整响应；
/// `metrics` 是共享低基数指标。
///
/// 返回：允许、monitor 或 redact 返回可发送响应；block/资源/解析失败返回不含原实体的 502。
async fn enforce_dlp_response(
    route: &Route,
    mut response: Response<BoxBody>,
    metrics: &Metrics,
) -> Response<BoxBody> {
    let Some(policy) = &route.dlp else {
        return response;
    };
    match policy.inspect_response_head(response.headers_mut()) {
        DlpHeadOutcome::Allowed => {}
        DlpHeadOutcome::Monitored(matched) => {
            metrics.inc_dlp(DlpMetric::Monitored);
            log_dlp_match(route, matched, "response DLP monitor match");
        }
        DlpHeadOutcome::Redacted(matched) => {
            metrics.inc_dlp(DlpMetric::Redacted);
            log_dlp_match(route, matched, "response DLP field redacted");
        }
        DlpHeadOutcome::Blocked(matched) => {
            // 响应尚未写下游，立即丢弃原 body，不能发送部分敏感数据后再改错。
            metrics.inc_dlp(DlpMetric::Blocked);
            log_dlp_match(route, matched, "response blocked by DLP");
            return text_status(502, "upstream response blocked by DLP");
        }
    }
    if !policy.inspects_response_body() {
        return response;
    }
    if response.status() == StatusCode::PARTIAL_CONTENT
        || response.headers().contains_key(http::header::CONTENT_RANGE)
    {
        // 局部实体无法在不知道完整表示的情况下安全遮蔽并重建 range/validator 语义。
        metrics.inc_dlp(DlpMetric::Invalid);
        return text_status(502, "partial upstream response cannot be inspected by DLP");
    }
    let (mut parts, body) = response.into_parts();
    match policy.inspect_response_body(&parts.headers, body).await {
        DlpBodyOutcome::Allowed(allowed) => Response::from_parts(parts, allowed),
        DlpBodyOutcome::Monitored(allowed, matched) => {
            metrics.inc_dlp(DlpMetric::Monitored);
            log_dlp_match(route, matched, "response body DLP monitor match");
            Response::from_parts(parts, allowed)
        }
        DlpBodyOutcome::Redacted(redacted, matched) => {
            strip_body_integrity_headers(&mut parts.headers);
            if let Some(length) = redacted.size_hint().exact() {
                normalize_content_length(&mut parts.headers, length as usize);
            }
            metrics.inc_dlp(DlpMetric::Redacted);
            log_dlp_match(route, matched, "response body redacted by DLP");
            Response::from_parts(parts, redacted)
        }
        DlpBodyOutcome::Blocked(matched) => {
            metrics.inc_dlp(DlpMetric::Blocked);
            log_dlp_match(route, matched, "response body blocked by DLP");
            text_status(502, "upstream response blocked by DLP")
        }
        DlpBodyOutcome::TooLarge => {
            metrics.inc_dlp(DlpMetric::TooLarge);
            text_status(502, "upstream response exceeds DLP limit")
        }
        DlpBodyOutcome::ReadFailed => {
            metrics.inc_dlp(DlpMetric::BodyReadError);
            text_status(502, "upstream response DLP read failed")
        }
        DlpBodyOutcome::Invalid => {
            metrics.inc_dlp(DlpMetric::Invalid);
            text_status(502, "upstream response cannot be inspected by DLP")
        }
    }
}

/// 业务作用：记录 DLP 固定 rule/target，不接收或格式化命中原值与字段名。
///
/// 参数说明：`route` 提供低基数路由标识；`matched` 只含固定枚举文本；`message` 是编译期事件名。
///
/// 返回：无；写入一条低敏 warn 日志。
fn log_dlp_match(route: &Route, matched: crate::dlp::DlpMatch, message: &'static str) {
    tracing::warn!(
        route = %route.id,
        rule = matched.rule,
        target = matched.target,
        event = message,
        "DLP policy match"
    );
}

/// 业务作用：在身份授权后执行显式 JSON/XML WAF 慢路径，并把通过检查的同一份 body 放回主管线。
///
/// 参数说明：
/// - `route`：当前已匹配 route。
/// - `parts`：用于 media type 与声明长度判断的请求 head。
/// - `body`：请求体唯一所有权槽。
/// - `metrics`：共享低基数指标。
///
/// 返回：通过或 monitor 时归还 body 并返回 `None`；enforce、超限或读取失败时返回本地错误响应。
async fn enforce_waf_body(
    route: &Route,
    parts: &Parts,
    body: &mut Option<forward::ForwardBody>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(policy) = &route.waf else {
        return None;
    };
    if !policy.inspects_body() {
        return None;
    }
    let current = body
        .take()
        .expect("request body is owned exactly once by WAF/forward pipeline");
    match policy.inspect_body(parts, current).await {
        WafBodyOutcome::Allowed(allowed) => {
            *body = Some(allowed);
            None
        }
        WafBodyOutcome::Monitored(allowed, matched) => {
            *body = Some(allowed);
            metrics.inc_waf(WafMetric::Monitored);
            tracing::warn!(
                route = %route.id,
                rule = %matched.rule,
                target = %matched.target,
                "request body matched WAF monitor rule"
            );
            None
        }
        WafBodyOutcome::Blocked(matched) => {
            // 已消费且判定违规的 body 不得重放给后续插件或上游，避免形成半拦截状态。
            metrics.inc_waf(WafMetric::Blocked);
            tracing::warn!(
                route = %route.id,
                rule = %matched.rule,
                target = %matched.target,
                "request body blocked by WAF"
            );
            Some(text_status(403, "request blocked by WAF"))
        }
        WafBodyOutcome::TooLarge => {
            // 聚合预算是独立资源门禁；monitor 也不能绕过，否则 chunked body 可制造无界内存。
            metrics.inc_waf(WafMetric::TooLarge);
            Some(text_status(413, "WAF request body is too large"))
        }
        WafBodyOutcome::ReadFailed => {
            metrics.inc_waf(WafMetric::BodyReadError);
            Some(text_status(400, "WAF request body read failed"))
        }
    }
}

/// 执行 route 显式请求契约慢路径，并稳定映射为网关 400/413。
///
/// `body` 用 `Option` 仅为安全转移所有权：validator 成功时会放回原始流或同一份聚合
/// `Bytes`，失败时请求已经短路，不会再访问 body。未配置校验时函数立即返回且不 take。
async fn validate_route_request(
    route: &Route,
    parts: &Parts,
    body: &mut Option<forward::ForwardBody>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(validation) = &route.request_validation else {
        return None;
    };
    let current = body
        .take()
        .expect("request body is owned exactly once by validation/forward pipeline");
    match validation.validate(parts, current).await {
        ValidationOutcome::Valid(validated) => {
            *body = Some(validated);
            metrics.inc_request_schema_valid();
            None
        }
        ValidationOutcome::BadRequest(message) => {
            metrics.inc_request_schema_invalid();
            Some(text_status(400, message))
        }
        ValidationOutcome::TooLarge => {
            metrics.inc_request_schema_too_large();
            Some(text_status(413, "request body too large"))
        }
        ValidationOutcome::BodyReadFailed => {
            metrics.inc_request_schema_body_read_error();
            Some(text_status(400, "request body read failed"))
        }
    }
}

/// 业务作用：在入站契约和安全插件通过后执行显式请求实体转换，并把唯一新实体交给上游管线。
///
/// 参数说明：`route` 提供转换计划；`parts` 是待同步 representation header；`body` 是请求体
/// 唯一所有权槽；`metrics` 记录固定低基数终态。
///
/// 返回：未配置或转换成功返回 None 并归还 body；超限、读取或结构错误返回本地 413/400。
async fn transform_route_request(
    route: &Route,
    parts: &mut Parts,
    body: &mut Option<forward::ForwardBody>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(transform) = &route.request_transform else {
        return None;
    };
    let current = body
        .take()
        .expect("request body is owned exactly once by transform/forward pipeline");
    match transform.transform_request(parts, current).await {
        crate::proxy::response_contract::TransformOutcome::Transformed { body: output, .. } => {
            *body = Some(output);
            metrics.inc_body_transform(crate::metrics::BodyTransformMetric::Transformed);
            None
        }
        failure => {
            crate::proxy::response_contract::record_transform_failure(metrics, &failure);
            match failure {
                crate::proxy::response_contract::TransformOutcome::TooLarge => {
                    Some(text_status(413, "request body transform exceeds limit"))
                }
                crate::proxy::response_contract::TransformOutcome::ReadFailed => {
                    Some(text_status(400, "request body transform read failed"))
                }
                crate::proxy::response_contract::TransformOutcome::Invalid(message) => {
                    tracing::debug!(route = %route.id, reason = message, "request body transform rejected input");
                    Some(text_status(400, "request body transform failed"))
                }
                crate::proxy::response_contract::TransformOutcome::Transformed { .. } => {
                    unreachable!("successful request transform is handled above")
                }
            }
        }
    }
}

/// 执行 route 显式 GraphQL 预算守卫，并把有界收集后的同一 body allocation 放回主管线。
///
/// 守卫位于认证之后、限流/缓存/上游之前：未授权请求不会消耗 parser CPU，合法请求的
/// 复杂查询又会在占用上游、熔断 permit 或 cache single-flight 之前早拒。
async fn enforce_graphql_guard(
    route: &Route,
    parts: &Parts,
    body: &mut Option<forward::ForwardBody>,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(policy) = &route.graphql_guard else {
        return None;
    };
    // degraphql query 已在候选快照构建期按同一 policy 完整解析；运行期只有 JSON
    // variables 变化，重复解析固定 query 只会浪费 CPU，且不能增加安全性。
    if route.degraphql.is_some() {
        return None;
    }
    // 浏览器 CORS capability probe 没有 GraphQL document；让既有 CORS filter 生成响应。
    if is_cors_preflight(parts, route) {
        return None;
    }
    let current = body
        .take()
        .expect("request body is owned exactly once by GraphQL/validation/forward pipeline");
    match policy.inspect(parts, current).await {
        GraphqlOutcome::Allowed(guarded) => {
            *body = Some(guarded);
            metrics.inc_graphql_guard(GraphqlGuardResult::Allowed);
            None
        }
        GraphqlOutcome::Rejected(rejection) => {
            metrics.inc_graphql_guard(rejection.result);
            Some(text_status(rejection.status, rejection.message))
        }
    }
}

fn transform_degraphql(
    route: &Route,
    parts: &mut Parts,
    body: &mut Option<forward::ForwardBody>,
    request_end_of_stream: bool,
    metrics: &Metrics,
) -> Option<Response<BoxBody>> {
    let Some(plan) = &route.degraphql else {
        return None;
    };
    // 原下游流在已知 EOF 时没有 payload；直接丢弃句柄并换成生成 body，不读取/复制
    // 客户端正文。未知/chunked 输入由 plan fail-closed，防止请求走私。
    let _original = body
        .take()
        .expect("request body is owned exactly once by degraphql/validation/forward pipeline");
    match plan.transform(parts, request_end_of_stream) {
        crate::degraphql::DegraphqlOutcome::Transformed(generated) => {
            *body = Some(generated);
            metrics.inc_degraphql(DegraphqlMetric::Transformed);
            None
        }
        crate::degraphql::DegraphqlOutcome::Rejected { status, message } => {
            metrics.inc_degraphql(DegraphqlMetric::Rejected);
            Some(text_status(status, message))
        }
    }
}

pub(super) type DownstreamUpgrade = Option<(OnUpgrade, Option<DownstreamConnectionLease>)>;
