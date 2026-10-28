//! 低基数运行指标。
//!
//! Prometheus 与可选结构化 exporter 读取同一组数据面事实。

pub(crate) mod buckets;
pub(crate) mod realtime;

#[cfg(feature = "telemetry-otlp")]
pub(crate) mod catalog;
#[cfg(feature = "telemetry-otlp")]
pub(crate) mod governance;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crossbeam_utils::CachePadded;

use crate::extensions::graphql::GraphqlGuardResult;
use crate::security::bot::BotDecision;
use crate::security::csrf::CsrfDecision;
use crate::security::geoip::GeoIpDecision;

const REQUEST_DURATION_BUCKET_MS: [u64; 12] =
    [1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];
/// 远大于常见 Tokio worker 数；每个槽独占 cache line，管理面读取时才求和。
const HOT_COUNTER_SHARDS: usize = 64;

static NEXT_HOT_COUNTER_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Tokio worker 线程固定命中自己的条带；task 跨 worker 移动不影响总量正确性。
    static HOT_COUNTER_SHARD: usize =
        NEXT_HOT_COUNTER_SHARD.fetch_add(1, Ordering::Relaxed) % HOT_COUNTER_SHARDS;
}

/// 高频总量的 cache-line 隔离计数器。
///
/// 数据面只写当前执行线程的一个 relaxed atomic；Prometheus 管理面低频遍历 64 个槽求和。
/// 相比单个全局 atomic，这会用约 4KiB 内存换掉高并发下的 cache coherency ping-pong。
pub(super) struct ShardedCounter {
    shards: [CachePadded<AtomicU64>; HOT_COUNTER_SHARDS],
}

impl Default for ShardedCounter {
    /// 业务作用：建立零值的分片计数器，将高频递增分散到不同 cache line 以减少线程争用。
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
        }
    }
}

impl ShardedCounter {
    /// 业务作用：给当前 worker 条带累加；计数器不发布其它状态，Relaxed 足够。
    pub(super) fn add(&self, value: u64) {
        HOT_COUNTER_SHARD.with(|index| {
            self.shards[*index].fetch_add(value, Ordering::Relaxed);
        });
    }

    /// 业务作用：管理面弱一致求和；并发更新可能跨越采样窗口，但值单调且不会漏掉已完成累加。
    pub(super) fn load(&self) -> u64 {
        self.shards.iter().fold(0_u64, |total, counter| {
            total.saturating_add(counter.load(Ordering::Relaxed))
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum OpaDecisionMetric {
    Allow,
    Deny,
    FailOpen,
    Unavailable,
    InvalidInput,
}

#[derive(Clone, Copy)]
pub(crate) enum OpaCacheMetric {
    Hit,
    Miss,
}

#[derive(Clone, Copy)]
pub(crate) enum OpaRequestMetric {
    Success,
    Error,
}

#[derive(Clone, Copy)]
pub(crate) enum CasbinDecisionMetric {
    Allow,
    Deny,
    FailOpen,
    Error,
    InvalidInput,
}

#[derive(Clone, Copy)]
pub(crate) enum WasmExecutionMetric {
    Continue,
    LocalResponse,
    FailOpen,
    Error,
}

/// 外部插件调用固定终态；plugin/route/target 不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum ExternalPluginMetric {
    Continue,
    LocalResponse,
    FailOpen,
    Error,
    InvalidInput,
}

/// LLM external moderation 的固定终态；endpoint、model、route 与 prompt 不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum LlmModerationMetric {
    Allowed,
    Blocked,
    FailOpen,
    Error,
}

/// WAF 的固定数据面结果；规则、target 与 route 只进入低敏日志，不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum WafMetric {
    /// monitor 模式命中后继续转发。
    Monitored,
    /// enforce 模式命中并拒绝。
    Blocked,
    /// body 超过显式聚合预算。
    TooLarge,
    /// 下游 body transport 读取失败。
    BodyReadError,
}

/// DLP 的固定数据面结果；规则、方向、字段名与命中原值不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum DlpMetric {
    /// monitor 命中后原字节继续传输。
    Monitored,
    /// redact 命中且敏感字段已替换。
    Redacted,
    /// block 命中且当前方向停止。
    Blocked,
    /// body 超过显式聚合预算。
    TooLarge,
    /// body transport 读取失败。
    BodyReadError,
    /// media type、Content-Encoding 或结构无法安全检查。
    Invalid,
}

/// 响应契约的固定终态；operation、status、schema path 与 route 不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum ResponseContractMetric {
    Valid = 0,
    Invalid = 1,
    Blocked = 2,
    Replaced = 3,
    TooLarge = 4,
    ReadError = 5,
    Unsupported = 6,
}

/// 声明式 body 转换的固定终态；字段路径、输入值与 route 不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum BodyTransformMetric {
    Transformed = 0,
    Invalid = 1,
    TooLarge = 2,
    ReadError = 3,
}

/// Usage Plan 的固定数据面结果；consumer、plan、route 均不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum UsagePlanMetric {
    Allowed,
    Limited,
    Unmapped,
}

/// 门户 key 申请固定结果；application/catalog/applicant 不进入 label。
#[derive(Clone, Copy)]
pub(crate) enum DeveloperApplicationMetric {
    Accepted,
    Rejected,
    Error,
}

/// degraphql 固定转换结果。
#[derive(Clone, Copy)]
pub(crate) enum DegraphqlMetric {
    Transformed,
    Rejected,
}

/// Dubbo generic invocation 固定结果。
#[derive(Clone, Copy)]
pub(crate) enum DubboMetric {
    Success,
    RemoteError,
    ProtocolError,
    Timeout,
    InvalidInput,
}

/// 后台服务发现的固定后端集合。该枚举不携带 service name，避免指标基数随配置增长。
#[derive(Clone, Copy)]
pub(crate) enum RegistryBackendMetric {
    Consul = 0,
    Eureka = 1,
    Dns = 2,
    Kubernetes = 3,
}

/// 一次注册中心轮询的固定终态。
#[derive(Clone, Copy)]
pub(crate) enum RegistryPollMetric {
    Success,
    Error,
    Timeout,
    InvalidSnapshot,
}

/// 数据面与管理面的共享指标。
pub struct Metrics {
    rate_limiter: std::sync::OnceLock<std::sync::Weak<dyn crate::runtime::state::RateLimiter>>,
    pub(crate) circuits: std::sync::Arc<super::circuit::Counters>,
    pub(crate) response_codec: std::sync::Arc<super::response_codec::Counters>,
    pub(crate) http_stream: super::http_stream::metrics::Counters,
    #[cfg(feature = "telemetry-otlp")]
    pub(crate) telemetry_metrics_enabled: std::sync::atomic::AtomicBool,
    #[cfg(feature = "telemetry-otlp")]
    pub(crate) started_unix_nanos: u64,
    #[cfg(feature = "telemetry-otlp")]
    request_duration_exemplars: Mutex<[Option<catalog::DurationExemplar>; 13]>,
    requests_total: ShardedCounter,
    /// 非累计桶；每个请求只写首个匹配槽，Prometheus 渲染时转换为累计桶。
    request_duration_buckets: [ShardedCounter; REQUEST_DURATION_BUCKET_MS.len()],
    request_duration_sum_micros: ShardedCounter,
    request_duration_count: ShardedCounter,
    responses_1xx: ShardedCounter,
    responses_2xx: ShardedCounter,
    responses_3xx: ShardedCounter,
    responses_4xx: ShardedCounter,
    responses_5xx: ShardedCounter,
    upstream_errors_total: AtomicU64,
    upstream_attempts_total: ShardedCounter,
    upstream_retry_status_total: AtomicU64,
    upstream_retry_error_total: AtomicU64,
    upstream_retry_exhausted_total: AtomicU64,
    upstream_hedge_started_total: AtomicU64,
    upstream_hedge_primary_won_total: AtomicU64,
    upstream_hedge_secondary_won_total: AtomicU64,
    upstream_hedge_failed_total: AtomicU64,
    /// `limits.upstream_pending_limit` 已满而快速拒绝的请求总数。
    upstream_overloaded_total: AtomicU64,
    interface_blocked_total: AtomicU64,
    no_route_total: AtomicU64,
    access_log_dropped_total: AtomicU64,
    /// 每 sink 固定结果。sink id 构建期限制 16 个安全 ASCII 值，不受请求输入控制。
    log_sink_stats: Mutex<BTreeMap<String, LogSinkStats>>,
    /// LLM 使用量。consumer 只保存固定 `anonymous` 或认证身份 SHA-256 短指纹；总 series
    /// 还有硬上限，防租户轮换/配置热更造成 Prometheus 基数与进程内存无界增长。
    llm_stats: Mutex<BTreeMap<LlmMetricKey, LlmMetricStats>>,
    pub(crate) ai: super::ai::AiMetrics,
    /// LLM 缓存命中只使用固定 level/tier 组合，不把 prompt、consumer 或 key 写入 label。
    llm_cache_exact_l1_hits_total: AtomicU64,
    llm_cache_exact_l2_hits_total: AtomicU64,
    llm_cache_semantic_l1_hits_total: AtomicU64,
    llm_cache_semantic_l2_hits_total: AtomicU64,
    llm_moderation_allowed_total: AtomicU64,
    llm_moderation_blocked_total: AtomicU64,
    llm_moderation_fail_open_total: AtomicU64,
    llm_moderation_error_total: AtomicU64,
    ai_guardrail_blocked_total: [AtomicU64; 12],
    acl_denied_total: AtomicU64,
    blacklist_denied_total: AtomicU64,
    ext_authz_allowed_total: AtomicU64,
    ext_authz_denied_total: AtomicU64,
    ext_authz_errors_total: AtomicU64,
    mirror_requests_total: AtomicU64,
    mirror_errors_total: AtomicU64,
    mirror_skipped_total: AtomicU64,
    rate_limited_total: AtomicU64,
    usage_plan_allowed_total: AtomicU64,
    usage_plan_limited_total: AtomicU64,
    usage_plan_unmapped_total: AtomicU64,
    developer_application_accepted_total: AtomicU64,
    developer_application_rejected_total: AtomicU64,
    developer_application_error_total: AtomicU64,
    degraphql_transformed_total: AtomicU64,
    degraphql_rejected_total: AtomicU64,
    dubbo_success_total: AtomicU64,
    dubbo_remote_error_total: AtomicU64,
    dubbo_protocol_error_total: AtomicU64,
    dubbo_timeout_total: AtomicU64,
    dubbo_invalid_input_total: AtomicU64,
    upstream_prewarm_success_total: AtomicU64,
    upstream_prewarm_error_total: AtomicU64,
    conn_limited_total: AtomicU64,
    circuit_rejected_total: AtomicU64,
    /// 请求 schema 校验固定结果；不使用 route/schema path 高基数 label。
    request_schema_valid_total: AtomicU64,
    request_schema_invalid_total: AtomicU64,
    request_schema_too_large_total: AtomicU64,
    request_schema_body_read_error_total: AtomicU64,
    /// 响应契约只按固定结果计数，不暴露 schema、operation 或字段信息。
    response_contract_total: [AtomicU64; 7],
    /// 请求和响应实体转换共用固定终态，方向通过独立日志上下文定位。
    body_transform_total: [AtomicU64; 4],
    /// GraphQL 守卫固定结果；不使用 operation/field/route 等高基数 label。
    graphql_allowed_total: AtomicU64,
    graphql_invalid_total: AtomicU64,
    graphql_too_large_total: AtomicU64,
    graphql_too_deep_total: AtomicU64,
    graphql_too_complex_total: AtomicU64,
    graphql_introspection_denied_total: AtomicU64,
    graphql_body_read_error_total: AtomicU64,
    /// WAF 固定终态；不把规则、target 或 route 写入指标 label。
    waf_monitored_total: AtomicU64,
    waf_blocked_total: AtomicU64,
    waf_too_large_total: AtomicU64,
    waf_body_read_error_total: AtomicU64,
    /// GeoIP 固定决策集合；不把 IP、国家、ASN、数据库或 route 写入 label。
    geoip_decisions_total: [AtomicU64; 10],
    /// Bot 固定决策与 enforce/monitor 终态；不把 IP、User-Agent、指纹或 route 写入 label。
    bot_decisions_total: [AtomicU64; 12],
    /// CSRF 固定决策与 enforce/monitor 终态；不把 Origin、Referer、cookie、token 或 route 写入 label。
    csrf_decisions_total: [AtomicU64; 8],
    /// DLP 固定处置集合；不把规则、方向、字段名、命中值或 route 写入 label。
    dlp_decisions_total: [AtomicU64; 6],
    /// OPA 固定结果；不使用 policy、consumer、route 或 header 等高基数 label。
    opa_decision_allow_total: AtomicU64,
    opa_decision_deny_total: AtomicU64,
    opa_decision_fail_open_total: AtomicU64,
    opa_decision_unavailable_total: AtomicU64,
    opa_decision_invalid_input_total: AtomicU64,
    opa_cache_hit_total: AtomicU64,
    opa_cache_miss_total: AtomicU64,
    opa_request_success_total: AtomicU64,
    opa_request_error_total: AtomicU64,
    /// Casbin 固定结果；不将 subject/object/policy/route 放入 label。
    casbin_allow_total: AtomicU64,
    casbin_deny_total: AtomicU64,
    casbin_fail_open_total: AtomicU64,
    casbin_error_total: AtomicU64,
    casbin_invalid_input_total: AtomicU64,
    /// Proxy-Wasm 固定结果；plugin/route 进日志，不进 metrics label。
    wasm_continue_total: AtomicU64,
    wasm_local_response_total: AtomicU64,
    wasm_fail_open_total: AtomicU64,
    wasm_error_total: AtomicU64,
    /// 外部 HTTP 插件固定结果；不把 endpoint/plugin/route 放入 label。
    external_plugin_continue_total: AtomicU64,
    external_plugin_local_response_total: AtomicU64,
    external_plugin_fail_open_total: AtomicU64,
    external_plugin_error_total: AtomicU64,
    external_plugin_invalid_input_total: AtomicU64,
    /// 多注册中心后台轮询；后端和结果都是编译期固定集合，不使用 service label。
    registry_poll_success_total: [AtomicU64; 4],
    registry_poll_error_total: [AtomicU64; 4],
    registry_poll_timeout_total: [AtomicU64; 4],
    registry_poll_invalid_snapshot_total: [AtomicU64; 4],
    /// BFF/chaos/mock 固定结果；不把 target/route 放入 label。
    bff_request_success_total: AtomicU64,
    bff_request_error_total: AtomicU64,
    bff_request_timeout_total: AtomicU64,
    bff_target_success_total: AtomicU64,
    bff_target_error_total: AtomicU64,
    fault_delayed_total: AtomicU64,
    fault_aborted_total: AtomicU64,
    mock_responses_total: AtomicU64,
    /// 动态 gzip 编码响应数；不含上游已 gzip 的直通响应。
    compression_gzip_total: AtomicU64,
    /// 动态 Brotli 编码响应数；不含上游已 br 的直通响应。
    compression_brotli_total: AtomicU64,
    /// 因下游不支持而解码 gzip 的响应数。
    decompression_gzip_total: AtomicU64,
    /// 因下游不支持而解码 Brotli 的响应数。
    decompression_brotli_total: AtomicU64,
    /// 公共 HTTP L1 命中数。
    http_cache_hits_total: AtomicU64,
    /// 安全可缓存 GET 的 L1 miss 数；绕过请求不计入。
    http_cache_misses_total: AtomicU64,
    /// Redis L2 读取结果只使用固定标签，不能把缓存键或实例地址带入指标。
    http_cache_l2_hits_total: AtomicU64,
    http_cache_l2_misses_total: AtomicU64,
    http_cache_l2_errors_total: AtomicU64,
    /// 异步 L2 fills；不阻塞下游 EOF。
    http_cache_l2_store_ok_total: AtomicU64,
    http_cache_l2_store_errors_total: AtomicU64,
    /// 管理操作或成功写入触发的路由缓存代数失效次数。
    http_cache_invalidation_ok_total: AtomicU64,
    http_cache_invalidation_errors_total: AtomicU64,
    /// 本节点 cache miss single-flight 固定结果计数；不使用 key/route 高基数 label。
    http_cache_singleflight_leader_total: AtomicU64,
    http_cache_singleflight_follower_total: AtomicU64,
    http_cache_singleflight_wait_hit_total: AtomicU64,
    http_cache_singleflight_timeout_total: AtomicU64,
    http_cache_singleflight_bypass_total: AtomicU64,
    /// SWR 固定结果计数；后台刷新不带 route/key label。
    http_cache_stale_total: AtomicU64,
    http_cache_revalidation_ok_total: AtomicU64,
    http_cache_revalidation_errors_total: AtomicU64,
    http_cache_revalidation_skipped_total: AtomicU64,
    active_connections: AtomicU64,
    stream_connections_total: AtomicU64,
    stream_connection_errors_total: AtomicU64,
    stream_bytes_downstream_to_upstream_total: AtomicU64,
    stream_bytes_upstream_to_downstream_total: AtomicU64,
    stream_active_connections: AtomicU64,
    /// UDP 固定方向 datagram 计数与资源预算丢弃数。
    stream_udp_downstream_datagrams_total: AtomicU64,
    stream_udp_upstream_datagrams_total: AtomicU64,
    stream_udp_dropped_datagrams_total: AtomicU64,
    /// MQTT 协议治理只进入 feature 制品；方向和违规原因都是固定集。
    #[cfg(feature = "mqtt-governance")]
    stream_mqtt_downstream_packets_total: AtomicU64,
    #[cfg(feature = "mqtt-governance")]
    stream_mqtt_upstream_packets_total: AtomicU64,
    #[cfg(feature = "mqtt-governance")]
    stream_mqtt_rejections_total: [AtomicU64; 5],
    /// Kafka 协议治理只进入 feature 制品；方向和违规原因均为固定集。
    #[cfg(feature = "kafka-governance")]
    stream_kafka_downstream_frames_total: AtomicU64,
    #[cfg(feature = "kafka-governance")]
    stream_kafka_upstream_frames_total: AtomicU64,
    #[cfg(feature = "kafka-governance")]
    stream_kafka_rejections_total: [AtomicU64; 5],
    /// QUIC/H3 只在 `http3` 制品中存在；结果集合固定，不将 IP/SNI/route 写入 label。
    #[cfg(feature = "http3")]
    quic_connections_active: AtomicU64,
    #[cfg(feature = "http3")]
    quic_handshake_success_total: AtomicU64,
    #[cfg(feature = "http3")]
    quic_handshake_error_total: AtomicU64,
    #[cfg(feature = "http3")]
    quic_handshake_retry_total: AtomicU64,
    #[cfg(feature = "http3")]
    quic_handshake_rejected_total: AtomicU64,
    #[cfg(feature = "http3")]
    quic_migrations_total: AtomicU64,
    #[cfg(feature = "http3")]
    http3_requests_success_total: AtomicU64,
    #[cfg(feature = "http3")]
    http3_requests_error_total: AtomicU64,
    #[cfg(feature = "http3")]
    http3_streams_active: AtomicU64,
    /// 0-RTT 只记录固定放行/拒绝终态，不把 nonce、ticket、route 或客户端写入 label。
    early_data_decisions_total: [AtomicU64; 10],
    /// CONNECT-UDP 只使用固定方向与丢弃终态，不把 route、目标或客户端写入 label。
    #[cfg(feature = "http3")]
    connect_udp_downstream_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    connect_udp_upstream_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    connect_udp_dropped_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    http3_dropped_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_sessions_active: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_sessions_success_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_sessions_error_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_bidi_streams_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_uni_streams_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_bidi_streams_rejected_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_uni_streams_rejected_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_downstream_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_upstream_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    webtransport_dropped_datagrams_total: AtomicU64,
    #[cfg(feature = "http3")]
    upstream_http3_connections_active: AtomicU64,
    #[cfg(feature = "http3")]
    upstream_http3_connections_created_total: AtomicU64,
    #[cfg(feature = "http3")]
    upstream_http3_connection_errors_total: AtomicU64,
    #[cfg(feature = "http3")]
    upstream_http3_goaway_total: AtomicU64,
    /// 主动健康探测当前判定为不健康的上游实例数;后台探测任务每轮刷新。
    active_health_unhealthy: AtomicU64,
    /// 主动健康探测累计可达次数。
    active_health_probe_ok: AtomicU64,
    /// 主动健康探测累计不可达、超时或状态不符次数。
    active_health_probe_fail: AtomicU64,
    /// 常驻上游 identity 表项数；仅在 reload reconcile 低频刷新。
    upstream_identity_inflight_entries: AtomicU64,
    upstream_identity_pending_entries: AtomicU64,
    upstream_identity_rr_entries: AtomicU64,
    upstream_identity_budget_entries: AtomicU64,
}

#[derive(Default, Clone, Copy)]
struct LogSinkStats {
    delivered: u64,
    errors: u64,
    dropped_queue_full: u64,
    dropped_delivery: u64,
    dropped_oversized: u64,
    dropped_encode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LlmMetricKey {
    route: String,
    model: String,
    consumer: String,
}

#[derive(Clone, Copy, Default)]
struct LlmMetricStats {
    prompt_tokens: u64,
    completion_tokens: u64,
    cost_microusd: u64,
}

impl Default for Metrics {
    /// 业务作用：创建全部低基数计数器为零的进程级 metrics 容器，feature 指标只进对应制品。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：可供数据面并发更新的空 metrics 集；不创建后台任务或高基数表项。
    fn default() -> Self {
        Self {
            circuits: Default::default(),
            rate_limiter: Default::default(),
            response_codec: Default::default(),
            http_stream: Default::default(),
            #[cfg(feature = "telemetry-otlp")]
            telemetry_metrics_enabled: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "telemetry-otlp")]
            started_unix_nanos: catalog::unix_nanos(),
            #[cfg(feature = "telemetry-otlp")]
            request_duration_exemplars: Mutex::new([None; 13]),
            requests_total: ShardedCounter::default(),
            request_duration_buckets: Default::default(),
            request_duration_sum_micros: ShardedCounter::default(),
            request_duration_count: ShardedCounter::default(),
            responses_1xx: ShardedCounter::default(),
            responses_2xx: ShardedCounter::default(),
            responses_3xx: ShardedCounter::default(),
            responses_4xx: ShardedCounter::default(),
            responses_5xx: ShardedCounter::default(),
            upstream_errors_total: AtomicU64::new(0),
            upstream_attempts_total: ShardedCounter::default(),
            upstream_retry_status_total: AtomicU64::new(0),
            upstream_retry_error_total: AtomicU64::new(0),
            upstream_retry_exhausted_total: AtomicU64::new(0),
            upstream_hedge_started_total: AtomicU64::new(0),
            upstream_hedge_primary_won_total: AtomicU64::new(0),
            upstream_hedge_secondary_won_total: AtomicU64::new(0),
            upstream_hedge_failed_total: AtomicU64::new(0),
            upstream_overloaded_total: AtomicU64::new(0),
            interface_blocked_total: AtomicU64::new(0),
            no_route_total: AtomicU64::new(0),
            access_log_dropped_total: AtomicU64::new(0),
            log_sink_stats: Mutex::new(BTreeMap::new()),
            llm_stats: Mutex::new(BTreeMap::new()),
            ai: super::ai::AiMetrics::default(),
            llm_cache_exact_l1_hits_total: AtomicU64::new(0),
            llm_cache_exact_l2_hits_total: AtomicU64::new(0),
            llm_cache_semantic_l1_hits_total: AtomicU64::new(0),
            llm_cache_semantic_l2_hits_total: AtomicU64::new(0),
            llm_moderation_allowed_total: AtomicU64::new(0),
            llm_moderation_blocked_total: AtomicU64::new(0),
            llm_moderation_fail_open_total: AtomicU64::new(0),
            llm_moderation_error_total: AtomicU64::new(0),
            ai_guardrail_blocked_total: std::array::from_fn(|_| AtomicU64::new(0)),
            acl_denied_total: AtomicU64::new(0),
            blacklist_denied_total: AtomicU64::new(0),
            ext_authz_allowed_total: AtomicU64::new(0),
            ext_authz_denied_total: AtomicU64::new(0),
            ext_authz_errors_total: AtomicU64::new(0),
            mirror_requests_total: AtomicU64::new(0),
            mirror_errors_total: AtomicU64::new(0),
            mirror_skipped_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            usage_plan_allowed_total: AtomicU64::new(0),
            usage_plan_limited_total: AtomicU64::new(0),
            usage_plan_unmapped_total: AtomicU64::new(0),
            developer_application_accepted_total: AtomicU64::new(0),
            developer_application_rejected_total: AtomicU64::new(0),
            developer_application_error_total: AtomicU64::new(0),
            degraphql_transformed_total: AtomicU64::new(0),
            degraphql_rejected_total: AtomicU64::new(0),
            dubbo_success_total: AtomicU64::new(0),
            dubbo_remote_error_total: AtomicU64::new(0),
            dubbo_protocol_error_total: AtomicU64::new(0),
            dubbo_timeout_total: AtomicU64::new(0),
            dubbo_invalid_input_total: AtomicU64::new(0),
            upstream_prewarm_success_total: AtomicU64::new(0),
            upstream_prewarm_error_total: AtomicU64::new(0),
            conn_limited_total: AtomicU64::new(0),
            circuit_rejected_total: AtomicU64::new(0),
            request_schema_valid_total: AtomicU64::new(0),
            request_schema_invalid_total: AtomicU64::new(0),
            request_schema_too_large_total: AtomicU64::new(0),
            request_schema_body_read_error_total: AtomicU64::new(0),
            response_contract_total: std::array::from_fn(|_| AtomicU64::new(0)),
            body_transform_total: std::array::from_fn(|_| AtomicU64::new(0)),
            graphql_allowed_total: AtomicU64::new(0),
            graphql_invalid_total: AtomicU64::new(0),
            graphql_too_large_total: AtomicU64::new(0),
            graphql_too_deep_total: AtomicU64::new(0),
            graphql_too_complex_total: AtomicU64::new(0),
            graphql_introspection_denied_total: AtomicU64::new(0),
            graphql_body_read_error_total: AtomicU64::new(0),
            waf_monitored_total: AtomicU64::new(0),
            waf_blocked_total: AtomicU64::new(0),
            waf_too_large_total: AtomicU64::new(0),
            waf_body_read_error_total: AtomicU64::new(0),
            geoip_decisions_total: Default::default(),
            bot_decisions_total: Default::default(),
            csrf_decisions_total: Default::default(),
            dlp_decisions_total: Default::default(),
            opa_decision_allow_total: AtomicU64::new(0),
            opa_decision_deny_total: AtomicU64::new(0),
            opa_decision_fail_open_total: AtomicU64::new(0),
            opa_decision_unavailable_total: AtomicU64::new(0),
            opa_decision_invalid_input_total: AtomicU64::new(0),
            opa_cache_hit_total: AtomicU64::new(0),
            opa_cache_miss_total: AtomicU64::new(0),
            opa_request_success_total: AtomicU64::new(0),
            opa_request_error_total: AtomicU64::new(0),
            casbin_allow_total: AtomicU64::new(0),
            casbin_deny_total: AtomicU64::new(0),
            casbin_fail_open_total: AtomicU64::new(0),
            casbin_error_total: AtomicU64::new(0),
            casbin_invalid_input_total: AtomicU64::new(0),
            wasm_continue_total: AtomicU64::new(0),
            wasm_local_response_total: AtomicU64::new(0),
            wasm_fail_open_total: AtomicU64::new(0),
            wasm_error_total: AtomicU64::new(0),
            external_plugin_continue_total: AtomicU64::new(0),
            external_plugin_local_response_total: AtomicU64::new(0),
            external_plugin_fail_open_total: AtomicU64::new(0),
            external_plugin_error_total: AtomicU64::new(0),
            external_plugin_invalid_input_total: AtomicU64::new(0),
            registry_poll_success_total: Default::default(),
            registry_poll_error_total: Default::default(),
            registry_poll_timeout_total: Default::default(),
            registry_poll_invalid_snapshot_total: Default::default(),
            bff_request_success_total: AtomicU64::new(0),
            bff_request_error_total: AtomicU64::new(0),
            bff_request_timeout_total: AtomicU64::new(0),
            bff_target_success_total: AtomicU64::new(0),
            bff_target_error_total: AtomicU64::new(0),
            fault_delayed_total: AtomicU64::new(0),
            fault_aborted_total: AtomicU64::new(0),
            mock_responses_total: AtomicU64::new(0),
            compression_gzip_total: AtomicU64::new(0),
            compression_brotli_total: AtomicU64::new(0),
            decompression_gzip_total: AtomicU64::new(0),
            decompression_brotli_total: AtomicU64::new(0),
            http_cache_hits_total: AtomicU64::new(0),
            http_cache_misses_total: AtomicU64::new(0),
            http_cache_l2_hits_total: AtomicU64::new(0),
            http_cache_l2_misses_total: AtomicU64::new(0),
            http_cache_l2_errors_total: AtomicU64::new(0),
            http_cache_l2_store_ok_total: AtomicU64::new(0),
            http_cache_l2_store_errors_total: AtomicU64::new(0),
            http_cache_invalidation_ok_total: AtomicU64::new(0),
            http_cache_invalidation_errors_total: AtomicU64::new(0),
            http_cache_singleflight_leader_total: AtomicU64::new(0),
            http_cache_singleflight_follower_total: AtomicU64::new(0),
            http_cache_singleflight_wait_hit_total: AtomicU64::new(0),
            http_cache_singleflight_timeout_total: AtomicU64::new(0),
            http_cache_singleflight_bypass_total: AtomicU64::new(0),
            http_cache_stale_total: AtomicU64::new(0),
            http_cache_revalidation_ok_total: AtomicU64::new(0),
            http_cache_revalidation_errors_total: AtomicU64::new(0),
            http_cache_revalidation_skipped_total: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            stream_connections_total: AtomicU64::new(0),
            stream_connection_errors_total: AtomicU64::new(0),
            stream_bytes_downstream_to_upstream_total: AtomicU64::new(0),
            stream_bytes_upstream_to_downstream_total: AtomicU64::new(0),
            stream_active_connections: AtomicU64::new(0),
            stream_udp_downstream_datagrams_total: AtomicU64::new(0),
            stream_udp_upstream_datagrams_total: AtomicU64::new(0),
            stream_udp_dropped_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "mqtt-governance")]
            stream_mqtt_downstream_packets_total: AtomicU64::new(0),
            #[cfg(feature = "mqtt-governance")]
            stream_mqtt_upstream_packets_total: AtomicU64::new(0),
            #[cfg(feature = "mqtt-governance")]
            stream_mqtt_rejections_total: std::array::from_fn(|_| AtomicU64::new(0)),
            #[cfg(feature = "kafka-governance")]
            stream_kafka_downstream_frames_total: AtomicU64::new(0),
            #[cfg(feature = "kafka-governance")]
            stream_kafka_upstream_frames_total: AtomicU64::new(0),
            #[cfg(feature = "kafka-governance")]
            stream_kafka_rejections_total: std::array::from_fn(|_| AtomicU64::new(0)),
            #[cfg(feature = "http3")]
            quic_connections_active: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            quic_handshake_success_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            quic_handshake_error_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            quic_handshake_retry_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            quic_handshake_rejected_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            quic_migrations_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            http3_requests_success_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            http3_requests_error_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            http3_streams_active: AtomicU64::new(0),
            early_data_decisions_total: std::array::from_fn(|_| AtomicU64::new(0)),
            #[cfg(feature = "http3")]
            connect_udp_downstream_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            connect_udp_upstream_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            connect_udp_dropped_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            http3_dropped_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_sessions_active: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_sessions_success_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_sessions_error_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_bidi_streams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_uni_streams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_bidi_streams_rejected_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_uni_streams_rejected_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_downstream_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_upstream_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            webtransport_dropped_datagrams_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            upstream_http3_connections_active: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            upstream_http3_connections_created_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            upstream_http3_connection_errors_total: AtomicU64::new(0),
            #[cfg(feature = "http3")]
            upstream_http3_goaway_total: AtomicU64::new(0),
            active_health_unhealthy: AtomicU64::new(0),
            active_health_probe_ok: AtomicU64::new(0),
            active_health_probe_fail: AtomicU64::new(0),
            upstream_identity_inflight_entries: AtomicU64::new(0),
            upstream_identity_pending_entries: AtomicU64::new(0),
            upstream_identity_rr_entries: AtomicU64::new(0),
            upstream_identity_budget_entries: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    /// 业务作用：记录一个进入 HTTP 数据面的请求。
    pub fn inc_request(&self) {
        self.requests_total.add(1);
    }

    /// 业务作用：将一次 HTTP 请求到响应头的耗时计入累计事实与固定直方图。
    ///
    /// 参数说明：
    /// - `elapsed`：是本请求到当前响应头的耗时，不包含随后实体流传输。
    ///
    /// 返回：累计值和一个有限桶更新；超出最大桶的请求仍进入总数与 sum。
    pub fn observe_request_duration(&self, elapsed: Duration) {
        let elapsed_micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.request_duration_sum_micros.add(elapsed_micros);
        self.request_duration_count.add(1);
        if let Some(idx) = REQUEST_DURATION_BUCKET_MS
            .iter()
            .position(|bucket_ms| elapsed_micros <= bucket_ms.saturating_mul(1_000))
        {
            self.request_duration_buckets[idx].add(1);
        }
    }

    /// 业务作用：先记录时延事实，再为已采样请求保留一个固定桶 exemplar。
    ///
    /// 参数说明：
    /// - `elapsed`：是到响应头耗时
    /// - `trace`：是完成信任门禁的请求 trace。
    ///
    /// 返回：每桶最多一项关联信息；竞争时丢弃 exemplar，不阻塞请求或漏记直方图。
    pub fn observe_request_duration_with_trace(
        &self,
        elapsed: Duration,
        trace: &super::telemetry::ServerTrace,
    ) {
        self.observe_request_duration(elapsed);
        #[cfg(feature = "telemetry-otlp")]
        if self.telemetry_metrics_enabled.load(Ordering::Acquire) {
            let Some(context) = trace.exemplar_context() else {
                return;
            };
            let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
            let bucket = REQUEST_DURATION_BUCKET_MS
                .iter()
                .position(|bound| micros <= bound * 1000)
                .unwrap_or(12);
            // exemplar 只能关联已经计入直方图的观测；不为保存 trace id 等待任何锁或出口。
            if let Ok(mut reservoir) = self.request_duration_exemplars.try_lock() {
                reservoir[bucket] = Some(catalog::DurationExemplar {
                    value: micros as f64 / 1_000_000.0,
                    time_unix_nano: catalog::unix_nanos(),
                    trace_id: context.trace_id().to_bytes(),
                    span_id: context.span_id().to_bytes(),
                });
            }
        }
        #[cfg(not(feature = "telemetry-otlp"))]
        let _ = trace;
    }

    /// 业务作用：按 HTTP 状态码类别记录一个最终响应。
    pub fn inc_response(&self, status: u16) {
        let counter = match status {
            100..=199 => &self.responses_1xx,
            200..=299 => &self.responses_2xx,
            300..=399 => &self.responses_3xx,
            400..=499 => &self.responses_4xx,
            _ => &self.responses_5xx,
        };
        counter.add(1);
    }

    /// 业务作用：记录一个最终未被恢复的上游错误。
    pub fn inc_upstream_error(&self) {
        self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次实际上游尝试，包括首次尝试和重试。
    pub fn inc_upstream_attempt(&self) {
        self.upstream_attempts_total.add(1);
    }

    /// 业务作用：记录一次由可重试 HTTP 状态触发的换实例。
    pub fn inc_upstream_retry_status(&self) {
        self.upstream_retry_status_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次由连接或传输错误触发的换实例。
    pub fn inc_upstream_retry_error(&self) {
        self.upstream_retry_error_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次重试预算或候选实例耗尽。
    pub fn inc_upstream_retry_exhausted(&self) {
        self.upstream_retry_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次真正启动了第二实例副本的 hedge；仅配置存在但主请求提前成功不计数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；低基数总量增加。
    pub fn inc_upstream_hedge_started(&self) {
        self.upstream_hedge_started_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录已启动副本后的首个成功响应来自主 attempt 还是副本 attempt。
    ///
    /// 参数说明：
    /// - `secondary`：为 true 表示第二实例副本获胜，false 表示主请求获胜。
    ///
    /// 返回：无；对应固定 winner 计数增加。
    pub fn inc_upstream_hedge_winner(&self, secondary: bool) {
        let counter = if secondary {
            &self.upstream_hedge_secondary_won_total
        } else {
            &self.upstream_hedge_primary_won_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录主、副两个 hedge attempt 都未得到非 5xx 响应的请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；低基数失败总量增加。
    pub fn inc_upstream_hedge_failed(&self) {
        self.upstream_hedge_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次每实例上游在途预算拒绝；只累加低基数总量，不把 URI 放进 label。
    pub fn inc_upstream_overloaded(&self) {
        self.upstream_overloaded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条被静态接口守卫或动态禁用规则拦截的请求。
    pub fn inc_interface_blocked(&self) {
        self.interface_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一个没有路由命中的请求。
    pub fn inc_no_route(&self) {
        self.no_route_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条因进程级 access-log 队列已满而丢弃的日志。
    pub fn inc_access_log_dropped(&self) {
        self.access_log_dropped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录单 sink 丢弃；reason 只接受调用点固定集合，避免请求值进入 label。
    pub fn inc_log_sink_dropped(&self, sink: &str, count: u64, reason: &'static str) {
        let mut stats = self
            .log_sink_stats
            .lock()
            .expect("log sink metrics mutex poisoned");
        let entry = stats.entry(sink.to_string()).or_default();
        match reason {
            "queue_full" => {
                entry.dropped_queue_full = entry.dropped_queue_full.saturating_add(count)
            }
            "delivery" => entry.dropped_delivery = entry.dropped_delivery.saturating_add(count),
            "oversized" => entry.dropped_oversized = entry.dropped_oversized.saturating_add(count),
            "encode" => entry.dropped_encode = entry.dropped_encode.saturating_add(count),
            _ => unreachable!("log sink drop reason is fixed at compile time"),
        }
    }

    /// 业务作用：记录后台 sink 已成功投递的记录数。
    pub fn inc_log_sink_delivered(&self, sink: &str, count: u64) {
        let mut stats = self
            .log_sink_stats
            .lock()
            .expect("log sink metrics mutex poisoned");
        let entry = stats.entry(sink.to_string()).or_default();
        entry.delivered = entry.delivered.saturating_add(count);
    }

    /// 业务作用：记录一次 sink batch 错误/超时。
    pub fn inc_log_sink_error(&self, sink: &str) {
        let mut stats = self
            .log_sink_stats
            .lock()
            .expect("log sink metrics mutex poisoned");
        let entry = stats.entry(sink.to_string()).or_default();
        entry.errors = entry.errors.saturating_add(1);
    }

    /// 业务作用：启动期注册有限 sink id，使零流量时 metrics 也能展示全部出口。
    pub fn register_log_sink(&self, sink: &str) {
        self.log_sink_stats
            .lock()
            .expect("log sink metrics mutex poisoned")
            .entry(sink.to_string())
            .or_default();
    }

    /// 业务作用：累加一次 provider 返回的真实 token usage 与按配置价格计算的微美元成本。
    #[allow(clippy::too_many_arguments)]
    pub fn observe_llm_usage(
        &self,
        route: &str,
        model: &str,
        consumer: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        input_cost_microusd_per_million: u64,
        output_cost_microusd_per_million: u64,
    ) {
        const MAX_LLM_METRIC_SERIES: usize = 4096;
        let mut stats = self.llm_stats.lock().expect("LLM metrics mutex poisoned");
        let mut key = LlmMetricKey {
            route: route.to_string(),
            model: model.to_string(),
            consumer: consumer.to_string(),
        };
        if !stats.contains_key(&key) && stats.len() >= MAX_LLM_METRIC_SERIES {
            key = LlmMetricKey {
                route: "__overflow__".to_string(),
                model: "__overflow__".to_string(),
                consumer: "__overflow__".to_string(),
            };
        }
        let value = stats.entry(key).or_default();
        value.prompt_tokens = value.prompt_tokens.saturating_add(prompt_tokens);
        value.completion_tokens = value.completion_tokens.saturating_add(completion_tokens);
        let input_cost = prompt_tokens.saturating_mul(input_cost_microusd_per_million) / 1_000_000;
        let output_cost =
            completion_tokens.saturating_mul(output_cost_microusd_per_million) / 1_000_000;
        value.cost_microusd = value
            .cost_microusd
            .saturating_add(input_cost.saturating_add(output_cost));
    }

    /// 业务作用：记录一次 LLM 缓存命中。两个参数来自内部固定枚举调用点，不接受请求动态 label。
    pub fn inc_llm_cache_hit(&self, semantic: bool, l2: bool) {
        match (semantic, l2) {
            (false, false) => &self.llm_cache_exact_l1_hits_total,
            (false, true) => &self.llm_cache_exact_l2_hits_total,
            (true, false) => &self.llm_cache_semantic_l1_hits_total,
            (true, true) => &self.llm_cache_semantic_l2_hits_total,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 external moderation 的固定终态，供安全告警区分放行、拦截与依赖降级。
    ///
    /// 参数说明：
    /// - `result`：是内部固定枚举，不携带请求或配置动态值。
    ///
    /// 返回：无；对应单调计数器增加一次。
    pub(crate) fn inc_llm_moderation(&self, result: LlmModerationMetric) {
        match result {
            LlmModerationMetric::Allowed => &self.llm_moderation_allowed_total,
            LlmModerationMetric::Blocked => &self.llm_moderation_blocked_total,
            LlmModerationMetric::FailOpen => &self.llm_moderation_fail_open_total,
            LlmModerationMetric::Error => &self.llm_moderation_error_total,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 AI 内容交付门的固定方向和分类，不创建用户或内容维度。
    ///
    /// 参数说明：
    /// - `direction`：是请求/响应相位
    /// - `category`：只能来自实现固定词表。
    ///
    /// 返回：对应计数递增；未知分类归入 invalid，不产生额外标签。
    pub(crate) fn inc_ai_guardrail(
        &self,
        direction: crate::ai::guardrail::Direction,
        category: &str,
    ) {
        let offset = match direction {
            crate::ai::guardrail::Direction::Request => 0,
            crate::ai::guardrail::Direction::Response => 6,
        };
        let index = ["prompt_injection", "jailbreak", "pii", "secret", "content"]
            .iter()
            .position(|label| *label == category)
            .unwrap_or(5);
        self.ai_guardrail_blocked_total[offset + index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条被 ACL 拒绝的请求。
    pub fn inc_acl_denied(&self) {
        self.acl_denied_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条被 IP 黑名单拒绝的请求。
    pub fn inc_blacklist_denied(&self) {
        self.blacklist_denied_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 ext_authz 外部鉴权放行。
    pub fn inc_ext_authz_allowed(&self) {
        self.ext_authz_allowed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 ext_authz 外部鉴权拒绝。
    pub fn inc_ext_authz_denied(&self) {
        self.ext_authz_denied_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 ext_authz 外部鉴权不可达/超时/异常状态。
    pub fn inc_ext_authz_error(&self) {
        self.ext_authz_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 mirror 子请求发起。
    pub fn inc_mirror_request(&self) {
        self.mirror_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 mirror 子请求构造/发送错误。
    pub fn inc_mirror_error(&self) {
        self.mirror_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 mirror 因采样未命中而跳过。
    pub fn inc_mirror_skipped(&self) {
        self.mirror_skipped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条被请求速率限制器拒绝的请求。
    pub fn inc_rate_limited(&self) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 Usage Plan 最终判定。固定枚举保证 Prometheus 序列数不受租户数量影响。
    pub(crate) fn inc_usage_plan(&self, result: UsagePlanMetric) {
        let counter = match result {
            UsagePlanMetric::Allowed => &self.usage_plan_allowed_total,
            UsagePlanMetric::Limited => &self.usage_plan_limited_total,
            UsagePlanMetric::Unmapped => &self.usage_plan_unmapped_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录开发者申请的固定结果分类，不把申请内容或主体标识放进指标标签。
    pub(crate) fn inc_developer_application(&self, result: DeveloperApplicationMetric) {
        let counter = match result {
            DeveloperApplicationMetric::Accepted => &self.developer_application_accepted_total,
            DeveloperApplicationMetric::Rejected => &self.developer_application_rejected_total,
            DeveloperApplicationMetric::Error => &self.developer_application_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录固定 REST 到 GraphQL 映射的执行结果，不记录查询变量原文。
    pub(crate) fn inc_degraphql(&self, result: DegraphqlMetric) {
        let counter = match result {
            DegraphqlMetric::Transformed => &self.degraphql_transformed_total,
            DegraphqlMetric::Rejected => &self.degraphql_rejected_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 Dubbo 协议执行的固定结果类别，区分转换拒绝与后端失败。
    pub(crate) fn inc_dubbo(&self, result: DubboMetric) {
        let counter = match result {
            DubboMetric::Success => &self.dubbo_success_total,
            DubboMetric::RemoteError => &self.dubbo_remote_error_total,
            DubboMetric::ProtocolError => &self.dubbo_protocol_error_total,
            DubboMetric::Timeout => &self.dubbo_timeout_total,
            DubboMetric::InvalidInput => &self.dubbo_invalid_input_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次实例级连接预热批次。service/instance 不进入 label，详细身份只写日志。
    pub(crate) fn inc_upstream_prewarm(&self, success: bool) {
        let counter = if success {
            &self.upstream_prewarm_success_total
        } else {
            &self.upstream_prewarm_error_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条被并发连接/请求限制器拒绝的请求。
    pub fn inc_conn_limited(&self) {
        self.conn_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条因熔断器开启而未发往上游的请求。
    pub fn inc_circuit_rejected(&self) {
        self.circuit_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次通过请求 schema 校验的请求。
    pub fn inc_request_schema_valid(&self) {
        self.request_schema_valid_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次未通过请求 schema 校验的请求。
    pub fn inc_request_schema_invalid(&self) {
        self.request_schema_invalid_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次因校验实体超过配置上限而拒绝的请求。
    pub fn inc_request_schema_too_large(&self) {
        self.request_schema_too_large_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次校验请求体读取失败。
    pub fn inc_request_schema_body_read_error(&self) {
        self.request_schema_body_read_error_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录响应契约的固定终态，同时避免 schema、operation 和字段进入指标 label。
    ///
    /// 参数说明：
    /// - `result`：是编译期固定的契约结果。
    ///
    /// 返回：无；对应计数器增加一次。
    pub(crate) fn inc_response_contract(&self, result: ResponseContractMetric) {
        self.response_contract_total[result as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录声明式 request/response body 转换的固定终态。
    ///
    /// 参数说明：
    /// - `result`：是不携带字段名或实体值的转换结果。
    ///
    /// 返回：无；对应计数器增加一次。
    pub(crate) fn inc_body_transform(&self, result: BodyTransformMetric) {
        self.body_transform_total[result as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 GraphQL 守卫的一个固定结果。
    pub(crate) fn inc_graphql_guard(&self, result: GraphqlGuardResult) {
        let counter = match result {
            GraphqlGuardResult::Allowed => &self.graphql_allowed_total,
            GraphqlGuardResult::Invalid => &self.graphql_invalid_total,
            GraphqlGuardResult::TooLarge => &self.graphql_too_large_total,
            GraphqlGuardResult::TooDeep => &self.graphql_too_deep_total,
            GraphqlGuardResult::TooComplex => &self.graphql_too_complex_total,
            GraphqlGuardResult::IntrospectionDenied => &self.graphql_introspection_denied_total,
            GraphqlGuardResult::BodyReadError => &self.graphql_body_read_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 WAF monitor、拦截或 body 安全门禁终态。
    ///
    /// 参数说明：
    /// - `result`：是编译期固定的低基数结果，不携带请求值。
    ///
    /// 返回：无；对应固定计数器增加一次。
    pub(crate) fn inc_waf(&self, result: WafMetric) {
        let counter = match result {
            WafMetric::Monitored => &self.waf_monitored_total,
            WafMetric::Blocked => &self.waf_blocked_total,
            WafMetric::TooLarge => &self.waf_too_large_total,
            WafMetric::BodyReadError => &self.waf_body_read_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 route GeoIP/ASN/匿名网络固定决策。
    ///
    /// 参数说明：
    /// - `decision`：不携带客户端 IP、国家、ASN 或数据库动态值。
    ///
    /// 返回：无；对应固定结果计数增加一次。
    pub(crate) fn inc_geoip(&self, decision: GeoIpDecision) {
        let index = match decision {
            GeoIpDecision::Allowed => 0,
            GeoIpDecision::CountryDenied => 1,
            GeoIpDecision::AsnDenied => 2,
            GeoIpDecision::AnonymousDenied => 3,
            GeoIpDecision::NotFoundAllowed => 4,
            GeoIpDecision::NotFoundDenied => 5,
            GeoIpDecision::LookupErrorAllowed => 6,
            GeoIpDecision::LookupErrorDenied => 7,
            GeoIpDecision::StaleAllowed => 8,
            GeoIpDecision::StaleDenied => 9,
        };
        self.geoip_decisions_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 route Bot 固定决策，并区分真正挑战与 monitor 观察。
    ///
    /// 参数说明：
    /// - `decision`：不携带客户端输入
    /// - `monitored`：表示拒绝原因是否仅观察。
    ///
    /// 返回：无；对应固定结果计数增加一次。
    pub(crate) fn inc_bot(&self, decision: BotDecision, monitored: bool) {
        let index = match (decision, monitored) {
            (BotDecision::Allowed, _) => 0,
            (BotDecision::Trusted, _) => 1,
            (BotDecision::UserAgentDenied, false) => 2,
            (BotDecision::UserAgentDenied, true) => 3,
            (BotDecision::FingerprintDenied, false) => 4,
            (BotDecision::FingerprintDenied, true) => 5,
            (BotDecision::BehaviorDenied, false) => 6,
            (BotDecision::BehaviorDenied, true) => 7,
            (BotDecision::TrustedClaimInvalid, false) => 8,
            (BotDecision::TrustedClaimInvalid, true) => 9,
            (BotDecision::RateDenied, false) => 10,
            (BotDecision::RateDenied, true) => 11,
        };
        self.bot_decisions_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 route CSRF 固定决策，并区分真正阻断与 monitor 观察。
    ///
    /// 参数说明：
    /// - `decision`：不携带请求输入
    /// - `monitored`：表示拒绝原因是否仅观察。
    ///
    /// 返回：无；对应固定结果计数增加一次。
    pub(crate) fn inc_csrf(&self, decision: CsrfDecision, monitored: bool) {
        let index = match (decision, monitored) {
            (CsrfDecision::SafeMethod, _) => 0,
            (CsrfDecision::Allowed, _) => 1,
            (CsrfDecision::OriginDenied, false) => 2,
            (CsrfDecision::OriginDenied, true) => 3,
            (CsrfDecision::TokenMissing, false) => 4,
            (CsrfDecision::TokenMissing, true) => 5,
            (CsrfDecision::TokenInvalid, false) => 6,
            (CsrfDecision::TokenInvalid, true) => 7,
        };
        self.csrf_decisions_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 DLP 固定处置，不接收规则、target 或命中原值。
    ///
    /// 参数说明：
    /// - `result`：是固定 monitor/redact/block/资源或解析终态。
    ///
    /// 返回：无；对应固定结果计数增加一次。
    pub(crate) fn inc_dlp(&self, result: DlpMetric) {
        let index = match result {
            DlpMetric::Monitored => 0,
            DlpMetric::Redacted => 1,
            DlpMetric::Blocked => 2,
            DlpMetric::TooLarge => 3,
            DlpMetric::BodyReadError => 4,
            DlpMetric::Invalid => 5,
        };
        self.dlp_decisions_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一个 OPA 最终数据面决策。
    pub(crate) fn inc_opa_decision(&self, result: OpaDecisionMetric) {
        let counter = match result {
            OpaDecisionMetric::Allow => &self.opa_decision_allow_total,
            OpaDecisionMetric::Deny => &self.opa_decision_deny_total,
            OpaDecisionMetric::FailOpen => &self.opa_decision_fail_open_total,
            OpaDecisionMetric::Unavailable => &self.opa_decision_unavailable_total,
            OpaDecisionMetric::InvalidInput => &self.opa_decision_invalid_input_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次已启用 OPA decision L1 的查询。
    pub(crate) fn inc_opa_cache(&self, result: OpaCacheMetric) {
        let counter = match result {
            OpaCacheMetric::Hit => &self.opa_cache_hit_total,
            OpaCacheMetric::Miss => &self.opa_cache_miss_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次真实 OPA HTTP attempt；cache hit 不计入。
    pub(crate) fn inc_opa_request(&self, result: OpaRequestMetric) {
        let counter = match result {
            OpaRequestMetric::Success => &self.opa_request_success_total,
            OpaRequestMetric::Error => &self.opa_request_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一个内嵌 Casbin 最终决策。
    pub(crate) fn inc_casbin_decision(&self, result: CasbinDecisionMetric) {
        let counter = match result {
            CasbinDecisionMetric::Allow => &self.casbin_allow_total,
            CasbinDecisionMetric::Deny => &self.casbin_deny_total,
            CasbinDecisionMetric::FailOpen => &self.casbin_fail_open_total,
            CasbinDecisionMetric::Error => &self.casbin_error_total,
            CasbinDecisionMetric::InvalidInput => &self.casbin_invalid_input_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条 Proxy-Wasm phase 链的固定结果。
    pub(crate) fn inc_wasm_execution(&self, result: WasmExecutionMetric) {
        let counter = match result {
            WasmExecutionMetric::Continue => &self.wasm_continue_total,
            WasmExecutionMetric::LocalResponse => &self.wasm_local_response_total,
            WasmExecutionMetric::FailOpen => &self.wasm_fail_open_total,
            WasmExecutionMetric::Error => &self.wasm_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次外部 HTTP 插件调用的最终结果。
    pub(crate) fn inc_external_plugin(&self, result: ExternalPluginMetric) {
        let counter = match result {
            ExternalPluginMetric::Continue => &self.external_plugin_continue_total,
            ExternalPluginMetric::LocalResponse => &self.external_plugin_local_response_total,
            ExternalPluginMetric::FailOpen => &self.external_plugin_fail_open_total,
            ExternalPluginMetric::Error => &self.external_plugin_error_total,
            ExternalPluginMetric::InvalidInput => &self.external_plugin_invalid_input_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 注册中心后台轮询。索引只能来自封闭枚举，数组访问不会接受外部输入。
    pub(crate) fn inc_registry_poll(
        &self,
        backend: RegistryBackendMetric,
        result: RegistryPollMetric,
    ) {
        let index = backend as usize;
        let counter = match result {
            RegistryPollMetric::Success => &self.registry_poll_success_total[index],
            RegistryPollMetric::Error => &self.registry_poll_error_total[index],
            RegistryPollMetric::Timeout => &self.registry_poll_timeout_total[index],
            RegistryPollMetric::InvalidSnapshot => {
                &self.registry_poll_invalid_snapshot_total[index]
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 BFF 聚合请求的最终结果，维持请求级计数与目标级计数分离。
    pub(crate) fn inc_bff_request(&self, result: &'static str) {
        match result {
            "success" => &self.bff_request_success_total,
            "error" => &self.bff_request_error_total,
            "timeout" => &self.bff_request_timeout_total,
            _ => unreachable!("BFF request result is fixed at compile time"),
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录单个 BFF 目标的执行结果，便于识别部分失败与整体失败。
    pub(crate) fn inc_bff_target(&self, success: bool) {
        if success {
            &self.bff_target_success_total
        } else {
            &self.bff_target_error_total
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录声明式故障注入的实际命中，避免把注入结果误归因为上游故障。
    pub(crate) fn inc_fault_injection(&self, aborted: bool) {
        if aborted {
            &self.fault_aborted_total
        } else {
            &self.fault_delayed_total
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录固定 mock 后端的实际响应，不参与真实上游健康裁决。
    pub(crate) fn inc_mock_response(&self) {
        self.mock_responses_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次由网关执行的 gzip 编码。
    pub fn inc_compression_gzip(&self) {
        self.compression_gzip_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次由网关执行的 Brotli 编码。
    pub fn inc_compression_brotli(&self) {
        self.compression_brotli_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次由网关执行的 gzip 解码。
    pub fn inc_decompression_gzip(&self) {
        self.decompression_gzip_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次由网关执行的 Brotli 解码。
    pub fn inc_decompression_brotli(&self) {
        self.decompression_brotli_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次公共响应 L1 命中。
    pub fn inc_http_cache_hit(&self) {
        self.http_cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次公共响应 L1 miss；Authorization/Cookie/非 GET bypass 不计入。
    pub fn inc_http_cache_miss(&self) {
        self.http_cache_misses_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 HTTP 缓存 Redis L2 命中。
    pub fn inc_http_cache_l2_hit(&self) {
        self.http_cache_l2_hits_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 HTTP 缓存 Redis L2 未命中。
    pub fn inc_http_cache_l2_miss(&self) {
        self.http_cache_l2_misses_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 HTTP 缓存 Redis L2 读取错误。
    pub fn inc_http_cache_l2_error(&self) {
        self.http_cache_l2_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 HTTP 缓存 Redis L2 写入成功。
    pub fn inc_http_cache_l2_store_ok(&self) {
        self.http_cache_l2_store_ok_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 HTTP 缓存 Redis L2 写入错误。
    pub fn inc_http_cache_l2_store_error(&self) {
        self.http_cache_l2_store_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次缓存 generation 失效广播或应用成功。
    pub fn inc_http_cache_invalidation_ok(&self) {
        self.http_cache_invalidation_ok_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次缓存 generation 失效广播或应用错误。
    pub fn inc_http_cache_invalidation_error(&self) {
        self.http_cache_invalidation_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一个负责回源填充缓存的 singleflight leader。
    pub fn inc_http_cache_singleflight_leader(&self) {
        self.http_cache_singleflight_leader_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一个等待同 key leader 的 singleflight follower。
    pub fn inc_http_cache_singleflight_follower(&self) {
        self.http_cache_singleflight_follower_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 follower 等待结束后命中已填充缓存。
    pub fn inc_http_cache_singleflight_wait_hit(&self) {
        self.http_cache_singleflight_wait_hit_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 follower 等待 singleflight 超时。
    pub fn inc_http_cache_singleflight_timeout(&self) {
        self.http_cache_singleflight_timeout_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录因 singleflight 表容量达到上限而绕过合并。
    pub fn inc_http_cache_singleflight_bypass(&self) {
        self.http_cache_singleflight_bypass_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 stale-while-revalidate 响应。
    pub fn inc_http_cache_stale(&self) {
        self.http_cache_stale_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次后台缓存重验证成功。
    pub fn inc_http_cache_revalidation_ok(&self) {
        self.http_cache_revalidation_ok_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次后台缓存重验证失败。
    pub fn inc_http_cache_revalidation_error(&self) {
        self.http_cache_revalidation_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次因已有任务或预算不足而跳过的后台重验证。
    pub fn inc_http_cache_revalidation_skipped(&self) {
        self.http_cache_revalidation_skipped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：增加进程当前活动下游连接数。
    pub fn inc_active_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：减少进程当前活动下游连接数。
    pub fn dec_active_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条 L4 stream TCP 连接进入处理流程。
    pub fn inc_stream_connection(&self) {
        self.stream_connections_total
            .fetch_add(1, Ordering::Relaxed);
        self.stream_active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：释放一条 L4 stream TCP 活跃连接。
    pub fn dec_stream_connection(&self) {
        self.stream_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 L4 stream 连接错误。
    pub fn inc_stream_error(&self) {
        self.stream_connection_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一枚 UDP datagram；`downstream=true` 表示 client→upstream。
    pub fn inc_stream_udp_datagram(&self, downstream: bool) {
        let counter = if downstream {
            &self.stream_udp_downstream_datagrams_total
        } else {
            &self.stream_udp_upstream_datagrams_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：UDP session/queue/datagram 上限触发的快速丢弃。
    pub fn inc_stream_udp_drop(&self) {
        self.stream_udp_dropped_datagrams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：累加 MQTT 状态机已成功转发的固定方向 packet，不使用 topic/client label。
    ///
    /// 参数说明：
    /// - `downstream_to_upstream`：是本次会话新增 packet 数。
    /// - `upstream_to_downstream`：是本次会话新增 packet 数。
    ///
    /// 返回：无；两个单调计数器分别累加。
    #[cfg(feature = "mqtt-governance")]
    pub fn add_stream_mqtt_packets(
        &self,
        downstream_to_upstream: u64,
        upstream_to_downstream: u64,
    ) {
        self.stream_mqtt_downstream_packets_total
            .fetch_add(downstream_to_upstream, Ordering::Relaxed);
        self.stream_mqtt_upstream_packets_total
            .fetch_add(upstream_to_downstream, Ordering::Relaxed);
    }

    /// 业务作用：按固定 MQTT 违规类型记录断连，让 ACL/畸形/资源攻击可区分且无高基数。
    ///
    /// 参数说明：
    /// - `kind`：是编译期固定的五类违规之一。
    ///
    /// 返回：无；对应分类计数器增加一。
    #[cfg(feature = "mqtt-governance")]
    pub fn inc_stream_mqtt_rejection(&self, kind: crate::protocols::mqtt::MqttViolationKind) {
        let index = match kind {
            crate::protocols::mqtt::MqttViolationKind::Malformed => 0,
            crate::protocols::mqtt::MqttViolationKind::Protocol => 1,
            crate::protocols::mqtt::MqttViolationKind::NotAuthorized => 2,
            crate::protocols::mqtt::MqttViolationKind::PacketTooLarge => 3,
            crate::protocols::mqtt::MqttViolationKind::ResourceLimit => 4,
        };
        self.stream_mqtt_rejections_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：累加 Kafka 状态机已成功转发的固定方向 frame，不使用 API/topic/client label。
    ///
    /// 参数说明：
    /// - `downstream_to_upstream`：是本次会话新增 frame 数。
    /// - `upstream_to_downstream`：是本次会话新增 frame 数。
    ///
    /// 返回：无；两个单调计数器分别累加。
    #[cfg(feature = "kafka-governance")]
    pub fn add_stream_kafka_frames(
        &self,
        downstream_to_upstream: u64,
        upstream_to_downstream: u64,
    ) {
        self.stream_kafka_downstream_frames_total
            .fetch_add(downstream_to_upstream, Ordering::Relaxed);
        self.stream_kafka_upstream_frames_total
            .fetch_add(upstream_to_downstream, Ordering::Relaxed);
    }

    /// 业务作用：按固定 Kafka 违规类型记录断连，使授权、畸形和资源攻击可区分且无高基数。
    ///
    /// 参数说明：
    /// - `kind`：是编译期固定的五类违规之一。
    ///
    /// 返回：无；对应分类计数器增加一。
    #[cfg(feature = "kafka-governance")]
    pub fn inc_stream_kafka_rejection(&self, kind: crate::protocols::kafka::KafkaViolationKind) {
        let index = match kind {
            crate::protocols::kafka::KafkaViolationKind::Malformed => 0,
            crate::protocols::kafka::KafkaViolationKind::Protocol => 1,
            crate::protocols::kafka::KafkaViolationKind::NotAuthorized => 2,
            crate::protocols::kafka::KafkaViolationKind::FrameTooLarge => 3,
            crate::protocols::kafka::KafkaViolationKind::ResourceLimit => 4,
        };
        self.stream_kafka_rejections_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条已经进入服务态的下游 QUIC connection。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；增加活跃连接 gauge，握手终态由独立方法记录。
    #[cfg(feature = "http3")]
    pub fn inc_quic_connection(&self) {
        self.quic_connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：在 QUIC TLS 握手确认后记录成功终态，与可提前处理的 0-RTT stream 解耦。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定 `result=success` 计数增加。
    #[cfg(feature = "http3")]
    pub fn inc_quic_handshake_success(&self) {
        self.quic_handshake_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：在 QUIC connection 完整退出时归还活跃 gauge。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；只减少当前值，不改写累计握手结果。
    #[cfg(feature = "http3")]
    pub fn dec_quic_connection(&self) {
        self.quic_connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 QUIC 握手或 H3 初始化失败。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定 `result=error` 计数增加。
    #[cfg(feature = "http3")]
    pub fn inc_quic_handshake_error(&self) {
        self.quic_handshake_error_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次因地址验证策略发出的 QUIC Retry。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定 `result=retry` 计数增加。
    #[cfg(feature = "http3")]
    pub fn inc_quic_handshake_retry(&self) {
        self.quic_handshake_retry_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次在创建握手 task 前被资源硬门拒绝的 Initial。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定 `result=rejected` 计数增加。
    #[cfg(feature = "http3")]
    pub fn inc_quic_handshake_rejected(&self) {
        self.quic_handshake_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：每条 connection 首次观察到对端地址变化时记录一次 QUIC migration。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；不使用 IP/connection id 作 label。
    #[cfg(feature = "http3")]
    pub fn inc_quic_migration(&self) {
        self.quic_migrations_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：在 H3 request stream 进入统一代理管线前增加活跃 stream gauge。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    #[cfg(feature = "http3")]
    pub fn inc_http3_stream(&self) {
        self.http3_streams_active.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：在 H3 request stream 退出时归还 gauge 并记录固定成功/失败结果。
    ///
    /// 参数说明：
    /// - `success`：表示响应已完整写出 FIN。
    ///
    /// 返回：无。
    #[cfg(feature = "http3")]
    pub fn finish_http3_stream(&self, success: bool) {
        self.http3_streams_active.fetch_sub(1, Ordering::Relaxed);
        let counter = if success {
            &self.http3_requests_success_total
        } else {
            &self.http3_requests_error_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次 transport 已确认的 early-data 放行或固定拒绝终态。
    ///
    /// 参数说明：
    /// - `denial`：为空表示通过全部门禁，非空表示拒绝原因。
    ///
    /// 返回：无；对应固定计数器增加一次，不记录请求输入。
    pub(crate) fn inc_early_data(&self, denial: Option<crate::protocols::masque::EarlyDataDenial>) {
        let index = match denial {
            None => 0,
            Some(crate::protocols::masque::EarlyDataDenial::NotEnabled) => 1,
            Some(crate::protocols::masque::EarlyDataDenial::NonIdempotentMethod) => 2,
            Some(crate::protocols::masque::EarlyDataDenial::SensitiveCredential) => 3,
            Some(crate::protocols::masque::EarlyDataDenial::Replayed) => 4,
            Some(crate::protocols::masque::EarlyDataDenial::MissingNonce) => 5,
            Some(crate::protocols::masque::EarlyDataDenial::MissingIndicator) => 6,
            Some(crate::protocols::masque::EarlyDataDenial::InvalidIndicator) => 7,
            Some(crate::protocols::masque::EarlyDataDenial::InvalidNonce) => 8,
            Some(crate::protocols::masque::EarlyDataDenial::RequestBody) => 9,
        };
        self.early_data_decisions_total[index].fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一枚成功穿过 CONNECT-UDP 的数据报，不暴露 route、目标或客户端身份。
    ///
    /// 参数说明：
    /// - `downstream`：为 true 表示客户端到 UDP 目标，false 表示反向。
    ///
    /// 返回：无；对应固定方向计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_connect_udp_datagram(&self, downstream: bool) {
        let counter = if downstream {
            &self.connect_udp_downstream_datagrams_total
        } else {
            &self.connect_udp_upstream_datagrams_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录因畸形、未知 session、队列满、payload 或累计预算触发的 DATAGRAM 丢弃。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定丢弃计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_connect_udp_datagram_drop(&self) {
        self.connect_udp_dropped_datagrams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录无法归属到活动扩展会话的 HTTP/3 DATAGRAM，暴露畸形、迟到与未知流量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定协议级丢弃计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_http3_datagram_drop(&self) {
        self.http3_dropped_datagrams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：登记一条已完成上下游握手的 WebTransport session。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；活跃 session gauge 增加一，终态由 [`Self::finish_webtransport_session`] 归还。
    #[cfg(feature = "http3")]
    pub fn inc_webtransport_session(&self) {
        self.webtransport_sessions_active
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：在 WebTransport session 退出时归还活跃量并记录固定成功或错误终态。
    ///
    /// 参数说明：
    /// - `success`：表示会话按关闭、超时、撤权或停机路径完整收口。
    ///
    /// 返回：无；只更新固定结果计数器，不记录 route、目标或客户端身份。
    #[cfg(feature = "http3")]
    pub fn finish_webtransport_session(&self, success: bool) {
        self.webtransport_sessions_active
            .fetch_sub(1, Ordering::Relaxed);
        let counter = if success {
            &self.webtransport_sessions_success_total
        } else {
            &self.webtransport_sessions_error_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条已取得会话准入的 WebTransport stream。
    ///
    /// 参数说明：
    /// - `bidirectional`：区分双向与单向 stream。
    ///
    /// 返回：无；对应固定类型计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_webtransport_stream(&self, bidirectional: bool) {
        let counter = if bidirectional {
            &self.webtransport_bidi_streams_total
        } else {
            &self.webtransport_uni_streams_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录因 session 身份或并发硬门而被明确终止的 WebTransport stream。
    ///
    /// 参数说明：
    /// - `bidirectional`：区分双向与单向 stream。
    ///
    /// 返回：无；对应固定类型拒绝计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_webtransport_stream_rejected(&self, bidirectional: bool) {
        let counter = if bidirectional {
            &self.webtransport_bidi_streams_rejected_total
        } else {
            &self.webtransport_uni_streams_rejected_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一枚成功穿过 WebTransport session 的 DATAGRAM。
    ///
    /// 参数说明：
    /// - `downstream`：为 true 表示客户端到上游，false 表示上游到客户端。
    ///
    /// 返回：无；对应固定方向计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_webtransport_datagram(&self, downstream: bool) {
        let counter = if downstream {
            &self.webtransport_downstream_datagrams_total
        } else {
            &self.webtransport_upstream_datagrams_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录因畸形、session 不匹配、队列、payload、累计预算或拥塞而丢弃的数据报。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；固定 WebTransport 丢弃计数器增加一。
    #[cfg(feature = "http3")]
    pub fn inc_webtransport_datagram_drop(&self) {
        self.webtransport_dropped_datagrams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一条新建且可多路复用的上游 H3 connection。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；同时更新 created counter 与 active gauge。
    #[cfg(feature = "http3")]
    pub fn inc_upstream_http3_connection(&self) {
        self.upstream_http3_connections_created_total
            .fetch_add(1, Ordering::Relaxed);
        self.upstream_http3_connections_active
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：上游 H3 connection generation 完整释放时归还 active gauge。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    #[cfg(feature = "http3")]
    pub fn dec_upstream_http3_connection(&self) {
        self.upstream_http3_connections_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// 业务作用：记录一次上游 H3 DNS/TLS/QUIC/H3 连接或运行错误。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    #[cfg(feature = "http3")]
    pub fn inc_upstream_http3_connection_error(&self) {
        self.upstream_http3_connection_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录上游 H3 driver 进入 GOAWAY/close 换代边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    #[cfg(feature = "http3")]
    pub fn inc_upstream_http3_goaway(&self) {
        self.upstream_http3_goaway_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：记录 L4 stream 双向转发字节数。
    ///
    /// 参数说明：
    /// - `downstream_to_upstream`: 下游到上游的字节数。
    /// - `upstream_to_downstream`: 上游到下游的字节数。
    pub fn add_stream_bytes(&self, downstream_to_upstream: u64, upstream_to_downstream: u64) {
        self.stream_bytes_downstream_to_upstream_total
            .fetch_add(downstream_to_upstream, Ordering::Relaxed);
        self.stream_bytes_upstream_to_downstream_total
            .fetch_add(upstream_to_downstream, Ordering::Relaxed);
    }

    /// 业务作用：主动健康探测任务每轮结束后刷新当前不健康实例总数(低基数,无 label)。
    pub fn set_active_health_unhealthy(&self, count: u64) {
        self.active_health_unhealthy.store(count, Ordering::Relaxed);
    }

    /// 业务作用：记一次主动健康探测结果：`ok=true` 表示可达，否则为不可达、超时或状态不符。
    pub fn inc_active_health_probe(&self, ok: bool) {
        if ok {
            self.active_health_probe_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.active_health_probe_fail
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 业务作用：刷新常驻上游 identity map 表项数。`kind` 集合固定，不暴露 service/URI。
    pub fn set_upstream_identity_entries(
        &self,
        inflight: usize,
        pending: usize,
        rr: usize,
        budgets: usize,
    ) {
        self.upstream_identity_inflight_entries
            .store(inflight as u64, Ordering::Relaxed);
        self.upstream_identity_pending_entries
            .store(pending as u64, Ordering::Relaxed);
        self.upstream_identity_rr_entries
            .store(rr as u64, Ordering::Relaxed);
        self.upstream_identity_budget_entries
            .store(budgets as u64, Ordering::Relaxed);
    }

    /// 业务作用：一次读取固定核心计数器，供文本与结构化出口共享相同事实映射。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无动态标签的核心累计事实；并发更新采用弱一致读取。
    fn core_counters(&self) -> [(&'static str, u64); 33] {
        [
            ("gw_requests_total", self.requests_total.load()),
            ("gw_responses_1xx_total", self.responses_1xx.load()),
            ("gw_responses_2xx_total", self.responses_2xx.load()),
            ("gw_responses_3xx_total", self.responses_3xx.load()),
            ("gw_responses_4xx_total", self.responses_4xx.load()),
            ("gw_responses_5xx_total", self.responses_5xx.load()),
            (
                "gw_upstream_errors_total",
                self.upstream_errors_total.load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_attempts_total",
                self.upstream_attempts_total.load(),
            ),
            (
                "gw_upstream_overloaded_total",
                self.upstream_overloaded_total.load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_retry_status_total",
                self.upstream_retry_status_total.load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_retry_error_total",
                self.upstream_retry_error_total.load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_retry_exhausted_total",
                self.upstream_retry_exhausted_total.load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_hedge_started_total",
                self.upstream_hedge_started_total.load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_hedge_primary_won_total",
                self.upstream_hedge_primary_won_total
                    .load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_hedge_secondary_won_total",
                self.upstream_hedge_secondary_won_total
                    .load(Ordering::Relaxed),
            ),
            (
                "gw_upstream_hedge_failed_total",
                self.upstream_hedge_failed_total.load(Ordering::Relaxed),
            ),
            (
                "gw_interface_blocked_total",
                self.interface_blocked_total.load(Ordering::Relaxed),
            ),
            (
                "gw_no_route_total",
                self.no_route_total.load(Ordering::Relaxed),
            ),
            (
                "gw_acl_denied_total",
                self.acl_denied_total.load(Ordering::Relaxed),
            ),
            (
                "gw_blacklist_denied_total",
                self.blacklist_denied_total.load(Ordering::Relaxed),
            ),
            (
                "gw_ext_authz_allowed_total",
                self.ext_authz_allowed_total.load(Ordering::Relaxed),
            ),
            (
                "gw_ext_authz_denied_total",
                self.ext_authz_denied_total.load(Ordering::Relaxed),
            ),
            (
                "gw_ext_authz_errors_total",
                self.ext_authz_errors_total.load(Ordering::Relaxed),
            ),
            (
                "gw_mirror_requests_total",
                self.mirror_requests_total.load(Ordering::Relaxed),
            ),
            (
                "gw_mirror_errors_total",
                self.mirror_errors_total.load(Ordering::Relaxed),
            ),
            (
                "gw_mirror_skipped_total",
                self.mirror_skipped_total.load(Ordering::Relaxed),
            ),
            (
                "gw_rate_limited_total",
                self.rate_limited_total.load(Ordering::Relaxed),
            ),
            (
                "gw_conn_limited_total",
                self.conn_limited_total.load(Ordering::Relaxed),
            ),
            (
                "gw_circuit_rejected_total",
                self.circuit_rejected_total.load(Ordering::Relaxed),
            ),
            (
                "gw_stream_connections_total",
                self.stream_connections_total.load(Ordering::Relaxed),
            ),
            (
                "gw_stream_connection_errors_total",
                self.stream_connection_errors_total.load(Ordering::Relaxed),
            ),
            (
                "gw_stream_bytes_downstream_to_upstream_total",
                self.stream_bytes_downstream_to_upstream_total
                    .load(Ordering::Relaxed),
            ),
            (
                "gw_stream_bytes_upstream_to_downstream_total",
                self.stream_bytes_upstream_to_downstream_total
                    .load(Ordering::Relaxed),
            ),
        ]
    }

    /// 业务作用：将当前快照和低基数运行态渲染成 Prometheus text exposition，不暴露租户、
    /// topic、client id 或 upstream URI。
    ///
    /// 参数说明：
    /// - `config_version`：是已发布快照版本
    /// - `upstream_services`：是当前低基数服务数。
    ///
    /// 返回：完整 Prometheus text；读取为弱一致快照，不阻塞数据面更新。
    pub fn render_prometheus(&self, config_version: u64, upstream_services: usize) -> String {
        let lines = self.core_counters();
        let mut out = String::with_capacity(2048);
        for (name, val) in lines {
            render_counter(&mut out, name, val);
        }
        render_request_duration(&mut out, self);
        self.http_stream.render(&mut out);
        self.circuits.render(&mut out);
        self.response_codec.render(&mut out);
        render_log_sink_metrics(&mut out, self);
        render_llm_metrics(&mut out, self);
        self.ai.render(&mut out);
        crate::routing::layers::metrics::render(&mut out);
        crate::upstream::load::metrics::render(&mut out);
        crate::runtime::traffic_limit::metrics::render(&mut out);
        crate::runtime::sentinel::queue::metrics::render(&mut out);
        nametrics_core::atomic::render_snapshot(
            &[&buckets::DESCRIPTORS[0], &buckets::DESCRIPTORS[1]],
            &buckets::samples(self),
            &mut out,
        );
        crate::io::request_decompression::metrics::render(&mut out);
        #[cfg(feature = "upstream-outlier")]
        crate::upstream::passive::metrics::render(&mut out);
        #[cfg(feature = "rate-preallocation")]
        crate::runtime::ratelimit::metrics::render(&mut out);
        #[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
        crate::protocols::cgi::metrics::render(&mut out);
        #[cfg(feature = "webdav")]
        crate::io::webdav::metrics::render(&mut out);
        #[cfg(feature = "media-streaming")]
        crate::io::media::metrics::render(&mut out);
        #[cfg(feature = "lua-scripts")]
        crate::extensions::scripts::metrics::render(&mut out);
        #[cfg(feature = "xds-server")]
        crate::control::xds_server::metrics::render(&mut out);
        #[cfg(feature = "config-providers")]
        crate::control::providers::metrics::render(&mut out);
        #[cfg(feature = "telemetry-otlp")]
        if self.telemetry_metrics_enabled.load(Ordering::Acquire) {
            catalog::render_extra(self, &mut out);
        }
        render_gauge(
            &mut out,
            "gw_active_connections",
            self.active_connections.load(Ordering::Relaxed),
        );
        render_gauge(
            &mut out,
            "gw_stream_active_connections",
            self.stream_active_connections.load(Ordering::Relaxed),
        );
        out.push_str("# HELP gw_stream_udp_datagrams_total UDP datagrams by fixed direction.\n");
        out.push_str("# TYPE gw_stream_udp_datagrams_total counter\n");
        out.push_str(&format!(
            "gw_stream_udp_datagrams_total{{direction=\"downstream_to_upstream\"}} {}\n",
            self.stream_udp_downstream_datagrams_total
                .load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_stream_udp_datagrams_total{{direction=\"upstream_to_downstream\"}} {}\n",
            self.stream_udp_upstream_datagrams_total
                .load(Ordering::Relaxed)
        ));
        render_counter(
            &mut out,
            "gw_stream_udp_dropped_datagrams_total",
            self.stream_udp_dropped_datagrams_total
                .load(Ordering::Relaxed),
        );
        #[cfg(feature = "mqtt-governance")]
        {
            out.push_str(
                "# HELP gw_stream_mqtt_packets_total MQTT packets forwarded by fixed direction.\n",
            );
            out.push_str("# TYPE gw_stream_mqtt_packets_total counter\n");
            out.push_str(&format!(
                "gw_stream_mqtt_packets_total{{direction=\"downstream_to_upstream\"}} {}\n",
                self.stream_mqtt_downstream_packets_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_stream_mqtt_packets_total{{direction=\"upstream_to_downstream\"}} {}\n",
                self.stream_mqtt_upstream_packets_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str("# HELP gw_stream_mqtt_rejections_total MQTT session terminations by fixed reason.\n");
            out.push_str("# TYPE gw_stream_mqtt_rejections_total counter\n");
            for (index, reason) in [
                "malformed",
                "protocol",
                "not_authorized",
                "packet_too_large",
                "resource_limit",
            ]
            .into_iter()
            .enumerate()
            {
                out.push_str(&format!(
                    "gw_stream_mqtt_rejections_total{{reason=\"{reason}\"}} {}\n",
                    self.stream_mqtt_rejections_total[index].load(Ordering::Relaxed)
                ));
            }
        }
        #[cfg(feature = "kafka-governance")]
        {
            out.push_str(
                "# HELP gw_stream_kafka_frames_total Kafka frames forwarded by fixed direction.\n",
            );
            out.push_str("# TYPE gw_stream_kafka_frames_total counter\n");
            out.push_str(&format!(
                "gw_stream_kafka_frames_total{{direction=\"downstream_to_upstream\"}} {}\n",
                self.stream_kafka_downstream_frames_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_stream_kafka_frames_total{{direction=\"upstream_to_downstream\"}} {}\n",
                self.stream_kafka_upstream_frames_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str("# HELP gw_stream_kafka_rejections_total Kafka session terminations by fixed reason.\n");
            out.push_str("# TYPE gw_stream_kafka_rejections_total counter\n");
            for (index, reason) in [
                "malformed",
                "protocol",
                "not_authorized",
                "frame_too_large",
                "resource_limit",
            ]
            .into_iter()
            .enumerate()
            {
                out.push_str(&format!(
                    "gw_stream_kafka_rejections_total{{reason=\"{reason}\"}} {}\n",
                    self.stream_kafka_rejections_total[index].load(Ordering::Relaxed)
                ));
            }
        }
        #[cfg(feature = "http3")]
        {
            render_gauge(
                &mut out,
                "gw_quic_connections_active",
                self.quic_connections_active.load(Ordering::Relaxed),
            );
            out.push_str("# HELP gw_quic_handshakes_total QUIC handshakes by fixed result.\n");
            out.push_str("# TYPE gw_quic_handshakes_total counter\n");
            for (result, value) in [
                (
                    "success",
                    self.quic_handshake_success_total.load(Ordering::Relaxed),
                ),
                (
                    "error",
                    self.quic_handshake_error_total.load(Ordering::Relaxed),
                ),
                (
                    "retry",
                    self.quic_handshake_retry_total.load(Ordering::Relaxed),
                ),
                (
                    "rejected",
                    self.quic_handshake_rejected_total.load(Ordering::Relaxed),
                ),
            ] {
                out.push_str(&format!(
                    "gw_quic_handshakes_total{{result=\"{result}\"}} {value}\n"
                ));
            }
            render_counter(
                &mut out,
                "gw_quic_migrations_total",
                self.quic_migrations_total.load(Ordering::Relaxed),
            );
            render_gauge(
                &mut out,
                "gw_http3_streams_active",
                self.http3_streams_active.load(Ordering::Relaxed),
            );
            out.push_str("# HELP gw_http3_requests_total HTTP/3 requests by fixed result.\n");
            out.push_str("# TYPE gw_http3_requests_total counter\n");
            out.push_str(&format!(
                "gw_http3_requests_total{{result=\"success\"}} {}\n",
                self.http3_requests_success_total.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_http3_requests_total{{result=\"error\"}} {}\n",
                self.http3_requests_error_total.load(Ordering::Relaxed)
            ));
            out.push_str("# HELP gw_http3_early_data_total HTTP/3 early data by fixed decision.\n");
            out.push_str("# TYPE gw_http3_early_data_total counter\n");
            for (index, decision) in [
                "accepted",
                "not_enabled",
                "non_idempotent_method",
                "sensitive_credential",
                "replayed",
                "missing_nonce",
                "missing_indicator",
                "invalid_indicator",
                "invalid_nonce",
                "request_body",
            ]
            .into_iter()
            .enumerate()
            {
                out.push_str(&format!(
                    "gw_http3_early_data_total{{decision=\"{decision}\"}} {}\n",
                    self.early_data_decisions_total[index].load(Ordering::Relaxed)
                ));
            }
            out.push_str(
                "# HELP gw_connect_udp_datagrams_total CONNECT-UDP datagrams by fixed direction.\n",
            );
            out.push_str("# TYPE gw_connect_udp_datagrams_total counter\n");
            out.push_str(&format!(
                "gw_connect_udp_datagrams_total{{direction=\"downstream_to_upstream\"}} {}\n",
                self.connect_udp_downstream_datagrams_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_connect_udp_datagrams_total{{direction=\"upstream_to_downstream\"}} {}\n",
                self.connect_udp_upstream_datagrams_total
                    .load(Ordering::Relaxed)
            ));
            render_counter(
                &mut out,
                "gw_connect_udp_dropped_datagrams_total",
                self.connect_udp_dropped_datagrams_total
                    .load(Ordering::Relaxed),
            );
            render_counter(
                &mut out,
                "gw_http3_dropped_datagrams_total",
                self.http3_dropped_datagrams_total.load(Ordering::Relaxed),
            );
            render_gauge(
                &mut out,
                "gw_webtransport_sessions_active",
                self.webtransport_sessions_active.load(Ordering::Relaxed),
            );
            out.push_str(
                "# HELP gw_webtransport_sessions_total WebTransport sessions by fixed result.\n",
            );
            out.push_str("# TYPE gw_webtransport_sessions_total counter\n");
            out.push_str(&format!(
                "gw_webtransport_sessions_total{{result=\"success\"}} {}\n",
                self.webtransport_sessions_success_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_webtransport_sessions_total{{result=\"error\"}} {}\n",
                self.webtransport_sessions_error_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(
                "# HELP gw_webtransport_streams_total WebTransport streams admitted by fixed type.\n",
            );
            out.push_str("# TYPE gw_webtransport_streams_total counter\n");
            out.push_str(&format!(
                "gw_webtransport_streams_total{{type=\"bidirectional\"}} {}\n",
                self.webtransport_bidi_streams_total.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_webtransport_streams_total{{type=\"unidirectional\"}} {}\n",
                self.webtransport_uni_streams_total.load(Ordering::Relaxed)
            ));
            out.push_str(
                "# HELP gw_webtransport_stream_rejections_total WebTransport streams rejected by fixed type.\n",
            );
            out.push_str("# TYPE gw_webtransport_stream_rejections_total counter\n");
            out.push_str(&format!(
                "gw_webtransport_stream_rejections_total{{type=\"bidirectional\"}} {}\n",
                self.webtransport_bidi_streams_rejected_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_webtransport_stream_rejections_total{{type=\"unidirectional\"}} {}\n",
                self.webtransport_uni_streams_rejected_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(
                "# HELP gw_webtransport_datagrams_total WebTransport datagrams by fixed direction.\n",
            );
            out.push_str("# TYPE gw_webtransport_datagrams_total counter\n");
            out.push_str(&format!(
                "gw_webtransport_datagrams_total{{direction=\"downstream_to_upstream\"}} {}\n",
                self.webtransport_downstream_datagrams_total
                    .load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "gw_webtransport_datagrams_total{{direction=\"upstream_to_downstream\"}} {}\n",
                self.webtransport_upstream_datagrams_total
                    .load(Ordering::Relaxed)
            ));
            render_counter(
                &mut out,
                "gw_webtransport_dropped_datagrams_total",
                self.webtransport_dropped_datagrams_total
                    .load(Ordering::Relaxed),
            );
            render_gauge(
                &mut out,
                "gw_upstream_http3_connections_active",
                self.upstream_http3_connections_active
                    .load(Ordering::Relaxed),
            );
            render_counter(
                &mut out,
                "gw_upstream_http3_connections_created_total",
                self.upstream_http3_connections_created_total
                    .load(Ordering::Relaxed),
            );
            render_counter(
                &mut out,
                "gw_upstream_http3_connection_errors_total",
                self.upstream_http3_connection_errors_total
                    .load(Ordering::Relaxed),
            );
            render_counter(
                &mut out,
                "gw_upstream_http3_goaway_total",
                self.upstream_http3_goaway_total.load(Ordering::Relaxed),
            );
        }
        render_gauge(&mut out, "gw_config_version", config_version);
        render_gauge(&mut out, "gw_upstream_services", upstream_services as u64);
        render_gauge(
            &mut out,
            "gw_upstream_unhealthy_instances",
            self.active_health_unhealthy.load(Ordering::Relaxed),
        );
        // 主动健康探测结果只使用固定 result=ok/fail 标签，不引入实例地址。
        out.push_str("# HELP gw_active_health_probe_total Active health probes by result.\n");
        out.push_str("# TYPE gw_active_health_probe_total counter\n");
        out.push_str(&format!(
            "gw_active_health_probe_total{{result=\"ok\"}} {}\n",
            self.active_health_probe_ok.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_active_health_probe_total{{result=\"fail\"}} {}\n",
            self.active_health_probe_fail.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP gw_content_coding_total Responses transformed by coding and direction.\n",
        );
        out.push_str("# TYPE gw_content_coding_total counter\n");
        for (direction, coding, value) in [
            (
                "encode",
                "gzip",
                self.compression_gzip_total.load(Ordering::Relaxed),
            ),
            (
                "encode",
                "br",
                self.compression_brotli_total.load(Ordering::Relaxed),
            ),
            (
                "decode",
                "gzip",
                self.decompression_gzip_total.load(Ordering::Relaxed),
            ),
            (
                "decode",
                "br",
                self.decompression_brotli_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_content_coding_total{{direction=\"{direction}\",coding=\"{coding}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_request_schema_total Requests by schema validation result.\n");
        out.push_str("# TYPE gw_request_schema_total counter\n");
        for (result, value) in [
            (
                "valid",
                self.request_schema_valid_total.load(Ordering::Relaxed),
            ),
            (
                "invalid",
                self.request_schema_invalid_total.load(Ordering::Relaxed),
            ),
            (
                "too_large",
                self.request_schema_too_large_total.load(Ordering::Relaxed),
            ),
            (
                "body_read_error",
                self.request_schema_body_read_error_total
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_request_schema_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_response_contract_total Responses by OpenAPI contract result.\n");
        out.push_str("# TYPE gw_response_contract_total counter\n");
        for (index, result) in [
            "valid",
            "invalid",
            "blocked",
            "replaced",
            "too_large",
            "body_read_error",
            "unsupported",
        ]
        .into_iter()
        .enumerate()
        {
            out.push_str(&format!(
                "gw_response_contract_total{{result=\"{result}\"}} {}\n",
                self.response_contract_total[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP gw_body_transform_total Body transformations by result.\n");
        out.push_str("# TYPE gw_body_transform_total counter\n");
        for (index, result) in ["transformed", "invalid", "too_large", "body_read_error"]
            .into_iter()
            .enumerate()
        {
            out.push_str(&format!(
                "gw_body_transform_total{{result=\"{result}\"}} {}\n",
                self.body_transform_total[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP gw_graphql_guard_total GraphQL requests by bounded guard result.\n");
        out.push_str("# TYPE gw_graphql_guard_total counter\n");
        for (result, value) in [
            (
                "allowed",
                self.graphql_allowed_total.load(Ordering::Relaxed),
            ),
            (
                "invalid",
                self.graphql_invalid_total.load(Ordering::Relaxed),
            ),
            (
                "too_large",
                self.graphql_too_large_total.load(Ordering::Relaxed),
            ),
            (
                "too_deep",
                self.graphql_too_deep_total.load(Ordering::Relaxed),
            ),
            (
                "too_complex",
                self.graphql_too_complex_total.load(Ordering::Relaxed),
            ),
            (
                "introspection_denied",
                self.graphql_introspection_denied_total
                    .load(Ordering::Relaxed),
            ),
            (
                "body_read_error",
                self.graphql_body_read_error_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_graphql_guard_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_waf_requests_total WAF interventions by fixed outcome.\n");
        out.push_str("# TYPE gw_waf_requests_total counter\n");
        for (result, value) in [
            (
                "monitored",
                self.waf_monitored_total.load(Ordering::Relaxed),
            ),
            ("blocked", self.waf_blocked_total.load(Ordering::Relaxed)),
            (
                "too_large",
                self.waf_too_large_total.load(Ordering::Relaxed),
            ),
            (
                "body_read_error",
                self.waf_body_read_error_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_waf_requests_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP gw_geoip_decisions_total GeoIP decisions by fixed low-cardinality result.\n",
        );
        out.push_str("# TYPE gw_geoip_decisions_total counter\n");
        for (index, result) in [
            "allowed",
            "country_denied",
            "asn_denied",
            "anonymous_denied",
            "not_found_allowed",
            "not_found_denied",
            "lookup_error_allowed",
            "lookup_error_denied",
            "stale_allowed",
            "stale_denied",
        ]
        .into_iter()
        .enumerate()
        {
            out.push_str(&format!(
                "gw_geoip_decisions_total{{result=\"{result}\"}} {}\n",
                self.geoip_decisions_total[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str(
            "# HELP gw_bot_decisions_total Bot decisions by fixed low-cardinality result.\n",
        );
        out.push_str("# TYPE gw_bot_decisions_total counter\n");
        for (index, result) in [
            "allowed",
            "trusted",
            "user_agent_blocked",
            "user_agent_monitored",
            "fingerprint_blocked",
            "fingerprint_monitored",
            "behavior_blocked",
            "behavior_monitored",
            "trusted_claim_invalid_blocked",
            "trusted_claim_invalid_monitored",
            "rate_blocked",
            "rate_monitored",
        ]
        .into_iter()
        .enumerate()
        {
            out.push_str(&format!(
                "gw_bot_decisions_total{{result=\"{result}\"}} {}\n",
                self.bot_decisions_total[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str(
            "# HELP gw_csrf_decisions_total CSRF decisions by fixed low-cardinality result.\n",
        );
        out.push_str("# TYPE gw_csrf_decisions_total counter\n");
        for (index, result) in [
            "safe_method",
            "allowed",
            "origin_blocked",
            "origin_monitored",
            "token_missing_blocked",
            "token_missing_monitored",
            "token_invalid_blocked",
            "token_invalid_monitored",
        ]
        .into_iter()
        .enumerate()
        {
            out.push_str(&format!(
                "gw_csrf_decisions_total{{result=\"{result}\"}} {}\n",
                self.csrf_decisions_total[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str(
            "# HELP gw_dlp_decisions_total DLP actions by fixed low-cardinality result.\n",
        );
        out.push_str("# TYPE gw_dlp_decisions_total counter\n");
        for (index, result) in [
            "monitored",
            "redacted",
            "blocked",
            "too_large",
            "body_read_error",
            "invalid",
        ]
        .into_iter()
        .enumerate()
        {
            out.push_str(&format!(
                "gw_dlp_decisions_total{{result=\"{result}\"}} {}\n",
                self.dlp_decisions_total[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP gw_opa_decisions_total Final OPA authorization decisions.\n");
        out.push_str("# TYPE gw_opa_decisions_total counter\n");
        for (result, value) in [
            (
                "allow",
                self.opa_decision_allow_total.load(Ordering::Relaxed),
            ),
            ("deny", self.opa_decision_deny_total.load(Ordering::Relaxed)),
            (
                "fail_open",
                self.opa_decision_fail_open_total.load(Ordering::Relaxed),
            ),
            (
                "unavailable",
                self.opa_decision_unavailable_total.load(Ordering::Relaxed),
            ),
            (
                "invalid_input",
                self.opa_decision_invalid_input_total
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_opa_decisions_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_opa_cache_total OPA decision L1 lookups.\n");
        out.push_str("# TYPE gw_opa_cache_total counter\n");
        for (result, value) in [
            ("hit", self.opa_cache_hit_total.load(Ordering::Relaxed)),
            ("miss", self.opa_cache_miss_total.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!(
                "gw_opa_cache_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_opa_requests_total Real OPA HTTP attempts.\n");
        out.push_str("# TYPE gw_opa_requests_total counter\n");
        for (result, value) in [
            (
                "success",
                self.opa_request_success_total.load(Ordering::Relaxed),
            ),
            (
                "error",
                self.opa_request_error_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_opa_requests_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP gw_casbin_decisions_total Final embedded Casbin authorization decisions.\n",
        );
        out.push_str("# TYPE gw_casbin_decisions_total counter\n");
        for (result, value) in [
            ("allow", self.casbin_allow_total.load(Ordering::Relaxed)),
            ("deny", self.casbin_deny_total.load(Ordering::Relaxed)),
            (
                "fail_open",
                self.casbin_fail_open_total.load(Ordering::Relaxed),
            ),
            ("error", self.casbin_error_total.load(Ordering::Relaxed)),
            (
                "invalid_input",
                self.casbin_invalid_input_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_casbin_decisions_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_wasm_executions_total Proxy-Wasm phase-chain executions.\n");
        out.push_str("# TYPE gw_wasm_executions_total counter\n");
        for (result, value) in [
            ("continue", self.wasm_continue_total.load(Ordering::Relaxed)),
            (
                "local_response",
                self.wasm_local_response_total.load(Ordering::Relaxed),
            ),
            (
                "fail_open",
                self.wasm_fail_open_total.load(Ordering::Relaxed),
            ),
            ("error", self.wasm_error_total.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!(
                "gw_wasm_executions_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP gw_external_plugin_calls_total External HTTP plugin calls by final result.\n",
        );
        out.push_str("# TYPE gw_external_plugin_calls_total counter\n");
        for (result, value) in [
            (
                "continue",
                self.external_plugin_continue_total.load(Ordering::Relaxed),
            ),
            (
                "local_response",
                self.external_plugin_local_response_total
                    .load(Ordering::Relaxed),
            ),
            (
                "fail_open",
                self.external_plugin_fail_open_total.load(Ordering::Relaxed),
            ),
            (
                "error",
                self.external_plugin_error_total.load(Ordering::Relaxed),
            ),
            (
                "invalid_input",
                self.external_plugin_invalid_input_total
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_external_plugin_calls_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_usage_plan_requests_total Usage Plan decisions by final result.\n");
        out.push_str("# TYPE gw_usage_plan_requests_total counter\n");
        for (result, value) in [
            (
                "allowed",
                self.usage_plan_allowed_total.load(Ordering::Relaxed),
            ),
            (
                "limited",
                self.usage_plan_limited_total.load(Ordering::Relaxed),
            ),
            (
                "unmapped",
                self.usage_plan_unmapped_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_usage_plan_requests_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP gw_developer_key_applications_total Developer key application submissions.\n",
        );
        out.push_str("# TYPE gw_developer_key_applications_total counter\n");
        for (result, value) in [
            (
                "accepted",
                self.developer_application_accepted_total
                    .load(Ordering::Relaxed),
            ),
            (
                "rejected",
                self.developer_application_rejected_total
                    .load(Ordering::Relaxed),
            ),
            (
                "error",
                self.developer_application_error_total
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_developer_key_applications_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_degraphql_total REST to GraphQL transformations.\n");
        out.push_str("# TYPE gw_degraphql_total counter\n");
        out.push_str(&format!(
            "gw_degraphql_total{{result=\"transformed\"}} {}\n",
            self.degraphql_transformed_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_degraphql_total{{result=\"rejected\"}} {}\n",
            self.degraphql_rejected_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP gw_dubbo_calls_total HTTP to Dubbo generic calls.\n");
        out.push_str("# TYPE gw_dubbo_calls_total counter\n");
        for (result, value) in [
            ("success", self.dubbo_success_total.load(Ordering::Relaxed)),
            (
                "remote_error",
                self.dubbo_remote_error_total.load(Ordering::Relaxed),
            ),
            (
                "protocol_error",
                self.dubbo_protocol_error_total.load(Ordering::Relaxed),
            ),
            ("timeout", self.dubbo_timeout_total.load(Ordering::Relaxed)),
            (
                "invalid_input",
                self.dubbo_invalid_input_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_dubbo_calls_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_upstream_prewarm_total Upstream pool prewarm batches.\n");
        out.push_str("# TYPE gw_upstream_prewarm_total counter\n");
        out.push_str(&format!(
            "gw_upstream_prewarm_total{{result=\"success\"}} {}\n",
            self.upstream_prewarm_success_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_upstream_prewarm_total{{result=\"error\"}} {}\n",
            self.upstream_prewarm_error_total.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP gw_registry_polls_total Background registry polls by backend and result.\n",
        );
        out.push_str("# TYPE gw_registry_polls_total counter\n");
        for (index, registry) in ["consul", "eureka", "dns", "kubernetes"]
            .into_iter()
            .enumerate()
        {
            for (result, value) in [
                (
                    "success",
                    self.registry_poll_success_total[index].load(Ordering::Relaxed),
                ),
                (
                    "error",
                    self.registry_poll_error_total[index].load(Ordering::Relaxed),
                ),
                (
                    "timeout",
                    self.registry_poll_timeout_total[index].load(Ordering::Relaxed),
                ),
                (
                    "invalid_snapshot",
                    self.registry_poll_invalid_snapshot_total[index].load(Ordering::Relaxed),
                ),
            ] {
                out.push_str(&format!(
                    "gw_registry_polls_total{{registry=\"{registry}\",result=\"{result}\"}} {value}\n"
                ));
            }
        }
        out.push_str("# HELP gw_bff_requests_total BFF aggregation requests by result.\n");
        out.push_str("# TYPE gw_bff_requests_total counter\n");
        for (result, value) in [
            (
                "success",
                self.bff_request_success_total.load(Ordering::Relaxed),
            ),
            (
                "error",
                self.bff_request_error_total.load(Ordering::Relaxed),
            ),
            (
                "timeout",
                self.bff_request_timeout_total.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_bff_requests_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_bff_targets_total BFF child requests by result.\n");
        out.push_str("# TYPE gw_bff_targets_total counter\n");
        out.push_str(&format!(
            "gw_bff_targets_total{{result=\"success\"}} {}\n",
            self.bff_target_success_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_bff_targets_total{{result=\"error\"}} {}\n",
            self.bff_target_error_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP gw_fault_injections_total Chaos injections by action.\n");
        out.push_str("# TYPE gw_fault_injections_total counter\n");
        out.push_str(&format!(
            "gw_fault_injections_total{{action=\"delay\"}} {}\n",
            self.fault_delayed_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_fault_injections_total{{action=\"abort\"}} {}\n",
            self.fault_aborted_total.load(Ordering::Relaxed)
        ));
        render_counter(
            &mut out,
            "gw_mock_responses_total",
            self.mock_responses_total.load(Ordering::Relaxed),
        );
        out.push_str("# HELP gw_http_cache_requests_total Cacheable requests by L1 result.\n");
        out.push_str("# TYPE gw_http_cache_requests_total counter\n");
        out.push_str(&format!(
            "gw_http_cache_requests_total{{result=\"hit\"}} {}\n",
            self.http_cache_hits_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_http_cache_requests_total{{result=\"miss\"}} {}\n",
            self.http_cache_misses_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP gw_http_cache_l2_requests_total Redis L2 cache reads by result.\n");
        out.push_str("# TYPE gw_http_cache_l2_requests_total counter\n");
        out.push_str(&format!(
            "gw_http_cache_l2_requests_total{{result=\"hit\"}} {}\n",
            self.http_cache_l2_hits_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_http_cache_l2_requests_total{{result=\"miss\"}} {}\n",
            self.http_cache_l2_misses_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_http_cache_l2_requests_total{{result=\"error\"}} {}\n",
            self.http_cache_l2_errors_total.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP gw_http_cache_l2_stores_total Asynchronous Redis L2 fills by result.\n",
        );
        out.push_str("# TYPE gw_http_cache_l2_stores_total counter\n");
        out.push_str(&format!(
            "gw_http_cache_l2_stores_total{{result=\"ok\"}} {}\n",
            self.http_cache_l2_store_ok_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_http_cache_l2_stores_total{{result=\"error\"}} {}\n",
            self.http_cache_l2_store_errors_total
                .load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP gw_http_cache_invalidations_total Route generation invalidations by result.\n",
        );
        out.push_str("# TYPE gw_http_cache_invalidations_total counter\n");
        out.push_str(&format!(
            "gw_http_cache_invalidations_total{{result=\"ok\"}} {}\n",
            self.http_cache_invalidation_ok_total
                .load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "gw_http_cache_invalidations_total{{result=\"error\"}} {}\n",
            self.http_cache_invalidation_errors_total
                .load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP gw_http_cache_singleflight_total Local cache miss collapsing outcomes.\n",
        );
        out.push_str("# TYPE gw_http_cache_singleflight_total counter\n");
        for (result, value) in [
            (
                "leader",
                self.http_cache_singleflight_leader_total
                    .load(Ordering::Relaxed),
            ),
            (
                "follower",
                self.http_cache_singleflight_follower_total
                    .load(Ordering::Relaxed),
            ),
            (
                "wait_hit",
                self.http_cache_singleflight_wait_hit_total
                    .load(Ordering::Relaxed),
            ),
            (
                "timeout",
                self.http_cache_singleflight_timeout_total
                    .load(Ordering::Relaxed),
            ),
            (
                "bypass",
                self.http_cache_singleflight_bypass_total
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_http_cache_singleflight_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP gw_http_cache_stale_total Stale responses served by SWR.\n");
        out.push_str("# TYPE gw_http_cache_stale_total counter\n");
        out.push_str(&format!(
            "gw_http_cache_stale_total {}\n",
            self.http_cache_stale_total.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP gw_http_cache_revalidations_total Background SWR revalidations by result.\n",
        );
        out.push_str("# TYPE gw_http_cache_revalidations_total counter\n");
        for (result, value) in [
            (
                "ok",
                self.http_cache_revalidation_ok_total
                    .load(Ordering::Relaxed),
            ),
            (
                "error",
                self.http_cache_revalidation_errors_total
                    .load(Ordering::Relaxed),
            ),
            (
                "skipped",
                self.http_cache_revalidation_skipped_total
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_http_cache_revalidations_total{{result=\"{result}\"}} {value}\n"
            ));
        }
        out.push_str(
            "# HELP gw_upstream_identity_entries Resident upstream runtime identity entries by fixed state kind.\n",
        );
        out.push_str("# TYPE gw_upstream_identity_entries gauge\n");
        for (kind, value) in [
            (
                "inflight",
                self.upstream_identity_inflight_entries
                    .load(Ordering::Relaxed),
            ),
            (
                "pending",
                self.upstream_identity_pending_entries
                    .load(Ordering::Relaxed),
            ),
            (
                "round_robin",
                self.upstream_identity_rr_entries.load(Ordering::Relaxed),
            ),
            (
                "physical_budget",
                self.upstream_identity_budget_entries
                    .load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "gw_upstream_identity_entries{{kind=\"{kind}\"}} {value}\n"
            ));
        }
        out
    }
}

/// 业务作用：把日志出口的累计事实渲染为 Prometheus 序列，标签只来自固定出口目录。
fn render_log_sink_metrics(out: &mut String, metrics: &Metrics) {
    let stats = metrics
        .log_sink_stats
        .lock()
        .expect("log sink metrics mutex poisoned")
        .clone();
    out.push_str("# HELP gw_log_dropped_total Access log records dropped by sink and reason.\n");
    out.push_str("# TYPE gw_log_dropped_total counter\n");
    out.push_str(&format!(
        "gw_log_dropped_total{{sink=\"dispatcher\",reason=\"queue_full\"}} {}\n",
        metrics.access_log_dropped_total.load(Ordering::Relaxed)
    ));
    for (sink, value) in &stats {
        for (reason, count) in [
            ("queue_full", value.dropped_queue_full),
            ("delivery", value.dropped_delivery),
            ("oversized", value.dropped_oversized),
            ("encode", value.dropped_encode),
        ] {
            out.push_str(&format!(
                "gw_log_dropped_total{{sink=\"{sink}\",reason=\"{reason}\"}} {count}\n"
            ));
        }
    }
    out.push_str("# HELP gw_log_sink_delivered_total Access log records delivered by sink.\n");
    out.push_str("# TYPE gw_log_sink_delivered_total counter\n");
    out.push_str("# HELP gw_log_sink_errors_total Access log batch errors by sink.\n");
    out.push_str("# TYPE gw_log_sink_errors_total counter\n");
    for (sink, value) in &stats {
        out.push_str(&format!(
            "gw_log_sink_delivered_total{{sink=\"{sink}\"}} {}\n",
            value.delivered
        ));
        out.push_str(&format!(
            "gw_log_sink_errors_total{{sink=\"{sink}\"}} {}\n",
            value.errors
        ));
    }
}

/// 业务作用：输出模型路由的固定观测维度，不暴露提示、凭据或请求内容。
fn render_llm_metrics(out: &mut String, metrics: &Metrics) {
    let stats = metrics
        .llm_stats
        .lock()
        .expect("LLM metrics mutex poisoned")
        .clone();
    out.push_str("# HELP gw_llm_tokens_total Provider-reported LLM tokens by bounded identity.\n");
    out.push_str("# TYPE gw_llm_tokens_total counter\n");
    out.push_str("# HELP gw_llm_cost_usd_total Estimated provider cost in US dollars.\n");
    out.push_str("# TYPE gw_llm_cost_usd_total counter\n");
    out.push_str(
        "# HELP gw_llm_cache_hit_total LLM exact or semantic cache hits by local/Redis tier.\n",
    );
    out.push_str("# TYPE gw_llm_cache_hit_total counter\n");
    out.push_str(
        "# HELP gw_llm_moderation_total External moderation decisions by bounded result.\n",
    );
    out.push_str("# TYPE gw_llm_moderation_total counter\n");
    out.push_str("# HELP gw_ai_guardrail_blocked_total AI content delivery refusals by fixed direction and category.\n");
    out.push_str("# TYPE gw_ai_guardrail_blocked_total counter\n");
    for (direction_index, direction) in ["request", "response"].iter().enumerate() {
        for (index, category) in [
            "prompt_injection",
            "jailbreak",
            "pii",
            "secret",
            "content",
            "invalid",
        ]
        .iter()
        .enumerate()
        {
            let value = metrics.ai_guardrail_blocked_total[direction_index * 6 + index]
                .load(Ordering::Relaxed);
            out.push_str(&format!("gw_ai_guardrail_blocked_total{{direction=\"{direction}\",category=\"{category}\"}} {value}\n"));
        }
    }
    for (result, value) in [
        (
            "allowed",
            metrics.llm_moderation_allowed_total.load(Ordering::Relaxed),
        ),
        (
            "blocked",
            metrics.llm_moderation_blocked_total.load(Ordering::Relaxed),
        ),
        (
            "fail_open",
            metrics
                .llm_moderation_fail_open_total
                .load(Ordering::Relaxed),
        ),
        (
            "error",
            metrics.llm_moderation_error_total.load(Ordering::Relaxed),
        ),
    ] {
        out.push_str(&format!(
            "gw_llm_moderation_total{{result=\"{result}\"}} {value}\n"
        ));
    }
    for (level, tier, value) in [
        (
            "exact",
            "l1",
            metrics
                .llm_cache_exact_l1_hits_total
                .load(Ordering::Relaxed),
        ),
        (
            "exact",
            "l2",
            metrics
                .llm_cache_exact_l2_hits_total
                .load(Ordering::Relaxed),
        ),
        (
            "semantic",
            "l1",
            metrics
                .llm_cache_semantic_l1_hits_total
                .load(Ordering::Relaxed),
        ),
        (
            "semantic",
            "l2",
            metrics
                .llm_cache_semantic_l2_hits_total
                .load(Ordering::Relaxed),
        ),
    ] {
        out.push_str(&format!(
            "gw_llm_cache_hit_total{{level=\"{level}\",tier=\"{tier}\"}} {value}\n"
        ));
    }
    for (key, value) in stats {
        let route = prometheus_label_escape(&key.route);
        let model = prometheus_label_escape(&key.model);
        let consumer = prometheus_label_escape(&key.consumer);
        for (direction, tokens) in [
            ("prompt", value.prompt_tokens),
            ("completion", value.completion_tokens),
        ] {
            out.push_str(&format!(
                "gw_llm_tokens_total{{route=\"{route}\",model=\"{model}\",consumer=\"{consumer}\",direction=\"{direction}\"}} {tokens}\n"
            ));
        }
        out.push_str(&format!(
            "gw_llm_cost_usd_total{{route=\"{route}\",model=\"{model}\",consumer=\"{consumer}\"}} {:.6}\n",
            value.cost_microusd as f64 / 1_000_000.0
        ));
    }
}

/// 业务作用：转义 Prometheus 标签的特殊字符，防止配置标识改变指标文本结构。
fn prometheus_label_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// 业务作用：按 Prometheus 合同输出累计计数，保持指标类型与采样值一致。
fn render_counter(out: &mut String, name: &str, val: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push_str(" Gateway counter.\n# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&val.to_string());
    out.push('\n');
}

/// 业务作用：输出当前状态量的 Prometheus 表示，不把瞬时值声明为累计计数。
fn render_gauge(out: &mut String, name: &str, val: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push_str(" Gateway gauge.\n# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&val.to_string());
    out.push('\n');
}

/// 业务作用：把请求时延桶、总数与总和一起输出，保持直方图统计口径一致。
fn render_request_duration(out: &mut String, metrics: &Metrics) {
    out.push_str("# HELP gw_request_duration_seconds HTTP request time to response head.\n");
    out.push_str("# TYPE gw_request_duration_seconds histogram\n");
    let mut cumulative = 0_u64;
    for (idx, bucket_ms) in REQUEST_DURATION_BUCKET_MS.iter().enumerate() {
        cumulative = cumulative.saturating_add(metrics.request_duration_buckets[idx].load());
        let seconds = *bucket_ms as f64 / 1_000.0;
        out.push_str("gw_request_duration_seconds_bucket{le=\"");
        out.push_str(&format!("{seconds:.3}"));
        out.push_str("\"} ");
        out.push_str(&cumulative.to_string());
        out.push('\n');
    }
    let count = metrics.request_duration_count.load();
    out.push_str("gw_request_duration_seconds_bucket{le=\"+Inf\"} ");
    out.push_str(&count.to_string());
    out.push('\n');
    let sum = metrics.request_duration_sum_micros.load() as f64 / 1_000_000.0;
    out.push_str("gw_request_duration_seconds_sum ");
    out.push_str(&format!("{sum:.6}"));
    out.push('\n');
    out.push_str("gw_request_duration_seconds_count ");
    out.push_str(&count.to_string());
    out.push('\n');
}
