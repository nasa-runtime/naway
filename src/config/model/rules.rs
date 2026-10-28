//! 接口守卫、流控、熔断与配额规则声明。

use super::*;

/// `interface-guard.yml` 的顶层文档。
#[derive(Debug, Deserialize, Default)]
pub struct GuardFile {
    /// 配置 schema 版本;按文件分别记录,缺省按 v1 处理并告警。
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
#[derive(Debug, Deserialize, Default, PartialEq, Eq)]
pub struct SentinelFile {
    /// 配置 schema 版本;按文件分别记录,缺省按 v1 处理并告警。
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// Sentinel FlowRule 列表，编译为 `limit_req` / `limit_conn` 两种原生动作。
    #[serde(default)]
    pub flow: Vec<SentinelFlowRuleCfg>,
    /// Sentinel DegradeRule 列表。编译为 route 资源级 circuit breaker。
    #[serde(default)]
    pub degrade: Vec<SentinelDegradeRuleCfg>,
}

/// 一条编译为 `limit_req` 或 `limit_conn` 的 Sentinel 流控规则。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SentinelFlowRuleCfg {
    /// 规则 id,用于错误定位和后续 Admin UI 编排。
    pub id: String,
    /// false 时忽略该规则,保留配置但不生效。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 绑定的 route id。按 route 精确绑定,后续可扩展 path/resource 维度。
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
    /// reject 为普通令牌桶；warmup 渐进放开速率；queue 在有界等待内匀速放行。
    #[serde(default = "default_sentinel_behavior")]
    pub behavior: String,
    /// 预热周期，毫秒；仅 warmup 模式可声明。
    #[serde(default)]
    pub warmup_ms: Option<u64>,
    /// 冷态速率除数；warmup 默认 3，其它模式禁止声明。
    #[serde(default)]
    pub cold_factor: Option<u16>,
    /// 连续无请求后重新预热的毫秒数；默认使用 warmup_ms。
    #[serde(default)]
    pub cold_after_ms: Option<u64>,
    /// 同维度共享的最大等待数，queue 必须显式声明1..4096。
    #[serde(default)]
    pub max_queue: Option<usize>,
    /// 入口绝对等待预算，queue 必须显式声明1..60000毫秒。
    #[serde(default)]
    pub max_wait_ms: Option<u64>,
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

/// 业务作用：未显式选择控制行为时保持原有快速拒绝令牌桶语义。
///
/// 参数说明: 无。
///
/// 返回：普通令牌桶的控制行为名。
pub(super) fn default_sentinel_behavior() -> String {
    "reject".to_owned()
}

/// 业务作用：为未显式声明的 `max_active_keys` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_sentinel_max_active_keys() -> usize {
    100_000
}

/// 业务作用：为未显式声明的 `active_keys_fail` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_sentinel_active_keys_fail() -> String {
    "open".to_string()
}

/// 一条编译为 route 级滑动窗口熔断器的 Sentinel 降级规则。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SentinelDegradeRuleCfg {
    /// 规则 id,用于错误定位和后续 Admin UI 编排。
    pub id: String,
    /// false 时忽略该规则,保留配置但不生效。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 绑定的 route id。
    pub route: String,
    /// 统计依据；默认按失败次数保护。
    #[serde(default)]
    pub strategy: SentinelDegradeStrategy,
    /// 失败次数策略的正整数阈值；比例策略禁止同时声明。
    #[serde(default)]
    pub failure_threshold: Option<u64>,
    /// 比例策略的万分比阈值，范围 1..=10000。
    #[serde(default)]
    pub ratio_bps: Option<u16>,
    /// 慢调用策略的响应头耗时阈值；包含转发及重试，不等待流式实体结束。
    #[serde(default)]
    pub slow_ms: Option<u64>,
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

/// 熔断窗口的观测依据；每条规则只启用一种策略。
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SentinelDegradeStrategy {
    #[default]
    ErrorCount,
    ErrorRatio,
    SlowRatio,
}

/// 业务作用：为未显式声明的 `key` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_sentinel_key() -> String {
    "ip".to_string()
}

/// 业务作用：为未显式声明的 `window_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_circuit_window_ms() -> u64 {
    10_000
}

/// 业务作用：为未显式声明的 `min_requests` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_circuit_min_requests() -> u64 {
    1
}

/// 业务作用：为未显式声明的 `break_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_circuit_break_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `fallback_status` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_circuit_fallback_status() -> u16 {
    503
}

/// 业务作用：为未显式声明的 `fallback_body` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_circuit_fallback_body() -> String {
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

/// 接口守卫/静态匹配类型。默认 `Glob` 接受 `path: /api/**` 配置；
/// `Exact`/`Prefix` 提供精确与前缀语义。Regex 默认禁用,此处不提供。
///
/// 显式类型决定匹配边界：关闭整棵路径子树时应使用 `Prefix`，不能把不含通配符的
/// `Glob` 当作前缀规则，否则子路径不在该规则的拒绝范围内。
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
    /// 匹配类型:`Exact`/`Prefix`/`Glob`(默认 `Glob`)。未知类型或未知字段直接 build 期报错,
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

/// 业务作用：为未显式声明的 `status` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_status() -> u16 {
    503
}

/// route 级双向带宽与成本型限额配置。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TrafficLimitCfg {
    /// 将本路由额度开始与结束事实交给独立持久 sink；未声明时不产生外部计量依赖。
    #[serde(default)]
    pub events: bool,
    /// 精确账本位置：local 或 redis；共享后端复用 runtime_state.rate_limiter 的已验证连接。
    #[serde(default = "default_traffic_limit_backend")]
    pub backend: String,
    /// 账本共享边界：route、service、global 或 shared:<name>；始终受配置工作区隔离。
    #[serde(default = "default_traffic_limit_scope")]
    pub scope: String,
    /// 限额维度键：global/ip/route/header:<n>/query:<n>；consumer/api_key 只接受冻结认证事实。
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
    /// 计数不可用时的处置：fail_open|fail_closed；缺省兼容 fail_open。
    #[serde(default = "default_traffic_limit_fail_mode")]
    pub fail_mode: String,
}

/// 业务作用：未显式授权共享依赖时保持进程内账本，不因其它 Redis 功能自动迁移额度。
///
/// 参数说明: 无。
///
/// 返回：本地后端配置名。
pub(super) fn default_traffic_limit_backend() -> String {
    "local".to_owned()
}

/// 业务作用：保持未显式声明共享边界的策略只约束当前入口路由。
///
/// 参数说明: 无。
///
/// 返回：路由作用域配置名，不隐式扩大到其它服务。
pub(super) fn default_traffic_limit_scope() -> String {
    "route".to_owned()
}

/// 业务作用：为流量治理选择不会跨调用方聚合的默认维度。
///
/// 参数说明: 无。
///
/// 返回：返回客户端 IP 维度配置名。
pub(super) fn default_traffic_limit_key() -> String {
    "ip".to_string()
}

/// 业务作用：定义本地流量计数不可用时的兼容处置，避免反序列化缺省值含义漂移。
///
/// 参数说明: 无。
///
/// 返回：返回 `fail_open`；需要强制保护的路由必须显式配置 `fail_closed`。
pub(super) fn default_traffic_limit_fail_mode() -> String {
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
    /// 单帧整形最长等待毫秒数；超界终止该方向，不提前发送已欠费字节。
    #[serde(default = "default_bandwidth_max_wait_ms")]
    pub max_wait_ms: u64,
}

/// 业务作用：为流式带宽等待设置有限期限，避免低速配置长期占用连接和保留帧。
///
/// 参数说明: 无。
///
/// 返回：默认上限 60000 毫秒，声明值也不得超过此边界。
pub(super) const fn default_bandwidth_max_wait_ms() -> u64 {
    60_000
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
    /// Redis 响应回执最长无进展毫秒数；超期不重建退款或补扣权威。
    #[serde(default = "default_quota_settlement_idle_ms")]
    pub settlement_idle_ms: u64,
    /// 可信计费的明确上游来源；仅用于 cost_source=trusted_usage。
    #[serde(default)]
    pub usage: Option<TrustedUsageCfg>,
}

/// 可信用量只选择固定 provider 解析器或一个明确响应头，客户端声明不进入此来源。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedUsageCfg {
    /// provider_tokens 或 response_header。
    pub source: String,
    /// response_header 必须指定唯一字段，provider_tokens 必须留空。
    #[serde(default)]
    pub header: String,
}

/// 业务作用：限制共享响应回执的闲置生命期，避免断流永久占用状态容量。
///
/// 参数说明: 无。
///
/// 返回：默认允许 60000 毫秒无响应帧进展。
pub(super) const fn default_quota_settlement_idle_ms() -> u64 {
    60_000
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
/// 参数说明: 无。
///
/// 返回：返回 `sliding_window`。
pub(super) fn default_quota_algorithm() -> String {
    "sliding_window".to_string()
}

/// 业务作用：定义额度耗尽时不隐式积压请求的默认动作。
///
/// 参数说明: 无。
///
/// 返回：返回 `reject`。
pub(super) fn default_quota_overflow() -> String {
    "reject".to_string()
}

/// 业务作用：限制显式延迟模式的默认排队请求数，避免过载时形成无界内存队列。
///
/// 参数说明: 无。
///
/// 返回：返回默认队列上限 128。
pub(super) const fn default_quota_max_queue() -> u64 {
    128
}

/// 业务作用：限制额度等待的默认时长，避免请求长期占用连接与并发槽。
///
/// 参数说明: 无。
///
/// 返回：返回 1000 毫秒。
pub(super) const fn default_quota_max_wait_ms() -> u64 {
    1_000
}

/// 业务作用：为未声明成本来源的额度规则提供一次请求一次计费的确定语义。
///
/// 参数说明: 无。
///
/// 返回：返回 `per_request`。
pub(super) fn default_quota_cost_source() -> String {
    "per_request".to_string()
}

/// 业务作用：为需要事后结算的成本来源预留最小准入额度。
///
/// 参数说明: 无。
///
/// 返回：返回 1 个额度单位。
pub(super) const fn default_quota_reserve() -> u64 {
    1
}

/// 业务作用：定义响应字节成本到额度单位的默认换算粒度。
///
/// 参数说明: 无。
///
/// 返回：返回每 1024 字节一个额度单位。
pub(super) const fn default_quota_bytes_per_unit() -> u64 {
    1_024
}

/// 业务作用：限制单请求事后结算的默认最大成本，防止异常响应击穿额度账本。
///
/// 参数说明: 无。
///
/// 返回：返回一百万个额度单位。
pub(super) const fn default_quota_max_actual() -> u64 {
    1_000_000
}
