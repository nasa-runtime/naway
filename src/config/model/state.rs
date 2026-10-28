//! 共享运行态后端与动态防护声明。

use super::*;

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

/// 可跨节点共享的限流、动态集合、熔断和缓存运行态配置。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuntimeStateCfg {
    /// 可选独立流量成本事件 sink；只有显式 traffic_limit.events 的路由使用，连接与容量变更需要重启。
    #[serde(default)]
    pub traffic_meter: Option<crate::observability::meter::MeterCfg>,
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
    /// 熔断滑动窗口统计后端。默认本地各自统计;显式开启后跨节点共享统计。
    #[serde(default)]
    pub circuit_breaker: CircuitStatsBackendCfg,
    /// HMAC 防重放守卫后端。默认本地各自去重;`redis` 跨节点 `SET NX PX` 去重。
    #[serde(default)]
    pub replay_guard: ReplayGuardBackendCfg,
    /// HTTP 响应缓存的共享 L2 后端。默认 local/off，保持网关零外部依赖；
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
    /// 业务作用：构造 `HttpCacheBackendCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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

/// HMAC 防重放守卫后端配置( `SET NX PX` ReplayGuard)。
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
    /// 业务作用：构造 `ReplayGuardBackendCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            backend: default_replay_guard_backend(),
            fail_mode: default_replay_guard_fail_mode(),
        }
    }
}

/// 业务作用：防重放后端默认类型:本地内存去重,零外部依赖。
pub(super) fn default_replay_guard_backend() -> String {
    "local".to_string()
}

/// 业务作用：防重放后端默认失败策略:fail-open(不硬依赖 Redis)。
pub(super) fn default_replay_guard_fail_mode() -> String {
    "open".to_string()
}

/// 熔断滑动窗口统计的进程内或共享后端配置。
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
    /// Sentinel/limit_req 的有界本地批领；省略时每次请求仍执行共享令牌桶。
    #[serde(default)]
    pub local_preallocation: Option<RatePreallocationCfg>,
}

impl Default for RateLimiterBackendCfg {
    /// 业务作用：构造 `RateLimiterBackendCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            backend: default_rate_limiter_backend(),
            fail_mode: default_rate_limiter_fail_mode(),
            redis: RedisRuntimeCfg::default(),
            local_preallocation: None,
        }
    }
}

/// 共享桶预扣额度的本地使用边界；总未结算额度上限覆盖同一桶的全部网关节点。
#[derive(Debug, Deserialize, serde::Serialize, Clone, Copy, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RatePreallocationCfg {
    /// 一次最多预扣的令牌数；共享桶不足时可以领取更小批次。
    pub batch_size: u64,
    /// Redis 与本地权威的最长保留毫秒数；网络往返时间计入本地期限。
    pub lease_ms: u64,
    /// 同一共享桶全部未结算批次的总令牌上限，也是延迟使用引入的突发误差上界。
    pub max_outstanding_tokens: u64,
    /// 每个后端最多保留的本地维度数；工作区与进程总预算仍额外生效。
    pub max_local_keys: usize,
}

impl Default for RatePreallocationCfg {
    /// 业务作用：提供小批次、短权威期限和有限维度的显式启用默认值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：每批8令牌、100毫秒期限、全桶32未结算令牌和4096本地维度。
    fn default() -> Self {
        Self {
            batch_size: 8,
            lease_ms: 100,
            max_outstanding_tokens: 32,
            max_local_keys: 4096,
        }
    }
}

impl RateLimiterBackendCfg {
    /// 业务作用：在候选发布前拒绝缺少制品能力、错误后端和无界预扣声明。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未启用或全部边界有效时成功；不支持的能力与超限配置直接拒绝候选。
    pub(crate) fn validate_preallocation(&self) -> anyhow::Result<()> {
        let Some(cfg) = self.local_preallocation else {
            return Ok(());
        };
        anyhow::ensure!(
            cfg!(feature = "rate-preallocation"),
            "local_preallocation requires feature `rate-preallocation`"
        );
        anyhow::ensure!(
            self.backend.trim().eq_ignore_ascii_case("redis"),
            "local_preallocation requires rate_limiter.backend=redis"
        );
        anyhow::ensure!(
            (1..=4096).contains(&cfg.batch_size),
            "local_preallocation.batch_size must be 1..=4096"
        );
        anyhow::ensure!(
            (20..=1000).contains(&cfg.lease_ms),
            "local_preallocation.lease_ms must be 20..=1000"
        );
        anyhow::ensure!(
            (cfg.batch_size..=4096).contains(&cfg.max_outstanding_tokens),
            "local_preallocation.max_outstanding_tokens must be batch_size..=4096"
        );
        anyhow::ensure!(
            (1..=65_536).contains(&cfg.max_local_keys),
            "local_preallocation.max_local_keys must be 1..=65536"
        );
        Ok(())
    }
}

impl RatePreallocationCfg {
    /// 业务作用：保证批领规则的 Lua 数值与 Redis 到期时间可准确表达，不把无效规则留到数据面降级。
    ///
    /// 参数说明：
    /// - `limit`：每个补充窗口的基础令牌数。
    /// - `window`：基础令牌的补充周期。
    /// - `burst`：额外突发容量。
    ///
    /// 返回：容量与补满时间都处于有限边界时成功；零规则、溢出或不支持的数值范围拒绝。
    pub(crate) fn validate_rule(
        limit: u64,
        window: std::time::Duration,
        burst: u64,
    ) -> anyhow::Result<()> {
        let capacity = limit
            .checked_add(burst)
            .ok_or_else(|| anyhow::anyhow!("preallocated token capacity overflow"))?;
        let refill = limit as f64 / window.as_secs_f64();
        let lifetime = capacity as f64 / refill * 1000.0 + 1000.0;
        anyhow::ensure!(limit > 0 && !window.is_zero() && capacity <= (1_u64 << 52) && refill >= 0.000000000001 && refill.is_finite() && lifetime <= 31_536_001_000.0 && window.as_millis() <= 31_536_000_000, "preallocated rate rule requires positive finite refill, capacity <= 2^52 and refill/window duration <= one year");
        Ok(())
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
    /// 业务作用：构造 `DynamicStoreBackendCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 参数说明: 无。
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
    /// 业务作用：构造 `FileStoreCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `RedisStoreCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `BlacklistCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `InterfaceDisableCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 解封后短期豁免窗口(ms,「ban/unban 抖动」)。手工解封某 IP 后,本节点在该窗口内
    /// **不再自动拉黑**它,避免刚解封又被限流信号立刻 auto-ban 的抖动。0 = 关闭(默认)。
    #[serde(default)]
    pub unban_exempt_ms: u64,
}

impl Default for AutoBanCfg {
    /// 业务作用：构造 `AutoBanCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 业务作用：构造 `RedisRuntimeCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_runtime_redis_namespace(),
            profile: default_runtime_redis_profile(),
        }
    }
}

/// 业务作用：为未显式声明的 `backend` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_rate_limiter_backend() -> String {
    "local".to_string()
}

/// 业务作用：为未显式声明的 `fail_mode` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_rate_limiter_fail_mode() -> String {
    "open".to_string()
}

/// 业务作用：为未显式声明的 `backend` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_dynamic_store_backend() -> String {
    "file".to_string()
}

/// 业务作用：为未显式声明的 `root` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_dynamic_store_file_root() -> String {
    "runtime-state".to_string()
}

/// 业务作用：为未显式声明的 `prefix` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_dynamic_store_redis_prefix() -> String {
    "gw:dynamic".to_string()
}

/// 业务作用：为未显式声明的 `data_id_prefix` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_dynamic_store_nacos_prefix() -> String {
    "naway.dynamic".to_string()
}

/// 业务作用：为未显式声明的 `max_document_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_dynamic_store_nacos_max_document_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：为未显式声明的 `collection` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_blacklist_collection() -> String {
    "acl_blacklist".to_string()
}

/// 业务作用：为未显式声明的 `refresh_interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_blacklist_refresh_interval_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `collection` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_interface_disable_collection() -> String {
    "interface_disable".to_string()
}

/// 业务作用：为未显式声明的 `refresh_interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_interface_disable_refresh_interval_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `limit_req_rejections` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_auto_ban_limit_req_rejections() -> u64 {
    10
}

/// 业务作用：为未显式声明的 `window_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_auto_ban_window_ms() -> u64 {
    60_000
}

/// 业务作用：为未显式声明的 `ban_ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_auto_ban_ttl_ms() -> u64 {
    300_000
}

/// 业务作用：提供共享运行态 Redis key 的默认品牌 namespace，隔离不同网关产品的状态。
///
/// 参数说明: 无。
///
/// 返回：返回 `naway`；部署可通过显式配置覆盖。
pub(super) fn default_runtime_redis_namespace() -> String {
    "naway".to_string()
}

/// 业务作用：为未显式声明的 `profile` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_runtime_redis_profile() -> String {
    "RustV2".to_string()
}

/// 业务作用：为未显式声明的 `backend` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_http_cache_backend() -> String {
    "local".to_string()
}

/// 业务作用：为未显式声明的 `prefix` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_http_cache_redis_prefix() -> String {
    "gw:http-cache:v1".to_string()
}

/// 业务作用：为未显式声明的 `invalidation_channel` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_http_cache_invalidation_channel() -> String {
    "gw:http-cache:invalidate:v1".to_string()
}

/// 业务作用：为未显式声明的 `reconcile_interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_http_cache_reconcile_interval_ms() -> u64 {
    5_000
}
