//! 上游实例、健康、负载与连接策略声明。

use super::*;

/// 上游逻辑服务目录与进程级预热扫描参数。
#[derive(Debug, Deserialize)]
pub struct UpstreamsCfg {
    /// service name -> static instances. 示例:`routes[].uri = "lb://order"` 命中 `services.order`。
    #[serde(default)]
    pub services: HashMap<String, StaticServiceCfg>,
    /// 新实例连接预热扫描间隔。后台只扫描配置快照/RCU 发现表，不进入请求热路径。
    #[serde(default = "default_prewarm_scan_interval_ms")]
    pub prewarm_scan_interval_ms: u64,
}

impl Default for UpstreamsCfg {
    /// 业务作用：构造 `UpstreamsCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
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
    /// 非 Nacos 注册中心中的物理服务名/DNS host；缺省使用 map key。
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
    /// 上游负载均衡策略。先解析并支持 `round_robin`/`first`/`least_conn` 的配置形态。
    #[serde(default)]
    pub lb_policy: Option<String>,
    /// 兼容 示例里的 `lb: least_conn`。
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
    /// 可信 region/zone/subzone 分层与份额；未配置时保持全实例 LB 语义。
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
    /// HTTP 上游 TLS profile( `proxy_ssl_*`):自定义信任 CA、SNI/server_name 与客户端证书。
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
    /// 可选滑动窗口摘除；存在时替代连续失败阈值，按比例上限和独占探测恢复。
    #[serde(default)]
    pub outlier: Option<OutlierCfg>,
    /// 主动健康探测:缺省 = 关闭。配置后后台任务按间隔 TCP/HTTP/gRPC/UDP 探测每个实例,
    /// 连续成功/失败达阈值翻转健康态;不健康实例不进入 LB 候选(与被动摘除叠加,双保险)。
    #[serde(default)]
    pub health_check: Option<HealthCheckCfg>,
    /// 新静态/发现实例进入目录后，使用真实业务连接池主动建立空闲连接。None = 关闭。
    #[serde(default)]
    pub prewarm: Option<UpstreamPrewarmCfg>,
}

/// 显式启用的实例窗口摘除；省略整段时不创建窗口状态。
#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OutlierCfg {
    /// 统计窗口长度；固定划分为十六桶，不随请求量增长。
    pub window_ms: u64,
    /// 窗口达到此样本数后才可按比例摘除。
    pub min_samples: u64,
    /// 失败比例阈值；0 表示不使用失败比例。
    pub failure_percent: u32,
    /// 慢调用比例阈值；0 表示不使用慢调用比例。
    pub slow_percent: u32,
    /// 一次真实上游尝试达到此耗时即属于慢调用。
    pub slow_ms: u64,
    /// 同服务同时被动摘除比例的硬上限，按实例数向下取整，不允许摘光实例。
    pub max_ejection_percent: u32,
    /// 首次摘除的冷却时长，后续探测失败按倍数增长。
    pub base_ejection_ms: u64,
    /// 连续探测失败时冷却时长的硬上限。
    pub max_ejection_ms: u64,
    /// 独占恢复探测的最长执行时间，取消或超时不能作为恢复成功证据。
    pub probe_timeout_ms: u64,
}

impl Default for OutlierCfg {
    /// 业务作用：为显式启用的服务提供有最小样本和比例保护的保守摘除策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认十秒窗口、二十样本和最多一半实例摘除；不自动启用任何服务。
    fn default() -> Self {
        Self {
            window_ms: 10_000,
            min_samples: 20,
            failure_percent: 50,
            slow_percent: 50,
            slow_ms: 500,
            max_ejection_percent: 50,
            base_ejection_ms: 1_000,
            max_ejection_ms: 30_000,
            probe_timeout_ms: 5_000,
        }
    }
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
#[serde(deny_unknown_fields)]
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
    /// 原生 ORCA 带外订阅；使用实例同一 HTTP/2 authority 和 TLS 身份，不接受报告指定重定向。
    #[serde(default)]
    pub out_of_band: Option<crate::upstream::load::subscription::Config>,
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

/// 上游可信拓扑的本地优先、显式故障转移与同层加权策略。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UpstreamLocalityCfg {
    /// 本 Naway 数据面所在的可信 zone；仅与配置/发现 metadata 比较。
    pub local_zone: String,
    /// 本数据面所在的 region；声明后使用 targets 的分层模型，不混用单层 zone 列表。
    #[serde(default)]
    pub local_region: Option<String>,
    /// 本数据面的 subzone；只有同时声明 local_region 才能参与精确距离优先。
    #[serde(default, alias = "local_sub_zone")]
    pub local_subzone: Option<String>,
    /// 分层模型允许的拓扑目标，最多256项；同一 zone 的整体目标与细分目标不得重叠。
    #[serde(default)]
    pub targets: Vec<UpstreamLocalityTargetCfg>,
    /// locality 调度模式:
    /// - `failover`(默认)：单层按 zone 顺序，分层先按 priority 再按距离选择健康容量；
    /// - `weighted`：单层已声明 zone 同级，分层仅在同 priority 内按有效权重分配。
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

/// 已获配置授权的分层拓扑范围，不从客户端请求头获取位置、权重或优先级。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UpstreamLocalityTargetCfg {
    pub region: String,
    pub zone: String,
    /// 省略表示整个 region/zone；指定后只匹配该 subzone。
    #[serde(default, alias = "sub_zone")]
    pub subzone: Option<String>,
    /// 越小越优先，范围0..=65535；优先级先于地域距离，不同层不混合分流。
    #[serde(default)]
    pub priority: u32,
    /// 同层相对权重，范围1..=10000；每个健康实例再乘自身有效权重。
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 仍可服务但份额按 degraded_weight_percent 降低，不代替权威健康摘除。
    #[serde(default)]
    pub degraded: bool,
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
#[serde(deny_unknown_fields)]
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
    /// 可信静态 region；同名 zone 只有处于相同 region 时才属于同一拓扑范围。
    #[serde(default)]
    pub region: Option<String>,
    /// 可选可信静态 subzone，与 region/zone 一起参与分层选择。
    #[serde(default, alias = "sub_zone")]
    pub subzone: Option<String>,
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
    /// 命名客户端身份的归属与远程来源策略；只由已验证的凭据绑定器写入。
    #[serde(skip)]
    pub(crate) client_identity_policy_identity: Option<[u8; 32]>,
}

/// 业务作用：为未显式声明的 `weight` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_weight() -> u32 {
    1
}

/// 业务作用：为未显式声明的 `next_upstream_tries` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_next_upstream_tries() -> usize {
    3
}

/// 业务作用：为未显式声明的 `max_fails` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_max_fails() -> u32 {
    1
}

/// 业务作用：为未显式声明的 `fail_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_fail_timeout_ms() -> u64 {
    10_000
}

/// 业务作用：为未显式声明的 `r#type` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_health_check_type() -> String {
    "tcp".to_string()
}

/// 业务作用：为未显式声明的 `path` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_health_check_path() -> String {
    "/".to_string()
}

/// 业务作用：为未显式声明的 `interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_health_check_interval_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_health_check_timeout_ms() -> u64 {
    2_000
}

/// 业务作用：为未显式声明的 `prewarm_scan_interval_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_prewarm_scan_interval_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `connections` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_prewarm_connections() -> usize {
    1
}

/// 业务作用：为未显式声明的 `path` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_prewarm_path() -> String {
    "/".to_owned()
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_prewarm_timeout_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `healthy_threshold` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_healthy_threshold() -> u32 {
    1
}

/// 业务作用：为未显式声明的 `unhealthy_threshold` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_unhealthy_threshold() -> u32 {
    3
}
