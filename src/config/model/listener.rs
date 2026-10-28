//! HTTP 入口、连接预算与超时声明。

use super::*;

#[derive(Debug, Deserialize, Clone)]
/// 旧版单 HTTP proxy 入口配置；新配置应优先使用 `proxies[]`。
pub struct ServerCfg {
    /// 数据面监听地址(对外流量)。
    pub listen: String,
    /// 可选 TLS 数据面监听。明文与 TLS 是两个 socket,不做同端口 sniffing。
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// HTTP/3/QUIC；UDP 端口固定复用 `tls.listen` 的数值端口。
    #[serde(default)]
    pub http3: Http3Cfg,
    /// 数据面资源上限:请求头/body/h2 stream 等预算必须在执行点生效。
    #[serde(default)]
    pub limits: ServerLimitsCfg,
    /// 数据面超时预算:连接空闲、上游响应头等。
    #[serde(default)]
    pub timeouts: TimeoutCfg,
    /// 可信前置代理网段；语义同 `ProxyCfg.trusted_proxies`。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

/// 一个数据面入口:独立监听地址、可选 TLS、PROXY protocol、路由表和资源预算。
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyCfg {
    /// 入口唯一标识,用于日志/metrics/reload 拓扑比较。
    pub id: String,
    /// 明文数据面监听地址。
    pub listen: String,
    /// 是否实际绑定明文 listener。默认 true；false 只用于独立 TLS-only proxy，且必须配置 tls。
    #[serde(default = "default_true")]
    pub plain_enabled: bool,
    /// 可选 TLS 监听。明文与 TLS 分 socket。
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// HTTP/3/QUIC；关闭时不建立 UDP listener，也不改变 h1/h2 行为。
    #[serde(default)]
    pub http3: Http3Cfg,
    /// server_name/Host 别名。空表示 default_server。
    #[serde(default)]
    pub server_names: Vec<String>,
    /// Gateway API 共享 HTTP/HTTPS socket 上的逻辑 listener。请求管线先按 Host 选择
    /// listener 隔离路由；HTTPS 再与 TLS SNI 的选择结果比较，不一致时返回 421。
    #[serde(default)]
    pub gateway_listeners: Vec<GatewayListenerCfg>,
    /// 可信前置代理网段：只有来自这些 CIDR 的直连对端，才信任其
    /// `X-Forwarded-For` / `traceparent` 等入站头(取真实客户端 IP、续用 trace);否则一律用 socket
    /// 对端并重生成 trace,防伪造绕过 IP ACL / 限流 / 审计。空 = 不信任任何 XFF(安全默认)。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// PROXY protocol v1/v2 真实客户端地址解析配置。
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolCfg,
    /// 当前入口的资源上限;缺省继承模型默认值。
    #[serde(default)]
    pub limits: ServerLimitsCfg,
    /// 当前入口的超时预算;缺省继承模型默认值。
    #[serde(default)]
    pub timeouts: TimeoutCfg,
    /// 当前入口下的有序路由表。
    #[serde(default)]
    pub routes: Vec<RouteCfg>,
    /// HTTP→HTTPS 跳转:明文入口收到请求即 3xx 跳到本 proxy 的 TLS 端口
    /// (对齐 nginx `listen 80; return 308 https://$host$request_uri`)。需同时配 `tls`。
    #[serde(default)]
    pub redirect_https: bool,
    /// 跳转状态码,默认 308(永久 + 保持方法);也可 301。仅 `redirect_https=true` 时生效。
    #[serde(default = "default_redirect_https_status")]
    pub redirect_https_status: u16,
    /// HSTS `max-age`(秒);>0 时在【TLS 响应】带 `Strict-Transport-Security`。
    /// 默认 0=关。HSTS 只在 https 响应上有意义(http 响应带它浏览器会忽略),故只作用于 TLS 入口。
    #[serde(default)]
    pub hsts_max_age: u64,
}

/// Gateway API HTTP/HTTPS socket 上参与 Host 路由隔离与 SNI 权威判断的逻辑 listener。
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayListenerCfg {
    /// listener 的稳定身份；同一 proxy 内必须唯一。
    pub id: String,
    /// 可选 listener hostname；支持精确 DNS 名和最左 `*.` 通配，空值是兜底 listener。
    #[serde(default)]
    pub hostname: Option<String>,
}

/// PROXY protocol 配置。开启后只信任 `accept_from` 内的直连对端。
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyProtocolCfg {
    /// 是否启用 PROXY protocol 解析。
    #[serde(default)]
    pub enabled: bool,
    /// 接受的协议版本,可写 `v1`/`v2`;空表示二者都接受。
    #[serde(default)]
    pub versions: Vec<String>,
    /// 可信前置 LB/VIP 网段或单 IP。
    #[serde(default)]
    pub accept_from: Vec<String>,
    /// 读取 PROXY 头的超时(ms)。
    #[serde(default = "default_proxy_protocol_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ProxyProtocolCfg {
    /// 业务作用：构造 `ProxyProtocolCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            versions: Vec::new(),
            accept_from: Vec::new(),
            timeout_ms: default_proxy_protocol_timeout_ms(),
        }
    }
}

/// 单个 HTTP proxy 的资源安全预算。
///
/// 所有字段均来自 yml 且随不可变快照热更；`0` 的关闭语义在字段上显式说明，避免运维调参时
/// 把“无限制”和“禁止”混淆。accept、协议解析与上游发送分别执行对应预算。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ServerLimitsCfg {
    /// 当前 proxy 的下游 TCP/TLS 物理连接上限。0 表示不限制；accept loop 在达到上限时暂停接收，
    /// 不为排队连接无限创建 task。
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// HTTP/1 头部数量上限。
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    /// HTTP/1 read buffer / HTTP/2 header list 近似上限。
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// 单请求 body 上限,0 表示不限制。
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    /// HTTP/2 单连接最大并发 stream 数。
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    /// HTTP/2 单 stream 初始接收窗口(bytes)。窗口只授予 flow-control credit，不预分配同等
    /// buffer；仍需设上界，避免对端在背压生效前发送过多数据。
    #[serde(default = "default_h2_initial_stream_window_bytes")]
    pub h2_initial_stream_window_bytes: u32,
    /// HTTP/2 单物理连接初始接收窗口(bytes)。默认 1 MiB，减少多 stream 小帧下过密的
    /// WINDOW_UPDATE，同时保持明确的连接级内存/在途字节边界。
    #[serde(default = "default_h2_initial_connection_window_bytes")]
    pub h2_initial_connection_window_bytes: u32,
    /// 参与路由/ACL/guard 的 path 最大字节数。0 表示不限制。
    #[serde(default = "default_max_path_bytes")]
    pub max_path_bytes: usize,
    /// path 最大 segment 数。0 表示不限制；用于阻断超深路径的 CPU 放大。
    #[serde(default = "default_max_path_segments")]
    pub max_path_segments: usize,
    /// 每个上游实例允许的在途请求数。0 表示不限制；满时快速返回 503，不在内存中排队。
    #[serde(default = "default_upstream_pending_limit")]
    pub upstream_pending_limit: usize,
    /// Hyper 每 authority 最多保留的 idle 连接数；0 表示不保留 idle 连接。
    #[serde(default = "default_pool_max_per_upstream")]
    pub pool_max_per_upstream: usize,
    /// 每个 h2/h2c 上游身份的独立连接池分片数。每个分片仍在单连接内多路复用 stream，
    /// 但不同分片不争用 h2 crate 的同一内部 stream mutex；物理连接上限更小时自动下调。
    #[serde(default = "default_h2_connection_shards_per_upstream")]
    pub h2_connection_shards_per_upstream: usize,
    /// 每个结构化上游身份允许的物理 socket 总数。connector 在真正 dial 前占用名额，
    /// transport Drop 时归还；0 表示不限制。
    #[serde(default = "default_pool_max_connections_per_upstream")]
    pub pool_max_connections_per_upstream: usize,
    /// 一个上游 client/pool generation 最多承载的请求数。达到上限后新请求切到新 generation，
    /// 旧 generation 只 drain 已在途请求；0 表示不按请求数轮换。
    #[serde(default = "default_keepalive_requests")]
    pub keepalive_requests: u64,
    /// 上游 idle 连接保留时间(ms)。0 表示不设 idle 超时。
    #[serde(default = "default_pool_idle_timeout_ms")]
    pub pool_idle_timeout_ms: u64,
    /// TLS profile/池参数换版后，旧 client cache 最长保留时间(ms)。在途请求持有自己的 client clone，
    /// cache 淘汰不会中断在途响应。0 表示下一次清理即淘汰未命中的旧池。
    #[serde(default = "default_old_pool_retain_ms")]
    pub old_pool_retain_ms: u64,
}

impl Default for ServerLimitsCfg {
    /// 业务作用：构造 `ServerLimitsCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_headers: default_max_headers(),
            max_header_bytes: default_max_header_bytes(),
            max_body_bytes: default_max_body_bytes(),
            max_concurrent_streams: default_max_concurrent_streams(),
            h2_initial_stream_window_bytes: default_h2_initial_stream_window_bytes(),
            h2_initial_connection_window_bytes: default_h2_initial_connection_window_bytes(),
            max_path_bytes: default_max_path_bytes(),
            max_path_segments: default_max_path_segments(),
            upstream_pending_limit: default_upstream_pending_limit(),
            pool_max_per_upstream: default_pool_max_per_upstream(),
            h2_connection_shards_per_upstream: default_h2_connection_shards_per_upstream(),
            pool_max_connections_per_upstream: default_pool_max_connections_per_upstream(),
            keepalive_requests: default_keepalive_requests(),
            pool_idle_timeout_ms: default_pool_idle_timeout_ms(),
            old_pool_retain_ms: default_old_pool_retain_ms(),
        }
    }
}

/// 单个 HTTP proxy 的分层超时策略。
///
/// 普通 HTTP body、WS 隧道与整个物理连接分别计时，避免一个 total timeout 误杀合法长流。
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct TimeoutCfg {
    /// 上游响应头超时(ms,TTFB),0 表示不限制。
    #[serde(default = "default_upstream_ttfb_timeout_ms")]
    pub upstream_ttfb_timeout_ms: u64,
    /// 读完整请求头的最长时间(ms,slowloris「只连不发头」防护),0 表示不限制。
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    /// 单连接【总】超时(ms),0 表示不限制。**默认 0(关闭)**:它会硬砍整条连接,
    /// 对 SSE / h2 长流 / 大文件下载会误杀(「total_timeout 默认对 streaming 关闭,否则长流被误杀」);
    /// 仅在明确需要「最大连接寿命」时才配。慢客户端防护应走 `header_read_timeout_ms` + 后续 stream_idle_timeout。
    #[serde(default = "default_connection_timeout_ms")]
    pub connection_timeout_ms: u64,
    /// HTTP request/upstream-response body/trailer 两帧之间的最大空闲时间(ms),0 表示关闭。用于慢体
    /// 上传及 SSE/gRPC 上游卡死兜底；下游停止读取由 `downstream_write_timeout_ms` 处理。
    #[serde(default = "default_stream_idle_timeout_ms")]
    pub stream_idle_timeout_ms: u64,
    /// 下游 socket 单次 write/flush/shutdown 持续 Pending 的上限(ms)，0 表示关闭。用于客户端停止
    /// 读取时释放响应流与上游连接；它只在有待写字节时计时，不会误杀空闲但无输出的 SSE/gRPC。
    #[serde(default = "default_downstream_write_timeout_ms")]
    pub downstream_write_timeout_ms: u64,
    /// WebSocket 隧道任一方向最后一次字节活动后的最大空闲时间(ms)，0 表示关闭。
    #[serde(default = "default_websocket_idle_timeout_ms")]
    pub websocket_idle_timeout_ms: u64,
    /// WebSocket 隧道从升级完成起的最长存活时间(ms)，0 表示关闭。
    #[serde(default = "default_websocket_max_lifetime_ms")]
    pub websocket_max_lifetime_ms: u64,
    /// SIGTERM 后等待在途请求完成的最长时间(ms)。
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
}

impl Default for TimeoutCfg {
    /// 业务作用：构造 `TimeoutCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            upstream_ttfb_timeout_ms: default_upstream_ttfb_timeout_ms(),
            header_read_timeout_ms: default_header_read_timeout_ms(),
            connection_timeout_ms: default_connection_timeout_ms(),
            stream_idle_timeout_ms: default_stream_idle_timeout_ms(),
            downstream_write_timeout_ms: default_downstream_write_timeout_ms(),
            websocket_idle_timeout_ms: default_websocket_idle_timeout_ms(),
            websocket_max_lifetime_ms: default_websocket_max_lifetime_ms(),
            drain_timeout_ms: default_drain_timeout_ms(),
        }
    }
}

/// 业务作用：为未显式声明的 `max_headers` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_max_headers() -> usize {
    100
}

/// 业务作用：默认每个 proxy 最多 10k 条物理下游连接；可按 listener 热调。
pub(super) fn default_max_connections() -> usize {
    10_000
}

/// 业务作用：为未显式声明的 `max_header_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_max_header_bytes() -> usize {
    64 * 1024
}

/// 业务作用：为未显式声明的 `max_body_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_max_body_bytes() -> u64 {
    64 * 1024 * 1024
}

/// 业务作用：为未显式声明的 `max_concurrent_streams` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_max_concurrent_streams() -> u32 {
    256
}

/// 业务作用：RFC 9113 的标准初始 stream window；保持单 stream 背压粒度。
pub(super) fn default_h2_initial_stream_window_bytes() -> u32 {
    65_535
}

/// 业务作用：连接级窗口放大到 1 MiB，让并发小 stream 共享 credit 时减少 WINDOW_UPDATE 频率。
pub(super) fn default_h2_initial_connection_window_bytes() -> u32 {
    1024 * 1024
}

/// 业务作用：默认 path 上限 8 KiB，与常见代理请求目标预算同量级。
pub(super) fn default_max_path_bytes() -> usize {
    8 * 1024
}

/// 业务作用：默认最多 128 个非空 path segment，避免超深路径放大匹配成本。
pub(super) fn default_max_path_segments() -> usize {
    128
}

/// 业务作用：默认每个完整 `health_key` 最多 1024 个在途上游请求。
pub(super) fn default_upstream_pending_limit() -> usize {
    1_024
}

/// 业务作用：默认每个 Hyper authority 最多保留 64 条 idle 连接。
pub(super) fn default_pool_max_per_upstream() -> usize {
    64
}

/// 业务作用：默认用 16 条独立 mux 连接分摊高并发 h2 stream 锁竞争。单连接会把所有 stream 串到 h2
/// 内部锁；过多连接又增加调度和 TLS 成本。当前同机 300k/64 对照为 8=36.95k、
/// 16=40.15k、32=36.97k RPS；具体部署仍可按 CPU 拓扑热更，并受物理连接硬上限自动钳制。
pub(super) fn default_h2_connection_shards_per_upstream() -> usize {
    16
}

/// 业务作用：默认每个结构化上游身份最多 128 条物理 socket；h2 多路复用通常远低于此数。
pub(super) fn default_pool_max_connections_per_upstream() -> usize {
    128
}

/// 业务作用：默认每个 pool generation 处理 1000 个请求后轮换，给长期连接可预期的回收边界。
pub(super) fn default_keepalive_requests() -> u64 {
    1_000
}

/// 业务作用：默认上游 idle 连接保留 60 秒。
pub(super) fn default_pool_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：默认换版后旧 client cache 保留 60 秒，给旧快照请求完成 drain。
pub(super) fn default_old_pool_retain_ms() -> u64 {
    60_000
}

/// 业务作用：为未显式声明的 `upstream_ttfb_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_upstream_ttfb_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `header_read_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_header_read_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `connection_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_connection_timeout_ms() -> u64 {
    0
}

/// 业务作用：为未显式声明的 `stream_idle_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_stream_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：默认下游连续写阻塞 30 秒后关闭连接，防停止读取的客户端无限占用 response/upstream。
pub(super) fn default_downstream_write_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：默认 WebSocket 60 秒无任何字节活动即优雅关闭。
pub(super) fn default_websocket_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：默认 WebSocket 最长存活 24 小时，定期释放旧快照与运行态引用。
pub(super) fn default_websocket_max_lifetime_ms() -> u64 {
    86_400_000
}

/// 业务作用：为未显式声明的 `drain_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_drain_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_proxy_protocol_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：为未显式声明的 `redirect_https_status` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_redirect_https_status() -> u16 {
    308
}
