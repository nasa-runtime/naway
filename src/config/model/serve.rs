//! 静态资源及代理隧道声明。

use super::*;

/// route 本地服务后端配置集合。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RouteServeCfg {
    /// 静态文件/SPA 后端配置。
    #[serde(default)]
    pub r#static: Option<StaticServeCfg>,
}

/// 静态文件/SPA 后端配置,对齐 nginx `root`/`try_files`/`index` 主流用法。
#[derive(Debug, Deserialize, Clone)]
pub struct StaticServeCfg {
    /// 静态文件根目录。相对路径按 `gateway.yml` 所在目录解析。
    pub root: String,
    /// 依次尝试的文件模板。默认 `["${uri}", "${uri}/index.html"]`;末项可显式写 `/index.html` 做 SPA 回落。
    #[serde(default)]
    pub try_files: Vec<String>,
    /// 目录请求的索引文件列表,默认 `["index.html"]`。
    #[serde(default)]
    pub index: Vec<String>,
    /// 响应 `Cache-Control` 值。为空则不写。
    #[serde(default)]
    pub cache_control: Option<String>,
    /// nginx `expires` 语法糖,如 `1h`/`7d`/`3600s`;为空或 off 表示不写 Expires。
    #[serde(default)]
    pub expires: Option<String>,
    /// 未识别扩展名时使用的 Content-Type,默认 `application/octet-stream`。
    #[serde(default)]
    pub default_type: Option<String>,
    /// 自定义扩展名到 Content-Type 的映射,等价 nginx `types{}` 常用形态。
    #[serde(default)]
    pub types: HashMap<String, String>,
    /// 是否允许访问点文件/点目录。默认 false,防 `.env`/`.git` 暴露。
    #[serde(default)]
    pub allow_dotfiles: bool,
    /// 是否生成弱 ETag。默认 true。
    #[serde(default = "default_true")]
    pub etag: bool,
    /// 是否支持单段 HTTP Range。默认 true,用于大文件/媒体断点下载。
    #[serde(default = "default_true")]
    pub range: bool,
}

/// route 级受控正向代理配置。
///
/// 所有 allowlist 都必须显式给出:没有"留空即全放行"的语义。正向代理把网关的
/// 网络位置交给调用方使用,一个默认放行的配置就是可被立刻利用的内网入口。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ForwardProxyCfg {
    /// 允许 CONNECT 的目标端口。不得为空。
    pub allowed_ports: Vec<u16>,
    /// 允许的目标域名,支持 `*.example.com` 形式的子域通配;不接受裸 `*`。
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// 允许的目标 CIDR。
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// 是否允许目标解析到私网地址。环回、链路本地与元数据地址即使开启也永远拒绝。
    #[serde(default)]
    pub allow_private: bool,
    /// 隧道空闲上限(ms);0 表示不限制。
    #[serde(default = "default_connect_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// 隧道绝对寿命上限(ms);0 表示不限制。
    #[serde(default)]
    pub max_lifetime_ms: u64,
    /// 单条隧道允许搬运的最大字节数;0 表示不限制。
    #[serde(default)]
    pub max_bytes: u64,
    /// 建连超时(ms)。
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

/// route 级 WebTransport 真上游代理配置。
///
/// 该后端只接受 HTTP/3 extended CONNECT，普通 HTTP 请求不会被静默转成 WebTransport。
/// 上游 URL 和信任根都在候选快照构建期冻结，客户端不能借请求字段改写拨号目标。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebTransportCfg {
    /// 固定 HTTPS WebTransport 上游 URL，包含上游 session path。
    pub upstream: String,
    /// 允许建立 session 的浏览器 Origin 精确集合；不得为空或包含通配符。
    pub allowed_origins: Vec<String>,
    /// 可选自定义 CA PEM；为空时使用系统信任根。相对路径按主配置目录解析并纳入热更新依赖。
    #[serde(default)]
    pub ca_file: Option<String>,
    /// 建立上游 QUIC 与 WebTransport session 的总时限。
    #[serde(default = "default_webtransport_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// 单 session 同时转发的双向 stream 上限。
    #[serde(default = "default_webtransport_max_bidi_streams")]
    pub max_bidi_streams: u64,
    /// 单 session 同时转发的单向 stream 上限。
    #[serde(default = "default_webtransport_max_uni_streams")]
    pub max_uni_streams: u64,
    /// 单方向等待转发的 DATAGRAM 数量上限；队列满时按不可靠语义丢弃。
    #[serde(default = "default_webtransport_max_datagram_queue")]
    pub max_datagram_queue: u64,
    /// 单个 WebTransport DATAGRAM payload 上限。
    #[serde(default = "default_webtransport_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
    /// session 两个方向合计允许转发的最大字节数；0 表示不限制。
    #[serde(default)]
    pub max_bytes: u64,
    /// session 无 stream/datagram 活动后的回收时限。
    #[serde(default = "default_webtransport_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// session 从建立起的最长存活时间；0 表示不额外限制。
    #[serde(default)]
    pub max_lifetime_ms: u64,
}

/// route 级 QUIC 0-RTT 安全契约。
///
/// 业务作用：仅对显式、无凭据且无认证副作用的读路由开放 early data；
/// listener 级 TLS 恢复与共享 anti-replay 是另一道必须同时成立的门禁。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlyDataRouteCfg {
    /// 是否显式允许本 route 接收 0-RTT；默认关闭。
    #[serde(default)]
    pub enabled: bool,
    /// 一次性 nonce 在 anti-replay 账本中的保留时间。
    #[serde(default = "default_early_data_replay_window_ms")]
    pub replay_window_ms: u64,
}

/// 业务作用：为 0-RTT 重放去重提供短且可容忍跨节点延迟的默认窗口。
///
/// 参数说明: 无。
///
/// 返回：返回 10 秒的默认 anti-replay 保留时间。
pub(super) const fn default_early_data_replay_window_ms() -> u64 {
    10_000
}

/// 业务作用：限制 WebTransport 上游握手占用会话准入资源的时间。
///
/// 参数说明: 无。
///
/// 返回：返回 5 秒默认建连时限。
pub(super) const fn default_webtransport_connect_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：为单个 WebTransport session 提供保守的双向 stream 并发上限。
///
/// 参数说明: 无。
///
/// 返回：返回 64 条双向 stream。
pub(super) const fn default_webtransport_max_bidi_streams() -> u64 {
    64
}

/// 业务作用：为单个 WebTransport session 提供保守的单向 stream 并发上限。
///
/// 参数说明: 无。
///
/// 返回：返回 64 条单向 stream。
pub(super) const fn default_webtransport_max_uni_streams() -> u64 {
    64
}

/// 业务作用：为 WebTransport 不可靠消息提供小型突发队列且保持内存有界。
///
/// 参数说明: 无。
///
/// 返回：返回每方向 128 个 DATAGRAM。
pub(super) const fn default_webtransport_max_datagram_queue() -> u64 {
    128
}

/// 业务作用：限制 WebTransport 单个 DATAGRAM，避免 QUIC path 分片与大包内存放大。
///
/// 参数说明: 无。
///
/// 返回：返回 1150 字节 payload 上限。
pub(super) const fn default_webtransport_max_datagram_bytes() -> usize {
    1_150
}

/// 业务作用：回收没有任何业务活动的 WebTransport session。
///
/// 参数说明: 无。
///
/// 返回：返回 60 秒默认空闲时限。
pub(super) const fn default_webtransport_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：为 CONNECT 隧道提供默认空闲回收期限，避免无流量连接永久占用资源。
///
/// 参数说明: 无。
///
/// 返回：返回 60000 毫秒。
pub(super) const fn default_connect_idle_timeout_ms() -> u64 {
    60_000
}

/// 业务作用：限制 CONNECT 目标建连的默认等待时间，避免不可达目标长期占用准入资源。
///
/// 参数说明: 无。
///
/// 返回：返回 5000 毫秒。
pub(super) const fn default_connect_timeout_ms() -> u64 {
    5_000
}

/// route 级 WebSocket 帧级治理配置。
///
/// 缺省即透明模式:不解析帧、不聚合消息,与既有行为完全一致。只有显式配置本块
/// 才进入 frame-aware 模式,相应的解析与聚合开销也只落在该 route 上。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsFrameCfg {
    /// 单帧载荷上限(字节)。
    #[serde(default = "default_ws_max_frame_bytes")]
    pub max_frame_bytes: u64,
    /// 单条消息(所有分片之和)上限(字节)。
    #[serde(default = "default_ws_max_message_bytes")]
    pub max_message_bytes: u64,
    /// 单条消息允许的最大分片数;用于挡住分片炸弹。
    #[serde(default = "default_ws_max_fragments")]
    pub max_fragments: u32,
    /// 交给插件的完整载荷上限(字节)；超限关闭，不能用截断前缀替代完整校验。
    #[serde(default = "default_ws_max_plugin_payload_bytes")]
    pub max_plugin_payload_bytes: usize,
    /// 单个消息插件的时限(ms)；外部插件仅按显式fail_open处理依赖错误。
    #[serde(default = "default_ws_plugin_timeout_ms")]
    pub plugin_timeout_ms: u64,
    /// permessage-deflate 允许的最大解压比。
    #[serde(default = "default_ws_max_decompress_ratio")]
    pub max_decompress_ratio: u32,
    /// 显式开放每条消息独立的permessage-deflate，未协商时RSV1仍禁止。
    #[serde(default)]
    pub permessage_deflate: bool,
    /// 有界消息模式从首帧到交付完成的绝对期限，插件不能重新开始总计时。
    #[serde(default = "default_ws_message_timeout_ms")]
    pub message_timeout_ms: u64,
    /// client到server方向的完整消息处理链；控制帧不进入插件。
    #[serde(default)]
    pub client_plugins: Vec<WsMessagePluginCfg>,
    /// server到client方向的完整消息处理链；控制帧不进入插件。
    #[serde(default)]
    pub server_plugins: Vec<WsMessagePluginCfg>,
    /// 违规处置动作:drop|policy_close|upstream_close。
    #[serde(default = "default_ws_on_violation")]
    pub on_violation: String,
}

impl Default for WsFrameCfg {
    /// 业务作用：程序化创建帧治理声明时沿用 YAML 省略字段的预算，不能产生零时限或无效动作。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只启用基础帧治理、不启用压缩或消息插件的有界默认配置。
    fn default() -> Self {
        Self {
            max_frame_bytes: default_ws_max_frame_bytes(),
            max_message_bytes: default_ws_max_message_bytes(),
            max_fragments: default_ws_max_fragments(),
            max_plugin_payload_bytes: default_ws_max_plugin_payload_bytes(),
            plugin_timeout_ms: default_ws_plugin_timeout_ms(),
            max_decompress_ratio: default_ws_max_decompress_ratio(),
            permessage_deflate: false,
            message_timeout_ms: default_ws_message_timeout_ms(),
            client_plugins: Vec::new(),
            server_plugins: Vec::new(),
            on_violation: default_ws_on_violation(),
        }
    }
}

/// 业务作用：给帧级治理设置默认单帧硬上限，阻止对端声明无界载荷。
///
/// 参数说明: 无。
///
/// 返回：返回 1 MiB。
pub(super) const fn default_ws_max_frame_bytes() -> u64 {
    1024 * 1024
}

/// 业务作用：给分片消息设置默认聚合上限，约束跨帧状态占用。
///
/// 参数说明: 无。
///
/// 返回：返回 8 MiB。
pub(super) const fn default_ws_max_message_bytes() -> u64 {
    8 * 1024 * 1024
}

/// 业务作用：限制单条消息的默认分片数量，阻止小分片放大解析与状态成本。
///
/// 参数说明: 无。
///
/// 返回：返回 256 个分片。
pub(super) const fn default_ws_max_fragments() -> u32 {
    256
}

/// 业务作用：限制默认插件可见载荷，避免插件链复制过大的业务消息。
///
/// 参数说明: 无。
///
/// 返回：返回 64 KiB。
pub(super) const fn default_ws_max_plugin_payload_bytes() -> usize {
    64 * 1024
}

/// 业务作用：约束单次帧插件默认执行期限，避免插件挂住长连接。
///
/// 参数说明: 无。
///
/// 返回：返回 100 毫秒。
pub(super) const fn default_ws_plugin_timeout_ms() -> u64 {
    100
}

/// 业务作用：限制压缩消息默认解压倍率，降低压缩炸弹风险。
///
/// 参数说明: 无。
///
/// 返回：返回 100 倍。
pub(super) const fn default_ws_max_decompress_ratio() -> u32 {
    100
}

/// 业务作用：定义帧级违规的默认协议化关闭动作，避免静默丢弃导致双方状态分叉。
///
/// 参数说明: 无。
///
/// 返回：返回 `policy_close`。
pub(super) fn default_ws_on_violation() -> String {
    "policy_close".to_string()
}
