//! TCP、UDP 及流式协议治理声明。

use super::*;

/// L4 stream 配置。
#[derive(Debug, Deserialize, Clone, Default)]
pub struct StreamCfg {
    /// stream listener 列表。每个 listener 独立绑定一个 TCP 端口。
    #[serde(default)]
    pub listeners: Vec<StreamListenerCfg>,
}

/// L4 TCP listener 配置。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamListenerCfg {
    /// listener 唯一标识。
    pub id: String,
    /// 本地监听地址。
    pub listen: String,
    /// L4 传输协议。`tcp` 默认；`udp` 使用按客户端地址隔离的短会话。
    #[serde(default)]
    pub protocol: StreamProtocolCfg,
    /// 可选 stream TLS 终止；与 `preread.ssl_preread` 互斥，因为前者解密、后者透传。
    #[serde(default)]
    pub tls: Option<StreamTlsCfg>,
    /// UDP 短会话资源预算；TCP listener 忽略且必须保持默认值。
    #[serde(default)]
    pub udp: StreamUdpCfg,
    /// 旧版单上游目标。支持 `host:port`、`tcp://host:port` 或 `lb://service`;配置 `routes[]` 时可为空。
    #[serde(default)]
    pub upstream: String,
    /// TLS ClientHello preread 配置,用于不终止 TLS 的 SNI 路由。
    #[serde(default)]
    pub preread: StreamPrereadCfg,
    /// MQTT 协议治理 profile；默认关闭时仍是 wire-transparent TCP。
    #[serde(default)]
    pub mqtt: StreamMqttCfg,
    /// Kafka 协议治理 profile；默认关闭时仍是 wire-transparent TCP。
    #[serde(default)]
    pub kafka: StreamKafkaCfg,
    /// 多 stream route。为空时沿用 listener 级 `upstream` 单路由行为。
    #[serde(default)]
    pub routes: Vec<StreamRouteCfg>,
    /// 显式声明该 listener 不含任何可转发路由，所有连接在匹配阶段关闭；用于保留已接纳但
    /// 暂无合法 Route 的受控 socket，不能与 `upstream` 或 `routes` 同时配置。
    #[serde(default)]
    pub reject_all: bool,
    /// PROXY protocol v1/v2 真实客户端地址解析配置。
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolCfg,
    /// 发往上游的 PROXY protocol 头配置。默认关闭。
    #[serde(default)]
    pub proxy_protocol_to_upstream: StreamProxyProtocolUpstreamCfg,
    /// 连接上游超时(ms)。
    #[serde(default = "default_stream_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// 会话总超时(ms)。用作 copy_bidirectional 的外层超时;0 表示不限制。
    #[serde(default)]
    pub timeout_ms: u64,
}

/// L4 stream preread 配置。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamPrereadCfg {
    /// 是否启用 TLS ClientHello SNI preread。
    #[serde(default)]
    pub ssl_preread: bool,
    /// 解析 MQTT 3.1/3.1.1/5 CONNECT client id，用于精确 route；未开启时零协议解析成本。
    #[serde(default)]
    pub mqtt_connect: bool,
    /// preread 超时(ms)。
    #[serde(default = "default_stream_preread_timeout_ms")]
    pub timeout_ms: u64,
    /// preread 最大字节数。
    #[serde(default = "default_stream_preread_max_bytes")]
    pub max_bytes: usize,
}

impl Default for StreamPrereadCfg {
    /// 业务作用：构造 `StreamPrereadCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            ssl_preread: false,
            mqtt_connect: false,
            timeout_ms: default_stream_preread_timeout_ms(),
            max_bytes: default_stream_preread_max_bytes(),
        }
    }
}

/// MQTT 3.1.1/5.0 受限协议治理配置。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamMqttCfg {
    /// 是否启用 MQTT frame 解析、ACL 与 QoS 状态跟踪。
    #[serde(default)]
    pub enabled: bool,
    /// 该 listener 同时允许的 MQTT 连接数，包含 CONNECT preread/TLS 阶段。
    #[serde(default = "default_stream_mqtt_max_connections")]
    pub max_connections: usize,
    /// 单个 MQTT Control Packet 的 wire 字节上限。
    #[serde(default = "default_stream_mqtt_max_packet_bytes")]
    pub max_packet_bytes: usize,
    /// 从收到 fixed-header 首字节起到整枚 packet 完整的 deadline；纯 idle 不计时。
    #[serde(default = "default_stream_mqtt_packet_timeout_ms")]
    pub packet_timeout_ms: u64,
    /// listener 内所有活跃 MQTT 连接可同时占用的双向 packet buffer 预算。
    #[serde(default = "default_stream_mqtt_max_buffered_bytes")]
    pub max_buffered_bytes: usize,
    /// Topic Name/Topic Filter 的 UTF-8 字节上限。
    #[serde(default = "default_stream_mqtt_max_topic_bytes")]
    pub max_topic_bytes: usize,
    /// 单连接已生效与待 SUBACK 的去重订阅总数上限。
    #[serde(default = "default_stream_mqtt_max_subscriptions")]
    pub max_subscriptions: usize,
    /// 单连接两个方向的 QoS publish 与待 ACK 控制包总数上限。
    #[serde(default = "default_stream_mqtt_max_inflight_messages")]
    pub max_inflight_messages: usize,
    /// 允许的 client id 精确集合；空集合表示不额外限制 client id。
    #[serde(default)]
    pub client_id_allow: Vec<String>,
    /// 允许 client PUBLISH 的 MQTT Topic Filter；空集合表示拒绝所有 publish。
    #[serde(default)]
    pub publish_topic_allow: Vec<String>,
    /// 允许 SUBSCRIBE/UNSUBSCRIBE 的 MQTT Topic Filter 边界；空集合表示拒绝全部。
    #[serde(default)]
    pub subscribe_topic_allow: Vec<String>,
}

impl Default for StreamMqttCfg {
    /// 业务作用：保持 MQTT 治理默认关闭，同时为显式开启提供有界资源基线。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认关闭的 profile；不会让透明 stream 进入 MQTT parser。
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: default_stream_mqtt_max_connections(),
            max_packet_bytes: default_stream_mqtt_max_packet_bytes(),
            packet_timeout_ms: default_stream_mqtt_packet_timeout_ms(),
            max_buffered_bytes: default_stream_mqtt_max_buffered_bytes(),
            max_topic_bytes: default_stream_mqtt_max_topic_bytes(),
            max_subscriptions: default_stream_mqtt_max_subscriptions(),
            max_inflight_messages: default_stream_mqtt_max_inflight_messages(),
            client_id_allow: Vec::new(),
            publish_topic_allow: Vec::new(),
            subscribe_topic_allow: Vec::new(),
        }
    }
}

/// Kafka client data-plane 受限协议治理配置。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamKafkaCfg {
    /// 是否启用 Kafka frame、ACL、correlation 与 broker endpoint rewrite。
    #[serde(default)]
    pub enabled: bool,
    /// listener 同时允许的受治理 Kafka 连接数，包含 TLS 阶段。
    #[serde(default = "default_stream_kafka_max_connections")]
    pub max_connections: usize,
    /// 单枚 Kafka request/response 的完整 wire 字节上限，包含四字节长度前缀。
    #[serde(default = "default_stream_kafka_max_frame_bytes")]
    pub max_frame_bytes: usize,
    /// 从长度前缀首字节到完整 frame 的 deadline；纯 idle 不计时。
    #[serde(default = "default_stream_kafka_frame_timeout_ms")]
    pub frame_timeout_ms: u64,
    /// listener 所有连接双向 frame buffer 的悲观聚合预留上限。
    #[serde(default = "default_stream_kafka_max_buffered_bytes")]
    pub max_buffered_bytes: usize,
    /// 单连接尚未收到 response 的 correlation id 数量上限。
    #[serde(default = "default_stream_kafka_max_inflight_requests")]
    pub max_inflight_requests: usize,
    /// request header 中 client id 的 UTF-8 字节上限。
    #[serde(default = "default_stream_kafka_max_client_id_bytes")]
    pub max_client_id_bytes: usize,
    /// topic 名 UTF-8 字节上限。
    #[serde(default = "default_stream_kafka_max_topic_bytes")]
    pub max_topic_bytes: usize,
    /// consumer group id UTF-8 字节上限。
    #[serde(default = "default_stream_kafka_max_group_bytes")]
    pub max_group_bytes: usize,
    /// 任一协议数组可包含的最大元素数。
    #[serde(default = "default_stream_kafka_max_array_items")]
    pub max_array_items: usize,
    /// 允许的 client id 精确集合；空集合表示不额外限制。
    #[serde(default)]
    pub client_id_allow: Vec<String>,
    /// 允许访问的 topic 精确集合；空集合拒绝所有 topic API。
    #[serde(default)]
    pub topic_allow: Vec<String>,
    /// 允许访问的 consumer group 精确集合；空集合拒绝所有 group API。
    #[serde(default)]
    pub group_allow: Vec<String>,
    /// 允许的 SASL mechanism 精确集合；空集合拒绝 SASL handshake。
    #[serde(default)]
    pub sasl_mechanism_allow: Vec<String>,
    /// broker 在 Metadata/FindCoordinator 中返回的 endpoint 改写表。
    #[serde(default)]
    pub broker_rewrite: Vec<KafkaBrokerRewriteCfg>,
}

impl Default for StreamKafkaCfg {
    /// 业务作用：保持 Kafka 治理默认关闭，同时提供总量可证明有界的连接/frame 基线。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认关闭的 profile；不会让透明 stream 进入 Kafka parser。
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: default_stream_kafka_max_connections(),
            max_frame_bytes: default_stream_kafka_max_frame_bytes(),
            frame_timeout_ms: default_stream_kafka_frame_timeout_ms(),
            max_buffered_bytes: default_stream_kafka_max_buffered_bytes(),
            max_inflight_requests: default_stream_kafka_max_inflight_requests(),
            max_client_id_bytes: default_stream_kafka_max_client_id_bytes(),
            max_topic_bytes: default_stream_kafka_max_topic_bytes(),
            max_group_bytes: default_stream_kafka_max_group_bytes(),
            max_array_items: default_stream_kafka_max_array_items(),
            client_id_allow: Vec::new(),
            topic_allow: Vec::new(),
            group_allow: Vec::new(),
            sasl_mechanism_allow: Vec::new(),
            broker_rewrite: Vec::new(),
        }
    }
}

/// Kafka broker endpoint 的精确地址改写项。
#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KafkaBrokerRewriteCfg {
    /// broker response 中声明的原 host。
    pub from_host: String,
    /// broker response 中声明的原 port。
    pub from_port: u16,
    /// client 应连接的代理 host。
    pub to_host: String,
    /// client 应连接的代理 port。
    pub to_port: u16,
}

/// L4 stream route。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamRouteCfg {
    /// route 唯一标识。
    pub id: String,
    /// SNI 精确匹配值。为空且 `default=true` 时作为默认路由。
    #[serde(default)]
    pub sni: Option<String>,
    /// MQTT CONNECT client id 精确匹配；与 `sni` 互斥。
    #[serde(default)]
    pub mqtt_client_id: Option<String>,
    /// 是否默认路由。
    #[serde(default)]
    pub default: bool,
    /// 是否在选中该路由后终止下游 TLS；仅与 listener TLS 身份和 SNI preread 同时使用。
    #[serde(default)]
    pub terminate_tls: bool,
    /// 上游目标。支持 `host:port`、`tcp://host:port` 或 `lb://service`。
    pub upstream: String,
    /// 按连接或 UDP session 选择的带权上游集合；非空时覆盖单一 `upstream`，零权重项不接收流量。
    #[serde(default)]
    pub weighted_upstreams: Vec<StreamWeightedUpstreamCfg>,
    /// 可选 stream 上游 TLS/mTLS profile；`lb://service` 应使用 service 级 `tls`。
    #[serde(default)]
    pub tls: Option<UpstreamTlsCfg>,
}

/// L4 route 的单个带权上游。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamWeightedUpstreamCfg {
    /// 上游目标；Gateway API 生成配置使用 `lb://service`。
    pub upstream: String,
    /// 相对权重；零表示保留声明但不参与选择。
    pub weight: u32,
}

/// L4 listener 传输协议。
#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StreamProtocolCfg {
    /// 面向连接的 TCP 字节流。
    #[default]
    Tcp,
    /// 保留报文边界的 UDP 数据报。
    Udp,
}

/// stream TLS 终止配置。证书只在启动/换版时解析，并由 watcher 原子热换。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamTlsCfg {
    /// PEM 证书链文件，相对主配置文件目录解析。
    #[serde(default)]
    pub cert_file: String,
    /// 与证书匹配的 PEM 私钥文件，相对主配置文件目录解析。
    #[serde(default)]
    pub key_file: String,
    /// 可选外部 TLS 签名身份；配置后 `key_file` 必须为空。
    #[serde(default)]
    pub private_key_provider: Option<ExternalPrivateKeyCfg>,
    /// 可选 SPIRE Workload API 身份；配置后文件身份、外部 signer 与 SNI 身份必须为空。
    #[serde(default)]
    pub spire: Option<SpireWorkloadCfg>,
    /// 同一 stream socket 上按 SNI 选择的额外证书身份。
    #[serde(default)]
    pub certs: Vec<SniCertCfg>,
    /// 下游 TLS 握手 deadline，防慢 ClientHello 长期占用连接任务。
    #[serde(default = "default_stream_tls_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// 可选 mTLS 客户端 CA，与 L7 `tls.client_auth` 使用同一 require/optional 契约。
    #[serde(default)]
    pub client_auth: Option<ClientAuthCfg>,
    /// 默认证书的服务端 OCSP staple；SNI 附加证书分别在各自条目声明。
    #[serde(default)]
    pub ocsp_stapling: Option<OcspStaplingCfg>,
    /// 可选共享 session ticket key 集；语义与 HTTP TLS listener 一致。
    #[serde(default)]
    pub session_tickets: Option<SessionTicketCfg>,
}

/// UDP listener 的有界 5-tuple 会话配置。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamUdpCfg {
    /// 双向都无数据后回收 connected upstream socket。
    #[serde(default = "default_stream_udp_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// 单 listener 最大客户端会话数；满时不再分配 socket。
    #[serde(default = "default_stream_udp_max_sessions")]
    pub max_sessions: usize,
    /// 每会话下行 datagram bounded channel 容量；满时丢当前 datagram，不阻塞 listener。
    #[serde(default = "default_stream_udp_queue_capacity")]
    pub queue_capacity: usize,
    /// 接收单 datagram 缓冲上限；最大 65507，不做 IP fragment/业务消息重组。
    #[serde(default = "default_stream_udp_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
}

impl Default for StreamUdpCfg {
    /// 业务作用：构造 `StreamUdpCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            idle_timeout_ms: default_stream_udp_idle_timeout_ms(),
            max_sessions: default_stream_udp_max_sessions(),
            queue_capacity: default_stream_udp_queue_capacity(),
            max_datagram_bytes: default_stream_udp_max_datagram_bytes(),
        }
    }
}

/// 业务作用：为未显式声明的 `idle_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_stream_udp_idle_timeout_ms() -> u64 {
    30_000
}

/// 业务作用：为未显式声明的 `max_sessions` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_stream_udp_max_sessions() -> usize {
    65_536
}

/// 业务作用：为未显式声明的 `queue_capacity` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_stream_udp_queue_capacity() -> usize {
    64
}

/// 业务作用：为未显式声明的 `max_datagram_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_stream_udp_max_datagram_bytes() -> usize {
    65_507
}

/// 业务作用：为未显式声明的 `handshake_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) const fn default_stream_tls_handshake_timeout_ms() -> u64 {
    10_000
}

/// stream 连接上游后写出的 PROXY protocol 头配置。
#[derive(Debug, Deserialize, Clone)]
pub struct StreamProxyProtocolUpstreamCfg {
    /// 是否向上游写 PROXY protocol 头。
    #[serde(default)]
    pub enabled: bool,
    /// 写出版本:`v1` 或 `v2`。
    #[serde(default = "default_stream_proxy_protocol_upstream_version")]
    pub version: String,
}

impl Default for StreamProxyProtocolUpstreamCfg {
    /// 业务作用：构造 `StreamProxyProtocolUpstreamCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            version: default_stream_proxy_protocol_upstream_version(),
        }
    }
}

/// 业务作用：为未显式声明的 `connect_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_stream_connect_timeout_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_stream_preread_timeout_ms() -> u64 {
    3_000
}

/// 业务作用：为未显式声明的 `max_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_stream_preread_max_bytes() -> usize {
    8 * 1024
}

/// 业务作用：给单 listener MQTT 会话设置默认并发硬门。
///
/// 参数说明: 无。
///
/// 返回：默认最多 256 条正在握手或已建立的 MQTT 连接。
pub(super) fn default_stream_mqtt_max_connections() -> usize {
    256
}

/// 业务作用：限制一枚 MQTT Control Packet 导致的单次分配。
///
/// 参数说明: 无。
///
/// 返回：默认 1 MiB wire packet 上限。
pub(super) fn default_stream_mqtt_max_packet_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制已开始 MQTT packet 的慢速传输，同时不误杀没有发包的长时间 idle 连接。
///
/// 参数说明: 无。
///
/// 返回：fixed-header 首字节到完整 packet 默认 10 秒 deadline。
pub(super) fn default_stream_mqtt_packet_timeout_ms() -> u64 {
    10_000
}

/// 业务作用：给 listener 内所有 MQTT packet buffer 设置可预留的聚合内存硬门。
///
/// 参数说明: 无。
///
/// 返回：默认 512 MiB，按每连接两个方向各一枚最大 packet 做悲观预留。
pub(super) fn default_stream_mqtt_max_buffered_bytes() -> usize {
    512 * 1024 * 1024
}

/// 业务作用：收紧 broker 协议理论上限，避免 topic 成为大字符串攻击面。
///
/// 参数说明: 无。
///
/// 返回：默认 1024 字节 Topic Name/Filter 上限。
pub(super) fn default_stream_mqtt_max_topic_bytes() -> usize {
    1_024
}

/// 业务作用：约束每条 MQTT 连接保留的订阅集合。
///
/// 参数说明: 无。
///
/// 返回：默认最多 1024 个去重 topic filter。
pub(super) fn default_stream_mqtt_max_subscriptions() -> usize {
    1_024
}

/// 业务作用：限制 QoS 与订阅控制流程的 packet-id 状态量。
///
/// 参数说明: 无。
///
/// 返回：默认最多 128 个双向在途交换。
pub(super) fn default_stream_mqtt_max_inflight_messages() -> usize {
    128
}

/// 业务作用：限制单 listener 的 Kafka 长连接任务与悲观 frame buffer 预留总量。
///
/// 参数说明: 无。
///
/// 返回：默认 256 条连接。
pub(super) fn default_stream_kafka_max_connections() -> usize {
    256
}

/// 业务作用：限制单枚 Kafka frame 的分配；默认与常见 1 MiB record batch 保持同量级。
///
/// 参数说明: 无。
///
/// 返回：默认 1 MiB wire 上限。
pub(super) fn default_stream_kafka_max_frame_bytes() -> usize {
    1024 * 1024
}

/// 业务作用：限制已经开始传输的慢 Kafka frame，不影响纯 idle 长连接。
///
/// 参数说明: 无。
///
/// 返回：默认 10 秒。
pub(super) fn default_stream_kafka_frame_timeout_ms() -> u64 {
    10_000
}

/// 业务作用：限制 listener 内所有 Kafka 双向 frame buffer 的聚合预留。
///
/// 参数说明: 无。
///
/// 返回：默认 512 MiB。
pub(super) fn default_stream_kafka_max_buffered_bytes() -> usize {
    512 * 1024 * 1024
}

/// 业务作用：限制单连接 correlation map，防止只发 request 不读 response 的状态堆积。
///
/// 参数说明: 无。
///
/// 返回：默认 128 个在途请求。
pub(super) fn default_stream_kafka_max_inflight_requests() -> usize {
    128
}

/// 业务作用：限制 Kafka request header 的 client id 字符串。
///
/// 参数说明: 无。
///
/// 返回：默认 256 字节。
pub(super) fn default_stream_kafka_max_client_id_bytes() -> usize {
    256
}

/// 业务作用：收紧 Kafka topic 名攻击面，同时覆盖 broker 的常见 topic 长度上限。
///
/// 参数说明: 无。
///
/// 返回：默认 249 字节。
pub(super) fn default_stream_kafka_max_topic_bytes() -> usize {
    249
}

/// 业务作用：限制 consumer group id 的协议字符串分配。
///
/// 参数说明: 无。
///
/// 返回：默认 255 字节。
pub(super) fn default_stream_kafka_max_group_bytes() -> usize {
    255
}

/// 业务作用：限制 topic/partition/member 等 Kafka 数组的循环与状态规模。
///
/// 参数说明: 无。
///
/// 返回：默认每数组最多 4096 项。
pub(super) fn default_stream_kafka_max_array_items() -> usize {
    4096
}

/// 业务作用：为未显式声明的 `version` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_stream_proxy_protocol_upstream_version() -> String {
    "v1".to_string()
}
