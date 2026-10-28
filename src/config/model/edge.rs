//! 边缘订阅、散出、集群传输与会话目录声明。

use super::*;

/// route 级 gRPC 边缘模式配置。
///
/// 这是【默认关闭的叠加模式】:缺省或 `enabled: false` 时,本 route 对 gRPC 的行为
/// 完全等同普通 L7 透传；只有显式开启才让 subscribe/publish/push
/// action header 触发网关自响应。字段默认值与  配置草案一致。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeCfg {
    /// 总开关。false = 本 route 就是普通 gRPC L7 透传;true 且二进制未编 `grpc-edge`
    /// feature 时,快照构建 fail fast(不上线、保留旧快照)。
    #[serde(default)]
    pub enabled: bool,
    /// 本 route 允许的 edge action 列表(平面隔离):公网面只放 `subscribe`,
    /// 内网发布面只放 `publish`/`push`。enabled=true 时不允许为空。
    #[serde(default)]
    pub allowed_actions: Vec<GrpcEdgeActionCfg>,
    /// 携带 action 的请求头名。
    #[serde(default = "default_grpc_edge_action_header")]
    pub action_header: String,
    /// 携带 group id 的请求头名。
    #[serde(default = "default_grpc_edge_group_header")]
    pub group_header: String,
    /// 定向单播携带目标 user 的请求头名。
    #[serde(default = "default_grpc_edge_target_header")]
    pub target_header: String,
    /// 鉴权等级:`required` = 终端用户须先过 route 鉴权;`service` = 发布面服务凭证
    /// (mTLS SAN / 服务 JWT)。构建期强制 subscribe=required、publish/push=service，
    /// 防止同 route 混用终端与发布凭证。
    #[serde(default)]
    pub auth: GrpcEdgeAuthCfg,
    /// 每订阅流的有界发送队列。
    #[serde(default)]
    pub send_queue: GrpcEdgeSendQueueCfg,
    /// 发布面 PublishStream 单流四门(lifetime/messages/rate/bytes)。
    #[serde(default)]
    pub publish_stream: GrpcEdgePublishStreamCfg,
    /// 投递语义。v1 只有 at_most_once;不丢语义走后端有序日志 + 普通 L7 backfill。
    #[serde(default)]
    pub delivery: GrpcEdgeDeliveryCfg,
    /// 发布面消息编码约束。v1 只有 identity:逐消息压缩会破坏"一份字节全订阅者复用"。
    #[serde(default)]
    pub encoding: GrpcEdgeEncodingCfg,
    /// 【兼容别名,已废弃】单条 protobuf message body(不含 5 字节前缀)字节上限。
    /// 权威位置是 `limits.max_msg_bytes`;两处同时设置且不相等时构建期报错,
    /// 只设旧位仍然生效(一次性迁移路径)。
    #[serde(default)]
    pub max_msg_bytes: Option<usize>,
    /// 每 action 的精确 gRPC `:path`。edge 不能只靠可伪造 header 触发,
    /// 必须同时命中精确方法;allowed_actions 里的每个 action 都要有对应 method。
    #[serde(default)]
    pub methods: GrpcEdgeMethodsCfg,
    /// tenant/user 身份从已验证 principal 的 claim 映射( 相位 4),
    /// 客户端自报 header 永不是权威身份。
    #[serde(default)]
    pub identity: GrpcEdgeIdentityCfg,
    /// 双维队列之外的节点级预算与基数上限,拒绝高基数内存攻击。
    #[serde(default)]
    pub limits: GrpcEdgeLimitsCfg,
    /// 浏览器 WS→内部 gRPC 边缘桥接入口路径（如 `/edge/ws`）。
    ///
    /// 设了才开桥;要求本 route 允许 subscribe。桥接只换**传输外壳**——鉴权、身份、
    /// group 索引、队列预算、治理关闭全部复用同一条订阅路径,每条广播以一个
    /// binary 帧原样送出与 native gRPC 订阅者**字节一致**的 `[5B prefix + payload]`。
    #[serde(default)]
    pub ws_bridge_path: Option<String>,
    /// 发布/订阅授权策略；在身份相位之后、任何执行副作用之前判定。
    ///
    /// 为什么必须单列一段:相位 4 只解决了「你是谁」——身份一律取自已验证 principal,
    /// 客户端自报 header 永不作数。但 `group`/`target` 是**客户端给的**,此前只校验
    /// 长度与字符集,于是同一租户内**任何已认证用户都能订阅任意 group、任何已认证
    /// 服务都能向任意 group 发布**。这一段回答「你能碰哪个 group」。
    ///
    /// enabled route 必须显式声明本段；缺失会在构建期拒绝，避免升级后继续沿用
    /// 隐式全放行。只有显式列出的模式放行，未列出的 action 一律拒绝；
    /// 空列表 = 全拒。确需公开放行也必须写出 "*"，让意图可审计。
    #[serde(default)]
    pub authz: Option<GrpcEdgeAuthzCfg>,
}

/// 发布/订阅授权策略。
///
/// 三个 action 各自独立:订阅面通常按用户收敛(只能订自己的),发布面通常按业务域收敛。
/// 未声明的 action 列表为空,即该 action 在本 route 上被全部拒绝——**空 ≠ 不限制**,
/// 否则"配了策略却漏写一个 action"会静默变成完全开放。
///
/// 模式语法:字面量、末尾 `*`(吞掉剩余)、以及 `%{user}` / `%{tenant}` 两个变量
/// (均取自**已验证** principal,客户端 header 永不参与)。例:
/// `subscribe_groups: ["user.%{user}", "room.*"]` = 只能订自己的私有流与任意房间。
///
/// **注意变量前缀是 `%{}` 而不是 `${}`**:gateway.yml 加载器会先把 `${NAME}` 按环境变量
/// 展开,授权规则若用 `${user}`,在存在同名环境变量的机器上会被静默替换成该值,
/// 导致同一份配置在不同机器上放行范围不同。模式里出现 `${` 会在构建期直接报错。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeAuthzCfg {
    /// 允许 subscribe 的 group 模式列表。
    #[serde(default)]
    pub subscribe_groups: Vec<String>,
    /// 允许 publish/publish_stream 的 group 模式列表。
    #[serde(default)]
    pub publish_groups: Vec<String>,
    /// 允许 push 的目标 user 模式列表。
    #[serde(default)]
    pub push_targets: Vec<String>,
}

/// 每 action 的精确 gRPC 方法路径(如 `/naway.edge.v1.NawayEdge/Subscribe`)。
///
/// route 可改路径,但不能用宽泛前缀把普通业务 RPC 误判成 edge。
/// `publish_stream` 归属 publish action:只有 allowed_actions 含 publish 才可声明。
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeMethodsCfg {
    /// Subscribe 方法路径;allowed_actions 含 subscribe 时必填。
    #[serde(default)]
    pub subscribe: Option<String>,
    /// unary Publish 方法路径;allowed_actions 含 publish 时必填。
    #[serde(default)]
    pub publish: Option<String>,
    /// client-streaming PublishStream 方法路径;可选,仅允许 publish 时可声明。
    #[serde(default)]
    pub publish_stream: Option<String>,
    /// unary Push 方法路径;allowed_actions 含 push 时必填。
    #[serde(default)]
    pub push: Option<String>,
}

/// tenant/user 身份的 claim 映射(身份只来自已验证 principal)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeIdentityCfg {
    /// 租户 claim 名;None = 单租户部署,内部统一落 default tenant。
    #[serde(default)]
    pub tenant_claim: Option<String>,
    /// 用户 claim 名(默认 JWT `sub`)。subscribe/push 的 user 索引键来自它。
    #[serde(default = "default_grpc_edge_user_claim")]
    pub user_claim: String,
}

impl Default for GrpcEdgeIdentityCfg {
    /// 业务作用：构造 `GrpcEdgeIdentityCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            tenant_claim: None,
            user_claim: default_grpc_edge_user_claim(),
        }
    }
}

/// 节点级预算与基数上限。
///
/// 仅有每队列上限不足以有界:`流数 × 队深 × 消息大小` 的乘积必须再被节点级
/// payload/引用/任务预算钉死;group/user/session 基数上限拒绝高基数内存攻击。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeLimitsCfg {
    /// 单条 protobuf message body（不含 5 字节前缀）字节上限；解码器读出 prefix
    /// length 后须在分配重组缓冲前执行该限制。
    #[serde(default)]
    pub max_msg_bytes: Option<usize>,
    /// tenant/group/user 等业务 ID 的字节上限。
    #[serde(default = "default_grpc_edge_max_id_bytes")]
    pub max_id_bytes: usize,
    /// 本节点 edge 订阅流总数上限。
    #[serde(default = "default_grpc_edge_max_streams_per_node")]
    pub max_streams_per_node: usize,
    /// 本节点 group 总数上限。
    #[serde(default = "default_grpc_edge_max_groups_per_node")]
    pub max_groups_per_node: usize,
    /// 单 group 成员数上限。
    #[serde(default = "default_grpc_edge_max_members_per_group")]
    pub max_members_per_group: usize,
    /// 单 user 并发 session 上限(多端在线)。
    #[serde(default = "default_grpc_edge_max_sessions_per_user")]
    pub max_sessions_per_user: usize,
    /// 节点唯一 payload 驻留字节预算(所有队列共享同一份 payload 只计一次)。
    #[serde(default = "default_grpc_edge_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// 全节点队列引用总数预算(`Bytes` clone 便宜,但队列元数据与滞留不免费)。
    #[serde(default = "default_grpc_edge_max_queue_refs")]
    pub max_queue_refs: usize,
    /// 并发 fanout job 上限;大群广播分片入队,不允许一次 O(N) 独占 runtime worker。
    #[serde(default = "default_grpc_edge_max_fanout_jobs")]
    pub max_fanout_jobs: usize,
}

impl Default for GrpcEdgeLimitsCfg {
    /// 业务作用：构造 `GrpcEdgeLimitsCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            max_msg_bytes: None,
            max_id_bytes: default_grpc_edge_max_id_bytes(),
            max_streams_per_node: default_grpc_edge_max_streams_per_node(),
            max_groups_per_node: default_grpc_edge_max_groups_per_node(),
            max_members_per_group: default_grpc_edge_max_members_per_group(),
            max_sessions_per_user: default_grpc_edge_max_sessions_per_user(),
            max_payload_bytes: default_grpc_edge_max_payload_bytes(),
            max_queue_refs: default_grpc_edge_max_queue_refs(),
            max_fanout_jobs: default_grpc_edge_max_fanout_jobs(),
        }
    }
}

/// edge action 枚举(serde 小写形态即 header 契约里的取值)。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeActionCfg {
    /// 终端订阅:挂起服务端流并登记进 group 索引。
    Subscribe,
    /// 后端群播:向 group 全体订阅流散出一份负载。
    Publish,
    /// 后端定向单播:向指定 user 的全部在线流投递。
    Push,
}

/// 鉴权等级。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeAuthCfg {
    /// 终端用户面:必须先过 route 级鉴权,身份取已认证 consumer,不裸信 header。
    #[default]
    Required,
    /// 发布面:服务级凭证(mTLS SAN / 服务 JWT),与终端鉴权分池。
    Service,
}

/// 每订阅流有界发送队列配置(消息数 + 逻辑字节双维;单一维度不足以有界)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeSendQueueCfg {
    /// 队列消息数上限;满时按 `overflow` 策略处理,绝不无界积压( 资源纪律)。
    #[serde(default = "default_grpc_edge_send_queue_max_messages")]
    pub max_messages: usize,
    /// 队列逻辑字节上限(帧全长 = 5 字节前缀 + body 计费);大消息 × 流数的聚合
    /// OOM 只有 messages+bytes 双维同时限制才封得住。
    #[serde(default = "default_grpc_edge_send_queue_max_bytes")]
    pub max_bytes: usize,
    /// 队满策略。
    #[serde(default)]
    pub overflow: GrpcEdgeOverflowCfg,
}

impl Default for GrpcEdgeSendQueueCfg {
    /// 业务作用：构造 `GrpcEdgeSendQueueCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            max_messages: default_grpc_edge_send_queue_max_messages(),
            max_bytes: default_grpc_edge_send_queue_max_bytes(),
            overflow: GrpcEdgeOverflowCfg::default(),
        }
    }
}

/// 发布面 PublishStream 单流四门。
///
/// 执行语义(v1):`max_msgs_per_sec` 是背压节流——无令牌即暂停读请求体,经 HTTP/2
/// 流控传导到发布方,不丢消息不断流;其余三门到界即**优雅轮转**——停止读取、返回
/// 已聚合 summary + OK,发布方凭 `messages` 字段判断进度并重建流。仅发布面
/// PublishStream 方法生效,unary Publish/Push 恒为恰一条。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgePublishStreamCfg {
    /// 单流生命周期上限(ms);长发布管道靠周期轮转保持有界,不允许无限流。
    #[serde(default = "default_grpc_edge_publish_stream_max_lifetime_ms")]
    pub max_lifetime_ms: u64,
    /// 单流累计消息数上限。
    #[serde(default = "default_grpc_edge_publish_stream_max_messages")]
    pub max_messages: u64,
    /// 每秒消息数节流(令牌桶容量=速率,连续补充)。
    #[serde(default = "default_grpc_edge_publish_stream_max_msgs_per_sec")]
    pub max_msgs_per_sec: u64,
    /// 单流累计字节上限(帧全长 = 5 字节前缀 + body 计费,与队列口径一致)。
    #[serde(default = "default_grpc_edge_publish_stream_max_total_bytes")]
    pub max_total_bytes: u64,
}

impl Default for GrpcEdgePublishStreamCfg {
    /// 业务作用：构造 `GrpcEdgePublishStreamCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            max_lifetime_ms: default_grpc_edge_publish_stream_max_lifetime_ms(),
            max_messages: default_grpc_edge_publish_stream_max_messages(),
            max_msgs_per_sec: default_grpc_edge_publish_stream_max_msgs_per_sec(),
            max_total_bytes: default_grpc_edge_publish_stream_max_total_bytes(),
        }
    }
}

/// 有界队列溢出策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeOverflowCfg {
    /// 丢最旧、保最新(订阅队列默认)。语义由自有 EdgeRing 在同一临界区弹旧入新实现,
    /// 普通 Tokio mpsc/PollSender 无法冒充。
    #[default]
    DropOldest,
    /// 拒绝新消息、保留既有 FIFO(relay 默认:偷偷删除更早消息再宣称 FIFO 是撒谎)。
    DropNew,
    /// 按 `FramePush.coalesce_key` 只保留每个业务 key 的最新一帧；空键按 drop_new 处理。
    LatestByKey,
    /// 直接断开慢客户端(发 grpc-status 关闭)。
    CloseSlow,
}

/// 投递语义。v1 只允许 at_most_once,枚举保留演进空间。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeDeliveryCfg {
    /// 至多一次:队满/peer 失联即丢并计数;不丢语义由后端 backfill 承担。
    #[default]
    AtMostOnce,
}

/// 发布面编码约束。v1 只允许 identity。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeEncodingCfg {
    /// 明文 gRPC framing:一份 `[前缀+消息体]` 切片可原样复用给全部订阅者与 relay。
    #[default]
    Identity,
}

/// 进程级集群中继面配置(方案 B:一次收单 + naway↔naway hop=1 中继,零 MQ/零 Redis)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeClusterCfg {
    /// relay 双向 TLS；非 loopback 集群必须启用。
    #[serde(default)]
    pub tls: GrpcEdgeRelayTlsCfg,
    /// `relay` = 多节点中继(需要 `grpc-edge` feature);`none` = 显式单机,忽略其余字段。
    #[serde(default)]
    pub mode: GrpcEdgeClusterModeCfg,
    /// `mode: redis_pubsub` 的独立连接与 channel 参数；与 relay 网络面严格互斥。
    #[serde(default)]
    pub redis_pubsub: GrpcEdgeRedisPubSubCfg,
    /// `mode: redis_stream` 的独立 XREAD 与游标参数。
    #[serde(default)]
    pub redis_stream: GrpcEdgeRedisStreamCfg,
    /// 集群身份;relay 握手交换并校验,跨 cluster 连接一律拒绝。relay 模式必填。
    #[serde(default)]
    pub cluster_id: String,
    /// 本节点身份(如 `${POD_UID}`);relay 握手交换,重复 node_id 拒绝、
    /// 较小 node_id 发起唯一连接。relay 模式必填。
    #[serde(default)]
    pub node_id: String,
    /// peer 成员来源。
    #[serde(default)]
    pub membership: GrpcEdgeMembershipCfg,
    /// `membership: static` 时的 peer relay endpoint 列表(host:port);nacos 模式必须留空。
    #[serde(default)]
    pub static_peers: Vec<String>,
    /// 内部 relay 监听地址(host:port),仅接受 peer 身份;relay 模式必填。
    #[serde(default)]
    pub relay_listen: String,
    /// peer 身份鉴别方式：默认 mTLS，在 TLS 握手期验证节点证书；
    /// `cluster_secret` 仅作为缺少 mTLS 基建时的兼容形态。
    #[serde(default)]
    pub peer_auth: GrpcEdgePeerAuthCfg,
    /// `peer_auth: cluster_secret` 的共享凭证(SecretSource:literal/env/file/...);
    /// 该模式下必填非空。数据面只持有构建期已解析值,请求路径不读环境/磁盘。
    #[serde(default)]
    pub cluster_secret: String,
    /// 每 peer 有界中继队列(消息数 + 字节双维)。
    #[serde(default)]
    pub relay_queue: GrpcEdgeRelayQueueCfg,
    /// ingress 聚合 peer enqueue-ack 的固定 deadline(ms);超时记 unknown、不自动重试
    /// ( 背压与回执)。对应  示例 `ack_deadline: 100ms`,本仓统一 `_ms` 整数。
    #[serde(default = "default_grpc_edge_ack_deadline_ms")]
    pub ack_deadline_ms: u64,
    /// 全网状中继的节点数硬门。静态 peers 或 Nacos 成员超门直接拒绝；
    /// `auto` 只降低无关 group 的 payload 流量，不改变全网状连接数量。
    #[serde(default = "default_grpc_edge_full_mesh_max_nodes")]
    pub full_mesh_max_nodes: usize,
    /// 兴趣路由策略：`auto` 使用 revision 快照过滤明确无兴趣的 peer，hint 缺失、断档或过期
    /// 一律 fail-open 广播；`broadcast_all` 显式永远广播且仅允许建议规模内的小集群。
    #[serde(default)]
    pub interest_route: GrpcEdgeInterestRouteCfg,
    /// 顺序承诺:默认仅"同 publisher stream → 同 ingress → 同目标队列"FIFO;
    /// `group_owner` 通过确定性 owner + 分片串行锁承诺跨发布者的 group 严格序。
    #[serde(default)]
    pub ordering: GrpcEdgeOrderingCfg,
    /// 用户会话语义:默认多端在线,probe 等全部节点到 deadline;
    /// `single_session` 必须显式配置；relay owner 以全 mesh fencing token 踢旧 session。
    #[serde(default)]
    pub session_mode: GrpcEdgeSessionModeCfg,
    /// 定向单播指路条。`none` = broadcast-probe(默认,零外部依赖);
    /// `redis` = 大集群可选加速,需要 `redis-runtime` feature。
    #[serde(default)]
    pub session_registry: GrpcEdgeSessionRegistryCfg,
    /// `session_registry: redis` 的连接与租约参数；`none` 时整段忽略。
    #[serde(default)]
    pub session_directory: GrpcEdgeSessionDirectoryCfg,
    /// relay **收包散出**使用的节点级预算。
    ///
    /// 为什么单列一段:relay 收到的 record 来自对端节点,**不经本地路由匹配**,因此没有
    /// route 计划可依。此前这里硬编码 `GrpcEdgeLimitsCfg::default`,后果是运维把某条
    /// route 的 `grpc_edge.limits` 调大之后,**本地发布放宽了而经 peer 中继的同一条消息
    /// 仍按默认值被拒**——同一业务动作在本节点和跨节点表现不同,且没有任何配置能改。
    ///
    /// 刻意**不**从各 route 的 limits 取并集:那是隐式推导,改一条 route 会静默改变整个
    /// 集群面的准入,审查时看不出来。要放宽 relay 面必须在集群块里写明。
    /// 默认值与 route 默认一致,不配置即维持既有行为。
    ///
    /// 注意 `max_msg_bytes` 在此段无效:relay record 的尺寸已由协议硬上限
    /// `RELAY_MAX_PAYLOAD_BYTES` 在解码层钉死,不允许配置放宽。
    #[serde(default)]
    pub fanout_limits: GrpcEdgeLimitsCfg,
}

/// SessionDirectory（Redis）连接与租约参数。
///
/// 目录只做寻址加速:miss/超时/脏条目一律回落 broadcast-probe,正确性不依赖它。
/// 因此 TTL 只需覆盖"续租任务两三个周期"的量级,不必追求与连接寿命等长。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeSessionDirectoryCfg {
    /// Redis URL,如 `redis://:password@127.0.0.1:6379`。`session_registry=redis` 时必填。
    #[serde(default)]
    pub url: String,
    /// nadis 协议命名空间。
    #[serde(default = "default_edge_directory_namespace")]
    pub namespace: String,
    /// nadis 兼容 profile。
    #[serde(default = "default_edge_directory_profile")]
    pub profile: String,
    /// 目录 key 前缀(完整 key = `{prefix}:{cluster_id}:{tenant}:{user}`)。
    #[serde(default = "default_edge_directory_prefix")]
    pub prefix: String,
    /// 租约 key TTL(ms);进程崩溃来不及 unbind 时由它兜底回收。
    #[serde(default = "default_edge_directory_ttl_ms")]
    pub ttl_ms: u64,
    /// 单条目录命令硬超时(ms);目录慢绝不能拖慢 push 主路径。
    #[serde(default = "default_edge_directory_command_timeout_ms")]
    pub command_timeout_ms: u64,
}

/// Redis Pub/Sub 集群散出参数。该模式没有持久化、背压或远端 ACK。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeRedisPubSubCfg {
    /// Redis/Valkey URL。
    #[serde(default)]
    pub url: String,
    /// nadis 协议命名空间。
    #[serde(default = "default_edge_directory_namespace")]
    pub namespace: String,
    /// nadis 兼容 profile。
    #[serde(default = "default_edge_directory_profile")]
    pub profile: String,
    /// 广播 channel；为空时派生为 `naway:edge:{cluster_id}`。
    #[serde(default)]
    pub channel: String,
    /// PUBLISH/重连命令硬超时(ms)。
    #[serde(default = "default_edge_redis_pubsub_command_timeout_ms")]
    pub command_timeout_ms: u64,
    /// 订阅断线后的重连退避(ms)。
    #[serde(default = "default_edge_redis_pubsub_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for GrpcEdgeRedisPubSubCfg {
    /// 业务作用：构造 `GrpcEdgeRedisPubSubCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_edge_directory_namespace(),
            profile: default_edge_directory_profile(),
            channel: String::new(),
            command_timeout_ms: default_edge_redis_pubsub_command_timeout_ms(),
            reconnect_backoff_ms: default_edge_redis_pubsub_reconnect_backoff_ms(),
        }
    }
}

/// 业务作用：为未显式声明的 `command_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_redis_pubsub_command_timeout_ms() -> u64 {
    1_000
}

/// 业务作用：为未显式声明的 `reconnect_backoff_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_redis_pubsub_reconnect_backoff_ms() -> u64 {
    500
}

/// Redis Stream 广播参数。每个 Naway 节点使用独立 XREAD 游标；绝不使用共享消费组。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeRedisStreamCfg {
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_edge_directory_namespace")]
    pub namespace: String,
    #[serde(default = "default_edge_directory_profile")]
    pub profile: String,
    /// Stream key；为空时派生为 `naway:edge:{cluster_id}`。
    #[serde(default)]
    pub stream: String,
    /// 每节点游标 key 前缀，完整 key 追加 cluster_id/node_id。
    #[serde(default = "default_edge_redis_stream_cursor_prefix")]
    pub cursor_prefix: String,
    /// 每次 XREAD 的 COUNT。
    #[serde(default = "default_edge_redis_stream_batch_size")]
    pub batch_size: usize,
    /// XREAD BLOCK 毫秒。
    #[serde(default = "default_edge_redis_stream_block_ms")]
    pub block_ms: u64,
    /// XADD/游标命令硬超时(ms)。
    #[serde(default = "default_edge_redis_pubsub_command_timeout_ms")]
    pub command_timeout_ms: u64,
    /// 读循环错误后的退避(ms)。
    #[serde(default = "default_edge_redis_pubsub_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for GrpcEdgeRedisStreamCfg {
    /// 业务作用：构造 `GrpcEdgeRedisStreamCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_edge_directory_namespace(),
            profile: default_edge_directory_profile(),
            stream: String::new(),
            cursor_prefix: default_edge_redis_stream_cursor_prefix(),
            batch_size: default_edge_redis_stream_batch_size(),
            block_ms: default_edge_redis_stream_block_ms(),
            command_timeout_ms: default_edge_redis_pubsub_command_timeout_ms(),
            reconnect_backoff_ms: default_edge_redis_pubsub_reconnect_backoff_ms(),
        }
    }
}

/// 业务作用：为未显式声明的 `cursor_prefix` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_redis_stream_cursor_prefix() -> String {
    "naway:edge:cursor".to_string()
}

/// 业务作用：为未显式声明的 `batch_size` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_redis_stream_batch_size() -> usize {
    100
}

/// 业务作用：为未显式声明的 `block_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_redis_stream_block_ms() -> u64 {
    500
}

impl Default for GrpcEdgeSessionDirectoryCfg {
    /// 业务作用：构造 `GrpcEdgeSessionDirectoryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            url: String::new(),
            namespace: default_edge_directory_namespace(),
            profile: default_edge_directory_profile(),
            prefix: default_edge_directory_prefix(),
            ttl_ms: default_edge_directory_ttl_ms(),
            command_timeout_ms: default_edge_directory_command_timeout_ms(),
        }
    }
}

/// 业务作用：为未显式声明的 `namespace` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_directory_namespace() -> String {
    "naway".to_string()
}

/// 业务作用：为未显式声明的 `profile` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_directory_profile() -> String {
    "RustV2".to_string()
}

/// 业务作用：为未显式声明的 `prefix` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_directory_prefix() -> String {
    "naway:edge:sess".to_string()
}

/// 业务作用：为未显式声明的 `ttl_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_directory_ttl_ms() -> u64 {
    60_000
}

/// 业务作用：为未显式声明的 `command_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_edge_directory_command_timeout_ms() -> u64 {
    100
}

/// 每 peer 有界中继队列(默认比订阅队列深:一个 peer 背后是整节点的订阅者集合)。
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcEdgeRelayQueueCfg {
    /// 队列消息数上限。
    #[serde(default = "default_grpc_edge_relay_queue_max_messages")]
    pub max_messages: usize,
    /// 队列逻辑字节上限(RelayRecord 全长计费)。
    #[serde(default = "default_grpc_edge_relay_queue_max_bytes")]
    pub max_bytes: usize,
    /// 队满策略;relay 默认 `drop_new`,`close_slow` 对 peer 无意义、构建期拒绝。
    #[serde(default = "default_grpc_edge_relay_overflow")]
    pub overflow: GrpcEdgeOverflowCfg,
}

impl Default for GrpcEdgeRelayQueueCfg {
    /// 业务作用：构造 `GrpcEdgeRelayQueueCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            max_messages: default_grpc_edge_relay_queue_max_messages(),
            max_bytes: default_grpc_edge_relay_queue_max_bytes(),
            overflow: default_grpc_edge_relay_overflow(),
        }
    }
}

/// 兴趣路由策略。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeInterestRouteCfg {
    /// 自动传播各节点当前 tenant/group 兴趣，只向明确有兴趣的 peer 发送业务 payload。
    /// hint 未就绪、版本断档或过期时 fail-open 广播，优化面不参与正确性。
    #[default]
    Auto,
    /// 显式声明永远向全部 peer 广播；仅允许小集群使用。
    BroadcastAll,
}

/// 跨节点顺序承诺。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeOrderingCfg {
    /// 尽力而为,无任何顺序承诺。
    BestEffort,
    /// 默认:同 publisher stream 经同 ingress 到同目标队列保持 FIFO。
    #[default]
    IngressFifo,
    /// group 严格序：由 rendezvous-hash group owner 统一定序。
    GroupOwner,
}

/// 用户会话语义。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeSessionModeCfg {
    /// 多端在线:定向 push 等全部节点到 deadline,不首命中即返回。
    #[default]
    MultiSession,
    /// 单端登录:登录阶段踢旧 session;必须显式配置。
    SingleSession,
}

/// 中继面模式。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeClusterModeCfg {
    /// 多节点中继(默认:配置了本段即视为要集群)。
    #[default]
    Relay,
    /// Redis Pub/Sub 广播；不启动 relay listener/peer discovery/session directory。
    RedisPubsub,
    /// Redis Stream 广播；每节点独立 XREAD 游标，历史裁剪完全由业务侧负责。
    RedisStream,
    /// 显式单机;等同不配置本段。
    None,
}

/// peer 成员来源。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeMembershipCfg {
    /// 复用  Nacos 自注册 watch 驱动运行时成员对账。
    #[default]
    Nacos,
    /// 静态 peer 列表(all-in-one/无注册中心部署)。
    Static,
}

/// peer 身份鉴别方式。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgePeerAuthCfg {
    /// 双向 TLS(默认, 优先):证书身份即节点身份,握手期校验。
    #[default]
    Mtls,
    /// 集群共享 secret（SecretSource，)；仅作为无 mTLS 基建时的过渡认证形态。
    ClusterSecret,
}

/// 定向单播指路条后端。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEdgeSessionRegistryCfg {
    /// broadcast-probe:无外部依赖,正确性不靠指路条。
    #[default]
    None,
    /// Redis user→node 指路条,仅作探测加速;失效自动回落 probe。
    Redis,
}

/// 业务作用：为未显式声明的 `action_header` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_action_header() -> String {
    "x-naway-edge-action".to_string()
}

/// 业务作用：为未显式声明的 `group_header` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_group_header() -> String {
    "x-naway-group".to_string()
}

/// 业务作用：为未显式声明的 `target_header` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_target_header() -> String {
    "x-naway-target-user".to_string()
}

/// 业务作用：为未显式声明的 `user_claim` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_user_claim() -> String {
    "sub".to_string()
}

/// 业务作用：为未显式声明的 `max_id_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_id_bytes() -> usize {
    128
}

/// 业务作用：为未显式声明的 `max_streams_per_node` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_streams_per_node() -> usize {
    200_000
}

/// 业务作用：为未显式声明的 `max_groups_per_node` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_groups_per_node() -> usize {
    100_000
}

/// 业务作用：为未显式声明的 `max_members_per_group` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_members_per_group() -> usize {
    100_000
}

/// 业务作用：为未显式声明的 `max_sessions_per_user` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_sessions_per_user() -> usize {
    8
}

/// 业务作用：为未显式声明的 `max_payload_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_payload_bytes() -> usize {
    536_870_912
}

/// 业务作用：为未显式声明的 `max_queue_refs` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_queue_refs() -> usize {
    4_000_000
}

/// 业务作用：为未显式声明的 `max_fanout_jobs` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_max_fanout_jobs() -> usize {
    4_096
}

/// 业务作用：为未显式声明的 `max_messages` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_send_queue_max_messages() -> usize {
    256
}

/// 业务作用：为未显式声明的 `max_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_send_queue_max_bytes() -> usize {
    4_194_304
}

/// 业务作用：为未显式声明的 `max_lifetime_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_publish_stream_max_lifetime_ms() -> u64 {
    3_600_000
}

/// 业务作用：为未显式声明的 `max_messages` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_publish_stream_max_messages() -> u64 {
    1_000_000
}

/// 业务作用：为未显式声明的 `max_msgs_per_sec` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_publish_stream_max_msgs_per_sec() -> u64 {
    10_000
}

/// 业务作用：为未显式声明的 `max_total_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_publish_stream_max_total_bytes() -> u64 {
    4_294_967_296
}

/// 业务作用：为未显式声明的 `max_messages` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_relay_queue_max_messages() -> usize {
    1_024
}

/// 业务作用：为未显式声明的 `max_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_relay_queue_max_bytes() -> usize {
    67_108_864
}

/// 业务作用：为未显式声明的 `overflow` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_relay_overflow() -> GrpcEdgeOverflowCfg {
    GrpcEdgeOverflowCfg::DropNew
}

/// 业务作用：为未显式声明的 `ack_deadline_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_ack_deadline_ms() -> u64 {
    100
}

/// 业务作用：为未显式声明的 `full_mesh_max_nodes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_grpc_edge_full_mesh_max_nodes() -> usize {
    32
}

/// gRPC edge relay 双向 TLS 配置。
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrpcEdgeRelayTlsCfg {
    /// 是否启用 relay mTLS。
    pub enabled: bool,
    /// 所有 relay 节点证书覆盖的固定 DNS 身份。
    pub server_name: String,
    /// relay 专用 CA PEM 绝对路径。
    pub ca_file: String,
    /// 本节点证书链 PEM 绝对路径。
    pub cert_file: String,
    /// 本节点私钥 PEM 绝对路径。
    pub key_file: String,
    /// 单次 TLS 握手硬超时。
    pub handshake_timeout_ms: u64,
}

impl Default for GrpcEdgeRelayTlsCfg {
    /// 业务作用：构造 `GrpcEdgeRelayTlsCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: "relay.naway.internal".to_string(),
            ca_file: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            handshake_timeout_ms: 5_000,
        }
    }
}
