//! gRPC 边缘模式的构建期契约。
//!
//! 本文件负责 route 级 `grpc_edge` 与进程级 `grpc_edge_cluster` 的解析定型和构建期
//! 拒绝矩阵。数据面由 [crate::edge::hub]、[crate::proxy] 与 [crate::edge::relay] 承担；本层必须拒绝任何
//! 没有运行时执行语义的选项，避免配置成功但静默退化。
//!
//! 校验顺序刻意是【值校验在前、feature 门在后】:这样"坏配置逐条被拒"的报错
//! 文案不因是否编译 `grpc-edge` 而改变；feature 门只在其余配置全部合法时作为最后一道闸。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use http::header::{HeaderName, HeaderValue};

use crate::config::model::{
    GrpcEdgeActionCfg, GrpcEdgeAuthCfg, GrpcEdgeCfg, GrpcEdgeClusterCfg, GrpcEdgeClusterModeCfg,
    GrpcEdgeDeliveryCfg, GrpcEdgeEncodingCfg, GrpcEdgeIdentityCfg, GrpcEdgeInterestRouteCfg,
    GrpcEdgeLimitsCfg, GrpcEdgeMembershipCfg, GrpcEdgeMethodsCfg, GrpcEdgeOrderingCfg,
    GrpcEdgeOverflowCfg, GrpcEdgePeerAuthCfg, GrpcEdgePublishStreamCfg, GrpcEdgeRelayQueueCfg,
    GrpcEdgeSendQueueCfg, GrpcEdgeSessionModeCfg, GrpcEdgeSessionRegistryCfg,
};

/// 单队列消息数硬上限。配合 `max_bytes` 与节点级 payload/ref/job 预算,把
/// `流数 × 队深 × 消息大小` 的乘积钉死在可审计范围内。
const MAX_QUEUE_MESSAGES: usize = 65_536;
/// 单队列逻辑字节硬上限:1 GiB。逻辑字节按帧/record 全长计费。
const MAX_QUEUE_BYTES: usize = 1024 * 1024 * 1024;
/// 单条 protobuf message body(不含 5 字节 gRPC 前缀)硬上限:16 MiB。
/// decoder 必须先校验 prefix 中的 length 再申请重组内存。
/// 边缘散出面向行情/IM 小帧,更大负载应走普通 L7。
const MAX_MSG_BYTES: usize = 16 * 1024 * 1024;
/// gRPC message 前缀长度(compressed flag 1B + big-endian length 4B)。
/// 订阅队列的计费单位是完整帧 `[prefix + body]`,因此 `send_queue.max_bytes`
/// 必须至少容得下一条最大消息的帧全长。
const GRPC_MESSAGE_PREFIX_BYTES: usize = 5;
/// 业务 ID 上限的硬上限(`limits.max_id_bytes` 只能配得更小)。
const MAX_ID_BYTES_CAP: usize = 1_024;
/// claim 名字节上限。
const MAX_CLAIM_BYTES: usize = 256;
/// 精确 gRPC 方法路径字节上限。
const MAX_METHOD_PATH_BYTES: usize = 256;
/// stream/group/member 三类基数上限的硬上限。
const MAX_CARDINALITY_CAP: usize = 10_000_000;
/// 单 user 并发 session 硬上限。
const MAX_SESSIONS_PER_USER_CAP: usize = 64;
/// 节点唯一 payload 预算硬上限:16 GiB。
const MAX_PAYLOAD_BYTES_CAP: usize = 16 * 1024 * 1024 * 1024;
/// 节点队列引用总数硬上限。
const MAX_QUEUE_REFS_CAP: usize = 100_000_000;
/// 并发 fanout job 硬上限。
const MAX_FANOUT_JOBS_CAP: usize = 65_536;
/// relay enqueue-ack deadline 硬上限(ms)。
const MAX_ACK_DEADLINE_MS: u64 = 60_000;
/// PublishStream 单流生命周期硬上限:24h。长发布管道靠周期轮转保持有界。
const MAX_PUBLISH_STREAM_LIFETIME_MS_CAP: u64 = 86_400_000;
/// PublishStream 单流累计消息数硬上限。
const MAX_PUBLISH_STREAM_MESSAGES_CAP: u64 = 100_000_000;
/// PublishStream 每秒消息数节流硬上限。
const MAX_PUBLISH_STREAM_RATE_CAP: u64 = 1_000_000;
/// PublishStream 单流累计字节硬上限:1 TiB(累计口径,非驻留内存;驻留由节点预算钉死)。
const MAX_PUBLISH_STREAM_TOTAL_BYTES_CAP: u64 = 1_099_511_627_776;
/// `full_mesh_max_nodes` 可配置的硬上限。
const MAX_FULL_MESH_NODES_CAP: usize = 256;
/// 全网状广播的建议节点上限；超过时必须启用 interest 路由，限制无订阅节点的无效散出。
const RECOMMENDED_FULL_MESH_NODES: usize = 32;
/// 目录租约 TTL 下界（ms）：续租按 TTL/3 触发，过短会让在线 session 频繁抖动。
const MIN_DIRECTORY_TTL_MS: u64 = 3_000;
/// 目录租约 TTL 上界（ms）：崩溃节点的脏条目最多滞留这么久。
const MAX_DIRECTORY_TTL_MS: u64 = 3_600_000;
/// 单条目录命令硬超时上界（ms）。
const MAX_DIRECTORY_COMMAND_TIMEOUT_MS: u64 = 5_000;
/// cluster_id 字节上限。
const MAX_CLUSTER_ID_BYTES: usize = 64;
/// node_id 字节上限(容纳 `${POD_UID}` 这类 UUID 形态)。
const MAX_NODE_ID_BYTES: usize = 128;
/// 单条授权模式的字节上限。模式在构建期编译、运行期只做逐段比较,长度限制是为了
/// 让配置错误(例如把整份名单粘成一条)在构建期就被挡住。
const MAX_AUTHZ_PATTERN_BYTES: usize = 512;
/// relay 收包散出的单条 message 上限。**不可配置**:record 尺寸已由 relay 协议在解码层
/// 钉死,允许配置放宽只会制造「配置校验通过、解码器仍然拒收」的自相矛盾状态。
/// 与 `edge_relay::RELAY_MAX_PAYLOAD_BYTES - GRPC_MESSAGE_PREFIX_BYTES` 必须相等,
/// 该模块受 `grpc-edge` 门控,故在此重述常量以便无 feature 构建同样能做值校验;
/// 一致性由 `edge_relay` 侧的编译期断言保证。
pub const RELAY_FANOUT_MAX_MSG_BYTES: usize = MAX_MSG_BYTES;

/// 每 action 的已编译精确方法路径(edge 只能由精确 `:path` + allowed_actions
/// + 鉴权三者同时命中触发,header action 只是 v1 的二次确认)。
#[derive(PartialEq, Eq)]
pub struct GrpcEdgeMethodPlan {
    /// Subscribe 精确路径;允许 subscribe 时必有。
    pub subscribe: Option<Box<str>>,
    /// unary Publish 精确路径;允许 publish 时必有。
    pub publish: Option<Box<str>>,
    /// client-streaming PublishStream 精确路径;可选。
    pub publish_stream: Option<Box<str>>,
    /// unary Push 精确路径;允许 push 时必有。
    pub push: Option<Box<str>>,
}

/// 已编译身份映射:tenant/user 一律来自已验证 principal 的 claim。
#[derive(PartialEq, Eq)]
pub struct GrpcEdgeIdentityPlan {
    /// 租户 claim;None = 单租户。
    pub tenant_claim: Option<Box<str>>,
    /// 用户 claim(默认 `sub`)。
    pub user_claim: Box<str>,
}

/// 已编译节点级预算与基数上限。
#[derive(Clone, PartialEq, Eq)]
pub struct GrpcEdgeLimitsPlan {
    /// 单条 message body 字节上限(不含 5 字节前缀)。
    pub max_msg_bytes: usize,
    /// 业务 ID 字节上限。
    pub max_id_bytes: usize,
    /// 节点订阅流总数上限。
    pub max_streams_per_node: usize,
    /// 节点 group 总数上限。
    pub max_groups_per_node: usize,
    /// 单 group 成员数上限。
    pub max_members_per_group: usize,
    /// 单 user 并发 session 上限。
    pub max_sessions_per_user: usize,
    /// 节点唯一 payload 驻留字节预算。
    pub max_payload_bytes: usize,
    /// 节点队列引用总数预算。
    pub max_queue_refs: usize,
    /// 并发 fanout job 上限。
    pub max_fanout_jobs: usize,
}

impl GrpcEdgeLimitsPlan {
    /// 两份预算是否逐项相等。
    ///
    /// 业务作用:供 [`GrpcEdgeClusterPlan::same_runtime_topology`] 判定 relay 面预算
    /// 有无变化。相等才允许热更继续复用常驻 relay;不等必须按拓扑变化拒绝,
    /// 否则 reload 会成功但新预算永远进不了运行态。
    ///
    /// 参数说明:
    /// - `other`: 候选快照里的同段预算。
    ///
    /// 返回:全部字段相等返回 true;任一不等返回 false。
    pub fn same_budget(&self, other: &Self) -> bool {
        self.max_msg_bytes == other.max_msg_bytes
            && self.max_id_bytes == other.max_id_bytes
            && self.max_streams_per_node == other.max_streams_per_node
            && self.max_groups_per_node == other.max_groups_per_node
            && self.max_members_per_group == other.max_members_per_group
            && self.max_sessions_per_user == other.max_sessions_per_user
            && self.max_payload_bytes == other.max_payload_bytes
            && self.max_queue_refs == other.max_queue_refs
            && self.max_fanout_jobs == other.max_fanout_jobs
    }
}

/// 已编译授权模式的一个片段。
///
/// 只支持「字面量 / `%{user}` / `%{tenant}` / 末尾 `*`」四种,刻意不做通用 glob:
/// 通用 glob 的匹配代价与回溯行为都不适合放在鉴权路径上,而且难以一眼看出一条规则
/// 到底放行了什么——授权规则的可审查性比表达力重要。
///
/// 变量用 `%{...}` 而**不是**全仓通用的 `${...}`:gateway.yml 的加载器会先把 `${NAME}`
/// 按环境变量解析(未命中才留给运行期变量系统)。若授权模式用 `${user}`,在恰好存在
/// 同名环境变量的机器上会被**静默**替换成该环境变量的值——同一份配置在不同机器上
/// 放行范围不同,且毫无提示。这在授权语义上不可接受,因此换用不会冲突的前缀,
/// 并在编译时把模式里出现的 `${` 直接判为错误(见 [`build_authz_pattern`])。
#[derive(Debug, PartialEq, Eq)]
enum AuthzSegment {
    /// 必须逐字节相等的字面片段。
    Literal(Box<str>),
    /// 替换为本次请求已验证的 user principal。
    User,
    /// 替换为本次请求已验证的 tenant。
    Tenant,
    /// 只能出现在末尾:吞掉剩余全部字符(含空)。
    RestWildcard,
}

/// 一条已编译的授权模式。
#[derive(PartialEq, Eq)]
pub struct AuthzPattern {
    segments: Vec<AuthzSegment>,
}

impl AuthzPattern {
    /// 判断本模式是否放行给定的 group/target。
    ///
    /// 业务作用:授权判定的最小单元。逐段消费 `value`,变量段用**本次请求已验证的**
    /// 身份现场比较,**不拼接字符串**——鉴权路径不做分配,也避免把用户可控内容
    /// 拼成新串后再比较时引入意外的等价形态。
    ///
    /// 参数说明:
    /// - `value`: 客户端给出的 group 或 push target。
    /// - `user`: 已验证 principal。
    /// - `tenant`: 已验证租户。
    ///
    /// 返回:完全匹配(或末尾通配吞掉剩余)返回 true;任一段不符返回 false。
    fn matches(&self, value: &str, user: &str, tenant: &str) -> bool {
        let mut rest = value;
        for segment in &self.segments {
            let expect = match segment {
                AuthzSegment::Literal(literal) => literal.as_ref(),
                // 变量展开为空一律判不匹配。principal/tenant 非空目前由**构建期**的
                // 认证策略校验保证(api_key 的 `consumer=` 走 validate_basic_auth_user、
                // JWT claim 走非空+长度+控制字符校验),但那是三个模块之外的不变量——
                // 鉴权判定不该依赖"别处应该已经拦住了"。这里显式兜住:否则一旦上游
                // 放松,规则 `user.%{user}` 会退化成放行字面量 `user.`。
                AuthzSegment::User if user.is_empty() => return false,
                AuthzSegment::Tenant if tenant.is_empty() => return false,
                AuthzSegment::User => user,
                AuthzSegment::Tenant => tenant,
                // 末尾通配:剩下多少都放行,包括剩下空串。
                AuthzSegment::RestWildcard => return true,
            };
            match rest.strip_prefix(expect) {
                Some(remaining) => rest = remaining,
                None => return false,
            }
        }
        rest.is_empty()
    }
}

/// 已编译的 route 级发布/订阅授权策略( 相位 4 之后执行)。
///
/// enabled route 的授权段由构建器强制存在；结构内一律 deny-by-default。
#[derive(PartialEq, Eq)]
pub struct GrpcEdgeAuthzPlan {
    /// 允许 subscribe 的 group 模式;空 = 该 action 全拒。
    pub subscribe_groups: Vec<AuthzPattern>,
    /// 允许 publish/publish_stream 的 group 模式;空 = 该 action 全拒。
    pub publish_groups: Vec<AuthzPattern>,
    /// 允许 push 的目标 user 模式;空 = 该 action 全拒。
    pub push_targets: Vec<AuthzPattern>,
}

impl GrpcEdgeAuthzPlan {
    /// 判定某 action 是否可以作用于给定 group/target。
    ///
    /// 业务作用:边缘面「你能碰哪个 group」的唯一判据。调用点必须在身份解析(相位 4)
    /// **之后**、任何订阅登记/散出/入队**之前**——放行前不得产生任何可观察副作用,
    /// 否则被拒的探测请求仍能从资源占用或时序上反推出 group 是否存在。
    ///
    /// 参数说明:
    /// - `action`: 本次请求命中的 edge action。
    /// - `value`: 客户端给出的 group(subscribe/publish)或 target user(push)。
    /// - `user`: 已验证 principal。
    /// - `tenant`: 已验证租户。
    ///
    /// 返回:命中任一模式返回 true;否则 false(调用方据此回 7 PERMISSION_DENIED)。
    pub fn allows(&self, action: GrpcEdgeAction, value: &str, user: &str, tenant: &str) -> bool {
        let patterns = match action {
            GrpcEdgeAction::Subscribe => &self.subscribe_groups,
            GrpcEdgeAction::Publish | GrpcEdgeAction::PublishStream => &self.publish_groups,
            GrpcEdgeAction::Push => &self.push_targets,
        };
        patterns
            .iter()
            .any(|pattern| pattern.matches(value, user, tenant))
    }
}

/// 已编译发布面 PublishStream 单流四门(执行语义见 model 层 rustdoc:
/// rate=背压节流,lifetime/messages/bytes=优雅轮转返聚合 summary)。
#[derive(PartialEq, Eq)]
pub struct GrpcEdgePublishStreamPlan {
    /// 单流生命周期上限。
    pub max_lifetime: Duration,
    /// 单流累计消息数上限。
    pub max_messages: u64,
    /// 每秒消息数(令牌桶容量与补充速率)。
    pub max_msgs_per_sec: u64,
    /// 单流累计字节上限(帧全长计费,与队列口径一致)。
    pub max_total_bytes: u64,
}

/// 运行期 edge action(由精确 `:path` 反查;:方法先行,header 只是 v1 二次确认)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrpcEdgeAction {
    /// 终端订阅(server-streaming 自响应)。
    Subscribe,
    /// 后端 unary 群播。
    Publish,
    /// 后端 client-streaming 群播。
    PublishStream,
    /// 后端定向单播。
    Push,
}

impl GrpcEdgeAction {
    /// 业务作用：header 契约里的 v1 action 值;publish_stream 归属 publish action。
    pub fn header_value(self) -> &'static str {
        match self {
            Self::Subscribe => "subscribe",
            Self::Publish | Self::PublishStream => "publish",
            Self::Push => "push",
        }
    }
}

/// route 级已编译边缘计划。
///
/// 字段在构建期定型为运行期可直接使用的类型(如 `HeaderName`/精确路径),请求热路径
/// 不再做字符串校验。数据面据此执行方法匹配、身份校验、授权和资源准入。
#[derive(PartialEq, Eq)]
pub struct GrpcEdgePlan {
    /// 允许的 action 集(平面隔离):公网面只放 subscribe,发布面只放 publish/push。
    pub allow_subscribe: bool,
    /// 是否允许后端群播。
    pub allow_publish: bool,
    /// 是否允许后端定向单播。
    pub allow_push: bool,
    /// 每 action 精确方法路径。
    pub methods: GrpcEdgeMethodPlan,
    /// action 请求头(已验证合法且小写;v1 协议二次确认用,不能覆盖方法对应 action)。
    pub action_header: HeaderName,
    /// group 请求头。
    pub group_header: HeaderName,
    /// 定向单播目标 user 请求头。
    pub target_header: HeaderName,
    /// 鉴权等级(required=终端用户面;service=发布面服务凭证)。
    pub auth: GrpcEdgeAuthCfg,
    /// 身份 claim 映射。
    pub identity: GrpcEdgeIdentityPlan,
    /// 每订阅流消息数上限。
    pub send_queue_max_messages: usize,
    /// 每订阅流逻辑字节上限(帧全长计费);与消息数构成双维有界队列。
    pub send_queue_max_bytes: usize,
    /// 队满策略。
    pub overflow: GrpcEdgeOverflowCfg,
    /// 投递语义(v1 恒为 at_most_once,保留字段供演进)。
    pub delivery: GrpcEdgeDeliveryCfg,
    /// 编码约束(v1 恒为 identity)。
    pub encoding: GrpcEdgeEncodingCfg,
    /// 节点级预算与基数上限。
    pub limits: GrpcEdgeLimitsPlan,
    /// 发布面 PublishStream 单流四门。
    pub publish_stream: GrpcEdgePublishStreamPlan,
    /// WS 桥接入口路径（None=不开桥）。
    pub ws_bridge_path: Option<Box<str>>,
    /// 发布/订阅授权策略。edge route 必须显式配置；每 action 独立
    /// deny-by-default，刻意公开时也必须写 `*`。
    pub authz: Option<GrpcEdgeAuthzPlan>,
}

impl GrpcEdgePlan {
    /// 业务作用：精确 `:path` → action。不匹配返回 None:该请求不属于 edge 面,照常走普通
    /// L7 转发( 连接模型:同 route 的非 edge RPC 一字节不受影响)。
    pub fn match_method(&self, path: &str) -> Option<GrpcEdgeAction> {
        let hit = |candidate: &Option<Box<str>>| {
            candidate.as_deref().is_some_and(|method| method == path)
        };
        if hit(&self.methods.subscribe) {
            Some(GrpcEdgeAction::Subscribe)
        } else if hit(&self.methods.publish) {
            Some(GrpcEdgeAction::Publish)
        } else if hit(&self.methods.publish_stream) {
            Some(GrpcEdgeAction::PublishStream)
        } else if hit(&self.methods.push) {
            Some(GrpcEdgeAction::Push)
        } else {
            None
        }
    }

    /// 业务作用：从 route 配置编译边缘计划。
    ///
    /// 参数说明：
    /// - `cfg`: route 的 `grpc_edge` 段;None 或 `enabled: false` 都返回 `Ok(None)`,
    ///   即该 route 保持普通 L7 透传(默认行为,可预置配置不生效)。
    /// - `route_id`: 仅用于报错定位。
    ///
    /// 返回:开启且全部校验通过时的已编译计划。任何一条拒绝都让整个快照构建失败,
    /// reload 事务保留旧快照(坏配置不上线)。
    pub fn build(cfg: Option<&GrpcEdgeCfg>, route_id: &str) -> Result<Option<Self>> {
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        if !cfg.enabled {
            // 显式关闭 = 允许预置配置块;不做值校验,serde 类型/未知字段仍然兜底。
            return Ok(None);
        }

        // —— 值校验(先于 feature 门,保证三种构建形态报错一致)——
        if cfg.allowed_actions.is_empty() {
            bail!(
                "route `{route_id}` grpc_edge.allowed_actions must not be empty; \
                 declare the plane explicitly, e.g. [subscribe] on public listeners \
                 or [publish, push] on the internal publish listener"
            );
        }
        let mut allow_subscribe = false;
        let mut allow_publish = false;
        let mut allow_push = false;
        for action in &cfg.allowed_actions {
            let slot = match action {
                GrpcEdgeActionCfg::Subscribe => &mut allow_subscribe,
                GrpcEdgeActionCfg::Publish => &mut allow_publish,
                GrpcEdgeActionCfg::Push => &mut allow_push,
            };
            if *slot {
                bail!("route `{route_id}` grpc_edge.allowed_actions contains duplicate entries");
            }
            *slot = true;
        }
        if allow_subscribe && (allow_publish || allow_push) {
            bail!(
                "route `{route_id}` grpc_edge cannot mix subscribe with publish/push; public and \
                 internal publish planes require separate routes and authentication profiles"
            );
        }
        let methods = build_methods(
            route_id,
            &cfg.methods,
            allow_subscribe,
            allow_publish,
            allow_push,
        )?;
        match cfg.auth {
            GrpcEdgeAuthCfg::Required if allow_publish || allow_push => bail!(
                "route `{route_id}` grpc_edge publish/push plane requires auth=service; \
                 terminal-user authentication must not authorize backend publishing"
            ),
            GrpcEdgeAuthCfg::Service if allow_subscribe => bail!(
                "route `{route_id}` grpc_edge subscribe plane requires auth=required; \
                 service credentials belong on a separate internal publish route"
            ),
            _ => {}
        }
        let action_header = parse_header(route_id, "action_header", &cfg.action_header)?;
        let group_header = parse_header(route_id, "group_header", &cfg.group_header)?;
        let target_header = parse_header(route_id, "target_header", &cfg.target_header)?;
        if action_header == group_header
            || action_header == target_header
            || group_header == target_header
        {
            bail!("route `{route_id}` grpc_edge header names must be pairwise distinct");
        }
        let identity = build_identity(route_id, &cfg.identity)?;
        let max_msg_bytes = resolve_max_msg_bytes(route_id, cfg)?;
        let limits = build_limits(
            &format!("route `{route_id}` grpc_edge.limits"),
            &cfg.limits,
            max_msg_bytes,
        )?;
        validate_send_queue(route_id, &cfg.send_queue, max_msg_bytes)?;
        let publish_stream = build_publish_stream(route_id, &cfg.publish_stream, max_msg_bytes)?;
        // 桥接只是 subscribe 的另一层传输外壳，发布/推送面不得开桥。
        let ws_bridge_path = match cfg.ws_bridge_path.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(path) => {
                if !allow_subscribe {
                    bail!(
                        "route `{route_id}` grpc_edge.ws_bridge_path requires allowed_actions to \
                         include subscribe; the bridge is a transport shim over the subscribe path"
                    );
                }
                if !path.starts_with('/') || path.len() > MAX_METHOD_PATH_BYTES {
                    bail!(
                        "route `{route_id}` grpc_edge.ws_bridge_path `{path}` must be an absolute \
                         path of at most {MAX_METHOD_PATH_BYTES} bytes"
                    );
                }
                if path
                    .bytes()
                    .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'?' || byte == b'#')
                {
                    bail!(
                        "route `{route_id}` grpc_edge.ws_bridge_path must be visible ASCII without \
                         query or fragment"
                    );
                }
                // 与 edge 方法路径冲突会让同一 :path 同时是 gRPC 方法与 WS 入口。
                for method in [
                    methods.subscribe.as_deref(),
                    methods.publish.as_deref(),
                    methods.publish_stream.as_deref(),
                    methods.push.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    if method == path {
                        bail!(
                            "route `{route_id}` grpc_edge.ws_bridge_path must differ from every \
                             exact edge method path"
                        );
                    }
                }
                Some(Box::from(path))
            }
        };

        // 授权策略在值校验段编译:坏规则要与其它坏配置一样在三种 feature 形态下
        // 给出相同报错(值校验先于 feature 门)。
        let authz = build_authz(
            route_id,
            cfg.authz.as_ref(),
            allow_subscribe,
            allow_publish,
            allow_push,
        )?;

        // —— feature 门(最后一道闸;fail fast 而不是运行期静默不生效)——
        if !cfg!(feature = "grpc-edge") {
            bail!(
                "route `{route_id}` grpc_edge.enabled=true but this binary was built without \
                 the `grpc-edge` feature; rebuild with `--features grpc-edge` or disable the \
                 route's edge mode (default L7 proxying does not need the feature)"
            );
        }

        Ok(Some(Self {
            allow_subscribe,
            allow_publish,
            allow_push,
            methods,
            action_header,
            group_header,
            target_header,
            auth: cfg.auth,
            identity,
            send_queue_max_messages: cfg.send_queue.max_messages,
            send_queue_max_bytes: cfg.send_queue.max_bytes,
            overflow: cfg.send_queue.overflow,
            delivery: cfg.delivery,
            encoding: cfg.encoding,
            limits,
            publish_stream,
            ws_bridge_path,
            authz,
        }))
    }
}

#[derive(Clone)]
pub struct GrpcEdgeRedisPubSubPlan {
    pub url: Box<str>,
    pub namespace: Box<str>,
    pub profile: Box<str>,
    pub channel: Box<str>,
    pub command_timeout: Duration,
    pub reconnect_backoff: Duration,
}

#[derive(Clone)]
pub struct GrpcEdgeRedisStreamPlan {
    pub url: Box<str>,
    pub namespace: Box<str>,
    pub profile: Box<str>,
    pub stream: Box<str>,
    pub cursor_key: Box<str>,
    pub batch_size: usize,
    pub block_ms: u64,
    pub command_timeout: Duration,
    pub reconnect_backoff: Duration,
}

/// 进程级集群传输计划。relay 与 Redis Pub/Sub 在构建期严格二选一。
pub struct GrpcEdgeClusterPlan {
    pub mode: GrpcEdgeClusterModeCfg,
    pub redis_pubsub: Option<GrpcEdgeRedisPubSubPlan>,
    pub redis_stream: Option<GrpcEdgeRedisStreamPlan>,
    /// relay 双向 TLS；非 loopback 集群必须存在。
    pub tls: Option<crate::tls::EdgeRelayTlsProfile>,
    /// 单次 TLS 握手硬超时。
    pub tls_handshake_timeout: Duration,
    /// 集群身份;relay 握手校验,跨 cluster 一律拒绝。
    pub cluster_id: Box<str>,
    /// 本节点身份;握手交换,重复 node_id 拒绝、较小者发起唯一连接。
    pub node_id: Box<str>,
    /// peer 成员来源。
    pub membership: GrpcEdgeMembershipCfg,
    /// `membership: static` 时已解析去重的 peer relay endpoint。
    pub static_peers: Vec<SocketAddr>,
    /// 内部 relay 监听地址；仅接受 peer 身份。
    pub relay_listen: SocketAddr,
    /// peer 鉴别方式，支持 mtls 与 cluster_secret；非 loopback 强制 TLS。
    pub peer_auth: GrpcEdgePeerAuthCfg,
    /// 已解析的共享凭证(peer_auth=cluster_secret 时 Some 且非空)。
    pub cluster_secret: Option<Box<str>>,
    /// 每 peer 中继队列消息数上限。
    pub relay_queue_max_messages: usize,
    /// 每 peer 中继队列逻辑字节上限。
    pub relay_queue_max_bytes: usize,
    /// peer 队满策略(默认 drop_new;close_slow 已在构建期拒绝)。
    pub relay_overflow: GrpcEdgeOverflowCfg,
    /// ingress 聚合 peer enqueue-ack 的 deadline(ms);超时记 unknown、不自动重试。
    pub ack_deadline_ms: u64,
    /// 全网状节点数硬门。
    pub full_mesh_max_nodes: usize,
    /// 兴趣路由策略；`auto` 使用已确认的远端兴趣快照过滤无关 group payload。
    pub interest_route: GrpcEdgeInterestRouteCfg,
    /// 顺序承诺；`group_owner` 通过确定性 owner 生效。
    pub ordering: GrpcEdgeOrderingCfg,
    /// 用户会话语义。
    pub session_mode: GrpcEdgeSessionModeCfg,
    /// 指路条后端(none=broadcast-probe)。
    pub session_registry: GrpcEdgeSessionRegistryCfg,
    /// 目录参数（仅 `session_registry=redis` 时 Some）。
    pub session_directory: Option<crate::config::model::GrpcEdgeSessionDirectoryCfg>,
    /// relay 收包散出的节点级预算。relay 侧没有 route 计划可依,预算必须由
    /// 集群块显式给出;`max_msg_bytes` 恒为协议硬上限,不随配置放宽。
    pub fanout_limits: GrpcEdgeLimitsPlan,
}

impl GrpcEdgeClusterPlan {
    /// 业务作用：判断两个计划是否能由同一常驻 relay 运行态继续服务。
    ///
    /// 当前 尚未把 relay socket 纳入 listener 两阶段重绑，因此任何会改变连接、认证、
    /// 排队或路由语义的字段都必须视为拓扑变化并拒绝热更；证书文件内容轮换由独立 watcher 处理。
    pub fn same_runtime_topology(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.cluster_id == other.cluster_id
            && self.node_id == other.node_id
            && match (&self.redis_pubsub, &other.redis_pubsub) {
                (None, None) => true,
                (Some(current), Some(candidate)) => {
                    current.url == candidate.url
                        && current.namespace == candidate.namespace
                        && current.profile == candidate.profile
                        && current.channel == candidate.channel
                        && current.command_timeout == candidate.command_timeout
                        && current.reconnect_backoff == candidate.reconnect_backoff
                }
                _ => false,
            }
            && match (&self.redis_stream, &other.redis_stream) {
                (None, None) => true,
                (Some(current), Some(candidate)) => {
                    current.url == candidate.url
                        && current.namespace == candidate.namespace
                        && current.profile == candidate.profile
                        && current.stream == candidate.stream
                        && current.cursor_key == candidate.cursor_key
                        && current.batch_size == candidate.batch_size
                        && current.block_ms == candidate.block_ms
                        && current.command_timeout == candidate.command_timeout
                        && current.reconnect_backoff == candidate.reconnect_backoff
                }
                _ => false,
            }
            && self.membership == other.membership
            && self.static_peers == other.static_peers
            && self.relay_listen == other.relay_listen
            && self.peer_auth == other.peer_auth
            && self.cluster_secret == other.cluster_secret
            && match (&self.tls, &other.tls) {
                (None, None) => true,
                (Some(current), Some(candidate)) => current.same_material_source(candidate),
                _ => false,
            }
            && self.tls_handshake_timeout == other.tls_handshake_timeout
            && self.relay_queue_max_messages == other.relay_queue_max_messages
            && self.relay_queue_max_bytes == other.relay_queue_max_bytes
            && self.relay_overflow == other.relay_overflow
            && self.ack_deadline_ms == other.ack_deadline_ms
            && self.full_mesh_max_nodes == other.full_mesh_max_nodes
            && self.interest_route == other.interest_route
            && self.ordering == other.ordering
            && self.session_mode == other.session_mode
            && self.session_registry == other.session_registry
            && match (&self.session_directory, &other.session_directory) {
                (None, None) => true,
                // 目录连接与租约参数属于常驻运行态,变更需重启(与 relay socket 同口径)。
                (Some(current), Some(candidate)) => {
                    current.url == candidate.url
                        && current.namespace == candidate.namespace
                        && current.profile == candidate.profile
                        && current.prefix == candidate.prefix
                        && current.ttl_ms == candidate.ttl_ms
                        && current.command_timeout_ms == candidate.command_timeout_ms
                }
                _ => false,
            }
            // relay 面预算同属常驻运行态:EdgeRelay 持有的是启动时那份 Arc<Plan>,
            // 热更不会把新预算换进去。若这里判"可继续服务",改了预算的 reload 会
            // **成功却静默不生效**——运维以为放宽了、实际仍按旧值拒。宁可拒绝热更。
            && self.fanout_limits.same_budget(&other.fanout_limits)
    }

    /// 业务作用：从顶层配置编译集群中继计划。
    ///
    /// 参数说明：
    /// - `cfg`: `grpc_edge_cluster` 段;None 或 `mode: none` 返回 `Ok(None)`(单机)。
    /// - `nacos_enabled`: `discovery.nacos.enabled`,校验 `membership: nacos` 的前提。
    /// - `config_dir`：证书与 SecretSource 相对路径的解析根。
    pub fn build(
        cfg: Option<&GrpcEdgeClusterCfg>,
        nacos_enabled: bool,
        config_dir: &std::path::Path,
    ) -> Result<Option<Self>> {
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        if cfg.mode == GrpcEdgeClusterModeCfg::None {
            // 显式单机:忽略其余字段(与整段缺省等价),不做值校验。
            return Ok(None);
        }

        // —— 值校验(先于 feature 门,理由同 GrpcEdgePlan::build)——
        let cluster_id = parse_identity_token(
            "grpc_edge_cluster.cluster_id",
            &cfg.cluster_id,
            MAX_CLUSTER_ID_BYTES,
        )?;
        let node_id =
            parse_identity_token("grpc_edge_cluster.node_id", &cfg.node_id, MAX_NODE_ID_BYTES)?;
        if cfg.mode == GrpcEdgeClusterModeCfg::RedisPubsub {
            if !cfg.relay_listen.trim().is_empty()
                || !cfg.static_peers.is_empty()
                || cfg.tls.enabled
                || !cfg.cluster_secret.trim().is_empty()
                || cfg.session_registry != GrpcEdgeSessionRegistryCfg::None
                || !cfg.redis_stream.url.trim().is_empty()
            {
                bail!(
                    "grpc_edge_cluster.mode=redis_pubsub is mutually exclusive with relay_listen, \
                     static_peers, tls, cluster_secret and session_registry; remove relay-only \
                     settings so one message cannot traverse two cluster transports"
                );
            }
            let redis = &cfg.redis_pubsub;
            if redis.url.trim().is_empty() {
                bail!("grpc_edge_cluster.mode=redis_pubsub requires redis_pubsub.url");
            }
            if redis.namespace.trim().is_empty() {
                bail!("grpc_edge_cluster.redis_pubsub.namespace must not be empty");
            }
            if !matches!(
                redis.profile.trim(),
                "RustV2" | "rustv2" | "rust-v2" | "LegacyV1" | "legacyv1" | "legacy-v1"
            ) {
                bail!(
                    "grpc_edge_cluster.redis_pubsub.profile `{}` is not a supported nadis \
                     compatibility profile (RustV2|LegacyV1)",
                    redis.profile
                );
            }
            if redis.command_timeout_ms == 0 || redis.command_timeout_ms > 5_000 {
                bail!("grpc_edge_cluster.redis_pubsub.command_timeout_ms must be within 1..=5000");
            }
            if !(100..=60_000).contains(&redis.reconnect_backoff_ms) {
                bail!(
                    "grpc_edge_cluster.redis_pubsub.reconnect_backoff_ms must be within 100..=60000"
                );
            }
            let channel = if redis.channel.trim().is_empty() {
                format!("naway:edge:{cluster_id}")
            } else {
                redis.channel.trim().to_string()
            };
            if channel.len() > 256 || !channel.bytes().all(|byte| byte.is_ascii_graphic()) {
                bail!("grpc_edge_cluster.redis_pubsub.channel must be 1..=256 visible ASCII bytes");
            }
            let fanout_limits = build_limits(
                "grpc_edge_cluster.fanout_limits",
                &cfg.fanout_limits,
                RELAY_FANOUT_MAX_MSG_BYTES,
            )?;
            if !cfg!(feature = "grpc-edge") || !cfg!(feature = "redis-runtime") {
                bail!(
                    "grpc_edge_cluster.mode=redis_pubsub requires both `grpc-edge` and \
                     `redis-runtime` features"
                );
            }
            return Ok(Some(Self {
                mode: GrpcEdgeClusterModeCfg::RedisPubsub,
                redis_pubsub: Some(GrpcEdgeRedisPubSubPlan {
                    url: redis.url.trim().to_string().into_boxed_str(),
                    namespace: redis.namespace.trim().to_string().into_boxed_str(),
                    profile: redis.profile.trim().to_string().into_boxed_str(),
                    channel: channel.into_boxed_str(),
                    command_timeout: Duration::from_millis(redis.command_timeout_ms),
                    reconnect_backoff: Duration::from_millis(redis.reconnect_backoff_ms),
                }),
                redis_stream: None,
                tls: None,
                tls_handshake_timeout: Duration::from_millis(cfg.tls.handshake_timeout_ms),
                cluster_id,
                node_id,
                membership: cfg.membership,
                static_peers: Vec::new(),
                relay_listen: "127.0.0.1:0".parse().expect("literal socket address"),
                peer_auth: cfg.peer_auth,
                cluster_secret: None,
                relay_queue_max_messages: cfg.relay_queue.max_messages,
                relay_queue_max_bytes: cfg.relay_queue.max_bytes,
                relay_overflow: cfg.relay_queue.overflow,
                ack_deadline_ms: cfg.ack_deadline_ms,
                full_mesh_max_nodes: cfg.full_mesh_max_nodes,
                interest_route: cfg.interest_route,
                ordering: cfg.ordering,
                session_mode: cfg.session_mode,
                session_registry: GrpcEdgeSessionRegistryCfg::None,
                session_directory: None,
                fanout_limits,
            }));
        }
        if cfg.mode == GrpcEdgeClusterModeCfg::RedisStream {
            if !cfg.relay_listen.trim().is_empty()
                || !cfg.static_peers.is_empty()
                || cfg.tls.enabled
                || !cfg.cluster_secret.trim().is_empty()
                || cfg.session_registry != GrpcEdgeSessionRegistryCfg::None
                || !cfg.redis_pubsub.url.trim().is_empty()
            {
                bail!(
                    "grpc_edge_cluster.mode=redis_stream is mutually exclusive with relay_listen, \
                     static_peers, tls, cluster_secret, session_registry and redis_pubsub"
                );
            }
            let redis = &cfg.redis_stream;
            if redis.url.trim().is_empty() {
                bail!("grpc_edge_cluster.mode=redis_stream requires redis_stream.url");
            }
            if redis.namespace.trim().is_empty() || redis.cursor_prefix.trim().is_empty() {
                bail!(
                    "grpc_edge_cluster.redis_stream.namespace and .cursor_prefix must not be empty"
                );
            }
            if !matches!(
                redis.profile.trim(),
                "RustV2" | "rustv2" | "rust-v2" | "LegacyV1" | "legacyv1" | "legacy-v1"
            ) {
                bail!(
                    "grpc_edge_cluster.redis_stream.profile `{}` is not a supported nadis \
                     compatibility profile (RustV2|LegacyV1)",
                    redis.profile
                );
            }
            if redis.batch_size == 0 || redis.batch_size > 10_000 {
                bail!("grpc_edge_cluster.redis_stream.batch_size must be within 1..=10000");
            }
            if redis.block_ms == 0 || redis.block_ms > 60_000 {
                bail!("grpc_edge_cluster.redis_stream.block_ms must be within 1..=60000");
            }
            if redis.command_timeout_ms == 0 || redis.command_timeout_ms > 5_000 {
                bail!("grpc_edge_cluster.redis_stream.command_timeout_ms must be within 1..=5000");
            }
            if !(100..=60_000).contains(&redis.reconnect_backoff_ms) {
                bail!(
                    "grpc_edge_cluster.redis_stream.reconnect_backoff_ms must be within 100..=60000"
                );
            }
            let stream = if redis.stream.trim().is_empty() {
                format!("naway:edge:{cluster_id}")
            } else {
                redis.stream.trim().to_string()
            };
            let cursor_key = format!("{}:{}:{}", redis.cursor_prefix.trim(), cluster_id, node_id);
            for (name, value) in [
                ("stream", stream.as_str()),
                ("cursor_key", cursor_key.as_str()),
            ] {
                if value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
                    bail!(
                        "grpc_edge_cluster.redis_stream.{name} must resolve to 1..=256 visible \
                         ASCII bytes"
                    );
                }
            }
            let fanout_limits = build_limits(
                "grpc_edge_cluster.fanout_limits",
                &cfg.fanout_limits,
                RELAY_FANOUT_MAX_MSG_BYTES,
            )?;
            if !cfg!(feature = "grpc-edge") || !cfg!(feature = "redis-runtime") {
                bail!(
                    "grpc_edge_cluster.mode=redis_stream requires both `grpc-edge` and \
                     `redis-runtime` features"
                );
            }
            return Ok(Some(Self {
                mode: GrpcEdgeClusterModeCfg::RedisStream,
                redis_pubsub: None,
                redis_stream: Some(GrpcEdgeRedisStreamPlan {
                    url: redis.url.trim().to_string().into_boxed_str(),
                    namespace: redis.namespace.trim().to_string().into_boxed_str(),
                    profile: redis.profile.trim().to_string().into_boxed_str(),
                    stream: stream.into_boxed_str(),
                    cursor_key: cursor_key.into_boxed_str(),
                    batch_size: redis.batch_size,
                    block_ms: redis.block_ms,
                    command_timeout: Duration::from_millis(redis.command_timeout_ms),
                    reconnect_backoff: Duration::from_millis(redis.reconnect_backoff_ms),
                }),
                tls: None,
                tls_handshake_timeout: Duration::from_millis(cfg.tls.handshake_timeout_ms),
                cluster_id,
                node_id,
                membership: cfg.membership,
                static_peers: Vec::new(),
                relay_listen: "127.0.0.1:0".parse().expect("literal socket address"),
                peer_auth: cfg.peer_auth,
                cluster_secret: None,
                relay_queue_max_messages: cfg.relay_queue.max_messages,
                relay_queue_max_bytes: cfg.relay_queue.max_bytes,
                relay_overflow: cfg.relay_queue.overflow,
                ack_deadline_ms: cfg.ack_deadline_ms,
                full_mesh_max_nodes: cfg.full_mesh_max_nodes,
                interest_route: cfg.interest_route,
                ordering: cfg.ordering,
                session_mode: cfg.session_mode,
                session_registry: GrpcEdgeSessionRegistryCfg::None,
                session_directory: None,
                fanout_limits,
            }));
        }
        if !cfg.redis_pubsub.url.trim().is_empty() || !cfg.redis_stream.url.trim().is_empty() {
            bail!(
                "grpc_edge_cluster.mode=relay cannot include redis_pubsub.url or redis_stream.url; \
                 select exactly one cluster transport"
            );
        }
        if cfg.full_mesh_max_nodes == 0 || cfg.full_mesh_max_nodes > MAX_FULL_MESH_NODES_CAP {
            bail!(
                "grpc_edge_cluster.full_mesh_max_nodes must be within 1..={MAX_FULL_MESH_NODES_CAP} \
                 (the recommended full-mesh limit is <=32)"
            );
        }
        let static_peers = match cfg.membership {
            GrpcEdgeMembershipCfg::Nacos => {
                if !nacos_enabled {
                    bail!(
                        "grpc_edge_cluster.membership=nacos requires discovery.nacos.enabled=true; \
                         edge relay reuses the self-registration watch for peer membership"
                    );
                }
                if !cfg.static_peers.is_empty() {
                    bail!(
                        "grpc_edge_cluster.static_peers must be empty when membership=nacos; \
                         mixing both sources would make the effective peer set ambiguous"
                    );
                }
                Vec::new()
            }
            GrpcEdgeMembershipCfg::Static => {
                if cfg.static_peers.is_empty() {
                    bail!("grpc_edge_cluster.membership=static requires a non-empty static_peers list");
                }
                if cfg.static_peers.len().saturating_add(1) > cfg.full_mesh_max_nodes {
                    bail!(
                        "grpc_edge_cluster.static_peers has {} peers plus this node, exceeding \
                         full_mesh_max_nodes={}; full-mesh relay is a small-cluster baseline — \
                         larger clusters require implemented interest/group-owner routing instead \
                         of O(N^2) blind broadcast",
                        cfg.static_peers.len(),
                        cfg.full_mesh_max_nodes
                    );
                }
                let mut seen = HashSet::with_capacity(cfg.static_peers.len());
                let mut peers = Vec::with_capacity(cfg.static_peers.len());
                for raw in &cfg.static_peers {
                    let addr: SocketAddr = raw.parse().map_err(|_| {
                        anyhow::anyhow!(
                            "grpc_edge_cluster.static_peers contains invalid address `{raw}` \
                             (expected host:port socket address)"
                        )
                    })?;
                    if !seen.insert(addr) {
                        bail!("grpc_edge_cluster.static_peers contains duplicate address `{raw}`");
                    }
                    peers.push(addr);
                }
                peers
            }
        };
        let relay_listen = cfg.relay_listen.trim();
        if relay_listen.is_empty() {
            bail!("grpc_edge_cluster.relay_listen is required when mode=relay");
        }
        let relay_listen: SocketAddr = relay_listen.parse().map_err(|_| {
            anyhow::anyhow!(
                "grpc_edge_cluster.relay_listen `{}` is not a valid host:port socket address",
                cfg.relay_listen
            )
        })?;
        if static_peers.contains(&relay_listen) {
            bail!(
                "grpc_edge_cluster.static_peers must not contain this node's relay_listen \
                 `{relay_listen}`; self-dial can never pass the distinct node_id handshake"
            );
        }
        validate_relay_queue(&cfg.relay_queue)?;
        if cfg.ack_deadline_ms == 0 || cfg.ack_deadline_ms > MAX_ACK_DEADLINE_MS {
            bail!(
                "grpc_edge_cluster.ack_deadline_ms must be within 1..={MAX_ACK_DEADLINE_MS}; \
                 the ingress aggregates peer enqueue-acks within this fixed deadline"
            );
        }
        // broadcast_all 明确接受 O(nodes × message_bytes) 基线，因此超过建议规模时拒绝；
        // auto 根据 peer 的 interest revision/hint 收敛目标；缺少可信兴趣证据时保留保守探测。
        if cfg.interest_route == GrpcEdgeInterestRouteCfg::BroadcastAll
            && cfg.full_mesh_max_nodes > RECOMMENDED_FULL_MESH_NODES
        {
            bail!(
                "grpc_edge_cluster.interest_route=broadcast_all cannot exceed the \
                 {RECOMMENDED_FULL_MESH_NODES}-node payload-broadcast baseline; use \
                 interest_route=auto or reduce full_mesh_max_nodes (got {})",
                cfg.full_mesh_max_nodes
            );
        }
        // relay 模式在 mesh 不完整时 fail-closed；Redis 模式则以 channel/stream 顺序、
        // Redis TIME membership 与 fencing ACK 实现同等级保护，不能退化成 local-first。
        // 目录是可选加速面；值校验必须先于 feature 门，避免坏配置因制品差异被掩盖。
        let session_directory = match cfg.session_registry {
            GrpcEdgeSessionRegistryCfg::None => None,
            GrpcEdgeSessionRegistryCfg::Redis => {
                let directory = &cfg.session_directory;
                if directory.url.trim().is_empty() {
                    bail!(
                        "grpc_edge_cluster.session_registry=redis requires \
                         session_directory.url"
                    );
                }
                if !matches!(
                    directory.profile.trim(),
                    "RustV2" | "rustv2" | "rust-v2" | "LegacyV1" | "legacyv1" | "legacy-v1"
                ) {
                    bail!(
                        "grpc_edge_cluster.session_directory.profile `{}` is not a supported \
                         nadis compatibility profile (RustV2|LegacyV1)",
                        directory.profile
                    );
                }
                if directory.namespace.trim().is_empty() || directory.prefix.trim().is_empty() {
                    bail!(
                        "grpc_edge_cluster.session_directory.namespace and .prefix must not be \
                         empty; directory keys are cluster/tenant scoped"
                    );
                }
                if !(MIN_DIRECTORY_TTL_MS..=MAX_DIRECTORY_TTL_MS).contains(&directory.ttl_ms) {
                    bail!(
                        "grpc_edge_cluster.session_directory.ttl_ms must be within \
                         {MIN_DIRECTORY_TTL_MS}..={MAX_DIRECTORY_TTL_MS}; the lease is refreshed \
                         at one third of the TTL and only backstops crashed nodes"
                    );
                }
                if directory.command_timeout_ms == 0
                    || directory.command_timeout_ms > MAX_DIRECTORY_COMMAND_TIMEOUT_MS
                {
                    bail!(
                        "grpc_edge_cluster.session_directory.command_timeout_ms must be within \
                         1..={MAX_DIRECTORY_COMMAND_TIMEOUT_MS}; a slow directory must never \
                         stall the push path"
                    );
                }
                if !cfg!(feature = "redis-runtime") {
                    bail!(
                        "grpc_edge_cluster.session_registry=redis requires the `redis-runtime` \
                         feature; the default broadcast-probe path needs no external dependency"
                    );
                }
                Some(directory.clone())
            }
        };
        let tls = build_relay_tls(&cfg.tls, config_dir)?;
        if tls.is_none()
            && (!relay_listen.ip().is_loopback()
                || static_peers.iter().any(|peer| !peer.ip().is_loopback()))
        {
            bail!(
                "grpc_edge_cluster.tls.enabled=true is required for every non-loopback relay; \
                 plaintext relay is restricted to 127.0.0.0/8 and ::1 development clusters"
            );
        }
        // mTLS 已在 TLS 握手层完成双向身份校验；cluster_secret 保留为兼容/纵深防御模式。
        let cluster_secret = match cfg.peer_auth {
            GrpcEdgePeerAuthCfg::Mtls => {
                if tls.is_none() {
                    bail!(
                        "grpc_edge_cluster.peer_auth=mtls requires \
                         grpc_edge_cluster.tls.enabled=true"
                    );
                }
                if !cfg.cluster_secret.trim().is_empty() {
                    bail!("grpc_edge_cluster.cluster_secret must be empty when peer_auth=mtls");
                }
                None
            }
            GrpcEdgePeerAuthCfg::ClusterSecret => {
                if cfg.cluster_secret.trim().is_empty() {
                    bail!(
                        "grpc_edge_cluster.peer_auth=cluster_secret requires a non-empty \
                         cluster_secret SecretSource (literal://, env://, file://, ...)"
                    );
                }
                let secret = crate::security::secret::resolve_text(
                    &cfg.cluster_secret,
                    config_dir,
                    "grpc_edge_cluster.cluster_secret",
                )?;
                if secret.is_empty() {
                    bail!("grpc_edge_cluster.cluster_secret resolved to an empty value");
                }
                HeaderValue::try_from(secret.as_str()).map_err(|_| {
                    anyhow::anyhow!(
                        "grpc_edge_cluster.cluster_secret must resolve to a valid HTTP header \
                         value because cluster_secret authentication is carried in `{}`",
                        "x-naway-relay-secret"
                    )
                })?;
                Some(secret.into_boxed_str())
            }
        };

        // relay 面预算与 route 面走同一套范围校验和交叉约束,错误路径指向集群块。
        // 单条 message 上限固定为协议硬上限:record 尺寸在解码层已被钉死,
        // 允许配置放宽只会让「配置说能过、解码器仍拒」这种自相矛盾的状态存在。
        // 放在值校验段末尾:既保持「值校验先于 feature 门」(三形态报错一致),
        // 又不抢身份/拓扑这些更根本字段的报错优先级。
        let fanout_limits = build_limits(
            "grpc_edge_cluster.fanout_limits",
            &cfg.fanout_limits,
            RELAY_FANOUT_MAX_MSG_BYTES,
        )?;

        // —— feature 门 ——
        if !cfg!(feature = "grpc-edge") {
            bail!(
                "grpc_edge_cluster.mode=relay but this binary was built without the `grpc-edge` \
                 feature; rebuild with `--features grpc-edge` or set mode=none"
            );
        }

        Ok(Some(Self {
            mode: GrpcEdgeClusterModeCfg::Relay,
            redis_pubsub: None,
            redis_stream: None,
            tls,
            tls_handshake_timeout: Duration::from_millis(cfg.tls.handshake_timeout_ms),
            cluster_id,
            node_id,
            membership: cfg.membership,
            static_peers,
            relay_listen,
            peer_auth: cfg.peer_auth,
            cluster_secret,
            relay_queue_max_messages: cfg.relay_queue.max_messages,
            relay_queue_max_bytes: cfg.relay_queue.max_bytes,
            relay_overflow: cfg.relay_queue.overflow,
            ack_deadline_ms: cfg.ack_deadline_ms,
            full_mesh_max_nodes: cfg.full_mesh_max_nodes,
            interest_route: cfg.interest_route,
            ordering: cfg.ordering,
            session_mode: cfg.session_mode,
            session_registry: cfg.session_registry,
            session_directory,
            fanout_limits,
        }))
    }
}

/// 业务作用：解析 `max_msg_bytes` 的新旧双位置:权威在 `limits.max_msg_bytes`,顶层旧字段是
/// 兼容别名。两处同时设置且不相等 = 配置自相矛盾,必须报错而不是静默取其一。
fn resolve_max_msg_bytes(route_id: &str, cfg: &GrpcEdgeCfg) -> Result<usize> {
    let effective = match (cfg.limits.max_msg_bytes, cfg.max_msg_bytes) {
        (Some(canonical), Some(legacy)) if canonical != legacy => {
            bail!(
                "route `{route_id}` sets grpc_edge.max_msg_bytes={legacy} and \
                 grpc_edge.limits.max_msg_bytes={canonical}; the top-level field is a \
                 deprecated alias — keep only limits.max_msg_bytes"
            );
        }
        (Some(canonical), _) => canonical,
        (None, Some(legacy)) => legacy,
        (None, None) => 65_536,
    };
    if effective == 0 || effective > MAX_MSG_BYTES {
        bail!(
            "route `{route_id}` grpc_edge.limits.max_msg_bytes must be within 1..={MAX_MSG_BYTES}; \
             the edge plane replicates every message N ways and must stay small"
        );
    }
    Ok(effective)
}

/// 业务作用：编译 methods 块:allowed action 与精确路径必须一一对应。
///
/// - 允许的 action 缺方法 → 拒绝(没有精确 `:path` 就无法四重门匹配);
/// - 未允许的 action 声明了方法 → 拒绝(端点存在但永远 403 只会掩盖配置错误);
/// - 所有已声明路径必须两两不同。
fn build_methods(
    route_id: &str,
    cfg: &GrpcEdgeMethodsCfg,
    allow_subscribe: bool,
    allow_publish: bool,
    allow_push: bool,
) -> Result<GrpcEdgeMethodPlan> {
    let parse = |field: &str, value: &Option<String>, required: bool| -> Result<Option<Box<str>>> {
        match value {
            Some(path) => Ok(Some(parse_method_path(route_id, field, path)?)),
            None if required => bail!(
                "route `{route_id}` grpc_edge.methods.{field} is required because the matching \
                 action is in allowed_actions; edge must match an exact gRPC :path, not just a \
                 forgeable header"
            ),
            None => Ok(None),
        }
    };
    let forbid = |field: &str, value: &Option<String>, allowed: bool| -> Result<()> {
        if value.is_some() && !allowed {
            bail!(
                "route `{route_id}` grpc_edge.methods.{field} is declared but its action is not \
                 in allowed_actions; remove the method or allow the action"
            );
        }
        Ok(())
    };
    forbid("subscribe", &cfg.subscribe, allow_subscribe)?;
    forbid("publish", &cfg.publish, allow_publish)?;
    forbid("publish_stream", &cfg.publish_stream, allow_publish)?;
    forbid("push", &cfg.push, allow_push)?;
    let subscribe = parse("subscribe", &cfg.subscribe, allow_subscribe)?;
    let publish = parse("publish", &cfg.publish, allow_publish)?;
    // publish_stream 归属 publish action,但它本身可选:只有声明了才编译。
    let publish_stream = parse("publish_stream", &cfg.publish_stream, false)?;
    let push = parse("push", &cfg.push, allow_push)?;
    let mut seen: HashSet<&str> = HashSet::with_capacity(4);
    for path in [&subscribe, &publish, &publish_stream, &push]
        .into_iter()
        .flatten()
    {
        if !seen.insert(path.as_ref()) {
            bail!("route `{route_id}` grpc_edge.methods paths must be pairwise distinct");
        }
    }
    Ok(GrpcEdgeMethodPlan {
        subscribe,
        publish,
        publish_stream,
        push,
    })
}

/// 业务作用：校验并定型一个精确 gRPC 方法路径:`/package.Service/Method` 两段、可见 ASCII、
/// 长度有界。宽泛前缀/通配不可表达——精确匹配本身就是四重门的第一道。
fn parse_method_path(route_id: &str, field: &str, raw: &str) -> Result<Box<str>> {
    if raw.is_empty() || raw.len() > MAX_METHOD_PATH_BYTES {
        bail!(
            "route `{route_id}` grpc_edge.methods.{field} must be 1..={MAX_METHOD_PATH_BYTES} bytes"
        );
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        bail!(
            "route `{route_id}` grpc_edge.methods.{field} `{raw}` must be visible ASCII without \
             spaces"
        );
    }
    let mut segments = raw.split('/');
    let leading = segments.next();
    let service = segments.next();
    let method = segments.next();
    let extra = segments.next();
    if leading != Some("")
        || service.is_none_or(|s| s.is_empty())
        || method.is_none_or(|s| s.is_empty())
        || extra.is_some()
    {
        bail!(
            "route `{route_id}` grpc_edge.methods.{field} `{raw}` must be an exact \
             `/package.Service/Method` path (two non-empty segments, no trailing slash)"
        );
    }
    Ok(Box::from(raw))
}

/// 业务作用：编译身份映射:claim 名必须可用作元数据键——非空、有界、可见 ASCII、
/// 不得是 `-bin` 后缀(二进制元数据不能承载身份)。
fn build_identity(route_id: &str, cfg: &GrpcEdgeIdentityCfg) -> Result<GrpcEdgeIdentityPlan> {
    let user_claim = parse_claim(route_id, "identity.user_claim", &cfg.user_claim)?;
    let tenant_claim = cfg
        .tenant_claim
        .as_deref()
        .map(|claim| parse_claim(route_id, "identity.tenant_claim", claim))
        .transpose()?;
    if tenant_claim
        .as_deref()
        .is_some_and(|tenant| tenant == user_claim.as_ref())
    {
        bail!(
            "route `{route_id}` grpc_edge.identity tenant_claim and user_claim must differ; \
             one claim cannot be both the tenant and the user identity"
        );
    }
    Ok(GrpcEdgeIdentityPlan {
        tenant_claim,
        user_claim,
    })
}

/// 业务作用：校验用于派生边缘身份的 claim 名，拒绝空值、超长和不适合作为文本身份的声明。
fn parse_claim(route_id: &str, field: &str, raw: &str) -> Result<Box<str>> {
    if raw.is_empty() || raw.len() > MAX_CLAIM_BYTES {
        bail!("route `{route_id}` grpc_edge.{field} must be 1..={MAX_CLAIM_BYTES} bytes");
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        bail!("route `{route_id}` grpc_edge.{field} `{raw}` must be visible ASCII");
    }
    if raw.ends_with("-bin") {
        bail!(
            "route `{route_id}` grpc_edge.{field} `{raw}` must not be a `-bin` metadata key; \
             binary metadata cannot carry identity"
        );
    }
    Ok(Box::from(raw))
}

/// 编译一条授权模式。
///
/// 业务作用:把配置里的模式串在**构建期**拆成零分配匹配所需的片段,坏模式在此
/// fail-fast——鉴权规则写错必须让网关起不来,而不是运行期静默放行或静默全拒。
///
/// 参数说明:
/// - `path`: 出错时指向的配置路径(如 `grpc_edge.authz.subscribe_groups[0]`)。
/// - `raw`: 原始模式串。
///
/// 返回:合法模式返回已编译片段;空串、未知 `${...}` 变量、`*` 不在末尾、
/// 或超长一律返回 Err。
fn build_authz_pattern(path: &str, raw: &str) -> Result<AuthzPattern> {
    if raw.is_empty() {
        bail!("{path} must not be empty");
    }
    if raw.len() > MAX_AUTHZ_PATTERN_BYTES {
        bail!("{path} must not exceed {MAX_AUTHZ_PATTERN_BYTES} bytes");
    }
    let mut segments = Vec::new();
    let mut rest = raw;
    let mut literal = String::new();
    while !rest.is_empty() {
        // `${` 一律拒绝:它会在配置加载阶段被环境变量展开,授权规则因此可能在不同
        // 机器上放行不同范围。宁可让网关起不来,也不能留这种静默的环境依赖。
        if rest.starts_with("${") {
            bail!(
                "{path} must not use `${{...}}`: gateway.yml resolves `${{NAME}}` from the environment \
                 before this policy is compiled, so the rule would silently differ per host. \
                 Use `%{{user}}` / `%{{tenant}}` instead"
            );
        }
        if let Some(tail) = rest.strip_prefix("%{") {
            let Some(end) = tail.find('}') else {
                bail!("{path} has an unterminated `%{{` variable");
            };
            if !literal.is_empty() {
                segments.push(AuthzSegment::Literal(std::mem::take(&mut literal).into()));
            }
            segments.push(match &tail[..end] {
                "user" => AuthzSegment::User,
                "tenant" => AuthzSegment::Tenant,
                other => bail!(
                    "{path} uses unsupported variable `%{{{other}}}`; only `%{{user}}` and `%{{tenant}}` are available \
                     (both come from the verified principal, never from client headers)"
                ),
            });
            rest = &tail[end + 1..];
            continue;
        }
        if let Some(tail) = rest.strip_prefix('*') {
            // `*` 只能收尾:允许出现在中间就等于引入回溯匹配,既有代价也难审查。
            if !tail.is_empty() {
                bail!("{path} may only use `*` as the final character");
            }
            if !literal.is_empty() {
                segments.push(AuthzSegment::Literal(std::mem::take(&mut literal).into()));
            }
            segments.push(AuthzSegment::RestWildcard);
            rest = tail;
            continue;
        }
        let mut chars = rest.chars();
        let ch = chars.next().expect("non-empty rest");
        literal.push(ch);
        rest = chars.as_str();
    }
    if !literal.is_empty() {
        segments.push(AuthzSegment::Literal(literal.into()));
    }
    Ok(AuthzPattern {
        segments,
    })
}

/// 编译 route 级授权策略。
///
/// 业务作用：把 group 与 target 的授权边界定型为构建期产物。enabled route
/// 缺少本段直接拒绝；存在时逐条编译并执行 deny-by-default。
///
/// 参数说明:
/// - `route_id`: 报错定位用。
/// - `cfg`: 原始策略段；None 是不安全的缺失配置。
/// - `allow_subscribe`：本 route 是否开放订阅；未开放时不得声明订阅规则。
/// - `allow_publish`：本 route 是否开放群播；未开放时不得声明群播规则。
/// - `allow_push`：本 route 是否开放定向推送；未开放时不得声明推送规则。
///
/// 返回:声明且全部合法返回 Ok(Some(plan));缺失或任一模式非法返回 Err。
fn build_authz(
    route_id: &str,
    cfg: Option<&crate::config::model::GrpcEdgeAuthzCfg>,
    allow_subscribe: bool,
    allow_publish: bool,
    allow_push: bool,
) -> Result<Option<GrpcEdgeAuthzPlan>> {
    let Some(cfg) = cfg else {
        bail!(
            "route `{route_id}` grpc_edge.enabled=true requires an explicit grpc_edge.authz +             block (deny-by-default); use per-action patterns, or write `*` explicitly for an +             intentionally public action"
        );
    };
    let compile = |field: &str, raw: &[String]| -> Result<Vec<AuthzPattern>> {
        raw.iter()
            .enumerate()
            .map(|(index, pattern)| {
                build_authz_pattern(
                    &format!("route `{route_id}` grpc_edge.authz.{field}[{index}]"),
                    pattern,
                )
            })
            .collect()
    };
    // 给未开放的 action 写规则一定是配置写错了(要么 action 漏配、要么规则写错地方)。
    // 静默忽略会让人以为策略生效了,必须报错。
    let cross_check = |field: &str, raw: &[String], allowed: bool| -> Result<()> {
        if !raw.is_empty() && !allowed {
            bail!(
                "route `{route_id}` grpc_edge.authz.{field} is set but this route does not allow \
                 that action; add it to allowed_actions or remove the rules"
            );
        }
        Ok(())
    };
    cross_check("subscribe_groups", &cfg.subscribe_groups, allow_subscribe)?;
    cross_check("publish_groups", &cfg.publish_groups, allow_publish)?;
    cross_check("push_targets", &cfg.push_targets, allow_push)?;
    Ok(Some(GrpcEdgeAuthzPlan {
        subscribe_groups: compile("subscribe_groups", &cfg.subscribe_groups)?,
        publish_groups: compile("publish_groups", &cfg.publish_groups)?,
        push_targets: compile("push_targets", &cfg.push_targets)?,
    }))
}

/// 业务作用：编译节点级预算:逐项范围校验 + 与消息上限的交叉约束。
///
/// 参数说明：
/// - `path`: 该段预算在配置里的完整路径前缀(如 ``route `api` grpc_edge.limits`` 或
///   `grpc_edge_cluster.fanout_limits`)。构建期报错必须能直接定位到写错的那一段——
///   relay 面预算与 route 面预算共用本函数,写死 route 前缀会把集群块的错误指错地方。
/// - `cfg`: 待校验的原始预算配置。
/// - `max_msg_bytes`: 该面已定的单条 message 上限,用于「payload 预算至少容得下一条
///   最大帧」的交叉约束。
fn build_limits(
    path: &str,
    cfg: &GrpcEdgeLimitsCfg,
    max_msg_bytes: usize,
) -> Result<GrpcEdgeLimitsPlan> {
    let range = |field: &str, value: usize, cap: usize| -> Result<()> {
        if value == 0 || value > cap {
            bail!("{path}.{field} must be within 1..={cap}");
        }
        Ok(())
    };
    range("max_id_bytes", cfg.max_id_bytes, MAX_ID_BYTES_CAP)?;
    range(
        "max_streams_per_node",
        cfg.max_streams_per_node,
        MAX_CARDINALITY_CAP,
    )?;
    range(
        "max_groups_per_node",
        cfg.max_groups_per_node,
        MAX_CARDINALITY_CAP,
    )?;
    range(
        "max_members_per_group",
        cfg.max_members_per_group,
        MAX_CARDINALITY_CAP,
    )?;
    range(
        "max_sessions_per_user",
        cfg.max_sessions_per_user,
        MAX_SESSIONS_PER_USER_CAP,
    )?;
    range(
        "max_payload_bytes",
        cfg.max_payload_bytes,
        MAX_PAYLOAD_BYTES_CAP,
    )?;
    range("max_queue_refs", cfg.max_queue_refs, MAX_QUEUE_REFS_CAP)?;
    range("max_fanout_jobs", cfg.max_fanout_jobs, MAX_FANOUT_JOBS_CAP)?;
    let min_frame = max_msg_bytes + GRPC_MESSAGE_PREFIX_BYTES;
    if cfg.max_payload_bytes < min_frame {
        bail!(
            "{path}.max_payload_bytes ({}) must be able to hold at \
             least one max-size framed message ({min_frame} bytes)",
            cfg.max_payload_bytes
        );
    }
    Ok(GrpcEdgeLimitsPlan {
        max_msg_bytes,
        max_id_bytes: cfg.max_id_bytes,
        max_streams_per_node: cfg.max_streams_per_node,
        max_groups_per_node: cfg.max_groups_per_node,
        max_members_per_group: cfg.max_members_per_group,
        max_sessions_per_user: cfg.max_sessions_per_user,
        max_payload_bytes: cfg.max_payload_bytes,
        max_queue_refs: cfg.max_queue_refs,
        max_fanout_jobs: cfg.max_fanout_jobs,
    })
}

/// 业务作用：校验并编译 PublishStream 四门。
///
/// 与 `send_queue.max_bytes` 同款不变量:累计字节门必须容得下至少一条最大帧
/// (`max_msg_bytes + 5`),否则合法的单条消息都发不进流,配置必然是笔误。
fn build_publish_stream(
    route_id: &str,
    cfg: &GrpcEdgePublishStreamCfg,
    max_msg_bytes: usize,
) -> Result<GrpcEdgePublishStreamPlan> {
    let range = |field: &str, value: u64, cap: u64| -> Result<()> {
        if value == 0 || value > cap {
            bail!("route `{route_id}` grpc_edge.publish_stream.{field} must be within 1..={cap}");
        }
        Ok(())
    };
    range(
        "max_lifetime_ms",
        cfg.max_lifetime_ms,
        MAX_PUBLISH_STREAM_LIFETIME_MS_CAP,
    )?;
    range(
        "max_messages",
        cfg.max_messages,
        MAX_PUBLISH_STREAM_MESSAGES_CAP,
    )?;
    range(
        "max_msgs_per_sec",
        cfg.max_msgs_per_sec,
        MAX_PUBLISH_STREAM_RATE_CAP,
    )?;
    range(
        "max_total_bytes",
        cfg.max_total_bytes,
        MAX_PUBLISH_STREAM_TOTAL_BYTES_CAP,
    )?;
    let min_total = (max_msg_bytes + GRPC_MESSAGE_PREFIX_BYTES) as u64;
    if cfg.max_total_bytes < min_total {
        bail!(
            "route `{route_id}` grpc_edge.publish_stream.max_total_bytes ({}) must be at least \
             limits.max_msg_bytes + {GRPC_MESSAGE_PREFIX_BYTES} = {min_total} so one max-size \
             framed message fits",
            cfg.max_total_bytes
        );
    }
    Ok(GrpcEdgePublishStreamPlan {
        max_lifetime: Duration::from_millis(cfg.max_lifetime_ms),
        max_messages: cfg.max_messages,
        max_msgs_per_sec: cfg.max_msgs_per_sec,
        max_total_bytes: cfg.max_total_bytes,
    })
}

/// 业务作用：校验 header 名:非空、合法 HTTP header、且必须小写声明。
///
/// HTTP/2 wire 上 header 恒为小写;强制配置侧就写小写,避免"配置大写、运行期
/// 匹配小写"的隐性归一化让 dry-run diff 与实际行为不一致。
fn parse_header(route_id: &str, field: &str, raw: &str) -> Result<HeaderName> {
    if raw.is_empty() {
        bail!("route `{route_id}` grpc_edge.{field} must not be empty");
    }
    if raw.bytes().any(|b| b.is_ascii_uppercase()) {
        bail!(
            "route `{route_id}` grpc_edge.{field} `{raw}` must be lowercase; \
             HTTP/2 header names are lowercase on the wire"
        );
    }
    HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
        anyhow::anyhow!("route `{route_id}` grpc_edge.{field} `{raw}` is not a valid header name")
    })
}

/// 业务作用：校验订阅队列:消息数与逻辑字节双维都有界,且必须容得下一条最大消息的帧全长
/// (队列计费单位是 `[5 字节前缀 + body]`;连一条都装不下的队列只会永远拒绝)。
fn validate_send_queue(
    route_id: &str,
    queue: &GrpcEdgeSendQueueCfg,
    max_msg_bytes: usize,
) -> Result<()> {
    if queue.max_messages == 0 || queue.max_messages > MAX_QUEUE_MESSAGES {
        bail!(
            "route `{route_id}` grpc_edge.send_queue.max_messages must be within \
             1..={MAX_QUEUE_MESSAGES}"
        );
    }
    if queue.max_bytes == 0 || queue.max_bytes > MAX_QUEUE_BYTES {
        bail!(
            "route `{route_id}` grpc_edge.send_queue.max_bytes must be within 1..={MAX_QUEUE_BYTES}"
        );
    }
    let min_frame = max_msg_bytes + GRPC_MESSAGE_PREFIX_BYTES;
    if queue.max_bytes < min_frame {
        bail!(
            "route `{route_id}` grpc_edge.send_queue.max_bytes ({}) must be at least \
             limits.max_msg_bytes + {GRPC_MESSAGE_PREFIX_BYTES} = {min_frame} so one max-size \
             framed message fits",
            queue.max_bytes
        );
    }
    Ok(())
}

/// 业务作用：校验 relay 队列:双维有界;`close_slow` 对 peer 无意义(关闭 relay 连接会波及
/// 整节点订阅者),构建期拒绝而不是运行期降级。
fn validate_relay_queue(queue: &GrpcEdgeRelayQueueCfg) -> Result<()> {
    if queue.max_messages == 0 || queue.max_messages > MAX_QUEUE_MESSAGES {
        bail!("grpc_edge_cluster.relay_queue.max_messages must be within 1..={MAX_QUEUE_MESSAGES}");
    }
    if queue.max_bytes == 0 || queue.max_bytes > MAX_QUEUE_BYTES {
        bail!("grpc_edge_cluster.relay_queue.max_bytes must be within 1..={MAX_QUEUE_BYTES}");
    }
    match queue.overflow {
        GrpcEdgeOverflowCfg::CloseSlow => bail!(
            "grpc_edge_cluster.relay_queue.overflow=close_slow is not allowed; closing a peer \
             relay stream punishes every subscriber behind that node — use drop_new (default) \
             or drop_oldest"
        ),
        GrpcEdgeOverflowCfg::LatestByKey => {}
        _ => {}
    }
    Ok(())
}

/// 业务作用：校验 cluster_id/node_id 形态:非空、有界、`[A-Za-z0-9._-]`。
///
/// 这个字符集覆盖 `${POD_UID}`/主机名/语义化版本,同时把控制字符、空白与分隔符
/// 挡在 relay 握手载荷之外。
fn parse_identity_token(field: &str, raw: &str, max_bytes: usize) -> Result<Box<str>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{field} is required when mode=relay (peers verify it during the relay handshake)");
    }
    if trimmed.len() > max_bytes {
        bail!("{field} must be at most {max_bytes} bytes");
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("{field} `{trimmed}` may only contain ASCII alphanumerics, `.`, `_` and `-`");
    }
    Ok(Box::from(trimmed))
}

/// 业务作用：编译 edge relay mTLS 配置；所有证书错误都在快照构建期 fail-fast。
fn build_relay_tls(
    cfg: &crate::config::model::GrpcEdgeRelayTlsCfg,
    config_dir: &std::path::Path,
) -> anyhow::Result<Option<crate::tls::EdgeRelayTlsProfile>> {
    anyhow::ensure!(
        (1..=30_000).contains(&cfg.handshake_timeout_ms),
        "grpc_edge_cluster.tls.handshake_timeout_ms must be in 1..=30000"
    );
    if !cfg.enabled {
        anyhow::ensure!(
            cfg.ca_file.is_empty() && cfg.cert_file.is_empty() && cfg.key_file.is_empty(),
            "grpc_edge_cluster.tls certificate paths require enabled=true"
        );
        return Ok(None);
    }
    let mut paths = Vec::with_capacity(3);
    for (field, value) in [
        ("ca_file", cfg.ca_file.as_str()),
        ("cert_file", cfg.cert_file.as_str()),
        ("key_file", cfg.key_file.as_str()),
    ] {
        let path = std::path::Path::new(value);
        anyhow::ensure!(
            !path.as_os_str().is_empty(),
            "grpc_edge_cluster.tls.{field} must not be empty"
        );
        paths.push(if path.is_absolute() {
            path.to_path_buf()
        } else {
            config_dir.join(path)
        });
    }
    crate::tls::build_edge_relay_tls_profile(&cfg.server_name, &paths[0], &paths[1], &paths[2])
        .map(Some)
        .map_err(|error| anyhow::anyhow!("grpc_edge_cluster.tls is invalid: {error:#}"))
}
