//! Kafka client data-plane 的有界协议治理。
//!
//! 本模块只在 `kafka-governance` feature 中编译。它不实现 broker、group coordinator 或 transaction
//! coordinator；只校验受支持的 request、跟踪 correlation/SASL re-auth，并在响应中改写显式映射的
//! broker endpoint。需要完整 Kafka API/version surface 时应使用透明 TCP profile。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout_at, Instant};

use crate::config::model::{KafkaBrokerRewriteCfg, StreamKafkaCfg};

const MAX_KAFKA_FRAME_BYTES: usize = 100 * 1024 * 1024;
const MAX_KAFKA_BUFFERED_BYTES: usize = 512 * 1024 * 1024;
const MAX_KAFKA_ACL_ITEMS: usize = 4096;
const MAX_KAFKA_ENDPOINTS: usize = 4096;

const API_PRODUCE: i16 = 0;
const API_FETCH: i16 = 1;
const API_LIST_OFFSETS: i16 = 2;
const API_METADATA: i16 = 3;
const API_OFFSET_COMMIT: i16 = 8;
const API_OFFSET_FETCH: i16 = 9;
const API_FIND_COORDINATOR: i16 = 10;
const API_JOIN_GROUP: i16 = 11;
const API_HEARTBEAT: i16 = 12;
const API_LEAVE_GROUP: i16 = 13;
const API_SYNC_GROUP: i16 = 14;
const API_DESCRIBE_GROUPS: i16 = 15;
const API_SASL_HANDSHAKE: i16 = 17;
const API_API_VERSIONS: i16 = 18;
const API_INIT_PRODUCER_ID: i16 = 22;
const API_OFFSET_FOR_LEADER_EPOCH: i16 = 23;
const API_SASL_AUTHENTICATE: i16 = 36;

const SUPPORTED_APIS: &[(i16, i16, i16)] = &[
    (API_PRODUCE, 0, 8),
    (API_FETCH, 4, 11),
    (API_LIST_OFFSETS, 1, 5),
    (API_METADATA, 0, 8),
    (API_OFFSET_COMMIT, 2, 7),
    (API_OFFSET_FETCH, 2, 5),
    (API_FIND_COORDINATOR, 0, 2),
    (API_JOIN_GROUP, 1, 5),
    (API_HEARTBEAT, 0, 3),
    (API_LEAVE_GROUP, 0, 3),
    (API_SYNC_GROUP, 0, 3),
    (API_DESCRIBE_GROUPS, 0, 4),
    (API_SASL_HANDSHAKE, 1, 1),
    (API_API_VERSIONS, 0, 4),
    (API_INIT_PRODUCER_ID, 0, 1),
    (API_OFFSET_FOR_LEADER_EPOCH, 3, 3),
    (API_SASL_AUTHENTICATE, 0, 1),
];

/// Kafka broker response endpoint 的运行期改写目标。
#[derive(Clone, Debug, PartialEq, Eq)]
struct BrokerEndpoint {
    host: Arc<str>,
    port: u16,
}

/// 构建期冻结的 Kafka ACL、资源门与 endpoint rewrite 计划。
#[derive(Debug, PartialEq, Eq)]
pub struct KafkaPolicy {
    max_connections: usize,
    max_frame_bytes: usize,
    frame_timeout_ms: u64,
    max_buffered_bytes: usize,
    max_inflight_requests: usize,
    max_client_id_bytes: usize,
    max_topic_bytes: usize,
    max_group_bytes: usize,
    max_array_items: usize,
    client_ids: HashSet<Arc<str>>,
    topics: HashSet<Arc<str>>,
    groups: HashSet<Arc<str>>,
    sasl_mechanisms: HashSet<Arc<str>>,
    broker_rewrite: HashMap<(Arc<str>, u16), BrokerEndpoint>,
}

impl KafkaPolicy {
    /// 业务作用：把 Kafka profile 编译为不可变 ACL/rewrite 计划，并在快照发布前证明资源总量有界。
    ///
    /// 参数说明：
    /// - `cfg`：是 listener 级 Kafka 治理配置。
    ///
    /// 返回：合法配置返回运行计划；预算乘法溢出、ACL/endpoint 重复或危险边界返回错误。
    pub fn build(cfg: &StreamKafkaCfg) -> Result<Self> {
        anyhow::ensure!(
            (1..=65_536).contains(&cfg.max_connections),
            "max_connections must be in 1..=65536"
        );
        anyhow::ensure!(
            (64..=MAX_KAFKA_FRAME_BYTES).contains(&cfg.max_frame_bytes),
            "max_frame_bytes must be in 64..={MAX_KAFKA_FRAME_BYTES}"
        );
        anyhow::ensure!(
            (100..=60_000).contains(&cfg.frame_timeout_ms),
            "frame_timeout_ms must be in 100..=60000"
        );
        anyhow::ensure!(
            (1024 * 1024..=MAX_KAFKA_BUFFERED_BYTES).contains(&cfg.max_buffered_bytes),
            "max_buffered_bytes must be in 1MiB..=512MiB"
        );
        let reservation = cfg
            .max_connections
            .checked_mul(cfg.max_frame_bytes)
            .and_then(|value| value.checked_mul(2))
            .context("max_connections * max_frame_bytes * 2 overflows")?;
        anyhow::ensure!(
            reservation <= cfg.max_buffered_bytes,
            "max_connections * max_frame_bytes * 2 exceeds max_buffered_bytes"
        );
        anyhow::ensure!(
            (1..=65_536).contains(&cfg.max_inflight_requests),
            "max_inflight_requests must be in 1..=65536"
        );
        anyhow::ensure!(
            (1..=1024).contains(&cfg.max_client_id_bytes),
            "max_client_id_bytes must be in 1..=1024"
        );
        anyhow::ensure!(
            (1..=1024).contains(&cfg.max_topic_bytes),
            "max_topic_bytes must be in 1..=1024"
        );
        anyhow::ensure!(
            (1..=32_767).contains(&cfg.max_group_bytes),
            "max_group_bytes must be in 1..=32767"
        );
        anyhow::ensure!(
            (1..=1_000_000).contains(&cfg.max_array_items),
            "max_array_items must be in 1..=1000000"
        );
        let client_ids = compile_exact_acl(
            "client_id_allow",
            &cfg.client_id_allow,
            cfg.max_client_id_bytes,
            false,
        )?;
        let topics = compile_exact_acl("topic_allow", &cfg.topic_allow, cfg.max_topic_bytes, true)?;
        let groups =
            compile_exact_acl("group_allow", &cfg.group_allow, cfg.max_group_bytes, false)?;
        let sasl_mechanisms = compile_sasl_mechanisms(&cfg.sasl_mechanism_allow)?;
        let broker_rewrite = compile_broker_rewrite(&cfg.broker_rewrite)?;
        anyhow::ensure!(
            !broker_rewrite.is_empty(),
            "broker_rewrite requires at least one endpoint mapping"
        );
        Ok(Self {
            max_connections: cfg.max_connections,
            max_frame_bytes: cfg.max_frame_bytes,
            frame_timeout_ms: cfg.frame_timeout_ms,
            max_buffered_bytes: cfg.max_buffered_bytes,
            max_inflight_requests: cfg.max_inflight_requests,
            max_client_id_bytes: cfg.max_client_id_bytes,
            max_topic_bytes: cfg.max_topic_bytes,
            max_group_bytes: cfg.max_group_bytes,
            max_array_items: cfg.max_array_items,
            client_ids,
            topics,
            groups,
            sasl_mechanisms,
            broker_rewrite,
        })
    }

    /// 业务作用：提供 listener 连接硬门，供 TLS/首 frame 前抢占名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置的最大并发连接数。
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// 业务作用：给一条连接预留双向最大 frame，避免双向同时读包突破聚合预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`max_frame_bytes * 2`；构建期已证明不会溢出。
    pub fn connection_buffer_reservation(&self) -> usize {
        self.max_frame_bytes * 2
    }

    /// 业务作用：提供 listener 跨连接聚合 buffer 硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置的最大聚合预留字节数。
    pub fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    /// 业务作用：判断 request header client id 是否在精确 ACL 内。
    ///
    /// 参数说明：
    /// - `client_id`：是已通过 UTF-8/长度门的可选 client id。
    ///
    /// 返回：ACL 为空时放行；否则只有非空且精确命中才放行。
    fn allows_client_id(&self, client_id: Option<&str>) -> bool {
        self.client_ids.is_empty() || client_id.is_some_and(|value| self.client_ids.contains(value))
    }

    /// 业务作用：对所有会触达数据/metadata 的 topic 名执行同一份精确授权。
    ///
    /// 参数说明：
    /// - `topic`：是已通过 Kafka STRING 与长度门的名称。
    ///
    /// 返回：只有精确命中 `topic_allow` 才返回 true；空 ACL 拒绝全部 topic API。
    fn allows_topic(&self, topic: &str) -> bool {
        self.topics.contains(topic)
    }

    /// 业务作用：对 consumer group/coordinator 请求执行精确授权。
    ///
    /// 参数说明：
    /// - `group`：是已通过 Kafka STRING 与长度门的 group id。
    ///
    /// 返回：只有精确命中 `group_allow` 才返回 true；空 ACL 拒绝全部 group API。
    fn allows_group(&self, group: &str) -> bool {
        self.groups.contains(group)
    }

    /// 业务作用：限制可进入 opaque SASL token 交换的 mechanism，避免未经声明的认证面扩张。
    ///
    /// 参数说明：
    /// - `mechanism`：是 SaslHandshake v1 中的名称。
    ///
    /// 返回：只有精确命中 `sasl_mechanism_allow` 才放行。
    fn allows_sasl_mechanism(&self, mechanism: &str) -> bool {
        self.sasl_mechanisms.contains(mechanism)
    }

    /// 业务作用：把 broker 返回的内部 endpoint 映射为 client 可达的代理 endpoint。
    ///
    /// 参数说明：
    /// - `host`：来自 Metadata 或 FindCoordinator 成功响应。
    /// - `port`：来自 Metadata 或 FindCoordinator 成功响应。
    ///
    /// 返回：精确映射存在时返回目标；缺项返回 None，调用方必须失败闭合以免泄露内部地址。
    fn rewrite_endpoint(&self, host: &str, port: i32) -> Option<&BrokerEndpoint> {
        let port = u16::try_from(port).ok()?;
        self.broker_rewrite
            .get(&(Arc::<str>::from(host.to_ascii_lowercase()), port))
    }
}

/// 业务作用：编译精确字符串 ACL，统一拒绝空值、控制字符、重复项和超长项。
///
/// 参数说明：
/// - `field`：用于错误上下文
/// - `values`：是配置值
/// - `maximum_bytes`：是单项上限
/// - `topic_syntax`：表示是否额外执行 Kafka topic 字符约束。
///
/// 返回：合法值返回共享字符串集合；任一项不安全时阻止快照发布。
fn compile_exact_acl(
    field: &str,
    values: &[String],
    maximum_bytes: usize,
    topic_syntax: bool,
) -> Result<HashSet<Arc<str>>> {
    anyhow::ensure!(
        values.len() <= MAX_KAFKA_ACL_ITEMS,
        "{field} exceeds {MAX_KAFKA_ACL_ITEMS} entries"
    );
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        anyhow::ensure!(
            !value.is_empty()
                && value.len() <= maximum_bytes
                && !value.chars().any(char::is_control),
            "{field} contains an empty, oversized, or control-character value"
        );
        if topic_syntax {
            anyhow::ensure!(
                value != "."
                    && value != ".."
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'.' | b'_' | b'-')),
                "{field} contains an invalid Kafka topic name"
            );
        }
        anyhow::ensure!(
            output.insert(Arc::from(value.as_str())),
            "{field} contains duplicate value `{value}`"
        );
    }
    Ok(output)
}

/// 业务作用：编译允许的 SASL mechanism 名称，不解析或记录后续凭据 token。
///
/// 参数说明：
/// - `values`：是显式 allowlist。
///
/// 返回：合法 ASCII mechanism 集；空集合表示治理 profile 不开放 SASL。
fn compile_sasl_mechanisms(values: &[String]) -> Result<HashSet<Arc<str>>> {
    anyhow::ensure!(
        values.len() <= 64,
        "sasl_mechanism_allow exceeds 64 entries"
    );
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        anyhow::ensure!(
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "sasl_mechanism_allow contains invalid mechanism"
        );
        anyhow::ensure!(
            output.insert(Arc::from(value.as_str())),
            "sasl_mechanism_allow contains duplicate `{value}`"
        );
    }
    Ok(output)
}

/// 业务作用：编译 broker endpoint 一一映射，避免多 broker 被错误折叠到同一不可区分入口。
///
/// 参数说明：
/// - `values`：是原 endpoint 到代理 endpoint 的显式表。
///
/// 返回：合法映射返回按小写 host 索引的表；源/目标重复、空 host、控制字符或零端口返回错误。
fn compile_broker_rewrite(
    values: &[KafkaBrokerRewriteCfg],
) -> Result<HashMap<(Arc<str>, u16), BrokerEndpoint>> {
    anyhow::ensure!(
        values.len() <= MAX_KAFKA_ENDPOINTS,
        "broker_rewrite exceeds {MAX_KAFKA_ENDPOINTS} entries"
    );
    let mut output = HashMap::with_capacity(values.len());
    let mut targets = HashSet::with_capacity(values.len());
    for value in values {
        for (field, host) in [("from_host", &value.from_host), ("to_host", &value.to_host)] {
            anyhow::ensure!(
                !host.is_empty()
                    && host.len() <= 255
                    && !host.chars().any(|ch| ch.is_control() || ch.is_whitespace()),
                "broker_rewrite.{field} is invalid"
            );
        }
        anyhow::ensure!(
            value.from_port != 0 && value.to_port != 0,
            "broker_rewrite ports must be non-zero"
        );
        let source = (
            Arc::<str>::from(value.from_host.to_ascii_lowercase()),
            value.from_port,
        );
        let target = (value.to_host.to_ascii_lowercase(), value.to_port);
        anyhow::ensure!(
            targets.insert(target),
            "broker_rewrite target endpoint must be unique"
        );
        anyhow::ensure!(
            output
                .insert(
                    source,
                    BrokerEndpoint {
                        host: Arc::from(value.to_host.as_str()),
                        port: value.to_port,
                    },
                )
                .is_none(),
            "broker_rewrite source endpoint must be unique"
        );
    }
    Ok(output)
}

/// Kafka 治理拒绝原因；集合固定，适合作为低基数指标 label。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KafkaViolationKind {
    Malformed,
    Protocol,
    NotAuthorized,
    FrameTooLarge,
    ResourceLimit,
}

impl fmt::Display for KafkaViolationKind {
    /// 业务作用：输出稳定低基数拒绝名，供日志和 metrics 共用。
    ///
    /// 参数说明：
    /// - `formatter`：是格式化目标。
    ///
    /// 返回：写入固定 snake_case 名称。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed",
            Self::Protocol => "protocol",
            Self::NotAuthorized => "not_authorized",
            Self::FrameTooLarge => "frame_too_large",
            Self::ResourceLimit => "resource_limit",
        })
    }
}

/// 发生失败或 I/O 错误的对端，用于隔离 client 攻击与 broker 被动健康。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KafkaPeer {
    Client,
    Broker,
}

/// 一次 Kafka 双向治理会话的累计转发量。
#[derive(Clone, Copy, Debug, Default)]
pub struct KafkaProxyReport {
    pub downstream_to_upstream_bytes: u64,
    pub upstream_to_downstream_bytes: u64,
    pub downstream_to_upstream_frames: u64,
    pub upstream_to_downstream_frames: u64,
}

/// 带失败对端、固定分类与当时累计量的 Kafka 会话错误。
#[derive(Debug)]
pub struct KafkaProxyError {
    kind: KafkaViolationKind,
    peer: KafkaPeer,
    message: String,
    report: KafkaProxyReport,
}

impl KafkaProxyError {
    /// 业务作用：暴露固定错误分类，不向指标泄露 topic/group/client 等高基数文本。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：错误的固定分类。
    pub fn kind(&self) -> KafkaViolationKind {
        self.kind
    }

    /// 业务作用：标识实际失败对端，防止 client 协议攻击污染 broker 被动健康。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：Client 或 Broker。
    pub fn peer(&self) -> KafkaPeer {
        self.peer
    }

    /// 业务作用：在失败访问日志中保留已成功转发的字节/frame 计数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：错误发生前的会话累计量。
    pub fn report(&self) -> KafkaProxyReport {
        self.report
    }
}

impl fmt::Display for KafkaProxyError {
    /// 业务作用：输出不含凭据和 packet body 的安全诊断。
    ///
    /// 参数说明：
    /// - `formatter`：是格式化目标。
    ///
    /// 返回：写入固定分类和内部静态诊断文本。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for KafkaProxyError {}

/// 协议解析内部错误；提升为 `KafkaProxyError` 时才附加对端与累计量。
#[derive(Debug)]
struct KafkaViolation {
    kind: KafkaViolationKind,
    message: String,
}

impl KafkaViolation {
    /// 业务作用：构造 malformed 分类，表示 frame 不能按声明 schema 完整解码。
    ///
    /// 参数说明：
    /// - `message`：是不含不可信原文的静态诊断。
    ///
    /// 返回：Malformed violation。
    fn malformed(message: impl Into<String>) -> Self {
        Self {
            kind: KafkaViolationKind::Malformed,
            message: message.into(),
        }
    }

    /// 业务作用：构造 protocol 分类，表示 correlation、方向、版本或 SASL 时序违规。
    ///
    /// 参数说明：
    /// - `message`：是不含不可信原文的静态诊断。
    ///
    /// 返回：Protocol violation。
    fn protocol(message: impl Into<String>) -> Self {
        Self {
            kind: KafkaViolationKind::Protocol,
            message: message.into(),
        }
    }

    /// 业务作用：构造授权拒绝，不把被拒 topic/group/client id 带入错误或 metrics。
    ///
    /// 参数说明：
    /// - `message`：是低基数诊断。
    ///
    /// 返回：NotAuthorized violation。
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            kind: KafkaViolationKind::NotAuthorized,
            message: message.into(),
        }
    }

    /// 业务作用：构造 frame 长度硬门拒绝，区分格式错误与资源攻击。
    ///
    /// 参数说明：
    /// - `message`：是低基数诊断。
    ///
    /// 返回：FrameTooLarge violation。
    fn frame_too_large(message: impl Into<String>) -> Self {
        Self {
            kind: KafkaViolationKind::FrameTooLarge,
            message: message.into(),
        }
    }

    /// 业务作用：构造在途 correlation/数组等运行资源硬门拒绝。
    ///
    /// 参数说明：
    /// - `message`：是低基数诊断。
    ///
    /// 返回：ResourceLimit violation。
    fn resource(message: impl Into<String>) -> Self {
        Self {
            kind: KafkaViolationKind::ResourceLimit,
            message: message.into(),
        }
    }
}

/// Kafka size-delimited wire frame，包含四字节长度前缀。
#[derive(Clone, Debug)]
struct KafkaFrame {
    wire: Vec<u8>,
}

impl KafkaFrame {
    /// 业务作用：从重写后的 payload 重新生成 canonical 四字节长度前缀。
    ///
    /// 参数说明：
    /// - `payload`：从 response correlation header 开始。
    ///
    /// 返回：长度可表示时返回完整 frame；超 i32 上限时返回资源错误。
    fn from_payload(payload: Vec<u8>) -> std::result::Result<Self, KafkaViolation> {
        let length = i32::try_from(payload.len())
            .map_err(|_| KafkaViolation::frame_too_large("rewritten Kafka frame exceeds i32"))?;
        let mut wire = Vec::with_capacity(payload.len() + 4);
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(&payload);
        Ok(Self {
            wire,
        })
    }
}

/// 业务作用：读取单枚 Kafka frame，并从长度前缀首字节开始执行 deadline 和分配硬门。
///
/// 参数说明：
/// - `reader`：是单方向字节流
/// - `max_frame_bytes`：包含四字节前缀
/// - `frame_timeout_ms`：只约束已经开始的 frame。
///
/// 返回：纯 idle 时等待；EOF 返回 None；完整合法长度返回 frame；截断、超时或超限返回固定分类。
async fn read_frame<R>(
    reader: &mut R,
    max_frame_bytes: usize,
    frame_timeout_ms: u64,
) -> std::result::Result<Option<KafkaFrame>, KafkaViolation>
where
    R: AsyncRead + Unpin,
{
    let mut length_prefix = [0_u8; 4];
    match reader.read(&mut length_prefix[..1]).await {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("single-byte read returned more than one byte"),
        Err(error) => {
            return Err(KafkaViolation::protocol(format!(
                "Kafka read failed: {error}"
            )))
        }
    }
    let deadline = Instant::now() + Duration::from_millis(frame_timeout_ms);
    timeout_at(deadline, reader.read_exact(&mut length_prefix[1..]))
        .await
        .map_err(|_| KafkaViolation::resource("Kafka frame prefix deadline exceeded"))?
        .map_err(|error| {
            KafkaViolation::malformed(format!("Kafka frame prefix truncated: {error}"))
        })?;
    let length = i32::from_be_bytes(length_prefix);
    if length < 0 {
        return Err(KafkaViolation::malformed("Kafka frame length is negative"));
    }
    let body_len = length as usize;
    let wire_len = body_len
        .checked_add(4)
        .ok_or_else(|| KafkaViolation::frame_too_large("Kafka frame length overflows"))?;
    if wire_len > max_frame_bytes {
        return Err(KafkaViolation::frame_too_large(
            "Kafka frame exceeds max_frame_bytes",
        ));
    }
    let mut wire = Vec::with_capacity(wire_len);
    wire.extend_from_slice(&length_prefix);
    wire.resize(wire_len, 0);
    timeout_at(deadline, reader.read_exact(&mut wire[4..]))
        .await
        .map_err(|_| KafkaViolation::resource("Kafka frame body deadline exceeded"))?
        .map_err(|error| {
            KafkaViolation::malformed(format!("Kafka frame body truncated: {error}"))
        })?;
    Ok(Some(KafkaFrame {
        wire,
    }))
}

/// 借用 frame 的有界 Kafka primitive reader。
struct KafkaReader<'a> {
    bytes: &'a [u8],
    position: usize,
    max_array_items: usize,
}

impl<'a> KafkaReader<'a> {
    /// 业务作用：创建只借用完整 frame 的 cursor，不复制业务 records/SASL token。
    ///
    /// 参数说明：
    /// - `bytes`：是待解析片段
    /// - `max_array_items`：约束所有数组。
    ///
    /// 返回：起点为零的 reader。
    fn new(bytes: &'a [u8], max_array_items: usize) -> Self {
        Self {
            bytes,
            position: 0,
            max_array_items,
        }
    }

    /// 业务作用：读取定长片段并统一执行截断检查。
    ///
    /// 参数说明：
    /// - `length`：是需要消费的字节数。
    ///
    /// 返回：成功返回借用 slice；越界返回 Malformed。
    fn take(&mut self, length: usize) -> std::result::Result<&'a [u8], KafkaViolation> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| KafkaViolation::malformed("Kafka cursor overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| KafkaViolation::malformed("Kafka field is truncated"))?;
        self.position = end;
        Ok(value)
    }

    /// 业务作用：读取 Kafka INT8。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功返回有符号字节；截断返回 Malformed。
    fn i8(&mut self) -> std::result::Result<i8, KafkaViolation> {
        Ok(self.take(1)?[0] as i8)
    }

    /// 业务作用：读取 Kafka BOOLEAN 并拒绝非 0/1 编码。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：0/1 返回 bool；其它值或截断返回 Malformed。
    fn boolean(&mut self) -> std::result::Result<bool, KafkaViolation> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(KafkaViolation::malformed("Kafka BOOLEAN is not 0 or 1")),
        }
    }

    /// 业务作用：读取 Kafka INT16。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功返回值；截断返回 Malformed。
    fn i16(&mut self) -> std::result::Result<i16, KafkaViolation> {
        let bytes: [u8; 2] = self.take(2)?.try_into().expect("two-byte slice");
        Ok(i16::from_be_bytes(bytes))
    }

    /// 业务作用：读取 Kafka INT32。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功返回值；截断返回 Malformed。
    fn i32(&mut self) -> std::result::Result<i32, KafkaViolation> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("four-byte slice");
        Ok(i32::from_be_bytes(bytes))
    }

    /// 业务作用：读取 Kafka INT64。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功返回值；截断返回 Malformed。
    fn i64(&mut self) -> std::result::Result<i64, KafkaViolation> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("eight-byte slice");
        Ok(i64::from_be_bytes(bytes))
    }

    /// 业务作用：读取 legacy STRING/NULLABLE_STRING 并执行 UTF-8 与长度硬门。
    ///
    /// 参数说明：
    /// - `maximum`：是业务字段上限
    /// - `nullable`：决定是否接受 -1。
    ///
    /// 返回：返回借用字符串或 None；非法负长度、超限、截断或非 UTF-8 返回 Malformed/ResourceLimit。
    fn string(
        &mut self,
        maximum: usize,
        nullable: bool,
    ) -> std::result::Result<Option<&'a str>, KafkaViolation> {
        let length = self.i16()?;
        if length == -1 && nullable {
            return Ok(None);
        }
        if length < 0 {
            return Err(KafkaViolation::malformed("Kafka STRING length is invalid"));
        }
        let length = length as usize;
        if length > maximum {
            return Err(KafkaViolation::resource("Kafka STRING exceeds field limit"));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| KafkaViolation::malformed("Kafka STRING is not UTF-8"))?;
        Ok(Some(value))
    }

    /// 业务作用：读取 legacy ARRAY 长度并统一限制循环规模。
    ///
    /// 参数说明：
    /// - `nullable`：决定是否接受 -1。
    ///
    /// 返回：合法长度返回 Some；nullable -1 返回 None；其它负值或超预算返回错误。
    fn array_len(&mut self, nullable: bool) -> std::result::Result<Option<usize>, KafkaViolation> {
        let length = self.i32()?;
        if length == -1 && nullable {
            return Ok(None);
        }
        if length < 0 {
            return Err(KafkaViolation::malformed("Kafka ARRAY length is invalid"));
        }
        let length = length as usize;
        if length > self.max_array_items {
            return Err(KafkaViolation::resource(
                "Kafka ARRAY exceeds max_array_items",
            ));
        }
        Ok(Some(length))
    }

    /// 业务作用：读取 BYTES/RECORDS 并跳过不需要反序列化的有界 payload。
    ///
    /// 参数说明：
    /// - `nullable`：决定是否接受 -1；frame 总门已限制最大字节。
    ///
    /// 返回：返回借用 payload 或 None；非法长度/截断返回错误。
    fn bytes_field(
        &mut self,
        nullable: bool,
    ) -> std::result::Result<Option<&'a [u8]>, KafkaViolation> {
        let length = self.i32()?;
        if length == -1 && nullable {
            return Ok(None);
        }
        if length < 0 {
            return Err(KafkaViolation::malformed("Kafka BYTES length is invalid"));
        }
        Ok(Some(self.take(length as usize)?))
    }

    /// 业务作用：读取 Kafka unsigned varint 并拒绝溢出或非最短编码。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法 canonical varint 返回值；超过五字节、溢出或非最短编码返回 Malformed。
    fn uvarint(&mut self) -> std::result::Result<u32, KafkaViolation> {
        let mut value = 0_u32;
        for index in 0..5 {
            let byte = self.take(1)?[0];
            if index == 4 && byte > 0x0f {
                return Err(KafkaViolation::malformed("Kafka varint overflows u32"));
            }
            value |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && value < (1_u32 << (index * 7)) {
                    return Err(KafkaViolation::malformed(
                        "Kafka varint is not minimally encoded",
                    ));
                }
                return Ok(value);
            }
        }
        Err(KafkaViolation::malformed("Kafka varint exceeds five bytes"))
    }

    /// 业务作用：读取 flexible COMPACT_STRING/COMPACT_NULLABLE_STRING。
    ///
    /// 参数说明：
    /// - `maximum`：是字段上限
    /// - `nullable`：决定零长度标记是否表示 None。
    ///
    /// 返回：返回借用 UTF-8 字符串或 None；超限/截断/非法编码返回错误。
    fn compact_string(
        &mut self,
        maximum: usize,
        nullable: bool,
    ) -> std::result::Result<Option<&'a str>, KafkaViolation> {
        let encoded = self.uvarint()?;
        if encoded == 0 && nullable {
            return Ok(None);
        }
        if encoded == 0 {
            return Err(KafkaViolation::malformed("Kafka compact string is null"));
        }
        let length = (encoded - 1) as usize;
        if length > maximum {
            return Err(KafkaViolation::resource(
                "Kafka compact string exceeds field limit",
            ));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| KafkaViolation::malformed("Kafka compact string is not UTF-8"))?;
        Ok(Some(value))
    }

    /// 业务作用：跳过 flexible tagged fields，并验证 tag 单调递增、数量和长度都受硬门限制。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法 tag buffer 消费完成；重复/乱序/超限/截断返回错误。
    fn tagged_fields(&mut self) -> std::result::Result<(), KafkaViolation> {
        let count = self.uvarint()? as usize;
        if count > self.max_array_items {
            return Err(KafkaViolation::resource(
                "Kafka tagged fields exceed max_array_items",
            ));
        }
        let mut previous = None;
        for _ in 0..count {
            let tag = self.uvarint()?;
            if previous.is_some_and(|last| tag <= last) {
                return Err(KafkaViolation::malformed(
                    "Kafka tagged fields are not strictly ordered",
                ));
            }
            previous = Some(tag);
            let size = self.uvarint()? as usize;
            self.take(size)?;
        }
        Ok(())
    }

    /// 业务作用：确认 schema 精确消费完整 frame，拒绝把隐藏尾随字段当 opaque 数据放行。
    ///
    /// 参数说明：
    /// - `name`：是低基数 API/结构名。
    ///
    /// 返回：无剩余返回成功；存在尾随字节返回 Malformed。
    fn finish(&self, name: &str) -> std::result::Result<(), KafkaViolation> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(KafkaViolation::malformed(format!(
                "Kafka {name} contains trailing bytes"
            )))
        }
    }
}

/// 在途 request 的响应 schema 与治理语义。
#[derive(Clone, Copy, Debug)]
struct PendingRequest {
    api_key: i16,
    api_version: i16,
    flexible_response: bool,
}

/// SASL v1 framed authentication/re-authentication 阶段。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SaslPhase {
    Normal,
    AwaitHandshakeResponse,
    Authenticate,
    AwaitAuthenticateResponse,
}

/// 单连接 correlation 与 SASL 时序状态；两个方向只在 frame 边界短暂加锁。
struct KafkaSession {
    policy: Arc<KafkaPolicy>,
    pending: HashMap<i32, PendingRequest>,
    sasl_phase: SaslPhase,
}

impl KafkaSession {
    /// 业务作用：为一条 broker 连接创建隔离的 correlation/SASL 状态，不跨连接复用协商结果。
    ///
    /// 参数说明：
    /// - `policy`：是 listener 快照内不可变治理计划。
    ///
    /// 返回：空在途表、Normal SASL 阶段的新状态机。
    fn new(policy: Arc<KafkaPolicy>) -> Self {
        Self {
            policy,
            pending: HashMap::new(),
            sasl_phase: SaslPhase::Normal,
        }
    }

    /// 业务作用：解析并授权 client request，在转发前预留 correlation id 与更新 SASL 门禁。
    ///
    /// 参数说明：
    /// - `frame`：是完整 client wire。
    ///
    /// 返回：合法 request 返回待转发；违规时不插入/不转发该 frame。
    fn validate_request(&mut self, frame: &KafkaFrame) -> std::result::Result<(), KafkaViolation> {
        if frame.wire.len() < 14 {
            return Err(KafkaViolation::malformed(
                "Kafka request header is truncated",
            ));
        }
        let payload = &frame.wire[4..];
        let mut reader = KafkaReader::new(payload, self.policy.max_array_items);
        let api_key = reader.i16()?;
        let api_version = reader.i16()?;
        let correlation_id = reader.i32()?;
        let (minimum, maximum) = supported_api(api_key)
            .ok_or_else(|| KafkaViolation::protocol("Kafka API is outside governed profile"))?;
        if !(minimum..=maximum).contains(&api_version) {
            return Err(KafkaViolation::protocol(
                "Kafka API version is outside governed profile",
            ));
        }
        let flexible_request = api_key == API_API_VERSIONS && api_version >= 3;
        let client_id = if flexible_request {
            // Kafka RequestHeader v2 的 client_id 仍是 NULLABLE_STRING；只有 header 尾部 tags 使用 flexible 编码。
            let value = reader.string(self.policy.max_client_id_bytes, true)?;
            reader.tagged_fields()?;
            value
        } else {
            reader.string(self.policy.max_client_id_bytes, true)?
        };
        if !self.policy.allows_client_id(client_id) {
            return Err(KafkaViolation::unauthorized(
                "Kafka client id is not authorized",
            ));
        }
        let expects_response = validate_request_body(
            &self.policy,
            api_key,
            api_version,
            &payload[reader.position..],
        )?;
        self.validate_sasl_request(api_key)?;
        if expects_response {
            if self.pending.len() >= self.policy.max_inflight_requests {
                return Err(KafkaViolation::resource(
                    "Kafka in-flight request budget exhausted",
                ));
            }
            if self.pending.contains_key(&correlation_id) {
                return Err(KafkaViolation::protocol(
                    "Kafka correlation id is already in flight",
                ));
            }
            let pending = PendingRequest {
                api_key,
                api_version,
                // ApiVersions v3/v4 虽有 flexible body，但协商前 response header 按规范固定为 v0。
                flexible_response: false,
            };
            self.pending.insert(correlation_id, pending);
            if api_key == API_SASL_HANDSHAKE {
                self.sasl_phase = SaslPhase::AwaitHandshakeResponse;
            } else if api_key == API_SASL_AUTHENTICATE {
                self.sasl_phase = SaslPhase::AwaitAuthenticateResponse;
            }
        }
        Ok(())
    }

    /// 业务作用：限制 SASL framed handshake/auth 与普通 API 的先后关系，并允许同连接 re-auth。
    ///
    /// 参数说明：
    /// - `api_key`：是已通过版本矩阵的请求 API。
    ///
    /// 返回：合法阶段成功；并发业务穿插握手、未握手认证或等待响应时再发请求返回 Protocol。
    fn validate_sasl_request(&mut self, api_key: i16) -> std::result::Result<(), KafkaViolation> {
        match self.sasl_phase {
            SaslPhase::AwaitHandshakeResponse | SaslPhase::AwaitAuthenticateResponse => Err(
                KafkaViolation::protocol("Kafka request interleaves an unfinished SASL exchange"),
            ),
            SaslPhase::Normal => {
                if api_key == API_SASL_AUTHENTICATE {
                    Err(KafkaViolation::protocol(
                        "SaslAuthenticate requires successful SaslHandshake v1",
                    ))
                } else if api_key == API_SASL_HANDSHAKE && !self.pending.is_empty() {
                    Err(KafkaViolation::protocol(
                        "Kafka re-authentication requires zero in-flight requests",
                    ))
                } else {
                    Ok(())
                }
            }
            SaslPhase::Authenticate => {
                if api_key == API_SASL_AUTHENTICATE {
                    Ok(())
                } else if api_key == API_SASL_HANDSHAKE {
                    if self.pending.is_empty() {
                        Ok(())
                    } else {
                        Err(KafkaViolation::protocol(
                            "Kafka re-authentication requires zero in-flight requests",
                        ))
                    }
                } else {
                    // 收到首枚普通 API 证明 SASL exchange 已结束；之后仍可按 broker lifetime 再握手。
                    self.sasl_phase = SaslPhase::Normal;
                    Ok(())
                }
            }
        }
    }

    /// 业务作用：按 correlation 找到原 request，校验/改写必要响应并推进 SASL re-auth 阶段。
    ///
    /// 参数说明：
    /// - `frame`：是 broker 返回的完整 wire。
    ///
    /// 返回：普通错误响应保持原字节；ApiVersions/Metadata/FindCoordinator 返回安全重写 frame；
    /// 未知/重复 correlation、坏 schema 或未映射成功 endpoint 返回错误且不转发。
    fn validate_response(
        &mut self,
        frame: KafkaFrame,
    ) -> std::result::Result<KafkaFrame, KafkaViolation> {
        if frame.wire.len() < 8 {
            return Err(KafkaViolation::malformed(
                "Kafka response header is truncated",
            ));
        }
        let correlation_id = i32::from_be_bytes(
            frame.wire[4..8]
                .try_into()
                .expect("four-byte correlation id"),
        );
        let pending = self.pending.remove(&correlation_id).ok_or_else(|| {
            KafkaViolation::protocol("Kafka response correlation id is not in flight")
        })?;
        let mut header_reader = KafkaReader::new(&frame.wire[4..], self.policy.max_array_items);
        header_reader.i32()?;
        if pending.flexible_response {
            header_reader.tagged_fields()?;
        }
        let body_start = 4 + header_reader.position;
        let result = match pending.api_key {
            API_API_VERSIONS => rewrite_api_versions(
                frame,
                body_start,
                pending.api_version,
                self.policy.max_array_items,
            ),
            API_METADATA => rewrite_metadata(&self.policy, frame, body_start, pending.api_version),
            API_FIND_COORDINATOR => {
                rewrite_find_coordinator(&self.policy, frame, body_start, pending.api_version)
            }
            API_SASL_HANDSHAKE => {
                let error = parse_sasl_handshake_response(
                    &frame.wire[body_start..],
                    self.policy.max_array_items,
                )?;
                self.sasl_phase = if error == 0 {
                    SaslPhase::Authenticate
                } else {
                    SaslPhase::Normal
                };
                Ok(frame)
            }
            API_SASL_AUTHENTICATE => {
                let error = parse_sasl_authenticate_response(
                    &frame.wire[body_start..],
                    pending.api_version,
                    self.policy.max_array_items,
                )?;
                self.sasl_phase = if error == 0 {
                    // 多轮 mechanism 可继续发 SaslAuthenticate；首枚普通 API 会结束该阶段。
                    SaslPhase::Authenticate
                } else {
                    SaslPhase::Normal
                };
                Ok(frame)
            }
            _ => Ok(frame),
        };
        if result.is_err() && matches!(pending.api_key, API_SASL_HANDSHAKE | API_SASL_AUTHENTICATE)
        {
            self.sasl_phase = SaslPhase::Normal;
        }
        result
    }
}

/// 业务作用：查询治理 profile 对 API 的唯一版本区间，供请求拒绝与 ApiVersions 响应求交共用。
///
/// 参数说明：
/// - `api_key`：是 Kafka request key。
///
/// 返回：受支持返回 `(min,max)`；未知/管理/事务 API 返回 None。
fn supported_api(api_key: i16) -> Option<(i16, i16)> {
    SUPPORTED_APIS
        .iter()
        .find(|(key, _, _)| *key == api_key)
        .map(|(_, minimum, maximum)| (*minimum, *maximum))
}

/// 业务作用：按 API/version 完整解析 client body，提取并授权 topic/group/SASL/transaction 边界。
///
/// 参数说明：
/// - `policy`：是不可变治理计划
/// - `api_key`：已过矩阵门
/// - `api_version`：已过矩阵门
/// - `body`：不含 header。
///
/// 返回：合法请求返回是否期待 response；任何未消费尾随、ACL 越权或危险 coordinator 语义返回错误。
fn validate_request_body(
    policy: &KafkaPolicy,
    api_key: i16,
    api_version: i16,
    body: &[u8],
) -> std::result::Result<bool, KafkaViolation> {
    let mut reader = KafkaReader::new(body, policy.max_array_items);
    let expects_response = match api_key {
        API_PRODUCE => validate_produce(policy, api_version, &mut reader)?,
        API_FETCH => {
            validate_fetch(policy, api_version, &mut reader)?;
            true
        }
        API_LIST_OFFSETS => {
            validate_list_offsets(policy, api_version, &mut reader)?;
            true
        }
        API_METADATA => {
            validate_metadata_request(policy, api_version, &mut reader)?;
            true
        }
        API_OFFSET_COMMIT => {
            validate_offset_commit(policy, api_version, &mut reader)?;
            true
        }
        API_OFFSET_FETCH => {
            validate_offset_fetch(policy, &mut reader)?;
            true
        }
        API_FIND_COORDINATOR => {
            validate_find_coordinator(policy, api_version, &mut reader)?;
            true
        }
        API_JOIN_GROUP => {
            validate_join_group(policy, api_version, &mut reader)?;
            true
        }
        API_HEARTBEAT => {
            validate_heartbeat(policy, api_version, &mut reader)?;
            true
        }
        API_LEAVE_GROUP => {
            validate_leave_group(policy, api_version, &mut reader)?;
            true
        }
        API_SYNC_GROUP => {
            validate_sync_group(policy, api_version, &mut reader)?;
            true
        }
        API_DESCRIBE_GROUPS => {
            validate_describe_groups(policy, api_version, &mut reader)?;
            true
        }
        API_SASL_HANDSHAKE => {
            let mechanism = required_string(&mut reader, 64, "SASL mechanism")?;
            if !policy.allows_sasl_mechanism(mechanism) {
                return Err(KafkaViolation::unauthorized(
                    "Kafka SASL mechanism is not authorized",
                ));
            }
            true
        }
        API_API_VERSIONS => {
            if api_version >= 3 {
                required_compact_string(&mut reader, 128, "client software name")?;
                required_compact_string(&mut reader, 128, "client software version")?;
                reader.tagged_fields()?;
            }
            true
        }
        API_INIT_PRODUCER_ID => {
            if reader.string(policy.max_group_bytes, true)?.is_some() {
                return Err(KafkaViolation::unauthorized(
                    "transactional producer is outside governed profile",
                ));
            }
            reader.i32()?;
            true
        }
        API_OFFSET_FOR_LEADER_EPOCH => {
            validate_offset_for_leader_epoch(policy, &mut reader)?;
            true
        }
        API_SASL_AUTHENTICATE => {
            reader.bytes_field(false)?;
            true
        }
        _ => {
            return Err(KafkaViolation::protocol(
                "Kafka API is outside governed profile",
            ));
        }
    };
    reader.finish("request")?;
    Ok(expects_response)
}

/// 业务作用：解析 Produce topic/partition records，拒绝 transactional id 并识别 `acks=0` 单向请求。
///
/// 参数说明：
/// - `policy`：提供 topic ACL
/// - `version`：是 0..8
/// - `reader`：指向 body 起点。
///
/// 返回：返回是否期待 response；ACL/事务/结构违规返回错误。
fn validate_produce(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<bool, KafkaViolation> {
    if version >= 3 && reader.string(policy.max_group_bytes, true)?.is_some() {
        return Err(KafkaViolation::unauthorized(
            "transactional produce is outside governed profile",
        ));
    }
    let acks = reader.i16()?;
    if !matches!(acks, -1..=1) {
        return Err(KafkaViolation::malformed("Produce acks is invalid"));
    }
    reader.i32()?;
    let topic_count = required_array(reader, "Produce topics")?;
    for _ in 0..topic_count {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        let partitions = required_array(reader, "Produce partitions")?;
        for _ in 0..partitions {
            reader.i32()?;
            let records = reader.bytes_field(true)?;
            if version >= 3 {
                validate_non_transactional_record_set(records)?;
            }
        }
    }
    Ok(acks != 0)
}

/// 业务作用：检查 Produce v3+ RECORDS 中每个 RecordBatch 的事务/控制位，阻止绕过 null transactional id。
///
/// 参数说明：
/// - `records`：是单 partition 的 nullable record set，frame 总门已限制其字节规模。
///
/// 返回：空 record set 或全部 magic=2 非事务数据 batch 成功；截断、旧格式、事务/控制 batch 拒绝。
fn validate_non_transactional_record_set(
    records: Option<&[u8]>,
) -> std::result::Result<(), KafkaViolation> {
    let Some(records) = records else {
        return Ok(());
    };
    let mut position = 0_usize;
    while position < records.len() {
        let header_end = position
            .checked_add(23)
            .ok_or_else(|| KafkaViolation::malformed("Kafka RecordBatch cursor overflows"))?;
        if header_end > records.len() {
            return Err(KafkaViolation::malformed(
                "Kafka RecordBatch header is truncated",
            ));
        }
        let batch_length = i32::from_be_bytes(
            records[position + 8..position + 12]
                .try_into()
                .expect("four-byte RecordBatch length"),
        );
        if batch_length < 49 {
            return Err(KafkaViolation::malformed(
                "Kafka RecordBatch length is below the fixed header",
            ));
        }
        let batch_end = position
            .checked_add(12)
            .and_then(|value| value.checked_add(batch_length as usize))
            .ok_or_else(|| KafkaViolation::malformed("Kafka RecordBatch length overflows"))?;
        if batch_end > records.len() {
            return Err(KafkaViolation::malformed(
                "Kafka RecordBatch body is truncated",
            ));
        }
        if records[position + 16] != 2 {
            return Err(KafkaViolation::protocol(
                "Produce v3+ requires RecordBatch magic 2 in governed profile",
            ));
        }
        let attributes = i16::from_be_bytes(
            records[position + 21..position + 23]
                .try_into()
                .expect("two-byte RecordBatch attributes"),
        );
        if attributes & 0x10 != 0 {
            return Err(KafkaViolation::unauthorized(
                "transactional RecordBatch is outside governed profile",
            ));
        }
        if attributes & 0x20 != 0 {
            return Err(KafkaViolation::unauthorized(
                "control RecordBatch is outside governed profile",
            ));
        }
        position = batch_end;
    }
    Ok(())
}

/// 业务作用：解析 consumer Fetch v4..11 的 topic/partition 与 incremental-session 遗忘列表。
///
/// 参数说明：
/// - `policy`：提供 topic ACL
/// - `version`：是受支持版本
/// - `reader`：指向 body。
///
/// 返回：consumer replica_id 与全部 topic 合法时成功；broker replication/越权/结构错误时拒绝。
fn validate_fetch(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    if reader.i32()? != -1 {
        return Err(KafkaViolation::unauthorized(
            "broker replica Fetch is outside governed profile",
        ));
    }
    reader.i32()?;
    reader.i32()?;
    reader.i32()?;
    reader.i8()?;
    if version >= 7 {
        reader.i32()?;
        reader.i32()?;
    }
    let topics = required_array(reader, "Fetch topics")?;
    for _ in 0..topics {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        let partitions = required_array(reader, "Fetch partitions")?;
        for _ in 0..partitions {
            reader.i32()?;
            if version >= 9 {
                reader.i32()?;
            }
            reader.i64()?;
            if version >= 5 {
                reader.i64()?;
            }
            reader.i32()?;
        }
    }
    if version >= 7 {
        let forgotten = required_array_allow_empty(reader, "Fetch forgotten topics")?;
        for _ in 0..forgotten {
            let topic = required_topic(policy, reader)?;
            authorize_topic(policy, topic)?;
            read_i32_array(reader, true)?;
        }
    }
    if version >= 11 {
        required_string(reader, 1024, "Fetch rack id")?;
    }
    Ok(())
}

/// 业务作用：解析 consumer ListOffsets 并对每个 topic 执行 ACL，拒绝 broker replica 查询。
///
/// 参数说明：
/// - `policy`：提供 topic ACL
/// - `version`：是 1..5
/// - `reader`：指向 body。
///
/// 返回：结构与 ACL 合法成功，否则拒绝。
fn validate_list_offsets(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    if reader.i32()? != -1 {
        return Err(KafkaViolation::unauthorized(
            "broker replica ListOffsets is outside governed profile",
        ));
    }
    if version >= 2 {
        reader.i8()?;
    }
    let topics = required_array(reader, "ListOffsets topics")?;
    for _ in 0..topics {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        let partitions = required_array(reader, "ListOffsets partitions")?;
        for _ in 0..partitions {
            reader.i32()?;
            if version >= 4 {
                reader.i32()?;
            }
            reader.i64()?;
            if version == 1 {
                // v1 已移除 v0 的 max_num_offsets，不再消费额外字段。
            }
        }
    }
    Ok(())
}

/// 业务作用：限制 Metadata 只能显式查询一个或多个授权 topic，禁止 null/空列表枚举整个集群。
///
/// 参数说明：
/// - `policy`：提供 topic ACL
/// - `version`：是 0..8
/// - `reader`：指向 body。
///
/// 返回：显式 topic 全部授权时成功；全量枚举、越权或结构错误时拒绝。
fn validate_metadata_request(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let topics = reader.array_len(true)?.ok_or_else(|| {
        KafkaViolation::unauthorized("Metadata all-topics request is outside governed profile")
    })?;
    if topics == 0 {
        return Err(KafkaViolation::unauthorized(
            "Metadata empty all-topics request is outside governed profile",
        ));
    }
    for _ in 0..topics {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
    }
    if version >= 4 {
        reader.boolean()?;
    }
    if version >= 8 {
        reader.boolean()?;
        reader.boolean()?;
    }
    Ok(())
}

/// 业务作用：解析 OffsetCommit group 与 topic partitions，统一执行 group/topic ACL。
///
/// 参数说明：
/// - `policy`：提供 ACL
/// - `version`：是 2..7
/// - `reader`：指向 body。
///
/// 返回：全部标识授权且 schema 完整时成功。
fn validate_offset_commit(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    reader.i32()?;
    required_string(reader, 1024, "OffsetCommit member id")?;
    if version == 7 {
        reader.string(1024, true)?;
    }
    if version <= 4 {
        reader.i64()?;
    }
    let topics = required_array(reader, "OffsetCommit topics")?;
    for _ in 0..topics {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        let partitions = required_array(reader, "OffsetCommit partitions")?;
        for _ in 0..partitions {
            reader.i32()?;
            reader.i64()?;
            if version >= 6 {
                reader.i32()?;
            }
            reader.string(4096, true)?;
        }
    }
    Ok(())
}

/// 业务作用：解析 OffsetFetch group 与显式 topic 列表，禁止 null 全 topic 查询。
///
/// 参数说明：
/// - `policy`：提供 ACL
/// - `reader`：指向 v2..5 body。
///
/// 返回：group/topic 全部授权成功；全量枚举、越权或坏结构拒绝。
fn validate_offset_fetch(
    policy: &KafkaPolicy,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    let topics = reader.array_len(true)?.ok_or_else(|| {
        KafkaViolation::unauthorized("OffsetFetch all-topics request is outside governed profile")
    })?;
    if topics == 0 {
        return Err(KafkaViolation::unauthorized(
            "OffsetFetch empty all-topics request is outside governed profile",
        ));
    }
    for _ in 0..topics {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        read_i32_array(reader, true)?;
    }
    Ok(())
}

/// 业务作用：只允许查找授权 consumer group coordinator，拒绝 transaction/share coordinator。
///
/// 参数说明：
/// - `policy`：提供 group ACL
/// - `version`：是 0..2
/// - `reader`：指向 body。
///
/// 返回：group key 授权且 coordinator type=group 时成功。
fn validate_find_coordinator(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    if version >= 1 && reader.i8()? != 0 {
        return Err(KafkaViolation::unauthorized(
            "non-group coordinator is outside governed profile",
        ));
    }
    Ok(())
}

/// 业务作用：解析 JoinGroup 的 group、成员、protocol 与 opaque metadata，限制数组和字节总量。
///
/// 参数说明：
/// - `policy`：提供 group ACL
/// - `version`：是 1..5
/// - `reader`：指向 body。
///
/// 返回：group 授权且 schema 完整成功；不解释 consumer protocol metadata。
fn validate_join_group(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    reader.i32()?;
    reader.i32()?;
    required_string(reader, 1024, "JoinGroup member id")?;
    if version >= 5 {
        reader.string(1024, true)?;
    }
    required_string(reader, 128, "JoinGroup protocol type")?;
    let protocols = required_array(reader, "JoinGroup protocols")?;
    for _ in 0..protocols {
        required_string(reader, 128, "JoinGroup protocol name")?;
        reader.bytes_field(false)?;
    }
    Ok(())
}

/// 业务作用：解析 Heartbeat group/member 字段并在 broker 前执行 group ACL。
///
/// 参数说明：
/// - `policy`：提供 group ACL
/// - `version`：是 0..3
/// - `reader`：指向 body。
///
/// 返回：授权且 schema 完整成功。
fn validate_heartbeat(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    reader.i32()?;
    required_string(reader, 1024, "Heartbeat member id")?;
    if version >= 3 {
        reader.string(1024, true)?;
    }
    Ok(())
}

/// 业务作用：解析 LeaveGroup 的旧单成员与 v3 多成员结构并执行 group ACL。
///
/// 参数说明：
/// - `policy`：提供 group ACL
/// - `version`：是 0..3
/// - `reader`：指向 body。
///
/// 返回：授权且成员数组有界时成功。
fn validate_leave_group(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    if version <= 2 {
        required_string(reader, 1024, "LeaveGroup member id")?;
    } else {
        let members = required_array(reader, "LeaveGroup members")?;
        for _ in 0..members {
            required_string(reader, 1024, "LeaveGroup member id")?;
            reader.string(1024, true)?;
        }
    }
    Ok(())
}

/// 业务作用：解析 SyncGroup assignment envelope 并在转发前执行 group ACL。
///
/// 参数说明：
/// - `policy`：提供 group ACL
/// - `version`：是 0..3
/// - `reader`：指向 body。
///
/// 返回：授权且 assignment 数组/bytes 在 frame 总门内时成功。
fn validate_sync_group(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let group = required_group(policy, reader)?;
    authorize_group(policy, group)?;
    reader.i32()?;
    required_string(reader, 1024, "SyncGroup member id")?;
    if version >= 3 {
        reader.string(1024, true)?;
    }
    let assignments = required_array_allow_empty(reader, "SyncGroup assignments")?;
    for _ in 0..assignments {
        required_string(reader, 1024, "SyncGroup assignment member id")?;
        reader.bytes_field(false)?;
    }
    Ok(())
}

/// 业务作用：解析 DescribeGroups 的显式 group 列表，禁止空列表绕过精确 ACL。
///
/// 参数说明：
/// - `policy`：提供 group ACL
/// - `version`：是 0..4
/// - `reader`：指向 body。
///
/// 返回：至少一个 group 且全部授权时成功。
fn validate_describe_groups(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    let groups = required_array(reader, "DescribeGroups groups")?;
    for _ in 0..groups {
        let group = required_group(policy, reader)?;
        authorize_group(policy, group)?;
    }
    if version >= 3 {
        reader.boolean()?;
    }
    Ok(())
}

/// 业务作用：解析 consumer OffsetForLeaderEpoch v3 的显式 topic/partition epoch。
///
/// 参数说明：
/// - `policy`：提供 topic ACL
/// - `reader`：指向 body。
///
/// 返回：consumer replica_id=-1 且全部 topic 授权成功，否则拒绝。
fn validate_offset_for_leader_epoch(
    policy: &KafkaPolicy,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    if reader.i32()? != -1 {
        return Err(KafkaViolation::unauthorized(
            "broker OffsetForLeaderEpoch is outside governed profile",
        ));
    }
    let topics = required_array(reader, "OffsetForLeaderEpoch topics")?;
    for _ in 0..topics {
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        let partitions = required_array(reader, "OffsetForLeaderEpoch partitions")?;
        for _ in 0..partitions {
            reader.i32()?;
            reader.i32()?;
            reader.i32()?;
        }
    }
    Ok(())
}

/// 业务作用：读取必须存在且非空的 legacy STRING。
///
/// 参数说明：
/// - `reader`：是 cursor
/// - `maximum`：是字节上限
/// - `name`：是低基数诊断名。
///
/// 返回：合法非空字符串；null/空/坏编码返回 Malformed。
fn required_string<'a>(
    reader: &mut KafkaReader<'a>,
    maximum: usize,
    name: &str,
) -> std::result::Result<&'a str, KafkaViolation> {
    let value = reader
        .string(maximum, false)?
        .ok_or_else(|| KafkaViolation::malformed(format!("Kafka {name} is null")))?;
    if value.is_empty() {
        return Err(KafkaViolation::malformed(format!("Kafka {name} is empty")));
    }
    Ok(value)
}

/// 业务作用：读取必须存在且非空的 flexible COMPACT_STRING。
///
/// 参数说明：
/// - `reader`：是 cursor
/// - `maximum`：是字节上限
/// - `name`：是低基数诊断名。
///
/// 返回：合法非空字符串；null/空/坏编码返回 Malformed。
fn required_compact_string<'a>(
    reader: &mut KafkaReader<'a>,
    maximum: usize,
    name: &str,
) -> std::result::Result<&'a str, KafkaViolation> {
    let value = reader
        .compact_string(maximum, false)?
        .ok_or_else(|| KafkaViolation::malformed(format!("Kafka {name} is null")))?;
    if value.is_empty() {
        return Err(KafkaViolation::malformed(format!("Kafka {name} is empty")));
    }
    Ok(value)
}

/// 业务作用：读取并校验 Kafka topic 名的协议字符与长度边界。
///
/// 参数说明：
/// - `policy`：提供最大长度
/// - `reader`：指向 STRING。
///
/// 返回：合法 topic 借用；坏字符、`.`/`..` 或空值返回 Malformed。
fn required_topic<'a>(
    policy: &KafkaPolicy,
    reader: &mut KafkaReader<'a>,
) -> std::result::Result<&'a str, KafkaViolation> {
    let topic = required_string(reader, policy.max_topic_bytes, "topic")?;
    if topic == "."
        || topic == ".."
        || !topic
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KafkaViolation::malformed("Kafka topic name is invalid"));
    }
    Ok(topic)
}

/// 业务作用：读取有界非空 consumer group id 并拒绝控制字符。
///
/// 参数说明：
/// - `policy`：提供最大长度
/// - `reader`：指向 STRING。
///
/// 返回：合法 group 借用；空值或控制字符返回 Malformed。
fn required_group<'a>(
    policy: &KafkaPolicy,
    reader: &mut KafkaReader<'a>,
) -> std::result::Result<&'a str, KafkaViolation> {
    let group = required_string(reader, policy.max_group_bytes, "group id")?;
    if group.chars().any(char::is_control) {
        return Err(KafkaViolation::malformed("Kafka group id is invalid"));
    }
    Ok(group)
}

/// 业务作用：执行 topic 精确 ACL，集中保持错误文本与指标低基数。
///
/// 参数说明：
/// - `policy`：是治理计划
/// - `topic`：已通过语法门。
///
/// 返回：命中成功；否则 NotAuthorized。
fn authorize_topic(policy: &KafkaPolicy, topic: &str) -> std::result::Result<(), KafkaViolation> {
    if policy.allows_topic(topic) {
        Ok(())
    } else {
        Err(KafkaViolation::unauthorized(
            "Kafka topic is not authorized",
        ))
    }
}

/// 业务作用：执行 consumer group 精确 ACL，集中保持错误文本与指标低基数。
///
/// 参数说明：
/// - `policy`：是治理计划
/// - `group`：已通过语法门。
///
/// 返回：命中成功；否则 NotAuthorized。
fn authorize_group(policy: &KafkaPolicy, group: &str) -> std::result::Result<(), KafkaViolation> {
    if policy.allows_group(group) {
        Ok(())
    } else {
        Err(KafkaViolation::unauthorized(
            "Kafka group is not authorized",
        ))
    }
}

/// 业务作用：读取必须非空的 legacy ARRAY，供 topic/group 等请求主体使用。
///
/// 参数说明：
/// - `reader`：是 cursor
/// - `name`：是低基数诊断名。
///
/// 返回：非零长度；null/空返回 Malformed/NotAuthorized 上层语义。
fn required_array(
    reader: &mut KafkaReader<'_>,
    name: &str,
) -> std::result::Result<usize, KafkaViolation> {
    let length = reader
        .array_len(false)?
        .ok_or_else(|| KafkaViolation::malformed(format!("Kafka {name} is null")))?;
    if length == 0 {
        return Err(KafkaViolation::malformed(format!("Kafka {name} is empty")));
    }
    Ok(length)
}

/// 业务作用：读取允许为空但不允许 null 的 legacy ARRAY。
///
/// 参数说明：
/// - `reader`：是 cursor
/// - `name`：是低基数诊断名。
///
/// 返回：合法长度（可为零）；null/坏长度返回 Malformed。
fn required_array_allow_empty(
    reader: &mut KafkaReader<'_>,
    name: &str,
) -> std::result::Result<usize, KafkaViolation> {
    reader
        .array_len(false)?
        .ok_or_else(|| KafkaViolation::malformed(format!("Kafka {name} is null")))
}

/// 业务作用：跳过有界 INT32 ARRAY，用于 partition index/replica/isr 列表。
///
/// 参数说明：
/// - `reader`：是 cursor
/// - `allow_empty`：决定零项是否合法。
///
/// 返回：合法数组成功；null/超限/截断或不允许的空数组返回错误。
fn read_i32_array(
    reader: &mut KafkaReader<'_>,
    allow_empty: bool,
) -> std::result::Result<(), KafkaViolation> {
    let length = reader
        .array_len(false)?
        .ok_or_else(|| KafkaViolation::malformed("Kafka INT32 array is null"))?;
    if length == 0 && !allow_empty {
        return Err(KafkaViolation::malformed("Kafka INT32 array is empty"));
    }
    for _ in 0..length {
        reader.i32()?;
    }
    Ok(())
}

/// 业务作用：重写 ApiVersions response，使 broker 宣告范围与治理 parser 支持矩阵求交。
///
/// 参数说明：
/// - `frame`：是 broker response
/// - `body_start`：跳过 correlation/header tags
/// - `version`：是 request 版本
/// - `max_array_items`：是数组硬门。
///
/// 返回：保留 broker error/throttle、过滤并收窄 API 列表的新 frame；坏 schema 返回错误。
fn rewrite_api_versions(
    frame: KafkaFrame,
    body_start: usize,
    version: i16,
    max_array_items: usize,
) -> std::result::Result<KafkaFrame, KafkaViolation> {
    let mut reader = KafkaReader::new(&frame.wire[body_start..], max_array_items);
    let error_code = reader.i16()?;
    let flexible = version >= 3;
    let count = if flexible {
        let encoded = reader.uvarint()?;
        if encoded == 0 {
            return Err(KafkaViolation::malformed("ApiVersions api_keys is null"));
        }
        let count = (encoded - 1) as usize;
        if count > max_array_items {
            return Err(KafkaViolation::resource(
                "ApiVersions api_keys exceeds max_array_items",
            ));
        }
        count
    } else {
        reader
            .array_len(false)?
            .ok_or_else(|| KafkaViolation::malformed("ApiVersions api_keys is null"))?
    };
    let mut intersected = Vec::new();
    for _ in 0..count {
        let api_key = reader.i16()?;
        let broker_min = reader.i16()?;
        let broker_max = reader.i16()?;
        if broker_min > broker_max {
            return Err(KafkaViolation::malformed(
                "ApiVersions broker range is inverted",
            ));
        }
        if flexible {
            reader.tagged_fields()?;
        }
        if let Some((proxy_min, proxy_max)) = supported_api(api_key) {
            let minimum = broker_min.max(proxy_min);
            let maximum = broker_max.min(proxy_max);
            if minimum <= maximum {
                intersected.push((api_key, minimum, maximum));
            }
        }
    }
    let throttle = if version >= 1 {
        Some(reader.i32()?)
    } else {
        None
    };
    if flexible {
        reader.tagged_fields()?;
    }
    reader.finish("ApiVersions response")?;

    let mut payload = frame.wire[4..body_start].to_vec();
    payload.extend_from_slice(&error_code.to_be_bytes());
    if flexible {
        write_uvarint(&mut payload, intersected.len() as u32 + 1);
    } else {
        payload.extend_from_slice(&(intersected.len() as i32).to_be_bytes());
    }
    for (api_key, minimum, maximum) in intersected {
        payload.extend_from_slice(&api_key.to_be_bytes());
        payload.extend_from_slice(&minimum.to_be_bytes());
        payload.extend_from_slice(&maximum.to_be_bytes());
        if flexible {
            payload.push(0);
        }
    }
    if let Some(throttle) = throttle {
        payload.extend_from_slice(&throttle.to_be_bytes());
    }
    if flexible {
        payload.push(0);
    }
    KafkaFrame::from_payload(payload)
}

/// 业务作用：校验 Metadata response topic/partition schema，并改写每个 broker endpoint。
///
/// 参数说明：
/// - `policy`：提供 ACL/rewrite
/// - `frame`：是 broker wire
/// - `body_start`：是 body 偏移
/// - `version`：是 Metadata v0..8。
///
/// 返回：所有 endpoint 均有映射且 response topic 未越权时返回重写 frame；否则失败闭合。
fn rewrite_metadata(
    policy: &KafkaPolicy,
    frame: KafkaFrame,
    body_start: usize,
    version: i16,
) -> std::result::Result<KafkaFrame, KafkaViolation> {
    let body = &frame.wire[body_start..];
    let mut reader = KafkaReader::new(body, policy.max_array_items);
    let mut prefix = Vec::new();
    if version >= 3 {
        prefix.extend_from_slice(&reader.i32()?.to_be_bytes());
    }
    let brokers = required_array_allow_empty(&mut reader, "Metadata brokers")?;
    prefix.extend_from_slice(&(brokers as i32).to_be_bytes());
    for _ in 0..brokers {
        let node_id = reader.i32()?;
        let host = required_string(&mut reader, 255, "Metadata broker host")?.to_owned();
        let port = reader.i32()?;
        let rack = if version >= 1 {
            reader.string(1024, true)?.map(str::to_owned)
        } else {
            None
        };
        let endpoint = policy.rewrite_endpoint(&host, port).ok_or_else(|| {
            KafkaViolation::protocol("Metadata broker endpoint has no rewrite mapping")
        })?;
        prefix.extend_from_slice(&node_id.to_be_bytes());
        write_string(&mut prefix, endpoint.host.as_ref())?;
        prefix.extend_from_slice(&i32::from(endpoint.port).to_be_bytes());
        if version >= 1 {
            write_nullable_string(&mut prefix, rack.as_deref())?;
        }
    }
    let tail_start = reader.position;
    validate_metadata_tail(policy, version, &mut reader)?;
    reader.finish("Metadata response")?;
    let mut payload = frame.wire[4..body_start].to_vec();
    payload.extend_from_slice(&prefix);
    payload.extend_from_slice(&body[tail_start..]);
    KafkaFrame::from_payload(payload)
}

/// 业务作用：完整校验 Metadata v0..8 除 broker 列表外的 cluster/topic/partition 尾部。
///
/// 参数说明：
/// - `policy`：提供 topic ACL/数组门
/// - `version`：是 response 版本
/// - `reader`：已位于 broker 后。
///
/// 返回：结构完整且所有 response topic 均获授权成功；否则拒绝。
fn validate_metadata_tail(
    policy: &KafkaPolicy,
    version: i16,
    reader: &mut KafkaReader<'_>,
) -> std::result::Result<(), KafkaViolation> {
    if version == 1 {
        reader.i32()?;
    } else if version >= 2 {
        reader.string(1024, true)?;
        reader.i32()?;
    }
    let topics = required_array_allow_empty(reader, "Metadata response topics")?;
    for _ in 0..topics {
        reader.i16()?;
        let topic = required_topic(policy, reader)?;
        authorize_topic(policy, topic)?;
        if version >= 1 {
            reader.boolean()?;
        }
        let partitions = required_array_allow_empty(reader, "Metadata response partitions")?;
        for _ in 0..partitions {
            reader.i16()?;
            reader.i32()?;
            reader.i32()?;
            if version >= 7 {
                reader.i32()?;
            }
            read_i32_array(reader, true)?;
            read_i32_array(reader, true)?;
            if version >= 5 {
                read_i32_array(reader, true)?;
            }
        }
        if version >= 8 {
            reader.i32()?;
        }
    }
    if version >= 8 {
        reader.i32()?;
    }
    Ok(())
}

/// 业务作用：保留 FindCoordinator error 语义并只在成功时改写 coordinator endpoint。
///
/// 参数说明：
/// - `policy`：提供 endpoint 表
/// - `frame`：是 broker wire
/// - `body_start`：是 body 偏移
/// - `version`：是 v0..2。
///
/// 返回：失败 error 原样通过；成功 endpoint 有映射时返回重写 frame；缺映射或坏 schema 拒绝。
fn rewrite_find_coordinator(
    policy: &KafkaPolicy,
    frame: KafkaFrame,
    body_start: usize,
    version: i16,
) -> std::result::Result<KafkaFrame, KafkaViolation> {
    let mut reader = KafkaReader::new(&frame.wire[body_start..], policy.max_array_items);
    let throttle = if version >= 1 {
        Some(reader.i32()?)
    } else {
        None
    };
    let error_code = reader.i16()?;
    let error_message = if version >= 1 {
        reader.string(4096, true)?.map(str::to_owned)
    } else {
        None
    };
    let node_id = reader.i32()?;
    let host = reader
        .string(255, false)?
        .ok_or_else(|| KafkaViolation::malformed("Kafka FindCoordinator host is null"))?
        .to_owned();
    let port = reader.i32()?;
    reader.finish("FindCoordinator response")?;
    if error_code != 0 {
        return Ok(frame);
    }
    if host.is_empty() {
        return Err(KafkaViolation::malformed(
            "Kafka successful FindCoordinator response has an empty host",
        ));
    }
    let endpoint = policy.rewrite_endpoint(&host, port).ok_or_else(|| {
        KafkaViolation::protocol("FindCoordinator endpoint has no rewrite mapping")
    })?;
    let mut payload = frame.wire[4..body_start].to_vec();
    if let Some(throttle) = throttle {
        payload.extend_from_slice(&throttle.to_be_bytes());
    }
    payload.extend_from_slice(&error_code.to_be_bytes());
    if version >= 1 {
        write_nullable_string(&mut payload, error_message.as_deref())?;
    }
    payload.extend_from_slice(&node_id.to_be_bytes());
    write_string(&mut payload, endpoint.host.as_ref())?;
    payload.extend_from_slice(&i32::from(endpoint.port).to_be_bytes());
    KafkaFrame::from_payload(payload)
}

/// 业务作用：解析 SaslHandshake error/mechanism 列表，供 framed SASL 阶段推进使用。
///
/// 参数说明：
/// - `body`：不含 response header
/// - `max_array_items`：是列表硬门。
///
/// 返回：schema 完整时返回 broker error code；错误内容保持原字节由上层转发。
fn parse_sasl_handshake_response(
    body: &[u8],
    max_array_items: usize,
) -> std::result::Result<i16, KafkaViolation> {
    let mut reader = KafkaReader::new(body, max_array_items);
    let error = reader.i16()?;
    let mechanisms = required_array_allow_empty(&mut reader, "SASL mechanisms")?;
    for _ in 0..mechanisms {
        required_string(&mut reader, 64, "SASL mechanism")?;
    }
    reader.finish("SaslHandshake response")?;
    Ok(error)
}

/// 业务作用：解析 SaslAuthenticate v0/v1 error 与 opaque auth bytes，支持 broker session lifetime re-auth。
///
/// 参数说明：
/// - `body`：不含 response header
/// - `version`：是 0/1
/// - `max_array_items`：仅供统一 reader 门。
///
/// 返回：schema 完整时返回 broker error code；凭据/token 不记录、不解释、不改写。
fn parse_sasl_authenticate_response(
    body: &[u8],
    version: i16,
    max_array_items: usize,
) -> std::result::Result<i16, KafkaViolation> {
    let mut reader = KafkaReader::new(body, max_array_items);
    let error = reader.i16()?;
    reader.string(4096, true)?;
    reader.bytes_field(false)?;
    if version >= 1 {
        reader.i64()?;
    }
    reader.finish("SaslAuthenticate response")?;
    Ok(error)
}

/// 业务作用：编码 canonical Kafka unsigned varint，供 flexible ApiVersions response 重建。
///
/// 参数说明：
/// - `output`：是目标 buffer
/// - `value`：是非负 u32。
///
/// 返回：无；追加 1..5 字节最短编码。
fn write_uvarint(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// 业务作用：编码 legacy Kafka STRING，供 endpoint rewrite 重建 response。
///
/// 参数说明：
/// - `output`：是目标 buffer
/// - `value`：是 UTF-8 host/rack/error 文本。
///
/// 返回：长度可表示为 i16 时成功；过长返回资源错误。
fn write_string(output: &mut Vec<u8>, value: &str) -> std::result::Result<(), KafkaViolation> {
    let length = i16::try_from(value.len())
        .map_err(|_| KafkaViolation::resource("Kafka rewritten STRING exceeds i16"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

/// 业务作用：编码 legacy Kafka NULLABLE_STRING，保留 broker 的 null/error/rack 语义。
///
/// 参数说明：
/// - `output`：是目标 buffer
/// - `value`：是可选字符串。
///
/// 返回：None 写 -1；Some 复用 STRING 编码；过长返回资源错误。
fn write_nullable_string(
    output: &mut Vec<u8>,
    value: Option<&str>,
) -> std::result::Result<(), KafkaViolation> {
    match value {
        Some(value) => write_string(output, value),
        None => {
            output.extend_from_slice(&(-1_i16).to_be_bytes());
            Ok(())
        }
    }
}

/// 业务作用：代理一条 Kafka 连接，双向逐 frame 校验并共享 correlation/SASL 状态。
///
/// 参数说明：
/// - `downstream`：是 client stream
/// - `upstream`：是已连接 broker stream
/// - `policy`：是 listener 计划。
///
/// 返回：任一方向 EOF 时取消另一方向并返回累计量；协议/I/O 失败返回真实对端与累计量。
pub async fn proxy<D, U>(
    downstream: D,
    upstream: U,
    policy: Arc<KafkaPolicy>,
) -> std::result::Result<KafkaProxyReport, KafkaProxyError>
where
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut downstream_read, mut downstream_write) = tokio::io::split(downstream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let session = Arc::new(Mutex::new(KafkaSession::new(policy.clone())));
    let report = Arc::new(Mutex::new(KafkaProxyReport::default()));
    let client_session = session.clone();
    let broker_session = session;
    let client_report = report.clone();
    let broker_report = report.clone();
    let client_policy = policy.clone();
    let broker_policy = policy;

    let client_to_broker = async move {
        loop {
            let frame = match read_frame(
                &mut downstream_read,
                client_policy.max_frame_bytes,
                client_policy.frame_timeout_ms,
            )
            .await
            {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(()),
                Err(error) => return Err((KafkaPeer::Client, error)),
            };
            if let Err(error) = client_session.lock().validate_request(&frame) {
                return Err((KafkaPeer::Client, error));
            }
            if let Err(error) = upstream_write.write_all(&frame.wire).await {
                return Err((
                    KafkaPeer::Broker,
                    KafkaViolation::protocol(format!("Kafka broker write failed: {error}")),
                ));
            }
            let mut report = client_report.lock();
            report.downstream_to_upstream_bytes = report
                .downstream_to_upstream_bytes
                .saturating_add(frame.wire.len() as u64);
            report.downstream_to_upstream_frames =
                report.downstream_to_upstream_frames.saturating_add(1);
        }
    };

    let broker_to_client = async move {
        loop {
            let frame = match read_frame(
                &mut upstream_read,
                broker_policy.max_frame_bytes,
                broker_policy.frame_timeout_ms,
            )
            .await
            {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(()),
                Err(error) => return Err((KafkaPeer::Broker, error)),
            };
            let frame = match broker_session.lock().validate_response(frame) {
                Ok(frame) => frame,
                Err(error) => return Err((KafkaPeer::Broker, error)),
            };
            if let Err(error) = downstream_write.write_all(&frame.wire).await {
                return Err((
                    KafkaPeer::Client,
                    KafkaViolation::protocol(format!("Kafka client write failed: {error}")),
                ));
            }
            let mut report = broker_report.lock();
            report.upstream_to_downstream_bytes = report
                .upstream_to_downstream_bytes
                .saturating_add(frame.wire.len() as u64);
            report.upstream_to_downstream_frames =
                report.upstream_to_downstream_frames.saturating_add(1);
        }
    };

    let outcome = tokio::select! {
        result = client_to_broker => result,
        result = broker_to_client => result,
    };
    match outcome {
        Ok(()) => Ok(*report.lock()),
        Err((peer, violation)) => Err(KafkaProxyError {
            kind: violation.kind,
            peer,
            message: violation.message,
            report: *report.lock(),
        }),
    }
}
