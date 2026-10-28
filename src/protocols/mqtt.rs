//! MQTT 3.1.1/5.0 受限协议治理。
//!
//! 模块只在 `mqtt-governance` feature 中编译。它不充当 broker，不伪造 ACK，
//! 只在双向转发前校验 packet 边界、topic ACL 与 QoS/subscribe packet-id 状态。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::model::StreamMqttCfg;

const MAX_CONFIG_ACL_ITEMS: usize = 4_096;
const MAX_PACKET_BYTES_HARD: usize = 16 * 1024 * 1024;
const MAX_BUFFERED_BYTES_HARD: usize = 512 * 1024 * 1024;
const MAX_SUBSCRIPTIONS_HARD: usize = 1_000_000;

/// 构建期编译的 MQTT listener 治理计划。
#[derive(Debug)]
pub struct MqttPolicy {
    max_connections: usize,
    max_packet_bytes: usize,
    packet_timeout_ms: u64,
    max_buffered_bytes: usize,
    max_topic_bytes: usize,
    max_subscriptions: usize,
    max_inflight_messages: usize,
    client_id_allow: HashSet<Arc<str>>,
    publish_topic_allow: Vec<TopicFilter>,
    subscribe_topic_allow: Vec<TopicFilter>,
}

impl MqttPolicy {
    /// 业务作用：在快照发布前编译 MQTT ACL 与资源硬门，避免数据面重复解析配置。
    ///
    /// 参数说明：
    /// - `cfg`：是 listener 级 MQTT profile。
    ///
    /// 返回：配置和 topic filter 全部合法时返回只读计划；越界或歧义 ACL 返回错误。
    pub fn build(cfg: &StreamMqttCfg) -> Result<Self> {
        anyhow::ensure!(
            (1..=65_536).contains(&cfg.max_connections),
            "max_connections must be within 1..=65536"
        );
        anyhow::ensure!(
            (16..=MAX_PACKET_BYTES_HARD).contains(&cfg.max_packet_bytes),
            "max_packet_bytes must be within 16..={MAX_PACKET_BYTES_HARD}"
        );
        anyhow::ensure!(
            (100..=60_000).contains(&cfg.packet_timeout_ms),
            "packet_timeout_ms must be within 100..=60000"
        );
        let per_connection_buffers = cfg
            .max_packet_bytes
            .checked_mul(2)
            .context("max_packet_bytes bidirectional reservation overflow")?;
        let required_buffers = cfg
            .max_connections
            .checked_mul(per_connection_buffers)
            .context("MQTT aggregate buffer reservation overflow")?;
        anyhow::ensure!(
            (1024 * 1024..=MAX_BUFFERED_BYTES_HARD).contains(&cfg.max_buffered_bytes),
            "max_buffered_bytes must be within 1048576..={MAX_BUFFERED_BYTES_HARD}"
        );
        anyhow::ensure!(
            required_buffers <= cfg.max_buffered_bytes,
            "max_connections * max_packet_bytes * 2 must not exceed max_buffered_bytes"
        );
        anyhow::ensure!(
            (1..=65_535).contains(&cfg.max_topic_bytes)
                && cfg.max_topic_bytes <= cfg.max_packet_bytes,
            "max_topic_bytes must be within 1..=65535 and not exceed max_packet_bytes"
        );
        anyhow::ensure!(
            (1..=MAX_SUBSCRIPTIONS_HARD).contains(&cfg.max_subscriptions),
            "max_subscriptions must be within 1..={MAX_SUBSCRIPTIONS_HARD}"
        );
        let maximum_topic_state = cfg
            .max_subscriptions
            .checked_mul(cfg.max_topic_bytes)
            .context("MQTT subscription state reservation overflow")?;
        anyhow::ensure!(
            maximum_topic_state <= cfg.max_buffered_bytes,
            "max_subscriptions * max_topic_bytes must not exceed max_buffered_bytes"
        );
        anyhow::ensure!(
            (1..=65_535).contains(&cfg.max_inflight_messages),
            "max_inflight_messages must be within 1..=65535"
        );
        for (name, values) in [
            ("client_id_allow", &cfg.client_id_allow),
            ("publish_topic_allow", &cfg.publish_topic_allow),
            ("subscribe_topic_allow", &cfg.subscribe_topic_allow),
        ] {
            anyhow::ensure!(
                values.len() <= MAX_CONFIG_ACL_ITEMS,
                "{name} exceeds {MAX_CONFIG_ACL_ITEMS} items"
            );
        }

        let mut client_id_allow = HashSet::with_capacity(cfg.client_id_allow.len());
        for client_id in &cfg.client_id_allow {
            validate_mqtt_utf8(client_id, 256).context("client_id_allow")?;
            anyhow::ensure!(
                !client_id.is_empty(),
                "client_id_allow contains an empty id"
            );
            anyhow::ensure!(
                client_id_allow.insert(Arc::from(client_id.as_str())),
                "client_id_allow contains duplicate `{client_id}`"
            );
        }
        let publish_topic_allow = compile_topic_filters(
            "publish_topic_allow",
            &cfg.publish_topic_allow,
            cfg.max_topic_bytes,
        )?;
        let subscribe_topic_allow = compile_topic_filters(
            "subscribe_topic_allow",
            &cfg.subscribe_topic_allow,
            cfg.max_topic_bytes,
        )?;
        Ok(Self {
            max_connections: cfg.max_connections,
            max_packet_bytes: cfg.max_packet_bytes,
            packet_timeout_ms: cfg.packet_timeout_ms,
            max_buffered_bytes: cfg.max_buffered_bytes,
            max_topic_bytes: cfg.max_topic_bytes,
            max_subscriptions: cfg.max_subscriptions,
            max_inflight_messages: cfg.max_inflight_messages,
            client_id_allow,
            publish_topic_allow,
            subscribe_topic_allow,
        })
    }

    /// 业务作用：向 listener 级 RAII 预算暴露快照当前的连接硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该 profile 允许的并发 MQTT 连接数。
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// 业务作用：向 listener 常驻预算暴露每连接双向 packet buffer 的悲观预留值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`max_packet_bytes * 2`；建连前一次预留，任务退出时归还。
    pub fn connection_buffer_reservation(&self) -> usize {
        self.max_packet_bytes * 2
    }

    /// 业务作用：向 listener 常驻预算暴露当前快照允许的聚合 packet buffer 硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该 profile 的 `max_buffered_bytes`。
    pub fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    /// 业务作用：在建立上游连接前执行 client id 精确 ACL。
    ///
    /// 参数说明：
    /// - `client_id`：是 CONNECT 中已校验的 UTF-8 标识。
    ///
    /// 返回：允许集为空或精确命中时返回 true。
    pub fn allows_client_id(&self, client_id: &str) -> bool {
        self.client_id_allow.is_empty() || self.client_id_allow.contains(client_id)
    }

    /// 业务作用：用编译后 Topic Filter 判定 client PUBLISH 的具体 Topic Name。
    ///
    /// 参数说明：
    /// - `topic`：是 PUBLISH 中的非空 topic name。
    ///
    /// 返回：任一 publish allow filter 命中时返回 true；空 ACL 固定拒绝。
    fn allows_publish(&self, topic: &str) -> bool {
        self.publish_topic_allow
            .iter()
            .any(|filter| filter.matches_topic(topic))
    }

    /// 业务作用：保证 client 请求的 Topic Filter 不比任一配置 ACL 更宽。
    ///
    /// 参数说明：
    /// - `filter`：是 SUBSCRIBE/UNSUBSCRIBE 的已校验 filter。
    ///
    /// 返回：请求 filter 的匹配集被某条 allow filter 覆盖时返回 true。
    fn allows_subscription(&self, filter: &TopicFilter) -> bool {
        self.subscribe_topic_allow
            .iter()
            .any(|allowed| allowed.covers(filter))
    }
}

/// MQTT 协议违规的固定低基数分类。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MqttViolationKind {
    Malformed,
    Protocol,
    NotAuthorized,
    PacketTooLarge,
    ResourceLimit,
}

/// 违规或 IO 失败所在的固定连接一侧。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MqttPeer {
    Client,
    Broker,
}

impl fmt::Display for MqttViolationKind {
    /// 业务作用：把固定违规类型转成可观测的低基数标签。
    ///
    /// 参数说明：
    /// - `formatter`：接收分类文本。
    ///
    /// 返回：写入成功或 formatter 错误。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed",
            Self::Protocol => "protocol",
            Self::NotAuthorized => "not_authorized",
            Self::PacketTooLarge => "packet_too_large",
            Self::ResourceLimit => "resource_limit",
        })
    }
}

/// 一次 MQTT 双向治理的完成统计。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MqttProxyReport {
    pub downstream_to_upstream_bytes: u64,
    pub upstream_to_downstream_bytes: u64,
    pub downstream_to_upstream_packets: u64,
    pub upstream_to_downstream_packets: u64,
}

/// 双向会话因协议或资源门禁终止。
#[derive(Debug)]
pub struct MqttProxyError {
    kind: MqttViolationKind,
    peer: MqttPeer,
    detail: String,
    report: MqttProxyReport,
}

impl MqttProxyError {
    /// 业务作用：向数据面暴露固定违规类型，避免把 topic/client id 写入 metrics label。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本次终止的低基数分类。
    pub fn kind(&self) -> MqttViolationKind {
        self.kind
    }

    /// 业务作用：区分 client 违规与 broker 协议失败，避免客户攻击污染上游被动健康。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：首个失败 packet/read/write 的来源一侧。
    pub fn peer(&self) -> MqttPeer {
        self.peer
    }

    /// 业务作用：保留违规前已成功转发的字节/包统计。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：断连前的双向统计快照。
    pub fn report(&self) -> MqttProxyReport {
        self.report
    }
}

impl fmt::Display for MqttProxyError {
    /// 业务作用：为结构化 stream 日志提供不含 payload 的错误摘要。
    ///
    /// 参数说明：
    /// - `formatter`：接收固定类型和安全细节。
    ///
    /// 返回：写入成功或 formatter 错误。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for MqttProxyError {}

/// 业务作用：在 CONNECT 已经上游回放后，对其余 MQTT packet 执行双向有界治理与转发。
///
/// 参数说明：
/// - `downstream`：是已建立的字节流
/// - `upstream`：是已建立的字节流
/// - `protocol_level`：只接受 MQTT 3.1.1(4) 或 5.0(5)
/// - `policy`：是快照编译的 listener 计划。
///
/// 返回：任一方 EOF/DISCONNECT 时返回已转发统计；读写失败、ACL、状态或资源越界时
/// 返回带分类和部分统计的错误，调用方应终止双向会话。
pub async fn proxy<D, U>(
    downstream: D,
    upstream: U,
    protocol_level: u8,
    policy: Arc<MqttPolicy>,
) -> std::result::Result<MqttProxyReport, MqttProxyError>
where
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    if !matches!(protocol_level, 4 | 5) {
        return Err(MqttProxyError {
            kind: MqttViolationKind::Protocol,
            peer: MqttPeer::Client,
            detail: "governance supports MQTT protocol level 4 or 5".to_string(),
            report: MqttProxyReport::default(),
        });
    }
    let state = Arc::new(Mutex::new(MqttSession::new(protocol_level, policy.clone())));
    let counters = Arc::new(RelayCounters::default());
    let (downstream_read, downstream_write) = io::split(downstream);
    let (upstream_read, upstream_write) = io::split(upstream);
    let client_to_broker = relay_direction(
        downstream_read,
        upstream_write,
        Direction::ClientToBroker,
        state.clone(),
        policy.clone(),
        counters.clone(),
    );
    let broker_to_client = relay_direction(
        upstream_read,
        downstream_write,
        Direction::BrokerToClient,
        state,
        policy,
        counters.clone(),
    );
    tokio::pin!(client_to_broker);
    tokio::pin!(broker_to_client);
    let outcome = tokio::select! {
        result = &mut client_to_broker => result,
        result = &mut broker_to_client => result,
    };
    let report = counters.report();
    match outcome {
        Ok(()) => Ok(report),
        Err(error) => Err(MqttProxyError {
            kind: error.violation.kind,
            peer: error.peer,
            detail: error.violation.detail,
            report,
        }),
    }
}

#[derive(Default)]
struct RelayCounters {
    downstream_bytes: AtomicU64,
    upstream_bytes: AtomicU64,
    downstream_packets: AtomicU64,
    upstream_packets: AtomicU64,
}

impl RelayCounters {
    /// 业务作用：在任一方终止时形成一致的弱一致会话统计快照。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已成功 `write_all` 的双向 packet 和 wire 字节数。
    fn report(&self) -> MqttProxyReport {
        MqttProxyReport {
            downstream_to_upstream_bytes: self.downstream_bytes.load(Ordering::Relaxed),
            upstream_to_downstream_bytes: self.upstream_bytes.load(Ordering::Relaxed),
            downstream_to_upstream_packets: self.downstream_packets.load(Ordering::Relaxed),
            upstream_to_downstream_packets: self.upstream_packets.load(Ordering::Relaxed),
        }
    }
}

/// 业务作用：按 packet 边界读取、校验并转发一个方向，使反向任务可独立推进。
///
/// 参数说明：
/// - `reader`：该方向的数据来源半流。
/// - `writer`：该方向的数据目标半流。
/// - `direction`：决定允许 control packet 类型的转发方向。
/// - `state`：已建立的 MQTT 会话状态。
/// - `policy`：当前快照固定的协议安全门。
/// - `counters`：当前方向实际消息与字节计数。
///
/// 返回：EOF 或合法 DISCONNECT 返回成功；首个违规或 IO 错误终止该方向并返回错误。
async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    state: Arc<Mutex<MqttSession>>,
    policy: Arc<MqttPolicy>,
    counters: Arc<RelayCounters>,
) -> std::result::Result<(), RelayFailure>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(packet) = read_packet(
            &mut reader,
            policy.max_packet_bytes,
            policy.packet_timeout_ms,
        )
        .await
        .map_err(|violation| RelayFailure {
            peer: direction.source_peer(),
            violation,
        })?
        else {
            let _ = writer.shutdown().await;
            return Ok(());
        };
        let action = state
            .lock()
            .validate(direction, &packet)
            .map_err(|violation| RelayFailure {
                peer: direction.source_peer(),
                violation,
            })?;
        writer
            .write_all(&packet.wire)
            .await
            .map_err(|error| RelayFailure {
                peer: direction.destination_peer(),
                violation: MqttViolation::protocol(format!("MQTT relay write failed: {error}")),
            })?;
        match direction {
            Direction::ClientToBroker => {
                counters
                    .downstream_bytes
                    .fetch_add(packet.wire.len() as u64, Ordering::Relaxed);
                counters.downstream_packets.fetch_add(1, Ordering::Relaxed);
            }
            Direction::BrokerToClient => {
                counters
                    .upstream_bytes
                    .fetch_add(packet.wire.len() as u64, Ordering::Relaxed);
                counters.upstream_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
        if action == RelayAction::Stop {
            let _ = writer.shutdown().await;
            return Ok(());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    ClientToBroker,
    BrokerToClient,
}

impl Direction {
    /// 业务作用：标记当前 relay reader 所属端，使读取/协议违规正确归因。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：ClientToBroker 对应 Client，反向对应 Broker。
    fn source_peer(self) -> MqttPeer {
        match self {
            Self::ClientToBroker => MqttPeer::Client,
            Self::BrokerToClient => MqttPeer::Broker,
        }
    }

    /// 业务作用：标记当前 relay writer 所属端，使写失败不被误算到 packet 来源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：ClientToBroker 对应 Broker，反向对应 Client。
    fn destination_peer(self) -> MqttPeer {
        match self {
            Self::ClientToBroker => MqttPeer::Broker,
            Self::BrokerToClient => MqttPeer::Client,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayAction {
    Continue,
    Stop,
}

#[derive(Debug)]
struct MqttPacket {
    packet_type: u8,
    flags: u8,
    header_len: usize,
    wire: Vec<u8>,
}

impl MqttPacket {
    /// 业务作用：只向 parser 暴露 Remaining Length 内的可信 packet body。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：fixed header 之后的 variable header + payload 切片。
    fn body(&self) -> &[u8] {
        &self.wire[self.header_len..]
    }
}

/// 业务作用：先解码并校验 Remaining Length，只在命中单包硬门后分配 body。
///
/// 参数说明：
/// - `reader`：是一个 MQTT 方向的字节流
/// - `max_packet_bytes`：包含 fixed header
/// - `packet_timeout_ms`：只从收到首字节后起算，不限制纯 idle 时间。
///
/// 返回：包边界完整时返回原始 wire；包起始前 EOF 返回 None；截断/非最短 VBI/超长返回违规。
async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_packet_bytes: usize,
    packet_timeout_ms: u64,
) -> std::result::Result<Option<MqttPacket>, MqttViolation> {
    let mut first = [0_u8; 1];
    let read = reader
        .read(&mut first)
        .await
        .map_err(|error| MqttViolation::protocol(format!("MQTT relay read failed: {error}")))?;
    if read == 0 {
        return Ok(None);
    }
    let read_tail = async {
        let packet_type = first[0] >> 4;
        if !(1..=15).contains(&packet_type) {
            return Err(MqttViolation::malformed("reserved packet type 0"));
        }
        let mut length_bytes = [0_u8; 4];
        let mut remaining = 0usize;
        let mut multiplier = 1usize;
        let mut encoded_len = 0usize;
        loop {
            if encoded_len == 4 {
                return Err(MqttViolation::malformed(
                    "Remaining Length exceeds four bytes",
                ));
            }
            reader
                .read_exact(&mut length_bytes[encoded_len..encoded_len + 1])
                .await
                .map_err(|_| MqttViolation::malformed("truncated Remaining Length"))?;
            let byte = length_bytes[encoded_len];
            remaining = remaining
                .checked_add(((byte & 0x7f) as usize).saturating_mul(multiplier))
                .ok_or_else(|| MqttViolation::malformed("Remaining Length overflow"))?;
            encoded_len += 1;
            if byte & 0x80 == 0 {
                break;
            }
            multiplier = multiplier.saturating_mul(128);
        }
        if mqtt_vbi_encoded_len(remaining) != encoded_len {
            return Err(MqttViolation::malformed(
                "Remaining Length is not minimally encoded",
            ));
        }
        let total = 1usize
            .checked_add(encoded_len)
            .and_then(|value| value.checked_add(remaining))
            .ok_or_else(|| MqttViolation::packet_too_large("packet length overflow"))?;
        if total > max_packet_bytes {
            return Err(MqttViolation::packet_too_large(format!(
                "packet requires {total} bytes, limit is {max_packet_bytes}"
            )));
        }
        let mut wire = Vec::with_capacity(total);
        wire.push(first[0]);
        wire.extend_from_slice(&length_bytes[..encoded_len]);
        wire.resize(total, 0);
        reader
            .read_exact(&mut wire[1 + encoded_len..])
            .await
            .map_err(|_| MqttViolation::malformed("truncated MQTT packet body"))?;
        Ok(MqttPacket {
            packet_type,
            flags: first[0] & 0x0f,
            header_len: 1 + encoded_len,
            wire,
        })
    };
    let packet = tokio::time::timeout(Duration::from_millis(packet_timeout_ms), read_tail)
        .await
        .map_err(|_| MqttViolation::resource_limit("MQTT packet read timeout"))??;
    Ok(Some(packet))
}

/// 业务作用：计算 MQTT Variable Byte Integer 的唯一最短 wire 长度。
///
/// 参数说明：
/// - `value`：是已解码的非负整数。
///
/// 返回：编码该值所需的 1–4 字节数。
fn mqtt_vbi_encoded_len(mut value: usize) -> usize {
    let mut bytes = 1;
    while value >= 128 {
        value /= 128;
        bytes += 1;
    }
    bytes
}

#[derive(Debug)]
struct MqttViolation {
    kind: MqttViolationKind,
    detail: String,
}

struct RelayFailure {
    peer: MqttPeer,
    violation: MqttViolation,
}

impl MqttViolation {
    /// 业务作用：把不可解码的 wire 归类为 Malformed Packet。
    ///
    /// 参数说明：
    /// - `detail`：是不含 payload 的固定原因。
    ///
    /// 返回：要求立即终止会话的 malformed 违规。
    fn malformed(detail: impl Into<String>) -> Self {
        Self {
            kind: MqttViolationKind::Malformed,
            detail: detail.into(),
        }
    }

    /// 业务作用：把方向、顺序或 packet-id 不变式破坏归类为 Protocol Error。
    ///
    /// 参数说明：
    /// - `detail`：是不含业务数据的错误摘要。
    ///
    /// 返回：要求终止双向会话的 protocol 违规。
    fn protocol(detail: impl Into<String>) -> Self {
        Self {
            kind: MqttViolationKind::Protocol,
            detail: detail.into(),
        }
    }

    /// 业务作用：把 client/topic ACL 拒绝与 malformed wire 分开观测。
    ///
    /// 参数说明：
    /// - `detail`：是不回显 topic 原文的拒绝原因。
    ///
    /// 返回：不向上游转发当前 packet 的 not-authorized 违规。
    fn not_authorized(detail: impl Into<String>) -> Self {
        Self {
            kind: MqttViolationKind::NotAuthorized,
            detail: detail.into(),
        }
    }

    /// 业务作用：在 body 分配前标记单包长度硬门越界。
    ///
    /// 参数说明：
    /// - `detail`：记录声明长度和配置上限。
    ///
    /// 返回：不分配 packet body 的 packet-too-large 违规。
    fn packet_too_large(detail: impl Into<String>) -> Self {
        Self {
            kind: MqttViolationKind::PacketTooLarge,
            detail: detail.into(),
        }
    }

    /// 业务作用：标记订阅或在途 packet-id 集合已达 profile 硬门。
    ///
    /// 参数说明：
    /// - `detail`：仅包含固定资源类型和数值。
    ///
    /// 返回：不接收新状态的 resource-limit 违规。
    fn resource_limit(detail: impl Into<String>) -> Self {
        Self {
            kind: MqttViolationKind::ResourceLimit,
            detail: detail.into(),
        }
    }
}

#[derive(Debug)]
struct MqttSession {
    protocol_level: u8,
    phase: SessionPhase,
    policy: Arc<MqttPolicy>,
    subscriptions: HashSet<String>,
    client_publish: HashMap<u16, PublishFlow>,
    broker_publish: HashMap<u16, PublishFlow>,
    pending_subscribe: HashMap<u16, Vec<String>>,
    pending_unsubscribe: HashMap<u16, Vec<String>>,
}

impl MqttSession {
    /// 业务作用：从已转发 CONNECT 的边界启动单连接状态，第一个 broker packet 必须是 CONNACK/AUTH。
    ///
    /// 参数说明：
    /// - `protocol_level`：固定 4/5 解析差异
    /// - `policy`：保持资源与 ACL 不变式。
    ///
    /// 返回：空订阅、空在途集合与 AwaitConnack 状态。
    fn new(protocol_level: u8, policy: Arc<MqttPolicy>) -> Self {
        Self {
            protocol_level,
            phase: SessionPhase::AwaitConnack,
            policy,
            subscriptions: HashSet::new(),
            client_publish: HashMap::new(),
            broker_publish: HashMap::new(),
            pending_subscribe: HashMap::new(),
            pending_unsubscribe: HashMap::new(),
        }
    }

    /// 业务作用：在转发前执行 packet 方向、顺序、ACL 和 packet-id 状态迁移。
    ///
    /// 参数说明：
    /// - `direction`：表示 packet 来源
    /// - `packet`：是已通过长度硬门的完整 wire。
    ///
    /// 返回：合法 packet 返回继续/转发后断开；违规时不推进后续转发。
    fn validate(
        &mut self,
        direction: Direction,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        validate_fixed_flags(packet)?;
        self.validate_direction_and_phase(direction, packet.packet_type)?;
        match packet.packet_type {
            2 => self.handle_connack(packet),
            3 => self.handle_publish(direction, packet),
            4..=7 => self.handle_publish_ack(direction, packet),
            8 => self.handle_subscribe(packet),
            9 => self.handle_suback(packet),
            10 => self.handle_unsubscribe(packet),
            11 => self.handle_unsuback(packet),
            12 | 13 => {
                ensure_empty_body(packet, "PING")?;
                Ok(RelayAction::Continue)
            }
            14 => {
                validate_disconnect_or_auth(self.protocol_level, packet)?;
                Ok(RelayAction::Stop)
            }
            15 => {
                validate_disconnect_or_auth(self.protocol_level, packet)?;
                Ok(RelayAction::Continue)
            }
            _ => Err(MqttViolation::protocol(
                "CONNECT or reserved control packet appeared after preread",
            )),
        }
    }

    /// 业务作用：限制 client/broker 各自可发送的 packet 集，并保证 CONNACK 之前不接收业务流量。
    ///
    /// 参数说明：
    /// - `direction`：是来源
    /// - `packet_type`：是 fixed-header 高四位。
    ///
    /// 返回：方向和会话阶段合法时成功，否则 protocol error。
    fn validate_direction_and_phase(
        &self,
        direction: Direction,
        packet_type: u8,
    ) -> std::result::Result<(), MqttViolation> {
        let direction_ok = match direction {
            Direction::ClientToBroker => matches!(packet_type, 3..=8 | 10 | 12 | 14 | 15),
            Direction::BrokerToClient => matches!(packet_type, 2..=7 | 9 | 11 | 13..=15),
        };
        if !direction_ok {
            return Err(MqttViolation::protocol(
                "control packet is not allowed in this direction",
            ));
        }
        match self.phase {
            SessionPhase::AwaitConnack => match (direction, packet_type) {
                (Direction::BrokerToClient, 2 | 15) | (Direction::ClientToBroker, 15) => Ok(()),
                _ => Err(MqttViolation::protocol(
                    "application packet arrived before successful CONNACK",
                )),
            },
            SessionPhase::Connected if packet_type == 2 => {
                Err(MqttViolation::protocol("duplicate CONNACK"))
            }
            SessionPhase::Connected => Ok(()),
        }
    }

    /// 业务作用：校验 broker 建连结果并只在成功后开放业务 packet。
    ///
    /// 参数说明：
    /// - `packet`：是 broker 的 CONNACK。
    ///
    /// 返回：成功原因码进入 Connected；拒绝原因码在转发后终止会话。
    fn handle_connack(
        &mut self,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let body = packet.body();
        if body.len() < 2 {
            return Err(MqttViolation::malformed("CONNACK body is truncated"));
        }
        if body[0] & 0xfe != 0 {
            return Err(MqttViolation::malformed("CONNACK flags are invalid"));
        }
        if body[0] & 0x01 != 0 {
            // 治理 profile 只接受 Clean Session/Start；broker 若仍恢复旧会话，本地订阅与 QoS2
            // 状态将不完整，继续放行业务 packet 会让 packet-id 和资源硬门失真。
            return Err(MqttViolation::protocol(
                "CONNACK Session Present is incompatible with Clean Session/Start",
            ));
        }
        let reason = body[1];
        if self.protocol_level == 4 {
            if body.len() != 2 || reason > 5 {
                return Err(MqttViolation::malformed("invalid MQTT 3.1.1 CONNACK"));
            }
        } else {
            let mut cursor = 2;
            skip_properties(body, &mut cursor)?;
            ensure_consumed(body, cursor, "CONNACK")?;
            if !matches!(
                reason,
                0 | 0x80
                    | 0x81
                    | 0x82
                    | 0x83
                    | 0x84
                    | 0x85
                    | 0x86
                    | 0x87
                    | 0x88
                    | 0x89
                    | 0x8a
                    | 0x8c
                    | 0x90
                    | 0x95
                    | 0x97
                    | 0x99
                    | 0x9a
                    | 0x9c
                    | 0x9d
                    | 0x9f
            ) {
                return Err(MqttViolation::malformed(
                    "CONNACK contains invalid MQTT 5 reason code",
                ));
            }
        }
        if reason == 0 {
            self.phase = SessionPhase::Connected;
            Ok(RelayAction::Continue)
        } else {
            Ok(RelayAction::Stop)
        }
    }

    /// 业务作用：对 client publish 执行 topic ACL，并为双向 QoS1/2 创建有界 ACK 状态。
    ///
    /// 参数说明：
    /// - `direction`：标识 publish 发起方
    /// - `packet`：含 topic/QoS/packet id。
    ///
    /// 返回：QoS0 直接继续；QoS1/2 成功预留 packet id 后继续；ACL/重复 id/预算失败则拒绝。
    fn handle_publish(
        &mut self,
        direction: Direction,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let parsed = parse_publish(self.protocol_level, packet, self.policy.max_topic_bytes)?;
        if direction == Direction::ClientToBroker && !self.policy.allows_publish(parsed.topic) {
            return Err(MqttViolation::not_authorized(
                "PUBLISH topic is outside publish_topic_allow",
            ));
        }
        let Some(packet_id) = parsed.packet_id else {
            return Ok(RelayAction::Continue);
        };
        let flow = if parsed.qos == 1 {
            PublishFlow::Puback
        } else {
            PublishFlow::Pubrec
        };
        let identifier_used = match direction {
            Direction::ClientToBroker => self.client_identifier_in_use(packet_id),
            Direction::BrokerToClient => self.broker_publish.contains_key(&packet_id),
        };
        let existing = match direction {
            Direction::ClientToBroker => self.client_publish.get(&packet_id),
            Direction::BrokerToClient => self.broker_publish.get(&packet_id),
        };
        if let Some(existing) = existing {
            if parsed.dup && *existing == flow {
                return Ok(RelayAction::Continue);
            }
            return Err(MqttViolation::protocol(
                "PUBLISH Packet Identifier is in use",
            ));
        }
        if identifier_used {
            return Err(MqttViolation::protocol(
                "Packet Identifier is already used by another client exchange",
            ));
        }
        self.ensure_inflight_capacity(1)?;
        let flows = match direction {
            Direction::ClientToBroker => &mut self.client_publish,
            Direction::BrokerToClient => &mut self.broker_publish,
        };
        flows.insert(packet_id, flow);
        Ok(RelayAction::Continue)
    }

    /// 业务作用：校验 PUBACK/PUBREC/PUBREL/PUBCOMP 与原 publish 方向、packet id 和 QoS 阶段一致。
    ///
    /// 参数说明：
    /// - `direction`：是 ACK 发送方
    /// - `packet`：是一枚 QoS control packet。
    ///
    /// 返回：合法迁移或终态释放 packet id 后继续；未知/错序 ACK 断开会话。
    fn handle_publish_ack(
        &mut self,
        direction: Direction,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let parsed = parse_publish_ack(self.protocol_level, packet)?;
        let packet_id = parsed.packet_id;
        let origin = match (packet.packet_type, direction) {
            // PUBREL 由原 PUBLISH 发起方发送；其余 ACK 由接收方发送。方向选错会让
            // 合法 QoS2 在第三步被误断，或更糟地修改反向同 id 交换。
            (6, Direction::ClientToBroker) | (4 | 5 | 7, Direction::BrokerToClient) => {
                &mut self.client_publish
            }
            (6, Direction::BrokerToClient) | (4 | 5 | 7, Direction::ClientToBroker) => {
                &mut self.broker_publish
            }
            _ => unreachable!("publish ACK packet type is fixed by caller"),
        };
        let expected = match packet.packet_type {
            4 => PublishFlow::Puback,
            5 => PublishFlow::Pubrec,
            6 => PublishFlow::Pubrel,
            7 => PublishFlow::Pubcomp,
            _ => unreachable!("publish ACK packet type is fixed by caller"),
        };
        let Some(current) = origin.get_mut(&packet_id) else {
            return Err(MqttViolation::protocol(
                "QoS ACK Packet Identifier not found",
            ));
        };
        if packet.packet_type == 6 && *current == PublishFlow::Pubcomp {
            // QoS2 PUBREL 在 PUBCOMP 丢失后可重传；保留 AwaitPubcomp 并原样转发，不重复分配状态。
            return Ok(RelayAction::Continue);
        }
        if *current != expected {
            // 先拒绝错序 ACK，再保留原状态；否则攻击者可跳过 QoS2 阶段提前释放 id。
            return Err(MqttViolation::protocol(
                "QoS ACK arrived in the wrong stage",
            ));
        }
        match packet.packet_type {
            4 | 7 => {
                origin.remove(&packet_id);
            }
            5 if parsed.reason >= 0x80 => {
                // MQTT 5 PUBREC 失败原因终止 QoS2 交换，不得继续等待永远不会出现的 PUBREL。
                origin.remove(&packet_id);
            }
            5 => *current = PublishFlow::Pubrel,
            6 => *current = PublishFlow::Pubcomp,
            _ => unreachable!("publish ACK packet type is fixed by caller"),
        }
        Ok(RelayAction::Continue)
    }

    /// 业务作用：校验 SUBSCRIBE filter ACL/选项，并在 broker ACK 前预留订阅和 packet-id 预算。
    ///
    /// 参数说明：
    /// - `packet`：是 client SUBSCRIBE。
    ///
    /// 返回：合法且未越订阅/在途门时继续；超宽 filter、重复 id 或越界则拒绝。
    fn handle_subscribe(
        &mut self,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let (packet_id, filters) =
            parse_subscribe(self.protocol_level, packet, self.policy.max_topic_bytes)?;
        for filter in &filters {
            let compiled = TopicFilter::parse(filter, self.policy.max_topic_bytes)?;
            if !self.policy.allows_subscription(&compiled) {
                return Err(MqttViolation::not_authorized(
                    "SUBSCRIBE filter is broader than subscribe_topic_allow",
                ));
            }
        }
        if let Some(existing) = self.pending_subscribe.get(&packet_id) {
            if existing == &filters {
                return Ok(RelayAction::Continue);
            }
            return Err(MqttViolation::protocol(
                "SUBSCRIBE Packet Identifier is already pending",
            ));
        }
        if self.client_identifier_in_use(packet_id) {
            return Err(MqttViolation::protocol(
                "SUBSCRIBE Packet Identifier is already in use",
            ));
        }
        self.ensure_inflight_capacity(1)?;
        self.ensure_subscription_capacity(&filters)?;
        self.pending_subscribe.insert(packet_id, filters);
        Ok(RelayAction::Continue)
    }

    /// 业务作用：只在 broker SUBACK 成功原因码上发布订阅状态，失败项不占后续预算。
    ///
    /// 参数说明：
    /// - `packet`：是 broker SUBACK。
    ///
    /// 返回：ACK 数量与待定 filter 一致时提交成功项；未知 id/数量不一致则拒绝。
    fn handle_suback(
        &mut self,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let (packet_id, reasons) = parse_suback(self.protocol_level, packet)?;
        let Some(filters) = self.pending_subscribe.remove(&packet_id) else {
            return Err(MqttViolation::protocol(
                "SUBACK Packet Identifier not found",
            ));
        };
        if reasons.len() != filters.len() {
            return Err(MqttViolation::protocol(
                "SUBACK reason count does not match SUBSCRIBE filters",
            ));
        }
        for (filter, reason) in filters.into_iter().zip(reasons) {
            if reason <= 2 {
                self.subscriptions.insert(filter);
            }
        }
        Ok(RelayAction::Continue)
    }

    /// 业务作用：对 UNSUBSCRIBE 执行同一 subscribe ACL，并保留待 broker 确认的变更。
    ///
    /// 参数说明：
    /// - `packet`：是 client UNSUBSCRIBE。
    ///
    /// 返回：合法请求进入 pending；越权 filter、packet-id 冲突或在途超限则拒绝。
    fn handle_unsubscribe(
        &mut self,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let (packet_id, filters) =
            parse_unsubscribe(self.protocol_level, packet, self.policy.max_topic_bytes)?;
        for filter in &filters {
            let compiled = TopicFilter::parse(filter, self.policy.max_topic_bytes)?;
            if !self.policy.allows_subscription(&compiled) {
                return Err(MqttViolation::not_authorized(
                    "UNSUBSCRIBE filter is outside subscribe_topic_allow",
                ));
            }
        }
        if let Some(existing) = self.pending_unsubscribe.get(&packet_id) {
            if existing == &filters {
                return Ok(RelayAction::Continue);
            }
            return Err(MqttViolation::protocol(
                "UNSUBSCRIBE Packet Identifier is already pending",
            ));
        }
        if self.client_identifier_in_use(packet_id) {
            return Err(MqttViolation::protocol(
                "UNSUBSCRIBE Packet Identifier is already in use",
            ));
        }
        self.ensure_inflight_capacity(1)?;
        self.pending_unsubscribe.insert(packet_id, filters);
        Ok(RelayAction::Continue)
    }

    /// 业务作用：按 MQTT 版本处理 UNSUBACK，只移除 broker 成功确认的本地订阅。
    ///
    /// 参数说明：
    /// - `packet`：是 broker UNSUBACK。
    ///
    /// 返回：待定 id 与 reason 数量合法时提交移除；未知 id/畸形 ACK 则拒绝。
    fn handle_unsuback(
        &mut self,
        packet: &MqttPacket,
    ) -> std::result::Result<RelayAction, MqttViolation> {
        let (packet_id, reasons) = parse_unsuback(self.protocol_level, packet)?;
        let Some(filters) = self.pending_unsubscribe.remove(&packet_id) else {
            return Err(MqttViolation::protocol(
                "UNSUBACK Packet Identifier not found",
            ));
        };
        if self.protocol_level == 5 && reasons.len() != filters.len() {
            return Err(MqttViolation::protocol(
                "UNSUBACK reason count does not match UNSUBSCRIBE filters",
            ));
        }
        if self.protocol_level == 4 {
            for filter in filters {
                self.subscriptions.remove(&filter);
            }
        } else {
            for (filter, reason) in filters.into_iter().zip(reasons) {
                if reason < 0x80 {
                    self.subscriptions.remove(&filter);
                }
            }
        }
        Ok(RelayAction::Continue)
    }

    /// 业务作用：按 OASIS 统一 client Packet Identifier 集检查 publish/subscribe/unsubscribe 交换冲突。
    ///
    /// 参数说明：
    /// - `packet_id`：是 client 即将发送的非零 id。
    ///
    /// 返回：任一 client-originated 交换仍占用该 id 时返回 true。
    fn client_identifier_in_use(&self, packet_id: u16) -> bool {
        self.client_publish.contains_key(&packet_id)
            || self.pending_subscribe.contains_key(&packet_id)
            || self.pending_unsubscribe.contains_key(&packet_id)
    }

    /// 业务作用：在新建 packet-id 状态前执行双向聚合在途硬门。
    ///
    /// 参数说明：
    /// - `additional`：是本 packet 将新增的交换数。
    ///
    /// 返回：总量不超 `max_inflight_messages` 时成功，否则不改变状态并拒绝。
    fn ensure_inflight_capacity(
        &self,
        additional: usize,
    ) -> std::result::Result<(), MqttViolation> {
        let current = self
            .client_publish
            .len()
            .saturating_add(self.broker_publish.len())
            .saturating_add(self.pending_subscribe.len())
            .saturating_add(self.pending_unsubscribe.len());
        if current.saturating_add(additional) > self.policy.max_inflight_messages {
            return Err(MqttViolation::resource_limit(format!(
                "inflight exchanges exceed {}",
                self.policy.max_inflight_messages
            )));
        }
        Ok(())
    }

    /// 业务作用：把已生效与所有 pending SUBSCRIBE 去重后一起纳入订阅硬门。
    ///
    /// 参数说明：
    /// - `requested`：是新 SUBSCRIBE 中的 filter 列表。
    ///
    /// 返回：联合集未越 `max_subscriptions` 时成功，否则不预留 packet id。
    fn ensure_subscription_capacity(
        &self,
        requested: &[String],
    ) -> std::result::Result<(), MqttViolation> {
        let mut all = self.subscriptions.clone();
        for pending in self.pending_subscribe.values() {
            all.extend(pending.iter().cloned());
        }
        all.extend(requested.iter().cloned());
        if all.len() > self.policy.max_subscriptions {
            return Err(MqttViolation::resource_limit(format!(
                "subscriptions exceed {}",
                self.policy.max_subscriptions
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionPhase {
    AwaitConnack,
    Connected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishFlow {
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
}

struct ParsedPublish<'a> {
    topic: &'a str,
    packet_id: Option<u16>,
    qos: u8,
    dup: bool,
}

struct ParsedPublishAck {
    packet_id: u16,
    reason: u8,
}

/// 业务作用：校验非 PUBLISH control packet 的保留 fixed-header flags，防止违规包绕过状态分支。
///
/// 参数说明：
/// - `packet`：是已解出 type/flags 的完整 packet。
///
/// 返回：flags 符合 control packet 固定值时成功；保留位非法时 malformed。
fn validate_fixed_flags(packet: &MqttPacket) -> std::result::Result<(), MqttViolation> {
    if packet.packet_type == 3 {
        return Ok(());
    }
    let expected = match packet.packet_type {
        6 | 8 | 10 => 0x02,
        _ => 0x00,
    };
    if packet.flags != expected {
        return Err(MqttViolation::malformed(
            "reserved fixed-header flags are invalid",
        ));
    }
    Ok(())
}

/// 业务作用：解析 PUBLISH topic/QoS/id，不读取或复制业务 payload。
///
/// 参数说明：
/// - `protocol_level`：决定是否跳过 v5 properties
/// - `packet`：是 PUBLISH
/// - `max_topic_bytes`：是 profile 上限。
///
/// 返回：合法 topic、QoS、DUP 与可选 packet id；空 topic alias、wildcard、QoS=3 或畸形字段则拒绝。
fn parse_publish<'a>(
    protocol_level: u8,
    packet: &'a MqttPacket,
    max_topic_bytes: usize,
) -> std::result::Result<ParsedPublish<'a>, MqttViolation> {
    let qos = (packet.flags >> 1) & 0x03;
    if qos == 3 || (qos == 0 && packet.flags & 0x08 != 0) {
        return Err(MqttViolation::malformed("invalid PUBLISH QoS/DUP flags"));
    }
    let mut cursor = 0;
    let topic = parse_utf8(packet.body(), &mut cursor, max_topic_bytes, "PUBLISH topic")?;
    if topic.is_empty() || topic.contains(['+', '#']) {
        return Err(MqttViolation::malformed(
            "PUBLISH topic must be non-empty and contain no wildcard",
        ));
    }
    let packet_id = if qos > 0 {
        Some(parse_packet_id(packet.body(), &mut cursor)?)
    } else {
        None
    };
    if protocol_level == 5 {
        skip_properties(packet.body(), &mut cursor)?;
    }
    Ok(ParsedPublish {
        topic,
        packet_id,
        qos,
        dup: packet.flags & 0x08 != 0,
    })
}

/// 业务作用：解析 QoS ACK 的 packet id 与 v5 可选 reason/properties，拒绝隐藏尾随字节。
///
/// 参数说明：
/// - `protocol_level`：区分 v3.1.1/v5 body
/// - `packet`：是 PUBACK/PUBREC/PUBREL/PUBCOMP。
///
/// 返回：非零 packet id 与经 packet type 白名单验证的 reason；长度、reason 或 properties 非法时 malformed。
fn parse_publish_ack(
    protocol_level: u8,
    packet: &MqttPacket,
) -> std::result::Result<ParsedPublishAck, MqttViolation> {
    let body = packet.body();
    let mut cursor = 0;
    let packet_id = parse_packet_id(body, &mut cursor)?;
    if protocol_level == 4 {
        ensure_consumed(body, cursor, "QoS ACK")?;
        return Ok(ParsedPublishAck {
            packet_id,
            reason: 0,
        });
    }
    let mut reason = 0;
    if cursor < body.len() {
        reason = body[cursor];
        cursor += 1;
        if cursor < body.len() {
            skip_properties(body, &mut cursor)?;
        }
    }
    ensure_consumed(body, cursor, "QoS ACK")?;
    let valid_reason = match packet.packet_type {
        4 | 5 => matches!(
            reason,
            0 | 0x10 | 0x80 | 0x83 | 0x87 | 0x90 | 0x91 | 0x97 | 0x99
        ),
        6 | 7 => matches!(reason, 0 | 0x92),
        _ => false,
    };
    if !valid_reason {
        return Err(MqttViolation::malformed(
            "QoS ACK contains invalid MQTT 5 reason code",
        ));
    }
    Ok(ParsedPublishAck {
        packet_id,
        reason,
    })
}

/// 业务作用：解析 SUBSCRIBE 的统一 packet id、v5 properties 和至少一个带选项 filter。
///
/// 参数说明：
/// - `protocol_level`：区分选项规则
/// - `packet`：是 SUBSCRIBE
/// - `max_topic_bytes`：限制 filter。
///
/// 返回：非零 id 与 filter 原文列表；空 payload、非法 filter/选项时 malformed。
fn parse_subscribe(
    protocol_level: u8,
    packet: &MqttPacket,
    max_topic_bytes: usize,
) -> std::result::Result<(u16, Vec<String>), MqttViolation> {
    let body = packet.body();
    let mut cursor = 0;
    let packet_id = parse_packet_id(body, &mut cursor)?;
    if protocol_level == 5 {
        skip_properties(body, &mut cursor)?;
    }
    let mut filters = Vec::new();
    while cursor < body.len() {
        let filter = parse_utf8(body, &mut cursor, max_topic_bytes, "SUBSCRIBE filter")?;
        TopicFilter::parse(filter, max_topic_bytes)?;
        let options = *body
            .get(cursor)
            .ok_or_else(|| MqttViolation::malformed("SUBSCRIBE options are missing"))?;
        cursor += 1;
        let valid = if protocol_level == 4 {
            options <= 2
        } else {
            options & 0xc0 == 0 && options & 0x03 <= 2 && (options >> 4) & 0x03 <= 2
        };
        if !valid {
            return Err(MqttViolation::malformed("SUBSCRIBE options are invalid"));
        }
        filters.push(filter.to_string());
    }
    if filters.is_empty() {
        return Err(MqttViolation::malformed("SUBSCRIBE payload is empty"));
    }
    Ok((packet_id, filters))
}

/// 业务作用：解析 SUBACK 中与 filter 一一对应的固定 reason 列表。
///
/// 参数说明：
/// - `protocol_level`：决定 properties 是否存在
/// - `packet`：是 SUBACK。
///
/// 返回：packet id 和非空 reason 列表；未定义成功码/截断时 malformed。
fn parse_suback(
    protocol_level: u8,
    packet: &MqttPacket,
) -> std::result::Result<(u16, Vec<u8>), MqttViolation> {
    let body = packet.body();
    let mut cursor = 0;
    let packet_id = parse_packet_id(body, &mut cursor)?;
    if protocol_level == 5 {
        skip_properties(body, &mut cursor)?;
    }
    if cursor >= body.len() {
        return Err(MqttViolation::malformed("SUBACK reasons are empty"));
    }
    let reasons = body[cursor..].to_vec();
    let valid = reasons.iter().all(|reason| {
        if protocol_level == 4 {
            matches!(*reason, 0 | 1 | 2 | 0x80)
        } else {
            matches!(
                *reason,
                0 | 1 | 2 | 0x80 | 0x83 | 0x87 | 0x8f | 0x91 | 0x97 | 0x9e | 0xa1 | 0xa2
            )
        }
    });
    if !valid {
        return Err(MqttViolation::malformed(
            "SUBACK contains invalid reason code",
        ));
    }
    Ok((packet_id, reasons))
}

/// 业务作用：解析 UNSUBSCRIBE 的 packet id 和非空 filter 列表。
///
/// 参数说明：
/// - `protocol_level`：决定 properties 区段
/// - `packet`：是 UNSUBSCRIBE
/// - `max_topic_bytes`：限制 filter。
///
/// 返回：非零 id 和已校验 filter；空/畸形 payload 时 malformed。
fn parse_unsubscribe(
    protocol_level: u8,
    packet: &MqttPacket,
    max_topic_bytes: usize,
) -> std::result::Result<(u16, Vec<String>), MqttViolation> {
    let body = packet.body();
    let mut cursor = 0;
    let packet_id = parse_packet_id(body, &mut cursor)?;
    if protocol_level == 5 {
        skip_properties(body, &mut cursor)?;
    }
    let mut filters = Vec::new();
    while cursor < body.len() {
        let filter = parse_utf8(body, &mut cursor, max_topic_bytes, "UNSUBSCRIBE filter")?;
        TopicFilter::parse(filter, max_topic_bytes)?;
        filters.push(filter.to_string());
    }
    if filters.is_empty() {
        return Err(MqttViolation::malformed("UNSUBSCRIBE payload is empty"));
    }
    Ok((packet_id, filters))
}

/// 业务作用：区分 v3.1.1 空 UNSUBACK 与 v5 带 properties/reasons 的确认。
///
/// 参数说明：
/// - `protocol_level`：是 CONNECT 固定版本
/// - `packet`：是 UNSUBACK。
///
/// 返回：packet id 和 v5 reason 列表；v3.1.1 返回空 reason；尾随字节非法时 malformed。
fn parse_unsuback(
    protocol_level: u8,
    packet: &MqttPacket,
) -> std::result::Result<(u16, Vec<u8>), MqttViolation> {
    let body = packet.body();
    let mut cursor = 0;
    let packet_id = parse_packet_id(body, &mut cursor)?;
    if protocol_level == 4 {
        ensure_consumed(body, cursor, "UNSUBACK")?;
        return Ok((packet_id, Vec::new()));
    }
    skip_properties(body, &mut cursor)?;
    let reasons = body[cursor..].to_vec();
    if reasons.is_empty() {
        return Err(MqttViolation::malformed("UNSUBACK reasons are empty"));
    }
    if !reasons
        .iter()
        .all(|reason| matches!(*reason, 0 | 0x11 | 0x80 | 0x83 | 0x87 | 0x8f | 0x91))
    {
        return Err(MqttViolation::malformed(
            "UNSUBACK contains invalid MQTT 5 reason code",
        ));
    }
    Ok((packet_id, reasons))
}

/// 业务作用：校验 DISCONNECT/AUTH 的版本差异和可选 reason/properties 边界。
///
/// 参数说明：
/// - `protocol_level`：是 4/5
/// - `packet`：是 DISCONNECT 或 AUTH。
///
/// 返回：版本内合法的空/可选 body 成功；v3.1.1 AUTH 或畸形 properties 拒绝。
fn validate_disconnect_or_auth(
    protocol_level: u8,
    packet: &MqttPacket,
) -> std::result::Result<(), MqttViolation> {
    if protocol_level == 4 {
        if packet.packet_type == 15 {
            return Err(MqttViolation::protocol("AUTH requires MQTT 5.0"));
        }
        return ensure_empty_body(packet, "DISCONNECT");
    }
    let body = packet.body();
    if body.is_empty() {
        return Ok(());
    }
    let reason = body[0];
    let reason_valid = if packet.packet_type == 15 {
        matches!(reason, 0 | 0x18 | 0x19)
    } else {
        matches!(
            reason,
            0 | 0x04
                | 0x80
                | 0x81
                | 0x82
                | 0x83
                | 0x87
                | 0x89
                | 0x8b
                | 0x8d
                | 0x8e
                | 0x8f
                | 0x90
                | 0x93
                | 0x94
                | 0x95
                | 0x96
                | 0x97
                | 0x98
                | 0x99
                | 0x9a
                | 0x9b
                | 0x9c
                | 0x9d
                | 0x9e
                | 0x9f
                | 0xa0
                | 0xa1
                | 0xa2
        )
    };
    if !reason_valid {
        return Err(MqttViolation::malformed(
            "DISCONNECT/AUTH contains invalid MQTT 5 reason code",
        ));
    }
    let mut cursor = 1;
    if cursor < body.len() {
        skip_properties(body, &mut cursor)?;
    }
    ensure_consumed(body, cursor, "DISCONNECT/AUTH")
}

/// 业务作用：解码 MQTT 非零两字节 Packet Identifier。
///
/// 参数说明：
/// - `body`：是 packet body
/// - `cursor`：指向 id 起始并在成功后前移。
///
/// 返回：1..=65535 id；截断或零值时 malformed。
fn parse_packet_id(body: &[u8], cursor: &mut usize) -> std::result::Result<u16, MqttViolation> {
    let end = cursor
        .checked_add(2)
        .ok_or_else(|| MqttViolation::malformed("Packet Identifier overflow"))?;
    let bytes = body
        .get(*cursor..end)
        .ok_or_else(|| MqttViolation::malformed("Packet Identifier is truncated"))?;
    *cursor = end;
    let packet_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    if packet_id == 0 {
        return Err(MqttViolation::malformed(
            "Packet Identifier must be non-zero",
        ));
    }
    Ok(packet_id)
}

/// 业务作用：有界解码 packet 内嵌 Variable Byte Integer，并拒绝非最短或越界表示。
///
/// 参数说明：
/// - `bytes`：是 packet body
/// - `cursor`：指向 VBI 并在成功后前移。
///
/// 返回：解码值；超四字节、截断或非最短时 malformed。
fn parse_vbi(bytes: &[u8], cursor: &mut usize) -> std::result::Result<usize, MqttViolation> {
    let start = *cursor;
    let mut value = 0usize;
    let mut multiplier = 1usize;
    for _ in 0..4 {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| MqttViolation::malformed("truncated Variable Byte Integer"))?;
        *cursor += 1;
        value = value
            .checked_add(((byte & 0x7f) as usize).saturating_mul(multiplier))
            .ok_or_else(|| MqttViolation::malformed("Variable Byte Integer overflow"))?;
        if byte & 0x80 == 0 {
            if mqtt_vbi_encoded_len(value) != *cursor - start {
                return Err(MqttViolation::malformed(
                    "Variable Byte Integer is not minimally encoded",
                ));
            }
            return Ok(value);
        }
        multiplier = multiplier.saturating_mul(128);
    }
    Err(MqttViolation::malformed(
        "Variable Byte Integer exceeds four bytes",
    ))
}

/// 业务作用：按声明长度跳过 MQTT 5 properties，不解释不参与治理的 property 值。
///
/// 参数说明：
/// - `body`：是 packet body
/// - `cursor`：指向 property length 并在成功后移到 payload。
///
/// 返回：整段 properties 在 packet 内时成功；声明越界时 malformed。
fn skip_properties(body: &[u8], cursor: &mut usize) -> std::result::Result<(), MqttViolation> {
    let length = parse_vbi(body, cursor)?;
    *cursor = cursor
        .checked_add(length)
        .ok_or_else(|| MqttViolation::malformed("properties length overflow"))?;
    if *cursor > body.len() {
        return Err(MqttViolation::malformed("properties exceed packet body"));
    }
    Ok(())
}

/// 业务作用：有界读取 MQTT UTF-8 string，统一执行长度和禁止 code point 门禁。
///
/// 参数说明：
/// - `body`：定位字符串
/// - `cursor`：定位字符串
/// - `max_bytes`：是业务上限
/// - `field`：用于安全错误摘要。
///
/// 返回：借用的合法 UTF-8；越界、非法 UTF-8 或 MQTT 禁止字符时 malformed。
fn parse_utf8<'a>(
    body: &'a [u8],
    cursor: &mut usize,
    max_bytes: usize,
    field: &str,
) -> std::result::Result<&'a str, MqttViolation> {
    let length_end = cursor
        .checked_add(2)
        .ok_or_else(|| MqttViolation::malformed(format!("{field} length overflow")))?;
    let length_bytes = body
        .get(*cursor..length_end)
        .ok_or_else(|| MqttViolation::malformed(format!("{field} length is truncated")))?;
    let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
    if length > max_bytes {
        return Err(MqttViolation::resource_limit(format!(
            "{field} exceeds {max_bytes} bytes"
        )));
    }
    let end = length_end
        .checked_add(length)
        .ok_or_else(|| MqttViolation::malformed(format!("{field} overflow")))?;
    let value = body
        .get(length_end..end)
        .ok_or_else(|| MqttViolation::malformed(format!("{field} is truncated")))?;
    *cursor = end;
    let value = std::str::from_utf8(value)
        .map_err(|_| MqttViolation::malformed(format!("{field} is not UTF-8")))?;
    validate_mqtt_utf8(value, max_bytes)
        .map_err(|_| MqttViolation::malformed(format!("{field} contains forbidden Unicode")))?;
    Ok(value)
}

/// 业务作用：统一执行 MQTT UTF-8 的 NUL、surrogate/non-character 与字节上限约束。
///
/// 参数说明：
/// - `value`：是 Rust 已验证 UTF-8
/// - `max_bytes`：是字段业务上限。
///
/// 返回：可安全用于 client/topic 判定时成功；含 MQTT 禁止 code point 或超长时返回错误。
fn validate_mqtt_utf8(value: &str, max_bytes: usize) -> Result<()> {
    anyhow::ensure!(
        value.len() <= max_bytes,
        "UTF-8 field exceeds {max_bytes} bytes"
    );
    anyhow::ensure!(
        !value.chars().any(|character| {
            character == '\0'
                || matches!(character as u32, 0xfdd0..=0xfdef)
                || character as u32 & 0xffff == 0xfffe
                || character as u32 & 0xffff == 0xffff
        }),
        "UTF-8 field contains an MQTT-forbidden code point"
    );
    Ok(())
}

/// 业务作用：拒绝本应无 body 的 control packet 携带隐藏字节。
///
/// 参数说明：
/// - `packet`：是 PING/DISCONNECT 等 packet
/// - `name`：用于错误摘要。
///
/// 返回：body 为空时成功，否则 malformed。
fn ensure_empty_body(packet: &MqttPacket, name: &str) -> std::result::Result<(), MqttViolation> {
    if packet.body().is_empty() {
        Ok(())
    } else {
        Err(MqttViolation::malformed(format!(
            "{name} packet body must be empty"
        )))
    }
}

/// 业务作用：保证 parser 已消费整个 packet body，不让多余字节绕过语义校验。
///
/// 参数说明：
/// - `body`：是 packet body
/// - `cursor`：是 parser 终点
/// - `name`：用于错误摘要。
///
/// 返回：cursor 精确等于 body 长度时成功，否则 malformed。
fn ensure_consumed(
    body: &[u8],
    cursor: usize,
    name: &str,
) -> std::result::Result<(), MqttViolation> {
    if cursor == body.len() {
        Ok(())
    } else {
        Err(MqttViolation::malformed(format!(
            "{name} contains trailing bytes"
        )))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TopicFilter {
    levels: Vec<FilterLevel>,
    starts_with_dollar: bool,
}

impl TopicFilter {
    /// 业务作用：把 MQTT Topic Filter 编译为 level 匹配器，拒绝 shared subscription 与歧义 wildcard。
    ///
    /// 参数说明：
    /// - `raw`：是配置或 client filter
    /// - `max_bytes`：是 listener topic 上限。
    ///
    /// 返回：合法的 exact/`+`/`#` level 列表；空、越长、shared 或 wildcard 位置非法时拒绝。
    fn parse(raw: &str, max_bytes: usize) -> std::result::Result<Self, MqttViolation> {
        validate_mqtt_utf8(raw, max_bytes)
            .map_err(|error| MqttViolation::malformed(format!("invalid topic filter: {error}")))?;
        if raw.is_empty() {
            return Err(MqttViolation::malformed("topic filter must not be empty"));
        }
        if raw.starts_with("$share/") {
            return Err(MqttViolation::not_authorized(
                "shared subscriptions are outside the bounded ACL profile",
            ));
        }
        let raw_levels: Vec<&str> = raw.split('/').collect();
        let mut levels = Vec::with_capacity(raw_levels.len());
        for (index, level) in raw_levels.iter().enumerate() {
            let compiled = match *level {
                "+" => FilterLevel::Single,
                "#" if index + 1 == raw_levels.len() => FilterLevel::Tail,
                value if value.contains(['+', '#']) => {
                    return Err(MqttViolation::malformed(
                        "topic wildcard must occupy a complete level and # must be last",
                    ))
                }
                value => FilterLevel::Exact(Arc::from(value)),
            };
            levels.push(compiled);
        }
        Ok(Self {
            levels,
            starts_with_dollar: raw.starts_with('$'),
        })
    }

    /// 业务作用：把具体 PUBLISH Topic Name 与配置 allow filter 匹配，保留 `$` 主题的 wildcard 隔离。
    ///
    /// 参数说明：
    /// - `topic`：是已验证不含 wildcard 的 topic name。
    ///
    /// 返回：filter 覆盖 topic 时返回 true。
    fn matches_topic(&self, topic: &str) -> bool {
        if topic.starts_with('$') && !self.starts_with_dollar {
            return false;
        }
        let topic_levels: Vec<&str> = topic.split('/').collect();
        let mut index = 0usize;
        loop {
            match (self.levels.get(index), topic_levels.get(index)) {
                (Some(FilterLevel::Tail), _) => return true,
                (Some(FilterLevel::Single), Some(_)) => {}
                (Some(FilterLevel::Exact(expected)), Some(actual))
                    if expected.as_ref() == *actual => {}
                (None, None) => return true,
                _ => return false,
            }
            index += 1;
        }
    }

    /// 业务作用：判定 client 请求 filter 的整个匹配集是否为 ACL filter 的子集。
    ///
    /// 参数说明：
    /// - `requested`：是 SUBSCRIBE/UNSUBSCRIBE 编译后 filter。
    ///
    /// 返回：每个 requested level 都不比 ACL 更宽且 `$` 边界一致时返回 true。
    fn covers(&self, requested: &TopicFilter) -> bool {
        if requested.starts_with_dollar && !self.starts_with_dollar {
            return false;
        }
        let mut index = 0usize;
        loop {
            match (self.levels.get(index), requested.levels.get(index)) {
                (Some(FilterLevel::Tail), _) => return true,
                (_, Some(FilterLevel::Tail)) => return false,
                (Some(FilterLevel::Single), Some(FilterLevel::Single | FilterLevel::Exact(_))) => {}
                (Some(FilterLevel::Exact(allowed)), Some(FilterLevel::Exact(actual)))
                    if allowed == actual => {}
                (None, None) => return true,
                _ => return false,
            }
            index += 1;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FilterLevel {
    Exact(Arc<str>),
    Single,
    Tail,
}

/// 业务作用：在快照构建期编译并去重 ACL Topic Filter，不让重复规则增加热路扫描。
///
/// 参数说明：
/// - `name`：标识配置键
/// - `values`：是原始 filter
/// - `max_bytes`：是 topic 上限。
///
/// 返回：顺序稳定的去重 filter 列表；非法或重复规则使快照构建失败。
fn compile_topic_filters(
    name: &str,
    values: &[String],
    max_bytes: usize,
) -> Result<Vec<TopicFilter>> {
    let mut seen = HashSet::with_capacity(values.len());
    let mut filters = Vec::with_capacity(values.len());
    for raw in values {
        anyhow::ensure!(
            seen.insert(raw.as_str()),
            "{name} contains duplicate `{raw}`"
        );
        filters.push(
            TopicFilter::parse(raw, max_bytes)
                .map_err(|error| anyhow::anyhow!("{name} `{raw}`: {}", error.detail))?,
        );
    }
    Ok(filters)
}
