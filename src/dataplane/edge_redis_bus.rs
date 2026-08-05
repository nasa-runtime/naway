//! Redis Pub/Sub 集群散出总线。
//!
//! 这里只解码固定、版本化的路由 envelope；`FramePush` message 及其 payload 始终按
//! opaque bytes 处理。Pub/Sub 没有持久化、背压和远端 ACK，因此 PUBLISH 成功不能
//! 折算成 `peers_accepted`。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use nasa::redis::{
    CompatibilityProfile, RedisClient, RedisConfig, StreamAckPolicy, StreamMode, StreamStart,
    StreamSubscribeCfg, StreamSubscription,
};

use crate::edge_hub::EdgeHub;
use crate::edge_relay::PeerBroadcastSummary;
use crate::grpc_edge::{GrpcEdgeClusterPlan, GrpcEdgeRedisPubSubPlan, GrpcEdgeRedisStreamPlan};

const PROTOCOL_VERSION: u32 = 1;
const GRPC_PREFIX_BYTES: usize = 5;
const MAX_ROUTING_BYTES: usize = 256;
const MAX_ENVELOPE_OVERHEAD: usize = 4 * 1024;
pub const REDIS_STREAM_FIELD: &str = "naway";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedisFanoutAction {
    Publish = 1,
    Push = 2,
}

#[derive(Default)]
pub struct EdgeRedisStreamMetrics {
    published_total: AtomicU64,
    received_total: AtomicU64,
    rejected_total: AtomicU64,
    publish_failed_total: AtomicU64,
    cursor_failed_total: AtomicU64,
    trim_gap_total: AtomicU64,
}

impl EdgeRedisStreamMetrics {
    pub fn published_total(&self) -> u64 {
        self.published_total.load(Ordering::Relaxed)
    }
    pub fn received_total(&self) -> u64 {
        self.received_total.load(Ordering::Relaxed)
    }
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }
    pub fn publish_failed_total(&self) -> u64 {
        self.publish_failed_total.load(Ordering::Relaxed)
    }
    pub fn cursor_failed_total(&self) -> u64 {
        self.cursor_failed_total.load(Ordering::Relaxed)
    }
    /// 启动时发现「持久 cursor 已被业务裁掉」的次数。
    ///
    /// 业务作用:naway **不裁剪**业务拥有的 edge 流(历史窗口是业务侧责任),因此保留窗口
    /// 完全不受 naway 控制。业务一旦裁到本节点 cursor 之前,Redis 的 XREAD **不会报错**——
    /// 它只会从"还存在的最早 entry"开始给,中间那段被**静默跳过**。这个计数器是该静默
    /// 丢失的唯一信号:非 0 就说明本节点确实漏读了一段历史,运维必须据此放大业务的保留
    /// 窗口(要覆盖最大停机时长与消费滞后),否则慢节点会周期性丢数据而无人知晓。
    pub fn trim_gap_total(&self) -> u64 {
        self.trim_gap_total.load(Ordering::Relaxed)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DecodedEnvelope {
    action: RedisFanoutAction,
    cluster_id: String,
    tenant: String,
    scope: String,
    message: Bytes,
    origin_node_id: String,
}

#[derive(Default)]
pub struct EdgeRedisBusMetrics {
    connected: AtomicBool,
    published_total: AtomicU64,
    received_total: AtomicU64,
    rejected_total: AtomicU64,
    publish_failed_total: AtomicU64,
    reconnect_total: AtomicU64,
}

impl EdgeRedisBusMetrics {
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    pub fn published_total(&self) -> u64 {
        self.published_total.load(Ordering::Relaxed)
    }
    pub fn received_total(&self) -> u64 {
        self.received_total.load(Ordering::Relaxed)
    }
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }
    pub fn publish_failed_total(&self) -> u64 {
        self.publish_failed_total.load(Ordering::Relaxed)
    }
    pub fn reconnect_total(&self) -> u64 {
        self.reconnect_total.load(Ordering::Relaxed)
    }
}

pub struct EdgeRedisBus {
    cluster: Arc<GrpcEdgeClusterPlan>,
    redis: Arc<RedisClient>,
    redis_plan: GrpcEdgeRedisPubSubPlan,
    hub: Arc<EdgeHub>,
    metrics: Arc<EdgeRedisBusMetrics>,
}

impl EdgeRedisBus {
    pub async fn start(cluster: Arc<GrpcEdgeClusterPlan>, hub: Arc<EdgeHub>) -> Result<Arc<Self>> {
        let redis_plan = cluster
            .redis_pubsub
            .clone()
            .ok_or_else(|| anyhow!("redis_pubsub plan is missing"))?;
        let profile = match redis_plan
            .profile
            .to_ascii_lowercase()
            .replace('-', "")
            .as_str()
        {
            "rustv2" => CompatibilityProfile::RustV2,
            "legacyv1" => CompatibilityProfile::LegacyV1,
            _ => unreachable!("profile was validated while building the cluster plan"),
        };
        let mut redis_config = RedisConfig::new(
            redis_plan.url.as_ref(),
            redis_plan.namespace.as_ref(),
            profile,
        );
        redis_config.command.response_timeout_ms = redis_plan.command_timeout.as_millis() as u64;
        let redis = RedisClient::connect(redis_config)
            .await
            .context("connect edge Redis Pub/Sub")?;
        // 在报告 gateway ready 之前完成 SUBSCRIBE，避免第一批业务消息落入启动空窗。
        let mut subscription = redis
            .sub(&[redis_plan.channel.as_ref()])
            .await
            .context("subscribe edge Redis Pub/Sub channel")?;
        let bus = Arc::new(Self {
            cluster,
            redis,
            redis_plan,
            hub,
            metrics: Arc::new(EdgeRedisBusMetrics::default()),
        });
        bus.metrics.connected.store(true, Ordering::Relaxed);
        let consumer = bus.clone();
        tokio::spawn(async move {
            loop {
                match subscription.next_message().await {
                    Some(message) => {
                        consumer.metrics.connected.store(true, Ordering::Relaxed);
                        consumer
                            .metrics
                            .received_total
                            .fetch_add(1, Ordering::Relaxed);
                        if message.channel != consumer.redis_plan.channel.as_ref()
                            || consumer
                                .consume_one(Bytes::from(message.payload))
                                .await
                                .is_err()
                        {
                            consumer
                                .metrics
                                .rejected_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => {
                        consumer.metrics.connected.store(false, Ordering::Relaxed);
                        consumer
                            .metrics
                            .reconnect_total
                            .fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(consumer.redis_plan.reconnect_backoff).await;
                        if subscription
                            .reconnect_timeout(consumer.redis_plan.command_timeout)
                            .await
                            .is_ok()
                        {
                            consumer.metrics.connected.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        Ok(bus)
    }

    pub fn metrics(&self) -> Arc<EdgeRedisBusMetrics> {
        self.metrics.clone()
    }

    pub async fn broadcast_publish(
        &self,
        tenant: &str,
        group: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Publish, tenant, group, frame)
            .await
    }

    pub async fn broadcast_push(
        &self,
        tenant: &str,
        target: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Push, tenant, target, frame)
            .await
    }

    async fn broadcast(
        &self,
        action: RedisFanoutAction,
        tenant: &str,
        scope: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        let mut summary = PeerBroadcastSummary::default();
        let payload = match encode_from_grpc_frame(
            action,
            self.cluster.cluster_id.as_ref(),
            tenant,
            scope,
            self.cluster.node_id.as_ref(),
            &frame,
        ) {
            Ok(payload) => payload,
            Err(_) => {
                summary.peers_rejected = 1;
                self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
                return summary;
            }
        };
        match tokio::time::timeout(
            self.redis_plan.command_timeout,
            self.redis
                .r#pub(self.redis_plan.channel.as_ref(), payload.as_ref()),
        )
        .await
        {
            Ok(Ok(_)) => {
                self.metrics.published_total.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(_)) | Err(_) => {
                summary.peers_unknown = 1;
                self.metrics
                    .publish_failed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        summary
    }

    async fn consume_one(&self, payload: Bytes) -> Result<()> {
        let envelope = decode_envelope(payload, self.cluster.fanout_limits.max_msg_bytes)?;
        if envelope.cluster_id != self.cluster.cluster_id.as_ref() {
            bail!("Redis envelope cluster_id mismatch");
        }
        // gRPC ingress 已先完成本地散出；跳过自己的 Redis 回环，避免本机收到两次。
        if envelope.origin_node_id == self.cluster.node_id.as_ref() {
            return Ok(());
        }
        let frame = grpc_frame(envelope.message)?;
        match envelope.action {
            RedisFanoutAction::Publish => {
                self.hub
                    .publish_group(
                        &self.cluster.fanout_limits,
                        Arc::from(envelope.tenant.as_str()),
                        Arc::from(envelope.scope.as_str()),
                        frame,
                        0,
                    )
                    .await
                    .map_err(|error| {
                        anyhow!("Redis publish fanout rejected: {}", error.reason())
                    })?;
            }
            RedisFanoutAction::Push => {
                self.hub
                    .push_user(
                        &self.cluster.fanout_limits,
                        Arc::from(envelope.tenant.as_str()),
                        Arc::from(envelope.scope.as_str()),
                        frame,
                        0,
                    )
                    .await
                    .map_err(|error| anyhow!("Redis push fanout rejected: {}", error.reason()))?;
            }
        }
        Ok(())
    }
}

/// Redis Stream 广播总线。每个节点使用独立 XREAD cursor，因此每个节点都能看到每条
/// entry；绝不能把所有 Naway 放进同一个 consumer group。
pub struct EdgeRedisStreamBus {
    cluster: Arc<GrpcEdgeClusterPlan>,
    redis: Arc<RedisClient>,
    redis_plan: GrpcEdgeRedisStreamPlan,
    hub: Arc<EdgeHub>,
    subscription: std::sync::OnceLock<StreamSubscription>,
    metrics: Arc<EdgeRedisStreamMetrics>,
}

impl EdgeRedisStreamBus {
    pub async fn start(cluster: Arc<GrpcEdgeClusterPlan>, hub: Arc<EdgeHub>) -> Result<Arc<Self>> {
        let redis_plan = cluster
            .redis_stream
            .clone()
            .ok_or_else(|| anyhow!("redis_stream plan is missing"))?;
        let profile = compatibility_profile(&redis_plan.profile);
        let mut redis_config = RedisConfig::new(
            redis_plan.url.as_ref(),
            redis_plan.namespace.as_ref(),
            profile,
        );
        redis_config.command.response_timeout_ms = redis_plan
            .block_ms
            .saturating_add(redis_plan.command_timeout.as_millis() as u64);
        let redis = RedisClient::connect(redis_config)
            .await
            .context("connect edge Redis Stream")?;
        let stored_cursor = tokio::time::timeout(
            redis_plan.command_timeout,
            redis.get::<String>(redis_plan.cursor_key.as_ref()),
        )
        .await
        .context("load edge Redis Stream cursor timeout")??;
        let start = stored_cursor
            .clone()
            .map(StreamStart::After)
            .unwrap_or(StreamStart::Now);
        // 启动期 trim-gap 检测:naway 不裁剪业务流,保留窗口不受它控制。若业务已经裁到
        // 本节点 cursor 之前,XREAD 会**静默**从现存最早 entry 开始,中间那段永久漏读且
        // 没有任何错误。这里在开始消费前比一次"流中最早 entry"与"本节点 cursor":
        // 前者更大即存在缺口。只在启动做一次——那正是缺口最可能出现的时刻(节点停机期间
        // 业务照常裁剪),稳态下每条 entry 再查一次既贵也没有额外信息。
        let trim_gap = match stored_cursor.as_deref() {
            Some(cursor) => {
                detect_trim_gap(
                    &redis,
                    redis_plan.stream.as_ref(),
                    cursor,
                    redis_plan.command_timeout,
                )
                .await
            }
            None => false,
        };
        let bus = Arc::new(Self {
            cluster,
            redis: redis.clone(),
            redis_plan: redis_plan.clone(),
            hub,
            subscription: std::sync::OnceLock::new(),
            metrics: Arc::new(EdgeRedisStreamMetrics::default()),
        });
        let weak = Arc::downgrade(&bus);
        let cfg = StreamSubscribeCfg {
            mode: StreamMode::Broadcast { start },
            batch_size: redis_plan.batch_size,
            block_ms: redis_plan.block_ms,
            idle_sleep_ms: redis_plan.reconnect_backoff.as_millis() as u64,
            handler_timeout_ms: 0,
            ack_policy: StreamAckPolicy::Auto,
        };
        let subscription = redis
            .subscribe(redis_plan.stream.as_ref())
            .with_cfg(cfg)
            .on(REDIS_STREAM_FIELD, move |event| {
                let weak = weak.clone();
                async move {
                    let Some(bus) = weak.upgrade() else {
                        return Err("edge Redis Stream bus stopped".to_string());
                    };
                    bus.consume_stream_entry(event.id, Bytes::from(event.raw))
                        .await
                        .map_err(|error| format!("{error:#}"))
                }
            })
            .start()
            .await
            .context("start edge Redis Stream XREAD subscription")?;
        let _ = bus.subscription.set(subscription);
        if trim_gap {
            bus.metrics.trim_gap_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                stream = %redis_plan.stream,
                cursor = ?stored_cursor,
                "edge Redis Stream cursor was trimmed away by the producer; this node permanently \
                 skipped that history. naway never trims the business-owned stream — widen the \
                 producer's retention window to cover max downtime and consumer lag"
            );
        }
        Ok(bus)
    }

    pub fn metrics(&self) -> Arc<EdgeRedisStreamMetrics> {
        self.metrics.clone()
    }

    pub async fn broadcast_publish(
        &self,
        tenant: &str,
        group: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Publish, tenant, group, frame)
            .await
    }

    pub async fn broadcast_push(
        &self,
        tenant: &str,
        target: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Push, tenant, target, frame)
            .await
    }

    async fn broadcast(
        &self,
        action: RedisFanoutAction,
        tenant: &str,
        scope: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        let mut summary = PeerBroadcastSummary::default();
        let payload = match encode_from_grpc_frame(
            action,
            self.cluster.cluster_id.as_ref(),
            tenant,
            scope,
            self.cluster.node_id.as_ref(),
            &frame,
        ) {
            Ok(payload) => payload,
            Err(_) => {
                summary.peers_rejected = 1;
                self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
                return summary;
            }
        };
        let fields = [(REDIS_STREAM_FIELD, payload.as_ref())];
        match tokio::time::timeout(
            self.redis_plan.command_timeout,
            self.redis
                .x_add_bytes(self.redis_plan.stream.as_ref(), "*", &fields),
        )
        .await
        {
            Ok(Ok(_)) => {
                self.metrics.published_total.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(_)) | Err(_) => {
                summary.peers_unknown = 1;
                self.metrics
                    .publish_failed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        summary
    }

    async fn consume_stream_entry(&self, id: String, payload: Bytes) -> Result<()> {
        self.metrics.received_total.fetch_add(1, Ordering::Relaxed);
        let fanout = self.fanout_stream_payload(payload).await;
        if fanout.is_err() {
            // poison entry 或节点预算拒绝都不能永久卡住流；at-most-once 数据面允许丢弃，
            // 并由指标暴露。可靠业务必须依靠 event_id/seq 补偿。
            self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
        }
        let cursor_result = tokio::time::timeout(
            self.redis_plan.command_timeout,
            self.redis
                .set(self.redis_plan.cursor_key.as_ref(), id.as_str()),
        )
        .await;
        match cursor_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.metrics
                    .cursor_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(anyhow!("persist Redis Stream cursor: {error}"))
            }
            Err(_) => {
                self.metrics
                    .cursor_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                bail!("persist Redis Stream cursor timeout")
            }
        }
    }

    async fn fanout_stream_payload(&self, payload: Bytes) -> Result<()> {
        let envelope = decode_envelope(payload, self.cluster.fanout_limits.max_msg_bytes)?;
        if envelope.cluster_id != self.cluster.cluster_id.as_ref() {
            bail!("Redis Stream envelope cluster_id mismatch");
        }
        if envelope.origin_node_id == self.cluster.node_id.as_ref() {
            return Ok(());
        }
        let frame = grpc_frame(envelope.message)?;
        match envelope.action {
            RedisFanoutAction::Publish => {
                self.hub
                    .publish_group(
                        &self.cluster.fanout_limits,
                        Arc::from(envelope.tenant.as_str()),
                        Arc::from(envelope.scope.as_str()),
                        frame,
                        0,
                    )
                    .await
                    .map_err(|error| {
                        anyhow!("Redis Stream publish fanout rejected: {}", error.reason())
                    })?;
            }
            RedisFanoutAction::Push => {
                self.hub
                    .push_user(
                        &self.cluster.fanout_limits,
                        Arc::from(envelope.tenant.as_str()),
                        Arc::from(envelope.scope.as_str()),
                        frame,
                        0,
                    )
                    .await
                    .map_err(|error| {
                        anyhow!("Redis Stream push fanout rejected: {}", error.reason())
                    })?;
            }
        }
        Ok(())
    }
}

fn compatibility_profile(raw: &str) -> CompatibilityProfile {
    match raw.to_ascii_lowercase().replace('-', "").as_str() {
        "rustv2" => CompatibilityProfile::RustV2,
        "legacyv1" => CompatibilityProfile::LegacyV1,
        _ => unreachable!("profile was validated while building the cluster plan"),
    }
}

/// 业务侧直接发布群消息时使用；`origin_node_id` 固定为空，使每个 Naway 节点都消费。
pub fn encode_external_publish(
    cluster_id: &str,
    tenant: &str,
    group: &str,
    frame_push_message: &[u8],
) -> Result<Bytes> {
    encode_envelope(
        RedisFanoutAction::Publish,
        cluster_id,
        tenant,
        group,
        "",
        frame_push_message,
    )
}

fn encode_from_grpc_frame(
    action: RedisFanoutAction,
    cluster_id: &str,
    tenant: &str,
    scope: &str,
    origin_node_id: &str,
    frame: &[u8],
) -> Result<Bytes> {
    if frame.len() < GRPC_PREFIX_BYTES || frame[0] != 0 {
        bail!("edge frame is not an uncompressed gRPC message");
    }
    let declared = u32::from_be_bytes(frame[1..5].try_into().expect("fixed prefix")) as usize;
    if declared != frame.len() - GRPC_PREFIX_BYTES {
        bail!("edge frame length mismatch");
    }
    encode_envelope(
        action,
        cluster_id,
        tenant,
        scope,
        origin_node_id,
        &frame[GRPC_PREFIX_BYTES..],
    )
}

fn encode_envelope(
    action: RedisFanoutAction,
    cluster_id: &str,
    tenant: &str,
    scope: &str,
    origin_node_id: &str,
    message: &[u8],
) -> Result<Bytes> {
    validate_routing("cluster_id", cluster_id)?;
    validate_routing("tenant", tenant)?;
    validate_routing("scope", scope)?;
    if !origin_node_id.is_empty() {
        validate_routing("origin_node_id", origin_node_id)?;
    }
    let mut out = BytesMut::with_capacity(message.len().saturating_add(128));
    put_varint_field(&mut out, 1, PROTOCOL_VERSION as u64);
    put_bytes_field(&mut out, 2, cluster_id.as_bytes());
    put_varint_field(&mut out, 3, action as u64);
    put_bytes_field(&mut out, 4, tenant.as_bytes());
    put_bytes_field(&mut out, 5, scope.as_bytes());
    // 即使 FramePush 是 proto3 默认空 message，也必须显式写 field 6 的零长度值。
    put_bytes_field(&mut out, 6, message);
    if !origin_node_id.is_empty() {
        put_bytes_field(&mut out, 7, origin_node_id.as_bytes());
    }
    Ok(out.freeze())
}

fn decode_envelope(input: Bytes, max_message_bytes: usize) -> Result<DecodedEnvelope> {
    if input.len() > max_message_bytes.saturating_add(MAX_ENVELOPE_OVERHEAD) {
        bail!("Redis envelope exceeds configured message limit");
    }
    let mut pos = 0usize;
    let mut version = None;
    let mut cluster_id = None;
    let mut action = None;
    let mut tenant = None;
    let mut scope = None;
    let mut message = None;
    let mut origin_node_id = None;
    while pos < input.len() {
        let key = take_varint(&input, &mut pos)?;
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        match field {
            1 if wire == 0 => set_once(&mut version, take_varint(&input, &mut pos)?, "version")?,
            2 if wire == 2 => set_once(
                &mut cluster_id,
                take_string(&input, &mut pos)?,
                "cluster_id",
            )?,
            3 if wire == 0 => set_once(&mut action, take_varint(&input, &mut pos)?, "action")?,
            4 if wire == 2 => set_once(&mut tenant, take_string(&input, &mut pos)?, "tenant")?,
            5 if wire == 2 => set_once(&mut scope, take_string(&input, &mut pos)?, "scope")?,
            6 if wire == 2 => set_once(&mut message, take_bytes(&input, &mut pos)?, "message")?,
            7 if wire == 2 => set_once(
                &mut origin_node_id,
                take_string(&input, &mut pos)?,
                "origin_node_id",
            )?,
            _ => skip_field(&input, &mut pos, wire)?,
        }
    }
    if version != Some(PROTOCOL_VERSION as u64) {
        bail!("unsupported Redis envelope protocol_version");
    }
    let action = match action {
        Some(1) => RedisFanoutAction::Publish,
        Some(2) => RedisFanoutAction::Push,
        _ => bail!("invalid Redis envelope action"),
    };
    let cluster_id = cluster_id.ok_or_else(|| anyhow!("missing cluster_id"))?;
    let tenant = tenant.ok_or_else(|| anyhow!("missing tenant"))?;
    let scope = scope.ok_or_else(|| anyhow!("missing scope"))?;
    validate_routing("cluster_id", &cluster_id)?;
    validate_routing("tenant", &tenant)?;
    validate_routing("scope", &scope)?;
    let origin_node_id = origin_node_id.unwrap_or_default();
    if !origin_node_id.is_empty() {
        validate_routing("origin_node_id", &origin_node_id)?;
    }
    let message = message.ok_or_else(|| anyhow!("missing message"))?;
    if message.len() > max_message_bytes {
        bail!("Redis envelope message exceeds configured limit");
    }
    Ok(DecodedEnvelope {
        action,
        cluster_id,
        tenant,
        scope,
        message,
        origin_node_id,
    })
}

/// 判断持久 cursor 是否已被业务裁掉。
///
/// 业务作用:给「naway 不裁剪、裁剪归业务」这条责任划分补上唯一的失效信号。取流中现存
/// 最早 entry 的 id,若它**严格大于**本节点 cursor,说明 cursor 与该 id 之间的 entry 已被
/// 业务裁走,本节点将静默跳过它们。
///
/// 参数说明:
/// - `stream`: 业务拥有的 edge 扇出流 key。
/// - `cursor`: 本节点持久化的上次已处理 entry id。
/// - `timeout`: 单次 Redis 命令硬超时。
///
/// 返回:确认存在缺口返回 true。**查询失败一律返回 false**——检测本身是可观测性增强,
/// 不能因为一次 Redis 抖动就把节点误报成丢数据,更不能阻断启动。
async fn detect_trim_gap(
    redis: &RedisClient,
    stream: &str,
    cursor: &str,
    timeout: Duration,
) -> bool {
    // XRANGE 的返回形状:每个 entry 是 (id, [(field, value)...])。这里只关心 id,
    // 但反序列化必须给出完整形状,否则解析会失败。
    type StreamEntry = (String, Vec<(String, Vec<u8>)>);
    // 只取一条:XRANGE - + COUNT 1 即流中现存最早的 entry。
    let earliest: Option<Vec<StreamEntry>> =
        match tokio::time::timeout(timeout, redis.x_range(stream, "-", "+", Some(1))).await {
            Ok(Ok(entries)) => entries,
            _ => return false,
        };
    let Some(first) = earliest.as_ref().and_then(|entries| entries.first()) else {
        // 空流:业务可能全裁光了,但也可能只是还没写过。无法区分,不报。
        return false;
    };
    stream_id_gt(&first.0, cursor)
}

/// 比较两个 Redis Stream entry id(`<ms>-<seq>`)。
///
/// 必须按两段整数比较而不是字典序:`10-0` 字典序小于 `9-0`,但时间上更晚。
/// 解析失败一律返回 false,理由同 [`detect_trim_gap`]——宁可漏报也不误报。
fn stream_id_gt(left: &str, right: &str) -> bool {
    let parse = |id: &str| -> Option<(u64, u64)> {
        let (ms, seq) = id.split_once('-')?;
        Some((ms.parse().ok()?, seq.parse().ok()?))
    };
    match (parse(left), parse(right)) {
        (Some(l), Some(r)) => l > r,
        _ => false,
    }
}

fn grpc_frame(message: Bytes) -> Result<Bytes> {
    let len = u32::try_from(message.len()).context("FramePush message exceeds gRPC u32 limit")?;
    let mut out = BytesMut::with_capacity(GRPC_PREFIX_BYTES + message.len());
    out.put_u8(0);
    out.put_u32(len);
    out.extend_from_slice(&message);
    Ok(out.freeze())
}

fn validate_routing(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ROUTING_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("invalid Redis envelope {name}");
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("duplicate Redis envelope field {name}");
    }
    Ok(())
}

fn put_varint_field(out: &mut BytesMut, field: u32, value: u64) {
    put_varint(out, (field as u64) << 3);
    put_varint(out, value);
}

fn put_bytes_field(out: &mut BytesMut, field: u32, value: &[u8]) {
    put_varint(out, ((field as u64) << 3) | 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn put_varint(out: &mut BytesMut, mut value: u64) {
    while value >= 0x80 {
        out.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

fn take_varint(input: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input.get(*pos).ok_or_else(|| anyhow!("truncated varint"))?;
        *pos += 1;
        if shift == 63 && byte > 1 {
            bail!("varint overflow");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("varint overflow")
}

fn take_bytes(input: &Bytes, pos: &mut usize) -> Result<Bytes> {
    let len = usize::try_from(take_varint(input, pos)?).context("length overflow")?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow!("length overflow"))?;
    if end > input.len() {
        bail!("truncated length-delimited field");
    }
    let value = input.slice(*pos..end);
    *pos = end;
    Ok(value)
}

fn take_string(input: &Bytes, pos: &mut usize) -> Result<String> {
    String::from_utf8(take_bytes(input, pos)?.to_vec()).context("routing field is not UTF-8")
}

fn skip_field(input: &Bytes, pos: &mut usize, wire: u8) -> Result<()> {
    match wire {
        0 => {
            take_varint(input, pos)?;
        }
        1 => {
            *pos = pos
                .checked_add(8)
                .ok_or_else(|| anyhow!("length overflow"))?
        }
        2 => {
            let len = usize::try_from(take_varint(input, pos)?).context("length overflow")?;
            *pos = pos
                .checked_add(len)
                .ok_or_else(|| anyhow!("length overflow"))?;
        }
        5 => {
            *pos = pos
                .checked_add(4)
                .ok_or_else(|| anyhow!("length overflow"))?
        }
        _ => bail!("unsupported protobuf wire type {wire}"),
    }
    if *pos > input.len() {
        bail!("truncated unknown field");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_keeps_business_message_opaque() {
        let encoded = encode_envelope(
            RedisFanoutAction::Publish,
            "cluster-a",
            "tenant-a",
            "room.1",
            "node-a",
            b"\x0a\x03raw",
        )
        .unwrap();
        let decoded = decode_envelope(encoded, 1024).unwrap();
        assert_eq!(decoded.action, RedisFanoutAction::Publish);
        assert_eq!(decoded.message.as_ref(), b"\x0a\x03raw");
        assert_eq!(decoded.origin_node_id, "node-a");
    }

    #[test]
    fn empty_frame_push_message_is_valid() {
        let encoded = encode_external_publish("cluster-a", "tenant-a", "room.1", b"").unwrap();
        let decoded = decode_envelope(encoded, 1024).unwrap();
        assert!(decoded.message.is_empty());
        assert!(decoded.origin_node_id.is_empty());
    }

    #[test]
    fn unknown_field_is_skipped_but_duplicate_routing_field_is_rejected() {
        let mut encoded = encode_external_publish("cluster-a", "tenant-a", "room.1", b"x")
            .unwrap()
            .to_vec();
        encoded.extend_from_slice(&[0x80, 0x06, 0x01]); // field 96,varint 1
        assert!(decode_envelope(Bytes::from(encoded.clone()), 1024).is_ok());
        encoded.extend_from_slice(&[0x22, 0x01, b'x']); // duplicate tenant
        assert!(decode_envelope(Bytes::from(encoded), 1024).is_err());
    }

    #[test]
    fn redis_cluster_modes_build_independent_transport_plans() {
        let pubsub: crate::config::model::GrpcEdgeClusterCfg = serde_json::from_str(
            r#"{
  "mode": "redis_pubsub",
  "cluster_id": "cluster-a",
  "node_id": "node-a",
  "redis_pubsub": { "url": "redis://127.0.0.1:6379" }
}"#,
        )
        .unwrap();
        let plan = GrpcEdgeClusterPlan::build(Some(&pubsub), false, std::path::Path::new("."))
            .unwrap()
            .unwrap();
        assert_eq!(
            plan.mode,
            crate::config::model::GrpcEdgeClusterModeCfg::RedisPubsub
        );
        assert!(plan.redis_pubsub.is_some());
        assert!(plan.redis_stream.is_none());

        let stream: crate::config::model::GrpcEdgeClusterCfg = serde_json::from_str(
            r#"{
  "mode": "redis_stream",
  "cluster_id": "cluster-a",
  "node_id": "node-a",
  "redis_stream": { "url": "redis://127.0.0.1:6379" }
}"#,
        )
        .unwrap();
        let plan = GrpcEdgeClusterPlan::build(Some(&stream), false, std::path::Path::new("."))
            .unwrap()
            .unwrap();
        assert_eq!(
            plan.mode,
            crate::config::model::GrpcEdgeClusterModeCfg::RedisStream
        );
        assert!(plan.redis_pubsub.is_none());
        assert!(plan.redis_stream.is_some());
    }

    #[test]
    fn redis_cluster_mode_rejects_relay_or_other_redis_transport() {
        let cfg: crate::config::model::GrpcEdgeClusterCfg = serde_json::from_str(
            r#"{
  "mode": "redis_stream",
  "cluster_id": "cluster-a",
  "node_id": "node-a",
  "relay_listen": "127.0.0.1:19000",
  "redis_pubsub": { "url": "redis://127.0.0.1:6379" },
  "redis_stream": { "url": "redis://127.0.0.1:6379" }
}"#,
        )
        .unwrap();
        let error = GrpcEdgeClusterPlan::build(Some(&cfg), false, std::path::Path::new("."))
            .err()
            .expect("mixed cluster transports must fail");
        assert!(error.to_string().contains("mutually exclusive"));
    }

    /// 回归场景:Stream entry id 必须按 `<ms>-<seq>` **两段整数**比较。
    ///
    /// 用字典序会得到 `10-0 < 9-0` 这种反直觉结果——而 trim-gap 检测正是靠这个比较判断
    /// "流中最早 entry 是否已经越过本节点 cursor"。比反了会在真有缺口时漏报(更糟),
    /// 或在没缺口时误报把运维引向错误方向。
    #[test]
    fn stream_id_comparison_is_numeric_not_lexicographic() {
        assert!(stream_id_gt("10-0", "9-0"), "毫秒段必须按数值比较");
        assert!(!stream_id_gt("9-0", "10-0"));
        assert!(stream_id_gt("5-10", "5-9"), "序号段同样按数值比较");
        assert!(!stream_id_gt("5-9", "5-10"));
        assert!(!stream_id_gt("7-3", "7-3"), "相等不算缺口");
        // 解析不了一律返回 false:宁可漏报也不误报,不能因为一个畸形 id 就宣告丢数据。
        assert!(!stream_id_gt("garbage", "5-0"));
        assert!(!stream_id_gt("5-0", "garbage"));
    }

    #[tokio::test]
    #[ignore = "requires GW_EDGE_TEST_REDIS, e.g. redis://:<password>@127.0.0.1:6379"]
    async fn live_redis_pubsub_reaches_every_naway_subscription() {
        let url = std::env::var("GW_EDGE_TEST_REDIS").expect("GW_EDGE_TEST_REDIS");
        let namespace = format!("naway-edge-live-{}", std::process::id());
        let client = RedisClient::connect(RedisConfig::new(
            &url,
            &namespace,
            CompatibilityProfile::RustV2,
        ))
        .await
        .unwrap();
        let channel = format!("naway:edge:live:{}", std::process::id());
        let mut node_a = client.sub(&[&channel]).await.unwrap();
        let mut node_b = client.sub(&[&channel]).await.unwrap();
        let envelope =
            encode_external_publish("live-cluster", "tenant-a", "room.1", b"\x0a\x01x").unwrap();
        client.r#pub(&channel, envelope.as_ref()).await.unwrap();

        for subscription in [&mut node_a, &mut node_b] {
            let message = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                subscription.next_message(),
            )
            .await
            .expect("Redis Pub/Sub delivery timeout")
            .expect("subscription closed");
            let decoded = decode_envelope(Bytes::from(message.payload), 1024).unwrap();
            assert_eq!(decoded.cluster_id, "live-cluster");
            assert_eq!(decoded.scope, "room.1");
            assert_eq!(decoded.message.as_ref(), b"\x0a\x01x");
        }
    }

    #[tokio::test]
    #[ignore = "requires GW_EDGE_TEST_REDIS, e.g. redis://:<password>@127.0.0.1:6379"]
    async fn live_redis_stream_xread_broadcast_reaches_every_node() {
        let url = std::env::var("GW_EDGE_TEST_REDIS").expect("GW_EDGE_TEST_REDIS");
        let namespace = format!("naway-edge-stream-live-{}", std::process::id());
        let client = RedisClient::connect(RedisConfig::new(
            &url,
            &namespace,
            CompatibilityProfile::RustV2,
        ))
        .await
        .unwrap();
        let stream = format!("naway:edge:stream-live:{}", std::process::id());
        let cfg = StreamSubscribeCfg {
            mode: StreamMode::Broadcast {
                start: StreamStart::Now,
            },
            batch_size: 10,
            block_ms: 100,
            idle_sleep_ms: 50,
            handler_timeout_ms: 1_000,
            ack_policy: StreamAckPolicy::Auto,
        };
        let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();
        let node_a = client
            .subscribe(&stream)
            .with_cfg(cfg.clone())
            .on(REDIS_STREAM_FIELD, move |event| {
                let tx = tx_a.clone();
                async move {
                    tx.send(event.raw).map_err(|error| error.to_string())?;
                    Ok(())
                }
            })
            .start()
            .await
            .unwrap();
        let node_b = client
            .subscribe(&stream)
            .with_cfg(cfg)
            .on(REDIS_STREAM_FIELD, move |event| {
                let tx = tx_b.clone();
                async move {
                    tx.send(event.raw).map_err(|error| error.to_string())?;
                    Ok(())
                }
            })
            .start()
            .await
            .unwrap();
        let envelope =
            encode_external_publish("live-stream-cluster", "tenant-a", "room.1", b"\x0a\x01s")
                .unwrap();
        client
            .x_add_bytes(&stream, "*", &[(REDIS_STREAM_FIELD, envelope.as_ref())])
            .await
            .unwrap();

        for receiver in [&mut rx_a, &mut rx_b] {
            let raw = tokio::time::timeout(std::time::Duration::from_secs(3), receiver.recv())
                .await
                .expect("Redis Stream XREAD delivery timeout")
                .expect("subscriber stopped");
            let decoded = decode_envelope(Bytes::from(raw), 1024).unwrap();
            assert_eq!(decoded.cluster_id, "live-stream-cluster");
            assert_eq!(decoded.message.as_ref(), b"\x0a\x01s");
        }
        drop((node_a, node_b));
    }
}
