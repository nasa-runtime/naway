//! Redis Pub/Sub 集群散出总线。
//!
//! 这里只解码固定、版本化的路由 envelope；`FramePush` message 及其 payload 始终按
//! opaque bytes 处理。Pub/Sub 没有持久化、背压和远端 ACK，因此 PUBLISH 成功不能
//! 折算成 `peers_accepted`。

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use nasa::redis::{
    CompatibilityProfile, RedisClient, RedisConfig, StreamAckPolicy, StreamMode, StreamStart,
    StreamSubscribeCfg, StreamSubscription,
};
use tokio::sync::{oneshot, watch, Notify};

use crate::config::model::{GrpcEdgeOrderingCfg, GrpcEdgeSessionModeCfg};
use crate::edge::config::{GrpcEdgeClusterPlan, GrpcEdgeRedisPubSubPlan, GrpcEdgeRedisStreamPlan};
use crate::edge::hub::{EdgeHub, EdgeSessionControl, LocalFanoutOutcome};
use crate::edge::relay::PeerBroadcastSummary;

const PROTOCOL_VERSION: u32 = 1;
const GRPC_PREFIX_BYTES: usize = 5;
const MAX_ROUTING_BYTES: usize = 256;
const MAX_ENVELOPE_OVERHEAD: usize = 4 * 1024;
const MIN_MEMBERSHIP_LEASE_MS: u64 = 3_000;
pub const REDIS_STREAM_FIELD: &str = "naway";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedisFanoutAction {
    Publish = 1,
    Push = 2,
    SessionFence = 3,
    SessionFenceAck = 4,
    SessionRelease = 5,
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
    /// 业务作用：提供总线成功发布次数的只读事实，不将入队确认解释为终端送达。
    pub fn published_total(&self) -> u64 {
        self.published_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线接收次数的只读事实，供传输层观测使用。
    pub fn received_total(&self) -> u64 {
        self.received_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线拒绝次数，区分协议或权限拒绝与成功接收。
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线发布失败次数，不把未知投递结果当作成功。
    pub fn publish_failed_total(&self) -> u64 {
        self.publish_failed_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供流游标持久化失败次数，使恢复位置不可确认的情况可被观测。
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
    correlation_id: u64,
    revision: u64,
}

struct PendingFanoutEntry {
    sender: oneshot::Sender<Result<LocalFanoutOutcome, ()>>,
    limits: crate::edge::config::GrpcEdgeLimitsPlan,
    reassembled: u64,
}

type PendingFanout = DashMap<u64, PendingFanoutEntry>;

struct FenceAckWaiter {
    revision: u64,
    expected: HashSet<String>,
    received: parking_lot::Mutex<HashSet<String>>,
    notify: Notify,
}

impl FenceAckWaiter {
    /// 业务作用：创建一次 claim 的固定 membership ACK 门，后加入节点不反向扩大本次事务。
    ///
    /// 参数说明：
    /// - `revision`：是 fencing token
    /// - `expected`：是 Redis 线性化快照中的活跃节点。
    ///
    /// 返回：返回尚未收到任何 ACK 的等待器。
    fn new(revision: u64, expected: HashSet<String>) -> Self {
        Self {
            revision,
            expected,
            received: parking_lot::Mutex::new(HashSet::new()),
            notify: Notify::new(),
        }
    }

    /// 业务作用：记录一个节点完成本地 fence 的证据，并唤醒 claim 复验。
    ///
    /// 参数说明：
    /// - `node_id`：是 ACK envelope 中经过路由字符门校验的节点身份。
    ///
    /// 返回：无返回值；非本次 membership 的 ACK 被忽略。
    fn acknowledge(&self, node_id: String) {
        if self.expected.contains(&node_id) && self.received.lock().insert(node_id) {
            self.notify.notify_waiters();
        }
    }

    /// 业务作用：判断固定 membership 是否已经全部先保护、后 ACK。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部预期节点均有唯一 ACK 时返回 `true`。
    fn complete(&self) -> bool {
        let received = self.received.lock();
        self.expected.is_subset(&received)
    }
}

/// Redis Pub/Sub/Stream 共用的 single-session 权威控制面。
struct RedisStrongControl {
    cluster: Arc<GrpcEdgeClusterPlan>,
    redis: Arc<RedisClient>,
    channel: Box<str>,
    membership_key: Box<str>,
    fence_counter_key: Box<str>,
    command_timeout: Duration,
    reconnect_backoff: Duration,
    membership_lease_ms: u64,
    hub: Arc<EdgeHub>,
    subscription_connected: AtomicBool,
    ready: AtomicBool,
    active: AtomicBool,
    next_correlation: AtomicU64,
    pending_fences: DashMap<u64, Arc<FenceAckWaiter>>,
    shutdown: watch::Sender<bool>,
}

impl RedisStrongControl {
    /// 业务作用：在数据面 ready 前建立独立控制订阅并登记带租约的 Redis membership。
    ///
    /// 参数说明：
    /// - `cluster`：提供节点/超时语义
    /// - `redis`：是与数据总线同配置的客户端
    /// - `data_key`：用于派生隔离的控制频道
    /// - `command_timeout`：约束失效窗口
    /// - `reconnect_backoff`：约束失效窗口
    /// - `hub`：承接本地 fencing 副作用。
    ///
    /// 返回：订阅与首次 membership 心跳均成功后返回控制面；任一步失败则拒绝启动。
    async fn prepare(
        cluster: Arc<GrpcEdgeClusterPlan>,
        redis: Arc<RedisClient>,
        data_key: &str,
        command_timeout: Duration,
        reconnect_backoff: Duration,
        hub: Arc<EdgeHub>,
    ) -> Result<Arc<Self>> {
        let channel = format!("{data_key}:naway-strong-control");
        let mut subscription = redis
            .sub(&[channel.as_str()])
            .await
            .context("subscribe edge Redis strong-control channel")?;
        let slot = hex_component(cluster.cluster_id.as_bytes());
        let membership_lease_ms = reconnect_backoff
            .as_millis()
            .saturating_mul(3)
            .max(u128::from(cluster.ack_deadline_ms.saturating_mul(3)))
            .max(u128::from(MIN_MEMBERSHIP_LEASE_MS))
            .min(u128::from(u64::MAX)) as u64;
        let (shutdown, _) = watch::channel(false);
        let control = Arc::new(Self {
            cluster,
            redis,
            channel: channel.into_boxed_str(),
            membership_key: format!("naway:edge:{{{slot}}}:strong:members").into_boxed_str(),
            fence_counter_key: format!("naway:edge:{{{slot}}}:strong:fence-seq").into_boxed_str(),
            command_timeout,
            reconnect_backoff,
            membership_lease_ms,
            hub,
            subscription_connected: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            active: AtomicBool::new(false),
            next_correlation: AtomicU64::new(1),
            pending_fences: DashMap::new(),
            shutdown,
        });
        // 在 Redis 内原子写回原 score，只复验候选具有 membership 所需权限，不让未发布代成为成员。
        control.probe_membership_permissions().await?;

        let consumer = control.clone();
        let mut consumer_shutdown = consumer.shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    changed = consumer_shutdown.changed() => {
                        if changed.is_err() || *consumer_shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                    message = subscription.next_message() => message,
                };
                match message {
                    Some(message) => {
                        if !consumer.active.load(Ordering::Acquire) {
                            continue;
                        }
                        if message.channel == consumer.channel.as_ref() {
                            if let Err(error) =
                                consumer.consume_control(Bytes::from(message.payload)).await
                            {
                                tracing::warn!(
                                    error = %format!("{error:#}"),
                                    "edge Redis strong-control envelope rejected"
                                );
                            }
                        }
                    }
                    None => {
                        // 控制订阅一旦失联，旧会话必须先保护再退出 membership；否则其他节点
                        // 会在租约过期后放行新会话，而本节点仍保留旧连接，形成多活。
                        consumer
                            .subscription_connected
                            .store(false, Ordering::Release);
                        consumer.enter_protection();
                        tokio::time::sleep(consumer.reconnect_backoff).await;
                        if subscription
                            .reconnect_timeout(consumer.command_timeout)
                            .await
                            .is_ok()
                        {
                            consumer
                                .subscription_connected
                                .store(true, Ordering::Release);
                            if consumer.refresh_membership().await.is_ok() {
                                consumer.ready.store(true, Ordering::Release);
                            }
                        }
                    }
                }
            }
        });

        let heartbeat = control.clone();
        let mut heartbeat_shutdown = heartbeat.shutdown.subscribe();
        tokio::spawn(async move {
            let period = Duration::from_millis((heartbeat.membership_lease_ms / 3).max(100));
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                tokio::select! {
                    changed = heartbeat_shutdown.changed() => {
                        if changed.is_err() || *heartbeat_shutdown.borrow() {
                            return;
                        }
                    }
                    _ = ticker.tick() => {}
                }
                if !heartbeat.subscription_connected.load(Ordering::Acquire) {
                    continue;
                }
                if !heartbeat.active.load(Ordering::Acquire) {
                    continue;
                }
                match heartbeat.refresh_membership().await {
                    Ok(()) => heartbeat.ready.store(true, Ordering::Release),
                    Err(error) => {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "edge Redis strong-control membership heartbeat failed"
                        );
                        // 心跳失败意味着节点即将从权威快照消失；立即停止本地旧 token。
                        heartbeat.enter_protection();
                    }
                }
            }
        });
        Ok(control)
    }

    /// 业务作用：在数据总线提交后登记 membership 并接管本地 session fencing 权威。
    ///
    /// 参数说明: 无。
    ///
    /// 控制订阅与 Redis 写权限已在 prepare 阶段验证。
    ///
    /// 返回：首次 membership 心跳成功时获得权威；网络在提交窗口失效则进入保护态并失败。
    async fn activate(self: &Arc<Self>) -> Result<()> {
        anyhow::ensure!(
            !self.active.swap(true, Ordering::AcqRel),
            "edge Redis strong-control generation is already active"
        );
        let session_control: Arc<dyn EdgeSessionControl> = self.clone();
        self.hub
            .attach_session_control(Arc::downgrade(&session_control));
        if let Err(error) = self.refresh_membership().await {
            self.active.store(false, Ordering::Release);
            self.enter_protection();
            return Err(error).context("activate edge Redis membership");
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// 业务作用：撤销本 Redis strong-control 代的 claim 权威并从 membership 中幂等移除。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；清理网络失败只保留有租约的旧成员，本地已立即进入保护态。
    async fn shutdown(&self) {
        let was_active = self.active.swap(false, Ordering::AcqRel);
        self.subscription_connected.store(false, Ordering::Release);
        let _ = self.shutdown.send(true);
        if !was_active {
            self.ready.store(false, Ordering::Release);
            return;
        }
        // 旧代先保护所有本地 token，再从 membership 移除；新代只能在此步骤完成后激活。
        self.enter_protection();
        const REMOVE_MEMBER: &str = "return redis.call('ZREM', KEYS[1], ARGV[1])";
        let result = tokio::time::timeout(
            self.command_timeout,
            self.redis.eval::<i64>(
                REMOVE_MEMBER,
                &[self.membership_key.as_ref()],
                &[self.cluster.node_id.as_ref()],
            ),
        )
        .await;
        if !matches!(result, Ok(Ok(_))) {
            tracing::warn!("edge Redis strong-control membership cleanup failed");
        }
    }

    /// 业务作用：用 Redis TIME 刷新本节点 membership score，避免应用节点时钟偏差改变租约生死。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：Redis 在命令期限内接受心跳时成功，否则返回错误且调用方进入保护态。
    async fn refresh_membership(&self) -> Result<()> {
        const SCRIPT: &str = r#"
local now = redis.call('TIME')
local ms = now[1] * 1000 + math.floor(now[2] / 1000)
redis.call('ZADD', KEYS[1], ms, ARGV[1])
return ms
"#;
        let _: i64 = tokio::time::timeout(
            self.command_timeout,
            self.redis.eval(
                SCRIPT,
                &[self.membership_key.as_ref()],
                &[self.cluster.node_id.as_ref()],
            ),
        )
        .await
        .context("refresh edge Redis membership timeout")??;
        Ok(())
    }

    /// 业务作用：原子复验 Redis ACL 覆盖 membership 所需命令，但把 key 恢复到调用前的精确事实。
    ///
    /// 参数说明: 无。
    ///
    /// 使用当前 cluster/node 固定键。
    ///
    /// 返回：EVAL/ZADD/ZREM/ZSCORE 全部获准时成功；无权限或依赖失败拒绝候选。
    async fn probe_membership_permissions(&self) -> Result<()> {
        const PROBE: &str = r#"
local old = redis.call('ZSCORE', KEYS[1], ARGV[1])
redis.call('ZADD', KEYS[1], 0, ARGV[1])
if old then
  redis.call('ZADD', KEYS[1], old, ARGV[1])
else
  redis.call('ZREM', KEYS[1], ARGV[1])
end
return 1
"#;
        let result = tokio::time::timeout(
            self.command_timeout,
            self.redis.eval::<i64>(
                PROBE,
                &[self.membership_key.as_ref()],
                &[self.cluster.node_id.as_ref()],
            ),
        )
        .await
        .context("probe edge Redis membership permissions timeout")??;
        anyhow::ensure!(result == 1, "edge Redis membership permission probe failed");
        Ok(())
    }

    /// 业务作用：把控制权丢失原子映射为本地保护态，并唤醒所有等待中的 claim 立即失败。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；重复调用幂等。
    fn enter_protection(&self) {
        self.ready.store(false, Ordering::Release);
        self.hub.protect_single_sessions();
        for waiter in &self.pending_fences {
            waiter.notify.notify_waiters();
        }
    }

    /// 业务作用：由 Redis 原子分配全局单调 token、截取活跃 membership，并等待全体节点先落 fence 后 ACK。
    ///
    /// 参数说明：
    /// - `tenant`：是已经通过身份与长度门的 single-session 作用域。
    /// - `user`：是已经通过身份与长度门的 single-session 作用域。
    ///
    /// 返回：全体快照节点 ACK、Redis 当前 token 与本地 fence 三重复验通过后返回 token；
    /// 控制失联、节点缺席、并发新 claim 或超时均 fail closed。
    async fn claim_single_session(
        &self,
        tenant: Arc<str>,
        user: Arc<str>,
    ) -> Result<u64, &'static str> {
        if !self.ready.load(Ordering::Acquire) {
            return Err("edge-redis-session-control-unavailable");
        }
        const CLAIM_SCRIPT: &str = r#"
local now = redis.call('TIME')
local ms = now[1] * 1000 + math.floor(now[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ms - tonumber(ARGV[1]))
local token = redis.call('INCR', KEYS[2])
redis.call('SET', KEYS[3], token)
local members = redis.call('ZRANGE', KEYS[1], 0, -1)
return {token, members}
"#;
        let fence_key = self.fence_key(&tenant, &user);
        let lease = self.membership_lease_ms.to_string();
        let claim: (i64, Vec<String>) = match tokio::time::timeout(
            self.command_timeout,
            self.redis.eval(
                CLAIM_SCRIPT,
                &[
                    self.membership_key.as_ref(),
                    self.fence_counter_key.as_ref(),
                    fence_key.as_str(),
                ],
                &[lease.as_str()],
            ),
        )
        .await
        {
            Ok(Ok(claim)) => claim,
            _ => return Err("edge-redis-session-claim-failed"),
        };
        let token = u64::try_from(claim.0)
            .ok()
            .filter(|token| *token != 0)
            .ok_or("edge-redis-session-token-invalid")?;
        let expected: HashSet<String> = claim.1.into_iter().collect();
        if expected.is_empty() || !expected.contains(self.cluster.node_id.as_ref()) {
            return Err("edge-redis-session-membership-incomplete");
        }
        let correlation_id = next_correlation(&self.next_correlation);
        let waiter = Arc::new(FenceAckWaiter::new(token, expected));
        let payload = encode_envelope(
            RedisFanoutAction::SessionFence,
            self.cluster.cluster_id.as_ref(),
            &tenant,
            &user,
            self.cluster.node_id.as_ref(),
            &[],
            EnvelopeControl {
                correlation_id,
                revision: token,
            },
        )
        .map_err(|_| "edge-redis-session-envelope-invalid")?;
        self.pending_fences.insert(correlation_id, waiter.clone());
        let published = tokio::time::timeout(
            self.command_timeout,
            self.redis.r#pub(self.channel.as_ref(), payload.as_ref()),
        )
        .await;
        if !matches!(published, Ok(Ok(_))) {
            self.pending_fences.remove(&correlation_id);
            return Err("edge-redis-session-fence-publish-failed");
        }
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.cluster.ack_deadline_ms);
        let acknowledged = loop {
            if waiter.complete() {
                break true;
            }
            if !self.ready.load(Ordering::Acquire) {
                break false;
            }
            if tokio::time::timeout_at(deadline, waiter.notify.notified())
                .await
                .is_err()
            {
                break false;
            }
        };
        self.pending_fences.remove(&correlation_id);
        if !acknowledged {
            return Err("edge-redis-session-fence-ack-timeout");
        }
        // ACK 只证明各节点处理过本次 fence；必须再读 Redis 权威值并复验本地 token，
        // 才能阻止并发更新更高 token 后旧 claim 反过来登记会话。
        let current =
            tokio::time::timeout(self.command_timeout, self.redis.get::<i64>(&fence_key)).await;
        if !matches!(current, Ok(Ok(Some(value))) if value == claim.0)
            || !self.hub.session_fence_matches(&tenant, &user, token)
            || !self.ready.load(Ordering::Acquire)
        {
            return Err("edge-redis-session-claim-lost");
        }
        Ok(token)
    }

    /// 业务作用：消费 fence/ACK/release 控制 envelope，并保持“先本地保护、后发 ACK”的安全时序。
    ///
    /// 参数说明：
    /// - `payload`：是独立控制频道收到的版本化 envelope。
    ///
    /// 返回：合法控制动作完成时成功；畸形、跨 cluster 或数据动作混入时返回错误。
    async fn consume_control(&self, payload: Bytes) -> Result<()> {
        let envelope = decode_envelope(payload, self.cluster.fanout_limits.max_msg_bytes)?;
        if envelope.cluster_id != self.cluster.cluster_id.as_ref() {
            bail!("Redis strong-control cluster_id mismatch");
        }
        match envelope.action {
            RedisFanoutAction::SessionFence => {
                if envelope.correlation_id == 0
                    || envelope.revision == 0
                    || envelope.origin_node_id.is_empty()
                {
                    bail!("invalid Redis session fence");
                }
                // 旧会话必须在 ACK 前关闭；否则 claim 看到 ACK 后放行新连接会制造短暂多活。
                self.hub.fence_single_session(
                    Arc::from(envelope.tenant.as_str()),
                    Arc::from(envelope.scope.as_str()),
                    envelope.revision,
                );
                let ack = encode_envelope(
                    RedisFanoutAction::SessionFenceAck,
                    self.cluster.cluster_id.as_ref(),
                    &envelope.tenant,
                    &envelope.scope,
                    self.cluster.node_id.as_ref(),
                    &[],
                    EnvelopeControl {
                        correlation_id: envelope.correlation_id,
                        revision: envelope.revision,
                    },
                )?;
                tokio::time::timeout(
                    self.command_timeout,
                    self.redis.r#pub(self.channel.as_ref(), ack.as_ref()),
                )
                .await
                .context("publish Redis session fence ACK timeout")??;
            }
            RedisFanoutAction::SessionFenceAck => {
                if let Some(waiter) = self.pending_fences.get(&envelope.correlation_id) {
                    if waiter.revision == envelope.revision {
                        waiter.acknowledge(envelope.origin_node_id);
                    }
                }
            }
            RedisFanoutAction::SessionRelease => {
                self.hub.release_session_fence(
                    &envelope.tenant,
                    &envelope.scope,
                    envelope.revision,
                );
            }
            RedisFanoutAction::Publish | RedisFanoutAction::Push => {
                bail!("data action received on Redis strong-control channel")
            }
        }
        Ok(())
    }

    /// 业务作用：构造与 membership/counter 同 Redis Cluster slot 的用户当前-token key。
    ///
    /// 参数说明：
    /// - `tenant`：是已验证身份；编码后不会把业务字符解释成 Redis hashtag。
    /// - `user`：是已验证身份；编码后不会把业务字符解释成 Redis hashtag。
    ///
    /// 返回：返回可安全用于多 key Lua 的同槽 key。
    fn fence_key(&self, tenant: &str, user: &str) -> String {
        let slot = hex_component(self.cluster.cluster_id.as_bytes());
        format!(
            "naway:edge:{{{slot}}}:strong:fence:{}:{}",
            hex_component(tenant.as_bytes()),
            hex_component(user.as_bytes())
        )
    }
}

impl EdgeSessionControl for RedisStrongControl {
    /// 业务作用：条件删除仍属于已结束会话的 Redis 当前 token，并广播本地 fence 清理。
    ///
    /// 参数说明：
    /// - `tenant`：标识用户
    /// - `user`：标识用户
    /// - `token`：是结束会话持有的版本。
    ///
    /// 返回：无返回值；迟到 release 遇到更高 token 时 Lua 不删除也不广播。
    fn session_closed(&self, tenant: Arc<str>, user: Arc<str>, token: u64) {
        self.hub.release_session_fence(&tenant, &user, token);
        let redis = self.redis.clone();
        let command_timeout = self.command_timeout;
        let fence_key = self.fence_key(&tenant, &user);
        let channel = self.channel.clone();
        let cluster_id = self.cluster.cluster_id.clone();
        let node_id = self.cluster.node_id.clone();
        let token_text = token.to_string();
        let payload = encode_envelope(
            RedisFanoutAction::SessionRelease,
            &cluster_id,
            &tenant,
            &user,
            &node_id,
            &[],
            EnvelopeControl {
                correlation_id: 0,
                revision: token,
            },
        );
        tokio::spawn(async move {
            const RELEASE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;
            let deleted = tokio::time::timeout(
                command_timeout,
                redis.eval::<i64>(
                    RELEASE_SCRIPT,
                    &[fence_key.as_str()],
                    &[token_text.as_str()],
                ),
            )
            .await;
            if matches!(deleted, Ok(Ok(1))) {
                if let Ok(payload) = payload {
                    let _ = tokio::time::timeout(
                        command_timeout,
                        redis.r#pub(channel.as_ref(), payload.as_ref()),
                    )
                    .await;
                }
            }
        });
    }
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
    /// 业务作用：报告当前总线连接状态，供管理读面判断共享传输是否可用。
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线成功发布次数的只读事实，不将入队确认解释为终端送达。
    pub fn published_total(&self) -> u64 {
        self.published_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线接收次数的只读事实，供传输层观测使用。
    pub fn received_total(&self) -> u64 {
        self.received_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线拒绝次数，区分协议或权限拒绝与成功接收。
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }
    /// 业务作用：提供总线发布失败次数，不把未知投递结果当作成功。
    pub fn publish_failed_total(&self) -> u64 {
        self.publish_failed_total.load(Ordering::Relaxed)
    }
    /// 业务作用：报告总线重连次数，便于识别传输持续抖动。
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
    next_correlation: AtomicU64,
    pending_fanout: PendingFanout,
    strong_control: Option<Arc<RedisStrongControl>>,
    shutdown: watch::Sender<bool>,
    active: AtomicBool,
}

impl EdgeRedisBus {
    /// 业务作用：建立 Redis Pub/Sub 数据订阅，并在启用 single-session 时先启动强控制面。
    ///
    /// 参数说明：
    /// - `cluster`：是已校验集群计划
    /// - `hub`：是进程唯一订阅索引。
    ///
    /// 返回：数据与所需控制订阅均 ready 后返回总线；连接或订阅失败则拒绝启动。
    pub async fn start(cluster: Arc<GrpcEdgeClusterPlan>, hub: Arc<EdgeHub>) -> Result<Arc<Self>> {
        let bus = Self::prepare(cluster, hub).await?;
        bus.activate().await?;
        Ok(bus)
    }

    /// 业务作用：连接并订阅 Redis Pub/Sub 候选，但发布前不消费消息、不登记成员或接管 session。
    ///
    /// 参数说明：
    /// - `cluster`：是候选集群计划
    /// - `hub`：是共享订阅索引。
    ///
    /// 返回：连接、SUBSCRIBE 与 ACL 探针均成功时返回休眠候选；失败不改变在线 owner。
    pub async fn prepare(
        cluster: Arc<GrpcEdgeClusterPlan>,
        hub: Arc<EdgeHub>,
    ) -> Result<Arc<Self>> {
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
        let strong_control = if cluster.session_mode == GrpcEdgeSessionModeCfg::SingleSession {
            Some(
                RedisStrongControl::prepare(
                    cluster.clone(),
                    redis.clone(),
                    redis_plan.channel.as_ref(),
                    redis_plan.command_timeout,
                    redis_plan.reconnect_backoff,
                    hub.clone(),
                )
                .await?,
            )
        } else {
            None
        };
        let (shutdown, _) = watch::channel(false);
        let bus = Arc::new(Self {
            cluster,
            redis,
            redis_plan,
            hub,
            metrics: Arc::new(EdgeRedisBusMetrics::default()),
            next_correlation: AtomicU64::new(1),
            pending_fanout: DashMap::new(),
            strong_control,
            shutdown,
            active: AtomicBool::new(false),
        });
        let consumer = bus.clone();
        let mut consumer_shutdown = consumer.shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    changed = consumer_shutdown.changed() => {
                        if changed.is_err() || *consumer_shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                    message = subscription.next_message() => message,
                };
                match message {
                    Some(message) => {
                        if !consumer.active.load(Ordering::Acquire) {
                            continue;
                        }
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

    /// 业务作用：提交 Pub/Sub 候选后授予 strong-control 与消息消费权，随后才允许请求使用该代。
    ///
    /// 参数说明: 无。
    ///
    /// 对象必须来自 `prepare` 且旧代已撤权。
    ///
    /// 返回：membership 激活成功后返回；重复激活或 Redis 失联失败闭合。
    pub async fn activate(self: &Arc<Self>) -> Result<()> {
        anyhow::ensure!(
            !self.active.load(Ordering::Acquire),
            "edge Redis Pub/Sub generation is already active"
        );
        if let Some(control) = &self.strong_control {
            control.activate().await?;
        }
        self.active.store(true, Ordering::Release);
        self.metrics.connected.store(true, Ordering::Release);
        Ok(())
    }

    /// 业务作用：撤销 Pub/Sub 代的新发布与控制权，并停止数据/强控制订阅。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；已在途 Redis 命令按原 deadline 结算，不再开始新订阅循环。
    pub async fn shutdown(&self) {
        self.active.store(false, Ordering::Release);
        self.metrics.connected.store(false, Ordering::Release);
        let _ = self.shutdown.send(true);
        if let Some(control) = &self.strong_control {
            control.shutdown().await;
        }
    }

    /// 业务作用：暴露 Pub/Sub 数据面低基数指标快照句柄。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回与总线同生命周期的指标共享引用。
    pub fn metrics(&self) -> Arc<EdgeRedisBusMetrics> {
        self.metrics.clone()
    }

    /// 业务作用：判断发布入口是否必须把 Redis channel 当作唯一排序权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置为 `group_owner` 时返回 `true`。
    pub fn group_owner_enabled(&self) -> bool {
        self.cluster.ordering == GrpcEdgeOrderingCfg::GroupOwner
    }

    /// 业务作用：判断订阅入口是否必须先完成 Redis 全网 fencing claim。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置为 `single_session` 时返回 `true`。
    pub fn single_session_enabled(&self) -> bool {
        self.cluster.session_mode == GrpcEdgeSessionModeCfg::SingleSession
    }

    /// 业务作用：通过 Redis 强控制面完成 single-session claim 与全节点 fencing。
    ///
    /// 参数说明：
    /// - `tenant`：是已验证作用域。
    /// - `user`：是已验证作用域。
    ///
    /// 返回：全网 ACK 与最终复验成功后返回 token；未启用或控制失效时 fail closed。
    pub async fn claim_single_session(
        &self,
        tenant: Arc<str>,
        user: Arc<str>,
    ) -> Result<u64, &'static str> {
        if !self.active.load(Ordering::Acquire) {
            return Err("edge-redis-generation-inactive");
        }
        let Some(control) = &self.strong_control else {
            return Err("edge-redis-session-control-disabled");
        };
        control.claim_single_session(tenant, user).await
    }

    /// 业务作用：将已授权群播编码为总线信封，维持租户、群组和发布顺序的边界。
    pub async fn broadcast_publish(
        &self,
        tenant: &str,
        group: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Publish, tenant, group, frame)
            .await
    }

    /// 业务作用：把群播先写入 Redis 全局顺序，再等待本节点从同一订阅序列应用该消息。
    ///
    /// 参数说明：
    /// - `limits`：约束本地 fanout
    /// - `tenant`：是作用域
    /// - `group`：是作用域
    /// - `frame`：是完整 gRPC 帧
    /// - `reassembled`：是入口跨 DATA 重组字节。
    ///
    /// 返回：本地回环在 ACK deadline 内完成时返回真实散出结果；发布、失联或超时返回静态错误。
    pub async fn publish_group_owned(
        &self,
        limits: &crate::edge::config::GrpcEdgeLimitsPlan,
        tenant: Arc<str>,
        group: Arc<str>,
        frame: Bytes,
        reassembled: u64,
    ) -> Result<(LocalFanoutOutcome, PeerBroadcastSummary), &'static str> {
        if !self.active.load(Ordering::Acquire) || !self.metrics.connected.load(Ordering::Acquire) {
            return Err("edge-redis-group-order-unavailable");
        }
        let correlation_id = next_correlation(&self.next_correlation);
        let payload = encode_from_grpc_frame_with_control(
            RedisFanoutAction::Publish,
            self.cluster.cluster_id.as_ref(),
            &tenant,
            &group,
            self.cluster.node_id.as_ref(),
            &frame,
            EnvelopeControl {
                correlation_id,
                revision: 0,
            },
        )
        .map_err(|_| "edge-redis-group-envelope-invalid")?;
        let (tx, rx) = oneshot::channel();
        self.pending_fanout.insert(
            correlation_id,
            PendingFanoutEntry {
                sender: tx,
                limits: limits.clone(),
                reassembled,
            },
        );
        let published = tokio::time::timeout(
            self.redis_plan.command_timeout,
            self.redis
                .r#pub(self.redis_plan.channel.as_ref(), payload.as_ref()),
        )
        .await;
        if !matches!(published, Ok(Ok(_))) {
            self.pending_fanout.remove(&correlation_id);
            self.metrics
                .publish_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Err("edge-redis-group-publish-failed");
        }
        self.metrics.published_total.fetch_add(1, Ordering::Relaxed);
        let outcome =
            tokio::time::timeout(Duration::from_millis(self.cluster.ack_deadline_ms), rx).await;
        self.pending_fanout.remove(&correlation_id);
        match outcome {
            Ok(Ok(Ok(outcome))) => Ok((outcome, PeerBroadcastSummary::default())),
            Ok(Ok(Err(()))) => Err("edge-redis-group-local-fanout-rejected"),
            Ok(Err(_)) | Err(_) => Err("edge-redis-group-local-ack-timeout"),
        }
    }

    /// 业务作用：将已授权定向推送编码为总线信封，保留目标用户的作用域。
    pub async fn broadcast_push(
        &self,
        tenant: &str,
        target: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Push, tenant, target, frame)
            .await
    }

    /// 业务作用：向选定 Redis 传输发布完整路由信封，不解析业务 payload。
    async fn broadcast(
        &self,
        action: RedisFanoutAction,
        tenant: &str,
        scope: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        let mut summary = PeerBroadcastSummary::default();
        if !self.active.load(Ordering::Acquire) {
            summary.peers_rejected = 1;
            return summary;
        }
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

    /// 业务作用：验证收到的总线信封并执行本地散出，非法来源或路由身份不能进入订阅队列。
    async fn consume_one(&self, payload: Bytes) -> Result<()> {
        let envelope = decode_envelope(payload, self.cluster.fanout_limits.max_msg_bytes)?;
        if envelope.cluster_id != self.cluster.cluster_id.as_ref() {
            bail!("Redis envelope cluster_id mismatch");
        }
        let own_group_order = self.group_owner_enabled()
            && envelope.action == RedisFanoutAction::Publish
            && envelope.origin_node_id == self.cluster.node_id.as_ref()
            && envelope.correlation_id != 0;
        // 普通模式仍是 local-first，必须跳过自身回环；group_owner 则恰好相反：本机也只能
        // 从 Redis 排序序列散出，任何入口直发都会破坏跨节点同序。
        if envelope.origin_node_id == self.cluster.node_id.as_ref() && !own_group_order {
            return Ok(());
        }
        let frame = grpc_frame(envelope.message)?;
        match envelope.action {
            RedisFanoutAction::Publish => {
                let pending = own_group_order
                    .then(|| self.pending_fanout.remove(&envelope.correlation_id))
                    .flatten()
                    .map(|(_, pending)| pending);
                let limits = pending
                    .as_ref()
                    .map_or(&self.cluster.fanout_limits, |pending| &pending.limits);
                let reassembled = pending.as_ref().map_or(0, |pending| pending.reassembled);
                let result = self
                    .hub
                    .publish_group(
                        limits,
                        Arc::from(envelope.tenant.as_str()),
                        Arc::from(envelope.scope.as_str()),
                        frame,
                        reassembled,
                    )
                    .await;
                match result {
                    Ok(outcome) => {
                        if let Some(pending) = pending {
                            let _ = pending.sender.send(Ok(outcome));
                        }
                    }
                    Err(error) => {
                        if let Some(pending) = pending {
                            let _ = pending.sender.send(Err(()));
                        }
                        return Err(anyhow!("Redis publish fanout rejected: {}", error.reason()));
                    }
                }
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
            RedisFanoutAction::SessionFence
            | RedisFanoutAction::SessionFenceAck
            | RedisFanoutAction::SessionRelease => {
                bail!("control action received on Redis data channel")
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
    subscription: parking_lot::Mutex<Option<StreamSubscription>>,
    metrics: Arc<EdgeRedisStreamMetrics>,
    next_correlation: AtomicU64,
    pending_fanout: PendingFanout,
    strong_control: std::sync::OnceLock<Arc<RedisStrongControl>>,
    active: AtomicBool,
}

impl EdgeRedisStreamBus {
    /// 业务作用：建立每节点独立 XREAD cursor，并在所需时追加 Redis strong-control 订阅。
    ///
    /// 参数说明：
    /// - `cluster`：是已校验集群计划
    /// - `hub`：是进程唯一订阅索引。
    ///
    /// 返回：Stream 消费器与所需控制面均 ready 后返回；任一步失败则拒绝启动。
    pub async fn start(cluster: Arc<GrpcEdgeClusterPlan>, hub: Arc<EdgeHub>) -> Result<Arc<Self>> {
        let bus = Self::prepare(cluster, hub).await?;
        bus.activate().await?;
        Ok(bus)
    }

    /// 业务作用：连接 Redis、建立独立 XREAD 和 strong-control 候选，但发布前丢弃候选消费结果。
    ///
    /// 参数说明：
    /// - `cluster`：是候选计划
    /// - `hub`：是共享订阅索引。
    ///
    /// 返回：cursor/trim 探测、订阅和 ACL 探针成功时返回休眠候选；失败不接管数据面。
    pub async fn prepare(
        cluster: Arc<GrpcEdgeClusterPlan>,
        hub: Arc<EdgeHub>,
    ) -> Result<Arc<Self>> {
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
            subscription: parking_lot::Mutex::new(None),
            metrics: Arc::new(EdgeRedisStreamMetrics::default()),
            next_correlation: AtomicU64::new(1),
            pending_fanout: DashMap::new(),
            strong_control: std::sync::OnceLock::new(),
            active: AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&bus);
        let cfg = StreamSubscribeCfg {
            mode: StreamMode::Broadcast {
                start,
            },
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
                    if !bus.active.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    bus.consume_stream_entry(event.id, Bytes::from(event.raw))
                        .await
                        .map_err(|error| format!("{error:#}"))
                }
            })
            .start()
            .await
            .context("start edge Redis Stream XREAD subscription")?;
        *bus.subscription.lock() = Some(subscription);
        if bus.cluster.session_mode == GrpcEdgeSessionModeCfg::SingleSession {
            let control = RedisStrongControl::prepare(
                bus.cluster.clone(),
                bus.redis.clone(),
                bus.redis_plan.stream.as_ref(),
                bus.redis_plan.command_timeout,
                bus.redis_plan.reconnect_backoff,
                bus.hub.clone(),
            )
            .await?;
            let _ = bus.strong_control.set(control);
        }
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

    /// 业务作用：旧代撤权后激活 Stream strong-control 与 XREAD 消费副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 候选连接和权限已在 prepare 阶段复验。
    ///
    /// 返回：membership 激活成功时授予业务权威；重复激活或提交时依赖故障失败。
    pub async fn activate(self: &Arc<Self>) -> Result<()> {
        anyhow::ensure!(
            !self.active.load(Ordering::Acquire),
            "edge Redis Stream generation is already active"
        );
        if let Some(control) = self.strong_control.get() {
            control.activate().await?;
        }
        self.active.store(true, Ordering::Release);
        Ok(())
    }

    /// 业务作用：撤销 Stream 代的新发布与控制权，并协作取消 XREAD/强控制订阅。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；方法返回时 XREAD worker 已确认停止，成员租约已尝试幂等清理。
    pub async fn shutdown(&self) {
        self.active.store(false, Ordering::Release);
        if let Some(control) = self.strong_control.get() {
            control.shutdown().await;
        }
        let subscription = {
            self.subscription.lock().take()
        };
        if let Some(subscription) = subscription {
            subscription.shutdown().await;
        }
    }

    /// 业务作用：暴露 Redis Stream 数据面低基数指标快照句柄。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回与总线同生命周期的指标共享引用。
    pub fn metrics(&self) -> Arc<EdgeRedisStreamMetrics> {
        self.metrics.clone()
    }

    /// 业务作用：判断发布入口是否必须把 Redis Stream entry 顺序当作唯一排序权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置为 `group_owner` 时返回 `true`。
    pub fn group_owner_enabled(&self) -> bool {
        self.cluster.ordering == GrpcEdgeOrderingCfg::GroupOwner
    }

    /// 业务作用：判断订阅入口是否必须先完成 Redis 全网 fencing claim。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置为 `single_session` 时返回 `true`。
    pub fn single_session_enabled(&self) -> bool {
        self.cluster.session_mode == GrpcEdgeSessionModeCfg::SingleSession
    }

    /// 业务作用：通过 Redis 强控制面完成 single-session claim 与全节点 fencing。
    ///
    /// 参数说明：
    /// - `tenant`：是已验证作用域。
    /// - `user`：是已验证作用域。
    ///
    /// 返回：全网 ACK 与最终复验成功后返回 token；未启用或控制失效时 fail closed。
    pub async fn claim_single_session(
        &self,
        tenant: Arc<str>,
        user: Arc<str>,
    ) -> Result<u64, &'static str> {
        if !self.active.load(Ordering::Acquire) {
            return Err("edge-redis-generation-inactive");
        }
        let Some(control) = self.strong_control.get() else {
            return Err("edge-redis-session-control-disabled");
        };
        control.claim_single_session(tenant, user).await
    }

    /// 业务作用：将已授权群播编码为总线信封，维持租户、群组和发布顺序的边界。
    pub async fn broadcast_publish(
        &self,
        tenant: &str,
        group: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Publish, tenant, group, frame)
            .await
    }

    /// 业务作用：把群播先 XADD 到 Redis 全局顺序，再等待本节点 XREAD 应用同一 entry。
    ///
    /// 参数说明：
    /// - `limits`：约束入口本地 fanout
    /// - `tenant`：是作用域
    /// - `group`：是作用域
    /// - `frame`：是完整 gRPC 帧
    /// - `reassembled`：是入口跨 DATA 重组字节。
    ///
    /// 返回：本地 cursor 消费在 ACK deadline 内完成时返回真实散出结果；写入、消费或超时失败则 fail closed。
    pub async fn publish_group_owned(
        &self,
        limits: &crate::edge::config::GrpcEdgeLimitsPlan,
        tenant: Arc<str>,
        group: Arc<str>,
        frame: Bytes,
        reassembled: u64,
    ) -> Result<(LocalFanoutOutcome, PeerBroadcastSummary), &'static str> {
        if !self.active.load(Ordering::Acquire) {
            return Err("edge-redis-group-order-unavailable");
        }
        let correlation_id = next_correlation(&self.next_correlation);
        let payload = encode_from_grpc_frame_with_control(
            RedisFanoutAction::Publish,
            self.cluster.cluster_id.as_ref(),
            &tenant,
            &group,
            self.cluster.node_id.as_ref(),
            &frame,
            EnvelopeControl {
                correlation_id,
                revision: 0,
            },
        )
        .map_err(|_| "edge-redis-group-envelope-invalid")?;
        let (tx, rx) = oneshot::channel();
        self.pending_fanout.insert(
            correlation_id,
            PendingFanoutEntry {
                sender: tx,
                limits: limits.clone(),
                reassembled,
            },
        );
        let fields = [(REDIS_STREAM_FIELD, payload.as_ref())];
        let published = tokio::time::timeout(
            self.redis_plan.command_timeout,
            self.redis
                .x_add_bytes(self.redis_plan.stream.as_ref(), "*", &fields),
        )
        .await;
        if !matches!(published, Ok(Ok(_))) {
            self.pending_fanout.remove(&correlation_id);
            self.metrics
                .publish_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Err("edge-redis-group-publish-failed");
        }
        self.metrics.published_total.fetch_add(1, Ordering::Relaxed);
        let outcome =
            tokio::time::timeout(Duration::from_millis(self.cluster.ack_deadline_ms), rx).await;
        self.pending_fanout.remove(&correlation_id);
        match outcome {
            Ok(Ok(Ok(outcome))) => Ok((outcome, PeerBroadcastSummary::default())),
            Ok(Ok(Err(()))) => Err("edge-redis-group-local-fanout-rejected"),
            Ok(Err(_)) | Err(_) => Err("edge-redis-group-local-ack-timeout"),
        }
    }

    /// 业务作用：将已授权定向推送编码为总线信封，保留目标用户的作用域。
    pub async fn broadcast_push(
        &self,
        tenant: &str,
        target: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        self.broadcast(RedisFanoutAction::Push, tenant, target, frame)
            .await
    }

    /// 业务作用：向选定 Redis 传输发布完整路由信封，不解析业务 payload。
    async fn broadcast(
        &self,
        action: RedisFanoutAction,
        tenant: &str,
        scope: &str,
        frame: Bytes,
    ) -> PeerBroadcastSummary {
        let mut summary = PeerBroadcastSummary::default();
        if !self.active.load(Ordering::Acquire) {
            summary.peers_rejected = 1;
            return summary;
        }
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

    /// 业务作用：处理 Redis Stream 的一条记录并推进消费位置，区分接收事实与终端投递保证。
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

    /// 业务作用：把验证后的流记录交给统一边缘散出内核，复用节点预算和会话授权域。
    async fn fanout_stream_payload(&self, payload: Bytes) -> Result<()> {
        let envelope = decode_envelope(payload, self.cluster.fanout_limits.max_msg_bytes)?;
        if envelope.cluster_id != self.cluster.cluster_id.as_ref() {
            bail!("Redis Stream envelope cluster_id mismatch");
        }
        let own_group_order = self.group_owner_enabled()
            && envelope.action == RedisFanoutAction::Publish
            && envelope.origin_node_id == self.cluster.node_id.as_ref()
            && envelope.correlation_id != 0;
        if envelope.origin_node_id == self.cluster.node_id.as_ref() && !own_group_order {
            return Ok(());
        }
        let frame = grpc_frame(envelope.message)?;
        match envelope.action {
            RedisFanoutAction::Publish => {
                let pending = own_group_order
                    .then(|| self.pending_fanout.remove(&envelope.correlation_id))
                    .flatten()
                    .map(|(_, pending)| pending);
                let limits = pending
                    .as_ref()
                    .map_or(&self.cluster.fanout_limits, |pending| &pending.limits);
                let reassembled = pending.as_ref().map_or(0, |pending| pending.reassembled);
                let result = self
                    .hub
                    .publish_group(
                        limits,
                        Arc::from(envelope.tenant.as_str()),
                        Arc::from(envelope.scope.as_str()),
                        frame,
                        reassembled,
                    )
                    .await;
                match result {
                    Ok(outcome) => {
                        if let Some(pending) = pending {
                            let _ = pending.sender.send(Ok(outcome));
                        }
                    }
                    Err(error) => {
                        if let Some(pending) = pending {
                            let _ = pending.sender.send(Err(()));
                        }
                        return Err(anyhow!(
                            "Redis Stream publish fanout rejected: {}",
                            error.reason()
                        ));
                    }
                }
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
            RedisFanoutAction::SessionFence
            | RedisFanoutAction::SessionFenceAck
            | RedisFanoutAction::SessionRelease => {
                bail!("control action received on Redis Stream data key")
            }
        }
        Ok(())
    }
}

/// 业务作用：冻结 Redis 能力约束，使总线只使用声明兼容的命令与模式。
fn compatibility_profile(raw: &str) -> CompatibilityProfile {
    match raw.to_ascii_lowercase().replace('-', "").as_str() {
        "rustv2" => CompatibilityProfile::RustV2,
        "legacyv1" => CompatibilityProfile::LegacyV1,
        _ => unreachable!("profile was validated while building the cluster plan"),
    }
}

/// 业务作用：生成进程内非零 correlation id，供 pending map 与 Redis 回环唯一关联。
///
/// 参数说明：
/// - `counter`：是对应总线或控制面的单调计数器。
///
/// 返回：返回非零 id；u64 回绕到零时跳过零值，保留零作为“无需本地回执”的协议标记。
fn next_correlation(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::Relaxed);
        if value != 0 {
            return value;
        }
    }
}

/// 业务作用：把业务身份编码成不会注入 Redis key 分隔符或 hashtag 的稳定 ASCII 组件。
///
/// 参数说明：
/// - `bytes`：是已经过业务长度门的 UTF-8/ASCII 身份字节。
///
/// 返回：返回小写十六进制字符串。
fn hex_component(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 业务作用：业务侧直接发布群消息时使用；`origin_node_id` 固定为空，使每个 Naway 节点都消费。
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
        EnvelopeControl::default(),
    )
}

/// Redis envelope 中只供强顺序/fencing 使用的控制元数据。
#[derive(Clone, Copy, Default)]
struct EnvelopeControl {
    correlation_id: u64,
    revision: u64,
}

/// 业务作用：从合法 gRPC 帧构建总线路由信封，不改变业务消息字节。
fn encode_from_grpc_frame(
    action: RedisFanoutAction,
    cluster_id: &str,
    tenant: &str,
    scope: &str,
    origin_node_id: &str,
    frame: &[u8],
) -> Result<Bytes> {
    encode_from_grpc_frame_with_control(
        action,
        cluster_id,
        tenant,
        scope,
        origin_node_id,
        frame,
        EnvelopeControl::default(),
    )
}

/// 业务作用：校验完整 gRPC 帧并编码带排序 correlation/fencing revision 的 Redis envelope。
///
/// 参数说明：
/// - `action`：定义路由
/// - `cluster_id`：定义路由
/// - `tenant`：定义路由
/// - `scope`：定义路由
/// - `origin_node_id`：定义路由
/// - `frame`：是 identity-compression gRPC 帧
/// - `control`：关联本地排序回执并承载 fencing 版本。
///
/// 返回：帧合法时返回版本化 envelope；压缩、长度不符或路由非法时返回错误。
fn encode_from_grpc_frame_with_control(
    action: RedisFanoutAction,
    cluster_id: &str,
    tenant: &str,
    scope: &str,
    origin_node_id: &str,
    frame: &[u8],
    control: EnvelopeControl,
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
        control,
    )
}

/// 业务作用：生成 Redis 数据/控制面共享的向后兼容 protobuf envelope。
///
/// 参数说明：
/// - `action`：待编码的总线动作。
/// - `cluster_id`：固定集群隔离标识。
/// - `tenant`：已验证的租户身份。
/// - `scope`：动作对应的 group 或 user 范围。
/// - `origin_node_id`：消息来源节点标识。
/// - `message`：不透明的业务消息。
/// - `control`：强排序或 fencing 动作所需的 correlation 与 revision。
///
/// 返回：路由字段合法时返回编码；非法身份立即拒绝，避免污染共享 channel/stream。
fn encode_envelope(
    action: RedisFanoutAction,
    cluster_id: &str,
    tenant: &str,
    scope: &str,
    origin_node_id: &str,
    message: &[u8],
    control: EnvelopeControl,
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
    if control.correlation_id != 0 {
        put_varint_field(&mut out, 8, control.correlation_id);
    }
    if control.revision != 0 {
        put_varint_field(&mut out, 9, control.revision);
    }
    Ok(out.freeze())
}

/// 业务作用：有界解码 Redis envelope，拒绝重复字段、非法 wire、跨上限 message 与未知动作。
///
/// 参数说明：
/// - `input`：是 Redis payload
/// - `max_message_bytes`：是业务 protobuf message 硬上限。
///
/// 返回：合法时返回独立路由字段与零拷贝 message slice；畸形输入返回错误且不会触发 fanout。
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
    let mut correlation_id = None;
    let mut revision = None;
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
            8 if wire == 0 => set_once(
                &mut correlation_id,
                take_varint(&input, &mut pos)?,
                "correlation_id",
            )?,
            9 if wire == 0 => set_once(&mut revision, take_varint(&input, &mut pos)?, "revision")?,
            _ => skip_field(&input, &mut pos, wire)?,
        }
    }
    if version != Some(PROTOCOL_VERSION as u64) {
        bail!("unsupported Redis envelope protocol_version");
    }
    let action = match action {
        Some(1) => RedisFanoutAction::Publish,
        Some(2) => RedisFanoutAction::Push,
        Some(3) => RedisFanoutAction::SessionFence,
        Some(4) => RedisFanoutAction::SessionFenceAck,
        Some(5) => RedisFanoutAction::SessionRelease,
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
        correlation_id: correlation_id.unwrap_or(0),
        revision: revision.unwrap_or(0),
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
/// - `redis`：固定身份与预算的 Redis 客户端。
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

/// 业务作用：比较两个 Redis Stream entry id(`<ms>-<seq>`)。
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

/// 业务作用：为总线携带的 protobuf 消息恢复标准 gRPC 前缀，供订阅响应复用。
fn grpc_frame(message: Bytes) -> Result<Bytes> {
    let len = u32::try_from(message.len()).context("FramePush message exceeds gRPC u32 limit")?;
    let mut out = BytesMut::with_capacity(GRPC_PREFIX_BYTES + message.len());
    out.put_u8(0);
    out.put_u32(len);
    out.extend_from_slice(&message);
    Ok(out.freeze())
}

/// 业务作用：检查总线信封的租户、群组或用户边界，拒绝含糊或缺失的投递目标。
fn validate_routing(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ROUTING_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("invalid Redis envelope {name}");
    }
    Ok(())
}

/// 业务作用：拒绝同一信封字段重复赋值，避免不同解析器采用不同身份值。
fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("duplicate Redis envelope field {name}");
    }
    Ok(())
}

/// 业务作用：按 protobuf 字段号编码整数元数据，不依赖内存结构布局。
fn put_varint_field(out: &mut BytesMut, field: u32, value: u64) {
    put_varint(out, (field as u64) << 3);
    put_varint(out, value);
}

/// 业务作用：编码有界的长度分隔字段，使路由元数据与业务载荷保持清晰边界。
fn put_bytes_field(out: &mut BytesMut, field: u32, value: &[u8]) {
    put_varint(out, ((field as u64) << 3) | 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// 业务作用：编码信封长度和整数标识，保持 Redis 传输与本地 wire 合同一致。
fn put_varint(out: &mut BytesMut, mut value: u64) {
    while value >= 0x80 {
        out.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

/// 业务作用：读取并校验变长整数，截断或溢出时拒绝整个总线信封。
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

/// 业务作用：根据已验证长度提取信封字段，拒绝越界切片与长度溢出。
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

/// 业务作用：把路由字段解码为合法 UTF-8 文本，不允许损坏身份参与寻址。
fn take_string(input: &Bytes, pos: &mut usize) -> Result<String> {
    String::from_utf8(take_bytes(input, pos)?.to_vec()).context("routing field is not UTF-8")
}

/// 业务作用：跳过兼容扩展字段且仍验证 wire 边界，未知字段不能绕过长度检查。
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
