//! 共享流量准入、逐帧整形与响应事实结算。

use super::*;

mod identity;
#[cfg(feature = "redis-runtime")]
mod remote;
#[cfg(feature = "redis-runtime")]
mod remote_body;
#[cfg(feature = "redis-runtime")]
mod remote_settlement;
mod usage;
pub(super) use identity::{api_key_identity, consumer_identity, freeze_identity};

/// 与准入策略同代的持久关联入口，不从 HTTP 字段恢复来源。
pub(super) struct EventContext<'a> {
    pub(super) listener: &'a str,
    pub(super) generation: u64,
    pub(super) request_id: &'a str,
}

/// 从准入移交响应的账本事实，独立于可被上游和插件改写的 HTTP 头。
#[derive(Default)]
pub(super) struct ResponseState {
    pub(super) usage: Option<crate::runtime::traffic_limit::usage::Facts>,
    #[cfg(feature = "redis-runtime")]
    remote_shaper: Option<crate::runtime::traffic_limit::redis::bandwidth::Shaper>,
    #[cfg(feature = "redis-runtime")]
    remote_settlement: Option<remote_settlement::Settlement>,
    shaper: Option<crate::runtime::traffic_limit::FrameShaper>,
    settlement: Option<TrafficSettlement>,
    decision: Option<crate::runtime::traffic_limit::QuotaDecision>,
    events: Option<crate::observability::meter::traffic::Facts>,
    /// 最后销毁，确保账本与取消清理先取得最终事实的完成权。
    event_request: Option<crate::observability::meter::traffic::Request>,
}

impl ResponseState {
    /// 业务作用：在最终响应变换完成后应用共享整形、事实结算与本次准入余额。
    ///
    /// 参数说明：
    /// - `response`：已经完成插件、实体变换和压缩的响应。
    ///
    /// 返回：保持逐帧背压的响应；额度头表示准入时余额，不冒充尚未知的最终结算余额。
    pub(super) async fn wrap(&mut self, mut response: Response<BoxBody>) -> Response<BoxBody> {
        if self.usage.as_ref().is_some_and(|facts| facts.invalid()) {
            // 坏用量不属于依赖不可用，不能通过 fail-open 或响应插件重新放开业务内容。
            self.settlement.take();
            #[cfg(feature = "redis-runtime")]
            self.remote_settlement.take();
            let response = text_status(502, "invalid trusted upstream usage");
            return match self.event_request.take() {
                Some(request) => request.wrap(response),
                None => response,
            };
        }
        if let Some(decision) = self.decision.take() {
            // 只发布网关账本事实，防止上游或响应插件伪造当前调用方的剩余额度。
            crate::runtime::traffic_limit::write_rate_limit_headers(
                response.headers_mut(),
                &decision,
            );
        }
        if let Some(shaper) = self.shaper.take() {
            response = response.map(|body| ShapedBody::new(body, shaper).boxed());
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(shaper) = self.remote_shaper.take() {
            response =
                response.map(|body| remote_body::ShapedBody::new(body, shaper, None).boxed());
        }
        if let Some(mut settlement) = self.settlement.take() {
            settlement.validate_response_headers(response.headers());
            if self.usage.as_ref().is_some_and(|facts| facts.known()) {
                // 已解析的完整 provider/头部成本先于响应头发布，背压不能延迟已知补扣。
                settlement.finish();
            }
            response = response.map(|body| {
                SettledTrafficBody {
                    inner: Box::pin(body),
                    settlement: Some(settlement),
                }
                .boxed()
            });
        }
        #[cfg(feature = "redis-runtime")]
        if let Some(settlement) = self.remote_settlement.take() {
            response = settlement.wrap(response).await;
        }
        if let Some(facts) = self.usage.take() {
            response = response.map(|body| usage::Guard::new(body, facts).boxed());
        }
        match self.event_request.take() {
            Some(request) => request.wrap(response),
            None => response,
        }
    }
}

impl GatewayProxy {
    /// 业务作用：取得 route+维度 的共享带宽桶。
    ///
    /// 参数说明：
    /// - `scope`: route 作用域标识。
    /// - `dimension`: 限额维度值。
    /// - `budget`: 受信工作区状态预算，平台入口为空。
    ///
    /// 返回：共享桶；维度表已满时返回 `None`，调用方必须遵守当前策略的依赖失败模式。
    pub(super) fn traffic_bandwidth_bucket(
        &self,
        scope: &str,
        dimension: &str,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> Option<Arc<crate::runtime::traffic_limit::BandwidthBucket>> {
        if budget.is_some_and(|budget| !budget.register_reclaimer(self.traffic_bandwidth.clone())) {
            return None;
        }
        self.traffic_bandwidth
            .bucket_with_budget(scope, dimension, budget)
    }

    /// 业务作用：取得 route+维度 的多窗口限额运行态。
    ///
    /// 参数说明：
    /// - `key`: 已包含 route 与维度的复合键。
    /// - `budget`: 受信工作区状态预算，平台入口为空。
    ///
    /// 返回：共享限额状态;维度表已达上限时返回 `None`,避免高基数 key 打爆内存。
    pub(super) fn traffic_quota_state(
        &self,
        key: &str,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> Option<Arc<crate::runtime::traffic_limit::QuotaState>> {
        if budget.is_some_and(|budget| !budget.register_reclaimer(self.traffic_quota.clone())) {
            return None;
        }
        let mut entries = self.traffic_quota.lock();
        if let Some(state) = entries.values.get(key) {
            return Some(state.clone());
        }
        let mut lease = budget.map(|budget| budget.acquire());
        if lease.as_ref().is_some_and(Result::is_err)
            || (budget.is_none()
                && entries.platform >= crate::runtime::traffic_limit::MAX_ACTIVE_KEYS)
        {
            // 只有超过最长窗口影响周期的账本才可回收；按 `Arc` 引用数清理会让攻击者
            // 填满维度表后重置仍有效的额度，形成可重复绕过。
            let now_ms = crate::upstream::load::monotonic_ms();
            entries
                .values
                .retain(|_, state| Arc::strong_count(state) > 1 || !state.evictable(now_ms));
            entries.platform = entries
                .values
                .values()
                .filter(|state| state.workspace_lease.is_none())
                .count();
            lease = budget.map(|budget| budget.acquire());
            if budget.is_none()
                && entries.platform >= crate::runtime::traffic_limit::MAX_ACTIVE_KEYS
            {
                return None;
            }
        }
        let state = Arc::new(
            crate::runtime::traffic_limit::QuotaState::with_workspace_lease(
                lease.transpose().ok()?,
            ),
        );
        if budget.is_none() {
            entries.platform += 1;
        }
        entries.values.insert(key.to_owned(), state.clone());
        Some(state)
    }

    /// 业务作用：执行 route 级双向带宽整形与多窗口成本型限额。
    ///
    /// 三件事在同一处完成,因为它们共享同一个维度键——分开算会出现"限额按 consumer、
    /// 带宽按 IP"这类错配,同一个调用方被当成两个主体治理。
    ///
    /// 参数说明：
    /// - `parts`: 请求头,用于解析维度键。
    /// - `route`: 已匹配 route。
    /// - `client_ip`: 经可信代理链与连接元数据判定的真实客户端 IP。
    /// - `forward_body`: 待转发的请求体;命中请求方向带宽策略时就地包上整形器。
    /// - `response`: 接收本次准入判定、响应整形器和事实成本结算凭据。
    /// - `event`：持久关联的入口、快照代际与网关生成请求标识。
    ///
    /// 返回：成本证据缺失返回 400，超额或等待资源不足返回 429，关闭模式下状态不可用返回 503；
    /// 放行返回 `None`，已经取得的带宽约束不会因另一计数项降级而被跳过。
    pub(super) async fn enforce_traffic_limit(
        &self,
        parts: &mut Parts,
        route: &Route,
        client_ip: IpAddr,
        forward_body: &mut Option<BoxBody>,
        response: &mut ResponseState,
        event: EventContext<'_>,
    ) -> Option<Response<BoxBody>> {
        use crate::runtime::traffic_limit::{FrameShaper, OverflowAction, QuotaFailMode};

        let policy = route.traffic_limit.as_ref()?;
        if matches!(
            policy.cost_source,
            crate::runtime::traffic_limit::CostSource::GraphqlCost
        ) && is_cors_preflight(parts, route)
        {
            // capability probe 没有查询正文，不生成 GraphQL 成本，也不占用查询额度。
            return None;
        }
        // 缺少查询证据属于输入与执行顺序错误，不是计数依赖故障；fail_open 不能绕过此门。
        let cost = match policy.cost_source.admission_cost(
            parts
                .extensions
                .get::<crate::extensions::graphql::VerifiedQueryCost>()
                .map(|cost| cost.units()),
        ) {
            Ok(cost) => cost,
            Err(_) => return Some(text_status(400, "verified GraphQL cost is required")),
        };
        if let Some(plan) = &policy.usage {
            let facts = crate::runtime::traffic_limit::usage::Facts::new(plan.clone());
            parts.extensions.insert(facts.clone());
            parts
                .extensions
                .insert(crate::runtime::traffic_limit::usage::Capture(plan.clone()));
            response.usage = Some(facts);
        }
        let dimension = match identity::dimension(parts, route, client_ip, &policy.key) {
            Some(dimension) => dimension,
            // 缺少认证事实不是计数依赖故障；fail-open 不能把匿名请求并入受信主体账本。
            None => return Some(text_status(401, "verified traffic identity is required")),
        };
        let Some(scope) = policy.bound_scope.get() else {
            // 未经过完整候选归属验证的策略没有扣账权威，不允许 fail-open 猜测平台身份。
            return Some(text_status(503, "traffic scope authority is unavailable"));
        };
        let state_budget = parts
            .extensions
            .get::<crate::control::ownership::state::Budget>();

        if policy.events {
            // 持久开始确认期间仍持有原请求体，已知实体必须纳入共享保留预算。
            let Some(_pending) = crate::runtime::traffic_limit::resources::Retained::acquire(
                forward_body
                    .as_ref()
                    .and_then(|body| body.size_hint().upper())
                    .unwrap_or(0),
            ) else {
                return Some(text_status(503, "traffic event capacity exceeded"));
            };
            let facts = crate::observability::meter::traffic::Facts::new(cost);
            let attribution = crate::observability::meter::traffic::Attribution {
                owner: parts
                    .extensions
                    .get::<crate::control::ownership::Owner>()
                    .map_or_else(|| "platform".to_owned(), |owner| owner.namespace()),
                listener: event.listener.to_owned(),
                route: route.id.to_string(),
                scope: scope.quota.to_string(),
                dimension_sha256: nasa::crypto::sha256_cased(dimension.as_ref(), false),
                policy: policy.state_key,
                config_generation: event.generation,
                gateway_request_id: event.request_id.to_owned(),
                source: policy.cost_source.label(),
            };
            match self
                .traffic_meter
                .admit_traffic(attribution, facts.clone())
                .await
            {
                Ok(request) => response.event_request = Some(request),
                Err(_) => return Some(text_status(503, "traffic event admission unavailable")),
            }
            response.events = Some(facts);
            // 持久确认跨过配置发布时必须重新取得路由权威，旧代事件不授予已撤销入口业务权限。
            if self.snap.load().version != event.generation {
                return Some(text_status(409, "traffic event authority changed"));
            }
        }

        #[cfg(feature = "redis-runtime")]
        if policy.redis_backend {
            let Some(client) = self.rate_limiter.redis_client() else {
                // 候选声明的后端权威不可缺失，不能临时猜测一份独立本地额度。
                return Some(text_status(503, "shared traffic backend unavailable"));
            };
            let (request, reply) =
                remote::shapers(policy, scope, &dimension, state_budget, &client);
            if policy.redis_quota.is_some() {
                if let Some(rejected) = self
                    .enforce_remote_traffic(
                        policy,
                        Arc::new(crate::runtime::traffic_limit::redis::Ledger::new(
                            client,
                            &scope.quota,
                            &dimension,
                            state_budget,
                        )),
                        cost,
                        forward_body
                            .as_ref()
                            .map_or(Some(0), |body| body.size_hint().upper()),
                        response,
                    )
                    .await
                {
                    return Some(rejected);
                }
            }
            if let Some(shaper) = request {
                if let Some(body) = forward_body.take() {
                    let pacing = crate::runtime::traffic_limit::pacing::RequestPacing::default();
                    *forward_body = Some(
                        remote_body::ShapedBody::new(body, shaper, Some(pacing.clone())).boxed(),
                    );
                    parts.extensions.insert(pacing);
                }
            }
            response.remote_shaper = reply;
            return None;
        }

        // 先取得两个方向的状态容量再扣准入额度，防止关闭模式在半完成状态下误放行。
        let prepare = |direction: &str,
                       bandwidth: Option<crate::runtime::traffic_limit::BandwidthPolicy>|
         -> anyhow::Result<Option<FrameShaper>> {
            let Some(bandwidth) = bandwidth else {
                return Ok(None);
            };
            match self.traffic_bandwidth_bucket(direction, &dimension, state_budget) {
                Some(bucket) => Ok(Some(FrameShaper::new(bucket, bandwidth))),
                None if policy.fail_mode == QuotaFailMode::FailOpen => {
                    crate::runtime::traffic_limit::metrics::STATE_OPEN
                        .fetch_add(1, Ordering::Relaxed);
                    Ok(None)
                }
                None => {
                    crate::runtime::traffic_limit::metrics::STATE_CLOSED
                        .fetch_add(1, Ordering::Relaxed);
                    anyhow::bail!("traffic bandwidth state capacity exceeded")
                }
            }
        };
        let request_shaper = match prepare(&scope.request, policy.request_bandwidth) {
            Ok(shaper) => shaper,
            Err(_) => return Some(text_status(503, "traffic bandwidth state unavailable")),
        };
        let response_shaper = match prepare(&scope.response, policy.response_bandwidth) {
            Ok(shaper) => shaper,
            Err(_) => return Some(text_status(503, "traffic bandwidth state unavailable")),
        };

        // —— 限额判定必须早于带宽整形 ——
        // 反过来会先为一个即将被拒的请求占用带宽额度,超额流量照样消耗了配额。
        if let Some(quota) = policy.quota.as_ref() {
            let key = format!(
                "{}:{:016x}",
                scope.quota,
                stable_hash64(dimension.as_bytes())
            );
            if let Some(state) = self.traffic_quota_state(&key, state_budget) {
                if let Some(events) = &response.events {
                    // 写入前先标记未知，异常退出不能留下虚假的未执行事实。
                    events.admission_pending();
                }
                let (mut decision, mut reservation) = state.check_with_reservation(quota, cost);
                if let Some(events) = &response.events {
                    events.admitted(decision.allowed);
                    events.cost(
                        if decision.allowed {
                            cost
                        } else {
                            0
                        },
                        true,
                    );
                }
                response.decision = Some(decision);
                if !decision.allowed {
                    match quota.overflow {
                        OverflowAction::Reject => {
                            self.metrics.inc_rate_limited();
                            return Some(quota_limited_response(&decision));
                        }
                        OverflowAction::Delay {
                            max_queue,
                            max_wait_ms,
                        } => {
                            // 排队名额本身有界:拿不到就立刻拒绝。无界排队会把过载从
                            // "快速失败"变成"内存耗尽",后者在生产上不可恢复。
                            let Some(_slot) = state.enqueue(max_queue) else {
                                crate::runtime::traffic_limit::metrics::CAPACITY
                                    .fetch_add(1, Ordering::Relaxed);
                                self.metrics.inc_rate_limited();
                                return Some(quota_limited_response(&decision));
                            };
                            // 只保留有明确实体上界的请求；不预读未知流，也不能把已缓冲正文藏在等待槽中。
                            let Some(bytes) = forward_body
                                .as_ref()
                                .map_or(Some(0), |body| body.size_hint().upper())
                            else {
                                crate::runtime::traffic_limit::metrics::UNKNOWN_BODY
                                    .fetch_add(1, Ordering::Relaxed);
                                self.metrics.inc_rate_limited();
                                return Some(quota_limited_response(&decision));
                            };
                            let Some(_retained) =
                                crate::runtime::traffic_limit::resources::Retained::acquire(bytes)
                            else {
                                // 物理资源不足是不可降级的安全门，fail_open 只描述计数依赖不可用。
                                self.metrics.inc_rate_limited();
                                return Some(quota_limited_response(&decision));
                            };
                            let deadline = Instant::now() + Duration::from_millis(max_wait_ms);
                            loop {
                                let remaining = deadline.saturating_duration_since(Instant::now());
                                if remaining.is_zero() {
                                    crate::runtime::traffic_limit::metrics::DEADLINE
                                        .fetch_add(1, Ordering::Relaxed);
                                    self.metrics.inc_rate_limited();
                                    return Some(quota_limited_response(&decision));
                                }
                                // 轮询步长取"建议等待"与剩余时间的较小值,并设 1ms 下界,
                                // 避免 retry_after 为 0 时退化成忙等把 CPU 打满。
                                let step = decision
                                    .retry_after
                                    .max(Duration::from_millis(1))
                                    .min(remaining)
                                    .min(Duration::from_millis(50));
                                tokio::time::sleep(step).await;
                                // 调度器唤醒可能晚于承诺期限；过期后不得再扣账并把请求送入上游。
                                if Instant::now() >= deadline {
                                    crate::runtime::traffic_limit::metrics::DEADLINE
                                        .fetch_add(1, Ordering::Relaxed);
                                    self.metrics.inc_rate_limited();
                                    return Some(quota_limited_response(&decision));
                                }
                                if let Some(events) = &response.events {
                                    events.admission_pending();
                                }
                                let (next_decision, next_reservation) =
                                    state.check_with_reservation(quota, cost);
                                decision = next_decision;
                                if let Some(events) = &response.events {
                                    events.admitted(decision.allowed);
                                    events.cost(
                                        if decision.allowed {
                                            cost
                                        } else {
                                            0
                                        },
                                        true,
                                    );
                                }
                                response.decision = Some(decision);
                                reservation = next_reservation;
                                if decision.allowed {
                                    break;
                                }
                            }
                        }
                    }
                }
                if let Some(reservation) = reservation {
                    response.settlement = TrafficSettlement::new(
                        state,
                        quota.clone(),
                        policy.cost_source.clone(),
                        reservation,
                        response.usage.clone(),
                    );
                    if let Some(events) = &response.events {
                        if let Some(settlement) = &mut response.settlement {
                            settlement.events = Some((events.clone(), events.lease()));
                            events.cost(cost, false);
                        } else {
                            events.settled(true);
                        }
                    }
                }
            } else if policy.fail_mode == QuotaFailMode::FailClosed {
                crate::runtime::traffic_limit::metrics::STATE_CLOSED
                    .fetch_add(1, Ordering::Relaxed);
                return Some(text_status(503, "traffic quota state unavailable"));
            } else {
                crate::runtime::traffic_limit::metrics::STATE_OPEN.fetch_add(1, Ordering::Relaxed);
            }
        }

        if let Some(shaper) = request_shaper {
            if let Some(body) = forward_body.take() {
                let pacing = crate::runtime::traffic_limit::pacing::RequestPacing::default();
                let mut shaped = ShapedBody::new(body, shaper);
                shaped.request_pacing = Some(pacing.clone());
                parts.extensions.insert(pacing);
                *forward_body = Some(shaped.boxed());
            }
        }
        response.shaper = response_shaper;
        None
    }
}

impl crate::control::ownership::state::ReclaimExpired for parking_lot::Mutex<TrafficQuotaEntries> {
    /// 业务作用：让其它状态使用者回收已经失效且无人借用的旧额度，避免休眠路由永久占用工作区名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只移除完全过期的账本；使用非阻塞锁，不能与正在申请容量的准入路径形成反向等待。
    fn reclaim_expired(&self) {
        let Some(mut entries) = self.try_lock() else {
            return;
        };
        let now = crate::upstream::load::monotonic_ms();
        entries
            .values
            .retain(|_, state| Arc::strong_count(state) > 1 || !state.evictable(now));
        entries.platform = entries
            .values
            .values()
            .filter(|state| state.workspace_lease.is_none())
            .count();
    }
}

/// 受共享带宽桶整形的 body。请求与响应两个方向共用同一实现。
/// 逐帧延迟响应数据且不聚合实体的带宽整形 body。
struct ShapedBody {
    /// 原始流式响应体。
    inner: Pin<Box<BoxBody>>,
    /// 当前 route+维度共享桶的帧级调度器。
    shaper: crate::runtime::traffic_limit::FrameShaper,
    /// 已扣带宽额度、等待发送时刻的数据帧。
    pending: Option<Frame<Bytes>>,
    /// pending frame 对应的单次等待计时器。
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// 与待发送帧一同保留的进程级容量，不随快照热更提前归还。
    retained: Option<crate::runtime::traffic_limit::resources::Retained>,
    /// 资源或期限门拒绝后不再轮询底层，避免错误之后继续发送。
    ended: bool,
    /// 仅请求方向提供；本地等待不能成为后端慢响应或失效证据。
    request_pacing: Option<crate::runtime::traffic_limit::pacing::RequestPacing>,
}

impl ShapedBody {
    /// 业务作用：将原始流交给共享整形器，等待时只保留一帧，不聚合或复制实体。
    ///
    /// 参数说明：
    /// - `inner`：原始流式实体。
    /// - `shaper`：该方向冻结的带宽桶与期限。
    ///
    /// 返回：尚未读取任何帧、没有占用等待预算的包装体。
    fn new(inner: BoxBody, shaper: crate::runtime::traffic_limit::FrameShaper) -> Self {
        Self {
            inner: Box::pin(inner),
            shaper,
            pending: None,
            sleep: None,
            retained: None,
            ended: false,
            request_pacing: None,
        }
    }
}

/// 响应事实成本的计量方式。
#[derive(Clone)]
enum TrafficObservation {
    /// 统计实际交付的响应 data frame 字节。
    ResponseBytes(u64),
    /// 统计完整交付的 gRPC message。
    GrpcMessages(GrpcMessageCounter),
    /// 独立于下游交付的真实上游消耗事实。
    TrustedUsage(crate::runtime::traffic_limit::usage::Facts),
}

impl TrafficObservation {
    /// 业务作用：区分真实累计成本与证据不足时保留的额度，避免事件把预留冒充实际消耗。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：字节计数、完整消息计数或已确认 provider 用量为真；协议残缺与缺失用量为假。
    fn known(&self) -> bool {
        match self {
            Self::ResponseBytes(_) => true,
            Self::GrpcMessages(counter) => {
                !counter.invalid && counter.header_len == 0 && counter.payload_remaining.is_none()
            }
            Self::TrustedUsage(facts) => facts.known(),
        }
    }
}

/// gRPC 五字节 envelope 的跨 frame 增量计数器。
#[derive(Clone, Default)]
struct GrpcMessageCounter {
    /// 跨 data frame 暂存的不完整五字节 gRPC envelope header。
    header: [u8; 5],
    /// `header` 中当前有效字节数。
    header_len: usize,
    /// 当前消息尚未交付的 payload 字节数；None 表示正在读取下一个 header。
    payload_remaining: Option<u32>,
    /// 已完整交付给下游的 gRPC message 数。
    completed: u64,
    /// envelope 非法后停止信任后续字节，避免错误返还账本额度。
    invalid: bool,
}

impl GrpcMessageCounter {
    /// 业务作用：消费一个响应 data frame，并只在完整 gRPC message 已交付时增加事实计数。
    ///
    /// 参数说明：
    /// - `data`：是即将交给下游的响应字节。
    ///
    /// 返回：无；畸形 envelope 后停止计数，避免把任意字节误当成 usage。
    fn observe(&mut self, mut data: &[u8]) {
        if self.invalid {
            return;
        }
        while !data.is_empty() {
            if let Some(remaining) = self.payload_remaining {
                let consumed = data.len().min(remaining as usize);
                data = &data[consumed..];
                let remaining = remaining - consumed as u32;
                if remaining == 0 {
                    self.completed = self.completed.saturating_add(1);
                    self.payload_remaining = None;
                } else {
                    self.payload_remaining = Some(remaining);
                }
                continue;
            }
            let needed = 5usize.saturating_sub(self.header_len);
            let consumed = data.len().min(needed);
            self.header[self.header_len..self.header_len + consumed]
                .copy_from_slice(&data[..consumed]);
            self.header_len += consumed;
            data = &data[consumed..];
            if self.header_len < 5 {
                continue;
            }
            // 压缩标志只有 0/1。未知值说明响应不再是可安全计量的 gRPC envelope，
            // 停止解析比继续错位计数更保守。
            if self.header[0] > 1 {
                self.invalid = true;
                return;
            }
            let payload_len = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]);
            self.header_len = 0;
            if payload_len == 0 {
                self.completed = self.completed.saturating_add(1);
            } else {
                self.payload_remaining = Some(payload_len);
            }
        }
    }
}

/// 一次成本型限额的响应期结算上下文。
struct TrafficSettlement {
    /// route+维度共享额度账本。
    state: Arc<crate::runtime::traffic_limit::QuotaState>,
    /// 准入和结算必须共用的不可变额度策略。
    policy: crate::runtime::traffic_limit::QuotaPolicy,
    /// 响应事实到额度单位的换算口径。
    source: crate::runtime::traffic_limit::CostSource,
    /// 尚未完成最终结算的准入预留凭据。
    reservation: Option<crate::runtime::traffic_limit::QuotaReservation>,
    /// 已从实际交付帧累计的可信事实。
    observation: TrafficObservation,
    /// 响应协议与成本来源一致时为 true；不一致时只保留准入预留。
    trustworthy_response: bool,
    /// 原账本完成后才允许结束事件发布最终成本。
    events: Option<(
        crate::observability::meter::traffic::Facts,
        crate::observability::meter::traffic::Lease,
    )>,
}

impl TrafficSettlement {
    /// 业务作用：把准入预留与支持的可信响应计量方式绑定，供 body 生命周期完成最终结算。
    ///
    /// 参数说明：
    /// - `state`：是共享账本
    /// - `policy`：是准入策略
    /// - `source`：是成本来源
    /// - `reservation`：是本次成功扣账凭据。
    /// - `usage`：可信来源的冻结事实槽，其生命周期独立于响应帧。
    ///
    /// 返回：需要响应期事实的来源返回结算上下文；固定请求成本返回 `None`。
    fn new(
        state: Arc<crate::runtime::traffic_limit::QuotaState>,
        policy: crate::runtime::traffic_limit::QuotaPolicy,
        source: crate::runtime::traffic_limit::CostSource,
        reservation: crate::runtime::traffic_limit::QuotaReservation,
        usage: Option<crate::runtime::traffic_limit::usage::Facts>,
    ) -> Option<Self> {
        let observation = match &source {
            crate::runtime::traffic_limit::CostSource::PerRequest(_) => return None,
            crate::runtime::traffic_limit::CostSource::ResponseBytes {
                ..
            } => TrafficObservation::ResponseBytes(0),
            crate::runtime::traffic_limit::CostSource::GrpcMessages {
                ..
            } => TrafficObservation::GrpcMessages(GrpcMessageCounter::default()),
            // 查询成本已在准入时全额扣减，不因响应取消或失败返还已提交的操作成本。
            crate::runtime::traffic_limit::CostSource::GraphqlCost => return None,
            crate::runtime::traffic_limit::CostSource::TrustedUsage {
                ..
            } => TrafficObservation::TrustedUsage(usage.expect("compiled trusted usage facts")),
        };
        Some(Self {
            state,
            policy,
            source,
            reservation: Some(reservation),
            observation,
            trustworthy_response: true,
            events: None,
        })
    }

    /// 业务作用：复验响应协议是否与声明的事实计量来源一致，防止把普通 HTTP body
    /// 按 gRPC envelope 误解析后返还配额。
    ///
    /// 参数说明：
    /// - `headers`：是最终响应头。
    ///
    /// 返回：无；协议不匹配时保留准入预留，不做事实返还。
    fn validate_response_headers(&mut self, headers: &HeaderMap) {
        if matches!(&self.observation, TrafficObservation::GrpcMessages(_)) {
            self.trustworthy_response = grpc_response_is_trustworthy(headers);
        }
    }

    /// 业务作用：登记一个即将交付给下游的数据帧，形成响应字节或完整 gRPC message 事实。
    ///
    /// 参数说明：
    /// - `data`：是响应 body 的 data frame。
    ///
    /// 返回：无；计数使用饱和运算。
    fn observe(&mut self, data: &[u8]) {
        // 协议不匹配时不尝试把普通实体解释成 gRPC envelope，更不能据此生成退款事实。
        if !self.trustworthy_response {
            return;
        }
        match &mut self.observation {
            TrafficObservation::ResponseBytes(bytes) => {
                *bytes = bytes.saturating_add(data.len() as u64);
            }
            TrafficObservation::GrpcMessages(counter) => counter.observe(data),
            TrafficObservation::TrustedUsage(_) => {}
        }
    }

    /// 业务作用：以已观测事实完成一次且仅一次账本结算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；重复调用不产生副作用。
    fn finish(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let observed = match &self.observation {
            TrafficObservation::TrustedUsage(facts) => {
                facts.cost(self.source.admission_cost(None).expect("usage reserve"))
            }
            TrafficObservation::ResponseBytes(bytes) => *bytes,
            TrafficObservation::GrpcMessages(counter) => {
                if counter.invalid || counter.header_len != 0 || counter.payload_remaining.is_some()
                {
                    // 畸形或不完整消息不能证明预留未被消费；已完整交付的更多消息仍形成补扣。
                    counter
                        .completed
                        .max(self.source.admission_cost(None).expect("response cost"))
                } else {
                    counter.completed
                }
            }
        };
        let actual = if self.trustworthy_response {
            self.source.settle_cost(observed)
        } else {
            self.source
                .admission_cost(None)
                .expect("response settlement never contains GraphQL cost")
        };
        self.state.settle(&self.policy, reservation, actual);
        if let Some((events, _lease)) = self.events.take() {
            events.cost(
                actual,
                self.trustworthy_response && self.observation.known(),
            );
            events.settled(true);
        }
    }
}

/// 业务作用：统一响应消息计量的协议门，普通实体或 HTTP 编码内容不能获得 gRPC 退款权威。
///
/// 参数说明：
/// - `headers`：网关最终交付的响应头。
///
/// 返回：仅原生 gRPC 且没有 HTTP 内容编码时可信。
fn grpc_response_is_trustworthy(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|mime| {
                let mime = mime.trim();
                mime.eq_ignore_ascii_case("application/grpc")
                    || mime.eq_ignore_ascii_case("application/grpc+proto")
                    || mime.eq_ignore_ascii_case("application/grpc+json")
            })
        })
        && headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .all(|value| {
                value.to_str().is_ok_and(|value| {
                    value
                        .split(',')
                        .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
                })
            })
}

impl Drop for TrafficSettlement {
    /// 业务作用：在客户端取消、响应错误或包装体提前销毁时结算已实际交付的成本，避免预留泄漏。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；已结算凭据不会重复扣账。
    fn drop(&mut self) {
        self.finish();
    }
}

/// 在不缓冲响应的前提下计量事实成本，并在 EOF、错误或取消时结算已交付部分。
struct SettledTrafficBody {
    /// 原始流式响应体。
    inner: Pin<Box<BoxBody>>,
    /// 尚未完成的成本结算上下文；EOF、错误或 Drop 后取空。
    settlement: Option<TrafficSettlement>,
}

impl Body for SettledTrafficBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：透传响应帧并在交付 data frame 前登记事实成本，终止路径立即结算。
    ///
    /// 参数说明：
    /// - `cx`：是异步 body 轮询上下文。
    ///
    /// 返回：底层 body 的下一帧；EOF 或错误时结算当前已交付事实。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = self.inner.as_mut().poll_frame(cx);
        match polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(settlement), Some(data)) = (self.settlement.as_mut(), frame.data_ref())
                {
                    settlement.observe(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                if let Some(mut settlement) = self.settlement.take() {
                    settlement.finish();
                }
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Some(mut settlement) = self.settlement.take() {
                    settlement.finish();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：报告底层响应是否已结束，同时确保结算包装不改变流结束语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层已结束时返回 `true`。
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    /// 业务作用：透传底层响应体大小提示，不因计量包装改变 framing 决策。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层 body 的大小提示。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Body for ShapedBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：逐帧执行共享响应带宽整形，同时保留底层 body 的流式背压与 trailer 顺序。
    ///
    /// 参数说明：
    /// - `cx`：是异步 body 轮询上下文。
    ///
    /// 返回：额度就绪时返回下一帧；需要等待时返回 Pending；底层错误与结束原样传播。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if self.pending.is_some() {
            let sleep = self.sleep.as_mut().expect("shaped body pending sleep");
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            self.retained = None;
            return Poll::Ready(self.pending.take().map(Ok));
        }
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 只有 data frame 计入带宽;trailer 参与计费会让限速随协议细节漂移。
                let len = frame.data_ref().map(|data| data.len() as u64).unwrap_or(0);
                let delay = match self.shaper.delay_for(len) {
                    Ok(delay) => delay,
                    Err(_) => {
                        // 等待超界不能提前交付；立即丢弃底层流，传播取消并保守保留已消费额度。
                        self.ended = true;
                        self.inner = Box::pin(full_body(Bytes::new()));
                        return Poll::Ready(Some(Err(Box::new(
                            crate::runtime::traffic_limit::resources::Rejected,
                        ))));
                    }
                };
                if delay.is_zero() {
                    return Poll::Ready(Some(Ok(frame)));
                }
                if let Some(pacing) = &self.request_pacing {
                    pacing.mark_wait();
                }
                let Some(retained) =
                    crate::runtime::traffic_limit::resources::Retained::acquire(len)
                else {
                    self.ended = true;
                    self.inner = Box::pin(full_body(Bytes::new()));
                    return Poll::Ready(Some(Err(Box::new(
                        crate::runtime::traffic_limit::resources::Rejected,
                    ))));
                };
                // 帧先扣配额再延后投递:桶已在 delay_for 里推进,
                // 这一帧的额度不会被并发流重复取走。
                self.pending = Some(frame);
                self.retained = Some(retained);
                self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            other => other,
        }
    }

    /// 业务作用：报告整形 body 是否已无底层帧和待发送帧，避免过早结束丢失已扣额度的数据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：底层结束且没有 pending frame 时返回 true。
    fn is_end_stream(&self) -> bool {
        self.ended || (self.inner.is_end_stream() && self.pending.is_none())
    }

    /// 业务作用：透传响应实体大小提示，整形只改变时序而不改变字节数量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回底层 body 的大小提示。
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
