//! 共享账本只接收已验证成本和已冻结身份，不读取实体或重新解释客户端用量声明。

use super::*;

/// 同一次准入的响应权威与持久事实，排队重试始终借用原上下文。
#[derive(Clone, Copy)]
struct AdmissionEvidence<'a> {
    receipt: Option<&'a crate::runtime::traffic_limit::redis::settlement::Receipt>,
    events: Option<&'a crate::observability::meter::traffic::Facts>,
}

/// 业务作用：为当前流冻结两个方向的共享调度身份，热更不改变在途帧的后端。
///
/// 参数说明：
/// - `policy`：编译后的流量策略。
/// - `scope`：完整候选已绑定的方向身份。
/// - `dimension`：当前请求可信维度。
/// - `budget`：受信工作区容量。
/// - `client`：当前已验证的 NASA 连接。
///
/// 返回：未读取实体、未预留带宽的请求与响应调度器。
pub(super) fn shapers(
    policy: &crate::routing::TrafficLimitPolicy,
    scope: &crate::routing::traffic::BoundScope,
    dimension: &str,
    budget: Option<&crate::control::ownership::state::Budget>,
    client: &Arc<nasa::redis::RedisClient>,
) -> (
    Option<crate::runtime::traffic_limit::redis::bandwidth::Shaper>,
    Option<crate::runtime::traffic_limit::redis::bandwidth::Shaper>,
) {
    let create =
        |direction: &str,
         config: Option<crate::runtime::traffic_limit::BandwidthPolicy>,
         compiled: &Option<Arc<crate::runtime::traffic_limit::redis::bandwidth::Policy>>| {
            config.zip(compiled.as_ref()).map(|(config, compiled)| {
                crate::runtime::traffic_limit::redis::bandwidth::Shaper {
                    ledger: Arc::new(crate::runtime::traffic_limit::redis::Ledger::new(
                        client.clone(),
                        direction,
                        dimension,
                        budget,
                    )),
                    policy: compiled.clone(),
                    after_remaining: config.after_bytes,
                    max_wait: config.max_wait,
                    fail_mode: policy.fail_mode,
                }
            })
        };
    (
        create(
            &scope.request,
            policy.request_bandwidth,
            &policy.redis_request,
        ),
        create(
            &scope.response,
            policy.response_bandwidth,
            &policy.redis_response,
        ),
    )
}

impl GatewayProxy {
    /// 业务作用：用原子共享账本执行流量准入，不把共享依赖失败转换成另一份本地额度。
    ///
    /// 参数说明：
    /// - `policy`：构建期预编码的共享窗口、来源和故障策略。
    /// - `ledger`：当前请求已冻结的后端、共享身份和容量。
    /// - `cost`：已验证成本。
    /// - `body_bound`：请求实体的已知保留上界，未知时不允许排队。
    /// - `response`：接收共享账本的准入余额。
    ///
    /// 返回：超额429、确定性错误503；仅依赖不可用或状态容量不足可按显式策略降级。
    pub(super) async fn enforce_remote_traffic(
        &self,
        policy: &crate::routing::TrafficLimitPolicy,
        ledger: Arc<crate::runtime::traffic_limit::redis::Ledger>,
        cost: u64,
        body_bound: Option<u64>,
        response: &mut ResponseState,
    ) -> Option<Response<BoxBody>> {
        use crate::runtime::traffic_limit::{redis::Failure, QuotaFailMode};
        let compiled = policy.redis_quota.as_ref().expect("compiled shared quota");
        let overflow = policy
            .quota
            .as_ref()
            .expect("shared quota overflow")
            .overflow;
        let mut receipt = match crate::runtime::traffic_limit::redis::settlement::Receipt::prepare(
            compiled.clone(),
            ledger.clone(),
        ) {
            Ok(receipt) => receipt,
            Err(_) => return Some(text_status(503, "shared response capacity exceeded")),
        };
        if let (Some(receipt), Some(facts)) = (receipt.as_mut(), response.usage.as_ref()) {
            receipt.bind_usage(facts.clone(), cost);
        }
        if let (Some(receipt), Some(facts)) = (receipt.as_mut(), response.events.as_ref()) {
            receipt.bind_events(facts.clone());
        }
        // 不预读未知流；已经有实体上界时同时计入保留预算，避免有限 RPC 隐藏大量已缓冲正文。
        let Some(pending) =
            crate::runtime::traffic_limit::resources::Retained::acquire(body_bound.unwrap_or(0))
        else {
            return Some(text_status(
                503,
                "shared traffic operation capacity exceeded",
            ));
        };
        let evidence = AdmissionEvidence {
            receipt: receipt.as_ref(),
            events: response.events.as_ref(),
        };
        let mut outcome = check(compiled, &ledger, cost, None, evidence).await;
        drop(pending);
        if let Ok(decision) = outcome.as_ref() {
            if !decision.allowed {
                outcome = delayed(
                    compiled, &ledger, cost, overflow, body_bound, *decision, evidence,
                )
                .await;
            }
        }
        match outcome {
            Ok(decision) => {
                response.decision = Some(decision);
                if decision.allowed {
                    if let Some(mut receipt) = receipt.take() {
                        // 只有明确准入成功的回执才能在响应结束时退款；未知提交不授予此权限。
                        receipt.delivered(cost, false);
                        receipt.activate();
                        response.remote_settlement = Some(remote_settlement::Settlement::new(
                            receipt,
                            policy.cost_source.clone(),
                            policy.fail_mode,
                            response.usage.clone(),
                        ));
                    }
                    None
                } else {
                    self.metrics.inc_rate_limited();
                    Some(quota_limited_response(&decision))
                }
            }
            Err(Failure::Unavailable | Failure::StateCapacity)
                if policy.fail_mode == QuotaFailMode::FailOpen =>
            {
                crate::runtime::traffic_limit::metrics::STATE_OPEN.fetch_add(1, Ordering::Relaxed);
                // 共享依赖降级不解除响应的成本、闲置和物理资源上限；未确认回执永远不提交退款。
                response.remote_settlement = receipt.take().map(|receipt| {
                    remote_settlement::Settlement::new(
                        receipt,
                        policy.cost_source.clone(),
                        policy.fail_mode,
                        response.usage.clone(),
                    )
                });
                None
            }
            Err(_) => {
                crate::runtime::traffic_limit::metrics::STATE_CLOSED
                    .fetch_add(1, Ordering::Relaxed);
                Some(text_status(503, "shared traffic ledger unavailable"))
            }
        }
    }
}

/// 业务作用：用全节点共享租约约束延迟请求，在每次尝试准入时复验名额与本地期限。
///
/// 参数说明：
/// - `policy`：已编译的窗口定义。
/// - `ledger`：当前请求冻结的后端与身份。
/// - `cost`：已验证的固定成本。
/// - `overflow`：超额动作及集群队列边界。
/// - `body_bound`：请求实体保留上界。
/// - `decision`：首次未通过的准入结果。
/// - `evidence`：同一待准入回执与持久事实，排队不创建第二份完成权。
///
/// 返回：准入、有限等待后拒绝或依赖错误；未知实体与物理容量不足不会降级放行。
async fn delayed(
    policy: &crate::runtime::traffic_limit::redis::Policy,
    ledger: &crate::runtime::traffic_limit::redis::Ledger,
    cost: u64,
    overflow: crate::runtime::traffic_limit::OverflowAction,
    body_bound: Option<u64>,
    mut decision: crate::runtime::traffic_limit::QuotaDecision,
    evidence: AdmissionEvidence<'_>,
) -> Result<
    crate::runtime::traffic_limit::QuotaDecision,
    crate::runtime::traffic_limit::redis::Failure,
> {
    use crate::runtime::traffic_limit::{
        metrics,
        redis::{queue::Slot, Failure},
        resources::Retained,
        OverflowAction,
    };
    let OverflowAction::Delay {
        max_queue,
        max_wait_ms,
    } = overflow
    else {
        return Ok(decision);
    };
    // 不能通过预读未知正文获取排队资格，资源安全门也不受后端 fail-open 策略影响。
    let Some(bytes) = body_bound else {
        metrics::UNKNOWN_BODY.fetch_add(1, Ordering::Relaxed);
        return Ok(decision);
    };
    let Some(retained) = Retained::acquire(bytes) else {
        return Ok(decision);
    };
    let deadline = Instant::now() + Duration::from_millis(max_wait_ms);
    let Some(slot) = Slot::acquire(ledger, max_queue, max_wait_ms, retained).await? else {
        metrics::CAPACITY.fetch_add(1, Ordering::Relaxed);
        return Ok(decision);
    };
    let outcome = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
            break Ok(decision);
        }
        let step = decision
            .retry_after
            .max(Duration::from_millis(5))
            .min(remaining)
            .min(Duration::from_millis(100));
        tokio::time::sleep(step).await;
        // 唤醒或网络响应晚于期限都不能开放业务路由；已提交的未知扣账保守保留。
        if Instant::now() >= deadline {
            metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
            break Ok(decision);
        }
        let outcome = check(policy, ledger, cost, Some(&slot), evidence).await;
        if Instant::now() >= deadline || matches!(outcome, Err(Failure::Deadline)) {
            metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
            break Ok(decision);
        }
        match outcome {
            Ok(next) if next.allowed => break Ok(next),
            Ok(next) => decision = next,
            Err(error) => break Err(error),
        }
    };
    slot.release().await;
    outcome
}

/// 业务作用：让响应回执准入与普通固定成本共享同一排队复验路径。
///
/// 参数说明：
/// - `policy`：固定窗口参数。
/// - `ledger`：冻结的共享连接和身份。
/// - `cost`：已验证预留成本。
/// - `slot`：队列名额，首次判定为空。
/// - `evidence`：同一未激活回执与事件槽，响应成本由回执自行记录。
///
/// 返回：一次原子准入判定，不创建本地替代额度。
async fn check(
    policy: &crate::runtime::traffic_limit::redis::Policy,
    ledger: &crate::runtime::traffic_limit::redis::Ledger,
    cost: u64,
    slot: Option<&crate::runtime::traffic_limit::redis::queue::Slot>,
    evidence: AdmissionEvidence<'_>,
) -> Result<
    crate::runtime::traffic_limit::QuotaDecision,
    crate::runtime::traffic_limit::redis::Failure,
> {
    if let Some(receipt) = evidence.receipt {
        return receipt.operation().invoke(0, cost, slot).await;
    }
    if let Some(events) = evidence.events {
        events.admission_pending();
        events.cost(cost, false);
        events.settled(false);
    }
    let outcome = if slot.is_none() {
        policy.check(ledger, cost).await
    } else {
        policy.check_queued(ledger, cost, slot).await
    };
    if let (Some(events), Ok(decision)) = (evidence.events, &outcome) {
        events.admitted(decision.allowed);
        events.cost(
            if decision.allowed {
                cost
            } else {
                0
            },
            true,
        );
        events.settled(true);
    }
    outcome
}
