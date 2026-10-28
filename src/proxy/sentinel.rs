//! 请求入口的原生速率、预热与匀速队列准入。

use super::*;
use crate::runtime::sentinel::queue::{self, Rejected};

pub(super) struct AdmissionContext {
    pub(super) generation: u64,
    pub(super) body_upper: Option<u64>,
    pub(super) started: Instant,
}

#[derive(Clone, Copy)]
struct QueueBudget {
    started: Instant,
    deadline: Instant,
}

impl GatewayProxy {
    /// 业务作用：按 route 声明的每条请求限流规则执行共享后端准入，并在首个拒绝处停止业务处理。
    ///
    /// 参数说明：
    /// - `parts`：是请求 head
    /// - `route`：是已匹配路由
    /// - `client_ip`：是权威客户端地址。
    /// - `context`：请求冻结的配置版本、实体上界与入口时刻。
    ///
    /// 返回：规则耗尽返回429，失权返回409，共享权威不可用返回503；全部允许为None。
    pub(super) async fn enforce_limit_req(
        &self,
        parts: &mut Parts,
        route: &Route,
        client_ip: IpAddr,
        context: AdmissionContext,
    ) -> Option<Response<BoxBody>> {
        let generation = context.generation;
        let queue_context = route
            .limit_req
            .iter()
            .filter_map(|policy| policy.queue)
            .map(|policy| policy.max_wait)
            .min()
            .map(|wait| {
                let previous = parts.extensions.get::<QueueBudget>().copied();
                let started = previous.map_or_else(Instant::now, |budget| budget.started);
                let deadline =
                    previous.map_or(started + wait, |budget| budget.deadline.min(started + wait));
                let deadline = route
                    .request_timeout_ms
                    .filter(|ms| *ms > 0)
                    .map_or(deadline, |ms| {
                        deadline.min(context.started + Duration::from_millis(ms))
                    });
                // 父层和叶子共享首次等待时刻，后续规则只能收紧总预算而不能重新计时。
                parts.extensions.insert(QueueBudget {
                    started,
                    deadline,
                });
                queue::Context {
                    deadline,
                    retained_bound: retained_bound(parts, context.body_upper),
                }
            });
        for (idx, policy) in route.limit_req.iter().enumerate() {
            let dimension = limit_req_dimension(parts, route, client_ip, &policy.key);
            let mut scope = format!("limit_req:{}:{}", route_state_scope(parts, route), idx);
            if let Some(warmup) = policy.warmup {
                use std::fmt::Write as _;
                // 只有相同速率和预热时序才复用热态，旧代请求不能把新曲线提前加热。
                let _ = write!(
                    scope,
                    ":warmup:{warmup}:{}:{}",
                    policy.limit,
                    policy.window.as_nanos()
                );
            }
            if let Some(queue) = policy.queue {
                use std::fmt::Write as _;
                // 只有相同速率和资源合同才复用债务，新策略不能继承旧预约的放行资格。
                let _ = write!(
                    scope,
                    ":queue:{}:{}:{}:{}:{}",
                    policy.limit,
                    policy.window.as_nanos(),
                    queue.interval_us,
                    queue.capacity,
                    queue.max_wait.as_micros()
                );
            }
            let key = format!("{}:{:016x}", scope, stable_hash64(dimension.as_bytes()));
            let request = RateLimitRequest {
                warmup: policy.warmup,
                state_budget: parts.extensions.get(),
                scope: &scope,
                key: &key,
                cost: 1,
                limit: policy.limit,
                window: policy.window,
                burst: policy.burst,
                max_active_keys: policy.max_active_keys,
                active_keys_fail_open: policy.active_keys_fail_open,
            };
            if let Some(policy) = policy.queue {
                let mut attempt = queue::metrics::Attempt::new();
                let admission = self.rate_limiter.queue(
                    request,
                    policy,
                    queue_context.expect("queue context compiled from route"),
                );
                tokio::pin!(admission);
                let outcome = loop {
                    // 等待期间持续检查当前配置，撤权后取消原预约，不能直到旧截止时刻才退出。
                    if self.snap.load().version != generation {
                        break Err(Rejected::Retired);
                    }
                    tokio::select! {
                        result = &mut admission => break result,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                };
                let outcome = if self.snap.load().version == generation {
                    outcome
                } else {
                    Err(Rejected::Retired)
                };
                attempt.complete(outcome);
                if let Err(reason) = outcome {
                    self.metrics.inc_rate_limited();
                    return Some(match reason {
                        Rejected::Retired => text_status(409, "queue authority changed"),
                        Rejected::Unavailable | Rejected::Clock => {
                            text_status(503, "queue authority unavailable")
                        }
                        _ => rate_limited_response(0),
                    });
                }
                continue;
            }
            #[cfg(feature = "rate-preallocation")]
            let decision = self
                .rate_limiter
                .allow_preallocated(request, generation)
                .await;
            #[cfg(not(feature = "rate-preallocation"))]
            let decision = {
                let _ = generation;
                self.rate_limiter.allow(request).await
            };
            if !decision.allowed {
                self.metrics.inc_rate_limited();
                // 租户规则的拒绝不能升级为全平台 IP 封禁；平台入口仍遵守全局自动封禁策略。
                if parts
                    .extensions
                    .get::<crate::control::ownership::Owner>()
                    .is_none_or(|owner| owner.workspace == crate::control::ownership::PLATFORM)
                {
                    self.maybe_auto_ban(client_ip).await;
                }
                return Some(rate_limited_response(decision.remaining));
            }
        }
        None
    }
}

/// 业务作用：按当前请求实体上界和保留头部计费，不读取或复制正文换取排队资格。
///
/// 参数说明：
/// - `parts`：本请求已完成变换的 head。
/// - `body_upper`：正文实现保证的剩余字节上界，未知时为空。
///
/// 返回：带保守结构开销的逻辑保留字节；未知或溢出不能进入等待态。
fn retained_bound(parts: &Parts, body_upper: Option<u64>) -> Option<u64> {
    let mut total = body_upper?.checked_add(4096)?;
    total = total.checked_add(parts.method.as_str().len() as u64)?;
    total = total.checked_add(parts.uri.scheme_str().map_or(0, str::len) as u64)?;
    total = total.checked_add(
        parts
            .uri
            .authority()
            .map_or(0, |value| value.as_str().len()) as u64,
    )?;
    total = total.checked_add(
        parts
            .uri
            .path_and_query()
            .map_or(0, |value| value.as_str().len()) as u64,
    )?;
    for (name, value) in &parts.headers {
        total = total.checked_add((name.as_str().len() + value.len() + 128) as u64)?;
    }
    total.checked_add((parts.headers.capacity() as u64).checked_mul(128)?)
}
