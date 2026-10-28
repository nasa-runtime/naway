//! 熔断窗口、保护状态与半开执行权。

use super::*;
use crate::routing::CircuitBreakerPolicy;

/// 转发结束时冻结的结果；后续响应改写、实体消费和统计后端延迟不改变该事实。
pub(super) struct Outcome {
    success: bool,
    elapsed: Duration,
}

impl Outcome {
    /// 业务作用：在取得原始响应头或上游终止错误时冻结熔断样本。
    ///
    /// 参数说明：
    /// - `status`：未经过 error_page 或响应插件改写的状态。
    /// - `started`：实际进入转发分支的单调时刻，未配置熔断时为空。
    ///
    /// 返回：存在熔断规则时返回原始状态与耗时；未启用时不读取时钟或分配样本。
    pub(super) fn capture(status: StatusCode, started: Option<Instant>) -> Option<Self> {
        started.map(|started| Self {
            success: !status.is_server_error(),
            elapsed: started.elapsed(),
        })
    }
}

#[derive(Debug, Default)]
pub(super) struct CircuitStates {
    entries: Mutex<HashMap<String, CircuitState>>,
}

impl crate::control::ownership::state::ReclaimExpired for CircuitStates {
    /// 业务作用：容量压力下回收空闲过期熔断器，不能抹去尚在保护期或执行中的控制状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅撤下已无在途凭证的过期条目，不阻塞状态更新。
    fn reclaim_expired(&self) {
        if let Some(mut states) = self.entries.try_lock() {
            let now = Instant::now();
            states.retain(|_, state| {
                state.expires_at > now
                    || state.active_calls > 0
                    || state.open_until.is_some_and(|until| until > now)
            });
        }
    }
}

#[derive(Debug)]
struct CircuitState {
    observation: crate::observability::circuit::Observation,
    _lease: Option<crate::control::ownership::state::Lease>,
    epoch: Arc<()>,
    active_calls: usize,
    expires_at: Instant,
    open_until: Option<Instant>,
    half_open_probe: bool,
}

impl CircuitState {
    /// 业务作用：在原熔断状态锁内发布已确定的保护事实，观测不反向参与许可裁决。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同步本实例状态和活动数；保护期限过去仍须真实探测才能离开open。
    fn observe(&mut self) {
        use crate::observability::circuit::State;
        let state = if self.half_open_probe {
            State::HalfOpen
        } else if self.open_until.is_some() {
            State::Open
        } else {
            State::Closed
        };
        self.observation.update(state, self.active_calls);
    }
}

pub(super) struct CircuitPermit {
    key: String,
    _lease: Option<crate::control::ownership::state::Lease>,
    budget: Option<crate::control::ownership::state::Budget>,
    epoch: Arc<()>,
    half_open: bool,
    policy: CircuitBreakerPolicy,
    /// Half-Open 探测必须用 RAII 释放：下游断连会取消整个 handler future，未必能走到
    /// `record_circuit_result`/`cancel_circuit_permits`。若无 Drop 兜底，探测位会永久卡住，
    /// 此后所有请求都被当作“已有探测在途”拒绝。
    states: Arc<CircuitStates>,
    release_half_open_on_drop: bool,
}

impl Drop for CircuitPermit {
    /// 业务作用：请求完成或取消时归还活动计数及本凭证持有的半开探测权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅修改同一状态实例，旧凭证不能释放新实例的探测权。
    fn drop(&mut self) {
        let mut states = self.states.entries.lock();
        if let Some(state) = states
            .get_mut(&self.key)
            .filter(|state| Arc::ptr_eq(&state.epoch, &self.epoch))
        {
            if self.release_half_open_on_drop && self.half_open {
                state.half_open_probe = false;
            }
            state.active_calls = state.active_calls.saturating_sub(1);
            state.observe();
        }
    }
}

impl GatewayProxy {
    /// 业务作用：在路由归属域内取得熔断许可，共享 backend 不共享租户请求失败账本。
    ///
    /// 参数说明：
    /// - `parts`：固定工作区上下文
    /// - `route`：提供策略
    /// - `permits`：保存本次请求取得的许可。
    ///
    /// 返回：全部熔断器允许时继续；任一拒绝时撤销已取得许可并返回声明的降级响应。
    pub(super) fn enforce_circuit_breakers(
        &self,
        parts: &Parts,
        route: &Route,
        permits: &mut Vec<CircuitPermit>,
    ) -> Option<Response<BoxBody>> {
        for (idx, policy) in route.circuit_breakers.iter().enumerate() {
            let key = format!(
                "circuit:{}:{}:{}:{}:{}:{}:{}",
                route_state_scope(parts, route),
                idx,
                policy.id,
                policy.window.as_nanos(),
                policy.break_duration.as_nanos(),
                policy.min_requests,
                policy.criterion,
            );
            match self.acquire_circuit_permit(
                key,
                policy,
                parts
                    .extensions
                    .get::<crate::control::ownership::state::Budget>(),
            ) {
                CircuitGate::Allowed(permit) => permits.push(permit),
                CircuitGate::Rejected => {
                    self.cancel_circuit_permits(std::mem::take(permits));
                    self.metrics.inc_circuit_rejected();
                    return Some(circuit_fallback_response(policy));
                }
            }
        }
        None
    }

    /// 业务作用：在独立归属容量内取得熔断执行权，半开只允许一个在途探测。
    ///
    /// 参数说明：
    /// - `key`：已包含归属和策略语义
    /// - `policy`：定义保护时长
    /// - `budget`：是冻结容量。
    ///
    /// 返回：带取消释放的许可；熔断开启或无状态容量时拒绝。
    fn acquire_circuit_permit(
        &self,
        key: String,
        policy: &CircuitBreakerPolicy,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> CircuitGate {
        let now = Instant::now();
        // 没有受归属容量管理的回收关系就不能建立新状态，避免退休工作区留下无界执行权。
        if budget.is_some_and(|budget| !budget.register_reclaimer(self.circuit_states.clone())) {
            return CircuitGate::Rejected;
        }
        let mut states = self.circuit_states.entries.lock();
        if !states.contains_key(&key) {
            states.retain(|_, state| {
                state.expires_at > now
                    || state.active_calls > 0
                    || state.open_until.is_some_and(|until| until > now)
            });
            // 平台与工作区分别承担状态预算；观测不能使容量拒绝转为隐式放行。
            if budget.is_none()
                && states
                    .values()
                    .filter(|state| state._lease.is_none())
                    .count()
                    >= 65_536
            {
                return CircuitGate::Rejected;
            }
            let lease = match budget.map(|budget| budget.acquire()).transpose() {
                Ok(lease) => lease,
                Err(_) => return CircuitGate::Rejected,
            };
            states.insert(
                key.clone(),
                CircuitState {
                    observation: crate::observability::circuit::Observation::new(
                        self.metrics.circuits.clone(),
                    ),
                    _lease: lease,
                    epoch: Arc::new(()),
                    active_calls: 0,
                    expires_at: now,
                    open_until: None,
                    half_open_probe: false,
                },
            );
        }
        let state = states.get_mut(&key).expect("inserted circuit state");
        state.expires_at = now
            + Duration::from_secs(60)
                .max(policy.window)
                .max(policy.break_duration);
        let mut half_open = false;
        if let Some(until) = state.open_until {
            if until > now {
                return CircuitGate::Rejected;
            }
            // 保护期结束也保留 open_until，直到唯一探测成功才开放业务；取消仅归还探测权。
            if state.half_open_probe {
                return CircuitGate::Rejected;
            }
            state.half_open_probe = true;
            half_open = true;
        }
        state.active_calls = state.active_calls.saturating_add(1);
        state.observe();
        CircuitGate::Allowed(CircuitPermit {
            key,
            _lease: state._lease.clone(),
            budget: budget.cloned(),
            epoch: state.epoch.clone(),
            half_open,
            policy: policy.clone(),
            states: self.circuit_states.clone(),
            release_half_open_on_drop: half_open,
        })
    }

    /// 业务作用：先完成所属域窗口统计，再推进原熔断实例；迟到结果不能创建退休实例。
    ///
    /// 参数说明：
    /// - `permits`：固定每条规则的状态实例与预算
    /// - `outcome`：为转发结束时冻结的原始状态与耗时。
    ///
    /// 返回：探测成功解除保护，失败或统计达到阈值进入保护；最后释放活动名额引用。
    pub(super) async fn record_circuit_result(
        &self,
        permits: Vec<CircuitPermit>,
        outcome: Outcome,
    ) {
        for mut permit in permits {
            let negative = permit
                .policy
                .criterion
                .negative(outcome.success, outcome.elapsed);
            if permit.half_open {
                // 慢调用探测既要响应及时也要成功；快速失败不能被当成后端已恢复而开放业务。
                let success = outcome.success && !negative;
                // 先清空旧统计再解除保护，失败或仍然缓慢的探测重新进入保护期。
                if success {
                    self.circuit_stats
                        .reset_scoped(&permit.key, permit.budget.as_ref())
                        .await;
                }
                let now = Instant::now();
                let mut states = self.circuit_states.entries.lock();
                let Some(state) = states
                    .get_mut(&permit.key)
                    .filter(|state| Arc::ptr_eq(&state.epoch, &permit.epoch))
                else {
                    continue;
                };
                state.half_open_probe = false;
                state.open_until = if success {
                    None
                } else {
                    Some(now + permit.policy.break_duration)
                };
                state.observe();
                // 状态机已确定落到 Closed/Open；解除 Drop 的取消兜底，避免正常返回重复修改。
                permit.release_half_open_on_drop = false;
                continue;
            }
            // Closed 态:把结果计入(本地或集群共享)滑动窗口,拿聚合值判是否跳闸。
            let window = self
                .circuit_stats
                .record_scoped(
                    &permit.key,
                    !negative,
                    permit.policy.window,
                    permit.budget.as_ref(),
                )
                .await;
            if window.total >= permit.policy.min_requests
                && permit
                    .policy
                    .criterion
                    .exceeded(window.total, window.failures)
            {
                let now = Instant::now();
                let mut states = self.circuit_states.entries.lock();
                if let Some(state) = states.get_mut(&permit.key).filter(|state| {
                    Arc::ptr_eq(&state.epoch, &permit.epoch) && state.open_until.is_none()
                }) {
                    // 迟到的普通请求不得覆盖已进入半开阶段的探测结果或不断延长同一次保护期。
                    state.open_until = Some(now + permit.policy.break_duration);
                    state.observe();
                }
            }
        }
    }

    /// 业务作用：撤销尚未执行的整组许可，统一通过凭证释放各自探测权。
    ///
    /// 参数说明：
    /// - `permits`：为已取得的规则许可。
    ///
    /// 返回：释放活动计数，不写成功或失败统计。
    pub(super) fn cancel_circuit_permits(&self, permits: Vec<CircuitPermit>) {
        drop(permits);
    }
}

enum CircuitGate {
    Allowed(CircuitPermit),
    Rejected,
}

/// 业务作用：在熔断开放时产生声明的降级响应，不再发起被保护的上游尝试。
fn circuit_fallback_response(policy: &CircuitBreakerPolicy) -> Response<BoxBody> {
    Response::builder()
        .status(policy.fallback_status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-gateway-circuit", "open")
        .body(full_body(Bytes::from(policy.fallback_body.clone())))
        .expect("build circuit fallback response")
}
