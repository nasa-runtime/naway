//! 请求入口的原生速率、预热与匀速队列准入。

use super::*;
use crate::config::sentinel::request::{self, Policy, RequestRules, Rule};
use crate::observability::http_stream::routes::{record_sentinel_rejection, SentinelRejection};
use crate::observability::logging::scoped::{Active as ScopedLog, Module};
use crate::routing::{CircuitBreakerPolicy, LimitConnPolicy, LimitReqPolicy};
use crate::runtime::sentinel::queue::{self, Rejected};

pub(super) struct AdmissionContext<'a> {
    pub(super) generation: u64,
    pub(super) body_upper: Option<u64>,
    pub(super) started: Instant,
    pub(super) log: &'a ScopedLog,
}

/// 独立请求规则冻结实际命中结果与完整分桶值；后续头部改写不重新推导身份。
#[derive(Default)]
pub(super) struct MatchedRules<'a> {
    pub(super) rate: Vec<(&'a Rule, &'a LimitReqPolicy, u64)>,
    pub(super) concurrency: Vec<(&'a Rule, &'a LimitConnPolicy, u64)>,
    pub(super) circuit: Vec<(&'a Rule, &'a CircuitBreakerPolicy)>,
}

impl<'a> MatchedRules<'a> {
    /// 业务作用：在执行转发过滤器前冻结适用规则和计数维度，使路径与属性选择共享同一请求事实。
    ///
    /// 参数说明：
    /// - `index`：当前不可变快照中的请求索引。
    /// - `parts`：过滤器改写前的入口头。
    /// - `route`：当前已选择的路由或层级。
    /// - `client_ip`：由网关验证的客户端地址。
    /// - `include_paths`：终端执行路径规则，分支仅查询自己的精确规则。
    ///
    /// 返回：按规则声明顺序分组的命中项，未命中时不分配策略存储。
    pub(super) fn find(
        index: &'a RequestRules,
        parts: &Parts,
        route: &Route,
        client_ip: IpAddr,
        include_paths: bool,
    ) -> Self {
        let mut matched = Self::default();
        for rule in index.matching(parts, &route.id, client_ip, include_paths) {
            match &rule.policy {
                Policy::Rate(policy) => matched.rate.push((
                    rule,
                    policy,
                    dimension_hash(parts, route, client_ip, &policy.key),
                )),
                Policy::Concurrency(policy) => matched.concurrency.push((
                    rule,
                    policy,
                    dimension_hash(parts, route, client_ip, &policy.key),
                )),
                Policy::Circuit(policy) => matched.circuit.push((rule, policy)),
            }
        }
        matched
    }
}

/// 业务作用：限制命中规则的状态共享范围，不能让一个工作区的请求消耗另一个工作区的保护额度。
///
/// 参数说明：
/// - `parts`：含网关冻结的归属和路由状态域。
/// - `route`：精确规则沿用原路由域。
/// - `rule`：共享规则身份和跨路由声明。
///
/// 返回：按规则及归属区分的共享键作用域。
pub(super) fn rule_scope(parts: &Parts, route: &Route, rule: &Rule) -> String {
    let scope = if rule.crosses_routes {
        parts
            .extensions
            .get::<crate::control::ownership::Owner>()
            .map_or_else(
                || crate::control::ownership::PLATFORM.to_owned(),
                |owner| owner.namespace(),
            )
    } else {
        route_state_scope(parts, route).to_owned()
    };
    format!("sentinel:{}:{scope}", rule.identity)
}

/// 业务作用：保持完整值分桶并分离缺失状态，避免真实文本占用缺失属性的额度。
///
/// 参数说明：
/// - `parts`：待读取维度的请求头。
/// - `route`：提供冻结的路由标识。
/// - `client_ip`：网关确认的客户端地址。
/// - `key`：已编译取值方式。
///
/// 返回：稳定维度摘要；正常 UTF-8 值沿用既有键，文本 `<missing>` 进入独立桶。
pub(super) fn dimension_hash(
    parts: &Parts,
    route: &Route,
    client_ip: IpAddr,
    key: &LimitReqKey,
) -> u64 {
    match request::value(parts, &route.id, client_ip, key).as_deref() {
        None => stable_hash64(b"<missing>"),
        Some(b"<missing>") => stable_hash64(b"\x00<missing>"),
        Some(value) => stable_hash64(value),
    }
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
    /// - `matched`：已从原始请求冻结的独立规则。
    /// - `context`：请求冻结的配置版本、实体上界、入口时刻及日志归属。
    ///
    /// 返回：规则耗尽返回429，失权返回409，共享权威不可用返回503；全部允许为None。
    pub(super) async fn enforce_limit_req(
        &self,
        parts: &mut Parts,
        route: &Route,
        client_ip: IpAddr,
        matched: &MatchedRules<'_>,
        context: AdmissionContext<'_>,
    ) -> Option<Response<BoxBody>> {
        let generation = context.generation;
        let queue_context = route
            .limit_req
            .iter()
            .chain(matched.rate.iter().map(|(_, policy, _)| *policy))
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
        let native = route
            .limit_req
            .iter()
            .enumerate()
            .map(|(index, policy)| (index, policy, None));
        let request_rules = matched
            .rate
            .iter()
            .map(|&(rule, policy, dimension)| (0, policy, Some((rule, dimension))));
        for (idx, policy, indexed) in native.chain(request_rules) {
            let (mut scope, dimension) = if let Some((rule, dimension)) = indexed {
                (
                    format!("limit_req:{}", rule_scope(parts, route, rule)),
                    dimension,
                )
            } else {
                let route_scope = route_state_scope(parts, route);
                // 独立规则以编译的计量身份归账，内联规则继续读取原位置的余额。
                let scope = match route
                    .sentinel_flows
                    .as_ref()
                    .and_then(|flows| flows.rate.get(&idx))
                {
                    Some(identity) => format!("limit_req:sentinel:{identity}:{route_scope}"),
                    None => format!("limit_req:{route_scope}:{idx}"),
                };
                (scope, dimension_hash(parts, route, client_ip, &policy.key))
            };
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
            let key = format!("{scope}:{dimension:016x}");
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
                    context.log.record_module(Module::Sentinel, || {
                        tracing::debug!(route = %route.id, ?reason, "Sentinel queue denied request");
                    });
                    self.metrics.inc_rate_limited();
                    record_sentinel_rejection(
                        parts,
                        match reason {
                            Rejected::Retired => SentinelRejection::QueueRetired,
                            Rejected::Unavailable | Rejected::Clock => {
                                SentinelRejection::QueueUnavailable
                            }
                            _ => SentinelRejection::Queue,
                        },
                    );
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
                context.log.record_module(Module::Sentinel, || {
                    tracing::debug!(route = %route.id, "Sentinel rate denied request");
                });
                self.metrics.inc_rate_limited();
                record_sentinel_rejection(parts, SentinelRejection::Rate);
                // 租户规则的拒绝不能升级为全平台 IP 封禁；平台入口仍遵守全局自动封禁策略。
                if parts
                    .extensions
                    .get::<crate::control::ownership::Owner>()
                    .is_none_or(|owner| owner.workspace == crate::control::ownership::PLATFORM)
                {
                    self.maybe_auto_ban(parts, generation, client_ip, auto_ban::Signal::Rate)
                        .await;
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
