//! 上游准入控制:retry budget 与自适应并发。
//!
//! 两者回答的是**不同问题**,必须分开建模:
//! - route 的 `next_upstream` 决定「这次失败**能不能**重试」(语义问题);
//! - retry budget 决定「当前整体**还能不能**再发重试」(容量问题)。
//!
//! 自适应并发同理:它不判断请求对错,只在后端已经变慢时收紧在途上限,把过载压力
//! 挡在网关而不是传导给后端。所有拒绝都是明确状态码,绝不静默丢弃。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;

#[cfg(feature = "telemetry-otlp")]
use crate::observability::metrics::governance::{admission, Admission};
use crate::upstream::load::monotonic_ms;

/// 自适应并发的最小采样数:样本太少时不得据此改动上限,否则单次抖动就会剧烈收缩。
const MIN_SAMPLES_PER_WINDOW: u64 = 5;
/// 单次窗口允许的最大上限变化倍率(万分比),防止一次采样把上限打到极端值。
const MAX_STEP_BP: u64 = 20_000;

/// 一次上游结果对准入统计的意义。
///
/// **区分来源是正确性问题**:把客户端取消或网关自身的过载拒绝当成"后端慢",
/// 会让自适应并发不断收紧,最终把健康后端压到零并发——故障会自我放大。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdmissionOutcome {
    /// 上游真实返回了响应头:唯一可用于延迟采样的样本。
    UpstreamResponded,
    /// 上游明确拒绝(连接被拒、协议错):计入失败,但不作为延迟样本。
    UpstreamRejected,
    /// 客户端提前取消/断开:与后端能力无关,完全不计入。
    ClientCanceled,
    /// 网关自身准入拒绝(并发满、预算耗尽):不得反过来当作后端变慢的证据。
    GatewayRejected,
    /// 主动健康探测等非业务流量:不参与业务并发调节。
    Probe,
}

impl AdmissionOutcome {
    /// 业务作用：判断结果是否包含可归因于真实上游的响应延迟。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有真实上游返回响应头时返回 `true`。
    fn is_latency_sample(self) -> bool {
        matches!(self, Self::UpstreamResponded)
    }
}

/// backend 级 retry budget 策略。
#[derive(Clone, Debug)]
pub struct RetryBudgetPolicy {
    /// 允许的活动重试数占滚动请求数的百分比(1..=100)。
    pub budget_percent: u32,
    /// 无论比例如何都允许的最小并发重试数,保证低流量服务仍能重试。
    pub min_retry_concurrency: u64,
    /// 滚动窗口内允许的最小重试总量，用于把低流量下的最小重试率换算为本地预算。
    pub min_retries_per_window: u64,
    /// 滚动统计窗口(ms)。
    pub window_ms: u64,
}

impl RetryBudgetPolicy {
    /// 业务作用：构造显式启用 retry budget 时的保守默认策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：10 秒窗口、20% 且至少 3 个并发重试的策略。
    pub fn default_enabled() -> Self {
        Self {
            budget_percent: 20,
            min_retry_concurrency: 3,
            min_retries_per_window: 3,
            window_ms: 10_000,
        }
    }
}

/// backend 级 retry budget 运行态。
#[derive(Debug, Default)]
struct RetryWindow {
    requests: u64,
    previous_requests: u64,
    retries: u64,
    started_ms: u64,
}

/// backend 级 retry budget 运行态。
#[derive(Debug, Default)]
pub struct RetryBudgetState {
    /// 窗口代次与计数必须在同一临界区切换，避免新窗口请求被旧线程交换进 previous。
    window: Mutex<RetryWindow>,
    /// 当前活动重试数。
    active_retries: AtomicU64,
}

impl RetryBudgetState {
    /// 业务作用：登记一次进入该 backend 的请求,推进滚动窗口。
    ///
    /// 参数说明：
    /// - `policy`：提供窗口长度。
    ///
    /// 返回：无返回值。
    pub fn record_request(&self, policy: &RetryBudgetPolicy) {
        let now = monotonic_ms();
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rotate_retry_window(&mut window, policy.window_ms, now);
        window.requests = window.requests.saturating_add(1);
    }

    /// 业务作用：尝试为一次重试取得预算名额。
    ///
    /// 预算同时受三件事约束:滚动请求量、允许的重试占比、以及**当前活动重试数**。
    /// 只看比例不看活动数,会在故障瞬间放行远超预算的并发重试;只看活动数不看比例,
    /// 又会让大流量服务的重试上限固定得离谱。
    ///
    /// 参数说明：
    /// - `policy`：是 backend 级预算策略。
    ///
    /// 返回：取得名额时返回 RAII 令牌(Drop 归还);预算耗尽返回 `None`。
    pub fn try_acquire(self: &Arc<Self>, policy: &RetryBudgetPolicy) -> Option<RetryPermit> {
        let allowed = {
            let now = monotonic_ms();
            let mut window = self
                .window
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            rotate_retry_window(&mut window, policy.window_ms, now);
            let requests = window.requests.max(window.previous_requests);
            let allowed = (requests.saturating_mul(u64::from(policy.budget_percent)) / 100)
                .max(policy.min_retry_concurrency)
                .max(policy.min_retries_per_window);
            // 窗口总量与代次一起提交，避免切窗线程把新请求的重试误清零。
            if window.retries >= allowed {
                #[cfg(feature = "telemetry-otlp")]
                admission(Admission::RetryRejected);
                return None;
            }
            window.retries = window.retries.saturating_add(1);
            allowed
        };

        // ② 活动重试**并发**门:限制同一瞬间在飞的重试,避免突发并发把后端打穿。
        //    CAS 循环而不是 fetch_add 后回退:回退式实现会短暂突破上限,
        //    在重试风暴场景下这个"短暂"正好是最危险的时刻。
        let mut active = self.active_retries.load(Ordering::Relaxed);
        loop {
            if active >= allowed {
                // 并发门未过时必须把已占的窗口配额还回去,否则预算会被悄悄漏掉。
                let mut window = self
                    .window
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                window.retries = window.retries.saturating_sub(1);
                #[cfg(feature = "telemetry-otlp")]
                admission(Admission::RetryRejected);
                return None;
            }
            match self.active_retries.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    #[cfg(feature = "telemetry-otlp")]
                    admission(Admission::RetryGranted);
                    return Some(RetryPermit {
                        state: self.clone(),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }

    /// 业务作用：读取当前活动重试数，供低基数指标导出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未结束的重试尝试数。
    pub fn active_retries(&self) -> u64 {
        self.active_retries.load(Ordering::Relaxed)
    }
}

/// 业务作用：在同一临界区推进 retry budget 窗口代次并保留上一窗口请求基数。
///
/// 参数说明：
/// - `window`：是共享窗口状态
/// - `window_ms`：是窗口长度
/// - `now`：是当前单调毫秒。
///
/// 返回：无；跨越多个完整窗口时清除已经失效的 previous 基数。
fn rotate_retry_window(window: &mut RetryWindow, window_ms: u64, now: u64) {
    if window.started_ms == 0 {
        window.started_ms = now;
        return;
    }
    let elapsed = now.saturating_sub(window.started_ms);
    if elapsed < window_ms.max(1) {
        return;
    }
    window.previous_requests = if elapsed >= window_ms.max(1).saturating_mul(2) {
        0
    } else {
        window.requests
    };
    window.requests = 0;
    window.retries = 0;
    window.started_ms = now;
}

/// retry budget 名额的 RAII 令牌;Drop 即归还,异常路径也不会泄漏预算。
pub struct RetryPermit {
    state: Arc<RetryBudgetState>,
}

impl Drop for RetryPermit {
    /// 业务作用：在重试尝试结束或取消时归还活动并发名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；RAII 确保所有退出路径都执行归还。
    fn drop(&mut self) {
        self.state.active_retries.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 自适应并发策略。
#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencyPolicy {
    /// 在途上限下界:再拥塞也保留这么多并发,避免把后端彻底饿死。
    pub min_concurrency: u64,
    /// 在途上限上界。
    pub max_concurrency: u64,
    /// 采样窗口(ms):窗口结束时据窗口内延迟重算上限。
    pub sample_window_ms: u64,
    /// minRTT 重新标定周期(ms)。
    pub min_rtt_window_ms: u64,
    /// 标定周期的抖动万分比,避免多节点同时进入标定造成同步震荡。
    pub jitter_bp: u32,
    /// 超出上限时允许排队的请求数;0 表示直接拒绝不排队。
    pub queue_limit: u64,
    /// 排队最长等待(ms);超时按过载拒绝。
    pub queue_deadline_ms: u64,
}

impl AdaptiveConcurrencyPolicy {
    /// 业务作用：构造自适应并发显式启用时的保守默认策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：带有限上下界、采样周期和默认不排队的策略。
    pub fn defaults() -> Self {
        Self {
            min_concurrency: 4,
            max_concurrency: 1_024,
            sample_window_ms: 1_000,
            min_rtt_window_ms: 30_000,
            jitter_bp: 1_000,
            queue_limit: 0,
            queue_deadline_ms: 100,
        }
    }
}

/// 自适应并发运行态。
#[derive(Debug)]
pub struct AdaptiveConcurrencyState {
    /// 当前允许的在途上限。
    limit: AtomicU64,
    /// 当前在途请求数。
    in_flight: AtomicU64,
    /// 当前排队等待数。
    queued: AtomicU64,
    /// 观测到的最小 RTT(微秒);0 表示尚未标定。
    min_rtt_micros: AtomicU64,
    /// 当前采样窗口的延迟总和与样本数。
    window_sum_micros: AtomicU64,
    window_samples: AtomicU64,
    /// 当前采样窗口结束时刻。
    window_end_ms: AtomicU64,
    /// 下次 minRTT 重标定时刻。
    recalibrate_at_ms: AtomicU64,
    /// 是否正处于 minRTT 标定期(此时按下界收紧以测得真实空载延迟)。
    calibrating: AtomicU64,
}

impl AdaptiveConcurrencyState {
    /// 业务作用：以策略下界为初始上限建立运行态。
    ///
    /// 参数说明：
    /// - `policy`：提供初始上下界。
    ///
    /// 返回：初始运行态。
    pub fn new(policy: &AdaptiveConcurrencyPolicy) -> Self {
        Self {
            limit: AtomicU64::new(policy.min_concurrency.max(1)),
            in_flight: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            min_rtt_micros: AtomicU64::new(0),
            window_sum_micros: AtomicU64::new(0),
            window_samples: AtomicU64::new(0),
            window_end_ms: AtomicU64::new(0),
            recalibrate_at_ms: AtomicU64::new(0),
            calibrating: AtomicU64::new(0),
        }
    }

    /// 业务作用：在配置换版后立即把已继承的运行上限收敛到新策略边界。
    ///
    /// 参数说明：
    /// - `policy`：是当前快照已经校验的并发上下界。
    ///
    /// 返回：无返回值；只钳制当前上限，不清空 minRTT、采样窗口或在途计数。
    pub fn reconcile_policy(&self, policy: &AdaptiveConcurrencyPolicy) {
        let lower = policy.min_concurrency.max(1);
        let upper = policy.max_concurrency.max(lower);
        let _ = self
            .limit
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some(current.clamp(lower, upper))
            });
    }

    /// 业务作用：读取当前自适应在途上限，供指标与管理面展示。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前允许的最大在途请求数。
    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// 业务作用：读取当前已占用的上游在途名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前尚未释放的并发名额数。
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// 业务作用：读取当前等待自适应并发名额的请求数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前仍持有排队位置的请求数。
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }

    /// 业务作用：尝试立即取得一个在途名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功返回 RAII 名额;在途已达上限返回 `None`,由调用方决定排队还是拒绝。
    pub fn try_acquire(self: &Arc<Self>) -> Option<ConcurrencyPermit> {
        let limit = self.limit.load(Ordering::Relaxed);
        let mut in_flight = self.in_flight.load(Ordering::Relaxed);
        loop {
            if in_flight >= limit {
                #[cfg(feature = "telemetry-otlp")]
                admission(Admission::ConcurrencyBusy);
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    #[cfg(feature = "telemetry-otlp")]
                    admission(Admission::ConcurrencyGranted);
                    return Some(ConcurrencyPermit {
                        state: self.clone(),
                    });
                }
                Err(observed) => in_flight = observed,
            }
        }
    }

    /// 业务作用：登记一次排队,受排队上限约束。
    ///
    /// 参数说明：
    /// - `policy`：提供排队上限。
    ///
    /// 返回：取得排队位返回 RAII 令牌;队列已满返回 `None`(必须立即拒绝而不是无界等待)。
    pub fn try_enqueue(self: &Arc<Self>, policy: &AdaptiveConcurrencyPolicy) -> Option<QueueSlot> {
        if policy.queue_limit == 0 {
            #[cfg(feature = "telemetry-otlp")]
            admission(Admission::QueueRejected);
            return None;
        }
        let mut queued = self.queued.load(Ordering::Relaxed);
        loop {
            if queued >= policy.queue_limit {
                #[cfg(feature = "telemetry-otlp")]
                admission(Admission::QueueRejected);
                return None;
            }
            match self.queued.compare_exchange_weak(
                queued,
                queued + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    #[cfg(feature = "telemetry-otlp")]
                    admission(Admission::Queued);
                    return Some(QueueSlot {
                        state: self.clone(),
                    });
                }
                Err(observed) => queued = observed,
            }
        }
    }

    /// 业务作用：并入一次上游结果,并在采样窗口结束时重算在途上限。
    ///
    /// **只有真实上游响应才是延迟样本**:客户端取消、网关自身拒绝与探测流量一律
    /// 不参与,否则会把网关自己造成的拒绝当成后端变慢,形成收紧→更多拒绝→继续收紧
    /// 的自激循环。
    ///
    /// 参数说明：
    /// - `policy`：是自适应并发策略
    /// - `outcome`：是结果分类
    /// - `rtt_micros`：是上游响应头耗时。
    ///
    /// 返回：无；只有达到采样门槛的真实上游响应才可能调整上限。
    pub fn record(
        &self,
        policy: &AdaptiveConcurrencyPolicy,
        outcome: AdmissionOutcome,
        rtt_micros: u64,
    ) {
        if !outcome.is_latency_sample() || rtt_micros == 0 {
            return;
        }
        let now = monotonic_ms();
        // minRTT 标定:周期性把上限压到下界,测得接近空载的延迟基线。
        // 不定期重标定,基线会被长期高负载"污染"成偏大值,自适应随之失去意义。
        let recalibrate_at = self.recalibrate_at_ms.load(Ordering::Relaxed);
        if recalibrate_at == 0 {
            self.recalibrate_at_ms.store(
                now.saturating_add(jittered(policy.min_rtt_window_ms, policy.jitter_bp, now)),
                Ordering::Relaxed,
            );
        } else if now >= recalibrate_at
            && self
                .recalibrate_at_ms
                .compare_exchange(
                    recalibrate_at,
                    now.saturating_add(jittered(policy.min_rtt_window_ms, policy.jitter_bp, now)),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            self.calibrating.store(1, Ordering::Release);
            self.min_rtt_micros.store(0, Ordering::Release);
            let previous = self
                .limit
                .swap(policy.min_concurrency.max(1), Ordering::AcqRel);
            #[cfg(feature = "telemetry-otlp")]
            if previous > policy.min_concurrency.max(1) {
                admission(Admission::LimitDecreased);
            }
            #[cfg(not(feature = "telemetry-otlp"))]
            let _ = previous;
        }

        // 并发响应只能把 minRTT 向更小值推进；普通 load/store 会让较慢线程
        // 在较快样本之后覆盖回更大的值，基线随并发顺序漂移。
        let _ = self
            .min_rtt_micros
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                (current == 0 || rtt_micros < current).then_some(rtt_micros)
            });

        let _ =
            self.window_sum_micros
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(rtt_micros))
                });
        let samples = self
            .window_samples
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some(current.saturating_add(1))
            })
            .unwrap_or_else(|current| current)
            .saturating_add(1);

        let window_end = self.window_end_ms.load(Ordering::Relaxed);
        if window_end == 0 {
            let _ = self.window_end_ms.compare_exchange(
                0,
                now.saturating_add(policy.sample_window_ms),
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
            return;
        }
        if now < window_end || samples < MIN_SAMPLES_PER_WINDOW {
            return;
        }
        // 只有一个 worker 能推进窗口,避免多线程用同一批样本重复调整上限。
        if self
            .window_end_ms
            .compare_exchange(
                window_end,
                now.saturating_add(policy.sample_window_ms),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }
        let sum = self.window_sum_micros.swap(0, Ordering::AcqRel);
        let count = self.window_samples.swap(0, Ordering::AcqRel).max(1);
        let avg = sum / count;
        let min_rtt = self.min_rtt_micros.load(Ordering::Relaxed).max(1);
        self.calibrating.store(0, Ordering::Release);

        // 梯度 = minRTT / 采样延迟:后端越慢梯度越小,上限随之收紧;
        // 空载时梯度趋近 1,上限缓慢回升。用定点万分比避免浮点。
        let gradient_bp = ((u128::from(min_rtt) * 10_000 / u128::from(avg.max(1)))
            .min(u128::from(MAX_STEP_BP))) as u64;
        let current = self.limit.load(Ordering::Relaxed).max(1);
        // headroom 取 sqrt(limit):没有它,上限一旦收紧就再也涨不回来
        // (梯度恒 ≤1 只会让 limit 单调下降)。
        let headroom = (current as f64).sqrt() as u64;
        let adjusted = (u128::from(current) * u128::from(gradient_bp) / 10_000)
            .saturating_add(u128::from(headroom))
            .min(u128::from(u64::MAX)) as u64;
        let next = adjusted.clamp(
            policy.min_concurrency.max(1),
            policy.max_concurrency.max(policy.min_concurrency.max(1)),
        );
        self.limit.store(next, Ordering::Relaxed);
        #[cfg(feature = "telemetry-otlp")]
        if next != current {
            admission(if next > current {
                Admission::LimitIncreased
            } else {
                Admission::LimitDecreased
            });
        }
    }
}

/// 业务作用：给周期加上确定性抖动,避免多节点同时进入 minRTT 标定造成同步震荡。
///
/// 参数说明：
/// - `base_ms`：是基准周期
/// - `jitter_bp`：是抖动万分比
/// - `seed`：提供确定性熵。
///
/// 返回：抖动后的周期。
fn jittered(base_ms: u64, jitter_bp: u32, seed: u64) -> u64 {
    if jitter_bp == 0 {
        return base_ms;
    }
    let span = base_ms.saturating_mul(u64::from(jitter_bp.min(10_000))) / 10_000;
    if span == 0 {
        return base_ms;
    }
    let mut hash = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    hash ^= hash >> 29;
    base_ms.saturating_sub(span / 2) + (hash % span.max(1))
}

/// 在途名额的 RAII 令牌。
pub struct ConcurrencyPermit {
    state: Arc<AdaptiveConcurrencyState>,
}

impl Drop for ConcurrencyPermit {
    /// 业务作用：在上游尝试结束或取消时归还自适应并发名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 排队位的 RAII 令牌。
pub struct QueueSlot {
    state: Arc<AdaptiveConcurrencyState>,
}

impl Drop for QueueSlot {
    /// 业务作用：在请求离队、超时或取消时归还有界队列位置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn drop(&mut self) {
        self.state.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 业务作用：校验并构建 retry budget 策略。
///
/// 参数说明：
/// - `cfg`：是可选预算配置。
///
/// 返回：未配置返回 `None`;阈值越界返回错误。
pub fn build_retry_budget(
    cfg: Option<&crate::config::model::RetryBudgetCfg>,
) -> Result<Option<RetryBudgetPolicy>> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    if !cfg.enabled {
        return Ok(None);
    }
    let mut policy = RetryBudgetPolicy::default_enabled();
    if let Some(percent) = cfg.budget_percent {
        anyhow::ensure!(percent <= 100, "retry_budget.budget_percent 必须在 0..=100");
        policy.budget_percent = percent;
    }
    if let Some(min) = cfg.min_retry_concurrency {
        anyhow::ensure!(
            (1..=100_000).contains(&min),
            "retry_budget.min_retry_concurrency 必须在 1..=100000"
        );
        policy.min_retry_concurrency = min;
    }
    if let Some(minimum) = cfg.min_retries_per_window {
        anyhow::ensure!(
            (1..=1_000_000).contains(&minimum),
            "retry_budget.min_retries_per_window 必须在 1..=1000000"
        );
        policy.min_retries_per_window = minimum;
    }
    if let Some(window) = cfg.window_ms {
        anyhow::ensure!(
            (100..=3_600_000).contains(&window),
            "retry_budget.window_ms 必须在 100..=3600000"
        );
        policy.window_ms = window;
    }
    Ok(Some(policy))
}

/// 业务作用：校验并构建自适应并发策略。
///
/// 参数说明：
/// - `cfg`：是可选自适应并发配置。
///
/// 返回：未配置返回 `None`;上下界颠倒或阈值越界返回错误。
pub fn build_adaptive_concurrency(
    cfg: Option<&crate::config::model::AdaptiveConcurrencyCfg>,
) -> Result<Option<AdaptiveConcurrencyPolicy>> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    if !cfg.enabled {
        return Ok(None);
    }
    let mut policy = AdaptiveConcurrencyPolicy::defaults();
    if let Some(min) = cfg.min_concurrency {
        anyhow::ensure!(min >= 1, "adaptive_concurrency.min_concurrency 必须 >= 1");
        policy.min_concurrency = min;
    }
    if let Some(max) = cfg.max_concurrency {
        policy.max_concurrency = max;
    }
    anyhow::ensure!(
        policy.min_concurrency <= policy.max_concurrency,
        "adaptive_concurrency.min_concurrency 不得大于 max_concurrency"
    );
    if let Some(window) = cfg.sample_window_ms {
        anyhow::ensure!(
            (50..=60_000).contains(&window),
            "adaptive_concurrency.sample_window_ms 必须在 50..=60000"
        );
        policy.sample_window_ms = window;
    }
    if let Some(window) = cfg.min_rtt_window_ms {
        anyhow::ensure!(
            (1_000..=3_600_000).contains(&window),
            "adaptive_concurrency.min_rtt_window_ms 必须在 1000..=3600000"
        );
        policy.min_rtt_window_ms = window;
    }
    if let Some(jitter) = cfg.jitter_bp {
        anyhow::ensure!(
            jitter <= 10_000,
            "adaptive_concurrency.jitter_bp 必须在 0..=10000"
        );
        policy.jitter_bp = jitter;
    }
    if let Some(queue) = cfg.queue_limit {
        anyhow::ensure!(
            queue <= 1_000_000,
            "adaptive_concurrency.queue_limit 必须 <= 1000000"
        );
        policy.queue_limit = queue;
    }
    if let Some(deadline) = cfg.queue_deadline_ms {
        anyhow::ensure!(
            (1..=60_000).contains(&deadline),
            "adaptive_concurrency.queue_deadline_ms 必须在 1..=60000"
        );
        policy.queue_deadline_ms = deadline;
    }
    Ok(Some(policy))
}
