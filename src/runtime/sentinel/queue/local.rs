//! 本地队列的跨请求状态与RAII等待凭证，实体仍由原请求持有，不进入调度表。

use super::policy::{Claim, Reservation};
use super::schedule::Schedule;
use super::{Context, Policy, Rejected};
use crate::control::ownership::state::{Lease, ReclaimExpired};
use crate::runtime::state::RateLimitRequest;
use crate::runtime::traffic_limit::resources::Retained;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_STATES: usize = 65_536;
static STATES: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct StateSlot;

#[derive(Debug)]
pub(crate) struct Local {
    origin: Instant,
    retired: AtomicBool,
    entries: Mutex<Entries>,
}

#[derive(Debug, Default)]
struct Entries {
    values: HashMap<String, Arc<Entry>>,
    scopes: HashMap<Arc<str>, usize>,
    last_sweep_us: u64,
}

#[derive(Debug)]
struct Entry {
    scope: Arc<str>,
    policy: Policy,
    schedule: Mutex<Schedule>,
    _lease: Option<Lease>,
    _slot: StateSlot,
}

struct Waiting {
    entry: Arc<Entry>,
    ticket: u64,
    _retained: Retained,
    _monitor: super::metrics::Wait,
}

impl Default for Local {
    /// 业务作用：建立同一后端实例共享的本地时钟与有限状态目录，不产生后台任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未退休的空调度后端。
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            retired: AtomicBool::new(false),
            entries: Mutex::new(Entries::default()),
        }
    }
}

impl Local {
    /// 业务作用：在同维度FIFO与共享资源预算内等待实际匀速放行权，取消自动归还本地名额。
    ///
    /// 参数说明：
    /// - `request`：冻结规则、维度与工作区状态预算。
    /// - `policy`：该规则整数时序和容量合同。
    /// - `context`：不随轮询延期的入口期限与已知实体上界。
    ///
    /// 返回：实际获得调度授权时成功，超时、退休或容量拒绝不转发业务。
    pub(crate) async fn admit(
        self: &Arc<Self>,
        request: RateLimitRequest<'_>,
        policy: Policy,
        context: Context,
    ) -> Result<(), Rejected> {
        if Instant::now() >= context.deadline {
            return Err(Rejected::Deadline);
        }
        if request.cost != 1
            || request.warmup.is_some()
            || request.burst != 0
            || Policy::build(
                request.limit,
                request.window,
                policy.capacity,
                policy.max_wait.as_millis().min(u128::from(u64::MAX)) as u64,
            )
            .ok()
                != Some(policy)
        {
            return Err(Rejected::Unavailable);
        }
        if self.retired.load(Ordering::Acquire) {
            return Err(Rejected::Retired);
        }
        let Some(entry) = self.entry(request, policy)? else {
            super::metrics::state_open();
            return Ok(());
        };
        let (reservation, retained) = {
            let mut schedule = entry.schedule.lock();
            let now = self.now_us();
            let remaining = context
                .deadline
                .saturating_duration_since(Instant::now())
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            let deadline = now.checked_add(remaining).ok_or(Rejected::Clock)?;
            // 快路径不占用等待名额；只有确实需要延迟时才验证实体上界并预留实际资源。
            match schedule.reserve(policy, now, deadline, false) {
                Reservation::Rejected(Rejected::UnknownBody) => {
                    let bytes = context.retained_bound.ok_or(Rejected::UnknownBody)?;
                    let retained = Retained::acquire(bytes).ok_or(Rejected::Capacity)?;
                    (
                        schedule.reserve(policy, now, deadline, true),
                        Some(retained),
                    )
                }
                result => (result, None),
            }
        };
        let (ticket, due_us) = match reservation {
            Reservation::Admitted => return Ok(()),
            Reservation::Rejected(reason) => return Err(reason),
            Reservation::Waiting {
                ticket,
                due_us,
            } => (ticket, due_us),
        };
        let _waiting = Waiting {
            entry: entry.clone(),
            ticket,
            _retained: retained.expect("waiting requires a physical reservation"),
            _monitor: super::metrics::Wait::new(),
        };
        let mut wait_us = due_us.saturating_sub(self.now_us());
        loop {
            if self.retired.load(Ordering::Acquire) {
                return Err(Rejected::Retired);
            }
            let remaining = context.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Rejected::Deadline);
            }
            tokio::time::sleep(Duration::from_micros(wait_us.clamp(1, 50_000)).min(remaining))
                .await;
            // 唤醒之后重新验证真实期限与后端权威，迟到调度不能获得继续执行的资格。
            if Instant::now() >= context.deadline {
                return Err(Rejected::Deadline);
            }
            if self.retired.load(Ordering::Acquire) {
                return Err(Rejected::Retired);
            }
            match entry.schedule.lock().claim(policy, ticket, self.now_us()) {
                Claim::Admitted => return Ok(()),
                Claim::Rejected(reason) => return Err(reason),
                Claim::Wait(next) => wait_us = next,
            }
        }
    }

    /// 业务作用：取得同规则维度的唯一调度状态，所有新状态同时受规则、进程和归属容量约束。
    ///
    /// 参数说明：
    /// - `request`：当前可信规则与维度标识。
    /// - `policy`：必须与已有同身份状态一致的时序合同。
    ///
    /// 返回：共享状态；规则显式允许的维度软门可返回None，物理或归属不足始终拒绝。
    fn entry(
        self: &Arc<Self>,
        request: RateLimitRequest<'_>,
        policy: Policy,
    ) -> Result<Option<Arc<Entry>>, Rejected> {
        if let Some(budget) = request.state_budget {
            if !budget.register_reclaimer(self.clone()) {
                return Err(Rejected::StateCapacity);
            }
        }
        let mut entries = self.entries.lock();
        // 与退休清表使用同一目录锁，避免已失权后又插入无人拥有的新状态。
        if self.retired.load(Ordering::Acquire) {
            return Err(Rejected::Retired);
        }
        if let Some(entry) = entries.values.get(request.key) {
            if entry.policy != policy || entry.scope.as_ref() != request.scope {
                return Err(Rejected::Unavailable);
            }
            return Ok(Some(entry.clone()));
        }
        let now = self.now_us();
        let active = entries.scopes.get(request.scope).copied().unwrap_or(0);
        if now.saturating_sub(entries.last_sweep_us) >= 1_000_000
            || active >= request.max_active_keys
            || STATES.load(Ordering::Acquire) >= MAX_STATES
        {
            entries.sweep(now);
        }
        if STATES.load(Ordering::Acquire) >= MAX_STATES {
            return Err(Rejected::StateCapacity);
        }
        if entries.scopes.get(request.scope).copied().unwrap_or(0) >= request.max_active_keys {
            return if request.active_keys_fail_open {
                Ok(None)
            } else {
                Err(Rejected::StateCapacity)
            };
        }
        STATES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < MAX_STATES).then_some(used + 1)
            })
            .map_err(|_| Rejected::StateCapacity)?;
        let slot = StateSlot;
        let lease = request
            .state_budget
            .map(|budget| budget.acquire().map_err(|_| Rejected::StateCapacity))
            .transpose()?;
        let scope: Arc<str> = Arc::from(request.scope);
        let entry = Arc::new(Entry {
            scope: scope.clone(),
            policy,
            schedule: Mutex::new(Schedule::default()),
            _lease: lease,
            _slot: slot,
        });
        entries.values.insert(request.key.to_owned(), entry.clone());
        *entries.scopes.entry(scope).or_default() += 1;
        Ok(Some(entry))
    }

    /// 业务作用：撤销旧后端发放队列授权的资格，已等待请求在下次有界唤醒时退出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原子进入退休态，不回退调度债务或提前释放仍被请求持有的资源。
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        // 先失权再撤下目录；等待者仍持有独立Arc和原资源凭证，不能提前归还其物理占用。
        let mut entries = self.entries.lock();
        entries.values.clear();
        entries.scopes.clear();
    }

    /// 业务作用：使用单调时钟为本后端的所有调度动作提供统一时间原点。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：启动以来有界微秒数，不受系统墙钟调整影响。
    fn now_us(&self) -> u64 {
        self.origin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }
}

impl Drop for StateSlot {
    /// 业务作用：仅在状态最后一个持有者结束时归还全进程维度容量，退休代仍计入硬门。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：精确归还一个状态名额，不影响其它维度或调度债务。
    fn drop(&mut self) {
        STATES.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Entries {
    /// 业务作用：只回收无请求持有且无剩余调度债务的维度，保持计数和状态同时撤下。
    ///
    /// 参数说明：
    /// - `now_us`：后端单调时刻。
    ///
    /// 返回：已过期目录名额归还，不驱逐仍等待或仍有限速债务的状态。
    fn sweep(&mut self, now_us: u64) {
        self.values.retain(|_, entry| {
            let expired = Arc::strong_count(entry) == 1
                && entry
                    .schedule
                    .try_lock()
                    .is_some_and(|mut schedule| schedule.expired(now_us));
            if expired {
                if let Some(count) = self.scopes.get_mut(&entry.scope) {
                    *count -= 1;
                    if *count == 0 {
                        self.scopes.remove(&entry.scope);
                    }
                }
            }
            !expired
        });
        self.last_sweep_us = now_us;
    }
}

impl ReclaimExpired for Local {
    /// 业务作用：在工作区容量压力下释放已经失效的队列状态，不造成回收锁顺序反转。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尝试回收；目录正被使用时立即返回，不等待其它业务锁。
    fn reclaim_expired(&self) {
        if let Some(mut entries) = self.entries.try_lock() {
            entries.sweep(self.now_us());
        }
    }
}

impl Drop for Waiting {
    /// 业务作用：未来被取消或完成时撤销唯一等待令牌，归还实际保留容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本地精确名额立即释放，已经被其它请求引用的调度时刻保持。
    fn drop(&mut self) {
        self.entry.schedule.lock().cancel(self.ticket);
    }
}
