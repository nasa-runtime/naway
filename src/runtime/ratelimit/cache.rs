//! 本地批次权威、跨代围栏和有界回收；任何失效都先停止使用，再尝试归还。

use super::{ledger::Ledger, metrics, Policy};
use crate::control::ownership::state::Lease;
use crate::runtime::state::{RateLimitDecision, RateLimitFailMode, RateLimitRequest};
use futures::StreamExt;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::Instant;

struct Batch {
    ledger: Ledger,
    id: String,
    remaining: u64,
    deadline: Instant,
}

struct State {
    retired: bool,
    last_used: Instant,
    batch: Option<Batch>,
}

struct Entry {
    state: tokio::sync::Mutex<State>,
    _budget: Option<Lease>,
}

impl Drop for Entry {
    /// 业务作用：最后一个在途持有者退出后归还本地状态名额，不能只在目录删除时清零。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：降低进程保留维度计数，工作区租约随字段析构归还。
    fn drop(&mut self) {
        metrics::ENTRIES.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) struct Cache {
    policy: Policy,
    client: Arc<nasa::redis::RedisClient>,
    fail_mode: RateLimitFailMode,
    active: AtomicBool,
    generation: AtomicU64,
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
    waiters: tokio::sync::Semaphore,
    drained: AtomicBool,
    stopped: tokio::sync::Notify,
}

impl Cache {
    /// 业务作用：预留有界后端代际并启动单一回收器，候选失败时同样能退出。
    ///
    /// 参数说明：
    /// - `client`：已准备连接。
    /// - `policy`：已校验批领边界。
    /// - `fail_mode`：仅依赖不可用时的策略。
    ///
    /// 返回：最多四个并存后端之一；达到上限时拒绝候选而不扩张后台任务。
    pub fn new(
        client: Arc<nasa::redis::RedisClient>,
        policy: Policy,
        fail_mode: RateLimitFailMode,
    ) -> anyhow::Result<Arc<Self>> {
        metrics::BACKENDS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 4).then_some(n + 1)
            })
            .map_err(|_| anyhow::anyhow!("preallocation retained backend capacity exhausted"))?;
        let cache = Arc::new(Self {
            policy,
            client,
            fail_mode,
            active: AtomicBool::new(true),
            generation: AtomicU64::new(0),
            entries: Mutex::new(BTreeMap::new()),
            waiters: tokio::sync::Semaphore::new(128),
            drained: AtomicBool::new(false),
            stopped: tokio::sync::Notify::new(),
        });
        tokio::spawn(Self::reap(cache.clone()));
        Ok(cache)
    }

    /// 业务作用：后端退休时同步关闭领取和本地消费，回收器再处理已知未用余额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：立即撤销准入权威；正在执行的 Redis 命令不能重新开放此后端。
    pub fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// 业务作用：停止新消费并在有限停机预算内等待已知余额归还，超时后仍不恢复权威。
    ///
    /// 参数说明：
    /// - `timeout`：停机可用于批领账本清理的最大时间。
    ///
    /// 返回：回收完成或预算耗尽后结束；未确认批次继续靠期限和桶补充收敛。
    pub async fn shutdown(&self, timeout: Duration) {
        self.retire();
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if !self.drained.load(Ordering::Acquire) {
            let _ = tokio::time::timeout(timeout, stopped).await;
        }
    }

    /// 业务作用：在目录与工作区预算内取得唯一维度状态，满表不以依赖降级放行。
    ///
    /// 参数说明：
    /// - `ledger`：共享桶身份。
    /// - `request`：可信归属预算。
    ///
    /// 返回：既有或新建条目；任一硬容量不足时拒绝，不留下无预算条目。
    fn entry(&self, ledger: &Ledger, request: RateLimitRequest<'_>) -> Option<Arc<Entry>> {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get(&ledger.key) {
            return Some(entry.clone());
        }
        if entries.len() >= self.policy.max_local_keys {
            return None;
        }
        let budget = match request.state_budget {
            Some(budget) => Some(budget.acquire().ok()?),
            None => None,
        };
        metrics::ENTRIES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 65_536).then_some(n + 1)
            })
            .ok()?;
        let entry = Arc::new(Entry {
            state: tokio::sync::Mutex::new(State {
                retired: false,
                last_used: Instant::now(),
                batch: None,
            }),
            _budget: budget,
        });
        entries.insert(ledger.key.clone(), entry.clone());
        Some(entry)
    }

    /// 业务作用：用仍有效的预扣权威进行本地准入，缺额时单维度串行领取且复验版本与期限。
    ///
    /// 参数说明：
    /// - `request`：冻结路由规则和工作区预算，成本必须为一个请求。
    /// - `generation`：冻结配置版本。
    ///
    /// 返回：有效额度扣减一次；明确容量、策略、过期与旧代拒绝闭合，只有 Redis 错误可按配置放行。
    pub async fn allow(&self, request: RateLimitRequest<'_>, generation: u64) -> RateLimitDecision {
        self.generation.fetch_max(generation, Ordering::AcqRel);
        // 已观察到更新配置或已退休的后端不能重新给旧请求发放可复用信用。
        if !self.current(generation) || request.key.len() > 4096 || request.scope.len() > 4096 {
            return denied();
        }
        // Lua 数值和到期时间必须处于精确可表示的有限区间，不能让异常规则变成无限凭据。
        if Policy::validate_rule(request.limit, request.window, request.burst).is_err() {
            return denied();
        }
        let Ok(_waiter) = self.waiters.try_acquire() else {
            return denied();
        };
        let ledger = Ledger::new(self.client.clone(), request, self.policy);
        let Some(entry) = self.entry(&ledger, request) else {
            return denied();
        };
        let duration = Duration::from_millis(self.policy.lease_ms);
        let Ok(mut state) = tokio::time::timeout(duration, entry.state.lock()).await else {
            return denied();
        };
        if state.retired || !self.current(generation) {
            return denied();
        }
        state.last_used = Instant::now();
        if let Some(batch) = state.batch.as_mut() {
            if batch.ledger.fingerprint == ledger.fingerprint
                && batch.deadline > Instant::now()
                && batch.remaining > 0
            {
                batch.remaining -= 1;
                metrics::HITS.fetch_add(1, Ordering::Relaxed);
                return RateLimitDecision {
                    allowed: true,
                    remaining: batch.remaining,
                };
            }
        }
        // 先取走本地凭据再归还，取消或网络不确定性只能损失额度，不能重复使用。
        if let Some(batch) = state.batch.take() {
            batch.ledger.give_back(&batch.id, batch.remaining).await;
        }
        if !self.current(generation) {
            return denied();
        }
        let deadline = Instant::now() + duration;
        let mut nonce = [0_u8; 16];
        if getrandom::getrandom(&mut nonce).is_err() {
            return denied();
        }
        let id = format!("{:032x}", u128::from_be_bytes(nonce));
        let result = ledger.grant(&id).await;
        // 领取发起时刻计算本地期限，把往返、排队和进程暂停都算入权威消耗。
        if !self.current(generation) || (result.is_ok() && Instant::now() >= deadline) {
            if let Ok((1, granted)) = result {
                ledger.give_back(&id, granted).await;
            }
            return denied();
        }
        match result {
            Ok((1, granted)) if granted > 0 && granted <= self.policy.batch_size => {
                state.batch = Some(Batch {
                    ledger,
                    id,
                    remaining: granted - 1,
                    deadline,
                });
                RateLimitDecision {
                    allowed: true,
                    remaining: granted - 1,
                }
            }
            Ok((2, _)) => RateLimitDecision {
                allowed: true,
                remaining: u64::MAX,
            },
            Ok(_) => denied(),
            Err(_) => {
                metrics::ERRORS.fetch_add(1, Ordering::Relaxed);
                if self.fail_mode == RateLimitFailMode::Open {
                    RateLimitDecision {
                        allowed: true,
                        remaining: u64::MAX,
                    }
                } else {
                    denied()
                }
            }
        }
    }

    /// 业务作用：复验后端与请求配置权威，阻止等待中的旧代结果污染新状态。
    ///
    /// 参数说明：
    /// - `generation`：本次请求冻结版本。
    ///
    /// 返回：后端仍开放且未观察到更新请求时为真。
    fn current(&self, generation: u64) -> bool {
        self.active.load(Ordering::Acquire) && self.generation.load(Ordering::Acquire) == generation
    }

    /// 业务作用：以固定批次扫描失活维度，先撤销凭据，再用有限并发归还余额。
    ///
    /// 参数说明：
    /// - `cache`：后台唯一持有者，退休且排空后释放后端代际。
    ///
    /// 返回：最多每轮64条、8个归还任务；进程异常终止由 Redis 期限和桶补充恢复，不依赖此任务必达。
    async fn reap(cache: Arc<Self>) {
        let mut cursor = String::new();
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut returns = Vec::new();
            {
                let mut entries = cache.entries.lock();
                let keys = entries
                    .range((
                        std::ops::Bound::Excluded(cursor.clone()),
                        std::ops::Bound::Unbounded,
                    ))
                    .take(64)
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                cursor = keys.last().cloned().unwrap_or_default();
                for key in keys {
                    let Some(entry) = entries.get(&key).cloned() else {
                        continue;
                    };
                    let Ok(mut state) = entry.state.try_lock() else {
                        continue;
                    };
                    let expired = state
                        .batch
                        .as_ref()
                        .is_some_and(|batch| batch.deadline <= Instant::now());
                    if !cache.active.load(Ordering::Acquire)
                        || expired
                        || state.last_used.elapsed()
                            >= Duration::from_millis(cache.policy.lease_ms / 2)
                    {
                        // 目录撤下之前标记退休，使已经排队持有 Arc 的请求也不能重新激活此条目。
                        state.retired = true;
                        if expired {
                            metrics::EXPIRED.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Some(batch) = state.batch.take() {
                            returns.push(batch);
                        }
                        entries.remove(&key);
                    }
                }
                if entries.is_empty() && !cache.active.load(Ordering::Acquire) && returns.is_empty()
                {
                    cache.drained.store(true, Ordering::Release);
                    cache.stopped.notify_waiters();
                    break;
                }
            }
            futures::stream::iter(returns)
                .for_each_concurrent(8, |batch| async move {
                    batch.ledger.give_back(&batch.id, batch.remaining).await;
                })
                .await;
        }
    }
}

impl Drop for Cache {
    /// 业务作用：所有回收与在途引用结束后释放后端代际名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：减少进程保留后端数，不影响远端仍有期限的未知批次。
    fn drop(&mut self) {
        metrics::BACKENDS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 业务作用：统一明确拒绝的响应与指标，不把资源耗尽归类为可放行的依赖错误。
///
/// 参数说明: 无。
///
/// 返回：拒绝且剩余额度为零。
fn denied() -> RateLimitDecision {
    metrics::DENIED.fetch_add(1, Ordering::Relaxed);
    RateLimitDecision {
        allowed: false,
        remaining: 0,
    }
}
