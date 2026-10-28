//! 服务级窗口摘除、比例门禁和独占恢复探测。

use super::metrics;
use super::policy::{Policy, Window};
use crate::upstream::UpstreamInstance;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_GROUPS: usize = 1024;
const MAX_ENTRIES: usize = 65_536;
const MAX_SERVICE_ENTRIES: usize = 4096;

/// 容量随真实状态句柄释放，撤路但仍有在途尝试时不能提前重用名额。
#[derive(Default)]
pub(super) struct Budget {
    groups: AtomicUsize,
    entries: AtomicUsize,
}

/// 一个逻辑服务的单一健康状态；成员只从上游目录导入，不独立执行服务发现。
pub struct Group {
    state: Mutex<State>,
    budget: Arc<Budget>,
    charged: AtomicUsize,
    sequence: AtomicU64,
}

struct State {
    version: u64,
    policy: Policy,
    source: Arc<[Arc<UpstreamInstance>]>,
    entries: HashMap<Arc<str>, Entry>,
    ejected: usize,
    probing: usize,
}

#[derive(Default)]
struct Entry {
    window: Window,
    generation: u64,
    until: Option<Instant>,
    failures: u32,
    probe: Option<u64>,
}

/// 一次真实尝试的健康写入权；恢复探测令牌直到 I/O 退出才释放。
pub struct Attempt {
    group: Arc<Group>,
    key: Arc<str>,
    generation: u64,
    probe: Option<u64>,
    deadline: Option<Instant>,
    done: bool,
}

/// 字段按声明顺序销毁：取消时先停止真实 I/O，再释放恢复探测权。
struct Observation<F> {
    operation: Option<std::pin::Pin<Box<F>>>,
    attempt: Option<Attempt>,
}

/// 业务作用：原子预留全局健康状态名额，避免多个服务同时扩容越过共享上限。
///
/// 参数说明：
/// - `counter`：当前已保留数量。
/// - `amount`：本次新增长期驻留的数量。
/// - `maximum`：进程硬上限。
///
/// 返回：容量足够则增加计数；失败不改变计数。
fn charge(counter: &AtomicUsize, amount: usize, maximum: usize) -> bool {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(amount).filter(|next| *next <= maximum)
        })
        .is_ok()
}

impl Group {
    /// 业务作用：为已发布服务创建有容量凭据的窗口状态，未完成构建的候选不得调用。
    ///
    /// 参数说明：
    /// - `version`：已发布快照的单调版本。
    /// - `policy`：构建期验证过的窗口策略。
    /// - `source`：与负载选择相同的权威实例切片。
    /// - `budget`：进程所有服务共享的状态容量。
    ///
    /// 返回：容量足够时创建空窗口；成员超限或进程容量不足时失败关闭。
    pub(super) fn new(
        version: u64,
        policy: Policy,
        source: Arc<[Arc<UpstreamInstance>]>,
        budget: Arc<Budget>,
    ) -> Option<Arc<Self>> {
        if source.len() > MAX_SERVICE_ENTRIES || !charge(&budget.groups, 1, MAX_GROUPS) {
            metrics::DENIED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        metrics::GROUPS.fetch_add(1, Ordering::Relaxed);
        let group = Arc::new(Self {
            state: Mutex::new(State {
                version,
                policy,
                source: Arc::from([]),
                entries: HashMap::new(),
                ejected: 0,
                probing: 0,
            }),
            budget,
            charged: AtomicUsize::new(0),
            sequence: AtomicU64::new(0),
        });
        group.refresh(version, policy, source).then_some(group)
    }

    /// 业务作用：在新目录或策略发布后对账成员，保留未变化实例的冷却事实并撤销旧代写入权。
    ///
    /// 参数说明：
    /// - `version`：当前发布版本，旧请求不能倒退它。
    /// - `policy`：同版本的已验证策略。
    /// - `source`：目录当前权威实例集合。
    ///
    /// 返回：成功时更新成员；旧版本或容量不足不改变现有状态，调用方拒绝本次选择。
    pub(super) fn refresh(
        &self,
        version: u64,
        policy: Policy,
        source: Arc<[Arc<UpstreamInstance>]>,
    ) -> bool {
        let mut state = self.state.lock();
        if version < state.version || source.len() > MAX_SERVICE_ENTRIES {
            return false;
        }
        if policy == state.policy && Arc::ptr_eq(&source, &state.source) {
            state.version = version;
            return true;
        }
        let identities: HashSet<Arc<str>> = source
            .iter()
            .filter(|instance| instance.healthy && !instance.down && instance.weight > 0)
            .map(|instance| instance.health_key.clone())
            .collect();
        let previous = state.entries.len();
        let additional = identities.len().saturating_sub(previous);
        if !charge(&self.budget.entries, additional, MAX_ENTRIES) {
            metrics::DENIED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        metrics::ENTRIES.fetch_add(additional as u64, Ordering::Relaxed);
        let changed_policy = policy != state.policy;
        state.entries.retain(|key, _| identities.contains(key));
        for key in identities {
            state.entries.entry(key).or_insert_with(|| Entry {
                generation: self.next_generation(),
                ..Entry::default()
            });
        }
        let removed = previous.saturating_sub(state.entries.len());
        self.budget.entries.fetch_sub(removed, Ordering::AcqRel);
        metrics::ENTRIES.fetch_sub(removed as u64, Ordering::Relaxed);
        self.charged.store(state.entries.len(), Ordering::Release);
        if changed_policy {
            // 旧阈值的在途结果不能改变新策略；冷却事实仍保留，热更不能成为免费恢复通道。
            for entry in state.entries.values_mut() {
                entry.generation = self.next_generation();
                entry.window = Window::default();
            }
        }
        state.version = version;
        state.policy = policy;
        state.source = source;
        // 目录缩小或比例降低时重新满足硬上限；确定性保留已有冷却，其余实例回到采样态。
        let mut ejected: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, entry)| entry.until.is_some())
            .map(|(key, _)| key.clone())
            .collect();
        ejected.sort();
        for key in ejected
            .into_iter()
            .skip(policy.capacity(state.entries.len()))
        {
            let entry = state
                .entries
                .get_mut(&key)
                .expect("current ejection identity");
            entry.until = None;
            entry.window = Window::default();
            entry.generation = self.next_generation();
            entry.failures = 0;
        }
        state.ejected = state
            .entries
            .values()
            .filter(|entry| entry.until.is_some())
            .count();
        state.probing = state
            .entries
            .values()
            .filter(|entry| entry.probe.is_some())
            .count();
        true
    }

    /// 业务作用：提供本轮负载选择需要排除的冷却或正在探测实例。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已到恢复时间且没有在途探测的实例不排除，但真正发送前仍必须获取独占令牌。
    pub fn blocked(&self) -> Vec<Arc<str>> {
        let state = self.state.lock();
        if state.ejected == 0 && state.probing == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        state
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.probe.is_some() || entry.until.is_some_and(|until| until > now)
            })
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// 业务作用：为选中实例固定本次结果的写入权；冷却期后只允许一个真实恢复探测。
    ///
    /// 参数说明：
    /// - `key`：负载选择从同一目录选出的实例身份。
    ///
    /// 返回：可执行时返回 RAII 尝试凭据；实例已撤销、冷却或探测占用时拒绝。
    pub fn acquire(self: &Arc<Self>, key: &Arc<str>) -> Option<Attempt> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let entry = state.entries.get(key)?;
        if entry.probe.is_some() || entry.until.is_some_and(|until| until > now) {
            return None;
        }
        if entry.generation == u64::MAX {
            return None;
        }
        let probe = if entry.until.is_some() {
            let generation = self.next_generation();
            if generation == u64::MAX {
                return None;
            }
            Some(generation)
        } else {
            None
        };
        let deadline = probe.map(|_| now + Duration::from_millis(state.policy.probe_timeout_ms));
        if probe.is_some() {
            state.probing += 1;
        }
        let entry = state.entries.get_mut(key)?;
        if let Some(generation) = probe {
            // 探测取得新一代写入权；摘除前已发出的普通请求不能用迟到成功解除保护。
            entry.generation = generation;
            entry.probe = probe;
            metrics::PROBE.fetch_add(1, Ordering::Relaxed);
        }
        Some(Attempt {
            group: self.clone(),
            key: key.clone(),
            generation: entry.generation,
            probe,
            deadline,
            done: false,
        })
    }

    /// 业务作用：在服务锁内提交健康观察，保证并发失败不能各自越过同一个摘除比例名额。
    ///
    /// 参数说明：
    /// - `attempt`：冻结实例代数与可选探测令牌的真实尝试。
    /// - `result`：真实结果及耗时；None 表示取消或本地拒绝，不能证明后端失效或恢复。
    ///
    /// 返回：仅当前代数可影响窗口；有效探测归还独占令牌并恢复或继续带上限退避。
    fn finish(&self, attempt: &Attempt, result: Option<(bool, u64)>) {
        let now = Instant::now();
        let mut state = self.state.lock();
        let policy = state.policy;
        let ejected = state.ejected;
        let capacity = policy.capacity(state.entries.len());
        if attempt.probe.is_some()
            && state
                .entries
                .get(&attempt.key)
                .is_some_and(|entry| entry.probe == attempt.probe)
        {
            state.probing = state.probing.saturating_sub(1);
        }
        let Some(entry) = state.entries.get_mut(&attempt.key) else {
            return;
        };
        if attempt.probe.is_some() && entry.probe == attempt.probe {
            entry.probe = None;
        }
        // 配置、成员或保护态已推进时，迟到结果不再拥有健康发布权。
        if entry.generation != attempt.generation {
            metrics::STALE.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if attempt.probe.is_some() {
            let recovered = result.is_some_and(|(failed, elapsed)| {
                !failed && (policy.slow_percent == 0 || elapsed < policy.slow_ms)
            }) && attempt.deadline.is_some_and(|deadline| now < deadline);
            if recovered {
                metrics::RECOVERED.fetch_add(1, Ordering::Relaxed);
                entry.until = None;
                entry.failures = 0;
                entry.window = Window::default();
            } else {
                // 取消不是成功证据；真实失败才增加退避阶数，取消仍保留冷却以免忙循环。
                if result.is_some() {
                    entry.failures = entry.failures.saturating_add(1);
                    metrics::FAILED.fetch_add(1, Ordering::Relaxed);
                } else {
                    metrics::CANCELLED.fetch_add(1, Ordering::Relaxed);
                }
                entry.until = Some(now + Duration::from_millis(backoff(policy, entry.failures)));
            }
            entry.generation = self.next_generation();
            if recovered {
                state.ejected = state.ejected.saturating_sub(1);
            }
            return;
        }
        let Some((failed, elapsed)) = result else {
            return;
        };
        if entry.until.is_some() {
            return;
        }
        if entry.window.observe(
            policy,
            crate::upstream::load::monotonic_ms(),
            failed,
            elapsed,
        ) {
            if ejected >= capacity {
                metrics::CAPPED.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // 窗口达标和比例门同时成立才发布摘除；单实例和已达比例的服务仍保留可调度路径。
            entry.failures = 1;
            entry.until = Some(now + Duration::from_millis(policy.base_ejection_ms));
            entry.generation = self.next_generation();
            metrics::EJECTED.fetch_add(1, Ordering::Relaxed);
            state.ejected += 1;
        }
    }

    /// 业务作用：为管理面提供当前组的配置与保护态数量，不复制实例身份目录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前策略、实例数、摘除数和探测数；冷却到期但尚未探测成功仍计入摘除。
    pub(super) fn status(&self) -> serde_json::Value {
        let state = self.state.lock();
        serde_json::json!({
            "policy": state.policy,
            "instances": state.entries.len(),
            "ejected": state.ejected,
            "probing": state.probing,
        })
    }

    /// 业务作用：为成员重建与保护态迁移分配不复用的写入代数，避免同名实例复用旧请求权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：单调递增代数；耗尽时返回保留拒绝值，后续准入失败关闭而不回绕。
    fn next_generation(&self) -> u64 {
        self.sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1).filter(|next| *next != u64::MAX)
            })
            .map(|previous| previous + 1)
            .unwrap_or(u64::MAX)
    }
}

/// 业务作用：计算连续恢复失败后的有界指数冷却，避免故障实例被同步高频探测。
///
/// 参数说明：
/// - `policy`：基础时长与硬上限。
/// - `failures`：包含首次摘除的连续失败阶数。
///
/// 返回：不超过配置上限的毫秒数，乘法不会溢出。
fn backoff(policy: Policy, failures: u32) -> u64 {
    policy
        .base_ejection_ms
        .saturating_mul(1_u64 << failures.saturating_sub(1).min(31))
        .min(policy.max_ejection_ms)
}

impl Drop for Group {
    /// 业务作用：最后一个目录或尝试句柄释放后归还状态容量，旧请求不能与新状态重复使用名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只归还该服务仍拥有的条目和服务名额。
    fn drop(&mut self) {
        metrics::ENTRIES.fetch_sub(
            self.charged.load(Ordering::Acquire) as u64,
            Ordering::Relaxed,
        );
        metrics::GROUPS.fetch_sub(1, Ordering::Relaxed);
        self.budget
            .entries
            .fetch_sub(self.charged.load(Ordering::Acquire), Ordering::AcqRel);
        self.budget.groups.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Attempt {
    /// 业务作用：把健康写入权与真实 I/O 生命周期绑定，并用绝对期限约束独占恢复探测。
    ///
    /// 参数说明：
    /// - `attempt`：未启用窗口时为空；存在时持有实例代数和可选探测权。
    /// - `future`：真实上游操作，不包含客户端输入解析或响应正文发送。
    /// - `judge`：从操作结果提取失败证据；None 表示本地拒绝，不能计入后端统计。
    ///
    /// 返回：普通完成保留原结果；探测期限到达时取消该 I/O 并返回 Err，调用方按协议报告超时。
    pub fn observe<F, T>(
        attempt: Option<Self>,
        future: F,
        judge: impl FnOnce(&T) -> Option<bool>,
    ) -> impl std::future::Future<Output = Result<T, ()>>
    where
        F: std::future::Future<Output = T>,
    {
        Self::observe_classified(attempt, future, judge, || true)
    }

    /// 业务作用：在取消真实 I/O 后区分后端探测超时与本地整形耗时，保持失效权威不能恢复路由。
    ///
    /// 参数说明：
    /// - `attempt`：冻结的窗口观察或独占探测凭据。
    /// - `future`：受探测期限约束的实际外呼。
    /// - `judge`：只根据真实完成结果给出后端成功、失败或不可归因。
    /// - `timeout_is_upstream`：探测超时时从受信运行态判断是否具有后端失败证据。
    ///
    /// 返回：完成值或期限错误；证据不足只释放探测权，不发布恢复或追加后端失败。
    pub(crate) fn observe_classified<F, T>(
        attempt: Option<Self>,
        future: F,
        judge: impl FnOnce(&T) -> Option<bool>,
        timeout_is_upstream: impl FnOnce() -> bool,
    ) -> impl std::future::Future<Output = Result<T, ()>>
    where
        F: std::future::Future<Output = T>,
    {
        // 协议 future 可包含多层转发分支；在进入观察状态机前固定到堆上，避免各层超时放大线程栈。
        let observation = Observation {
            operation: Some(Box::pin(future)),
            attempt,
        };
        async move {
            // 整体移入，保留 operation → attempt 的析构顺序，不能拆成独立捕获。
            let mut observation = observation;
            if observation.attempt.is_none() {
                return Ok(observation
                    .operation
                    .as_mut()
                    .expect("pending operation")
                    .await);
            }
            let started = Instant::now();
            let deadline = observation.attempt.as_ref().and_then(Attempt::deadline);
            let output = if let Some(deadline) = deadline {
                // 排队可能已耗尽探测期限；尚未发起的 I/O 不得在过期权威下产生外部请求。
                if deadline <= started {
                    return Err(());
                }
                let completed = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    observation.operation.as_mut().expect("pending operation"),
                )
                .await;
                // 先销毁 I/O，再发布健康结果；超时与正常完成都不能提前归还仍被实际操作持有的探测权。
                drop(observation.operation.take());
                match completed {
                    Ok(output) => output,
                    Err(_) => {
                        let attempt = observation.attempt.take().expect("observation authority");
                        // 先取消 I/O，再判断归因；本地等待不足以证明后端失败，也不能授予恢复。
                        if timeout_is_upstream() {
                            attempt.complete(true, started.elapsed());
                        }
                        return Err(());
                    }
                }
            } else {
                let output = observation
                    .operation
                    .as_mut()
                    .expect("pending operation")
                    .await;
                drop(observation.operation.take());
                output
            };
            if let Some(failed) = judge(&output) {
                observation
                    .attempt
                    .take()
                    .expect("observation authority")
                    .complete(failed, started.elapsed());
            }
            Ok(output)
        }
    }

    /// 业务作用：把恢复探测的绝对期限传给真实 I/O，不能仅令牌超时而让旧探测继续占用连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：普通采样无额外期限；恢复探测返回取得权威时冻结的绝对截止时间。
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// 业务作用：结束一次真实尝试并提交其健康观察，正文传输和下游慢读不计入上游延迟。
    ///
    /// 参数说明：
    /// - `failed`：真实上游响应或传输是否失败。
    /// - `elapsed`：本次尝试至响应头或连接结果的耗时。
    ///
    /// 返回：至多提交一次；旧代观察自动失效，并归还任何探测权。
    pub fn complete(mut self, failed: bool, elapsed: Duration) {
        self.group.finish(
            &self,
            Some((failed, elapsed.as_millis().min(u128::from(u64::MAX)) as u64)),
        );
        self.done = true;
    }
}

impl Drop for Attempt {
    /// 业务作用：取消、超限或本地拒绝时撤销尝试权，不把未完成请求当作健康恢复。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：探测名额随真实 I/O 作用域归还；普通取消不新增窗口样本。
    fn drop(&mut self) {
        if !self.done {
            self.group.finish(self, None);
        }
    }
}
