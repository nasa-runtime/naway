//! 一个进程只保留一个通知执行者，旧配置不能借排队操作继续向新出口发送。

use super::{Event, Plan};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

const QUEUE_CAPACITY: usize = 128;

pub struct Runtime {
    current: watch::Sender<Arc<Plan>>,
    sender: mpsc::Sender<Job>,
    receiver: Mutex<Option<mpsc::Receiver<Job>>>,
    stats: Arc<Stats>,
}

struct Job {
    plan: Arc<Plan>,
    event: Event,
    body: Vec<u8>,
    deadline: Instant,
}

#[derive(Default)]
struct Stats {
    submitted: AtomicU64,
    delivered: AtomicU64,
    failed: AtomicU64,
    revoked: AtomicU64,
    expired: AtomicU64,
    full: AtomicU64,
    worker_failed: AtomicBool,
}

impl Default for Runtime {
    /// 业务作用：建立有界通知槽但不启动任务，未配置外发时不持有网络资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认store-watch及128个操作槽；所有配置代共享同一接收器。
    fn default() -> Self {
        let (current, _) = watch::channel(Plan::store_watch());
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        Self {
            current,
            sender,
            receiver: Mutex::new(Some(receiver)),
            stats: Arc::new(Stats::default()),
        }
    }
}

impl Runtime {
    /// 业务作用：在原事实写入之前冻结外发目的地，后续换代不得把这个操作转交另一出口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前不可变计划；此读取不分配动作槽、不启动网络工作。
    pub fn plan(&self) -> Arc<Plan> {
        self.current.borrow().clone()
    }

    /// 业务作用：与快照提交一起撤销旧计划，第一次显式启用外发时才启动唯一worker。
    ///
    /// 参数说明：
    /// - `next`：已经完成候选验证的计划。
    ///
    /// 返回：新计划立即成为排队资格来源；旧重试取消，原队列不会换用新出口。
    pub fn apply(&self, next: Arc<Plan>) {
        let previous = self.plan();
        if Arc::ptr_eq(&previous, &next) {
            return;
        }
        // 先撤销旧资格再发布目的地；已经外发的字节只能由接收业务按原事件身份去重。
        previous.revoke();
        next.revoked.store(false, Ordering::Release);
        self.current.send_replace(next.clone());
        if next.external() {
            if let Some(receiver) = self.receiver.lock().take() {
                tokio::spawn(run(receiver, self.current.subscribe(), self.stats.clone()));
            }
        }
    }

    /// 业务作用：由确认写入事实的动作节点尝试投递，普通watch读者不得通过此入口转发事件。
    ///
    /// 参数说明：
    /// - `event`：已确认操作的原事件。
    /// - `plan`：写入之前冻结的原目的地计划。
    ///
    /// 返回：非阻塞受理；禁用、撤销、编码、容量或worker失败只增加固定观测，不撤销封禁或自动重放动作。
    pub fn publish(&self, event: &Event, plan: Arc<Plan>) {
        if !plan.external() {
            return;
        }
        if plan.revoked.load(Ordering::Acquire) || !Arc::ptr_eq(&plan, &self.plan()) {
            self.stats.revoked.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(body) = event.encode() else {
            self.stats.failed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let now = super::receiver::now_ms().ok();
        let timestamp = event.timestamp_unix_ms.parse::<u64>().ok();
        let remaining = now.zip(timestamp).and_then(|(now, timestamp)| {
            if timestamp > now.saturating_add(5000) {
                return None;
            }
            plan.max_age
                .checked_sub(Duration::from_millis(now.saturating_sub(timestamp)))
        });
        let Some(remaining) = remaining.filter(|value| !value.is_zero()) else {
            self.stats.expired.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let job = Job {
            deadline: Instant::now() + remaining,
            plan,
            event: event.clone(),
            body,
        };
        match self.sender.try_send(job) {
            Ok(()) => {
                self.stats.submitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.full.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 业务作用：提供当前通知预算与固定累计结局，不披露目标地址、消息正文或凭据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本进程低基数快照；delivered只表示出口确认，失败和未知不能推断业务未收到。
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "transport": self.plan().kind(),
            "queue_capacity": QUEUE_CAPACITY,
            "queued": self.sender.max_capacity() - self.sender.capacity(),
            "submitted": self.stats.submitted.load(Ordering::Relaxed).to_string(),
            "delivered": self.stats.delivered.load(Ordering::Relaxed).to_string(),
            "failed": self.stats.failed.load(Ordering::Relaxed).to_string(),
            "revoked": self.stats.revoked.load(Ordering::Relaxed).to_string(),
            "expired": self.stats.expired.load(Ordering::Relaxed).to_string(),
            "full": self.stats.full.load(Ordering::Relaxed).to_string(),
            "worker_failed": self.stats.worker_failed.load(Ordering::Acquire),
            "queue_closed": self.sender.is_closed(),
        })
    }
}

/// 业务作用：在单一任务内串行投递与有界重试，配置撤销优先于任何下一次网络尝试。
///
/// 参数说明：
/// - `receiver`：进程唯一128槽操作队列。
/// - `plans`：只保留当前计划的换代信号。
/// - `stats`：固定结局观测，不持有调用方或业务请求。
///
/// 返回：持有者退出或旧出口停止失败时结束；停止失败后不创建新客户端积累资源。
async fn run(
    mut receiver: mpsc::Receiver<Job>,
    mut plans: watch::Receiver<Arc<Plan>>,
    stats: Arc<Stats>,
) {
    let mut active = plans.borrow_and_update().clone();
    let mut backend: Option<Box<dyn super::AclNotifier>> = None;
    loop {
        let job = tokio::select! {
            biased;
            changed = plans.changed() => {
                if let Some(mut old) = backend.take() {
                    if !matches!(tokio::time::timeout(Duration::from_secs(2), old.shutdown()).await, Ok(Ok(()))) {
                        // 停止证据不足时关闭整个外发执行者，不能不断创建新的生产者扩大未知资源。
                        stats.worker_failed.store(true, Ordering::Release);
                        return;
                    }
                }
                if changed.is_err() {
                    return;
                }
                active = plans.borrow_and_update().clone();
                continue;
            }
            job = receiver.recv() => job,
        };
        let Some(job) = job else {
            if let Some(mut old) = backend.take() {
                let _ = tokio::time::timeout(Duration::from_secs(2), old.shutdown()).await;
            }
            return;
        };
        if job.plan.revoked.load(Ordering::Acquire) || !Arc::ptr_eq(&active, &job.plan) {
            stats.revoked.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let work = deliver(&job, &mut backend);
        let outcome = tokio::select! {
            biased;
            _ = plans.changed() => "revoked",
            outcome = work => outcome,
        };
        match outcome {
            "delivered" => {
                stats.delivered.fetch_add(1, Ordering::Relaxed);
            }
            "revoked" => {
                stats.revoked.fetch_add(1, Ordering::Relaxed);
                // changed已消费信号，显式复验计划并停止旧适配器，不能等下一次变化才释放旧owner。
                if let Some(mut old) = backend.take() {
                    if !matches!(
                        tokio::time::timeout(Duration::from_secs(2), old.shutdown()).await,
                        Ok(Ok(()))
                    ) {
                        stats.worker_failed.store(true, Ordering::Release);
                        return;
                    }
                }
                active = plans.borrow_and_update().clone();
                if plans.has_changed().is_err() {
                    return;
                }
            }
            "expired" => {
                stats.expired.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// 业务作用：重试同一事件原文，使用排队也计入的绝对期限，未知网络结果不得重建整个封禁动作。
///
/// 参数说明：
/// - `job`：固定目的地、事件和总截止时刻。
/// - `backend`：唯一执行者保留的当前适配器。
///
/// 返回：固定投递结局；最多八次尝试，单次与总年龄均不超过已验证预算。
async fn deliver(job: &Job, backend: &mut Option<Box<dyn super::AclNotifier>>) -> &'static str {
    for attempt in 0..job.plan.attempts {
        if job.plan.revoked.load(Ordering::Acquire) {
            return "revoked";
        }
        let remaining = job.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return "expired";
        }
        if backend.is_none() {
            match super::transport::build(job.plan.clone()) {
                Ok(created) => {
                    *backend = Some(created);
                }
                Err(_) => return "failed",
            }
        }
        let sender = backend.as_mut().expect("initialized ACL notifier");
        if matches!(
            tokio::time::timeout(
                remaining.min(job.plan.timeout),
                sender.send(&job.event, &job.body)
            )
            .await,
            Ok(Ok(()))
        ) {
            return "delivered";
        }
        if attempt + 1 < job.plan.attempts {
            let delay = job
                .plan
                .retry_delay
                .saturating_mul(1_u32 << attempt)
                .min(Duration::from_secs(5));
            tokio::time::sleep(delay.min(job.deadline.saturating_duration_since(Instant::now())))
                .await;
        }
    }
    if Instant::now() >= job.deadline {
        "expired"
    } else {
        "failed"
    }
}
