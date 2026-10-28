use super::super::config::LimitsCfg;
use anyhow::{ensure, Context, Result};
use nabudget::RequestBudget;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Catalog {
    entries: Mutex<HashMap<String, Entry>>,
    limits: LimitsCfg,
}

struct Entry {
    _workspace_lease: Option<crate::control::ownership::state::Lease>,
    owner: [u8; 32],
    task: Option<String>,
    context: Option<String>,
    state: String,
    expires: Instant,
    calls: u64,
    bytes: u64,
    epoch: u64,
    active: Option<RequestBudget>,
}

pub(super) struct Lease {
    catalog: Arc<Catalog>,
    key: String,
    epoch: u64,
    pub budget: RequestBudget,
}

/// 同一次已认证任务动作的预留证据，身份、引用、实体大小与期限不能来自不同请求。
pub(super) struct Reservation<'a> {
    pub owner: [u8; 32],
    pub task: Option<&'a str>,
    pub context: Option<&'a str>,
    pub method: &'a str,
    pub bytes: usize,
    pub deadline: Instant,
    pub state_budget: Option<&'a crate::control::ownership::state::Budget>,
}

impl Catalog {
    /// 业务作用：建立只属于当前配置快照的有界任务与上下文索引，不保留消息或产物正文。
    ///
    /// 参数说明：
    /// - `limits`：是任务保留、主体配额和调用预算。
    ///
    /// 返回：空索引；配置换代时不继承旧权限或旧任务。
    pub(super) fn new(limits: LimitsCfg) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            limits,
        })
    }

    /// 业务作用：在外呼前原子确认任务 owner、上下文和终态，并预留本次动作资源。
    ///
    /// 参数说明：
    /// - `reservation`：同一动作的认证摘要、已校验引用、方法、输入大小、截止点和受信工作区容量。
    ///
    /// 返回：独占动作租约；跨主体、过期、并发冲突、非法终态和资源耗尽均拒绝。
    pub(super) fn reserve(self: &Arc<Self>, reservation: Reservation<'_>) -> Result<Lease> {
        let Reservation {
            owner,
            task,
            context,
            method,
            bytes,
            deadline,
            state_budget,
        } = reservation;
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| {
            if entry.expires <= Instant::now() {
                if let Some(active) = &entry.active {
                    active.cancel();
                }
                return false;
            }
            true
        });
        if let Some(context) = context {
            ensure!(
                entries
                    .values()
                    .any(|entry| entry.owner == owner && entry.context.as_deref() == Some(context)),
                "A2A context unavailable"
            );
        }
        let key = if let Some(task) = task {
            entries
                .iter()
                .find(|(_, entry)| entry.owner == owner && entry.task.as_deref() == Some(task))
                .map(|(key, _)| key.clone())
                .context("A2A task unavailable")?
        } else {
            ensure!(method.starts_with("message/"), "A2A task required");
            ensure!(
                entries.len() < self.limits.max_sessions
                    && entries
                        .values()
                        .filter(|entry| entry.owner == owner)
                        .count()
                        < self.limits.max_sessions_per_identity,
                "A2A task capacity exhausted"
            );
            let key = nasa::crypto::generate_salt(24);
            ensure!(!entries.contains_key(&key), "A2A task identifier collision");
            // 状态名额先于远端任务动作；不能在本域满载时借用其它域的任务目录容量。
            let workspace_lease = state_budget
                .map(|budget| {
                    budget
                        .acquire()
                        .map_err(|_| anyhow::anyhow!("workspace task capacity exhausted"))
                })
                .transpose()?;
            entries.insert(
                key.clone(),
                Entry {
                    _workspace_lease: workspace_lease,
                    owner,
                    task: None,
                    context: context.map(str::to_owned),
                    state: "submitted".into(),
                    expires: Instant::now() + Duration::from_millis(self.limits.session_ttl_ms),
                    calls: 0,
                    bytes: 0,
                    epoch: 0,
                    active: None,
                },
            );
            key
        };
        let entry = entries.get_mut(&key).expect("reserved A2A entry exists");
        ensure!(
            context.is_none_or(|context| entry.context.as_deref() == Some(context)),
            "A2A task context mismatch"
        );
        // 终态任务只能读取；取消先撤销旧动作的交付权限，再请求远端停止，不能让迟到 working 重新开放任务。
        ensure!(
            method == "tasks/get" || !terminal(&entry.state),
            "A2A task is terminal"
        );
        ensure!(
            entry.active.is_none() || method == "tasks/cancel",
            "A2A task action already active"
        );
        let reserved = bytes as u64 + self.limits.max_response_bytes as u64;
        ensure!(
            entry.calls < self.limits.max_calls_per_session
                && entry.bytes.saturating_add(reserved) <= self.limits.max_bytes_per_session,
            "A2A task budget exhausted"
        );
        if let Some(active) = entry.active.take() {
            active.cancel();
        }
        let budget = RequestBudget::until(deadline.min(entry.expires));
        entry.calls += 1;
        entry.bytes += reserved;
        entry.epoch += 1;
        entry.active = Some(budget.clone());
        Ok(Lease {
            catalog: self.clone(),
            key,
            epoch: entry.epoch,
            budget,
        })
    }
}

impl Lease {
    /// 业务作用：在任务结果对外可见前绑定 owner 和上下文，并原子发布合法的任务状态推进。
    ///
    /// 参数说明：
    /// - `value`：是已验证形态的 A2A task、message 或事件。
    ///
    /// 返回：发布成功；跨任务结果、跨主体上下文、终态回退和迟到代次拒绝且不发送该事件。
    pub(super) fn publish(&self, value: &Value) -> Result<()> {
        ensure!(!self.budget.is_exhausted(), "A2A action authority expired");
        let mut entries = self.catalog.entries.lock();
        let entry = entries.get(&self.key).context("A2A task retired")?;
        ensure!(
            entry.epoch == self.epoch && entry.expires > Instant::now(),
            "A2A action superseded"
        );
        let task = if value.get("kind").and_then(Value::as_str) == Some("task") {
            value.get("id")
        } else {
            value.get("taskId")
        }
        .and_then(Value::as_str);
        let context = value.get("contextId").and_then(Value::as_str);
        ensure!(
            entry
                .task
                .as_deref()
                .is_none_or(|expected| task == Some(expected)),
            "A2A result task mismatch"
        );
        ensure!(
            entry
                .context
                .as_deref()
                .is_none_or(|expected| context == Some(expected)),
            "A2A result context mismatch"
        );
        ensure!(
            !entries.iter().any(|(key, other)| key != &self.key
                && task.is_some()
                && other.task.as_deref() == task),
            "A2A result task already owned"
        );
        ensure!(
            !entries.values().any(|other| other.owner != entry.owner
                && context.is_some()
                && other.context.as_deref() == context),
            "A2A result context belongs to another identity"
        );
        let entry = entries
            .get_mut(&self.key)
            .expect("A2A entry still held under lock");
        if let Some(state) = value.pointer("/status/state").and_then(Value::as_str) {
            ensure!(
                !terminal(&entry.state) || state == entry.state,
                "A2A terminal state cannot change"
            );
            ensure!(
                state != "submitted" || entry.state == "submitted",
                "A2A task state cannot regress"
            );
            entry.state = state.to_owned();
            tracing::info!(task = %opaque(task.unwrap_or("")), context = %opaque(context.unwrap_or("")), state, "Agent task state");
        }
        if let Some(task) = task {
            entry.task = Some(task.to_owned());
        }
        if let Some(context) = context {
            entry.context = Some(context.to_owned());
        }
        Ok(())
    }
}

impl Drop for Lease {
    /// 业务作用：取消断开的本地动作并释放并发标记，不撤销已发布任务或远端副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅当前动作可释放自己的标记；未绑定任务或上下文的占位被删除。
    fn drop(&mut self) {
        self.budget.cancel();
        let mut entries = self.catalog.entries.lock();
        if let Some(entry) = entries.get_mut(&self.key) {
            if entry.epoch == self.epoch {
                entry.active = None;
                if entry.task.is_none() && entry.context.is_none() {
                    entries.remove(&self.key);
                }
            }
        }
    }
}

/// 业务作用：定义不允许继续执行或重新订阅的任务终态。
///
/// 参数说明：
/// - `state`：为已校验的 A2A 状态。
///
/// 返回：不可重新开放的终态为 true。
pub(super) fn terminal(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "canceled" | "rejected")
}

/// 业务作用：将任务与上下文标识压缩成低敏关联摘要，避免记录业务命名原文。
///
/// 参数说明：
/// - `id`：是受限协议标识。
///
/// 返回：固定长度摘要；不作为认证或授权依据。
fn opaque(id: &str) -> String {
    nasa::crypto::sha256(id)[..16].to_owned()
}
