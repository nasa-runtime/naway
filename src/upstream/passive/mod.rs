//! L7 与 L4 共用的实例反馈、连续失败记录和被动健康运行态。

#[cfg(feature = "upstream-outlier")]
pub(crate) mod metrics;
pub mod policy;
#[cfg(feature = "upstream-outlier")]
pub mod window;
#[cfg(not(feature = "upstream-outlier"))]
#[path = "disabled.rs"]
pub mod window;

use super::{load, PassiveHealthPolicy};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 实例身份由当前上游目录提供；反馈和摘除事实不另行发现或创建业务实例。
#[derive(Default)]
pub struct Registry {
    loads: DashMap<Arc<str>, LoadSlot>,
    load_admission: Mutex<()>,
    load_version: AtomicU64,
    failures: Mutex<HashMap<String, Failure>>,
    failure_entries: AtomicU64,
    #[cfg(feature = "upstream-outlier")]
    groups: Mutex<Groups>,
    #[cfg(feature = "upstream-outlier")]
    budget: Arc<window::Budget>,
}

struct LoadSlot {
    generation: (u64, u64),
    entry: Arc<load::InstanceLoad>,
}

#[cfg(feature = "upstream-outlier")]
#[derive(Default)]
struct Groups {
    version: u64,
    values: HashMap<String, Arc<window::Group>>,
}

struct Failure {
    consecutive: u32,
    until: Option<Instant>,
}

impl Registry {
    /// 业务作用：向受权管理读面提供已存在窗口组的当前摘要，不因读取创建状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按逻辑服务名排序的固定容量摘要，不含实例地址、请求键或响应内容。
    #[cfg(feature = "upstream-outlier")]
    pub(crate) fn status(&self) -> serde_json::Value {
        let groups = self.groups.lock();
        let summaries: std::collections::BTreeMap<_, _> = groups
            .values
            .iter()
            .map(|(name, group)| (name.as_str(), group.status()))
            .collect();
        serde_json::json!({
            "snapshot_version": groups.version, "services": summaries
        })
    }
    /// 业务作用：在共享目录锁内取得窗口组，避免同一发现更新被旧成员视图覆盖。
    ///
    /// 参数说明：
    /// - `version`：已发布快照的单调版本。
    /// - `service`：目录中的逻辑服务名。
    /// - `policy`：当前快照已验证的策略。
    /// - `source`：持锁后读取当前实例切片，不进行网络或阻塞 I/O。
    ///
    /// 返回：成员与容量合法时返回共享组；旧版本或资源不足拒绝，不创建第二份健康状态。
    #[cfg(feature = "upstream-outlier")]
    pub(super) fn group(
        &self,
        version: u64,
        service: &str,
        policy: policy::Policy,
        source: impl FnOnce() -> Arc<[Arc<super::UpstreamInstance>]>,
    ) -> Option<Arc<window::Group>> {
        let mut groups = self.groups.lock();
        if version < groups.version {
            return None;
        }
        groups.version = version;
        let source = source();
        if let Some(group) = groups.values.get(service) {
            return group
                .refresh(version, policy, source)
                .then(|| group.clone());
        }
        let group = window::Group::new(version, policy, source, self.budget.clone())?;
        groups.values.insert(service.to_owned(), group.clone());
        Some(group)
    }

    /// 业务作用：发布后撤下已删除或关闭窗口策略的服务，使旧请求不能重新创建过期健康组。
    ///
    /// 参数说明：
    /// - `directory`：唯一活动快照的上游目录。
    /// - `version`：已经发布的版本。
    ///
    /// 返回：撤销旧组的查找权威，仍有真实 I/O 的组继续持有容量直到最后释放。
    #[cfg(feature = "upstream-outlier")]
    pub fn reconcile_groups(&self, directory: &super::UpstreamDirectory, version: u64) {
        let mut groups = self.groups.lock();
        if version < groups.version {
            return;
        }
        groups.version = version;
        groups.values.retain(|service, group| {
            let Some(snapshot) = directory.services.get(service) else {
                return false;
            };
            let Some(policy) = snapshot.outlier else {
                return false;
            };
            let source = match directory.instances_for(service, snapshot) {
                super::UpstreamInstances::Static(_) => snapshot.instances.clone(),
                super::UpstreamInstances::Dynamic(instances) => instances,
                super::UpstreamInstances::Empty => Arc::from([]),
            };
            // 容量不足不抹去旧保护事实；下一次请求会再次复验，并以无法对账拒绝发送。
            group.refresh(version, policy, source);
            true
        });
    }

    /// 业务作用：读取实例的共享负载反馈，保持所有调度者使用同一量纲和过期口径。
    ///
    /// 参数说明：
    /// - `instance`：本次候选中的真实实例，包含不可复用的入场代际。
    /// - `version`：本次选择固定持有的配置版本。
    /// - `policy`：当前服务的反馈策略。
    /// - `now_ms`：本次选择固定使用的单调时刻。
    ///
    /// 返回：样本有效时返回调度分数；无记录、样本不足或过期时返回 None。
    pub fn load_score(
        &self,
        instance: &super::UpstreamInstance,
        version: u64,
        policy: &load::LoadFeedbackPolicy,
        now_ms: u64,
    ) -> Option<u64> {
        self.loads
            .get(instance.feedback_key.as_ref())
            .filter(|slot| slot.generation == (version, instance.feedback_generation))
            .and_then(|slot| slot.entry.score(policy, now_ms))
    }

    /// 业务作用：在真实实例被选中时固定反馈句柄，迟到响应只更新原句柄而不重建已撤下身份。
    ///
    /// 参数说明：
    /// - `instance`：已由请求快照选择或订阅目录授权的真实实例。
    /// - `version`：授予观察权的配置版本，策略变化不能继承旧口径的样本。
    ///
    /// 返回：同代共享反馈；换代建立空状态，旧代调用或达到硬容量时拒绝新建。
    pub fn load_entry(
        &self,
        instance: &super::UpstreamInstance,
        version: u64,
    ) -> Option<Arc<load::InstanceLoad>> {
        if version < self.load_version.load(Ordering::Acquire) {
            return None;
        }
        let key = &instance.feedback_key;
        let generation = (version, instance.feedback_generation);
        if let Some(slot) = self.loads.get(key.as_ref()) {
            if slot.generation == generation {
                return Some(slot.entry.clone());
            }
            // 迟到请求只能继续持有旧句柄，不能撤换新配置或同地址新实例的调度状态。
            if slot.generation > generation {
                return None;
            }
        }
        // 换代、容量检查与插入串行；旧 Arc 可完成在途响应，但不会参与新代读取。
        let _admission = self.load_admission.lock();
        // 发布对账会撤销旧配置的建表权，避免仍在途的旧请求在回收后重新占用容量。
        if version < self.load_version.load(Ordering::Acquire) {
            return None;
        }
        if let Some(slot) = self.loads.get(key.as_ref()) {
            if slot.generation == generation {
                return Some(slot.entry.clone());
            }
            if slot.generation > generation {
                return None;
            }
        } else if self.loads.len() >= load::MAX_TRACKED_INSTANCES {
            return None;
        }
        let entry = Arc::new(load::InstanceLoad::default());
        self.loads.insert(
            key.clone(),
            LoadSlot {
                generation,
                entry: entry.clone(),
            },
        );
        Some(entry)
    }

    /// 业务作用：在目录发布后撤下已无权参与调度的运行态，所有协议共用这次对账。
    ///
    /// 参数说明：
    /// - `identities`：当前快照与新鲜发现结果中的实例身份集合。
    /// - `directory`：当前服务目录，用于回收已撤销的服务内反馈身份。
    /// - `version`：已经发布的配置版本。
    ///
    /// 返回：不触发外部查询；旧请求持有的反馈 Arc 可自然结束，但不会重新出现在目录中。
    pub fn reconcile(
        &self,
        identities: &HashSet<Arc<str>>,
        directory: &super::UpstreamDirectory,
        version: u64,
    ) {
        self.reconcile_loads(directory, version);
        let mut failures = self.failures.lock();
        failures.retain(|key, _| identities.contains(key.as_str()));
        self.failure_entries
            .store(failures.len() as u64, Ordering::Release);
    }

    /// 业务作用：周期回收已离开动态目录的反馈，避免长期实例变更耗尽固定状态容量。
    ///
    /// 参数说明：
    /// - `directory`：已发布配置中的唯一上游目录。
    /// - `version`：该配置的单调版本。
    ///
    /// 返回：撤下无效反馈的查找权；已授予的旧 Arc 不影响新代，未启用反馈时不扫描目录。
    pub(crate) fn reconcile_loads(&self, directory: &super::UpstreamDirectory, version: u64) {
        let admission = self.load_admission.lock();
        // 对账与建表共享门禁，先撤销旧代建表权再回收；并发的旧发布不能反向删除新反馈。
        if version < self.load_version.load(Ordering::Acquire) {
            return;
        }
        self.load_version.store(version, Ordering::Release);
        if self.loads.is_empty() {
            return;
        }
        let mut feedback_identities = HashMap::new();
        for (name, service) in &directory.services {
            if !service.load_feedback.enabled() {
                continue;
            }
            for instance in directory.instances_for(name, service).as_slice() {
                feedback_identities
                    .insert(instance.feedback_key.clone(), instance.feedback_generation);
            }
        }
        self.loads.retain(|key, slot| {
            // 新请求可能比本轮扫描先观察到发现更新；不能用较旧目录撤销已经建立的新代状态。
            slot.generation.0 > version
                || (slot.generation.0 == version
                    && feedback_identities
                        .get(key)
                        .is_some_and(|created| slot.generation.1 >= *created))
        });
        drop(admission);
    }

    /// 业务作用：提供连续失败策略当前仍在冷却的实例集合，供 L7/L4 与主动健康结果一起过滤。
    ///
    /// 参数说明：
    /// - `policy`：该服务的连续失败策略；关闭时不读取运行态。
    ///
    /// 返回：只包含仍在摘除期的身份；已到期的失败状态被回收。
    pub fn ejected(&self, policy: PassiveHealthPolicy) -> Vec<String> {
        if !policy.enabled() || self.failure_entries.load(Ordering::Acquire) == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        let mut failures = self.failures.lock();
        failures.retain(|_, state| {
            state
                .until
                .map_or(state.consecutive > 0, |until| until > now)
        });
        self.failure_entries
            .store(failures.len() as u64, Ordering::Release);
        failures
            .iter()
            .filter_map(|(key, state)| {
                state
                    .until
                    .filter(|until| *until > now)
                    .map(|_| key.clone())
            })
            .collect()
    }

    /// 业务作用：用真实上游成功清除连续失败事实，避免协议各自保留相互矛盾的健康状态。
    ///
    /// 参数说明：
    /// - `key`：实际响应或连接成功的实例身份。
    ///
    /// 返回：仅影响已有失败记录；正常成功热路径不创建条目。
    pub fn success(&self, key: &str) {
        if self.failure_entries.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut failures = self.failures.lock();
        if failures.remove(key).is_some() {
            self.failure_entries.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// 业务作用：汇总真实失败并发布连续失败摘除事实，后续所有协议都能观察同一冷却状态。
    ///
    /// 参数说明：
    /// - `key`：实际尝试的实例身份。
    /// - `policy`：尝试所属服务冻结的连续失败策略。
    ///
    /// 返回：关闭策略时无副作用；达到阈值后发布带期限的摘除，不修改发现事实源。
    pub fn failure(&self, key: &str, policy: PassiveHealthPolicy) {
        if !policy.enabled() {
            return;
        }
        let now = Instant::now();
        let mut failures = self.failures.lock();
        if !failures.contains_key(key) {
            failures.insert(
                key.to_owned(),
                Failure {
                    consecutive: 0,
                    until: None,
                },
            );
            self.failure_entries.fetch_add(1, Ordering::Release);
        }
        let state = failures
            .get_mut(key)
            .expect("failure identity was inserted");
        if state.until.is_some_and(|until| until <= now) {
            state.until = None;
            state.consecutive = 0;
        }
        state.consecutive = state.consecutive.saturating_add(1);
        if state.consecutive >= policy.max_fails {
            // 先在共享锁内写完整截止时间，释放后新的选择才能观察到摘除事实。
            state.until = Some(now + Duration::from_millis(policy.fail_timeout_ms));
            state.consecutive = 0;
            tracing::warn!(
                upstream = key,
                fail_timeout_ms = policy.fail_timeout_ms,
                "upstream passively ejected"
            );
        }
    }
}
