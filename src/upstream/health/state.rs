//! 后台阈值与当前拒绝事实按逻辑服务和策略隔离，传输池身份保持独立。

use super::{InstanceHealth, PolicyIdentity};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct ProbeKey {
    pub service: Arc<str>,
    pub policy: PolicyIdentity,
    pub endpoint: Arc<str>,
}

#[derive(Default)]
pub(super) struct CycleState {
    pub owner: Arc<()>,
    pub instances: HashMap<ProbeKey, InstanceHealth>,
    pub clients: super::clients::ClientSet,
}

#[derive(Default)]
pub struct Rejections {
    services: HashMap<Arc<str>, HashMap<PolicyIdentity, HashSet<String>>>,
    empty: HashSet<String>,
}

impl Rejections {
    /// 业务作用：只借用当前逻辑服务和探测策略的拒绝集合，策略撤销或变更立即撤去旧拒绝权。
    ///
    /// 参数说明：
    /// - `service`：本次选择冻结的逻辑服务身份。
    /// - `policy`：当前配置的规范策略与传输协议，None 表示未配置主动探测。
    ///
    /// 返回：同身份端点集合；无当前证据时为空，不跨服务借用，也不复制身份或集合。
    pub fn service(&self, service: &str, policy: Option<PolicyIdentity>) -> &HashSet<String> {
        policy
            .and_then(|policy| self.services.get(service)?.get(&policy))
            .unwrap_or(&self.empty)
    }

    /// 业务作用：统计按服务与策略隔离的实际拒绝数量，供固定低基数健康指标发布。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前服务端点拒绝总数，同一物理端点可能在不同服务分别计数。
    pub(super) fn count(&self) -> usize {
        self.services
            .values()
            .flat_map(HashMap::values)
            .map(HashSet::len)
            .sum()
    }

    /// 业务作用：从当前轮次仍有效的阈值状态冻结低频发布事实，不混合旧服务或旧策略。
    ///
    /// 参数说明：
    /// - `states`：已通过轮次所有权复验的后台实例状态。
    ///
    /// 返回：仅包含当前被拒绝端点的新快照，成功实例不占用数据面集合条目。
    pub(super) fn collect(states: &HashMap<ProbeKey, InstanceHealth>) -> Self {
        let mut result = Self::default();
        for (key, state) in states {
            if !state.healthy {
                result
                    .services
                    .entry(key.service.clone())
                    .or_default()
                    .entry(key.policy)
                    .or_default()
                    .insert(key.endpoint.to_string());
            }
        }
        result
    }
}
