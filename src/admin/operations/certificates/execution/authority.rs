//! 材料任务的运行权和全部原批准分别复验，离线节点不能被当前在线子集替代。

use super::frozen::Frozen;
use crate::{
    admin::{
        cluster,
        operations::{model::Error, Store},
        AdminState,
    },
    config::GatewaySnapshot,
    control::{
        baseline::NodeBaseline,
        material::{authorization, node::Intent},
        ownership::config::Action,
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(in crate::admin::operations) struct Authority<'a> {
    pub(super) state: &'a Arc<AdminState>,
    pub(super) snapshot: Arc<GatewaySnapshot>,
    local: Option<(Instant, Arc<NodeBaseline>)>,
}

impl<'a> Authority<'a> {
    /// 业务作用：保留本次精确快照继续原材料任务，重投不重新收集或替换原批准基线。
    ///
    /// 参数说明：
    /// - `state`：当前管理owner。
    /// - `snapshot`：本轮已发布的完整权限与资源实例。
    ///
    /// 返回：只能用于继续原任务的授权视图；缺初始本机观察时不能创建含本机的新任务。
    pub(in crate::admin::operations) fn continued(
        state: &'a Arc<AdminState>,
        snapshot: Arc<GatewaySnapshot>,
    ) -> Self {
        Self {
            state,
            snapshot,
            local: None,
        }
    }

    /// 业务作用：在共享事务之外收集有限本机基线，新任务等待数据库时不能把观察自动续期。
    ///
    /// 参数说明：
    /// - `state`：实际管理与可选Data共同owner。
    /// - `snapshot`：本次创建请求使用的精确活动实例。
    ///
    /// 返回：冻结本机有限观察的授权视图；缺本机基线不阻止全部为远端的任务继续核验。
    pub(in crate::admin::operations) async fn new(
        state: &'a Arc<AdminState>,
        snapshot: Arc<GatewaySnapshot>,
    ) -> Self {
        let local = if state.mode.full_control_plane() && state.mode.runs_data() {
            let started = Instant::now();
            cluster::baseline::collect(state, &snapshot)
                .await
                .node_baseline
                .map(|baseline| (started, baseline))
        } else {
            None
        };
        Self {
            state,
            snapshot,
            local,
        }
    }

    /// 业务作用：复验完整原批准和可选请求者，首次创建还要求每个原物理节点仍具原基线及独立材料能力。
    ///
    /// 参数说明：
    /// - `store`：本进程实际挂接的共享存储。
    /// - `frozen`：完整原任务及两个分母，不能从在线目录重建。
    /// - `initial`：创建新持久任务时为真，已提交任务重放为假。
    /// - `principal`：实际执行请求者；后台没有新增请求者时为空。
    ///
    /// 返回：所有当前权威和必要原节点基线均一致时成功；任一缺席、失权或配置变化拒绝整批。
    pub(in crate::admin::operations) fn check(
        &self,
        store: &Store,
        frozen: &Frozen,
        initial: bool,
        principal: Option<&str>,
    ) -> Result<(), Error> {
        let plan = running(self.state, store, &self.snapshot)?;
        frozen.authorize(&self.snapshot)?;
        let first = frozen.nodes.first().ok_or(Error::Conflict)?;
        if first.baseline.cluster_id != store.plan.config.cluster_id {
            return Err(Error::Conflict);
        }
        if let Some(principal) = principal {
            for action in [Action::Read, Action::Write] {
                authorization::check(&first.scope, &self.snapshot, principal, action)
                    .ok_or(Error::Denied)?;
            }
        }
        if initial {
            for intent in &frozen.nodes {
                // 原完整批准是不可缩减的创建屏障，远端缺席时保留失败，不能跳过该节点发布其它来源。
                if intent.node_id == plan.node_id {
                    self.local(intent)?;
                } else {
                    self.state
                        .management
                        .remote_material_action_session(&self.snapshot, intent, true)
                        .map_err(|_| Error::Conflict)?;
                }
            }
        }
        Ok(())
    }

    /// 业务作用：本机创建门同时限定角色、独立开关、原boot与完整文档基线，旧观察不能授予新文件权。
    ///
    /// 参数说明：
    /// - `intent`：原批准中的本机完整节点意图。
    ///
    /// 返回：六秒内同一活动实例的空闲基线成立才成功；数据面缺席、材料能力关闭或漂移均拒绝。
    fn local(&self, intent: &Intent) -> Result<(), Error> {
        let Some((at, baseline)) = &self.local else {
            return Err(Error::Conflict);
        };
        let facts = cluster::facts::collect(self.state, &self.snapshot);
        if at.elapsed() > Duration::from_secs(6)
            || !self.state.mode.runs_data()
            || !self
                .snapshot
                .admin_management
                .as_ref()
                .is_some_and(|plan| plan.material_actions_enabled)
            || !facts.ready
            || facts.boot_id != intent.original_boot_id
            || self.snapshot.version != intent.base_version
            || self.snapshot.config_fingerprint != Some(intent.base_fingerprint)
            || baseline.as_ref() != &intent.baseline
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// 业务作用：以独立材料开关和精确活动实例授权本轮共享任务，配置执行开关不授予材料发行权。
///
/// 参数说明：
/// - `state`：当前角色和实际挂接的存储owner。
/// - `store`：本轮使用的原共享数据库资源。
/// - `snapshot`：本次读取、提交及发行共同保留的活动快照。
///
/// 返回：同集群当前发行计划；停机、旧实例、撤权、未安装合同或未启用独立能力时拒绝。
pub(in crate::admin::operations) fn running(
    state: &AdminState,
    store: &Store,
    snapshot: &Arc<GatewaySnapshot>,
) -> Result<Arc<crate::admin::management::Plan>, Error> {
    if store.stopping.is_cancelled()
        || !store.material_execution_installed
        || store.workflow.get().is_none()
        || !state.mode.full_control_plane()
        || !Arc::ptr_eq(&state.snap.load_full(), snapshot)
        || !snapshot.admin_auth.enabled
        || !snapshot.admin_auth.rbac_enabled
        || !snapshot.admin_audit.enabled
        || !snapshot.admin_audit.fsync
        || !state
            .operations
            .get()
            .is_some_and(|installed| std::ptr::eq(installed.as_ref(), store))
        || !snapshot.admin_operations.as_ref().is_some_and(|plan| {
            plan.same_bootstrap(&store.plan)
                && plan.config.workflow.enabled
                && plan.config.certificates.enabled
                && plan.config.certificates.impact_approvals.enabled
                && plan.config.certificates.execution.enabled
        })
    {
        return Err(Error::Unavailable);
    }
    state
        .management
        .action_plan(snapshot, &store.plan.config.cluster_id)
        .map_err(|_| Error::Denied)
}
