//! 执行权限来自当前完整快照，原审批和节点观察只能作为待复验的证据。

use super::frozen::Frozen;
use crate::{
    admin::{
        cluster,
        operations::{model::Error, Store},
        AdminState,
    },
    config::GatewaySnapshot,
    control::{
        actions::{authorization::Scope, command::Intent},
        baseline::NodeBaseline,
        ownership::config::Action,
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(in crate::admin::operations) struct Authority<'a> {
    state: &'a AdminState,
    snapshot: Arc<GatewaySnapshot>,
    local: Option<(Instant, Arc<NodeBaseline>)>,
}

impl<'a> Authority<'a> {
    /// 业务作用：为已有执行的投递保留当前快照，不重新收集或补选原目标的空闲基线。
    ///
    /// 参数说明：
    /// - state：当前完整管理 owner。
    /// - snapshot：本轮实际冻结的活动实例。
    ///
    /// 返回：仅用于非初始复验的授权视图；若误用于本机初次创建，缺基线会明确拒绝。
    pub(in crate::admin::operations) fn continued(
        state: &'a AdminState,
        snapshot: Arc<GatewaySnapshot>,
    ) -> Self {
        Self {
            state,
            snapshot,
            local: None,
        }
    }

    /// 业务作用：在数据库事务之外读取本机有限基线，避免持事务锁等待文件工作或阻塞任务。
    ///
    /// 参数说明：
    /// - state：当前完整控制面及唯一节点文件 owner。
    /// - snapshot：本次请求或投递冻结的已发布实例。
    ///
    /// 返回：保留原快照的复验器；本机基线缺席不妨碍仅包含远端目标的原操作。
    pub(in crate::admin::operations) async fn new(
        state: &'a AdminState,
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

    /// 业务作用：复验原审批双方、权威摘要与全部初始目标，整体创建不能被单节点的合格证据替代。
    ///
    /// 参数说明：
    /// - store：当前进程实际挂接的同源持久 owner。
    /// - frozen：数据库读出的原审批意图及完整目标集合。
    /// - initial：创建前为真，已经提交的执行重放为假。
    /// - principal：当前执行请求主体；后台投递没有新增请求主体时为空。
    ///
    /// 返回：所有当前门同时成立才成功；任何目标、身份或快照失权都拒绝整个决定。
    pub(in crate::admin::operations) fn check(
        &self,
        store: &Store,
        frozen: &Frozen,
        initial: bool,
        principal: Option<&str>,
    ) -> Result<(), Error> {
        let intent = frozen.targets.first().ok_or(Error::Unavailable)?;
        // 已挂接 owner、同源资源与精确快照共同约束本次提交，不能用相同内容的新实例续权。
        if store.plan.config.cluster_id != intent.baseline.cluster_id {
            return Err(Error::Unavailable);
        }
        let plan = running(self.state, store, &self.snapshot)?;
        current(self.state, &self.snapshot, intent, principal)?;
        if initial {
            for target in &frozen.targets {
                if target.node_id == plan.node_id {
                    self.check_local(target)?;
                } else {
                    self.state
                        .management
                        .remote_action_session(&self.snapshot, target, true)
                        .map_err(|_| Error::Conflict)?;
                }
            }
        }
        Ok(())
    }

    /// 业务作用：将本机空闲基线限定到同一次有限观察，当前 readiness 与原快照缺一不可。
    ///
    /// 参数说明：
    /// - intent：审批时冻结的本机原目标。
    ///
    /// 返回：本机角色、动作开关、原启动、配置和持久基线一致才成功；过时观察不延长创建资格。
    fn check_local(&self, intent: &Intent) -> Result<(), Error> {
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
                .is_some_and(|plan| plan.actions_enabled)
            || !Arc::ptr_eq(&self.state.snap.load_full(), &self.snapshot)
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

/// 业务作用：拒绝仅凭持久身份或旧权限摘要继续写入，双人当前权限必须同时成立。
///
/// 参数说明：
/// - state：当前已发布状态及部署角色。
/// - snapshot：本次决定保留的完整实例。
/// - intent：原审批范围、主体和权威摘要。
/// - principal：可选的当前请求主体，还需具有同范围 Write。
///
/// 返回：同一快照、启用认证与 RBAC、不同主体及全部当前权限成立才成功。
fn current(
    state: &AdminState,
    snapshot: &Arc<GatewaySnapshot>,
    intent: &Intent,
    principal: Option<&str>,
) -> Result<(), Error> {
    let scope = Scope::parse(&intent.scope).ok_or(Error::Denied)?;
    if !state.mode.full_control_plane()
        || !Arc::ptr_eq(&state.snap.load_full(), snapshot)
        || !snapshot.admin_auth.enabled
        || !snapshot.admin_auth.rbac_enabled
        || intent.creator == intent.reviewer
        || scope.authority(snapshot) != Some(intent.authority_sha256)
        || !scope.allows(snapshot, &intent.creator, intent.domain, Action::Write)
        || !scope.allows(snapshot, &intent.reviewer, intent.domain, Action::Review)
        || principal.is_some_and(|principal| {
            !scope.allows(snapshot, principal, intent.domain, Action::Write)
        })
    {
        return Err(Error::Denied);
    }
    Ok(())
}

/// 业务作用：为派发与定时器复用同一当前运行门，安装数据库本身不启动执行。
///
/// 参数说明：
/// - state：本进程真实控制面及已挂接存储。
/// - store：本轮使用的唯一持久 owner。
/// - snapshot：本轮冻结的完整活动实例。
///
/// 返回：当前同集群发行计划；执行关闭、停机、旧资源或缺少已安装结构时拒绝。
pub(in crate::admin::operations) fn running(
    state: &AdminState,
    store: &Store,
    snapshot: &Arc<GatewaySnapshot>,
) -> Result<Arc<crate::admin::management::Plan>, Error> {
    if store.stopping.is_cancelled()
        || !store.delivery_installed
        || store.workflow.get().is_none()
        || !state
            .operations
            .get()
            .is_some_and(|installed| std::ptr::eq(installed.as_ref(), store))
        || !snapshot.admin_audit.enabled
        || !snapshot.admin_audit.fsync
        || !snapshot
            .admin_operations
            .as_ref()
            .is_some_and(|plan| plan.config.execution.enabled && plan.same_bootstrap(&store.plan))
    {
        return Err(Error::Unavailable);
    }
    state
        .management
        .action_plan(snapshot, &store.plan.config.cluster_id)
        .map_err(|_| Error::Denied)
}
