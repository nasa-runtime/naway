//! 独立材料会话和当前四主体共同授权，工作许可覆盖下载、阻塞文件任务和结果交付。

use crate::{
    admin::{
        management::{actions::window::Window, issuer::Verifier, Plan},
        AdminState,
    },
    config::GatewaySnapshot,
    control::{
        actions::command::Delivery,
        material::{authorization, execution::command::Command, node::Intent},
        ownership::config::Action,
    },
};
use anyhow::{ensure, Context, Result};
use std::sync::{atomic::Ordering, Arc};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

pub(in crate::admin::management) struct Session {
    plan: Arc<Plan>,
    pub(super) issuer: Arc<Verifier>,
    pub(super) token: [u8; 32],
    expires_at: u64,
    revoked: CancellationToken,
    window: parking_lot::Mutex<Option<(String, Arc<Window>)>>,
}

pub(in crate::admin::management) struct Work {
    command: Command,
    admission: Admission,
}

pub(super) struct Admission {
    active: Arc<GatewaySnapshot>,
    session: Arc<Session>,
    window: Arc<Window>,
    _permit: OwnedSemaphorePermit,
}

impl Session {
    /// 业务作用：将材料会话限定到当前计划的精确受信发行者，显式关闭时不创建材料执行权威。
    ///
    /// 参数说明：
    /// - `plan`：握手时已经发布的原管理计划。
    /// - `issuer`：该计划对应真实连接目标的验证器。
    /// - `token`：成功挑战已经绑定的随机会话。
    ///
    /// 返回：独立可撤销会话；关闭、非计划目标或非法令牌拒绝。
    pub(super) fn new(plan: Arc<Plan>, issuer: Arc<Verifier>, token: &[u8]) -> Result<Arc<Self>> {
        ensure!(plan.material_actions_enabled, "material actions disabled");
        let expires_at = plan
            .targets
            .iter()
            .find(|target| {
                target
                    .issuer
                    .as_ref()
                    .is_some_and(|candidate| Arc::ptr_eq(candidate, &issuer))
            })
            .context("material issuer does not belong to this plan")?
            .expires_at;
        Ok(Arc::new(Self {
            plan,
            issuer,
            token: token
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid material session"))?,
            expires_at,
            revoked: CancellationToken::new(),
            window: parking_lot::Mutex::new(None),
        }))
    }

    /// 业务作用：为本机全控制面建立随机材料会话，直接调用也必须持同一独立开关和配对发行身份。
    ///
    /// 参数说明：
    /// - `plan`：本机已通过角色和当前集群门的原计划。
    ///
    /// 返回：仅本次工作持有的会话；没有材料开关、配对发行者或随机源时拒绝。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(super) fn local(plan: Arc<Plan>) -> Result<Arc<Self>> {
        ensure!(
            plan.material_actions_enabled,
            "local material actions disabled"
        );
        let receiver = plan
            .receiver
            .as_ref()
            .context("local material receiver absent")?;
        let issuer = receiver
            .issuer
            .as_ref()
            .context("local material issuer absent")?
            .local_verifier(&plan.node_id);
        let expires_at = receiver.expires_at;
        let mut token = [0; 32];
        getrandom::getrandom(&mut token).context("material session entropy unavailable")?;
        Ok(Arc::new(Self {
            plan,
            issuer,
            token,
            expires_at,
            revoked: CancellationToken::new(),
            window: parking_lot::Mutex::new(None),
        }))
    }

    /// 业务作用：连接失效或身份换代立即撤销后续决定，后台任务持有Arc不能延长原会话权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：之后全部授权门拒绝，已决定的持久文件方向仍由原记录负责恢复。
    pub(super) fn revoke(&self) {
        self.revoked.cancel();
    }
}

impl Work {
    /// 业务作用：在任何候选下载前验签并取得节点唯一实际动作许可，材料与配置写入不能并行受理。
    ///
    /// 参数说明：
    /// - `state`：当前节点的快照、boot和全进程动作容量。
    /// - `session`：已通过挑战且未撤销的独立材料会话。
    /// - `command`：保持原分配的完整原生命令。
    /// - `signature`：绑定原意图、物理位置及当前投递的材料域签名。
    ///
    /// 返回：持有当前读取权和实际许可的共享工作；签名、窗口、权限或容量失败无持久副作用。
    pub(super) fn accept(
        state: &AdminState,
        session: Arc<Session>,
        command: Command,
        signature: &str,
    ) -> Result<Arc<Self>> {
        let checked =
            session
                .issuer
                .verify_material_command(&command, signature, &session.token)?;
        let admission = Admission::claim(state, session, &command.delivery, checked.message())?;
        let work = Arc::new(Self {
            command,
            admission,
        });
        work.authorize(state, false)?;
        Ok(work)
    }

    /// 业务作用：在查询、下载和业务决定前复验原实例与当前四主体，不由原批准替代当前本机权限。
    ///
    /// 参数说明：
    /// - `state`：当前节点唯一管理owner。
    /// - `write`：新增持久决定要求两创建者写权和两审阅者审阅权，读取要求四者当前读权。
    ///
    /// 返回：原会话、原快照、窗口、角色及完整共享影响归属全部成立时成功。
    pub(super) fn authorize(&self, state: &AdminState, write: bool) -> Result<()> {
        self.admission
            .authorize(state, &self.command.intent, &self.command.delivery, write)
    }

    /// 业务作用：借用同次验签的原命令，下载或执行阶段不能替换审批和投递身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与本工作许可绑定的不可变原命令。
    pub(super) fn command(&self) -> &Command {
        &self.command
    }

    /// 业务作用：文件决定使用受理时固定的真实配置，最终权限门仍验证其未被另一实例替代。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本工作冻结的原活动快照，不从新目录补齐原目标。
    pub(super) fn active(&self) -> &GatewaySnapshot {
        &self.admission.active
    }
}

impl Admission {
    /// 业务作用：用真实动作名额和首次验真窗口约束命令或释放，同投递重复不会重新取得更长期限。
    ///
    /// 参数说明：
    /// - `state`：当前实际节点与配置动作共用的容量。
    /// - `session`：同次完整验签使用的原会话。
    /// - `delivery`：签名中的不可变时间与接收boot。
    /// - `message`：完整验签后的规范摘要。
    ///
    /// 返回：随实际任务释放的独占许可；容量或期限不成立时拒绝排队。
    pub(super) fn claim(
        state: &AdminState,
        session: Arc<Session>,
        delivery: &Delivery,
        message: &str,
    ) -> Result<Self> {
        let permit = state
            .management
            .action_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("material action worker is busy"))?;
        let window = {
            let mut retained = session.window.lock();
            if let Some((_, window)) = retained.as_ref().filter(|(key, _)| key == message) {
                window.clone()
            } else {
                let window = Arc::new(Window::preview(
                    delivery.issued_at_ms,
                    delivery.expires_at_ms,
                )?);
                *retained = Some((message.to_owned(), window.clone()));
                window
            }
        };
        Ok(Self {
            active: state.snap.load_full(),
            session,
            window,
            _permit: permit,
        })
    }

    /// 业务作用：将材料读写限制到当前四主体和原完整影响对象，发行签名不能授予跨工作区或旧实例权威。
    ///
    /// 参数说明：
    /// - `state`：当前管理owner与已发布快照。
    /// - `intent`：独立验签的原节点材料意图。
    /// - `delivery`：本会话当前投递。
    /// - `write`：为真时逐主体要求写入或审阅，为假时要求当前读取。
    ///
    /// 返回：全部当前条件同时成立时成功；失权不改变已持久方向，也不允许新增效果。
    pub(super) fn authorize(
        &self,
        state: &AdminState,
        intent: &Intent,
        delivery: &Delivery,
        write: bool,
    ) -> Result<()> {
        self.window.check()?;
        let current = state.snap.load_full();
        // 原实例、原会话和当前boot必须同时有效，配置A→B→A不能恢复旧请求资格。
        ensure!(
            !state.management.stopping.is_cancelled()
                && state.mode.runs_data()
                && state.ready.load(Ordering::Acquire)
                && !self.session.revoked.is_cancelled()
                && super::super::runtime::unix_seconds() < self.session.expires_at
                && Arc::ptr_eq(&current, &self.active)
                && current
                    .admin_management
                    .as_ref()
                    .is_some_and(|plan| Arc::ptr_eq(plan, &self.session.plan))
                && self.session.plan.material_actions_enabled
                && self.session.plan.node_id == intent.node_id
                && state.monitor.boot_id() == delivery.receiving_boot_id
                && current.admin_auth.enabled
                && current.admin_auth.rbac_enabled
                && current.admin_audit.enabled
                && !current.config_source.nacos.enabled,
            "material action current authority changed"
        );
        for (principal, permission) in [
            (&intent.material_creator, Action::Write),
            (&intent.material_reviewer, Action::Review),
            (&intent.impact_creator, Action::Write),
            (&intent.impact_reviewer, Action::Review),
        ] {
            ensure!(
                authorization::check(
                    &intent.scope,
                    &current,
                    principal,
                    if write {
                        permission
                    } else {
                        Action::Read
                    }
                )
                .is_some(),
                "material action principal authority denied"
            );
        }
        // 原批准覆盖所有共享对象；只检查用户选中的别名会遗漏另一工作区的实际受影响监听。
        ensure!(
            authorization::logical_targets(
                &intent.scope,
                &current,
                &intent.node_id,
                intent
                    .conditions
                    .groups
                    .iter()
                    .flat_map(|group| group.affected.iter().map(|entry| &entry.target)),
            )
            .is_some(),
            "material action affected scope denied"
        );
        Ok(())
    }
}
