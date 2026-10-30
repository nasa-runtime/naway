//! 只读构建保持当前会话与实际工作许可，取消等待不能释放仍在运行的候选任务。

use super::{command::Command, Reason};
use crate::{
    admin::{
        management::{actions::window::Window, issuer::Verifier, Plan},
        AdminState,
    },
    config::GatewaySnapshot,
    control::{actions::authorization::Scope, ownership::config::Action},
};
use std::sync::{atomic::Ordering, Arc};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

pub(super) struct Session {
    plan: Arc<Plan>,
    issuer: Arc<Verifier>,
    pub(super) token: [u8; 32],
    expires_at: u64,
    revoked: CancellationToken,
    window: parking_lot::Mutex<Option<(String, Arc<Window>)>>,
}

pub(super) struct Work {
    pub command: Arc<Command>,
    pub message: String,
    pub active: Arc<GatewaySnapshot>,
    session: Arc<Session>,
    window: Arc<Window>,
    _permit: OwnedSemaphorePermit,
}

pub(super) struct Verified {
    pub command: Arc<Command>,
    pub message: String,
    session: Arc<Session>,
    window: Arc<Window>,
}

impl Session {
    /// 业务作用：固定已完成发行者挑战的预览连接，任何后续候选都不能自行选择信任域。
    ///
    /// 参数说明：
    /// - `plan`：当前已发布管理计划。
    /// - `issuer`：该计划中实际目标的验证器。
    /// - `token`：挑战已绑定的本连接会话。
    ///
    /// 返回：独立可撤销的预览会话；未启用、非计划目标或非法令牌拒绝。
    pub(super) fn new(
        plan: Arc<Plan>,
        issuer: Arc<Verifier>,
        token: &[u8],
    ) -> Result<Arc<Self>, Reason> {
        if !plan.previews_enabled {
            return Err(Reason::Disabled);
        }
        let expires_at = plan
            .targets
            .iter()
            .find(|target| {
                target
                    .issuer
                    .as_ref()
                    .is_some_and(|value| Arc::ptr_eq(value, &issuer))
            })
            .ok_or(Reason::Denied)?
            .expires_at;
        Ok(Arc::new(Self {
            plan,
            issuer,
            token: token.try_into().map_err(|_| Reason::Denied)?,
            expires_at,
            revoked: CancellationToken::new(),
            window: parking_lot::Mutex::new(None),
        }))
    }

    /// 业务作用：为本机原目标建立独立预览会话，保持与远程路径相同的签名与撤销合同。
    ///
    /// 参数说明：
    /// - `plan`：本机已通过发行和当前集群门的精确管理计划。
    ///
    /// 返回：只供本次本机预览的随机会话；无预览开关、发行材料或随机源时拒绝。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(super) fn local(plan: Arc<Plan>) -> Result<Arc<Self>, Reason> {
        if !plan.previews_enabled {
            return Err(Reason::Disabled);
        }
        let receiver = plan.receiver.as_ref().ok_or(Reason::Unavailable)?;
        let issuer = receiver
            .issuer
            .as_ref()
            .ok_or(Reason::Unavailable)?
            .local_verifier(&plan.node_id);
        let expires_at = receiver.expires_at;
        let mut token = [0; 32];
        getrandom::getrandom(&mut token).map_err(|_| Reason::Unavailable)?;
        Ok(Arc::new(Self {
            plan,
            issuer,
            token,
            expires_at,
            revoked: CancellationToken::new(),
            window: parking_lot::Mutex::new(None),
        }))
    }

    /// 业务作用：连接退出或换代立即取消原会话资格，后台工作持有 Arc 也不能延长授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：之后所有构建与交付门拒绝，真实工作许可仍随工作清理释放。
    pub(super) fn revoke(&self) {
        self.revoked.cancel();
    }

    /// 业务作用：在任何正文或工作容量申请前验真完整命令，并固定不能续期的原会话窗口。
    ///
    /// 参数说明：
    /// - `command`：当前收到的原生命令，共享身份而不复制候选或元数据。
    /// - `signature`：独立只读域的发行者证明。
    ///
    /// 返回：只能由此验签入口构造的验证对象；非法签名、撤销会话或失效期限拒绝。
    pub(super) fn verify(
        self: &Arc<Self>,
        command: Arc<Command>,
        signature: &str,
    ) -> Result<Verified, Reason> {
        if self.revoked.is_cancelled() {
            return Err(Reason::Denied);
        }
        let message = self
            .issuer
            .verify_preview(&command, signature, &self.token)
            .map_err(|_| Reason::Denied)?;
        let window = {
            let mut retained = self.window.lock();
            if let Some((_, window)) = retained.as_ref().filter(|(key, _)| key == &message) {
                window.clone()
            } else {
                let window = Arc::new(
                    Window::preview(command.issued_at_ms, command.expires_at_ms)
                        .map_err(|_| Reason::Expired)?,
                );
                *retained = Some((message.clone(), window.clone()));
                window
            }
        };
        Ok(Verified {
            command,
            message,
            session: self.clone(),
            window,
        })
    }
}

impl Work {
    /// 业务作用：在原文下载前核对独立预览签名并取得节点有界持有名额，不借持久动作受理权。
    ///
    /// 参数说明：
    /// - `state`：当前实际节点与预览容量。
    /// - `verified`：已经绑定原会话和短期窗口的独立验签结果。
    ///
    /// 返回：持有当前快照、期限和真实名额的工作；任何拒绝均不读取候选正文或修改持久状态。
    pub(super) fn accept(state: &AdminState, verified: Verified) -> Result<Arc<Self>, Reason> {
        let permit = state
            .management
            .preview_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Reason::Capacity)?;
        let work = Arc::new(Self {
            command: verified.command,
            message: verified.message,
            active: state.snap.load_full(),
            session: verified.session,
            window: verified.window,
            _permit: permit,
        });
        work.authorize(state)?;
        Ok(work)
    }

    /// 业务作用：在下载、构建与交付边界复验原实例和当前主体，旧签名不能恢复已失去的预览权。
    ///
    /// 参数说明：
    /// - `state`：当前进程唯一管理 owner。
    ///
    /// 返回：会话、原启动、配置实例、当前权限和期限全部成立才成功；失败不得交付差异事实。
    pub(super) fn authorize(&self, state: &AdminState) -> Result<(), Reason> {
        self.window.check().map_err(|_| Reason::Expired)?;
        let current = state.snap.load_full();
        let intent = &self.command.intent;
        // 原目标只能由原启动和原配置提供事实；A→B→A 不恢复旧任务的快照资格。
        if state.management.stopping.is_cancelled()
            || !state.mode.runs_data()
            || !state.ready.load(Ordering::Acquire)
            || self.session.revoked.is_cancelled()
            || super::super::runtime::unix_seconds() >= self.session.expires_at
            || !Arc::ptr_eq(&current, &self.active)
            || !current
                .admin_management
                .as_ref()
                .is_some_and(|plan| Arc::ptr_eq(plan, &self.session.plan))
            || !self.session.plan.previews_enabled
            || self.session.plan.node_id != intent.node
            || state.monitor.boot_id() != intent.boot
            || current.version != intent.version
            || current.config_fingerprint != Some(intent.fingerprint)
            || !current.admin_auth.enabled
            || !current.admin_auth.rbac_enabled
            || current.config_source.nacos.enabled
        {
            return Err(Reason::BaselineChanged);
        }
        let scope = Scope::parse(&intent.scope).ok_or(Reason::Denied)?;
        // 请求者的构建权与创建者的原写权分别复验，原提案不能替任何主体保留撤销前的权限。
        if !super::allows(&current, &intent.scope, &intent.principal, intent.domain)
            || !scope.allows(&current, &intent.creator, intent.domain, Action::Write)
            || scope.authority(&current) != Some(intent.authority)
        {
            return Err(Reason::Denied);
        }
        Ok(())
    }

    /// 业务作用：读取原目标当前持久基线并复验同一配置，不为预览登记动作或占有文件发布方向。
    ///
    /// 参数说明：
    /// - `state`：原节点的唯一持久目录与快照 owner。
    ///
    /// 返回：原 store、代际与三文档摘要仍完全一致时成功；缺失、忙碌、换代或失权拒绝。
    pub(super) async fn baseline(&self, state: &AdminState) -> Result<(), Reason> {
        self.authorize(state)?;
        let observation = state
            .config_history
            .node_observation(self.active.clone())
            .await;
        self.authorize(state)?;
        if observation.baseline.as_ref() != Some(&self.command.intent.baseline) {
            return Err(Reason::BaselineChanged);
        }
        Ok(())
    }
}
