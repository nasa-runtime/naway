//! 已验真会话、单个真实工作许可与当前本机授权共同约束命令生命周期。

use super::{window::Window, wire};
use crate::{
    admin::{
        management::{issuer::Verifier, protocol, Plan},
        AdminState,
    },
    config::GatewaySnapshot,
    control::{
        actions::{
            authorization::Scope,
            command::{Command, Delivery, Intent},
            definition,
            release::Release,
        },
        ownership::config::Action,
    },
};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

/// 原握手所属的计划与会话；连接 owner 必须在换代或失效时明确撤销。
pub(in crate::admin::management) struct Session {
    plan: Arc<Plan>,
    issuer: Arc<Verifier>,
    pub(super) token: [u8; 32],
    expires_at: u64,
    revoked: CancellationToken,
    window: parking_lot::Mutex<Option<(String, Arc<Window>)>>,
}

/// 容量从下载前起随真实工作单元持有，等待者不能释放已经交给阻塞任务的许可。
pub(in crate::admin) struct Work {
    command: Command,
    admission: Admission,
}

/// 业务命令与终态释放共享进程容量和不可延长的会话权威。
pub(super) struct Admission {
    active: Arc<GatewaySnapshot>,
    session: Arc<Session>,
    window: Arc<Window>,
    _permit: OwnedSemaphorePermit,
}

impl Session {
    /// 业务作用：为已验证的本机全控制面建立独立随机会话，复用同一计划的配对发行身份。
    ///
    /// 参数说明：
    /// - plan：本机入口已经通过角色、当前快照、证书与集群门的精确计划。
    ///
    /// 返回：拥有撤销权的本机会话；未开动作、缺签名身份或随机源不可用时拒绝。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(super) fn local(plan: Arc<Plan>) -> Result<Arc<Self>> {
        ensure!(plan.actions_enabled, "local node actions disabled");
        let receiver = plan
            .receiver
            .as_ref()
            .context("local receiver unavailable")?;
        let issuer = receiver
            .issuer
            .as_ref()
            .context("local issuer unavailable")?;
        let verifier = issuer.local_verifier(&plan.node_id);
        let expires_at = receiver.expires_at;
        let mut token = [0; 32];
        getrandom::getrandom(&mut token).context("local session entropy unavailable")?;
        Ok(Arc::new(Self {
            plan,
            issuer: verifier,
            token,
            expires_at,
            revoked: CancellationToken::new(),
            window: parking_lot::Mutex::new(None),
        }))
    }

    /// 业务作用：在发行者挑战已经通过后固定本连接的信任计划和随机会话，后续命令不能自行选择公钥。
    ///
    /// 参数说明：
    /// - `plan`：握手时实际已发布的管理计划。
    /// - `issuer`：该计划中精确目标的发行者验证器。
    /// - `token`：成功挑战已经绑定的原会话字节。
    ///
    /// 返回：独立可撤销的会话 owner；目标不属于计划或会话长度错误时拒绝。
    pub(in crate::admin::management) fn new(
        plan: Arc<Plan>,
        issuer: Arc<Verifier>,
        token: &[u8],
    ) -> Result<Arc<Self>> {
        let target = plan
            .targets
            .iter()
            .find(|target| {
                target
                    .issuer
                    .as_ref()
                    .is_some_and(|value| Arc::ptr_eq(value, &issuer))
            })
            .context("node action issuer does not belong to this plan")?;
        let expires_at = target.expires_at;
        Ok(Arc::new(Self {
            plan,
            issuer,
            expires_at,
            token: token
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid node action session"))?,
            revoked: CancellationToken::new(),
            window: parking_lot::Mutex::new(None),
        }))
    }

    /// 业务作用：连接或身份换代立即撤销未提交的工作，旧任务持有 Arc 也不能延长原会话写权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：之后所有权限门拒绝；不撤销已经持久的文件恢复方向。
    pub(in crate::admin::management) fn revoke(&self) {
        self.revoked.cancel();
    }
}

impl Work {
    /// 业务作用：在候选分配和下载前验签、取得整个节点唯一真实许可并冻结当前快照，不排队积累命令。
    ///
    /// 参数说明：
    /// - `state`：真实活动快照、监控 boot 与进程级动作容量。
    /// - `session`：本通道已通过发行者挑战且尚未撤销的会话。
    /// - `offer`：本次有界类型化命令，不包含候选正文。
    ///
    /// 返回：原文尚未下载的独占工作权；身份、签名、时钟、权限或容量不符时没有持久副作用。
    pub(in crate::admin::management) fn accept(
        state: &AdminState,
        session: Arc<Session>,
        offer: protocol::ActionOffer,
    ) -> Result<Self> {
        let (command, signature) = wire::decode(offer)?;
        Self::accept_native(state, session, command, &signature)
    }

    /// 业务作用：让本机与网络入口共用完整验签和独占受理门，直接移动中性命令而不转换协议对象。
    ///
    /// 参数说明：
    /// - state：真实活动节点与进程级容量。
    /// - session：当前受信且可撤销的会话。
    /// - command：保持原分配的完整命令，内部调用也必须通过固定定义验证。
    /// - signature：绑定完整命令和本会话的发行者证明。
    ///
    /// 返回：尚未读取候选的真实工作权；验签或授权失败不取得持久业务效果。
    pub(super) fn accept_native(
        state: &AdminState,
        session: Arc<Session>,
        command: Command,
        signature: &str,
    ) -> Result<Self> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let validated =
            session
                .issuer
                .verify_command(&command, signature, &session.token, &definition)?;
        let admission = Admission::claim(state, session, &command.delivery, validated.message())?;
        let work = Self {
            command,
            admission,
        };
        work.authorize(state, false)?;
        Ok(work)
    }

    /// 业务作用：在查询或业务决定前重新验证同一活动实例及本机权限，内容恢复原值不能恢复旧请求资格。
    ///
    /// 参数说明：
    /// - state：当前进程 owner，停止和热更会立即撤销新决定。
    /// - write：真要求创建者写入和审阅者审阅；假只读取双方当前可见的同一领域事实。
    ///
    /// 返回：身份、窗口、计划实例和对应 RBAC 同时成立时成功，否则不得新增持久效果。
    pub(in crate::admin) fn authorize(&self, state: &AdminState, write: bool) -> Result<()> {
        self.admission
            .authorize(state, &self.command.intent, &self.command.delivery, write)
    }

    /// 业务作用：向真实工作单元借用原命令，不能在下载与落盘之间替换意图或投递身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与本许可和签名绑定的不可变命令。
    pub(in crate::admin) fn command(&self) -> &Command {
        &self.command
    }

    /// 业务作用：使用实际受理时的原快照构建候选，最终授权门仍验证该实例未被替换。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：许可生命周期内的原活动快照引用，不从后来快照补齐缺失基线。
    pub(in crate::admin) fn active(&self) -> &GatewaySnapshot {
        &self.admission.active
    }
}

impl Admission {
    /// 业务作用：为已验真的消息取得唯一实际工作容量，并复用同一签名消息首次接受时的单调截止点。
    ///
    /// 参数说明：
    /// - state：提供实际进程容量和当前活动快照的节点。
    /// - session：尚未撤销的原握手会话。
    /// - delivery：同次签名绑定的时间与会话声明。
    /// - message：验签已经确认的规范消息摘要。
    ///
    /// 返回：贯穿实际工作及结果确认的许可；忙碌或期限非法时拒绝，不等待排队。
    fn claim(
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
            .map_err(|_| anyhow::anyhow!("node action worker is busy"))?;
        let window = {
            let mut retained = session.window.lock();
            if let Some((_, window)) = retained
                .as_ref()
                .filter(|(retained, _)| retained == message)
            {
                window.clone()
            } else {
                let window = Arc::new(Window::admit(delivery)?);
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

    /// 业务作用：在查询或业务决定前重新验证同一活动实例及本机权限，内容恢复原值不能恢复旧请求资格。
    ///
    /// 参数说明：
    /// - state：当前进程 owner，停止和热更会立即撤销新决定。
    /// - intent：验签后一直绑定本许可的原意图。
    /// - delivery：同次签名中的接收启动与期限声明。
    /// - write：真要求创建者写入和审阅者审阅；假只读取双方当前可见的同一领域事实。
    ///
    /// 返回：身份、窗口、计划实例和对应 RBAC 同时成立时成功，否则不得新增持久效果。
    pub(super) fn authorize(
        &self,
        state: &AdminState,
        intent: &Intent,
        delivery: &Delivery,
        write: bool,
    ) -> Result<()> {
        self.window.check()?;
        let current = state.snap.load_full();
        // 不能只比较权限摘要；已经发布过其它实例的 A→B→A 仍应撤销旧工作。
        ensure!(
            !state.management.stopping.is_cancelled()
                && state.mode.runs_data()
                && !self.session.revoked.is_cancelled()
                && crate::admin::management::runtime::unix_seconds() < self.session.expires_at
                && Arc::ptr_eq(&current, &self.active)
                && current
                    .admin_management
                    .as_ref()
                    .is_some_and(|plan| Arc::ptr_eq(plan, &self.session.plan))
                && self.session.plan.actions_enabled
                && self.session.plan.node_id == intent.node_id
                && state.monitor.boot_id() == delivery.receiving_boot_id
                && current.admin_auth.enabled
                && current.admin_auth.rbac_enabled
                && !current.config_source.nacos.enabled,
            "node action current authority changed"
        );
        let scope = Scope::parse(&intent.scope).context("node action scope is unavailable")?;
        ensure!(
            scope.allows(
                &current,
                &intent.creator,
                intent.domain,
                if write {
                    Action::Write
                } else {
                    Action::Read
                }
            ) && scope.allows(
                &current,
                &intent.reviewer,
                intent.domain,
                if write {
                    Action::Review
                } else {
                    Action::Read
                }
            ),
            "node action principal authority denied"
        );
        Ok(())
    }

    /// 业务作用：将独立释放签名复验与公共容量绑定，释放不能绕过仍在运行的业务动作。
    ///
    /// 参数说明：
    /// - state：原节点的进程级容量和活动快照。
    /// - session：已经验证发行者身份的当前会话。
    /// - release：有界释放声明。
    /// - signature：同次独立释放域证明。
    ///
    /// 返回：签名、单调窗口和当前写权均成立的独占许可；失败没有文件副作用。
    pub(super) fn release(
        state: &AdminState,
        session: Arc<Session>,
        release: &Release,
        signature: &str,
    ) -> Result<Self> {
        let definition = definition::cached(release.intent.target_count as usize)?;
        let checked =
            session
                .issuer
                .verify_release(release, signature, &session.token, &definition)?;
        let admission = Self::claim(state, session, &release.delivery, &checked.message)?;
        admission.authorize(state, &release.intent, &release.delivery, true)?;
        Ok(admission)
    }
}
