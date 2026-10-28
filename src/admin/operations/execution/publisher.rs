//! 发行端串接原审批、共享租约与真实节点回报，网络发送不能提前确认工作流命令。

use super::{
    authority::{self, Authority},
    cache::Cache,
};
use crate::{
    admin::{
        management::actions::local::Local,
        operations::{
            model::Error,
            workflow::dispatch::{Disposition, Pending},
            Store,
        },
        AdminState,
    },
    control::actions::command::Command,
};
use nasa::outbox::{OutboxEvent, OutboxPublishError, OutboxPublisher};
use std::sync::Arc;

pub(in crate::admin::operations) struct Publisher<'a> {
    pub(in crate::admin::operations) state: &'a Arc<AdminState>,
    pub(in crate::admin::operations) store: &'a Store,
    pub(in crate::admin::operations) owner: &'a [u8; 16],
    pub(in crate::admin::operations) cache: &'a Cache,
}

#[nasa::grpc::async_trait]
impl OutboxPublisher for Publisher<'_> {
    /// 业务作用：只在真实结果事务提交或命令有明确替代证据后确认当前 Outbox，任何未知保持可重投。
    ///
    /// 参数说明：
    /// - event：NASA 本轮领取的原持久命令，不含候选正文。
    ///
    /// 返回：明确停止投递的成功确认；其余失败均保留未知，不因传输错误推测目标未执行。
    async fn publish(&self, event: &OutboxEvent) -> Result<(), OutboxPublishError> {
        Box::pin(self.deliver(event))
            .await
            .map_err(|_| OutboxPublishError::transient("node delivery not confirmed"))
    }
}

impl Publisher<'_> {
    /// 业务作用：按同一原意图取得租约、签发并等待稳定效果，所有数据库事务都与节点工作分离。
    ///
    /// 参数说明：
    /// - event：唯一已领取 Outbox 事件，身份仍须重新验证。
    ///
    /// 返回：NASA 与目标事实已明确提交或原命令已被替代；失败不重选节点、不释放持久目标。
    async fn deliver(&self, event: &OutboxEvent) -> Result<(), Error> {
        let snapshot = self.state.snap.load_full();
        let plan = authority::running(self.state, self.store, &snapshot)?;
        let pending = Pending::decode(event, &self.store.plan.config.cluster_id)?;
        let resolve_compensation = match pending.disposition(self.store).await? {
            Disposition::Retired => {
                // 只读证据不能延长已经关闭的执行运行权，确认过时事件前仍复验原完整快照。
                authority::running(self.state, self.store, &snapshot)?;
                return Ok(());
            }
            Disposition::Deferred => return Err(Error::Unavailable),
            Disposition::Deliver {
                resolve_compensation,
            } => resolve_compensation,
        };
        let frozen = self
            .cache
            .get(self.store, &pending.envelope.saga_id)
            .await?;
        let authority = Authority::continued(self.state, snapshot.clone());
        let authorize = || authority.check(self.store, &frozen, false, None);
        authorize()?;
        let intent = frozen.target(&pending)?;
        let local = if intent.node_id == plan.node_id {
            Some(
                Local::new(
                    self.state.clone(),
                    snapshot.clone(),
                    &intent.baseline.cluster_id,
                )
                .map_err(|_| Error::Unavailable)?,
            )
        } else {
            None
        };
        let address = match &local {
            Some(local) => local.address(),
            None => self
                .state
                .management
                .remote_action_session(&snapshot, intent, false)
                .map_err(|_| Error::Unavailable)?,
        };
        // 只有明确 COMMIT 后的一次性证明可以进入签名；等待节点期间绝不保留数据库连接或推进锁。
        let lease = self
            .store
            .acquire_target_lease(intent, self.owner, &authorize)
            .await?;
        let mut delivery =
            lease.into_delivery(intent, plan.node_id.clone(), address.boot, address.token)?;
        delivery.resolve_compensation = resolve_compensation;
        authorize()?;
        let command = Command {
            schema: 1,
            envelope: pending.envelope.clone(),
            intent: intent.clone(),
            delivery,
        };
        if let Some(local) = local {
            let received = local
                .execute(command, frozen.body.clone())
                .await
                .map_err(|_| Error::Unavailable)?;
            let result = received.result.as_ref().ok_or(Error::Unavailable)?;
            self.store
                .accept_target_result(&pending, &frozen, resolve_compensation, result, &authorize)
                .await?;
            received.authorize(self.state).map_err(|_| Error::Denied)?;
        } else {
            let mut ticket = self
                .state
                .management
                .offer_action(snapshot, command, frozen.body.clone())
                .map_err(|_| Error::Unavailable)?;
            let received = ticket.receive().await.map_err(|_| Error::Unavailable)?;
            let result = received.result.as_ref().ok_or(Error::Unavailable)?;
            self.store
                .accept_target_result(&pending, &frozen, resolve_compensation, result, &authorize)
                .await?;
            // Inbox、实例和目标投影均已确认提交，才允许当前节点 RPC 收到 ACK。
            received.confirm();
        }
        Ok(())
    }
}
