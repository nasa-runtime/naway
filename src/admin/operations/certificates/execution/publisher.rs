//! 材料派发复用唯一Outbox扫描器，完整报告先持久确认，未决事实不提前完成原命令。

use super::authority::{self, Authority};
use crate::{
    admin::{
        management::material_actions::local::Local,
        operations::{
            model::Error,
            workflow::dispatch::{Disposition, Family, Pending},
            Store,
        },
        AdminState,
    },
    control::{
        actions::command::Step,
        journal::MaterialEffect,
        material::execution::{command::Command, report::Observation},
    },
};
use nasa::saga::StepPhase;
use std::sync::Arc;

/// 业务作用：按原完整材料任务取得独立租约，真实本机或mTLS回报与NASA共同提交后才确认交付。
///
/// 参数说明：
/// - `state`：实际发行管理owner。
/// - `store`：原共享存储与唯一任务缓存。
/// - `owner`：本进程稳定租约身份。
/// - `pending`：唯一扫描器已经验证的原Outbox身份。
///
/// 返回：稳定结果已提交或原命令有明确替代证据时成功；Pending只确认报告，不确认Outbox完成。
pub(in crate::admin::operations) async fn deliver(
    state: &Arc<AdminState>,
    store: &Store,
    owner: &[u8; 16],
    pending: &Pending,
) -> Result<(), Error> {
    if pending.family != Family::Material {
        return Err(Error::Invalid);
    }
    let snapshot = state.snap.load_full();
    let plan = authority::running(state, store, &snapshot)?;
    let resolve_compensation = match pending.disposition(store).await? {
        Disposition::Retired => {
            // 过时证据只能撤下原命令；当前独立材料运行权失效后仍不得确认共享队列。
            authority::running(state, store, &snapshot)?;
            return Ok(());
        }
        Disposition::Deferred => return Err(Error::Unavailable),
        Disposition::Deliver {
            resolve_compensation,
        } => resolve_compensation,
    };
    let authority = Authority::continued(state, snapshot.clone());
    let entry = store
        .material_cache
        .get(&authority, store, &pending.envelope.saga_id)
        .await?;
    let frozen = &entry.frozen;
    let authorize = || authority.check(store, frozen, false, None);
    authorize()?;
    let (intent, position) = frozen.target(pending)?;
    let content = if pending.step == Step::Prepare && pending.identity.phase == StepPhase::Execute {
        // 认证解密先于领取有限租约；其它方向从原节点责任恢复，不向旧钥借补偿或释放资格。
        Some(
            entry
                .content(&store.material_cache, &authority, store)
                .await?,
        )
    } else {
        None
    };
    let local = if intent.node_id == plan.node_id {
        Some(
            Local::new(state.clone(), snapshot.clone(), &intent.baseline.cluster_id)
                .map_err(|_| Error::Unavailable)?,
        )
    } else {
        None
    };
    let address = match &local {
        Some(local) => local.address(),
        None => state
            .management
            .remote_material_action_session(&snapshot, intent, false)
            .map_err(|_| Error::Unavailable)?,
    };
    // 已知COMMIT的一次性材料证明才可进入签名；网络等待不持有数据库连接或推进锁。
    let lease = store
        .acquire_material_lease(intent, position, owner, &authorize)
        .await?;
    let mut delivery = lease.into_delivery(
        intent,
        position,
        plan.node_id.clone(),
        address.boot,
        address.token,
    )?;
    delivery.resolve_compensation = resolve_compensation;
    authorize()?;
    let command = Command {
        schema: 1,
        envelope: pending.envelope.clone(),
        intent: intent.clone(),
        position,
        delivery,
    };
    let stable = if let Some(local) = local {
        let received = local
            .execute(command.clone(), content)
            .await
            .map_err(|_| Error::Unavailable)?;
        let facts = match &received.outcome {
            MaterialEffect::Pending(facts)
            | MaterialEffect::Stable {
                facts,
                ..
            } => facts,
            // 空槽和关闭只有当前读取含义，不能伪造历史业务结果填入共享工作流。
            MaterialEffect::Vacant | MaterialEffect::Closed => return Err(Error::Unavailable),
        };
        let report = facts.report().map_err(|_| Error::Conflict)?;
        let confirm = || {
            authorize()?;
            received.authorize(state).map_err(|_| Error::Denied)
        };
        store
            .accept_material_report(frozen, &command, &report, owner, &confirm)
            .await?
    } else {
        let mut ticket = state
            .management
            .offer_material_action(snapshot, command.clone(), content)
            .map_err(|_| Error::Unavailable)?;
        let received = ticket.receive().await.map_err(|_| Error::Unavailable)?;
        let Some(Observation::Report(report)) = &received.observation else {
            return Err(Error::Unavailable);
        };
        let confirm = || {
            authorize()?;
            ticket.authorize().map_err(|_| Error::Denied)
        };
        let stable = store
            .accept_material_report(frozen, &command, report, owner, &confirm)
            .await?;
        // 完整报告已明确提交并再次确认真实Ticket才ACK；Pending没有NASA稳定结论，原Outbox继续保留。
        received.confirm();
        stable
    };
    if stable {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}
