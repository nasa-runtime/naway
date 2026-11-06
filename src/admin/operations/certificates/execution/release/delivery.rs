//! 释放按原任务与原物理节点轮转，离线目标保留责任但不替换完整分母。

use super::super::authority::{self, Authority};
use crate::{
    admin::{
        management::material_actions::local::Local,
        operations::{model::Error, Store},
        AdminState,
    },
    control::material::execution::release::Release,
};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Default)]
pub(in crate::admin::operations) struct Cursor {
    operation: Option<String>,
    nodes: BTreeMap<String, usize>,
}

impl Cursor {
    /// 业务作用：每轮只关闭一个原材料节点，当前失败也移动有限游标，为其它原任务保留后续机会。
    ///
    /// 参数说明：
    /// - `state`：当前完整控制面与发行者。
    /// - `store`：原共享存储和唯一材料缓存。
    /// - `owner`：本进程稳定材料租约身份。
    ///
    /// 返回：无可释放对象或一次已确认释放时成功；离线、失权、未知结果保持原节点占位。
    pub(in crate::admin::operations) async fn advance(
        &mut self,
        state: &Arc<AdminState>,
        store: &Store,
        owner: &[u8; 16],
    ) -> Result<(), Error> {
        let snapshot = state.snap.load_full();
        let plan = authority::running(state, store, &snapshot)?;
        let ids = store.material_cache.refresh(store).await?;
        self.nodes.retain(|id, _| ids.binary_search(id).is_ok());
        let Some(id) = ids
            .iter()
            .find(|id| {
                self.operation
                    .as_ref()
                    .is_none_or(|previous| *id > previous)
            })
            .or_else(|| ids.first())
        else {
            self.operation = None;
            return Ok(());
        };
        self.operation = Some(id.clone());
        let authority = Authority::continued(state, snapshot.clone());
        let entry = store.material_cache.get(&authority, store, id).await?;
        let frozen = &entry.frozen;
        let authorize = || authority.check(store, frozen, false, None);
        let Some(progress) = store.prepare_material_release(frozen, &authorize).await? else {
            return Ok(());
        };
        let after = self.nodes.get(id).copied().unwrap_or(0);
        let Some(index) = (after..progress.released.len())
            .chain(0..after.min(progress.released.len()))
            .find(|index| !progress.released[*index])
        else {
            return Ok(());
        };
        // 先推进原节点游标再等待网络，无法联系的节点不会占住其它原节点的下轮释放机会。
        self.nodes
            .insert(id.clone(), (index + 1) % progress.released.len());
        let (intent, position) = frozen.node(index)?;
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
        // 释放使用独立材料租约；业务终态和配置域水位都不能替代本次实际接收会话的写权。
        let lease = store
            .acquire_material_lease(intent, position, owner, &authorize)
            .await?;
        let delivery = lease.into_delivery(
            intent,
            position,
            plan.node_id.clone(),
            address.boot,
            address.token,
        )?;
        authorize()?;
        let release = Release {
            schema: 1,
            intent: intent.clone(),
            position,
            definition_digest: frozen.definition.digest(),
            terminal: progress.terminal,
            delivery,
        };
        if let Some(local) = local {
            let received = local
                .release(release.clone())
                .await
                .map_err(|_| Error::Unavailable)?;
            let confirm = || {
                authorize()?;
                received.authorize(state).map_err(|_| Error::Denied)
            };
            store
                .confirm_material_release(frozen, &release, owner, &confirm)
                .await?;
        } else {
            let mut ticket = state
                .management
                .offer_material_release(snapshot, release.clone())
                .map_err(|_| Error::Unavailable)?;
            let received = ticket.receive().await.map_err(|_| Error::Unavailable)?;
            if !received.closed || received.observation.is_some() || received.result.is_some() {
                return Err(Error::Conflict);
            }
            let confirm = || {
                authorize()?;
                ticket.authorize().map_err(|_| Error::Denied)
            };
            store
                .confirm_material_release(frozen, &release, owner, &confirm)
                .await?;
            // 精确released与原slot删除已经共同提交，才解开原节点RPC；ACK丢失只能重放原关闭事实。
            received.confirm();
        }
        Ok(())
    }
}
