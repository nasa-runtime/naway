//! 原执行与目标按有限游标轮转，离线成员保留占位且不独占其它终态的释放机会。

use super::super::{
    authority::{self, Authority},
    cache::Cache,
};
use crate::{
    admin::{
        management::actions::local::Local,
        operations::{model::Error, Store},
        AdminState,
    },
    control::actions::release::Release,
};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Default)]
pub(in crate::admin::operations) struct Cursor {
    operation: Option<String>,
    targets: BTreeMap<String, usize>,
}

impl Cursor {
    /// 业务作用：每轮最多关闭一个原目标，失联或拒绝后仍继续轮转其它执行及原目标。
    ///
    /// 参数说明：
    /// - state：当前完整控制面及停止权。
    /// - store：同一共享数据库 owner。
    /// - owner：本进程固定随机租约身份。
    /// - cache：派发和释放共享的有限原候选缓存。
    ///
    /// 返回：本轮无可释放目标或该目标已明确确认时成功；其它失败保留原集合与下一次轮转位置。
    pub(in crate::admin::operations) async fn advance(
        &mut self,
        state: &Arc<AdminState>,
        store: &Store,
        owner: &[u8; 16],
        cache: &Cache,
    ) -> Result<(), Error> {
        let snapshot = state.snap.load_full();
        let plan = authority::running(state, store, &snapshot)?;
        let ids = cache.refresh(store).await?;
        self.targets.retain(|id, _| ids.binary_search(id).is_ok());
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
        // 先推进有界游标再等待该执行，失联或未收敛不会永远占据第一个身份。
        self.operation = Some(id.clone());
        let frozen = cache.get(store, id).await?;
        let authority = Authority::continued(state, snapshot.clone());
        let authorize = || authority.check(store, &frozen, false, None);
        authorize()?;
        let Some(progress) = store.prepare_release(&frozen, &authorize).await? else {
            return Ok(());
        };
        let after = self.targets.get(id).copied().unwrap_or(0);
        let index = (after..progress.released.len())
            .chain(0..after.min(progress.released.len()))
            .find(|index| !progress.released[*index]);
        let Some(index) = index else {
            return Ok(());
        };
        self.targets
            .insert(id.clone(), (index + 1) % progress.released.len());
        let intent = &frozen.targets[index];
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
                .remote_action_session(&snapshot, intent, false)
                .map_err(|_| Error::Unavailable)?,
        };
        let lease = store
            .acquire_target_lease(intent, owner, &authorize)
            .await?;
        let delivery =
            lease.into_delivery(intent, plan.node_id.clone(), address.boot, address.token)?;
        authorize()?;
        let release = Release {
            schema: 1,
            intent: intent.clone(),
            definition_digest: frozen.definition.digest().to_owned(),
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
                .confirm_target_release(&frozen, &release, owner, &confirm)
                .await?;
            received.authorize(state).map_err(|_| Error::Denied)?;
        } else {
            let mut ticket = state
                .management
                .offer_release(snapshot, release.clone())
                .map_err(|_| Error::Unavailable)?;
            let received = ticket.receive().await.map_err(|_| Error::Unavailable)?;
            if !received.closed || received.result.is_some() {
                return Err(Error::Invalid);
            }
            let confirm = || {
                authorize()?;
                ticket.authorize().map_err(|_| Error::Denied)
            };
            store
                .confirm_target_release(&frozen, &release, owner, &confirm)
                .await?;
            // 原目标 released 和精确 slot 删除明确共同提交后，才解除节点 RPC 的确认等待。
            received.confirm();
        }
        Ok(())
    }
}
