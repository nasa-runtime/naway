//! 业务安全终态与节点代际关闭分别确认，全部冻结目标释放之前不归还执行容量。

mod delivery;
mod model;
mod state;

pub(super) use delivery::Cursor;

use super::frozen::Frozen;
use crate::{
    admin::operations::{model::Error, store::DATASOURCE, Store},
    control::actions::release::{Release, Terminal},
};
use sqlx::Row;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Running,
    Releasing,
    Complete,
}

pub(in crate::admin::operations) struct Progress {
    pub(in crate::admin::operations) terminal: Terminal,
    pub(in crate::admin::operations) released: Vec<bool>,
    lifecycle: Lifecycle,
}

impl Store {
    /// 业务作用：在原推进锁内确认完整安全终态并进入释放阶段，不因单个目标缺席改变分母。
    ///
    /// 参数说明：
    /// - frozen：原审批的完整执行，不能使用当前在线目标替代。
    /// - authorize：同快照、同集群及当前双人权限的同步复验。
    ///
    /// 返回：事务明确提交后的完整释放进度；未收敛为空，缺证据、失权或未知提交均不签发释放。
    pub(in crate::admin::operations) async fn prepare_release(
        &self,
        frozen: &Frozen,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<Option<Progress>, Error> {
        self.workflow_transaction(Box::pin(async {
            authorize()?;
            let Some(mut progress) = state::load(self, frozen).await? else {
                authorize()?;
                return Ok(None);
            };
            if progress.lifecycle == Lifecycle::Running {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await
                    .map_err(|_| Error::Unavailable)?;
                // 安全终态先共享提交，之后才可在事务外签发节点关闭；未知 COMMIT 不产生交付权。
                let changed = sqlx::query(concat!(
                    "UPDATE naway_delivery_executions SET state='releasing',",
                    "updated_at_ms=greatest(updated_at_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) ",
                    "WHERE cluster_id=$1 AND operation_id=$2 AND state='running'"
                )).bind(&self.plan.config.cluster_id).bind(&frozen.targets[0].operation_id)
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if changed.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                progress.lifecycle = Lifecycle::Releasing;
            }
            authorize()?;
            Ok(Some(progress))
        })).await
    }

    /// 业务作用：节点精确关闭事实已经确认后，原子标记目标释放并删除原占位，全部目标完成才回收执行容量。
    ///
    /// 参数说明：
    /// - frozen：原审批冻结的完整执行。
    /// - release：本次实际签名并取得节点精确确认的释放声明。
    /// - owner：本进程租约 owner，不从节点确认中读取。
    /// - authorize：复验原快照与当前双方权限，调用者仍持原投递或本机真实许可。
    ///
    /// 返回：事务已明确提交；真表示全部原目标都释放，错终态、过期租约或撤权整体回滚。
    pub(in crate::admin::operations) async fn confirm_target_release(
        &self,
        frozen: &Frozen,
        release: &Release,
        owner: &[u8; 16],
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<bool, Error> {
        release
            .validate(&frozen.definition)
            .map_err(|_| Error::Invalid)?;
        let index = release.intent.target_index as usize;
        if frozen.targets.get(index) != Some(&release.intent) {
            return Err(Error::Conflict);
        }
        self.workflow_transaction(Box::pin(async {
            authorize()?;
            let mut progress = state::load(self, frozen).await?.ok_or(Error::Conflict)?;
            if progress.terminal != release.terminal || progress.lifecycle == Lifecycle::Running {
                return Err(Error::Conflict);
            }
            let intent = &release.intent;
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await
                .map_err(|_| Error::Unavailable)?;
            if !progress.released[index] {
                // 永久行已在完整终态检查中锁定；再锁同意图 slot，旧 owner 不得在新租约之后删除它。
                let slot = sqlx::query(concat!(
                    "SELECT owner,fence,expires_at_ms,",
                    "floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms ",
                    "FROM naway_delivery_slots WHERE cluster_id=$1 AND operation_id=$2 AND node_id=$3 FOR UPDATE"
                )).bind(&self.plan.config.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?
                    .ok_or(Error::Conflict)?;
                if slot.try_get::<Option<&[u8]>, _>("owner").map_err(|_| Error::Unavailable)? != Some(owner.as_slice())
                    || slot.try_get::<i64, _>("fence").map_err(|_| Error::Unavailable)? as u64 != release.delivery.fence
                    || slot.try_get::<i64, _>("expires_at_ms").map_err(|_| Error::Unavailable)?
                        <= slot.try_get::<i64, _>("now_ms").map_err(|_| Error::Unavailable)?
                {
                    return Err(Error::Conflict);
                }
                let updated = sqlx::query("UPDATE naway_delivery_targets SET released=TRUE WHERE cluster_id=$1 AND operation_id=$2 AND node_id=$3 AND NOT released")
                    .bind(&self.plan.config.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                // released 与精确占位删除在同一事务，异常会共同回滚，不能先把新操作放进半释放节点。
                let removed = sqlx::query("DELETE FROM naway_delivery_slots WHERE cluster_id=$1 AND operation_id=$2 AND node_id=$3")
                    .bind(&self.plan.config.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if updated.rows_affected() != 1 || removed.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                progress.released[index] = true;
            }
            let complete = progress.released.iter().all(|closed| *closed);
            if complete && progress.lifecycle != Lifecycle::Complete {
                // 完整原分母都已关闭才释放活动执行预算；数据库触发器再独立检查没有任何残留原槽。
                let updated = sqlx::query(concat!(
                    "UPDATE naway_delivery_executions SET state='complete',",
                    "updated_at_ms=greatest(updated_at_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) ",
                    "WHERE cluster_id=$1 AND operation_id=$2 AND state='releasing'"
                )).bind(&self.plan.config.cluster_id).bind(&intent.operation_id)
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if updated.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
            }
            authorize()?;
            Ok(complete)
        })).await
    }
}
