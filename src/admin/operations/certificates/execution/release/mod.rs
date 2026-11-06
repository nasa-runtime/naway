//! 材料终态、节点实际关闭和共同保留回收分别提交，全部原节点关闭之前不释放共享容量。

mod delivery;
pub(super) mod evidence;
mod state;

use super::frozen::Frozen;
use crate::{
    admin::operations::{model::Error, store::DATASOURCE, Store},
    control::material::execution::release::{Release, Terminal},
};
pub(in crate::admin::operations) use delivery::Cursor;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Running,
    Releasing,
    Complete,
}

pub(in crate::admin::operations) struct Progress {
    pub terminal: Terminal,
    pub released: Vec<bool>,
    lifecycle: Lifecycle,
}

impl Store {
    /// 业务作用：在原推进事务中证明全部材料步骤和节点报告安全收敛，明确提交释放阶段后才允许节点清理。
    ///
    /// 参数说明：
    /// - `frozen`：原两份批准和完整节点集合。
    /// - `authorize`：复验当前快照、四主体和完整原影响。
    ///
    /// 返回：已提交的完整释放进度；尚未收敛为空，任何未知或撤权不签发释放。
    pub(in crate::admin::operations) async fn prepare_material_release(
        &self,
        frozen: &Frozen,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<Option<Progress>, Error> {
        let progress = self.workflow_transaction(Box::pin(async {
            authorize()?;
            let Some(mut progress) = state::load(self, frozen).await? else {
                authorize()?;
                return Ok(None);
            };
            if progress.lifecycle == Lifecycle::Running {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
                // 共享安全终态先明确提交，外部节点关闭随后执行；结果未知不能被解释为尚未开始清理。
                let changed = sqlx::query("UPDATE naway_material_execution_tasks SET state='releasing',terminal=$3,updated_at_ms=greatest(updated_at_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE cluster_id=$1 AND operation_id=$2 AND state='running'")
                    .bind(&self.plan.config.cluster_id).bind(&frozen.nodes[0].operation_id).bind(name(progress.terminal))
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if changed.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                progress.lifecycle = Lifecycle::Releasing;
            }
            authorize()?;
            Ok(Some(progress))
        })).await?;
        authorize()?;
        Ok(progress)
    }

    /// 业务作用：真实节点已同步关闭原材料代际后，原子删除精确占位并保留完整历史报告和父批准。
    ///
    /// 参数说明：
    /// - `frozen`：原完整任务。
    /// - `release`：本轮实际签名并获节点确认的独立释放请求。
    /// - `owner`：实际领取原材料租约的发行进程。
    /// - `authorize`：同时复验当前全批权威和真实Ticket或本机关闭许可。
    ///
    /// 返回：已知提交后的全批关闭标志；原终态、owner、fence或窗口不符使整个确认回滚。
    pub(in crate::admin::operations) async fn confirm_material_release(
        &self,
        frozen: &Frozen,
        release: &Release,
        owner: &[u8; 16],
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<bool, Error> {
        release.validate().map_err(|_| Error::Invalid)?;
        let index = release.position.index as usize;
        let (intent, position) = frozen.node(index)?;
        if !Arc::ptr_eq(intent, &release.intent) || position != release.position {
            return Err(Error::Conflict);
        }
        let complete = self.workflow_transaction(Box::pin(async {
            authorize()?;
            let mut progress = state::load(self, frozen).await?.ok_or(Error::Conflict)?;
            if progress.terminal != release.terminal || progress.lifecycle == Lifecycle::Running {
                return Err(Error::Conflict);
            }
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
            if !progress.released[index] {
                // 共同水位屏障仍持有；只允许当前未过期owner/fence删除自己的占位，旧会话不能释放接管者。
                let changed = sqlx::query(concat!(
                    "UPDATE naway_material_execution_nodes n SET released=TRUE WHERE n.cluster_id=$1 AND n.operation_id=$2 AND n.node_id=$3 AND NOT n.released ",
                    "AND EXISTS (SELECT 1 FROM naway_material_execution_slots s WHERE s.cluster_id=n.cluster_id AND s.operation_id=n.operation_id AND s.node_id=n.node_id ",
                    "AND s.owner=$4 AND s.fence=$5 AND s.expires_at_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint)"
                )).bind(&self.plan.config.cluster_id).bind(&intent.operation_id).bind(&intent.node_id).bind(owner.as_slice())
                    .bind(release.delivery.fence as i64).execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                let removed = sqlx::query("DELETE FROM naway_material_execution_slots WHERE cluster_id=$1 AND operation_id=$2 AND node_id=$3")
                    .bind(&self.plan.config.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if changed.rows_affected() != 1 || removed.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                progress.released[index] = true;
            }
            let complete = progress.released.iter().all(|closed| *closed);
            if complete && progress.lifecycle != Lifecycle::Complete {
                // 所有原物理节点都关闭才归还活动任务预算；两份父批准仍由共同保留回收承担，不提前丢失原身份。
                let changed = sqlx::query("UPDATE naway_material_execution_tasks SET state='complete',updated_at_ms=greatest(updated_at_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE cluster_id=$1 AND operation_id=$2 AND state='releasing'")
                    .bind(&self.plan.config.cluster_id).bind(&intent.operation_id).execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                if changed.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
            }
            authorize()?;
            Ok(complete)
        })).await?;
        authorize()?;
        Ok(complete)
    }
}

/// 业务作用：将已证材料安全终态编码为独立持久字段，不接受客户端自报状态。
///
/// 参数说明：
/// - `terminal`：全部NASA步骤和节点证据已经共同确认的有限终态。
///
/// 返回：原材料表声明的规范名称，不能借配置释放签名直接使用。
pub(super) fn name(terminal: Terminal) -> &'static str {
    match terminal {
        Terminal::Completed => "completed",
        Terminal::Compensated => "compensated",
    }
}
