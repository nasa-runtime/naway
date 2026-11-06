//! 原任务、全部节点报告和NASA安全终态在同一推进事务核对，缺项保留全部责任。

use super::{evidence, Lifecycle, Progress};
use crate::{
    admin::operations::{
        certificates::execution::frozen::Frozen, model::Error, store::DATASOURCE,
        workflow::completion, Store,
    },
    control::material::execution::{release::Terminal, report::Report},
};
use nasa::saga::SagaId;
use nasaga_backend::SagaBackend;
use sqlx::Row;

/// 业务作用：共同锁序下重新证明原材料任务安全终态和全部物理节点责任，单个节点成功不能缩减释放分母。
///
/// 参数说明：
/// - `store`：当前已持有共享推进事务的原集群owner。
/// - `frozen`：完整原批准及独立材料定义。
///
/// 返回：完整安全终态的原释放进度；未收敛为空，错身份、缺步骤、报告或占位异常均拒绝。
pub(super) async fn load(store: &Store, frozen: &Frozen) -> Result<Option<Progress>, Error> {
    let first = frozen.nodes.first().ok_or(Error::Conflict)?;
    if first.baseline.cluster_id != store.plan.config.cluster_id {
        return Err(Error::Conflict);
    }
    let saga = SagaId::new(&first.operation_id).map_err(|_| Error::Invalid)?;
    let backend = nasa::saga::pgsql::PgSagaBackend::with_datasource(DATASOURCE)
        .map_err(|_| Error::Unavailable)?;
    let instance = backend
        .store()
        .load_instance(&saga)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    let steps = backend
        .store()
        .load_steps(&saga)
        .await
        .map_err(|_| Error::Unavailable)?;
    let Some(terminal) = completion::terminal(
        &frozen.definition,
        &first.operation_id,
        &first.baseline.cluster_id,
        &instance,
        &steps,
    )?
    else {
        return Ok(None);
    };
    let terminal = match terminal {
        completion::Terminal::Completed => Terminal::Completed,
        completion::Terminal::Compensated => Terminal::Compensated,
    };
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    // 与材料租约保持共同配置屏障、独立材料水位、任务及节点的锁序，不能在接管之间删除原占位。
    let common = sqlx::query(
        "UPDATE naway_delivery_fence SET watermark=watermark WHERE singleton AND cluster_id=$1",
    )
    .bind(&store.plan.config.cluster_id)
    .execute(connection.as_mut())
    .await
    .map_err(|_| Error::Unavailable)?;
    let material = sqlx::query("UPDATE naway_material_execution_fence SET watermark=watermark WHERE singleton AND cluster_id=$1 AND store_id=$2")
        .bind(&store.plan.config.cluster_id).bind(&first.execution_store).execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
    if common.rows_affected() != 1 || material.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    let row = sqlx::query("SELECT state,terminal,execution_store,proposal_id,impact_id,target_count,node_count,definition_digest FROM naway_material_execution_tasks WHERE cluster_id=$1 AND operation_id=$2 FOR UPDATE")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id).fetch_optional(connection.as_mut()).await
        .map_err(|_| Error::Unavailable)?.ok_or(Error::Missing)?;
    let lifecycle = match row
        .try_get::<&str, _>("state")
        .map_err(|_| Error::Unavailable)?
    {
        "running" => Lifecycle::Running,
        "releasing" => Lifecycle::Releasing,
        "complete" => Lifecycle::Complete,
        "halted" => return Ok(None),
        _ => return Err(Error::Unavailable),
    };
    if row
        .try_get::<&str, _>("execution_store")
        .map_err(|_| Error::Unavailable)?
        != first.execution_store
        || row
            .try_get::<&str, _>("proposal_id")
            .map_err(|_| Error::Unavailable)?
            != first.proposal_id
        || row
            .try_get::<&str, _>("impact_id")
            .map_err(|_| Error::Unavailable)?
            != first.impact_id
        || row
            .try_get::<i16, _>("target_count")
            .map_err(|_| Error::Unavailable)? as u32
            != first.target_count
        || row
            .try_get::<i16, _>("node_count")
            .map_err(|_| Error::Unavailable)? as usize
            != frozen.nodes.len()
        || row
            .try_get::<&str, _>("definition_digest")
            .map_err(|_| Error::Unavailable)?
            != frozen.definition.digest()
        || row
            .try_get::<Option<&str>, _>("terminal")
            .map_err(|_| Error::Unavailable)?
            != (lifecycle != Lifecycle::Running).then_some(super::name(terminal))
    {
        return Err(Error::Conflict);
    }
    let rows = sqlx::query(concat!(
        "SELECT n.node_id,n.node_index,n.intent_digest,n.store_id,n.node_epoch::text AS epoch,",
        "n.report,n.report_revision::text AS revision,n.released,s.operation_id AS slot_operation ",
        "FROM naway_material_execution_nodes n LEFT JOIN naway_material_execution_slots s ",
        "ON s.cluster_id=n.cluster_id AND s.operation_id=n.operation_id AND s.node_id=n.node_id ",
        "WHERE n.cluster_id=$1 AND n.operation_id=$2 ORDER BY n.node_index LIMIT 129 FOR UPDATE OF n"
    )).bind(&store.plan.config.cluster_id).bind(&first.operation_id).fetch_all(connection.as_mut())
        .await.map_err(|_| Error::Unavailable)?;
    if rows.len() != frozen.nodes.len() {
        return Err(Error::Conflict);
    }
    let mut released = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let (intent, position) = frozen.node(index)?;
        if row
            .try_get::<&str, _>("node_id")
            .map_err(|_| Error::Unavailable)?
            != intent.node_id
            || row
                .try_get::<i16, _>("node_index")
                .map_err(|_| Error::Unavailable)? as usize
                != index
            || row
                .try_get::<&[u8], _>("intent_digest")
                .map_err(|_| Error::Unavailable)?
                != position.fingerprint(intent).map_err(|_| Error::Conflict)?
            || row
                .try_get::<&str, _>("store_id")
                .map_err(|_| Error::Unavailable)?
                != intent.baseline.store_id
            || row
                .try_get::<&str, _>("epoch")
                .map_err(|_| Error::Unavailable)?
                != intent.baseline.node_admission_epoch
        {
            return Err(Error::Conflict);
        }
        let report = row
            .try_get::<Option<&[u8]>, _>("report")
            .map_err(|_| Error::Unavailable)?
            .map(|bytes| serde_json::from_slice::<Report>(bytes).map_err(|_| Error::Unavailable))
            .transpose()?;
        let revision: Option<String> = row.try_get("revision").map_err(|_| Error::Unavailable)?;
        if revision != report.as_ref().map(|report| report.revision.to_string()) {
            return Err(Error::Conflict);
        }
        evidence::validate(
            intent,
            position,
            terminal,
            report.as_ref(),
            &steps[index],
            &steps[frozen.nodes.len() + index],
        )?;
        let closed: bool = row.try_get("released").map_err(|_| Error::Unavailable)?;
        let slot: Option<&str> = row
            .try_get("slot_operation")
            .map_err(|_| Error::Unavailable)?;
        // 已关闭节点可被后来任务使用，原任务自己的占位必须消失；缺席不能被推成已经关闭。
        if closed == slot.is_some()
            || (!closed && slot != Some(first.operation_id.as_str()))
            || (closed && lifecycle == Lifecycle::Running)
        {
            return Err(Error::Conflict);
        }
        released.push(closed);
    }
    if lifecycle == Lifecycle::Complete && released.iter().any(|closed| !closed) {
        return Err(Error::Conflict);
    }
    Ok(Some(Progress {
        terminal,
        released,
        lifecycle,
    }))
}
