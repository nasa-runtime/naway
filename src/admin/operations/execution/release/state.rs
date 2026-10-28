//! 在同一推进事务读取完整目标及 NASA 事实，并按租约既定锁顺序核对占位。

use super::{model, Lifecycle, Progress};
use crate::admin::operations::{execution::frozen::Frozen, model::Error, store::DATASOURCE, Store};
use nasa::saga::SagaId;
use nasaga_backend::SagaBackend;
use sqlx::Row;

/// 业务作用：复验原工作流终态与全部目标投影，再取得精确释放状态；任何缺项都保留原占位。
///
/// 参数说明：
/// - store：持有共享推进事务的原集群 owner。
/// - frozen：原审批冻结的完整执行。
///
/// 返回：已证安全终态的完整释放分母；未收敛为空，身份或投影矛盾拒绝，不产生节点动作。
pub(super) async fn load(store: &Store, frozen: &Frozen) -> Result<Option<Progress>, Error> {
    let first = frozen.targets.first().ok_or(Error::Unavailable)?;
    if first.baseline.cluster_id != store.plan.config.cluster_id {
        return Err(Error::Conflict);
    }
    let saga = SagaId::new(&first.operation_id).map_err(|_| Error::Unavailable)?;
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
    let Some(terminal) = model::terminal(frozen, &instance, &steps)? else {
        return Ok(None);
    };
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    // 和 acquire 一样先锁永久权威，再读执行和目标；不能让接管租约与删除占位交错提交。
    let locked = sqlx::query(
        "UPDATE naway_delivery_fence SET watermark=watermark WHERE singleton AND cluster_id=$1",
    )
    .bind(&store.plan.config.cluster_id)
    .execute(connection.as_mut())
    .await
    .map_err(|_| Error::Unavailable)?;
    if locked.rows_affected() != 1 {
        return Err(Error::Unavailable);
    }
    let row = sqlx::query("SELECT state,target_count,definition_digest FROM naway_delivery_executions WHERE cluster_id=$1 AND operation_id=$2 FOR UPDATE")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id)
        .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Missing)?;
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
        .try_get::<i16, _>("target_count")
        .map_err(|_| Error::Unavailable)? as usize
        != frozen.targets.len()
        || row
            .try_get::<&str, _>("definition_digest")
            .map_err(|_| Error::Unavailable)?
            != frozen.definition.digest()
    {
        return Err(Error::Unavailable);
    }
    let rows = sqlx::query(concat!(
        "SELECT t.node_id,t.target_index,t.intent_digest,t.store_id,t.node_epoch::text AS epoch,",
        "t.prepare_outcome,t.apply_outcome,t.prepare_compensation,t.apply_compensation,t.released,",
        "s.operation_id AS slot_operation FROM naway_delivery_targets t LEFT JOIN naway_delivery_slots s ",
        "ON s.cluster_id=t.cluster_id AND s.operation_id=t.operation_id AND s.node_id=t.node_id ",
        "WHERE t.cluster_id=$1 AND t.operation_id=$2 ORDER BY t.target_index LIMIT 129"
    )).bind(&store.plan.config.cluster_id).bind(&first.operation_id)
        .fetch_all(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
    if rows.len() != frozen.targets.len() {
        return Err(Error::Unavailable);
    }
    let mut released = Vec::with_capacity(rows.len());
    for (index, (row, intent)) in rows.iter().zip(&frozen.targets).enumerate() {
        let digest = intent.fingerprint().map_err(|_| Error::Unavailable)?;
        if row
            .try_get::<&str, _>("node_id")
            .map_err(|_| Error::Unavailable)?
            != intent.node_id
            || row
                .try_get::<i16, _>("target_index")
                .map_err(|_| Error::Unavailable)? as usize
                != index
            || row
                .try_get::<&[u8], _>("intent_digest")
                .map_err(|_| Error::Unavailable)?
                != digest
            || row
                .try_get::<&str, _>("store_id")
                .map_err(|_| Error::Unavailable)?
                != intent.baseline.store_id
            || row
                .try_get::<&str, _>("epoch")
                .map_err(|_| Error::Unavailable)?
                != intent.baseline.node_admission_epoch
        {
            return Err(Error::Unavailable);
        }
        let expected = [
            model::forward(&steps[index])?,
            model::forward(&steps[frozen.targets.len() + index])?,
            model::compensation(&steps[index])?,
            model::compensation(&steps[frozen.targets.len() + index])?,
        ];
        for (name, expected) in [
            "prepare_outcome",
            "apply_outcome",
            "prepare_compensation",
            "apply_compensation",
        ]
        .into_iter()
        .zip(expected)
        {
            if row
                .try_get::<Option<&str>, _>(name)
                .map_err(|_| Error::Unavailable)?
                != expected
            {
                return Err(Error::Unavailable);
            }
        }
        let closed: bool = row.try_get("released").map_err(|_| Error::Unavailable)?;
        let slot: Option<&str> = row
            .try_get("slot_operation")
            .map_err(|_| Error::Unavailable)?;
        // 已释放目标可能已有后来操作，但旧操作自己的槽必须精确消失；未释放目标必须仍占有原槽。
        if closed == slot.is_some()
            || (!closed && slot != Some(first.operation_id.as_str()))
            || (closed && lifecycle == Lifecycle::Running)
        {
            return Err(Error::Unavailable);
        }
        released.push(closed);
    }
    if lifecycle == Lifecycle::Complete && released.iter().any(|closed| !closed) {
        return Err(Error::Unavailable);
    }
    Ok(Some(Progress {
        terminal,
        released,
        lifecycle,
    }))
}
