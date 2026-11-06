//! 完整释放后的任务与原两份批准共同回收，任一原幂等收据失败会回滚所有删除。

use crate::admin::operations::{model::Error, Store};
use sqlx::Row;

/// 业务作用：创建、重放和联合回收在锁定父材料之前取得两类节点占位共同屏障，保持统一锁序。
///
/// 参数说明：
/// - `store`：已验证材料执行结构的原存储。
/// - `connection`：已经持有集群与影响owner、复验材料合同的同源事务。
///
/// 返回：共同屏障及已登记的材料域均已锁定时成功；尚未登记的材料域不创建、不重置任何水位。
pub(in crate::admin::operations::certificates) async fn lock(
    store: &Store,
    connection: &mut sqlx::PgConnection,
) -> Result<(), Error> {
    let common = sqlx::query(
        "UPDATE naway_delivery_fence SET watermark=watermark WHERE singleton AND cluster_id=$1",
    )
    .bind(&store.plan.config.cluster_id)
    .execute(&mut *connection)
    .await
    .map_err(|_| Error::Unavailable)?;
    if common.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE naway_material_execution_fence SET watermark=watermark WHERE singleton AND cluster_id=$1")
        .bind(&store.plan.config.cluster_id).execute(connection).await.map_err(|_| Error::Unavailable)?;
    Ok(())
}

/// 业务作用：原父材料已经满足共同保留期限后，清除完整关闭的执行引用以允许同事务回收父子与收据。
///
/// 参数说明：
/// - `store`：原永久集群与数据库owner。
/// - `connection`：已经持有共同屏障和父材料锁的保留事务。
/// - `proposal`：本轮精确选中的原父材料身份。
/// - `cutoff`：数据库当前时钟减去保留期，任务完成时间也必须不晚于此值。
///
/// 返回：无任务或完整任务引用已删除时成功；未释放节点、错分母、残留占位或期限不足保留整笔事务。
pub(in crate::admin::operations::certificates) async fn collect(
    store: &Store,
    connection: &mut sqlx::PgConnection,
    proposal: &str,
    cutoff: i64,
) -> Result<(), Error> {
    let cluster = &store.plan.config.cluster_id;
    let row = sqlx::query("SELECT operation_id,impact_id,state,node_count,updated_at_ms FROM naway_material_execution_tasks WHERE cluster_id=$1 AND proposal_id=$2 FOR UPDATE")
        .bind(cluster).bind(proposal).fetch_optional(&mut *connection).await.map_err(|_| Error::Unavailable)?;
    let Some(row) = row else {
        return Ok(());
    };
    let operation: String = row
        .try_get("operation_id")
        .map_err(|_| Error::Unavailable)?;
    let impact: String = row.try_get("impact_id").map_err(|_| Error::Unavailable)?;
    let count: i16 = row.try_get("node_count").map_err(|_| Error::Unavailable)?;
    if row
        .try_get::<&str, _>("state")
        .map_err(|_| Error::Unavailable)?
        != "complete"
        || row
            .try_get::<i64, _>("updated_at_ms")
            .map_err(|_| Error::Unavailable)?
            > cutoff
    {
        return Err(Error::Conflict);
    }
    let complete: bool = sqlx::query_scalar(concat!(
        "SELECT (SELECT count(*)=$3 AND coalesce(bool_and(released),FALSE) FROM naway_material_execution_nodes WHERE cluster_id=$1 AND operation_id=$2) ",
        "AND NOT EXISTS (SELECT 1 FROM naway_material_execution_slots WHERE cluster_id=$1 AND operation_id=$2)"
    )).bind(cluster).bind(&operation).bind(i64::from(count)).fetch_one(&mut *connection).await.map_err(|_| Error::Unavailable)?;
    if !complete {
        return Err(Error::Conflict);
    }
    for (query, id) in [
        ("UPDATE naway_certificate_proposals SET execution_started=FALSE,updated_at_ms=greatest(updated_at_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE cluster_id=$1 AND id=$2 AND execution_started", proposal),
        ("UPDATE naway_material_impact_proposals SET execution_started=FALSE,updated_at_ms=greatest(updated_at_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE cluster_id=$1 AND id=$2 AND execution_started", impact.as_str()),
    ] {
        // 原complete任务仍存在时才能解除父保留标志；节点、任务、两批准与收据的后续删除必须共同提交。
        if sqlx::query(query).bind(cluster).bind(id).execute(&mut *connection).await.map_err(|_| Error::Unavailable)?.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
    }
    let nodes = sqlx::query("DELETE FROM naway_material_execution_nodes WHERE cluster_id=$1 AND operation_id=$2 AND released")
        .bind(cluster).bind(&operation).execute(&mut *connection).await.map_err(|_| Error::Unavailable)?;
    let task = sqlx::query("DELETE FROM naway_material_execution_tasks WHERE cluster_id=$1 AND operation_id=$2 AND state='complete'")
        .bind(cluster).bind(&operation).execute(connection).await.map_err(|_| Error::Unavailable)?;
    if nodes.rows_affected() != count as u64 || task.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
