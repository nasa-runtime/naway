//! 材料回收只删除已经关闭原受理代且没有交付责任的精确记录。

use super::{Error, Store};
use sqlx::Row;

/// 业务作用：与原提案清理共用已持有的集群权威，原收据与密文必须在同一事务内一起删除。
///
/// 参数说明：
/// - `store`：独立材料功能开关和冻结保留资源。
/// - `connection`：已有集群锁的同源物理事务。
/// - `epoch`：已提交推进到的当前受理代。
/// - `cutoff`：数据库时钟减去共同保留期的截止值。
/// - `limit`：本轮剩余删除名额。
///
/// 返回：原收据匹配且无执行责任的删除数量；关闭时不访问材料表，失败整批回滚。
pub(in crate::admin::operations) async fn collect(
    store: &Store,
    connection: &mut sqlx::PgConnection,
    epoch: i64,
    cutoff: i64,
    limit: usize,
) -> Result<usize, Error> {
    if !store.plan.config.certificates.enabled || limit == 0 {
        return Ok(0);
    }
    super::capacity::owner(connection, store).await?;
    super::impact::lock_retention(store, connection).await?;
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    if store.material_execution_installed {
        super::execution::retention::lock(store, connection).await?;
    }
    let cluster = &store.plan.config.cluster_id;
    let query = if cfg!(all(
        feature = "node-actions",
        feature = "admin-operations-workflow-pgsql"
    )) && store.material_execution_installed
    {
        "SELECT p.id,p.scope,p.creator,p.client_key,p.admission_epoch FROM naway_certificate_proposals p WHERE p.cluster_id=$1 AND p.admission_epoch < $2 AND (CASE WHEN p.state IN ('rejected','cancelled') THEN p.updated_at_ms ELSE p.expires_at_ms END) <= $3 AND (NOT p.execution_started OR EXISTS (SELECT 1 FROM naway_material_execution_tasks t WHERE t.cluster_id=p.cluster_id AND t.proposal_id=p.id AND t.state='complete' AND t.impact_epoch < $2 AND t.updated_at_ms <= $3)) ORDER BY p.id LIMIT $4 FOR UPDATE OF p"
    } else {
        "SELECT id,scope,creator,client_key,admission_epoch FROM naway_certificate_proposals WHERE cluster_id=$1 AND NOT execution_started AND admission_epoch < $2 AND (CASE WHEN state IN ('rejected','cancelled') THEN updated_at_ms ELSE expires_at_ms END) <= $3 ORDER BY id LIMIT $4 FOR UPDATE"
    };
    let rows = sqlx::query(query)
        .bind(cluster)
        .bind(epoch)
        .bind(cutoff)
        .bind(limit as i64)
        .fetch_all(&mut *connection)
        .await
        .map_err(super::database_error)?;
    for row in &rows {
        let id: String = row.try_get("id").map_err(|_| Error::Unavailable)?;
        let scope: String = row.try_get("scope").map_err(|_| Error::Unavailable)?;
        let creator: String = row.try_get("creator").map_err(|_| Error::Unavailable)?;
        let key: String = row.try_get("client_key").map_err(|_| Error::Unavailable)?;
        let original_epoch: i64 = row
            .try_get("admission_epoch")
            .map_err(|_| Error::Unavailable)?;
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        if store.material_execution_installed {
            super::execution::retention::collect(store, connection, &id, cutoff).await?;
        }
        // 子影响及其原收据先于父材料释放，任一子责任未结束会回滚整批，避免留下孤立批准。
        super::impact::collect(store, connection, &id, epoch).await?;
        // 精确原收据缺失或仍在途时保留整份密文，不用清理重置尚未解决的结果未知。
        let receipt = sqlx::query("DELETE FROM idempotency_record_v2 WHERE tenant=$1 AND subject=$2 AND route_id=$3 AND client_key=$4 AND state=1 AND status=201 AND body=$5 AND headers=$6")
            .bind(cluster).bind(creator).bind(super::route(&scope, original_epoch)).bind(key).bind(id.as_bytes()).bind(b"[]".as_slice())
            .execute(&mut *connection).await.map_err(super::database_error)?;
        if receipt.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        let proposal = sqlx::query("DELETE FROM naway_certificate_proposals WHERE cluster_id=$1 AND id=$2 AND NOT execution_started")
            .bind(cluster).bind(id).execute(&mut *connection).await.map_err(super::database_error)?;
        if proposal.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
    }
    Ok(rows.len())
}
