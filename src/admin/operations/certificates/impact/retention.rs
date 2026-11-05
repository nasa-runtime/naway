//! 影响与父材料共同保留，关闭审批开关不能留下悬挂引用或丢失原请求的幂等责任。

use super::{Error, Store};
use sqlx::Row;

/// 业务作用：选择父材料之前先锁影响 owner，保留任务遵守与登记和审阅相同的锁序。
///
/// 参数说明：
/// - `store`：已验证实际迁移事实的存储。
/// - `connection`：持有集群行锁的同源事务。
///
/// 返回：已安装时锁定现有 owner；未启用过的 namespace 可以没有 owner，不创建新记录。
pub(in crate::admin::operations::certificates) async fn lock_retention(
    store: &Store,
    connection: &mut sqlx::PgConnection,
) -> Result<(), Error> {
    if !store.material_impact_installed {
        return Ok(());
    }
    let keep: Option<i64> = sqlx::query_scalar(
        "SELECT retain_ms FROM naway_material_impact_owners WHERE cluster_id=$1 FOR UPDATE",
    )
    .bind(&store.plan.config.cluster_id)
    .fetch_optional(connection)
    .await
    .map_err(super::super::database_error)?;
    // 关闭审批时不要求沿用其受理预算，但联合删除必须仍满足同一个不可变保留期限。
    if keep.is_some_and(|keep| keep != i64::from(store.plan.config.retention.retain_seconds) * 1000)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// 业务作用：在父材料删除前精确删除唯一影响记录与完成收据，任何未结束责任都会保留整个事务。
///
/// 参数说明：
/// - `store`：提供已安装合同事实与唯一集群身份。
/// - `connection`：已经锁定集群、影响 owner 和父材料的同源事务。
/// - `proposal`：本轮满足共同保留门的父材料身份。
/// - `epoch`：已提交推进的共享受理代。
///
/// 返回：没有影响或完整父子清理可以继续时成功；旧影响仍处当前代、执行中或收据不符则拒绝。
pub(in crate::admin::operations::certificates) async fn collect(
    store: &Store,
    connection: &mut sqlx::PgConnection,
    proposal: &str,
    epoch: i64,
) -> Result<(), Error> {
    if !store.material_impact_installed {
        return Ok(());
    }
    let cluster = &store.plan.config.cluster_id;
    let row = sqlx::query("SELECT id,scope,creator,client_key,admission_epoch,execution_started FROM naway_material_impact_proposals WHERE cluster_id=$1 AND proposal_id=$2 FOR UPDATE")
        .bind(cluster).bind(proposal).fetch_optional(&mut *connection).await.map_err(super::super::database_error)?;
    let Some(row) = row else {
        return Ok(());
    };
    let parse = || -> Result<_, sqlx::Error> {
        Ok((
            row.try_get::<String, _>("id")?,
            row.try_get::<String, _>("scope")?,
            row.try_get::<String, _>("creator")?,
            row.try_get::<String, _>("client_key")?,
            row.try_get::<i64, _>("admission_epoch")?,
            row.try_get::<bool, _>("execution_started")?,
        ))
    };
    let (id, scope, creator, key, original_epoch, started) =
        parse().map_err(|_| Error::Unavailable)?;
    // 即使父材料已退出自己的原受理代，较晚登记的影响也必须先失去再次新建的资格。
    if started || original_epoch >= epoch {
        return Err(Error::Conflict);
    }
    let receipt = sqlx::query("DELETE FROM idempotency_record_v2 WHERE tenant=$1 AND subject=$2 AND route_id=$3 AND client_key=$4 AND state=1 AND status=201 AND body=$5 AND headers=$6")
        .bind(cluster).bind(creator).bind(super::route(&scope, original_epoch)).bind(key)
        .bind(id.as_bytes()).bind(b"[]".as_slice()).execute(&mut *connection).await.map_err(super::super::database_error)?;
    if receipt.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    let removed = sqlx::query("DELETE FROM naway_material_impact_proposals WHERE cluster_id=$1 AND id=$2 AND NOT execution_started")
        .bind(cluster).bind(id).execute(connection).await.map_err(super::super::database_error)?;
    if removed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
