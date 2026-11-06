//! 材料执行拥有独立永久存储身份，登记身份本身不开放节点动作。

use crate::admin::operations::{
    model::{hex, Error},
    store::DATASOURCE,
    Store,
};
use sqlx::Row;

/// 业务作用：在两份批准存储与工作流资源成立后登记独立材料执行域，重启不能更换身份或清空水位。
///
/// 参数说明：
/// - `store`：通过结构门并已登记材料和影响 owner 的唯一共享存储。
///
/// 返回：保留原身份或明确提交首次登记；前置资源未启用时不创建身份，已要求执行而缺迁移时拒绝。
pub(in crate::admin::operations) async fn register(store: &Store) -> Result<(), Error> {
    let config = &store.plan.config.certificates;
    if !config.enabled || !config.impact_approvals.enabled || !store.plan.config.workflow.enabled {
        return Ok(());
    }
    if !store.material_execution_installed {
        return if config.execution.enabled {
            Err(Error::Unavailable)
        } else {
            Ok(())
        };
    }
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
    let identity = hex(&random);
    store.transaction(Box::pin(async {
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
            .await.map_err(|_| Error::Unavailable)?;
        // 原影响 owner 已独立登记，永久绑定触发器复验 schema 集群；冲突只回读原身份，不重置水位。
        sqlx::query("INSERT INTO naway_material_execution_fence(singleton,cluster_id,store_id,watermark) VALUES(TRUE,$1,$2,0) ON CONFLICT (singleton) DO NOTHING")
            .bind(&store.plan.config.cluster_id).bind(&identity)
            .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
        identity_in(connection.as_mut(), store).await.map(|_| ())
    })).await
}

/// 业务作用：在任务创建事务内读取材料独立执行身份，不让配置水位或当前随机值替代原持久权威。
///
/// 参数说明：
/// - `connection`：当前共享事务的数据库连接。
/// - `store`：冻结了原集群的资源 owner。
///
/// 返回：经过结构检查的永久身份；缺席、异集群或水位非法时封闭材料任务创建。
pub(super) async fn identity_in(
    connection: &mut sqlx::PgConnection,
    store: &Store,
) -> Result<String, Error> {
    let row = sqlx::query("SELECT store_id,watermark FROM naway_material_execution_fence WHERE singleton AND cluster_id=$1")
        .bind(&store.plan.config.cluster_id).fetch_optional(connection).await
        .map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
    let identity: String = row.try_get("store_id").map_err(|_| Error::Unavailable)?;
    let watermark: i64 = row.try_get("watermark").map_err(|_| Error::Unavailable)?;
    if !crate::control::material::node::hexadecimal(&identity, 64) || watermark < 0 {
        return Err(Error::Unavailable);
    }
    Ok(identity)
}
