//! 影响批准具有独立共享预算，不能从原密文容量推断可用空间。

use super::{Error, Store};
use sqlx::Row;

/// 业务作用：只在显式启用且原材料存储成立后登记不可变影响 owner。
///
/// 参数说明：
/// - `store`：已通过原材料结构和资源门的管理存储。
///
/// 返回：共享身份与全部预算一致才就绪；关闭时不访问影响 owner 或创建身份。
pub(in crate::admin::operations) async fn register(store: &Store) -> Result<(), Error> {
    let config = &store.plan.config.certificates;
    if !config.enabled || !config.impact_approvals.enabled {
        return Ok(());
    }
    if !store.material_impact_installed {
        return Err(Error::Unavailable);
    }
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
    let identity = crate::admin::operations::model::hex(&random);
    store.transaction(Box::pin(async {
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(crate::admin::operations::store::DATASOURCE)
            .await.map_err(|_| Error::Unavailable)?;
        let cluster = &store.plan.config.cluster_id;
        // 原材料 owner 和影响 owner 都受同一集群锁裁决，先验证前置身份再创建审批存储。
        let authority = crate::admin::operations::retention::Authority::lock(connection.as_mut(), cluster).await?;
        if !authority.required {
            return Err(Error::Unavailable);
        }
        super::super::capacity::owner(connection.as_mut(), store).await?;
        let config = &config.impact_approvals;
        sqlx::query("INSERT INTO naway_material_impact_owners(cluster_id,store_id,max_records,max_records_per_scope,max_total_bytes,retain_ms) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (cluster_id) DO NOTHING")
            .bind(cluster).bind(identity).bind(config.max_records as i32)
            .bind(config.max_records_per_scope as i32).bind(config.max_total_bytes as i64)
            .bind(i64::from(store.plan.config.retention.retain_seconds) * 1000)
            .execute(connection.as_mut()).await.map_err(super::super::database_error)?;
        owner(connection.as_mut(), store).await.map(|_| ())
    })).await
}

/// 业务作用：持有集群锁后锁定并验证影响 owner，不让不同启动预算的 Admin 写入同一批准存储。
///
/// 参数说明：
/// - `connection`：当前同源事务连接。
/// - `store`：冻结的影响资源合同。
///
/// 返回：原持久随机身份；缺记录、身份异常或预算不同都封闭写入。
pub(super) async fn owner(
    connection: &mut sqlx::PgConnection,
    store: &Store,
) -> Result<String, Error> {
    let row = sqlx::query("SELECT store_id,max_records,max_records_per_scope,max_total_bytes,retain_ms FROM naway_material_impact_owners WHERE cluster_id=$1 FOR UPDATE")
        .bind(&store.plan.config.cluster_id).fetch_one(connection).await.map_err(super::super::database_error)?;
    let config = &store.plan.config.certificates.impact_approvals;
    let read = || -> Result<String, sqlx::Error> {
        let id: String = row.try_get("store_id")?;
        let same = row.try_get::<i32, _>("max_records")? == config.max_records as i32
            && row.try_get::<i32, _>("max_records_per_scope")?
                == config.max_records_per_scope as i32
            && row.try_get::<i64, _>("max_total_bytes")? == config.max_total_bytes as i64
            && row.try_get::<i64, _>("retain_ms")?
                == i64::from(store.plan.config.retention.retain_seconds) * 1000;
        if !same || !super::super::model::valid_hex(&id, 64) {
            return Err(sqlx::Error::Protocol(
                "material impact authority differs".into(),
            ));
        }
        Ok(id)
    };
    read().map_err(|_| Error::Unavailable)
}
