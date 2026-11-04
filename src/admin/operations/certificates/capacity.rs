//! 跨 Admin 共享材料容量与随机存储身份，不能由进程重启重置。

use super::{Error, Store};
use sqlx::Row;

/// 业务作用：在显式启用且命名空间已绑定后登记材料 owner；关闭时不访问材料表或产生身份。
///
/// 参数说明：
/// - `store`：已有共享受理代与配置提案容量的数据库 owner。
///
/// 返回：永久身份和共享预算一致才就绪，异集群、缺迁移或不同预算拒绝启动。
pub(in crate::admin::operations) async fn register(store: &Store) -> Result<(), Error> {
    let config = &store.plan.config.certificates;
    if !config.enabled {
        return Ok(());
    }
    if !store.certificates_installed {
        return Err(Error::Unavailable);
    }
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
    let identity = super::super::model::hex(&random);
    store.transaction(Box::pin(async {
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(super::super::store::DATASOURCE)
            .await.map_err(|_| Error::Unavailable)?;
        let cluster = &store.plan.config.cluster_id;
        // 共享集群锁先于材料 owner，已绑定命名空间才可登记；数据库触发器覆盖并发入口。
        let authority = super::super::retention::Authority::lock(connection.as_mut(), cluster).await?;
        if !authority.required {
            return Err(Error::Unavailable);
        }
        sqlx::query("INSERT INTO naway_certificate_owners(cluster_id, store_id, max_records, max_records_per_scope, max_material_bytes, max_total_bytes, retain_ms) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (cluster_id) DO NOTHING")
            .bind(cluster)
            .bind(&identity)
            .bind(config.max_records as i32)
            .bind(config.max_records_per_scope as i32)
            .bind(config.max_material_bytes as i32)
            .bind(config.max_total_bytes as i64)
            .bind(i64::from(store.plan.config.retention.retain_seconds) * 1000)
            .execute(connection.as_mut()).await.map_err(super::database_error)?;
        owner(connection.as_mut(), store).await.map(|_| ())
    })).await
}

/// 业务作用：复验所有入口共享的不可变容量和随机材料身份，不允许持有不同启动预算的写者继续受理。
///
/// 参数说明：
/// - `connection`：已经持有集群行锁的事务连接。
/// - `store`：当前进程的冻结资源计划。
///
/// 返回：合法的持久随机身份；缺记录、预算不同或读取异常均封闭。
pub(super) async fn owner(
    connection: &mut sqlx::PgConnection,
    store: &Store,
) -> Result<String, Error> {
    let row = sqlx::query("SELECT store_id, max_records, max_records_per_scope, max_material_bytes, max_total_bytes, retain_ms FROM naway_certificate_owners WHERE cluster_id = $1")
        .bind(&store.plan.config.cluster_id)
        .fetch_one(connection)
        .await
        .map_err(super::database_error)?;
    let config = &store.plan.config.certificates;
    let parse = || -> Result<String, sqlx::Error> {
        let same = row.try_get::<i32, _>("max_records")? == config.max_records as i32
            && row.try_get::<i32, _>("max_records_per_scope")?
                == config.max_records_per_scope as i32
            && row.try_get::<i32, _>("max_material_bytes")? == config.max_material_bytes as i32
            && row.try_get::<i64, _>("max_total_bytes")? == config.max_total_bytes as i64
            && row.try_get::<i64, _>("retain_ms")?
                == i64::from(store.plan.config.retention.retain_seconds) * 1000;
        let identity: String = row.try_get("store_id")?;
        if !same || !super::model::valid_hex(&identity, 64) {
            return Err(sqlx::Error::Protocol(
                "certificate storage authority differs".into(),
            ));
        }
        Ok(identity)
    };
    parse().map_err(|_| Error::Unavailable)
}
