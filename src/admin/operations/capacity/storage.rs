//! 容量登记和维护复用 NASA 命名事务，数据库触发器承担唯一的现存用量裁决。

use super::{Contract, Expected, Limits};
use crate::admin::operations::{
    model::Error,
    store::{Store, DATASOURCE},
};
use sqlx::PgConnection;

impl Store {
    /// 业务作用：普通启动只登记首次容量或补齐与原摘要相同的旧合同，不能改变已登记预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置与完整共享合同一致时成功；冲突、用量异常或未知提交阻止本次启动。
    pub(in crate::admin::operations) async fn register_capacity(&self) -> Result<(), Error> {
        let limits = Limits::from_config(&self.plan.config);
        let digest = limits.digest();
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
            let cluster = &self.plan.config.cluster_id;
            sqlx::query("INSERT INTO naway_operation_clusters(cluster_id, capacity_digest, capacity_revision, max_records, max_records_per_scope, max_candidate_bytes, max_total_candidate_bytes) VALUES ($1,$2,1,$3,$4,$5,$6) ON CONFLICT (cluster_id) DO NOTHING")
                .bind(cluster).bind(digest.as_slice()).bind(i64::from(limits.max_records))
                .bind(i64::from(limits.max_records_per_scope)).bind(i64::from(limits.max_candidate_bytes))
                .bind(limits.max_total_candidate_bytes as i64).execute(connection.as_mut()).await.map_err(database_error)?;
            let contract = lock(connection.as_mut(), cluster).await?;
            // 启动不消费任意旧合同的变更权；只允许用同摘要补齐尚未登记的实值。
            if contract.identity.digest != digest {
                return Err(Error::Conflict);
            }
            if contract.limits.is_none() {
                update(connection.as_mut(), cluster, &contract, limits).await?;
            } else if contract.limits != Some(limits) {
                return Err(Error::Conflict);
            }
            Ok(())
        })).await
    }

    /// 业务作用：查看当前共享容量而不登记集群、不推进修订，允许准备中的配置与持久预算不同。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：六秒内取得的单次低敏事实；没有集群时不创建占位行。
    pub(super) async fn capacity_status(&self) -> Result<Contract, Error> {
        let row = self.read_query(async {
            let mut connection = crate::admin::operations::connection::Reading::acquire(&self.pool).await?;
            let row = sqlx::query("SELECT capacity_revision, capacity_digest, capacity_previous_digest, max_records, max_records_per_scope, max_candidate_bytes, max_total_candidate_bytes FROM naway_operation_clusters WHERE cluster_id = $1")
                .bind(&self.plan.config.cluster_id).fetch_optional(connection.as_mut()).await?;
            connection.release().await;
            Ok(row)
        }).await?.ok_or(Error::Missing)?;
        Contract::from_row(&row)
    }

    /// 业务作用：以原修订和摘要比较交换完整容量，重复恢复不再次推进或覆盖后续运维结果。
    ///
    /// 参数说明：
    /// - `expected`：调用方第一次发起时冻结的原合同身份。
    ///
    /// 返回：明确提交的目标合同；前驱不符、缩容不足或未知提交保留独立分类。
    pub(super) async fn change_capacity(&self, expected: Expected) -> Result<Contract, Error> {
        let desired = Limits::from_config(&self.plan.config);
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                .await
                .map_err(|_| Error::Unavailable)?;
            let cluster = &self.plan.config.cluster_id;
            let current = lock(connection.as_mut(), cluster).await?;
            if !current.transition(expected, desired)? {
                return Ok(current);
            }
            // 修订、前驱、摘要和实值同事务发布；触发器先核对全部现存用量才允许更新。
            update(connection.as_mut(), cluster, &current, desired).await
        }))
        .await
    }
}

/// 业务作用：与提案创建及清理取得同一集群行锁，防止容量调整与旧 writer 交错越界。
///
/// 参数说明：
/// - `connection`：NASA 同源事务借用的物理连接。
/// - `cluster`：当前唯一集群。
///
/// 返回：当前完整合同；不存在时不隐式登记。
async fn lock(connection: &mut PgConnection, cluster: &str) -> Result<Contract, Error> {
    let row = sqlx::query("SELECT capacity_revision, capacity_digest, capacity_previous_digest, max_records, max_records_per_scope, max_candidate_bytes, max_total_candidate_bytes FROM naway_operation_clusters WHERE cluster_id = $1 FOR UPDATE")
        .bind(cluster).fetch_optional(connection).await.map_err(database_error)?.ok_or(Error::Missing)?;
    Contract::from_row(&row)
}

/// 业务作用：在持有集群锁时提交完整目标预算，让数据库在同一更新内核对用量与修订门。
///
/// 参数说明：
/// - `connection`：仍持有原集群锁的事务连接。
/// - `cluster`：被调整的唯一集群。
/// - `current`：锁内读取且已通过调用资格检查的原合同。
/// - `desired`：已经通过配置边界检查的目标四项容量。
///
/// 返回：更新后的同一持久合同；任何数据库拒绝都不交付成功状态。
async fn update(
    connection: &mut PgConnection,
    cluster: &str,
    current: &Contract,
    desired: Limits,
) -> Result<Contract, Error> {
    let revision = current
        .identity
        .revision
        .checked_add(1)
        .ok_or(Error::Conflict)?;
    let digest = desired.digest();
    let row = sqlx::query("UPDATE naway_operation_clusters SET capacity_revision = $2, capacity_previous_digest = capacity_digest, capacity_digest = $3, max_records = $4, max_records_per_scope = $5, max_candidate_bytes = $6, max_total_candidate_bytes = $7 WHERE cluster_id = $1 AND capacity_revision = $8 AND capacity_digest = $9 RETURNING capacity_revision, capacity_digest, capacity_previous_digest, max_records, max_records_per_scope, max_candidate_bytes, max_total_candidate_bytes")
        .bind(cluster).bind(revision).bind(digest.as_slice()).bind(i64::from(desired.max_records))
        .bind(i64::from(desired.max_records_per_scope)).bind(i64::from(desired.max_candidate_bytes))
        .bind(desired.max_total_candidate_bytes as i64).bind(current.identity.revision).bind(current.identity.digest.as_slice())
        .fetch_optional(connection).await.map_err(database_error)?.ok_or(Error::Conflict)?;
    Contract::from_row(&row)
}

/// 业务作用：将容量裁决与受理窗口过期分开，禁止把 SQL 原始错误或连接信息交付调用方。
///
/// 参数说明：
/// - `error`：数据库返回的状态或传输错误。
///
/// 返回：固定容量、合同冲突或权威不可用分类。
fn database_error(error: sqlx::Error) -> Error {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("PN001") => Error::Capacity,
        Some("23514") => Error::Conflict,
        _ => Error::Unavailable,
    }
}
