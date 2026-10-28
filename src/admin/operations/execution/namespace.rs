//! 集群注册与执行绑定竞争同一数据库行，永久保留唯一命名空间身份。

use crate::admin::operations::{
    connection::Reading,
    model::Error,
    store::{Store, DATASOURCE},
};
use sqlx::{postgres::PgRow, Row};

pub(in crate::admin::operations) struct Binding {
    pub(super) cluster: Option<String>,
    pub(super) bound_at_ms: Option<i64>,
}

impl Binding {
    /// 业务作用：验证持久身份的成对字段，避免缺失或非法权威被当成尚未绑定。
    ///
    /// 参数说明：
    /// - `row`：已确认存在的唯一 namespace 行。
    ///
    /// 返回：未绑定或完整合法的绑定；半登记和非法身份均拒绝。
    fn from_row(row: &PgRow) -> Result<Self, Error> {
        let cluster: Option<String> = row.try_get("cluster_id").map_err(|_| Error::Unavailable)?;
        let bound_at_ms: Option<i64> =
            row.try_get("bound_at_ms").map_err(|_| Error::Unavailable)?;
        match (&cluster, bound_at_ms) {
            (None, None) => {}
            (Some(cluster), Some(at))
                if crate::config::operations::token(cluster, 128) && at >= 0 => {}
            _ => return Err(Error::Unavailable),
        }
        Ok(Self {
            cluster,
            bound_at_ms,
        })
    }

    /// 业务作用：在容量登记前判定配置集群是否仍属于当前 schema 允许的范围。
    ///
    /// 参数说明：
    /// - `cluster`：当前进程启动时冻结的集群身份。
    ///
    /// 返回：未绑定或精确匹配时允许登记；已有其它绑定时拒绝。
    pub(in crate::admin::operations) fn permits(&self, cluster: &str) -> bool {
        self.cluster.as_deref().is_none_or(|owner| owner == cluster)
    }

    /// 业务作用：仅授予已经永久绑定的精确集群工作流存储资格，区分未绑定的提案共享库。
    ///
    /// 参数说明：
    /// - `cluster`：当前工作流计划的冻结集群身份。
    ///
    /// 返回：已有绑定且完全一致时为真；未绑定和异集群均为假。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(in crate::admin::operations) fn bound_to(&self, cluster: &str) -> bool {
        self.cluster.as_deref() == Some(cluster)
    }
}

impl Store {
    /// 业务作用：在有限只读期限内读取执行存储的集群身份，不注册业务集群或绑定 schema。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：唯一持久行；缺席、读取超时或传输异常时拒绝授予命名空间资格。
    pub(in crate::admin::operations) async fn execution_namespace(&self) -> Result<Binding, Error> {
        let row = self
            .read_query(async {
                let mut connection = Reading::acquire(&self.pool).await?;
                let row = sqlx::query(
                    "SELECT cluster_id, bound_at_ms FROM naway_operation_namespace WHERE singleton",
                )
                .fetch_optional(connection.as_mut())
                .await?;
                connection.release().await;
                Ok(row)
            })
            .await?
            .ok_or(Error::Unavailable)?;
        Binding::from_row(&row)
    }

    /// 业务作用：在同源事务内永久绑定一个 schema，重复请求回读原绑定且不更改其时间。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已明确提交的原或新绑定；其它集群、保护行缺失与未知提交分别保留失败语义。
    pub(super) async fn bind_execution_namespace(&self) -> Result<Binding, Error> {
        self.transaction(Box::pin(async {
            let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                .await
                .map_err(|_| Error::Unavailable)?;
            // 先等待全部注册释放同一行；触发器在更新时再次复验，不能只依赖锁前读取。
            let row = sqlx::query("SELECT cluster_id, bound_at_ms FROM naway_operation_namespace WHERE singleton FOR UPDATE")
                .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
            let binding = Binding::from_row(&row)?;
            if !binding.permits(&self.plan.config.cluster_id) {
                return Err(Error::Conflict);
            }
            if binding.cluster.is_some() {
                return Ok(binding);
            }
            let row = sqlx::query("UPDATE naway_operation_namespace SET cluster_id = $1, bound_at_ms = floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint WHERE singleton AND cluster_id IS NULL RETURNING cluster_id, bound_at_ms")
                .bind(&self.plan.config.cluster_id).fetch_optional(connection.as_mut()).await
                .map_err(|error| if error.as_database_error().and_then(|error| error.code()).as_deref() == Some("PN002") {
                    Error::Conflict
                } else {
                    Error::Unavailable
                })?.ok_or(Error::Conflict)?;
            Binding::from_row(&row)
        }))
        .await
    }
}
