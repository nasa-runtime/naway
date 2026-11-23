//! 普通查询只读取公开提案事实，不装载密文或解密材料。

use super::{
    model::{Record, Summary, Target},
    Error, Store,
};
use sqlx::{postgres::PgRow, PgConnection, Row};

pub(super) enum Selection<'a> {
    Id(&'a str),
    Original {
        creator: &'a str,
        epoch: i64,
        key: &'a str,
    },
    Page {
        after: &'a str,
        limit: i64,
    },
}

/// 业务作用：按精确域读取原提案或有界目录，原请求恢复不要求再次上传材料。
///
/// 参数说明：
/// - `store`：当前共享存储权威。
/// - `scope`：已获读权的唯一范围。
/// - `selection`：精确 id、原提交主体及键，或有限游标。
///
/// 返回：完整的低敏记录集合；空查询不证明其它尚未结束事务已经回滚。
pub(super) async fn read(
    store: &Store,
    scope: &str,
    selection: Selection<'_>,
) -> Result<Vec<Record>, Error> {
    let rows = store.read_query(async {
        let mut connection = super::super::connection::Reading::acquire(&store.pool).await?;
        let rows = match selection {
            Selection::Id(id) => by_id(connection.as_mut(), &store.plan.config.cluster_id, scope, id)
                .await?
                .into_iter()
                .collect(),
            Selection::Original { creator, epoch, key } => sqlx::query("SELECT id,scope,admission_epoch,creator,reviewer,state,key_id,targets,summary,created_at_ms,expires_at_ms,updated_at_ms,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_certificate_proposals WHERE cluster_id = $1 AND scope = $2 AND creator = $3 AND admission_epoch = $4 AND client_key = $5")
                .bind(&store.plan.config.cluster_id)
                .bind(scope)
                .bind(creator)
                .bind(epoch)
                .bind(key)
                .fetch_all(connection.as_mut())
                .await?,
            Selection::Page { after, limit } => sqlx::query("SELECT id,scope,admission_epoch,creator,reviewer,state,key_id,targets,summary,created_at_ms,expires_at_ms,updated_at_ms,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_certificate_proposals WHERE cluster_id = $1 AND scope = $2 AND id > $3 ORDER BY id LIMIT $4")
                .bind(&store.plan.config.cluster_id)
                .bind(scope)
                .bind(after)
                .bind(limit)
                .fetch_all(connection.as_mut())
                .await?,
        };
        connection.release().await;
        Ok(rows)
    }).await?;
    rows.into_iter().map(record).collect()
}

/// 业务作用：通过现有连接读取唯一提案的公开投影，使提交响应可在原事务内准备。
///
/// 参数说明：
/// - `connection`：读连接，或正在写入和决议的原事务连接。
/// - `cluster`：已绑定的共享存储集群。
/// - `scope`：当前已授权的唯一范围。
/// - `id`：该范围内的精确提案身份。
///
/// 返回：公开行或缺失事实；连接错误交由当前事务或读取预算处置。
async fn by_id(
    connection: &mut PgConnection,
    cluster: &str,
    scope: &str,
    id: &str,
) -> Result<Option<PgRow>, sqlx::Error> {
    sqlx::query("SELECT id,scope,admission_epoch,creator,reviewer,state,key_id,targets,summary,created_at_ms,expires_at_ms,updated_at_ms,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_certificate_proposals WHERE cluster_id = $1 AND scope = $2 AND id = $3")
        .bind(cluster)
        .bind(scope)
        .bind(id)
        .fetch_optional(connection)
        .await
}

/// 业务作用：从当前写事务准备响应，避免确定提交后因另一次连接获取失败而丢失响应。
///
/// 参数说明：
/// - `store`：当前已绑定的证书提案存储。
/// - `scope`：本事务写入或重放的授权范围。
/// - `id`：本事务已确认的提案身份。
///
/// 返回：低敏响应候选；读取或解码失败阻止当前事务提交，成功结果仍需等待提交确认。
pub(super) async fn in_transaction(store: &Store, scope: &str, id: &str) -> Result<Record, Error> {
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(super::super::store::DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    let row = by_id(
        connection.as_mut(),
        &store.plan.config.cluster_id,
        scope,
        id,
    )
    .await
    .map_err(super::database_error)?
    .ok_or(Error::Unavailable)?;
    record(row)
}

/// 业务作用：把持久行转换为公开投影，按数据库时钟显示过期，未知形状不返回半份记录。
///
/// 参数说明：
/// - `row`：只含公开字段的数据库行。
///
/// 返回：完整记录或固定不可用；不含原幂等键、权限摘要、密文和秘密。
fn record(row: sqlx::postgres::PgRow) -> Result<Record, Error> {
    let parse = || -> Result<Record, sqlx::Error> {
        let targets: Vec<u8> = row.try_get("targets")?;
        let summary: Vec<u8> = row.try_get("summary")?;
        let targets = serde_json::from_slice::<Vec<Target>>(&targets)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        let summary = serde_json::from_slice::<Summary>(&summary)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        let expires = row.try_get("expires_at_ms")?;
        let now: i64 = row.try_get("now_ms")?;
        let mut status: String = row.try_get("state")?;
        if now >= expires && matches!(status.as_str(), "awaiting_approval" | "approved") {
            status = "expired".into();
        }
        Ok(Record {
            id: row.try_get("id")?,
            scope: row.try_get("scope")?,
            admission_epoch: row.try_get("admission_epoch")?,
            creator: row.try_get("creator")?,
            reviewer: row.try_get("reviewer")?,
            status,
            key_id: row.try_get("key_id")?,
            targets,
            certificate: summary,
            created_at_ms: row.try_get("created_at_ms")?,
            expires_at_ms: expires,
            updated_at_ms: row.try_get("updated_at_ms")?,
        })
    };
    parse().map_err(|_| Error::Unavailable)
}
