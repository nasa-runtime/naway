//! 普通查询只读取公开提案事实，不装载密文或解密材料。

use super::{
    model::{Record, Summary, Target},
    Error, Store,
};
use sqlx::Row;

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
            Selection::Id(id) => sqlx::query("SELECT id,scope,admission_epoch,creator,reviewer,state,key_id,targets,summary,created_at_ms,expires_at_ms,updated_at_ms,floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms FROM naway_certificate_proposals WHERE cluster_id = $1 AND scope = $2 AND id = $3")
                .bind(&store.plan.config.cluster_id)
                .bind(scope)
                .bind(id)
                .fetch_all(connection.as_mut())
                .await?,
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
