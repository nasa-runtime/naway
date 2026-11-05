//! 只读影响查询不解密材料，也不把客户端自报目标转化为持久审批事实。

use super::{
    Error, Store,
    model::{self, Record},
};

pub(super) enum Selection<'a> {
    Proposal(&'a str),
    Original {
        creator: &'a str,
        epoch: i64,
        key: &'a str,
    },
}

/// 业务作用：按精确范围读取父材料唯一影响或原登记身份，支持跨 Admin 恢复未知提交。
///
/// 参数说明：
/// - `store`：已验证独立影响合同的共享存储。
/// - `scope`：当前唯一授权范围。
/// - `selection`：父提案身份或原登记者、代际与幂等键。
///
/// 返回：完整且通过原生校验的公开记录；没有记录不代表另一个在途事务已经回滚。
pub(super) async fn read(
    store: &Store,
    scope: &str,
    selection: Selection<'_>,
) -> Result<Option<Record>, Error> {
    let row = store.read_query(async {
        let mut connection = crate::admin::operations::connection::Reading::acquire(&store.pool).await?;
        let row = match selection {
            Selection::Proposal(proposal) => sqlx::query(concat!(include_str!("sql/reading.sql"), " WHERE i.cluster_id=$1 AND i.scope=$2 AND i.proposal_id=$3"))
                .bind(&store.plan.config.cluster_id).bind(scope).bind(proposal).fetch_optional(connection.as_mut()).await?,
            Selection::Original { creator, epoch, key } => sqlx::query(concat!(include_str!("sql/reading.sql"), " WHERE i.cluster_id=$1 AND i.scope=$2 AND i.creator=$3 AND i.admission_epoch=$4 AND i.client_key=$5"))
                .bind(&store.plan.config.cluster_id).bind(scope).bind(creator).bind(epoch).bind(key).fetch_optional(connection.as_mut()).await?,
        };
        connection.release().await;
        Ok(row)
    }).await?;
    row.map(model::parse).transpose()
}
