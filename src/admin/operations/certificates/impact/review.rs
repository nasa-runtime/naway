//! 完整影响只接受独立主体的明确确认，父材料状态与影响状态在同一事务裁决。

use super::{capacity, model, Error, Store};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Review {
    pub impact_id: String,
    pub impact_sha256: String,
    pub decision: super::super::review::Decision,
}

/// 业务作用：锁定父子后复验服务端原证明及审批身份，不能以原pair-only审阅人代替新的独立批准。
///
/// 参数说明：
/// - `store`：当前独立共享影响 owner。
/// - `context`：持有配置发布权后复验过的当前身份、范围及完整归属。
/// - `proposal`：原父材料身份。
/// - `review`：明确确认的影响身份、摘要与决定。
///
/// 返回：仅一次合法迁移可以提交；原父失效、独立主体不成立或摘要不匹配时整笔拒绝。
pub(super) async fn apply(
    store: &Store,
    context: &super::super::preview::Context<'_>,
    proposal: &str,
    review: &Review,
) -> Result<(), Error> {
    use super::super::review::Decision;
    store.transaction(Box::pin(async {
        let mut connection = nasa::tx::pgsql::mandatory_conn_for(crate::admin::operations::store::DATASOURCE).await.map_err(|_| Error::Unavailable)?;
        let cluster = &store.plan.config.cluster_id;
        // 父材料和影响行的固定锁序使取消、审批和联合回收只能取得一个确定结果。
        crate::admin::operations::retention::Authority::lock(connection.as_mut(), cluster).await?;
        capacity::owner(connection.as_mut(), store).await?;
        let parent: Option<String> = sqlx::query_scalar("SELECT id FROM naway_certificate_proposals WHERE cluster_id=$1 AND scope=$2 AND id=$3 FOR UPDATE")
            .bind(cluster).bind(&context.scope.key).bind(proposal).fetch_optional(connection.as_mut()).await.map_err(super::super::database_error)?;
        if parent.is_none() {
            return Err(Error::Missing);
        }
        let row = sqlx::query(concat!(include_str!("sql/reading.sql"), " WHERE i.cluster_id=$1 AND i.scope=$2 AND i.proposal_id=$3 FOR UPDATE OF i"))
            .bind(cluster).bind(&context.scope.key).bind(proposal).fetch_optional(connection.as_mut()).await.map_err(super::super::database_error)?.ok_or(Error::Missing)?;
        let record = model::parse(row)?;
        super::api::authorize(context, &record, true)?;
        if !record.parent_active || record.status != "awaiting_approval"
            || review.impact_id != record.id || review.impact_sha256 != record.impact_sha256 {
            return Err(Error::Conflict);
        }
        let next = match review.decision {
            Decision::Cancel if context.principal == record.creator => "cancelled",
            Decision::Approve if context.principal != record.creator && context.principal != record.material_creator => "approved",
            Decision::Reject if context.principal != record.creator && context.principal != record.material_creator => "rejected",
            _ => return Err(Error::Denied),
        };
        // 父状态、期限和所有冻结字段由数据库触发器再次验证，排队时间不能延长原批准窗口。
        let changed = sqlx::query("UPDATE naway_material_impact_proposals SET state=$4,reviewer=$5,updated_at_ms=floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint WHERE cluster_id=$1 AND scope=$2 AND id=$3 AND state='awaiting_approval' AND expires_at_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .bind(cluster).bind(&context.scope.key).bind(&record.id).bind(next).bind(context.principal)
            .execute(connection.as_mut()).await.map_err(|error| match super::super::database_error(error) {
                Error::Expired => Error::Conflict,
                other => other,
            })?;
        if changed.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    })).await
}
