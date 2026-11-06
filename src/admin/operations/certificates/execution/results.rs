//! 完整材料报告和NASA结果共享一个事务，未决事实可以确认接收但不完成Outbox。

use super::frozen::Frozen;
use crate::{
    admin::operations::{model::Error, store::DATASOURCE, workflow::results::database_now, Store},
    control::material::execution::{command::Command, report::Report},
};
use nasa::saga::{Direction, ServiceIdentity, StepPhase};
use sqlx::Row;
use std::sync::Arc;

impl Store {
    /// 业务作用：以完整原生报告保存每个原节点的事实增长，并把稳定原效果与NASA Inbox及后续步骤原子提交。
    ///
    /// 参数说明：
    /// - `frozen`：两份原批准冻结的完整任务，不能用当前在线子集替代。
    /// - `command`：本轮真实租约签发的同一原生命令，含原查询方向。
    /// - `report`：真实接收会话交付的同head完整事实。
    /// - `owner`：取得原共享租约的进程身份。
    /// - `authorize`：同时复验当前快照、四主体及本次真实Ticket或本机工作权威。
    ///
    /// 返回：稳定效果已明确提交时为真，只有未决事实提交时为假；失败不得ACK或确认Outbox。
    pub(in crate::admin::operations) async fn accept_material_report(
        &self,
        frozen: &Frozen,
        command: &Command,
        report: &Report,
        owner: &[u8; 16],
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<bool, Error> {
        authorize()?;
        if !self.material_execution_installed {
            return Err(Error::Unavailable);
        }
        let (intent, position) = frozen.node(command.position.index as usize)?;
        // 本轮发行与结果使用同一冻结owner；不能借合法节点结果把另一份来源树带入共享事务。
        if !Arc::ptr_eq(intent, &command.intent)
            || position != command.position
            || report.fence > command.delivery.fence
        {
            return Err(Error::Conflict);
        }
        let checked = command.validate().map_err(|_| Error::Invalid)?;
        let result = report.result_for(command).map_err(|_| Error::Conflict)?;
        let encoded = super::super::impact::encoding::bytes(report, 128 * 1024)?;
        let workflow = self.workflow.get().ok_or(Error::Unavailable)?;
        let stable = self.workflow_transaction(Box::pin(async {
            authorize()?;
            {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                    .await.map_err(|_| Error::Unavailable)?;
                // 同一节点完整事实必须先锁定复验；过期、已换owner或更高fence均不能借旧RPC改写NASA状态。
                let row = sqlx::query(concat!(
                    "SELECT n.report,n.report_revision::text AS revision FROM naway_material_execution_nodes n ",
                    "JOIN naway_material_execution_tasks t ON t.cluster_id=n.cluster_id AND t.operation_id=n.operation_id ",
                    "JOIN naway_material_execution_slots s ON s.cluster_id=n.cluster_id AND s.operation_id=n.operation_id AND s.node_id=n.node_id ",
                    "WHERE n.cluster_id=$1 AND n.operation_id=$2 AND n.node_id=$3 AND n.intent_digest=$4 ",
                    "AND n.node_index=$5 AND NOT n.released AND t.execution_store=$6 AND t.definition_digest=$7 AND t.state='running' ",
                    "AND s.owner=$8 AND s.fence=$9 AND s.expires_at_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint ",
                    "FOR UPDATE OF n,t,s"
                )).bind(&intent.baseline.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .bind(checked.intent_sha256().as_slice()).bind(position.index as i16)
                    .bind(&intent.execution_store).bind(frozen.definition.digest()).bind(owner.as_slice())
                    .bind(command.delivery.fence as i64).fetch_optional(connection.as_mut()).await
                    .map_err(|_| Error::Unavailable)?.ok_or(Error::Conflict)?;
                if let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>("report").map_err(|_| Error::Unavailable)? {
                    let original: Report = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
                    let revision: String = row.try_get("revision").map_err(|_| Error::Unavailable)?;
                    if revision != original.revision.to_string() {
                        return Err(Error::Unavailable);
                    }
                    // 高序号也不能抹去原未知受理或替换历史收据，逐阶段后继与同head完全一致一起约束持久增长。
                    original.require_successor(report, intent, position).map_err(|_| Error::Conflict)?;
                }
            }
            let identity = checked.identity();
            let instance = workflow.engine.load_instance(&identity.tenant, &identity.saga_id).await
                .map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
            if instance.workflow != *frozen.definition.name()
                || instance.definition_digest != frozen.definition.digest()
                || instance.definition_version != frozen.definition.version()
                || instance.business_key.as_str() != intent.operation_id
            {
                return Err(Error::Conflict);
            }
            // Resolve自身没有业务方向字段，等待中的补偿转换不能把原正向查询重新解释为补偿成功。
            if identity.phase == StepPhase::Resolve
                && (instance.direction == Direction::Compensating) != command.delivery.resolve_compensation
            {
                return Err(Error::Conflict);
            }
            if let Some(result) = &result {
                let producer = ServiceIdentity::new("naway-data").map_err(|_| Error::Unavailable)?;
                let now = database_now().await?;
                let authorized = || authorize().map_err(|_| anyhow::anyhow!("material result authority changed"));
                workflow.engine.handle_authenticated_result_authorized_traced(result, &producer, None, now, &authorized)
                    .await.map_err(|_| Error::Unavailable)?;
            }
            {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                    .await.map_err(|_| Error::Unavailable)?;
                // NASA等待之后再次读取数据库期限；租约失效则连同Inbox、实例、后续Outbox和完整报告整体回滚。
                let changed = sqlx::query(concat!(
                    "UPDATE naway_material_execution_nodes n SET report=$4,report_revision=$5::numeric ",
                    "WHERE n.cluster_id=$1 AND n.operation_id=$2 AND n.node_id=$3 AND NOT n.released ",
                    "AND EXISTS (SELECT 1 FROM naway_material_execution_slots s WHERE s.cluster_id=n.cluster_id ",
                    "AND s.operation_id=n.operation_id AND s.node_id=n.node_id AND s.owner=$6 AND s.fence=$7 ",
                    "AND s.expires_at_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint)"
                )).bind(&intent.baseline.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .bind(&encoded).bind(report.revision.to_string()).bind(owner.as_slice())
                    .bind(command.delivery.fence as i64).execute(connection.as_mut()).await
                    .map_err(|_| Error::Unavailable)?.rows_affected();
                if changed != 1 {
                    return Err(Error::Conflict);
                }
            }
            authorize()?;
            Ok(result.is_some())
        })).await?;
        // 提交后撤权仍不能向旧会话确认；持久事实保留，后续按同一原报告重放而不推测事务未发生。
        authorize()?;
        Ok(stable)
    }
}
