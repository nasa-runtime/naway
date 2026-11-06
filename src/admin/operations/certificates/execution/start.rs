//! 两份原批准、全部原节点责任和NASA首步原子创建，未知提交只能按原任务恢复。

mod reserve;

use super::{cache::Entry, frozen::Frozen};
use crate::admin::operations::{
    model::Error, store::DATASOURCE, workflow::results::database_now, Store,
};
use nasa::saga::{BusinessKey, SagaId, TenantId, TriggerKind};
use nasaga_runtime_core::{StartOutcome, StartSagaRequest};
use sqlx::Row;
use std::sync::Arc;

pub(in crate::admin::operations) struct Started {
    pub entry: Arc<Entry>,
    pub created: bool,
}

impl Store {
    /// 业务作用：把原完整影响批准创建为唯一材料任务，全部节点占位与NASA首步共同提交后才可派发。
    ///
    /// 参数说明：
    /// - `entry`：在数据库事务之外认证候选并冻结的完整原批准，重放时沿用原持久候选摘要。
    /// - `authorize`：复验精确快照、请求者和四主体；为真时还须核对全部原节点当前初始基线。
    ///
    /// 返回：明确提交的新任务或原身份重放；任一节点冲突、撤权、过期或未知提交不声称创建完成。
    pub(in crate::admin::operations) async fn start_material_execution(
        &self,
        entry: Arc<Entry>,
        authorize: &(dyn Fn(&Frozen, bool) -> Result<(), Error> + Send + Sync),
    ) -> Result<Started, Error> {
        if !self.material_execution_installed {
            return Err(Error::Unavailable);
        }
        let frozen = &entry.frozen;
        let first = frozen.nodes.first().ok_or(Error::Conflict)?;
        if first.baseline.cluster_id != self.plan.config.cluster_id {
            return Err(Error::Conflict);
        }
        let workflow = self.workflow.get().ok_or(Error::Unavailable)?;
        let created = self
            .workflow_transaction(Box::pin(async {
                authorize(frozen, false)?;
                {
                    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                        .await
                        .map_err(|_| Error::Unavailable)?;
                    // 审阅和回收先锁集群与影响owner，再锁共同节点屏障和原批准；重放也遵守同一顺序，避免持有父记录等待上层权威。
                    crate::admin::operations::retention::Authority::lock(
                        connection.as_mut(),
                        &self.plan.config.cluster_id,
                    )
                    .await?;
                    super::super::capacity::owner(connection.as_mut(), self).await?;
                    super::super::impact::lock_retention(self, connection.as_mut()).await?;
                    super::retention::lock(self, connection.as_mut()).await?;
                }
                let saga = SagaId::new(&first.operation_id).map_err(|_| Error::Invalid)?;
                let tenant =
                    TenantId::new(&first.baseline.cluster_id).map_err(|_| Error::Invalid)?;
                if existing(self, frozen).await? {
                    let instance = workflow
                        .engine
                        .load_instance(&tenant, &saga)
                        .await
                        .map_err(|_| Error::Unavailable)?
                        .ok_or(Error::Unavailable)?;
                    if instance.workflow != *frozen.definition.name()
                        || instance.definition_version != frozen.definition.version()
                        || instance.definition_digest != frozen.definition.digest()
                        || instance.business_key.as_str() != first.operation_id
                    {
                        return Err(Error::Conflict);
                    }
                    // 原任务重放不重新选择在线节点，也不由审批TTL撤销已提交的恢复和终态释放责任。
                    authorize(frozen, false)?;
                    return Ok(false);
                }
                authorize(frozen, true)?;
                {
                    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                        .await
                        .map_err(|_| Error::Unavailable)?;
                    entry.secret.lock_for_start(connection.as_mut()).await?;
                }
                reserve::all(self, frozen).await?;
                let key = BusinessKey::new(&first.operation_id).map_err(|_| Error::Invalid)?;
                let now = database_now().await?;
                let authorized = || {
                    authorize(frozen, true)
                        .map_err(|_| anyhow::anyhow!("material execution authority changed"))
                };
                let outcome = workflow
                    .engine
                    .start_saga_authorized_traced(
                        &StartSagaRequest {
                            saga_id: &saga,
                            tenant: &tenant,
                            workflow: frozen.definition.name(),
                            version: frozen.definition.version(),
                            business_key: &key,
                            deadline_at_ms: None,
                            trigger_kind: TriggerKind::Admin,
                            trigger_id: &first.operation_id,
                            first_command_payload: None,
                            first_command_raw_payload: None,
                            now_ms: now,
                        },
                        None,
                        &authorized,
                    )
                    .await
                    .map_err(|_| Error::Unavailable)?;
                // 没有原材料任务却已有同名Saga不是合法重放，不能把另一个工作流收养为本次批准。
                if !matches!(outcome, StartOutcome::Started(_)) {
                    return Err(Error::Conflict);
                }
                // NASA等待结束后再读取数据库时钟；首次创建不得跨过原审批截止后仍提交节点新责任。
                if database_now().await? >= entry.secret.context.expires {
                    return Err(Error::Expired);
                }
                authorize(frozen, true)?;
                Ok(true)
            }))
            .await?;
        authorize(frozen, false)?;
        Ok(Started {
            entry,
            created,
        })
    }
}

/// 业务作用：在原任务锁内判定同身份重放，原材料摘要、完整分母、定义与节点摘要均不可被替换。
///
/// 参数说明：
/// - `store`：同一命名事务owner。
/// - `frozen`：本次请求保留的完整原批准。
///
/// 返回：没有任务为假；存在且全部关联精确一致才为真；不完整、错域或父责任漂移拒绝。
async fn existing(store: &Store, frozen: &Frozen) -> Result<bool, Error> {
    let first = &frozen.nodes[0];
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    let row = sqlx::query(concat!(
        "SELECT t.state, (t.execution_store=$3 AND t.proposal_id=$4 AND t.impact_id=$5 AND t.material_intent=$6 ",
        "AND t.impact_digest=$7 AND t.candidate_digest=$8 AND t.candidate_bytes=$9 AND t.target_count=$10 ",
        "AND t.node_count=$11 AND t.definition_digest=$12) AS matches, ",
        "p.execution_started AS material_started,i.execution_started AS impact_started ",
        "FROM naway_material_execution_tasks t JOIN naway_certificate_proposals p ON p.cluster_id=t.cluster_id AND p.id=t.proposal_id ",
        "JOIN naway_material_impact_proposals i ON i.cluster_id=t.cluster_id AND i.id=t.impact_id ",
        "WHERE t.cluster_id=$1 AND t.operation_id=$2 FOR UPDATE OF t,p,i"
    )).bind(&store.plan.config.cluster_id).bind(&first.operation_id).bind(&first.execution_store).bind(&first.proposal_id)
        .bind(&first.impact_id).bind(first.material_intent_sha256.as_slice()).bind(first.impact_sha256.as_slice())
        .bind(first.candidate_sha256.as_slice()).bind(first.candidate_bytes as i32).bind(first.target_count as i16)
        .bind(frozen.nodes.len() as i16).bind(frozen.definition.digest()).fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
    let Some(row) = row else {
        return Ok(false);
    };
    if !row
        .try_get::<bool, _>("matches")
        .map_err(|_| Error::Unavailable)?
        || !row
            .try_get::<bool, _>("material_started")
            .map_err(|_| Error::Unavailable)?
        || !row
            .try_get::<bool, _>("impact_started")
            .map_err(|_| Error::Unavailable)?
    {
        return Err(Error::Conflict);
    }
    let nodes = sqlx::query("SELECT node_id,node_index,intent_digest FROM naway_material_execution_nodes WHERE cluster_id=$1 AND operation_id=$2 ORDER BY node_index")
        .bind(&store.plan.config.cluster_id).bind(&first.operation_id).fetch_all(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
    if nodes.len() != frozen.nodes.len() {
        return Err(Error::Conflict);
    }
    for (index, row) in nodes.iter().enumerate() {
        let (intent, position) = frozen.node(index)?;
        if row
            .try_get::<String, _>("node_id")
            .map_err(|_| Error::Unavailable)?
            != intent.node_id
            || row
                .try_get::<i16, _>("node_index")
                .map_err(|_| Error::Unavailable)?
                != index as i16
            || row
                .try_get::<Vec<u8>, _>("intent_digest")
                .map_err(|_| Error::Unavailable)?
                != position.fingerprint(intent).map_err(|_| Error::Invalid)?
        {
            return Err(Error::Conflict);
        }
    }
    Ok(true)
}
