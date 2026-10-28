//! 执行观察使用同一数据库快照，原目标集合不受当前成员在线状态影响。

use crate::admin::operations::{
    model::{Domain, Error, Target},
    store::DATASOURCE,
    Store,
};
use crate::control::actions::definition;
use nasa::saga::SagaId;
use nasaga_backend::{SagaBackend, SagaStepRow};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, Row};

impl Store {
    /// 业务作用：为已授权范围读取原执行和完整目标进度，不读取或复制候选正文。
    ///
    /// 参数说明：
    /// - scope：当前请求已经通过 Read 的精确范围。
    /// - domain：请求的原配置领域。
    /// - id：原提案身份。
    ///
    /// 返回：一致的未启动或完整进度视图；跨范围缺席和存储不一致不泄漏其它操作事实。
    pub(in crate::admin::operations) async fn execution_view(
        &self,
        scope: &str,
        domain: Domain,
        id: &str,
    ) -> Result<Value, Error> {
        self.transaction(Box::pin(async {
            let (started, execution, targets) = {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
                // 提案、目标投影与 NASA 步骤必须同代读取，避免并发推进被拼成虚假的完成比例。
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                let proposal = sqlx::query("SELECT execution_started FROM naway_operation_proposals WHERE cluster_id=$1 AND scope=$2 AND domain=$3 AND id=$4")
                    .bind(&self.plan.config.cluster_id).bind(scope).bind(domain.identity().0).bind(id)
                    .fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Missing)?;
                let started: bool = proposal.try_get("execution_started").map_err(|_| Error::Unavailable)?;
                if !started {
                    return Ok(json!({
                        "operation_id": id,
                        "cluster_id": self.plan.config.cluster_id,
                        "execution_started": false,
                        "lifecycle": "not_started"
                    }));
                }
                if !self.delivery_installed || self.workflow.get().is_none() {
                    return Err(Error::Unavailable);
                }
                let execution = sqlx::query(concat!(
                    "SELECT e.state,e.target_count,e.definition_digest,e.targets,e.created_at_ms,e.updated_at_ms,",
                    "(ROW(e.admission_epoch,e.scope,e.domain,e.creator,e.reviewer,e.authority,e.candidate_digest,e.candidate_bytes,e.targets) ",
                    "= ROW(p.admission_epoch,p.scope,p.domain,p.creator,p.reviewer,p.authority,p.candidate_digest,octet_length(p.candidate),p.targets)) AS matches ",
                    "FROM naway_delivery_executions e JOIN naway_operation_proposals p ON p.cluster_id=e.cluster_id AND p.id=e.operation_id ",
                    "WHERE e.cluster_id=$1 AND e.operation_id=$2"
                )).bind(&self.plan.config.cluster_id).bind(id).fetch_optional(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
                let targets = sqlx::query(concat!(
                    "SELECT node_id,target_index,store_id,node_epoch::text AS epoch,prepare_outcome,apply_outcome,",
                    "prepare_compensation,apply_compensation,released FROM naway_delivery_targets ",
                    "WHERE cluster_id=$1 AND operation_id=$2 ORDER BY target_index LIMIT 129"
                )).bind(&self.plan.config.cluster_id).bind(id).fetch_all(connection.as_mut()).await.map_err(|_| Error::Unavailable)?;
                (started, execution, targets)
            };
            let raw: &[u8] = execution.try_get("targets").map_err(|_| Error::Unavailable)?;
            if !(2..=65536).contains(&raw.len()) {
                return Err(Error::Unavailable);
            }
            let original: Vec<Target> = serde_json::from_slice(raw).map_err(|_| Error::Unavailable)?;
            let definition = definition::cached(original.len()).map_err(|_| Error::Unavailable)?;
            let count: i16 = execution.try_get("target_count").map_err(|_| Error::Unavailable)?;
            let digest: &str = execution.try_get("definition_digest").map_err(|_| Error::Unavailable)?;
            if count as usize != original.len() || targets.len() != original.len() || digest != definition.digest()
                || !execution.try_get::<bool, _>("matches").map_err(|_| Error::Unavailable)?
                || original.windows(2).any(|pair| pair[0].node_id >= pair[1].node_id) {
                return Err(Error::Unavailable);
            }
            let backend = nasa::saga::pgsql::PgSagaBackend::with_datasource(DATASOURCE).map_err(|_| Error::Unavailable)?;
            let saga = SagaId::new(id).map_err(|_| Error::Invalid)?;
            let instance = backend.store().load_instance(&saga).await.map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
            let steps = backend.store().load_steps(&saga).await.map_err(|_| Error::Unavailable)?;
            if instance.saga_id != saga || instance.tenant.as_str() != self.plan.config.cluster_id || instance.business_key.as_str() != id
                || instance.workflow != *definition.name() || instance.definition_version != definition.version()
                || instance.definition_digest != definition.digest() || steps.len() != definition.steps().len()
                || steps.iter().zip(definition.steps()).enumerate().any(|(index, (row, step))| row.ordinal as usize != index + 1 || row.step != *step.name()) {
                return Err(Error::Unavailable);
            }
            let mut values = Vec::with_capacity(original.len());
            let mut released = 0;
            for (index, (row, target)) in targets.iter().zip(original).enumerate() {
                let value = target_view(row, target, index, &self.plan.config.cluster_id)?;
                released += usize::from(value["released"] == true);
                values.push(value);
            }
            let lifecycle: &str = execution.try_get("state").map_err(|_| Error::Unavailable)?;
            if !matches!(lifecycle, "running" | "releasing" | "halted" | "complete")
                || (lifecycle == "complete" && released != values.len()) {
                return Err(Error::Unavailable);
            }
            Ok(json!({
                "operation_id": id,
                "cluster_id": self.plan.config.cluster_id,
                "execution_started": started,
                "lifecycle": lifecycle,
                "business_status": instance.status.as_str(),
                "control_state": instance.control_state.as_str(),
                "direction": instance.direction.as_str(),
                "current_step": instance.current_step.as_ref().map(|step| step.as_str()),
                "instance_version": instance.version.to_string(),
                "control_version": instance.control_version.to_string(),
                "definition": {
                    "name": definition.name().as_str(),
                    "version": definition.version().get().to_string(),
                    "sha256": definition.digest()
                },
                "target_count": values.len(),
                "released_count": released,
                "targets": values,
                "steps": steps.iter().map(step_view).collect::<Vec<_>>(),
                "created_at_ms": execution.try_get::<i64, _>("created_at_ms").map_err(|_| Error::Unavailable)?,
                "updated_at_ms": execution.try_get::<i64, _>("updated_at_ms").map_err(|_| Error::Unavailable)?
            }))
        })).await
    }
}

/// 业务作用：把每一行持久效果绑定到审批原目标，未知效果保留为空且不伪造拒绝。
///
/// 参数说明：
/// - row：同次快照内的目标结果。
/// - target：原审批冻结的目标身份和基线。
/// - index：原始有序集合中的位置。
/// - cluster：持久绑定的发行集群。
///
/// 返回：原目标及四效果和代际释放事实；乱序、跨集群或身份矛盾拒绝整个视图。
fn target_view(row: &PgRow, target: Target, index: usize, cluster: &str) -> Result<Value, Error> {
    let baseline = target.node_baseline.as_ref().ok_or(Error::Unavailable)?;
    if baseline.cluster_id != cluster
        || row
            .try_get::<&str, _>("node_id")
            .map_err(|_| Error::Unavailable)?
            != target.node_id
        || row
            .try_get::<i16, _>("target_index")
            .map_err(|_| Error::Unavailable)? as usize
            != index
        || row
            .try_get::<&str, _>("store_id")
            .map_err(|_| Error::Unavailable)?
            != baseline.store_id
        || row
            .try_get::<&str, _>("epoch")
            .map_err(|_| Error::Unavailable)?
            != baseline.node_admission_epoch
    {
        return Err(Error::Unavailable);
    }
    let mut value = serde_json::to_value(target).map_err(|_| Error::Unavailable)?;
    value["target_index"] = index.into();
    value["released"] = row
        .try_get::<bool, _>("released")
        .map_err(|_| Error::Unavailable)?
        .into();
    for name in [
        "prepare_outcome",
        "apply_outcome",
        "prepare_compensation",
        "apply_compensation",
    ] {
        let outcome: Option<&str> = row.try_get(name).map_err(|_| Error::Unavailable)?;
        if outcome.is_some_and(|outcome| !matches!(outcome, "SUCCEEDED" | "REJECTED" | "HALTED"))
            || (name.ends_with("compensation") && outcome == Some("REJECTED"))
        {
            return Err(Error::Unavailable);
        }
        value[name] = outcome.into();
    }
    Ok(value)
}

/// 业务作用：只暴露 NASA 当前有限步骤状态，不交付内部错误正文、载荷或历史事件。
///
/// 参数说明：
/// - step：同次快照读取的原定义步骤。
///
/// 返回：正向、补偿、解决和取消的独立状态，未决状态不会被合并成失败。
fn step_view(step: &SagaStepRow) -> Value {
    json!({
        "name": step.step.as_str(),
        "ordinal": step.ordinal,
        "forward": step.forward_status.as_str(),
        "compensation": step.compensation_status.as_str(),
        "resolution": step.resolution_status.as_str(),
        "cancel": step.cancel_status.as_str()
    })
}
