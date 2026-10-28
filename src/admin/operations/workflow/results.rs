//! NASA Inbox 和目标稳定事实同源提交，旧查询方向不得被当前实例重新解释。

use super::{
    super::{execution::frozen::Frozen, model::Error, store::DATASOURCE, Store},
    dispatch::Pending,
};
use crate::control::actions::command::Step;
use nasa::saga::{Direction, ServiceIdentity, StepPhase};
use nasaga_runtime_core::{HandleOutcome, SagaResultEnvelope};

impl Store {
    /// 业务作用：在同一推进事务保存节点稳定事实与 NASA 裁决，确认前不得释放投递或目标占位。
    ///
    /// 参数说明：
    /// - pending：本次投递前已验证的原 Outbox 命令。
    /// - frozen：原审批全部目标及共享候选。
    /// - resolve_compensation：原签名中冻结的查询方向。
    /// - result：已经通过原节点、会话及命令门的稳定回报。
    /// - authorize：复验本次完整快照和原审批双方当前权限。
    ///
    /// 返回：明确提交后的 NASA 处理结论；错方向、目标冲突、撤权或未知提交都不能确认投递成功。
    pub(in crate::admin::operations) async fn accept_target_result(
        &self,
        pending: &Pending,
        frozen: &Frozen,
        resolve_compensation: bool,
        result: &SagaResultEnvelope,
        authorize: &(dyn Fn() -> Result<(), Error> + Send + Sync),
    ) -> Result<HandleOutcome, Error> {
        let intent = frozen.target(pending)?;
        validate(pending, resolve_compensation, result)?;
        let digest = intent.fingerprint().map_err(|_| Error::Invalid)?;
        let workflow = self.workflow.get().ok_or(Error::Unavailable)?;
        self.workflow_transaction(Box::pin(async {
            authorize()?;
            let instance = workflow.engine.load_instance(&pending.identity.tenant, &pending.identity.saga_id)
                .await.map_err(|_| Error::Unavailable)?.ok_or(Error::Unavailable)?;
            // NASA 通用 Resolve 结果没有方向字段；持同一推进锁时先拒绝旧方向，防止被投影成另一效果。
            if pending.identity.phase == StepPhase::Resolve
                && (instance.direction == Direction::Compensating) != resolve_compensation
            {
                return Err(Error::Conflict);
            }
            let now = database_now().await?;
            let producer = ServiceIdentity::new("naway-data").map_err(|_| Error::Unavailable)?;
            let authorized = || authorize().map_err(|_| anyhow::anyhow!("target result authority changed"));
            let handled = workflow.engine.handle_authenticated_result_authorized_traced(
                result, &producer, None, now, &authorized,
            ).await.map_err(|_| Error::Unavailable)?;
            let slot = match (pending.step, pending.identity.phase == StepPhase::Compensate || resolve_compensation) {
                (Step::Prepare, false) => 0i32,
                (Step::Apply, false) => 1,
                (Step::Prepare, true) => 2,
                (Step::Apply, true) => 3,
            };
            {
                let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE).await.map_err(|_| Error::Unavailable)?;
                // 稳定效果只能首次写入或同值重放；与已有事实矛盾时连同 NASA Inbox 和后续命令一起回滚。
                let affected = sqlx::query(
                    "UPDATE naway_delivery_targets SET \
                    prepare_outcome=CASE WHEN $6=0 THEN $5 ELSE prepare_outcome END, \
                    apply_outcome=CASE WHEN $6=1 THEN $5 ELSE apply_outcome END, \
                    prepare_compensation=CASE WHEN $6=2 THEN $5 ELSE prepare_compensation END, \
                    apply_compensation=CASE WHEN $6=3 THEN $5 ELSE apply_compensation END \
                    WHERE cluster_id=$1 AND operation_id=$2 AND node_id=$3 AND intent_digest=$4 AND NOT released \
                    AND ($6<>0 OR prepare_outcome IS NULL OR prepare_outcome=$5) \
                    AND ($6<>1 OR apply_outcome IS NULL OR apply_outcome=$5) \
                    AND ($6<>2 OR prepare_compensation IS NULL OR prepare_compensation=$5) \
                    AND ($6<>3 OR apply_compensation IS NULL OR apply_compensation=$5)"
                ).bind(&intent.baseline.cluster_id).bind(&intent.operation_id).bind(&intent.node_id)
                    .bind(digest.as_slice()).bind(&result.status).bind(slot)
                    .execute(connection.as_mut()).await.map_err(|_| Error::Unavailable)?.rows_affected();
                if affected != 1 {
                    return Err(Error::Conflict);
                }
            }
            authorize()?;
            Ok(handled)
        })).await
    }
}

/// 业务作用：在数据库或 Inbox 副作用之前验证完整回报身份和有限稳定效果。
///
/// 参数说明：
/// - pending：原投递的已证命令。
/// - resolve_compensation：原签名携带的补偿查询位。
/// - result：有限节点稳定回报。
///
/// 返回：同一身份和合法方向下的确定效果才成功；未知状态、另一目标或跨方向状态全部拒绝。
fn validate(
    pending: &Pending,
    resolve_compensation: bool,
    result: &SagaResultEnvelope,
) -> Result<(), Error> {
    let identity = result.verified().map_err(|_| Error::Invalid)?;
    if identity.saga_id != pending.identity.saga_id
        || identity.tenant != pending.identity.tenant
        || identity.workflow != pending.identity.workflow
        || identity.definition_version != pending.identity.definition_version
        || identity.definition_digest != pending.identity.definition_digest
        || identity.step != pending.identity.step
        || identity.phase != pending.identity.phase
        || identity.attempt != pending.identity.attempt
        || identity.command != pending.identity.command
        || identity.effect != pending.identity.effect
        || result.terminal_status.is_some()
        || !matches!(result.status.as_str(), "SUCCEEDED" | "REJECTED" | "HALTED")
        || (resolve_compensation && identity.phase != StepPhase::Resolve)
        || (result.status == "REJECTED"
            && (resolve_compensation || identity.phase == StepPhase::Compensate))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// 业务作用：使工作流状态变更使用同一事务中的数据库时钟，不能由调用者提供任意推进时间。
///
/// 参数说明: 无。
///
/// 返回：当前正毫秒时间；没有同源事务或数据库不可用时拒绝状态推进。
pub(super) async fn database_now() -> Result<i64, Error> {
    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
        .await
        .map_err(|_| Error::Unavailable)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(connection.as_mut())
            .await
            .map_err(|_| Error::Unavailable)?;
    if now <= 0 {
        return Err(Error::Unavailable);
    }
    Ok(now)
}
