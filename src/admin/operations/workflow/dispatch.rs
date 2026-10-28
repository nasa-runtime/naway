//! 交付只读取 NASA 已提交的命令权威，不自行推进步骤或推测节点效果。

mod eligibility;

use super::super::{model::Error, store::DATASOURCE, Store};
use crate::control::actions::{command::Step, definition};
pub(in crate::admin::operations) use eligibility::Disposition;
use nasa::{outbox::OutboxEvent, saga::StepPhase};
use nasaga_backend::SagaBackend;
use nasaga_runtime_core::{
    SagaCommandEnvelope, VerifiedIdentity, COMMAND_EVENT_TYPE, SAGA_AGGREGATE_TYPE,
};

/// 已复验的有限事件；正文仍在原提案中，不能由 Outbox 注入另一份候选。
pub(in crate::admin::operations) struct Pending {
    pub(in crate::admin::operations) envelope: SagaCommandEnvelope,
    pub(in crate::admin::operations) identity: VerifiedIdentity,
    pub(in crate::admin::operations) target_count: usize,
    pub(in crate::admin::operations) target_index: usize,
    pub(in crate::admin::operations) step: Step,
}

impl Pending {
    /// 业务作用：在读取执行正文前复验 Outbox 外层归属和 NASA 派生身份，拒绝其它生产者或错定义消息。
    ///
    /// 参数说明：
    /// - `event`：NASA publisher 本次收到的持久事件。
    /// - `cluster`：共享 schema 永久绑定的当前集群。
    ///
    /// 返回：唯一冻结目标的有限命令；未知归属、正文载荷、身份篡改和非规范步骤全部拒绝。
    pub(in crate::admin::operations) fn decode(
        event: &OutboxEvent,
        cluster: &str,
    ) -> Result<Self, Error> {
        if event.tenant != cluster
            || event.aggregate_type != SAGA_AGGREGATE_TYPE
            || event.event_type != COMMAND_EVENT_TYPE
            || event.payload.len() > 16 * 1024
        {
            return Err(Error::Invalid);
        }
        let envelope: SagaCommandEnvelope =
            serde_json::from_slice(&event.payload).map_err(|_| Error::Invalid)?;
        let identity = envelope.verified().map_err(|_| Error::Invalid)?;
        if identity.tenant.as_str() != cluster
            || envelope.command_id != event.event_id
            || envelope.saga_id != event.aggregate_id
            || envelope.payload.is_some()
            || envelope.raw_payload.is_some()
            || identity.phase == StepPhase::Cancel
            || envelope.saga_id.len() != 32
            || !envelope
                .saga_id
                .bytes()
                .all(|value| value.is_ascii_digit() || matches!(value, b'a'..=b'f'))
        {
            return Err(Error::Invalid);
        }
        let target_count: usize = envelope
            .workflow
            .strip_prefix("naway-config-targets-")
            .and_then(|value| value.parse().ok())
            .ok_or(Error::Invalid)?;
        let definition = definition::cached(target_count).map_err(|_| Error::Invalid)?;
        if identity.workflow != *definition.name()
            || identity.definition_version != definition.version()
            || identity.definition_digest != definition.digest()
        {
            return Err(Error::Invalid);
        }
        let (step, index) = if let Some(index) = envelope.step.strip_prefix("prepare-") {
            (Step::Prepare, index)
        } else if let Some(index) = envelope.step.strip_prefix("apply-") {
            (Step::Apply, index)
        } else {
            return Err(Error::Invalid);
        };
        let target_index: usize = index.parse().map_err(|_| Error::Invalid)?;
        if target_index >= target_count || index != format!("{target_index:03}") {
            return Err(Error::Invalid);
        }
        Ok(Self {
            envelope,
            identity,
            target_count,
            target_index,
            step,
        })
    }

    /// 业务作用：用同一数据库快照裁决是否仍可发送命令，超时后已被替代的 Execute 不再阻挡 Resolve。
    ///
    /// 参数说明：
    /// - `store`：绑定同一集群、NASA datasource 和停止权的持久 owner。
    ///
    /// 返回：有效、明确失效或暂停；缺行、投影矛盾和未知事务结果不授予发送或确认资格。
    pub(in crate::admin::operations) async fn disposition(
        &self,
        store: &Store,
    ) -> Result<Disposition, Error> {
        if store.stopping.is_cancelled()
            || store.workflow.get().is_none()
            || self.identity.tenant.as_str() != store.plan.config.cluster_id
        {
            return Err(Error::Unavailable);
        }
        let backend = nasa::saga::pgsql::PgSagaBackend::with_datasource(DATASOURCE)
            .map_err(|_| Error::Unavailable)?;
        store
            .transaction(Box::pin(async {
                {
                    let mut connection = nasa::tx::pgsql::mandatory_conn_for(DATASOURCE)
                        .await
                        .map_err(|_| Error::Unavailable)?;
                    // 实例、步骤与 attempt 必须属于同一已提交快照，不能拼接并发推进前后的字段撤下命令。
                    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                        .execute(connection.as_mut())
                        .await
                        .map_err(|_| Error::Unavailable)?;
                }
                let instance = backend
                    .store()
                    .load_instance(&self.identity.saga_id)
                    .await
                    .map_err(|_| Error::Unavailable)?
                    .ok_or(Error::Unavailable)?;
                let steps = backend
                    .store()
                    .load_steps(&self.identity.saga_id)
                    .await
                    .map_err(|_| Error::Unavailable)?;
                let definition =
                    definition::cached(self.target_count).map_err(|_| Error::Unavailable)?;
                if steps.len() != definition.steps().len()
                    || steps.iter().zip(definition.steps()).enumerate().any(
                        |(index, (row, step))| {
                            row.step != *step.name() || row.ordinal as usize != index + 1
                        },
                    )
                {
                    return Err(Error::Unavailable);
                }
                let row = steps
                    .iter()
                    .find(|row| row.step == self.identity.step)
                    .ok_or(Error::Unavailable)?;
                let attempts = backend
                    .store()
                    .load_attempts(&self.identity.saga_id, &self.identity.step)
                    .await
                    .map_err(|_| Error::Unavailable)?;
                let mut matching = attempts.iter().filter(|row| {
                    row.phase == self.identity.phase && row.attempt == self.identity.attempt
                });
                let attempt = matching.next().ok_or(Error::Unavailable)?;
                if matching.next().is_some() {
                    return Err(Error::Unavailable);
                }
                eligibility::classify(self, &instance, row, attempt)
            }))
            .await
    }
}
