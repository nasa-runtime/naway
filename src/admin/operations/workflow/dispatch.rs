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
use std::sync::Arc;

/// 持久命令的业务域由独立定义确认，共用扫描器不能把同名步骤视为同一种节点动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::admin::operations) enum Family {
    Configuration,
    Material,
}

/// 已复验的有限事件；正文仍在原提案中，不能由 Outbox 注入另一份候选。
pub(in crate::admin::operations) struct Pending {
    pub(in crate::admin::operations) family: Family,
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
        let (family, target_count) = Family::identify(
            &envelope.workflow,
            envelope.definition_version,
            &envelope.definition_digest,
        )?;
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
            family,
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
                let definition = self.family.definition(self.target_count)?;
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

impl Family {
    /// 业务作用：由原不可变定义确认业务域与完整分母，定时器不能只按步骤名借用另一域的开关。
    ///
    /// 参数说明：
    /// - `workflow`：原实例或已证命令中的规范工作流名。
    /// - `version`：该原定义的业务版本。
    /// - `digest`：原登记的完整定义摘要。
    ///
    /// 返回：唯一定义的业务域和原分母；未知名称、非规范数量、版本或摘要漂移均拒绝。
    pub(in crate::admin::operations) fn identify(
        workflow: &str,
        version: u32,
        digest: &str,
    ) -> Result<(Self, usize), Error> {
        let (family, suffix) = if let Some(suffix) = workflow.strip_prefix("naway-config-targets-")
        {
            (Self::Configuration, suffix)
        } else if let Some(suffix) = workflow.strip_prefix("naway-material-nodes-") {
            (Self::Material, suffix)
        } else {
            return Err(Error::Invalid);
        };
        let count: usize = suffix.parse().map_err(|_| Error::Invalid)?;
        let definition = family.definition(count)?;
        if workflow != definition.name().as_str()
            || version != definition.version().get()
            || digest != definition.digest()
        {
            return Err(Error::Invalid);
        }
        Ok((family, count))
    }

    /// 业务作用：按已证业务域读取原固定定义，共享定时器和资格裁决不能借另一域的步骤合同。
    ///
    /// 参数说明：
    /// - `count`：原配置目标数或原材料物理节点数，不能取当前在线数量。
    ///
    /// 返回：该域唯一不可变定义；未知分母和构造失败都拒绝。
    pub(in crate::admin::operations) fn definition(
        self,
        count: usize,
    ) -> Result<Arc<nasa::saga::WorkflowDefinition>, Error> {
        match self {
            Self::Configuration => definition::cached(count),
            Self::Material => crate::control::material::execution::definition::cached(count),
        }
        .map_err(|_| Error::Invalid)
    }
}
