//! 未完成效果只保留原命令身份，不保存旧投递凭据或提前宣告终态。

use super::command::{Command, Intent, Step};
use anyhow::{ensure, Result};
use nasa::saga::{StepPhase, WorkflowDefinition};
use nasaga_runtime_core::{SagaCommandEnvelope, VerifiedIdentity};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admission {
    schema: u32,
    intent_sha256: [u8; 32],
    definition_version: u32,
    definition_digest: String,
    step: Step,
    phase: String,
    attempt: u32,
    effect_id: String,
    command_id: String,
    recovery_operation_id: Option<String>,
}

impl Admission {
    /// 业务作用：冻结实际受理的业务命令身份，断线与重启后的效果确认仍属于原命令。
    ///
    /// 参数说明：
    /// - `command`：已经完成当前授权和合同核验、即将进入持久动作的命令。
    /// - `definition`：节点支持的原冻结工作流。
    ///
    /// 返回：无结果的待提交元数据；查询和取消没有业务受理槽，构造本身不产生写入权。
    pub(crate) fn new(command: &Command, definition: &WorkflowDefinition) -> Result<Self> {
        let checked = command.validate(definition)?;
        ensure!(
            matches!(
                checked.identity().phase,
                StepPhase::Execute | StepPhase::Compensate
            ),
            "node admission requires a business effect"
        );
        let identity = checked.identity();
        Ok(Self {
            schema: 1,
            intent_sha256: *checked.intent_sha256(),
            definition_version: identity.definition_version.get(),
            definition_digest: identity.definition_digest.clone(),
            step: checked.step(),
            phase: identity.phase.as_str().into(),
            attempt: identity.attempt.get(),
            effect_id: identity.effect.to_string(),
            command_id: identity.command.to_string(),
            recovery_operation_id: command.envelope.recovery_operation_id.clone(),
        })
    }

    /// 业务作用：从无结果受理记录重新派生原效果与命令，损坏的元数据不能被恢复流程补成成功。
    ///
    /// 参数说明：
    /// - `intent`：同一节点槽的完整业务意图。
    /// - `definition`：原动作的固定定义。
    ///
    /// 返回：NASA 确认的原身份；跨意图、定义漂移、错 phase 或伪造字段均拒绝，不判断执行结果。
    pub(crate) fn validate(
        &self,
        intent: &Intent,
        definition: &WorkflowDefinition,
    ) -> Result<VerifiedIdentity> {
        ensure!(
            self.schema == 1
                && self.intent_sha256 == intent.fingerprint()?
                && self.definition_version == definition.version().get()
                && self.definition_digest == definition.digest()
                && definition.name().as_str()
                    == format!("naway-config-targets-{}", intent.target_count)
                && matches!(
                    StepPhase::parse(&self.phase),
                    Some(StepPhase::Execute | StepPhase::Compensate)
                ),
            "node admission contract differs"
        );
        let step = match self.step {
            Step::Prepare => format!("prepare-{:03}", intent.target_index),
            Step::Apply => format!("apply-{:03}", intent.target_index),
        };
        // 原始身份必须由 NASA 重新派生，持久记录的存在不能替代命令真实性与步骤归属。
        SagaCommandEnvelope {
            saga_id: intent.operation_id.clone(),
            tenant_id: intent.baseline.cluster_id.clone(),
            workflow: definition.name().as_str().into(),
            definition_version: self.definition_version,
            definition_digest: self.definition_digest.clone(),
            step,
            phase: self.phase.clone(),
            attempt: self.attempt,
            effect_id: self.effect_id.clone(),
            command_id: self.command_id.clone(),
            recovery_operation_id: self.recovery_operation_id.clone(),
            payload: None,
            raw_payload: None,
        }
        .verified()
    }

    /// 业务作用：为持久动作状态区分预检和应用，不能从状态名称猜测当前文件副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原受理命令的有限步骤，外层仍须先校验完整 Admission。
    pub(crate) fn step(&self) -> Step {
        self.step
    }

    /// 业务作用：为同一动作内的去重槽提供稳定效果键，不使用随重投变化的 command 身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：在 validate 成功后可用于比较的原效果身份；不授予覆盖其它收据的资格。
    pub(crate) fn effect_id(&self) -> &str {
        &self.effect_id
    }
}
