//! 材料受理只冻结原效果身份；旧投递期限和会话不能变成重启后的新写权。

use super::{
    command::{Command, Step},
    definition,
    position::Position,
};
use crate::control::material::node::Intent;
use anyhow::{ensure, Result};
use nasa::saga::StepPhase;
use nasaga_runtime_core::{SagaCommandEnvelope, VerifiedIdentity};
use serde::{Deserialize, Serialize};

/// 原head实际受理的业务效果；旧投递会话和期限不作为恢复后的新授权保存。
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
    /// 业务作用：冻结实际受理的整批材料命令，原请求断线后仍能独立确认同一效果。
    ///
    /// 参数说明：
    /// - `command`：外层已通过当前权限、签名、窗口与独占门的命令。
    ///
    /// 返回：不含候选正文的原身份；Resolve和Cancel不能形成文件动作受理事实。
    pub(crate) fn new(command: &Command) -> Result<Self> {
        let checked = command.validate()?;
        let identity = checked.identity();
        ensure!(
            matches!(identity.phase, StepPhase::Execute | StepPhase::Compensate),
            "material admission requires a business effect"
        );
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

    /// 业务作用：从原报告携带的历史业务信封恢复受理，禁止借当前投递伪造旧attempt或恢复操作。
    ///
    /// 参数说明：
    /// - `intent`：共享任务独立保存的完整原意图。
    /// - `position`：原物理节点在完整任务中的位置。
    /// - `envelope`：节点实际持久受理的原身份，不含临时投递授权。
    ///
    /// 返回：原生校验后的受理；跨任务、跨定义、查询phase或额外payload拒绝。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(crate) fn restore(
        intent: &Intent,
        position: Position,
        envelope: SagaCommandEnvelope,
    ) -> Result<Self> {
        let definition = definition::cached(position.count as usize)?;
        let identity = envelope.verified()?;
        ensure!(
            envelope.payload.is_none()
                && envelope.raw_payload.is_none()
                && identity.saga_id.as_str() == intent.operation_id
                && identity.tenant.as_str() == intent.baseline.cluster_id
                && identity.workflow == *definition.name(),
            "material historical admission owner differs"
        );
        let step = if identity.step.as_str() == Step::Prepare.name(position) {
            Step::Prepare
        } else if identity.step.as_str() == Step::Apply.name(position) {
            Step::Apply
        } else {
            anyhow::bail!("material historical admission position differs");
        };
        let admission = Self {
            schema: 1,
            intent_sha256: position.fingerprint(intent)?,
            definition_version: envelope.definition_version,
            definition_digest: envelope.definition_digest,
            step,
            phase: envelope.phase,
            attempt: envelope.attempt,
            effect_id: envelope.effect_id,
            command_id: envelope.command_id,
            recovery_operation_id: envelope.recovery_operation_id,
        };
        admission.validate(intent, position)?;
        Ok(admission)
    }

    /// 业务作用：从持久原身份重新派生NASA效果与命令，记录存在不能替代正确的来源和步骤归属。
    ///
    /// 参数说明：
    /// - `intent`：同一动作保留的原完整审批意图。
    /// - `position`：原任务冻结的唯一节点位置和节点总数。
    ///
    /// 返回：重新验证的业务身份；跨意图、跨工作流、非业务phase或伪造派生字段拒绝。
    pub(crate) fn validate(&self, intent: &Intent, position: Position) -> Result<VerifiedIdentity> {
        let definition = definition::cached(position.count as usize)?;
        ensure!(
            self.schema == 1
                && self.intent_sha256 == position.fingerprint(intent)?
                && self.definition_version == definition.version().get()
                && self.definition_digest == definition.digest()
                && matches!(
                    StepPhase::parse(&self.phase),
                    Some(StepPhase::Execute | StepPhase::Compensate)
                ),
            "material admission contract differs"
        );
        self.envelope(intent, position)?.verified()
    }

    /// 业务作用：在验证或网络边界还原原业务身份，历史受理不会继承任何当前会话写权。
    ///
    /// 参数说明：
    /// - `intent`：该受理绑定的完整原意图。
    /// - `position`：原节点步骤位置。
    ///
    /// 返回：保留原attempt、效果和恢复操作的信封；无效节点数量拒绝，使用前仍须验证原意图一致。
    pub(crate) fn envelope(
        &self,
        intent: &Intent,
        position: Position,
    ) -> Result<SagaCommandEnvelope> {
        let definition = definition::cached(position.count as usize)?;
        Ok(SagaCommandEnvelope {
            saga_id: intent.operation_id.clone(),
            tenant_id: intent.baseline.cluster_id.clone(),
            workflow: definition.name().as_str().into(),
            definition_version: self.definition_version,
            definition_digest: self.definition_digest.clone(),
            step: self.step.name(position),
            phase: self.phase.clone(),
            attempt: self.attempt,
            effect_id: self.effect_id.clone(),
            command_id: self.command_id.clone(),
            recovery_operation_id: self.recovery_operation_id.clone(),
            payload: None,
            raw_payload: None,
        })
    }

    /// 业务作用：区分整批准备和文件方向的受理槽，状态名称不能替代原业务步骤。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原受理的有限步骤，使用前仍须完整校验身份。
    pub(crate) fn step(&self) -> Step {
        self.step
    }

    /// 业务作用：以稳定效果身份去重当前动作内的收据，不随重投attempt重复执行文件方向。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原效果标识；不授予替换其它动作事实的资格。
    pub(crate) fn effect_id(&self) -> &str {
        &self.effect_id
    }

    /// 业务作用：复用原受理的完整意图摘要核对重投，稳定结果投影不重新编码或重复遍历目标树。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原意图与节点位置摘要的借用，使用前须完成受理格式校验。
    pub(crate) fn intent_sha256(&self) -> &[u8; 32] {
        &self.intent_sha256
    }
}
