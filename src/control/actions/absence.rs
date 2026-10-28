//! 未受理效果的持久拒绝证明，不构造从未到达节点的业务受理身份。

use super::{
    command::{Command, Intent, Step},
    receipt::{self, Outcome, Reason},
};
use anyhow::{ensure, Result};
use nasa::saga::{EffectId, SagaId, StepName, StepPhase, WorkflowDefinition};
use nasaga_runtime_core::SagaResultEnvelope;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Absence {
    schema: u32,
    intent_sha256: [u8; 32],
    definition_version: u32,
    definition_digest: String,
    step: Step,
    effect_id: String,
}

impl Absence {
    /// 业务作用：为正向查询建立有限拒绝证明，业务 attempt 缺席时不伪造 Execute Admission。
    ///
    /// 参数说明：
    /// - `command`：持有当前写权、即将关闭未受理效果的原 Resolve。
    /// - `definition`：节点支持的原冻结工作流定义。
    ///
    /// 返回：尚未提交的效果证明；补偿查询和其它阶段拒绝，构造本身不证明效果尚未受理。
    pub(crate) fn new(command: &Command, definition: &WorkflowDefinition) -> Result<Self> {
        let checked = command.validate(definition)?;
        ensure!(
            checked.identity().phase == StepPhase::Resolve
                && !command.delivery.resolve_compensation,
            "node nonadmission requires a forward resolution"
        );
        Ok(Self {
            schema: 1,
            intent_sha256: *checked.intent_sha256(),
            definition_version: definition.version().get(),
            definition_digest: definition.digest(),
            step: checked.step(),
            effect_id: checked.forward_effect().to_string(),
        })
    }

    /// 业务作用：从原意图和固定定义重新派生被永久拒绝的效果，证明不能挪给其它步骤或节点。
    ///
    /// 参数说明：
    /// - `intent`：同一持久动作槽的完整意图。
    /// - `definition`：对应目标数量的固定定义。
    ///
    /// 返回：身份、定义和效果全部一致时交付步骤；任何漂移拒绝恢复。
    pub(crate) fn validate(
        &self,
        intent: &Intent,
        definition: &WorkflowDefinition,
    ) -> Result<Step> {
        let name = match self.step {
            Step::Prepare => format!("prepare-{:03}", intent.target_index),
            Step::Apply => format!("apply-{:03}", intent.target_index),
        };
        let step = StepName::new(name)?;
        let effect = EffectId::derive(
            &SagaId::new(&intent.operation_id)?,
            definition.version(),
            &step,
            StepPhase::Execute,
        );
        ensure!(
            self.schema == 1
                && self.intent_sha256 == intent.fingerprint()?
                && self.definition_version == definition.version().get()
                && self.definition_digest == definition.digest()
                && definition.name().as_str()
                    == format!("naway-config-targets-{}", intent.target_count)
                && definition.step(&step).is_some()
                && self.effect_id == effect.to_string(),
            "node nonadmission proof differs"
        );
        Ok(self.step)
    }

    /// 业务作用：把已提交的永久拒绝投影到当前真实命令，不沿用或虚构历史 attempt。
    ///
    /// 参数说明：
    /// - `command`：当前合法 Execute 重投或正向 Resolve。
    /// - `definition`：原动作固定定义。
    ///
    /// 返回：同一稳定效果的 REJECTED；其它效果和补偿用途拒绝。
    pub(crate) fn result_for(
        &self,
        command: &Command,
        definition: &WorkflowDefinition,
    ) -> Result<SagaResultEnvelope> {
        let step = self.validate(&command.intent, definition)?;
        let checked = command.validate(definition)?;
        ensure!(
            step == checked.step()
                && self.effect_id == checked.forward_effect().to_string()
                && !command.delivery.resolve_compensation
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Resolve
                ),
            "node nonadmission does not answer this command"
        );
        let result = receipt::result(
            checked.identity(),
            Outcome::Rejected,
            Some(Reason::EffectNotAdmitted),
        );
        result.verified()?;
        Ok(result)
    }

    /// 业务作用：让原动作查询按稳定效果选择拒绝证明，避免读取到其它步骤的否定事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：经过 validate 后可用于比较的 Execute 效果身份，不授予写入资格。
    pub(crate) fn effect_id(&self) -> &str {
        &self.effect_id
    }
}
