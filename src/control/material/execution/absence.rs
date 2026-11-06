//! 未受理证明只关闭原材料效果，不伪造从未到达的Admission或授予任何秘密写权。

use super::{
    command::{Command, Step},
    definition,
    position::Position,
};
use crate::control::{actions::receipt::Outcome, material::node::Intent};
use anyhow::{ensure, Result};
use nasa::saga::{EffectId, SagaId, StepName, StepPhase};
use nasaga_runtime_core::SagaResultEnvelope;
use serde::{Deserialize, Serialize};

/// 从未受理的原正向效果及独立定义证明，不包含虚构的业务attempt或文件来源计划。
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Absence {
    schema: u32,
    position: Position,
    intent_sha256: [u8; 32],
    definition_digest: String,
    step: Step,
    effect_id: String,
}

impl Absence {
    /// 业务作用：从完整报告恢复原否定事实，原效果由独立定义重新派生，不构造虚假Resolve投递。
    ///
    /// 参数说明：
    /// - `intent`：共享任务保存的完整原意图。
    /// - `position`：该节点的原物理位置。
    /// - `step`：原未受理的有限步骤。
    /// - `effect_id`：报告中原正向效果身份。
    /// - `definition_digest`：原否定事实绑定的独立定义摘要。
    ///
    /// 返回：一致的原否定事实；任何跨效果或定义内容拒绝，不产生文件写权。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(crate) fn restore(
        intent: &Intent,
        position: Position,
        step: Step,
        effect_id: String,
        definition_digest: String,
    ) -> Result<Self> {
        let proof = Self {
            schema: 1,
            position,
            intent_sha256: position.fingerprint(intent)?,
            definition_digest,
            step,
            effect_id,
        };
        proof.validate(intent)?;
        Ok(proof)
    }

    /// 业务作用：交付原否定事实的效果标识，结果传输不能用当前查询命令替换它。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正向效果标识的借用。
    pub(crate) fn effect_id(&self) -> &str {
        &self.effect_id
    }

    /// 业务作用：在结果边界保留原否定事实的独立定义约束。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原定义摘要的借用，不引入新的投递期限或会话。
    pub(crate) fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    /// 业务作用：构造只绑定原正向材料效果的否定事实，查询本身不被记录成一次Execute受理。
    ///
    /// 参数说明：
    /// - `command`：当前有排他写权的正向Resolve，尚未证明效果真的缺席。
    ///
    /// 返回：待持久证明；补偿查询和非Resolve命令拒绝，不创建来源计划或秘密槽。
    pub(crate) fn new(command: &Command) -> Result<Self> {
        let checked = command.validate()?;
        ensure!(
            checked.identity().phase == StepPhase::Resolve
                && !command.delivery.resolve_compensation,
            "material nonadmission requires a forward resolution"
        );
        Ok(Self {
            schema: 1,
            position: command.position,
            intent_sha256: *checked.intent_sha256(),
            definition_digest: checked.identity().definition_digest.clone(),
            step: checked.step(),
            effect_id: checked.resolved_effect().to_string(),
        })
    }

    /// 业务作用：从独立材料定义重新派生被关闭效果，旧配置签名域不能变成材料否定事实。
    ///
    /// 参数说明：
    /// - `intent`：原完整材料意图，保留完整逻辑目标分母。
    ///
    /// 返回：原物理节点位置；摘要、独立定义、步骤或效果不符拒绝。
    pub(crate) fn validate(&self, intent: &Intent) -> Result<Position> {
        let definition = definition::cached(self.position.count as usize)?;
        ensure!(
            self.schema == 1
                && self.intent_sha256 == self.position.fingerprint(intent)?
                && self.definition_digest == definition.digest()
                && self.effect_id
                    == EffectId::derive(
                        &SagaId::new(&intent.operation_id)?,
                        definition.version(),
                        &StepName::new(self.step.name(self.position))?,
                        StepPhase::Execute,
                    )
                    .to_string(),
            "material nonadmission identity differs"
        );
        Ok(self.position)
    }

    /// 业务作用：把已提交未受理事实投影到当前重投，迟到Execute只获得同一拒绝，不能再产生副作用。
    ///
    /// 参数说明：
    /// - `command`：当前已验签且有读取权限的正向命令或Resolve。
    ///
    /// 返回：该原效果的当前NASA拒绝信封；其它效果或补偿查询拒绝。
    pub(crate) fn result_for(&self, command: &Command) -> Result<SagaResultEnvelope> {
        let position = self.validate(&command.intent)?;
        let checked = command.validate()?;
        ensure!(
            position == command.position
                && checked.step() == self.step
                && !command.delivery.resolve_compensation
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Resolve
                )
                && checked.resolved_effect().to_string() == self.effect_id,
            "material nonadmission does not answer this command"
        );
        let result = super::receipt::result(
            checked.identity(),
            Outcome::Rejected,
            Some(super::receipt::Reason::EffectNotAdmitted),
        );
        result.verified()?;
        Ok(result)
    }

    /// 业务作用：为唯一责任槽区分prepare和apply的未受理事实，不能由当前阶段猜测被关闭效果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原正向效果的有限业务步骤。
    pub(crate) fn step(&self) -> Step {
        self.step
    }
}
