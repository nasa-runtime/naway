//! 稳定效果的有界身份与结果投影；构造收据不代替节点 owner 的持久提交。

use super::{
    command::{Command, Intent},
    effect::Admission,
};
use anyhow::{ensure, Result};
use nasa::saga::{StepPhase, WorkflowDefinition};
use nasaga_runtime_core::{derive_result_event_id, SagaResultEnvelope, VerifiedIdentity};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Outcome {
    Succeeded,
    Rejected,
    Halted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    CandidateInvalid,
    BaselineChanged,
    PublicationConflict,
    AuthorityChanged,
    GateHalted,
    PreparationInterrupted,
    EffectNotAdmitted,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    admission: Admission,
    outcome: Outcome,
    reason: Option<Reason>,
}

impl Receipt {
    /// 业务作用：把稳定收据与原未决身份精确配对，重试命令不能冒充已持久受理的那一次执行。
    ///
    /// 参数说明：
    /// - `admission`：当前 head 仍保留的原始受理事实。
    ///
    /// 返回：包含 attempt、效果及恢复操作身份的完整元数据相同才为真。
    pub(crate) fn settles(&self, admission: &Admission) -> bool {
        self.admission == *admission
    }

    /// 业务作用：为已确定效果建立可持久化的完整身份，查询与未知状态不能占据稳定事实槽。
    ///
    /// 参数说明：
    /// - `command`：实际完成业务裁决的原命令，调用方已经确认当前授权。
    /// - `definition`：节点冻结的完整工作流定义。
    /// - `outcome`：执行器根据真实效果确认的稳定结果。
    /// - `reason`：有限低敏原因，拒绝或保护状态必须说明原因。
    ///
    /// 返回：格式及 NASA 合同成立的待提交收据；不会写磁盘，也不证明业务副作用已经完成。
    pub(crate) fn new(
        command: &Command,
        definition: &WorkflowDefinition,
        outcome: Outcome,
        reason: Option<Reason>,
    ) -> Result<Self> {
        Self::settle(
            Admission::new(command, definition)?,
            &command.intent,
            definition,
            outcome,
            reason,
        )
    }

    /// 业务作用：将已经确定的效果绑定原持久受理身份，崩溃恢复不凭空创造新的投递或过期会话。
    ///
    /// 参数说明：
    /// - `admission`：原动作槽保存且尚未产生稳定结果的受理事实。
    /// - `intent`：与该槽绑定的原业务意图。
    /// - `definition`：本机支持的原冻结定义。
    /// - `outcome`：文件与快照恢复流程确认的稳定效果。
    /// - `reason`：拒绝或保护所需的有限原因码。
    ///
    /// 返回：身份和 NASA 结果合同一致的待提交收据；必须随节点 head 持久提交后才能报告。
    pub(crate) fn settle(
        admission: Admission,
        intent: &Intent,
        definition: &WorkflowDefinition,
        outcome: Outcome,
        reason: Option<Reason>,
    ) -> Result<Self> {
        let receipt = Self {
            admission,
            outcome,
            reason,
        };
        receipt.validate(intent, definition)?;
        Ok(receipt)
    }

    /// 业务作用：从持久记录重新验证意图、定义、原命令和结果组合，不信任保存过的自报身份。
    ///
    /// 参数说明：
    /// - `intent`：同一持久动作槽保存的完整原始意图。
    /// - `definition`：当前制品支持的原冻结工作流。
    ///
    /// 返回：收据与原动作全部一致时交付 NASA 已证身份；损坏、错阶段、非法原因及伪造身份均拒绝。
    pub(crate) fn validate(
        &self,
        intent: &Intent,
        definition: &WorkflowDefinition,
    ) -> Result<VerifiedIdentity> {
        let identity = self.admission.validate(intent, definition)?;
        ensure!(
            (self.outcome == Outcome::Succeeded) == self.reason.is_none()
                && self.reason != Some(Reason::EffectNotAdmitted),
            "node receipt contract differs"
        );
        // NASA 同时复验 effect/command 派生和 phase/status 组合；本地格式合法不能替代这些协议门。
        result(&identity, self.outcome, self.reason).verified()
    }

    /// 业务作用：把同一稳定事实投影到当前命令，重试沿用效果而结果 Inbox 身份跟随当前 attempt。
    ///
    /// 参数说明：
    /// - `command`：当前已经通过发行者、会话和节点查询权限的命令。
    /// - `definition`：原动作的固定工作流定义。
    ///
    /// 返回：NASA 合同成立的结果；错意图、错效果或跨执行/补偿用途拒绝，不改变原收据。
    pub(crate) fn result_for(
        &self,
        command: &Command,
        definition: &WorkflowDefinition,
    ) -> Result<SagaResultEnvelope> {
        let original = self.validate(&command.intent, definition)?;
        let checked = command.validate(definition)?;
        let identity = checked.identity();
        let effect_matches = if identity.phase == StepPhase::Resolve {
            original.effect == checked.resolved_effect()
        } else {
            original.phase == identity.phase && original.effect == identity.effect
        };
        // 查询只能观察签名指定方向的事实，正向发布和补偿成功不能相互替代。
        ensure!(
            effect_matches && self.admission.step() == checked.step(),
            "node receipt does not answer this command"
        );
        let result = result(identity, self.outcome, self.reason);
        result.verified()?;
        Ok(result)
    }

    /// 业务作用：为同一动作内的去重槽提供稳定效果键，不使用随重投变化的 command 身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：在 validate 成功后可用于比较的原效果身份；不授予覆盖其它收据的资格。
    pub(crate) fn effect_id(&self) -> &str {
        self.admission.effect_id()
    }

    /// 业务作用：让持久动作状态校验读取稳定裁决，不从一次网络超时推测节点效果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：执行器明确记录的成功、拒绝或保护状态。
    pub(crate) fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// 业务作用：为动作槽的状态约束提供原步骤，不能把应用或补偿事实误放进预检位置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：收据内原受理身份的有限步骤；使用前仍须 validate 整份收据。
    pub(crate) fn step(&self) -> super::command::Step {
        self.admission.step()
    }
}

impl Outcome {
    /// 业务作用：把有限稳定结果映射为 NASA 的结果词汇，未知状态不进入持久效果合同。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：NASA 支持的稳定结果名称。
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Rejected => "REJECTED",
            Self::Halted => "HALTED",
        }
    }
}

impl Reason {
    /// 业务作用：仅向工作流与审计传递有限原因码，错误链、文件路径和秘密不能成为结果内容。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无外部插值的固定原因码。
    fn as_str(self) -> &'static str {
        match self {
            Self::CandidateInvalid => "node_candidate_invalid",
            Self::BaselineChanged => "node_baseline_changed",
            Self::PublicationConflict => "node_publication_conflict",
            Self::AuthorityChanged => "node_authority_changed",
            Self::GateHalted => "node_gate_halted",
            Self::PreparationInterrupted => "node_preparation_interrupted",
            Self::EffectNotAdmitted => "node_effect_not_admitted",
        }
    }
}

/// 业务作用：沿用 NASA 的当前强类型身份构造结果，不复制候选正文或浏览器认证。
///
/// 参数说明：
/// - `identity`：本次命令已经重新派生的完整身份。
/// - `outcome`：当前业务效果的稳定事实。
/// - `reason`：相同事实的有限原因。
///
/// 返回：绑定当前 command 的结果；调用方仍须经过 NASA 结果合同校验和持久确认门。
pub(super) fn result(
    identity: &VerifiedIdentity,
    outcome: Outcome,
    reason: Option<Reason>,
) -> SagaResultEnvelope {
    let command_id = identity.command.to_string();
    SagaResultEnvelope {
        event_id: derive_result_event_id(&command_id),
        saga_id: identity.saga_id.as_str().into(),
        tenant_id: identity.tenant.as_str().into(),
        workflow: identity.workflow.as_str().into(),
        definition_version: identity.definition_version.get(),
        definition_digest: identity.definition_digest.clone(),
        step: identity.step.as_str().into(),
        phase: identity.phase.as_str().into(),
        attempt: identity.attempt.get(),
        effect_id: identity.effect.to_string(),
        command_id,
        status: outcome.as_str().into(),
        terminal_status: None,
        reason_code: reason.map(|reason| reason.as_str().into()),
    }
}
