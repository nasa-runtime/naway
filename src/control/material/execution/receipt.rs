//! 材料收据绑定原业务效果和真实监听证据；稳定事实只能在目录head提交后对外回答。

use super::{
    command::{Command, Step},
    effect::Admission,
    observation::{Evidence, Protocols},
    position::Position,
};
use crate::control::{actions::receipt::Outcome, material::node::Intent};
use anyhow::{ensure, Result};
use nasa::saga::StepPhase;
use nasaga_runtime_core::{derive_result_event_id, SagaResultEnvelope, VerifiedIdentity};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 供调度与保护态使用的固定低敏原因，路径、私钥和底层错误链不能进入结果。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    EffectNotAdmitted,
    CandidateInvalid,
    SourceChanged,
    BaselineChanged,
    AuthorityChanged,
    GateHalted,
    PreparationInterrupted,
}

/// 原持久受理的稳定结果；应用成功还必须保留全部原协议的实际监听证据。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    admission: Admission,
    outcome: Outcome,
    reason: Option<Reason>,
    evidence: Option<Arc<Evidence>>,
}

/// 原计划按当前效果方向提供预分配代；准备阶段仍使用同一原来源协议集合。
pub(crate) struct Expected<'a> {
    pub intent: &'a Intent,
    pub position: Position,
    pub generations: &'a [&'a str],
    pub protocols: &'a [Vec<Protocols>],
}

impl Receipt {
    /// 业务作用：交付稳定收据所结算的原受理，当前重投身份不能替换原attempt或恢复操作。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原持久业务身份的借用，完整校验仍由同一原意图和位置决定。
    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    /// 业务作用：交付原稳定拒绝的有限原因，不能从当前网络错误重新解释历史结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原原因；成功收据没有拒绝原因。
    pub(crate) fn reason(&self) -> Option<Reason> {
        self.reason
    }

    /// 业务作用：让材料结果保留真正确认的全部监听事实，文件完成不产生替代Evidence。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原共享监听证据的借用，仅应用或补偿成功收据携带。
    pub(crate) fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_deref()
    }

    /// 业务作用：将确定结果绑定原持久受理，重启确认不需要制造新的投递身份或重复执行。
    ///
    /// 参数说明：
    /// - `admission`：原head承认且尚未结算的业务身份。
    /// - `expected`：原节点位置、完整来源、所选方向的预分配代与协议分母。
    /// - `outcome`：已确定的执行裁决，未知网络结果不能替代它。
    /// - `reason`：拒绝或保护所需的有限低敏原因。
    /// - `evidence`：应用或补偿成功的实际监听证据；准备结果不得携带它。
    ///
    /// 返回：完整可验证的待提交收据；构造成功仍不能代替持久head确认。
    pub(crate) fn settle(
        admission: Admission,
        expected: &Expected<'_>,
        outcome: Outcome,
        reason: Option<Reason>,
        evidence: Option<Arc<Evidence>>,
    ) -> Result<Self> {
        let receipt = Self {
            admission,
            outcome,
            reason,
            evidence,
        };
        receipt.validate(expected)?;
        Ok(receipt)
    }

    /// 业务作用：重新验证原意图、NASA身份及整批监听证据，文件完成不能冒充应用成功。
    ///
    /// 参数说明：
    /// - `expected`：从同一持久来源计划借用的完整方向合同。
    ///
    /// 返回：原稳定业务身份；错意图、错结果组合或不完整协议材料代均拒绝。
    pub(crate) fn validate(&self, expected: &Expected<'_>) -> Result<VerifiedIdentity> {
        let identity = self
            .admission
            .validate(expected.intent, expected.position)?;
        let needs_evidence =
            self.admission.step() == Step::Apply && self.outcome == Outcome::Succeeded;
        ensure!(
            (self.outcome == Outcome::Succeeded) == self.reason.is_none()
                && needs_evidence == self.evidence.is_some(),
            "material receipt result contract differs"
        );
        // 只允许完整原目标实际装载的目标代结算；HTTPS、HTTP3、L4任何缺项都保留未确认责任。
        if let Some(evidence) = &self.evidence {
            evidence.validate(expected.intent, expected.generations, expected.protocols)?;
        }
        result(&identity, self.outcome, self.reason).verified()
    }

    /// 业务作用：将同一稳定事实投影到当前重投或Resolve，收据本身仍保留原受理attempt。
    ///
    /// 参数说明：
    /// - `command`：当前已通过发行者、会话、窗口及读取授权的命令。
    /// - `expected`：原持久计划所选方向的完整验证合同。
    ///
    /// 返回：NASA可接受的当前命令结果；跨意图、跨步骤或跨执行/补偿方向拒绝。
    pub(crate) fn result_for(
        &self,
        command: &Command,
        expected: &Expected<'_>,
    ) -> Result<SagaResultEnvelope> {
        let original = self.validate(expected)?;
        let checked = command.validate()?;
        let identity = checked.identity();
        let effect_matches = if identity.phase == StepPhase::Resolve {
            original.effect == checked.resolved_effect()
        } else {
            original.effect == identity.effect && original.phase == identity.phase
        };
        // 相同操作名或节点名不足以继承收据；完整冻结意图、原节点位置和选择方向必须同时一致。
        ensure!(
            checked.intent_sha256() == self.admission.intent_sha256()
                && checked.step() == self.admission.step()
                && effect_matches,
            "material receipt does not answer this command"
        );
        let result = result(identity, self.outcome, self.reason);
        result.verified()?;
        Ok(result)
    }

    /// 业务作用：比较收据与原未决事实的全部身份，不能仅靠效果相同覆盖不同受理attempt。
    ///
    /// 参数说明：
    /// - `admission`：head当前承认的原受理记录。
    ///
    /// 返回：全部原生身份字段一致才为真，不复制证据或秘密。
    pub(crate) fn settles(&self, admission: &Admission) -> bool {
        self.admission == *admission
    }

    /// 业务作用：为状态机提供有限稳定裁决，不从一次请求失败推测文件是否已执行。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原持久收据的成功、拒绝或保护结果。
    pub(crate) fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// 业务作用：定位同一动作内的稳定效果槽，重投命令不能新增第二次文件副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原效果身份，使用前须完整验证收据。
    pub(crate) fn effect_id(&self) -> &str {
        self.admission.effect_id()
    }

    /// 业务作用：区分稳定收据所属的准备或文件步骤，不能凭结果名称猜测对应的副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原受理的有限步骤，完整身份仍由收据校验门验证。
    pub(crate) fn step(&self) -> Step {
        self.admission.step()
    }

    /// 业务作用：为所选方向提供原phase，实际观察必须按该方向的预分配代验证。
    ///
    /// 参数说明：
    /// - `intent`：同一槽原完整材料意图。
    /// - `position`：原节点步骤位置。
    ///
    /// 返回：已重新派生的执行或补偿phase；不代替完整观察和结果验证。
    pub(crate) fn phase(&self, intent: &Intent, position: Position) -> Result<StepPhase> {
        Ok(self.admission.validate(intent, position)?.phase)
    }
}

impl Reason {
    /// 业务作用：只向调度器交付固定原因，文件路径、秘密和内部错误链不进入收据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无外部插值的低敏业务原因码。
    fn as_str(self) -> &'static str {
        match self {
            Self::EffectNotAdmitted => "material_effect_not_admitted",
            Self::CandidateInvalid => "material_candidate_invalid",
            Self::SourceChanged => "material_source_changed",
            Self::BaselineChanged => "material_baseline_changed",
            Self::AuthorityChanged => "material_authority_changed",
            Self::GateHalted => "material_gate_halted",
            Self::PreparationInterrupted => "material_preparation_interrupted",
        }
    }
}

/// 业务作用：按当前已证NASA命令构造有限结果，重新投递只改变结果Inbox身份。
///
/// 参数说明：
/// - `identity`：NASA已验证的完整命令身份。
/// - `outcome`：同一业务效果已确认的稳定事实。
/// - `reason`：拒绝或保护的固定原因。
///
/// 返回：无秘密正文的结果信封；外层仍须通过NASA验证和持久提交门。
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
        status: match outcome {
            Outcome::Succeeded => "SUCCEEDED",
            Outcome::Rejected => "REJECTED",
            Outcome::Halted => "HALTED",
        }
        .into(),
        terminal_status: None,
        reason_code: reason.map(|value| value.as_str().into()),
    }
}
