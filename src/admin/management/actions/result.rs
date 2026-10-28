//! 结果只携带封闭状态，NASA 身份始终从发行端保留的精确命令派生。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use crate::{
    admin::management::protocol,
    control::actions::{command::Command, definition},
};
use crate::{
    admin::management::protocol::{ActionOutcome, ActionReason},
    control::journal::EffectState,
};
use nasa::grpc::Status;
#[cfg(feature = "admin-operations-workflow-pgsql")]
use nasaga_runtime_core::{derive_result_event_id, SagaResultEnvelope};

/// 业务作用：把已持久效果或明确未决状态编码为有限结果，不泄露本地错误链和文件路径。
///
/// 参数说明：
/// - `state`：唯一节点 owner 查询得到的效果事实。
///
/// 返回：可发送的封闭状态与原因；非法稳定收据或未知原因拒绝，不猜测执行结果。
pub(super) fn encode(state: EffectState) -> Result<(i32, i32), Status> {
    let (outcome, reason) = classify(state)?;
    Ok((outcome as i32, reason as i32))
}

/// 业务作用：从本机持久事实生成本次命令的 NASA 回报，不组装网络消息或沿用旧命令事件身份。
///
/// 参数说明：
/// - command：当前已经验签并持有真实许可的命令。
/// - state：真实节点工作返回的原生效果事实。
///
/// 返回：稳定事实绑定本次命令；未知或关闭为空，非法收据拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn from_state(
    command: &Command,
    state: EffectState,
) -> Result<Option<SagaResultEnvelope>, Status> {
    let (outcome, reason) = classify(state)?;
    bind(command, outcome, reason)
}

/// 业务作用：在两种传输路径共用的边界校验原生事实，只允许公开的有限结果与原因。
///
/// 参数说明：
/// - state：原持久节点事实，包含的稳定收据必须通过 NASA 合同。
///
/// 返回：已验证的有限枚举，不分配协议消息；未授权状态或原因拒绝。
fn classify(state: EffectState) -> Result<(ActionOutcome, ActionReason), Status> {
    let (outcome, reason) = match state {
        EffectState::Vacant | EffectState::Pending(_) => (ActionOutcome::Pending, None),
        EffectState::Closed => (ActionOutcome::Gone, None),
        EffectState::Stable(result) => {
            result
                .verified()
                .map_err(|_| Status::data_loss("invalid node effect receipt"))?;
            if result.terminal_status.is_some() {
                return Err(Status::data_loss("unexpected terminal node receipt"));
            }
            let outcome = match result.status.as_str() {
                "SUCCEEDED" => ActionOutcome::Succeeded,
                "REJECTED" => ActionOutcome::Rejected,
                "HALTED" => ActionOutcome::Halted,
                _ => return Err(Status::data_loss("invalid stable node outcome")),
            };
            (outcome, result.reason_code)
        }
    };
    let reason = match reason.as_deref() {
        None => ActionReason::Unspecified,
        Some("node_candidate_invalid") => ActionReason::CandidateInvalid,
        Some("node_baseline_changed") => ActionReason::BaselineChanged,
        Some("node_publication_conflict") => ActionReason::PublicationConflict,
        Some("node_authority_changed") => ActionReason::AuthorityChanged,
        Some("node_gate_halted") => ActionReason::GateHalted,
        Some("node_preparation_interrupted") => ActionReason::PreparationInterrupted,
        Some("node_effect_not_admitted") => ActionReason::EffectNotAdmitted,
        _ => return Err(Status::data_loss("invalid node receipt reason")),
    };
    validate(outcome, reason)?;
    Ok((outcome, reason))
}

/// 业务作用：将当前投递的有限回报绑定完整 NASA 身份，节点不能用自报身份替其它目标推进工作流。
///
/// 参数说明：
/// - `command`：已经由当前目标槽保留的原签名命令。
/// - `request`：通过节点、会话和 offer_id 门之后的有限状态。
///
/// 返回：稳定结果为 Some，Pending/Gone 为 None；非法组合或 NASA 合同不成立拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn decode(
    command: &Command,
    request: &protocol::ActionResultRequest,
) -> Result<Option<SagaResultEnvelope>, Status> {
    let outcome = ActionOutcome::try_from(request.outcome)
        .map_err(|_| Status::invalid_argument("invalid node outcome"))?;
    let reason = ActionReason::try_from(request.reason)
        .map_err(|_| Status::invalid_argument("invalid node reason"))?;
    bind(command, outcome, reason)
}

/// 业务作用：以发行端原命令派生完整回报身份，本机和网络收据遵循相同的业务结果合同。
///
/// 参数说明：
/// - command：保留的完整本次命令。
/// - outcome：已解析的有限状态。
/// - reason：已解析的有限原因。
///
/// 返回：稳定状态产生经过 NASA 验证的回报；非法组合拒绝，未知和关闭不推进工作流。
#[cfg(feature = "admin-operations-workflow-pgsql")]
fn bind(
    command: &Command,
    outcome: ActionOutcome,
    reason: ActionReason,
) -> Result<Option<SagaResultEnvelope>, Status> {
    validate(outcome, reason)?;
    let status = match outcome {
        ActionOutcome::Succeeded => "SUCCEEDED",
        ActionOutcome::Rejected => "REJECTED",
        ActionOutcome::Halted => "HALTED",
        ActionOutcome::Pending | ActionOutcome::Gone => return Ok(None),
        ActionOutcome::Unspecified => {
            return Err(Status::invalid_argument("unspecified node outcome"))
        }
    };
    let definition = definition::cached(command.intent.target_count as usize)
        .map_err(|_| Status::failed_precondition("node definition unavailable"))?;
    let checked = command
        .validate(&definition)
        .map_err(|_| Status::failed_precondition("node command differs"))?;
    if reason == ActionReason::EffectNotAdmitted
        && (command.delivery.resolve_compensation
            || !matches!(
                checked.identity().phase,
                nasa::saga::StepPhase::Execute | nasa::saga::StepPhase::Resolve
            ))
    {
        // 否定证明只回答原正向效果，不能替补偿提供成功或失败事实。
        return Err(Status::invalid_argument(
            "node nonadmission result phase differs",
        ));
    }
    let original = &command.envelope;
    let result = SagaResultEnvelope {
        event_id: derive_result_event_id(&original.command_id),
        saga_id: original.saga_id.clone(),
        tenant_id: original.tenant_id.clone(),
        workflow: original.workflow.clone(),
        definition_version: original.definition_version,
        definition_digest: original.definition_digest.clone(),
        step: original.step.clone(),
        phase: original.phase.clone(),
        attempt: original.attempt,
        effect_id: original.effect_id.clone(),
        command_id: original.command_id.clone(),
        status: status.into(),
        terminal_status: None,
        reason_code: match reason {
            ActionReason::Unspecified => None,
            ActionReason::CandidateInvalid => Some("node_candidate_invalid"),
            ActionReason::BaselineChanged => Some("node_baseline_changed"),
            ActionReason::PublicationConflict => Some("node_publication_conflict"),
            ActionReason::AuthorityChanged => Some("node_authority_changed"),
            ActionReason::GateHalted => Some("node_gate_halted"),
            ActionReason::PreparationInterrupted => Some("node_preparation_interrupted"),
            ActionReason::EffectNotAdmitted => Some("node_effect_not_admitted"),
        }
        .map(str::to_owned),
    };
    result
        .verified()
        .map_err(|_| Status::invalid_argument("node result contract differs"))?;
    Ok(Some(result))
}

/// 业务作用：拒绝把未知状态当成功、把成功附加失败原因或将空原因当成确定拒绝。
///
/// 参数说明：
/// - `outcome`：已解析的有限结果。
/// - `reason`：已解析的有限原因。
///
/// 返回：组合符合持久收据合同才成功；没有业务状态的消息始终拒绝。
fn validate(outcome: ActionOutcome, reason: ActionReason) -> Result<(), Status> {
    if outcome == ActionOutcome::Unspecified
        || (reason == ActionReason::EffectNotAdmitted && outcome != ActionOutcome::Rejected)
        || matches!(outcome, ActionOutcome::Rejected | ActionOutcome::Halted)
            == (reason == ActionReason::Unspecified)
    {
        return Err(Status::invalid_argument("node outcome and reason differ"));
    }
    Ok(())
}
