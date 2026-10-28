//! 有效性判定不改变 NASA 实例；撤下命令不代表参与方成功或安全释放。

use super::{Error, Pending};
use nasa::saga::{
    ControlState, Direction, SagaStatus, StepAttemptStatus, StepCompensationStatus,
    StepForwardStatus, StepPhase, StepResolutionStatus,
};
use nasaga_backend::{SagaInstanceRow, SagaStepAttemptRow, SagaStepRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::admin::operations) enum Disposition {
    Deliver {
        resolve_compensation: bool,
    },
    Retired,
    Deferred,
}

/// 业务作用：只按同一已提交快照中的确定证据撤下旧命令，未知与暂停不会被转换成节点结果。
///
/// 参数说明：
/// - `pending`：重新派生身份并绑定固定定义的持久命令。
/// - `instance`：同一可重复读事务取得的实例。
/// - `step`：命令所属步骤的完整当前投影。
/// - `attempt`：该命令原 attempt 的真实日志。
///
/// 返回：可发送的方向、已失效或暂缓；缺失、跨身份和互相矛盾的投影拒绝判断。
pub(super) fn classify(
    pending: &Pending,
    instance: &SagaInstanceRow,
    step: &SagaStepRow,
    attempt: &SagaStepAttemptRow,
) -> Result<Disposition, Error> {
    let identity = &pending.identity;
    if instance.saga_id != identity.saga_id
        || instance.tenant != identity.tenant
        || instance.workflow != identity.workflow
        || instance.definition_version != identity.definition_version
        || instance.definition_digest != identity.definition_digest
        || instance.version == 0
        || step.step != identity.step
        || attempt.step != identity.step
        || attempt.phase != identity.phase
        || attempt.attempt != identity.attempt
        || attempt.effect_id != pending.envelope.effect_id
        || attempt.command_id != pending.envelope.command_id
    {
        return Err(Error::Unavailable);
    }
    let (number, effect, command) = match identity.phase {
        StepPhase::Execute => (
            step.execute_attempt,
            &step.execute_effect_id,
            &step.execute_command_id,
        ),
        StepPhase::Compensate => (
            step.compensate_attempt,
            &step.compensate_effect_id,
            &step.compensate_command_id,
        ),
        StepPhase::Resolve => (
            step.resolve_attempt,
            &step.resolve_effect_id,
            &step.resolve_command_id,
        ),
        StepPhase::Cancel => return Err(Error::Invalid),
    };
    let number = number.ok_or(Error::Unavailable)?;
    let projected = nasa::saga::CommandId::derive(
        &identity.effect,
        nasa::saga::AttemptNo::new(number).map_err(|_| Error::Unavailable)?,
    )
    .to_string();
    if number < identity.attempt.get()
        || effect.as_deref() != Some(pending.envelope.effect_id.as_str())
        || command.as_deref() != Some(projected.as_str())
    {
        return Err(Error::Unavailable);
    }
    // 终态、同 attempt 已有结果或更高 attempt 均不再需要重发；这些事实不说明目标材料可以清理。
    if instance.status.is_terminal()
        || attempt.status != StepAttemptStatus::Started
        || number > identity.attempt.get()
    {
        return Ok(Disposition::Retired);
    }
    // 暂停和人工保护可经受控流程恢复，不能仅据“不允许自动动作”丢弃尚未替代的命令。
    if instance.control_state != ControlState::Active
        || !instance.status.allows_automatic_commands()
    {
        return Ok(Disposition::Deferred);
    }
    let current = instance.current_step.as_ref().ok_or(Error::Unavailable)?;
    let definition = crate::control::actions::definition::cached(pending.target_count)
        .map_err(|_| Error::Unavailable)?;
    if definition.step(current).is_none() {
        return Err(Error::Unavailable);
    }
    if current != &identity.step {
        // 当前业务步骤已经离开此命令；原效果仍由 NASA 的迟到结果和补偿计划裁决。
        return Ok(Disposition::Retired);
    }
    let (phase, resolve_compensation) = match (instance.status, instance.direction) {
        (SagaStatus::Running, Direction::Forward)
            if step.forward_status == StepForwardStatus::Pending =>
        {
            (StepPhase::Execute, false)
        }
        (SagaStatus::Compensating, Direction::Compensating)
            if step.compensation_status == StepCompensationStatus::Pending =>
        {
            (StepPhase::Compensate, false)
        }
        (SagaStatus::WaitingResolution, Direction::Forward)
            if step.forward_status == StepForwardStatus::Unknown
                && step.resolution_status == StepResolutionStatus::Pending =>
        {
            (StepPhase::Resolve, false)
        }
        (SagaStatus::WaitingResolution, Direction::Compensating)
            if step.compensation_status == StepCompensationStatus::Unknown
                && step.resolution_status == StepResolutionStatus::Pending =>
        {
            (StepPhase::Resolve, true)
        }
        _ => return Err(Error::Unavailable),
    };
    if identity.phase != phase {
        // 超时后的 Execute 可能仍为 STARTED，但当前实例和步骤已要求只读查询，禁止重新签发旧写。
        return Ok(Disposition::Retired);
    }
    Ok(Disposition::Deliver {
        resolve_compensation,
    })
}
