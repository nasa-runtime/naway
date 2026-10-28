//! 安全终态从 NASA 原实例与全部步骤重新证明，手工关闭不能代替业务收敛。

use super::super::frozen::Frozen;
use crate::{admin::operations::model::Error, control::actions::release::Terminal};
use nasa::saga::{
    freeze_compensation_plan, ControlState, Direction, SagaStatus, StepCancelStatus,
    StepCompensationStatus, StepForwardStatus, StepJournalEntry, StepResolutionStatus,
};
use nasaga_backend::{SagaInstanceRow, SagaStepRow};

/// 业务作用：使用 NASA 公开补偿合同核对完整原步骤，终态不一致时禁止回收任何目标占位。
///
/// 参数说明：
/// - frozen：原审批冻结的完整目标和不可变定义。
/// - instance：同一推进事务读取的 NASA 原实例。
/// - steps：原实例全部已提交步骤，按定义顺序排列。
///
/// 返回：已证正常完成或补偿完成；其它业务/控制态保持未释放，缺失或矛盾证据返回不可用。
pub(super) fn terminal(
    frozen: &Frozen,
    instance: &SagaInstanceRow,
    steps: &[SagaStepRow],
) -> Result<Option<Terminal>, Error> {
    let first = frozen.targets.first().ok_or(Error::Unavailable)?;
    let definition = &frozen.definition;
    if instance.saga_id.as_str() != first.operation_id
        || instance.tenant.as_str() != first.baseline.cluster_id
        || instance.business_key.as_str() != first.operation_id
        || instance.workflow != *definition.name()
        || instance.definition_version != definition.version()
        || instance.definition_digest != definition.digest()
        || instance.version == 0
        || steps.len() != definition.steps().len()
        || steps
            .iter()
            .zip(definition.steps())
            .enumerate()
            .any(|(index, (row, step))| {
                row.step != *step.name() || row.ordinal as usize != index + 1
            })
    {
        return Err(Error::Unavailable);
    }
    // 未收敛、暂停或人工关闭都不提供释放证明；缺席目标仍由原分母保留。
    if instance.control_state != ControlState::Active {
        return Ok(None);
    }
    let terminal = match instance.status {
        SagaStatus::Completed => Terminal::Completed,
        SagaStatus::Compensated => Terminal::Compensated,
        _ => return Ok(None),
    };
    if steps.iter().any(|step| {
        step.cancel_status != StepCancelStatus::None
            || matches!(
                step.resolution_status,
                StepResolutionStatus::Pending | StepResolutionStatus::Halted
            )
    }) {
        return Err(Error::Unavailable);
    }
    match terminal {
        Terminal::Completed => {
            if instance.direction != Direction::Forward
                || instance.compensation_plan_version.is_some()
                || steps.iter().any(|step| {
                    step.forward_status != StepForwardStatus::Succeeded
                        || step.compensation_status != StepCompensationStatus::None
                        || step.compensation_plan_version.is_some()
                        || step.compensation_order.is_some()
                })
            {
                return Err(Error::Unavailable);
            }
        }
        Terminal::Compensated => {
            let journal = steps
                .iter()
                .map(|step| StepJournalEntry::new(step.step.clone(), step.forward_status))
                .collect::<Vec<_>>();
            // 原计划必须按公开算法从同一完整事实得到，不能按当前在线节点重选或复制补偿算法。
            let plan =
                freeze_compensation_plan(definition, &journal).map_err(|_| Error::Unavailable)?;
            if instance.direction != Direction::Compensating
                || instance.compensation_plan_version.as_deref() != Some(plan.version())
            {
                return Err(Error::Unavailable);
            }
            for step in steps {
                let entry = plan
                    .entries()
                    .iter()
                    .find(|entry| entry.step() == &step.step);
                let valid = match entry {
                    Some(entry) => {
                        step.compensation_status == StepCompensationStatus::Succeeded
                            && step.compensation_plan_version.as_deref() == Some(plan.version())
                            && step.compensation_order == Some(entry.order())
                    }
                    None => {
                        step.compensation_status == StepCompensationStatus::None
                            && step.compensation_plan_version.is_none()
                            && step.compensation_order.is_none()
                    }
                };
                if !valid {
                    return Err(Error::Unavailable);
                }
            }
        }
    }
    Ok(Some(terminal))
}

/// 业务作用：让目标正向投影与 NASA 原步骤逐项对应，缺失回报不能推断为拒绝。
///
/// 参数说明：
/// - step：已通过整体安全终态检查的原步骤。
///
/// 返回：未受理为空、确定成功或拒绝为相应事实；未知、取消或矛盾身份不授予释放资格。
pub(super) fn forward(step: &SagaStepRow) -> Result<Option<&'static str>, Error> {
    match step.forward_status {
        StepForwardStatus::Pending
            if step.execute_attempt.is_none()
                && step.execute_command_id.is_none()
                && step.execute_effect_id.is_none()
                && step.resolve_attempt.is_none()
                && step.resolution_status == StepResolutionStatus::None =>
        {
            Ok(None)
        }
        StepForwardStatus::Succeeded => Ok(Some("SUCCEEDED")),
        StepForwardStatus::Rejected => Ok(Some("REJECTED")),
        _ => Err(Error::Unavailable),
    }
}

/// 业务作用：只把原计划内已完成补偿映射为成功，空补偿状态不会伪造节点回报。
///
/// 参数说明：
/// - step：已经核对原补偿计划归属的步骤。
///
/// 返回：无补偿为空、确定成功为稳定投影；未决或保护状态拒绝。
pub(super) fn compensation(step: &SagaStepRow) -> Result<Option<&'static str>, Error> {
    match step.compensation_status {
        StepCompensationStatus::None => Ok(None),
        StepCompensationStatus::Succeeded => Ok(Some("SUCCEEDED")),
        _ => Err(Error::Unavailable),
    }
}
