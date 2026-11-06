//! 配置终态与目标投影分别核对，原完整NASA终态合同由共享校验器复用。

use super::super::frozen::Frozen;
use crate::{
    admin::operations::{model::Error, workflow::completion},
    control::actions::release::Terminal,
};
use nasa::saga::{StepCompensationStatus, StepForwardStatus, StepResolutionStatus};
use nasaga_backend::{SagaInstanceRow, SagaStepRow};

/// 业务作用：以配置原定义核对完整NASA安全终态，材料域的定义不能成为配置释放证明。
///
/// 参数说明：
/// - frozen：原配置批准和完整目标集合。
/// - instance：同一推进事务中的原实例。
/// - steps：按原定义排列的全部步骤事实。
///
/// 返回：原配置任务安全完成或补偿完成时的终态；未收敛为空，不一致证据拒绝。
pub(super) fn terminal(
    frozen: &Frozen,
    instance: &SagaInstanceRow,
    steps: &[SagaStepRow],
) -> Result<Option<Terminal>, Error> {
    let first = frozen.targets.first().ok_or(Error::Unavailable)?;
    completion::terminal(
        &frozen.definition,
        &first.operation_id,
        &first.baseline.cluster_id,
        instance,
        steps,
    )
    .map(|terminal| {
        terminal.map(|terminal| match terminal {
            completion::Terminal::Completed => Terminal::Completed,
            completion::Terminal::Compensated => Terminal::Compensated,
        })
    })
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
