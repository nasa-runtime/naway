//! 完整终态复验只依赖原NASA定义和全部步骤，业务域各自核对真实节点证据。

use crate::admin::operations::model::Error;
use nasa::saga::{
    freeze_compensation_plan, ControlState, Direction, SagaStatus, StepCancelStatus,
    StepCompensationStatus, StepForwardStatus, StepJournalEntry, StepResolutionStatus,
};
use nasaga_backend::{SagaInstanceRow, SagaStepRow};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::admin::operations) enum Terminal {
    Completed,
    Compensated,
}

/// 业务作用：使用 NASA 公开补偿合同核对完整原步骤，终态不一致时禁止回收任何目标占位。
///
/// 参数说明：
/// - definition：原任务登记的不可变定义。
/// - operation：原任务及业务键的唯一身份。
/// - cluster：永久绑定的原集群。
/// - instance：同一推进事务读取的 NASA 原实例。
/// - steps：原实例全部已提交步骤，按定义顺序排列。
///
/// 返回：已证正常完成或补偿完成；其它业务/控制态保持未释放，缺失或矛盾证据返回不可用。
pub(in crate::admin::operations) fn terminal(
    definition: &nasa::saga::WorkflowDefinition,
    operation: &str,
    cluster: &str,
    instance: &SagaInstanceRow,
    steps: &[SagaStepRow],
) -> Result<Option<Terminal>, Error> {
    if instance.saga_id.as_str() != operation
        || instance.tenant.as_str() != cluster
        || instance.business_key.as_str() != operation
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
