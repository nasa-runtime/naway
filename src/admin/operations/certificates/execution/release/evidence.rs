//! NASA终态逐节点对应完整原报告，未知应用只有实际补偿证据才能结束保留责任。

use crate::{
    admin::operations::model::Error,
    control::{
        actions::receipt::Outcome,
        material::{
            execution::{
                command::Step, position::Position, release::Terminal, report::Report, state::Stage,
            },
            node::Intent,
        },
    },
};
use nasa::saga::{StepCompensationStatus, StepForwardStatus, StepResolutionStatus};
use nasaga_backend::SagaStepRow;

/// 业务作用：逐项核对原节点的两步骤两方向，完整报告不得用当前成功覆盖未决历史或缺席节点。
///
/// 参数说明：
/// - `intent`：原完整批准中的该节点意图。
/// - `position`：原物理节点位置。
/// - `terminal`：已从全部NASA步骤证明的安全终态。
/// - `report`：共享存储已确认的完整节点事实；未曾投递的后续节点可为空。
/// - `prepare`：原节点准备步骤的NASA事实。
/// - `apply`：原节点应用步骤的NASA事实。
///
/// 返回：全部原效果与本机可清理阶段对应时成功；缺收据、未知无证据、错方向或保护责任拒绝。
pub(in crate::admin::operations::certificates::execution) fn validate(
    intent: &Intent,
    position: Position,
    terminal: Terminal,
    report: Option<&Report>,
    prepare: &SagaStepRow,
    apply: &SagaStepRow,
) -> Result<(), Error> {
    let mut outcomes = [None; 4];
    let mut pending = [false; 4];
    let mut absent = None;
    if let Some(report) = report {
        report
            .validate(intent, position)
            .map_err(|_| Error::Conflict)?;
        // 原共享事实必须已经达到本机允许清理的阶段，单独NASA终态不能替代真实安装或补偿确认。
        let releasable = match terminal {
            Terminal::Completed => report.stage == Stage::Applied,
            Terminal::Compensated => matches!(report.stage, Stage::Compensated | Stage::Rejected),
        };
        if !releasable || report.protection.is_some() || report.release.is_some() {
            return Err(Error::Conflict);
        }
        for receipt in &report.receipts {
            let phase = receipt
                .phase(intent, position)
                .map_err(|_| Error::Conflict)?;
            let slot = crate::control::material::execution::state::slot(receipt.step(), phase)
                .map_err(|_| Error::Conflict)?;
            outcomes[slot] = Some(receipt.outcome());
        }
        for admission in &report.admissions {
            let identity = admission
                .validate(intent, position)
                .map_err(|_| Error::Conflict)?;
            let slot =
                crate::control::material::execution::state::slot(admission.step(), identity.phase)
                    .map_err(|_| Error::Conflict)?;
            pending[slot] = true;
        }
        absent = report.absence.as_ref().map(|proof| proof.step());
    } else if terminal != Terminal::Compensated {
        return Err(Error::Conflict);
    }
    for (index, (name, step)) in [(Step::Prepare, prepare), (Step::Apply, apply)]
        .into_iter()
        .enumerate()
    {
        let forward = match step.forward_status {
            StepForwardStatus::Pending => {
                step.execute_attempt.is_none()
                    && step.execute_effect_id.is_none()
                    && step.execute_command_id.is_none()
                    && step.resolve_attempt.is_none()
                    && step.resolution_status == StepResolutionStatus::None
                    && outcomes[index].is_none()
                    && !pending[index]
                    && absent != Some(name)
            }
            StepForwardStatus::Succeeded => {
                outcomes[index] == Some(Outcome::Succeeded) && !pending[index]
            }
            StepForwardStatus::Rejected => {
                !pending[index]
                    && (outcomes[index] == Some(Outcome::Rejected) || absent == Some(name))
            }
            // 完整补偿可保留原应用未知；它必须仍有原受理或后来稳定事实，不能用空报告抹去该责任。
            StepForwardStatus::Unknown => {
                terminal == Terminal::Compensated && (pending[index] || outcomes[index].is_some())
            }
            _ => false,
        };
        let compensation = match step.compensation_status {
            StepCompensationStatus::None => outcomes[index + 2].is_none() && !pending[index + 2],
            StepCompensationStatus::Succeeded => {
                outcomes[index + 2] == Some(Outcome::Succeeded) && !pending[index + 2]
            }
            _ => false,
        };
        if !forward || !compensation || step.step.as_str() != name.name(position) {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
