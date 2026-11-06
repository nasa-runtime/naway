//! 节点持久记录与结果交付共用同一阶段合同，稳定字符串不能替代原效果和文件方向。

use super::{command::Step, release::Terminal};
use crate::control::actions::receipt::Outcome;
use anyhow::{ensure, Result};
use nasa::saga::StepPhase;
use serde::{Deserialize, Serialize};

/// 原材料责任阶段，文件方向、真实监听确认与精确清理分别表达。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Reserved,
    Prepared,
    Invalidated,
    Forward,
    Applied,
    Backward,
    Reverted,
    Rejected,
    Compensated,
    Protected,
    Cleaning,
}

/// 全批已决定的唯一文件方向，补偿不得借用原材料代。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    Forward,
    Backward,
}

/// 与文件路径无关的责任不变量，供持久owner和完整结果共同验证。
pub(crate) struct State {
    pub prepared: bool,
    pub direction: Option<Direction>,
    pub compensation: bool,
    pub protection: bool,
    pub terminal: Option<Terminal>,
}

impl State {
    /// 业务作用：以原效果槽同时核对阶段、准备完整性、文件方向与共享终态，网络结果不能放宽本机合同。
    ///
    /// 参数说明：
    /// - `stage`：同一原子事实的材料阶段。
    /// - `pending`：prepare、apply及各自补偿的四个原未决槽。
    /// - `outcomes`：相同槽顺序下已经完整验证的稳定收据。
    ///
    /// 返回：全部阶段不变量同时成立时成功；缺项或自相矛盾拒绝，不授予文件写权。
    pub(crate) fn validate(
        &self,
        stage: Stage,
        pending: [bool; 4],
        outcomes: [Option<Outcome>; 4],
    ) -> Result<()> {
        // 原准备成功收据永不撤销；补偿或清理后的无文件方向不能抹去曾完整持久准备的事实。
        ensure!(
            self.prepared == (outcomes[0] == Some(Outcome::Succeeded)),
            "material preparation history contradicts its receipt"
        );
        ensure!(
            self.matches_stage(stage, pending, outcomes),
            "material stage contradicts its effects"
        );
        ensure!(
            !self.protection || stage == Stage::Protected,
            "material protection stage differs"
        );
        self.validate_direction(stage)?;
        if let Some(terminal) = self.terminal {
            ensure!(
                stage == Stage::Cleaning
                    && match terminal {
                        Terminal::Completed => completed(pending, outcomes),
                        Terminal::Compensated =>
                            compensated(pending, outcomes) || rejected(pending, outcomes),
                    },
                "material cleanup contradicts terminal facts"
            );
        } else {
            ensure!(
                stage != Stage::Cleaning,
                "material cleanup terminal proof absent"
            );
        }
        Ok(())
    }

    /// 业务作用：让文件方向只由全批阶段授予，准备、拒绝和清理记录均不能继续执行活动文件写入。
    ///
    /// 参数说明：
    /// - `stage`：外层材料阶段。
    ///
    /// 返回：准备完整性、方向与补偿代对应时成功；任意少项或越阶段写权拒绝。
    fn validate_direction(&self, stage: Stage) -> Result<()> {
        let direction = match stage {
            Stage::Forward | Stage::Applied => Some(Direction::Forward),
            Stage::Backward | Stage::Reverted => Some(Direction::Backward),
            Stage::Protected => self.direction,
            _ => None,
        };
        ensure!(
            self.direction == direction
                && (self.direction.is_none() || self.prepared)
                && (self.direction != Some(Direction::Backward) || self.compensation)
                && (!matches!(stage, Stage::Reserved | Stage::Rejected) || !self.prepared)
                && (!matches!(
                    stage,
                    Stage::Prepared
                        | Stage::Invalidated
                        | Stage::Forward
                        | Stage::Applied
                        | Stage::Backward
                        | Stage::Reverted
                ) || self.prepared)
                && (!self.compensation
                    || matches!(
                        stage,
                        Stage::Backward
                            | Stage::Reverted
                            | Stage::Compensated
                            | Stage::Cleaning
                            | Stage::Protected
                    )),
            "material file direction differs"
        );
        Ok(())
    }

    /// 业务作用：把两步骤两方向限制为四个明确效果，未确认应用可被已确认补偿保留但不能变成成功。
    ///
    /// 参数说明：
    /// - `stage`：当前材料责任阶段。
    /// - `pending`：原prepare/apply及各自补偿的未决身份槽。
    /// - `outcomes`：同一顺序下已验证的稳定事实。
    ///
    /// 返回：仅允许本实现声明的阶段组合，HALTED保留保护而不自动重试写入。
    fn matches_stage(
        &self,
        stage: Stage,
        pending: [bool; 4],
        outcomes: [Option<Outcome>; 4],
    ) -> bool {
        use Outcome::{Halted, Rejected, Succeeded};
        let [prepare, apply, undo_prepare, undo_apply] = outcomes;
        match stage {
            Stage::Reserved => pending == [true, false, false, false] && outcomes == [None; 4],
            Stage::Prepared => {
                pending == [false; 4] && outcomes == [Some(Succeeded), None, None, None]
            }
            Stage::Invalidated => {
                pending == [false; 4]
                    && prepare == Some(Succeeded)
                    && matches!(apply, None | Some(Rejected))
                    && undo_prepare.is_none()
                    && undo_apply.is_none()
            }
            Stage::Forward => {
                pending == [false, true, false, false]
                    && outcomes == [Some(Succeeded), None, None, None]
            }
            Stage::Applied => completed(pending, outcomes),
            Stage::Backward => {
                prepare == Some(Succeeded)
                    && !pending[0]
                    && !pending[2]
                    && pending[3]
                    && undo_prepare.is_none()
                    && undo_apply.is_none()
                    && match apply {
                        None => pending[1],
                        Some(Succeeded) => !pending[1],
                        _ => false,
                    }
            }
            Stage::Reverted => {
                pending == [false, apply.is_none(), false, false]
                    && prepare == Some(Succeeded)
                    && matches!(apply, None | Some(Succeeded))
                    && undo_prepare.is_none()
                    && undo_apply == Some(Succeeded)
            }
            Stage::Rejected => rejected(pending, outcomes),
            Stage::Compensated => compensated(pending, outcomes),
            Stage::Protected => self.protection || outcomes.contains(&Some(Halted)),
            Stage::Cleaning => {
                completed(pending, outcomes)
                    || compensated(pending, outcomes)
                    || rejected(pending, outcomes)
            }
        }
    }
}

/// 业务作用：要求节点准备和全部实际协议安装均有稳定成功，文件完成或未决观察都不能释放成功任务。
///
/// 参数说明：
/// - `pending`：四个原业务效果的未决槽。
/// - `outcomes`：已经验证的完整稳定结果。
///
/// 返回：恰好prepare和apply成功且没有补偿事实时为真。
fn completed(pending: [bool; 4], outcomes: [Option<Outcome>; 4]) -> bool {
    pending == [false; 4]
        && outcomes
            == [
                Some(Outcome::Succeeded),
                Some(Outcome::Succeeded),
                None,
                None,
            ]
}

/// 业务作用：只把未形成文件方向的明确准备拒绝作为可释放失败，不从缺失应用收据推断未执行。
///
/// 参数说明：
/// - `pending`：四个原业务效果的未决槽。
/// - `outcomes`：已经验证的完整稳定结果。
///
/// 返回：仅原prepare已拒绝且无其它效果时为真。
fn rejected(pending: [bool; 4], outcomes: [Option<Outcome>; 4]) -> bool {
    pending == [false; 4] && outcomes == [Some(Outcome::Rejected), None, None, None]
}

/// 业务作用：以完整补偿事实关闭本机责任，保留原应用未知身份而不捏造原应用成功或未执行。
///
/// 参数说明：
/// - `pending`：四个原业务效果的未决槽。
/// - `outcomes`：已确认的准备、应用及各自补偿结果。
///
/// 返回：原prepare已结算且准备补偿成功，任何已执行或未决apply都有实际安装补偿证据时为真。
fn compensated(pending: [bool; 4], outcomes: [Option<Outcome>; 4]) -> bool {
    use Outcome::{Rejected, Succeeded};
    let [prepare, apply, undo_prepare, undo_apply] = outcomes;
    !pending[0]
        && !pending[2]
        && !pending[3]
        && matches!(prepare, Some(Succeeded | Rejected))
        && undo_prepare == Some(Succeeded)
        && matches!(apply, None | Some(Succeeded | Rejected))
        && matches!(undo_apply, None | Some(Succeeded))
        && (apply != Some(Succeeded) || undo_apply == Some(Succeeded))
        && (prepare != Some(Rejected) || (apply.is_none() && undo_apply.is_none() && !pending[1]))
        && (!pending[1]
            || (apply.is_none() && prepare == Some(Succeeded) && undo_apply == Some(Succeeded)))
}

/// 业务作用：把NASA业务phase和节点步骤映射到四个固定槽，查询和取消不能生成持久副作用身份。
///
/// 参数说明：
/// - `step`：原节点prepare或apply步骤。
/// - `phase`：NASA已重新派生的原phase。
///
/// 返回：有限效果槽；Resolve或Cancel拒绝。
pub(crate) fn slot(step: Step, phase: StepPhase) -> Result<usize> {
    let base = match phase {
        StepPhase::Execute => 0,
        StepPhase::Compensate => 2,
        _ => anyhow::bail!("material query cannot occupy an effect slot"),
    };
    Ok(base + usize::from(step == Step::Apply))
}
