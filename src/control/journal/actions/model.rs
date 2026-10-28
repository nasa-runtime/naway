//! 动作阶段、有限效果与正文归属的完整性合同，不从缺失收据推断未执行。

use super::super::{
    identity::Identity,
    local::{Direction, Plan},
};
use crate::control::actions::{
    absence::Absence,
    command::{Intent, Step},
    definition,
    effect::Admission,
    receipt::{Outcome, Receipt},
};
use anyhow::{ensure, Result};
use nasa::saga::StepPhase;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Preparing,
    Prepared,
    Invalidated,
    Forward,
    Applied,
    Backward,
    Reverted,
    Rejected,
    Compensated,
    Protected,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control::journal) struct Publication {
    pub boot_id: String,
    pub version: u64,
    pub fingerprint: u64,
    pub direction: Direction,
    pub owned: bool,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control::journal) struct Record {
    pub schema: u32,
    pub intent: Intent,
    pub intent_sha256: [u8; 32],
    pub fence: u64,
    pub stage: Stage,
    pub dependencies_sha256: [u8; 32],
    pub baseline_dependencies_sha256: [u8; 32],
    pub candidate_fingerprint: Option<u64>,
    pub files: Option<Plan>,
    pub admissions: Vec<Admission>,
    pub receipts: Vec<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absence: Option<Absence>,
    pub publication: Option<Publication>,
}

impl Record {
    /// 业务作用：限定可与本地文件决定共存的动作事实，仍持补偿材料或未知效果时禁止复用正文槽。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有无正文、无未决身份的明确失效或终态允许普通 writer。
    pub(in crate::control::journal) fn allows_local(&self) -> bool {
        matches!(
            self.stage,
            Stage::Invalidated | Stage::Rejected | Stage::Compensated
        ) && self.files.is_none()
            && self.admissions.is_empty()
    }

    /// 业务作用：保护已经持久的原始意图、文件计划和效果事实，后续步骤不能重新解释先前的执行身份。
    ///
    /// 参数说明：
    /// - `next`：已经完成结构与阶段校验的下一动作状态。
    ///
    /// 返回：只允许既定状态推进、单调 fence 与原 Admission 的准确收尾；保护态不自动解除。
    pub(in crate::control::journal) fn require_successor(&self, next: &Self) -> Result<()> {
        ensure!(
            self.stage != Stage::Protected
                && self.intent == next.intent
                && self.intent_sha256 == next.intent_sha256
                && self.dependencies_sha256 == next.dependencies_sha256
                && self.baseline_dependencies_sha256 == next.baseline_dependencies_sha256
                && next.fence >= self.fence
                && next.receipts.starts_with(&self.receipts)
                && self
                    .absence
                    .as_ref()
                    .is_none_or(|proof| next.absence.as_ref() == Some(proof))
                && self
                    .candidate_fingerprint
                    .is_none_or(|value| next.candidate_fingerprint == Some(value)),
            "node action cannot replace durable facts"
        );
        for admission in &self.admissions {
            // 原 attempt 和 recovery 身份随事实保留，迟到重试只能查询，不能把未知效果换成新命令。
            ensure!(
                next.admissions.contains(admission)
                    || next
                        .receipts
                        .iter()
                        .any(|receipt| receipt.settles(admission)),
                "node action lost an unresolved admission"
            );
        }
        if next.stage == Stage::Protected {
            // 人工保护保留原恢复材料和发布证据，不能一边声明停止自动推进一边丢弃原文件权威。
            ensure!(
                self.files == next.files && self.publication == next.publication,
                "node action protection lost recovery evidence"
            );
        }
        match (&self.files, &next.files) {
            (Some(old), Some(new)) => {
                let mut expected = old.clone();
                expected.direction = new.direction;
                ensure!(expected == *new, "node action file plan changed");
            }
            (None, Some(_)) => anyhow::bail!("node action cannot restore discarded file authority"),
            _ => {}
        }
        if self.publication.as_ref().is_some_and(|value| !value.owned) {
            // 一旦主动撤销覆盖权，即使内容或版本再次相同也不能通过后续状态重获它。
            ensure!(
                next.publication.as_ref().is_none_or(|value| !value.owned),
                "node action publication ownership cannot resume"
            );
        }
        let allowed = self.stage == next.stage
            || next.stage == Stage::Protected
            || match self.stage {
                Stage::Preparing => matches!(next.stage, Stage::Prepared | Stage::Rejected),
                Stage::Prepared => matches!(
                    next.stage,
                    Stage::Invalidated | Stage::Forward | Stage::Compensated
                ),
                Stage::Forward => matches!(next.stage, Stage::Applied | Stage::Backward),
                Stage::Applied => next.stage == Stage::Backward,
                Stage::Backward => next.stage == Stage::Reverted,
                Stage::Invalidated | Stage::Rejected | Stage::Reverted => {
                    next.stage == Stage::Compensated
                }
                Stage::Compensated | Stage::Protected => false,
            };
        ensure!(allowed, "node action stage transition differs");
        Ok(())
    }

    /// 业务作用：在承认动作状态之前核对永久节点、受理代际、fence 与全部有限效果，损坏不能取得恢复权。
    ///
    /// 参数说明：
    /// - `identity`：同一目录已经验证的永久节点身份。
    /// - `epoch`：head 保存的当前未关闭受理代际。
    /// - `highest_fence`：节点独立保存、释放动作后仍保留的最高目标 fence。
    ///
    /// 返回：身份、效果、阶段与正文归属全部一致才成功；不读取文件或改变目录状态。
    pub(in crate::control::journal) fn validate(
        &self,
        identity: &Identity,
        epoch: u64,
        highest_fence: u64,
    ) -> Result<()> {
        ensure!(
            self.schema == 1
                && self.intent_sha256 == self.intent.fingerprint()?
                && self.intent.node_id == identity.node_id
                && self.intent.baseline.cluster_id == identity.cluster_id
                && self.intent.baseline.store_id == identity.store_id
                && self.intent.baseline.node_admission_epoch == epoch.to_string()
                && (1..=i64::MAX as u64).contains(&self.fence)
                && self.fence == highest_fence
                && self.admissions.len() <= 2
                && self.admissions.len()
                    + self.receipts.len()
                    + usize::from(self.absence.is_some())
                    <= 4,
            "node action storage binding differs"
        );
        let definition = definition::cached(self.intent.target_count as usize)?;
        let mut pending = [false; 4];
        let mut outcomes = [None; 4];
        for admission in &self.admissions {
            let verified = admission.validate(&self.intent, &definition)?;
            let index = slot(admission.step(), verified.phase)?;
            ensure!(!pending[index], "node action admission repeats an effect");
            pending[index] = true;
        }
        for receipt in &self.receipts {
            let verified = receipt.validate(&self.intent, &definition)?;
            let index = slot(receipt.step(), verified.phase)?;
            // 同一效果只能仍待确认或已有稳定事实，不能同时出现两份权威。
            ensure!(
                !pending[index] && outcomes[index].is_none(),
                "node action receipts repeat an effect"
            );
            outcomes[index] = Some(receipt.outcome());
        }
        if let Some(proof) = &self.absence {
            let index = slot(
                proof.validate(&self.intent, &definition)?,
                StepPhase::Execute,
            )?;
            // 未受理证明只能关闭从未形成受理或收据的效果，不能覆盖任何已有业务事实。
            ensure!(
                !pending[index] && outcomes[index].is_none(),
                "node nonadmission contradicts an effect"
            );
            outcomes[index] = Some(Outcome::Rejected);
        }
        self.validate_files()?;
        ensure!(
            self.matches_stage(pending, outcomes),
            "node action stage contradicts its effects"
        );
        Ok(())
    }

    /// 业务作用：限制每个阶段持有的正文方向和真实发布身份，未发布文件不得伪装为 Applied。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文件计划、依赖指纹与发布记录符合当前阶段时成功，否则拒绝恢复。
    fn validate_files(&self) -> Result<()> {
        let direction = match self.stage {
            Stage::Preparing | Stage::Prepared => Some(Direction::Preparing),
            Stage::Forward | Stage::Applied => Some(Direction::Forward),
            Stage::Backward | Stage::Reverted => Some(Direction::Backward),
            Stage::Invalidated | Stage::Rejected | Stage::Compensated => None,
            Stage::Protected => self.files.as_ref().map(|files| files.direction),
        };
        ensure!(
            self.files.as_ref().map(|files| files.direction) == direction,
            "node action file direction differs"
        );
        if let Some(files) = &self.files {
            files.validate()?;
        }
        if let Some(publication) = &self.publication {
            ensure!(
                crate::admin::management::valid_node_id(&publication.boot_id)
                    && publication.version > 0
                    && match publication.direction {
                        Direction::Forward =>
                            self.candidate_fingerprint == Some(publication.fingerprint),
                        Direction::Backward =>
                            self.intent.base_fingerprint == publication.fingerprint,
                        Direction::Preparing => false,
                    },
                "node action publication identity differs"
            );
        }
        let publication_valid = match self.stage {
            Stage::Applied => self
                .publication
                .as_ref()
                .is_some_and(|value| value.direction == Direction::Forward),
            Stage::Reverted => self
                .publication
                .as_ref()
                .is_some_and(|value| value.direction == Direction::Backward),
            Stage::Backward => self
                .publication
                .as_ref()
                .is_none_or(|value| value.direction == Direction::Forward),
            Stage::Protected => true,
            _ => self.publication.is_none(),
        };
        ensure!(publication_valid, "node action publication phase differs");
        Ok(())
    }

    /// 业务作用：将文件方向与预检、应用、补偿事实的合法组合封闭，错误组合不得通过重启重新取得执行权。
    ///
    /// 参数说明：
    /// - `pending`：四种业务效果当前仍待确认的身份槽。
    /// - `outcomes`：同一顺序下已经验证的稳定事实。
    ///
    /// 返回：只接受已定义的阶段组合；保护状态也必须有真实 HALTED 收据，不能凭字段名授权。
    fn matches_stage(&self, pending: [bool; 4], outcomes: [Option<Outcome>; 4]) -> bool {
        use Outcome::{Halted, Rejected, Succeeded};
        let [prepare, apply, undo_prepare, undo_apply] = outcomes;
        match self.stage {
            Stage::Preparing => pending == [true, false, false, false] && outcomes == [None; 4],
            Stage::Prepared => {
                pending == [false; 4] && outcomes == [Some(Succeeded), None, None, None]
            }
            Stage::Invalidated => {
                pending == [false; 4]
                    && prepare == Some(Succeeded)
                    && matches!(apply, None | Some(Rejected))
                    && undo_prepare.is_none()
                    && matches!(undo_apply, None | Some(Succeeded))
            }
            Stage::Forward => {
                pending == [false, true, false, false]
                    && outcomes == [Some(Succeeded), None, None, None]
            }
            Stage::Applied => {
                pending == [false; 4] && outcomes == [Some(Succeeded), Some(Succeeded), None, None]
            }
            Stage::Backward => {
                let apply_state = match apply {
                    None => pending[1] && self.publication.is_none(),
                    Some(Succeeded) => !pending[1] && self.publication.is_some(),
                    _ => false,
                };
                prepare == Some(Succeeded)
                    && apply_state
                    && !pending[0]
                    && !pending[2]
                    && pending[3]
                    && undo_prepare.is_none()
                    && undo_apply.is_none()
            }
            Stage::Reverted => {
                pending == [false, apply.is_none(), false, false]
                    && prepare == Some(Succeeded)
                    && matches!(apply, None | Some(Succeeded | Rejected))
                    && undo_prepare.is_none()
                    && undo_apply == Some(Succeeded)
            }
            Stage::Rejected => {
                pending == [false; 4] && outcomes == [Some(Rejected), None, None, None]
            }
            Stage::Compensated => {
                !pending[0]
                    && !pending[2]
                    && !pending[3]
                    && matches!(prepare, Some(Succeeded | Rejected))
                    && undo_prepare == Some(Succeeded)
                    && matches!(apply, None | Some(Succeeded | Rejected))
                    && matches!(undo_apply, None | Some(Succeeded))
                    && (apply != Some(Succeeded) || undo_apply == Some(Succeeded))
                    && (prepare != Some(Rejected) || apply.is_none())
                    && (!pending[1]
                        || (apply.is_none()
                            && prepare == Some(Succeeded)
                            && undo_apply == Some(Succeeded)))
            }
            // HALTED 只保留已知事实，所有执行与释放入口必须拒绝该阶段，不能靠重投解除。
            Stage::Protected => outcomes.contains(&Some(Halted)),
        }
    }
}

/// 业务作用：把已验证的两步骤两业务阶段映射到固定四槽，查询不占用永久效果容量。
///
/// 参数说明：
/// - `step`：已经绑定原目标索引的步骤。
/// - `phase`：NASA 已验证的原命令阶段。
///
/// 返回：有限业务槽；Resolve 或 Cancel 拒绝，不允许额外永久身份。
fn slot(step: Step, phase: StepPhase) -> Result<usize> {
    let phase = match phase {
        StepPhase::Execute => 0,
        StepPhase::Compensate => 2,
        _ => anyhow::bail!("node storage cannot retain a query effect"),
    };
    Ok(phase + usize::from(step == Step::Apply))
}
