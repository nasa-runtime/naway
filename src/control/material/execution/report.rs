//! 共享任务只保留不含部署位置的完整节点事实，原受理和监听证据不能被当前结果字符串覆盖。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::command::Command;
use super::{
    absence::Absence,
    command::Step,
    effect::Admission,
    observation::{Evidence, Protocols},
    position::Position,
    receipt::{Expected, Reason, Receipt},
    release::{Proof, Terminal},
    state::{slot, Direction, Stage, State},
};
use crate::control::material::node::Intent;
use anyhow::{ensure, Result};
use nasa::saga::StepPhase;
#[cfg(feature = "admin-operations-workflow-pgsql")]
use nasaga_runtime_core::SagaResultEnvelope;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 每个原来源的预分配代，没有文件位置、备份摘要或秘密正文。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub source_id: String,
    pub forward: String,
    pub backward: Option<String>,
}

/// 同一head原子交付的全部公开执行事实，完整原意图由共享任务独立保存而不重复嵌入。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    pub schema: u32,
    pub revision: u64,
    pub position: Position,
    pub intent_sha256: [u8; 32],
    pub fence: u64,
    pub stage: Stage,
    pub prepared: bool,
    pub direction: Option<Direction>,
    pub sources: Vec<Source>,
    pub protocols: Vec<Vec<Protocols>>,
    pub admissions: Vec<Admission>,
    pub receipts: Vec<Arc<Receipt>>,
    pub absence: Option<Absence>,
    pub protection: Option<Reason>,
    pub release: Option<Proof>,
}

/// 空槽与关闭是独立读取事实，只有完整报告中的原收据才能投影稳定业务效果。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(crate) enum Observation {
    Vacant,
    Closed,
    Report(Box<Report>),
}

#[cfg(feature = "admin-operations-workflow-pgsql")]
impl Observation {
    /// 业务作用：统一本机和远程结果投影，缺少完整原效果时保持未知而不推进工作流。
    ///
    /// 参数说明：
    /// - `command`：发行端保存的原完整投递身份。
    ///
    /// 返回：完整报告中对应原效果的稳定结果；空槽、关闭或未决为空，跨意图拒绝。
    pub(crate) fn result_for(&self, command: &Command) -> Result<Option<SagaResultEnvelope>> {
        match self {
            Self::Report(report) => report.result_for(command),
            Self::Vacant | Self::Closed => {
                command.validate()?;
                Ok(None)
            }
        }
    }
}

impl Report {
    /// 业务作用：对照共享任务原意图验证完整节点事实，采用与本机Journal相同的阶段和效果不变量。
    ///
    /// 参数说明：
    /// - `intent`：原任务冻结的完整节点审批意图，不能从当前目录重建。
    /// - `position`：该节点在全任务物理分母中的唯一位置。
    ///
    /// 返回：来源代、完整协议、原受理、稳定收据及终态关系都一致时成功，不授予节点写权。
    pub(crate) fn validate(&self, intent: &Intent, position: Position) -> Result<()> {
        ensure!(
            self.schema == 1
                && self.revision > 0
                && self.position == position
                && self.intent_sha256 == position.fingerprint(intent)?
                && (1..=i64::MAX as u64).contains(&self.fence)
                && self.admissions.len() <= 2
                && self.admissions.len() + self.receipts.len() <= 4,
            "material report identity or effect bounds differ"
        );
        if let Some(absence) = &self.absence {
            ensure!(
                absence.validate(intent)? == position,
                "material report absence position differs"
            );
        }
        if let Some(release) = &self.release {
            release.validate(intent, position)?;
        }
        if self.sources.is_empty() {
            // 未受理布局没有计划、秘密或Admission，不能用空来源数组伪装完整准备或安装。
            ensure!(
                self.protocols.is_empty()
                    && !self.prepared
                    && self.direction.is_none()
                    && self.admissions.is_empty()
                    && self.receipts.is_empty()
                    && self.protection.is_none()
                    && self
                        .absence
                        .as_ref()
                        .is_some_and(|proof| proof.step() == Step::Prepare)
                    && matches!(self.stage, Stage::Rejected | Stage::Cleaning)
                    && (self.stage == Stage::Cleaning) == self.release.is_some()
                    && self
                        .release
                        .as_ref()
                        .is_none_or(|proof| proof.terminal() == Terminal::Compensated),
                "material unadmitted report has execution facts"
            );
            return Ok(());
        }
        self.validate_sources(intent)?;
        let forward: Vec<_> = self
            .sources
            .iter()
            .map(|source| source.forward.as_str())
            .collect();
        let backward: Vec<_> = self
            .sources
            .iter()
            .filter_map(|source| source.backward.as_deref())
            .collect();
        let mut pending = [false; 4];
        let mut outcomes = [None; 4];
        for admission in &self.admissions {
            let identity = admission.validate(intent, position)?;
            let index = slot(admission.step(), identity.phase)?;
            ensure!(!pending[index], "material report repeats admission");
            pending[index] = true;
        }
        for receipt in &self.receipts {
            let phase = receipt.phase(intent, position)?;
            let identity = receipt.validate(&Expected {
                intent,
                position,
                generations: if phase == StepPhase::Compensate {
                    &backward
                } else {
                    &forward
                },
                protocols: &self.protocols,
            })?;
            let index = slot(receipt.step(), identity.phase)?;
            ensure!(
                !pending[index] && outcomes[index].is_none(),
                "material report repeats stable effect"
            );
            outcomes[index] = Some(receipt.outcome());
        }
        State {
            prepared: self.prepared,
            direction: self.direction,
            compensation: !backward.is_empty(),
            protection: self.protection.is_some(),
            terminal: self.release.as_ref().map(Proof::terminal),
        }
        .validate(self.stage, pending, outcomes)?;
        if let Some(absence) = &self.absence {
            // 应用否定事实与任何原应用受理互斥，实际补偿不能反过来证明原应用从未发生。
            ensure!(
                absence.step() == Step::Apply
                    && matches!(
                        self.stage,
                        Stage::Invalidated | Stage::Compensated | Stage::Cleaning
                    )
                    && !pending[1]
                    && !pending[3]
                    && outcomes[1].is_none()
                    && outcomes[3].is_none(),
                "material report absence contradicts admitted application"
            );
        }
        Ok(())
    }

    /// 业务作用：验证每个原物理来源的目标代及全部协议，补偿必须全批另分配且不能借回旧材料代。
    ///
    /// 参数说明：
    /// - `intent`：原完整来源组和共享逻辑目标。
    ///
    /// 返回：逐来源逐目标对应且完整成功观察可表达时成功；少项、混合补偿代或未知协议拒绝。
    fn validate_sources(&self, intent: &Intent) -> Result<()> {
        ensure!(
            self.sources.len() == intent.conditions.groups.len()
                && self.protocols.len() == self.sources.len(),
            "material report source count differs"
        );
        let compensating = self.sources[0].backward.is_some();
        for ((source, original), protocols) in self
            .sources
            .iter()
            .zip(&intent.conditions.groups)
            .zip(&self.protocols)
        {
            ensure!(
                source.source_id == original.source_id
                    && crate::tls::keypair::valid_material_generation(&source.forward)
                    && original.material_generation.as_deref() != Some(&source.forward)
                    && source.backward.is_some() == compensating
                    && source.backward.as_ref().is_none_or(|generation| {
                        crate::tls::keypair::valid_material_generation(generation)
                            && generation != &source.forward
                            && original.material_generation.as_ref() != Some(generation)
                    })
                    && protocols.len() == original.affected.len()
                    && protocols
                        .iter()
                        .zip(&original.affected)
                        .all(|(protocols, target)| protocols.allows(target.target.kind)),
                "material report original source or protocol differs"
            );
        }
        Evidence::require_capacity(&self.protocols)
    }

    /// 业务作用：只由完整原事实投影当前查询结果，未知正向受理不会因另一方向成功而被改写。
    ///
    /// 参数说明：
    /// - `command`：当前已验签并绑定同一共享任务的命令或Resolve。
    ///
    /// 返回：所查原效果的稳定NASA结果；尚无原收据时为空，跨意图或不完整事实拒绝。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(crate) fn result_for(&self, command: &Command) -> Result<Option<SagaResultEnvelope>> {
        self.validate(&command.intent, command.position)?;
        let checked = command.validate()?;
        if let Some(absence) = self.absence.as_ref().filter(|absence| {
            absence.step() == checked.step()
                && !command.delivery.resolve_compensation
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Resolve
                )
        }) {
            return Ok(Some(absence.result_for(command)?));
        }
        let effect = if checked.identity().phase == StepPhase::Resolve {
            checked.resolved_effect()
        } else {
            checked.identity().effect
        }
        .to_string();
        let Some(receipt) = self
            .receipts
            .iter()
            .find(|receipt| receipt.effect_id() == effect)
        else {
            return Ok(None);
        };
        let backward = receipt.phase(&command.intent, self.position)? == StepPhase::Compensate;
        let generations: Vec<_> = self
            .sources
            .iter()
            .filter_map(|source| {
                if backward {
                    source.backward.as_deref()
                } else {
                    Some(source.forward.as_str())
                }
            })
            .collect();
        Ok(Some(receipt.result_for(
            command,
            &Expected {
                intent: &command.intent,
                position: self.position,
                generations: &generations,
                protocols: &self.protocols,
            },
        )?))
    }

    /// 业务作用：共享存储接纳后续快照时保留已经见证的全部原事实，较新head不能删除历史未知或替换已确认收据。
    ///
    /// 参数说明：
    /// - `next`：同一节点后续原子报告，可能跨过多个中间提交。
    /// - `intent`：原任务完整意图。
    /// - `position`：原物理节点位置。
    ///
    /// 返回：同序号完全一致或更高序号的合法事实增长时成功；倒退、改代、少收据或遗失受理拒绝。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(crate) fn require_successor(
        &self,
        next: &Self,
        intent: &Intent,
        position: Position,
    ) -> Result<()> {
        self.validate(intent, position)?;
        next.validate(intent, position)?;
        if self.revision == next.revision {
            ensure!(self == next, "material report changed at the same revision");
            return Ok(());
        }
        ensure!(
            next.revision > self.revision
                && next.fence >= self.fence
                && self.intent_sha256 == next.intent_sha256
                && self.protocols == next.protocols
                && self.sources.len() == next.sources.len()
                && self.sources.iter().zip(&next.sources).all(|(old, new)| {
                    old.source_id == new.source_id
                        && old.forward == new.forward
                        && old
                            .backward
                            .as_ref()
                            .is_none_or(|generation| new.backward.as_ref() == Some(generation))
                })
                && (!self.prepared || next.prepared)
                && next.receipts.starts_with(&self.receipts)
                && self
                    .absence
                    .as_ref()
                    .is_none_or(|proof| next.absence.as_ref() == Some(proof))
                && self
                    .release
                    .as_ref()
                    .is_none_or(|proof| next.release.as_ref() == Some(proof))
                && self
                    .protection
                    .is_none_or(|reason| next.protection == Some(reason))
                && allowed_after(self.stage, next.stage),
            "material report replaced original durable facts"
        );
        for admission in &self.admissions {
            ensure!(
                next.admissions.contains(admission)
                    || next
                        .receipts
                        .iter()
                        .any(|receipt| receipt.settles(admission)),
                "material report lost unresolved original admission"
            );
        }
        Ok(())
    }
}

/// 业务作用：允许报告跳过未观察到的中间提交，但不能跨越已经撤销的准备权或解除保护责任。
///
/// 参数说明：
/// - `previous`：共享存储已经确认的原阶段。
/// - `next`：更高head序号的新阶段。
///
/// 返回：原状态图可到达才为真；完整效果和不变字段还由报告后继门检查。
#[cfg(feature = "admin-operations-workflow-pgsql")]
fn allowed_after(previous: Stage, next: Stage) -> bool {
    use Stage::*;
    if previous == next {
        return true;
    }
    if next == Protected && !matches!(previous, Protected | Cleaning) {
        return true;
    }
    match previous {
        Reserved => !matches!(next, Reserved),
        Prepared => matches!(
            next,
            Invalidated | Forward | Applied | Backward | Reverted | Compensated | Cleaning
        ),
        Invalidated | Rejected => matches!(next, Compensated | Cleaning),
        Forward => matches!(next, Applied | Backward | Reverted | Compensated | Cleaning),
        Applied => matches!(next, Backward | Reverted | Compensated | Cleaning),
        Backward => matches!(next, Reverted | Compensated | Cleaning),
        Reverted => matches!(next, Compensated | Cleaning),
        Compensated => next == Cleaning,
        Protected | Cleaning => false,
    }
}
