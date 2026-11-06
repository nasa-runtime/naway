//! 原计划共享保存，阶段只推进整批方向、有限效果和清理责任，不重建完整审批树。

use super::Stage;
use crate::{
    control::material::{
        execution::{
            configuration::Configuration,
            effect::Admission,
            position::Position,
            receipt::{Expected, Reason, Receipt},
            release::Proof,
            state::slot,
        },
        node::Intent,
    },
    tls::keypair::execution::{prepare::Sources, source::Goal},
};
use anyhow::{ensure, Result};
use nasa::saga::StepPhase;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(in crate::control::journal) use crate::control::material::execution::state::Direction;

/// 原生执行责任与完整计划的共享引用；阶段推进保留原受理、稳定收据和清理证明。
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control::journal) struct Execution {
    pub position: Position,
    pub configuration: Arc<Configuration>,
    pub sources: Arc<Sources>,
    pub prepared: bool,
    pub direction: Option<Direction>,
    pub compensation: Option<Arc<Vec<Goal>>>,
    pub admissions: Vec<Admission>,
    pub receipts: Vec<Arc<Receipt>>,
    pub release: Option<Proof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<Reason>,
}

impl Execution {
    /// 业务作用：在承认可执行记录之前核对原计划、完整效果、方向和清理责任，缺项不能推成成功。
    ///
    /// 参数说明：
    /// - `intent`：该head唯一保留的完整原意图。
    /// - `stage`：原外层材料责任阶段。
    ///
    /// 返回：全部原生结构与阶段不变量一致时成功，不读取秘密或活动文件。
    pub(in crate::control::journal) fn validate(
        &self,
        intent: &Intent,
        stage: Stage,
    ) -> Result<()> {
        self.position.validate(intent)?;
        self.configuration.validate(intent)?;
        self.sources.validate(intent)?;
        ensure!(
            self.admissions.len() <= 2 && self.admissions.len() + self.receipts.len() <= 4,
            "material effects exceed bounds"
        );
        if let Some(goals) = &self.compensation {
            ensure!(
                goals.len() == self.sources.plans.len(),
                "material compensation source count differs"
            );
            for (goal, source) in goals.iter().zip(&self.sources.plans) {
                goal.validate(source)?;
            }
        }
        let forward: Vec<_> = self
            .sources
            .plans
            .iter()
            .map(|plan| plan.generation())
            .collect();
        let backward: Vec<_> = self
            .compensation
            .iter()
            .flat_map(|goals| goals.iter())
            .map(|goal| goal.generation())
            .collect();
        let mut pending = [false; 4];
        let mut outcomes = [None; 4];
        for admission in &self.admissions {
            let identity = admission.validate(intent, self.position)?;
            let index = slot(admission.step(), identity.phase)?;
            ensure!(!pending[index], "material effect admission repeats");
            pending[index] = true;
        }
        for receipt in &self.receipts {
            let phase = receipt.phase(intent, self.position)?;
            let expected = Expected {
                intent,
                position: self.position,
                generations: if phase == StepPhase::Compensate {
                    &backward
                } else {
                    &forward
                },
                protocols: &self.sources.protocols,
            };
            let identity = receipt.validate(&expected)?;
            let index = slot(receipt.step(), identity.phase)?;
            // 原效果只能未决或已有稳定事实；相同effect的另一个attempt也不能占用第二个永久槽。
            ensure!(
                !pending[index] && outcomes[index].is_none(),
                "material receipt repeats an effect"
            );
            outcomes[index] = Some(receipt.outcome());
        }
        if let Some(proof) = &self.release {
            proof.validate(intent, self.position)?;
        }
        crate::control::material::execution::state::State {
            prepared: self.prepared,
            direction: self.direction,
            compensation: self.compensation.is_some(),
            protection: self.protection.is_some(),
            terminal: self.release.as_ref().map(Proof::terminal),
        }
        .validate(stage, pending, outcomes)?;
        Ok(())
    }

    /// 业务作用：保留所有已提交原计划和效果身份，后续租约只能推进同一动作，不能改写历史事实。
    ///
    /// 参数说明：
    /// - `next`：已经通过完整结构门的下一执行记录。
    /// - `stage`：当前持久阶段。
    /// - `next_stage`：拟提交阶段。
    ///
    /// 返回：合法单向阶段推进、原受理精确结算且不可变字段不变时成功；保护态不能自动解除。
    pub(in crate::control::journal) fn require_successor(
        &self,
        next: &Self,
        stage: Stage,
        next_stage: Stage,
    ) -> Result<()> {
        ensure!(
            stage != Stage::Protected
                && self.position == next.position
                && self.configuration == next.configuration
                && self.sources == next.sources
                && (!self.prepared || next.prepared)
                && next.receipts.starts_with(&self.receipts)
                && self
                    .compensation
                    .as_ref()
                    .is_none_or(|goals| next.compensation.as_ref() == Some(goals))
                && self
                    .release
                    .as_ref()
                    .is_none_or(|proof| next.release.as_ref() == Some(proof)),
            "material execution cannot replace durable facts"
        );
        for admission in &self.admissions {
            ensure!(
                next.admissions.contains(admission)
                    || next
                        .receipts
                        .iter()
                        .any(|receipt| receipt.settles(admission)),
                "material execution lost an unresolved effect"
            );
        }
        if next.compensation.is_some() && self.compensation.is_none() {
            // 全部补偿代与整批Backward同时决定，不能先改一个来源再为其它来源补分配身份。
            ensure!(
                next_stage == Stage::Backward,
                "material compensation has no batch decision"
            );
        }
        if next_stage == Stage::Protected {
            ensure!(
                self.direction == next.direction
                    && self.prepared == next.prepared
                    && self.compensation == next.compensation,
                "material protection lost file responsibility"
            );
            ensure!(
                next.protection.is_some()
                    && self.admissions == next.admissions
                    && self.receipts == next.receipts,
                "material protection changed original effects"
            );
        }
        let allowed = stage == next_stage
            || next_stage == Stage::Protected
            || match stage {
                Stage::Reserved => matches!(next_stage, Stage::Prepared | Stage::Rejected),
                Stage::Prepared => matches!(
                    next_stage,
                    Stage::Invalidated | Stage::Forward | Stage::Compensated
                ),
                Stage::Invalidated => next_stage == Stage::Compensated,
                Stage::Forward => matches!(next_stage, Stage::Applied | Stage::Backward),
                Stage::Applied => matches!(next_stage, Stage::Backward | Stage::Cleaning),
                Stage::Backward => next_stage == Stage::Reverted,
                Stage::Reverted => next_stage == Stage::Compensated,
                Stage::Rejected => matches!(next_stage, Stage::Compensated | Stage::Cleaning),
                Stage::Compensated => next_stage == Stage::Cleaning,
                Stage::Cleaning | Stage::Protected => false,
            };
        ensure!(allowed, "material stage transition differs");
        Ok(())
    }
}
