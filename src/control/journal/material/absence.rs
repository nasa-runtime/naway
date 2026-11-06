//! 未受理布局没有本机来源计划或秘密预算，持久否定事实先于向调度器回答拒绝。

use super::{Fence, Record, Stage};
use crate::control::{
    journal::Journal,
    material::execution::{
        absence::Absence,
        command::{Command, Step},
        release::{Proof, Terminal},
    },
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 不占秘密预算的原否定事实及终态清理证明；已有来源计划不能由它推成从未执行。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control::journal) struct Nonadmission {
    pub proof: Absence,
    pub release: Option<Proof>,
}

impl Nonadmission {
    /// 业务作用：限制否定事实为无执行能力的原效果，不能凭缺席证明补造来源、秘密预算或受理记录。
    ///
    /// 参数说明：
    /// - `record`：同一head的唯一材料责任。
    ///
    /// 返回：准备未受理或原准备后的应用未受理布局完整时成功；任何已有应用受理均拒绝。
    pub(super) fn validate(&self, record: &Record) -> Result<()> {
        let position = self.proof.validate(&record.intent)?;
        match (record.schema, self.proof.step(), &record.execution) {
            (3, Step::Prepare, None) => {
                ensure!(
                    record.backup_bytes.is_empty()
                        && matches!(record.stage, Stage::Rejected | Stage::Cleaning)
                        && (record.stage == Stage::Cleaning) == self.release.is_some(),
                    "material unadmitted preparation has execution authority"
                );
                if let Some(proof) = &self.release {
                    proof.validate(&record.intent, position)?;
                    ensure!(
                        proof.terminal() == Terminal::Compensated,
                        "unadmitted material terminal differs"
                    );
                }
            }
            (2, Step::Apply, Some(execution)) => {
                ensure!(
                    self.release.is_none()
                        && position == execution.position
                        && matches!(
                            record.stage,
                            Stage::Invalidated | Stage::Compensated | Stage::Cleaning
                        )
                        && execution
                            .admissions
                            .iter()
                            .all(|admission| admission.step() != Step::Apply)
                        && execution
                            .receipts
                            .iter()
                            .all(|receipt| receipt.step() != Step::Apply),
                    "material unadmitted application has existing effect authority"
                );
            }
            _ => anyhow::bail!("material nonadmission layout differs"),
        }
        Ok(())
    }
}

impl Journal {
    /// 业务作用：以严格更高独立水位关闭从未受理的原正向效果，迟到prepare或apply无法在Resolve之后取得写权。
    ///
    /// 参数说明：
    /// - `command`：当前验签、原节点和原意图绑定的正向Resolve。
    /// - `authorize`：持真实排他许可复验当前四主体、租约、会话、快照和有限窗口。
    ///
    /// 返回：原否定事实同步成功；已有受理、异意图、旧水位或未知head拒绝，不创建或删除秘密。
    pub(crate) fn reject_unadmitted_material(
        &self,
        command: &Command,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let proof = Absence::new(command)?;
        let checked = command.validate()?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("material nonadmission storage absent")?;
        let boot = self
            .action_boot
            .get()
            .context("material nonadmission boot absent")?;
        ensure!(
            command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.intent.baseline.node_admission_epoch
                    == current.admission_epoch().to_string()
                && command.delivery.receiving_boot_id == *boot
                && current.local().is_none()
                && current.action().is_none(),
            "material nonadmission binding differs"
        );
        authorize()?;
        if let Some(record) = current.material() {
            ensure!(
                record.intent == command.intent && record.intent_sha256 == *checked.intent_sha256(),
                "material nonadmission intent differs"
            );
            if let Some(absence) = &record.absence {
                absence.proof.result_for(command)?;
                return Ok(());
            }
        }
        // 只观察到空槽不足以排除迟到请求；更高水位与否定事实必须在同一head中一起持久。
        ensure!(
            current
                .material_fence()
                .is_none_or(|highest| highest.store == command.intent.execution_store
                    && command.delivery.fence > highest.value),
            "material nonadmission requires a newer fence"
        );
        let absence = Some(Arc::new(Nonadmission {
            proof,
            release: None,
        }));
        let next = match (checked.step(), current.material()) {
            (Step::Prepare, None) => Record {
                schema: 3,
                intent: command.intent.clone(),
                intent_sha256: *checked.intent_sha256(),
                fence: Fence {
                    store: command.intent.execution_store.clone(),
                    value: command.delivery.fence,
                },
                stage: Stage::Rejected,
                backup_bytes: Vec::new(),
                execution: None,
                absence,
            },
            (Step::Apply, Some(record)) => {
                ensure!(
                    matches!(record.stage, Stage::Prepared | Stage::Invalidated),
                    "material application already has a direction"
                );
                let mut next = record.clone();
                next.stage = Stage::Invalidated;
                next.fence.value = command.delivery.fence;
                next.absence = absence;
                next
            }
            _ => anyhow::bail!("material effect cannot be proven unadmitted"),
        };
        authorize()?;
        self.advance_material(&mut storage, next)
    }
}
