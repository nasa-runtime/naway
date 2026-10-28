//! 在唯一工作许可内持久关闭尚未受理的效果，空槽观察本身不构成否定事实。

use super::model::{Record, Stage};
use crate::control::{
    actions::{
        absence::Absence,
        command::{Command, Step},
        definition,
        receipt::Outcome,
    },
    journal::{local, Journal},
};
use anyhow::{ensure, Context, Result};

impl Journal {
    /// 业务作用：以严格更高 fence 永久拒绝尚未受理的正向效果，使迟到 Execute 不能在查询后产生副作用。
    ///
    /// 参数说明：
    /// - `command`：已验签且绑定当前会话的正向 Resolve，不承担新的业务执行。
    /// - `authorize`：仍持真实动作许可及文件事务的调用方复验当前权限、快照与期限。
    ///
    /// 返回：证明完整同步后成功；已有受理、文件方向、未知 head、异意图或失权均拒绝且不清理正文。
    pub(crate) fn reject_unadmitted_action(
        &self,
        command: &Command,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let proof = Absence::new(command, &definition)?;
        let step = proof.validate(&command.intent, &definition)?;
        let boot = self
            .action_boot
            .get()
            .context("node action boot is not bound")?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node action storage is not initialized")?;
        ensure!(
            command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.intent.baseline.node_admission_epoch
                    == current.admission_epoch().to_string()
                && command.delivery.receiving_boot_id == *boot,
            "node nonadmission binding differs"
        );
        authorize()?;
        if let Some(action) = current.action() {
            ensure!(
                action.intent == command.intent
                    && action.intent_sha256 == command.intent.fingerprint()?,
                "node nonadmission intent differs"
            );
            if let Some(existing) = &action.absence {
                existing.result_for(command, &definition)?;
                return Ok(());
            }
        }
        // 读取到空效果不足以排除迟到命令；新决定必须先持久推进水位，并且不能与本地文件决定共存。
        ensure!(
            current.local().is_none() && command.delivery.fence > current.highest_fence(),
            "node nonadmission requires a newer exclusive fence"
        );
        let next = match (step, current.action()) {
            (Step::Prepare, None) => Record {
                schema: 1,
                intent: command.intent.clone(),
                intent_sha256: command.intent.fingerprint()?,
                fence: command.delivery.fence,
                stage: Stage::Rejected,
                dependencies_sha256: [0; 32],
                baseline_dependencies_sha256: [0; 32],
                candidate_fingerprint: None,
                files: None,
                admissions: Vec::new(),
                receipts: Vec::new(),
                absence: Some(proof),
                publication: None,
            },
            (Step::Apply, Some(action)) => {
                // 只有原 Prepare 成功且从未受理 Apply 时能关闭它；任何方向或补偿事实都保留原恢复责任。
                ensure!(
                    matches!(action.stage, Stage::Prepared | Stage::Invalidated)
                        && action.admissions.is_empty()
                        && action.receipts.len() == 1
                        && action.receipts[0].step() == Step::Prepare
                        && action.receipts[0].outcome() == Outcome::Succeeded
                        && action.publication.is_none(),
                    "node application has existing effect authority"
                );
                let mut next = action.clone();
                next.fence = command.delivery.fence;
                next.stage = Stage::Invalidated;
                next.files = None;
                next.absence = Some(proof);
                next
            }
            _ => anyhow::bail!("node effect cannot be proven unadmitted"),
        };
        authorize()?;
        // 先提交拒绝及 fence，再清理无引用正文；未知同步不能回报结果或让迟到命令重新取得资格。
        self.advance_action(&mut storage, next)?;
        local::bodies::clear(&self.root)?;
        Ok(())
    }
}
