//! 确定的准备拒绝只终结无文件副作用的意图，不抹去已经成功或未知的应用。

use super::model::{Record, Stage};
use crate::control::{
    actions::{
        command::{Command, Step},
        definition,
        receipt::{Outcome, Reason, Receipt},
    },
    journal::{local, Journal},
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;

impl Journal {
    /// 业务作用：为合法但无法准备的业务候选提交确定拒绝，或在真实工作已退出后收尾无文件授权的 Preparing。
    ///
    /// 参数说明：
    /// - `command`：已验签且绑定当前会话的 prepare/execute，或仅用于收尾原 Preparing 的 prepare/resolve。
    /// - `reason`：候选、基线、权限或准备中断的有限业务原因。
    /// - `authorize`：当前主体、计划实例及单调期限的最终门，调用者仍持真实工作许可与文件写事务。
    ///
    /// 返回：原稳定事实或完整同步的新拒绝收据；其它意图、已决定文件方向和未知 head 拒绝处理。
    pub(crate) fn reject_action_preparation(
        &self,
        command: &Command,
        reason: Reason,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<Receipt> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let checked = command.validate(&definition)?;
        ensure!(
            checked.step() == Step::Prepare
                && !command.delivery.resolve_compensation
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Resolve
                ),
            "node preparation rejection requires prepare execute or resolve"
        );
        let boot = self
            .action_boot
            .get()
            .context("node action boot is not bound")?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        ensure!(
            command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.intent.baseline.node_admission_epoch
                    == current.admission_epoch().to_string()
                && command.delivery.receiving_boot_id == *boot,
            "node preparation rejection binding differs"
        );
        authorize()?;
        let effect = checked.forward_effect().to_string();
        let mut next = if let Some(action) = current.action() {
            ensure!(
                action.intent == command.intent && action.intent_sha256 == *checked.intent_sha256(),
                "node preparation rejection intent differs"
            );
            if let Some(receipt) = action
                .receipts
                .iter()
                .find(|receipt| receipt.effect_id() == effect)
            {
                // 成功或 HALTED 都是原稳定事实，候选再次被拒绝不能替换先前已经确认的结果。
                return Ok(receipt.clone());
            }
            // 单个真实工作许可保证原工作已经退出；Preparing 从未授权活动文件替换，才允许确定地拒绝。
            ensure!(
                action.stage == Stage::Preparing
                    && current.local().is_none()
                    && command.delivery.fence >= current.highest_fence(),
                "node preparation rejection cannot change a file decision"
            );
            let mut next = action.clone();
            let admission = next
                .admissions
                .pop()
                .context("node preparation admission is absent")?;
            next.receipts.push(Receipt::settle(
                admission,
                &next.intent,
                &definition,
                Outcome::Rejected,
                Some(Reason::PreparationInterrupted),
            )?);
            next
        } else {
            // 空槽拒绝仍消费本启动和更高 fence，旧命令不能通过反复提交拒绝重新建立过期意图。
            ensure!(
                checked.identity().phase == StepPhase::Execute
                    && current.local().is_none()
                    && command.intent.original_boot_id == *boot
                    && command.delivery.fence > current.highest_fence(),
                "node preparation rejection authority differs"
            );
            let receipt = Receipt::new(command, &definition, Outcome::Rejected, Some(reason))?;
            Record {
                schema: 1,
                intent: command.intent.clone(),
                intent_sha256: *checked.intent_sha256(),
                fence: command.delivery.fence,
                stage: Stage::Rejected,
                dependencies_sha256: [0; 32],
                baseline_dependencies_sha256: [0; 32],
                candidate_fingerprint: None,
                files: None,
                admissions: Vec::new(),
                receipts: vec![receipt],
                absence: None,
                publication: None,
            }
        };
        next.stage = Stage::Rejected;
        next.files = None;
        next.fence = command.delivery.fence;
        let receipt = next
            .receipts
            .last()
            .context("node preparation rejection receipt is absent")?
            .clone();
        authorize()?;
        // 确定拒绝必须先进入同一 head，再清理无副作用正文，崩溃不能重新得到 Prepared 资格。
        self.advance_action(&mut storage, next)?;
        local::bodies::clear(&self.root)?;
        Ok(receipt)
    }
}
