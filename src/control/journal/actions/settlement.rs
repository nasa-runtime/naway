//! 无文件效果的确定收尾必须先撤销未来应用资格，再回收原准备材料。

use super::model::Stage;
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
    /// 业务作用：在文件方向尚未决定时确认 apply 拒绝，保留原 prepare 成功事实并关闭迟到执行资格。
    ///
    /// 参数说明：
    /// - `command`：当前已验真的 apply 执行命令。
    /// - `reason`：完整候选或基线不能继续应用的有限原因。
    /// - `authorize`：真实工作许可和文件事务中的当前权限、会话与期限门。
    ///
    /// 返回：原稳定收据或已持久的确定拒绝；已选择文件方向、未知 head 或其它意图不能被改写。
    pub(crate) fn reject_action_application(
        &self,
        command: &Command,
        reason: Reason,
        authorize: impl FnMut() -> Result<()>,
    ) -> Result<Receipt> {
        self.settle_action_without_files(command, Some(reason), authorize)
    }

    /// 业务作用：完成尚无文件应用或已经回退完成的补偿，不允许提前删除仍承担回退责任的正文。
    ///
    /// 参数说明：
    /// - `command`：同一意图的 prepare 补偿，或尚未进入文件方向的 apply 补偿。
    /// - `authorize`：当前权限、会话、快照实例与期限门，调用方仍持真实任务许可。
    ///
    /// 返回：无文件副作用的补偿事实已持久；Forward/Applied/Backward 必须先按原材料完成文件补偿。
    pub(crate) fn compensate_action_without_files(
        &self,
        command: &Command,
        authorize: impl FnMut() -> Result<()>,
    ) -> Result<Receipt> {
        self.settle_action_without_files(command, None, authorize)
    }

    /// 业务作用：统一无文件效果的事实提交与清理次序，去重只回读原效果且不重新授权已经撤销的准备。
    ///
    /// 参数说明：
    /// - `command`：已通过外层信任门的确定收尾命令。
    /// - `rejection`：有值表示 apply 执行拒绝，无值表示明确无文件副作用的补偿。
    /// - `authorize`：每次持久决定前复验当前授权。
    ///
    /// 返回：相应原稳定收据；无原意图、阶段不符、过期 fence 或持久失败拒绝，不清理其它决定的正文。
    fn settle_action_without_files(
        &self,
        command: &Command,
        rejection: Option<Reason>,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<Receipt> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let checked = command.validate(&definition)?;
        ensure!(
            if rejection.is_some() {
                checked.step() == Step::Apply && checked.identity().phase == StepPhase::Execute
            } else {
                checked.identity().phase == StepPhase::Compensate
            },
            "node action settlement phase differs"
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
        let action = current
            .action()
            .context("node action settlement has no original intent")?;
        ensure!(
            action.intent == command.intent
                && action.intent_sha256 == *checked.intent_sha256()
                && command.delivery.receiving_boot_id == *boot,
            "node action settlement intent differs"
        );
        authorize()?;
        let effect = checked.identity().effect.to_string();
        if let Some(receipt) = action
            .receipts
            .iter()
            .find(|receipt| receipt.effect_id() == effect)
        {
            return Ok(receipt.clone());
        }
        ensure!(
            command.delivery.fence >= current.highest_fence(),
            "node action settlement fence expired"
        );
        let stage = if checked.step() == Step::Apply {
            // 未选择方向时才可确认无文件效果；失效先进入 head，迟到 apply 才不能在清理后重新生效。
            ensure!(
                matches!(action.stage, Stage::Prepared | Stage::Invalidated),
                "node action settlement requires no file decision"
            );
            Stage::Invalidated
        } else {
            // prepare 的补偿不能抢先抹去 Forward/Applied 的基线；已完成 Backward 才能结束材料责任。
            ensure!(
                matches!(
                    action.stage,
                    Stage::Prepared | Stage::Invalidated | Stage::Rejected | Stage::Reverted
                ),
                "node preparation still retains file recovery responsibility"
            );
            Stage::Compensated
        };
        let receipt = Receipt::new(
            command,
            &definition,
            if rejection.is_some() {
                Outcome::Rejected
            } else {
                Outcome::Succeeded
            },
            rejection,
        )?;
        let reclaim = current.local().is_none();
        let mut next = action.clone();
        next.stage = stage;
        next.fence = command.delivery.fence;
        next.files = None;
        next.publication = None;
        next.receipts.push(receipt.clone());
        authorize()?;
        // 只有无引用状态完整同步后才删除原正文；本地 writer 共存时保留它当前正在使用的固定槽。
        self.advance_action(&mut storage, next)?;
        if reclaim {
            local::bodies::clear(&self.root)?;
        }
        Ok(receipt)
    }
}
