//! 节点关闭原代际后才回收材料；缺失、未知或保护事实不授予释放权。

use super::model::{Record, Stage};
use crate::control::{
    actions::{
        command::Step,
        definition,
        receipt::Outcome,
        release::{Release, Terminal},
    },
    journal::{local, storage, Journal},
};
use anyhow::{ensure, Context, Result};
use nasa::saga::{StepPhase, WorkflowDefinition};

impl Journal {
    /// 业务作用：关闭安全终态的原目标代际，保留永久 fence，并防止释放重投影响后来操作。
    ///
    /// 参数说明：
    /// - release：管理适配器已验证独立签名、当前会话及共享安全终态的完整声明。
    /// - authorize：持有真实动作许可与唯一文件 writer 的调用方复验当前写权和期限。
    ///
    /// 返回：原代际已经持久关闭且无引用材料已清理时成功；未知提交、未决动作、错绑定或失权拒绝确认。
    pub(crate) fn release_action(
        &self,
        release: &Release,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let definition = definition::cached(release.intent.target_count as usize)?;
        let checked = release.validate(&definition)?;
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
            release.intent.node_id == self.identity.node_id
                && release.intent.baseline.cluster_id == self.identity.cluster_id
                && release.intent.baseline.store_id == self.identity.store_id
                && release.delivery.receiving_boot_id == *boot,
            "node terminal release binding differs"
        );
        let epoch: u64 = release.intent.baseline.node_admission_epoch.parse()?;
        authorize()?;
        if epoch < current.admission_epoch() {
            // 旧代际只读确认不得触碰新决定；先前关闭后清理中断，仅在当前完全无引用时继续回收。
            if current.action().is_none() && current.local().is_none() {
                local::bodies::clear(&self.root)?;
            }
            return Ok(());
        }
        ensure!(
            epoch == current.admission_epoch() && current.local().is_none(),
            "node terminal release epoch is unavailable"
        );
        if let Some(action) = current.action() {
            ensure!(
                action.intent_sha256 == checked.intent_sha256 && action.intent == release.intent,
                "node terminal release intent differs"
            );
            require_terminal(action, &definition, release.terminal)?;
        } else {
            // 正常完成必须有实际应用证据；只有整体补偿结束才可能包含尚未受理的后续目标。
            ensure!(
                release.terminal == Terminal::Compensated,
                "node completed target has no action evidence"
            );
        }
        authorize()?;
        // 同一 head 先永久关闭代际与提高水位，再清除引用；未知同步不能接纳内存状态或回报成功。
        let closed = storage::actions::release(
            &self.root,
            &self.identity,
            current,
            &checked.intent_sha256,
            epoch,
            release.delivery.fence,
            release.terminal == Terminal::Compensated,
        )?;
        *storage = Some(closed);
        local::bodies::clear(&self.root)?;
        Ok(())
    }
}

/// 业务作用：用节点原始稳定效果核对整体安全终态，未知应用只能在对应补偿已确认后释放。
///
/// 参数说明：
/// - action：原代际保存的完整动作，已经随同 head 验证。
/// - definition：本机冻结的原工作流。
/// - terminal：共享事务确认并经独立签名绑定的整体终态。
///
/// 返回：实际发布完成或完整补偿证据符合时成功；保护、未决、缺失收据及矛盾阶段拒绝。
fn require_terminal(
    action: &Record,
    definition: &WorkflowDefinition,
    terminal: Terminal,
) -> Result<()> {
    let mut outcomes = [None; 4];
    for receipt in &action.receipts {
        let verified = receipt.validate(&action.intent, definition)?;
        let phase = match verified.phase {
            StepPhase::Execute => 0,
            StepPhase::Compensate => 2,
            _ => anyhow::bail!("node terminal release contains a query receipt"),
        };
        let slot = phase + usize::from(receipt.step() == Step::Apply);
        ensure!(
            outcomes[slot].is_none(),
            "node terminal release repeats an effect"
        );
        outcomes[slot] = Some(receipt.outcome());
    }
    if let Some(proof) = &action.absence {
        let slot = usize::from(proof.validate(&action.intent, definition)? == Step::Apply);
        // 持久未受理证明可以确认拒绝，不能与真实受理的稳定收据同时占据一个效果。
        ensure!(
            outcomes[slot].is_none(),
            "node terminal nonadmission repeats an effect"
        );
        outcomes[slot] = Some(Outcome::Rejected);
    }
    let [prepare, apply, undo_prepare, undo_apply] = outcomes;
    let success = Some(Outcome::Succeeded);
    let safe = match terminal {
        Terminal::Completed => {
            action.stage == Stage::Applied
                && action.admissions.is_empty()
                && outcomes == [success, success, None, None]
        }
        Terminal::Compensated => {
            (action.stage == Stage::Rejected
                && action.admissions.is_empty()
                && outcomes == [Some(Outcome::Rejected), None, None, None])
                || (action.stage == Stage::Compensated
                    && matches!(prepare, Some(Outcome::Succeeded | Outcome::Rejected))
                    && undo_prepare == success
                    && (apply != success || undo_apply == success)
                    && (action.admissions.is_empty() || undo_apply == success))
        }
    };
    ensure!(safe, "node terminal release lacks safe effect evidence");
    Ok(())
}
