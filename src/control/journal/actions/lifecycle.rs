//! 与本地 writer 共用正文槽的受理边界及启动恢复。

use super::model::{Record, Stage};
use crate::control::{
    actions::{
        definition,
        receipt::{Outcome, Reason, Receipt},
    },
    journal::{local, storage, Journal},
};
use anyhow::{ensure, Context, Result};
use std::path::Path;

impl Journal {
    /// 业务作用：在普通 writer 的基线比较前只检查资格，过期或无变化请求不得撤销远程准备。
    ///
    /// 参数说明：
    /// - `storage`：同一 owner 已复验且仍持锁的提交事实。
    ///
    /// 返回：无动作、明确空闲事实或可被合法写入失效的 Prepared 时成功，其余状态拒绝。
    pub(in crate::control::journal) fn require_local_action_slot(
        storage: Option<&storage::Snapshot>,
    ) -> Result<()> {
        ensure!(
            storage
                .and_then(storage::Snapshot::action)
                .is_none_or(|action| action.stage == Stage::Prepared || action.allows_local()),
            "node journal action retains file authority"
        );
        Ok(())
    }

    /// 业务作用：在普通写入已经通过自身基线与候选门之后持久撤销远程准备，再允许复用固定正文。
    ///
    /// 参数说明：
    /// - `storage`：同一文件事务内持锁的 owner 事实。
    ///
    /// 返回：没有可执行准备或明确提交 Invalidated 后成功；未知同步保持原期望并阻止后续写入。
    pub(in crate::control::journal) fn invalidate_prepared_action(
        &self,
        storage: &mut Option<storage::Snapshot>,
    ) -> Result<()> {
        Self::require_local_action_slot(storage.as_ref())?;
        if let Some(action) = storage.as_ref().and_then(storage::Snapshot::action) {
            if action.stage == Stage::Prepared {
                let mut next = action.clone();
                next.stage = Stage::Invalidated;
                next.files = None;
                // 必须先失去 apply 权威再清理正文，不能让崩溃后的 Prepared 指向已被其它 writer 复用的材料。
                self.advance_action(storage, next)?;
            }
        }
        Ok(())
    }

    /// 业务作用：启动仅按既有持久方向恢复，准备成功事实不能跨进程自动授予新的 apply。
    ///
    /// 参数说明：
    /// - `storage`：本次启动已选定的 head 及其 owner 期望。
    /// - `main`：本次 CLI 的真实主配置路径。
    ///
    /// 返回：仍持有动作正文时为真，调用方不得执行本地 Idle 清理；冲突或人工保护拒绝启动。
    pub(in crate::control::journal) fn recover_action(
        &self,
        storage: &mut Option<storage::Snapshot>,
        main: &Path,
    ) -> Result<bool> {
        let Some(current) = storage.as_ref() else {
            return Ok(false);
        };
        let Some(action) = current.action() else {
            return Ok(false);
        };
        ensure!(
            action.stage != Stage::Protected,
            "node journal action requires explicit recovery authority"
        );
        if let Some(files) = &action.files {
            local::require_main(files, main)?;
        }
        // 可见 head 不代表前次目录同步已经完成，恢复写入和确定拒绝前必须确认原持久权威。
        storage::confirm(&self.root, &self.identity, current)?;
        match action.stage {
            Stage::Preparing => {
                let mut next = action.clone();
                let admission = next
                    .admissions
                    .pop()
                    .context("node prepare admission is absent")?;
                let definition = definition::cached(next.intent.target_count as usize)?;
                next.receipts.push(Receipt::settle(
                    admission,
                    &next.intent,
                    &definition,
                    Outcome::Rejected,
                    Some(Reason::PreparationInterrupted),
                )?);
                next.stage = Stage::Rejected;
                next.files = None;
                // Preparing 没有授权任何目标替换，先记录确定拒绝再回收可能只有一部分的正文。
                self.advance_action(storage, next)?;
                Ok(false)
            }
            Stage::Prepared => {
                self.invalidate_prepared_action(storage)?;
                Ok(false)
            }
            Stage::Forward | Stage::Backward => {
                local::apply::run(
                    &self.root,
                    action
                        .files
                        .as_ref()
                        .context("node action file decision is absent")?,
                )?;
                Ok(true)
            }
            Stage::Applied | Stage::Reverted => Ok(true),
            Stage::Invalidated | Stage::Rejected | Stage::Compensated => Ok(false),
            Stage::Protected => unreachable!("protected action was rejected"),
        }
    }

    /// 业务作用：只把全部持久同步成功的动作状态交给当前 owner，提交错误不能靠回读自动续写。
    ///
    /// 参数说明：
    /// - `storage`：当前已承认状态的独占借用。
    /// - `next`：同一意图的下一完整事实。
    ///
    /// 返回：成功时推进内存期望；失败保持原期望，后续复验因未知 head 变化而拒绝。
    pub(in crate::control::journal) fn advance_action(
        &self,
        storage: &mut Option<storage::Snapshot>,
        next: Record,
    ) -> Result<()> {
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        let next = storage::actions::transition(&self.root, &self.identity, current, next)?;
        *storage = Some(next);
        Ok(())
    }
}
