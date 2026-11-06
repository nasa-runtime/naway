//! 原共享终态与节点事实共同授予秘密清理权，先提交清理责任再删除精确槽并关闭原代际。

use super::{bodies, Stage};
use crate::{
    config::GatewaySnapshot,
    control::{
        actions::receipt::Outcome,
        journal::{storage, Journal},
        material::execution::{
            command::{Command, Step},
            effect::Admission,
            receipt::{Expected, Receipt},
            release::{Release, Terminal},
        },
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use std::sync::Arc;

impl Journal {
    /// 业务作用：在没有未完成文件方向时结算准备补偿，原应用未知只能在实际安装补偿成功后被覆盖。
    ///
    /// 参数说明：
    /// - `command`：原Prepare步骤的当前合法Compensate命令。
    /// - `active`：调用者持发布权的当前配置。
    /// - `authorize`：当前四主体、窗口、会话和真实动作许可复验。
    ///
    /// 返回：同步成功的准备补偿收据；原文件方向未确认或现有责任不符拒绝，不删秘密槽。
    pub(crate) fn compensate_material_preparation(
        &self,
        command: &Command,
        active: &GatewaySnapshot,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<Arc<Receipt>> {
        let checked = command.validate()?;
        ensure!(
            checked.step() == Step::Prepare && checked.identity().phase == StepPhase::Compensate,
            "material preparation compensation phase differs"
        );
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let original = self
            .require_material_command(storage.as_ref(), command)?
            .clone();
        let execution = original
            .execution
            .as_ref()
            .context("material compensation plan absent")?;
        let generations: Vec<_> = execution
            .compensation
            .iter()
            .flat_map(|goals| goals.iter())
            .map(|goal| goal.generation())
            .collect();
        let expected = Expected {
            intent: &original.intent,
            position: execution.position,
            generations: &generations,
            protocols: &execution.sources.protocols,
        };
        authorize()?;
        if let Some(receipt) = execution
            .receipts
            .iter()
            .find(|receipt| receipt.effect_id() == checked.identity().effect.to_string())
        {
            receipt.result_for(command, &expected)?;
            return Ok(receipt.clone());
        }
        // 未确认的Forward/Backward保留文件责任；只有未动文件或完整监听补偿已确认才可退休准备权。
        ensure!(
            matches!(
                original.stage,
                Stage::Prepared | Stage::Invalidated | Stage::Rejected | Stage::Reverted
            ),
            "material file responsibility is not compensated"
        );
        execution
            .configuration
            .require_snapshot(active, &original.intent)?;
        let receipt = Arc::new(Receipt::settle(
            Admission::new(command)?,
            &expected,
            Outcome::Succeeded,
            None,
            None,
        )?);
        let mut next_execution = execution.as_ref().clone();
        next_execution.direction = None;
        next_execution.receipts.push(receipt.clone());
        let mut next = original.clone();
        next.fence.value = command.delivery.fence;
        next.stage = Stage::Compensated;
        next.execution = Some(Arc::new(next_execution));
        authorize()?;
        execution
            .configuration
            .require_snapshot(active, &original.intent)?;
        self.advance_material(&mut storage, next)?;
        Ok(receipt)
    }

    /// 业务作用：核对独立材料共享终态与完整本机事实后持久撤销正文执行引用，精确删除秘密并关闭原受理代际。
    ///
    /// 参数说明：
    /// - `release`：独立验签域中的原意图、物理节点位置和共享终态。
    /// - `authorize`：复验当前四主体、租约、水位、会话、窗口及共享调度终态的调用者门。
    ///
    /// 返回：本动作清理与关闭全部同步，或原代际已关闭事实再次确认后成功；异常秘密或未知提交保留原责任。
    pub(crate) fn release_material(
        &self,
        release: &Release,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let checked = release.validate()?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("material release storage absent")?;
        let boot = self
            .action_boot
            .get()
            .context("material release boot absent")?;
        ensure!(
            release.intent.node_id == self.identity.node_id
                && release.intent.baseline.cluster_id == self.identity.cluster_id
                && release.intent.baseline.store_id == self.identity.store_id
                && release.delivery.receiving_boot_id == *boot
                && current
                    .material_fence()
                    .is_none_or(|highest| highest.store == release.intent.execution_store),
            "material release binding differs"
        );
        authorize()?;
        let epoch: u64 = release.intent.baseline.node_admission_epoch.parse()?;
        if epoch < current.admission_epoch() {
            // 原代际已关闭只证明迟到命令不能再受理；同步原head后只读确认，不能触碰后续动作或其秘密。
            storage::confirm(&self.root, &self.identity, current)?;
            authorize()?;
            return Ok(());
        }
        ensure!(
            epoch == current.admission_epoch(),
            "material release uses a future epoch"
        );
        let Some(record) = current.material() else {
            // 全批补偿终态可包含从未受理的后续节点；必须独立关闭原epoch，不能把空槽算成安装成功。
            ensure!(
                release.terminal == Terminal::Compensated,
                "completed material target has no stable evidence"
            );
            let fence = super::Fence {
                store: release.intent.execution_store.clone(),
                value: release.delivery.fence,
            };
            authorize()?;
            *storage = Some(storage::material::close_unadmitted(
                &self.root,
                &self.identity,
                current,
                epoch,
                &fence,
            )?);
            return Ok(());
        };
        ensure!(
            matches!(record.schema, 2 | 3)
                && record.stage != Stage::Protected
                && record.intent == release.intent
                && record.intent_sha256 == release.position.fingerprint(&release.intent)?
                && release.delivery.fence >= record.fence.value,
            "material release responsibility differs"
        );
        if record.stage != Stage::Cleaning {
            let mut next = record.clone();
            if let Some(execution) = &record.execution {
                let mut next_execution = execution.as_ref().clone();
                next_execution.direction = None;
                next_execution.release = Some(checked.proof);
                next.execution = Some(Arc::new(next_execution));
            } else {
                let absence = record
                    .absence
                    .as_ref()
                    .context("material release absence missing")?;
                next.absence = Some(Arc::new(super::absence::Nonadmission {
                    proof: absence.proof.clone(),
                    release: Some(checked.proof),
                }));
            }
            next.fence.value = release.delivery.fence;
            next.stage = Stage::Cleaning;
            // 先由完整状态机证明共享终态确实覆盖本机原效果；终态名本身不能授予秘密删除权。
            next.validate(&self.identity, current.admission_epoch(), Some(&next.fence))?;
            authorize()?;
            self.advance_material(&mut storage, next)?;
        } else {
            ensure!(
                record
                    .execution
                    .as_ref()
                    .and_then(|execution| execution.release.as_ref())
                    .or_else(|| record
                        .absence
                        .as_ref()
                        .and_then(|absence| absence.release.as_ref()))
                    == Some(&checked.proof),
                "material release proof changed"
            );
        }
        let current = storage
            .as_ref()
            .context("material cleaning storage absent")?;
        let record = current
            .material()
            .context("material cleaning responsibility absent")?;
        // 清理决定已同步，取消或网络丢响应不撤销这项责任；重试和启动恢复都只删除同一固定槽集合。
        bodies::cleanup(&self.root, record)?;
        *storage = Some(storage::material::finish_cleanup(
            &self.root,
            &self.identity,
            current,
        )?);
        Ok(())
    }
}
