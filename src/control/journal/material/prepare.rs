//! 整批材料在同一发布权与目录owner下完成持久准备，不以网络受理替代已同步秘密责任。

use super::{bodies, execution::Execution, Fence, Record, Stage};
use crate::{
    config::GatewaySnapshot,
    control::{
        actions::receipt::Outcome,
        journal::{storage, Journal},
        material::{
            execution::{
                command::{Command, Step},
                configuration::Configuration,
                effect::Admission,
                receipt::{Expected, Reason, Receipt},
            },
            Material,
        },
    },
    tls::keypair::execution::prepare::with_prepared,
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use std::sync::Arc;

impl Journal {
    /// 业务作用：持当前完整授权和文件发布权，把唯一候选与全批原备份提交为Prepared，再允许报告准备成功。
    ///
    /// 参数说明：
    /// - `command`：已验签并绑定当前节点会话和单调窗口的整批准备命令。
    /// - `active`：调用者持有发布权与文件事务权的原完整配置。
    /// - `candidate`：原审批唯一清零候选帧，不转成JSON或Base64。
    /// - `authorize`：每次持久决定前复验当前四主体、会话、快照实例和窗口的门。
    ///
    /// 返回：完整Prepared head同步后返回原稳定收据；中途失败保留可判定的原准备责任，不写活动材料。
    pub(crate) fn prepare_material(
        &self,
        command: &Command,
        active: &GatewaySnapshot,
        candidate: &Material,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<Arc<Receipt>> {
        let checked = command.validate()?;
        ensure!(
            checked.step() == Step::Prepare && checked.identity().phase == StepPhase::Execute,
            "material preparation requires prepare execute"
        );
        let boot = self
            .action_boot
            .get()
            .context("material action boot is not bound")?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("material journal storage not initialized")?;
        // 原节点、未关闭epoch和独立永久fence共同裁决首次受理；当前boot不能继承另一启动的准备请求。
        ensure!(
            current.material().is_none()
                && current.action().is_none()
                && current.local().is_none()
                && command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.intent.baseline.node_admission_epoch
                    == current.admission_epoch().to_string()
                && command.delivery.receiving_boot_id == *boot
                && command.intent.original_boot_id == *boot
                && current
                    .material_fence()
                    .is_none_or(|highest| highest.store == command.intent.execution_store
                        && command.delivery.fence > highest.value),
            "material preparation authority differs"
        );
        authorize()?;
        let configuration = Arc::new(Configuration::capture(active, &command.intent)?);
        let result = with_prepared(active, &command.intent, candidate, |prepared| {
            let execution = Arc::new(Execution {
                position: command.position,
                configuration: configuration.clone(),
                sources: prepared.sources.clone(),
                prepared: false,
                direction: None,
                compensation: None,
                admissions: vec![Admission::new(command)?],
                receipts: Vec::new(),
                release: None,
                protection: None,
            });
            let next = Record {
                schema: 2,
                intent: command.intent.clone(),
                intent_sha256: *checked.intent_sha256(),
                fence: Fence {
                    store: command.intent.execution_store.clone(),
                    value: command.delivery.fence,
                },
                stage: Stage::Reserved,
                backup_bytes: prepared
                    .sources
                    .plans
                    .iter()
                    .map(|plan| plan.backup_bytes())
                    .collect(),
                execution: Some(execution),
                absence: None,
            };
            authorize()?;
            configuration.require_current(&active.document_paths.gateway, &command.intent)?;
            prepared.require_current()?;
            // 完整原计划、全部预算与状态编码先于第一份秘密；失败提交不能留下无责任的候选槽。
            self.advance_material(&mut storage, next)?;
            let original = storage
                .as_ref()
                .and_then(storage::Snapshot::material)
                .context("material reservation absent")?;
            bodies::write(&self.root, original, candidate, prepared)?;
            authorize()?;
            configuration.require_current(&active.document_paths.gateway, &command.intent)?;
            prepared.require_current()?;
            bodies::require_complete(&self.root, original)?;
            authorize()?;
            let execution = original
                .execution
                .as_ref()
                .context("material reservation plan absent")?;
            let generations: Vec<_> = execution
                .sources
                .plans
                .iter()
                .map(|plan| plan.generation())
                .collect();
            let receipt = Arc::new(Receipt::settle(
                execution.admissions[0].clone(),
                &Expected {
                    intent: &original.intent,
                    position: execution.position,
                    generations: &generations,
                    protocols: &execution.sources.protocols,
                },
                Outcome::Succeeded,
                None,
                None,
            )?);
            let mut execution = execution.as_ref().clone();
            execution.prepared = true;
            execution.admissions.clear();
            execution.receipts.push(receipt.clone());
            let mut next = original.clone();
            next.stage = Stage::Prepared;
            next.execution = Some(Arc::new(execution));
            // 秘密完整且原来源仍成立后才提交准备成功；成功返回必须晚于新head和目录同步。
            self.advance_material(&mut storage, next)?;
            Ok(receipt)
        });
        if result.is_err() {
            // 准备阶段没有活动文件方向，可结算原准备拒绝；未知head仍拒绝推进并保留原现场。
            self.reject_material_preparation(&mut storage)?;
        }
        result
    }

    /// 业务作用：用当前合法准备请求结算中断的原受理，不把Resolve构造成新的Execute或重写原身份。
    ///
    /// 参数说明：
    /// - `command`：同一原准备效果的当前Execute重投或正向Resolve。
    /// - `authorize`：当前四主体、真实许可、会话、快照和窗口的复验门。
    ///
    /// 返回：原Reserved结算为稳定拒绝；旧水位、错误方向或其它责任拒绝，不改活动文件或删除秘密。
    pub(crate) fn resolve_material_preparation(
        &self,
        command: &Command,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let checked = command.validate()?;
        ensure!(
            checked.step() == Step::Prepare
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Resolve
                )
                && !command.delivery.resolve_compensation,
            "material interrupted preparation phase differs"
        );
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let original = self.require_material_command(storage.as_ref(), command)?;
        ensure!(
            original.stage == Stage::Reserved,
            "material preparation is not pending"
        );
        authorize()?;
        // 先保留新水位再结算原Admission，取消不能恢复旧发行者的重投资格。
        self.retain_material_fence(&mut storage, command.delivery.fence, &mut authorize)?;
        authorize()?;
        self.reject_material_preparation(&mut storage)
    }

    /// 业务作用：将未完成准备结算为原效果的稳定拒绝，秘密残留继续由同一记录承担清理责任。
    ///
    /// 参数说明：
    /// - `storage`：owner当前承认的原head，调用者持有状态锁。
    ///
    /// 返回：没有准备责任时不改变状态，Reserved仅在原head仍一致时转为Rejected；未知提交保持拒绝。
    pub(in crate::control::journal) fn reject_material_preparation(
        &self,
        storage: &mut Option<storage::Snapshot>,
    ) -> Result<()> {
        self.verify_expected(storage.as_ref())?;
        let Some(original) = storage.as_ref().and_then(storage::Snapshot::material) else {
            return Ok(());
        };
        if original.schema != 2 || original.stage != Stage::Reserved {
            return Ok(());
        }
        let execution = original
            .execution
            .as_ref()
            .context("material preparation record absent")?;
        let generations: Vec<_> = execution
            .sources
            .plans
            .iter()
            .map(|plan| plan.generation())
            .collect();
        let receipt = Arc::new(Receipt::settle(
            execution.admissions[0].clone(),
            &Expected {
                intent: &original.intent,
                position: execution.position,
                generations: &generations,
                protocols: &execution.sources.protocols,
            },
            Outcome::Rejected,
            Some(Reason::PreparationInterrupted),
            None,
        )?);
        let mut execution = execution.as_ref().clone();
        execution.admissions.clear();
        execution.receipts.push(receipt);
        let mut next = original.clone();
        next.stage = Stage::Rejected;
        next.execution = Some(Arc::new(execution));
        self.advance_material(storage, next)
    }

    /// 业务作用：在每次材料持久决定前复验原head，仅同步确认后更新owner内存事实，未知提交不猜测成功。
    ///
    /// 参数说明：
    /// - `storage`：调用者已锁定的当前存储事实。
    /// - `next`：按整批材料状态机形成的新记录。
    ///
    /// 返回：新head确认后替换内存快照；任何错误保持原期望并阻止后续写入。
    pub(in crate::control::journal) fn advance_material(
        &self,
        storage: &mut Option<storage::Snapshot>,
        next: Record,
    ) -> Result<()> {
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("material journal storage absent")?;
        let confirmed = storage::material::transition(&self.root, &self.identity, current, next)?;
        *storage = Some(confirmed);
        Ok(())
    }
}
