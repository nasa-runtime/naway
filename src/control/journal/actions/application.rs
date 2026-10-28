//! 在完整重建与覆盖权复验后提交文件方向，真实快照发布仍由正常 reload 完成。

use super::{
    materials::Materials,
    model::{Record, Stage},
    prepare,
};
use crate::{
    config::{
        candidate::{dependencies, Documents},
        GatewaySnapshot,
    },
    control::{
        actions::{
            command::{Command, Step},
            definition,
            effect::Admission,
        },
        baseline::NodeBaseline,
        journal::{
            local::{self, Direction},
            Journal,
        },
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;

pub(crate) struct Application<'a> {
    pub command: &'a Command,
    pub active: &'a GatewaySnapshot,
    pub candidate: &'a GatewaySnapshot,
    pub documents: Documents<'a>,
    pub materials: &'a Materials,
}

impl Journal {
    /// 业务作用：在实际工作许可和文件写事务内将完整重建转为唯一持久方向，防止使用已失效的准备或补偿覆盖权。
    ///
    /// 参数说明：
    /// - `input`：同一意图的原材料、夹住依赖复验的完整候选和当前活动快照。
    /// - `authorize`：复验当前会话、权限、计划实例和单调期限；不能在回调内重入 journal。
    ///
    /// 返回：文件按已提交方向同步完成；尚未确认效果成功，异常保留原事实或已提交方向供后续恢复。
    pub(crate) fn decide_action_files(
        &self,
        input: Application<'_>,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let command = input.command;
        let definition = definition::cached(command.intent.target_count as usize)?;
        let checked = command.validate(&definition)?;
        ensure!(
            checked.step() == Step::Apply,
            "node file decision requires apply step"
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
            .context("node action file materials are absent")?;
        // 工作区只携带读取能力；任何先发生的 head 推进都使此次完整重建失去提交资格。
        ensure!(
            current.local().is_none()
                && current.revision() == input.materials.revision
                && action.intent == command.intent
                && action.intent_sha256 == *checked.intent_sha256()
                && action.intent_sha256 == input.materials.intent_sha256
                && command.delivery.receiving_boot_id == *boot
                && command.delivery.fence >= current.highest_fence(),
            "node action material authority changed"
        );
        authorize()?;
        let (stage, direction, proof) = match checked.identity().phase {
            StepPhase::Execute => {
                ensure!(
                    action.stage == Stage::Prepared && command.intent.original_boot_id == *boot,
                    "node action preparation is no longer applicable"
                );
                prepare::require_baseline(command, input.active)?;
                ensure!(
                    dependencies::capture(
                        input.active,
                        Documents {
                            gateway: &input.active.source_config_path,
                            sidecars: None,
                        }
                    )? == action.baseline_dependencies_sha256,
                    "node action active dependencies changed"
                );
                (
                    Stage::Forward,
                    Direction::Forward,
                    action.dependencies_sha256,
                )
            }
            StepPhase::Compensate => {
                ensure!(
                    matches!(action.stage, Stage::Forward | Stage::Applied),
                    "node action has no compensable file decision"
                );
                require_compensation_owner(action, input.active, boot)?;
                (
                    Stage::Backward,
                    Direction::Backward,
                    action.baseline_dependencies_sha256,
                )
            }
            _ => anyhow::bail!("node query cannot select a new file direction"),
        };
        ensure!(
            input.materials.dependencies_sha256 == proof
                && input.materials.paths.ordered() == input.candidate.document_paths.ordered()
                && dependencies::capture(input.candidate, input.documents)? == proof,
            "node action rebuilt dependencies differ"
        );
        let mut next = action.clone();
        let plan = next
            .files
            .as_mut()
            .context("node action file plan is absent")?;
        if direction == Direction::Forward {
            ensure!(
                local::prepare::baseline_matches(plan)?,
                "node action file baseline changed"
            );
        }
        plan.direction = direction;
        local::require_snapshot(plan, input.candidate)?;
        local::apply::preflight(&self.root, plan)?;
        next.stage = stage;
        next.fence = command.delivery.fence;
        next.admissions.push(Admission::new(command, &definition)?);
        authorize()?;
        // 先同步唯一方向与原受理身份，再触碰活动文件；后续超时或取消不撤销已经取得的恢复责任。
        self.advance_action(&mut storage, next)?;
        let plan = storage
            .as_ref()
            .and_then(|current| current.action())
            .and_then(|action| action.files.as_ref())
            .context("node action file decision disappeared")?;
        local::apply::run(&self.root, plan)
    }

    /// 业务作用：当前授权重投只继续原持久方向，文件中断后不重新选候选或替换原 attempt。
    ///
    /// 参数说明：
    /// - `command`：同一意图的 apply 执行、执行查询或补偿重投。
    /// - `authorize`：真实工作许可内的当前会话、权限和期限门。
    ///
    /// 返回：原方向完整落位；没有相应未决方向时拒绝，不把文件完成解释为快照已发布。
    pub(crate) fn resume_action_files(
        &self,
        command: &Command,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let checked = command.validate(&definition)?;
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
            .context("node action file decision is absent")?;
        let matches = match (
            checked.identity().phase,
            command.delivery.resolve_compensation,
        ) {
            (StepPhase::Execute | StepPhase::Resolve, false) => action.stage == Stage::Forward,
            (StepPhase::Compensate, false) | (StepPhase::Resolve, true) => {
                action.stage == Stage::Backward
            }
            _ => false,
        };
        ensure!(
            checked.step() == Step::Apply
                && matches
                && current.local().is_none()
                && action.intent == command.intent
                && action.intent_sha256 == *checked.intent_sha256()
                && command.delivery.receiving_boot_id == *boot
                && command.delivery.fence >= current.highest_fence(),
            "node action cannot resume this file direction"
        );
        authorize()?;
        local::apply::preflight(
            &self.root,
            action
                .files
                .as_ref()
                .context("node action file plan is absent")?,
        )?;
        let mut next = action.clone();
        next.fence = command.delivery.fence;
        authorize()?;
        if next.fence != action.fence {
            // 更高目标 fence 先持久，失去租约的旧投递不能在本次恢复之后重新取得决定权。
            self.advance_action(&mut storage, next)?;
        }
        let plan = storage
            .as_ref()
            .and_then(|current| current.action())
            .and_then(|action| action.files.as_ref())
            .context("node action file decision disappeared")?;
        local::apply::run(&self.root, plan)
    }
}

/// 业务作用：补偿只能作用于原动作仍拥有的活动状态，外部发布和重启不能仅靠相同正文重新取得覆盖权。
///
/// 参数说明：
/// - `action`：当前 head 中不可改写的原意图及发布事实。
/// - `active`：外层实例门仍在复验的实际活动快照。
/// - `boot`：本次真实进程身份。
///
/// 返回：原已确认发布仍拥有，或未确认方向对应原基线/完整原候选时成功；其余情况拒绝文件回退。
fn require_compensation_owner(action: &Record, active: &GatewaySnapshot, boot: &str) -> Result<()> {
    if let Some(publication) = &action.publication {
        ensure!(
            publication.owned
                && publication.boot_id == boot
                && publication.version == active.version
                && active.config_fingerprint == Some(publication.fingerprint),
            "node action lost publication ownership"
        );
        return Ok(());
    }
    if action.intent.original_boot_id == boot
        && active.version == action.intent.base_version
        && active.config_fingerprint == Some(action.intent.base_fingerprint)
        && active.document_identity.as_ref().is_some_and(|identity| {
            NodeBaseline::from_parts(
                action.intent.baseline.cluster_id.clone(),
                action.intent.baseline.store_id.clone(),
                action
                    .intent
                    .baseline
                    .node_admission_epoch
                    .parse()
                    .expect("validated epoch"),
                identity.digest(),
            ) == action.intent.baseline
        })
    {
        return Ok(());
    }
    // 未确认方向可能已经完成 ArcSwap；只承认完整原候选，不从未知收据推断任何后来快照也可被撤回。
    local::require_snapshot(
        action
            .files
            .as_ref()
            .context("node action file plan is absent")?,
        active,
    )?;
    ensure!(
        active.config_fingerprint.is_some()
            && dependencies::capture(
                active,
                Documents {
                    gateway: &active.source_config_path,
                    sidecars: None
                }
            )? == action.dependencies_sha256,
        "node action unconfirmed publication differs"
    );
    Ok(())
}
