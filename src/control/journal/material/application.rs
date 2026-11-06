//! 新文件方向必须先取得完整当前授权并提交整批事实，重放只沿用原计划和原秘密槽。

use super::{bodies, execution::Direction, Record, Stage};
use crate::{
    config::GatewaySnapshot,
    control::{
        journal::{storage, Journal},
        material::execution::{
            command::{Command, Step},
            effect::Admission,
            receipt::Reason,
        },
    },
    tls::keypair::execution::apply::locked,
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use std::{path::Path, sync::Arc};

impl Journal {
    /// 业务作用：持当前发布权决定整批应用或条件补偿，所有来源的方向和目标代先于第一处活动文件变化。
    ///
    /// 参数说明：
    /// - `command`：已经验签的原节点Apply、补偿或Resolve；Resolve仅可补齐已经决定的对应方向。
    /// - `active`：调用者持有发布权的当前完整配置。
    /// - `authorize`：复验当前四主体、实际许可、会话和有限执行窗口。
    ///
    /// 返回：原方向文件已完整落地时成功；仍无监听成功收据，失败保留已提交责任供原方向恢复。
    pub(crate) fn apply_material(
        &self,
        command: &Command,
        active: &GatewaySnapshot,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let checked = command.validate()?;
        ensure!(
            checked.step() == Step::Apply
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Compensate | StepPhase::Resolve
                ),
            "material application requires an apply direction"
        );
        let backward = checked.identity().phase == StepPhase::Compensate
            || (checked.identity().phase == StepPhase::Resolve
                && command.delivery.resolve_compensation);
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let original = self
            .require_material_command(storage.as_ref(), command)?
            .clone();
        let execution = original
            .execution
            .as_ref()
            .context("material execution absent")?;
        authorize()?;
        let pending = if backward {
            Stage::Backward
        } else {
            Stage::Forward
        };
        let stable = if backward {
            Stage::Reverted
        } else {
            Stage::Applied
        };
        if matches!(original.stage, stage if stage == pending || stage == stable) {
            // 重投只沿用原受理身份和原目标代，不创建第二份Admission或重新分配补偿代。
            return locked(|| {
                execution
                    .configuration
                    .require_snapshot(active, &original.intent)?;
                if original.stage == stable {
                    return require_goal(&original);
                }
                self.retain_material_fence(&mut storage, command.delivery.fence, &mut authorize)?;
                self.deliver_material_direction(
                    &mut storage,
                    &active.document_paths.gateway,
                    &mut authorize,
                )
            });
        }
        // 查询只能沿原持久方向推进，不能把Prepared或另一个方向变成一次新的业务受理。
        ensure!(
            checked.identity().phase != StepPhase::Resolve,
            "material resolution has no matching admitted direction"
        );
        // 新方向不借旧boot或旧内存版本取得正向覆盖权；重启后Prepared必须先失效。
        if !backward {
            ensure!(
                original.stage == Stage::Prepared
                    && command.intent.original_boot_id == command.delivery.receiving_boot_id
                    && active.version == original.intent.base_version,
                "material preparation is no longer applicable"
            );
        } else {
            ensure!(
                matches!(original.stage, Stage::Forward | Stage::Applied),
                "material compensation requires an original forward decision"
            );
        }
        if let Err(error) = execution
            .configuration
            .require_snapshot(active, &original.intent)
        {
            self.protect_material(&mut storage, Reason::BaselineChanged)?;
            return Err(error);
        }
        locked(|| {
            bodies::require_complete(&self.root, &original)?;
            if backward && original.stage == Stage::Forward {
                // 已决定Forward的部分完成仍有原恢复权；先完整到达原next，再以全批next为条件决定新补偿代。
                // 任何第三方来源变化仍由原重放门保护，不能把未写完的原批直接判成第三方接管。
                self.retain_material_fence(&mut storage, command.delivery.fence, &mut authorize)?;
                self.deliver_material_direction(
                    &mut storage,
                    &active.document_paths.gateway,
                    &mut authorize,
                )?;
            }
            let mut goals = Vec::new();
            for (index, plan) in execution.sources.plans.iter().enumerate() {
                let backup = bodies::backup(&self.root, &original, index)?;
                let verified = if backward {
                    // 原完整next才有条件补偿资格；任一第三方代出现时整批拒绝，不覆盖已变来源。
                    plan.require_applied()
                } else {
                    plan.require_prepared(&backup)
                };
                if let Err(error) = verified {
                    self.protect_material(&mut storage, Reason::SourceChanged)?;
                    return Err(error);
                }
                if backward {
                    goals.push(plan.compensation(&backup)?);
                }
            }
            let mut next_execution = execution.as_ref().clone();
            next_execution.direction = Some(if backward {
                Direction::Backward
            } else {
                Direction::Forward
            });
            if backward {
                next_execution.compensation = Some(Arc::new(goals));
            }
            next_execution.admissions.push(Admission::new(command)?);
            let mut next = original.clone();
            next.fence.value = command.delivery.fence;
            next.stage = if backward {
                Stage::Backward
            } else {
                Stage::Forward
            };
            next.execution = Some(Arc::new(next_execution));
            authorize()?;
            execution
                .configuration
                .require_snapshot(active, &original.intent)?;
            bodies::require_complete(&self.root, &original)?;
            // 全部来源在最后授权之后再复验，前面已读到的旧pair不能在整批决定前失去归属。
            for (index, plan) in execution.sources.plans.iter().enumerate() {
                if backward {
                    plan.require_applied()?;
                } else {
                    plan.require_prepared(&bodies::backup(&self.root, &original, index)?)?;
                }
            }
            self.advance_material(&mut storage, next)?;
            // 方向同步先于任何文件替换；此后失权只停止当前交付，不把已决定方向改回未受理。
            self.deliver_material_direction(
                &mut storage,
                &active.document_paths.gateway,
                &mut authorize,
            )
        })
    }

    /// 业务作用：在原方向在线重放之前持久更高独立水位，旧租约投递不能在恢复之后重新取得写权。
    ///
    /// 参数说明：
    /// - `storage`：调用者持有并已复验的原head锁。
    /// - `fence`：同一已验证命令的材料执行水位。
    /// - `authorize`：当前会话、四主体和期限门。
    ///
    /// 返回：更高水位同步后成功；相同水位不改head，旧水位或授权变化拒绝。
    pub(super) fn retain_material_fence(
        &self,
        storage: &mut Option<storage::Snapshot>,
        fence: u64,
        authorize: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let record = storage
            .as_ref()
            .and_then(storage::Snapshot::material)
            .context("material replay responsibility absent")?;
        ensure!(
            fence >= record.fence.value,
            "material replay fence is stale"
        );
        if fence > record.fence.value {
            let mut next = record.clone();
            next.fence.value = fence;
            authorize()?;
            // 更高权威先于任何恢复副作用；随后取消仍保留该水位与原受理事实。
            self.advance_material(storage, next)?;
        }
        Ok(())
    }

    /// 业务作用：把当前交付绑定原永久节点、受理代际、独立水位和完整意图，禁止跨动作继承文件权威。
    ///
    /// 参数说明：
    /// - `storage`：调用者已锁定并复验的head。
    /// - `command`：当前已验签的材料命令。
    ///
    /// 返回：同一原责任借用；旧代际、旧fence、异boot或不可执行格式均拒绝。
    pub(super) fn require_material_command<'a>(
        &self,
        storage: Option<&'a storage::Snapshot>,
        command: &Command,
    ) -> Result<&'a Record> {
        let checked = command.validate()?;
        let current = storage.context("material storage absent")?;
        let record = current
            .material()
            .context("material responsibility absent")?;
        let boot = self
            .action_boot
            .get()
            .context("material action boot is not bound")?;
        ensure!(
            record.schema == 2
                && record.stage != Stage::Protected
                && record.intent == command.intent
                && record.intent_sha256 == *checked.intent_sha256()
                && record.intent.node_id == self.identity.node_id
                && record.intent.baseline.cluster_id == self.identity.cluster_id
                && record.intent.baseline.store_id == self.identity.store_id
                && record.intent.baseline.node_admission_epoch
                    == current.admission_epoch().to_string()
                && command.delivery.receiving_boot_id == *boot
                && record.fence.store == command.intent.execution_store
                && command.delivery.fence >= record.fence.value,
            "material command does not own the original responsibility"
        );
        Ok(record)
    }

    /// 业务作用：在同一TLS锁内区分当前交付失权与原来源不可信，后者持久保护且不改写原受理事实。
    ///
    /// 参数说明：
    /// - `storage`：调用者持有的当前head锁。
    /// - `main`：当前实际主配置入口。
    /// - `authorize`：每处副作用前复验当前交付资格。
    ///
    /// 返回：完整原方向已到达时成功；失权保留原方向，其它可解释失败持久保护，未知head拒绝推进。
    fn deliver_material_direction(
        &self,
        storage: &mut Option<storage::Snapshot>,
        main: &Path,
        authorize: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let mut authority_lost = false;
        let current = storage
            .as_ref()
            .context("material direction storage absent")?;
        let result = self.replay_material(current, main, &mut || {
            let result = authorize();
            authority_lost |= result.is_err();
            result
        });
        if result.is_err() && !authority_lost {
            self.protect_material(storage, Reason::SourceChanged)?;
        }
        result
    }

    /// 业务作用：持同一TLS锁逐来源补齐已提交方向，每次只读取一份备份，文件完成不直接结算监听收据。
    ///
    /// 参数说明：
    /// - `current`：当前head已经持久确认的完整存储事实。
    /// - `main`：本机实际主配置入口。
    /// - `authorize`：在线交付的当前授权门；启动恢复只使用原持久方向，不继承旧会话。
    ///
    /// 返回：全部来源精确到达所选预分配代时成功；任一失败保留原方向与秘密，不清理未知现场。
    pub(super) fn replay_material(
        &self,
        current: &storage::Snapshot,
        main: &Path,
        authorize: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let record = current
            .material()
            .context("material replay responsibility absent")?;
        let execution = record
            .execution
            .as_ref()
            .context("material replay plan absent")?;
        ensure!(
            matches!(record.stage, Stage::Forward | Stage::Backward),
            "material stage has no pending file direction"
        );
        execution
            .configuration
            .require_current(main, &record.intent)?;
        bodies::require_complete(&self.root, record)?;
        let candidate = bodies::candidate(&self.root, record)?;
        for (index, plan) in execution.sources.plans.iter().enumerate() {
            authorize()?;
            execution
                .configuration
                .require_current(main, &record.intent)?;
            self.verify_expected(Some(current))?;
            let backup = bodies::backup(&self.root, record, index)?;
            let goal = execution.compensation.as_ref().map(|goals| &goals[index]);
            plan.replay(&candidate, &backup, goal)?;
        }
        execution
            .configuration
            .require_current(main, &record.intent)?;
        self.verify_expected(Some(current))?;
        require_goal(record)
    }
}

/// 业务作用：在路由开放或稳定收据之前复验完整原方向，单个来源成功不能代表整批完成。
///
/// 参数说明：
/// - `record`：当前持久材料责任及原目标代。
///
/// 返回：全部来源完整属于原方向时成功，不读取监听注册表、不产生稳定结果。
pub(super) fn require_goal(record: &Record) -> Result<()> {
    let execution = record.execution.as_ref().context("material goal absent")?;
    ensure!(
        execution.direction.is_some(),
        "material file direction absent"
    );
    for (index, plan) in execution.sources.plans.iter().enumerate() {
        plan.require_goal(execution.compensation.as_ref().map(|goals| &goals[index]))?;
    }
    Ok(())
}
