//! 所有材料节点入口共用持久状态机，发布权、文件事务和TLS锁按固定次序取得。

use super::{Content, Work};
use crate::{
    admin::AdminState,
    control::{
        journal::{Journal, MaterialEffect, MaterialStage},
        material::execution::command::Step,
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use std::{sync::Arc, time::Duration};

/// 业务作用：在下载候选前回读原材料效果，稳定结果和原秘密责任不需要重复获取材料。
///
/// 参数说明：
/// - `state`：本节点当前配置和唯一文件事务owner。
/// - `work`：当前验签且持有真实排他容量的工作。
///
/// 返回：同一已确认head的完整原生效果；取消等待仍由实际阻塞任务持有工作容量。
pub(super) async fn inspect(state: Arc<AdminState>, work: Arc<Work>) -> Result<MaterialEffect> {
    work.authorize(&state, false)?;
    tokio::task::spawn_blocking(move || {
        state.config_history.with_node_action(|journal| {
            work.authorize(&state, false)?;
            let observed = journal.read_material(work.command())?;
            work.authorize(&state, false)?;
            Ok(observed)
        })
    })
    .await
    .context("material query worker did not complete")?
}

/// 业务作用：仅允许尚无持久责任的首次准备下载候选，Resolve和重投必须沿原持久事实继续。
///
/// 参数说明：
/// - `work`：已经完整验签的原工作。
/// - `observed`：下载前同一文件owner的原子查询结果。
///
/// 返回：空槽Prepare Execute为真，其它情况不需要候选帧；非法原合同拒绝。
pub(super) fn needs_body(work: &Work, observed: &MaterialEffect) -> Result<bool> {
    let checked = work.command().validate()?;
    Ok(matches!(observed, MaterialEffect::Vacant)
        && checked.step() == Step::Prepare
        && checked.identity().phase == StepPhase::Execute)
}

/// 业务作用：在统一发布锁内处理完整材料生命周期，文件完成只触发后续安装确认而不伪造成功。
///
/// 参数说明：
/// - `state`：本节点发布、文件事务与真实安装注册表owner。
/// - `work`：贯穿候选与实际阻塞执行的已验签工作。
/// - `content`：仅首次准备需要的唯一完整材料帧。
///
/// 返回：推进后同一head的完整原生效果；等待取消不提前释放真实文件任务的许可或秘密容量。
pub(super) async fn process(
    state: Arc<AdminState>,
    work: Arc<Work>,
    content: Option<Arc<Content>>,
) -> Result<MaterialEffect> {
    work.authorize(&state, false)?;
    let publication =
        tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned())
            .await
            .context("material publication capacity unavailable")?;
    work.authorize(&state, false)?;
    tokio::task::spawn_blocking(move || {
        let _publication = publication;
        // 先持发布权再进文件事务，最内层由Journal持TLS锁；取消等待不能把文件任务留给无许可后台。
        state.config_history.with_node_action(|journal| {
            work.authorize(&state, false)?;
            let observed = journal.read_material(work.command())?;
            if matches!(
                observed,
                MaterialEffect::Stable { .. } | MaterialEffect::Closed
            ) {
                work.authorize(&state, false)?;
                return Ok(observed);
            }
            work.authorize(&state, true)?;
            advance(&state, &work, content.as_deref(), journal, &observed)?;
            let outcome = journal.read_material(work.command())?;
            work.authorize(&state, false)?;
            Ok(outcome)
        })
    })
    .await
    .context("material execution worker did not complete")?
}

/// 业务作用：只根据原生阶段和当前签名phase选择合法转换，查询不得创造一个新文件方向或受理身份。
///
/// 参数说明：
/// - `state`：持发布权的当前节点与实际安装注册表。
/// - `work`：已复验当前写权的原工作。
/// - `content`：首次Prepare Execute的候选；其它阶段不使用。
/// - `journal`：调用者持文件事务权的永久owner。
/// - `observed`：同一事务内刚刚读取的原材料效果。
///
/// 返回：合法决定完成或仍待外部安装时成功；持久身份、权限、来源或目标改变拒绝。
fn advance(
    state: &AdminState,
    work: &Work,
    content: Option<&Content>,
    journal: &Journal,
    observed: &MaterialEffect,
) -> Result<()> {
    let command = work.command();
    let checked = command.validate()?;
    let phase = checked.identity().phase;
    let stage = match observed {
        MaterialEffect::Pending(facts) => Some(facts.stage()),
        _ => None,
    };
    let authorize = || work.authorize(state, true);
    match (checked.step(), phase, stage) {
        (Step::Prepare, StepPhase::Execute, None) if matches!(observed, MaterialEffect::Vacant) => {
            let content = content.context("material preparation candidate absent")?;
            ensure!(
                content.material.0.len() == command.intent.candidate_bytes as usize
                    && content.digest == command.intent.candidate_sha256,
                "material preparation candidate differs"
            );
            journal.prepare_material(command, work.active(), &content.material, authorize)?;
        }
        (Step::Prepare, StepPhase::Resolve, None)
            if matches!(observed, MaterialEffect::Vacant)
                && !command.delivery.resolve_compensation =>
        {
            journal.reject_unadmitted_material(command, authorize)?;
        }
        (Step::Prepare, StepPhase::Execute | StepPhase::Resolve, Some(MaterialStage::Reserved))
            if !command.delivery.resolve_compensation =>
        {
            journal.resolve_material_preparation(command, authorize)?;
        }
        (
            Step::Prepare,
            StepPhase::Compensate,
            Some(
                MaterialStage::Prepared
                | MaterialStage::Invalidated
                | MaterialStage::Rejected
                | MaterialStage::Reverted,
            ),
        ) => {
            journal.compensate_material_preparation(command, work.active(), authorize)?;
        }
        (
            Step::Apply,
            StepPhase::Resolve,
            Some(MaterialStage::Prepared | MaterialStage::Invalidated),
        ) if !command.delivery.resolve_compensation => {
            journal.reject_unadmitted_material(command, authorize)?;
        }
        (
            Step::Apply,
            StepPhase::Execute,
            Some(MaterialStage::Prepared | MaterialStage::Forward),
        )
        | (
            Step::Apply,
            StepPhase::Compensate,
            Some(MaterialStage::Forward | MaterialStage::Applied | MaterialStage::Backward),
        ) => {
            journal.apply_material(command, work.active(), authorize)?;
            journal.try_confirm_material_installation(
                command,
                work.active(),
                state.installed_certificates(),
                authorize,
            )?;
        }
        (Step::Apply, StepPhase::Resolve, Some(stage))
            if (stage == MaterialStage::Forward && !command.delivery.resolve_compensation)
                || (stage == MaterialStage::Backward && command.delivery.resolve_compensation) =>
        {
            journal.apply_material(command, work.active(), authorize)?;
            journal.try_confirm_material_installation(
                command,
                work.active(),
                state.installed_certificates(),
                authorize,
            )?;
        }
        // 没有原受理、保护责任或相反方向都保持未知；不能从缺席稳定收据猜测一次成功或未执行。
        _ => {}
    }
    Ok(())
}
