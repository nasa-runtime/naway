//! 节点命令沿用候选容量、私有工作区和唯一文件事务，等待取消不遗失真实任务。

use super::{admission::Permit, node_policy, Workspace};
use crate::{
    admin::{management::actions::Work, AdminState},
    config::candidate::{dependencies, Documents},
    control::{
        actions::{command::Step, definition, domain::Domain, receipt::Reason},
        journal::{Application, EffectState, Journal, LocalInput, Preparation, Stage},
    },
};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use nasa::saga::StepPhase;
use std::sync::Arc;

/// 业务作用：在分配正文前查询持久效果，重投不重复下载且取消查询不能提前归还动作许可。
///
/// 参数说明：
/// - `state`：提供同一文件事务及当前节点授权的管理实例。
/// - `work`：下载前已验签并取得的独占工作权。
///
/// 返回：原工作权与真实持久事实；存储或权限不能确认时拒绝，不产生效果收据。
pub(in crate::admin) async fn inspect(
    state: Arc<AdminState>,
    work: Work,
) -> Result<(Work, EffectState)> {
    work.authorize(&state, false)?;
    tokio::task::spawn_blocking(move || {
        state.config_history.with_node_action(|journal| {
            work.authorize(&state, false)?;
            let status = journal.read_action(work.command())?;
            Ok((work, status))
        })
    })
    .await
    .context("node effect inspection did not complete")?
}

/// 业务作用：将动作许可、候选和全部清理责任交给真实阻塞任务，客户端取消不产生第二个并行动作。
///
/// 参数说明：
/// - `state`：同一管理实例的候选预算、当前快照及统一文件事务。
/// - `work`：下载前取得且仍持续复验的真实动作许可。
/// - `body`：仅新 prepare 使用的验真原文，其余步骤复用持久材料。
///
/// 返回：原工作权及稳定效果或准确未决状态；文件落位仍须唤醒正常 reload，失败不猜测未执行。
pub(in crate::admin) async fn process(
    state: Arc<AdminState>,
    work: Work,
    body: Option<Bytes>,
) -> Result<(Work, EffectState)> {
    work.authorize(&state, false)?;
    let permit = state
        .candidate_builds
        .acquire()
        .map_err(|_| anyhow::anyhow!("candidate build capacity unavailable"))?;
    permit
        .spawn(move |permit| {
            state.config_history.with_node_action(|journal| {
                let status = execute(&state, &work, body, permit, journal)?;
                Ok((work, status))
            })
        })
        .await
        .context("node action worker did not complete")?
}

/// 业务作用：依据持久事实选择唯一允许的动作分支，查询、重投和补偿不能从空槽推测历史。
///
/// 参数说明：
/// - `state`：当前管理 owner。
/// - `work`：贯穿本阻塞闭包的动作许可和原始身份。
/// - `body`：新 prepare 的有限原文。
/// - `permit`：现有候选工作区预算及清理保护权。
/// - `journal`：同一文件写事务内的永久节点 owner。
///
/// 返回：原效果的当前事实；未知阶段不产生新收据，任何副作用先经过当前写入和审阅门。
fn execute(
    state: &AdminState,
    work: &Work,
    body: Option<Bytes>,
    permit: &Permit,
    journal: &Journal,
) -> Result<EffectState> {
    work.authorize(state, false)?;
    let command = work.command();
    let definition = definition::cached(command.intent.target_count as usize)?;
    let checked = command.validate(&definition)?;
    let phase = checked.identity().phase;
    let status = journal.read_action(command)?;
    if command.delivery.resolve_compensation {
        // 补偿查询只能继续已经持久决定的 Backward，不能用它收尾准备或触发新的文件方向。
        if checked.step() == Step::Apply && matches!(&status, EffectState::Pending(Stage::Backward))
        {
            journal.resume_action_files(command, || work.authorize(state, true))?;
            work.authorize(state, false)?;
            return journal.read_action(command);
        }
        return Ok(status);
    }
    match (checked.step(), phase, status) {
        (_, _, stable @ (EffectState::Stable(_) | EffectState::Closed)) => return Ok(stable),
        (Step::Prepare, StepPhase::Execute, EffectState::Vacant) => {
            work.authorize(state, true)?;
            prepare(
                state,
                work,
                body.context("node preparation body is absent")?,
                permit,
                journal,
            )?;
        }
        (Step::Prepare, StepPhase::Resolve, EffectState::Vacant)
        | (
            Step::Apply,
            StepPhase::Resolve,
            EffectState::Pending(Stage::Prepared | Stage::Invalidated),
        ) => {
            // 唯一工作许可和文件事务排除仍在执行的旧动作；持久拒绝及更高 fence 先于查询结果。
            journal.reject_unadmitted_action(command, || work.authorize(state, true))?;
        }
        (
            Step::Prepare,
            StepPhase::Execute | StepPhase::Resolve,
            EffectState::Pending(Stage::Preparing),
        ) => {
            // 唯一真实许可证明前一个准备工作已经退出，才可按原 Admission 收尾无文件授权的中断。
            journal.reject_action_preparation(command, Reason::PreparationInterrupted, || {
                work.authorize(state, true)
            })?;
        }
        (Step::Apply, StepPhase::Execute, EffectState::Pending(Stage::Prepared)) => {
            work.authorize(state, true)?;
            if let Err(error) = apply(state, work, permit, journal) {
                // 只有仍未选择 Forward 时才能确定拒绝；方向或未知 head 已存在则保留原错误与恢复责任。
                if journal
                    .reject_action_application(command, Reason::BaselineChanged, || {
                        work.authorize(state, true)
                    })
                    .is_err()
                {
                    return Err(error);
                }
            }
        }
        (Step::Apply, StepPhase::Execute, EffectState::Pending(Stage::Invalidated)) => {
            journal.reject_action_application(command, Reason::BaselineChanged, || {
                work.authorize(state, true)
            })?;
        }
        (
            Step::Apply,
            StepPhase::Execute | StepPhase::Resolve,
            EffectState::Pending(Stage::Forward),
        )
        | (Step::Apply, StepPhase::Compensate, EffectState::Pending(Stage::Backward)) => {
            journal.resume_action_files(command, || work.authorize(state, true))?;
        }
        (
            Step::Apply,
            StepPhase::Compensate,
            EffectState::Pending(Stage::Forward | Stage::Applied),
        ) => {
            work.authorize(state, true)?;
            apply(state, work, permit, journal)?;
        }
        (
            Step::Apply,
            StepPhase::Compensate,
            EffectState::Pending(Stage::Prepared | Stage::Invalidated),
        )
        | (
            Step::Prepare,
            StepPhase::Compensate,
            EffectState::Pending(
                Stage::Prepared | Stage::Invalidated | Stage::Rejected | Stage::Reverted,
            ),
        ) => {
            journal.compensate_action_without_files(command, || work.authorize(state, true))?;
        }
        (_, _, unresolved) => return Ok(unresolved),
    }
    work.authorize(state, false)?;
    journal.read_action(command)
}

/// 业务作用：以原领域字节夹住完整候选构建和依赖证明，再持久准备，不触碰活动配置。
///
/// 参数说明：
/// - `state`：真实部署根及初始化边界。
/// - `work`：当前签名、许可与原活动实例。
/// - `body`：只替换签名领域的原始字节。
/// - `permit`：工作区的真实清理 owner。
/// - `journal`：已持唯一文件事务的持久动作 owner。
///
/// 返回：成功准备或确定拒绝已落盘；身份、清理或存储不能确认时返回错误并保留原事实。
fn prepare(
    state: &AdminState,
    work: &Work,
    body: Bytes,
    permit: &Permit,
    journal: &Journal,
) -> Result<()> {
    let command = work.command();
    let active = work.active();
    use sha2::{Digest as _, Sha256};
    ensure!(
        body.len() == command.intent.candidate_bytes as usize
            && Sha256::digest(&body)[..] == command.intent.candidate_sha256,
        "node preparation body integrity differs"
    );
    let version = active
        .version
        .checked_add(1)
        .context("config version space exhausted")?;
    let mut workspace = Workspace::create(&state.cfg_path, permit)?;
    let result = (|| -> Result<()> {
        node_policy::require_scope(work, &body)?;
        let baseline = dependencies::capture(
            active,
            Documents {
                gateway: &active.source_config_path,
                sidecars: None,
            },
        )?;
        let documents =
            workspace.write_domain(command.intent.domain, &body, &active.document_paths)?;
        let first = node_policy::load(
            &state.cfg_path,
            documents,
            version,
            active,
            &state.config_history,
        )?;
        let proof = dependencies::capture(&first, documents)?;
        let candidate = node_policy::load(
            &state.cfg_path,
            documents,
            version,
            active,
            &state.config_history,
        )?;
        ensure!(
            dependencies::capture(&candidate, documents)? == proof,
            "node candidate dependencies changed during build"
        );
        let mut desired = [None; 3];
        desired[match command.intent.domain {
            Domain::InterfaceGuard => 0,
            Domain::Sentinel => 1,
            Domain::Gateway => 2,
        }] = Some(body.as_ref());
        journal.prepare_action(
            Preparation {
                command,
                active,
                documents,
                files: LocalInput {
                    current: active.document_paths.ordered(),
                    targets: candidate.document_paths.ordered(),
                    baseline: None,
                    desired,
                    candidate: Some(&candidate),
                },
                dependencies_sha256: proof,
                baseline_dependencies_sha256: baseline,
            },
            || work.authorize(state, true),
        )?;
        Ok(())
    })();
    workspace.cleanup()?;
    if let Err(error) = result {
        // 准备从未授权活动文件写入；仅在当前写入权仍存在且 head 可确认时记录这次无法准备的事实。
        if journal
            .reject_action_preparation(command, Reason::CandidateInvalid, || {
                work.authorize(state, true)
            })
            .is_err()
        {
            return Err(error);
        }
    }
    Ok(())
}

/// 业务作用：用持久原文流式重建正向或补偿候选，在最后一个门确认后才选择文件方向。
///
/// 参数说明：
/// - `state`：当前配置边界与真实文件事务。
/// - `work`：本次仍持有的动作许可和当前活动实例。
/// - `permit`：临时工作区清理责任。
/// - `journal`：提供精确原材料和最终决定的唯一 owner。
///
/// 返回：文件目标落位且临时材料已清理；仍须等正常资源准备和实际发布后确认效果。
fn apply(state: &AdminState, work: &Work, permit: &Permit, journal: &Journal) -> Result<()> {
    let command = work.command();
    let active = work.active();
    let version = active
        .version
        .checked_add(1)
        .context("config version space exhausted")?;
    let mut materials = journal.read_action_materials(command)?;
    let mut workspace = Workspace::create(&state.cfg_path, permit)?;
    workspace.write_files(&mut materials.files)?;
    let result = (|| -> Result<()> {
        let documents = workspace.documents();
        let first = node_policy::load(
            &state.cfg_path,
            documents,
            version,
            active,
            &state.config_history,
        )?;
        ensure!(
            dependencies::capture(&first, documents)? == materials.dependencies_sha256,
            "node action frozen dependencies changed"
        );
        let candidate = node_policy::load(
            &state.cfg_path,
            documents,
            version,
            active,
            &state.config_history,
        )?;
        journal.decide_action_files(
            Application {
                command,
                active,
                candidate: &candidate,
                documents,
                materials: &materials,
            },
            || work.authorize(state, true),
        )
    })();
    workspace.cleanup()?;
    result
}
