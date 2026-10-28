//! 动作与本地文件决定共用唯一 head，最高 fence 不随受理代际回收。

use super::*;
use crate::control::journal::actions::model::{Record, Stage};

impl Snapshot {
    /// 业务作用：向新动作受理提供永久 fence 水位，释放操作或关闭代际不能重置该权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已提交最高 fence；零只表示从未受理动作，不授予新动作资格。
    pub(in crate::control::journal) fn highest_fence(&self) -> u64 {
        self.state.highest_fence
    }

    /// 业务作用：提供同一 head 中的完整动作事实，任何旧槽或网络重投不能替换它。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前保留动作的借用；空只表示没有槽，不证明旧代际未执行。
    pub(in crate::control::journal) fn action(&self) -> Option<&Record> {
        self.state.action.as_ref()
    }
}

/// 业务作用：持久受理或推进同一业务意图，只有更高 fence 才能在空槽建立新动作。
///
/// 参数说明：
/// - `root`：唯一 owner 持有的存储目录。
/// - `identity`：该目录的永久节点绑定。
/// - `current`：owner 完整确认的原 head。
/// - `next`：经业务裁决产生的下一动作事实，不包含会话或临时租约。
///
/// 返回：完整同步后的新提交；冲突、身份替换、事实倒退或同步失败拒绝接纳。
pub(in crate::control::journal) fn transition(
    root: &Root,
    identity: &Identity,
    current: &Snapshot,
    next: Record,
) -> Result<Snapshot> {
    next.validate(identity, current.admission_epoch(), next.fence)?;
    match current.action() {
        Some(previous) => previous.require_successor(&next)?,
        None => {
            // 空槽仍保留最高 fence 和关闭代际，旧 owner 不能借终态回收重新获得写权。
            ensure!(
                current.local().is_none()
                    && next.fence > current.state.highest_fence
                    && matches!(next.stage, Stage::Preparing | Stage::Rejected),
                "node journal cannot admit this action"
            );
        }
    }
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.highest_fence = next.fence;
    state.action = Some(next);
    commit(root, identity, current, state)
}

/// 业务作用：在外层终态与授权已经确认后关闭精确动作代际，旧请求不能在释放后的空槽再次执行。
///
/// 参数说明：
/// - `root`：唯一 owner 持有的存储目录。
/// - `identity`：原永久绑定。
/// - `current`：当前完整提交事实。
/// - `intent_sha256`：外层已验证终态事件绑定的精确意图摘要。
/// - epoch：本次释放所关闭的原受理代际。
/// - fence：同意图已提交租约授予的新水位。
/// - allow_empty：整体已补偿时允许关闭从未受理的目标，不能据此构造业务收据。
///
/// 返回：先关闭代际再清除动作引用的新提交，最高 fence 保留；未决、保护或不符身份拒绝。
pub(in crate::control::journal) fn release(
    root: &Root,
    identity: &Identity,
    current: &Snapshot,
    intent_sha256: &[u8; 32],
    epoch: u64,
    fence: u64,
    allow_empty: bool,
) -> Result<Snapshot> {
    // 缺失收据不是终态；Prepared 仍可能应用，方向未确认或 HALTED 更不能自动回收。
    ensure!(
        current.local().is_none()
            && epoch == current.admission_epoch()
            && (1..=i64::MAX as u64).contains(&fence)
            && fence >= current.highest_fence(),
        "node journal action is not releasable"
    );
    if let Some(action) = current.action() {
        ensure!(
            action.intent_sha256 == *intent_sha256
                && (action.admissions.is_empty() || action.stage == Stage::Compensated)
                && matches!(
                    action.stage,
                    Stage::Applied
                        | Stage::Invalidated
                        | Stage::Reverted
                        | Stage::Rejected
                        | Stage::Compensated
                ),
            "node journal action is not releasable"
        );
    } else {
        // 未受理目标没有业务收据，仍须以更新的共享权威永久封闭原代际，阻止迟到准备。
        ensure!(
            allow_empty && fence > current.highest_fence(),
            "node journal empty epoch cannot be released"
        );
    }
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.admission_epoch = state
        .admission_epoch
        .checked_add(1)
        .context("node journal admission epoch exhausted")?;
    state.closed_epoch = current.admission_epoch();
    state.action = None;
    state.highest_fence = fence;
    commit(root, identity, current, state)
}
