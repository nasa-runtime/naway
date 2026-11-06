//! 材料执行与配置写者共享唯一head，独立调度域及fence在释放后仍永久保留。

use super::*;
use crate::control::journal::material::{bodies, Fence, Record, Stage};
use std::sync::Arc;

impl Snapshot {
    /// 业务作用：让一次已验证查询保留原head的共享材料事实，后续推进不混合不同提交的计划与收据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前完整记录的共享引用；不解析新副本，不暴露给网络编码器。
    pub(in crate::control::journal) fn shared_material(&self) -> Option<&Arc<Record>> {
        self.state.material.as_ref()
    }

    /// 业务作用：在受理材料动作时读取独立永久水位，配置动作的fence不能用来比较材料租约。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一head绑定的材料执行域和最高水位，缺失表示该域尚未绑定。
    pub(in crate::control::journal) fn material_fence(&self) -> Option<&Fence> {
        self.state.material_fence.as_ref()
    }
}

/// 业务作用：在原唯一head内受理或推进整批材料责任，所有元数据预算先于首次秘密槽创建。
///
/// 参数说明：
/// - `root`：唯一owner持有的私有目录能力。
/// - `identity`：该目录的永久节点绑定。
/// - `current`：owner已经完整确认的原提交。
/// - `next`：具有完整原计划和明确阶段的下一记录。
///
/// 返回：新head及目录同步完成后交付新快照；冲突、旧格式、容量或同步失败不推进内存事实。
pub(in crate::control::journal) fn transition(
    root: &Root,
    identity: &Identity,
    current: &Snapshot,
    next: Record,
) -> Result<Snapshot> {
    next.validate(identity, current.admission_epoch(), Some(&next.fence))?;
    ensure!(
        matches!(next.schema, 2 | 3) && current.local().is_none() && current.action().is_none(),
        "material execution overlaps configuration responsibility"
    );
    let reserve = match current.material() {
        Some(previous) => {
            previous.require_successor(&next)?;
            0
        }
        None => {
            // 首次受理只允许完整Reserved；永久域不能切换，更高水位也不能替换尚未释放的另一意图。
            ensure!(
                ((next.schema == 2 && next.stage == Stage::Reserved)
                    || (next.schema == 3 && next.stage == Stage::Rejected))
                    && current
                        .material_fence()
                        .is_none_or(|highest| highest.store == next.fence.store
                            && next.fence.value > highest.value),
                "material journal cannot admit this operation"
            );
            bodies::inspect(root, None)?;
            next.successor_reserve()?
        }
    };
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.material_fence = Some(next.fence.clone());
    state.material = Some(Arc::new(next));
    commit_reserving(root, identity, current, state, reserve)
}

/// 业务作用：在已持久撤销文件执行权且固定秘密槽全部清理之后关闭原受理代际，迟到准备不能复活。
///
/// 参数说明：
/// - `root`：原owner持有的目录能力。
/// - `identity`：原永久节点身份。
/// - `current`：已经确认的Cleaning提交，不接受未决或保护阶段。
///
/// 返回：清除责任并推进受理代际的新head；秘密仍在、证据异常或同步失败保留清理责任。
pub(in crate::control::journal) fn finish_cleanup(
    root: &Root,
    identity: &Identity,
    current: &Snapshot,
) -> Result<Snapshot> {
    let material = current
        .material()
        .context("material cleanup record absent")?;
    ensure!(
        material.stage == Stage::Cleaning
            && ((material.schema == 2
                && material
                    .execution
                    .as_ref()
                    .is_some_and(
                        |execution| execution.release.is_some() && execution.direction.is_none()
                    ))
                || (material.schema == 3
                    && material
                        .absence
                        .as_ref()
                        .is_some_and(|absence| absence.release.is_some()))),
        "material cleanup is not decided"
    );
    // 最后一个秘密槽删除与目录同步先于撤销预算；否则重启会留下没有任何原责任的秘密。
    bodies::inspect(root, None)?;
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.closed_epoch = current.admission_epoch();
    state.admission_epoch = state
        .admission_epoch
        .checked_add(1)
        .context("node journal admission epoch exhausted")?;
    state.material = None;
    commit(root, identity, current, state)
}

/// 业务作用：以独立材料共享补偿终态关闭从未受理的原节点代际，不伪造材料成功或清理其它写者正文。
///
/// 参数说明：
/// - `root`：原owner持有的私有目录。
/// - `identity`：永久节点绑定。
/// - `current`：调用者持锁并确认的原head。
/// - `epoch`：签名原意图的受理代际。
/// - `fence`：当前租约绑定的独立材料执行域及严格更高水位。
///
/// 返回：原epoch关闭且永久材料水位同步保留的新head；任何已有责任、秘密或异域均拒绝。
pub(in crate::control::journal) fn close_unadmitted(
    root: &Root,
    identity: &Identity,
    current: &Snapshot,
    epoch: u64,
    fence: &Fence,
) -> Result<Snapshot> {
    fence.validate()?;
    ensure!(
        current.admission_epoch() == epoch
            && current.material().is_none()
            && current.action().is_none()
            && current.local().is_none()
            && current
                .material_fence()
                .is_none_or(|highest| highest.store == fence.store && fence.value > highest.value),
        "unadmitted material release overlaps another responsibility"
    );
    // 没有原保留记录就没有任何秘密槽清理权，连未解释的空槽也不能在关闭代际时忽略。
    bodies::inspect(root, None)?;
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.closed_epoch = epoch;
    state.admission_epoch = epoch
        .checked_add(1)
        .context("node journal admission epoch exhausted")?;
    state.material_fence = Some(fence.clone());
    commit(root, identity, current, state)
}
