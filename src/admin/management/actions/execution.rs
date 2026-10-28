//! 本机和远程命令共用同一持久执行与有限结果解释，文件落位不冒充已发布成功。

use super::Work;
use crate::{
    admin::{candidate::node, AdminState},
    control::{
        actions::{command::Step, definition},
        journal::{EffectState, Stage},
    },
};
use anyhow::{ensure, Result};
use bytes::Bytes;
use nasa::saga::StepPhase;
use std::sync::Arc;

/// 业务作用：仅在原效果尚未受理的新准备命令中允许获取候选正文。
///
/// 参数说明：
/// - work：已经验签并持有唯一真实许可的原工作。
/// - observed：同一文件 owner 查询的持久事实。
///
/// 返回：只有 Vacant 的 Prepare Execute 为真；重投和查询复用原持久材料。
pub(super) fn needs_body(work: &Work, observed: &EffectState) -> Result<bool> {
    let definition = definition::cached(work.command().intent.target_count as usize)?;
    let checked = work.command().validate(&definition)?;
    Ok(matches!(observed, EffectState::Vacant)
        && checked.step() == Step::Prepare
        && checked.identity().phase == StepPhase::Execute)
}

/// 业务作用：完成节点持久工作并保持真实许可到结果确认，原文只在新准备时传入。
///
/// 参数说明：
/// - state：活动节点及原候选、文件和重载 owner。
/// - work：贯穿执行和后续确认的原工作权。
/// - observed：下载之前读取的效果，只能跳过已经稳定或关闭的事实。
/// - body：新准备使用的共享验真原文，其余阶段为空。
///
/// 返回：原工作权与有限当前结果；信号、存储或权限不能证明时不声明业务成功。
pub(super) async fn finish(
    state: Arc<AdminState>,
    work: Work,
    observed: EffectState,
    body: Option<Bytes>,
) -> Result<(Work, EffectState)> {
    let (work, outcome) = if matches!(observed, EffectState::Stable(_) | EffectState::Closed) {
        (work, observed)
    } else {
        node::process(state.clone(), work, body).await?
    };
    if matches!(
        outcome,
        EffectState::Pending(Stage::Forward | Stage::Backward)
    ) {
        // 文件落位不等于资源已发布；只有现有 reload worker 能准备监听并发布唯一活动快照。
        // SAFETY: 只向本进程发送 SIGHUP，不解引用指针，信号处理器沿用已有有界事件通道。
        ensure!(
            unsafe {
                libc::kill(std::process::id() as i32, libc::SIGHUP)
            } == 0,
            "node reload signal unavailable"
        );
    }
    work.authorize(&state, false)?;
    Ok((work, outcome))
}
