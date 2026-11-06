//! 文件决定完成后由正常重载入口发布TLS，节点结果始终保留真实未决阶段。

use super::{node, Content, Work};
use crate::{
    admin::AdminState,
    control::journal::{MaterialEffect, MaterialStage},
};
use anyhow::{ensure, Result};
use std::sync::Arc;

/// 业务作用：完成本机或远程材料工作后唤醒实际重载，持久文件完成不能单独产生监听成功收据。
///
/// 参数说明：
/// - `state`：当前节点与唯一发布器。
/// - `work`：贯穿下载、持久执行和结果交付的原实际许可。
/// - `observed`：下载前原子读取的效果，仅稳定或关闭事实可以直接复用。
/// - `content`：首次准备使用的共享唯一材料帧，其余阶段为空。
///
/// 返回：完整原生效果供有界交付；失败不声称成功，真实文件责任继续由Journal保留。
pub(super) async fn finish(
    state: Arc<AdminState>,
    work: Arc<Work>,
    observed: MaterialEffect,
    content: Option<Arc<Content>>,
) -> Result<MaterialEffect> {
    let outcome = if matches!(
        observed,
        MaterialEffect::Stable { .. } | MaterialEffect::Closed
    ) {
        observed
    } else {
        node::process(state.clone(), work.clone(), content).await?
    };
    work.authorize(&state, false)?;
    if matches!(&outcome, MaterialEffect::Pending(facts)
        if matches!(facts.stage(), MaterialStage::Forward | MaterialStage::Backward))
    {
        // 同配置材料换代仍须进入正常资源发布流程；已提交方向允许去重门放行，但不自动确认收据。
        // SAFETY: 只向本进程发SIGHUP，不解引用指针，信号处理器沿用已有有界事件通道。
        let signaled = unsafe {
            // 已提交方向只唤醒唯一发布器，信号本身不产生材料稳定结果。
            libc::kill(std::process::id() as i32, libc::SIGHUP)
        };
        ensure!(signaled == 0, "material reload signal unavailable");
    }
    work.authorize(&state, false)?;
    Ok(outcome)
}
