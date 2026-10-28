//! 将已保存的精确正文能力交给候选重建，外来文件名不参与读取路径。

use super::{bodies, Direction, Plan};
use crate::{config::candidate::Paths, control::journal::filesystem::Root};
use anyhow::Result;
use std::fs::File;

/// 业务作用：按明确目标方向打开全部已校验正文，供同一私有工作单元流式重建候选。
///
/// 参数说明：
/// - `root`：当前唯一 owner 的固定持久目录能力。
/// - `plan`：当前 head 绑定的完整原文件计划。
/// - `direction`：候选 Forward 或原基线 Backward，不能由外部路径选择正文。
///
/// 返回：真实部署目标及主文档、guard、Sentinel 三个已验证句柄；任何材料或父目录异常拒绝。
pub(in crate::control::journal) fn open(
    root: &Root,
    plan: &Plan,
    direction: Direction,
) -> Result<(Paths, [File; 3])> {
    plan.validate()?;
    bodies::verify(root, plan)?;
    let states = match direction {
        Direction::Forward => plan
            .targets
            .each_ref()
            .map(|target| (&target.location, target.candidate)),
        Direction::Backward => plan
            .baseline
            .each_ref()
            .map(|document| (&document.location, document.state)),
        Direction::Preparing => anyhow::bail!("node action materials need a file goal"),
    };
    for (location, _) in &states {
        location.open()?;
    }
    let paths = Paths {
        gateway: states[2].0.path.clone(),
        guard: states[0].0.path.clone(),
        sentinel: states[1].0.path.clone(),
    };
    let files = [
        bodies::open(root, states[2].1.body)?.into_std(),
        bodies::open(root, states[0].1.body)?.into_std(),
        bodies::open(root, states[1].1.body)?.into_std(),
    ];
    Ok((paths, files))
}
