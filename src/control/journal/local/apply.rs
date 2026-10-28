//! 只执行已持久决定的文件方向，未知实际内容始终保留。

use super::{
    bodies,
    model::{mode, permissions, Destination, Direction, FileState, Plan},
    prepare::matches,
};
use crate::control::{documents::Target, journal::filesystem::Root};
use anyhow::{ensure, Context, Result};
use cap_std::fs::OpenOptions;
use std::io::Read;

/// 业务作用：先验证完整恢复集合和所有保留暂存项，任何证据不足都不得先修改其它实际配置。
///
/// 参数说明：
/// - `root`：唯一owner持有的私有正文目录。
/// - `plan`：head已选择的Forward或Backward决定。
///
/// 返回：全部正文、父目录、旧/新目标与暂存前缀可信时成功；不写入文件。
pub(in crate::control::journal) fn preflight(root: &Root, plan: &Plan) -> Result<()> {
    ensure!(
        plan.direction != Direction::Preparing,
        "local publication has no file decision"
    );
    bodies::verify(root, plan)?;
    retired(plan)?;
    for destination in &plan.targets {
        let target = destination.location.open()?;
        owned(&target, destination)?;
        check_reserved(
            root,
            &target,
            &destination.forward_stage,
            Some(destination.candidate),
        )?;
        check_reserved(
            root,
            &target,
            &destination.backward_stage,
            destination.original,
        )?;
    }
    Ok(())
}

/// 业务作用：按已提交方向恢复guard、Sentinel再恢复主指针，进程中断后可从同一计划继续。
///
/// 参数说明：
/// - `root`：持有完整权威正文的固定目录。
/// - `plan`：唯一已持久文件决定。
///
/// 返回：全部目标及目录同步完成；异常留下决定供重启或显式回退，绝不猜测另一方向。
pub(in crate::control::journal) fn run(root: &Root, plan: &Plan) -> Result<()> {
    preflight(root, plan)?;
    for (index, destination) in plan.targets.iter().enumerate() {
        let target = destination.location.open()?;
        let (expected, stage) = goal(plan.direction, destination)?;
        if !matches(&target, expected)? {
            if let Some(expected) = expected {
                install(root, plan, index, &target, destination, expected, stage)?;
            } else {
                // 原本缺失的目标只能删除本计划的完整候选；部分正文或第三方文件不能冒充已安装内容。
                ensure!(
                    matches(&target, Some(destination.candidate))?,
                    "local publication delete target changed"
                );
                target.directory.remove_file(&target.name)?;
                target.sync()?;
            }
        }
    }
    // 只有目标集合完整后才能回收已验证的保留空间，无法证明所有权时保留决定并阻止新写入。
    cleanup(root, plan)?;
    require_goal(plan)
}

/// 业务作用：确认最终实际文件集合与当前决定完全一致，不能仅凭rename返回就结束持久记录。
///
/// 参数说明：
/// - `plan`：已经完成或等待完成的唯一方向。
///
/// 返回：所有目标和重新引用的退役基线成立；内容或目录变化拒绝。
pub(in crate::control::journal) fn require_goal(plan: &Plan) -> Result<()> {
    retired(plan)?;
    for destination in &plan.targets {
        let (expected, _) = goal(plan.direction, destination)?;
        ensure!(
            matches(&destination.location.open()?, expected)?,
            "local publication target is not complete"
        );
    }
    Ok(())
}

/// 业务作用：仅清理能够与权威正文逐字比较的协议保留项，不对任意文件名做递归或模糊匹配。
///
/// 参数说明：
/// - `root`：完整正文所在的固定目录。
/// - `plan`：授权这些有限保留名字的持久计划。
///
/// 返回：两个方向的精确暂存项都缺失或已确认删除；未知内容拒绝且保留。
pub(in crate::control::journal) fn cleanup(root: &Root, plan: &Plan) -> Result<()> {
    for destination in &plan.targets {
        let target = destination.location.open()?;
        for (name, state) in [
            (&destination.forward_stage, Some(destination.candidate)),
            (&destination.backward_stage, destination.original),
        ] {
            if check_reserved(root, &target, name, state)? {
                target.directory.remove_file(name)?;
                target.sync()?;
            }
        }
    }
    Ok(())
}

/// 业务作用：安装一份完整同步的权威正文，最终副作用之前复验目标和保留文件的实际身份。
///
/// 参数说明：
/// - `root`：固定正文目录。
/// - `plan`：已持久决定，用于恢复主指针前的退役基线门。
/// - `index`：固定文档角色位置。
/// - `target`：已复验父目录能力的目标。
/// - `destination`：该角色的旧/新身份。
/// - `expected`：本次方向需要安装的完整文件状态。
/// - `stage`：记录中已保留的单目录项名。
///
/// 返回：完整rename和目录同步成功；失败保留计划，部分暂存可在下一次按精确前缀续做。
fn install(
    root: &Root,
    plan: &Plan,
    index: usize,
    target: &Target,
    destination: &Destination,
    expected: FileState,
    stage: &str,
) -> Result<()> {
    if check_reserved(root, target, stage, Some(expected))? {
        target.directory.remove_file(stage)?;
        target.sync()?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = target.directory.open_with(stage, &options)?;
    let mut source = bodies::open(root, expected.body)?;
    ensure!(
        bodies::copy(&mut source, &mut file)? == expected.body.fingerprint,
        "local publication body changed during copy"
    );
    file.sync_all()?;
    file.set_permissions(permissions(expected.mode)?)?;
    file.sync_all()?;
    let temporary = temporary(target, stage);
    ensure!(
        matches(&temporary, Some(expected))?,
        "local publication staging changed before installation"
    );
    let metadata = file.metadata()?;
    let current = temporary
        .file()?
        .context("local publication staging disappeared")?
        .1;
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        ensure!(
            metadata.dev() == current.dev() && metadata.ino() == current.ino(),
            "local publication staging owner changed"
        );
    }
    // 暂存和正文验证不授予新的覆盖权；紧邻rename再次检查父目录与当前实际旧/新内容。
    destination.location.open()?;
    owned(target, destination)?;
    if index == 2 {
        // 恢复旧主指针会重新引用退役文件，最后一步必须确认它们仍属于原基线。
        retired(plan)?;
    }
    target
        .directory
        .rename(stage, &target.directory, &target.name)?;
    target.sync()
}

/// 业务作用：限定配置目标只能是记录中的完整旧态或完整候选态，禁止以前缀接纳实际配置。
///
/// 参数说明：
/// - `target`：当前实际目标。
/// - `destination`：唯一持久计划记录的身份集合。
///
/// 返回：至少匹配一个完整状态时成功，第三种内容或权限立即拒绝。
fn owned(target: &Target, destination: &Destination) -> Result<()> {
    ensure!(
        matches(target, destination.original)? || matches(target, Some(destination.candidate))?,
        "local publication target has foreign content"
    );
    Ok(())
}

/// 业务作用：回退旧指针之前保护退出候选引用的原文件，不能把后来变更的退役内容重新开放。
///
/// 参数说明：
/// - `plan`：当前文件方向和明确旧/新路径。
///
/// 返回：Backward的所有退役基线仍完整时成功，Forward不要求恢复已退出引用的正文。
fn retired(plan: &Plan) -> Result<()> {
    for old in &plan.baseline {
        let target = old.location.open()?;
        if plan.direction == Direction::Backward
            && !plan
                .targets
                .iter()
                .any(|destination| destination.location.path == old.location.path)
        {
            ensure!(
                matches(&target, Some(old.state))?,
                "local publication retired baseline changed"
            );
        }
    }
    Ok(())
}

/// 业务作用：从唯一持久方向取得目标状态和保留名，Preparing没有任何文件副作用权。
///
/// 参数说明：
/// - `direction`：head选择的恢复方向。
/// - `destination`：固定角色的目标记录。
///
/// 返回：完整目标状态与保留名字；未决定时拒绝。
fn goal(direction: Direction, destination: &Destination) -> Result<(Option<FileState>, &str)> {
    match direction {
        Direction::Forward => Ok((Some(destination.candidate), &destination.forward_stage)),
        Direction::Backward => Ok((destination.original, &destination.backward_stage)),
        Direction::Preparing => anyhow::bail!("local publication has no file decision"),
    }
}

/// 业务作用：只对协议保留临时项允许部分原文，必须与完整权威正文逐字匹配且权限合法。
///
/// 参数说明：
/// - `root`：完整权威正文所在目录。
/// - `target`：已固定的真实父目录。
/// - `name`：完整计划中的保留名字。
/// - `expected`：该临时项对应正文，空表示该方向绝不能有暂存文件。
///
/// 返回：缺失为假；普通单链接文件是准确前缀时为真，未知内容或非法权限拒绝。
fn check_reserved(
    root: &Root,
    target: &Target,
    name: &str,
    expected: Option<FileState>,
) -> Result<bool> {
    let temporary = temporary(target, name);
    let Some((mut file, metadata)) = temporary.file()? else {
        return Ok(false);
    };
    let expected = expected.context("local publication has an unexpected staging file")?;
    let actual_mode = mode(&metadata.permissions())?;
    ensure!(
        (actual_mode == 0o600 || actual_mode == expected.mode)
            && metadata.len() <= expected.body.fingerprint.length,
        "local publication staging boundary differs"
    );
    let mut source = bodies::open(root, expected.body)?;
    let mut actual = [0u8; 16384];
    let mut authoritative = [0u8; 16384];
    let mut length = 0u64;
    loop {
        let count = file.read(&mut actual)?;
        if count == 0 {
            break;
        }
        length += count as u64;
        ensure!(
            length <= metadata.len(),
            "local publication staging grew while reading"
        );
        source.read_exact(&mut authoritative[..count])?;
        ensure!(
            actual[..count] == authoritative[..count],
            "local publication staging has foreign content"
        );
    }
    ensure!(
        length == metadata.len(),
        "local publication staging changed while reading"
    );
    Ok(true)
}

/// 业务作用：在同一固定父目录中检查精确保留项，不重新解析或扩大目录访问能力。
///
/// 参数说明：
/// - `target`：已经固定的最终目标。
/// - `name`：计划验证过的单个保留名字。
///
/// 返回：共用父目录能力的临时目标，仅用于验证该目录项。
fn temporary(target: &Target, name: &str) -> Target {
    Target {
        directory: target.directory.clone(),
        path: target.path.with_file_name(name),
        name: name.into(),
    }
}
