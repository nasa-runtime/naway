//! 秘密正文只占用已选材料记录的固定槽，保留状态不声明正文已完整或可以执行。

use super::{Record, Stage};
use crate::control::journal::filesystem::Root;
use crate::control::material::{backup::Backup, Material};
use crate::tls::keypair::execution::prepare::Preparation;
use anyhow::{ensure, Context, Result};
use sha2::{Digest as _, Sha256};
use std::ffi::OsStr;
use std::io::{Read, Write};
use zeroize::Zeroizing;

const CANDIDATE: &str = "material-candidate";
const BACKUPS: [&str; crate::control::material::node::MAX_GROUPS] = [
    "material-backup-00",
    "material-backup-01",
    "material-backup-02",
    "material-backup-03",
    "material-backup-04",
    "material-backup-05",
    "material-backup-06",
    "material-backup-07",
    "material-backup-08",
    "material-backup-09",
    "material-backup-10",
    "material-backup-11",
    "material-backup-12",
    "material-backup-13",
    "material-backup-14",
    "material-backup-15",
    "material-backup-16",
    "material-backup-17",
    "material-backup-18",
    "material-backup-19",
    "material-backup-20",
    "material-backup-21",
    "material-backup-22",
    "material-backup-23",
    "material-backup-24",
    "material-backup-25",
    "material-backup-26",
    "material-backup-27",
    "material-backup-28",
    "material-backup-29",
    "material-backup-30",
    "material-backup-31",
];

/// 业务作用：限定独立秘密空间为一个候选和固定数量的来源备份，外部标识不参与路径解释。
///
/// 参数说明：
/// - `name`：存储目录枚举得到的单个名字。
///
/// 返回：仅协议固定槽为真，不接受其它数字拼写、路径或临时后缀。
pub(in crate::control::journal) fn known(name: &OsStr) -> bool {
    name == CANDIDATE
        || BACKUPS
            .iter()
            .any(|candidate| name == OsStr::new(candidate))
}

/// 业务作用：按已选 head 的原预算检查所有秘密槽，未选状态不能为额外文件提供保留资格。
///
/// 参数说明：
/// - `root`：当前固定的私有存储目录能力。
/// - `record`：已验证且属于当前提交的材料记录；没有记录时不允许任何秘密槽。
///
/// 返回：槽缺失或属于原保留额度的私有普通单链接文件时成功；只验边界，不读取秘密或确认完整性。
pub(in crate::control::journal) fn inspect(root: &Root, record: Option<&Record>) -> Result<()> {
    // 未受理布局没有秘密预算，连空槽也不能借否定证明获得保留或清理资格。
    let record = record.filter(|record| record.schema != 3);
    let required = record.is_some_and(|value| {
        value.stage != Stage::Cleaning
            && value
                .execution
                .as_ref()
                .is_some_and(|execution| execution.prepared)
    });
    // Reserved允许尚未写入的槽；只打开实际存在的固定名字，空闲查询不逐个探测全部秘密配额。
    for entry in root.dir.read_dir(".")? {
        let name = entry?.file_name();
        if name == CANDIDATE {
            inspect_one(
                root,
                CANDIDATE,
                record.map(|value| value.intent.candidate_bytes),
                required,
            )?;
        } else if let Some(index) = BACKUPS
            .iter()
            .position(|candidate| name == OsStr::new(candidate))
        {
            inspect_one(
                root,
                BACKUPS[index],
                record.and_then(|value| value.backup_bytes.get(index).copied()),
                required,
            )?;
        }
    }
    if required {
        let record = record.expect("complete material record is present");
        inspect_one(root, CANDIDATE, Some(record.intent.candidate_bytes), true)?;
        for (index, budget) in record.backup_bytes.iter().enumerate() {
            inspect_one(root, BACKUPS[index], Some(*budget), true)?;
        }
    }
    Ok(())
}

/// 业务作用：只有完整Reserved已经提交后才排他创建整批秘密槽，任何已有内容都不被覆盖或截断。
///
/// 参数说明：
/// - `root`：原owner的私有目录能力。
/// - `record`：当前head承认的原材料保留及完整来源计划。
/// - `candidate`：唯一原生候选帧借用。
/// - `prepared`：仍持有全批原来源句柄及单份备份的准备对象。
///
/// 返回：全部秘密正文与目录同步并通过完整摘要后成功；错误保留Reserved的明确清理责任。
pub(in crate::control::journal) fn write(
    root: &Root,
    record: &Record,
    candidate: &Material,
    prepared: &Preparation<'_>,
) -> Result<()> {
    let execution = record
        .execution
        .as_ref()
        .context("material preparation plan absent")?;
    ensure!(
        record.schema == 2
            && record.stage == Stage::Reserved
            && !execution.prepared
            && execution.sources == prepared.sources
            && prepared.backups.len() == record.backup_bytes.len(),
        "material preparation body contract differs"
    );
    require_candidate(record, candidate)?;
    for (plan, backup) in execution.sources.plans.iter().zip(&prepared.backups) {
        plan.require_backup(backup)?;
    }
    prepared.require_current()?;
    // 保留责任先于任何秘密落盘；只创建固定空槽，失败后的部分文件仍归原Reserved处理。
    write_one(root, CANDIDATE, &candidate.0)?;
    for (index, backup) in prepared.backups.iter().enumerate() {
        write_one(root, BACKUPS[index], backup.bytes())?;
    }
    require_complete(root, record)
}

/// 业务作用：在Prepared或文件方向提交前完整校验全部固定秘密槽，不将长度正确等同于原材料。
///
/// 参数说明：
/// - `root`：原固定秘密目录。
/// - `record`：含原候选及全部备份摘要的已验证记录。
///
/// 返回：全部槽存在且完整摘要成立时成功；任何缺项、替换、短读或损坏拒绝，不分配整份秘密。
pub(in crate::control::journal) fn require_complete(root: &Root, record: &Record) -> Result<()> {
    let execution = record
        .execution
        .as_ref()
        .context("material source plan absent")?;
    verify_one(
        root,
        CANDIDATE,
        record.intent.candidate_bytes,
        &record.intent.candidate_sha256,
        false,
    )?;
    for (index, plan) in execution.sources.plans.iter().enumerate() {
        verify_one(
            root,
            BACKUPS[index],
            plan.backup_bytes(),
            plan.backup_sha256(),
            false,
        )?;
    }
    Ok(())
}

/// 业务作用：在执行原决定时接管唯一候选清零缓冲，正文身份仍受原意图约束。
///
/// 参数说明：
/// - `root`：原秘密目录能力。
/// - `record`：当前head承认的完整材料责任。
///
/// 返回：完整合法候选帧；缺失、损坏或被替换拒绝，不返回部分正文。
pub(in crate::control::journal) fn candidate(root: &Root, record: &Record) -> Result<Material> {
    let candidate = Material(read_one(root, CANDIDATE, record.intent.candidate_bytes)?);
    require_candidate(record, &candidate)?;
    Ok(candidate)
}

/// 业务作用：按原来源索引读取唯一备份帧，当前目标顺序不能重新解释固定槽归属。
///
/// 参数说明：
/// - `root`：原秘密目录能力。
/// - `record`：当前完整材料责任。
/// - `index`：原来源计划中的固定顺序索引。
///
/// 返回：完整原pair备份；越界、缺失、摘要或owner不符拒绝并清零已读内容。
pub(in crate::control::journal) fn backup(
    root: &Root,
    record: &Record,
    index: usize,
) -> Result<Backup> {
    let execution = record
        .execution
        .as_ref()
        .context("material source plan absent")?;
    let plan = execution
        .sources
        .plans
        .get(index)
        .context("material source index differs")?;
    let name = BACKUPS.get(index).context("material backup slot differs")?;
    let backup = Backup::from_bytes(read_one(root, name, plan.backup_bytes())?)?;
    plan.require_backup(&backup)?;
    Ok(backup)
}

/// 业务作用：只在已提交清理责任后删除原固定秘密槽，清理中断可继续且不会恢复活动文件写权。
///
/// 参数说明：
/// - `root`：唯一owner仍持有的原目录。
/// - `record`：已经决定Cleaning的原责任，仍保留原预算与完整性信息。
///
/// 返回：全部精确槽删除并同步成功；未知类型或已准备正文损坏保留现场，不擅自丢弃。
pub(in crate::control::journal) fn cleanup(root: &Root, record: &Record) -> Result<()> {
    if record.schema == 3 {
        ensure!(
            record.stage == Stage::Cleaning
                && record
                    .absence
                    .as_ref()
                    .is_some_and(|absence| absence.release.is_some()),
            "material nonadmission cleanup is not committed"
        );
        return inspect(root, None);
    }
    let execution = record
        .execution
        .as_ref()
        .context("material cleanup plan absent")?;
    ensure!(
        record.schema == 2
            && record.stage == Stage::Cleaning
            && execution.release.is_some()
            && execution.direction.is_none(),
        "material cleanup is not committed"
    );
    inspect(root, Some(record))?;
    // 已准备正文必须仍是原帧；未完成准备只拥有原预算内的部分私有槽，均不得跟随链接或删除其它名字。
    let mut pending = Vec::with_capacity(execution.sources.plans.len() + 1);
    for index in 0..=execution.sources.plans.len() {
        let (name, budget, digest) = if index == 0 {
            (
                CANDIDATE,
                record.intent.candidate_bytes,
                &record.intent.candidate_sha256,
            )
        } else {
            let plan = &execution.sources.plans[index - 1];
            (
                BACKUPS[index - 1],
                plan.backup_bytes(),
                plan.backup_sha256(),
            )
        };
        let Some(file) = root.open_record(name, budget as usize)? else {
            continue;
        };
        if execution.prepared {
            hash_open(&file, budget, digest)?;
        }
        require_identity(root, name, &file)?;
        pending.push((name, file));
    }
    // 全部仍在的槽先通过完整性门，再删除第一项；后面的未知正文不能被前面的清理掩盖。
    for (name, file) in &pending {
        require_identity(root, name, file)?;
    }
    for (name, file) in pending {
        require_identity(root, name, &file)?;
        root.remove(name)?;
    }
    root.sync()
}

/// 业务作用：候选身份必须精确匹配原完整帧，单独证书摘要不能授权另一私钥。
///
/// 参数说明：
/// - `record`：原审批与候选身份。
/// - `candidate`：调用者唯一持有的原生帧。
///
/// 返回：格式、长度和完整SHA同时成立时成功，不解析或复制秘密。
fn require_candidate(record: &Record, candidate: &Material) -> Result<()> {
    candidate
        .parts()
        .map_err(|_| anyhow::anyhow!("material candidate frame differs"))?;
    ensure!(
        candidate.0.len() == record.intent.candidate_bytes as usize
            && <[u8; 32]>::from(Sha256::digest(&candidate.0)) == record.intent.candidate_sha256,
        "material candidate integrity differs"
    );
    Ok(())
}

/// 业务作用：通过排他新文件句柄直接写入原帧，并确认原文件与目录项已同步。
///
/// 参数说明：
/// - `root`：原固定目录。
/// - `name`：协议选择的唯一秘密槽名。
/// - `bytes`：原清零帧的只读借用。
///
/// 返回：正文和目录同步完成且原文件项仍一致时成功；错误保留原槽，不尝试覆盖重写。
fn write_one(root: &Root, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = root.create_file(name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    root.sync()?;
    require_identity(root, name, &file)
}

/// 业务作用：只为确实需要解析的方向材料分配单份清零缓冲，文件替换不能借读完旧句柄取得执行资格。
///
/// 参数说明：
/// - `root`：原秘密目录。
/// - `name`：固定槽名。
/// - `length`：原保留的精确完整帧长度。
///
/// 返回：原文件的完整清零原文；长度或目录项变化拒绝。
fn read_one(root: &Root, name: &str, length: u32) -> Result<Zeroizing<Vec<u8>>> {
    let file = root
        .open_record(name, length as usize)?
        .context("material body absent")?;
    ensure!(
        file.metadata()?.len() == u64::from(length),
        "material body length differs"
    );
    let bytes = crate::io::secret_file::read_open(file.try_clone()?.into_std(), length as usize)?;
    ensure!(
        bytes.len() == length as usize && file.metadata()?.len() == u64::from(length),
        "material body changed while reading"
    );
    require_identity(root, name, &file)?;
    Ok(bytes)
}

/// 业务作用：用固定清零缓冲验证原秘密槽，不为了准备确认再创建第二份完整私钥。
///
/// 参数说明：
/// - `root`：原秘密目录。
/// - `name`：固定槽名。
/// - `length`：原完整帧长度。
/// - `digest`：原帧摘要。
/// - `missing`：清理重试允许已删除槽；普通准备和执行禁止缺失。
///
/// 返回：存在且完整，或明确允许缺失时成功；其余情况保留责任。
fn verify_one(
    root: &Root,
    name: &str,
    length: u32,
    digest: &[u8; 32],
    missing: bool,
) -> Result<()> {
    let Some(file) = root.open_record(name, length as usize)? else {
        ensure!(missing, "material complete body absent");
        return Ok(());
    };
    hash_open(&file, length, digest)?;
    require_identity(root, name, &file)
}

/// 业务作用：在原已打开秘密句柄上核对精确长度、EOF与完整摘要，不接受部分或尾随内容。
///
/// 参数说明：
/// - `file`：位于起点的原普通私有文件句柄。
/// - `length`：原完整帧长度。
/// - `expected`：原完整帧摘要。
///
/// 返回：完整内容与原证明相同才成功；失败缓冲随作用域清零。
fn hash_open(file: &cap_std::fs::File, length: u32, expected: &[u8; 32]) -> Result<()> {
    ensure!(
        file.metadata()?.len() == u64::from(length),
        "material body length differs"
    );
    let mut file = file;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    let mut hash = Sha256::new();
    let mut remaining = length as usize;
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count;
    }
    ensure!(
        file.read(&mut buffer[..1])? == 0
            && file.metadata()?.len() == u64::from(length)
            && <[u8; 32]>::from(hash.finalize()) == *expected,
        "material body content differs"
    );
    Ok(())
}

/// 业务作用：文件读写与清理都必须仍针对原普通单链接项，不能把同名后来文件当作本次秘密。
///
/// 参数说明：
/// - `root`：原目录能力。
/// - `name`：原固定槽名。
/// - `file`：操作期间始终持有的原文件句柄。
///
/// 返回：目录项设备/inode与原句柄相同才成功；特殊文件或替换拒绝。
fn require_identity(root: &Root, name: &str, file: &cap_std::fs::File) -> Result<()> {
    ensure!(
        crate::io::file_target::same_file(&root.dir.symlink_metadata(name)?, &file.metadata()?),
        "material body identity changed"
    );
    Ok(())
}

/// 业务作用：让未分配槽和部分写入遵守各自边界，超额残留不能被状态查询默许或自动清理。
///
/// 参数说明：
/// - `root`：已固定的材料存储目录。
/// - `name`：由本模块选择的协议固定名字。
/// - `budget`：原记录为此槽保留的容量；空表示该提交不拥有此槽。
/// - `required`：已准备阶段必须有完整长度的原槽；清理和未完成准备允许缺席。
///
/// 返回：原记录预算内的普通私有文件或明确缺失时成功，否则保留现场并拒绝。
fn inspect_one(root: &Root, name: &str, budget: Option<u32>, required: bool) -> Result<()> {
    let file = root.open_record(name, budget.unwrap_or(0) as usize)?;
    // 保留记录先于任何秘密写入；即便是零字节文件，也不能借空闲状态或未选槽获得恢复身份。
    ensure!(
        budget.is_some() || file.is_none(),
        "material body has no selected reservation"
    );
    if required {
        ensure!(
            file.as_ref().is_some_and(|file| file
                .metadata()
                .is_ok_and(|metadata| Some(metadata.len()) == budget.map(u64::from))),
            "material prepared body absent or incomplete"
        );
    }
    Ok(())
}
