//! 秘密正文只占用已选材料记录的固定槽，保留状态不声明正文已完整或可以执行。

use super::Record;
use crate::control::journal::filesystem::Root;
use anyhow::{ensure, Result};
use std::ffi::OsStr;

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
    // Reserved允许尚未写入的槽；只打开实际存在的固定名字，空闲查询不逐个探测全部秘密配额。
    for entry in root.dir.read_dir(".")? {
        let name = entry?.file_name();
        if name == CANDIDATE {
            inspect_one(
                root,
                CANDIDATE,
                record.map(|value| value.intent.candidate_bytes),
            )?;
        } else if let Some(index) = BACKUPS
            .iter()
            .position(|candidate| name == OsStr::new(candidate))
        {
            inspect_one(
                root,
                BACKUPS[index],
                record.and_then(|value| value.backup_bytes.get(index).copied()),
            )?;
        }
    }
    Ok(())
}

/// 业务作用：让未分配槽和部分写入遵守各自边界，超额残留不能被状态查询默许或自动清理。
///
/// 参数说明：
/// - `root`：已固定的材料存储目录。
/// - `name`：由本模块选择的协议固定名字。
/// - `budget`：原记录为此槽保留的容量；空表示该提交不拥有此槽。
///
/// 返回：原记录预算内的普通私有文件或明确缺失时成功，否则保留现场并拒绝。
fn inspect_one(root: &Root, name: &str, budget: Option<u32>) -> Result<()> {
    let file = root.open_record(name, budget.unwrap_or(0) as usize)?;
    // 保留记录先于任何秘密写入；即便是零字节文件，也不能借空闲状态或未选槽获得恢复身份。
    ensure!(
        budget.is_some() || file.is_none(),
        "material body has no selected reservation"
    );
    Ok(())
}
