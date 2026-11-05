//! 同目录替换及目录同步使用固定能力；私钥文件从创建时即限制读取权限。

use crate::io::file_target::{same_file, Target};
use anyhow::{ensure, Context, Result};
use cap_std::fs::OpenOptions;
use std::{fs, io::Write, path::Path};
use zeroize::Zeroizing;

/// 业务作用：创建所需父目录后固定目录能力，完整同步同目录替换的材料文件。
///
/// 参数说明：
/// - `path`：本机配置或受管事务确定的最终位置。
/// - `bytes`：完整候选原文借用。
/// - `secret`：私有材料使用0600，其它材料使用0644。
///
/// 返回：文件及目录项持久化成功；失败不证明替换尚未发生。
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let parent = path.parent().context("atomic target has no parent")?;
    fs::create_dir_all(parent).context("create material parent")?;
    write(&Target::open(path)?, bytes, secret)
}

/// 业务作用：沿用已经授权的父目录执行临时创建和原子替换，路径被替换不能把写入转移到新目录。
///
/// 参数说明：
/// - `target`：事务持有的固定父目录与单一目标槽。
/// - `bytes`：原生材料借用，不额外序列化或复制。
/// - `secret`：是否在创建时限制为0600。
///
/// 返回：原目录仍为部署位置且同步完成时成功；失败仅清理仍属于本次创建的临时项。
pub(super) fn write(target: &Target, bytes: &[u8], secret: bool) -> Result<()> {
    // 目录变化撤销当前发布资格；检查之后的所有操作仍用原句柄，不能再按路径打开新目录。
    target.require_current()?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate atomic file suffix")?;
    let file_name = target
        .name
        .to_str()
        .context("atomic target name must be UTF-8")?;
    let name = format!(".{file_name}.tmp-{:016x}", u64::from_le_bytes(random));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(if secret {
            0o600
        } else {
            0o644
        });
    }
    let mut file = target.directory.open_with(&name, &options)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        target.require_current()?;
        // 同名临时项可能被外部替换；只能发布仍由本句柄持有的普通单链接文件。
        ensure!(
            same_file(
                &target.directory.symlink_metadata(&name)?,
                &file.metadata()?
            ),
            "TLS temporary material owner changed"
        );
        target
            .directory
            .rename(&name, &target.directory, &target.name)?;
        target.sync()?;
        target.require_current()
    })();
    if result.is_err() {
        // 失败不拥有同名后来文件的删除权；rename已发生时原暂存项也不再存在。
        if let (Ok(current), Ok(original)) =
            (target.directory.symlink_metadata(&name), file.metadata())
        {
            if same_file(&current, &original) {
                let _ = target.directory.remove_file(&name);
            }
        }
    }
    result
}

/// 业务作用：在原目录中取得完整秘密备份，设备、FIFO和链接不能形成受管事务的恢复依据。
///
/// 参数说明：
/// - `target`：调用方已经绑定的材料槽。
/// - `limit`：该槽读取和内存分配共用的上限。
///
/// 返回：缺失为空，存在时从首次填充起持有清零缓冲；其它错误拒绝且不重开路径。
pub(super) fn read(target: &Target, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some((file, _)) = target.open_regular(limit)? else {
        return Ok(None);
    };
    crate::io::secret_file::read_open(file.into_std(), limit).map(Some)
}

/// 业务作用：恢复原本缺席的材料槽，删除只能发生在事务已经绑定的同一父目录。
///
/// 参数说明：
/// - `target`：已通过完整pair边界验证的目标。
///
/// 返回：原槽已删除或本来缺席且目录仍有效时成功；失败保留未确认恢复语义。
pub(super) fn remove(target: &Target) -> Result<()> {
    target.require_current()?;
    match target.directory.remove_file(&target.name) {
        Ok(()) => target.sync()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("cannot restore absent TLS material"),
    }
    target.require_current()
}

/// 业务作用：同步既有目录项，使材料创建或目录rename具有明确持久确认。
///
/// 参数说明：
/// - `path`：当前操作确定的目录。
///
/// 返回：Unix目录同步成功；不支持目录同步的平台不提供断电持久性保证。
pub(super) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    Ok(())
}
