//! 同目录替换及目录同步；私钥文件从创建时即限制读取权限。

use anyhow::{Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

/// 业务作用：把一个文件同目录原子替换，并在 secret 模式下强制 0600 权限。
///
/// 参数说明：
/// - `path`: 最终事实源路径。
/// - `bytes`: 完整新文件内容。
/// - `secret`: true 用 0600，false 用 0644。
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("atomic target has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create secret dir {}", parent.display()))?;
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).context("generate atomic file suffix")?;
    let suffix = u64::from_le_bytes(random);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("atomic target has invalid file name"))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{suffix:016x}"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret {
            0o600
        } else {
            0o644
        });
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create atomic temp {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write atomic temp {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync atomic temp {}", temporary.display()))?;
        fs::rename(&temporary, path)
            .with_context(|| format!("rename atomic target {}", path.display()))?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// 业务作用：Unix 上 fsync 目录项，使 create/rename 在突然断电后也有可预期持久性。
pub(super) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .with_context(|| format!("open directory for fsync {}", path.display()))?
            .sync_all()
            .with_context(|| format!("fsync directory {}", path.display()))?;
    }
    Ok(())
}
