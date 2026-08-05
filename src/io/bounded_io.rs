//! 控制面本地文件的有界读取助手。
//!
//! 配置构建与 reload 会读取证书、策略和生成文件。单纯先看 metadata 再调用
//! `std::fs::read` 存在 TOCTOU：文件可在两步之间增长，`fs::read` 会按新文件大小分配，导致
//! “读取后再检查上限”无法防止控制面 OOM。本模块始终只读 `max_bytes + 1`，让超限判定发生在
//! 有界分配内；它只在低频控制面使用，不进入请求数据面。

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

/// 有界读取一个必须存在的普通文件。
///
/// # 参数
///
/// - `path`：要读取的本地文件；符号链接可以指向普通文件，以兼容 Kubernetes Secret 轮换。
/// - `max_bytes`：允许返回的最大字节数。
/// - `kind`：不含敏感值的错误上下文，例如 `TLS certificate`。
pub(crate) fn read_file(path: &Path, max_bytes: usize, kind: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {kind} {}", path.display()))?;
    read_open_file(file, path, max_bytes, kind)
}

/// 有界读取一个可缺失的普通文件。
///
/// # 参数
///
/// - `path`：要读取的本地文件；不存在返回 `Ok(None)`。
/// - `max_bytes`：允许返回的最大字节数。
/// - `kind`：不含敏感值的错误上下文。
pub(crate) fn read_optional_file(
    path: &Path,
    max_bytes: usize,
    kind: &str,
) -> Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {kind} {}", path.display())),
    };
    read_open_file(file, path, max_bytes, kind).map(Some)
}

/// 从已经解析到同一 inode 的句柄读取，避免 metadata 检查后按路径重新打开产生替换竞态。
///
/// # 参数
///
/// - `file`：已经打开的只读句柄。
/// - `path`：只用于安全错误上下文，不参与第二次打开。
/// - `max_bytes`：允许返回的最大字节数。
/// - `kind`：文件业务类型。
fn read_open_file(mut file: File, path: &Path, max_bytes: usize, kind: &str) -> Result<Vec<u8>> {
    let read_limit = max_bytes
        .checked_add(1)
        .context("bounded file byte limit overflows usize")?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {kind} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{kind} {} must be a regular file",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= max_bytes as u64,
        "{kind} {} exceeds {max_bytes} bytes",
        path.display()
    );
    let capacity = usize::try_from(metadata.len())
        .unwrap_or(read_limit)
        .min(read_limit);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(read_limit as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {kind} {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "{kind} {} grew beyond {max_bytes} bytes while reading",
        path.display()
    );
    Ok(bytes)
}

#[path = "../../tests/unit/bounded_io.rs"]
#[cfg(test)]
mod tests;
