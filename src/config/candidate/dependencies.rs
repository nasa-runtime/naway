//! 持久动作的非 base 文件依赖证明，隔离候选不借用活动文件集指纹。

use super::{Documents, Paths};
use crate::config::{ConfigWatchPlan, GatewaySnapshot};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_PATHS: usize = 2048;
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;

/// 业务作用：冻结本次候选实际引用的非 base 依赖，原始文档由独立文件计划约束。
///
/// 参数说明：
/// - `snapshot`：同一次 naml 与完整业务构建得到的候选。
/// - `documents`：该次构建实际读取的隔离或真实 base 位置。
///
/// 返回：有界文件集合的 SHA-256；调用方必须在完整重建前后比较，不把一次读取当作编译原子性证明。
pub(crate) fn capture(snapshot: &GatewaySnapshot, documents: Documents<'_>) -> Result<[u8; 32]> {
    proof(&snapshot.config_watch, &snapshot.document_paths, documents)
}

/// 业务作用：统一候选与实际文件布局的依赖集合，排除即将由文件计划替换的六个 base 位置。
///
/// 参数说明：
/// - `watch`：同次解析提供的精确来源与附加路径。
/// - `declared`：候选声明的三个真实目标。
/// - `documents`：本次实际使用的 base 输入。
///
/// 返回：包含缺失候选和完整内容的固定摘要；路径、容量、文件类型或读取漂移均拒绝。
fn proof(watch: &ConfigWatchPlan, declared: &Paths, documents: Documents<'_>) -> Result<[u8; 32]> {
    let root = std::env::current_dir().context("node dependency root unavailable")?;
    let mut excluded = BTreeSet::new();
    for path in declared
        .ordered()
        .into_iter()
        .chain(std::iter::once(documents.gateway))
    {
        excluded.insert(absolute(&root, path)?);
    }
    if let Some(sidecars) = documents.sidecars {
        for path in [sidecars.guard, sidecars.sentinel] {
            excluded.insert(absolute(&root, path)?);
        }
    }
    let mut paths = BTreeSet::new();
    for path in watch
        .sources()
        .watch_files()
        .chain(watch.dependencies().iter().map(PathBuf::as_path))
    {
        let path = absolute(&root, path)?;
        if !excluded.contains(&path) {
            ensure!(
                paths.len() < MAX_PATHS || paths.contains(&path),
                "node dependency count exceeds limit"
            );
            paths.insert(path);
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"naway-node-action-dependencies\0");
    digest.update(1_u32.to_be_bytes());
    digest.update((paths.len() as u32).to_be_bytes());
    let mut remaining = MAX_TOTAL;
    let mut buffer = [0_u8; 16 * 1024];
    for path in paths {
        let text = path.to_str().expect("validated dependency path");
        digest.update((text.len() as u32).to_be_bytes());
        digest.update(text.as_bytes());
        hash_file(&path, &mut digest, &mut remaining, &mut buffer)?;
    }
    Ok(digest.finalize().into())
}

/// 业务作用：保留真实路径解析语义并为摘要建立唯一进程根，不能有损替换非 UTF-8 名称。
///
/// 参数说明：
/// - `root`：本次捕获固定的进程工作目录。
/// - `path`：同次配置模型给出的来源位置。
///
/// 返回：有界绝对路径；不消除可能经过符号链接的父路径，也不在读取前重新选择文件。
fn absolute(root: &Path, path: &Path) -> Result<PathBuf> {
    let path = root.join(path);
    let text = path
        .to_str()
        .context("node dependency path must be UTF-8")?;
    ensure!(
        text.len() <= 4096 && !text.as_bytes().contains(&0) && path.is_absolute(),
        "node dependency path exceeds bounds"
    );
    Ok(path)
}

/// 业务作用：按固定缓冲把依赖原文纳入证明，读完后复验同句柄和当前路径，不能把替换后的内容混为一份。
///
/// 参数说明：
/// - `path`：已验证的当前文件位置。
/// - `digest`：该次依赖集合的流式摘要。
/// - `remaining`：本次全部文件共用的剩余读取预算。
/// - `buffer`：整个捕获过程共享的固定缓冲，不按文件大小分配。
///
/// 返回：缺失或完整稳定普通文件时推进摘要；异常、类型不符、增长或替换拒绝整份证明。
fn hash_file(
    path: &Path,
    digest: &mut Sha256,
    remaining: &mut u64,
    buffer: &mut [u8],
) -> Result<()> {
    let mut file = match open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            digest.update([0]);
            return Ok(());
        }
        Err(_) => anyhow::bail!("node dependency open failed"),
    };
    let metadata = file
        .metadata()
        .context("node dependency metadata unavailable")?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FILE && metadata.len() <= *remaining,
        "node dependency file exceeds bounds"
    );
    let before = stamp(&metadata)?;
    digest.update([1]);
    for value in before {
        digest.update(value.to_be_bytes());
    }
    let mut length = 0_u64;
    loop {
        let count = file.read(buffer).context("node dependency read failed")?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .context("node dependency length overflow")?;
        ensure!(
            length <= MAX_FILE && length <= metadata.len(),
            "node dependency changed while reading"
        );
        *remaining = remaining
            .checked_sub(count as u64)
            .context("node dependency total exceeds limit")?;
        digest.update(&buffer[..count]);
    }
    // 内容和原文件身份都必须稳定；路径发生替换时不能承认仍打开的旧 inode。
    ensure!(
        length == metadata.len()
            && stamp(
                &file
                    .metadata()
                    .context("node dependency metadata unavailable")?
            )? == before
            && stamp(&path.metadata().context("node dependency path changed")?)? == before,
        "node dependency identity changed while reading"
    );
    Ok(())
}

/// 业务作用：在读取元数据前拒绝会阻塞打开的特殊文件，符号链接仍可指向正常轮换的 Secret 文件。
///
/// 参数说明：
/// - `path`：本次已冻结位置。
///
/// 返回：Unix 非阻塞只读句柄；其它平台或打开失败不尝试降级。
fn open(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "node dependencies require Unix file identity",
        ))
    }
}

/// 业务作用：把会改变文件内容或归属的元数据纳入证明，排除仅因读取改变的 atime。
///
/// 参数说明：
/// - `metadata`：同一打开句柄或最终路径查询取得的文件事实。
///
/// 返回：Unix 文件身份、权限、长度和纳秒变化时间；无法提供这些事实的平台拒绝。
fn stamp(metadata: &Metadata) -> Result<[u64; 8]> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok([
            metadata.dev(),
            metadata.ino(),
            u64::from(metadata.mode()),
            metadata.len(),
            metadata.mtime() as u64,
            metadata.mtime_nsec() as u64,
            metadata.ctime() as u64,
            metadata.ctime_nsec() as u64,
        ])
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        anyhow::bail!("node dependencies require Unix file identity")
    }
}
