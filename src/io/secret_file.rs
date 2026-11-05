//! 秘密文件按已打开句柄的有限长度一次分配，失败路径也清除已经读取的原文。

use anyhow::{ensure, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};
use zeroize::Zeroizing;

/// 业务作用：读取完整秘密原文，避免先用普通缓冲读入再移交清零容器留下失败残余。
///
/// 参数说明：
/// - `path`：部署配置或原事务确定的位置，允许指向普通文件的 Secret 轮换链接。
/// - `limit`：该用途允许的最大字节数。
/// - `kind`：不含路径或秘密的业务错误上下文。
///
/// 返回：从读取开始即受清零保护的唯一原文缓冲；类型、长度变化或 I/O 异常拒绝。
pub(crate) fn read_file(path: &Path, limit: usize, kind: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file = open(path).with_context(|| format!("cannot open {kind}"))?;
    read_open(file, limit).with_context(|| format!("cannot read {kind}"))
}

/// 业务作用：保留材料事务中的真实缺席状态，同时保证部分读取失败不遗留普通秘密缓冲。
///
/// 参数说明：
/// - `path`：受信材料来源或原事务备份位置。
/// - `limit`：该材料用途的字节上限。
/// - `kind`：不含秘密的业务类型。
///
/// 返回：缺失为空，完整存在时返回清零原文；其它错误拒绝，不把失败解释为未安装。
pub(crate) fn read_optional_file(
    path: &Path,
    limit: usize,
    kind: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let file = match open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("cannot open {kind}")),
    };
    read_open(file, limit)
        .map(Some)
        .with_context(|| format!("cannot read {kind}"))
}

/// 业务作用：在 Unix 上避免特殊文件打开阶段等待对端，保留普通 Secret 文件的轮换链接语义。
///
/// 参数说明：
/// - `path`：受信配置选定但仍须验证实际类型的来源。
///
/// 返回：只读句柄或打开错误；后续必须验证同一句柄是普通文件，不能直接消费特殊设备内容。
fn open(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // 配置位置被替换成 FIFO 时不能卡住材料锁；普通文件忽略此标志，链接仍由实际目标类型裁决。
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

/// 业务作用：将容量与读取绑定到同一普通文件句柄，读取期间增长不能触发含秘密缓冲的重新分配。
///
/// 参数说明：
/// - `file`：已经取得且位于起点的唯一输入句柄。
/// - `limit`：分配和读取共同遵守的硬上限。
///
/// 返回：长度未变且完整读至 EOF 的清零缓冲；不声明其它进程不能修改相同长度的内容。
fn read_open(mut file: File, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "secret source must be a regular file");
    let length = usize::try_from(metadata.len()).context("secret source length exceeds bounds")?;
    ensure!(length <= limit, "secret source exceeds its byte budget");
    let bytes = read_exact(&mut file, length)?;
    // 长度变化撤销本次读取；完整 pair 的归属仍由上层在同一安装锁内核对，不能仅靠文件长度推定。
    ensure!(
        file.metadata()?.len() == metadata.len(),
        "secret source length changed"
    );
    Ok(bytes)
}

/// 业务作用：在固定分配中读取原文并验证 EOF，部分错误和多出的一字节同样由清零容器持有。
///
/// 参数说明：
/// - `source`：受限来源，不在读取过程中重开路径。
/// - `length`：调用者已经按用途预算校验的精确原文长度。
///
/// 返回：恰好完整且无尾随数据时返回唯一缓冲；短读、增长或读取错误清零后拒绝。
fn read_exact(source: &mut impl Read, length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .context("cannot reserve secret source buffer")?;
    bytes.resize(length, 0);
    source.read_exact(&mut bytes)?;
    let mut probe = Zeroizing::new([0u8; 1]);
    // EOF探测也可能读到私钥字节，不能放入不受清零保护的临时缓冲。
    match source.read_exact(probe.as_mut()) {
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(bytes),
        Err(error) => Err(error.into()),
        Ok(()) => anyhow::bail!("secret source grew while reading"),
    }
}
