//! 本机原pair直接填入单份清零帧，磁盘备份上限不扩大网络候选的受理预算。

use super::frame::{self, HEADER_BYTES, MAGIC};
use anyhow::{ensure, Context, Result};
use cap_std::fs::File;
use std::io::Read;
use zeroize::Zeroizing;

pub(crate) const PART_LIMIT: usize = 4 * 1024 * 1024;
pub(crate) const FRAME_LIMIT: usize = 2 * PART_LIMIT + HEADER_BYTES;

pub(crate) struct Backup(Zeroizing<Vec<u8>>);

impl Backup {
    /// 业务作用：接管持久秘密槽的唯一清零缓冲，恢复不经解析重编码或复制完整pair。
    ///
    /// 参数说明：
    /// - `bytes`：按原槽预算读取的完整原生帧，所有权转入备份。
    ///
    /// 返回：符合磁盘pair边界的备份；格式失败时原缓冲随错误路径清零。
    pub(crate) fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let backup = Self(bytes);
        backup.parts()?;
        Ok(backup)
    }

    /// 业务作用：为固定秘密槽提供完整原帧借用，持久写入不再组合另一份私钥缓冲。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：唯一清零帧的只读切片，不延长原所有者生命周期。
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// 业务作用：用原打开句柄的完整长度一次分配原pair帧，避免分别聚合后再复制证书和私钥。
    ///
    /// 参数说明：
    /// - `certificate`：已通过普通单链接门且位于起点的原证书句柄。
    /// - `private_key`：与原来源绑定、位于起点的私钥句柄。
    /// - `part_limit`：调用用途更严格的单文件预算，不得超过磁盘材料上限。
    ///
    /// 返回：完整原生清零帧；超量、短读、增长或I/O异常拒绝，失败缓冲同样清零。
    pub(crate) fn read(
        certificate: &mut File,
        private_key: &mut File,
        part_limit: usize,
    ) -> Result<Self> {
        ensure!(
            (1..=PART_LIMIT).contains(&part_limit),
            "material backup limit differs"
        );
        let certificate_length = length(certificate, part_limit)?;
        let private_key_length = length(private_key, part_limit)?;
        let length = certificate_length + private_key_length + HEADER_BYTES;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .context("cannot reserve material backup buffer")?;
        bytes.resize(length, 0);
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&(certificate_length as u32).to_be_bytes());
        bytes[12..16].copy_from_slice(&(private_key_length as u32).to_be_bytes());
        fill(
            certificate,
            &mut bytes[HEADER_BYTES..HEADER_BYTES + certificate_length],
        )?;
        fill(private_key, &mut bytes[HEADER_BYTES + certificate_length..])?;
        Ok(Self(bytes))
    }

    /// 业务作用：从唯一原pair缓冲借用两个材料角色，备份的较大预算不能放宽网络候选解析器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：符合磁盘原材料预算的完整切片；不分配副本或提供诊断秘密。
    pub(crate) fn parts(&self) -> Result<(&[u8], &[u8])> {
        frame::parts(&self.0, PART_LIMIT, FRAME_LIMIT)
            .map_err(|_| anyhow::anyhow!("material backup frame differs"))
    }
}

/// 业务作用：只为已经打开的有限普通材料保留容量，空或过量文件不能成为原pair备份。
///
/// 参数说明：
/// - `file`：调用方固定的原材料句柄。
/// - `limit`：当前用途单文件上限。
///
/// 返回：可安全计入完整帧的非零长度；类型或容量不符时在分配之前拒绝。
fn length(file: &File, limit: usize) -> Result<usize> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= limit as u64,
        "material backup type or size differs"
    );
    Ok(metadata.len() as usize)
}

/// 业务作用：直接填入已经清零管理的最终帧分区，探测多出字节时也不留下普通秘密缓冲。
///
/// 参数说明：
/// - `file`：原材料的同一句柄，不重开当前路径。
/// - `destination`：唯一清零帧为该角色预分配的完整分区。
///
/// 返回：精确读满且长度/EOF一致时成功；失败由完整帧owner清除已读秘密。
fn fill(file: &mut File, destination: &mut [u8]) -> Result<()> {
    file.read_exact(destination)?;
    let mut probe = Zeroizing::new([0u8; 1]);
    match file.read_exact(probe.as_mut()) {
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.into()),
        Ok(()) => anyhow::bail!("material backup source grew while reading"),
    }
    ensure!(
        file.metadata()?.len() == destination.len() as u64,
        "material backup source length changed"
    );
    Ok(())
}
