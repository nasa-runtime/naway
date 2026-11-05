//! 完整材料准备与唯一指针激活共用原目录，准备失败不能取得活动文件覆盖权。

use super::super::{generation, io};
use super::bound::{Directory, Pointer};
use crate::io::file_target::{same_file, Target};
use anyhow::{ensure, Context, Result};
use cap_std::fs::File;
use sha2::{Digest as _, Sha256};
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

struct SealedFile {
    target: Target,
    file: File,
    length: usize,
    digest: [u8; 32],
}

pub(in crate::tls::keypair) struct PreparedKeypairVersion<'a> {
    pub(in crate::tls::keypair) directory: PathBuf,
    pub(in crate::tls::keypair) manifest: Vec<u8>,
    pointer: Pointer<'a>,
    root: Directory,
    material: Directory,
    files: [SealedFile; 3],
    owner: generation::Record,
}

/// 业务作用：在固定原目录内准备完整pair和预分配归属，指针激活保留同一能力而不重开声明路径。
///
/// 参数说明：
/// - `manifest_file`：本机配置确定的唯一活动指针。
/// - `certificate_pem`：已验证的完整证书链原文。
/// - `private_key_pem`：与证书匹配的私钥原文借用。
/// - `owner`：上层在文件副作用之前为该来源和完整pair分配的材料记录。
///
/// 返回：已同步但尚未激活的完整材料能力；失败仅清理仍属于本次且未被指针引用的准备目录。
pub(in crate::tls::keypair) fn prepare_keypair_version<'a>(
    manifest_file: &'a Path,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    owner: generation::Record,
) -> Result<PreparedKeypairVersion<'a>> {
    ensure!(
        !certificate_pem.is_empty()
            && !private_key_pem.is_empty()
            && certificate_pem.len() <= super::super::MAX_KEYPAIR_BYTES
            && private_key_pem.len() <= super::super::MAX_KEYPAIR_BYTES,
        "TLS prepared material exceeds bounds"
    );
    let pointer = Pointer::capture(manifest_file)?;
    // 不允许目录创建先于来源和完整pair验证，错误的预分配代不能留下可被误认的材料。
    owner.require_material(
        &generation::digest_paths(b"manifest", &[&pointer.target.path]),
        certificate_pem,
        private_key_pem,
    )?;
    let root = Directory::create(
        pointer
            .target
            .sibling(std::ffi::OsStr::new(".gateway-keypairs"))?,
        true,
    )?;
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random).context("TLS material directory entropy unavailable")?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let name = format!("v-{timestamp}-{:016x}", u64::from_le_bytes(random));
    let material = Directory::create(root.entry(&name)?, false)?;
    let result = (|| -> Result<_> {
        pointer.require_original()?;
        root.require_current()?;
        material.require_current()?;
        let certificate = material.entry("cert.pem")?;
        let key = material.entry("key.pem")?;
        let ownership = material.entry(generation::MANIFEST_RECORD)?;
        let ownership_bytes =
            serde_json::to_vec(&owner).context("encode TLS material ownership")?;
        io::write(&key, private_key_pem, true)?;
        io::write(&certificate, certificate_pem, false)?;
        // 完整pair与材料代先同步，再交付可激活指针，不能在活动指针发布后补记owner。
        io::write(&ownership, &ownership_bytes, true)?;
        let files = [
            SealedFile::capture(certificate, certificate_pem)?,
            SealedFile::capture(key, private_key_pem)?,
            SealedFile::capture(ownership, &ownership_bytes)?,
        ];
        material.sync()?;
        root.sync()?;
        pointer.require_original()?;
        let manifest = serde_json::to_vec(&super::KeypairManifest {
            schema_version: 1,
            directory: format!(".gateway-keypairs/{name}"),
        })
        .context("encode TLS keypair manifest")?;
        let directory = files[0]
            .target
            .path
            .parent()
            .context("TLS material parent absent")?
            .to_path_buf();
        Ok((files, manifest, directory))
    })();
    let (files, manifest, directory) = match result {
        Ok(prepared) => prepared,
        Err(error) => {
            // 只能清理原指针仍未变化的未激活目录；未知来源或目录替换保留证据，不追随后来路径。
            if pointer.require_original().is_ok() && root.require_current().is_ok() {
                let _ = material.discard();
            }
            return Err(error);
        }
    };
    Ok(PreparedKeypairVersion {
        directory,
        manifest,
        pointer,
        root,
        material,
        files,
        owner,
    })
}

impl PreparedKeypairVersion<'_> {
    /// 业务作用：通过准备时的唯一指针能力激活原材料，外部替换不能把旧准备结果写入新来源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录、完整材料及本次指针已明确同步时成功；任何写入后错误均保留结果未知和材料目录。
    pub(in crate::tls::keypair) fn publish(&self) -> Result<()> {
        self.pointer.require_original()?;
        self.require_material()?;
        // 完整正文校验可能跨过外部换证；实际指针写入前重新验证原决定，不能沿用哈希之前的观察。
        self.pointer.require_original()?;
        // 原文件资格全部复验以后才切唯一指针；之后即使同步失败也不能删除可能已经生效的材料。
        io::write(&self.pointer.target, &self.manifest, false)?;
        self.require_material()?;
        self.pointer.require_published(&self.manifest)
    }

    /// 业务作用：读取活动决定之前已分配的唯一材料代，成功回执不另造无法关联准备的身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本次原生owner的随机代借用，不复制元数据或秘密。
    pub(in crate::tls::keypair) fn generation(&self) -> &str {
        &self.owner.generation
    }

    /// 业务作用：激活前后检查两层目录与三份原文件，不能把同名或同长度替换当作原完整准备。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录、文件身份及完整原文摘要同时成立时成功，不锁定外部文件系统写者。
    fn require_material(&self) -> Result<()> {
        self.root.require_current()?;
        self.material.require_current()?;
        for file in &self.files {
            file.verify()?;
        }
        self.material.require_current()?;
        self.root.require_current()
    }
}

impl SealedFile {
    /// 业务作用：保留本次刚写入材料的句柄与借用原文摘要，之后校验不再聚合另一份完整秘密。
    ///
    /// 参数说明：
    /// - `target`：原材料目录内的固定角色位置。
    /// - `bytes`：已经写入的完整原文借用。
    ///
    /// 返回：原普通单链接文件及精确预算；缺失、类型或长度不符拒绝。
    fn capture(target: Target, bytes: &[u8]) -> Result<Self> {
        let (file, metadata) = target
            .open_regular(bytes.len())?
            .context("TLS prepared material absent")?;
        ensure!(
            metadata.len() == bytes.len() as u64,
            "TLS prepared material length differs"
        );
        Ok(Self {
            target,
            file,
            length: bytes.len(),
            digest: Sha256::digest(bytes).into(),
        })
    }

    /// 业务作用：在原句柄上用固定清零缓冲复验完整材料，避免为激活再分配整份私钥或仅检查长度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录项、精确长度、EOF及原文摘要都一致时成功；短读、增长和替换均拒绝。
    fn verify(&self) -> Result<()> {
        self.require_identity()?;
        let mut file = &self.file;
        file.seek(SeekFrom::Start(0))?;
        let mut buffer = Zeroizing::new([0u8; 8192]);
        let mut digest = Sha256::new();
        let mut remaining = self.length;
        while remaining > 0 {
            let count = remaining.min(buffer.len());
            file.read_exact(&mut buffer[..count])?;
            digest.update(&buffer[..count]);
            remaining -= count;
        }
        ensure!(
            file.read(&mut buffer[..1])? == 0,
            "TLS prepared material grew"
        );
        ensure!(
            <[u8; 32]>::from(digest.finalize()) == self.digest,
            "TLS prepared material content changed"
        );
        self.require_identity()
    }

    /// 业务作用：正文校验两侧都核对原文件项，旧句柄读成功不能掩盖活动路径已替换。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原父目录、普通单链接文件和长度不变时成功，否则保留未激活准备。
    fn require_identity(&self) -> Result<()> {
        self.target.require_current()?;
        let current = self.target.directory.symlink_metadata(&self.target.name)?;
        let original = self.file.metadata()?;
        ensure!(
            same_file(&current, &original)
                && current.len() == self.length as u64
                && original.len() == self.length as u64,
            "TLS prepared material identity changed"
        );
        Ok(())
    }
}
