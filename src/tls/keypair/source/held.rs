//! 写入预检固定完整来源的原目录和文件句柄，指针或文件替换不能为原读取补发新归属。

use super::super::{generation, io, manifest};
use crate::{
    config::TlsRuntimeCfg,
    control::material::backup::Backup,
    io::file_target::{same_file, Target},
};
use anyhow::{ensure, Context, Result};
use cap_std::fs::File;
use sha2::{Digest as _, Sha256};
use std::{
    borrow::Cow,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

struct Slot {
    target: Target,
    file: File,
    length: u64,
}

struct Control {
    slot: Slot,
    digest: [u8; 32],
    limit: usize,
}

pub(in crate::tls::keypair) struct Source<'a> {
    declared: &'a TlsRuntimeCfg,
    selected_directory: Option<PathBuf>,
    manifest: Option<Control>,
    certificate: Slot,
    private_key: Slot,
    owner: Control,
    record: generation::Record,
}

impl<'a> Source<'a> {
    /// 业务作用：以同次完整owner和原句柄确认所选材料代，重放不能仅凭相同证书或随机代文本跳过文件。
    ///
    /// 参数说明：
    /// - `expected`：原整批决定允许的完整归属。
    ///
    /// 返回：原记录完全相同且当前pair两个摘要成立时成功；不分配第二份完整秘密。
    pub(in crate::tls::keypair) fn require_owner(
        &self,
        expected: &generation::Record,
    ) -> Result<()> {
        ensure!(
            self.record == *expected,
            "material current complete ownership differs"
        );
        self.require_pair()
    }

    /// 业务作用：提交材料准备前用固定清零缓冲复验原句柄完整pair，同inode等长改写也会撤销原证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原文件身份、控制原文和两个材料摘要全部一致时成功，不聚合第二份完整私钥。
    pub(in crate::tls::keypair) fn require_pair(&self) -> Result<()> {
        self.require_current()?;
        let certificate = self.certificate.digest()?;
        let private_key = self.private_key.digest()?;
        ensure!(
            self.record.matches_digests(&certificate, &private_key),
            "material original pair changed during preparation"
        );
        self.require_current()
    }

    /// 业务作用：在整批分配秘密缓冲或持久保留之前计算原pair额度，空或过量来源不能部分受理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整原生帧预算；两个角色必须非空并满足磁盘材料上限。
    pub(in crate::tls::keypair) fn budget(&self) -> Result<u32> {
        let limit = crate::control::material::backup::PART_LIMIT as u64;
        ensure!(
            (1..=limit).contains(&self.certificate.length)
                && (1..=limit).contains(&self.private_key.length),
            "material source backup budget differs"
        );
        Ok((self.certificate.length + self.private_key.length + 16) as u32)
    }

    /// 业务作用：从同次原句柄及完整备份冻结本机来源计划，路径、原代和预分配新代一起进入持久预算。
    ///
    /// 参数说明：
    /// - `backup`：由这两个原句柄读出的唯一完整pair帧。
    /// - `certificate`：已经通过整批监听策略检查的候选证书借用。
    /// - `private_key`：同一候选帧中的私钥借用。
    ///
    /// 返回：尚无文件决定的原生计划；原归属、目录或预算不符时拒绝，不创建候选目录。
    pub(in crate::tls::keypair) fn prepare(
        &self,
        backup: &Backup,
        certificate: &[u8],
        private_key: &[u8],
    ) -> Result<super::super::execution::source::Plan> {
        use super::super::execution::source::{Binding, Declaration, Plan};
        use crate::io::file_target::Location;
        self.require_current()?;
        let budget = self.budget()?;
        ensure!(
            backup.bytes().len() == budget as usize,
            "material original frame length differs"
        );
        let (old_certificate, old_private_key) = backup.parts()?;
        ensure!(
            self.record.matches(old_certificate, Some(old_private_key)),
            "material original frame ownership differs"
        );
        let certificate_location = Location::capture(&self.certificate.target)?;
        let private_key_location = Location::capture(&self.private_key.target)?;
        let owner_location = Location::capture(&self.owner.slot.target)?;
        let (binding, identity) = if let Some(pointer) = &self.manifest {
            let pointer_location = Location::capture(&pointer.slot.target)?;
            let root = pointer
                .slot
                .target
                .path
                .parent()
                .context("material manifest parent absent")?
                .join(".gateway-keypairs");
            ensure!(
                std::fs::symlink_metadata(&root)?.is_dir(),
                "material manifest root must be an original directory"
            );
            let root = Location::capture(&Target::open(&root.join(".naway-binding"))?)?;
            let identity = generation::digest_paths(b"manifest", &[&pointer_location.path]);
            (
                Binding::Manifest {
                    pointer: pointer_location,
                    root,
                    certificate: certificate_location,
                    private_key: private_key_location,
                    owner: owner_location,
                    pointer_sha256: pointer.digest,
                },
                identity,
            )
        } else {
            let transaction_path = super::super::legacy::legacy_directory_for_paths(
                &certificate_location.path,
                &private_key_location.path,
            )?;
            let transaction = Location::capture(
                &self.certificate.target.sibling(
                    transaction_path
                        .file_name()
                        .context("material transaction name absent")?,
                )?,
            )?;
            let identity = generation::digest_paths(
                b"legacy",
                &[&certificate_location.path, &private_key_location.path],
            );
            (
                Binding::Legacy {
                    certificate: certificate_location,
                    private_key: private_key_location,
                    owner: owner_location,
                    transaction,
                },
                identity,
            )
        };
        let plan = Plan {
            declared: Declaration::capture(self.declared)?,
            binding,
            original: self.record.clone(),
            next: generation::Record::new(identity, certificate, private_key)?,
            backup_bytes: budget,
            backup_sha256: Sha256::digest(backup.bytes()).into(),
        };
        plan.validate()?;
        plan.require_original(self, backup)?;
        Ok(plan)
    }

    /// 业务作用：从本机声明一次固定完整受管来源，预算和后续读取均使用同一组打开的句柄。
    ///
    /// 参数说明：
    /// - `tls`：调用方持有配置发布权和材料锁的来源声明。
    /// - `part_limit`：当前预检或准备用途的单文件预算。
    ///
    /// 返回：原指针、pair及owner能力；未受管、缺失、链接或非普通材料拒绝，不写入或创建新代。
    pub(in crate::tls::keypair) fn capture(
        tls: &'a TlsRuntimeCfg,
        part_limit: usize,
    ) -> Result<Self> {
        let (manifest, selected_directory) = if let Some(path) = &tls.keypair_manifest_file {
            let (pointer, bytes) = Control::open(Target::open(path)?, 64 * 1024)?;
            let directory = manifest::parse_material_directory(&pointer.slot.target.path, &bytes)?;
            (Some(pointer), Some(directory))
        } else {
            (None, None)
        };
        let (certificate, private_key, owner, identity) = if let Some(directory) =
            &selected_directory
        {
            let certificate = Target::open(&directory.join("cert.pem"))?;
            let private_key = certificate.sibling(std::ffi::OsStr::new("key.pem"))?;
            let owner = certificate.sibling(std::ffi::OsStr::new(generation::MANIFEST_RECORD))?;
            let identity = generation::digest_paths(
                b"manifest",
                &[&manifest
                    .as_ref()
                    .context("TLS manifest source absent")?
                    .slot
                    .target
                    .path],
            );
            (certificate, private_key, owner, identity)
        } else {
            let certificate = Target::open(&tls.cert_file)?;
            let private_key = Target::open(&tls.key_file)?;
            let identity =
                generation::digest_paths(b"legacy", &[&certificate.path, &private_key.path]);
            let owner_path = generation::legacy_path(tls)?;
            let owner =
                certificate.sibling(owner_path.file_name().context("TLS owner name absent")?)?;
            (certificate, private_key, owner, identity)
        };
        let certificate = Slot::open(certificate, part_limit)?;
        let private_key = Slot::open(private_key, part_limit)?;
        let (owner, bytes) = Control::open(owner, 4096)?;
        let record = generation::decode(&bytes, &identity)?;
        let source = Self {
            declared: tls,
            selected_directory,
            manifest,
            certificate,
            private_key,
            owner,
            record,
        };
        source.require_current()?;
        Ok(source)
    }

    /// 业务作用：直接从原两个句柄读入单份清零帧，并以原归属核对完整pair而不只比较公开证书。
    ///
    /// 参数说明：
    /// - `part_limit`：此次读取的单文件硬上限，不能扩大磁盘材料预算。
    ///
    /// 返回：原owner拥有的完整材料；不匹配为空，读取或来源复验错误拒绝，失败原文均清零。
    pub(in crate::tls::keypair) fn read(&mut self, part_limit: usize) -> Result<Option<Backup>> {
        // 空文件不可能属于已受管的完整pair；保留材料条件已变语义，不把它编造成有效备份帧。
        if self.certificate.length == 0 || self.private_key.length == 0 {
            self.require_current()?;
            return Ok(None);
        }
        let backup = Backup::read(
            &mut self.certificate.file,
            &mut self.private_key.file,
            part_limit,
        )?;
        let (certificate, private_key) = backup.parts()?;
        self.require_current()?;
        // 任一角色不属于原owner就撤销完整材料条件，不能把公开证书仍一致当作写入资格。
        if !self.record.matches(certificate, Some(private_key)) {
            return Ok(None);
        }
        Ok(Some(backup))
    }

    /// 业务作用：借用本次完整来源捕获的随机材料代，公开条件比较不重新解析另一份owner。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原记录内的不可重用随机代；仅表示此次读取归属，不授予写入权。
    pub(in crate::tls::keypair) fn generation(&self) -> &str {
        &self.record.generation
    }

    /// 业务作用：在完整批预检返回前复验原声明、指针和所有文件项，先前成功的来源不能被后来替换蒙混。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录/文件身份、指针原文及owner原文均未改变时成功；不宣称阻止其它进程后续写入。
    pub(in crate::tls::keypair) fn require_current(&self) -> Result<()> {
        let (certificate, private_key): (Cow<'_, Path>, Cow<'_, Path>) =
            match &self.selected_directory {
                Some(directory) => (
                    Cow::Owned(directory.join("cert.pem")),
                    Cow::Owned(directory.join("key.pem")),
                ),
                None => (
                    Cow::Borrowed(&self.declared.cert_file),
                    Cow::Borrowed(&self.declared.key_file),
                ),
            };
        // 固定目录句柄不能代替当前声明；别名转向之后只能保留原读取，不能报告当前来源仍一致。
        ensure!(
            generation::identity_path(&certificate)? == self.certificate.target.path
                && generation::identity_path(&private_key)? == self.private_key.target.path,
            "TLS declared source changed during capture"
        );
        if let Some(pointer) = &self.manifest {
            ensure!(
                generation::identity_path(
                    self.declared
                        .keypair_manifest_file
                        .as_deref()
                        .context("TLS manifest declaration absent")?
                )? == pointer.slot.target.path,
                "TLS manifest declaration changed during capture"
            );
            pointer.require_current()?;
        }
        self.certificate.require_current()?;
        self.private_key.require_current()?;
        self.owner.require_current()
    }
}

impl Slot {
    /// 业务作用：在仍持有的原文件上流式复验完整内容，当前路径不能为原读取偷偷换入另一份秘密。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：精确原长度和EOF对应的SHA-256；短读、增长、替换或读取失败拒绝。
    fn digest(&self) -> Result<[u8; 32]> {
        self.require_current()?;
        let mut file = &self.file;
        file.seek(SeekFrom::Start(0))?;
        let mut buffer = Zeroizing::new([0u8; 8192]);
        let mut digest = Sha256::new();
        let mut remaining = self.length;
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            digest.update(&buffer[..count]);
            remaining -= count as u64;
        }
        ensure!(
            file.read(&mut buffer[..1])? == 0,
            "material original source grew"
        );
        self.require_current()?;
        Ok(digest.finalize().into())
    }

    /// 业务作用：同时固定文件句柄、原长度和父目录，后续读取不能跟随同名后来文件。
    ///
    /// 参数说明：
    /// - `target`：从本机来源取得的单个文件位置。
    /// - `limit`：本用途允许的最大长度。
    ///
    /// 返回：普通单链接文件的原句柄；缺失、类型或容量异常拒绝。
    fn open(target: Target, limit: usize) -> Result<Self> {
        let (file, metadata) = target
            .open_regular(limit)?
            .context("TLS source file absent")?;
        Ok(Self {
            target,
            file,
            length: metadata.len(),
        })
    }

    /// 业务作用：把当前目录项与仍持有的原文件相比较，原inode未释放时同名替换不能冒充原读取。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原父目录、单链接文件身份和长度仍一致时成功；并不锁定外部写者。
    fn require_current(&self) -> Result<()> {
        self.target.require_current()?;
        let current = self.target.directory.symlink_metadata(&self.target.name)?;
        let original = self.file.metadata()?;
        ensure!(
            same_file(&current, &original)
                && original.len() == self.length
                && current.len() == self.length,
            "TLS source file identity or length changed"
        );
        Ok(())
    }
}

impl Control {
    /// 业务作用：从原句柄读取一次有界控制原文，目录解析与归属解析不通过路径重新取得另一文件。
    ///
    /// 参数说明：
    /// - `target`：原指针或owner位置。
    /// - `limit`：对应控制记录的最大字节数。
    ///
    /// 返回：原文件能力、固定摘要及唯一原文；完整读取或身份不符拒绝。
    fn open(target: Target, limit: usize) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let slot = Slot::open(target, limit)?;
        let bytes = crate::io::secret_file::read_open(slot.file.try_clone()?.into_std(), limit)?;
        let control = Self {
            slot,
            digest: Sha256::digest(&bytes).into(),
            limit,
        };
        control.require_current()?;
        Ok((control, bytes))
    }

    /// 业务作用：原文件身份之外再核对控制原文，原inode上的指针或owner改写也会撤销预检证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原文件项和完整原文摘要同时一致时成功；缺失、替换或内容变化拒绝。
    fn require_current(&self) -> Result<()> {
        self.slot.require_current()?;
        let bytes =
            io::read(&self.slot.target, self.limit)?.context("TLS control record absent")?;
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == self.digest,
            "TLS control record changed during capture"
        );
        self.slot.require_current()
    }
}
