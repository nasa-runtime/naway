//! 指针与材料目录沿用准备时的能力，后来的同名文件不能继承激活资格。

use super::super::{generation, io};
use crate::io::file_target::{same_file, Target};
use anyhow::{ensure, Context, Result};
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
use sha2::{Digest as _, Sha256};
use std::{ffi::OsStr, io::ErrorKind, path::Path, sync::Arc};

pub(super) struct Pointer<'a> {
    declared: &'a Path,
    pub(super) target: Target,
    original: Option<(File, [u8; 32])>,
}

pub(super) struct Directory {
    target: Target,
    directory: Arc<Dir>,
}

impl<'a> Pointer<'a> {
    /// 业务作用：在材料准备之前固定原指针的存在状态和文件身份，初次激活不能覆盖后来出现的指针。
    ///
    /// 参数说明：
    /// - `declared`：本机配置选择的manifest位置，父目录已经存在。
    ///
    /// 返回：原父目录和原指针证据；链接、特殊文件或超量指针拒绝。
    pub(super) fn capture(declared: &'a Path) -> Result<Self> {
        let target = Target::open(declared)?;
        let original = target
            .open_regular(64 * 1024)?
            .map(|(file, _)| {
                let bytes =
                    crate::io::secret_file::read_open(file.try_clone()?.into_std(), 64 * 1024)?;
                Ok::<_, anyhow::Error>((file, Sha256::digest(&bytes).into()))
            })
            .transpose()?;
        let pointer = Self {
            declared,
            target,
            original,
        };
        pointer.require_original()?;
        Ok(pointer)
    }

    /// 业务作用：复验当前声明仍指向准备时的原目录，声明别名切换不能重定向指针写入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：声明映射和原父目录身份同时成立时成功，否则保留原准备目录。
    pub(super) fn require_declared(&self) -> Result<()> {
        ensure!(
            generation::identity_path(self.declared)? == self.target.path,
            "TLS manifest declaration changed"
        );
        self.target.require_current()
    }

    /// 业务作用：激活前同时复验原指针身份与原文，不能覆盖准备期间发生的另一材料决定。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原来缺失仍缺失，或原普通文件及摘要均不变时成功；相同字节的新文件也拒绝。
    pub(super) fn require_original(&self) -> Result<()> {
        self.require_declared()?;
        let current = self.target.open_regular(64 * 1024)?;
        match (&self.original, current) {
            (None, None) => Ok(()),
            (Some((original, digest)), Some((file, metadata))) => {
                ensure!(
                    same_file(&metadata, &original.metadata()?),
                    "TLS original manifest identity changed"
                );
                let bytes = crate::io::secret_file::read_open(file.into_std(), 64 * 1024)?;
                ensure!(
                    <[u8; 32]>::from(Sha256::digest(&bytes)) == *digest,
                    "TLS original manifest content changed"
                );
                ensure!(
                    same_file(
                        &self.target.directory.symlink_metadata(&self.target.name)?,
                        &original.metadata()?
                    ),
                    "TLS original manifest replaced while reading"
                );
                self.require_declared()
            }
            _ => anyhow::bail!("TLS original manifest presence changed"),
        }
    }

    /// 业务作用：在原指针位置观察本次已决定原文，目录同步错误后也不能把旧指针当作成功。
    ///
    /// 参数说明：
    /// - `expected`：本次准备生成的唯一指针原文。
    ///
    /// 返回：当前原位置仍选择该原文时成功，不赋予后续任务持续写权。
    pub(super) fn require_published(&self, expected: &[u8]) -> Result<()> {
        self.require_declared()?;
        let bytes = io::read(&self.target, 64 * 1024)?.context("TLS published manifest absent")?;
        ensure!(
            bytes.as_slice() == expected,
            "TLS published manifest changed"
        );
        self.require_declared()
    }
}

impl Directory {
    /// 业务作用：在原父目录取得材料根或独占新目录，目录创建时即限制访问且不跟随符号链接。
    ///
    /// 参数说明：
    /// - `target`：从原父目录能力派生的单一目录项。
    /// - `existing`：材料根允许复用既有目录，新材料目录必须独占创建。
    ///
    /// 返回：原目录及其父目录能力；名称碰撞、链接、目录替换或同步失败拒绝。
    pub(super) fn create(target: Target, existing: bool) -> Result<Self> {
        target.require_current()?;
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use cap_std::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match target.directory.create_dir_with(&target.name, &builder) {
            Ok(()) => {}
            Err(error) if existing && error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            target.directory.symlink_metadata(&target.name)?.is_dir(),
            "TLS material location must be a directory"
        );
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        }
        let file = target.directory.open_with(&target.name, &options)?;
        let directory = Self {
            target,
            directory: Arc::new(Dir::from_std_file(file.into_std())),
        };
        directory.require_current()?;
        // 子目录内部文件的同步不包含父目录项；准备成功前必须确认这个目录本身可在重启后找到。
        directory.target.sync()?;
        Ok(directory)
    }

    /// 业务作用：在固定材料目录内派生文件或子目录位置，不重新解析原声明字符串。
    ///
    /// 参数说明：
    /// - `name`：受信代码确定的单一目录项名称。
    ///
    /// 返回：共享本目录能力的目标；多组件或绝对名称拒绝。
    pub(super) fn entry(&self, name: &str) -> Result<Target> {
        let target = Target {
            directory: self.directory.clone(),
            path: self.target.path.join("cert.pem"),
            name: "cert.pem".into(),
        };
        target.sibling(OsStr::new(name))
    }

    /// 业务作用：材料目录和父目录必须都保留原身份，不能激活同名替换的材料树。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录项设备及inode一致时成功；不支持稳定目录身份的平台拒绝。
    pub(super) fn require_current(&self) -> Result<()> {
        self.target.require_current()?;
        #[cfg(unix)]
        {
            use cap_std::fs::MetadataExt as _;
            let current = self.target.directory.symlink_metadata(&self.target.name)?;
            let original = self.directory.dir_metadata()?;
            ensure!(
                current.is_dir()
                    && current.dev() == original.dev()
                    && current.ino() == original.ino(),
                "TLS material directory identity changed"
            );
            Ok(())
        }
        #[cfg(not(unix))]
        anyhow::bail!("TLS material directories require Unix filesystem semantics")
    }

    /// 业务作用：完整材料准备和失败清理都必须确认原目录项持久化，不把文件内容同步当成目录提交。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定目录及其父目录同步成功，否则不提供明确准备结论。
    pub(super) fn sync(&self) -> Result<()> {
        self.directory.try_clone()?.into_std_file().sync_all()?;
        self.target.sync()?;
        self.require_current()
    }

    /// 业务作用：仅撤销尚未激活且仍属于原句柄的准备目录，同名后来目录不能被失败清理删除。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原目录删除并同步成功；身份不符保留现场，不按文本路径递归删除。
    pub(super) fn discard(&self) -> Result<()> {
        self.require_current()?;
        self.directory.try_clone()?.remove_open_dir_all()?;
        self.target.sync()
    }
}
