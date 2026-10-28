//! 固定目录能力与有限身份文件访问。

use super::identity::{Identity, MAX_RECORD};
use anyhow::{ensure, Context, Result};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use std::fs::{File, TryLockError};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path};

pub(super) const IDENTITY: &str = "identity";
pub(super) const INITIALIZING: &str = ".initializing";

pub(super) struct Root {
    pub(super) dir: Dir,
}

impl Root {
    /// 业务作用：逐路径组件取得固定目录能力，拒绝链接、父目录跳转和公开可读的存储根。
    ///
    /// 参数说明：
    /// - `path`：部署者预先创建的journal目录，不创建任何祖先。
    ///
    /// 返回：仅能操作该目录的句柄；平台、路径、类型或权限不满足时拒绝。
    pub(super) fn open(path: &Path) -> Result<Self> {
        ensure!(
            !path.as_os_str().is_empty(),
            "node journal directory is empty"
        );
        let options = options(true)?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut dir = Dir::open_ambient_dir("/", cap_std::ambient_authority())
            .context("cannot open node journal path root")?;
        let mut depth = 0;
        for component in absolute.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    ensure!(depth < 64, "node journal path exceeds depth limit");
                    let child = dir
                        .open_with(name, &options)
                        .context("node journal path must contain only ordinary directories")?;
                    dir = Dir::from_std_file(child.into_std());
                    depth += 1;
                }
                _ => anyhow::bail!("node journal path cannot traverse parent components"),
            }
        }
        ensure!(depth > 0, "node journal cannot use the filesystem root");
        private(&dir.dir_metadata()?)?;
        Ok(Self {
            dir,
        })
    }

    /// 业务作用：非阻塞取得目录独占权，区分已有owner与文件系统不能提供锁的情况。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：成功时返回必须持有的锁句柄，已有owner时为空；其它锁错误拒绝，不伪称忙碌。
    pub(super) fn try_lock(&self) -> Result<Option<File>> {
        let file = self.dir.try_clone()?.into_std_file();
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => {
                Err(error).context("node journal owner lock unavailable")
            }
        }
    }

    /// 业务作用：拒绝当前实现不能解释的目录内容，避免把未知动作事实当成空闲状态。
    ///
    /// 参数说明：
    /// - `initializing`：仅显式初始化允许识别尚未提交的固定临时记录。
    ///
    /// 返回：全部条目均属于当前格式时成功，发现未知项立即拒绝，不扫描或删除其内容。
    pub(super) fn inspect(&self, initializing: bool) -> Result<()> {
        private(&self.dir.dir_metadata()?)?;
        for entry in self.dir.read_dir(".")? {
            let name = entry?.file_name();
            ensure!(
                name == IDENTITY
                    || (initializing && name == INITIALIZING)
                    || super::storage::known(&name, initializing),
                "node journal contains unsupported or incomplete records"
            );
        }
        Ok(())
    }

    /// 业务作用：通过已固定目录读取有限完整身份，链接、特殊文件和共享硬链接不能提供写权证据。
    ///
    /// 参数说明：
    /// - `name`：模块内部固定的identity或初始化记录名。
    ///
    /// 返回：缺失为空，存在时返回已验证身份与原字节；任何结构或I/O错误拒绝。
    pub(super) fn read(&self, name: &str) -> Result<Option<(Identity, Vec<u8>)>> {
        self.read_raw(name, MAX_RECORD)?
            .map(|bytes| Identity::decode(&bytes).map(|identity| (identity, bytes)))
            .transpose()
    }

    /// 业务作用：从固定目录读取有界私有记录，为身份与状态提供相同的文件类型和权限门。
    ///
    /// 参数说明：
    /// - `name`：模块内部固定的文件名。
    /// - `limit`：该类记录允许的最大字节数。
    ///
    /// 返回：缺失为空，存在时读取至EOF；类型、权限、共享链接或长度异常拒绝。
    pub(super) fn read_raw(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        let Some(file) = self.open_record(name, limit)? else {
            return Ok(None);
        };
        let mut bytes = Vec::with_capacity(256);
        file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= limit, "node journal record exceeds limit");
        Ok(Some(bytes))
    }

    /// 业务作用：为大正文提供同一私有普通文件门，调用者可流式处理而不分配完整副本。
    ///
    /// 参数说明：
    /// - `name`：存储协议确定的固定文件名。
    /// - `limit`：该记录允许的最大长度。
    ///
    /// 返回：缺失或并发解除链接为空；有效记录返回从起点读取的句柄，类型或权限异常拒绝。
    pub(super) fn open_record(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<cap_std::fs::File>> {
        match self.dir.symlink_metadata(name) {
            Ok(metadata) => {
                if unlinked(&metadata) {
                    return Ok(None);
                }
                regular(&metadata, limit)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("cannot inspect node journal record"),
        }
        let file = match self.dir.open_with(name, &options(false)?) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("cannot open node journal record"),
        };
        // 打开后复验同一句柄，路径检查与打开之间的替换不能把FIFO、目录或链接变成身份事实。
        let metadata = file.metadata()?;
        // 原子替换可能解除读者已打开的旧槽链接；报告缺席，让head双读协议重试，不能误判共享硬链接。
        if unlinked(&metadata) {
            return Ok(None);
        }
        regular(&metadata, limit)?;
        Ok(Some(file))
    }

    /// 业务作用：先完整同步新身份的临时记录，再允许目录项发布，断电不把部分正文标为已初始化。
    ///
    /// 参数说明：
    /// - `bytes`：已经编码并限制长度的身份记录。
    ///
    /// 返回：临时记录完整同步后成功；失败保留精确临时路径供显式复验，不自动清空未知写结果。
    pub(super) fn stage(&self, bytes: &[u8]) -> Result<()> {
        self.create(INITIALIZING, bytes)
    }

    /// 业务作用：排他创建并同步固定暂存记录，已有文件不被隐式截断或覆盖。
    ///
    /// 参数说明：
    /// - `name`：已经由存储协议选定的固定空闲记录名。
    /// - `bytes`：完成有界编码的原始记录。
    ///
    /// 返回：正文和目录都同步后成功；失败保留精确残留供下一次协议复验。
    pub(super) fn create(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = self.create_file(name)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.sync()
    }

    /// 业务作用：排他创建私有固定正文槽，持久计划确认之后才能调用，不覆盖任何残留。
    ///
    /// 参数说明：
    /// - `name`：已确认空闲的协议固定文件名。
    ///
    /// 返回：新文件的写句柄；调用方必须完成正文、文件与目录同步后才声明可用。
    pub(super) fn create_file(&self, name: &str) -> Result<cap_std::fs::File> {
        let mut options = options(false)?;
        options.read(false).write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = self
            .dir
            .open_with(name, &options)
            .context("cannot create node journal initialization record")?;
        Ok(file)
    }

    /// 业务作用：发布已完整核验的永久身份并同步父目录，调用方只有在同步成功后才确认初始化。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原子rename与目录同步完成后成功；错误保留未知提交语义，需用原身份复查。
    pub(super) fn publish(&self) -> Result<()> {
        self.publish_record(INITIALIZING, IDENTITY)
    }

    /// 业务作用：显式初始化重试只删除与永久记录完全相同的残留，避免清除未确认的其它绑定。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定临时项删除且目录同步后成功；失败保留重试边界。
    pub(super) fn finish(&self) -> Result<()> {
        self.remove(INITIALIZING)
    }

    /// 业务作用：原子切换固定提交入口，并在确认目录持久化之后才承认新权威。
    ///
    /// 参数说明：
    /// - `from`：已经完整校验和同步的暂存记录。
    /// - `to`：协议确定的提交记录名。
    ///
    /// 返回：rename及目录同步完成；失败可能已提交，调用方必须回读原事实。
    pub(super) fn publish_record(&self, from: &str, to: &str) -> Result<()> {
        self.dir.rename(from, &self.dir, to)?;
        self.sync()
    }

    /// 业务作用：只移除调用方已经判定不具提交权威的固定记录，并确认目录变化。
    ///
    /// 参数说明：
    /// - `name`：已验证可以回收的精确文件名。
    ///
    /// 返回：删除与同步完成；失败不得当作空间已释放。
    pub(super) fn remove(&self, name: &str) -> Result<()> {
        self.dir.remove_file(name)?;
        self.sync()
    }

    /// 业务作用：重试时重新确认完整记录和目录已经持久化，读到完整字节不能替代成功同步。
    ///
    /// 参数说明：
    /// - `name`：已经完整校验的固定记录名。
    /// - `limit`：该类记录的长度上限。
    ///
    /// 返回：当前私有普通文件及目录同步完成；缺失、替换或I/O异常拒绝确认。
    pub(super) fn sync_record(&self, name: &str, limit: usize) -> Result<()> {
        let file = self.dir.open_with(name, &options(false)?)?;
        regular(&file.metadata()?, limit)?;
        file.sync_all()?;
        self.sync()
    }

    /// 业务作用：持久确认目录项变化，文件正文同步不能替代rename或删除的提交证据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：目录句柄同步成功，否则调用者不得报告已确认提交。
    pub(super) fn sync(&self) -> Result<()> {
        self.dir
            .try_clone()?
            .into_std_file()
            .sync_all()
            .context("node journal directory synchronization failed")
    }
}

/// 业务作用：为目录和记录统一禁止链接跟随，并使特殊文件替换不能阻塞启动线程。
///
/// 参数说明：
/// - `directory`：是否要求只打开目录组件。
///
/// 返回：Unix受限打开选项；未支持平台明确拒绝，不退回普通路径访问。
fn options(directory: bool) -> Result<OpenOptions> {
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    0
                },
        );
        Ok(options)
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        anyhow::bail!("node journal requires Unix directory and durability semantics")
    }
}

/// 业务作用：存储根与身份不能开放给其它用户，原文和永久控制事实遵守同一私有权限边界。
///
/// 参数说明：
/// - `metadata`：来自当前已固定对象的元数据。
///
/// 返回：当前平台的私有权限成立时成功；其它权限或未支持平台拒绝。
fn private(metadata: &Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "node journal requires private permissions"
        );
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        anyhow::bail!("node journal private permissions are unsupported")
    }
}

/// 业务作用：身份只能由一个私有普通文件提供，拒绝通过共享inode或特殊设备改变证据语义。
///
/// 参数说明：
/// - `metadata`：当前记录的元数据。
/// - `limit`：该类记录的字节上限。
///
/// 返回：普通文件、单硬链接、长度及权限都成立；不合法时不读取正文。
fn regular(metadata: &Metadata, limit: usize) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "node journal record type or size differs"
    );
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "node journal record cannot have hard links"
        );
    }
    private(metadata)
}

/// 业务作用：区分已被提交切换解除链接的旧读句柄与共享硬链接，允许上层按head重新读取。
///
/// 参数说明：
/// - `metadata`：路径检查或打开后取得的文件元数据。
///
/// 返回：仅普通文件已无目录链接时为true；共享链接和特殊文件仍交给严格类型门拒绝。
fn unlinked(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        metadata.is_file() && metadata.nlink() == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
