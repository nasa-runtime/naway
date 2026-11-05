//! 受限文件位置与固定父目录能力，持久恢复不能只凭同名路径取得写权。

use anyhow::{ensure, Context, Result};
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub(crate) struct Target {
    pub(crate) directory: Arc<Dir>,
    pub(crate) path: PathBuf,
    pub(crate) name: OsString,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Location {
    pub(crate) path: PathBuf,
    device: u64,
    inode: u64,
}

impl Target {
    /// 业务作用：打开有界普通单链接文件，受管写入不能把链接或特殊设备当成原备份依据。
    ///
    /// 参数说明：
    /// - `limit`：本业务允许的最大文件字节数。
    ///
    /// 返回：缺失为空，存在时返回同一句柄及元数据；类型、链接或超量在正文读取前拒绝。
    pub(crate) fn open_regular(&self, limit: usize) -> Result<Option<(File, Metadata)>> {
        match self.directory.symlink_metadata(&self.name) {
            Ok(metadata) => regular(&metadata, limit)?,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = self.directory.open_with(&self.name, &options)?;
        let metadata = file.metadata()?;
        regular(&metadata, limit)?;
        Ok(Some((file, metadata)))
    }

    /// 业务作用：在已固定父目录内选择另一个单一槽名，材料归属和journal不能重新追随路径别名。
    ///
    /// 参数说明：
    /// - `name`：受信代码产生的单个普通目录项名称。
    ///
    /// 返回：共享原目录句柄的相邻目标；绝对路径或多组件名称拒绝。
    pub(crate) fn sibling(&self, name: &std::ffi::OsStr) -> Result<Self> {
        let mut components = Path::new(name).components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
            "file target name must be one directory entry"
        );
        Ok(Self {
            directory: self.directory.clone(),
            path: self.path.with_file_name(name),
            name: name.to_owned(),
        })
    }

    /// 业务作用：拒绝把已持有的旧父目录当成当前部署位置，后续副作用仍必须使用该原目录句柄。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文本位置仍解析到原目录时成功；目录换代或消失拒绝，不重新授予新目录写权。
    pub(crate) fn require_current(&self) -> Result<()> {
        Location::capture(self)?.open()?;
        Ok(())
    }
    /// 业务作用：固定已存在的真实父目录及单个文件名，别名归一化不能扩大到任意目录创建。
    ///
    /// 参数说明：
    /// - `path`：已验证本机配置声明的部署目标。
    ///
    /// 返回：固定目录能力和真实目标位置；父目录缺失或目标名非法时拒绝。
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .context("file target has no file name")?
            .to_os_string();
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent).context("file target parent must exist")?;
        let directory = Arc::new(Dir::open_ambient_dir(
            &parent,
            cap_std::ambient_authority(),
        )?);
        Ok(Self {
            directory,
            path: parent.join(&name),
            name,
        })
    }

    /// 业务作用：确认本次目录项替换或删除，不把正文同步当成文件名已持久提交。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定目录同步成功，否则保留未确认提交的错误语义。
    pub(crate) fn sync(&self) -> Result<()> {
        self.directory.try_clone()?.into_std_file().sync_all()?;
        Ok(())
    }
}

impl Location {
    /// 业务作用：绑定真实父目录与文件名，进程重启后不能把旧决定应用到替换过的目录。
    ///
    /// 参数说明：
    /// - `target`：已经取得父目录能力的文件位置。
    ///
    /// 返回：有界绝对路径与父目录设备/inode；平台或路径不能稳定表达时拒绝。
    pub(crate) fn capture(target: &Target) -> Result<Self> {
        validate_path(&target.path)?;
        let (device, inode) = directory_identity(target)?;
        Ok(Self {
            path: target.path.clone(),
            device,
            inode,
        })
    }

    /// 业务作用：恢复前重新取得相同父目录能力，路径相同而目录已换代时保留保护状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：父目录和真实路径均匹配的目标；缺失、别名漂移或目录替换拒绝。
    pub(crate) fn open(&self) -> Result<Target> {
        validate_path(&self.path)?;
        let target = Target::open(&self.path)?;
        ensure!(
            Self::capture(&target)? == *self,
            "file location parent identity differs"
        );
        Ok(target)
    }
}

/// 业务作用：限定持久路径的长度和组件，恢复不能解释父目录跳转或非规范绝对路径。
///
/// 参数说明：
/// - `path`：待编码或解码的真实文件位置。
///
/// 返回：有界UTF-8绝对文件路径时成功，否则拒绝。
pub(crate) fn validate_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("file location path must be UTF-8")?;
    ensure!(
        text.len() <= 4096
            && !text.as_bytes().contains(&0)
            && path.is_absolute()
            && path.file_name().is_some()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "file location path differs"
    );
    Ok(())
}

/// 业务作用：提取固定父目录身份，不能仅凭文本位置承认恢复副作用。
///
/// 参数说明：
/// - `target`：持有父目录能力的目标。
///
/// 返回：Unix设备与inode；未支持平台拒绝持久文件恢复。
fn directory_identity(target: &Target) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        let metadata = target.directory.dir_metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        anyhow::bail!("file location requires Unix filesystem semantics")
    }
}

/// 业务作用：把发布目标限制为有界普通单链接文件，防止链接或设备扩大写入影响。
///
/// 参数说明：
/// - `metadata`：路径检查或实际打开句柄的元数据。
/// - `limit`：当前用途允许的最大字节数。
///
/// 返回：类型、硬链接数和长度满足时成功，否则在读取或写入前拒绝。
fn regular(metadata: &Metadata, limit: usize) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "file target type or size differs"
    );
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        ensure!(metadata.nlink() == 1, "file target cannot have hard links");
    }
    Ok(())
}

/// 业务作用：只有仍指向原临时文件的目录项才能由owner清理，防止删除后来占用同名路径的内容。
///
/// 参数说明：
/// - `current`：当前目录项的元数据。
/// - `original`：owner仍持有的原文件句柄元数据。
///
/// 返回：Unix设备与inode及普通单链接条件一致时为真，未支持平台保持内容不删。
pub(crate) fn same_file(current: &Metadata, original: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        current.is_file()
            && current.nlink() == 1
            && current.dev() == original.dev()
            && current.ino() == original.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (current, original);
        false
    }
}
