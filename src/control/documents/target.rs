//! 明确文件目标的受限访问与原文字节比较。

use super::LIMIT;
use anyhow::{ensure, Context, Result};
use cap_std::fs::{Dir, File, Metadata, OpenOptions, Permissions};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub(in crate::control) struct Target {
    pub(in crate::control) directory: Arc<Dir>,
    pub(in crate::control) path: PathBuf,
    pub(in crate::control) name: OsString,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control) struct Fingerprint {
    pub(in crate::control) length: u64,
    pub(in crate::control) sha256: [u8; 32],
}

pub(in crate::control) struct Original {
    pub(in crate::control) bytes: Vec<u8>,
    pub(in crate::control) permissions: Permissions,
    pub(in crate::control) fingerprint: Fingerprint,
}

impl Target {
    /// 业务作用：固定已存在的真实父目录及单个文件名，别名归一化不能扩大到任意目录创建。
    ///
    /// 参数说明：
    /// - `path`：已验证配置声明的部署目标。
    ///
    /// 返回：固定目录能力和真实目标位置；父目录缺失或目标名非法时拒绝。
    pub(in crate::control) fn open(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .context("configuration target has no file name")?
            .to_os_string();
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent =
            std::fs::canonicalize(parent).context("configuration target parent must exist")?;
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

    /// 业务作用：读取普通单链接目标，禁止符号链接或特殊文件成为发布与补偿依据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：缺失为空；存在时给出同一句柄及元数据，类型、长度或打开失败拒绝。
    pub(in crate::control) fn file(&self) -> Result<Option<(File, Metadata)>> {
        match self.directory.symlink_metadata(&self.name) {
            Ok(metadata) => regular(&metadata)?,
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
        regular(&metadata)?;
        Ok(Some((file, metadata)))
    }

    /// 业务作用：仅为确实需要补偿的控制面文件保留一份有界原文，后续比较使用流式摘要。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原文、权限及摘要；缺失为空，超限或读取错误拒绝且不写入。
    pub(in crate::control) fn read(&self) -> Result<Option<Original>> {
        let Some((file, metadata)) = self.file()? else {
            return Ok(None);
        };
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= LIMIT, "configuration document exceeds limit");
        Ok(Some(Original {
            fingerprint: Fingerprint::of(&bytes),
            bytes,
            permissions: metadata.permissions(),
        }))
    }

    /// 业务作用：将存在与缺失两类基线统一为副作用前的条件比较，不能把缺失当空文档。
    ///
    /// 参数说明：
    /// - `original`：暂存之前捕获的原始目标。
    ///
    /// 返回：目标仍有相同正文/权限或仍缺失时为真，I/O错误拒绝。
    pub(in crate::control) fn matches_original(&self, original: Option<&Original>) -> Result<bool> {
        self.matches(original.map(|old| (old.fingerprint, &old.permissions)))
    }

    /// 业务作用：用固定缓冲复验正文和权限，避免等待发布或补偿期间再次复制完整配置。
    ///
    /// 参数说明：
    /// - `expected`：期望的摘要与权限；为空要求目标仍不存在。
    ///
    /// 返回：存在状态、权限、长度及SHA-256一致时为真，类型或I/O异常返回错误。
    pub(in crate::control) fn matches(
        &self,
        expected: Option<(Fingerprint, &Permissions)>,
    ) -> Result<bool> {
        let actual = self.file()?;
        let (mut file, metadata, expected, permissions) = match (actual, expected) {
            (None, None) => return Ok(true),
            (Some((file, metadata)), Some((expected, permissions))) => {
                (file, metadata, expected, permissions)
            }
            _ => return Ok(false),
        };
        if metadata.len() != expected.length
            || !same_permissions(&metadata.permissions(), permissions)
        {
            return Ok(false);
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut total = 0u64;
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            total += length as u64;
            if total > expected.length {
                return Ok(false);
            }
            hash.update(&buffer[..length]);
        }
        Ok(total == expected.length && <[u8; 32]>::from(hash.finalize()) == expected.sha256)
    }

    /// 业务作用：确认本次目录项替换或删除，不把正文同步当成文件名已持久提交。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定目录同步成功，否则保留未确认提交的错误语义。
    pub(in crate::control) fn sync(&self) -> Result<()> {
        self.directory.try_clone()?.into_std_file().sync_all()?;
        Ok(())
    }
}

impl Fingerprint {
    /// 业务作用：以固定缓冲冻结原文身份，为持久正文与文件复验提供相同的长度和摘要边界。
    ///
    /// 参数说明：
    /// - `reader`：位于正文起点的输入，读取至EOF。
    ///
    /// 返回：完整原文的长度和SHA-256；读取失败或超过文档上限时拒绝。
    #[cfg(feature = "node-journal")]
    pub(in crate::control) fn read(reader: &mut impl Read) -> Result<Self> {
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 16384];
        let mut length = 0u64;
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            length += count as u64;
            ensure!(
                length <= LIMIT as u64,
                "configuration document exceeds limit"
            );
            hash.update(&buffer[..count]);
        }
        Ok(Self {
            length,
            sha256: hash.finalize().into(),
        })
    }

    /// 业务作用：绑定单份原文长度和内容，补偿不能仅凭配置展示版本覆盖文件。
    ///
    /// 参数说明：
    /// - `bytes`：原文借用，不解析或重新编码。
    ///
    /// 返回：定长比较证据，不保留第二份正文。
    pub(in crate::control) fn of(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }
}

/// 业务作用：把发布目标限制为有界普通单链接文件，防止链接或设备扩大写入影响。
///
/// 参数说明：
/// - `metadata`：路径检查或实际打开句柄的元数据。
///
/// 返回：类型、硬链接数和长度满足时成功，否则在读取或写入前拒绝。
fn regular(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.len() <= LIMIT as u64,
        "configuration target type or size differs"
    );
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "configuration target cannot have hard links"
        );
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
pub(super) fn same_file(current: &Metadata, original: &Metadata) -> bool {
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

/// 业务作用：权限变化同样使旧补偿失效，不能在恢复正文时撤销操作者后来设置的访问约束。
///
/// 参数说明：
/// - `left`：当前目标权限。
/// - `right`：本次发布保存的权限。
///
/// 返回：当前平台可观察的权限相等时为真。
fn same_permissions(left: &Permissions, right: &Permissions) -> bool {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        left.mode() & 0o7777 == right.mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        left.readonly() == right.readonly()
    }
}
