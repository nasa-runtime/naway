//! 明确文件目标的受限访问与原文字节比较。

use super::LIMIT;
use anyhow::{ensure, Result};
use cap_std::fs::{File, Metadata, Permissions};
use sha2::{Digest as _, Sha256};
use std::io::Read;

pub(super) use crate::io::file_target::same_file;
pub(in crate::control) use crate::io::file_target::Target;

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
    /// 业务作用：读取普通单链接目标，禁止符号链接或特殊文件成为发布与补偿依据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：缺失为空；存在时给出同一句柄及元数据，类型、长度或打开失败拒绝。
    pub(in crate::control) fn file(&self) -> Result<Option<(File, Metadata)>> {
        self.open_regular(LIMIT)
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
