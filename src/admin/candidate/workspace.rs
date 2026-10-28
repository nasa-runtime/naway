//! 三份原始候选文档的有限、私有临时存储。

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;

use crate::config::candidate::{Documents, Sidecars};
use crate::control::history::ArchivedDocs;

/// 一个构建任务独占创建的目录和文件；不扫描或删除其它任务的路径。
pub(super) struct Workspace<'a> {
    root: PathBuf,
    files: [PathBuf; 3],
    created: [bool; 3],
    removed: bool,
    permit: &'a super::admission::Permit,
}

impl<'a> Workspace<'a> {
    /// 业务作用：在复制原文或创建文件前拒绝超出单文档预算的输入。
    ///
    /// 参数说明：
    /// - `docs`：待构建的三份原文。
    ///
    /// 返回：全部在预算内成功；超限不分配工作区或复制正文。
    pub(super) fn validate(docs: &ArchivedDocs) -> Result<()> {
        anyhow::ensure!(
            [&docs.gateway, &docs.interface_guard, &docs.sentinel_rules]
                .iter()
                .all(|document| document.len() <= crate::config::document::MAX_DOCUMENT_BYTES),
            "candidate document exceeds size limit"
        );
        Ok(())
    }

    /// 业务作用：在真实配置旁排他创建私有工作区，防止并发候选覆盖或复用已有文件。
    ///
    /// 参数说明：
    /// - `real`：真实主配置路径，只用于选择临时目录所在位置。
    /// - `permit`：覆盖本任务真实生命周期，清理失败时关闭后续受理。
    ///
    /// 返回：唯一目录 owner；随机源、权限或创建失败时不读取既存目录。
    pub(super) fn create(real: &Path, permit: &'a super::admission::Permit) -> Result<Self> {
        let parent = real.parent().unwrap_or_else(|| Path::new("."));
        for _ in 0..8 {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| anyhow::anyhow!("candidate randomness unavailable"))?;
            let name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
            let root = parent.join(format!(".naway-candidate-{name}"));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => {
                    return Ok(Self {
                        files: [
                            root.join("gateway.yml"),
                            root.join("guard.yml"),
                            root.join("sentinel.yml"),
                        ],
                        root,
                        created: [false; 3],
                        removed: false,
                        permit,
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("cannot create candidate workspace"),
            }
        }
        anyhow::bail!("candidate workspace collision budget exhausted")
    }

    /// 业务作用：把三份原文直接写入私有工作区，不改写路径、注释、占位符或秘密。
    ///
    /// 参数说明：
    /// - `docs`：已经接收的候选原文。
    ///
    /// 返回：三文件完整写入后成功；任一失败仍由当前 owner 清理已创建文件。
    pub(super) fn write(&mut self, docs: &ArchivedDocs) -> Result<()> {
        Self::validate(docs)?;
        for (index, document) in [&docs.gateway, &docs.interface_guard, &docs.sentinel_rules]
            .into_iter()
            .enumerate()
        {
            self.write_document(index, document.as_bytes())?;
        }
        Ok(())
    }

    /// 业务作用：只暂存主文档原字节，规则文件继续由真实部署根与profile解析。
    ///
    /// 参数说明：
    /// - `bytes`：有界主文档载荷，保持共享Bytes的原始表示。
    ///
    /// 返回：主文档完整写入后成功；超限不创建文件，写失败仍由当前owner清理。
    pub(super) fn write_main(&mut self, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            bytes.len() <= crate::config::document::MAX_DOCUMENT_BYTES,
            "candidate document exceeds size limit"
        );
        self.write_document(0, bytes)
    }

    /// 业务作用：只覆盖命令签名的一个领域，另外两个 base 沿用真实来源，不能夹带未签名原文。
    ///
    /// 参数说明：
    /// - `domain`：原命令唯一配置领域。
    /// - `bytes`：已通过长度和摘要验证的原始候选。
    /// - `real`：当前真实主文档与规则位置。
    ///
    /// 返回：实际候选读取集合；超限或写入失败拒绝，主配置仍可通过声明选择新的规则目标。
    #[cfg(feature = "node-actions")]
    pub(super) fn write_domain<'b>(
        &'b mut self,
        domain: crate::control::actions::domain::Domain,
        bytes: &[u8],
        real: &'b crate::config::candidate::Paths,
    ) -> Result<Documents<'b>> {
        use crate::control::actions::domain::Domain;
        anyhow::ensure!(
            bytes.len() <= crate::config::document::MAX_DOCUMENT_BYTES,
            "candidate document exceeds size limit"
        );
        if domain == Domain::Gateway {
            self.write_main(bytes)?;
            return Ok(self.main_document());
        }
        self.write_document(
            if domain == Domain::InterfaceGuard {
                1
            } else {
                2
            },
            bytes,
        )?;
        Ok(Documents {
            gateway: &real.gateway,
            sidecars: Some(Sidecars {
                guard: if domain == Domain::InterfaceGuard {
                    &self.files[1]
                } else {
                    &real.guard
                },
                sentinel: if domain == Domain::Sentinel {
                    &self.files[2]
                } else {
                    &real.sentinel
                },
            }),
        })
    }

    /// 业务作用：将持久动作的三份原文按固定缓冲送入现有构建链，避免为重新解析额外分配完整正文。
    ///
    /// 参数说明：
    /// - `sources`：位于起点的主文档、guard、Sentinel 只读句柄，内容身份由动作最终决定门复验。
    ///
    /// 返回：全部原字节复制成功；超限、长度变化或读写失败拒绝，已创建内容仍由当前 owner 清理。
    #[cfg(feature = "node-actions")]
    pub(super) fn write_files(&mut self, sources: &mut [File; 3]) -> Result<()> {
        use std::io::Read as _;

        let lengths = [
            sources[0].metadata()?.len(),
            sources[1].metadata()?.len(),
            sources[2].metadata()?.len(),
        ];
        anyhow::ensure!(
            lengths
                .iter()
                .all(|length| *length <= crate::config::document::MAX_DOCUMENT_BYTES as u64),
            "candidate document exceeds size limit"
        );
        let mut buffer = [0u8; 16384];
        for (index, source) in sources.iter_mut().enumerate() {
            let mut destination = self.create_document(index)?;
            let mut length = 0u64;
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                length += count as u64;
                anyhow::ensure!(
                    length <= lengths[index],
                    "candidate document grew during copy"
                );
                destination.write_all(&buffer[..count])?;
            }
            anyhow::ensure!(
                length == lengths[index],
                "candidate document changed during copy"
            );
        }
        Ok(())
    }

    /// 业务作用：为本任务固定文档排他创建私有文件，记录创建事实后才写入以覆盖中途失败。
    ///
    /// 参数说明：
    /// - `index`：内部固定的主文档、guard或Sentinel位置。
    /// - `bytes`：直接写入的原文，不重新序列化。
    ///
    /// 返回：写入成功；已有路径不覆盖，部分写入继续由当前owner回收。
    fn write_document(&mut self, index: usize, bytes: &[u8]) -> Result<()> {
        self.create_document(index)?
            .write_all(bytes)
            .context("cannot write candidate document")
    }

    /// 业务作用：统一所有候选输入的排他创建和私有权限，在首次写入之前记录清理责任。
    ///
    /// 参数说明：
    /// - `index`：本工作区内部的固定文档位置。
    ///
    /// 返回：仅属于当前 owner 的新文件；已有路径拒绝且不取得其清理权。
    fn create_document(&mut self, index: usize) -> Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&self.files[index])
            .context("cannot create candidate document")?;
        self.created[index] = true;
        Ok(file)
    }

    /// 业务作用：只覆盖主文档输入，不能把未提供的规则文档误当成空规则集。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：主文档路径及明确未覆盖的sidecars，借用期受当前owner限制。
    pub(super) fn main_document(&self) -> Documents<'_> {
        Documents {
            gateway: &self.files[0],
            sidecars: None,
        }
    }

    /// 业务作用：将当前 owner 的固定文件借给构建器，避免把物理工作区路径编码进 YAML。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅在 owner 存活期间有效的完整文档输入引用。
    pub(super) fn documents(&self) -> Documents<'_> {
        Documents {
            gateway: &self.files[0],
            sidecars: Some(Sidecars {
                guard: &self.files[1],
                sentinel: &self.files[2],
            }),
        }
    }

    /// 业务作用：逐一删除本任务实际创建的文件，清理异常不能被当成候选成功。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：文件和目录均已删除时成功；失败仍尝试其它已知路径，并关闭新候选受理、留待析构再试。
    pub(super) fn cleanup(&mut self) -> Result<()> {
        if self.removed {
            return Ok(());
        }
        let mut failure = None;
        for (path, created) in self.files.iter().zip(&mut self.created) {
            if !*created {
                continue;
            }
            match fs::remove_file(path) {
                Ok(()) => *created = false,
                Err(error) if error.kind() == ErrorKind::NotFound => *created = false,
                Err(error) => failure = Some(error),
            }
        }
        match fs::remove_dir(&self.root) {
            Ok(()) => self.removed = true,
            Err(error) if error.kind() == ErrorKind::NotFound => self.removed = true,
            Err(error) => failure = Some(error),
        }
        match failure {
            Some(error) => {
                // 未确认清理时不能按普通空闲槽继续接单，否则重复失败会无限积累原始配置。
                self.permit.close_admission();
                tracing::warn!("candidate cleanup incomplete; candidate admission closed");
                Err(error).context("cannot remove candidate workspace")
            }
            None => Ok(()),
        }
    }
}

impl Drop for Workspace<'_> {
    /// 业务作用：在解析拒绝或工作单元展开退出时保留清理职责，避免请求取消遗留原始配置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；精确清理失败记录低敏告警，不递归删除未知文件。
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(%error, "candidate workspace cleanup incomplete");
        }
    }
}
