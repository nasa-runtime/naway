//! 活动具名配置的有界原文归档。

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::config::GatewaySnapshot;

pub(super) struct Archive {
    root: PathBuf,
    documents: BTreeMap<String, (PathBuf, [u8; 32])>,
}

impl Archive {
    /// 业务作用：冻结实际生效的所有模块原文并保护含凭据引用的归档文件。
    /// 参数说明：
    /// - `parent`：该节点配置历史目录。
    /// - `snapshot`：带有已生效模块路径和原文摘要的快照。
    /// 返回：已写入完整、摘要匹配的模块集合。失败时释放此归档独占创建的文件。
    pub(super) fn capture(parent: &Path, snapshot: &GatewaySnapshot) -> Result<Self> {
        ensure!(
            !snapshot.named_documents.is_empty(),
            "active named configuration is empty"
        );
        fs::create_dir_all(parent)?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|error| anyhow::anyhow!("{error}"))?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let root = parent.join(format!("named-{}-{nonce}", snapshot.version));
        DirBuilder::new().mode(0o700).create(&root)?;
        let mut archive = Self {
            root,
            documents: BTreeMap::new(),
        };
        let mut remaining = super::MAX_ARCHIVED_DOCUMENT_BYTES;
        for (position, document) in snapshot.named_documents.iter().enumerate() {
            let bytes = crate::io::bounded_io::read_file(
                &document.path,
                remaining,
                "named configuration archive",
            )?;
            remaining -= bytes.len();
            ensure!(
                Sha256::digest(&bytes).as_slice() == document.digest,
                "named configuration changed before archive"
            );
            let path = archive.root.join(position.to_string());
            let mut file = OpenOptions::new()
                .write(true)
                .mode(0o600)
                .create_new(true)
                .open(&path)?;
            // 在写原文前记录文件所属，任何短写或刷盘失败也能精确清理。
            archive
                .documents
                .insert(document.name.clone(), (path, document.digest));
            file.write_all(&bytes)?;
            file.sync_data()?;
        }
        Ok(archive)
    }

    /// 业务作用：只交付与当前索引摘要完全一致的历史原文，防止磁盘漂移改变管理候选。
    /// 参数说明: 无。
    /// 返回：完整 UTF-8 文档集合；缺件、超限、编码错误或摘要变化时拒绝整个集合。
    pub(super) fn read(&self) -> Result<BTreeMap<String, String>> {
        let mut remaining = super::MAX_ARCHIVED_DOCUMENT_BYTES;
        self.documents
            .iter()
            .map(|(name, (path, digest))| {
                let bytes = crate::io::bounded_io::read_file(path, remaining, "named archive")?;
                remaining -= bytes.len();
                ensure!(
                    Sha256::digest(&bytes).as_slice() == *digest,
                    "named archive content changed"
                );
                let value = String::from_utf8(bytes).context("named archive is not UTF-8")?;
                Ok((name.clone(), value))
            })
            .collect()
    }
}

impl Drop for Archive {
    /// 业务作用：最后一个归档使用者退出后移除该归档专属原文，防止秘密随无效历史残留。
    /// 参数说明: 无。
    /// 返回：无；删除失败记录低敏告警，未知目录项由目录本身的排他所有权约束。
    fn drop(&mut self) {
        for (path, _) in self.documents.values() {
            if let Err(error) = fs::remove_file(path) {
                tracing::warn!(%error, "named configuration archive file cleanup failed");
            }
        }
        if let Err(error) = fs::remove_dir(&self.root) {
            tracing::warn!(%error, "named configuration archive directory cleanup failed");
        }
    }
}
