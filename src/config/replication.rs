//! 本地具名配置的集群原文身份。只保留业务名称与经完整装配确认的字节。

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use super::{
    config_fingerprint, GatewaySnapshot, MAX_FINGERPRINT_FILE_BYTES, NAMED_DOCUMENT_LIMIT,
};

pub(crate) const MAX_TRANSFER_BYTES: usize = 2 * MAX_FINGERPRINT_FILE_BYTES;
pub(crate) const MAX_TRANSFER_DOCUMENTS: usize = NAMED_DOCUMENT_LIMIT + 1;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Name {
    Entry,
    Module(String),
}

pub(crate) struct Document {
    pub(crate) digest: [u8; 32],
    pub(crate) body: Arc<[u8]>,
}

pub(crate) struct Generation {
    pub(crate) digest: [u8; 32],
    pub(crate) documents: BTreeMap<Name, Document>,
}

impl Name {
    /// 业务作用：在集群接收边界区分入口与业务模块，不把网络名称解析成本机文件路径。
    ///
    /// 参数说明：
    /// - `entry`：传输记录是否是部署入口。
    /// - `name`：传输使用的逻辑配置名。
    ///
    /// 返回：合法且唯一的逻辑名称。入口与模块保留各自命名空间；路径、转义和空名称均拒绝。
    pub(crate) fn new(entry: bool, name: String) -> Result<Self> {
        if entry {
            ensure!(name == "application.yml", "invalid replicated entry name");
            return Ok(Self::Entry);
        }
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                && name.rsplit_once('.').is_some_and(|(prefix, ext)| {
                    !prefix.is_empty() && matches!(ext, "yml" | "yaml")
                })
                && !matches!(name.as_str(), "application.yml" | "application.yaml"),
            "invalid replicated module name"
        );
        Ok(Self::Module(name))
    }

    /// 业务作用：提供跨节点稳定的目录项标识，无需暴露本机真实路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：入口的规范名称或原始模块名。
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Entry => "application.yml",
            Self::Module(name) => name,
        }
    }
}

impl Document {
    /// 业务作用：验证一份集群传输原文的大小、UTF-8 和摘要，未经验证的字节无法进入整组候选。
    ///
    /// 参数说明：
    /// - `body`：已按有界传输接收的完整 YAML。
    /// - `expected`：声明的文档身份；本地受管入口可在冻结时形成。
    ///
    /// 返回：合法文档的精确原字节。超限、非法 UTF-8 或摘要不符时拒绝。
    pub(crate) fn from_bytes(body: Arc<[u8]>, expected: Option<[u8; 32]>) -> Result<Self> {
        ensure!(
            body.len() <= MAX_FINGERPRINT_FILE_BYTES,
            "replicated YAML exceeds byte limit"
        );
        std::str::from_utf8(&body).context("replicated YAML must be UTF-8")?;
        let digest: [u8; 32] = Sha256::digest(&body).into();
        ensure!(
            expected.is_none_or(|expected| expected == digest),
            "replicated YAML digest differs"
        );
        Ok(Self {
            digest,
            body,
        })
    }
}

impl Generation {
    /// 业务作用：冻结当前实际活动的本地 YAML。读取失败或已经出现并发运维编辑时不传播旧授权。
    ///
    /// 参数说明：
    /// - `active`：当前发布者持有的已装配业务快照。
    ///
    /// 返回：已确认同一活动代的入口和模块原字节；远端 Nacos 模式和原文漂移时不提供候选。
    pub(crate) fn capture(active: &GatewaySnapshot) -> Result<Self> {
        ensure!(
            active.named_configuration && active.config_bundle_digest.is_none(),
            "local named configuration required for file replication"
        );
        let entry = active.source_config_path.as_path();
        let fingerprint = active
            .config_fingerprint
            .context("replication needs live file identity")?;
        // 原文拷贝前后均核对完整依赖，避免快照刚发布后磁盘内容又被换成另一候选。
        ensure!(
            config_fingerprint(entry)? == fingerprint,
            "replicated local baseline changed"
        );
        let mut documents = BTreeMap::new();
        documents.insert(
            Name::Entry,
            Document::from_bytes(read(entry)?.into(), None)?,
        );
        for module in active.named_documents.iter() {
            let name = Name::new(false, module.name.clone())?;
            let body = if let Some(content) = &module.content {
                Arc::from(content.as_bytes())
            } else {
                Arc::from(read(&module.path)?)
            };
            let document = Document::from_bytes(body, Some(module.digest))?;
            ensure!(
                documents.insert(name, document).is_none(),
                "duplicate replicated module"
            );
        }
        ensure!(
            config_fingerprint(entry)? == fingerprint,
            "replicated local baseline changed"
        );
        Self::build(documents)
    }

    /// 业务作用：生成可跨挂载、节点身份和记录顺序复验的整组原文摘要。
    ///
    /// 参数说明：
    /// - `documents`：传输边界或本机快照已经验证过的完整原文。
    ///
    /// 返回：包含入口和至少一份模块的合法完整代。重复命名、集合或字节超限会拒绝。
    pub(crate) fn build(documents: BTreeMap<Name, Document>) -> Result<Self> {
        ensure!(
            documents.contains_key(&Name::Entry)
                && (2..=MAX_TRANSFER_DOCUMENTS).contains(&documents.len()),
            "replicated YAML set must include an entry and registered modules"
        );
        let mut digest = Sha256::new();
        digest.update(b"naway.named-file-generation\x00");
        digest.update((documents.len() as u64).to_be_bytes());
        let mut total = 0usize;
        for (name, document) in &documents {
            total = total
                .checked_add(document.body.len())
                .context("replicated YAML size overflow")?;
            ensure!(
                total <= MAX_TRANSFER_BYTES,
                "replicated YAML set exceeds byte limit"
            );
            let bytes = name.as_str().as_bytes();
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
            digest.update((document.body.len() as u64).to_be_bytes());
            digest.update(document.digest);
        }
        Ok(Self {
            digest: digest.finalize().into(),
            documents,
        })
    }
}

/// 业务作用：从本机受管理配置目录读取普通文件，避免路径变化时阻塞或传播意外设备内容。
///
/// 参数说明：
/// - `path`：由已发布入口或具名清单确定的可信本地路径。
///
/// 返回：有界的原始字节；缺失、文件类型或上限无效时拒绝。
fn read(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    crate::io::bounded_io::read_open_file(file, path, MAX_FINGERPRINT_FILE_BYTES, "replicated YAML")
}
