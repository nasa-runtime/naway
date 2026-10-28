//! 三份实际base原文的强摘要；不代替profile、环境、依赖或当前授权验证。

use super::{candidate, GatewaySnapshot};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Read, path::Path};

const LIMIT: u64 = 32 * 1024 * 1024;

/// 单份原文的字节身份，不保存插值后的秘密或完整正文副本。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Document {
    length: u64,
    sha256: [u8; 32],
    utf8: bool,
}

/// 具有固定文档角色和明确边界的原文集合身份。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    documents: [Document; 3],
    sha256: [u8; 32],
    bundle_sha256: [u8; 32],
}

/// 编译前冻结的物理来源和真实声明，候选工作区不能替代部署目标。
pub(super) struct Prepared {
    physical: candidate::Paths,
    declared: candidate::Paths,
    identity: Identity,
}

impl Document {
    /// 业务作用：在主配置解析前冻结原始文件身份，后续不能用新字节冒充已解析输入。
    ///
    /// 参数说明：
    /// - `path`：本次真正读取的主base路径，允许普通只读配置链接。
    ///
    /// 返回：读取至EOF且长度稳定的有界原文身份；超限、特殊文件或I/O异常拒绝。
    pub(super) fn read(path: &Path) -> Result<Self> {
        read_document(path, None)
    }
}

impl Prepared {
    /// 业务作用：冻结完整候选的三个原文来源，并将主base绑定到解析之前的同一字节身份。
    ///
    /// 参数说明：
    /// - `declared`：已合并主配置声明的真实部署路径。
    /// - `documents`：本次候选的物理base替换，仅用于读取。
    /// - `main`：解析主配置之前取得的原文身份。
    ///
    /// 返回：可供编译结束复验的有限证据；主base已变或任一规则不可读取时拒绝。
    pub(super) fn new(
        declared: candidate::Paths,
        documents: candidate::Documents<'_>,
        main: Document,
    ) -> Result<Self> {
        let physical = candidate::Paths {
            gateway: documents.gateway.to_path_buf(),
            guard: documents
                .sidecars
                .map_or_else(|| declared.guard.clone(), |paths| paths.guard.to_path_buf()),
            sentinel: documents.sidecars.map_or_else(
                || declared.sentinel.clone(),
                |paths| paths.sentinel.to_path_buf(),
            ),
        };
        let identity = Identity::read(&physical)?;
        // 原文身份必须覆盖主解析的前后边界，不能仅在构建完成后对当时文件补做摘要。
        ensure!(
            identity.documents[0] == main,
            "gateway base changed during parsing"
        );
        Ok(Self {
            physical,
            declared,
            identity,
        })
    }

    /// 业务作用：完整语义构建后复验原文与目标，使摘要和候选同代发布而不另设配置发布者。
    ///
    /// 参数说明：
    /// - `snapshot`：已经编译完成但尚未开放资源的候选。
    ///
    /// 返回：绑定本次三份原文身份的候选；编译期间原文或目标变化拒绝，不发布部分事实。
    pub(super) fn finish(self, mut snapshot: GatewaySnapshot) -> Result<GatewaySnapshot> {
        ensure!(
            snapshot.document_paths == self.declared,
            "document targets changed during compilation"
        );
        ensure!(
            Identity::read(&self.physical)? == self.identity,
            "document bases changed during compilation"
        );
        // Nacos保留原来的原文字节长度分帧算法与启用条件，不能把其它来源伪装成bundle收敛。
        if snapshot.config_source.nacos.enabled
            && !snapshot
                .config_source
                .nacos
                .bundle_data_id
                .trim()
                .is_empty()
        {
            ensure!(
                self.identity.documents.iter().all(|document| document.utf8),
                "configuration bundle bases must be UTF-8"
            );
            snapshot.config_bundle_digest = Some(self.identity.bundle_hex());
        }
        snapshot.document_identity = Some(self.identity);
        Ok(snapshot)
    }
}

impl Identity {
    /// 业务作用：在低频范围校验前把读取的主文档绑定到实际活动原文，外部文件不能成为扩大委派范围的假基线。
    ///
    /// 参数说明：
    /// - `bytes`：已经按文档预算读取的主 base 原字节。
    ///
    /// 返回：长度与原始 SHA 都一致才为真；不执行环境求值或复制完整正文。
    #[cfg(feature = "node-actions")]
    pub(crate) fn matches_gateway(&self, bytes: &[u8]) -> bool {
        self.documents[0].length == bytes.len() as u64
            && self.documents[0].sha256 == <[u8; 32]>::from(Sha256::digest(bytes))
    }
    /// 业务作用：将候选构建时冻结的原文绑定到持久文件决定，不依赖展示指纹或重新序列化。
    ///
    /// 参数说明：
    /// - `documents`：按主文档、guard、Sentinel排列的完整长度与SHA-256。
    ///
    /// 返回：三个角色的原文身份全部一致时为真，不授予文件覆盖或配置发布权限。
    #[cfg(feature = "node-journal")]
    pub(crate) fn matches_documents(&self, documents: [(u64, [u8; 32]); 3]) -> bool {
        self.documents
            .iter()
            .zip(documents)
            .all(|(actual, (length, sha256))| actual.length == length && actual.sha256 == sha256)
    }

    /// 业务作用：提供已随活动候选发布的三base原文身份，供节点基线绑定而不再次读取全文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定角色集合的SHA-256引用；不包含profile、外部依赖或执行权限声明。
    #[cfg(feature = "node-journal")]
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// 业务作用：按固定角色流式计算单文档、集合和既有bundle摘要，避免为哈希保留完整正文。
    ///
    /// 参数说明：
    /// - `paths`：本次实际读取的三个base来源。
    ///
    /// 返回：完整有界原文集合的固定长度身份；任一文件失败不提供部分结果。
    fn read(paths: &candidate::Paths) -> Result<Self> {
        let mut bundle = Sha256::new();
        let documents = [
            read_document(&paths.gateway, Some(&mut bundle))?,
            read_document(&paths.guard, Some(&mut bundle))?,
            read_document(&paths.sentinel, Some(&mut bundle))?,
        ];
        let mut digest = Sha256::new();
        digest.update(b"naway-source-documents\0");
        for (role, document) in ["gateway", "interface-guard", "sentinel-rules"]
            .into_iter()
            .zip(documents)
        {
            digest.update((role.len() as u32).to_be_bytes());
            digest.update(role.as_bytes());
            digest.update(document.length.to_be_bytes());
            digest.update(document.sha256);
        }
        Ok(Self {
            documents,
            sha256: digest.finalize().into(),
            bundle_sha256: bundle.finalize().into(),
        })
    }

    /// 业务作用：保持Nacos既有bundle摘要的固定小写表示，不改变远端发布和收敛合同。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：由实际三份原文字节生成的64字符SHA-256。
    fn bundle_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(64);
        for byte in self.bundle_sha256 {
            write!(&mut text, "{byte:02x}").expect("writing to a string cannot fail");
        }
        text
    }
}

/// 业务作用：以固定缓冲读取普通配置文件，长度变化或特殊文件不能提供稳定正文证据。
///
/// 参数说明：
/// - `path`：实际base来源；正常只读符号链接保持支持。
/// - `bundle`：需要同时更新的原bundle长度分帧摘要，主解析预检时为空。
///
/// 返回：完整EOF与初始长度一致时返回单文档身份；任一预算、类型或读取错误拒绝。
fn read_document(path: &Path, mut bundle: Option<&mut Sha256>) -> Result<Document> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .context("cannot open configuration base identity")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= LIMIT,
        "configuration base identity requires a bounded ordinary file"
    );
    let length = metadata.len();
    if let Some(bundle) = &mut bundle {
        bundle.update(length.to_be_bytes());
    }
    let mut digest = Sha256::new();
    let mut utf8 = Utf8::default();
    let mut buffer = [0; 16 * 1024];
    let mut read = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        ensure!(read <= length, "configuration base grew while hashing");
        digest.update(&buffer[..count]);
        utf8.accept(&buffer[..count]);
        if let Some(bundle) = &mut bundle {
            bundle.update(&buffer[..count]);
        }
    }
    ensure!(
        read == length && file.metadata()?.len() == length,
        "configuration base length changed while hashing"
    );
    Ok(Document {
        length,
        sha256: digest.finalize().into(),
        utf8: utf8.valid(),
    })
}

/// 最多保留一个跨缓冲UTF-8字符，原文摘要始终使用原始字节。
#[derive(Default)]
struct Utf8 {
    pending: [u8; 4],
    length: usize,
    invalid: bool,
}

impl Utf8 {
    /// 业务作用：以常量空间确认跨块UTF-8边界，保留bundle原有的严格原文编码条件。
    ///
    /// 参数说明：
    /// - `bytes`：同一文件顺序读取的下一块原文字节。
    ///
    /// 返回：更新完整性状态，不改写原文；非法编码保持拒绝状态，未完成字符最多保留三个字节。
    fn accept(&mut self, mut bytes: &[u8]) {
        if self.invalid {
            return;
        }
        if self.length > 0 {
            let expected = match self.pending[0] {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                _ => 4,
            };
            let count = (expected - self.length).min(bytes.len());
            self.pending[self.length..self.length + count].copy_from_slice(&bytes[..count]);
            self.length += count;
            bytes = &bytes[count..];
            if self.length < expected {
                return;
            }
            if std::str::from_utf8(&self.pending[..expected]).is_err() {
                self.invalid = true;
                return;
            }
            self.length = 0;
        }
        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                self.invalid = true;
            } else {
                let trailing = &bytes[error.valid_up_to()..];
                self.pending[..trailing.len()].copy_from_slice(trailing);
                self.length = trailing.len();
            }
        }
    }

    /// 业务作用：EOF时确认没有非法编码或残缺字符，不能把合法前缀当成完整bundle正文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部字节是完整UTF-8时为true，否则为false。
    fn valid(&self) -> bool {
        !self.invalid && self.length == 0
    }
}
