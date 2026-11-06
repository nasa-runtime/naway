//! 材料代只属于受管文件事务；摘要相同不能使已经退休的写入重新获得所有权。

use crate::config::TlsRuntimeCfg;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: usize = 4096;
pub(super) const MANIFEST_RECORD: &str = "ownership.json";

/// 私有元数据绑定完整 pair 和来源计划；对外只能提供不可重用的随机代。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    schema: u32,
    pub(super) generation: String,
    target: [u8; 32],
    certificate: [u8; 32],
    private_key: [u8; 32],
}

impl Record {
    /// 业务作用：用原句柄流式所得摘要复验完整pair，提交前不再分配另一份完整私钥。
    ///
    /// 参数说明：
    /// - `certificate`：完整证书链原文字节的摘要。
    /// - `private_key`：完整私钥原文字节的摘要。
    ///
    /// 返回：两个角色都属于该owner时为真；来源和当前文件身份由调用者分别验证。
    #[cfg(feature = "node-actions")]
    pub(super) fn matches_digests(&self, certificate: &[u8; 32], private_key: &[u8; 32]) -> bool {
        &self.certificate == certificate && &self.private_key == private_key
    }

    /// 业务作用：把本机完整归属绑定原审批的公开材料条件，不以叶证书相同代替完整证书链身份。
    ///
    /// 参数说明：
    /// - `source`：原影响清单中的写入来源摘要。
    /// - `generation`：原审批冻结的不可重用材料代。
    /// - `etag`：原完整证书链的强条件值。
    ///
    /// 返回：三项公开条件与同一完整owner一致才成功；不替代当前私钥和目录复验。
    #[cfg(feature = "node-actions")]
    pub(super) fn require_condition(
        &self,
        source: &str,
        generation: &str,
        etag: &str,
    ) -> Result<()> {
        ensure!(
            source == hex(&self.target)
                && generation == self.generation
                && etag == format!("\"sha256-{}\"", hex(&self.certificate)),
            "material owner differs from original conditions"
        );
        Ok(())
    }

    /// 业务作用：让持久补偿计划证明完整原pair相同而材料代独立，不读取或复制秘密正文。
    ///
    /// 参数说明：
    /// - `other`：同一来源另一方向已验证的完整归属记录。
    ///
    /// 返回：来源和两个材料摘要都相同才为真；不比较随机代，也不授予文件写权。
    #[cfg(feature = "node-actions")]
    pub(super) fn same_material(&self, other: &Self) -> bool {
        self.target == other.target
            && self.certificate == other.certificate
            && self.private_key == other.private_key
    }

    /// 业务作用：为一次新的受管写入生成不可重用的材料代，相同字节也不能复用旧动作所有权。
    ///
    /// 参数说明：
    /// - `target`：固定文件计划的域分隔摘要。
    /// - `certificate`：已验证的完整证书链 PEM。
    /// - `private_key`：与证书匹配的完整私钥 PEM。
    ///
    /// 返回：尚未持久化的新代；随机源失败时拒绝开始材料事务。
    pub(super) fn new(target: [u8; 32], certificate: &[u8], private_key: &[u8]) -> Result<Self> {
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).context("TLS material generation entropy unavailable")?;
        Ok(Self {
            schema: 1,
            generation: hex(&random),
            target,
            certificate: Sha256::digest(certificate).into(),
            private_key: Sha256::digest(private_key).into(),
        })
    }

    /// 业务作用：复验元数据格式及原目标绑定，另一材料位置的记录不能授权当前文件。
    ///
    /// 参数说明：
    /// - `target`：当前配置明确选择的材料来源摘要。
    ///
    /// 返回：格式、随机代和目标均匹配才成功；不将损坏记录降格成未受管材料。
    pub(super) fn validate(&self, target: &[u8; 32]) -> Result<()> {
        ensure!(
            self.schema == 1 && valid_token(&self.generation) && &self.target == target,
            "TLS material generation evidence is invalid"
        );
        Ok(())
    }

    /// 业务作用：证明当前材料仍属于记录中的完整 pair，私钥单独变化也会撤销原写入资格。
    ///
    /// 参数说明：
    /// - `certificate`：同一安装锁内读取的当前证书 PEM。
    /// - `private_key`：写入裁决时的当前私钥；只读目录不提供时仅核对公开证书。
    ///
    /// 返回：提供的全部材料与原记录一致时为真；目录的证书核对不能替代写入时完整 pair 核对。
    pub(super) fn matches(&self, certificate: &[u8], private_key: Option<&[u8]>) -> bool {
        self.certificate == <[u8; 32]>::from(Sha256::digest(certificate))
            && private_key
                .is_none_or(|key| self.private_key == <[u8; 32]>::from(Sha256::digest(key)))
    }

    /// 业务作用：文件事务只接收与原来源及完整候选一致的预分配材料代，不能在下层替换准备身份。
    ///
    /// 参数说明：
    /// - `target`：实际文件事务重新解析的来源摘要。
    /// - `certificate`：本次准备写入的完整证书链。
    /// - `private_key`：本次准备写入的完整私钥。
    ///
    /// 返回：原记录格式、来源与完整 pair 全部匹配时成功；不授予基线覆盖权，也不写入任何文件。
    pub(super) fn require_material(
        &self,
        target: &[u8; 32],
        certificate: &[u8],
        private_key: &[u8],
    ) -> Result<()> {
        self.validate(target)?;
        ensure!(
            self.matches(certificate, Some(private_key)),
            "TLS prepared material differs from its generation"
        );
        Ok(())
    }

    /// 业务作用：沿用文件事务已固定的父目录提交归属，不因再次解析路径而把材料代写入另一目录。
    ///
    /// 参数说明：
    /// - `target`：原事务绑定的唯一归属槽。
    ///
    /// 返回：原目录中的记录及目录项同步成功；失败保留提交未知语义。
    pub(super) fn publish_to(&self, target: &crate::io::file_target::Target) -> Result<()> {
        let bytes = serde_json::to_vec(self).context("encode TLS material generation")?;
        super::io::write(target, &bytes, true)
    }
}

/// 业务作用：约束材料条件令牌为固定长度小写随机身份，不接受路径、通配或弱比较形式。
///
/// 参数说明：
/// - `value`：请求或持久记录中的材料代。
///
/// 返回：仅 64 个小写十六进制字符为真。
pub(crate) fn valid_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// 业务作用：固定材料来源的业务身份，manifest 与双文件计划不能共享条件写入证据。
///
/// 参数说明：
/// - `tls`：声明证书文件或 manifest 位置的运行计划。
///
/// 返回：解析实际父目录后得到域分隔和长度分帧的 SHA-256；不读取材料内容，目录证据错误时失败。
pub(super) fn target(tls: &TlsRuntimeCfg) -> Result<[u8; 32]> {
    match &tls.keypair_manifest_file {
        Some(path) => manifest_target(path),
        None => Ok(digest_paths(
            b"legacy",
            &[
                &identity_path(&tls.cert_file)?,
                &identity_path(&tls.key_file)?,
            ],
        )),
    }
}

/// 业务作用：让不可变目录和当前 manifest 使用同一来源身份，切换目录不改变目标归属。
///
/// 参数说明：
/// - `path`：配置固定的 manifest 路径。
///
/// 返回：仅绑定 manifest 位置的材料目标摘要，不包含其可变内容。
pub(super) fn manifest_target(path: &Path) -> Result<[u8; 32]> {
    Ok(digest_paths(b"manifest", &[&identity_path(path)?]))
}

/// 业务作用：为双文件目标定位唯一材料代记录，多个逻辑监听共享同一 pair 时共享归属。
///
/// 参数说明：
/// - `tls`：无 manifest 的规范化双文件计划。
///
/// 返回：证书同目录下的私有元数据路径；非法来源拒绝定位。
pub(super) fn legacy_path(tls: &TlsRuntimeCfg) -> Result<PathBuf> {
    ensure!(
        tls.keypair_manifest_file.is_none(),
        "TLS source is not a legacy pair"
    );
    legacy_path_for_source(&tls.cert_file, &target(tls)?)
}

/// 业务作用：复用已经固定的来源摘要定位双文件归属，持久结构校验不重新访问路径或目录。
///
/// 参数说明：
/// - `certificate`：该来源明确的证书位置。
/// - `source`：同次原位置计算的完整来源摘要。
///
/// 返回：证书同目录的唯一归属槽；无父目录时拒绝。
pub(super) fn legacy_path_for_source(certificate: &Path, source: &[u8; 32]) -> Result<PathBuf> {
    let parent = certificate
        .parent()
        .context("TLS certificate has no parent")?;
    Ok(parent.join(format!(".naway-keypair-generation-{}.json", hex(source))))
}

/// 业务作用：从确定位置读取完整有界归属证据，损坏或跨目标记录不能变成无条件写入资格。
///
/// 参数说明：
/// - `path`：受管计划确定的元数据位置。
/// - `target`：本次访问允许的唯一材料来源。
///
/// 返回：缺失为未受管，存在且完整合法时返回原字节及记录；错误阻断材料写入。
pub(super) fn read(path: &Path, target: &[u8; 32]) -> Result<Option<(Vec<u8>, Record)>> {
    let Some(bytes) = crate::io::bounded_io::read_optional_file(
        path,
        MAX_RECORD_BYTES,
        "TLS material generation",
    )?
    else {
        return Ok(None);
    };
    let record = decode(&bytes, target)?;
    Ok(Some((bytes, record)))
}

/// 业务作用：让路径读取与固定句柄读取共用完整归属格式门，不重新打开另一来源补充owner。
///
/// 参数说明：
/// - `bytes`：已由调用者按归属记录上限读取的原文字节。
/// - `target`：此次读取允许的唯一材料来源摘要。
///
/// 返回：完整合法且属于原来源的记录；未知字段、容量或身份不符均拒绝。
pub(super) fn decode(bytes: &[u8], target: &[u8; 32]) -> Result<Record> {
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "TLS generation record exceeds limit"
    );
    let record: Record = serde_json::from_slice(bytes).context("parse TLS material generation")?;
    record.validate(target)?;
    Ok(record)
}

/// 业务作用：只从当前活动来源读取材料代，旧目录和 seed 文件不能冒充已激活的 manifest 材料。
///
/// 参数说明：
/// - `tls`：已完成旧事务恢复的当前文件计划。
/// - `certificate`：安装锁内选定的公开证书原文。
/// - `private_key`：条件写入时必须提供的当前私钥；只读投影可省略。
///
/// 返回：与所给材料一致的随机代或未受管；损坏证据返回错误，调用方不得据此安装。
pub(super) fn current(
    tls: &TlsRuntimeCfg,
    certificate: &[u8],
    private_key: Option<&[u8]>,
) -> Result<Option<String>> {
    super::capture::Files::capture(tls)?.current(certificate, private_key)
}

/// 业务作用：从加载时的完整 pair 取得不可变归属，不把证书有效或叶身份相同解释为受管安装成功。
///
/// 参数说明：
/// - `record`：从本次 pair 已选来源取得的归属，不允许再次解析活动指针取得另一目录的记录。
/// - `certificate`：本次将交给签名身份解析器的完整证书字节。
/// - `private_key`：同次读取的完整私钥字节，只参与原生校验，不进入公开事实。
///
/// 返回：原代和完整 pair 一致时共享受管证据；无记录与不匹配分别返回明确状态。
pub(super) fn loaded(
    record: Option<Record>,
    certificate: &[u8],
    private_key: &[u8],
) -> crate::tls::material::MaterialProvenance {
    use crate::tls::material::{ManagedMaterial, MaterialProvenance};
    // 合法pair不等于受管pair；来源没有记录时只报告未受管，不能从另一活动来源补齐材料代。
    let Some(record) = record else {
        return MaterialProvenance::Unmanaged;
    };
    // 记录仍存在不代表它拥有当前字节；任何一个槽位改变都撤销完整 pair 的安装证明。
    if !record.matches(certificate, Some(private_key)) {
        return MaterialProvenance::Unproven;
    }
    MaterialProvenance::Managed(std::sync::Arc::new(ManagedMaterial {
        source_id: record.target,
        generation: record.generation,
    }))
}

/// 业务作用：固定实际父目录及文件槽位，目录别名和点路径不能形成两套受管材料所有权。
///
/// 参数说明：
/// - `path`：当前文件计划的目标路径，最终文件可尚不存在。
///
/// 返回：解析已有父目录别名并保留未创建后缀后的绝对路径；权限或目录证据错误拒绝写入。
pub(super) fn identity_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let filename = absolute
        .file_name()
        .context("TLS material file name missing")?;
    let mut parent = absolute.parent().context("TLS material parent missing")?;
    let mut missing = Vec::new();
    let mut canonical = loop {
        match std::fs::canonicalize(parent) {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    parent
                        .file_name()
                        .context("TLS material ancestor missing")?,
                );
                parent = parent.parent().context("TLS material ancestor missing")?;
            }
            Err(error) => return Err(error).context("resolve TLS material parent"),
        }
    };
    for suffix in missing.into_iter().rev() {
        canonical.push(suffix);
    }
    canonical.push(filename);
    Ok(canonical)
}

/// 业务作用：为审批冻结声明本身，路径后来发生别名或文件系统变化不能悄然改写已批准的意图。
///
/// 参数说明：
/// - `tls`：原提交时的文件来源计划。
///
/// 返回：不读取文件系统的声明摘要；实际安装另行证明物理目标身份。
pub(super) fn declared_target(tls: &TlsRuntimeCfg) -> [u8; 32] {
    match &tls.keypair_manifest_file {
        Some(path) => digest_paths(b"manifest", &[path]),
        None => digest_paths(b"legacy", &[&tls.cert_file, &tls.key_file]),
    }
}

/// 业务作用：为来源摘要保持字段边界，不让不同路径分段或材料模式产生相同输入。
///
/// 参数说明：
/// - `kind`：固定来源类别。
/// - `paths`：按业务角色排列的规范化路径。
///
/// 返回：单次增量 SHA-256，不复制路径字节。
pub(super) fn digest_paths(kind: &[u8], paths: &[&Path]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"naway-tls-material-target\0");
    digest.update(kind);
    for path in paths {
        let bytes = path.as_os_str().as_encoded_bytes();
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

/// 业务作用：编码固定随机身份或摘要，输出不携带秘密材料。
///
/// 参数说明：
/// - `bytes`：随机身份或材料来源摘要。
///
/// 返回：规范小写十六进制文本。
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("write hexadecimal identity");
    }
    text
}
