//! 已决定材料动作以原本机配置证据恢复，不能依赖可能因半份TLS而尚无法构建的监听快照。

use crate::{
    config::{candidate::dependencies::Frozen, GatewaySnapshot},
    control::{
        documents::{Fingerprint, Target},
        material::node::Intent,
    },
    io::file_target::{same_file, Location},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 一个原配置角色的声明、原目录能力与完整原文身份，不保存配置秘密正文。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    declared: PathBuf,
    location: Location,
    fingerprint: Fingerprint,
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// 原三文档与非base依赖的恢复证明，可在正常TLS快照尚不能构建时核验原配置。
pub(crate) struct Configuration {
    documents: [Document; 3],
    dependencies: Frozen,
}

impl Configuration {
    /// 业务作用：把节点材料准备绑定到实际发布的完整配置和原文位置，后续恢复不重新选择来源。
    ///
    /// 参数说明：
    /// - `snapshot`：调用者持有发布权的原完整配置。
    /// - `intent`：原节点基线及材料审批意图。
    ///
    /// 返回：三份base和原非base依赖的有限证据；语义基线、原文或目录不符拒绝，不写入。
    pub(crate) fn capture(snapshot: &GatewaySnapshot, intent: &Intent) -> Result<Self> {
        ensure!(
            snapshot.version == intent.base_version
                && snapshot.config_fingerprint == Some(intent.base_fingerprint),
            "material configuration baseline differs"
        );
        let paths = &snapshot.document_paths;
        let documents = [
            Document::capture(&paths.gateway)?,
            Document::capture(&paths.guard)?,
            Document::capture(&paths.sentinel)?,
        ];
        ensure!(
            snapshot
                .document_identity
                .as_ref()
                .is_some_and(|identity| identity.matches_documents(
                    documents
                        .each_ref()
                        .map(|value| (value.fingerprint.length, value.fingerprint.sha256))
                )),
            "material configuration documents differ from snapshot"
        );
        let proof = Self {
            documents,
            dependencies: Frozen::capture(snapshot)?,
        };
        proof.require_current(&paths.gateway, intent)?;
        Ok(proof)
    }

    /// 业务作用：限定恢复证据的完整角色和有界位置，格式合法不等于获得当前文件写权。
    ///
    /// 参数说明：
    /// - `intent`：原节点基线，三份原文角色摘要必须与其精确对应。
    ///
    /// 返回：三份原文角色和原依赖列表完整合法时成功，不访问当前磁盘内容。
    pub(crate) fn validate(&self, intent: &Intent) -> Result<()> {
        for document in &self.documents {
            document.validate()?;
        }
        for (index, document) in self.documents.iter().enumerate() {
            ensure!(
                !self.documents[..index]
                    .iter()
                    .any(|prior| prior.location.path == document.location.path),
                "material configuration roles overlap"
            );
        }
        let digest = crate::config::source_identity::documents_digest(
            self.documents
                .each_ref()
                .map(|document| (document.fingerprint.length, document.fingerprint.sha256)),
        );
        let expected = intent.baseline.documents_sha256.as_bytes();
        ensure!(
            expected.len() == 64
                && digest
                    .iter()
                    .zip(expected.chunks_exact(2))
                    .all(
                        |(byte, text)| text[0] == b"0123456789abcdef"[usize::from(byte >> 4)]
                            && text[1] == b"0123456789abcdef"[usize::from(byte & 15)]
                    ),
            "material original document set differs from node baseline"
        );
        self.dependencies.validate()
    }

    /// 业务作用：在任何已决定文件恢复之前复验启动主文件、三份原文和全部原依赖，配置漂移保持保护。
    ///
    /// 参数说明：
    /// - `main`：本进程实际启动的主配置位置，不取网络路径。
    /// - `intent`：原持久动作的节点基线。
    ///
    /// 返回：全部原证据仍成立时成功；任何缺失、目录替换、别名转向或内容变化拒绝恢复。
    pub(crate) fn require_current(&self, main: &Path, intent: &Intent) -> Result<()> {
        self.validate(intent)?;
        ensure!(
            Location::capture(&Target::open(main)?)? == self.documents[0].location,
            "material recovery main configuration differs"
        );
        // 先验证外部依赖再复验三个base，早先的原文不能在依赖读取期间被新的部署替代。
        self.dependencies.require_current()?;
        for document in &self.documents {
            document.require_current()?;
        }
        Ok(())
    }

    /// 业务作用：将正常构建后的语义快照重新绑定原文件证据，恢复完成不允许另一配置借用旧材料责任。
    ///
    /// 参数说明：
    /// - `snapshot`：文件方向补齐后本进程完整构建的配置。
    /// - `intent`：原持久动作的语义基线，不要求重启复用旧内存版本号。
    ///
    /// 返回：语义指纹和全部原文角色一致时成功；不将快照构建成功当作实际监听已安装。
    pub(crate) fn require_snapshot(
        &self,
        snapshot: &GatewaySnapshot,
        intent: &Intent,
    ) -> Result<()> {
        ensure!(
            snapshot.config_fingerprint == Some(intent.base_fingerprint),
            "material recovery semantic configuration differs"
        );
        let paths = &snapshot.document_paths;
        for (document, path) in
            self.documents
                .iter()
                .zip([&paths.gateway, &paths.guard, &paths.sentinel])
        {
            ensure!(
                Location::capture(&Target::open(path)?)? == document.location,
                "material recovery configuration roles differ"
            );
        }
        ensure!(
            snapshot
                .document_identity
                .as_ref()
                .is_some_and(|identity| identity.matches_documents(
                    self.documents
                        .each_ref()
                        .map(|value| (value.fingerprint.length, value.fingerprint.sha256))
                )),
            "material recovery snapshot documents differ"
        );
        self.require_current(&paths.gateway, intent)
    }
}

impl Document {
    /// 业务作用：用原打开目录和文件流式捕获base身份，配置秘密不被复制进持久元数据。
    ///
    /// 参数说明：
    /// - `path`：本机原配置给出的真实角色位置。
    ///
    /// 返回：原声明、父目录身份和完整原文摘要；缺失、链接、替换或超量拒绝。
    fn capture(path: &Path) -> Result<Self> {
        let declared = std::path::absolute(path)?;
        let target = Target::open(&declared)?;
        let document = Self {
            declared,
            location: Location::capture(&target)?,
            fingerprint: read(&target)?,
        };
        document.validate()?;
        Ok(document)
    }

    /// 业务作用：保持声明路径的真实别名语义，同时限制持久位置和正文预算，恢复不能接受任意长输入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原声明与规范真实位置均有界且长度合法时成功，不证明当前文件存在。
    fn validate(&self) -> Result<()> {
        ensure!(
            self.declared.is_absolute()
                && self
                    .declared
                    .to_str()
                    .is_some_and(|text| text.len() <= 4096 && !text.as_bytes().contains(&0))
                && self.fingerprint.length <= crate::config::document::MAX_DOCUMENT_BYTES as u64,
            "material configuration document format differs"
        );
        crate::io::file_target::validate_path(&self.location.path)
    }

    /// 业务作用：复验原声明仍选择原父目录及完整原文，同名后来目录不能继承已决定恢复资格。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：声明、位置和原文字节全部一致时成功；读取异常保留原责任。
    fn require_current(&self) -> Result<()> {
        let target = self.location.open()?;
        ensure!(
            Location::capture(&Target::open(&self.declared)?)? == self.location
                && read(&target)? == self.fingerprint,
            "material configuration document changed"
        );
        target.require_current()
    }
}

/// 业务作用：从同一普通文件句柄完整读取原文摘要，读取期间替换不能混合成可恢复证据。
///
/// 参数说明：
/// - `target`：原位置的固定父目录能力。
///
/// 返回：完整字节身份；长度漂移、替换、目录变化或读取失败拒绝。
fn read(target: &Target) -> Result<Fingerprint> {
    let (mut file, before) = target
        .file()?
        .context("material configuration document absent")?;
    let fingerprint = Fingerprint::read(&mut file)?;
    let original = file.metadata()?;
    let current = target.directory.symlink_metadata(&target.name)?;
    ensure!(
        fingerprint.length == before.len()
            && original.len() == before.len()
            && current.len() == before.len()
            && same_file(&current, &original),
        "material configuration document changed while reading"
    );
    target.require_current()?;
    Ok(fingerprint)
}
