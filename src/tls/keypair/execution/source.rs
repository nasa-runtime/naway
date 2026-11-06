//! 本机来源计划保留原目录及完整pair归属，网络命令不能提供文件路径或指定材料代。

use super::super::{generation, legacy, source::held};
use crate::{
    config::TlsRuntimeCfg,
    control::material::backup::Backup,
    io::file_target::{Location, Target},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

/// 从本机TLS声明捕获的固定来源位置，不接受网络输入提供的文件路径。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::tls::keypair) struct Declaration {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub manifest: Option<PathBuf>,
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
/// legacy或manifest的原角色目录关系，恢复不能将同名后来目录解释成原文件能力。
pub(in crate::tls::keypair) enum Binding {
    Legacy {
        certificate: Location,
        private_key: Location,
        owner: Location,
        transaction: Location,
    },
    Manifest {
        pointer: Location,
        root: Location,
        certificate: Location,
        private_key: Location,
        owner: Location,
        pointer_sha256: [u8; 32],
    },
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// 单一物理来源的原归属、预分配目标归属与唯一备份预算，全部共享别名沿用同一计划。
pub(crate) struct Plan {
    pub(in crate::tls::keypair) declared: Declaration,
    pub(in crate::tls::keypair) binding: Binding,
    pub(in crate::tls::keypair) original: generation::Record,
    pub(in crate::tls::keypair) next: generation::Record,
    pub(in crate::tls::keypair) backup_bytes: u32,
    pub(in crate::tls::keypair) backup_sha256: [u8; 32],
}

/// 一次批次恢复只借用预分配方向，不改写原准备计划或深复制来源树。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Goal {
    pub(in crate::tls::keypair) owner: generation::Record,
}

impl Declaration {
    /// 业务作用：只保留本机文件来源声明，TLS策略留在原配置证据中，不能由网络覆盖。
    ///
    /// 参数说明：
    /// - `tls`：原已授权的文件来源计划。
    ///
    /// 返回：绝对声明位置，保留父目录别名语义；外部身份或ACME归属拒绝。
    pub(in crate::tls::keypair) fn capture(tls: &TlsRuntimeCfg) -> Result<Self> {
        ensure!(
            tls.in_memory.is_none()
                && tls.spire.is_none()
                && tls.private_key_provider.is_none()
                && tls.acme.is_none(),
            "material execution requires a manual file source"
        );
        let declared = Self {
            certificate: std::path::absolute(&tls.cert_file)?,
            private_key: std::path::absolute(&tls.key_file)?,
            manifest: tls
                .keypair_manifest_file
                .as_deref()
                .map(std::path::absolute)
                .transpose()?,
        };
        declared.validate()?;
        Ok(declared)
    }

    /// 业务作用：限定持久声明路径大小与编码，不能将损坏元数据解释为新的外部来源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有角色均为有界绝对UTF-8位置时成功，不读取或创建文件。
    fn validate(&self) -> Result<()> {
        for path in [&self.certificate, &self.private_key]
            .into_iter()
            .chain(self.manifest.iter())
        {
            ensure!(
                path.is_absolute()
                    && path.file_name().is_some()
                    && path
                        .to_str()
                        .is_some_and(|text| text.len() <= 4096 && !text.as_bytes().contains(&0)),
                "material execution declaration differs"
            );
        }
        Ok(())
    }

    /// 业务作用：仅为已提交文件方向恢复原底层事务的路径输入，不构建新监听策略或对外授予安装权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无外部身份、ACME和监听策略的文件计划；使用前必须验证原配置与目录证据。
    pub(in crate::tls::keypair) fn files(&self) -> TlsRuntimeCfg {
        TlsRuntimeCfg {
            listen: String::new(),
            cert_file: self.certificate.clone(),
            key_file: self.private_key.clone(),
            private_key_provider: None,
            spire: None,
            keypair_manifest_file: self.manifest.clone(),
            certs: Vec::new(),
            client_auth: None,
            ocsp_stapling: None,
            session_tickets: None,
            acme: None,
            in_memory: None,
        }
    }
}

impl Plan {
    /// 业务作用：把本机来源计划绑定原审批组，合法本地owner不能冒充另一个原逻辑来源。
    ///
    /// 参数说明：
    /// - `condition`：完整原影响批次中同顺序的来源组。
    ///
    /// 返回：原来源、材料代和完整证书链条件同时一致时成功；不读取磁盘。
    pub(crate) fn require_condition(
        &self,
        condition: &super::super::conditions::Group,
    ) -> Result<()> {
        self.validate()?;
        self.original.require_condition(
            &condition.source_id,
            condition
                .material_generation
                .as_deref()
                .context("material original generation absent")?,
            &condition.certificate_etag,
        )
    }

    /// 业务作用：对持久来源计划执行纯结构校验，原归属和预分配新代必须绑定同一文件来源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：位置关系、完整owner和备份预算合法时成功；不代表当前磁盘仍属于该计划。
    pub(crate) fn validate(&self) -> Result<()> {
        self.declared.validate()?;
        let source = self.binding.validate()?;
        self.original.validate(&source)?;
        self.next.validate(&source)?;
        ensure!(
            self.original.generation != self.next.generation
                && (18..=crate::control::material::backup::FRAME_LIMIT as u32)
                    .contains(&self.backup_bytes),
            "material source generations or budget differ"
        );
        let manifest = match &self.binding {
            Binding::Legacy {
                ..
            } => false,
            Binding::Manifest {
                ..
            } => true,
        };
        ensure!(
            manifest == self.declared.manifest.is_some(),
            "material source mode differs"
        );
        Ok(())
    }

    /// 业务作用：将唯一原pair备份绑定原owner和完整帧摘要，损坏秘密槽不能成为补偿来源。
    ///
    /// 参数说明：
    /// - `backup`：原固定槽完整读取并清零管理的帧。
    ///
    /// 返回：长度、完整帧摘要、原来源和完整pair归属同时一致才成功。
    pub(crate) fn require_backup(&self, backup: &Backup) -> Result<()> {
        self.validate()?;
        ensure!(
            backup.bytes().len() == self.backup_bytes as usize
                && <[u8; 32]>::from(Sha256::digest(backup.bytes())) == self.backup_sha256,
            "material original backup differs"
        );
        let (certificate, private_key) = backup.parts()?;
        self.original
            .require_material(&self.binding.validate()?, certificate, private_key)
    }

    /// 业务作用：原pair恢复使用独立新材料代，不能让旧字节重现后重新授予已退休动作写权。
    ///
    /// 参数说明：
    /// - `backup`：已经通过原秘密槽完整性门的备份。
    ///
    /// 返回：尚未形成任何文件决定的新补偿归属；随机源或原备份不符拒绝。
    pub(crate) fn compensation(&self, backup: &Backup) -> Result<Goal> {
        self.require_backup(backup)?;
        let (certificate, private_key) = backup.parts()?;
        Ok(Goal {
            owner: generation::Record::new(self.binding.validate()?, certificate, private_key)?,
        })
    }

    /// 业务作用：在原文件副作用之前复验当前部署的声明及固定目录，不能向替换过的目录继续写入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有仍需写入的原目录和原声明映射一致时成功；不证明活动pair属于所选方向。
    pub(in crate::tls::keypair) fn require_locations(&self) -> Result<()> {
        self.validate()?;
        match &self.binding {
            Binding::Legacy {
                certificate,
                private_key,
                owner,
                transaction,
            } => {
                for location in [certificate, private_key, owner, transaction] {
                    location.open()?;
                }
                ensure!(
                    Location::capture(&Target::open(&self.declared.certificate)?)? == *certificate
                        && Location::capture(&Target::open(&self.declared.private_key)?)?
                            == *private_key,
                    "material legacy declaration changed"
                );
            }
            Binding::Manifest {
                pointer,
                root,
                ..
            } => {
                pointer.open()?;
                root.open()?;
                ensure!(
                    Location::capture(&Target::open(
                        self.declared
                            .manifest
                            .as_deref()
                            .context("material manifest declaration absent")?
                    )?)? == *pointer,
                    "material manifest declaration changed"
                );
            }
        }
        Ok(())
    }

    /// 业务作用：确认尚未执行的完整旧边界，原owner相同也不能掩盖指针或原材料目录被替换。
    ///
    /// 参数说明：
    /// - `captured`：当前同一安装锁内固定的完整来源句柄。
    /// - `backup`：从这些句柄读取的唯一当前pair帧。
    ///
    /// 返回：当前来源和完整pair仍为原准备基线时成功；第三方材料、目录或指针变化拒绝。
    pub(in crate::tls::keypair) fn require_original(
        &self,
        captured: &held::Source<'_>,
        backup: &Backup,
    ) -> Result<()> {
        self.require_locations()?;
        self.require_backup(backup)?;
        captured.require_owner(&self.original)?;
        match &self.binding {
            Binding::Legacy {
                ..
            } => {}
            Binding::Manifest {
                pointer,
                certificate,
                private_key,
                owner,
                pointer_sha256,
                ..
            } => {
                for location in [certificate, private_key, owner] {
                    location.open()?;
                }
                let bytes = super::super::io::read(&pointer.open()?, 64 * 1024)?
                    .context("material original pointer absent")?;
                ensure!(
                    <[u8; 32]>::from(Sha256::digest(&bytes)) == *pointer_sha256,
                    "material original pointer changed"
                );
            }
        }
        captured.require_pair()
    }

    /// 业务作用：让状态与收据借用原预分配执行代，不重建候选或复制完整来源计划。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：准备时冻结的新材料代。
    pub(crate) fn generation(&self) -> &str {
        &self.next.generation
    }

    /// 业务作用：在整批秘密预算检查中读取原来源额度，共享别名只计一次备份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原完整pair帧长度，不读取秘密文件。
    pub(crate) fn backup_bytes(&self) -> u32 {
        self.backup_bytes
    }

    /// 业务作用：让秘密槽完整性检查直接复用原备份摘要，清理不再读取解析或重组整份私钥。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原完整备份帧的固定摘要借用，仅用于本机私有存储校验。
    pub(crate) fn backup_sha256(&self) -> &[u8; 32] {
        &self.backup_sha256
    }
}

impl Binding {
    /// 业务作用：从固定角色关系重建来源摘要，持久路径不能把owner或事务转移到另一位置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原来源的域分隔摘要；角色重叠、目录关系或固定名字不符拒绝。
    pub(super) fn validate(&self) -> Result<[u8; 32]> {
        match self {
            Self::Legacy {
                certificate,
                private_key,
                owner,
                transaction,
            } => {
                for location in [certificate, private_key, owner, transaction] {
                    crate::io::file_target::validate_path(&location.path)?;
                }
                let source =
                    generation::digest_paths(b"legacy", &[&certificate.path, &private_key.path]);
                ensure!(
                    certificate.path != private_key.path
                        && certificate.same_directory(owner)
                        && certificate.same_directory(transaction)
                        && owner.path
                            == generation::legacy_path_for_source(&certificate.path, &source)?
                        && transaction.path
                            == legacy::legacy_directory_for_paths(
                                &certificate.path,
                                &private_key.path
                            )?,
                    "material legacy roles differ"
                );
                Ok(source)
            }
            Self::Manifest {
                pointer,
                root,
                certificate,
                private_key,
                owner,
                ..
            } => {
                for location in [pointer, root, certificate, private_key, owner] {
                    crate::io::file_target::validate_path(&location.path)?;
                }
                let parent = pointer
                    .path
                    .parent()
                    .context("material manifest parent absent")?;
                let directory = certificate
                    .path
                    .parent()
                    .context("material original directory absent")?;
                ensure!(
                    root.path == parent.join(".gateway-keypairs").join(".naway-binding")
                        && directory.parent() == root.path.parent()
                        && certificate.path.file_name() == Some(std::ffi::OsStr::new("cert.pem"))
                        && certificate.same_directory(private_key)
                        && certificate.same_directory(owner)
                        && private_key.path == directory.join("key.pem")
                        && owner.path == directory.join(generation::MANIFEST_RECORD),
                    "material manifest roles differ"
                );
                Ok(generation::digest_paths(b"manifest", &[&pointer.path]))
            }
        }
    }
}

impl Goal {
    /// 业务作用：复验补偿代确实属于原完整备份且与两次旧代不同，不能利用同字节恢复旧动作权威。
    ///
    /// 参数说明：
    /// - `plan`：同一来源永久保留的原准备计划。
    ///
    /// 返回：完整pair和来源相同、随机代独立时成功；不证明当前仍允许补偿。
    pub(crate) fn validate(&self, plan: &Plan) -> Result<()> {
        plan.validate()?;
        self.owner.validate(&plan.binding.validate()?)?;
        ensure!(
            self.owner.same_material(&plan.original)
                && self.owner.generation != plan.original.generation
                && self.owner.generation != plan.next.generation,
            "material compensation ownership differs"
        );
        Ok(())
    }

    /// 业务作用：让补偿收据使用文件决定之前已分配的新代，原备份字节相同也不会复用旧身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该补偿方向的原随机材料代。
    pub(crate) fn generation(&self) -> &str {
        &self.owner.generation
    }
}
