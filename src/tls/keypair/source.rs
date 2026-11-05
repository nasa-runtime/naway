//! 物理来源与完整共享影响在同一材料锁内解析，不向管理调用者暴露路径。

use super::generation;
use crate::config::TlsRuntimeCfg;
use crate::tls::targets::Kind;
use anyhow::{ensure, Result};
use std::path::PathBuf;

#[cfg(feature = "node-actions")]
pub(super) mod held;
mod index;
pub(super) use index::Index;

pub(super) struct Position {
    certificate: PathBuf,
    private_key: Option<PathBuf>,
    manifest: Option<PathBuf>,
    manifest_active: bool,
}

impl Position {
    /// 业务作用：复用已解析的物理槽位计算写入来源身份，不为共享影响再次访问目录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与持久材料代相同域的来源摘要；外部私钥来源没有手工写入身份。
    pub(super) fn identity(&self) -> Result<[u8; 32]> {
        if let Some(manifest) = &self.manifest {
            return Ok(generation::digest_paths(b"manifest", &[manifest]));
        }
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS source has no local private key authority"))?;
        Ok(generation::digest_paths(
            b"legacy",
            &[&self.certificate, private_key],
        ))
    }
    /// 业务作用：定位实际文件槽位与指针，使共享来源判定不会被目录别名或默认 seed 混淆。
    ///
    /// 参数说明：
    /// - `source`：默认或 SNI 的独立来源计划。
    ///
    /// 返回：规范化槽位；不能解析当前来源时拒绝证明无冲突，不读取私钥内容。
    pub(super) fn read(source: &TlsRuntimeCfg) -> Result<Self> {
        let active = source
            .keypair_manifest_file
            .as_deref()
            .map(super::current_material_directory)
            .transpose()?
            .flatten();
        let (certificate, private_key) = match &active {
            Some(directory) => (directory.join("cert.pem"), directory.join("key.pem")),
            None => (source.cert_file.clone(), source.key_file.clone()),
        };
        Ok(Self {
            certificate: generation::identity_path(&certificate)?,
            private_key: if source.private_key_provider.is_none() {
                Some(generation::identity_path(&private_key)?)
            } else {
                None
            },
            manifest: source
                .keypair_manifest_file
                .as_deref()
                .map(generation::identity_path)
                .transpose()?,
            manifest_active: active.is_some(),
        })
    }

    /// 业务作用：区分完整共同来源与危险的部分文件共享，单个身份不能覆盖另一来源的材料。
    ///
    /// 参数说明：
    /// - `other`：同一快照中另一身份的实际槽位。
    ///
    /// 返回：同一受管来源为真、完全独立为假；部分共享、跨模式复用或外部 signer 重叠均失败。
    pub(super) fn shares(&self, other: &Self) -> Result<bool> {
        let same = match (&self.manifest, &other.manifest) {
            (Some(left), Some(right)) => left == right,
            (None, _) if !other.manifest_active => {
                self.certificate == other.certificate
                    && self.private_key.is_some()
                    && self.private_key == other.private_key
            }
            _ => false,
        };
        if same {
            ensure!(
                other.private_key.is_some(),
                "shared TLS source has an external signer"
            );
            return Ok(true);
        }
        // 首次激活 manifest 只写新目录和指针，原 seed 文件继续供其它监听使用，不把只读 seed 视为写入。
        if let Some(manifest) = &self.manifest {
            if !self.manifest_active {
                ensure!(
                    !other
                        .slots()
                        .into_iter()
                        .flatten()
                        .any(|slot| slot == manifest),
                    "TLS manifest overlaps another source slot"
                );
                return Ok(false);
            }
        }
        // 任一文件角色重叠都不能被当成无关监听；manifest 目录也不得手工借给另一来源。
        ensure!(
            !self.slots().into_iter().flatten().any(|left| {
                other
                    .slots()
                    .into_iter()
                    .flatten()
                    .any(|right| left == right)
            }),
            "TLS sources share only part of their material authority"
        );
        Ok(false)
    }

    /// 业务作用：在文件角色之间检查重叠，证书、私钥和指针不能借角色不同绕过共享保护。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用固定三个槽位，不分配或复制路径。
    fn slots(&self) -> [Option<&PathBuf>; 3] {
        [
            Some(&self.certificate),
            self.private_key.as_ref(),
            self.manifest.as_ref(),
        ]
    }
}

/// 共享来源的全部逻辑身份；实际来源证明留在控制面，不由路径文本推测共同所有权。
pub(super) struct Impact<'a> {
    pub(super) listeners: Vec<Listener<'a>>,
}

pub(super) struct Listener<'a> {
    pub(super) plan: &'a TlsRuntimeCfg,
    pub(super) kind: Kind,
    pub(super) id: &'a str,
    pub(super) entries: Vec<Option<usize>>,
}
