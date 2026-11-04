//! 文件决定前检查共享材料的全部监听策略；预检不向活动 listener 发布候选。

use super::{generation, recover_legacy_keypair_transaction_locked};
use crate::config::{GatewaySnapshot, TlsRuntimeCfg};
use crate::tls::{identity, material, targets};
use anyhow::{ensure, Result};
use std::path::PathBuf;
use tokio_rustls::rustls::sign::CertifiedKey;

struct Position {
    certificate: PathBuf,
    private_key: Option<PathBuf>,
    manifest: Option<PathBuf>,
    manifest_active: bool,
}

impl Position {
    /// 业务作用：定位实际文件槽位与指针，使共享来源判定不会被目录别名或默认 seed 混淆。
    ///
    /// 参数说明：
    /// - `source`：默认或 SNI 的独立来源计划。
    ///
    /// 返回：规范化槽位；不能解析当前来源时拒绝证明无冲突，不读取私钥内容。
    fn read(source: &TlsRuntimeCfg) -> Result<Self> {
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
    fn shares(&self, other: &Self) -> Result<bool> {
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

/// 业务作用：在唯一材料锁内把候选覆盖到所有共享监听，完整策略通过前不开始文件准备。
///
/// 参数说明：
/// - `snapshot`：由调用方持有配置发布权冻结的完整已发布计划。
/// - `selected`：目标声明解析出的默认或 SNI 来源。
/// - `candidate`：只解析一次并已匹配的候选证书与签名密钥。
///
/// 返回：所有受影响监听均可构建时成功；资源上限、来源冲突或任一策略失败均不安装候选。
pub(super) fn validate(
    snapshot: &GatewaySnapshot,
    selected: &TlsRuntimeCfg,
    candidate: &CertifiedKey,
) -> Result<()> {
    let plans = || {
        snapshot
            .proxies
            .iter()
            .filter_map(|proxy| proxy.tls.as_ref())
            .chain(
                snapshot
                    .stream_listeners
                    .iter()
                    .filter_map(|stream| stream.tls.as_ref()),
            )
    };
    let identities = plans().try_fold(0usize, |count, plan| {
        count.checked_add(plan.certs.len().saturating_add(1))
    });
    ensure!(
        identities.is_some_and(|count| count <= 4096),
        "TLS material preflight exceeds identity budget"
    );
    let position = Position::read(selected)?;
    ensure!(
        position.private_key.as_ref() != Some(&position.certificate),
        "TLS certificate and private key require distinct file slots"
    );
    let mut matched = false;
    for plan in plans() {
        if plan.in_memory.is_some() || plan.spire.is_some() {
            continue;
        }
        let mut affected = position.shares(&Position::read(plan)?)?;
        for sni in &plan.certs {
            affected |= position.shares(&Position::read(&targets::sni_source(plan, sni))?)?;
        }
        if !affected {
            continue;
        }
        let resolver = identity::build_sni_resolver_with(plan, |source| {
            // 已持有唯一材料锁，不重入公开 loader 的锁；其它 SNI 的未完成事务仍须先结算。
            recover_legacy_keypair_transaction_locked(source)?;
            if position.shares(&Position::read(source)?)? {
                ensure!(targets::writable(source), "TLS source is externally owned");
                // 签名私钥共享已解析产物；不同身份仍各自验证自己的 OCSP 策略，不能继承目标的响应。
                identity::apply_ocsp_policy(
                    CertifiedKey::new(candidate.cert.clone(), candidate.key.clone()),
                    source.ocsp_stapling.as_ref(),
                )
            } else {
                let (certificate, private_key) =
                    crate::tls::active_keypair_paths_unrecovered(source)?;
                identity::certified_identity(
                    &certificate,
                    &private_key,
                    source.private_key_provider.as_ref(),
                    source.ocsp_stapling.as_ref(),
                )
            }
        })?;
        // 完整 CA、会话及选证策略必须可构建，但产物只作预检，文件决定前不能发布到数据面。
        material::build_with_resolver(plan, resolver)?;
        matched = true;
    }
    ensure!(matched, "TLS material target is no longer declared");
    Ok(())
}
