//! 文件决定前检查共享材料的全部监听策略；预检不向活动 listener 发布候选。

use super::{recover_legacy_keypair_transaction_locked, source};
use crate::config::{GatewaySnapshot, TlsRuntimeCfg};
use crate::tls::{identity, material, targets};
use anyhow::{ensure, Result};
use std::collections::BTreeMap;
use tokio_rustls::rustls::sign::CertifiedKey;

struct Candidate<'a> {
    key: &'a CertifiedKey,
    retained: usize,
    policies: Vec<(
        Option<crate::config::OcspStaplingRuntime>,
        crate::tls::CertifiedIdentity,
    )>,
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
    let index = source::Index::read(snapshot)?;
    let position = source::Position::read(selected)?;
    validate_sources(&index, &[&position], candidate)
}

/// 业务作用：同时覆盖本次所有来源后构建完整监听计划，每个共享监听只检查一次而不混入其它选中来源的旧材料。
///
/// 参数说明：
/// - `index`：在唯一材料锁内取得的完整物理来源索引。
/// - `selected`：本次一起采用同一候选的写入来源，调用方已经复验原条件及完整归属。
/// - `candidate`：只解析一次并且证书与私钥已匹配的候选。
///
/// 返回：全部受影响监听通过完整 TLS 策略构建；来源冲突、超量或策略失败均不写文件、不发布监听。
pub(super) fn validate_sources(
    index: &source::Index<'_>,
    selected: &[&source::Position],
    candidate: &CertifiedKey,
) -> Result<()> {
    ensure!(
        !selected.is_empty() && selected.len() <= 128,
        "TLS candidate source count exceeds budget"
    );
    let mut listeners = BTreeMap::new();
    for position in selected {
        for listener in index.impact(position)?.listeners {
            listeners.insert((listener.kind as u8, listener.id), listener.plan);
        }
    }
    let mut candidate = Candidate {
        key: candidate,
        retained: 0,
        policies: Vec::new(),
    };
    for plan in listeners.into_values() {
        let resolver = identity::build_sni_resolver_with(plan, |source| {
            // 已持有唯一材料锁，不重入公开 loader 的锁；其它 SNI 的未完成事务仍须先结算。
            recover_legacy_keypair_transaction_locked(source)?;
            let position = source::Position::read(source)?;
            let replace = selected.iter().try_fold(false, |replace, selected| {
                selected.shares(&position).map(|shared| replace || shared)
            })?;
            if replace {
                ensure!(targets::writable(source), "TLS source is externally owned");
                candidate.identity(source.ocsp_stapling.as_ref())
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
    }
    Ok(())
}

impl Candidate<'_> {
    /// 业务作用：为相同候选与相同 OCSP 策略共享签名身份，避免共享来源的每个监听重复复制证书链。
    ///
    /// 参数说明：
    /// - `policy`：当前具体身份自己的 OCSP 策略，不能用默认身份的策略代替。
    ///
    /// 返回：已通过当前策略的共享身份；首次遇到策略时验证真实响应，失败不缓存或回退其它身份。
    fn identity(
        &mut self,
        policy: Option<&crate::config::OcspStaplingRuntime>,
    ) -> Result<crate::tls::CertifiedIdentity> {
        if let Some((_, identity)) = self
            .policies
            .iter()
            .find(|(current, _)| current.as_ref() == policy)
        {
            return Ok(identity.clone());
        }
        // 缓存键包含完整策略，相同文件但不同 required 或 freshness 约束仍分别验证，不继承另一身份的响应。
        let identity = identity::apply_ocsp_policy(
            CertifiedKey::new(self.key.cert.clone(), self.key.key.clone()),
            policy,
        )?;
        let bytes = std::iter::once(identity.active.as_ref())
            .chain(identity.expired_fallback.as_deref())
            .fold(0usize, |bytes, key| {
                key.cert
                    .iter()
                    .fold(bytes, |bytes, certificate| {
                        bytes.saturating_add(certificate.len())
                    })
                    .saturating_add(key.ocsp.as_ref().map_or(0, Vec::len))
            });
        // 复用只保留有限公开证书和响应；大量不同策略继续逐项验证，不累积整个配置的已完成构建产物。
        if self.policies.len() < 16 && bytes <= (4 * 1024 * 1024usize).saturating_sub(self.retained)
        {
            self.retained += bytes;
            self.policies.push((policy.cloned(), identity.clone()));
        }
        Ok(identity)
    }
}
