//! 文件决定前检查共享材料的全部监听策略；预检不向活动 listener 发布候选。

use super::{recover_legacy_keypair_transaction_locked, source};
use crate::config::{GatewaySnapshot, TlsRuntimeCfg};
use crate::tls::{identity, material, targets};
use anyhow::{ensure, Result};
use tokio_rustls::rustls::sign::CertifiedKey;

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
    let impact = source::Impact::read(snapshot, selected)?;
    for listener in &impact.listeners {
        let plan = listener.plan;
        let resolver = identity::build_sni_resolver_with(plan, |source| {
            // 已持有唯一材料锁，不重入公开 loader 的锁；其它 SNI 的未完成事务仍须先结算。
            recover_legacy_keypair_transaction_locked(source)?;
            if impact.position.shares(&source::Position::read(source)?)? {
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
    }
    Ok(())
}
