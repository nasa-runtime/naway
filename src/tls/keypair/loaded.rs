//! 同一次受管材料读取同时提供签名输入和原生归属，解析过程不重新读取当前文件。

use super::{generation, keypair_install_lock, recover_legacy_keypair_transaction_locked};
use crate::{config::TlsRuntimeCfg, tls::material::MaterialProvenance};
use anyhow::Result;
use zeroize::Zeroizing;

pub(in crate::tls) struct Loaded {
    pub certificate: Zeroizing<Vec<u8>>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub provenance: MaterialProvenance,
}

/// 业务作用：在唯一材料锁内取得完整 pair 与同源归属，防止加载旧文件后附上另一轮的新材料代。
///
/// 参数说明：
/// - `tls`：不使用外部 signer 的默认或 SNI 文件来源。
///
/// 返回：本次有界读取的唯一材料缓冲和原生归属；文件或旧事务恢复失败拒绝加载，归属不足不阻断合法 TLS。
pub(in crate::tls) fn read(tls: &TlsRuntimeCfg) -> Result<Loaded> {
    anyhow::ensure!(
        tls.in_memory.is_none() && tls.spire.is_none() && tls.private_key_provider.is_none(),
        "TLS file loading requires a local pair"
    );
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS keypair install lock is poisoned"))?;
    // 先结算原文件决定再取样，半份 pair 不能和完整材料代共同进入待安装 resolver。
    recover_legacy_keypair_transaction_locked(tls)?;
    let (certificate, private_key) = crate::tls::active_keypair_paths_unrecovered(tls)?;
    let certificate = crate::io::secret_file::read_file(
        &certificate,
        super::MAX_KEYPAIR_BYTES,
        "TLS loaded certificate",
    )?;
    let private_key = crate::io::secret_file::read_file(
        &private_key,
        super::MAX_KEYPAIR_BYTES,
        "TLS loaded private key",
    )?;
    // 外部合法换材可以继续服务，但损坏或不匹配的归属不能为未来交付补发安装证明。
    let provenance =
        generation::loaded(tls, &certificate, &private_key).unwrap_or(MaterialProvenance::Unproven);
    Ok(Loaded {
        certificate,
        private_key,
        provenance,
    })
}
