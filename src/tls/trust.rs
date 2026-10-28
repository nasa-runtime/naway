//! 显式 HTTP 信任材料在候选构建时严格验证，空证书集合不能悄然退回系统信任。

use anyhow::{ensure, Result};

/// 业务作用：把有界且非空的合法信任根移交 HTTP 客户端，使错误 CA 材料在配置发布前被拒绝。
///
/// 参数说明：
/// - `pem`：已由文件、SecretSource 或控制面取得的显式 CA bundle。
///
/// 返回：全部证书可导入时返回客户端材料；超界、空集合、PEM 或 DER 错误不发布候选。
pub(crate) fn http_ca(pem: &[u8]) -> Result<reqwest::Certificate> {
    ensure!(
        pem.len() <= super::TLS_PEM_MAX_BYTES,
        "HTTP client CA exceeds byte limit"
    );
    // 客户端的 PEM 包装不保证存在证书；先验证完整根集合，避免坏材料清空自定义信任。
    super::root_store_from_ca_bytes(pem, "HTTP client CA")?;
    Ok(reqwest::Certificate::from_pem(pem)?)
}
