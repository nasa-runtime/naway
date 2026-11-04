//! 完整证书链与私钥的密码学匹配门，验证失败不得触及活动文件。

use anyhow::{Context, Result};
use std::io::Cursor;
use tokio_rustls::rustls::sign::CertifiedKey;

/// 业务作用：在落盘前验证证书链可解析、私钥算法受 rustls 支持且 leaf/key 匹配。
///
/// 参数说明：
/// - `certificate_pem`: 待安装证书链。
/// - `private_key_pem`: 待安装私钥。
///
/// 返回：已解析且匹配的签名身份；格式、算法或密钥不匹配时失败，不访问活动文件。
pub(super) fn validate_keypair(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<CertifiedKey> {
    let mut cert_reader = Cursor::new(certificate_pem);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse issued certificate chain")?;
    if certs.is_empty() {
        anyhow::bail!("issued certificate chain is empty");
    }
    let mut key_reader = Cursor::new(private_key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse issued private key")?
        .ok_or_else(|| anyhow::anyhow!("issued private key is empty"))?;
    let signing_key = tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .context("issued private key algorithm is unsupported")?;
    let certified = tokio_rustls::rustls::sign::CertifiedKey::new(certs, signing_key);
    certified
        .keys_match()
        .context("issued certificate does not match private key")?;
    Ok(certified)
}
