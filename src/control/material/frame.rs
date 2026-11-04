//! 原生材料帧由受理和目标预检共用，公开摘要不包含私钥信息。

use super::hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug)]
pub(crate) struct Invalid;

/// 长度帧只编码一次，不经 JSON 或 Base64 中间转换，也不提供诊断或序列化能力。
pub(crate) struct Material(pub Zeroizing<Vec<u8>>);

impl Material {
    /// 业务作用：严格解帧并借用唯一明文缓冲区，拒绝截断、尾随数据和超量密文产物。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原证书与私钥切片；不分配副本，也不读取文件。
    pub(crate) fn parts(&self) -> Result<(&[u8], &[u8]), Invalid> {
        let bytes = &self.0;
        if bytes.len() < 16 || bytes.len() > 1024 * 1024 + 16 || &bytes[..8] != b"NCERT001" {
            return Err(Invalid);
        }
        let cert = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| Invalid)?) as usize;
        let key = u32::from_be_bytes(bytes[12..16].try_into().map_err(|_| Invalid)?) as usize;
        if cert == 0
            || key == 0
            || cert.checked_add(key).and_then(|n| n.checked_add(16)) != Some(bytes.len())
        {
            return Err(Invalid);
        }
        Ok((&bytes[16..16 + cert], &bytes[16 + cert..]))
    }

    /// 业务作用：复用安装端的密码学匹配门并解析公开叶证书，受理不冒充完整目标 TLS 策略预检。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只含公开证书摘要和有效期的有限投影；不保留私钥解析产物或返回底层错误。
    pub(crate) fn inspect(&self) -> Result<Summary, Invalid> {
        let (cert, key) = self.parts()?;
        let identity = crate::tls::keypair::validate_keypair(cert, key).map_err(|_| Invalid)?;
        if identity.cert.len() > 32 {
            return Err(Invalid);
        }
        for der in &identity.cert {
            let (rest, _) = x509_parser::parse_x509_certificate(der).map_err(|_| Invalid)?;
            if !rest.is_empty() {
                return Err(Invalid);
            }
        }
        let leaf = identity.cert[0].as_ref();
        let (_, certificate) = x509_parser::parse_x509_certificate(leaf).map_err(|_| Invalid)?;
        Ok(Summary {
            certificate_sha256: hex(&Sha256::digest(cert)),
            leaf_sha256: hex(&Sha256::digest(leaf)),
            chain_length: identity.cert.len() as u32,
            not_before_seconds: certificate.validity().not_before.timestamp(),
            not_after_seconds: certificate.validity().not_after.timestamp(),
        })
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Summary {
    pub certificate_sha256: String,
    pub leaf_sha256: String,
    pub chain_length: u32,
    pub not_before_seconds: i64,
    pub not_after_seconds: i64,
}
