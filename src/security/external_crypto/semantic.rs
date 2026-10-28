//! Envelope 使用实际密码 provider 的冻结身份，避免 KEK 或 AAD 变化沿用旧解密授权。

use super::ExternalEnvelopePlan;
use sha2::{Digest, Sha256};

impl ExternalEnvelopePlan {
    /// 业务作用：为远程凭据缓存绑定实际密码后端、KEK 与附加 AAD，不读取 provider 运行状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：长度分隔的固定身份；既有 provider 身份覆盖实际材料、算法和资源预算。
    pub(crate) fn configuration_identity(&self) -> [u8; 32] {
        let Self {
            provider,
            key_id,
            aad_context,
        } = self;
        let mut digest = Sha256::new();
        digest.update(b"naway-remote-secret-envelope\0");
        digest.update(provider.identity);
        for value in [key_id, aad_context] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.finalize().into()
    }
}
