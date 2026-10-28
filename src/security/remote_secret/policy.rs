//! 远程值的 LKG 许可绑定完整构建策略，逻辑对象版本水位仍由独立缓存键维护。

use super::{PreparedAdapter, PreparedProvider};
use sha2::{Digest, Sha256};

/// 只在候选构建期间使用的长度分隔摘要，不保留认证、证书或私钥副本。
pub(super) struct Material(Sha256);

impl Material {
    /// 业务作用：建立 provider 传输材料摘要，使缺省系统根与显式材料属于不同身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空的构建期摘要；调用者按 CA、证书、私钥的固定顺序追加三个可选字段。
    pub(super) fn new() -> Self {
        Self(Sha256::new())
    }

    /// 业务作用：在原始解析点记录传输材料，避免后续重新读取文件造成身份与客户端不一致。
    ///
    /// 参数说明：
    /// - `value`：本次实际加载的材料；None 表示该字段未配置。
    ///
    /// 返回：追加存在性、字节长度及材料，不持有或复制材料内容。
    pub(super) fn field(&mut self, value: Option<&[u8]>) {
        self.0.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            part(&mut self.0, value);
        }
    }

    /// 业务作用：冻结传输材料身份供完整 provider 策略使用，不暴露材料原文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：消耗构建期摘要并返回固定 32 字节身份。
    pub(super) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// 业务作用：冻结决定远程值是否允许继续使用的全部固定策略，避免新信任边界复用旧 LKG。
///
/// 参数说明：
/// - `provider`：本次已构建的实际传输、凭据、适配器与预算。
/// - `connect_ms`：HTTP 客户端实际连接预算。
/// - `request_ms`：HTTP 客户端实际完整请求预算。
/// - `material`：同次读取的 CA 与 mTLS 材料身份。
///
/// 返回：固定策略身份，不包含缓存内容、当前时间、连接池或熔断状态。
pub(super) fn identity(
    provider: &PreparedProvider,
    connect_ms: u64,
    request_ms: u64,
    material: [u8; 32],
) -> [u8; 32] {
    let PreparedProvider {
        name,
        endpoint,
        client: _,
        authorization,
        adapter,
        value_pointer,
        version_pointer,
        lease_seconds_pointer,
        refresh_interval,
        max_stale,
        retry_base,
        retry_max,
        max_response_bytes,
        envelope,
        policy_identity: _,
    } = provider;
    let mut digest = Sha256::new();
    digest.update(b"naway-remote-secret-policy\0");
    for value in [
        name.as_ref(),
        endpoint.as_str(),
        value_pointer,
        version_pointer,
    ] {
        part(&mut digest, value.as_bytes());
    }
    digest.update([u8::from(authorization.is_some())]);
    if let Some((name, value)) = authorization {
        part(&mut digest, name.as_str().as_bytes());
        part(&mut digest, value.as_bytes());
    }
    match adapter {
        PreparedAdapter::GenericJson => digest.update([0]),
        PreparedAdapter::AwsSecretsManager {
            region,
            access_key_id,
            secret_access_key,
            session_token,
        } => {
            digest.update([1]);
            part(&mut digest, region.as_bytes());
            part(&mut digest, access_key_id.as_bytes());
            part(&mut digest, secret_access_key);
            part(&mut digest, session_token.as_bytes());
        }
        PreparedAdapter::AzureKeyVault {
            api_version,
        } => {
            digest.update([2]);
            part(&mut digest, api_version.as_bytes());
        }
        PreparedAdapter::GcpSecretManager => digest.update([3]),
    }
    digest.update([u8::from(lease_seconds_pointer.is_some())]);
    if let Some(pointer) = lease_seconds_pointer {
        part(&mut digest, pointer.as_bytes());
    }
    for duration in [refresh_interval, max_stale, retry_base, retry_max] {
        digest.update(duration.as_millis().to_be_bytes());
    }
    digest.update(connect_ms.to_be_bytes());
    digest.update(request_ms.to_be_bytes());
    digest.update((*max_response_bytes as u64).to_be_bytes());
    digest.update(material);
    digest.update([u8::from(envelope.is_some())]);
    if let Some(envelope) = envelope {
        digest.update(envelope.configuration_identity());
    }
    digest.finalize().into()
}

/// 业务作用：在可变长度字段前写入长度，防止不同字段边界产生相同的摘要输入。
///
/// 参数说明：
/// - `digest`：当前策略摘要。
/// - `bytes`：已经有界验证的一个固定字段。
///
/// 返回：仅更新摘要，不分配中间编码或复制字段。
fn part(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
