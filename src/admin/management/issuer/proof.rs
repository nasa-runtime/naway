//! 身份证明签名域与动作协议隔离；只借用有界字段计算摘要。

use super::super::{plan::stamp, protocol, security};
use nasa::grpc::Status;
use sha2::{Digest, Sha256};

/// 业务作用：绑定具体集群、发行者及远端当前握手，避免分段歧义或旧挑战重放。
///
/// 参数说明：
/// - `cluster`：本地已配置的集群身份。
/// - `issuer`：本地已配置的发行节点身份。
/// - `request`：原节点、启动、会话和随机挑战，均不包含业务正文。
///
/// 返回：固定64字符摘要；非法节点或非32字节的会话/挑战拒绝签名与验证。
pub(super) fn message(
    cluster: &str,
    issuer: &str,
    request: &protocol::IssuerChallenge,
) -> Result<String, Status> {
    if !security::identifier(&request.node_id)
        || !security::identifier(&request.boot_id)
        || request.session.len() != 32
        || request.challenge.len() != 32
    {
        return Err(Status::invalid_argument("invalid issuer challenge"));
    }
    let mut digest = Sha256::new();
    digest.update(b"naway-management-issuer-identity\0");
    digest.update(1_u32.to_be_bytes());
    for field in [
        cluster.as_bytes(),
        issuer.as_bytes(),
        request.node_id.as_bytes(),
        request.boot_id.as_bytes(),
        &request.session,
        &request.challenge,
    ] {
        stamp(&mut digest, field);
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        encoded.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    Ok(encoded)
}
