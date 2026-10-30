//! 只读构建使用独立签名域，身份握手和持久动作证明都不能替代预览证明。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::Signer;
use super::Verifier;
use crate::admin::management::preview::command::Command;
use nasa::grpc::Status;

#[cfg(feature = "admin-operations-workflow-pgsql")]
impl Signer {
    /// 业务作用：只为当前发行者与同集群原目标签发只读构建证明，不生成持久执行身份。
    ///
    /// 参数说明：
    /// - `issuer`：当前发布计划声明的本机发行者。
    /// - `command`：已经取得当前预览授权的完整原目标声明。
    ///
    /// 返回：独立预览域的 Ed25519 签名；跨集群、错发行者或非法字段拒绝。
    pub(in crate::admin::management) fn sign_preview(
        &self,
        issuer: &str,
        command: &Command,
    ) -> Result<String, Status> {
        if command.intent.baseline.cluster_id != self.cluster || command.issuer != issuer {
            return Err(Status::permission_denied("preview issuer differs"));
        }
        let message = command
            .message()
            .map_err(|_| Status::invalid_argument("invalid preview contract"))?;
        nasa::crypto::sign_ed25519(&message, &self.private_key)
            .map_err(|_| Status::unavailable("preview proof unavailable"))
    }
}

impl Verifier {
    /// 业务作用：把预览签名绑定到已验证发行者及当前会话，禁止由请求选择信任材料。
    ///
    /// 参数说明：
    /// - `command`：收到的有限预览声明。
    /// - `signature`：独立预览签名。
    /// - `session`：本连接已通过握手的原会话。
    ///
    /// 返回：验签成立的消息摘要；仍须验证当前角色、权限、基线、期限与实际容量。
    pub(in crate::admin::management) fn verify_preview(
        &self,
        command: &Command,
        signature: &str,
        session: &[u8; 32],
    ) -> Result<String, Status> {
        // 先确认固定信任域与本连接，任何自报会话都不能越过独立的完整消息验签。
        if command.intent.baseline.cluster_id != self.cluster
            || command.issuer != self.node
            || signature.len() != 88
            || !crate::security::auth::constant_time_eq(session, &command.session)
        {
            return Err(Status::permission_denied("preview binding differs"));
        }
        let message = command
            .message()
            .map_err(|_| Status::invalid_argument("invalid preview contract"))?;
        if !nasa::crypto::verify_ed25519(&message, signature, &self.public_key) {
            return Err(Status::permission_denied("preview signature denied"));
        }
        Ok(message)
    }
}
