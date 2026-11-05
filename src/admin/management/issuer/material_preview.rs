//! 只读构建使用独立签名域，身份握手和持久动作证明都不能替代材料候选预检证明。

#[cfg(feature = "admin-operations-pgsql")]
use super::Signer;
use super::Verifier;
use crate::admin::management::material_preview::command::Command;
use nasa::grpc::Status;

#[cfg(feature = "admin-operations-pgsql")]
impl Signer {
    /// 业务作用：只为当前发行者与同集群原目标签发只读构建证明，不生成持久执行身份。
    ///
    /// 参数说明：
    /// - `issuer`：当前发布计划声明的本机发行者。
    /// - `command`：已经取得当前材料候选预检授权的完整原目标声明。
    ///
    /// 返回：独立材料候选预检域的 Ed25519 签名；跨集群、错发行者或非法字段拒绝。
    pub(in crate::admin::management) fn sign_material_preview(
        &self,
        issuer: &str,
        command: &Command,
    ) -> Result<String, Status> {
        // 私钥只为当前集群和本机发行身份服务，不能成为调用者自选身份的签名代理。
        if command.intent.baseline.cluster_id != self.cluster || command.issuer != issuer {
            return Err(Status::permission_denied("material preview issuer differs"));
        }
        let message = command
            .message()
            .map_err(|_| Status::invalid_argument("invalid material preview contract"))?;
        nasa::crypto::sign_ed25519(&message, &self.private_key)
            .map_err(|_| Status::unavailable("material preview proof unavailable"))
    }
}

impl Verifier {
    /// 业务作用：把材料候选预检签名绑定到已验证发行者及当前会话，禁止由请求选择信任材料。
    ///
    /// 参数说明：
    /// - `command`：收到的有限材料候选预检声明。
    /// - `signature`：独立材料候选预检签名。
    /// - `session`：本连接已通过握手的原会话。
    ///
    /// 返回：验签成立的消息摘要；仍须验证当前角色、权限、基线、期限与实际容量。
    pub(in crate::admin::management) fn verify_material_preview(
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
            return Err(Status::permission_denied(
                "material preview binding differs",
            ));
        }
        let message = command
            .message()
            .map_err(|_| Status::invalid_argument("invalid material preview contract"))?;
        if !nasa::crypto::verify_ed25519(&message, signature, &self.public_key) {
            return Err(Status::permission_denied(
                "material preview signature denied",
            ));
        }
        Ok(message)
    }
}
