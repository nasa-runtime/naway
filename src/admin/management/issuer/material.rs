//! 材料观察使用独立签名域，身份握手和持久动作证明都不能替代条件查询证明。

use super::Signer;
use super::Verifier;
use crate::admin::management::material::command::Command;
use nasa::grpc::Status;

impl Signer {
    /// 业务作用：只用构建时已证明与本机私钥配对的公钥建立内部验证器，命令不能自行选择信任材料。
    ///
    /// 参数说明：
    /// - node：当前管理计划的本机永久节点身份。
    ///
    /// 返回：仅供同进程受控会话的验证器，不修改任何远程成员或可信目标声明。
    pub(in crate::admin::management) fn local_verifier(
        &self,
        node: &str,
    ) -> std::sync::Arc<Verifier> {
        std::sync::Arc::new(Verifier {
            cluster: self.cluster.clone(),
            node: node.to_owned(),
            public_key: self.public_key.clone(),
        })
    }

    /// 业务作用：只为当前发行者与同集群原目标签发材料查询证明，不生成持久执行身份。
    ///
    /// 参数说明：
    /// - `issuer`：当前发布计划声明的本机发行者。
    /// - `command`：已经取得当前材料条件查询授权的完整原目标声明。
    ///
    /// 返回：独立材料条件查询域的 Ed25519 签名；跨集群、错发行者或非法字段拒绝。
    pub(in crate::admin::management) fn sign_material_conditions(
        &self,
        issuer: &str,
        command: &Command,
    ) -> Result<String, Status> {
        if command.intent.baseline.cluster_id != self.cluster || command.issuer != issuer {
            return Err(Status::permission_denied(
                "material conditions issuer differs",
            ));
        }
        let message = command
            .message()
            .map_err(|_| Status::invalid_argument("invalid material conditions contract"))?;
        nasa::crypto::sign_ed25519(&message, &self.private_key)
            .map_err(|_| Status::unavailable("material conditions proof unavailable"))
    }
}

impl Verifier {
    /// 业务作用：把材料条件查询签名绑定到已验证发行者及当前会话，禁止由请求选择信任材料。
    ///
    /// 参数说明：
    /// - `command`：收到的有限材料条件查询声明。
    /// - `signature`：独立材料条件查询签名。
    /// - `session`：本连接已通过握手的原会话。
    ///
    /// 返回：验签成立的消息摘要；仍须验证当前角色、权限、基线、期限与实际容量。
    pub(in crate::admin::management) fn verify_material_conditions(
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
                "material conditions binding differs",
            ));
        }
        let message = command
            .message()
            .map_err(|_| Status::invalid_argument("invalid material conditions contract"))?;
        if !nasa::crypto::verify_ed25519(&message, signature, &self.public_key) {
            return Err(Status::permission_denied(
                "material conditions signature denied",
            ));
        }
        Ok(message)
    }
}
