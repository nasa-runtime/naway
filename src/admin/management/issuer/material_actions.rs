//! 材料业务与终态清理分别验签，配置动作、身份握手和预检证明不能取得材料写权。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::Signer;
use super::Verifier;
use crate::control::material::execution::{command, release};
use nasa::grpc::Status;

#[cfg(feature = "admin-operations-workflow-pgsql")]
impl Signer {
    /// 业务作用：只为当前发行者和固定集群签发完整材料命令，原物理位置与独立工作流不能被替换。
    ///
    /// 参数说明：
    /// - `issuer`：当前已发布管理计划的本机身份。
    /// - `command`：已经复验共享批准、原分母和租约的完整命令。
    ///
    /// 返回：独立材料执行域的Ed25519证明；错集群、错发行者或非法合同拒绝。
    pub(in crate::admin::management) fn sign_material_command(
        &self,
        issuer: &str,
        command: &command::Command,
    ) -> Result<String, Status> {
        // 私钥只服务当前信任域，不能由调用者的待签名文本选择另一集群或发行身份。
        if command.intent.baseline.cluster_id != self.cluster
            || command.delivery.issuer_node_id != issuer
        {
            return Err(Status::permission_denied("material command issuer differs"));
        }
        let checked = command
            .validate()
            .map_err(|_| Status::invalid_argument("invalid material command contract"))?;
        nasa::crypto::sign_ed25519(checked.message(), &self.private_key)
            .map_err(|_| Status::unavailable("material command proof unavailable"))
    }

    /// 业务作用：为已确认的共享终态签发独立清理证明，业务收据不能被当作秘密删除权。
    ///
    /// 参数说明：
    /// - `issuer`：当前已发布管理计划的本机身份。
    /// - `release`：原完整意图、物理位置、共享终态及当前投递。
    ///
    /// 返回：独立材料释放域的证明；错信任域或非法终态合同拒绝。
    pub(in crate::admin::management) fn sign_material_release(
        &self,
        issuer: &str,
        release: &release::Release,
    ) -> Result<String, Status> {
        if release.intent.baseline.cluster_id != self.cluster
            || release.delivery.issuer_node_id != issuer
        {
            return Err(Status::permission_denied("material release issuer differs"));
        }
        let checked = release
            .validate()
            .map_err(|_| Status::invalid_argument("invalid material release contract"))?;
        nasa::crypto::sign_ed25519(&checked.message, &self.private_key)
            .map_err(|_| Status::unavailable("material release proof unavailable"))
    }
}

impl Verifier {
    /// 业务作用：用本连接的固定发行者和会话验证材料命令，原生合同决定唯一完整签名域。
    ///
    /// 参数说明：
    /// - `command`：尚未下载候选的有界原生命令。
    /// - `signature`：发行者提供的材料执行签名。
    /// - `session`：已通过挑战的当前连接会话，不能来自命令自报字段。
    ///
    /// 返回：完整验真的原生身份；不授予当前RBAC、节点容量或持久文件权。
    pub(in crate::admin::management) fn verify_material_command(
        &self,
        command: &command::Command,
        signature: &str,
        session: &[u8; 32],
    ) -> Result<command::Validated, Status> {
        // 固定信任域与当前连接先于合同验签，旧会话不能借同一公钥恢复写权。
        if command.intent.baseline.cluster_id != self.cluster
            || command.delivery.issuer_node_id != self.node
            || signature.len() != 88
            || !crate::security::auth::constant_time_eq(session, &command.delivery.session)
        {
            return Err(Status::permission_denied(
                "material command binding differs",
            ));
        }
        let checked = command
            .validate()
            .map_err(|_| Status::invalid_argument("invalid material command contract"))?;
        if !nasa::crypto::verify_ed25519(checked.message(), signature, &self.public_key) {
            return Err(Status::permission_denied(
                "material command signature denied",
            ));
        }
        Ok(checked)
    }

    /// 业务作用：在实际清理前验证原共享终态的独立证明，配置释放或业务命令签名不可互换。
    ///
    /// 参数说明：
    /// - `release`：当前收到的完整原意图、物理位置与终态声明。
    /// - `signature`：独立材料释放签名。
    /// - `session`：当前挑战已经绑定的原会话。
    ///
    /// 返回：验真的释放证明；仍须当前四主体、期限和本机责任共同允许清理。
    pub(in crate::admin::management) fn verify_material_release(
        &self,
        release: &release::Release,
        signature: &str,
        session: &[u8; 32],
    ) -> Result<release::Validated, Status> {
        if release.intent.baseline.cluster_id != self.cluster
            || release.delivery.issuer_node_id != self.node
            || signature.len() != 88
            || !crate::security::auth::constant_time_eq(session, &release.delivery.session)
        {
            return Err(Status::permission_denied(
                "material release binding differs",
            ));
        }
        let checked = release
            .validate()
            .map_err(|_| Status::invalid_argument("invalid material release contract"))?;
        if !nasa::crypto::verify_ed25519(&checked.message, signature, &self.public_key) {
            return Err(Status::permission_denied(
                "material release signature denied",
            ));
        }
        Ok(checked)
    }
}
