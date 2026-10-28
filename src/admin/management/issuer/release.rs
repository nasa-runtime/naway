//! 释放只证明原代际的关闭资格，不复用握手或业务命令签名。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::Signer;
use super::Verifier;
use crate::control::actions::release::{Release, Validated};
use nasa::{grpc::Status, saga::WorkflowDefinition};

#[cfg(feature = "admin-operations-workflow-pgsql")]
impl Signer {
    /// 业务作用：为共享安全终态和原目标的精确释放声明签名，限制发行者的集群与节点身份。
    ///
    /// 参数说明：
    /// - issuer：当前计划的真实本机发行者节点。
    /// - release：执行适配器已确认共享安全终态及新租约的释放声明。
    /// - definition：本机冻结的原工作流定义。
    ///
    /// 返回：独立释放域的 Ed25519 证明；身份或合同不成立时拒绝，不代替事务与授权门。
    pub(in crate::admin::management) fn sign_release(
        &self,
        issuer: &str,
        release: &Release,
        definition: &WorkflowDefinition,
    ) -> Result<String, Status> {
        // 不能用同一私钥声明其它控制集群，实际身份始终取已发布计划。
        if release.intent.baseline.cluster_id != self.cluster
            || release.delivery.issuer_node_id != issuer
        {
            return Err(Status::permission_denied("release issuer identity differs"));
        }
        let checked = release
            .validate(definition)
            .map_err(|_| Status::invalid_argument("invalid node release contract"))?;
        nasa::crypto::sign_ed25519(&checked.message, &self.private_key)
            .map_err(|_| Status::unavailable("node release proof unavailable"))
    }
}

impl Verifier {
    /// 业务作用：用当前受信发行者和握手会话核对释放证明，旧连接或业务命令不能关闭节点代际。
    ///
    /// 参数说明：
    /// - release：同一响应中的有界释放声明。
    /// - signature：独立释放域的发行者签名。
    /// - session：本通道已验证的原会话，不取自释放自报字段。
    /// - definition：本机冻结的原工作流定义。
    ///
    /// 返回：签名与绑定一致时返回已验证摘要；不产生文件副作用或跳过当前权限检查。
    pub(in crate::admin::management) fn verify_release(
        &self,
        release: &Release,
        signature: &str,
        session: &[u8],
        definition: &WorkflowDefinition,
    ) -> Result<Validated, Status> {
        // 会话和集群先收敛到本地信任材料，再接受签名，防止对端自选公钥或跨连接重放。
        if release.intent.baseline.cluster_id != self.cluster
            || release.delivery.issuer_node_id != self.node
            || signature.len() != 88
            || session.len() != 32
            || !crate::security::auth::constant_time_eq(session, &release.delivery.session)
        {
            return Err(Status::permission_denied("node release binding differs"));
        }
        let checked = release
            .validate(definition)
            .map_err(|_| Status::invalid_argument("invalid node release contract"))?;
        if !nasa::crypto::verify_ed25519(&checked.message, signature, &self.public_key) {
            return Err(Status::permission_denied("node release signature denied"));
        }
        Ok(checked)
    }
}
