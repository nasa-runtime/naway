//! 动作证明使用独立签名域与当前会话，发行身份握手不授予文件写权。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::Signer;
use super::Verifier;
use crate::control::actions::command::{Command, Validated};
use nasa::{grpc::Status, saga::WorkflowDefinition};

#[cfg(feature = "admin-operations-workflow-pgsql")]
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

    /// 业务作用：只为本发行者和固定集群的完整命令签名，避免同一私钥被用来声明其它管理身份。
    ///
    /// 参数说明：
    /// - `issuer`：当前已发布管理计划的本机节点身份。
    /// - `command`：已由执行适配器取得当前授权的完整命令声明。
    /// - `definition`：本机冻结的对应工作流定义。
    ///
    /// 返回：NASA Ed25519 签名；身份或合同不符拒绝，不代替执行适配器的租约和权限复验。
    pub(in crate::admin::management) fn sign_command(
        &self,
        issuer: &str,
        command: &Command,
        definition: &WorkflowDefinition,
    ) -> Result<String, Status> {
        // 发行者不能通过待签名内容选择另一集群或节点，签名材料始终来自当前冻结计划。
        if command.intent.baseline.cluster_id != self.cluster
            || command.delivery.issuer_node_id != issuer
        {
            return Err(Status::permission_denied("command issuer identity differs"));
        }
        let validated = command
            .validate(definition)
            .map_err(|_| Status::invalid_argument("invalid node command contract"))?;
        nasa::crypto::sign_ed25519(validated.message(), &self.private_key)
            .map_err(|_| Status::unavailable("node command proof unavailable"))
    }
}

impl Verifier {
    /// 业务作用：用当前受信发行者与原管理会话核对动作签名，旧连接或身份握手的证明不能授权本次命令。
    ///
    /// 参数说明：
    /// - `command`：同一响应中收到的有界类型化声明。
    /// - `signature`：发行者给出的动作签名。
    /// - `session`：调用方已经通过当前握手确认的原会话，不来自命令自报字段。
    /// - `definition`：本机冻结的对应工作流定义。
    ///
    /// 返回：签名与身份都一致时的验证视图；不检查实际目标、当前授权或租约，不触发文件副作用。
    pub(in crate::admin::management) fn verify_command(
        &self,
        command: &Command,
        signature: &str,
        session: &[u8],
        definition: &WorkflowDefinition,
    ) -> Result<Validated, Status> {
        // 先绑定本机当前信任域与会话，再验证完整动作摘要；不能接纳自报公钥或旧会话。
        if command.intent.baseline.cluster_id != self.cluster
            || command.delivery.issuer_node_id != self.node
            || signature.len() != 88
            || session.len() != 32
            || !crate::security::auth::constant_time_eq(session, &command.delivery.session)
        {
            return Err(Status::permission_denied("node command binding differs"));
        }
        let validated = command
            .validate(definition)
            .map_err(|_| Status::invalid_argument("invalid node command contract"))?;
        if !nasa::crypto::verify_ed25519(validated.message(), signature, &self.public_key) {
            return Err(Status::permission_denied("node command signature denied"));
        }
        Ok(validated)
    }
}
