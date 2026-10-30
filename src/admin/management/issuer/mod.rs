//! 管理端发行身份使用独立公钥证明；TLS 和该证明均不授予配置动作权限。

#[cfg(feature = "node-actions")]
mod command;
#[cfg(feature = "node-actions")]
mod preview;
mod proof;
#[cfg(feature = "node-actions")]
mod release;

use super::{plan::stamp, protocol, security};
use crate::config::management::{Issuer, TrustedIssuer};
use anyhow::{ensure, Result};
use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use nasa::grpc::Status;
use sha2::Sha256;
use std::{path::Path, sync::Arc};

pub(super) struct Signer {
    cluster: String,
    private_key: String,
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    public_key: String,
}

pub(super) struct Verifier {
    cluster: String,
    node: String,
    public_key: String,
}

impl Signer {
    /// 业务作用：把本机发行身份与永久节点目录所属集群进行比较，不暴露签名材料。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：构建时冻结的发行集群标识。
    #[cfg(feature = "node-journal")]
    pub(super) fn cluster(&self) -> &str {
        &self.cluster
    }

    /// 业务作用：在候选构建时冻结发行密钥并证明私钥与声明公钥配对，关闭时不读取秘密。
    ///
    /// 参数说明：
    /// - `cfg`：接收端独立的发行身份开关和材料来源。
    /// - `root`：SecretSource 文件的配置根。
    /// - `authority`：管理计划的同代权威摘要。
    ///
    /// 返回：关闭时为空；有效配对进入不可变计划，材料或集群错误拒绝候选。
    pub(super) fn build(cfg: &Issuer, root: &Path, authority: &mut Sha256) -> Result<Option<Self>> {
        stamp(authority, &[u8::from(cfg.enabled)]);
        if !cfg.enabled {
            return Ok(None);
        }
        ensure!(
            crate::config::operations::token(&cfg.cluster_id, 128),
            "invalid issuer cluster_id"
        );
        let private_key = material(&cfg.private_key, root)?;
        let public_key = public_key(&cfg.public_key, root)?;
        let signature = nasa::crypto::sign_ed25519("naway-management-key-pair", &private_key)
            .map_err(|_| anyhow::anyhow!("invalid management issuer private key"))?;
        ensure!(
            nasa::crypto::verify_ed25519("naway-management-key-pair", &signature, &public_key),
            "management issuer key pair differs"
        );
        for value in [&cfg.cluster_id, &private_key, &public_key] {
            stamp(authority, value.as_bytes());
        }
        Ok(Some(Self {
            cluster: cfg.cluster_id.clone(),
            private_key,
            #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
            public_key,
        }))
    }

    /// 业务作用：为已通过当前证书和会话门的单次挑战出具发行身份，不生成可执行命令。
    ///
    /// 参数说明：
    /// - `issuer`：当前已发布管理计划的本机节点身份。
    /// - `request`：已验证的远端节点、启动、会话与随机挑战。
    ///
    /// 返回：固定协议的有界签名证明；签名失败不泄露密钥或请求内容。
    pub(super) fn prove(
        &self,
        issuer: &str,
        request: &protocol::IssuerChallenge,
    ) -> Result<protocol::IssuerProof, Status> {
        let message = proof::message(&self.cluster, issuer, request)?;
        let signature = nasa::crypto::sign_ed25519(&message, &self.private_key)
            .map_err(|_| Status::unavailable("issuer proof unavailable"))?;
        Ok(protocol::IssuerProof {
            schema: 1,
            cluster_id: self.cluster.clone(),
            issuer_node_id: issuer.into(),
            signature,
        })
    }
}

impl Verifier {
    /// 业务作用：确认目录owner的所有管理目标仍属于同一已声明信任域。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本目标必须证明的集群标识，不返回公钥或会话材料。
    #[cfg(feature = "node-journal")]
    pub(super) fn cluster(&self) -> &str {
        &self.cluster
    }

    /// 业务作用：冻结特定上报端点的发行者绑定，禁止服务器自报身份决定信任范围。
    ///
    /// 参数说明：
    /// - `cfg`：显式验证开关、集群、Admin节点及公钥来源。
    /// - `root`：SecretSource 文件的配置根。
    /// - `authority`：当前管理计划的权威摘要。
    ///
    /// 返回：关闭时为空；有效绑定使用Arc共享，错误材料拒绝候选。
    pub(super) fn build(
        cfg: &TrustedIssuer,
        root: &Path,
        authority: &mut Sha256,
    ) -> Result<Option<Arc<Self>>> {
        stamp(authority, &[u8::from(cfg.enabled)]);
        if !cfg.enabled {
            return Ok(None);
        }
        ensure!(
            crate::config::operations::token(&cfg.cluster_id, 128)
                && security::identifier(&cfg.node_id),
            "invalid trusted issuer identity"
        );
        let public_key = public_key(&cfg.public_key, root)?;
        for value in [&cfg.cluster_id, &cfg.node_id, &public_key] {
            stamp(authority, value.as_bytes());
        }
        Ok(Some(Arc::new(Self {
            cluster: cfg.cluster_id.clone(),
            node: cfg.node_id.clone(),
            public_key,
        })))
    }

    /// 业务作用：只接受当前单次挑战的精确发行者证明，不把其它节点或旧握手签名用于本会话。
    ///
    /// 参数说明：
    /// - `request`：调用方仍在同一绝对期限内等待的原始挑战。
    /// - `response`：该RPC返回的有界证明。
    ///
    /// 返回：协议、集群、节点及签名全部匹配才成功；任何差异拒绝建立本地会话。
    pub(super) fn verify(
        &self,
        request: &protocol::IssuerChallenge,
        response: &protocol::IssuerProof,
    ) -> Result<(), Status> {
        // 对端声明不能选择信任密钥或协议；先固定本地允许的身份，再验证完整挑战摘要。
        if response.schema != 1
            || response.cluster_id != self.cluster
            || response.issuer_node_id != self.node
            || response.signature.len() != 88
        {
            return Err(Status::permission_denied("issuer proof identity differs"));
        }
        let message = proof::message(&self.cluster, &self.node, request)?;
        if !nasa::crypto::verify_ed25519(&message, &response.signature, &self.public_key) {
            return Err(Status::permission_denied("issuer proof signature denied"));
        }
        Ok(())
    }
}

/// 业务作用：在构建期有界解析发行身份材料，运行握手不读取环境或文件。
///
/// 参数说明：
/// - `source`：已有SecretSource支持的文本来源。
/// - `root`：相对文件的配置根。
///
/// 返回：非空且最多2048字节的材料；错误只包含字段名。
fn material(source: &str, root: &Path) -> Result<String> {
    let value = crate::security::secret::resolve_text(source, root, "admin.management issuer key")
        .map_err(|_| anyhow::anyhow!("management issuer key source unavailable"))?;
    ensure!(
        !value.is_empty() && value.len() <= 2048,
        "management issuer key size invalid"
    );
    Ok(value)
}

/// 业务作用：拒绝畸形或弱Ed25519公钥，不能让固定身份绑定退化为不可信签名接受条件。
///
/// 参数说明：
/// - `source`：Base64 SPKI公钥的SecretSource。
/// - `root`：相对文件的配置根。
///
/// 返回：NASA可验证的原公钥文本；解析或强度不成立时阻断计划发布。
fn public_key(source: &str, root: &Path) -> Result<String> {
    let value = material(source, root)?;
    let parsed = base64::engine::general_purpose::STANDARD
        .decode(&value)
        .ok()
        .and_then(|der| ed25519_dalek::VerifyingKey::from_public_key_der(&der).ok());
    ensure!(
        parsed.is_some_and(|key| !key.is_weak()),
        "invalid management issuer public key"
    );
    Ok(value)
}
