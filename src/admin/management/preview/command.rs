//! 预览证明绑定原提案和原目标，不包含持久动作步骤、租约或文件发布权。

use crate::{
    config::operations::{token, MAX_TARGETS},
    control::{actions::domain::Domain, baseline::NodeBaseline},
};
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

pub(in crate::admin) struct Intent {
    pub proposal: String,
    pub epoch: u64,
    pub index: u32,
    pub count: u32,
    pub domain: Domain,
    pub node: String,
    pub boot: String,
    pub baseline: NodeBaseline,
    pub version: u64,
    pub fingerprint: u64,
    pub candidate_bytes: u32,
    pub candidate_sha256: [u8; 32],
    pub scope: String,
    pub creator: String,
    pub principal: String,
    pub authority: [u8; 32],
}

pub(in crate::admin) struct Command {
    pub intent: Intent,
    pub issuer: String,
    pub session: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Command {
    /// 业务作用：为一次只读候选构建生成独立签名消息，全部原目标证明必须完整进入摘要。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界字段合法时返回固定域 SHA-256 文本；无效身份或时间声明拒绝，不授予构建权限。
    pub(in crate::admin) fn message(&self) -> Result<String> {
        let intent = &self.intent;
        ensure!(
            intent.proposal.len() == 32
                && intent
                    .proposal
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                && (1..=i64::MAX as u64).contains(&intent.epoch)
                && (1..=MAX_TARGETS as u32).contains(&intent.count)
                && intent.index < intent.count
                && super::super::security::identifier(&intent.node)
                && super::super::security::identifier(&intent.boot)
                && intent.baseline.valid()
                && intent.version > 0
                && (1..=1024 * 1024).contains(&intent.candidate_bytes)
                && (intent.scope == "platform"
                    || intent
                        .scope
                        .strip_prefix("workspace.")
                        .is_some_and(|id| token(id, 118)))
                && token(&intent.creator, 128)
                && token(&intent.principal, 128)
                && super::super::security::identifier(&self.issuer)
                && self.issued_at_ms > 0
                && self
                    .expires_at_ms
                    .checked_sub(self.issued_at_ms)
                    .is_some_and(|span| (1..=20_000).contains(&span))
                && self.expires_at_ms <= i64::MAX as u64,
            "invalid node preview contract"
        );
        let mut digest = Sha256::new();
        digest.update(b"naway-node-preview-command\0");
        digest.update(1_u32.to_be_bytes());
        for field in [
            intent.proposal.as_bytes(),
            &intent.epoch.to_be_bytes(),
            &intent.index.to_be_bytes(),
            &intent.count.to_be_bytes(),
            intent.domain.identity().0.as_bytes(),
            intent.node.as_bytes(),
            intent.boot.as_bytes(),
            &intent.baseline.schema.to_be_bytes(),
            intent.baseline.cluster_id.as_bytes(),
            intent.baseline.store_id.as_bytes(),
            intent.baseline.node_admission_epoch.as_bytes(),
            intent.baseline.documents_sha256.as_bytes(),
            &intent.version.to_be_bytes(),
            &intent.fingerprint.to_be_bytes(),
            &intent.candidate_bytes.to_be_bytes(),
            &intent.candidate_sha256,
            intent.scope.as_bytes(),
            intent.creator.as_bytes(),
            intent.principal.as_bytes(),
            &intent.authority,
            self.issuer.as_bytes(),
            &self.session,
            &self.issued_at_ms.to_be_bytes(),
            &self.expires_at_ms.to_be_bytes(),
        ] {
            super::super::plan::stamp(&mut digest, field);
        }
        Ok(format!("{:x}", digest.finalize()))
    }
}
