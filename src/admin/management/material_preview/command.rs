//! 候选预检独立绑定原提案和材料，条件查询签名不能授权秘密下载。

use crate::admin::management::material::command as conditions;
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(in crate::admin) struct Pair {
    pub certificate_etag: String,
    pub material_generation: String,
}

pub(in crate::admin) struct Intent {
    pub original: Arc<conditions::Intent>,
    pub proposal: String,
    pub store: String,
    pub epoch: i64,
    pub creator: String,
    pub proposal_authority: [u8; 32],
    pub proposal_intent: [u8; 32],
    pub pairs: Vec<Pair>,
    pub candidate_bytes: u32,
    pub candidate_sha256: [u8; 32],
}

impl std::ops::Deref for Intent {
    type Target = conditions::Intent;

    /// 业务作用：借用同一原目标批次的节点和权限字段，预检额外条件不复制整份目标身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只读原批次声明，不能据此取得条件查询之外的签名资格。
    fn deref(&self) -> &Self::Target {
        &self.original
    }
}

pub(in crate::admin) struct Command {
    pub intent: Arc<Intent>,
    pub issuer: String,
    pub session: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Command {
    /// 业务作用：借用原目标批次组成公共基线声明，仅用于字段校验和网络适配，不签发条件查询授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：共享原批次的有限元数据，不复制目标数组或任何材料。
    pub(super) fn conditions(&self) -> conditions::Command {
        conditions::Command {
            intent: self.intent.original.clone(),
            issuer: self.issuer.clone(),
            session: self.session,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        }
    }

    /// 业务作用：独立签名原提案、全部原条件与候选摘要，查询或审批证明不能被挪作秘密下载授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：带独立域和长度边界的完整摘要；任何不规范身份、无界材料或错位原条件拒绝。
    pub(in crate::admin) fn message(&self) -> Result<String> {
        let intent = &self.intent;
        let hexadecimal = |value: &str, length| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        ensure!(
            hexadecimal(&intent.proposal, 32)
                && hexadecimal(&intent.store, 64)
                && intent.epoch > 0
                && crate::config::operations::token(&intent.creator, 128)
                && (17..=1024 * 1024 + 16).contains(&intent.candidate_bytes)
                && intent.pairs.len() == intent.targets.len()
                && intent.pairs.iter().all(|pair| {
                    hexadecimal(&pair.material_generation, 64)
                        && pair
                            .certificate_etag
                            .strip_prefix("\"sha256-")
                            .and_then(|value| value.strip_suffix('"'))
                            .is_some_and(|value| hexadecimal(value, 64))
                }),
            "invalid material preview contract"
        );
        let baseline = self.conditions().message()?;
        let mut hash = Sha256::new();
        hash.update(b"naway-material-preview-command\0");
        hash.update(1u32.to_be_bytes());
        for field in [
            baseline.as_bytes(),
            intent.proposal.as_bytes(),
            intent.store.as_bytes(),
            &intent.epoch.to_be_bytes(),
            intent.creator.as_bytes(),
            &intent.proposal_authority,
            &intent.proposal_intent,
            &intent.candidate_bytes.to_be_bytes(),
            &intent.candidate_sha256,
        ] {
            super::super::plan::stamp(&mut hash, field);
        }
        for pair in &intent.pairs {
            super::super::plan::stamp(&mut hash, pair.certificate_etag.as_bytes());
            super::super::plan::stamp(&mut hash, pair.material_generation.as_bytes());
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}
