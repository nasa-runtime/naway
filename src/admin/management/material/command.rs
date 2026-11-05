//! 独立签名冻结整批原目标与绝对期限，索引不因节点缺席而改变。

use crate::{
    config::operations::token,
    control::{actions::authorization::Scope, baseline::NodeBaseline},
    tls::targets::Target,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::admin) enum Query {
    Conditions,
    Installations,
}

impl Query {
    /// 业务作用：每种材料读取只使用自己的显式开关，文件条件许可不能授予实际安装观察权。
    ///
    /// 参数说明：
    /// - `plan`：当前已发布并绑定本会话的管理计划。
    ///
    /// 返回：对应只读能力已经明确启用时为真，不推断其它材料或执行能力。
    pub(in crate::admin) fn enabled(self, plan: &super::super::Plan) -> bool {
        match self {
            Self::Conditions => plan.material_previews_enabled,
            Self::Installations => plan.material_installations_enabled,
        }
    }
}

pub(in crate::admin) struct Intent {
    pub query_kind: Query,
    pub query: String,
    pub count: u32,
    pub indices: Vec<u32>,
    pub targets: Vec<Target>,
    pub node: String,
    pub boot: String,
    pub baseline: NodeBaseline,
    pub version: u64,
    pub fingerprint: u64,
    pub scope: String,
    pub principal: String,
    pub authority: [u8; 32],
}

pub(in crate::admin) struct Command {
    pub intent: std::sync::Arc<Intent>,
    pub issuer: String,
    pub session: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Command {
    /// 业务作用：签名完整节点批次，重复索引、重复目标或改变分母均不能复用原查询证明。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：对应只读查询独立域的 SHA-256 文本；非法或无界声明拒绝，不授予文件写权。
    pub(in crate::admin) fn message(&self) -> Result<String> {
        let intent = &self.intent;
        ensure!(
            intent.query.len() == 32
                && intent
                    .query
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && (1..=128).contains(&intent.count)
                && !intent.targets.is_empty()
                && intent.targets.len() <= intent.count as usize
                && intent.indices.len() == intent.targets.len()
                && intent.indices.iter().all(|index| *index < intent.count)
                && intent.indices.windows(2).all(|pair| pair[0] < pair[1])
                && intent.targets.iter().all(Target::valid)
                && super::super::security::identifier(&intent.node)
                && super::super::security::identifier(&intent.boot)
                && intent.baseline.valid()
                && intent.version > 0
                && Scope::parse(&intent.scope).is_some()
                && token(&intent.principal, 128)
                && super::super::security::identifier(&self.issuer)
                && self.issued_at_ms > 0
                && self
                    .expires_at_ms
                    .checked_sub(self.issued_at_ms)
                    .is_some_and(|span| (1..=20_000).contains(&span))
                && self.expires_at_ms <= i64::MAX as u64,
            "invalid material conditions contract"
        );
        let mut identities = std::collections::BTreeSet::new();
        ensure!(
            intent.targets.iter().all(|target| identities.insert((
                target.kind as u8,
                &target.listener,
                &target.entry
            ))),
            "duplicate material conditions target"
        );
        let mut hash = Sha256::new();
        hash.update(match intent.query_kind {
            Query::Conditions => b"naway-material-conditions-command\0".as_slice(),
            Query::Installations => b"naway-material-installations-command\0".as_slice(),
        });
        hash.update(1_u32.to_be_bytes());
        for field in [
            intent.query.as_bytes(),
            &intent.count.to_be_bytes(),
            intent.node.as_bytes(),
            intent.boot.as_bytes(),
            &intent.baseline.schema.to_be_bytes(),
            intent.baseline.cluster_id.as_bytes(),
            intent.baseline.store_id.as_bytes(),
            intent.baseline.node_admission_epoch.as_bytes(),
            intent.baseline.documents_sha256.as_bytes(),
            &intent.version.to_be_bytes(),
            &intent.fingerprint.to_be_bytes(),
            intent.scope.as_bytes(),
            intent.principal.as_bytes(),
            &intent.authority,
            self.issuer.as_bytes(),
            &self.session,
            &self.issued_at_ms.to_be_bytes(),
            &self.expires_at_ms.to_be_bytes(),
        ] {
            super::super::plan::stamp(&mut hash, field);
        }
        for (index, target) in intent.indices.iter().zip(&intent.targets) {
            for field in [
                &index.to_be_bytes()[..],
                &[target.kind as u8],
                target.listener.as_bytes(),
                target.entry.as_bytes(),
            ] {
                super::super::plan::stamp(&mut hash, field);
            }
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}
