//! 节点材料意图只保存本节点完整来源，原索引与全批批准摘要不能由在线目录重建。

use crate::{
    config::operations::token,
    control::{actions::authorization::Scope, baseline::NodeBaseline},
    tls::{keypair::conditions::Batch, targets::Target},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const MAX_GROUPS: usize = 32;
pub(crate) const MAX_CANDIDATE_BYTES: u32 = 1024 * 1024 + 16;

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub index: u32,
    pub target: Target,
}

/// 完整原生意图不包含PEM和活动路径，也不提供携带秘密摘要的诊断格式。
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub schema: u32,
    pub operation_id: String,
    pub execution_store: String,
    pub proposal_id: String,
    pub material_store: String,
    pub material_epoch: u64,
    pub impact_id: String,
    pub impact_store: String,
    pub impact_epoch: u64,
    pub material_creator: String,
    pub material_reviewer: String,
    pub impact_creator: String,
    pub impact_reviewer: String,
    pub scope: String,
    pub material_intent_sha256: [u8; 32],
    pub impact_sha256: [u8; 32],
    pub authority_sha256: [u8; 32],
    pub impact_authority_sha256: [u8; 32],
    pub target_count: u32,
    pub node_id: String,
    pub original_boot_id: String,
    pub baseline: NodeBaseline,
    pub base_version: u64,
    pub base_fingerprint: u64,
    pub candidate_bytes: u32,
    pub candidate_sha256: [u8; 32],
    pub selections: Arc<[Selection]>,
    pub conditions: Batch,
}

impl Intent {
    /// 业务作用：固定节点原意图与全批关联，签名和持久状态不能通过重新分组省略共享来源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部身份、原索引和完整来源结构成立时生成流式摘要；不证明当前权限或外部批准仍有效。
    pub(crate) fn fingerprint(&self) -> Result<[u8; 32]> {
        ensure!(
            self.schema == 1
                && hexadecimal(&self.operation_id, 32)
                && hexadecimal(&self.execution_store, 64)
                && hexadecimal(&self.proposal_id, 32)
                && hexadecimal(&self.material_store, 64)
                && hexadecimal(&self.impact_id, 32)
                && hexadecimal(&self.impact_store, 64)
                && (1..=i64::MAX as u64).contains(&self.material_epoch)
                && (1..=i64::MAX as u64).contains(&self.impact_epoch)
                && Scope::parse(&self.scope).is_some()
                && self.baseline.valid()
                && token(&self.node_id, 128)
                && token(&self.original_boot_id, 128)
                && self.base_version > 0
                && (18..=MAX_CANDIDATE_BYTES).contains(&self.candidate_bytes)
                && (1..=crate::config::operations::MAX_TARGETS as u32).contains(&self.target_count),
            "invalid material node intent identity"
        );
        // 两份批准各自保留真实主体，旧材料审阅不能隐式替代完整影响审阅。
        ensure!(
            [
                &self.material_creator,
                &self.material_reviewer,
                &self.impact_creator,
                &self.impact_reviewer,
            ]
            .iter()
            .all(|principal| token(principal, 128))
                && self.material_creator != self.material_reviewer
                && self.impact_reviewer != self.material_creator
                && self.impact_reviewer != self.impact_creator,
            "invalid material node approval identities"
        );
        ensure!(
            !self.selections.is_empty()
                && self.selections.len() <= self.target_count as usize
                && self.selections.iter().all(|selection| {
                    selection.index < self.target_count && selection.target.valid()
                })
                && self.selections.windows(2).all(|pair| {
                    pair[0].index.checked_add(1) == Some(pair[1].index)
                        && target_key(&pair[0].target) < target_key(&pair[1].target)
                }),
            "invalid material node original target indices"
        );
        ensure!(
            self.conditions.groups.len() <= MAX_GROUPS
                && super::conditions::validate(
                    &self.conditions,
                    self.selections.iter().map(|selection| &selection.target),
                )
                .is_ok()
                && self
                    .conditions
                    .groups
                    .iter()
                    .all(|group| group.material_generation.is_some())
                && self.conditions.entries.iter().all(|entry| {
                    !matches!(entry.source, crate::tls::keypair::conditions::Source::Acme)
                }),
            "invalid material node complete source conditions"
        );
        // 一个物理来源只有一种文件决定语义，共享别名不能同时声称legacy与manifest模式。
        for group in 0..self.conditions.groups.len() {
            let mut entries = self
                .conditions
                .entries
                .iter()
                .filter(|entry| entry.group == group);
            let first = entries
                .next()
                .expect("complete conditions reference every group");
            ensure!(
                entries.all(|entry| entry.source == first.source),
                "material source modes differ"
            );
        }
        let mut hash = Sha256::new();
        hash.update(b"naway-node-material-intent\0");
        hash.update(self.schema.to_be_bytes());
        for field in [
            self.operation_id.as_bytes(),
            self.execution_store.as_bytes(),
            self.proposal_id.as_bytes(),
            self.material_store.as_bytes(),
            &self.material_epoch.to_be_bytes(),
            self.impact_id.as_bytes(),
            self.impact_store.as_bytes(),
            &self.impact_epoch.to_be_bytes(),
            self.material_creator.as_bytes(),
            self.material_reviewer.as_bytes(),
            self.impact_creator.as_bytes(),
            self.impact_reviewer.as_bytes(),
            self.scope.as_bytes(),
            &self.material_intent_sha256,
            &self.impact_sha256,
            &self.authority_sha256,
            &self.impact_authority_sha256,
            &self.target_count.to_be_bytes(),
            self.node_id.as_bytes(),
            self.original_boot_id.as_bytes(),
            &self.baseline.schema.to_be_bytes(),
            self.baseline.cluster_id.as_bytes(),
            self.baseline.store_id.as_bytes(),
            self.baseline.node_admission_epoch.as_bytes(),
            self.baseline.documents_sha256.as_bytes(),
            &self.base_version.to_be_bytes(),
            &self.base_fingerprint.to_be_bytes(),
            &self.candidate_bytes.to_be_bytes(),
            &self.candidate_sha256,
        ] {
            stamp(&mut hash, field);
        }
        hash.update((self.selections.len() as u32).to_be_bytes());
        for selection in self.selections.iter() {
            hash.update(selection.index.to_be_bytes());
            hash.update([selection.target.kind as u8]);
            stamp(&mut hash, selection.target.listener.as_bytes());
            stamp(&mut hash, selection.target.entry.as_bytes());
        }
        hash.update(super::conditions::digest(&self.conditions));
        Ok(hash.finalize().into())
    }
}

/// 业务作用：限定永久存储和动作身份的唯一编码，拒绝大小写或长度歧义。
///
/// 参数说明：
/// - `value`：受约束的原身份。
/// - `length`：该身份合同指定的固定字符数。
///
/// 返回：精确小写十六进制表示才为真。
pub(crate) fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// 业务作用：保持本节点逻辑目标与全批原排序一致，别名不能改变索引解释。
///
/// 参数说明：
/// - `target`：经过结构校验的逻辑身份。
///
/// 返回：借用原名称的排序键，不复制对象或读取配置。
fn target_key(target: &Target) -> (u8, &str, &str) {
    (target.kind as u8, &target.listener, &target.entry)
}

/// 业务作用：为摘要加入明确字段边界，不依赖JSON对象顺序或中间编码。
///
/// 参数说明：
/// - `hash`：当前节点意图的增量摘要。
/// - `bytes`：原字段的借用。
///
/// 返回：加入长度和内容，不创建完整序列化副本。
fn stamp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
