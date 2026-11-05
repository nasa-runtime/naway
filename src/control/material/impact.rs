//! 完整影响是固定原目标的独立批准对象，摘要不依赖 JSON 表示或网络消息类型。

use super::{Summary, Target, authorization, conditions};
use crate::{config::GatewaySnapshot, tls::keypair::conditions::Batch};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Node {
    pub node_id: String,
    pub target_indices: Vec<u32>,
    pub conditions: Batch,
    pub impact_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    pub schema: u32,
    pub targets: Arc<[Target]>,
    pub certificate: Summary,
    pub nodes: Vec<Node>,
}

pub(crate) struct Context<'a> {
    pub cluster: &'a str,
    pub material_store: &'a str,
    pub impact_store: &'a str,
    pub proposal: &'a str,
    pub scope: &'a str,
    pub material_creator: &'a str,
    pub material_epoch: i64,
    pub material_intent: &'a [u8; 32],
    pub authority: &'a [u8; 32],
    pub impact_authority: &'a [u8; 32],
    pub issued: u64,
    pub observed_until: u64,
}

impl Proof {
    /// 业务作用：验证每个原目标恰好属于一个完整节点证明，失败、遗漏或重新分组不能进入批准对象。
    ///
    /// 参数说明：
    /// - `cluster`：原材料的永久发行集群。
    ///
    /// 返回：规范完整分母、原材料条件和公开证书均成立时为真；不按当前在线目录补齐内容。
    pub(crate) fn valid(&self, cluster: &str) -> bool {
        if self.schema != 1
            || !Target::valid_set(&self.targets, cluster)
            || self.nodes.is_empty()
            || self.nodes.len() > self.targets.len()
            || !hexadecimal(&self.certificate.certificate_sha256, 64)
            || !hexadecimal(&self.certificate.leaf_sha256, 64)
            || !(1..=32).contains(&self.certificate.chain_length)
            || self.certificate.not_after_seconds <= self.certificate.not_before_seconds
        {
            return false;
        }
        let mut offset = 0;
        for node in &self.nodes {
            let Some(first) = self.targets.get(offset) else {
                return false;
            };
            let count = self.targets[offset..]
                .iter()
                .take_while(|target| target.node_id == first.node_id)
                .count();
            if node.node_id != first.node_id
                || node.target_indices.len() != count
                || !node
                    .target_indices
                    .iter()
                    .copied()
                    .eq((offset..offset + count).map(|index| index as u32))
            {
                return false;
            }
            let targets = &self.targets[offset..offset + count];
            if conditions::validate(
                &node.conditions,
                targets.iter().map(|target| &target.target),
            )
            .is_err()
                || node.impact_sha256 != super::hex(&conditions::digest(&node.conditions))
            {
                return false;
            }
            // 完整来源证明仍必须是原 pair 的观测，不能把后来的材料代偷偷替换为审批时的基线。
            for (target, entry) in targets.iter().zip(&node.conditions.entries) {
                let group = &node.conditions.groups[entry.group];
                if group.certificate_etag != target.certificate_etag
                    || group.material_generation.as_deref() != Some(&target.material_generation)
                    || matches!(entry.source, crate::tls::keypair::conditions::Source::Acme)
                {
                    return false;
                }
            }
            offset += count;
        }
        offset == self.targets.len()
    }

    /// 业务作用：冻结并复验全部共享对象归属，原目标有权限不能代替共享文件影响的其它对象权限。
    ///
    /// 参数说明：
    /// - `scope`：当前唯一平台或工作区域。
    /// - `snapshot`：当前完整权限和归属快照。
    ///
    /// 返回：覆盖全部节点、完整来源及影响顺序的当前权威摘要；任一对象不属于当前域则为空。
    pub(crate) fn authority(&self, scope: &str, snapshot: &GatewaySnapshot) -> Option<[u8; 32]> {
        authorization::targets(scope, snapshot, &self.targets)?;
        let mut hash = Sha256::new();
        hash.update(b"naway-material-impact-authority\0");
        hash.update((self.nodes.len() as u32).to_be_bytes());
        for node in &self.nodes {
            let targets = || {
                node.conditions
                    .groups
                    .iter()
                    .flat_map(|group| group.affected.iter().map(|affected| &affected.target))
            };
            authorization::logical_targets(scope, snapshot, &node.node_id, targets())?;
            field(&mut hash, node.node_id.as_bytes());
            hash.update(authorization::logical_authority(
                scope,
                snapshot,
                targets(),
            )?);
        }
        Some(hash.finalize().into())
    }

    /// 业务作用：绑定原材料身份、所有原条件和完整影响，独立审批不能重放到另一 owner 或候选。
    ///
    /// 参数说明：
    /// - `context`：已由持久原记录和当前完整权限构造的固定上下文。
    ///
    /// 返回：规范完整对象的增量摘要；任何身份、窗口或来源结构异常均拒绝，不序列化中间 JSON。
    pub(crate) fn digest(&self, context: &Context<'_>) -> Option<[u8; 32]> {
        if !self.valid(context.cluster)
            || !hexadecimal(context.material_store, 64)
            || !hexadecimal(context.impact_store, 64)
            || !hexadecimal(context.proposal, 32)
            || context.material_epoch <= 0
            || context.issued == 0
            || context.observed_until <= context.issued
            || context.observed_until.checked_sub(context.issued)? > 20_000
            || !crate::config::operations::token(context.material_creator, 128)
            || crate::control::actions::authorization::Scope::parse(context.scope).is_none()
        {
            return None;
        }
        let mut hash = Sha256::new();
        hash.update(b"naway-material-impact-approval\0");
        hash.update(self.schema.to_be_bytes());
        for value in [
            context.cluster,
            context.material_store,
            context.impact_store,
            context.proposal,
            context.scope,
            context.material_creator,
        ] {
            field(&mut hash, value.as_bytes());
        }
        hash.update(context.material_epoch.to_be_bytes());
        hash.update(context.material_intent);
        hash.update(context.authority);
        hash.update(context.impact_authority);
        hash.update(context.issued.to_be_bytes());
        hash.update(context.observed_until.to_be_bytes());
        field(&mut hash, self.certificate.certificate_sha256.as_bytes());
        field(&mut hash, self.certificate.leaf_sha256.as_bytes());
        hash.update(self.certificate.chain_length.to_be_bytes());
        hash.update(self.certificate.not_before_seconds.to_be_bytes());
        hash.update(self.certificate.not_after_seconds.to_be_bytes());
        hash.update((self.targets.len() as u32).to_be_bytes());
        for target in self.targets.iter() {
            field(&mut hash, target.node_id.as_bytes());
            field(&mut hash, target.boot_id.as_bytes());
            hash.update(target.base_version.to_be_bytes());
            field(&mut hash, target.base_fingerprint.as_bytes());
            hash.update(target.node_baseline.schema.to_be_bytes());
            for value in [
                &target.node_baseline.cluster_id,
                &target.node_baseline.store_id,
                &target.node_baseline.node_admission_epoch,
                &target.node_baseline.documents_sha256,
            ] {
                field(&mut hash, value.as_bytes());
            }
            hash.update([target.target.kind as u8]);
            for value in [
                &target.target.listener,
                &target.target.entry,
                &target.certificate_etag,
                &target.material_generation,
            ] {
                field(&mut hash, value.as_bytes());
            }
        }
        hash.update((self.nodes.len() as u32).to_be_bytes());
        for node in &self.nodes {
            field(&mut hash, node.node_id.as_bytes());
            hash.update((node.target_indices.len() as u32).to_be_bytes());
            for index in &node.target_indices {
                hash.update(index.to_be_bytes());
            }
            hash.update(conditions::digest(&node.conditions));
        }
        Some(hash.finalize().into())
    }
}

/// 业务作用：统一固定身份和公开摘要的唯一文本表示，不能接受大小写或长度歧义。
///
/// 参数说明：
/// - `value`：原身份或摘要文本。
/// - `length`：合同指定的字符数。
///
/// 返回：精确小写十六进制表示才为真。
fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// 业务作用：保持可变长字段的明确边界，不因字符串拼接方式不同产生同一审批摘要。
///
/// 参数说明：
/// - `hash`：当前完整影响摘要。
/// - `value`：只借用的原字段字节。
///
/// 返回：按长度和内容更新摘要，不分配材料或来源副本。
fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}
