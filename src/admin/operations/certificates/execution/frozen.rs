//! 原影响证明只解析一次并移动来源树，重复投递共享同一节点意图而不重建在线目标。

use crate::{
    admin::operations::model::Error,
    config::GatewaySnapshot,
    control::{
        material::{
            authorization,
            execution::{definition, position::Position},
            impact::{self, Context, Proof},
            node::{Intent, Selection},
        },
        ownership::config::Action,
    },
};
use nasa::saga::WorkflowDefinition;
use std::sync::Arc;

/// 两份原批准与认证候选的固定身份；当前审批状态和事务权威由共享存储入口另行复验。
pub(in crate::admin::operations) struct Approved<'a> {
    pub proof: Proof,
    pub context: Context<'a>,
    pub operation: &'a str,
    pub execution_store: &'a str,
    pub impact_id: &'a str,
    pub impact_epoch: u64,
    pub material_reviewer: &'a str,
    pub impact_creator: &'a str,
    pub impact_reviewer: &'a str,
    pub impact_digest: [u8; 32],
    pub candidate_bytes: u32,
    pub candidate_digest: [u8; 32],
}

pub(in crate::admin::operations) struct Frozen {
    pub nodes: Vec<Arc<Intent>>,
    pub definition: Arc<WorkflowDefinition>,
}

impl Frozen {
    /// 业务作用：将已核验全批证明按原物理节点冻结，保留逻辑目标原索引并移动每份完整来源树。
    ///
    /// 参数说明：
    /// - `approved`：同一原记录取得的四主体、独立存储、完整影响及认证候选摘要。
    ///
    /// 返回：所有节点意图均合法的完整任务；少节点、摘要漂移或任何不合法批准身份整批拒绝。
    pub(in crate::admin::operations) fn build(approved: Approved<'_>) -> Result<Self, Error> {
        if approved.proof.digest(&approved.context) != Some(approved.impact_digest) {
            return Err(Error::Conflict);
        }
        let definition =
            definition::cached(approved.proof.nodes.len()).map_err(|_| Error::Conflict)?;
        let count = approved.proof.nodes.len() as u32;
        let target_count = approved.proof.targets.len() as u32;
        let mut nodes = Vec::with_capacity(count as usize);
        for (index, node) in approved.proof.nodes.into_iter().enumerate() {
            // 证明已覆盖全部原目标；这里只沿原索引取基线，不能向当前成员目录借缺失节点。
            let first = &approved.proof.targets[node.target_indices[0] as usize];
            let selections: Arc<[Selection]> = node
                .target_indices
                .into_iter()
                .map(|index| Selection {
                    index,
                    target: approved.proof.targets[index as usize].target.clone(),
                })
                .collect();
            let intent = Arc::new(Intent {
                schema: 1,
                operation_id: approved.operation.into(),
                execution_store: approved.execution_store.into(),
                proposal_id: approved.context.proposal.into(),
                material_store: approved.context.material_store.into(),
                material_epoch: approved.context.material_epoch as u64,
                impact_id: approved.impact_id.into(),
                impact_store: approved.context.impact_store.into(),
                impact_epoch: approved.impact_epoch,
                material_creator: approved.context.material_creator.into(),
                material_reviewer: approved.material_reviewer.into(),
                impact_creator: approved.impact_creator.into(),
                impact_reviewer: approved.impact_reviewer.into(),
                scope: approved.context.scope.into(),
                material_intent_sha256: *approved.context.material_intent,
                impact_sha256: approved.impact_digest,
                authority_sha256: *approved.context.authority,
                impact_authority_sha256: *approved.context.impact_authority,
                target_count,
                node_id: node.node_id,
                original_boot_id: first.boot_id.clone(),
                baseline: first.node_baseline.clone(),
                base_version: first.base_version,
                base_fingerprint: u64::from_str_radix(&first.base_fingerprint, 16)
                    .map_err(|_| Error::Conflict)?,
                candidate_bytes: approved.candidate_bytes,
                candidate_sha256: approved.candidate_digest,
                selections,
                conditions: node.conditions,
            });
            Position {
                index: index as u32,
                count,
            }
            .fingerprint(&intent)
            .map_err(|_| Error::Conflict)?;
            nodes.push(intent);
        }
        Ok(Self {
            nodes,
            definition,
        })
    }

    /// 业务作用：为原工作流节点取得唯一物理位置，不把共享证书别名重复计入步骤分母。
    ///
    /// 参数说明：
    /// - `index`：独立材料定义已经校验的原物理节点序号。
    ///
    /// 返回：原共享意图与固定位置；越界拒绝，不搜索当前在线成员。
    pub(in crate::admin::operations) fn node(
        &self,
        index: usize,
    ) -> Result<(&Arc<Intent>, Position), Error> {
        let intent = self.nodes.get(index).ok_or(Error::Conflict)?;
        Ok((
            intent,
            Position {
                index: index as u32,
                count: self.nodes.len() as u32,
            },
        ))
    }

    /// 业务作用：把共享Outbox已证身份绑定到原材料任务，拒绝用配置步骤或另一个任务取得材料正文。
    ///
    /// 参数说明：
    /// - `pending`：唯一扫描器复验后的独立材料命令。
    ///
    /// 返回：原完整节点意图和物理位置；业务域、定义、集群、任务或分母不一致拒绝。
    pub(in crate::admin::operations) fn target(
        &self,
        pending: &crate::admin::operations::workflow::dispatch::Pending,
    ) -> Result<(&Arc<Intent>, Position), Error> {
        use crate::admin::operations::workflow::dispatch::Family;
        let (intent, position) = self.node(pending.target_index)?;
        if pending.family != Family::Material
            || pending.target_count != self.nodes.len()
            || pending.envelope.saga_id != intent.operation_id
            || pending.envelope.tenant_id != intent.baseline.cluster_id
            || pending.envelope.workflow != self.definition.name().as_str()
            || pending.envelope.definition_version != self.definition.version().get()
            || pending.envelope.definition_digest != self.definition.digest()
        {
            return Err(Error::Conflict);
        }
        Ok((intent, position))
    }

    /// 业务作用：共享发行每次复验四主体及全批原对象权威，单节点可见子集不能替代完整影响批准。
    ///
    /// 参数说明：
    /// - `snapshot`：本次事务与投递使用的当前完整管理快照。
    ///
    /// 返回：当前读取、两份写入与审阅资格及两份完整权威摘要均一致才成功；任一撤权拒绝整批。
    pub(in crate::admin::operations) fn authorize(
        &self,
        snapshot: &GatewaySnapshot,
    ) -> Result<(), Error> {
        let original = self.nodes.first().ok_or(Error::Conflict)?;
        for (principal, action) in [
            (&original.material_creator, Action::Write),
            (&original.material_reviewer, Action::Review),
            (&original.impact_creator, Action::Write),
            (&original.impact_reviewer, Action::Review),
        ] {
            authorization::check(&original.scope, snapshot, principal, Action::Read)
                .ok_or(Error::Denied)?;
            authorization::check(&original.scope, snapshot, principal, action)
                .ok_or(Error::Denied)?;
        }
        for intent in &self.nodes {
            authorization::logical_targets(
                &original.scope,
                snapshot,
                &intent.node_id,
                intent.selections.iter().map(|selection| &selection.target),
            )
            .ok_or(Error::Denied)?;
        }
        // 全批逻辑目标保持原顺序；来源影响另用原节点和全部共享对象生成独立审批权威。
        let material = authorization::logical_authority(
            &original.scope,
            snapshot,
            self.nodes
                .iter()
                .flat_map(|intent| intent.selections.iter().map(|selection| &selection.target)),
        );
        let affected = impact::source_authority(
            &original.scope,
            snapshot,
            self.nodes
                .iter()
                .map(|intent| (intent.node_id.as_str(), &intent.conditions)),
        );
        if material != Some(original.authority_sha256)
            || affected != Some(original.impact_authority_sha256)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
}
