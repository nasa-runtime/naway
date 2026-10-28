//! 执行只消费原审批意图，候选字节共享且目标不随当前在线成员变化。

use crate::{
    admin::operations::{
        model::{Domain, Error, Target},
        workflow::dispatch::Pending,
    },
    control::actions::{command::Intent, definition},
};
use bytes::Bytes;
use nasa::saga::WorkflowDefinition;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Row};
use std::sync::Arc;

pub(in crate::admin::operations) struct Frozen {
    pub(in crate::admin::operations) body: Bytes,
    pub(in crate::admin::operations) targets: Vec<Intent>,
    pub(in crate::admin::operations) definition: Arc<WorkflowDefinition>,
}

struct Source {
    id: String,
    epoch: i64,
    scope: String,
    domain: String,
    creator: String,
    reviewer: Option<String>,
    authority: Vec<u8>,
    digest: Vec<u8>,
    body: Vec<u8>,
    targets: Vec<u8>,
}

impl Frozen {
    /// 业务作用：把受当前事务保护的原审批行转换成有界执行意图，不补选节点或重编码候选。
    ///
    /// 参数说明：
    /// - `row`：显式选择原提案身份、审批、候选和目标字段的数据库行。
    /// - `cluster`：共享存储已绑定的唯一集群。
    ///
    /// 返回：正文只保留一份 Bytes 的冻结执行；旧零代际、缺基线或不完整审批不获得执行资格。
    pub(in crate::admin::operations) fn from_row(
        row: &PgRow,
        cluster: &str,
    ) -> Result<Self, Error> {
        let source = (|| -> Result<Source, sqlx::Error> {
            Ok(Source {
                id: row.try_get("id")?,
                epoch: row.try_get("admission_epoch")?,
                scope: row.try_get("scope")?,
                domain: row.try_get("domain")?,
                creator: row.try_get("creator")?,
                reviewer: row.try_get("reviewer")?,
                authority: row.try_get("authority")?,
                digest: row.try_get("candidate_digest")?,
                body: row.try_get("candidate")?,
                targets: row.try_get("targets")?,
            })
        })()
        .map_err(|_| Error::Unavailable)?;
        Self::build(source, cluster)
    }

    /// 业务作用：复验固定字节、完整目标顺序和基线身份，让旧记录的可读性与执行资格分开判定。
    ///
    /// 参数说明：
    /// - `source`：同一持久记录的原始有界字段。
    /// - `cluster`：当前不可变执行命名空间。
    ///
    /// 返回：每目标唯一 Intent 与共享原文；任何目标缺席、乱序、跨集群或摘要不符都拒绝整体构造。
    fn build(source: Source, cluster: &str) -> Result<Self, Error> {
        if source.epoch <= 0 || source.reviewer.is_none() {
            return Err(Error::Conflict);
        }
        if source.body.is_empty()
            || source.body.len() > 1024 * 1024
            || !(2..=65536).contains(&source.targets.len())
            || Sha256::digest(&source.body).as_slice() != source.digest
        {
            return Err(Error::Unavailable);
        }
        let domain = match source.domain.as_str() {
            "gateway" => Domain::Gateway,
            "sentinel" => Domain::Sentinel,
            "interface-guard" => Domain::InterfaceGuard,
            _ => return Err(Error::Unavailable),
        };
        let targets: Vec<Target> =
            serde_json::from_slice(&source.targets).map_err(|_| Error::Unavailable)?;
        let definition = definition::cached(targets.len()).map_err(|_| Error::Unavailable)?;
        if targets
            .windows(2)
            .any(|pair| pair[0].node_id >= pair[1].node_id)
        {
            return Err(Error::Unavailable);
        }
        let count = targets.len() as u32;
        let digest: [u8; 32] = source.digest.try_into().map_err(|_| Error::Unavailable)?;
        let authority: [u8; 32] = source
            .authority
            .try_into()
            .map_err(|_| Error::Unavailable)?;
        let reviewer = source.reviewer.expect("reviewer checked");
        let mut intents = Vec::with_capacity(targets.len());
        for (index, target) in targets.into_iter().enumerate() {
            // 旧提案可只声明启动与配置版本；执行不能在此借当前目录为它补出原先没有批准的持久基线。
            let baseline = target.node_baseline.ok_or(Error::Conflict)?;
            if baseline.cluster_id != cluster
                || target.base_fingerprint.len() != 16
                || !target
                    .base_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(Error::Unavailable);
            }
            let intent = Intent {
                operation_id: source.id.clone(),
                proposal_epoch: source.epoch as u64,
                target_index: index as u32,
                target_count: count,
                domain,
                node_id: target.node_id,
                original_boot_id: target.boot_id,
                baseline,
                base_version: target.base_version,
                base_fingerprint: u64::from_str_radix(&target.base_fingerprint, 16)
                    .map_err(|_| Error::Unavailable)?,
                candidate_bytes: source.body.len() as u32,
                candidate_sha256: digest,
                scope: source.scope.clone(),
                creator: source.creator.clone(),
                reviewer: reviewer.clone(),
                authority_sha256: authority,
            };
            intent.fingerprint().map_err(|_| Error::Unavailable)?;
            intents.push(intent);
        }
        Ok(Self {
            body: source.body.into(),
            targets: intents,
            definition,
        })
    }

    /// 业务作用：将 NASA 已证步骤绑定回原冻结目标，禁止用有效消息读取另一提案或重排目标。
    ///
    /// 参数说明：
    /// - `pending`：经过 Outbox 外层、固定定义和派生身份校验的命令。
    ///
    /// 返回：原目标的借用；数量、原操作、集群或定义不一致时拒绝交付正文及签发。
    pub(in crate::admin::operations) fn target(&self, pending: &Pending) -> Result<&Intent, Error> {
        let intent = self
            .targets
            .get(pending.target_index)
            .ok_or(Error::Conflict)?;
        if pending.target_count != self.targets.len()
            || pending.envelope.saga_id != intent.operation_id
            || pending.envelope.tenant_id != intent.baseline.cluster_id
            || pending.envelope.workflow != self.definition.name().as_str()
            || pending.envelope.definition_version != self.definition.version().get()
            || pending.envelope.definition_digest != self.definition.digest()
        {
            return Err(Error::Conflict);
        }
        Ok(intent)
    }
}
