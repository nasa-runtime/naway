//! 材料保留记录独占写入资格，秘密预算与配置正文槽分别计费。

mod absence;
mod application;
pub(super) mod bodies;
mod capacity;
pub(super) mod execution;
mod facts;
mod prepare;
mod query;
mod recovery;
mod release;
mod settlement;

pub(crate) use crate::control::material::execution::state::Stage;
pub(crate) use query::MaterialEffect;

use super::identity::Identity;
use crate::control::material::node::{hexadecimal, Intent, MAX_GROUPS};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_BACKUP_BYTES: u32 = 8 * 1024 * 1024 + 16;
const MAX_RESERVED_BYTES: u64 = 32 * 1024 * 1024;

/// 最高水位连同永久调度域保留；不同执行存储的计数没有可比较关系。
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::control::journal) struct Fence {
    pub store: String,
    pub value: u64,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// 唯一head选择的原材料责任，明确区分不可执行保留、完整执行计划和没有秘密预算的否定事实。
pub(in crate::control::journal) struct Record {
    pub schema: u32,
    pub intent: Arc<Intent>,
    pub intent_sha256: [u8; 32],
    pub fence: Fence,
    pub stage: Stage,
    pub backup_bytes: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Arc<execution::Execution>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absence: Option<Arc<absence::Nonadmission>>,
}

#[derive(Serialize)]
/// 只读公开的原动作、阶段与占用计数，不包含材料摘要、文件路径或可复用命令。
pub(in crate::control::journal) struct Status {
    operation_id: String,
    stage: Stage,
    target_count: u32,
    local_target_count: usize,
    source_count: usize,
    reserved_secret_bytes: u64,
}

impl Fence {
    /// 业务作用：验证独立材料调度域及正水位，空闲或关闭代际不能抹去已经存在的域绑定。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：永久执行存储身份和有界正水位成立时成功；未知或零水位拒绝。
    pub(in crate::control::journal) fn validate(&self) -> Result<()> {
        ensure!(
            hexadecimal(&self.store, 64) && (1..=i64::MAX as u64).contains(&self.value),
            "invalid material journal fence"
        );
        Ok(())
    }
}

impl Record {
    /// 业务作用：复验原材料责任与节点永久身份，预算或来源缺项不能被当作可恢复的完整记录。
    ///
    /// 参数说明：
    /// - `identity`：当前唯一目录的永久节点绑定。
    /// - `epoch`：head承认且尚未关闭的受理代际。
    /// - `highest`：同一head保留的独立材料调度域及最高水位。
    ///
    /// 返回：原意图、节点归属、fence及全部秘密预算一致时成功；不授予文件副作用。
    pub(in crate::control::journal) fn validate(
        &self,
        identity: &Identity,
        epoch: u64,
        highest: Option<&Fence>,
    ) -> Result<()> {
        self.fence.validate()?;
        let fingerprint = match (self.schema, &self.execution) {
            (1, None) if self.stage == Stage::Reserved && self.absence.is_none() => {
                self.intent.fingerprint()?
            }
            (2, Some(execution)) => {
                execution.validate(&self.intent, self.stage)?;
                ensure!(
                    self.backup_bytes.iter().copied().eq(execution
                        .sources
                        .plans
                        .iter()
                        .map(|plan| plan.backup_bytes())),
                    "material execution backup budgets differ"
                );
                execution.position.fingerprint(&self.intent)?
            }
            (3, None) => {
                let absence = self
                    .absence
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("material nonadmission absent"))?;
                absence.validate(self)?;
                absence
                    .proof
                    .validate(&self.intent)?
                    .fingerprint(&self.intent)?
            }
            _ => anyhow::bail!("material journal execution layout differs"),
        };
        ensure!(
            fingerprint == self.intent_sha256
                && self.intent.node_id == identity.node_id
                && self.intent.baseline.cluster_id == identity.cluster_id
                && self.intent.baseline.store_id == identity.store_id
                && self.intent.baseline.node_admission_epoch == epoch.to_string()
                && self.fence.store == self.intent.execution_store
                && highest == Some(&self.fence),
            "material journal binding differs"
        );
        if let Some(absence) = &self.absence {
            absence.validate(self)?;
        }
        if self.schema == 3 {
            return Ok(());
        }
        // 候选只计一次，每个来源的原pair各自计费；目标别名不能少算备份或扩大容量。
        ensure!(
            self.backup_bytes.len() == self.intent.conditions.groups.len()
                && (1..=MAX_GROUPS).contains(&self.backup_bytes.len())
                && self
                    .backup_bytes
                    .iter()
                    .all(|bytes| (18..=MAX_BACKUP_BYTES).contains(bytes))
                && self.reserved_bytes() <= MAX_RESERVED_BYTES,
            "material journal reservation exceeds bounds"
        );
        Ok(())
    }

    /// 业务作用：在原材料责任内只允许同一完整意图单向推进，旧保留格式不能升级成可执行权威。
    ///
    /// 参数说明：
    /// - `next`：已经完成完整结构校验的候选记录。
    ///
    /// 返回：原意图、预算、执行域与不可变计划一致且fence单调时成功；其它情况保留当前head。
    pub(in crate::control::journal) fn require_successor(&self, next: &Self) -> Result<()> {
        ensure!(
            self.schema == next.schema
                && matches!(self.schema, 2 | 3)
                && self.intent == next.intent
                && self.intent_sha256 == next.intent_sha256
                && self.backup_bytes == next.backup_bytes
                && self.fence.store == next.fence.store
                && next.fence.value >= self.fence.value,
            "material journal cannot replace original responsibility"
        );
        if let Some(original) = &self.absence {
            let successor = next
                .absence
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("material nonadmission lost"))?;
            ensure!(
                original.proof == successor.proof
                    && original
                        .release
                        .as_ref()
                        .is_none_or(|proof| successor.release.as_ref() == Some(proof)),
                "material nonadmission changed"
            );
        } else if next.absence.is_some() {
            // 新否定事实只可关闭尚未受理的apply，原已受理效果和文件方向不能被它抹去。
            ensure!(
                matches!(self.stage, Stage::Prepared | Stage::Invalidated)
                    && next.stage == Stage::Invalidated
                    && self.execution == next.execution,
                "material nonadmission cannot replace an admitted effect"
            );
        }
        if self.schema == 3 {
            ensure!(
                matches!(
                    (self.stage, next.stage),
                    (Stage::Rejected, Stage::Rejected | Stage::Cleaning)
                        | (Stage::Cleaning, Stage::Cleaning)
                ),
                "material nonadmission transition differs"
            );
            return Ok(());
        }
        self.execution
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("material original execution absent"))?
            .require_successor(
                next.execution
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("material next execution absent"))?,
                self.stage,
                next.stage,
            )
    }

    /// 业务作用：从已验证记录计算候选与所有来源备份的共同保留预算，状态观察不读取秘密文件。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整有限字节总额；只表示保留责任，不表示材料已写入或监听已安装。
    fn reserved_bytes(&self) -> u64 {
        if self.schema == 3 {
            return 0;
        }
        u64::from(self.intent.candidate_bytes)
            + self
                .backup_bytes
                .iter()
                .map(|bytes| u64::from(*bytes))
                .sum::<u64>()
    }

    /// 业务作用：导出不含路径或秘密摘要的保留事实，不能把占用记录解释为执行成功。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有限动作身份及完整计数，不复制来源树或输出命令凭据。
    pub(in crate::control::journal) fn status(&self) -> Status {
        Status {
            operation_id: self.intent.operation_id.clone(),
            stage: self.stage,
            target_count: self.intent.target_count,
            local_target_count: self.intent.selections.len(),
            source_count: self.intent.conditions.groups.len(),
            reserved_secret_bytes: self.reserved_bytes(),
        }
    }
}
