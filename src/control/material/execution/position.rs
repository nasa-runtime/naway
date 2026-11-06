//! 节点工作流位置与原逻辑目标分母分别绑定，共享材料别名不能制造重复节点步骤。

use crate::control::material::node::Intent;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// 冻结原批次中的物理节点位置，独立于Intent保留的完整逻辑目标索引与分母。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Position {
    pub index: u32,
    pub count: u32,
}

impl Position {
    /// 业务作用：将本节点的整批来源绑定到唯一工作流步骤，保留完整逻辑目标的原索引及分母。
    ///
    /// 参数说明：
    /// - `intent`：由原完整影响证明冻结的本节点意图。
    ///
    /// 返回：节点位置与逻辑目标范围可以同时成立时成功；不自行补全其它节点或证明全批原文。
    pub(crate) fn validate(&self, intent: &Intent) -> Result<()> {
        ensure!(
            (1..=intent.target_count).contains(&self.count) && self.index < self.count,
            "material execution node position differs"
        );
        let first = intent
            .selections
            .first()
            .ok_or_else(|| anyhow::anyhow!("material node targets absent"))?
            .index;
        let last = intent
            .selections
            .last()
            .ok_or_else(|| anyhow::anyhow!("material node targets absent"))?
            .index;
        let after = intent
            .target_count
            .checked_sub(last)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| anyhow::anyhow!("material node target span differs"))?;
        // 每个其它原节点都至少有一个逻辑目标；首尾节点不能留下无法归属的全批索引。
        ensure!(
            first >= self.index
                && after >= self.count - self.index - 1
                && (self.index != 0 || first == 0)
                && (self.index + 1 != self.count || after == 0),
            "material node position and original targets disagree"
        );
        Ok(())
    }

    /// 业务作用：为可执行意图增加独立节点步骤域，旧保留意图摘要不能单独获得执行资格。
    ///
    /// 参数说明：
    /// - `intent`：同一命令与持久槽共享的原材料意图。
    ///
    /// 返回：同时覆盖完整原意图和节点位置的固定摘要；字段或原逻辑目标非法时拒绝。
    pub(crate) fn fingerprint(&self, intent: &Intent) -> Result<[u8; 32]> {
        let original = intent.fingerprint()?;
        self.validate(intent)?;
        let mut hash = Sha256::new();
        hash.update(b"naway-material-execution-intent\0");
        hash.update(1u32.to_be_bytes());
        hash.update(original);
        hash.update(self.index.to_be_bytes());
        hash.update(self.count.to_be_bytes());
        Ok(hash.finalize().into())
    }
}
