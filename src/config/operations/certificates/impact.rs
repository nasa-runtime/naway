//! 完整来源影响审批独立控制受理和共享容量，不改动原材料密文的持久预算。

use anyhow::{ensure, Result};
use serde::Deserialize;

pub(crate) const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const RECORD_OVERHEAD: u64 = 4096;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub accept_proposals: bool,
    pub max_records: u32,
    pub max_records_per_scope: u32,
    pub max_total_bytes: u64,
}

impl Default for Config {
    /// 业务作用：影响审批默认关闭，显式启用时使用独立且有界的记录与存储预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：关闭的影响审批声明，不注册新存储或扩大旧材料批准的含义。
    fn default() -> Self {
        Self {
            enabled: false,
            accept_proposals: true,
            max_records: 4096,
            max_records_per_scope: 256,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

impl Config {
    /// 业务作用：在配置发布前约束全部保留影响所占的共享预算，不依赖单个 Admin 的内存计数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：关闭或全部预算合法时成功；记录、工作区或字节边界不成立则拒绝候选。
    pub(super) fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        ensure!(
            cfg!(all(
                feature = "admin-operations-pgsql",
                feature = "node-actions"
            )),
            "certificate impact approvals require admin-operations-pgsql and node-actions"
        );
        ensure!(
            (1..=4096).contains(&self.max_records)
                && (1..=self.max_records).contains(&self.max_records_per_scope)
                && (MAX_PROOF_BYTES as u64 + RECORD_OVERHEAD..=64 * 1024 * 1024)
                    .contains(&self.max_total_bytes),
            "invalid certificate impact approval capacity"
        );
        Ok(())
    }

    /// 业务作用：资源身份比较只排除可热更的受理开关，容量和启用状态继续要求持久 owner 一致。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前资源副本不再保留受理状态，不改变已发布的共享存储预算。
    pub(super) fn clear_dynamic(&mut self) {
        self.accept_proposals = false;
    }
}
