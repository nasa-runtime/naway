//! 整批准备先核对全部来源与预算，再保留单份候选和每来源单份清零备份。

use super::source::Plan;
use crate::{
    config::GatewaySnapshot,
    control::material::{
        backup::{Backup, PART_LIMIT},
        execution::observation::{Evidence, Protocols},
        node::Intent,
        Material,
    },
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// 原来源顺序与完整共享目标协议分母，持久推进只共享此不可变计划。
pub(crate) struct Sources {
    pub plans: Vec<Plan>,
    pub protocols: Vec<Vec<Protocols>>,
}

/// 全批原句柄与每来源唯一清零备份，直到持久准备结束前持续保持来源复验能力。
pub(crate) struct Preparation<'a> {
    pub sources: Arc<Sources>,
    pub backups: Vec<Backup>,
    held: Vec<super::super::source::held::Source<'a>>,
}

impl Sources {
    /// 业务作用：保证持久计划与完整原来源顺序和协议分母对应，恢复不能漏掉共享逻辑目标。
    ///
    /// 参数说明：
    /// - `intent`：同一节点的原审批意图及完整来源影响。
    ///
    /// 返回：每个原来源恰有一份计划和完整协议集合时成功，不读取文件。
    pub(crate) fn validate(&self, intent: &Intent) -> Result<()> {
        ensure!(
            self.plans.len() == intent.conditions.groups.len()
                && self.protocols.len() == self.plans.len()
                && !self.plans.is_empty(),
            "material source plan count differs"
        );
        let mut total = u64::from(intent.candidate_bytes);
        for ((plan, protocols), original) in self
            .plans
            .iter()
            .zip(&self.protocols)
            .zip(&intent.conditions.groups)
        {
            plan.require_condition(original)?;
            total += u64::from(plan.backup_bytes());
            ensure!(
                protocols.len() == original.affected.len()
                    && protocols
                        .iter()
                        .zip(&original.affected)
                        .all(|(protocol, target)| protocol.allows(target.target.kind)),
                "material original protocol set differs"
            );
        }
        ensure!(
            total <= 32 * 1024 * 1024,
            "material source secret reservation exceeds limit"
        );
        Evidence::require_capacity(&self.protocols)
    }
}

impl Preparation<'_> {
    /// 业务作用：准备提交前复验整批原句柄，先前读取成功的来源不能在批内后续工作期间被替换。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：每份原备份和完整原来源仍一致时成功，不重复分配或读取完整私钥。
    pub(crate) fn require_current(&self) -> Result<()> {
        for ((source, backup), plan) in self.held.iter().zip(&self.backups).zip(&self.sources.plans)
        {
            plan.require_original(source, backup)?;
        }
        Ok(())
    }
}

/// 业务作用：在与本机安装共享的锁内冻结整批原材料，并保持原句柄直到调用方持久准备结束。
///
/// 参数说明：
/// - `snapshot`：外层已取得发布权并完成当前四主体授权的完整原配置。
/// - `intent`：本次原审批、完整影响和候选身份。
/// - `candidate`：唯一清零候选帧，只借用其原文。
/// - `persist`：消费完整准备与原句柄的持久处理，不得重入材料锁。
///
/// 返回：完整原条件和策略成立后才调用持久处理；任何前置失败不创建材料或秘密槽。
pub(crate) fn with_prepared<T>(
    snapshot: &GatewaySnapshot,
    intent: &Intent,
    candidate: &Material,
    persist: impl FnOnce(&Preparation<'_>) -> Result<T>,
) -> Result<T> {
    intent.fingerprint()?;
    ensure!(
        candidate.0.len() == intent.candidate_bytes as usize
            && <[u8; 32]>::from(Sha256::digest(&candidate.0)) == intent.candidate_sha256,
        "material candidate identity differs"
    );
    let (certificate, private_key) = candidate
        .parts()
        .map_err(|_| anyhow::anyhow!("material candidate frame differs"))?;
    let certified = super::super::validate_keypair(certificate, private_key)?;
    let targets: Vec<_> = intent
        .selections
        .iter()
        .map(|selection| &selection.target)
        .collect();
    super::super::conditions::with_many(
        snapshot,
        &targets,
        |index, selected, conditions| -> Result<T> {
            // 完整共享影响必须仍与双重审批时一致；当前在线目录不能替换来源或缩减原目标集合。
            ensure!(
                conditions == intent.conditions,
                "material original conditions changed"
            );
            let mut held = Vec::with_capacity(conditions.groups.len());
            let mut positions = Vec::with_capacity(conditions.groups.len());
            let mut protocols = Vec::with_capacity(conditions.groups.len());
            let mut reserved = u64::from(intent.candidate_bytes);
            for (group, original) in conditions.groups.iter().enumerate() {
                let local = conditions
                    .entries
                    .iter()
                    .position(|entry| entry.group == group)
                    .context("material source has no selected target")?;
                let captured =
                    super::super::source::held::Source::capture(&selected[local], PART_LIMIT)?;
                reserved += u64::from(captured.budget()?);
                ensure!(
                    reserved <= 32 * 1024 * 1024,
                    "material secret reservation exceeds limit"
                );
                positions.push(
                    index
                        .position(targets[local])
                        .context("material source index changed")?,
                );
                protocols.push(
                    original
                        .affected
                        .iter()
                        .map(|affected| {
                            Protocols::capture(snapshot, &affected.target)
                                .context("material original protocol plan absent")
                        })
                        .collect::<Result<Vec<_>>>()?,
                );
                held.push(captured);
            }
            // 所有来源预算与监听策略先于整批秘密分配；部分来源可用不能形成可执行的准备责任。
            Evidence::require_capacity(&protocols)?;
            super::super::preflight::validate_sources(index, &positions, &certified)?;
            let mut backups = Vec::with_capacity(held.len());
            let mut plans = Vec::with_capacity(held.len());
            for source in &mut held {
                let backup = source
                    .read(PART_LIMIT)?
                    .context("material original pair ownership changed")?;
                plans.push(source.prepare(&backup, certificate, private_key)?);
                backups.push(backup);
            }
            let prepared = Preparation {
                sources: Arc::new(Sources {
                    plans,
                    protocols,
                }),
                backups,
                held,
            };
            prepared.sources.validate(intent)?;
            prepared.require_current()?;
            persist(&prepared)
        },
    )
    .map_err(|_| anyhow::anyhow!("material original source capture unavailable"))?
}
