//! 稳定效果查询只读取已提交事实，缺失收据不能被推断为没有执行。

use super::model::Stage;
use crate::control::{
    actions::{command::Command, definition},
    journal::Journal,
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use nasaga_runtime_core::SagaResultEnvelope;

// 单次查询只保留一个效果；直接承载已构造的稳定结果，避免每次回读再增加一次堆分配。
#[allow(clippy::large_enum_variant)]
pub(crate) enum EffectState {
    Vacant,
    Pending(Stage),
    Closed,
    Stable(SagaResultEnvelope),
}

impl Journal {
    /// 业务作用：为已验真且具当前读取资格的命令回读精确效果，重投使用当前命令结果身份但不改写原收据。
    ///
    /// 参数说明：
    /// - `command`：管理适配器已经验证签名、当前会话和读取授权的完整命令。
    ///
    /// 返回：当前空槽、未决、已关闭代际或稳定结果；未来代际、跨存储、异意图及未知 head 均拒绝。
    pub(crate) fn read_action(&self, command: &Command) -> Result<EffectState> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let verified = command.validate(&definition)?;
        let boot = self
            .action_boot
            .get()
            .context("node action boot is not bound")?;
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        ensure!(
            command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.delivery.receiving_boot_id == *boot,
            "node effect query binding differs"
        );
        let epoch: u64 = command.intent.baseline.node_admission_epoch.parse()?;
        if epoch < current.admission_epoch() {
            // 关闭水位只证明旧代际不可再受理，不证明原配置是否曾经发布，也不能生成 REJECTED 收据。
            return Ok(EffectState::Closed);
        }
        ensure!(
            epoch == current.admission_epoch(),
            "node effect query uses a future epoch"
        );
        let Some(action) = current.action() else {
            return Ok(EffectState::Vacant);
        };
        ensure!(
            action.intent_sha256 == *verified.intent_sha256() && action.intent == command.intent,
            "node effect query intent differs"
        );
        let effect = if verified.identity().phase == StepPhase::Resolve {
            verified.resolved_effect()
        } else {
            verified.identity().effect
        }
        .to_string();
        if let Some(proof) = action
            .absence
            .as_ref()
            .filter(|proof| proof.effect_id() == effect)
        {
            return proof
                .result_for(command, &definition)
                .map(EffectState::Stable);
        }
        if let Some(receipt) = action
            .receipts
            .iter()
            .find(|receipt| receipt.effect_id() == effect)
        {
            return receipt
                .result_for(command, &definition)
                .map(EffectState::Stable);
        }
        // 尚无该效果的稳定事实可能是未受理、正在执行或收据提交前崩溃；查询不替业务处理器做决定。
        Ok(EffectState::Pending(action.stage))
    }
}
