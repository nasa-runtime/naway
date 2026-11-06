//! 原效果查询只回答同一意图与方向的已提交事实，缺失稳定收据不能推断为未执行。

use super::facts::Facts;
use crate::control::{
    journal::Journal,
    material::execution::{command::Command, receipt::Expected},
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;

/// 同一原效果的有界持久观察，未决阶段供运行时选择确认、否定或保护流程。
pub(crate) enum MaterialEffect {
    Vacant,
    Pending(Facts),
    Closed,
    Stable {
        facts: Facts,
    },
}

impl Journal {
    /// 业务作用：为当前合法读取者回读原材料效果，重投不改变原受理或原监听观察boot。
    ///
    /// 参数说明：
    /// - `command`：当前已验签并复验会话、读取授权及窗口的完整原命令。
    ///
    /// 返回：空槽、代际已关闭或带同一head完整原生事实的未决/稳定结果；跨意图、未来代际、异boot或异执行域拒绝。
    pub(crate) fn read_material(&self, command: &Command) -> Result<MaterialEffect> {
        let checked = command.validate()?;
        let boot = self
            .action_boot
            .get()
            .context("material query boot absent")?;
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage.as_ref().context("material query storage absent")?;
        ensure!(
            command.intent.node_id == self.identity.node_id
                && command.intent.baseline.cluster_id == self.identity.cluster_id
                && command.intent.baseline.store_id == self.identity.store_id
                && command.delivery.receiving_boot_id == *boot
                && current
                    .material_fence()
                    .is_none_or(|highest| highest.store == command.intent.execution_store),
            "material query binding differs"
        );
        let epoch: u64 = command.intent.baseline.node_admission_epoch.parse()?;
        if epoch < current.admission_epoch() {
            // 关闭代际只证明迟到请求不可再受理，不能由此虚构原效果拒绝或原监听成功。
            return Ok(MaterialEffect::Closed);
        }
        ensure!(
            epoch == current.admission_epoch(),
            "material query uses a future epoch"
        );
        let Some(record) = current.shared_material() else {
            return Ok(MaterialEffect::Vacant);
        };
        ensure!(
            record.intent == command.intent && record.intent_sha256 == *checked.intent_sha256(),
            "material query intent differs"
        );
        let facts = || Facts::new(current.revision(), command.position, record.clone());
        if let Some(absence) = &record.absence {
            if absence.proof.step() == checked.step()
                && !command.delivery.resolve_compensation
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Resolve
                )
            {
                absence.proof.result_for(command)?;
                return Ok(MaterialEffect::Stable {
                    facts: facts(),
                });
            }
        }
        if let Some(execution) = &record.execution {
            let effect = if checked.identity().phase == StepPhase::Resolve {
                checked.resolved_effect()
            } else {
                checked.identity().effect
            }
            .to_string();
            if let Some(receipt) = execution
                .receipts
                .iter()
                .find(|receipt| receipt.effect_id() == effect)
            {
                let phase = receipt.phase(&record.intent, execution.position)?;
                let generations: Vec<_> = if phase == StepPhase::Compensate {
                    execution
                        .compensation
                        .iter()
                        .flat_map(|goals| goals.iter())
                        .map(|goal| goal.generation())
                        .collect()
                } else {
                    execution
                        .sources
                        .plans
                        .iter()
                        .map(|plan| plan.generation())
                        .collect()
                };
                let expected = Expected {
                    intent: &record.intent,
                    position: execution.position,
                    generations: &generations,
                    protocols: &execution.sources.protocols,
                };
                receipt.result_for(command, &expected)?;
                return Ok(MaterialEffect::Stable {
                    facts: facts(),
                });
            }
        }
        Ok(MaterialEffect::Pending(facts()))
    }
}
