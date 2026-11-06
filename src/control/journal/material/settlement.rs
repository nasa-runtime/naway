//! 实际监听归属完整到达原预分配代后才提交稳定收据，文件完成与收据完成分别持久解释。

use super::{application::require_goal, Stage};
use crate::{
    config::GatewaySnapshot,
    control::{
        actions::receipt::Outcome,
        journal::Journal,
        material::execution::{
            command::{Command, Step},
            observation::Evidence,
            receipt::{Expected, Receipt},
        },
    },
    tls::{
        installed::{material::collect, InstalledCertificates},
        keypair::execution::apply::locked,
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use std::sync::Arc;

impl Journal {
    /// 业务作用：在线轮询明确区分尚未到达的真实监听与不可证明的持久责任，不吞掉权限或文件错误。
    ///
    /// 参数说明：
    /// - `command`：当前已验签并有写权的原方向请求。
    /// - `active`：调用者持发布锁的当前完整配置。
    /// - `installed`：实际transport安装后维护的本机注册表。
    /// - `authorize`：当前四主体、会话、实例和期限的重复权限门。
    ///
    /// 返回：完整安装返回已同步收据；实际观察尚未到达返回空；身份、来源或持久状态异常返回错误。
    pub(crate) fn try_confirm_material_installation(
        &self,
        command: &Command,
        active: &GatewaySnapshot,
        installed: &InstalledCertificates,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<Option<Arc<Receipt>>> {
        let checked = command.validate()?;
        ensure!(
            checked.step() == Step::Apply
                && matches!(
                    checked.identity().phase,
                    StepPhase::Execute | StepPhase::Compensate | StepPhase::Resolve
                ),
            "material confirmation phase differs"
        );
        let backward = checked.identity().phase == StepPhase::Compensate
            || (checked.identity().phase == StepPhase::Resolve
                && command.delivery.resolve_compensation);
        let phase = if backward {
            StepPhase::Compensate
        } else {
            StepPhase::Execute
        };
        let effect = if checked.identity().phase == StepPhase::Resolve {
            checked.resolved_effect()
        } else {
            checked.identity().effect
        }
        .to_string();
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let original = self
            .require_material_command(storage.as_ref(), command)?
            .clone();
        let execution = original
            .execution
            .as_ref()
            .context("material confirmation plan absent")?;
        let generations: Vec<_> = if backward {
            execution
                .compensation
                .as_ref()
                .context("material compensation absent")?
                .iter()
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
            intent: &original.intent,
            position: execution.position,
            generations: &generations,
            protocols: &execution.sources.protocols,
        };
        authorize()?;
        if let Some(receipt) = execution
            .receipts
            .iter()
            .find(|receipt| receipt.effect_id() == effect)
        {
            // 稳定历史仍保留原观察boot；当前重投只能投影该原效果，不能把它重写成新观察。
            receipt.result_for(command, &expected)?;
            return Ok(Some(receipt.clone()));
        }
        ensure!(
            original.stage
                == if backward {
                    Stage::Backward
                } else {
                    Stage::Forward
                },
            "material confirmation does not match its file direction"
        );
        locked(|| {
            execution
                .configuration
                .require_snapshot(active, &original.intent)?;
            super::bodies::require_complete(&self.root, &original)?;
            require_goal(&original)?;
            let installed_snapshot = installed.snapshot();
            let observed = collect(active, &installed_snapshot, &original.intent.conditions)
                .context("material actual installation unavailable")?;
            // 正常交接期间实际监听可能仍持原代或尚未登记；这些观察保留未决，不掩盖文件与权限错误。
            if observed
                .groups
                .iter()
                .zip(&generations)
                .any(|(group, expected)| {
                    group.targets.iter().any(|target| {
                        target.protocols.iter().any(|protocol| {
                            protocol.state
                                != crate::control::material::installation::State::DifferentMaterial
                                || protocol.material_generation.as_deref() != Some(*expected)
                        })
                    })
                })
            {
                authorize()?;
                return Ok(None);
            }
            let boot = self
                .action_boot
                .get()
                .context("material observation boot absent")?;
            let evidence = Arc::new(Evidence::new(
                boot.clone(),
                &original.intent,
                &generations,
                &execution.sources.protocols,
                observed,
            )?);
            let index = execution
                .admissions
                .iter()
                .position(|admission| {
                    admission.step() == Step::Apply
                        && admission
                            .validate(&original.intent, execution.position)
                            .is_ok_and(|identity| identity.phase == phase)
                })
                .context("material original admission absent")?;
            let mut next_execution = execution.as_ref().clone();
            let admission = next_execution.admissions.remove(index);
            let receipt = Arc::new(Receipt::settle(
                admission,
                &expected,
                Outcome::Succeeded,
                None,
                Some(evidence),
            )?);
            next_execution.receipts.push(receipt.clone());
            let mut next = original.clone();
            next.fence.value = command.delivery.fence;
            next.stage = if backward {
                Stage::Reverted
            } else {
                Stage::Applied
            };
            next.execution = Some(Arc::new(next_execution));
            authorize()?;
            execution
                .configuration
                .require_snapshot(active, &original.intent)?;
            super::bodies::require_complete(&self.root, &original)?;
            require_goal(&original)?;
            // 最终授权、完整文件和原head均成立才确认；失败不把已可见文件或旧观察转换为稳定成功。
            ensure!(
                installed_snapshot.same_generation(&installed.snapshot()),
                "material listener ownership changed before confirmation"
            );
            self.advance_material(&mut storage, next)?;
            Ok(Some(receipt))
        })
    }
}
