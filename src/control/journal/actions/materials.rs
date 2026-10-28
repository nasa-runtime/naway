//! 正向与补偿重建仅借助原动作保存的正文，不复用网络重投的其它内容。

use super::model::Stage;
use crate::{
    config::candidate::Paths,
    control::{
        actions::{
            command::{Command, Step},
            definition,
        },
        journal::{
            local::{self, Direction},
            Journal,
        },
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;
use std::fs::File;

pub(crate) struct Materials {
    pub revision: u64,
    pub intent_sha256: [u8; 32],
    pub dependencies_sha256: [u8; 32],
    pub paths: Paths,
    pub files: [File; 3],
}

impl Journal {
    /// 业务作用：为已经验真且持真实任务许可的 apply/compensate 提供原正文，构建结束后仍须精确复验当前 head。
    ///
    /// 参数说明：
    /// - `command`：当前会话和权限已由外层适配器复验的命令。
    ///
    /// 返回：同一意图及方向的三个只读句柄和冻结证明；跨 boot/store/代际、低 fence 或不符阶段拒绝。
    pub(crate) fn read_action_materials(&self, command: &Command) -> Result<Materials> {
        let definition = definition::cached(command.intent.target_count as usize)?;
        let checked = command.validate(&definition)?;
        ensure!(
            checked.step() == Step::Apply,
            "node action materials require apply step"
        );
        let boot = self
            .action_boot
            .get()
            .context("node action boot is not bound")?;
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        let action = current
            .action()
            .context("node action materials are absent")?;
        ensure!(
            current.local().is_none()
                && action.intent == command.intent
                && action.intent_sha256 == *checked.intent_sha256()
                && command.delivery.receiving_boot_id == *boot
                && command.delivery.fence >= current.highest_fence(),
            "node action material authority differs"
        );
        let (direction, dependencies) = match checked.identity().phase {
            StepPhase::Execute => {
                // Prepared 只在原进程有效，材料不能帮助重启后的迟到 apply 重新取得原基线。
                ensure!(
                    action.stage == Stage::Prepared && command.intent.original_boot_id == *boot,
                    "node action preparation is no longer applicable"
                );
                (Direction::Forward, action.dependencies_sha256)
            }
            StepPhase::Compensate => {
                ensure!(
                    matches!(action.stage, Stage::Forward | Stage::Applied)
                        && action.publication.as_ref().is_none_or(|value| value.owned),
                    "node action no longer owns compensation materials"
                );
                (Direction::Backward, action.baseline_dependencies_sha256)
            }
            _ => anyhow::bail!("node action query cannot acquire file materials"),
        };
        let (paths, files) = local::materials::open(
            &self.root,
            action
                .files
                .as_ref()
                .context("node action file plan is absent")?,
            direction,
        )?;
        Ok(Materials {
            revision: current.revision(),
            intent_sha256: action.intent_sha256,
            dependencies_sha256: dependencies,
            paths,
            files,
        })
    }
}
