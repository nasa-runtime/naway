//! 文件决定与实际快照发布之间的持久效果边界。

use super::model::{Publication, Record, Stage};
use crate::{
    config::{
        candidate::{dependencies, Documents},
        GatewaySnapshot,
    },
    control::{
        actions::{
            command::Step,
            definition,
            receipt::{Outcome, Receipt},
        },
        journal::{
            local::{self, Direction},
            storage, Journal,
        },
    },
};
use anyhow::{ensure, Context, Result};
use nasa::saga::StepPhase;

impl Journal {
    /// 业务作用：在配置内容去重前确认是否仍有文件方向等待真实快照发布，避免同内容动作永久未决。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整 head 中存在 Forward 或 Backward 时为真；没有待发布动作时为假；持久事实不明拒绝判断。
    pub(crate) fn action_publication_pending(&self) -> Result<bool> {
        let storage = self.storage.lock();
        // 去重同样会阻止业务推进，必须复验磁盘权威，不能把未接纳的 head 当作没有动作。
        self.verify_expected(storage.as_ref())?;
        Ok(storage
            .as_ref()
            .and_then(storage::Snapshot::action)
            .is_some_and(|action| matches!(action.stage, Stage::Forward | Stage::Backward)))
    }

    /// 业务作用：绑定现有管理监控的进程身份，所有文件效果和节点报告必须使用同一个 boot。
    ///
    /// 参数说明：
    /// - `boot`：管理运行态已经生成且本次进程固定的标识。
    ///
    /// 返回：首次合法绑定或相同绑定成功，不允许运行时替换为另一 boot。
    pub(crate) fn bind_action_boot(&self, boot: &str) -> Result<()> {
        ensure!(
            crate::admin::management::valid_node_id(boot),
            "node action boot identity differs"
        );
        if let Err(candidate) = self.action_boot.set(boot.to_owned()) {
            ensure!(
                self.action_boot.get() == Some(&candidate),
                "node action boot is already bound"
            );
        }
        Ok(())
    }

    /// 业务作用：在快照可见之前验证远程文件方向或持久撤销旧覆盖权，禁止原本地结束路径回收动作正文。
    ///
    /// 参数说明：
    /// - `storage`：已经复验且持锁的唯一 head。
    /// - `snapshot`：已完成语义与资源准备的即将发布快照。
    ///
    /// 返回：动作仍占有正文时为真；无动作正文时为假；证据不足或未知决定拒绝发布。
    pub(in crate::control::journal) fn before_action_publication(
        &self,
        storage: &mut Option<storage::Snapshot>,
        snapshot: &GatewaySnapshot,
    ) -> Result<bool> {
        let Some(action) = storage.as_ref().and_then(storage::Snapshot::action) else {
            return Ok(false);
        };
        match action.stage {
            Stage::Preparing | Stage::Protected => {
                anyhow::bail!("node action does not permit snapshot publication")
            }
            Stage::Prepared => {
                // 新快照即使只改变版本，也已经消耗原冻结基线；先撤销准备，旧 apply 才不会跨越它。
                self.invalidate_prepared_action(storage)?;
                Ok(false)
            }
            Stage::Forward | Stage::Backward => {
                self.action_boot
                    .get()
                    .context("node action boot is not bound")?;
                self.require_action_goal(action, snapshot)?;
                local::apply::cleanup(
                    &self.root,
                    action
                        .files
                        .as_ref()
                        .context("node action files are absent")?,
                )?;
                Ok(true)
            }
            Stage::Applied | Stage::Reverted => {
                let publication = action
                    .publication
                    .as_ref()
                    .context("node action publication is absent")?;
                if publication.owned {
                    let boot = self
                        .action_boot
                        .get()
                        .context("node action boot is not bound")?;
                    let matches = if publication.boot_id == *boot {
                        publication.version == snapshot.version
                            && Some(publication.fingerprint) == snapshot.config_fingerprint
                    } else {
                        self.require_action_goal(action, snapshot).is_ok()
                    };
                    if !matches {
                        let mut next = action.clone();
                        next.publication
                            .as_mut()
                            .expect("validated action publication")
                            .owned = false;
                        // 撤销覆盖权先于新 ArcSwap，A→B→A 或重启不得把旧效果重新解释为当前配置的 owner。
                        self.advance_action(storage, next)?;
                    }
                }
                Ok(true)
            }
            Stage::Invalidated | Stage::Rejected | Stage::Compensated => Ok(false),
        }
    }

    /// 业务作用：真实快照已发布后确认原 Admission 的结果，提交失败保留未知，不能回撤已经可见的快照。
    ///
    /// 参数说明：
    /// - `snapshot`：调用者刚刚实际发布或已完整装配的初始快照。
    ///
    /// 返回：无待确认动作或收据完整提交时成功；任何失败由调用方保留新快照并停止进一步动作。
    pub(crate) fn confirm_action_publication(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let Some(action) = storage.as_ref().and_then(storage::Snapshot::action) else {
            return Ok(());
        };
        if !matches!(
            action.stage,
            Stage::Forward | Stage::Backward | Stage::Applied | Stage::Reverted
        ) {
            return Ok(());
        }
        let boot = self
            .action_boot
            .get()
            .context("node action boot is not bound")?;
        let mut next = action.clone();
        if matches!(action.stage, Stage::Applied | Stage::Reverted) {
            let publication = next
                .publication
                .as_mut()
                .context("node action publication is absent")?;
            if !publication.owned || publication.boot_id == *boot {
                return Ok(());
            }
            // 跨启动接纳必须再次证明原文件与依赖，此时初始快照已经装配且全部业务资源准备完成。
            self.require_action_goal(action, snapshot)?;
            publication.boot_id.clone_from(boot);
            publication.version = snapshot.version;
            return self.advance_action(&mut storage, next);
        }
        self.require_action_goal(action, snapshot)?;
        let forward = action.stage == Stage::Forward;
        let definition = definition::cached(action.intent.target_count as usize)?;
        let phase = if forward {
            StepPhase::Execute
        } else {
            StepPhase::Compensate
        };
        let index = next
            .admissions
            .iter()
            .position(|admission| {
                admission.step() == Step::Apply
                    && admission
                        .validate(&next.intent, &definition)
                        .is_ok_and(|value| value.phase == phase)
            })
            .context("node action publication admission is absent")?;
        let admission = next.admissions.remove(index);
        next.receipts.push(Receipt::settle(
            admission,
            &next.intent,
            &definition,
            Outcome::Succeeded,
            None,
        )?);
        let fingerprint = snapshot
            .config_fingerprint
            .context("node action publication fingerprint is absent")?;
        if forward {
            next.candidate_fingerprint = Some(fingerprint);
        }
        // 补偿只确认基线已经重新发布，原 apply 未决时继续保留其身份，不能猜测崩溃前是否发布过。
        next.stage = if forward {
            Stage::Applied
        } else {
            Stage::Reverted
        };
        next.publication = Some(Publication {
            boot_id: boot.clone(),
            version: snapshot.version,
            fingerprint,
            direction: if forward {
                Direction::Forward
            } else {
                Direction::Backward
            },
            owned: true,
        });
        self.advance_action(&mut storage, next)
    }

    /// 业务作用：将待确认的真实快照与对应方向的原文、路径、完整指纹和非 base 依赖同时绑定。
    ///
    /// 参数说明：
    /// - `action`：同一 head 保留的明确方向与原始材料。
    /// - `snapshot`：正常构建并完成资源准备的候选。
    ///
    /// 返回：全部文件、依赖和当前读取结果一致时成功，不写成功收据或改变快照。
    fn require_action_goal(&self, action: &Record, snapshot: &GatewaySnapshot) -> Result<()> {
        let files = action
            .files
            .as_ref()
            .context("node action files are absent")?;
        local::require_snapshot(files, snapshot)?;
        local::apply::preflight(&self.root, files)?;
        local::apply::require_goal(files)?;
        ensure!(
            snapshot.config_fingerprint.is_some()
                && crate::config::config_fingerprint(&snapshot.source_config_path).ok()
                    == snapshot.config_fingerprint,
            "node action publication fingerprint changed"
        );
        if files.direction == Direction::Backward {
            ensure!(
                snapshot.config_fingerprint == Some(action.intent.base_fingerprint),
                "node action baseline fingerprint differs"
            );
        } else if let Some(expected) = action.candidate_fingerprint {
            ensure!(
                snapshot.config_fingerprint == Some(expected),
                "node action candidate fingerprint differs"
            );
        }
        ensure!(
            dependencies::capture(
                snapshot,
                Documents {
                    gateway: &snapshot.source_config_path,
                    sidecars: None
                }
            )? == expected_dependencies(action)?,
            "node action publication dependencies changed"
        );
        Ok(())
    }
}

/// 业务作用：按持久方向选择准备时冻结的依赖，补偿不能错误复用候选可能完全不同的秘密或 profile。
///
/// 参数说明：
/// - `action`：当前完整动作事实。
///
/// 返回：Forward 的候选证明或 Backward 的基线证明；未决定文件方向拒绝。
pub(super) fn expected_dependencies(action: &Record) -> Result<[u8; 32]> {
    match action.files.as_ref().map(|files| files.direction) {
        Some(Direction::Forward) => Ok(action.dependencies_sha256),
        Some(Direction::Backward) => Ok(action.baseline_dependencies_sha256),
        _ => anyhow::bail!("node action has no dependency decision"),
    }
}
