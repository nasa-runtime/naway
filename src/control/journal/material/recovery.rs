//! 启动先补齐原材料文件方向，再构建监听；未决定准备不跨启动取得新的应用资格。

use super::{application::require_goal, bodies, Stage};
use crate::control::material::execution::receipt::Reason;
use crate::{
    config::GatewaySnapshot,
    control::journal::{storage, Journal},
    tls::keypair::execution::apply::locked,
};
use anyhow::{ensure, Context, Result};
use std::{path::Path, sync::Arc};

impl Journal {
    /// 业务作用：在正常TLS快照构建之前解释唯一材料责任，旧受理只恢复原文件方向，不继承旧会话授权。
    ///
    /// 参数说明：
    /// - `storage`：已持锁并复验的当前head。
    /// - `main`：本进程实际启动的主配置位置。
    ///
    /// 返回：存在材料责任且已处理时为真；未知格式、保护态或外来来源拒绝启动并保留全部现场。
    pub(in crate::control::journal) fn recover_material(
        &self,
        storage: &mut Option<storage::Snapshot>,
        main: &Path,
    ) -> Result<bool> {
        let Some(current) = storage.as_ref() else {
            return Ok(false);
        };
        let Some(record) = current.material() else {
            return Ok(false);
        };
        // 旧保留格式没有原配置、原方向或终态证明，不能补造可执行计划来开放路由。
        ensure!(
            matches!(record.schema, 2 | 3),
            "material reservation has no executable recovery plan"
        );
        ensure!(
            record.stage != Stage::Protected,
            "material responsibility is protected"
        );
        storage::confirm(&self.root, &self.identity, current)?;
        if record.stage == Stage::Cleaning {
            // 清理权已持久且没有活动文件方向；重启只完成精确槽删除，不重新验证过期交付窗口。
            bodies::cleanup(&self.root, record)?;
            *storage = Some(storage::material::finish_cleanup(
                &self.root,
                &self.identity,
                current,
            )?);
            return Ok(true);
        }
        if record.schema == 3 {
            // 否定事实没有来源或文件方向，启动保留它以拒绝迟到请求，不创建或清理任何秘密。
            bodies::inspect(&self.root, None)?;
            return Ok(true);
        }
        let execution = record
            .execution
            .as_ref()
            .context("material recovery plan absent")?;
        if let Err(error) = execution
            .configuration
            .require_current(main, &record.intent)
        {
            // 已检测到配置漂移即永久撤销自动文件权，后来恢复相同字节也不能复活旧动作。
            self.protect_material(storage, Reason::BaselineChanged)?;
            return Err(error);
        }
        match record.stage {
            Stage::Reserved => {
                // 尚无文件方向，秘密不完整也只能拒绝原prepare，不能在重启时补成成功受理。
                self.reject_material_preparation(storage)?;
            }
            Stage::Prepared => {
                let mut next = record.clone();
                next.stage = Stage::Invalidated;
                next.execution = Some(Arc::clone(execution));
                // 新boot不拥有旧prepare的正向应用权；先持久撤销资格，再允许正常配置与监听构建。
                self.advance_material(storage, next)?;
            }
            Stage::Forward | Stage::Backward => {
                // 已提交方向是恢复唯一权威；所有来源沿用原目标代，不要求旧boot或旧签名仍有效。
                if let Err(error) = locked(|| self.replay_material(current, main, &mut || Ok(()))) {
                    self.protect_material(storage, Reason::SourceChanged)?;
                    return Err(error);
                }
            }
            Stage::Applied | Stage::Reverted => {
                if let Err(error) = locked(|| require_goal(record)) {
                    self.protect_material(storage, Reason::SourceChanged)?;
                    return Err(error);
                }
            }
            Stage::Invalidated | Stage::Rejected | Stage::Compensated => {}
            Stage::Protected | Stage::Cleaning => unreachable!("recovery stages checked"),
        }
        Ok(true)
    }

    /// 业务作用：将已经观察到的配置或来源不可信持久化，保留原方向与未知受理，禁止同字节回归后自动继续。
    ///
    /// 参数说明：
    /// - `storage`：owner仍承认并持锁的原head。
    /// - `reason`：有限低敏保护原因，不包含路径或底层错误链。
    ///
    /// 返回：保护事实同步后成功；未知head拒绝推进且保留原期望，不虚构HALTED或成功收据。
    pub(super) fn protect_material(
        &self,
        storage: &mut Option<storage::Snapshot>,
        reason: Reason,
    ) -> Result<()> {
        let record = storage
            .as_ref()
            .and_then(storage::Snapshot::material)
            .context("material protection responsibility absent")?;
        let execution = record
            .execution
            .as_ref()
            .context("material protection plan absent")?;
        let mut protected = execution.as_ref().clone();
        protected.protection = Some(reason);
        let mut next = record.clone();
        next.stage = Stage::Protected;
        next.execution = Some(Arc::new(protected));
        self.advance_material(storage, next)
    }

    /// 业务作用：让正常候选只能继续原材料责任的配置，保留记录不能被普通热更或外部策略重新解释。
    ///
    /// 参数说明：
    /// - `storage`：调用者持锁复验的存储事实。
    /// - `snapshot`：尚未开放路由的完整候选。
    ///
    /// 返回：没有材料责任时为假；原配置与方向完整时为真；准备中、清理中或保护态拒绝发布。
    pub(in crate::control::journal) fn require_material_snapshot(
        &self,
        storage: Option<&storage::Snapshot>,
        snapshot: &GatewaySnapshot,
    ) -> Result<bool> {
        let Some(record) = storage.and_then(storage::Snapshot::material) else {
            return Ok(false);
        };
        ensure!(
            matches!(record.schema, 2 | 3)
                && !matches!(
                    record.stage,
                    Stage::Reserved | Stage::Prepared | Stage::Protected | Stage::Cleaning
                ),
            "material responsibility does not permit snapshot publication"
        );
        if record.schema == 3 {
            return Ok(true);
        }
        let execution = record
            .execution
            .as_ref()
            .context("material snapshot plan absent")?;
        execution
            .configuration
            .require_snapshot(snapshot, &record.intent)?;
        if execution.direction.is_some() {
            locked(|| require_goal(record))?;
        }
        Ok(true)
    }
}
