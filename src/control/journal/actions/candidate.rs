//! 跨步骤动作的实际语义构建必须被同一冻结依赖证明夹住。

use super::{model::Stage, publication::expected_dependencies};
use crate::{
    config::{
        candidate::{dependencies, Documents},
        GatewaySnapshot,
    },
    control::journal::{storage, Journal},
};
use anyhow::{ensure, Context, Result};

impl Journal {
    /// 业务作用：在持久方向恢复时复用正常构建器重建实际候选，避免只在编译结束后读取一次文件证明。
    ///
    /// 参数说明：
    /// - `build`：同一版本、动态来源与部署根的正常语义构建器，不能开放监听或发布快照。
    ///
    /// 返回：普通状态只构建一次；未决方向要求重建前后证明均匹配。启动接纳旧所有权证据不足时先撤销覆盖权。
    pub fn build_action_candidate(
        &self,
        mut build: impl FnMut() -> Result<GatewaySnapshot>,
    ) -> Result<GatewaySnapshot> {
        let first = build()?;
        let guard = {
            let storage = self.storage.lock();
            self.verify_expected(storage.as_ref())?;
            let Some(current) = storage.as_ref() else {
                return Ok(first);
            };
            let Some(action) = current.action() else {
                return Ok(first);
            };
            let required = matches!(action.stage, Stage::Forward | Stage::Backward);
            let adopting = self.action_boot.get().is_none()
                && matches!(action.stage, Stage::Applied | Stage::Reverted)
                && action.publication.as_ref().is_some_and(|value| value.owned);
            if !required && !adopting {
                return Ok(first);
            }
            (current.revision(), expected_dependencies(action)?, required)
        };
        let before = capture(&first);
        if !before.is_ok_and(|proof| proof == guard.1) {
            // 未决文件方向不允许降级；旧已完成效果只能失去覆盖权，不能阻止普通有效配置启动。
            ensure!(
                !guard.2,
                "node action dependencies differ before candidate build"
            );
            self.withdraw_action_ownership(guard.0)?;
            return Ok(first);
        }
        drop(first);
        let candidate = build()?;
        let stable = capture(&candidate).is_ok_and(|proof| proof == guard.1);
        if !stable {
            ensure!(
                !guard.2,
                "node action dependencies changed during candidate build"
            );
            self.withdraw_action_ownership(guard.0)?;
        } else {
            let storage = self.storage.lock();
            self.verify_expected(storage.as_ref())?;
            ensure!(
                storage.as_ref().map(storage::Snapshot::revision) == Some(guard.0),
                "node action changed during candidate build"
            );
        }
        Ok(candidate)
    }

    /// 业务作用：启动重建不能证实原效果的依赖时先持久撤销所有权，不允许稍后文件恢复原值重新取得覆盖资格。
    ///
    /// 参数说明：
    /// - `revision`：开始候选重建时冻结的唯一提交序号。
    ///
    /// 返回：精确同一动作的覆盖权撤销并同步后成功；并发换代或提交未知拒绝。
    fn withdraw_action_ownership(&self, revision: u64) -> Result<()> {
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node action storage disappeared")?;
        ensure!(
            current.revision() == revision,
            "node action changed during candidate build"
        );
        let mut next = current.action().context("node action disappeared")?.clone();
        next.publication
            .as_mut()
            .context("node action publication disappeared")?
            .owned = false;
        self.advance_action(&mut storage, next)
    }
}

/// 业务作用：从正常部署文件布局获取候选依赖证明，三个 base 已由持久文件计划独立覆盖。
///
/// 参数说明：
/// - `snapshot`：本次实际构建的完整快照。
///
/// 返回：固定预算内的依赖摘要；读取或身份变化拒绝。
fn capture(snapshot: &GatewaySnapshot) -> Result<[u8; 32]> {
    dependencies::capture(
        snapshot,
        Documents {
            gateway: &snapshot.source_config_path,
            sidecars: None,
        },
    )
}
