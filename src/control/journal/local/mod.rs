//! 已授权本地发布的持久文件决定；不提供远端动作或Saga终态收据。

pub(super) mod apply;
pub(super) mod bodies;
#[cfg(feature = "node-actions")]
pub(super) mod materials;
mod model;
pub(super) mod prepare;

pub(super) use bodies::{inspect, known};
pub(super) use model::{Direction, Plan};
pub(crate) use prepare::Input;

use super::{storage, Journal};
use crate::{config::GatewaySnapshot, control::documents::Target};
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::{path::Path, sync::Arc};

/// 绑定同一owner和可选操作身份；无变化收据不授予文件副作用，恢复方向始终读取持久head。
pub(crate) struct Receipt {
    owner: Arc<Journal>,
    operation: Option<String>,
}

/// 低敏未决状态；不含原文、路径或远程执行成功声明。
#[derive(Serialize)]
pub(super) struct Status {
    operation: String,
    direction: Direction,
}

impl Status {
    /// 业务作用：把已提交文件方向提供给离线维护观察，不把文件决定解释成已应用快照。
    ///
    /// 参数说明：
    /// - `plan`：当前head唯一选择的记录。
    ///
    /// 返回：操作身份和方向，不泄露配置路径或正文。
    pub(super) fn from_plan(plan: &Plan) -> Self {
        Self {
            operation: plan.operation.clone(),
            direction: plan.direction,
        }
    }
}

impl Journal {
    /// 业务作用：合作 writer 先核对旧文件方向与正文归属，可失效的远程准备只在真正写入时撤销。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有未决文件方向且动作不保留应用或补偿材料时成功；Prepared 允许继续基线检查，identity-only保持允许。
    pub(crate) fn require_idle(&self) -> Result<()> {
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        ensure!(
            storage
                .as_ref()
                .and_then(storage::Snapshot::local)
                .is_none(),
            "node journal has a pending local publication"
        );
        #[cfg(feature = "node-actions")]
        Self::require_local_action_slot(storage.as_ref())?;
        Ok(())
    }

    /// 业务作用：只在显式初始化的存储模式接入持久文件协议，不自动升级identity-only部署。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：owner承认且复验的存储存在时为真，任何外部变化返回错误。
    pub(crate) fn durable_local_files(&self) -> Result<bool> {
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        Ok(storage.is_some())
    }

    /// 业务作用：先持久保存计划与正文，再提交唯一Forward决定，最后执行明确的本地文件替换。
    ///
    /// 参数说明：
    /// - `input`：已经通过语义与授权门的明确旧/新目标和原文借用。
    ///
    /// 返回：成功返回绑定本次计划的补偿收据；基线冲突为空，任何不确定失败保留持久保护记录。
    pub(crate) fn publish_local(self: &Arc<Self>, input: Input<'_>) -> Result<Option<Receipt>> {
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        ensure!(
            current.local().is_none(),
            "node journal has a pending local publication"
        );
        #[cfg(feature = "node-actions")]
        Self::require_local_action_slot(Some(current))?;
        let Some(mut prepared) = prepare::Prepared::new(input)? else {
            return Ok(None);
        };
        if prepared.plan.unchanged() {
            // 完整基线已复验且没有文件副作用，不能为无变化请求创建依赖未来信号才能结束的决定。
            return Ok(Some(Receipt {
                owner: self.clone(),
                operation: None,
            }));
        }
        #[cfg(feature = "node-actions")]
        self.invalidate_prepared_action(&mut storage)?;
        // 已提交Idle才允许回收前次未引用正文；Preparing必须先持久化，之后才能创建本次正文槽。
        bodies::clear(&self.root)?;
        self.advance(&mut storage, Some(prepared.plan.clone()))?;
        bodies::write(&self.root, &mut prepared)?;
        ensure!(
            prepare::baseline_matches(&prepared.plan)?,
            "local publication baseline changed before decision"
        );
        prepared.plan.direction = Direction::Forward;
        // Forward是配置副作用的唯一授权，rename后同步不确定时advance不会推进内存期望，也不会执行文件替换。
        self.advance(&mut storage, Some(prepared.plan.clone()))?;
        apply::run(&self.root, &prepared.plan)?;
        Ok(Some(Receipt {
            owner: self.clone(),
            operation: Some(prepared.plan.operation),
        }))
    }

    /// 业务作用：启动自举之前将未决记录绑定实际CLI主配置，并按唯一持久方向补齐文件集合。
    ///
    /// 参数说明：
    /// - `main`：本次启动实际使用的固定主配置路径。
    ///
    /// 返回：文件集合可供正常候选构建；资源准备与最终结束仍未完成，冲突保留记录并拒绝启动。
    pub(super) fn recover_local(&self, main: &Path) -> Result<()> {
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        #[cfg(feature = "node-actions")]
        if self.recover_action(&mut storage, main)? {
            return Ok(());
        }
        let Some(current) = storage.as_ref() else {
            return Ok(());
        };
        let Some(plan) = current.local().cloned() else {
            return bodies::clear(&self.root);
        };
        require_main(&plan, main)?;
        // 上次进程可能在head可见但目录同步之前退出，先持久确认唯一方向才能恢复任何目标。
        storage::confirm(&self.root, &self.identity, current)?;
        if plan.direction == Direction::Preparing {
            // Preparing从未授权配置暂存或目标替换，只回收固定正文；不能把未选槽里的Forward当作已提交。
            bodies::clear(&self.root)?;
            self.advance(&mut storage, None)?;
            return Ok(());
        }
        apply::run(&self.root, &plan)
    }

    /// 业务作用：唯一发布者完成资源prepare后确认文件决定，先结束本地记录再开放对应快照。
    ///
    /// 参数说明：
    /// - `snapshot`：已经通过正常语义、永久身份与资源准备的完整候选。
    ///
    /// 返回：原文、路径、目标与持久记录全部一致并结束后成功；失败不得发布ArcSwap或初始监听。
    pub fn complete_local_publication(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        self.validate_snapshot(snapshot)?;
        let mut storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        #[cfg(feature = "node-actions")]
        if self.before_action_publication(&mut storage, snapshot)? {
            return Ok(());
        }
        let Some(current) = storage.as_ref() else {
            return Ok(());
        };
        let Some(plan) = current.local().cloned() else {
            return bodies::clear(&self.root);
        };
        require_snapshot(&plan, snapshot)?;
        // 初始资源准备期间profile或文件型秘密也可能变化；三个base相同不能证明完整候选仍可开放。
        ensure!(
            snapshot.config_fingerprint.is_some()
                && crate::config::config_fingerprint(&snapshot.source_config_path).ok()
                    == snapshot.config_fingerprint,
            "local publication dependencies changed before completion"
        );
        apply::preflight(&self.root, &plan)?;
        apply::require_goal(&plan)?;
        apply::cleanup(&self.root, &plan)?;
        // 调用者仍持唯一文件事务；本地完成先持久化，随后才允许快照发布，不能产生跨进程半完成声明。
        self.advance(&mut storage, None)?;
        bodies::clear(&self.root)
    }

    /// 业务作用：外部策略发布必须让出未完成文件事务，不能用 xDS 候选代替文件动作确认。
    ///
    /// 参数说明：
    /// - `snapshot`：已经构建并完成资源准备的外部策略候选。
    ///
    /// 返回：不存在未决文件方向且旧动作覆盖权已撤销时成功；未知事实拒绝发布。
    #[cfg(feature = "xds-client")]
    pub(crate) fn prepare_external_publication(&self, snapshot: &GatewaySnapshot) -> Result<()> {
        self.validate_snapshot(snapshot)?;
        let storage = self.storage.lock();
        self.verify_expected(storage.as_ref())?;
        // 外部策略没有执行原文件决定的资源准备流程，必须等待正常文件发布者完成它。
        ensure!(
            storage
                .as_ref()
                .and_then(storage::Snapshot::local)
                .is_none(),
            "external snapshot cannot complete a local file decision"
        );
        #[cfg(feature = "node-actions")]
        {
            use super::actions::model::Stage;
            let mut storage = storage;
            ensure!(
                storage
                    .as_ref()
                    .and_then(storage::Snapshot::action)
                    .is_none_or(|action| !matches!(
                        action.stage,
                        Stage::Preparing | Stage::Forward | Stage::Backward | Stage::Protected
                    )),
                "external snapshot cannot complete an action file decision"
            );
            if !self.before_action_publication(&mut storage, snapshot)? {
                bodies::clear(&self.root)?;
            }
        }
        Ok(())
    }

    /// 业务作用：仅将完整同步成功的新head推进为本owner事实，失败不得自动接纳可见但未确认的提交。
    ///
    /// 参数说明：
    /// - `storage`：已经持锁的当前期望事实。
    /// - `plan`：下一文件方向或经确认的空闲状态。
    ///
    /// 返回：持久提交成功后更新内存，任何错误保留原期望并关闭后续写入。
    fn advance(&self, storage: &mut Option<storage::Snapshot>, plan: Option<Plan>) -> Result<()> {
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        let next = storage::transition(&self.root, &self.identity, current, plan)?;
        *storage = Some(next);
        Ok(())
    }

    /// 业务作用：离线比较交换选择原基线方向，不能由HTTP超时或墙钟自动撤销已决定候选。
    ///
    /// 参数说明：
    /// - `path`：部署固定的journal目录。
    /// - `main`：此次维护对应的主配置路径。
    /// - `expected`：只读状态提供的完整比较令牌。
    ///
    /// 返回：已持久Backward且文件恢复完成的状态；仍保留记录，正常启动准备资源后才结束。
    pub fn rollback_local(path: &Path, main: &Path, expected: &str) -> Result<super::Status> {
        let owner = Self::acquire(path)?;
        let mut storage = owner.storage.lock();
        owner.verify_expected(storage.as_ref())?;
        let current = storage
            .as_ref()
            .context("node journal action storage is not initialized")?;
        current.compare(expected)?;
        let mut plan = current
            .local()
            .cloned()
            .context("node journal has no local publication")?;
        require_main(&plan, main)?;
        ensure!(
            plan.direction != Direction::Preparing,
            "local publication has no file decision"
        );
        let changed = plan.direction != Direction::Backward;
        plan.direction = Direction::Backward;
        // 退役文件、全部目标和正文在方向提交之前一起复验，任何外来内容均不授予回退权。
        apply::preflight(&owner.root, &plan)?;
        if changed {
            owner.advance(&mut storage, Some(plan.clone()))?;
        } else {
            // 原Backward可能来自未确认同步的维护重试，不能仅凭可见方向直接继续文件副作用。
            storage::confirm(&owner.root, &owner.identity, current)?;
        }
        apply::run(&owner.root, &plan)?;
        Ok(super::status(&owner.identity, false, storage.as_ref()))
    }
}

impl Receipt {
    /// 业务作用：在外层活动版本与文件指纹门成立后，先持久选择Backward再执行精确恢复。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一未决Forward仍持有全部候选时恢复为真；记录已完成或换代为空权返回假，证据异常报错。
    pub(crate) fn restore(self) -> Result<bool> {
        let owner = &self.owner;
        let mut storage = owner.storage.lock();
        owner.verify_expected(storage.as_ref())?;
        let Some(operation) = self.operation else {
            // 无变化请求没有文件覆盖权；后续请求已受理时也不能替它结束正在进行的决定。
            return Ok(storage
                .as_ref()
                .and_then(storage::Snapshot::local)
                .is_none());
        };
        let Some(mut plan) = storage.as_ref().and_then(storage::Snapshot::local).cloned() else {
            return Ok(false);
        };
        if plan.operation != operation || plan.direction != Direction::Forward {
            return Ok(false);
        }
        // 进程内补偿要求完整候选仍归本请求，不能把任意旧/新中间态当作HTTP恢复资格。
        apply::require_goal(&plan)?;
        plan.direction = Direction::Backward;
        apply::preflight(&owner.root, &plan)?;
        owner.advance(&mut storage, Some(plan.clone()))?;
        apply::run(&owner.root, &plan)?;
        Ok(true)
    }
}

/// 业务作用：把待开放快照绑定到持久决定对应的原文与路径，另一候选不得越过未决文件事务。
///
/// 参数说明：
/// - `plan`：当前head的唯一文件决定。
/// - `snapshot`：正常构建得到的候选快照。
///
/// 返回：三个原文身份和明确来源位置匹配时成功；Preparing、缺证据或其它候选拒绝。
pub(super) fn require_snapshot(plan: &Plan, snapshot: &GatewaySnapshot) -> Result<()> {
    ensure!(
        plan.direction != Direction::Preparing,
        "local publication is still preparing"
    );
    let states = match plan.direction {
        Direction::Forward => plan
            .targets
            .each_ref()
            .map(|target| (&target.location, target.candidate)),
        Direction::Backward => plan
            .baseline
            .each_ref()
            .map(|document| (&document.location, document.state)),
        Direction::Preparing => unreachable!("preparing was rejected"),
    };
    for ((location, _), path) in states.iter().zip(snapshot.document_paths.ordered()) {
        ensure!(
            location.open()?.path == Target::open(path)?.path,
            "local publication candidate paths differ"
        );
    }
    let documents = [states[2].1, states[0].1, states[1].1]
        .map(|state| (state.body.fingerprint.length, state.body.fingerprint.sha256));
    ensure!(
        snapshot
            .document_identity
            .as_ref()
            .is_some_and(|identity| identity.matches_documents(documents)),
        "local publication candidate source identity differs"
    );
    Ok(())
}

/// 业务作用：恢复之前确认部署者仍启动同一个主配置，不能借用journal影响另一套业务文件。
///
/// 参数说明：
/// - `plan`：已提交的明确文件决定。
/// - `main`：实际CLI给出的主配置路径。
///
/// 返回：规范目标及父目录身份一致时成功，否则没有文件副作用。
pub(super) fn require_main(plan: &Plan, main: &Path) -> Result<()> {
    let expected = plan.baseline[2].location.open()?;
    ensure!(
        Target::open(main)?.path == expected.path,
        "local publication bootstrap path differs"
    );
    Ok(())
}
