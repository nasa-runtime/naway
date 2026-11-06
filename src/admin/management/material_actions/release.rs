//! 终态清理与普通材料工作使用同一节点容量，清理决定始终受当前四主体和独立签名约束。

use super::admission::{Admission, Session};
use crate::{admin::AdminState, control::material::execution::release::Release};
use anyhow::{ensure, Context, Result};
use std::{sync::Arc, time::Duration};

pub(super) struct Work {
    release: Release,
    admission: Admission,
    closed: bool,
}

impl Work {
    /// 业务作用：验真独立材料释放域并取得真实排他许可，释放不绕过仍在执行的配置或材料动作。
    ///
    /// 参数说明：
    /// - `state`：当前真实节点与进程动作容量。
    /// - `session`：当前已经通过发行者挑战的材料会话。
    /// - `release`：绑定原意图和物理位置的共享终态声明。
    /// - `signature`：同次独立释放证明。
    ///
    /// 返回：持有当前写权的工作；无效签名、期限、权限或容量均无持久副作用。
    pub(super) fn accept(
        state: &AdminState,
        session: Arc<Session>,
        release: Release,
        signature: &str,
    ) -> Result<Self> {
        let checked =
            session
                .issuer
                .verify_material_release(&release, signature, &session.token)?;
        let admission = Admission::claim(state, session, &release.delivery, &checked.message)?;
        let work = Self {
            release,
            admission,
            closed: false,
        };
        work.authorize(state)?;
        Ok(work)
    }

    /// 业务作用：清理和确认都复验当前四主体，原共享终态不能延长已经失效的会话或本机权限。
    ///
    /// 参数说明：
    /// - `state`：当前节点owner。
    ///
    /// 返回：原会话、实例、完整影响范围和写入/审阅权仍成立才成功。
    pub(super) fn authorize(&self, state: &AdminState) -> Result<()> {
        self.admission
            .authorize(state, &self.release.intent, &self.release.delivery, true)
    }

    /// 业务作用：按统一锁序提交清理责任并永久关闭原代际，真实阻塞任务负责持有许可直到清理结束。
    ///
    /// 参数说明：
    /// - `state`：提供当前权威、发布锁与永久Journal的节点。
    ///
    /// 返回：已确认关闭的原工作供回执阶段继续持有；取消等待不释放后台任务的实际名额。
    pub(super) async fn close(mut self, state: Arc<AdminState>) -> Result<Self> {
        self.authorize(&state)?;
        let publication =
            tokio::time::timeout(Duration::from_secs(2), state.apply_coordinator.lock_owned())
                .await
                .context("material release publication capacity unavailable")?;
        self.authorize(&state)?;
        tokio::task::spawn_blocking(move || {
            let _publication = publication;
            state.config_history.with_node_action(|journal| {
                journal.release_material(&self.release, || self.authorize(&state))?;
                self.authorize(&state)?;
                self.closed = true;
                Ok(self)
            })
        })
        .await
        .context("material release worker did not complete")?
    }

    /// 业务作用：仅为已经同步关闭的原请求提供确认身份，受理或清理开始不能被解释为释放完成。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原释放声明的借用；尚未持久关闭拒绝，不复制原完整意图。
    pub(super) fn closed(&self) -> Result<&Release> {
        ensure!(self.closed, "material release is not closed");
        Ok(&self.release)
    }
}
