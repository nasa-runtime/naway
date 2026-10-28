//! 终态释放与业务执行共享真实许可，关闭代际的阻塞工作不能被外层取消提前解除互斥。

use super::admission::{Admission, Session};
use crate::{
    admin::{management::protocol, AdminState},
    control::actions::{definition, release::Release},
};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;

pub(super) struct Work {
    release: Release,
    admission: Admission,
    closed: bool,
}

impl Work {
    /// 业务作用：在文件工作前固定已验真的释放声明与当前写权，释放不能绕过业务动作的唯一许可。
    ///
    /// 参数说明：
    /// - state：实际节点的管理实例。
    /// - session：本通道已经验证发行者身份的当前会话。
    /// - release：独立终态释放声明。
    /// - signature：该声明的独立域签名。
    ///
    /// 返回：持有真实工作容量的释放权；错误签名、失权、过期或繁忙均无持久副作用。
    pub(super) fn accept(
        state: &AdminState,
        session: Arc<Session>,
        release: Release,
        signature: &str,
    ) -> Result<Self> {
        let admission = Admission::release(state, session, &release, signature)?;
        Ok(Self {
            release,
            admission,
            closed: false,
        })
    }

    /// 业务作用：关闭代际与确认之间始终复验原权限，已完成文件提交也不能延长原会话写权。
    ///
    /// 参数说明：
    /// - state：当前节点 owner。
    ///
    /// 返回：原会话、计划实例、双人写权及单调期限仍成立时成功。
    pub(super) fn authorize(&self, state: &AdminState) -> Result<()> {
        self.admission
            .authorize(state, &self.release.intent, &self.release.delivery, true)
    }

    /// 业务作用：在统一文件 writer 内永久关闭原代际，真实阻塞闭包持有许可直到存储与清理完成。
    ///
    /// 参数说明：
    /// - state：提供当前授权、唯一文件事务及永久 journal 的节点。
    ///
    /// 返回：关闭成功后的原工作权供确认阶段继续持有；取消等待不会释放仍在运行的阻塞工作容量。
    pub(super) async fn close(mut self, state: Arc<AdminState>) -> Result<Self> {
        self.authorize(&state)?;
        tokio::task::spawn_blocking(move || {
            state.config_history.with_node_action(|journal| {
                journal.release_action(&self.release, || self.authorize(&state))?;
                self.authorize(&state)?;
                self.closed = true;
                Ok(self)
            })
        })
        .await
        .context("node terminal release worker did not complete")?
    }

    /// 业务作用：只从实际持久关闭成功的工作生成有限确认，不把受理或任务创建解释为释放完成。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：包含原意图、存储、代际及当前签名摘要的关闭事实；尚未关闭或合同不符时拒绝。
    pub(super) fn receipt(&self) -> Result<protocol::ReleaseResultRequest> {
        ensure!(self.closed, "node release has not closed its epoch");
        let definition = definition::cached(self.release.intent.target_count as usize)?;
        let checked = self.release.validate(&definition)?;
        Ok(protocol::ReleaseResultRequest {
            node_id: self.release.intent.node_id.clone(),
            boot_id: self.release.delivery.receiving_boot_id.clone(),
            session: self.release.delivery.session.to_vec(),
            release_id: checked.message,
            intent_sha256: checked.intent_sha256.to_vec(),
            store_id: self.release.intent.baseline.store_id.clone(),
            node_admission_epoch: self.release.intent.baseline.node_admission_epoch.parse()?,
            closed: true,
        })
    }
}
