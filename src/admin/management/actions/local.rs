//! 同进程目标复用签名与节点工作权，正文直接共享，目标仍须持有共享数据库租约。

use super::{
    admission::{Session, Work},
    execution, release, result, ActionSession,
};
use crate::{
    admin::{candidate::node, AdminState},
    config::GatewaySnapshot,
    control::actions::{command::Command, definition, release::Release},
};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use nasaga_runtime_core::SagaResultEnvelope;
use std::sync::Arc;

pub(in crate::admin) struct Local {
    state: Arc<AdminState>,
    snapshot: Arc<GatewaySnapshot>,
    session: Arc<Session>,
}

/// 调用者在数据库确认前持有此值，真实节点许可不能随网络等待提前释放。
pub(in crate::admin) struct Received {
    work: Work,
    pub(in crate::admin) result: Option<SagaResultEnvelope>,
}

pub(in crate::admin) struct Released {
    work: release::Work,
}

impl Local {
    /// 业务作用：本机目标直接复用独立签名与真实释放工作，不为同进程路径编码 protobuf 或复制正文。
    ///
    /// 参数说明：
    /// - release：共享安全终态及一次性租约已经确认的原目标声明。
    ///
    /// 返回：代际持久关闭且仍持节点许可的确认权；必须保留到共享释放事务结束。
    pub(in crate::admin) async fn release(&self, release: Release) -> Result<Released> {
        let work = {
            let _gate = self.state.management.publication.read();
            let plan = self
                .state
                .management
                .action_plan(&self.snapshot, &release.intent.baseline.cluster_id)?;
            let definition = definition::cached(release.intent.target_count as usize)?;
            let signer = plan
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.issuer.as_ref())
                .context("local issuer unavailable")?;
            let signature = signer.sign_release(&plan.node_id, &release, &definition)?;
            release::Work::accept(&self.state, self.session.clone(), release, &signature)?
        };
        Ok(Released {
            work: work.close(self.state.clone()).await?,
        })
    }

    /// 业务作用：为 all-in-one 自身建立受当前发行计划约束的本机会话，不登记伪远端成员。
    ///
    /// 参数说明：
    /// - state：本机实际管理和数据共同 owner。
    /// - snapshot：执行权限冻结的完整活动实例。
    /// - cluster：原执行永久绑定的集群。
    ///
    /// 返回：必须由调用者持有至结果确认的会话 owner；非双角色或当前发行权无效时拒绝。
    pub(in crate::admin) fn new(
        state: Arc<AdminState>,
        snapshot: Arc<GatewaySnapshot>,
        cluster: &str,
    ) -> Result<Self> {
        let session = {
            let _gate = state.management.publication.read();
            ensure!(
                state.mode.full_control_plane() && state.mode.runs_data(),
                "local action role unavailable"
            );
            ensure!(
                crate::admin::cluster::facts::collect(&state, &snapshot).ready,
                "local action node is not ready"
            );
            let plan = state.management.action_plan(&snapshot, cluster)?;
            Session::local(plan)?
        };
        Ok(Self {
            state,
            snapshot,
            session,
        })
    }

    /// 业务作用：将本次私有会话地址交给租约签发器，不能复用原审批时的 boot 或外部自报会话。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：实际进程启动身份和此 owner 的随机 token，不包含数据库租约。
    pub(in crate::admin) fn address(&self) -> ActionSession {
        ActionSession {
            boot: self.state.monitor.boot_id().to_owned(),
            token: self.session.token,
        }
    }

    /// 业务作用：签发并复验本机命令后执行真实节点工作，候选原文直接借用同一 Bytes。
    ///
    /// 参数说明：
    /// - command：已确认租约、完整原意图和本次会话的有限命令。
    /// - body：同一审批候选的共享原文；只有新 prepare 才交给文件工作。
    ///
    /// 返回：仍持有节点许可的未确认结果；取消等待先由 owner 撤权，真实阻塞工作自行结束。
    pub(in crate::admin) async fn execute(
        &self,
        command: Command,
        body: Bytes,
    ) -> Result<Received> {
        let work = {
            let _gate = self.state.management.publication.read();
            let plan = self
                .state
                .management
                .action_plan(&self.snapshot, &command.intent.baseline.cluster_id)?;
            let definition = definition::cached(command.intent.target_count as usize)?;
            let signer = plan
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.issuer.as_ref())
                .context("local issuer unavailable")?;
            let signature = signer.sign_command(&plan.node_id, &command, &definition)?;
            Work::accept_native(&self.state, self.session.clone(), command, &signature)?
        };
        let (work, observed) = node::inspect(self.state.clone(), work).await?;
        let body = if execution::needs_body(&work, &observed)? {
            work.authorize(&self.state, true)?;
            Some(body)
        } else {
            None
        };
        let (work, outcome) = execution::finish(self.state.clone(), work, observed, body).await?;
        let result = result::from_state(work.command(), outcome)?;
        Ok(Received {
            work,
            result,
        })
    }
}

impl Drop for Local {
    /// 业务作用：在本机投递 owner 退出时立即撤销未提交工作，取消等待不能遗留可写会话。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续权限门拒绝；已持久文件方向与真实阻塞许可由原任务负责收尾。
    fn drop(&mut self) {
        self.session.revoke();
    }
}

impl Received {
    /// 业务作用：确认事务前再次复验节点原工作权，不能因本机调用省去远程 ACK 具有的当前授权门。
    ///
    /// 参数说明：
    /// - state：同一活动节点实例。
    ///
    /// 返回：当前只读事实权仍有效才成功；失败不否认数据库中已提交的稳定结果。
    pub(in crate::admin) fn authorize(&self, state: &AdminState) -> Result<()> {
        self.work.authorize(state, false)
    }
}

impl Released {
    /// 业务作用：共享释放确认前保持原本机工作权，权限和会话改变时不继续声明确认成功。
    ///
    /// 参数说明：
    /// - state：同一实际节点 owner。
    ///
    /// 返回：原写权和单调期限仍有效时成功；已经持久关闭的事实不因失权被撤销。
    pub(in crate::admin) fn authorize(&self, state: &AdminState) -> Result<()> {
        self.work.authorize(state)
    }
}
