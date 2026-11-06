//! 本机目标仍经过独立签名和真实工作许可，完整原生结果与共享事务确认保持同一生命周期。

use super::{execution, node, release, Content, Session, Work};
use crate::{
    admin::{management::actions::ActionSession, AdminState},
    config::GatewaySnapshot,
    control::{
        journal::MaterialEffect,
        material::execution::{command::Command, release::Release},
    },
};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;

pub(in crate::admin) struct Local {
    state: Arc<AdminState>,
    snapshot: Arc<GatewaySnapshot>,
    session: Arc<Session>,
}

/// 原事实与实际节点许可一同保留，调用者必须在共享存储确认后才释放该值。
pub(in crate::admin) struct Received {
    pub outcome: MaterialEffect,
    work: Arc<Work>,
}

pub(in crate::admin) struct Released {
    work: release::Work,
}

impl Local {
    /// 业务作用：只为当前双角色节点建立独立材料会话，本机路径不借管理角色绕过实际Data与就绪门。
    ///
    /// 参数说明：
    /// - `state`：本机实际管理与数据共同owner。
    /// - `snapshot`：共享执行授权冻结的当前完整实例。
    /// - `cluster`：原执行永久绑定的集群。
    ///
    /// 返回：保持到共享结果确认的会话owner；角色、当前实例、发行者或独立开关不符拒绝。
    pub(in crate::admin) fn new(
        state: Arc<AdminState>,
        snapshot: Arc<GatewaySnapshot>,
        cluster: &str,
    ) -> Result<Self> {
        let session = {
            let _gate = state.management.publication.read();
            // 同进程直达不改变角色边界，管理-only节点不能冒充原材料目标执行文件动作。
            ensure!(
                state.mode.full_control_plane()
                    && state.mode.runs_data()
                    && crate::admin::cluster::facts::collect(&state, &snapshot).ready,
                "local material role unavailable"
            );
            Session::local(state.management.action_plan(&snapshot, cluster)?)?
        };
        Ok(Self {
            state,
            snapshot,
            session,
        })
    }

    /// 业务作用：让共享租约发行者使用本次实际会话与接收boot，不继承原审批时的临时连接身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前进程身份和此owner唯一随机令牌，不授予共享租约或文件权。
    pub(in crate::admin) fn address(&self) -> ActionSession {
        ActionSession {
            boot: self.state.monitor.boot_id().into(),
            token: self.session.token,
        }
    }

    /// 业务作用：在本机复验当前发行权和独立签名后运行材料生命周期，不进行协议或JSON往返。
    ///
    /// 参数说明：
    /// - `command`：共享批准、原分母和租约已复验的完整命令。
    /// - `content`：原记录唯一解密候选，只有首次准备使用，其余请求可为空。
    ///
    /// 返回：完整原生效果与实际节点许可；数据库确认前调用者必须持有并再次授权该返回值。
    pub(in crate::admin) async fn execute(
        &self,
        command: Command,
        content: Option<Arc<Content>>,
    ) -> Result<Received> {
        let work = {
            let _gate = self.state.management.publication.read();
            let plan = self
                .state
                .management
                .action_plan(&self.snapshot, &command.intent.baseline.cluster_id)?;
            let signer = plan
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.issuer.as_ref())
                .context("local material issuer unavailable")?;
            let signature = signer.sign_material_command(&plan.node_id, &command)?;
            Work::accept(&self.state, self.session.clone(), command, &signature)?
        };
        let observed = node::inspect(self.state.clone(), work.clone()).await?;
        let content = if node::needs_body(&work, &observed)? {
            work.authorize(&self.state, true)?;
            content
        } else {
            None
        };
        let outcome =
            execution::finish(self.state.clone(), work.clone(), observed, content).await?;
        Ok(Received {
            outcome,
            work,
        })
    }

    /// 业务作用：用当前本机发行者和独立释放域关闭原材料代际，不把终态名称单独作为清理权。
    ///
    /// 参数说明：
    /// - `release`：共享终态与当前租约已经确认的原完整释放请求。
    ///
    /// 返回：实际关闭后的确认权；保持许可到共享释放事务结束，取消等待不终止后台精确清理责任。
    pub(in crate::admin) async fn release(&self, release: Release) -> Result<Released> {
        let work = {
            let _gate = self.state.management.publication.read();
            let plan = self
                .state
                .management
                .action_plan(&self.snapshot, &release.intent.baseline.cluster_id)?;
            let signer = plan
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.issuer.as_ref())
                .context("local material issuer unavailable")?;
            let signature = signer.sign_material_release(&plan.node_id, &release)?;
            release::Work::accept(&self.state, self.session.clone(), release, &signature)?
        };
        Ok(Released {
            work: work.close(self.state.clone()).await?,
        })
    }
}

impl Drop for Local {
    /// 业务作用：本机投递owner退出立即撤销未提交权威，持有旧Arc的阻塞任务也必须在下一门停止。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：取消原会话资格，已同步的文件方向与清理责任继续由Journal承担。
    fn drop(&mut self) {
        self.session.revoke();
    }
}

impl Received {
    /// 业务作用：在共享事务确认前复验原节点工作权，本机直接调用不能省略网络交付所需的当前授权。
    ///
    /// 参数说明：
    /// - `state`：同一真实节点owner。
    ///
    /// 返回：当前读取、原会话和有限窗口仍成立才成功；失败不否认已经提交的原生事实。
    pub(in crate::admin) fn authorize(&self, state: &AdminState) -> Result<()> {
        self.work.authorize(state, false)
    }
}

impl Released {
    /// 业务作用：共享释放确认前保持当前节点写权与真实已关闭证明，受理不能替代同步关闭。
    ///
    /// 参数说明：
    /// - `state`：同一实际节点owner。
    ///
    /// 返回：原权限和期限有效且已实际关闭才成功，旧会话不能继续确认。
    pub(in crate::admin) fn authorize(&self, state: &AdminState) -> Result<()> {
        self.work.closed()?;
        self.work.authorize(state)
    }
}
