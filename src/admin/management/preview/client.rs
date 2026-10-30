//! 预览沿节点主动管理连接执行，单连接不积压任务或保留历史结果。

use super::{
    body::Body,
    node,
    session::{Session, Work},
    wire, Reason,
};
use crate::admin::{
    management::{issuer::Verifier, protocol, reporter::timed_request, Plan, RPC_TIMEOUT},
    AdminState,
};
use nasa::grpc::Channel as GrpcChannel;
use std::{sync::Arc, time::Duration};
use tokio_util::task::AbortOnDropHandle;

type Client = protocol::node_management_client::NodeManagementClient<GrpcChannel>;

#[derive(Default)]
pub(in crate::admin::management) struct Channel {
    session: Option<Arc<Session>>,
    task: Option<AbortOnDropHandle<()>>,
}

impl Channel {
    /// 业务作用：只在已验证发行者的连接上安装独立预览会话，显式关闭时不创建执行 owner。
    ///
    /// 参数说明：
    /// - `plan`：本连接实际握手所用的当前管理计划。
    /// - `issuer`：该计划明确允许的原目标发行者。
    /// - `token`：已通过挑战的会话字节。
    ///
    /// 返回：预览会话安装或保持关闭；开启但缺失可信发行者时拒绝。
    pub(in crate::admin::management) fn open(
        &mut self,
        plan: Arc<Plan>,
        issuer: Option<Arc<Verifier>>,
        token: &[u8],
    ) -> Result<(), Reason> {
        self.clear();
        if plan.previews_enabled {
            self.session = Some(Session::new(plan, issuer.ok_or(Reason::Denied)?, token)?);
        }
        Ok(())
    }

    /// 业务作用：连接失效时先撤销原会话再取消网络等待，不能通过后台 Arc 保留预览权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原连接不再受理或交付新结果，已经运行的阻塞构建继续承担真实清理责任。
    pub(in crate::admin::management) fn clear(&mut self) {
        if let Some(session) = self.session.take() {
            session.revoke();
        }
        self.task.take();
    }

    /// 业务作用：让上报器与持久动作共享原有两条 RPC 预算，预览只占其中一条后台工作通道。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚有网络任务时为真；结束后立即回收句柄，不保留历史结果。
    pub(in crate::admin::management) fn busy(&mut self) -> bool {
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            self.task.take();
        }
        self.task.is_some()
    }

    /// 业务作用：在原文下载前完成独立验签，每个连接最多受理一个有限预览任务。
    ///
    /// 参数说明：
    /// - `state`：实际目标的当前配置和有限候选容量。
    /// - `client`：同一已认证管理端点的复用通道。
    /// - `offer`：心跳收到的原目标只读证明。
    ///
    /// 返回：合法任务已受理或明确拒绝；不排队、不创建持久动作、不提前确认预览成功。
    pub(in crate::admin::management) fn start(
        &mut self,
        state: Arc<AdminState>,
        mut client: Client,
        offer: protocol::PreviewOffer,
    ) -> Result<(), Reason> {
        if self.busy() {
            return Err(Reason::Capacity);
        }
        let (command, signature) = wire::decode(offer)?;
        let command = Arc::new(command);
        let verified = self
            .session
            .as_ref()
            .ok_or(Reason::Disabled)?
            .verify(command.clone(), &signature)?;
        let message = verified.message.clone();
        let work = Work::accept(&state, verified);
        self.task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(20), async {
                let result = match &work {
                    Ok(work) => execute(state.clone(), &mut client, work.clone()).await,
                    Err(reason) => Err(*reason),
                };
                let result = match &work {
                    Ok(work) => work.authorize(&state).and(result),
                    Err(_) => result,
                };
                let (status, summary) = match result {
                    Ok(summary) => (
                        protocol::PreviewStatus::Succeeded,
                        Some(wire::summary(summary)),
                    ),
                    Err(reason) => (wire::status(reason), None),
                };
                let request = protocol::PreviewResultRequest {
                    node_id: command.intent.node.clone(),
                    boot_id: command.intent.boot.clone(),
                    session: command.session.to_vec(),
                    offer_id: message.clone(),
                    status: status as i32,
                    summary,
                };
                if let Ok(request) =
                    timed_request(request, tokio::time::Instant::now() + RPC_TIMEOUT)
                {
                    let _ = client.preview_result(request).await;
                }
            })
            .await;
        })));
        Ok(())
    }
}

impl Drop for Channel {
    /// 业务作用：目标移除或上报器停止时同步撤销只读会话，网络任务不能脱离其连接 owner 存活。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原会话与等待任务被取消，实际构建工作仍保留清理所需许可。
    fn drop(&mut self) {
        self.clear();
    }
}

/// 业务作用：在原目标下载完整候选、构建并复验基线，任何等待都不能扩大签名窗口。
///
/// 参数说明：
/// - `state`：原目标的当前活动配置与持久基线读取入口。
/// - `client`：原受信端点的复用客户端。
/// - `work`：贯穿正文、构建、清理和回报的真实预览许可。
///
/// 返回：完整低敏差异或有限失败类别；数据面与持久动作状态不由此路径修改。
async fn execute(
    state: Arc<AdminState>,
    client: &mut Client,
    work: Arc<Work>,
) -> Result<crate::admin::diff::model::Summary, Reason> {
    work.baseline(&state).await?;
    let mut body = Body::new(&work);
    loop {
        work.authorize(&state)?;
        let request = protocol::PreviewDataRequest {
            node_id: work.command.intent.node.clone(),
            boot_id: work.command.intent.boot.clone(),
            session: work.command.session.to_vec(),
            offer_id: work.message.clone(),
            offset: body.offset(),
        };
        let request = timed_request(request, tokio::time::Instant::now() + RPC_TIMEOUT)
            .map_err(|_| Reason::Expired)?;
        let part = client
            .preview_data(request)
            .await
            .map_err(|_| Reason::Unavailable)?
            .into_inner();
        if body.push(part)? {
            break;
        }
    }
    node::inspect(state, work, body.finish()?).await
}
