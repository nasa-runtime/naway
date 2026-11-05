//! 材料条件查询沿节点主动管理连接执行，单连接不积压任务或保留历史结果。

use super::{
    Reason, node,
    session::{Session, Work},
    wire,
};
use crate::admin::{
    AdminState,
    management::{Plan, RPC_TIMEOUT, issuer::Verifier, protocol, reporter::timed_request},
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
    /// 业务作用：只在已验证发行者的连接上安装独立材料条件查询会话，显式关闭时不创建执行 owner。
    ///
    /// 参数说明：
    /// - `plan`：本连接实际握手所用的当前管理计划。
    /// - `issuer`：该计划明确允许的原目标发行者。
    /// - `token`：已通过挑战的会话字节。
    ///
    /// 返回：材料条件查询会话安装或保持关闭；开启但缺失可信发行者时拒绝。
    pub(in crate::admin::management) fn open(
        &mut self,
        plan: Arc<Plan>,
        issuer: Option<Arc<Verifier>>,
        token: &[u8],
    ) -> Result<(), Reason> {
        self.clear();
        if plan.material_previews_enabled || plan.material_installations_enabled {
            self.session = Some(Session::new(plan, issuer.ok_or(Reason::Denied)?, token)?);
        }
        Ok(())
    }

    /// 业务作用：连接失效时先撤销原会话再取消网络等待，不能通过后台 Arc 保留材料条件查询权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原连接不再受理或交付新结果，已经运行的文件观察继续承担真实清理责任。
    pub(in crate::admin::management) fn clear(&mut self) {
        if let Some(session) = self.session.take() {
            session.revoke();
        }
        self.task.take();
    }

    /// 业务作用：让上报器与持久动作共享原有两条 RPC 预算，材料条件查询只占其中一条后台工作通道。
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

    /// 业务作用：在材料文件读取前完成独立验签，每个连接最多受理一个有限材料条件查询任务。
    ///
    /// 参数说明：
    /// - `state`：实际目标的当前配置和独立材料观察容量。
    /// - `client`：同一已认证管理端点的复用通道。
    /// - `offer`：心跳收到的原目标只读证明。
    ///
    /// 返回：合法任务已受理或明确拒绝；不排队、不创建持久动作、不提前确认材料条件查询成功。
    pub(in crate::admin::management) fn start(
        &mut self,
        state: Arc<AdminState>,
        mut client: Client,
        offer: protocol::MaterialConditionsOffer,
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
                    Ok(work) => node::inspect(state.clone(), work.clone()).await,
                    Err(reason) => Err(*reason),
                };
                let result = match &work {
                    Ok(work) => work.authorize(&state).and(result),
                    Err(_) => result,
                };
                let result = result.and_then(|batch| wire::encode_result(batch, &command.intent));
                let (status, batch, installations) = match result {
                    Ok((batch, installations)) => (
                        protocol::MaterialConditionsStatus::Succeeded,
                        Some(batch),
                        installations,
                    ),
                    Err(reason) => (wire::status(reason), None, None),
                };
                let request = protocol::MaterialConditionsResultRequest {
                    node_id: command.intent.node.clone(),
                    boot_id: command.intent.boot.clone(),
                    session: command.session.to_vec(),
                    offer_id: message.clone(),
                    status: status as i32,
                    batch,
                    installations,
                };
                if let Ok(request) =
                    timed_request(request, tokio::time::Instant::now() + RPC_TIMEOUT)
                {
                    let _ = client.material_conditions_result(request).await;
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
    /// 返回：原会话与等待任务被取消，实际材料读取仍保留清理所需许可。
    fn drop(&mut self) {
        self.clear();
    }
}
