//! 节点主动复用管理连接执行单个动作，网络等待取消不释放阻塞任务的真实许可。

use super::{
    admission::{Session, Work},
    body::Body,
    execution, release, release_wire, result,
};
use crate::{
    admin::{
        candidate::node,
        management::{issuer::Verifier, protocol, reporter::timed_request, Plan, RPC_TIMEOUT},
        AdminState,
    },
    control::actions::definition,
};
use anyhow::{ensure, Context, Result};
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
    /// 业务作用：在当前通道派发独立释放任务，和业务命令共用唯一任务及真实节点容量。
    ///
    /// 参数说明：
    /// - state：实际活动节点及永久文件 owner。
    /// - client：同一目标已认证的 mTLS 通道。
    /// - offer：心跳取得的有界独立释放消息。
    ///
    /// 返回：合法释放已受理或明确拒绝；不等待排队，也不提前确认节点关闭。
    pub(in crate::admin::management) fn start_release(
        &mut self,
        state: Arc<AdminState>,
        client: Client,
        offer: protocol::ReleaseOffer,
    ) -> Result<()> {
        ensure!(!self.busy(), "node action channel busy");
        let (release, signature) = release_wire::decode(offer)?;
        let work = release::Work::accept(
            &state,
            self.session
                .clone()
                .context("node release session unavailable")?,
            release,
            &signature,
        )?;
        self.task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            // 超时只取消网络等待；已经进入统一 writer 的工作继续持有实际许可，直到关闭或失败退出。
            let _ = tokio::time::timeout(Duration::from_secs(20), close(state, client, work)).await;
        })));
        Ok(())
    }

    /// 业务作用：只在发行者挑战成功后安装会话，替换连接前先撤销旧任务的写入资格。
    ///
    /// 参数说明：
    /// - `plan`：握手实际使用的已发布计划。
    /// - `issuer`：该计划的精确可信发行者。
    /// - `token`：接收端在当前 boot 建立的会话。
    ///
    /// 返回：当前会话安装成功；无受信发行者的通道保持无法执行动作。
    pub(in crate::admin::management) fn open(
        &mut self,
        plan: Arc<Plan>,
        issuer: Option<Arc<Verifier>>,
        token: &[u8],
    ) -> Result<()> {
        self.clear();
        if plan.actions_enabled {
            self.session = Some(Session::new(
                plan,
                issuer.context("node issuer missing")?,
                token,
            )?);
        }
        Ok(())
    }

    /// 业务作用：连接失效时先撤销授权再取消网络等待，旧闭包不能凭 Arc 延长会话寿命。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本通道不再接收新命令；已提交文件方向仍由持久 owner 恢复。
    pub(in crate::admin::management) fn clear(&mut self) {
        if let Some(session) = self.session.take() {
            session.revoke();
        }
        self.task.take();
    }

    /// 业务作用：让报告器保留心跳与动作两条流预算，动作结束后恢复目录和指标传输。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本通道仍有真实网络等待时为真；不会因其它 Admin 忙碌暂停本通道。
    pub(in crate::admin::management) fn busy(&mut self) -> bool {
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            self.task.take();
        }
        self.task.is_some()
    }

    /// 业务作用：在任何候选下载前验签和取得唯一节点容量，任务由本目标连接管理生命周期。
    ///
    /// 参数说明：
    /// - `state`：实际活动节点与文件 owner。
    /// - `client`：当前目标的复用 mTLS 通道。
    /// - `offer`：心跳取得的单个有限命令。
    ///
    /// 返回：任务已受理或明确拒绝；没有队列，也不把受理当作持久执行成功。
    pub(in crate::admin::management) fn start(
        &mut self,
        state: Arc<AdminState>,
        client: Client,
        offer: protocol::ActionOffer,
    ) -> Result<()> {
        ensure!(!self.busy(), "node action channel busy");
        let work = Work::accept(
            &state,
            self.session
                .clone()
                .context("node action session unavailable")?,
            offer,
        )?;
        self.task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            // 网络任务只有原签名的有限窗口；超时丢弃等待，阻塞闭包仍持有许可完成门禁和清理。
            let _ =
                tokio::time::timeout(Duration::from_secs(20), execute(state, client, work)).await;
        })));
        Ok(())
    }
}

impl Drop for Channel {
    /// 业务作用：目标移除或报告器退出时撤销会话，不能留下脱离连接 owner 的动作授权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同步撤销并取消网络任务，持久文件恢复责任保持不变。
    fn drop(&mut self) {
        self.clear();
    }
}

/// 业务作用：先查询真实效果，再按需下载和调用唯一执行器，稳定结果仍等待发行端事务确认。
///
/// 参数说明：
/// - `state`：真实节点状态，候选和文件工作沿用已有 owner。
/// - `client`：当前已验证发行者的复用连接。
/// - `work`：贯穿下载、执行与结果发送的原授权和独占容量。
///
/// 返回：结果已由发行端确认才成功；网络、时钟或权限失败保留持久事实供后续查询。
async fn execute(state: Arc<AdminState>, mut client: Client, work: Work) -> Result<()> {
    let (work, observed) = node::inspect(state.clone(), work).await?;
    let definition = definition::cached(work.command().intent.target_count as usize)?;
    let checked = work.command().validate(&definition)?;
    let offer_id = checked.message().to_owned();
    let needs_body = execution::needs_body(&work, &observed)?;
    let body = if needs_body {
        work.authorize(&state, true)?;
        let mut body = Body::new(&work.command().intent, &checked)?;
        loop {
            work.authorize(&state, true)?;
            let response = client
                .action_data(timed_request(
                    protocol::ActionDataRequest {
                        node_id: work.command().intent.node_id.clone(),
                        boot_id: work.command().delivery.receiving_boot_id.clone(),
                        session: work.command().delivery.session.to_vec(),
                        offer_id: offer_id.clone(),
                        offset: body.offset(),
                    },
                    tokio::time::Instant::now() + RPC_TIMEOUT,
                )?)
                .await?
                .into_inner();
            if body.push(response)? {
                break;
            }
        }
        Some(body.finish()?)
    } else {
        None
    };
    let (work, outcome) = execution::finish(state.clone(), work, observed, body).await?;
    let (outcome, reason) = result::encode(outcome)?;
    let result = protocol::ActionResultRequest {
        node_id: work.command().intent.node_id.clone(),
        boot_id: work.command().delivery.receiving_boot_id.clone(),
        session: work.command().delivery.session.to_vec(),
        offer_id: offer_id.clone(),
        outcome,
        reason,
    };
    let response = client
        .action_result(timed_request(
            result,
            tokio::time::Instant::now() + RPC_TIMEOUT,
        )?)
        .await?
        .into_inner();
    ensure!(
        response.accepted_offer_id == offer_id,
        "node action result acknowledgement differs"
    );
    work.authorize(&state, false)?;
    Ok(())
}

/// 业务作用：先关闭节点原代际再等待共享事务确认，全程保留同一个真实工作许可。
///
/// 参数说明：
/// - state：实际节点的当前授权与文件 owner。
/// - client：本通道已认证的原发行者连接。
/// - work：已验签并持有唯一容量的释放权。
///
/// 返回：持久关闭、共享确认及当前权限同时成立才成功；失联保留已关闭事实供同意图重投。
async fn close(state: Arc<AdminState>, mut client: Client, work: release::Work) -> Result<()> {
    let work = work.close(state.clone()).await?;
    let receipt = work.receipt()?;
    let release_id = receipt.release_id.clone();
    work.authorize(&state)?;
    let response = client
        .release_result(timed_request(
            receipt,
            tokio::time::Instant::now() + RPC_TIMEOUT,
        )?)
        .await?
        .into_inner();
    ensure!(
        response.accepted_release_id == release_id,
        "node release acknowledgement differs"
    );
    work.authorize(&state)?;
    Ok(())
}
