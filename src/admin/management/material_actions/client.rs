//! 材料任务复用已经认证的管理连接，真实工作许可覆盖下载、执行及共享结果确认。

use super::{body::Body, execution, node, release, report, wire, Session, Work};
use crate::{
    admin::{
        management::{
            issuer::Verifier, protocol, reporter::timed_request, Plan, MAX_MESSAGE, RPC_TIMEOUT,
        },
        AdminState,
    },
    control::journal::MaterialEffect,
};
use anyhow::{ensure, Context, Result};
use nasa::grpc::{codegen::prost::Message, Channel as GrpcChannel};
use std::{sync::Arc, time::Duration};
use tokio_util::task::AbortOnDropHandle;
use zeroize::Zeroizing;

type Client = protocol::node_management_client::NodeManagementClient<GrpcChannel>;

#[derive(Default)]
pub(in crate::admin::management) struct Channel {
    session: Option<Arc<Session>>,
    task: Option<AbortOnDropHandle<()>>,
}

impl Channel {
    /// 业务作用：只在发行者挑战完成后建立独立材料会话，换连接先撤销旧工作权威。
    ///
    /// 参数说明：
    /// - `plan`：握手采用的精确已发布计划。
    /// - `issuer`：该连接实际核验的受信发行者。
    /// - `token`：挑战绑定的当前随机会话。
    ///
    /// 返回：显式启用时安装材料会话；关闭时保持无执行权，身份不符拒绝。
    pub(in crate::admin::management) fn open(
        &mut self,
        plan: Arc<Plan>,
        issuer: Option<Arc<Verifier>>,
        token: &[u8],
    ) -> Result<()> {
        self.clear();
        if plan.material_actions_enabled {
            self.session = Some(Session::new(
                plan,
                issuer.context("material issuer absent")?,
                token,
            )?);
        }
        Ok(())
    }

    /// 业务作用：连接失效立即撤销原会话，再取消网络等待，旧后台闭包不能靠Arc延长写权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不再接受新投递；已同步的文件方向仍由永久Journal承担。
    pub(in crate::admin::management) fn clear(&mut self) {
        if let Some(session) = self.session.take() {
            session.revoke();
        }
        self.task.take();
    }

    /// 业务作用：让报告器保留心跳和单个材料任务的并发预算，不把结束任务长期计为繁忙。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍有本连接网络任务时为真；节点实际文件容量由工作许可独立保留。
    pub(in crate::admin::management) fn busy(&mut self) -> bool {
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            self.task.take();
        }
        self.task.is_some()
    }

    /// 业务作用：在秘密下载之前独立验签并取得真实动作许可，单槽不为忙碌节点排队。
    ///
    /// 参数说明：
    /// - `state`：当前真实节点owner。
    /// - `client`：同一已认证管理通道。
    /// - `offer`：完整材料命令及独立签名。
    ///
    /// 返回：有限任务已受理或明确拒绝；受理不等于任何持久材料效果。
    pub(in crate::admin::management) fn start(
        &mut self,
        state: Arc<AdminState>,
        client: Client,
        offer: protocol::MaterialActionOffer,
    ) -> Result<()> {
        ensure!(!self.busy(), "material channel busy");
        let (command, signature) = wire::decode(offer)?;
        let work = Work::accept(
            &state,
            self.session.clone().context("material session absent")?,
            command,
            &signature,
        )?;
        self.task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            // 超时只取消网络等待；真实阻塞文件任务仍持有原许可并遵守撤权门。
            let _ =
                tokio::time::timeout(Duration::from_secs(20), execute(state, client, work)).await;
        })));
        Ok(())
    }

    /// 业务作用：独立终态清理与业务执行共享同一通道及实际节点容量，不以终态名称跳过验签。
    ///
    /// 参数说明：
    /// - `state`：原目标节点owner。
    /// - `client`：同一已认证发行连接。
    /// - `offer`：完整独立释放声明。
    ///
    /// 返回：清理任务已受理或明确拒绝；未同步关闭前不发送确认。
    pub(in crate::admin::management) fn start_release(
        &mut self,
        state: Arc<AdminState>,
        client: Client,
        offer: protocol::MaterialReleaseOffer,
    ) -> Result<()> {
        ensure!(!self.busy(), "material channel busy");
        let (declaration, signature) = wire::decode_release(offer)?;
        let work = release::Work::accept(
            &state,
            self.session.clone().context("material session absent")?,
            declaration,
            &signature,
        )?;
        self.task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            // 真实清理不随网络等待取消提前释放名额，关闭事实可由原意图重投确认。
            let _ = tokio::time::timeout(Duration::from_secs(20), close(state, client, work)).await;
        })));
        Ok(())
    }
}

impl Drop for Channel {
    /// 业务作用：目标移除或报告器退出立即撤销会话，避免留下脱离连接的材料执行权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：撤销并取消网络任务，永久责任不被删除。
    fn drop(&mut self) {
        self.clear();
    }
}

/// 业务作用：先读原效果再按需下载唯一秘密帧，完整事实交付后等待共享持久事务确认。
///
/// 参数说明：
/// - `state`：节点实际配置、文件和监听owner。
/// - `client`：已认证发行者的当前管理连接。
/// - `work`：覆盖整个请求的独立授权与真实动作许可。
///
/// 返回：共享端确认且当前权威仍成立才成功；网络失败保留原持久事实供后续Resolve。
async fn execute(state: Arc<AdminState>, mut client: Client, work: Arc<Work>) -> Result<()> {
    let observed = node::inspect(state.clone(), work.clone()).await?;
    let command = work.command();
    let message = command.validate()?.message().to_owned();
    let content = if node::needs_body(&work, &observed)? {
        work.authorize(&state, true)?;
        let mut body = Body::new(work.clone())?;
        loop {
            work.authorize(&state, true)?;
            let response = client
                .material_action_data(timed_request(
                    protocol::MaterialActionDataRequest {
                        node_id: command.intent.node_id.clone(),
                        boot_id: command.delivery.receiving_boot_id.clone(),
                        session: command.delivery.session.to_vec(),
                        offer_id: message.clone(),
                        offset: body.offset(),
                    },
                    tokio::time::Instant::now() + RPC_TIMEOUT,
                )?)
                .await?
                .into_inner();
            let fragment = Zeroizing::new(response.body);
            work.authorize(&state, true)?;
            if body.push(&response.offer_id, response.offset, response.eof, fragment)? {
                break;
            }
        }
        Some(body.finish()?)
    } else {
        None
    };
    let outcome = execution::finish(state.clone(), work.clone(), observed, content).await?;
    work.authorize(&state, false)?;
    use protocol::material_action_result_request::Observation;
    let observation = match outcome {
        MaterialEffect::Pending(facts)
        | MaterialEffect::Stable {
            facts,
            ..
        } => Observation::Report(report::encode(
            &facts.report()?,
            &command.intent,
            command.position,
        )?),
        MaterialEffect::Vacant => {
            Observation::Missing(protocol::MaterialExecutionMissing::Vacant as i32)
        }
        MaterialEffect::Closed => {
            Observation::Missing(protocol::MaterialExecutionMissing::Closed as i32)
        }
    };
    let request = protocol::MaterialActionResultRequest {
        node_id: command.intent.node_id.clone(),
        boot_id: command.delivery.receiving_boot_id.clone(),
        session: command.delivery.session.to_vec(),
        offer_id: message.clone(),
        observation: Some(observation),
    };
    ensure!(
        request.encoded_len() <= MAX_MESSAGE,
        "material result capacity exceeded"
    );
    work.authorize(&state, false)?;
    let response = client
        .material_action_result(timed_request(
            request,
            tokio::time::Instant::now() + RPC_TIMEOUT,
        )?)
        .await?
        .into_inner();
    ensure!(
        response.accepted_offer_id == message,
        "material acknowledgement differs"
    );
    work.authorize(&state, false)
}

/// 业务作用：本机同步关闭原责任后才发送独立释放确认，真实许可保持到共享端提交结束。
///
/// 参数说明：
/// - `state`：当前真实节点owner。
/// - `client`：同一已认证管理连接。
/// - `work`：通过独立签名及四主体当前授权的释放工作。
///
/// 返回：原关闭身份被共享端确认且权威仍有效时成功；失败不否认已同步的关闭事实。
async fn close(state: Arc<AdminState>, mut client: Client, work: release::Work) -> Result<()> {
    let work = work.close(state.clone()).await?;
    let release = work.closed()?;
    let checked = release.validate()?;
    work.authorize(&state)?;
    let response = client
        .material_release_result(timed_request(
            protocol::MaterialReleaseResultRequest {
                node_id: release.intent.node_id.clone(),
                boot_id: release.delivery.receiving_boot_id.clone(),
                session: release.delivery.session.to_vec(),
                release_id: checked.message.clone(),
                intent_sha256: release.position.fingerprint(&release.intent)?.to_vec(),
                execution_store: release.intent.execution_store.clone(),
                node_admission_epoch: release.intent.baseline.node_admission_epoch.clone(),
                definition_digest: release.definition_digest.clone(),
                terminal: super::report_fields::terminal(release.terminal),
                closed: true,
            },
            tokio::time::Instant::now() + RPC_TIMEOUT,
        )?)
        .await?
        .into_inner();
    ensure!(
        response.accepted_release_id == checked.message,
        "material release acknowledgement differs"
    );
    work.authorize(&state)
}
