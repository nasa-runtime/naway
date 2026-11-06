//! 原生命令保留在有限投递槽，只有网络边界编码；完整节点事实等待共享事务确认后才ACK。

mod terminal;

use super::{body::CHUNK, report, wire, Content};
use crate::{
    admin::management::{actions::window::Window, protocol, Manager, MAX_MESSAGE},
    config::GatewaySnapshot,
    control::{
        actions::command::Delivery,
        material::{
            execution::{
                command::{Command, Step},
                release::Release,
                report::Observation,
            },
            node::Intent,
        },
    },
};
use nasa::{
    grpc::{codegen::prost::Message as _, Status},
    saga::StepPhase,
};
use nasaga_runtime_core::SagaResultEnvelope;
use std::sync::{Arc, Weak};
use tokio::sync::oneshot;

enum Message {
    Action(Box<Command>),
    Release(Release),
}

pub(in crate::admin::management) struct Offer {
    content: Option<Arc<Content>>,
    command: Message,
    signature: String,
    message: String,
    snapshot: Arc<GatewaySnapshot>,
    window: Window,
    reply: parking_lot::Mutex<Option<oneshot::Sender<Received>>>,
}

pub(in crate::admin) struct Ticket {
    manager: Weak<Manager>,
    offer: Arc<Offer>,
    reply: oneshot::Receiver<Received>,
}

/// 完整公开事实与当前命令投影一起交给共享事务，confirmation不能早于明确提交。
pub(in crate::admin) struct Received {
    pub observation: Option<Observation>,
    pub result: Option<SagaResultEnvelope>,
    pub closed: bool,
    confirmation: oneshot::Sender<()>,
}

impl Manager {
    /// 业务作用：将共享租约已经提交的材料命令安装到有限目标槽，秘密正文只共享唯一清零帧。
    ///
    /// 参数说明：
    /// - `snapshot`：当前发行授权采用的精确实例。
    /// - `command`：完整原批准、物理分母与当前租约投递。
    /// - `content`：仅首次准备需要的原候选共享帧，其余请求必须为空。
    ///
    /// 返回：原投递的唯一等待权；会话、身份、容量或正文不一致拒绝，无共享库副作用。
    pub(in crate::admin) fn offer_material_action(
        self: &Arc<Self>,
        snapshot: Arc<GatewaySnapshot>,
        command: Command,
        content: Option<Arc<Content>>,
    ) -> Result<Ticket, Status> {
        let _gate = self.publication.read();
        let plan = self.action_plan(&snapshot, &command.intent.baseline.cluster_id)?;
        let receiver = plan.receiver.as_ref().expect("validated receiver");
        if command.intent.node_id == plan.node_id
            || !receiver.nodes.contains_key(&command.intent.node_id)
        {
            return Err(Status::failed_precondition(
                "remote material membership unavailable",
            ));
        }
        let checked = command
            .validate()
            .map_err(|_| Status::invalid_argument("material command differs"))?;
        let needs_content =
            checked.step() == Step::Prepare && checked.identity().phase == StepPhase::Execute;
        if needs_content != content.is_some()
            || content.as_ref().is_some_and(|content| {
                content.material.0.len() != command.intent.candidate_bytes as usize
                    || content.digest != command.intent.candidate_sha256
            })
        {
            return Err(Status::data_loss("material candidate identity differs"));
        }
        let window = Window::admit(&command.delivery)
            .map_err(|_| Status::deadline_exceeded("material delivery window unavailable"))?;
        self.store.lock().material_action_authority(
            &plan,
            &command.intent.node_id,
            &command.delivery.receiving_boot_id,
            &command.delivery.session,
        )?;
        let signature = receiver
            .issuer
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("material issuer absent"))?
            .sign_material_command(&plan.node_id, &command)?;
        // 只有完整消息可表达才安装槽；实际编码只存在于边界，不在槽中保留第二份审批树。
        wire::encode(&command, &signature)?;
        self.install_material_offer(Offer {
            content,
            command: Message::Action(Box::new(command)),
            signature,
            message: checked.message().into(),
            snapshot,
            window,
            reply: parking_lot::Mutex::new(None),
        })
    }

    /// 业务作用：配置与材料投递共享目标容量，未知结果期间不能安装第二个同节点命令。
    ///
    /// 参数说明：
    /// - `offer`：当前发布读锁内已经完整验证的原生投递。
    ///
    /// 返回：唯一目标槽与等待者；同节点忙碌或全局达到128项拒绝，不排队。
    fn install_material_offer(self: &Arc<Self>, offer: Offer) -> Result<Ticket, Status> {
        let (sender, reply) = oneshot::channel();
        *offer.reply.lock() = Some(sender);
        let offer = Arc::new(offer);
        // 两类安装始终先取配置槽锁，再取材料槽锁，互斥检查与插入必须原子完成。
        let actions = self.action_deliveries.lock();
        let mut slots = self.material_action_deliveries.lock();
        if actions.len() + slots.len() >= 128
            || actions.contains_key(offer.node())
            || slots.contains_key(offer.node())
        {
            return Err(Status::resource_exhausted(
                "material delivery capacity unavailable",
            ));
        }
        slots.insert(offer.node().into(), offer.clone());
        Ok(Ticket {
            manager: Arc::downgrade(self),
            offer,
            reply,
        })
    }
}

impl Offer {
    /// 业务作用：从原生投递借用唯一节点标识，避免另存可漂移的目标字段。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原完整意图的物理节点身份。
    fn node(&self) -> &str {
        &self.intent().node_id
    }

    /// 业务作用：业务与释放共用完整原审批意图，网络边界不重建目标树。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原不可变节点意图的借用。
    fn intent(&self) -> &Intent {
        match &self.command {
            Message::Action(command) => &command.intent,
            Message::Release(release) => &release.intent,
        }
    }

    /// 业务作用：所有投递访问共用签名绑定的实际会话和有限租约窗口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原投递字段的借用，不延长期限或更换接收boot。
    fn delivery(&self) -> &Delivery {
        match &self.command {
            Message::Action(command) => &command.delivery,
            Message::Release(release) => &release.delivery,
        }
    }

    /// 业务作用：每次正文与结果访问都复验原实例、会话和单调期限，旧槽不能延长材料授权。
    ///
    /// 参数说明：
    /// - `manager`：当前发行实例。
    /// - `node`：mTLS已绑定的节点。
    /// - `boot`：当前实际启动身份。
    /// - `session`：当前认证会话。
    /// - `message`：正文或结果指定的原投递摘要，心跳读取时为空。
    ///
    /// 返回：仍属精确原投递才成功；失权或错身份拒绝，不刷新心跳。
    pub(in crate::admin::management) fn authorize(
        &self,
        manager: &Manager,
        node: &str,
        boot: &str,
        session: &[u8],
        message: Option<&str>,
    ) -> Result<(), Status> {
        self.window
            .check()
            .map_err(|_| Status::deadline_exceeded("material delivery expired"))?;
        if manager.stopping.is_cancelled()
            || !Arc::ptr_eq(&manager.snapshots.load_full(), &self.snapshot)
            || node != self.node()
            || boot != self.delivery().receiving_boot_id
            || !crate::security::auth::constant_time_eq(session, &self.delivery().session)
            || message.is_some_and(|message| message != self.message)
        {
            return Err(Status::failed_precondition(
                "material delivery authority changed",
            ));
        }
        Ok(())
    }

    /// 业务作用：仅在实际心跳边界编码完整命令，独立释放与业务消息不能同时交付。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：单个完整有界消息；超量不截断原批准。
    pub(in crate::admin::management) fn wire(
        &self,
    ) -> Result<
        (
            Option<protocol::MaterialActionOffer>,
            Option<protocol::MaterialReleaseOffer>,
        ),
        Status,
    > {
        match &self.command {
            Message::Action(command) => Ok((Some(wire::encode(command, &self.signature)?), None)),
            Message::Release(release) => {
                Ok((None, Some(wire::encode_release(release, &self.signature)?)))
            }
        }
    }

    /// 业务作用：只为实际准备命令提供有界原候选分片，其余阶段没有秘密下载权。
    ///
    /// 参数说明：
    /// - `offset`：本次请求的精确原帧偏移。
    ///
    /// 返回：最多16KiB片段及准确EOF；缺正文或越界拒绝。
    pub(in crate::admin::management) fn data(
        &self,
        offset: u32,
    ) -> Result<protocol::MaterialActionDataResponse, Status> {
        let content = self
            .content
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("material body not offered"))?;
        let start = offset as usize;
        if start >= content.material.0.len() {
            return Err(Status::out_of_range("material body offset differs"));
        }
        let end = (start + CHUNK).min(content.material.0.len());
        Ok(protocol::MaterialActionDataResponse {
            offer_id: self.message.clone(),
            offset,
            body: content.material.0[start..end].to_vec(),
            eof: end == content.material.0.len(),
        })
    }

    /// 业务作用：完整验证节点原事实后交给共享事务，空槽或关闭不能投影成稳定业务结果。
    ///
    /// 参数说明：
    /// - `request`：当前mTLS会话中精确投递的原结果，完整报告直接移动所有权。
    ///
    /// 返回：等待持久事务确认的通道；畸形、超量或重复在途结果拒绝。
    pub(in crate::admin::management) fn receive(
        &self,
        request: &mut protocol::MaterialActionResultRequest,
    ) -> Result<oneshot::Receiver<()>, Status> {
        if request.encoded_len() > MAX_MESSAGE {
            return Err(Status::resource_exhausted(
                "material result exceeds capacity",
            ));
        }
        let Message::Action(command) = &self.command else {
            return Err(Status::invalid_argument("material business offer absent"));
        };
        use protocol::material_action_result_request::Observation as Wire;
        let observation = match request.observation.take() {
            Some(Wire::Report(value)) => Observation::Report(Box::new(report::decode(
                value,
                &command.intent,
                command.position,
            )?)),
            Some(Wire::Missing(value)) => match protocol::MaterialExecutionMissing::try_from(value)
            {
                Ok(protocol::MaterialExecutionMissing::Vacant) => Observation::Vacant,
                Ok(protocol::MaterialExecutionMissing::Closed) => Observation::Closed,
                _ => return Err(Status::invalid_argument("material missing state differs")),
            },
            None => return Err(Status::invalid_argument("material observation absent")),
        };
        let result = observation
            .result_for(command)
            .map_err(|_| Status::invalid_argument("material original effect differs"))?;
        self.submit(Some(observation), result, false)
    }

    /// 业务作用：将唯一原结果交给等待者，RPC确认只由明确的共享提交解锁。
    ///
    /// 参数说明：
    /// - `observation`：业务原公开事实，释放请求为空。
    /// - `result`：从同一完整原收据投影的当前NASA结果。
    /// - `closed`：已精确核对的独立释放确认。
    ///
    /// 返回：原RPC确认等待；owner已退出或已有在途回报时拒绝。
    fn submit(
        &self,
        observation: Option<Observation>,
        result: Option<SagaResultEnvelope>,
        closed: bool,
    ) -> Result<oneshot::Receiver<()>, Status> {
        let (confirmation, receiver) = oneshot::channel();
        self.reply
            .lock()
            .take()
            .ok_or_else(|| Status::already_exists("material result awaiting confirmation"))?
            .send(Received {
                observation,
                result,
                closed,
                confirmation,
            })
            .map_err(|_| Status::unavailable("material delivery owner stopped"))?;
        Ok(receiver)
    }
}

impl Ticket {
    /// 业务作用：共享结果事务内复验实际原会话和租约窗口，网络返回不延长旧发行权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原完整快照、会话与有限期限仍有效才成功。
    pub(in crate::admin) fn authorize(&self) -> Result<(), Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("material issuer stopped"))?;
        let _gate = manager.publication.read();
        let plan = manager.action_plan(
            &self.offer.snapshot,
            &self.offer.intent().baseline.cluster_id,
        )?;
        let delivery = self.offer.delivery();
        manager.store.lock().material_action_authority(
            &plan,
            self.offer.node(),
            &delivery.receiving_boot_id,
            &delivery.session,
        )?;
        self.offer.authorize(
            &manager,
            self.offer.node(),
            &delivery.receiving_boot_id,
            &delivery.session,
            Some(&self.offer.message),
        )
    }

    /// 业务作用：等待原节点完整回报，接收完成不意味着共享结果已经持久确认。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原完整事实与确认权；取消或owner退出保留未确认状态。
    pub(in crate::admin) async fn receive(&mut self) -> Result<Received, Status> {
        (&mut self.reply)
            .await
            .map_err(|_| Status::unavailable("material result unavailable"))
    }
}

impl Drop for Ticket {
    /// 业务作用：等待者退出只移除自身精确内存槽，不能影响后来同节点的新投递或持久责任。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：匹配Arc身份的槽被回收，原秘密最后持有者清零后释放容量。
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            let mut slots = manager.material_action_deliveries.lock();
            if slots
                .get(self.offer.node())
                .is_some_and(|current| Arc::ptr_eq(current, &self.offer))
            {
                slots.remove(self.offer.node());
            }
        }
    }
}

impl Received {
    /// 业务作用：仅在共享事务明确提交之后解锁原RPC，确认丢失仍允许原事实重投。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：通知仍等待的原RPC，不修改NASA或节点文件状态。
    pub(in crate::admin) fn confirm(self) {
        let _ = self.confirmation.send(());
    }
}
