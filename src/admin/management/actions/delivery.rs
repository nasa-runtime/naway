//! 内存投递槽只桥接当前会话；唯一重投事实与效果确认仍由共享事务负责。

mod release;

use super::{body::CHUNK, result, window::Window, wire};
use crate::{
    admin::management::{protocol, Manager},
    config::GatewaySnapshot,
    control::actions::{command::Command, definition},
};
use bytes::Bytes;
use nasa::grpc::Status;
use nasaga_runtime_core::SagaResultEnvelope;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use tokio::sync::oneshot;

pub(in crate::admin::management) struct Offer {
    accepts_body: bool,
    message: String,
    wire: Message,
    body: Bytes,
    snapshot: Arc<GatewaySnapshot>,
    window: Window,
    reply: parking_lot::Mutex<Option<oneshot::Sender<Received>>>,
}

enum Message {
    Action(protocol::ActionOffer),
    Release(protocol::ReleaseOffer),
}

/// 发行任务持有唯一清理权；取消只能移除它自己安装的精确槽。
pub(in crate::admin) struct Ticket {
    manager: Weak<Manager>,
    offer: Arc<Offer>,
    reply: oneshot::Receiver<Received>,
}

/// 回报仍未确认；只有共享事务提交后的调用者才能完成确认通道。
pub(in crate::admin) struct Received {
    pub(in crate::admin) result: Option<SagaResultEnvelope>,
    pub(in crate::admin) closed: bool,
    confirmation: oneshot::Sender<()>,
}

impl Manager {
    /// 业务作用：把已由共享事务授予租约的命令放入单目标有界槽，发送行为不提前确认 Outbox。
    ///
    /// 参数说明：
    /// - `snapshot`：租约与当前权限复验时使用的精确活动实例。
    /// - `command`：已确认数据库提交、有限期限及 fence 的完整命令。
    /// - `body`：该提案共享的原始候选，不按目标重新编码 YAML。
    ///
    /// 返回：本投递的唯一结果等待和清理权；同节点忙碌、会话失效或权限换代拒绝安装。
    pub(in crate::admin) fn offer_action(
        self: &Arc<Self>,
        snapshot: Arc<GatewaySnapshot>,
        command: Command,
        body: Bytes,
    ) -> Result<Ticket, Status> {
        let _gate = self.publication.read();
        let plan = self.action_plan(&snapshot, &command.intent.baseline.cluster_id)?;
        if command.intent.node_id == plan.node_id
            || !plan
                .receiver
                .as_ref()
                .expect("validated receiver")
                .nodes
                .contains_key(&command.intent.node_id)
        {
            return Err(Status::failed_precondition(
                "remote node membership unavailable",
            ));
        }
        let signer = plan
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.issuer.as_ref())
            .ok_or_else(|| Status::failed_precondition("node issuer unavailable"))?;
        let definition = definition::cached(command.intent.target_count as usize)
            .map_err(|_| Status::failed_precondition("node definition unavailable"))?;
        let checked = command
            .validate(&definition)
            .map_err(|_| Status::invalid_argument("invalid node command"))?;
        if body.len() != command.intent.candidate_bytes as usize
            || Sha256::digest(&body)[..] != command.intent.candidate_sha256
        {
            return Err(Status::data_loss("node candidate identity differs"));
        }
        let window = Window::admit(&command.delivery)
            .map_err(|_| Status::deadline_exceeded("node delivery window unavailable"))?;
        self.store.lock().action_authority(
            &plan,
            &command.intent.node_id,
            &command.delivery.receiving_boot_id,
            &command.delivery.session,
        )?;
        let signature = signer.sign_command(&plan.node_id, &command, &definition)?;
        let accepts_body = checked.step() == crate::control::actions::command::Step::Prepare
            && checked.identity().phase == nasa::saga::StepPhase::Execute;
        let wire = wire::encode(command, signature, &definition)?;
        self.install_offer(Offer {
            message: checked.message().to_owned(),
            accepts_body,
            wire: Message::Action(wire),
            body,
            snapshot,
            window,
            reply: parking_lot::Mutex::new(None),
        })
    }

    /// 业务作用：让业务和释放共同占用单目标槽，取消时只交给同一个 Ticket 回收精确内存身份。
    ///
    /// 参数说明：
    /// - offer：调用方在发布读锁内完成全部当前权威门的消息。
    ///
    /// 返回：唯一等待和清理权；同节点已有投递或达到全局容量时拒绝，没有共享库副作用。
    fn install_offer(self: &Arc<Self>, offer: Offer) -> Result<Ticket, Status> {
        let (sender, reply) = oneshot::channel();
        *offer.reply.lock() = Some(sender);
        let offer = Arc::new(offer);
        let mut slots = self.action_deliveries.lock();
        // 同一目标不得在未知结果期间换槽；全局固定上限也覆盖配置移除后尚未退出的任务。
        if slots.len() >= 128 || slots.contains_key(offer.node()) {
            return Err(Status::resource_exhausted(
                "node delivery capacity unavailable",
            ));
        }
        slots.insert(offer.node().to_owned(), offer.clone());
        Ok(Ticket {
            manager: Arc::downgrade(self),
            offer,
            reply,
        })
    }
}

impl Offer {
    /// 业务作用：从已经完整验证的唯一消息借用目标身份，不再保留第二套 native 命令字段。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：安装时验证的永久节点标识，供精确槽归属与清理比较。
    fn node(&self) -> &str {
        &self.intent().node_id
    }

    /// 业务作用：从独占槽的具体消息借用同一原意图，禁止跨用途拼接节点身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：安装时验证的原意图字段，不复制元数据。
    fn intent(&self) -> &protocol::ActionIntent {
        match &self.wire {
            Message::Action(wire) => wire.intent.as_ref(),
            Message::Release(wire) => wire.intent.as_ref(),
        }
        .expect("validated intent")
    }

    /// 业务作用：让两种消息使用同一会话复验逻辑，释放不另建更长的租约窗口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同次签名绑定的投递字段。
    fn delivery(&self) -> &protocol::ActionDelivery {
        match &self.wire {
            Message::Action(wire) => wire.delivery.as_ref(),
            Message::Release(wire) => wire.delivery.as_ref(),
        }
        .expect("validated delivery")
    }

    /// 业务作用：每次正文、offer 或结果访问都重新核对发行权和会话，不用内存槽延长过期租约。
    ///
    /// 参数说明：
    /// - `manager`：提供当前发行快照与停止权的实例。
    /// - `node`：已经通过 mTLS 绑定的实际节点。
    /// - `boot`：本次连接声明并由接收槽验证的启动身份。
    /// - `session`：当前接收端会话。
    /// - `message`：正文或结果所指的完整投递摘要；心跳取得 offer 时为空。
    ///
    /// 返回：仍属于当前实例、节点和有限期限时成功；失权或错投递拒绝。
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
            .map_err(|_| Status::deadline_exceeded("node delivery expired"))?;
        if manager.stopping.is_cancelled()
            || !Arc::ptr_eq(&manager.snapshots.load_full(), &self.snapshot)
            || node != self.node()
            || boot != self.delivery().receiving_boot_id
            || !crate::security::auth::constant_time_eq(session, &self.delivery().session)
            || message.is_some_and(|message| message != self.message)
        {
            return Err(Status::failed_precondition(
                "node delivery authority changed",
            ));
        }
        Ok(())
    }

    /// 业务作用：向已通过当前会话门的心跳提供有限元数据，候选原文保持单独共享。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前签名消息的必要 protobuf 字段副本，不确认任何业务效果。
    pub(in crate::admin::management) fn wire(
        &self,
    ) -> (
        Option<protocol::ActionOffer>,
        Option<protocol::ReleaseOffer>,
    ) {
        match &self.wire {
            Message::Action(wire) => (Some(wire.clone()), None),
            Message::Release(wire) => (None, Some(wire.clone())),
        }
    }

    /// 业务作用：按客户端精确偏移交付有限原文分片，不允许非准备命令借此读取候选秘密。
    ///
    /// 参数说明：
    /// - `offset`：调用者已经确认的原文长度。
    ///
    /// 返回：最多十六 KiB 原文和准确 EOF；越界、错阶段或错步骤拒绝。
    pub(in crate::admin::management) fn data(
        &self,
        offset: u32,
    ) -> Result<protocol::ActionDataResponse, Status> {
        let start = offset as usize;
        if !self.accepts_body || start >= self.body.len() {
            return Err(Status::out_of_range(
                "node candidate offset or purpose differs",
            ));
        }
        let end = (start + CHUNK).min(self.body.len());
        Ok(protocol::ActionDataResponse {
            offer_id: self.message.clone(),
            offset,
            body: self.body[start..end].to_vec(),
            eof: end == self.body.len(),
        })
    }

    /// 业务作用：把唯一当前回报交给发行任务，ACK 必须等待共享结果事务完成。
    ///
    /// 参数说明：
    /// - `request`：已经经过当前 mTLS、会话、权限和投递摘要门的结果。
    ///
    /// 返回：只在调用者确认事务提交后完成的等待权；重复回报、过期等待或非法组合拒绝。
    pub(in crate::admin::management) fn receive(
        &self,
        request: &protocol::ActionResultRequest,
    ) -> Result<oneshot::Receiver<()>, Status> {
        let Message::Action(wire) = &self.wire else {
            return Err(Status::invalid_argument(
                "node delivery is not a business command",
            ));
        };
        let (command, _) = wire::decode(wire.clone())?;
        let result = result::decode(&command, request)?;
        let (confirmation, receiver) = oneshot::channel();
        let sender =
            self.reply.lock().take().ok_or_else(|| {
                Status::already_exists("node result already awaiting confirmation")
            })?;
        sender
            .send(Received {
                result,
                closed: false,
                confirmation,
            })
            .map_err(|_| Status::unavailable("node delivery owner stopped"))?;
        Ok(receiver)
    }
}

impl Ticket {
    /// 业务作用：共享确认事务前复验原投递窗口及实际接收会话，不让网络返回延长旧租约权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原节点仍具当前发行计划、会话和有限窗口时成功；停止、换代或失联拒绝确认。
    pub(in crate::admin) fn authorize(&self) -> Result<(), Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("node delivery owner stopped"))?;
        let _gate = manager.publication.read();
        let baseline = self
            .offer
            .intent()
            .baseline
            .as_ref()
            .expect("validated baseline");
        let plan = manager.action_plan(&self.offer.snapshot, &baseline.cluster_id)?;
        let delivery = self.offer.delivery();
        manager.store.lock().action_authority(
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

    /// 业务作用：等待当前目标回报，不把网络接收解释为 NASA Inbox 已提交。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：可进入共享事务的有限结果；投递撤销或对端缺席保持失败和可重投状态。
    pub(in crate::admin) async fn receive(&mut self) -> Result<Received, Status> {
        (&mut self.reply)
            .await
            .map_err(|_| Status::unavailable("node result unavailable"))
    }
}

impl Drop for Ticket {
    /// 业务作用：发行任务退出时只移除自己安装的原槽，不能清理其它 owner 后来持有的投递。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：精确槽被清理；共享租约和节点持久状态均不在此删除。
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            let mut slots = manager.action_deliveries.lock();
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
    /// 业务作用：在共享结果事务确认后允许接收 RPC 返回 ACK，取消等待不能倒推事务回滚。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只通知仍在等待的原 RPC；通知丢失仍可通过 NASA Inbox 和节点收据重投确认。
    pub(in crate::admin) fn confirm(self) {
        let _ = self.confirmation.send(());
    }
}
