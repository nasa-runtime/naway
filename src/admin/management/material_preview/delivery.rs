//! 材料候选预检投递槽只服务一次有限请求，取消后精确回收，不产生重试或执行收据。

use super::{body::CHUNK, command::Command, wire, Content, Reason};
use crate::admin::management::{actions::window::Window, protocol, Manager};
use crate::config::GatewaySnapshot;
use nasa::grpc::Status;
use std::sync::{Arc, Weak};
use tokio::sync::{oneshot, OwnedSemaphorePermit};

pub(in crate::admin::management) struct Offer {
    pub(in crate::admin::management) command: Command,
    snapshot: Arc<GatewaySnapshot>,
    content: Arc<Content>,
    offset: parking_lot::Mutex<usize>,
    message: String,
    signature: String,
    window: Window,
    reply: parking_lot::Mutex<
        Option<oneshot::Sender<Result<crate::tls::keypair::preview::Proof, Reason>>>,
    >,
}

pub(in crate::admin) struct Ticket {
    manager: Weak<Manager>,
    offer: Arc<Offer>,
    reply: oneshot::Receiver<Result<crate::tls::keypair::preview::Proof, Reason>>,
}

impl Manager {
    /// 业务作用：在接收确认正文前限制整份查询数量，慢客户端不能耗尽集群材料观察容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多两个整请求名额之一；没有名额立即拒绝，不排队或读取正文。
    pub(in crate::admin) fn admit_material_preview(&self) -> Result<OwnedSemaphorePermit, Reason> {
        self.material_preview_requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Reason::Capacity)
    }

    /// 业务作用：为原节点批次安装独占短期槽，全部逻辑目标共享当前发行快照及原会话。
    ///
    /// 参数说明：
    /// - `snapshot`：开始材料候选预检时冻结且仍有效的管理权限快照。
    /// - `command`：全部字段来自已获权原提案的有限声明。
    /// - `content`：唯一认证材料及真实受理名额的共享持有者。
    ///
    /// 返回：唯一等待与清理权；旧基线、身份不符、同节点忙碌或总量超限均拒绝。
    pub(in crate::admin) fn offer_material_preview(
        self: &Arc<Self>,
        snapshot: Arc<GatewaySnapshot>,
        command: Command,
        content: Arc<Content>,
    ) -> Result<Ticket, Reason> {
        let _gate = self.publication.read();
        let plan = self
            .action_plan(&snapshot, &command.intent.baseline.cluster_id)
            .map_err(|_| Reason::Denied)?;
        // 本机目标必须经过原生工作许可和同一材料锁，不为自身建立可旁路这些门禁的远端槽。
        if command.intent.node == plan.node_id {
            return Err(Reason::Denied);
        }
        let session = self
            .store
            .lock()
            .material_preview_session(&plan, &command.intent)?;
        // 查询会话与安装槽之间可能发生节点重连，不能把旧命令交给新会话。
        if session != command.session {
            return Err(Reason::Denied);
        }
        let message = command.message().map_err(|_| Reason::Denied)?;
        let window = Window::preview(command.issued_at_ms, command.expires_at_ms)
            .map_err(|_| Reason::Expired)?;
        let signature = plan
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.issuer.as_ref())
            .ok_or(Reason::Unavailable)?
            .sign_material_preview(&plan.node_id, &command)
            .map_err(|_| Reason::Denied)?;
        if content.material.0.len() != command.intent.candidate_bytes as usize
            || content.digest != command.intent.candidate_sha256
        {
            return Err(Reason::CandidateInvalid);
        }
        let (sender, reply) = oneshot::channel();
        let offer = Arc::new(Offer {
            command,
            snapshot,
            content,
            offset: parking_lot::Mutex::new(0),
            message,
            signature,
            window,
            reply: parking_lot::Mutex::new(Some(sender)),
        });
        let mut slots = self.material_preview_deliveries.lock();
        // 每节点至多一个请求等待；全局上限还覆盖已被新配置移除但尚未退出的旧目标。
        if slots.len() >= 128 || slots.contains_key(&offer.command.intent.node) {
            return Err(Reason::Capacity);
        }
        slots.insert(offer.command.intent.node.clone(), offer.clone());
        Ok(Ticket {
            manager: Arc::downgrade(self),
            offer,
            reply,
        })
    }
}

impl Offer {
    /// 业务作用：每次读取 offer 和接收结果都验证原发行实例与短期会话，不延长已撤销的等待。
    ///
    /// 参数说明：
    /// - `manager`：当前管理生命周期 owner。
    /// - `node`：已由 mTLS 证书绑定的实际节点。
    /// - `boot`：本次请求携带且须匹配原目标的启动身份。
    /// - `session`：原接收会话。
    /// - `message`：结果指向的材料候选预检摘要，心跳获取 offer 时为空。
    ///
    /// 返回：仍属于原请求时成功；过期、换代或错投递拒绝，不更新心跳或材料候选预检期限。
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
            .map_err(|_| Status::deadline_exceeded("material preview expired"))?;
        // 暂停服务、换代或错投递都会撤销秘密读取资格，已签发命令不能延长原 owner 的寿命。
        if manager.stopping.is_cancelled()
            || !Arc::ptr_eq(&manager.snapshots.load_full(), &self.snapshot)
            || node != self.command.intent.node
            || boot != self.command.intent.boot
            || !crate::security::auth::constant_time_eq(session, &self.command.session)
            || message.is_some_and(|value| value != self.message)
        {
            return Err(Status::failed_precondition(
                "material preview authority changed",
            ));
        }
        Ok(())
    }

    /// 业务作用：在实际网络边界生成有限签名声明，原生槽不保存第二份 protobuf 对象。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一命令的协议元数据，不产生材料观察成功或执行确认。
    pub(in crate::admin::management) fn wire(
        &self,
    ) -> Result<protocol::MaterialPreviewOffer, Status> {
        wire::encode(&self.command, &self.signature)
    }

    /// 业务作用：按原节点确认的连续偏移交付有限候选分片，重复、跳跃或结果已完成都不再释放秘密。
    ///
    /// 参数说明：
    /// - `offset`：原节点已验证的连续字节数。
    ///
    /// 返回：最多16KiB的二进制片段；无法证明连续进度时拒绝，传输失败不隐式重放。
    pub(in crate::admin::management) fn data(
        &self,
        offset: u32,
    ) -> Result<protocol::MaterialPreviewDataResponse, Status> {
        let mut next = self.offset.lock();
        let start = offset as usize;
        let bytes = &self.content.material.0;
        if start != *next || start >= bytes.len() || self.reply.lock().is_none() {
            return Err(Status::out_of_range("material preview offset differs"));
        }
        let end = (start + CHUNK).min(bytes.len());
        *next = end;
        Ok(protocol::MaterialPreviewDataResponse {
            offer_id: self.message.clone(),
            offset,
            body: bytes[start..end].to_vec(),
            eof: end == bytes.len(),
        })
    }

    /// 业务作用：把完整类型化结果只交给原等待者，缺失字段和非法状态不能变成零条件成功。
    ///
    /// 参数说明：
    /// - `request`：已经通过节点、原会话和投递摘要授权的完整结果。
    ///
    /// 返回：原等待者接收成功才确认；重复、取消、未知状态或摘要合同不符均拒绝。
    pub(in crate::admin::management) fn receive(
        &self,
        request: protocol::MaterialPreviewResultRequest,
    ) -> Result<(), Status> {
        let result = if request.status == protocol::MaterialPreviewStatus::Succeeded as i32 {
            let batch = super::super::material::wire::decode_batch(
                request
                    .batch
                    .ok_or_else(|| Status::invalid_argument("material preview summary absent"))?,
                &self.command.intent.original,
            )
            .map_err(|_| Status::invalid_argument("material preview result invalid"))?;
            let proof = wire::proof(batch, &self.command.intent, &request.impact_sha256)
                .map_err(|_| Status::invalid_argument("material preview proof invalid"))?;
            // 节点证明不能替发行端授予额外对象权限，完整共享影响仍须满足本次冻结范围。
            crate::control::material::authorization::logical_targets(
                &self.command.intent.scope,
                &self.snapshot,
                &self.command.intent.node,
                proof
                    .conditions
                    .groups
                    .iter()
                    .flat_map(|group| group.affected.iter().map(|affected| &affected.target)),
            )
            .ok_or_else(|| Status::permission_denied("material preview impact denied"))?;
            Ok(proof)
        } else {
            if request.batch.is_some() || !request.impact_sha256.is_empty() {
                return Err(Status::invalid_argument(
                    "failed material preview includes proof",
                ));
            }
            Err(wire::reason(request.status)
                .ok_or_else(|| Status::invalid_argument("material preview status unknown"))?)
        };
        let sender = self
            .reply
            .lock()
            .take()
            .ok_or_else(|| Status::already_exists("material preview already returned"))?;
        sender
            .send(result)
            .map_err(|_| Status::cancelled("material preview owner stopped"))
    }
}

impl Ticket {
    /// 业务作用：在采纳节点结果之前复验同一发行快照、原会话和完整原目标基线。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前原目标事实仍成立才成功；缺席或换代拒绝交付已有条件。
    pub(in crate::admin) fn authorize(&self) -> Result<(), Reason> {
        let manager = self.manager.upgrade().ok_or(Reason::Unavailable)?;
        let _gate = manager.publication.read();
        let plan = manager
            .action_plan(
                &self.offer.snapshot,
                &self.offer.command.intent.baseline.cluster_id,
            )
            .map_err(|_| Reason::Denied)?;
        let session = manager
            .store
            .lock()
            .material_preview_session(&plan, &self.offer.command.intent)?;
        self.offer
            .authorize(
                &manager,
                &self.offer.command.intent.node,
                &self.offer.command.intent.boot,
                &session,
                Some(&self.offer.message),
            )
            .map_err(|_| Reason::Expired)
    }

    /// 业务作用：等待原节点的一次完整候选策略结果，网络返回不形成持久执行收据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍有当前授权的原目标结果；等待取消或原节点失去资格时保持明确失败。
    pub(in crate::admin) async fn receive(
        &mut self,
    ) -> Result<crate::tls::keypair::preview::Proof, Reason> {
        loop {
            // 新报告已经撤下原基线时立即结束等待；不能把已知换代留到网络期限后误报为超时。
            self.authorize()?;
            tokio::select! {
                result = &mut self.reply => {
                    self.authorize()?;
                    return result.map_err(|_| Reason::Unavailable)?;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
            }
        }
    }
}

impl Drop for Ticket {
    /// 业务作用：请求结束或取消时只删除自己安装的精确槽，不能清理后来同节点的另一份材料候选预检。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：回收本投递的批次引用和等待者，不删除任何持久记录或节点文件。
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            let mut slots = manager.material_preview_deliveries.lock();
            if slots
                .get(&self.offer.command.intent.node)
                .is_some_and(|current| Arc::ptr_eq(current, &self.offer))
            {
                slots.remove(&self.offer.command.intent.node);
            }
        }
    }
}
