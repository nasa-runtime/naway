//! 预览投递槽只服务一次有限请求，取消后精确回收，不产生重试或执行收据。

use super::{body::CHUNK, command::Command, wire, Reason};
use crate::admin::{
    diff::model::Summary,
    management::{actions::window::Window, protocol, Manager},
};
use crate::config::GatewaySnapshot;
use bytes::Bytes;
use nasa::grpc::Status;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use tokio::sync::{oneshot, OwnedSemaphorePermit};

pub(in crate::admin::management) struct Offer {
    pub(in crate::admin::management) command: Command,
    snapshot: Arc<GatewaySnapshot>,
    message: String,
    signature: String,
    body: Bytes,
    window: Window,
    reply: parking_lot::Mutex<Option<oneshot::Sender<Result<Summary, Reason>>>>,
}

pub(in crate::admin) struct Ticket {
    manager: Weak<Manager>,
    offer: Arc<Offer>,
    reply: oneshot::Receiver<Result<Summary, Reason>>,
}

impl Manager {
    /// 业务作用：在读取共享候选之前限制整份预览的数量，慢预览不能耗尽全部提案入口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多两个整请求名额之一；没有名额立即拒绝，不排队或读取正文。
    pub(in crate::admin) fn admit_preview(&self) -> Result<OwnedSemaphorePermit, Reason> {
        self.preview_requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Reason::Capacity)
    }

    /// 业务作用：为原目标安装独占的短期预览槽，签名和正文只属于当前发行快照及原会话。
    ///
    /// 参数说明：
    /// - `snapshot`：开始预览时冻结且仍有效的管理权限快照。
    /// - `command`：全部字段来自已获权原提案的只读声明。
    /// - `body`：共享的一份原始候选，不能按目标替换或重编码。
    ///
    /// 返回：唯一等待与清理权；旧基线、身份不符、同节点忙碌或总量超限均拒绝。
    pub(in crate::admin) fn offer_preview(
        self: &Arc<Self>,
        snapshot: Arc<GatewaySnapshot>,
        command: Command,
        body: Bytes,
    ) -> Result<Ticket, Reason> {
        let _gate = self.publication.read();
        let plan = self
            .action_plan(&snapshot, &command.intent.baseline.cluster_id)
            .map_err(|_| Reason::Denied)?;
        if command.intent.node == plan.node_id {
            return Err(Reason::Denied);
        }
        let session = self.store.lock().preview_session(&plan, &command.intent)?;
        if session != command.session
            || body.len() != command.intent.candidate_bytes as usize
            || Sha256::digest(&body)[..] != command.intent.candidate_sha256
        {
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
            .sign_preview(&plan.node_id, &command)
            .map_err(|_| Reason::Denied)?;
        let (sender, reply) = oneshot::channel();
        let offer = Arc::new(Offer {
            command,
            snapshot,
            message,
            signature,
            body,
            window,
            reply: parking_lot::Mutex::new(Some(sender)),
        });
        let mut slots = self.preview_deliveries.lock();
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
    /// 业务作用：每次读取 offer、正文和结果都验证原发行实例与短期会话，不延长已撤销的等待。
    ///
    /// 参数说明：
    /// - `manager`：当前管理生命周期 owner。
    /// - `node`：已由 mTLS 证书绑定的实际节点。
    /// - `boot`：本次请求携带且须匹配原目标的启动身份。
    /// - `session`：原接收会话。
    /// - `message`：正文或结果指向的预览摘要，心跳获取 offer 时为空。
    ///
    /// 返回：仍属于原请求时成功；过期、换代或错投递拒绝，不更新心跳或预览期限。
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
            .map_err(|_| Status::deadline_exceeded("preview expired"))?;
        if manager.stopping.is_cancelled()
            || !Arc::ptr_eq(&manager.snapshots.load_full(), &self.snapshot)
            || node != self.command.intent.node
            || boot != self.command.intent.boot
            || !crate::security::auth::constant_time_eq(session, &self.command.session)
            || message.is_some_and(|value| value != self.message)
        {
            return Err(Status::failed_precondition("preview authority changed"));
        }
        Ok(())
    }

    /// 业务作用：在实际网络边界生成有限签名声明，原生槽不保存第二份 protobuf 或候选正文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一命令的协议元数据，不产生任何构建或执行确认。
    pub(in crate::admin::management) fn wire(&self) -> Result<protocol::PreviewOffer, Status> {
        wire::encode(&self.command, &self.signature)
    }

    /// 业务作用：只按精确偏移交付签名候选的有限分片，慢节点不能持数据库连接或文件锁。
    ///
    /// 参数说明：
    /// - `offset`：节点已经连续验证的正文长度。
    ///
    /// 返回：最多16KiB正文和精确EOF；越界偏移拒绝。
    pub(in crate::admin::management) fn data(
        &self,
        offset: u32,
    ) -> Result<protocol::PreviewDataResponse, Status> {
        let start = offset as usize;
        if start >= self.body.len() {
            return Err(Status::out_of_range("preview offset differs"));
        }
        let end = (start + CHUNK).min(self.body.len());
        Ok(protocol::PreviewDataResponse {
            offer_id: self.message.clone(),
            offset,
            body: self.body[start..end].to_vec(),
            eof: end == self.body.len(),
        })
    }

    /// 业务作用：把完整类型化结果只交给原等待者，缺失字段和非法状态不能变成零差异成功。
    ///
    /// 参数说明：
    /// - `request`：已经通过节点、原会话和投递摘要授权的完整结果。
    ///
    /// 返回：原等待者接收成功才确认；重复、取消、未知状态或摘要合同不符均拒绝。
    pub(in crate::admin::management) fn receive(
        &self,
        request: protocol::PreviewResultRequest,
    ) -> Result<(), Status> {
        let result = if request.status == protocol::PreviewStatus::Succeeded as i32 {
            Ok(wire::decode_summary(
                request
                    .summary
                    .ok_or_else(|| Status::invalid_argument("preview summary absent"))?,
                self.command.intent.version,
            )?)
        } else {
            if request.summary.is_some() {
                return Err(Status::invalid_argument("failed preview includes summary"));
            }
            Err(wire::reason(request.status)
                .ok_or_else(|| Status::invalid_argument("preview status unknown"))?)
        };
        let sender = self
            .reply
            .lock()
            .take()
            .ok_or_else(|| Status::already_exists("preview already returned"))?;
        sender
            .send(result)
            .map_err(|_| Status::cancelled("preview owner stopped"))
    }
}

impl Ticket {
    /// 业务作用：在采纳节点结果之前复验同一发行快照、原会话和完整原目标基线。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前原目标事实仍成立才成功；缺席或换代拒绝交付已有差异。
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
            .preview_session(&plan, &self.offer.command.intent)?;
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

    /// 业务作用：等待原节点的一次完整只读结果，网络返回不形成持久执行收据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍有当前授权的原目标结果；等待取消或原节点失去资格时保持明确失败。
    pub(in crate::admin) async fn receive(&mut self) -> Result<Summary, Reason> {
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
    /// 业务作用：请求结束或取消时只删除自己安装的精确槽，不能清理后来同节点的另一份预览。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：回收本投递的共享正文引用和等待者，不删除任何持久记录或节点文件。
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            let mut slots = manager.preview_deliveries.lock();
            if slots
                .get(&self.offer.command.intent.node)
                .is_some_and(|current| Arc::ptr_eq(current, &self.offer))
            {
                slots.remove(&self.offer.command.intent.node);
            }
        }
    }
}
