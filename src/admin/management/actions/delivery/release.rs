//! 释放共用原目标投递槽，节点关闭事实经过完整比较后才进入共享确认事务。

use super::{Message, Offer, Received, Ticket};
use crate::{
    admin::management::{
        actions::{release_wire, window::Window},
        protocol, Manager,
    },
    config::GatewaySnapshot,
    control::actions::{definition, release::Release},
};
use bytes::Bytes;
use nasa::grpc::Status;
use std::sync::Arc;
use tokio::sync::oneshot;

impl Manager {
    /// 业务作用：为原冻结目标交付独立签名释放，和业务命令互斥使用同一个有限投递槽。
    ///
    /// 参数说明：
    /// - snapshot：共享终态与当前权限复验使用的精确活动实例。
    /// - release：已经取得同意图新租约并确认提交的安全终态声明。
    ///
    /// 返回：唯一确认等待权；身份、当前会话、期限或容量不成立时拒绝，不携带候选正文。
    pub(in crate::admin) fn offer_release(
        self: &Arc<Self>,
        snapshot: Arc<GatewaySnapshot>,
        release: Release,
    ) -> Result<Ticket, Status> {
        let _gate = self.publication.read();
        let plan = self.action_plan(&snapshot, &release.intent.baseline.cluster_id)?;
        let receiver = plan.receiver.as_ref().expect("validated receiver");
        if release.intent.node_id == plan.node_id
            || !receiver.nodes.contains_key(&release.intent.node_id)
        {
            return Err(Status::failed_precondition(
                "remote node membership unavailable",
            ));
        }
        let signer = receiver
            .issuer
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("node issuer unavailable"))?;
        let definition = definition::cached(release.intent.target_count as usize)
            .map_err(|_| Status::failed_precondition("node definition unavailable"))?;
        let checked = release
            .validate(&definition)
            .map_err(|_| Status::invalid_argument("invalid node release"))?;
        let window = Window::admit(&release.delivery)
            .map_err(|_| Status::deadline_exceeded("node release window unavailable"))?;
        // 签名前再次复验真实接收槽，数据库目标记录不能代替当前节点的会话和就绪事实。
        self.store.lock().action_authority(
            &plan,
            &release.intent.node_id,
            &release.delivery.receiving_boot_id,
            &release.delivery.session,
        )?;
        let signature = signer.sign_release(&plan.node_id, &release, &definition)?;
        self.install_offer(Offer {
            accepts_body: false,
            message: checked.message,
            wire: Message::Release(release_wire::encode(release, signature, &definition)?),
            body: Bytes::new(),
            snapshot,
            window,
            reply: parking_lot::Mutex::new(None),
        })
    }
}

impl Offer {
    /// 业务作用：把精确原代际关闭事实交给发行任务，任何业务结果或模糊关闭声明都不能释放占位。
    ///
    /// 参数说明：
    /// - request：已经通过当前 mTLS、会话和释放摘要门的节点确认。
    ///
    /// 返回：仅在共享释放事务提交后完成的等待权；用途、原意图、存储或代际不一致时拒绝。
    pub(in crate::admin::management) fn receive_release(
        &self,
        request: &protocol::ReleaseResultRequest,
    ) -> Result<oneshot::Receiver<()>, Status> {
        let Message::Release(wire) = &self.wire else {
            return Err(Status::invalid_argument(
                "node delivery is not a terminal release",
            ));
        };
        let (release, _) = release_wire::decode(wire.clone())?;
        let definition = definition::cached(release.intent.target_count as usize)
            .map_err(|_| Status::failed_precondition("node definition unavailable"))?;
        let checked = release
            .validate(&definition)
            .map_err(|_| Status::invalid_argument("invalid node release"))?;
        if !request.closed
            || request.release_id != checked.message
            || request.intent_sha256.as_slice() != checked.intent_sha256
            || request.store_id != release.intent.baseline.store_id
            || request.node_admission_epoch.to_string()
                != release.intent.baseline.node_admission_epoch
        {
            return Err(Status::invalid_argument(
                "node closed epoch evidence differs",
            ));
        }
        let (confirmation, receiver) = oneshot::channel();
        let sender =
            self.reply.lock().take().ok_or_else(|| {
                Status::already_exists("node release already awaiting confirmation")
            })?;
        sender
            .send(Received {
                result: None,
                closed: true,
                confirmation,
            })
            .map_err(|_| Status::unavailable("node release owner stopped"))?;
        Ok(receiver)
    }
}
