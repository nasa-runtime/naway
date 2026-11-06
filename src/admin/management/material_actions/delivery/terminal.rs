//! 原共享终态独立签发，只有节点精确同步关闭后才交给共享释放事务确认。

use super::*;

impl Manager {
    /// 业务作用：为已确认共享终态安装独立材料释放投递，不携带任何候选秘密。
    ///
    /// 参数说明：
    /// - `snapshot`：当前共享释放授权采用的精确实例。
    /// - `release`：完整原意图、物理位置、终态及当前租约。
    ///
    /// 返回：原释放唯一等待权；身份、会话、签名或容量不符拒绝。
    pub(in crate::admin) fn offer_material_release(
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
                "remote material membership unavailable",
            ));
        }
        let checked = release
            .validate()
            .map_err(|_| Status::invalid_argument("material release differs"))?;
        let window = Window::admit(&release.delivery)
            .map_err(|_| Status::deadline_exceeded("material release window unavailable"))?;
        self.store.lock().material_action_authority(
            &plan,
            &release.intent.node_id,
            &release.delivery.receiving_boot_id,
            &release.delivery.session,
        )?;
        let signature = receiver
            .issuer
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("material issuer absent"))?
            .sign_material_release(&plan.node_id, &release)?;
        wire::encode_release(&release, &signature)?;
        self.install_material_offer(Offer {
            content: None,
            command: Message::Release(release),
            signature,
            message: checked.message,
            snapshot,
            window,
            reply: parking_lot::Mutex::new(None),
        })
    }
}

impl Offer {
    /// 业务作用：精确核对原释放的关闭事实，业务结果、另一执行域或另一终态都不能释放原任务占位。
    ///
    /// 参数说明：
    /// - `request`：当前会话绑定的独立释放回执。
    ///
    /// 返回：等待共享释放提交的确认通道；少字段或任一身份不符拒绝。
    pub(in crate::admin::management) fn receive_release(
        &self,
        request: &protocol::MaterialReleaseResultRequest,
    ) -> Result<oneshot::Receiver<()>, Status> {
        let Message::Release(release) = &self.command else {
            return Err(Status::invalid_argument("material terminal offer absent"));
        };
        let digest = release
            .position
            .fingerprint(&release.intent)
            .map_err(|_| Status::invalid_argument("material release intent differs"))?;
        if request.encoded_len() > MAX_MESSAGE
            || !request.closed
            || request.release_id != self.message
            || request.intent_sha256.as_slice() != digest
            || request.execution_store != release.intent.execution_store
            || request.node_admission_epoch != release.intent.baseline.node_admission_epoch
            || request.definition_digest != release.definition_digest
            || request.terminal != super::super::report_fields::terminal(release.terminal)
        {
            return Err(Status::invalid_argument(
                "material terminal confirmation differs",
            ));
        }
        self.submit(None, None, true)
    }
}
