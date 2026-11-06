//! 材料投递使用独立节点能力，结果确认沿原mTLS会话等待共享事务，不刷新运行事实。

mod authority;

use super::{protocol, Service, Store};
use crate::admin::management::{
    actions::ActionSession, material_actions::Offer, Manager, Plan, FRESHNESS, RPC_TIMEOUT,
};
use crate::{config::GatewaySnapshot, control::material::node::Intent};
use nasa::grpc::{PeerIdentity, Request, Response, Status};
use std::{sync::Arc, time::Instant};

impl Service {
    /// 业务作用：在当前同步发布门内复验节点证书、独立会话和精确投递，正文与结果采用同一权威。
    ///
    /// 参数说明：
    /// - `manager`：当前管理监听owner。
    /// - `identity`：本连接实际验证的mTLS主体。
    /// - `node`：请求节点标识。
    /// - `boot`：当前接收启动身份。
    /// - `session`：当前随机管理会话。
    /// - `message`：原独立材料投递摘要。
    ///
    /// 返回：精确当前原生槽；错身份、失联或窗口失效拒绝，不持锁跨await。
    fn material_action_offer(
        &self,
        manager: &Manager,
        identity: Option<&PeerIdentity>,
        node: &str,
        boot: &str,
        session: &[u8],
        message: &str,
    ) -> Result<Arc<Offer>, Status> {
        let plan = self.authorize(manager, node, identity)?;
        manager
            .store
            .lock()
            .material_action_authority(&plan, node, boot, session)?;
        let offer = manager
            .material_action_deliveries
            .lock()
            .get(node)
            .cloned()
            .ok_or_else(|| Status::failed_precondition("material delivery absent"))?;
        offer.authorize(manager, node, boot, session, Some(message))?;
        Ok(offer)
    }

    /// 业务作用：在最终当前授权门内读取有限秘密分片，慢客户端不能持有文件或数据库锁。
    ///
    /// 参数说明：
    /// - `request`：当前认证连接中的原材料投递与偏移。
    ///
    /// 返回：同一次原帧的有限片段，失权或错用途时不泄露正文。
    pub(super) fn read_material_action_data(
        &self,
        request: Request<protocol::MaterialActionDataRequest>,
    ) -> Result<Response<protocol::MaterialActionDataResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.material_action_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        offer.data(value.offset).map(Response::new)
    }

    /// 业务作用：移交完整事实后释放同步锁等待共享提交，数据库迟缓不冻结心跳或其它目标。
    ///
    /// 参数说明：
    /// - `request`：精确原投递的完整节点结果，报告只移动一次所有权。
    ///
    /// 返回：共享事务明确确认且原会话仍有效后ACK；等待失败不宣称提交回滚。
    pub(super) async fn receive_material_action_result(
        &self,
        mut request: Request<protocol::MaterialActionResultRequest>,
    ) -> Result<Response<protocol::MaterialActionResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let (offer, confirmation) = {
            let _gate = manager.publication.read();
            let value = request.get_ref();
            let offer = self.material_action_offer(
                &manager,
                request.extensions().get::<PeerIdentity>(),
                &value.node_id,
                &value.boot_id,
                &value.session,
                &value.offer_id,
            )?;
            let confirmation = offer.receive(request.get_mut())?;
            (offer, confirmation)
        };
        tokio::time::timeout(RPC_TIMEOUT, confirmation)
            .await
            .map_err(|_| Status::deadline_exceeded("material confirmation expired"))?
            .map_err(|_| Status::unavailable("material transaction unconfirmed"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        // 提交后原槽可能已被等待者移除，复验必须仍绑定原Arc而不能借后来投递确认。
        let plan = self.authorize(
            &manager,
            &value.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        manager.store.lock().material_action_authority(
            &plan,
            &value.node_id,
            &value.boot_id,
            &value.session,
        )?;
        offer.authorize(
            &manager,
            &value.node_id,
            &value.boot_id,
            &value.session,
            Some(&value.offer_id),
        )?;
        Ok(Response::new(protocol::MaterialActionResultResponse {
            accepted_offer_id: value.offer_id.clone(),
        }))
    }

    /// 业务作用：原关闭事实完整匹配后等待共享释放事务，不把收到网络消息当作责任已释放。
    ///
    /// 参数说明：
    /// - `request`：当前认证会话的独立材料终态回执。
    ///
    /// 返回：共享提交与原会话复验均成功后ACK，超时或取消仍可原意图重投。
    pub(super) async fn receive_material_release_result(
        &self,
        request: Request<protocol::MaterialReleaseResultRequest>,
    ) -> Result<Response<protocol::MaterialReleaseResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let (offer, confirmation) = {
            let _gate = manager.publication.read();
            let value = request.get_ref();
            let offer = self.material_action_offer(
                &manager,
                request.extensions().get::<PeerIdentity>(),
                &value.node_id,
                &value.boot_id,
                &value.session,
                &value.release_id,
            )?;
            let confirmation = offer.receive_release(value)?;
            (offer, confirmation)
        };
        tokio::time::timeout(RPC_TIMEOUT, confirmation)
            .await
            .map_err(|_| Status::deadline_exceeded("material release confirmation expired"))?
            .map_err(|_| Status::unavailable("material release transaction unconfirmed"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        // 已关闭证明与原投递同时保留到事务确认，当前新槽不能替代原释放身份。
        let plan = self.authorize(
            &manager,
            &value.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        manager.store.lock().material_action_authority(
            &plan,
            &value.node_id,
            &value.boot_id,
            &value.session,
        )?;
        offer.authorize(
            &manager,
            &value.node_id,
            &value.boot_id,
            &value.session,
            Some(&value.release_id),
        )?;
        Ok(Response::new(protocol::MaterialReleaseResultResponse {
            accepted_release_id: value.release_id.clone(),
        }))
    }
}
