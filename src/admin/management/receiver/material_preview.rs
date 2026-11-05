//! 材料候选预检读取与回报沿用当前 mTLS 会话，只接受原目标的同代完整事实。

use super::{protocol, Service, Store};
use crate::admin::management::{
    material_preview::{command::Intent, Offer, Reason},
    Manager, Plan,
};
use crate::config::GatewaySnapshot;
use nasa::grpc::{PeerIdentity, Request, Response, Status};
use std::sync::Arc;

impl Manager {
    /// 业务作用：只从当前受信接收槽取得原目标材料候选预检会话，不补选成员或以旧启动代替原目标。
    ///
    /// 参数说明：
    /// - `snapshot`：本次请求冻结的当前发行快照。
    /// - `intent`：原查询固定的同节点目标批次与完整基线。
    ///
    /// 返回：原目标仍具当前材料候选预检能力和原基线时的会话；其它情况保留明确拒绝类别。
    pub(in crate::admin) fn remote_material_preview_session(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        intent: &Intent,
    ) -> Result<[u8; 32], Reason> {
        let _gate = self.publication.read();
        let plan = self
            .action_plan(snapshot, &intent.baseline.cluster_id)
            .map_err(|_| Reason::Denied)?;
        self.store.lock().material_preview_session(&plan, intent)
    }
}

impl Store {
    /// 业务作用：在同一接收锁内核对材料候选预检能力、原启动、配置与持久基线，避免拼接不同报告的证明。
    ///
    /// 参数说明：
    /// - `plan`：已经通过当前发行权限门的管理计划。
    /// - `intent`：原查询已固定的节点和目标批次。
    ///
    /// 返回：仍新鲜且完整匹配的原会话；不支持、关闭、缺席、失权或换代均不形成材料候选预检成功。
    pub(in crate::admin::management) fn material_preview_session(
        &mut self,
        plan: &Arc<Plan>,
        intent: &Intent,
    ) -> Result<[u8; 32], Reason> {
        let session = self
            .material_session(plan, &intent.original)
            .map_err(Reason::from)?;
        let entry = self.entries.get(&intent.node).ok_or(Reason::Unavailable)?;
        // 旧节点的公开条件能力不足以接收秘密候选，必须独立证明支持且显式启用候选预检。
        if !entry.material_candidates_supported {
            return Err(Reason::Unsupported);
        }
        if !entry.material_candidates_enabled {
            return Err(Reason::Disabled);
        }
        Ok(session)
    }
}

impl Service {
    /// 业务作用：为材料结果复验当前证书、原会话、原目标基线和精确投递门。
    ///
    /// 参数说明：
    /// - `manager`：本监听的当前生命周期 owner。
    /// - `identity`：本次 mTLS 已验证的证书主体。
    /// - `node`：请求声明且必须与证书绑定的节点。
    /// - `boot`：原目标启动身份。
    /// - `session`：原管理会话。
    /// - `message`：独立材料候选预检签名消息的摘要。
    ///
    /// 返回：仍有效的唯一原投递；调用者必须持同步发布读锁，不得跨 await 保留。
    fn material_preview_offer(
        &self,
        manager: &Manager,
        identity: Option<&PeerIdentity>,
        node: &str,
        boot: &str,
        session: &[u8],
        message: &str,
    ) -> Result<Arc<Offer>, Status> {
        let plan = self.authorize(manager, node, identity)?;
        let offer = manager
            .material_preview_deliveries
            .lock()
            .get(node)
            .cloned()
            .ok_or_else(|| Status::failed_precondition("material preview absent"))?;
        let current = manager
            .store
            .lock()
            .material_preview_session(&plan, &offer.command.intent)
            .map_err(|_| {
                Status::failed_precondition("material preview original target unavailable")
            })?;
        // mTLS 证书只绑定节点身份；原会话也必须一致，避免重连后重放旧材料分片请求。
        if !crate::security::auth::constant_time_eq(&current, session) {
            return Err(Status::permission_denied(
                "material preview session differs",
            ));
        }
        offer.authorize(manager, node, boot, session, Some(message))?;
        Ok(offer)
    }

    /// 业务作用：仅在当前原目标证明成立时把完整预检证明交给原请求，回报不刷新节点事实年龄。
    ///
    /// 参数说明：
    /// - `request`：本次 mTLS 会话的低敏完整结果。
    ///
    /// 返回：原等待者接收成功后的 ACK；取消、部分结果或旧基线拒绝，不保存历史结果。
    pub(super) fn receive_material_preview_result(
        &self,
        request: Request<protocol::MaterialPreviewResultRequest>,
    ) -> Result<Response<protocol::MaterialPreviewResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("material preview receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.material_preview_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        let message = value.offer_id.clone();
        offer.receive(request.into_inner())?;
        Ok(Response::new(protocol::MaterialPreviewResultResponse {
            accepted_offer_id: message,
        }))
    }
    /// 业务作用：只向原mTLS节点和原会话释放有限分片，换代、关闭或投递取消立即撤销秘密读取。
    ///
    /// 参数说明：
    /// - `request`：原节点的精确消息身份与连续字节偏移。
    ///
    /// 返回：当前有效投递的最多16KiB片段，不访问数据库、不刷新任务期限。
    pub(super) fn read_material_preview_data(
        &self,
        request: Request<protocol::MaterialPreviewDataRequest>,
    ) -> Result<Response<protocol::MaterialPreviewDataResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("material preview receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.material_preview_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        Ok(Response::new(offer.data(value.offset)?))
    }
}
