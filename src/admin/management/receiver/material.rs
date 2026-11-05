//! 材料条件查询读取与回报沿用当前 mTLS 会话，只接受原目标的同代完整事实。

use super::{Service, Store, protocol};
use crate::admin::management::{
    FRESHNESS, Manager, Plan,
    material::{Offer, Reason, command::Intent},
};
use crate::config::GatewaySnapshot;
use nasa::grpc::{PeerIdentity, Request, Response, Status};
use std::{sync::Arc, time::Instant};

impl Manager {
    /// 业务作用：只从当前受信接收槽取得原目标材料条件查询会话，不补选成员或以旧启动代替原目标。
    ///
    /// 参数说明：
    /// - `snapshot`：本次请求冻结的当前发行快照。
    /// - `intent`：原查询固定的同节点目标批次与完整基线。
    ///
    /// 返回：原目标仍具当前材料条件查询能力和原基线时的会话；其它情况保留明确拒绝类别。
    pub(in crate::admin) fn remote_material_session(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        intent: &Intent,
    ) -> Result<[u8; 32], Reason> {
        let _gate = self.publication.read();
        let plan = self
            .action_plan(snapshot, &intent.baseline.cluster_id)
            .map_err(|_| Reason::Denied)?;
        self.store.lock().material_session(&plan, intent)
    }
}

impl Store {
    /// 业务作用：在同一接收锁内核对材料条件查询能力、原启动、配置与持久基线，避免拼接不同报告的证明。
    ///
    /// 参数说明：
    /// - `plan`：已经通过当前发行权限门的管理计划。
    /// - `intent`：原查询已固定的节点和目标批次。
    ///
    /// 返回：仍新鲜且完整匹配的原会话；不支持、关闭、缺席、失权或换代均不形成材料条件查询成功。
    pub(in crate::admin::management) fn material_session(
        &mut self,
        plan: &Arc<Plan>,
        intent: &Intent,
    ) -> Result<[u8; 32], Reason> {
        self.reconcile(plan);
        if intent.node == plan.node_id
            || !plan
                .receiver
                .as_ref()
                .is_some_and(|receiver| receiver.nodes.contains_key(&intent.node))
        {
            return Err(Reason::Unavailable);
        }
        let entry = self.entries.get(&intent.node).ok_or(Reason::Unavailable)?;
        let now = Instant::now();
        if now.saturating_duration_since(entry.at) > FRESHNESS
            || entry
                .conflict
                .is_some_and(|at| now.saturating_duration_since(at) <= FRESHNESS)
            || !entry.facts.as_ref().is_some_and(|facts| {
                facts.ready && matches!(facts.mode.as_str(), "data" | "sidecar" | "all-in-one")
            })
        {
            return Err(Reason::Unavailable);
        }
        let (supported, enabled) = match intent.query_kind {
            crate::admin::management::material::command::Query::Conditions => (
                entry.material_previews_supported,
                entry.material_previews_enabled,
            ),
            crate::admin::management::material::command::Query::Installations => (
                entry.material_installations_supported,
                entry.material_installations_enabled,
            ),
        };
        if !supported {
            return Err(Reason::Unsupported);
        }
        if !enabled {
            return Err(Reason::Disabled);
        }
        // 材料条件查询没有跨重启恢复语义；原 boot 或原基线缺失必须保留失败，不能从当前节点补齐。
        if entry.boot != intent.boot
            || entry.baseline.as_deref() != Some(&intent.baseline)
            || !entry.facts.as_ref().is_some_and(|facts| {
                facts.config_version == intent.version
                    && facts
                        .config_fingerprint
                        .as_deref()
                        .and_then(|value| u64::from_str_radix(value, 16).ok())
                        == Some(intent.fingerprint)
            })
        {
            return Err(Reason::BaselineChanged);
        }
        Ok(entry.session)
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
    /// - `message`：独立材料条件查询签名消息的摘要。
    ///
    /// 返回：仍有效的唯一原投递；调用者必须持同步发布读锁，不得跨 await 保留。
    fn material_offer(
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
            .material_deliveries
            .lock()
            .get(node)
            .cloned()
            .ok_or_else(|| Status::failed_precondition("material conditions absent"))?;
        let current = manager
            .store
            .lock()
            .material_session(&plan, &offer.command.intent)
            .map_err(|_| {
                Status::failed_precondition("material conditions original target unavailable")
            })?;
        if !crate::security::auth::constant_time_eq(&current, session) {
            return Err(Status::permission_denied(
                "material conditions session differs",
            ));
        }
        offer.authorize(manager, node, boot, session, Some(message))?;
        Ok(offer)
    }

    /// 业务作用：仅在当前原目标证明成立时把完整条件交给原请求，回报不刷新节点事实年龄。
    ///
    /// 参数说明：
    /// - `request`：本次 mTLS 会话的低敏完整结果。
    ///
    /// 返回：原等待者接收成功后的 ACK；取消、部分结果或旧基线拒绝，不保存历史结果。
    pub(super) fn receive_material_result(
        &self,
        request: Request<protocol::MaterialConditionsResultRequest>,
    ) -> Result<Response<protocol::MaterialConditionsResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("material conditions receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.material_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        let message = value.offer_id.clone();
        offer.receive(request.into_inner())?;
        Ok(Response::new(protocol::MaterialConditionsResultResponse {
            accepted_offer_id: message,
        }))
    }
}
