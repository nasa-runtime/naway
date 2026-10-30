//! 预览读取与回报沿用当前 mTLS 会话，只接受原目标的同代完整事实。

use super::{protocol, Service, Store};
use crate::admin::management::{
    preview::{command::Intent, Offer, Reason},
    Manager, Plan, FRESHNESS,
};
use crate::config::GatewaySnapshot;
use nasa::grpc::{PeerIdentity, Request, Response, Status};
use std::{sync::Arc, time::Instant};

impl Manager {
    /// 业务作用：只从当前受信接收槽取得原目标预览会话，不补选成员或以旧启动代替原目标。
    ///
    /// 参数说明：
    /// - `snapshot`：本次请求冻结的当前发行快照。
    /// - `intent`：原提案固定的目标与完整基线。
    ///
    /// 返回：原目标仍具当前预览能力和原基线时的会话；其它情况保留明确拒绝类别。
    pub(in crate::admin) fn remote_preview_session(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        intent: &Intent,
    ) -> Result<[u8; 32], Reason> {
        let _gate = self.publication.read();
        let plan = self
            .action_plan(snapshot, &intent.baseline.cluster_id)
            .map_err(|_| Reason::Denied)?;
        self.store.lock().preview_session(&plan, intent)
    }
}

impl Store {
    /// 业务作用：在同一接收锁内核对预览能力、原启动、配置与持久基线，避免拼接不同报告的证明。
    ///
    /// 参数说明：
    /// - `plan`：已经通过当前发行权限门的管理计划。
    /// - `intent`：原提案已固定的唯一目标声明。
    ///
    /// 返回：仍新鲜且完整匹配的原会话；不支持、关闭、缺席、失权或换代均不形成预览成功。
    pub(in crate::admin::management) fn preview_session(
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
        if !entry.previews_supported {
            return Err(Reason::Unsupported);
        }
        if !entry.previews_enabled {
            return Err(Reason::Disabled);
        }
        // 预览没有跨重启恢复语义；原 boot 或原基线缺失必须保留失败，不能从当前节点补齐。
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
    /// 业务作用：为预览原文与结果共用当前证书、原会话、原目标基线和精确投递门。
    ///
    /// 参数说明：
    /// - `manager`：本监听的当前生命周期 owner。
    /// - `identity`：本次 mTLS 已验证的证书主体。
    /// - `node`：请求声明且必须与证书绑定的节点。
    /// - `boot`：原目标启动身份。
    /// - `session`：原管理会话。
    /// - `message`：独立预览签名消息的摘要。
    ///
    /// 返回：仍有效的唯一原投递；调用者必须持同步发布读锁，不得跨 await 保留。
    fn preview_offer(
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
            .preview_deliveries
            .lock()
            .get(node)
            .cloned()
            .ok_or_else(|| Status::failed_precondition("preview absent"))?;
        let current = manager
            .store
            .lock()
            .preview_session(&plan, &offer.command.intent)
            .map_err(|_| Status::failed_precondition("preview original target unavailable"))?;
        if !crate::security::auth::constant_time_eq(&current, session) {
            return Err(Status::permission_denied("preview session differs"));
        }
        offer.authorize(manager, node, boot, session, Some(message))?;
        Ok(offer)
    }

    /// 业务作用：在最终同步权限门内交付一份有限原文片段，不占用数据库或文件发布事务。
    ///
    /// 参数说明：
    /// - `request`：本次传输认证的节点、原会话与连续偏移。
    ///
    /// 返回：原签名候选的精确片段；失权、换代或错摘要时没有正文交付。
    pub(super) fn read_preview_data(
        &self,
        request: Request<protocol::PreviewDataRequest>,
    ) -> Result<Response<protocol::PreviewDataResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("preview receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.preview_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        offer.data(value.offset).map(Response::new)
    }

    /// 业务作用：仅在当前原目标证明成立时把完整差异交给原请求，回报不刷新节点事实年龄。
    ///
    /// 参数说明：
    /// - `request`：本次 mTLS 会话的低敏完整结果。
    ///
    /// 返回：原等待者接收成功后的 ACK；取消、部分结果或旧基线拒绝，不保存历史结果。
    pub(super) fn receive_preview_result(
        &self,
        request: Request<protocol::PreviewResultRequest>,
    ) -> Result<Response<protocol::PreviewResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("preview receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.preview_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        let message = value.offer_id.clone();
        offer.receive(request.into_inner())?;
        Ok(Response::new(protocol::PreviewResultResponse {
            accepted_offer_id: message,
        }))
    }
}
