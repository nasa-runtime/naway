//! 动作正文和结果沿用当前证书与会话权威，不刷新节点心跳或推测工作流事实。

use super::{protocol, Service, Store};
use crate::admin::management::{actions::Offer, Manager, Plan, FRESHNESS};
use crate::{
    admin::management::actions::ActionSession, config::GatewaySnapshot,
    control::actions::command::Intent,
};
use nasa::grpc::{PeerIdentity, Request, Response, Status};
use std::{sync::Arc, time::Instant};

impl Manager {
    /// 业务作用：从当前认证接收槽取得原目标的实际会话，创建时额外确认完整审批基线没有漂移。
    ///
    /// 参数说明：
    /// - snapshot：本次授权固定的完整活动快照。
    /// - intent：原审批目标，不能从当前在线目录补选。
    /// - initial：初次创建为真；已有执行的查询和重投允许当前 boot 接续原持久意图。
    ///
    /// 返回：当前接收 boot 和随机会话；缺席、失联、冲突或初始基线不一致时不产生投递身份。
    pub(in crate::admin) fn remote_action_session(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        intent: &Intent,
        initial: bool,
    ) -> Result<ActionSession, Status> {
        let _gate = self.publication.read();
        let plan = self.action_plan(snapshot, &intent.baseline.cluster_id)?;
        let receiver = plan.receiver.as_ref().expect("validated receiver");
        if intent.node_id == plan.node_id || !receiver.nodes.contains_key(&intent.node_id) {
            return Err(Status::failed_precondition(
                "remote node membership unavailable",
            ));
        }
        self.store.lock().action_session(&plan, intent, initial)
    }
}

impl Store {
    /// 业务作用：在同一接收锁内复验会话与原始基线，不拼接来自不同次报告的节点事实。
    ///
    /// 参数说明：
    /// - plan：已经验证的当前发行计划。
    /// - intent：冻结目标及其审批基线。
    /// - initial：真时检查原始启动、配置及持久基线，假时只取得当前会话。
    ///
    /// 返回：通过新鲜度和动作开关门的有限地址；不刷新报告年龄或建立新会话。
    fn action_session(
        &mut self,
        plan: &Arc<Plan>,
        intent: &Intent,
        initial: bool,
    ) -> Result<ActionSession, Status> {
        self.reconcile(plan);
        let entry = self
            .entries
            .get(&intent.node_id)
            .ok_or_else(|| Status::failed_precondition("node action session unavailable"))?;
        let address = ActionSession {
            boot: entry.boot.clone(),
            token: entry.session,
        };
        self.action_authority(plan, &intent.node_id, &address.boot, &address.token)?;
        let entry = self.entries.get(&intent.node_id).expect("validated node");
        // 已开始的动作会撤下空闲基线；只在创建时要求原基线，后续仍由节点永久槽裁决原意图。
        if initial
            && (address.boot != intent.original_boot_id
                || entry.baseline.as_deref() != Some(&intent.baseline)
                || !entry.facts.as_ref().is_some_and(|facts| {
                    facts.config_version == intent.base_version
                        && facts
                            .config_fingerprint
                            .as_deref()
                            .and_then(|value| u64::from_str_radix(value, 16).ok())
                            == Some(intent.base_fingerprint)
                }))
        {
            return Err(Status::failed_precondition(
                "node action original baseline differs",
            ));
        }
        Ok(address)
    }

    /// 业务作用：复验节点已明确启用动作、当前会话和新鲜运行事实，失联或同名冲突不得继续交付。
    ///
    /// 参数说明：
    /// - `plan`：当前发布的接收权威。
    /// - `node`：mTLS 已绑定的节点。
    /// - `boot`：本次命令实际接收启动身份。
    /// - `session`：接收端签发的原会话。
    ///
    /// 返回：仍属于当前新鲜且可工作的节点时成功；不延长心跳、不创建会话。
    pub(in crate::admin::management) fn action_authority(
        &mut self,
        plan: &Arc<Plan>,
        node: &str,
        boot: &str,
        session: &[u8],
    ) -> Result<(), Status> {
        self.reconcile(plan);
        let now = Instant::now();
        let valid = self.entries.get(node).is_some_and(|entry| {
            entry.boot == boot
                && crate::security::auth::constant_time_eq(&entry.session, session)
                && entry.actions_enabled
                && now.saturating_duration_since(entry.at) <= FRESHNESS
                && entry
                    .conflict
                    .is_none_or(|at| now.saturating_duration_since(at) > FRESHNESS)
                && entry.facts.as_ref().is_some_and(|facts| {
                    facts.ready && matches!(facts.mode.as_str(), "data" | "sidecar" | "all-in-one")
                })
        });
        if !valid {
            // 没有当前节点证据时只能等待新的报告，不能用旧目录或数据库目标列表代替运行事实。
            return Err(Status::failed_precondition(
                "node action session unavailable",
            ));
        }
        Ok(())
    }
}

impl Service {
    /// 业务作用：仅在原代际关闭事实通过完整绑定后等待共享释放事务，网络确认不代替数据库提交。
    ///
    /// 参数说明：
    /// - request：本次 mTLS 连接中的独立释放确认。
    ///
    /// 返回：共享事务确认且原会话仍有效时交付 ACK；超时或取消保留同意图重投语义。
    pub(super) async fn receive_release_result(
        &self,
        request: Request<protocol::ReleaseResultRequest>,
    ) -> Result<Response<protocol::ReleaseResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let (offer, confirmation) = {
            let _gate = manager.publication.read();
            let value = request.get_ref();
            let offer = self.action_offer(
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
        tokio::time::timeout(crate::admin::management::RPC_TIMEOUT, confirmation)
            .await
            .map_err(|_| Status::deadline_exceeded("node release confirmation expired"))?
            .map_err(|_| Status::unavailable("node release transaction unconfirmed"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        // 事务之后可能已经移除原槽，仍须按原 offer 验证，不能把后来同节点投递当作此次确认。
        let plan = self.authorize(
            &manager,
            &value.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        manager.store.lock().action_authority(
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
        Ok(Response::new(protocol::ReleaseResultResponse {
            accepted_release_id: value.release_id.clone(),
        }))
    }

    /// 业务作用：为正文和结果共用完整接收门，TLS 名称、当前会话与精确投递缺一不可。
    ///
    /// 参数说明：
    /// - `manager`：当前接收监听 owner。
    /// - `identity`：本次传输已经验证的证书主体。
    /// - `node`：实际请求节点。
    /// - `boot`：实际请求启动身份。
    /// - `session`：原管理会话。
    /// - `message`：本次签名域摘要。
    ///
    /// 返回：当前唯一投递槽；调用方必须持同步发布读锁且不能跨 await 持有该锁。
    fn action_offer(
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
            .action_authority(&plan, node, boot, session)?;
        let offer = manager
            .action_deliveries
            .lock()
            .get(node)
            .cloned()
            .ok_or_else(|| Status::failed_precondition("node delivery absent"))?;
        offer.authorize(manager, node, boot, session, Some(message))?;
        Ok(offer)
    }

    /// 业务作用：在同步最终授权门内读取一个有界原文分片，慢客户端不持有数据库或文件锁。
    ///
    /// 参数说明：
    /// - `request`：当前有限正文读取声明及实际传输身份。
    ///
    /// 返回：精确偏移的原文字节；失权或错投递时没有正文泄露。
    pub(super) fn read_action_data(
        &self,
        request: Request<protocol::ActionDataRequest>,
    ) -> Result<Response<protocol::ActionDataResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let offer = self.action_offer(
            &manager,
            request.extensions().get::<PeerIdentity>(),
            &value.node_id,
            &value.boot_id,
            &value.session,
            &value.offer_id,
        )?;
        offer.data(value.offset).map(Response::new)
    }

    /// 业务作用：移交有限结果后释放同步锁等待事务，数据库迟缓不能冻结其它节点心跳。
    ///
    /// 参数说明：
    /// - `request`：精确当前投递的节点结果。
    ///
    /// 返回：只有事务确认且当前读取权仍有效才返回 ACK；等待取消不宣称回滚。
    pub(super) async fn receive_action_result(
        &self,
        request: Request<protocol::ActionResultRequest>,
    ) -> Result<Response<protocol::ActionResultResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let (offer, confirmation) = {
            let _gate = manager.publication.read();
            let value = request.get_ref();
            let offer = self.action_offer(
                &manager,
                request.extensions().get::<PeerIdentity>(),
                &value.node_id,
                &value.boot_id,
                &value.session,
                &value.offer_id,
            )?;
            let confirmation = offer.receive(value)?;
            (offer, confirmation)
        };
        tokio::time::timeout(crate::admin::management::RPC_TIMEOUT, confirmation)
            .await
            .map_err(|_| Status::deadline_exceeded("node result confirmation expired"))?
            .map_err(|_| Status::unavailable("node result transaction unconfirmed"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        // 发行任务可能已在事务提交后释放内存槽；确认仍绑定原 offer，不能借后来同节点的槽替代。
        let plan = self.authorize(
            &manager,
            &value.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        manager.store.lock().action_authority(
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
        Ok(Response::new(protocol::ActionResultResponse {
            accepted_offer_id: value.offer_id.clone(),
        }))
    }
}
