//! 节点上报使用证书绑定和接收端会话令牌，迟到报告不能覆盖新启动实例。

use super::{catalog, protocol, security, telemetry, Manager, Plan, FRESHNESS};
use crate::admin::cluster::facts::Facts;
use nasa::grpc::{PeerIdentity, Request, Response, Status};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Instant;

#[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
mod actions;
#[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
mod preview;

#[derive(Default)]
pub(super) struct Store {
    plan: Weak<Plan>,
    entries: BTreeMap<String, Entry>,
}

struct Entry {
    boot: String,
    session: [u8; 32],
    sequence: u64,
    at: Instant,
    conflict: Option<Instant>,
    facts: Option<Arc<Facts>>,
    catalog: catalog::State,
    metrics_supported: bool,
    metrics_enabled: bool,
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    actions_enabled: bool,
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    previews_supported: bool,
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    previews_enabled: bool,
    baseline_supported: bool,
    baseline: Option<Arc<crate::control::baseline::NodeBaseline>>,
    publication: Arc<crate::control::publication_status::PublicationStatus>,
    sample: Option<Arc<telemetry::Current>>,
    last_sample: Option<(u64, [u8; 32], u64)>,
}

pub(in crate::admin) struct Observation {
    pub id: String,
    pub availability: &'static str,
    pub facts: Option<Arc<Facts>>,
    pub at: Option<Instant>,
    pub catalog: Option<Arc<crate::admin::catalog::Catalog>>,
    pub sample: Option<Arc<telemetry::Current>>,
    pub action_baseline: crate::admin::cluster::baseline::Observation,
    pub metrics_availability: &'static str,
}

pub(super) struct Service {
    pub manager: Weak<Manager>,
    pub address: SocketAddr,
}

impl Store {
    /// 业务作用：使会话和当前报告只属于同一授权计划，撤权不留下可继续读取的旧事实。
    ///
    /// 参数说明：
    /// - `plan`：当前已发布管理计划。
    ///
    /// 返回：计划变化时释放全部旧会话与报告，否则保留单调序号。
    fn reconcile(&mut self, plan: &Arc<Plan>) {
        if !self
            .plan
            .upgrade()
            .is_some_and(|old| Arc::ptr_eq(&old, plan))
        {
            self.entries.clear();
            self.plan = Arc::downgrade(plan);
        }
    }

    /// 业务作用：为已认证节点建立唯一启动会话，活跃同名进程冲突不能静默覆盖。
    ///
    /// 参数说明：
    /// - `id`：已通过证书绑定的节点。
    /// - `boot`：经过长度和字符验证的启动身份。
    /// - `now`：接收端单调时刻。
    ///
    /// 返回：当前启动的随机会话；不同活跃boot返回冲突且不延长原样本有效期。
    fn open(&mut self, id: String, boot: String, now: Instant) -> Result<Vec<u8>, Status> {
        if let Some(entry) = self.entries.get_mut(&id) {
            if entry.boot == boot {
                return Ok(entry.session.to_vec());
            }
            if now.saturating_duration_since(entry.at) <= FRESHNESS {
                // 第二个活跃进程不能借重连夺取同名节点；冲突单独保留，不篡改原节点采样时刻。
                entry.conflict = Some(now);
                return Err(Status::already_exists("node boot conflict"));
            }
        }
        let mut session = [0u8; 32];
        getrandom::getrandom(&mut session)
            .map_err(|_| Status::unavailable("session entropy unavailable"))?;
        self.entries.insert(
            id,
            Entry {
                boot,
                session,
                sequence: 0,
                at: now,
                conflict: None,
                facts: None,
                catalog: catalog::State::default(),
                metrics_supported: false,
                metrics_enabled: false,
                #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
                actions_enabled: false,
                #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
                previews_supported: false,
                #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
                previews_enabled: false,
                baseline_supported: false,
                baseline: None,
                publication: Arc::new(
                    crate::control::publication_status::PublicationStatus::empty("unsupported"),
                ),
                sample: None,
                last_sample: None,
            },
        );
        Ok(session.to_vec())
    }

    /// 业务作用：只接收当前会话严格递增的事实，重复、乱序和旧boot均不能刷新健康年龄。
    ///
    /// 参数说明：
    /// - `facts`：已经验证的当前协议事实。
    /// - `session`：接收端签发的当前会话令牌。
    /// - `sequence`：上报者单调序号。
    /// - `now`：用于freshness的接收端单调时刻。
    ///
    /// 返回：完整接收时更新单一事实槽；拒绝时不改变原样本。
    fn report(
        &mut self,
        facts: Facts,
        session: &[u8],
        sequence: u64,
        now: Instant,
    ) -> Result<(), Status> {
        let id = facts.node_id.as_deref().expect("validated node identity");
        let entry = self
            .entries
            .get_mut(id)
            .ok_or_else(|| Status::failed_precondition("open node session first"))?;
        if entry.boot != facts.boot_id
            || !crate::security::auth::constant_time_eq(&entry.session, session)
        {
            // boot更替后旧令牌永久失去本会话权威，不能因新样本暂时过期而恢复旧写入。
            return Err(Status::failed_precondition("node session changed"));
        }
        if sequence == 0 || sequence <= entry.sequence {
            return Err(Status::out_of_range("node sequence must increase"));
        }
        entry.sequence = sequence;
        entry.at = now;
        // 新事实本身不能继承旧的持久基线；接收入口只在同一锁内补入本次已验证的证明。
        entry.baseline = None;
        entry.baseline_supported = false;
        entry.publication =
            Arc::new(crate::control::publication_status::PublicationStatus::empty("unsupported"));
        if entry.facts.as_ref().is_none_or(|old| {
            old.config_version != facts.config_version
                || old.config_fingerprint != facts.config_fingerprint
        }) {
            // 心跳宣布新配置后，旧对象目录立即失去权威，不能等待下一份目录完成再撤下。
            entry.catalog = catalog::State::default();
            entry.sample = None;
        }
        entry.facts = Some(Arc::new(facts));
        Ok(())
    }

    /// 业务作用：在目录分片进入内存前复验当前会话、配置身份与全接收槽预算。
    ///
    /// 参数说明：
    /// - `request`：已通过TLS节点绑定的分片。
    /// - `now`：接收端单调时刻。
    ///
    /// 返回：当前目录装配结果；陈旧、冲突、换代或预算不足均拒绝且不延长心跳。
    fn catalog(
        &mut self,
        request: protocol::CatalogRequest,
        now: Instant,
    ) -> Result<protocol::CatalogResponse, Status> {
        let others = self
            .entries
            .iter()
            .filter(|(id, _)| id.as_str() != request.node_id)
            .map(|(_, entry)| entry.catalog.bytes())
            .sum::<usize>();
        let entry = self
            .entries
            .get_mut(&request.node_id)
            .ok_or_else(|| Status::failed_precondition("open node session first"))?;
        let expected = request
            .config_fingerprint
            .map(|value| format!("{value:016x}"));
        if entry.boot != request.boot_id
            || !crate::security::auth::constant_time_eq(&entry.session, &request.session)
            || now.saturating_duration_since(entry.at) > FRESHNESS
            || entry
                .conflict
                .is_some_and(|at| now.saturating_duration_since(at) <= FRESHNESS)
            || !entry.facts.as_ref().is_some_and(|facts| {
                facts.config_version == request.config_version
                    && facts.config_fingerprint == expected
            })
        {
            // 目录只证明同一活跃配置，旧会话与失去心跳的节点不能继续补全可读集合。
            return Err(Status::failed_precondition(
                "catalog node authority changed",
            ));
        }
        entry
            .catalog
            .accept(request, catalog::STORE_BYTES.saturating_sub(others))
    }

    /// 业务作用：按配置成员生成有界当前视图，未报告和过期节点仍计入预期覆盖。
    ///
    /// 参数说明：
    /// - `plan`：读取时重新取得的授权计划。
    /// - `now`：接收端单调时刻。
    ///
    /// 返回：成员完整清单；只共享有效事实，不克隆字段或返回过期报告。
    pub(super) fn observations(&mut self, plan: &Arc<Plan>, now: Instant) -> Vec<Observation> {
        self.reconcile(plan);
        self.prune_samples(now, true);
        let Some(receiver) = &plan.receiver else {
            return Vec::new();
        };
        receiver
            .nodes
            .keys()
            .map(|id| {
                let entry = self.entries.get(id);
                let conflict = entry
                    .and_then(|entry| entry.conflict)
                    .is_some_and(|at| now.saturating_duration_since(at) <= FRESHNESS);
                let fresh =
                    entry.filter(|entry| now.saturating_duration_since(entry.at) <= FRESHNESS);
                let facts = fresh.and_then(|entry| entry.facts.clone());
                Observation {
                    action_baseline: crate::admin::cluster::baseline::Observation {
                        availability: if conflict {
                            "identity_conflict"
                        } else if let Some(entry) = fresh.filter(|entry| entry.facts.is_some()) {
                            if !entry.baseline_supported {
                                "unsupported"
                            } else if entry.baseline.is_some() {
                                "available"
                            } else {
                                "unavailable"
                            }
                        } else if entry.is_some() {
                            "stale"
                        } else {
                            "sampling"
                        },
                        node_baseline: fresh
                            .filter(|_| !conflict)
                            .and_then(|entry| entry.baseline.clone()),
                        local_publication: fresh
                            .filter(|entry| !conflict && entry.facts.is_some())
                            .map(|entry| entry.publication.clone())
                            .unwrap_or_else(|| {
                                Arc::new(
                                    crate::control::publication_status::PublicationStatus::empty(
                                        "unavailable",
                                    ),
                                )
                            }),
                    },
                    sample: fresh
                        .filter(|_| !conflict && receiver.metrics)
                        .and_then(|entry| entry.sample.clone()),
                    metrics_availability: if conflict {
                        "identity_conflict"
                    } else if !receiver.metrics {
                        "disabled"
                    } else if let Some(entry) = fresh.filter(|entry| entry.facts.is_some()) {
                        if !entry.metrics_supported {
                            "unsupported"
                        } else if !entry.metrics_enabled {
                            "disabled"
                        } else if entry.sample.is_some() {
                            "available"
                        } else if entry.last_sample.is_some() {
                            "stale"
                        } else {
                            "sampling"
                        }
                    } else if entry.is_some() {
                        "stale"
                    } else {
                        "sampling"
                    },
                    id: id.clone(),
                    availability: if conflict {
                        "identity_conflict"
                    } else if let Some(facts) = &facts {
                        if facts.ready {
                            "available"
                        } else {
                            "not_ready"
                        }
                    } else if entry.is_some() {
                        "stale"
                    } else {
                        "sampling"
                    },
                    at: fresh
                        .filter(|entry| entry.facts.is_some())
                        .map(|entry| entry.at),
                    catalog: fresh
                        .filter(|_| !conflict)
                        .and_then(|entry| entry.catalog.complete()),
                    facts,
                }
            })
            .collect()
    }

    /// 业务作用：释放已过期或已无观察兴趣的样本，心跳不得让旧指标一直占用内存。
    ///
    /// 参数说明：
    /// - `now`：接收端当前单调时刻。
    /// - `interested`：当前同代观察权是否仍有效。
    ///
    /// 返回：过期引用和内存许可一并释放，节点事实与目录保持独立。
    pub(super) fn prune_samples(&mut self, now: Instant, interested: bool) {
        for entry in self.entries.values_mut() {
            if !interested
                || entry.sample.as_ref().is_some_and(|current| {
                    now.saturating_duration_since(current.at)
                        > std::time::Duration::from_millis(current.sample.sampling_period_ms) * 3
                })
            {
                entry.sample = None;
            }
        }
    }

    /// 业务作用：在上传开始与最终发布时复验同一会话、配置和节点角色，旧流不能越过撤权。
    ///
    /// 参数说明：
    /// - `node`：已通过mTLS绑定的节点。
    /// - `session`：当前boot会话令牌。
    /// - `sample`：待发布的完整样本身份。
    /// - `now`：当前接收时刻，用于心跳与冲突门。
    ///
    /// 返回：仍有指标上报权的接收槽；无权、失联和配置分歧均拒绝且不续期。
    fn sample_authority(
        &mut self,
        node: &str,
        session: &[u8],
        sample: &crate::admin::monitor::model::Sample,
        now: Instant,
    ) -> Result<&mut Entry, Status> {
        let entry = self
            .entries
            .get_mut(node)
            .ok_or_else(|| Status::failed_precondition("open node session first"))?;
        if entry.boot != sample.boot_id
            || !crate::security::auth::constant_time_eq(&entry.session, session)
            || !entry.metrics_supported
            || !entry.metrics_enabled
            || now.saturating_duration_since(entry.at) > FRESHNESS
            || entry
                .conflict
                .is_some_and(|at| now.saturating_duration_since(at) <= FRESHNESS)
            || !entry.facts.as_ref().is_some_and(|facts| {
                facts.config_version == sample.state.config_version
                    && facts.config_fingerprint == sample.state.config_fingerprint
                    && facts.mode == sample.state.mode
                    && facts.discovery_enabled == sample.state.discovery_enabled
                    && facts.configuration_enabled == sample.state.configuration_enabled
                    && facts.proxies == sample.state.proxies
                    && facts.routes == sample.state.routes
                    && facts.services == sample.state.services
            })
        {
            // 心跳、配置和声明能力共同授予当前接收权，旧会话不能在流末尾恢复权限。
            return Err(Status::failed_precondition("sample node authority changed"));
        }
        Ok(entry)
    }
    /// 业务作用：在最终授权门内单次替换当前样本，缓存释放后仍保留单调序号与内容证明。
    ///
    /// 参数说明：
    /// - `node`：当前已认证管理节点。
    /// - `session`：该boot的会话令牌。
    /// - `current`：完整验证且已持有内存许可的当前样本。
    /// - `hash`：全字段规范摘要。
    ///
    /// 返回：发布或相同内容确认后的序号；重放、倒退或权限变化拒绝且释放候选许可。
    fn publish_sample(
        &mut self,
        node: &str,
        session: &[u8],
        current: telemetry::Current,
        hash: [u8; 32],
    ) -> Result<u64, Status> {
        let sample = &current.sample;
        let sample_id = sample.sample_id;
        if current.at.elapsed() > std::time::Duration::from_millis(sample.sampling_period_ms) * 3 {
            // 完整校验和等待发布锁也消耗样本年龄，最终提交不能重新获得完整新鲜期。
            return Err(Status::out_of_range("sample expired before publication"));
        }
        let entry = self.sample_authority(node, session, sample, Instant::now())?;
        if let Some((old_id, old_hash, old_elapsed)) = entry.last_sample {
            if sample_id < old_id
                || (sample_id == old_id && hash != old_hash)
                || (sample_id > old_id && sample.elapsed_ms <= old_elapsed)
            {
                return Err(Status::out_of_range("sample sequence must increase"));
            }
            if sample_id == old_id {
                // ACK丢失只能确认旧内容，即使缓存已过期也不能重新安装样本或刷新年龄。
                return Ok(sample_id);
            }
        }
        // 先验证完整内容、内存与最终权威，再发布单一当前引用，读面不经过半份状态。
        entry.last_sample = Some((sample_id, hash, sample.elapsed_ms));
        entry.sample = Some(Arc::new(current));
        Ok(sample_id)
    }
}

impl Service {
    /// 业务作用：在RPC处理期间复验监听、运行模式和当前节点证书授权，旧连接不能继承新权限。
    ///
    /// 参数说明：
    /// - `manager`：唯一接收运行态。
    /// - `node`：消息声明的节点。
    /// - `identity`：传输层验证产生的叶证书身份。
    ///
    /// 返回：当前完整计划；停机、监听撤销、证书失配或未知节点均拒绝。
    fn authorize(
        &self,
        manager: &Manager,
        node: &str,
        identity: Option<&PeerIdentity>,
    ) -> Result<Arc<Plan>, Status> {
        if manager.stopping.is_cancelled() {
            return Err(Status::unavailable("management receiver draining"));
        }
        let plan = manager
            .snapshots
            .load()
            .admin_management
            .clone()
            .ok_or_else(|| Status::permission_denied("management disabled"))?;
        let receiver = plan
            .receiver
            .as_ref()
            .filter(|receiver| receiver.listen == self.address)
            .ok_or_else(|| Status::permission_denied("management listener withdrawn"))?;
        if super::runtime::unix_seconds() >= receiver.expires_at {
            return Err(Status::unauthenticated("management identity expired"));
        }
        let identity =
            identity.ok_or_else(|| Status::unauthenticated("management mTLS identity required"))?;
        if receiver.nodes.get(node).map(String::as_str) != Some(identity.principal()) {
            return Err(Status::permission_denied("management node binding denied"));
        }
        Ok(plan)
    }
}

#[nasa::grpc::async_trait]
impl protocol::node_management_server::NodeManagement for Service {
    /// 业务作用：为实际证书绑定的node/boot取得接收端会话，重复建立不刷新运行事实。
    ///
    /// 参数说明：
    /// - `request`：有界身份声明与传输身份。
    ///
    /// 返回：成功时交付仅此boot可用的随机令牌，身份冲突时保持原事实。
    async fn open(
        &self,
        request: Request<protocol::OpenRequest>,
    ) -> Result<Response<protocol::OpenResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        if !security::identifier(&value.node_id) || !security::identifier(&value.boot_id) {
            return Err(Status::invalid_argument("invalid node identity"));
        }
        let plan = self.authorize(
            &manager,
            &value.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        let mut store = manager.store.lock();
        store.reconcile(&plan);
        let value = request.into_inner();
        let session = store.open(value.node_id, value.boot_id, Instant::now())?;
        Ok(Response::new(protocol::OpenResponse {
            session,
        }))
    }

    /// 业务作用：在当前证书、启动和会话共同认可后证明本端发行身份，不续期心跳或授予节点动作。
    ///
    /// 参数说明：
    /// - `request`：已受mTLS保护的节点声明、会话和单次随机挑战。
    ///
    /// 返回：当前发布身份的签名证明；未启用、错会话或旧权威均拒绝。
    async fn authenticate_issuer(
        &self,
        request: Request<protocol::IssuerChallenge>,
    ) -> Result<Response<protocol::IssuerProof>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let plan = self.authorize(
            &manager,
            &value.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        let signer = plan
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.issuer.as_ref())
            .ok_or_else(|| Status::failed_precondition("issuer proof disabled"))?;
        let mut store = manager.store.lock();
        store.reconcile(&plan);
        // 身份证明不能替其它启动建立信任，也不能通过反复证明延长节点事实的新鲜度。
        if !store.entries.get(&value.node_id).is_some_and(|entry| {
            entry.boot == value.boot_id && entry.session.as_slice() == value.session.as_slice()
        }) {
            return Err(Status::failed_precondition("issuer proof session differs"));
        }
        drop(store);
        signer.prove(&plan.node_id, value).map(Response::new)
    }

    /// 业务作用：将最新节点事实原子放入有界槽，不能通过客户端时钟或重放延长可用状态。
    ///
    /// 参数说明：
    /// - `request`：当前会话、严格递增序号及完整事实。
    ///
    /// 返回：仅成功发布当前槽后确认序号，任何门禁失败均保留原事实。
    async fn report(
        &self,
        request: Request<protocol::ReportRequest>,
    ) -> Result<Response<protocol::ReportResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let _gate = manager.publication.read();
        let value = request.get_ref();
        let node = value
            .facts
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing node facts"))?;
        let plan = self.authorize(
            &manager,
            &node.node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        let value = request.into_inner();
        if value.actions_enabled && !value.actions_supported
            || value.previews_enabled && !value.previews_supported
        {
            return Err(Status::invalid_argument("node action capability differs"));
        }
        let facts = protocol::decode(value.facts.expect("checked facts"))?;
        let cluster = plan
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.issuer.as_ref())
            .map(|issuer| issuer.cluster());
        let baseline = super::baseline::decode(
            value.baseline_supported,
            value.node_baseline,
            &facts,
            cluster,
        )?;
        let publication = super::publication::decode(
            value.local_publication,
            value.baseline_supported,
            &facts,
            cluster,
            baseline.as_deref(),
        )?;
        let node_id = facts.node_id.clone().expect("validated node id");
        let mut store = manager.store.lock();
        store.reconcile(&plan);
        store.report(facts, &value.session, value.sequence, Instant::now())?;
        let entry = store
            .entries
            .get_mut(&node_id)
            .expect("accepted node report");
        // 同次报告原子替换基线，缺席或能力关闭也必须撤销旧证明，不能跨新事实继续保留。
        entry.baseline_supported = value.baseline_supported;
        entry.baseline = baseline;
        entry.publication = publication;
        entry.metrics_supported = value.metrics_supported;
        entry.metrics_enabled = value.metrics_supported && value.metrics_enabled;
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        {
            entry.actions_enabled = value.actions_supported && value.actions_enabled;
            entry.previews_supported = value.previews_supported;
            entry.previews_enabled = value.previews_supported && value.previews_enabled;
        }
        let interest = manager.metrics_interest();
        if !entry.metrics_enabled || interest == 0 {
            entry.sample = None;
        }
        let metrics_interest_ms = if entry.metrics_enabled {
            interest
        } else {
            0
        };
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        let (action, release) = {
            let boot = entry.boot.clone();
            if store
                .action_authority(&plan, &node_id, &boot, &value.session)
                .is_ok()
            {
                manager
                    .action_deliveries
                    .lock()
                    .get(&node_id)
                    .filter(|offer| {
                        offer
                            .authorize(&manager, &node_id, &boot, &value.session, None)
                            .is_ok()
                    })
                    .map(|offer| offer.wire())
                    .unwrap_or_default()
            } else {
                (None, None)
            }
        };
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        // 节点接收能力没有共享执行 owner，心跳不能自行创建可写动作或释放声明。
        let (action, release) = (None, None);
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        let preview = if action.is_none() && release.is_none() {
            manager
                .preview_deliveries
                .lock()
                .get(&node_id)
                .filter(|offer| {
                    store
                        .preview_session(&plan, &offer.command.intent)
                        .is_ok_and(|session| session.as_slice() == value.session.as_slice())
                        && offer
                            .authorize(
                                &manager,
                                &node_id,
                                &offer.command.intent.boot,
                                &value.session,
                                None,
                            )
                            .is_ok()
                })
                .and_then(|offer| offer.wire().ok())
        } else {
            None
        };
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        let preview = None;
        Ok(Response::new(protocol::ReportResponse {
            accepted_sequence: value.sequence,
            action,
            release,
            metrics_interest_ms,
            service_metrics_supported: true,
            preview,
        }))
    }

    /// 业务作用：只向当前已获权原目标交付预览候选，未装配共享预览发行端的制品不提供正文。
    ///
    /// 参数说明：
    /// - `request`：当前 mTLS 节点提交的原会话、投递摘要和偏移。
    ///
    /// 返回：已授权的有界片段；能力关闭或任何身份不符都拒绝。
    async fn preview_data(
        &self,
        request: Request<protocol::PreviewDataRequest>,
    ) -> Result<Response<protocol::PreviewDataResponse>, Status> {
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        {
            self.read_preview_data(request)
        }
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        {
            let _ = request;
            Err(Status::unimplemented("node previews unavailable"))
        }
    }

    /// 业务作用：接收一次完整只读差异，不把网络确认解释为配置发布或持久效果。
    ///
    /// 参数说明：
    /// - `request`：原目标与原会话绑定的有限结果。
    ///
    /// 返回：原等待者接收结果后确认；无发行能力、旧结果或非法摘要拒绝。
    async fn preview_result(
        &self,
        request: Request<protocol::PreviewResultRequest>,
    ) -> Result<Response<protocol::PreviewResultResponse>, Status> {
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        {
            self.receive_preview_result(request)
        }
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        {
            let _ = request;
            Err(Status::unimplemented("node previews unavailable"))
        }
    }

    /// 业务作用：只向当前节点交付原签名动作的有限正文，未包含发行适配器的制品不提供候选读取。
    ///
    /// 参数说明：
    /// - `request`：mTLS 节点身份、原会话、投递摘要与精确偏移。
    ///
    /// 返回：当前授权分片；跨会话、过期或功能关闭均拒绝且不改变投递事实。
    async fn action_data(
        &self,
        request: Request<protocol::ActionDataRequest>,
    ) -> Result<Response<protocol::ActionDataResponse>, Status> {
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        {
            self.read_action_data(request)
        }
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        {
            // 没有发行适配器就没有受控原文投递槽，不能用节点身份获得候选正文。
            let _ = request;
            Err(Status::failed_precondition("node action issuing disabled"))
        }
    }

    /// 业务作用：将实际节点的结果交给共享事务 owner，只有事务明确确认才向节点返回 ACK。
    ///
    /// 参数说明：
    /// - `request`：当前会话与精确投递所声明的封闭结果。
    ///
    /// 返回：事务确认后的原投递身份；超时、权限变化或未知提交均保留可重投语义。
    async fn action_result(
        &self,
        request: Request<protocol::ActionResultRequest>,
    ) -> Result<Response<protocol::ActionResultResponse>, Status> {
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        {
            self.receive_action_result(request).await
        }
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        {
            // 缺少共享结果事务的 owner，不能向发送节点确认其效果已被控制面接纳。
            let _ = request;
            Err(Status::failed_precondition("node action issuing disabled"))
        }
    }

    /// 业务作用：独立接收节点代际关闭事实，共享事务确认前不向节点声明占位已释放。
    ///
    /// 参数说明：
    /// - request：当前连接与原释放声明绑定的精确关闭确认。
    ///
    /// 返回：事务提交及当前权威仍成立时返回原释放摘要；功能关闭、未知提交或失权均拒绝。
    async fn release_result(
        &self,
        request: Request<protocol::ReleaseResultRequest>,
    ) -> Result<Response<protocol::ReleaseResultResponse>, Status> {
        #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
        {
            self.receive_release_result(request).await
        }
        #[cfg(not(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql")))]
        {
            // 节点代际关闭不能代替共享占位释放；没有发行事务时不得返回释放确认。
            let _ = request;
            Err(Status::failed_precondition("node action issuing disabled"))
        }
    }

    /// 业务作用：在同一mTLS和发布门内接收当前配置对象分片，不提供任意配置上传或执行入口。
    ///
    /// 参数说明：
    /// - `request`：当前节点会话及固定目录消息。
    ///
    /// 返回：已受理偏移；只有完整内容验证后complete才为true。
    async fn catalog(
        &self,
        request: Request<protocol::CatalogRequest>,
    ) -> Result<Response<protocol::CatalogResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let _gate = manager.publication.read();
        let plan = self.authorize(
            &manager,
            &request.get_ref().node_id,
            request.extensions().get::<PeerIdentity>(),
        )?;
        let mut store = manager.store.lock();
        store.reconcile(&plan);
        store
            .catalog(request.into_inner(), Instant::now())
            .map(Response::new)
    }

    /// 业务作用：在独立期限与内存许可内接收一份当前指标，完整EOF和最终授权通过后才发布。
    ///
    /// 参数说明：
    /// - `request`：mTLS认证的类型化样本流。
    ///
    /// 返回：原子发布或相同样本确认；取消、半份、超时、越权与容量不足均保留原样本年龄。
    async fn sample(
        &self,
        request: Request<nasa::grpc::Streaming<protocol::SampleRequest>>,
    ) -> Result<Response<protocol::SampleResponse>, Status> {
        tokio::time::timeout(super::RPC_TIMEOUT, self.receive_sample(request))
            .await
            .map_err(|_| Status::deadline_exceeded("sample upload expired"))?
    }
}

impl Service {
    /// 业务作用：让网络等待与同步授权发布分开，慢上传不能占住全局事实锁或阻塞心跳。
    ///
    /// 参数说明：
    /// - `request`：仅携带当前样本的流及传输身份。
    ///
    /// 返回：完整样本ACK；流结束前不会改变可读槽，任何错误释放候选许可。
    async fn receive_sample(
        &self,
        request: Request<nasa::grpc::Streaming<protocol::SampleRequest>>,
    ) -> Result<Response<protocol::SampleResponse>, Status> {
        let manager = self
            .manager
            .upgrade()
            .ok_or_else(|| Status::unavailable("receiver stopped"))?;
        let mut memory = manager
            .sample_memory
            .clone()
            .try_acquire_many_owned(telemetry::SAMPLE_BYTES as u32)
            .map_err(|_| Status::resource_exhausted("sample receiver capacity"))?;
        let started = Instant::now();
        let identity = request.extensions().get::<PeerIdentity>().cloned();
        let mut stream = request.into_inner();
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("sample stream empty"))?;
        let plan = {
            let _gate = manager.publication.read();
            let plan = self.authorize(&manager, &first.node_id, identity.as_ref())?;
            if manager.metrics_interest() == 0 {
                // 未授权观察不产生接收兴趣，上传端不能自行延长采样或开启接收开关。
                return Err(Status::permission_denied("sample receiver has no interest"));
            }
            plan
        };
        let mut candidate = telemetry::Candidate::new(first, started)?;
        {
            let _gate = manager.publication.read();
            let current = self.authorize(&manager, &candidate.node, identity.as_ref())?;
            if !Arc::ptr_eq(&current, &plan) {
                return Err(Status::permission_denied(
                    "sample receiver authority changed",
                ));
            }
            let mut store = manager.store.lock();
            store.reconcile(&plan);
            store.sample_authority(
                &candidate.node,
                &candidate.session,
                &candidate.sample,
                Instant::now(),
            )?;
        }
        while let Some(part) = stream.message().await? {
            candidate.push(part)?;
        }
        let node = candidate.node.clone();
        let session = candidate.session.clone();
        let hash = candidate.digest;
        let at = candidate.at;
        let (sample, bytes) = candidate.finish()?;
        let _gate = manager.publication.read();
        let current = self.authorize(&manager, &node, identity.as_ref())?;
        if !Arc::ptr_eq(&current, &plan) || manager.metrics_interest() == 0 {
            // 完成流不能替代最终授权复验，撤权期间收到的EOF也没有发布权。
            return Err(Status::permission_denied(
                "sample receiver authority changed",
            ));
        }
        let mut store = manager.store.lock();
        store.reconcile(&plan);
        let retained = memory.split(bytes).expect("reserved sample memory");
        drop(memory);
        let sample_id = store.publish_sample(
            &node,
            &session,
            telemetry::Current {
                sample: Arc::new(sample),
                at,
                _memory: retained,
            },
            hash,
        )?;
        Ok(Response::new(protocol::SampleResponse {
            accepted_sample_id: sample_id,
        }))
    }
}
