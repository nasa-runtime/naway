//! 管理监听的绑定、发布与停机只有一个owner，数据转发不依赖管理端存活。

use super::{plan, protocol, receiver, reporter, telemetry, Plan};
use crate::admin::{AdminPlaneMode, AdminState};
use crate::config::GatewaySnapshot;
use anyhow::{ensure, Result};
use arc_swap::ArcSwap;
use nagrpc::{GrpcServerActivation, GrpcTlsAcceptor, GrpcTlsAcceptorSource};
use nasa::grpc::{GrpcMethodPolicy, GrpcServerConfig, GrpcServerHandle, ServerPlan};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

pub struct Manager {
    pub(super) snapshots: Arc<ArcSwap<GatewaySnapshot>>,
    pub(super) store: parking_lot::Mutex<receiver::Store>,
    pub(super) publication: parking_lot::RwLock<()>,
    pub(super) stopping: CancellationToken,
    interest: parking_lot::Mutex<Option<(std::sync::Weak<GatewaySnapshot>, Instant)>>,
    pub(super) sample_memory: Arc<tokio::sync::Semaphore>,
    #[cfg(feature = "node-actions")]
    pub(super) action_permits: Arc<tokio::sync::Semaphore>,
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    pub(super) action_deliveries:
        parking_lot::Mutex<std::collections::BTreeMap<String, Arc<super::actions::Offer>>>,
    mode: AdminPlaneMode,
    active: parking_lot::Mutex<Option<Active>>,
    reporter: OnceLock<AbortOnDropHandle<()>>,
}

struct Active {
    address: SocketAddr,
    handle: GrpcServerHandle,
}

pub struct Prepared {
    manager: Arc<Manager>,
    address: Option<SocketAddr>,
    bound: Option<(GrpcServerHandle, GrpcServerActivation)>,
}

struct TlsSource {
    snapshots: Arc<ArcSwap<GatewaySnapshot>>,
    address: SocketAddr,
    prepared: GrpcTlsAcceptor,
}

impl GrpcTlsAcceptorSource for TlsSource {
    /// 业务作用：每次新握手选取完整已发布TLS材料，禁止文件轮换越过快照提交。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前监听的已验证材料；撤销期间只保留原验证资源，RPC授权仍拒绝旧监听。
    fn acceptor(&self) -> GrpcTlsAcceptor {
        self.snapshots
            .load()
            .admin_management
            .as_ref()
            .and_then(|plan| plan.receiver.as_ref())
            .filter(|receiver| receiver.listen == self.address)
            .map(|receiver| receiver.acceptor.clone())
            .unwrap_or_else(|| self.prepared.clone())
    }
}

impl Manager {
    /// 业务作用：在发行前绑定完整控制面、当前快照和同集群签名权，旧计划不能借新监听继续工作。
    ///
    /// 参数说明：
    /// - snapshot：本次执行实际冻结的完整活动实例。
    /// - cluster：原执行持久绑定的集群。
    ///
    /// 返回：仍有效的同一管理计划；停机、角色不足、证书过期或发行身份不符时拒绝。
    #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
    pub(in crate::admin) fn action_plan(
        &self,
        snapshot: &Arc<GatewaySnapshot>,
        cluster: &str,
    ) -> Result<Arc<Plan>, nasa::grpc::Status> {
        let plan = snapshot.admin_management.as_ref().ok_or_else(|| {
            nasa::grpc::Status::failed_precondition("node management unavailable")
        })?;
        // 内容相同不能恢复旧快照的资格；证书和签名身份必须来自此刻发布的完整计划。
        if self.stopping.is_cancelled()
            || !self.mode.full_control_plane()
            || !Arc::ptr_eq(&self.snapshots.load_full(), snapshot)
            || !plan.receiver.as_ref().is_some_and(|receiver| {
                unix_seconds() < receiver.expires_at
                    && receiver
                        .issuer
                        .as_ref()
                        .is_some_and(|issuer| issuer.cluster() == cluster)
            })
        {
            return Err(nasa::grpc::Status::failed_precondition(
                "node issuer authority unavailable",
            ));
        }
        Ok(plan.clone())
    }

    /// 业务作用：记录已通过集群读取授权的有限观察兴趣，配置换代不能继承旧观察权。
    ///
    /// 参数说明：
    /// - `snapshot`：请求认证与集群开关共同采用的当前快照。
    ///
    /// 返回：只更新单一截止时刻，不创建逐观察者任务或远端调用。
    pub(in crate::admin) fn observe_metrics(&self, snapshot: &Arc<GatewaySnapshot>) {
        *self.interest.lock() = Some((Arc::downgrade(snapshot), Instant::now()));
    }

    /// 业务作用：向当前会话表达剩余采样需求，心跳自身不能续期观察兴趣。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同代且启用监控和接收能力时最多十二秒，否则为零。
    pub(super) fn metrics_interest(&self) -> u32 {
        let snapshot = self.snapshots.load_full();
        if !snapshot.admin_monitor.enabled
            || !snapshot
                .admin_management
                .as_ref()
                .and_then(|plan| plan.receiver.as_ref())
                .is_some_and(|receiver| receiver.metrics)
        {
            return 0;
        }
        self.interest
            .lock()
            .as_ref()
            .filter(|(owner, _)| {
                owner
                    .upgrade()
                    .is_some_and(|owner| Arc::ptr_eq(&owner, &snapshot))
            })
            .map_or(0, |(_, at)| {
                telemetry::INTEREST_MS
                    .saturating_sub(at.elapsed().as_millis().min(u128::from(u32::MAX)) as u32)
            })
    }

    /// 业务作用：只向同代观测提供当前管理监听的真实owner，禁止撤权后读取旧监听会计。
    ///
    /// 参数说明：
    /// - `snapshot`：本轮采样冻结的完整配置。
    ///
    /// 返回：身份、地址与已发布计划均一致时返回只读观察句柄，否则保留未知。
    pub(super) fn observer(
        &self,
        snapshot: &GatewaySnapshot,
    ) -> Option<nasa::grpc::GrpcServerObserver> {
        let _gate = self.publication.read();
        let plan = snapshot.admin_management.as_ref()?;
        let receiver = plan.receiver.as_ref()?;
        if self.stopping.is_cancelled()
            || !self
                .snapshots
                .load()
                .admin_management
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, plan))
        {
            // 旧快照不能取得已换代或已撤销监听的事实，调用方将本轮标为不可观测。
            return None;
        }
        self.active
            .lock()
            .as_ref()
            .filter(|active| active.address == receiver.listen)
            .map(|active| active.handle.observer())
    }

    /// 业务作用：创建跨热更的管理生命周期owner，尚未发布资源时不绑定或主动连接。
    ///
    /// 参数说明：
    /// - `snapshots`：数据面与管理面共用的唯一快照槽。
    /// - `mode`：启动时冻结的Admin/Data权限边界。
    ///
    /// 返回：空接收槽和停止权，只有prepare/commit后才开放监听。
    pub(in crate::admin) fn new(
        snapshots: Arc<ArcSwap<GatewaySnapshot>>,
        mode: AdminPlaneMode,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshots,
            interest: parking_lot::Mutex::new(None),
            sample_memory: Arc::new(tokio::sync::Semaphore::new(telemetry::STORE_BYTES)),
            #[cfg(feature = "node-actions")]
            action_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(all(feature = "node-actions", feature = "admin-operations-workflow-pgsql"))]
            action_deliveries: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            mode,
            store: parking_lot::Mutex::new(receiver::Store::default()),
            publication: parking_lot::RwLock::new(()),
            stopping: CancellationToken::new(),
            active: parking_lot::Mutex::new(None),
            reporter: OnceLock::new(),
        })
    }

    /// 业务作用：在配置提交前绑定候选管理监听，地址冲突或Data角色不得形成半完成发布。
    ///
    /// 参数说明：
    /// - `candidate`：已完整验证但尚未发布的快照。
    ///
    /// 返回：仅Bound的候选与一次性激活权；失败保留旧监听，丢弃候选自动关闭。
    pub async fn prepare(self: &Arc<Self>, candidate: &GatewaySnapshot) -> Result<Prepared> {
        let receiver = candidate
            .admin_management
            .as_ref()
            .and_then(|plan| plan.receiver.as_ref());
        ensure!(
            receiver.is_none() || self.mode.full_control_plane(),
            "management receiver requires admin or all-in-one mode"
        );
        let address = receiver.map(|receiver| receiver.listen);
        let current = self.active.lock().as_ref().map(|active| active.address);
        let bound = if address != current {
            if let Some(receiver) = receiver {
                Some(bind(self, receiver).await?)
            } else {
                None
            }
        } else {
            None
        };
        Ok(Prepared {
            manager: self.clone(),
            address,
            bound,
        })
    }

    /// 业务作用：使最终节点事实受理与权限快照发布互斥，旧连接不能跨撤权继续更新事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只可在同步发布区间持有的写锁，不得跨await。
    pub fn publication_guard(&self) -> parking_lot::RwLockWriteGuard<'_, ()> {
        self.publication.write()
    }

    /// 业务作用：启动唯一主动报告任务，多个管理监听不会复制节点上报连接。
    ///
    /// 参数说明：
    /// - `state`：提供真实运行事实的进程管理状态。
    ///
    /// 返回：仅首次启动任务；任务等待时只保留弱引用，避免状态生命周期循环。
    pub fn start_reporter(&self, state: &Arc<AdminState>) {
        self.reporter.get_or_init(|| {
            AbortOnDropHandle::new(tokio::spawn(reporter::run(Arc::downgrade(state))))
        });
    }

    /// 业务作用：按当前接收授权返回完整成员集合，证书失效或监听故障不能继续显示为健康。
    ///
    /// 参数说明：
    /// - `plan`：与页面查询同代的管理计划。
    ///
    /// 返回：逐节点有限事实与失效原因，不包含历史样本。
    pub(in crate::admin) fn observations(&self, plan: &Arc<Plan>) -> Vec<receiver::Observation> {
        let _gate = self.publication.read();
        if !self
            .snapshots
            .load()
            .admin_management
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, plan))
        {
            return Vec::new();
        }
        let active = self.active.lock();
        let running = active.as_ref().is_some_and(|active| {
            active.handle.observer().snapshot().state == nasa::grpc::GrpcServerState::Running
        });
        let valid = !self.stopping.is_cancelled()
            && running
            && plan
                .receiver
                .as_ref()
                .is_some_and(|receiver| unix_seconds() < receiver.expires_at);
        let mut observations = self.store.lock().observations(plan, Instant::now());
        if !valid {
            // 接收权威失效后旧样本不再构成可用性证据，仍保留预期成员以显示覆盖缺口。
            for observation in &mut observations {
                observation.availability = "receiver_unavailable";
                observation.facts = None;
                observation.at = None;
                observation.catalog = None;
                observation.action_baseline.withdraw("receiver_unavailable");
                observation.sample = None;
                observation.metrics_availability = "receiver_unavailable";
            }
        }
        observations
    }

    /// 业务作用：先撤销报告和接收权，再等待受管监听在固定预算内排空。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有管理准入已关闭；排空故障记录固定原因，不阻止业务进程结束。
    pub async fn shutdown(&self) {
        let active = {
            let _gate = self.publication.write();
            self.stopping.cancel();
            if let Some(task) = self.reporter.get() {
                task.abort();
            }
            *self.store.lock() = receiver::Store::default();
            self.active.lock().take()
        };
        if let Some(active) = active {
            if active.handle.shutdown().await.is_err() {
                tracing::warn!("management receiver drain did not complete");
            }
        }
    }
}

impl Prepared {
    /// 业务作用：快照已发布后才开放候选接收权，同时关闭旧地址并有界等待其退出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：候选激活完成；若受管owner丢失则保留明确不可用状态，不让旧地址恢复权限。
    pub async fn commit(self) {
        if self
            .manager
            .active
            .lock()
            .as_ref()
            .map(|active| active.address)
            == self.address
        {
            return;
        }
        let old = self.manager.active.lock().take();
        if let (Some(address), Some((handle, activation))) = (self.address, self.bound) {
            // 入站授权读取的快照已经生效；激活失败只能报告不可用，不能恢复已经撤销的旧监听。
            if activation.activate().await.is_err() {
                tracing::error!("management receiver activation failed");
            }
            *self.manager.active.lock() = Some(Active {
                address,
                handle,
            });
        }
        if let Some(old) = old {
            if old.handle.shutdown().await.is_err() {
                tracing::warn!("previous management receiver drain did not complete");
            }
        }
    }
}

/// 业务作用：通过NASA受管装配统一消息、连接和方法身份门禁，不复制底层HTTP/2执行器。
///
/// 参数说明：
/// - `manager`：唯一管理运行态。
/// - `receiver`：完整候选接收计划。
///
/// 返回：绑定但尚未接流的受管句柄与一次性激活权。
async fn bind(
    manager: &Arc<Manager>,
    receiver: &plan::Receiver,
) -> Result<(GrpcServerHandle, GrpcServerActivation)> {
    let mut config = GrpcServerConfig {
        max_connections: 128,
        concurrency_limit_per_connection: 2,
        max_concurrent_streams: 2,
        max_inflight_rpcs: 32,
        max_inflight_message_bytes: 2 * 1024 * 1024,
        managed_memory_budget_bytes: 64 * 1024 * 1024,
        unary_timeout: super::RPC_TIMEOUT,
        connection_handshake_timeout: Duration::from_secs(2),
        first_request_timeout: Duration::from_secs(3),
        idle_connection_timeout: Duration::from_secs(15),
        initial_stream_window_size: 32 * 1024,
        initial_connection_window_size: 64 * 1024,
        max_send_buffer_size: 32 * 1024,
        max_connection_age: Some(Duration::from_secs(300)),
        connection_eviction_grace: Duration::from_secs(1),
        drain_timeout: Duration::from_secs(2),
        message_limits: nasa::grpc::GrpcMessageLimits {
            max_decoding_bytes: super::MAX_MESSAGE,
            max_encoding_bytes: super::MAX_MESSAGE,
        },
        ..GrpcServerConfig::default()
    };
    for method in [
        "Open",
        "AuthenticateIssuer",
        "Report",
        "Catalog",
        "Sample",
        "ActionData",
        "ActionResult",
    ] {
        config.method_policies.insert(
            format!("/naway.management.v1.NodeManagement/{method}"),
            GrpcMethodPolicy {
                require_peer_identity: true,
                max_inflight_rpcs: Some(32),
                requests_per_second: Some(256),
                burst: Some(512),
            },
        );
    }
    Ok(ServerPlan::with_config(config)
        .add_service(protocol::node_management_server::NodeManagementServer::new(
            receiver::Service {
                manager: Arc::downgrade(manager),
                address: receiver.listen,
            },
        ))?
        .tls_source(Arc::new(TlsSource {
            snapshots: manager.snapshots.clone(),
            address: receiver.listen,
            prepared: receiver.acceptor.clone(),
        }))
        .bind(receiver.listen)
        .await?)
}

/// 业务作用：按证书绝对有效期检查身份，不用采样单调时钟替代X.509墙钟合同。
///
/// 参数说明: 无。
///
/// 返回：当前Unix秒；墙钟早于epoch时返回零并由证书准备阶段拒绝不合理时间。
pub(super) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
