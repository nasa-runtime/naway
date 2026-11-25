//! 本地具名配置由已登记的管理对端同步，接收和发送都只认识完整活动代。

mod ledger;
mod transfer;

use anyhow::{Context, Result};
use hyper::StatusCode;
use nasa::grpc::{Code, Request, Status};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use super::protocol::{self, node_management_client::NodeManagementClient};
use crate::admin::AdminState;
use crate::config::{replication::Generation, GatewaySnapshot};
use ledger::{Ledger, Revision};

pub(super) struct Local {
    owner: OnceLock<Weak<AdminState>>,
    observations: parking_lot::Mutex<BTreeMap<String, Observation>>,
    pub(super) gate: Arc<tokio::sync::Mutex<()>>,
}

struct Observation {
    snapshot: Weak<GatewaySnapshot>,
    at: Instant,
    status: &'static str,
}

pub(super) struct Published {
    storage: PathBuf,
    ledger: Ledger,
    generation: Arc<Generation>,
}

pub(super) struct Received {
    target: Generation,
    history: Vec<Revision>,
}

/// 业务作用：读取本节点引导的配置复制权开关。
/// 参数说明: 无。
/// 返回：只有明确启用本地管理 gRPC 复制时为真。
pub(super) fn enabled() -> bool {
    std::env::var("NAWAY_NAMED_CONFIG_GRPC_SYNC").as_deref() == Ok("true")
}

impl Local {
    /// 业务作用：用节点引导开启独立复制协议，保持普通管理心跳角色的现有写权边界。
    /// 参数说明: 无。
    /// 返回：明确启用时创建一个操作槽，否则管理 RPC 不提供配置复制。
    pub(super) fn from_env() -> Option<Self> {
        enabled().then(|| Self {
            owner: OnceLock::new(),
            observations: parking_lot::Mutex::default(),
            gate: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// 业务作用：建立唯一管理运行态与正式配置事务的弱引用，复制进程不能延长业务生命周期。
    /// 参数说明：
    /// - `owner`：拥有快照与文件事务的管理运行态。
    /// 返回：首次绑定成功后该关联在进程生命周期内保持不变。
    pub(super) fn bind(&self, owner: &Arc<AdminState>) {
        let _ = self.owner.set(Arc::downgrade(owner));
    }

    /// 业务作用：取得当前可参与本地复制的运行态，删除最后一个真实 owner 即撤销写权。
    /// 参数说明: 无。
    /// 返回：当前已启用的正式配置事务；准备期或已关闭时拒绝。
    pub(super) fn owner(&self) -> Result<Arc<AdminState>, Status> {
        self.owner
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| Status::unavailable("named configuration owner unavailable"))
    }

    /// 业务作用：只记录经受信端点返回的配置确认，避免将前一活动代误标为已同步。
    /// 参数说明：
    /// - `node`：本机固定的受信对端身份。
    /// - `snapshot`：本次真实共享原文所使用的快照。
    /// - `result`：对端精确落盘确认、分叉或暂时不可达。
    /// 返回：为一个固定目标替换最新低敏状态。
    pub(super) fn observe_peer(
        &self,
        node: String,
        snapshot: Weak<GatewaySnapshot>,
        result: &Result<(), Status>,
    ) {
        let mut observations = self.observations.lock();
        observations.retain(|_, observation| observation.snapshot.strong_count() != 0);
        let status = match result {
            Ok(()) => "applied",
            Err(error) if error.code() == Code::Aborted => "conflict",
            Err(error) if error.code() == Code::FailedPrecondition => "pending",
            Err(error) if error.code() == Code::InvalidArgument => "rejected",
            Err(_) => "unavailable",
        };
        observations.insert(
            node,
            Observation {
                snapshot,
                at: Instant::now(),
                status,
            },
        );
    }

    /// 业务作用：为配置管理页展示当前代的对端应用事实，不泄露业务内容或 TLS 地址。
    /// 参数说明：
    /// - `active`：查询时的唯一活动配置代。
    /// 返回：按已配置目标排列的确认，旧代或过期观察显示正在等待。
    pub(super) fn status(&self, active: &Arc<GatewaySnapshot>) -> Option<serde_json::Value> {
        let plan = active
            .admin_management
            .as_ref()
            .filter(|_| active.named_configuration && active.config_bundle_digest.is_none())?;
        let observations = self.observations.lock();
        let peers = plan
            .targets
            .iter()
            .filter_map(|target| target.issuer.as_ref())
            .map(|issuer| {
                let node = issuer.node();
                let status = observations
                    .get(node)
                    .filter(|observation| {
                        observation.at.elapsed() <= Duration::from_secs(12)
                            && observation
                                .snapshot
                                .upgrade()
                                .is_some_and(|observed| Arc::ptr_eq(&observed, active))
                    })
                    .map_or("pending", |observation| observation.status);
                serde_json::json!({ "node": node, "status": status })
            })
            .collect::<Vec<_>>();
        let converged = !peers.is_empty() && peers.iter().all(|peer| peer["status"] == "applied");
        Some(serde_json::json!({ "mode": "grpc", "converged": converged, "peers": peers }))
    }
}

impl Published {
    /// 业务作用：读取经过 reload 发布的完整本地原文，与持久代次对齐后才提供给对端。
    /// 参数说明：
    /// - `snapshot`：已活动的本地配置快照。
    /// - `gate`：本节点复制事务的独占许可，必须跟随负责磁盘变更的阻塞任务。
    /// 返回：冻结的原文、代次及续办许可；未完成的阻塞任务即使失去 RPC 调用方也持有唯一写权。
    pub(super) async fn capture(
        snapshot: Arc<GatewaySnapshot>,
        gate: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<(Self, tokio::sync::OwnedMutexGuard<()>)> {
        // Tokio 取消等待不会中止磁盘任务，许可随任务转移才能防止一次失约请求覆盖新的代次。
        tokio::task::spawn_blocking(move || {
            let current = Self::capture_checked(&snapshot)?;
            Ok((current, gate))
        })
        .await?
    }

    /// 业务作用：在开启业务流量前和获得本机复制槽时使用同一完整原文判定。
    /// 参数说明：
    /// - `snapshot`：已完成完整语义解析且没有向数据面开放中间状态的配置。
    /// 返回：当前复制身份与字节。未决方向只承认精确的基线或目标。
    pub(super) fn capture_checked(snapshot: &GatewaySnapshot) -> Result<Self> {
        let generation = Generation::capture(snapshot)?;
        let storage = snapshot
            .source_config_path
            .parent()
            .context("replication root missing")?
            .join(".naway-config-replication.json");
        let mut ledger = Ledger::read(&storage)?;
        if ledger.observe(generation.digest)? {
            ledger.write(&storage)?;
        }
        Ok(Self {
            storage,
            ledger,
            generation: Arc::new(generation),
        })
    }

    /// 业务作用：返回来自实际活动快照的复制代次，避免把待写入或待应用状态当作确认。
    /// 参数说明: 无。
    /// 返回：当前活动代标识与完整原文摘要。
    pub(super) fn head(&self) -> protocol::NamedConfigHeadResponse {
        let revision = self
            .ledger
            .current
            .last()
            .expect("capture observes complete generation");
        protocol::NamedConfigHeadResponse {
            revision: revision.id.to_vec(),
            content_sha256: revision.content.to_vec(),
            recent_revisions: self
                .ledger
                .current
                .iter()
                .map(|entry| entry.id.to_vec())
                .collect(),
        }
    }

    /// 业务作用：在同一发布槽内保存接收方向，跨重连和重启仍对同一个候选解释应用结果。
    /// 参数说明：
    /// - `history`：从本地活动代向前的完整对端链。
    /// 返回：持久保存待处理方向后成功；持久化失败后不得写入受管原文。
    fn stage(&mut self, history: Vec<Revision>) -> Result<()> {
        self.ledger.pending = Some(history);
        self.ledger.write(&self.storage)
    }

    /// 业务作用：处理已明确拒绝且原字节已恢复的发布，允许后续独立编辑继续推进。
    /// 参数说明: 无。
    /// 返回：持久撤下待处理方向；失败后后续重试仍能观察原方向。
    fn clear_pending(&mut self) -> Result<()> {
        self.ledger.pending = None;
        self.ledger.write(&self.storage)
    }
}

/// 业务作用：接收完整正文前比较集群代次，落后、无共同基线和其它候选待处理时回绝写入。
/// 参数说明：
/// - `current`：本机活动原文和持久代次。
/// - `offer`：已通过节点身份判断的有限原文描述。
/// - `stream`：同一个对端会话内剩余的正文帧。
/// 返回：已验证的完整原文与匹配的对端链；未完成前没有配置副作用。
pub(super) async fn receive_offer(
    current: &Published,
    offer: protocol::NamedConfigOffer,
    stream: nasa::grpc::Streaming<protocol::NamedConfigFrame>,
) -> Result<Received, Status> {
    let incoming = transfer::Incoming::accept(offer)
        .map_err(|_| Status::invalid_argument("invalid named configuration offer"))?;
    let local = current
        .ledger
        .current
        .last()
        .expect("capture observes complete generation");
    if !ledger::advance(&current.ledger.current, local.id, &incoming.history)
        || current
            .ledger
            .pending
            .as_ref()
            .and_then(|pending| pending.last())
            .is_some_and(|pending| {
                incoming
                    .history
                    .iter()
                    .all(|revision| revision.id != pending.id && revision.parent != pending.id)
            })
    {
        return Err(Status::failed_precondition(
            "named configuration revision conflicts with the active baseline",
        ));
    }
    let desired = tokio::time::timeout(Duration::from_secs(10), incoming.receive(stream))
        .await
        .map_err(|_| Status::deadline_exceeded("named configuration body deadline"))??;
    Ok(Received {
        target: desired,
        history: incoming.history,
    })
}

/// 业务作用：接收端将共享原文映射到本地已登记模块，沿用现有配置写事务和唯一 reload 发布者。
/// 参数说明：
/// - `state`：被认证管理通道绑定的本机管理状态。
/// - `active`：接收前已经冻结的活动快照，写入时还会紧邻复验。
/// - `current`：本机经过读取验证的当前原文和代次。
/// - `received`：经过全传输校验的对端配置集合及其生命周期链。
/// - `gate`：接收端为本次提交持有的唯一复制许可。
/// - `reauthorize`：紧邻持久副作用复验传输与会话权限。
/// 返回：磁盘原字节已写入且活动快照确认为目标代才成功。
pub(super) async fn install(
    state: &Arc<AdminState>,
    active: Arc<GatewaySnapshot>,
    mut current: Published,
    received: Received,
    gate: tokio::sync::OwnedMutexGuard<()>,
    reauthorize: impl Fn() -> Result<(), Status> + Send + Sync + 'static,
) -> Result<protocol::NamedConfigHeadResponse, Status> {
    let Received {
        target,
        history,
    } = received;
    if target.digest == current.generation.digest {
        reauthorize()?;
        // 同样原文可以是经过中间代的回滚，仍须推进复制身份以拒绝旧代重放。
        current.stage(history).map_err(unavailable)?;
        let (published, _gate) = Published::capture(active, gate)
            .await
            .map_err(unavailable)?;
        return Ok(published.head());
    }
    let target = Arc::new(target);
    let paths =
        crate::admin::candidate::validate_replicated_named(state, active.clone(), target.clone())
            .await
            .map_err(|error| {
                tracing::warn!(
                    status = error.status().as_u16(),
                    "replicated named configuration candidate rejected"
                );
                Status::invalid_argument("named configuration candidate rejected")
            })?;
    // 候选语义构建跨越异步 I/O 后复验接收权限，之后才允许留下待处理方向。
    reauthorize()?;
    // 代次方向要先于文件替换持久化，重新开始时才能识别刚刚被写入的对端代。
    current.stage(history).map_err(unavailable)?;
    let baseline = current.generation.clone();
    let desired = target.clone();
    let response = crate::admin::publication::publish_local(
        state,
        active.clone(),
        move |history, active, snapshot| {
            if reauthorize().is_err() {
                return Ok(None);
            }
            history.compare_and_replicate_named(active, &baseline, &desired, &paths, snapshot)
        },
    )
    .await;
    match response.status() {
        StatusCode::OK => {
            let (published, _gate) = Published::capture(state.snap.load_full(), gate)
                .await
                .map_err(unavailable)?;
            if published.generation.digest != target.digest {
                return Err(Status::aborted(
                    "named configuration changed before confirmation",
                ));
            }
            Ok(published.head())
        }
        StatusCode::BAD_REQUEST => {
            current.clear_pending().map_err(unavailable)?;
            Err(Status::invalid_argument(
                "named configuration application rejected",
            ))
        }
        StatusCode::PRECONDITION_FAILED => {
            // 基线漂移明确未写入，可以释放方向让后续本地代单独完成。
            current.clear_pending().map_err(unavailable)?;
            Err(Status::aborted("named configuration baseline changed"))
        }
        _ => Err(Status::unavailable(
            "named configuration application awaiting confirmation",
        )),
    }
}

/// 业务作用：用已通过对端签名校验的管理会话比较代次，仅把完整配置发送给落后且同源的节点。
/// 参数说明：
/// - `client`：已认证的固定 gRPC 节点通道。
/// - `sender`：本轮管理心跳取得的节点、启动和会话绑定。
/// - `published`：仅包含本机已应用的配置及其行进历史。
/// 返回：当前对端身份或完整持久应用得到确认；分叉与失败以协议状态返回。
pub(super) async fn share(
    mut client: NodeManagementClient<nasa::grpc::Channel>,
    sender: protocol::NamedConfigSession,
    published: &Published,
) -> Result<(), Status> {
    let mut head = Request::new(sender.clone());
    head.set_timeout(Duration::from_secs(2));
    let remote = client.named_config_head(head).await?.into_inner();
    let id = transfer::hash(&remote.revision).map_err(unavailable)?;
    let content = transfer::hash(&remote.content_sha256).map_err(unavailable)?;
    let local = published
        .ledger
        .current
        .last()
        .expect("published revision exists");
    if id == local.id && content == local.content {
        return Ok(());
    }
    if !published
        .ledger
        .current
        .iter()
        .any(|revision| revision.parent == id)
    {
        if remote
            .recent_revisions
            .iter()
            .any(|previous| previous.as_slice() == local.id)
        {
            return Err(Status::failed_precondition(
                "named configuration peer is ahead",
            ));
        }
        return Err(Status::aborted(
            "named configuration revisions have no known forward direction",
        ));
    }
    let mut offer = Request::new(transfer::outgoing(
        sender,
        &published.ledger.current,
        &published.generation,
    ));
    offer.set_timeout(Duration::from_secs(15));
    let remote = client.named_config_push(offer).await?.into_inner();
    if remote.revision != local.id || remote.content_sha256 != local.content {
        return Err(Status::data_loss(
            "named configuration confirmation differs",
        ));
    }
    Ok(())
}

/// 业务作用：用固定网络状态报告内部持久化错误，避免把本地路径或配置正文传给其它节点。
/// 参数说明：
/// - `error`：本机有界操作的失败信息。
/// 返回：统一不确定状态；内部原因只在本机记录。
pub(super) fn unavailable(error: anyhow::Error) -> Status {
    tracing::warn!(%error, "local named configuration replication unavailable");
    Status::unavailable("named configuration replication unavailable")
}
