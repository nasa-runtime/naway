//! 多管理入口的共享当前节点读面，不以接入节点配置代替整个集群的运行事实。

use super::{directory, facts};
use crate::admin::{AdminState, BoxBody};
use crate::config::GatewaySnapshot;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use futures::{stream, StreamExt};
use http::{Response, StatusCode};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

const PERIOD: Duration = Duration::from_secs(2);

pub(in crate::admin) struct Runtime {
    origin: Instant,
    interest: AtomicU64,
    wake: Arc<Notify>,
    latest: ArcSwapOption<Publication>,
    task: OnceLock<AbortOnDropHandle<()>>,
}

pub(in crate::admin) struct Publication {
    document: Bytes,
    pub at: Instant,
    valid_until: Instant,
    snapshot: Weak<GatewaySnapshot>,
    pub nodes: Arc<[Node]>,
    pub coverage: Coverage,
}

impl Publication {
    /// 业务作用：把最早失效节点的剩余期限传给页面，网络中断不能重新获得完整六秒有效期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：覆盖本轮实体与最旧节点证据的有效年龄，单位毫秒。
    pub(in crate::admin) fn age_ms(&self) -> u64 {
        let remaining = self.valid_until.saturating_duration_since(Instant::now());
        self.at
            .elapsed()
            .max((PERIOD * 3).saturating_sub(remaining))
            .as_millis() as u64
    }
}

#[derive(Serialize)]
pub(in crate::admin) struct Node {
    pub id: String,
    pub address: String,
    pub availability: &'static str,
    pub source_age_ms: Option<u64>,
    pub facts: Option<Arc<facts::Facts>>,
    pub action_baseline: super::baseline::Observation,
    #[serde(skip)]
    at: Option<Instant>,
    #[serde(skip)]
    pub catalog: Option<Arc<crate::admin::catalog::Catalog>>,
}

#[derive(Serialize, Clone)]
pub(in crate::admin) struct Coverage {
    pub total: usize,
    declared_targets: usize,
    reachable: usize,
    ready: usize,
    unknown: usize,
    data_nodes: usize,
    control_nodes: usize,
    pub conflicting_ids: bool,
    pub truncated: bool,
    discovery_enabled: bool,
    pub discovery_available: bool,
    pub directory_stale: bool,
    pub limited_to_local: bool,
}

#[derive(Serialize)]
struct View<'a> {
    schema_version: u8,
    scope: &'static str,
    sample_id: u64,
    sampled_at_ms: i64,
    sampling_period_ms: u64,
    directory_version: u64,
    directory_fingerprint: Option<String>,
    availability: &'static str,
    coverage: Coverage,
    nodes: &'a [Node],
}

impl Runtime {
    /// 业务作用：创建空的节点事实槽，不因管理监听启动就访问远端成员。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有授权观察兴趣才能启动查询的有限运行态。
    pub(in crate::admin) fn new() -> Self {
        Self {
            origin: Instant::now(),
            interest: AtomicU64::new(0),
            wake: Arc::new(Notify::new()),
            latest: ArcSwapOption::empty(),
            task: OnceLock::new(),
        }
    }

    /// 业务作用：用进程单调时钟衡量当前观察兴趣，墙钟调整不延长保留期限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前运行态已存在的有限毫秒数。
    fn elapsed(&self) -> u64 {
        self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

/// 业务作用：使所有管理监听代共享一个节点目录协调任务，避免随页面和监听热换重复查询。
///
/// 参数说明：
/// - `state`：唯一进程管理状态，任务等待时不持有其强引用。
///
/// 返回：首次安装后台任务；状态销毁后自动取消查询。
pub(in crate::admin) fn start(state: &Arc<AdminState>) {
    state.cluster.task.get_or_init(|| {
        AbortOnDropHandle::new(tokio::spawn(run(
            Arc::downgrade(state),
            state.cluster.wake.clone(),
        )))
    });
}

/// 业务作用：取得当前共享集群节点事实，并阻止配置或凭据撤销前的数据跨代回填。
///
/// 参数说明：
/// - `state`：已通过Cluster/Read鉴权的完整管理入口。
///
/// 返回：当前200快照或202明确等待状态，读取本身不发起逐节点查询。
pub(in crate::admin) fn read(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load_full();
    let publication = match current(state, &snapshot) {
        Ok(publication) => publication,
        Err(reason) => return pending(reason),
    };
    super::response(
        StatusCode::OK,
        publication.document.clone(),
        publication.age_ms(),
    )
}

/// 业务作用：向领域聚合共享同一成员事实，浏览器查询不额外触发发现和逐节点外呼。
///
/// 参数说明：
/// - `state`：进程共享的目录协调器。
/// - `snapshot`：调用方完成鉴权时冻结的配置代。
///
/// 返回：当前完整成员集合；关闭、未采样或配置变化只返回固定等待原因。
pub(in crate::admin) fn current(
    state: &AdminState,
    snapshot: &Arc<GatewaySnapshot>,
) -> Result<Arc<Publication>, &'static str> {
    let runtime = &state.cluster;
    if !enabled(snapshot) {
        runtime.latest.store(None);
        return Err("disabled");
    }
    runtime
        .interest
        .store(runtime.elapsed().saturating_add(1), Ordering::Release);
    let publication = runtime.latest.load_full().filter(|value| {
        value.at.elapsed() <= PERIOD * 3
            && Instant::now() <= value.valid_until
            && value
                .snapshot
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, snapshot))
    });
    let Some(publication) = publication else {
        runtime.wake.notify_one();
        return Err("sampling");
    };
    Ok(publication)
}

/// 业务作用：只派生本机明确授权的远端只读凭据，不能转发观察者凭据或借匿名管理扩大内网访问。
///
/// 参数说明：
/// - `snapshot`：同一配置代的认证与成员计划。
///
/// 返回：可用于固定节点事实路径的凭据，未授权时为空。
fn credential(snapshot: &GatewaySnapshot) -> Option<String> {
    (snapshot.admin_auth.enabled && snapshot.admin_auth.allow_cluster_metrics_scrape)
        .then(|| crate::admin::cluster_scrape_auth_header(&snapshot.admin_auth))
        .flatten()
}

/// 业务作用：分别检查HTTP主动读取和独立管理接收权，不让监控或抓取开关禁用已授权上报。
///
/// 参数说明：
/// - `snapshot`：当前完整授权快照。
///
/// 返回：至少一种明确授权的节点事实来源可用时为true。
fn enabled(snapshot: &GatewaySnapshot) -> bool {
    #[cfg(feature = "admin-grpc")]
    if snapshot.admin_auth.enabled
        && snapshot
            .admin_management
            .as_ref()
            .is_some_and(|plan| plan.receiver.is_some())
    {
        return true;
    }
    credential(snapshot).is_some()
}

/// 业务作用：把管理通道的授权成员转为节点行，未上报节点仍占据完整覆盖分母。
///
/// 参数说明：
/// - `state`：进程管理状态及接收槽。
/// - `snapshot`：与本轮页面目录一致的授权计划。
///
/// 返回：仅当前管理成员的有界清单，未启用管理通信时为空。
#[cfg(feature = "admin-grpc")]
fn reported(state: &AdminState, snapshot: &GatewaySnapshot) -> Vec<Node> {
    snapshot
        .admin_management
        .as_ref()
        .map(|plan| state.management.observations(plan))
        .unwrap_or_default()
        .into_iter()
        .map(|observation| Node {
            address: format!("gRPC / {}", observation.id),
            id: observation.id,
            availability: observation.availability,
            source_age_ms: None,
            facts: observation.facts,
            at: observation.at,
            catalog: observation.catalog,
            action_baseline: observation.action_baseline,
        })
        .collect()
}

/// 业务作用：明确表达尚无当前集群事实，防止把空目录解释为健康的零节点集群。
///
/// 参数说明：
/// - `reason`：固定的关闭或采样状态。
///
/// 返回：无历史实体的202响应。
fn pending(reason: &'static str) -> Response<BoxBody> {
    let value = serde_json::json!({
        "schema_version": 1, "scope": "cluster", "availability": reason, "sampling_period_ms": 2000
    });
    super::response(
        StatusCode::ACCEPTED,
        serde_json::to_vec(&value)
            .expect("fixed cluster state serializes")
            .into(),
        0,
    )
}

/// 业务作用：串行收集同代成员事实，观察停止后释放目录及结果，个别坏节点不阻塞其它成员。
///
/// 参数说明：
/// - `owner`：不延长管理入口生命周期的弱引用。
/// - `wake`：所有观察者共用的首次查询唤醒器。
///
/// 返回：管理状态释放后结束；每轮最多八个在途固定只读请求。
async fn run(owner: Weak<AdminState>, wake: Arc<Notify>) {
    let mut next = tokio::time::Instant::now();
    let mut generation = Weak::<GatewaySnapshot>::new();
    let mut cache = directory::Cache::default();
    let mut sequence = 0u64;
    loop {
        let scheduled = tokio::select! {
            _ = tokio::time::sleep_until(next) => true,
            _ = wake.notified() => false,
        };
        let Some(state) = owner.upgrade() else {
            return;
        };
        let runtime = &state.cluster;
        let snapshot = state.snap.load_full();
        let interest = runtime.interest.load(Ordering::Acquire);
        let authorization = credential(&snapshot);
        if scheduled {
            next = tokio::time::Instant::now() + Duration::from_secs(1);
        }
        if interest == 0
            || runtime.elapsed().saturating_sub(interest) > 12_000
            || !enabled(&snapshot)
        {
            runtime.latest.store(None);
            cache = directory::Cache::default();
            generation = Weak::new();
            continue;
        }
        let same = generation
            .upgrade()
            .is_some_and(|old| Arc::ptr_eq(&old, &snapshot));
        if !same {
            // 权限或成员代改变后旧目录不再具有本轮权威，必须先撤销再重新建立。
            cache = directory::Cache::default();
            runtime.latest.store(None);
        } else if !scheduled && runtime.latest.load().is_some() {
            continue;
        }
        generation = Arc::downgrade(&snapshot);
        next = tokio::time::Instant::now() + PERIOD;
        let mut members = if authorization.is_some() {
            directory::read(&state.member_discovery, &snapshot, &mut cache).await
        } else {
            directory::Members::empty()
        };
        #[cfg(feature = "admin-grpc")]
        let reported = reported(&state, &snapshot);
        #[cfg(not(feature = "admin-grpc"))]
        let reported = Vec::<Node>::new();
        let reported_ids: BTreeSet<_> = reported.iter().map(|node| node.id.as_str()).collect();
        // 显式管理成员由上报槽提供当前权威，失败时不能改用HTTP读面掩盖身份冲突或失联。
        members
            .peers
            .retain(|peer| !reported_ids.contains(peer.id.as_str()));
        if members.peers.len() + reported.len() > 127 {
            members.peers.truncate(127 - reported.len());
            members.truncated = true;
        }
        let at = Instant::now();
        let deadline = tokio::time::Instant::now() + PERIOD;
        let declared = members.peers.len() + reported.len() + 1;
        let local_only =
            members.peers.is_empty() && reported.is_empty() && !members.discovery_enabled;
        let local = facts::collect(&state, &snapshot);
        let local_id = local.node_id.clone().unwrap_or_else(|| "local".into());
        let mut boots = BTreeSet::from([local.boot_id.clone()]);
        let mut nodes = vec![Node {
            id: local_id,
            address: snapshot.admin_listen.to_string(),
            availability: if local.ready {
                "available"
            } else {
                "not_ready"
            },
            source_age_ms: Some(0),
            facts: Some(Arc::new(local)),
            at: Some(at),
            catalog: Some(state.catalog.local(&snapshot)),
            action_baseline: super::baseline::collect(&state, &snapshot).await,
        }];
        for node in &reported {
            if let Some(facts) = &node.facts {
                boots.insert(facts.boot_id.clone());
            }
        }
        nodes.extend(reported);
        let count = members.peers.len();
        if count > 0 {
            members.peers.rotate_left(sequence as usize % count);
        }
        let authorization = authorization.unwrap_or_default();
        let mut pending: BTreeMap<_, _> = members
            .peers
            .iter()
            .map(|peer| (peer.address, peer.id.clone()))
            .collect();
        let futures = std::mem::take(&mut members.peers).into_iter().map(|peer| {
            let state = &state;
            let snapshot = &snapshot;
            let authorization = &authorization;
            async move {
                // 取得查询槽后再次验证当前配置，撤权不能继续打开尚未开始的连接。
                let value = if Arc::ptr_eq(&state.snap.load_full(), snapshot) {
                    facts::fetch(peer.address, authorization).await
                } else {
                    Err("configuration_changed")
                };
                (peer, value)
            }
        });
        let mut work = stream::iter(futures).buffer_unordered(8);
        while let Ok(Some((peer, result))) = tokio::time::timeout_at(deadline, work.next()).await {
            pending.remove(&peer.address);
            if let Some(node) = node_result(peer.id, peer.address.to_string(), result, &mut boots) {
                nodes.push(node);
            }
        }
        // 整轮期限用尽时取消剩余连接；保留未观察成员的行，不能通过缩小分母得到完整成功。
        drop(work);
        for (address, id) in pending {
            nodes.push(
                node_result(id, address.to_string(), Err("budget_exhausted"), &mut boots)
                    .expect("failed node is retained"),
            );
        }
        if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
            // 结果发布是权限边界，外呼成功也不能越过已撤销的目录或认证代。
            runtime.latest.store(None);
            continue;
        }
        sequence = sequence.saturating_add(1);
        let valid_until = nodes.iter().filter_map(|node| node.at).min().unwrap_or(at) + PERIOD * 3;
        let encoded = encode(nodes, &members, declared, local_only, &snapshot, sequence);
        runtime
            .latest
            .store(encoded.map(|(document, nodes, coverage)| {
                Arc::new(Publication {
                    document,
                    at,
                    valid_until,
                    snapshot: Arc::downgrade(&snapshot),
                    nodes: nodes.into(),
                    coverage,
                })
            }));
        if next < tokio::time::Instant::now() {
            next = tokio::time::Instant::now() + PERIOD;
        }
    }
}

/// 业务作用：保留成功与失败成员的逐节点证据，同一启动实例的多个入口只计一次。
///
/// 参数说明：
/// - `id`：服务器目录声明的有限成员标识。
/// - `address`：已冻结的管理地址。
/// - `result`：固定事实读面结果。
/// - `boots`：本轮已经计数的进程启动身份。
///
/// 返回：唯一节点事实或失败行；重复进程返回None。
fn node_result(
    id: String,
    address: String,
    result: Result<(facts::Facts, Instant), &'static str>,
    boots: &mut BTreeSet<String>,
) -> Option<Node> {
    let (facts, at, availability) = match result {
        Ok((facts, at)) => {
            if !boots.insert(facts.boot_id.clone()) {
                return None;
            }
            let availability = if facts.ready {
                "available"
            } else {
                "not_ready"
            };
            (Some(Arc::new(facts)), Some(at), availability)
        }
        Err(reason) => (None, None, reason),
    };
    Some(Node {
        id,
        address,
        availability,
        source_age_ms: None,
        facts,
        at,
        catalog: None,
        action_baseline: super::baseline::Observation::unsupported(),
    })
}

/// 业务作用：发布有限节点清单与明确覆盖，不对节点专属配置指纹推断未经声明的全局版本。
///
/// 参数说明：
/// - `nodes`：本轮完整逐节点证据。
/// - `members`：有限目录及其失败标识。
/// - `declared`：去除进程别名前的声明目标数量。
/// - `local_only`：是否仅有未声明远端成员的接入节点。
/// - `snapshot`：授权本轮查询的配置代。
/// - `sequence`：当前入口的递增观察序号。
///
/// 返回：只编码一次的当前结果；超出输出硬门时不发布半个清单。
fn encode(
    mut nodes: Vec<Node>,
    members: &directory::Members,
    declared: usize,
    local_only: bool,
    snapshot: &GatewaySnapshot,
    sequence: u64,
) -> Option<(Bytes, Vec<Node>, Coverage)> {
    let mut identities = BTreeMap::new();
    let mut boots = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for node in &nodes {
        if let Some(facts) = &node.facts {
            if let Some(id) = &facts.node_id {
                if let Some(previous) = boots.insert(facts.boot_id.clone(), id.clone()) {
                    if previous != *id {
                        // 启动身份必须唯一；多个显式成员声称同一进程时保留冲突，不能重复累计对象。
                        conflicts.insert(previous);
                        conflicts.insert(id.clone());
                    }
                }
                if identities
                    .insert(id.clone(), facts.boot_id.clone())
                    .is_some_and(|old| old != facts.boot_id)
                {
                    conflicts.insert(id.clone());
                }
            }
        }
    }
    let mut reachable = 0;
    let mut ready = 0;
    let mut data = 0;
    let mut control = 0;
    for node in &mut nodes {
        node.source_age_ms = node.at.map(|at| at.elapsed().as_millis() as u64);
        if let Some(facts) = &node.facts {
            reachable += 1;
            ready += usize::from(facts.ready);
            control += usize::from(facts.mode == "admin");
            data += usize::from(facts.mode != "admin");
            if facts
                .node_id
                .as_ref()
                .is_some_and(|id| conflicts.contains(id))
            {
                node.availability = "identity_conflict";
                node.action_baseline.withdraw("identity_conflict");
            }
        }
    }
    nodes.sort_by(|a, b| (&a.id, &a.address).cmp(&(&b.id, &b.address)));
    let conflict = members.conflicting_ids
        || !conflicts.is_empty()
        || nodes
            .iter()
            .any(|node| node.availability == "identity_conflict");
    let capacity = members.truncated || nodes.iter().any(|node| node.availability == "capacity");
    let availability = if capacity {
        "capacity"
    } else if reachable < nodes.len() || conflict || !members.discovery_available || local_only {
        "partial"
    } else if ready < nodes.len() {
        "not_ready"
    } else if data == 0 {
        "no_data_nodes"
    } else {
        "available"
    };
    let value = View {
        schema_version: 1,
        scope: "cluster",
        sample_id: sequence,
        sampled_at_ms: crate::admin::unix_now_ms(),
        sampling_period_ms: 2000,
        directory_version: snapshot.version,
        directory_fingerprint: snapshot
            .config_fingerprint
            .map(|value| format!("{value:016x}")),
        availability,
        coverage: Coverage {
            total: nodes.len(),
            declared_targets: declared,
            reachable,
            ready,
            unknown: nodes.len() - reachable,
            data_nodes: data,
            control_nodes: control,
            conflicting_ids: conflict,
            truncated: members.truncated,
            discovery_enabled: members.discovery_enabled,
            discovery_available: members.discovery_available,
            directory_stale: members.stale,
            limited_to_local: local_only,
        },
        nodes: &nodes,
    };
    let document = serde_json::to_vec(&value).ok()?;
    let coverage = value.coverage.clone();
    (document.len() <= 1024 * 1024).then(|| (document.into(), nodes, coverage))
}
