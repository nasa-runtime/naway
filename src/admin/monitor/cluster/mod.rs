//! 单一集群观察协调器，有限并发读取当前成员且只保留相邻成功基线。

pub(super) mod aggregate;
mod push;
mod remote;

use super::routes;
use super::{model, AdminState, BoxBody};
use crate::admin::cluster::directory as members;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use futures::{stream, StreamExt};
use http::{Response, StatusCode};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;

const BASELINE_LIMIT: usize = 8 * 1024 * 1024;

pub(super) struct Runtime {
    last_interest: AtomicU64,
    wake: Arc<Notify>,
    latest: ArcSwapOption<Publication>,
    task: OnceLock<AbortOnDropHandle<()>>,
}

struct Publication {
    document: Bytes,
    at: Instant,
    snapshot: Weak<crate::config::GatewaySnapshot>,
    routes: routes::Publication,
}

struct Baseline {
    sample: Arc<model::Sample>,
    previous: Option<Arc<model::Sample>>,
    bytes: usize,
    observed: Instant,
}

#[derive(Default)]
struct Round {
    baselines: BTreeMap<String, Baseline>,
    retained: usize,
    aggregate: aggregate::Aggregate,
    controls: aggregate::Aggregate,
    nodes: Vec<serde_json::Value>,
    boots: HashSet<String>,
    seen: HashSet<String>,
    reachable: usize,
    valid: usize,
    data_nodes: usize,
    control_nodes: usize,
    unclassified_nodes: usize,
    capacity: bool,
    routes: Vec<routes::Node>,
}

impl Runtime {
    /// 业务作用：建立无历史的集群采样槽，构造阶段不发现成员或打开连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空采样状态，等待已授权观察者产生兴趣。
    pub(super) fn new() -> Self {
        Self {
            last_interest: AtomicU64::new(0),
            wake: Arc::new(Notify::new()),
            latest: ArcSwapOption::empty(),
            task: OnceLock::new(),
        }
    }
}

/// 业务作用：使所有管理监听器共用唯一集群协调器，避免每页面或每监听代重复外连。
///
/// 参数说明：
/// - `state`：管理运行态，后台等待期间仅保留弱引用。
///
/// 返回：首次调用启动任务，状态销毁时自动终止。
pub(super) fn start(state: &Arc<AdminState>) {
    state.monitor.cluster.task.get_or_init(|| {
        AbortOnDropHandle::new(tokio::spawn(run(
            Arc::downgrade(state),
            state.monitor.cluster.wake.clone(),
        )))
    });
}

/// 业务作用：读取共享集群结果，并用当前配置身份拒绝撤权前或目标更换前的迟到数据。
///
/// 参数说明：
/// - `state`：已完成请求认证的当前管理状态。
///
/// 返回：当前快照或明确关闭、采样中状态；无逐请求远端调用。
pub(super) fn read(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load_full();
    let runtime = &state.monitor.cluster;
    if !enabled(&snapshot) {
        runtime.latest.store(None);
        return super::pending("disabled", snapshot.admin_monitor.period);
    }
    runtime.last_interest.store(
        state.monitor.elapsed_ms().saturating_add(1),
        Ordering::Release,
    );
    #[cfg(feature = "admin-grpc")]
    if push::enabled(&snapshot) {
        state.management.observe_metrics(&snapshot);
    }
    let publication = runtime.latest.load_full().filter(|value| {
        value.at.elapsed() <= snapshot.admin_monitor.period * 3
            && value
                .snapshot
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, &snapshot))
    });
    let Some(publication) = publication else {
        runtime.wake.notify_one();
        return super::pending("sampling", snapshot.admin_monitor.period);
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header(
            "x-naway-sample-age-ms",
            publication.at.elapsed().as_millis().to_string(),
        )
        .body(crate::full_body(publication.document.clone()))
        .expect("fixed monitor response headers")
}

/// 业务作用：串行执行有观察兴趣的聚合轮次，权限代变化或空闲后销毁基线。
///
/// 参数说明：
/// - `owner`：不延长管理状态寿命的弱引用。
/// - `wake`：多观察者共用的唤醒器。
///
/// 返回：状态销毁时结束；一轮最多八条在途连接，不建立历史存储。
async fn run(owner: Weak<AdminState>, wake: Arc<Notify>) {
    let mut next = tokio::time::Instant::now();
    let mut baseline_snapshot = Weak::<crate::config::GatewaySnapshot>::new();
    let mut round = Round::default();
    let mut member_cache = members::Cache::default();
    let mut sequence = 0u64;
    loop {
        let scheduled = tokio::select! {
            _ = tokio::time::sleep_until(next) => true,
            _ = wake.notified() => false,
        };
        let Some(state) = owner.upgrade() else {
            return;
        };
        let snapshot = state.snap.load_full();
        let runtime = &state.monitor.cluster;
        let period = snapshot.admin_monitor.period;
        if scheduled {
            next = tokio::time::Instant::now() + Duration::from_secs(1);
        }
        let interest = runtime.last_interest.load(Ordering::Acquire);
        let credential = snapshot
            .admin_auth
            .allow_cluster_metrics_scrape
            .then(|| crate::admin::cluster_scrape_auth_header(&snapshot.admin_auth))
            .flatten();
        if !snapshot.admin_monitor.enabled
            || !enabled(&snapshot)
            || interest == 0
            || state.monitor.elapsed_ms().saturating_sub(interest)
                > super::IDLE_MS.max(period.as_millis() as u64 * 3)
        {
            round = Round::default();
            member_cache = members::Cache::default();
            baseline_snapshot = Weak::new();
            runtime.latest.store(None);
            continue;
        }
        let same = baseline_snapshot
            .upgrade()
            .is_some_and(|old| Arc::ptr_eq(&old, &snapshot));
        if !same {
            // 权限、凭据或成员配置发生变化后不跨代保留差值，所有结果必须从新权威重新建立。
            round = Round::default();
            member_cache = members::Cache::default();
            runtime.latest.store(None);
        } else if !scheduled && runtime.latest.load().is_some() {
            continue;
        }
        baseline_snapshot = Arc::downgrade(&snapshot);
        next = tokio::time::Instant::now() + period;
        state.monitor.touch();
        let mut members = if credential.is_some() {
            members::read(&state.member_discovery, &snapshot, &mut member_cache).await
        } else {
            members::Members::empty()
        };
        let reported = push::read(&state, &snapshot);
        let reported_ids: HashSet<_> = reported.iter().map(|peer| peer.id.as_str()).collect();
        // 显式推送成员只能由当前上报证明，HTTP成功不得掩盖失联、撤权或陈旧指标。
        members
            .peers
            .retain(|peer| !reported_ids.contains(peer.id.as_str()));
        if members.peers.len() + reported.len() > 127 {
            members.peers.truncate(127 - reported.len());
            members.truncated = true;
        }
        let limited_to_local =
            members.peers.is_empty() && reported.is_empty() && !members.discovery_enabled;
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + period;
        let peer_count = members.peers.len();
        if peer_count > 0 {
            members
                .peers
                .rotate_left((sequence as usize * 8) % peer_count);
        }
        let mut pending: BTreeMap<_, _> = members
            .peers
            .iter()
            .map(|peer| (format!("{}\0{}", peer.id, peer.address), peer.id.clone()))
            .collect();
        round.begin();
        let local = state
            .monitor
            .latest
            .load_full()
            .filter(|value| {
                value.at.elapsed() <= period * 3
                    && value.sample.state.config_version == snapshot.version
                    && value.sample.state.config_fingerprint
                        == snapshot
                            .config_fingerprint
                            .map(|value| format!("{value:016x}"))
            })
            .map(|value| (value.sample.clone(), value.at))
            .ok_or("sampling");
        round.accept_source(
            "local".into(),
            push::local_id(&snapshot),
            local,
            period,
            "local",
        );
        for peer in reported {
            round.accept_source(
                format!("grpc\0{}", peer.id),
                &peer.id,
                peer.result,
                period,
                "grpc",
            );
        }
        let futures = members.peers.into_iter().map(|peer| {
            let authorization = &credential;
            let snapshot = &snapshot;
            let state = &state;
            async move {
                // 每个排队目标在取得并发槽后复验权威，撤权后尚未发出的连接不得继续开始。
                let result = if Arc::ptr_eq(&state.snap.load_full(), snapshot) {
                    if let Some(authorization) = authorization {
                        remote::fetch(peer.address, authorization).await
                    } else {
                        Err("disabled")
                    }
                } else {
                    Err("configuration_changed")
                };
                (peer, result)
            }
        });
        let mut work = stream::iter(futures).buffer_unordered(8);
        while let Ok(Some((peer, result))) = tokio::time::timeout_at(deadline, work.next()).await {
            let key = format!("{}\0{}", peer.id, peer.address);
            pending.remove(&key);
            round.accept_source(key, &peer.id, result, period, "http");
        }
        // 总预算耗尽时销毁未完成连接；下一轮轮转优先级，不能让坏节点永久占据前排。
        drop(work);
        for (key, id) in pending {
            round.accept_source(key, &id, Err("budget_exhausted"), period, "http");
        }
        round.finish();
        // 外连完成后再次核对整份快照身份，禁止旧凭据取得的数据跨越原子权限发布。
        if !Arc::ptr_eq(&state.snap.load_full(), &snapshot) {
            round = Round::default();
            runtime.latest.store(None);
            continue;
        }
        sequence = sequence.saturating_add(1);
        let total = round.nodes.len();
        let data_total = round.data_nodes + round.unclassified_nodes;
        let points = round.aggregate.points(data_total);
        let control_points = round.controls.points(round.control_nodes);
        let capacity = members.truncated
            || round.capacity
            || round.aggregate.capacity
            || round.controls.capacity;
        let availability = if capacity {
            "capacity"
        } else if round.reachable == 0 {
            "unavailable"
        } else if data_total == 0 {
            "no_data_nodes"
        } else if round.valid == total
            && members.discovery_available
            && !members.conflicting_ids
            && !limited_to_local
        {
            "available"
        } else if round.valid == 0
            && round.reachable == total
            && members.discovery_available
            && !members.conflicting_ids
        {
            "sampling"
        } else {
            "partial"
        };
        let document = super::encode(&serde_json::json!({
            "schema_version": 1,
            "boot_id": state.monitor.boot_id,
            "scope": "cluster",
            "sample_id": sequence,
            "sampled_at_ms": super::unix_millis(),
            "sampling_period_ms": period.as_millis(),
            "interval_ms": null,
            "availability": availability,
            "coverage": { "total": total, "reachable": round.reachable, "valid": round.valid, "unknown": total - round.valid,
                "truncated": members.truncated, "discovery_available": members.discovery_available,
                "discovery_enabled": members.discovery_enabled, "directory_stale": members.stale,
                "conflicting_ids": members.conflicting_ids, "limited_to_local": limited_to_local,
                "data_nodes": round.data_nodes, "control_nodes": round.control_nodes,
                "unclassified_nodes": round.unclassified_nodes,
                "baseline_bytes": round.retained, "baseline_limit_bytes": BASELINE_LIMIT },
            "summary": super::summary(&points),
            "control_summary": super::summary(&control_points),
            "latency": round.aggregate.latency(data_total),
            "metrics": points,
            "control_metrics": control_points,
            "nodes": round.nodes,
        }));
        runtime.latest.store(document.map(|document| {
            Arc::new(Publication {
                document,
                at: started,
                snapshot: Arc::downgrade(&snapshot),
                routes: routes::Publication {
                    nodes: std::mem::take(&mut round.routes).into(),
                    total,
                    sequence,
                    at: started,
                    complete_directory: !members.truncated
                        && members.discovery_available
                        && !members.conflicting_ids
                        && !members.stale
                        && !limited_to_local,
                },
            })
        }));
        if next < tokio::time::Instant::now() {
            next = tokio::time::Instant::now() + period;
        }
    }
}

impl Round {
    /// 业务作用：标注每个当前节点的实际指标来源，故障时仍保留期望通道而不隐藏回退。
    ///
    /// 参数说明：
    /// - `key`：基线成员身份。
    /// - `id`：公开节点标识。
    /// - `result`：共享样本或明确缺口。
    /// - `period`：当前聚合周期。
    /// - `source`：固定本机、HTTP或gRPC来源。
    ///
    /// 返回：更新节点行与聚合；同boot别名仍由公共接收逻辑去重。
    fn accept_source(
        &mut self,
        key: String,
        id: &str,
        result: Result<(Arc<model::Sample>, Instant), &'static str>,
        period: Duration,
        source: &'static str,
    ) {
        let before = self.nodes.len();
        self.accept(key, id, result, period);
        if self.nodes.len() > before {
            self.nodes.last_mut().expect("accepted node row")["source"] = source.into();
        }
    }
    /// 业务作用：释放上一轮派生读面，只保留有限累计基线用于下一次差值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前结果清空，基线和容量账目保持一致。
    fn begin(&mut self) {
        self.aggregate = aggregate::Aggregate::default();
        self.controls = aggregate::Aggregate::default();
        self.nodes.clear();
        self.boots.clear();
        self.seen.clear();
        self.reachable = 0;
        self.valid = 0;
        self.data_nodes = 0;
        self.control_nodes = 0;
        self.unclassified_nodes = 0;
        self.capacity = false;
        self.routes.clear();
    }

    /// 业务作用：接收一个节点的完整事实并更新唯一基线，失败、重复或容量不足不生成假速率。
    ///
    /// 参数说明：
    /// - `key`：稳定成员与管理地址的组合身份。
    /// - `id`：页面显示的有限节点标识。
    /// - `result`：当前抓取结果。
    /// - `period`：协调器有效采样周期。
    ///
    /// 返回：更新当前节点摘要与预算；同进程多个地址仅计算一次。
    fn accept(
        &mut self,
        key: String,
        id: &str,
        result: Result<(Arc<model::Sample>, Instant), &'static str>,
        period: Duration,
    ) {
        let old = self.baselines.remove(&key);
        if let Some(old) = &old {
            self.retained = self.retained.saturating_sub(old.bytes);
        }
        let (sample, sampled) = match result {
            Ok(sample) => sample,
            Err(reason) => {
                self.routes.push(routes::Node::missing(id, reason));
                self.unclassified_nodes += 1;
                self.capacity |= reason == "capacity";
                self.nodes.push(serde_json::json!({
                    "id": id, "availability": reason
                }));
                return;
            }
        };
        if sampled.elapsed() > Duration::from_millis(sample.sampling_period_ms) * 3 {
            self.routes.push(routes::Node::missing(id, "stale"));
            self.unclassified_nodes += 1;
            self.nodes.push(serde_json::json!({
                "id": id, "availability": "stale"
            }));
            return;
        }
        if !self.boots.insert(sample.boot_id.clone()) {
            return;
        }
        self.reachable += 1;
        let control_only = sample.state.mode == "admin";
        self.control_nodes += usize::from(control_only);
        self.data_nodes += usize::from(!control_only);
        let repeated = old.as_ref().is_some_and(|old| {
            old.sample.boot_id == sample.boot_id && old.sample.sample_id == sample.sample_id
        });
        // 当前年龄与采样差分别受三周期限制，旧基线总回看允许两者之和，兼容异步上传。
        let previous = old
            .as_ref()
            .filter(|old| {
                old.observed.elapsed()
                    <= period.max(Duration::from_millis(sample.sampling_period_ms)) * 6
            })
            .and_then(|old| {
                if repeated {
                    old.previous.clone()
                } else {
                    Some(old.sample.clone())
                }
            })
            .filter(|old| {
                model::interval_with_period(&sample, Some(old), period.as_millis() as u64).is_some()
            });
        let bytes =
            model::retained_bytes(&sample) + previous.as_deref().map_or(0, model::retained_bytes);
        if bytes > BASELINE_LIMIT.saturating_sub(self.retained) {
            self.routes.push(routes::Node::missing(id, "capacity"));
            self.capacity = true;
            self.nodes.push(serde_json::json!({
                "id":id,"availability":"capacity"
            }));
            return;
        }
        let previous_ref = previous.as_deref();
        let elapsed = model::interval_with_period(&sample, previous_ref, period.as_millis() as u64);
        let points = model::points_with_period(&sample, previous_ref, period.as_millis() as u64);
        let latency = model::latency(
            &sample.latency,
            previous_ref
                .filter(|_| elapsed.is_some())
                .map(|old| &old.latency),
        );
        self.valid += usize::from(elapsed.is_some());
        self.routes.push(routes::Node {
            id: id.into(),
            availability: "available",
            sample: Some(sample.clone()),
            previous: previous.clone(),
            interval_ms: elapsed,
            at: sampled,
        });
        // 纯管理进程不承载业务，不能把其零流量、资源或时延计入数据节点覆盖和业务汇总。
        if control_only {
            self.controls.add(&points, &latency, elapsed);
        } else {
            self.aggregate.add(&points, &latency, elapsed);
        }
        self.nodes.push(serde_json::json!({
            "id": id, "availability": if elapsed.is_some() {
                "available"
            } else {
                "sampling"
            },
            "sample_id": sample.sample_id, "interval_ms": elapsed,
            "sample_age_ms": sampled.elapsed().as_millis(),
            "sampling_period_ms": sample.sampling_period_ms, "state": sample.state,
            "summary": super::summary(&points), "latency": latency,
        }));
        self.seen.insert(key.clone());
        // 重复读取只复用原区间，不能刷新当前样本时刻；同代两个实体一起进入基线容量门。
        let observed = if repeated {
            old.as_ref().expect("matching baseline").observed
        } else {
            sampled
        };
        let baseline = Baseline {
            sample,
            previous,
            bytes,
            observed,
        };
        self.retained += baseline.bytes;
        self.baselines.insert(key, baseline);
    }

    /// 业务作用：丢弃已离开目录或本轮失败节点的基线，恢复后必须重新取样。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：保留字节数与当前有效成员完全一致，节点顺序稳定。
    fn finish(&mut self) {
        self.baselines.retain(|key, _| self.seen.contains(key));
        self.retained = self.baselines.values().map(|value| value.bytes).sum();
        self.nodes
            .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    }
}

/// 业务作用：统一检查当前实时读取能力，独立推送开关不依赖HTTP抓取凭据。
///
/// 参数说明：
/// - `snapshot`：当前完整配置。
///
/// 返回：监控与任一明确授权来源同时开启时为true。
pub(super) fn enabled(snapshot: &crate::config::GatewaySnapshot) -> bool {
    snapshot.admin_monitor.enabled
        && (push::enabled(snapshot)
            || (snapshot.admin_auth.enabled
                && snapshot.admin_auth.allow_cluster_metrics_scrape
                && crate::admin::cluster_scrape_auth_header(&snapshot.admin_auth).is_some()))
}

/// 业务作用：为路由、服务与工作区读取复用同一集群观察轮次，保留原生实体而不反解析HTTP文档。
///
/// 参数说明：
/// - `state`：当前已认证管理状态。
/// - `snapshot`：调用方判权冻结的同代配置。
///
/// 返回：同代且未过期的共享对象事实；未建立时唤醒原协调器并返回明确采样状态。
pub(super) fn object_sample(
    state: &AdminState,
    snapshot: &Arc<crate::config::GatewaySnapshot>,
) -> Result<routes::Publication, &'static str> {
    if !enabled(snapshot) {
        return Err("disabled");
    }
    let runtime = &state.monitor.cluster;
    runtime.last_interest.store(
        state.monitor.elapsed_ms().saturating_add(1),
        Ordering::Release,
    );
    #[cfg(feature = "admin-grpc")]
    if push::enabled(snapshot) {
        state.management.observe_metrics(snapshot);
    }
    let Some(value) = runtime.latest.load_full().filter(|value| {
        value.at.elapsed() <= snapshot.admin_monitor.period * 3
            && value
                .snapshot
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, snapshot))
    }) else {
        runtime.wake.notify_one();
        return Err("sampling");
    };
    Ok(value.routes.clone())
}
