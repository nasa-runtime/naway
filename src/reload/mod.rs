//! 无感热重载(架构规范 §7)。
//!
//! 两个触发通道(R1):① `notify` 监听配置**目录**(编辑器写临时文件+rename 会丢 inode 事件)+ 防抖;
//! ② `SIGHUP` 信号(`kill -HUP <pid>` 或 `naway -s reload`)。
//! 都汇入唯一的 reload worker:事务化 build 新快照 → `ArcSwap` 原子换版;坏配置保留旧快照,在线流量零影响。

use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex, MutexGuard};

use crate::blacklist::BlacklistCache;
use crate::config::model::{NacosConfigSourceCfg, ReloadCfg};
use crate::config::{
    config_fingerprint, load_gateway_config, load_snapshot_with_dynamic, resolve_relative,
    GatewaySnapshot,
};
use crate::config_history::ConfigHistory;
use crate::conn_registry::ConnectionRegistry;
use crate::discovery::NacosDiscoveryManager;
use crate::runtime_state::{
    build_circuit_stats, build_conn_limiter, build_dynamic_store, build_rate_limiter,
    build_replay_guard, circuit_stats_config_signature, dynamic_store_config_signature,
    rate_limiter_config_signature, replay_guard_config_signature, SwappableCircuitStats,
    SwappableConnLimiter, SwappableDynamicStore, SwappableRateLimiter, SwappableReplayGuard,
};
use crate::upstream::DynamicUpstreamStore;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReloadEvent {
    File,
    Dependency,
    Sighup,
    Nacos { cfg_path: PathBuf },
}

/// 其它控制面 worker 向唯一 reload worker 提交候选变更的窄接口。
///
/// 句柄不暴露事件枚举，也不能直接替换快照；Kubernetes controller 等生产者只能声明
/// “本地物化文件已更新”，随后仍经过 fingerprint、完整构建、审计和 ArcSwap 事务。
#[derive(Clone)]
pub struct ReloadHandle {
    tx: mpsc::Sender<ReloadEvent>,
}

/// listener 异步 prepare 的 Future；返回事务在 commit 或失败 Drop 前独占全部候选 socket。
pub type PreparedListenerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn PreparedListenerTopology>>> + Send + 'a>>;

/// 数据面 listener 两阶段切换器。`prepare` 必须只绑定/构建新资源，不停旧 accept；返回成功后
/// reload worker 才发布快照，随后调用 `commit` 启动新 accept 并停止旧 listener。
pub trait ListenerTopologyReconciler: Send + Sync {
    /// 业务作用：绑定并验证候选快照需要的全部 listener/worker 资源，同时保持在线 acceptor 不变。
    ///
    /// 参数说明：`candidate` 是已通过完整配置构建、尚未发布的候选快照。
    ///
    /// 返回：成功返回持有候选资源的事务；错误会中止 reload，Drop 事务只释放候选资源。
    fn prepare<'a>(&'a self, candidate: &'a GatewaySnapshot) -> PreparedListenerFuture<'a>;
}

/// 已成功绑定、尚未发布的 listener 拓扑事务。未 commit 即 Drop 会关闭新 socket，旧 listener
/// 完全不受影响；commit 本身只做不可失败的 task/stop-channel 交接。
pub trait PreparedListenerTopology: Send {
    /// 业务作用：在快照发布后执行不可失败的 generation 交接，先启动候选再停止旧代新增工作。
    ///
    /// 参数说明：无；事务自身持有 prepare 完成的全部资源。
    ///
    /// 返回：无返回值；消费事务后，候选成为 active，旧连接按既有 drain 规则存续。
    fn commit(self: Box<Self>);
}

impl ReloadHandle {
    /// 通知唯一 worker 重新校验本地候选文件。队列有界，背压时异步等待而不丢最终状态。
    pub async fn trigger_file(&self) -> bool {
        self.tx.send(ReloadEvent::File).await.is_ok()
    }
}

impl ReloadEvent {
    fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dependency => "dependency-file",
            Self::Sighup => "SIGHUP",
            Self::Nacos { .. } => "nacos-config",
        }
    }

    fn cfg_path(&self, local_cfg_path: &Path) -> PathBuf {
        match self {
            Self::File | Self::Dependency | Self::Sighup => local_cfg_path.to_path_buf(),
            Self::Nacos { cfg_path } => cfg_path.clone(),
        }
    }
}

/// file/Nacos 与 xDS 共用的进程级 Snapshot 发布串行器。
#[derive(Default)]
pub struct SnapshotApplyCoordinator {
    gate: Mutex<()>,
}

impl SnapshotApplyCoordinator {
    /// 业务作用：取得唯一快照写权，保证版本分配、候选构建和 ArcSwap 发布不能被另一控制面穿插。
    ///
    /// 参数说明：无。
    ///
    /// 返回：持有期间调用方是唯一 Snapshot writer；guard 释放后下一候选才能开始提交。
    pub async fn lock(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().await
    }
}

#[derive(Clone)]
/// reload 成功后需要 reconcile/换代的常驻运行态句柄集。
pub struct ReloadRuntime {
    /// file/Nacos/xDS 共享的唯一快照发布权威。
    pub apply_coordinator: Arc<SnapshotApplyCoordinator>,
    /// Nacos watch 写入的动态上游事实源。
    pub dynamic_upstreams: Arc<DynamicUpstreamStore>,
    /// 服务订阅与网关自注册协调器。
    pub discovery: Arc<NacosDiscoveryManager>,
    /// 可在成功换版后原子替换后端的限流器。
    pub rate_limiter: Arc<SwappableRateLimiter>,
    /// 可换代的全局并发计数器。
    pub conn_limiter: Arc<SwappableConnLimiter>,
    /// 可换代的熔断滑动窗口统计后端。
    pub circuit_stats: Arc<SwappableCircuitStats>,
    /// 可换代的 nonce/防重放后端。
    pub replay_guard: Arc<SwappableReplayGuard>,
    /// 黑名单/接口禁用等动态事实源。
    pub dynamic_store: Arc<SwappableDynamicStore>,
    /// 数据面本地黑名单快照。
    pub blacklist: Arc<BlacklistCache>,
    /// 数据面本地接口禁用快照。
    pub interface_disable: Arc<crate::guard::DynamicInterfaceGuardCache>,
    /// 常驻 WS/gRPC 长连接表；成功换版后按配置安排 stale drain。
    pub conn_registry: Arc<ConnectionRegistry>,
    /// 常驻 HTTP 代理运行态；成功换版后回收已失效且无活跃 handle 的 identity entry。
    pub proxy: Option<Arc<crate::proxy::GatewayProxy>>,
    /// 是否执行 sidecar loopback listener 门禁；该属性由启动 CLI 固定，不能被动态配置关闭。
    pub sidecar_mode: bool,
    /// data/stream listener 两阶段热切换；纯库测试或 admin-only 模式可为 None。
    pub listener_topology: Option<Arc<dyn ListenerTopologyReconciler>>,
}

/// 起热重载后台任务(notify + SIGHUP 汇入同一 reload)。
///
/// # 参数
/// - `cfg_path`: 本地 bootstrap 配置路径，也是文件 watch 目标。
/// - `snap`: 当前不可变配置快照，成功构建新版后原子替换。
/// - `version`: 成功快照版本序列。
/// - `runtime`: 需要随快照协调更新的运行态后端。
/// - `history`: 重载审计历史。
/// - `cfg`: 有界事件队列与去抖窗口；worker 启动后保持不变。
pub fn spawn(
    cfg_path: PathBuf,
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    version: Arc<AtomicU64>,
    runtime: ReloadRuntime,
    history: ConfigHistory,
    cfg: ReloadCfg,
) -> ReloadHandle {
    let (tx, rx) = mpsc::channel::<ReloadEvent>(cfg.channel_capacity.max(1));
    spawn_file_watch(cfg_path.clone(), tx.clone());
    spawn_sighup(tx.clone());
    spawn_nacos_config_watch(cfg_path.clone(), tx.clone());
    tokio::spawn(reload_worker(
        cfg_path,
        snap,
        version,
        runtime,
        history,
        rx,
        Duration::from_millis(cfg.debounce_ms),
    ));
    ReloadHandle { tx }
}

/// 业务作用：统一执行事务化 reload，并在发布前复验 bootstrap authority、外部副作用和 listener 准备。
///
/// 参数说明：`cfg_path` 是候选配置；`snap/version/runtime/history` 是唯一发布链状态；`trigger` 标识来源。
///
/// 返回：候选完整提交返回 true；任一校验/prepare/apply 失败返回 false 并保留旧快照。
pub async fn apply_reload(
    cfg_path: &std::path::Path,
    snap: &ArcSwap<GatewaySnapshot>,
    version: &AtomicU64,
    runtime: &ReloadRuntime,
    trigger: &str,
    history: &ConfigHistory,
) -> bool {
    // 从版本分配前就取得写权；否则 xDS 与 reload 可能拿到同一 next version，并以最后 store 者
    // 覆盖对方已经 ACK/审计的快照，破坏“先完整构建、后单点发布”的控制面 fencing。
    let _apply_guard = runtime.apply_coordinator.lock().await;
    let old_version = version.load(Ordering::Relaxed);
    let Some(next) = old_version.checked_add(1) else {
        tracing::error!(old_version, trigger, "config version space exhausted");
        history.record_rejected(
            trigger,
            cfg_path,
            old_version,
            old_version,
            "config version space exhausted",
        );
        return false;
    };
    let candidate = history.with_stable_local_files(|| {
        load_snapshot_with_dynamic(cfg_path, next, runtime.dynamic_upstreams.clone())
    });
    match candidate {
        Ok(new_snap) => {
            if runtime.sidecar_mode {
                // 必须先复验部署边界，再进入候选 socket prepare；否则恶意热更可能短暂绑定公网地址。
                if let Err(error) = new_snap.validate_sidecar_listeners() {
                    tracing::error!(trigger, error = %error, "sidecar listener isolation check failed; keeping old snapshot");
                    history.record_rejected(
                        trigger,
                        cfg_path,
                        old_version,
                        next,
                        format!("sidecar listener isolation check failed: {error:#}"),
                    );
                    return false;
                }
            }
            // 数据面、admin 与 ACME worker 共用同一两阶段 supervisor：先绑定/建锁，发布后才
            // 启动候选并撤销旧权威，任何 prepare 失败都保持旧快照和旧 listener 完整可用。
            let old = snap.load();
            let old_topology = old.listen_topology();
            let old_admin_listen = old.admin_listen.clone();
            let old_edge_cluster = old.grpc_edge_cluster.clone();
            #[cfg(feature = "grpc-edge")]
            let old_edge_nacos = old.discovery.nacos.clone();
            let old_runtime_state = rate_limiter_config_signature(&old.runtime_state);
            let old_dynamic_store = dynamic_store_config_signature(&old.runtime_state);
            let old_circuit_stats = circuit_stats_config_signature(&old.runtime_state);
            let old_replay_guard = replay_guard_config_signature(&old.runtime_state);
            let old_http_cache =
                crate::http_cache::runtime_config_signature(&old.runtime_state.http_cache);
            let old_telemetry = crate::telemetry::config_signature(&old.telemetry);
            let old_access_log = old.access_log.clone();
            let old_admin_audit = old.admin_audit.clone();
            let old_control_plane = old.control_plane.clone();
            #[cfg(feature = "xds-client")]
            let xds_policy_owned = old.control_plane.xds.enabled
                && old.control_plane.xds.ownership.routes
                    == crate::config::model::XdsResourceOwnerCfg::Xds;
            let mut old_xds_specs = old.upstreams.xds_watch_specs();
            old_xds_specs.sort_by(|left, right| {
                left.logical_service
                    .cmp(&right.logical_service)
                    .then_with(|| left.cluster_name.cmp(&right.cluster_name))
            });
            let nacos_bootstrap_violation = (trigger == "nacos-config")
                .then(|| nacos_bootstrap_change(old.as_ref(), &new_snap))
                .flatten();
            drop(old);
            #[cfg(feature = "xds-client")]
            if xds_policy_owned {
                // 当前 CDS/RDS generation 与 file bootstrap 合成后才成为 active。overlay merge 尚未
                // 纳入同一协调事务前，禁止 file/Nacos reload 单独覆盖 ArcSwap 并擦除已 ACK 路由。
                tracing::error!(
                    trigger,
                    "reload rejected while xDS owns routes/clusters; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "reload while xDS owns routes/clusters requires restart",
                );
                return false;
            }
            if let Some(field) = nacos_bootstrap_violation {
                tracing::error!(
                    trigger,
                    field,
                    "Nacos dynamic config attempted to override a bootstrap-layer field"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    format!("Nacos dynamic config cannot override bootstrap-layer `{field}`"),
                );
                return false;
            }
            let mut new_xds_specs = new_snap.upstreams.xds_watch_specs();
            new_xds_specs.sort_by(|left, right| {
                left.logical_service
                    .cmp(&right.logical_service)
                    .then_with(|| left.cluster_name.cmp(&right.cluster_name))
            });
            if new_snap.control_plane != old_control_plane || new_xds_specs != old_xds_specs {
                // ADS server/identity/trust/budgets 与 EDS owner 映射共同定义一个常驻 authority；
                // 未实现 task 两阶段换代前绝不能先发布新快照，让旧 stream 写入新 owner 域。
                tracing::error!(
                    trigger,
                    "xDS bootstrap or EDS ownership change rejected; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "control_plane.xds bootstrap/EDS ownership change requires restart",
                );
                return false;
            }
            let new_topology = new_snap.listen_topology();
            let edge_relay_changed = !same_edge_relay_topology(
                old_edge_cluster.as_deref(),
                new_snap.grpc_edge_cluster.as_deref(),
            );
            if edge_relay_changed
                && !edge_relay_hot_reload_compatible(
                    old_edge_cluster.as_deref(),
                    new_snap.grpc_edge_cluster.as_deref(),
                )
            {
                tracing::error!(
                    trigger,
                    "gRPC edge cluster transport mode or identity change rejected; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "grpc_edge_cluster mode/cluster_id/node_id/membership change requires restart",
                );
                return false;
            }
            let acme_lock_runtime_changed = rate_limiter_config_signature(&new_snap.runtime_state)
                != old_runtime_state
                && old_topology
                    .iter()
                    .chain(new_topology.iter())
                    .any(|topology| topology.tls.as_ref().is_some_and(|tls| tls.acme.is_some()));
            let prepared_listener_topology = if new_topology != old_topology
                || new_snap.admin_listen != old_admin_listen
                || acme_lock_runtime_changed
            {
                let Some(reconciler) = &runtime.listener_topology else {
                    tracing::error!(
                        trigger,
                        "listener topology change rejected; no runtime supervisor"
                    );
                    history.record_rejected(
                        trigger,
                        cfg_path,
                        old_version,
                        next,
                        "listener topology change requires a running listener supervisor",
                    );
                    return false;
                };
                match reconciler.prepare(&new_snap).await {
                    Ok(prepared) => Some(prepared),
                    Err(error) => {
                        tracing::error!(trigger, error = %error, "listener topology prepare failed; keeping old listeners");
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("listener topology prepare failed: {error:#}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let new_runtime_state = rate_limiter_config_signature(&new_snap.runtime_state);
            let new_dynamic_store = dynamic_store_config_signature(&new_snap.runtime_state);
            let new_circuit_stats = circuit_stats_config_signature(&new_snap.runtime_state);
            let new_replay_guard = replay_guard_config_signature(&new_snap.runtime_state);
            let new_http_cache =
                crate::http_cache::runtime_config_signature(&new_snap.runtime_state.http_cache);
            let new_telemetry = crate::telemetry::config_signature(&new_snap.telemetry);
            if !old_access_log.same_sink_topology(&new_snap.access_log) {
                tracing::error!(
                    trigger,
                    "access log queue/sink topology change rejected; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "access_log queue/sink topology change requires restart",
                );
                return false;
            }
            if !old_admin_audit.same_bootstrap(&new_snap.admin_audit) {
                tracing::error!(
                    trigger,
                    "admin audit spool/credential/endpoint change rejected; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "admin.audit bootstrap change requires restart",
                );
                return false;
            }
            if new_http_cache != old_http_cache {
                tracing::error!(
                    trigger,
                    "HTTP cache Redis connection/prefix/invalidation topology change rejected; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "runtime_state.http_cache bootstrap change requires restart",
                );
                return false;
            }
            if new_telemetry != old_telemetry {
                tracing::error!(
                    trigger,
                    "telemetry exporter/sampling topology change rejected; restart required"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    "telemetry bootstrap change requires restart",
                );
                return false;
            }
            let next_rate_limiter = if new_runtime_state != old_runtime_state {
                match build_rate_limiter(&new_snap.runtime_state).await {
                    Ok(next) => Some(next),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime rate limiter rebuild failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime rate limiter rebuild failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let next_conn_limiter = if new_runtime_state != old_runtime_state {
                match build_conn_limiter(&new_snap.runtime_state).await {
                    Ok(next) => Some(next),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime conn limiter rebuild failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime conn limiter rebuild failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            // §10.6 R3 熔断统计后端:独立签名判定是否重建(local↔redis 切换或 shared 开关变化)。
            let next_circuit_stats = if new_circuit_stats != old_circuit_stats {
                match build_circuit_stats(&new_snap.runtime_state).await {
                    Ok(next) => Some(next),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime circuit stats rebuild failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime circuit stats rebuild failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            // §20 防重放后端:独立签名判定是否重建(local↔redis 切换或 fail_mode 变化)。
            let next_replay_guard = if new_replay_guard != old_replay_guard {
                match build_replay_guard(&new_snap.runtime_state).await {
                    Ok(next) => Some(next),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime replay guard rebuild failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime replay guard rebuild failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let next_dynamic_store = if new_dynamic_store != old_dynamic_store {
                match build_dynamic_store(&new_snap.runtime_state, cfg_path).await {
                    Ok(next) => Some(next),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime dynamic store rebuild failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime dynamic store rebuild failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let next_blacklist_cfg = new_snap.runtime_state.blacklist.clone();
            let next_interface_disable_cfg = new_snap.runtime_state.interface_disable.clone();
            if let Err(e) = crate::blacklist::validate_config(&next_blacklist_cfg) {
                tracing::error!(
                    trigger,
                    error = %e,
                    "reload rejected, runtime blacklist config invalid"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    format!("runtime blacklist config invalid: {e}"),
                );
                return false;
            }
            if let Err(e) =
                crate::guard::validate_interface_disable_config(&next_interface_disable_cfg)
            {
                tracing::error!(
                    trigger,
                    error = %e,
                    "reload rejected, runtime interface disable config invalid"
                );
                history.record_rejected(
                    trigger,
                    cfg_path,
                    old_version,
                    next,
                    format!("runtime interface disable config invalid: {e}"),
                );
                return false;
            }
            let blacklist_store = next_dynamic_store
                .clone()
                .unwrap_or_else(|| runtime.dynamic_store.current());
            let interface_disable_store = blacklist_store.clone();
            let next_blacklist_ips = if next_blacklist_cfg.enabled {
                match crate::blacklist::load_blacklist_ips(
                    blacklist_store.as_ref(),
                    &next_blacklist_cfg.collection,
                )
                .await
                {
                    Ok(ips) => Some(ips),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime blacklist reload failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime blacklist reload failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let next_interface_disable_guard = if next_interface_disable_cfg.enabled {
                match crate::guard::load_dynamic_interface_guard(
                    interface_disable_store.as_ref(),
                    &next_interface_disable_cfg.collection,
                )
                .await
                {
                    Ok(guard) => Some(guard),
                    Err(e) => {
                        tracing::error!(
                            trigger,
                            error = %e,
                            "reload rejected, runtime interface disable reload failed"
                        );
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("runtime interface disable reload failed: {e}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let routes = new_snap.router.len();
            let guards = new_snap.interface_guard.rule_count();
            #[cfg(feature = "grpc-edge")]
            let prepared_edge_relay = if edge_relay_changed {
                match prepare_edge_relay_reload(
                    runtime,
                    old_edge_cluster
                        .as_ref()
                        .expect("compatible change has current relay"),
                    new_snap
                        .grpc_edge_cluster
                        .as_ref()
                        .expect("compatible change has candidate relay")
                        .clone(),
                    old_edge_nacos,
                    new_snap.discovery.nacos.clone(),
                )
                .await
                {
                    Ok(prepared) => Some(prepared),
                    Err(error) => {
                        tracing::error!(trigger, error = %error, "gRPC edge relay prepare failed; old generation restored");
                        history.record_rejected(
                            trigger,
                            cfg_path,
                            old_version,
                            next,
                            format!("grpc_edge_cluster hot reload prepare failed: {error:#}"),
                        );
                        return false;
                    }
                }
            } else {
                None
            };
            let new_snap = Arc::new(new_snap);
            snap.store(new_snap.clone()); // ★唯一的原子换版点(无锁、纳秒级)★
            #[cfg(feature = "grpc-edge")]
            if let Some(prepared) = prepared_edge_relay {
                prepared.commit();
            }
            if let Some(prepared) = prepared_listener_topology {
                // prepare 已完成所有可能失败的 bind/TLS 构建；commit 只启动新 accept task，
                // 再通知旧 task 停 accept。旧 task 已交出的连接各自持有 IO/快照继续 drain。
                prepared.commit();
            }
            if let Some(next) = next_rate_limiter {
                runtime.rate_limiter.replace(next);
            }
            if let Some(next) = next_conn_limiter {
                runtime.conn_limiter.replace(next);
            }
            if let Some(next) = next_circuit_stats {
                runtime.circuit_stats.replace(next);
            }
            if let Some(next) = next_replay_guard {
                runtime.replay_guard.replace(next);
            }
            if let Some(next) = next_dynamic_store {
                runtime.dynamic_store.replace(next);
            }
            if let Err(e) = runtime.blacklist.apply_config(&next_blacklist_cfg) {
                tracing::error!(trigger, error = %e, "blacklist config apply failed after validation");
            }
            if let Some(ips) = next_blacklist_ips {
                runtime.blacklist.replace_entries(ips);
            } else {
                runtime.blacklist.clear();
            }
            if let Err(e) = runtime
                .interface_disable
                .apply_config(&next_interface_disable_cfg)
            {
                tracing::error!(trigger, error = %e, "interface disable config apply failed after validation");
            }
            if let Some(guard) = next_interface_disable_guard {
                runtime.interface_disable.replace_guard(guard);
            } else {
                runtime.interface_disable.clear();
            }
            runtime.discovery.reconcile(&new_snap);
            if let Some(proxy) = &runtime.proxy {
                proxy.reconcile_runtime_identities(&new_snap);
            }
            if new_snap.long_connections.drain_on_config_change {
                let grace = Duration::from_millis(new_snap.long_connections.drain_grace_ms);
                let scheduled = runtime.conn_registry.schedule_drain_stale(next, grace);
                tracing::info!(
                    version = next,
                    scheduled,
                    grace_ms = new_snap.long_connections.drain_grace_ms,
                    "scheduled stale long-connection drain after config reload"
                );
            }
            version.store(next, Ordering::Relaxed);
            history.record_success(trigger, cfg_path, old_version, new_snap.as_ref());
            tracing::info!(
                trigger,
                version = next,
                routes,
                interface_rules = guards,
                "config reloaded"
            );
            true
        }
        // ★坏配置绝不上线★:保留旧快照,在线流量零影响(比 nginx reload 更稳)。
        Err(e) => {
            tracing::error!(trigger, error = %e, "reload rejected, keep old config");
            history.record_rejected(trigger, cfg_path, old_version, next, e.to_string());
            false
        }
    }
}

/// 找出 Nacos 候选快照试图覆盖的首个 bootstrap 层字段。
///
/// 比较基线使用当前已生效快照：进程启动时它来自本地文件；本地受信通道若显式调整 bootstrap
/// 配置并成功换版，后续 Nacos 也必须继续与新的本地基线一致。被拒的 Nacos 候选永远不会污染基线。
fn nacos_bootstrap_change(
    current: &GatewaySnapshot,
    candidate: &GatewaySnapshot,
) -> Option<&'static str> {
    if current.admin_auth != candidate.admin_auth {
        return Some("admin.auth");
    }
    if !current.admin_audit.same_bootstrap(&candidate.admin_audit) {
        return Some("admin.audit");
    }
    if rate_limiter_config_signature(&current.runtime_state)
        != rate_limiter_config_signature(&candidate.runtime_state)
        || circuit_stats_config_signature(&current.runtime_state)
            != circuit_stats_config_signature(&candidate.runtime_state)
        || replay_guard_config_signature(&current.runtime_state)
            != replay_guard_config_signature(&candidate.runtime_state)
    {
        return Some("runtime_state.rate_limiter/redis");
    }
    if dynamic_store_config_signature(&current.runtime_state)
        != dynamic_store_config_signature(&candidate.runtime_state)
    {
        return Some("runtime_state.store");
    }
    if crate::http_cache::runtime_config_signature(&current.runtime_state.http_cache)
        != crate::http_cache::runtime_config_signature(&candidate.runtime_state.http_cache)
    {
        return Some("runtime_state.http_cache connection/prefix/channel");
    }
    if crate::telemetry::config_signature(&current.telemetry)
        != crate::telemetry::config_signature(&candidate.telemetry)
    {
        return Some("telemetry exporter/sampling");
    }
    if !current.access_log.same_sink_topology(&candidate.access_log) {
        return Some("access_log queue/sink topology");
    }
    if !same_discovery_bootstrap(current, candidate) {
        return Some("discovery.nacos connection/identity");
    }
    if !same_config_source_bootstrap(&current.config_source.nacos, &candidate.config_source.nacos) {
        return Some("config_source.nacos");
    }
    if !same_tls_secret_references(current, candidate) {
        return Some("TLS private-key/credential path");
    }
    None
}

fn same_discovery_bootstrap(current: &GatewaySnapshot, candidate: &GatewaySnapshot) -> bool {
    let current = &current.discovery.nacos;
    let candidate = &candidate.discovery.nacos;
    current.enabled == candidate.enabled
        && current.server_addr == candidate.server_addr
        && current.namespace == candidate.namespace
        && current.group == candidate.group
        && current.app_name == candidate.app_name
        && current.discovery_ip == candidate.discovery_ip
        && current.username == candidate.username
        && current.password == candidate.password
}

fn same_config_source_bootstrap(
    current: &NacosConfigSourceCfg,
    candidate: &NacosConfigSourceCfg,
) -> bool {
    current.enabled == candidate.enabled
        && current.server_addr == candidate.server_addr
        && current.namespace == candidate.namespace
        && current.group == candidate.group
        && current.app_name == candidate.app_name
        && current.username == candidate.username
        && current.password == candidate.password
        && current.gateway_data_id == candidate.gateway_data_id
        && current.interface_guard_data_id == candidate.interface_guard_data_id
        && current.sentinel_rules_data_id == candidate.sentinel_rules_data_id
        && current.bundle_data_id == candidate.bundle_data_id
        && current.materialized_dir == candidate.materialized_dir
        && current.reconnect_backoff_ms == candidate.reconnect_backoff_ms
}

fn same_tls_secret_references(current: &GatewaySnapshot, candidate: &GatewaySnapshot) -> bool {
    if current.proxies.len() != candidate.proxies.len() {
        return false;
    }
    current
        .proxies
        .iter()
        .zip(candidate.proxies.iter())
        .all(
            |(current, candidate)| match (&current.tls, &candidate.tls) {
                (None, None) => true,
                (Some(current), Some(candidate)) => {
                    current.key_file == candidate.key_file
                        && current.keypair_manifest_file == candidate.keypair_manifest_file
                        && current.client_auth == candidate.client_auth
                        && current.certs.len() == candidate.certs.len()
                        && current
                            .certs
                            .iter()
                            .zip(candidate.certs.iter())
                            .all(|(current, candidate)| current.key_file == candidate.key_file)
                        && match (&current.acme, &candidate.acme) {
                            (None, None) => true,
                            (Some(current), Some(candidate)) => {
                                current.directory_ca_file == candidate.directory_ca_file
                                    && current.account_credentials_file
                                        == candidate.account_credentials_file
                                    && current.dns01.as_ref().map(|dns| &dns.command)
                                        == candidate.dns01.as_ref().map(|dns| &dns.command)
                            }
                            _ => false,
                        }
                }
                _ => false,
            },
        )
}

async fn reload_worker(
    cfg_path: PathBuf,
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    version: Arc<AtomicU64>,
    runtime: ReloadRuntime,
    history: ConfigHistory,
    mut rx: mpsc::Receiver<ReloadEvent>,
    debounce: Duration,
) {
    let mut last_hashes = HashMap::new();
    match config_fingerprint(&cfg_path) {
        Ok(hash) => {
            last_hashes.insert(cfg_path.clone(), hash);
        }
        Err(e) => {
            tracing::warn!(error = %e, "initial config fingerprint failed; first reload will still be validated");
        }
    }

    while let Some(first) = rx.recv().await {
        if !debounce.is_zero() {
            tokio::time::sleep(debounce).await;
        }
        let trigger = drain_reload_events(first, &mut rx);
        let source_cfg_path = trigger.cfg_path(&cfg_path);

        match config_fingerprint(&source_cfg_path) {
            Ok(hash) if last_hashes.get(&source_cfg_path) == Some(&hash) => {
                tracing::debug!(
                    trigger = trigger.as_str(),
                    cfg = %source_cfg_path.display(),
                    "reload skipped; config unchanged"
                );
                continue;
            }
            Ok(hash) => {
                if apply_reload(
                    &source_cfg_path,
                    &snap,
                    &version,
                    &runtime,
                    trigger.as_str(),
                    &history,
                )
                .await
                {
                    last_hashes.insert(source_cfg_path, hash);
                }
            }
            Err(e) => {
                tracing::error!(
                    trigger = trigger.as_str(),
                    cfg = %source_cfg_path.display(),
                    error = %e,
                    "reload rejected before build; cannot fingerprint config"
                );
            }
        }
    }
}

fn drain_reload_events(first: ReloadEvent, rx: &mut mpsc::Receiver<ReloadEvent>) -> ReloadEvent {
    let mut trigger = first;
    while let Ok(next) = rx.try_recv() {
        trigger = merge_reload_events(trigger, next);
    }
    trigger
}

fn merge_reload_events(current: ReloadEvent, next: ReloadEvent) -> ReloadEvent {
    match next {
        ReloadEvent::Nacos { .. } => next,
        ReloadEvent::File => match current {
            ReloadEvent::Nacos { .. } => current,
            ReloadEvent::File | ReloadEvent::Dependency | ReloadEvent::Sighup => ReloadEvent::File,
        },
        ReloadEvent::Dependency => match current {
            ReloadEvent::Nacos { .. } | ReloadEvent::File => current,
            ReloadEvent::Dependency | ReloadEvent::Sighup => ReloadEvent::Dependency,
        },
        ReloadEvent::Sighup => current,
    }
}

/// 通道①:notify 监听配置目录,事件交给统一 worker 防抖与换版。
fn spawn_file_watch(cfg_path: PathBuf, tx: mpsc::Sender<ReloadEvent>) {
    // macOS 的 `/var` 是 `/private/var` 符号链接：进程参数可能使用前者，而 FSEvents/notify
    // 返回后者。监听前固定为真实路径，才能在精确过滤时仍识别主配置和依赖文件。
    let cfg_path = canonical_watch_path(&cfg_path);
    let config_dir = cfg_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    tokio::spawn(async move {
        // notify 回调在同步线程；先递到本 watcher manager，由它区分主配置与 secret
        // 轮换、并在主配置改变后对账新旧 secret 目录，避免常驻 watcher 无界累积。
        let (event_tx, mut event_rx) = mpsc::channel::<notify::Event>(64);
        let mut watcher = match RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(ev) = res {
                    if matches!(
                        ev.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        let _ = event_tx.blocking_send(ev);
                    }
                }
            },
            notify::Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "file watcher init failed; hot-reload-by-file disabled");
                return;
            }
        };
        if let Err(e) = watcher.watch(&config_dir, RecursiveMode::NonRecursive) {
            tracing::error!(dir = %config_dir.display(), error = %e, "watch dir failed");
            return;
        }
        let mut watched_dirs = HashSet::from([config_dir.clone()]);
        let mut dependency_files = load_reload_dependencies(&cfg_path).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "initial config dependency scan failed; config dir watch remains active");
            Vec::new()
        });
        reconcile_dependency_watches(
            &mut watcher,
            &config_dir,
            &dependency_files,
            &mut watched_dirs,
        );
        tracing::info!(
            dir = %config_dir.display(),
            dependency_files = dependency_files.len(),
            "watching config dependency directories for changes"
        );
        while let Some(event) = event_rx.recv().await {
            let Some(reload_event) =
                classify_watched_paths(&event.paths, &cfg_path, &dependency_files)
            else {
                // notify 必须监听目录而不是 inode，才能观察编辑器的 temp+rename 原子发布；目录
                // 同时会产生日志、证书旁路文件和临时文件事件。它们不属于当前配置依赖，不能
                // 触发换版，否则会无故 drain WebSocket/gRPC 长连接并重建上游池。
                continue;
            };
            if tx.send(reload_event).await.is_err() {
                break;
            }
            match load_reload_dependencies(&cfg_path) {
                Ok(next) => {
                    reconcile_dependency_watches(
                        &mut watcher,
                        &config_dir,
                        &next,
                        &mut watched_dirs,
                    );
                    dependency_files = next;
                }
                Err(e) => tracing::debug!(
                    error = %e,
                    "config dependency rescan failed; keeping prior watches until config validates"
                ),
            }
        }
    });
}

/// 尽量把 watch 目标固定为操作系统事件返回的真实路径；目标短暂不存在时保留原路径，后续
/// create/rename 仍可由已监听的父目录捕获。
fn canonical_watch_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn load_reload_dependencies(cfg_path: &Path) -> Result<Vec<PathBuf>> {
    crate::config::reload_dependencies(cfg_path).map(|mut paths| {
        for path in &mut paths {
            *path = canonical_watch_path(path);
        }
        paths.sort();
        paths.dedup();
        paths
    })
}

/// 将目录级 notify 事件收窄为真实配置依赖事件。
///
/// watcher 监听父目录以兼容原子 rename，但 reload 权限只属于主配置目标和 loader 已解析出的
/// `SecretSource` 文件。原子替换会在目标路径产生 create/rename 事件，因此无需接受同目录任意
/// 文件；精确匹配也避免日志/临时文件变化造成无意义换版和长连接 drain。
fn classify_watched_paths(
    paths: &[PathBuf],
    cfg_path: &Path,
    dependency_files: &[PathBuf],
) -> Option<ReloadEvent> {
    if paths.iter().any(|path| path == cfg_path) {
        return Some(ReloadEvent::File);
    }
    paths
        .iter()
        .any(|path| dependency_files.iter().any(|dependency| dependency == path))
        .then_some(ReloadEvent::Dependency)
}

/// 把 notify 目录精确对账为“主配置目录 + 当前声明式文件依赖父目录”。
fn reconcile_dependency_watches(
    watcher: &mut RecommendedWatcher,
    config_dir: &Path,
    dependency_files: &[PathBuf],
    watched_dirs: &mut HashSet<PathBuf>,
) {
    let mut desired = HashSet::from([config_dir.to_path_buf()]);
    desired.extend(
        dependency_files
            .iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf)),
    );
    for removed in watched_dirs
        .difference(&desired)
        .cloned()
        .collect::<Vec<_>>()
    {
        match watcher.unwatch(&removed) {
            Ok(()) => {
                watched_dirs.remove(&removed);
            }
            Err(e) => {
                // 保留在已观察集合中,下次对账继续重试,避免 bookkeeping 声称成功。
                tracing::warn!(dir = %removed.display(), error = %e, "unwatch old SecretSource dir failed");
            }
        }
    }
    for added in desired
        .difference(watched_dirs)
        .cloned()
        .collect::<Vec<_>>()
    {
        match watcher.watch(&added, RecursiveMode::NonRecursive) {
            Ok(()) => {
                watched_dirs.insert(added);
            }
            Err(e) => {
                // 不记成成功;后续任一配置事件都会重新尝试挂 watch。
                tracing::error!(dir = %added.display(), error = %e, "watch SecretSource dir failed");
            }
        }
    }
}

/// 通道②:SIGHUP(nginx `-s reload` 风格)。
fn spawn_sighup(tx: mpsc::Sender<ReloadEvent>) {
    tokio::spawn(async move {
        let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "install SIGHUP handler failed");
                return;
            }
        };
        while hup.recv().await.is_some() {
            if tx.send(ReloadEvent::Sighup).await.is_err() {
                break;
            }
        }
    });
}

/// 通道③:Nacos 配置中心 watch。远端配置只物化到私有目录,不覆盖 operator 本地文件。
///
/// # 参数
/// - `bootstrap_cfg_path`: 本地 bootstrap `gateway.yml`,用于读取 `config_source.nacos` 与定位物化目录。
/// - `tx`: reload worker 事件通道。
fn spawn_nacos_config_watch(bootstrap_cfg_path: PathBuf, tx: mpsc::Sender<ReloadEvent>) {
    // Nacos SDK 配置 watch 组合出的 future 在真实 feature 下不保证满足 `tokio::spawn` 的 Send 约束。
    // 它是低频控制面任务,放进独立 current-thread runtime 可隔离该约束,也不占用数据面 worker。
    let spawn_result = std::thread::Builder::new()
        .name("gateway-nacos-config-watch".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    tracing::error!(error = %e, "Nacos config watch runtime init failed");
                    return;
                }
            };
            runtime.block_on(run_nacos_config_watch_loop(bootstrap_cfg_path, tx));
        });
    if let Err(e) = spawn_result {
        tracing::error!(error = %e, "spawn Nacos config watch thread failed");
    }
}

/// Nacos 配置 watch 主循环。
///
/// # 参数
/// - `bootstrap_cfg_path`: 本地 bootstrap `gateway.yml`。
/// - `tx`: reload worker 事件通道。
async fn run_nacos_config_watch_loop(bootstrap_cfg_path: PathBuf, tx: mpsc::Sender<ReloadEvent>) {
    let cfg = match load_gateway_config(&bootstrap_cfg_path) {
        Ok(cfg) => cfg.config_source.nacos,
        Err(e) => {
            tracing::warn!(error = %e, "Nacos config source disabled; bootstrap config cannot be read");
            return;
        }
    };
    if !cfg.enabled {
        return;
    }
    if let Err(e) = validate_nacos_config_source(&cfg) {
        tracing::error!(error = %e, "Nacos config source disabled; invalid config_source.nacos");
        return;
    }
    let backoff = Duration::from_millis(cfg.reconnect_backoff_ms.max(100));
    loop {
        if let Err(e) = run_nacos_config_watch_once(&bootstrap_cfg_path, &cfg, &tx).await {
            tracing::warn!(error = %e, "Nacos config watch failed; reconnecting");
        }
        tokio::time::sleep(backoff).await;
    }
}

/// 建立一次 Nacos 配置 watch,直到 watch 断开或 reload worker 退出。
///
/// # 参数
/// - `bootstrap_cfg_path`: 本地 bootstrap `gateway.yml`。
/// - `cfg`: Nacos 配置中心来源。
/// - `tx`: reload worker 事件通道。
async fn run_nacos_config_watch_once(
    bootstrap_cfg_path: &Path,
    cfg: &NacosConfigSourceCfg,
    tx: &mpsc::Sender<ReloadEvent>,
) -> Result<()> {
    let props = nacos_config_props(cfg);
    let client = nasa::config::nacos::NacosConfigClient::connect(&props).await?;
    let refs = nacos_config_refs(cfg);
    let (_guard, mut rx) = client.watch_many_channel(refs).await?;

    let cfg_path = materialize_nacos_config_bundle(bootstrap_cfg_path, cfg, &rx.borrow())?;
    tx.send(ReloadEvent::Nacos { cfg_path }).await?;
    loop {
        rx.changed().await?;
        let cfg_path = materialize_nacos_config_bundle(bootstrap_cfg_path, cfg, &rx.borrow())?;
        tx.send(ReloadEvent::Nacos { cfg_path }).await?;
    }
}

/// 构造 Nacos 配置中心连接参数。
///
/// # 参数
/// - `cfg`: `config_source.nacos` 配置。
pub(crate) fn nacos_config_props(cfg: &NacosConfigSourceCfg) -> nasa::config::nacos::NacosProps {
    let mut props = nasa::config::nacos::NacosProps::new(&cfg.server_addr)
        .with_namespace(&cfg.namespace)
        .with_group(&cfg.group)
        .with_app_name(&cfg.app_name);
    if !cfg.username.is_empty() || !cfg.password.is_empty() {
        props = props.with_auth(&cfg.username, &cfg.password);
    }
    props
}

/// 构造网关统一配置需要 watch 的 Nacos dataId 列表。
///
/// # 参数
/// - `cfg`: `config_source.nacos` 配置。
fn nacos_config_refs(cfg: &NacosConfigSourceCfg) -> Vec<nasa::config::nacos::ConfigRef> {
    if !cfg.bundle_data_id.trim().is_empty() {
        return vec![
            nasa::config::nacos::ConfigRef::required(cfg.bundle_data_id.clone())
                .with_group(cfg.group.clone())
                .with_file_extension("json"),
        ];
    }
    vec![
        nasa::config::nacos::ConfigRef::required(cfg.gateway_data_id.clone())
            .with_group(cfg.group.clone())
            .with_file_extension("yaml"),
        nasa::config::nacos::ConfigRef::required(cfg.interface_guard_data_id.clone())
            .with_group(cfg.group.clone())
            .with_file_extension("yaml"),
        nasa::config::nacos::ConfigRef::required(cfg.sentinel_rules_data_id.clone())
            .with_group(cfg.group.clone())
            .with_file_extension("yaml"),
    ]
}

/// Nacos 单 dataId 原子配置 bundle。三份原文作为 JSON string 一次 CAS，watcher 不会
/// 观察到跨 dataId 的新旧混合窗口。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AtomicNacosConfigBundle {
    pub(crate) schema_version: u32,
    pub(crate) bundle_version: String,
    pub(crate) gateway: String,
    pub(crate) interface_guard: String,
    pub(crate) sentinel_rules: String,
}

pub(crate) fn parse_atomic_nacos_bundle(content: &str) -> Result<AtomicNacosConfigBundle> {
    let bundle: AtomicNacosConfigBundle =
        serde_json::from_str(content).context("parse Nacos atomic config bundle JSON")?;
    anyhow::ensure!(
        bundle.schema_version == 1,
        "Nacos atomic config bundle uses unsupported schema_version {}",
        bundle.schema_version
    );
    anyhow::ensure!(
        !bundle.bundle_version.trim().is_empty(),
        "Nacos atomic config bundle_version must not be empty"
    );
    for (name, document) in [
        ("gateway", &bundle.gateway),
        ("interface_guard", &bundle.interface_guard),
        ("sentinel_rules", &bundle.sentinel_rules),
    ] {
        anyhow::ensure!(
            !document.trim().is_empty(),
            "Nacos atomic config bundle document `{name}` must not be empty"
        );
    }
    Ok(bundle)
}

pub(crate) fn encode_atomic_nacos_bundle(
    bundle_version: impl Into<String>,
    docs: &crate::config_history::ArchivedDocs,
) -> Result<String> {
    let bundle = AtomicNacosConfigBundle {
        schema_version: 1,
        bundle_version: bundle_version.into(),
        gateway: docs.gateway.clone(),
        interface_guard: docs.interface_guard.clone(),
        sentinel_rules: docs.sentinel_rules.clone(),
    };
    parse_atomic_nacos_bundle(&serde_json::to_string(&bundle)?)?;
    serde_json::to_string(&bundle).context("serialize Nacos atomic config bundle")
}

/// 将 Nacos bundle 物化为网关现有 loader 可读取的三文件目录。
///
/// # 参数
/// - `bootstrap_cfg_path`: 本地 bootstrap `gateway.yml`,用于解析相对物化目录。
/// - `cfg`: Nacos 配置中心来源。
/// - `bundle`: nasa 返回的远端配置 bundle。
fn materialize_nacos_config_bundle(
    bootstrap_cfg_path: &Path,
    cfg: &NacosConfigSourceCfg,
    bundle: &nasa::config::nacos::ConfigBundle,
) -> Result<PathBuf> {
    let dir = resolve_relative(bootstrap_cfg_path, &cfg.materialized_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("create Nacos config materialized dir {}", dir.display()))?;
    let documents = if cfg.bundle_data_id.trim().is_empty() {
        (
            bundle_required_doc(bundle, &cfg.gateway_data_id)?.to_string(),
            bundle_required_doc(bundle, &cfg.interface_guard_data_id)?.to_string(),
            bundle_required_doc(bundle, &cfg.sentinel_rules_data_id)?.to_string(),
        )
    } else {
        let atomic = parse_atomic_nacos_bundle(bundle_required_doc(bundle, &cfg.bundle_data_id)?)?;
        (
            atomic.gateway,
            atomic.interface_guard,
            atomic.sentinel_rules,
        )
    };
    write_atomic(&dir.join("gateway.yml"), documents.0.as_bytes())?;
    write_atomic(&dir.join("interface-guard.yml"), documents.1.as_bytes())?;
    write_atomic(&dir.join("sentinel-rules.yml"), documents.2.as_bytes())?;
    Ok(dir.join("gateway.yml"))
}

/// 从 Nacos bundle 中取必需文档。
///
/// # 参数
/// - `bundle`: nasa 返回的远端配置 bundle。
/// - `data_id`: 必需 dataId。
fn bundle_required_doc<'a>(
    bundle: &'a nasa::config::nacos::ConfigBundle,
    data_id: &str,
) -> Result<&'a str> {
    bundle
        .documents
        .iter()
        .find(|doc| doc.source.data_id == data_id)
        .map(|doc| doc.content.as_str())
        .with_context(|| format!("Nacos config bundle missing required dataId `{data_id}`"))
}

/// 校验 Nacos 配置中心来源,在启动 watch 前 fail-fast。
///
/// # 参数
/// - `cfg`: `config_source.nacos` 配置。
fn validate_nacos_config_source(cfg: &NacosConfigSourceCfg) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    validate_non_empty("config_source.nacos.server_addr", &cfg.server_addr)?;
    validate_non_empty("config_source.nacos.group", &cfg.group)?;
    if cfg.bundle_data_id.trim().is_empty() {
        validate_non_empty("config_source.nacos.gateway_data_id", &cfg.gateway_data_id)?;
        validate_non_empty(
            "config_source.nacos.interface_guard_data_id",
            &cfg.interface_guard_data_id,
        )?;
        validate_non_empty(
            "config_source.nacos.sentinel_rules_data_id",
            &cfg.sentinel_rules_data_id,
        )?;
    } else {
        validate_non_empty("config_source.nacos.bundle_data_id", &cfg.bundle_data_id)?;
    }
    validate_non_empty(
        "config_source.nacos.materialized_dir",
        &cfg.materialized_dir,
    )?;
    if cfg.bundle_data_id.trim().is_empty() {
        let mut ids = std::collections::HashSet::new();
        for data_id in [
            &cfg.gateway_data_id,
            &cfg.interface_guard_data_id,
            &cfg.sentinel_rules_data_id,
        ] {
            if !ids.insert(data_id.as_str()) {
                anyhow::bail!("duplicate Nacos config dataId `{data_id}`");
            }
        }
    }
    Ok(())
}

/// 校验非空配置项。
///
/// # 参数
/// - `field`: 配置项名。
/// - `value`: 配置项值。
fn validate_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    Ok(())
}

/// 原子写文件,避免 reload worker 读到半截物化内容。
///
/// # 参数
/// - `path`: 目标文件路径。
/// - `bytes`: 文件内容。
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let Some(parent) = path.parent() else {
        anyhow::bail!("invalid materialized config path {}", path.display());
    };
    fs::create_dir_all(parent)
        .with_context(|| format!("create materialized config dir {}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("materialized config path has invalid file name")?;
    let tmp = parent.join(format!(".{file_name}.tmp"));
    fs::write(&tmp, bytes).with_context(|| format!("write temp config {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "publish temp config {} to {}",
            tmp.display(),
            path.display()
        )
    })
}

#[path = "../../tests/unit/reload_mod.rs"]
#[cfg(test)]
mod tests;

/// 比较当前与候选快照的 edge relay 常驻拓扑。
fn same_edge_relay_topology(
    current: Option<&crate::grpc_edge::GrpcEdgeClusterPlan>,
    candidate: Option<&crate::grpc_edge::GrpcEdgeClusterPlan>,
) -> bool {
    match (current, candidate) {
        (None, None) => true,
        (Some(current), Some(candidate)) => current.same_runtime_topology(candidate),
        _ => false,
    }
}

/// 业务作用：判定 relay 候选能否在进程内热换代，防止身份/成员事实源变化绕过显式迁移。
///
/// 参数说明：`current`/`candidate` 是当前与候选集群计划。
///
/// 返回：两侧均为 relay 且 cluster/node/membership 权威不变时返回 `true`。
///
/// relay hot swap 只允许同一逻辑成员换运行参数；改变 mode/集群身份/成员事实源会
/// 同时改变连接所有权和外部依赖，仍要求显式重启迁移。
fn edge_relay_hot_reload_compatible(
    current: Option<&crate::grpc_edge::GrpcEdgeClusterPlan>,
    candidate: Option<&crate::grpc_edge::GrpcEdgeClusterPlan>,
) -> bool {
    use crate::config::model::GrpcEdgeClusterModeCfg;
    matches!((current, candidate), (Some(current), Some(candidate))
        if current.mode == GrpcEdgeClusterModeCfg::Relay
            && candidate.mode == GrpcEdgeClusterModeCfg::Relay
            && current.cluster_id == candidate.cluster_id
            && current.node_id == candidate.node_id
            && current.membership == candidate.membership)
}

#[cfg(feature = "grpc-edge")]
struct PreparedEdgeRelayReload {
    old: Arc<crate::edge_relay::EdgeRelay>,
    candidate: Arc<crate::edge_relay::EdgeRelay>,
    proxy: Arc<crate::proxy::GatewayProxy>,
}

#[cfg(feature = "grpc-edge")]
impl PreparedEdgeRelayReload {
    /// 业务作用：原子发布已准备的 relay 候选，再异步排干旧代，保持“先可用后切换”的提交顺序。
    ///
    /// 参数说明：无；`self` 已持有完成 bind/成员任务准备的候选和当前旧代。
    ///
    /// 返回：无返回值；提交后新请求只见候选，旧代最多保留一个 ACK deadline 结算在途。
    fn commit(self) {
        // 候选已完成所有可失败准备，必须先原子发布再排干旧代；反序会制造无 relay 窗口。
        self.proxy.attach_edge_relay(self.candidate);
        tokio::spawn(self.old.drain_and_shutdown());
    }
}

#[cfg(feature = "grpc-edge")]
/// 业务作用：在不发布半完成状态的前提下准备 relay 热换代，并在任一失败点恢复旧代权威。
///
/// 参数说明：`runtime` 提供当前 Proxy；`old_plan`/`candidate_plan` 是换代两侧计划；
/// `old_nacos`/`candidate_nacos` 用于分别恢复或启动成员事实源。
///
/// 返回：候选 listener 与成员任务全部就绪时返回可提交对象；失败时恢复旧 transport 后返回错误。
async fn prepare_edge_relay_reload(
    runtime: &ReloadRuntime,
    old_plan: &Arc<crate::grpc_edge::GrpcEdgeClusterPlan>,
    candidate_plan: Arc<crate::grpc_edge::GrpcEdgeClusterPlan>,
    old_nacos: crate::config::model::NacosDiscoveryCfg,
    candidate_nacos: crate::config::model::NacosDiscoveryCfg,
) -> anyhow::Result<PreparedEdgeRelayReload> {
    use crate::config::model::GrpcEdgeMembershipCfg;

    let proxy = runtime
        .proxy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("relay hot reload requires a running data plane"))?
        .clone();
    let old = proxy
        .current_edge_relay()
        .ok_or_else(|| anyhow::anyhow!("active relay generation is missing"))?;
    let same_listener = old_plan.relay_listen == candidate_plan.relay_listen;
    if same_listener {
        // 同地址候选只有在旧 accept/dial 暂停并释放 listener 后才能 bind；既有链路继续持有，
        // 候选失败时可先恢复旧权威再返回，避免把集群留在半完成保护态。
        old.pause_transport().await;
    }

    let candidate =
        match crate::edge_relay::EdgeRelay::start(candidate_plan.clone(), proxy.grpc_edge_hub())
            .await
        {
            Ok(candidate) => candidate,
            Err(error) => {
                // 候选尚未发布；先把 Hub 的控制权和旧 transport 恢复，再把失败交给 reload 回滚。
                old.activate_interest();
                if same_listener {
                    old.resume_transport()
                        .await
                        .context("restore old relay transport")?;
                    if old_plan.membership == GrpcEdgeMembershipCfg::Nacos {
                        old.start_nacos_membership(old_nacos)
                            .context("restore old relay Nacos membership")?;
                    }
                }
                return Err(error).context("start candidate relay generation");
            }
        };
    if candidate_plan.membership == GrpcEdgeMembershipCfg::Nacos {
        if let Err(error) = candidate.start_nacos_membership(candidate_nacos) {
            // 成员事实源未就绪的候选不能发布；先清候选资源，再完整恢复旧代控制权与 watcher。
            candidate.shutdown_now().await;
            old.activate_interest();
            if same_listener {
                old.resume_transport()
                    .await
                    .context("restore old relay transport")?;
                old.start_nacos_membership(old_nacos)
                    .context("restore old relay Nacos membership")?;
            }
            return Err(error).context("start candidate relay Nacos membership");
        }
    }
    Ok(PreparedEdgeRelayReload {
        old,
        candidate,
        proxy,
    })
}
