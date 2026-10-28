//! 进程启动、控制面与数据面装配、有序停机。

mod cli;
mod journal;
mod listener;
mod stream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{info, warn};

use gateway::admin;
use gateway::config::load_snapshot_with_dynamic;
use gateway::control::reload;
use gateway::observability::access_log::AccessLogger;
use gateway::observability::metrics::Metrics;
use gateway::proxy::{GatewayProxy, ProxyRuntimeState};
use gateway::upstream::discovery::{GatewaySelfRegistration, NacosDiscoveryManager};
use gateway::upstream::DynamicUpstreamStore;

use cli::{config_path, pidfile_path, send_signal, Args, RunMode};
use listener::*;
use stream::*;

/// 业务作用：完成 Naway 进程 bootstrap、控制面/数据面装配、readiness 开放与有序停机。
///
/// 参数说明: 无。
///
/// CLI 与环境变量由 `Args`/配置加载器读取。
///
/// 返回：全部启动与停机步骤成功时返回成功；bootstrap 或不可恢复运行错误返回失败退出。
pub(super) async fn run() -> Result<()> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    let run_mode = args.command.unwrap_or(RunMode::AllInOne);

    // 信号子命令(不启动服务)。
    if let Some(sig) = args.signal.as_deref() {
        return send_signal(sig);
    }

    let cfg_path = config_path(&args);
    // journal来源固定在CLI，必须先核对未完成存储；缺失YAML不能让自动bootstrap绕过永久节点保护。
    let node_journal = journal::prepare(&args, run_mode, &cfg_path)?;
    if node_journal.maintenance {
        return Ok(());
    }

    // 启动自举(对标 Higress 首次启动生成默认配置):检测固定配置目录下的 yml 是否齐全,
    // 缺失则新建最低运行默认(能监听、无路由/不拦任何接口),不覆盖已存在文件。
    gateway::config::bootstrap::ensure(&cfg_path)
        .with_context(|| format!("bootstrap config dir for {}", cfg_path.display()))?;

    // 初始快照(v1)。启动期配置错误直接失败退出(不带病上线)。
    let version = Arc::new(AtomicU64::new(1));
    // 指标对象必须早于服务发现创建，使首轮 registry poll（可能发生在 listener 绑定前）
    // 也不会丢失成功/错误/超时事实；后续数据面、管理面共享同一组原子计数器。
    let metrics = Arc::new(Metrics::default());
    let dynamic_upstreams = DynamicUpstreamStore::new();
    let discovery = NacosDiscoveryManager::with_metrics(dynamic_upstreams.clone(), metrics.clone());
    let snapshot = node_journal
        .build(|| load_snapshot_with_dynamic(&cfg_path, 1, dynamic_upstreams.clone()))
        .with_context(|| format!("load initial config from {}", cfg_path.display()))?;
    node_journal.validate(&snapshot)?;
    if args.admin_operations_migrate
        || args.admin_operations_capacity_status
        || args.admin_operations_capacity_expected.is_some()
        || args.admin_operations_execution_status
        || args.admin_operations_execution_bind
        || args.admin_operations_workflow_migrate
        || args.admin_operations_workflow_status
    {
        #[cfg(not(feature = "admin-operations-pgsql"))]
        anyhow::bail!("operations maintenance requires admin-operations-pgsql");
        #[cfg(feature = "admin-operations-pgsql")]
        {
            // 持久维护必须显式选中权威；纯数据模式不能取得管理数据库变更资格。
            anyhow::ensure!(
                matches!(run_mode, RunMode::Admin | RunMode::AllInOne),
                "operations maintenance requires admin or all-in-one mode"
            );
            let plan = snapshot
                .admin_operations
                .as_ref()
                .context("operations maintenance requires enabled admin.operations")?;
            if args.admin_operations_migrate {
                return admin::operations::migrate(plan).await;
            }
            if args.admin_operations_workflow_migrate || args.admin_operations_workflow_status {
                #[cfg(not(feature = "admin-operations-workflow-pgsql"))]
                anyhow::bail!("workflow maintenance requires admin-operations-workflow-pgsql");
                #[cfg(feature = "admin-operations-workflow-pgsql")]
                {
                    let status = admin::operations::maintain_workflow(
                        plan.clone(),
                        args.admin_operations_workflow_migrate,
                    )
                    .await?;
                    println!("{}", serde_json::to_string(&status)?);
                    return Ok(());
                }
            }
            let status =
                if args.admin_operations_execution_status || args.admin_operations_execution_bind {
                    admin::operations::maintain_execution_namespace(
                        plan.clone(),
                        args.admin_operations_execution_bind,
                    )
                    .await?
                } else {
                    admin::operations::maintain_capacity(
                        plan.clone(),
                        args.admin_operations_capacity_expected.as_deref(),
                    )
                    .await?
                };
            println!("{}", serde_json::to_string(&status)?);
            return Ok(());
        }
    }
    if run_mode.is_sidecar() {
        // sidecar 的本地边界必须在打开任何外部资源前成立；失败直接退出，不能先短暂暴露端口。
        snapshot
            .validate_sidecar_listeners()
            .context("validate sidecar listener isolation")?;
    }
    // 审计 hash-chain/client 是 bootstrap 资源；启动时完整验旧 spool，篡改或 endpoint 配置错误均 fail-fast。
    let admin_audit = gateway::admin::audit::AdminAuditLog::open(&snapshot.admin_audit)
        .context("open admin audit log")?;
    // 日志仍由 nasa::log 统一格式化/滚动/热调级；OTel layer 同挂一个 tracing subscriber，
    // 避免两个全局 subscriber 争用。必须先读 bootstrap telemetry 配置再一次性初始化。
    let telemetry_generation =
        gateway::observability::telemetry::TelemetryRuntime::build(&snapshot.telemetry)
            .context("build OpenTelemetry runtime")?;
    nasa::log::init_with_default_and_layer(
        "gateway=info,info",
        tracing_opentelemetry::layer().with_tracer(telemetry_generation.tracer()),
    );
    // 文件日志必须在开放路由前成功建立；守卫活到全部停机步骤结束，避免缓冲输出提前失去刷盘线程。
    let _process_log_guard = snapshot.process_log.start()?;
    let telemetry =
        gateway::observability::telemetry::SwappableTelemetryRuntime::new(telemetry_generation);
    // reload channel 容量和去抖窗口属 bootstrap 执行参数；worker 建立后不在热更时自重建。
    let reload_cfg = snapshot.reload.clone();
    discovery.reconcile(&snapshot);
    // 管理面监听(与数据面端口隔离);同为 bootstrap 层,启动期绑定一次、热更不重绑。
    let admin_listen: SocketAddr = snapshot
        .admin_listen
        .parse()
        .with_context(|| format!("invalid admin.listen `{}`", snapshot.admin_listen))?;
    // Admin-only 进程不得绑定或启动任何 public 数据面资源；配置仍完整 build，供 dry-run/
    // explain 使用同一份强类型语义，避免控制面校验与数据面执行产生分叉。
    let initial_proxies = if run_mode.runs_data() {
        snapshot.proxies.as_ref().clone()
    } else {
        Vec::new()
    };
    let initial_streams = if run_mode.runs_data() {
        snapshot.stream_listeners.as_ref().clone()
    } else {
        Vec::new()
    };
    // 运行态后端启动期装配:默认 local 零外部依赖;redis 通过 nasa::redis fail-fast 建连。
    let runtime_state_cfg = snapshot.runtime_state.clone();
    let rate_limiter = gateway::runtime::state::build_rate_limiter(&runtime_state_cfg)
        .await
        .context("build runtime rate limiter")?;
    let rate_limiter = Arc::new(gateway::runtime::state::SwappableRateLimiter::new(
        rate_limiter,
    ));
    let proxy_rate_limiter: Arc<dyn gateway::runtime::state::RateLimiter> = rate_limiter.clone();
    metrics.bind_rate_limiter(&proxy_rate_limiter)?;
    let conn_limiter = gateway::runtime::state::build_conn_limiter(&runtime_state_cfg)
        .await
        .context("build runtime conn limiter")?;
    let conn_limiter = Arc::new(gateway::runtime::state::SwappableConnLimiter::new(
        conn_limiter,
    ));
    let proxy_conn_limiter: Arc<dyn gateway::runtime::state::ConnLimiter> = conn_limiter.clone();
    // 熔断统计默认在本地隔离；circuit_breaker.shared=true 时由共享后端维持跨节点事实。
    let circuit_stats = gateway::runtime::state::build_circuit_stats(&runtime_state_cfg)
        .await
        .context("build runtime circuit stats")?;
    let circuit_stats = Arc::new(gateway::runtime::state::SwappableCircuitStats::new(
        circuit_stats,
    ));
    let proxy_circuit_stats: Arc<dyn gateway::runtime::state::CircuitStats> = circuit_stats.clone();
    //  HMAC 防重放守卫:默认 local 内存去重;replay_guard.backend=redis 时跨节点 SET NX PX。
    let replay_guard = gateway::runtime::state::build_replay_guard(&runtime_state_cfg)
        .await
        .context("build runtime replay guard")?;
    let replay_guard = Arc::new(gateway::runtime::state::SwappableReplayGuard::new(
        replay_guard,
    ));
    let proxy_replay_guard: Arc<dyn gateway::runtime::state::ReplayGuard> = replay_guard.clone();
    let dynamic_store = gateway::runtime::state::build_dynamic_store(&runtime_state_cfg, &cfg_path)
        .await
        .context("build runtime dynamic store")?;
    let dynamic_store = Arc::new(gateway::runtime::state::SwappableDynamicStore::new(
        dynamic_store,
    ));
    let proxy_dynamic_store: Arc<dyn gateway::runtime::state::DynamicStore> = dynamic_store.clone();
    let blacklist = Arc::new(
        gateway::security::blacklist::BlacklistCache::new(&runtime_state_cfg.blacklist)
            .context("build runtime blacklist cache")?,
    );
    if blacklist.is_enabled() {
        let collection = blacklist.collection();
        blacklist
            .refresh_from_store(proxy_dynamic_store.as_ref(), &collection)
            .await
            .context("load initial runtime blacklist")?;
    }
    gateway::security::blacklist::spawn_blacklist_refresh(blacklist.clone(), dynamic_store.clone());
    let interface_disable = Arc::new(
        gateway::security::guard::DynamicInterfaceGuardCache::new(
            &runtime_state_cfg.interface_disable,
        )
        .context("build runtime interface disable cache")?,
    );
    if interface_disable.is_enabled() {
        let collection = interface_disable.collection();
        interface_disable
            .refresh_from_store(proxy_dynamic_store.as_ref(), &collection)
            .await
            .context("load initial runtime interface disable")?;
    }
    gateway::security::guard::spawn_interface_disable_refresh(
        interface_disable.clone(),
        dynamic_store.clone(),
    );
    // cache L2 是显式 bootstrap 依赖：local 默认零网络；redis 模式启动期 fail-fast 建连，
    // 运行中 GET/SET 错误仍 fail-open 成普通 miss，不阻断业务数据面。
    let http_cache_generation =
        gateway::cache::http::HttpCacheRuntime::build(&runtime_state_cfg.http_cache)
            .await
            .context("build HTTP cache runtime")?;
    let http_cache = gateway::cache::http::SwappableHttpCacheRuntime::new(http_cache_generation);
    let snap = Arc::new(ArcSwap::from_pointee(snapshot));
    #[cfg(feature = "telemetry-otlp")]
    telemetry
        .bind_metrics(&metrics, &snap)
        .context("register shared telemetry metric catalog")?;
    let usage_meter = gateway::portal::meter::Meter::start(&snap.load().usage_meter);
    let traffic_meter = gateway::observability::meter::Meter::start(&snap.load().traffic_meter);
    let apply_coordinator = Arc::new(reload::SnapshotApplyCoordinator::default());
    // xDS 状态句柄先接入 admin/readiness，网络 task 等 listener supervisor 建好后才启动；
    // 后续 reload 继续复用该句柄并由 generation manager 撤销旧 owner。
    #[cfg(feature = "xds-client")]
    let xds_bootstrap = if run_mode.runs_data() && snap.load().control_plane.xds.enabled {
        let initial = snap.load();
        let specs = initial.upstreams.xds_watch_specs();
        let xds_cfg = initial.control_plane.xds.clone();
        drop(initial);
        Some((xds_cfg, specs))
    } else {
        None
    };
    #[cfg(feature = "xds-client")]
    let xds_status = run_mode.runs_data().then(gateway::control::xds::new_status);
    http_cache.spawn_invalidation_worker(snap.clone());
    let history_root = cfg_path
        .parent()
        .map(|parent| parent.join(".gateway-config-history"))
        .unwrap_or_else(|| PathBuf::from(".gateway-config-history"));
    let config_history = gateway::control::history::ConfigHistory::new(history_root, 128);
    node_journal.attach(&config_history)?;
    {
        let initial = snap.load();
        config_history.record_initial(&cfg_path, &initial);
    }
    // 常驻长连接表必须早于 reload worker 创建，使成功换版可以按全局策略安排 stale drain。
    let conn_registry = gateway::runtime::connections::ConnectionRegistry::new();

    // 就绪标志:数据面监听绑定后置 true;停机时置 false → /readyz 转 503,供前置 LB 摘流。
    let ready = Arc::new(AtomicBool::new(false));
    let active_connections = Arc::new(AtomicU64::new(0));
    let access_log = AccessLogger::spawn(
        metrics.clone(),
        snap.clone(),
        snap.load().access_log.queue_size,
    )
    .context("start access log sinks")?;
    let access_log_shutdown = access_log.clone();
    let stream_access_log = access_log.clone();
    // 管理/观测面(独立内网监听:/healthz /readyz;端口与数据面隔离)。
    // 监听在启动期绑定，失败即 fatal；健康端点是容器部署关键依赖，不能静默缺席。
    // 之后的 accept 循环若 runtime 出错,不影响数据面转发。
    let admin_listener = TcpListener::bind(admin_listen)
        .await
        .with_context(|| format!("bind admin.listen {admin_listen}"))?;
    // 主动健康探测器:后台按服务 health_check 探测上游,不健康实例不进 LB 候选;/readyz 也据它判 critical
    // 可用性。常驻(与快照解耦)、读当前快照的健康目标;与被动摘除叠加成双保险。
    // 在 AdminState 之前构造，让 admin readyz 与数据面选实例共用同一个 checker，保持可用性判定一致。
    let active_health = gateway::upstream::health::ActiveHealthChecker::new(metrics.clone());
    gateway::upstream::health::spawn_active_health(active_health.clone(), snap.clone());

    let admin_state = admin::AdminState::new(
        snap.clone(),
        cfg_path.clone(),
        ready.clone(),
        metrics.clone(),
        conn_registry.clone(),
        active_health.clone(),
        admin::AdminRuntimeState {
            #[cfg(feature = "telemetry-otlp")]
            telemetry: telemetry.clone(),
            usage_meter: usage_meter.clone(),
            traffic_meter: traffic_meter.clone(),
            mode: run_mode.admin_plane_mode(),
            config_history: config_history.clone(),
            dynamic_store: dynamic_store.clone(),
            blacklist: blacklist.clone(),
            interface_disable: interface_disable.clone(),
            http_cache: http_cache.clone(),
            audit: admin_audit.clone(),
            #[cfg(feature = "xds-client")]
            xds_status: xds_status.clone(),
        },
    );
    #[cfg(feature = "node-actions")]
    admin_state.bind_node_action_boot()?;
    #[cfg(feature = "admin-grpc")]
    let management = admin_state.management.clone();
    #[cfg(feature = "admin-operations-pgsql")]
    let operations = admin::operations::start(&admin_state).await?;
    #[cfg(feature = "admin-grpc")]
    let initial_management = management.prepare(&snap.load_full()).await?;
    // proxy 构造在 admin serve 之后,提前留一份句柄以便把边缘订阅索引注入
    // /metrics 渲染;未编 feature 时零残留。
    #[cfg(feature = "grpc-edge")]
    let admin_state_for_edge = admin_state.clone();

    // 代理(持有原子快照 + 常驻上游连接池 + 长连接注册表 + 主动健康检查器)。
    let proxy = GatewayProxy::new(
        snap.clone(),
        metrics.clone(),
        access_log,
        conn_registry.clone(),
        ProxyRuntimeState {
            #[cfg(feature = "webdav")]
            webdav_audit: admin_audit.clone(),
            usage_meter: usage_meter.clone(),
            traffic_meter: traffic_meter.clone(),
            rate_limiter: proxy_rate_limiter,
            conn_limiter: proxy_conn_limiter,
            circuit_stats: proxy_circuit_stats,
            replay_guard: proxy_replay_guard,
            dynamic_store: dynamic_store.clone(),
            blacklist: blacklist.clone(),
            interface_disable: interface_disable.clone(),
            http_cache: http_cache.clone(),
            telemetry: telemetry.clone(),
        },
        active_health.clone(),
    );
    #[cfg(feature = "grpc-edge")]
    admin_state_for_edge.attach_edge_hub(proxy.grpc_edge_hub());
    #[cfg(feature = "grpc-edge")]
    admin_state_for_edge.attach_edge_relay_slot(proxy.edge_relay_slot());
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    admin_state_for_edge.attach_edge_redis_bus_slot(proxy.edge_redis_bus_slot());
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    admin_state_for_edge.attach_edge_redis_stream_slot(proxy.edge_redis_stream_slot());
    // 集群传输随初始快照启动。relay 与 Redis Pub/Sub 已在配置构建期严格互斥，
    // 这里按 mode 只启动其中一条链路，避免重复散出。
    #[cfg(feature = "grpc-edge")]
    if run_mode.runs_data() {
        if let Some(cluster) = snap.load().grpc_edge_cluster.clone() {
            match cluster.mode {
                gateway::config::model::GrpcEdgeClusterModeCfg::Relay => {
                    let membership = cluster.membership;
                    #[cfg(feature = "redis-runtime")]
                    let plan_session_directory = cluster.session_directory.clone();
                    #[cfg(feature = "redis-runtime")]
                    let cluster_identity = (cluster.cluster_id.clone(), cluster.node_id.clone());
                    let relay =
                        gateway::edge::relay::EdgeRelay::start(cluster, proxy.grpc_edge_hub())
                            .await
                            .context("start grpc edge relay")?;
                    if membership == gateway::config::model::GrpcEdgeMembershipCfg::Nacos {
                        relay
                            .start_nacos_membership(snap.load().discovery.nacos.clone())
                            .context("start grpc edge Nacos membership")?;
                    }
                    proxy.attach_edge_relay(relay.clone());
                    // SessionDirectory 只属于 relay 定向寻址；Redis bus 模式不启动它。
                    #[cfg(feature = "redis-runtime")]
                    if let Some(directory_cfg) = plan_session_directory {
                        let proxy_for_directory = proxy.clone();
                        let admin_for_directory = admin_state_for_edge.clone();
                        let boot_id = relay.boot_id();
                        let (cluster_id, node_id) = cluster_identity;
                        tokio::spawn(async move {
                            let mut backoff = std::time::Duration::from_millis(500);
                            loop {
                                match gateway::edge::directory::SessionDirectory::connect(
                                    &directory_cfg,
                                    &cluster_id,
                                    &node_id,
                                    boot_id,
                                )
                                .await
                                {
                                    Ok(directory) => {
                                        proxy_for_directory
                                            .attach_edge_directory(directory.clone());
                                        admin_for_directory.attach_edge_directory(directory);
                                        tracing::info!("edge session directory attached");
                                        return;
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            error = %format!("{error:#}"),
                                            "edge session directory unavailable; push uses broadcast-probe"
                                        );
                                        tokio::time::sleep(backoff).await;
                                        backoff =
                                            (backoff * 2).min(std::time::Duration::from_secs(30));
                                    }
                                }
                            }
                        });
                    }
                }
                gateway::config::model::GrpcEdgeClusterModeCfg::RedisPubsub => {
                    #[cfg(feature = "redis-runtime")]
                    {
                        let bus = gateway::edge::redis_bus::EdgeRedisBus::start(
                            cluster,
                            proxy.grpc_edge_hub(),
                        )
                        .await
                        .context("start grpc edge Redis Pub/Sub bus")?;
                        proxy.attach_edge_redis_bus(bus);
                    }
                    #[cfg(not(feature = "redis-runtime"))]
                    unreachable!("redis_pubsub plan requires redis-runtime at build time");
                }
                gateway::config::model::GrpcEdgeClusterModeCfg::RedisStream => {
                    #[cfg(feature = "redis-runtime")]
                    {
                        let bus = gateway::edge::redis_bus::EdgeRedisStreamBus::start(
                            cluster,
                            proxy.grpc_edge_hub(),
                        )
                        .await
                        .context("start grpc edge Redis Stream bus")?;
                        proxy.attach_edge_redis_stream(bus);
                    }
                    #[cfg(not(feature = "redis-runtime"))]
                    unreachable!("redis_stream plan requires redis-runtime at build time");
                }
                gateway::config::model::GrpcEdgeClusterModeCfg::None => {}
            }
        }
    }
    admin_state.attach_upstream_health(proxy.upstream_health_runtime());
    proxy.reconcile_runtime_identities(&snap.load());
    #[cfg(feature = "upstream-orca")]
    let orca_worker = run_mode.runs_data().then(|| proxy.spawn_upstream_orca());
    if run_mode.runs_data() {
        // 连接预热使用与真实转发完全相同的 Hyper client cache/物理 socket 预算。worker 会
        // 自动识别 reload 与动态发现新增实例；只预热一次，不把它变成周期业务探测。
        proxy.spawn_upstream_prewarm();
    }
    let data_plane = DataPlaneState {
        snap: snap.clone(),
        proxy: proxy.clone(),
        connection_budget: Arc::new(ConnectionBudget::default()),
        #[cfg(feature = "http3")]
        http3_peer_connection_budget: Arc::new(Http3PeerConnectionBudget::default()),
        active_connections: active_connections.clone(),
        metrics: metrics.clone(),
    };
    let stream_lb = StreamLbState {
        health: proxy.upstream_health_runtime(),
        ..StreamLbState::default()
    };
    let stream_plane = StreamPlaneState {
        snap: snap.clone(),
        workspace_proxy: proxy.clone(),
        active_health: active_health.clone(),
        lb: stream_lb,
        active_connections: active_connections.clone(),
        metrics: metrics.clone(),
        access_log: stream_access_log,
        #[cfg(feature = "mqtt-governance")]
        mqtt_connections: MqttConnectionBudget::default(),
        #[cfg(feature = "kafka-governance")]
        kafka_connections: KafkaConnectionBudget::default(),
    };

    let mut bound_proxies = Vec::with_capacity(initial_proxies.len());
    for proxy_cfg in &initial_proxies {
        bound_proxies.push(bind_proxy(proxy_cfg).await?);
    }
    let mut bound_streams = Vec::with_capacity(initial_streams.len());
    for stream_cfg in &initial_streams {
        bound_streams.push(bind_stream(stream_cfg).await?);
    }

    // pidfile 供 `-s reload` 定位进程，必须在两个 listener 都绑定成功之后写入——
    // 否则启动期 bind 失败(如 admin/data 端口被占)会残留一个指向已退出进程的 stale pidfile。
    let pf = pidfile_path();
    std::fs::write(&pf, std::process::id().to_string())
        .with_context(|| format!("write pidfile {}", pf.display()))?;

    let deferred_tls = DeferredTlsReadiness {
        pending: Arc::new(AtomicU64::new(0)),
        ready: ready.clone(),
        stopping: Arc::new(AtomicBool::new(false)),
    };
    // ACME 的 provider 与分布式锁也属于候选资源：启动 generation 前完整 prepare，避免 listener
    // 已开放后才发现续期权威不可用。真正签发任务要等 HTTP listener 激活后再启动。
    let initial_acme = if run_mode.runs_data() {
        Some(
            gateway::tls::acme::prepare_acme_workers(
                initial_proxies.iter().filter_map(|proxy| proxy.tls.clone()),
                runtime_state_cfg.clone(),
                proxy.acme_http01_store(),
            )
            .await
            .context("prepare initial ACME workers")?,
        )
    } else {
        None
    };
    let listener_supervisor = Arc::new(ListenerSupervisor::new(
        data_plane,
        stream_plane,
        admin_state.clone(),
        proxy.acme_http01_store(),
        run_mode.runs_data(),
        deferred_tls.clone(),
    ));
    let initial_snapshot = snap.load_full();
    #[cfg(feature = "xds-server")]
    let xds_server_manager =
        gateway::control::xds_server::Manager::new(snap.clone(), admin_audit.clone());
    #[cfg(feature = "xds-server")]
    let initial_xds_server = xds_server_manager.prepare(&initial_snapshot).await?;
    // 所有资源准备完成但尚未接流；持久文件记录先与初始候选核对并结束，失败不能开放监听。
    config_history.complete_local_publication(&initial_snapshot)?;
    // 初始 ArcSwap 已装配且资源全部准备完成，先确认原动作效果；失败保留方向并拒绝首次接流。
    config_history.confirm_action_publication(&initial_snapshot)?;
    let (proxy_log, stream_log) = listener_supervisor.install_initial(
        initial_snapshot.as_ref(),
        bound_proxies,
        bound_streams,
        admin_listener,
        admin_listen,
        initial_acme,
    );
    #[cfg(feature = "xds-server")]
    initial_xds_server.commit();
    #[cfg(feature = "admin-grpc")]
    {
        // 所有业务监听已经安装，管理接流和主动上报才获得当前运行事实的发布权。
        initial_management.commit().await;
        management.start_reporter(&admin_state);
    }
    drop(initial_snapshot);

    #[cfg(feature = "xds-client")]
    let xds_manager = if run_mode.runs_data() {
        let manager = gateway::control::xds::XdsGenerationManager::new(
            dynamic_upstreams.clone(),
            gateway::control::xds::XdsSnapshotRuntime {
                snap: snap.clone(),
                version: version.clone(),
                apply_coordinator: apply_coordinator.clone(),
                cfg_path: cfg_path.clone(),
                config_history: config_history.clone(),
                listener_topology: Some(listener_supervisor.clone()),
            },
            xds_status
                .as_ref()
                .expect("data plane has a pre-created xDS status")
                .clone(),
        );
        if let Some((xds_cfg, specs)) = xds_bootstrap {
            manager.start_initial(xds_cfg, specs);
        }
        Some(manager)
    } else {
        None
    };

    // listener 已进入 supervisor 后再启动唯一 reload worker；从此数据面拓扑也遵守
    // bind/build → ArcSwap publish → accept generation handoff 的同一事务边界。
    let reload_handle = reload::spawn(
        cfg_path.clone(),
        snap.clone(),
        version.clone(),
        reload::ReloadRuntime {
            apply_coordinator: apply_coordinator.clone(),
            dynamic_upstreams: dynamic_upstreams.clone(),
            discovery: discovery.clone(),
            rate_limiter: rate_limiter.clone(),
            conn_limiter: conn_limiter.clone(),
            circuit_stats: circuit_stats.clone(),
            replay_guard: replay_guard.clone(),
            dynamic_store: dynamic_store.clone(),
            blacklist: blacklist.clone(),
            interface_disable: interface_disable.clone(),
            conn_registry: conn_registry.clone(),
            proxy: Some(proxy.clone()),
            sidecar_mode: run_mode.is_sidecar(),
            listener_topology: Some(listener_supervisor.clone()),
            access_log: Some(access_log_shutdown.clone()),
            admin_audit: Some(admin_audit.clone()),
            http_cache: Some(http_cache.clone()),
            telemetry: Some(telemetry.clone()),
            #[cfg(feature = "xds-client")]
            xds: xds_manager.clone(),
            #[cfg(feature = "xds-server")]
            xds_server: Some(xds_server_manager.clone()),
            #[cfg(feature = "admin-grpc")]
            management: Some(management.clone()),
        },
        config_history.clone(),
        reload_cfg,
    );
    // Kubernetes 对象只在后台编译成物化候选，并通过上面的唯一 reload worker 发布。
    gateway::control::kubernetes::spawn_controller(snap.clone(), cfg_path.clone(), reload_handle);
    // 无 seed ACME 首签期间 TLS socket 虽已绑定但尚不 accept；readiness 必须保持 503，避免 LB
    // 把业务流量送到只有 challenge 能力的半就绪节点。最后一个 deferred listener 激活时会置 true。
    if deferred_tls.pending.load(Ordering::Acquire) == 0 {
        ready.store(true, Ordering::Release);
    }
    // 网关节点自注册:后台只感知快照变化并写注册中心,请求热路径不访问 Nacos。
    #[cfg(feature = "xds-client")]
    let registration_control_ready: Arc<dyn Fn() -> bool + Send + Sync> = match &xds_status {
        Some(status) => {
            let status = status.clone();
            let snapshot = snap.clone();
            Arc::new(move || !snapshot.load().control_plane.xds.enabled || status.ready())
        }
        None => Arc::new(|| true),
    };
    #[cfg(not(feature = "xds-client"))]
    let registration_control_ready: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(|| true);
    let self_registration = run_mode.runs_data().then(|| {
        GatewaySelfRegistration::spawn(
            snap.clone(),
            ready.clone(),
            active_health.clone(),
            registration_control_ready,
        )
    });
    info!(
        proxies = %proxy_log.join(","),
        streams = %stream_log.join(","),
        %admin_listen,
        config = %cfg_path.display(),
        mode = ?run_mode,
        "gateway started"
    );

    // 优雅退出:Ctrl-C 停 accept、清 pidfile。
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
            // 停机:先置 /readyz=503(前置 LB 摘流)。
            _ = sigint.recv() => {
                info!("SIGINT received, shutting down"); ready.store(false, Ordering::Relaxed);
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down"); ready.store(false, Ordering::Relaxed);
            }
    }
    #[cfg(feature = "xds-server")]
    xds_server_manager.shutdown();
    #[cfg(feature = "admin-grpc")]
    management.shutdown().await;
    #[cfg(feature = "admin-operations-pgsql")]
    if let Some(operations) = operations {
        // 停止数据库入口后仍由提交收据恢复未知结果，不能在停机时重放未确认动作。
        operations.close().await;
    }
    #[cfg(feature = "upstream-orca")]
    if let Some(worker) = orca_worker {
        // 停止接入前先撤销后台反馈，长流排空期间不再为已退出节点建立新订阅。
        worker.abort();
        let _ = worker.await;
    }
    let deregister_timeout_ms = snap
        .load()
        .discovery
        .nacos
        .self_register
        .deregister_timeout_ms;
    if let Some(self_registration) = self_registration {
        self_registration.deregister(deregister_timeout_ms).await;
    }
    // supervisor 停止所有当前 accept generation；已建 HTTP/TCP 连接仍独立持有 IO，
    // 随后由统一 active_connections 预算等待自然 drain。
    usage_meter.stop_admissions();
    traffic_meter.stop_admissions();
    listener_supervisor.shutdown();

    let drain_timeout_ms = snap
        .load()
        .proxies
        .iter()
        .map(|proxy| proxy.timeouts.drain_timeout_ms)
        .max()
        .unwrap_or(0);
    if drain_timeout_ms > 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(drain_timeout_ms);
        while active_connections.load(Ordering::Relaxed) > 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[cfg(feature = "rate-preallocation")]
    {
        // 已在途准入结束后撤销批领并等待有限归还；超时不猜测退款，也不延迟进程永久退出。
        gateway::runtime::state::RateLimiter::shutdown_preallocation(
            rate_limiter.as_ref(),
            Duration::from_millis(1000),
        )
        .await;
    }
    // 已停止新入口且完成连接 drain 后再等结束事实，故障时由固定预算退出并保留远端 incomplete 证据。
    if !usage_meter
        .flush(Duration::from_millis(drain_timeout_ms.min(5000)))
        .await
    {
        warn!("usage meter flush deadline reached; remote admissions may remain incomplete");
    }
    if !traffic_meter
        .flush(Duration::from_millis(drain_timeout_ms.min(5000)))
        .await
    {
        warn!("traffic meter flush deadline reached; remote admissions may remain incomplete");
    }
    let _ = std::fs::remove_file(&pf);
    if let Err(error) = access_log_shutdown.shutdown().await {
        warn!(%error, "access log sink shutdown/flush failed");
    }
    if let Err(error) = telemetry.shutdown() {
        warn!(%error, "OpenTelemetry shutdown/flush failed");
    }
    info!("gateway stopped");
    Ok(())
}
