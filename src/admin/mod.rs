//! 管理 / 观测面( )。
//!
//! 与数据面端口隔离：默认绑定回环地址 `127.0.0.1:18080`，提供健康、就绪、指标、
//! admin API 与 Web UI。管理面不可用时，数据面继续使用已发布的快照转发。
//!
//! 当前管理面优先提供部署所需的健康、就绪与指标端点：
//! - `GET /healthz`:liveness,进程活着即 200(不看依赖),供容器 / K8s 判是否重启。
//! - `GET /readyz`:readiness,配置已加载且数据面监听就绪 → 200,否则 503(供前置 LB / K8s 判是否分流)。

pub mod audit;
mod candidate;
use candidate::build as build_cluster_candidate_snapshot;
mod catalog;
mod cluster;
#[cfg(feature = "telemetry-otlp")]
mod diagnostics;
mod diff;
use diff::semantic_config_diff;
#[cfg(feature = "admin-grpc")]
pub mod management;
mod monitor;
#[cfg(feature = "admin-operations-pgsql")]
pub mod operations;
mod portal;
mod publication;
use publication::{publish_document_set, publish_scoped_document_set, publish_validated_config};
#[cfg(feature = "config-providers")]
mod providers;
mod session;
mod ui;
mod workspaces;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use futures::stream::{self, StreamExt as _};
use http::request::Parts as AdminRequestParts;
use http_body_util::BodyExt;
use hyper::{Method, Response, StatusCode};
use nasa::web::{Request as AdminRequest, Router, State};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::model::{AdminAction, AdminResource};
use crate::config::GatewaySnapshot;
use crate::control::history::ConfigHistory;
use crate::observability::metrics::{DeveloperApplicationMetric, Metrics};
use crate::runtime::connections::ConnectionRegistry;
use crate::runtime::state::{DynamicStore, SwappableDynamicStore};
use crate::security::auth::{
    basic_authorization_matches, bearer_authorization_matches, escape_header_quote,
};
use crate::{full_body, BoxBody};

/// 当前进程对管理端口开放的能力边界。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminPlaneMode {
    /// 数据节点：只开放健康、指标、reload/status 等最小节点运维接口。
    Data,
    /// service-mesh sidecar：权限与 Data 相同，但 status 明确暴露部署 profile。
    Sidecar,
    /// 独立控制面：开放完整 admin API/UI，但不承载数据流量。
    Admin,
    /// 小规模兼容形态：完整管理面与数据面同进程。
    AllInOne,
}

impl AdminPlaneMode {
    /// 业务作用：判断当前进程是否拥有完整控制面写权限与 UI。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅独立 admin 与 all-in-one 返回 true；data/sidecar 均保持最小权限。
    fn full_control_plane(self) -> bool {
        matches!(self, Self::Admin | Self::AllInOne)
    }

    /// 业务作用：判断 readiness 是否必须同时检查数据面 listener 与关键上游。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：data、sidecar、all-in-one 返回 true，纯 admin 返回 false。
    fn runs_data(self) -> bool {
        matches!(self, Self::Data | Self::Sidecar | Self::AllInOne)
    }
}

/// 管理面共享状态:只读引用数据面的配置快照 + 就绪标志(不持有任何数据面连接)。
pub struct AdminState {
    /// 常驻断言去重域：撤销旧会话不等于允许旧签名断言重放。
    portal_saml_replay: crate::security::enterprise_identity::PortalSamlReplay,
    /// 与数据面共用的计量 owner；分析权限仍由当前门户团队映射裁决。
    usage_meter: Arc<crate::portal::meter::Meter>,
    traffic_meter: Arc<crate::observability::meter::Meter>,
    /// CLI 选择的部署平面，启动后固定，热更不能扩大控制面权限。
    mode: AdminPlaneMode,
    /// 与数据面共享的同一份原子配置快照(用于 /readyz 报告当前版本,后续 admin 读配置)。
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// 本地 bootstrap 配置路径,供 `/admin/config/dry-run` 做只读候选快照构建。
    cfg_path: PathBuf,
    /// 配置 reload 历史与本地 rollback 归档。
    config_history: ConfigHistory,
    /// 候选许可覆盖实际阻塞工作与清理，所有管理入口共用同一有界容量。
    candidate_builds: candidate::Admission,
    /// 数据面是否已就绪(监听已绑定、可接流量);停机时置 false → /readyz 转 503,供 LB 摘流。
    ready: Arc<AtomicBool>,
    /// xDS require_xds 独立启动门与低基数状态；未启用 xDS 时为 None。
    #[cfg(feature = "xds-client")]
    xds_status: Option<Arc<crate::control::xds::XdsStatus>>,
    metrics: Arc<Metrics>,
    #[cfg(feature = "telemetry-otlp")]
    telemetry: Arc<crate::observability::telemetry::SwappableTelemetryRuntime>,
    /// 长连接注册表：/metrics 据此输出 gw_long_connections 低基数指标。
    conn_registry: Arc<ConnectionRegistry>,
    /// 边缘订阅索引(仅 /metrics 渲染读取)。启动期由 main 注入一次;admin-only
    /// 进程没有数据面,保持未注入即不渲染 edge gauge。
    #[cfg(feature = "grpc-edge")]
    edge_hub: std::sync::OnceLock<Arc<crate::edge::hub::EdgeHub>>,
    /// 集群中继运行时；仅供 `/metrics` 渲染读取，单机部署保持未注入。
    #[cfg(feature = "grpc-edge")]
    edge_relay: std::sync::OnceLock<Arc<arc_swap::ArcSwapOption<crate::edge::relay::EdgeRelay>>>,
    /// Redis Pub/Sub 集群总线观测；配置保证与 relay 互斥。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_redis_bus:
        std::sync::OnceLock<Arc<arc_swap::ArcSwapOption<crate::edge::redis_bus::EdgeRedisBus>>>,
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_redis_stream: std::sync::OnceLock<
        Arc<arc_swap::ArcSwapOption<crate::edge::redis_bus::EdgeRedisStreamBus>>,
    >,
    /// 可选 SessionDirectory 指路条；仅供 `/metrics` 渲染，`session_registry=none` 时未注入。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_directory: std::sync::OnceLock<Arc<crate::edge::directory::SessionDirectory>>,
    /// 集群发布登记(进程内有界,重启归零;事实源仍是 Nacos + 成员表)。
    rollouts: RolloutRegistry,
    /// 高危管理变更待审批队列；候选受容量和 TTL 约束，执行前仍复验配置/证书 CAS。
    approvals: ApprovalRegistry,
    /// 管理构建与长轮询分别限额；工作区不能耗尽其它域的操作槽。
    workspace_operations: crate::control::ownership::admission::Runtime,
    workspace_watches: crate::control::ownership::admission::Runtime,
    /// 主动健康探测器：/readyz 据此判「critical 服务是否还有主动健康的实例」，与数据面选实例保持一致。
    active_health: Arc<crate::upstream::health::ActiveHealthChecker>,
    /// 与 L7/L4 共用的被动健康状态；未挂接数据面时只展示配置，不创建运行态。
    upstream_health: std::sync::OnceLock<Arc<crate::upstream::passive::Registry>>,
    /// 运行态动态事实源。admin 黑名单写入走同一 DynamicStore,避免绕过 Redis/file 后端。
    dynamic_store: Arc<SwappableDynamicStore>,
    /// 本节点黑名单缓存。admin 写入成功后立即刷新,无需等待周期任务。
    blacklist: Arc<crate::security::blacklist::BlacklistCache>,
    /// 本节点动态接口禁用缓存。admin 写入成功后立即刷新,无需等待周期任务。
    interface_disable: Arc<crate::security::guard::DynamicInterfaceGuardCache>,
    /// HTTP cache L2 与 generation 失效总线。
    http_cache: Arc<crate::cache::http::SwappableHttpCacheRuntime>,
    /// 管理写操作 append-only HMAC 审计与外部持久 sink。
    audit: crate::admin::audit::AdminAuditLog,
    /// 集群流量计数器的上次成功采样；仅用于把单调 counter 换算为节点速率。
    cluster_metric_samples: parking_lot::Mutex<HashMap<String, ClusterMetricSample>>,
    /// 实时监控共享采样；没有观察者时释放基线，不存储监控历史。
    monitor: monitor::Runtime,
    cluster: cluster::Runtime,
    /// 所有集群读面共用惰性有界成员查询，不随请求重建SDK运行时。
    member_discovery: cluster::discovery::Runtime,
    /// 与上报共享当前配置对象目录；不进入普通请求执行链。
    catalog: catalog::Runtime,
    /// 启动期安装的持久提案权威；纯数据节点不创建数据库资源。
    #[cfg(feature = "admin-operations-pgsql")]
    operations: std::sync::OnceLock<Arc<operations::Store>>,
    /// 独立mTLS节点上报与接收；多管理监听共享同一个生命周期。
    #[cfg(feature = "admin-grpc")]
    pub management: Arc<management::Manager>,
}

/// 管理面需要写入/刷新的一组运行态依赖。
pub struct AdminRuntimeState {
    /// 与数据面共享诊断审批和限时样本目录，不为管理面另建采集 owner。
    #[cfg(feature = "telemetry-otlp")]
    pub telemetry: Arc<crate::observability::telemetry::SwappableTelemetryRuntime>,
    /// 启动期创建、不会随应用候选发布重建的外部计量 owner。
    pub usage_meter: Arc<crate::portal::meter::Meter>,
    /// 独立流量事件的进程级容量与传输指标来源。
    pub traffic_meter: Arc<crate::observability::meter::Meter>,
    /// CLI 选择的部署平面；作为启动期依赖与其余常驻管理资源一起传入。
    pub mode: AdminPlaneMode,
    /// 配置版本历史与本地归档。
    pub config_history: ConfigHistory,
    /// 运行态事实源,用于 admin 写入黑名单和动态接口禁用。
    pub dynamic_store: Arc<SwappableDynamicStore>,
    /// 本节点黑名单缓存。
    pub blacklist: Arc<crate::security::blacklist::BlacklistCache>,
    /// 本节点动态接口禁用缓存。
    pub interface_disable: Arc<crate::security::guard::DynamicInterfaceGuardCache>,
    /// HTTP response cache runtime，供 route 级 PURGE。
    pub http_cache: Arc<crate::cache::http::SwappableHttpCacheRuntime>,
    /// 管理操作持久审计器。
    pub audit: crate::admin::audit::AdminAuditLog,
    /// xDS EDS 客户端状态；只读挂接到 readiness/metrics/admin status。
    #[cfg(feature = "xds-client")]
    pub xds_status: Option<Arc<crate::control::xds::XdsStatus>>,
}

impl AdminState {
    /// 业务作用：挂接唯一数据面被动健康状态，管理读取不另行采样或建立实例目录。
    ///
    /// 参数说明：
    /// - `registry`：L7/L4 共享的进程运行态。
    ///
    /// 返回：首次挂接生效，后续调用不替换已经共享的状态。
    pub fn attach_upstream_health(&self, registry: Arc<crate::upstream::passive::Registry>) {
        let _ = self.upstream_health.set(registry);
    }
    /// 业务作用：挂接边缘订阅索引;仅 /metrics 渲染读取。一次性注入,后到者忽略。
    #[cfg(feature = "grpc-edge")]
    pub fn attach_edge_hub(&self, hub: Arc<crate::edge::hub::EdgeHub>) {
        let _ = self.edge_hub.set(hub);
    }

    /// 业务作用：把数据面 relay generation slot 挂到管理面，使 metrics 始终读取热换代后的当前代。
    ///
    /// 参数说明：
    /// - `relay`：是 Proxy 与 reload 共同持有的原子 relay slot。
    ///
    /// 返回：无返回值；只接受首次注入，重复调用不会替换已共享的 slot。
    #[cfg(feature = "grpc-edge")]
    pub fn attach_edge_relay_slot(
        &self,
        relay: Arc<arc_swap::ArcSwapOption<crate::edge::relay::EdgeRelay>>,
    ) {
        let _ = self.edge_relay.set(relay);
    }

    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    /// 业务作用：共享 Pub/Sub 当前代 slot，避免热更后 metrics 继续读取已撤权代。
    ///
    /// 参数说明：
    /// - `bus`：是 Proxy 持有的原子 slot。
    ///
    /// 返回：无返回值；只接受启动期首次接线。
    pub fn attach_edge_redis_bus_slot(
        &self,
        bus: Arc<arc_swap::ArcSwapOption<crate::edge::redis_bus::EdgeRedisBus>>,
    ) {
        let _ = self.edge_redis_bus.set(bus);
    }

    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    /// 业务作用：共享 Redis Stream 当前代 slot，保证管理观测与数据发布使用同一 owner。
    ///
    /// 参数说明：
    /// - `bus`：是 Proxy 持有的原子 slot。
    ///
    /// 返回：无返回值；只接受启动期首次接线。
    pub fn attach_edge_redis_stream_slot(
        &self,
        bus: Arc<arc_swap::ArcSwapOption<crate::edge::redis_bus::EdgeRedisStreamBus>>,
    ) {
        let _ = self.edge_redis_stream.set(bus);
    }

    /// 业务作用：挂接仅供 `/metrics` 读取的 SessionDirectory 指路条，保持运行时身份唯一。
    ///
    /// 参数说明：
    /// - `directory`：是已完成连接与配置校验的进程级目录句柄。
    ///
    /// 返回：无；只接受首次注入，后到句柄忽略。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_directory(&self, directory: Arc<crate::edge::directory::SessionDirectory>) {
        let _ = self.edge_directory.set(directory);
    }

    /// 业务作用：构造管理面共享状态，并把 listener、关键上游与可选 xDS readiness 事实接到同一读面。
    ///
    /// 参数说明：
    /// - `snap`：当前不可变配置快照的原子槽。
    /// - `cfg_path`：主配置文件路径。
    /// - `ready`：监听器就绪标记。
    /// - `metrics`：常驻指标目录。
    /// - `conn_registry`：长连接注册表。
    /// - `active_health`：主动健康探测状态。
    /// - `runtime_state`：共享运行态及附加控制面就绪状态。
    ///
    /// 返回：所有句柄封装成共享 `AdminState`；不打开 socket、不执行外部写操作。
    pub fn new(
        snap: Arc<ArcSwap<GatewaySnapshot>>,
        cfg_path: PathBuf,
        ready: Arc<AtomicBool>,
        metrics: Arc<Metrics>,
        conn_registry: Arc<ConnectionRegistry>,
        active_health: Arc<crate::upstream::health::ActiveHealthChecker>,
        runtime_state: AdminRuntimeState,
    ) -> Arc<Self> {
        Arc::new(Self {
            mode: runtime_state.mode,
            #[cfg(feature = "admin-grpc")]
            management: management::Manager::new(snap.clone(), runtime_state.mode),
            snap,
            cfg_path,
            #[cfg(feature = "grpc-edge")]
            edge_hub: std::sync::OnceLock::new(),
            #[cfg(feature = "grpc-edge")]
            edge_relay: std::sync::OnceLock::new(),
            #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
            edge_redis_bus: std::sync::OnceLock::new(),
            #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
            edge_redis_stream: std::sync::OnceLock::new(),
            #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
            edge_directory: std::sync::OnceLock::new(),
            rollouts: RolloutRegistry::new(),
            approvals: ApprovalRegistry::new(),
            workspace_operations: Default::default(),
            workspace_watches: Default::default(),
            config_history: runtime_state.config_history,
            candidate_builds: candidate::Admission::new(),
            ready,
            #[cfg(feature = "xds-client")]
            xds_status: runtime_state.xds_status,
            metrics,
            #[cfg(feature = "telemetry-otlp")]
            telemetry: runtime_state.telemetry,
            conn_registry,
            active_health,
            upstream_health: std::sync::OnceLock::new(),
            dynamic_store: runtime_state.dynamic_store,
            blacklist: runtime_state.blacklist,
            interface_disable: runtime_state.interface_disable,
            http_cache: runtime_state.http_cache,
            audit: runtime_state.audit,
            usage_meter: runtime_state.usage_meter,
            traffic_meter: runtime_state.traffic_meter,
            portal_saml_replay: Default::default(),
            cluster_metric_samples: parking_lot::Mutex::new(HashMap::new()),
            monitor: monitor::Runtime::new(),
            cluster: cluster::Runtime::new(),
            member_discovery: Default::default(),
            catalog: catalog::Runtime::default(),
            #[cfg(feature = "admin-operations-pgsql")]
            operations: std::sync::OnceLock::new(),
        })
    }
}

#[cfg(feature = "node-actions")]
impl AdminState {
    /// 业务作用：在任何管理上报或业务监听开放前绑定同一监控 boot，节点效果不得使用独立进程身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：动作开关要求的永久 owner 已安装且 boot 绑定成功才可继续；缺失权威或身份冲突拒绝开放监听。
    pub fn bind_node_action_boot(&self) -> anyhow::Result<()> {
        self.config_history.validate_candidate(&self.snap.load())?;
        self.config_history.bind_action_boot(self.monitor.boot_id())
    }
}

/// 业务作用：运行一个可代际停止的管理面 accept generation，单连接错误不拖垮数据面。
///
/// 参数说明：
/// - `listener`：是 prepare 阶段已绑定 socket
/// - `state`：是共享管理状态
/// - `shutdown`：在候选发布后关闭旧代。
///
/// 返回：监听器正常 drain 或服务错误后返回；服务错误只记录告警，不触发进程 panic/abort。
pub async fn serve_until(
    listener: TcpListener,
    state: Arc<AdminState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let local = listener.local_addr().ok();
    info!(?local, "admin plane listening (nasa::web + axum)");
    monitor::start(&state);
    cluster::start(&state);
    // 注解路由先由链接期表装配，成熟的精确分发器作为 fallback；当前注解只声明
    // method/path/content-type，认证/RBAC/审计仍由统一 dispatch 执行。使用显式 empty runtime
    // 做启动审计，不能再走会忽略未来安全元数据的 deprecated register_all 兼容入口。
    let mapping_runtime = Arc::new(nasa::web::MappingRuntime::empty());
    let mapping_plan = nasa::web::MappingPlan::new().with_runtime(mapping_runtime.clone());
    let mvc = match crate::__mvc::try_register_all(
        Router::new(),
        mapping_runtime,
        mapping_plan,
        state.clone(),
    ) {
        Ok(router) => router,
        Err(error) => {
            warn!(%error, "admin MVC route audit failed");
            return;
        }
    };
    let app = mvc.fallback(legacy_admin_handler).with_state(state);
    let graceful_shutdown = async move {
        loop {
            if *shutdown.borrow() || shutdown.changed().await.is_err() {
                return;
            }
        }
    };
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(graceful_shutdown)
        .await
    {
        // Admin task 退出不会 panic/abort 数据面；主进程仍由数据 listener 与信号生命周期管理。
        warn!(%error, "admin axum server stopped");
    }
}

/// 业务作用：未迁到 MVC 注解的管理 API fallback；仍复用统一 dispatch 安全前置链。
///
/// 参数说明：
/// - `state`: axum 注入的进程级管理状态。
/// - `req`: axum 已解析的管理 HTTP 请求。
async fn legacy_admin_handler(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：`nasa::web` 编译期注册的管理 UI 入口；实际认证/RBAC 仍统一走 dispatch。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: UI 文档请求。
#[nasa::web::get_mapping(path = "/", produces = "text/html; charset=utf-8")]
pub async fn admin_ui_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：`nasa::web` 注册的 UI 样式资产。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: CSS 请求。
#[nasa::web::get_mapping(path = "/ui/app.css", produces = "text/css; charset=utf-8")]
pub async fn admin_ui_css_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：`nasa::web` 注册的无框架 UI 脚本；DOM 写入全部使用 textContent，避免服务端数据触发 XSS。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: JavaScript 请求。
#[nasa::web::get_mapping(
    path = "/ui/app.js",
    produces = "application/javascript; charset=utf-8"
)]
pub async fn admin_ui_js_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：`nasa::web` 注册的 UI 聚合读模型；只读当前本地快照/运行态，不触发远端写操作。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: dashboard API 请求。
#[nasa::web::get_mapping(path = "/api/dashboard", produces = "application/json")]
pub async fn admin_dashboard_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：`nasa::web` 注册的候选 gateway.yml dry-run；body 有显式上限且绝不覆盖真实配置。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: `application/yaml` 候选配置请求。
#[nasa::web::post_mapping(
    path = "/api/config/dry-run",
    consumes = "application/yaml",
    produces = "application/json"
)]
pub async fn admin_candidate_dry_run_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：读取当前主 YML(带 `ETag`),供 Console 编辑器载入并作为后续 CAS 发布的基线。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: 只读请求(无 body)。
#[nasa::web::get_mapping(path = "/api/config/current", produces = "application/json")]
pub async fn admin_config_current_read_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：发布 Console 编辑后的主 YML(`If-Match` CAS + 候选校验 + 确认生效)。
///
/// 参数说明：
/// - `state`: MVC router 注入的管理状态。
/// - `req`: `application/yaml` 候选配置请求,必须带 `If-Match`。
#[nasa::web::put_mapping(
    path = "/api/config/current",
    consumes = "application/yaml",
    produces = "application/json"
)]
pub async fn admin_config_current_publish_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// 业务作用：管理面统一安全分发：认证 → Origin → 平面边界 → RBAC → 审计 → handler；未知路径 404。
async fn dispatch(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    #[cfg(feature = "admin-operations-pgsql")]
    if req.uri().path() == "/api/operations/proposals"
        || req.uri().path().starts_with("/api/operations/proposals/")
    {
        // 持久事务有独立且较大的异步状态机；只在该慢路径分配，避免扩大所有管理请求的栈帧。
        return Box::pin(operations::handle(req, state)).await;
    }
    if req.method() == Method::GET {
        // 静态壳没有业务数据；认证在API入口执行，Bearer使用者才能先加载登录界面。
        if let Some(response) = ui::asset(req.uri().path(), &state) {
            return response;
        }
    }
    #[cfg(feature = "config-providers")]
    if req.uri().path() == "/api/providers" || req.uri().path().starts_with("/api/providers/") {
        return providers::handle(req, state).await;
    }
    #[cfg(feature = "telemetry-otlp")]
    if req.uri().path() == "/api/diagnostics" || req.uri().path().starts_with("/api/diagnostics/") {
        return diagnostics::handle(req, state).await;
    }
    if req.method() == Method::GET
        && state.mode.full_control_plane()
        && state.snap.load().ownership.enabled()
    {
        let asset = match req.uri().path() {
            "/workspaces" => Some((
                "text/html; charset=utf-8",
                include_bytes!("assets/workspaces.html").as_slice(),
            )),
            "/ui/workspaces.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("assets/workspaces.js").as_slice(),
            )),
            "/ui/workspaces.css" => Some((
                "text/css; charset=utf-8",
                concat!(
                    include_str!("assets/console.css"),
                    "\n",
                    include_str!("assets/workspaces.css")
                )
                .as_bytes(),
            )),
            _ => None,
        };
        // 页面壳不含租户状态或凭据；所有业务读取与动作仍必须通过认证后的工作区 API。
        if let Some((content_type, body)) = asset {
            return admin_ui_asset(content_type, Bytes::from_static(body));
        }
    }
    if req.uri().path() == "/api/workspaces" || req.uri().path().starts_with("/api/workspaces/") {
        return workspaces::handle(req, state).await;
    }
    if req.method() == Method::POST && req.uri().path() == "/api/explain" {
        return explain_route_request(req, state).await;
    }
    if req.method() == Method::POST
        && req.uri().path().starts_with("/api/config/")
        && req.uri().path().ends_with("/diff")
    {
        return semantic_config_diff(req, state).await;
    }
    if req.method() == Method::POST && req.uri().path() == "/api/config/dry-run" {
        return dry_run_submitted_config(req, state).await;
    }
    if req.method() == Method::PUT && req.uri().path() == "/api/config/current" {
        return publish_current_config(req, state).await;
    }
    if req.method() == Method::PUT && req.uri().path() == "/api/sentinel" {
        return publish_sentinel_config(req, state).await;
    }
    if matches!(req.method(), &Method::POST | &Method::DELETE)
        && (req.uri().path() == "/api/consumers" || req.uri().path().starts_with("/api/consumers/"))
    {
        return mutate_consumers(req, state).await;
    }
    if req.method() == Method::POST && req.uri().path() == "/api/certs" {
        return upload_certificate(req, state).await;
    }
    if req.method() == Method::POST && parse_change_action(req.uri().path()).is_some() {
        return review_pending_change(req, state).await;
    }
    if req.method() == Method::POST && req.uri().path() == "/api/developer/key-applications" {
        return submit_developer_key_application(req, state).await;
    }
    if req.uri().path() == "/api/developer/account"
        || req.uri().path().starts_with("/api/developer/account/")
    {
        return portal::handle(req, state).await;
    }
    if req.method() == Method::GET
        && state.mode.full_control_plane()
        && state.snap.load().developer_portal.public_catalog()
        && is_developer_portal_read_path(req.uri().path())
    {
        let (request, _body) = req.into_parts();
        return developer_portal_read(&request, &state, false)
            .unwrap_or_else(|| plain(StatusCode::NOT_FOUND, "not found\n"));
    }
    // 现有节点运维 API 都是 head/query-only；尽早丢弃非 Sync 的 axum Body，后续 await 只借用 Sync Parts。
    // 未来配置 PUT 由独立 MVC handler 以显式 body 上限收取，不能把无界 body 偷渡进 legacy 分发器。
    let (request, _body) = req.into_parts();
    let identity = match authenticate_admin_request(&request, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(resp) = reject_untrusted_admin_browser_origin(&request, &state) {
        return resp;
    }
    // 数据节点只保留节点级 read/reload；即使拿到管理员凭据，也不能借数据节点执行集群写操作。
    if !state.mode.full_control_plane()
        && !data_mode_path_allowed(&request.method, request.uri.path())
    {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let permission = admin_permission(&request.method, request.uri.path());
    if request.method == Method::GET
        && request.uri.path() == "/"
        && state.snap.load().ownership.enabled()
        && !identity.allows(AdminResource::Cluster, AdminAction::Read)
    {
        return admin_ui_asset(
            "text/html; charset=utf-8",
            Bytes::from_static(include_bytes!("assets/workspaces.html")),
        );
    }
    if let Some((resource, action)) = permission {
        if !identity.allows(resource, action) {
            tracing::warn!(
                principal = %identity.principal_id,
                ?resource,
                ?action,
                "admin RBAC denied request"
            );
            // 拒绝本身也是安全事件；审计失败不改变 403，避免外部 sink 故障把越权探测变成 503 oracle。
            if let Err(error) = record_admin_audit(
                &state,
                &identity,
                &request,
                resource,
                action,
                "completed",
                Some(StatusCode::FORBIDDEN.as_u16()),
            )
            .await
            {
                tracing::error!(%error, "failed to audit RBAC denial");
            }
            return json(
                StatusCode::FORBIDDEN,
                serde_json::json!({
                    "ok": false,
                    "error": "forbidden"
                }),
            );
        }
    }
    if let Some((resource, action)) = permission.filter(|(_, action)| is_mutating_action(*action)) {
        if let Err(error) = record_admin_audit(
            &state, &identity, &request, resource, action, "attempt", None,
        )
        .await
        {
            tracing::error!(%error, "admin action rejected because durable audit is unavailable");
            return json(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "ok": false,
                    "error": "audit sink unavailable; action not executed"
                }),
            );
        }
    }
    let resp = match (&request.method, request.uri.path()) {
        (&Method::GET, "/") => admin_ui_asset(
            "text/html; charset=utf-8",
            Bytes::from_static(include_bytes!("assets/console.html")),
        ),
        (&Method::GET, "/ui/app.css") => admin_ui_asset(
            "text/css; charset=utf-8",
            Bytes::from_static(include_bytes!("assets/console.css")),
        ),
        (&Method::GET, "/ui/app.js") => admin_ui_asset(
            "application/javascript; charset=utf-8",
            Bytes::from_static(include_bytes!("assets/console.js")),
        ),
        // liveness:进程活着即 200(不看依赖),供容器 / K8s 判是否重启。
        (&Method::GET, "/healthz") => plain(StatusCode::OK, "ok\n"),
        // readiness:配置已加载 + 数据面监听就绪才 200,否则 503(前置 LB 据此挂/摘流量)。
        (&Method::GET, "/readyz") => readyz(&state),
        (&Method::GET, "/metrics") => metrics(&state),
        (&Method::GET, "/admin/config/status") => config_status(&state),
        #[cfg(feature = "xds-client")]
        (&Method::GET, "/admin/xds/status") => xds_status(&state),
        #[cfg(feature = "xds-server")]
        (&Method::GET, "/admin/xds-server/status") => xds_server_status(&state),
        (&Method::GET, "/api/dashboard") => dashboard(&state),
        (&Method::GET, "/api/session") => session::read(&state, &identity),
        (&Method::GET, "/api/monitor/routes") => {
            monitor::routes::read(&state, &request, &state.snap.load_full(), None)
        }
        (&Method::GET, "/api/monitor/services") => {
            monitor::services::read(&state, &request, &state.snap.load_full(), None)
        }
        (&Method::GET, "/api/cluster/catalog") => catalog::read(&state, &request).await,
        (&Method::GET, "/api/cluster/overview") | (&Method::GET, "/admin/cluster/facts") => {
            if request.uri.query().is_some() {
                plain(
                    StatusCode::BAD_REQUEST,
                    "only current cluster facts are available\n",
                )
            } else if request.uri.path() == "/api/cluster/overview" {
                cluster::read(&state)
            } else {
                cluster::facts::read(&state)
            }
        }
        (&Method::GET, "/api/monitor") | (&Method::GET, "/admin/monitor/sample") => {
            if request.uri.path() == "/api/monitor" && request.uri.query() == Some("scope=cluster")
            {
                monitor::read_cluster(&state)
            } else if request
                .uri
                .query()
                .is_some_and(|query| !query.is_empty() && query != "scope=local")
            {
                plain(
                    StatusCode::BAD_REQUEST,
                    "only current local or cluster monitoring is available\n",
                )
            } else {
                monitor::read(&state, request.uri.path() == "/admin/monitor/sample")
            }
        }
        (&Method::POST, "/admin/reload") => reload_config(),
        // 只读发现视图:列出上游服务/实例/来源,供管理面展示集群拓扑。
        (&Method::GET, "/admin/upstreams") => {
            let snap = state.snap.load();
            let route_refs = upstream_route_refs(&snap);
            let mut view = snap.upstreams.service_view_json(&route_refs);
            view["outlier_runtime"] = state
                .upstream_health
                .get()
                .map(|registry| registry.status())
                .unwrap_or(serde_json::Value::Null);
            json(StatusCode::OK, view)
        }
        (&Method::GET, "/admin/config/dry-run") => dry_run_config(&state).await,
        (&Method::GET, "/api/config/current") => read_current_config(&state).await,
        (&Method::GET, "/admin/config/history") => config_history(&state),
        (&Method::GET, "/admin/config/rejections") => config_rejections(&state),
        (&Method::POST, "/admin/config/rollback") => rollback_config(&request, &state).await,
        // 集群配置版本收敛视图:从 Nacos 反查本网关成员,聚合各节点已注册的 gateway.version。
        (&Method::GET, "/admin/cluster/consistency") => cluster_consistency(&state).await,
        (&Method::GET, "/api/cluster/metrics") | (&Method::GET, "/admin/cluster/metrics") => {
            cluster_metrics(&state).await
        }
        (&Method::GET, "/api/cluster/nodes") => cluster_nodes(&state).await,
        (&Method::GET, "/api/cluster/rollout") => cluster_rollout_status(&state).await,
        (&Method::POST, "/api/cluster/rollout/approve") => {
            approve_cluster_rollout(&request, &identity, state.clone()).await
        }
        (&Method::POST, "/api/cluster/rollout/reject") => {
            reject_cluster_rollout(&request, &identity, state.clone()).await
        }
        (&Method::POST, "/admin/long-connections/close") => {
            close_long_connections(&request, &state)
        }
        (&Method::PUT, "/admin/blacklist") | (&Method::POST, "/admin/blacklist") => {
            set_blacklist_ip(&request, &state, true).await
        }
        (&Method::DELETE, "/admin/blacklist") => set_blacklist_ip(&request, &state, false).await,
        //  黑名单 ban/unban 审计流(本节点最近事件)。
        (&Method::GET, "/admin/blacklist/audit") => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "events": state.blacklist.audit_snapshot()
            }),
        ),
        (&Method::GET, "/api/audit") => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "events": state.audit.snapshot().await
            }),
        ),
        (&Method::GET, "/api/changes") => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "changes": state.approvals.snapshot(&identity)
            }),
        ),
        (&Method::GET, "/api/sentinel") => read_sentinel_config(&state),
        (&Method::GET, path) if path == "/api/consumers" || path.starts_with("/api/consumers/") => {
            read_consumers(path, &state)
        }
        (&Method::GET, "/api/certs") => read_certificates(&state),
        (&Method::GET, path)
            if path.starts_with("/admin/nodes/") && path.ends_with("/snapshot") =>
        {
            node_snapshot(path, &state).await
        }
        (&Method::PUT, "/admin/interface-disable")
        | (&Method::POST, "/admin/interface-disable") => {
            set_interface_disable(&request, &state, true).await
        }
        (&Method::DELETE, "/admin/interface-disable") => {
            set_interface_disable(&request, &state, false).await
        }
        // route-wide PURGE：generation 失效避免 Redis SCAN/批量 DEL；需要 admin auth/CSRF 前置。
        (&Method::DELETE, "/admin/cache") => purge_http_cache(&request, &state).await,
        (&Method::GET, path)
            if is_developer_portal_read_path(path) || is_product_admin_read_path(path) =>
        {
            developer_portal_read(&request, &state, true)
                .unwrap_or_else(|| plain(StatusCode::NOT_FOUND, "not found\n"))
        }
        _ => plain(StatusCode::NOT_FOUND, "not found\n"),
    };
    if let Some((resource, action)) = permission.filter(|(_, action)| is_mutating_action(*action)) {
        if let Err(error) = record_admin_audit(
            &state,
            &identity,
            &request,
            resource,
            action,
            "completed",
            Some(resp.status().as_u16()),
        )
        .await
        {
            // attempt 已确认且副作用可能已发生；返回明确的 ambiguous 状态，避免伪装成功。
            tracing::error!(%error, "admin action completed but result audit failed");
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": "action result audit failed",
                    "operation_may_have_completed": true,
                }),
            );
        }
    }
    resp
}

/// 业务作用：只有可能改变配置/运行态的动作进入 fail-closed 审计；read/dry-run 不阻断控制面查询。
///
/// 参数说明：
/// - `action`: RBAC 风险动作。
fn is_mutating_action(action: AdminAction) -> bool {
    matches!(
        action,
        AdminAction::Write | AdminAction::EmergencyKill | AdminAction::Rollback
    )
}

/// 业务作用：写一条不含敏感原文的管理审计；query 仅记录 SHA-256，便于关联而不泄漏参数。
///
/// 参数说明：
/// - `state`: 提供审计器和当前配置版本。
/// - `identity`: 已绑定凭据的 principal。
/// - `req`: 管理请求，只借 method/path/query 做小字段。
/// - `resource`: 固定资源域。
/// - `action`: 固定风险动作。
/// - `phase`: `attempt` 或 `completed`。
/// - `status`: completed 响应状态。
async fn record_admin_audit(
    state: &AdminState,
    identity: &AdminIdentity,
    req: &AdminRequestParts,
    resource: AdminResource,
    action: AdminAction,
    phase: &'static str,
    status: Option<u16>,
) -> anyhow::Result<()> {
    let query_sha256 = req.uri.query().map(nasa::crypto::sha256);
    let config_version = state.snap.load().version;
    state
        .audit
        .record_scoped(
            crate::admin::audit::AdminAuditInput {
                principal: identity.principal_id.clone(),
                method: req.method.as_str(),
                path: req.uri.path(),
                resource,
                action,
                phase,
                status,
                query_sha256,
                config_version,
            },
            req.extensions.get::<audit::WorkspaceAudit>().cloned(),
        )
        .await
}

/// 已认证的单请求主体；只带 Arc id 与 Copy 权限位，不把 token/password 克隆出快照。
struct AdminIdentity {
    /// 审计主体 id。
    principal_id: Arc<str>,
    /// `None` 仅用于 RBAC 关闭的向后兼容管理员；启用 RBAC 后始终为显式位图。
    permissions: Option<u128>,
}

impl AdminIdentity {
    /// 业务作用：判断当前请求主体是否允许给定资源动作。
    ///
    /// 参数说明：
    /// - `resource`: 端点所属资源域。
    /// - `action`: 端点风险动作。
    fn allows(&self, resource: AdminResource, action: AdminAction) -> bool {
        self.permissions.is_none_or(|permissions| {
            let bit = 1_u128 << (resource.index() * AdminAction::COUNT + action.index());
            permissions & bit != 0
        })
    }
}

/// 业务作用：把现有 admin API 精确映射为 `资源域 × 动作`；未知路由保持 404，不意外继承宽权限。
///
/// 参数说明：
/// - `method`：是不含 query 的规范请求目标。
/// - `path`：是不含 query 的规范请求目标。
///
/// 返回：已知端点的资源域与动作；未知路径返回 None 并由分发器保持 404。
fn admin_permission(method: &Method, path: &str) -> Option<(AdminResource, AdminAction)> {
    match (method, path) {
        (&Method::GET, "/readyz") | (&Method::GET, "/metrics") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/admin/config/status") => Some((AdminResource::Config, AdminAction::Read)),
        #[cfg(feature = "xds-client")]
        (&Method::GET, "/admin/xds/status") => Some((AdminResource::Cluster, AdminAction::Read)),
        #[cfg(feature = "xds-server")]
        (&Method::GET, "/admin/xds-server/status") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/api/dashboard") => Some((AdminResource::Cluster, AdminAction::Read)),
        (&Method::GET, "/api/monitor/routes") => Some((AdminResource::Cluster, AdminAction::Read)),
        (&Method::GET, "/api/monitor/services") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/api/cluster/catalog") => Some((AdminResource::Cluster, AdminAction::Read)),
        (&Method::GET, "/api/cluster/overview") | (&Method::GET, "/admin/cluster/facts") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/api/monitor") | (&Method::GET, "/admin/monitor/sample") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::POST, "/api/explain") => Some((AdminResource::Routes, AdminAction::DryRun)),
        (&Method::POST, path) if path.starts_with("/api/config/") && path.ends_with("/diff") => {
            Some((AdminResource::Config, AdminAction::DryRun))
        }
        (&Method::POST, "/admin/reload") => Some((AdminResource::Cluster, AdminAction::Write)),
        (&Method::GET, "/admin/upstreams") => Some((AdminResource::Upstreams, AdminAction::Read)),
        (&Method::GET, "/admin/config/dry-run") => {
            Some((AdminResource::Config, AdminAction::DryRun))
        }
        (&Method::POST, "/api/config/dry-run") => {
            Some((AdminResource::Config, AdminAction::DryRun))
        }
        (&Method::GET, "/api/config/current") => Some((AdminResource::Config, AdminAction::Read)),
        (&Method::GET, "/api/cluster/rollout") => Some((AdminResource::Cluster, AdminAction::Read)),
        (&Method::POST, "/api/cluster/rollout/approve")
        | (&Method::POST, "/api/cluster/rollout/reject") => {
            Some((AdminResource::Config, AdminAction::Write))
        }
        (&Method::PUT, "/api/config/current") => Some((AdminResource::Config, AdminAction::Write)),
        (&Method::GET, "/admin/config/history") => Some((AdminResource::Config, AdminAction::Read)),
        (&Method::GET, "/admin/config/rejections") => {
            Some((AdminResource::Config, AdminAction::Read))
        }
        (&Method::POST, "/admin/config/rollback") => {
            Some((AdminResource::Config, AdminAction::Rollback))
        }
        (&Method::GET, "/admin/cluster/consistency") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/api/cluster/metrics") | (&Method::GET, "/admin/cluster/metrics") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/api/cluster/nodes") => Some((AdminResource::Cluster, AdminAction::Read)),
        (&Method::GET, path)
            if path.starts_with("/admin/nodes/") && path.ends_with("/snapshot") =>
        {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::POST, "/admin/long-connections/close") => {
            Some((AdminResource::Connections, AdminAction::EmergencyKill))
        }
        (&Method::GET, "/admin/blacklist/audit") => Some((AdminResource::Acl, AdminAction::Read)),
        (&Method::GET, "/api/audit") => Some((AdminResource::Audit, AdminAction::Read)),
        (&Method::GET, "/api/sentinel") => Some((AdminResource::Sentinel, AdminAction::Read)),
        (&Method::PUT, "/api/sentinel") => Some((AdminResource::Sentinel, AdminAction::Write)),
        (&Method::GET, path) if path == "/api/consumers" || path.starts_with("/api/consumers/") => {
            Some((AdminResource::Consumers, AdminAction::Read))
        }
        (&Method::POST, path) | (&Method::DELETE, path)
            if path == "/api/consumers" || path.starts_with("/api/consumers/") =>
        {
            Some((AdminResource::Consumers, AdminAction::Write))
        }
        (&Method::GET, "/api/certs") => Some((AdminResource::Certs, AdminAction::Read)),
        (&Method::POST, "/api/certs") => Some((AdminResource::Certs, AdminAction::Write)),
        (&Method::PUT, "/admin/blacklist")
        | (&Method::POST, "/admin/blacklist")
        | (&Method::DELETE, "/admin/blacklist") => {
            Some((AdminResource::Acl, AdminAction::EmergencyKill))
        }
        (&Method::PUT, "/admin/interface-disable")
        | (&Method::POST, "/admin/interface-disable")
        | (&Method::DELETE, "/admin/interface-disable") => {
            Some((AdminResource::InterfaceGuard, AdminAction::EmergencyKill))
        }
        (&Method::DELETE, "/admin/cache") => Some((AdminResource::Cache, AdminAction::Write)),
        (&Method::GET, path)
            if is_developer_portal_read_path(path) || is_product_admin_read_path(path) =>
        {
            Some((AdminResource::Routes, AdminAction::Read))
        }
        _ => None,
    }
}

/// 业务作用：判断 data 模式的最小 admin allowlist；默认拒绝能改运行态或配置事实源的端点。
///
/// 参数说明：
/// - `method`：是已由 HTTP parser 分离 query 的规范请求目标。
/// - `path`：是已由 HTTP parser 分离 query 的规范请求目标。
///
/// 返回：数据/sidecar 节点允许访问时返回 true；其它管理能力返回 false。
fn data_mode_path_allowed(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/healthz")
            | (&Method::GET, "/readyz")
            | (&Method::GET, "/metrics")
            | (&Method::GET, "/admin/monitor/sample")
            | (&Method::GET, "/admin/cluster/facts")
            | (&Method::GET, "/admin/config/status")
            | (&Method::GET, "/admin/xds/status")
            | (&Method::GET, "/admin/xds-server/status")
            | (&Method::POST, "/admin/reload")
    )
}

/// 业务作用：返回本节点当前配置与部署模式；只暴露低基数摘要，不返回密钥或完整配置原文。
///
/// 参数说明：
/// - `state`：是当前节点管理面共享状态。
///
/// 返回：包含部署模式和低基数 Snapshot 摘要的 JSON 200 响应。
fn config_status(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let ai = snapshot
        .proxies
        .iter()
        .flat_map(|proxy| {
            proxy.router.routes().iter().filter_map(|route| {
                let governance = route.llm.as_ref().and_then(|llm| llm.governance.as_ref());
                (route.agent.is_some() || governance.is_some()).then(|| {
                    serde_json::json!({
                        "proxy":proxy.id,
                        "route":route.id,
                        "agent":route.agent.as_ref().map(|plan| plan.summary()),
                        "governance":governance.map(|plan| plan.summary())
                    })
                })
            })
        })
        .collect::<Vec<_>>();
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "mode": admin_mode_name(state.mode),
            "ready": state.ready.load(Ordering::Acquire),
            "summary": snapshot.summary(),
            "ai": ai,
        }),
    )
}

/// 业务作用：输出本节点 ADS/EDS 权威状态，供发布门区分首次未同步、active 与 LKG degraded。
///
/// 参数说明：
/// - `state`：提供可选 xDS 运行时句柄。
///
/// 返回：启用 xDS 时返回低敏 version/nonce、错误摘要和累计计数；未启用时返回 404。
#[cfg(feature = "xds-client")]
fn xds_status(state: &AdminState) -> Response<BoxBody> {
    if !state.snap.load().control_plane.xds.enabled {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let Some(status) = &state.xds_status else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let status = status.snapshot();
    let state_name = match status.state {
        crate::control::xds::XdsConnectionState::Disconnected => "disconnected",
        crate::control::xds::XdsConnectionState::Syncing => "syncing",
        crate::control::xds::XdsConnectionState::Active => "active",
        crate::control::xds::XdsConnectionState::Degraded => "degraded",
    };
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "state": state_name,
            "ready": status.ready,
            "stream_up": status.stream_up,
            "accepted_version": status.accepted_version,
            "accepted_versions": status.accepted_versions,
            "last_nonce": status.last_nonce,
            "last_nonces": status.last_nonces,
            "last_error": status.last_error,
            "warming_dependencies": status.warming_dependencies,
            "applied_fingerprint": status.applied_fingerprint,
            "ack_total": status.ack_total,
            "nack_total": status.nack_total,
            "reconnect_total": status.reconnect_total,
            "duplicate_total": status.duplicate_total,
            "last_received_timestamp": status.last_received_timestamp,
            "last_applied_timestamp": status.last_applied_timestamp,
            "active_resources": status.active_resources,
            "active_resources_by_type": status.active_resources_by_type,
            "apply_queue_depth": status.apply_queue_depth,
            "rejected_bytes_total": status.rejected_bytes_total,
            "warming_timeout_total": status.warming_timeout_total,
            "ttl_expired_total": status.ttl_expired_total,
        }),
    )
}

/// 业务作用：展示已发布管理端投影的容量与协议事实，不泄漏节点身份、订阅内容或 SDS 密钥。
///
/// 参数说明：
/// - `state`：已经通过管理面权限检查的共享状态。
///
/// 返回：启用时返回当前版本和固定计数；未启用时返回 404，不显示未发布候选。
#[cfg(feature = "xds-server")]
fn xds_server_status(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let Some(plan) = &snapshot.xds_server else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    json(
        StatusCode::OK,
        serde_json::json!({
            "snapshot_version": snapshot.version,
            "projection": plan.summary(),
            "protocol": crate::control::xds_server::metrics::status(),
        }),
    )
}

/// 业务作用：构建 UI 首屏聚合读模型，仅消费当前快照和公开低基数事实。
///
/// 参数说明：
/// - `state`：是同一管理面共享状态。
///
/// 返回：配置、健康和历史摘要；新遥测激活时附同源指标，不触发外部 I/O。
fn dashboard(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let summary = snapshot.summary();
    let health = state
        .active_health
        .service_health()
        .iter()
        .map(|service| {
            serde_json::json!({
                "service": service.service,
                "healthy": service.healthy,
                "total": service.total,
            })
        })
        .collect::<Vec<_>>();
    let data = serde_json::json!({
        "ok": true,
        "mode": admin_mode_name(state.mode),
        "ready": state.ready.load(Ordering::Acquire),
        "summary": summary,
        "health": health,
        "history": state.config_history.snapshot(),
    });
    #[cfg(feature = "telemetry-otlp")]
    let data = {
        let mut data = data;
        if snapshot.telemetry.multi_signal.is_some() {
            data["telemetry"] = crate::observability::metrics::catalog::dashboard(
                &state.metrics,
                snapshot.version,
                snapshot.upstreams.service_count(),
            );
        }
        data
    };
    json(StatusCode::OK, data)
}

/// 业务作用：返回固定部署模式名称，供 status/dashboard 使用同一协议值。
///
/// 参数说明：
/// - `mode`：是启动时确定且热更不可改变的管理平面模式。
///
/// 返回：稳定的小写 API 字符串。
const fn admin_mode_name(mode: AdminPlaneMode) -> &'static str {
    match mode {
        AdminPlaneMode::Data => "data",
        AdminPlaneMode::Sidecar => "sidecar",
        AdminPlaneMode::Admin => "admin",
        AdminPlaneMode::AllInOne => "all-in-one",
    }
}

/// 业务作用：唤醒唯一 reload worker；本端点不直接 build/swap，保持所有触发源串行化不变式。
fn reload_config() -> Response<BoxBody> {
    // SAFETY: 只向本进程发送 SIGHUP，不解引用裸指针；signal handler 仅向 bounded channel 投事件。
    let rc = unsafe {
        libc::kill(std::process::id() as i32, libc::SIGHUP)
    };
    if rc == 0 {
        json(
            StatusCode::ACCEPTED,
            serde_json::json!({
                "ok": true,
                "status": "reload scheduled"
            }),
        )
    } else {
        json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "failed to signal reload worker"
            }),
        )
    }
}

/// 业务作用：`DELETE /admin/cache?proxy=<id>&route=<id>` 主动失效一条 route 的全部 L1/L2 entry。
///
/// 只 clone 当前 `Arc<HttpCachePolicy>` 后就释放 ArcSwap guard，再执行 Redis I/O；不能让控制面
/// await 长时间钉住整个旧配置快照。
async fn purge_http_cache(req: &AdminRequestParts, state: &AdminState) -> Response<BoxBody> {
    let query = req.uri.query().unwrap_or_default();
    let Some(proxy_id) = query_param(query, "proxy") else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "missing proxy"
            }),
        );
    };
    let Some(route_id) = query_param(query, "route") else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "missing route"
            }),
        );
    };
    if proxy_id.len() > 256 || route_id.len() > 256 {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "proxy/route id exceeds 256 bytes"
            }),
        );
    }
    let policy = {
        let snapshot = state.snap.load();
        snapshot
            .proxy(proxy_id)
            .and_then(|proxy| proxy.router.route_by_id(route_id))
            .and_then(|route| route.http_cache.clone())
    };
    let Some(policy) = policy else {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "ok": false,
                "error": "proxy/route cache not found"
            }),
        );
    };
    match state
        .http_cache
        .purge_route(proxy_id, route_id, policy.as_ref())
        .await
    {
        Ok(generation) => {
            state.metrics.inc_http_cache_invalidation_ok();
            json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "proxy": proxy_id,
                    "route": route_id,
                    "generation": generation,
                }),
            )
        }
        Err(error) => {
            state.metrics.inc_http_cache_invalidation_error();
            json(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    }
}

/// 业务作用：返回本节点配置 reload 审计历史。
///
/// 参数说明：
/// - `state`: 管理面共享状态。
fn config_history(state: &AdminState) -> Response<BoxBody> {
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "history": state.config_history.snapshot(),
        }),
    )
}

/// 业务作用：返回最近被候选 builder/reload 拒绝的配置事件，供节点未收敛时定位而无需读日志。
///
/// 参数说明：
/// - `state`：提供已有界保留的配置历史。
///
/// 返回：返回 200 和按发生顺序的 rejected 事件；不读取配置原文或密钥。
fn config_rejections(state: &AdminState) -> Response<BoxBody> {
    let rejected = state
        .config_history
        .snapshot()
        .events
        .into_iter()
        .filter(|event| event.status == "rejected" || event.status.starts_with("rejected_"))
        .collect::<Vec<_>>();
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "rejections": rejected
        }),
    )
}

/// 业务作用：汇总 service -> proxy/route 引用关系,供 `/admin/upstreams` 展示。
///
/// 参数说明：
/// - `snap`: 当前配置快照。
fn upstream_route_refs(snap: &GatewaySnapshot) -> HashMap<String, Vec<String>> {
    let mut refs: HashMap<String, Vec<String>> = HashMap::new();
    for proxy in snap.proxies.iter() {
        for (service, route) in proxy.router.upstream_service_refs() {
            refs.entry(service)
                .or_default()
                .push(format!("{}/{}", proxy.id, route));
        }
    }
    for routes in refs.values_mut() {
        routes.sort();
        routes.dedup();
    }
    refs
}

/// 业务作用：回滚到已归档配置版本。
///
/// 两条路径:
/// - **本地文件源**:三份归档先通过完整候选与启动身份校验，再逐文件原子替换；进程内事务锁
///   阻止 reload 观察中间态，由 SIGHUP 唤醒唯一 worker 发布。三文件不具备整体掉电原子性。
/// - **Nacos 配置源**：把归档版本 CAS 写回 Nacos dataId（带并发保护），集群经 config watch 收敛；
///   见 [`rollback_config_nacos`]。
///
/// 参数说明：
/// - `req`: 管理面请求,使用 `version` query 参数(可选 `base_version` 见 Nacos 路径)。
/// - `state`: 管理面共享状态。
///
/// 返回：归档、完整候选或文件门拒绝时不调度；文件替换成功后返回已调度，实际生效由reload确认。
async fn rollback_config(req: &AdminRequestParts, state: &AdminState) -> Response<BoxBody> {
    let Some(raw_version) = query_param(req.uri.query().unwrap_or_default(), "version") else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "missing version"
            }),
        );
    };
    let Ok(target_version) = raw_version.parse::<u64>() else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "invalid version"
            }),
        );
    };
    if state.snap.load().config_source.nacos.enabled {
        // Nacos 配置源:走 CAS 写回远端事实源,不直接改本地文件(否则会被下次 watch 覆盖、且不集群生效)。
        return rollback_config_nacos(state, target_version).await;
    }
    let active = state.snap.load_full();
    let current_version = active.version;
    let Some(expected_fingerprint) = active.config_fingerprint else {
        return plain(
            StatusCode::CONFLICT,
            "configuration fingerprint unavailable\n",
        );
    };
    let current_paths = active.document_paths.clone();
    let history = state.config_history.clone();
    // 节点处于持久保护态时先拒绝控制写请求，不能把失去写权掩盖成普通文件基线冲突。
    if let Err(error) = history.validate_candidate(&active) {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false, "error": error.to_string()
            }),
        );
    }
    let documents = match history.read_archived(target_version) {
        Ok(documents) => documents,
        Err(error) => {
            return json(
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "ok":false,"error":error.to_string()
                }),
            )
        }
    };
    let baseline_reader = history.clone();
    let baseline_paths = current_paths.clone();
    let baseline = tokio::task::spawn_blocking(move || {
        baseline_reader.read_current_documents(&baseline_paths, expected_fingerprint)
    })
    .await;
    let baseline = match baseline {
        Ok(Ok(Some(documents))) => documents,
        Ok(Ok(None)) => {
            return plain(
                StatusCode::CONFLICT,
                "current configuration changed before rollback validation\n",
            )
        }
        _ => {
            return plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot read rollback baseline\n",
            )
        }
    };
    // 归档属于过去的配置事实，不能绕过当前永久节点、来源和启动边界直接覆盖文件。
    let targets = match build_cluster_candidate_snapshot(state, &documents).await {
        Ok(candidate) => candidate.document_paths,
        Err(error) => return error.response(),
    };
    let restore = tokio::task::spawn_blocking(move || {
        history.restore_documents(
            &documents,
            &baseline,
            expected_fingerprint,
            &current_paths,
            &targets,
        )
    })
    .await;
    let restore = match restore {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!("rollback file worker failed: {error}")),
    };
    if let Err(e) = restore {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": e.to_string()
            }),
        );
    }
    if matches!(restore, Ok(false)) {
        return plain(StatusCode::CONFLICT, "rollback document targets changed\n");
    }
    state.config_history.record_control_event(
        "admin-rollback",
        &state.cfg_path,
        current_version,
        target_version,
        "rollback_scheduled",
    );
    // 只唤醒唯一 reload worker,避免 Admin 直接换版导致 file watcher 再次重复 reload。
    // SAFETY:kill 只向本进程发送 SIGHUP,不解引用指针。
    let rc = unsafe {
        libc::kill(std::process::id() as i32, libc::SIGHUP)
    };
    if rc != 0 {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "failed to signal reload worker"
            }),
        );
    }
    json(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "ok": true,
            "rollback_version": target_version,
            "status": "restored; reload scheduled",
        }),
    )
}

/// Nacos CAS 回滚的判定结果:在专用运行时线程算出,回到 admin 上下文映射为响应 + 审计。
enum NacosRollbackOutcome {
    /// 远端配置已等于目标版本,无需发布(幂等)。
    AlreadyMatches,
    /// 原子 bundle dataId 原先不存在，首次发布成功。
    Created(String),
    /// 远端已偏离本节点线上版本(有人先改了),携带漂移的 dataId 列表 → 前端 rebase。
    Drifted(Vec<String>),
    /// 旧兼容模式中需改动的 dataId 多于一个,拒绝用多次单 dataId CAS 冒充事务。
    MultiDataId(Vec<String>),
    /// 单 dataId CAS 发布成功,携带该 dataId。
    Published(String),
    /// 单 dataId CAS 失配(并发写),携带该 dataId → 前端 rebase。
    CasConflict(String),
}

/// 业务作用：通过 CAS 恢复 Nacos 配置源中的归档版本，避免覆盖并发发布。
///
/// 与本地文件回滚不同,Nacos 是集群统一配置事实源:必须把归档版本【CAS 写回 Nacos】并靠 config watch 收敛,
/// 直接改本地物化文件会被下次 watch 覆盖、且不集群生效。策略(兼顾并发安全与「不伪造多文件事务」):
///
/// 1. 读归档【目标版本 N】三文件;读归档【当前线上版本 M】(= 本节点快照版本)作为并发基线。
/// 2. `bundle_data_id` 非空时,拉取单 JSON bundle,核对三份原文后用一次 `publish_cas` 原子写回
///    完整目标配置;watcher 只会看到旧 bundle 或新 bundle。
/// 3. 旧三 dataId 兼容模式逐个拉取并判漂移;只允许 0/1 个 dataId 变化,多于一个时返回 409,
///    **不能用多次单 dataId CAS 冒充事务**(watch 会瞬时读到新旧混合配置, 边界)。
/// 4. 远端偏离版本 M → 409 rebase;CAS 成功 → 202;CAS 失配 → 409;网络错 → 502。
///
/// 参数说明：
/// - `state`: 管理面共享状态。
/// - `target_version`: 目标归档版本 N。
async fn rollback_config_nacos(state: &AdminState, target_version: u64) -> Response<BoxBody> {
    // 从快照取 Nacos 来源与当前线上版本,随即释放 guard(不把 arc_swap Guard 跨 await 持有)。
    let (nacos, current_version) = {
        let snap = state.snap.load();
        (snap.config_source.nacos.clone(), snap.version)
    };
    // 读归档目标版本 N。
    let target = match state.config_history.read_archived(target_version) {
        Ok(docs) => docs,
        Err(e) => {
            return json(
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "ok": false,
                    "error": e.to_string()
                }),
            )
        }
    };
    // 读归档当前线上版本 M 作为并发基线;缺失(极少见,归档曾失败)则无法核对基线,让前端稍后重试。
    let baseline = match state.config_history.read_archived(current_version) {
        Ok(docs) => docs,
        Err(e) => {
            return json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": format!("cannot verify rollback base: current version {current_version} not archived: {e}; retry after next successful reload"),
                }),
            )
        }
    };
    // Nacos I/O 卸载到专用线程执行(nacos-sdk future 非 Send),仅回送 Send 的判定结果。
    let outcome =
        run_nacos_rollback_offloaded(nacos, target_version, target, baseline, false).await;
    let record = |status: &str| {
        state.config_history.record_control_event(
            "nacos-rollback",
            &state.cfg_path,
            current_version,
            target_version,
            status,
        );
    };
    match outcome {
        Ok(NacosRollbackOutcome::AlreadyMatches) => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "rollback_version": target_version,
                "status": "remote already matches target version; nothing to publish",
            }),
        ),
        Ok(NacosRollbackOutcome::Created(data_id)) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "data_id": data_id,
                "error": "rollback must not initialize a missing Nacos bundle",
            }),
        ),
        Ok(NacosRollbackOutcome::Drifted(ids)) => {
            record("rejected_drift");
            json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": "remote config drifted from current live version; rebase and retry",
                    "drifted_data_ids": ids,
                    "base_version": current_version,
                }),
            )
        }
        Ok(NacosRollbackOutcome::MultiDataId(ids)) => {
            record("rejected_multi_dataid");
            json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": "legacy three-dataId mode cannot atomically roll back multiple documents; configure config_source.nacos.bundle_data_id, or change only one legacy dataId",
                    "changed_data_ids": ids,
                }),
            )
        }
        Ok(NacosRollbackOutcome::Published(data_id)) => {
            record("cas_published");
            json(
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "ok": true,
                    "rollback_version": target_version,
                    "data_id": data_id,
                    "status": "CAS published to Nacos; cluster converges via config watch",
                }),
            )
        }
        Ok(NacosRollbackOutcome::CasConflict(data_id)) => {
            record("cas_conflict");
            json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "data_id": data_id,
                    "error": "CAS conflict: remote changed concurrently; rebase and retry",
                }),
            )
        }
        Err(e) => json(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "ok": false,
                "error": e.to_string()
            }),
        ),
    }
}

/// 业务作用：把 Nacos I/O 卸载到【专用 current-thread 运行时线程】执行,通过 oneshot 回送结果。
///
/// nacos-sdk 的 future 不保证 `Send`,而 admin 连接在多线程 runtime 上经
/// `tokio::spawn` 处理(要求 `Send`)。故把 connect/fetch/publish 放到独立线程的 current-thread runtime,
/// 只把【Send 的判定结果】送回 admin 上下文,保持连接 future 的 Send 约束。回滚是低频控制动作,按次起线程可接受。
///
/// 参数说明：
/// - `nacos`: `config_source.nacos` 配置(含地址/鉴权/dataId/group)。
/// - `target_version`: 目标归档版本号,写入原子 bundle 的审计版本。
/// - `target`: 目标归档版本三文件原文。
/// - `baseline`: 当前线上版本三文件原文,用于并发漂移判定。
/// - `allow_initial_publish`: 原子 bundle 不存在时是否允许首次发布；仅集群发布入口可开启。
async fn run_nacos_rollback_offloaded(
    nacos: crate::config::model::NacosConfigSourceCfg,
    target_version: u64,
    target: crate::control::history::ArchivedDocs,
    baseline: crate::control::history::ArchivedDocs,
    allow_initial_publish: bool,
) -> anyhow::Result<NacosRollbackOutcome> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("gateway-nacos-rollback".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!(
                        "build nacos rollback runtime failed: {e}"
                    )));
                    return;
                }
            };
            let result = rt.block_on(nacos_rollback_once(
                &nacos,
                target_version,
                &target,
                &baseline,
                allow_initial_publish,
            ));
            let _ = tx.send(result);
        });
    if let Err(e) = spawned {
        return Err(anyhow::anyhow!("spawn nacos rollback thread failed: {e}"));
    }
    rx.await.unwrap_or_else(|_| {
        Err(anyhow::anyhow!(
            "nacos rollback worker exited without result"
        ))
    })
}

/// 业务作用：在 Nacos 上执行一次 CAS 回滚判定与发布(运行在专用 current-thread runtime)。
///
/// 参数说明：
/// - `nacos`: `config_source.nacos` 配置。
/// - `target_version`: 目标归档版本号。
/// - `target`: 目标归档版本三文件原文。
/// - `baseline`: 当前线上版本三文件原文(并发漂移基线)。
/// - `allow_initial_publish`: 缺少原子 bundle 时是否允许初始化。
async fn nacos_rollback_once(
    nacos: &crate::config::model::NacosConfigSourceCfg,
    target_version: u64,
    target: &crate::control::history::ArchivedDocs,
    baseline: &crate::control::history::ArchivedDocs,
    allow_initial_publish: bool,
) -> anyhow::Result<NacosRollbackOutcome> {
    let props = crate::control::reload::nacos_config_props(nacos);
    let client = nasa::config::nacos::NacosConfigClient::connect(&props)
        .await
        .map_err(|e| anyhow::anyhow!("connect nacos failed: {e}"))?;
    let group = nacos.group.as_str();
    if !nacos.bundle_data_id.trim().is_empty() {
        let data_id = nacos.bundle_data_id.trim();
        let remote = client
            .fetch_optional_with_md5(data_id, group)
            .await
            .map_err(|e| anyhow::anyhow!("fetch {data_id} failed: {e}"))?;
        let Some((remote_content, remote_md5)) = remote else {
            if !allow_initial_publish {
                anyhow::bail!(
                    "Nacos atomic bundle {data_id} does not exist; rollback cannot initialize it"
                );
            }
            let content = crate::control::reload::encode_atomic_nacos_bundle(
                format!("initial-{target_version}"),
                target,
            )?;
            return if client
                .publish_initial(data_id, group, &content, "json")
                .await
                .map_err(|e| anyhow::anyhow!("nacos initial atomic bundle publish failed: {e}"))?
            {
                Ok(NacosRollbackOutcome::Created(data_id.to_string()))
            } else {
                Ok(NacosRollbackOutcome::CasConflict(data_id.to_string()))
            };
        };
        let remote = crate::control::reload::parse_atomic_nacos_bundle(&remote_content)
            .map_err(|e| anyhow::anyhow!("parse remote atomic bundle {data_id} failed: {e:#}"))?;

        // 先识别已发布目标,使管理端在 CAS 成功但响应丢失后可安全重试。
        if atomic_bundle_matches_docs(&remote, target) {
            return Ok(NacosRollbackOutcome::AlreadyMatches);
        }
        // 目标尚未发布时,远端必须仍等于本节点线上归档基线;否则有人先改了。
        if !atomic_bundle_matches_docs(&remote, baseline) {
            return Ok(NacosRollbackOutcome::Drifted(vec![data_id.to_string()]));
        }

        let content = crate::control::reload::encode_atomic_nacos_bundle(
            format!("rollback-{target_version}"),
            target,
        )?;
        return if client
            .publish_cas(data_id, group, &content, &remote_md5)
            .await
            .map_err(|e| anyhow::anyhow!("nacos publish atomic bundle failed: {e}"))?
        {
            Ok(NacosRollbackOutcome::Published(data_id.to_string()))
        } else {
            Ok(NacosRollbackOutcome::CasConflict(data_id.to_string()))
        };
    }

    // 三个 dataId ↔ (目标内容, 基线内容);逐个拉远端当前内容 + md5,组装成纯判定输入。
    let triples = [
        (
            nacos.gateway_data_id.as_str(),
            target.gateway.as_str(),
            baseline.gateway.as_str(),
        ),
        (
            nacos.interface_guard_data_id.as_str(),
            target.interface_guard.as_str(),
            baseline.interface_guard.as_str(),
        ),
        (
            nacos.sentinel_rules_data_id.as_str(),
            target.sentinel_rules.as_str(),
            baseline.sentinel_rules.as_str(),
        ),
    ];
    let mut items = Vec::with_capacity(triples.len());
    for (data_id, target_content, baseline_content) in triples {
        let (remote, remote_md5) = client
            .fetch_with_md5(data_id, group)
            .await
            .map_err(|e| anyhow::anyhow!("fetch {data_id} failed: {e}"))?;
        items.push(RollbackItem {
            data_id: data_id.to_string(),
            target: target_content.to_string(),
            baseline: baseline_content.to_string(),
            remote,
            remote_md5,
        });
    }
    // 判定与发布分离：存在内容漂移或涉及多个文件时，必须在任何写入之前拒绝。
    match decide_nacos_rollback(&items) {
        RollbackPlan::AlreadyMatches => Ok(NacosRollbackOutcome::AlreadyMatches),
        RollbackPlan::Drifted(ids) => Ok(NacosRollbackOutcome::Drifted(ids)),
        RollbackPlan::MultiDataId(ids) => Ok(NacosRollbackOutcome::MultiDataId(ids)),
        RollbackPlan::PublishSingle {
            data_id,
            content,
            cas_md5,
        } => {
            // 恰好一个 dataId 需写回:单次 CAS 原子安全,不触发混合配置窗口。
            if client
                .publish_cas(&data_id, group, &content, &cas_md5)
                .await
                .map_err(|e| anyhow::anyhow!("nacos publish failed: {e}"))?
            {
                Ok(NacosRollbackOutcome::Published(data_id))
            } else {
                Ok(NacosRollbackOutcome::CasConflict(data_id))
            }
        }
    }
}

/// 业务作用：原子 bundle 的三份配置原文是否与某归档版本完全一致。
fn atomic_bundle_matches_docs(
    bundle: &crate::control::reload::AtomicNacosConfigBundle,
    docs: &crate::control::history::ArchivedDocs,
) -> bool {
    bundle.gateway == docs.gateway
        && bundle.interface_guard == docs.interface_guard
        && bundle.sentinel_rules == docs.sentinel_rules
}

/// 单个 dataId 的回滚三方内容对照(目标 / 基线 / 远端当前 + 远端 md5),供纯判定函数使用。
struct RollbackItem {
    /// Nacos dataId。
    data_id: String,
    /// 目标归档版本内容。
    target: String,
    /// 当前线上版本内容(并发漂移基线)。
    baseline: String,
    /// 远端当前内容。
    remote: String,
    /// 远端当前内容 md5(单 dataId 写回时用作 CAS 基线)。
    remote_md5: String,
}

/// CAS 回滚的纯判定结果(不含 I/O)。
enum RollbackPlan {
    /// 远端已等于目标版本,无需发布。
    AlreadyMatches,
    /// 远端偏离线上版本(有人先改了),携带漂移 dataId。
    Drifted(Vec<String>),
    /// 需改动多于一个 dataId,拒绝伪事务。
    MultiDataId(Vec<String>),
    /// 恰好一个 dataId 需 CAS 写回。
    PublishSingle {
        /// 待写回 dataId。
        data_id: String,
        /// 待写回内容(目标版本)。
        content: String,
        /// CAS 基线(远端当前 md5)。
        cas_md5: String,
    },
}

/// 业务作用：对照目标、基线和当前远端内容决定回滚动作，不在判定阶段触发网络写入。
///
/// 规则:任一 dataId【远端 ≠ 基线】→ 漂移(前端 rebase);否则【远端 ≠ 目标】者为需写回;
/// 需写回 0 / 1 / 多 → 幂等 / 单 dataId CAS / 拒绝多文件伪事务( 边界)。
///
/// 参数说明：
/// - `items`: 各 dataId 的三方内容对照。
fn decide_nacos_rollback(items: &[RollbackItem]) -> RollbackPlan {
    // 先判漂移:远端相对本节点线上版本已变,说明有人先改了,整体让前端 rebase。
    let drifted: Vec<String> = items
        .iter()
        .filter(|i| i.remote != i.baseline)
        .map(|i| i.data_id.clone())
        .collect();
    if !drifted.is_empty() {
        return RollbackPlan::Drifted(drifted);
    }
    // 无漂移下,远端 ≠ 目标者即回滚会改动的 dataId。
    let changed: Vec<&RollbackItem> = items.iter().filter(|i| i.remote != i.target).collect();
    match changed.as_slice() {
        [] => RollbackPlan::AlreadyMatches,
        [one] => RollbackPlan::PublishSingle {
            data_id: one.data_id.clone(),
            content: one.target.clone(),
            cas_md5: one.remote_md5.clone(),
        },
        many => RollbackPlan::MultiDataId(many.iter().map(|i| i.data_id.clone()).collect()),
    }
}

/// 集群中单个网关成员的版本视图(从 Nacos 实例元数据抽取)。
#[derive(serde::Serialize)]
struct ClusterNode {
    /// 成员对外 IP。
    ip: String,
    /// 成员数据面端口。
    port: u16,
    /// 成员管理面监听(元数据 `gateway.admin_listen`)。
    admin_listen: Option<String>,
    /// 可选节点标识(元数据 `gateway.node_id`)。
    node_id: Option<String>,
    /// 该成员已注册的配置版本(元数据 `gateway.version`);非网关/旧实例可能缺失。
    version: Option<u64>,
    /// 该成员已注册的 schema 版本(元数据 `gateway.schema_version`)。
    schema_version: Option<u64>,
    /// 该成员**已上线**配置集指纹(元数据 `gateway.fingerprint`);旧节点可能缺失。
    fingerprint: Option<u64>,
    /// 活动原子配置三文档的摘要，与发布目标逐字节绑定。
    bundle_sha256: Option<String>,
    /// 该成员进程启动时刻(Unix 毫秒,元数据 `gateway.started_at_ms`)。
    started_at_ms: Option<u128>,
    /// Nacos 健康态(心跳)。
    healthy: bool,
    /// Nacos 是否启用(未被手动下线)。
    enabled: bool,
}

/// 集群配置版本收敛汇总。
#[derive(serde::Serialize)]
struct ClusterSummary {
    /// 是否已收敛(参与统计的成员版本唯一)。
    converged: bool,
    /// 已注册的去重版本(升序;仅统计 enabled 且带版本的成员)。
    distinct_versions: Vec<u64>,
    /// 已注册的去重指纹(升序);长度 >1 表示**同版本不同内容**的分叉。
    distinct_fingerprints: Vec<u64>,
    /// 是否存在 enabled 却没上报指纹的成员(旧版本节点);为真时不判定为已收敛。
    fingerprint_unknown: bool,
    /// 众数版本(出现最多者;并列取较高版本),供高亮「应达版本」。
    expected_version: Option<u64>,
    /// Nacos 返回的成员总数。
    node_count: usize,
    /// 各成员明细。
    nodes: Vec<ClusterNode>,
}

/// 业务作用：根据 Nacos 成员实例的版本证据聚合集群配置收敛情况。
///
/// 收敛判定只统计 **enabled 且带 `gateway.version`** 的成员(手动下线 / 无版本元数据的不参与),
/// 避免一个已摘除节点永远拖着「未收敛」。
///
/// 参数说明：
/// - `instances`: Nacos `discover_all` 返回的本网关服务成员实例。
fn summarize_cluster_versions(instances: &[nasa::discovery::Instance]) -> ClusterSummary {
    let nodes: Vec<ClusterNode> = instances
        .iter()
        .map(|inst| ClusterNode {
            ip: inst.ip.clone(),
            port: inst.port,
            admin_listen: inst.metadata.get("gateway.admin_listen").cloned(),
            node_id: inst.metadata.get("gateway.node_id").cloned(),
            bundle_sha256: inst.metadata.get("gateway.bundle_sha256").cloned(),
            version: inst
                .metadata
                .get("gateway.version")
                .and_then(|v| v.parse::<u64>().ok()),
            fingerprint: inst
                .metadata
                .get("gateway.fingerprint")
                .and_then(|v| v.parse::<u64>().ok()),
            started_at_ms: inst
                .metadata
                .get("gateway.started_at_ms")
                .and_then(|v| v.parse::<u128>().ok()),
            schema_version: inst
                .metadata
                .get("gateway.schema_version")
                .and_then(|v| v.parse::<u64>().ok()),
            healthy: inst.healthy,
            enabled: inst.enabled,
        })
        .collect();
    let mut counts: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for node in &nodes {
        if node.enabled {
            if let Some(version) = node.version {
                *counts.entry(version).or_insert(0) += 1;
            }
        }
    }
    let distinct_versions: Vec<u64> = counts.keys().copied().collect();
    // 众数:出现次数最多者;BTreeMap 升序遍历下 max_by_key 并列取较高版本(确定性)。
    let expected_version = counts.iter().max_by_key(|(_, c)| **c).map(|(v, _)| *v);
    // 同版本不代表同内容——指纹分叉(某节点从不同配置源/被旁路改动物化)必须能看见。
    // 收敛判据因此是【版本一致 **且** 指纹一致】;有节点未上报指纹时不谎称收敛。
    let mut fingerprints: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut fingerprint_unknown = false;
    for node in &nodes {
        if !node.enabled {
            continue;
        }
        match node.fingerprint {
            Some(fingerprint) => {
                fingerprints.insert(fingerprint);
            }
            None => fingerprint_unknown = true,
        }
    }
    let distinct_fingerprints: Vec<u64> = fingerprints.iter().copied().collect();
    ClusterSummary {
        converged: distinct_versions.len() <= 1
            && distinct_fingerprints.len() <= 1
            && !fingerprint_unknown,
        distinct_versions,
        distinct_fingerprints,
        fingerprint_unknown,
        expected_version,
        node_count: nodes.len(),
        nodes,
    }
}

/// 业务作用：集群配置版本收敛端点( `/api/cluster/consistency`)。
///
/// 从 Nacos 反查本网关自注册服务的所有成员,聚合各成员元数据里的 `gateway.version`,判断是否收敛一致。
/// 版本来自**自注册元数据**(节点换版会原位 refresh 注册 payload),故有 self-register 轮询级滞后:此处附带本节点
/// **实时** `local_version`,便于识别「本地已换版、成员表尚未刷新」的过渡态。
///
/// 参数说明：
/// - `state`: 管理面共享状态。
async fn cluster_consistency(state: &AdminState) -> Response<BoxBody> {
    let (nacos, local_version) = {
        let snap = state.snap.load();
        (snap.discovery.nacos.clone(), snap.version)
    };
    let Some(service) = crate::upstream::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster consistency requires discovery.nacos.self_register.enabled",
            }),
        );
    };
    // Nacos查询共享常驻有界执行者，SDK非Send future与鉴权调度保持同一运行时。
    match state
        .member_discovery
        .discover(&nacos, service.clone(), cluster::discovery::REQUEST_TIMEOUT)
        .await
    {
        Ok(instances) => {
            let summary = summarize_cluster_versions(&instances);
            let mut body = serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = body.as_object_mut() {
                obj.insert("ok".to_string(), serde_json::json!(true));
                obj.insert("service".to_string(), serde_json::json!(service));
                obj.insert(
                    "local_version".to_string(),
                    serde_json::json!(local_version),
                );
            }
            json(StatusCode::OK, body)
        }
        Err(e) => json(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "ok": false,
                "error": e.to_string()
            }),
        ),
    }
}

/// 业务作用：按稳定 node_id 查询指定成员已自注册的快照版本、指纹和健康事实。
///
/// 参数说明：
/// - `path`：形如 `/admin/nodes/{id}/snapshot`
/// - `state`：提供冻结的 Nacos 发现配置。
///
/// 返回：节点存在时返回 200 与低敏快照事实；身份非法/不存在返回 4xx；发现失败返回 502。
async fn node_snapshot(path: &str, state: &AdminState) -> Response<BoxBody> {
    let node_id = path
        .strip_prefix("/admin/nodes/")
        .and_then(|path| path.strip_suffix("/snapshot"))
        .unwrap_or_default();
    if node_id.is_empty()
        || node_id.len() > 128
        || !node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "invalid node id"
            }),
        );
    }
    let nacos = state.snap.load().discovery.nacos.clone();
    let Some(service) = crate::upstream::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "node snapshot requires Nacos self-registration"
            }),
        );
    };
    let instances = match state
        .member_discovery
        .discover(&nacos, service, cluster::discovery::REQUEST_TIMEOUT)
        .await
    {
        Ok(instances) => instances,
        Err(error) => {
            return json(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    let Some(instance) = instances.iter().find(|instance| {
        instance
            .metadata
            .get("gateway.node_id")
            .is_some_and(|id| id == node_id)
    }) else {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "ok": false,
                "error": "node not found"
            }),
        );
    };
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "node_id": node_id,
            "ip": instance.ip,
            "port": instance.port,
            "healthy": instance.healthy,
            "enabled": instance.enabled,
            "version": instance.metadata.get("gateway.version"),
            "schema_version": instance.metadata.get("gateway.schema_version"),
            "fingerprint": instance.metadata.get("gateway.fingerprint"),
            "started_at_ms": instance.metadata.get("gateway.started_at_ms"),
            "admin_listen": instance.metadata.get("gateway.admin_listen"),
        }),
    )
}

const CLUSTER_METRICS_SCRAPE_CONCURRENCY: usize = 8;
const CLUSTER_METRICS_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const CLUSTER_METRICS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(2_000);
const CLUSTER_METRICS_BODY_TIMEOUT: Duration = Duration::from_millis(2_000);
const CLUSTER_METRICS_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClusterMetricCounters {
    requests_total: u64,
    responses_5xx_total: u64,
    active_connections: u64,
}

#[derive(Clone, Copy, Debug)]
struct ClusterMetricSample {
    counters: ClusterMetricCounters,
    sampled_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct ClusterMetricRates {
    qps: Option<f64>,
    responses_5xx_per_second: Option<f64>,
}

#[derive(Debug)]
struct ClusterMetricSuccess {
    node_id: String,
    admin_listen: String,
    sample_key: String,
    counters: ClusterMetricCounters,
    sampled_at: Instant,
}

#[derive(Debug)]
enum ClusterMetricRow {
    Success(ClusterMetricSuccess),
    Failure {
        node_id: String,
        admin_listen: String,
        reason: &'static str,
    },
}

/// 业务作用：聚合集群各节点的真实 QPS、5xx 速率与活跃连接，供管理页定位热点和故障节点。
///
/// 参数说明：
/// - `state`：提供当前成员发现配置、本节点 admin 凭据和跨轮采样基线。
///
/// 返回：成功发现成员时返回 200 与每节点明细；功能未开启返回 409，成员发现失败返回 502。
/// 单节点失败只影响对应明细，首轮采样或 counter 重置时速率为 `null`，绝不伪造零值。
async fn cluster_metrics(state: &AdminState) -> Response<BoxBody> {
    let (nacos, auth) = {
        let snap = state.snap.load();
        (snap.discovery.nacos.clone(), snap.admin_auth.clone())
    };
    if !auth.allow_cluster_metrics_scrape {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "set admin.auth.allow_cluster_metrics_scrape=true to let this node scrape \
                          peer /metrics with its own admin credential",
            }),
        );
    }
    // 主动跨节点抓取必须携带本节点受 Cluster/Read 约束的凭据；匿名模式即使误开开关也不外连。
    let Some(auth_header) = cluster_scrape_auth_header(&auth) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster metrics scrape requires an authenticated local admin credential with cluster read permission",
            }),
        );
    };
    let Some(service) = crate::upstream::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster metrics requires discovery.nacos.self_register.enabled",
            }),
        );
    };
    let instances = match state
        .member_discovery
        .discover(&nacos, service.clone(), cluster::discovery::REQUEST_TIMEOUT)
        .await
    {
        Ok(instances) => instances,
        Err(e) => {
            return json(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "ok": false,
                    "error": e.to_string()
                }),
            )
        }
    };
    // 成员规模不再与 edge full-mesh 上限绑定；显式限制并发，避免错误注册或大集群刷新耗尽 fd。
    let rows = stream::iter(instances.into_iter().map(|inst| {
        let auth_header = auth_header.clone();
        async move {
            let node_id = inst
                .metadata
                .get("gateway.node_id")
                .cloned()
                .unwrap_or_else(|| format!("{}:{}", inst.ip, inst.port));
            let raw_admin = inst
                .metadata
                .get("gateway.admin_listen")
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            let target = match cluster_metrics_target(&inst) {
                Ok(target) => target,
                Err(reason) => {
                    return ClusterMetricRow::Failure {
                        node_id,
                        admin_listen: raw_admin,
                        reason,
                    }
                }
            };
            scrape_node_metrics(node_id, target, auth_header).await
        }
    }))
    .buffer_unordered(CLUSTER_METRICS_SCRAPE_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let mut successful_keys = HashSet::new();
    let mut nodes = Vec::with_capacity(rows.len());
    let mut samples = state.cluster_metric_samples.lock();
    for row in rows {
        match row {
            ClusterMetricRow::Success(success) => {
                successful_keys.insert(success.sample_key.clone());
                let rates = update_cluster_metric_rates(
                    &mut samples,
                    success.sample_key,
                    success.counters,
                    success.sampled_at,
                );
                nodes.push(serde_json::json!({
                    "node_id": success.node_id,
                    "admin_listen": success.admin_listen,
                    "ok": true,
                    "qps": rates.qps,
                    "responses_5xx_per_second": rates.responses_5xx_per_second,
                    "requests_total": success.counters.requests_total,
                    "responses_5xx_total": success.counters.responses_5xx_total,
                    "active_connections": success.counters.active_connections,
                }));
            }
            ClusterMetricRow::Failure {
                node_id,
                admin_listen,
                reason,
            } => nodes.push(serde_json::json!({
                "node_id": node_id,
                "admin_listen": admin_listen,
                "ok": false,
                "reason": reason,
            })),
        }
    }
    // 抓取失败或已经离开成员表的节点必须丢弃旧基线；恢复后的第一轮重新显示未知，
    // 不能把不可观测时段平均进 QPS，制造看似可信的低速率。
    samples.retain(|key, _| successful_keys.contains(key));
    drop(samples);
    nodes.sort_by(|a, b| a["node_id"].as_str().cmp(&b["node_id"].as_str()));
    let reachable = nodes
        .iter()
        .filter(|n| n["ok"].as_bool().unwrap_or(false))
        .count();
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "service": service,
            "nodes": nodes,
            "reachable": reachable,
            "total": nodes.len(),
        }),
    )
}

/// 业务作用：输出 Nacos 网关成员的健康、版本、指纹与可选真实流量采样，作为 Console 集群节点读模型。
///
/// 参数说明：
/// - `state`：提供发现、本地 peer 抓取凭据和相邻 counter 采样。
///
/// 返回：成员发现成功返回 200；未开启跨节点抓取时仍返回成员事实并标记 metrics 不可用；发现失败返回 502。
async fn cluster_nodes(state: &AdminState) -> Response<BoxBody> {
    let (nacos, auth, local_version) = {
        let snapshot = state.snap.load();
        (
            snapshot.discovery.nacos.clone(),
            snapshot.admin_auth.clone(),
            snapshot.version,
        )
    };
    let Some(service) = crate::upstream::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster nodes requires Nacos self-registration"
            }),
        );
    };
    let instances = match state
        .member_discovery
        .discover(&nacos, service.clone(), cluster::discovery::REQUEST_TIMEOUT)
        .await
    {
        Ok(instances) => instances,
        Err(error) => {
            return json(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    let summary = summarize_cluster_versions(&instances);
    let metrics = if auth.allow_cluster_metrics_scrape {
        if let Some(auth_header) = cluster_scrape_auth_header(&auth) {
            let rows = stream::iter(instances.iter().cloned().map(|instance| {
                let auth_header = auth_header.clone();
                async move {
                    let node_id = instance
                        .metadata
                        .get("gateway.node_id")
                        .cloned()
                        .unwrap_or_else(|| format!("{}:{}", instance.ip, instance.port));
                    let raw_admin = instance
                        .metadata
                        .get("gateway.admin_listen")
                        .cloned()
                        .unwrap_or_else(|| "?".to_string());
                    match cluster_metrics_target(&instance) {
                        Ok(target) => scrape_node_metrics(node_id, target, auth_header).await,
                        Err(reason) => ClusterMetricRow::Failure {
                            node_id,
                            admin_listen: raw_admin,
                            reason,
                        },
                    }
                }
            }))
            .buffer_unordered(CLUSTER_METRICS_SCRAPE_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
            let mut samples = state.cluster_metric_samples.lock();
            let mut successful = HashSet::new();
            let mut values = Vec::new();
            for row in rows {
                match row {
                    ClusterMetricRow::Success(success) => {
                        successful.insert(success.sample_key.clone());
                        let rates = update_cluster_metric_rates(
                            &mut samples,
                            success.sample_key,
                            success.counters,
                            success.sampled_at,
                        );
                        values.push(serde_json::json!({
                            "node_id": success.node_id,
                            "ok": true,
                            "qps": rates.qps,
                            "responses_5xx_per_second": rates.responses_5xx_per_second,
                            "active_connections": success.counters.active_connections,
                        }));
                    }
                    ClusterMetricRow::Failure {
                        node_id,
                        reason,
                        ..
                    } => values.push(serde_json::json!({
                        "node_id": node_id,
                        "ok": false,
                        "reason": reason
                    })),
                }
            }
            samples.retain(|key, _| successful.contains(key));
            values.sort_by(|left, right| left["node_id"].as_str().cmp(&right["node_id"].as_str()));
            serde_json::json!({
                "available": true,
                "nodes": values
            })
        } else {
            serde_json::json!({
                "available": false,
                "reason": "no Cluster/Read peer credential"
            })
        }
    } else {
        serde_json::json!({
            "available": false,
            "reason": "admin.auth.allow_cluster_metrics_scrape is disabled"
        })
    };
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "service": service,
            "local_version": local_version,
            "cluster": summary,
            "metrics": metrics,
        }),
    )
}

/// 业务作用：把发现成员转换为受限的 admin 抓取目标，阻止元数据把控制面引向任意主机。
///
/// 参数说明：
/// - `instance`：是 Nacos 自注册服务返回的单个成员。
///
/// 返回：成员 IP 与元数据 admin 端口组成的可拨号地址；缺少端口或成员 IP 非法时返回低基数原因。
fn cluster_metrics_target(
    instance: &nasa::discovery::Instance,
) -> Result<SocketAddr, &'static str> {
    let raw_admin = instance
        .metadata
        .get("gateway.admin_listen")
        .ok_or("missing gateway.admin_listen")?;
    let advertised = raw_admin
        .parse::<SocketAddr>()
        .map_err(|_| "gateway.admin_listen is not a socket address")?;
    if advertised.port() == 0 {
        return Err("gateway.admin_listen port is zero");
    }
    let member_ip = instance
        .ip
        .parse::<IpAddr>()
        .map_err(|_| "member IP is not an IP address")?;
    // 元数据只声明 admin 端口；目标 IP 必须重新绑定到发现成员，避免伪造 metadata 形成 SSRF。
    Ok(SocketAddr::new(member_ip, advertised.port()))
}

/// 业务作用：用相邻两次成功 counter 采样计算节点速率，并维护下一轮基线。
///
/// 参数说明：
/// - `samples`：是受锁保护的节点基线
/// - `sample_key`：唯一标识成员
/// - `counters`：是本轮完整响应的事实。
/// - `sampled_at`：是本轮完整响应的事实。
///
/// 返回：有严格更新的前序采样且 counter 未重置时返回 QPS/5xx 每秒速率；否则返回未知并建立新基线。
fn update_cluster_metric_rates(
    samples: &mut HashMap<String, ClusterMetricSample>,
    sample_key: String,
    counters: ClusterMetricCounters,
    sampled_at: Instant,
) -> ClusterMetricRates {
    let rates = samples
        .get(&sample_key)
        .and_then(|previous| {
            let elapsed = sampled_at.checked_duration_since(previous.sampled_at)?;
            if elapsed.is_zero()
                || counters.requests_total < previous.counters.requests_total
                || counters.responses_5xx_total < previous.counters.responses_5xx_total
            {
                return None;
            }
            let seconds = elapsed.as_secs_f64();
            Some(ClusterMetricRates {
                qps: Some(
                    counters
                        .requests_total
                        .saturating_sub(previous.counters.requests_total)
                        as f64
                        / seconds,
                ),
                responses_5xx_per_second: Some(
                    counters
                        .responses_5xx_total
                        .saturating_sub(previous.counters.responses_5xx_total)
                        as f64
                        / seconds,
                ),
            })
        })
        .unwrap_or_default();
    let should_publish = samples
        .get(&sample_key)
        .is_none_or(|previous| sampled_at > previous.sampled_at);
    if should_publish {
        samples.insert(
            sample_key,
            ClusterMetricSample {
                counters,
                sampled_at,
            },
        );
    }
    rates
}

/// 构造抓取用的 Authorization 头。
///
/// 业务作用：只从本节点已验证配置派生 peer metrics 抓取凭据，禁止把调用方凭据透传成内网跳板。
///
/// 参数说明：
/// - `auth`：是当前快照中已经解析的管理面认证配置。
///
/// 返回：RBAC 模式选择首个拥有 Cluster/Read 的主体，兼容模式使用 legacy 凭据；两者都优先
/// Bearer、其次 Basic。认证关闭、无授权主体或凭据非法时返回 `None`，调用方禁止主动外连。
fn cluster_scrape_auth_header(auth: &crate::config::AdminAuthRuntimeCfg) -> Option<String> {
    if !auth.enabled {
        return None;
    }
    if auth.rbac_enabled {
        return auth
            .principals
            .iter()
            .filter(|principal| principal.allows(AdminResource::Cluster, AdminAction::Read))
            .find_map(|principal| {
                if let Some(token) = principal.bearer_token.as_deref() {
                    return std::str::from_utf8(token)
                        .ok()
                        .map(|token| format!("Bearer {token}"));
                }
                principal
                    .basic_expected
                    .as_deref()
                    .map(|expected| format!("Basic {}", basic_base64(expected)))
            });
    }
    if let Some(token) = auth.bearer_token.as_deref() {
        return std::str::from_utf8(token)
            .ok()
            .map(|token| format!("Bearer {token}"));
    }
    // 运行态里 basic_expected 已是 `user:password` 原始字节,直接编码即可,
    // 不需要也不应该再从明文配置里重新取一遍。
    if let Some(expected) = auth.basic_expected.as_deref() {
        return Some(format!("Basic {}", basic_base64(expected)));
    }
    None
}

/// 标准 base64 编码(Basic 认证用)。
///
/// 业务作用：为管理面 peer metrics 抓取生成 RFC 7617 Basic 凭据编码，默认 feature 下也可用。
///
/// 参数说明：
/// - `bytes`：是已经拼成 `user:password` 的运行态凭据字节。
///
/// 返回：返回带标准 `=` padding 的 Base64 文本，不记录或缓存明文。
///
/// 不复用 `edge_ws_bridge` 里那份:那个模块受 `grpc-edge` feature 门控,而集群指标
/// 抓取在默认构建下也要可用——跨 feature 借用会让默认形态编译不过。
fn basic_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// 业务作用：在硬连接/响应体上限内读取一个已发现成员的低基数流量事实，供集群页定位热点与 5xx。
///
/// 参数说明：
/// - `node_id`：标识成员与受限目标
/// - `target`：标识成员与受限目标
/// - `auth_header`：是本节点派生的认证凭据。
///
/// 返回：成功返回三项指标；任意网络、协议或解析失败返回 `ok=false` 与低基数原因，绝不伪造零值。
async fn scrape_node_metrics(
    node_id: String,
    target: SocketAddr,
    auth_header: String,
) -> ClusterMetricRow {
    let admin_listen = target.to_string();
    let fail = |reason: &'static str| ClusterMetricRow::Failure {
        node_id: node_id.clone(),
        admin_listen: admin_listen.clone(),
        reason,
    };
    let text = match fetch_peer_metrics_text(target, &auth_header).await {
        Ok(text) => text,
        Err(reason) => return fail(reason),
    };
    let Some(counters) = parse_cluster_metric_counters(&text) else {
        return fail("required metrics missing or invalid");
    };
    ClusterMetricRow::Success(ClusterMetricSuccess {
        sample_key: format!("{node_id}\0{target}"),
        node_id,
        admin_listen,
        counters,
        sampled_at: Instant::now(),
    })
}

/// 业务作用：在硬连接、响应和 body 上限内读取一个已发现成员的 Prometheus 文本。
///
/// 参数说明：
/// - `target`：已被成员 IP 门禁约束
/// - `auth_header`：是本节点从已验证配置派生的读凭据。
///
/// 返回：成功返回有界 UTF-8 宽容文本；网络、协议、认证或资源门禁失败返回低基数原因。
async fn fetch_peer_metrics_text(
    target: SocketAddr,
    auth_header: &str,
) -> Result<String, &'static str> {
    let admin_listen = target.to_string();
    // 成员表里的节点可能已经死了但 Nacos 还没摘除；连接与后续每一阶段都必须独立封顶。
    let connect = tokio::time::timeout(
        CLUSTER_METRICS_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(target),
    )
    .await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Err("connect refused"),
        Err(_) => return Err("connect timeout"),
    };
    let handshake = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream));
    let (mut sender, conn) = match handshake.await {
        Ok(pair) => pair,
        Err(_) => return Err("http handshake failed"),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = http::Request::builder()
        .uri("/metrics")
        .header(http::header::HOST, admin_listen.as_str());
    builder = builder.header(http::header::AUTHORIZATION, auth_header);
    let Ok(request) = builder.body(http_body_util::Full::<bytes::Bytes>::default()) else {
        return Err("build request failed");
    };
    let response = match tokio::time::timeout(
        CLUSTER_METRICS_RESPONSE_TIMEOUT,
        sender.send_request(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return Err("request failed"),
        Err(_) => return Err("request timeout"),
    };
    if response.status() == StatusCode::UNAUTHORIZED {
        // 明确区分"凭据不通"与"连不上":前者说明集群配置不同构,运维要改的是配置。
        return Err("unauthorized (peer admin credential differs)");
    }
    if !response.status().is_success() {
        return Err("peer returned non-2xx");
    }
    // 大小上限防内存耗尽，总读取超时同时阻断无限慢速响应体。
    let limited = http_body_util::Limited::new(response.into_body(), CLUSTER_METRICS_BODY_LIMIT);
    let collected =
        match tokio::time::timeout(CLUSTER_METRICS_BODY_TIMEOUT, limited.collect()).await {
            Ok(Ok(collected)) => collected,
            Ok(Err(_)) => return Err("metrics body too large or truncated"),
            Err(_) => return Err("metrics body timeout"),
        };
    Ok(String::from_utf8_lossy(&collected.to_bytes()).into_owned())
}

/// 业务作用：从 Prometheus 文本中提取节点流量聚合所需的三个无标签指标。
///
/// 参数说明：
/// - `text`：是已经通过大小与读取时限门的完整 `/metrics` 响应体。
///
/// 返回：三个指标全部存在且为 `u64` 时返回计数快照；缺少或格式非法时返回 `None`。
fn parse_cluster_metric_counters(text: &str) -> Option<ClusterMetricCounters> {
    let read = |name: &str| -> Option<u64> {
        text.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(' '))
                .and_then(|rest| rest.trim().parse().ok())
        })
    };
    Some(ClusterMetricCounters {
        requests_total: read("gw_requests_total")?,
        responses_5xx_total: read("gw_responses_5xx_total")?,
        active_connections: read("gw_active_connections")?,
    })
}

/// 渐进发布一次节点采样的单调指标。
#[derive(Clone, Debug, PartialEq)]
struct RolloutMetricCounters {
    requests_total: u64,
    responses_5xx_total: u64,
    circuit_rejected_total: u64,
    /// 按 `le` 升序的累积直方图 bucket；`+Inf` 使用 `f64::INFINITY`。
    duration_buckets: Vec<(f64, u64)>,
}

/// 一个流量组在观察窗内的增量事实。
#[derive(Clone, Debug)]
struct RolloutMetricDelta {
    requests: u64,
    responses_5xx: u64,
    circuit_rejected: u64,
    duration_buckets: Vec<(f64, u64)>,
}

/// 对外暴露的渐进发布健康证据；只含聚合值，不含凭据或配置原文。
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct RolloutHealthEvidence {
    observation_seconds: u64,
    canary_requests: u64,
    canary_5xx_ratio: f64,
    canary_p99_ms: f64,
    canary_circuit_rejected: u64,
    baseline_requests: u64,
    baseline_5xx_ratio: Option<f64>,
    baseline_p99_ms: Option<f64>,
}

/// 业务作用：从 Prometheus 文本提取渐进发布健康门所需的 counter 与累积延迟直方图。
///
/// 参数说明：
/// - `text`：是已通过资源上限的完整 `/metrics` 响应。
///
/// 返回：所有必需指标存在且直方图边界严格递增时返回采样；缺失或非法返回 `None`。
fn parse_rollout_metric_counters(text: &str) -> Option<RolloutMetricCounters> {
    let read = |name: &str| -> Option<u64> {
        text.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(' '))
                .and_then(|rest| rest.trim().parse().ok())
        })
    };
    let prefix = "gw_request_duration_seconds_bucket{le=\"";
    let mut duration_buckets = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(prefix) else {
            continue;
        };
        let (bound, value) = rest.split_once("\"} ")?;
        let bound = if bound == "+Inf" {
            f64::INFINITY
        } else {
            bound.parse::<f64>().ok()?
        };
        if bound.is_nan() || bound.is_sign_negative() {
            return None;
        }
        duration_buckets.push((bound, value.trim().parse::<u64>().ok()?));
    }
    if duration_buckets.len() < 2
        || !duration_buckets
            .windows(2)
            .all(|window| window[0].0 < window[1].0 && window[0].1 <= window[1].1)
        || !duration_buckets
            .last()
            .is_some_and(|(bound, _)| bound.is_infinite())
    {
        return None;
    }
    Some(RolloutMetricCounters {
        requests_total: read("gw_requests_total")?,
        responses_5xx_total: read("gw_responses_5xx_total")?,
        circuit_rejected_total: read("gw_circuit_rejected_total")?,
        duration_buckets,
    })
}

/// 业务作用：汇总同一组节点相邻采样的增量，并把 counter reset 视为证据失效。
///
/// 参数说明：
/// - `before`：按节点 id 存储观察窗两端采样
/// - `after`：按节点 id 存储观察窗两端采样
/// - `members`：是本流量组成员。
///
/// 返回：成员、bucket 和 counter 连续时返回聚合增量；任一证据缺失、重置或 schema 变化则失败。
fn aggregate_rollout_metric_delta(
    before: &std::collections::BTreeMap<String, RolloutMetricCounters>,
    after: &std::collections::BTreeMap<String, RolloutMetricCounters>,
    members: &std::collections::BTreeSet<String>,
) -> Result<RolloutMetricDelta, String> {
    let mut result = RolloutMetricDelta {
        requests: 0,
        responses_5xx: 0,
        circuit_rejected: 0,
        duration_buckets: Vec::new(),
    };
    for node_id in members {
        let old = before
            .get(node_id)
            .ok_or_else(|| format!("missing initial metrics for node {node_id}"))?;
        let new = after
            .get(node_id)
            .ok_or_else(|| format!("missing final metrics for node {node_id}"))?;
        if new.requests_total < old.requests_total
            || new.responses_5xx_total < old.responses_5xx_total
            || new.circuit_rejected_total < old.circuit_rejected_total
            || new.duration_buckets.len() != old.duration_buckets.len()
        {
            return Err(format!(
                "metric counter reset or schema changed on node {node_id}"
            ));
        }
        result.requests = result
            .requests
            .saturating_add(new.requests_total - old.requests_total);
        result.responses_5xx = result
            .responses_5xx
            .saturating_add(new.responses_5xx_total - old.responses_5xx_total);
        result.circuit_rejected = result
            .circuit_rejected
            .saturating_add(new.circuit_rejected_total - old.circuit_rejected_total);
        if result.duration_buckets.is_empty() {
            result.duration_buckets = new
                .duration_buckets
                .iter()
                .zip(&old.duration_buckets)
                .map(|((bound, value), (old_bound, old_value))| {
                    if bound != old_bound || value < old_value {
                        return Err(format!(
                            "duration histogram reset or schema changed on node {node_id}"
                        ));
                    }
                    Ok((*bound, value - old_value))
                })
                .collect::<Result<Vec<_>, String>>()?;
        } else {
            for ((sum_bound, sum), ((bound, value), (old_bound, old_value))) in result
                .duration_buckets
                .iter_mut()
                .zip(new.duration_buckets.iter().zip(&old.duration_buckets))
            {
                if *sum_bound != *bound || bound != old_bound || value < old_value {
                    return Err(format!(
                        "duration histogram reset or schema changed on node {node_id}"
                    ));
                }
                *sum = sum.saturating_add(value - old_value);
            }
        }
    }
    Ok(result)
}

/// 业务作用：从累积直方图增量估算 p99 上界，供发布门做保守判定。
///
/// 参数说明：
/// - `buckets`：必须按边界升序且最后为 `+Inf`。
///
/// 返回：有观测时返回命中 p99 的 bucket 上界毫秒；无请求返回 `None`，落入 `+Inf` 则返回无穷大以便门禁失败。
fn rollout_p99_ms(buckets: &[(f64, u64)]) -> Option<f64> {
    let total = buckets.last()?.1;
    if total == 0 {
        return None;
    }
    let rank = ((total as f64) * 0.99).ceil().max(1.0) as u64;
    buckets
        .iter()
        .find(|(_, count)| *count >= rank)
        .map(|(seconds, _)| seconds * 1_000.0)
}

/// 业务作用：管理面认证前置检查。认证在路由分发前完成，并把凭据绑定到不可伪造的 RBAC principal。
///
/// 参数说明：
/// - `req`: 管理面请求。
/// - `state`: 管理面共享状态,其中 `snap` 提供当前认证策略。
fn authenticate_admin_request(
    req: &AdminRequestParts,
    state: &AdminState,
) -> Result<AdminIdentity, Box<Response<BoxBody>>> {
    let snap = state.snap.load();
    let auth = &snap.admin_auth;
    if auth.allow_healthz_unauthenticated && req.uri.path() == "/healthz" {
        return Ok(AdminIdentity {
            principal_id: Arc::from("anonymous-health"),
            permissions: Some(0),
        });
    }
    if !auth.enabled {
        return Ok(AdminIdentity {
            principal_id: Arc::from("anonymous-loopback"),
            permissions: None,
        });
    }
    if auth.rbac_enabled {
        for principal in auth.principals.iter() {
            let bearer_ok = principal
                .bearer_token
                .as_deref()
                .map(|expected| bearer_authorization_matches(&req.headers, expected))
                .unwrap_or(false);
            let basic_ok = principal
                .basic_expected
                .as_deref()
                .map(|expected| basic_authorization_matches(&req.headers, expected))
                .unwrap_or(false);
            if bearer_ok || basic_ok {
                // 只把 id Arc 和权限整数带出 guard；Secret Vec 仍只存在快照中。
                return Ok(AdminIdentity {
                    principal_id: principal.id.clone(),
                    permissions: Some(principal.permission_bits()),
                });
            }
        }
        return Err(Box::new(admin_unauthorized_response(auth.realm.as_str())));
    }
    let bearer_ok = auth
        .bearer_token
        .as_deref()
        .map(|expected| bearer_authorization_matches(&req.headers, expected))
        .unwrap_or(false);
    let basic_ok = auth
        .basic_expected
        .as_deref()
        .map(|expected| basic_authorization_matches(&req.headers, expected))
        .unwrap_or(false);
    if bearer_ok || basic_ok {
        return Ok(AdminIdentity {
            principal_id: Arc::from("legacy-admin"),
            permissions: None,
        });
    }
    Err(Box::new(admin_unauthorized_response(auth.realm.as_str())))
}

/// 业务作用：构造不泄露“用户不存在/密码错误”差异的统一 401 响应。
///
/// 参数说明：
/// - `realm`: 已在构建期校验的 Basic challenge realm。
fn admin_unauthorized_response(realm: &str) -> Response<BoxBody> {
    let challenge = format!("Basic realm=\"{}\"", escape_header_quote(realm));
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(hyper::header::WWW_AUTHENTICATE, challenge)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from_static(b"unauthorized\n")))
        .expect("build admin unauthorized response")
}

/// 业务作用：拒绝来自未显式允许浏览器来源的管理面状态变更请求，防 DNS rebinding / Basic-auth CSRF。
///
/// CLI 与服务间调用通常不携带 `Origin`/`Referer`，继续由 Authorization 独立保护；浏览器只要
/// 携带任一来源头，所有来源头都必须落在 allowlist，避免用重复/冲突 header 绕过。
fn reject_untrusted_admin_browser_origin(
    req: &AdminRequestParts,
    state: &AdminState,
) -> Option<Response<BoxBody>> {
    if admin_browser_source_allowed(
        &req.method,
        &req.headers,
        &state.snap.load().admin_auth.allowed_origins,
    ) {
        return None;
    }
    Some(plain(
        StatusCode::FORBIDDEN,
        "untrusted admin browser origin\n",
    ))
}

/// 业务作用：约束浏览器管理请求的来源站点，避免跨站页面借用本地管理权限。
fn admin_browser_source_allowed(
    method: &Method,
    headers: &http::HeaderMap,
    allowed_origins: &[String],
) -> bool {
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return true;
    }
    let mut saw_browser_source = false;
    for name in [http::header::ORIGIN, http::header::REFERER] {
        for value in headers.get_all(name).iter() {
            saw_browser_source = true;
            let Ok(raw) = value.to_str() else {
                return false;
            };
            let Ok(origin) = crate::config::normalize_http_origin(raw) else {
                return false;
            };
            if !allowed_origins.iter().any(|allowed| allowed == &origin) {
                return false;
            }
        }
    }
    !saw_browser_source || !allowed_origins.is_empty()
}

/// 业务作用：实现 `/readyz` 关键依赖门；只有 listener、xDS 权威与每个 critical 上游同时可用才放流。
///
/// `/readyz`( 关键依赖):就绪 = 数据面已绑定监听(`ready`)**且**每个 critical 上游服务都还有可用实例。
/// 「可用」与数据面选实例同源:selectable(healthy && !down)+ 未被主动探测判死+ Nacos 未失联超 stale_ttl。
/// 未就绪即 503,供前置 LB / K8s 摘流;非关键上游全挂不摘除整个节点(「关键依赖」)。
///
/// 参数说明：
/// - `state`：提供 listener、xDS、关键上游和配置版本事实。
///
/// 返回：所有门通过返回 200；否则返回 503 与单一低敏 reason。
fn readyz(state: &AdminState) -> Response<BoxBody> {
    let snap = state.snap.load();
    let version = snap.version;
    // 独立控制面没有数据 listener/critical upstream 可供摘流；它的 readiness 只表达管理服务已启动。
    if !state.mode.runs_data() {
        return plain(StatusCode::OK, &format!("ready config_version={version}\n"));
    }
    // 传入主动探测的不健康集合:readyz 与选实例用同一份可用集判定,避免「select 挂但 readyz 仍 ready」。
    let critical_down =
        crate::upstream::health::critical_upstreams_not_ready(snap.as_ref(), &state.active_health);
    #[cfg(feature = "xds-client")]
    let xds_ready = !snap.control_plane.xds.enabled
        || state
            .xds_status
            .as_ref()
            .is_some_and(|status| status.ready());
    #[cfg(not(feature = "xds-client"))]
    let xds_ready = true;
    if state.ready.load(Ordering::Relaxed) && xds_ready && critical_down.is_empty() {
        plain(StatusCode::OK, &format!("ready config_version={version}\n"))
    } else {
        let reason = if !state.ready.load(Ordering::Relaxed) {
            "listener_not_ready".to_string()
        } else if !xds_ready {
            "xds_not_ready".to_string()
        } else {
            format!("critical_upstreams_down={}", critical_down.join(","))
        };
        plain(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("not ready config_version={version} reason={reason}\n"),
        )
    }
}

/// 业务作用：渲染数据面与可选控制面的低基数 Prometheus 指标，不暴露资源名/version/nonce 标签。
///
/// 参数说明：
/// - `state`：提供当前快照和常驻运行态计数器。
///
/// 返回：允许暴露时返回文本指标；关闭 metrics 时返回 404。
fn metrics(state: &AdminState) -> Response<BoxBody> {
    let snap = state.snap.load();
    if !snap.expose_metrics {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let mut body = state
        .metrics
        .render_prometheus(snap.version, snap.upstreams.service_count());
    state.usage_meter.render_metrics(&mut body);
    state.traffic_meter.render_traffic_metrics(&mut body);
    #[cfg(feature = "xds-client")]
    if snap.control_plane.xds.enabled {
        if let Some(status) = &state.xds_status {
            let status = status.snapshot();
            body.push_str(
                "# HELP gw_xds_ready Whether at least one EDS version has been applied.\n",
            );
            body.push_str("# TYPE gw_xds_ready gauge\n");
            body.push_str(&format!("gw_xds_ready {}\n", u8::from(status.ready)));
            body.push_str("# HELP gw_xds_stream_up Whether the ADS HTTP/2 stream is connected.\n");
            body.push_str("# TYPE gw_xds_stream_up gauge\n");
            body.push_str(&format!(
                "gw_xds_stream_up {}\n",
                u8::from(status.stream_up)
            ));
            body.push_str("# HELP gw_xds_ack_total Accepted xDS responses.\n");
            body.push_str("# TYPE gw_xds_ack_total counter\n");
            body.push_str(&format!("gw_xds_ack_total {}\n", status.ack_total));
            body.push_str("# HELP gw_xds_nack_total Rejected xDS responses.\n");
            body.push_str("# TYPE gw_xds_nack_total counter\n");
            body.push_str(&format!("gw_xds_nack_total {}\n", status.nack_total));
            body.push_str("# HELP gw_xds_reconnect_total ADS reconnect attempts.\n");
            body.push_str("# TYPE gw_xds_reconnect_total counter\n");
            body.push_str(&format!(
                "gw_xds_reconnect_total {}\n",
                status.reconnect_total
            ));
            body.push_str(
            "# HELP gw_xds_duplicate_total Accepted xDS responses with unchanged native content.\n",
        );
            body.push_str("# TYPE gw_xds_duplicate_total counter\n");
            body.push_str(&format!(
                "gw_xds_duplicate_total {}\n",
                status.duplicate_total
            ));
            body.push_str("# HELP gw_xds_resources Active xDS resources by fixed type.\n");
            body.push_str("# TYPE gw_xds_resources gauge\n");
            for type_label in ["cds", "rds", "eds"] {
                body.push_str(&format!(
                    "gw_xds_resources{{type=\"{type_label}\",state=\"active\"}} {}\n",
                    status
                        .active_resources_by_type
                        .get(type_label)
                        .copied()
                        .unwrap_or_default()
                ));
                let warming = status
                    .warming_dependencies
                    .iter()
                    .filter(|dependency| dependency.starts_with(&format!("{type_label}:")))
                    .count();
                body.push_str(&format!(
                    "gw_xds_resources{{type=\"{type_label}\",state=\"warming\"}} {warming}\n"
                ));
            }
            body.push_str(
            "# HELP gw_xds_last_received_timestamp Unix timestamp of the latest xDS response.\n",
        );
            body.push_str("# TYPE gw_xds_last_received_timestamp gauge\n");
            body.push_str(&format!(
                "gw_xds_last_received_timestamp {}\n",
                status.last_received_timestamp
            ));
            body.push_str("# HELP gw_xds_last_applied_timestamp Unix timestamp of the latest applied xDS response.\n");
            body.push_str("# TYPE gw_xds_last_applied_timestamp gauge\n");
            body.push_str(&format!(
                "gw_xds_last_applied_timestamp {}\n",
                status.last_applied_timestamp
            ));
            body.push_str(
                "# HELP gw_xds_apply_queue_depth Current xDS translate/apply queue depth.\n",
            );
            body.push_str("# TYPE gw_xds_apply_queue_depth gauge\n");
            body.push_str(&format!(
                "gw_xds_apply_queue_depth {}\n",
                status.apply_queue_depth
            ));
            body.push_str("# HELP gw_xds_warming_timeout_total Dependency warming cycles that exceeded their deadline.\n");
            body.push_str("# TYPE gw_xds_warming_timeout_total counter\n");
            body.push_str(&format!(
                "gw_xds_warming_timeout_total {}\n",
                status.warming_timeout_total
            ));
            body.push_str(
                "# HELP gw_xds_ttl_expired_total Delta xDS resources removed after TTL expiry.\n",
            );
            body.push_str("# TYPE gw_xds_ttl_expired_total counter\n");
            body.push_str(&format!(
                "gw_xds_ttl_expired_total {}\n",
                status.ttl_expired_total
            ));
            body.push_str(
                "# HELP gw_xds_rejected_bytes_total Encoded bytes of rejected xDS responses.\n",
            );
            body.push_str("# TYPE gw_xds_rejected_bytes_total counter\n");
            body.push_str(&format!(
                "gw_xds_rejected_bytes_total {}\n",
                status.rejected_bytes_total
            ));
        }
    }
    // 长连接低基数指标：按 current/stale 拆分并输出最旧快照版本，不把具体版本作为高基数 label。
    let stats = state.conn_registry.stats(snap.version);
    body.push_str("# HELP gw_long_connections Active long-lived upgraded connections.\n");
    body.push_str("# TYPE gw_long_connections gauge\n");
    body.push_str(&format!(
        "gw_long_connections{{version_state=\"current\"}} {}\n",
        stats.current
    ));
    body.push_str(&format!(
        "gw_long_connections{{version_state=\"stale\"}} {}\n",
        stats.stale
    ));
    // 边缘订阅低基数 gauge:只出数值,不带 tenant/group/user label。
    #[cfg(feature = "grpc-edge")]
    if let Some(hub) = state.edge_hub.get() {
        body.push_str("# HELP gw_edge_active_streams Active gRPC edge subscribe streams.\n");
        body.push_str("# TYPE gw_edge_active_streams gauge\n");
        body.push_str(&format!(
            "gw_edge_active_streams {}\n",
            hub.active_streams()
        ));
        body.push_str("# HELP gw_edge_groups Active gRPC edge groups.\n");
        body.push_str("# TYPE gw_edge_groups gauge\n");
        body.push_str(&format!("gw_edge_groups {}\n", hub.group_count()));
        body.push_str(
            "# HELP gw_edge_payload_bytes Resident unique payload bytes across edge queues.\n",
        );
        body.push_str("# TYPE gw_edge_payload_bytes gauge\n");
        body.push_str(&format!("gw_edge_payload_bytes {}\n", hub.payload_bytes()));
        body.push_str(
            "# HELP gw_edge_queue_refs Total queued frame references across edge rings.\n",
        );
        body.push_str("# TYPE gw_edge_queue_refs gauge\n");
        body.push_str(&format!("gw_edge_queue_refs {}\n", hub.queue_refs()));
        body.push_str(
            "# HELP gw_edge_runtime_schedule_pause_max_us Maximum observed Tokio scheduling pause in microseconds.\n",
        );
        body.push_str("# TYPE gw_edge_runtime_schedule_pause_max_us gauge\n");
        body.push_str(&format!(
            "gw_edge_runtime_schedule_pause_max_us {}\n",
            hub.runtime_schedule_pause_max_us()
        ));
        let (publish_total, publish_rejected, dropped_frames, reassembly_bytes) =
            hub.publish_counters();
        body.push_str(
            "# HELP gw_edge_publish_total Edge publish/push requests fanned out locally.\n",
        );
        body.push_str("# TYPE gw_edge_publish_total counter\n");
        body.push_str(&format!("gw_edge_publish_total {publish_total}\n"));
        body.push_str("# HELP gw_edge_publish_rejected_total Edge publish/push requests rejected by node budgets.\n");
        body.push_str("# TYPE gw_edge_publish_rejected_total counter\n");
        body.push_str(&format!(
            "gw_edge_publish_rejected_total {publish_rejected}\n"
        ));
        body.push_str("# HELP gw_edge_dropped_frames_total Edge frames dropped by ring overflow or closed rings.\n");
        body.push_str("# TYPE gw_edge_dropped_frames_total counter\n");
        body.push_str(&format!("gw_edge_dropped_frames_total {dropped_frames}\n"));
        body.push_str("# HELP gw_edge_reassembly_bytes_total Bytes copied reassembling gRPC messages across DATA chunks.\n");
        body.push_str("# TYPE gw_edge_reassembly_bytes_total counter\n");
        body.push_str(&format!(
            "gw_edge_reassembly_bytes_total {reassembly_bytes}\n"
        ));
    }
    // 集群中继只暴露低基数观测；peer 明细只进有界日志，不得成为 metric label。
    #[cfg(feature = "grpc-edge")]
    if let Some(relay) = state.edge_relay.get().and_then(|slot| slot.load_full()) {
        let snapshot = relay.metrics();
        body.push_str("# HELP gw_edge_relay_peers_connected Handshaked live relay peer links.\n");
        body.push_str("# TYPE gw_edge_relay_peers_connected gauge\n");
        body.push_str(&format!(
            "gw_edge_relay_peers_connected {}\n",
            snapshot.connected_peers
        ));
        body.push_str(
            "# HELP gw_edge_relay_queue_depth Records waiting in per-peer relay queues.\n",
        );
        body.push_str("# TYPE gw_edge_relay_queue_depth gauge\n");
        body.push_str(&format!(
            "gw_edge_relay_queue_depth {}\n",
            snapshot.queued_records
        ));
        body.push_str("# HELP gw_edge_relay_sent_total Relay data records written to peers.\n");
        body.push_str("# TYPE gw_edge_relay_sent_total counter\n");
        body.push_str(&format!(
            "gw_edge_relay_sent_total {}\n",
            snapshot.sent_total
        ));
        body.push_str("# HELP gw_edge_relay_interest_filtered_total Peer payload copies skipped by confirmed group-interest hints.\n");
        body.push_str("# TYPE gw_edge_relay_interest_filtered_total counter\n");
        body.push_str(&format!(
            "gw_edge_relay_interest_filtered_total {}\n",
            snapshot.interest_filtered_total
        ));
        body.push_str("# HELP gw_edge_relay_interest_ready_peers Peers with a complete non-expired interest snapshot.\n");
        body.push_str("# TYPE gw_edge_relay_interest_ready_peers gauge\n");
        body.push_str(&format!(
            "gw_edge_relay_interest_ready_peers {}\n",
            snapshot.interest_ready_peers
        ));
        body.push_str(
            "# HELP gw_edge_relay_failed_total Relay records rejected or targeting down peers.\n",
        );
        body.push_str("# TYPE gw_edge_relay_failed_total counter\n");
        body.push_str(&format!(
            "gw_edge_relay_failed_total {}\n",
            snapshot.failed_total
        ));
        body.push_str("# HELP gw_edge_relay_unknown_total Relay records with no enqueue-ack within the deadline.\n");
        body.push_str("# TYPE gw_edge_relay_unknown_total counter\n");
        body.push_str(&format!(
            "gw_edge_relay_unknown_total {}\n",
            snapshot.unknown_total
        ));
        body.push_str("# HELP gw_edge_relay_dedup_total Relay records dropped by the (node,boot,seq) watermark.\n");
        body.push_str("# TYPE gw_edge_relay_dedup_total counter\n");
        body.push_str(&format!(
            "gw_edge_relay_dedup_total {}\n",
            snapshot.dedup_total
        ));
        body.push_str(
            "# HELP gw_edge_probe_miss_total Push broadcast-probes with zero local and peer enqueues.\n",
        );
        body.push_str("# TYPE gw_edge_probe_miss_total counter\n");
        body.push_str(&format!(
            "gw_edge_probe_miss_total {}\n",
            snapshot.probe_miss_total
        ));
    }
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    if let Some(bus) = state.edge_redis_bus.get().and_then(|slot| slot.load_full()) {
        let metrics = bus.metrics();
        body.push_str(
            "# HELP gw_edge_redis_pubsub_connected Whether the Redis subscription is connected.\n",
        );
        body.push_str("# TYPE gw_edge_redis_pubsub_connected gauge\n");
        body.push_str(&format!(
            "gw_edge_redis_pubsub_connected {}\n",
            u8::from(metrics.connected())
        ));
        body.push_str(
            "# HELP gw_edge_redis_pubsub_published_total Envelopes accepted by Redis PUBLISH.\n",
        );
        body.push_str("# TYPE gw_edge_redis_pubsub_published_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_pubsub_published_total {}\n",
            metrics.published_total()
        ));
        body.push_str("# HELP gw_edge_redis_pubsub_received_total Envelopes received from the subscribed channel.\n");
        body.push_str("# TYPE gw_edge_redis_pubsub_received_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_pubsub_received_total {}\n",
            metrics.received_total()
        ));
        body.push_str("# HELP gw_edge_redis_pubsub_rejected_total Malformed or out-of-scope envelopes rejected locally.\n");
        body.push_str("# TYPE gw_edge_redis_pubsub_rejected_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_pubsub_rejected_total {}\n",
            metrics.rejected_total()
        ));
        body.push_str("# HELP gw_edge_redis_pubsub_publish_failed_total Redis PUBLISH commands failed or timed out.\n");
        body.push_str("# TYPE gw_edge_redis_pubsub_publish_failed_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_pubsub_publish_failed_total {}\n",
            metrics.publish_failed_total()
        ));
        body.push_str(
            "# HELP gw_edge_redis_pubsub_reconnect_total Subscription reconnect attempts.\n",
        );
        body.push_str("# TYPE gw_edge_redis_pubsub_reconnect_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_pubsub_reconnect_total {}\n",
            metrics.reconnect_total()
        ));
    }
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    if let Some(bus) = state
        .edge_redis_stream
        .get()
        .and_then(|slot| slot.load_full())
    {
        let metrics = bus.metrics();
        body.push_str(
            "# HELP gw_edge_redis_stream_published_total Envelopes appended with XADD.\n",
        );
        body.push_str("# TYPE gw_edge_redis_stream_published_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_stream_published_total {}\n",
            metrics.published_total()
        ));
        body.push_str(
            "# HELP gw_edge_redis_stream_received_total Entries pulled by this node with XREAD.\n",
        );
        body.push_str("# TYPE gw_edge_redis_stream_received_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_stream_received_total {}\n",
            metrics.received_total()
        ));
        body.push_str(
            "# HELP gw_edge_redis_stream_rejected_total Poison or locally rejected entries.\n",
        );
        body.push_str("# TYPE gw_edge_redis_stream_rejected_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_stream_rejected_total {}\n",
            metrics.rejected_total()
        ));
        // naway 不裁剪业务拥有的 edge 流,保留窗口不受它控制;业务裁到本节点 cursor 之前时
        // XREAD 会静默跳过那段历史。这个计数器是该静默丢失的**唯一**信号,必须可告警。
        body.push_str(
            "# HELP gw_edge_redis_stream_trim_gap_total Startup detections that the producer trimmed past this node's cursor (history was silently skipped).\n",
        );
        body.push_str("# TYPE gw_edge_redis_stream_trim_gap_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_stream_trim_gap_total {}\n",
            metrics.trim_gap_total()
        ));
        body.push_str(
            "# HELP gw_edge_redis_stream_publish_failed_total XADD commands failed or timed out.\n",
        );
        body.push_str("# TYPE gw_edge_redis_stream_publish_failed_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_stream_publish_failed_total {}\n",
            metrics.publish_failed_total()
        ));
        body.push_str(
            "# HELP gw_edge_redis_stream_cursor_failed_total Per-node cursor checkpoints failed.\n",
        );
        body.push_str("# TYPE gw_edge_redis_stream_cursor_failed_total counter\n");
        body.push_str(&format!(
            "gw_edge_redis_stream_cursor_failed_total {}\n",
            metrics.cursor_failed_total()
        ));
    }
    // SessionDirectory 指路条只暴露低基数观测，不得带 tenant/user label。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    if let Some(directory) = state.edge_directory.get() {
        let snapshot = directory.metrics();
        body.push_str(
            "# HELP gw_edge_directory_leases Session leases this node holds in the directory.\n",
        );
        body.push_str("# TYPE gw_edge_directory_leases gauge\n");
        body.push_str(&format!("gw_edge_directory_leases {}\n", snapshot.leases));
        body.push_str(
            "# HELP gw_edge_directory_hit_total Directory lookups that returned a node set.\n",
        );
        body.push_str("# TYPE gw_edge_directory_hit_total counter\n");
        body.push_str(&format!(
            "gw_edge_directory_hit_total {}\n",
            snapshot.hit_total
        ));
        body.push_str(
            "# HELP gw_edge_directory_miss_total Directory lookups that found no session.\n",
        );
        body.push_str("# TYPE gw_edge_directory_miss_total counter\n");
        body.push_str(&format!(
            "gw_edge_directory_miss_total {}\n",
            snapshot.miss_total
        ));
        body.push_str(
            "# HELP gw_edge_directory_error_total Directory commands that failed or timed out.\n",
        );
        body.push_str("# TYPE gw_edge_directory_error_total counter\n");
        body.push_str(&format!(
            "gw_edge_directory_error_total {}\n",
            snapshot.error_total
        ));
        body.push_str(
            "# HELP gw_edge_directory_fallback_total Pushes that fell back to broadcast-probe.\n",
        );
        body.push_str("# TYPE gw_edge_directory_fallback_total counter\n");
        body.push_str(&format!(
            "gw_edge_directory_fallback_total {}\n",
            snapshot.fallback_total
        ));
    }
    body.push_str(
        "# HELP gw_oldest_long_connection_snapshot_version Oldest snapshot version held by long connections.\n",
    );
    body.push_str("# TYPE gw_oldest_long_connection_snapshot_version gauge\n");
    body.push_str(&format!(
        "gw_oldest_long_connection_snapshot_version {}\n",
        stats.oldest_version.unwrap_or(0)
    ));
    // 每服务主动健康实例数：healthy/total；service 来自配置并转义，避免请求字段造成高基数或格式注入。
    let service_health = state.active_health.service_health();
    if !service_health.is_empty() {
        body.push_str(
            "# HELP gw_upstream_healthy Healthy upstream instances per service (active health).\n",
        );
        body.push_str("# TYPE gw_upstream_healthy gauge\n");
        for s in service_health.iter() {
            body.push_str(&format!(
                "gw_upstream_healthy{{service=\"{}\"}} {}\n",
                escape_label(&s.service),
                s.healthy
            ));
        }
        body.push_str(
            "# HELP gw_upstream_total Configured upstream instances per service (active health).\n",
        );
        body.push_str("# TYPE gw_upstream_total gauge\n");
        for s in service_health.iter() {
            body.push_str(&format!(
                "gw_upstream_total{{service=\"{}\"}} {}\n",
                escape_label(&s.service),
                s.total
            ));
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(full_body(Bytes::from(body)))
        .expect("build metrics response")
}

/// 业务作用：对活动配置源执行 build-only dry-run，不换版、不重建常驻运行态、不触碰数据面连接。
///
/// 参数说明：
/// - `state`：提供已发布快照的实际来源及文件事务。
///
/// 返回：完整候选的构建报告，或非法候选错误；不把远端模式的 bootstrap 当作活动来源。
async fn dry_run_config(state: &AdminState) -> Response<BoxBody> {
    match Box::pin(candidate::build_current(state)).await {
        Ok(candidate) => dry_run_snapshot_response(state, candidate),
        Err(error) => error.response(),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainRouteInput {
    method: String,
    path: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    proxy: Option<String>,
    #[serde(default)]
    client_ip: Option<String>,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    request_key: Option<String>,
    #[serde(default)]
    candidate_yaml: Option<String>,
}

/// 业务作用：在当前或隔离候选快照上推演一个请求的 route、变量 upstream 和 filter 链。
///
/// 参数说明：
/// - `req`：提供有界 JSON 请求头事实和可选候选 YAML
/// - `state`：提供当前快照、RBAC 与归档基线。
///
/// 返回：输入和候选合法时返回 200 推演结果；无路由仍返回 200 与 `matched=false`；越权、超限或候选构建失败返回 4xx。
async fn explain_route_request(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    if !identity.allows(AdminResource::Routes, AdminAction::DryRun) {
        return json(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "ok": false,
                "error": "forbidden"
            }),
        );
    }
    if !request_content_type(&parts, "application/json") {
        return json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            serde_json::json!({
                "ok": false,
                "error": "Content-Type must be application/json"
            }),
        );
    }
    let body = match collect_bounded_admin_body(
        &parts,
        body,
        state.snap.load().admin_max_config_body_bytes,
    )
    .await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let input: ExplainRouteInput = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(error) => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": format!("invalid explain JSON: {error}")
                }),
            )
        }
    };
    if input.path.len() > 8_192 || !input.path.starts_with('/') {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "path must be an origin-form URI within 8192 bytes"
            }),
        );
    }
    if input.headers.len() > 128
        || input
            .headers
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum::<usize>()
            > 64 * 1024
    {
        return json(
            StatusCode::PAYLOAD_TOO_LARGE,
            serde_json::json!({
                "ok": false,
                "error": "explain headers exceed limits"
            }),
        );
    }
    let method = match input.method.parse::<Method>() {
        Ok(method) => method,
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "invalid HTTP method"
                }),
            )
        }
    };
    let uri = match input.path.parse::<http::Uri>() {
        Ok(uri) if uri.scheme().is_none() && uri.authority().is_none() => uri,
        _ => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "path must be an origin-form URI"
                }),
            )
        }
    };
    let mut request = match http::Request::builder().method(method).uri(uri).body(()) {
        Ok(request) => request,
        Err(error) => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": format!("cannot build explain request: {error}")
                }),
            )
        }
    };
    for (name, value) in &input.headers {
        let name = match name.parse::<http::HeaderName>() {
            Ok(name) => name,
            Err(_) => {
                return json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "error": format!("invalid header name `{name}`")
                    }),
                )
            }
        };
        let value = match value.parse::<http::HeaderValue>() {
            Ok(value) => value,
            Err(_) => {
                return json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "error": format!("invalid header value for `{name}`")
                    }),
                )
            }
        };
        request.headers_mut().append(name, value);
    }
    let (mut request_parts, _) = request.into_parts();
    let snapshot = if let Some(candidate_yaml) = input.candidate_yaml {
        if candidate_yaml.len() > state.snap.load().admin_max_config_body_bytes {
            return json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({
                    "ok": false,
                    "error": "candidate_yaml exceeds configured limit"
                }),
            );
        }
        let version = state.snap.load().version;
        let baseline = match state.config_history.read_archived(version) {
            Ok(baseline) => baseline,
            Err(error) => {
                return json(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "ok": false,
                        "error": error.to_string()
                    }),
                )
            }
        };
        let docs = crate::control::history::ArchivedDocs {
            gateway: candidate_yaml,
            interface_guard: baseline.interface_guard,
            sentinel_rules: baseline.sentinel_rules,
        };
        match build_cluster_candidate_snapshot(&state, &docs).await {
            Ok(candidate) => Arc::new(candidate),
            Err(error) => return error.response(),
        }
    } else {
        state.snap.load_full()
    };
    let proxy = match input
        .proxy
        .as_deref()
        .map(|id| snapshot.proxy(id))
        .unwrap_or_else(|| snapshot.proxies.first())
    {
        Some(proxy) => proxy,
        None => {
            return json(
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "ok": false,
                    "error": "proxy not found"
                }),
            )
        }
    };
    if !crate::proxy::normalize_request_path(&mut request_parts, &proxy.limits) {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok":false,
                "error":"invalid normalized request path"
            }),
        );
    }
    let request_key = input.request_key.unwrap_or_default();
    if request_key.len() > 256 {
        return json(
            StatusCode::PAYLOAD_TOO_LARGE,
            serde_json::json!({
                "ok": false,
                "error": "request_key exceeds 256 bytes"
            }),
        );
    }
    let Some(route) = proxy
        .router
        .match_route_with_key(&request_parts, request_key.as_bytes())
    else {
        return json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "matched": false,
                "proxy": proxy.id,
                "snapshot_version": snapshot.version,
            }),
        );
    };
    let client_ip = match input.client_ip.as_deref().unwrap_or("127.0.0.1").parse() {
        Ok(ip) => ip,
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "invalid client_ip"
                }),
            )
        }
    };
    let scheme = match input.scheme.as_deref().unwrap_or("http") {
        "http" => "http",
        "https" => "https",
        _ => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "scheme must be http or https"
                }),
            )
        }
    };
    if let Some(plan) = proxy
        .router
        .layers
        .as_ref()
        .filter(|plan| plan.topology.nodes.contains_key(&route.id))
    {
        static LAYER_EXPLAINS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
        let Ok(_permit) = LAYER_EXPLAINS.try_acquire() else {
            return plain(
                StatusCode::TOO_MANY_REQUESTS,
                "route explain capacity unavailable\n",
            );
        };
        let explanation = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            plan.explain(
                route.clone(),
                request_parts,
                client_ip,
                &snapshot.ownership,
                &proxy.id,
            ),
        )
        .await
        {
            Ok(value) => value,
            Err(_) => {
                return plain(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route explain deadline exceeded\n",
                )
            }
        };
        // 推演可能跨过管理权限变更；返回任何候选拓扑前重新验证当前管理身份。
        if !authenticate_admin_request(&parts, &state)
            .is_ok_and(|identity| identity.allows(AdminResource::Routes, AdminAction::DryRun))
        {
            return plain(StatusCode::FORBIDDEN, "forbidden\n");
        }
        return json(
            StatusCode::OK,
            serde_json::json!({
                "ok":true,
                "matched":true,
                "proxy":proxy.id,
                "snapshot_version":snapshot.version,
                "route":route.admin_semantic_json(),
                "layers":explanation
            }),
        );
    }
    let eval = crate::routing::variable::EvalContext {
        parts: &request_parts,
        client_ip,
        downstream_proto: scheme,
        request_id: "admin-explain",
        route_id: &route.id,
        response_status: None,
    };
    let upstream = route.upstream_template.render(&eval, &snapshot.variables);
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "matched": true,
            "proxy": proxy.id,
            "snapshot_version": snapshot.version,
            "route": route.admin_semantic_json(),
            "resolved_upstream": upstream,
            "filter_chain": route.admin_filter_chain(),
        }),
    )
}

/// 业务作用：按媒体类型主值检查有 body 的管理请求，允许合法 charset 参数但不做宽松前缀匹配。
///
/// 参数说明：
/// - `parts`：是已解析请求头
/// - `expected`：是小写规范 MIME。
///
/// 返回：Content-Type 主值与期望值大小写无关地精确匹配时返回 true。
fn request_content_type(parts: &AdminRequestParts, expected: &str) -> bool {
    parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

/// 待审批高危变更的不可序列化执行载荷；配置与私钥只保留在有界进程内队列。
enum ApprovalPayload {
    WorkspaceDocuments {
        binding: crate::control::ownership::Binding,
        target: crate::control::history::ArchivedDocs,
        baseline: crate::control::history::ArchivedDocs,
    },
    Documents {
        target: crate::control::history::ArchivedDocs,
        baseline: crate::control::history::ArchivedDocs,
    },
    Certificate {
        tls: Box<crate::config::TlsRuntimeCfg>,
        expected_etag: String,
        certificate_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
    },
}

/// 单条 maker-checker 状态；API 只输出元信息，不输出 payload 或其可逆内容。
struct ApprovalRecord {
    workspace: Option<crate::control::ownership::Binding>,
    id: String,
    resource: AdminResource,
    initiator: String,
    approver: Option<String>,
    digest: String,
    base_version: u64,
    base_fingerprint: u64,
    created_at_ms: u128,
    expires_at_ms: u128,
    status: String,
    reason: Option<String>,
    payload: Option<ApprovalPayload>,
}

/// 已取得唯一执行权的审批候选。
struct ApprovedChange {
    id: String,
    initiator: String,
    base_version: u64,
    base_fingerprint: u64,
    payload: ApprovalPayload,
}

/// 高危变更的进程内有界 maker-checker 登记表。
struct ApprovalRegistry {
    inner: parking_lot::Mutex<VecDeque<ApprovalRecord>>,
    next_id: AtomicU64,
}

impl ApprovalRegistry {
    /// 业务作用：构造空审批登记表；真实容量由当前不可变快照策略逐次限制。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回无候选且单调 id 从 1 开始的 registry。
    fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 业务作用：登记完整候选并冻结提交主体、基线、摘要和过期时刻，登记本身不执行任何外部副作用。
    ///
    /// 参数说明：
    /// - `policy`：审批容量与 TTL 策略。
    /// - `resource`：待执行动作的权限资源域。
    /// - `initiator`：审批发起主体。
    /// - `base_version`：提交时配置基线版本。
    /// - `base_fingerprint`：提交时完整配置指纹。
    /// - `digest`：用于后续复验的候选摘要。
    /// - `payload`：有界待执行载荷。
    /// - `domain_capacity`：当前工作区的审批容量上限。
    ///
    /// 返回：容量可用时返回 change id 与摘要；待审批数达到上限时拒绝且不保存 payload。
    #[allow(clippy::too_many_arguments)]
    fn submit(
        &self,
        policy: &crate::config::model::AdminApprovalCfg,
        resource: AdminResource,
        initiator: &str,
        base_version: u64,
        base_fingerprint: u64,
        digest: String,
        payload: ApprovalPayload,
        domain_capacity: usize,
    ) -> Result<(String, String), String> {
        let now = approval_now_ms();
        let mut inner = self.inner.lock();
        expire_approval_records(&mut inner, now);
        let workspace = match &payload {
            ApprovalPayload::WorkspaceDocuments {
                binding,
                ..
            } => Some(binding.clone()),
            _ => None,
        };
        // 同域名额在登记锁内比较并占用；平台和各工作区分别预留，不能以并发提交越过公平边界。
        if inner
            .iter()
            .filter(|record| {
                matches!(record.status.as_str(), "pending" | "executing")
                    && record
                        .workspace
                        .as_ref()
                        .map(|binding| &binding.owner.workspace)
                        == workspace.as_ref().map(|binding| &binding.owner.workspace)
            })
            .count()
            >= domain_capacity
        {
            return Err("approval domain capacity reached".into());
        }
        if inner
            .iter()
            .filter(|record| matches!(record.status.as_str(), "pending" | "executing"))
            .count()
            >= policy.max_pending
        {
            return Err("pending approval capacity reached".to_string());
        }
        while inner.len() >= policy.max_pending.saturating_mul(2).max(policy.max_pending) {
            let removable = inner
                .iter()
                .position(|record| !matches!(record.status.as_str(), "pending" | "executing"));
            let Some(removable) = removable else {
                return Err("approval history capacity reached".to_string());
            };
            inner.remove(removable);
        }
        let id = format!(
            "change-{}-{now}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        inner.push_back(ApprovalRecord {
            workspace,
            id: id.clone(),
            resource,
            initiator: initiator.to_string(),
            approver: None,
            digest: digest.clone(),
            base_version,
            base_fingerprint,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(u128::from(policy.ttl_seconds) * 1000),
            status: "pending".to_string(),
            reason: None,
            payload: Some(payload),
        });
        Ok((id, digest))
    }

    /// 业务作用：输出调用者获授权资源的审批元信息，并在读取前让过期候选失去 payload 权威。
    ///
    /// 参数说明：
    /// - `identity`：是已认证主体，用于逐资源过滤。
    ///
    /// 返回：返回不含配置、证书、私钥的 JSON 数组。
    fn snapshot(&self, identity: &AdminIdentity) -> Vec<serde_json::Value> {
        let now = approval_now_ms();
        let mut inner = self.inner.lock();
        expire_approval_records(&mut inner, now);
        inner
            .iter()
            .filter(|record| {
                record.workspace.is_none() && identity.allows(record.resource, AdminAction::Write)
            })
            .map(approval_record_json)
            .collect()
    }

    /// 业务作用：原子完成另一主体、阶段、TTL 与候选摘要复验，并一次性取走 payload 执行权。
    ///
    /// 参数说明：
    /// - `id`：绑定候选
    /// - `digest`：绑定候选
    /// - `approver`：是当前已认证主体。
    ///
    /// 返回：全部门禁通过时返回唯一 ApprovedChange；任一不满足时保持无副作用并返回原因。
    fn approve(&self, id: &str, digest: &str, approver: &str) -> Result<ApprovedChange, String> {
        let now = approval_now_ms();
        let mut inner = self.inner.lock();
        expire_approval_records(&mut inner, now);
        let record = inner
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| "change not found".to_string())?;
        if record.status != "pending" {
            return Err(format!("change is not pending (status={})", record.status));
        }
        if record.initiator == approver {
            return Err("initiator cannot approve the same change".to_string());
        }
        if record.digest != digest {
            return Err("candidate digest changed; refresh change status".to_string());
        }
        let payload = record
            .payload
            .take()
            .ok_or_else(|| "change payload is unavailable".to_string())?;
        record.status = "executing".to_string();
        record.approver = Some(approver.to_string());
        Ok(ApprovedChange {
            id: record.id.clone(),
            initiator: record.initiator.clone(),
            base_version: record.base_version,
            base_fingerprint: record.base_fingerprint,
            payload,
        })
    }

    /// 业务作用：让待审批候选原子进入拒绝终态并销毁 payload，迟到批准不能再产生副作用。
    ///
    /// 参数说明：
    /// - `id`：绑定候选
    /// - `digest`：绑定候选
    /// - `principal`：记录拒绝主体。
    ///
    /// 返回：候选仍 pending 且摘要一致时成功；其它状态或失配返回原因。
    fn reject(&self, id: &str, digest: &str, principal: &str) -> Result<(), String> {
        let now = approval_now_ms();
        let mut inner = self.inner.lock();
        expire_approval_records(&mut inner, now);
        let record = inner
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| "change not found".to_string())?;
        if record.status != "pending" {
            return Err(format!("change is not pending (status={})", record.status));
        }
        if record.digest != digest {
            return Err("candidate digest changed; refresh change status".to_string());
        }
        record.payload = None;
        record.status = "rejected".to_string();
        record.approver = Some(principal.to_string());
        record.reason = Some("rejected by reviewer".to_string());
        Ok(())
    }

    /// 业务作用：在外部执行完成后记录终态，禁止同一 change 再次取得 payload 或被误判 pending。
    ///
    /// 参数说明：
    /// - `id`：定位 executing 记录
    /// - `status`：描述真实执行结果。
    /// - `reason`：描述真实执行结果。
    ///
    /// 返回：记录存在时更新；不存在时忽略，因为执行权已经唯一消费且不能重建 payload。
    fn complete(&self, id: &str, status: &str, reason: Option<String>) {
        if let Some(record) = self.inner.lock().iter_mut().find(|record| record.id == id) {
            record.status = status.to_string();
            record.reason = reason;
            record.payload = None;
        }
    }

    /// 业务作用：读取变更的资源域供动态 RBAC 裁决，不暴露 payload。
    ///
    /// 参数说明：
    /// - `id`：是 change path 中的稳定标识。
    ///
    /// 返回：记录存在时返回资源域；不存在返回 None。
    fn resource(&self, id: &str) -> Option<AdminResource> {
        self.inner
            .lock()
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.resource)
    }

    /// 业务作用：读取审批固定的归属域，不以审批路径或提交者自报值作为权威。
    ///
    /// 参数说明：
    /// - `id`：是待复核记录。
    ///
    /// 返回：存在时返回其工作区绑定，平台记录为空绑定；不存在返回外层 None。
    fn workspace(&self, id: &str) -> Option<Option<crate::control::ownership::Binding>> {
        self.inner
            .lock()
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.workspace.clone())
    }

    /// 业务作用：读取登记时冻结的候选摘要，审计不能把客户端 If-Match 冒充真实候选。
    ///
    /// 参数说明：
    /// - `id`：为已经定位的审批记录。
    ///
    /// 返回：记录存在时返回固定摘要；记录被退休后返回 None。
    fn candidate_digest(&self, id: &str) -> Option<String> {
        self.inner
            .lock()
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.digest.clone())
    }

    /// 业务作用：输出已授权单工作区的审批元信息，不含候选正文或其它域统计。
    ///
    /// 参数说明：
    /// - `owner`：是 handler 已复验的工作区、租户与环境，不能仅凭可复用的显示标识查询历史。
    ///
    /// 返回：当前域有限审批列表，读取时退休过期候选。
    fn workspace_snapshot(
        &self,
        owner: &crate::control::ownership::Owner,
    ) -> Vec<serde_json::Value> {
        let mut records = self.inner.lock();
        expire_approval_records(&mut records, approval_now_ms());
        records
            .iter()
            .filter(|record| {
                record
                    .workspace
                    .as_ref()
                    .is_some_and(|binding| &binding.owner == owner)
            })
            .map(approval_record_json)
            .collect()
    }
}

/// 业务作用：使达到 TTL 的 pending 候选失去执行载荷并进入 expired 终态。
///
/// 参数说明：
/// - `records`：是锁内登记表
/// - `now`：是同一轮使用的 Unix 毫秒。
///
/// 返回：无；只修改过期 pending 记录，执行中和终态保持不变。
fn expire_approval_records(records: &mut VecDeque<ApprovalRecord>, now: u128) {
    for record in records.iter_mut() {
        if record.status == "pending" && now >= record.expires_at_ms {
            record.payload = None;
            record.status = "expired".to_string();
            record.reason = Some("approval TTL expired".to_string());
        }
    }
}

/// 业务作用：为审批 TTL 与审计展示取得当前 Unix 毫秒；系统时钟早于 epoch 时安全回退为零。
///
/// 参数说明: 无。
///
/// 返回：返回当前 Unix epoch 毫秒或零。
fn approval_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

/// 业务作用：把审批记录转换为低敏读模型，资源名保持与 RBAC 配置键一致。
///
/// 参数说明：
/// - `record`：是锁内稳定借用。
///
/// 返回：返回不含 payload 的 JSON value。
fn approval_record_json(record: &ApprovalRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "workspace":record.workspace,
        "resource": admin_resource_name(record.resource),
        "initiator": record.initiator,
        "approver": record.approver,
        "candidate_etag": format!("\"sha256-{}\"", record.digest),
        "base_version": record.base_version,
        "base_fingerprint": record.base_fingerprint,
        "created_at_ms": record.created_at_ms,
        "expires_at_ms": record.expires_at_ms,
        "status": record.status,
        "reason": record.reason,
    })
}

/// 业务作用：将固定 RBAC 资源域映射为公开配置使用的 kebab-case 名称。
///
/// 参数说明：
/// - `resource`：是枚举资源域。
///
/// 返回：返回稳定、非本地化资源名。
fn admin_resource_name(resource: AdminResource) -> &'static str {
    match resource {
        AdminResource::Config => "config",
        AdminResource::Routes => "routes",
        AdminResource::InterfaceGuard => "interface-guard",
        AdminResource::Sentinel => "sentinel",
        AdminResource::Acl => "acl",
        AdminResource::Secrets => "secrets",
        AdminResource::Consumers => "consumers",
        AdminResource::Certs => "certs",
        AdminResource::Cluster => "cluster",
        AdminResource::Cache => "cache",
        AdminResource::Connections => "connections",
        AdminResource::Upstreams => "upstreams",
        AdminResource::Audit => "audit",
        AdminResource::Diagnostics => "diagnostics",
    }
}

// ── 集群 rollout 登记与收敛查询 ──

/// 一次集群发布的登记项。**不含配置内容**:内容事实源在 Nacos,这里只留可审计的元信息。
#[derive(Clone, serde::Serialize)]
pub(crate) struct RolloutRecord {
    /// 工作区动作保留审批的 owner 与候选摘要；平台发布为 None。
    pub(crate) workspace: Option<audit::WorkspaceAudit>,
    /// 候选生效后的权威图；canary 节点自身也可证明仍属于这一发布。
    #[serde(skip)]
    candidate_authority: Option<crate::control::ownership::Binding>,
    /// 本节点生成的 rollout 标识(单调序号 + 起始时刻,便于日志对齐)。
    pub(crate) id: String,
    /// 发布时本节点线上版本(收敛判据:各节点版本必须越过它)。
    pub(crate) base_version: u64,
    /// CAS 写入的 Nacos dataId。
    pub(crate) data_id: String,
    /// 发起时刻(Unix 毫秒)。
    pub(crate) started_at_ms: u128,
    /// 状态机阶段；全量兼容发布使用 `published`，渐进发布使用 canary/approval/promoting 等阶段。
    pub(crate) phase: String,
    /// 发起发布的已认证主体；只记录稳定 id，不保存凭据。
    pub(crate) initiator: String,
    /// 完成四眼确认的主体；未要求或尚未确认时为空。
    pub(crate) approver: Option<String>,
    /// canary 节点及其独立 override dataId。
    pub(crate) canary_nodes: Vec<CanaryNode>,
    /// 阶段失败或健康门拒绝的低敏原因。
    pub(crate) reason: Option<String>,
    /// 候选完整三文档的稳定 SHA-256；审批必须绑定该值。
    pub(crate) candidate_digest: String,
    /// 发布目标的原始三文档摘要；不同于包含工作区权威的审批摘要。
    pub(crate) documents_digest: String,
    /// 当前阶段是否需要另一主体确认。
    pub(crate) approval_required: bool,
    /// 观察窗完成后的聚合健康证据；证据不足时保持为空并回滚。
    pub(crate) health: Option<RolloutHealthEvidence>,
    /// 渐进发布内部目标配置；只留进程内，不通过 API 回显原文。
    #[serde(skip)]
    target: Option<crate::control::history::ArchivedDocs>,
    /// 发布前全局配置，用于 CAS、健康失败回滚和并发漂移判断。
    #[serde(skip)]
    baseline: Option<crate::control::history::ArchivedDocs>,
    /// 健康门阈值快照；后续配置热更不能改变一个已经开始的 rollout 判据。
    #[serde(skip)]
    policy: Option<crate::config::model::AdminRolloutCfg>,
    /// 发布开始时的 Nacos 配置事实源，避免 canary 自身改动 bootstrap 后把后续阶段引向另一集群。
    #[serde(skip)]
    nacos: Option<crate::config::model::NacosConfigSourceCfg>,
    /// 发布开始时的成员发现配置，用于收敛和健康证据复验。
    #[serde(skip)]
    discovery: Option<crate::config::model::NacosDiscoveryCfg>,
}

/// 渐进发布选中的单个节点；IP 来自发现事实，node_id 用于派生节点专属 dataId。
#[derive(Clone, serde::Serialize)]
pub(crate) struct CanaryNode {
    /// Nacos 自注册稳定节点身份。
    pub(crate) node_id: String,
    /// Nacos 发现返回的成员 IP；用于受限 admin metrics 抓取。
    pub(crate) ip: String,
    /// 节点专属 canary override dataId。
    pub(crate) data_id: String,
    /// 发布前成员表版本，用于证明节点确已换版。
    pub(crate) baseline_version: u64,
    /// 发布前配置指纹，用于防止只看版本就误判已应用候选。
    pub(crate) baseline_fingerprint: u64,
    /// 发现事实约束后的 admin 抓取目标；不信任 metadata 中的主机部分。
    pub(crate) admin_listen: String,
}

/// 进程内有界 rollout 登记表。
///
/// rollout 是**控制面观察辅助**而非事实源:进程重启后归零,集群仍可由
/// `/admin/cluster/consistency` 判断收敛。因此不持久化,只保留最近若干条防无界增长。
pub struct RolloutRegistry {
    inner: parking_lot::Mutex<std::collections::VecDeque<RolloutRecord>>,
    next_id: AtomicU64,
}

impl RolloutRegistry {
    /// 平台保留最近发布；每个工作区有独立四条目录，不能通过高频发布驱逐其它域记录。
    const MAX_RECORDS: usize = 32;

    /// 业务作用：建立不持久化的有界发布观察目录，配置事实仍由原事实源与归档负责。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空登记表和单调进程内标识计数器。
    fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 业务作用：识别不再拥有发布动作的终态，以便退休敏感文档和后端连接配置。
    ///
    /// 参数说明：
    /// - `record`：为锁内一致发布记录。
    ///
    /// 返回：已成功、回滚或失败的记录返回 true，进行中状态返回 false。
    fn terminal(record: &RolloutRecord) -> bool {
        matches!(
            record.phase.as_str(),
            "succeeded" | "rolled_back" | "failed" | "cleanup_failed"
        )
    }

    /// 业务作用：在终态释放完整配置和凭据，只保留有界的归属、候选摘要与结果投影。
    ///
    /// 参数说明：
    /// - `record`：为刚完成状态迁移的发布记录。
    ///
    /// 返回：进行中记录不变；终态不再长期驻留候选和基线正文。
    fn retire_payload(record: &mut RolloutRecord) {
        if Self::terminal(record) {
            record.target = None;
            record.baseline = None;
            record.nacos = None;
            record.discovery = None;
            record.policy = None;
            record.candidate_authority = None;
        }
    }

    /// 业务作用：按当前归属目录和独立域份额回收历史，不驱逐其它活动工作区的观察记录。
    ///
    /// 参数说明：
    /// - `inner`：是锁内目录
    /// - `workspace`：是新记录归属
    /// - `catalog`：是已验证的活动权限图。
    ///
    /// 返回：仅撤下退休域或本域最老的非活动记录；唯一进行中 canary 始终保留。
    fn make_room(
        inner: &mut std::collections::VecDeque<RolloutRecord>,
        workspace: Option<&audit::WorkspaceAudit>,
        catalog: &crate::control::ownership::OwnershipCatalog,
    ) {
        inner.retain(|record| {
            if record.target.is_some() && !Self::terminal(record) {
                return true;
            }
            record.workspace.as_ref().is_none_or(|scope| {
                catalog
                    .binding(&scope.binding.owner.workspace)
                    .is_some_and(|binding| binding.owner == scope.binding.owner)
            })
        });
        let owner = workspace.map(|scope| &scope.binding.owner);
        let limit = if owner.is_some() {
            4
        } else {
            Self::MAX_RECORDS
        };
        while inner
            .iter()
            .filter(|record| record.workspace.as_ref().map(|scope| &scope.binding.owner) == owner)
            .count()
            >= limit
        {
            let Some(index) = inner.iter().position(|record| {
                record.workspace.as_ref().map(|scope| &scope.binding.owner) == owner
                    && (record.target.is_none() || Self::terminal(record))
            }) else {
                break;
            };
            inner.remove(index);
        }
    }

    /// 业务作用：为已完成远端 CAS 的发布保存归属摘要，使工作区状态查询不能回退到平台目录。
    ///
    /// 参数说明：
    /// - `base_version`：发布前全局配置版本。
    /// - `data_id`：全局事实源 dataId。
    /// - `initiator`：已认证提交主体。
    /// - `documents_digest`：完整文档摘要。
    /// - `workspace`：冻结的工作区审批权威。
    /// - `catalog`：当前归属目录。
    ///
    /// 返回：进程内有界发布登记 id，不代表集群已收敛。
    fn start_scoped(
        &self,
        base_version: u64,
        data_id: &str,
        initiator: &str,
        documents_digest: String,
        workspace: Option<audit::WorkspaceAudit>,
        catalog: &crate::control::ownership::OwnershipCatalog,
    ) -> String {
        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or_default();
        let id = format!(
            "rollout-{}-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed),
            started_at_ms
        );
        let record = RolloutRecord {
            documents_digest,
            candidate_digest: workspace
                .as_ref()
                .map_or_else(String::new, |scope| scope.candidate_sha256.clone()),
            workspace,
            candidate_authority: None,
            id: id.clone(),
            base_version,
            data_id: data_id.to_string(),
            started_at_ms,
            phase: "published".to_string(),
            initiator: initiator.to_string(),
            approver: None,
            canary_nodes: Vec::new(),
            reason: None,
            approval_required: false,
            health: None,
            target: None,
            baseline: None,
            policy: None,
            nacos: None,
            discovery: None,
        };
        let mut inner = self.inner.lock();
        Self::make_room(&mut inner, record.workspace.as_ref(), catalog);
        inner.push_back(record);
        #[cfg(feature = "telemetry-otlp")]
        crate::observability::metrics::governance::rollout(None, "published");
        id
    }

    /// 业务作用：登记一项已经写入节点 override 的渐进发布，并冻结目标、基线和健康门判据。
    ///
    /// 参数说明：
    /// - `base_version`：全局配置基线版本。
    /// - `data_id`：全局事实源 dataId。
    /// - `initiator`：已认证审批发起主体。
    /// - `candidate_digest`：绑定审批候选的文档摘要。
    /// - `canary_nodes`：参与金丝雀阶段的固定节点集。
    /// - `target`：完整目标文档。
    /// - `baseline`：完整回退基线。
    /// - `policy`：渐进发布与观察策略。
    /// - `nacos`：冻结的 Nacos 配置源。
    /// - `discovery`：冻结的成员发现配置。
    /// - `workspace`：冻结的工作区审批权威。
    /// - `candidate_authority`：候选中的控制面归属权威。
    /// - `catalog`：当前归属目录。
    ///
    /// 返回：新 rollout id；若已有未结束的渐进发布则拒绝，避免同一节点 override 被并发流程覆盖。
    #[allow(clippy::too_many_arguments)]
    fn start_canary(
        &self,
        base_version: u64,
        data_id: &str,
        initiator: &str,
        candidate_digest: String,
        canary_nodes: Vec<CanaryNode>,
        target: crate::control::history::ArchivedDocs,
        baseline: crate::control::history::ArchivedDocs,
        policy: crate::config::model::AdminRolloutCfg,
        nacos: crate::config::model::NacosConfigSourceCfg,
        discovery: crate::config::model::NacosDiscoveryCfg,
        workspace: Option<audit::WorkspaceAudit>,
        candidate_authority: Option<crate::control::ownership::Binding>,
        catalog: &crate::control::ownership::OwnershipCatalog,
    ) -> anyhow::Result<String> {
        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or_default();
        let mut inner = self.inner.lock();
        anyhow::ensure!(
            !inner.iter().any(|record| {
                record.target.is_some()
                    && !matches!(
                        record.phase.as_str(),
                        "succeeded" | "rolled_back" | "failed" | "cleanup_failed"
                    )
            }),
            "another canary rollout is still active"
        );
        let id = format!(
            "rollout-{}-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed),
            started_at_ms
        );
        Self::make_room(&mut inner, workspace.as_ref(), catalog);
        inner.push_back(RolloutRecord {
            documents_digest: target.digest(),
            workspace,
            candidate_authority,
            id: id.clone(),
            base_version,
            data_id: data_id.to_string(),
            started_at_ms,
            phase: "canary_published".to_string(),
            initiator: initiator.to_string(),
            approver: None,
            canary_nodes,
            reason: None,
            candidate_digest,
            approval_required: policy.require_approval,
            health: None,
            target: Some(target),
            baseline: Some(baseline),
            policy: Some(policy),
            nacos: Some(nacos),
            discovery: Some(discovery),
        });
        #[cfg(feature = "telemetry-otlp")]
        crate::observability::metrics::governance::rollout(None, "canary_published");
        Ok(id)
    }

    /// 业务作用：读取指定 rollout 的一致快照，供后台状态机和审批端点复验身份、候选与阶段。
    ///
    /// 参数说明：
    /// - `id`：是管理面返回的稳定 rollout id。
    ///
    /// 返回：存在时返回克隆快照；不存在返回 `None`。
    fn get(&self, id: &str) -> Option<RolloutRecord> {
        self.inner
            .lock()
            .iter()
            .find(|record| record.id == id)
            .cloned()
    }

    /// 业务作用：在锁内更新指定 rollout，保证阶段、审批人和失败原因不会被并发请求撕裂。
    ///
    /// 参数说明：
    /// - `id`：定位记录
    /// - `update`：只修改低频控制面状态，不执行外部 I/O。
    ///
    /// 返回：找到并更新时为 true；记录不存在时为 false。
    fn update(&self, id: &str, update: impl FnOnce(&mut RolloutRecord)) -> bool {
        let mut inner = self.inner.lock();
        let Some(record) = inner.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        #[cfg(feature = "telemetry-otlp")]
        let previous = record.phase.clone();
        update(record);
        #[cfg(feature = "telemetry-otlp")]
        crate::observability::metrics::governance::rollout(Some(&previous), &record.phase);
        Self::retire_payload(record);
        true
    }

    /// 业务作用：仅当 rollout 仍处于预期阶段时执行转移，防止后台观察覆盖人工拒绝或其它终态。
    ///
    /// 参数说明：
    /// - `id`：定位记录
    /// - `expected`：是转移前阶段
    /// - `update`：只修改进程内状态。
    ///
    /// 返回：阶段匹配时返回转移后快照；记录不存在或已被并发转移时返回 `None`。
    fn update_if_phase(
        &self,
        id: &str,
        expected: &str,
        update: impl FnOnce(&mut RolloutRecord),
    ) -> Option<RolloutRecord> {
        let mut inner = self.inner.lock();
        let record = inner
            .iter_mut()
            .find(|record| record.id == id && record.phase == expected)?;
        update(record);
        #[cfg(feature = "telemetry-otlp")]
        crate::observability::metrics::governance::rollout(Some(expected), &record.phase);
        Self::retire_payload(record);
        Some(record.clone())
    }

    /// 业务作用：在同一把锁内完成四眼审批的阶段、候选摘要和主体复验。
    ///
    /// 参数说明：
    /// - `id`：定位发布
    /// - `candidate_digest`：来自 `If-Match`
    /// - `approver`：是已通过 RBAC 的主体。
    ///
    /// 返回：所有门禁通过时原子进入 `promoting` 并返回快照；否则不改状态并返回可审计原因。
    fn approve(
        &self,
        id: &str,
        candidate_digest: &str,
        approver: &str,
    ) -> Result<RolloutRecord, String> {
        let mut inner = self.inner.lock();
        let record = inner
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| "rollout not found".to_string())?;
        if record.phase != "awaiting_approval" {
            return Err(format!(
                "rollout is not awaiting approval (phase={})",
                record.phase
            ));
        }
        if !record.approval_required {
            return Err("rollout does not require approval".to_string());
        }
        if record.initiator == approver {
            return Err("initiator cannot approve the same rollout".to_string());
        }
        if record.candidate_digest != candidate_digest {
            return Err("candidate digest changed; refresh rollout status".to_string());
        }
        record.approver = Some(approver.to_string());
        record.phase = "promoting".to_string();
        #[cfg(feature = "telemetry-otlp")]
        crate::observability::metrics::governance::rollout(
            Some("awaiting_approval"),
            &record.phase,
        );
        Ok(record.clone())
    }

    /// 业务作用：原子标记一个尚未全局放量的 canary 为人工拒绝，为后续安全撤销取得唯一执行权。
    ///
    /// 参数说明：
    /// - `id`：定位发布
    /// - `candidate_digest`：绑定用户看到的候选
    /// - `principal`：用于失败原因审计。
    ///
    /// 返回：可撤销阶段进入 `rolling_back` 并返回快照；已开始全局晋级、终态或摘要失配时拒绝。
    fn reject(
        &self,
        id: &str,
        candidate_digest: &str,
        principal: &str,
    ) -> Result<RolloutRecord, String> {
        let mut inner = self.inner.lock();
        let record = inner
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| "rollout not found".to_string())?;
        if !matches!(
            record.phase.as_str(),
            "canary_published" | "observing" | "awaiting_approval"
        ) {
            return Err(format!(
                "rollout cannot be rejected in phase {}",
                record.phase
            ));
        }
        if record.candidate_digest != candidate_digest {
            return Err("candidate digest changed; refresh rollout status".to_string());
        }
        #[cfg(feature = "telemetry-otlp")]
        let previous = record.phase.clone();
        record.phase = "rolling_back".to_string();
        record.reason = Some(format!("rejected by {principal}"));
        #[cfg(feature = "telemetry-otlp")]
        crate::observability::metrics::governance::rollout(Some(&previous), &record.phase);
        Ok(record.clone())
    }

    /// 业务作用：最近一次发布登记。
    fn latest(&self) -> Option<RolloutRecord> {
        self.inner.lock().back().cloned()
    }
}

/// 业务作用：从已发现成员中确定性选出 canary，同时固化发布前版本、指纹和受限 admin 目标。
///
/// 参数说明：
/// - `instances`：是完整网关成员表
/// - `policy`：提供数量与 metadata selector
/// - `nacos`：提供原子 bundle dataId。
///
/// 返回：存在足够健康、可观测节点且仍留有基线组时返回按 node_id 排序的 canary；证据不足时拒绝。
fn select_canary_nodes(
    instances: &[nasa::discovery::Instance],
    policy: &crate::config::model::AdminRolloutCfg,
    nacos: &crate::config::model::NacosConfigSourceCfg,
) -> anyhow::Result<Vec<CanaryNode>> {
    let mut all_observable = Vec::new();
    let mut selected_candidates = Vec::new();
    let mut node_ids = HashSet::new();
    for instance in instances.iter().filter(|item| item.enabled && item.healthy) {
        let Some(node_id) = instance.metadata.get("gateway.node_id") else {
            continue;
        };
        let data_id = match crate::control::reload::nacos_canary_data_id(nacos, node_id) {
            Ok(data_id) => data_id,
            Err(_) => continue,
        };
        let Some(version) = instance
            .metadata
            .get("gateway.version")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        let Some(fingerprint) = instance
            .metadata
            .get("gateway.fingerprint")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        let Ok(target) = cluster_metrics_target(instance) else {
            continue;
        };
        anyhow::ensure!(
            node_ids.insert(node_id.clone()),
            "duplicate gateway.node_id `{node_id}` in discovery membership"
        );
        let candidate = CanaryNode {
            node_id: node_id.clone(),
            ip: instance.ip.clone(),
            data_id,
            baseline_version: version,
            baseline_fingerprint: fingerprint,
            admin_listen: target.to_string(),
        };
        all_observable.push(node_id.clone());
        let selector_matches = policy.selector_key.is_empty()
            || instance
                .metadata
                .get(&policy.selector_key)
                .is_some_and(|value| value == &policy.selector_value);
        if selector_matches {
            selected_candidates.push(candidate);
        }
    }
    selected_candidates.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    anyhow::ensure!(
        selected_candidates.len() >= policy.canary_count,
        "only {} observable members match canary selector; {} required",
        selected_candidates.len(),
        policy.canary_count
    );
    anyhow::ensure!(
        all_observable.len() > policy.canary_count,
        "canary requires at least one separate observable baseline member"
    );
    selected_candidates.truncate(policy.canary_count);
    Ok(selected_candidates)
}

#[derive(Clone, Copy)]
enum CanaryOverrideOperation {
    Publish,
    Cleanup,
}

/// 业务作用：把节点级 canary override 的 Nacos I/O 卸载到独立 current-thread runtime。
///
/// 参数说明：
/// - `nacos`：定位配置中心
/// - `rollout_id`：绑定候选
/// - `target`：绑定候选
/// - `nodes`：限定 override 集合
/// - `operation`：决定发布或安全清理。
///
/// 返回：所有 override 完成时成功；任一节点并发冲突、归属丢失或网络错误时失败。
async fn run_canary_overrides_offloaded(
    nacos: crate::config::model::NacosConfigSourceCfg,
    rollout_id: String,
    target: crate::control::history::ArchivedDocs,
    nodes: Vec<CanaryNode>,
    operation: CanaryOverrideOperation,
) -> anyhow::Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("gateway-nacos-canary".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(Err(anyhow::anyhow!(
                        "build nacos canary runtime failed: {error}"
                    )));
                    return;
                }
            };
            let result = runtime.block_on(canary_overrides_once(
                &nacos,
                &rollout_id,
                &target,
                &nodes,
                operation,
            ));
            let _ = tx.send(result);
        });
    if let Err(error) = spawned {
        return Err(anyhow::anyhow!("spawn nacos canary worker failed: {error}"));
    }
    rx.await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("nacos canary worker exited without result")))
}

/// 业务作用：发布或清理一组带 rollout 归属的 Nacos 节点 override。
///
/// 参数说明：
/// - `nacos`：冻结的 Nacos 配置源。
/// - `rollout_id`：本次渐进发布标识。
/// - `target`：将要发布的完整目标文档。
/// - `nodes`：本次允许操作的节点集合。
/// - `operation`：发布或撤销 override 的动作类型。
///
/// 返回：全部成功时返回空值；发布部分失败会先尽力清理本次已写节点再返回错误。
async fn canary_overrides_once(
    nacos: &crate::config::model::NacosConfigSourceCfg,
    rollout_id: &str,
    target: &crate::control::history::ArchivedDocs,
    nodes: &[CanaryNode],
    operation: CanaryOverrideOperation,
) -> anyhow::Result<()> {
    let props = crate::control::reload::nacos_config_props(nacos);
    let client = nasa::config::nacos::NacosConfigClient::connect(&props)
        .await
        .map_err(|error| anyhow::anyhow!("connect nacos failed: {error}"))?;
    let content =
        crate::control::reload::encode_atomic_nacos_bundle(format!("canary-{rollout_id}"), target)?;
    let group = nacos.group.as_str();
    match operation {
        CanaryOverrideOperation::Publish => {
            let mut owned = Vec::new();
            let publish = async {
                for node in nodes {
                    let remote = client
                        .fetch_optional_with_md5(&node.data_id, group)
                        .await
                        .map_err(|error| {
                            anyhow::anyhow!("fetch {} failed: {error}", node.data_id)
                        })?;
                    let (released, released_md5) = if let Some((remote, md5)) = remote {
                        if crate::control::reload::released_canary_owner(&remote).is_some() {
                            (remote, md5)
                        } else {
                            let parsed = crate::control::reload::parse_atomic_nacos_bundle(&remote)
                                .map_err(|error| {
                                    anyhow::anyhow!("parse {} failed: {error:#}", node.data_id)
                                })?;
                            anyhow::ensure!(
                                canary_bundle_owned(&parsed, target, rollout_id),
                                "canary override {} is owned by another candidate",
                                node.data_id
                            );
                            owned.push(node.data_id.clone());
                            continue;
                        }
                    } else {
                        // Nacos 首次创建没有原子 create-only；在线控制器只能复用已离线初始化的槽，
                        // 否则两个发布者可能在“均读到缺席”后互相覆盖。
                        anyhow::bail!("canary slot {} is absent; provision a released marker before enabling rollout", node.data_id)
                    };
                    // 已释放槽只能以读取的 MD5 取得发布权，任何并发写入都使本次 CAS 失配。
                    let published = client
                        .publish_cas_typed(&node.data_id, group, &content, "json", &released_md5)
                        .await
                    .map_err(|error| anyhow::anyhow!("publish {} failed: {error}", node.data_id))?;
                    // 发布 ACK 不代表读取节点已经可见；缺席或精确旧标记只允许有界等待。
                    // 其它内容意味着失权；等待期间不重发，避免把传播延迟变成第二次写入。
                    let verified = if published {
                        owned.push(node.data_id.clone());
                        await_owned_canary_visibility(
                            &client,
                            &node.data_id,
                            group,
                            target,
                            rollout_id,
                            &released,
                        )
                        .await?
                    } else {
                        false
                    };
                    anyhow::ensure!(
                        published && verified,
                        "concurrent canary publish detected at {}",
                        node.data_id
                    );
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(error) = publish {
                // 任一外部错误都必须补偿已经取得归属的 override，不能留下半完成 canary。
                for data_id in owned.iter().rev() {
                    let _ =
                        remove_owned_canary_override(&client, data_id, group, target, rollout_id)
                            .await;
                }
                return Err(error);
            }
            Ok(())
        }
        CanaryOverrideOperation::Cleanup => {
            for node in nodes {
                remove_owned_canary_override(&client, &node.data_id, group, target, rollout_id)
                    .await?;
            }
            Ok(())
        }
    }
}

/// 业务作用：确认已获发布 ACK 的节点候选可读且仍属于同一次发布，不把传播期间的缺席当作归属。
///
/// 参数说明：
/// - `client`：定位远端候选
/// - `data_id`：定位远端候选
/// - `group`：定位远端候选
/// - `target`：固定文档和身份
/// - `rollout_id`：固定文档和身份
/// - `previous`：是 CAS 消费的精确释放标记。
///
/// 返回：五秒内读取到完全一致的候选时成功；其它候选立即返回 false，旧标记或缺席只等待，超时或读取故障失败。
async fn await_owned_canary_visibility(
    client: &nasa::config::nacos::NacosConfigClient,
    data_id: &str,
    group: &str,
    target: &crate::control::history::ArchivedDocs,
    rollout_id: &str,
    previous: &str,
) -> anyhow::Result<bool> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some((remote, _)) = client.fetch_optional_with_md5(data_id, group).await? {
                if remote != previous {
                    let parsed = crate::control::reload::parse_atomic_nacos_bundle(&remote)?;
                    return Ok(canary_bundle_owned(&parsed, target, rollout_id));
                }
            }
            // 没有可见证据时不开放业务路由，也不把缺席解释为可以重新取得发布权。
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("canary publication visibility deadline exceeded"))?
}

/// 业务作用：只原子释放仍与本 rollout 一致的覆盖层，防止读取后删除误删并发新候选。
///
/// 参数说明：
/// - `client`：受信 Nacos 配置客户端。
/// - `data_id`：节点 override 的 dataId。
/// - `group`：节点 override 所属 group。
/// - `target`：用于证明本次 rollout 所有权的完整文档。
/// - `rollout_id`：必须与远端拥有者一致的 rollout 标识。
///
/// 返回：缺席、已由本次释放或 CAS 释放成功时成功；内容换主或 CAS 失配时不修改远端。
async fn remove_owned_canary_override(
    client: &nasa::config::nacos::NacosConfigClient,
    data_id: &str,
    group: &str,
    target: &crate::control::history::ArchivedDocs,
    rollout_id: &str,
) -> anyhow::Result<()> {
    let Some((remote, md5)) = client.fetch_optional_with_md5(data_id, group).await? else {
        return Ok(());
    };
    if let Some(owner) = crate::control::reload::released_canary_owner(&remote) {
        anyhow::ensure!(
            owner == rollout_id,
            "canary release belongs to another rollout"
        );
        return Ok(());
    }
    let parsed = crate::control::reload::parse_atomic_nacos_bundle(&remote)
        .map_err(|error| anyhow::anyhow!("parse canary override {data_id} failed: {error:#}"))?;
    anyhow::ensure!(
        canary_bundle_owned(&parsed, target, rollout_id),
        "refuse to remove canary override {data_id}: candidate ownership changed"
    );
    // Nacos 删除不提供内容 CAS；保留小型释放标记让节点回到全局 bundle，禁止 get 后无条件删除。
    let release = crate::control::reload::encode_canary_release(rollout_id)?;
    anyhow::ensure!(
        client
            .publish_cas_typed(data_id, group, &release, "json", &md5)
            .await?,
        "canary override changed before release CAS: {data_id}"
    );
    Ok(())
}

/// 业务作用：同时复验 override 的 rollout 标识与完整三文档，作为清理外部副作用的归属证据。
///
/// 参数说明：
/// - `bundle`：是远端当前内容
/// - `target`：是冻结候选
/// - `rollout_id`：是本状态机唯一标识。
///
/// 返回：版本标识和三文档全部精确匹配时返回 true；任一差异都视为归属已改变。
fn canary_bundle_owned(
    bundle: &crate::control::reload::AtomicNacosConfigBundle,
    target: &crate::control::history::ArchivedDocs,
    rollout_id: &str,
) -> bool {
    bundle.bundle_version == format!("canary-{rollout_id}")
        && atomic_bundle_matches_docs(bundle, target)
}

/// 业务作用：等待所有 canary 节点的自注册事实证明候选已上线。
///
/// 参数说明：
/// - `state`：提供常驻有界成员查询。
/// - `record`：固化发现配置、canary 及各自基线版本/指纹。
///
/// 返回：选中节点全部健康、版本前进、指纹变化且三文档精确匹配目标时成功；发现失败或超时时失败。
async fn await_canary_applied(state: &AdminState, record: &RolloutRecord) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let nacos = record
            .discovery
            .clone()
            .ok_or_else(|| anyhow::anyhow!("rollout discovery snapshot is missing"))?;
        let service = crate::upstream::discovery::self_register_service_name(&nacos)
            .ok_or_else(|| anyhow::anyhow!("canary rollout requires Nacos self-registration"))?;
        let instances = state
            .member_discovery
            .discover(&nacos, service, cluster::discovery::REQUEST_TIMEOUT)
            .await?;
        let ready = record.canary_nodes.iter().all(|canary| {
            instances.iter().any(|instance| {
                instance.enabled
                    && instance.healthy
                    && instance.metadata.get("gateway.bundle_sha256")
                        == Some(&record.documents_digest)
                    && instance
                        .metadata
                        .get("gateway.node_id")
                        .is_some_and(|node_id| node_id == &canary.node_id)
                    && instance
                        .metadata
                        .get("gateway.version")
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|version| version > canary.baseline_version)
                    && instance
                        .metadata
                        .get("gateway.fingerprint")
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|fingerprint| fingerprint != canary.baseline_fingerprint)
            })
        });
        if ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("canary nodes did not publish the candidate version within 120 seconds");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// 业务作用：对当前所有健康可观测成员抓取一次渐进发布指标快照。
///
/// 参数说明：
/// - `state`：提供发现与受 Cluster/Read 限制凭据的管理状态。
/// - `record`：固定本次发布范围与观察基线的记录。
///
/// 返回：每个健康可观测节点都成功返回按 node_id 索引的快照；任一抓取或解析失败时整体失败闭合。
async fn sample_rollout_metrics(
    state: &AdminState,
    record: &RolloutRecord,
) -> anyhow::Result<std::collections::BTreeMap<String, RolloutMetricCounters>> {
    let auth = {
        let snapshot = state.snap.load();
        snapshot.admin_auth.clone()
    };
    let nacos = record
        .discovery
        .clone()
        .ok_or_else(|| anyhow::anyhow!("rollout discovery snapshot is missing"))?;
    anyhow::ensure!(
        auth.allow_cluster_metrics_scrape,
        "cluster metrics scrape is not enabled"
    );
    let auth_header = cluster_scrape_auth_header(&auth)
        .ok_or_else(|| anyhow::anyhow!("no authenticated Cluster/Read scrape credential"))?;
    let service = crate::upstream::discovery::self_register_service_name(&nacos)
        .ok_or_else(|| anyhow::anyhow!("Nacos self-registration is disabled"))?;
    let instances = state
        .member_discovery
        .discover(&nacos, service, cluster::discovery::REQUEST_TIMEOUT)
        .await?;
    let mut targets = Vec::new();
    let mut ids = HashSet::new();
    for instance in instances.iter().filter(|item| item.enabled && item.healthy) {
        let Some(node_id) = instance.metadata.get("gateway.node_id").cloned() else {
            continue;
        };
        let target = cluster_metrics_target(instance)
            .map_err(|reason| anyhow::anyhow!("node {node_id} is not observable: {reason}"))?;
        anyhow::ensure!(ids.insert(node_id.clone()), "duplicate node id {node_id}");
        targets.push((node_id, target));
    }
    anyhow::ensure!(
        targets.len() >= 2,
        "rollout health gate requires at least two nodes"
    );
    let rows = stream::iter(targets.into_iter().map(|(node_id, target)| {
        let auth_header = auth_header.clone();
        async move {
            let text = fetch_peer_metrics_text(target, &auth_header)
                .await
                .map_err(|reason| anyhow::anyhow!("scrape node {node_id}: {reason}"))?;
            let counters = parse_rollout_metric_counters(&text)
                .ok_or_else(|| anyhow::anyhow!("node {node_id} rollout metrics are invalid"))?;
            Ok::<_, anyhow::Error>((node_id, counters))
        }
    }))
    .buffer_unordered(CLUSTER_METRICS_SCRAPE_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    let mut samples = std::collections::BTreeMap::new();
    for row in rows {
        let (node_id, counters) = row?;
        samples.insert(node_id, counters);
    }
    Ok(samples)
}

/// 业务作用：用 canary/基线两组增量证据执行 5xx、熔断和 p99 健康门。
///
/// 参数说明：
/// - `before`：是观察窗两端
/// - `after`：是观察窗两端
/// - `canary`：固定选中节点
/// - `policy`：是发布开始时冻结的阈值。
///
/// 返回：证据完整且全部阈值通过时返回聚合证据；无 canary 流量、counter reset 或指标超限时失败。
fn evaluate_rollout_health(
    before: &std::collections::BTreeMap<String, RolloutMetricCounters>,
    after: &std::collections::BTreeMap<String, RolloutMetricCounters>,
    canary: &std::collections::BTreeSet<String>,
    policy: &crate::config::model::AdminRolloutCfg,
) -> Result<RolloutHealthEvidence, String> {
    let before_members: std::collections::BTreeSet<String> = before.keys().cloned().collect();
    let after_members: std::collections::BTreeSet<String> = after.keys().cloned().collect();
    if before_members != after_members {
        return Err("observable cluster membership changed during rollout observation".to_string());
    }
    if !canary.is_subset(&before_members) {
        return Err("one or more canary nodes became unobservable".to_string());
    }
    let baseline: std::collections::BTreeSet<String> =
        before_members.difference(canary).cloned().collect();
    if baseline.is_empty() {
        return Err("no separate baseline nodes remain observable".to_string());
    }
    let canary_delta = aggregate_rollout_metric_delta(before, after, canary)?;
    let baseline_delta = aggregate_rollout_metric_delta(before, after, &baseline)?;
    if canary_delta.requests == 0 {
        return Err("canary received no requests during the observation window".to_string());
    }
    let canary_5xx_ratio = canary_delta.responses_5xx as f64 / canary_delta.requests as f64;
    if canary_5xx_ratio > policy.max_5xx_ratio {
        return Err(format!(
            "canary 5xx ratio {canary_5xx_ratio:.6} exceeds {:.6}",
            policy.max_5xx_ratio
        ));
    }
    if canary_delta.circuit_rejected > 0 {
        return Err(format!(
            "canary circuit breaker rejected {} requests",
            canary_delta.circuit_rejected
        ));
    }
    let canary_p99_ms = rollout_p99_ms(&canary_delta.duration_buckets)
        .ok_or_else(|| "canary request duration histogram has no observations".to_string())?;
    if !canary_p99_ms.is_finite() || canary_p99_ms > policy.max_p99_ms as f64 {
        return Err(format!(
            "canary p99 {canary_p99_ms:.3}ms exceeds {}ms",
            policy.max_p99_ms
        ));
    }
    let baseline_p99_ms = rollout_p99_ms(&baseline_delta.duration_buckets);
    if let Some(baseline_p99_ms) = baseline_p99_ms {
        if canary_p99_ms > baseline_p99_ms * policy.max_p99_regression_ratio {
            return Err(format!(
                "canary p99 {canary_p99_ms:.3}ms exceeds baseline {baseline_p99_ms:.3}ms x {:.3}",
                policy.max_p99_regression_ratio
            ));
        }
    }
    Ok(RolloutHealthEvidence {
        observation_seconds: policy.observation_seconds,
        canary_requests: canary_delta.requests,
        canary_5xx_ratio,
        canary_p99_ms,
        canary_circuit_rejected: canary_delta.circuit_rejected,
        baseline_requests: baseline_delta.requests,
        baseline_5xx_ratio: (baseline_delta.requests > 0)
            .then(|| baseline_delta.responses_5xx as f64 / baseline_delta.requests as f64),
        baseline_p99_ms,
    })
}

/// 业务作用：驱动 canary 换版、观察、健康门与审批/自动晋级的后台状态机。
///
/// 参数说明：
/// - `state`：是常驻管理状态
/// - `rollout_id`：定位已写节点 override 的发布。
///
/// 返回：无显式返回值；每个终态都写入 rollout 登记与配置历史，任一证据不足会先撤销 override。
async fn run_canary_rollout(state: Arc<AdminState>, rollout_id: String) {
    let Some(record) = state.rollouts.get(&rollout_id) else {
        return;
    };
    if let Err(error) = await_canary_applied(&state, &record).await {
        fail_canary_rollout(&state, &rollout_id, "canary_published", error.to_string()).await;
        return;
    }
    let Some(record) = state
        .rollouts
        .update_if_phase(&rollout_id, "canary_published", |record| {
            record.phase = "observing".to_string();
        })
    else {
        return;
    };
    let before = match sample_rollout_metrics(&state, &record).await {
        Ok(sample) => sample,
        Err(error) => {
            fail_canary_rollout(&state, &rollout_id, "observing", error.to_string()).await;
            return;
        }
    };
    let Some(policy) = record.policy.clone() else {
        fail_canary_rollout(
            &state,
            &rollout_id,
            "observing",
            "rollout policy snapshot is missing".to_string(),
        )
        .await;
        return;
    };
    tokio::time::sleep(Duration::from_secs(policy.observation_seconds)).await;
    if state
        .rollouts
        .get(&rollout_id)
        .is_none_or(|current| current.phase != "observing")
    {
        return;
    }
    let after = match sample_rollout_metrics(&state, &record).await {
        Ok(sample) => sample,
        Err(error) => {
            fail_canary_rollout(&state, &rollout_id, "observing", error.to_string()).await;
            return;
        }
    };
    let canary = record
        .canary_nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let evidence = match evaluate_rollout_health(&before, &after, &canary, &policy) {
        Ok(evidence) => evidence,
        Err(error) => {
            fail_canary_rollout(&state, &rollout_id, "observing", error).await;
            return;
        }
    };
    let Some(advanced) = state
        .rollouts
        .update_if_phase(&rollout_id, "observing", |record| {
            record.health = Some(evidence);
            record.phase = if record.approval_required {
                "awaiting_approval".to_string()
            } else {
                "promoting".to_string()
            };
        })
    else {
        return;
    };
    state.config_history.record_control_event(
        "admin-canary-rollout",
        &state.cfg_path,
        record.base_version,
        record.base_version.saturating_add(1),
        if policy.require_approval {
            "awaiting_approval"
        } else {
            "health_passed"
        },
    );
    if policy.require_approval {
        if advanced.workspace.is_some() {
            let ttl = state.snap.load().admin_approval.ttl_seconds;
            let retained = state.clone();
            let id = advanced.id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl)).await;
                // 未审批候选不能无限占用全局 canary 控制槽；仅预期阶段的调用者可撤销。
                fail_canary_rollout(
                    &retained,
                    &id,
                    "awaiting_approval",
                    "workspace approval expired".into(),
                )
                .await;
            });
        }
        return;
    }
    promote_canary_rollout(state, advanced).await;
}

/// 业务作用：在预期阶段原子取得回滚执行权，再执行 override 撤销，防止人工拒绝与后台失败分支双重补偿。
///
/// 参数说明：
/// - `state`：定位发布
/// - `rollout_id`：定位发布
/// - `expected_phase`：限定转移前阶段
/// - `reason`：是低敏失败证据。
///
/// 返回：无显式返回值；只有成功把阶段转为 `rolling_back` 的调用方会执行外部清理。
async fn fail_canary_rollout(
    state: &AdminState,
    rollout_id: &str,
    expected_phase: &str,
    reason: String,
) {
    let transitioned = state
        .rollouts
        .update_if_phase(rollout_id, expected_phase, |record| {
            record.phase = "rolling_back".to_string();
            record.reason = Some(reason.clone());
        });
    if transitioned.is_some() {
        rollback_canary_rollout(state, rollout_id, reason).await;
    }
}

/// 业务作用：在健康门或证据门失败时撤销 canary override，使选中节点回到未改动的全局 bundle。
///
/// 参数说明：
/// - `state`：定位冻结候选与节点集
/// - `rollout_id`：定位冻结候选与节点集
/// - `reason`：是低敏失败证据。
///
/// 返回：无显式返回值；覆盖层 CAS 释放成功记为 `rolled_back`，归属复验或释放失败记为 `cleanup_failed`。
async fn rollback_canary_rollout(state: &AdminState, rollout_id: &str, reason: String) {
    let Some(record) = state.rollouts.get(rollout_id) else {
        return;
    };
    let cleanup = match (record.nacos.clone(), record.target.clone()) {
        (Some(nacos), Some(target)) => {
            run_canary_overrides_offloaded(
                nacos,
                record.id.clone(),
                target,
                record.canary_nodes.clone(),
                CanaryOverrideOperation::Cleanup,
            )
            .await
        }
        _ => Err(anyhow::anyhow!("rollout cleanup snapshot is incomplete")),
    };
    let (phase, final_reason) = match cleanup {
        Ok(()) => ("rolled_back", reason),
        Err(error) => (
            "cleanup_failed",
            format!("{reason}; override cleanup failed: {error}"),
        ),
    };
    state.rollouts.update(rollout_id, |record| {
        record.phase = phase.to_string();
        record.reason = Some(final_reason.clone());
    });
    state.config_history.record_control_event(
        "admin-canary-rollout",
        &state.cfg_path,
        record.base_version,
        record.base_version,
        phase,
    );
    if let Err(error) =
        record_rollout_controller_audit(state, &record, "completed", Some(409)).await
    {
        tracing::error!(%error, rollout_id, "failed to persist automated canary rollback audit");
    }
}

/// 业务作用：将已通过健康门与可选四眼审批的候选 CAS 晋级为全局 bundle。
///
/// 参数说明：
/// - `state`：承载登记/审计
/// - `record`：是已原子进入 `promoting` 的冻结发布快照。
///
/// 返回：无显式返回值；CAS、全集群收敛和 override 清理都完成才记为 `succeeded`，晋级前失败则撤销 canary。
async fn promote_canary_rollout(state: Arc<AdminState>, record: RolloutRecord) {
    let (Some(nacos), Some(target), Some(baseline)) = (
        record.nacos.clone(),
        record.target.clone(),
        record.baseline.clone(),
    ) else {
        fail_canary_rollout(
            &state,
            &record.id,
            "promoting",
            "rollout promotion snapshot is incomplete".to_string(),
        )
        .await;
        return;
    };
    // 全局 CAS 是扩大业务路由的外部副作用；持久 attempt 失败时不允许放量。
    if let Err(error) = record_rollout_controller_audit(&state, &record, "attempt", None).await {
        fail_canary_rollout(
            &state,
            &record.id,
            "promoting",
            format!("promotion audit unavailable: {error}"),
        )
        .await;
        return;
    }
    // 审计等待可能跨过撤权或 owner 变更；失权后只允许撤销本次 override，不能全局放量。
    if !workspaces::rollout_authority(&state, &record, None) {
        fail_canary_rollout(
            &state,
            &record.id,
            "promoting",
            "workspace authority changed".into(),
        )
        .await;
        return;
    }
    let outcome = run_nacos_rollback_offloaded(
        nacos.clone(),
        record.base_version.saturating_add(1),
        target.clone(),
        baseline.clone(),
        false,
    )
    .await;
    match outcome {
        Ok(NacosRollbackOutcome::Published(_)) | Ok(NacosRollbackOutcome::AlreadyMatches) => {}
        Ok(NacosRollbackOutcome::CasConflict(data_id)) => {
            fail_canary_rollout(
                &state,
                &record.id,
                "promoting",
                format!("global promotion CAS conflict at {data_id}"),
            )
            .await;
            return;
        }
        Ok(NacosRollbackOutcome::Drifted(ids)) => {
            fail_canary_rollout(
                &state,
                &record.id,
                "promoting",
                format!("global bundle drifted at {}", ids.join(",")),
            )
            .await;
            return;
        }
        Ok(NacosRollbackOutcome::Created(_)) | Ok(NacosRollbackOutcome::MultiDataId(_)) => {
            fail_canary_rollout(
                &state,
                &record.id,
                "promoting",
                "global promotion returned an invalid atomic-bundle outcome".to_string(),
            )
            .await;
            return;
        }
        Err(error) => {
            fail_canary_rollout(&state, &record.id, "promoting", error.to_string()).await;
            return;
        }
    }
    if let Err(error) = await_global_rollout_convergence(&state, &record).await {
        // 全局收敛证据不足时先用“候选作为当前基线”执行反向 CAS；
        // 只有确认远端仍是本候选才能恢复旧全局 bundle，避免覆盖新的并发发布。
        let reversed = run_nacos_rollback_offloaded(
            nacos,
            record.base_version,
            baseline,
            target.clone(),
            false,
        )
        .await;
        if matches!(
            &reversed,
            Ok(NacosRollbackOutcome::Published(_)) | Ok(NacosRollbackOutcome::AlreadyMatches)
        ) {
            fail_canary_rollout(
                &state,
                &record.id,
                "promoting",
                format!("global promotion did not converge and was reverted: {error}"),
            )
            .await;
        } else {
            state.rollouts.update(&record.id, |record| {
                record.phase = "failed".to_string();
                record.reason = Some(format!(
                    "global bundle published but convergence failed: {error}; reverse CAS outcome: {}",
                    match &reversed {
                        Ok(_) => "conflict or drift".to_string(),
                        Err(reverse_error) => reverse_error.to_string(),
                    }
                ));
            });
            state.config_history.record_control_event(
                "admin-canary-rollout",
                &state.cfg_path,
                record.base_version,
                record.base_version.saturating_add(1),
                "promotion_convergence_failed",
            );
        }
        return;
    }
    let cleanup = run_canary_overrides_offloaded(
        record.nacos.clone().expect("checked above"),
        record.id.clone(),
        target,
        record.canary_nodes.clone(),
        CanaryOverrideOperation::Cleanup,
    )
    .await;
    match cleanup {
        Ok(()) => {
            state.rollouts.update(&record.id, |record| {
                record.phase = "succeeded".to_string();
                record.reason = None;
            });
            state.config_history.record_control_event(
                "admin-canary-rollout",
                &state.cfg_path,
                record.base_version,
                record.base_version.saturating_add(1),
                "succeeded",
            );
            if let Err(error) =
                record_rollout_controller_audit(&state, &record, "completed", Some(200)).await
            {
                tracing::error!(%error, rollout_id = %record.id, "failed to persist rollout completion audit");
            }
        }
        Err(error) => {
            state.rollouts.update(&record.id, |record| {
                record.phase = "cleanup_failed".to_string();
                record.reason = Some(format!(
                    "global rollout succeeded but override cleanup failed: {error}"
                ));
            });
        }
    }
}

/// 业务作用：在全局 CAS 后等待所有 enabled 节点越过基线、健康且应用精确目标三文档。
///
/// 参数说明：
/// - `state`：提供常驻有界成员查询
/// - `record`：提供冻结发现配置和基线版本。
///
/// 返回：120 秒内收敛返回成功；发现失败持续到截止时间或仍有掉队节点时失败。
async fn await_global_rollout_convergence(
    state: &AdminState,
    record: &RolloutRecord,
) -> anyhow::Result<()> {
    let discovery = record
        .discovery
        .clone()
        .ok_or_else(|| anyhow::anyhow!("rollout discovery snapshot is missing"))?;
    let service = crate::upstream::discovery::self_register_service_name(&discovery)
        .ok_or_else(|| anyhow::anyhow!("Nacos self-registration is disabled"))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(instances) = state
            .member_discovery
            .discover(
                &discovery,
                service.clone(),
                cluster::discovery::REQUEST_TIMEOUT,
            )
            .await
        {
            let summary = summarize_cluster_versions(&instances);
            if rollout_status(&summary, record.base_version, &record.documents_digest).converged {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("cluster did not converge within 120 seconds");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// 业务作用：为自动发布控制器追加持久防篡改审计，不伪装成人工主体。
///
/// 参数说明：
/// - `state`：提供审计器与配置版本的管理状态。
/// - `record`：本次渐进发布的冻结记录。
/// - `phase`：外部副作用所在阶段。
/// - `status`：该阶段的实际执行状态。
///
/// 返回：本地与可选外部 sink 均确认时成功；否则返回失败供状态机按安全边界决策。
async fn record_rollout_controller_audit(
    state: &AdminState,
    record: &RolloutRecord,
    phase: &'static str,
    status: Option<u16>,
) -> anyhow::Result<()> {
    state
        .audit
        .record_scoped(
            crate::admin::audit::AdminAuditInput {
                principal: Arc::from("naway-rollout-controller"),
                method: "INTERNAL",
                path: "/api/cluster/rollout/controller",
                resource: AdminResource::Config,
                action: AdminAction::Write,
                phase,
                status,
                query_sha256: None,
                config_version: state.snap.load().version,
            },
            record.workspace.clone(),
        )
        .await
}

/// 业务作用：报告最近发布的控制器阶段及节点观测，不将其它换代误判为灰度发布成功。
///
/// 参数说明：
/// - `state`：提供发布记录和发现配置。
///
/// 返回：灰度发布只有控制器确认推广与清理完成才成功；普通发布按所有启用节点的版本和指纹收敛判断。
async fn cluster_rollout_status(state: &AdminState) -> Response<BoxBody> {
    let Some(rollout) = state.rollouts.latest() else {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "ok": false,
                "error": "no rollout has been started on this node"
            }),
        );
    };
    let (nacos, local_version) = {
        let snap = state.snap.load();
        (snap.discovery.nacos.clone(), snap.version)
    };
    let Some(service) = crate::upstream::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "rollout status requires discovery.nacos.self_register.enabled",
            }),
        );
    };
    match state
        .member_discovery
        .discover(&nacos, service.clone(), cluster::discovery::REQUEST_TIMEOUT)
        .await
    {
        Ok(instances) => {
            let summary = summarize_cluster_versions(&instances);
            let status = rollout_status(&summary, rollout.base_version, &rollout.documents_digest);
            let (label, converged) = if !rollout.canary_nodes.is_empty() {
                (rollout.phase.as_str(), rollout.phase == "succeeded")
            } else {
                (status.label, status.converged)
            };
            let candidate_etag = (!rollout.candidate_digest.is_empty())
                .then(|| format!("\"sha256-{}\"", rollout.candidate_digest));
            let mut body = serde_json::json!({
                "ok": true,
                "service": service,
                "local_version": local_version,
                "rollout": rollout,
                "candidate_etag": candidate_etag,
                "status": label,
                "converged": converged,
                "pending_nodes": status.pending,
            });
            if let (Some(object), Ok(cluster)) =
                (body.as_object_mut(), serde_json::to_value(&summary))
            {
                object.insert("cluster".to_string(), cluster);
            }
            json(StatusCode::OK, body)
        }
        Err(error) => json(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "ok": false,
                "error": error.to_string()
            }),
        ),
    }
}

/// 业务作用：处理渐进发布四眼审批，将已通过健康门的候选交给全局晋级状态机。
///
/// 参数说明：
/// - `request`：必须含 `id` query 和候选 `If-Match`
/// - `identity`：是已授权 Config/Write 主体
/// - `state`：持有 rollout 登记。
///
/// 返回：审批原子生效并启动晋级时返回 202；缺少前置条件、同主体审批或摘要失配时返回 4xx。
fn approve_cluster_rollout<'a>(
    request: &'a AdminRequestParts,
    identity: &'a AdminIdentity,
    state: Arc<AdminState>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<BoxBody>> + Send + 'a>> {
    Box::pin(async move {
        let Some(id) = workspaces::rollout_path(request.uri.path())
            .map(|(_, id, _)| id)
            .or_else(|| query_param(request.uri.query().unwrap_or_default(), "id"))
        else {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "missing rollout id"
                }),
            );
        };
        let Some(if_match) = request
            .headers
            .get(hyper::header::IF_MATCH)
            .and_then(|value| value.to_str().ok())
        else {
            return json(
                StatusCode::PRECONDITION_REQUIRED,
                serde_json::json!({
                    "ok": false,
                    "error": "If-Match candidate ETag is required"
                }),
            );
        };
        let Some(digest) = if_match
            .trim()
            .strip_prefix("\"sha256-")
            .and_then(|value| value.strip_suffix('\"'))
        else {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "If-Match must use the rollout candidate_etag"
                }),
            );
        };
        if state.rollouts.get(id).is_some_and(|record| {
            !workspaces::rollout_action_allowed(request, identity, &state, &record)
        }) {
            return plain(
                StatusCode::FORBIDDEN,
                "rollout workspace authority denied\n",
            );
        }
        let record = match state
            .rollouts
            .approve(id, digest, identity.principal_id.as_ref())
        {
            Ok(record) => record,
            Err(error) if error.contains("digest changed") => {
                return json(
                    StatusCode::PRECONDITION_FAILED,
                    serde_json::json!({
                        "ok": false,
                        "error": error
                    }),
                )
            }
            Err(error) if error == "rollout not found" => {
                return json(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({
                        "ok": false,
                        "error": error
                    }),
                )
            }
            Err(error) => {
                return json(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "ok": false,
                        "error": error
                    }),
                )
            }
        };
        tokio::spawn(promote_canary_rollout(state, record));
        json(
            StatusCode::ACCEPTED,
            serde_json::json!({
                "ok": true,
                "rollout_id": id,
                "status": "promoting"
            }),
        )
    })
}

/// 业务作用：处理人工拒绝，在全局晋级前取得撤销权并异步清理节点 override。
///
/// 参数说明：
/// - `request`：必须含 `id` 和候选 `If-Match`
/// - `identity`：记录拒绝主体
/// - `state`：承载登记与 Nacos 快照。
///
/// 返回：成功进入撤销返回 202；已全局放量、终态、不存在或摘要失配返回 4xx。
fn reject_cluster_rollout<'a>(
    request: &'a AdminRequestParts,
    identity: &'a AdminIdentity,
    state: Arc<AdminState>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<BoxBody>> + Send + 'a>> {
    Box::pin(async move {
        let Some(id) = workspaces::rollout_path(request.uri.path())
            .map(|(_, id, _)| id)
            .or_else(|| query_param(request.uri.query().unwrap_or_default(), "id"))
        else {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "missing rollout id"
                }),
            );
        };
        let Some(if_match) = request
            .headers
            .get(hyper::header::IF_MATCH)
            .and_then(|value| value.to_str().ok())
        else {
            return json(
                StatusCode::PRECONDITION_REQUIRED,
                serde_json::json!({
                    "ok": false,
                    "error": "If-Match candidate ETag is required"
                }),
            );
        };
        let Some(digest) = if_match
            .trim()
            .strip_prefix("\"sha256-")
            .and_then(|value| value.strip_suffix('\"'))
        else {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "If-Match must use the rollout candidate_etag"
                }),
            );
        };
        if state.rollouts.get(id).is_some_and(|record| {
            !workspaces::rollout_action_allowed(request, identity, &state, &record)
        }) {
            return plain(
                StatusCode::FORBIDDEN,
                "rollout workspace authority denied\n",
            );
        }
        let record = match state
            .rollouts
            .reject(id, digest, identity.principal_id.as_ref())
        {
            Ok(record) => record,
            Err(error) if error.contains("digest changed") => {
                return json(
                    StatusCode::PRECONDITION_FAILED,
                    serde_json::json!({
                        "ok": false,
                        "error": error
                    }),
                )
            }
            Err(error) if error == "rollout not found" => {
                return json(
                    StatusCode::NOT_FOUND,
                    serde_json::json!({
                        "ok": false,
                        "error": error
                    }),
                )
            }
            Err(error) => {
                return json(
                    StatusCode::CONFLICT,
                    serde_json::json!({
                        "ok": false,
                        "error": error
                    }),
                )
            }
        };
        let reason = record
            .reason
            .clone()
            .unwrap_or_else(|| "rejected by authorized operator".to_string());
        let rollout_id = record.id.clone();
        tokio::spawn(async move {
            rollback_canary_rollout(&state, &rollout_id, reason).await;
        });
        json(
            StatusCode::ACCEPTED,
            serde_json::json!({
                "ok": true,
                "rollout_id": id,
                "status": "rolling_back"
            }),
        )
    })
}

/// rollout 收敛判定结果，区分已收敛、证据缺失与拒绝。
struct RolloutStatus {
    /// 是否全部启用节点已收敛到同一新配置。
    converged: bool,
    /// 展示用状态标签。
    label: &'static str,
    /// 尚未越过 base_version 或指纹不一致的节点标识。
    pending: Vec<String>,
}

/// 业务作用：按实际目标验证集群应用证据，不把其它发布的版本前进当成本次成功。
///
/// 参数说明：
/// - `summary`：为发现事实
/// - `base_version`：是发布前版本
/// - `documents_digest`：是冻结目标摘要。
///
/// 返回：所有启用节点均健康、越过基线、三文档匹配且依赖指纹一致时成功；否则列出未满足的节点。
fn rollout_status(
    summary: &ClusterSummary,
    base_version: u64,
    documents_digest: &str,
) -> RolloutStatus {
    let mut pending = Vec::new();
    let mut advanced = 0usize;
    let mut enabled = 0usize;
    for node in &summary.nodes {
        if !node.enabled {
            continue;
        }
        enabled += 1;
        let node_label = node
            .node_id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", node.ip, node.port));
        match node.version {
            // 版本必须**越过**发布基线:等于基线说明还没收到新 bundle。
            Some(version)
                if version > base_version
                    && node.healthy
                    && !documents_digest.is_empty()
                    && node.bundle_sha256.as_deref() == Some(documents_digest) =>
            {
                advanced += 1
            }
            _ => pending.push(node_label),
        }
    }
    if enabled == 0 {
        return RolloutStatus {
            converged: false,
            label: "no_enabled_nodes",
            pending,
        };
    }
    // 版本都前进了还不够:内容必须也一致(同版本不同指纹 = 分叉)。
    if !pending.is_empty() {
        return RolloutStatus {
            converged: false,
            label: "in_progress",
            pending,
        };
    }
    if summary.fingerprint_unknown {
        return RolloutStatus {
            converged: false,
            label: "fingerprint_unknown",
            pending,
        };
    }
    if summary.distinct_fingerprints.len() > 1 || summary.distinct_versions.len() > 1 {
        return RolloutStatus {
            converged: false,
            label: "diverged",
            pending,
        };
    }
    debug_assert_eq!(advanced, enabled);
    RolloutStatus {
        converged: true,
        label: "succeeded",
        pending,
    }
}

// ── Console 配置发布闭环 ──

/// 业务作用：主 YML 读取上限:与候选提交同一预算,防止误挂大文件把控制面读爆。
fn admin_config_read_limit(state: &AdminState) -> usize {
    state.snap.load().admin_max_config_body_bytes
}

/// 业务作用：当前配置集指纹 → ETag。
///
/// 指纹覆盖主 YML **及其依赖**(OpenAPI/schema/WASM/文件型 SecretSource),因此"依赖文件被
/// 旁路改动"同样会让旧 ETag 失效——CAS 语义是"你基于的整份配置状态",不是单个文件的哈希。
fn config_etag(fingerprint: u64) -> String {
    format!("\"cfg-{fingerprint:016x}\"")
}

/// 业务作用：返回活动快照对应的归档主文档与同代 ETag，不能把 bootstrap 或待发布文件冒充在线配置。
///
/// 参数说明：
/// - `state`：提供已提交快照、归档和读取上限。
///
/// 返回：一致在线文档返回 200；无控制面返回 404，缺失归档或换代竞争返回 409。
async fn read_current_config(state: &AdminState) -> Response<BoxBody> {
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let limit = admin_config_read_limit(state);
    let snapshot = state.snap.load_full();
    let version = snapshot.version;
    let Some(fingerprint) = snapshot.config_fingerprint else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "live configuration fingerprint unavailable"
            }),
        );
    };
    let history = state.config_history.clone();
    let content = match tokio::task::spawn_blocking(move || history.read_archived(version)).await {
        Ok(Ok(docs)) if docs.gateway.len() <= limit => docs.gateway,
        _ => {
            return json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok":false,
                    "error":"live configuration archive unavailable or exceeds read limit"
                }),
            )
        }
    };
    // 在线文档与 ETag 必须属于同一代；异步归档读取期间换代时不能拼接新旧事实。
    if state.snap.load().version != version {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok":false,
                "error":"configuration changed during read; retry"
            }),
        );
    }
    let etag = config_etag(fingerprint);
    let body = serde_json::json!({
        "ok": true,
        "version": snapshot.version,
        "fingerprint": fingerprint,
        "etag": etag,
        "centers": {
            "discovery_enabled": snapshot.discovery.enabled,
            "config_source_enabled": snapshot.config_source.enabled,
            "change_requires_restart": true
        },
        // 配置源是 Nacos 时本地文件只是物化产物,PUT 必须走集群 rollout(见 publish 分支)。
        "source": if snapshot.config_source.nacos.enabled {
            "nacos"
        } else {
            "file"
        },
        "content": content,
    });
    let mut response = json(StatusCode::OK, body);
    if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
        response.headers_mut().insert(hyper::header::ETAG, value);
    }
    response
}

/// 业务作用：读取当前已上线版本对应的 Sentinel 独立文档，为 Console 编辑提供整体 CAS 基线。
///
/// 参数说明：
/// - `state`：提供当前版本、归档和配置集指纹。
///
/// 返回：归档可用时返回 200、YAML 原文、文档摘要与整体 ETag；归档缺失时返回 409，不退回未必与快照同版的磁盘文件。
fn read_sentinel_config(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let version = snapshot.version;
    let fingerprint = snapshot.config_fingerprint;
    drop(snapshot);
    let docs = match state.config_history.read_archived(version) {
        Ok(docs) => docs,
        Err(error) => {
            return json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    let etag = fingerprint.map(config_etag);
    let document_etag = format!("\"sha256-{}\"", nasa::crypto::sha256(&docs.sentinel_rules));
    let mut response = json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "version": version,
            "etag": etag.clone(),
            "document_etag": document_etag,
            "content": docs.sentinel_rules,
        }),
    );
    if let Some(etag) = etag {
        if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
            response.headers_mut().insert(hyper::header::ETAG, value);
        }
    }
    response
}

/// 已通过身份、RBAC、持久审计和整体配置 CAS 的文档写入上下文。
struct PreparedConfigWrite {
    identity: AdminIdentity,
    baseline: crate::control::history::ArchivedDocs,
    base_version: u64,
    base_fingerprint: u64,
}

/// 业务作用：为高级配置写接口执行统一前置门禁，防止 Sentinel、消费者等资源形成绕开主配置 CAS
/// 与持久审计的旁路。
///
/// 参数说明：
/// - `parts`：是尚未读取 body 的请求头
/// - `state`：提供认证、当前快照、归档与事实源
/// - `resource`：是精确 RBAC 域。
///
/// 返回：全部门禁通过时返回已认证主体和当前完整归档；失败返回已确定的 HTTP 响应且不产生配置副作用。
async fn prepare_config_write(
    parts: &AdminRequestParts,
    state: &Arc<AdminState>,
    resource: AdminResource,
) -> Result<PreparedConfigWrite, Box<Response<BoxBody>>> {
    let identity = authenticate_admin_request(parts, state)?;
    if let Some(response) = reject_untrusted_admin_browser_origin(parts, state) {
        return Err(Box::new(response));
    }
    if !state.mode.full_control_plane() {
        return Err(Box::new(plain(StatusCode::NOT_FOUND, "not found\n")));
    }
    if !identity.allows(resource, AdminAction::Write) {
        let _ = record_admin_audit(
            state,
            &identity,
            parts,
            resource,
            AdminAction::Write,
            "completed",
            Some(StatusCode::FORBIDDEN.as_u16()),
        )
        .await;
        return Err(Box::new(json(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "ok": false,
                "error": "forbidden"
            }),
        )));
    }
    // 持久 attempt 必须先于配置读取和任何写副作用；审计不可用时保持事实源不变。
    if record_admin_audit(
        state,
        &identity,
        parts,
        resource,
        AdminAction::Write,
        "attempt",
        None,
    )
    .await
    .is_err()
    {
        return Err(Box::new(json(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "ok": false,
                "error": "audit sink unavailable; action not executed"
            }),
        )));
    }
    let snapshot = state.snap.load_full();
    let version = snapshot.version;
    let fingerprint = snapshot.config_fingerprint.ok_or_else(|| {
        Box::new(json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "cannot fingerprint current config set"
            }),
        ))
    })?;
    // 写入基线必须来自当前已提交代，并复验活动源；远端模式下 bootstrap 不是在线事实。
    if !current_config_baseline_matches(state, version, fingerprint).await {
        return Err(Box::new(json(
            StatusCode::PRECONDITION_FAILED,
            serde_json::json!({
                "ok":false,
                "error":"active configuration baseline changed; retry"
            }),
        )));
    }
    let expected = config_etag(fingerprint);
    let Some(if_match) = parts
        .headers
        .get(hyper::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(Box::new(json(
            StatusCode::PRECONDITION_REQUIRED,
            serde_json::json!({
                "ok": false,
                "error": "If-Match is required",
                "etag": expected
            }),
        )));
    };
    if if_match.trim() != expected {
        let mut response = json(
            StatusCode::PRECONDITION_FAILED,
            serde_json::json!({
                "ok": false,
                "error": "config changed since it was read; rebase on the current version",
                "etag": expected,
            }),
        );
        if let Ok(value) = hyper::header::HeaderValue::from_str(&expected) {
            response.headers_mut().insert(hyper::header::ETAG, value);
        }
        return Err(Box::new(response));
    }
    // 指纹计算期间若快照换代，归档与 If-Match 就不再属于同一基线，必须让调用方重新读取。
    if state.snap.load().version != version {
        return Err(Box::new(json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "config changed during precondition check; retry"
            }),
        )));
    }
    let baseline = state
        .config_history
        .read_archived(version)
        .map_err(|error| {
            Box::new(json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            ))
        })?;
    Ok(PreparedConfigWrite {
        identity,
        baseline,
        base_version: version,
        base_fingerprint: fingerprint,
    })
}

/// 业务作用：补齐高级配置写接口的完成审计；副作用已经发生但 completion 落盘失败时返回歧义错误，
/// 禁止伪装成可安全重试的成功。
///
/// 参数说明：
/// - `state`：持有审计器的管理状态。
/// - `identity`：已认证提交主体。
/// - `parts`：请求头与路径，用于审计定位。
/// - `resource`：本次动作的权限资源域。
/// - `response`：处理器真实执行结果。
///
/// 返回：完成审计成功时原样返回 handler 响应；失败时返回 500 和可能已完成标记。
async fn finish_config_write(
    state: &AdminState,
    identity: &AdminIdentity,
    parts: &AdminRequestParts,
    resource: AdminResource,
    response: Response<BoxBody>,
) -> Response<BoxBody> {
    if record_admin_audit(
        state,
        identity,
        parts,
        resource,
        AdminAction::Write,
        "completed",
        Some(response.status().as_u16()),
    )
    .await
    .is_err()
    {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "action result audit failed",
                "operation_may_have_completed": true,
            }),
        );
    }
    response
}

/// 业务作用：判断一个资源写操作是否必须先登记 maker-checker，策略随已发布快照原子切换。
///
/// 参数说明：
/// - `state`：提供当前审批策略
/// - `resource`：是写接口的精确 RBAC 域。
///
/// 返回：审批总开关开启且资源在明确列表中时返回 true。
fn approval_required(state: &AdminState, resource: AdminResource) -> bool {
    let snapshot = state.snap.load();
    snapshot.admin_approval.enabled && snapshot.admin_approval.resources.contains(&resource)
}

/// 业务作用：登记完整高危候选并返回与其摘要绑定的审批令牌；登记过程不调用发布或证书安装。
///
/// 参数说明：
/// - `state`：持有审批目录与审计器的管理状态。
/// - `prepared`：已认证 maker 与 CAS 基线。
/// - `resource`：本次审批的权限资源域。
/// - `payload`：有界且绑定摘要的执行载荷。
///
/// 返回：登记成功返回 202、change id 与候选 ETag；容量或摘要编码失败时返回错误且不保留候选。
fn submit_approval_change(
    state: &AdminState,
    prepared: &PreparedConfigWrite,
    resource: AdminResource,
    payload: ApprovalPayload,
) -> Response<BoxBody> {
    let digest = approval_payload_digest(&payload);
    let policy = state.snap.load().admin_approval.clone();
    let domain_capacity = state.snap.load().ownership.approval_capacity(
        match &payload {
            ApprovalPayload::WorkspaceDocuments {
                binding,
                ..
            } => Some(binding.owner.workspace.as_str()),
            _ => None,
        },
        policy.max_pending,
    );
    match state.approvals.submit(
        &policy,
        resource,
        prepared.identity.principal_id.as_ref(),
        prepared.base_version,
        prepared.base_fingerprint,
        digest.clone(),
        payload,
        domain_capacity,
    ) {
        Ok((id, digest)) => {
            let etag = format!("\"sha256-{digest}\"");
            let mut response = json(
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "ok": true,
                    "status": "awaiting_approval",
                    "change_id": id,
                    "candidate_etag": etag,
                    "expires_in_seconds": policy.ttl_seconds,
                }),
            );
            if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
                response.headers_mut().insert(hyper::header::ETAG, value);
            }
            response
        }
        Err(error) => json(
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "ok": false,
                "error": error
            }),
        ),
    }
}

/// 业务作用：对审批载荷按带长度边界的完整字节计算 SHA-256，使审批令牌同时绑定三文档或证书 pair。
///
/// 参数说明：
/// - `payload`：是尚未进入 registry 的完整候选。
///
/// 返回：返回 64 字符小写十六进制摘要；不记录或输出 payload。
fn approval_payload_digest(payload: &ApprovalPayload) -> String {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    let mut update = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    match payload {
        ApprovalPayload::WorkspaceDocuments {
            binding,
            target,
            ..
        } => {
            update(binding.owner.workspace.as_bytes());
            update(binding.owner.tenant.as_bytes());
            update(binding.owner.environment.as_bytes());
            update(binding.authority_digest.as_bytes());
            update(target.gateway.as_bytes());
            update(target.interface_guard.as_bytes());
            update(target.sentinel_rules.as_bytes());
        }
        ApprovalPayload::Documents {
            target,
            ..
        } => {
            update(target.gateway.as_bytes());
            update(target.interface_guard.as_bytes());
            update(target.sentinel_rules.as_bytes());
        }
        ApprovalPayload::Certificate {
            certificate_pem,
            private_key_pem,
            ..
        } => {
            update(certificate_pem);
            update(private_key_pem);
        }
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing SHA-256 hex to String cannot fail");
    }
    encoded
}

/// 业务作用：解析 maker-checker 审批与拒绝端点的固定 path，未知层级保持 404。
///
/// 参数说明：
/// - `path`：是不带 query 的规范 URI path。
///
/// 返回：只接受 `/api/changes/{safe-id}/approve|reject`，返回 change id 与动作；其它返回 None。
fn parse_change_action(path: &str) -> Option<(&str, &str)> {
    let mut segments = path.strip_prefix("/api/changes/")?.split('/');
    let id = segments.next()?;
    let action = segments.next()?;
    if segments.next().is_some()
        || id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !matches!(action, "approve" | "reject")
    {
        return None;
    }
    Some((id, action))
}

/// 业务作用：执行 maker-checker 的动态资源 RBAC、另一主体、摘要、TTL 与基线复验，并在唯一取得
/// payload 后调用正常发布链路。
///
/// 参数说明：
/// - `req`：path 指定 change/动作且 `If-Match` 绑定候选
/// - `state`：提供审批表、事实源和审计。
///
/// 返回：拒绝成功返回终态；批准仅在所有门禁通过后执行，过期、同主体、摘要或基线失配均不产生
/// 配置/证书副作用。
async fn review_pending_change(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (mut parts, _body) = req.into_parts();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    if !state.mode.full_control_plane() || !state.snap.load().admin_approval.enabled {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let requested_workspace =
        workspaces::review_path(parts.uri.path()).map(|(workspace, _, _)| workspace.to_owned());
    let parsed = parse_change_action(parts.uri.path())
        .or_else(|| workspaces::review_path(parts.uri.path()).map(|(_, id, action)| (id, action)));
    let Some((id, action)) = parsed else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let id = id.to_string();
    let action = action.to_string();
    let Some(resource) = state.approvals.resource(&id) else {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "ok": false,
                "error": "change not found"
            }),
        );
    };
    let binding = state.approvals.workspace(&id).flatten();
    let authorized = if let Some(binding) = &binding {
        let snapshot = state.snap.load();
        requested_workspace.as_deref() == Some(binding.owner.workspace.as_str())
            && snapshot
                .ownership
                .binding(&binding.owner.workspace)
                .as_ref()
                == Some(binding)
            && snapshot.ownership.allows(
                &identity.principal_id,
                &binding.owner.workspace,
                crate::control::ownership::config::Action::Review,
            )
    } else {
        requested_workspace.is_none() && identity.allows(resource, AdminAction::Write)
    };
    if !authorized {
        return json(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "ok": false,
                "error": "forbidden"
            }),
        );
    }
    let digest = match parts
        .headers
        .get(hyper::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("\"sha256-"))
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        Some(digest) => digest.to_ascii_lowercase(),
        None => {
            let response = json(
                StatusCode::PRECONDITION_REQUIRED,
                serde_json::json!({
                    "ok": false,
                    "error": "If-Match must use the change candidate_etag"
                }),
            );
            return finish_config_write(&state, &identity, &parts, resource, response).await;
        }
    };
    if let Some(binding) = binding {
        let Some(candidate_sha256) = state.approvals.candidate_digest(&id) else {
            return plain(StatusCode::NOT_FOUND, "change not found\n");
        };
        parts.extensions.insert(audit::WorkspaceAudit {
            binding,
            candidate_sha256,
            approved_by: None,
        });
    }
    // 持久 attempt 绑定固定 owner 与真实候选摘要；审计不可用时不得消费唯一执行权。
    if record_admin_audit(
        &state,
        &identity,
        &parts,
        resource,
        AdminAction::Write,
        "attempt",
        None,
    )
    .await
    .is_err()
    {
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit sink unavailable; action not executed\n",
        );
    }
    let response = if action == "reject" {
        match state
            .approvals
            .reject(&id, &digest, identity.principal_id.as_ref())
        {
            Ok(()) => json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "status": "rejected",
                    "change_id": id
                }),
            ),
            Err(error) => json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": error
                }),
            ),
        }
    } else {
        match state
            .approvals
            .approve(&id, &digest, identity.principal_id.as_ref())
        {
            Err(error) => json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": error
                }),
            ),
            Ok(change) => {
                if !current_config_baseline_matches(
                    &state,
                    change.base_version,
                    change.base_fingerprint,
                )
                .await
                {
                    state.approvals.complete(
                        &change.id,
                        "stale",
                        Some("config baseline changed before approval".to_string()),
                    );
                    json(
                        StatusCode::PRECONDITION_FAILED,
                        serde_json::json!({
                            "ok": false,
                            "error": "config baseline changed; submit a new change"
                        }),
                    )
                } else {
                    let response = match change.payload {
                        ApprovalPayload::WorkspaceDocuments {
                            binding,
                            target,
                            baseline,
                        } => {
                            let still_allowed = {
                                let snapshot = state.snap.load();
                                snapshot
                                    .ownership
                                    .binding(&binding.owner.workspace)
                                    .as_ref()
                                    == Some(&binding)
                                    && snapshot.ownership.allows(
                                        &identity.principal_id,
                                        &binding.owner.workspace,
                                        crate::control::ownership::config::Action::Review,
                                    )
                            };
                            // 审计与磁盘读取可能跨代；失去工作区权威后不得消费候选进行外部发布。
                            if !still_allowed {
                                plain(
                                    StatusCode::PRECONDITION_FAILED,
                                    "workspace authority changed\n",
                                )
                            } else {
                                let scope = audit::WorkspaceAudit {
                                    binding,
                                    candidate_sha256: digest.clone(),
                                    approved_by: Some(identity.principal_id.to_string()),
                                };
                                let response = publish_scoped_document_set(
                                    &state,
                                    target,
                                    baseline,
                                    &change.initiator,
                                    Some(scope),
                                )
                                .await;
                                workspaces::publication_response(response).await
                            }
                        }
                        ApprovalPayload::Documents {
                            target,
                            baseline,
                        } => {
                            publish_document_set(&state, target, baseline, &change.initiator).await
                        }
                        ApprovalPayload::Certificate {
                            tls,
                            expected_etag,
                            certificate_pem,
                            private_key_pem,
                        } => {
                            install_uploaded_certificate(
                                *tls,
                                expected_etag,
                                certificate_pem,
                                private_key_pem,
                            )
                            .await
                        }
                    };
                    let terminal = if response.status().is_success() {
                        "executed"
                    } else {
                        "failed"
                    };
                    state.approvals.complete(
                        &change.id,
                        terminal,
                        (!response.status().is_success())
                            .then(|| format!("execution returned HTTP {}", response.status())),
                    );
                    response
                }
            }
        }
    };
    finish_config_write(&state, &identity, &parts, resource, response).await
}

/// 业务作用：在批准后、执行前复验提交时的完整配置基线，候选期间任何 reload 都使旧审批失效。
///
/// 参数说明：
/// - `version`：是提交时冻结值
/// - `fingerprint`：是提交时冻结值
/// - `state`：提供当前快照与文件事实源。
///
/// 返回：版本和配置集指纹同时一致时返回 true；读取失败或任一变化均返回 false。
async fn current_config_baseline_matches(
    state: &AdminState,
    version: u64,
    fingerprint: u64,
) -> bool {
    let snapshot = state.snap.load_full();
    if snapshot.version != version || snapshot.config_fingerprint != Some(fingerprint) {
        return false;
    }
    // 远端配置上线后 bootstrap 不再代表活动事实源；只能复验该快照实际读取的物化文档。
    let cfg_path = snapshot.source_config_path.clone();
    let history = state.config_history.clone();
    let observed = tokio::task::spawn_blocking(move || {
        history.with_stable_local_files(|| crate::config::config_fingerprint(&cfg_path))
    })
    .await
    .ok()
    .and_then(Result::ok);
    let current = state.snap.load();
    observed == Some(fingerprint)
        && current.version == version
        && current.config_fingerprint == Some(fingerprint)
}

/// 业务作用：以完整文档 CAS 更新 Sentinel 规则，并复用统一候选构建、rollout 和回滚链路。
///
/// 参数说明：
/// - `req`：必须携带整体配置 ETag 与有界 YAML body
/// - `state`：提供事实源和发布状态机。
///
/// 返回：候选非法、ETag 失配或权限不足时返回 4xx；本地换版或集群 rollout 建立后返回对应发布状态。
async fn publish_sentinel_config(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let prepared = match prepare_config_write(&parts, &state, AdminResource::Sentinel).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let response = if !request_content_type(&parts, "application/yaml") {
        json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            serde_json::json!({
                "ok": false,
                "error": "Content-Type must be application/yaml"
            }),
        )
    } else {
        match collect_bounded_admin_body(
            &parts,
            body,
            state.snap.load().admin_max_config_body_bytes,
        )
        .await
        {
            Ok(body) => match String::from_utf8(body.to_vec()) {
                Ok(sentinel_rules) => {
                    let target = crate::control::history::ArchivedDocs {
                        gateway: prepared.baseline.gateway.clone(),
                        interface_guard: prepared.baseline.interface_guard.clone(),
                        sentinel_rules,
                    };
                    if approval_required(&state, AdminResource::Sentinel) {
                        submit_approval_change(
                            &state,
                            &prepared,
                            AdminResource::Sentinel,
                            ApprovalPayload::Documents {
                                target,
                                baseline: prepared.baseline.clone(),
                            },
                        )
                    } else {
                        publish_document_set(
                            &state,
                            target,
                            prepared.baseline.clone(),
                            prepared.identity.principal_id.as_ref(),
                        )
                        .await
                    }
                }
                Err(_) => json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "error": "sentinel document must be UTF-8"
                    }),
                ),
            },
            Err(response) => *response,
        }
    };
    finish_config_write(
        &state,
        &prepared.identity,
        &parts,
        AdminResource::Sentinel,
        response,
    )
    .await
}

/// 业务作用：从当前解析配置中生成消费者、套餐和非敏 API-Key 绑定读模型。
///
/// 参数说明：
/// - `path`：可为集合、单个 consumer 或其 `/keys`
/// - `state`：提供活动快照与同代配置读取门。
///
/// 返回：返回 consumer 到 plan 的绑定和 key 所在 route/source；绝不返回 `value`/`secret`/SecretSource 或它们的可验证摘要。
fn read_consumers(path: &str, state: &AdminState) -> Response<BoxBody> {
    let config = match read_active_gateway_config(state) {
        Ok(config) => config,
        Err(error) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    let mut keys = std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
    for (proxy, route) in configured_routes(&config) {
        for (index, filter) in route.filters.iter().enumerate() {
            let trimmed = filter.trim();
            if !trimmed.starts_with("api_key") {
                continue;
            }
            let Some(consumer) = filter_option(trimmed, "consumer") else {
                continue;
            };
            let source = filter_option(trimmed, "header")
                .map(|name| format!("header:{name}"))
                .or_else(|| filter_option(trimmed, "query").map(|name| format!("query:{name}")))
                .unwrap_or_else(|| "unknown".to_string());
            keys.entry(consumer.to_string())
                .or_default()
                .push(serde_json::json!({
                    "id": api_key_binding_id(proxy, &route.id, index),
                    "proxy": proxy,
                    "route": route.id,
                    "source": source,
                }));
        }
    }
    let suffix = path.strip_prefix("/api/consumers").unwrap_or_default();
    if suffix.is_empty() || suffix == "/" {
        let ids = config
            .usage_plans
            .consumers
            .keys()
            .cloned()
            .chain(keys.keys().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        let consumers = ids
            .iter()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "plan": config.usage_plans.consumers.get(id),
                    "key_count": keys.get(id).map_or(0, Vec::len),
                })
            })
            .collect::<Vec<_>>();
        return json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "consumers": consumers
            }),
        );
    }
    let suffix = suffix.trim_start_matches('/');
    let (consumer, wants_keys) = suffix
        .strip_suffix("/keys")
        .map(|consumer| (consumer, true))
        .unwrap_or((suffix, false));
    if !valid_consumer_id(consumer) {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "invalid consumer id"
            }),
        );
    }
    let plan = config.usage_plans.consumers.get(consumer);
    let consumer_keys = keys.remove(consumer).unwrap_or_default();
    if plan.is_none() && consumer_keys.is_empty() {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "ok": false,
                "error": "consumer not found"
            }),
        );
    }
    if wants_keys {
        json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "consumer": consumer,
                "keys": consumer_keys
            }),
        )
    } else {
        json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "consumer": {
                    "id": consumer,
                    "plan": plan,
                    "key_count": consumer_keys.len()
                },
            }),
        )
    }
}

/// 业务作用：为结构化管理接口读取已应用配置，阻止 bootstrap、未提交文件或换代中间态混入读写决策。
///
/// 参数说明：
/// - `state`：提供活动快照和与发布共用的文件事务。
///
/// 返回：配置指纹与代际在读取前后均未变化时返回解析模型，否则要求调用方重读。
fn read_active_gateway_config(
    state: &AdminState,
) -> anyhow::Result<crate::config::model::GatewayConfig> {
    let snapshot = state.snap.load_full();
    state.config_history.with_stable_local_files(|| {
        let expected = snapshot
            .config_fingerprint
            .context("active configuration fingerprint unavailable")?;
        // 文件可能已经被 watcher 物化但尚未发布，不能用未验证候选回答管理读面。
        anyhow::ensure!(
            crate::config::config_fingerprint(&snapshot.source_config_path)? == expected,
            "active configuration changed; retry"
        );
        let config = crate::config::load_gateway_config(&snapshot.source_config_path)?;
        anyhow::ensure!(
            state.snap.load().version == snapshot.version
                && crate::config::config_fingerprint(&snapshot.source_config_path)? == expected,
            "active configuration changed during read; retry"
        );
        Ok(config)
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerUpsertInput {
    id: String,
    plan: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumerKeyInput {
    proxy: String,
    route: String,
    source: String,
    name: String,
}

/// 消费者管理 path 的精确语义，未知层级不得落入宽匹配写操作。
enum ConsumerMutationPath {
    Consumer(String),
    Keys(String),
    Key {
        consumer: String,
        key_id: String,
    },
}

/// 业务作用：处理消费者绑定与 API-Key 的创建/删除，并把变更编译成普通 gateway 配置后走统一发布。
///
/// 参数说明：
/// - `req`：path/method 定位 consumer 或 key 操作，POST body 是有界 JSON
/// - `state`：提供 CAS、 RBAC、审计和发布状态机。
///
/// 返回：创建 key 时只在发布已接受后返回一次原值；其它操作返回统一发布结果，候选或并发无效时无
/// 副作用地返回 4xx。
async fn mutate_consumers(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let prepared = match prepare_config_write(&parts, &state, AdminResource::Consumers).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let path = parts.uri.path().to_string();
    let method = parts.method.clone();
    let mutation = if method == Method::POST && path == "/api/consumers" {
        collect_consumer_json::<ConsumerUpsertInput>(&parts, body, &state)
            .await
            .and_then(|input| {
                if !valid_consumer_id(&input.id) || !valid_consumer_id(&input.plan) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "invalid consumer id or plan".to_string(),
                    ));
                }
                let config = read_active_gateway_config(&state)
                    .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
                if !config.usage_plans.plans.contains_key(&input.plan) {
                    return Err((StatusCode::BAD_REQUEST, "usage plan not found".to_string()));
                }
                let gateway = upsert_consumer_binding(
                    &prepared.baseline.gateway,
                    &input.id,
                    Some(&input.plan),
                )?;
                Ok((gateway, None))
            })
    } else if method == Method::DELETE {
        match parse_consumer_mutation_path(&path) {
            Some(ConsumerMutationPath::Consumer(consumer)) => {
                if !valid_consumer_id(&consumer) {
                    Err((StatusCode::BAD_REQUEST, "invalid consumer id".to_string()))
                } else {
                    upsert_consumer_binding(&prepared.baseline.gateway, &consumer, None)
                        .map(|gateway| (gateway, None))
                }
            }
            Some(ConsumerMutationPath::Key {
                consumer,
                key_id,
            }) => {
                if !valid_consumer_id(&consumer) || !valid_api_key_binding_id(&key_id) {
                    Err((
                        StatusCode::BAD_REQUEST,
                        "invalid consumer or key id".to_string(),
                    ))
                } else {
                    remove_consumer_key(&prepared.baseline.gateway, &consumer, &key_id)
                        .map(|gateway| (gateway, None))
                }
            }
            _ => Err((
                StatusCode::NOT_FOUND,
                "unsupported consumer operation".to_string(),
            )),
        }
    } else if method == Method::POST {
        match parse_consumer_mutation_path(&path) {
            Some(ConsumerMutationPath::Keys(consumer)) if valid_consumer_id(&consumer) => {
                collect_consumer_json::<ConsumerKeyInput>(&parts, body, &state)
                    .await
                    .and_then(|input| {
                        let config = read_active_gateway_config(&state)
                            .map_err(|error| (StatusCode::CONFLICT, error.to_string()))?;
                        if !config.usage_plans.consumers.contains_key(&consumer) {
                            return Err((StatusCode::NOT_FOUND, "consumer not found".to_string()));
                        }
                        let mut random = [0_u8; 32];
                        getrandom::getrandom(&mut random).map_err(|error| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("generate API key: {error}"),
                            )
                        })?;
                        let key = format!(
                            "nwy_{}",
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
                        );
                        let digest = nasa::crypto::sha256(&key);
                        let (gateway, key_id) = add_consumer_key(
                            &prepared.baseline.gateway,
                            &consumer,
                            &input,
                            &digest,
                        )?;
                        Ok((gateway, Some((key, key_id))))
                    })
            }
            _ => Err((
                StatusCode::NOT_FOUND,
                "unsupported consumer operation".to_string(),
            )),
        }
    } else {
        Err((
            StatusCode::NOT_FOUND,
            "unsupported consumer operation".to_string(),
        ))
    };
    let response = match mutation {
        Ok((gateway, secret)) => {
            let target = crate::control::history::ArchivedDocs {
                gateway,
                interface_guard: prepared.baseline.interface_guard.clone(),
                sentinel_rules: prepared.baseline.sentinel_rules.clone(),
            };
            let response = if approval_required(&state, AdminResource::Consumers) {
                submit_approval_change(
                    &state,
                    &prepared,
                    AdminResource::Consumers,
                    ApprovalPayload::Documents {
                        target,
                        baseline: prepared.baseline.clone(),
                    },
                )
            } else {
                publish_document_set(
                    &state,
                    target,
                    prepared.baseline.clone(),
                    prepared.identity.principal_id.as_ref(),
                )
                .await
            };
            if response.status().is_success() {
                if let Some((key, key_id)) = secret {
                    inject_created_api_key(response, key, key_id).await
                } else {
                    response
                }
            } else {
                response
            }
        }
        Err((status, error)) => json(
            status,
            serde_json::json!({
                "ok": false,
                "error": error
            }),
        ),
    };
    finish_config_write(
        &state,
        &prepared.identity,
        &parts,
        AdminResource::Consumers,
        response,
    )
    .await
}

/// 业务作用：解析消费者管理 path 的固定层级，阻止多余 path 段被误解释成其它 consumer。
///
/// 参数说明：
/// - `path`：是未带 query 的规范 URI path。
///
/// 返回：只接受 consumer、consumer/keys 和 consumer/keys/key_id 三种形态；其它返回 None。
fn parse_consumer_mutation_path(path: &str) -> Option<ConsumerMutationPath> {
    let segments = path
        .strip_prefix("/api/consumers/")?
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [consumer] => Some(ConsumerMutationPath::Consumer((*consumer).to_string())),
        [consumer, "keys"] => Some(ConsumerMutationPath::Keys((*consumer).to_string())),
        [consumer, "keys", key_id] => Some(ConsumerMutationPath::Key {
            consumer: (*consumer).to_string(),
            key_id: (*key_id).to_string(),
        }),
        _ => None,
    }
}

/// 业务作用：有界收取并严格反序列化消费者写接口 JSON，统一媒体类型和错误语义。
///
/// 参数说明：
/// - `parts`：原请求头，用于媒体类型与声明长度检查。
/// - `body`：唯一请求体，按管理面预算读取。
/// - `state`：提供请求体硬上限的管理状态。
///
/// 返回：合法 JSON 返回输入模型；媒体类型、大小或 schema 非法时返回对应 HTTP 状态与低敏原因。
async fn collect_consumer_json<T: serde::de::DeserializeOwned>(
    parts: &AdminRequestParts,
    body: axum::body::Body,
    state: &AdminState,
) -> Result<T, (StatusCode, String)> {
    if !request_content_type(parts, "application/json") {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json".to_string(),
        ));
    }
    let body =
        collect_bounded_admin_body(parts, body, state.snap.load().admin_max_config_body_bytes)
            .await
            .map_err(|response| (response.status(), "invalid request body".to_string()))?;
    serde_json::from_slice(&body).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid consumer JSON: {error}"),
        )
    })
}

type ConsumerMutationResult<T> = Result<T, (StatusCode, String)>;

/// 业务作用：在 gateway YAML 中新增、修改或删除 consumer→plan 绑定；删除 consumer 时同步撤销其
/// 所有 route API-Key，避免孤儿凭据继续获得身份。
///
/// 参数说明：
/// - `gateway`：是当前主文档
/// - `consumer`：是已校验身份
/// - `plan`：为 Some 时 upsert，为 None 时删除。
///
/// 返回：返回可交给完整 builder 的 YAML；文档结构错误或删除目标不存在时返回 4xx 语义错误。
fn upsert_consumer_binding(
    gateway: &str,
    consumer: &str,
    plan: Option<&str>,
) -> ConsumerMutationResult<String> {
    let mut document = parse_gateway_yaml_value(gateway)?;
    let root = document.as_object_mut().ok_or((
        StatusCode::BAD_REQUEST,
        "gateway YAML must be a mapping".to_string(),
    ))?;
    let usage_plans = yaml_mapping_child(root, "usage_plans")?;
    let consumers = yaml_mapping_child(usage_plans, "consumers")?;
    let key = consumer.to_string();
    let existed = if let Some(plan) = plan {
        consumers.insert(key, serde_json::Value::String(plan.to_string()));
        true
    } else {
        consumers.remove(&key).is_some()
    };
    let removed_keys = if plan.is_none() {
        remove_matching_api_key_filters(&mut document, |_, _, _, filter| {
            filter_option(filter, "consumer") == Some(consumer)
        })?
    } else {
        0
    };
    if plan.is_none() && !existed && removed_keys == 0 {
        return Err((StatusCode::NOT_FOUND, "consumer not found".to_string()));
    }
    encode_gateway_yaml_value(&document)
}

/// 业务作用：向指定 route 加入只保存 SHA-256 的 API-Key 策略，使原始 key 不进入配置事实源。
///
/// 参数说明：
/// - `gateway`：是当前主文档
/// - `consumer`：已存在
/// - `input`：指定 proxy/route/source
/// - `digest`：是随机 key 的 64 字符 SHA-256。
///
/// 返回：目标唯一时返回新 YAML 与公开绑定 id；目标缺失、重复或 source 非法时拒绝。
fn add_consumer_key(
    gateway: &str,
    consumer: &str,
    input: &ConsumerKeyInput,
    digest: &str,
) -> ConsumerMutationResult<(String, String)> {
    if !matches!(input.source.as_str(), "header" | "query")
        || input.name.is_empty()
        || input.name.len() > 256
        || input.name.chars().any(char::is_whitespace)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "key source must be header/query with a bounded token name".to_string(),
        ));
    }
    let mut document = parse_gateway_yaml_value(gateway)?;
    let filter = format!(
        "api_key {}={} sha256={} consumer={}",
        input.source, input.name, digest, consumer
    );
    let mut matched = 0_usize;
    let mut key_id = None;
    visit_route_mappings_mut(&mut document, |proxy, route, route_map| {
        if proxy != input.proxy || route != input.route {
            return Ok(());
        }
        matched = matched.saturating_add(1);
        let filters = yaml_sequence_child(route_map, "filters")?;
        let index = filters.len();
        key_id = Some(api_key_binding_id(proxy, route, index));
        filters.push(serde_json::Value::String(filter.clone()));
        Ok(())
    })?;
    if matched != 1 {
        return Err((
            if matched == 0 {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            "route target must resolve exactly once".to_string(),
        ));
    }
    Ok((
        encode_gateway_yaml_value(&document)?,
        key_id.expect("one matched route has a key id"),
    ))
}

/// 业务作用：按当前读模型公开的绑定 id 精确删除 consumer 的一条 API-Key，不允许跨 consumer 撤销。
///
/// 参数说明：
/// - `gateway`：是当前主文档
/// - `consumer`：来自已校验 path。
/// - `key_id`：来自已校验 path。
///
/// 返回：唯一匹配时返回新 YAML；不存在返回 404，多重匹配返回 409 且不发布。
fn remove_consumer_key(
    gateway: &str,
    consumer: &str,
    key_id: &str,
) -> ConsumerMutationResult<String> {
    let mut document = parse_gateway_yaml_value(gateway)?;
    let removed = remove_matching_api_key_filters(&mut document, |proxy, route, index, filter| {
        filter_option(filter, "consumer") == Some(consumer)
            && api_key_binding_id(proxy, route, index) == key_id
    })?;
    match removed {
        0 => Err((StatusCode::NOT_FOUND, "API key not found".to_string())),
        1 => encode_gateway_yaml_value(&document),
        _ => Err((
            StatusCode::CONFLICT,
            "API key binding id is ambiguous".to_string(),
        )),
    }
}

/// 业务作用：遍历主文档中的旧式和多 proxy route，供管理写操作在不理解其它字段时局部修改 filters。
///
/// 参数说明：
/// - `document`：是 gateway YAML value
/// - `visitor`：获得 proxy id、route id 与可变 route mapping。
///
/// 返回：所有 route 结构合法且 visitor 成功时返回；非 sequence/mapping 或缺 id 时拒绝候选。
fn visit_route_mappings_mut(
    document: &mut serde_json::Value,
    mut visitor: impl FnMut(
        &str,
        &str,
        &mut serde_json::Map<String, serde_json::Value>,
    ) -> ConsumerMutationResult<()>,
) -> ConsumerMutationResult<()> {
    let root = document.as_object_mut().ok_or((
        StatusCode::BAD_REQUEST,
        "gateway YAML must be a mapping".to_string(),
    ))?;
    let proxies_key = "proxies";
    let has_proxies = root
        .get(proxies_key)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|proxies| !proxies.is_empty());
    if has_proxies {
        let proxies = root
            .get_mut(proxies_key)
            .and_then(serde_json::Value::as_array_mut)
            .ok_or((
                StatusCode::BAD_REQUEST,
                "proxies must be a sequence".to_string(),
            ))?;
        for proxy in proxies {
            let proxy = proxy.as_object_mut().ok_or((
                StatusCode::BAD_REQUEST,
                "proxy must be a mapping".to_string(),
            ))?;
            let proxy_id = yaml_string_field(proxy, "id")?.to_string();
            visit_route_sequence(proxy, &proxy_id, &mut visitor)?;
        }
    } else {
        visit_route_sequence(root, "default", &mut visitor)?;
    }
    Ok(())
}

/// 业务作用：遍历一个入口的 route sequence，并冻结 id 后再交给可变 visitor，避免身份与内容错位。
///
/// 参数说明：
/// - `owner`：包含 routes
/// - `proxy`：是稳定入口 id
/// - `visitor`：执行局部修改。
///
/// 返回：routes 缺失视为空；存在但结构或 route id 非法时返回错误。
fn visit_route_sequence(
    owner: &mut serde_json::Map<String, serde_json::Value>,
    proxy: &str,
    visitor: &mut impl FnMut(
        &str,
        &str,
        &mut serde_json::Map<String, serde_json::Value>,
    ) -> ConsumerMutationResult<()>,
) -> ConsumerMutationResult<()> {
    let Some(routes) = owner.get_mut("routes") else {
        return Ok(());
    };
    let routes = routes.as_array_mut().ok_or((
        StatusCode::BAD_REQUEST,
        "routes must be a sequence".to_string(),
    ))?;
    for route in routes {
        let route = route.as_object_mut().ok_or((
            StatusCode::BAD_REQUEST,
            "route must be a mapping".to_string(),
        ))?;
        let route_id = yaml_string_field(route, "id")?.to_string();
        visitor(proxy, &route_id, route)?;
    }
    Ok(())
}

/// 业务作用：删除满足身份条件的 API-Key filter，同时保留所有非 API-Key 和其它 consumer 策略的顺序。
///
/// 参数说明：
/// - `document`：是可变 gateway YAML
/// - `predicate`：只接收定位字段与原始 filter。
///
/// 返回：返回删除条数；route/filter 结构非法时拒绝而不序列化半完成结果。
fn remove_matching_api_key_filters(
    document: &mut serde_json::Value,
    mut predicate: impl FnMut(&str, &str, usize, &str) -> bool,
) -> ConsumerMutationResult<usize> {
    let mut removed = 0_usize;
    visit_route_mappings_mut(document, |proxy, route, route_map| {
        let Some(filters) = route_map.get_mut("filters") else {
            return Ok(());
        };
        let filters = filters.as_array_mut().ok_or((
            StatusCode::BAD_REQUEST,
            "route filters must be a sequence".to_string(),
        ))?;
        let mut index = 0_usize;
        filters.retain(|value| {
            let remove = value.as_str().is_some_and(|filter| {
                filter.trim().starts_with("api_key")
                    && predicate(proxy, route, index, filter.trim())
            });
            index = index.saturating_add(1);
            if remove {
                removed = removed.saturating_add(1);
            }
            !remove
        });
        Ok(())
    })?;
    Ok(removed)
}

/// 业务作用：解析管理写接口所修改的 gateway YAML，并统一给出可映射为 400 的错误。
///
/// 参数说明：
/// - `gateway`：是当前归档主文档。
///
/// 返回：合法 YAML 返回 value；语法错误返回低敏解析原因。
fn parse_gateway_yaml_value(gateway: &str) -> ConsumerMutationResult<serde_json::Value> {
    crate::config::document::parse(
        gateway.as_bytes(),
        crate::config::document::MAX_DOCUMENT_BYTES,
    )
    .map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("parse gateway YAML: {error}"),
        )
    })
}

/// 业务作用：把局部修改后的 YAML value 编码成完整主文档，供统一 builder 复验全部语义。
///
/// 参数说明：
/// - `document`：是完成局部修改但尚未发布的候选。
///
/// 返回：编码成功返回 YAML；序列化失败返回内部错误且不触碰事实源。
fn encode_gateway_yaml_value(document: &serde_json::Value) -> ConsumerMutationResult<String> {
    crate::config::document::encode(document, crate::config::document::MAX_DOCUMENT_BYTES).map_err(
        |error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encode gateway YAML: {error}"),
            )
        },
    )
}

/// 业务作用：取得或建立指定 YAML mapping 子节点，并拒绝把既有 scalar/sequence 静默覆盖为 mapping。
///
/// 参数说明：
/// - `parent`：是父 mapping
/// - `name`：是固定 schema 字段。
///
/// 返回：字段缺失时建立空 mapping；字段已是 mapping 时借用它；类型冲突返回 400。
fn yaml_mapping_child<'a>(
    parent: &'a mut serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> ConsumerMutationResult<&'a mut serde_json::Map<String, serde_json::Value>> {
    let key = name.to_string();
    if !parent.contains_key(&key) {
        parent.insert(
            key.clone(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
    }
    parent
        .get_mut(&key)
        .and_then(serde_json::Value::as_object_mut)
        .ok_or((
            StatusCode::BAD_REQUEST,
            format!("gateway `{name}` must be a mapping"),
        ))
}

/// 业务作用：取得或建立 route filters sequence，拒绝覆盖错误类型以免丢失用户配置。
///
/// 参数说明：
/// - `parent`：是 route mapping
/// - `name`：当前固定为 filters。
///
/// 返回：缺失时建立空 sequence；类型冲突返回 400。
fn yaml_sequence_child<'a>(
    parent: &'a mut serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> ConsumerMutationResult<&'a mut Vec<serde_json::Value>> {
    let key = name.to_string();
    if !parent.contains_key(&key) {
        parent.insert(key.clone(), serde_json::Value::Array(Vec::new()));
    }
    parent
        .get_mut(&key)
        .and_then(serde_json::Value::as_array_mut)
        .ok_or((
            StatusCode::BAD_REQUEST,
            format!("gateway `{name}` must be a sequence"),
        ))
}

/// 业务作用：读取 route/proxy 的稳定字符串身份，不接受隐式数值或空值转换。
///
/// 参数说明：
/// - `mapping`：是对象
/// - `name`：是固定 id 字段。
///
/// 返回：非空字符串返回借用；缺失或类型错误返回 400。
fn yaml_string_field<'a>(
    mapping: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> ConsumerMutationResult<&'a str> {
    mapping
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or((
            StatusCode::BAD_REQUEST,
            format!("gateway `{name}` must be a non-empty string"),
        ))
}

/// 业务作用：为 API-Key 绑定生成不含 key/摘要材料的稳定公开 id，避免 Consumers/Read 成为密钥
/// 猜测 oracle。
///
/// 参数说明：
/// - `proxy`：是当前整体 CAS 基线内的位置。
/// - `route`：是当前整体 CAS 基线内的位置。
/// - `index`：是当前整体 CAS 基线内的位置。
///
/// 返回：返回 24 字符小写十六进制定位 id；route 重排会产生新 id，旧 id 因 CAS 无法误删。
fn api_key_binding_id(proxy: &str, route: &str, index: usize) -> String {
    use sha2::Digest as _;

    let material = format!("{proxy}\0{route}\0{index}");
    let digest = sha2::Sha256::digest(material.as_bytes());
    let mut id = String::with_capacity(24);
    use std::fmt::Write as _;
    for byte in &digest[..12] {
        write!(&mut id, "{byte:02x}").expect("writing SHA-256 hex to String cannot fail");
    }
    id
}

/// 业务作用：校验 URL 中的 API-Key 绑定 id，避免宽字符和超长 path 进入遍历比较。
///
/// 参数说明：
/// - `id`：是未解码 path segment。
///
/// 返回：精确 24 个小写十六进制字符时返回 true。
fn valid_api_key_binding_id(id: &str) -> bool {
    id.len() == 24
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// 业务作用：仅在创建操作已被事实源接受后，把一次性 API-Key 注入 JSON 响应，不写 header、审计或
/// 日志。
///
/// 参数说明：
/// - `response`：是统一发布结果
/// - `key`：是原始随机值
/// - `key_id`：是后续撤销定位 id。
///
/// 返回：可解析 JSON 时保留状态/headers 并追加字段；异常 body 返回 500，绝不在其它通道泄露 key。
async fn inject_created_api_key(
    response: Response<BoxBody>,
    key: String,
    key_id: String,
) -> Response<BoxBody> {
    let (mut parts, body) = response.into_parts();
    let collected = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": "cannot encode key creation result"
                }),
            )
        }
    };
    let mut value: serde_json::Value = match serde_json::from_slice(&collected) {
        Ok(value) => value,
        Err(_) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": "cannot encode key creation result"
                }),
            )
        }
    };
    let Some(object) = value.as_object_mut() else {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": "cannot encode key creation result"
            }),
        );
    };
    object.insert("api_key".to_string(), serde_json::Value::String(key));
    object.insert("key_id".to_string(), serde_json::Value::String(key_id));
    object.insert(
        "secret_returned_once".to_string(),
        serde_json::Value::Bool(true),
    );
    let bytes = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": "cannot encode key creation result"
                }),
            )
        }
    };
    parts.headers.remove(hyper::header::CONTENT_LENGTH);
    parts.headers.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("private, no-store"),
    );
    Response::from_parts(parts, full_body(Bytes::from(bytes)))
}

/// 业务作用：枚举所有 TLS listener 的域名、证书到期时间、原子 manifest 与 ACME 策略状态。
///
/// 参数说明：
/// - `state`：提供当前不可变 TLS 计划与有界证书读取路径。
///
/// 返回：返回 200 和逐证书状态；单个证书缺失/损坏仅将该项标记 `ok=false`，不读取或返回私钥。
fn read_certificates(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    let mut certificates = Vec::new();
    for proxy in snapshot.proxies.iter() {
        let Some(tls) = &proxy.tls else {
            continue;
        };
        let source = if tls.in_memory.is_some() {
            "sds"
        } else if tls.keypair_manifest_file.is_some() {
            "manifest"
        } else if tls.acme.is_some() {
            "acme"
        } else {
            "static"
        };
        let default_status = if let Some(material) = &tls.in_memory {
            certificate_status(material.certificate_chain.as_ref())
        } else {
            crate::tls::active_keypair_paths(tls)
                .and_then(|(cert, _)| {
                    crate::io::bounded_io::read_file(&cert, 1024 * 1024, "admin TLS certificate")
                })
                .and_then(|bytes| certificate_status(&bytes))
        };
        certificates.push(certificate_json(
            &proxy.id,
            "default",
            proxy.server_names.as_ref(),
            source,
            tls,
            default_status,
        ));
        for (index, sni) in tls.certs.iter().enumerate() {
            let status = crate::io::bounded_io::read_file(
                &sni.cert_file,
                1024 * 1024,
                "admin SNI TLS certificate",
            )
            .and_then(|bytes| certificate_status(&bytes));
            certificates.push(certificate_json(
                &proxy.id,
                &format!("sni-{index}"),
                sni.server_names.as_ref(),
                "static",
                tls,
                status,
            ));
        }
    }
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "certificates": certificates
        }),
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateUploadInput {
    proxy: String,
    certificate_pem: String,
    private_key_pem: String,
}

/// 业务作用：以配置集 CAS 和证书事实 CAS 双重保护手工证书轮换，并与 ACME 安装共享互斥与 pair
/// 校验，防止覆盖并发续期或发布不匹配私钥。
///
/// 参数说明：
/// - `req`：必须带配置 `If-Match`、`X-Naway-Certificate-If-Match` 和有界 JSON PEM
/// - `state`：提供当前 TLS 计划、RBAC 与审计。
///
/// 返回：两个基线均未变化且 pair 安装成功时返回 200；并发轮换返回 412；无 listener、SDS、非法
/// PEM、超限或权限错误返回 4xx，I/O 故障返回 5xx。
async fn upload_certificate(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    const MAX_CERT_UPLOAD_BYTES: usize = 2 * 1024 * 1024;

    let (parts, body) = req.into_parts();
    let prepared = match prepare_config_write(&parts, &state, AdminResource::Certs).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let expected_certificate = parts
        .headers
        .get("x-naway-certificate-if-match")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let response = if !request_content_type(&parts, "application/json") {
        json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            serde_json::json!({
                "ok": false,
                "error": "Content-Type must be application/json"
            }),
        )
    } else if expected_certificate.is_none() {
        json(
            StatusCode::PRECONDITION_REQUIRED,
            serde_json::json!({
                "ok": false,
                "error": "X-Naway-Certificate-If-Match is required; read GET /api/certs",
            }),
        )
    } else {
        match collect_bounded_admin_body(&parts, body, MAX_CERT_UPLOAD_BYTES).await {
            Err(response) => *response,
            Ok(body) => match serde_json::from_slice::<CertificateUploadInput>(&body) {
                Err(error) => json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "error": format!("invalid certificate JSON: {error}")
                    }),
                ),
                Ok(input)
                    if input
                        .certificate_pem
                        .len()
                        .saturating_add(input.private_key_pem.len())
                        > MAX_CERT_UPLOAD_BYTES =>
                {
                    json(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        serde_json::json!({
                            "ok": false,
                            "error": "certificate pair exceeds 2 MiB"
                        }),
                    )
                }
                Ok(input) => {
                    let tls = {
                        let snapshot = state.snap.load();
                        snapshot
                            .proxies
                            .iter()
                            .find(|proxy| proxy.id == input.proxy)
                            .and_then(|proxy| proxy.tls.clone())
                    };
                    match tls {
                        None => json(
                            StatusCode::NOT_FOUND,
                            serde_json::json!({
                                "ok": false,
                                "error": "TLS proxy not found"
                            }),
                        ),
                        Some(tls) if tls.in_memory.is_some() => json(
                            StatusCode::CONFLICT,
                            serde_json::json!({
                                "ok": false,
                                "error": "SDS-owned certificate cannot be overwritten by file upload"
                            }),
                        ),
                        Some(tls) => {
                            let expected = expected_certificate
                                .as_deref()
                                .expect("presence checked")
                                .to_string();
                            let certificate = input.certificate_pem.into_bytes();
                            let private_key = input.private_key_pem.into_bytes();
                            if approval_required(&state, AdminResource::Certs) {
                                submit_approval_change(
                                    &state,
                                    &prepared,
                                    AdminResource::Certs,
                                    ApprovalPayload::Certificate {
                                        tls: Box::new(tls),
                                        expected_etag: expected,
                                        certificate_pem: certificate,
                                        private_key_pem: private_key,
                                    },
                                )
                            } else {
                                install_uploaded_certificate(
                                    tls,
                                    expected,
                                    certificate,
                                    private_key,
                                )
                                .await
                            }
                        }
                    }
                }
            },
        }
    };
    finish_config_write(
        &state,
        &prepared.identity,
        &parts,
        AdminResource::Certs,
        response,
    )
    .await
}

/// 业务作用：执行已经通过管理门禁的证书 CAS 安装，并把并发变化与执行故障映射为稳定 HTTP 语义。
///
/// 参数说明：
/// - `tls`：已冻结的 TLS 安装目标。
/// - `expected`：安装前必须仍匹配的证书基线。
/// - `certificate`：有界且已读完的证书 PEM。
/// - `private_key`：有界且已读完的私钥 PEM。
///
/// 返回：安装成功返回 200；证书已变化返回 412 和新 ETag；pair 非法返回 400；worker 故障返回 500。
async fn install_uploaded_certificate(
    tls: crate::config::TlsRuntimeCfg,
    expected: String,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
) -> Response<BoxBody> {
    let installed = tokio::task::spawn_blocking(move || {
        crate::tls::acme::install_keypair_atomically_if_match(
            &tls,
            &expected,
            &certificate,
            &private_key,
        )
    })
    .await;
    match installed {
        Ok(Ok(crate::tls::acme::KeypairCasInstallOutcome::Installed)) => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "status": "installed"
            }),
        ),
        Ok(Ok(crate::tls::acme::KeypairCasInstallOutcome::Changed(etag))) => {
            let mut response = json(
                StatusCode::PRECONDITION_FAILED,
                serde_json::json!({
                    "ok": false,
                    "error": "certificate changed since it was read",
                    "certificate_etag": etag,
                }),
            );
            if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
                response.headers_mut().insert(hyper::header::ETAG, value);
            }
            response
        }
        Ok(Err(error)) => json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": error.to_string()
            }),
        ),
        Err(error) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "ok": false,
                "error": format!("certificate worker failed: {error}")
            }),
        ),
    }
}

/// 业务作用：将一张可见证书的有效期解析成 Console 可用状态，不接触私钥。
///
/// 参数说明：
/// - `pem`：是经 1 MiB 上限保护的 PEM 证书链。
///
/// 返回：有 leaf 且 X.509 可解析时返回 notBefore/notAfter Unix 时间与剩余天数；空链或非法证书失败。
fn certificate_status(pem: &[u8]) -> anyhow::Result<serde_json::Value> {
    let mut reader = std::io::Cursor::new(pem);
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parse TLS certificate PEM")?
        .ok_or_else(|| anyhow::anyhow!("certificate PEM contains no certificate"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("parse X.509 certificate: {error}"))?;
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64;
    Ok(serde_json::json!({
        "etag": crate::tls::acme::certificate_etag(pem),
        "not_before_unix": not_before,
        "not_after_unix": not_after,
        "days_remaining": not_after.saturating_sub(now) / 86_400,
        "expired": not_after <= now,
        "subject": certificate.subject().to_string(),
    }))
}

/// 业务作用：组装一条不含路径和私钥的 TLS/ACME 管理读模型。
///
/// 参数说明：
/// - `proxy`：证书所属 proxy 标识。
/// - `entry`：该 proxy 内证书条目标识。
/// - `domains`：证书覆盖的域名集合。
/// - `source`：证书来源类型。
/// - `tls`：TLS 交付策略。
/// - `status`：有界 X.509 解析结果。
///
/// 返回：解析成功时合并有效期；失败时返回 `ok=false` 和低敏原因。
fn certificate_json(
    proxy: &str,
    entry: &str,
    domains: &[String],
    source: &str,
    tls: &crate::config::TlsRuntimeCfg,
    status: anyhow::Result<serde_json::Value>,
) -> serde_json::Value {
    let acme = tls.acme.as_ref().map(|acme| {
        serde_json::json!({
            "domains": acme.domains.as_ref(),
            "challenge": match acme.challenge {
                crate::config::AcmeChallenge::Http01 => "http-01",
                crate::config::AcmeChallenge::Dns01 => "dns-01",
            },
            "renew_before_days": acme.renew_before_days,
            "storage_mode": acme.storage_mode,
            "lock_backend": acme.lock_backend,
        })
    });
    match status {
        Ok(status) => serde_json::json!({
            "proxy": proxy,
            "entry": entry,
            "domains": domains,
            "source": source,
            "manifest": tls.keypair_manifest_file.is_some(),
            "acme": acme,
            "ok": true,
            "status": status,
        }),
        Err(error) => serde_json::json!({
            "proxy": proxy,
            "entry": entry,
            "domains": domains,
            "source": source,
            "manifest": tls.keypair_manifest_file.is_some(),
            "acme": acme,
            "ok": false,
            "reason": error.to_string(),
        }),
    }
}

/// 业务作用：枚举手写单入口与多 proxy 配置中的原始 route，供低频消费者管理对账。
///
/// 参数说明：
/// - `config`：是当前已解析主配置。
///
/// 返回：返回 `(proxy_id, route)` 借用集；多 proxy 存在时不重复枚举旧全局 route。
fn configured_routes(
    config: &crate::config::model::GatewayConfig,
) -> Vec<(&str, &crate::config::model::RouteCfg)> {
    if config.proxies.is_empty() {
        return config
            .routes
            .iter()
            .map(|route| ("default", route))
            .collect();
    }
    config
        .proxies
        .iter()
        .flat_map(|proxy| {
            proxy
                .routes
                .iter()
                .map(move |route| (proxy.id.as_str(), route))
        })
        .collect()
}

/// 业务作用：从已由 route parser 限定为空白分隔的 filter DSL 中取一个非敏 option。
///
/// 参数说明：
/// - `filter`：是原始 filter
/// - `name`：只用于 `consumer/header/query` 等非密钥字段。
///
/// 返回：找到 `name=value` 返回去除成对引号的值；缺失返回 `None`。
fn filter_option<'a>(filter: &'a str, name: &str) -> Option<&'a str> {
    filter.split_whitespace().find_map(|token| {
        let (key, value) = token.split_once('=')?;
        (key == name).then(|| value.trim_matches(['\'', '"']))
    })
}

/// 业务作用：校验 Console path 中的 consumer 身份，保持与用量套餐目录的低风险字符边界一致。
///
/// 参数说明：
/// - `consumer`：是 URL path 中未解码的稳定 id。
///
/// 返回：1..=256 字节、无控制字符且不含 `/` 时返回 true。
fn valid_consumer_id(consumer: &str) -> bool {
    !consumer.is_empty()
        && consumer.len() <= 256
        && !consumer
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte == b'/')
}

/// 业务作用：`PUT /api/config/current`:`If-Match` CAS + 候选校验 + 原子落盘 + **确认生效**。
///
/// 参数说明：
/// - `req`：包含主体凭据、整体 If-Match 和有界主文档原文的请求。
/// - `state`：当前事实源、活动快照、审计与发布入口。
///
/// 返回：同一候选已经生效时返回成功；构建或基线不符时拒绝，结果未确认时不能推断已经还原。
///
/// 发布顺序：
/// 1. 认证 → Origin → 平面边界 → RBAC(Config,Write);
/// 2. `If-Match` 必填且必须等于当前配置集 ETag(缺失 428、失配 412);
/// 3. Content-Type/有界 body → 临时文件 → **候选构建校验**(坏配置 400,线上文件不动);
/// 4. 原子 rename 覆盖主 YML → SIGHUP 唤醒唯一 reload worker;
/// 5. 等待 history 出现目标指纹的成功事件且 ArcSwap 版本前进,才回 `applied`;
///    明确拒绝后仅在旧快照和本候选文件仍被持有时恢复基线；已发布或被其它写者替换的文件不得撤回。
async fn publish_current_config(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let deny = |status: StatusCode, error: &str| {
        json(
            status,
            serde_json::json!({
                "ok": false,
                "error": error
            }),
        )
    };
    if !identity.allows(AdminResource::Config, AdminAction::Write) {
        let response = deny(StatusCode::FORBIDDEN, "forbidden");
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    }
    let content_type_ok = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/yaml"))
        });
    if !content_type_ok {
        let response = deny(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/yaml",
        );
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    }
    // 只能对已提交代的完整配置执行 CAS；磁盘候选或 bootstrap 不能成为旁路发布基线。
    let baseline = state.snap.load_full();
    let current_fingerprint = baseline.config_fingerprint;
    let Some(current_fingerprint) = current_fingerprint else {
        let response = deny(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot fingerprint current config set",
        );
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    };
    if !current_config_baseline_matches(&state, baseline.version, current_fingerprint).await {
        let response = deny(
            StatusCode::PRECONDITION_FAILED,
            "active configuration baseline changed; retry",
        );
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    }
    let expected_etag = config_etag(current_fingerprint);
    let Some(if_match) = parts
        .headers
        .get(hyper::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        // 428:强制 CAS,不允许"盲发"覆盖别人的改动。
        let response = deny(
            StatusCode::PRECONDITION_REQUIRED,
            "If-Match is required; read GET /api/config/current for the current ETag",
        );
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    };
    if if_match.trim() != expected_etag {
        let mut response = json(
            StatusCode::PRECONDITION_FAILED,
            serde_json::json!({
                "ok": false,
                "error": "config changed since it was read; rebase on the current version",
                "etag": expected_etag,
                "fingerprint": current_fingerprint,
            }),
        );
        if let Ok(value) = hyper::header::HeaderValue::from_str(&expected_etag) {
            response.headers_mut().insert(hyper::header::ETAG, value);
        }
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    }
    let max_bytes = state.snap.load().admin_max_config_body_bytes;
    let candidate_body = match collect_bounded_admin_body(&parts, body, max_bytes).await {
        Ok(body) => body,
        Err(response) => {
            let status = response.status();
            audit_publish(&state, &identity, &parts, status).await;
            return *response;
        }
    };
    // Nacos 是集群配置事实源:必须 CAS 写回远端并靠 config watch 收敛,
    // 直接改本地物化文件会被下次 watch 覆盖，且不会在集群生效。
    let response = if baseline.config_source.nacos.enabled {
        publish_cluster_config(&state, candidate_body, identity.principal_id.as_ref()).await
    } else {
        publish_validated_config(&state, candidate_body, current_fingerprint).await
    };
    audit_publish(&state, &identity, &parts, response.status()).await;
    response
}

/// 业务作用：Nacos 配置源的集群发布——原子 bundle CAS + 生成 rollout id。
///
/// 与本地发布的关键差别:**本节点不自行换版**,发布只是把新配置 CAS 写回集群事实源,
/// 各节点(含本节点)靠 config watch 各自收敛。因此这里返回 202 + `rollout_id`,
/// 由 `GET /api/cluster/rollout` 判定"全部启用节点是否收敛到同一 (version, fingerprint)"。
///
/// 只改 `gateway.yml` 文档:interface-guard/sentinel 取当前线上归档原文一起写回,
/// 保证 bundle 始终是完整一致的三件套,watcher 不会读到新旧混合配置。
async fn publish_cluster_config(
    state: &Arc<AdminState>,
    candidate_body: Bytes,
    initiator: &str,
) -> Response<BoxBody> {
    let Ok(gateway_yaml) = String::from_utf8(candidate_body.to_vec()) else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": "config must be valid UTF-8"
            }),
        );
    };
    let current_version = state.snap.load().version;
    // 当前线上版本的归档三文件既是并发基线,也提供本次不改动的另外两份文档。
    let baseline = match state.config_history.read_archived(current_version) {
        Ok(docs) => docs,
        Err(error) => {
            return json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": format!("cannot verify publish base: current version {current_version} not archived: {error}; retry after next successful reload"),
                }),
            )
        }
    };
    let target = crate::control::history::ArchivedDocs {
        gateway: gateway_yaml,
        interface_guard: baseline.interface_guard.clone(),
        sentinel_rules: baseline.sentinel_rules.clone(),
    };
    publish_cluster_documents(state, target, baseline, initiator).await
}

/// 业务作用：把完整三文档候选通过 Nacos 原子 bundle 和同一 rollout 状态机发布，供主配置、
/// Sentinel 与消费者管理接口共享唯一集群事实源。
///
/// 参数说明：
/// - `state`：提供当前配置源与策略
/// - `target`：是完整候选和发布基线
/// - `baseline`：是完整候选和发布基线
/// - `initiator`：绑定审计及 maker-checker 身份。
///
/// 返回：候选非法或远端漂移时无副作用地返回 4xx；CAS/override 成功后返回可轮询的 rollout；依赖
/// 故障返回 502。
async fn publish_cluster_documents(
    state: &Arc<AdminState>,
    target: crate::control::history::ArchivedDocs,
    baseline: crate::control::history::ArchivedDocs,
    initiator: &str,
) -> Response<BoxBody> {
    publish_scoped_cluster_documents(state, target, baseline, initiator, None).await
}

/// 业务作用：在同一集群发布状态机内保留工作区审批范围，候选先构建并复验权限后才写远端事实源。
///
/// 参数说明：
/// - `state`：固定发布
/// - `target`：固定发布
/// - `baseline`：固定发布
/// - `initiator`：固定发布
/// - `workspace`：是审批中的归属与摘要。
///
/// 返回：原子 CAS 或 canary 登记结果；权威漂移拒绝且没有新增外部发布。
async fn publish_scoped_cluster_documents(
    state: &Arc<AdminState>,
    target: crate::control::history::ArchivedDocs,
    baseline: crate::control::history::ArchivedDocs,
    initiator: &str,
    workspace: Option<audit::WorkspaceAudit>,
) -> Response<BoxBody> {
    let (nacos, discovery, rollout_policy, current_version) = {
        let snap = state.snap.load();
        (
            snap.config_source.nacos.clone(),
            snap.discovery.nacos.clone(),
            snap.admin_rollout.clone(),
            snap.version,
        )
    };
    if nacos.bundle_data_id.trim().is_empty() {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster publish requires config_source.nacos.bundle_data_id for atomic CAS",
            }),
        );
    }
    // 候选先本地 build-only 校验:坏配置绝不进集群事实源。
    let candidate = match build_cluster_candidate_snapshot(state, &target).await {
        Ok(candidate) => candidate,
        Err(error) => return error.response(),
    };
    let candidate_authority = workspace
        .as_ref()
        .and_then(|scope| candidate.ownership.binding(&scope.binding.owner.workspace));
    if let Some(scope) = &workspace {
        let current = state.snap.load();
        if current
            .ownership
            .binding(&scope.binding.owner.workspace)
            .as_ref()
            != Some(&scope.binding)
        {
            return plain(
                StatusCode::PRECONDITION_FAILED,
                "workspace authority changed\n",
            );
        }
    }
    if rollout_policy.enabled {
        return publish_cluster_canary(
            state,
            nacos,
            discovery,
            rollout_policy,
            current_version,
            target,
            baseline,
            initiator,
            workspace,
            candidate_authority,
        )
        .await;
    }
    let documents_digest = target.digest();
    let outcome = run_nacos_rollback_offloaded(
        nacos,
        current_version.saturating_add(1),
        target,
        baseline,
        true,
    )
    .await;
    let record = |status: &str| {
        state.config_history.record_control_event(
            "admin-cluster-publish",
            &state.cfg_path,
            current_version,
            current_version.saturating_add(1),
            status,
        );
    };
    match outcome {
        Ok(NacosRollbackOutcome::AlreadyMatches) => json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "status": "already_published",
                "note": "remote bundle already equals the submitted config",
            }),
        ),
        Ok(NacosRollbackOutcome::Created(data_id)) => {
            record("initial_published");
            let rollout = state.rollouts.start_scoped(
                current_version,
                &data_id,
                initiator,
                documents_digest.clone(),
                workspace.clone(),
                &state.snap.load().ownership,
            );
            json(
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "ok": true,
                    "status": "initialized",
                    "rollout_id": rollout,
                    "base_version": current_version,
                    "data_id": data_id,
                    "note": "initial bundle published to Nacos; poll /api/cluster/rollout until all enabled nodes converge",
                }),
            )
        }
        Ok(NacosRollbackOutcome::Published(data_id)) => {
            record("cas_published");
            let rollout = state.rollouts.start_scoped(
                current_version,
                &data_id,
                initiator,
                documents_digest.clone(),
                workspace.clone(),
                &state.snap.load().ownership,
            );
            json(
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "ok": true,
                    "status": "published",
                    "rollout_id": rollout,
                    "base_version": current_version,
                    "data_id": data_id,
                    "note": "CAS published to Nacos; poll /api/cluster/rollout until all enabled nodes converge",
                }),
            )
        }
        Ok(NacosRollbackOutcome::Drifted(ids)) => {
            record("rejected_drift");
            json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": "remote config drifted from this node's live version; rebase and retry",
                    "drifted_data_ids": ids,
                    "base_version": current_version,
                }),
            )
        }
        Ok(NacosRollbackOutcome::CasConflict(data_id)) => {
            record("cas_conflict");
            json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": "concurrent publish detected; rebase on the current remote bundle",
                    "data_id": data_id,
                }),
            )
        }
        Ok(NacosRollbackOutcome::MultiDataId(ids)) => json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "legacy multi-dataId publish is not atomic",
                "changed_data_ids": ids
            }),
        ),
        Err(error) => json(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "ok": false,
                "error": error.to_string()
            }),
        ),
    }
}

/// 业务作用：建立节点级 Nacos override 并启动可观测、可回滚、可审批的渐进发布。
///
/// 参数说明：
/// - `state`：管理运行态与发布登记。
/// - `nacos`：冻结的 Nacos 配置源。
/// - `discovery`：冻结的集群成员发现配置。
/// - `policy`：渐进发布与观察策略。
/// - `current_version`：发起发布时的活动配置版本。
/// - `target`：完整候选文档集。
/// - `baseline`：完整回退基线。
/// - `initiator`：受四眼审批约束的提交主体。
/// - `workspace`：冻结的工作区审批权威。
/// - `candidate_authority`：候选中的控制面归属权威。
///
/// 返回：override 全部发布并启动后台状态机时返回 202；成员证据不足、并发候选或 Nacos 失败时拒绝。
#[allow(clippy::too_many_arguments)]
async fn publish_cluster_canary(
    state: &Arc<AdminState>,
    nacos: crate::config::model::NacosConfigSourceCfg,
    discovery: crate::config::model::NacosDiscoveryCfg,
    policy: crate::config::model::AdminRolloutCfg,
    current_version: u64,
    target: crate::control::history::ArchivedDocs,
    baseline: crate::control::history::ArchivedDocs,
    initiator: &str,
    workspace: Option<audit::WorkspaceAudit>,
    candidate_authority: Option<crate::control::ownership::Binding>,
) -> Response<BoxBody> {
    let Some(service) = crate::upstream::discovery::self_register_service_name(&discovery) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "canary rollout requires discovery.nacos.self_register.enabled"
            }),
        );
    };
    let instances = match state
        .member_discovery
        .discover(&discovery, service, cluster::discovery::REQUEST_TIMEOUT)
        .await
    {
        Ok(instances) => instances,
        Err(error) => {
            return json(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    let canary_nodes = match select_canary_nodes(&instances, &policy, &nacos) {
        Ok(nodes) => nodes,
        Err(error) => {
            return json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    let digest_input =
        match crate::control::reload::encode_atomic_nacos_bundle("candidate-digest", &target) {
            Ok(content) => content,
            Err(error) => {
                return json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({
                        "ok": false,
                        "error": error.to_string()
                    }),
                )
            }
        };
    if let Some(scope) = &workspace {
        if state
            .snap
            .load()
            .ownership
            .binding(&scope.binding.owner.workspace)
            .as_ref()
            != Some(&scope.binding)
        {
            return plain(
                StatusCode::PRECONDITION_FAILED,
                "workspace authority changed\n",
            );
        }
    }
    let candidate_digest = workspace.as_ref().map_or_else(
        || nasa::crypto::sha256(&digest_input),
        |scope| scope.candidate_sha256.clone(),
    );
    let rollout_id = match state.rollouts.start_canary(
        current_version,
        nacos.bundle_data_id.trim(),
        initiator,
        candidate_digest.clone(),
        canary_nodes.clone(),
        target.clone(),
        baseline,
        policy,
        nacos.clone(),
        discovery,
        workspace,
        candidate_authority,
        &state.snap.load().ownership,
    ) {
        Ok(id) => id,
        Err(error) => {
            return json(
                StatusCode::CONFLICT,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            )
        }
    };
    if let Err(error) = run_canary_overrides_offloaded(
        nacos,
        rollout_id.clone(),
        target,
        canary_nodes.clone(),
        CanaryOverrideOperation::Publish,
    )
    .await
    {
        state.rollouts.update(&rollout_id, |record| {
            record.phase = "failed".to_string();
            record.reason = Some(error.to_string());
        });
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "rollout_id": rollout_id,
                "error": error.to_string()
            }),
        );
    }
    state.config_history.record_control_event(
        "admin-canary-rollout",
        &state.cfg_path,
        current_version,
        current_version.saturating_add(1),
        "canary_published",
    );
    tokio::spawn(run_canary_rollout(state.clone(), rollout_id.clone()));
    json(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "ok": true,
            "status": "canary_published",
            "rollout_id": rollout_id,
            "base_version": current_version,
            "candidate_etag": format!("\"sha256-{candidate_digest}\""),
            "canary_nodes": canary_nodes,
            "note": "poll /api/cluster/rollout; approval, promotion, rollback and cleanup are driven by the rollout state machine",
        }),
    )
}

/// 业务作用：为只需预检的工作区和门户入口执行完整候选验证，不提前创建文件提交权。
///
/// 参数说明：
/// - `state`：提供真实部署根、当前来源和启动权限边界。
/// - `docs`：尚未发布的三份原文。
///
/// 返回：完整候选可构建时成功；任何语义或启动门失败均拒绝，不写文件或快照。
async fn validate_cluster_candidate(
    state: &Arc<AdminState>,
    docs: &crate::control::history::ArchivedDocs,
) -> Result<(), candidate::BuildError> {
    build_cluster_candidate_snapshot(state, docs)
        .await
        .map(|_| ())
}

/// 业务作用：发布动作审计:与其它写操作同一 fail-closed 口径(审计失败只记日志,状态已由调用方决定)。
async fn audit_publish(
    state: &AdminState,
    identity: &AdminIdentity,
    parts: &AdminRequestParts,
    status: StatusCode,
) {
    if let Err(error) = record_admin_audit(
        state,
        identity,
        parts,
        AdminResource::Config,
        AdminAction::Write,
        "completed",
        Some(status.as_u16()),
    )
    .await
    {
        tracing::error!(%error, "failed to audit config publish");
    }
}

/// 业务作用：对 UI 提交的候选 gateway.yml 做有界 build-only 校验；真实配置文件和 ArcSwap 均不修改。
///
/// 参数说明：
/// - `req`：带有当前主体权限与有限主文档原文的请求。
/// - `state`：当前部署根、候选容量与启动资源边界。
///
/// 返回：完成构建后返回候选摘要；忙碌503、非法400或内部失败500均不发布配置。
async fn dry_run_submitted_config(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    let (parts, body) = req.into_parts();
    let identity = match authenticate_admin_request(&parts, &state) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        return response;
    }
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    if !identity.allows(AdminResource::Config, AdminAction::DryRun) {
        if let Err(error) = record_admin_audit(
            &state,
            &identity,
            &parts,
            AdminResource::Config,
            AdminAction::DryRun,
            "completed",
            Some(StatusCode::FORBIDDEN.as_u16()),
        )
        .await
        {
            tracing::error!(%error, "failed to audit candidate dry-run RBAC denial");
        }
        return json(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "ok": false,
                "error": "forbidden"
            }),
        );
    }
    let content_type_ok = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/yaml"))
        });
    if !content_type_ok {
        return json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            serde_json::json!({
                "ok": false,
                "error": "Content-Type must be application/yaml"
            }),
        );
    }
    let max_bytes = state.snap.load().admin_max_config_body_bytes;
    let candidate_body = match collect_bounded_admin_body(&parts, body, max_bytes).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    match candidate::build_main(&state, candidate_body).await {
        Ok(candidate) => dry_run_snapshot_response(&state, candidate),
        Err(error) => error.response(),
    }
}

/// 业务作用：从 axum body 逐 frame 收集有界控制面请求：单 frame 直接复用 Bytes，多 frame 只分配一次聚合缓冲。
async fn collect_bounded_admin_body(
    parts: &AdminRequestParts,
    mut body: axum::body::Body,
    max_bytes: usize,
) -> Result<Bytes, Box<Response<BoxBody>>> {
    if let Some(content_length) = parts.headers.get(hyper::header::CONTENT_LENGTH) {
        let declared = content_length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                Box::new(json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "ok": false,
                        "error": "invalid Content-Length"
                    }),
                ))
            })?;
        if declared > max_bytes {
            return Err(Box::new(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({
                    "ok": false,
                    "error": "request body too large"
                }),
            )));
        }
    }
    let mut total = 0_usize;
    let mut one: Option<Bytes> = None;
    let mut many: Option<BytesMut> = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            Box::new(json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": format!("read request body: {error}")
                }),
            ))
        })?;
        let data = frame.into_data().map_err(|_| {
            Box::new(json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": "request body trailers are not supported"
                }),
            ))
        })?;
        total = total.checked_add(data.len()).ok_or_else(|| {
            Box::new(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({
                    "ok": false,
                    "error": "request body too large"
                }),
            ))
        })?;
        if total > max_bytes {
            return Err(Box::new(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({
                    "ok": false,
                    "error": "request body too large"
                }),
            )));
        }
        if let Some(buffer) = &mut many {
            buffer.extend_from_slice(data.as_ref());
        } else if let Some(first) = one.take() {
            let mut buffer = BytesMut::with_capacity(total);
            buffer.extend_from_slice(first.as_ref());
            buffer.extend_from_slice(data.as_ref());
            many = Some(buffer);
        } else {
            one = Some(data);
        }
    }
    Ok(match many {
        Some(buffer) => buffer.freeze(),
        None => one.unwrap_or_default(),
    })
}

/// 业务作用：对候选快照执行与真实 reload 一致的 bootstrap 拓扑判定，再返回低基数摘要。
///
/// 参数说明：
/// - `state`：提供仍在服务的活动快照。
/// - `candidate`：已完成配置构建、尚未发布的候选。
///
/// 返回：需要重启的配置变化返回冲突；允许热更时返回候选摘要与监听准备要求，不发布快照。
fn dry_run_snapshot_response(state: &AdminState, candidate: GatewaySnapshot) -> Response<BoxBody> {
    let current = state.snap.load();
    let candidate_listener_topology = candidate.listen_topology();
    let current_listener_topology = current.listen_topology();
    let listener_prepare_required = candidate_listener_topology != current_listener_topology
        || candidate.admin_listen != current.admin_listen;
    #[cfg(feature = "admin-grpc")]
    let listener_prepare_required = listener_prepare_required
        || candidate
            .admin_management
            .as_ref()
            .and_then(|plan| plan.receiver_address())
            != current
                .admin_management
                .as_ref()
                .and_then(|plan| plan.receiver_address());
    let restart_field =
        if let Some(field) = crate::config::centers::restart_field(&current, &candidate) {
            Some(field)
        } else if !current.process_log.same_bootstrap(&candidate.process_log) {
            Some("log")
        } else if !current.admin_audit.same_bootstrap(&candidate.admin_audit) {
            Some("admin.audit")
        } else if !current.access_log.same_sink_topology(&candidate.access_log) {
            Some("access_log queue/sink topology")
        } else if crate::cache::http::runtime_config_signature(&current.runtime_state.http_cache)
            != crate::cache::http::runtime_config_signature(&candidate.runtime_state.http_cache)
        {
            Some("runtime_state.http_cache bootstrap")
        } else if crate::observability::telemetry::config_signature(&current.telemetry)
            != crate::observability::telemetry::config_signature(&candidate.telemetry)
        {
            Some("telemetry bootstrap")
        } else {
            None
        };
    if let Some(field) = restart_field {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": format!("{field} change requires restart"),
            }),
        );
    }
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "summary": candidate.summary(),
            "applied": false,
            "listener_prepare_required": listener_prepare_required,
        }),
    )
}

/// 业务作用：执行已授权的连接治理动作，按指定 route、IP 或 consumer 关闭匹配长连接。
fn close_long_connections(req: &AdminRequestParts, state: &AdminState) -> Response<BoxBody> {
    let query = req.uri.query().unwrap_or_default();
    if let Some(route) = query_param(query, "route") {
        let n = state.conn_registry.close_by_route(route);
        return plain(StatusCode::OK, &format!("closed route={route} count={n}\n"));
    }
    if let Some(raw_ip) = query_param(query, "ip") {
        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            return plain(StatusCode::BAD_REQUEST, "invalid ip\n");
        };
        let n = state.conn_registry.close_by_ip(ip);
        return plain(StatusCode::OK, &format!("closed ip={ip} count={n}\n"));
    }
    if let Some(consumer) = query_param(query, "consumer") {
        if consumer.is_empty() || consumer.len() > 256 {
            return plain(StatusCode::BAD_REQUEST, "invalid consumer\n");
        }
        let n = state.conn_registry.close_by_consumer(consumer);
        return plain(
            StatusCode::OK,
            &format!("closed consumer={consumer} count={n}\n"),
        );
    }
    if let Some(raw_version) = query_param(query, "stale_before") {
        let Ok(version) = raw_version.parse::<u64>() else {
            return plain(StatusCode::BAD_REQUEST, "invalid stale_before\n");
        };
        let grace_ms = match query_param(query, "grace_ms") {
            Some(raw) => match raw.parse::<u64>() {
                Ok(value) => value,
                Err(_) => return plain(StatusCode::BAD_REQUEST, "invalid grace_ms\n"),
            },
            None => state.snap.load().long_connections.drain_grace_ms,
        };
        let n = state
            .conn_registry
            .schedule_drain_stale(version, Duration::from_millis(grace_ms));
        if grace_ms == 0 {
            return plain(
                StatusCode::OK,
                &format!("closed stale_before={version} count={n}\n"),
            );
        }
        return plain(
            StatusCode::OK,
            &format!("scheduled stale_before={version} grace_ms={grace_ms} count={n}\n"),
        );
    }
    plain(
        StatusCode::BAD_REQUEST,
        "missing route, ip, consumer, or stale_before query parameter\n",
    )
}

/// 业务作用：把管理面的 IP 封禁或撤销写入动态事实源，并触发本地黑名单同步。
async fn set_blacklist_ip(
    req: &AdminRequestParts,
    state: &AdminState,
    blocked: bool,
) -> Response<BoxBody> {
    let Some(raw_ip) = query_param(req.uri.query().unwrap_or_default(), "ip") else {
        return plain(StatusCode::BAD_REQUEST, "missing ip query parameter\n");
    };
    let Ok(ip) = raw_ip.parse::<IpAddr>() else {
        return plain(StatusCode::BAD_REQUEST, "invalid ip\n");
    };
    let cfg = state.snap.load().runtime_state.blacklist.clone();
    if !cfg.enabled {
        return plain(StatusCode::CONFLICT, "blacklist disabled\n");
    }
    let key = ip.to_string();
    let result = if blocked {
        let value = match blacklist_value(req.uri.query().unwrap_or_default()) {
            Ok(value) => value,
            Err(msg) => return plain(StatusCode::BAD_REQUEST, msg),
        };
        state
            .dynamic_store
            .put(&cfg.collection, &key, value.as_bytes())
            .await
    } else {
        state.dynamic_store.delete(&cfg.collection, &key).await
    };
    if let Err(e) = result {
        tracing::warn!(ip = %ip, error = %e, "admin blacklist store update failed");
        return plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            "blacklist store update failed\n",
        );
    }
    if let Err(e) = state
        .blacklist
        .refresh_from_store(state.dynamic_store.as_ref(), &cfg.collection)
        .await
    {
        tracing::warn!(ip = %ip, error = %e, "admin blacklist cache refresh failed");
        return plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            "blacklist cache refresh failed\n",
        );
    }
    if blocked {
        let closed = state.conn_registry.close_by_ip(ip);
        //  审计:手工拉黑记 who/why/source + TTL。
        let ttl_ms = query_param(req.uri.query().unwrap_or_default(), "ttl_ms")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        state.blacklist.record_ban(ip, "admin", ttl_ms);
        plain(
            StatusCode::OK,
            &format!("blocked ip={ip} closed_long_connections={closed}\n"),
        )
    } else {
        //  审计 + 解封豁免:手工解封记审计,并在本节点开启解封豁免窗口(防抖)。
        state.blacklist.record_unban(ip, "admin");
        plain(StatusCode::OK, &format!("unblocked ip={ip}\n"))
    }
}

/// 业务作用：发布或撤销接口关闭事实，使新请求由统一接口守卫裁决。
async fn set_interface_disable(
    req: &AdminRequestParts,
    state: &AdminState,
    disabled: bool,
) -> Response<BoxBody> {
    let query = req.uri.query().unwrap_or_default();
    let Some(id) = query_param(query, "id") else {
        return plain(StatusCode::BAD_REQUEST, "missing id query parameter\n");
    };
    let cfg = state.snap.load().runtime_state.interface_disable.clone();
    if !cfg.enabled {
        return plain(StatusCode::CONFLICT, "interface disable disabled\n");
    }
    let result = if disabled {
        let value = match interface_disable_value(query, id) {
            Ok(value) => value,
            Err(msg) => return plain(StatusCode::BAD_REQUEST, msg),
        };
        state
            .dynamic_store
            .put(&cfg.collection, id, value.as_bytes())
            .await
    } else {
        state.dynamic_store.delete(&cfg.collection, id).await
    };
    if let Err(e) = result {
        tracing::warn!(id, error = %e, "admin interface disable store update failed");
        return plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            "interface disable store update failed\n",
        );
    }
    if let Err(e) = state
        .interface_disable
        .refresh_from_store(state.dynamic_store.as_ref(), &cfg.collection)
        .await
    {
        tracing::warn!(id, error = %e, "admin interface disable cache refresh failed");
        return plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            "interface disable cache refresh failed\n",
        );
    }
    if disabled {
        plain(StatusCode::OK, &format!("disabled id={id}\n"))
    } else {
        plain(StatusCode::OK, &format!("enabled id={id}\n"))
    }
}

/// 业务作用：构造包含过期边界的黑名单事实，供持久化存储与缓存使用同一字段合同。
fn blacklist_value(query: &str) -> Result<String, &'static str> {
    let Some(raw_ttl) = query_param(query, "ttl_ms") else {
        return Ok(r#"{"source":"admin"}"#.to_string());
    };
    let Ok(ttl_ms) = raw_ttl.parse::<u64>() else {
        return Err("invalid ttl_ms\n");
    };
    if ttl_ms == 0 {
        return Err("invalid ttl_ms\n");
    }
    let now_ms = unix_now_ms();
    let ttl_ms = ttl_ms.min(i64::MAX as u64) as i64;
    let expire_at_unix_ms = now_ms.saturating_add(ttl_ms);
    Ok(serde_json::json!({
        "source": "admin",
        "expire_at_unix_ms": expire_at_unix_ms,
    })
    .to_string())
}

/// 业务作用：构造接口关闭事实，保留操作范围和有效期供守卫解释。
fn interface_disable_value(query: &str, id: &str) -> Result<String, &'static str> {
    let Some(path) = query_param(query, "path") else {
        return Err("missing path query parameter\n");
    };
    let status = match query_param(query, "status") {
        Some(raw) => raw
            .parse::<u16>()
            .ok()
            .filter(|status| StatusCode::from_u16(*status).is_ok())
            .ok_or("invalid status\n")?,
        None => 503,
    };
    let methods = query_param(query, "methods")
        .map(|raw| {
            raw.split(',')
                .filter(|method| !method.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let body = query_param(query, "body").unwrap_or("disabled");
    let expire_at_unix_ms = match query_param(query, "ttl_ms") {
        Some(raw) => {
            let ttl_ms = raw.parse::<u64>().map_err(|_| "invalid ttl_ms\n")?;
            if ttl_ms == 0 {
                return Err("invalid ttl_ms\n");
            }
            Some(unix_now_ms().saturating_add(ttl_ms.min(i64::MAX as u64) as i64))
        }
        None => None,
    };
    Ok(serde_json::json!({
        "id": id,
        "enabled": true,
        "match": {
            "path": path,
            "methods": methods,
        },
        "response": {
            "status": status,
            "headers": {
                "content-type": "text/plain; charset=utf-8",
            },
            "body": body,
        },
        "expire_at_unix_ms": expire_at_unix_ms,
    })
    .to_string())
}

/// 业务作用：提供管理事实与过期判断使用的 Unix 毫秒时间，时钟异常时采用保守零值。
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

/// 业务作用：从管理请求查询串读取指定参数，不把整个查询串暴露到操作日志。
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key && !v.is_empty() {
            Some(v)
        } else {
            None
        }
    })
}

/// 业务作用：Prometheus label 值最小转义(反斜杠 / 双引号 / 换行):防 service 名里的特殊字符破坏 exposition 文本格式。
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

/// 业务作用：限定可选择匿名读的门户路径，不包含管理目录或任何写入口。
///
/// 参数说明：
/// - `path`：是规范化请求路径。
///
/// 返回：仅固定静态资源、目录与受限文档路径返回 true。
fn is_developer_portal_read_path(path: &str) -> bool {
    matches!(
        path,
        "/developer"
            | "/developer/"
            | "/developer/app.css"
            | "/developer/app.js"
            | "/api/developer/catalogs"
            | "/api/developer/products"
    ) || developer_catalog_id_from_openapi_path(path).is_some()
        || product_document_path(path, "/api/developer/products/").is_some()
}

/// 业务作用：识别始终要求 Routes/Read 的产品管理读面，避免公开门户开关放行私有目录。
///
/// 参数说明：
/// - `path`：为请求路径。
///
/// 返回：只有产品列表或固定文档层级为 true。
fn is_product_admin_read_path(path: &str) -> bool {
    path == "/api/products" || product_document_path(path, "/api/products/").is_some()
}

/// 业务作用：将固定产品文档路径绑定为三个有界身份，拒绝任意文件路径或多余层级。
///
/// 参数说明：
/// - `path`：为请求路径
/// - `prefix`：为调用入口固定前缀。
///
/// 返回：合法的产品、版本、文档身份；不匹配时为 None。
fn product_document_path<'a>(path: &'a str, prefix: &str) -> Option<(&'a str, &'a str, &'a str)> {
    let segments: Vec<_> = path.strip_prefix(prefix)?.split('/').collect();
    if segments.len() != 5 || segments[1] != "versions" || segments[3] != "documents" {
        return None;
    }
    for value in [segments[0], segments[2], segments[4]] {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return None;
        }
    }
    Some((segments[0], segments[2], segments[4]))
}

/// 业务作用：只从固定文档端点解析目录身份，避免任意路径被当作文件读取目标。
fn developer_catalog_id_from_openapi_path(path: &str) -> Option<&str> {
    path.strip_prefix("/api/developer/catalogs/")?
        .strip_suffix("/openapi")
        .filter(|id| {
            !id.is_empty()
                && !id.contains('/')
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// 业务作用：按调用入口的认证结果返回冻结门户资源，私有版本不与匿名缓存共用读面。
///
/// 参数说明：
/// - `request`：为请求 head
/// - `state`：为已发布控制面
/// - `privileged`：只来自认证分派器。
///
/// 返回：可见资源响应；关闭门户、不存在或不可见时统一返回 None。
fn developer_portal_read(
    request: &AdminRequestParts,
    state: &AdminState,
    privileged: bool,
) -> Option<Response<BoxBody>> {
    let snapshot = state.snap.load();
    let portal = &snapshot.developer_portal;
    if !portal.enabled() {
        return None;
    }
    match request.uri.path() {
        "/developer" | "/developer/" => Some(admin_ui_asset(
            "text/html; charset=utf-8",
            Bytes::from_static(include_bytes!("../portal/assets/portal.html")),
        )),
        "/developer/app.css" => Some(admin_ui_asset(
            "text/css; charset=utf-8",
            Bytes::from_static(include_bytes!("../portal/assets/portal.css")),
        )),
        "/developer/app.js" => Some(admin_ui_asset(
            "application/javascript; charset=utf-8",
            Bytes::from_static(include_bytes!("../portal/assets/portal.js")),
        )),
        "/api/developer/catalogs" => Some(json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "catalogs": portal.catalog_json()
            }),
        )),
        "/api/developer/products" | "/api/products" => {
            let mut response = json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "products": portal.products.json(privileged)
                }),
            );
            response.headers_mut().insert(
                hyper::header::CACHE_CONTROL,
                hyper::header::HeaderValue::from_static("private, no-store"),
            );
            Some(response)
        }
        path => {
            if let Some((product, version, document)) =
                product_document_path(path, "/api/developer/products/")
                    .or_else(|| product_document_path(path, "/api/products/"))
            {
                let document = portal
                    .products
                    .document(product, version, document, privileged)?;
                return Some(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(hyper::header::CONTENT_TYPE, document.content_type)
                        .header(hyper::header::CACHE_CONTROL, "private, no-store")
                        .header("x-content-type-options", "nosniff")
                        .header(
                            "content-security-policy",
                            "default-src 'none'; sandbox; frame-ancestors 'none'",
                        )
                        .body(full_body(document.body.clone()))
                        .expect("product document response"),
                );
            }
            let id = developer_catalog_id_from_openapi_path(path)?;
            let catalog = portal.catalog(id)?;
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, catalog.content_type)
                    .header(hyper::header::CACHE_CONTROL, "private, no-store")
                    .header("x-content-type-options", "nosniff")
                    .header(
                        "content-security-policy",
                        "default-src 'none'; sandbox; frame-ancestors 'none'",
                    )
                    .body(full_body(catalog.document.clone()))
                    .expect("build developer OpenAPI response"),
            )
        }
    }
}

/// 业务作用：接收门户 key 申请。该入口使用独立 Bearer token，只写 `pending` 记录，绝不在请求中
/// 创建或返回 API key。单 frame body 直接复用 Hyper `Bytes`；多 frame 才做一次有界合并。
async fn submit_developer_key_application(
    req: AdminRequest,
    state: Arc<AdminState>,
) -> Response<BoxBody> {
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let snapshot = state.snap.load_full();
    let portal = snapshot.developer_portal.clone();
    let Some(application_cfg) = portal.key_applications() else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let (parts, body) = req.into_parts();
    if !bearer_authorization_matches(&parts.headers, application_cfg.authorization_token.as_ref()) {
        state
            .metrics
            .inc_developer_application(DeveloperApplicationMetric::Rejected);
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                hyper::header::WWW_AUTHENTICATE,
                "Bearer realm=\"developer-portal\"",
            )
            .body(full_body(Bytes::from_static(b"unauthorized")))
            .expect("build developer portal authentication response");
    }
    if let Some(response) = reject_untrusted_admin_browser_origin(&parts, &state) {
        state
            .metrics
            .inc_developer_application(DeveloperApplicationMetric::Rejected);
        return response;
    }
    let json_content_type = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !json_content_type {
        state
            .metrics
            .inc_developer_application(DeveloperApplicationMetric::Rejected);
        return json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            serde_json::json!({
                "ok": false,
                "error": "Content-Type must be application/json"
            }),
        );
    }
    let bytes = match collect_bounded_admin_body(&parts, body, application_cfg.max_body_bytes).await
    {
        Ok(bytes) => bytes,
        Err(response) => {
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Rejected);
            return *response;
        }
    };
    let application = match portal.parse_application(bytes.as_ref()) {
        Ok(application) => application,
        Err(error) => {
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Rejected);
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string()
                }),
            );
        }
    };
    let application_id_input = format!("{}\0{}", application.catalog_id, application.applicant_id);
    let application_id = nasa::crypto::sha256(&application_id_input);
    let submitted_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let record = serde_json::json!({
        "application_id": application_id,
        "status": "pending",
        "catalog_id": application.catalog_id,
        "applicant_id": application.applicant_id,
        "display_name": application.display_name,
        "requested_plan": application.requested_plan,
        "submitted_at_ms": submitted_at_ms,
    });
    let encoded = match serde_json::to_vec(&record) {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::error!(%error, "serialize developer key application failed");
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Error);
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "ok": false,
                    "error": "cannot serialize application"
                }),
            );
        }
    };
    let admission = state
        .dynamic_store
        .put_if_capacity(
            application_cfg.collection.as_ref(),
            &application_id,
            encoded.as_slice(),
            application_cfg.max_pending,
        )
        .await;
    match admission {
        Ok(crate::runtime::state::StoreCapacityOutcome::Stored) => {}
        Ok(crate::runtime::state::StoreCapacityOutcome::CapacityReached) => {
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Rejected);
            return json(
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({
                    "ok": false,
                    "error": "pending application capacity reached"
                }),
            );
        }
        Err(error) => {
            tracing::error!(%error, "persist developer key application failed");
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Error);
            return json(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "ok": false,
                    "error": "application store unavailable"
                }),
            );
        }
    }
    state
        .metrics
        .inc_developer_application(DeveloperApplicationMetric::Accepted);
    tracing::info!(application_id = %application_id, "developer key application accepted");
    json(
        StatusCode::ACCEPTED,
        serde_json::json!({
            "ok": true,
            "application_id": application_id,
            "status": "pending",
        }),
    )
}

/// 业务作用：按固定白名单提供管理页面资源，不将请求路径映射为任意本地文件。
fn admin_ui_asset(content_type: &'static str, body: Bytes) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .header(
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        .body(full_body(body))
        .expect("build embedded admin UI asset")
}

/// 业务作用：纯文本响应助手(管理面自产短路应答)。
fn plain(status: StatusCode, body: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(body.to_owned())))
        .expect("build admin response")
}

/// 业务作用：JSON 响应助手。
///
/// 参数说明：
/// - `status`: HTTP 状态码。
/// - `value`: 可序列化为 JSON 的响应体。
fn json(status: StatusCode, value: serde_json::Value) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(value.to_string())))
        .expect("build admin json response")
}
