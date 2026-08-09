//! 管理 / 观测面(架构规范 §14 / §24)。
//!
//! 与数据面【端口隔离】:默认只绑内网 `127.0.0.1:18080`,承载健康 / 就绪端点(本增量),
//! 以及后续的 `/metrics`(V2-B)、admin API / Web UI(V4/V5)。**控制面挂了不影响数据面转发**(§14.1)。
//!
//! 当前管理面优先提供部署所需的健康、就绪与指标端点：
//! - `GET /healthz`:liveness,进程活着即 200(不看依赖),供容器 / K8s 判是否重启。
//! - `GET /readyz`:readiness,配置已加载且数据面监听就绪 → 200,否则 503(供前置 LB / K8s 判是否分流)。

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use http::request::Parts as AdminRequestParts;
use http_body_util::BodyExt;
use hyper::{Method, Response, StatusCode};
use nasa::web::{Request as AdminRequest, Router, State};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::auth::{basic_authorization_matches, bearer_authorization_matches, escape_header_quote};
use crate::config::model::{AdminAction, AdminResource};
use crate::config::{load_snapshot, GatewaySnapshot};
use crate::config_history::ConfigHistory;
use crate::conn_registry::ConnectionRegistry;
use crate::metrics::{DeveloperApplicationMetric, Metrics};
use crate::runtime_state::{DynamicStore, SwappableDynamicStore};
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
    /// 参数说明：无。
    ///
    /// 返回：仅独立 admin 与 all-in-one 返回 true；data/sidecar 均保持最小权限。
    fn full_control_plane(self) -> bool {
        matches!(self, Self::Admin | Self::AllInOne)
    }

    /// 业务作用：判断 readiness 是否必须同时检查数据面 listener 与关键上游。
    ///
    /// 参数说明：无。
    ///
    /// 返回：data、sidecar、all-in-one 返回 true，纯 admin 返回 false。
    fn runs_data(self) -> bool {
        matches!(self, Self::Data | Self::Sidecar | Self::AllInOne)
    }
}

/// 管理面共享状态:只读引用数据面的配置快照 + 就绪标志(不持有任何数据面连接)。
pub struct AdminState {
    /// CLI 选择的部署平面，启动后固定，热更不能扩大控制面权限。
    mode: AdminPlaneMode,
    /// 与数据面共享的同一份原子配置快照(用于 /readyz 报告当前版本,后续 admin 读配置)。
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    /// 本地 bootstrap 配置路径,供 `/admin/config/dry-run` 做只读候选快照构建。
    cfg_path: PathBuf,
    /// 配置 reload 历史与本地 rollback 归档。
    config_history: ConfigHistory,
    /// 数据面是否已就绪(监听已绑定、可接流量);停机时置 false → /readyz 转 503,供 LB 摘流(§24)。
    ready: Arc<AtomicBool>,
    /// V10 xDS require_xds 独立启动门与低基数状态；未启用 xDS 时为 None。
    #[cfg(feature = "xds-client")]
    xds_status: Option<Arc<crate::xds::XdsStatus>>,
    metrics: Arc<Metrics>,
    /// 长连接注册表(§6.1 / L2):/metrics 据此出 gw_long_connections 低基数指标。
    conn_registry: Arc<ConnectionRegistry>,
    /// V8:边缘订阅索引(仅 /metrics 渲染读取)。启动期由 main 注入一次;admin-only
    /// 进程没有数据面,保持未注入即不渲染 edge gauge。
    #[cfg(feature = "grpc-edge")]
    edge_hub: std::sync::OnceLock<Arc<crate::edge_hub::EdgeHub>>,
    /// 集群中继运行时；仅供 `/metrics` 渲染读取，单机部署保持未注入。
    #[cfg(feature = "grpc-edge")]
    edge_relay: std::sync::OnceLock<Arc<arc_swap::ArcSwapOption<crate::edge_relay::EdgeRelay>>>,
    /// Redis Pub/Sub 集群总线观测；配置保证与 relay 互斥。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_redis_bus: std::sync::OnceLock<Arc<crate::edge_redis_bus::EdgeRedisBus>>,
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_redis_stream: std::sync::OnceLock<Arc<crate::edge_redis_bus::EdgeRedisStreamBus>>,
    /// 可选 SessionDirectory 指路条；仅供 `/metrics` 渲染，`session_registry=none` 时未注入。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    edge_directory: std::sync::OnceLock<Arc<crate::edge_directory::SessionDirectory>>,
    /// P0-3:集群发布登记(进程内有界,重启归零;事实源仍是 Nacos + 成员表)。
    rollouts: RolloutRegistry,
    /// 主动健康探测器(§5.1 / N2):/readyz 据此判「critical 服务是否还有主动健康的实例」,与数据面选实例保持一致。
    active_health: Arc<crate::health::ActiveHealthChecker>,
    /// 运行态动态事实源。admin 黑名单写入走同一 DynamicStore,避免绕过 Redis/file 后端。
    dynamic_store: Arc<SwappableDynamicStore>,
    /// 本节点黑名单缓存。admin 写入成功后立即刷新,无需等待周期任务。
    blacklist: Arc<crate::blacklist::BlacklistCache>,
    /// 本节点动态接口禁用缓存。admin 写入成功后立即刷新,无需等待周期任务。
    interface_disable: Arc<crate::guard::DynamicInterfaceGuardCache>,
    /// V5 HTTP cache L2 与 generation 失效总线。
    http_cache: Arc<crate::http_cache::HttpCacheRuntime>,
    /// 管理写操作 append-only HMAC 审计与外部持久 sink。
    audit: crate::admin_audit::AdminAuditLog,
}

/// 管理面需要写入/刷新的一组运行态依赖。
pub struct AdminRuntimeState {
    /// CLI 选择的部署平面；作为启动期依赖与其余常驻管理资源一起传入。
    pub mode: AdminPlaneMode,
    /// 配置版本历史与本地归档。
    pub config_history: ConfigHistory,
    /// 运行态事实源,用于 admin 写入黑名单和动态接口禁用。
    pub dynamic_store: Arc<SwappableDynamicStore>,
    /// 本节点黑名单缓存。
    pub blacklist: Arc<crate::blacklist::BlacklistCache>,
    /// 本节点动态接口禁用缓存。
    pub interface_disable: Arc<crate::guard::DynamicInterfaceGuardCache>,
    /// HTTP response cache runtime，供 route 级 PURGE。
    pub http_cache: Arc<crate::http_cache::HttpCacheRuntime>,
    /// 管理操作持久审计器。
    pub audit: crate::admin_audit::AdminAuditLog,
    /// V10 xDS EDS 客户端状态；只读挂接到 readiness/metrics/admin status。
    #[cfg(feature = "xds-client")]
    pub xds_status: Option<Arc<crate::xds::XdsStatus>>,
}

impl AdminState {
    /// V8:挂接边缘订阅索引;仅 /metrics 渲染读取。一次性注入,后到者忽略。
    #[cfg(feature = "grpc-edge")]
    pub fn attach_edge_hub(&self, hub: Arc<crate::edge_hub::EdgeHub>) {
        let _ = self.edge_hub.set(hub);
    }

    /// 业务作用：把数据面 relay generation slot 挂到管理面，使 metrics 始终读取热换代后的当前代。
    ///
    /// 参数说明：`relay` 是 Proxy 与 reload 共同持有的原子 relay slot。
    ///
    /// 返回：无返回值；只接受首次注入，重复调用不会替换已共享的 slot。
    #[cfg(feature = "grpc-edge")]
    pub fn attach_edge_relay_slot(
        &self,
        relay: Arc<arc_swap::ArcSwapOption<crate::edge_relay::EdgeRelay>>,
    ) {
        let _ = self.edge_relay.set(relay);
    }

    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_redis_bus(&self, bus: Arc<crate::edge_redis_bus::EdgeRedisBus>) {
        let _ = self.edge_redis_bus.set(bus);
    }

    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_redis_stream(&self, bus: Arc<crate::edge_redis_bus::EdgeRedisStreamBus>) {
        let _ = self.edge_redis_stream.set(bus);
    }

    /// 业务作用：挂接仅供 `/metrics` 读取的 SessionDirectory 指路条，保持运行时身份唯一。
    ///
    /// 参数说明：`directory` 是已完成连接与配置校验的进程级目录句柄。
    ///
    /// 返回：无；只接受首次注入，后到句柄忽略。
    #[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
    pub fn attach_edge_directory(&self, directory: Arc<crate::edge_directory::SessionDirectory>) {
        let _ = self.edge_directory.set(directory);
    }

    /// 业务作用：构造管理面共享状态，并把 listener、关键上游与可选 xDS readiness 事实接到同一读面。
    ///
    /// 参数说明：`snap`/`cfg_path` 是当前配置；`ready`、`active_health` 和
    /// `runtime_state.xds_status` 共同形成 readiness；其余参数是常驻管理观测依赖。
    ///
    /// 返回：所有句柄封装成共享 `AdminState`；不打开 socket、不执行外部写操作。
    pub fn new(
        snap: Arc<ArcSwap<GatewaySnapshot>>,
        cfg_path: PathBuf,
        ready: Arc<AtomicBool>,
        metrics: Arc<Metrics>,
        conn_registry: Arc<ConnectionRegistry>,
        active_health: Arc<crate::health::ActiveHealthChecker>,
        runtime_state: AdminRuntimeState,
    ) -> Arc<Self> {
        Arc::new(Self {
            mode: runtime_state.mode,
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
            config_history: runtime_state.config_history,
            ready,
            #[cfg(feature = "xds-client")]
            xds_status: runtime_state.xds_status,
            metrics,
            conn_registry,
            active_health,
            dynamic_store: runtime_state.dynamic_store,
            blacklist: runtime_state.blacklist,
            interface_disable: runtime_state.interface_disable,
            http_cache: runtime_state.http_cache,
            audit: runtime_state.audit,
        })
    }
}

/// 业务作用：运行一个可代际停止的管理面 accept generation，单连接错误不拖垮数据面。
///
/// 参数说明：`listener` 是 prepare 阶段已绑定 socket；`state` 是共享管理状态；`shutdown` 在候选发布后关闭旧代。
///
/// 返回：监听器正常 drain 或服务错误后返回；服务错误只记录告警，不触发进程 panic/abort。
pub async fn serve_until(
    listener: TcpListener,
    state: Arc<AdminState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let local = listener.local_addr().ok();
    info!(?local, "admin plane listening (nasa::web + axum)");
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

/// 未迁到 MVC 注解的管理 API fallback；仍复用统一 dispatch 安全前置链。
///
/// # 参数
/// - `state`: axum 注入的进程级管理状态。
/// - `req`: axum 已解析的管理 HTTP 请求。
async fn legacy_admin_handler(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// `nasa::web` 编译期注册的管理 UI 入口；实际认证/RBAC 仍统一走 dispatch。
///
/// # 参数
/// - `state`: MVC router 注入的管理状态。
/// - `req`: UI 文档请求。
#[nasa::web::get_mapping(path = "/", produces = "text/html; charset=utf-8")]
pub async fn admin_ui_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// `nasa::web` 注册的 UI 样式资产。
///
/// # 参数
/// - `state`: MVC router 注入的管理状态。
/// - `req`: CSS 请求。
#[nasa::web::get_mapping(path = "/ui/app.css", produces = "text/css; charset=utf-8")]
pub async fn admin_ui_css_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// `nasa::web` 注册的无框架 UI 脚本；DOM 写入全部使用 textContent，避免服务端数据触发 XSS。
///
/// # 参数
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

/// `nasa::web` 注册的 UI 聚合读模型；只读当前本地快照/运行态，不触发远端写操作。
///
/// # 参数
/// - `state`: MVC router 注入的管理状态。
/// - `req`: dashboard API 请求。
#[nasa::web::get_mapping(path = "/api/dashboard", produces = "application/json")]
pub async fn admin_dashboard_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// `nasa::web` 注册的候选 gateway.yml dry-run；body 有显式上限且绝不覆盖真实配置。
///
/// # 参数
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

/// P0-2:读取当前主 YML(带 `ETag`),供 Console 编辑器载入并作为后续 CAS 发布的基线。
///
/// # 参数
/// - `state`: MVC router 注入的管理状态。
/// - `req`: 只读请求(无 body)。
#[nasa::web::get_mapping(path = "/api/config/current", produces = "application/json")]
pub async fn admin_config_current_read_mvc(
    State(state): State<Arc<AdminState>>,
    req: AdminRequest,
) -> Response<axum::body::Body> {
    dispatch(req, state).await.map(axum::body::Body::new)
}

/// P0-2:发布 Console 编辑后的主 YML(`If-Match` CAS + 候选校验 + 确认生效)。
///
/// # 参数
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

/// 管理面统一安全分发：认证 → Origin → 平面边界 → RBAC → 审计 → handler；未知路径 404。
async fn dispatch(req: AdminRequest, state: Arc<AdminState>) -> Response<BoxBody> {
    if req.method() == Method::POST && req.uri().path() == "/api/config/dry-run" {
        return dry_run_submitted_config(req, state).await;
    }
    if req.method() == Method::PUT && req.uri().path() == "/api/config/current" {
        return publish_current_config(req, state).await;
    }
    if req.method() == Method::POST && req.uri().path() == "/api/developer/key-applications" {
        return submit_developer_key_application(req, state).await;
    }
    if req.method() == Method::GET
        && state.mode.full_control_plane()
        && state.snap.load().developer_portal.public_catalog()
        && is_developer_portal_read_path(req.uri().path())
    {
        let (request, _body) = req.into_parts();
        return developer_portal_read(&request, &state)
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
                serde_json::json!({"ok": false, "error": "forbidden"}),
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
                serde_json::json!({"ok": false, "error": "audit sink unavailable; action not executed"}),
            );
        }
    }
    let resp = match (&request.method, request.uri.path()) {
        (&Method::GET, "/") => admin_ui_asset(
            "text/html; charset=utf-8",
            Bytes::from_static(include_bytes!("../admin_ui.html")),
        ),
        (&Method::GET, "/ui/app.css") => admin_ui_asset(
            "text/css; charset=utf-8",
            Bytes::from_static(include_bytes!("../admin_ui.css")),
        ),
        (&Method::GET, "/ui/app.js") => admin_ui_asset(
            "application/javascript; charset=utf-8",
            Bytes::from_static(include_bytes!("../admin_ui.js")),
        ),
        // liveness:进程活着即 200(不看依赖),供容器 / K8s 判是否重启。
        (&Method::GET, "/healthz") => plain(StatusCode::OK, "ok\n"),
        // readiness:配置已加载 + 数据面监听就绪才 200,否则 503(前置 LB 据此挂/摘流量)。
        (&Method::GET, "/readyz") => readyz(&state),
        (&Method::GET, "/metrics") => metrics(&state),
        (&Method::GET, "/admin/config/status") => config_status(&state),
        #[cfg(feature = "xds-client")]
        (&Method::GET, "/admin/xds/status") => xds_status(&state),
        (&Method::GET, "/api/dashboard") => dashboard(&state),
        (&Method::POST, "/admin/reload") => reload_config(),
        // 只读发现视图(§34 V4):列出上游服务/实例/来源,供管理面展示集群拓扑。
        (&Method::GET, "/admin/upstreams") => {
            let snap = state.snap.load();
            let route_refs = upstream_route_refs(&snap);
            json(
                StatusCode::OK,
                snap.upstreams.service_view_json(&route_refs),
            )
        }
        (&Method::GET, "/admin/config/dry-run") => dry_run_config(&state),
        (&Method::GET, "/api/config/current") => read_current_config(&state).await,
        (&Method::GET, "/admin/config/history") => config_history(&state),
        (&Method::POST, "/admin/config/rollback") => rollback_config(&request, &state).await,
        // 集群配置版本收敛视图(§14.2):从 Nacos 反查本网关成员,聚合各节点已注册的 gateway.version。
        (&Method::GET, "/admin/cluster/consistency") => cluster_consistency(&state).await,
        (&Method::GET, "/admin/cluster/metrics") => cluster_metrics(&state).await,
        (&Method::GET, "/api/cluster/rollout") => cluster_rollout_status(&state).await,
        (&Method::POST, "/admin/long-connections/close") => {
            close_long_connections(&request, &state)
        }
        (&Method::PUT, "/admin/blacklist") | (&Method::POST, "/admin/blacklist") => {
            set_blacklist_ip(&request, &state, true).await
        }
        (&Method::DELETE, "/admin/blacklist") => set_blacklist_ip(&request, &state, false).await,
        // §18 黑名单 ban/unban 审计流(本节点最近事件)。
        (&Method::GET, "/admin/blacklist/audit") => json(
            StatusCode::OK,
            serde_json::json!({"ok": true, "events": state.blacklist.audit_snapshot()}),
        ),
        (&Method::GET, "/api/audit") => json(
            StatusCode::OK,
            serde_json::json!({"ok": true, "events": state.audit.snapshot().await}),
        ),
        (&Method::PUT, "/admin/interface-disable")
        | (&Method::POST, "/admin/interface-disable") => {
            set_interface_disable(&request, &state, true).await
        }
        (&Method::DELETE, "/admin/interface-disable") => {
            set_interface_disable(&request, &state, false).await
        }
        // V5 route-wide PURGE：generation 失效避免 Redis SCAN/批量 DEL；需要 admin auth/CSRF 前置。
        (&Method::DELETE, "/admin/cache") => purge_http_cache(&request, &state).await,
        (&Method::GET, path) if is_developer_portal_read_path(path) => {
            developer_portal_read(&request, &state)
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

/// 只有可能改变配置/运行态的动作进入 fail-closed 审计；read/dry-run 不阻断控制面查询。
///
/// # 参数
/// - `action`: RBAC 风险动作。
fn is_mutating_action(action: AdminAction) -> bool {
    matches!(
        action,
        AdminAction::Write | AdminAction::EmergencyKill | AdminAction::Rollback
    )
}

/// 写一条不含敏感原文的管理审计；query 仅记录 SHA-256，便于关联而不泄漏参数。
///
/// # 参数
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
        .record(crate::admin_audit::AdminAuditInput {
            principal: identity.principal_id.clone(),
            method: req.method.as_str(),
            path: req.uri.path(),
            resource,
            action,
            phase,
            status,
            query_sha256,
            config_version,
        })
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
    /// 判断当前请求主体是否允许给定资源动作。
    ///
    /// # 参数
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
/// 参数说明：`method`/`path` 是不含 query 的规范请求目标。
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
        (&Method::GET, "/api/dashboard") => Some((AdminResource::Cluster, AdminAction::Read)),
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
        (&Method::PUT, "/api/config/current") => Some((AdminResource::Config, AdminAction::Write)),
        (&Method::GET, "/admin/config/history") => Some((AdminResource::Config, AdminAction::Read)),
        (&Method::POST, "/admin/config/rollback") => {
            Some((AdminResource::Config, AdminAction::Rollback))
        }
        (&Method::GET, "/admin/cluster/consistency") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::GET, "/admin/cluster/metrics") => {
            Some((AdminResource::Cluster, AdminAction::Read))
        }
        (&Method::POST, "/admin/long-connections/close") => {
            Some((AdminResource::Connections, AdminAction::EmergencyKill))
        }
        (&Method::GET, "/admin/blacklist/audit") => Some((AdminResource::Acl, AdminAction::Read)),
        (&Method::GET, "/api/audit") => Some((AdminResource::Audit, AdminAction::Read)),
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
        (&Method::GET, path) if is_developer_portal_read_path(path) => {
            Some((AdminResource::Routes, AdminAction::Read))
        }
        _ => None,
    }
}

/// 业务作用：判断 data 模式的最小 admin allowlist；默认拒绝能改运行态或配置事实源的端点。
///
/// 参数说明：`method`/`path` 是已由 HTTP parser 分离 query 的规范请求目标。
///
/// 返回：数据/sidecar 节点允许访问时返回 true；其它管理能力返回 false。
fn data_mode_path_allowed(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/healthz")
            | (&Method::GET, "/readyz")
            | (&Method::GET, "/metrics")
            | (&Method::GET, "/admin/config/status")
            | (&Method::GET, "/admin/xds/status")
            | (&Method::POST, "/admin/reload")
    )
}

/// 业务作用：返回本节点当前配置与部署模式；只暴露低基数摘要，不返回密钥或完整配置原文。
///
/// 参数说明：`state` 是当前节点管理面共享状态。
///
/// 返回：包含部署模式和低基数 Snapshot 摘要的 JSON 200 响应。
fn config_status(state: &AdminState) -> Response<BoxBody> {
    let snapshot = state.snap.load();
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "mode": admin_mode_name(state.mode),
            "ready": state.ready.load(Ordering::Acquire),
            "summary": snapshot.summary(),
        }),
    )
}

/// 业务作用：输出本节点 ADS/EDS 权威状态，供发布门区分首次未同步、active 与 LKG degraded。
///
/// 参数说明：`state` 提供可选 xDS 运行时句柄。
///
/// 返回：启用 xDS 时返回低敏 version/nonce、错误摘要和累计计数；未启用时返回 404。
#[cfg(feature = "xds-client")]
fn xds_status(state: &AdminState) -> Response<BoxBody> {
    let Some(status) = &state.xds_status else {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    };
    let status = status.snapshot();
    let state_name = match status.state {
        crate::xds::XdsConnectionState::Disconnected => "disconnected",
        crate::xds::XdsConnectionState::Syncing => "syncing",
        crate::xds::XdsConnectionState::Active => "active",
        crate::xds::XdsConnectionState::Degraded => "degraded",
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

/// 构建 UI 首屏聚合读模型；集合来自当前快照/常驻 health/history，不触发远端写操作。
///
/// # 参数
/// - `state`: 管理面共享状态。
fn dashboard(state: &AdminState) -> Response<BoxBody> {
    let summary = state.snap.load().summary();
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
    json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "mode": admin_mode_name(state.mode),
            "ready": state.ready.load(Ordering::Acquire),
            "summary": summary,
            "health": health,
            "history": state.config_history.snapshot(),
        }),
    )
}

/// 业务作用：返回固定部署模式名称，供 status/dashboard 使用同一协议值。
///
/// 参数说明：`mode` 是启动时确定且热更不可改变的管理平面模式。
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

/// 唤醒唯一 reload worker；本端点不直接 build/swap，保持所有触发源串行化不变式。
fn reload_config() -> Response<BoxBody> {
    // SAFETY: 只向本进程发送 SIGHUP，不解引用裸指针；signal handler 仅向 bounded channel 投事件。
    let rc = unsafe { libc::kill(std::process::id() as i32, libc::SIGHUP) };
    if rc == 0 {
        json(
            StatusCode::ACCEPTED,
            serde_json::json!({"ok": true, "status": "reload scheduled"}),
        )
    } else {
        json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "failed to signal reload worker"}),
        )
    }
}

/// `DELETE /admin/cache?proxy=<id>&route=<id>` 主动失效一条 route 的全部 L1/L2 entry。
///
/// 只 clone 当前 `Arc<HttpCachePolicy>` 后就释放 ArcSwap guard，再执行 Redis I/O；不能让控制面
/// await 长时间钉住整个旧配置快照。
async fn purge_http_cache(req: &AdminRequestParts, state: &AdminState) -> Response<BoxBody> {
    let query = req.uri.query().unwrap_or_default();
    let Some(proxy_id) = query_param(query, "proxy") else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "missing proxy"}),
        );
    };
    let Some(route_id) = query_param(query, "route") else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "missing route"}),
        );
    };
    if proxy_id.len() > 256 || route_id.len() > 256 {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "proxy/route id exceeds 256 bytes"}),
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
            serde_json::json!({"ok": false, "error": "proxy/route cache not found"}),
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
                serde_json::json!({"ok": false, "error": error.to_string()}),
            )
        }
    }
}

/// 返回本节点配置 reload 审计历史。
///
/// # 参数
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

/// 汇总 service -> proxy/route 引用关系,供 `/admin/upstreams` 展示。
///
/// # 参数
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

/// 回滚到已归档配置版本。
///
/// 两条路径:
/// - **本地文件源**:三份归档先有界校验、逐文件原子替换；进程内事务锁阻止 reload 观察中间态，
///   再由 SIGHUP 唤醒唯一 worker 执行 build-then-swap。跨进程/掉电原子性仍需版本目录指针。
/// - **Nacos 配置源**(§14.2/§14.3):把归档版本 CAS 写回 Nacos dataId(带并发保护),集群经 config watch 收敛;
///   见 [`rollback_config_nacos`]。
///
/// # 参数
/// - `req`: 管理面请求,使用 `version` query 参数(可选 `base_version` 见 Nacos 路径)。
/// - `state`: 管理面共享状态。
async fn rollback_config(req: &AdminRequestParts, state: &AdminState) -> Response<BoxBody> {
    let Some(raw_version) = query_param(req.uri.query().unwrap_or_default(), "version") else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "missing version"}),
        );
    };
    let Ok(target_version) = raw_version.parse::<u64>() else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "invalid version"}),
        );
    };
    if state.snap.load().config_source.nacos.enabled {
        // Nacos 配置源:走 CAS 写回远端事实源,不直接改本地文件(否则会被下次 watch 覆盖、且不集群生效)。
        return rollback_config_nacos(state, target_version).await;
    }
    let current_version = state.snap.load().version;
    let history = state.config_history.clone();
    let cfg_path = state.cfg_path.clone();
    let restore =
        tokio::task::spawn_blocking(move || history.restore_to(target_version, &cfg_path)).await;
    let restore = match restore {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!("rollback file worker failed: {error}")),
    };
    if let Err(e) = restore {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({"ok": false, "error": e.to_string()}),
        );
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
    let rc = unsafe { libc::kill(std::process::id() as i32, libc::SIGHUP) };
    if rc != 0 {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "failed to signal reload worker"}),
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

/// Nacos 配置源的 CAS 回滚(§14.2/§14.3)。
///
/// 与本地文件回滚不同,Nacos 是集群统一配置事实源:必须把归档版本【CAS 写回 Nacos】并靠 config watch 收敛,
/// 直接改本地物化文件会被下次 watch 覆盖、且不集群生效。策略(兼顾并发安全与「不伪造多文件事务」):
///
/// 1. 读归档【目标版本 N】三文件;读归档【当前线上版本 M】(= 本节点快照版本)作为并发基线。
/// 2. `bundle_data_id` 非空时,拉取单 JSON bundle,核对三份原文后用一次 `publish_cas` 原子写回
///    完整目标配置;watcher 只会看到旧 bundle 或新 bundle。
/// 3. 旧三 dataId 兼容模式逐个拉取并判漂移;只允许 0/1 个 dataId 变化,多于一个时返回 409,
///    **不能用多次单 dataId CAS 冒充事务**(watch 会瞬时读到新旧混合配置,§14.3 边界)。
/// 4. 远端偏离版本 M → 409 rebase;CAS 成功 → 202;CAS 失配 → 409;网络错 → 502。
///
/// # 参数
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
                serde_json::json!({"ok": false, "error": e.to_string()}),
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
            serde_json::json!({"ok": false, "error": e.to_string()}),
        ),
    }
}

/// 把 Nacos I/O 卸载到【专用 current-thread 运行时线程】执行,通过 oneshot 回送结果。
///
/// WHY:nacos-sdk 的 future 不保证 `Send`(与 §reload 配置 watch 同因),而 admin 连接在多线程 runtime 上经
/// `tokio::spawn` 处理(要求 `Send`)。故把 connect/fetch/publish 放到独立线程的 current-thread runtime,
/// 只把【Send 的判定结果】送回 admin 上下文,保持连接 future 的 Send 约束。回滚是低频控制动作,按次起线程可接受。
///
/// # 参数
/// - `nacos`: `config_source.nacos` 配置(含地址/鉴权/dataId/group)。
/// - `target_version`: 目标归档版本号,写入原子 bundle 的审计版本。
/// - `target`: 目标归档版本三文件原文。
/// - `baseline`: 当前线上版本三文件原文,用于并发漂移判定。
/// - `allow_initial_publish`: 原子 bundle 不存在时是否允许首次发布；仅集群发布入口可开启。
async fn run_nacos_rollback_offloaded(
    nacos: crate::config::model::NacosConfigSourceCfg,
    target_version: u64,
    target: crate::config_history::ArchivedDocs,
    baseline: crate::config_history::ArchivedDocs,
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

/// 在 Nacos 上执行一次 CAS 回滚判定与发布(运行在专用 current-thread runtime)。
///
/// # 参数
/// - `nacos`: `config_source.nacos` 配置。
/// - `target_version`: 目标归档版本号。
/// - `target`: 目标归档版本三文件原文。
/// - `baseline`: 当前线上版本三文件原文(并发漂移基线)。
/// - `allow_initial_publish`: 缺少原子 bundle 时是否允许初始化。
async fn nacos_rollback_once(
    nacos: &crate::config::model::NacosConfigSourceCfg,
    target_version: u64,
    target: &crate::config_history::ArchivedDocs,
    baseline: &crate::config_history::ArchivedDocs,
    allow_initial_publish: bool,
) -> anyhow::Result<NacosRollbackOutcome> {
    let props = crate::reload::nacos_config_props(nacos);
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
            let content = crate::reload::encode_atomic_nacos_bundle(
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
        let remote = crate::reload::parse_atomic_nacos_bundle(&remote_content)
            .map_err(|e| anyhow::anyhow!("parse remote atomic bundle {data_id} failed: {e:#}"))?;

        // 先识别已发布目标,使管理端在 CAS 成功但响应丢失后可安全重试。
        if atomic_bundle_matches_docs(&remote, target) {
            return Ok(NacosRollbackOutcome::AlreadyMatches);
        }
        // 目标尚未发布时,远端必须仍等于本节点线上归档基线;否则有人先改了。
        if !atomic_bundle_matches_docs(&remote, baseline) {
            return Ok(NacosRollbackOutcome::Drifted(vec![data_id.to_string()]));
        }

        let content = crate::reload::encode_atomic_nacos_bundle(
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
    // 判定(纯逻辑,已单测)与发布(I/O)分离:漂移/多文件在写任何东西【之前】就拒绝。
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

/// 原子 bundle 的三份配置原文是否与某归档版本完全一致。
fn atomic_bundle_matches_docs(
    bundle: &crate::reload::AtomicNacosConfigBundle,
    docs: &crate::config_history::ArchivedDocs,
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

/// 纯判定:据三方内容对照决定回滚动作(便于单测,不触碰网络)。
///
/// 规则:任一 dataId【远端 ≠ 基线】→ 漂移(前端 rebase);否则【远端 ≠ 目标】者为需写回;
/// 需写回 0 / 1 / 多 → 幂等 / 单 dataId CAS / 拒绝多文件伪事务(§14.3 边界)。
///
/// # 参数
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

/// 从 Nacos 成员实例聚合集群配置版本收敛情况(纯逻辑,便于单测)。
///
/// 收敛判定只统计 **enabled 且带 `gateway.version`** 的成员(手动下线 / 无版本元数据的不参与),
/// 避免一个已摘除节点永远拖着「未收敛」。
///
/// # 参数
/// - `instances`: Nacos `discover_all` 返回的本网关服务成员实例。
fn summarize_cluster_versions(instances: &[nasa::discovery::Instance]) -> ClusterSummary {
    let nodes: Vec<ClusterNode> = instances
        .iter()
        .map(|inst| ClusterNode {
            ip: inst.ip.clone(),
            port: inst.port,
            admin_listen: inst.metadata.get("gateway.admin_listen").cloned(),
            node_id: inst.metadata.get("gateway.node_id").cloned(),
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
    // P0-3:同版本不代表同内容——指纹分叉(某节点从不同配置源/被旁路改动物化)必须能看见。
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

/// 集群配置版本收敛端点(§14.2 `/api/cluster/consistency`)。
///
/// 从 Nacos 反查本网关自注册服务的所有成员,聚合各成员元数据里的 `gateway.version`,判断是否收敛一致。
/// 版本来自**自注册元数据**(节点换版会原位 refresh 注册 payload,§9),故有 self-register 轮询级滞后:此处附带本节点
/// **实时** `local_version`,便于识别「本地已换版、成员表尚未刷新」的过渡态。
///
/// # 参数
/// - `state`: 管理面共享状态。
async fn cluster_consistency(state: &AdminState) -> Response<BoxBody> {
    let (nacos, local_version) = {
        let snap = state.snap.load();
        (snap.discovery.nacos.clone(), snap.version)
    };
    let Some(service) = crate::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster consistency requires discovery.nacos.self_register.enabled",
            }),
        );
    };
    // Nacos I/O 卸载到专用 current-thread runtime 线程(nacos-sdk future 非 Send,同 R2 回滚)。
    match run_gateway_discover_offloaded(nacos, service.clone()).await {
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
            serde_json::json!({"ok": false, "error": e.to_string()}),
        ),
    }
}

/// C5:聚合集群各节点的流量指标(QPS / 5xx / 活跃连接)。
///
/// 业务作用:集群页此前只能看"版本与指纹是否收敛",看不到"哪个节点在扛流量、哪个在报错"。
/// 本端点用**本节点自己的 admin 凭据**去抓同集群其它节点的 `/metrics`,把三项低基数
/// 计数汇总成一张表。
///
/// 安全边界(三条,缺一不可):
/// 1. **必须显式开启** `admin.auth.allow_cluster_metrics_scrape`。它让 admin 从"只被访问"
///    变成"会主动外连",是攻击面的实质变化,不能默认打开。
/// 2. **凭据只从进程内已解析的配置取**,绝不透传调用方请求里的任何凭证——否则控制面
///    就成了可被借用的跳板(调用方带什么凭据,网关就拿什么去连内网别的机器)。
/// 3. **只抓 Nacos 自注册成员表里的地址**,不接受调用方指定目标;抓取范围因此受限于
///    "本网关自己注册进去的那些实例",不能被诱导去连任意主机。
///
/// 单节点失败(超时/401/解析不了)只标记该行 `ok=false` 并带 reason,**不伪造零值**——
/// 把抓不到显示成 0 会让运维以为那个节点没流量,比看不到更糟。
///
/// # 参数
/// - `state`: 管理面共享状态(取快照、凭据与成员表)。
///
/// # 返回
/// 200 + 每节点一行指标;未开启开关返回 409 并说明原因;成员发现失败返回 502。
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
    let Some(service) = crate::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster metrics requires discovery.nacos.self_register.enabled",
            }),
        );
    };
    let instances = match run_gateway_discover_offloaded(nacos, service.clone()).await {
        Ok(instances) => instances,
        Err(e) => {
            return json(
                StatusCode::BAD_GATEWAY,
                serde_json::json!({"ok": false, "error": e.to_string()}),
            )
        }
    };
    // 逐节点并发抓取:成员数受 full-mesh 上限约束(<=32),不需要额外限流;
    // 每个请求各自带硬超时,慢节点不拖垮整张表。
    let mut tasks = Vec::new();
    for inst in instances {
        let Some(admin_listen) = inst.metadata.get("gateway.admin_listen").cloned() else {
            continue;
        };
        let node_id = inst
            .metadata
            .get("gateway.node_id")
            .cloned()
            .unwrap_or_else(|| format!("{}:{}", inst.ip, inst.port));
        let header = cluster_scrape_auth_header(&auth);
        tasks.push(tokio::spawn(async move {
            scrape_node_metrics(node_id, admin_listen, header).await
        }));
    }
    let mut nodes = Vec::new();
    for task in tasks {
        if let Ok(row) = task.await {
            nodes.push(row);
        }
    }
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

/// 构造抓取用的 Authorization 头。
///
/// 业务作用：只从本节点已验证配置派生 peer metrics 抓取凭据，禁止把调用方凭据透传成内网跳板。
///
/// 参数说明：`auth` 是当前快照中已经解析的管理面认证配置。
///
/// 返回：优先返回 Bearer，其次返回 Basic；未配置或 Bearer 非 UTF-8 时返回 `None`，由对端如实拒绝。
fn cluster_scrape_auth_header(auth: &crate::config::AdminAuthRuntimeCfg) -> Option<String> {
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
/// 参数说明：`bytes` 是已经拼成 `user:password` 的运行态凭据字节。
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

/// 抓取单个节点的 `/metrics` 并提取三项流量指标。
///
/// 业务作用：在硬连接/响应体上限内读取一个已发现成员的低基数流量事实，供集群页定位热点与 5xx。
///
/// 参数说明：`node_id`/`admin_listen` 标识成员与受限目标，`auth_header` 是本节点派生的可选凭据。
///
/// 返回：成功返回三项指标；任意网络、协议或解析失败返回 `ok=false` 与低基数原因，绝不伪造零值。
///
/// 失败一律返回 `ok=false` + 低基数 reason,**不返回零值**:把抓不到显示成"没流量"
/// 会让运维得出完全相反的结论。
async fn scrape_node_metrics(
    node_id: String,
    admin_listen: String,
    auth_header: Option<String>,
) -> serde_json::Value {
    let fail = |reason: &str| {
        serde_json::json!({
            "node_id": node_id,
            "admin_listen": admin_listen,
            "ok": false,
            "reason": reason,
        })
    };
    let Ok(addr) = admin_listen.parse::<std::net::SocketAddr>() else {
        return fail("admin_listen is not a socket address");
    };
    // 硬超时:成员表里的节点可能已经死了但 Nacos 还没摘除,不能让集群页跟着挂住。
    let connect = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        tokio::net::TcpStream::connect(addr),
    )
    .await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return fail("connect refused"),
        Err(_) => return fail("connect timeout"),
    };
    let handshake = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream));
    let (mut sender, conn) = match handshake.await {
        Ok(pair) => pair,
        Err(_) => return fail("http handshake failed"),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = http::Request::builder()
        .uri("/metrics")
        .header(http::header::HOST, admin_listen.as_str());
    if let Some(value) = auth_header.as_deref() {
        builder = builder.header(http::header::AUTHORIZATION, value);
    }
    let Ok(request) = builder.body(http_body_util::Full::<bytes::Bytes>::default()) else {
        return fail("build request failed");
    };
    let response = match tokio::time::timeout(
        std::time::Duration::from_millis(2000),
        sender.send_request(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return fail("request failed"),
        Err(_) => return fail("request timeout"),
    };
    if response.status() == StatusCode::UNAUTHORIZED {
        // 明确区分"凭据不通"与"连不上":前者说明集群配置不同构,运维要改的是配置。
        return fail("unauthorized (peer admin credential differs)");
    }
    if !response.status().is_success() {
        return fail("peer returned non-2xx");
    }
    use http_body_util::BodyExt as _;
    // /metrics 是纯文本且低基数,但仍要设上界:对端异常时不能让控制面被拖爆内存。
    let limited = http_body_util::Limited::new(response.into_body(), 1024 * 1024);
    let Ok(collected) = limited.collect().await else {
        return fail("metrics body too large or truncated");
    };
    let text = String::from_utf8_lossy(&collected.to_bytes()).into_owned();
    let read = |name: &str| -> Option<u64> {
        text.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(' '))
                .and_then(|rest| rest.trim().parse().ok())
        })
    };
    serde_json::json!({
        "node_id": node_id,
        "admin_listen": admin_listen,
        "ok": true,
        "requests_total": read("gw_requests_total"),
        "responses_5xx_total": read("gw_responses_5xx_total"),
        "active_connections": read("gw_active_connections"),
    })
}

/// 把「反查本网关 Nacos 成员」卸载到专用 current-thread runtime 线程执行,oneshot 回送成员实例。
///
/// WHY:与 R2 回滚同因——nacos-sdk future 非 `Send`,admin 连接在多线程 runtime 经 `tokio::spawn` 处理。
///
/// # 参数
/// - `nacos`: `discovery.nacos` 配置。
/// - `service`: 本网关自注册服务名。
async fn run_gateway_discover_offloaded(
    nacos: crate::config::model::NacosDiscoveryCfg,
    service: String,
) -> anyhow::Result<Vec<nasa::discovery::Instance>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("gateway-cluster-consistency".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::anyhow!(
                        "build cluster discover runtime failed: {e}"
                    )));
                    return;
                }
            };
            let result = rt.block_on(discover_gateway_members(&nacos, &service));
            let _ = tx.send(result);
        });
    if let Err(e) = spawned {
        return Err(anyhow::anyhow!("spawn cluster discover thread failed: {e}"));
    }
    rx.await.unwrap_or_else(|_| {
        Err(anyhow::anyhow!(
            "cluster discover worker exited without result"
        ))
    })
}

/// 连接 Nacos 并列出本网关服务的全部成员(含不健康,便于暴露掉队节点)。
///
/// # 参数
/// - `nacos`: `discovery.nacos` 配置。
/// - `service`: 本网关自注册服务名。
async fn discover_gateway_members(
    nacos: &crate::config::model::NacosDiscoveryCfg,
    service: &str,
) -> anyhow::Result<Vec<nasa::discovery::Instance>> {
    let props = crate::discovery::nacos_props(nacos);
    let client = nasa::discovery::nacos::NacosDiscoveryClient::connect(&props)
        .await
        .map_err(|e| anyhow::anyhow!("connect nacos discovery failed: {e}"))?;
    client
        .discover_all(service)
        .await
        .map_err(|e| anyhow::anyhow!("discover_all({service}) failed: {e}"))
}

/// 管理面认证前置检查。认证在路由分发前完成，并把凭据绑定到不可伪造的 RBAC principal。
///
/// # 参数
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

/// 构造不泄露“用户不存在/密码错误”差异的统一 401 响应。
///
/// # 参数
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

/// 拒绝来自未显式允许浏览器来源的管理面状态变更请求，防 DNS rebinding / Basic-auth CSRF。
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
/// `/readyz`(§24 关键依赖):就绪 = 数据面已绑定监听(`ready`)**且**每个 critical 上游服务都还有可用实例。
/// 「可用」与数据面选实例同源:selectable(healthy && !down)+ 未被主动探测判死(N2)+ Nacos 未失联超 stale_ttl(N1)。
/// 未就绪即 503,供前置 LB / K8s 摘流;非关键上游全挂不摘除整个节点(§24「关键依赖」)。
///
/// 参数说明：`state` 提供 listener、xDS、关键上游和配置版本事实。
///
/// 返回：所有门通过返回 200；否则返回 503 与单一低敏 reason。
fn readyz(state: &AdminState) -> Response<BoxBody> {
    let snap = state.snap.load();
    let version = snap.version;
    // 独立控制面没有数据 listener/critical upstream 可供摘流；它的 readiness 只表达管理服务已启动。
    if !state.mode.runs_data() {
        return plain(StatusCode::OK, &format!("ready config_version={version}\n"));
    }
    // 传入主动探测的不健康集合(N2):readyz 与选实例用同一份可用集判定,避免「select 挂但 readyz 仍 ready」。
    let critical_down =
        crate::health::critical_upstreams_not_ready(snap.as_ref(), &state.active_health);
    #[cfg(feature = "xds-client")]
    let xds_ready = state
        .xds_status
        .as_ref()
        .is_none_or(|status| status.ready());
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
/// 参数说明：`state` 提供当前快照和常驻运行态计数器。
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
    #[cfg(feature = "xds-client")]
    if let Some(status) = &state.xds_status {
        let status = status.snapshot();
        body.push_str("# HELP gw_xds_ready Whether at least one EDS version has been applied.\n");
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
        body.push_str("# HELP gw_xds_apply_queue_depth Current xDS translate/apply queue depth.\n");
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
    // 长连接低基数指标(§6.1/§13/L2):按 current/stale 拆分 + 最旧快照版本(不出高基数具体版本 label)。
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
    // V8 边缘订阅低基数 gauge(§25.2.8):只出数值,不带 tenant/group/user label。
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
    if let Some(bus) = state.edge_redis_bus.get() {
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
    if let Some(bus) = state.edge_redis_stream.get() {
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
    // 每服务主动健康实例数(§13 / N5):healthy/total;service 名低基数可作 label(值做最小转义防坏格式)。
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

/// 对本地配置执行 build-only dry-run,不换版、不重建运行态、不触碰数据面连接。
///
/// # 参数
/// - `state`: 管理面共享状态。
fn dry_run_config(state: &AdminState) -> Response<BoxBody> {
    let current = state.snap.load();
    let next_version = current.version.checked_add(1);
    drop(current);
    let Some(next_version) = next_version else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({"ok": false, "error": "config version space exhausted"}),
        );
    };

    match load_snapshot(&state.cfg_path, next_version) {
        Ok(candidate) => dry_run_snapshot_response(state, candidate),
        Err(e) => json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "ok": false,
                "error": e.to_string(),
            }),
        ),
    }
}

// ── P0-3 集群 rollout 登记与收敛查询(验收记录 P0-2 集群分支 / P0-3 rollout 表)──

/// 一次集群发布的登记项。**不含配置内容**:内容事实源在 Nacos,这里只留可审计的元信息。
#[derive(Clone, serde::Serialize)]
pub(crate) struct RolloutRecord {
    /// 本节点生成的 rollout 标识(单调序号 + 起始时刻,便于日志对齐)。
    pub(crate) id: String,
    /// 发布时本节点线上版本(收敛判据:各节点版本必须越过它)。
    pub(crate) base_version: u64,
    /// CAS 写入的 Nacos dataId。
    pub(crate) data_id: String,
    /// 发起时刻(Unix 毫秒)。
    pub(crate) started_at_ms: u128,
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
    /// 保留条数上限:控制面只需要看最近几次发布,历史归 config history 审计。
    const MAX_RECORDS: usize = 32;

    fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 登记一次已 CAS 成功的发布,返回 rollout id。
    fn start(&self, base_version: u64, data_id: &str) -> String {
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
            id: id.clone(),
            base_version,
            data_id: data_id.to_string(),
            started_at_ms,
        };
        let mut inner = self.inner.lock();
        if inner.len() >= Self::MAX_RECORDS {
            inner.pop_front();
        }
        inner.push_back(record);
        id
    }

    /// 最近一次发布登记。
    fn latest(&self) -> Option<RolloutRecord> {
        self.inner.lock().back().cloned()
    }
}

/// `GET /api/cluster/rollout`:最近一次集群发布的逐节点收敛状态。
///
/// 收敛判据(P0-3):**全部 enabled 节点** 的版本都越过 `base_version`,且它们的
/// `(version, fingerprint)` 完全一致。这里刻意不预测"期望指纹"——各节点把 bundle
/// 物化到本地后,指纹还取决于该节点的依赖文件,发布端算不出;集群自身收敛到的那个
/// 值才是唯一诚实的期望值。任一 enabled 节点未上报指纹时不判定成功。
async fn cluster_rollout_status(state: &AdminState) -> Response<BoxBody> {
    let Some(rollout) = state.rollouts.latest() else {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({"ok": false, "error": "no rollout has been started on this node"}),
        );
    };
    let (nacos, local_version) = {
        let snap = state.snap.load();
        (snap.discovery.nacos.clone(), snap.version)
    };
    let Some(service) = crate::discovery::self_register_service_name(&nacos) else {
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "rollout status requires discovery.nacos.self_register.enabled",
            }),
        );
    };
    match run_gateway_discover_offloaded(nacos, service.clone()).await {
        Ok(instances) => {
            let summary = summarize_cluster_versions(&instances);
            let status = rollout_status(&summary, rollout.base_version);
            let mut body = serde_json::json!({
                "ok": true,
                "service": service,
                "local_version": local_version,
                "rollout": rollout,
                "status": status.label,
                "converged": status.converged,
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
            serde_json::json!({"ok": false, "error": error.to_string()}),
        ),
    }
}

/// rollout 收敛判定结果(纯逻辑,便于单测)。
struct RolloutStatus {
    /// 是否全部启用节点已收敛到同一新配置。
    converged: bool,
    /// 展示用状态标签。
    label: &'static str,
    /// 尚未越过 base_version 或指纹不一致的节点标识。
    pending: Vec<String>,
}

/// 依据集群成员汇总判定一次 rollout 是否收敛(纯函数)。
fn rollout_status(summary: &ClusterSummary, base_version: u64) -> RolloutStatus {
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
            Some(version) if version > base_version => advanced += 1,
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

// ── P0-2 Console 配置发布闭环(验收记录 P0-2)──

/// 主 YML 读取上限:与候选提交同一预算,防止误挂大文件把控制面读爆。
fn admin_config_read_limit(state: &AdminState) -> usize {
    state.snap.load().admin_max_config_body_bytes
}

/// 当前配置集指纹 → ETag。
///
/// 指纹覆盖主 YML **及其依赖**(OpenAPI/schema/WASM/文件型 SecretSource),因此"依赖文件被
/// 旁路改动"同样会让旧 ETag 失效——CAS 语义是"你基于的整份配置状态",不是单个文件的哈希。
fn config_etag(fingerprint: u64) -> String {
    format!("\"cfg-{fingerprint:016x}\"")
}

/// `GET /api/config/current`:有界读取当前主 YML + 版本 + 指纹 + ETag。
///
/// 只在 full control-plane 开放(data-only 节点没有配置事实源,返回 404 而不是半个视图)。
async fn read_current_config(state: &AdminState) -> Response<BoxBody> {
    if !state.mode.full_control_plane() {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    let limit = admin_config_read_limit(state);
    let cfg_path = state.cfg_path.clone();
    let read = tokio::task::spawn_blocking(move || {
        crate::bounded_io::read_file(&cfg_path, limit, "admin config read")
    })
    .await;
    let bytes = match read {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": format!("{error:#}")}),
            )
        }
        Err(error) => {
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": format!("config read worker failed: {error}")}),
            )
        }
    };
    let Ok(content) = String::from_utf8(bytes) else {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "config file is not valid UTF-8"}),
        );
    };
    let cfg_path = state.cfg_path.clone();
    let fingerprint =
        tokio::task::spawn_blocking(move || crate::config::config_fingerprint(&cfg_path))
            .await
            .ok()
            .and_then(Result::ok);
    let Some(fingerprint) = fingerprint else {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "cannot fingerprint current config set"}),
        );
    };
    let snapshot = state.snap.load();
    let etag = config_etag(fingerprint);
    let body = serde_json::json!({
        "ok": true,
        "version": snapshot.version,
        "fingerprint": fingerprint,
        "etag": etag,
        // 配置源是 Nacos 时本地文件只是物化产物,PUT 必须走集群 rollout(见 publish 分支)。
        "source": if snapshot.config_source.nacos.enabled { "nacos" } else { "file" },
        "content": content,
    });
    let mut response = json(StatusCode::OK, body);
    if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
        response.headers_mut().insert(hyper::header::ETAG, value);
    }
    response
}

/// 发布结果:决定 HTTP 状态、审计文案与是否需要回滚文件。
enum PublishOutcome {
    /// 已换版并观察到目标指纹的成功事件。
    Applied {
        /// 上线后的配置版本。
        version: u64,
        /// 上线配置集指纹(新 ETag 来源)。
        fingerprint: u64,
    },
    /// reload worker 明确拒绝;文件已回滚到发布前内容。
    Rejected(String),
    /// 等待窗口内既没成功也没拒绝(worker 卡住/极慢)。诚实回 202,不谎称成功。
    Pending,
}

/// `PUT /api/config/current`:`If-Match` CAS + 候选校验 + 原子落盘 + **确认生效**。
///
/// 相位序(任一步失败都不改变线上快照):
/// 1. 认证 → Origin → 平面边界 → RBAC(Config,Write);
/// 2. `If-Match` 必填且必须等于当前配置集 ETag(缺失 428、失配 412);
/// 3. Content-Type/有界 body → 临时文件 → **候选构建校验**(坏配置 400,线上文件不动);
/// 4. 原子 rename 覆盖主 YML → SIGHUP 唤醒唯一 reload worker;
/// 5. 等待 history 出现目标指纹的成功事件且 ArcSwap 版本前进,才回 `applied`;
///    被拒绝则**恢复发布前文件内容**并回 400,保持"文件与线上快照一致"。
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
        json(status, serde_json::json!({"ok": false, "error": error}))
    };
    if !identity.allows(AdminResource::Config, AdminAction::Write) {
        let response = deny(StatusCode::FORBIDDEN, "forbidden");
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    }
    let nacos_source = state.snap.load().config_source.nacos.enabled;
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
    // —— CAS 前置:先算当前指纹,再比 If-Match ——
    let cfg_path = state.cfg_path.clone();
    let current_fingerprint =
        tokio::task::spawn_blocking(move || crate::config::config_fingerprint(&cfg_path))
            .await
            .ok()
            .and_then(Result::ok);
    let Some(current_fingerprint) = current_fingerprint else {
        let response = deny(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot fingerprint current config set",
        );
        audit_publish(&state, &identity, &parts, response.status()).await;
        return response;
    };
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
    // 直接改本地物化文件会被下次 watch 覆盖且不集群生效(§14.2/§14.3)。
    let response = if nacos_source {
        publish_cluster_config(&state, candidate_body).await
    } else {
        publish_validated_config(&state, candidate_body).await
    };
    audit_publish(&state, &identity, &parts, response.status()).await;
    response
}

/// P0-3:Nacos 配置源的集群发布——原子 bundle CAS + 生成 rollout id。
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
) -> Response<BoxBody> {
    let Ok(gateway_yaml) = String::from_utf8(candidate_body.to_vec()) else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": "config must be valid UTF-8"}),
        );
    };
    let (nacos, current_version) = {
        let snap = state.snap.load();
        (snap.config_source.nacos.clone(), snap.version)
    };
    if nacos.bundle_data_id.trim().is_empty() {
        // 三 dataId 兼容模式下无法用一次 CAS 原子写三份;不伪造事务(§14.3 边界)。
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({
                "ok": false,
                "error": "cluster publish requires config_source.nacos.bundle_data_id for atomic CAS",
            }),
        );
    }
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
    let target = crate::config_history::ArchivedDocs {
        gateway: gateway_yaml,
        interface_guard: baseline.interface_guard.clone(),
        sentinel_rules: baseline.sentinel_rules.clone(),
    };
    // 候选先本地 build-only 校验:坏配置绝不进集群事实源。
    if let Err(error) = validate_cluster_candidate(state, &target).await {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": error}),
        );
    }
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
            let rollout = state.rollouts.start(current_version, &data_id);
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
            let rollout = state.rollouts.start(current_version, &data_id);
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
            serde_json::json!({"ok": false, "error": "legacy multi-dataId publish is not atomic", "changed_data_ids": ids}),
        ),
        Err(error) => json(
            StatusCode::BAD_GATEWAY,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        ),
    }
}

/// 集群候选的本地 build-only 校验:把三份文档物化到临时目录后走同一 SnapshotBuilder。
async fn validate_cluster_candidate(
    state: &Arc<AdminState>,
    docs: &crate::config_history::ArchivedDocs,
) -> Result<(), String> {
    let (candidate_path, mut file) = create_dry_run_file(&state.cfg_path)
        .await
        .map_err(|error| format!("cannot create publish workspace: {error}"))?;
    let write = async {
        file.write_all(docs.gateway.as_bytes()).await?;
        file.flush().await
    }
    .await;
    drop(file);
    if let Err(error) = write {
        let _ = tokio::fs::remove_file(&candidate_path).await;
        return Err(format!("cannot write publish workspace: {error}"));
    }
    let real_cfg = state.cfg_path.clone();
    let build_path = candidate_path.clone();
    let next_version = state.snap.load().version.saturating_add(1);
    let built = tokio::task::spawn_blocking(move || {
        crate::config::load_candidate_snapshot(&real_cfg, &build_path, next_version)
    })
    .await;
    let _ = tokio::fs::remove_file(&candidate_path).await;
    match built {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(format!("publish worker failed: {error}")),
    }
}

/// 候选构建校验 → 原子落盘 → 触发 reload → 确认生效。调用方已完成鉴权与 CAS。
async fn publish_validated_config(
    state: &Arc<AdminState>,
    candidate_body: Bytes,
) -> Response<BoxBody> {
    // 1) 写临时候选并 build-only 校验:坏配置在碰线上文件之前就被拒。
    let (candidate_path, mut file) = match create_dry_run_file(&state.cfg_path).await {
        Ok(created) => created,
        Err(error) => {
            tracing::error!(%error, "create publish workspace failed");
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": "cannot create publish workspace"}),
            );
        }
    };
    let write_result = async {
        file.write_all(candidate_body.as_ref()).await?;
        file.flush().await
    }
    .await;
    drop(file);
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&candidate_path).await;
        tracing::error!(%error, "write publish workspace failed");
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "cannot write publish workspace"}),
        );
    }
    let real_cfg = state.cfg_path.clone();
    let build_path = candidate_path.clone();
    let Some(next_version) = state.snap.load().version.checked_add(1) else {
        let _ = tokio::fs::remove_file(&candidate_path).await;
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({"ok": false, "error": "config version space exhausted"}),
        );
    };
    let built = tokio::task::spawn_blocking(move || {
        crate::config::load_candidate_snapshot(&real_cfg, &build_path, next_version)
    })
    .await;
    match built {
        Ok(Ok(_candidate)) => {}
        Ok(Err(error)) => {
            let _ = tokio::fs::remove_file(&candidate_path).await;
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"ok": false, "error": error.to_string()}),
            );
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&candidate_path).await;
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": format!("publish worker failed: {error}")}),
            );
        }
    }

    // 2) 备份发布前内容(拒绝时要还原,保持"文件 == 线上快照")。
    let limit = admin_config_read_limit(state);
    let backup_path = state.cfg_path.clone();
    let previous = tokio::task::spawn_blocking(move || {
        crate::bounded_io::read_file(&backup_path, limit, "admin config backup")
    })
    .await
    .ok()
    .and_then(Result::ok);

    // 3) 原子换文件:同目录 rename,reload worker 只会看到旧文件或新文件。
    let observed_before = state.snap.load().version;
    if let Err(error) = tokio::fs::rename(&candidate_path, &state.cfg_path).await {
        let _ = tokio::fs::remove_file(&candidate_path).await;
        tracing::error!(%error, "atomic publish rename failed");
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "cannot publish config atomically"}),
        );
    }
    state.config_history.record_control_event(
        "admin-publish",
        &state.cfg_path,
        observed_before,
        next_version,
        "publish_scheduled",
    );
    // 只唤醒唯一 reload worker;admin 不自行换版,避免与 file watcher 双重 reload。
    // SAFETY:kill 只向本进程发 SIGHUP,不解引用指针。
    let rc = unsafe { libc::kill(std::process::id() as i32, libc::SIGHUP) };
    if rc != 0 {
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "failed to signal reload worker"}),
        );
    }

    // 4) 等待"真正生效":必须同时看到 history 成功事件与 ArcSwap 版本前进。
    match await_publish_outcome(state, observed_before).await {
        PublishOutcome::Applied {
            version,
            fingerprint,
        } => {
            let etag = config_etag(fingerprint);
            let mut response = json(
                StatusCode::OK,
                serde_json::json!({
                    "ok": true,
                    "status": "applied",
                    "version": version,
                    "fingerprint": fingerprint,
                    "etag": etag,
                }),
            );
            if let Ok(value) = hyper::header::HeaderValue::from_str(&etag) {
                response.headers_mut().insert(hyper::header::ETAG, value);
            }
            response
        }
        PublishOutcome::Rejected(error) => {
            // 还原发布前文件:线上快照没换版,文件也不能停在被拒内容上。
            if let Some(previous) = previous {
                let restore_path = state.cfg_path.clone();
                let restored = tokio::task::spawn_blocking(move || {
                    crate::reload::write_atomic(&restore_path, &previous)
                })
                .await;
                match restored {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(%error, "restore config after rejected publish failed")
                    }
                    Err(error) => {
                        tracing::error!(%error, "restore worker after rejected publish failed")
                    }
                }
            }
            json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "ok": false,
                    "status": "rejected",
                    "error": error,
                    "note": "previous config restored; live snapshot unchanged",
                }),
            )
        }
        PublishOutcome::Pending => json(
            StatusCode::ACCEPTED,
            serde_json::json!({
                "ok": true,
                "status": "pending",
                "note": "reload scheduled but not yet observed; poll /admin/config/history",
            }),
        ),
    }
}

/// 等待 reload worker 对本次发布给出结论(成功换版 / 明确拒绝 / 超时未观察到)。
async fn await_publish_outcome(state: &Arc<AdminState>, before_version: u64) -> PublishOutcome {
    // 观察窗口:reload 是本地文件构建 + ArcSwap 换版,秒级足够;超时只回 pending,不谎称成功。
    const OBSERVE_ATTEMPTS: usize = 120;
    const OBSERVE_INTERVAL: Duration = Duration::from_millis(50);
    for _ in 0..OBSERVE_ATTEMPTS {
        tokio::time::sleep(OBSERVE_INTERVAL).await;
        let snapshot = state.snap.load();
        let version = snapshot.version;
        drop(snapshot);
        let history = state.config_history.snapshot();
        // 先看拒绝:被拒时版本不会前进,只能靠事件判定。
        if let Some(rejected) = history
            .events
            .iter()
            .rev()
            .find(|event| event.status == "rejected" && event.old_version >= before_version)
        {
            return PublishOutcome::Rejected(
                rejected
                    .error
                    .clone()
                    .unwrap_or_else(|| "config rejected".to_string()),
            );
        }
        if version > before_version {
            if let Some(applied) = history.events.iter().rev().find(|event| {
                event.new_version == Some(version) && event.status.starts_with("applied")
            }) {
                if let Some(fingerprint) = applied.fingerprint {
                    return PublishOutcome::Applied {
                        version,
                        fingerprint,
                    };
                }
            }
        }
    }
    PublishOutcome::Pending
}

/// 发布动作审计:与其它写操作同一 fail-closed 口径(审计失败只记日志,状态已由调用方决定)。
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

/// 对 UI 提交的候选 gateway.yml 做有界 build-only 校验；真实配置文件和 ArcSwap 均不修改。
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
            serde_json::json!({"ok": false, "error": "forbidden"}),
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
            serde_json::json!({"ok": false, "error": "Content-Type must be application/yaml"}),
        );
    }
    let max_bytes = state.snap.load().admin_max_config_body_bytes;
    let candidate_body = match collect_bounded_admin_body(&parts, body, max_bytes).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let (candidate_path, mut file) = match create_dry_run_file(&state.cfg_path).await {
        Ok(created) => created,
        Err(error) => {
            tracing::error!(%error, "create candidate dry-run file failed");
            return json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"ok": false, "error": "cannot create dry-run workspace"}),
            );
        }
    };
    let write_result = async {
        file.write_all(candidate_body.as_ref()).await?;
        file.flush().await
    }
    .await;
    drop(file);
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&candidate_path).await;
        tracing::error!(%error, "write candidate dry-run file failed");
        return json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": "cannot write dry-run workspace"}),
        );
    }
    let real_cfg = state.cfg_path.clone();
    let build_path = candidate_path.clone();
    let next_version = state.snap.load().version.checked_add(1);
    let Some(next_version) = next_version else {
        let _ = tokio::fs::remove_file(&candidate_path).await;
        return json(
            StatusCode::CONFLICT,
            serde_json::json!({"ok": false, "error": "config version space exhausted"}),
        );
    };
    let built = tokio::task::spawn_blocking(move || {
        crate::config::load_candidate_snapshot(&real_cfg, &build_path, next_version)
    })
    .await;
    if let Err(error) = tokio::fs::remove_file(&candidate_path).await {
        tracing::warn!(path = %candidate_path.display(), %error, "remove dry-run workspace failed");
    }
    match built {
        Ok(Ok(candidate)) => dry_run_snapshot_response(&state, candidate),
        Ok(Err(error)) => json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"ok": false, "error": error.to_string()}),
        ),
        Err(error) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"ok": false, "error": format!("dry-run worker failed: {error}")}),
        ),
    }
}

/// 从 axum body 逐 frame 收集有界控制面请求：单 frame 直接复用 Bytes，多 frame 只分配一次聚合缓冲。
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
                    serde_json::json!({"ok": false, "error": "invalid Content-Length"}),
                ))
            })?;
        if declared > max_bytes {
            return Err(Box::new(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"ok": false, "error": "request body too large"}),
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
                serde_json::json!({"ok": false, "error": format!("read request body: {error}")}),
            ))
        })?;
        let data = frame.into_data().map_err(|_| {
            Box::new(json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({"ok": false, "error": "request body trailers are not supported"}),
            ))
        })?;
        total = total.checked_add(data.len()).ok_or_else(|| {
            Box::new(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"ok": false, "error": "request body too large"}),
            ))
        })?;
        if total > max_bytes {
            return Err(Box::new(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({"ok": false, "error": "request body too large"}),
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

/// 以 `create_new` 在真实配置同目录创建临时文件；不覆盖任何已有文件，也保持相对依赖基准一致。
async fn create_dry_run_file(
    cfg_path: &std::path::Path,
) -> anyhow::Result<(PathBuf, tokio::fs::File)> {
    static NEXT_DRY_RUN_ID: AtomicU64 = AtomicU64::new(1);
    let dir = cfg_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    for _ in 0..8 {
        let id = NEXT_DRY_RUN_ID.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".gateway-dry-run-{}-{id}.yml", std::process::id()));
        match tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("cannot allocate unique dry-run workspace file")
}

/// 对候选快照执行与真实 reload 一致的 bootstrap 拓扑判定，再返回低基数摘要。
fn dry_run_snapshot_response(state: &AdminState, candidate: GatewaySnapshot) -> Response<BoxBody> {
    let current = state.snap.load();
    let candidate_listener_topology = candidate.listen_topology();
    let current_listener_topology = current.listen_topology();
    let listener_prepare_required = candidate_listener_topology != current_listener_topology
        || candidate.admin_listen != current.admin_listen;
    let restart_field = if !current.admin_audit.same_bootstrap(&candidate.admin_audit) {
        Some("admin.audit")
    } else if !current.access_log.same_sink_topology(&candidate.access_log) {
        Some("access_log queue/sink topology")
    } else if crate::http_cache::runtime_config_signature(&current.runtime_state.http_cache)
        != crate::http_cache::runtime_config_signature(&candidate.runtime_state.http_cache)
    {
        Some("runtime_state.http_cache bootstrap")
    } else if crate::telemetry::config_signature(&current.telemetry)
        != crate::telemetry::config_signature(&candidate.telemetry)
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
        // §18 审计:手工拉黑记 who/why/source + TTL。
        let ttl_ms = query_param(req.uri.query().unwrap_or_default(), "ttl_ms")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        state.blacklist.record_ban(ip, "admin", ttl_ms);
        plain(
            StatusCode::OK,
            &format!("blocked ip={ip} closed_long_connections={closed}\n"),
        )
    } else {
        // §18 审计 + 解封豁免:手工解封记审计,并在本节点开启解封豁免窗口(防抖)。
        state.blacklist.record_unban(ip, "admin");
        plain(StatusCode::OK, &format!("unblocked ip={ip}\n"))
    }
}

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

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

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

/// Prometheus label 值最小转义(反斜杠 / 双引号 / 换行):防 service 名里的特殊字符破坏 exposition 文本格式。
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

/// 返回编译进二进制的 UI 资产；`Bytes::from_static` 不复制 asset，严格 CSP 禁止 inline script/style。
///
/// # 参数
/// - `content_type`: 资产 MIME。
/// - `body`: `include_bytes!` 产生的静态 Bytes view。
fn is_developer_portal_read_path(path: &str) -> bool {
    matches!(
        path,
        "/developer"
            | "/developer/"
            | "/developer/app.css"
            | "/developer/app.js"
            | "/api/developer/catalogs"
    ) || developer_catalog_id_from_openapi_path(path).is_some()
}

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

/// 服务门户静态页、catalog 读模型和原始 OpenAPI 文件。
///
/// 文档 [`Bytes`] 由配置快照持有；响应 clone 只增加引用计数，不复制可能达到 MiB 的正文。
fn developer_portal_read(
    request: &AdminRequestParts,
    state: &AdminState,
) -> Option<Response<BoxBody>> {
    let snapshot = state.snap.load();
    let portal = &snapshot.developer_portal;
    if !portal.enabled() {
        return None;
    }
    match request.uri.path() {
        "/developer" | "/developer/" => Some(admin_ui_asset(
            "text/html; charset=utf-8",
            Bytes::from_static(include_bytes!("../developer_portal.html")),
        )),
        "/developer/app.css" => Some(admin_ui_asset(
            "text/css; charset=utf-8",
            Bytes::from_static(include_bytes!("../developer_portal.css")),
        )),
        "/developer/app.js" => Some(admin_ui_asset(
            "application/javascript; charset=utf-8",
            Bytes::from_static(include_bytes!("../developer_portal.js")),
        )),
        "/api/developer/catalogs" => Some(json(
            StatusCode::OK,
            serde_json::json!({"ok": true, "catalogs": portal.catalog_json()}),
        )),
        path => {
            let id = developer_catalog_id_from_openapi_path(path)?;
            let catalog = portal.catalog(id)?;
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, catalog.content_type)
                    .header(hyper::header::CACHE_CONTROL, "no-cache")
                    .body(full_body(catalog.document.clone()))
                    .expect("build developer OpenAPI response"),
            )
        }
    }
}

/// 接收门户 key 申请。该入口使用独立 Bearer token，只写 `pending` 记录，绝不在请求中
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
            serde_json::json!({"ok": false, "error": "Content-Type must be application/json"}),
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
                serde_json::json!({"ok": false, "error": error.to_string()}),
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
                serde_json::json!({"ok": false, "error": "cannot serialize application"}),
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
        Ok(crate::runtime_state::StoreCapacityOutcome::Stored) => {}
        Ok(crate::runtime_state::StoreCapacityOutcome::CapacityReached) => {
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Rejected);
            return json(
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({"ok": false, "error": "pending application capacity reached"}),
            );
        }
        Err(error) => {
            tracing::error!(%error, "persist developer key application failed");
            state
                .metrics
                .inc_developer_application(DeveloperApplicationMetric::Error);
            return json(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"ok": false, "error": "application store unavailable"}),
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

/// 纯文本响应助手(管理面自产短路应答)。
fn plain(status: StatusCode, body: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(body.to_owned())))
        .expect("build admin response")
}

/// JSON 响应助手。
///
/// # 参数
/// - `status`: HTTP 状态码。
/// - `value`: 可序列化为 JSON 的响应体。
fn json(status: StatusCode, value: serde_json::Value) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(value.to_string())))
        .expect("build admin json response")
}

#[path = "../../tests/unit/admin_mod.rs"]
#[cfg(test)]
mod tests;
