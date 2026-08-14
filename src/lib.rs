//! Naway —— 超高性能 Rust 流量网关 + 业务网关（nginx + SCG + Higress 替代，HA-native）。
//!
//! 模块划分:
//! - [`resp`]    共享响应类型/助手(`BoxBody` / `full_body` / `text_status`)
//! - [`config`]  配置模型 + 加载 + 运行期不可变快照(`ArcSwap` 换版)
//! - [`routing`] 路由:`Router`/`Route` + `Predicate`(SCG DSL)
//! - [`upstream`] 上游发现抽象 + static `lb://` 目录
//! - [`guard`]   接口级拦截(独立 yml → 直接响应)
//! - [`proxy`]   反向代理数据面(请求管线 + 上游流式转发)
//! - [`reload`]  无感热重载(naml 精确文件观察 + `SIGHUP`)
//! - [`admin`]   管理/观测面(与数据面端口隔离:/healthz /readyz + 后续 /metrics、admin)
//! - [`metrics`] 低基数运行指标(`/metrics`)
//! - [`access_log`] 非阻塞 access log
//! - [`runtime_state`] DynamicStore / RateLimiter 后端接口
//! - [`http_cache`] V5 有界 L1 + 可选 Redis L2 / generation 失效运行时
//! - [`telemetry`] V5 W3C/B3 传播 + OpenTelemetry OTLP 有界导出
//! - [`static_serve`] 本地静态文件 / SPA 后端
//! - [`tls`] TLS acceptor 配置加载
//!
//! 设计蓝本见 `架构规范`。R2+ 逐步接 nasa 的服务发现 / 分布式限流 / 集群统一配置 / 管理界面。

#[path = "observability/access_log.rs"]
pub mod access_log;
#[path = "dataplane/acme.rs"]
pub mod acme;
pub mod admin;
#[path = "admin/admin_audit.rs"]
pub mod admin_audit;
#[path = "dataplane/admission.rs"]
pub mod admission;
#[path = "security/auth.rs"]
pub mod auth;
#[path = "security/blacklist.rs"]
pub mod blacklist;
#[path = "security/bot.rs"]
mod bot;
#[path = "io/bounded_io.rs"]
mod bounded_io;
#[path = "security/casbin_auth.rs"]
mod casbin_auth;
#[path = "io/compression.rs"]
mod compression;
pub mod config;
#[path = "dataplane/config_history.rs"]
pub mod config_history;
#[path = "dataplane/conn_registry.rs"]
pub mod conn_registry;
#[path = "security/csrf.rs"]
mod csrf;
#[path = "extensions/degraphql.rs"]
mod degraphql;
#[path = "extensions/developer_portal.rs"]
pub mod developer_portal;
#[path = "dataplane/discovery.rs"]
pub mod discovery;
#[path = "security/dlp.rs"]
mod dlp;
#[path = "extensions/dubbo.rs"]
mod dubbo;
#[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
#[path = "dataplane/edge_directory.rs"]
pub mod edge_directory;
#[cfg(feature = "grpc-edge")]
#[path = "dataplane/edge_hub.rs"]
pub mod edge_hub;
#[cfg(all(feature = "grpc-edge", feature = "redis-runtime"))]
#[path = "dataplane/edge_redis_bus.rs"]
pub mod edge_redis_bus;
#[cfg(feature = "grpc-edge")]
#[path = "dataplane/edge_relay.rs"]
pub mod edge_relay;
#[cfg(feature = "grpc-edge")]
#[path = "dataplane/edge_ws_bridge.rs"]
pub mod edge_ws_bridge;
#[path = "security/enterprise_identity.rs"]
mod enterprise_identity;
#[path = "extensions/ext_proc.rs"]
mod ext_proc;
#[path = "security/external_crypto.rs"]
pub mod external_crypto;
#[path = "extensions/external_plugin.rs"]
mod external_plugin;
#[path = "dataplane/forward_proxy.rs"]
pub mod forward_proxy;
#[path = "security/geoip.rs"]
mod geoip;
#[path = "extensions/graphql.rs"]
mod graphql;
#[path = "extensions/grpc_edge.rs"]
pub mod grpc_edge;
#[path = "extensions/grpc_transcoding.rs"]
pub(crate) mod grpc_transcoding;
pub mod guard;
#[cfg(feature = "http3")]
#[path = "dataplane/h3_quinn_tracked.rs"]
pub(crate) mod h3_quinn_tracked;
#[path = "dataplane/health.rs"]
pub mod health;
#[cfg(feature = "http3")]
#[path = "dataplane/http3.rs"]
pub mod http3;
#[path = "cache/http_cache.rs"]
pub mod http_cache;
#[cfg(feature = "kafka-governance")]
#[path = "dataplane/kafka.rs"]
pub mod kafka;
#[path = "dataplane/kubernetes_routes.rs"]
pub mod kubernetes_routes;
#[path = "dataplane/lb_hash.rs"]
pub mod lb_hash;
#[path = "dataplane/lb_load.rs"]
pub mod lb_load;
#[path = "extensions/llm.rs"]
pub mod llm;
#[path = "observability/log_sink.rs"]
mod log_sink;
#[path = "dataplane/masque.rs"]
pub mod masque;
#[path = "observability/metrics.rs"]
pub mod metrics;
#[cfg(feature = "mqtt-governance")]
#[path = "dataplane/mqtt.rs"]
pub mod mqtt;
#[path = "dataplane/net.rs"]
pub mod net;
#[path = "security/opa.rs"]
mod opa;
pub mod proxy;
#[path = "dataplane/proxy_protocol.rs"]
pub mod proxy_protocol;
pub mod reload;
#[path = "security/remote_secret.rs"]
mod remote_secret;
#[path = "io/resp.rs"]
pub mod resp;
pub mod routing;
#[path = "dataplane/runtime_state.rs"]
pub mod runtime_state;
#[path = "security/secret.rs"]
pub mod secret;
#[path = "security/spire.rs"]
pub mod spire;
#[path = "io/static_serve.rs"]
pub mod static_serve;
#[path = "observability/telemetry.rs"]
pub mod telemetry;
#[path = "dataplane/tls.rs"]
pub mod tls;
#[path = "dataplane/traffic_limit.rs"]
pub mod traffic_limit;
#[path = "dataplane/upstream.rs"]
pub mod upstream;
#[path = "security/upstream_credential.rs"]
mod upstream_credential;
#[path = "extensions/variable.rs"]
pub mod variable;
#[path = "security/waf.rs"]
mod waf;
#[path = "extensions/wasm.rs"]
mod wasm;
#[path = "dataplane/ws_frame.rs"]
pub mod ws_frame;
#[cfg(feature = "xds-client")]
#[path = "control/xds.rs"]
pub mod xds;
#[cfg(feature = "xds-client")]
#[path = "control/xds_resources.rs"]
pub(crate) mod xds_resources;

// V5 管理面路由由 nasa::web 在链接期收集；状态类型固定为进程级 AdminState Arc。
nasa::web::mvc_router!(std::sync::Arc<crate::admin::AdminState>);

// 便捷 re-export:crate 根仍可直接用响应助手(`crate::full_body` / `crate::BoxBody`)。
pub use resp::{full_body, text_status, BoxBody, BoxError};
