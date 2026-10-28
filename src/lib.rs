//! Naway 流量与业务网关。
//!
//! 配置构建与控制面发布由 [config]、[control] 负责；[proxy]、[protocols] 和 [upstream]
//! 承担数据转发；[security]、[runtime]、[observability] 提供策略、常驻状态与观测。
//! [ai]、[edge] 和 [extensions] 承载按路由启用的业务能力。

pub mod admin;
pub mod ai;
pub mod cache;
pub mod config;
pub mod control;
pub mod edge;
pub mod extensions;
pub mod io;
pub mod observability;
pub mod portal;
pub mod protocols;
pub mod proxy;
pub mod routing;
pub mod runtime;
pub mod security;
pub mod tls;
pub mod upstream;

// 管理面路由由 nasa::web 收集，状态类型绑定当前进程的管理上下文。
nasa::web::mvc_router!(std::sync::Arc<crate::admin::AdminState>);

pub use io::resp::{full_body, text_status, BoxBody, BoxError};
