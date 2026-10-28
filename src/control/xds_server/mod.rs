//! 独立 xDS 管理端：只发布当前 GatewaySnapshot 的授权投影，不接受下游配置写入。

mod admission;
pub(crate) mod metrics;
mod plan;
mod projection;
mod proto;
mod runtime;
pub(crate) mod security;
mod state;
mod stream;

pub use plan::{Plan, Summary};
pub use runtime::Manager;
