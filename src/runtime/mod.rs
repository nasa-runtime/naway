//! 跨请求常驻的准入、连接与共享状态。

pub mod admission;
pub mod connections;
#[cfg(feature = "rate-preallocation")]
pub(crate) mod ratelimit;
pub mod sentinel;
pub mod state;
pub mod traffic_limit;
