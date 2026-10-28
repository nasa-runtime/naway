//! 原生匀速入口准入；等待凭证同时绑定调度顺序、绝对期限和实际保留资源。

pub(crate) mod local;
pub(crate) mod metrics;
mod policy;
#[cfg(feature = "redis-runtime")]
pub(crate) mod redis;
mod schedule;

pub use policy::{Policy, Rejected};
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

pub type AdmissionFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Rejected>> + Send + 'a>>;

/// 从请求入口冻结的等待边界，未知正文只能尝试立即准入。
#[derive(Clone, Copy)]
pub struct Context {
    pub deadline: Instant,
    pub retained_bound: Option<u64>,
}
