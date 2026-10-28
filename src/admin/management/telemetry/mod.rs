//! 当前样本的有界上传、完整性校验与内存许可，不建立历史队列。

mod routes;
mod send;
mod wire;
pub(super) use send::upload;
pub(super) use wire::{digest, frame, Candidate};

use crate::admin::monitor::model;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::OwnedSemaphorePermit;

pub(super) const SAMPLE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const STORE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const CHUNK: usize = 64;
pub(super) const INTEREST_MS: u32 = 12_000;

pub(in crate::admin) struct Current {
    pub sample: Arc<model::Sample>,
    pub at: Instant,
    pub(super) _memory: OwnedSemaphorePermit,
}

pub(super) struct Upload {
    pub sample: Arc<model::Sample>,
    pub at: Instant,
    pub digest: [u8; 32],
}
