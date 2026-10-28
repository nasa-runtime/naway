//! 匀速排队的冻结时序与资源合同，不借用令牌桶的突发余额。

use anyhow::{ensure, Result};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub interval_us: u64,
    pub capacity: usize,
    pub max_wait: Duration,
}

impl Policy {
    /// 业务作用：把稳定速率换算为保守整数间隔，并在构建期限定等待容量与期限。
    ///
    /// 参数说明：
    /// - `limit`：窗口内允许的请求数。
    /// - `window`：速率窗口长度。
    /// - `capacity`：同维度最多等待的请求数。
    /// - `wait_ms`：单请求不可续期的最长等待毫秒数。
    ///
    /// 返回：有限调度合同；零速率、非法窗口、超容量或超期限拒绝候选。
    pub fn build(limit: u64, window: Duration, capacity: usize, wait_ms: u64) -> Result<Self> {
        ensure!(
            limit > 0 && !window.is_zero() && window <= Duration::from_secs(3600),
            "queue rate window must be within one hour and have positive rate"
        );
        ensure!(
            (1..=4096).contains(&capacity),
            "queue_capacity must be within 1..=4096"
        );
        ensure!(
            (1..=60_000).contains(&wait_ms),
            "queue_wait_ms must be within 1..=60000"
        );
        let interval_us = window.as_micros().div_ceil(u128::from(limit)).max(1) as u64;
        Ok(Self {
            interval_us,
            capacity,
            max_wait: Duration::from_millis(wait_ms),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    Capacity,
    Deadline,
    UnknownBody,
    Clock,
    StateCapacity,
    Unavailable,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reservation {
    Admitted,
    Waiting {
        ticket: u64,
        due_us: u64,
    },
    Rejected(Rejected),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Claim {
    Admitted,
    Wait(u64),
    Rejected(Rejected),
}
