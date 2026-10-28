//! 延迟准入、逐帧整形与显式消息治理共用的进程级保留资源边界。

use super::metrics::{CAPACITY, RETAINED_BYTES, WAITERS};
use std::sync::atomic::Ordering;

pub(crate) const MAX_WAIT_MS: u64 = 60_000;
pub(crate) const MAX_WAITERS: u64 = 4_096;
pub(crate) const MAX_RETAINED_BYTES: u64 = 64 << 20;

/// 本地流量治理拒绝；沿 transport 错误链保留，不能作为上游健康证据。
#[derive(Debug)]
pub(crate) struct Rejected;

impl std::fmt::Display for Rejected {
    /// 业务作用：提供固定的流量保护拒绝描述，不暴露维度或工作区占用。
    ///
    /// 参数说明：
    /// - `out`：错误文本目标。
    ///
    /// 返回：写入不含请求信息的拒绝原因。
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("traffic stream resource limit reached")
    }
}

impl std::error::Error for Rejected {}

/// 等待期间持有的名额与实体字节预算，直到真实取消或交付后归还。
pub(crate) struct Retained {
    bytes: u64,
}

impl Retained {
    /// 业务作用：让同一流或消息的名额随待交付实体调整保留字节，不逐帧重复占用等待槽。
    ///
    /// 参数说明：
    /// - `bytes`：本次需要保留的原始帧及消息处理缓冲总量；交付后传零。
    ///
    /// 返回：预算足够时原子调整，失败保留旧预算；此物理资源门不能降级。
    pub(crate) fn resize(&mut self, bytes: u64) -> bool {
        // 拒绝对端声明的极大长度后才做增量运算，失败时保留原凭证与账目。
        if bytes > MAX_RETAINED_BYTES {
            CAPACITY.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if bytes <= self.bytes {
            RETAINED_BYTES.fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        } else if RETAINED_BYTES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let extra = bytes - self.bytes;
                (extra <= MAX_RETAINED_BYTES - used).then_some(used + extra)
            })
            .is_err()
        {
            CAPACITY.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.bytes = bytes;
        true
    }

    /// 业务作用：在延后准入或保存待发送帧前占用全进程容量，不把压力转移到无界等待队列。
    ///
    /// 参数说明：
    /// - `bytes`：将保留的已知实体上界或实际帧长度。
    ///
    /// 返回：取得名额和字节预算时返回凭证；任何预算不足立即拒绝，不支持 fail-open。
    pub(crate) fn acquire(bytes: u64) -> Option<Self> {
        if bytes > MAX_RETAINED_BYTES {
            CAPACITY.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if WAITERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_WAITERS).then_some(count + 1)
            })
            .is_err()
        {
            CAPACITY.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if RETAINED_BYTES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (bytes <= MAX_RETAINED_BYTES - used).then_some(used + bytes)
            })
            .is_err()
        {
            // 字节预算失败必须补偿先取得的名额，避免失败请求耗尽空等待槽。
            WAITERS.fetch_sub(1, Ordering::AcqRel);
            CAPACITY.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(Self {
            bytes,
        })
    }
}

impl Drop for Retained {
    /// 业务作用：等待任务结束、帧实际交付或取消时恰好归还一次保留容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归还字节及一个等待槽，不创建后台清理任务。
    fn drop(&mut self) {
        RETAINED_BYTES.fetch_sub(self.bytes, Ordering::AcqRel);
        WAITERS.fetch_sub(1, Ordering::AcqRel);
    }
}
