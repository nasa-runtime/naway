//! 当前路由的HTTP入口事实；计数随配置所有者退出，不保存请求身份或历史。

mod snapshot;
pub(crate) use snapshot::{capture, Reading, Snapshot, MAX_ROUTES};

use super::{metrics::BOUNDS_MS, Outcome};
use http::request::Parts;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub(crate) struct Counters {
    requests: AtomicU64,
    active: AtomicU64,
    responses: [AtomicU64; 5],
    bytes: AtomicU64,
    outcomes: [AtomicU64; 4],
    duration_micros: AtomicU64,
    buckets: [AtomicU64; 13],
    sentinel_rejections: [AtomicU64; 5],
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Totals {
    pub requests: u64,
    pub active: u64,
    pub responses: [u64; 5],
    pub bytes: u64,
    pub outcomes: [u64; 4],
    pub duration_micros: u64,
    pub buckets: [u64; 13],
    #[serde(default)]
    pub sentinel_rejections: Option<[u64; 5]>,
}

impl Counters {
    /// 业务作用：为首次公开入口取得唯一在途占用，重试与内部转路由不再进入此入口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：累计一次命中并增加一个在途响应，不分配请求级状态。
    pub(super) fn start(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：按最终下游响应头记录状态类别，避免把上游尝试或改写前状态当作入口结果。
    ///
    /// 参数说明：
    /// - `status`：最终响应的HTTP状态码。
    ///
    /// 返回：合法类别累计一次；扩展状态不混入标准类别。
    pub(super) fn headers(&self, status: u16) {
        if let Some(counter) = status.checked_div(100).and_then(|class| {
            class
                .checked_sub(1)
                .and_then(|index| self.responses.get(usize::from(index)))
        }) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 业务作用：只记录正文观察器实际交付的编码实体字节，不读取或复制帧内容。
    ///
    /// 参数说明：
    /// - `length`：本次DATA帧长度，不包含协议开销与trailers。
    ///
    /// 返回：更新原路由所有者的输出累计，旧代完成不会写入新归属。
    pub(super) fn bytes(&self, length: usize) {
        self.bytes.fetch_add(length as u64, Ordering::Relaxed);
    }

    /// 业务作用：随唯一观察器结算响应并归还在途量，只有实际EOF进入完整耗时分布。
    ///
    /// 参数说明：
    /// - `outcome`：本地正文交付边界的最终结局。
    /// - `elapsed`：从统一HTTP入口至当前终态的单调耗时。
    ///
    /// 返回：累计终态并减少一个在途占用；调用方必须保证只调用一次。
    pub(super) fn finish(&self, outcome: Outcome, elapsed: Duration) {
        self.outcomes[outcome as usize].fetch_add(1, Ordering::Relaxed);
        if matches!(outcome, Outcome::Eof) {
            self.duration_micros.fetch_add(
                elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );
            let index =
                BOUNDS_MS.partition_point(|bound| elapsed.as_micros() > u128::from(*bound) * 1000);
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// 业务作用：读取当前路由的固定原子事实，不持锁或枚举请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有限弱一致累计快照，区间读取方仍需检查各累计值是否回退。
    pub(crate) fn read(&self) -> Totals {
        Totals {
            requests: self.requests.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            responses: std::array::from_fn(|index| self.responses[index].load(Ordering::Relaxed)),
            bytes: self.bytes.load(Ordering::Relaxed),
            outcomes: std::array::from_fn(|index| self.outcomes[index].load(Ordering::Relaxed)),
            duration_micros: self.duration_micros.load(Ordering::Relaxed),
            buckets: std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed)),
            sentinel_rejections: Some(std::array::from_fn(|index| {
                self.sentinel_rejections[index].load(Ordering::Relaxed)
            })),
        }
    }
}

/// Sentinel 明确裁决的固定目录，数组顺序同时用于管理协议和当前区间展示。
#[derive(Clone, Copy)]
pub(crate) enum SentinelRejection {
    Rate = 0,
    Concurrency = 1,
    Queue = 2,
    QueueUnavailable = 3,
    QueueRetired = 4,
}

#[derive(Clone)]
struct SentinelOwner(Arc<Counters>);

/// 业务作用：在首次公开路由命中时冻结防护计数所有者，父层、叶子和内部跳转不能重新归属。
///
/// 参数说明：
/// - `parts`：当前请求的原生扩展，不读取客户端提供的身份。
/// - `counters`：同一配置快照编译的公开入口计数。
///
/// 返回：仅首次绑定保留一个共享引用；后续选择不创建第二份计数或改变归属。
pub(crate) fn select_sentinel_owner(parts: &mut Parts, counters: &Arc<Counters>) {
    if parts.extensions.get::<SentinelOwner>().is_none() {
        parts.extensions.insert(SentinelOwner(counters.clone()));
    }
}

/// 业务作用：在实际 Sentinel 拒绝分支记录明确裁决，不由最终响应状态推断防护行为。
///
/// 参数说明：
/// - `parts`：仍持有首次公开入口所有者的当前请求。
/// - `reason`：速率、并发或队列拒绝的固定类别。
///
/// 返回：存在入口所有者时只更新原配置代；未命中公开入口时不制造工作区事实。
pub(crate) fn record_sentinel_rejection(parts: &Parts, reason: SentinelRejection) {
    if let Some(owner) = parts.extensions.get::<SentinelOwner>() {
        owner.0.sentinel_rejections[reason as usize].fetch_add(1, Ordering::Relaxed);
    }
}
