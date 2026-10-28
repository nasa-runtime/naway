//! 双向带宽整形、滑动窗口/漏桶限额与超额动作。
//!
//! 与既有 `limit_rate` 的关键差别有两点,都是正确性而非功能性的:
//!
//! 1. **共享作用域**。`limit_rate` 的桶挂在单个响应上,同一 consumer 并发 10 条流就能
//!    拿到 10 倍带宽,配额形同虚设。本模块的桶按 scope+key 共享,并发流之间真实竞争。
//! 2. **逐帧整形**。带宽判定只依赖当前 frame 的字节数,任何时候都不缓冲完整 body——
//!    否则限速本身会把流式响应变成一次性大包,把内存压力从后端搬到网关。
//!
//! 共享桶用 GCRA(虚拟调度)而不是"读令牌-判断-写令牌":后者在并发预留下会互相覆盖,
//! 导致实际放行速率高于配置。GCRA 把状态压缩成一个"理论到达时刻",每次预留原子推进,
//! 并发正确性由推进本身保证。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};

use crate::upstream::load::{monotonic_ms, monotonic_ns};

pub(crate) mod metrics;
pub(crate) mod pacing;
#[cfg(feature = "redis-runtime")]
pub(crate) mod redis;
pub(crate) mod resources;
pub(crate) mod usage;

/// 单个限额维度表允许的最大活动 key 数,防止攻击者用高基数 key 打爆内存。
pub const MAX_ACTIVE_KEYS: usize = 65_536;

// ---------------------------------------------------------------------------
// 带宽整形
// ---------------------------------------------------------------------------

/// 单方向带宽策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandwidthPolicy {
    /// 稳态速率(字节/秒)。
    pub bytes_per_second: u64,
    /// 突发容量(字节):允许短时间超过稳态速率的额度。
    pub burst_bytes: u64,
    /// 前 N 字节不整形,对齐 nginx `limit_rate_after` 的"小响应不受影响"语义。
    pub after_bytes: u64,
    /// 每帧允许的最长等待；超过边界不再生成带宽债务。
    pub max_wait: Duration,
}

impl BandwidthPolicy {
    /// 业务作用：校验带宽策略,拒绝会导致整形失效或永久挂起的取值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法返回 `Ok`;速率为 0 时返回错误——0 会让每一帧都等待无穷久,
    /// 表现为连接静默挂死,必须在配置期就拒绝而不是留到运行期。
    pub fn validate(&self) -> Result<()> {
        if self.bytes_per_second == 0 {
            bail!("bandwidth.bytes_per_second 必须大于 0");
        }
        if self.max_wait.is_zero() || self.max_wait > Duration::from_millis(resources::MAX_WAIT_MS)
        {
            bail!("bandwidth.max_wait_ms 必须在 1..=60000");
        }
        Ok(())
    }

    /// 业务作用：把突发字节额度换算成 GCRA 的时间容忍宽度。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：按当前稳态速率折算的纳秒数。
    fn burst_tolerance_ns(&self) -> u64 {
        ns_for_bytes(self.burst_bytes, self.bytes_per_second)
    }
}

/// 业务作用：把字节成本换算成指定速率下的理论发送时长。
///
/// 参数说明：
/// - `bytes`：是数据量
/// - `bytes_per_second`：是稳态速率。
///
/// 返回：向上取整的纳秒数，并在数值超界时饱和。
fn ns_for_bytes(bytes: u64, bytes_per_second: u64) -> u64 {
    if bytes == 0 {
        return 0;
    }
    let rate = bytes_per_second.max(1) as u128;
    let nanos = (bytes as u128)
        .saturating_mul(1_000_000_000_u128)
        .div_ceil(rate);
    nanos.min(u64::MAX as u128) as u64
}

/// 共享带宽桶。同一 scope+key 下的所有并发流共用一个实例。
#[derive(Debug)]
pub struct BandwidthBucket {
    _workspace_lease: Option<crate::control::ownership::state::Lease>,
    /// GCRA 的理论到达时刻(纳秒);所有并发预留都原子推进它。
    tat_ns: AtomicU64,
    /// 已整形字节数,用于观测。
    shaped_bytes: AtomicU64,
}

impl Default for BandwidthBucket {
    /// 业务作用：构造没有历史债务与累计字节的共享带宽桶。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：理论到达时刻为零的空桶。
    fn default() -> Self {
        Self {
            _workspace_lease: None,
            tat_ns: AtomicU64::new(0),
            shaped_bytes: AtomicU64::new(0),
        }
    }
}

impl BandwidthBucket {
    /// 业务作用：为一帧数据预留带宽,返回发送前应当等待的时长。
    ///
    /// 这是 GCRA:每次预留把理论到达时刻推进 `bytes/rate`,并允许在突发容忍范围内提前发送。
    /// 因为推进是 CAS 原子的,N 条并发流各自预留后得到的是**互不重叠**的发送时刻,
    /// 合起来恰好等于配置速率;这正是"读-判断-写"式实现做不到的地方。
    ///
    /// 参数说明：
    /// - `policy`：是该方向的带宽策略
    /// - `bytes`：是本帧的数据字节数。
    ///
    /// 返回：需要等待的时长；超过期限或数值边界时拒绝且不推进债务。
    pub fn reserve(&self, policy: &BandwidthPolicy, bytes: u64) -> Result<Duration> {
        if bytes == 0 {
            return Ok(Duration::ZERO);
        }
        if policy.bytes_per_second == 0 {
            bail!("bandwidth rate is unavailable");
        }
        let cost_ns = ns_for_bytes(bytes, policy.bytes_per_second);
        let tolerance_ns = policy.burst_tolerance_ns();
        let now = monotonic_ns();

        let mut current = self.tat_ns.load(Ordering::Relaxed);
        loop {
            // 桶长期空闲时理论到达时刻会落后于当前时间,此时以 now 为基准重新起算,
            // 否则空闲越久攒下的"信用"越多,一开闸就是不受限的洪峰。
            let base = current.max(now);
            let next = base
                .checked_add(cost_ns)
                .ok_or_else(|| anyhow::anyhow!("bandwidth schedule exceeds numeric capacity"))?;
            // 整帧成本都必须进入发送时刻；按帧起点放行会使任意大首帧绕过 burst。
            let delay = Duration::from_nanos(next.saturating_sub(tolerance_ns).saturating_sub(now));
            if delay > policy.max_wait {
                // 尚未提交就拒绝，防止不可能等待的请求把共享桶推入长时间保护态。
                metrics::DEADLINE.fetch_add(1, Ordering::Relaxed);
                bail!("bandwidth wait deadline exceeded");
            }
            match self.tat_ns.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let _ = self.shaped_bytes.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |current| Some(current.saturating_add(bytes)),
                    );
                    return Ok(delay);
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// 业务作用：读取累计进入整形器的数据量，供低基数指标导出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：累计整形字节数，达到数值上限后保持饱和。
    pub fn shaped_bytes(&self) -> u64 {
        self.shaped_bytes.load(Ordering::Relaxed)
    }

    /// 业务作用：判断共享桶是否已无活动流且所有已预留发送时刻均已过去，可安全回收。
    ///
    /// 参数说明：
    /// - `now_ns`：是当前单调时钟纳秒值。
    ///
    /// 返回：理论到达时刻不晚于当前时刻时返回 `true`；调用方还需复验 `Arc` 独占。
    fn schedule_expired(&self, now_ns: u64) -> bool {
        self.tat_ns.load(Ordering::Acquire) <= now_ns
    }
}

/// 带宽桶注册表:按 scope+key 复用共享桶。
#[derive(Debug, Default)]
pub struct BandwidthRegistry {
    buckets: Mutex<BandwidthEntries>,
}

#[derive(Debug, Default)]
struct BandwidthEntries {
    values: HashMap<String, Arc<BandwidthBucket>>,
    platform: usize,
}

impl crate::control::ownership::state::ReclaimExpired for BandwidthRegistry {
    /// 业务作用：在其它路由申请状态容量时回收无活动流且无未到期债务的带宽桶。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只撤下可安全回收的目录引用；非阻塞锁避免工作区预算回调反向等待当前整形路径。
    fn reclaim_expired(&self) {
        let Ok(mut buckets) = self.buckets.try_lock() else {
            return;
        };
        let now = monotonic_ns();
        buckets
            .values
            .retain(|_, bucket| Arc::strong_count(bucket) > 1 || !bucket.schedule_expired(now));
        buckets.platform = buckets
            .values
            .values()
            .filter(|bucket| bucket._workspace_lease.is_none())
            .count();
    }
}

impl BandwidthRegistry {
    /// 业务作用：取得(或建立)指定维度的共享带宽桶。
    ///
    /// 参数说明：
    /// - `scope`：是策略作用域
    /// - `key`：是 consumer、API-Key 或客户端地址等维度值。
    ///
    /// 返回：共享桶;维度表已达上限且该 key 尚未存在时返回 `None`,
    /// 调用方按策略选择 fail-open 或 fail-closed，不能私自新建条目绕过容量上限。
    pub fn bucket(&self, scope: &str, key: &str) -> Option<Arc<BandwidthBucket>> {
        self.bucket_with_budget(scope, key, None)
    }

    /// 业务作用：创建带宽状态前计入受信工作区预算，平台表与租户表容量互不挤占。
    ///
    /// 参数说明：
    /// - `scope`：为固定状态域与维度
    /// - `key`：为固定状态域与维度
    /// - `budget`：来自路由快照，平台为空。
    ///
    /// 返回：已有桶或新桶；无名额且不存在可安全回收状态时不创建条目。
    pub(crate) fn bucket_with_budget(
        &self,
        scope: &str,
        key: &str,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> Option<Arc<BandwidthBucket>> {
        let composite = format!("{scope}\u{1}{key}");
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(found) = buckets.values.get(&composite) {
            return Some(found.clone());
        }
        let mut lease = budget.map(|budget| budget.acquire());
        if lease.as_ref().is_some_and(Result::is_err)
            || (budget.is_none() && buckets.platform >= MAX_ACTIVE_KEYS)
        {
            // 只有没有活动流且已预留发送时刻全部过去的桶才可回收；过早重建同一维度
            // 会产生两个并行桶，让调用方通过制造高基数条目重置带宽债务。
            let now_ns = monotonic_ns();
            buckets.values.retain(|_, bucket| {
                Arc::strong_count(bucket) > 1 || !bucket.schedule_expired(now_ns)
            });
            buckets.platform = buckets
                .values
                .values()
                .filter(|bucket| bucket._workspace_lease.is_none())
                .count();
            lease = budget.map(|budget| budget.acquire());
            if budget.is_none() && buckets.platform >= MAX_ACTIVE_KEYS {
                return None;
            }
        }
        let lease = lease.transpose().ok()?;
        let bucket = Arc::new(BandwidthBucket {
            _workspace_lease: lease,
            ..BandwidthBucket::default()
        });
        if budget.is_none() {
            buckets.platform += 1;
        }
        buckets.values.insert(composite, bucket.clone());
        Some(bucket)
    }

    /// 业务作用：reload 后清掉不再被任何策略引用的维度,避免旧作用域常驻内存。
    ///
    /// 参数说明：
    /// - `keep`：判定某个复合 key 是否仍然有效。
    ///
    /// 返回：无返回值。
    pub fn retain<F: Fn(&str) -> bool>(&self, keep: F) {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buckets.values.retain(|composite, _| keep(composite));
        buckets.platform = buckets
            .values
            .values()
            .filter(|bucket| bucket._workspace_lease.is_none())
            .count();
    }

    /// 业务作用：读取注册表内当前维度数，供容量观测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前缓存的共享桶数量。
    pub fn len(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values
            .len()
    }

    /// 业务作用：判断带宽维度表是否为空。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有缓存桶时返回 `true`。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 逐帧整形器:把共享桶的预留结果转成"这一帧等多久"。
///
/// 独立成结构是因为 `after_bytes` 是**每条流**的语义(前 N 字节不限速),
/// 而速率配额是**跨流共享**的;两者混在一个对象里会让其中之一失去本来的含义。
#[derive(Debug)]
pub struct FrameShaper {
    bucket: Arc<BandwidthBucket>,
    policy: BandwidthPolicy,
    after_remaining: u64,
}

impl FrameShaper {
    /// 业务作用：为一条流建立整形器。
    ///
    /// 参数说明：
    /// - `bucket`：是该维度的共享带宽桶
    /// - `policy`：是方向策略。
    ///
    /// 返回：整形器实例。
    pub fn new(bucket: Arc<BandwidthBucket>, policy: BandwidthPolicy) -> Self {
        Self {
            after_remaining: policy.after_bytes,
            bucket,
            policy,
        }
    }

    /// 业务作用：计算本帧发送前需要等待的时长。
    ///
    /// 参数说明：
    /// - `len`：是本帧数据字节数；非 data frame 传 0。
    ///
    /// 返回：严格满足共享桶预留顺序的等待时长；超过单帧期限时拒绝，不能截断等待后放行。
    pub fn delay_for(&mut self, len: u64) -> Result<Duration> {
        if len == 0 {
            return Ok(Duration::ZERO);
        }
        // after_bytes 内的字节完全不进桶,否则小响应也会被计入共享配额,
        // 与 nginx `limit_rate_after` 的语义不符。
        if self.after_remaining >= len {
            self.after_remaining -= len;
            return Ok(Duration::ZERO);
        }
        let limited = len - self.after_remaining;
        self.after_remaining = 0;
        self.bucket.reserve(&self.policy, limited)
    }
}

// ---------------------------------------------------------------------------
// 限额窗口:滑动窗口与漏桶
// ---------------------------------------------------------------------------

/// 限额算法。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitAlgorithm {
    /// 固定窗口:实现最简单,但窗口边界可以放行两倍额度。
    FixedWindow,
    /// 滑动窗口:用上一窗口的加权残值消除边界双倍放行。
    SlidingWindow,
    /// 漏桶:恒定速率漏出,天然平滑,不允许突发。
    LeakyBucket,
}

impl LimitAlgorithm {
    /// 业务作用：解析配置中的算法名。
    ///
    /// 参数说明：
    /// - `raw`：为配置字符串。
    ///
    /// 返回：识别成功返回算法;未知取值返回错误,而不是静默退回默认值——
    /// 静默退化会让运维以为配了滑动窗口,实际跑的是固定窗口。
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fixed_window" | "fixed" => Ok(Self::FixedWindow),
            "sliding_window" | "sliding" => Ok(Self::SlidingWindow),
            "leaky_bucket" | "leaky" => Ok(Self::LeakyBucket),
            other => bail!("未知限额算法 `{other}`,可选 fixed_window|sliding_window|leaky_bucket"),
        }
    }
}

/// 超额动作。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OverflowAction {
    /// 直接拒绝并返回标准限额响应头。
    Reject,
    /// 排队等待额度;队列长度与等待时长都必须有界。
    Delay {
        /// 队列最大长度;超过直接拒绝,避免把过载变成无界内存增长。
        max_queue: u64,
        /// 单个请求最长等待(ms);超过按拒绝处理。
        max_wait_ms: u64,
    },
}

/// 单个限额窗口的定义。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitWindow {
    /// 窗口内允许的额度。
    pub limit: u64,
    /// 窗口长度。
    pub window: Duration,
    /// 突发容量,仅对 FixedWindow/SlidingWindow 生效;漏桶按定义不接受突发。
    pub burst: u64,
}

impl LimitWindow {
    /// 业务作用：校验窗口定义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法返回 `Ok`;limit 为 0 或窗口为 0 时返回错误。
    pub fn validate(&self) -> Result<()> {
        if self.limit == 0 {
            bail!("limit 必须大于 0");
        }
        if self.window.is_zero() {
            bail!("window 必须大于 0");
        }
        Ok(())
    }
}

/// 多窗口限额策略:所有窗口必须同时通过。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaPolicy {
    /// 算法。
    pub algorithm: LimitAlgorithm,
    /// 并行窗口集合,例如同时限 100/秒 与 1000/分钟。
    pub windows: Vec<LimitWindow>,
    /// 超额动作。
    pub overflow: OverflowAction,
}

impl QuotaPolicy {
    /// 业务作用：校验策略整体。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法返回 `Ok`;窗口为空或任一窗口非法时返回错误。
    pub fn validate(&self) -> Result<()> {
        if self.windows.is_empty() {
            bail!("quota 至少需要一个窗口");
        }
        if self.windows.len() > 16 {
            bail!("quota 窗口数不得超过 16:每次请求必须同步判定全部窗口");
        }
        for window in &self.windows {
            window.validate()?;
        }
        if let OverflowAction::Delay {
            max_queue,
            max_wait_ms,
        } = self.overflow
        {
            if !(1..=resources::MAX_WAITERS).contains(&max_queue) {
                bail!("overflow=delay 时 max_queue 必须在 1..=4096");
            }
            if !(1..=resources::MAX_WAIT_MS).contains(&max_wait_ms) {
                bail!("overflow=delay 时 max_wait_ms 必须在 1..=60000");
            }
        }
        Ok(())
    }
}

/// 单个窗口的运行态。
#[derive(Debug, Default)]
struct WindowState {
    /// 当前窗口计数。
    current: u64,
    /// 上一窗口计数,滑动窗口用它做加权。
    previous: u64,
    /// 当前窗口起点(ms)。
    started_ms: u64,
    /// 漏桶的理论到达时刻(ns)。
    tat_ns: u64,
    /// 累计退款引起的时间前移；旧凭据据此扣除已经被其它结算移走的历史债务。
    refunded_ns: u128,
}

/// 一次限额判定结果。
#[derive(Clone, Copy, Debug)]
pub struct QuotaDecision {
    /// 是否放行。
    pub allowed: bool,
    /// 最紧窗口的剩余额度。
    pub remaining: u64,
    /// 最紧窗口的额度上限,用于 `RateLimit-Limit`。
    pub limit: u64,
    /// 距离额度恢复还需多久,用于 `RateLimit-Reset` 与 `Retry-After`。
    pub reset_after: Duration,
    /// 超额时建议等待的时长;`OverflowAction::Delay` 下调用方据此排队。
    pub retry_after: Duration,
}

/// 一次已提交限额预留的结算凭据。
///
/// 凭据记录预留所在窗口代次；响应跨越窗口时，返还只能落回仍有影响的历史窗口，
/// 不能误减新窗口中其它请求的消费。
#[derive(Clone, Debug)]
pub struct QuotaReservation {
    started_ms: Box<[u64]>,
    reserved: u64,
    /// 漏桶预留段的结束时刻；已经自然流出的部分不能再用来抵消其它请求的债务。
    leaky: Option<Box<[LeakyReservation]>>,
}

#[derive(Clone, Debug)]
struct LeakyReservation {
    end_ns: u64,
    refunded_ns: u128,
}

/// 多窗口限额运行态。
#[derive(Debug, Default)]
pub struct QuotaState {
    pub(crate) workspace_lease: Option<crate::control::ownership::state::Lease>,
    windows: Mutex<Vec<WindowState>>,
    /// 当前排队等待的请求数,`Delay` 动作据此限制队列长度。
    queued: AtomicU64,
    /// 最近一次账本判定时刻，用于只回收已经完全过期的高基数维度。
    last_seen_ms: AtomicU64,
    /// 当前语义下账本需要保留的最长空闲时间。
    retention_ms: AtomicU64,
}

impl QuotaState {
    /// 业务作用：将额度账本与已预留的工作区状态名额绑定，随最后一个账本引用归还。
    ///
    /// 参数说明：
    /// - `workspace_lease`：为已取得名额，平台账本为空。
    ///
    /// 返回：无历史额度的空账本。
    pub(crate) fn with_workspace_lease(
        workspace_lease: Option<crate::control::ownership::state::Lease>,
    ) -> Self {
        Self {
            workspace_lease,
            ..Self::default()
        }
    }
    /// 业务作用：对一次成本为 `cost` 的请求做多窗口限额判定。
    ///
    /// 所有窗口必须同时通过;任一窗口不通过即整体拒绝,并以**最紧**的那个窗口
    /// 决定回给客户端的 `Retry-After`——回一个乐观的时间会让客户端立刻重试,
    /// 把超额流量原样打回来。
    ///
    /// 参数说明：
    /// - `policy`：是限额策略
    /// - `cost`：是本次消耗额度，普通 QPS 为 1。
    ///
    /// 返回：判定结果;放行时额度已被扣减,拒绝时不扣减任何窗口。
    pub fn check(&self, policy: &QuotaPolicy, cost: u64) -> QuotaDecision {
        self.check_with_reservation(policy, cost).0
    }

    /// 业务作用：执行多窗口准入并在成功时返回与本次扣减绑定的结算凭据。
    ///
    /// 参数说明：
    /// - `policy`：是限额策略
    /// - `cost`：是准入期预留额度。
    ///
    /// 返回：判定结果及可选结算凭据；拒绝时不扣账且凭据为 `None`。
    pub fn check_with_reservation(
        &self,
        policy: &QuotaPolicy,
        cost: u64,
    ) -> (QuotaDecision, Option<QuotaReservation>) {
        let now_ms = monotonic_ms();
        let now_ns = monotonic_ns();
        self.last_seen_ms.store(now_ms, Ordering::Release);
        let retention_ms = policy
            .windows
            .iter()
            .map(|window| window.window.as_millis().min(u64::MAX as u128) as u64)
            .max()
            .unwrap_or(1)
            .saturating_mul(2);
        let _ = self
            .retention_ms
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.max(retention_ms))
            });
        let mut states = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if states.len() != policy.windows.len() {
            states.clear();
            states.resize_with(policy.windows.len(), WindowState::default);
        }

        // 先做**只读**的预检:任一窗口不通过就整体拒绝,一个额度都不扣。
        // 先扣后回滚在并发下会短暂对外表现为额度已用尽,导致本可放行的请求被误拒。
        let mut worst: Option<QuotaDecision> = None;
        let mut tightest_remaining = u64::MAX;
        let mut tightest_limit = 0_u64;
        let mut tightest_reset = Duration::ZERO;
        for (state, window) in states.iter_mut().zip(policy.windows.iter()) {
            roll_window(state, window, now_ms);
            let probe = probe_window(state, window, policy.algorithm, cost, now_ms, now_ns);
            if !probe.allowed {
                let replace = worst
                    .as_ref()
                    .is_none_or(|current| probe.retry_after > current.retry_after);
                if replace {
                    worst = Some(probe);
                }
            }
            if probe.remaining < tightest_remaining {
                tightest_remaining = probe.remaining;
                tightest_limit = probe.limit;
                tightest_reset = probe.reset_after;
            }
        }
        if let Some(mut rejected) = worst {
            rejected.remaining = tightest_remaining.min(rejected.remaining);
            return (rejected, None);
        }

        // 全部窗口预检通过后统一提交。
        let started_ms = states
            .iter()
            .map(|state| state.started_ms)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        for (state, window) in states.iter_mut().zip(policy.windows.iter()) {
            commit_window(state, window, policy.algorithm, cost, now_ns);
        }
        let leaky = (policy.algorithm == LimitAlgorithm::LeakyBucket).then(|| {
            states
                .iter()
                .map(|state| LeakyReservation {
                    end_ns: state.tat_ns,
                    refunded_ns: state.refunded_ns,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        (
            QuotaDecision {
                allowed: true,
                remaining: tightest_remaining.saturating_sub(cost),
                limit: tightest_limit,
                reset_after: tightest_reset,
                retry_after: Duration::ZERO,
            },
            Some(QuotaReservation {
                started_ms,
                reserved: cost,
                leaky,
            }),
        )
    }

    /// 业务作用：按响应事实成本补扣或返还准入预留，使成本型配额最终与实际消耗一致。
    ///
    /// 参数说明：
    /// - `policy`：是准入时的同一策略
    /// - `reservation`：是成功准入返回的凭据
    /// - `actual`：是从可信响应数据面观测到的最终额度。
    ///
    /// 返回：无；补扣形成后续请求可见的额度债务，返还不会跨代误减新窗口消费。
    pub fn settle(&self, policy: &QuotaPolicy, reservation: QuotaReservation, actual: u64) {
        if actual == reservation.reserved {
            return;
        }
        let now_ms = monotonic_ms();
        let now_ns = monotonic_ns();
        self.last_seen_ms.store(now_ms, Ordering::Release);
        let mut states = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if states.len() != policy.windows.len() || states.len() != reservation.started_ms.len() {
            return;
        }
        for (index, ((state, window), admitted_start)) in states
            .iter_mut()
            .zip(policy.windows.iter())
            .zip(reservation.started_ms.iter().copied())
            .enumerate()
        {
            roll_window(state, window, now_ms);
            match policy.algorithm {
                LimitAlgorithm::LeakyBucket => {
                    let window_ns = window.window.as_nanos().min(u64::MAX as u128) as u64;
                    let per_unit_ns = window_ns.div_ceil(window.limit.max(1)).max(1);
                    if actual > reservation.reserved {
                        state.tat_ns = state.tat_ns.max(now_ns).saturating_add(
                            per_unit_ns.saturating_mul(actual - reservation.reserved),
                        );
                    } else {
                        // 只返还本预留仍未自然流出的时间，过期凭据不能抵消后来请求的消费。
                        let outstanding = reservation
                            .leaky
                            .as_ref()
                            .and_then(|ends| ends.get(index))
                            .map_or(0, |admitted| {
                                let shifted =
                                    state.refunded_ns.saturating_sub(admitted.refunded_ns);
                                admitted
                                    .end_ns
                                    .saturating_sub(shifted.min(u128::from(u64::MAX)) as u64)
                                    .saturating_sub(now_ns)
                            });
                        let refund = per_unit_ns
                            .saturating_mul(reservation.reserved - actual)
                            .min(outstanding)
                            .min(state.tat_ns.saturating_sub(now_ns));
                        state.tat_ns = state.tat_ns.saturating_sub(refund).max(now_ns);
                        state.refunded_ns = state.refunded_ns.saturating_add(u128::from(refund));
                    }
                }
                LimitAlgorithm::FixedWindow => {
                    if state.started_ms == admitted_start {
                        settle_counter(&mut state.current, reservation.reserved, actual);
                    } else if actual > reservation.reserved {
                        // 原预留窗口已经失效，无法返还；额外事实成本仍需记入当前窗口，
                        // 否则长响应可以通过跨窗逃掉补扣。
                        state.current = state.current.saturating_add(actual - reservation.reserved);
                    }
                }
                LimitAlgorithm::SlidingWindow => {
                    if state.started_ms == admitted_start {
                        settle_counter(&mut state.current, reservation.reserved, actual);
                    } else if actual > reservation.reserved {
                        state.current = state.current.saturating_add(actual - reservation.reserved);
                    } else {
                        let window_ms =
                            window.window.as_millis().max(1).min(u64::MAX as u128) as u64;
                        if now_ms.saturating_sub(admitted_start) < window_ms.saturating_mul(2) {
                            state.previous =
                                state.previous.saturating_sub(reservation.reserved - actual);
                        }
                    }
                }
            }
        }
    }

    /// 业务作用：为一次 `Delay` 排队占位,保证队列长度有界。
    ///
    /// 参数说明：
    /// - `max_queue`：为允许的最大排队数。
    ///
    /// 返回：占位成功返回 RAII 令牌(Drop 自动释放);队列已满返回 `None`,
    /// 调用方必须按拒绝处理——排队本身是有成本的,无界排队会把过载
    /// 从"快速拒绝"变成"内存耗尽"。
    pub fn enqueue(self: &Arc<Self>, max_queue: u64) -> Option<QueueSlot> {
        let mut queued = self.queued.load(Ordering::Relaxed);
        loop {
            if queued >= max_queue {
                return None;
            }
            match self.queued.compare_exchange_weak(
                queued,
                queued + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(QueueSlot {
                        state: self.clone(),
                    })
                }
                Err(observed) => queued = observed,
            }
        }
    }

    /// 业务作用：读取当前排队请求数，供容量与过载观测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仍持有排队名额的请求数量。
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }

    /// 业务作用：判断该维度的全部窗口历史是否已经自然失效，可安全从高基数注册表回收。
    ///
    /// 参数说明：
    /// - `now_ms`：是当前单调时钟毫秒值。
    ///
    /// 返回：没有排队请求且空闲时间超过最长状态影响周期时返回 `true`。
    pub fn evictable(&self, now_ms: u64) -> bool {
        let expired = self.queued.load(Ordering::Acquire) == 0
            && now_ms.saturating_sub(self.last_seen_ms.load(Ordering::Acquire))
                >= self.retention_ms.load(Ordering::Acquire).max(1);
        if !expired {
            return false;
        }
        // 响应补扣可形成超过两个窗口的漏桶债务，不能按空闲时间重建一份无债额度。
        let Ok(states) = self.windows.try_lock() else {
            return false;
        };
        let now_ns = monotonic_ns();
        states.iter().all(|state| state.tat_ns <= now_ns)
    }
}

/// 排队占位的 RAII 令牌;Drop 即释放,取消与超时路径也不会泄漏队列长度。
pub struct QueueSlot {
    state: Arc<QuotaState>,
}

impl Drop for QueueSlot {
    /// 业务作用：在请求离队、超时或取消时归还限额排队位置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn drop(&mut self) {
        self.state.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 业务作用：推进限额窗口边界，并为滑动窗口保留仍有影响的上一窗口计数。
///
/// 参数说明：
/// - `state`：是窗口状态
/// - `window`：是窗口定义
/// - `now_ms`：是当前单调毫秒。
///
/// 返回：无；跨过两个以上窗口时清除已经失效的历史。
fn roll_window(state: &mut WindowState, window: &LimitWindow, now_ms: u64) {
    let window_ms = window.window.as_millis().max(1).min(u64::MAX as u128) as u64;
    if state.started_ms == 0 {
        state.started_ms = now_ms;
        return;
    }
    let elapsed = now_ms.saturating_sub(state.started_ms);
    if elapsed < window_ms {
        return;
    }
    // 跨越多个窗口时上一窗口的残值已经完全无关,直接清零;
    // 保留它会让长时间空闲后的第一个请求被历史流量误伤。
    if elapsed >= window_ms.saturating_mul(2) {
        state.previous = 0;
    } else {
        state.previous = state.current;
    }
    state.current = 0;
    // 沿既有边界推进，访问频率不能重置滑动残值的衰减周期。
    state.started_ms = now_ms - elapsed % window_ms;
}

/// 业务作用：只读预检单个窗口能否容纳成本，供多窗口全部通过后统一提交。
///
/// 参数说明：
/// - `state`：是当前状态与定义
/// - `window`：是当前状态与定义
/// - `algorithm`：是算法
/// - `cost`：是待扣额度
/// - `now_ms`：是同一判定时刻的单调时间。
/// - `now_ns`：是同一判定时刻的单调时间。
///
/// 返回：该窗口的准入、余额与恢复时间，不修改账本。
fn probe_window(
    state: &WindowState,
    window: &LimitWindow,
    algorithm: LimitAlgorithm,
    cost: u64,
    now_ms: u64,
    now_ns: u64,
) -> QuotaDecision {
    let window_ms = window.window.as_millis().max(1).min(u64::MAX as u128) as u64;
    let elapsed = now_ms.saturating_sub(state.started_ms).min(window_ms);
    let reset_after = Duration::from_millis(window_ms.saturating_sub(elapsed));

    match algorithm {
        LimitAlgorithm::LeakyBucket => {
            // 漏桶按恒定速率漏出:limit 个额度均匀铺满整个窗口。
            let window_ns = window.window.as_nanos().min(u64::MAX as u128) as u64;
            let per_unit_ns = window_ns.div_ceil(window.limit.max(1)).max(1);
            let cost_ns = per_unit_ns.saturating_mul(cost);
            let base = state.tat_ns.max(now_ns);
            let next = base.saturating_add(cost_ns);
            // 漏桶不接受突发,允许的最大在途量就是一个窗口的宽度。
            let horizon = now_ns.saturating_add(window_ns);
            let allowed = next <= horizon;
            let wait = base.saturating_sub(now_ns);
            QuotaDecision {
                allowed,
                remaining: horizon.saturating_sub(base) / per_unit_ns.max(1),
                limit: window.limit,
                reset_after,
                retry_after: Duration::from_nanos(wait),
            }
        }
        LimitAlgorithm::FixedWindow => {
            let capacity = window.limit.saturating_add(window.burst);
            let used = state.current;
            let allowed = used.saturating_add(cost) <= capacity;
            QuotaDecision {
                allowed,
                remaining: capacity.saturating_sub(used),
                limit: window.limit,
                reset_after,
                retry_after: reset_after,
            }
        }
        LimitAlgorithm::SlidingWindow => {
            // 上一窗口按剩余比例加权计入,消除固定窗口边界处放行两倍额度的问题。
            let weight_num = window_ms.saturating_sub(elapsed);
            let weighted_previous =
                (state.previous as u128 * weight_num as u128) / (window_ms.max(1) as u128);
            let capacity = window.limit.saturating_add(window.burst);
            let used = state.current.saturating_add(weighted_previous as u64);
            let allowed = used.saturating_add(cost) <= capacity;
            QuotaDecision {
                allowed,
                remaining: capacity.saturating_sub(used.min(capacity)),
                limit: window.limit,
                reset_after,
                // 滑动窗口下额度是连续恢复的,不必等到整窗结束;
                // 回整窗会让客户端退避过久,浪费本来可用的额度。
                retry_after: estimate_sliding_wait(used, capacity, cost, window_ms, state.previous),
            }
        }
    }
}

/// 业务作用：估算滑动窗口恢复到可容纳指定成本所需的退避时间。
///
/// 参数说明：
/// - `used`：是加权使用量
/// - `capacity`：是容量
/// - `cost`：是待扣额度
/// - `window_ms`：是窗口长度
/// - `previous`：是上一窗口原始计数。
///
/// 返回：连续衰减可恢复时返回估算时长，否则返回完整窗口时长。
fn estimate_sliding_wait(
    used: u64,
    capacity: u64,
    cost: u64,
    window_ms: u64,
    previous: u64,
) -> Duration {
    let excess = used.saturating_add(cost).saturating_sub(capacity);
    if excess == 0 {
        return Duration::ZERO;
    }
    if previous == 0 {
        // 超额全部来自当前窗口,只能等当前窗口结束。
        return Duration::from_millis(window_ms);
    }
    // 上一窗口残值以 previous/window_ms 的速率退出,解出需要多久退够 excess。
    let need_ms = (excess as u128 * window_ms as u128).div_ceil(previous as u128);
    Duration::from_millis(need_ms.min(window_ms as u128) as u64)
}

/// 业务作用：在所有窗口预检通过后提交单窗口扣减，维持全有或全无的多窗口语义。
///
/// 参数说明：
/// - `state`：是运行态与定义
/// - `window`：是运行态与定义
/// - `algorithm`：是算法
/// - `cost`：是额度
/// - `now_ns`：是本次统一提交时刻。
///
/// 返回：无。
fn commit_window(
    state: &mut WindowState,
    window: &LimitWindow,
    algorithm: LimitAlgorithm,
    cost: u64,
    now_ns: u64,
) {
    match algorithm {
        LimitAlgorithm::LeakyBucket => {
            let window_ns = window.window.as_nanos().min(u64::MAX as u128) as u64;
            let per_unit_ns = window_ns.div_ceil(window.limit.max(1)).max(1);
            let cost_ns = per_unit_ns.saturating_mul(cost);
            state.tat_ns = state.tat_ns.max(now_ns).saturating_add(cost_ns);
        }
        LimitAlgorithm::FixedWindow | LimitAlgorithm::SlidingWindow => {
            state.current = state.current.saturating_add(cost);
        }
    }
}

/// 业务作用：把固定或滑动窗口中的预留值原子替换为事实值。
///
/// 参数说明：
/// - `counter`：是当前窗口计数
/// - `reserved`：是已扣预留
/// - `actual`：是事实成本。
///
/// 返回：无；补扣与返还均使用饱和运算，损坏或过期状态不会发生整数回绕。
fn settle_counter(counter: &mut u64, reserved: u64, actual: u64) {
    if actual >= reserved {
        *counter = counter.saturating_add(actual - reserved);
    } else {
        *counter = counter.saturating_sub(reserved - actual);
    }
}

// ---------------------------------------------------------------------------
// 成本型限额
// ---------------------------------------------------------------------------

/// 成本来源。决定"一次请求消耗多少额度"。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CostSource {
    /// 每请求固定成本,等价于传统 QPS 限流。
    PerRequest(u64),
    /// 按实际响应字节结算:先按 `reserve` 预留,响应结束后以事实字节补扣/返还。
    ResponseBytes {
        /// 预留额度。
        reserve: u64,
        /// 每多少字节记 1 个额度。
        bytes_per_unit: u64,
    },
    /// 按 gRPC message 条数结算。
    GrpcMessages {
        /// 预留额度。
        reserve: u64,
    },
    /// 按 GraphQL 已编译字段成本直接扣账，缺少完整查询证据时拒绝准入。
    GraphqlCost,
    /// 按可信来源提供的 usage 结算(如 AI provider 的 token 用量)。
    ///
    /// **只接受网关解析的 provider 事实或显式绑定的原始上游响应头**;客户端请求头一律不作数,
    /// 否则任何人都能靠伪造一个 `x-usage: 0` 把账本清零。
    TrustedUsage {
        /// 预留额度。
        reserve: u64,
        /// 结算上限,防止上游返回异常大的 usage 击穿账本。
        max_actual: u64,
    },
}

impl CostSource {
    /// 业务作用：为持久成本事件提供固定来源名称，不把路由、身份或金额作为协议字段名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与配置一致的低基数来源标识。
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::PerRequest(_) => "per_request",
            Self::ResponseBytes {
                ..
            } => "response_bytes",
            Self::GrpcMessages {
                ..
            } => "grpc_messages",
            Self::GraphqlCost => "graphql_cost",
            Self::TrustedUsage {
                ..
            } => "trusted_usage",
        }
    }
    /// 业务作用：给出该成本来源在**准入期**应当扣减的额度。
    ///
    /// 准入期往往还不知道真实成本(响应还没产生),因此这里返回的是保守预留值;
    /// 真实成本在响应结束后通过结算补扣或返还。先放行后计费会让超额流量
    /// 在被发现前就已经全部打到后端。
    ///
    /// 参数说明：
    /// - `query_cost`：仅来自网关完成解析的 GraphQL 查询或构建期冻结的模板。
    ///
    /// 返回：准入期扣减的额度；GraphQL 缺少可信成本时返回错误，不使用默认成本放行。
    pub fn admission_cost(&self, query_cost: Option<u64>) -> Result<u64> {
        Ok(match self {
            Self::PerRequest(cost) => *cost,
            Self::ResponseBytes {
                reserve,
                ..
            } => *reserve,
            Self::GrpcMessages {
                reserve,
            } => *reserve,
            Self::GraphqlCost => query_cost
                .filter(|cost| *cost > 0)
                .ok_or_else(|| anyhow::anyhow!("verified GraphQL cost is required"))?,
            Self::TrustedUsage {
                reserve,
                ..
            } => *reserve,
        })
    }

    /// 业务作用：把观测到的事实换算成最终额度,用于结算。
    ///
    /// 参数说明：
    /// - `observed`：是响应字节数、message 条数、GraphQL 成本或 usage token 数。
    ///
    /// 返回：最终额度;`TrustedUsage` 会按 `max_actual` 封顶。
    pub fn settle_cost(&self, observed: u64) -> u64 {
        match self {
            Self::PerRequest(cost) => *cost,
            Self::ResponseBytes {
                bytes_per_unit,
                ..
            } => observed.div_ceil((*bytes_per_unit).max(1)),
            Self::GrpcMessages {
                ..
            } => observed,
            Self::GraphqlCost => observed,
            Self::TrustedUsage {
                max_actual,
                ..
            } => observed.min(*max_actual),
        }
    }
}

/// 计数后端失败时的处置；兼容配置缺省为 fail-open，强制保护需声明 fail-closed。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuotaFailMode {
    /// 计数不可用时放行:可用性优先,代价是限额短暂失效。
    FailOpen,
    /// 计数不可用时拒绝:配额正确性优先,代价是后端故障会放大成入口不可用。
    FailClosed,
}

impl QuotaFailMode {
    /// 业务作用：解析配置中的 fail 模式。
    ///
    /// 参数说明：
    /// - `raw`：为配置字符串。
    ///
    /// 返回：识别成功返回模式;未知取值返回错误——这个选择直接决定故障时
    /// 是"限额失效"还是"入口不可用",不能靠猜。
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fail_open" | "open" => Ok(Self::FailOpen),
            "fail_closed" | "closed" => Ok(Self::FailClosed),
            other => bail!("未知 fail 模式 `{other}`,可选 fail_open|fail_closed"),
        }
    }
}

/// 业务作用：输出 `RateLimit-*` 与兼容的 `X-RateLimit-*` 额度头，使调用方观测同一次准入事实。
///
/// 参数说明：
/// - `headers`：是待写入的响应头集合
/// - `decision`：是限额判定结果。
///
/// 返回：无返回值。
pub fn write_rate_limit_headers(headers: &mut http::HeaderMap, decision: &QuotaDecision) {
    let set = |headers: &mut http::HeaderMap, name: &'static str, value: String| {
        if let Ok(value) = http::HeaderValue::from_str(&value) {
            headers.insert(http::HeaderName::from_static(name), value);
        }
    };
    set(headers, "ratelimit-limit", decision.limit.to_string());
    set(
        headers,
        "ratelimit-remaining",
        decision.remaining.to_string(),
    );
    set(
        headers,
        "ratelimit-reset",
        decision.reset_after.as_secs().to_string(),
    );
    set(headers, "x-ratelimit-limit", decision.limit.to_string());
    set(
        headers,
        "x-ratelimit-remaining",
        decision.remaining.to_string(),
    );
    if !decision.allowed {
        // Retry-After 至少 1 秒:回 0 等于邀请客户端立刻重试,
        // 超额流量会原样打回来,退避完全失效。
        let secs = decision.retry_after.as_secs().max(1);
        set(headers, "retry-after", secs.to_string());
    }
}
