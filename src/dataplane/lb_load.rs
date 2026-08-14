//! 后端负载反馈:延迟 EWMA、ORCA 利用率报告与它们的失效闭合规则。
//!
//! 本模块只维护「每实例的调度参考量」,**绝不参与健康裁决**。反馈缺失、过期、越界或
//! 格式非法时一律退回既有算法,而不是把实例判死——负载反馈是优化项,健康事实的权威
//! 始终是主动探测与被动摘除。

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use anyhow::Result;

/// 利用率用万分比定点存储:避免在原子上放浮点,也让越界值有唯一非法表示。
const UTILIZATION_SCALE: u32 = 10_000;
/// 无有效利用率报告的哨兵值。
const UTILIZATION_NONE: u32 = u32::MAX;
/// 单个服务允许跟踪的实例数硬上限,防止发现抖动把调度状态表撑爆。
pub const MAX_TRACKED_INSTANCES: usize = 65_536;
/// ORCA 报告头允许的最大字节数;超过直接忽略,不做无界解析。
const MAX_ORCA_HEADER_BYTES: usize = 4 * 1024;

/// 业务作用：提供全进程唯一的单调时钟原点，使不同治理模块的时间刻度可比较。
///
/// 参数说明：无。
///
/// 返回：首次调用冻结的进程内 `Instant`。
fn origin() -> Instant {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

/// 业务作用：给出进程内单调递增的毫秒刻度,供反馈新鲜度判定。
///
/// 用单调时钟而非墙钟:NTP 回拨不能让陈旧反馈忽然变"新鲜"。
///
/// **刻度从 1 起**:`0` 被保留为「从未更新」的哨兵。若刻度也能取 0,进程启动瞬间
/// 写入的合法反馈会与「从未更新」同值,被误判成过期而永远不参与调度。
///
/// 参数说明：无。
///
/// 返回：自进程启动起的单调毫秒数,恒大于 0。
pub fn monotonic_ms() -> u64 {
    (origin().elapsed().as_millis().min(u64::MAX as u128 - 1) as u64).saturating_add(1)
}

/// 业务作用：给出与 `monotonic_ms` 同原点的单调纳秒刻度,供带宽整形等亚毫秒判定使用。
///
/// 带宽整形按帧计算等待,单帧耗时常常远小于 1ms;用毫秒刻度会把这些等待全部截断成 0,
/// 限速在小帧场景下彻底失效。刻度同样从 1 起,与 `monotonic_ms` 保持同一哨兵约定。
///
/// 参数说明：无。
///
/// 返回：自进程启动起的单调纳秒数,恒大于 0。
pub fn monotonic_ns() -> u64 {
    (origin().elapsed().as_nanos().min(u64::MAX as u128 - 1) as u64).saturating_add(1)
}

/// 负载反馈的取值口径。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadFeedback {
    /// 不使用反馈:P2C 直接比较在途请求数(除以权重)。
    None,
    /// 使用响应首字节延迟的 EWMA。
    LatencyEwma,
    /// 使用后端自报的利用率(ORCA)。
    Utilization,
}

impl LoadFeedback {
    /// 业务作用：解析配置声明的反馈口径,未知写法构建期拒绝。
    ///
    /// 参数说明：`raw` 是 `load_feedback` 原文。
    ///
    /// 返回：受支持口径;其它返回错误。
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim() {
            "none" | "" => Ok(Self::None),
            "latency_ewma" | "latency-ewma" | "latency" => Ok(Self::LatencyEwma),
            "utilization" | "orca" => Ok(Self::Utilization),
            other => anyhow::bail!(
                "unsupported load_feedback `{other}`(仅 none / latency_ewma / utilization)"
            ),
        }
    }

    /// 业务作用：给出负载反馈口径的稳定配置与管理面名称。
    ///
    /// 参数说明：无。
    ///
    /// 返回：低基数、向后兼容的反馈口径名称。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LatencyEwma => "latency_ewma",
            Self::Utilization => "utilization",
        }
    }
}

/// 已校验的负载反馈策略。
#[derive(Clone)]
pub struct LoadFeedbackPolicy {
    /// 反馈口径。
    pub feedback: LoadFeedback,
    /// 反馈最大有效期(ms);超过即视为无反馈,回退基础算法。
    pub freshness_ms: u64,
    /// 参与比较所需的最小样本数;不足时该实例按无反馈处理,避免冷启动实例被一次慢采样打死。
    pub min_samples: u64,
    /// EWMA 平滑系数,万分比(0<alpha<=10000)。越小越平滑、对抖动越不敏感。
    pub smoothing_bp: u32,
    /// panic 阈值,万分比:拥有新鲜反馈的候选占比低于它时,整服务停用反馈。
    ///
    /// 这是反馈系统的安全阀:少数实例有反馈时按反馈调度会把全部流量压到那几个实例上,
    /// 反而制造热点。宁可整体退回基础算法。
    pub panic_threshold_bp: u32,
    /// ORCA 报告头名(仅 `utilization` 使用)。
    pub orca_header: Arc<str>,
}

impl LoadFeedbackPolicy {
    /// 业务作用：构造完全关闭反馈采集的默认策略，保持既有负载均衡路径零额外开销。
    ///
    /// 参数说明：无。
    ///
    /// 返回：反馈口径为 `None` 的安全默认策略。
    pub fn disabled() -> Self {
        Self {
            feedback: LoadFeedback::None,
            freshness_ms: 30_000,
            min_samples: 3,
            smoothing_bp: 2_000,
            panic_threshold_bp: 5_000,
            orca_header: Arc::from("endpoint-load-metrics"),
        }
    }

    /// 业务作用：判断请求路径是否需要采集反馈；关闭时不读响应头也不更新调度状态。
    ///
    /// 参数说明：无。
    ///
    /// 返回：配置了实际反馈口径时返回 `true`。
    pub fn enabled(&self) -> bool {
        self.feedback != LoadFeedback::None
    }
}

/// 单实例的调度参考量。全部用原子存放,读路径无锁。
#[derive(Debug)]
pub struct InstanceLoad {
    /// 平滑后的响应首字节延迟(微秒);0 表示尚无有效样本。
    ewma_micros: AtomicU64,
    /// 已累计样本数,用于最小样本门。
    samples: AtomicU64,
    /// 最近一次 ORCA 利用率(万分比);`UTILIZATION_NONE` 表示无有效报告。
    utilization_bp: AtomicU32,
    /// 最近一次反馈更新的单调毫秒。
    updated_ms: AtomicU64,
}

impl Default for InstanceLoad {
    /// 业务作用：构造尚无任何有效样本的单实例负载状态。
    ///
    /// 参数说明：无。
    ///
    /// 返回：所有数值处于明确哨兵状态的运行态。
    fn default() -> Self {
        Self {
            ewma_micros: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            utilization_bp: AtomicU32::new(UTILIZATION_NONE),
            updated_ms: AtomicU64::new(0),
        }
    }
}

impl InstanceLoad {
    /// 业务作用：把一次真实响应延迟并入 EWMA,作为 `latency_ewma` 的调度输入。
    ///
    /// 参数说明：`micros` 是本次响应首字节耗时;`smoothing_bp` 是平滑系数万分比。
    ///
    /// 返回：无返回值;样本数与更新时刻同步推进。
    pub fn record_latency(&self, micros: u64, smoothing_bp: u32) {
        // 单次异常长尾不应立刻主导调度,故用 EWMA 而非最近值;alpha 越小越平滑。
        let alpha = smoothing_bp.clamp(1, UTILIZATION_SCALE) as u128;
        let micros = micros.max(1);
        let mut previous = self.ewma_micros.load(Ordering::Relaxed);
        loop {
            let next = if previous == 0 {
                micros
            } else {
                let blended = (micros as u128 * alpha
                    + previous as u128 * (UTILIZATION_SCALE as u128 - alpha))
                    / UTILIZATION_SCALE as u128;
                blended.min(u64::MAX as u128) as u64
            };
            match self.ewma_micros.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        let _ = self
            .samples
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |samples| {
                Some(samples.saturating_add(1))
            });
        // 更新时间最后发布，使读取方观察到新鲜时间时也能看到本次分数与样本数。
        self.updated_ms.store(monotonic_ms(), Ordering::Release);
    }

    /// 业务作用：并入一次后端自报利用率。
    ///
    /// 参数说明：`utilization_bp` 是已校验的万分比利用率;`smoothing_bp` 是平滑系数。
    ///
    /// 返回：无返回值。
    pub fn record_utilization(&self, utilization_bp: u32, smoothing_bp: u32) {
        let alpha = smoothing_bp.clamp(1, UTILIZATION_SCALE) as u64;
        let utilization_bp = utilization_bp.min(UTILIZATION_SCALE);
        let mut previous = self.utilization_bp.load(Ordering::Relaxed);
        loop {
            let next = if previous == UTILIZATION_NONE {
                utilization_bp
            } else {
                let blended = (utilization_bp as u64 * alpha
                    + previous as u64 * (UTILIZATION_SCALE as u64 - alpha))
                    / UTILIZATION_SCALE as u64;
                blended as u32
            };
            match self.utilization_bp.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        let _ = self
            .samples
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |samples| {
                Some(samples.saturating_add(1))
            });
        self.updated_ms.store(monotonic_ms(), Ordering::Release);
    }

    /// 业务作用：按策略给出当前可用的调度分数,同时执行新鲜度与最小样本门。
    ///
    /// 参数说明：`policy` 是服务级反馈策略;`now_ms` 是本轮选择的统一时刻。
    ///
    /// 返回：反馈可用时返回分数(越小越优);缺失、过期或样本不足时返回 `None`。
    pub fn score(&self, policy: &LoadFeedbackPolicy, now_ms: u64) -> Option<u64> {
        if self.samples.load(Ordering::Relaxed) < policy.min_samples {
            return None;
        }
        let updated = self.updated_ms.load(Ordering::Acquire);
        // 单调时钟保证不会因回拨把陈旧反馈判成新鲜;`0` 是「从未更新」哨兵(刻度从 1 起)。
        if updated == 0 || now_ms.saturating_sub(updated) > policy.freshness_ms {
            return None;
        }
        match policy.feedback {
            LoadFeedback::None => None,
            LoadFeedback::LatencyEwma => {
                let ewma = self.ewma_micros.load(Ordering::Relaxed);
                (ewma > 0).then_some(ewma)
            }
            LoadFeedback::Utilization => {
                let utilization = self.utilization_bp.load(Ordering::Relaxed);
                (utilization != UTILIZATION_NONE).then_some(utilization as u64)
            }
        }
    }
}

/// 业务作用：解析 ORCA 负载报告头,得到万分比利用率。
///
/// 支持 ORCA over HTTP 的两种文本形态:
/// - `TEXT`:`cpu_utilization:0.9,mem_utilization:0.5`
/// - `JSON`:`{"cpu_utilization":0.9,"application_utilization":0.4}`
///
/// **越界与非法一律丢弃**:利用率必须落在 `[0,1]`。后端上报 `-1`、`2.5` 或非数字时
/// 返回 `None`,调度退回基础算法,而不是把异常值当成"极空闲"把流量全灌过去。
/// 优先取 `application_utilization`(应用自定义口径最贴近真实容量),否则取 `cpu_utilization`。
///
/// 参数说明：`raw` 是响应头原始值。
///
/// 返回：解析出合法利用率时返回万分比;其它情况返回 `None`。
pub fn parse_orca_utilization(raw: &str) -> Option<u32> {
    if raw.is_empty() || raw.len() > MAX_ORCA_HEADER_BYTES {
        return None;
    }
    // 字段名必须按 token 精确匹配；子串搜索会把 `not_application_utilization`
    // 误当成权威字段，使任意附加字段有机会劫持调度。
    let value = match parse_orca_field(raw, "application_utilization") {
        Ok(Some(value)) => value,
        Ok(None) => parse_orca_field(raw, "cpu_utilization").ok().flatten()?,
        Err(()) => return None,
    };
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return None;
    }
    Some((value * UTILIZATION_SCALE as f64).round() as u32)
}

/// 业务作用：从受限文本或扁平 JSON 报告中精确读取一个 ORCA 利用率字段。
///
/// 参数说明：`raw` 是完整报告；`wanted` 是允许读取的精确字段名。
///
/// 返回：字段缺失返回 `Ok(None)`；字段存在且数值合法返回 `Ok(Some)`；字段存在但
/// 语法非法返回 `Err`，调用方必须丢弃整份报告而不能回退到低优先级字段。
fn parse_orca_field(raw: &str, wanted: &str) -> std::result::Result<Option<f64>, ()> {
    for field in raw.split(',') {
        let field = field
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();
        let Some((name, value)) = field.split_once(':') else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        if name != wanted {
            continue;
        }
        let value = value.trim().trim_end_matches('}').trim();
        return value.parse::<f64>().map(Some).map_err(|_| ());
    }
    Ok(None)
}

/// 业务作用：把已校验的 locality 权重折算成候选份额,支持 weighted zone 调度。
///
/// 参数说明：`weight` 是 zone 权重;`instances` 是该 zone 内当前可用实例数。
///
/// 返回：份额基数;任一为 0 时返回 0,表示该 zone 本轮不承接流量。
pub fn zone_share(weight: u32, instances: usize) -> u64 {
    u64::from(weight).saturating_mul(instances.min(u64::MAX as usize) as u64)
}
