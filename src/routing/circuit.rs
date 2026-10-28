//! 熔断策略及声明编译。

use super::*;

/// Sentinel 熔断规则；按 route 统计错误或慢调用，保护期内直接返回降级响应。
#[derive(Clone, PartialEq, Eq)]
pub struct CircuitBreakerPolicy {
    /// 规则 id,用于状态 key 与日志定位。
    pub id: String,
    /// 单条规则的计数依据和阈值，不混用不同策略的历史窗口。
    pub criterion: Criterion,
    /// 统计窗口。
    pub window: Duration,
    /// 窗口内至少有多少请求才允许打开熔断,避免低流量偶发错误过敏。
    pub min_requests: u64,
    /// Open 持续时长;到期进入 Half-Open,放一个探测请求。
    pub break_duration: Duration,
    /// 熔断打开时返回的状态码。
    pub fallback_status: StatusCode,
    /// 熔断打开时返回的短文本 body。
    pub fallback_body: String,
}

/// 熔断窗口中的负面样本定义；比例使用整数万分比，避免浮点边界漂移。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Criterion {
    ErrorCount(u64),
    ErrorRatio(u16),
    SlowRatio {
        ratio_bps: u16,
        threshold: Duration,
    },
}

impl Criterion {
    /// 业务作用：把冻结的转发事实映射为当前规则的负面样本，不读取修改后的响应。
    ///
    /// 参数说明：
    /// - `success`：原始上游状态或传输结果是否成功。
    /// - `elapsed`：转发开始至原始响应头或终止错误的耗时。
    ///
    /// 返回：错误策略只计上游失败；慢调用策略只计严格超过耗时阈值的转发。
    pub(crate) fn negative(self, success: bool, elapsed: Duration) -> bool {
        match self {
            Self::ErrorCount(_) | Self::ErrorRatio(_) => !success,
            Self::SlowRatio {
                threshold,
                ..
            } => elapsed > threshold,
        }
    }

    /// 业务作用：在已满足最少样本数后判定聚合窗口是否达到保护阈值。
    ///
    /// 参数说明：
    /// - `total`：统计窗口内的总样本数。
    /// - `negative`：同一窗口按本策略累计的负面样本数。
    ///
    /// 返回：计数或比例达到阈值时为真；空窗口永不触发，整数乘积不会溢出。
    pub(crate) fn exceeded(self, total: u64, negative: u64) -> bool {
        if total == 0 {
            return false;
        }
        match self {
            Self::ErrorCount(threshold) => negative >= threshold,
            Self::ErrorRatio(ratio_bps)
            | Self::SlowRatio {
                ratio_bps,
                ..
            } => u128::from(negative) * 10_000 >= u128::from(total) * u128::from(ratio_bps),
        }
    }
}

impl std::fmt::Display for Criterion {
    /// 业务作用：生成稳定的统计身份，使阈值或统计依据变化后不串用旧窗口。
    ///
    /// 参数说明：
    /// - `formatter`：状态键的写入目标。
    ///
    /// 返回：保留既有次数策略的身份格式，比例和慢调用策略包含全部判定参数。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErrorCount(threshold) => write!(formatter, "{threshold}"),
            Self::ErrorRatio(ratio) => write!(formatter, "error_ratio:{ratio}"),
            Self::SlowRatio {
                ratio_bps,
                threshold,
            } => {
                write!(formatter, "slow_ratio:{ratio_bps}:{}", threshold.as_nanos())
            }
        }
    }
}

/// 业务作用：编译互斥的错误次数、错误比例或慢调用策略，并校验窗口和降级响应。
///
/// 参数说明：
/// - `spec`：完整的 circuit_breaker 指令。
///
/// 返回：所有参数唯一且策略组合有效时返回冻结计划，否则拒绝整个候选。
pub(super) fn parse_circuit_breaker(spec: &str) -> Result<CircuitBreakerPolicy> {
    let rest = filter_args(spec, "circuit_breaker");
    if rest.is_empty() {
        bail!("circuit_breaker requires `id=<id> failure_threshold=<N>`");
    }
    let mut id = None;
    let mut failure_threshold = None;
    let mut strategy = "error_count";
    let mut ratio_bps = None;
    let mut slow_ms = None;
    let mut seen = HashSet::new();
    let mut window_ms = 10_000_u64;
    let mut min_requests = 1_u64;
    let mut break_ms = 30_000_u64;
    let mut fallback_status = StatusCode::SERVICE_UNAVAILABLE;
    let mut fallback_body = "circuit open".to_string();
    for token in rest.split_whitespace() {
        let (name, value) = token
            .split_once('=')
            .with_context(|| format!("circuit_breaker option `{token}` must be key=value"))?;
        let canonical = match name {
            "failures" | "threshold" => "failure_threshold",
            "open_ms" => "break_ms",
            "status" => "fallback_status",
            "body" => "fallback_body",
            other => other,
        };
        // 重复字段不能通过声明顺序覆盖保护参数，别名也必须指向同一个唯一字段。
        if !seen.insert(canonical) {
            bail!("duplicate circuit_breaker option `{canonical}`");
        }
        match name {
            "strategy" => strategy = value,
            "ratio_bps" => {
                ratio_bps = Some(
                    value
                        .parse::<u16>()
                        .context("invalid circuit_breaker ratio_bps")?,
                )
            }
            "slow_ms" => {
                slow_ms = Some(
                    value
                        .parse::<u64>()
                        .context("invalid circuit_breaker slow_ms")?,
                )
            }
            "id" => {
                if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                    bail!(
                        "circuit_breaker id `{value}` must be non-empty and contain no whitespace"
                    );
                }
                id = Some(value.to_string());
            }
            "failure_threshold" | "failures" | "threshold" => {
                failure_threshold = Some(value.parse::<u64>().with_context(|| {
                    format!("circuit_breaker invalid failure_threshold `{value}`")
                })?);
            }
            "window_ms" => {
                window_ms = value
                    .parse::<u64>()
                    .with_context(|| format!("circuit_breaker invalid window_ms `{value}`"))?;
            }
            "min_requests" => {
                min_requests = value
                    .parse::<u64>()
                    .with_context(|| format!("circuit_breaker invalid min_requests `{value}`"))?;
            }
            "break_ms" | "open_ms" => {
                break_ms = value
                    .parse::<u64>()
                    .with_context(|| format!("circuit_breaker invalid break_ms `{value}`"))?;
            }
            "fallback_status" | "status" => {
                let code = value.parse::<u16>().with_context(|| {
                    format!("circuit_breaker invalid fallback_status `{value}`")
                })?;
                fallback_status = StatusCode::from_u16(code)
                    .with_context(|| format!("circuit_breaker invalid fallback_status `{code}`"))?;
            }
            "fallback_body" | "body" => {
                fallback_body = value.replace('_', " ");
            }
            other => bail!("unsupported circuit_breaker option `{other}`"),
        }
    }
    let criterion = match (strategy, failure_threshold, ratio_bps, slow_ms) {
        ("error_count", Some(threshold), None, None) if threshold > 0 => Criterion::ErrorCount(threshold),
        ("error_ratio", None, Some(ratio), None) if (1..=10_000).contains(&ratio) => Criterion::ErrorRatio(ratio),
        ("slow_ratio", None, Some(ratio), Some(slow))
            if (1..=10_000).contains(&ratio) && (1..=MAX_LONG_STREAM_DURATION_MS).contains(&slow) => {
                Criterion::SlowRatio {
                    ratio_bps: ratio,
                    threshold: Duration::from_millis(slow)
                }
            }
        _ => bail!("circuit_breaker expects error_count with positive failure_threshold, error_ratio with ratio_bps=1..10000, or slow_ratio with ratio_bps and bounded positive slow_ms"),
    };
    if !(1..=MAX_LONG_STREAM_DURATION_MS).contains(&window_ms)
        || !(1..=MAX_LONG_STREAM_DURATION_MS).contains(&break_ms)
        || min_requests == 0
    {
        bail!(
            "circuit_breaker window_ms/break_ms must be within 1..={MAX_LONG_STREAM_DURATION_MS} and min_requests must be positive"
        );
    }
    Ok(CircuitBreakerPolicy {
        id: id.unwrap_or_else(|| "default".to_string()),
        criterion,
        window: Duration::from_millis(window_ms),
        min_requests,
        break_duration: Duration::from_millis(break_ms),
        fallback_status,
        fallback_body,
    })
}
