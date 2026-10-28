//! Sentinel 速率规则和冷启动控制计划。

use super::*;

/// `limit_req` 流控规则的已编译形态。数据面只求维度值并调用 `RateLimiter`,不再解析 DSL。
#[derive(Clone, PartialEq, Eq)]
pub struct LimitReqPolicy {
    /// 有界匀速调度，存在时不使用令牌桶或预热余额。
    pub queue: Option<crate::runtime::sentinel::queue::Policy>,
    /// 可选线性预热曲线；为空时保持稳定速率令牌桶。
    pub warmup: Option<crate::runtime::sentinel::Warmup>,
    /// 限流维度,如真实客户端 IP、指定请求头、query 参数或 route。
    pub key: LimitReqKey,
    /// 一个窗口内的稳定放行量,由 `rate=<N>r/s|r/m|r/h` 编译得到。
    pub limit: u64,
    /// 限流窗口,与 `limit` 共同表达补充速率。
    pub window: Duration,
    /// 额外突发容量,对齐 nginx `limit_req burst=` 的运维心智。
    pub burst: u64,
    /// 本规则允许同时存在的维度桶上限，防止轮换 IP/header/query 值打爆本地内存或 Redis key。
    pub max_active_keys: usize,
    /// 达到维度上限时是否 fail-open；false 表示 fail-closed 返回 429。
    pub active_keys_fail_open: bool,
}

/// 业务作用：编译速率、维度容量与可选预热曲线，禁止互相覆盖的重复控制参数。
///
/// 参数说明：
/// - `spec`：完整的 limit_req 指令。
///
/// 返回：合法且有界的令牌策略；未知字段、重复字段或不可执行的预热声明拒绝候选。
pub(super) fn parse_limit_req(spec: &str) -> Result<LimitReqPolicy> {
    let rest = filter_args(spec, "limit_req");
    if rest.is_empty() {
        bail!("limit_req requires `key=<dimension> rate=<N>r/s`");
    }
    let mut key = None;
    let mut rate = None;
    let mut burst = 0_u64;
    let mut max_active_keys = DEFAULT_LIMIT_REQ_MAX_ACTIVE_KEYS;
    let mut active_keys_fail_open = true;
    let mut warmup_ms = None;
    let mut cold_factor = None;
    let mut cold_after_ms = None;
    let mut queue_capacity = None;
    let mut queue_wait_ms = None;
    let mut nodelay = false;
    let mut seen = HashSet::new();
    for token in rest.split_whitespace() {
        if token == "nodelay" {
            if nodelay {
                bail!("duplicate limit_req option `nodelay`");
            }
            nodelay = true;
            continue;
        }
        let (name, value) = token
            .split_once('=')
            .with_context(|| format!("limit_req option `{token}` must be key=value"))?;
        let canonical = match name {
            "dimension" | "by" => "key",
            "qps" => "rate",
            "key_overflow" => "active_keys_fail",
            other => other,
        };
        if !seen.insert(canonical) {
            bail!("duplicate limit_req option `{canonical}`");
        }
        match name {
            "queue_capacity" => {
                queue_capacity = Some(value.parse::<usize>().context("invalid queue_capacity")?)
            }
            "queue_wait_ms" => {
                queue_wait_ms = Some(value.parse::<u64>().context("invalid queue_wait_ms")?)
            }
            "warmup_ms" => warmup_ms = Some(value.parse::<u64>().context("invalid warmup_ms")?),
            "cold_factor" => {
                cold_factor = Some(value.parse::<u16>().context("invalid cold_factor")?)
            }
            "cold_after_ms" => {
                cold_after_ms = Some(value.parse::<u64>().context("invalid cold_after_ms")?)
            }
            "key" | "dimension" | "by" => key = Some(parse_limit_key(value)?),
            "rate" | "qps" => rate = Some(parse_limit_req_rate(value)?),
            "burst" => {
                burst = value
                    .parse::<u64>()
                    .with_context(|| format!("limit_req invalid burst `{value}`"))?;
            }
            "max_active_keys" => {
                max_active_keys = value
                    .parse::<usize>()
                    .with_context(|| format!("limit_req invalid max_active_keys `{value}`"))?;
                if max_active_keys == 0 {
                    bail!("limit_req max_active_keys must be positive");
                }
            }
            "active_keys_fail" | "key_overflow" => match value {
                "open" | "allow" => active_keys_fail_open = true,
                "closed" | "close" | "reject" => active_keys_fail_open = false,
                _ => bail!("limit_req active_keys_fail expects open|closed, got `{value}`"),
            },
            other => bail!("unsupported limit_req option `{other}`"),
        }
    }
    let (limit, window) = rate.context("limit_req requires `rate=<N>r/s`")?;
    if limit == 0 {
        bail!("limit_req rate must be positive");
    }
    let warmup = match warmup_ms {
        Some(period) => Some(crate::runtime::sentinel::Warmup::build(
            period,
            cold_factor.unwrap_or(3),
            cold_after_ms.unwrap_or(period),
            limit,
            burst,
        )?),
        None if cold_factor.is_none() && cold_after_ms.is_none() => None,
        None => bail!("cold_factor/cold_after_ms require warmup_ms"),
    };
    let queue = match (queue_capacity, queue_wait_ms) {
        (None, None) => None,
        (Some(capacity), Some(wait)) if warmup.is_none() && !nodelay && burst == 0 => Some(crate::runtime::sentinel::queue::Policy::build(limit, window, capacity, wait)?),
        _ => bail!("limit_req queue requires queue_capacity and queue_wait_ms, zero burst, and no warmup or nodelay"),
    };
    Ok(LimitReqPolicy {
        queue,
        warmup,
        key: key.unwrap_or(LimitReqKey::Ip),
        limit,
        window,
        burst,
        max_active_keys,
        active_keys_fail_open,
    })
}
