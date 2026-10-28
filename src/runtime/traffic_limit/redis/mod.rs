//! 同 slot 原子多窗口账本；协议连接与错误分类复用 NASA Redis。

use super::{LimitAlgorithm, QuotaDecision, QuotaPolicy};
use anyhow::{ensure, Result};
use sha2::Digest;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

mod ledger;
pub(crate) use ledger::Ledger;
pub(crate) mod bandwidth;
pub(crate) mod queue;
pub(crate) mod settlement;

const SCRIPT: &str = include_str!("quota.lua");
static SHA: LazyLock<String> =
    LazyLock::new(|| format!("{:x}", sha1::Sha1::digest(SCRIPT.as_bytes())));
const SAFE_PRODUCT: u128 = 1u128 << 52;
const MAX_WINDOW_MS: u64 = 31 * 86_400_000;
pub(crate) const MAX_COST: u64 = 1 << 32;

/// 运行期只编码成本与容量，固定窗口参数在候选构建时编码一次。
#[derive(PartialEq, Eq)]
pub(crate) struct Policy {
    args: Arc<[String]>,
    settlement: Option<settlement::Limits>,
}

/// 不把确定性账本错误归入可降级的基础设施故障。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Unavailable,
    StateCapacity,
    Invalid,
    Deadline,
}

impl Policy {
    /// 业务作用：固定多窗口算法与数值边界，保证 Redis Lua 的整数计算不丢精度。
    ///
    /// 参数说明：
    /// - `policy`：已经完成通用限额校验的不可变策略。
    ///
    /// 返回：预编码参数；超出精确整数范围或31天窗口上限时拒绝候选。
    pub(crate) fn build(policy: &QuotaPolicy) -> Result<Self> {
        policy.validate()?;
        let algorithm = match policy.algorithm {
            LimitAlgorithm::FixedWindow => 1,
            LimitAlgorithm::SlidingWindow => 2,
            LimitAlgorithm::LeakyBucket => 3,
        };
        let mut args = vec![policy.windows.len().to_string(), algorithm.to_string()];
        for window in &policy.windows {
            let duration = window.window.as_millis();
            let capacity = window.limit.saturating_add(window.burst);
            ensure!(
                duration >= 1 && duration <= u128::from(MAX_WINDOW_MS),
                "Redis traffic window must be within 1ms..31days"
            );
            ensure!(
                capacity <= MAX_COST && u128::from(capacity) * duration <= SAFE_PRODUCT,
                "Redis traffic capacity/window product exceeds exact integer range"
            );
            ensure!(
                algorithm != 3 || u128::from(window.limit) <= duration * 1000,
                "Redis traffic leaky bucket requires at least one microsecond per unit"
            );
            args.extend([
                window.limit.to_string(),
                duration.to_string(),
                window.burst.to_string(),
            ]);
        }
        Ok(Self {
            args: Arc::from(args),
            settlement: None,
        })
    }

    /// 业务作用：为共享响应成本绑定有限回执寿命与事实成本硬上限。
    ///
    /// 参数说明：
    /// - `policy`：与准入及最终结算共用的窗口。
    /// - `reserve`：准入时预留的成本。
    /// - `maximum`：单次响应允许提交的最大事实成本。
    /// - `idle_ms`：回执最长无进展时长。
    ///
    /// 返回：可创建响应回执的策略；数值超界或预留超过硬上限时拒绝候选。
    pub(crate) fn build_response(
        policy: &QuotaPolicy,
        reserve: u64,
        maximum: u64,
        idle_ms: u64,
    ) -> Result<Self> {
        ensure!(
            maximum > 0 && maximum <= MAX_COST && reserve <= maximum,
            "Redis response cost requires reserve <= max_actual within 1..2^32"
        );
        ensure!(
            (1000..=600_000).contains(&idle_ms),
            "Redis settlement_idle_ms must be within 1000..600000"
        );
        let mut compiled = Self::build(policy)?;
        compiled.settlement = Some(settlement::Limits {
            maximum,
            maximum_arg: maximum.to_string(),
            idle: Duration::from_millis(idle_ms),
            idle_arg: idle_ms.to_string(),
        });
        Ok(compiled)
    }

    /// 业务作用：在一个 Redis 原子操作中预检并提交全部窗口，不串行扣减后再补偿。
    ///
    /// 参数说明：
    /// - `ledger`：冻结的连接、归属身份和状态预算。
    /// - `cost`：已经验证的请求成本。
    ///
    /// 返回：原子准入结果或封闭失败类别；超时结果未知，不重发非幂等扣账或猜测退款。
    pub(crate) async fn check(
        &self,
        ledger: &Ledger,
        cost: u64,
    ) -> std::result::Result<QuotaDecision, Failure> {
        self.check_queued(ledger, cost, None).await
    }

    /// 业务作用：在提交额度的同一原子操作中复验排队租约，防止失去名额后继续准入。
    ///
    /// 参数说明：
    /// - `ledger`：冻结的共享账本。
    /// - `cost`：已验证成本。
    /// - `slot`：排队时必须提供的精确租约；首次无排队判定为空。
    ///
    /// 返回：共享准入结果；过期或被撤销的队列权威返回 Deadline。
    pub(crate) async fn check_queued(
        &self,
        ledger: &Ledger,
        cost: u64,
        slot: Option<&queue::Slot>,
    ) -> std::result::Result<QuotaDecision, Failure> {
        if cost > MAX_COST {
            return Err(Failure::Invalid);
        }
        let cost = cost.to_string();
        let mut args = [""; 53];
        args[0] = &ledger.capacity;
        args[1] = &cost;
        for (target, value) in args[2..].iter_mut().zip(self.args.iter()) {
            *target = value;
        }
        let mut count = self.args.len() + 2;
        let values = if let Some(slot) = slot {
            args[count] = &slot.token;
            count += 1;
            ledger
                .invoke_keys(
                    SCRIPT,
                    &SHA,
                    &[&ledger.data, &ledger.index, &slot.ledger.data],
                    &args[..count],
                )
                .await?
        } else {
            ledger.invoke(SCRIPT, &SHA, &args[..count]).await?
        };
        decode(values)
    }
}

/// 业务作用：把固定整数协议转换成准入事实，未知返回不能成为放行依据。
///
/// 参数说明：
/// - `values`：固定产品脚本返回的整数数组。
///
/// 返回：已验证的判定，或容量、回执权威及协议错误。
fn decode(values: Vec<i64>) -> std::result::Result<QuotaDecision, Failure> {
    if values.as_slice() == [-1] {
        return Err(Failure::StateCapacity);
    }
    if values.as_slice() == [-3] {
        return Err(Failure::Deadline);
    }
    if values.len() != 5
        || !(0..=1).contains(&values[0])
        || values[1..].iter().any(|value| *value < 0)
    {
        return Err(Failure::Invalid);
    }
    Ok(QuotaDecision {
        allowed: values[0] == 1,
        remaining: values[1] as u64,
        limit: values[2] as u64,
        reset_after: Duration::from_millis(values[3] as u64),
        retry_after: Duration::from_millis(values[4] as u64),
    })
}
