//! 逐帧共享带宽只传递整数成本，不传输或重新编码实体。

use super::{Failure, Ledger, MAX_COST};
use crate::runtime::traffic_limit::BandwidthPolicy;
use sha2::Digest;
use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

const SCRIPT: &str = include_str!("bandwidth.lua");
static SHA: LazyLock<String> =
    LazyLock::new(|| format!("{:x}", sha1::Sha1::digest(SCRIPT.as_bytes())));

pub(crate) struct Policy {
    args: [String; 3],
}

impl Policy {
    /// 业务作用：在发布前限定共享带宽的整数精度与历史债务寿命。
    ///
    /// 参数说明：
    /// - `policy`：已验证的带宽配置。
    ///
    /// 返回：冻结的速率、突发和期限参数；超界配置拒绝发布。
    pub(crate) fn build(policy: &BandwidthPolicy) -> anyhow::Result<Self> {
        policy.validate()?;
        anyhow::ensure!(
            policy.bytes_per_second <= MAX_COST && policy.burst_bytes <= MAX_COST,
            "Redis bandwidth rate and burst must not exceed 2^32 bytes"
        );
        anyhow::ensure!(
            u128::from(policy.burst_bytes) <= u128::from(policy.bytes_per_second) * 60,
            "Redis bandwidth burst must not exceed sixty seconds of rate"
        );
        Ok(Self {
            args: [
                policy.bytes_per_second.to_string(),
                policy.burst_bytes.to_string(),
                policy.max_wait.as_micros().to_string(),
            ],
        })
    }

    /// 业务作用：为一帧完整字节成本原子安排发送时刻，超期不写入新的债务。
    ///
    /// 参数说明：
    /// - `ledger`：该方向冻结的后端、身份与容量索引。
    /// - `bytes`：扣除每流免费前缀后的本帧成本。
    ///
    /// 返回：发送前等待时长；错误结果不代表提交必然没有发生。
    pub(crate) async fn reserve(&self, ledger: &Ledger, bytes: u64) -> Result<Duration, Failure> {
        if bytes == 0 {
            return Ok(Duration::ZERO);
        }
        if bytes > MAX_COST {
            return Err(Failure::Deadline);
        }
        let bytes = bytes.to_string();
        let result = ledger
            .invoke(
                SCRIPT,
                &SHA,
                &[
                    &ledger.capacity,
                    &bytes,
                    &self.args[0],
                    &self.args[1],
                    &self.args[2],
                ],
            )
            .await?;
        match result.as_slice() {
            [-1] => Err(Failure::StateCapacity),
            [-2] => Err(Failure::Deadline),
            [delay] if (0..=60_000_000).contains(delay) => Ok(Duration::from_micros(*delay as u64)),
            _ => Err(Failure::Invalid),
        }
    }
}

/// 每条流冻结同一后端；共享调度只保存时间债务，每流免费前缀保留在本地。
pub(crate) struct Shaper {
    pub(crate) ledger: Arc<Ledger>,
    pub(crate) policy: Arc<Policy>,
    pub(crate) after_remaining: u64,
    pub(crate) max_wait: Duration,
    pub(crate) fail_mode: crate::runtime::traffic_limit::QuotaFailMode,
}
