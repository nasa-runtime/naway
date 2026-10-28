//! ORCA 带外订阅的声明与构建期资源门；订阅不改变业务实例或健康事实。

use serde::Deserialize;

pub const MAX_SUBSCRIPTIONS: usize = 256;

/// 已验证配置只控制本机向已发现实例发起的反馈订阅。
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub report_interval_ms: u64,
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub reconnect_backoff_ms: u64,
    pub max_report_bytes: usize,
    /// 明文只适用于部署方已保证身份的受控网络，必须显式接受该信任边界。
    pub allow_plaintext: bool,
}

impl Default for Config {
    /// 业务作用：为带外订阅提供有界、默认要求认证传输的资源策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认一秒一份报告，连接与空闲均有硬期限，不允许明文传输。
    fn default() -> Self {
        Self {
            report_interval_ms: 1_000,
            connect_timeout_ms: 3_000,
            idle_timeout_ms: 10_000,
            reconnect_backoff_ms: 500,
            max_report_bytes: super::report::MAX_REPORT_BYTES,
            allow_plaintext: false,
        }
    }
}

impl Config {
    /// 业务作用：把反馈 authority 绑定到业务实例的 HTTP/2 传输，禁止隐式明文或跳过证书认证。
    ///
    /// 参数说明：
    /// - `protocol`：服务声明的上游协议。
    /// - `plaintext`：实例 authority 是否使用明文。
    /// - `skip_verify`：服务 TLS 配置是否关闭服务端身份认证。
    ///
    /// 返回：传输符合信任声明时成功，否则拒绝订阅配置。
    pub(crate) fn validate_transport(
        &self,
        protocol: crate::upstream::UpstreamProtocol,
        plaintext: bool,
        skip_verify: bool,
    ) -> anyhow::Result<()> {
        use crate::upstream::UpstreamProtocol;
        anyhow::ensure!(
            matches!(protocol, UpstreamProtocol::H2 | UpstreamProtocol::H2c),
            "ORCA out_of_band requires protocol h2 or h2c"
        );
        anyhow::ensure!(
            !plaintext || self.allow_plaintext,
            "ORCA plaintext requires explicit allow_plaintext"
        );
        anyhow::ensure!(
            !skip_verify,
            "ORCA feedback requires authenticated TLS; insecure_skip_verify is not allowed"
        );
        Ok(())
    }

    /// 业务作用：在候选发布前拒绝不受支持的订阅或可造成无界重试、缓存和空闲连接的配置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：制品支持且全部预算合法时成功；否则拒绝整个候选。
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            cfg!(feature = "upstream-orca"),
            "load_feedback.out_of_band requires feature `upstream-orca`"
        );
        anyhow::ensure!(
            (100..=60_000).contains(&self.report_interval_ms),
            "ORCA report_interval_ms must be within 100..=60000"
        );
        anyhow::ensure!(
            (100..=60_000).contains(&self.connect_timeout_ms),
            "ORCA connect_timeout_ms must be within 100..=60000"
        );
        anyhow::ensure!(
            self.idle_timeout_ms > self.report_interval_ms && self.idle_timeout_ms <= 300_000,
            "ORCA idle_timeout_ms must exceed report interval and be <=300000"
        );
        anyhow::ensure!(
            (100..=60_000).contains(&self.reconnect_backoff_ms),
            "ORCA reconnect_backoff_ms must be within 100..=60000"
        );
        anyhow::ensure!(
            (1..=super::report::MAX_REPORT_BYTES).contains(&self.max_report_bytes),
            "ORCA max_report_bytes exceeds bounded report capacity"
        );
        Ok(())
    }
}
