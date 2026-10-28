//! 固定来源结果计数；观测与权威水位分离，指标不能延长声明期限。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use serde::Serialize;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Published,
    Rejected,
    Unavailable,
}

#[derive(Default)]
pub(super) struct Health {
    pub last: Option<Outcome>,
    pub attempted: Option<Instant>,
    pub failures: u64,
}

impl Health {
    /// 业务作用：记录最近来源处理结果供漂移诊断，不保存远端错误或原始载荷。
    ///
    /// 参数说明：
    /// - `outcome`：为完整发布或固定失败类别。
    ///
    /// 返回：更新单来源有限状态与进程计数，不影响任何新鲜度或版本权威。
    pub fn record(&mut self, outcome: Outcome) {
        self.last = Some(outcome);
        self.attempted = Some(Instant::now());
        self.failures = if outcome == Outcome::Published {
            0
        } else {
            self.failures.saturating_add(1)
        };
        nametrics_core::atomic::add(&COUNTERS[outcome as usize], 1);
    }
}

static COUNTERS: [AtomicU64; 3] = [const {
    AtomicU64::new(0)
}; 3];
pub(crate) static DESCRIPTOR: MetricDescriptor = MetricDescriptor {
    name: "gw_configuration_provider_observations_total",
    help: "Configuration source observations by fixed publication outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["outcome"],
    histogram_bounds: &[],
};

/// 业务作用：为 Prometheus 与 OTLP 提供同源的三条固定系列，不携带来源、地址或租户标签。
///
/// 参数说明: 无。
///
/// 返回：进程累计计数；关闭 provider 功能的制品不包含该目录。
pub(crate) fn samples() -> Vec<MetricSample> {
    ["published", "rejected", "unavailable"]
        .into_iter()
        .enumerate()
        .map(|(index, outcome)| MetricSample {
            name: DESCRIPTOR.name,
            labels: vec![("outcome", outcome.into())],
            value: MetricValue::Counter(COUNTERS[index].load(Ordering::Relaxed)),
        })
        .collect()
}

/// 业务作用：在未启用 OTLP 时也输出同一来源累计事实。
///
/// 参数说明：
/// - `output`：为管理面指标响应缓冲区。
///
/// 返回：追加固定名称和结果系列，不执行 I/O。
pub(crate) fn render(output: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&DESCRIPTOR], &samples(), output);
}
