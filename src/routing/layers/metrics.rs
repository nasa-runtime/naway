//! 层级选择的固定深度与结果计数；身份、路由名与上下文不进入指标标签。

use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTERS: [AtomicU64; 40] = [const {
    AtomicU64::new(0)
}; 40];
const OUTCOMES: [&str; 5] = [
    "selected",
    "no_child",
    "rejected",
    "authority_changed",
    "preflight",
];
pub(crate) static DESCRIPTOR: MetricDescriptor = MetricDescriptor {
    name: "gw_layered_route_selections_total",
    help: "Layered route selections by bounded depth and outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["depth", "outcome"],
    histogram_bounds: &[],
};

/// 业务作用：记录一次层级选择的最终结果，不把叶子上游响应混同为选择成功或失败。
///
/// 参数说明：
/// - `depth`：为已访问层数
/// - `status`：是选择阶段短路状态，None 表示已交付叶子。
///
/// 返回：只增加固定累计计数，不创建按请求动态扩展的指标系列。
pub(crate) fn record(depth: usize, status: Option<u16>) {
    let outcome = match status {
        None => 0,
        Some(404) => 1,
        Some(409) => 3,
        Some(204) => 4,
        _ => 2,
    };
    nametrics_core::atomic::add(
        &COUNTERS[(depth.clamp(1, 8) - 1) * OUTCOMES.len() + outcome],
        1,
    );
}

/// 业务作用：从同一组原子事实提供 Prometheus 与 OTLP 的有限系列。
///
/// 参数说明: 无。
///
/// 返回：八种深度与五种结果的累计计数，无主体或原始条件。
pub(crate) fn samples() -> Vec<MetricSample> {
    (1..=8)
        .flat_map(|depth| {
            OUTCOMES
                .iter()
                .enumerate()
                .map(move |(outcome, name)| MetricSample {
                    name: DESCRIPTOR.name,
                    labels: vec![("depth", depth.to_string()), ("outcome", (*name).into())],
                    value: MetricValue::Counter(
                        COUNTERS[(depth - 1) * OUTCOMES.len() + outcome].load(Ordering::Relaxed),
                    ),
                })
        })
        .collect()
}

/// 业务作用：输出同源的固定层级计数，不依赖 OTLP 是否启用。
///
/// 参数说明：
/// - `output`：为当前指标缓冲区。
///
/// 返回：追加描述和样本，不产生外部 I/O。
pub(crate) fn render(output: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&DESCRIPTOR], &samples(), output);
}
