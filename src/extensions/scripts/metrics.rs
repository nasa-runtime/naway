//! 固定脚本相位与执行结果是唯一标签，源码、身份和输入不会进入遥测。
use crate::config::scripts::Phase;
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) static DESCRIPTOR: MetricDescriptor = MetricDescriptor {
    name: "gw_script_invocations_total",
    help: "Sandboxed script invocations by fixed phase and outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["phase", "outcome"],
    histogram_bounds: &[],
};
const PHASES: [&str; 6] = [
    "request_headers",
    "request_body",
    "request_body_stream",
    "response_headers",
    "response_body",
    "response_body_stream",
];
const OUTCOMES: [&str; 14] = [
    "continue",
    "reject",
    "fail_open",
    "input",
    "output",
    "instructions",
    "cpu",
    "memory",
    "allocations",
    "deadline",
    "cancelled",
    "capacity",
    "script",
    "dependency",
];
static COUNTERS: [AtomicU64; 84] = [const {
    AtomicU64::new(0)
}; 84];
pub(super) struct Operation {
    base: usize,
    finished: bool,
}
impl Operation {
    /// 业务作用：建立取消可见的调用计数，不把未完成调用误报成功。
    ///
    /// 参数说明：
    /// - `phase`：固定执行阶段。
    ///
    /// 返回：尚无终态的计数凭证。
    pub fn begin(phase: Phase) -> Self {
        let index = match phase {
            Phase::RequestHeaders => 0,
            Phase::RequestBody => 1,
            Phase::RequestBodyStream => 2,
            Phase::ResponseHeaders => 3,
            Phase::ResponseBody => 4,
            Phase::ResponseBodyStream => 5,
        };
        Self {
            base: index * OUTCOMES.len(),
            finished: false,
        }
    }
    /// 业务作用：记录宿主确认的最终执行类别。
    ///
    /// 参数说明：
    /// - `outcome`：固定目录中的类别。
    ///
    /// 返回：累计一次低基数事实。
    pub fn finish(&mut self, outcome: &str) {
        let offset = OUTCOMES
            .iter()
            .position(|value| *value == outcome)
            .unwrap_or(12);
        COUNTERS[self.base + offset].fetch_add(1, Ordering::Relaxed);
        self.finished = true;
    }
}
impl Drop for Operation {
    /// 业务作用：调用 future 被丢弃时记录取消，不能被解释器后台退出掩盖。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无终态时累计取消。
    fn drop(&mut self) {
        if !self.finished {
            COUNTERS[self.base + 10].fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// 业务作用：为 Prometheus、OTLP 与目录提供同一份固定事实。
///
/// 参数说明: 无。
///
/// 返回：八十四个固定相位与结果组合，没有动态基数。
pub(crate) fn samples() -> Vec<MetricSample> {
    PHASES
        .into_iter()
        .enumerate()
        .flat_map(|(phase_index, phase)| {
            OUTCOMES
                .into_iter()
                .enumerate()
                .map(move |(offset, outcome)| MetricSample {
                    name: DESCRIPTOR.name,
                    labels: vec![("phase", phase.into()), ("outcome", outcome.into())],
                    value: MetricValue::Counter(
                        COUNTERS[phase_index * OUTCOMES.len() + offset].load(Ordering::Relaxed),
                    ),
                })
        })
        .collect()
}
/// 业务作用：复用统一编码器导出脚本执行事实。
///
/// 参数说明：
/// - `out`：指标响应缓冲区。
///
/// 返回：追加固定目录与累计样本。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&DESCRIPTOR], &samples(), out);
}
