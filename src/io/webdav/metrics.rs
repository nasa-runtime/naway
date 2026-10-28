//! 文件协议只输出固定模式和终态，不把资源路径、主体或锁凭证放进指标。
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static DESCRIPTOR: MetricDescriptor = MetricDescriptor {
    name: "gw_webdav_operations_total",
    help: "WebDAV operations by fixed mode and outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["mode", "outcome"],
    histogram_bounds: &[],
};
static COUNTERS: [AtomicU64; 8] = [const {
    AtomicU64::new(0)
}; 8];
pub(crate) struct Operation {
    base: usize,
    finished: bool,
}
impl Operation {
    /// 业务作用：为显式 DAV 执行登记取消可见的观测凭证。
    ///
    /// 参数说明：
    /// - `mode`：配置中已固定的本地或代理模式。
    ///
    /// 返回：未完成凭证；异步执行被取消时自动记录 canceled。
    pub fn begin(mode: crate::config::webdav::Mode) -> Self {
        Self {
            base: if mode == crate::config::webdav::Mode::Local {
                0
            } else {
                4
            },
            finished: false,
        }
    }
    /// 业务作用：按协议操作响应分类，不把多资源 207 误称为所有文件都成功。
    ///
    /// 参数说明：
    /// - `status`：控制响应的最终 HTTP 状态；207 仅说明已交付逐资源结果。
    ///
    /// 返回：恰好累计一个 completed、rejected 或 failed 事实。
    pub fn finish(&mut self, status: u16) {
        let outcome = if status < 400 {
            0
        } else if status < 500 {
            1
        } else {
            2
        };
        COUNTERS[self.base + outcome].fetch_add(1, Ordering::Relaxed);
        self.finished = true;
    }
}
impl Drop for Operation {
    /// 业务作用：保留请求取消的事实，不将没有响应的动作记成确定成功或回滚。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未分类时累计 canceled。
    fn drop(&mut self) {
        if !self.finished {
            COUNTERS[self.base + 3].fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// 业务作用：为 Prometheus 与 OTLP 提供同源的八个固定累计系列。
///
/// 参数说明: 无。
///
/// 返回：仅带 mode/outcome 的计数样本。
pub(crate) fn samples() -> Vec<MetricSample> {
    ["local", "proxy"]
        .into_iter()
        .enumerate()
        .flat_map(|(base, mode)| {
            ["completed", "rejected", "failed", "canceled"]
                .into_iter()
                .enumerate()
                .map(move |(offset, outcome)| MetricSample {
                    name: DESCRIPTOR.name,
                    labels: vec![("mode", mode.into()), ("outcome", outcome.into())],
                    value: MetricValue::Counter(
                        COUNTERS[base * 4 + offset].load(Ordering::Relaxed),
                    ),
                })
        })
        .collect()
}
/// 业务作用：将相同目录和样本写入文本指标出口。
///
/// 参数说明：
/// - `out`：当前指标缓冲区。
///
/// 返回：追加固定系列，不访问文件或外部系统。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&DESCRIPTOR], &samples(), out);
}
