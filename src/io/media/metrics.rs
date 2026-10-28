//! 点播只记录固定容器与准备结果，不记录文件路径或查询参数。
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) static DESCRIPTOR: MetricDescriptor = MetricDescriptor {
    name: "gw_media_operations_total",
    help: "Media preparation by fixed format and outcome.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["format", "outcome"],
    histogram_bounds: &[],
};
static COUNTERS: [AtomicU64; 10] = [const {
    AtomicU64::new(0)
}; 10];
pub(super) struct Operation {
    base: usize,
    finished: bool,
}
impl Operation {
    /// 业务作用：为显式媒体解析建立取消可见的计数凭证。
    ///
    /// 参数说明：
    /// - `format`：路由固定的容器类型。
    ///
    /// 返回：尚未产生终态的计数凭证。
    pub fn begin(format: &crate::config::media::Format) -> Self {
        Self {
            base: if matches!(format, crate::config::media::Format::Mp4) {
                0
            } else {
                5
            },
            finished: false,
        }
    }
    /// 业务作用：区分片段准备、兼容回退、明确拒绝和依赖失败，准备成功不代表客户端完整播放。
    ///
    /// 参数说明：
    /// - `outcome`：执行器固定的终态名。
    ///
    /// 返回：仅累计一次低基数准备结果。
    pub fn finish(&mut self, outcome: &str) {
        let offset = match outcome {
            "prepared" => 0,
            "fallback" => 1,
            "rejected" => 2,
            _ => 3,
        };
        COUNTERS[self.base + offset].fetch_add(1, Ordering::Relaxed);
        self.finished = true;
    }
}
impl Drop for Operation {
    /// 业务作用：记录等待准备期间的取消，不能将未返回的片段记为成功。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚无终态时累计 canceled。
    fn drop(&mut self) {
        if !self.finished {
            COUNTERS[self.base + 4].fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// 业务作用：向 Prometheus 和 OTLP 提供同一组十个固定累计事实。
///
/// 参数说明: 无。
///
/// 返回：不含资源路径和请求维度的样本。
pub(crate) fn samples() -> Vec<MetricSample> {
    ["mp4", "flv"]
        .into_iter()
        .enumerate()
        .flat_map(|(base, format)| {
            ["prepared", "fallback", "rejected", "failed", "canceled"]
                .into_iter()
                .enumerate()
                .map(move |(offset, outcome)| MetricSample {
                    name: DESCRIPTOR.name,
                    labels: vec![("format", format.into()), ("outcome", outcome.into())],
                    value: MetricValue::Counter(
                        COUNTERS[base * 5 + offset].load(Ordering::Relaxed),
                    ),
                })
        })
        .collect()
}
/// 业务作用：复用统一指标编码器输出媒体准备事实。
///
/// 参数说明：
/// - `out`：当前指标响应缓冲区。
///
/// 返回：追加固定目录与样本，不访问文件。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&DESCRIPTOR], &samples(), out);
}
