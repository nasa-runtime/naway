//! 记录协议固定维度的失败事实。
use nametrics_core::{MetricDescriptor, MetricKind, MetricSample, MetricValue};
pub(crate) static DESCRIPTOR: MetricDescriptor = MetricDescriptor {
    name: "gw_cgi_session_failures_total",
    help: "CGI stream or record failures by fixed protocol.",
    unit: "",
    kind: MetricKind::Counter,
    label_names: &["protocol"],
    histogram_bounds: &[],
};
/// 业务作用：生成不带脚本、请求或租户信息的协议失败样本。
///
/// 参数说明: 无。
///
/// 返回：三项固定累计事实，供 Prometheus 和 OTLP 共用。
pub(crate) fn samples() -> Vec<MetricSample> {
    ["fastcgi", "uwsgi", "scgi"]
        .into_iter()
        .zip(super::wire::failures())
        .map(|(protocol, count)| MetricSample {
            name: DESCRIPTOR.name,
            labels: vec![("protocol", protocol.into())],
            value: MetricValue::Counter(count),
        })
        .collect()
}
/// 业务作用：向文本出口追加相同协议事实。
///
/// 参数说明：
/// - `out`：当前指标输出缓冲区。
///
/// 返回：追加固定目录与样本，无外部 I/O。
pub(crate) fn render(out: &mut String) {
    nametrics_core::atomic::render_snapshot(&[&DESCRIPTOR], &samples(), out);
}
