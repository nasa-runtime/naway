//! 有界 AI 操作、交付首帧与生命周期指标；不接收内容或主体标识作为标签。

use super::metrics::Metrics;
use crate::BoxBody;
use bytes::Bytes;
use http::Response;
use hyper::body::{Body, Frame};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct AiMetrics {
    values: Mutex<BTreeMap<Key, Stats>>,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    route: String,
    protocol: String,
    method: String,
    target: String,
    outcome: String,
}
#[derive(Default)]
struct Stats {
    calls: u64,
    duration_us: u128,
    first_count: u64,
    first_us: u128,
}

impl AiMetrics {
    /// 业务作用：把已有 AI 操作事实投影到固定协议和结果集合，避免复制配置或主体标签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：九十个累计计数；未知分类折叠到 other，目录大小不受请求输入影响。
    #[cfg(feature = "telemetry-otlp")]
    pub(crate) fn summary(&self) -> Vec<nametrics_core::MetricSample> {
        let mut counts = [[0u64; AI_OUTCOMES.len()]; AI_PROTOCOLS.len()];
        for (key, value) in self.values.lock().iter() {
            let protocol = match key.protocol.as_str() {
                "mcp" => 0,
                "a2a" => 1,
                "rag" => 2,
                "guardrail" => 3,
                _ if key.method == "chat.completions" => 4,
                _ => 5,
            };
            let outcome = AI_OUTCOMES
                .iter()
                .position(|label| *label == key.outcome)
                .unwrap_or(AI_OUTCOMES.len() - 1);
            counts[protocol][outcome] = counts[protocol][outcome].saturating_add(value.calls);
        }
        let mut samples = Vec::with_capacity(AI_PROTOCOLS.len() * AI_OUTCOMES.len());
        for (protocol, name) in AI_PROTOCOLS.iter().enumerate() {
            for (outcome, label) in AI_OUTCOMES.iter().enumerate() {
                samples.push(nametrics_core::MetricSample {
                    name: SUMMARY.name,
                    labels: vec![("protocol", (*name).into()), ("outcome", (*label).into())],
                    value: nametrics_core::MetricValue::Counter(counts[protocol][outcome]),
                });
            }
        }
        samples
    }

    /// 业务作用：累计低敏配置身份和固定结果分类，动态系列达到硬门后折叠为 overflow。
    ///
    /// 参数说明：
    /// - `key`：是配置或固定协议标签
    /// - `elapsed`：是生命周期
    /// - `first`：是首次实际交付耗时。
    ///
    /// 返回：更新一项有界序列，不记录请求或响应内容。
    fn record(&self, mut key: Key, elapsed: Duration, first: Option<Duration>) {
        let mut values = self.values.lock();
        if !values.contains_key(&key) && values.len() >= 4096 {
            key = Key {
                route: "__overflow__".into(),
                protocol: "__overflow__".into(),
                method: "__overflow__".into(),
                target: "__overflow__".into(),
                outcome: "__overflow__".into(),
            };
        }
        let entry = values.entry(key).or_default();
        entry.calls = entry.calls.saturating_add(1);
        entry.duration_us = entry.duration_us.saturating_add(elapsed.as_micros());
        if let Some(first) = first {
            entry.first_count = entry.first_count.saturating_add(1);
            entry.first_us = entry.first_us.saturating_add(first.as_micros());
        }
    }

    /// 业务作用：输出固定名称的 AI 操作和交付时延指标，串行化时对配置标签执行转义。
    ///
    /// 参数说明：
    /// - `out`：是当前 Prometheus 文档。
    ///
    /// 返回：追加有界计数与时延总和，不修改活动操作。
    pub(crate) fn render(&self, out: &mut String) {
        out.push_str("# HELP gw_ai_operations_total AI operation outcomes by bounded configured identity.\n# TYPE gw_ai_operations_total counter\n# HELP gw_ai_duration_seconds_sum AI operation lifetime in seconds.\n# TYPE gw_ai_duration_seconds_sum counter\n# HELP gw_ai_ttft_seconds_sum Time to first delivered data frame after policy decisions.\n# TYPE gw_ai_ttft_seconds_sum counter\n# HELP gw_ai_ttft_seconds_count Operations that delivered a data frame.\n# TYPE gw_ai_ttft_seconds_count counter\n");
        for (key, value) in self.values.lock().iter() {
            let labels = format!(
                "route=\"{}\",protocol=\"{}\",method=\"{}\",target=\"{}\",outcome=\"{}\"",
                escape(&key.route),
                escape(&key.protocol),
                escape(&key.method),
                escape(&key.target),
                escape(&key.outcome)
            );
            out.push_str(&format!("gw_ai_operations_total{{{labels}}} {}\ngw_ai_duration_seconds_sum{{{labels}}} {:.6}\ngw_ai_ttft_seconds_sum{{{labels}}} {:.6}\ngw_ai_ttft_seconds_count{{{labels}}} {}\n", value.calls, value.duration_us as f64 / 1_000_000.0, value.first_us as f64 / 1_000_000.0, value.first_count));
        }
    }
}

#[cfg(feature = "telemetry-otlp")]
const AI_PROTOCOLS: [&str; 6] = ["mcp", "a2a", "rag", "guardrail", "llm", "other"];
#[cfg(feature = "telemetry-otlp")]
const AI_OUTCOMES: [&str; 15] = [
    "completed",
    "rejected",
    "failed",
    "interrupted",
    "allowed",
    "blocked",
    "fail_open",
    "received",
    "fallback",
    "submitted",
    "working",
    "input-required",
    "auth-required",
    "canceled",
    "other",
];
#[cfg(feature = "telemetry-otlp")]
pub(crate) static SUMMARY: nametrics_core::MetricDescriptor = nametrics_core::MetricDescriptor {
    name: "gw_ai_operations_summary_total",
    help: "AI operation totals projected to fixed protocol and outcome categories.",
    unit: "",
    kind: nametrics_core::MetricKind::Counter,
    label_names: &["protocol", "outcome"],
    histogram_bounds: &[],
};

pub(crate) struct Operation {
    metrics: Arc<Metrics>,
    key: Key,
    started: Instant,
    first: Option<Duration>,
}

impl Operation {
    /// 业务作用：为一个已选定的 AI 动作建立生命周期观测，默认未完成直到响应实体确认结束。
    ///
    /// 参数说明：
    /// - `metrics`：是节点指标
    /// - `route`：来自固定配置或协议集合。
    /// - `protocol`：来自固定配置或协议集合。
    /// - `method`：来自固定配置或协议集合。
    /// - `target`：来自固定配置或协议集合。
    ///
    /// 返回：不持有正文的操作守卫，Drop 记录完成、失败或中断。
    pub(crate) fn new(
        metrics: Arc<Metrics>,
        route: &str,
        protocol: &str,
        method: &str,
        target: &str,
    ) -> Self {
        Self {
            metrics,
            key: Key {
                route: route.into(),
                protocol: protocol.into(),
                method: method.into(),
                target: target.into(),
                outcome: "interrupted".into(),
            },
            started: Instant::now(),
            first: None,
        }
    }

    /// 业务作用：记录实现已确认的结果分类，不把客户端字段当作动态结果名。
    ///
    /// 参数说明：
    /// - `outcome`：是固定状态集合中的完成或拒绝类型。
    ///
    /// 返回：更新最终观测分类，不改变业务授权。
    pub(crate) fn outcome(&mut self, outcome: &'static str) {
        self.key.outcome = outcome.into();
    }
}

impl Drop for Operation {
    /// 业务作用：即使下游断开或 future 被取消，也完成低敏生命周期记录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：向有界指标表提交一次操作结论。
    fn drop(&mut self) {
        self.metrics
            .ai
            .record(self.key.clone(), self.started.elapsed(), self.first);
    }
}

/// 业务作用：只在经过全部输出策略后观测实际交付首帧，避免将 provider 首字节误认为用户可见首 token。
///
/// 参数说明：
/// - `response`：是最终响应
/// - `operation`：是已开始的动作观测。
///
/// 返回：头和正文语义不变的响应；所有权随 body 持续到结束或断开。
pub(crate) fn response(response: Response<BoxBody>, mut operation: Operation) -> Response<BoxBody> {
    let success = response.status().is_success();
    if !success {
        operation.outcome("rejected");
    }
    response.map(|body| {
        http_body_util::BodyExt::boxed(ObservedBody {
            body,
            operation,
            success,
        })
    })
}

struct ObservedBody {
    body: BoxBody,
    operation: Operation,
    success: bool,
}
impl Body for ObservedBody {
    type Data = Bytes;
    type Error = crate::BoxError;
    /// 业务作用：保持背压与帧保真，在交付、结束和失败边界记录固定事实。
    ///
    /// 参数说明：
    /// - `cx`：是响应任务上下文。
    ///
    /// 返回：原始帧、等待或结束，不读取正文内容。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let result = Pin::new(&mut self.body).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.data_ref().is_some_and(|data| !data.is_empty())
                    && self.operation.first.is_none()
                {
                    self.operation.first = Some(self.operation.started.elapsed());
                }
                if self.body.is_end_stream() && self.success {
                    self.operation.outcome("completed");
                }
            }
            Poll::Ready(None) if self.success => self.operation.outcome("completed"),
            Poll::Ready(Some(Err(_))) => self.operation.outcome("failed"),
            _ => {}
        }
        result
    }
}

/// 业务作用：按 Prometheus label 文本合同编码固定配置值，防止引号或换行改变指标结构。
///
/// 参数说明：
/// - `value`：是已限制基数的配置标签。
///
/// 返回：保留语义的转义文本。
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
