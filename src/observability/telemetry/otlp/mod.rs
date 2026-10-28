//! 三信号 exporter 的代际 owner；每个信号独立排队、重试、熔断与丢弃。

mod metrics;
mod queue;
mod transport;
mod wire;

pub(super) use metrics::bind;

use std::sync::Arc;
use std::time::{Duration, Instant};

use opentelemetry::trace::{SpanContext, SpanKind};
use opentelemetry_proto::tonic::{
    common::v1::{any_value, AnyValue, KeyValue},
    logs::v1::LogRecord,
    metrics::v1::Metric,
    resource::v1::Resource,
    trace::v1::Span,
};
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::trace::{SpanData, SpanProcessor};
use tokio_util::sync::CancellationToken;

use crate::config::{model::TelemetryCfg, telemetry::endpoint};
use queue::Sender;
use wire::{string_attribute, unix_nanos, Signal};

pub(super) type MetricSource = Arc<dyn Fn() -> Vec<Metric> + Send + Sync>;

pub(super) struct OtlpRuntime {
    lease: Arc<GenerationPermit>,
    signals: [Option<Sender>; 3],
    stop: CancellationToken,
    metric_stop: CancellationToken,
    metric_started: std::sync::atomic::AtomicBool,
    interval: Duration,
    shutdown_budget: Duration,
}

static LIVE_GENERATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) struct GenerationPermit;

impl GenerationPermit {
    /// 业务作用：给活动、准备和排空中的 exporter 代共用进程硬门，连续热换不能无界创建队列。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：最多四代同时持有许可；容量不足时拒绝候选并保留当前活动配置。
    fn acquire() -> anyhow::Result<Arc<Self>> {
        use std::sync::atomic::Ordering;
        LIVE_GENERATIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < 4).then_some(value + 1)
            })
            .map_err(|_| {
                anyhow::anyhow!(
                    "telemetry generation budget exhausted; wait for retiring exporters"
                )
            })?;
        Ok(Arc::new(Self))
    }
}

impl Drop for GenerationPermit {
    /// 业务作用：只有 owner 和全部 worker 都释放后才归还代际容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：归还一个进程名额，不在取消信号发出时提前宣称载荷内存已释放。
    fn drop(&mut self) {
        LIVE_GENERATIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl OtlpRuntime {
    /// 业务作用：预构建三个独立出口，但不在候选发布前采集指标或发送数据。
    ///
    /// 参数说明：
    /// - `cfg`：已通过三信号配置硬门。
    ///
    /// 返回：持有全部 worker 撤销权威的 owner；任一构建失败会撤销已创建 worker。
    pub fn build(cfg: &TelemetryCfg) -> anyhow::Result<Arc<Self>> {
        let multi = cfg
            .multi_signal
            .as_ref()
            .expect("validated multi signal configuration");
        let mut owner = Self {
            lease: GenerationPermit::acquire()?,
            signals: [None, None, None],
            stop: CancellationToken::new(),
            metric_stop: CancellationToken::new(),
            metric_started: std::sync::atomic::AtomicBool::new(false),
            interval: Duration::from_millis(multi.metrics_interval_ms),
            shutdown_budget: Duration::from_millis(
                multi
                    .traces
                    .deadline_ms
                    .max(multi.metrics.deadline_ms)
                    .max(multi.logs.deadline_ms),
            ),
        };
        let resource = Resource {
            attributes: vec![
                string_attribute("service.name", &cfg.service_name),
                string_attribute("service.version", env!("CARGO_PKG_VERSION")),
            ],
            ..Default::default()
        };
        for (signal, signal_cfg) in [
            (Signal::Traces, &multi.traces),
            (Signal::Metrics, &multi.metrics),
            (Signal::Logs, &multi.logs),
        ] {
            if !signal_cfg.enabled || (matches!(signal, Signal::Traces) && !cfg.enabled) {
                continue;
            }
            let endpoint = endpoint(
                multi.protocol,
                signal_cfg.endpoint.as_deref().unwrap_or(&cfg.endpoint),
                signal.name(),
            )?;
            owner.signals[signal as usize] = Some(queue::start(
                signal,
                signal_cfg.clone(),
                multi.protocol,
                endpoint,
                resource.clone(),
                owner.stop.clone(),
                owner.lease.clone(),
            )?);
        }
        Ok(Arc::new(owner))
    }

    /// 业务作用：把 SDK span 完成回调接到唯一 trace 队列，不叠加第二个 SDK batch 队列。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：trace 已启用时返回非阻塞 processor，否则为空。
    pub fn processor(&self) -> Option<Processor> {
        self.signals[0].clone().map(Processor)
    }

    /// 业务作用：冻结请求日志的本代出口与标准关联标识。
    ///
    /// 参数说明：
    /// - `context`：是网关完成信任门禁后产生的 server span context。
    ///
    /// 返回：日志启用时返回请求收尾句柄；不读取任何 header/body。
    pub fn request_log(&self, context: &SpanContext) -> Option<RequestLog> {
        self.signals[2].clone().map(|sender| RequestLog {
            sender,
            trace_id: context.trace_id().to_bytes(),
            span_id: context.span_id().to_bytes(),
            flags: u32::from(context.trace_flags().to_u8()),
        })
    }

    /// 业务作用：在本代发布后启动独立指标采集，不让 collector 消费速度控制采集周期。
    ///
    /// 参数说明：
    /// - `source`：读取稳定进程事实，不得执行网络或无界分配。
    ///
    /// 返回：重复调用不创建重复 producer；停止时不再读取或投递旧代数据。
    pub fn start_metrics(&self, source: MetricSource) {
        use std::sync::atomic::Ordering;
        let Some(sender) = self.signals[1].clone() else {
            return;
        };
        if self.metric_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let stop = self.metric_stop.clone();
        let interval = self.interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! { biased; _ = stop.cancelled() => break, _ = ticker.tick() => {} }
                for metric in source() {
                    if stop.is_cancelled() {
                        break;
                    }
                    let points = match &metric.data {
                        Some(opentelemetry_proto::tonic::metrics::v1::metric::Data::Sum(value)) => {
                            value.data_points.len()
                        }
                        Some(opentelemetry_proto::tonic::metrics::v1::metric::Data::Gauge(
                            value,
                        )) => value.data_points.len(),
                        Some(opentelemetry_proto::tonic::metrics::v1::metric::Data::Histogram(
                            value,
                        )) => value.data_points.len(),
                        _ => 0,
                    };
                    sender.record(&metric, points as u64);
                }
            }
        });
    }

    /// 业务作用：撤销旧代指标采集，让累计事实只由活动出口周期发送。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：在途请求 trace/log 仍可在排空窗口内结束，指标不再重复采集。
    pub fn stop_metrics(&self) {
        self.metric_stop.cancel();
    }

    /// 业务作用：关闭生产入口，在共享停机期限内尽力排空，再撤销全部后台 I/O。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：屏障全部处理后成功；队列满或期限耗尽时报错，任务仍会被撤销。
    pub fn shutdown(&self) -> anyhow::Result<()> {
        self.stop_metrics();
        let deadline = Instant::now() + self.shutdown_budget + Duration::from_millis(100);
        let mut receipts = Vec::new();
        let mut success = true;
        for sender in self.signals.iter().flatten() {
            sender.close();
            match sender.barrier() {
                Ok(rx) => receipts.push(rx),
                Err(_) => success = false,
            }
        }
        for receipt in receipts {
            success &= receipt
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok();
        }
        self.stop.cancel();
        anyhow::ensure!(
            success,
            "OTLP shutdown could not drain all queues within budget"
        );
        Ok(())
    }
}

impl Drop for OtlpRuntime {
    /// 业务作用：未发布候选或异常退出时撤销其 worker，避免候选失败后留下出口任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不等待网络；后台任务在取消点释放其队列和连接。
    fn drop(&mut self) {
        self.metric_stop.cancel();
        self.stop.cancel();
    }
}

#[derive(Debug)]
pub(super) struct Processor(Sender);

impl SpanProcessor for Processor {
    /// 业务作用：开始 span 时不触碰 exporter，只有完成事件才允许进入队列。
    ///
    /// 参数说明：
    /// - `_span`：由 SDK 管理，本 processor 不修改。
    /// - `_cx`：由 SDK 管理，本 processor 不修改。
    ///
    /// 返回：无副作用。
    fn on_start(&self, _span: &mut opentelemetry_sdk::trace::Span, _cx: &opentelemetry::Context) {}

    /// 业务作用：完成 span 后删除非白名单信息，并非阻塞提交有限 protobuf。
    ///
    /// 参数说明：
    /// - `data`：是 SDK 已冻结的完成事实。
    ///
    /// 返回：只投递 sampled span；不采集任意事件、链接、URL、请求头或错误正文。
    fn on_end(&self, mut data: SpanData) {
        if !data.span_context.is_sampled() {
            return;
        }
        let name = match data.span_kind {
            SpanKind::Server => "gateway.request",
            SpanKind::Client => "gateway.upstream",
            _ => "gateway.operation",
        };
        data.name = name.into();
        data.dropped_attributes_count = data
            .dropped_attributes_count
            .saturating_add(data.attributes.len() as u32);
        // 在 protobuf 转换前裁剪属性和事件，禁止编码器为随后会丢弃的敏感载荷再次分配内存。
        data.attributes.retain(|attribute| {
            matches!(
                attribute.key.as_str(),
                "http.request.method"
                    | "url.scheme"
                    | "http.route"
                    | "http.response.status_code"
                    | "gateway.upstream.attempt"
                    | "gateway.upstream.attempts"
                    | "gateway.trace_context_rejected"
                    | "gateway.request.cancelled"
                    | "gateway.upstream.cancelled"
                    | "gateway.sampling.promotion"
            ) && matches!(
                attribute.value,
                opentelemetry::Value::Bool(_)
                    | opentelemetry::Value::I64(_)
                    | opentelemetry::Value::F64(_)
                    | opentelemetry::Value::String(_)
            )
        });
        data.dropped_attributes_count = data
            .dropped_attributes_count
            .saturating_sub(data.attributes.len() as u32);
        for attribute in &mut data.attributes {
            if let opentelemetry::Value::String(value) = &mut attribute.value {
                if value.as_str().len() > 1024 {
                    let mut end = 1024;
                    while !value.as_str().is_char_boundary(end) {
                        end -= 1;
                    }
                    *value = value.as_str()[..end].to_owned().into();
                }
            }
        }
        data.events.dropped_count = data
            .events
            .dropped_count
            .saturating_add(data.events.len() as u32);
        data.events.events.clear();
        data.links.dropped_count = data
            .links
            .dropped_count
            .saturating_add(data.links.len() as u32);
        data.links.links.clear();
        if matches!(data.status, opentelemetry::trace::Status::Error {
            ..
        }) {
            data.status = opentelemetry::trace::Status::error("");
        }
        let mut span: Span = data.into();
        span.trace_state.clear();
        self.0.record(&span, 1);
    }

    /// 业务作用：控制面显式 flush 时等待已完成 span 到达出口屏障。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：五秒内排空时成功，队列满或后台失败时返回 SDK 错误。
    fn force_flush(&self) -> OTelSdkResult {
        self.0
            .barrier()
            .and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).map_err(Into::into))
            .map_err(|_| OTelSdkError::InternalFailure("OTLP flush incomplete".into()))
    }

    /// 业务作用：provider 关闭时停止 span 生产；三信号联合排空由代际 owner 执行。
    ///
    /// 参数说明：
    /// - `_timeout`：属 SDK 停机预算，本方法不等待网络。
    ///
    /// 返回：关闭入口后成功，不宣称 collector 已持久化数据。
    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.0.close();
        Ok(())
    }
}

pub(super) struct RequestLog {
    sender: Sender,
    trace_id: [u8; 16],
    span_id: [u8; 8],
    flags: u32,
}

impl RequestLog {
    /// 业务作用：在有限提升完成后同步标准日志关联，保持日志与最终 server span 的 sampled 位一致。
    ///
    /// 参数说明：
    /// - `context`：是同一请求的最终 server context，不读取传播头重新取值。
    ///
    /// 返回：更新固定 ID 与 flags，不保存额外采样载荷。
    pub fn set_context(&mut self, context: &SpanContext) {
        self.trace_id = context.trace_id().to_bytes();
        self.span_id = context.span_id().to_bytes();
        self.flags = u32::from(context.trace_flags().to_u8());
    }
    /// 业务作用：发布固定形状的请求收尾日志，不复用可能含敏感值的访问日志正文。
    ///
    /// 参数说明：
    /// - `status`：是最终响应头状态、稳定路由 ID 和尝试次数。
    /// - `route`：是最终响应头状态、稳定路由 ID 和尝试次数。
    /// - `attempts`：是最终响应头状态、稳定路由 ID 和尝试次数。
    ///
    /// 返回：日志仅包含标准关联字段和白名单属性，满队列直接丢弃。
    pub fn finish(&self, status: u16, route: Option<&str>, attempts: usize) {
        let mut route = route.unwrap_or("-").to_owned();
        truncate(&mut route, 1024);
        let now = unix_nanos();
        self.sender.record(
            &LogRecord {
                time_unix_nano: now,
                observed_time_unix_nano: now,
                severity_number: if status >= 500 {
                    17
                } else {
                    9
                },
                severity_text: if status >= 500 {
                    "ERROR"
                } else {
                    "INFO"
                }
                .into(),
                body: Some(AnyValue {
                    value: Some(any_value::Value::StringValue("gateway.request".into())),
                }),
                attributes: vec![
                    string_attribute("http.route", &route),
                    integer_attribute("http.response.status_code", i64::from(status)),
                    integer_attribute(
                        "gateway.upstream.attempts",
                        attempts.min(i64::MAX as usize) as i64,
                    ),
                ],
                trace_id: self.trace_id.to_vec(),
                span_id: self.span_id.to_vec(),
                flags: self.flags,
                ..Default::default()
            },
            1,
        );
    }
}

/// 业务作用：把明确的整数字段保持为 OTLP 数值类型。
///
/// 参数说明：
/// - `key`：是静态键与受限事实。
/// - `value`：是静态键与受限事实。
///
/// 返回：无动态标签的整数属性。
fn integer_attribute(key: &str, value: i64) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::IntValue(value)),
        }),
        ..Default::default()
    }
}

/// 业务作用：在 UTF-8 字符边界处限制遥测文本，不以编码错误破坏整个导出批次。
///
/// 参数说明：
/// - `value`：是允许采集的文本
/// - `max`：是字节上限。
///
/// 返回：保留有界合法前缀。
fn truncate(value: &mut String, max: usize) {
    if value.len() > max {
        let mut end = max;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
}

/// 业务作用：将三信号出口累计事实交给统一指标目录，不把 endpoint 或错误正文变成标签。
///
/// 参数说明: 无。
///
/// 返回：固定三十项样本，热换不重置进程计数。
pub(crate) fn export_samples() -> Vec<nametrics_core::MetricSample> {
    let mut samples = Vec::with_capacity(3 * queue::OUTCOMES.len());
    for signal in [Signal::Traces, Signal::Metrics, Signal::Logs] {
        for (index, outcome) in queue::OUTCOMES.iter().enumerate() {
            samples.push(nametrics_core::MetricSample {
                name: "gw_telemetry_export_total",
                labels: vec![
                    ("signal", signal.name().into()),
                    ("outcome", (*outcome).into()),
                ],
                value: nametrics_core::MetricValue::Counter(
                    queue::COUNTERS[signal as usize][index]
                        .load(std::sync::atomic::Ordering::Relaxed),
                ),
            });
        }
    }
    samples
}
