//! V5 OpenTelemetry trace 运行时。
//!
//! 数据面只在 request head 上解析/写入传播头，不读取也不缓存 body。Span 完成后交给 SDK 的
//! bounded `BatchSpanProcessor`；collector 变慢或失联不会反压代理请求。W3C 是权威格式，B3
//! 仅用于兼容提取/附加传播。

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use bytes::BytesMut;
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::{
    SpanBuilder, SpanContext, SpanId, SpanKind, Status, TraceContextExt, TraceFlags, TraceId,
    TraceState, Tracer, TracerProvider as _,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracer, SdkTracerProvider,
};
use opentelemetry_sdk::Resource;

use crate::config::model::TelemetryCfg;

const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");
const B3: HeaderName = HeaderName::from_static("b3");
const X_B3_TRACE_ID: HeaderName = HeaderName::from_static("x-b3-traceid");
const X_B3_SPAN_ID: HeaderName = HeaderName::from_static("x-b3-spanid");
const X_B3_SAMPLED: HeaderName = HeaderName::from_static("x-b3-sampled");
const X_B3_FLAGS: HeaderName = HeaderName::from_static("x-b3-flags");
const X_B3_PARENT_SPAN_ID: HeaderName = HeaderName::from_static("x-b3-parentspanid");
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

static FAST_ID_THREAD_SEQUENCE: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// telemetry 关闭态只需要 W3C 唯一 ID，不需要密码学不可预测性。每个 worker 从一次性 OS
    /// 随机进程种子派生独立 SplitMix64 状态，之后无锁、无 syscall；避免关闭 tracing 后仍为
    /// 每个 server/client span 进入 OTel SDK sampler/allocator。
    static FAST_ID_STATE: Cell<u64> = Cell::new(initial_fast_id_state());
}

#[derive(Clone)]
struct FastPropagationContext {
    trace_id: TraceId,
    trace_flags: TraceFlags,
    trace_state: Option<HeaderValue>,
}

/// 校验 telemetry bootstrap 配置；坏配置在构建快照阶段整轮拒绝。
pub fn validate_config(cfg: &TelemetryCfg) -> Result<()> {
    if !cfg.sample_ratio.is_finite() || !(0.0..=1.0).contains(&cfg.sample_ratio) {
        bail!("telemetry.sample_ratio must be within 0.0..=1.0");
    }
    if cfg.queue_size == 0 {
        bail!("telemetry.queue_size must be > 0");
    }
    if cfg.batch_size == 0 || cfg.batch_size > cfg.queue_size {
        bail!("telemetry.batch_size must be within 1..=queue_size");
    }
    if cfg.scheduled_delay_ms == 0 {
        bail!("telemetry.scheduled_delay_ms must be > 0");
    }
    if cfg.export_timeout_ms == 0 {
        bail!("telemetry.export_timeout_ms must be > 0");
    }
    if cfg.service_name.trim().is_empty() {
        bail!("telemetry.service_name must not be empty");
    }
    if cfg.enabled {
        let uri: http::Uri = cfg
            .endpoint
            .parse()
            .context("telemetry.endpoint must be a valid URI")?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            bail!("telemetry.endpoint must be an absolute http/https URI");
        }
    }
    Ok(())
}

/// telemetry 配置签名；exporter/队列在启动时建一次，reload 改动必须明确拒绝而非静默失效。
pub fn config_signature(cfg: &TelemetryCfg) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        cfg.enabled,
        cfg.endpoint,
        cfg.service_name,
        cfg.sample_ratio.to_bits(),
        cfg.queue_size,
        cfg.batch_size,
        cfg.scheduled_delay_ms,
        cfg.export_timeout_ms,
        cfg.b3_compat
    )
}

/// 进程级 OTel provider/tracer。
///
/// 启用导出时由 SDK tracer 维护完整 span/parent/sampler 语义；`enabled=false` 时仍保留一个
/// AlwaysOff provider 供全局 tracing layer 初始化，但每个请求走轻量传播路径，不再构造 SDK
/// span。轻量路径继续校验/继承受信 W3C/B3 上下文并生成非零关联 ID，因此关闭导出不会破坏
/// request/client span 关联，也不会把 SDK sampler 与上下文分配留在数据面热路径。
pub struct TelemetryRuntime {
    provider: SdkTracerProvider,
    tracer: SdkTracer,
    propagator: TraceContextPropagator,
    b3_compat: bool,
    /// 是否真正记录/导出 span；关闭态仍创建合法上下文以维持 W3C/B3 传播，但不构造属性。
    recording: bool,
}

impl TelemetryRuntime {
    /// 构建进程级 exporter 与有界 batch processor。
    pub fn build(cfg: &TelemetryCfg) -> Result<Arc<Self>> {
        validate_config(cfg)?;
        let sampler = Sampler::ParentBased(Box::new(if cfg.enabled {
            Sampler::TraceIdRatioBased(cfg.sample_ratio)
        } else {
            Sampler::AlwaysOff
        }));
        let resource = Resource::builder()
            .with_service_name(cfg.service_name.clone())
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();
        let mut provider = SdkTracerProvider::builder()
            .with_sampler(sampler)
            .with_resource(resource);

        if cfg.enabled {
            // HTTP/protobuf exporter 使用独立后台线程；请求线程只把已结束 span try_send 到
            // bounded 队列。这里显式配置队列/批次，避免 SDK 环境变量意外放大内存预算。
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                // `with_endpoint` 与 OTEL_* 基地址环境变量语义不同：程序化值被当成最终
                // signal URL，不会自动补 `/v1/traces`。根地址在这里显式规范化。
                .with_endpoint(trace_endpoint(&cfg.endpoint)?)
                .with_timeout(Duration::from_millis(cfg.export_timeout_ms))
                .build()
                .context("build OTLP HTTP span exporter")?;
            let batch = BatchSpanProcessor::builder(exporter)
                .with_batch_config(
                    BatchConfigBuilder::default()
                        .with_max_queue_size(cfg.queue_size)
                        .with_max_export_batch_size(cfg.batch_size)
                        .with_scheduled_delay(Duration::from_millis(cfg.scheduled_delay_ms))
                        .build(),
                )
                .build();
            provider = provider.with_span_processor(batch);
        }

        let provider = provider.build();
        let tracer = provider.tracer("gateway.data-plane");
        Ok(Arc::new(Self {
            provider,
            tracer,
            propagator: TraceContextPropagator::new(),
            b3_compat: cfg.b3_compat,
            recording: cfg.enabled,
        }))
    }

    /// 返回给 `tracing-opentelemetry` layer 的 SDK tracer；clone 只共享 provider 内部 Arc。
    pub fn tracer(&self) -> SdkTracer {
        self.tracer.clone()
    }

    /// 创建 server span，并把请求头规范化为本 span 的传播上下文。
    ///
    /// 只有可信入口会读取远端 W3C/B3；不可信入口的所有 trace 头先清除再开新 root，防止
    /// trace 注入。HeaderMap 原地更新，不 clone 整张表。
    pub fn begin_server(
        &self,
        headers: &mut HeaderMap,
        trusted_inbound: bool,
        method: &http::Method,
        path: &str,
        scheme: &'static str,
        peer_ip: std::net::IpAddr,
    ) -> ServerTrace {
        if !self.recording {
            return self.begin_fast_server(headers, trusted_inbound);
        }
        let rejected_untrusted_context = !trusted_inbound && has_trace_headers(headers);
        let parent = if trusted_inbound {
            let w3c = self
                .propagator
                .extract_with_context(&Context::new(), &HeaderExtractor(headers));
            if w3c.span().span_context().is_valid() {
                w3c
            } else if self.b3_compat {
                extract_b3(headers).unwrap_or_default()
            } else {
                Context::new()
            }
        } else {
            Context::new()
        };

        remove_trace_headers(headers);
        let builder = if self.recording {
            SpanBuilder::from_name(format!("{} {}", method.as_str(), path))
                .with_kind(SpanKind::Server)
                .with_attributes([
                    KeyValue::new("http.request.method", method.as_str().to_owned()),
                    KeyValue::new("url.path", path.to_owned()),
                    KeyValue::new("url.scheme", scheme),
                    KeyValue::new("client.address", peer_ip.to_string()),
                    KeyValue::new("gateway.trace_context_rejected", rejected_untrusted_context),
                ])
        } else {
            // AlwaysOff 仍需要一个有效 span context 来生成/转发 traceparent；静态名称不会分配，
            // 且关闭态没有 exporter，构造 HTTP/route/client 等属性没有任何可观察价值。
            SpanBuilder::from_name("gateway.request").with_kind(SpanKind::Server)
        };
        let span = self.tracer.build_with_context(builder, &parent);
        let context = parent.with_span(span);
        inject_context(&self.propagator, &context, headers, self.b3_compat);
        ServerTrace {
            tracer: Some(self.tracer.clone()),
            propagator: Some(self.propagator.clone()),
            context: Some(context),
            fast: None,
            b3_compat: self.b3_compat,
            recording: self.recording,
            finished: false,
        }
    }

    /// telemetry 关闭态只保留传播与信任边界，不构造 SDK span/sampler/attributes。
    fn begin_fast_server(&self, headers: &mut HeaderMap, trusted_inbound: bool) -> ServerTrace {
        let parent =
            trusted_inbound.then(|| extract_fast_parent(&self.propagator, headers, self.b3_compat));
        let parent = parent.flatten();
        let fast = parent.unwrap_or_else(|| FastPropagationContext {
            trace_id: fast_trace_id(),
            trace_flags: TraceFlags::NOT_SAMPLED,
            trace_state: None,
        });
        remove_trace_headers(headers);
        inject_fast_context(&fast, fast_span_id(), headers, self.b3_compat);
        ServerTrace {
            tracer: None,
            propagator: None,
            context: None,
            fast: Some(fast),
            b3_compat: self.b3_compat,
            recording: false,
            finished: false,
        }
    }

    /// 进程退出前尽量 flush 已结束 span；超时/collector 故障只记错误，不改变停机语义。
    pub fn shutdown(&self) -> Result<()> {
        self.provider
            .shutdown()
            .map_err(|error| anyhow::anyhow!("shutdown OpenTelemetry provider: {error}"))
    }
}

fn trace_endpoint(configured: &str) -> Result<String> {
    let uri: http::Uri = configured
        .parse()
        .context("telemetry.endpoint must be a valid URI")?;
    match uri.path_and_query().map(|value| value.as_str()) {
        None | Some("/") => Ok(format!("{}/v1/traces", configured.trim_end_matches('/'))),
        Some(_) => Ok(configured.to_owned()),
    }
}

/// 单请求 server span 上下文；client attempt 只 clone OTel `Context` 内部共享指针。
pub struct ServerTrace {
    tracer: Option<SdkTracer>,
    propagator: Option<TraceContextPropagator>,
    context: Option<Context>,
    /// telemetry 关闭态的无 SDK 传播上下文；启用态为空。
    fast: Option<FastPropagationContext>,
    b3_compat: bool,
    recording: bool,
    finished: bool,
}

impl ServerTrace {
    /// 返回供 access log 持有的 trace-id。
    ///
    /// 只在 producer 确认日志启用后才调用并分配 `Arc<str>`；关闭 access log 的默认热路径
    /// 不再为了一个无人读取的字段格式化 128-bit id。
    pub fn trace_id(&self) -> Arc<str> {
        let trace_id = if let Some(context) = self.context.as_ref() {
            context.span().span_context().trace_id()
        } else {
            self.fast
                .as_ref()
                .expect("server trace has recording or fast context")
                .trace_id
        };
        Arc::from(trace_id.to_string())
    }

    /// 为一次真实上游尝试创建 client span，并覆盖传播头为该 client span。
    pub fn begin_client(
        &self,
        headers: &mut HeaderMap,
        upstream: &str,
        attempt: usize,
    ) -> ClientTrace {
        if let Some(fast) = self.fast.as_ref() {
            prepare_fast_client_trace_headers(headers, fast, self.b3_compat);
            inject_fast_context(fast, fast_span_id(), headers, self.b3_compat);
            return ClientTrace {
                context: None,
                recording: false,
                finished: false,
            };
        }
        let parent = self
            .context
            .as_ref()
            .expect("recording server trace has context");
        let builder = if self.recording {
            SpanBuilder::from_name("HTTP upstream")
                .with_kind(SpanKind::Client)
                .with_attributes([
                    KeyValue::new("server.address", upstream.to_owned()),
                    KeyValue::new("gateway.upstream.attempt", attempt as i64),
                ])
        } else {
            SpanBuilder::from_name("gateway.upstream").with_kind(SpanKind::Client)
        };
        let span = self
            .tracer
            .as_ref()
            .expect("recording server trace has tracer")
            .build_with_context(builder, parent);
        let context = parent.with_span(span);
        prepare_client_trace_headers(headers, self.b3_compat);
        inject_context(
            self.propagator
                .as_ref()
                .expect("recording server trace has propagator"),
            &context,
            headers,
            self.b3_compat,
        );
        ClientTrace {
            context: Some(context),
            recording: self.recording,
            finished: false,
        }
    }

    /// 完成 server span，记录最终路由、真实上游尝试与下游状态。
    pub fn finish(
        &mut self,
        status: u16,
        route: Option<&str>,
        upstream: Option<&str>,
        attempts: usize,
    ) {
        if let Some(context) = self.context.as_ref() {
            let span = context.span();
            if self.recording {
                span.set_attributes([
                    KeyValue::new("http.response.status_code", i64::from(status)),
                    KeyValue::new("http.route", route.unwrap_or("-").to_owned()),
                    KeyValue::new("server.address", upstream.unwrap_or("-").to_owned()),
                    KeyValue::new("gateway.upstream.attempts", attempts as i64),
                ]);
                if status >= 500 {
                    span.set_status(Status::error(format!("HTTP {status}")));
                }
            }
            span.end();
        }
        self.finished = true;
    }
}

impl Drop for ServerTrace {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Handler future 被下游取消时仍结束 span，避免 exporter 中出现永久悬挂；不做 IO。
        if let Some(context) = self.context.as_ref() {
            let span = context.span();
            if self.recording {
                span.set_attribute(KeyValue::new("gateway.request.cancelled", true));
                span.set_status(Status::error("request cancelled"));
            }
            span.end();
        }
    }
}

/// 单次上游 client span。Drop 是取消/早退兜底。
pub struct ClientTrace {
    context: Option<Context>,
    recording: bool,
    finished: bool,
}

impl ClientTrace {
    /// 上游返回 response head 后完成 span。
    pub fn finish_status(mut self, status: u16) {
        if let Some(context) = self.context.as_ref() {
            let span = context.span();
            if self.recording {
                span.set_attribute(KeyValue::new(
                    "http.response.status_code",
                    i64::from(status),
                ));
                if status >= 400 {
                    span.set_status(Status::error(format!("HTTP {status}")));
                }
            }
            span.end();
        }
        self.finished = true;
    }

    /// 上游连接/协议/超时失败时完成 span；错误文本只进 span，不作为 metric label。
    pub fn finish_error(mut self, error: &str) {
        if let Some(context) = self.context.as_ref() {
            let span = context.span();
            if self.recording {
                span.set_status(Status::error(error.to_owned()));
            }
            span.end();
        }
        self.finished = true;
    }
}

impl Drop for ClientTrace {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(context) = self.context.as_ref() {
            let span = context.span();
            if self.recording {
                span.set_attribute(KeyValue::new("gateway.upstream.cancelled", true));
                span.set_status(Status::error("upstream attempt cancelled"));
            }
            span.end();
        }
    }
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        // SDK 会为无 TraceState 的 root 写空 `tracestate`。空传播头没有语义，却会让下游误以为
        // 网关保留了不可信输入；原地删除还能少建一个 HeaderValue。
        if value.is_empty() {
            self.0.remove(key);
            return;
        }
        let Ok(name) = HeaderName::from_bytes(key.as_bytes()) else {
            return;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            return;
        };
        self.0.insert(name, value);
    }
}

fn inject_context(
    propagator: &TraceContextPropagator,
    context: &Context,
    headers: &mut HeaderMap,
    b3_compat: bool,
) {
    propagator.inject_context(context, &mut HeaderInjector(headers));
    if b3_compat {
        let span = context.span();
        let span_context = span.span_context();
        if span_context.is_valid() {
            let sampled = if span_context.is_sampled() { '1' } else { '0' };
            let value = format!(
                "{}-{}-{sampled}",
                span_context.trace_id(),
                span_context.span_id()
            );
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(B3, value);
            }
        }
    }
}

/// 从可信入口提取一次父上下文；关闭 telemetry 时只保留传播需要的三个小字段。
fn extract_fast_parent(
    propagator: &TraceContextPropagator,
    headers: &HeaderMap,
    b3_compat: bool,
) -> Option<FastPropagationContext> {
    let w3c = propagator.extract_with_context(&Context::new(), &HeaderExtractor(headers));
    if let Some(parent) = fast_context_from_otel(&w3c) {
        return Some(parent);
    }
    b3_compat
        .then(|| extract_b3(headers))
        .flatten()
        .and_then(|context| fast_context_from_otel(&context))
}

fn fast_context_from_otel(context: &Context) -> Option<FastPropagationContext> {
    let span = context.span();
    let span_context = span.span_context();
    if !span_context.is_valid() {
        return None;
    }
    let trace_state = span_context.trace_state().header();
    Some(FastPropagationContext {
        trace_id: span_context.trace_id(),
        trace_flags: span_context.trace_flags(),
        trace_state: (!trace_state.is_empty())
            .then(|| HeaderValue::from_str(&trace_state).ok())
            .flatten(),
    })
}

/// 直接写固定名称的 W3C/B3 header。每个 HeaderValue 只有最终的一份必要存储；没有 SDK
/// SpanBuilder、Context 链、String key 或 HeaderName 解析。
fn inject_fast_context(
    context: &FastPropagationContext,
    span_id: SpanId,
    headers: &mut HeaderMap,
    b3_compat: bool,
) {
    let (traceparent, b3) =
        encode_fast_headers(context.trace_id, span_id, context.trace_flags, b3_compat);
    headers.insert(TRACEPARENT, traceparent);
    if let Some(trace_state) = context.trace_state.as_ref() {
        headers.insert(TRACESTATE, trace_state.clone());
    }
    if let Some(b3) = b3 {
        headers.insert(B3, b3);
    }
}

/// 编码关闭态传播头；启用 B3 时 W3C/B3 两个 HeaderValue 共享一块 immutable Bytes。
///
/// `HeaderValue::from_bytes` 会分别复制栈数组，因此默认 B3 兼容路径原来每个 server/client span
/// 都做两次 allocator 调用和两次 payload copy。这里一次分配 106 字节、原地写入两个固定格式，
/// freeze 后用 `Bytes::slice` 建两个共享 owner；HeaderMap 仍分别拥有合法值，删除/替换任一 header
/// 都不会影响另一个。未启用 B3 时保留 55 字节栈缓冲，避免为了单个短值引入 BytesMut 管理。
fn encode_fast_headers(
    trace_id: TraceId,
    span_id: SpanId,
    flags: TraceFlags,
    b3_compat: bool,
) -> (HeaderValue, Option<HeaderValue>) {
    const TRACEPARENT_LEN: usize = 55;
    const B3_LEN: usize = 51;

    if !b3_compat {
        let mut traceparent = [0_u8; TRACEPARENT_LEN];
        encode_traceparent_into(trace_id, span_id, flags, &mut traceparent);
        return (
            HeaderValue::from_bytes(&traceparent).expect("fixed lowercase W3C traceparent"),
            None,
        );
    }

    let mut encoded = BytesMut::with_capacity(TRACEPARENT_LEN + B3_LEN);
    encoded.resize(TRACEPARENT_LEN + B3_LEN, 0);
    encode_traceparent_into(trace_id, span_id, flags, &mut encoded[..TRACEPARENT_LEN]);
    encode_b3_into(
        trace_id,
        span_id,
        flags.is_sampled(),
        &mut encoded[TRACEPARENT_LEN..],
    );
    let encoded = encoded.freeze();
    let traceparent = HeaderValue::from_maybe_shared(encoded.slice(..TRACEPARENT_LEN))
        .expect("fixed lowercase W3C traceparent");
    let b3 = HeaderValue::from_maybe_shared(encoded.slice(TRACEPARENT_LEN..))
        .expect("fixed lowercase B3 single header");
    (traceparent, Some(b3))
}

fn encode_traceparent_into(
    trace_id: TraceId,
    span_id: SpanId,
    flags: TraceFlags,
    encoded: &mut [u8],
) {
    debug_assert_eq!(encoded.len(), 55);
    encoded[..3].copy_from_slice(b"00-");
    encode_hex(&trace_id.to_bytes(), &mut encoded[3..35]);
    encoded[35] = b'-';
    encode_hex(&span_id.to_bytes(), &mut encoded[36..52]);
    encoded[52] = b'-';
    encode_hex(&[flags.to_u8()], &mut encoded[53..55]);
}

fn encode_b3_into(trace_id: TraceId, span_id: SpanId, sampled: bool, encoded: &mut [u8]) {
    debug_assert_eq!(encoded.len(), 51);
    encode_hex(&trace_id.to_bytes(), &mut encoded[..32]);
    encoded[32] = b'-';
    encode_hex(&span_id.to_bytes(), &mut encoded[33..49]);
    encoded[49] = b'-';
    encoded[50] = if sampled { b'1' } else { b'0' };
}

fn encode_hex(source: &[u8], target: &mut [u8]) {
    debug_assert_eq!(target.len(), source.len() * 2);
    for (byte, pair) in source.iter().zip(target.chunks_exact_mut(2)) {
        pair[0] = LOWER_HEX[usize::from(byte >> 4)];
        pair[1] = LOWER_HEX[usize::from(byte & 0x0f)];
    }
}

fn fast_trace_id() -> TraceId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&fast_nonzero_u64().to_be_bytes());
    bytes[8..].copy_from_slice(&fast_nonzero_u64().to_be_bytes());
    TraceId::from_bytes(bytes)
}

fn fast_span_id() -> SpanId {
    SpanId::from_bytes(fast_nonzero_u64().to_be_bytes())
}

fn fast_nonzero_u64() -> u64 {
    FAST_ID_STATE.with(|state| {
        let next = state.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
        state.set(next);
        splitmix64(next).max(1)
    })
}

fn initial_fast_id_state() -> u64 {
    static PROCESS_SEED: OnceLock<u64> = OnceLock::new();
    let process_seed = *PROCESS_SEED.get_or_init(|| {
        let mut seed = [0_u8; 8];
        if getrandom::getrandom(&mut seed).is_ok() {
            u64::from_ne_bytes(seed)
        } else {
            // OS RNG failure is not fatal for a non-security correlation id. Wall clock and pid
            // only seed the process once; the per-thread sequence below still prevents duplicates.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            nanos ^ u64::from(std::process::id())
        }
    });
    let thread_sequence = FAST_ID_THREAD_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    splitmix64(process_seed ^ thread_sequence).max(1)
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn has_trace_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(&TRACEPARENT)
        || headers.contains_key(&TRACESTATE)
        || headers.contains_key(&B3)
        || headers.contains_key(&X_B3_TRACE_ID)
        || headers.contains_key(&X_B3_SPAN_ID)
}

fn remove_trace_headers(headers: &mut HeaderMap) {
    // 这些名字位于每条请求的 server/client 两段传播路径。使用编译期 HeaderName 可直接
    // 复用 http crate 的标准头索引/预计算表示，避免 `&str` AsHeaderName 每次重新校验 ASCII、
    // 小写化并识别标准头。只原地删除 map entry，不 clone HeaderMap 或 HeaderValue。
    headers.remove(TRACEPARENT);
    headers.remove(TRACESTATE);
    headers.remove(B3);
    remove_legacy_b3_headers(headers);
}

/// 清除 B3 multi-header 兼容字段。server trust boundary 与每次 client 最终盖章都会调用；
/// 单独成函数可让 client 路径跳过马上会被 `insert` 覆盖的 W3C/B3 single 字段。
#[inline]
fn remove_legacy_b3_headers(headers: &mut HeaderMap) {
    headers.remove(X_B3_TRACE_ID);
    headers.remove(X_B3_SPAN_ID);
    headers.remove(X_B3_SAMPLED);
    headers.remove(X_B3_FLAGS);
    headers.remove(X_B3_PARENT_SPAN_ID);
}

/// 为 SDK client span 最终盖章清理旁路字段。
///
/// `inject_context` 必定覆盖 traceparent，并对空 tracestate 执行删除；启用 B3 时也会覆盖 B3
/// single。因此这里不做“先 remove、后 insert”的重复哈希查表，只清理注入器不会写的字段。
#[inline]
fn prepare_client_trace_headers(headers: &mut HeaderMap, b3_compat: bool) {
    remove_legacy_b3_headers(headers);
    if !b3_compat {
        headers.remove(B3);
    }
}

/// telemetry 关闭态的无 SDK client 盖章准备。
///
/// fast injector 总会覆盖 traceparent；有 trace state/B3 时也会覆盖对应字段。缺失时必须显式
/// 删除用户 filter/plugin 可能在 server span 之后写入的旧值，确保优化不削弱最终信任边界。
#[inline]
fn prepare_fast_client_trace_headers(
    headers: &mut HeaderMap,
    context: &FastPropagationContext,
    b3_compat: bool,
) {
    prepare_client_trace_headers(headers, b3_compat);
    if context.trace_state.is_none() {
        headers.remove(TRACESTATE);
    }
}

fn extract_b3(headers: &HeaderMap) -> Option<Context> {
    if let Some(single) = headers.get(&B3).and_then(|value| value.to_str().ok()) {
        let mut fields = single.split('-');
        let trace_id = fields.next()?;
        let span_id = fields.next()?;
        let sampled = fields.next().map(b3_sampled).unwrap_or(false);
        return remote_context(trace_id, span_id, sampled);
    }

    let trace_id = headers.get(&X_B3_TRACE_ID)?.to_str().ok()?;
    let span_id = headers.get(&X_B3_SPAN_ID)?.to_str().ok()?;
    let sampled = headers
        .get(&X_B3_FLAGS)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1")
        || headers
            .get(&X_B3_SAMPLED)
            .and_then(|value| value.to_str().ok())
            .is_some_and(b3_sampled);
    remote_context(trace_id, span_id, sampled)
}

fn b3_sampled(value: &str) -> bool {
    matches!(value, "1" | "true" | "d")
}

fn remote_context(trace_id: &str, span_id: &str, sampled: bool) -> Option<Context> {
    if !matches!(trace_id.len(), 16 | 32)
        || span_id.len() != 16
        || !trace_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !span_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let trace_id = TraceId::from_hex(trace_id).ok()?;
    let span_id = SpanId::from_hex(span_id).ok()?;
    if trace_id == TraceId::INVALID || span_id == SpanId::INVALID {
        return None;
    }
    let flags = if sampled {
        TraceFlags::SAMPLED
    } else {
        TraceFlags::NOT_SAMPLED
    };
    Some(Context::new().with_remote_span_context(SpanContext::new(
        trace_id,
        span_id,
        flags,
        true,
        TraceState::default(),
    )))
}

#[path = "../../tests/unit/telemetry.rs"]
#[cfg(test)]
mod tests;
