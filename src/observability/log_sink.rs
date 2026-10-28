//! access-log 多 sink 投递。
//!
//! 数据面不直接调用本模块：[`crate::observability::access_log::AccessLogger`] 先在共享 bounded queue 中
//! 采样并把记录序列化一次，再用 `Arc<LogEnvelope>` fan-out。每个 sink 拥有独立 channel、
//! batch deadline 和 I/O timeout；任一远端卡住只会填满并丢弃自己的队列。

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use tokio::sync::mpsc;

use crate::config::model::{AccessLogSinkCfg, AccessLogSinkKind};
use crate::observability::access_log::{log_record, AccessRecord};
use crate::observability::metrics::Metrics;

/// 配置允许的 sink 数量硬上限。它同时约束 fan-out 次数和 metrics sink label 基数。
const MAX_LOG_SINKS: usize = 16;
/// 单 sink queue 硬上限，避免 bootstrap 误配预留过多 channel slots。
const MAX_LOG_SINK_QUEUE: usize = 1_000_000;
/// 单批记录数硬上限。
const MAX_LOG_SINK_BATCH: usize = 10_000;
/// 单条外发 access event 上限硬保护。
const MAX_LOG_EVENT_BYTES: usize = 1024 * 1024;

/// 已完成一次共享序列化的 access-log envelope。
pub(crate) struct LogEnvelope {
    /// 原始拥有型记录只以 Arc 跨 tracing sink 共享，不复制 method/URI/upstream 字符串。
    pub(crate) record: Arc<AccessRecord>,
    /// 所有远端 sink 共享同一 JSON allocation。
    pub(crate) json: Bytes,
    /// Loki 要求 Unix 纳秒字符串；仅 Loki backend 在组 batch 时格式化。
    pub(crate) unix_nanos: u128,
    /// 可选自定义 format，只渲染一次并与 tracing sink 共享。
    pub(crate) formatted: Option<Arc<str>>,
}

/// build-then-swap 时已校验并解析 SecretSource 的 sink bootstrap 计划。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LogSinkSpec {
    pub(crate) id: Arc<str>,
    pub(crate) kind: AccessLogSinkKind,
    pub(crate) queue_size: usize,
    pub(crate) batch_size: usize,
    pub(crate) batch_delay: Duration,
    pub(crate) timeout: Duration,
    pub(crate) endpoint: Arc<str>,
    pub(crate) headers: HeaderMap,
    pub(crate) index: Arc<str>,
    pub(crate) bootstrap_servers: Arc<str>,
    pub(crate) topic: Arc<str>,
    pub(crate) lane: Arc<str>,
    pub(crate) max_event_bytes: usize,
}

/// dispatcher 到单 sink worker 的非阻塞句柄。
pub(crate) struct LogSinkSender {
    id: Arc<str>,
    max_event_bytes: usize,
    tx: mpsc::Sender<Arc<LogEnvelope>>,
    metrics: Arc<Metrics>,
}

/// Dispatcher 独占的 worker 集合；先 drop senders 关闭 channel，再 await handles 完成 flush。
pub(crate) struct SpawnedLogSinks {
    pub(crate) senders: Vec<LogSinkSender>,
    pub(crate) workers: Vec<tokio::task::JoinHandle<()>>,
}

impl LogSinkSender {
    /// 业务作用：非阻塞 fan-out；满载或单条过大只归因并丢弃当前 sink。
    pub(crate) fn try_send(&self, event: Arc<LogEnvelope>) {
        if event.json.len() > self.max_event_bytes {
            self.metrics
                .inc_log_sink_dropped(self.id.as_ref(), 1, "oversized");
            return;
        }
        if self.tx.try_send(event).is_err() {
            self.metrics
                .inc_log_sink_dropped(self.id.as_ref(), 1, "queue_full");
        }
    }
}

/// 可插拔 sink 契约。异步 future 只在该 sink 的后台 worker 被 poll，永不进入数据面 task。
trait LogSink: Send + Sync {
    /// 业务作用：投递一批共享 envelope。
    fn send_batch<'a>(
        &'a self,
        batch: &'a [Arc<LogEnvelope>],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// 业务作用：drain 完成后的 backend 关闭/flush。
    fn shutdown(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            Ok(())
        })
    }
}

/// 业务作用：校验/解析所有 sink 配置。空列表兼容旧配置，生成一个本地 tracing sink。
pub(crate) fn build_sink_specs(
    cfgs: &[AccessLogSinkCfg],
    config_dir: &Path,
    fallback_queue_size: usize,
) -> Result<Arc<[LogSinkSpec]>> {
    let fallback;
    let cfgs = if cfgs.is_empty() {
        fallback = vec![AccessLogSinkCfg {
            id: "tracing".to_string(),
            kind: AccessLogSinkKind::Tracing,
            enabled: true,
            queue_size: fallback_queue_size.max(1),
            batch_size: 1,
            batch_delay_ms: 1,
            timeout_ms: 3000,
            endpoint: String::new(),
            headers: Default::default(),
            index: String::new(),
            bootstrap_servers: String::new(),
            topic: String::new(),
            lane: "default".to_string(),
            max_event_bytes: 256 * 1024,
        }];
        fallback.as_slice()
    } else {
        cfgs
    };
    let enabled = cfgs.iter().filter(|cfg| cfg.enabled).count();
    if enabled == 0 {
        bail!("access_log.sinks must contain at least one enabled sink");
    }
    if enabled > MAX_LOG_SINKS {
        bail!("access_log.sinks supports at most {MAX_LOG_SINKS} enabled sinks");
    }

    let mut specs = Vec::with_capacity(enabled);
    for cfg in cfgs.iter().filter(|cfg| cfg.enabled) {
        validate_sink_id(cfg.id.as_str())?;
        if specs
            .iter()
            .any(|spec: &LogSinkSpec| spec.id.as_ref() == cfg.id)
        {
            bail!("duplicate access_log sink id `{}`", cfg.id);
        }
        if !(1..=MAX_LOG_SINK_QUEUE).contains(&cfg.queue_size) {
            bail!(
                "access_log sink `{}` queue_size must be within 1..={MAX_LOG_SINK_QUEUE}",
                cfg.id
            );
        }
        if !(1..=MAX_LOG_SINK_BATCH).contains(&cfg.batch_size) || cfg.batch_size > cfg.queue_size {
            bail!(
                "access_log sink `{}` batch_size must be within 1..=min(queue_size,{MAX_LOG_SINK_BATCH})",
                cfg.id
            );
        }
        if !(1..=60_000).contains(&cfg.batch_delay_ms) {
            bail!(
                "access_log sink `{}` batch_delay_ms must be within 1..=60000",
                cfg.id
            );
        }
        if !(100..=120_000).contains(&cfg.timeout_ms) {
            bail!(
                "access_log sink `{}` timeout_ms must be within 100..=120000",
                cfg.id
            );
        }
        if !(1024..=MAX_LOG_EVENT_BYTES).contains(&cfg.max_event_bytes) {
            bail!(
                "access_log sink `{}` max_event_bytes must be within 1024..={MAX_LOG_EVENT_BYTES}",
                cfg.id
            );
        }

        validate_kind_fields(cfg)?;
        let mut headers = HeaderMap::with_capacity(cfg.headers.len());
        for (name, raw_value) in &cfg.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).with_context(|| {
                format!("access_log sink `{}` invalid header name `{name}`", cfg.id)
            })?;
            if is_forbidden_sink_header(&name) {
                bail!(
                    "access_log sink `{}` header `{}` is transport-managed and cannot be configured",
                    cfg.id,
                    name
                );
            }
            let value = crate::security::secret::resolve_text(
                raw_value,
                config_dir,
                &format!("access_log.sinks.{}.headers.{name}", cfg.id),
            )?;
            if value.len() > 16 * 1024 {
                bail!("access_log sink `{}` header `{name}` exceeds 16KiB", cfg.id);
            }
            let value = HeaderValue::from_str(&value).with_context(|| {
                format!(
                    "access_log sink `{}` header `{name}` has invalid value",
                    cfg.id
                )
            })?;
            headers.append(name, value);
        }
        specs.push(LogSinkSpec {
            id: Arc::from(cfg.id.as_str()),
            kind: cfg.kind,
            queue_size: cfg.queue_size,
            batch_size: cfg.batch_size,
            batch_delay: Duration::from_millis(cfg.batch_delay_ms),
            timeout: Duration::from_millis(cfg.timeout_ms),
            endpoint: Arc::from(cfg.endpoint.as_str()),
            headers,
            index: Arc::from(cfg.index.as_str()),
            bootstrap_servers: Arc::from(cfg.bootstrap_servers.as_str()),
            topic: Arc::from(cfg.topic.as_str()),
            lane: Arc::from(cfg.lane.as_str()),
            max_event_bytes: cfg.max_event_bytes,
        });
    }
    Ok(specs.into())
}

/// 业务作用：约束日志出口标识，使观测维度和后台任务身份保持稳定且有界。
fn validate_sink_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("access_log sink id `{id}` must be 1..=64 ASCII [A-Za-z0-9._-]");
    }
    Ok(())
}

/// 业务作用：拒绝与出口类型不匹配的配置字段，避免配置成功却静默忽略安全参数。
fn validate_kind_fields(cfg: &AccessLogSinkCfg) -> Result<()> {
    match cfg.kind {
        AccessLogSinkKind::Tracing => {
            if !cfg.endpoint.is_empty()
                || !cfg.bootstrap_servers.is_empty()
                || !cfg.topic.is_empty()
                || !cfg.headers.is_empty()
                || !cfg.index.is_empty()
            {
                bail!(
                    "access_log tracing sink `{}` cannot configure remote fields",
                    cfg.id
                );
            }
        }
        AccessLogSinkKind::Http | AccessLogSinkKind::Loki => {
            validate_http_endpoint(cfg.id.as_str(), cfg.endpoint.as_str())?;
            if !cfg.bootstrap_servers.is_empty() || !cfg.topic.is_empty() || !cfg.index.is_empty() {
                bail!(
                    "access_log HTTP/Loki sink `{}` contains fields for another sink type",
                    cfg.id
                );
            }
        }
        AccessLogSinkKind::Elasticsearch => {
            validate_http_endpoint(cfg.id.as_str(), cfg.endpoint.as_str())?;
            if cfg.index.is_empty()
                || cfg.index.len() > 255
                || !cfg.index.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
            {
                bail!(
                    "access_log Elasticsearch sink `{}` has invalid lowercase index",
                    cfg.id
                );
            }
            if !cfg.bootstrap_servers.is_empty() || !cfg.topic.is_empty() {
                bail!(
                    "access_log Elasticsearch sink `{}` contains Kafka fields",
                    cfg.id
                );
            }
        }
        AccessLogSinkKind::Kafka => {
            if cfg.bootstrap_servers.trim().is_empty() {
                bail!(
                    "access_log Kafka sink `{}` requires bootstrap_servers",
                    cfg.id
                );
            }
            validate_kafka_name("topic", cfg.topic.as_str(), cfg.id.as_str())?;
            validate_kafka_name("lane", cfg.lane.as_str(), cfg.id.as_str())?;
            if !cfg.endpoint.is_empty() || !cfg.headers.is_empty() || !cfg.index.is_empty() {
                bail!(
                    "access_log Kafka sink `{}` contains HTTP/Elasticsearch fields",
                    cfg.id
                );
            }
            #[cfg(not(feature = "log-kafka"))]
            bail!(
                "access_log Kafka sink `{}` requires gateway feature `log-kafka`",
                cfg.id
            );
        }
    }
    Ok(())
}

/// 业务作用：验证固定日志 HTTP 目的地，不允许请求数据选择外发地址。
fn validate_http_endpoint(id: &str, endpoint: &str) -> Result<()> {
    let uri: http::Uri = endpoint
        .parse()
        .with_context(|| format!("access_log sink `{id}` invalid endpoint"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        bail!("access_log sink `{id}` endpoint must be absolute http/https URI");
    }
    Ok(())
}

/// 业务作用：校验 Kafka 主题与相关标识，阻止非法或过长名称进入后台生产者。
fn validate_kafka_name(label: &str, value: &str, id: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 249
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("access_log Kafka sink `{id}` invalid {label}");
    }
    Ok(())
}

/// 业务作用：识别日志外发不能覆盖的协议控制头，维持固定传输合同。
fn is_forbidden_sink_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host" | "content-length" | "content-type" | "transfer-encoding" | "connection"
    )
}

/// 业务作用：启动所有 sink worker。每项先完成本地 client 构造；任一配置/客户端错误会让进程启动失败。
pub(crate) fn spawn_sink_workers(
    specs: &[LogSinkSpec],
    metrics: Arc<Metrics>,
) -> Result<SpawnedLogSinks> {
    let mut senders = Vec::with_capacity(specs.len());
    let mut workers = Vec::with_capacity(specs.len());
    for spec in specs {
        metrics.register_log_sink(spec.id.as_ref());
        let backend = build_backend(spec)?;
        let (tx, rx) = mpsc::channel(spec.queue_size);
        workers.push(tokio::spawn(run_sink_worker(
            spec.clone(),
            backend,
            metrics.clone(),
            rx,
        )));
        senders.push(LogSinkSender {
            id: spec.id.clone(),
            max_event_bytes: spec.max_event_bytes,
            tx,
            metrics: metrics.clone(),
        });
    }
    Ok(SpawnedLogSinks {
        senders,
        workers,
    })
}

/// 业务作用：按已验证的出口类型构建后台发送器，未编译的能力明确拒绝。
fn build_backend(spec: &LogSinkSpec) -> Result<Arc<dyn LogSink>> {
    match spec.kind {
        AccessLogSinkKind::Tracing => Ok(Arc::new(TracingLogSink)),
        AccessLogSinkKind::Http | AccessLogSinkKind::Elasticsearch | AccessLogSinkKind::Loki => {
            let client = reqwest::Client::builder()
                .default_headers(spec.headers.clone())
                .timeout(spec.timeout)
                .user_agent("gateway-access-log/1")
                .build()
                .with_context(|| format!("build access_log HTTP client `{}`", spec.id))?;
            Ok(Arc::new(HttpLogSink {
                client,
                endpoint: spec.endpoint.clone(),
                mode: match spec.kind {
                    AccessLogSinkKind::Http => HttpPayloadMode::JsonArray,
                    AccessLogSinkKind::Elasticsearch => {
                        HttpPayloadMode::Elasticsearch(spec.index.clone())
                    }
                    AccessLogSinkKind::Loki => HttpPayloadMode::Loki(spec.id.clone()),
                    _ => unreachable!("HTTP kinds matched above"),
                },
            }))
        }
        AccessLogSinkKind::Kafka => build_kafka_backend(spec),
    }
}

/// 业务作用：消费有界日志队列并批量发送，依赖慢或失败时不阻塞业务请求线程。
async fn run_sink_worker(
    spec: LogSinkSpec,
    backend: Arc<dyn LogSink>,
    metrics: Arc<Metrics>,
    mut rx: mpsc::Receiver<Arc<LogEnvelope>>,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = Vec::with_capacity(spec.batch_size);
        batch.push(first);
        let delay = tokio::time::sleep(spec.batch_delay);
        tokio::pin!(delay);
        let mut channel_closed = false;
        while batch.len() < spec.batch_size {
            tokio::select! {
                next = rx.recv() => match next {
                    Some(event) => batch.push(event),
                    None => {
                        channel_closed = true;
                        break;
                    }
                },
                _ = &mut delay => break,
            }
        }
        let result = tokio::time::timeout(spec.timeout, backend.send_batch(batch.as_slice())).await;
        match result {
            Ok(Ok(())) => metrics.inc_log_sink_delivered(spec.id.as_ref(), batch.len() as u64),
            Ok(Err(error)) => {
                metrics.inc_log_sink_error(spec.id.as_ref());
                metrics.inc_log_sink_dropped(spec.id.as_ref(), batch.len() as u64, "delivery");
                tracing::warn!(sink = %spec.id, error = %error, records = batch.len(), "access log sink delivery failed");
            }
            Err(_) => {
                metrics.inc_log_sink_error(spec.id.as_ref());
                metrics.inc_log_sink_dropped(spec.id.as_ref(), batch.len() as u64, "delivery");
                tracing::warn!(sink = %spec.id, timeout_ms = spec.timeout.as_millis(), records = batch.len(), "access log sink timed out");
            }
        }
        if channel_closed {
            break;
        }
    }
    if let Err(error) = backend.shutdown().await {
        metrics.inc_log_sink_error(spec.id.as_ref());
        tracing::warn!(sink = %spec.id, error = %error, "access log sink shutdown failed");
    }
}

struct TracingLogSink;

impl LogSink for TracingLogSink {
    /// 业务作用：将一批日志发送到固定出口，统一执行超时和失败统计而不重入业务管线。
    fn send_batch<'a>(
        &'a self,
        batch: &'a [Arc<LogEnvelope>],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            for event in batch {
                log_record(event.record.as_ref(), event.formatted.as_deref());
            }
            Ok(())
        })
    }
}

enum HttpPayloadMode {
    JsonArray,
    Elasticsearch(Arc<str>),
    Loki(Arc<str>),
}

struct HttpLogSink {
    client: reqwest::Client,
    endpoint: Arc<str>,
    mode: HttpPayloadMode,
}

impl LogSink for HttpLogSink {
    /// 业务作用：将一批日志发送到固定出口，统一执行超时和失败统计而不重入业务管线。
    fn send_batch<'a>(
        &'a self,
        batch: &'a [Arc<LogEnvelope>],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let elasticsearch = matches!(&self.mode, HttpPayloadMode::Elasticsearch(_));
            let (content_type, body) = match &self.mode {
                HttpPayloadMode::JsonArray => ("application/json", encode_json_array(batch)),
                HttpPayloadMode::Elasticsearch(index) => (
                    "application/x-ndjson",
                    encode_elasticsearch_bulk(batch, index.as_ref()),
                ),
                HttpPayloadMode::Loki(sink) => (
                    "application/json",
                    encode_loki_payload(batch, sink.as_ref())?,
                ),
            };
            // `Bytes` 克隆只增加引用计数，后台请求完成前由 reqwest 持有；批次合并只承担一次必要编码。
            let mut response = self
                .client
                .post(self.endpoint.as_ref())
                .header(http::header::CONTENT_TYPE, content_type)
                .body(body)
                .send()
                .await
                .context("send access log HTTP batch")?;
            if !response.status().is_success() {
                bail!("access log HTTP endpoint returned {}", response.status());
            }
            // 有界读完响应以复用连接。Elasticsearch bulk 的 HTTP 200 仍可能包含逐项失败，
            // 必须同时检查 errors；响应硬上限防止异常端点让日志工作任务无界聚合。
            const MAX_SINK_RESPONSE_BYTES: usize = 64 * 1024;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_SINK_RESPONSE_BYTES as u64)
            {
                bail!("access log HTTP response exceeds 64KiB");
            }
            let mut response_body = BytesMut::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .context("read access log HTTP response")?
            {
                if response_body.len().saturating_add(chunk.len()) > MAX_SINK_RESPONSE_BYTES {
                    bail!("access log HTTP response exceeds 64KiB");
                }
                response_body.extend_from_slice(chunk.as_ref());
            }
            if elasticsearch && !response_body.is_empty() {
                let result: ElasticsearchBulkResult =
                    serde_json::from_slice(response_body.as_ref())
                        .context("decode Elasticsearch bulk response")?;
                if result.errors {
                    bail!("Elasticsearch bulk response contains failed items");
                }
            }
            Ok(())
        })
    }
}

#[derive(serde::Deserialize)]
struct ElasticsearchBulkResult {
    errors: bool,
}

/// 业务作用：把日志批次编码为标准 JSON 数组，不改变单条事件内容。
fn encode_json_array(batch: &[Arc<LogEnvelope>]) -> Bytes {
    let content_len = batch.iter().map(|event| event.json.len()).sum::<usize>();
    let mut out =
        BytesMut::with_capacity(content_len.saturating_add(batch.len()).saturating_add(1));
    out.put_u8(b'[');
    for (index, event) in batch.iter().enumerate() {
        if index > 0 {
            out.put_u8(b',');
        }
        out.extend_from_slice(event.json.as_ref());
    }
    out.put_u8(b']');
    out.freeze()
}

/// 业务作用：生成 Elasticsearch Bulk 的动作行和文档行，保持批次协议边界。
fn encode_elasticsearch_bulk(batch: &[Arc<LogEnvelope>], index: &str) -> Bytes {
    // index 已限制为安全 ASCII，不需要每条调用 JSON serializer；action line 只构造一次并复用。
    let action = format!("{{\"index\":{{\"_index\":\"{index}\"}}}}\n");
    let content_len = batch
        .iter()
        .map(|event| {
            action
                .len()
                .saturating_add(event.json.len())
                .saturating_add(1)
        })
        .sum();
    let mut out = BytesMut::with_capacity(content_len);
    for event in batch {
        out.extend_from_slice(action.as_bytes());
        out.extend_from_slice(event.json.as_ref());
        out.put_u8(b'\n');
    }
    out.freeze()
}

#[derive(serde::Serialize)]
struct LokiPayload<'a> {
    streams: [LokiStream<'a>; 1],
}

#[derive(serde::Serialize)]
struct LokiStream<'a> {
    stream: LokiLabels<'a>,
    values: Vec<(String, &'a str)>,
}

#[derive(serde::Serialize)]
struct LokiLabels<'a> {
    job: &'static str,
    sink: &'a str,
}

/// 业务作用：把日志事件按固定标签构造成 Loki push 载荷，不引入请求级高基数标签。
fn encode_loki_payload(batch: &[Arc<LogEnvelope>], sink: &str) -> Result<Bytes> {
    let values = batch
        .iter()
        .map(|event| {
            let line = std::str::from_utf8(event.json.as_ref())
                .expect("access log JSON serializer always emits UTF-8");
            (event.unix_nanos.to_string(), line)
        })
        .collect();
    serde_json::to_vec(&LokiPayload {
        streams: [LokiStream {
            stream: LokiLabels {
                job: "gateway",
                sink,
            },
            values,
        }],
    })
    .map(Bytes::from)
    .context("encode Loki access log batch")
}

#[cfg(feature = "log-kafka")]
struct KafkaLogSink {
    runtime: nasa::kafka::KafkaProxy,
    lane: nasa::kafka::ProducerLane,
    topic: Arc<str>,
}

#[cfg(feature = "log-kafka")]
impl LogSink for KafkaLogSink {
    /// 业务作用：将一批日志发送到固定出口，统一执行超时和失败统计而不重入业务管线。
    fn send_batch<'a>(
        &'a self,
        batch: &'a [Arc<LogEnvelope>],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            for event in batch {
                self.lane
                    .publish_raw(self.topic.as_ref(), event.json.as_ref())
                    .event("gateway.access")
                    .key(event.record.request_id.clone())
                    .send()
                    .await
                    .map_err(|error| anyhow::anyhow!("Kafka access log publish failed: {error}"))?;
            }
            Ok(())
        })
    }

    /// 业务作用：在关闭日志出口时结束生产者并等待已有发送工作，避免继续接受新批次。
    fn shutdown(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.runtime
                .shutdown()
                .await
                .map_err(|error| anyhow::anyhow!("Kafka access log shutdown failed: {error}"))
        })
    }
}

/// 业务作用：按固定配置构建 Kafka 日志生产者，缺少制品能力时拒绝该出口。
#[cfg(feature = "log-kafka")]
fn build_kafka_backend(spec: &LogSinkSpec) -> Result<Arc<dyn LogSink>> {
    use std::collections::BTreeMap;

    let request_timeout_ms = spec.timeout.as_millis().min(u128::from(u64::MAX)) as u64;
    let producer_defaults = nasa::kafka::ProducerConfig::default();
    let mut producer = nasa::kafka::ProducerConfig {
        request_timeout_ms,
        delivery_timeout_ms: request_timeout_ms.saturating_add(producer_defaults.linger_ms),
        queue_buffering_max_messages: spec.queue_size,
        ..producer_defaults
    };
    if spec.lane.as_ref() != "default" {
        producer.lanes.insert(
            spec.lane.to_string(),
            nasa::kafka::ProducerLaneOverride::default(),
        );
    }
    let behavior = nasa::kafka::BehaviorConfig {
        publish_timeout_ms: producer.delivery_timeout_ms,
        shutdown_timeout_ms: request_timeout_ms,
        ..nasa::kafka::BehaviorConfig::default()
    };
    let runtime = nasa::kafka::KafkaProxy::connect(nasa::kafka::KafkaConfig {
        client_name: format!("gateway-log-{}", spec.id),
        bootstrap_servers: spec.bootstrap_servers.to_string(),
        group_id: None,
        client_id_prefix: Some("gateway-access".to_string()),
        producer,
        consumer: nasa::kafka::ConsumerConfig::default(),
        admin: nasa::kafka::AdminConfig::default(),
        behavior,
        security: nasa::kafka::SecurityConfig::default(),
        properties: BTreeMap::new(),
    })
    .map_err(|error| anyhow::anyhow!("build Kafka access log sink `{}`: {error}", spec.id))?;
    let lane = runtime
        .producer_lane(spec.lane.as_ref())
        .map_err(|error| anyhow::anyhow!("build Kafka access log lane `{}`: {error}", spec.id))?;
    Ok(Arc::new(KafkaLogSink {
        runtime,
        lane,
        topic: spec.topic.clone(),
    }))
}

/// 业务作用：按固定配置构建 Kafka 日志生产者，缺少制品能力时拒绝该出口。
#[cfg(not(feature = "log-kafka"))]
fn build_kafka_backend(_spec: &LogSinkSpec) -> Result<Arc<dyn LogSink>> {
    bail!("Kafka access log sink requires gateway feature `log-kafka`")
}
