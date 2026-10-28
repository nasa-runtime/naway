//! 访问日志及遥测出口声明。

use super::*;

#[derive(Debug, Deserialize, Clone, PartialEq)]
/// 非阻塞 access log 的有界队列、格式、条件与采样配置。
pub struct AccessLogCfg {
    /// 是否启用 access log。关闭后热路径仍构造最小 logger,但直接丢弃记录。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 非阻塞队列长度;队列满丢弃并累加 `gw_log_dropped_total`。0 按默认 4096 处理。
    #[serde(default = "default_access_log_queue_size")]
    pub queue_size: usize,
    /// 自定义单行格式,支持 nginx 风格 `$status` 与 `${status}` 变量。为空时输出默认 structured fields。
    #[serde(default, alias = "log_format")]
    pub format: Option<String>,
    /// 条件日志表达式,如 `$status >= 500`。未配置则全量输出。
    #[serde(default, rename = "if", alias = "condition")]
    pub condition: Option<String>,
    /// 稳定采样率,范围 0.0..=1.0,按 request_id hash 决定是否输出。
    #[serde(default = "default_access_log_sample")]
    pub sample: f64,
    /// 独立日志出口。空列表保持兼容，自动创建一个 `tracing` sink。
    #[serde(default)]
    pub sinks: Vec<AccessLogSinkCfg>,
}

/// 单个 access-log sink 的 bootstrap 配置。
///
/// 每个 sink 都有自己的 bounded queue/batch/timeout。连接拓扑和凭据在进程启动时创建，热更
/// 必须重启；format/condition/sample 仍可随快照热更。
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessLogSinkCfg {
    /// 低基数唯一 id，只允许 ASCII 字母、数字、点、下划线、短横线。
    pub id: String,
    /// `tracing` / `http` / `elasticsearch` / `loki` / `kafka`。
    #[serde(rename = "type")]
    pub kind: AccessLogSinkKind,
    /// 是否启动该 sink；关闭项不创建 channel/client。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 本 sink 独立队列长度；满载只丢本 sink 的记录。
    #[serde(default = "default_access_log_sink_queue_size")]
    pub queue_size: usize,
    /// 单批最多记录数。
    #[serde(default = "default_access_log_sink_batch_size")]
    pub batch_size: usize,
    /// 首条记录到达后的最大聚批等待。
    #[serde(default = "default_access_log_sink_batch_delay_ms")]
    pub batch_delay_ms: u64,
    /// HTTP/Kafka 单批投递超时。
    #[serde(default = "default_access_log_sink_timeout_ms")]
    pub timeout_ms: u64,
    /// HTTP/Elasticsearch/Loki 完整 endpoint。Elasticsearch 应指向 `_bulk`。
    #[serde(default)]
    pub endpoint: String,
    /// HTTP 类 sink 的静态 header；值支持 `env://`/`file://` SecretSource。
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Elasticsearch index；只用于 `elasticsearch`。
    #[serde(default)]
    pub index: String,
    /// Kafka broker 列表；只用于 `kafka`。
    #[serde(default)]
    pub bootstrap_servers: String,
    /// Kafka topic；只用于 `kafka`。
    #[serde(default)]
    pub topic: String,
    /// Kafka producer lane，默认 `default`。
    #[serde(default = "default_access_log_kafka_lane")]
    pub lane: String,
    /// 单条结构化记录最大字节数，避免异常字段放大 sink 内存/消息。
    #[serde(default = "default_access_log_sink_max_event_bytes")]
    pub max_event_bytes: usize,
}

/// access-log sink 类型。
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogSinkKind {
    /// 输出到既有 nasa/tracing 日志管线。
    Tracing,
    /// JSON array POST 到通用 HTTP endpoint。
    Http,
    /// NDJSON bulk POST 到 Elasticsearch `_bulk` endpoint。
    Elasticsearch,
    /// Loki push JSON。
    Loki,
    /// 原始 JSON 逐条投递 Kafka topic（需 feature `log-kafka`）。
    Kafka,
}

/// OpenTelemetry 导出与 W3C/B3 传播配置。
#[derive(Debug, Deserialize, serde::Serialize, Clone, PartialEq)]
pub struct TelemetryCfg {
    /// 是否把已采样 span 导出到 OTLP collector。关闭时仍生成合规 trace-id 并向上游传播。
    #[serde(default)]
    pub enabled: bool,
    /// OTLP/HTTP collector 基地址；exporter 按协议写 `/v1/traces`。
    #[serde(default = "default_otel_endpoint")]
    pub endpoint: String,
    /// OTel resource `service.name`。
    #[serde(default = "default_otel_service_name")]
    pub service_name: String,
    /// root trace 头采样率。可信远端父的 sampled 位由 ParentBased 语义继承。
    #[serde(default = "default_otel_sample_ratio")]
    pub sample_ratio: f64,
    /// BatchSpanProcessor 有界队列容量；满时 SDK fail-open 丢 span，不反压数据面。
    #[serde(default = "default_otel_queue_size")]
    pub queue_size: usize,
    /// 单次 OTLP 导出的最大 span 数，不得大于 `queue_size`。
    #[serde(default = "default_otel_batch_size")]
    pub batch_size: usize,
    /// 后台批量导出最大聚合等待时间。
    #[serde(default = "default_otel_scheduled_delay_ms")]
    pub scheduled_delay_ms: u64,
    /// 单次 collector 请求超时；只约束后台 exporter，不进入请求预算。
    #[serde(default = "default_otel_export_timeout_ms")]
    pub export_timeout_ms: u64,
    /// 是否兼容提取 B3 single/multi header，并向上游额外注入 single `b3`。
    #[serde(default = "default_true")]
    pub b3_compat: bool,
    /// 显式三信号出口；缺省保持原有 HTTP trace 出口，配置存在时需要 telemetry-otlp 制品。
    #[serde(default)]
    pub multi_signal: Option<crate::config::telemetry::OtlpCfg>,
}

impl Default for TelemetryCfg {
    /// 业务作用：构造 `TelemetryCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            service_name: default_otel_service_name(),
            sample_ratio: default_otel_sample_ratio(),
            queue_size: default_otel_queue_size(),
            batch_size: default_otel_batch_size(),
            scheduled_delay_ms: default_otel_scheduled_delay_ms(),
            export_timeout_ms: default_otel_export_timeout_ms(),
            b3_compat: true,
            multi_signal: None,
        }
    }
}

impl Default for AccessLogCfg {
    /// 业务作用：构造 `AccessLogCfg` 的缺省配置，统一各字段的省略语义与显式默认值。
    fn default() -> Self {
        Self {
            enabled: true,
            queue_size: default_access_log_queue_size(),
            format: None,
            condition: None,
            sample: default_access_log_sample(),
            sinks: Vec::new(),
        }
    }
}

/// 业务作用：为未显式声明的 `queue_size` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_queue_size() -> usize {
    4096
}

/// 业务作用：为未显式声明的 `sample` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_sample() -> f64 {
    1.0
}

/// 业务作用：为未显式声明的 `queue_size` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_sink_queue_size() -> usize {
    1024
}

/// 业务作用：为未显式声明的 `batch_size` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_sink_batch_size() -> usize {
    100
}

/// 业务作用：为未显式声明的 `batch_delay_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_sink_batch_delay_ms() -> u64 {
    200
}

/// 业务作用：为未显式声明的 `timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_sink_timeout_ms() -> u64 {
    3000
}

/// 业务作用：为未显式声明的 `max_event_bytes` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_sink_max_event_bytes() -> usize {
    256 * 1024
}

/// 业务作用：为未显式声明的 `lane` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_access_log_kafka_lane() -> String {
    "default".to_string()
}

/// 业务作用：为未显式声明的 `endpoint` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_otel_endpoint() -> String {
    "http://127.0.0.1:4318".to_string()
}

/// 业务作用：提供 OpenTelemetry resource 的默认服务名，使 Naway 信号可被稳定归类。
///
/// 参数说明: 无。
///
/// 返回：返回 `naway`；部署可通过 telemetry 配置覆盖。
pub(super) fn default_otel_service_name() -> String {
    "naway".to_string()
}

/// 业务作用：为未显式声明的 `sample_ratio` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_otel_sample_ratio() -> f64 {
    1.0
}

/// 业务作用：为未显式声明的 `queue_size` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_otel_queue_size() -> usize {
    2048
}

/// 业务作用：为未显式声明的 `batch_size` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_otel_batch_size() -> usize {
    512
}

/// 业务作用：为未显式声明的 `scheduled_delay_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_otel_scheduled_delay_ms() -> u64 {
    5_000
}

/// 业务作用：为未显式声明的 `export_timeout_ms` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
pub(super) fn default_otel_export_timeout_ms() -> u64 {
    3_000
}
