//! 标准 OTLP protobuf 包装；记录已受字节预算约束，collector 返回正文另设硬限。

use opentelemetry_proto::tonic::{
    collector::{logs::v1::*, metrics::v1::*, trace::v1::*},
    common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    metrics::v1::{Metric, ResourceMetrics, ScopeMetrics},
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span},
};
use prost::Message;

#[derive(Clone, Copy, Debug)]
pub(super) enum Signal {
    Traces,
    Metrics,
    Logs,
}

impl Signal {
    /// 业务作用：为 endpoint 与低基数指标提供固定信号名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只可能是三种标准 OTLP 信号名。
    pub fn name(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Metrics => "metrics",
            Self::Logs => "logs",
        }
    }

    /// 业务作用：选择标准 OTLP gRPC unary 方法。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：静态服务路径，不允许配置注入任意 RPC。
    pub fn path(self) -> &'static str {
        match self {
            Self::Traces => "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            Self::Metrics => "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
            Self::Logs => "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
        }
    }

    /// 业务作用：将已完成的独立记录包装为单个资源和 instrumentation scope 的标准请求。
    ///
    /// 参数说明：
    /// - `records`：是同种信号的有界 protobuf
    /// - `resource`：是已审核服务身份。
    ///
    /// 返回：完整 OTLP 请求；任何内部记录不符合对应消息类型时返回错误。
    pub fn encode(
        self,
        records: &[Vec<u8>],
        resource: &Resource,
    ) -> Result<Vec<u8>, prost::DecodeError> {
        let scope = Some(InstrumentationScope {
            name: "naway.gateway".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        });
        let resource = Some(resource.clone());
        Ok(match self {
            Self::Traces => ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans {
                    resource,
                    scope_spans: vec![ScopeSpans {
                        scope,
                        spans: records
                            .iter()
                            .map(|r| Span::decode(r.as_slice()))
                            .collect::<Result<_, _>>()?,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
            Self::Metrics => ExportMetricsServiceRequest {
                resource_metrics: vec![ResourceMetrics {
                    resource,
                    scope_metrics: vec![ScopeMetrics {
                        scope,
                        metrics: records
                            .iter()
                            .map(|r| Metric::decode(r.as_slice()))
                            .collect::<Result<_, _>>()?,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
            Self::Logs => ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    resource,
                    scope_logs: vec![ScopeLogs {
                        scope,
                        log_records: records
                            .iter()
                            .map(|r| LogRecord::decode(r.as_slice()))
                            .collect::<Result<_, _>>()?,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
        })
    }

    /// 业务作用：读取 collector 的部分接收计数，避免把已接收数据重试成重复事件。
    ///
    /// 参数说明：
    /// - `body`：是已经过响应大小门禁的 protobuf。
    ///
    /// 返回：拒绝条数；非空 collector 提示只计固定告警数，不导出其正文；非法响应返回错误。
    pub fn rejected(self, body: &[u8]) -> anyhow::Result<u64> {
        let (count, warning) = match self {
            Self::Traces => ExportTraceServiceResponse::decode(body)?
                .partial_success
                .map_or((0, false), |v| {
                    (v.rejected_spans, !v.error_message.is_empty())
                }),
            Self::Metrics => ExportMetricsServiceResponse::decode(body)?
                .partial_success
                .map_or((0, false), |v| {
                    (v.rejected_data_points, !v.error_message.is_empty())
                }),
            Self::Logs => ExportLogsServiceResponse::decode(body)?
                .partial_success
                .map_or((0, false), |v| {
                    (v.rejected_log_records, !v.error_message.is_empty())
                }),
        };
        if count < 0 {
            anyhow::bail!("negative OTLP partial rejection count");
        }
        if warning {
            super::queue::count(self, 10, 1);
        }
        Ok(count as u64)
    }
}

/// 业务作用：编码明确允许的文本属性，不展开任意请求头或日志对象。
///
/// 参数说明：
/// - `key`：是调用方确定的业务字段。
/// - `value`：是调用方确定的业务字段。
///
/// 返回：标准 OTLP 属性；值由生产者负责资源与敏感字段门禁。
pub(super) fn string_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
        ..Default::default()
    }
}

/// 业务作用：为资源内记录提供 Unix 纳秒时间戳。
///
/// 参数说明: 无。
///
/// 返回：系统时间在 epoch 之前时取零，超出协议范围时饱和。
pub(super) fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}
