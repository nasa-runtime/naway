//! 独立 collector 传输；只重试 OTLP 规范允许的状态，所有尝试受同一个外层期限约束。

use std::time::{Duration, SystemTime};

use opentelemetry_proto::tonic::collector::{logs::v1::*, metrics::v1::*, trace::v1::*};
use prost::Message;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use super::wire::Signal;
use crate::config::telemetry::OtlpProtocol;

const RESPONSE_LIMIT: usize = 64 * 1024;

pub(super) enum Transport {
    Http {
        client: reqwest::Client,
        endpoint: String,
    },
    Grpc(Channel),
}

#[derive(Debug)]
pub(super) enum Failure {
    Permanent,
    Retry(Option<Duration>),
}

impl Transport {
    /// 业务作用：在专用 runtime 中构建 collector client，不允许重定向泄漏遥测载荷。
    ///
    /// 参数说明：
    /// - `protocol`：已通过配置门禁
    /// - `endpoint`：已通过配置门禁
    /// - `timeout`：限制建连与每次调用。
    ///
    /// 返回：惰性连接的传输；本地 TLS 或地址装配失败时拒绝启动该出口。
    pub fn build(
        protocol: OtlpProtocol,
        endpoint: String,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        match protocol {
            OtlpProtocol::HttpProtobuf => Ok(Self::Http {
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(timeout)
                    .timeout(timeout)
                    .pool_max_idle_per_host(1)
                    .http2_max_header_list_size(RESPONSE_LIMIT as u32)
                    .build()?,
                endpoint,
            }),
            OtlpProtocol::Grpc => {
                let tls = endpoint.starts_with("https:");
                let mut builder = Endpoint::from_shared(endpoint)?
                    .connect_timeout(timeout)
                    .timeout(timeout)
                    .buffer_size(1);
                builder = builder.http2_max_header_list_size(RESPONSE_LIMIT as u32);
                if tls {
                    builder = builder.tls_config(ClientTlsConfig::new().with_native_roots())?;
                }
                Ok(Self::Grpc(builder.connect_lazy()))
            }
        }
    }

    /// 业务作用：执行单次标准 OTLP 请求，不在此处循环重试或读取无界响应。
    ///
    /// 参数说明：
    /// - `signal`：确定 wire 类型
    /// - `body`：是大小受限的请求
    /// - `remaining`：是批次剩余期限。
    ///
    /// 返回：collector 拒绝的记录数；失败只携带固定类别和受信重试等待时间。
    pub async fn send(
        &mut self,
        signal: Signal,
        body: &[u8],
        remaining: Duration,
    ) -> Result<u64, Failure> {
        match self {
            Self::Http {
                client,
                endpoint,
            } => {
                let mut response = client
                    .post(endpoint.as_str())
                    .header("content-type", "application/x-protobuf")
                    .timeout(remaining)
                    .body(body.to_vec())
                    .send()
                    .await
                    .map_err(|_| Failure::Retry(None))?;
                let status = response.status().as_u16();
                if status != 200 {
                    // 只有规范列出的瞬时状态可重试；其余错误不借重试扩大 collector 压力。
                    return Err(if matches!(status, 429 | 502 | 503 | 504) {
                        Failure::Retry(
                            response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(retry_after),
                        )
                    } else {
                        Failure::Permanent
                    });
                }
                if response
                    .content_length()
                    .is_some_and(|v| v > RESPONSE_LIMIT as u64)
                {
                    return Err(Failure::Permanent);
                }
                let mut result = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Retry(None))? {
                    if result.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
                        return Err(Failure::Permanent);
                    }
                    result.extend_from_slice(&chunk);
                }
                signal.rejected(&result).map_err(|_| Failure::Permanent)
            }
            Self::Grpc(channel) => {
                let response = match signal {
                    Signal::Traces => {
                        grpc_call::<ExportTraceServiceRequest, ExportTraceServiceResponse>(
                            channel.clone(),
                            signal,
                            body,
                            remaining,
                        )
                        .await?
                    }
                    Signal::Metrics => {
                        grpc_call::<ExportMetricsServiceRequest, ExportMetricsServiceResponse>(
                            channel.clone(),
                            signal,
                            body,
                            remaining,
                        )
                        .await?
                    }
                    Signal::Logs => {
                        grpc_call::<ExportLogsServiceRequest, ExportLogsServiceResponse>(
                            channel.clone(),
                            signal,
                            body,
                            remaining,
                        )
                        .await?
                    }
                };
                signal.rejected(&response).map_err(|_| Failure::Permanent)
            }
        }
    }
}

/// 业务作用：发送大小受限的 unary RPC，禁止框架响应解码无界分配。
///
/// 参数说明：
/// - `channel`：是信号独占连接
/// - `signal`：是固定 RPC 与载荷
/// - `body`：是固定 RPC 与载荷
/// - `remaining`：限制 RPC。
///
/// 返回：标准响应或经协议分类的失败，不传播 collector 错误正文。
async fn grpc_call<Q, R>(
    channel: Channel,
    signal: Signal,
    body: &[u8],
    remaining: Duration,
) -> Result<Vec<u8>, Failure>
where
    Q: Message + Default + Send + 'static,
    R: Message + Default + Send + 'static,
{
    let mut client = tonic::client::Grpc::new(channel)
        .max_decoding_message_size(RESPONSE_LIMIT)
        .max_encoding_message_size(4 * 1024 * 1024);
    client.ready().await.map_err(|_| Failure::Retry(None))?;
    let mut request = tonic::Request::new(Q::decode(body).map_err(|_| Failure::Permanent)?);
    request.set_timeout(remaining);
    let response: tonic::Response<R> = client
        .unary(
            request,
            http::uri::PathAndQuery::from_static(signal.path()),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .map_err(classify_grpc)?;
    Ok(response.into_inner().encode_to_vec())
}

/// 业务作用：遵循 OTLP gRPC 重试边界，资源耗尽仅在服务端明确提供 RetryInfo 时恢复尝试。
///
/// 参数说明：
/// - `status`：是已完成 RPC 的标准状态。
///
/// 返回：永久失败或可重试失败，不保留任意 metadata/message。
fn classify_grpc(status: tonic::Status) -> Failure {
    let delay = retry_info(status.details());
    match status.code() {
        tonic::Code::Cancelled
        | tonic::Code::DeadlineExceeded
        | tonic::Code::Aborted
        | tonic::Code::OutOfRange
        | tonic::Code::Unavailable
        | tonic::Code::DataLoss => Failure::Retry(delay),
        tonic::Code::ResourceExhausted if delay.is_some() => Failure::Retry(delay),
        _ => Failure::Permanent,
    }
}

/// 业务作用：读取 HTTP 秒数或 HTTP-date 重试提示，不在过去时间上产生负等待。
///
/// 参数说明：
/// - `value`：是单个 Retry-After 值。
///
/// 返回：有效等待时间；无效提示交由本地指数退避。
fn retry_after(value: &str) -> Option<Duration> {
    value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .map(|t| t.duration_since(SystemTime::now()).unwrap_or_default())
        })
}

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(message, repeated, tag = "3")]
    details: Vec<RpcAny>,
}
#[derive(Clone, PartialEq, Message)]
struct RpcAny {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct RetryInfo {
    #[prost(message, optional, tag = "1")]
    retry_delay: Option<RpcDuration>,
}
#[derive(Clone, PartialEq, Message)]
struct RpcDuration {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

/// 业务作用：只解释 google.rpc.RetryInfo，不接受其它类型充当资源恢复证据。
///
/// 参数说明：
/// - `details`：是大小已由 gRPC 响应门禁限制的 status details。
///
/// 返回：合法非负时长；缺失或畸形信息不赋予资源耗尽重试权限。
fn retry_info(details: &[u8]) -> Option<Duration> {
    if details.len() > RESPONSE_LIMIT {
        return None;
    }
    let status = RpcStatus::decode(details).ok()?;
    for detail in status.details {
        if detail.type_url != "type.googleapis.com/google.rpc.RetryInfo" {
            continue;
        }
        let delay = RetryInfo::decode(detail.value.as_slice())
            .ok()?
            .retry_delay?;
        if delay.seconds < 0 || !(0..1_000_000_000).contains(&delay.nanos) {
            return None;
        }
        return Some(Duration::new(delay.seconds as u64, delay.nanos as u32));
    }
    None
}
