//! 浏览器 RPC 与 native gRPC 之间的协议翻译。
//!
//! gRPC-Web 与 Connect 都以 HTTP body envelope 表达浏览器无法直接使用的 gRPC trailer。
//! 本模块只改传输外壳：method path、protobuf message、认证元数据和上游治理仍走普通 gRPC
//! 转发链。gRPC-Web/Connect streaming 始终逐帧转换；只有必须等待最终 status 才能确定 HTTP
//! 状态的 Connect unary 使用有界聚合。

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read as _;
use std::pin::Pin;
#[cfg(feature = "grpc-descriptor")]
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TE, TRAILER};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::Response;

use super::forward::ForwardBody;
use crate::{full_body, BoxBody, BoxError};

#[cfg(feature = "grpc-descriptor")]
use crate::protocols::grpc_transcoding::{
    GrpcTranscodingPlan, ResolvedGoogleRequest, ResolvedGrpcMethod,
};
#[cfg(feature = "grpc-descriptor")]
use http::Uri;

const CONNECT_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("connect-protocol-version");
const CONNECT_TIMEOUT_MS: HeaderName = HeaderName::from_static("connect-timeout-ms");
const CONNECT_CONTENT_ENCODING: HeaderName = HeaderName::from_static("connect-content-encoding");
const CONNECT_ACCEPT_ENCODING: HeaderName = HeaderName::from_static("connect-accept-encoding");
const GRPC_ENCODING: HeaderName = HeaderName::from_static("grpc-encoding");
const GRPC_ACCEPT_ENCODING: HeaderName = HeaderName::from_static("grpc-accept-encoding");
const GRPC_TIMEOUT: HeaderName = HeaderName::from_static("grpc-timeout");
const GRPC_STATUS: HeaderName = HeaderName::from_static("grpc-status");
const GRPC_MESSAGE: HeaderName = HeaderName::from_static("grpc-message");
const GRPC_STATUS_DETAILS: HeaderName = HeaderName::from_static("grpc-status-details-bin");
const X_GRPC_WEB: HeaderName = HeaderName::from_static("x-grpc-web");
const DEFAULT_UNARY_BUFFER_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_BROWSER_REQUEST_TRAILERS: usize = 32;
const MAX_BROWSER_REQUEST_TRAILER_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BrowserRequestEncoding {
    Identity,
    Gzip,
}

/// 浏览器请求使用的 wire protocol；值会跨一次上游 await，用于恢复下游响应外壳。
#[derive(Clone, Debug)]
pub(super) enum BrowserGrpc {
    /// 二进制 gRPC-Web；DATA envelope 与 native gRPC 相同，trailer 改放 body。
    GrpcWebBinary,
    /// Base64 文本 gRPC-Web；请求/响应都跨 HTTP chunk 保持连续 Base64 流。
    GrpcWebText,
    /// Connect unary protobuf；request/response 是去掉 5-byte envelope 的单条消息。
    ConnectUnary,
    /// Connect streaming protobuf；message envelope 与 gRPC 相同，最终状态是 EndStream envelope。
    ConnectStreaming,
    /// Connect unary JSON；descriptor 决定 input/output schema 与 native RPC path。
    #[cfg(feature = "grpc-descriptor")]
    ConnectUnaryJson(std::sync::Arc<ResolvedGrpcMethod>),
    /// Connect streaming JSON；每个 envelope 独立转换，未完成消息受 route 级 buffer 硬门约束。
    #[cfg(feature = "grpc-descriptor")]
    ConnectStreamingJson(std::sync::Arc<ResolvedGrpcMethod>),
    /// `google.api.http` unary JSON；annotation 决定 HTTP method/path/body/query 与 native RPC。
    #[cfg(feature = "grpc-descriptor")]
    GoogleUnaryJson(std::sync::Arc<ResolvedGoogleRequest>),
}

/// 内部 response extension：记录从 trailer 读取的 canonical gRPC code，供不同 JSON 外壳复用。
#[derive(Clone, Copy)]
#[cfg(feature = "grpc-descriptor")]
struct BrowserGrpcStatus(u16);

/// 浏览器协议错误；请求格式错误映射 4xx，上游 native gRPC 响应畸形映射 502。
#[derive(Debug)]
pub(super) struct BrowserGrpcError {
    status: StatusCode,
    message: &'static str,
}

impl BrowserGrpcError {
    /// 业务作用：构造客户端协议错误，确保不把无效 envelope 误报为上游故障。
    ///
    /// 参数说明：
    /// - `status`：是稳定 HTTP 状态
    /// - `message`：是不含敏感载荷的固定原因。
    ///
    /// 返回：可交给通用 forward error 映射的浏览器协议错误。
    fn request(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
        }
    }

    /// 业务作用：构造上游响应协议错误，防止缺失 status 或畸形 unary frame 被当作成功。
    ///
    /// 参数说明：
    /// - `message`：是低基数、无业务数据的固定原因。
    ///
    /// 返回：HTTP 502 浏览器协议错误。
    fn upstream(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
        }
    }

    /// 业务作用：向通用代理错误层提供稳定的 HTTP 状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：请求错误为 4xx，上游响应错误为 502。
    pub(super) fn status(&self) -> StatusCode {
        self.status
    }

    /// 业务作用：向下游返回不泄漏请求/上游 payload 的固定错误文本。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：静态协议错误原因。
    pub(super) fn message(&self) -> &'static str {
        self.message
    }

    /// 业务作用：区分客户端格式错误与真实上游协议故障，避免错误污染 upstream error 指标。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有 5xx 协议错误算上游错误。
    pub(super) fn is_upstream_error(&self) -> bool {
        self.status.is_server_error()
    }
}

impl fmt::Display for BrowserGrpcError {
    /// 业务作用：展示浏览器 gRPC 适配的协议失败原因，保持统一错误表示。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for BrowserGrpcError {}

impl BrowserGrpc {
    /// 业务作用：统一识别需要单消息有界聚合与 Connect unary 头语义的 protobuf/JSON 模式。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：Connect unary protobuf 或 descriptor JSON 时为 true。
    fn is_connect_unary(&self) -> bool {
        if matches!(self, Self::ConnectUnary) {
            return true;
        }
        #[cfg(feature = "grpc-descriptor")]
        {
            matches!(self, Self::ConnectUnaryJson(_))
        }
        #[cfg(not(feature = "grpc-descriptor"))]
        {
            false
        }
    }

    /// 业务作用：按标准 Content-Type 与 Connect 版本头识别浏览器 RPC，不误拦普通 JSON/Protobuf HTTP API。
    ///
    /// 参数说明：
    /// - `method`：来自已完成通用请求头校验的下游请求。
    /// - `headers`：来自已完成通用请求头校验的下游请求。
    ///
    /// 返回：支持的 protobuf 模式返回计划；普通 HTTP 返回 None；已声明但不支持的 JSON/方法返回 4xx。
    #[cfg(not(feature = "grpc-descriptor"))]
    pub(super) fn detect(
        method: &Method,
        headers: &HeaderMap,
    ) -> Result<Option<Self>, BrowserGrpcError> {
        Self::detect_inner(method, headers, None)
    }

    /// 业务作用：在 route 显式携带 descriptor 计划时识别 Connect JSON，并按 RPC path 绑定
    /// 唯一 message schema；普通 JSON route 继续不被误拦。
    ///
    /// 参数说明：
    /// - `method`：来自下游 request head
    /// - `headers`：来自下游 request head
    /// - `uri`：来自下游 request head
    /// - `transcoding`：是当前 route 的可选只读 descriptor 计划。
    ///
    /// 返回：支持的浏览器 RPC 返回 wire 计划；未知 Connect schema 或错误 unary/streaming
    /// Content-Type 明确 4xx；普通 HTTP 返回 None。
    #[cfg(feature = "grpc-descriptor")]
    pub(super) fn detect_with_transcoding(
        method: &Method,
        headers: &HeaderMap,
        uri: &Uri,
        transcoding: Option<&GrpcTranscodingPlan>,
    ) -> Result<Option<Self>, BrowserGrpcError> {
        let media_type = media_type(headers);
        if media_type == Some("application/json") && is_connect_unary(headers) {
            if method != Method::POST {
                return Err(BrowserGrpcError::request(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "browser gRPC translation requires POST",
                ));
            }
            let resolved = transcoding
                .and_then(|plan| plan.resolve_connect_json(uri.path()))
                .ok_or_else(|| {
                    BrowserGrpcError::request(
                        StatusCode::NOT_FOUND,
                        "Connect JSON RPC is absent from descriptor allowlist",
                    )
                })?;
            if !resolved.is_unary() {
                return Err(BrowserGrpcError::request(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Connect streaming JSON requires the streaming transcoder",
                ));
            }
            return Ok(Some(Self::ConnectUnaryJson(resolved)));
        }
        if media_type == Some("application/connect+json") {
            if method != Method::POST {
                return Err(BrowserGrpcError::request(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "browser gRPC translation requires POST",
                ));
            }
            let resolved = transcoding
                .and_then(|plan| plan.resolve_connect_json(uri.path()))
                .ok_or_else(|| {
                    BrowserGrpcError::request(
                        StatusCode::NOT_FOUND,
                        "Connect JSON RPC is absent from descriptor allowlist",
                    )
                })?;
            if resolved.is_unary() {
                return Err(BrowserGrpcError::request(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Connect unary JSON requires application/json",
                ));
            }
            return Ok(Some(Self::ConnectStreamingJson(resolved)));
        }
        if media_type == Some("application/json") && !is_connect_unary(headers) {
            let resolved = match transcoding {
                Some(plan) => plan
                    .resolve_google_json(method, uri)
                    .map_err(|error| BrowserGrpcError::request(error.status(), error.message()))?,
                None => None,
            };
            if let Some(resolved) = resolved {
                if !resolved.is_unary() {
                    return Err(BrowserGrpcError::request(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "gRPC-JSON streaming requires the streaming transcoder",
                    ));
                }
                return Ok(Some(Self::GoogleUnaryJson(resolved)));
            }
        }
        Self::detect_inner(method, headers, media_type)
    }

    /// 业务作用：识别不需要 descriptor 的 gRPC-Web/Connect protobuf 模式，并保留 schema-less
    /// Connect JSON 的早拒语义。
    ///
    /// 参数说明：
    /// - `method`：是下游 head
    /// - `headers`：是下游 head
    /// - `known_media_type`：可复用调用方已解析结果。
    ///
    /// 返回：支持的 protobuf wire 计划、普通 HTTP None 或协议 4xx。
    fn detect_inner(
        method: &Method,
        headers: &HeaderMap,
        known_media_type: Option<&str>,
    ) -> Result<Option<Self>, BrowserGrpcError> {
        let Some(media_type) = known_media_type.or_else(|| media_type(headers)) else {
            return Ok(None);
        };
        let protocol = match media_type {
            "application/grpc-web" | "application/grpc-web+proto" => Self::GrpcWebBinary,
            "application/grpc-web-text" | "application/grpc-web-text+proto" => Self::GrpcWebText,
            "application/connect+proto" => Self::ConnectStreaming,
            "application/connect+json" => {
                return Err(BrowserGrpcError::request(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Connect JSON translation requires a protobuf schema",
                ));
            }
            "application/proto" if is_connect_unary(headers) => Self::ConnectUnary,
            "application/json" if is_connect_unary(headers) => {
                return Err(BrowserGrpcError::request(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Connect JSON translation requires a protobuf schema",
                ));
            }
            _ => return Ok(None),
        };
        if method != Method::POST {
            return Err(BrowserGrpcError::request(
                StatusCode::METHOD_NOT_ALLOWED,
                "browser gRPC translation requires POST",
            ));
        }
        Ok(Some(protocol))
    }

    /// 业务作用：把浏览器请求 head/body 改写成 native gRPC，同时保持 protobuf payload 与背压语义。
    ///
    /// 参数说明：
    /// - `parts`：是准备进入上游 header filter 的请求
    /// - `body`：是唯一 body 所有权
    /// - `max_body_bytes`：为 proxy 请求预算，Connect unary 聚合不得越过它。
    ///
    /// 返回：成功时返回 native gRPC body；客户端 Base64/压缩/大小错误时返回明确 4xx。
    pub(super) async fn prepare_request(
        &self,
        parts: &mut http::request::Parts,
        body: ForwardBody,
        max_body_bytes: u64,
    ) -> Result<ForwardBody, BrowserGrpcError> {
        let request_encoding = validate_request_encoding(self, &parts.headers)?;
        map_connect_timeout(&mut parts.headers)?;
        map_connect_compression(self, &mut parts.headers);
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(X_GRPC_WEB);
        parts.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        parts
            .headers
            .insert(TE, HeaderValue::from_static("trailers"));

        let body = match self {
            Self::GrpcWebBinary | Self::ConnectStreaming => body,
            Self::GrpcWebText => Base64DecodeBody::new(body).boxed(),
            Self::ConnectUnary => {
                let collected = collect_unary_payload(body, unary_limit(max_body_bytes)).await?;
                let payload = decode_unary_request(
                    collected.bytes,
                    request_encoding,
                    unary_limit(max_body_bytes),
                )?;
                GrpcUnaryRequestBody::new(payload, collected.trailers).boxed()
            }
            #[cfg(feature = "grpc-descriptor")]
            Self::ConnectUnaryJson(method) => {
                let collected = collect_unary_payload(body, unary_limit(max_body_bytes)).await?;
                let json = decode_unary_request(
                    collected.bytes,
                    request_encoding,
                    unary_limit(max_body_bytes),
                )?;
                let payload = method
                    .encode_json_request(&json)
                    .map_err(|error| BrowserGrpcError::request(error.status(), error.message()))?;
                parts.method = Method::POST;
                parts.uri = Uri::builder()
                    .path_and_query(method.rpc_path())
                    .build()
                    .expect("validated protobuf RPC path");
                GrpcUnaryRequestBody::new(payload, collected.trailers).boxed()
            }
            #[cfg(feature = "grpc-descriptor")]
            Self::ConnectStreamingJson(method) => {
                parts.method = Method::POST;
                parts.uri = Uri::builder()
                    .path_and_query(method.rpc_path())
                    .build()
                    .expect("validated protobuf RPC path");
                StreamingJsonBody::new(body, method.clone(), StreamingJsonDirection::Request, None)
                    .boxed()
            }
            #[cfg(feature = "grpc-descriptor")]
            Self::GoogleUnaryJson(request) => {
                let collected = collect_unary_payload(body, unary_limit(max_body_bytes)).await?;
                let json = decode_unary_request(
                    collected.bytes,
                    request_encoding,
                    unary_limit(max_body_bytes),
                )?;
                let payload = request
                    .encode_json_request(&json)
                    .map_err(|error| BrowserGrpcError::request(error.status(), error.message()))?;
                parts.method = Method::POST;
                parts.uri = Uri::builder()
                    .path_and_query(request.rpc_path())
                    .build()
                    .expect("validated protobuf RPC path");
                GrpcUnaryRequestBody::new(payload, collected.trailers).boxed()
            }
        };
        Ok(EnvelopeValidateBody::new(
            body,
            parts.headers.contains_key(GRPC_ENCODING),
            unary_limit(max_body_bytes),
        )
        .boxed())
    }

    /// 业务作用：把 native gRPC response 恢复成浏览器可消费的 gRPC-Web/Connect wire 语义。
    ///
    /// 参数说明：
    /// - `response`：已包含上游流式治理 wrapper
    /// - `max_body_bytes`：是 Connect unary 有界聚合上限，0 时使用内部 64MiB 安全上限。
    ///
    /// 返回：gRPC-Web/Connect streaming 立即返回流式 body；Connect unary 等最终 status 后返回；
    /// native 响应畸形或超限时返回 502。
    pub(super) async fn translate_response(
        &self,
        response: Response<BoxBody>,
        max_body_bytes: u64,
    ) -> Result<Response<BoxBody>, BrowserGrpcError> {
        match self {
            Self::GrpcWebBinary => Ok(grpc_web_response(response, false)),
            Self::GrpcWebText => Ok(grpc_web_response(response, true)),
            Self::ConnectStreaming => Ok(connect_streaming_response(response)),
            Self::ConnectUnary => {
                connect_unary_response(response, unary_limit(max_body_bytes)).await
            }
            #[cfg(feature = "grpc-descriptor")]
            Self::ConnectUnaryJson(method) => {
                connect_unary_json_response(response, unary_limit(max_body_bytes), method).await
            }
            #[cfg(feature = "grpc-descriptor")]
            Self::ConnectStreamingJson(method) => {
                Ok(connect_streaming_json_response(response, method.clone()))
            }
            #[cfg(feature = "grpc-descriptor")]
            Self::GoogleUnaryJson(request) => {
                google_unary_json_response(response, unary_limit(max_body_bytes), request).await
            }
        }
    }
}

/// 业务作用：解析 Content-Type 主类型，参数不参与 wire mode 判定。
///
/// 参数说明：
/// - `headers`：是下游请求头。
///
/// 返回：合法 UTF-8 主类型的借用字符串，否则 None。
fn media_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()
        .map(str::trim)
}

/// 业务作用：只在 Connect 显式版本头为 1 时把通用 application/proto/json 识别为 unary RPC。
///
/// 参数说明：
/// - `headers`：是下游请求头。
///
/// 返回：版本精确为 1 时 true，避免误拦普通 HTTP API。
fn is_connect_unary(headers: &HeaderMap) -> bool {
    headers
        .get(CONNECT_PROTOCOL_VERSION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "1")
}

/// 业务作用：决定 Connect unary 唯一允许的聚合预算；即使全局 0 表示不限制，也不允许协议翻译无界占用内存。
///
/// 参数说明：
/// - `configured`：是 proxy max_body_bytes。
///
/// 返回：非零配置原样使用，0 回退 64MiB 内部安全线。
fn unary_limit(configured: u64) -> u64 {
    if configured == 0 {
        DEFAULT_UNARY_BUFFER_LIMIT
    } else {
        configured
    }
}

/// 业务作用：拒绝当前翻译层不能保持语义的压缩组合，避免把压缩字节当明文 protobuf 转发。
///
/// 参数说明：
/// - `protocol`：决定读取 Content-Encoding 还是 Connect-Content-Encoding
/// - `headers`：是原请求头。
///
/// 返回：identity/缺省成功；支持的 streaming 压缩交给 native gRPC；Connect unary 压缩返回 415。
fn validate_request_encoding(
    protocol: &BrowserGrpc,
    headers: &HeaderMap,
) -> Result<BrowserRequestEncoding, BrowserGrpcError> {
    #[cfg(feature = "grpc-descriptor")]
    let descriptor_json = matches!(
        protocol,
        BrowserGrpc::ConnectUnaryJson(_)
            | BrowserGrpc::ConnectStreamingJson(_)
            | BrowserGrpc::GoogleUnaryJson(_)
    );
    #[cfg(not(feature = "grpc-descriptor"))]
    let descriptor_json = false;
    let header = if protocol.is_connect_unary() || descriptor_json {
        headers
            .get(CONTENT_ENCODING)
            .or_else(|| headers.get(CONNECT_CONTENT_ENCODING))
    } else if matches!(protocol, BrowserGrpc::ConnectStreaming) {
        headers.get(CONNECT_CONTENT_ENCODING)
    } else {
        headers.get(GRPC_ENCODING)
    };
    let Some(value) = header else {
        return Ok(BrowserRequestEncoding::Identity);
    };
    let value = value.to_str().map_err(|_| {
        BrowserGrpcError::request(
            StatusCode::BAD_REQUEST,
            "browser gRPC request encoding is not valid ASCII",
        )
    })?;
    if value.eq_ignore_ascii_case("identity") {
        return Ok(BrowserRequestEncoding::Identity);
    }
    if !value.eq_ignore_ascii_case("gzip") {
        return Err(BrowserGrpcError::request(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "browser gRPC request compression algorithm is not supported",
        ));
    }
    #[cfg(feature = "grpc-descriptor")]
    if matches!(protocol, BrowserGrpc::ConnectStreamingJson(_)) {
        return Err(BrowserGrpcError::request(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "compressed streaming JSON requests are not supported",
        ));
    }
    Ok(BrowserRequestEncoding::Gzip)
}

/// 业务作用：把 Connect timeout 毫秒值转换为 gRPC timeout，并在非法/溢出时 fail closed。
///
/// 参数说明：
/// - `headers`：是即将发往 native gRPC upstream 的请求头。
///
/// 返回：缺省/合法值成功；非十进制或超过八位协议上限时返回 400。
fn map_connect_timeout(headers: &mut HeaderMap) -> Result<(), BrowserGrpcError> {
    let Some(value) = headers.remove(CONNECT_TIMEOUT_MS) else {
        return Ok(());
    };
    let raw = value.to_str().map_err(|_| {
        BrowserGrpcError::request(StatusCode::BAD_REQUEST, "invalid Connect-Timeout-Ms")
    })?;
    let millis = raw.parse::<u64>().map_err(|_| {
        BrowserGrpcError::request(StatusCode::BAD_REQUEST, "invalid Connect-Timeout-Ms")
    })?;
    let encoded = if millis <= 99_999_999 {
        format!("{millis}m")
    } else {
        let seconds = millis.saturating_add(999) / 1000;
        if seconds > 99_999_999 {
            return Err(BrowserGrpcError::request(
                StatusCode::BAD_REQUEST,
                "Connect-Timeout-Ms exceeds gRPC timeout range",
            ));
        }
        format!("{seconds}S")
    };
    headers.insert(
        GRPC_TIMEOUT,
        HeaderValue::from_str(&encoded).expect("bounded ASCII timeout"),
    );
    Ok(())
}

/// 业务作用：把 Connect streaming 压缩协商头映射到 native gRPC，且移除浏览器协议私有头。
///
/// 参数说明：
/// - `protocol`：是已识别模式
/// - `headers`：将原地改写。
///
/// 返回：无返回值；header value 已由 HTTP parser 校验，原样移动避免复制 payload。
fn map_connect_compression(protocol: &BrowserGrpc, headers: &mut HeaderMap) {
    #[cfg(feature = "grpc-descriptor")]
    if matches!(
        protocol,
        BrowserGrpc::ConnectUnaryJson(_)
            | BrowserGrpc::ConnectStreamingJson(_)
            | BrowserGrpc::GoogleUnaryJson(_)
    ) {
        // JSON 慢路径必须看到未压缩 protobuf 才能按 descriptor 解码；不向上游协商压缩，
        // 也不让浏览器 Content-Encoding 被误当成 grpc-encoding。
        headers.remove(ACCEPT_ENCODING);
        headers.remove(CONNECT_ACCEPT_ENCODING);
        headers.remove(CONNECT_PROTOCOL_VERSION);
        headers.remove(CONTENT_ENCODING);
        headers.remove(CONNECT_CONTENT_ENCODING);
        return;
    }
    if protocol.is_connect_unary() {
        if let Some(value) = headers.remove(ACCEPT_ENCODING) {
            headers.insert(GRPC_ACCEPT_ENCODING, value);
        }
        headers.remove(CONNECT_PROTOCOL_VERSION);
        headers.remove(CONTENT_ENCODING);
        headers.remove(CONNECT_CONTENT_ENCODING);
        return;
    }
    match protocol {
        BrowserGrpc::ConnectUnary => unreachable!("handled Connect unary above"),
        BrowserGrpc::ConnectStreaming => {
            if let Some(value) = headers.remove(CONNECT_CONTENT_ENCODING) {
                if !value
                    .to_str()
                    .is_ok_and(|value| value.eq_ignore_ascii_case("identity"))
                {
                    headers.insert(GRPC_ENCODING, value);
                }
            }
            if let Some(value) = headers.remove(CONNECT_ACCEPT_ENCODING) {
                headers.insert(GRPC_ACCEPT_ENCODING, value);
            }
            headers.remove(CONNECT_PROTOCOL_VERSION);
            headers.remove(CONTENT_ENCODING);
        }
        BrowserGrpc::GrpcWebBinary | BrowserGrpc::GrpcWebText => {}
        #[cfg(feature = "grpc-descriptor")]
        BrowserGrpc::ConnectUnaryJson(_) => unreachable!("handled Connect unary JSON above"),
        #[cfg(feature = "grpc-descriptor")]
        BrowserGrpc::ConnectStreamingJson(_) => {
            unreachable!("handled Connect streaming JSON above")
        }
        #[cfg(feature = "grpc-descriptor")]
        BrowserGrpc::GoogleUnaryJson(_) => unreachable!("handled gRPC-JSON unary above"),
    }
}

/// 业务作用：有界读取 Connect unary 裸消息，拒绝请求 trailer 与超预算实体。
///
/// 参数说明：`body` 是裸 protobuf body；`limit` 是已确定的非零预算。
///
/// 返回：成功时复用聚合 Bytes；读取、trailer 或大小错误映射 400/413。
struct CollectedUnaryPayload {
    bytes: Bytes,
    trailers: Option<HeaderMap>,
}

/// 业务作用：在显式上限内读取浏览器 gRPC unary 载荷，拒绝多消息或截断的信封。
async fn collect_unary_payload(
    mut body: BoxBody,
    limit: u64,
) -> Result<CollectedUnaryPayload, BrowserGrpcError> {
    let mut bytes = BytesMut::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            BrowserGrpcError::request(StatusCode::BAD_REQUEST, "Connect request body read failed")
        })?;
        match frame.into_data() {
            Ok(data) => {
                if (bytes.len() as u64).saturating_add(data.len() as u64) > limit {
                    return Err(BrowserGrpcError::request(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Connect unary request exceeds body limit",
                    ));
                }
                bytes.extend_from_slice(&data);
            }
            Err(frame) => {
                if let Ok(next) = frame.into_trailers() {
                    if trailers.is_some() {
                        return Err(BrowserGrpcError::request(
                            StatusCode::BAD_REQUEST,
                            "browser gRPC request contains duplicate trailer blocks",
                        ));
                    }
                    validate_browser_request_trailers(&next)?;
                    trailers = Some(next);
                }
            }
        }
    }
    if bytes.len() > u32::MAX as usize {
        return Err(BrowserGrpcError::request(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Connect unary request exceeds gRPC frame limit",
        ));
    }
    Ok(CollectedUnaryPayload {
        bytes: bytes.freeze(),
        trailers,
    })
}

/// 业务作用：对 Connect unary gzip 实体执行同步有界解压，防止压缩炸弹进入 protobuf/JSON 编码器。
///
/// 参数说明：
/// - `bytes`：是已受压缩体上限保护的原始实体
/// - `encoding`：只允许 identity/gzip
/// - `limit`：是解压后硬门。
///
/// 返回：identity 原样复用；gzip 成功返回解压字节；算法、格式或解压后超限返回 4xx。
fn decode_unary_request(
    bytes: Bytes,
    encoding: BrowserRequestEncoding,
    limit: u64,
) -> Result<Bytes, BrowserGrpcError> {
    if encoding == BrowserRequestEncoding::Identity {
        return Ok(bytes);
    }
    let take_limit = limit.saturating_add(1);
    let mut decoder = flate2::read::GzDecoder::new(bytes.as_ref()).take(take_limit);
    let capacity = usize::try_from(limit.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut decoded = Vec::with_capacity(capacity);
    decoder.read_to_end(&mut decoded).map_err(|_| {
        BrowserGrpcError::request(StatusCode::BAD_REQUEST, "invalid gzip browser RPC request")
    })?;
    if decoded.len() as u64 > limit {
        return Err(BrowserGrpcError::request(
            StatusCode::PAYLOAD_TOO_LARGE,
            "decompressed browser RPC request exceeds body limit",
        ));
    }
    Ok(Bytes::from(decoded))
}

/// 业务作用：限制浏览器请求 trailers 为低风险应用 metadata，防止在认证后追加凭据、路由或 framing 权威。
///
/// 参数说明：
/// - `trailers`：是下游提交且准备转发给 native gRPC 的最终 trailer block。
///
/// 返回：名称、数量和值总预算均合法时成功；敏感字段、控制字符或超限返回 400 类协议错误。
fn validate_browser_request_trailers(trailers: &HeaderMap) -> Result<(), BrowserGrpcError> {
    if trailers.len() > MAX_BROWSER_REQUEST_TRAILERS {
        return Err(BrowserGrpcError::request(
            StatusCode::BAD_REQUEST,
            "browser gRPC request has too many trailers",
        ));
    }
    let mut total = 0usize;
    for (name, value) in trailers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or_else(|| {
                BrowserGrpcError::request(
                    StatusCode::BAD_REQUEST,
                    "browser gRPC request trailers exceed size limit",
                )
            })?;
        let lower = name.as_str();
        if lower.starts_with("grpc-")
            || lower.starts_with("content-")
            || lower.starts_with("x-forwarded-")
            || lower.starts_with("x-original-")
            || matches!(
                lower,
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "x-request-id"
            )
        {
            return Err(BrowserGrpcError::request(
                StatusCode::BAD_REQUEST,
                "browser gRPC request trailer name is forbidden",
            ));
        }
        if value.to_str().is_err() || value.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
            return Err(BrowserGrpcError::request(
                StatusCode::BAD_REQUEST,
                "browser gRPC request trailer value is invalid",
            ));
        }
    }
    if total > MAX_BROWSER_REQUEST_TRAILER_BYTES {
        return Err(BrowserGrpcError::request(
            StatusCode::BAD_REQUEST,
            "browser gRPC request trailers exceed size limit",
        ));
    }
    Ok(())
}

/// Connect unary 请求体：先发送 5-byte native gRPC envelope，再零拷贝发送已聚合 payload。
struct GrpcUnaryRequestBody {
    header: Option<Bytes>,
    payload: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl GrpcUnaryRequestBody {
    /// 业务作用：把一条 Connect unary 裸消息包装为 native gRPC envelope，不再复制 payload。
    ///
    /// 参数说明：
    /// - `payload`：已通过 u32 帧长度与代理 body 预算校验的 payload。
    /// - `trailers`：随正文结束一并交付的原始 trailers。
    ///
    /// 返回：两帧以内的请求 body；HTTP frame 边界不改变 gRPC 字节流语义。
    fn new(payload: Bytes, trailers: Option<HeaderMap>) -> Self {
        let mut header = [0_u8; 5];
        header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        Self {
            header: Some(Bytes::copy_from_slice(&header)),
            payload: Some(payload),
            trailers,
        }
    }
}

impl Body for GrpcUnaryRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按 envelope header→payload 顺序交付 Connect unary，保持 payload 的原 Bytes 所有权。
    ///
    /// 参数说明：
    /// - `_cx`：无需注册唤醒，因为两帧都已就绪。
    ///
    /// 返回：依次返回 header DATA、payload DATA 与 EOF。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(header) = self.header.take() {
            return Poll::Ready(Some(Ok(Frame::data(header))));
        }
        if let Some(payload) = self.payload.take() {
            return Poll::Ready(Some(Ok(Frame::data(payload))));
        }
        Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }

    /// 业务作用：让 Hyper 只在 header 与 payload 都已交付后关闭请求流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：两段数据均被取走时为 true。
    fn is_end_stream(&self) -> bool {
        self.header.is_none() && self.payload.is_none() && self.trailers.is_none()
    }

    /// 业务作用：提供精确 native gRPC body 长度，避免上游使用 chunked 语义猜测 unary 边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未交付的 envelope header 与 payload 总字节数。
    fn size_hint(&self) -> SizeHint {
        let len = self.header.as_ref().map_or(0, Bytes::len)
            + self.payload.as_ref().map_or(0, Bytes::len);
        SizeHint::with_exact(len as u64)
    }
}

/// 浏览器请求 envelope 校验器：逐字节跟踪 header/payload 边界，输出仍复用原 DATA Bytes。
struct EnvelopeValidateBody {
    inner: BoxBody,
    header: [u8; 5],
    header_len: usize,
    remaining: u32,
    compression_allowed: bool,
    max_frame_bytes: u64,
    saw_trailers: bool,
    finished: bool,
}

impl EnvelopeValidateBody {
    /// 业务作用：建立请求 framing 门禁，拒绝 Connect EndStream、保留位与无协商压缩标志。
    ///
    /// 参数说明：
    /// - `inner`：完成 text 解码或 unary 包装后的原生 envelope 字节流。
    /// - `compression_allowed`：请求头是否声明了 grpc-encoding。
    /// - `max_frame_bytes`：单条原生 gRPC frame 的字节硬上限。
    ///
    /// 返回：逐帧零拷贝转发、同时跨 HTTP chunk 校验 5-byte envelope 的 body。
    fn new(inner: BoxBody, compression_allowed: bool, max_frame_bytes: u64) -> Self {
        Self {
            inner,
            header: [0; 5],
            header_len: 0,
            remaining: 0,
            compression_allowed,
            max_frame_bytes,
            saw_trailers: false,
            finished: false,
        }
    }

    /// 业务作用：消费一段 envelope 字节并推进 framing 状态，不复制将要转发的 DATA。
    ///
    /// 参数说明：
    /// - `data`：是一个 HTTP DATA frame，可在 header/message 任意位置切分。
    ///
    /// 返回：边界与 flag 合法时成功；EndStream/保留位/无协商压缩时返回 body error。
    fn validate(&mut self, data: &[u8]) -> Result<(), BoxError> {
        let mut cursor = 0usize;
        while cursor < data.len() {
            if self.remaining > 0 {
                let consumed = usize::min(self.remaining as usize, data.len() - cursor);
                self.remaining -= consumed as u32;
                cursor += consumed;
                continue;
            }
            let copied = usize::min(5 - self.header_len, data.len() - cursor);
            self.header[self.header_len..self.header_len + copied]
                .copy_from_slice(&data[cursor..cursor + copied]);
            self.header_len += copied;
            cursor += copied;
            if self.header_len == 5 {
                let flags = self.header[0];
                if flags & !0x01 != 0 {
                    return Err(protocol_body_error(
                        "browser gRPC request uses reserved or EndStream flags",
                    ));
                }
                if flags & 0x01 != 0 && !self.compression_allowed {
                    return Err(protocol_body_error(
                        "compressed browser gRPC message has no encoding",
                    ));
                }
                self.remaining = u32::from_be_bytes([
                    self.header[1],
                    self.header[2],
                    self.header[3],
                    self.header[4],
                ]);
                if u64::from(self.remaining) > self.max_frame_bytes {
                    return Err(protocol_body_error(
                        "browser gRPC request frame exceeds configured limit",
                    ));
                }
                self.header_len = 0;
            }
        }
        Ok(())
    }
}

impl Body for EnvelopeValidateBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：在 DATA 交给上游 transport 前逐段复验 gRPC envelope，截断、保留 flag 或非法
    /// compression 只终止当前 request stream。
    ///
    /// 参数说明：
    /// - `cx`：是上游 Hyper client 的 body 唤醒上下文。
    ///
    /// 返回：合法 frame 原 Bytes 转发；协议错误返回 body error；无数据时保持 Pending/EOF。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(_data) if self.saw_trailers => {
                    self.finished = true;
                    Poll::Ready(Some(Err(protocol_body_error(
                        "browser gRPC request DATA followed trailers",
                    ))))
                }
                Ok(data) => match self.validate(&data) {
                    Ok(()) => Poll::Ready(Some(Ok(Frame::data(data)))),
                    Err(error) => {
                        self.finished = true;
                        Poll::Ready(Some(Err(error)))
                    }
                },
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        if self.saw_trailers {
                            self.finished = true;
                            return Poll::Ready(Some(Err(protocol_body_error(
                                "browser gRPC request contains duplicate trailer blocks",
                            ))));
                        }
                        if self.header_len != 0 || self.remaining != 0 {
                            self.finished = true;
                            return Poll::Ready(Some(Err(protocol_body_error(
                                "browser gRPC request trailers arrived inside an envelope",
                            ))));
                        }
                        match validate_browser_request_trailers(&trailers) {
                            Ok(()) => {
                                self.saw_trailers = true;
                                Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                            }
                            Err(error) => {
                                self.finished = true;
                                Poll::Ready(Some(Err(protocol_body_error(error.message()))))
                            }
                        }
                    } else {
                        self.finished = true;
                        Poll::Ready(Some(Err(protocol_body_error(
                            "browser gRPC request contains an unsupported body frame",
                        ))))
                    }
                }
            },
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finished = true;
                if self.header_len != 0 || self.remaining != 0 {
                    Poll::Ready(Some(Err(protocol_body_error(
                        "browser gRPC request ended inside an envelope",
                    ))))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：协议错误或完整 EOF 后立即标记终态，防止 Hyper 再次读取已经拒绝的下游 body。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：校验器已结束时 true。
    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

/// descriptor streaming codec 的转换方向；两侧都使用 5-byte envelope，但 payload schema 相反。
#[cfg(feature = "grpc-descriptor")]
#[derive(Clone, Copy)]
enum StreamingJsonDirection {
    /// Connect JSON request envelope 转为 native protobuf request envelope。
    Request,
    /// native protobuf response envelope 转为 Connect JSON response envelope。
    Response,
}

/// 逐 envelope 的 streaming JSON/protobuf 转码器；最多保留 route 声明的一段未完成消息。
#[cfg(feature = "grpc-descriptor")]
struct StreamingJsonBody {
    inner: BoxBody,
    method: Arc<ResolvedGrpcMethod>,
    direction: StreamingJsonDirection,
    buffer: BytesMut,
    messages: u64,
    max_messages: u64,
    max_buffer_bytes: usize,
    initial_status: Option<u16>,
    finished: bool,
}

#[cfg(feature = "grpc-descriptor")]
impl StreamingJsonBody {
    /// 业务作用：建立逐消息 descriptor codec，并按 RPC streaming 形态把非流一侧收窄为单消息，
    /// 防止声明为 server/client streaming 的 method 被错误扩展成 bidi。
    ///
    /// 参数说明：
    /// - `inner`：是 Connect/native envelope body
    /// - `method`：固定 input/output schema
    /// - `direction`：决定 JSON→protobuf 或 protobuf→JSON
    /// - `initial_status`：只用于响应 trailers-only 基数判断。
    ///
    /// 返回：只在下游继续 poll 时读取下一帧、且驻留量受 route stream buffer 限制的 body。
    fn new(
        inner: BoxBody,
        method: Arc<ResolvedGrpcMethod>,
        direction: StreamingJsonDirection,
        initial_status: Option<u16>,
    ) -> Self {
        let (configured_messages, max_buffer_bytes) = method.stream_limits();
        let max_messages = match direction {
            StreamingJsonDirection::Request if !method.is_client_streaming() => 1,
            StreamingJsonDirection::Response if !method.is_server_streaming() => 1,
            StreamingJsonDirection::Request | StreamingJsonDirection::Response => {
                configured_messages
            }
        };
        Self {
            inner,
            method,
            direction,
            buffer: BytesMut::new(),
            messages: 0,
            max_messages,
            max_buffer_bytes,
            initial_status,
            finished: false,
        }
    }

    /// 业务作用：从当前暂存中只取一条完整 envelope 并转换 payload，避免一次 poll 吞完长流、
    /// 破坏 Hyper/H2 背压与取消传播。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：消息完整时返回一个新 envelope；数据不足返回 None；flag、长度、schema 或预算非法时失败。
    fn decode_ready(&mut self) -> Result<Option<Bytes>, BoxError> {
        if self.buffer.len() < 5 {
            return Ok(None);
        }
        if self.buffer[0] != 0 {
            return Err(protocol_body_error(match self.direction {
                StreamingJsonDirection::Request => {
                    "Connect JSON request compression or EndStream flag is not supported"
                }
                StreamingJsonDirection::Response => {
                    "compressed or reserved native gRPC response flag cannot be translated to JSON"
                }
            }));
        }
        let length = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;
        let envelope_len = length
            .checked_add(5)
            .ok_or_else(|| protocol_body_error("streaming JSON envelope length overflow"))?;
        if envelope_len > self.max_buffer_bytes {
            return Err(protocol_body_error(
                "streaming JSON envelope exceeds configured buffer limit",
            ));
        }
        if self.buffer.len() < envelope_len {
            return Ok(None);
        }
        if self.messages >= self.max_messages {
            return Err(protocol_body_error(
                "streaming JSON message count exceeds configured limit",
            ));
        }
        let mut envelope = self.buffer.split_to(envelope_len);
        envelope.advance(5);
        let payload = envelope.freeze();
        let converted = match self.direction {
            StreamingJsonDirection::Request => self
                .method
                .encode_json_request(&payload)
                .map_err(|error| protocol_body_error(error.message()))?,
            StreamingJsonDirection::Response => self
                .method
                .decode_json_response(&payload)
                .map_err(|error| protocol_body_error(error.message()))?,
        };
        let converted_len = u32::try_from(converted.len())
            .map_err(|_| protocol_body_error("streaming converted message exceeds gRPC limit"))?;
        if converted.len().saturating_add(5) > self.max_buffer_bytes {
            return Err(protocol_body_error(
                "streaming converted message exceeds configured buffer limit",
            ));
        }
        self.messages += 1;
        let mut output = BytesMut::with_capacity(converted.len() + 5);
        output.extend_from_slice(&[0]);
        output.extend_from_slice(&converted_len.to_be_bytes());
        output.extend_from_slice(&converted);
        Ok(Some(output.freeze()))
    }

    /// 业务作用：在 EOF/trailer 处复验未完成 envelope 与非流一侧的消息基数，避免把截断或
    /// 多消息输入当作正常 half-close；错误 status 的 trailers-only 响应仍合法。
    ///
    /// 参数说明：
    /// - `trailers`：是响应方向刚收到的 native trailer；请求 EOF 或无 trailer 响应传 None。
    ///
    /// 返回：边界完整且基数符合 descriptor 时成功，否则产生当前 stream 的协议错误。
    fn validate_finish(&self, trailers: Option<&HeaderMap>) -> Result<(), BoxError> {
        if !self.buffer.is_empty() {
            return Err(protocol_body_error(
                "streaming JSON body ended inside an envelope",
            ));
        }
        match self.direction {
            StreamingJsonDirection::Request
                if !self.method.is_client_streaming() && self.messages != 1 =>
            {
                Err(protocol_body_error(
                    "server-streaming RPC requires exactly one request message",
                ))
            }
            StreamingJsonDirection::Response
                if !self.method.is_server_streaming() && self.messages == 0 =>
            {
                let status = trailers
                    .map(grpc_status)
                    .or(self.initial_status)
                    .unwrap_or(2);
                if status == 0 {
                    Err(protocol_body_error(
                        "client-streaming RPC success requires one response message",
                    ))
                } else {
                    Ok(())
                }
            }
            StreamingJsonDirection::Request | StreamingJsonDirection::Response => Ok(()),
        }
    }
}

#[cfg(feature = "grpc-descriptor")]
impl Body for StreamingJsonBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按下游 demand 推进最多一条 JSON/protobuf 消息，并把 trailer 保留给外层
    /// Connect EndStream 转换器；取消该 future 会直接停止读取上游/下游 stream。
    ///
    /// 参数说明：
    /// - `cx`：是 Hyper 当前 body 消费者的唤醒上下文。
    ///
    /// 返回：产生一条转换后的 DATA、原样 trailer、协议错误、Pending 或流结束。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.finished {
                return Poll::Ready(None);
            }
            match self.decode_ready() {
                Ok(Some(message)) => return Poll::Ready(Some(Ok(Frame::data(message)))),
                Ok(None) => {}
                Err(error) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(error)));
                }
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if self.buffer.len().saturating_add(data.len()) > self.max_buffer_bytes {
                            self.finished = true;
                            return Poll::Ready(Some(Err(protocol_body_error(
                                "streaming JSON DATA exceeds configured buffer limit",
                            ))));
                        }
                        self.buffer.extend_from_slice(&data);
                    }
                    Err(frame) => {
                        let trailers = frame.into_trailers().ok();
                        if matches!(self.direction, StreamingJsonDirection::Request) {
                            if let Some(trailers) = trailers {
                                if let Err(error) = validate_browser_request_trailers(&trailers) {
                                    self.finished = true;
                                    return Poll::Ready(Some(Err(protocol_body_error(
                                        error.message(),
                                    ))));
                                }
                                if let Err(error) = self.validate_finish(Some(&trailers)) {
                                    self.finished = true;
                                    return Poll::Ready(Some(Err(error)));
                                }
                                self.finished = true;
                                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                            }
                        }
                        if let Err(error) = self.validate_finish(trailers.as_ref()) {
                            self.finished = true;
                            return Poll::Ready(Some(Err(error)));
                        }
                        self.finished = true;
                        return Poll::Ready(trailers.map(|trailers| Ok(Frame::trailers(trailers))));
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(match self.validate_finish(None) {
                        Ok(()) => None,
                        Err(error) => Some(Err(error)),
                    });
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// 业务作用：只在 codec 已完成 trailer/EOF 或失败后报告结束，避免 Hyper 提前停止轮询未完成消息。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：终态为 true；仍有输入、暂存或输出可能性时 false。
    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

/// gRPC-Web text 请求解码器；Base64 quartet 可跨任意 HTTP DATA frame。
struct Base64DecodeBody {
    inner: BoxBody,
    pending: BytesMut,
    saw_padding: bool,
    pending_trailers: Option<HeaderMap>,
    done: bool,
}

impl Base64DecodeBody {
    /// 业务作用：建立跨 chunk 的 Base64 解码状态，保持下游背压并把错误留在当前 stream。
    ///
    /// 参数说明：
    /// - `inner`：是 gRPC-Web text body。
    ///
    /// 返回：逐批产生 native gRPC envelope 字节的 body。
    fn new(inner: BoxBody) -> Self {
        Self {
            inner,
            pending: BytesMut::new(),
            saw_padding: false,
            pending_trailers: None,
            done: false,
        }
    }

    /// 业务作用：解码当前已具备的完整 Base64 quartet，并保留不足四字节的尾部。
    ///
    /// 参数说明：
    /// - `eof`：表示下游已结束，此时剩余字节也必须构成合法最终量子。
    ///
    /// 返回：有解码产物时返回 Bytes；等待更多输入时 None；非法 Base64 返回 body error。
    fn decode_ready(&mut self, eof: bool) -> Result<Option<Bytes>, BoxError> {
        let decode_len = if eof {
            self.pending.len()
        } else if self.pending.contains(&b'=') {
            if !self.pending.len().is_multiple_of(4) {
                return Ok(None);
            }
            self.saw_padding = true;
            self.pending.len()
        } else {
            self.pending.len() / 4 * 4
        };
        if decode_len == 0 {
            return Ok(None);
        }
        let encoded = self.pending.split_to(decode_len);
        let decoded = STANDARD
            .decode(encoded.as_ref())
            .map_err(|_| protocol_body_error("invalid gRPC-Web text Base64"))?;
        Ok(Some(Bytes::from(decoded)))
    }
}

impl Body for Base64DecodeBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按下游 demand 增量解码 gRPC-Web text，Base64 quartet 可跨 HTTP DATA frame，
    /// 且不会读取到当前输出之后的整个请求。
    ///
    /// 参数说明：
    /// - `cx`：是 native 上游消费者的唤醒上下文。
    ///
    /// 返回：可用 decoded DATA、协议错误、Pending 或 EOF。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }
            if self.pending.is_empty() {
                if let Some(trailers) = self.pending_trailers.take() {
                    self.done = true;
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        for &byte in data.iter() {
                            if byte.is_ascii_whitespace() {
                                continue;
                            }
                            if self.saw_padding {
                                self.done = true;
                                return Poll::Ready(Some(Err(protocol_body_error(
                                    "data after gRPC-Web Base64 padding",
                                ))));
                            }
                            self.pending.extend_from_slice(&[byte]);
                        }
                        match self.decode_ready(false) {
                            Ok(Some(decoded)) => {
                                return Poll::Ready(Some(Ok(Frame::data(decoded))))
                            }
                            Ok(None) => continue,
                            Err(error) => {
                                self.done = true;
                                return Poll::Ready(Some(Err(error)));
                            }
                        }
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            if let Err(error) = validate_browser_request_trailers(&trailers) {
                                self.done = true;
                                return Poll::Ready(Some(Err(protocol_body_error(
                                    error.message(),
                                ))));
                            }
                            self.pending_trailers = Some(trailers);
                            match self.decode_ready(true) {
                                Ok(Some(decoded)) => {
                                    return Poll::Ready(Some(Ok(Frame::data(decoded))))
                                }
                                Ok(None) => continue,
                                Err(error) => {
                                    self.done = true;
                                    return Poll::Ready(Some(Err(error)));
                                }
                            }
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    return match self.decode_ready(true) {
                        Ok(Some(decoded)) => Poll::Ready(Some(Ok(Frame::data(decoded)))),
                        Ok(None) => Poll::Ready(None),
                        Err(error) => Poll::Ready(Some(Err(error))),
                    };
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// 业务作用：只有输入 EOF 且 Base64 尾部已经完整消费时才声明结束，避免丢失最终量子。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：解码器完成且无 pending 字节时 true。
    fn is_end_stream(&self) -> bool {
        self.done && self.pending.is_empty()
    }
}

/// 业务作用：把 BoxBody 协议错误构造成可取消当前 H2 request stream 的 owned error。
///
/// 参数说明：
/// - `message`：是固定、无 payload 的错误原因。
///
/// 返回：线程安全的 io::Error trait object。
fn protocol_body_error(message: &'static str) -> BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

/// 业务作用：构造 gRPC-Web 响应，DATA 原样流过，最终 gRPC trailer 改成 body trailer frame。
///
/// 参数说明：
/// - `response`：是 native gRPC 响应
/// - `text`：决定是否再做连续 Base64 编码。
///
/// 返回：HTTP status/metadata 保留、Content-Type 与 body framing 已转换的响应。
fn grpc_web_response(response: Response<BoxBody>, text: bool) -> Response<BoxBody> {
    let (mut parts, body) = response.into_parts();
    let initial = take_initial_status(&mut parts.headers);
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRAILER);
    parts.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(if text {
            "application/grpc-web-text+proto"
        } else {
            "application/grpc-web+proto"
        }),
    );
    let body = BrowserTrailerBody::new(body, initial, TrailerMode::GrpcWeb);
    let body = if text {
        Base64EncodeBody::new(body.boxed()).boxed()
    } else {
        body.boxed()
    };
    Response::from_parts(parts, body)
}

/// 业务作用：构造 Connect streaming 响应，把最终 gRPC trailer 转成唯一 EndStream envelope。
///
/// 参数说明：
/// - `response`：是 native gRPC streaming 响应。
///
/// 返回：逐消息流式响应；结束状态在 body 中表达，不依赖浏览器不可见的 HTTP trailer。
fn connect_streaming_response(response: Response<BoxBody>) -> Response<BoxBody> {
    let (mut parts, body) = response.into_parts();
    let initial = take_initial_status(&mut parts.headers);
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRAILER);
    parts.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/connect+proto"),
    );
    parts.status = StatusCode::OK;
    if let Some(value) = parts.headers.remove(GRPC_ENCODING) {
        parts.headers.insert(CONNECT_CONTENT_ENCODING, value);
    }
    Response::from_parts(
        parts,
        BrowserTrailerBody::new(body, initial, TrailerMode::Connect).boxed(),
    )
}

/// 业务作用：逐条把 native protobuf response envelope 转为 Connect JSON，并在最后复用
/// EndStream status/details/metadata 映射；DATA 流不聚合、不预读下一条消息。
///
/// 参数说明：
/// - `response`：是 native gRPC streaming 响应
/// - `method`：固定 output descriptor 与流预算。
///
/// 返回：HTTP 200 `application/connect+json` 流；每条消息和最终 EndStream 都是独立 envelope。
#[cfg(feature = "grpc-descriptor")]
fn connect_streaming_json_response(
    response: Response<BoxBody>,
    method: Arc<ResolvedGrpcMethod>,
) -> Response<BoxBody> {
    let (mut parts, body) = response.into_parts();
    let initial = take_initial_status(&mut parts.headers);
    let initial_status = initial
        .contains_key(&GRPC_STATUS)
        .then(|| grpc_status(&initial));
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRAILER);
    parts.headers.remove(GRPC_ENCODING);
    parts.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/connect+json"),
    );
    parts.status = StatusCode::OK;
    let converted = StreamingJsonBody::new(
        body,
        method,
        StreamingJsonDirection::Response,
        initial_status,
    )
    .boxed();
    Response::from_parts(
        parts,
        BrowserTrailerBody::new(converted, initial, TrailerMode::Connect).boxed(),
    )
}

#[derive(Clone, Copy)]
enum TrailerMode {
    GrpcWeb,
    Connect,
}

/// 流式浏览器响应体：native DATA 直接转发，只在尾部把 trailer 序列化成协议 body envelope。
struct BrowserTrailerBody {
    inner: BoxBody,
    initial: HeaderMap,
    mode: TrailerMode,
    finished: bool,
}

impl BrowserTrailerBody {
    /// 业务作用：建立 trailer-to-body 转换器，并保留 trailers-only response 的初始 status。
    ///
    /// 参数说明：
    /// - `inner`：是 native gRPC body
    /// - `initial`：是从 response head 移出的 status
    /// - `mode`：决定 gRPC-Web header block 或 Connect EndStream JSON。
    ///
    /// 返回：不聚合 DATA、最多额外产生一个结尾 DATA frame 的 body。
    fn new(inner: BoxBody, initial: HeaderMap, mode: TrailerMode) -> Self {
        Self {
            inner,
            initial,
            mode,
            finished: false,
        }
    }

    /// 业务作用：合并 response-head status 与真实 trailer，并保证缺失 grpc-status 时 fail closed。
    ///
    /// 参数说明：
    /// - `trailers`：是上游 body 的最终 trailer；None 表示上游直接 EOF。
    ///
    /// 返回：按下游协议编码的唯一结束 envelope。
    fn finish(&mut self, trailers: Option<HeaderMap>) -> Bytes {
        let mut merged = std::mem::take(&mut self.initial);
        if let Some(trailers) = trailers {
            for (name, value) in trailers {
                if let Some(name) = name {
                    merged.append(name, value);
                }
            }
        }
        ensure_grpc_status(&mut merged);
        match self.mode {
            TrailerMode::GrpcWeb => encode_grpc_web_trailers(&merged),
            TrailerMode::Connect => encode_connect_end_stream(&merged),
        }
    }
}

impl Body for BrowserTrailerBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：流式转发 native DATA，并在观察到 trailer/EOF 的同一位置生成唯一浏览器结束
    /// envelope，防止先向浏览器宣告成功再丢失最终 gRPC status。
    ///
    /// 参数说明：
    /// - `cx`：是浏览器下游连接的 body 唤醒上下文。
    ///
    /// 返回：原 DATA、编码后的结束 DATA、上游错误、Pending 或 EOF。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
                Err(frame) => {
                    let trailers = frame.into_trailers().ok();
                    self.finished = true;
                    let end = self.finish(trailers);
                    Poll::Ready(Some(Ok(Frame::data(end))))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finished = true;
                let end = self.finish(None);
                Poll::Ready(Some(Ok(Frame::data(end))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 业务作用：结束 envelope 已生成或上游失败后封闭 body，保证 status 只编码一次。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：转换器已进入终态时 true。
    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

/// gRPC-Web text 响应编码器；只编码完整 3-byte group，最终 EOF 才补 Base64 padding。
struct Base64EncodeBody {
    inner: BoxBody,
    carry: BytesMut,
    source_done: bool,
    finished: bool,
}

impl Base64EncodeBody {
    /// 业务作用：建立跨 native DATA frame 的连续 Base64 编码器，避免在中间 chunk 写 padding。
    ///
    /// 参数说明：
    /// - `inner`：已把 gRPC trailer 转成最后一个 DATA frame。
    ///
    /// 返回：gRPC-Web text body。
    fn new(inner: BoxBody) -> Self {
        Self {
            inner,
            carry: BytesMut::new(),
            source_done: false,
            finished: false,
        }
    }

    /// 业务作用：编码当前可安全输出的 Base64 字节，并保留不足 3 字节的尾部。
    ///
    /// 参数说明：
    /// - `flush`：只在 source EOF 时为 true，允许输出 padding。
    ///
    /// 返回：有可输出数据时返回 ASCII Bytes，否则 None。
    fn encode_ready(&mut self, flush: bool) -> Option<Bytes> {
        let encode_len = if flush {
            self.carry.len()
        } else {
            self.carry.len() / 3 * 3
        };
        if encode_len == 0 {
            return None;
        }
        let bytes = self.carry.split_to(encode_len);
        Some(Bytes::from(STANDARD.encode(bytes.as_ref())))
    }
}

impl Body for Base64EncodeBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按下游写入能力增量编码连续 gRPC-Web text 字节流，只在源 EOF 写 Base64 padding。
    ///
    /// 参数说明：
    /// - `cx`：是 HTTP 下游消费者的唤醒上下文。
    ///
    /// 返回：完整三字节组的 Base64 DATA、错误、Pending 或最终带 padding DATA/EOF。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.finished {
                return Poll::Ready(None);
            }
            if self.source_done {
                self.finished = true;
                return Poll::Ready(self.encode_ready(true).map(|bytes| Ok(Frame::data(bytes))));
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        self.carry.extend_from_slice(&data);
                        if let Some(encoded) = self.encode_ready(false) {
                            return Poll::Ready(Some(Ok(Frame::data(encoded))));
                        }
                    }
                    Err(_) => {
                        self.finished = true;
                        return Poll::Ready(Some(Err(protocol_body_error(
                            "unexpected trailer after browser trailer conversion",
                        ))));
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => self.source_done = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// 业务作用：最终 carry 已编码后才允许 Hyper 结束响应，避免丢失末尾 padding 数据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：编码器已完全结束时 true。
    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

/// 业务作用：从 native response head 移出 trailers-only status，避免浏览器收到两份冲突状态。
///
/// 参数说明：
/// - `headers`：是 native gRPC response headers。
///
/// 返回：只包含 grpc-status/message/details 的 HeaderMap，其余初始 metadata 仍留在 response head。
fn take_initial_status(headers: &mut HeaderMap) -> HeaderMap {
    let mut status = HeaderMap::new();
    for name in [GRPC_STATUS, GRPC_MESSAGE, GRPC_STATUS_DETAILS] {
        for value in headers.get_all(&name).iter().cloned().collect::<Vec<_>>() {
            status.append(name.clone(), value);
        }
        headers.remove(name);
    }
    status
}

/// 业务作用：保证浏览器结束 envelope 总有权威 status；上游直接 EOF 不得被解释为成功。
///
/// 参数说明：
/// - `trailers`：是合并后的 native status/metadata。
///
/// 返回：无返回值；缺失 status 时原地写入 UNKNOWN 与固定原因。
fn ensure_grpc_status(trailers: &mut HeaderMap) {
    if !trailers.contains_key(GRPC_STATUS) {
        trailers.insert(GRPC_STATUS, HeaderValue::from_static("2"));
        trailers.insert(
            GRPC_MESSAGE,
            HeaderValue::from_static("missing%20grpc-status"),
        );
    }
}

/// 业务作用：把 gRPC trailer headers 编码为 gRPC-Web MSB trailer frame。
///
/// 参数说明：
/// - `trailers`：已保证包含 grpc-status。
///
/// 返回：`0x80 + u32 length + HTTP/1 header block` 的完整 body frame。
fn encode_grpc_web_trailers(trailers: &HeaderMap) -> Bytes {
    let mut block = BytesMut::new();
    for (name, value) in trailers {
        block.extend_from_slice(name.as_str().as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    let mut frame = BytesMut::with_capacity(5 + block.len());
    frame.extend_from_slice(&[0x80]);
    frame.extend_from_slice(&(block.len() as u32).to_be_bytes());
    frame.extend_from_slice(&block);
    frame.freeze()
}

/// 业务作用：把 native gRPC status/metadata 编码为 Connect streaming EndStream JSON envelope。
///
/// 参数说明：
/// - `trailers`：已保证包含 grpc-status。
///
/// 返回：flag=0x02 的 Connect envelope；成功省略 error，失败包含规范 code/message。
fn encode_connect_end_stream(trailers: &HeaderMap) -> Bytes {
    let status = grpc_status(trailers);
    let mut root = serde_json::Map::new();
    let metadata = connect_metadata(trailers);
    if !metadata.is_empty() {
        root.insert(
            "metadata".to_string(),
            serde_json::to_value(metadata).expect("header metadata is serializable"),
        );
    }
    if status != 0 {
        let mut error = serde_json::Map::new();
        error.insert(
            "code".to_string(),
            serde_json::Value::String(grpc_code_name(status).to_string()),
        );
        if let Some(message) = grpc_message(trailers) {
            error.insert("message".to_string(), serde_json::Value::String(message));
        }
        if let Some(details) = grpc_error_details(trailers) {
            error.insert("details".to_string(), serde_json::Value::Array(details));
        }
        root.insert("error".to_string(), serde_json::Value::Object(error));
    }
    let json = serde_json::to_vec(&root).expect("Connect EndStream JSON is serializable");
    let mut frame = BytesMut::with_capacity(5 + json.len());
    frame.extend_from_slice(&[0x02]);
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(&json);
    frame.freeze()
}

/// 业务作用：聚合 Connect unary native response，读取最终 trailer 后映射 HTTP status 与裸消息。
///
/// 参数说明：
/// - `response`：是 native unary response
/// - `limit`：同时限制 envelope 聚合与下游 payload。
///
/// 返回：成功响应为 application/proto 裸消息；RPC 错误为 Connect JSON + canonical HTTP status；
/// 缺失/多条/畸形 gRPC message 返回 502。
async fn connect_unary_response(
    response: Response<BoxBody>,
    limit: u64,
) -> Result<Response<BoxBody>, BrowserGrpcError> {
    let (mut parts, mut body) = response.into_parts();
    let mut trailers = take_initial_status(&mut parts.headers);
    let mut data = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|_| BrowserGrpcError::upstream("gRPC response body read failed"))?;
        match frame.into_data() {
            Ok(bytes) => {
                if (data.len() as u64).saturating_add(bytes.len() as u64) > limit.saturating_add(5)
                {
                    return Err(BrowserGrpcError::upstream(
                        "Connect unary response exceeds body limit",
                    ));
                }
                data.extend_from_slice(&bytes);
            }
            Err(frame) => {
                if let Ok(incoming) = frame.into_trailers() {
                    for (name, value) in incoming {
                        if let Some(name) = name {
                            trailers.append(name, value);
                        }
                    }
                }
            }
        }
    }
    ensure_grpc_status(&mut trailers);
    append_connect_metadata(&mut parts.headers, &trailers);
    parts.headers.remove(TRAILER);
    let status = grpc_status(&trailers);
    if status != 0 {
        #[cfg(feature = "grpc-descriptor")]
        parts.extensions.insert(BrowserGrpcStatus(status));
        parts.status = grpc_status_to_http(status);
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = connect_error_json(&trailers);
        parts.headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).expect("body length header"),
        );
        return Ok(Response::from_parts(parts, full_body(body)));
    }
    if data.len() < 5 {
        return Err(BrowserGrpcError::upstream(
            "Connect unary response is missing a gRPC message",
        ));
    }
    let compressed = data[0];
    if compressed > 1 {
        return Err(BrowserGrpcError::upstream(
            "Connect unary response has invalid compression flag",
        ));
    }
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() != 5 + length {
        return Err(BrowserGrpcError::upstream(
            "Connect unary response must contain exactly one gRPC message",
        ));
    }
    data.advance(5);
    let payload = data.freeze();
    if compressed == 1 {
        let encoding = parts.headers.get(GRPC_ENCODING).cloned().ok_or_else(|| {
            BrowserGrpcError::upstream("compressed gRPC response is missing grpc-encoding")
        })?;
        parts.headers.insert(CONTENT_ENCODING, encoding);
    }
    parts.headers.remove(GRPC_ENCODING);
    parts.status = StatusCode::OK;
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/proto"));
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&payload.len().to_string()).expect("body length header"),
    );
    Ok(Response::from_parts(parts, full_body(payload)))
}

/// 业务作用：复用 Connect unary status/trailer 聚合后，把唯一 protobuf success message 按
/// descriptor 编码为 canonical JSON；RPC error 继续沿用 Connect JSON error 语义。
///
/// 参数说明：
/// - `response`：是 native unary response
/// - `limit`：是通用聚合上限
/// - `method`：锁定 output schema 和 route 级 JSON/output 预算。
///
/// 返回：成功为 `application/json` canonical protobuf JSON；RPC error 保留 Connect HTTP/JSON；
/// 压缩、畸形或超预算上游 payload 返回 502。
#[cfg(feature = "grpc-descriptor")]
async fn connect_unary_json_response(
    response: Response<BoxBody>,
    limit: u64,
    method: &ResolvedGrpcMethod,
) -> Result<Response<BoxBody>, BrowserGrpcError> {
    let response = connect_unary_response(response, limit).await?;
    if response.status() != StatusCode::OK {
        return Ok(response);
    }
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Err(BrowserGrpcError::upstream(
            "compressed protobuf response cannot be translated to JSON",
        ));
    }
    let (mut parts, body) = response.into_parts();
    let payload = body
        .collect()
        .await
        .map_err(|_| BrowserGrpcError::upstream("Connect unary response body read failed"))?
        .to_bytes();
    let json = method
        .decode_json_response(&payload)
        .map_err(|error| BrowserGrpcError::upstream(error.message()))?;
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&json.len().to_string()).expect("body length header"),
    );
    Ok(Response::from_parts(parts, full_body(json)))
}

/// 业务作用：把 annotated unary RPC response 转为 canonical protobuf JSON；错误使用
/// `google.rpc.Status` 风格的数字 code/HTTP status，而不是 Connect 的字符串 code。
///
/// 参数说明：
/// - `response`：是 native unary response
/// - `limit`：是聚合预算
/// - `request`：持有 output schema。
///
/// 返回：成功为 protobuf canonical JSON；RPC error 为数字 code JSON；畸形/压缩/超限为 502。
#[cfg(feature = "grpc-descriptor")]
async fn google_unary_json_response(
    response: Response<BoxBody>,
    limit: u64,
    request: &ResolvedGoogleRequest,
) -> Result<Response<BoxBody>, BrowserGrpcError> {
    let response = connect_unary_response(response, limit).await?;
    if response.status() != StatusCode::OK {
        let (mut parts, body) = response.into_parts();
        let status = parts
            .extensions
            .remove::<BrowserGrpcStatus>()
            .map(|status| status.0)
            .unwrap_or(2);
        let bytes = body
            .collect()
            .await
            .map_err(|_| BrowserGrpcError::upstream("gRPC-JSON error body read failed"))?
            .to_bytes();
        let mut value = serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|_| BrowserGrpcError::upstream("gRPC-JSON error body encoding failed"))?;
        if let Some(object) = value.as_object_mut() {
            object.insert("code".to_owned(), serde_json::Value::from(status));
        }
        let json = serde_json::to_vec(&value)
            .map_err(|_| BrowserGrpcError::upstream("gRPC-JSON error body encoding failed"))?;
        parts.headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&json.len().to_string()).expect("body length header"),
        );
        return Ok(Response::from_parts(parts, full_body(Bytes::from(json))));
    }
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Err(BrowserGrpcError::upstream(
            "compressed protobuf response cannot be translated to JSON",
        ));
    }
    let (mut parts, body) = response.into_parts();
    let payload = body
        .collect()
        .await
        .map_err(|_| BrowserGrpcError::upstream("gRPC-JSON response body read failed"))?
        .to_bytes();
    let json = request
        .decode_json_response(&payload)
        .map_err(|error| BrowserGrpcError::upstream(error.message()))?;
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    parts.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&json.len().to_string()).expect("body length header"),
    );
    Ok(Response::from_parts(parts, full_body(json)))
}

/// 业务作用：把 trailer metadata 搬到 Connect unary response headers，使浏览器无需读取 HTTP trailer。
///
/// 参数说明：
/// - `headers`：是下游 response headers
/// - `trailers`：含 status 与应用 metadata。
///
/// 返回：无返回值；保留多值，排除 gRPC status 专用字段与 hop-by-hop 字段。
fn append_connect_metadata(headers: &mut HeaderMap, trailers: &HeaderMap) {
    for (name, value) in trailers {
        if is_grpc_status_header(name) || name == CONTENT_LENGTH || name == TRAILER {
            continue;
        }
        let Ok(prefixed) = HeaderName::from_bytes(format!("trailer-{name}").as_bytes()) else {
            continue;
        };
        headers.append(prefixed, value.clone());
    }
}

/// 业务作用：把 Connect RPC error 编码为浏览器客户端可解析的 JSON error body。
///
/// 参数说明：
/// - `trailers`：含 grpc-status/message。
///
/// 返回：UTF-8 JSON Bytes；不反射未经解码的 header 文本。
fn connect_error_json(trailers: &HeaderMap) -> Bytes {
    let status = grpc_status(trailers);
    let mut error = serde_json::Map::new();
    error.insert(
        "code".to_string(),
        serde_json::Value::String(grpc_code_name(status).to_string()),
    );
    if let Some(message) = grpc_message(trailers) {
        error.insert("message".to_string(), serde_json::Value::String(message));
    }
    if let Some(details) = grpc_error_details(trailers) {
        error.insert("details".to_string(), serde_json::Value::Array(details));
    }
    Bytes::from(serde_json::to_vec(&error).expect("Connect error JSON is serializable"))
}

/// 业务作用：抽取 Connect EndStream 可公开的应用 trailer metadata，并保持重复值顺序。
///
/// 参数说明：
/// - `trailers`：是 native gRPC trailer。
///
/// 返回：按 header name 排序的 JSON map；status 专用字段不混入 metadata。
fn connect_metadata(trailers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut metadata = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in trailers {
        if is_grpc_status_header(name) {
            continue;
        }
        metadata
            .entry(name.as_str().to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    metadata
}

/// 业务作用：识别只表达 RPC 状态、不得当作应用 metadata 复制的 gRPC 字段。
///
/// 参数说明：
/// - `name`：是已由 HTTP parser 校验的 header name。
///
/// 返回：grpc-status/message/details-bin 时 true。
fn is_grpc_status_header(name: &HeaderName) -> bool {
    name == GRPC_STATUS || name == GRPC_MESSAGE || name == GRPC_STATUS_DETAILS
}

/// 业务作用：读取并约束 gRPC canonical status；非法值按 UNKNOWN fail closed。
///
/// 参数说明：
/// - `trailers`：是合并后的 status metadata。
///
/// 返回：0..=16 原值，缺失/非法返回 2。
fn grpc_status(trailers: &HeaderMap) -> u16 {
    trailers
        .get(GRPC_STATUS)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value <= 16)
        .unwrap_or(2)
}

/// 业务作用：按 gRPC percent-encoding 解码错误消息，避免把转义文本原样展示给 Connect 客户端。
///
/// 参数说明：
/// - `trailers`：是合并后的 status metadata。
///
/// 返回：存在合法 UTF-8 header 时返回有损安全解码文本，否则 None。
fn grpc_message(trailers: &HeaderMap) -> Option<String> {
    let raw = trailers.get(GRPC_MESSAGE)?.to_str().ok()?;
    Some(
        percent_encoding::percent_decode_str(raw)
            .decode_utf8_lossy()
            .into_owned(),
    )
}

/// 业务作用：把 google.rpc.Status 中的 Any details 转为 Connect Error.details，保留强类型错误载荷。
///
/// 参数说明：
/// - `trailers`：的 grpc-status-details-bin 是 Base64 编码 google.rpc.Status protobuf。
///
/// 返回：成功解析至少一个 Any 时返回 Connect detail 数组；缺失或畸形时 None，主 status 仍可返回。
fn grpc_error_details(trailers: &HeaderMap) -> Option<Vec<serde_json::Value>> {
    let encoded = trailers.get(GRPC_STATUS_DETAILS)?.as_bytes();
    let status = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    let mut cursor = 0usize;
    let mut details = Vec::new();
    while cursor < status.len() {
        let key = read_proto_varint(&status, &mut cursor)?;
        let field = key >> 3;
        let wire = (key & 0x07) as u8;
        if field == 3 && wire == 2 {
            let any = read_proto_bytes(&status, &mut cursor)?;
            if let Some(detail) = decode_any_detail(any) {
                details.push(detail);
            }
        } else if !skip_proto_field(&status, &mut cursor, wire) {
            return None;
        }
    }
    (!details.is_empty()).then_some(details)
}

/// 业务作用：解析 google.protobuf.Any 的 type_url/value，转换为 Connect 的 type/value 对象。
///
/// 参数说明：
/// - `input`：是单个 Any 的 length-delimited protobuf payload。
///
/// 返回：字段完整时返回 JSON detail；畸形或缺字段时 None。
fn decode_any_detail(input: &[u8]) -> Option<serde_json::Value> {
    let mut cursor = 0usize;
    let mut type_url = None;
    let mut value = None;
    while cursor < input.len() {
        let key = read_proto_varint(input, &mut cursor)?;
        match (key >> 3, (key & 0x07) as u8) {
            (1, 2) => {
                type_url = Some(std::str::from_utf8(read_proto_bytes(input, &mut cursor)?).ok()?)
            }
            (2, 2) => value = Some(read_proto_bytes(input, &mut cursor)?),
            (_, wire) if skip_proto_field(input, &mut cursor, wire) => {}
            _ => return None,
        }
    }
    let type_name = type_url?
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())?;
    let value = STANDARD_NO_PAD.encode(value?);
    Some(serde_json::json!({
        "type": type_name,
        "value": value
    }))
}

/// 业务作用：读取受 header 大小上限保护的 protobuf varint，供 status details 的无 schema 解析使用。
///
/// 参数说明：
/// - `input`：是 protobuf 字节
/// - `cursor`：是读位置并在成功后推进。
///
/// 返回：最多十字节的 u64；截断或溢出返回 None。
fn read_proto_varint(input: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *input.get(*cursor)?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// 业务作用：读取 length-delimited protobuf 字段并严格检查边界。
///
/// 参数说明：
/// - `input`：是 protobuf 字节
/// - `cursor`：位于长度 varint。
///
/// 返回：字段借用切片；长度溢出或截断返回 None。
fn read_proto_bytes<'a>(input: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let length = usize::try_from(read_proto_varint(input, cursor)?).ok()?;
    let end = cursor.checked_add(length)?;
    let bytes = input.get(*cursor..end)?;
    *cursor = end;
    Some(bytes)
}

/// 业务作用：跳过 google.rpc.Status/Any 的未知 protobuf 字段，保持向前兼容且不越界。
///
/// 参数说明：
/// - `input`：是 protobuf 字节
/// - `cursor`：位于字段值
/// - `wire`：是 wire type。
///
/// 返回：支持的 wire type 且字段完整时 true，否则 false。
fn skip_proto_field(input: &[u8], cursor: &mut usize, wire: u8) -> bool {
    match wire {
        0 => read_proto_varint(input, cursor).is_some(),
        1 => cursor
            .checked_add(8)
            .filter(|end| *end <= input.len())
            .is_some_and(|end| {
                *cursor = end;
                true
            }),
        2 => read_proto_bytes(input, cursor).is_some(),
        5 => cursor
            .checked_add(4)
            .filter(|end| *end <= input.len())
            .is_some_and(|end| {
                *cursor = end;
                true
            }),
        _ => false,
    }
}

/// 业务作用：把 gRPC canonical code 映射为 Connect 协议使用的小写枚举名。
///
/// 参数说明：
/// - `status`：已归一到 0..=16。
///
/// 返回：稳定 Connect code 字符串。
fn grpc_code_name(status: u16) -> &'static str {
    match status {
        0 => "ok",
        1 => "canceled",
        2 => "unknown",
        3 => "invalid_argument",
        4 => "deadline_exceeded",
        5 => "not_found",
        6 => "already_exists",
        7 => "permission_denied",
        8 => "resource_exhausted",
        9 => "failed_precondition",
        10 => "aborted",
        11 => "out_of_range",
        12 => "unimplemented",
        13 => "internal",
        14 => "unavailable",
        15 => "data_loss",
        16 => "unauthenticated",
        _ => "unknown",
    }
}

/// 业务作用：把 gRPC canonical error 映射为 Connect unary 规范 HTTP 状态。
///
/// 参数说明：
/// - `status`：是 1..=16 的 gRPC code。
///
/// 返回：与 Connect protocol 一致的 4xx/5xx；未知值为 500。
fn grpc_status_to_http(status: u16) -> StatusCode {
    match status {
        1 => StatusCode::from_u16(499).expect("499 is a valid extension status"),
        3 | 9 | 11 => StatusCode::BAD_REQUEST,
        4 => StatusCode::GATEWAY_TIMEOUT,
        5 => StatusCode::NOT_FOUND,
        6 | 10 => StatusCode::CONFLICT,
        7 => StatusCode::FORBIDDEN,
        8 => StatusCode::TOO_MANY_REQUESTS,
        12 => StatusCode::NOT_IMPLEMENTED,
        14 => StatusCode::SERVICE_UNAVAILABLE,
        16 => StatusCode::UNAUTHORIZED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
