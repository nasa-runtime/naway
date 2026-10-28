//! 显式普通 HTTP 请求解压；认证原字节，正文安全检查消费解码实体。

mod body;
mod config;
pub(crate) mod metrics;

pub(crate) use config::parse;

use http::{header, request::Parts, HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

use crate::routing::ContentCoding;
use crate::{text_status, BoxBody};

/// 冻结到单次请求的内容解码硬边界。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    gzip: bool,
    brotli: bool,
    encoded: u64,
    decoded: u64,
    ratio: u64,
    timeout_ms: u64,
    chunk: usize,
}

/// 客户端实体拒绝，不能作为后端故障证据。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Rejected {
    Malformed = 1,
    Limit = 2,
    Unsupported = 3,
    Deadline = 4,
    Capacity = 5,
}

impl Rejected {
    /// 业务作用：为正文失败提供稳定 HTTP 状态，不暴露解析器内部信息。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：客户端格式、预算、编码、期限或本机容量对应状态。
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::Malformed => StatusCode::BAD_REQUEST,
            Self::Limit => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Unsupported => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Deadline => StatusCode::REQUEST_TIMEOUT,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// 业务作用：输出低敏固定拒绝描述，避免将客户端封装或字节写入错误响应。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前失败类别的固定说明。
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Malformed => "invalid compressed request body",
            Self::Limit => "request decompression limit exceeded",
            Self::Unsupported => "request content encoding rejected",
            Self::Deadline => "request decompression deadline exceeded",
            Self::Capacity => "request decompression capacity reached",
        }
    }
}

impl std::fmt::Display for Rejected {
    /// 业务作用：保持错误链中的本地输入归因与固定诊断信息。
    ///
    /// 参数说明：
    /// - `out`：诊断输出目标。
    ///
    /// 返回：固定错误描述的写入结果。
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.message())
    }
}
impl std::error::Error for Rejected {}

/// 请求消费方与响应交付方共享首个失败，不保存实体内容或后台任务。
#[derive(Default)]
pub(crate) struct State {
    failure: AtomicU8,
    wake: futures::task::AtomicWaker,
}

impl State {
    /// 业务作用：恢复首个实体失败，让聚合检查器和转发错误保持相同归因。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已发生的固定拒绝；None 不代表整篇正文已验证。
    pub(crate) fn failure(&self) -> Option<Rejected> {
        match self.failure.load(Ordering::Acquire) {
            1 => Some(Rejected::Malformed),
            2 => Some(Rejected::Limit),
            3 => Some(Rejected::Unsupported),
            4 => Some(Rejected::Deadline),
            5 => Some(Rejected::Capacity),
            _ => None,
        }
    }

    /// 业务作用：冻结第一失败并唤醒响应流，不能在迟到的正文错误之后继续交付成功内容。
    ///
    /// 参数说明：
    /// - `error`：当前请求的本地拒绝原因。
    ///
    /// 返回：记录失败且唤醒等待响应，不覆盖先前原因。
    fn reject(&self, error: Rejected) {
        if self
            .failure
            .compare_exchange(0, error as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            metrics::EVENTS[error as usize].fetch_add(1, Ordering::Relaxed);
        }
        self.wake.wake();
    }

    /// 业务作用：在响应头发送前恢复客户端错误，发送后通过流错误中断迟到失败。
    ///
    /// 参数说明：
    /// - `response`：业务管线产生、尚未交给下游的响应。
    ///
    /// 返回：已失败时固定拒绝，否则保留响应并附加失败观察器。
    pub(crate) fn protect(self: &Arc<Self>, response: Response<BoxBody>) -> Response<BoxBody> {
        if let Some(error) = self.failure() {
            return text_status(error.status().as_u16(), error.message());
        }
        response.map(|inner| body::ResponseGuard::new(inner, self.clone()).boxed())
    }
}

/// 业务作用：在认证后安装解码正文，未编码路径不读取输入也不申请资源。
///
/// 参数说明：
/// - `policy`：匹配路由冻结的策略。
/// - `parts`：认证后请求头，成功时就地移除旧实体元数据。
/// - `body`：待消费的正文所有权。
/// - `state`：供主响应管线观察本次解码失败的槽。
///
/// 返回：无拒绝时正文按需解码；格式、协议或资源门失败时返回本地响应。
pub(crate) fn install(
    policy: &Policy,
    parts: &mut Parts,
    body: &mut Option<BoxBody>,
    state: &mut Option<Arc<State>>,
) -> Option<Response<BoxBody>> {
    let coding = match coding(&parts.headers, policy) {
        Ok(None) => return None,
        Ok(Some(coding)) => coding,
        Err(error) => return Some(rejection(error, policy)),
    };
    // 隧道和 RPC 有自己的封装边界；禁止先去除编码再由专用解析器猜测内容。
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if parts.method == Method::CONNECT
        || parts.headers.contains_key(header::UPGRADE)
        || parts.headers.contains_key(header::CONTENT_RANGE)
        || parts.headers.contains_key("connect-protocol-version")
        || content_type
            .get(..16)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/grpc"))
        || content_type
            .get(..20)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/connect+"))
        || crate::io::compression::cache_control_forbids_transform(&parts.headers)
    {
        return Some(rejection(Rejected::Unsupported, policy));
    }
    if parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.parse::<u64>().ok())
        .is_some_and(|length| length > policy.encoded)
    {
        return Some(rejection(Rejected::Limit, policy));
    }
    let trailers = match trailer_declaration(&parts.headers) {
        Ok(value) => value,
        Err(error) => return Some(rejection(error, policy)),
    };
    let input = body
        .take()
        .unwrap_or_else(|| crate::full_body(bytes::Bytes::new()));
    let marker = Arc::new(State::default());
    match body::Decoded::new(input, coding, policy.clone(), marker.clone()) {
        Ok(decoded) => {
            // 原摘要与 framing 属于编码实体；保留会导致截断、验签歧义或错误完整性承诺。
            strip_representation(&mut parts.headers);
            if let Some(value) = trailers {
                parts.headers.insert(header::TRAILER, value);
            }
            parts.extensions.insert(marker.clone());
            *state = Some(marker);
            *body = Some(decoded.boxed());
            None
        }
        Err(error) => Some(rejection(error, policy)),
    }
}

/// 业务作用：严格识别唯一编码，拒绝多层或歧义编码绕过明文正文检查。
///
/// 参数说明：
/// - `headers`：客户端原始实体头。
/// - `policy`：本路由允许的编码集合。
///
/// 返回：单层支持编码、未编码，或415拒绝。
fn coding(headers: &HeaderMap, policy: &Policy) -> Result<Option<ContentCoding>, Rejected> {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Rejected::Unsupported);
    }
    let raw = value.to_str().map_err(|_| Rejected::Unsupported)?.trim();
    if raw.eq_ignore_ascii_case("identity") {
        Ok(None)
    } else if policy.gzip
        && (raw.eq_ignore_ascii_case("gzip") || raw.eq_ignore_ascii_case("x-gzip"))
    {
        Ok(Some(ContentCoding::Gzip))
    } else if policy.brotli && raw.eq_ignore_ascii_case("br") {
        Ok(Some(ContentCoding::Brotli))
    } else {
        Err(Rejected::Unsupported)
    }
}

/// 业务作用：删除变换前实体字段与旧 trailer 声明，避免对解码表示作错误完整性承诺。
///
/// 参数说明：
/// - `headers`：请求头或最终 trailers。
///
/// 返回：原地移除实体编码、长度与摘要；业务字段保留。
fn strip_representation(headers: &mut HeaderMap) {
    for name in [
        "content-encoding",
        "content-length",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "trailer",
    ] {
        headers.remove(name);
    }
}

/// 业务作用：识别解码后失效的实体字段，供头部与trailer声明使用同一规则。
///
/// 参数说明：
/// - `name`：已规范化的小写字段名。
///
/// 返回：该字段是否必须从变换后的表示中移除。
fn representation_field(name: &str) -> bool {
    matches!(
        name,
        "content-encoding"
            | "content-length"
            | "content-md5"
            | "digest"
            | "content-digest"
            | "repr-digest"
            | "trailer"
    )
}

/// 业务作用：限制trailer只能携带业务尾部元数据，不能重新决定身份、路由或HTTP framing。
///
/// 参数说明：
/// - `name`：已规范化的小写字段名。
///
/// 返回：该名称是否不能出现在解码后的trailer中。
fn forbidden_trailer(name: &str) -> bool {
    name.starts_with("content-")
        || name.starts_with("x-forwarded-")
        || name.starts_with("x-original-")
        || matches!(
            name,
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "host"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "te"
                | "upgrade"
                | "x-request-id"
        )
}

/// 业务作用：重建安全的trailer声明，使HTTP/1编码器仍可发送解码后的合法尾部字段。
///
/// 参数说明：
/// - `headers`：原始请求头；没有Trailer时不分配声明缓冲。
///
/// 返回：仅包含合法业务字段的声明，空声明为None；歧义或身份字段拒绝400。
fn trailer_declaration(headers: &HeaderMap) -> Result<Option<HeaderValue>, Rejected> {
    let mut output = String::new();
    let mut count = 0;
    for value in headers.get_all(header::TRAILER) {
        for raw in value.to_str().map_err(|_| Rejected::Malformed)?.split(',') {
            count += 1;
            if count > 64 || raw.len() > 1024 {
                return Err(Rejected::Malformed);
            }
            let name = http::HeaderName::from_bytes(raw.trim().as_bytes())
                .map_err(|_| Rejected::Malformed)?;
            if representation_field(name.as_str()) {
                continue;
            }
            if forbidden_trailer(name.as_str()) {
                return Err(Rejected::Malformed);
            }
            if !output.is_empty() {
                output.push_str(", ");
            }
            output.push_str(name.as_str());
            if output.len() > 32 << 10 {
                return Err(Rejected::Malformed);
            }
        }
    }
    if output.is_empty() {
        Ok(None)
    } else {
        HeaderValue::from_str(&output)
            .map(Some)
            .map_err(|_| Rejected::Malformed)
    }
}

/// 业务作用：生成编码协商拒绝，明确此路由当前接受的请求编码。
///
/// 参数说明：
/// - `error`：本次拒绝类别。
/// - `policy`：当前允许的算法。
///
/// 返回：固定错误响应；415包含Accept-Encoding提示。
fn rejection(error: Rejected, policy: &Policy) -> Response<BoxBody> {
    metrics::EVENTS[error as usize].fetch_add(1, Ordering::Relaxed);
    let mut response = text_status(error.status().as_u16(), error.message());
    if error == Rejected::Unsupported {
        response.headers_mut().insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static(match (policy.gzip, policy.brotli) {
                (true, true) => "gzip, br",
                (true, false) => "gzip",
                _ => "br",
            }),
        );
    }
    response
}
