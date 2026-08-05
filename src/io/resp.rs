//! 网关对下游应答的统一 Body 类型与响应助手(少拷贝:body 用引用计数 `Bytes`)。

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};

/// 统一错误盒子:下游静态响应(Infallible)与上游流(hyper::Error)归一到同一 Body 类型。
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 网关对下游应答统一用的 Body 类型(既能装静态字节,也能装上游流式响应)。
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// 把一段字节包成 `BoxBody`(静态响应用:接口守卫 / 404 / 502 等)。
pub fn full_body(data: Bytes) -> BoxBody {
    Full::new(data).map_err(|never| match never {}).boxed()
}

/// 造一个纯文本状态响应(网关自身产生的短路应答)。
pub fn text_status(code: u16, msg: &str) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(msg.to_owned())))
        .expect("build text response")
}
