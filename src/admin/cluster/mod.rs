//! 集群管理共享成员解析与权威边界，领域页面不能自行推断远端操作权限。

pub(super) mod baseline;
pub(super) mod directory;
pub(super) mod discovery;
pub(crate) mod facts;
mod overview;
pub(super) mod transport;

pub(super) use overview::current;
pub(super) use overview::Coverage;
pub(super) use overview::{read, start, Runtime};

/// 业务作用：把当前集群事实按禁止缓存的固定响应合同发布给授权读取方。
///
/// 参数说明：
/// - `status`：当前结果或尚未形成事实的状态。
/// - `body`：同一配置代内预编码的有界实体。
/// - `age`：当前实体的实际单调年龄，单位毫秒。
///
/// 返回：共享Bytes响应，不重复序列化、不允许浏览器缓存旧管理状态。
fn response(
    status: http::StatusCode,
    body: bytes::Bytes,
    age: u64,
) -> http::Response<crate::BoxBody> {
    http::Response::builder()
        .status(status)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-naway-sample-age-ms", age.to_string())
        .body(crate::full_body(body))
        .expect("fixed cluster response headers")
}
