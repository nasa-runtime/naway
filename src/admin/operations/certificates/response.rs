//! HTTP 边界借用原生记录直接编码，不构造复制全部目标的 JSON 中间树。

use super::{model::Record, Error};
use crate::admin::{full_body, BoxBody};
use bytes::Bytes;
use http::{Response, StatusCode};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Context<'a> {
    pub cluster_id: &'a str,
    pub scope: &'a str,
    pub admission_epoch: i64,
    pub epoch_expires_at_ms: i64,
    pub epoch_required: bool,
    pub accept_proposals: bool,
    pub access: Access,
    pub capacity: Capacity,
}

#[derive(Serialize)]
pub(super) struct Access {
    pub read: bool,
    pub write: bool,
    pub review: bool,
}

#[derive(Serialize)]
pub(super) struct Capacity {
    pub max_records: u32,
    pub max_records_per_scope: u32,
    pub max_material_bytes: u32,
    pub max_total_bytes: u64,
}

#[derive(Serialize)]
pub(super) struct Single<'a> {
    pub proposal: &'a Record,
}

#[derive(Serialize)]
pub(super) struct Page<'a> {
    pub proposals: &'a [Record],
    pub next_after: Option<&'a str>,
}

#[derive(Serialize)]
struct Envelope<'a, T> {
    #[serde(flatten)]
    value: &'a T,
    execution_supported: bool,
    targets_validated: bool,
    validation: &'static str,
}

/// 业务作用：只在 HTTP 输出边界序列化一次借用投影，并明确受理不代表节点验证或安装。
///
/// 参数说明：
/// - `value`：只含公开字段的原生响应，编码期间保留原记录所有权。
///
/// 返回：完整 JSON 响应或固定不可用；不复制目标树，不交付部分编码或秘密材料。
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Response<BoxBody>, Error> {
    let bytes = serde_json::to_vec(&Envelope {
        value,
        execution_supported: false,
        targets_validated: false,
        validation: "material_pair_only",
    })
    .map_err(|_| Error::Unavailable)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(bytes)))
        .map_err(|_| Error::Unavailable)
}
