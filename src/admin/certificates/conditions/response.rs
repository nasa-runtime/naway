//! HTTP 边界借用原生批次一次编码，结果不包含会话令牌、路径或可重放执行身份。

use super::Observed;
use crate::{
    admin::{self, BoxBody, management::material::Reason},
    tls::{keypair::conditions::Batch, targets::Target},
};
use http::{Response, StatusCode};
use serde::Serialize;

#[derive(Serialize)]
struct Node<'a> {
    node_id: &'a str,
    boot_id: &'a str,
    base_version: u64,
    base_fingerprint: String,
    node_baseline: &'a crate::control::baseline::NodeBaseline,
    indices: &'a [u32],
    targets: &'a [Target],
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conditions: Option<&'a Batch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installations: Option<&'a crate::control::material::installation::Batch>,
}

#[derive(Serialize)]
struct View<'a> {
    query_id: &'a str,
    scope: &'a str,
    target_count: usize,
    complete_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_count: Option<usize>,
    nodes: Vec<Node<'a>>,
    execution_supported: bool,
}

/// 业务作用：保留全部原目标及失败分母，区分观察完整与全部共享协议已安装，不形成持久收据或审批结论。
///
/// 参数说明：
/// - `query`：本次只读查询随机身份。
/// - `scope`：本次当前授权的唯一范围。
/// - `observed`：已复验原节点基线的全部结果，包含缺席及明确拒绝。
///
/// 返回：有界 no-store JSON；容量或编码失败不输出部分响应。
pub(super) fn encode(query: &str, scope: &str, observed: &[Observed]) -> Response<BoxBody> {
    let view = View {
        query_id: query,
        scope,
        target_count: observed
            .iter()
            .map(|value| value.intent.targets.len())
            .sum(),
        complete_count: observed
            .iter()
            .filter(|value| value.result.is_ok())
            .map(|value| value.intent.targets.len())
            .sum(),
        installed_count: observed
            .first()
            .filter(|value| {
                value.intent.query_kind
                    == crate::admin::management::material::command::Query::Installations
            })
            .map(|_| {
                observed
                    .iter()
                    .filter_map(|value| value.result.as_ref().ok())
                    .map(|value| {
                        value.installations.as_ref().map_or(0, |installations| {
                            value
                                .batch
                                .entries
                                .iter()
                                .filter(|entry| installations.current(entry.group))
                                .count()
                        })
                    })
                    .sum()
            }),
        nodes: observed
            .iter()
            .map(|value| Node {
                node_id: &value.intent.node,
                boot_id: &value.intent.boot,
                base_version: value.intent.version,
                base_fingerprint: format!("{:016x}", value.intent.fingerprint),
                node_baseline: &value.intent.baseline,
                indices: &value.intent.indices,
                targets: &value.intent.targets,
                status: if value.result.is_ok() {
                    "complete"
                } else {
                    "unavailable"
                },
                reason: value.result.as_ref().err().copied(),
                conditions: value.result.as_ref().ok().map(|value| &value.batch),
                installations: value
                    .result
                    .as_ref()
                    .ok()
                    .and_then(|value| value.installations.as_ref()),
            })
            .collect(),
        execution_supported: false,
    };
    let mut buffer = admin::catalog::read::Buffer(Vec::with_capacity(8192));
    if serde_json::to_writer(&mut buffer, &view).is_err() {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "material_conditions_response_capacity",
        );
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(admin::full_body(buffer.0.into()))
        .expect("material conditions response")
}

/// 业务作用：仅返回固定失败原因，输入、存储与证书诊断不能出现在管理响应中。
///
/// 参数说明：
/// - `status`：已分类的 HTTP 拒绝状态。
/// - `code`：代码定义的固定错误标识。
///
/// 返回：带 no-store 的有限 JSON，不声明任何执行能力。
pub(super) fn failure(status: StatusCode, code: &'static str) -> Response<BoxBody> {
    let mut response = admin::json(
        status,
        serde_json::json!({
            "error": code,
            "execution_supported": false
        }),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
