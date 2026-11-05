//! HTTP只借用原目标与公开条件编码一次，材料帧及其摘要不进入普通管理响应。

use super::{
    request::{hex, Observed},
    source::Source,
    Context,
};
use crate::{
    admin::{self, management::material_preview::Reason, operations::certificates::Error, BoxBody},
    control::material::{Summary, Target},
    tls::keypair::conditions::Batch,
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome<'a> {
    Succeeded {
        conditions: &'a Batch,
        impact_sha256: String,
    },
    Failed {
        reason: Reason,
    },
}

#[derive(Serialize)]
struct Node<'a> {
    node_id: &'a str,
    target_indices: &'a [u32],
    #[serde(flatten)]
    outcome: Outcome<'a>,
}

#[derive(Serialize)]
struct Response<'a> {
    scope: &'static str,
    cluster_id: &'a str,
    proposal_id: &'a str,
    admission_epoch: String,
    proposal_scope: &'a str,
    validation: &'static str,
    targets_validated: bool,
    execution_supported: bool,
    certificate: &'a Summary,
    issued_at_ms: u64,
    expires_at_ms: u64,
    target_count: usize,
    targets: &'a [Target],
    nodes: Vec<Node<'a>>,
}

/// 业务作用：按完整原分母一次编码低敏预检结果，任一节点失败都不宣称全部目标已验证。
///
/// 参数说明：
/// - `context`：唯一发行集群和当前精确范围。
/// - `id`：原提案身份。
/// - `source`：认证材料的公开摘要和全部原目标，秘密字段不得序列化。
/// - `observed`：每个原节点的完整成功或固定失败。
/// - `issued`：本次签发Unix毫秒。
/// - `expires`：本次不可延长的截止Unix毫秒。
///
/// 返回：私有不可缓存的完整响应；不提供候选下载，也不扩大原批准的执行资格。
pub(super) fn encode(
    context: &Context<'_>,
    id: &str,
    source: &Source,
    observed: &[Observed],
    issued: u64,
    expires: u64,
) -> Result<http::Response<BoxBody>, Error> {
    let response = Response {
        scope: "original_targets",
        cluster_id: &context.store.plan.config.cluster_id,
        proposal_id: id,
        admission_epoch: source.stamp.context.epoch.to_string(),
        proposal_scope: &context.scope.key,
        validation: "original_target_tls_policy",
        targets_validated: !observed.is_empty() && observed.iter().all(|item| item.result.is_ok()),
        execution_supported: false,
        certificate: &source.certificate,
        issued_at_ms: issued,
        expires_at_ms: expires,
        target_count: source.targets.len(),
        targets: &source.targets,
        nodes: observed
            .iter()
            .map(|item| Node {
                node_id: &item.intent.node,
                target_indices: &item.intent.indices,
                outcome: match &item.result {
                    Ok(completed) => Outcome::Succeeded {
                        conditions: &completed.proof.conditions,
                        impact_sha256: hex(&completed.proof.impact),
                    },
                    Err(reason) => Outcome::Failed {
                        reason: *reason,
                    },
                },
            })
            .collect(),
    };
    let mut buffer = admin::catalog::read::Buffer(Vec::with_capacity(8192));
    serde_json::to_writer(&mut buffer, &response).map_err(|_| Error::Capacity)?;
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(admin::full_body(buffer.0.into()))
        .map_err(|_| Error::Unavailable)
}
