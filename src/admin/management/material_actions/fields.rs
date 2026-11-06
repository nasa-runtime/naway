//! 两份原批准、完整来源与物理位置直接进入类型化字段，不借预检意图或JSON封装。

use crate::{
    admin::management::{actions::fields::fixed, material::wire, protocol},
    control::{
        baseline::NodeBaseline,
        material::{
            execution::position::Position,
            node::{Intent, Selection},
        },
    },
};
use nasa::grpc::Status;
use std::sync::Arc;

/// 业务作用：恢复完整原批准与来源分母，任何缺失字段均不能从当前在线目录补齐。
///
/// 参数说明：
/// - `value`：受管理消息总上限约束、尚未验签的原字段。
///
/// 返回：通过原生完整合同的共享意图；非法摘要、基线、原索引或来源拒绝。
pub(super) fn decode_intent(value: protocol::MaterialActionIntent) -> Result<Arc<Intent>, Status> {
    let baseline = value
        .baseline
        .ok_or_else(|| invalid("material baseline absent"))?;
    if baseline.schema != 1 {
        return Err(invalid("material baseline schema differs"));
    }
    let selections = value
        .selections
        .into_iter()
        .map(|selection| {
            Ok(Selection {
                index: selection.index,
                target: wire::native_target(selection.target)
                    .map_err(|_| invalid("material target differs"))?,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let conditions = wire::decode_fields(
        value
            .conditions
            .ok_or_else(|| invalid("material conditions absent"))?,
        selections.iter().map(|selection| selection.index),
    )
    .map_err(|_| invalid("material conditions differ"))?;
    let intent = Intent {
        schema: value.schema,
        operation_id: value.operation_id,
        execution_store: value.execution_store,
        proposal_id: value.proposal_id,
        material_store: value.material_store,
        material_epoch: value.material_epoch,
        impact_id: value.impact_id,
        impact_store: value.impact_store,
        impact_epoch: value.impact_epoch,
        material_creator: value.material_creator,
        material_reviewer: value.material_reviewer,
        impact_creator: value.impact_creator,
        impact_reviewer: value.impact_reviewer,
        scope: value.scope,
        material_intent_sha256: fixed(value.material_intent_sha256)?,
        impact_sha256: fixed(value.impact_sha256)?,
        authority_sha256: fixed(value.authority_sha256)?,
        impact_authority_sha256: fixed(value.impact_authority_sha256)?,
        target_count: value.target_count,
        node_id: value.node_id,
        original_boot_id: value.original_boot_id,
        baseline: NodeBaseline::from_parts(
            baseline.cluster_id,
            baseline.store_id,
            baseline.node_admission_epoch,
            &fixed(baseline.documents_sha256)?,
        ),
        base_version: value.base_version,
        base_fingerprint: value.base_fingerprint,
        candidate_bytes: value.candidate_bytes,
        candidate_sha256: fixed(value.candidate_sha256)?,
        selections: selections.into(),
        conditions,
    };
    intent
        .fingerprint()
        .map_err(|_| invalid("material intent contract differs"))?;
    Ok(Arc::new(intent))
}

/// 业务作用：在实际发送边界编码共享意图，进程内投递保持原Arc而不预存另一份协议树。
///
/// 参数说明：
/// - `intent`：已由原命令合同完整验证的节点意图。
///
/// 返回：只含原逻辑身份与批准摘要的类型化字段；无法表达完整条件时拒绝，不复制秘密。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode_intent(intent: &Intent) -> Result<protocol::MaterialActionIntent, Status> {
    Ok(protocol::MaterialActionIntent {
        schema: intent.schema,
        operation_id: intent.operation_id.clone(),
        execution_store: intent.execution_store.clone(),
        proposal_id: intent.proposal_id.clone(),
        material_store: intent.material_store.clone(),
        material_epoch: intent.material_epoch,
        impact_id: intent.impact_id.clone(),
        impact_store: intent.impact_store.clone(),
        impact_epoch: intent.impact_epoch,
        material_creator: intent.material_creator.clone(),
        material_reviewer: intent.material_reviewer.clone(),
        impact_creator: intent.impact_creator.clone(),
        impact_reviewer: intent.impact_reviewer.clone(),
        scope: intent.scope.clone(),
        material_intent_sha256: intent.material_intent_sha256.to_vec(),
        impact_sha256: intent.impact_sha256.to_vec(),
        authority_sha256: intent.authority_sha256.to_vec(),
        impact_authority_sha256: intent.impact_authority_sha256.to_vec(),
        target_count: intent.target_count,
        node_id: intent.node_id.clone(),
        original_boot_id: intent.original_boot_id.clone(),
        baseline: Some(
            crate::admin::management::baseline::encode(&intent.baseline)
                .ok_or_else(|| invalid("material baseline differs"))?,
        ),
        base_version: intent.base_version,
        base_fingerprint: intent.base_fingerprint,
        candidate_bytes: intent.candidate_bytes,
        candidate_sha256: intent.candidate_sha256.to_vec(),
        selections: intent
            .selections
            .iter()
            .map(|selection| protocol::MaterialConditionsTarget {
                index: selection.index,
                target: Some(wire::target(selection.target.clone())),
            })
            .collect(),
        conditions: Some(
            wire::encode_fields(
                &intent.conditions,
                intent.selections.iter().map(|selection| selection.index),
            )
            .map_err(|_| Status::resource_exhausted("material conditions capacity"))?,
        ),
    })
}

/// 业务作用：保持物理节点位置和总数独立于逻辑目标索引，缺失位置不能被当作首节点。
///
/// 参数说明：
/// - `value`：原消息的位置字段。
///
/// 返回：待原意图完整校验的位置；缺字段拒绝，不采样当前成员目录。
pub(super) fn decode_position(
    value: Option<protocol::MaterialActionPosition>,
) -> Result<Position, Status> {
    let value = value.ok_or_else(|| invalid("material physical position absent"))?;
    Ok(Position {
        index: value.index,
        count: value.count,
    })
}

/// 业务作用：只输出有限合同错误，不向管理连接泄露底层材料或部署位置。
///
/// 参数说明：
/// - `message`：代码内固定的低敏拒绝文本。
///
/// 返回：明确的无效参数状态，不包含来源错误链。
fn invalid(message: &'static str) -> Status {
    Status::invalid_argument(message)
}
