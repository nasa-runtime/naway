//! 动作身份在 protobuf 与中性合同之间直接转换，正文保持独立原始字节。

use super::fields;
use crate::admin::management::protocol;
use crate::control::actions::command::Command;
#[cfg(feature = "admin-operations-workflow-pgsql")]
use nasa::saga::WorkflowDefinition;
use nasa::{grpc::Status, saga::StepPhase};
use nasaga_runtime_core::SagaCommandEnvelope;

/// 业务作用：将完整内部命令移动到类型化 offer，拒绝不满足固定定义的内部声明。
///
/// 参数说明：
/// - `command`：已取得当前业务授权且使用独立动作域签名的命令。
/// - `signature`：同次签名结果，不携带密钥或用户凭据。
/// - `definition`：本机冻结的工作流，不能由命令内容构造。
///
/// 返回：合法命令的有界消息；合同不符不产生可交付 offer，签名真实性仍由接收端校验。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode(
    command: Command,
    signature: String,
    definition: &WorkflowDefinition,
) -> Result<protocol::ActionOffer, Status> {
    let checked = command
        .validate(definition)
        .map_err(|_| Status::invalid_argument("invalid node command contract"))?;
    if signature.len() != 88 {
        return Err(Status::invalid_argument("invalid node command proof"));
    }
    let phase = match checked.identity().phase {
        StepPhase::Execute => protocol::ActionPhase::Execute,
        StepPhase::Resolve => protocol::ActionPhase::Resolve,
        StepPhase::Compensate => protocol::ActionPhase::Compensate,
        StepPhase::Cancel => {
            return Err(Status::invalid_argument("node cancel command unsupported"))
        }
    };
    let Command {
        schema,
        envelope,
        intent,
        delivery,
    } = command;
    Ok(protocol::ActionOffer {
        schema,
        identity: Some(protocol::ActionIdentity {
            saga_id: envelope.saga_id,
            tenant_id: envelope.tenant_id,
            workflow: envelope.workflow,
            definition_version: envelope.definition_version,
            definition_digest: envelope.definition_digest,
            step: envelope.step,
            phase: phase as i32,
            attempt: envelope.attempt,
            effect_id: envelope.effect_id,
            command_id: envelope.command_id,
            recovery_operation_id: envelope.recovery_operation_id,
        }),
        intent: Some(fields::encode_intent(intent)),
        delivery: Some(fields::encode_delivery(delivery)),
        signature,
    })
}

/// 业务作用：在验签前拆解有界 offer，拒绝未知枚举、缺失字段或摘要长度歧义。
///
/// 参数说明：
/// - `offer`：已经受管理消息上限约束、尚未授信的完整类型化消息。
///
/// 返回：待复验的命令与原签名；仅完成字段转换，不授予文件、查询或正文下载权限。
pub(super) fn decode(offer: protocol::ActionOffer) -> Result<(Command, String), Status> {
    if offer.schema != 1 || offer.signature.len() != 88 {
        return Err(Status::invalid_argument("invalid node command offer"));
    }
    let identity = offer
        .identity
        .ok_or_else(|| Status::invalid_argument("missing node command identity"))?;
    let intent = offer
        .intent
        .ok_or_else(|| Status::invalid_argument("missing node command intent"))?;
    let delivery = offer
        .delivery
        .ok_or_else(|| Status::invalid_argument("missing node command delivery"))?;
    let phase = match protocol::ActionPhase::try_from(identity.phase) {
        Ok(protocol::ActionPhase::Execute) => StepPhase::Execute,
        Ok(protocol::ActionPhase::Resolve) => StepPhase::Resolve,
        Ok(protocol::ActionPhase::Compensate) => StepPhase::Compensate,
        _ => return Err(Status::invalid_argument("invalid node command phase")),
    };
    Ok((
        Command {
            schema: offer.schema,
            envelope: SagaCommandEnvelope {
                saga_id: identity.saga_id,
                tenant_id: identity.tenant_id,
                workflow: identity.workflow,
                definition_version: identity.definition_version,
                definition_digest: identity.definition_digest,
                step: identity.step,
                phase: phase.as_str().into(),
                attempt: identity.attempt,
                effect_id: identity.effect_id,
                command_id: identity.command_id,
                recovery_operation_id: identity.recovery_operation_id,
                payload: None,
                raw_payload: None,
            },
            intent: fields::decode_intent(intent)?,
            delivery: fields::decode_delivery(delivery)?,
        },
        offer.signature,
    ))
}
