//! 材料命令与清理在固定消息预算内直接转换，独立签名域仍由原生合同决定。

use super::fields;
use crate::{
    admin::management::{actions::fields as common, protocol, MAX_MESSAGE},
    control::material::execution::{
        command::Command,
        release::{Release, Terminal},
    },
};
use nasa::{
    grpc::{codegen::prost::Message, Status},
    saga::StepPhase,
};
use nasaga_runtime_core::SagaCommandEnvelope;

/// 业务作用：接收完整材料命令而不借配置动作的意图或工作流，任何未知phase均失败闭合。
///
/// 参数说明：
/// - `value`：本连接收到的有界材料offer。
///
/// 返回：完成原生合同校验的未验签命令与原签名；无效或超量不进入节点许可门。
pub(super) fn decode(value: protocol::MaterialActionOffer) -> Result<(Command, String), Status> {
    require_offer(value.schema, &value.signature, value.encoded_len())?;
    let command = Command {
        schema: value.schema,
        envelope: decode_identity(
            value
                .identity
                .ok_or_else(|| Status::invalid_argument("material identity absent"))?,
        )?,
        intent: fields::decode_intent(
            value
                .intent
                .ok_or_else(|| Status::invalid_argument("material intent absent"))?,
        )?,
        position: fields::decode_position(value.position)?,
        delivery: common::decode_delivery(
            value
                .delivery
                .ok_or_else(|| Status::invalid_argument("material delivery absent"))?,
        )?,
    };
    command
        .validate()
        .map_err(|_| Status::invalid_argument("material command contract differs"))?;
    Ok((command, value.signature))
}

/// 业务作用：只在远程发送时编码原材料命令，当前接收者、完整意图与独立物理分母全部保留。
///
/// 参数说明：
/// - `command`：当前已获授权并签名的共享原命令。
/// - `signature`：完整独立材料域证明。
///
/// 返回：现有32KiB管理预算内的完整offer；超量整批拒绝，不截断来源或缩减影响。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode(
    command: &Command,
    signature: &str,
) -> Result<protocol::MaterialActionOffer, Status> {
    command
        .validate()
        .map_err(|_| Status::invalid_argument("material command contract differs"))?;
    let value = protocol::MaterialActionOffer {
        schema: command.schema,
        identity: Some(encode_identity(&command.envelope)?),
        intent: Some(fields::encode_intent(&command.intent)?),
        position: Some(protocol::MaterialActionPosition {
            index: command.position.index,
            count: command.position.count,
        }),
        delivery: Some(common::encode_delivery(command.delivery.clone())),
        signature: signature.into(),
    };
    require_offer(value.schema, &value.signature, value.encoded_len())?;
    Ok(value)
}

/// 业务作用：解码独立材料终态释放，未知终态或缺失完整意图不能取得秘密清理权。
///
/// 参数说明：
/// - `value`：受同一管理预算约束的释放offer。
///
/// 返回：待当前会话验签的完整原生释放；格式或合同不符拒绝。
pub(super) fn decode_release(
    value: protocol::MaterialReleaseOffer,
) -> Result<(Release, String), Status> {
    require_offer(value.schema, &value.signature, value.encoded_len())?;
    let terminal = match protocol::ReleaseTerminal::try_from(value.terminal) {
        Ok(protocol::ReleaseTerminal::Completed) => Terminal::Completed,
        Ok(protocol::ReleaseTerminal::Compensated) => Terminal::Compensated,
        _ => return Err(Status::invalid_argument("material terminal differs")),
    };
    let release = Release {
        schema: value.schema,
        intent: fields::decode_intent(
            value
                .intent
                .ok_or_else(|| Status::invalid_argument("material release intent absent"))?,
        )?,
        position: fields::decode_position(value.position)?,
        definition_digest: value.definition_digest,
        terminal,
        delivery: common::decode_delivery(
            value
                .delivery
                .ok_or_else(|| Status::invalid_argument("material release delivery absent"))?,
        )?,
    };
    release
        .validate()
        .map_err(|_| Status::invalid_argument("material release contract differs"))?;
    Ok((release, value.signature))
}

/// 业务作用：仅在网络边界编码共享终态释放，保持原节点完整批准和独立清理签名不可分离。
///
/// 参数说明：
/// - `release`：当前共享终态和租约已经允许的原释放。
/// - `signature`：独立材料清理域的证明。
///
/// 返回：完整有限offer；非法或超量拒绝，不复用配置释放字段容器。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode_release(
    release: &Release,
    signature: &str,
) -> Result<protocol::MaterialReleaseOffer, Status> {
    release
        .validate()
        .map_err(|_| Status::invalid_argument("material release contract differs"))?;
    let value = protocol::MaterialReleaseOffer {
        schema: release.schema,
        intent: Some(fields::encode_intent(&release.intent)?),
        position: Some(protocol::MaterialActionPosition {
            index: release.position.index,
            count: release.position.count,
        }),
        definition_digest: release.definition_digest.clone(),
        terminal: match release.terminal {
            Terminal::Completed => protocol::ReleaseTerminal::Completed,
            Terminal::Compensated => protocol::ReleaseTerminal::Compensated,
        } as i32,
        delivery: Some(common::encode_delivery(release.delivery.clone())),
        signature: signature.into(),
    };
    require_offer(value.schema, &value.signature, value.encoded_len())?;
    Ok(value)
}

/// 业务作用：把类型化NASA身份移入原生信封，不添加payload或合成另一请求的身份。
///
/// 参数说明：
/// - `value`：原消息中明确携带的业务或查询身份。
///
/// 返回：待原生定义复验的原信封；未知或取消phase拒绝。
pub(super) fn decode_identity(
    value: protocol::ActionIdentity,
) -> Result<SagaCommandEnvelope, Status> {
    let phase = match protocol::ActionPhase::try_from(value.phase) {
        Ok(protocol::ActionPhase::Execute) => StepPhase::Execute,
        Ok(protocol::ActionPhase::Resolve) => StepPhase::Resolve,
        Ok(protocol::ActionPhase::Compensate) => StepPhase::Compensate,
        _ => return Err(Status::invalid_argument("material phase differs")),
    };
    Ok(SagaCommandEnvelope {
        saga_id: value.saga_id,
        tenant_id: value.tenant_id,
        workflow: value.workflow,
        definition_version: value.definition_version,
        definition_digest: value.definition_digest,
        step: value.step,
        phase: phase.as_str().into(),
        attempt: value.attempt,
        effect_id: value.effect_id,
        command_id: value.command_id,
        recovery_operation_id: value.recovery_operation_id,
        payload: None,
        raw_payload: None,
    })
}

/// 业务作用：将原NASA身份只在边界投影为协议字段，命令与效果摘要不会被重新派生覆盖。
///
/// 参数说明：
/// - `value`：已经通过独立定义验证的原信封。
///
/// 返回：保留原attempt与恢复身份的完整字段；未知phase拒绝。
pub(super) fn encode_identity(
    value: &SagaCommandEnvelope,
) -> Result<protocol::ActionIdentity, Status> {
    let phase = match StepPhase::parse(&value.phase) {
        Some(StepPhase::Execute) => protocol::ActionPhase::Execute,
        Some(StepPhase::Resolve) => protocol::ActionPhase::Resolve,
        Some(StepPhase::Compensate) => protocol::ActionPhase::Compensate,
        _ => return Err(Status::invalid_argument("material phase differs")),
    };
    Ok(protocol::ActionIdentity {
        saga_id: value.saga_id.clone(),
        tenant_id: value.tenant_id.clone(),
        workflow: value.workflow.clone(),
        definition_version: value.definition_version,
        definition_digest: value.definition_digest.clone(),
        step: value.step.clone(),
        phase: phase as i32,
        attempt: value.attempt,
        effect_id: value.effect_id.clone(),
        command_id: value.command_id.clone(),
        recovery_operation_id: value.recovery_operation_id.clone(),
    })
}

/// 业务作用：同一收发预算在分配工作之前拒绝超量或无完整证明的消息，未知协议默认值不能取得能力。
///
/// 参数说明：
/// - `schema`：外层协议标识。
/// - `signature`：原Ed25519证明文本。
/// - `bytes`：整个消息实际protobuf长度。
///
/// 返回：协议、签名长度及完整32KiB预算同时成立才成功，不证明签名真实性。
fn require_offer(schema: u32, signature: &str, bytes: usize) -> Result<(), Status> {
    if schema != 1 || signature.len() != 88 {
        return Err(Status::invalid_argument("material offer contract differs"));
    }
    if bytes > MAX_MESSAGE {
        return Err(Status::resource_exhausted("material offer capacity"));
    }
    Ok(())
}
