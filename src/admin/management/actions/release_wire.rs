//! 独立释放消息不承载 NASA 效果或候选正文，关闭确认必须逐字段绑定原声明。

use super::fields;
use crate::{
    admin::management::protocol,
    control::actions::release::{Release, Terminal},
};
use nasa::grpc::Status;
#[cfg(feature = "admin-operations-workflow-pgsql")]
use nasa::saga::WorkflowDefinition;

/// 业务作用：将已签名的终态释放直接移动到独立类型化消息，保持与业务命令的协议隔离。
///
/// 参数说明：
/// - release：已取得当前授权和共享安全终态的释放声明。
/// - signature：同次独立域签名。
/// - definition：本机冻结的原工作流。
///
/// 返回：完整有界消息；非法合同和签名长度拒绝，接收端仍须验真。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode(
    release: Release,
    signature: String,
    definition: &WorkflowDefinition,
) -> Result<protocol::ReleaseOffer, Status> {
    release
        .validate(definition)
        .map_err(|_| Status::invalid_argument("invalid node release contract"))?;
    if signature.len() != 88 {
        return Err(Status::invalid_argument("invalid node release proof"));
    }
    Ok(protocol::ReleaseOffer {
        schema: release.schema,
        intent: Some(fields::encode_intent(release.intent)),
        definition_digest: release.definition_digest,
        terminal: match release.terminal {
            Terminal::Completed => protocol::ReleaseTerminal::Completed,
            Terminal::Compensated => protocol::ReleaseTerminal::Compensated,
        } as i32,
        delivery: Some(fields::encode_delivery(release.delivery)),
        signature,
    })
}

/// 业务作用：封闭释放协议和整体终态枚举，未知版本不能获得关闭节点代际的资格。
///
/// 参数说明：
/// - offer：已经受管理消息大小限制、尚未授信的释放消息。
///
/// 返回：待验真的完整声明和原签名；缺失字段或未知终态拒绝。
pub(super) fn decode(offer: protocol::ReleaseOffer) -> Result<(Release, String), Status> {
    if offer.schema != 1 || offer.signature.len() != 88 {
        return Err(Status::invalid_argument("invalid node release offer"));
    }
    let terminal = match protocol::ReleaseTerminal::try_from(offer.terminal) {
        Ok(protocol::ReleaseTerminal::Completed) => Terminal::Completed,
        Ok(protocol::ReleaseTerminal::Compensated) => Terminal::Compensated,
        _ => return Err(Status::invalid_argument("invalid node release terminal")),
    };
    let intent = offer
        .intent
        .ok_or_else(|| Status::invalid_argument("missing node release intent"))?;
    let delivery = offer
        .delivery
        .ok_or_else(|| Status::invalid_argument("missing node release delivery"))?;
    Ok((
        Release {
            schema: offer.schema,
            intent: fields::decode_intent(intent)?,
            definition_digest: offer.definition_digest,
            terminal,
            delivery: fields::decode_delivery(delivery)?,
        },
        offer.signature,
    ))
}
