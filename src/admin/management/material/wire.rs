//! 传输边界只转换原生有界字段，不把材料条件嵌套为 JSON。

mod batch;
mod offer;
pub(super) use batch::{decode_batch, encode_batch, validate};
pub(super) use offer::{decode, encode};

use super::Reason;
use crate::{
    admin::management::protocol,
    tls::targets::{Kind, Target},
};

/// 业务作用：在网络发送边界移动逻辑目标的字符串，不保留第二份来源文档。
///
/// 参数说明：
/// - `target`：已经验证的逻辑身份。
///
/// 返回：不含文件路径的原生 protobuf 身份。
fn target(target: Target) -> protocol::MaterialTarget {
    protocol::MaterialTarget {
        kind: match target.kind {
            Kind::Proxy => protocol::material_target::Kind::Proxy,
            Kind::Stream => protocol::material_target::Kind::Stream,
        } as i32,
        listener: target.listener,
        entry: target.entry,
    }
}

/// 业务作用：拒绝缺失或未知目标种类，协议默认值不能冒充默认监听身份。
///
/// 参数说明：
/// - `value`：传输中的完整目标字段。
///
/// 返回：合法逻辑身份；非法种类、名字或条目拒绝。
fn native_target(value: Option<protocol::MaterialTarget>) -> Result<Target, Reason> {
    let value = value.ok_or(Reason::Denied)?;
    let target = Target {
        kind: match protocol::material_target::Kind::try_from(value.kind) {
            Ok(protocol::material_target::Kind::Proxy) => Kind::Proxy,
            Ok(protocol::material_target::Kind::Stream) => Kind::Stream,
            _ => return Err(Reason::Denied),
        },
        listener: value.listener,
        entry: value.entry,
    };
    if !target.valid() {
        return Err(Reason::Denied);
    }
    Ok(target)
}

/// 业务作用：只传播明确的低敏失败，成功必须另行携带完整材料批次。
///
/// 参数说明：
/// - `reason`：当前节点确认的拒绝原因。
///
/// 返回：固定协议枚举，不包含底层错误链。
pub(super) fn status(reason: Reason) -> protocol::MaterialConditionsStatus {
    use protocol::MaterialConditionsStatus as Status;
    match reason {
        Reason::Unsupported => Status::Unsupported,
        Reason::Disabled => Status::Disabled,
        Reason::Unavailable => Status::Unavailable,
        Reason::Capacity => Status::Capacity,
        Reason::Expired => Status::Expired,
        Reason::Denied => Status::Denied,
        Reason::BaselineChanged => Status::BaselineChanged,
        Reason::TargetAbsent => Status::TargetAbsent,
        Reason::ExternalSource => Status::ExternalSource,
        Reason::Storage => Status::Storage,
        Reason::ImpactUnproven => Status::ImpactUnproven,
    }
}

/// 业务作用：未知状态不能被降格成成功或空来源，跨协议变化必须明确失败。
///
/// 参数说明：
/// - `value`：原结果的状态值。
///
/// 返回：已知失败枚举；未知值和成功值均不由失败路径接受。
pub(super) fn reason(value: i32) -> Option<Reason> {
    use protocol::MaterialConditionsStatus as Status;
    Some(match Status::try_from(value).ok()? {
        Status::Unsupported => Reason::Unsupported,
        Status::Disabled => Reason::Disabled,
        Status::Unavailable => Reason::Unavailable,
        Status::Capacity => Reason::Capacity,
        Status::Expired => Reason::Expired,
        Status::Denied => Reason::Denied,
        Status::BaselineChanged => Reason::BaselineChanged,
        Status::TargetAbsent => Reason::TargetAbsent,
        Status::ExternalSource => Reason::ExternalSource,
        Status::Storage => Reason::Storage,
        Status::ImpactUnproven => Reason::ImpactUnproven,
        Status::Unspecified | Status::Succeeded => return None,
    })
}
