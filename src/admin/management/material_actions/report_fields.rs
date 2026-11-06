//! 完整材料结果只接受明确的有限枚举，协议未知值不能退化成缺省成功或未决状态。

use crate::{
    admin::management::protocol,
    control::material::execution::{
        observation::Protocols,
        receipt::Reason,
        release::Terminal,
        state::{Direction, Stage},
    },
};
use nasa::grpc::Status;

/// 业务作用：在结果边界准确表达原材料责任阶段。
///
/// 参数说明：
/// - `value`：已经通过原生阶段合同的有限状态。
///
/// 返回：明确的协议枚举，不包含未指定值。
pub(super) fn stage(value: Stage) -> i32 {
    use protocol::MaterialExecutionStage as Wire;
    (match value {
        Stage::Reserved => Wire::Reserved,
        Stage::Prepared => Wire::Prepared,
        Stage::Invalidated => Wire::Invalidated,
        Stage::Forward => Wire::Forward,
        Stage::Applied => Wire::Applied,
        Stage::Backward => Wire::Backward,
        Stage::Reverted => Wire::Reverted,
        Stage::Rejected => Wire::Rejected,
        Stage::Compensated => Wire::Compensated,
        Stage::Protected => Wire::Protected,
        Stage::Cleaning => Wire::Cleaning,
    }) as i32
}

/// 业务作用：拒绝未定义的材料阶段，结果不能用协议缺省替代原持久事实。
///
/// 参数说明：
/// - `value`：网络阶段整数。
///
/// 返回：明确原生阶段；未知值或未指定值拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn native_stage(value: i32) -> Result<Stage, Status> {
    use protocol::MaterialExecutionStage as Wire;
    Ok(match Wire::try_from(value) {
        Ok(Wire::Reserved) => Stage::Reserved,
        Ok(Wire::Prepared) => Stage::Prepared,
        Ok(Wire::Invalidated) => Stage::Invalidated,
        Ok(Wire::Forward) => Stage::Forward,
        Ok(Wire::Applied) => Stage::Applied,
        Ok(Wire::Backward) => Stage::Backward,
        Ok(Wire::Reverted) => Stage::Reverted,
        Ok(Wire::Rejected) => Stage::Rejected,
        Ok(Wire::Compensated) => Stage::Compensated,
        Ok(Wire::Protected) => Stage::Protected,
        Ok(Wire::Cleaning) => Stage::Cleaning,
        _ => return Err(invalid()),
    })
}

/// 业务作用：保留原决定的文件方向，空方向不代表任何写权。
///
/// 参数说明：
/// - `value`：原报告中可选的全批方向。
///
/// 返回：方向或明确未设置枚举。
pub(super) fn direction(value: Option<Direction>) -> i32 {
    use protocol::MaterialExecutionDirection as Wire;
    (match value {
        None => Wire::Unspecified,
        Some(Direction::Forward) => Wire::Forward,
        Some(Direction::Backward) => Wire::Backward,
    }) as i32
}

/// 业务作用：恢复已决定方向并拒绝未知值，避免将不认识的写入方向当成无责任。
///
/// 参数说明：
/// - `value`：原协议方向整数。
///
/// 返回：已知方向或明确空方向；未知值拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn native_direction(value: i32) -> Result<Option<Direction>, Status> {
    use protocol::MaterialExecutionDirection as Wire;
    Ok(match Wire::try_from(value) {
        Ok(Wire::Unspecified) => None,
        Ok(Wire::Forward) => Some(Direction::Forward),
        Ok(Wire::Backward) => Some(Direction::Backward),
        _ => return Err(invalid()),
    })
}

/// 业务作用：保留原准备冻结的每目标协议集合，不能按当前在线协议数量编码。
///
/// 参数说明：
/// - `value`：原目标要求的完整协议组合。
///
/// 返回：精确组合的有限枚举。
pub(super) fn protocols(value: Protocols) -> i32 {
    use protocol::MaterialExecutionProtocols as Wire;
    (match value {
        Protocols::Https => Wire::Https,
        Protocols::HttpsAndHttp3 => Wire::HttpsAndHttp3,
        Protocols::StreamTls => Wire::StreamTls,
    }) as i32
}

/// 业务作用：拒绝未知或空协议集合，缺席HTTP3不能被简化为HTTPS成功。
///
/// 参数说明：
/// - `value`：原协议组合整数。
///
/// 返回：明确原生组合；未知或未指定值拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn native_protocols(value: i32) -> Result<Protocols, Status> {
    use protocol::MaterialExecutionProtocols as Wire;
    Ok(match Wire::try_from(value) {
        Ok(Wire::Https) => Protocols::Https,
        Ok(Wire::HttpsAndHttp3) => Protocols::HttpsAndHttp3,
        Ok(Wire::StreamTls) => Protocols::StreamTls,
        _ => return Err(invalid()),
    })
}

/// 业务作用：只编码固定低敏原因，底层错误链不能进入共享执行结果。
///
/// 参数说明：
/// - `value`：稳定拒绝或保护事实的原原因。
///
/// 返回：精确原因枚举；无原因显式编码为空。
pub(super) fn reason(value: Option<Reason>) -> i32 {
    use protocol::MaterialExecutionReason as Wire;
    (match value {
        None => Wire::Unspecified,
        Some(Reason::EffectNotAdmitted) => Wire::EffectNotAdmitted,
        Some(Reason::CandidateInvalid) => Wire::CandidateInvalid,
        Some(Reason::SourceChanged) => Wire::SourceChanged,
        Some(Reason::BaselineChanged) => Wire::BaselineChanged,
        Some(Reason::AuthorityChanged) => Wire::AuthorityChanged,
        Some(Reason::GateHalted) => Wire::GateHalted,
        Some(Reason::PreparationInterrupted) => Wire::PreparationInterrupted,
    }) as i32
}

/// 业务作用：恢复稳定原原因，未知错误码不能冒充成功的空原因。
///
/// 参数说明：
/// - `value`：报告中有限原因整数。
///
/// 返回：明确原因或空值；未知枚举拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn native_reason(value: i32) -> Result<Option<Reason>, Status> {
    use protocol::MaterialExecutionReason as Wire;
    Ok(match Wire::try_from(value) {
        Ok(Wire::Unspecified) => None,
        Ok(Wire::EffectNotAdmitted) => Some(Reason::EffectNotAdmitted),
        Ok(Wire::CandidateInvalid) => Some(Reason::CandidateInvalid),
        Ok(Wire::SourceChanged) => Some(Reason::SourceChanged),
        Ok(Wire::BaselineChanged) => Some(Reason::BaselineChanged),
        Ok(Wire::AuthorityChanged) => Some(Reason::AuthorityChanged),
        Ok(Wire::GateHalted) => Some(Reason::GateHalted),
        Ok(Wire::PreparationInterrupted) => Some(Reason::PreparationInterrupted),
        _ => return Err(invalid()),
    })
}

/// 业务作用：编码原共享终态声明，不从本机阶段猜测全任务是否完成。
///
/// 参数说明：
/// - `value`：独立释放原证明的终态。
///
/// 返回：明确的完成或补偿终态。
pub(super) fn terminal(value: Terminal) -> i32 {
    (match value {
        Terminal::Completed => protocol::ReleaseTerminal::Completed,
        Terminal::Compensated => protocol::ReleaseTerminal::Compensated,
    }) as i32
}

/// 业务作用：拒绝未指定或未知释放终态，缺省字段不构成清理确认。
///
/// 参数说明：
/// - `value`：报告中的共享终态整数。
///
/// 返回：明确终态；其它值拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn native_terminal(value: i32) -> Result<Terminal, Status> {
    Ok(match protocol::ReleaseTerminal::try_from(value) {
        Ok(protocol::ReleaseTerminal::Completed) => Terminal::Completed,
        Ok(protocol::ReleaseTerminal::Compensated) => Terminal::Compensated,
        _ => return Err(invalid()),
    })
}

/// 业务作用：统一报告合同拒绝的低敏响应，不泄露路径或内部校验错误链。
///
/// 参数说明: 无。
///
/// 返回：不能用作稳定业务收据的协议拒绝。
pub(super) fn invalid() -> Status {
    Status::invalid_argument("material execution report differs")
}
