//! 安装附加证据仅按原条件位置转换，旧查询不接收也不产生新的安装声明。

use super::{decode_batch, encode_batch, validate};
use crate::{
    admin::management::{
        material::{
            Inspection, Reason,
            command::{Intent, Query},
        },
        protocol,
    },
    control::material::installation::{Batch, Group, MAX_WIRE_BYTES, Observation, State, Target},
    tls::installed::CertificateProtocol,
};
use nasa::grpc::codegen::prost::Message;

/// 业务作用：网络边界一次移动完整原生观察，安装证据只允许出现在独立安装查询中。
///
/// 参数说明：
/// - `value`：同一节点已经复验权限与原基线的完整观察。
/// - `intent`：原查询类别、全部目标与原索引。
///
/// 返回：完整条件及可选安装附加消息；类别不符或容量不足时整批拒绝，不发送半份结果。
pub(in crate::admin::management) fn encode_result(
    value: Inspection,
    intent: &Intent,
) -> Result<
    (
        protocol::MaterialConditionsBatch,
        Option<protocol::MaterialInstallationsBatch>,
    ),
    Reason,
> {
    validate(&value.batch, intent)?;
    let installations = match (intent.query_kind, value.installations) {
        (Query::Conditions, None) => None,
        (Query::Installations, Some(batch)) if batch.valid(&value.batch) => Some(encode(batch)?),
        _ => return Err(Reason::Denied),
    };
    Ok((encode_batch(value.batch, intent)?, installations))
}

/// 业务作用：按原签名类别接纳完整条件与安装证据，缺省附加字段不能被当成已经安装。
///
/// 参数说明：
/// - `conditions`：原条件协议，任何类别都必须保留完整来源分母。
/// - `installations`：只有明确安装查询才允许出现的附加证明。
/// - `intent`：原等待者冻结的查询身份。
///
/// 返回：完成结构和预算复验的原生观察；跨类别、缺失或超量均拒绝。
pub(in crate::admin::management) fn decode_result(
    conditions: protocol::MaterialConditionsBatch,
    installations: Option<protocol::MaterialInstallationsBatch>,
    intent: &Intent,
) -> Result<Inspection, Reason> {
    let batch = decode_batch(conditions, intent)?;
    let installations = match (intent.query_kind, installations) {
        (Query::Conditions, None) => None,
        (Query::Installations, Some(value)) => {
            if value.encoded_len() > MAX_WIRE_BYTES {
                return Err(Reason::Capacity);
            }
            let value = decode(value)?;
            if !value.valid(&batch) {
                return Err(Reason::Denied);
            }
            Some(value)
        }
        _ => return Err(Reason::Denied),
    };
    Ok(Inspection {
        batch,
        installations,
    })
}

/// 业务作用：在发送边界消费唯一安装树，保留组、目标和实际协议的原生顺序。
///
/// 参数说明：
/// - `batch`：已对照完整文件条件验证的有限安装观察。
///
/// 返回：独立预算内的 protobuf；超量拒绝，不截断任何原影响。
fn encode(batch: Batch) -> Result<protocol::MaterialInstallationsBatch, Reason> {
    let value = protocol::MaterialInstallationsBatch {
        groups: batch
            .groups
            .into_iter()
            .map(|group| protocol::MaterialInstallationGroup {
                targets: group
                    .targets
                    .into_iter()
                    .map(|target| protocol::MaterialInstallationTarget {
                        protocols: target
                            .protocols
                            .into_iter()
                            .map(|observation| protocol::MaterialInstallationObservation {
                                protocol: match observation.protocol {
                                    CertificateProtocol::Https => "https",
                                    CertificateProtocol::Http3 => "http3",
                                    CertificateProtocol::StreamTls => "stream_tls",
                                }
                                .into(),
                                state: state(observation.state) as i32,
                                bindings: observation.bindings,
                                material_generation: observation.material_generation,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    };
    if value.encoded_len() > MAX_WIRE_BYTES {
        return Err(Reason::Capacity);
    }
    Ok(value)
}

/// 业务作用：从明确协议枚举恢复安装树，未知值不能被映射成正常或未受管状态。
///
/// 参数说明：
/// - `value`：已经检查实际传输字节上限的完整附加消息。
///
/// 返回：原生结构，随后必须对照原文件条件验证全部位置与状态关系。
fn decode(value: protocol::MaterialInstallationsBatch) -> Result<Batch, Reason> {
    let groups = value
        .groups
        .into_iter()
        .map(|group| {
            let targets = group
                .targets
                .into_iter()
                .map(|target| {
                    let protocols = target
                        .protocols
                        .into_iter()
                        .map(|observation| {
                            Ok(Observation {
                                protocol: match observation.protocol.as_str() {
                                    "https" => CertificateProtocol::Https,
                                    "http3" => CertificateProtocol::Http3,
                                    "stream_tls" => CertificateProtocol::StreamTls,
                                    _ => return Err(Reason::Denied),
                                },
                                state: native_state(observation.state)?,
                                bindings: observation.bindings,
                                material_generation: observation.material_generation,
                            })
                        })
                        .collect::<Result<Vec<_>, Reason>>()?;
                    Ok(Target {
                        protocols,
                    })
                })
                .collect::<Result<Vec<_>, Reason>>()?;
            Ok(Group {
                targets,
            })
        })
        .collect::<Result<Vec<_>, Reason>>()?;
    Ok(Batch {
        groups,
    })
}

/// 业务作用：只输出实现明确支持的安装状态，未定义默认值不参与成功或失败回报。
///
/// 参数说明：
/// - `value`：原生安装观察状态。
///
/// 返回：一一对应的稳定协议枚举。
fn state(value: State) -> protocol::MaterialInstallationState {
    use protocol::MaterialInstallationState as Wire;
    match value {
        State::Current => Wire::Current,
        State::DifferentMaterial => Wire::DifferentMaterial,
        State::Unmanaged => Wire::Unmanaged,
        State::Unproven => Wire::Unproven,
        State::External => Wire::External,
        State::Pending => Wire::Pending,
        State::NotSelected => Wire::NotSelected,
        State::Capacity => Wire::Capacity,
        State::Unavailable => Wire::Unavailable,
    }
}

/// 业务作用：拒绝网络中的未知安装状态，不以将来协议值补齐当前执行证明。
///
/// 参数说明：
/// - `value`：原消息中的状态整数。
///
/// 返回：当前支持的原生状态；未知或未指定值拒绝整节点结果。
fn native_state(value: i32) -> Result<State, Reason> {
    use protocol::MaterialInstallationState as Wire;
    Ok(match Wire::try_from(value).map_err(|_| Reason::Denied)? {
        Wire::Current => State::Current,
        Wire::DifferentMaterial => State::DifferentMaterial,
        Wire::Unmanaged => State::Unmanaged,
        Wire::Unproven => State::Unproven,
        Wire::External => State::External,
        Wire::Pending => State::Pending,
        Wire::NotSelected => State::NotSelected,
        Wire::Capacity => State::Capacity,
        Wire::Unavailable => State::Unavailable,
        Wire::Unspecified => return Err(Reason::Denied),
    })
}
