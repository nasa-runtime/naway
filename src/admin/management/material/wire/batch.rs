//! 原目标分母和完整共享影响在本机与远程路径使用同一个容量及完整性门。

use super::{native_target, target};
use crate::{
    admin::management::{
        material::{command::Intent, Reason},
        protocol,
    },
    tls::keypair::conditions::{Affected, Batch, Group, Reference, Source},
};
use nasa::grpc::codegen::prost::Message;

/// 业务作用：同源材料仅传送一份，原请求位置单独引用来源组，不复制证书关系数组。
///
/// 参数说明：
/// - `batch`：已经通过完整性门的原生批次。
/// - `intent`：冻结原全局索引的签名意图。
///
/// 返回：移动既有字符串与数组的协议结果；超量或身份不一致拒绝。
pub(in crate::admin::management) fn encode_batch(
    batch: Batch,
    intent: &Intent,
) -> Result<protocol::MaterialConditionsBatch, Reason> {
    validate(&batch, intent)?;
    Ok(protocol::MaterialConditionsBatch {
        entries: batch
            .entries
            .into_iter()
            .zip(&intent.indices)
            .map(|(entry, index)| protocol::MaterialConditionsReference {
                index: *index,
                group: entry.group as u32,
                source: match entry.source {
                    Source::File => protocol::MaterialSource::File,
                    Source::Manifest => protocol::MaterialSource::Manifest,
                    Source::Acme => protocol::MaterialSource::Acme,
                } as i32,
            })
            .collect(),
        groups: batch
            .groups
            .into_iter()
            .map(|group| protocol::MaterialConditionsGroup {
                certificate_etag: group.certificate_etag,
                material_generation: group.material_generation,
                source_id: group.source_id,
                affected: group
                    .affected
                    .into_iter()
                    .map(|affected| protocol::MaterialAffected {
                        target: Some(target(affected.target)),
                        source_id: affected.source_id,
                    })
                    .collect(),
            })
            .collect(),
    })
}

/// 业务作用：仅接受完整原批次，不将缺项、重复索引或非法来源解释为部分成功。
///
/// 参数说明：
/// - `value`：本次已由原节点会话绑定的完整消息。
/// - `intent`：原请求唯一分母及逻辑目标。
///
/// 返回：移动原分配的完整原生批次；未知状态、来源、索引或超量影响均拒绝。
pub(in crate::admin::management) fn decode_batch(
    value: protocol::MaterialConditionsBatch,
    intent: &Intent,
) -> Result<Batch, Reason> {
    if value.encoded_len() > 24 * 1024 || value.entries.len() != intent.indices.len() {
        return Err(Reason::Capacity);
    }
    let entries = value
        .entries
        .into_iter()
        .zip(&intent.indices)
        .map(|(entry, index)| {
            if entry.index != *index {
                return Err(Reason::Denied);
            }
            Ok(Reference {
                group: entry.group as usize,
                source: match protocol::MaterialSource::try_from(entry.source) {
                    Ok(protocol::MaterialSource::File) => Source::File,
                    Ok(protocol::MaterialSource::Manifest) => Source::Manifest,
                    Ok(protocol::MaterialSource::Acme) => Source::Acme,
                    _ => return Err(Reason::Denied),
                },
            })
        })
        .collect::<Result<_, _>>()?;
    let groups = value
        .groups
        .into_iter()
        .map(|group| {
            Ok(Group {
                certificate_etag: group.certificate_etag,
                material_generation: group.material_generation,
                source_id: group.source_id,
                affected: group
                    .affected
                    .into_iter()
                    .map(|affected| {
                        Ok(Affected {
                            target: native_target(affected.target)?,
                            source_id: affected.source_id,
                        })
                    })
                    .collect::<Result<_, Reason>>()?,
            })
        })
        .collect::<Result<_, Reason>>()?;
    let batch = Batch {
        entries,
        groups,
    };
    validate(&batch, intent)?;
    Ok(batch)
}

/// 业务作用：以相同规则验证原生和网络批次，来源不能缺失、拆分重复或隐去原目标自身。
///
/// 参数说明：
/// - `batch`：完整观察结果，无任何截断标记。
/// - `intent`：原请求逻辑身份与固定数量。
///
/// 返回：所有组均被引用、原目标均包含在自己的影响内且整体小于消息预算才成功。
pub(in crate::admin::management) fn validate(batch: &Batch, intent: &Intent) -> Result<(), Reason> {
    use crate::control::material::conditions::{self, Invalid};
    conditions::validate(batch, intent.targets.iter()).map_err(|reason| match reason {
        Invalid::Structure => Reason::Denied,
        Invalid::Capacity => Reason::Capacity,
    })
}
