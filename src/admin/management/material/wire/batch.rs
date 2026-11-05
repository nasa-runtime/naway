//! 原目标分母和完整共享影响在本机与远程路径使用同一个容量及完整性门。

use super::{native_target, target};
use crate::{
    admin::management::{
        material::{command::Intent, Reason},
        protocol,
    },
    tls::{
        keypair::conditions::{Affected, Batch, Group, Reference, Source},
        targets::Target,
    },
};
use nasa::grpc::codegen::prost::Message;
use std::collections::BTreeSet;

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
    if batch.entries.len() != intent.targets.len()
        || batch.groups.is_empty()
        || batch.groups.len() > batch.entries.len()
    {
        return Err(Reason::Denied);
    }
    let mut used = BTreeSet::new();
    for (entry, target) in batch.entries.iter().zip(&intent.targets) {
        let group = batch.groups.get(entry.group).ok_or(Reason::Denied)?;
        if !group
            .affected
            .iter()
            .any(|affected| &affected.target == target && affected.source_id == group.source_id)
        {
            return Err(Reason::Denied);
        }
        used.insert(entry.group);
    }
    if used.len() != batch.groups.len() {
        return Err(Reason::Denied);
    }
    let mut sources = BTreeSet::new();
    // 逐字段预留 protobuf 标签与长度的保守上界；本机路径不为预算再序列化一份结果。
    let mut bytes = 32 * batch.entries.len();
    for group in &batch.groups {
        if !crate::tls::keypair::valid_material_generation(&group.source_id)
            || !sources.insert(&group.source_id)
            || group
                .material_generation
                .as_ref()
                .is_some_and(|value| !crate::tls::keypair::valid_material_generation(value))
            || !group
                .certificate_etag
                .strip_prefix("\"sha256-")
                .and_then(|value| value.strip_suffix('"'))
                .is_some_and(crate::tls::keypair::valid_material_generation)
            || group.affected.is_empty()
            || group.affected.len() > 128
            || !group
                .affected
                .windows(2)
                .all(|pair| identity(&pair[0].target) < identity(&pair[1].target))
        {
            return Err(Reason::Denied);
        }
        bytes += 256;
        for affected in &group.affected {
            if !affected.target.valid()
                || !crate::tls::keypair::valid_material_generation(&affected.source_id)
            {
                return Err(Reason::Denied);
            }
            bytes += 112 + affected.target.listener.len() + affected.target.entry.len();
            if bytes > 24 * 1024 {
                return Err(Reason::Capacity);
            }
        }
    }
    Ok(())
}

/// 业务作用：保持共享影响的唯一规范顺序，重复或乱序目标不能被结果聚合忽略。
///
/// 参数说明：
/// - `target`：已经验证的逻辑身份。
///
/// 返回：借用字段组成的排序键，不分配对象名称。
fn identity(target: &Target) -> (u8, &str, &str) {
    (target.kind as u8, &target.listener, &target.entry)
}
