//! 完整来源影响采用同一原生校验与摘要合同，网络和持久适配不能各自放宽原目标分母。

use crate::tls::{keypair::conditions::Batch, targets::Target};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) enum Invalid {
    Structure,
    Capacity,
}

/// 业务作用：统一验证完整原目标与来源影响，缺项、重复来源或超量关系不能构成可审阅事实。
///
/// 参数说明：
/// - `batch`：本机、网络或持久边界得到的完整原生来源批次。
/// - `targets`：按原批次顺序借用的全部逻辑身份，不从当前成员列表补齐。
///
/// 返回：全部来源均被引用、每个原目标包含在所属影响内且满足固定预算时成功。
pub(crate) fn validate<'a>(
    batch: &Batch,
    targets: impl ExactSizeIterator<Item = &'a Target>,
) -> Result<(), Invalid> {
    if batch.entries.len() > 128 {
        return Err(Invalid::Capacity);
    }
    if batch.entries.len() != targets.len()
        || batch.groups.is_empty()
        || batch.groups.len() > batch.entries.len()
    {
        return Err(Invalid::Structure);
    }
    let mut used = BTreeSet::new();
    for (entry, target) in batch.entries.iter().zip(targets) {
        let group = batch.groups.get(entry.group).ok_or(Invalid::Structure)?;
        // 原逻辑目标必须真实属于该来源，不能用其它对象的合法影响清单替代原目标证明。
        if !group
            .affected
            .iter()
            .any(|affected| &affected.target == target && affected.source_id == group.source_id)
        {
            return Err(Invalid::Structure);
        }
        used.insert(entry.group);
    }
    if used.len() != batch.groups.len() {
        return Err(Invalid::Structure);
    }
    let mut sources = BTreeSet::new();
    // 保留协议字段开销的保守上界，原生调用不为判断预算再序列化一份完整关系。
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
            return Err(Invalid::Structure);
        }
        bytes += 256;
        for affected in &group.affected {
            if !affected.target.valid()
                || !crate::tls::keypair::valid_material_generation(&affected.source_id)
            {
                return Err(Invalid::Structure);
            }
            bytes += 112 + affected.target.listener.len() + affected.target.entry.len();
            if bytes > 24 * 1024 {
                return Err(Invalid::Capacity);
            }
        }
    }
    Ok(())
}

/// 业务作用：对完整来源影响生成稳定的独立证明，材料条件批准不能自动包含未确认的共享对象。
///
/// 参数说明：
/// - `batch`：全部原引用及规范来源影响，调用方负责完整性和容量门。
///
/// 返回：带数量、顺序和字段边界的固定摘要，不序列化JSON，不包含文件路径或私钥摘要。
pub(crate) fn digest(batch: &Batch) -> [u8; 32] {
    use crate::tls::keypair::conditions::Source;
    let mut hash = Sha256::new();
    hash.update(b"naway-material-preview-impact\0");
    hash.update((batch.entries.len() as u32).to_be_bytes());
    for entry in &batch.entries {
        hash.update([match entry.source {
            Source::File => 1,
            Source::Manifest => 2,
            Source::Acme => 3,
        }]);
        hash.update((entry.group as u32).to_be_bytes());
    }
    hash.update((batch.groups.len() as u32).to_be_bytes());
    for group in &batch.groups {
        for field in [
            group.source_id.as_bytes(),
            group.certificate_etag.as_bytes(),
            group
                .material_generation
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        ] {
            stamp(&mut hash, field);
        }
        hash.update((group.affected.len() as u32).to_be_bytes());
        for affected in &group.affected {
            hash.update([affected.target.kind as u8]);
            for field in [
                affected.target.listener.as_bytes(),
                affected.target.entry.as_bytes(),
                affected.source_id.as_bytes(),
            ] {
                stamp(&mut hash, field);
            }
        }
    }
    hash.finalize().into()
}

/// 业务作用：保持共享影响的唯一规范顺序，重复或乱序对象不能被结果聚合忽略。
///
/// 参数说明：
/// - `target`：已经验证的逻辑身份。
///
/// 返回：借用字段组成的排序键，不分配对象名称。
fn identity(target: &Target) -> (u8, &str, &str) {
    (target.kind as u8, &target.listener, &target.entry)
}

/// 业务作用：在影响证明中保留相邻字段边界，字符串拼接不能改变逻辑身份解释。
///
/// 参数说明：
/// - `hash`：本批独立影响摘要。
/// - `bytes`：当前字段的原始借用内容。
///
/// 返回：增量加入长度和内容，不分配中间编码。
fn stamp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
