//! 原材料条件和完整监听策略在同一锁内验证，候选只驻留内存，不产生安装决定。

use super::{conditions, generation, preflight};
use crate::{config::GatewaySnapshot, tls::targets::Target};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::sign::CertifiedKey;

pub(crate) struct Expected<'a> {
    pub target: &'a Target,
    pub certificate_etag: &'a str,
    pub material_generation: &'a str,
}

pub(crate) struct Proof {
    pub conditions: conditions::Batch,
    pub impact: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Rejected {
    Conditions(conditions::Unavailable),
    Changed,
    Denied,
    Invalid,
}

/// 业务作用：原条件、完整共享授权与候选 TLS 策略共用材料锁，不允许条件读取与构建之间穿插受管换证。
///
/// 参数说明：
/// - `snapshot`：调用者已取得配置发布权和文件事务权的原配置。
/// - `expected`：全部原逻辑目标及其不可替换的完整材料条件。
/// - `authorize`：按当前请求者和创建者检查完整共享影响，拒绝后不读取私钥或构建候选。
/// - `candidate`：已匹配的唯一候选身份；为空时只执行下载前的原条件及权限门。
///
/// 返回：完整公开条件与本次影响摘要；拒绝不创建材料代、不写候选文件、不发布活动监听。
pub(crate) fn inspect(
    snapshot: &GatewaySnapshot,
    expected: &[Expected<'_>],
    authorize: impl FnOnce(&conditions::Batch) -> bool,
    candidate: Option<&CertifiedKey>,
) -> Result<Proof, Rejected> {
    let targets: Vec<_> = expected.iter().map(|item| item.target).collect();
    conditions::with_many(snapshot, &targets, |index, sources, batch| {
        // 共享文件扩大了真实读取和替换范围；原逻辑目标可写也不能绕过其它租户的完整归属门。
        if !authorize(&batch) {
            return Err(Rejected::Denied);
        }
        for (original, entry) in expected.iter().zip(&batch.entries) {
            let group = &batch.groups[entry.group];
            if group.certificate_etag != original.certificate_etag
                || group.material_generation.as_deref() != Some(original.material_generation)
            {
                return Err(Rejected::Changed);
            }
        }
        let mut checked = std::collections::BTreeSet::new();
        let mut positions = Vec::with_capacity(batch.groups.len());
        for ((original, entry), source) in expected.iter().zip(&batch.entries).zip(sources) {
            if !checked.insert(entry.group) {
                continue;
            }
            // 公开 ETag 不能证明私钥未被单独替换；候选下载和完整构建前都验证原受管 pair。
            let (certificate_path, key_path) = crate::tls::active_keypair_paths_unrecovered(source)
                .map_err(|_| Rejected::Conditions(conditions::Unavailable::Storage))?;
            let read = |path: &std::path::Path| {
                crate::io::bounded_io::read_file(path, 1024 * 1024, "TLS material preview")
                    .map(zeroize::Zeroizing::new)
                    .map_err(|_| Rejected::Conditions(conditions::Unavailable::Storage))
            };
            let certificate = read(&certificate_path)?;
            let private_key = read(&key_path)?;
            let current = generation::current(source, &certificate, Some(&private_key))
                .map_err(|_| Rejected::Conditions(conditions::Unavailable::Storage))?;
            if current.as_deref() != Some(original.material_generation)
                || super::certificate_etag(&certificate) != original.certificate_etag
            {
                return Err(Rejected::Changed);
            }
            positions.push(index.position(original.target).ok_or(Rejected::Changed)?);
        }
        if let Some(candidate) = candidate {
            preflight::validate_sources(index, &positions, candidate)
                .map_err(|_| Rejected::Invalid)?;
        }
        Ok(Proof {
            impact: impact(&batch),
            conditions: batch,
        })
    })
    .map_err(Rejected::Conditions)?
}

/// 业务作用：给同次完整来源影响生成独立证明，原仅含 pair 条件的批准不能被解释为已批准该摘要。
///
/// 参数说明：
/// - `batch`：同一材料锁内生成的全部原引用与完整影响。
///
/// 返回：带数量、顺序和字段边界的固定摘要，不序列化 JSON，不包含文件路径或私钥摘要。
pub(crate) fn impact(batch: &conditions::Batch) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naway-material-preview-impact\0");
    hash.update((batch.entries.len() as u32).to_be_bytes());
    for entry in &batch.entries {
        hash.update([match entry.source {
            conditions::Source::File => 1,
            conditions::Source::Manifest => 2,
            conditions::Source::Acme => 3,
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

/// 业务作用：在影响证明中保留相邻字段的边界，字符串拼接不能改变逻辑身份解释。
///
/// 参数说明：
/// - `hash`：本批独立影响摘要。
/// - `bytes`：当前字段的原始借用内容。
///
/// 返回：增量加入长度和字段内容，不分配中间编码。
fn stamp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
