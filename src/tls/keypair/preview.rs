//! 原材料条件和完整监听策略在同一锁内验证，候选只驻留内存，不产生安装决定。

use super::{conditions, generation, preflight};
use crate::{config::GatewaySnapshot, tls::targets::Target};
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
            impact: crate::control::material::conditions::digest(&batch),
            conditions: batch,
        })
    })
    .map_err(Rejected::Conditions)?
}
