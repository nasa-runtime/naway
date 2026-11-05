//! 证书提案冻结原目标与材料意图；输入基线不等于节点已经验证。

use super::super::model::Error;
pub(super) use crate::control::material::{Material, Summary, Target};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submission {
    pub admission_epoch: i64,
    pub targets: Vec<Target>,
    pub ttl_seconds: u32,
    #[serde(deserialize_with = "secret")]
    pub certificate_pem: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    pub private_key_pem: Zeroizing<String>,
}

/// 业务作用：将 JSON 材料字段直接交给清零容器，后续字段解析失败也能释放已经接收的秘密。
///
/// 参数说明：
/// - `deserializer`：有界请求的当前文本字段。
///
/// 返回：拥有原始文本的清零容器；字段类型不正确时拒绝。
fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub(super) struct Candidate {
    pub epoch: i64,
    pub ttl_seconds: u32,
    pub targets: Vec<Target>,
    pub target_bytes: Vec<u8>,
    pub material: Material,
}

impl Candidate {
    /// 业务作用：冻结有界、唯一且有持久材料代的目标意图，不把调用者声明当作目标执行权威。
    ///
    /// 参数说明：
    /// - `input`：已通过请求大小门的原始声明。
    /// - `limit`：单份明文材料的配置上限。
    /// - `cluster`：本存储的唯一发行集群。
    ///
    /// 返回：有界元数据和唯一清零材料帧；错误不包含材料或路径。
    pub(super) fn build(mut input: Submission, limit: usize, cluster: &str) -> Result<Self, Error> {
        if input.admission_epoch <= 0
            || !(60..=86400).contains(&input.ttl_seconds)
            || input.targets.is_empty()
            || input.targets.len() > crate::config::operations::MAX_TARGETS
            || input.certificate_pem.is_empty()
            || input.private_key_pem.is_empty()
            || input
                .certificate_pem
                .len()
                .saturating_add(input.private_key_pem.len())
                > limit
        {
            return Err(Error::Invalid);
        }
        input
            .targets
            .sort_unstable_by(|left, right| left.identity().cmp(&right.identity()));
        if !Target::valid_set(&input.targets, cluster) {
            return Err(Error::Invalid);
        }
        let target_bytes = serde_json::to_vec(&input.targets).map_err(|_| Error::Invalid)?;
        if target_bytes.len() > 65536 {
            return Err(Error::Invalid);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            input.certificate_pem.len() + input.private_key_pem.len() + 16,
        ));
        bytes.extend_from_slice(b"NCERT001");
        bytes.extend_from_slice(&(input.certificate_pem.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(input.private_key_pem.len() as u32).to_be_bytes());
        bytes.extend_from_slice(input.certificate_pem.as_bytes());
        bytes.extend_from_slice(input.private_key_pem.as_bytes());
        Ok(Self {
            epoch: input.admission_epoch,
            ttl_seconds: input.ttl_seconds,
            targets: input.targets,
            target_bytes,
            material: Material(bytes),
        })
    }

    /// 业务作用：冻结材料、全部原目标、期限和授权摘要，阻止同原幂等键覆盖另一份提案。
    ///
    /// 参数说明：
    /// - `authority`：当前范围的权限及对象归属摘要。
    ///
    /// 返回：仅供持久意图与 AAD 使用的摘要，不作为私钥摘要交付普通查询。
    pub(super) fn fingerprint(&self, authority: &[u8; 32]) -> [u8; 32] {
        fingerprint(
            &self.material,
            &self.target_bytes,
            self.epoch,
            self.ttl_seconds,
            authority,
        )
    }

    /// 业务作用：在运行 KDF 之前预留最坏密文扩张、公开摘要和固定元数据所占的共享容量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：大于 NC2 及有限公开摘要实际字节数的确定上界，全部保留状态均按该值占用容量。
    pub(super) fn reservation(&self) -> u64 {
        self.material.0.len() as u64 * 2 + self.target_bytes.len() as u64 + 4096
    }
}

/// 业务作用：让首次受理与解密复验使用相同长度分帧意图，数据库元数据不能替换已认证材料。
///
/// 参数说明：
/// - `material`：唯一明文材料帧。
/// - `targets`：冻结的完整目标编码。
/// - `epoch`：原受理代际。
/// - `ttl`：原提案可审阅期限秒数。
/// - `authority`：原权限和归属摘要。
///
/// 返回：不公开的固定意图摘要。
pub(super) fn fingerprint(
    material: &Material,
    targets: &[u8],
    epoch: i64,
    ttl: u32,
    authority: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"naway-certificate-proposal-intent\0");
    for field in [
        material.0.as_slice(),
        targets,
        authority.as_slice(),
        &epoch.to_be_bytes(),
        &ttl.to_be_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

#[derive(Serialize)]
pub(super) struct Record {
    pub id: String,
    pub scope: String,
    pub admission_epoch: i64,
    pub creator: String,
    pub reviewer: Option<String>,
    pub status: String,
    pub key_id: String,
    pub targets: Vec<Target>,
    pub certificate: Summary,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub updated_at_ms: i64,
}

/// 业务作用：统一限制公开随机身份和摘要为唯一小写十六进制表示。
///
/// 参数说明：
/// - `value`：协议中的固定长度身份。
/// - `length`：该字段定义的字符数。
///
/// 返回：长度和字符集均符合合同才为真。
pub(super) fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
