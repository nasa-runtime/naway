//! 提案保存和审阅的低敏模型；批准记录不等于目标执行成功。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::operations::MAX_TARGETS;
pub(super) use crate::control::actions::domain::Domain;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub node_id: String,
    pub boot_id: String,
    pub base_version: u64,
    pub base_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_baseline: Option<crate::control::baseline::NodeBaseline>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submission {
    #[serde(default)]
    pub admission_epoch: Option<i64>,
    pub domain: Domain,
    pub candidate: String,
    pub targets: Vec<Target>,
    pub ttl_seconds: u32,
}

/// 通过语法和长度门的原始候选；只有存储事务拥有提交决定权。
pub(super) struct Candidate {
    pub admission_epoch: i64,
    pub domain: Domain,
    pub bytes: bytes::Bytes,
    pub digest: [u8; 32],
    pub target_bytes: Vec<u8>,
    pub ttl_seconds: u32,
}

impl Candidate {
    /// 业务作用：一次验证候选语法和目标意图，保留原文而不重复编码 YAML。
    ///
    /// 参数说明：
    /// - `submission`：有界请求解析后的候选声明。
    /// - `max_bytes`：当前权威允许的单候选上限。
    ///
    /// 返回：排序去重后的目标和原始候选；不执行插值、外呼、目标预检或配置发布。
    pub(super) fn build(mut submission: Submission, max_bytes: usize) -> Result<Self, Error> {
        if submission.candidate.is_empty()
            || submission.candidate.len() > max_bytes
            || !(60..=86400).contains(&submission.ttl_seconds)
            || submission.targets.is_empty()
            || submission.targets.len() > MAX_TARGETS
            || submission.admission_epoch.is_some_and(|epoch| epoch <= 0)
        {
            return Err(Error::Invalid);
        }
        submission
            .targets
            .sort_unstable_by(|left, right| left.node_id.cmp(&right.node_id));
        for (index, target) in submission.targets.iter().enumerate() {
            if !crate::config::operations::token(&target.node_id, 128)
                || !crate::config::operations::token(&target.boot_id, 128)
                || target.base_version == 0
                || target.base_fingerprint.len() != 16
                || target
                    .node_baseline
                    .as_ref()
                    .is_some_and(|value| !value.valid())
                || !target
                    .base_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || index > 0 && submission.targets[index - 1].node_id == target.node_id
            {
                return Err(Error::Invalid);
            }
        }
        let value = crate::config::document::parse(submission.candidate.as_bytes(), max_bytes)
            .map_err(|_| Error::Invalid)?;
        if !value.is_object() {
            return Err(Error::Invalid);
        }
        let target_bytes = serde_json::to_vec(&submission.targets).map_err(|_| Error::Invalid)?;
        // 目标元数据沿用数据库的独立预算；原文仍在预算内也不能把超量目标交给存储层裁决为过期。
        if target_bytes.len() > 65536 {
            return Err(Error::Invalid);
        }
        let digest = Sha256::digest(submission.candidate.as_bytes()).into();
        Ok(Self {
            admission_epoch: submission.admission_epoch.unwrap_or(0),
            domain: submission.domain,
            bytes: submission.candidate.into(),
            digest,
            target_bytes,
            ttl_seconds: submission.ttl_seconds,
        })
    }

    /// 业务作用：把内容、目标和冻结权限共同纳入幂等身份，阻止旧收据用于另一意图。
    ///
    /// 参数说明：
    /// - `authority`：当前主体与工作区的授权摘要。
    ///
    /// 返回：长度分帧后的 SHA-256；相同键不能靠续期或换目标复用。
    pub(super) fn fingerprint(&self, authority: &[u8; 32]) -> [u8; 32] {
        let mut digest = Sha256::new();
        for field in [
            self.domain.identity().0.as_bytes(),
            &self.digest,
            &self.target_bytes,
            authority,
            &self.ttl_seconds.to_be_bytes(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        if self.admission_epoch > 0 {
            digest.update(b"admission_epoch\0");
            digest.update(self.admission_epoch.to_be_bytes());
        }
        digest.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    Approve,
    Reject,
    Cancel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Review {
    pub decision: Decision,
    pub candidate_sha256: String,
}

/// 低敏持久记录投影；候选正文、凭据和幂等键永不进入列表。
#[derive(Serialize)]
pub(super) struct Record {
    pub admission_epoch: i64,
    pub id: String,
    pub scope: String,
    pub domain: String,
    pub creator: String,
    pub reviewer: Option<String>,
    pub status: String,
    pub execution_started: bool,
    pub candidate_sha256: String,
    pub candidate_bytes: i32,
    pub targets: Vec<Target>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Expired,
    Invalid,
    Conflict,
    Capacity,
    Missing,
    Denied,
    Unavailable,
    OutcomeUnknown,
}

/// 业务作用：用固定小写十六进制表示随机操作身份或摘要，不附带正文。
///
/// 参数说明：
/// - `bytes`：固定长度随机身份或摘要。
///
/// 返回：两倍输入长度的稳定 ASCII 表示。
pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
