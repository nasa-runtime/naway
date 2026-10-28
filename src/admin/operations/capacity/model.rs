//! 容量修订与比较交换身份；摘要编码沿用原始容量合同。

use super::super::model::{hex, Error};
use crate::config::operations::Config;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Row};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct Limits {
    pub max_records: u32,
    pub max_records_per_scope: u32,
    pub max_candidate_bytes: u32,
    pub max_total_candidate_bytes: u64,
}

impl Limits {
    /// 业务作用：只提取已验证配置的四项共享预算，排除本机受理和保留开关。
    ///
    /// 参数说明：
    /// - `config`：已经通过 Plan 边界检查的配置。
    ///
    /// 返回：用于同数据库合同比较的固定大小预算。
    pub(super) fn from_config(config: &Config) -> Self {
        Self {
            max_records: config.max_records,
            max_records_per_scope: config.max_records_per_scope,
            max_candidate_bytes: config.max_candidate_bytes,
            max_total_candidate_bytes: config.max_total_candidate_bytes,
        }
    }

    /// 业务作用：按已有大端整数协议计算容量身份，保持已登记集群摘要可继续核对。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：四项预算的 SHA-256，不进行 JSON 或 YAML 序列化。
    pub(super) fn digest(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.max_records.to_be_bytes());
        digest.update(self.max_records_per_scope.to_be_bytes());
        digest.update(self.max_candidate_bytes.to_be_bytes());
        digest.update(self.max_total_candidate_bytes.to_be_bytes());
        digest.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Expected {
    pub revision: i64,
    pub digest: [u8; 32],
}

impl Expected {
    /// 业务作用：解析运维明确复制的原容量令牌，避免自动接受当前权威覆盖他人的变更。
    ///
    /// 参数说明：
    /// - `raw`：规范十进制修订与小写 SHA-256，中间用冒号分隔。
    ///
    /// 返回：精确原身份；溢出、额外分隔、非规范数字或摘要失败时不连接数据库。
    pub(super) fn parse(raw: &str) -> Result<Self, Error> {
        let (revision, hash) = raw.split_once(':').ok_or(Error::Invalid)?;
        if revision.is_empty()
            || revision.len() > 19
            || !revision.bytes().all(|byte| byte.is_ascii_digit())
            || revision.len() > 1 && revision.starts_with('0')
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Invalid);
        }
        let revision = revision.parse().map_err(|_| Error::Invalid)?;
        let mut digest = [0_u8; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)
                .map_err(|_| Error::Invalid)?;
        }
        Ok(Self {
            revision,
            digest,
        })
    }

    /// 业务作用：输出可原样复制的低敏维护令牌，调用方无需自行拼接或舍入修订数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：携带原修订与摘要的稳定文本，不包含连接或主体秘密。
    pub(super) fn token(self) -> String {
        format!("{}:{}", self.revision, hex(&self.digest))
    }
}

pub(in crate::admin::operations) struct Contract {
    pub(super) identity: Expected,
    pub(super) previous: Option<[u8; 32]>,
    pub(super) limits: Option<Limits>,
}

impl Contract {
    /// 业务作用：从已锁定或单次读取的集群行提取完整容量，拒绝不完整或不一致的持久事实。
    ///
    /// 参数说明：
    /// - `row`：包含容量修订、摘要和四个可空实值的同一集群记录。
    ///
    /// 返回：兼容未登记或完整合同；不符合数据库协议时拒绝继续使用。
    pub(in crate::admin::operations) fn from_row(row: &PgRow) -> Result<Self, Error> {
        let parse = || -> Result<Self, sqlx::Error> {
            let digest: Vec<u8> = row.try_get("capacity_digest")?;
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| sqlx::Error::Protocol("invalid capacity digest".into()))?;
            let revision: i64 = row.try_get("capacity_revision")?;
            let previous: Option<Vec<u8>> = row.try_get("capacity_previous_digest")?;
            let previous = previous
                .map(|bytes| {
                    bytes.try_into().map_err(|_| {
                        sqlx::Error::Protocol("invalid previous capacity digest".into())
                    })
                })
                .transpose()?;
            if revision > 1 && previous.is_none() {
                return Err(sqlx::Error::Protocol(
                    "missing predecessor capacity digest".into(),
                ));
            }
            let records: Option<i32> = row.try_get("max_records")?;
            let scope: Option<i32> = row.try_get("max_records_per_scope")?;
            let candidate: Option<i32> = row.try_get("max_candidate_bytes")?;
            let bytes: Option<i64> = row.try_get("max_total_candidate_bytes")?;
            let limits = match (records, scope, candidate, bytes) {
                (None, None, None, None) if revision == 0 && previous.is_none() => None,
                (Some(records), Some(scope), Some(candidate), Some(bytes))
                    if revision > 0
                        && (1..=4096).contains(&records)
                        && (1..=records).contains(&scope)
                        && (1024..=1048576).contains(&candidate)
                        && (i64::from(candidate)..=67108864).contains(&bytes) =>
                {
                    Some(Limits {
                        max_records: records as u32,
                        max_records_per_scope: scope as u32,
                        max_candidate_bytes: candidate as u32,
                        max_total_candidate_bytes: bytes as u64,
                    })
                }
                _ => return Err(sqlx::Error::Protocol("incomplete capacity contract".into())),
            };
            if limits.is_some_and(|limits| limits.digest() != digest) {
                return Err(sqlx::Error::Protocol("capacity digest differs".into()));
            }
            Ok(Self {
                identity: Expected {
                    revision,
                    digest,
                },
                previous,
                limits,
            })
        };
        parse().map_err(|_| Error::Unavailable)
    }

    /// 业务作用：判断本入口的启动预算是否仍与共享合同相同，陈旧配置不能继续创建新提案。
    ///
    /// 参数说明：
    /// - `config`：本入口当前冻结的持久资源配置。
    ///
    /// 返回：四项实值和摘要完全一致时为真，未登记状态不能作为新入口的就绪证据。
    pub(in crate::admin::operations) fn matches(&self, config: &Config) -> bool {
        let expected = Limits::from_config(config);
        self.limits == Some(expected) && self.identity.digest == expected.digest()
    }

    /// 业务作用：区分原比较交换仍有效与相同维护操作已提交，阻止旧令牌跨后续变更重用。
    ///
    /// 参数说明：
    /// - `expected`：调用方保留的原容量修订与摘要。
    /// - `desired`：本次请求固定的目标四项容量。
    ///
    /// 返回：需要原子更新时为真；已经满足时为假；其它修订冲突或溢出拒绝。
    pub(super) fn transition(&self, expected: Expected, desired: Limits) -> Result<bool, Error> {
        if self.identity == expected {
            if self.limits == Some(desired) {
                return Ok(false);
            }
            expected.revision.checked_add(1).ok_or(Error::Conflict)?;
            return Ok(true);
        }
        if expected.revision.checked_add(1) == Some(self.identity.revision)
            && self.previous == Some(expected.digest)
            && self.limits == Some(desired)
            && self.identity.digest == desired.digest()
        {
            return Ok(false);
        }
        Err(Error::Conflict)
    }

    /// 业务作用：向页面与维护命令公开当前共享容量，明确区分未登记和入口配置过期。
    ///
    /// 参数说明：
    /// - `config`：本入口用于比较的目标或启动配置。
    ///
    /// 返回：低敏容量、可复制令牌与配置一致性，不包含候选或连接秘密。
    pub(in crate::admin::operations) fn view(&self, config: &Config) -> serde_json::Value {
        serde_json::json!({
            "revision": self.identity.revision,
            "expected": self.identity.token(),
            "limits": self.limits,
            "matches_config": self.matches(config)
        })
    }
}
