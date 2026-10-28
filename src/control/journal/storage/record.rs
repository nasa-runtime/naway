//! 永久受理代际和提交入口的严格有界编码。

use super::super::identity::Identity;
use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const STATE_LIMIT: usize = 128 * 1024;
pub(super) const SMALL_LIMIT: usize = 4096;
pub(super) const STATE_MAGIC: &[u8; 8] = b"NWYSTA1\0";
pub(super) const HEAD_MAGIC: &[u8; 8] = b"NWYHED1\0";
pub(super) const STORAGE_MAGIC: &[u8; 8] = b"NWYSTO1\0";
const HEADER: usize = 44;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Slot {
    A,
    B,
}

impl Slot {
    /// 业务作用：将有限状态槽映射到固定文件名，外部标识不参与路径构造。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：两个受协议约束的状态文件名之一。
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::A => "state-a",
            Self::B => "state-b",
        }
    }

    /// 业务作用：为新提交选择非当前槽，完整旧状态必须保留到head提交之后。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与当前提交槽不同的固定槽。
    pub(super) fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub(super) identity: Identity,
    pub(super) revision: u64,
    pub(super) admission_epoch: u64,
    pub(super) closed_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) local_publication: Option<super::super::local::Plan>,
    #[cfg(feature = "node-actions")]
    #[serde(default, skip_serializing_if = "zero")]
    pub(super) highest_fence: u64,
    #[cfg(feature = "node-actions")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) action: Option<super::super::actions::model::Record>,
}

impl State {
    /// 业务作用：创建尚未受理任何动作的初始代际，永久身份沿用既有目录绑定。
    ///
    /// 参数说明：
    /// - `identity`：已经完整核验的节点身份。
    ///
    /// 返回：首个受理代际与关闭水位，不授予远程执行权。
    pub(super) fn initial(identity: &Identity) -> Self {
        Self {
            identity: identity.clone(),
            revision: 1,
            admission_epoch: 1,
            closed_epoch: 0,
            local_publication: None,
            #[cfg(feature = "node-actions")]
            highest_fence: 0,
            #[cfg(feature = "node-actions")]
            action: None,
        }
    }

    /// 业务作用：验证状态身份与代际顺序，损坏或外来记录不得重新开放已经关闭的代际。
    ///
    /// 参数说明：
    /// - `identity`：目录的永久绑定。
    ///
    /// 返回：身份一致、revision有效且受理代际紧随关闭水位时成功，否则拒绝。
    pub(super) fn validate(&self, identity: &Identity) -> Result<()> {
        ensure!(
            self.identity == *identity,
            "node journal state binding differs"
        );
        ensure!(
            self.revision > 0
                && self.closed_epoch.checked_add(1) == Some(self.admission_epoch)
                && self.revision >= self.admission_epoch,
            "node journal state ordering differs"
        );
        if let Some(plan) = &self.local_publication {
            plan.validate()?;
        }
        #[cfg(feature = "node-actions")]
        {
            ensure!(
                self.highest_fence <= i64::MAX as u64,
                "node journal fence exceeds bounds"
            );
            if let Some(action) = &self.action {
                action.validate(identity, self.admission_epoch, self.highest_fence)?;
                // 两种文件事务共用六正文槽；只有明确丢弃正文权威的动作可与本地决定并存。
                ensure!(
                    self.local_publication.is_none() || action.allows_local(),
                    "node journal file owners overlap"
                );
            }
        }
        Ok(())
    }
}

/// 业务作用：让从未受理动作的持久状态保留原空槽编码，非零 fence 永不因终态清理而省略。
///
/// 参数说明：
/// - `value`：当前持久最高 fence。
///
/// 返回：仅初始零水位允许省略字段；已有动作事实必须保留能力边界。
#[cfg(feature = "node-actions")]
fn zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    pub(super) identity: Identity,
    pub(super) revision: u64,
    pub(super) slot: Slot,
    pub(super) sha256: [u8; 32],
}

impl Head {
    /// 业务作用：将提交权威绑定到某一完整状态原文，另一槽序号更大也不能取得执行权。
    ///
    /// 参数说明：
    /// - `state`：已完成业务校验的候选状态。
    /// - `slot`：保存候选的固定槽。
    /// - `bytes`：该状态实际落盘的完整原始记录。
    ///
    /// 返回：绑定身份、序号、槽及SHA-256的提交入口。
    pub(super) fn new(state: &State, slot: Slot, bytes: &[u8]) -> Self {
        Self {
            identity: state.identity.clone(),
            revision: state.revision,
            slot,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    /// 业务作用：为离线维护生成绑定目录与当前状态的比较令牌，阻止过期或跨目录请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：revision与完整状态摘要组成的稳定令牌。
    pub(super) fn token(&self) -> String {
        use std::fmt::Write as _;
        let mut token = format!("{}:", self.revision);
        for byte in self.sha256 {
            write!(&mut token, "{byte:02x}").expect("writing to a string cannot fail");
        }
        token
    }
}

/// 业务作用：为持久元数据生成带长度与摘要的有限记录，不将配置正文嵌入状态。
///
/// 参数说明：
/// - `value`：已经按业务规则构造的元数据。
/// - `magic`：该记录类型的固定格式标识。
/// - `limit`：包含头部在内的最大长度。
///
/// 返回：一次序列化的完整记录；编码或长度不满足时拒绝。
pub(super) fn encode<T: Serialize>(value: &T, magic: &[u8; 8], limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(256);
    bytes.resize(HEADER, 0);
    serde_json::to_writer(&mut bytes, value).context("cannot encode node journal state")?;
    ensure!(bytes.len() <= limit, "node journal state exceeds limit");
    let length = (bytes.len() - HEADER) as u32;
    let digest = Sha256::digest(&bytes[HEADER..]);
    bytes[..8].copy_from_slice(magic);
    bytes[8..12].copy_from_slice(&length.to_be_bytes());
    bytes[12..HEADER].copy_from_slice(&digest);
    Ok(bytes)
}

/// 业务作用：按类型、长度与完整摘要读取持久元数据，拒绝截断、尾随或未知字段。
///
/// 参数说明：
/// - `bytes`：读取至EOF的有限记录。
/// - `magic`：当前入口接受的固定格式标识。
/// - `limit`：该记录类型的最大长度。
///
/// 返回：结构完整的元数据；业务身份及状态顺序仍须由调用方复验。
pub(super) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    magic: &[u8; 8],
    limit: usize,
) -> Result<T> {
    ensure!(
        (HEADER..=limit).contains(&bytes.len()) && &bytes[..8] == magic,
        "node journal state format differs"
    );
    let length = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed state length"));
    ensure!(
        length as usize == bytes.len() - HEADER,
        "node journal state length differs"
    );
    ensure!(
        Sha256::digest(&bytes[HEADER..])[..] == bytes[12..HEADER],
        "node journal state integrity differs"
    );
    serde_json::from_slice(&bytes[HEADER..])
        .map_err(|_| anyhow::anyhow!("node journal state fields differ"))
}
