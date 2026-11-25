//! 本地接收进度和待应用原文身份。文件本身不保存配置正文。

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(super) const LIMIT: usize = 64;
const MAX_BYTES: u64 = 64 * 1024;
pub(super) type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Revision {
    pub(super) id: Hash,
    pub(super) parent: Hash,
    pub(super) content: Hash,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub(super) current: Vec<Revision>,
    pub(super) pending: Option<Vec<Revision>>,
}

impl Revision {
    /// 业务作用：将每次原文变动绑定到唯一父代，回滚到相同内容也形成新代。
    /// 参数说明：
    /// - `parent`：本次编辑前完整配置代的标识。
    /// - `content`：本次完整原文的摘要。
    /// 返回：两项输入决定的内容可验证标识，零父代只用于初次加入时的共同原文。
    pub(super) fn new(parent: Hash, content: Hash) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"naway.named-config-lineage\x00");
        hash.update(parent);
        hash.update(content);
        Self {
            id: hash.finalize().into(),
            parent,
            content,
        }
    }
}

impl Ledger {
    /// 业务作用：加载同一配置目录的复制代次，保留进程重启前的冲突与回滚身份。
    /// 参数说明：
    /// - `path`：本节点通过入口配置定位的固定元数据文件。
    /// 返回：合法的有限历史；缺失代表初始状态，异常不重建历史以免接受旧代。
    pub(super) fn read(path: &Path) -> Result<Self> {
        let mut input = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(input) => input,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let metadata = input.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_BYTES,
            "invalid replication ledger file"
        );
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut input).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "replication ledger too large"
        );
        let ledger: Self = serde_json::from_slice(&bytes)?;
        validate(&ledger.current)?;
        if let Some(pending) = &ledger.pending {
            validate(pending)?;
            let current = ledger
                .current
                .last()
                .context("pending ledger baseline missing")?;
            ensure!(
                advance(&ledger.current, current.id, pending),
                "pending ledger baseline differs"
            );
        }
        Ok(ledger)
    }

    /// 业务作用：在文件写入前持久记录待处理代，只有当前配置完整应用时才能在下一轮推进。
    /// 参数说明：
    /// - `path`：本节点的固定元数据目标。
    /// 返回：文件及其目录均同步后成功；持久化失败阻止配置受到本次复制写入。
    pub(super) fn write(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .context("replication ledger directory missing")?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| anyhow::anyhow!("replication entropy unavailable"))?;
        let stage = parent.join(format!(
            ".naway-config-replication-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .mode(0o600)
            .create_new(true)
            .open(&stage)?;
        let result = (|| {
            file.write_all(&serde_json::to_vec(self)?)?;
            file.sync_all()?;
            std::fs::rename(&stage, path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            // 暂存失败只能移除本次拥有的随机路径，不能碰前一次确认的记录。
            let _ = std::fs::remove_file(stage);
        }
        result
    }

    /// 业务作用：将当前完整快照纳入复制代，并在接收后恢复精确的对端代次。
    /// 参数说明：
    /// - `content`：已真实装配且再次核对文件得到的完整原文摘要。
    /// 返回：本轮是否更新持久记录。待处理代对应的原文仍缺席时保持该代待处理。
    pub(super) fn observe(&mut self, content: Hash) -> Result<bool> {
        if let Some(pending) = self.pending.as_ref() {
            let target = pending
                .last()
                .context("missing pending replication revision")?;
            if content == target.content {
                self.current = self.pending.take().expect("observed pending ledger");
                return Ok(true);
            }
            let parent = self
                .current
                .last()
                .context("missing active replication revision")?;
            ensure!(
                parent.content == content,
                "file contents conflict with pending replication"
            );
            return Ok(false);
        }
        if self
            .current
            .last()
            .is_some_and(|revision| revision.content == content)
        {
            return Ok(false);
        }
        let parent = self.current.last().map_or([0; 32], |revision| revision.id);
        if self.current.len() == LIMIT {
            self.current.remove(0);
        }
        self.current.push(Revision::new(parent, content));
        Ok(true)
    }
}

/// 业务作用：验证代次链逐项与原文摘要匹配，防止缺段或同一代次被重复解释。
/// 参数说明：
/// - `chain`：来自本地事实文件或已认证对端的有限历史。
/// 返回：每个代次有效且连续时成功。
pub(super) fn validate(chain: &[Revision]) -> Result<()> {
    ensure!(
        !chain.is_empty() && chain.len() <= LIMIT,
        "invalid replication history size"
    );
    let mut parent = chain[0].parent;
    for revision in chain {
        ensure!(
            parent == revision.parent && *revision == Revision::new(parent, revision.content),
            "invalid replication lineage"
        );
        parent = revision.id;
    }
    Ok(())
}

/// 业务作用：只在目标确实从活动代向前推进时接受，旧代和分叉不能覆盖本机已应用配置。
/// 参数说明：
/// - `current`：经过持久确认的本地代次链。
/// - `id`：本地链头。
/// - `incoming`：已经验证连续性的对端链。
/// 返回：存在精确共同基线且至少推进一代时为真。
pub(super) fn advance(current: &[Revision], id: Hash, incoming: &[Revision]) -> bool {
    current.last().is_some_and(|local| local.id == id)
        && incoming.iter().any(|revision| revision.parent == id)
}
