//! 以原子head为唯一提交权威的节点受理代际。

#[cfg(feature = "node-actions")]
pub(super) mod actions;
mod install;
mod record;

use super::{filesystem::Root, identity::Identity};
use anyhow::{ensure, Context, Result};
use record::{
    decode, encode, Head, Slot, State, HEAD_MAGIC, SMALL_LIMIT, STATE_LIMIT, STATE_MAGIC,
    STORAGE_MAGIC,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;

const MARKER: &str = "storage";
const INITIALIZING: &str = ".storage-initializing";
const HEAD: &str = "head";
const PENDING: &str = ".head-pending";

/// 当前已提交的存储事实；owner只承认自己的完整持久转换，拒绝外部换代。
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    head: Head,
    state: State,
}

/// 只读代际及比较令牌；不声明动作收据或配置已经应用。
#[derive(Serialize)]
pub(super) struct Status {
    revision: u64,
    admission_epoch: u64,
    closed_epoch: u64,
    compare_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_publication: Option<super::local::Status>,
}

impl Snapshot {
    /// 业务作用：提供当前选中提交的单调序号，供只读管理观察区分文件决定的推进。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：经过head完整验证的revision，不包含可用于维护的比较令牌。
    pub(super) fn revision(&self) -> u64 {
        self.state.revision
    }

    /// 业务作用：向同一目录owner提供已提交受理代际，未提交槽不能影响节点报告。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前head选择状态的正代际，外层仍须复验目录没有被替换。
    pub(super) fn admission_epoch(&self) -> u64 {
        self.state.admission_epoch
    }

    /// 业务作用：导出有界低敏存储状态，维护请求必须沿用同一提交令牌。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前revision、受理代际、关闭水位及比较令牌。
    pub(super) fn status(&self) -> Status {
        Status {
            revision: self.state.revision,
            admission_epoch: self.state.admission_epoch,
            closed_epoch: self.state.closed_epoch,
            compare_token: self.head.token(),
            local_publication: self.local().map(super::local::Status::from_plan),
        }
    }

    /// 业务作用：提供当前head选中的本地文件决定，未提交槽中的记录不参与恢复。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前唯一文件决定的借用；空表示没有未决本地发布。
    pub(super) fn local(&self) -> Option<&super::local::Plan> {
        self.state.local_publication.as_ref()
    }

    /// 业务作用：要求离线维护请求绑定完整当前提交，旧令牌不能改变文件方向。
    ///
    /// 参数说明：
    /// - `expected`：调用者从只读状态取得的完整比较令牌。
    ///
    /// 返回：令牌与当前head一致时成功，否则拒绝。
    pub(super) fn compare(&self, expected: &str) -> Result<()> {
        ensure!(
            expected == self.head.token(),
            "node journal storage compare token differs"
        );
        Ok(())
    }
}

/// 业务作用：限定存储目录的精确文件名，不能把任意动作标识当成可访问路径。
///
/// 参数说明：
/// - `name`：目录枚举取得的单一文件名。
/// - `initializing`：是否为允许处理初始化意图的显式维护。
///
/// 返回：当前格式可解释的文件名返回true，未知目录项始终拒绝。
pub(super) fn known(name: &OsStr, initializing: bool) -> bool {
    [MARKER, HEAD, PENDING, Slot::A.name(), Slot::B.name()]
        .iter()
        .any(|candidate| name == OsStr::new(candidate))
        || (initializing && name == OsStr::new(INITIALIZING))
        || super::local::known(name)
}

/// 业务作用：只按已提交head读取状态，较新但未提交的槽不能获得受理权威。
///
/// 参数说明：
/// - `root`：已经取得的固定目录能力。
/// - `identity`：该目录的永久节点绑定。
///
/// 返回：身份模式返回空，存储模式返回同一提交的完整事实；损坏或连续换代时拒绝。
pub(super) fn load(root: &Root, identity: &Identity) -> Result<Option<Snapshot>> {
    root.inspect(false)?;
    let Some(marker) = root.read_raw(MARKER, SMALL_LIMIT)? else {
        super::local::inspect(root, false)?;
        for name in [HEAD, PENDING, Slot::A.name(), Slot::B.name()] {
            // 未安装永久存储标记的动作记录不能冒充identity-only目录，也不能由普通启动收尾。
            ensure!(
                root.read_raw(name, STATE_LIMIT)?.is_none(),
                "node journal storage installation is incomplete"
            );
        }
        return Ok(None);
    };
    require_marker(&marker, identity)?;
    let mut observed_head = false;
    for _ in 0..3 {
        let Some(first) = root.read_raw(HEAD, SMALL_LIMIT)? else {
            continue;
        };
        observed_head = true;
        let selected = read_selected(root, identity, &first);
        let Some(second) = root.read_raw(HEAD, SMALL_LIMIT)? else {
            continue;
        };
        if first == second {
            return selected.map(Some);
        }
        // 读状态期间可能跨越两次换槽；先确认head没有变化，才能把状态读取错误判为损坏。
    }
    ensure!(observed_head, "node journal storage head is absent");
    anyhow::bail!("node journal storage status is busy")
}

/// 业务作用：验证head选择的完整状态和其余固定文件边界，不让未提交内容影响恢复方向。
///
/// 参数说明：
/// - `root`：固定存储目录。
/// - `identity`：永久节点身份。
/// - `bytes`：本次读取冻结的head原文。
///
/// 返回：head与状态身份、revision及摘要一致时成功；未知字段、缺失或损坏拒绝。
fn read_selected(root: &Root, identity: &Identity, bytes: &[u8]) -> Result<Snapshot> {
    let head: Head = decode(bytes, HEAD_MAGIC, SMALL_LIMIT)?;
    ensure!(
        head.identity == *identity,
        "node journal head binding differs"
    );
    let bytes = root
        .read_raw(head.slot.name(), STATE_LIMIT)?
        .context("node journal selected state is absent")?;
    ensure!(
        Sha256::digest(&bytes)[..] == head.sha256,
        "node journal selected state digest differs"
    );
    let state: State = decode(&bytes, STATE_MAGIC, STATE_LIMIT)?;
    state.validate(identity)?;
    ensure!(
        head.revision == state.revision,
        "node journal head revision differs"
    );
    // 未提交槽允许保留中断写入，但仍必须是有界私有普通文件，不能借残留绕过目录安全边界。
    root.read_raw(head.slot.other().name(), STATE_LIMIT)?;
    root.read_raw(PENDING, SMALL_LIMIT)?;
    super::local::inspect(root, true)?;
    Ok(Snapshot {
        head,
        state,
    })
}

/// 业务作用：确认永久存储标记仍属于原目录，损坏或其它节点标记不能触发重新初始化。
///
/// 参数说明：
/// - `bytes`：永久标记或安装意图的完整原文。
/// - `identity`：目录永久身份。
///
/// 返回：同一身份且格式完整时成功，否则保留原文件并拒绝。
fn require_marker(bytes: &[u8], identity: &Identity) -> Result<()> {
    let marker: Identity = decode(bytes, STORAGE_MAGIC, SMALL_LIMIT)?;
    ensure!(marker == *identity, "node journal storage binding differs");
    Ok(())
}

/// 业务作用：显式安装受理代际存储，既有永久标记只复验而不重建缺失事实。
///
/// 参数说明：
/// - `root`：已取得独占锁的固定目录。
/// - `identity`：已有完整永久节点绑定。
///
/// 返回：完整初始或原有存储状态；安装残留只有符合精确初始事实才能续做。
pub(super) fn initialize(root: &Root, identity: &Identity) -> Result<Snapshot> {
    install::initialize(root, identity)
}

/// 业务作用：离线关闭当前受理代际，原令牌重投不能重复推进水位或重新开放旧请求。
///
/// 参数说明：
/// - `root`：整个维护期间独占的目录。
/// - `identity`：原永久节点绑定。
/// - `expected`：调用方从只读状态取得的revision与SHA-256令牌。
///
/// 返回：完整同步后的新状态；比较冲突或溢出拒绝，I/O失败必须回读提交事实。
pub(super) fn close_epoch(root: &Root, identity: &Identity, expected: &str) -> Result<Snapshot> {
    let current =
        load(root, identity)?.context("node journal action storage is not initialized")?;
    current.compare(expected)?;
    // 未决文件决定仍依赖当前受理事实，维护不能通过推进代际抹去其正文与恢复权威。
    ensure!(
        current.local().is_none(),
        "node journal has a pending local publication"
    );
    #[cfg(feature = "node-actions")]
    ensure!(
        current.action().is_none(),
        "node journal has a retained action"
    );
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.admission_epoch = state
        .admission_epoch
        .checked_add(1)
        .context("node journal admission epoch exhausted")?;
    state.closed_epoch = current.state.admission_epoch;
    commit(root, identity, &current, state)
}

/// 业务作用：把本地文件方向作为新的持久状态提交，受理代际和关闭水位保持原事实。
///
/// 参数说明：
/// - `root`：唯一owner持有的目录。
/// - `identity`：永久节点绑定。
/// - `current`：该owner当前承认的完整提交。
/// - `plan`：新的本地文件决定，空表示经过完整确认后结束。
///
/// 返回：全部同步完成的新状态；失败不提供可承认的新权威，调用方必须保留原期望。
pub(super) fn transition(
    root: &Root,
    identity: &Identity,
    current: &Snapshot,
    plan: Option<super::local::Plan>,
) -> Result<Snapshot> {
    let mut state = current.state.clone();
    state.revision = state
        .revision
        .checked_add(1)
        .context("node journal revision exhausted")?;
    state.local_publication = plan;
    commit(root, identity, current, state)
}

/// 业务作用：恢复执行前确认所选head及状态已经持久化，进程重启后可见记录不等于上次同步成功。
///
/// 参数说明：
/// - `root`：已独占的固定目录。
/// - `identity`：永久节点绑定。
/// - `current`：本次owner选中且准备执行的完整状态。
///
/// 返回：同一事实的状态、head、标记与目录均同步且复验一致；失败不得执行文件副作用。
pub(super) fn confirm(root: &Root, identity: &Identity, current: &Snapshot) -> Result<()> {
    ensure!(
        load(root, identity)?.as_ref() == Some(current),
        "node journal storage changed before confirmation"
    );
    root.sync_record(current.head.slot.name(), STATE_LIMIT)?;
    root.sync_record(HEAD, SMALL_LIMIT)?;
    root.sync_record(MARKER, SMALL_LIMIT)?;
    ensure!(
        load(root, identity)?.as_ref() == Some(current),
        "node journal storage changed during confirmation"
    );
    Ok(())
}

/// 业务作用：复验当前事实后提交下一状态，先完整持久化正文槽再切换唯一head。
///
/// 参数说明：
/// - `root`：整个提交期间独占的目录。
/// - `identity`：该目录的永久身份。
/// - `current`：调用方已经承认的当前状态。
/// - `state`：待提交的下一状态。
///
/// 返回：head和目录同步完成后提供新快照；任何失败保留未知提交语义。
fn commit(root: &Root, identity: &Identity, current: &Snapshot, state: State) -> Result<Snapshot> {
    ensure!(
        load(root, identity)?.as_ref() == Some(current),
        "node journal storage changed before commit"
    );
    state.validate(identity)?;
    let slot = current.head.slot.other();
    let bytes = encode(&state, STATE_MAGIC, STATE_LIMIT)?;
    let head = Head::new(&state, slot, &bytes);
    let head_bytes = encode(&head, HEAD_MAGIC, SMALL_LIMIT)?;
    // 上次rename后若目录同步报错，回读只能证明当前可见；复用旧槽前先确认当前head及其状态已持久化。
    confirm(root, identity, current)?;
    // 只有已提交head之外的固定空间允许回收；当前状态在新head持久提交前始终保留。
    discard_uncommitted(root, slot.name(), STATE_LIMIT)?;
    discard_uncommitted(root, PENDING, SMALL_LIMIT)?;
    root.create(slot.name(), &bytes)?;
    root.create(PENDING, &head_bytes)?;
    // 水位必须先成为持久提交事实，调用方才能确认旧代际已关闭；同步错误保持未知提交语义。
    root.publish_record(PENDING, HEAD)?;
    Ok(Snapshot {
        head,
        state,
    })
}

/// 业务作用：回收不具提交权威的固定槽，未知名称和当前槽由调用方协议禁止传入。
///
/// 参数说明：
/// - `root`：当前独占目录。
/// - `name`：非当前状态槽或head暂存名。
/// - `limit`：相应记录的长度边界。
///
/// 返回：缺失或已确认移除时成功；类型、权限、长度或同步异常拒绝后续写入。
fn discard_uncommitted(root: &Root, name: &str, limit: usize) -> Result<()> {
    if root.read_raw(name, limit)?.is_some() {
        root.remove(name)?;
    }
    Ok(())
}
