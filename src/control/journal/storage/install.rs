//! 显式存储安装与精确初始化残留续做。

use super::*;

/// 业务作用：按持久安装意图建立首个状态与head，永久标记存在后禁止补齐缺失元数据。
///
/// 参数说明：
/// - `root`：显式维护持有的独占目录。
/// - `identity`：当前完整永久身份。
///
/// 返回：原存储或已完整同步的新存储；任何不符、截断或未知残留均保留并拒绝。
pub(super) fn initialize(root: &Root, identity: &Identity) -> Result<Snapshot> {
    root.inspect(true)?;
    ensure!(
        root.read(super::super::filesystem::INITIALIZING)?.is_none(),
        "node journal identity installation is incomplete"
    );
    if root.read_raw(MARKER, SMALL_LIMIT)?.is_some() {
        // 永久标记说明安装已经结束，任何缺失都只能报告损坏，不能用初始化重置代际。
        let snapshot = load(root, identity)?.context("node journal storage marker disappeared")?;
        root.sync_record(snapshot.head.slot.name(), STATE_LIMIT)?;
        root.sync_record(HEAD, SMALL_LIMIT)?;
        root.sync_record(MARKER, SMALL_LIMIT)?;
        return Ok(snapshot);
    }
    super::super::local::inspect(root, false)?;
    let marker = encode(identity, STORAGE_MAGIC, SMALL_LIMIT)?;
    let intent = root.read_raw(INITIALIZING, SMALL_LIMIT)?;
    if intent.is_none() {
        for name in [HEAD, PENDING, Slot::A.name(), Slot::B.name()] {
            ensure!(
                root.read_raw(name, STATE_LIMIT)?.is_none(),
                "node journal storage installation lacks its original intent"
            );
        }
        root.create(INITIALIZING, &marker)?;
    } else {
        ensure!(
            intent.as_deref() == Some(marker.as_slice()),
            "node journal storage installation intent differs"
        );
        root.sync_record(INITIALIZING, SMALL_LIMIT)?;
    }
    // 尚未发布永久标记的安装只能恢复精确初始状态；其它槽或较新状态意味着不能解释的事实。
    ensure!(
        root.read_raw(Slot::B.name(), STATE_LIMIT)?.is_none(),
        "node journal storage installation has another state slot"
    );
    let state = State::initial(identity);
    let state_bytes = encode(&state, STATE_MAGIC, STATE_LIMIT)?;
    let head = Head::new(&state, Slot::A, &state_bytes);
    let head_bytes = encode(&head, HEAD_MAGIC, SMALL_LIMIT)?;
    let installed = root.read_raw(HEAD, SMALL_LIMIT)?;
    let pending = root.read_raw(PENDING, SMALL_LIMIT)?;
    if let Some(bytes) = &installed {
        ensure!(
            bytes == &head_bytes,
            "node journal storage installation head differs"
        );
    }
    if let Some(bytes) = &pending {
        ensure!(
            bytes == &head_bytes,
            "node journal storage installation pending head differs"
        );
    }
    require_exact(root, Slot::A.name(), &state_bytes, STATE_LIMIT)?;
    if installed.is_none() {
        if pending.is_none() {
            root.create(PENDING, &head_bytes)?;
        } else {
            root.sync_record(PENDING, SMALL_LIMIT)?;
        }
        root.publish_record(PENDING, HEAD)?;
    } else {
        root.sync_record(HEAD, SMALL_LIMIT)?;
        if pending.is_some() {
            root.remove(PENDING)?;
        }
    }
    // 初始状态和head均已持久确认后才能提交永久标记；后续初始化不得跨过此边界重新建库。
    root.publish_record(INITIALIZING, MARKER)?;
    load(root, identity)?.context("node journal storage initialization was not confirmed")
}

/// 业务作用：续做安装仅接受相同完整原文，缺失才创建，部分写入不能被盲目覆盖。
///
/// 参数说明：
/// - `root`：独占目录能力。
/// - `name`：初始状态固定槽名。
/// - `expected`：由原永久身份派生的精确初始记录。
/// - `limit`：对应记录长度上限。
///
/// 返回：原文件完全相同或新文件同步完成；差异保留原文件并拒绝。
fn require_exact(root: &Root, name: &str, expected: &[u8], limit: usize) -> Result<()> {
    match root.read_raw(name, limit)? {
        Some(bytes) => {
            ensure!(
                bytes == expected,
                "node journal storage installation state differs"
            );
            root.sync_record(name, limit)?;
        }
        None => root.create(name, expected)?,
    }
    Ok(())
}
