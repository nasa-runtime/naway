//! 六个私有固定正文槽，正文和恢复复制始终使用有界流式访问。

use super::{
    model::{Body, Plan, BODY_NAMES, LIMIT},
    prepare::Prepared,
};
use crate::control::{documents::Fingerprint, journal::filesystem::Root};
use anyhow::{ensure, Context, Result};
use std::{
    ffi::OsStr,
    io::{Read, Seek, SeekFrom, Write},
};

/// 业务作用：识别本地文件决定的固定正文空间，任何业务标识不能扩大journal白名单。
///
/// 参数说明：
/// - `name`：目录枚举取得的文件名。
///
/// 返回：仅六个协议固定正文名字返回真。
pub(in crate::control::journal) fn known(name: &OsStr) -> bool {
    BODY_NAMES
        .iter()
        .any(|candidate| name == OsStr::new(candidate))
}

/// 业务作用：只检查固定正文空间的类型、权限和长度，状态观察不分配或哈希全部大正文。
///
/// 参数说明：
/// - `root`：已经固定的私有journal目录。
/// - `installed`：是否已有永久存储标记。
///
/// 返回：全部槽有界且私有时成功；未安装存储却有正文时拒绝，不声明正文完整性。
pub(in crate::control::journal) fn inspect(root: &Root, installed: bool) -> Result<()> {
    for name in BODY_NAMES {
        let file = root.open_record(name, LIMIT)?;
        ensure!(
            installed || file.is_none(),
            "node journal bodies require initialized storage"
        );
    }
    Ok(())
}

/// 业务作用：Preparing提交后写入全部必要正文，完整同步和摘要复验之前不得授权配置副作用。
///
/// 参数说明：
/// - `root`：当前owner持有的私有目录。
/// - `prepared`：已提交计划对应的有限原文来源。
///
/// 返回：全部正文和目录已同步且摘要相同时成功；失败保留Preparing及精确残留。
pub(in crate::control::journal) fn write(root: &Root, prepared: &mut Prepared<'_>) -> Result<()> {
    for (body, source) in &mut prepared.sources {
        let mut file = root.create_file(body.name())?;
        let fingerprint = copy(source, &mut file)?;
        ensure!(
            fingerprint == body.fingerprint,
            "local publication body source changed"
        );
        file.sync_all()?;
        root.sync()?;
    }
    verify(root, &prepared.plan)
}

/// 业务作用：恢复或完成之前核验全部被引用原文，不能先改部分文件再发现另一份证据损坏。
///
/// 参数说明：
/// - `root`：固定私有正文目录。
/// - `plan`：已选head中的完整决定。
///
/// 返回：全部引用正文长度和SHA-256一致；缺失或差异拒绝且没有文件修改。
pub(super) fn verify(root: &Root, plan: &Plan) -> Result<()> {
    for body in plan.bodies().into_iter().flatten() {
        open(root, body)?;
    }
    Ok(())
}

/// 业务作用：打开并完整验证一份权威正文，再交给恢复复制，避免使用未知或部分内容。
///
/// 参数说明：
/// - `root`：持久目录能力。
/// - `body`：经过计划校验的固定正文引用。
///
/// 返回：完整摘要一致且位于起点的私有文件句柄；任何缺失或差异拒绝。
pub(super) fn open(root: &Root, body: Body) -> Result<cap_std::fs::File> {
    let mut file = root
        .open_record(body.name(), LIMIT)?
        .context("local publication body is absent")?;
    ensure!(
        Fingerprint::read(&mut file)? == body.fingerprint,
        "local publication body integrity differs"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// 业务作用：依据已提交Idle或Preparing的无配置副作用事实回收固定正文空间，不使用递归删除。
///
/// 参数说明：
/// - `root`：当前独占目录，调用方已经确认没有需保留的正文引用。
///
/// 返回：六个固定普通私有槽全部缺失或已同步删除；异常保留保护状态。
pub(in crate::control::journal) fn clear(root: &Root) -> Result<()> {
    inspect(root, true)?;
    for name in BODY_NAMES {
        if root.open_record(name, LIMIT)?.is_some() {
            root.remove(name)?;
        }
    }
    Ok(())
}

/// 业务作用：以固定缓冲复制并同时生成完整摘要，任何输入增长均受文档上限限制。
///
/// 参数说明：
/// - `source`：位于正文起点的原始输入。
/// - `destination`：已经按协议排他取得的输出句柄。
///
/// 返回：实际复制原文的长度与SHA-256；失败不声明输出已完整或持久。
pub(super) fn copy(source: &mut impl Read, destination: &mut impl Write) -> Result<Fingerprint> {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 16384];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length += count as u64;
        ensure!(
            length <= LIMIT as u64,
            "local publication body exceeds limit"
        );
        destination.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    Ok(Fingerprint {
        length,
        sha256: hash.finalize().into(),
    })
}
