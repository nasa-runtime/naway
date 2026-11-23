//! 通过配置声明的精确路径补齐原生文件通知可能遗漏的变更。

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const RECHECK_INTERVAL: Duration = Duration::from_millis(250);

#[derive(PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[derive(Default)]
pub(crate) struct FileObservations {
    stamps: HashMap<PathBuf, Result<Stamp, ErrorKind>>,
}

impl FileObservations {
    /// 业务作用：跟随活动候选的精确目标集合，在换版对账中保留仍受观察目标的基线。
    ///
    /// 参数说明：
    /// - `paths`：当前观察计划声明的路径，可包含尚不存在的目标。
    ///
    /// 返回：新增路径以当前状态为基线，移除路径停止观察。
    pub(crate) fn reconcile<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) {
        let mut previous = std::mem::take(&mut self.stamps);
        self.stamps = paths
            .into_iter()
            .map(|path| {
                let stamp = previous.remove(path).unwrap_or_else(|| read(path));
                (path.to_owned(), stamp)
            })
            .collect();
    }

    /// 业务作用：发现文件创建、删除、原位更新和原子换入，补齐同目录原生通知的遗漏。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：任一目标的元数据或访问状态变化时为真，并推进观察基线。
    pub(crate) fn changed(&mut self) -> bool {
        let mut changed = false;
        for (path, previous) in &mut self.stamps {
            let current = read(path);
            changed |= *previous != current;
            *previous = current;
        }
        changed
    }
}

/// 业务作用：观察部署路径当前指向的文件，区分同名替换和访问错误，无需读取正文或扫描目录。
///
/// 参数说明：
/// - `path`：配置声明的精确文件路径。
///
/// 返回：当前文件身份和更新时间，目标不可访问时返回错误类型供下一轮对比。
fn read(path: &Path) -> Result<Stamp, ErrorKind> {
    let metadata = fs::metadata(path).map_err(|error| error.kind())?;
    Ok(Stamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}
