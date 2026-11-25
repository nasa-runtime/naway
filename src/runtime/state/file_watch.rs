//! 文件动态集合的有界失效提示；文件事实仍由接收方重新读取并完整校验。

use super::{
    decode_dynamic_key, validate_component, validate_dynamic_key, DynamicStoreChange,
    DynamicStoreChangeKind, DynamicStoreWatchGuard, DynamicStoreWatcher, ENCODED_DYNAMIC_KEYS_DIR,
    MAX_DYNAMIC_KEYS,
};
use anyhow::{ensure, Context, Result};
use notify::Watcher as _;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

const MAX_SUBSCRIPTIONS: usize = 16;
const MAX_PENDING_CHANGES: usize = 256;
const MAX_EVENT_PATHS: usize = 32;
const FILE_RECONCILE_INTERVAL: Duration = Duration::from_millis(500);

static FILE_SUBSCRIPTIONS: Mutex<Vec<Subscription>> = parking_lot::const_mutex(Vec::new());

#[derive(Clone, Default)]
pub(super) struct Subscriptions {
    owner: Arc<()>,
}

struct Subscription {
    directory: PathBuf,
    collection: String,
    owner: Weak<()>,
    sender: Weak<mpsc::Sender<DynamicStoreChange>>,
}

pub(super) struct Guard {
    _watcher: Option<notify::RecommendedWatcher>,
    _reconcile: AbortOnDropHandle<()>,
    _sender: Arc<mpsc::Sender<DynamicStoreChange>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    changed: (i64, i64),
    modified: (i64, i64),
    size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryStamp {
    plain: Option<FileStamp>,
    encoded: Option<FileStamp>,
}

struct Snapshot {
    directories: DirectoryStamp,
    files: BTreeMap<String, FileStamp>,
}

impl FileStamp {
    /// 业务作用：标识一次替换或同一文件的元数据变化，提示订阅方重新读取实际事实。
    ///
    /// 参数说明：
    /// - `metadata`：已观察到的本地普通文件或目录元数据。
    ///
    /// 返回：文件系统身份、变更时刻和长度，不打开文件、不读取业务正文。
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            size: metadata.len(),
        }
    }
}

impl DirectoryStamp {
    /// 业务作用：廉价检查两级事实目录，普通周期只观察目录，受管原子写入才触发重建集合。
    ///
    /// 参数说明：
    /// - `directory`：已规范化的订阅集合目录。
    ///
    /// 返回：两级目录各自的身份，缺失记录为空。权限、类型或读取错误不能当成集合清空。
    fn read(directory: &Path) -> Result<Self> {
        let plain = directory_stamp(directory)?;
        let encoded = if plain.is_some() {
            directory_stamp(&directory.join(ENCODED_DYNAMIC_KEYS_DIR))?
        } else {
            None
        };
        Ok(Self {
            plain,
            encoded,
        })
    }
}

/// 业务作用：拒绝把符号链接和普通文件当作动态事实目录，防止对账沿错误路径解释文件。
///
/// 参数说明：
/// - `path`：集合目录或其编码键子目录。
///
/// 返回：确认目录时给出身份，路径缺席时为空，其它错误保留给上层重试。
fn directory_stamp(path: &Path) -> Result<Option<FileStamp>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(metadata.is_dir(), "dynamic file watch expected a directory");
            Ok(Some(FileStamp::from_metadata(&metadata)))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read dynamic directory identity"),
    }
}

impl Snapshot {
    /// 业务作用：从两个固定目录重建有界键级事实身份，弥补原生观察器遗漏的进程间原子替换。
    ///
    /// 参数说明：
    /// - `directory`：已固定的订阅集合目录。
    /// - `previous`：上轮已完成发送的目录身份。
    ///
    /// 返回：目录未变时为空。变更后返回一致身份，扫描时遇到并发修改或超出预算时拒绝本轮。
    fn read(directory: &Path, previous: Option<DirectoryStamp>) -> Result<Option<Self>> {
        let directories = DirectoryStamp::read(directory)?;
        if previous == Some(directories) {
            return Ok(None);
        }
        let mut files = BTreeMap::new();
        let mut scanned = 0;
        let encoded = directory.join(ENCODED_DYNAMIC_KEYS_DIR);
        for (path, present) in [
            (directory, directories.plain),
            (encoded.as_path(), directories.encoded),
        ] {
            if present.is_none() {
                continue;
            }
            for entry in fs::read_dir(path).context("scan watched dynamic directory")? {
                scanned += 1;
                // 只扫描已知两级目录，非业务项也占扫描预算；在途目录及符号链接不产生键提示。
                ensure!(
                    scanned <= MAX_DYNAMIC_KEYS + 2,
                    "dynamic file watch scan limit exceeded"
                );
                let entry = entry?;
                let Some(key) = business_key(directory, &entry.path()) else {
                    continue;
                };
                let metadata = entry.metadata()?;
                if !metadata.is_file() {
                    continue;
                }
                // 编码目录只拥有无法用普通组件保存的业务键，避免人为别名盖过真实键的身份。
                if path == encoded
                    && validate_component(&key, "key").is_ok()
                    && key != ENCODED_DYNAMIC_KEYS_DIR
                {
                    continue;
                }
                files.insert(key, FileStamp::from_metadata(&metadata));
            }
        }
        // 只比较完整目录，避免把扫描中途的写入解释成删除并推进对账水位。
        ensure!(
            DirectoryStamp::read(directory)? == directories,
            "dynamic directory changed during scan"
        );
        Ok(Some(Self {
            directories,
            files,
        }))
    }

    /// 业务作用：只推进已进入有界队列的事实变化，拥塞解除后继续同一批剩余键。
    ///
    /// 参数说明：
    /// - `next`：本次完整目录扫描结果。
    /// - `collection`：订阅绑定的集合名。
    /// - `sender`：发送失效提示的有界通道。
    ///
    /// 返回：队列有空间时逐键推进。队列满时保留未交付键的旧身份，下一次继续。
    fn reconcile(
        &mut self,
        next: &Self,
        collection: &str,
        sender: &mpsc::Sender<DynamicStoreChange>,
    ) {
        let mut full = false;
        self.files.retain(|key, _| {
            if next.files.contains_key(key) || full {
                return true;
            }
            full = !send_change(sender, collection, key, DynamicStoreChangeKind::Delete);
            full
        });
        if full {
            return;
        }
        for (key, stamp) in &next.files {
            if self.files.get(key) == Some(stamp) {
                continue;
            }
            if !send_change(sender, collection, key, DynamicStoreChangeKind::Put) {
                return;
            }
            self.files.insert(key.clone(), *stamp);
        }
        self.directories = next.directories;
    }
}

/// 业务作用：投递由文件身份变化派生的低频提示，业务方仍须重读事实。
///
/// 参数说明：
/// - `sender`：集合当前订阅的有界通道。
/// - `collection`：订阅注册的集合名。
/// - `key`：已校验的文件业务键。
/// - `kind`：扫描观察到的新增、替换或删除类型。
///
/// 返回：提示已入队时为真。拥塞或接收方已退出时为假。
fn send_change(
    sender: &mpsc::Sender<DynamicStoreChange>,
    collection: &str,
    key: &str,
    kind: DynamicStoreChangeKind,
) -> bool {
    sender
        .try_send(DynamicStoreChange {
            collection: collection.to_owned(),
            key: key.to_owned(),
            kind,
            notification: None,
        })
        .is_ok()
}

/// 业务作用：在独立文件观察丢事件或启动失败时，持续核对受管原子写入的最终事实身份。
///
/// 参数说明：
/// - `directory`：订阅固定的文件集合。
/// - `collection`：发给接收方的原集合名称。
/// - `sender`：只在交付轮临时持有的弱引用。
/// - `current`：启动时可读取的初始集合身份。
///
/// 返回：订阅结束时退出。阻塞池至多有一个有界扫描在途，本轮非一致结果不会推进水位。
async fn reconcile_files(
    directory: Arc<Path>,
    collection: String,
    sender: Weak<mpsc::Sender<DynamicStoreChange>>,
    mut current: Option<Snapshot>,
) {
    let mut retry = false;
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + FILE_RECONCILE_INTERVAL,
        FILE_RECONCILE_INTERVAL,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let path = directory.clone();
        let previous = current.as_ref().map(|snapshot| snapshot.directories);
        let next = tokio::task::spawn_blocking(move || Snapshot::read(&path, previous)).await;
        let Some(sender) = sender.upgrade() else {
            return;
        };
        match next {
            Ok(Ok(Some(next))) => {
                if let Some(current) = current.as_mut() {
                    current.reconcile(&next, &collection, &sender);
                } else {
                    current = Some(next);
                }
                retry = false;
            }
            Ok(Ok(None)) => {
                retry = false;
            }
            _ if !retry => {
                tracing::warn!(%collection, "file dynamic reconciliation postponed");
                retry = true;
            }
            _ => {}
        }
    }
}

/// 业务作用：向进程内共享同一文件集合的订阅者发送已落盘的变更，避免依赖原生事件传递受管写入。
///
/// 参数说明：
/// - `root`：写入者使用的动态事实根目录。
/// - `collection`：事实所属集合。
/// - `key`：已完成写入或删除的业务键。
/// - `kind`：文件决定的操作类型。
/// - `notification`：写入者明确提供的有界通知；删除不沿用旧通知。
///
/// 返回：无；目录不可定位或队列满时由原生观察与周期对账补偿，已落盘决定继续有效。
pub(super) fn publish(
    root: &Path,
    collection: &str,
    key: &str,
    kind: DynamicStoreChangeKind,
    notification: Option<serde_json::Value>,
) {
    let Ok(directory) = root.join(collection).canonicalize() else {
        return;
    };
    FILE_SUBSCRIPTIONS.lock().retain(|entry| {
        let Some(sender) = entry.sender.upgrade() else {
            return false;
        };
        if entry.directory == directory && entry.collection == collection {
            let _ = sender.try_send(DynamicStoreChange {
                collection: collection.to_owned(),
                key: key.to_owned(),
                kind,
                notification: notification.clone(),
            });
        }
        true
    });
}

impl Subscriptions {
    /// 业务作用：将受管文件决定和操作系统观察绑定到同一个有界订阅生命周期。
    ///
    /// 参数说明：
    /// - `root`：已选择的本机动态事实根目录。
    /// - `collection`：仅允许单路径组件的集合名称。
    ///
    /// 返回：完整注册后返回接收器；原生观察不可用时继续按目录重新对账，容量不足时拒绝注册。
    pub(super) fn watch(&self, root: &Path, collection: &str) -> Result<DynamicStoreWatcher> {
        validate_component(collection, "collection")?;
        let owner = Arc::downgrade(&self.owner);
        let mut subscriptions = FILE_SUBSCRIPTIONS.lock();
        subscriptions.retain(|entry| entry.sender.strong_count() > 0);
        anyhow::ensure!(
            subscriptions
                .iter()
                .filter(|entry| entry.owner.ptr_eq(&owner))
                .count()
                < MAX_SUBSCRIPTIONS,
            "file dynamic subscriptions full"
        );
        let directory = root.join(collection);
        std::fs::create_dir_all(&directory).context("create watched dynamic collection")?;
        let directory = directory
            .canonicalize()
            .context("locate watched dynamic collection")?;
        let (sender, rx) = mpsc::channel(MAX_PENDING_CHANGES);
        let sender = Arc::new(sender);
        let weak = Arc::downgrade(&sender);
        let native_sender = weak.clone();
        let watched = directory.clone();
        let name = collection.to_owned();
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            let Some(sender) = native_sender.upgrade() else {
                return;
            };
            let event = match event {
                Ok(event) => event,
                Err(error) => {
                    tracing::warn!(error = %error, "file dynamic watch failed; interval reconciliation retained");
                    return;
                }
            };
            if !matches!(
                event.kind,
                notify::EventKind::Create(_)
                    | notify::EventKind::Modify(_)
                    | notify::EventKind::Remove(_)
            ) {
                return;
            }
            for path in event.paths.iter().take(MAX_EVENT_PATHS) {
                let Some(key) = business_key(&watched, path) else {
                    continue;
                };
                let kind = if path.is_file() {
                    DynamicStoreChangeKind::Put
                } else {
                    DynamicStoreChangeKind::Delete
                };
                send_change(&sender, &name, &key, kind);
            }
        })
        .and_then(|mut watcher| {
            watcher.watch(&directory, notify::RecursiveMode::Recursive)?;
            Ok(watcher)
        });
        let watcher = match watcher {
            Ok(watcher) => Some(watcher),
            Err(error) => {
                tracing::warn!(%collection, %error, "file dynamic native watch unavailable; directory reconciliation active");
                None
            }
        };
        subscriptions.push(Subscription {
            directory: directory.clone(),
            collection: collection.to_owned(),
            owner,
            sender: Arc::downgrade(&sender),
        });
        drop(subscriptions);
        // 首次读失败时保持基线未知，不能把尚未观察的旧文件解释成已新增或已删除。
        let baseline = Snapshot::read(&directory, None).ok().flatten();
        let reconcile = AbortOnDropHandle::new(tokio::spawn(reconcile_files(
            Arc::from(directory.as_path()),
            collection.to_owned(),
            weak,
            baseline,
        )));
        Ok(DynamicStoreWatcher {
            rx,
            _guard: DynamicStoreWatchGuard::File {
                _guard: Guard {
                    _watcher: watcher,
                    _reconcile: reconcile,
                    _sender: sender,
                },
            },
        })
    }
}

/// 业务作用：仅将当前集合的真实键路径转换为失效提示，忽略目录和在途文件。
///
/// 参数说明：
/// - `directory`：订阅建立时固定的集合目录。
/// - `path`：原生观察器提供的变更路径。
///
/// 返回：合法普通键或编码键；越界、额外层级、非UTF-8及未知编码返回None。
fn business_key(directory: &Path, path: &Path) -> Option<String> {
    let mut parts = path.strip_prefix(directory).ok()?.components();
    let Component::Normal(first) = parts.next()? else {
        return None;
    };
    let first = first.to_str()?;
    let key = if first == ENCODED_DYNAMIC_KEYS_DIR {
        let Component::Normal(name) = parts.next()? else {
            return None;
        };
        decode_dynamic_key(name.to_str()?).ok()?
    } else {
        first.to_owned()
    };
    if parts.next().is_some() || validate_dynamic_key(&key).is_err() {
        return None;
    }
    Some(key)
}
