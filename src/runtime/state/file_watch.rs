//! 文件动态集合的有界失效提示；文件事实仍由接收方重新读取并完整校验。

use super::{
    decode_dynamic_key, validate_component, validate_dynamic_key, DynamicStoreChange,
    DynamicStoreChangeKind, DynamicStoreWatchGuard, DynamicStoreWatcher, ENCODED_DYNAMIC_KEYS_DIR,
};
use anyhow::{Context, Result};
use notify::Watcher as _;
use parking_lot::Mutex;
use std::path::{Component, Path};
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;

const MAX_SUBSCRIPTIONS: usize = 16;
const MAX_PENDING_CHANGES: usize = 256;
const MAX_EVENT_PATHS: usize = 32;

#[derive(Default)]
pub(super) struct Subscriptions {
    entries: Mutex<Vec<Subscription>>,
}

struct Subscription {
    collection: String,
    sender: Weak<mpsc::Sender<DynamicStoreChange>>,
}

pub(super) struct Guard {
    _watcher: notify::RecommendedWatcher,
    _sender: Arc<mpsc::Sender<DynamicStoreChange>>,
}

impl Subscriptions {
    /// 业务作用：只向仍存活且同集合的读者提供已决定文件变更提示，不等待慢消费者。
    ///
    /// 参数说明：
    /// - `collection`：事实所属集合。
    /// - `key`：已完成写入或删除的业务键。
    /// - `kind`：文件决定的操作类型。
    /// - `notification`：写入者明确提供的有界通知；删除不沿用旧封禁事件。
    ///
    /// 返回：无返回值；满队列仍保留已排队提示并由周期全量对账兜底，不回滚事实。
    pub(super) fn publish(
        &self,
        collection: &str,
        key: &str,
        kind: DynamicStoreChangeKind,
        notification: Option<serde_json::Value>,
    ) {
        self.entries.lock().retain(|entry| {
            let Some(sender) = entry.sender.upgrade() else {
                return false;
            };
            if entry.collection == collection {
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

    /// 业务作用：将受管文件决定和操作系统观察绑定到同一个有界订阅生命周期。
    ///
    /// 参数说明：
    /// - `root`：已选择的本机动态事实根目录。
    /// - `collection`：仅允许单路径组件的集合名称。
    ///
    /// 返回：完整注册后返回接收器；观察初始化或容量失败不保留发送端及原生观察器。
    pub(super) fn watch(&self, root: &Path, collection: &str) -> Result<DynamicStoreWatcher> {
        validate_component(collection, "collection")?;
        let mut subscriptions = self.entries.lock();
        subscriptions.retain(|entry| entry.sender.strong_count() > 0);
        anyhow::ensure!(
            subscriptions.len() < MAX_SUBSCRIPTIONS,
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
        let watched = directory.clone();
        let name = collection.to_owned();
        let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            let Some(sender) = weak.upgrade() else {
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
                let _ = sender.try_send(DynamicStoreChange {
                    collection: name.clone(),
                    key,
                    kind,
                    notification: None,
                });
            }
        })
        .context("create file dynamic watcher")?;
        watcher
            .watch(&directory, notify::RecursiveMode::Recursive)
            .context("watch dynamic collection")?;
        subscriptions.push(Subscription {
            collection: collection.to_owned(),
            sender: Arc::downgrade(&sender),
        });
        Ok(DynamicStoreWatcher {
            rx,
            _guard: DynamicStoreWatchGuard::File {
                _guard: Guard {
                    _watcher: watcher,
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
