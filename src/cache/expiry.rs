//! 为 NASA 有界缓存补充按值到期与工作区压力回收，不建立独立缓存事实源。

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

use nasa::cache::local_cache::BoundedLocalCache;
use parking_lot::Mutex;

use crate::control::ownership::state::{Budget, ReclaimExpired};

struct Slot<V> {
    value: Mutex<Option<Arc<V>>>,
    expires: Instant,
}

struct Directory<K, V> {
    by_key: BTreeMap<K, (Instant, Weak<Slot<V>>)>,
    by_time: BTreeSet<(Instant, K)>,
}

struct ExpiryIndex<K, V>(Mutex<Directory<K, V>>);

impl<K, V> std::fmt::Debug for ExpiryIndex<K, V> {
    /// 业务作用：提供不含缓存键和值的目录诊断表示。
    ///
    /// 参数说明：
    /// - `formatter`：为诊断输出目标。
    ///
    /// 返回：只输出类型名称，避免缓存身份和内容泄露。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExpiryIndex")
    }
}

impl<K: Ord + Clone, V> Directory<K, V> {
    /// 业务作用：撤下精确条目并立即释放目录持有的正文与名额，不依赖底层延迟维护。
    ///
    /// 参数说明：
    /// - `key`：为同缓存内稳定键。
    ///
    /// 返回：已借出的 Arc 不受影响；其余驻留值立即退休。
    fn remove(&mut self, key: &K) {
        if let Some((expires, slot)) = self.by_key.remove(key) {
            self.by_time.remove(&(expires, key.clone()));
            if let Some(slot) = slot.upgrade() {
                slot.value.lock().take();
            }
        }
    }

    /// 业务作用：按时间索引回收过期值，每个退休条目只处理一次。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：到期正文与其名额撤下，不扫描仍有效的全部条目。
    fn prune(&mut self) {
        let now = Instant::now();
        while let Some((expires, key)) = self.by_time.first() {
            if *expires > now {
                break;
            }
            let key = key.clone();
            self.remove(&key);
        }
    }
}

impl<K, V> ReclaimExpired for ExpiryIndex<K, V>
where
    K: Ord + Clone + Send + Sync,
    V: Send + Sync,
{
    /// 业务作用：在同工作区其它状态申请容量时尝试回收到期缓存，不等待正在写入的目录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：能取得目录锁则退休过期值，否则交由后续访问或容量申请再试。
    fn reclaim_expired(&self) {
        if let Some(mut directory) = self.0.try_lock() {
            directory.prune();
        }
    }
}

/// NASA TinyLFU 负责缓存准入；索引只保留弱引用并提供精确到期与容量回收。
pub(crate) struct ExpiringCache<K, V> {
    cache: BoundedLocalCache<K, Slot<V>>,
    index: Arc<ExpiryIndex<K, V>>,
    max_entries: usize,
    bound: OnceLock<bool>,
}

impl<K, V> ExpiringCache<K, V>
where
    K: Hash + Ord + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// 业务作用：建立随配置快照存活的有界缓存及同容量过期索引。
    ///
    /// 参数说明：
    /// - `max_entries`：是已验证的正数条目上限。
    ///
    /// 返回：不创建后台任务、不持有业务状态的空缓存。
    pub(crate) fn new(max_entries: u64) -> Self {
        Self {
            cache: BoundedLocalCache::new(max_entries),
            index: Arc::new(ExpiryIndex(Mutex::new(Directory {
                by_key: BTreeMap::new(),
                by_time: BTreeSet::new(),
            }))),
            max_entries: max_entries as usize,
            bound: OnceLock::new(),
        }
    }

    /// 业务作用：只按路由受信归属登记跨路由回收能力，不能由请求内容选择工作区。
    ///
    /// 参数说明：
    /// - `budget`：为冻结配置注入的工作区预算，平台为 None。
    ///
    /// 返回：成功绑定返回 true；回收目录满时返回 false，调用方应绕过缓存。
    pub(crate) fn bind_budget(&self, budget: Option<&Budget>) -> bool {
        *self.bound.get_or_init(|| {
            budget.is_none_or(|budget| budget.register_reclaimer(self.index.clone()))
        })
    }

    /// 业务作用：读取仍在保留期内的共享值，同时回收到期目录项。
    ///
    /// 参数说明：
    /// - `key`：是完整缓存键。
    ///
    /// 返回：有效命中共享 Arc；已退休或到期返回空，不复制正文。
    pub(crate) async fn get(&self, key: &K) -> Option<Arc<V>> {
        self.index.reclaim_expired();
        let slot = self.cache.get(key).await?;
        if slot.expires <= Instant::now() {
            slot.value.lock().take();
            return None;
        }
        let value = slot.value.lock().clone();
        value
    }

    /// 业务作用：发布已取得名额的缓存值，并以精确条目替换与有界索引保证长期回收。
    ///
    /// 参数说明：
    /// - `key`：为完整键
    /// - `value`：为持有自身状态凭证的值
    /// - `expires`：为硬保留截止点。
    ///
    /// 返回：与缓存共享的业务值；并发退休只会造成 miss，不会复活过期值。
    pub(crate) async fn insert(&self, key: K, value: V, expires: Instant) -> Arc<V> {
        let value = Arc::new(value);
        let slot = self
            .cache
            .insert(
                key.clone(),
                Slot {
                    value: Mutex::new(Some(value.clone())),
                    expires,
                },
            )
            .await;
        let mut directory = self.index.0.lock();
        directory.prune();
        directory.remove(&key);
        while directory.by_key.len() >= self.max_entries {
            let Some((_, oldest)) = directory.by_time.first() else {
                break;
            };
            let oldest = oldest.clone();
            directory.remove(&oldest);
        }
        directory
            .by_key
            .insert(key.clone(), (expires, Arc::downgrade(&slot)));
        directory.by_time.insert((expires, key));
        value
    }

    /// 业务作用：撤下指定键对应的正文与状态凭证，再通知 NASA 缓存删除索引。
    ///
    /// 参数说明：
    /// - `key`：为要失效的完整键。
    ///
    /// 返回：后续读为 miss，已借出值在最后引用释放时归还名额。
    pub(crate) async fn invalidate(&self, key: &K) {
        self.index.0.lock().remove(key);
        self.cache.invalidate(key).await;
    }

    /// 业务作用：撤销当前缓存所有值，使 PURGE 无需等待底层维护即可归还未借出名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有值退休，已借出值和在途响应不被截断。
    pub(crate) fn invalidate_all(&self) {
        let mut directory = self.index.0.lock();
        for (_, slot) in directory.by_key.values() {
            if let Some(slot) = slot.upgrade() {
                slot.value.lock().take();
            }
        }
        directory.by_key.clear();
        directory.by_time.clear();
        self.cache.invalidate_all();
    }
}
