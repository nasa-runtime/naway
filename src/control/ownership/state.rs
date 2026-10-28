//! 按配置归属计数的常驻状态名额；条目存活期间持有，不因请求结束或配置换代重置。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use super::{Owner, OwnershipCatalog, ReservationDenied, PLATFORM};

const PROCESS_LIMIT: usize = 4_000_000;

#[derive(Default)]
pub struct Registry {
    owners: parking_lot::Mutex<BTreeMap<String, Weak<Counter>>>,
    total: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct Counter {
    namespace: String,
    used: AtomicUsize,
    total: Arc<AtomicUsize>,
    reclaimers: parking_lot::Mutex<Vec<Weak<dyn ReclaimExpired>>>,
}

/// 工作区内可回收的缓存目录；只允许撤下已过期值，不得清除有效配额或重放证据。
pub(crate) trait ReclaimExpired: Send + Sync + std::fmt::Debug {
    /// 业务作用：在容量压力下回收已失效且不再需要驻留的状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同步撤下过期目录引用；已借给在途请求的值仍持有原名额。
    fn reclaim_expired(&self);
}

/// 名额上限来自冻结快照，计数器跨快照共享；不能用客户端声明构造。
#[derive(Clone, Debug)]
pub struct Budget {
    counter: Arc<Counter>,
    limit: usize,
}

/// 状态的每个共享持有者都属于同一名额，最后一个持有者结束后才归还。
#[derive(Clone, Debug)]
pub struct Lease {
    _entry: Arc<Entry>,
}

#[derive(Debug)]
struct Entry {
    counter: Arc<Counter>,
}

impl Registry {
    /// 业务作用：从已验证目录取得请求归属的状态预算，复用仍有活跃条目的跨代计数器。
    ///
    /// 参数说明：
    /// - `catalog`：为冻结配置
    /// - `owner`：只能来自路由归属目录。
    ///
    /// 返回：平台无需租户预算；目录缺席或退休计数器表满时拒绝，不借用其它域容量。
    pub fn budget(
        &self,
        catalog: &OwnershipCatalog,
        owner: &Owner,
    ) -> Result<Option<Budget>, ReservationDenied> {
        if owner.workspace == PLATFORM {
            return Ok(None);
        }
        if catalog
            .binding(&owner.workspace)
            .is_none_or(|binding| binding.owner != *owner)
        {
            return Err(ReservationDenied);
        }
        let limit = catalog
            .workspaces
            .get(&owner.workspace)
            .ok_or(ReservationDenied)?
            .quota
            .max_state_entries;
        let mut owners = self.owners.lock();
        let key = owner.namespace();
        let counter = if let Some(counter) = owners.get(&key).and_then(Weak::upgrade) {
            counter
        } else {
            owners.retain(|_, counter| counter.strong_count() != 0);
            if owners.len() >= 256 {
                return Err(ReservationDenied);
            }
            let counter = Arc::new(Counter {
                namespace: key.clone(),
                used: AtomicUsize::new(0),
                total: self.total.clone(),
                reclaimers: parking_lot::Mutex::new(Vec::new()),
            });
            owners.insert(key, Arc::downgrade(&counter));
            counter
        };
        Ok(Some(Budget {
            counter,
            limit,
        }))
    }
}

impl Budget {
    /// 业务作用：为同一 Redis 部署与工作区生成同 slot 的状态键和共享容量索引。
    ///
    /// 参数说明：
    /// - `namespace`：为 Redis 配置命名空间
    /// - `kind`：为固定状态类型
    /// - `key`：是业务状态身份。
    ///
    /// 返回：数据键与容量索引，不把业务 key 原文放入 Redis 键；不同部署不共享名额。
    #[cfg(feature = "redis-runtime")]
    pub(crate) fn redis_keys(&self, namespace: &str, kind: &str, key: &str) -> (String, String) {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update((namespace.len() as u64).to_be_bytes());
        hash.update(namespace.as_bytes());
        hash.update(self.counter.namespace.as_bytes());
        let owner = format!("{:x}", hash.finalize());
        let digest = format!("{:x}", Sha256::digest(key.as_bytes()));
        let prefix = format!("gw:workspace:{{{owner}}}:{namespace}");
        (
            format!("{prefix}:{kind}:{digest}"),
            format!("{prefix}:states"),
        )
    }

    /// 业务作用：把工作区缓存写入与远端容量预留合并为同 slot 原子事务。
    ///
    /// 参数说明：
    /// - `client`：为受信 Redis 后端
    /// - `kind`：标识缓存
    /// - `key`：标识缓存
    /// - `value`：为有界编码
    /// - `ttl`：为硬保留期。
    ///
    /// 返回：容量足够则写入并返回 true，容量满返回 false；依赖失败返回错误，不留下无期限名额。
    #[cfg(feature = "redis-runtime")]
    pub(crate) async fn redis_store(
        &self,
        client: &nasa::redis::RedisClient,
        kind: &str,
        key: &str,
        value: &[u8],
        ttl: std::time::Duration,
    ) -> anyhow::Result<bool> {
        const SCRIPT: &str = include_str!("redis/store.lua");
        let (data, index) = self.redis_keys(&client.config().namespace, kind, key);
        let mut command = nasa::redis::RedisCommand::new();
        command
            .arg("EVAL")
            .arg(SCRIPT)
            .arg(2)
            .arg(data)
            .arg(index)
            .arg(ttl.as_millis().clamp(1, i64::MAX as u128) as u64)
            .arg(self.limit)
            .arg(value);
        Ok(client.execute_raw::<i64>(&command).await? == 1)
    }

    /// 业务作用：登记本域有界缓存的弱引用，容量耗尽时允许其它路由触发过期回收。
    ///
    /// 参数说明：
    /// - `reclaimer`：只回收自身已过期状态，不创建新状态或取得额外名额。
    ///
    /// 返回：登记成功返回 true；目录容量不足时返回 false，调用方不得启用新缓存。
    pub(crate) fn register_reclaimer(&self, reclaimer: Arc<dyn ReclaimExpired>) -> bool {
        let mut reclaimers = self.counter.reclaimers.lock();
        reclaimers.retain(|entry| entry.strong_count() != 0);
        let weak = Arc::downgrade(&reclaimer);
        if reclaimers.iter().any(|entry| Weak::ptr_eq(entry, &weak)) {
            return true;
        }
        if reclaimers.len() >= 65_536 {
            return false;
        }
        reclaimers.push(weak);
        true
    }

    /// 业务作用：给共享后端提供稳定归属与独立容量，不使用客户端身份作为 Redis hash tag。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：受信命名空间及该后端的状态上限，供同 slot 原子脚本校验。
    pub(crate) fn remote_scope(&self) -> (&str, usize) {
        (&self.counter.namespace, self.limit)
    }

    /// 业务作用：将后端集合的更小容量叠加到本域总容量，不创建独立可绕过的计数器。
    ///
    /// 参数说明：
    /// - `limit`：为已验证的集合容量。
    ///
    /// 返回：共享相同权威计数、但不能超过任一上限的预算视图。
    #[cfg(feature = "redis-runtime")]
    pub(crate) fn restricted(&self, limit: usize) -> Self {
        Self {
            counter: self.counter.clone(),
            limit: self.limit.min(limit),
        }
    }
    /// 业务作用：在真实状态条目创建前原子预留本域与进程名额，不以 fail-open 绕过内存上界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：双重容量均足够时返回唯一条目凭证；任一不足时保持两个计数不变。
    pub fn acquire(&self) -> Result<Lease, ReservationDenied> {
        if self.used() >= self.limit {
            // 失活路由也可能持有过期缓存；仅访问新路由不能让这些值永久占住本域容量。
            // 回收器只使用 try_lock，避免插件或缓存调用链形成锁顺序反转。
            if let Some(reclaimers) = self.counter.reclaimers.try_lock() {
                for reclaimer in reclaimers.iter().filter_map(Weak::upgrade) {
                    reclaimer.reclaim_expired();
                }
            }
        }
        self.counter
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.limit).then_some(used + 1)
            })
            .map_err(|_| ReservationDenied)?;
        // 退休域仍占进程容量，不能通过反复更名或 reload 形成无界旧代。
        if self
            .counter
            .total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < PROCESS_LIMIT).then_some(used + 1)
            })
            .is_err()
        {
            self.counter.used.fetch_sub(1, Ordering::AcqRel);
            return Err(ReservationDenied);
        }
        Ok(Lease {
            _entry: Arc::new(Entry {
                counter: self.counter.clone(),
            }),
        })
    }

    /// 业务作用：读取当前本域实际状态占用，用于有界控制面摘要。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：包含仍被旧代或在途请求引用的条目数。
    pub fn used(&self) -> usize {
        self.counter.used.load(Ordering::Acquire)
    }
}

impl Drop for Entry {
    /// 业务作用：在状态最后一个引用消失时归还实际内存名额，不提前释放仍可访问的旧代状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本域与进程计数各减少一次。
    fn drop(&mut self) {
        self.counter.used.fetch_sub(1, Ordering::AcqRel);
        self.counter.total.fetch_sub(1, Ordering::AcqRel);
    }
}
