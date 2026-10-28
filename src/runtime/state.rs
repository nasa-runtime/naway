//! 运行态动态数据与限流接口。低频事实支持 file、Redis 与 Nacos，令牌结算支持 local/Redis；
//! 所有远端 I/O 都在请求转发契约之外保持有界并显式失败。

mod buckets;

#[cfg(feature = "nacos-sdk")]
use std::collections::BTreeMap;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
#[cfg(feature = "nacos-sdk")]
use base64::Engine as _;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
#[cfg(feature = "redis-runtime")]
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::config::model::RuntimeStateCfg;
use crate::config::resolve_relative;

/// 动态集合存储:黑名单、临时禁用、动态规则等低频运行态事实源。
pub trait DynamicStore: Send + Sync {
    /// 业务作用：读取按工作区隔离的派生缓存；持久文档后端仍由值内过期合同裁决。
    ///
    /// 参数说明：
    /// - `collection`：已包含受信归属
    /// - `key`：已包含受信归属
    /// - `budget`：供具备 TTL 的后端定位共享容量域。
    ///
    /// 返回：有界缓存值或缺失/依赖错误，不构造默认授权结果。
    fn get_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        let _ = budget;
        self.get(collection, key)
    }

    /// 业务作用：写入有界派生缓存；文档后端按隔离集合限制条目，TTL 后端同时自动回收过期数据。
    ///
    /// 参数说明：
    /// - `collection`：为受信缓存域
    /// - `key`：为受信缓存域
    /// - `value`：含自描述过期时间
    /// - `max_entries`：是容量与保留期
    /// - `ttl`：是容量与保留期
    /// - `budget`：是本域总预算。
    ///
    /// 返回：原子容量判定结果或依赖错误，满载只跳过缓存。
    #[allow(clippy::too_many_arguments)]
    fn put_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        let _ = (ttl, budget);
        self.put_if_capacity(collection, key, value, max_entries)
    }

    /// 业务作用：撤下已判定不可用的缓存；删除不产生任何授权事实。
    ///
    /// 参数说明：
    /// - `collection`：为本域缓存定位
    /// - `key`：为本域缓存定位
    /// - `budget`：决定后端隔离键。
    ///
    /// 返回：幂等删除结果；失败时调用方仍按 miss 重新授权。
    fn delete_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<()>> {
        let _ = budget;
        self.delete(collection, key)
    }
    /// 业务作用：读取 collection 中一个 key；不存在返回 `None`。
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>>;

    /// 业务作用：原子创建或覆盖 collection 中一个 key。
    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>>;

    /// 业务作用：删除一个 key；不存在时也视为成功。
    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>>;

    /// 业务作用：列出 collection 当前全部 key；只供低频控制面刷新使用。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>>;

    /// 业务作用：原子写入一个有容量上限的 collection。已存在 key 始终允许覆盖；新 key 只有在当前
    /// field 数小于 `max_entries` 时写入。门户等 admission 场景不得用 get/list/put 拼事务。
    fn put_if_capacity<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>>;

    /// 业务作用：订阅 collection 变更；不支持事件流的后端返回 `None` 并由调用方轮询。
    fn watch<'a>(
        &'a self,
        collection: &'a str,
    ) -> StoreFuture<'a, Result<Option<DynamicStoreWatcher>>> {
        let _ = collection;
        Box::pin(async {
            Ok(None)
        })
    }
}

/// 动态存储后端返回 future 的统一别名。低频控制面使用,不进入请求热路径。
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 有容量写入操作的原子结果。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreCapacityOutcome {
    /// 已覆盖既有 key 或在容量内创建新 key。
    Stored,
    /// 新 key 因 collection 已达到上限而未写入。
    CapacityReached,
}

/// 动态集合变更类型。
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicStoreChangeKind {
    /// key 被创建或覆盖。
    Put,
    /// key 被删除。
    Delete,
}

/// 动态集合 watch 产生的一条低频变更通知。
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicStoreChange {
    /// 发生变更的 collection。
    pub collection: String,
    /// 发生变更的 key。
    pub key: String,
    /// 写入或删除事件。
    pub kind: DynamicStoreChangeKind,
}

/// 持有后端订阅生命周期的有界变更接收器。
pub struct DynamicStoreWatcher {
    rx: mpsc::Receiver<DynamicStoreChange>,
    _guard: DynamicStoreWatchGuard,
}

impl DynamicStoreWatcher {
    /// 业务作用：接收动态事实源下一条有界变更，并让 watcher guard 与接收端保持同寿命。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有事件时返回 key 级变更；后端断开且无法恢复时返回 `None`。
    pub async fn recv(&mut self) -> Option<DynamicStoreChange> {
        self.rx.recv().await
    }
}

enum DynamicStoreWatchGuard {
    #[cfg(feature = "redis-runtime")]
    Redis {
        _subscription: nasa::redis::StreamSubscription,
    },
    #[cfg(feature = "nacos-sdk")]
    Nacos {
        cancel: Option<tokio::sync::oneshot::Sender<()>>,
    },
}

impl Drop for DynamicStoreWatchGuard {
    /// 业务作用：在 watcher 生命周期结束时撤销 Nacos 远端监听，避免热换或调用方退出后泄漏控制面任务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值；取消信号是幂等尽力发送，接收端已经退出时无需升级为进程错误。
    fn drop(&mut self) {
        #[allow(unreachable_patterns)]
        match self {
            #[cfg(feature = "nacos-sdk")]
            Self::Nacos {
                cancel,
            } => {
                if let Some(cancel) = cancel.take() {
                    let _ = cancel.send(());
                }
            }
            #[cfg(feature = "redis-runtime")]
            Self::Redis {
                ..
            } => {}
            _ => {}
        }
    }
}

/// 文件后端:单机/边缘模式完整可用,重启后数据仍在。
pub struct FileDynamicStore {
    root: PathBuf,
    /// file backend 的写/枚举事务锁；只服务低频控制面，不进入请求转发热路径。
    write_lock: Mutex<()>,
}

/// 含 `/` 等文件名不安全字符的业务 key 存入该保留子目录，并以 UTF-8 字节十六进制编码。
/// 旧版本已写入的普通单组件 key 仍保留原路径，升级不需要迁移。
const ENCODED_DYNAMIC_KEYS_DIR: &str = ".gateway-encoded-keys-v1";
const MAX_DYNAMIC_KEY_BYTES: usize = 1024;
/// 单个动态事实值上限。当前最大调用方是受 16MiB 管理面 body 限制的配置记录；
/// 黑名单、接口禁用和开发者申请通常只有数百字节。
const MAX_DYNAMIC_VALUE_BYTES: usize = 16 * 1024 * 1024;
/// 全量刷新允许返回的最大 key 数。它与 Portal 的最大 admission 上限对齐，阻止被篡改
/// file/Redis collection 在刷新时构造无界 `Vec<String>`。
const MAX_DYNAMIC_KEYS: usize = 100_000;

impl FileDynamicStore {
    /// 业务作用：构造以指定目录为根的持久化动态集合后端。
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            write_lock: Mutex::new(()),
        }
    }

    /// 业务作用：把经过校验的集合与键定位到动态状态目录，防止身份字段逃逸文件边界。
    fn path_for(&self, collection: &str, key: &str) -> Result<PathBuf> {
        validate_component(collection, "collection")?;
        validate_dynamic_key(key)?;
        let collection_dir = self.root.join(collection);
        if validate_component(key, "key").is_ok() && key != ENCODED_DYNAMIC_KEYS_DIR {
            Ok(collection_dir.join(key))
        } else {
            Ok(collection_dir
                .join(ENCODED_DYNAMIC_KEYS_DIR)
                .join(encode_dynamic_key(key)))
        }
    }

    /// 业务作用：在文件后端持久化完整动态事实，使用受控写入路径避免读到半份内容。
    fn put_sync(&self, collection: &str, key: &str, value: &[u8]) -> Result<()> {
        anyhow::ensure!(
            value.len() <= MAX_DYNAMIC_VALUE_BYTES,
            "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
        );
        let path = self.path_for(collection, key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create dynamic store dir {}", parent.display()))?;
        }
        let tmp = temp_path_for(&path);
        fs::write(&tmp, value)
            .with_context(|| format!("write dynamic store temp {}", tmp.display()))?;
        if let Err(error) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(error).with_context(|| {
                format!(
                    "publish dynamic store temp {} to {}",
                    tmp.display(),
                    path.display()
                )
            });
        }
        Ok(())
    }

    /// 业务作用：枚举当前集合中的合法事实键，不把临时文件解释为业务状态。
    fn list_keys_sync(&self, collection: &str) -> Result<Vec<String>> {
        validate_component(collection, "collection")?;
        let dir = self.root.join(collection);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut keys = Vec::new();
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            if entry.path().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    anyhow::ensure!(
                        keys.len() < MAX_DYNAMIC_KEYS,
                        "dynamic store collection exceeds {MAX_DYNAMIC_KEYS} keys"
                    );
                    keys.push(name.to_string());
                }
            }
        }
        let encoded_dir = dir.join(ENCODED_DYNAMIC_KEYS_DIR);
        if encoded_dir.is_dir() {
            for entry in fs::read_dir(&encoded_dir)
                .with_context(|| format!("read {}", encoded_dir.display()))?
            {
                let entry = entry?;
                if !entry.path().is_file() {
                    continue;
                }
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                anyhow::ensure!(
                    keys.len() < MAX_DYNAMIC_KEYS,
                    "dynamic store collection exceeds {MAX_DYNAMIC_KEYS} keys"
                );
                keys.push(decode_dynamic_key(name)?);
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

impl DynamicStore for FileDynamicStore {
    /// 业务作用：从当前选定的事实后端读取指定集合和键，不把缺失值伪装为有效规则。
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let path = self.path_for(collection, key)?;
            crate::io::bounded_io::read_optional_file(
                &path,
                MAX_DYNAMIC_VALUE_BYTES,
                "dynamic store value",
            )
        })
    }

    /// 业务作用：把指定动态事实写入当前后端，供黑名单、接口关闭等治理读面同步。
    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>> {
        Box::pin(async move {
            let _guard = self.write_lock.lock();
            self.put_sync(collection, key, value)
        })
    }

    /// 业务作用：撤销指定集合中的事实键，使后续治理判定不再使用已删除声明。
    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>> {
        Box::pin(async move {
            let _guard = self.write_lock.lock();
            let path = self.path_for(collection, key)?;
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => {
                    Err(e).with_context(|| format!("delete dynamic store {}", path.display()))
                }
            }
        })
    }

    /// 业务作用：读取当前集合的事实目录，供有界缓存重建与对账使用。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        Box::pin(async move {
            let _guard = self.write_lock.lock();
            self.list_keys_sync(collection)
        })
    }

    /// 业务作用：在集合容量约束下写入动态事实，避免新增身份绕过状态基数上限。
    fn put_if_capacity<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        Box::pin(async move {
            anyhow::ensure!(max_entries > 0, "dynamic store capacity must be positive");
            let _guard = self.write_lock.lock();
            let exists = self.path_for(collection, key)?.is_file();
            if !exists && self.list_keys_sync(collection)?.len() >= max_entries {
                return Ok(StoreCapacityOutcome::CapacityReached);
            }
            self.put_sync(collection, key, value)?;
            Ok(StoreCapacityOutcome::Stored)
        })
    }
}

/// Redis 动态集合存储。每个 collection 对应一个 Redis hash,field 为业务 key。
#[cfg(feature = "redis-runtime")]
pub struct RedisDynamicStore {
    client: Arc<nasa::redis::RedisClient>,
    prefix: String,
}

#[cfg(feature = "redis-runtime")]
const DYNAMIC_STORE_EVENT_STREAM_MAXLEN: u64 = 10_000;

/// 在 Redis 内先检查 hash value 长度；脏大值直接删除并返回 miss，不能先跨网络分配再校验。
#[cfg(feature = "redis-runtime")]
const DYNAMIC_STORE_GET_BOUNDED_LUA: &str = include_str!("redis/dynamic_get.lua");

/// 分页枚举 field，并在第 `MAX_DYNAMIC_KEYS + 1` 个 key 出现时于 Redis 内停止。
#[cfg(feature = "redis-runtime")]
const DYNAMIC_STORE_LIST_BOUNDED_LUA: &str = include_str!("redis/dynamic_list.lua");

#[cfg(feature = "redis-runtime")]
const DYNAMIC_STORE_PUT_IF_CAPACITY_LUA: &str = include_str!("redis/dynamic_put.lua");

/// 业务作用：把 DynamicStore 二进制值编码为 nasa Redis EVAL 接口接受的字符串参数。
/// 控制面按精确长度分配十六进制文本；Lua 在 HSET 前还原字节，保留二进制合同和原子写入，
/// 不把存储限制为 UTF-8，也不引入第二次非原子写入。
#[cfg(feature = "redis-runtime")]
fn encode_redis_lua_hex(value: &[u8]) -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let encoded_len = value
        .len()
        .checked_mul(2)
        .context("bounded dynamic-store value is too large to encode")?;
    let mut encoded = String::with_capacity(encoded_len);
    for byte in value {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(encoded)
}

#[cfg(feature = "redis-runtime")]
impl RedisDynamicStore {
    /// 业务作用：创建 Redis store。`prefix` 用于隔离 gateway 运行态 key,默认可传 `gw:dynamic`。
    pub fn new(client: Arc<nasa::redis::RedisClient>, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
        }
    }

    /// 业务作用：为 Redis 动态集合建立固定命名空间，隔离不同用途的业务事实。
    fn collection_key(&self, collection: &str) -> Result<String> {
        validate_component(collection, "collection")?;
        Ok(format!("{}:{}", self.prefix, collection))
    }

    /// 业务作用：定位当前动态集合的变更通知通道，通知与事实数据保持独立编码。
    fn events_key(&self, collection: &str) -> Result<String> {
        validate_component(collection, "collection")?;
        Ok(format!("{}:{}:events", self.prefix, collection))
    }

    /// 业务作用：发布动态事实变更通知，接收方仍需从事实源重新读取完整状态。
    async fn publish_change(
        &self,
        collection: &str,
        key: &str,
        kind: DynamicStoreChangeKind,
    ) -> Result<()> {
        let stream = self.events_key(collection)?;
        let event = match kind {
            DynamicStoreChangeKind::Put => "put",
            DynamicStoreChangeKind::Delete => "delete",
        };
        let change = DynamicStoreChange {
            collection: collection.to_string(),
            key: key.to_string(),
            kind,
        };
        self.client.publish(&stream, event, &change).await?;
        let _ = self
            .client
            .x_trim_maxlen_approx(&stream, DYNAMIC_STORE_EVENT_STREAM_MAXLEN)
            .await;
        Ok(())
    }
}

#[cfg(feature = "redis-runtime")]
impl DynamicStore for RedisDynamicStore {
    /// 业务作用：读取工作区同 slot 的独立 TTL 缓存值，平台保留原集合布局。
    ///
    /// 参数说明：
    /// - `collection`：定位受信派生状态
    /// - `key`：定位受信派生状态
    /// - `budget`：为工作区预算。
    ///
    /// 返回：有界值或缺失；超大远端值不下载到进程。
    fn get_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        let Some(budget) = budget else {
            return self.get(collection, key);
        };
        Box::pin(async move {
            let key = format!("{}:{key}", self.collection_key(collection)?);
            let (key, _) =
                budget.redis_keys(&self.client.config().namespace, "dynamic-cache", &key);
            const SCRIPT: &str = include_str!("redis/cache_get.lua");
            Ok(self
                .client
                .eval(SCRIPT, &[&key], &[&MAX_DYNAMIC_VALUE_BYTES.to_string()])
                .await?)
        })
    }

    /// 业务作用：将共享缓存值、TTL 与工作区容量以单个原子脚本提交，平台保持原容量合同。
    ///
    /// 参数说明：
    /// - `collection`：受信缓存集合名称。
    /// - `key`：集合内的条目键。
    /// - `value`：受编码上限约束的缓存值。
    /// - `max_entries`：集合内最大驻留条目数。
    /// - `ttl`：本条目的驻留期限。
    /// - `budget`：固定条目归属与总体容量的预算。
    ///
    /// 返回：成功或满载判定；依赖失败不宣称已写入。
    fn put_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        let Some(budget) = budget else {
            return self.put_if_capacity(collection, key, value, max_entries);
        };
        Box::pin(async move {
            validate_dynamic_key(key)?;
            anyhow::ensure!(
                value.len() <= MAX_DYNAMIC_VALUE_BYTES && max_entries > 0,
                "dynamic cache value or capacity exceeds bounds"
            );
            let key = format!("{}:{key}", self.collection_key(collection)?);
            Ok(
                if budget
                    .restricted(max_entries)
                    .redis_store(&self.client, "dynamic-cache", &key, value, ttl)
                    .await?
                {
                    StoreCapacityOutcome::Stored
                } else {
                    StoreCapacityOutcome::CapacityReached
                },
            )
        })
    }

    /// 业务作用：删除本域不可用的派生缓存，容量索引保守保留到原 TTL，避免并发新值被提前减计数。
    ///
    /// 参数说明：
    /// - `collection`：定位缓存
    /// - `key`：定位缓存
    /// - `budget`：提供稳定归属。
    ///
    /// 返回：删除结果，不触及其它域数据。
    fn delete_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<()>> {
        let Some(budget) = budget else {
            return self.delete(collection, key);
        };
        Box::pin(async move {
            let key = format!("{}:{key}", self.collection_key(collection)?);
            let (key, _) =
                budget.redis_keys(&self.client.config().namespace, "dynamic-cache", &key);
            self.client.del(&[key.as_str()]).await?;
            Ok(())
        })
    }
    /// 业务作用：从当前选定的事实后端读取指定集合和键，不把缺失值伪装为有效规则。
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            validate_dynamic_key(key)?;
            let redis_key = self.collection_key(collection)?;
            let limit = MAX_DYNAMIC_VALUE_BYTES.to_string();
            self.client
                .eval::<Option<Vec<u8>>>(
                    DYNAMIC_STORE_GET_BOUNDED_LUA,
                    &[redis_key.as_str()],
                    &[key, limit.as_str()],
                )
                .await
                .map_err(Into::into)
        })
    }

    /// 业务作用：把指定动态事实写入当前后端，供黑名单、接口关闭等治理读面同步。
    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>> {
        Box::pin(async move {
            validate_dynamic_key(key)?;
            anyhow::ensure!(
                value.len() <= MAX_DYNAMIC_VALUE_BYTES,
                "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
            );
            let redis_key = self.collection_key(collection)?;
            self.client.h_set(&redis_key, key, value.to_vec()).await?;
            if let Err(e) = self
                .publish_change(collection, key, DynamicStoreChangeKind::Put)
                .await
            {
                tracing::warn!(collection, key, error = %e, "publish dynamic store put event failed");
            }
            Ok(())
        })
    }

    /// 业务作用：撤销指定集合中的事实键，使后续治理判定不再使用已删除声明。
    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>> {
        Box::pin(async move {
            validate_dynamic_key(key)?;
            let redis_key = self.collection_key(collection)?;
            self.client.h_del(&redis_key, &[key]).await?;
            if let Err(e) = self
                .publish_change(collection, key, DynamicStoreChangeKind::Delete)
                .await
            {
                tracing::warn!(collection, key, error = %e, "publish dynamic store delete event failed");
            }
            Ok(())
        })
    }

    /// 业务作用：读取当前集合的事实目录，供有界缓存重建与对账使用。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        Box::pin(async move {
            let redis_key = self.collection_key(collection)?;
            let limit = MAX_DYNAMIC_KEYS.to_string();
            let mut keys: Vec<String> = self
                .client
                .eval(
                    DYNAMIC_STORE_LIST_BOUNDED_LUA,
                    &[redis_key.as_str()],
                    &[limit.as_str()],
                )
                .await?;
            keys.sort();
            Ok(keys)
        })
    }

    /// 业务作用：在集合容量约束下写入动态事实，避免新增身份绕过状态基数上限。
    fn put_if_capacity<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        Box::pin(async move {
            anyhow::ensure!(max_entries > 0, "dynamic store capacity must be positive");
            validate_dynamic_key(key)?;
            anyhow::ensure!(
                value.len() <= MAX_DYNAMIC_VALUE_BYTES,
                "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
            );
            // nasa 当前 EVAL 门面只接收 &str。十六进制是这里唯一的必要控制面拷贝；Lua 在
            // 同一原子命令内还原原始字节，因而 file/Redis 后端保持完全相同的二进制契约。
            let value = encode_redis_lua_hex(value)?;
            let redis_key = self.collection_key(collection)?;
            let capacity = max_entries.to_string();
            let stored = self
                .client
                .eval::<i64>(
                    DYNAMIC_STORE_PUT_IF_CAPACITY_LUA,
                    &[redis_key.as_str()],
                    &[key, value.as_str(), capacity.as_str()],
                )
                .await?
                == 1;
            if !stored {
                return Ok(StoreCapacityOutcome::CapacityReached);
            }
            if let Err(error) = self
                .publish_change(collection, key, DynamicStoreChangeKind::Put)
                .await
            {
                tracing::warn!(collection, key, error = %error, "publish bounded dynamic store put event failed");
            }
            Ok(StoreCapacityOutcome::Stored)
        })
    }

    /// 业务作用：提供当前动态后端的变更订阅，供缓存后台刷新而非请求路径直接等待。
    fn watch<'a>(
        &'a self,
        collection: &'a str,
    ) -> StoreFuture<'a, Result<Option<DynamicStoreWatcher>>> {
        Box::pin(async move {
            use nasa::redis::StreamStart;

            let stream = self.events_key(collection)?;
            let (tx, rx) = mpsc::channel(128);
            let tx_put = tx.clone();
            let sub = self
                .client
                .subscribe(stream.clone())
                .broadcast_from(StreamStart::Now)
                .on_typed::<DynamicStoreChange, _, _>("put", move |ev| {
                    let tx = tx_put.clone();
                    async move {
                        tx.send(ev.data)
                            .await
                            .map_err(|e| format!("dynamic store put watcher channel closed: {e}"))
                    }
                })
                .on_typed::<DynamicStoreChange, _, _>("delete", move |ev| {
                    let tx = tx.clone();
                    async move {
                        tx.send(ev.data).await.map_err(|e| {
                            format!("dynamic store delete watcher channel closed: {e}")
                        })
                    }
                })
                .start()
                .await
                .context("start Redis dynamic store watch")?;
            Ok(Some(DynamicStoreWatcher {
                rx,
                _guard: DynamicStoreWatchGuard::Redis {
                    _subscription: sub,
                },
            }))
        })
    }
}

/// Nacos-backed DynamicStore。所有 SDK I/O 固定在专用 current-thread actor，数据面 future 只经有界 channel 交换 owned 消息。
#[cfg(feature = "nacos-sdk")]
pub struct NacosDynamicStore {
    commands: mpsc::Sender<NacosStoreCommand>,
    data_id_prefix: Arc<str>,
}

#[cfg(feature = "nacos-sdk")]
enum NacosStoreCommand {
    Get {
        data_id: String,
        key: String,
        reply: tokio::sync::oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    Put {
        data_id: String,
        key: String,
        value: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<()>>,
    },
    Delete {
        data_id: String,
        key: String,
        reply: tokio::sync::oneshot::Sender<Result<()>>,
    },
    List {
        data_id: String,
        reply: tokio::sync::oneshot::Sender<Result<Vec<String>>>,
    },
    PutIfCapacity {
        data_id: String,
        key: String,
        value: Vec<u8>,
        max_entries: usize,
        reply: tokio::sync::oneshot::Sender<Result<StoreCapacityOutcome>>,
    },
    Watch {
        data_id: String,
        collection: String,
        reply: tokio::sync::oneshot::Sender<Result<NacosWatchRegistration>>,
    },
}

#[cfg(feature = "nacos-sdk")]
struct NacosWatchRegistration {
    rx: mpsc::Receiver<DynamicStoreChange>,
    cancel: tokio::sync::oneshot::Sender<()>,
}

#[cfg(feature = "nacos-sdk")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NacosDynamicDocument {
    schema_version: u32,
    revision: u64,
    entries: StrictNacosEntries,
}

#[cfg(feature = "nacos-sdk")]
#[derive(Serialize)]
#[serde(transparent)]
struct StrictNacosEntries(BTreeMap<String, String>);

#[cfg(feature = "nacos-sdk")]
impl<'de> Deserialize<'de> for StrictNacosEntries {
    /// 业务作用：严格读取 Nacos entries 对象并拒绝重复 key，避免外部文档在不同解析器中产生歧义。
    ///
    /// 参数说明：
    /// - `deserializer`：提供单个 JSON object 的 token 流。
    ///
    /// 返回：唯一 key 映射成功时返回稳定有序表；非对象、重复 key 或字符串解码失败时拒绝文档。
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
            type Value = StrictNacosEntries;

            /// 业务作用：向 serde 声明 entries 的严格对象形态，供类型错误生成可定位诊断。
            ///
            /// 参数说明：
            /// - `formatter`：接收期望结构说明。
            ///
            /// 返回：格式化写入成功或底层 formatter 错误。
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Nacos dynamic store entries object with unique keys")
            }

            /// 业务作用：逐项构建唯一键映射，在值覆盖发生前拒绝重复 JSON key。
            ///
            /// 参数说明：
            /// - `map`：是 serde 提供的 entries object 游标。
            ///
            /// 返回：返回有序唯一映射；重复键或 token 解码失败时拒绝整份文档。
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if entries.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate Nacos dynamic store key `{key}`"
                        )));
                    }
                }
                Ok(StrictNacosEntries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

#[cfg(feature = "nacos-sdk")]
struct NacosDynamicSnapshot {
    revision: u64,
    entries: BTreeMap<String, Vec<u8>>,
}

#[cfg(feature = "nacos-sdk")]
impl Default for NacosDynamicSnapshot {
    /// 业务作用：创建 revision=0 的空 collection，作为首次 CAS 发布的唯一规范初态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回不含任何动态事实的内存快照。
    fn default() -> Self {
        Self {
            revision: 0,
            entries: BTreeMap::new(),
        }
    }
}

#[cfg(feature = "nacos-sdk")]
impl NacosDynamicStore {
    /// 业务作用：校验 Nacos DynamicStore 配置并启动隔离 SDK 非 Send future 的专用 actor。
    ///
    /// 参数说明：
    /// - `cfg`：是 `runtime_state.store.nacos` 的完整连接与文档资源配置。
    ///
    /// 返回：连接成功且 actor 已进入命令循环时返回 store；配置、线程、runtime 或 Nacos 连接失败时拒绝启动/候选热换。
    async fn connect(cfg: crate::config::model::NacosStoreCfg) -> Result<Self> {
        anyhow::ensure!(
            !cfg.server_addr.trim().is_empty(),
            "runtime_state.store.nacos.server_addr is required when backend=nacos"
        );
        anyhow::ensure!(
            !cfg.group.trim().is_empty(),
            "runtime_state.store.nacos.group must not be empty"
        );
        anyhow::ensure!(
            !cfg.app_name.trim().is_empty(),
            "runtime_state.store.nacos.app_name must not be empty"
        );
        anyhow::ensure!(
            cfg.username.is_empty() == cfg.password.is_empty(),
            "runtime_state.store.nacos.username/password must be both set or both empty"
        );
        validate_nacos_data_id_prefix(cfg.data_id_prefix.as_str())?;
        anyhow::ensure!(
            (1..=MAX_DYNAMIC_VALUE_BYTES as u64).contains(&cfg.max_document_bytes),
            "runtime_state.store.nacos.max_document_bytes must be within 1..={MAX_DYNAMIC_VALUE_BYTES}"
        );
        let prefix: Arc<str> = Arc::from(cfg.data_id_prefix.as_str());
        let (commands, rx) = mpsc::channel(256);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("gateway-nacos-dynamic-store".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx
                            .send(Err(anyhow::Error::new(error)
                                .context("build Nacos DynamicStore runtime")));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, run_nacos_store_actor(cfg, rx, ready_tx));
            })
            .context("spawn Nacos DynamicStore actor")?;
        ready_rx
            .await
            .context("Nacos DynamicStore actor exited before readiness")??;
        Ok(Self {
            commands,
            data_id_prefix: prefix,
        })
    }

    /// 业务作用：把已验证 collection 映射为独立 Nacos dataId，避免不同集合出现读改写冲突。
    ///
    /// 参数说明：
    /// - `collection`：是 DynamicStore 集合名。
    ///
    /// 返回：长度不超过 256 字节的固定 dataId；非法 collection 或组合超长时返回错误。
    fn data_id(&self, collection: &str) -> Result<String> {
        validate_component(collection, "collection")?;
        let data_id = format!("{}.{}.json", self.data_id_prefix, collection);
        anyhow::ensure!(
            data_id.len() <= 256,
            "Nacos dynamic store dataId exceeds 256 bytes"
        );
        Ok(data_id)
    }
}

#[cfg(feature = "nacos-sdk")]
impl DynamicStore for NacosDynamicStore {
    /// 业务作用：从 Nacos collection 文档读取一个动态事实，并隔离 SDK 的线程约束。
    ///
    /// 参数说明：
    /// - `collection`：唯一定位业务事实。
    /// - `key`：唯一定位业务事实。
    ///
    /// 返回：事实存在时返回原始字节，不存在返回 None；校验、actor 或 Nacos 错误向调用方传播。
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        let result = self.data_id(collection).and_then(|data_id| {
            validate_dynamic_key(key)?;
            Ok((data_id, key.to_string()))
        });
        let commands = self.commands.clone();
        Box::pin(async move {
            let (data_id, key) = result?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::Get {
                    data_id,
                    key,
                    reply,
                })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            response
                .await
                .context("Nacos DynamicStore get reply dropped")?
        })
    }

    /// 业务作用：通过 Nacos 文档 CAS 创建或覆盖一个动态事实。
    ///
    /// 参数说明：
    /// - `collection`：定位事实
    /// - `key`：定位事实
    /// - `value`：是受单值与聚合文档硬门约束的原始内容。
    ///
    /// 返回：CAS 发布成功返回成功；输入超限、冲突耗尽或远端错误返回失败且不声称已写入。
    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>> {
        let result = self.data_id(collection).and_then(|data_id| {
            validate_dynamic_key(key)?;
            anyhow::ensure!(
                value.len() <= MAX_DYNAMIC_VALUE_BYTES,
                "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
            );
            Ok((data_id, key.to_string(), value.to_vec()))
        });
        let commands = self.commands.clone();
        Box::pin(async move {
            let (data_id, key, value) = result?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::Put {
                    data_id,
                    key,
                    value,
                    reply,
                })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            response
                .await
                .context("Nacos DynamicStore put reply dropped")?
        })
    }

    /// 业务作用：通过 Nacos 文档 CAS 幂等删除一个动态事实。
    ///
    /// 参数说明：
    /// - `collection`：唯一定位待删除事实。
    /// - `key`：唯一定位待删除事实。
    ///
    /// 返回：事实或集合不存在也返回成功；冲突耗尽或远端失败返回错误并保留可复验状态。
    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>> {
        let result = self.data_id(collection).and_then(|data_id| {
            validate_dynamic_key(key)?;
            Ok((data_id, key.to_string()))
        });
        let commands = self.commands.clone();
        Box::pin(async move {
            let (data_id, key) = result?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::Delete {
                    data_id,
                    key,
                    reply,
                })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            response
                .await
                .context("Nacos DynamicStore delete reply dropped")?
        })
    }

    /// 业务作用：读取 Nacos collection 当前完整 key 集，供低频控制面对账。
    ///
    /// 参数说明：
    /// - `collection`：是已经过命名约束的集合名。
    ///
    /// 返回：集合缺失返回空集；坏文档、超限或远端失败返回错误，避免把损坏误判为空。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        let data_id = self.data_id(collection);
        let commands = self.commands.clone();
        Box::pin(async move {
            let data_id = data_id?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::List {
                    data_id,
                    reply,
                })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            response
                .await
                .context("Nacos DynamicStore list reply dropped")?
        })
    }

    /// 业务作用：用单次 Nacos 文档 CAS 原子完成容量 admission 与写入，禁止 list/put 竞态超卖。
    ///
    /// 参数说明：
    /// - `collection`：描述事实
    /// - `key`：描述事实
    /// - `value`：描述事实
    /// - `max_entries`：是集合硬容量。
    ///
    /// 返回：写入或覆盖返回 Stored，满容量新建返回 CapacityReached；其它失败不修改已确认事实。
    fn put_if_capacity<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        let result = self.data_id(collection).and_then(|data_id| {
            anyhow::ensure!(max_entries > 0, "dynamic store capacity must be positive");
            validate_dynamic_key(key)?;
            anyhow::ensure!(
                value.len() <= MAX_DYNAMIC_VALUE_BYTES,
                "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
            );
            Ok((data_id, key.to_string(), value.to_vec()))
        });
        let commands = self.commands.clone();
        Box::pin(async move {
            let (data_id, key, value) = result?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::PutIfCapacity {
                    data_id,
                    key,
                    value,
                    max_entries,
                    reply,
                })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            response
                .await
                .context("Nacos DynamicStore bounded put reply dropped")?
        })
    }

    /// 业务作用：把 Nacos 完整文档推送转换为有界增量流，并在 guard 释放时注销监听。
    ///
    /// 参数说明：
    /// - `collection`：是要持续观察的动态集合。
    ///
    /// 返回：注册成功返回 watcher；初值损坏、注册或 actor 失败时返回错误且不遗留孤儿监听。
    fn watch<'a>(
        &'a self,
        collection: &'a str,
    ) -> StoreFuture<'a, Result<Option<DynamicStoreWatcher>>> {
        let result = self
            .data_id(collection)
            .map(|data_id| (data_id, collection.to_string()));
        let commands = self.commands.clone();
        Box::pin(async move {
            let (data_id, collection) = result?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::Watch {
                    data_id,
                    collection,
                    reply,
                })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            let registration = response
                .await
                .context("Nacos DynamicStore watch reply dropped")??;
            Ok(Some(DynamicStoreWatcher {
                rx: registration.rx,
                _guard: DynamicStoreWatchGuard::Nacos {
                    cancel: Some(registration.cancel),
                },
            }))
        })
    }
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：连接 Nacos 并串行执行 DynamicStore 命令；watch 任务留在同一 LocalSet，SDK future 不跨线程。
///
/// 参数说明：
/// - `cfg`：是连接配置
/// - `commands`：是有界命令队列
/// - `ready`：在连接结果确定后只发送一次。
///
/// 返回：命令发送端全部释放后退出；单个操作错误只回复调用方，不终止其它集合。
async fn run_nacos_store_actor(
    cfg: crate::config::model::NacosStoreCfg,
    mut commands: mpsc::Receiver<NacosStoreCommand>,
    ready: tokio::sync::oneshot::Sender<Result<()>>,
) {
    let mut props = nasa::config::nacos::NacosProps::new(&cfg.server_addr)
        .with_namespace(&cfg.namespace)
        .with_group(&cfg.group)
        .with_app_name(&cfg.app_name);
    if !cfg.username.is_empty() || !cfg.password.is_empty() {
        props = props.with_auth(&cfg.username, &cfg.password);
    }
    let client = match nasa::config::nacos::NacosConfigClient::connect(&props).await {
        Ok(client) => client,
        Err(error) => {
            let _ = ready.send(Err(error.context("connect Nacos DynamicStore")));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    while let Some(command) = commands.recv().await {
        match command {
            NacosStoreCommand::Get {
                data_id,
                key,
                reply,
            } => {
                let result = nacos_load_snapshot(
                    &client,
                    &data_id,
                    &cfg.group,
                    cfg.max_document_bytes as usize,
                )
                .await
                .map(|snapshot| {
                    snapshot.and_then(|snapshot| snapshot.0.entries.get(&key).cloned())
                });
                let _ = reply.send(result);
            }
            NacosStoreCommand::Put {
                data_id,
                key,
                value,
                reply,
            } => {
                let result = nacos_put_value(
                    &client,
                    &data_id,
                    &cfg.group,
                    cfg.max_document_bytes as usize,
                    key,
                    value,
                    None,
                )
                .await
                .map(|_| ());
                let _ = reply.send(result);
            }
            NacosStoreCommand::Delete {
                data_id,
                key,
                reply,
            } => {
                let result = nacos_delete_value(
                    &client,
                    &data_id,
                    &cfg.group,
                    cfg.max_document_bytes as usize,
                    &key,
                )
                .await;
                let _ = reply.send(result);
            }
            NacosStoreCommand::List {
                data_id,
                reply,
            } => {
                let result = nacos_load_snapshot(
                    &client,
                    &data_id,
                    &cfg.group,
                    cfg.max_document_bytes as usize,
                )
                .await
                .map(|snapshot| {
                    snapshot
                        .map(|snapshot| snapshot.0.entries.into_keys().collect())
                        .unwrap_or_default()
                });
                let _ = reply.send(result);
            }
            NacosStoreCommand::PutIfCapacity {
                data_id,
                key,
                value,
                max_entries,
                reply,
            } => {
                let result = nacos_put_value(
                    &client,
                    &data_id,
                    &cfg.group,
                    cfg.max_document_bytes as usize,
                    key,
                    value,
                    Some(max_entries),
                )
                .await;
                let _ = reply.send(result);
            }
            NacosStoreCommand::Watch {
                data_id,
                collection,
                reply,
            } => {
                let result = nacos_start_watch(
                    &client,
                    &data_id,
                    &cfg.group,
                    cfg.max_document_bytes as usize,
                    collection,
                )
                .await;
                let _ = reply.send(result);
            }
        }
    }
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：从 Nacos 拉取并严格解析一个 collection 文档，缺失与坏文档保持不同语义。
///
/// 参数说明：
/// - `client`：是 actor 内专用配置客户端
/// - `data_id`：定位集合
/// - `group`：定位集合
/// - `max_document_bytes`：是聚合硬门。
///
/// 返回：dataId 缺失返回 None；合法文档返回 snapshot 与服务端 md5；网络、超限、schema 或 Base64 错误返回失败。
async fn nacos_load_snapshot(
    client: &nasa::config::nacos::NacosConfigClient,
    data_id: &str,
    group: &str,
    max_document_bytes: usize,
) -> Result<Option<(NacosDynamicSnapshot, String)>> {
    let Some((content, md5)) = client.fetch_optional_with_md5(data_id, group).await? else {
        return Ok(None);
    };
    let snapshot = parse_nacos_dynamic_document(content.as_bytes(), max_document_bytes)?;
    Ok(Some((snapshot, md5)))
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：用最多八次 CAS 重试创建或覆盖 Nacos collection key，并原子执行可选容量 admission。
///
/// 参数说明：
/// - `client`：固定身份的 Nacos 配置客户端。
/// - `data_id`：目标状态文档 dataId。
/// - `group`：目标状态文档 group。
/// - `max_document_bytes`：单个状态文档的字节硬上限。
/// - `key`：已经验证的条目键。
/// - `value`：已经验证的条目值。
/// - `max_entries`：可选条目容量上限，满额时禁止创建新键。
///
/// 返回：写入成功返回 Stored，容量不足返回 CapacityReached；冲突耗尽、网络或文档超限返回错误。
#[allow(clippy::too_many_arguments)]
async fn nacos_put_value(
    client: &nasa::config::nacos::NacosConfigClient,
    data_id: &str,
    group: &str,
    max_document_bytes: usize,
    key: String,
    value: Vec<u8>,
    max_entries: Option<usize>,
) -> Result<StoreCapacityOutcome> {
    for _ in 0..8 {
        let current = nacos_load_snapshot(client, data_id, group, max_document_bytes).await?;
        let (mut snapshot, md5) = current
            .map(|(snapshot, md5)| (snapshot, Some(md5)))
            .unwrap_or_else(|| (NacosDynamicSnapshot::default(), None));
        if let Some(capacity) = max_entries {
            if !snapshot.entries.contains_key(&key) && snapshot.entries.len() >= capacity {
                return Ok(StoreCapacityOutcome::CapacityReached);
            }
        }
        snapshot.entries.insert(key.clone(), value.clone());
        snapshot.revision = snapshot
            .revision
            .checked_add(1)
            .context("Nacos dynamic store revision overflow")?;
        let content = encode_nacos_dynamic_document(&snapshot, max_document_bytes)?;
        let published = match md5 {
            Some(md5) => {
                client
                    .publish_cas_typed(data_id, group, &content, "json", &md5)
                    .await?
            }
            None => {
                client
                    .publish_initial(data_id, group, &content, "json")
                    .await?
            }
        };
        if published {
            return Ok(StoreCapacityOutcome::Stored);
        }
        tokio::task::yield_now().await;
    }
    anyhow::bail!("Nacos dynamic store CAS conflict retry limit exceeded")
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：用 CAS 删除一个 Nacos collection key，不存在时保持幂等成功。
///
/// 参数说明：
/// - `client`：定位集合
/// - `data_id`：定位集合
/// - `group`：定位集合
/// - `max_document_bytes`：约束文档
/// - `key`：是已验证业务键。
///
/// 返回：缺失集合或 key 返回成功；删除发布成功返回成功；冲突耗尽与远端错误返回失败。
async fn nacos_delete_value(
    client: &nasa::config::nacos::NacosConfigClient,
    data_id: &str,
    group: &str,
    max_document_bytes: usize,
    key: &str,
) -> Result<()> {
    for _ in 0..8 {
        let Some((mut snapshot, md5)) =
            nacos_load_snapshot(client, data_id, group, max_document_bytes).await?
        else {
            return Ok(());
        };
        if snapshot.entries.remove(key).is_none() {
            return Ok(());
        }
        snapshot.revision = snapshot
            .revision
            .checked_add(1)
            .context("Nacos dynamic store revision overflow")?;
        let content = encode_nacos_dynamic_document(&snapshot, max_document_bytes)?;
        if client
            .publish_cas_typed(data_id, group, &content, "json", &md5)
            .await?
        {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    anyhow::bail!("Nacos dynamic store delete CAS conflict retry limit exceeded")
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：为一个 Nacos collection 建立先监听后播种的 watch，并把完整快照差异投影为 DynamicStoreChange。
///
/// 参数说明：
/// - `client`：定位集合
/// - `data_id`：定位集合
/// - `group`：定位集合
/// - `collection`：进入事件
/// - `max_document_bytes`：限制每次推送解析。
///
/// 返回：监听注册与初值解析成功时返回有界 receiver/cancel；初始化、注册或坏文档失败时返回错误且不泄漏 guard。
async fn nacos_start_watch(
    client: &nasa::config::nacos::NacosConfigClient,
    data_id: &str,
    group: &str,
    max_document_bytes: usize,
    collection: String,
) -> Result<NacosWatchRegistration> {
    if client
        .fetch_optional_with_md5(data_id, group)
        .await?
        .is_none()
    {
        let content =
            encode_nacos_dynamic_document(&NacosDynamicSnapshot::default(), max_document_bytes)?;
        if !client
            .publish_initial(data_id, group, &content, "json")
            .await?
        {
            // 并发初始化由其它节点获胜时重新读取；缺失或坏文档会在 watch_channel 初值播种阶段显式失败。
            tokio::task::yield_now().await;
        }
    }
    let mut visible = false;
    for _ in 0..20 {
        if nacos_load_snapshot(client, data_id, group, max_document_bytes)
            .await?
            .is_some()
        {
            visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::ensure!(
        visible,
        "Nacos dynamic store initial document did not become visible before watch"
    );
    let (guard, mut source) = client.watch_channel(data_id, group).await?;
    let mut previous =
        parse_nacos_dynamic_document(source.borrow().as_bytes(), max_document_bytes)?;
    let (events, rx) = mpsc::channel(128);
    let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
    tokio::task::spawn_local(async move {
        'watch: loop {
            tokio::select! {
                _ = &mut cancelled => break,
                changed = source.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let next = match parse_nacos_dynamic_document(source.borrow().as_bytes(), max_document_bytes) {
                        Ok(next) => next,
                        Err(error) => {
                            tracing::warn!(collection, %error, "discard invalid Nacos DynamicStore watch document");
                            continue;
                        }
                    };
                    let changes = diff_nacos_dynamic_snapshots(&collection, &previous, &next);
                    previous = next;
                    for change in changes {
                        if events.send(change).await.is_err() {
                            break 'watch;
                        }
                    }
                }
            }
        }
        if let Err(error) = guard.close().await {
            tracing::warn!(collection, %error, "close Nacos DynamicStore watch failed");
        }
    });
    Ok(NacosWatchRegistration {
        rx,
        cancel,
    })
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：严格解码 Nacos collection JSON，将外部文档转换成经过 key/value/数量复验的内存快照。
///
/// 参数说明：
/// - `content`：是 Nacos 原文
/// - `max_document_bytes`：是 route-independent 文档硬上限。
///
/// 返回：schema v1 合法时返回二进制 entries；超限、重复/非法 key、Base64 或单值超限时失败闭合。
fn parse_nacos_dynamic_document(
    content: &[u8],
    max_document_bytes: usize,
) -> Result<NacosDynamicSnapshot> {
    anyhow::ensure!(
        content.len() <= max_document_bytes,
        "Nacos dynamic store document exceeds {max_document_bytes} bytes"
    );
    let document: NacosDynamicDocument =
        serde_json::from_slice(content).context("parse Nacos dynamic store document")?;
    anyhow::ensure!(
        document.schema_version == 1,
        "unsupported Nacos dynamic store schema_version {}",
        document.schema_version
    );
    anyhow::ensure!(
        document.entries.0.len() <= MAX_DYNAMIC_KEYS,
        "Nacos dynamic store collection exceeds {MAX_DYNAMIC_KEYS} keys"
    );
    let mut entries = BTreeMap::new();
    for (key, encoded) in document.entries.0 {
        validate_dynamic_key(&key)?;
        let value = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .context("decode Nacos dynamic store Base64 value")?;
        anyhow::ensure!(
            value.len() <= MAX_DYNAMIC_VALUE_BYTES,
            "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
        );
        entries.insert(key, value);
    }
    Ok(NacosDynamicSnapshot {
        revision: document.revision,
        entries,
    })
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：把内存 collection 快照稳定编码为 Nacos 单 dataId JSON，并在发布前执行最终体积门。
///
/// 参数说明：
/// - `snapshot`：是 CAS 候选状态
/// - `max_document_bytes`：是配置硬上限。
///
/// 返回：返回稳定 JSON string；键数、单值或序列化总长度超限时拒绝发布。
fn encode_nacos_dynamic_document(
    snapshot: &NacosDynamicSnapshot,
    max_document_bytes: usize,
) -> Result<String> {
    anyhow::ensure!(
        snapshot.entries.len() <= MAX_DYNAMIC_KEYS,
        "Nacos dynamic store collection exceeds {MAX_DYNAMIC_KEYS} keys"
    );
    let mut entries = BTreeMap::new();
    for (key, value) in &snapshot.entries {
        validate_dynamic_key(key)?;
        anyhow::ensure!(
            value.len() <= MAX_DYNAMIC_VALUE_BYTES,
            "dynamic store value exceeds {MAX_DYNAMIC_VALUE_BYTES} bytes"
        );
        entries.insert(
            key.clone(),
            base64::engine::general_purpose::STANDARD.encode(value),
        );
    }
    let content = serde_json::to_string(&NacosDynamicDocument {
        schema_version: 1,
        revision: snapshot.revision,
        entries: StrictNacosEntries(entries),
    })
    .context("encode Nacos dynamic store document")?;
    anyhow::ensure!(
        content.len() <= max_document_bytes,
        "Nacos dynamic store document exceeds {max_document_bytes} bytes"
    );
    Ok(content)
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：把两个完整 Nacos collection 快照收敛为最终 key 级变更，供现有缓存触发对账。
///
/// 参数说明：
/// - `collection`：是固定集合名
/// - `previous`：是连续合法快照。
/// - `next`：是连续合法快照。
///
/// 返回：按 key 排序的 Put/Delete 事件；值变化也归一化为 Put，不携带敏感 value。
fn diff_nacos_dynamic_snapshots(
    collection: &str,
    previous: &NacosDynamicSnapshot,
    next: &NacosDynamicSnapshot,
) -> Vec<DynamicStoreChange> {
    let mut changes = Vec::new();
    for (key, value) in &next.entries {
        if previous.entries.get(key) != Some(value) {
            changes.push(DynamicStoreChange {
                collection: collection.to_string(),
                key: key.clone(),
                kind: DynamicStoreChangeKind::Put,
            });
        }
    }
    for key in previous.entries.keys() {
        if !next.entries.contains_key(key) {
            changes.push(DynamicStoreChange {
                collection: collection.to_string(),
                key: key.clone(),
                kind: DynamicStoreChangeKind::Delete,
            });
        }
    }
    changes.sort_by(|left, right| left.key.cmp(&right.key));
    changes
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：验证 Nacos dataId 前缀只含安全 ASCII token，阻止 group/dataId 注入和意外空命名空间。
///
/// 参数说明：
/// - `prefix`：是 `runtime_state.store.nacos.data_id_prefix`。
///
/// 返回：1..=128 字节 `[A-Za-z0-9._-]` 返回成功，其它值拒绝候选配置。
fn validate_nacos_data_id_prefix(prefix: &str) -> Result<()> {
    anyhow::ensure!(
        !prefix.is_empty()
            && prefix.len() <= 128
            && prefix
                .bytes()
                .all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                }),
        "runtime_state.store.nacos.data_id_prefix must be 1..=128 ASCII [A-Za-z0-9._-]"
    );
    Ok(())
}

/// 可热替换的动态存储后端。黑名单刷新等后台任务持有它,reload 成功后原子换入新后端。
pub struct SwappableDynamicStore {
    inner: RwLock<Arc<dyn DynamicStore>>,
    generation: AtomicU64,
}

impl SwappableDynamicStore {
    /// 业务作用：以一个已经初始化的后端构造热替换容器。
    pub fn new(inner: Arc<dyn DynamicStore>) -> Self {
        Self {
            inner: RwLock::new(inner),
            generation: AtomicU64::new(0),
        }
    }

    /// 业务作用：克隆当前后端的共享指针；锁只覆盖指针读取。
    pub fn current(&self) -> Arc<dyn DynamicStore> {
        self.inner.read().clone()
    }

    /// 业务作用：原子语义替换后端并递增 generation。
    pub fn replace(&self, next: Arc<dyn DynamicStore>) {
        *self.inner.write() = next;
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// 业务作用：返回最近一次成功替换对应的单调 generation。
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }
}

impl DynamicStore for SwappableDynamicStore {
    /// 业务作用：将派生缓存读取交给一次冻结的后端代次，不跨代拼接数据。
    ///
    /// 参数说明：
    /// - `collection`：保留调用方归属。
    /// - `key`：保留调用方归属。
    /// - `budget`：保留调用方归属。
    ///
    /// 返回：该代后端的缓存读取结果。
    fn get_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        let inner = self.current();
        Box::pin(async move {
            inner.get_cache(collection, key, budget).await
        })
    }

    /// 业务作用：在同一后端代次执行有归属的原子缓存容量写入。
    ///
    /// 参数说明：
    /// - `collection`：受信缓存集合名称。
    /// - `key`：集合内的条目键。
    /// - `value`：受编码上限约束的缓存值。
    /// - `max_entries`：集合内最大驻留条目数。
    /// - `ttl`：本条目的驻留期限。
    /// - `budget`：固定条目归属与总体容量的预算。
    ///
    /// 返回：成功/满载或错误，不跨代补写。
    fn put_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        let inner = self.current();
        Box::pin(async move {
            inner
                .put_cache(collection, key, value, max_entries, ttl, budget)
                .await
        })
    }

    /// 业务作用：在选定后端代次撤下不可用的本域缓存。
    ///
    /// 参数说明：
    /// - `collection`：为定位
    /// - `key`：为定位
    /// - `budget`：为冻结归属。
    ///
    /// 返回：该代删除结果，不访问其它代次。
    fn delete_cache<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> StoreFuture<'a, Result<()>> {
        let inner = self.current();
        Box::pin(async move {
            inner.delete_cache(collection, key, budget).await
        })
    }
    /// 业务作用：从当前选定的事实后端读取指定集合和键，不把缺失值伪装为有效规则。
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        let inner = self.current();
        Box::pin(async move {
            inner.get(collection, key).await
        })
    }

    /// 业务作用：把指定动态事实写入当前后端，供黑名单、接口关闭等治理读面同步。
    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>> {
        let inner = self.current();
        Box::pin(async move {
            inner.put(collection, key, value).await
        })
    }

    /// 业务作用：撤销指定集合中的事实键，使后续治理判定不再使用已删除声明。
    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>> {
        let inner = self.current();
        Box::pin(async move {
            inner.delete(collection, key).await
        })
    }

    /// 业务作用：读取当前集合的事实目录，供有界缓存重建与对账使用。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        let inner = self.current();
        Box::pin(async move {
            inner.list_keys(collection).await
        })
    }

    /// 业务作用：在集合容量约束下写入动态事实，避免新增身份绕过状态基数上限。
    fn put_if_capacity<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>> {
        let inner = self.current();
        Box::pin(async move {
            inner
                .put_if_capacity(collection, key, value, max_entries)
                .await
        })
    }

    /// 业务作用：提供当前动态后端的变更订阅，供缓存后台刷新而非请求路径直接等待。
    fn watch<'a>(
        &'a self,
        collection: &'a str,
    ) -> StoreFuture<'a, Result<Option<DynamicStoreWatcher>>> {
        let inner = self.current();
        Box::pin(async move {
            inner.watch(collection).await
        })
    }
}

/// 高频计数限流接口。Redis 后端可精确跨节点;local 后端用于单机/降级。
pub trait RateLimiter: Send + Sync {
    /// 业务作用：提供当前限流后端的有限只读观测，未实现的后端不伪造本地空桶。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原生状态摘要或明确不支持；不触发外部网络和业务状态迁移。
    fn bucket_observation(&self) -> crate::runtime::sentinel::buckets::Observation {
        crate::runtime::sentinel::buckets::Observation::Unsupported
    }
    /// 业务作用：为显式匀速规则取得实际调度授权，未实现排队的后端必须明确拒绝。
    ///
    /// 参数说明：
    /// - `request`：冻结规则、维度与归属容量。
    /// - `policy`：已校验的匀速间隔与队列容量。
    /// - `context`：原始等待期限和已知实体上界。
    ///
    /// 返回：只有明确授权才成功，默认失败关闭，不自动换成本地额度。
    fn queue<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        policy: crate::runtime::sentinel::queue::Policy,
        context: crate::runtime::sentinel::queue::Context,
    ) -> crate::runtime::sentinel::queue::AdmissionFuture<'a> {
        let _ = (request, policy, context);
        Box::pin(async {
            Err(crate::runtime::sentinel::queue::Rejected::Unavailable)
        })
    }
    /// 业务作用：向显式共享流量策略借用已经验证的 Redis 连接，不另建连接或改变后端失败模式。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：本地后端为 None；共享后端返回当前连接的引用计数句柄。
    #[cfg(feature = "redis-runtime")]
    fn redis_client(&self) -> Option<Arc<nasa::redis::RedisClient>> {
        None
    }
    /// 业务作用：判断一次请求是否允许通过。
    ///
    /// 参数说明：
    /// - `request`: 已编译规则、短 key 与活跃维度资源边界。
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a>;

    /// 业务作用：为请求次数限流提供可选批领入口，不把最终成本结算隐式改为本地扣减。
    ///
    /// 参数说明：
    /// - `request`：当前冻结规则的单请求额度。
    /// - `generation`：请求持有的配置版本，用于阻止迟到请求重新激活旧策略。
    ///
    /// 返回：默认直接沿用共享或本地精确准入；批领后端按有效预扣权威判定。
    #[cfg(feature = "rate-preallocation")]
    fn allow_preallocated<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        generation: u64,
    ) -> RateLimitFuture<'a> {
        let _ = generation;
        self.allow(request)
    }

    /// 业务作用：在后端换代时停止旧后端发放批领及排队调度权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：没有可复用权威的后端无需动作；排队与批领后端撤销尚未交付的准入资格。
    fn retire(&self) {}

    /// 业务作用：为正常停机提供有界批领回收入口，普通精确后端无需额外清理。
    ///
    /// 参数说明：
    /// - `timeout`：调用方授予的最大清理时间。
    ///
    /// 返回：普通后端立即结束；批领后端先关闭消费再等待有限回收。
    #[cfg(feature = "rate-preallocation")]
    fn shutdown_preallocation(
        &self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let _ = timeout;
        self.retire();
        Box::pin(async {})
    }

    /// 业务作用：为需要按最终成本结算的请求执行原子预留，并返回绑定本次后端实例的结算句柄。
    ///
    /// 参数说明：
    /// - `request`：是预留额度与桶边界
    /// - `reservation_id`：是全局唯一幂等标识
    /// - `max_actual`：是异常 provider 可形成的最大有界负债。
    ///
    /// 返回：返回 admission 判定；支持结算的后端在允许时同时返回 reservation，旧式后端保留完整预留且不伪造退款。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        let _ = (reservation_id, max_actual);
        Box::pin(async move {
            RateLimitReserveDecision {
                decision: self.allow(request).await,
                reservation: None,
            }
        })
    }
}

/// 一次令牌桶判定所需的借用参数与维度资源边界。
#[derive(Clone, Copy)]
pub struct RateLimitRequest<'a> {
    /// 仅请求次数使用的预热曲线；为空时保持稳定速率，不进入额外控制分支。
    pub warmup: Option<crate::runtime::sentinel::Warmup>,
    /// 来自路由冻结归属的本地状态预算；平台入口为空，不能由 header 构造。
    pub state_budget: Option<&'a crate::control::ownership::state::Budget>,
    /// 配置生成的规则作用域，隔离不同 limiter。
    pub scope: &'a str,
    /// 当前请求解析出的限流维度键。
    pub key: &'a str,
    /// 本次原子扣减的令牌数。普通 QPS 规则固定为 1；LLM 配额使用有界 token 成本。
    pub cost: u64,
    /// 窗口内基础令牌数。
    pub limit: u64,
    /// 令牌补充/固定统计窗口。
    pub window: Duration,
    /// 基础额度外的突发容量。
    pub burst: u64,
    /// 该规则允许维护的最大活动维度数。
    pub max_active_keys: usize,
    /// 维度表满时是否放行尚未存在的新 key。
    pub active_keys_fail_open: bool,
}

/// 限流后端返回 future 的统一别名。避免引入 async-trait,保持依赖面最小。
pub type RateLimitFuture<'a> = Pin<Box<dyn Future<Output = RateLimitDecision> + Send + 'a>>;

/// 带最终成本结算句柄的限流预留 future。
pub type RateLimitReserveFuture<'a> =
    Pin<Box<dyn Future<Output = RateLimitReserveDecision> + Send + 'a>>;

#[derive(Debug, Clone)]
/// 限流后端对一次请求的判定结果。数据面只根据它决定继续转发还是 429 短路。
pub struct RateLimitDecision {
    /// 本次请求是否消耗到令牌并允许进入后续管线。
    pub allowed: bool,
    /// 当前可用的剩余令牌数；批领准入仅报告本地余额，不代表集群总余额。
    pub remaining: u64,
}

/// 一次配额预留的 admission 判定与可选最终结算句柄。
pub struct RateLimitReserveDecision {
    /// 与普通限流相同的 admission 结果。
    pub decision: RateLimitDecision,
    /// 仅当支持结算的后端真实扣减了预留时存在。
    pub reservation: Option<RateLimitReservation>,
}

/// 绑定预留时后端实例的单次结算句柄；Drop 表示 usage 未知并保留完整预留。
pub struct RateLimitReservation {
    backend: Arc<dyn RateLimitSettlementBackend>,
    spec: RateLimitSettlementSpec,
}

impl RateLimitReservation {
    /// 业务作用：按 provider 最终成本幂等调整预留，多退少补；失败时保留原预留作为安全补偿。
    ///
    /// 参数说明：
    /// - `actual`：是经过 provider 协议校验的最终 token 总数。
    ///
    /// 返回：账本原子应用或识别重复结算时成功；后端连续三次失败时返回错误，原保守预留不被猜测退款。
    pub async fn settle(mut self, actual: u64) -> Result<()> {
        if actual > self.spec.max_actual {
            tracing::warn!(
                actual,
                max_actual = self.spec.max_actual,
                "provider usage exceeded configured accounting hard limit; debit was capped"
            );
        }
        self.spec.actual = actual.min(self.spec.max_actual);
        let mut last_error = None;
        for attempt in 0..3 {
            match tokio::time::timeout(
                Duration::from_millis(500),
                self.backend.apply(self.spec.clone()),
            )
            .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(anyhow::anyhow!("rate limit settlement timeout")),
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(25_u64 << attempt)).await;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("rate limit settlement failed")))
    }

    /// 业务作用：在流式 body 解析到最终 usage 时异步执行同一幂等结算，不阻塞下游数据帧背压。
    ///
    /// 参数说明：
    /// - `actual`：是 provider 最终 token 总数。
    ///
    /// 返回：无；后台失败会记录错误，完整预留继续保留，重复重放由后端 reservation id 去重。
    pub fn settle_spawn(self, actual: u64) {
        tokio::spawn(async move {
            if let Err(error) = self.settle(actual).await {
                tracing::warn!(%error, "LLM token quota settlement failed; conservative reservation retained");
            }
        });
    }

    /// 业务作用：确认请求未形成可计费 provider 成功响应时幂等退回全部预留。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：退款成功或识别重复退款时成功；后端失败时返回错误并保留预留，避免错误放大可用额度。
    pub async fn refund(self) -> Result<()> {
        self.settle(0).await
    }
}

#[derive(Clone)]
struct RateLimitSettlementSpec {
    state_budget: Option<crate::control::ownership::state::Budget>,
    reservation_id: String,
    scope: String,
    key: String,
    reserved: u64,
    actual: u64,
    max_actual: u64,
    limit: u64,
    window: Duration,
    burst: u64,
}

trait RateLimitSettlementBackend: Send + Sync {
    /// 业务作用：把一次 reservation 的最终成本幂等应用到创建它的原始额度账本。
    ///
    /// 参数说明：
    /// - `settlement`：固化 reservation id、原桶参数、预留值和最终成本。
    ///
    /// 返回：首次或重复应用成功时完成；远端或账本错误时失败并保留保守预留。
    fn apply(
        &self,
        settlement: RateLimitSettlementSpec,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;
}

/// 单进程本地令牌桶。它满足单机/Redis 故障降级可用性,但多节点时不是集群共享限流。
#[derive(Default)]
pub struct LocalRateLimiter {
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
    settlements: Arc<Mutex<HashMap<String, SettlementEntry>>>,
    queue: Arc<crate::runtime::sentinel::queue::local::Local>,
}

impl RateLimiter for LocalRateLimiter {
    /// 业务作用：按当前单调时刻读取本机桶的完整有限分类，查询不影响后续准入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前保留桶状态，锁忙或表容量超预算时明确不可用。
    fn bucket_observation(&self) -> crate::runtime::sentinel::buckets::Observation {
        self.observe_buckets(Instant::now())
    }
    /// 业务作用：使用同一后端常驻的FIFO调度状态执行单机匀速准入。
    ///
    /// 参数说明：
    /// - `request`：可信规则、维度与归属预算。
    /// - `policy`：已编译的匀速合同。
    /// - `context`：绝对等待边界。
    ///
    /// 返回：获得实际放行授权或明确拒绝，不建立第二份令牌桶。
    fn queue<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        policy: crate::runtime::sentinel::queue::Policy,
        context: crate::runtime::sentinel::queue::Context,
    ) -> crate::runtime::sentinel::queue::AdmissionFuture<'a> {
        Box::pin(self.queue.admit(request, policy, context))
    }

    /// 业务作用：后端退休时停止本地等待请求取得新的实际放行权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：队列进入退休态，原请求RAII凭证仍负责资源归还。
    fn retire(&self) {
        self.queue.retire();
    }
    /// 业务作用：在本地规则桶内执行带工作区状态预算的准入，不创建超额维度。
    ///
    /// 参数说明：
    /// - `request`：为冻结规则、成本、维度与归属预算。
    ///
    /// 返回：实际扣账或拒绝结果；容量不足不新增状态。
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        Box::pin(async move {
            self.allow_sync(request)
        })
    }

    /// 业务作用：在本地桶中原子预留 provider 最大成本，并生成绑定原桶账本的幂等结算句柄。
    ///
    /// 参数说明：
    /// - `request`：描述额度
    /// - `reservation_id`：是结算去重标识
    /// - `max_actual`：限制异常负债。
    ///
    /// 返回：返回 admission 结果；真实扣减成功时同时返回可退款或多退少补的句柄。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        Box::pin(async move {
            // 成本结算不能改变冷启动曲线或重建热桶；预热只授予单请求次数准入。
            if request.warmup.is_some() {
                return RateLimitReserveDecision {
                    decision: active_key_overflow_decision(false),
                    reservation: None,
                };
            }
            let decision = self.allow_sync(request);
            let reservation = (decision.allowed && decision.remaining != u64::MAX).then(|| {
                RateLimitReservation {
                    backend: Arc::new(LocalRateLimitSettlementBackend {
                        buckets: self.buckets.clone(),
                        settlements: self.settlements.clone(),
                    }),
                    spec: RateLimitSettlementSpec {
                        state_budget: request.state_budget.cloned(),
                        reservation_id: reservation_id.to_string(),
                        scope: request.scope.to_string(),
                        key: request.key.to_string(),
                        reserved: request.cost,
                        actual: request.cost,
                        max_actual,
                        limit: request.limit,
                        window: request.window,
                        burst: request.burst,
                    },
                }
            });
            RateLimitReserveDecision {
                decision,
                reservation,
            }
        })
    }
}

impl LocalRateLimiter {
    /// 业务作用：在原子令牌桶内执行限流，首次创建维度同时取得工作区状态名额。
    ///
    /// 参数说明：
    /// - `request`：冻结归属、维度、令牌参数和可选预热曲线。
    ///
    /// 返回：额度允许才扣减；工作区容量不足始终拒绝，不能由规则 fail-open 扩大状态表。
    fn allow_sync(&self, request: RateLimitRequest<'_>) -> RateLimitDecision {
        let RateLimitRequest {
            warmup,
            state_budget,
            scope,
            key,
            cost,
            limit,
            window,
            burst,
            max_active_keys,
            active_keys_fail_open,
        } = request;
        if warmup.is_some() && cost != 1 {
            return active_key_overflow_decision(false);
        }
        if limit == 0 || window.is_zero() || cost == 0 {
            return RateLimitDecision {
                allowed: true,
                remaining: u64::MAX,
            };
        }
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        let capacity = limit.saturating_add(burst).max(1);
        let refill_per_sec = limit as f64 / window.as_secs_f64();
        let idle_ttl = token_bucket_idle_ttl(limit, window, capacity)
            .max(warmup.map_or(Duration::ZERO, |plan| plan.period + plan.cold_after));
        if !buckets.contains_key(key) {
            let mut lease = None;
            // 只在新维度到来时清理和计数，已有维度只按借用键进行常数时间查找。
            buckets.retain(|_, bucket| {
                now.saturating_duration_since(bucket.last_refill) <= bucket.idle_ttl
            });
            let active = buckets
                .values()
                .filter(|bucket| bucket.scope == scope)
                .count();
            if active >= max_active_keys {
                return active_key_overflow_decision(active_keys_fail_open);
            }
            if let Some(budget) = state_budget {
                // 名额属于真实桶，不随请求结束归还；不得驱逐仍有额度债务的其它租户状态。
                match budget.acquire() {
                    Ok(acquired) => lease = Some(acquired),
                    Err(_) => return active_key_overflow_decision(false),
                }
            }
            buckets.insert(
                key.to_owned(),
                Bucket {
                    _lease: lease,
                    scope: scope.to_string(),
                    tokens: warmup.map_or(capacity as f64, |plan| {
                        plan.allowance(limit, window, Duration::ZERO, Duration::ZERO)
                            .0
                    }),
                    warmup_started: now,
                    last_refill: now,
                    idle_ttl,
                    warmup,
                },
            );
        }
        // 已有桶直接借用请求键；只有取得新维度容量之后才分配持久键字符串。
        let bucket = buckets.get_mut(key).expect("admitted local bucket");
        bucket.warmup = warmup;
        let (current_capacity, refill) = if let Some(plan) = warmup {
            // 连续空闲后先收紧容量再恢复补充，不能把静默期积累成冷缓存承受不了的突发。
            if now.saturating_duration_since(bucket.last_refill) >= plan.cold_after {
                bucket.warmup_started = now;
                bucket.tokens = bucket.tokens.min(
                    plan.allowance(limit, window, Duration::ZERO, Duration::ZERO)
                        .0,
                );
            }
            plan.allowance(
                limit,
                window,
                bucket
                    .last_refill
                    .saturating_duration_since(bucket.warmup_started),
                now.saturating_duration_since(bucket.warmup_started),
            )
        } else {
            (
                capacity as f64,
                now.saturating_duration_since(bucket.last_refill)
                    .as_secs_f64()
                    * refill_per_sec,
            )
        };
        bucket.tokens = (bucket.tokens + refill).min(current_capacity);
        bucket.last_refill = now;
        bucket.idle_ttl = idle_ttl;
        let cost = cost as f64;
        if bucket.tokens < cost {
            return RateLimitDecision {
                allowed: false,
                remaining: 0,
            };
        }
        bucket.tokens -= cost;
        RateLimitDecision {
            allowed: true,
            remaining: bucket.tokens.floor().max(0.0) as u64,
        }
    }
}

/// 可热替换的限流后端句柄。数据面持有它,reload 成功后原子换入新的 local/Redis 后端。
pub struct SwappableRateLimiter {
    inner: RwLock<Arc<dyn RateLimiter>>,
}

impl SwappableRateLimiter {
    /// 业务作用：用启动期构造好的后端创建热替换句柄。
    pub fn new(inner: Arc<dyn RateLimiter>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 业务作用：关闭旧后端可复用权威后发布新后端，已经创建的成本结算仍绑定原账本。
    ///
    /// 参数说明：
    /// - `next`：已完整准备的新后端。
    ///
    /// 返回：后续请求使用新后端，旧批领不再准入；在途真实成本结算不迁移。
    pub fn replace(&self, next: Arc<dyn RateLimiter>) {
        let mut inner = self.inner.write();
        // 先撤销可复用权威，再开放新后端，避免旧请求在换代后继续批领。
        inner.retire();
        *inner = next;
    }
}

impl RateLimiter for SwappableRateLimiter {
    /// 业务作用：只向当前后端转交观测，旧在途请求持有的后端不混入新状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前 owner 的原生摘要；换代锁忙时不等待也不使用上一次结果。
    fn bucket_observation(&self) -> crate::runtime::sentinel::buckets::Observation {
        let Some(inner) = self.inner.try_read().map(|inner| inner.clone()) else {
            return crate::runtime::sentinel::buckets::Observation::Busy;
        };
        inner.bucket_observation()
    }
    /// 业务作用：将一次匀速等待绑定到原后端，热更不能把尚未完成的预约迁入新账本。
    ///
    /// 参数说明：
    /// - `request`：冻结的规则和作用域。
    /// - `policy`：匀速合同。
    /// - `context`：原始绝对期限及资源边界。
    ///
    /// 返回：原后端明确授予或拒绝；换代后旧等待凭证不能取得新后端额度。
    fn queue<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        policy: crate::runtime::sentinel::queue::Policy,
        context: crate::runtime::sentinel::queue::Context,
    ) -> crate::runtime::sentinel::queue::AdmissionFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.queue(request, policy, context).await
        })
    }
    /// 业务作用：冻结当前共享连接供一次流量操作使用，等待中不切换到新后端。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前后端的共享连接；本地后端返回 None。
    #[cfg(feature = "redis-runtime")]
    fn redis_client(&self) -> Option<Arc<nasa::redis::RedisClient>> {
        self.inner.read().redis_client()
    }
    /// 业务作用：停机清理绑定当前后端，不能在等待期间迁移其未用余额。
    ///
    /// 参数说明：
    /// - `timeout`：调用方授予的清理预算。
    ///
    /// 返回：当前后端完成有界清理后结束。
    #[cfg(feature = "rate-preallocation")]
    fn shutdown_preallocation(
        &self,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.shutdown_preallocation(timeout).await;
        })
    }
    /// 业务作用：将请求次数准入绑定当前后端及请求配置版本。
    ///
    /// 参数说明：
    /// - `request`：冻结规则和预算。
    /// - `generation`：请求配置版本。
    ///
    /// 返回：当前后端的批领或精确判定，旧句柄不会切换账本。
    #[cfg(feature = "rate-preallocation")]
    fn allow_preallocated<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        generation: u64,
    ) -> RateLimitFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.allow_preallocated(request, generation).await
        })
    }
    /// 业务作用：在当前选定的限流后端执行速率准入，结果同时包含允许与拒绝的可观测依据。
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.allow(request).await
        })
    }

    /// 业务作用：从当前后端创建 reservation，并让结算句柄跨 reload 继续绑定预留时的原后端。
    ///
    /// 参数说明：
    /// - `request`：是额度请求
    /// - `reservation_id`：定义幂等结算边界。
    /// - `max_actual`：定义幂等结算边界。
    ///
    /// 返回：返回当前 generation 的 admission 与可选结算句柄；后续 replace 不改变其归属。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        let inner = self.inner.read().clone();
        // reservation 由当前 inner 创建并捕获其状态；reload 只影响后续预留，不能把在途
        // provider usage 结算到新后端，否则会同时在旧桶保留扣减并污染新桶。
        Box::pin(async move {
            inner.reserve(request, reservation_id, max_actual).await
        })
    }
}

struct Bucket {
    _lease: Option<crate::control::ownership::state::Lease>,
    scope: String,
    tokens: f64,
    last_refill: Instant,
    warmup_started: Instant,
    idle_ttl: Duration,
    warmup: Option<crate::runtime::sentinel::Warmup>,
}

struct LocalRateLimitSettlementBackend {
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
    settlements: Arc<Mutex<HashMap<String, SettlementEntry>>>,
}

struct SettlementEntry {
    expires_at: Instant,
    _lease: Option<crate::control::ownership::state::Lease>,
}

impl RateLimitSettlementBackend for LocalRateLimitSettlementBackend {
    /// 业务作用：在同一进程账本中原子去重并把 provider 实际成本调整回预留时使用的 token bucket。
    ///
    /// 参数说明：
    /// - `settlement`：包含唯一 reservation id、原桶边界、预留值和最终成本。
    ///
    /// 返回：首次或重复结算成功返回；账本容量、标识或桶参数非法时返回错误并保留原预留。
    fn apply(
        &self,
        settlement: RateLimitSettlementSpec,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
        let buckets = self.buckets.clone();
        let settlements = self.settlements.clone();
        Box::pin(async move {
            const MAX_SETTLEMENTS: usize = 1_000_000;
            if settlement.reservation_id.is_empty()
                || settlement.reservation_id.len() > 256
                || !settlement.reservation_id.is_ascii()
            {
                anyhow::bail!("invalid rate limit reservation id");
            }
            if settlement.limit == 0 || settlement.window.is_zero() {
                return Ok(());
            }
            let now = Instant::now();
            let ledger_ttl = settlement_ledger_ttl(
                settlement.limit,
                settlement.window,
                settlement.limit.saturating_add(settlement.burst).max(1),
            );
            let mut ledger = settlements.lock();
            if ledger
                .get(&settlement.reservation_id)
                .is_some_and(|entry| entry.expires_at > now)
            {
                return Ok(());
            }
            if settlement.state_budget.is_none()
                && ledger
                    .values()
                    .filter(|entry| entry._lease.is_none())
                    .count()
                    >= MAX_SETTLEMENTS
            {
                ledger.retain(|_, entry| entry.expires_at > now);
                if ledger
                    .values()
                    .filter(|entry| entry._lease.is_none())
                    .count()
                    >= MAX_SETTLEMENTS
                {
                    anyhow::bail!("local rate limit settlement ledger is full");
                }
            }

            // 去重事实和额度桶分别占一个名额；任何名额不足都保持完整预留，不生成无账本退款。
            let ledger_lease = settlement
                .state_budget
                .as_ref()
                .map(|budget| {
                    // 本域满时仅回收过期去重事实，不能删除仍有效的退款幂等凭证。
                    if let Ok(lease) = budget.acquire() {
                        return Ok(lease);
                    }
                    ledger.retain(|_, entry| entry.expires_at > now);
                    budget
                        .acquire()
                        .map_err(|_| anyhow::anyhow!("workspace settlement capacity exhausted"))
                })
                .transpose()?;

            let capacity = settlement.limit.saturating_add(settlement.burst).max(1);
            let refill_per_sec = settlement.limit as f64 / settlement.window.as_secs_f64();
            let idle_ttl = token_bucket_idle_ttl(settlement.limit, settlement.window, capacity);
            let mut buckets = buckets.lock();
            let bucket_lease = if !buckets.contains_key(&settlement.key) {
                settlement
                    .state_budget
                    .as_ref()
                    .map(|budget| {
                        budget
                            .acquire()
                            .map_err(|_| anyhow::anyhow!("workspace rate capacity exhausted"))
                    })
                    .transpose()?
            } else {
                None
            };
            let bucket = buckets
                .entry(settlement.key.clone())
                .or_insert_with(|| Bucket {
                    _lease: bucket_lease,
                    scope: settlement.scope.clone(),
                    tokens: capacity as f64,
                    last_refill: now,
                    warmup_started: now,
                    idle_ttl,
                    warmup: None,
                });
            let elapsed = now
                .saturating_duration_since(bucket.last_refill)
                .as_secs_f64();
            if elapsed > 0.0 {
                bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity as f64);
            }
            let adjustment = settlement.reserved as f64 - settlement.actual as f64;
            // 负债下限限制为一桶容量：一旦到达下限，后续 admission 都会拒绝，避免异常
            // provider usage 或并发在途结算把浮点状态推向无界负数。
            bucket.tokens = (bucket.tokens + adjustment)
                .min(capacity as f64)
                .max(-(capacity as f64));
            bucket.last_refill = now;
            bucket.idle_ttl = idle_ttl;
            ledger.insert(
                settlement.reservation_id,
                SettlementEntry {
                    expires_at: now.checked_add(ledger_ttl).unwrap_or(now),
                    _lease: ledger_lease,
                },
            );
            Ok(())
        })
    }
}

/// 业务作用：根据令牌恢复窗口确定空闲条目的保留期，防止回收导致仍有负债的身份重新获得额度。
fn token_bucket_idle_ttl(limit: u64, window: Duration, capacity: u64) -> Duration {
    let millis = window
        .as_millis()
        .saturating_mul(capacity as u128)
        .div_ceil(limit.max(1) as u128)
        .saturating_add(1_000)
        .min(u64::MAX as u128) as u64;
    Duration::from_millis(millis)
}

/// 业务作用：计算幂等 marker 至少覆盖完整桶恢复周期的有界存活时间，支持超时后安全重放结算。
///
/// 参数说明：
/// - `limit`：是预留时冻结的 token bucket 参数。
/// - `window`：是预留时冻结的 token bucket 参数。
/// - `capacity`：是预留时冻结的 token bucket 参数。
///
/// 返回：桶恢复周期加一分钟且不超过七天的 TTL。
fn settlement_ledger_ttl(limit: u64, window: Duration, capacity: u64) -> Duration {
    token_bucket_idle_ttl(limit, window, capacity)
        .saturating_add(Duration::from_secs(60))
        .min(Duration::from_secs(7 * 24 * 60 * 60))
}

/// 业务作用：在活动限流键目录已满时执行明确的溢出策略，不创建无预算状态。
fn active_key_overflow_decision(fail_open: bool) -> RateLimitDecision {
    RateLimitDecision {
        allowed: fail_open,
        remaining: if fail_open {
            u64::MAX
        } else {
            0
        },
    }
}

/// 可释放的并发连接限制接口。Redis 后端用于跨节点 `limit_conn`,local 后端用于单机/降级。
pub trait ConnLimiter: Send + Sync {
    /// 业务作用：尝试占用一个并发槽。
    ///
    /// 参数说明：
    /// - `key`: 已 hash 的规则维度 key,不得包含原始 token/header 明文。
    /// - `limit`: 同一 key 最大并发数;0 表示规则禁用。
    /// - `ttl`: Redis 崩溃泄漏兜底 TTL;local 后端忽略。
    fn acquire<'a>(&'a self, key: &'a str, limit: u64, ttl: Duration) -> ConnLimitFuture<'a>;

    /// 业务作用：释放一个并发槽。必须幂等处理异常状态。
    fn release<'a>(&'a self, key: &'a str) -> ConnLimitReleaseFuture<'a>;

    /// 业务作用：刷新并发槽 TTL。local 后端可为空操作。
    fn refresh<'a>(&'a self, key: &'a str, ttl: Duration) -> ConnLimitReleaseFuture<'a>;
}

/// 并发限制 acquire future。
pub type ConnLimitFuture<'a> = Pin<Box<dyn Future<Output = ConnLimitDecision> + Send + 'a>>;

/// 并发限制 release/refresh future。
pub type ConnLimitReleaseFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Debug, Clone)]
/// 并发限制占用结果。
pub struct ConnLimitDecision {
    /// 是否允许进入后续管线。
    pub allowed: bool,
    /// 当前已占用数量,用于调试/未来指标。
    pub current: u64,
    /// 是否需要在 guard drop 时调用 release。
    pub release_required: bool,
}

/// 单进程本地并发限制器。
#[derive(Default)]
pub struct LocalConnLimiter {
    counts: Mutex<HashMap<String, u64>>,
}

impl ConnLimiter for LocalConnLimiter {
    /// 业务作用：按维度申请并发额度，只有成功获得名额的请求才能进入受保护工作。
    fn acquire<'a>(&'a self, key: &'a str, limit: u64, _ttl: Duration) -> ConnLimitFuture<'a> {
        Box::pin(async move {
            if limit == 0 {
                return ConnLimitDecision {
                    allowed: true,
                    current: 0,
                    release_required: false,
                };
            }
            let mut counts = self.counts.lock();
            let current = *counts.get(key).unwrap_or(&0);
            if current >= limit {
                return ConnLimitDecision {
                    allowed: false,
                    current,
                    release_required: false,
                };
            }
            let next = current + 1;
            counts.insert(key.to_string(), next);
            ConnLimitDecision {
                allowed: true,
                current: next,
                release_required: true,
            }
        })
    }

    /// 业务作用：归还当前后端的并发占位，供请求结束与取消路径使用同一结算合同。
    fn release<'a>(&'a self, key: &'a str) -> ConnLimitReleaseFuture<'a> {
        Box::pin(async move {
            let mut counts = self.counts.lock();
            let Some(current) = counts.get_mut(key) else {
                return;
            };
            if *current <= 1 {
                counts.remove(key);
            } else {
                *current -= 1;
            }
        })
    }

    /// 业务作用：满足并发租约接口的续期合同；本地占位由生命周期管理，不依赖远端 TTL。
    fn refresh<'a>(&'a self, _key: &'a str, _ttl: Duration) -> ConnLimitReleaseFuture<'a> {
        Box::pin(async {})
    }
}

/// 可热替换的并发限制器句柄。reload 成功后新请求使用新后端,旧 guard 释放旧后端。
pub struct SwappableConnLimiter {
    inner: RwLock<Arc<dyn ConnLimiter>>,
}

impl SwappableConnLimiter {
    /// 业务作用：创建热替换句柄。
    pub fn new(inner: Arc<dyn ConnLimiter>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 业务作用：替换当前后端。
    pub fn replace(&self, next: Arc<dyn ConnLimiter>) {
        *self.inner.write() = next;
    }
}

impl ConnLimiter for SwappableConnLimiter {
    /// 业务作用：按维度申请并发额度，只有成功获得名额的请求才能进入受保护工作。
    fn acquire<'a>(&'a self, key: &'a str, limit: u64, ttl: Duration) -> ConnLimitFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.acquire(key, limit, ttl).await
        })
    }

    /// 业务作用：归还当前后端的并发占位，供请求结束与取消路径使用同一结算合同。
    fn release<'a>(&'a self, key: &'a str) -> ConnLimitReleaseFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.release(key).await
        })
    }

    /// 业务作用：将租约续期转发到当前选定后端，维持并发额度的有效期合同。
    fn refresh<'a>(&'a self, key: &'a str, ttl: Duration) -> ConnLimitReleaseFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.refresh(key, ttl).await
        })
    }
}

/// Redis 异常时的限流策略。open 偏可用性,closed 偏保护后端。
#[cfg(feature = "redis-runtime")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RateLimitFailMode {
    /// Redis 不可用或脚本异常时放行请求。
    Open,
    /// Redis 不可用或脚本异常时拒绝请求。
    Closed,
}

#[cfg(feature = "redis-runtime")]
impl RateLimitFailMode {
    /// 业务作用：解析限流依赖不可用时的明确处理策略，未知值必须拒绝而不能隐式放行。
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "open" | "fail-open" | "fail_open" => Ok(Self::Open),
            "closed" | "close" | "fail-closed" | "fail_closed" => Ok(Self::Closed),
            other => anyhow::bail!("unsupported rate_limiter.fail_mode `{other}`"),
        }
    }
}

/// 熔断滑动窗口内的聚合计数，数据面据此判断是否跳闸。
#[derive(Debug, Clone, Copy)]
pub struct CircuitWindowCount {
    /// 窗口内总请求数。
    pub total: u64,
    /// 窗口内按规则定义的负面样本数：上游错误或超过耗时阈值的调用。
    pub failures: u64,
}

/// 熔断统计后端：local 后端每节点各自统计，Redis 后端跨节点共享。
///
/// **只共享统计,不共享状态机**:开/半开/闭由数据面本地维护,本 trait 只负责把成功/失败计入滑动窗口并回吐窗口聚合值,
/// 各节点据【集群聚合值】各自决定是否跳闸——对齐 doc「共享统计」定位,acquire 热路径不打 Redis。
pub trait CircuitStats: Send + Sync {
    /// 业务作用：为未启用归属预算的熔断资源累计请求结果。
    ///
    /// 参数说明：
    /// - `key`：是资源身份
    /// - `success`：表示请求成功
    /// - `window`：为统计窗口。
    ///
    /// 返回：窗口内聚合计数。
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a>;

    /// 业务作用：在半开探测成功后清除旧失败统计，避免恢复后立即再次跳闸。
    ///
    /// 参数说明：
    /// - `key`：是资源身份。
    ///
    /// 返回：完成本后端清除尝试。
    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a>;

    /// 业务作用：在受信归属预算内累计有界窗口，后端可实现共享容量事务。
    ///
    /// 参数说明：
    /// - `key`：是资源和结果
    /// - `success`：是资源和结果
    /// - `window`：是资源和结果
    /// - `budget`：仅来自冻结配置。
    ///
    /// 返回：聚合计数；容量不足以饱和计数使调用方进入保护态，不静默创建额外条目。
    fn record_scoped<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsRecordFuture<'a> {
        let _ = budget;
        self.record(key, success, window)
    }

    /// 业务作用：在原归属域内清除恢复成功的熔断统计。
    ///
    /// 参数说明：
    /// - `key`：是资源身份
    /// - `budget`：固定远端命名空间。
    ///
    /// 返回：完成本后端清除尝试，不影响其它工作区。
    fn reset_scoped<'a>(
        &'a self,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsResetFuture<'a> {
        let _ = budget;
        self.reset(key)
    }
}

/// 熔断统计 record future 别名。
pub type CircuitStatsRecordFuture<'a> =
    Pin<Box<dyn Future<Output = CircuitWindowCount> + Send + 'a>>;

/// 熔断统计 reset future 别名。
pub type CircuitStatsResetFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// 单进程熔断统计；每资源至多 17 个聚合桶，边界最多保守多计一个桶宽。
#[derive(Default)]
pub struct LocalCircuitStats {
    windows: Arc<LocalCircuitWindows>,
}

#[derive(Debug, Default)]
struct LocalCircuitWindows {
    entries: Mutex<HashMap<String, LocalCircuitWindow>>,
}

#[derive(Debug)]
struct LocalCircuitWindow {
    _lease: Option<crate::control::ownership::state::Lease>,
    expires_at: Instant,
    width: Duration,
    buckets: VecDeque<CircuitBucket>,
}

#[derive(Debug)]
struct CircuitBucket {
    started: Instant,
    total: u64,
    failures: u64,
}

impl crate::control::ownership::state::ReclaimExpired for LocalCircuitWindows {
    /// 业务作用：在其它状态申请容量时归还已过期的本地窗口名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不阻塞正在更新的窗口，仅撤下过期资源。
    fn reclaim_expired(&self) {
        if let Some(mut entries) = self.entries.try_lock() {
            let now = Instant::now();
            entries.retain(|_, entry| entry.expires_at > now);
        }
    }
}

impl LocalCircuitStats {
    /// 业务作用：把请求结果压入固定数量的时间桶，流量增长不增加事件节点。
    ///
    /// 参数说明：
    /// - `key`：定义统计
    /// - `success`：定义统计
    /// - `window`：定义统计
    /// - `budget`：控制真实驻留资源数。
    ///
    /// 返回：有界聚合计数；无容量时返回饱和失败计数以触发保护。
    fn record_sync(
        &self,
        key: &str,
        success: bool,
        window: Duration,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> CircuitWindowCount {
        let now = Instant::now();
        let exhausted = CircuitWindowCount {
            total: u64::MAX,
            failures: u64::MAX,
        };
        if budget.is_some_and(|budget| !budget.register_reclaimer(self.windows.clone())) {
            return exhausted;
        }
        let width = window / 16 + Duration::from_nanos(1);
        let mut windows = self.windows.entries.lock();
        if !windows.contains_key(key) {
            windows.retain(|_, entry| entry.expires_at > now);
            if budget.is_none()
                && windows
                    .values()
                    .filter(|entry| entry._lease.is_none())
                    .count()
                    >= 65_536
            {
                return exhausted;
            }
            let lease = match budget.map(|budget| budget.acquire()).transpose() {
                Ok(lease) => lease,
                Err(_) => return exhausted,
            };
            windows.insert(
                key.to_owned(),
                LocalCircuitWindow {
                    _lease: lease,
                    expires_at: now + window + width,
                    width,
                    buckets: VecDeque::new(),
                },
            );
        }
        let entry = windows.get_mut(key).expect("inserted circuit window");
        if entry.width != width || window.is_zero() {
            entry.buckets.clear();
            entry.width = width;
        }
        entry.expires_at = now + window + width;
        while entry
            .buckets
            .front()
            .is_some_and(|bucket| now.saturating_duration_since(bucket.started) >= window + width)
        {
            entry.buckets.pop_front();
        }
        if entry
            .buckets
            .back()
            .is_none_or(|bucket| now.saturating_duration_since(bucket.started) >= width)
        {
            entry.buckets.push_back(CircuitBucket {
                started: now,
                total: 0,
                failures: 0,
            });
        }
        let bucket = entry.buckets.back_mut().expect("current circuit bucket");
        bucket.total = bucket.total.saturating_add(1);
        bucket.failures = bucket.failures.saturating_add(u64::from(!success));
        let (total, failures) =
            entry
                .buckets
                .iter()
                .fold((0u64, 0u64), |(total, failures), bucket| {
                    (
                        total.saturating_add(bucket.total),
                        failures.saturating_add(bucket.failures),
                    )
                });
        CircuitWindowCount {
            total,
            failures,
        }
    }
}

impl CircuitStats for LocalCircuitStats {
    /// 业务作用：累计平台资源的本地窗口。
    ///
    /// 参数说明：
    /// - `key`：为资源、结果和窗口。
    /// - `success`：为资源、结果和窗口。
    /// - `window`：为资源、结果和窗口。
    ///
    /// 返回：聚合计数，平台目录满时触发保护。
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a> {
        self.record_scoped(key, success, window, None)
    }

    /// 业务作用：累计工作区资源的本地窗口并持有状态名额。
    ///
    /// 参数说明：
    /// - `key`：为统计输入
    /// - `success`：为统计输入
    /// - `window`：为统计输入
    /// - `budget`：限制所属域驻留量。
    ///
    /// 返回：聚合计数，配额满时触发保护。
    fn record_scoped<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsRecordFuture<'a> {
        Box::pin(async move {
            self.record_sync(key, success, window, budget)
        })
    }

    /// 业务作用：恢复后释放本地统计及其名额。
    ///
    /// 参数说明：
    /// - `key`：为目标资源。
    ///
    /// 返回：目标不存在或已删除时均完成。
    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a> {
        Box::pin(async move {
            self.windows.entries.lock().remove(key);
        })
    }
}

/// 可热替换熔断统计后端句柄。reload 成功后原子换入新的 local/Redis 后端。
pub struct SwappableCircuitStats {
    inner: RwLock<Arc<dyn CircuitStats>>,
}

impl SwappableCircuitStats {
    /// 业务作用：用启动期构造好的后端创建热替换句柄。
    pub fn new(inner: Arc<dyn CircuitStats>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 业务作用：替换当前熔断统计后端。
    pub fn replace(&self, next: Arc<dyn CircuitStats>) {
        *self.inner.write() = next;
    }
}

impl CircuitStats for SwappableCircuitStats {
    /// 业务作用：通过冻结后端记录平台熔断结果。
    ///
    /// 参数说明：
    /// - `key`：为统计输入。
    /// - `success`：为统计输入。
    /// - `window`：为统计输入。
    ///
    /// 返回：同一后端完成的聚合计数。
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.record(key, success, window).await
        })
    }

    /// 业务作用：把受信预算传给本次冻结的统计后端。
    ///
    /// 参数说明：
    /// - `key`：为统计输入
    /// - `success`：为统计输入
    /// - `window`：为统计输入
    /// - `budget`：为归属容量。
    ///
    /// 返回：同一后端的有界聚合计数。
    fn record_scoped<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsRecordFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.record_scoped(key, success, window, budget).await
        })
    }

    /// 业务作用：通过冻结后端清除恢复成功的统计。
    ///
    /// 参数说明：
    /// - `key`：为目标资源。
    ///
    /// 返回：完成该后端清除尝试。
    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.reset(key).await
        })
    }

    /// 业务作用：在原工作区远端命名空间清除统计。
    ///
    /// 参数说明：
    /// - `key`：为目标资源
    /// - `budget`：固定归属域。
    ///
    /// 返回：完成冻结后端的清除尝试。
    fn reset_scoped<'a>(
        &'a self,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsResetFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.reset_scoped(key, budget).await
        })
    }
}

/// 一次性令牌(nonce)防重放守卫( HMAC 防重放)。local 每节点各自去重;Redis `SET NX PX` 跨节点去重。
///
/// 只保证**新鲜性**(此 token 未用过),不做签名验证——签名有效性由上层 HMAC 验签保证。
pub trait ReplayGuard: Send + Sync {
    /// 业务作用：提供严格防重放账本的权威标识，防止清空或更换后端后继续接受旧挑战。
    /// 参数说明: 无。
    /// 返回：支持严格登记的后端返回稳定标识；未知后端返回 None，调用方必须拒绝认证。
    fn strict_authority(&self) -> Option<[u8; 32]> {
        None
    }

    /// 业务作用：仅在同一权威下原子消费凭证，依赖失败与容量不足不得沿用软放行策略。
    /// 参数说明：
    /// - `authority`：签发挑战时绑定的后端权威。
    /// - `expires_at`：nonce 的绝对 Unix 秒截止时间，共享后端以自身时钟复验。
    /// - `key`：已验证凭证的不可逆摘要。
    /// - `ttl`：证据需要保留的有效期。
    /// - `budget`：已冻结的工作区状态预算。
    ///
    /// 返回：只有确实首次登记成功才为 true；不支持此合同的后端默认拒绝。
    fn check_and_set_strict<'a>(
        &'a self,
        authority: [u8; 32],
        expires_at: u64,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        let _ = (authority, expires_at, key, ttl, budget);
        Box::pin(async {
            false
        })
    }

    /// 业务作用：记录一个一次性 token,返回是否【首次出现】。
    ///
    /// 参数说明：
    /// - `key`: 已由调用方按 route + nonce 生成的去重 key。
    /// - `ttl`: token 有效期(通常 = 允许的时间戳偏差窗口),到期自动清理。
    ///
    /// 返回：
    /// `true` = 首次出现(fresh,放行);`false` = 已用过(重放,拒绝)。
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a>;

    /// 业务作用：在受信工作区预算下登记一次性凭证；后端可覆写以提供实际状态名额。
    ///
    /// 参数说明：
    /// - `key`：已含归属域
    /// - `ttl`：为有效窗
    /// - `budget`：只来自路由配置。
    ///
    /// 返回：首次登记成功为 true，重放或容量不足为 false；默认委托既有后端语义。
    fn check_and_set_scoped<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        let _ = budget;
        self.check_and_set(key, ttl)
    }
}

/// 防重放守卫 future 别名。
pub type ReplayGuardFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// 单进程本地防重放:内存 `key -> 过期时刻` 表。单机/降级可用,不跨节点去重。
pub struct LocalReplayGuard {
    seen: Mutex<ReplayLedger>,
    strict_authority: Option<[u8; 32]>,
}

/// 两个索引共享键文本；有效凭证不能像缓存条目一样被容量驱逐。
#[derive(Default)]
struct ReplayLedger {
    entries: HashMap<Arc<str>, SettlementEntry>,
    expiry: std::collections::BTreeSet<(Instant, Arc<str>)>,
    platform: usize,
}

impl ReplayLedger {
    /// 业务作用：只回收到期证据及其工作区名额，登记新凭证无需扫描全部有效记录。
    /// 参数说明：
    /// - `now`：当前单调时刻。
    ///
    /// 返回：过期记录从两个索引同步移除，平台计数随实际移除更新。
    fn prune(&mut self, now: Instant) {
        while self
            .expiry
            .first()
            .is_some_and(|(expires, _)| *expires <= now)
        {
            let (_, key) = self
                .expiry
                .pop_first()
                .expect("nonempty replay expiry index");
            if let Some(entry) = self.entries.remove(&key) {
                if entry._lease.is_none() {
                    self.platform -= 1;
                }
            }
        }
    }
}

impl Default for LocalReplayGuard {
    /// 业务作用：为新本地账本生成独立权威，空账本不能继承已消费过的旧挑战。
    /// 参数说明: 无。
    /// 返回：空账本及随机权威；熵源失败时严格认证不可用，既有其它协议不受影响。
    fn default() -> Self {
        let mut authority = [0; 32];
        Self {
            seen: Mutex::new(ReplayLedger::default()),
            strict_authority: getrandom::getrandom(&mut authority).ok().map(|_| authority),
        }
    }
}

/// 单进程防重放账本的最大活跃 nonce 数；满载时必须拒绝新 nonce，
/// 不得驱逐仍在有效期内的记录导致旧请求再次通过。
const MAX_LOCAL_REPLAY_ENTRIES: usize = 65_536;

impl LocalReplayGuard {
    /// 业务作用：原子登记 nonce，保留仍有效的防重放事实，并隔离平台与工作区状态容量。
    ///
    /// 参数说明：
    /// - `key`：为带归属的 nonce 摘要
    /// - `ttl`：为有效窗
    /// - `budget`：为受信状态预算。
    ///
    /// 返回：首次且名额足够时为 true，重复或满载时不改变有效账本。
    fn check_and_set_sync(
        &self,
        key: &str,
        ttl: Duration,
        budget: Option<&crate::control::ownership::state::Budget>,
    ) -> bool {
        let now = Instant::now();
        let mut seen = self.seen.lock();
        // 仅过期证据可退出；满载拒绝新凭证，不能通过驱逐有效 nonce 重新开放重放窗口。
        seen.prune(now);
        if seen.entries.contains_key(key)
            || (budget.is_none() && seen.platform >= MAX_LOCAL_REPLAY_ENTRIES)
        {
            return false;
        }
        let Some(expires_at) = now.checked_add(ttl) else {
            return false;
        };
        let lease = match budget.map(|budget| budget.acquire()).transpose() {
            Ok(lease) => lease,
            Err(_) => return false,
        };
        if lease.is_none() {
            seen.platform += 1;
        }
        let key: Arc<str> = Arc::from(key);
        seen.expiry.insert((expires_at, key.clone()));
        seen.entries.insert(
            key,
            SettlementEntry {
                expires_at,
                _lease: lease,
            },
        );
        true
    }
}

impl ReplayGuard for LocalReplayGuard {
    /// 业务作用：标识当前本地账本实例，阻止跨节点或账本重建后复用 nonce。
    /// 参数说明: 无。
    /// 返回：本次账本创建时的随机标识；熵源失败为 None。
    fn strict_authority(&self) -> Option<[u8; 32]> {
        self.strict_authority
    }

    /// 业务作用：复验挑战权威后按本地容量原子消费一次性凭证。
    /// 参数说明：
    /// - `authority`：挑战冻结的账本身份。
    /// - `expires_at`：nonce 的绝对 Unix 秒截止时间，共享后端以自身时钟复验。
    /// - `key`：凭证摘要。
    /// - `ttl`：有效证据保留期。
    /// - `budget`：工作区名额。
    ///
    /// 返回：仅同一账本内首次且有容量的登记成功。
    fn check_and_set_strict<'a>(
        &'a self,
        authority: [u8; 32],
        expires_at: u64,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        Box::pin(async move {
            let _ = expires_at;
            self.strict_authority == Some(authority) && self.check_and_set_sync(key, ttl, budget)
        })
    }

    /// 业务作用：原子判断并登记防重放身份，使同一有效期内的重复 nonce 被拒绝。
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a> {
        Box::pin(async move {
            self.check_and_set_sync(key, ttl, None)
        })
    }

    /// 业务作用：把防重放条目绑定到请求的配置预算，满载始终失败闭合。
    ///
    /// 参数说明：
    /// - `key`：固定此次 nonce 的作用域和容量。
    /// - `ttl`：固定此次 nonce 的作用域和容量。
    /// - `budget`：固定此次 nonce 的作用域和容量。
    ///
    /// 返回：仅真实首次登记返回 true。
    fn check_and_set_scoped<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        Box::pin(async move {
            self.check_and_set_sync(key, ttl, budget)
        })
    }
}

/// 可热替换防重放守卫句柄。reload 成功后原子换入新的 local/Redis 后端。
pub struct SwappableReplayGuard {
    inner: RwLock<Arc<dyn ReplayGuard>>,
}

impl SwappableReplayGuard {
    /// 业务作用：用启动期构造好的后端创建热替换句柄。
    pub fn new(inner: Arc<dyn ReplayGuard>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 业务作用：替换当前防重放后端。
    pub fn replace(&self, next: Arc<dyn ReplayGuard>) {
        *self.inner.write() = next;
    }
}

impl ReplayGuard for SwappableReplayGuard {
    /// 业务作用：读取当前可消费凭证的后端权威，不能把热换句柄本身当作账本身份。
    /// 参数说明: 无。
    /// 返回：当前后端的严格权威标识或不可用。
    fn strict_authority(&self) -> Option<[u8; 32]> {
        self.inner.read().strict_authority()
    }

    /// 业务作用：冻结一个后端执行严格登记，热换到不同权威后拒绝旧挑战。
    /// 参数说明：
    /// - `authority`：认证计算时冻结的权威。
    /// - `expires_at`：nonce 的绝对 Unix 秒截止时间，共享后端以自身时钟复验。
    /// - `key`：一次性凭证摘要。
    /// - `ttl`：证据保留期。
    /// - `budget`：受信归属预算。
    ///
    /// 返回：只返回冻结后端的严格登记结果，不跨后端重试。
    fn check_and_set_strict<'a>(
        &'a self,
        authority: [u8; 32],
        expires_at: u64,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner
                .check_and_set_strict(authority, expires_at, key, ttl, budget)
                .await
        })
    }

    /// 业务作用：向当前后端透传工作区预算，换代不能退回无归属的登记入口。
    ///
    /// 参数说明：
    /// - `key`：是冻结请求权威。
    /// - `ttl`：是冻结请求权威。
    /// - `budget`：是冻结请求权威。
    ///
    /// 返回：当前后端真实登记结果。
    fn check_and_set_scoped<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.check_and_set_scoped(key, ttl, budget).await
        })
    }
    /// 业务作用：原子判断并登记防重放身份，使同一有效期内的重复 nonce 被拒绝。
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move {
            inner.check_and_set(key, ttl).await
        })
    }
}

/// 业务作用：在候选发布前验证批领边界并完整构造选定的限流后端。
///
/// 参数说明：
/// - `cfg`：候选快照冻结的共享运行态配置。
///
/// 返回：配置与外部连接全部有效后返回后端；缺少制品能力、无效边界或准备失败拒绝候选。
pub async fn build_rate_limiter(cfg: &RuntimeStateCfg) -> Result<Arc<dyn RateLimiter>> {
    cfg.rate_limiter.validate_preallocation()?;
    match cfg
        .rate_limiter
        .backend
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "local" | "memory" => Ok(Arc::new(LocalRateLimiter::default())),
        "redis" => build_redis_rate_limiter(cfg).await,
        other => anyhow::bail!("unsupported runtime_state.rate_limiter.backend `{other}`"),
    }
}

/// 业务作用：按 `gateway.yml` 的运行态配置构造并发连接限制后端。
pub async fn build_conn_limiter(cfg: &RuntimeStateCfg) -> Result<Arc<dyn ConnLimiter>> {
    match cfg
        .rate_limiter
        .backend
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "local" | "memory" => Ok(Arc::new(LocalConnLimiter::default())),
        "redis" => build_redis_conn_limiter(cfg).await,
        other => anyhow::bail!("unsupported runtime_state.rate_limiter.backend `{other}`"),
    }
}

/// 业务作用：生成限流与 ACME Redis 锁共享连接参数的稳定签名，驱动成功候选的运行态换代。
///
/// 参数说明：
/// - `cfg`：是候选快照的运行态配置。
///
/// 返回：返回只用于进程内相等比较的签名；不会写入日志或管理面。
pub fn rate_limiter_config_signature(cfg: &RuntimeStateCfg) -> String {
    let redis = &cfg.rate_limiter.redis;
    format!(
        "{}|{}|{}|{}|{}|{:?}",
        cfg.rate_limiter.backend.trim(),
        cfg.rate_limiter.fail_mode.trim(),
        redis.url.trim(),
        redis.namespace.trim(),
        redis.profile.trim(),
        cfg.rate_limiter.local_preallocation
    )
}

/// 业务作用：按网关运行态配置构造熔断统计后端。
///
/// `circuit_breaker.shared=false`(默认)→ 本地各自统计;`true` → 复用 `rate_limiter.redis` 连接跨节点共享。
pub async fn build_circuit_stats(cfg: &RuntimeStateCfg) -> Result<Arc<dyn CircuitStats>> {
    if cfg.circuit_breaker.shared {
        build_redis_circuit_stats(cfg).await
    } else {
        Ok(Arc::new(LocalCircuitStats::default()))
    }
}

/// 业务作用：熔断统计后端的配置签名。reload 用它判断是否需要重建后端连接(独立于限流签名,避免互相牵连重建)。
pub fn circuit_stats_config_signature(cfg: &RuntimeStateCfg) -> String {
    let redis = &cfg.rate_limiter.redis;
    format!(
        "{}|{}|{}|{}",
        cfg.circuit_breaker.shared,
        redis.url.trim(),
        redis.namespace.trim(),
        redis.profile.trim()
    )
}

/// 业务作用：按 `gateway.yml` 的运行态配置构造 HMAC 防重放守卫后端。
///
/// `replay_guard.backend=local`(默认)→ 每节点内存去重;`redis` → 复用 `rate_limiter.redis` 跨节点 `SET NX PX`。
pub async fn build_replay_guard(cfg: &RuntimeStateCfg) -> Result<Arc<dyn ReplayGuard>> {
    match cfg
        .replay_guard
        .backend
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "local" | "memory" => Ok(Arc::new(LocalReplayGuard::default())),
        "redis" => build_redis_replay_guard(cfg).await,
        other => anyhow::bail!("unsupported runtime_state.replay_guard.backend `{other}`"),
    }
}

/// 业务作用：防重放守卫后端的配置签名。reload 用它判断是否需要重建后端连接。
pub fn replay_guard_config_signature(cfg: &RuntimeStateCfg) -> String {
    let redis = &cfg.rate_limiter.redis;
    format!(
        "{}|{}|{}|{}|{}",
        cfg.replay_guard.backend.trim(),
        cfg.replay_guard.fail_mode.trim(),
        redis.url.trim(),
        redis.namespace.trim(),
        redis.profile.trim()
    )
}

/// 业务作用：按候选配置完整初始化动态事实源，成功前不替换在线后端。
///
/// 参数说明：
/// - `cfg`：选择 file/Redis/Nacos 并提供资源硬门
/// - `cfg_path`：用于解析 file 相对路径。
///
/// 返回：后端初始化完成时返回共享实例；配置、feature 或外部连接失败时拒绝候选。
pub async fn build_dynamic_store(
    cfg: &RuntimeStateCfg,
    cfg_path: &Path,
) -> Result<Arc<dyn DynamicStore>> {
    match cfg.store.backend.trim().to_ascii_lowercase().as_str() {
        "" | "file" | "local" => {
            let root = resolve_relative(cfg_path, &cfg.store.file.root);
            Ok(Arc::new(FileDynamicStore::new(root)))
        }
        "redis" => build_redis_dynamic_store(cfg).await,
        "nacos" => build_nacos_dynamic_store(cfg).await,
        other => anyhow::bail!("unsupported runtime_state.store.backend `{other}`"),
    }
}

/// 业务作用：生成动态事实源连接、命名与资源边界的稳定签名，防止 reload 成功却沿用旧后端。
///
/// 参数说明：
/// - `cfg`：是当前或候选运行态配置。
///
/// 返回：返回只用于进程内相等比较的签名；包含的 credential 不进入日志或管理响应。
pub fn dynamic_store_config_signature(cfg: &RuntimeStateCfg) -> String {
    let redis = &cfg.store.redis;
    let nacos = &cfg.store.nacos;
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        cfg.store.backend.trim(),
        cfg.store.file.root.trim(),
        redis.url.trim(),
        redis.namespace.trim(),
        redis.profile.trim(),
        redis.prefix.trim(),
        nacos.server_addr.trim(),
        nacos.namespace.trim(),
        nacos.group.trim(),
        nacos.app_name.trim(),
        nacos.username.trim(),
        nacos.password.trim(),
        nacos.data_id_prefix.trim(),
        nacos.max_document_bytes,
    )
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：构造并连接 Nacos-backed DynamicStore，连接成功前不替换当前在线后端。
///
/// 参数说明：
/// - `cfg`：是候选快照的 runtime-state 配置。
///
/// 返回：actor 与 Nacos 配置服务就绪时返回后端；配置或连接失败时返回错误，由 reload 保留旧后端。
async fn build_nacos_dynamic_store(cfg: &RuntimeStateCfg) -> Result<Arc<dyn DynamicStore>> {
    Ok(Arc::new(
        NacosDynamicStore::connect(cfg.store.nacos.clone()).await?,
    ))
}

#[cfg(not(feature = "nacos-sdk"))]
/// 业务作用：在未编入 Nacos SDK 的制品中显式拒绝 Nacos DynamicStore，禁止静默降级到本地事实源。
///
/// 参数说明：
/// - `_cfg`：是已选择 Nacos 的候选运行态配置，本制品不会读取其中 credential。
///
/// 返回：始终返回 feature 缺失错误，使启动或 reload 保留既有后端。
async fn build_nacos_dynamic_store(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn DynamicStore>> {
    anyhow::bail!(
        "runtime_state.store.backend=nacos requires building gateway with feature `nacos-sdk`"
    )
}

/// 业务作用：按制品能力与兼容配置构建共享动态事实源，未启用 Redis 时拒绝相关声明。
#[cfg(feature = "redis-runtime")]
async fn build_redis_dynamic_store(cfg: &RuntimeStateCfg) -> Result<Arc<dyn DynamicStore>> {
    use nasa::redis::{RedisClient, RedisConfig};

    let redis = &cfg.store.redis;
    if redis.url.trim().is_empty() {
        anyhow::bail!("runtime_state.store.redis.url is required when backend=redis");
    }
    let profile = parse_redis_profile(&redis.profile, "runtime_state.store.redis.profile")?;
    let redis_cfg = RedisConfig::new(redis.url.clone(), redis.namespace.clone(), profile);
    let client = RedisClient::connect(redis_cfg)
        .await
        .context("connect Redis dynamic store through nasa::redis")?;
    Ok(Arc::new(RedisDynamicStore::new(
        client,
        redis.prefix.clone(),
    )))
}

/// 业务作用：按制品能力与兼容配置构建共享动态事实源，未启用 Redis 时拒绝相关声明。
#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_dynamic_store(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn DynamicStore>> {
    anyhow::bail!(
        "runtime_state.store.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

/// 业务作用：构建共享速率准入后端，冻结连接、超时及依赖失败策略。
///
/// 参数说明：
/// - `cfg`：经过边界校验的候选运行态。
///
/// 返回：NASA 连接及可选批领层准备完成时返回后端；任何准备失败阻止候选发布。
#[cfg(feature = "redis-runtime")]
async fn build_redis_rate_limiter(cfg: &RuntimeStateCfg) -> Result<Arc<dyn RateLimiter>> {
    use nasa::redis::{RedisClient, RedisConfig};

    let redis = &cfg.rate_limiter.redis;
    let profile = parse_redis_profile(&redis.profile, "runtime_state.rate_limiter.redis.profile")?;
    let fail_mode = RateLimitFailMode::parse(&cfg.rate_limiter.fail_mode)?;
    let redis_cfg = RedisConfig::new(redis.url.clone(), redis.namespace.clone(), profile);
    let client = RedisClient::connect(redis_cfg)
        .await
        .context("connect Redis rate limiter through nasa::redis")?;
    let backend = Arc::new(RedisRateLimiter::new(client.clone(), fail_mode));
    #[cfg(feature = "rate-preallocation")]
    if let Some(policy) = cfg.rate_limiter.local_preallocation {
        return Ok(Arc::new(crate::runtime::ratelimit::Preallocated::new(
            backend, client, fail_mode, policy,
        )?));
    }
    Ok(backend)
}

/// 业务作用：构建共享并发额度后端，使跨节点名额申请使用同一原子计数合同。
#[cfg(feature = "redis-runtime")]
async fn build_redis_conn_limiter(cfg: &RuntimeStateCfg) -> Result<Arc<dyn ConnLimiter>> {
    use nasa::redis::{RedisClient, RedisConfig};

    let redis = &cfg.rate_limiter.redis;
    let profile = parse_redis_profile(&redis.profile, "runtime_state.rate_limiter.redis.profile")?;
    let fail_mode = RateLimitFailMode::parse(&cfg.rate_limiter.fail_mode)?;
    let redis_cfg = RedisConfig::new(redis.url.clone(), redis.namespace.clone(), profile);
    let client = RedisClient::connect(redis_cfg)
        .await
        .context("connect Redis conn limiter through nasa::redis")?;
    Ok(Arc::new(RedisConnLimiter::new(client, fail_mode)))
}

/// 业务作用：构建共享熔断统计后端，默认不启用时不创建 Redis 状态访问。
#[cfg(feature = "redis-runtime")]
async fn build_redis_circuit_stats(cfg: &RuntimeStateCfg) -> Result<Arc<dyn CircuitStats>> {
    use nasa::redis::{RedisClient, RedisConfig};

    // 复用限流的 Redis 连接参数(同一集群),避免再开一套连接配置。
    let redis = &cfg.rate_limiter.redis;
    if redis.url.trim().is_empty() {
        anyhow::bail!(
            "runtime_state.circuit_breaker.shared=true requires runtime_state.rate_limiter.redis.url"
        );
    }
    let profile = parse_redis_profile(&redis.profile, "runtime_state.rate_limiter.redis.profile")?;
    let redis_cfg = RedisConfig::new(redis.url.clone(), redis.namespace.clone(), profile);
    let client = RedisClient::connect(redis_cfg)
        .await
        .context("connect Redis circuit stats through nasa::redis")?;
    Ok(Arc::new(RedisCircuitStats::new(client)))
}

/// 业务作用：构建共享 nonce 占位后端，防止不同网关节点重复接受同一签名请求。
#[cfg(feature = "redis-runtime")]
async fn build_redis_replay_guard(cfg: &RuntimeStateCfg) -> Result<Arc<dyn ReplayGuard>> {
    use nasa::redis::{RedisClient, RedisConfig};

    // 复用限流的 Redis 连接参数(同一集群)。
    let redis = &cfg.rate_limiter.redis;
    if redis.url.trim().is_empty() {
        anyhow::bail!(
            "runtime_state.replay_guard.backend=redis requires runtime_state.rate_limiter.redis.url"
        );
    }
    let profile = parse_redis_profile(&redis.profile, "runtime_state.rate_limiter.redis.profile")?;
    let fail_mode = RateLimitFailMode::parse(&cfg.replay_guard.fail_mode)?;
    let redis_cfg = RedisConfig::new(redis.url.clone(), redis.namespace.clone(), profile);
    let client = RedisClient::connect(redis_cfg)
        .await
        .context("connect Redis replay guard through nasa::redis")?;
    Ok(Arc::new(RedisReplayGuard::new(client, fail_mode)))
}

/// 业务作用：验证声明的 Redis 兼容能力，避免在不支持的后端执行必要原子操作。
#[cfg(feature = "redis-runtime")]
fn parse_redis_profile(raw: &str, label: &str) -> Result<nasa::redis::CompatibilityProfile> {
    match raw.trim() {
        "RustV2" | "rustv2" | "rust-v2" => Ok(nasa::redis::CompatibilityProfile::RustV2),
        "LegacyV1" | "legacyv1" | "legacy-v1" => Ok(nasa::redis::CompatibilityProfile::LegacyV1),
        other => anyhow::bail!("unsupported {label} `{other}`"),
    }
}

/// 业务作用：构建共享速率准入后端，冻结连接、超时及依赖失败策略。
#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_rate_limiter(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn RateLimiter>> {
    anyhow::bail!(
        "runtime_state.rate_limiter.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

/// 业务作用：构建共享并发额度后端，使跨节点名额申请使用同一原子计数合同。
#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_conn_limiter(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn ConnLimiter>> {
    anyhow::bail!(
        "runtime_state.rate_limiter.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

/// 业务作用：构建共享熔断统计后端，默认不启用时不创建 Redis 状态访问。
#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_circuit_stats(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn CircuitStats>> {
    anyhow::bail!(
        "runtime_state.circuit_breaker.shared=true requires building gateway with feature `redis-runtime`"
    )
}

/// 业务作用：构建共享 nonce 占位后端，防止不同网关节点重复接受同一签名请求。
#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_replay_guard(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn ReplayGuard>> {
    anyhow::bail!(
        "runtime_state.replay_guard.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

#[cfg(feature = "redis-runtime")]
const TOKEN_BUCKET_LUA: &str = include_str!("redis/token_bucket.lua");

#[cfg(feature = "redis-runtime")]
const TOKEN_BUCKET_SETTLE_LUA: &str = include_str!("redis/token_settle.lua");

#[cfg(feature = "redis-runtime")]
const CONN_ACQUIRE_LUA: &str = include_str!("redis/connection_acquire.lua");

#[cfg(feature = "redis-runtime")]
const CONN_RELEASE_LUA: &str = include_str!("redis/connection_release.lua");

/// Redis Lua 令牌桶。所有节点对同一 key 执行原子 EVAL,实现集群共享 QPS。
#[cfg(feature = "redis-runtime")]
pub struct RedisRateLimiter {
    client: Arc<nasa::redis::RedisClient>,
    fail_mode: RateLimitFailMode,
    queue_retired: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "redis-runtime")]
impl RedisRateLimiter {
    /// 业务作用：创建 Redis 限流后端。调用方负责通过 `nasa::redis` 完成连接和协议 marker 校验。
    pub fn new(client: Arc<nasa::redis::RedisClient>, fail_mode: RateLimitFailMode) -> Self {
        Self {
            client,
            fail_mode,
            queue_retired: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[cfg(feature = "redis-runtime")]
impl RateLimiter for RedisRateLimiter {
    /// 业务作用：声明共享桶不能由本机枚举，管理采样不得增加 Redis 扫描或连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：明确的共享后端边界，不把空本地表当成集群零状态。
    fn bucket_observation(&self) -> crate::runtime::sentinel::buckets::Observation {
        crate::runtime::sentinel::buckets::Observation::Shared
    }
    /// 业务作用：让匀速队列直接使用共享调度权威，不继承普通令牌桶的故障放行策略。
    ///
    /// 参数说明：
    /// - `request`：冻结规则和归属预算。
    /// - `policy`：整数间隔和队列资源合同。
    /// - `context`：原请求绝对期限与实体上界。
    ///
    /// 返回：明确共享授权时成功，未知提交或失权一律拒绝。
    fn queue<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        policy: crate::runtime::sentinel::queue::Policy,
        context: crate::runtime::sentinel::queue::Context,
    ) -> crate::runtime::sentinel::queue::AdmissionFuture<'a> {
        Box::pin(crate::runtime::sentinel::queue::redis::admit(
            self.client.clone(),
            &self.queue_retired,
            request,
            policy,
            context,
        ))
    }

    /// 业务作用：撤销旧共享后端的队列准入资格，等待者不得迁移到新后端继续放行。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：进入退休态，已提交的共享间隔债务保持有效。
    fn retire(&self) {
        self.queue_retired
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// 业务作用：让精确流量账本复用已经完成协议校验的 NASA Redis 客户端。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一连接池的共享句柄，不执行网络操作。
    fn redis_client(&self) -> Option<Arc<nasa::redis::RedisClient>> {
        Some(self.client.clone())
    }
    /// 业务作用：在当前选定的限流后端执行速率准入，结果同时包含允许与拒绝的可观测依据。
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let RateLimitRequest {
                warmup,
                state_budget,
                scope,
                key,
                cost,
                limit,
                window,
                burst,
                max_active_keys,
                active_keys_fail_open,
            } = request;
            if warmup.is_some() && cost != 1 {
                return active_key_overflow_decision(false);
            }
            if limit == 0 || window.is_zero() || cost == 0 {
                return RateLimitDecision {
                    allowed: true,
                    remaining: u64::MAX,
                };
            }
            let capacity = limit.saturating_add(burst).max(1);
            let refill_per_sec = limit as f64 / window.as_secs_f64();
            if refill_per_sec <= 0.0 || !refill_per_sec.is_finite() {
                return RateLimitDecision {
                    allowed: true,
                    remaining: u64::MAX,
                };
            }
            let (redis_key, active_key, _, owner_key) = redis_scoped_rate_limit_keys(
                scope,
                key,
                state_budget,
                &self.client.config().namespace,
            );
            let owner_limit = state_budget
                .map_or(0, |budget| budget.remote_scope().1)
                .to_string();
            let capacity = capacity.to_string();
            let refill = format!("{refill_per_sec:.12}");
            let max_active_keys = max_active_keys.min(i64::MAX as usize).to_string();
            let overflow_allowed = if active_keys_fail_open {
                "1"
            } else {
                "0"
            };
            let cost = cost.to_string();
            let warmup_args = warmup.map(|plan| {
                [
                    plan.period.as_millis().to_string(),
                    plan.cold_factor.to_string(),
                    plan.cold_after.as_millis().to_string(),
                ]
            });
            let args = [
                capacity.as_str(),
                refill.as_str(),
                max_active_keys.as_str(),
                overflow_allowed,
                key,
                cost.as_str(),
                owner_limit.as_str(),
                warmup_args.as_ref().map_or("0", |args| args[0].as_str()),
                warmup_args.as_ref().map_or("1", |args| args[1].as_str()),
                warmup_args.as_ref().map_or("0", |args| args[2].as_str()),
            ];
            let result = self
                .client
                .eval::<Vec<i64>>(
                    TOKEN_BUCKET_LUA,
                    &[redis_key.as_str(), active_key.as_str(), owner_key.as_str()],
                    if warmup.is_some() {
                        &args
                    } else {
                        &args[..7]
                    },
                )
                .await;
            match result {
                Ok(values) if values.len() >= 2 => RateLimitDecision {
                    allowed: values[0] == 1,
                    remaining: values[1].max(0) as u64,
                },
                Ok(values) => {
                    tracing::warn!(
                        ?values,
                        "redis rate limiter returned unexpected token bucket result"
                    );
                    self.fail_decision()
                }
                Err(err) => {
                    tracing::warn!(error = %err, "redis rate limiter failed");
                    self.fail_decision()
                }
            }
        })
    }

    /// 业务作用：在共享 Redis 桶中预留 provider 成本，并创建与同 cluster slot 幂等 marker 绑定的结算句柄。
    ///
    /// 参数说明：
    /// - `request`：描述额度
    /// - `reservation_id`：是跨重试去重标识
    /// - `max_actual`：限制异常负债。
    ///
    /// 返回：返回 Redis admission 结果；真实扣减且未走 fail-open 时同时返回可结算句柄。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        Box::pin(async move {
            // 预热额度不具有 provider 成本退款权威，不能由结算重建完整容量。
            if request.warmup.is_some() {
                return RateLimitReserveDecision {
                    decision: active_key_overflow_decision(false),
                    reservation: None,
                };
            }
            let decision = self.allow(request).await;
            let reservation = (decision.allowed && decision.remaining != u64::MAX).then(|| {
                let (redis_key, _, settlement_prefix, owner_key) = redis_scoped_rate_limit_keys(
                    request.scope,
                    request.key,
                    request.state_budget,
                    &self.client.config().namespace,
                );
                RateLimitReservation {
                    backend: Arc::new(RedisRateLimitSettlementBackend {
                        client: self.client.clone(),
                        redis_key,
                        settlement_prefix,
                        owner_key,
                    }),
                    spec: RateLimitSettlementSpec {
                        reservation_id: reservation_id.to_string(),
                        state_budget: request.state_budget.cloned(),
                        scope: request.scope.to_string(),
                        key: request.key.to_string(),
                        reserved: request.cost,
                        actual: request.cost,
                        max_actual,
                        limit: request.limit,
                        window: request.window,
                        burst: request.burst,
                    },
                }
            });
            RateLimitReserveDecision {
                decision,
                reservation,
            }
        })
    }
}

#[cfg(feature = "redis-runtime")]
struct RedisRateLimitSettlementBackend {
    owner_key: String,
    client: Arc<nasa::redis::RedisClient>,
    redis_key: String,
    settlement_prefix: String,
}

#[cfg(feature = "redis-runtime")]
impl RateLimitSettlementBackend for RedisRateLimitSettlementBackend {
    /// 业务作用：用 Redis Lua 在共享 token bucket 上原子执行 reservation id 去重与多退少补。
    ///
    /// 参数说明：
    /// - `settlement`：携带预留值、provider 最终成本和原桶补充参数。
    ///
    /// 返回：首次应用或已存在同 id marker 时成功；Redis/协议错误返回失败，由句柄重试并保留原预留。
    fn apply(
        &self,
        settlement: RateLimitSettlementSpec,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
        let client = self.client.clone();
        let redis_key = self.redis_key.clone();
        let owner_key = self.owner_key.clone();
        let settlement_prefix = self.settlement_prefix.clone();
        Box::pin(async move {
            if settlement.reservation_id.is_empty()
                || settlement.reservation_id.len() > 256
                || !settlement.reservation_id.is_ascii()
            {
                anyhow::bail!("invalid rate limit reservation id");
            }
            if settlement.limit == 0 || settlement.window.is_zero() {
                return Ok(());
            }
            let capacity = settlement.limit.saturating_add(settlement.burst).max(1);
            let refill_per_sec = settlement.limit as f64 / settlement.window.as_secs_f64();
            if refill_per_sec <= 0.0 || !refill_per_sec.is_finite() {
                anyhow::bail!("invalid rate limit settlement refill rate");
            }
            let ledger_ttl = settlement_ledger_ttl(settlement.limit, settlement.window, capacity)
                .as_millis()
                .min(i64::MAX as u128)
                .to_string();
            let settlement_key = format!("{}{}", settlement_prefix, settlement.reservation_id);
            let capacity = capacity.to_string();
            let refill = format!("{refill_per_sec:.12}");
            let reserved = settlement.reserved.to_string();
            let actual = settlement.actual.to_string();
            let owner_limit = settlement
                .state_budget
                .as_ref()
                .map_or(0, |budget| budget.remote_scope().1)
                .to_string();
            client
                .eval::<i64>(
                    TOKEN_BUCKET_SETTLE_LUA,
                    &[
                        redis_key.as_str(),
                        settlement_key.as_str(),
                        owner_key.as_str(),
                    ],
                    &[
                        capacity.as_str(),
                        refill.as_str(),
                        reserved.as_str(),
                        actual.as_str(),
                        ledger_ttl.as_str(),
                        owner_limit.as_str(),
                    ],
                )
                .await
                .context("Redis token quota settlement")?;
            Ok(())
        })
    }
}

#[cfg(feature = "redis-runtime")]
/// 业务作用：为同一 rate-limit scope 生成共享 Redis Cluster hash tag，使桶、活跃维度与结算 marker 可原子执行 Lua。
///
/// 参数说明：
/// - `scope`：是配置生成的规则作用域
/// - `key`：是已经脱敏的维度键。
///
/// 返回：同 slot 的 bucket key、active key 和 settlement key 前缀；原始身份不写入 key。
fn redis_rate_limit_keys(scope: &str, key: &str) -> (String, String, String) {
    let digest = Sha256::digest(scope.as_bytes());
    let mut tag = String::with_capacity(16);
    use std::fmt::Write as _;
    for byte in &digest[..8] {
        write!(&mut tag, "{byte:02x}").expect("writing SHA-256 tag cannot fail");
    }
    (
        format!("gw:ratelimit:{{{tag}}}:bucket:{key}"),
        format!("gw:ratelimit:{{{tag}}}:active"),
        format!("gw:ratelimit:{{{tag}}}:settlement:"),
    )
}

#[cfg(feature = "redis-runtime")]
/// 业务作用：把工作区的所有限流规则与结算账本放入同一 Redis slot，以共享原子容量门。
///
/// 参数说明：
/// - `scope`：固定限流规则域。
/// - `key`：规则内的请求维度键。
/// - `budget`：来自路由归属权威的预算，平台域为空。
/// - `namespace`：Redis 状态键使用的固定命名空间。
///
/// 返回：桶、规则索引、结算前缀和工作区容量索引；平台键布局保持不变。
pub(super) fn redis_scoped_rate_limit_keys(
    scope: &str,
    key: &str,
    budget: Option<&crate::control::ownership::state::Budget>,
    namespace: &str,
) -> (String, String, String, String) {
    let Some(budget) = budget else {
        let (bucket, active, settlement) = redis_rate_limit_keys(scope, key);
        return (bucket, active.clone(), settlement, active);
    };
    let rule = format!("{:x}", Sha256::digest(scope.as_bytes()));
    let dimension = format!("{:x}", Sha256::digest(key.as_bytes()));
    let (_, owner_key) = budget.redis_keys(namespace, "rate", key);
    let prefix = owner_key.trim_end_matches(":states");
    (
        format!("{prefix}:rate:{rule}:{dimension}"),
        format!("{prefix}:active:{rule}"),
        format!("{prefix}:settlement:{rule}:"),
        owner_key,
    )
}

#[cfg(feature = "redis-runtime")]
impl RedisRateLimiter {
    /// 业务作用：把共享依赖失败映射为配置声明的准入决定，不把依赖错误当作真实额度证据。
    fn fail_decision(&self) -> RateLimitDecision {
        match self.fail_mode {
            RateLimitFailMode::Open => RateLimitDecision {
                allowed: true,
                remaining: u64::MAX,
            },
            RateLimitFailMode::Closed => RateLimitDecision {
                allowed: false,
                remaining: 0,
            },
        }
    }
}

/// Redis Lua 并发连接限制器。所有节点对同一 key 执行原子 INCR/DECR。
#[cfg(feature = "redis-runtime")]
pub struct RedisConnLimiter {
    client: Arc<nasa::redis::RedisClient>,
    fail_mode: RateLimitFailMode,
}

#[cfg(feature = "redis-runtime")]
impl RedisConnLimiter {
    /// 业务作用：创建 Redis 并发限制后端。
    pub fn new(client: Arc<nasa::redis::RedisClient>, fail_mode: RateLimitFailMode) -> Self {
        Self {
            client,
            fail_mode,
        }
    }

    /// 业务作用：为受保护的并发或防重放维度编码共享键，保持命名空间隔离。
    fn redis_key(key: &str) -> String {
        format!("gw:limitconn:{key}")
    }

    /// 业务作用：把共享依赖失败映射为配置声明的准入决定，不把依赖错误当作真实额度证据。
    fn fail_decision(&self) -> ConnLimitDecision {
        match self.fail_mode {
            RateLimitFailMode::Open => ConnLimitDecision {
                allowed: true,
                current: 0,
                release_required: false,
            },
            RateLimitFailMode::Closed => ConnLimitDecision {
                allowed: false,
                current: 0,
                release_required: false,
            },
        }
    }
}

#[cfg(feature = "redis-runtime")]
impl ConnLimiter for RedisConnLimiter {
    /// 业务作用：按维度申请并发额度，只有成功获得名额的请求才能进入受保护工作。
    fn acquire<'a>(&'a self, key: &'a str, limit: u64, ttl: Duration) -> ConnLimitFuture<'a> {
        Box::pin(async move {
            if limit == 0 {
                return ConnLimitDecision {
                    allowed: true,
                    current: 0,
                    release_required: false,
                };
            }
            let redis_key = Self::redis_key(key);
            let limit = limit.to_string();
            let ttl_ms = ttl.as_millis().clamp(1, u128::from(u64::MAX)).to_string();
            let result = self
                .client
                .eval::<Vec<i64>>(
                    CONN_ACQUIRE_LUA,
                    &[redis_key.as_str()],
                    &[limit.as_str(), ttl_ms.as_str()],
                )
                .await;
            match result {
                Ok(values) if values.len() >= 2 => ConnLimitDecision {
                    allowed: values[0] == 1,
                    current: values[1].max(0) as u64,
                    release_required: values[0] == 1,
                },
                Ok(values) => {
                    tracing::warn!(?values, "redis conn limiter returned unexpected result");
                    self.fail_decision()
                }
                Err(err) => {
                    tracing::warn!(error = %err, "redis conn limiter acquire failed");
                    self.fail_decision()
                }
            }
        })
    }

    /// 业务作用：归还当前后端的并发占位，供请求结束与取消路径使用同一结算合同。
    fn release<'a>(&'a self, key: &'a str) -> ConnLimitReleaseFuture<'a> {
        Box::pin(async move {
            let redis_key = Self::redis_key(key);
            if let Err(err) = self
                .client
                .eval::<i64>(CONN_RELEASE_LUA, &[redis_key.as_str()], &[])
                .await
            {
                tracing::warn!(error = %err, "redis conn limiter release failed");
            }
        })
    }

    /// 业务作用：延长共享并发占位的存活期，避免长请求在仍执行时失去计数保护。
    fn refresh<'a>(&'a self, key: &'a str, ttl: Duration) -> ConnLimitReleaseFuture<'a> {
        Box::pin(async move {
            let redis_key = Self::redis_key(key);
            if let Err(err) = self
                .client
                .expire(&redis_key, ttl.max(Duration::from_millis(1)))
                .await
            {
                tracing::warn!(error = %err, "redis conn limiter ttl refresh failed");
            }
        })
    }
}

/// 业务作用：限制动态事实的集合与键标识，防止路径、分隔符或控制字符改变存储范围。
fn validate_component(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || value == "."
        || value == ".."
        || Path::new(value).components().count() != 1
    {
        anyhow::bail!("invalid dynamic store {name} `{value}`");
    }
    Ok(())
}

/// 业务作用：校验业务 key 本身；它不再受文件路径组件规则限制，因为 file 后端会对不安全字符编码。
fn validate_dynamic_key(value: &str) -> Result<()> {
    if value.is_empty() || value.contains('\0') || value.len() > MAX_DYNAMIC_KEY_BYTES {
        anyhow::bail!(
            "invalid dynamic store key (must be 1..={MAX_DYNAMIC_KEY_BYTES} bytes without NUL)"
        );
    }
    Ok(())
}

/// 业务作用：把任意合法业务键编码为安全存储标识，避免键内容被解释为路径结构。
fn encode_dynamic_key(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value.as_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// 业务作用：恢复存储标识中的业务键，非法编码不能进入动态事实目录。
fn decode_dynamic_key(value: &str) -> Result<String> {
    if !value.len().is_multiple_of(2) || value.len() > MAX_DYNAMIC_KEY_BYTES.saturating_mul(2) {
        anyhow::bail!("invalid encoded dynamic store key `{value}`");
    }
    let raw = value.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])
            .with_context(|| format!("invalid encoded dynamic store key `{value}`"))?;
        let low = decode_hex_nibble(pair[1])
            .with_context(|| format!("invalid encoded dynamic store key `{value}`"))?;
        decoded.push((high << 4) | low);
    }
    let decoded = String::from_utf8(decoded).context("encoded dynamic store key is not UTF-8")?;
    validate_dynamic_key(&decoded)?;
    Ok(decoded)
}

/// 业务作用：验证动态键编码中的十六进制字符，拒绝畸形键名。
fn decode_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => anyhow::bail!("invalid hexadecimal digit"),
    }
}

/// 业务作用：在目标文件同目录选择临时写入位置，使最终替换保持文件系统原子性。
fn temp_path_for(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("value");
    path.with_file_name(format!(".{file_name}.tmp.{}.{}", std::process::id(), nanos))
}

/// Redis Lua 熔断分桶滑动窗口；工作区统计与其它状态共用同 slot 容量索引。
///
/// 单 HASH key 存本资源的时间分桶计数(字段 `t:<bucket>` 总数 / `f:<bucket>` 失败数),一次 EVAL 内原子完成:
/// ① 把本次结果计入当前桶并续期 ② 汇总窗口内各桶得集群聚合 (total, failures) ③ 顺带删除过期桶。
/// 单 key 无 CROSSSLOT 问题;桶数受 `window/bucket` 约束有界。用服务端 `TIME` 取时刻,各节点时钟无关。
#[cfg(feature = "redis-runtime")]
const CIRCUIT_WINDOW_LUA: &str = include_str!("redis/circuit_window.lua");

/// Redis 熔断统计后端：共享有界分桶计数，由各节点独立决定保护状态。
#[cfg(feature = "redis-runtime")]
pub struct RedisCircuitStats {
    client: Arc<nasa::redis::RedisClient>,
}

#[cfg(feature = "redis-runtime")]
impl RedisCircuitStats {
    /// 业务作用：固定熔断统计使用的 Redis 连接与命名空间。
    ///
    /// 参数说明：
    /// - `client`：为受信共享后端。
    ///
    /// 返回：不创建远端状态的统计句柄。
    pub fn new(client: Arc<nasa::redis::RedisClient>) -> Self {
        Self {
            client,
        }
    }

    /// 业务作用：保留平台熔断统计的既有存储键。
    ///
    /// 参数说明：
    /// - `key`：为平台资源身份。
    ///
    /// 返回：兼容平台统计布局的键。
    fn redis_key(key: &str) -> String {
        format!("gw:circuit:{key}")
    }

    /// 业务作用：把窗口划为约十个聚合桶，小窗口至少使用一毫秒。
    ///
    /// 参数说明：
    /// - `window_ms`：为统计窗口毫秒数。
    ///
    /// 返回：不大于非零窗口的分桶粒度。
    fn bucket_ms(window_ms: u64) -> u64 {
        (window_ms / 10).max(100).min(window_ms.max(1))
    }
}

#[cfg(feature = "redis-runtime")]
impl CircuitStats for RedisCircuitStats {
    /// 业务作用：累计平台共享熔断统计。
    ///
    /// 参数说明：
    /// - `key`：为统计输入。
    /// - `success`：为统计输入。
    /// - `window`：为统计输入。
    ///
    /// 返回：聚合计数，保持平台统计依赖故障时不主动跳闸的语义。
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a> {
        self.record_scoped(key, success, window, None)
    }

    /// 业务作用：以原子事务预留工作区状态容量并累计共享熔断统计。
    ///
    /// 参数说明：
    /// - `key`：为统计输入
    /// - `success`：为统计输入
    /// - `window`：为统计输入
    /// - `budget`：固定归属与容量。
    ///
    /// 返回：聚合计数；工作区容量或依赖失败时触发本地保护，不跨域借用状态。
    fn record_scoped<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsRecordFuture<'a> {
        Box::pin(async move {
            let window_ms = window.as_millis() as u64;
            if window_ms == 0 {
                return CircuitWindowCount {
                    total: 0,
                    failures: 0,
                };
            }
            let (redis_key, index) = budget
                .map(|budget| {
                    let (key, index) =
                        budget.redis_keys(&self.client.config().namespace, "circuit", key);
                    (key, Some(index))
                })
                .unwrap_or_else(|| (Self::redis_key(key), None));
            let mut keys = vec![redis_key.as_str()];
            if let Some(index) = &index {
                keys.push(index.as_str());
            }
            let ok = if success {
                "1"
            } else {
                "0"
            };
            let window_ms_s = window_ms.to_string();
            let bucket_ms_s = Self::bucket_ms(window_ms).to_string();
            let capacity = budget
                .map(|budget| budget.remote_scope().1)
                .unwrap_or(0)
                .to_string();
            let unavailable = if budget.is_some() {
                CircuitWindowCount {
                    total: u64::MAX,
                    failures: u64::MAX,
                }
            } else {
                CircuitWindowCount {
                    total: 0,
                    failures: 0,
                }
            };
            match self
                .client
                .eval::<Vec<i64>>(
                    CIRCUIT_WINDOW_LUA,
                    &keys,
                    &[
                        ok,
                        window_ms_s.as_str(),
                        bucket_ms_s.as_str(),
                        capacity.as_str(),
                    ],
                )
                .await
            {
                Ok(values) if values.len() >= 2 && values[0] < 0 => unavailable,
                Ok(values) if values.len() >= 2 => CircuitWindowCount {
                    total: values[0].max(0) as u64,
                    failures: values[1].max(0) as u64,
                },
                Ok(values) => {
                    tracing::warn!(
                        ?values,
                        "redis circuit stats returned unexpected window result"
                    );
                    unavailable
                }
                Err(err) => {
                    tracing::warn!(error = %err, "redis circuit stats record failed");
                    unavailable
                }
            }
        })
    }

    /// 业务作用：清除平台熔断统计。
    ///
    /// 参数说明：
    /// - `key`：为平台资源身份。
    ///
    /// 返回：完成远端删除尝试。
    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a> {
        self.reset_scoped(key, None)
    }

    /// 业务作用：恢复成功后原子删除同域窗口与容量索引，避免与并发记账交错释放错误名额。
    ///
    /// 参数说明：
    /// - `key`：为资源身份
    /// - `budget`：为原工作区归属。
    ///
    /// 返回：完成删除尝试，失败时保留 TTL 有界的原统计。
    fn reset_scoped<'a>(
        &'a self,
        key: &'a str,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> CircuitStatsResetFuture<'a> {
        Box::pin(async move {
            if let Some(budget) = budget {
                let (key, index) =
                    budget.redis_keys(&self.client.config().namespace, "circuit", key);
                if let Err(error) = self
                    .client
                    .eval::<i64>(
                        "redis.call('DEL', KEYS[1]); return redis.call('ZREM', KEYS[2], KEYS[1])",
                        &[key.as_str(), index.as_str()],
                        &[],
                    )
                    .await
                {
                    tracing::warn!(%error, "redis scoped circuit stats reset failed");
                }
                return;
            }
            let redis_key = Self::redis_key(key);
            if let Err(err) = self.client.del(&[redis_key.as_str()]).await {
                tracing::warn!(error = %err, "redis circuit stats reset failed");
            }
        })
    }
}

/// Redis `SET NX PX` 防重放:所有节点对同一 nonce key 原子占位,首个成功、后续判重放。
#[cfg(feature = "redis-runtime")]
const REPLAY_SET_NX_PX_LUA: &str = include_str!("redis/replay.lua");

/// Redis 防重放守卫:跨节点 `SET key 1 NX PX <ttl>`,占位成功=fresh,已存在=重放。
#[cfg(feature = "redis-runtime")]
pub struct RedisReplayGuard {
    client: Arc<nasa::redis::RedisClient>,
    fail_mode: RateLimitFailMode,
    strict_authority: [u8; 32],
}

#[cfg(feature = "redis-runtime")]
impl RedisReplayGuard {
    /// 业务作用：创建 Redis 防重放后端。
    pub fn new(client: Arc<nasa::redis::RedisClient>, fail_mode: RateLimitFailMode) -> Self {
        let mut hash = Sha256::new();
        for part in [
            "digest-replay",
            &client.config().url,
            &client.config().namespace,
            &client.config().qualifier,
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        Self {
            client,
            fail_mode,
            strict_authority: hash.finalize().into(),
        }
    }

    /// 业务作用：为受保护的并发或防重放维度编码共享键，保持命名空间隔离。
    fn redis_key(key: &str) -> String {
        format!("gw:replay:{key}")
    }

    /// 业务作用：Redis 异常时的判定:fail-open 视为 fresh 放行(签名仍已验,只放开窄重放窗口),fail-closed 视为重放拒绝。
    fn fail_fresh(&self) -> bool {
        matches!(self.fail_mode, RateLimitFailMode::Open)
    }
}

#[cfg(feature = "redis-runtime")]
impl ReplayGuard for RedisReplayGuard {
    /// 业务作用：让相同共享后端声明的节点识别同一挑战权威。
    /// 参数说明: 无。
    /// 返回：由连接声明及命名空间生成的摘要，不暴露连接凭据。
    fn strict_authority(&self) -> Option<[u8; 32]> {
        Some(self.strict_authority)
    }

    /// 业务作用：在有界共享账本内消费凭证，未知 ACK 和依赖错误始终拒绝。
    /// 参数说明：
    /// - `authority`：挑战绑定的共享后端。
    /// - `expires_at`：nonce 的绝对 Unix 秒截止时间，共享后端以自身时钟复验。
    /// - `key`：已验签的凭证摘要。
    /// - `ttl`：证据保留期。
    /// - `budget`：工作区容量；平台使用独立的共享硬上限。
    ///
    /// 返回：只有 Lua 原子占位成功为 true，不能回退到本地或 fail-open。
    fn check_and_set_strict<'a>(
        &'a self,
        authority: [u8; 32],
        expires_at: u64,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        Box::pin(async move {
            // 后端更换意味着防重放证据来源改变，旧挑战不能向新空账本取得授权。
            if authority != self.strict_authority
                || key.len() > 128
                || ttl.is_zero()
                || ttl > Duration::from_secs(310)
            {
                return false;
            }
            let (nonce, index, limit) = if let Some(budget) = budget {
                let (nonce, index) =
                    budget.redis_keys(&self.client.config().namespace, "digest", key);
                (nonce, index, budget.remote_scope().1)
            } else {
                let scope = format!("{:x}", Sha256::digest(authority));
                let prefix = format!("gw:digest:{{{scope}}}:{}", self.client.config().namespace);
                (
                    format!("{prefix}:{key}"),
                    format!("{prefix}:states"),
                    MAX_LOCAL_REPLAY_ENTRIES,
                )
            };
            let Some(expires_ms) = expires_at
                .checked_mul(1000)
                .filter(|value| *value < (1_u64 << 53))
            else {
                return false;
            };
            let expires = expires_ms.to_string();
            let ttl = ttl.as_millis().to_string();
            let limit = limit.to_string();
            matches!(
                self.client
                    .eval::<i64>(
                        include_str!("redis/replay_strict.lua"),
                        &[&nonce, &index],
                        &[&ttl, &limit, &expires]
                    )
                    .await,
                Ok(1)
            )
        })
    }

    /// 业务作用：在工作区共享容量与 nonce 消费之间执行同 slot 原子判定，不挤占其它域账本。
    ///
    /// 参数说明：
    /// - `key`：为已隔离凭证摘要
    /// - `ttl`：为有效窗
    /// - `budget`：为冻结工作区容量。
    ///
    /// 返回：首次占位成功为 true；重复、容量不足或共享账本不可用均拒绝工作区请求。
    fn check_and_set_scoped<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
        budget: Option<&'a crate::control::ownership::state::Budget>,
    ) -> ReplayGuardFuture<'a> {
        let Some(budget) = budget else {
            return self.check_and_set(key, ttl);
        };
        Box::pin(async move {
            let (_, _, _, owner_key) = redis_scoped_rate_limit_keys(
                "replay",
                key,
                Some(budget),
                &self.client.config().namespace,
            );
            let digest = format!("{:x}", Sha256::digest(key.as_bytes()));
            let nonce_key = format!("{}:nonce:{digest}", owner_key.trim_end_matches(":states"));
            let ttl_ms = ttl.as_millis().clamp(1, i64::MAX as u128).to_string();
            let limit = budget.remote_scope().1.to_string();
            const SCRIPT: &str = include_str!("redis/replay_scoped.lua");
            matches!(
                self.client
                    .eval::<i64>(SCRIPT, &[&nonce_key, &owner_key], &[&ttl_ms, &limit])
                    .await,
                Ok(1)
            )
        })
    }

    /// 业务作用：原子判断并登记防重放身份，使同一有效期内的重复 nonce 被拒绝。
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a> {
        Box::pin(async move {
            let ttl_ms = (ttl.as_millis() as u64).max(1);
            let redis_key = Self::redis_key(key);
            let ttl_s = ttl_ms.to_string();
            match self
                .client
                .eval::<i64>(
                    REPLAY_SET_NX_PX_LUA,
                    &[redis_key.as_str()],
                    &[ttl_s.as_str()],
                )
                .await
            {
                Ok(1) => true,  // 占位成功 → fresh
                Ok(_) => false, // 已存在 → 重放
                Err(err) => {
                    tracing::warn!(error = %err, "redis replay guard failed");
                    self.fail_fresh()
                }
            }
        })
    }
}
