//! 运行态动态数据与限流接口。
//!
//! V2-B 先落接口与 file/local 后端;V3 再接 Redis/Nacos,数据面调用契约不变。

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::model::RuntimeStateCfg;
use crate::config::resolve_relative;

/// 动态集合存储:黑名单、临时禁用、动态规则等低频运行态事实源。
pub trait DynamicStore: Send + Sync {
    /// 读取 collection 中一个 key；不存在返回 `None`。
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>>;

    /// 原子创建或覆盖 collection 中一个 key。
    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>>;

    /// 删除一个 key；不存在时也视为成功。
    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>>;

    /// 列出 collection 当前全部 key；只供低频控制面刷新使用。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>>;

    /// 原子写入一个有容量上限的 collection。已存在 key 始终允许覆盖；新 key 只有在当前
    /// field 数小于 `max_entries` 时写入。门户等 admission 场景不得用 get/list/put 拼事务。
    fn put_if_capacity<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
        max_entries: usize,
    ) -> StoreFuture<'a, Result<StoreCapacityOutcome>>;

    /// 订阅 collection 变更；不支持事件流的后端返回 `None` 并由调用方轮询。
    fn watch<'a>(
        &'a self,
        collection: &'a str,
    ) -> StoreFuture<'a, Result<Option<DynamicStoreWatcher>>> {
        let _ = collection;
        Box::pin(async { Ok(None) })
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
    /// 异步接收下一条通知；后端断开且无法恢复时返回 `None`。
    pub async fn recv(&mut self) -> Option<DynamicStoreChange> {
        self.rx.recv().await
    }
}

enum DynamicStoreWatchGuard {
    #[cfg(feature = "redis-runtime")]
    Redis {
        _subscription: nasa::redis::StreamSubscription,
    },
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
    /// 构造以指定目录为根的持久化动态集合后端。
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            write_lock: Mutex::new(()),
        }
    }

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
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let path = self.path_for(collection, key)?;
            crate::bounded_io::read_optional_file(
                &path,
                MAX_DYNAMIC_VALUE_BYTES,
                "dynamic store value",
            )
        })
    }

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

    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        Box::pin(async move {
            let _guard = self.write_lock.lock();
            self.list_keys_sync(collection)
        })
    }

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
const DYNAMIC_STORE_GET_BOUNDED_LUA: &str = r#"
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then return false end
if redis.call('HSTRLEN', KEYS[1], ARGV[1]) > tonumber(ARGV[2]) then
  redis.call('HDEL', KEYS[1], ARGV[1])
  return false
end
return redis.call('HGET', KEYS[1], ARGV[1])
"#;

/// 分页枚举 field，并在第 `MAX_DYNAMIC_KEYS + 1` 个 key 出现时于 Redis 内停止。
#[cfg(feature = "redis-runtime")]
const DYNAMIC_STORE_LIST_BOUNDED_LUA: &str = r#"
local cursor = '0'
local out = {}
local max = tonumber(ARGV[1])
repeat
  local page = redis.call('HSCAN', KEYS[1], cursor, 'COUNT', 1000)
  cursor = page[1]
  local entries = page[2]
  for i = 1, #entries, 2 do
    if #out >= max then return redis.error_reply('dynamic store collection key limit exceeded') end
    out[#out + 1] = entries[i]
  end
until cursor == '0'
return out
"#;

#[cfg(feature = "redis-runtime")]
const DYNAMIC_STORE_PUT_IF_CAPACITY_LUA: &str = r#"
local exists = redis.call('HEXISTS', KEYS[1], ARGV[1])
if exists == 0 and redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[3]) then
  return 0
end
local value = string.gsub(ARGV[2], '..', function(pair)
  return string.char(tonumber(pair, 16))
end)
redis.call('HSET', KEYS[1], ARGV[1], value)
return 1
"#;

/// Encode binary DynamicStore values for the current nasa Redis EVAL facade, whose ARGV
/// contract is `&str`. This is a low-frequency control-plane path: one precisely-sized String
/// is preferable to either weakening DynamicStore to UTF-8-only or adding another non-atomic
/// write. Lua decodes the value before HSET, so callers still observe exact original bytes.
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
    /// 创建 Redis store。`prefix` 用于隔离 gateway 运行态 key,默认可传 `gw:dynamic`。
    pub fn new(client: Arc<nasa::redis::RedisClient>, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
        }
    }

    fn collection_key(&self, collection: &str) -> Result<String> {
        validate_component(collection, "collection")?;
        Ok(format!("{}:{}", self.prefix, collection))
    }

    fn events_key(&self, collection: &str) -> Result<String> {
        validate_component(collection, "collection")?;
        Ok(format!("{}:{}:events", self.prefix, collection))
    }

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
                _guard: DynamicStoreWatchGuard::Redis { _subscription: sub },
            }))
        })
    }
}

/// 可热替换的动态存储后端。黑名单刷新等后台任务持有它,reload 成功后原子换入新后端。
pub struct SwappableDynamicStore {
    inner: RwLock<Arc<dyn DynamicStore>>,
    generation: AtomicU64,
}

impl SwappableDynamicStore {
    /// 以一个已经初始化的后端构造热替换容器。
    pub fn new(inner: Arc<dyn DynamicStore>) -> Self {
        Self {
            inner: RwLock::new(inner),
            generation: AtomicU64::new(0),
        }
    }

    /// 克隆当前后端的共享指针；锁只覆盖指针读取。
    pub fn current(&self) -> Arc<dyn DynamicStore> {
        self.inner.read().clone()
    }

    /// 原子语义替换后端并递增 generation。
    pub fn replace(&self, next: Arc<dyn DynamicStore>) {
        *self.inner.write() = next;
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// 返回最近一次成功替换对应的单调 generation。
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }
}

impl DynamicStore for SwappableDynamicStore {
    fn get<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Result<Option<Vec<u8>>>> {
        let inner = self.current();
        Box::pin(async move { inner.get(collection, key).await })
    }

    fn put<'a>(
        &'a self,
        collection: &'a str,
        key: &'a str,
        value: &'a [u8],
    ) -> StoreFuture<'a, Result<()>> {
        let inner = self.current();
        Box::pin(async move { inner.put(collection, key, value).await })
    }

    fn delete<'a>(&'a self, collection: &'a str, key: &'a str) -> StoreFuture<'a, Result<()>> {
        let inner = self.current();
        Box::pin(async move { inner.delete(collection, key).await })
    }

    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        let inner = self.current();
        Box::pin(async move { inner.list_keys(collection).await })
    }

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

    fn watch<'a>(
        &'a self,
        collection: &'a str,
    ) -> StoreFuture<'a, Result<Option<DynamicStoreWatcher>>> {
        let inner = self.current();
        Box::pin(async move { inner.watch(collection).await })
    }
}

/// 高频计数限流接口。Redis 后端可精确跨节点;local 后端用于单机/降级。
pub trait RateLimiter: Send + Sync {
    /// 判断一次请求是否允许通过。
    ///
    /// # 参数
    /// - `request`: 已编译规则、短 key 与活跃维度资源边界。
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a>;
}

/// 一次令牌桶判定所需的借用参数与维度资源边界。
#[derive(Clone, Copy)]
pub struct RateLimitRequest<'a> {
    /// 配置生成的规则作用域，隔离不同 limiter。
    pub scope: &'a str,
    /// 当前请求解析出的限流维度键。
    pub key: &'a str,
    /// 本次原子扣减的令牌数。普通 QPS 规则固定为 1；V6 LLM 配额使用有界 token 成本。
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

#[derive(Debug, Clone)]
/// 限流后端对一次请求的判定结果。数据面只根据它决定继续转发还是 429 短路。
pub struct RateLimitDecision {
    /// 本次请求是否消耗到令牌并允许进入后续管线。
    pub allowed: bool,
    /// 当前桶内剩余令牌数,用于 `X-RateLimit-Remaining` 与观测。
    pub remaining: u64,
}

/// 单进程本地令牌桶。它满足单机/Redis 故障降级可用性,但多节点时不是集群共享限流。
#[derive(Default)]
pub struct LocalRateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter for LocalRateLimiter {
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        Box::pin(async move {
            self.allow_sync(
                request.scope,
                request.key,
                request.cost,
                request.limit,
                request.window,
                request.burst,
                request.max_active_keys,
                request.active_keys_fail_open,
            )
        })
    }
}

impl LocalRateLimiter {
    #[allow(clippy::too_many_arguments)]
    fn allow_sync(
        &self,
        scope: &str,
        key: &str,
        cost: u64,
        limit: u64,
        window: Duration,
        burst: u64,
        max_active_keys: usize,
        active_keys_fail_open: bool,
    ) -> RateLimitDecision {
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
        let idle_ttl = token_bucket_idle_ttl(limit, window, capacity);
        if !buckets.contains_key(key) {
            // 只在新维度到来时清理/计数；常态已有维度仍是单次 HashMap 查找。
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
        }
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            scope: scope.to_string(),
            tokens: capacity as f64,
            last_refill: now,
            idle_ttl,
        });
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity as f64);
        }
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
    /// 用启动期构造好的后端创建热替换句柄。
    pub fn new(inner: Arc<dyn RateLimiter>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 替换当前限流后端。已在途请求继续使用它克隆出的旧 Arc,新请求读到新后端。
    pub fn replace(&self, next: Arc<dyn RateLimiter>) {
        *self.inner.write() = next;
    }
}

impl RateLimiter for SwappableRateLimiter {
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.allow(request).await })
    }
}

struct Bucket {
    scope: String,
    tokens: f64,
    last_refill: Instant,
    idle_ttl: Duration,
}

fn token_bucket_idle_ttl(limit: u64, window: Duration, capacity: u64) -> Duration {
    let millis = window
        .as_millis()
        .saturating_mul(capacity as u128)
        .div_ceil(limit.max(1) as u128)
        .saturating_add(1_000)
        .min(u64::MAX as u128) as u64;
    Duration::from_millis(millis)
}

fn active_key_overflow_decision(fail_open: bool) -> RateLimitDecision {
    RateLimitDecision {
        allowed: fail_open,
        remaining: if fail_open { u64::MAX } else { 0 },
    }
}

/// 可释放的并发连接限制接口。Redis 后端用于跨节点 `limit_conn`,local 后端用于单机/降级。
pub trait ConnLimiter: Send + Sync {
    /// 尝试占用一个并发槽。
    ///
    /// # 参数
    /// - `key`: 已 hash 的规则维度 key,不得包含原始 token/header 明文。
    /// - `limit`: 同一 key 最大并发数;0 表示规则禁用。
    /// - `ttl`: Redis 崩溃泄漏兜底 TTL;local 后端忽略。
    fn acquire<'a>(&'a self, key: &'a str, limit: u64, ttl: Duration) -> ConnLimitFuture<'a>;

    /// 释放一个并发槽。必须幂等处理异常状态。
    fn release<'a>(&'a self, key: &'a str) -> ConnLimitReleaseFuture<'a>;

    /// 刷新并发槽 TTL。local 后端可为空操作。
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

    fn refresh<'a>(&'a self, _key: &'a str, _ttl: Duration) -> ConnLimitReleaseFuture<'a> {
        Box::pin(async {})
    }
}

/// 可热替换的并发限制器句柄。reload 成功后新请求使用新后端,旧 guard 释放旧后端。
pub struct SwappableConnLimiter {
    inner: RwLock<Arc<dyn ConnLimiter>>,
}

impl SwappableConnLimiter {
    /// 创建热替换句柄。
    pub fn new(inner: Arc<dyn ConnLimiter>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 替换当前后端。
    pub fn replace(&self, next: Arc<dyn ConnLimiter>) {
        *self.inner.write() = next;
    }
}

impl ConnLimiter for SwappableConnLimiter {
    fn acquire<'a>(&'a self, key: &'a str, limit: u64, ttl: Duration) -> ConnLimitFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.acquire(key, limit, ttl).await })
    }

    fn release<'a>(&'a self, key: &'a str) -> ConnLimitReleaseFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.release(key).await })
    }

    fn refresh<'a>(&'a self, key: &'a str, ttl: Duration) -> ConnLimitReleaseFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.refresh(key, ttl).await })
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
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "open" | "fail-open" | "fail_open" => Ok(Self::Open),
            "closed" | "close" | "fail-closed" | "fail_closed" => Ok(Self::Closed),
            other => anyhow::bail!("unsupported rate_limiter.fail_mode `{other}`"),
        }
    }
}

/// 熔断滑动窗口内的聚合计数(§10.6 R3)。数据面据它判断是否跳闸。
#[derive(Debug, Clone, Copy)]
pub struct CircuitWindowCount {
    /// 窗口内总请求数。
    pub total: u64,
    /// 窗口内失败(5xx/网关错误)数。
    pub failures: u64,
}

/// 熔断统计后端(§10.6 line1142)。local 后端每节点各自统计(快);Redis 后端跨节点共享(集群错误率更准)。
///
/// **只共享统计,不共享状态机**:开/半开/闭由数据面本地维护,本 trait 只负责把成功/失败计入滑动窗口并回吐窗口聚合值,
/// 各节点据【集群聚合值】各自决定是否跳闸——对齐 doc「共享统计」定位,acquire 热路径不打 Redis。
pub trait CircuitStats: Send + Sync {
    /// 记录一次请求结果到滑动窗口,返回窗口内聚合计数。
    ///
    /// # 参数
    /// - `key`: 熔断资源 key(已由调用方按 route+规则生成)。
    /// - `success`: 本次是否成功(非 5xx)。
    /// - `window`: 滑动窗口时长。
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a>;

    /// 清空某 key 的窗口计数。半开探测成功、电路恢复 Closed 时调用,避免陈旧失败样本导致恢复后立即再次跳闸。
    ///
    /// # 参数
    /// - `key`: 熔断资源 key。
    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a>;
}

/// 熔断统计 record future 别名。
pub type CircuitStatsRecordFuture<'a> =
    Pin<Box<dyn Future<Output = CircuitWindowCount> + Send + 'a>>;

/// 熔断统计 reset future 别名。
pub type CircuitStatsResetFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// 单进程本地熔断统计:每 key 一份内存滑动窗口(时间戳 + 成败),等价 R3 前的本地窗口逻辑。
#[derive(Default)]
pub struct LocalCircuitStats {
    windows: Mutex<HashMap<String, VecDeque<(Instant, bool)>>>,
}

impl LocalCircuitStats {
    fn record_sync(&self, key: &str, success: bool, window: Duration) -> CircuitWindowCount {
        let now = Instant::now();
        let mut windows = self.windows.lock();
        let events = windows.entry(key.to_string()).or_default();
        // 剔除超出窗口的旧样本(与 R3 前 prune_circuit_events 同语义)。
        while events
            .front()
            .map(|(at, _)| now.saturating_duration_since(*at) > window)
            .unwrap_or(false)
        {
            events.pop_front();
        }
        events.push_back((now, success));
        let total = events.len() as u64;
        let failures = events.iter().filter(|(_, ok)| !*ok).count() as u64;
        CircuitWindowCount { total, failures }
    }
}

impl CircuitStats for LocalCircuitStats {
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a> {
        Box::pin(async move { self.record_sync(key, success, window) })
    }

    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a> {
        Box::pin(async move {
            self.windows.lock().remove(key);
        })
    }
}

/// 可热替换熔断统计后端句柄。reload 成功后原子换入新的 local/Redis 后端。
pub struct SwappableCircuitStats {
    inner: RwLock<Arc<dyn CircuitStats>>,
}

impl SwappableCircuitStats {
    /// 用启动期构造好的后端创建热替换句柄。
    pub fn new(inner: Arc<dyn CircuitStats>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 替换当前熔断统计后端。
    pub fn replace(&self, next: Arc<dyn CircuitStats>) {
        *self.inner.write() = next;
    }
}

impl CircuitStats for SwappableCircuitStats {
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.record(key, success, window).await })
    }

    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.reset(key).await })
    }
}

/// 一次性令牌(nonce)防重放守卫(§20 HMAC 防重放)。local 每节点各自去重;Redis `SET NX PX` 跨节点去重。
///
/// 只保证**新鲜性**(此 token 未用过),不做签名验证——签名有效性由上层 HMAC 验签保证。
pub trait ReplayGuard: Send + Sync {
    /// 记录一个一次性 token,返回是否【首次出现】。
    ///
    /// # 参数
    /// - `key`: 已由调用方按 route + nonce 生成的去重 key。
    /// - `ttl`: token 有效期(通常 = 允许的时间戳偏差窗口),到期自动清理。
    ///
    /// # 返回
    /// `true` = 首次出现(fresh,放行);`false` = 已用过(重放,拒绝)。
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a>;
}

/// 防重放守卫 future 别名。
pub type ReplayGuardFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// 单进程本地防重放:内存 `key -> 过期时刻` 表。单机/降级可用,不跨节点去重。
#[derive(Default)]
pub struct LocalReplayGuard {
    seen: Mutex<HashMap<String, Instant>>,
}

impl LocalReplayGuard {
    fn check_and_set_sync(&self, key: &str, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut seen = self.seen.lock();
        // 表偏大时顺带清理过期项,避免无界增长(nonce TTL 短,过期即可忘)。
        if seen.len() > 4096 {
            seen.retain(|_, expiry| *expiry > now);
        }
        match seen.get(key) {
            Some(expiry) if *expiry > now => false, // 未过期且已存在 → 重放
            _ => {
                seen.insert(key.to_string(), now + ttl);
                true // 首次(或旧记录已过期)→ fresh
            }
        }
    }
}

impl ReplayGuard for LocalReplayGuard {
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a> {
        Box::pin(async move { self.check_and_set_sync(key, ttl) })
    }
}

/// 可热替换防重放守卫句柄。reload 成功后原子换入新的 local/Redis 后端。
pub struct SwappableReplayGuard {
    inner: RwLock<Arc<dyn ReplayGuard>>,
}

impl SwappableReplayGuard {
    /// 用启动期构造好的后端创建热替换句柄。
    pub fn new(inner: Arc<dyn ReplayGuard>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// 替换当前防重放后端。
    pub fn replace(&self, next: Arc<dyn ReplayGuard>) {
        *self.inner.write() = next;
    }
}

impl ReplayGuard for SwappableReplayGuard {
    fn check_and_set<'a>(&'a self, key: &'a str, ttl: Duration) -> ReplayGuardFuture<'a> {
        let inner = self.inner.read().clone();
        Box::pin(async move { inner.check_and_set(key, ttl).await })
    }
}

/// 按 `gateway.yml` 的运行态配置构造限流后端。
pub async fn build_rate_limiter(cfg: &RuntimeStateCfg) -> Result<Arc<dyn RateLimiter>> {
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

/// 按 `gateway.yml` 的运行态配置构造并发连接限制后端。
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

/// 运行态限流后端的配置签名。reload 用它判断是否需要重建后端连接。
pub fn rate_limiter_config_signature(cfg: &RuntimeStateCfg) -> String {
    let redis = &cfg.rate_limiter.redis;
    format!(
        "{}|{}|{}|{}|{}",
        cfg.rate_limiter.backend.trim(),
        cfg.rate_limiter.fail_mode.trim(),
        redis.url.trim(),
        redis.namespace.trim(),
        redis.profile.trim()
    )
}

/// 按 `gateway.yml` 的运行态配置构造熔断统计后端(§10.6 R3)。
///
/// `circuit_breaker.shared=false`(默认)→ 本地各自统计;`true` → 复用 `rate_limiter.redis` 连接跨节点共享。
pub async fn build_circuit_stats(cfg: &RuntimeStateCfg) -> Result<Arc<dyn CircuitStats>> {
    if cfg.circuit_breaker.shared {
        build_redis_circuit_stats(cfg).await
    } else {
        Ok(Arc::new(LocalCircuitStats::default()))
    }
}

/// 熔断统计后端的配置签名。reload 用它判断是否需要重建后端连接(独立于限流签名,避免互相牵连重建)。
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

/// 按 `gateway.yml` 的运行态配置构造 HMAC 防重放守卫后端(§20)。
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

/// 防重放守卫后端的配置签名。reload 用它判断是否需要重建后端连接。
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

/// 按 `gateway.yml` 的运行态配置构造动态事实源后端。
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
        other => anyhow::bail!("unsupported runtime_state.store.backend `{other}`"),
    }
}

/// 动态事实源后端的配置签名。reload 用它判断是否需要重建后端连接。
pub fn dynamic_store_config_signature(cfg: &RuntimeStateCfg) -> String {
    let redis = &cfg.store.redis;
    format!(
        "{}|{}|{}|{}|{}|{}",
        cfg.store.backend.trim(),
        cfg.store.file.root.trim(),
        redis.url.trim(),
        redis.namespace.trim(),
        redis.profile.trim(),
        redis.prefix.trim()
    )
}

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

#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_dynamic_store(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn DynamicStore>> {
    anyhow::bail!(
        "runtime_state.store.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

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
    Ok(Arc::new(RedisRateLimiter::new(client, fail_mode)))
}

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

#[cfg(feature = "redis-runtime")]
fn parse_redis_profile(raw: &str, label: &str) -> Result<nasa::redis::CompatibilityProfile> {
    match raw.trim() {
        "RustV2" | "rustv2" | "rust-v2" => Ok(nasa::redis::CompatibilityProfile::RustV2),
        "LegacyV1" | "legacyv1" | "legacy-v1" => Ok(nasa::redis::CompatibilityProfile::LegacyV1),
        other => anyhow::bail!("unsupported {label} `{other}`"),
    }
}

#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_rate_limiter(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn RateLimiter>> {
    anyhow::bail!(
        "runtime_state.rate_limiter.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_conn_limiter(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn ConnLimiter>> {
    anyhow::bail!(
        "runtime_state.rate_limiter.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_circuit_stats(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn CircuitStats>> {
    anyhow::bail!(
        "runtime_state.circuit_breaker.shared=true requires building gateway with feature `redis-runtime`"
    )
}

#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_replay_guard(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn ReplayGuard>> {
    anyhow::bail!(
        "runtime_state.replay_guard.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

#[cfg(feature = "redis-runtime")]
const TOKEN_BUCKET_LUA: &str = r#"
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local max_active = tonumber(ARGV[3])
local overflow_allowed = tonumber(ARGV[4])
local member = ARGV[5]
local cost = tonumber(ARGV[6])
if cap == nil or refill == nil or cost == nil or cap <= 0 or refill <= 0 or cost <= 0 then
  return {1, 9223372036854775807}
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = math.ceil((cap / refill) * 1000) + 1000
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - ttl)
if redis.call('ZSCORE', KEYS[2], member) == false then
  if max_active == nil or max_active <= 0 or redis.call('ZCARD', KEYS[2]) >= max_active then
    if overflow_allowed == 1 then return {1, 9223372036854775807} end
    return {0, 0}
  end
end
redis.call('ZADD', KEYS[2], now, member)
redis.call('PEXPIRE', KEYS[2], ttl + 1000)
local st = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(st[1])
local ts = tonumber(st[2])
if tokens == nil then tokens = cap end
if ts == nil then ts = now end
if now > ts then
  tokens = math.min(cap, tokens + ((now - ts) / 1000.0) * refill)
end
local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return {allowed, math.floor(tokens)}
"#;

#[cfg(feature = "redis-runtime")]
const CONN_ACQUIRE_LUA: &str = r#"
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
if limit == nil or limit <= 0 then
  return {1, 0}
end
if ttl == nil or ttl <= 0 then ttl = 60000 end
local current = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ttl)
if current > limit then
  current = redis.call('DECR', KEYS[1])
  if current <= 0 then redis.call('DEL', KEYS[1]) end
  return {0, current}
end
return {1, current}
"#;

#[cfg(feature = "redis-runtime")]
const CONN_RELEASE_LUA: &str = r#"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if current <= 1 then
  redis.call('DEL', KEYS[1])
  return 0
end
current = redis.call('DECR', KEYS[1])
return current
"#;

/// Redis Lua 令牌桶。所有节点对同一 key 执行原子 EVAL,实现集群共享 QPS。
#[cfg(feature = "redis-runtime")]
pub struct RedisRateLimiter {
    client: Arc<nasa::redis::RedisClient>,
    fail_mode: RateLimitFailMode,
}

#[cfg(feature = "redis-runtime")]
impl RedisRateLimiter {
    /// 创建 Redis 限流后端。调用方负责通过 `nasa::redis` 完成连接和协议 marker 校验。
    pub fn new(client: Arc<nasa::redis::RedisClient>, fail_mode: RateLimitFailMode) -> Self {
        Self { client, fail_mode }
    }
}

#[cfg(feature = "redis-runtime")]
impl RateLimiter for RedisRateLimiter {
    fn allow<'a>(&'a self, request: RateLimitRequest<'a>) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let RateLimitRequest {
                scope,
                key,
                cost,
                limit,
                window,
                burst,
                max_active_keys,
                active_keys_fail_open,
            } = request;
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
            let redis_key = format!("gw:ratelimit:{key}");
            let active_key = format!("gw:ratelimit:{scope}:active");
            let capacity = capacity.to_string();
            let refill = format!("{refill_per_sec:.12}");
            let max_active_keys = max_active_keys.min(i64::MAX as usize).to_string();
            let overflow_allowed = if active_keys_fail_open { "1" } else { "0" };
            let cost = cost.to_string();
            let result = self
                .client
                .eval::<Vec<i64>>(
                    TOKEN_BUCKET_LUA,
                    &[redis_key.as_str(), active_key.as_str()],
                    &[
                        capacity.as_str(),
                        refill.as_str(),
                        max_active_keys.as_str(),
                        overflow_allowed,
                        key,
                        cost.as_str(),
                    ],
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
}

#[cfg(feature = "redis-runtime")]
impl RedisRateLimiter {
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
    /// 创建 Redis 并发限制后端。
    pub fn new(client: Arc<nasa::redis::RedisClient>, fail_mode: RateLimitFailMode) -> Self {
        Self { client, fail_mode }
    }

    fn redis_key(key: &str) -> String {
        format!("gw:limitconn:{key}")
    }

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

/// 校验业务 key 本身；它不再受文件路径组件规则限制，因为 file 后端会对不安全字符编码。
fn validate_dynamic_key(value: &str) -> Result<()> {
    if value.is_empty() || value.contains('\0') || value.len() > MAX_DYNAMIC_KEY_BYTES {
        anyhow::bail!(
            "invalid dynamic store key (must be 1..={MAX_DYNAMIC_KEY_BYTES} bytes without NUL)"
        );
    }
    Ok(())
}

fn encode_dynamic_key(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value.as_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

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

fn decode_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => anyhow::bail!("invalid hexadecimal digit"),
    }
}

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

/// Redis Lua 熔断分桶滑动窗口(§10.6 R3)。
///
/// 单 HASH key 存本资源的时间分桶计数(字段 `t:<bucket>` 总数 / `f:<bucket>` 失败数),一次 EVAL 内原子完成:
/// ① 把本次结果计入当前桶并续期 ② 汇总窗口内各桶得集群聚合 (total, failures) ③ 顺带删除过期桶。
/// 单 key 无 CROSSSLOT 问题;桶数受 `window/bucket` 约束有界。用服务端 `TIME` 取时刻,各节点时钟无关。
#[cfg(feature = "redis-runtime")]
const CIRCUIT_WINDOW_LUA: &str = r#"
local key = KEYS[1]
local ok = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local bucket_ms = tonumber(ARGV[3])
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local cur = math.floor(now_ms / bucket_ms)
local min_bucket = cur - math.ceil(window_ms / bucket_ms)
redis.call('HINCRBY', key, 't:' .. cur, 1)
if ok == 0 then redis.call('HINCRBY', key, 'f:' .. cur, 1) end
redis.call('PEXPIRE', key, window_ms + bucket_ms * 2)
local total = 0
local fails = 0
local data = redis.call('HGETALL', key)
for i = 1, #data, 2 do
  local name = data[i]
  local val = tonumber(data[i + 1]) or 0
  local colon = string.find(name, ':')
  local b = tonumber(string.sub(name, colon + 1))
  if b == nil or b <= min_bucket then
    redis.call('HDEL', key, name)
  else
    local kind = string.sub(name, 1, colon - 1)
    if kind == 't' then
      total = total + val
    elseif kind == 'f' then
      fails = fails + val
    end
  end
end
return {total, fails}
"#;

/// Redis 熔断统计后端:各节点把成功/失败计入共享分桶窗口,读集群聚合值决定跳闸(§10.6 R3「共享统计」)。
#[cfg(feature = "redis-runtime")]
pub struct RedisCircuitStats {
    client: Arc<nasa::redis::RedisClient>,
}

#[cfg(feature = "redis-runtime")]
impl RedisCircuitStats {
    /// 创建 Redis 熔断统计后端。
    pub fn new(client: Arc<nasa::redis::RedisClient>) -> Self {
        Self { client }
    }

    fn redis_key(key: &str) -> String {
        format!("gw:circuit:{key}")
    }

    /// 分桶粒度:窗口十等分,夹在 [100ms, window] 内。约十个桶,兼顾精度与字段数。
    fn bucket_ms(window_ms: u64) -> u64 {
        (window_ms / 10).clamp(100, window_ms.max(1))
    }
}

#[cfg(feature = "redis-runtime")]
impl CircuitStats for RedisCircuitStats {
    fn record<'a>(
        &'a self,
        key: &'a str,
        success: bool,
        window: Duration,
    ) -> CircuitStatsRecordFuture<'a> {
        Box::pin(async move {
            let window_ms = window.as_millis() as u64;
            if window_ms == 0 {
                return CircuitWindowCount {
                    total: 0,
                    failures: 0,
                };
            }
            let redis_key = Self::redis_key(key);
            let ok = if success { "1" } else { "0" };
            let window_ms_s = window_ms.to_string();
            let bucket_ms_s = Self::bucket_ms(window_ms).to_string();
            match self
                .client
                .eval::<Vec<i64>>(
                    CIRCUIT_WINDOW_LUA,
                    &[redis_key.as_str()],
                    &[ok, window_ms_s.as_str(), bucket_ms_s.as_str()],
                )
                .await
            {
                Ok(values) if values.len() >= 2 => CircuitWindowCount {
                    total: values[0].max(0) as u64,
                    failures: values[1].max(0) as u64,
                },
                Ok(values) => {
                    tracing::warn!(
                        ?values,
                        "redis circuit stats returned unexpected window result"
                    );
                    // WHY:fail-open——统计后端异常绝不主动跳闸(否则 Redis 抖动=自造全网熔断);返回零计数即不跳闸。
                    CircuitWindowCount {
                        total: 0,
                        failures: 0,
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "redis circuit stats record failed");
                    CircuitWindowCount {
                        total: 0,
                        failures: 0,
                    }
                }
            }
        })
    }

    fn reset<'a>(&'a self, key: &'a str) -> CircuitStatsResetFuture<'a> {
        Box::pin(async move {
            let redis_key = Self::redis_key(key);
            if let Err(err) = self.client.del(&[redis_key.as_str()]).await {
                tracing::warn!(error = %err, "redis circuit stats reset failed");
            }
        })
    }
}

/// Redis `SET NX PX` 防重放:所有节点对同一 nonce key 原子占位,首个成功、后续判重放(§20)。
#[cfg(feature = "redis-runtime")]
const REPLAY_SET_NX_PX_LUA: &str = r#"
if redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[1]) then
  return 1
else
  return 0
end
"#;

/// Redis 防重放守卫:跨节点 `SET key 1 NX PX <ttl>`,占位成功=fresh,已存在=重放。
#[cfg(feature = "redis-runtime")]
pub struct RedisReplayGuard {
    client: Arc<nasa::redis::RedisClient>,
    fail_mode: RateLimitFailMode,
}

#[cfg(feature = "redis-runtime")]
impl RedisReplayGuard {
    /// 创建 Redis 防重放后端。
    pub fn new(client: Arc<nasa::redis::RedisClient>, fail_mode: RateLimitFailMode) -> Self {
        Self { client, fail_mode }
    }

    fn redis_key(key: &str) -> String {
        format!("gw:replay:{key}")
    }

    /// Redis 异常时的判定:fail-open 视为 fresh 放行(签名仍已验,只放开窄重放窗口),fail-closed 视为重放拒绝。
    fn fail_fresh(&self) -> bool {
        matches!(self.fail_mode, RateLimitFailMode::Open)
    }
}

#[cfg(feature = "redis-runtime")]
impl ReplayGuard for RedisReplayGuard {
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

#[path = "../../tests/unit/runtime_state.rs"]
#[cfg(test)]
mod tests;
