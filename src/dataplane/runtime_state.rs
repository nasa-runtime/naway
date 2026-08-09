//! 运行态动态数据与限流接口。低频事实支持 file、Redis 与 Nacos，令牌结算支持 local/Redis；
//! 所有远端 I/O 都在请求转发契约之外保持有界并显式失败。

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
    /// 业务作用：接收动态事实源下一条有界变更，并让 watcher guard 与接收端保持同寿命。
    ///
    /// 参数说明：无。
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
    /// 参数说明：无。
    ///
    /// 返回：无返回值；取消信号是幂等尽力发送，接收端已经退出时无需升级为进程错误。
    fn drop(&mut self) {
        #[allow(unreachable_patterns)]
        match self {
            #[cfg(feature = "nacos-sdk")]
            Self::Nacos { cancel } => {
                if let Some(cancel) = cancel.take() {
                    let _ = cancel.send(());
                }
            }
            #[cfg(feature = "redis-runtime")]
            Self::Redis { .. } => {}
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
    /// 参数说明：`deserializer` 提供单个 JSON object 的 token 流。
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
            /// 参数说明：`formatter` 接收期望结构说明。
            ///
            /// 返回：格式化写入成功或底层 formatter 错误。
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Nacos dynamic store entries object with unique keys")
            }

            /// 业务作用：逐项构建唯一键映射，在值覆盖发生前拒绝重复 JSON key。
            ///
            /// 参数说明：`map` 是 serde 提供的 entries object 游标。
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
    /// 参数说明：无。
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
    /// 参数说明：`cfg` 是 `runtime_state.store.nacos` 的完整连接与文档资源配置。
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
    /// 参数说明：`collection` 是 DynamicStore 集合名。
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
    /// 参数说明：`collection`/`key` 唯一定位业务事实。
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
    /// 参数说明：`collection`/`key` 定位事实，`value` 是受单值与聚合文档硬门约束的原始内容。
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
    /// 参数说明：`collection`/`key` 唯一定位待删除事实。
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
    /// 参数说明：`collection` 是已经过命名约束的集合名。
    ///
    /// 返回：集合缺失返回空集；坏文档、超限或远端失败返回错误，避免把损坏误判为空。
    fn list_keys<'a>(&'a self, collection: &'a str) -> StoreFuture<'a, Result<Vec<String>>> {
        let data_id = self.data_id(collection);
        let commands = self.commands.clone();
        Box::pin(async move {
            let data_id = data_id?;
            let (reply, response) = tokio::sync::oneshot::channel();
            commands
                .send(NacosStoreCommand::List { data_id, reply })
                .await
                .context("Nacos DynamicStore actor stopped")?;
            response
                .await
                .context("Nacos DynamicStore list reply dropped")?
        })
    }

    /// 业务作用：用单次 Nacos 文档 CAS 原子完成容量 admission 与写入，禁止 list/put 竞态超卖。
    ///
    /// 参数说明：`collection`/`key`/`value` 描述事实，`max_entries` 是集合硬容量。
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
    /// 参数说明：`collection` 是要持续观察的动态集合。
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
/// 参数说明：`cfg` 是连接配置，`commands` 是有界命令队列，`ready` 在连接结果确定后只发送一次。
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
            NacosStoreCommand::List { data_id, reply } => {
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
/// 参数说明：`client` 是 actor 内专用配置客户端；`data_id/group` 定位集合；`max_document_bytes` 是聚合硬门。
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
/// 参数说明：`key/value` 是已验证事实；`max_entries` 存在时禁止在满集合创建新 key。
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
/// 参数说明：`client/data_id/group` 定位集合，`max_document_bytes` 约束文档，`key` 是已验证业务键。
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
/// 参数说明：`client/data_id/group` 定位集合；`collection` 进入事件；`max_document_bytes` 限制每次推送解析。
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
    Ok(NacosWatchRegistration { rx, cancel })
}

#[cfg(feature = "nacos-sdk")]
/// 业务作用：严格解码 Nacos collection JSON，将外部文档转换成经过 key/value/数量复验的内存快照。
///
/// 参数说明：`content` 是 Nacos 原文；`max_document_bytes` 是 route-independent 文档硬上限。
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
/// 参数说明：`snapshot` 是 CAS 候选状态；`max_document_bytes` 是配置硬上限。
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
/// 参数说明：`collection` 是固定集合名，`previous/next` 是连续合法快照。
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
/// 参数说明：`prefix` 是 `runtime_state.store.nacos.data_id_prefix`。
///
/// 返回：1..=128 字节 `[A-Za-z0-9._-]` 返回成功，其它值拒绝候选配置。
fn validate_nacos_data_id_prefix(prefix: &str) -> Result<()> {
    anyhow::ensure!(
        !prefix.is_empty()
            && prefix.len() <= 128
            && prefix
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') }),
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

    /// 业务作用：为需要按最终成本结算的请求执行原子预留，并返回绑定本次后端实例的结算句柄。
    ///
    /// 参数说明：`request` 是预留额度与桶边界；`reservation_id` 是全局唯一幂等标识；`max_actual` 是异常 provider 可形成的最大有界负债。
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

/// 带最终成本结算句柄的限流预留 future。
pub type RateLimitReserveFuture<'a> =
    Pin<Box<dyn Future<Output = RateLimitReserveDecision> + Send + 'a>>;

#[derive(Debug, Clone)]
/// 限流后端对一次请求的判定结果。数据面只根据它决定继续转发还是 429 短路。
pub struct RateLimitDecision {
    /// 本次请求是否消耗到令牌并允许进入后续管线。
    pub allowed: bool,
    /// 当前桶内剩余令牌数,用于 `X-RateLimit-Remaining` 与观测。
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
    /// 参数说明：`actual` 是经过 provider 协议校验的最终 token 总数。
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
    /// 参数说明：`actual` 是 provider 最终 token 总数。
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
    /// 参数说明：无。
    ///
    /// 返回：退款成功或识别重复退款时成功；后端失败时返回错误并保留预留，避免错误放大可用额度。
    pub async fn refund(self) -> Result<()> {
        self.settle(0).await
    }
}

#[derive(Clone)]
struct RateLimitSettlementSpec {
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
    /// 参数说明：`settlement` 固化 reservation id、原桶参数、预留值和最终成本。
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
    settlements: Arc<Mutex<HashMap<String, Instant>>>,
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

    /// 业务作用：在本地桶中原子预留 provider 最大成本，并生成绑定原桶账本的幂等结算句柄。
    ///
    /// 参数说明：`request` 描述额度；`reservation_id` 是结算去重标识；`max_actual` 限制异常负债。
    ///
    /// 返回：返回 admission 结果；真实扣减成功时同时返回可退款或多退少补的句柄。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        Box::pin(async move {
            let decision = self.allow_sync(
                request.scope,
                request.key,
                request.cost,
                request.limit,
                request.window,
                request.burst,
                request.max_active_keys,
                request.active_keys_fail_open,
            );
            let reservation = (decision.allowed && decision.remaining != u64::MAX).then(|| {
                RateLimitReservation {
                    backend: Arc::new(LocalRateLimitSettlementBackend {
                        buckets: self.buckets.clone(),
                        settlements: self.settlements.clone(),
                    }),
                    spec: RateLimitSettlementSpec {
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

    /// 业务作用：从当前后端创建 reservation，并让结算句柄跨 reload 继续绑定预留时的原后端。
    ///
    /// 参数说明：`request` 是额度请求；`reservation_id`/`max_actual` 定义幂等结算边界。
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
        Box::pin(async move { inner.reserve(request, reservation_id, max_actual).await })
    }
}

struct Bucket {
    scope: String,
    tokens: f64,
    last_refill: Instant,
    idle_ttl: Duration,
}

struct LocalRateLimitSettlementBackend {
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
    settlements: Arc<Mutex<HashMap<String, Instant>>>,
}

impl RateLimitSettlementBackend for LocalRateLimitSettlementBackend {
    /// 业务作用：在同一进程账本中原子去重并把 provider 实际成本调整回预留时使用的 token bucket。
    ///
    /// 参数说明：`settlement` 包含唯一 reservation id、原桶边界、预留值和最终成本。
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
                .is_some_and(|expires_at| *expires_at > now)
            {
                return Ok(());
            }
            if ledger.len() >= MAX_SETTLEMENTS {
                ledger.retain(|_, expires_at| *expires_at > now);
                if ledger.len() >= MAX_SETTLEMENTS {
                    anyhow::bail!("local rate limit settlement ledger is full");
                }
            }

            let capacity = settlement.limit.saturating_add(settlement.burst).max(1);
            let refill_per_sec = settlement.limit as f64 / settlement.window.as_secs_f64();
            let idle_ttl = token_bucket_idle_ttl(settlement.limit, settlement.window, capacity);
            let mut buckets = buckets.lock();
            let bucket = buckets
                .entry(settlement.key.clone())
                .or_insert_with(|| Bucket {
                    scope: settlement.scope.clone(),
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
                now.checked_add(ledger_ttl).unwrap_or(now),
            );
            Ok(())
        })
    }
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

/// 业务作用：计算幂等 marker 至少覆盖完整桶恢复周期的有界存活时间，支持超时后安全重放结算。
///
/// 参数说明：`limit`、`window` 与 `capacity` 是预留时冻结的 token bucket 参数。
///
/// 返回：桶恢复周期加一分钟且不超过七天的 TTL。
fn settlement_ledger_ttl(limit: u64, window: Duration, capacity: u64) -> Duration {
    token_bucket_idle_ttl(limit, window, capacity)
        .saturating_add(Duration::from_secs(60))
        .min(Duration::from_secs(7 * 24 * 60 * 60))
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

/// 业务作用：生成限流与 ACME Redis 锁共享连接参数的稳定签名，驱动成功候选的运行态换代。
///
/// 参数说明：`cfg` 是候选快照的运行态配置。
///
/// 返回：返回只用于进程内相等比较的签名；不会写入日志或管理面。
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

/// 业务作用：按候选配置完整初始化动态事实源，成功前不替换在线后端。
///
/// 参数说明：`cfg` 选择 file/Redis/Nacos 并提供资源硬门；`cfg_path` 用于解析 file 相对路径。
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
/// 参数说明：`cfg` 是当前或候选运行态配置。
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
/// 参数说明：`cfg` 是候选快照的 runtime-state 配置。
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
/// 参数说明：`_cfg` 是已选择 Nacos 的候选运行态配置，本制品不会读取其中 credential。
///
/// 返回：始终返回 feature 缺失错误，使启动或 reload 保留既有后端。
async fn build_nacos_dynamic_store(_cfg: &RuntimeStateCfg) -> Result<Arc<dyn DynamicStore>> {
    anyhow::bail!(
        "runtime_state.store.backend=nacos requires building gateway with feature `nacos-sdk`"
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
const TOKEN_BUCKET_SETTLE_LUA: &str = r#"
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local reserved = tonumber(ARGV[3])
local actual = tonumber(ARGV[4])
local ledger_ttl = tonumber(ARGV[5])
if cap == nil or refill == nil or reserved == nil or actual == nil or ledger_ttl == nil
  or cap <= 0 or refill <= 0 or reserved < 0 or actual < 0 or ledger_ttl <= 0 then
  return redis.error_reply('invalid token settlement arguments')
end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ledger_ttl) == false then
  return 0
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local ttl = math.ceil((cap / refill) * 1000) + 1000
local st = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(st[1])
local ts = tonumber(st[2])
if tokens == nil then tokens = cap end
if ts == nil then ts = now end
if now > ts then
  tokens = math.min(cap, tokens + ((now - ts) / 1000.0) * refill)
end
tokens = math.min(cap, math.max(-cap, tokens + reserved - actual))
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return 1
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
            let (redis_key, active_key, _) = redis_rate_limit_keys(scope, key);
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

    /// 业务作用：在共享 Redis 桶中预留 provider 成本，并创建与同 cluster slot 幂等 marker 绑定的结算句柄。
    ///
    /// 参数说明：`request` 描述额度；`reservation_id` 是跨重试去重标识；`max_actual` 限制异常负债。
    ///
    /// 返回：返回 Redis admission 结果；真实扣减且未走 fail-open 时同时返回可结算句柄。
    fn reserve<'a>(
        &'a self,
        request: RateLimitRequest<'a>,
        reservation_id: &'a str,
        max_actual: u64,
    ) -> RateLimitReserveFuture<'a> {
        Box::pin(async move {
            let decision = self.allow(request).await;
            let reservation = (decision.allowed && decision.remaining != u64::MAX).then(|| {
                let (redis_key, _, settlement_prefix) =
                    redis_rate_limit_keys(request.scope, request.key);
                RateLimitReservation {
                    backend: Arc::new(RedisRateLimitSettlementBackend {
                        client: self.client.clone(),
                        redis_key,
                        settlement_prefix,
                    }),
                    spec: RateLimitSettlementSpec {
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

#[cfg(feature = "redis-runtime")]
struct RedisRateLimitSettlementBackend {
    client: Arc<nasa::redis::RedisClient>,
    redis_key: String,
    settlement_prefix: String,
}

#[cfg(feature = "redis-runtime")]
impl RateLimitSettlementBackend for RedisRateLimitSettlementBackend {
    /// 业务作用：用 Redis Lua 在共享 token bucket 上原子执行 reservation id 去重与多退少补。
    ///
    /// 参数说明：`settlement` 携带预留值、provider 最终成本和原桶补充参数。
    ///
    /// 返回：首次应用或已存在同 id marker 时成功；Redis/协议错误返回失败，由句柄重试并保留原预留。
    fn apply(
        &self,
        settlement: RateLimitSettlementSpec,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
        let client = self.client.clone();
        let redis_key = self.redis_key.clone();
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
            client
                .eval::<i64>(
                    TOKEN_BUCKET_SETTLE_LUA,
                    &[redis_key.as_str(), settlement_key.as_str()],
                    &[
                        capacity.as_str(),
                        refill.as_str(),
                        reserved.as_str(),
                        actual.as_str(),
                        ledger_ttl.as_str(),
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
/// 参数说明：`scope` 是配置生成的规则作用域，`key` 是已经脱敏的维度键。
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
