//! V5 HTTP 响应缓存的安全策略、L1 读写与有界流式回填。
//!
//! 缓存是 route 显式 opt-in 的慢路径：命中 body 用 `Bytes` 共享；miss 仍把原 frame
//! 原样交给下游，只额外复制不超过 `max_body_bytes` 的未压缩实体用于回填。超过上限、
//! 出错、trailers 或下游取消都不写缓存，默认代理快路径完全不进入本模块。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(any(feature = "redis-runtime", test))]
use anyhow::Context as _;
use anyhow::Result;
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use http::header::{
    AGE, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_LOCATION,
    CONTENT_RANGE, COOKIE, DATE, ETAG, EXPIRES, HOST, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED, PRAGMA, RANGE, SET_COOKIE, VARY,
};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::Response;
use nasa::cache::local_cache::BoundedLocalCache;
use parking_lot::Mutex;
#[cfg(feature = "redis-runtime")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, Notify};

use crate::config::model::HttpCacheBackendCfg;
use crate::config::GatewaySnapshot;
use crate::metrics::Metrics;
use crate::{full_body, BoxBody, BoxError};

/// Redis 二进制 entry 格式魔数与版本。版本不认识时 fail-safe 当 miss，绝不尝试猜格式。
#[cfg(any(feature = "redis-runtime", test))]
const CACHE_ENTRY_MAGIC: &[u8; 4] = b"GWHC";
#[cfg(any(feature = "redis-runtime", test))]
const CACHE_ENTRY_VERSION: u8 = 2;
/// route fresh 与 stale window 各最多七天，因此合法 L2 记录的总驻留期最多十四天。
/// Redis 是不可信共享状态，decoder 不能依赖 encoder 曾经写过合法 TTL。
#[cfg(any(feature = "redis-runtime", test))]
const MAX_CACHE_RETENTION: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// 缓存响应头的独立防御上限。它不替代 HTTP parser 的 header 限制，而是保护 Redis 脏值解码。
const MAX_CACHE_HEADER_COUNT: usize = 256;
const MAX_CACHE_HEADER_BYTES: usize = 64 * 1024;
/// route TTL 最大 7 天；generation 再多保留一天，确保 generation 回到 0 前旧 data 已自然过期。
#[cfg(feature = "redis-runtime")]
const CACHE_GENERATION_TTL: Duration = Duration::from_secs(8 * 24 * 60 * 60);
#[cfg(feature = "redis-runtime")]
const CACHE_GENERATION_GET_LUA: &str =
    "local v=redis.call('GET',KEYS[1]); if not v then return 0 else return tonumber(v) end";
#[cfg(feature = "redis-runtime")]
const CACHE_ENTRY_GET_LUA: &str = "local n=redis.call('STRLEN',KEYS[1]); if n==0 then return {false,-2} end; if n>tonumber(ARGV[1]) then redis.call('DEL',KEYS[1]); return {false,-2} end; return {redis.call('GET',KEYS[1]),redis.call('PTTL',KEYS[1])}";
/// LLM 语义索引写入：exact response 已先用 PSETEX 写好；这里原子推进最近候选列表、裁上限、续 TTL。
#[cfg(feature = "redis-runtime")]
const LLM_CACHE_INDEX_STORE_LUA: &str = "redis.call('LPUSH',KEYS[1],ARGV[1]); redis.call('LTRIM',KEYS[1],0,tonumber(ARGV[2])-1); redis.call('PEXPIRE',KEYS[1],ARGV[3]); return 1";
/// 只返回总字节预算内的最近语义候选，Redis 脏大成员不会跨网络放大 gateway 内存。
#[cfg(feature = "redis-runtime")]
const LLM_CACHE_INDEX_READ_LUA: &str = "local out={}; local total=0; local count=tonumber(ARGV[1]); local each=tonumber(ARGV[2]); local budget=tonumber(ARGV[3]); for i=0,count-1 do local v=redis.call('LINDEX',KEYS[1],i); if not v then break end; local n=string.len(v); if n<=each and total+n<=budget then table.insert(out,v); total=total+n end end; return out";
/// 先在 Redis 内检查 exact value 大小；超限脏值删除且不下载到数据面。
#[cfg(feature = "redis-runtime")]
const LLM_CACHE_EXACT_READ_LUA: &str = "local n=redis.call('STRLEN',KEYS[1]); if n==0 then return false end; if n>tonumber(ARGV[1]) then redis.call('DEL',KEYS[1]); return false end; return redis.call('GET',KEYS[1])";

/// V5 HTTP cache 的进程级 L2 运行时。
///
/// route 的 L1 随不可变配置快照存在；本对象只持 bootstrap Redis 连接、二进制协议与失效总线。
/// 默认 backend=local 时所有方法都是零网络的空操作，因此核心代理不硬依赖 Redis。
pub struct HttpCacheRuntime {
    backend: HttpCacheBackend,
    #[cfg(feature = "redis-runtime")]
    reconcile_interval: Duration,
    shutdown: watch::Sender<bool>,
}

/// 进程级 HTTP cache L2 代际句柄；请求每次只借用当前代，reload 可先建连再切换。
pub struct SwappableHttpCacheRuntime {
    active: ArcSwap<HttpCacheRuntime>,
    snapshot: OnceLock<Arc<arc_swap::ArcSwap<GatewaySnapshot>>>,
}

enum HttpCacheBackend {
    Disabled,
    #[cfg(feature = "redis-runtime")]
    Redis {
        client: Arc<nasa::redis::RedisClient>,
        /// 跨节点同 key 回填锁；只在 L2 route cache miss 上访问。
        fill_lock: Arc<nasa::redis::DistributedLock>,
        prefix: Arc<str>,
        invalidation_channel: Arc<str>,
    },
}

/// route generation 广播。只传 route 身份与新代号，不传 URI/Vary，避免敏感 key 进入消息系统。
#[cfg(feature = "redis-runtime")]
#[derive(Serialize, Deserialize)]
struct CacheInvalidation {
    proxy: String,
    route: String,
    generation: u64,
}

impl HttpCacheRuntime {
    /// 从 bootstrap 配置建立 L2。Redis 显式启用时建连失败会拒绝启动；运行中命令失败则 cache
    /// fail-open，当作 miss 回源，绝不把缓存可用性升级成业务可用性的硬依赖。
    ///
    /// # 参数
    /// - `cfg`: `runtime_state.http_cache` 配置。
    pub async fn build(cfg: &HttpCacheBackendCfg) -> Result<Arc<Self>> {
        validate_runtime_config(cfg)?;
        let backend = match cfg.backend.trim().to_ascii_lowercase().as_str() {
            "" | "local" | "off" | "disabled" => HttpCacheBackend::Disabled,
            "redis" => build_redis_backend(cfg).await?,
            other => anyhow::bail!("unsupported runtime_state.http_cache.backend `{other}`"),
        };
        let (shutdown, _) = watch::channel(false);
        Ok(Arc::new(Self {
            backend,
            #[cfg(feature = "redis-runtime")]
            reconcile_interval: Duration::from_millis(cfg.reconcile_interval_ms),
            shutdown,
        }))
    }

    /// 是否装配了真实共享 L2。route 的 `l2=true` 会在快照构建期与本开关交叉校验。
    pub fn is_shared(&self) -> bool {
        match &self.backend {
            HttpCacheBackend::Disabled => false,
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { .. } => true,
        }
    }

    /// 读取 LLM Redis exact entry。默认 local backend 返回 miss；运行错误由调用方按缓存
    /// fail-open 处理。scope/digest 都是固定长度十六进制摘要，不把 prompt/consumer 明文写 key。
    pub(crate) async fn llm_cache_get_exact(
        &self,
        scope: &str,
        digest: &str,
        max_encoded_bytes: usize,
    ) -> Result<Option<Bytes>> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (scope, digest, max_encoded_bytes);
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(None),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let key = llm_exact_redis_key(prefix, scope, digest);
                let limit = max_encoded_bytes.to_string();
                let raw: Option<Vec<u8>> = client
                    .eval(LLM_CACHE_EXACT_READ_LUA, &[key.as_str()], &[limit.as_str()])
                    .await
                    .context("read LLM exact cache entry")?;
                Ok(raw.map(Bytes::from))
            }
        }
    }

    /// 读取最近的有界语义索引成员。Lua 同时限制单成员与总返回字节，避免 Redis 脏值把
    /// `LRANGE` 变成无界网络/内存输入。
    pub(crate) async fn llm_cache_candidates(
        &self,
        scope: &str,
        max_candidates: usize,
        max_dimensions: usize,
    ) -> Result<Vec<Vec<u8>>> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (scope, max_candidates, max_dimensions);
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(Vec::new()),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let key = llm_index_redis_key(prefix, scope);
                // JSON f32 最坏文本显著小于 32 bytes/component；再给摘要/字段 1KiB 余量。
                // build 已约束 candidates*dimensions <= 1,048,576，总预算最多约 32MiB。
                let each = max_dimensions.saturating_mul(32).saturating_add(1024);
                let total = max_candidates.saturating_mul(each).min(32 * 1024 * 1024);
                let count = max_candidates.to_string();
                let each = each.to_string();
                let total = total.to_string();
                client
                    .eval(
                        LLM_CACHE_INDEX_READ_LUA,
                        &[key.as_str()],
                        &[count.as_str(), each.as_str(), total.as_str()],
                    )
                    .await
                    .context("read LLM semantic cache candidates")
            }
        }
    }

    /// 回填 LLM Redis L2。先写 exact response，再原子裁剪候选索引；若第二步失败，只留下一个
    /// 可被精确命中的 TTL key，不会出现索引指向不存在响应的错误命中。L1/下游继续共享原 Bytes，
    /// 只有 Redis string 格式需要一份连续编码。
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn llm_cache_store(
        &self,
        scope: &str,
        digest: &str,
        encoded_response: &[u8],
        encoded_candidate: Option<&str>,
        ttl: Duration,
        max_entries: usize,
    ) -> Result<()> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (
            scope,
            digest,
            encoded_response,
            encoded_candidate,
            ttl,
            max_entries,
        );
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(()),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let exact_key = llm_exact_redis_key(prefix, scope, digest);
                client
                    .set_ttl(&exact_key, encoded_response, ttl)
                    .await
                    .context("write LLM exact cache response")?;
                let Some(encoded_candidate) = encoded_candidate else {
                    return Ok(());
                };
                let index_key = llm_index_redis_key(prefix, scope);
                let max_entries = max_entries.to_string();
                let ttl_ms = ttl.as_millis().max(1).to_string();
                let _: u64 = client
                    .eval(
                        LLM_CACHE_INDEX_STORE_LUA,
                        &[index_key.as_str()],
                        &[encoded_candidate, max_entries.as_str(), ttl_ms.as_str()],
                    )
                    .await
                    .context("write LLM semantic cache index")?;
                Ok(())
            }
        }
    }

    /// 启动失效订阅与周期 generation 对账。只有 Redis backend 会产生后台任务。
    ///
    /// Pub/Sub 是瞬时通知，不足以单独承担正确性；周期读取 generation 会补回断线窗口漏掉的
    /// 消息。发现代号变化时整 route L1 失效，旧 Redis data 因 key 含旧 generation 而不可达。
    ///
    /// # 参数
    /// - `snap`: 与数据面共享的原子快照，用于定位当前 route L1。
    pub fn spawn_invalidation_worker(
        self: &Arc<Self>,
        snap: Arc<arc_swap::ArcSwap<GatewaySnapshot>>,
    ) {
        #[cfg(feature = "redis-runtime")]
        if matches!(self.backend, HttpCacheBackend::Redis { .. }) {
            let runtime = self.clone();
            let shutdown = runtime.shutdown.subscribe();
            tokio::spawn(async move {
                runtime.run_invalidation_worker(snap, shutdown).await;
            });
        }
        #[cfg(not(feature = "redis-runtime"))]
        let _ = snap;
    }

    /// 管理面按 route 主动 PURGE：先推进 Redis generation，再清本机 L1，最后广播其它节点。
    ///
    /// 先改共享事实源可避免“本机先清、并发请求又从旧 L2 灌回”的复活竞态。Redis 失败时不清
    /// 本地，返回错误让 operator 重试；local-only route 则只清本机。
    ///
    /// # 参数
    /// - `proxy_id`: proxy 稳定 id。
    /// - `route_id`: route 稳定 id。
    /// - `policy`: 当前快照中的 route cache。
    pub(crate) async fn purge_route(
        &self,
        proxy_id: &str,
        route_id: &str,
        policy: &HttpCachePolicy,
    ) -> Result<u64> {
        if !policy.l2_enabled {
            policy.invalidate_all();
            return Ok(policy.generation.load(Ordering::Acquire));
        }
        let scope = cache_scope(proxy_id, route_id);
        let next = self.bump_generation(&scope).await?;
        policy.apply_generation(next);
        self.publish_invalidation(proxy_id, route_id, next).await?;
        Ok(next)
    }

    async fn generation(&self, scope: &str) -> Result<u64> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = scope;
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(0),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let key = generation_redis_key(prefix, scope);
                let generation: u64 = client
                    .eval(CACHE_GENERATION_GET_LUA, &[key.as_str()], &[])
                    .await
                    .context("read HTTP cache route generation")?;
                if generation > 0 {
                    // 活跃 route 每次周期对账都续期 generation；只有 route 被配置删除超过 8 天才回收。
                    // 因 data TTL 最长 7 天，generation 归零时旧 data 已全部自然消失。
                    if let Err(error) = client.expire(&key, CACHE_GENERATION_TTL).await {
                        tracing::warn!(%error, "HTTP cache generation TTL reconcile failed");
                    }
                }
                Ok(generation)
            }
        }
    }

    async fn bump_generation(&self, scope: &str) -> Result<u64> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = scope;
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(0),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let key = generation_redis_key(prefix, scope);
                let next = client
                    .incr_by(&key, 1)
                    .await
                    .context("increment HTTP cache route generation")?;
                anyhow::ensure!(next >= 0, "HTTP cache generation became negative");
                // 若 EXPIRE 失败，代号仍是正确的新事实，只可能留下一个小的持久 key；不能回滚 INCR。
                if let Err(error) = client.expire(&key, CACHE_GENERATION_TTL).await {
                    tracing::warn!(%error, "HTTP cache generation TTL refresh failed");
                }
                Ok(next as u64)
            }
        }
    }

    async fn lookup_l2(
        &self,
        storage_key: &str,
        max_body_bytes: usize,
    ) -> Result<Option<CachedResponse>> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (storage_key, max_body_bytes);
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(None),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let key = data_redis_key(prefix, storage_key);
                let max_wire = max_cache_wire_bytes(max_body_bytes)?.to_string();
                let (raw, pttl): (Option<Vec<u8>>, i64) = client
                    .eval(CACHE_ENTRY_GET_LUA, &[key.as_str()], &[max_wire.as_str()])
                    .await
                    .context("read HTTP cache L2 entry")?;
                let Some(raw) = raw else {
                    return Ok(None);
                };
                if pttl <= 0 {
                    return Ok(None);
                }
                match decode_cached_response(
                    Bytes::from(raw),
                    Duration::from_millis(pttl as u64),
                    max_body_bytes,
                ) {
                    Ok(entry) => Ok(Some(entry)),
                    Err(error) => {
                        // 脏值若保留会让每个请求重复下载/解析；单 key DEL 是有界、幂等的自愈。
                        if let Err(delete_error) = client.del(&[key.as_str()]).await {
                            tracing::warn!(%delete_error, "delete malformed HTTP cache L2 entry failed");
                        }
                        Err(error)
                    }
                }
            }
        }
    }

    async fn store_l2(&self, storage_key: &str, entry: &CachedResponse) -> Result<()> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (storage_key, entry);
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(()),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis { client, prefix, .. } => {
                let key = data_redis_key(prefix, storage_key);
                let remaining = entry.stale_until.saturating_duration_since(Instant::now());
                anyhow::ensure!(
                    !remaining.is_zero(),
                    "HTTP cache entry expired before L2 store"
                );
                let encoded = encode_cached_response(entry)?;
                // Redis string 必须是一段连续字节；这是 L2 opt-in 慢路径唯一额外完整 payload copy。
                // L1 与下游仍共享原 `Bytes`，默认/命中热路径不为此付费。
                client
                    .set_ttl(&key, encoded.as_ref(), remaining)
                    .await
                    .context("write HTTP cache L2 entry")
            }
        }
    }

    async fn publish_invalidation(
        &self,
        proxy_id: &str,
        route_id: &str,
        generation: u64,
    ) -> Result<()> {
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (proxy_id, route_id, generation);
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(()),
            #[cfg(feature = "redis-runtime")]
            HttpCacheBackend::Redis {
                client,
                invalidation_channel,
                ..
            } => {
                let payload = serde_json::to_vec(&CacheInvalidation {
                    proxy: proxy_id.to_string(),
                    route: route_id.to_string(),
                    generation,
                })?;
                let _ = client
                    .r#pub(invalidation_channel, payload.as_slice())
                    .await
                    .context("publish HTTP cache invalidation")?;
                Ok(())
            }
        }
    }

    /// 跨节点等待/获取一个 cache fill 锁。锁 key 只含固定摘要，不包含 URI/Vary 明文。
    ///
    /// NASA 锁的等待覆盖 Redis subscribe/PTTL 且受绝对 timeout 约束；拿到锁后调用方必须
    /// double-check L2，因为前任 leader 很可能已经完成回填。
    #[cfg(feature = "redis-runtime")]
    async fn acquire_fill_lock(
        &self,
        storage_key: &str,
        timeout: Duration,
    ) -> Result<Option<nasa::redis::LockGuard>> {
        match &self.backend {
            HttpCacheBackend::Disabled => Ok(None),
            HttpCacheBackend::Redis {
                fill_lock, prefix, ..
            } => {
                let key = format!("{prefix}:fill:{storage_key}");
                let guard = fill_lock
                    .lock(&key, Some(timeout))
                    .await
                    .context("wait for HTTP cache distributed single-flight lock")?;
                Ok(Some(guard))
            }
        }
    }

    #[cfg(feature = "redis-runtime")]
    async fn run_invalidation_worker(
        self: Arc<Self>,
        snap: Arc<arc_swap::ArcSwap<GatewaySnapshot>>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let HttpCacheBackend::Redis {
            client,
            invalidation_channel,
            ..
        } = &self.backend
        else {
            return;
        };
        loop {
            if *shutdown.borrow() {
                return;
            }
            // 每次重订前先对账；即使上次断线期间漏了广播，也不会永久保留旧 L1。
            self.reconcile_all_generations(&snap).await;
            match client.sub(&[invalidation_channel]).await {
                Ok(mut subscription) => {
                    let mut tick = tokio::time::interval(self.reconcile_interval);
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() { return; }
                            }
                            message = subscription.next_message() => {
                                let Some(message) = message else { break; };
                                self.apply_invalidation_message(&snap, &message.payload);
                            }
                            _ = tick.tick() => self.reconcile_all_generations(&snap).await,
                        }
                    }
                    tracing::warn!("HTTP cache invalidation subscription disconnected");
                }
                Err(error) => {
                    tracing::warn!(%error, "HTTP cache invalidation subscribe failed");
                }
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    #[cfg(feature = "redis-runtime")]
    fn apply_invalidation_message(
        &self,
        snap: &arc_swap::ArcSwap<GatewaySnapshot>,
        payload: &[u8],
    ) {
        let Ok(event) = serde_json::from_slice::<CacheInvalidation>(payload) else {
            tracing::warn!("discard malformed HTTP cache invalidation message");
            return;
        };
        if event.proxy.len() > 256 || event.route.len() > 256 {
            tracing::warn!("discard oversized HTTP cache invalidation identity");
            return;
        }
        if let Some(policy) = find_cache_policy(&snap.load(), &event.proxy, &event.route) {
            policy.apply_generation(event.generation);
        }
    }

    #[cfg(feature = "redis-runtime")]
    async fn reconcile_all_generations(&self, snap: &arc_swap::ArcSwap<GatewaySnapshot>) {
        let snapshot = snap.load_full();
        for proxy in snapshot.proxies.iter() {
            for route in proxy.router.routes() {
                let Some(policy) = route.http_cache.as_ref().filter(|policy| policy.l2_enabled)
                else {
                    continue;
                };
                let scope = cache_scope(&proxy.id, &route.id);
                let observed = policy.generation.load(Ordering::Acquire);
                match self.generation(&scope).await {
                    Ok(generation) => policy.reconcile_generation(observed, generation),
                    Err(error) => {
                        // 对账失败时清 L1 是 fail-safe：可能损失命中率，但不会在失效总线异常时长期返旧。
                        policy.invalidate_all();
                        tracing::warn!(proxy = %proxy.id, route = %route.id, %error, "HTTP cache generation reconcile failed; cleared L1");
                    }
                }
            }
        }
    }
}

impl SwappableHttpCacheRuntime {
    /// 业务作用：以已建立的 cache 代创建稳定句柄，使 Proxy/Admin 无需换指针。
    ///
    /// 参数说明：`initial` 是启动期已完成 Redis 连接复验的初始代。
    ///
    /// 返回：返回尚未启动失效订阅的可换代句柄。
    pub fn new(initial: Arc<HttpCacheRuntime>) -> Arc<Self> {
        Arc::new(Self {
            active: ArcSwap::from(initial),
            snapshot: OnceLock::new(),
        })
    }

    /// 业务作用：启动当前 cache 代的失效订阅，并保存后续换代共用的快照句柄。
    ///
    /// 参数说明：`snap` 用于将 Redis generation 对账到当前 route L1。
    ///
    /// 返回：无返回值；重复调用不会改变已绑定的快照 owner。
    pub fn spawn_invalidation_worker(
        self: &Arc<Self>,
        snap: Arc<arc_swap::ArcSwap<GatewaySnapshot>>,
    ) {
        if self.snapshot.set(snap.clone()).is_ok() {
            self.active.load_full().spawn_invalidation_worker(snap);
        }
    }

    /// 业务作用：原子切换已建连的 cache 代，先让新代可见再撤销旧失效订阅。
    ///
    /// 参数说明：`candidate` 是通过 [`HttpCacheRuntime::build`] 准备好的候选代。
    ///
    /// 返回：无返回值；新请求立即使用候选拓扑，旧代在通知后退出。
    pub fn replace(&self, candidate: Arc<HttpCacheRuntime>) {
        let old = self.active.swap(candidate.clone());
        if let Some(snapshot) = self.snapshot.get() {
            candidate.spawn_invalidation_worker(snapshot.clone());
        }
        let _ = old.shutdown.send(true);
    }

    /// 业务作用：读取当前 L2 共享状态，供候选 route 构建与运行门禁使用。
    ///
    /// 参数说明：无。
    ///
    /// 返回：当前代使用 Redis L2 时返回 true。
    pub fn is_shared(&self) -> bool {
        self.active.load().is_shared()
    }

    async fn generation(&self, scope: &str) -> Result<u64> {
        self.active.load_full().generation(scope).await
    }

    async fn lookup_l2(
        &self,
        storage_key: &str,
        max_body_bytes: usize,
    ) -> Result<Option<CachedResponse>> {
        self.active
            .load_full()
            .lookup_l2(storage_key, max_body_bytes)
            .await
    }

    async fn store_l2(&self, storage_key: &str, entry: &CachedResponse) -> Result<()> {
        self.active.load_full().store_l2(storage_key, entry).await
    }

    #[cfg(feature = "redis-runtime")]
    async fn acquire_fill_lock(
        &self,
        storage_key: &str,
        timeout: Duration,
    ) -> Result<Option<nasa::redis::LockGuard>> {
        self.active
            .load_full()
            .acquire_fill_lock(storage_key, timeout)
            .await
    }

    pub(crate) async fn llm_cache_get_exact(
        &self,
        scope: &str,
        digest: &str,
        max_encoded_bytes: usize,
    ) -> Result<Option<Bytes>> {
        self.active
            .load_full()
            .llm_cache_get_exact(scope, digest, max_encoded_bytes)
            .await
    }

    pub(crate) async fn llm_cache_candidates(
        &self,
        scope: &str,
        max_candidates: usize,
        max_dimensions: usize,
    ) -> Result<Vec<Vec<u8>>> {
        self.active
            .load_full()
            .llm_cache_candidates(scope, max_candidates, max_dimensions)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn llm_cache_store(
        &self,
        scope: &str,
        digest: &str,
        encoded_response: &[u8],
        encoded_candidate: Option<&str>,
        ttl: Duration,
        max_entries: usize,
    ) -> Result<()> {
        self.active
            .load_full()
            .llm_cache_store(
                scope,
                digest,
                encoded_response,
                encoded_candidate,
                ttl,
                max_entries,
            )
            .await
    }

    pub(crate) async fn purge_route(
        &self,
        proxy_id: &str,
        route_id: &str,
        policy: &HttpCachePolicy,
    ) -> Result<u64> {
        self.active
            .load_full()
            .purge_route(proxy_id, route_id, policy)
            .await
    }
}

/// 校验 L2 bootstrap 配置。单独导出给快照 build/dry-run 复用，不发生网络访问。
///
/// # 参数
/// - `cfg`: `runtime_state.http_cache` 配置。
pub fn validate_runtime_config(cfg: &HttpCacheBackendCfg) -> Result<()> {
    match cfg.backend.trim().to_ascii_lowercase().as_str() {
        "" | "local" | "off" | "disabled" => {}
        "redis" => {
            #[cfg(not(feature = "redis-runtime"))]
            {
                anyhow::bail!(
                    "runtime_state.http_cache.backend=redis requires building gateway with feature `redis-runtime`"
                );
            }
            #[cfg(feature = "redis-runtime")]
            {
                anyhow::ensure!(
                    !cfg.redis.url.trim().is_empty(),
                    "runtime_state.http_cache.redis.url is required when backend=redis"
                );
                anyhow::ensure!(
                    !cfg.prefix.trim().is_empty() && cfg.prefix.len() <= 256,
                    "runtime_state.http_cache.prefix must contain 1..=256 bytes"
                );
                anyhow::ensure!(
                    !cfg.invalidation_channel.trim().is_empty()
                        && cfg.invalidation_channel.len() <= 256,
                    "runtime_state.http_cache.invalidation_channel must contain 1..=256 bytes"
                );
            }
        }
        other => anyhow::bail!("unsupported runtime_state.http_cache.backend `{other}`"),
    }
    anyhow::ensure!(
        (100..=3_600_000).contains(&cfg.reconcile_interval_ms),
        "runtime_state.http_cache.reconcile_interval_ms must be within 100..=3600000"
    );
    Ok(())
}

/// HTTP cache bootstrap 连接签名。只用于候选快照等值比较，不记录/输出，避免 Redis URL 密码泄露。
///
/// # 参数
/// - `cfg`: `runtime_state.http_cache` 配置。
pub fn runtime_config_signature(cfg: &HttpCacheBackendCfg) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        cfg.backend.trim(),
        cfg.redis.url.trim(),
        cfg.redis.namespace.trim(),
        cfg.redis.profile.trim(),
        cfg.prefix.trim(),
        cfg.invalidation_channel.trim(),
        cfg.reconcile_interval_ms,
    )
}

#[cfg(feature = "redis-runtime")]
async fn build_redis_backend(cfg: &HttpCacheBackendCfg) -> Result<HttpCacheBackend> {
    use nasa::redis::{CompatibilityProfile, RedisClient, RedisConfig};

    let profile = match cfg.redis.profile.trim() {
        "RustV2" | "rustv2" | "rust-v2" => CompatibilityProfile::RustV2,
        "LegacyV1" | "legacyv1" | "legacy-v1" => CompatibilityProfile::LegacyV1,
        other => anyhow::bail!("unsupported runtime_state.http_cache.redis.profile `{other}`"),
    };
    let client = RedisClient::connect(RedisConfig::new(
        cfg.redis.url.clone(),
        cfg.redis.namespace.clone(),
        profile,
    ))
    .await
    .context("connect Redis HTTP cache L2 through nasa::redis")?;
    Ok(HttpCacheBackend::Redis {
        fill_lock: Arc::new(nasa::redis::DistributedLock::new(client.clone())),
        client,
        prefix: Arc::from(cfg.prefix.trim()),
        invalidation_channel: Arc::from(cfg.invalidation_channel.trim()),
    })
}

#[cfg(not(feature = "redis-runtime"))]
async fn build_redis_backend(_cfg: &HttpCacheBackendCfg) -> Result<HttpCacheBackend> {
    anyhow::bail!(
        "runtime_state.http_cache.backend=redis requires building gateway with feature `redis-runtime`"
    )
}

/// 缓存命中标记；代理响应阶段据此避免再次执行 header/sub_filter。
#[derive(Clone, Copy)]
pub(crate) struct HttpCacheHit;

/// 响应已被 cache fill body 包装；后台 SWR 用它区分成功启动回填与策略跳过。
#[derive(Clone, Copy)]
pub(crate) struct HttpCacheFill;

/// 一次 route cache 查询结果。miss 携带已经加入 route generation 的最终 storage key，
/// 响应 EOF 回填直接复用，不在 response path 再拼 key。
pub(crate) enum CacheLookup {
    /// L1 或 L2 命中。
    Hit(Response<BoxBody>),
    /// stale 命中立即返回；可选 miss 由代理后台刷新，不阻塞当前响应。
    Stale(Response<BoxBody>, Option<CacheMiss>),
    /// 两级均未命中；携带最终 key 与可选 single-flight leader 生命周期。
    Miss(CacheMiss),
}

/// 一次可回填 cache miss。
pub(crate) struct CacheMiss {
    /// L1/Redis data 共用的摘要 key。
    key: String,
    /// 本请求若是同 key leader，守卫持续到完整 EOF/L1 可见；follower 超时降级时为 None。
    flight: Option<CacheFlightLeader>,
}

/// 同 key single-flight 共享状态。finished 原子位防止 Notify 的无记忆广播产生 lost wakeup。
struct CacheFlight {
    finished: AtomicBool,
    notify: Notify,
}

/// single-flight leader 的取消安全守卫。
///
/// 正常 EOF、上游/body error、下游取消、ineligible response 和 task panic 都会 Drop；先从有界
/// flight 表删除，再发布 finished/notify，等待者醒来后可以 double-check 或成为下一任 leader。
struct CacheFlightLeader {
    policy: Weak<HttpCachePolicy>,
    key: String,
    state: Arc<CacheFlight>,
    /// Redis fill lock 随 leader 持有；正常完整回填时移交 L2 store task 后再显式解锁。
    #[cfg(feature = "redis-runtime")]
    distributed: Option<nasa::redis::LockGuard>,
}

impl CacheFlightLeader {
    /// 附上已经取得的跨节点锁。
    #[cfg(feature = "redis-runtime")]
    fn attach_distributed(&mut self, guard: nasa::redis::LockGuard) {
        debug_assert!(self.distributed.is_none());
        self.distributed = Some(guard);
    }

    /// 把跨节点锁移交给 L2 store task；本地 L1 leader 可先完成并唤醒同节点 follower。
    #[cfg(feature = "redis-runtime")]
    fn take_distributed(&mut self) -> Option<nasa::redis::LockGuard> {
        self.distributed.take()
    }
}

impl Drop for CacheFlightLeader {
    fn drop(&mut self) {
        if let Some(policy) = self.policy.upgrade() {
            let mut flights = policy.flights.lock();
            if flights
                .get(self.key.as_str())
                .is_some_and(|current| Arc::ptr_eq(current, &self.state))
            {
                flights.remove(self.key.as_str());
            }
        }
        self.state.finished.store(true, Ordering::Release);
        self.state.notify.notify_waiters();
        #[cfg(feature = "redis-runtime")]
        if let Some(guard) = self.distributed.take() {
            // error/ineligible/cancel 路径不能 await；派生显式 unlock，避免把 30s lease 当正常释放。
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    if let Err(error) = guard.unlock().await {
                        tracing::warn!(%error, "release HTTP cache distributed fill lock failed");
                    }
                });
            }
        }
    }
}

enum CacheFlightClaim {
    Leader(CacheFlightLeader),
    Follower(Arc<CacheFlight>),
    /// 表已达到 `max_inflight`；fail-open 回源，不能创建无界 per-key 状态。
    Bypass,
}

enum PreparedFlight {
    #[cfg(feature = "redis-runtime")]
    Fresh(Arc<CachedResponse>),
    Leader(CacheFlightLeader),
}

enum CacheReady {
    Fresh(Arc<CachedResponse>),
    Stale(Arc<CachedResponse>),
}

/// route 级公共响应缓存策略与随快照生命周期存在的 L1。
pub(crate) struct HttpCachePolicy {
    /// entry 新鲜期。
    ttl: Duration,
    /// 单响应允许复制回填的最大未压缩 body。
    max_body_bytes: usize,
    /// 可缓存状态码白名单。
    statuses: Vec<StatusCode>,
    /// 运维显式声明进入 key 的 Vary header。
    vary_headers: Vec<HeaderName>,
    /// 是否为此 route 启用共享 Redis L2；false 时 runtime 完全不被访问。
    l2_enabled: bool,
    /// 每 route 独立 TinyLFU L1；热更后旧快照连同旧 cache 自然退场。
    store: Arc<BoundedLocalCache<String, CachedResponse>>,
    /// Redis route generation；PURGE 推进后旧 L1/L2 key 全部不可达。
    generation: AtomicU64,
    /// 启动/新快照后是否至少从 Redis 对账过一次 generation。
    generation_loaded: AtomicBool,
    /// 同节点 follower 最长等待 leader 完整回填的时间；超时自行回源，避免慢流拖死请求。
    singleflight_wait: Duration,
    /// 是否启用请求合并；false 时 cache miss 保持直接回源。
    singleflight_enabled: bool,
    /// 活跃不同 key 的 single-flight 硬上限。
    max_inflight: usize,
    /// key -> 当前 leader 状态。临界区只做 O(1) 查/插/删，绝不跨 await 持锁。
    flights: Mutex<HashMap<String, Arc<CacheFlight>>>,
    /// fresh 到期后允许立即返旧并后台刷新的最长窗口；0 禁用。
    stale_while_revalidate: Duration,
    /// fresh TTL 的确定性缩短上限百分比；分散不同 key 同时过期，0 禁用。
    ttl_jitter_percent: u8,
}

impl HttpCachePolicy {
    /// 构建一条已通过 routing 校验的公共缓存策略。
    ///
    /// # 参数
    /// - `ttl`: entry 新鲜期，必须非零。
    /// - `max_body_bytes`: miss 回填最多复制的未压缩实体字节数。
    /// - `max_entries`: 本 route L1 entry 硬上限。
    /// - `statuses`: 可缓存响应状态白名单。
    /// - `vary_headers`: 必须进入 key 的请求头集合；Accept-Encoding 不应传入，因为缓存未压缩实体。
    /// - `l2_enabled`: 是否使用进程级 Redis L2。
    /// - `singleflight_enabled`: 是否合并同节点并发 miss。
    /// - `singleflight_wait`: follower 最大等待时间，超时 fail-open 回源。
    /// - `max_inflight`: 不同 miss key 的活跃 leader 上限。
    /// - `stale_while_revalidate`: fresh 到期后的有界返旧窗口；0 禁用。
    /// - `ttl_jitter_percent`: fresh TTL 最多缩短的百分比，范围 0..=50。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ttl: Duration,
        max_body_bytes: usize,
        max_entries: u64,
        statuses: Vec<StatusCode>,
        vary_headers: Vec<HeaderName>,
        l2_enabled: bool,
        singleflight_enabled: bool,
        singleflight_wait: Duration,
        max_inflight: usize,
        stale_while_revalidate: Duration,
        ttl_jitter_percent: u8,
    ) -> Self {
        Self {
            ttl,
            max_body_bytes,
            statuses,
            vary_headers,
            l2_enabled,
            store: Arc::new(BoundedLocalCache::new(max_entries)),
            generation: AtomicU64::new(0),
            generation_loaded: AtomicBool::new(!l2_enabled),
            singleflight_wait,
            singleflight_enabled,
            max_inflight,
            flights: Mutex::new(HashMap::new()),
            stale_while_revalidate,
            ttl_jitter_percent,
        }
    }

    /// 当前 route 是否显式启用共享 L2。
    pub(crate) fn l2_enabled(&self) -> bool {
        self.l2_enabled
    }

    /// 是否显式配置了 stale-while-revalidate；路由构建期据此拒绝后台无法等价重放的控制流。
    pub(crate) fn stale_enabled(&self) -> bool {
        !self.stale_while_revalidate.is_zero()
    }

    /// 配置的 Vary key 是否包含给定请求头；路由构建期用来拒绝动态 CORS 等泄漏组合。
    pub(crate) fn covers_vary(&self, name: &HeaderName) -> bool {
        self.vary_headers.iter().any(|item| item == name)
    }

    /// 为一个安全可缓存请求构造稳定 key。
    ///
    /// GET/HEAD 共享同一个未压缩表示 key；HEAD miss 不回填空 body，但可复用已有 GET entry。
    /// Authorization/Cookie、Range、前置条件写语义和显式 no-cache 请求一律 bypass；
    /// If-None-Match/If-Modified-Since 则在 fresh hit 上由本层生成 304。query 按参数名稳定排序，避免把
    /// `a=1&a=2` 与 `a=2&a=1` 误判为同一上游语义。
    ///
    /// 所有字段增量写入 SHA-256，最终 key 固定 64 hex 字符；这既限制 L1 key 内存，也避免
    /// Redis key/日志暴露 Vary header 原值。摘要前写 64-bit 长度，消除字段边界碰撞。
    ///
    /// # 参数
    /// - `parts`: 已完成安全 path 规范化、但尚未移入上游请求的 head。
    /// - `proxy_id`: proxy listener 稳定 id，隔离不同入口的同名 route。
    /// - `route_id`: route 稳定 id，用于隔离不同 route 的相同 URI。
    /// - `downstream_proto`: `http` 或 `https`；动态 header/HSTS 等 scheme 语义不能串缓存。
    pub(crate) fn request_key(
        &self,
        parts: &Parts,
        proxy_id: &str,
        route_id: &str,
        downstream_proto: &str,
    ) -> Option<String> {
        if !matches!(parts.method, Method::GET | Method::HEAD)
            || parts.headers.contains_key(AUTHORIZATION)
            || parts.headers.contains_key(COOKIE)
            || parts.headers.contains_key(RANGE)
            || parts.headers.contains_key(IF_MATCH)
            || parts.headers.contains_key(IF_UNMODIFIED_SINCE)
            || parts.headers.contains_key(IF_RANGE)
            || request_forces_revalidation(&parts.headers)
        {
            return None;
        }
        let host = parts
            .uri
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                parts
                    .headers
                    .get(HOST)
                    .and_then(|value| value.to_str().ok())
            })?;
        let mut hasher = Sha256::new();
        hash_key_part(&mut hasher, proxy_id.as_bytes());
        hash_key_part(&mut hasher, route_id.as_bytes());
        hash_key_part(&mut hasher, downstream_proto.as_bytes());
        hash_key_part(&mut hasher, host.as_bytes());
        hash_key_part(&mut hasher, parts.uri.path().as_bytes());

        hash_key_part(&mut hasher, b"query-v2");
        if let Some(raw_query) = parts.uri.query() {
            hash_key_part(&mut hasher, b"present");
            // URI 总长度已受入口 head 预算约束；这里只收集 `&str` 引用，不复制 query 字节。
            // 空段也必须保留，避免 `/p`、`/p?`、`/p?&` 被错误合并成同一个缓存对象。
            let mut query = raw_query.split('&').collect::<Vec<_>>();
            // `sort_by` 是稳定排序：跨参数名顺序规范化，同名参数仍保持客户端原顺序。
            query.sort_by(|left, right| query_name(left).cmp(query_name(right)));
            hash_key_part(&mut hasher, &(query.len() as u64).to_be_bytes());
            for part in query {
                hash_key_part(&mut hasher, part.as_bytes());
            }
        } else {
            hash_key_part(&mut hasher, b"absent");
        }
        hash_key_part(&mut hasher, &(self.vary_headers.len() as u64).to_be_bytes());
        for name in &self.vary_headers {
            hash_key_part(&mut hasher, name.as_str().as_bytes());
            let values = parts.headers.get_all(name);
            hash_key_part(&mut hasher, &(values.iter().count() as u64).to_be_bytes());
            for value in values {
                hash_key_part(&mut hasher, value.as_bytes());
            }
        }
        Some(hex_digest(hasher.finalize().as_slice()))
    }

    /// 查询 L1 → L2。L1 命中只浅 clone body `Bytes`；L2 解码时 Redis 返回的 `Vec<u8>`
    /// 转成 `Bytes` 后，header value/body 都切片共享同一 backing allocation，不再复制 payload。
    ///
    /// # 参数
    /// - `digest`: [`Self::request_key`] 生成的固定长度请求摘要。
    /// - `request`: 原请求 head，用于 HEAD body 抑制和条件命中 304。
    /// - `proxy_id`: 当前 proxy id。
    /// - `route_id`: 当前 route id。
    /// - `runtime`: 进程级 L2 runtime。
    /// - `metrics`: 固定 label 的 L2 hit/miss/error 指标。
    pub(crate) async fn lookup(
        self: &Arc<Self>,
        digest: String,
        request: &Parts,
        proxy_id: &str,
        route_id: &str,
        runtime: &SwappableHttpCacheRuntime,
        metrics: &Metrics,
    ) -> CacheLookup {
        let scope = cache_scope(proxy_id, route_id);
        let generation = if self.l2_enabled {
            if !self.generation_loaded.load(Ordering::Acquire) {
                let observed = self.generation.load(Ordering::Acquire);
                match runtime.generation(&scope).await {
                    Ok(value) => self.reconcile_generation(observed, value),
                    Err(error) => {
                        // Redis 命令失败按 miss 回源；保留当前 generation 的有界 L1 能力。
                        metrics.inc_http_cache_l2_error();
                        tracing::warn!(proxy = proxy_id, route = route_id, %error, "HTTP cache generation read failed; use local generation");
                    }
                }
            }
            self.generation.load(Ordering::Acquire)
        } else {
            0
        };
        let key = storage_key(&scope, generation, &digest);

        if let Some(ready) = self
            .lookup_ready(&key, proxy_id, route_id, runtime, metrics, true)
            .await
        {
            return self.lookup_from_ready(key, ready, request, metrics);
        }

        // HEAD miss 没有实体可回填；条件 GET miss 必须让真实上游判断验证器。两者都不能成为
        // 会令 follower 徒等的 leader，但已有 fresh entry 仍已在上方正常复用。
        if request.method == Method::HEAD
            || request.headers.contains_key(IF_NONE_MATCH)
            || request.headers.contains_key(IF_MODIFIED_SINCE)
        {
            return CacheLookup::Miss(CacheMiss { key, flight: None });
        }

        let flight = if self.singleflight_enabled {
            match self.claim_flight(&key) {
                CacheFlightClaim::Leader(leader) => {
                    metrics.inc_http_cache_singleflight_leader();
                    match self
                        .prepare_flight_leader(&key, leader, proxy_id, route_id, runtime, metrics)
                        .await
                    {
                        #[cfg(feature = "redis-runtime")]
                        PreparedFlight::Fresh(entry) => {
                            metrics.inc_http_cache_singleflight_wait_hit();
                            return CacheLookup::Hit(response_from_entry(&entry, request));
                        }
                        PreparedFlight::Leader(leader) => Some(leader),
                    }
                }
                CacheFlightClaim::Follower(state) => {
                    metrics.inc_http_cache_singleflight_follower();
                    let completed = self.wait_for_flight(&state).await;
                    if completed {
                        if let Some(ready) = self
                            .lookup_ready(&key, proxy_id, route_id, runtime, metrics, true)
                            .await
                        {
                            metrics.inc_http_cache_singleflight_wait_hit();
                            return self.lookup_from_ready(key, ready, request, metrics);
                        }
                        // Leader 得到了不可缓存响应或被取消；只尝试接任一次，不形成无限等待环。
                        match self.claim_flight(&key) {
                            CacheFlightClaim::Leader(leader) => {
                                metrics.inc_http_cache_singleflight_leader();
                                match self
                                    .prepare_flight_leader(
                                        &key, leader, proxy_id, route_id, runtime, metrics,
                                    )
                                    .await
                                {
                                    #[cfg(feature = "redis-runtime")]
                                    PreparedFlight::Fresh(entry) => {
                                        metrics.inc_http_cache_singleflight_wait_hit();
                                        return CacheLookup::Hit(response_from_entry(
                                            &entry, request,
                                        ));
                                    }
                                    PreparedFlight::Leader(leader) => Some(leader),
                                }
                            }
                            CacheFlightClaim::Follower(_) | CacheFlightClaim::Bypass => None,
                        }
                    } else {
                        metrics.inc_http_cache_singleflight_timeout();
                        None
                    }
                }
                CacheFlightClaim::Bypass => {
                    metrics.inc_http_cache_singleflight_bypass();
                    None
                }
            }
        } else {
            None
        };
        CacheLookup::Miss(CacheMiss { key, flight })
    }

    /// 把 fresh/stale entry 转成请求响应；stale leader 只登记后台刷新，不等待上游。
    fn lookup_from_ready(
        self: &Arc<Self>,
        key: String,
        ready: CacheReady,
        request: &Parts,
        metrics: &Metrics,
    ) -> CacheLookup {
        match ready {
            CacheReady::Fresh(entry) => CacheLookup::Hit(response_from_entry(&entry, request)),
            CacheReady::Stale(entry) => {
                // 条件请求必须到真实上游做 revalidation，不能用 stale entry 本地生成 304。
                if request.headers.contains_key(IF_NONE_MATCH)
                    || request.headers.contains_key(IF_MODIFIED_SINCE)
                {
                    return CacheLookup::Miss(CacheMiss { key, flight: None });
                }
                let refresh = if request.method == Method::GET {
                    match self.claim_flight(&key) {
                        CacheFlightClaim::Leader(leader) => {
                            metrics.inc_http_cache_singleflight_leader();
                            Some(CacheMiss {
                                key,
                                flight: Some(leader),
                            })
                        }
                        CacheFlightClaim::Follower(_) => {
                            metrics.inc_http_cache_singleflight_follower();
                            None
                        }
                        CacheFlightClaim::Bypass => {
                            metrics.inc_http_cache_singleflight_bypass();
                            None
                        }
                    }
                } else {
                    None
                };
                CacheLookup::Stale(response_from_entry(&entry, request), refresh)
            }
        }
    }

    /// 查询已经存在的 L1/L2，不创建新的 single-flight 状态；供初查和 follower double-check 复用。
    #[allow(clippy::too_many_arguments)]
    async fn lookup_ready(
        &self,
        key: &String,
        proxy_id: &str,
        route_id: &str,
        runtime: &SwappableHttpCacheRuntime,
        metrics: &Metrics,
        accept_stale: bool,
    ) -> Option<CacheReady> {
        if let Some(entry) = self.store.get(key).await {
            let now = Instant::now();
            if entry.fresh_until > now {
                return Some(CacheReady::Fresh(entry));
            }
            if accept_stale && entry.stale_until > now {
                return Some(CacheReady::Stale(entry));
            }
            if entry.stale_until <= now {
                self.store.invalidate(key).await;
            }
        }
        if self.l2_enabled {
            match runtime.lookup_l2(key, self.max_body_bytes).await {
                Ok(Some(entry)) => {
                    metrics.inc_http_cache_l2_hit();
                    let entry = self.store.insert(key.clone(), entry).await;
                    let now = Instant::now();
                    let ready = if entry.fresh_until > now {
                        CacheReady::Fresh(entry)
                    } else if accept_stale && entry.stale_until > now {
                        CacheReady::Stale(entry)
                    } else {
                        if entry.stale_until <= now {
                            self.store.invalidate(key).await;
                        }
                        return None;
                    };
                    return Some(ready);
                }
                Ok(None) => metrics.inc_http_cache_l2_miss(),
                Err(error) => {
                    metrics.inc_http_cache_l2_error();
                    tracing::warn!(proxy = proxy_id, route = route_id, %error, "HTTP cache L2 lookup failed; fallback to upstream");
                }
            }
        }
        None
    }

    /// 为一个 miss key 抢本节点 single-flight 身份。表大小达到配置上限时 fail-open。
    fn claim_flight(self: &Arc<Self>, key: &str) -> CacheFlightClaim {
        let mut flights = self.flights.lock();
        if let Some(state) = flights.get(key) {
            return CacheFlightClaim::Follower(state.clone());
        }
        if flights.len() >= self.max_inflight {
            return CacheFlightClaim::Bypass;
        }
        let state = Arc::new(CacheFlight {
            finished: AtomicBool::new(false),
            notify: Notify::new(),
        });
        // key 是固定长度摘要组合，复制只发生在显式 miss 控制结构中；表有 max_inflight 硬上限。
        flights.insert(key.to_string(), state.clone());
        CacheFlightClaim::Leader(CacheFlightLeader {
            policy: Arc::downgrade(self),
            key: key.to_string(),
            state,
            #[cfg(feature = "redis-runtime")]
            distributed: None,
        })
    }

    /// 有界等待 leader。二次 finished 检查封住“检查 false → leader notify → 注册 future”的丢唤醒窗。
    async fn wait_for_flight(&self, state: &CacheFlight) -> bool {
        if state.finished.load(Ordering::Acquire) {
            return true;
        }
        let notified = state.notify.notified();
        tokio::pin!(notified);
        if state.finished.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::timeout(self.singleflight_wait, &mut notified)
            .await
            .is_ok()
            || state.finished.load(Ordering::Acquire)
    }

    /// L2 route 的本地 leader 继续获取跨节点锁，并在锁内 double-check L2。
    #[allow(clippy::too_many_arguments)]
    async fn prepare_flight_leader(
        &self,
        key: &String,
        leader: CacheFlightLeader,
        proxy_id: &str,
        route_id: &str,
        runtime: &SwappableHttpCacheRuntime,
        metrics: &Metrics,
    ) -> PreparedFlight {
        #[cfg(feature = "redis-runtime")]
        let mut leader = leader;
        #[cfg(feature = "redis-runtime")]
        if self.l2_enabled {
            match runtime.acquire_fill_lock(key, self.singleflight_wait).await {
                Ok(Some(guard)) => {
                    leader.attach_distributed(guard);
                    if let Some(CacheReady::Fresh(entry)) = self
                        .lookup_ready(key, proxy_id, route_id, runtime, metrics, false)
                        .await
                    {
                        let guard = leader.take_distributed();
                        // L1/L2 已可见，先唤醒同节点 follower；远端在显式 unlock 后接管并 double-check。
                        drop(leader);
                        if let Some(guard) = guard {
                            if let Err(error) = guard.unlock().await {
                                tracing::warn!(%error, "release HTTP cache distributed fill lock after hit failed");
                            }
                        }
                        return PreparedFlight::Fresh(entry);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    // 缓存锁/Redis 不能成为业务硬依赖；有界等待失败后本请求回源并保留本地合并。
                    metrics.inc_http_cache_l2_error();
                    metrics.inc_http_cache_singleflight_bypass();
                    tracing::warn!(proxy = proxy_id, route = route_id, %error, "HTTP cache distributed single-flight unavailable; fallback to local leader");
                }
            }
        }
        #[cfg(not(feature = "redis-runtime"))]
        let _ = (key, proxy_id, route_id, runtime, metrics);
        PreparedFlight::Leader(leader)
    }

    /// 判断最终 post-filter、未压缩响应是否允许回填。
    ///
    /// # 参数
    /// - `resp`: response header filters/sub_filter 已就位、压缩尚未执行的响应。
    fn response_ttl(&self, resp: &Response<BoxBody>) -> Option<CacheLifetime> {
        if !self.statuses.contains(&resp.status())
            || resp.headers().contains_key(SET_COOKIE)
            || resp.headers().contains_key(CONTENT_RANGE)
            || has_non_identity_content_encoding(resp.headers())
            || !response_vary_is_covered(resp.headers(), &self.vary_headers)
            || !cache_headers_within_budget(resp.headers())
        {
            return None;
        }
        cache_control_lifetime(resp.headers(), self.ttl, self.stale_while_revalidate)
    }

    /// 为 stale 后台刷新准备本地/跨节点 leader，并在 Redis 锁内再次确认是否已有新 fresh entry。
    ///
    /// 当前 stale 响应在调用本函数前已经交还主链路；这里的 Redis 等锁只发生在派生任务，绝不
    /// 增加用户请求延迟。若其它节点已回填 fresh，返回 None 并释放本地 follower。
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare_revalidation(
        self: &Arc<Self>,
        miss: CacheMiss,
        proxy_id: &str,
        route_id: &str,
        runtime: &SwappableHttpCacheRuntime,
        metrics: &Metrics,
    ) -> Option<CacheMiss> {
        let CacheMiss { key, flight } = miss;
        let leader = flight?;
        match self
            .prepare_flight_leader(&key, leader, proxy_id, route_id, runtime, metrics)
            .await
        {
            #[cfg(feature = "redis-runtime")]
            PreparedFlight::Fresh(_) => {
                metrics.inc_http_cache_singleflight_wait_hit();
                None
            }
            PreparedFlight::Leader(leader) => Some(CacheMiss {
                key,
                flight: Some(leader),
            }),
        }
    }

    /// 包装 miss 响应，在不改变下游 frame/背压的情况下有界复制并于 EOF 回填。
    ///
    /// # 参数
    /// - `resp`: post-filter 后、压缩前的响应。
    /// - `miss`: 当前 miss 的稳定缓存 key 与可选 single-flight leader guard。
    pub(crate) fn wrap_fill(
        self: &Arc<Self>,
        mut resp: Response<BoxBody>,
        miss: CacheMiss,
        runtime: Arc<SwappableHttpCacheRuntime>,
        metrics: Arc<Metrics>,
    ) -> Response<BoxBody> {
        let Some(mut lifetime) = self.response_ttl(&resp) else {
            tracing::debug!(status = %resp.status(), "HTTP cache response is not eligible for fill");
            return resp;
        };
        let CacheMiss { key, flight } = miss;
        lifetime.fresh = jitter_fresh_ttl(lifetime.fresh, &key, self.ttl_jitter_percent);
        let mut headers = resp.headers().clone();
        let Some(initial_age_secs) = take_initial_age(&mut headers) else {
            tracing::debug!("HTTP cache response has invalid/multiple Age header; skip fill");
            return resp;
        };
        let already_aged = Duration::from_secs(initial_age_secs);
        if already_aged >= lifetime.fresh {
            // 已超过 freshness lifetime 的上游响应不作为新 fill；否则本节点会把 stale 对象
            // 错当成完整 TTL 的 fresh。等待下一请求按上游条件语义重新获取更安全。
            return resp;
        }
        lifetime.fresh -= already_aged;
        let status = resp.status();
        let version = resp.version();
        // Hyper 可以在恰好写满 Content-Length 后停止轮询 body，而不再向内层请求 EOF。
        // 回填必须等到真实 EOF 才能排除迟到的 body error/trailer；因此 cache miss 的下游响应
        // 改用流式 framing，强制消费者继续 poll 到 EOF。缓存快照仍保留原响应头，并在完整 EOF
        // 后用实际收集长度重写 Content-Length；命中响应不会付出 chunked framing 成本。
        // 这里只改 header metadata，不聚合、不重建 data frame，原始 Bytes 仍零拷贝透传。
        resp.headers_mut().remove(CONTENT_LENGTH);
        resp.extensions_mut().insert(HttpCacheFill);
        let policy = self.clone();
        resp.map(|body| {
            CacheFillBody {
                inner: Box::pin(body),
                policy,
                runtime,
                metrics,
                key: Some(key),
                headers: Some(headers),
                status,
                version,
                lifetime,
                initial_age_secs,
                buffer: BytesMut::new(),
                cacheable: true,
                done: false,
                commit_task: None,
                flight,
            }
            .boxed()
        })
    }

    /// 清空当前 route L1。moka 的 invalidate_all 是标记式 O(1)，不会同步扫描/阻塞请求线程。
    pub(crate) fn invalidate_all(&self) {
        self.store.invalidate_all();
    }

    /// 应用 Redis generation；只有发生变化才清 L1。Acquire/Release 保证先发布代号再让后续请求
    /// 观察新 key，旧在途请求即使晚回填也只会写旧 generation，之后不可达并由 TTL 回收。
    fn apply_generation(&self, generation: u64) {
        self.generation_loaded.store(true, Ordering::Release);
        let mut current = self.generation.load(Ordering::Acquire);
        while generation > current {
            match self.generation.compare_exchange_weak(
                current,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.invalidate_all();
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// 用一次 Redis 权威读取校准 generation，并允许 Redis 数据丢失后的代号回到较小值。
    ///
    /// `observed_before_read` 解决“旧 GET 晚于新 PURGE 返回”的竞态：若网络等待期间本地代号
    /// 已变化，只接受更大的结果；若未变化，则 Redis 返回的较小值代表事实源被 flush/重建，
    /// 必须清 L1 并采用它，否则节点会永久停留在其它节点不可见的旧命名空间。
    fn reconcile_generation(&self, observed_before_read: u64, authoritative: u64) {
        self.generation_loaded.store(true, Ordering::Release);
        match self.generation.compare_exchange(
            observed_before_read,
            authoritative,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(previous) => {
                if previous != authoritative {
                    self.invalidate_all();
                }
            }
            // Pub/Sub/PURGE 已在本次 Redis GET 等待期间推进本地代号。旧 GET 不能回滚它；
            // 仍复用单调应用逻辑，以便极少数情况下权威值更大时继续前进。
            Err(_) => self.apply_generation(authoritative),
        }
    }
}

/// L1 中保存的 post-filter、未压缩 HTTP 表示。
struct CachedResponse {
    /// 下游状态。
    status: StatusCode,
    /// 下游协议版本；发送时主连接协议仍由 Hyper 决定。
    version: Version,
    /// post-filter 响应头，不含动态压缩产生的 Content-Encoding。
    headers: HeaderMap,
    /// 有界收集后冻结的共享实体。
    body: Bytes,
    /// 上游已有 Age；本地驻留时间在命中时累加，不能覆盖掉共享缓存已经经历的年龄。
    initial_age_secs: u64,
    /// 用于生成 Age。
    stored_at: Instant,
    /// fresh 截止时刻；之后只有配置了 SWR 才可返旧。
    fresh_until: Instant,
    /// entry 最终回收时刻；Redis TTL 与 L1 手动淘汰都按它执行。
    stale_until: Instant,
}

/// 一条响应最终采用的新鲜期与 stale-while-revalidate 保留期。
#[derive(Clone, Copy)]
struct CacheLifetime {
    fresh: Duration,
    stale: Duration,
}

/// miss 回填 body wrapper。
///
/// 原始 frame 不 clone、不重建；只把 data bytes 复制进一个受 route `max_body_bytes` 限制的
/// BytesMut。缓存资格失效后立即释放 buffer，后续完全退化为透明 body。
struct CacheFillBody {
    /// 上一层 body（通常是 sub_filter 或原上游流）。
    inner: Pin<Box<BoxBody>>,
    /// route cache 与配置。
    policy: Arc<HttpCachePolicy>,
    /// 进程级 L2；只有 policy.l2_enabled 时提交任务会访问。
    runtime: Arc<SwappableHttpCacheRuntime>,
    /// L2 回填成功/失败计数器；Arc clone 不复制指标状态。
    metrics: Arc<Metrics>,
    /// EOF 提交时消费的 key。
    key: Option<String>,
    /// EOF 提交时消费的响应头快照。
    headers: Option<HeaderMap>,
    /// 缓存状态码。
    status: StatusCode,
    /// 缓存协议版本。
    version: Version,
    /// fresh 与 stale retention 窗口；均由 route 上限和上游 Cache-Control 共同约束。
    lifetime: CacheLifetime,
    /// 上游响应已经携带的共享缓存年龄。
    initial_age_secs: u64,
    /// 唯一的有界 payload 副本。
    buffer: BytesMut,
    /// 是否仍满足缓存资格。
    cacheable: bool,
    /// 内层 EOF 已处理。
    done: bool,
    /// EOF 时启动的 moka insert；下游 EOF 等它完成，保证紧随其后的请求稳定命中。
    commit_task: Option<tokio::task::JoinHandle<()>>,
    /// leader 身份保持到 L1 insert 完成；任意 error/cancel Drop 都会释放并唤醒 follower。
    flight: Option<CacheFlightLeader>,
}

impl CacheFillBody {
    /// 看到完整 EOF 后启动 moka 写入任务；Body 只 poll JoinHandle，不在同步 poll 内阻塞。
    /// 下游最终 EOF 等写入结束，保证“首个响应读完→立刻第二次 GET”稳定命中。
    fn start_commit(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        if !self.cacheable {
            return None;
        }
        let key = self.key.take()?;
        let mut headers = self.headers.take()?;
        let body = self.buffer.split().freeze();
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())
                .expect("usize content length is a valid header"),
        );
        let policy = self.policy.clone();
        let runtime = self.runtime.clone();
        let metrics = self.metrics.clone();
        #[cfg(feature = "redis-runtime")]
        let mut flight = self.flight.take();
        #[cfg(not(feature = "redis-runtime"))]
        let flight = self.flight.take();
        #[cfg(feature = "redis-runtime")]
        let distributed = flight
            .as_mut()
            .and_then(CacheFlightLeader::take_distributed);
        let l2_enabled = policy.l2_enabled;
        let lifetime = self.lifetime;
        let stored_at = Instant::now();
        let entry = CachedResponse {
            status: self.status,
            version: self.version,
            headers,
            body,
            initial_age_secs: self.initial_age_secs,
            stored_at,
            fresh_until: stored_at + lifetime.fresh,
            stale_until: stored_at + lifetime.fresh + lifetime.stale,
        };
        tracing::debug!(
            l2_enabled,
            body_bytes = entry.body.len(),
            "HTTP cache EOF commit started"
        );
        Some(tokio::spawn(async move {
            let l2_key = key.clone();
            let entry = policy.store.insert(key, entry).await;
            // L1 已可见后立即释放 leader；follower 醒来只 clone Arc/Bytes，不等待 Redis 网络。
            drop(flight);
            if l2_enabled {
                // 下游 EOF 只等待 L1 可见；L2 网络 I/O 单独派生，Redis 抖动不能延长业务响应。
                // Arc 只增加引用计数，body 仍与 L1 共用同一块 Bytes backing memory。跨节点 fill
                // lock 留在本任务直到 Redis SET 完成，防止远端醒来时 L2 尚不可见而重复回源。
                tokio::spawn(async move {
                    match runtime.store_l2(&l2_key, &entry).await {
                        Ok(()) => metrics.inc_http_cache_l2_store_ok(),
                        Err(error) => {
                            metrics.inc_http_cache_l2_store_error();
                            tracing::warn!(%error, "HTTP cache L2 fill failed; L1 remains valid");
                        }
                    }
                    #[cfg(feature = "redis-runtime")]
                    if let Some(guard) = distributed {
                        if let Err(error) = guard.unlock().await {
                            tracing::warn!(%error, "release HTTP cache distributed fill lock after store failed");
                        }
                    }
                });
            }
        }))
    }
}

impl Body for CacheFillBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(task) = self.commit_task.as_mut() {
            match Pin::new(task).poll(cx) {
                Poll::Ready(_) => {
                    self.commit_task = None;
                    self.done = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.trailers_ref().is_some() {
                    // 基础 L1 不缓存 trailers，避免命中时丢失语义；原 trailer frame 仍原样透传。
                    self.cacheable = false;
                    self.buffer.clear();
                } else if let Some(data) = frame.data_ref() {
                    if self.cacheable
                        && self.buffer.len().saturating_add(data.len())
                            <= self.policy.max_body_bytes
                    {
                        // 这是 cache opt-in 慢路径唯一 payload copy；原 frame 仍原样返回给下游。
                        self.buffer.extend_from_slice(data);
                    } else if self.cacheable {
                        self.cacheable = false;
                        self.buffer.clear();
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.cacheable = false;
                self.buffer.clear();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.commit_task = self.start_commit();
                if self.commit_task.is_some() {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    self.done = true;
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        // 不向 Hyper 暴露内层 exact size。即使上面移除了 Content-Length，Hyper 仍会依据
        // exact SizeHint 自动补回该头，并可能在写满后直接 drop body、永远不给包装层一次 EOF poll。
        // unknown hint 只改变 miss 的 wire framing，不触碰 data frame；这是保证“仅完整响应可回填”
        // 所必需的协议约束。命中路径使用 Full<Bytes>，仍会自然提供 exact size / Content-Length。
        SizeHint::default()
    }
}

/// 增量 hash 一个 key 字段。长度使用固定端序 u64，因此 `a|bc` 与 `ab|c` 不会碰撞。
fn hash_key_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// 把 32-byte SHA-256 摘要转成固定 64-byte 小写 hex；只分配最终 key 一次。
fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 按 storage key 确定性缩短 fresh TTL，分散不同 key 的集中失效时间。
///
/// 只缩短、不延长上游/route TTL；至少保留 1ms。相同 key 在所有节点得到相同结果，避免 L1/L2
/// freshness 撕裂；同 key 的热点过期仍由本地 + Redis single-flight 合并。
fn jitter_fresh_ttl(fresh: Duration, storage_key: &str, percent: u8) -> Duration {
    if percent == 0 {
        return fresh;
    }
    let fresh_ms = fresh.as_millis().min(u64::MAX as u128) as u64;
    if fresh_ms <= 1 {
        return fresh;
    }
    let max_reduction = fresh_ms
        .saturating_mul(percent as u64)
        .checked_div(100)
        .unwrap_or(0)
        .min(fresh_ms - 1);
    if max_reduction == 0 {
        return fresh;
    }
    let digest = Sha256::digest(storage_key.as_bytes());
    let seed = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    fresh.saturating_sub(Duration::from_millis(seed % (max_reduction + 1)))
}

/// query pair 的原始参数名（不做 percent decode，保持 wire 语义）。
fn query_name(pair: &str) -> &str {
    pair.split_once('=').map(|(name, _)| name).unwrap_or(pair)
}

/// proxy/route 身份摘要。route id 不直接进入 Redis key，限制 key 长度并避免运维命名泄露。
fn cache_scope(proxy_id: &str, route_id: &str) -> String {
    let mut hasher = Sha256::new();
    hash_key_part(&mut hasher, proxy_id.as_bytes());
    hash_key_part(&mut hasher, route_id.as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

/// 把 route generation 加入 data key。PURGE 只推进 generation，无需 SCAN/批量 DEL。
fn storage_key(scope: &str, generation: u64, digest: &str) -> String {
    format!("{scope}:{generation}:{digest}")
}

#[cfg(feature = "redis-runtime")]
fn generation_redis_key(prefix: &str, scope: &str) -> String {
    format!("{prefix}:gen:{scope}")
}

#[cfg(feature = "redis-runtime")]
fn data_redis_key(prefix: &str, storage_key: &str) -> String {
    format!("{prefix}:data:{storage_key}")
}

/// LLM exact/index keys share the same Redis Cluster hash tag so future atomic maintenance scripts
/// remain legal. `scope` is a SHA-256 hex digest produced by the gateway, never user plaintext。
#[cfg(feature = "redis-runtime")]
fn llm_exact_redis_key(prefix: &str, scope: &str, digest: &str) -> String {
    format!("{prefix}:llm:{{{scope}}}:exact:{digest}")
}

#[cfg(feature = "redis-runtime")]
fn llm_index_redis_key(prefix: &str, scope: &str) -> String {
    format!("{prefix}:llm:{{{scope}}}:semantic")
}

/// 请求端显式要求 revalidate/no-store 时绕过共享缓存，保证条件语义交给真实上游/静态服务。
fn request_forces_revalidation(headers: &HeaderMap) -> bool {
    for value in headers.get_all(CACHE_CONTROL) {
        let Ok(raw) = value.to_str() else {
            return true;
        };
        for directive in raw.split(',').map(str::trim) {
            if directive.eq_ignore_ascii_case("no-cache")
                || directive.eq_ignore_ascii_case("no-store")
                || directive.split_once('=').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("max-age")
                        && value.trim().trim_matches('"') == "0"
                })
            {
                return true;
            }
        }
    }
    headers.get_all(PRAGMA).iter().any(|value| {
        value
            .to_str()
            .map(|raw| {
                raw.split(',')
                    .any(|directive| directive.trim().eq_ignore_ascii_case("no-cache"))
            })
            .unwrap_or(true)
    })
}

/// 计算收到响应时的初始共享缓存年龄。
///
/// `Age` 只接受一个合法无符号秒数；同时用 `Date` 推导 apparent age 并取较大者，防止旧响应
/// 通过缺失/过小 Age 获得一整段新鲜期。缓存副本移除原 Age，命中时写累计值。
fn take_initial_age(headers: &mut HeaderMap) -> Option<u64> {
    let mut age = None;
    for value in headers.get_all(AGE) {
        if age.is_some() {
            return None;
        }
        age = Some(value.to_str().ok()?.trim().parse::<u64>().ok()?);
    }
    headers.remove(AGE);
    let apparent = headers
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| httpdate::parse_http_date(raw).ok())
        .and_then(|date| std::time::SystemTime::now().duration_since(date).ok())
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    Some(age.unwrap_or(0).max(apparent))
}

/// 构造命中响应。GET body 的 `Bytes::clone` 只增引用计数；HEAD/304 使用空共享 body。
///
/// 条件判断发生在 cache hit 内，If-None-Match 优先于 If-Modified-Since；未命中缓存时原请求
/// 仍完整转给上游。这样既保留验证器语义，也不把条件 header 错误纳入表示 key。
fn response_from_entry(entry: &CachedResponse, request: &Parts) -> Response<BoxBody> {
    if cached_not_modified(entry, request) {
        return not_modified_from_entry(entry);
    }
    let body = if request.method == Method::HEAD {
        Bytes::new()
    } else {
        entry.body.clone()
    };
    let mut response = Response::new(full_body(body));
    *response.status_mut() = entry.status;
    *response.version_mut() = entry.version;
    *response.headers_mut() = entry.headers.clone();
    insert_current_age(response.headers_mut(), entry);
    response.extensions_mut().insert(HttpCacheHit);
    response
}

/// 判断缓存验证器是否满足 GET/HEAD 的条件请求。
fn cached_not_modified(entry: &CachedResponse, request: &Parts) -> bool {
    if request.headers.contains_key(IF_NONE_MATCH) {
        let Some(current) = entry
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        return request.headers.get_all(IF_NONE_MATCH).iter().any(|value| {
            value
                .to_str()
                .map(|raw| etag_list_matches(raw, current))
                .unwrap_or(false)
        });
    }

    let Some(since) = request
        .headers
        .get(IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| httpdate::parse_http_date(raw).ok())
    else {
        return false;
    };
    entry
        .headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| httpdate::parse_http_date(raw).ok())
        .is_some_and(|modified| modified <= since)
}

/// 解析 If-None-Match 列表并执行 RFC 弱比较。
///
/// opaque-tag 合法字符包含逗号，因此不能直接 `split(',')`；这里只在双引号外识别列表分隔符，
/// 全程借用原 header 字节，不构造 token Vec/String。
fn etag_list_matches(raw: &str, current: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut start = 0usize;
    let mut quoted = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                if weak_etag_matches(raw[start..index].trim(), current) {
                    return true;
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    weak_etag_matches(raw[start..].trim(), current)
}

/// GET/HEAD 的 If-None-Match 使用弱比较：忽略双方可选 `W/`，opaque-tag 必须逐字节一致。
fn weak_etag_matches(candidate: &str, current: &str) -> bool {
    if candidate == "*" {
        return true;
    }
    fn opaque(tag: &str) -> Option<&str> {
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        (tag.len() >= 2 && tag.starts_with('"') && tag.ends_with('"')).then_some(tag)
    }
    matches!((opaque(candidate), opaque(current)), (Some(left), Some(right)) if left == right)
}

/// 从缓存 entry 构造无 body 的 304，只保留 RFC 要求重新生成/转发的表示元数据。
fn not_modified_from_entry(entry: &CachedResponse) -> Response<BoxBody> {
    let mut response = Response::new(full_body(Bytes::new()));
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    *response.version_mut() = entry.version;
    for name in [
        CACHE_CONTROL,
        CONTENT_LOCATION,
        DATE,
        ETAG,
        EXPIRES,
        LAST_MODIFIED,
        VARY,
    ] {
        for value in entry.headers.get_all(&name) {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }
    insert_current_age(response.headers_mut(), entry);
    response.extensions_mut().insert(HttpCacheHit);
    response
}

/// 写入累计 Age。u64 的十进制始终是合法 header；保底分支只防依赖 API 行为变化。
fn insert_current_age(headers: &mut HeaderMap, entry: &CachedResponse) {
    let age = entry
        .initial_age_secs
        .saturating_add(entry.stored_at.elapsed().as_secs());
    headers.insert(
        AGE,
        HeaderValue::from_str(&age.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
}

/// response header 数量/字节预算。上游异常 header 不得借 cache 把内存放大到每个 entry。
fn cache_headers_within_budget(headers: &HeaderMap) -> bool {
    if headers.len() > MAX_CACHE_HEADER_COUNT {
        return false;
    }
    headers
        .iter()
        .try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
        })
        .is_some_and(|bytes| bytes <= MAX_CACHE_HEADER_BYTES)
}

/// 编码 L2 entry。格式是自描述的有界二进制，不用 JSON/base64 把 body 膨胀 33% 以上。
#[cfg(any(feature = "redis-runtime", test))]
fn encode_cached_response(entry: &CachedResponse) -> Result<Bytes> {
    anyhow::ensure!(
        cache_headers_within_budget(&entry.headers),
        "cache headers exceed budget"
    );
    anyhow::ensure!(
        entry.body.len() <= u32::MAX as usize,
        "cache body exceeds wire format"
    );
    let header_bytes = entry
        .headers
        .iter()
        .try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(2 + 4)?
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
        })
        .context("cache header size overflow")?;
    let fixed: usize = 4 + 1 + 2 + 1 + 8 + 8 + 8 + 2 + 4 + 4;
    let capacity = fixed
        .checked_add(header_bytes)
        .and_then(|size| size.checked_add(entry.body.len()))
        .context("cache entry size overflow")?;
    let fresh_ttl_ms = entry
        .fresh_until
        .saturating_duration_since(entry.stored_at)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let retention_ttl_ms = entry
        .stale_until
        .saturating_duration_since(entry.stored_at)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    anyhow::ensure!(fresh_ttl_ms > 0, "cache fresh TTL must be positive");
    anyhow::ensure!(
        retention_ttl_ms >= fresh_ttl_ms,
        "cache retention precedes fresh TTL"
    );
    let mut out = BytesMut::with_capacity(capacity);
    out.extend_from_slice(CACHE_ENTRY_MAGIC);
    out.extend_from_slice(&[CACHE_ENTRY_VERSION]);
    out.extend_from_slice(&entry.status.as_u16().to_be_bytes());
    out.extend_from_slice(&[encode_http_version(entry.version)?]);
    out.extend_from_slice(&fresh_ttl_ms.to_be_bytes());
    out.extend_from_slice(&retention_ttl_ms.to_be_bytes());
    // original retention 与 Redis PTTL 的差会在解码端还原完整驻留时间（含异步 SET 前延迟）；
    // 此处只能写原始 Age。若再加 stored_at.elapsed，会在解码后把 SET 前延迟重复计算两次。
    out.extend_from_slice(&entry.initial_age_secs.to_be_bytes());
    out.extend_from_slice(&(entry.headers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(header_bytes as u32).to_be_bytes());
    out.extend_from_slice(&(entry.body.len() as u32).to_be_bytes());
    for (name, value) in &entry.headers {
        anyhow::ensure!(
            name.as_str().len() <= u16::MAX as usize,
            "cache header name too long"
        );
        anyhow::ensure!(
            value.as_bytes().len() <= u32::MAX as usize,
            "cache header value too long"
        );
        out.extend_from_slice(&(name.as_str().len() as u16).to_be_bytes());
        out.extend_from_slice(&(value.as_bytes().len() as u32).to_be_bytes());
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    // Redis string 需要连续内存，所以 L2 回填在这里复制一次 body；L1/下游不复制。
    out.extend_from_slice(&entry.body);
    Ok(out.freeze())
}

/// 计算一条 L2 二进制记录允许占用的最大 wire bytes。
///
/// 固定头、每个 header 的长度前缀和 route body 上限都使用 checked arithmetic；配置即使被
/// 构造到 `usize` 边界也只会拒绝，不能在控制面触发整数回绕。该值同时交给 Redis Lua 和本地
/// decoder，保证脏大值先在 Redis 内删除、不会先跨网络分配再发现超限。
#[cfg(any(feature = "redis-runtime", test))]
fn max_cache_wire_bytes(max_body_bytes: usize) -> Result<usize> {
    (4usize + 1 + 2 + 1 + 8 + 8 + 8 + 2 + 4 + 4)
        .checked_add(MAX_CACHE_HEADER_BYTES + MAX_CACHE_HEADER_COUNT * 6)
        .and_then(|size| size.checked_add(max_body_bytes))
        .context("cache decode limit overflow")
}

/// 解码 L2 entry。Redis `Vec<u8> -> Bytes` 接管分配，header value 与 body 均用 slice 共享它。
#[cfg(any(feature = "redis-runtime", test))]
fn decode_cached_response(
    raw: Bytes,
    redis_remaining: Duration,
    max_body_bytes: usize,
) -> Result<CachedResponse> {
    let max_wire = max_cache_wire_bytes(max_body_bytes)?;
    anyhow::ensure!(
        raw.len() <= max_wire,
        "cache L2 value exceeds route byte budget"
    );
    let mut cursor = CacheCursor::new(raw);
    anyhow::ensure!(
        cursor.take(4)?.as_ref() == CACHE_ENTRY_MAGIC,
        "unknown cache entry magic"
    );
    anyhow::ensure!(
        cursor.u8()? == CACHE_ENTRY_VERSION,
        "unsupported cache entry version"
    );
    let status = StatusCode::from_u16(cursor.u16()?).context("invalid cached status")?;
    let version = decode_http_version(cursor.u8()?)?;
    let fresh_ttl = Duration::from_millis(cursor.u64()?);
    let retention_ttl = Duration::from_millis(cursor.u64()?);
    anyhow::ensure!(!fresh_ttl.is_zero(), "cached fresh TTL is zero");
    anyhow::ensure!(
        fresh_ttl <= MAX_CACHE_RETENTION && retention_ttl <= MAX_CACHE_RETENTION,
        "cached TTL exceeds protocol limit"
    );
    anyhow::ensure!(
        retention_ttl >= fresh_ttl,
        "cached retention precedes fresh TTL"
    );
    let initial_age_secs = cursor.u64()?;
    let header_count = cursor.u16()? as usize;
    let declared_header_bytes = cursor.u32()? as usize;
    let body_len = cursor.u32()? as usize;
    anyhow::ensure!(
        header_count <= MAX_CACHE_HEADER_COUNT,
        "cached header count exceeds limit"
    );
    anyhow::ensure!(
        declared_header_bytes <= MAX_CACHE_HEADER_BYTES + header_count * 6,
        "cached header bytes exceed limit"
    );
    anyhow::ensure!(
        body_len <= max_body_bytes,
        "cached body exceeds route limit"
    );
    let header_start = cursor.position();
    let mut headers = HeaderMap::with_capacity(header_count);
    for _ in 0..header_count {
        let name_len = cursor.u16()? as usize;
        let value_len = cursor.u32()? as usize;
        let name_bytes = cursor.take(name_len)?;
        let value_bytes = cursor.take(value_len)?;
        let name = HeaderName::from_bytes(&name_bytes).context("invalid cached header name")?;
        // HeaderValue 接管 Bytes slice，不把大 header value 再复制一份。
        let value =
            HeaderValue::from_maybe_shared(value_bytes).context("invalid cached header value")?;
        headers.append(name, value);
    }
    anyhow::ensure!(
        cursor.position().saturating_sub(header_start) == declared_header_bytes,
        "cached header length mismatch"
    );
    let body = cursor.take(body_len)?;
    anyhow::ensure!(cursor.remaining() == 0, "trailing bytes in cache entry");
    if let Some(length) = headers.get(CONTENT_LENGTH) {
        let declared = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        anyhow::ensure!(declared == Some(body_len), "cached Content-Length mismatch");
    }
    let remaining = redis_remaining.min(retention_ttl);
    anyhow::ensure!(!remaining.is_zero(), "cached entry already expired");
    let elapsed = retention_ttl.saturating_sub(remaining);
    let fresh_remaining = fresh_ttl.saturating_sub(elapsed);
    let now = Instant::now();
    let fresh_until = now
        .checked_add(fresh_remaining)
        .context("cached fresh deadline overflows Instant")?;
    let stale_until = now
        .checked_add(remaining)
        .context("cached stale deadline overflows Instant")?;
    Ok(CachedResponse {
        status,
        version,
        headers,
        body,
        initial_age_secs,
        stored_at: now.checked_sub(elapsed).unwrap_or(now),
        fresh_until,
        stale_until,
    })
}

#[cfg(any(feature = "redis-runtime", test))]
fn encode_http_version(version: Version) -> Result<u8> {
    match version {
        Version::HTTP_09 => Ok(0),
        Version::HTTP_10 => Ok(1),
        Version::HTTP_11 => Ok(2),
        Version::HTTP_2 => Ok(3),
        Version::HTTP_3 => Ok(4),
        other => anyhow::bail!("unsupported cached HTTP version {other:?}"),
    }
}

#[cfg(any(feature = "redis-runtime", test))]
fn decode_http_version(encoded: u8) -> Result<Version> {
    match encoded {
        0 => Ok(Version::HTTP_09),
        1 => Ok(Version::HTTP_10),
        2 => Ok(Version::HTTP_11),
        3 => Ok(Version::HTTP_2),
        4 => Ok(Version::HTTP_3),
        other => anyhow::bail!("unsupported cached HTTP version byte {other}"),
    }
}

/// 只前移索引的 Bytes reader；所有 `take` 返回 slice，共享 Redis GET 的唯一 allocation。
#[cfg(any(feature = "redis-runtime", test))]
struct CacheCursor {
    raw: Bytes,
    position: usize,
}

#[cfg(any(feature = "redis-runtime", test))]
impl CacheCursor {
    fn new(raw: Bytes) -> Self {
        Self { raw, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> usize {
        self.raw.len().saturating_sub(self.position)
    }

    fn take(&mut self, len: usize) -> Result<Bytes> {
        let end = self
            .position
            .checked_add(len)
            .context("cache cursor overflow")?;
        anyhow::ensure!(end <= self.raw.len(), "truncated cache entry");
        let bytes = self.raw.slice(self.position..end);
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

#[cfg(feature = "redis-runtime")]
fn find_cache_policy(
    snapshot: &GatewaySnapshot,
    proxy_id: &str,
    route_id: &str,
) -> Option<Arc<HttpCachePolicy>> {
    snapshot
        .proxy(proxy_id)?
        .router
        .route_by_id(route_id)?
        .http_cache
        .clone()
}

/// 解析共享缓存新鲜期；禁止存储指令或坏 max-age 都 fail-safe 跳过缓存。
///
/// # 参数
/// - `headers`: post-filter 响应头。
/// - `configured`: route 配置 TTL；上游声明只能缩短、不能放大它。
fn cache_control_lifetime(
    headers: &HeaderMap,
    configured: Duration,
    configured_stale: Duration,
) -> Option<CacheLifetime> {
    let mut max_age = None;
    let mut shared_max_age = None;
    let mut upstream_stale = None;
    let mut forbid_stale = false;
    for value in headers.get_all(CACHE_CONTROL) {
        let raw = value.to_str().ok()?;
        for directive in raw.split(',').map(str::trim) {
            let (name, value) = directive
                .split_once('=')
                .map(|(name, value)| (name.trim(), Some(value.trim().trim_matches('"'))))
                .unwrap_or((directive, None));
            if name.eq_ignore_ascii_case("no-store")
                || name.eq_ignore_ascii_case("private")
                || name.eq_ignore_ascii_case("no-cache")
            {
                return None;
            }
            if name.eq_ignore_ascii_case("s-maxage") {
                let parsed = value?.parse::<u64>().ok()?;
                shared_max_age = Some(shared_max_age.map_or(parsed, |old: u64| old.min(parsed)));
            } else if name.eq_ignore_ascii_case("max-age") {
                let parsed = value?.parse::<u64>().ok()?;
                max_age = Some(max_age.map_or(parsed, |old: u64| old.min(parsed)));
            } else if name.eq_ignore_ascii_case("stale-while-revalidate") {
                let parsed = value?.parse::<u64>().ok()?;
                upstream_stale = Some(upstream_stale.map_or(parsed, |old: u64| old.min(parsed)));
            } else if name.eq_ignore_ascii_case("must-revalidate")
                || name.eq_ignore_ascii_case("proxy-revalidate")
            {
                forbid_stale = true;
            }
        }
    }
    let upstream = shared_max_age.or(max_age).map(Duration::from_secs);
    let ttl = upstream
        .map(|ttl| ttl.min(configured))
        .unwrap_or(configured);
    if ttl.is_zero() {
        return None;
    }
    let stale = if forbid_stale {
        Duration::ZERO
    } else {
        upstream_stale
            .map(Duration::from_secs)
            .map(|upstream| upstream.min(configured_stale))
            .unwrap_or(configured_stale)
    };
    Some(CacheLifetime { fresh: ttl, stale })
}

/// 判断响应 Vary 是否完全被 key 覆盖；Accept-Encoding 因缓存未压缩实体而特殊允许。
fn response_vary_is_covered(headers: &HeaderMap, configured: &[HeaderName]) -> bool {
    headers.get_all(VARY).iter().all(|value| {
        value
            .to_str()
            .map(|raw| {
                raw.split(',').all(|name| {
                    let name = name.trim();
                    !name.is_empty()
                        && name != "*"
                        && (name.eq_ignore_ascii_case("accept-encoding")
                            || configured
                                .iter()
                                .any(|item| item.as_str().eq_ignore_ascii_case(name)))
                })
            })
            .unwrap_or(false)
    })
}

/// 判断上游是否已经带非 identity 内容编码；L1 基础版只存未压缩实体。
fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_ENCODING).iter().any(|value| {
        value
            .to_str()
            .map(|raw| {
                raw.split(',').any(|coding| {
                    let coding = coding.trim();
                    !coding.is_empty() && !coding.eq_ignore_ascii_case("identity")
                })
            })
            .unwrap_or(true)
    })
}
