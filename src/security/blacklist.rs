//! 动态 IP 黑名单缓存。
//!
//! DynamicStore 是低频事实源;数据面热路径只读本地 `HashSet<IpAddr>`,避免请求期访问 Redis/文件。

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

/// 黑名单审计事件在内存中保留的最近条数上限。
const AUDIT_MAX_EVENTS: usize = 256;

use crate::config::model::BlacklistCfg;
use crate::runtime_state::{DynamicStore, SwappableDynamicStore};

const MIN_REFRESH_INTERVAL_MS: u64 = 250;
/// 所有黑名单本地 timer 的安全上限；一年已经远超正常封禁/豁免窗口，同时避免外部
/// `u64` 极值越过平台 `Instant` 可表示范围。
const MAX_BLACKLIST_DURATION_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

/// 黑名单 ban/unban 审计事件(§18:审计每次 ban/unban 的 who/when/why/source)。
#[derive(Clone, Serialize)]
pub struct BlacklistAuditEvent {
    /// 本节点单调事件号。
    pub id: u64,
    /// Unix epoch 毫秒。
    pub ts_ms: i64,
    /// 事件类型:`ban` 或 `unban`。
    pub kind: &'static str,
    /// 目标 IP。
    pub ip: String,
    /// 来源:`auto_limit_req`(自动拉黑)/ `admin`(手工)等。
    pub source: String,
    /// ban 事件的 TTL(ms);unban 无。
    pub ttl_ms: Option<u64>,
}

/// 黑名单本地快照:精确 IP 走 O(1) HashSet;CIDR 段走小规模线性扫描。
///
/// WHY 分两张表:§12/§18 要求「CIDR 单 IP + 段」都能封禁。早期实现只把 key 解析成 `IpAddr`、
/// CIDR key(如 `10.0.0.0/8`)解析失败被 debug 级静默丢弃 → 运维封一个网段实际是空操作,
/// 一个「以为生效」的安全控制悄悄什么都没做。这里精确 IP 仍走哈希 O(1)(封单 IP 是常态、量大),
/// CIDR 段数量少、线性扫描即可,不拖慢常态命中判定。
#[derive(Default)]
pub struct BlacklistEntries {
    /// 精确单 IP,O(1) 命中。
    ips: HashSet<IpAddr>,
    /// CIDR 网段,构建期已解析成位比较结构(§net),运行期零分配匹配。
    cidrs: Vec<crate::net::Cidr>,
}

impl BlacklistEntries {
    /// 有效条目总数(精确 IP + CIDR 段)。
    pub fn len(&self) -> usize {
        self.ips.len() + self.cidrs.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.cidrs.is_empty()
    }

    /// 判断 IP 是否命中黑名单:先查精确 IP(O(1)),再扫 CIDR 段。
    ///
    /// # 参数
    /// - `ip`: 待检查的真实客户端 IP。
    fn contains(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

/// 动态黑名单的无锁读缓存；刷新路径替换整张集合，数据面只做哈希查询。
pub struct BlacklistCache {
    enabled: AtomicBool,
    collection: RwLock<String>,
    refresh_interval_ms: AtomicU64,
    entries: ArcSwap<BlacklistEntries>,
    /// 解封后短期豁免窗口(ms);0 = 关闭。auto-ban 对窗口内 IP 直接跳过。
    unban_exempt_ms: AtomicU64,
    /// 本节点解封豁免表:ip -> 豁免截止时刻。仅手工解封写入,过期即失效。
    exemptions: Mutex<HashMap<IpAddr, Instant>>,
    /// 本节点 ban/unban 审计事件环形缓冲(供 `/admin/blacklist/audit` 查询)。
    audit: Mutex<VecDeque<BlacklistAuditEvent>>,
    /// 审计事件单调号。
    audit_seq: AtomicU64,
}

impl BlacklistCache {
    /// 按配置创建空缓存。
    ///
    /// # 参数
    /// - `cfg`: 黑名单及自动封禁配置。
    pub fn new(cfg: &BlacklistCfg) -> Result<Self> {
        validate_config(cfg)?;
        Ok(Self {
            enabled: AtomicBool::new(cfg.enabled),
            collection: RwLock::new(cfg.collection.clone()),
            refresh_interval_ms: AtomicU64::new(cfg.refresh_interval_ms),
            entries: ArcSwap::from_pointee(BlacklistEntries::default()),
            unban_exempt_ms: AtomicU64::new(cfg.auto_ban.unban_exempt_ms),
            exemptions: Mutex::new(HashMap::new()),
            audit: Mutex::new(VecDeque::new()),
            audit_seq: AtomicU64::new(0),
        })
    }

    /// 原子应用新配置；禁用时同步清空数据面集合。
    ///
    /// # 参数
    /// - `cfg`: 已解析并待校验的新配置。
    pub fn apply_config(&self, cfg: &BlacklistCfg) -> Result<()> {
        validate_config(cfg)?;
        *self.collection.write() = cfg.collection.clone();
        self.refresh_interval_ms
            .store(cfg.refresh_interval_ms, Ordering::Relaxed);
        self.unban_exempt_ms
            .store(cfg.auto_ban.unban_exempt_ms, Ordering::Relaxed);
        self.enabled.store(cfg.enabled, Ordering::Relaxed);
        if !cfg.enabled {
            self.clear();
        }
        Ok(())
    }

    /// 某 IP 当前是否处于解封豁免窗口内(auto-ban 应跳过它)。过期项顺带清理。
    ///
    /// # 参数
    /// - `ip`: 待判定的客户端 IP。
    pub fn is_exempt(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut exemptions = self.exemptions.lock();
        match exemptions.get(&ip) {
            Some(until) if *until > now => true,
            Some(_) => {
                exemptions.remove(&ip);
                false
            }
            None => false,
        }
    }

    /// 记录一次拉黑审计(不改缓存,缓存由 store 刷新驱动)。
    ///
    /// # 参数
    /// - `ip`: 被拉黑 IP。
    /// - `source`: 来源(`auto_limit_req` / `admin`)。
    /// - `ttl_ms`: 拉黑 TTL。
    pub fn record_ban(&self, ip: IpAddr, source: &str, ttl_ms: u64) {
        self.push_audit("ban", ip, source, Some(ttl_ms));
    }

    /// 记录一次解封审计,并(若配置了 `unban_exempt_ms`)对该 IP 设置本节点解封豁免窗口。
    ///
    /// # 参数
    /// - `ip`: 被解封 IP。
    /// - `source`: 来源(通常 `admin`)。
    pub fn record_unban(&self, ip: IpAddr, source: &str) {
        let exempt_ms = self.unban_exempt_ms.load(Ordering::Relaxed);
        if exempt_ms > 0 {
            // validate_config 已限制时长；checked_add 继续防御不同平台 Instant 范围差异。
            if let Some(until) = Instant::now().checked_add(Duration::from_millis(exempt_ms)) {
                self.exemptions.lock().insert(ip, until);
            }
        }
        self.push_audit("unban", ip, source, None);
    }

    fn push_audit(&self, kind: &'static str, ip: IpAddr, source: &str, ttl_ms: Option<u64>) {
        let id = self.audit_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut audit = self.audit.lock();
        audit.push_back(BlacklistAuditEvent {
            id,
            ts_ms: unix_now_ms(),
            kind,
            ip: ip.to_string(),
            source: source.to_string(),
            ttl_ms,
        });
        while audit.len() > AUDIT_MAX_EVENTS {
            audit.pop_front();
        }
    }

    /// 返回本节点最近的 ban/unban 审计事件(按发生顺序)。
    pub fn audit_snapshot(&self) -> Vec<BlacklistAuditEvent> {
        self.audit.lock().iter().cloned().collect()
    }

    /// 返回黑名单功能是否启用。
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 返回当前动态存储集合名的快照。
    pub fn collection(&self) -> String {
        self.collection.read().clone()
    }

    /// 在本地快照中判断 IP；不会访问外部存储。
    ///
    /// # 参数
    /// - `ip`: 待检查的客户端地址。
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.is_enabled() && self.entries.load().contains(ip)
    }

    /// 用新集合替换当前快照，读者无需等待刷新锁。
    ///
    /// # 参数
    /// - `entries`: 已完成过期清理的精确 IP + CIDR 段集合。
    pub fn replace_entries(&self, entries: BlacklistEntries) {
        self.entries.store(Arc::new(entries));
    }

    /// 清空数据面黑名单快照。
    pub fn clear(&self) {
        self.replace_entries(BlacklistEntries::default());
    }

    /// 从动态存储加载、过滤过期项并替换本地快照。
    ///
    /// # 参数
    /// - `store`: 动态存储事实源。
    /// - `collection`: 要读取的集合名。
    ///
    /// 返回本次加载的有效地址数量。
    pub async fn refresh_from_store(
        &self,
        store: &dyn DynamicStore,
        collection: &str,
    ) -> Result<usize> {
        let entries = load_blacklist_ips(store, collection).await?;
        let count = entries.len();
        self.replace_entries(entries);
        Ok(count)
    }

    fn refresh_interval(&self) -> Duration {
        let ms = self
            .refresh_interval_ms
            .load(Ordering::Relaxed)
            .max(MIN_REFRESH_INTERVAL_MS);
        Duration::from_millis(ms)
    }
}

/// 校验黑名单配置及自动封禁参数之间的依赖关系。
///
/// # 参数
/// - `cfg`: 待校验配置。
pub fn validate_config(cfg: &BlacklistCfg) -> Result<()> {
    validate_component(&cfg.collection, "blacklist.collection")?;
    if cfg.enabled && cfg.refresh_interval_ms == 0 {
        anyhow::bail!("runtime_state.blacklist.refresh_interval_ms must be positive when enabled");
    }
    if cfg.refresh_interval_ms > MAX_BLACKLIST_DURATION_MS {
        anyhow::bail!(
            "runtime_state.blacklist.refresh_interval_ms must be <= {MAX_BLACKLIST_DURATION_MS}"
        );
    }
    if cfg.auto_ban.enabled && !cfg.enabled {
        anyhow::bail!("runtime_state.blacklist.enabled must be true when auto_ban is enabled");
    }
    if cfg.auto_ban.enabled
        && (cfg.auto_ban.limit_req_rejections == 0
            || cfg.auto_ban.window_ms == 0
            || cfg.auto_ban.ban_ttl_ms == 0)
    {
        anyhow::bail!(
            "runtime_state.blacklist.auto_ban limit_req_rejections/window_ms/ban_ttl_ms must be positive when enabled"
        );
    }
    if cfg.auto_ban.window_ms > MAX_BLACKLIST_DURATION_MS
        || cfg.auto_ban.ban_ttl_ms > MAX_BLACKLIST_DURATION_MS
        || cfg.auto_ban.unban_exempt_ms > MAX_BLACKLIST_DURATION_MS
    {
        anyhow::bail!(
            "runtime_state.blacklist auto-ban durations must be <= {MAX_BLACKLIST_DURATION_MS}ms"
        );
    }
    Ok(())
}

/// 从动态存储加载未过期的 IP，并删除已过期条目。
///
/// # 参数
/// - `store`: 动态存储事实源。
/// - `collection`: 黑名单集合名。
pub async fn load_blacklist_ips(
    store: &dyn DynamicStore,
    collection: &str,
) -> Result<BlacklistEntries> {
    validate_component(collection, "blacklist.collection")?;
    let keys = store
        .list_keys(collection)
        .await
        .with_context(|| format!("load blacklist collection `{collection}`"))?;
    let mut entries = BlacklistEntries {
        ips: HashSet::with_capacity(keys.len()),
        cidrs: Vec::new(),
    };
    let now_ms = unix_now_ms();
    for key in keys {
        // 单 IP 与 CIDR 段统一按 `Cidr::parse` 解析:含 `/` → 网段,否则精确 IP(§18「CIDR 单 IP + 段」)。
        match crate::net::Cidr::parse(&key) {
            Ok(cidr) => {
                let value = store
                    .get(collection, &key)
                    .await
                    .with_context(|| format!("load blacklist entry `{collection}/{key}`"))?;
                if entry_expired(value.as_deref(), now_ms) {
                    if let Err(e) = store.delete(collection, &key).await {
                        tracing::warn!(
                            collection,
                            key = %key,
                            error = %e,
                            "delete expired blacklist entry failed"
                        );
                    }
                } else {
                    // 精确单 IP 进哈希表(O(1) 命中),真正的网段进 CIDR 表(线性扫描)。
                    match cidr {
                        crate::net::Cidr::Single(ip) => {
                            entries.ips.insert(ip);
                        }
                        cidr => entries.cidrs.push(cidr),
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    collection,
                    key = %key,
                    error = %e,
                    "ignore invalid dynamic blacklist entry"
                );
            }
        }
    }
    Ok(entries)
}

#[derive(Deserialize)]
struct BlacklistEntryMeta {
    #[serde(default)]
    expire_at_unix_ms: Option<i64>,
}

fn entry_expired(value: Option<&[u8]>, now_ms: i64) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Ok(meta) = serde_json::from_slice::<BlacklistEntryMeta>(value) else {
        return false;
    };
    meta.expire_at_unix_ms
        .map(|expire_at| expire_at <= now_ms)
        .unwrap_or(false)
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

/// 启动后台黑名单刷新任务；任务持续监听动态存储变更并定期兜底刷新。
///
/// # 参数
/// - `cache`: 数据面黑名单缓存。
/// - `store`: 可热切换的动态存储句柄。
pub fn spawn_blacklist_refresh(
    cache: Arc<BlacklistCache>,
    store: Arc<SwappableDynamicStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watcher = None;
        let mut watched_collection = String::new();
        let mut watched_generation = 0;
        loop {
            if !cache.is_enabled() {
                watcher = None;
                tokio::time::sleep(cache.refresh_interval()).await;
                continue;
            }

            let collection = cache.collection();
            let generation = store.generation();
            if watcher.is_none()
                || watched_collection != collection
                || watched_generation != generation
            {
                watcher = match store.watch(&collection).await {
                    Ok(next) => next,
                    Err(e) => {
                        tracing::warn!(collection, error = %e, "blacklist watch unavailable; fallback to interval refresh");
                        None
                    }
                };
                watched_collection = collection.clone();
                watched_generation = generation;
            }

            let reason = if let Some(watcher) = watcher.as_mut() {
                tokio::select! {
                    changed = watcher.recv() => {
                        match changed {
                            Some(change) => {
                                tracing::debug!(
                                    collection = %change.collection,
                                    key = %change.key,
                                    kind = ?change.kind,
                                    "blacklist dynamic store change received"
                                );
                                "event"
                            }
                            None => "watch-ended",
                        }
                    }
                    _ = tokio::time::sleep(cache.refresh_interval()) => "interval",
                }
            } else {
                tokio::time::sleep(cache.refresh_interval()).await;
                "interval"
            };

            if reason == "watch-ended" {
                watcher = None;
                continue;
            }

            match cache.refresh_from_store(store.as_ref(), &collection).await {
                Ok(count) => {
                    tracing::debug!(collection, count, reason, "blacklist cache refreshed");
                }
                Err(e) => {
                    tracing::warn!(collection, reason, error = %e, "blacklist refresh failed; keep last cache");
                }
            }
        }
    })
}

fn validate_component(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || value == "."
        || value == ".."
        || std::path::Path::new(value).components().count() != 1
    {
        anyhow::bail!("invalid dynamic {name} `{value}`");
    }
    Ok(())
}
