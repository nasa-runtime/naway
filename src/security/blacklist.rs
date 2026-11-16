//! 动态 IP 黑名单缓存。
//!
//! DynamicStore 是低频事实源；数据面只读本地地址与期限快照，避免请求期访问 Redis/文件。

use std::collections::{HashMap, VecDeque};
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
use crate::runtime::state::{DynamicStore, SwappableDynamicStore};

const MIN_REFRESH_INTERVAL_MS: u64 = 250;
/// 所有黑名单本地 timer 的安全上限；一年已经远超正常封禁/豁免窗口，同时避免外部
/// `u64` 极值越过平台 `Instant` 可表示范围。
const MAX_BLACKLIST_DURATION_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

/// 黑名单 ban/unban 审计事件(审计每次 ban/unban 的 who/when/why/source)。
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

/// 黑名单本地快照：精确 IP 走 O(1) 哈希查询；CIDR 段走小规模线性扫描。
///
/// 精确 IP 与 CIDR 分开存储，保证网段封禁不会因按单 IP 解析而失效。
/// 高频单 IP 命中保持 O(1)，少量 CIDR 使用线性扫描，不增加普通哈希查找的成本。
#[derive(Default)]
pub struct BlacklistEntries {
    /// 精确单 IP,O(1) 命中。
    ips: HashMap<IpAddr, Option<i64>>,
    /// CIDR 网段，构建期已解析成位比较结构，运行期零分配匹配。
    cidrs: Vec<(crate::io::net::Cidr, Option<i64>)>,
}

impl BlacklistEntries {
    /// 业务作用：返回快照保存的条目数；请求命中时另行复验到期时间。
    pub fn len(&self) -> usize {
        self.ips.len() + self.cidrs.len()
    }

    /// 业务作用：是否为空。
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.cidrs.is_empty()
    }

    /// 业务作用：判定仍在有效期内的地址封禁，不依赖后台刷新及时到达。
    ///
    /// 参数说明：
    /// - `ip`: 待检查的真实客户端 IP。
    ///
    /// 返回：存在永久或未到期的精确地址或网段封禁时为 true；重叠条目独立生效。
    fn contains(&self, ip: IpAddr) -> bool {
        let ip = crate::io::net::canonical_ip(ip);
        if self.is_empty() {
            return false;
        }
        let now_ms = unix_now_ms();
        self.ips
            .get(&ip)
            .is_some_and(|expiry| expiry.is_none_or(|until| until > now_ms))
            || self.cidrs.iter().any(|(cidr, expiry)| {
                expiry.is_none_or(|until| until > now_ms) && cidr.contains(ip)
            })
    }
}

/// 动态黑名单的无锁读缓存；刷新路径替换整张集合，数据面只做哈希查询。
pub struct BlacklistCache {
    enabled: AtomicBool,
    collection: RwLock<String>,
    refresh_interval_ms: AtomicU64,
    entries: ArcSwap<BlacklistEntries>,
    /// 配置、直接发布和刷新领取共用短锁；迟到读取不能覆盖后续撤销或新集合。
    publication: Mutex<Arc<()>>,
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
    /// 业务作用：按配置创建空缓存。
    ///
    /// 参数说明：
    /// - `cfg`: 黑名单及自动封禁配置。
    pub fn new(cfg: &BlacklistCfg) -> Result<Self> {
        validate_config(cfg)?;
        Ok(Self {
            enabled: AtomicBool::new(cfg.enabled),
            collection: RwLock::new(cfg.collection.clone()),
            refresh_interval_ms: AtomicU64::new(cfg.refresh_interval_ms),
            entries: ArcSwap::from_pointee(BlacklistEntries::default()),
            publication: Mutex::new(Arc::new(())),
            unban_exempt_ms: AtomicU64::new(cfg.auto_ban.unban_exempt_ms),
            exemptions: Mutex::new(HashMap::new()),
            audit: Mutex::new(VecDeque::new()),
            audit_seq: AtomicU64::new(0),
        })
    }

    /// 业务作用：原子应用新配置；禁用时同步清空数据面集合。
    ///
    /// 参数说明：
    /// - `cfg`: 已解析并待校验的新配置。
    ///
    /// 返回：合法配置立即撤销旧刷新权；禁用或更换集合时清空原快照，非法配置保留原状态。
    pub fn apply_config(&self, cfg: &BlacklistCfg) -> Result<()> {
        validate_config(cfg)?;
        // 先撤销已领取的刷新权，再改变集合；旧 I/O 即使完成也不能重新发布。
        let mut publication = self.publication.lock();
        *publication = Arc::new(());
        let changed_collection = *self.collection.read() != cfg.collection;
        *self.collection.write() = cfg.collection.clone();
        self.refresh_interval_ms
            .store(cfg.refresh_interval_ms, Ordering::Relaxed);
        self.unban_exempt_ms
            .store(cfg.auto_ban.unban_exempt_ms, Ordering::Relaxed);
        self.enabled.store(cfg.enabled, Ordering::Relaxed);
        if !cfg.enabled || changed_collection {
            self.entries.store(Arc::new(BlacklistEntries::default()));
            self.exemptions.lock().clear();
        }
        Ok(())
    }

    /// 业务作用：某 IP 当前是否处于解封豁免窗口内(auto-ban 应跳过它)。过期项顺带清理。
    ///
    /// 参数说明：
    /// - `ip`: 待判定的客户端 IP。
    pub fn is_exempt(&self, ip: IpAddr) -> bool {
        let ip = crate::io::net::canonical_ip(ip);
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

    /// 业务作用：记录一次拉黑审计(不改缓存,缓存由 store 刷新驱动)。
    ///
    /// 参数说明：
    /// - `ip`: 被拉黑 IP。
    /// - `source`: 来源(`auto_limit_req` / `admin`)。
    /// - `ttl_ms`: 拉黑 TTL。
    pub fn record_ban(&self, ip: IpAddr, source: &str, ttl_ms: u64) {
        self.push_audit("ban", ip, source, Some(ttl_ms));
    }

    /// 业务作用：记录一次解封审计,并(若配置了 `unban_exempt_ms`)对该 IP 设置本节点解封豁免窗口。
    ///
    /// 参数说明：
    /// - `ip`: 被解封 IP。
    /// - `source`: 来源(通常 `admin`)。
    pub fn record_unban(&self, ip: IpAddr, source: &str) {
        let ip = crate::io::net::canonical_ip(ip);
        let exempt_ms = self.unban_exempt_ms.load(Ordering::Relaxed);
        if exempt_ms > 0 {
            // validate_config 已限制时长；checked_add 继续防御不同平台 Instant 范围差异。
            if let Some(until) = Instant::now().checked_add(Duration::from_millis(exempt_ms)) {
                self.exemptions.lock().insert(ip, until);
            }
        }
        self.push_audit("unban", ip, source, None);
    }

    /// 业务作用：把封禁或撤销事件加入有界审计读面，保留原因与期限而不无限积累记录。
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

    /// 业务作用：返回本节点最近的 ban/unban 审计事件(按发生顺序)。
    pub fn audit_snapshot(&self) -> Vec<BlacklistAuditEvent> {
        self.audit.lock().iter().cloned().collect()
    }

    /// 业务作用：返回黑名单功能是否启用。
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 业务作用：返回当前动态存储集合名的快照。
    pub fn collection(&self) -> String {
        self.collection.read().clone()
    }

    /// 业务作用：在本地快照中判断 IP；不会访问外部存储。
    ///
    /// 参数说明：
    /// - `ip`: 待检查的客户端地址。
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.is_enabled() && self.entries.load().contains(ip)
    }

    /// 业务作用：用新集合替换当前快照，读者无需等待刷新锁。
    ///
    /// 参数说明：
    /// - `entries`: 已完成过期清理的精确 IP + CIDR 段集合。
    ///
    /// 返回：发布完整快照并撤销先前刷新权，不允许迟到读取覆盖本次发布。
    pub fn replace_entries(&self, entries: BlacklistEntries) {
        let mut publication = self.publication.lock();
        *publication = Arc::new(());
        self.entries.store(Arc::new(entries));
    }

    /// 业务作用：清空数据面黑名单快照。
    pub fn clear(&self) {
        self.replace_entries(BlacklistEntries::default());
    }

    /// 业务作用：从动态存储加载、过滤过期项并替换本地快照。
    ///
    /// 参数说明：
    /// - `store`: 动态存储事实源。
    /// - `collection`: 要读取的集合名。
    ///
    /// 返回：成功时返回当前缓存条目数；读取失败保留原快照，失去发布权时保留后续快照。
    pub async fn refresh_from_store(
        &self,
        store: &dyn DynamicStore,
        collection: &str,
    ) -> Result<usize> {
        let ticket = {
            let mut publication = self.publication.lock();
            if !self.is_enabled() || *self.collection.read() != collection {
                // 非当前集合没有发布资格，避免旧配置调用把另一来源的封禁带回。
                return Ok(self.entries.load().len());
            }
            *publication = Arc::new(());
            publication.clone()
        };
        let entries = load_blacklist_ips(store, collection).await?;
        let publication = self.publication.lock();
        if Arc::ptr_eq(&publication, &ticket) {
            // 撤销和新刷新领取都在同一锁下改变令牌，发布点复验封住迟到结果。
            self.entries.store(Arc::new(entries));
        }
        Ok(self.entries.load().len())
    }

    /// 业务作用：提供动态黑名单的后台对账周期，不让请求线程承担事实源轮询。
    fn refresh_interval(&self) -> Duration {
        let ms = self
            .refresh_interval_ms
            .load(Ordering::Relaxed)
            .max(MIN_REFRESH_INTERVAL_MS);
        Duration::from_millis(ms)
    }
}

/// 业务作用：校验黑名单配置及自动封禁参数之间的依赖关系。
///
/// 参数说明：
/// - `cfg`: 待校验配置。
///
/// 返回：启用依赖、至少一个拒绝门槛与所有期限合法时成功；非法声明拒绝候选，保留活动策略。
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
        && ((cfg.auto_ban.limit_req_rejections == 0
            && cfg.auto_ban.waf_rejections == 0
            && cfg.auto_ban.authentication_failures == 0
            && cfg.auto_ban.abnormal_rejections == 0)
            || cfg.auto_ban.window_ms == 0
            || cfg.auto_ban.ban_ttl_ms == 0)
    {
        anyhow::bail!(
            "runtime_state.blacklist.auto_ban requires a positive signal threshold, window_ms and ban_ttl_ms when enabled"
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

/// 业务作用：加载仍存在且未过期的封禁，并仅在值未变化时回收过期事实。
///
/// 参数说明：
/// - `store`: 动态存储事实源。
/// - `collection`: 黑名单集合名。
///
/// 返回：完整读取成功时返回带期限的地址快照；读取失败返回错误，不发布部分集合。
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
        ips: HashMap::with_capacity(keys.len()),
        cidrs: Vec::new(),
    };
    let now_ms = unix_now_ms();
    for key in keys {
        // 单 IP 与 CIDR 段统一按 `Cidr::parse` 解析:含 `/` → 网段,否则精确 IP(「CIDR 单 IP + 段」)。
        match crate::io::net::Cidr::parse(&key) {
            Ok(cidr) => {
                let Some(value) = store
                    .get(collection, &key)
                    .await
                    .with_context(|| format!("load blacklist entry `{collection}/{key}`"))?
                else {
                    // 枚举后被解封的键已经失去封禁事实，缺失值不能升级为永久条目。
                    continue;
                };
                let expiry = serde_json::from_slice::<BlacklistEntryMeta>(&value)
                    .ok()
                    .and_then(|meta| meta.expire_at_unix_ms);
                if expiry.is_some_and(|until| until <= now_ms) {
                    // 续期可能与对账并发；只有原值仍匹配时才有删除权。
                    if let Err(e) = store.delete_if_value(collection, &key, &value).await {
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
                        crate::io::net::Cidr::Single(ip) => {
                            // 等价地址声明叠加；另一条较短期限不能缩短永久或仍有效的封禁。
                            entries
                                .ips
                                .entry(ip)
                                .and_modify(|current| {
                                    *current = match (*current, expiry) {
                                        (Some(left), Some(right)) => Some(left.max(right)),
                                        _ => None,
                                    };
                                })
                                .or_insert(expiry);
                        }
                        cidr => entries.cidrs.push((cidr, expiry)),
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

/// 业务作用：撤销一个规范客户端地址的精确封禁，同时兼容已经持久化的 IPv4 映射地址键。
///
/// 参数说明：
/// - `store`：当前动态事实源。
/// - `collection`：封禁集合名称。
/// - `ip`：需要撤销的客户端地址，IPv4 与其映射 IPv6 表示等价。
///
/// 返回：相关精确键全部删除时成功；存储失败返回错误，前面的删除可能已提交，不自动回滚或重试。
/// 重叠 CIDR 是独立声明，不随单地址撤销删除。
pub async fn revoke_ip(store: &dyn DynamicStore, collection: &str, ip: IpAddr) -> Result<()> {
    let ip = crate::io::net::canonical_ip(ip);
    store.delete(collection, &ip.to_string()).await?;
    if let IpAddr::V4(address) = ip {
        // 既有节点曾使用映射地址的文本键，明确撤销同一来源时不能让该键继续阻断业务。
        store
            .delete(collection, &address.to_ipv6_mapped().to_string())
            .await?;
    }
    Ok(())
}

/// 业务作用：提供动态封禁有效期使用的 Unix 毫秒时间，时钟异常采用保守零值。
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

/// 业务作用：启动后台黑名单刷新任务；任务持续监听动态存储变更并定期兜底刷新。
///
/// 参数说明：
/// - `cache`: 数据面黑名单缓存。
/// - `store`: 可热切换的动态存储句柄。
///
/// 返回：后台任务句柄；完整刷新后发布缓存，读取失败保留原快照；此入口不关联连接注册表。
pub fn spawn_blacklist_refresh(
    cache: Arc<BlacklistCache>,
    store: Arc<SwappableDynamicStore>,
) -> tokio::task::JoinHandle<()> {
    spawn_blacklist_refresh_worker(cache, store, None)
}

/// 业务作用：同步动态封禁事实，并让共享事实源中的封禁关闭本机已有长连接。
///
/// 参数说明：
/// - `cache`：HTTP 和 stream 共用的本地封禁快照。
/// - `store`：可热切换的动态事实源。
/// - `connections`：本机受控连接注册表。
///
/// 返回：后台任务句柄；读取失败保留原快照，完整刷新后按当前有效封禁发出关闭信号。
pub fn spawn_blacklist_refresh_with_connections(
    cache: Arc<BlacklistCache>,
    store: Arc<SwappableDynamicStore>,
    connections: Arc<crate::runtime::connections::ConnectionRegistry>,
) -> tokio::task::JoinHandle<()> {
    spawn_blacklist_refresh_worker(cache, store, Some(Arc::downgrade(&connections)))
}

/// 业务作用：驱动订阅与定期对账，避免漏事件或更换事实源后残留旧封禁。
///
/// 参数说明：
/// - `cache`：本地完整封禁快照。
/// - `store`：运行期可切换的事实源。
/// - `connections`：可选弱连接注册表，不延长数据面生命周期。
///
/// 返回：后台任务句柄；新订阅先重读，配置通知撤销旧订阅，完整读取成功后才触发连接关闭。
fn spawn_blacklist_refresh_worker(
    cache: Arc<BlacklistCache>,
    store: Arc<SwappableDynamicStore>,
    connections: Option<std::sync::Weak<crate::runtime::connections::ConnectionRegistry>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watcher = None;
        let mut watched_collection = String::new();
        let mut watched_generation = 0;
        let mut registered = false;
        let mut refreshes = store.subscribe_refresh();
        loop {
            if !cache.is_enabled() {
                watcher = None;
                registered = false;
                tokio::select! {
                    _ = refreshes.changed() => {}
                    _ = tokio::time::sleep(cache.refresh_interval()) => {}
                }
                continue;
            }

            let collection = cache.collection();
            let generation = store.generation();
            let reason = if !registered
                || watched_collection != collection
                || watched_generation != generation
            {
                // 原来源已不再提供当前订阅资格，先释放其句柄和容量再建立新观察。
                drop(watcher.take());
                watcher = match store.watch(&collection).await {
                    Ok(next) => next,
                    Err(e) => {
                        tracing::warn!(collection, error = %e, "blacklist watch unavailable; fallback to interval refresh");
                        None
                    }
                };
                watched_collection = collection.clone();
                watched_generation = generation;
                registered = true;
                // 先建立订阅再完整重读，注册前已经发生的变更也不能漏到下一次对账。
                "watch-started"
            } else if let Some(watcher) = watcher.as_mut() {
                tokio::select! {
                    _ = refreshes.changed() => "configuration",
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
                tokio::select! {
                    _ = refreshes.changed() => "configuration",
                    _ = tokio::time::sleep(cache.refresh_interval()) => "interval",
                }
            };

            if reason == "watch-ended" || reason == "configuration" {
                // 原观察已经结束或失去来源身份，释放其句柄后再为当前配置建立新订阅。
                watcher = None;
                registered = false;
                continue;
            }
            if watcher.is_none() && reason == "interval" {
                registered = false;
                continue;
            }

            match cache.refresh_from_store(store.as_ref(), &collection).await {
                Ok(count) => {
                    // 外部发布和 CIDR 规则也必须影响既有会话；按当前缓存复验，不重放旧事件值。
                    if let Some(connections) =
                        connections.as_ref().and_then(|value| value.upgrade())
                    {
                        connections.close_blocked(&cache);
                    }
                    tracing::debug!(collection, count, reason, "blacklist cache refreshed");
                }
                Err(e) => {
                    tracing::warn!(collection, reason, error = %e, "blacklist refresh failed; keep last cache");
                }
            }
        }
    })
}

/// 业务作用：约束黑名单集合标识，避免动态配置突破后端命名空间。
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
