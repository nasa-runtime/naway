//! 接口级拦截。
//!
//! 独立 `interface-guard.yml` 配「某接口对外禁止服务」,网关在管线**最前**一步命中即**直接返回配置的 response**,
//! 不进路由/鉴权/上游。规则 = match(path glob + methods)→ response(status + headers + body)。

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use globset::{Glob, GlobMatcher};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use hyper::Response;
use parking_lot::RwLock;
use serde::Deserialize;

use crate::config::model::{
    GuardFile, GuardMatchCfg, GuardMatchType, GuardRuleCfg, InterfaceDisableCfg, RespCfg,
};
use crate::runtime::state::{DynamicStore, SwappableDynamicStore};
use crate::{full_body, BoxBody};

/// 编译后的直接响应模板。
#[derive(Clone)]
pub struct RespTemplate {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl RespTemplate {
    /// 业务作用：在构建期验证守卫短路响应的状态、头部与正文，避免拒绝路径产生无效 HTTP。
    fn compile(cfg: &RespCfg) -> Result<Self> {
        let status = StatusCode::from_u16(cfg.status)
            .with_context(|| format!("invalid status {}", cfg.status))?;
        let mut headers = HeaderMap::new();
        for (k, v) in &cfg.headers {
            let name =
                HeaderName::from_str(k).with_context(|| format!("invalid header name `{k}`"))?;
            let val =
                HeaderValue::from_str(v).with_context(|| format!("invalid header value `{v}`"))?;
            headers.insert(name, val);
        }
        Ok(Self {
            status,
            headers,
            body: Bytes::from(cfg.body.clone().into_bytes()),
        })
    }

    /// 业务作用：默认响应:503 + 纯文本(未配 default_response / 规则 response 时兜底)。
    fn service_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"service unavailable"),
        }
    }

    /// 业务作用：构造下游响应(body 是引用计数 `Bytes`,clone 只加计数不拷内存)。
    pub fn to_response(&self) -> Response<BoxBody> {
        let mut resp = Response::new(full_body(self.body.clone()));
        *resp.status_mut() = self.status;
        *resp.headers_mut() = self.headers.clone();
        resp
    }
}

/// 已编译的接口守卫路径匹配器。按 `type` 分派,热路径零分配:
/// Exact/Prefix 只做借用串比较,Glob 沿用预编译 `GlobMatcher`。
enum GuardPathMatcher {
    /// 精确匹配:`path == pattern`。
    Exact(String),
    /// 前缀匹配:`path.starts_with(pattern)`(nginx `location` 前缀语义)。
    Prefix(String),
    /// glob 匹配(`**`/`*`),build 期预编译。
    Glob(GlobMatcher),
}

impl GuardPathMatcher {
    /// 业务作用：判断请求 path 是否命中本规则(热路径,零分配)。
    ///
    /// 参数说明：
    /// - `path`: 已规范化的请求路径。
    fn is_match(&self, path: &str) -> bool {
        match self {
            Self::Exact(pattern) => path == pattern,
            Self::Prefix(pattern) => path.starts_with(pattern.as_str()),
            Self::Glob(matcher) => matcher.is_match(path),
        }
    }
}

/// 一条接口守卫规则(已预编译匹配器 + 方法 + 响应)。
struct GuardRule {
    id: String,
    enabled: bool,
    path: GuardPathMatcher,
    methods: Vec<Method>, // 空 = 所有方法
    response: RespTemplate,
}

/// 接口守卫:命中任一 enabled 规则 → 返回它的直接响应。
pub struct InterfaceGuard {
    rules: Vec<GuardRule>,
}

impl InterfaceGuard {
    /// 业务作用：构造不阻断任何请求的空守卫。
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    /// 业务作用：校验并预编译完整守卫文档；任一规则非法即拒绝整个候选快照。
    pub fn build(gf: GuardFile) -> Result<Self> {
        let default_resp = match &gf.default_response {
            Some(c) => RespTemplate::compile(c)?,
            None => RespTemplate::service_unavailable(),
        };
        let mut rules = Vec::with_capacity(gf.rules.len());
        for r in &gf.rules {
            // 按声明的匹配类型编译;Glob 才做 glob 解析,Exact/Prefix 直接持有 pattern 串。
            let path = match r.matcher.match_type {
                GuardMatchType::Exact => GuardPathMatcher::Exact(r.matcher.path.clone()),
                GuardMatchType::Prefix => GuardPathMatcher::Prefix(r.matcher.path.clone()),
                GuardMatchType::Glob => GuardPathMatcher::Glob(
                    Glob::new(&r.matcher.path)
                        .with_context(|| {
                            format!("rule `{}` invalid path glob `{}`", r.id, r.matcher.path)
                        })?
                        .compile_matcher(),
                ),
            };
            let methods = r
                .matcher
                .methods
                .iter()
                .map(|m| Method::from_str(m.trim()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .with_context(|| format!("rule `{}` invalid method", r.id))?;
            let response = match &r.response {
                Some(c) => RespTemplate::compile(c)?,
                None => default_resp.clone(),
            };
            rules.push(GuardRule {
                id: r.id.clone(),
                enabled: r.enabled,
                path,
                methods,
                response,
            });
        }
        Ok(Self {
            rules,
        })
    }

    /// 业务作用：命中任一 enabled 规则 → Some(直接响应,附命中规则 id);否则 None(继续正常管线)。
    pub fn check(&self, parts: &Parts) -> Option<(Response<BoxBody>, &str)> {
        let path = parts.uri.path();
        // 配置书写顺序决定覆盖关系，只执行首个启用且匹配的规则，不按路径匹配类型重排。
        for r in &self.rules {
            if !r.enabled {
                continue;
            }
            let method_ok = r.methods.is_empty() || r.methods.contains(&parts.method);
            if method_ok && r.path.is_match(path) {
                return Some((r.response.to_response(), r.id.as_str()));
            }
        }
        None
    }

    /// 业务作用：返回已编译规则数，包括显式禁用的规则。
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// 动态接口禁用缓存。
///
/// 它从 [`DynamicStore`] 低频刷新,数据面热路径只读内存里的 [`InterfaceGuard`] 快照。
pub struct DynamicInterfaceGuardCache {
    /// 是否启用动态接口禁用。
    enabled: AtomicBool,
    /// DynamicStore collection 名。
    collection: RwLock<String>,
    /// 兜底刷新间隔(ms)。
    refresh_interval_ms: AtomicU64,
    /// 已编译的动态守卫规则。
    guard: ArcSwap<InterfaceGuard>,
}

impl DynamicInterfaceGuardCache {
    /// 业务作用：构造动态接口禁用缓存。
    ///
    /// 参数说明：
    /// - `cfg`: `runtime_state.interface_disable` 配置。
    pub fn new(cfg: &InterfaceDisableCfg) -> Result<Self> {
        validate_interface_disable_config(cfg)?;
        Ok(Self {
            enabled: AtomicBool::new(cfg.enabled),
            collection: RwLock::new(cfg.collection.clone()),
            refresh_interval_ms: AtomicU64::new(cfg.refresh_interval_ms),
            guard: ArcSwap::from_pointee(InterfaceGuard::empty()),
        })
    }

    /// 业务作用：应用新配置。已编译规则由调用方随后按新 collection 刷新。
    ///
    /// 参数说明：
    /// - `cfg`: 新的动态接口禁用配置。
    pub fn apply_config(&self, cfg: &InterfaceDisableCfg) -> Result<()> {
        validate_interface_disable_config(cfg)?;
        self.enabled.store(cfg.enabled, Ordering::Relaxed);
        *self.collection.write() = cfg.collection.clone();
        self.refresh_interval_ms
            .store(cfg.refresh_interval_ms, Ordering::Relaxed);
        if !cfg.enabled {
            self.guard.store(Arc::new(InterfaceGuard::empty()));
        }
        Ok(())
    }

    /// 业务作用：当前是否启用。
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 业务作用：当前 DynamicStore collection 名。
    pub fn collection(&self) -> String {
        self.collection.read().clone()
    }

    /// 业务作用：当前兜底刷新间隔。
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_millis(self.refresh_interval_ms.load(Ordering::Relaxed).max(100))
    }

    /// 业务作用：从动态事实源刷新规则并替换本地缓存。
    ///
    /// 参数说明：
    /// - `store`: 当前动态事实源。
    /// - `collection`: collection 名。
    pub async fn refresh_from_store(
        &self,
        store: &dyn DynamicStore,
        collection: &str,
    ) -> Result<usize> {
        let guard = load_dynamic_interface_guard(store, collection).await?;
        let count = guard.rule_count();
        self.guard.store(Arc::new(guard));
        Ok(count)
    }

    /// 业务作用：直接替换已编译规则。
    ///
    /// 参数说明：
    /// - `guard`: 已编译动态守卫。
    pub fn replace_guard(&self, guard: InterfaceGuard) {
        self.guard.store(Arc::new(guard));
    }

    /// 业务作用：清空动态规则。
    pub fn clear(&self) {
        self.guard.store(Arc::new(InterfaceGuard::empty()));
    }

    /// 业务作用：按当前动态规则检查请求。
    ///
    /// 参数说明：
    /// - `parts`: 下游请求 head。
    pub fn check(&self, parts: &Parts) -> Option<(Response<BoxBody>, String)> {
        if !self.is_enabled() {
            return None;
        }
        let guard = self.guard.load();
        guard.check(parts).map(|(resp, id)| (resp, id.to_string()))
    }
}

/// 业务作用：校验动态接口禁用配置。
///
/// 参数说明：
/// - `cfg`: `runtime_state.interface_disable` 配置。
pub fn validate_interface_disable_config(cfg: &InterfaceDisableCfg) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    validate_component(&cfg.collection, "interface_disable.collection")?;
    if cfg.refresh_interval_ms == 0 {
        anyhow::bail!(
            "runtime_state.interface_disable.refresh_interval_ms must be positive when enabled"
        );
    }
    if cfg.refresh_interval_ms > 365 * 24 * 60 * 60 * 1_000 {
        anyhow::bail!("runtime_state.interface_disable.refresh_interval_ms must be <=31536000000");
    }
    Ok(())
}

/// 业务作用：从 DynamicStore 加载动态接口禁用规则。
///
/// 参数说明：
/// - `store`: 当前动态事实源。
/// - `collection`: collection 名。
pub async fn load_dynamic_interface_guard(
    store: &dyn DynamicStore,
    collection: &str,
) -> Result<InterfaceGuard> {
    validate_component(collection, "interface_disable.collection")?;
    let keys = store
        .list_keys(collection)
        .await
        .with_context(|| format!("load interface disable collection `{collection}`"))?;
    let now_ms = unix_now_ms();
    let mut rules = Vec::new();
    for key in keys {
        match load_dynamic_interface_rule(store, collection, &key, now_ms).await {
            Ok(Some(rule)) => rules.push(rule),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    collection,
                    key = %key,
                    error = %e,
                    "ignore invalid dynamic interface disable entry"
                );
            }
        }
    }
    InterfaceGuard::build(GuardFile {
        schema_version: Some(1),
        default_response: None,
        rules,
    })
}

/// 业务作用：启动动态接口禁用后台刷新任务。
///
/// 参数说明：
/// - `cache`: 动态接口禁用本地缓存。
/// - `store`: 可热替换动态事实源。
pub fn spawn_interface_disable_refresh(
    cache: Arc<DynamicInterfaceGuardCache>,
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
                        tracing::warn!(collection, error = %e, "interface disable watch unavailable; fallback to interval refresh");
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
                                    "interface disable dynamic store change received"
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
                    tracing::debug!(
                        collection,
                        count,
                        reason,
                        "interface disable cache refreshed"
                    );
                }
                Err(e) => {
                    tracing::warn!(collection, reason, error = %e, "interface disable refresh failed; keep last cache");
                }
            }
        }
    })
}

#[derive(Deserialize)]
struct DynamicInterfaceRuleCfg {
    #[serde(default)]
    id: String,
    #[serde(default = "default_rule_enabled")]
    enabled: bool,
    #[serde(rename = "match")]
    matcher: GuardMatchCfg,
    #[serde(default)]
    response: Option<RespCfg>,
    #[serde(default)]
    expire_at_unix_ms: Option<i64>,
}

/// 业务作用：把持久化接口关闭事实转换为守卫规则，非法或过期声明不能扩张拦截范围。
async fn load_dynamic_interface_rule(
    store: &dyn DynamicStore,
    collection: &str,
    key: &str,
    now_ms: i64,
) -> Result<Option<GuardRuleCfg>> {
    validate_component(key, "interface_disable.key")?;
    let Some(value) = store
        .get(collection, key)
        .await
        .with_context(|| format!("load interface disable entry `{collection}/{key}`"))?
    else {
        return Ok(None);
    };
    let cfg: DynamicInterfaceRuleCfg = serde_json::from_slice(&value)
        .with_context(|| format!("parse interface disable entry `{collection}/{key}`"))?;
    if cfg
        .expire_at_unix_ms
        .map(|expire_at| expire_at <= now_ms)
        .unwrap_or(false)
    {
        if let Err(e) = store.delete(collection, key).await {
            tracing::warn!(
                collection,
                key = %key,
                error = %e,
                "delete expired interface disable entry failed"
            );
        }
        return Ok(None);
    }
    Ok(Some(GuardRuleCfg {
        id: if cfg.id.is_empty() {
            key.to_string()
        } else {
            cfg.id
        },
        enabled: cfg.enabled,
        matcher: cfg.matcher,
        response: cfg.response,
    }))
}

/// 业务作用：为未显式声明的 `enabled` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
fn default_rule_enabled() -> bool {
    true
}

/// 业务作用：提供动态接口规则有效期使用的 Unix 毫秒时间。
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

/// 业务作用：验证动态规则集合标识，防止配置键改变存储路径或命名空间。
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
