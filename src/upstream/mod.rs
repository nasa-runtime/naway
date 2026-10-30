//! 上游发现抽象、静态服务目录与动态发现目录。
//!
//! 数据面只读本地快照:静态实例来自 yml,Nacos 实例由 discovery manager watch 后写入
//! [`DynamicUpstreamStore`]。LB 选择逻辑不关心实例来源。

pub mod discovery;
pub mod hash;
pub mod health;
pub mod load;
mod locality;
pub(crate) mod observation;
pub mod passive;
mod semantic;

use locality::Policy as UpstreamLocalityPolicy;

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::config::model::{
    DiscoveryCfg, StaticInstanceCfg, StaticServiceCfg, UpstreamPrewarmCfg, UpstreamsCfg,
};
use crate::config::resolve_relative;
use crate::tls::{
    build_upstream_tls_profile, build_upstream_tls_profile_with_material, UpstreamTlsProfile,
};

/// 服务发现快照提供者。
pub trait ServiceRegistry: Send + Sync {
    /// 业务作用：返回当前服务目录快照。实现方应保证调用不阻塞数据面热路径。
    fn snapshot(&self) -> UpstreamDirectory;
}

/// 静态服务发现后端:直接从 yml 的 `upstreams.services` 构建。
pub struct StaticRegistry {
    directory: UpstreamDirectory,
}

impl StaticRegistry {
    /// 业务作用：校验配置并构造不再变化的静态服务目录。
    pub fn new(cfg: &UpstreamsCfg) -> Result<Self> {
        Ok(Self {
            directory: UpstreamDirectory::build(cfg)?,
        })
    }
}

impl ServiceRegistry for StaticRegistry {
    /// 业务作用：提供静态实例目录的不可变视图，负载选择不修改配置中的实例定义。
    fn snapshot(&self) -> UpstreamDirectory {
        self.directory.clone()
    }
}

/// Nacos watch 写入的动态实例表。读路径是 ArcSwap load + Vec clone,没有 await / IO。
///
/// WHY `write_lock`:每个 Nacos 服务有一个独立 watch 任务并发写同一张 `services` 表
/// (`touch_service`/`replace_service`/`remove_service`),而这三者都是 read-copy-update
/// (load→clone→store)。没有串行化时两个不同服务的并发写会互相丢更新(lost update):
/// A 读 V0、B 读 V0、A 存 V0+{a}、B 存 V0+{b} → A 的更新被覆盖回退,可能让已摘除的死实例复活
/// 或让刚删除的服务残留且再无任务维护。写是低频控制面操作,持锁跨 load→store(无 await)开销可忽略;
/// 读路径仍走 `services.load` 无锁,不受影响。
pub struct DynamicUpstreamStore {
    services: ArcSwap<HashMap<String, DynamicServiceState>>,
    write_lock: std::sync::Mutex<()>,
}

impl Default for DynamicUpstreamStore {
    /// 业务作用：建立空的原子发现目录与串行写入门，保证并发更新不会互相覆盖。
    fn default() -> Self {
        Self {
            services: ArcSwap::from_pointee(HashMap::new()),
            write_lock: std::sync::Mutex::new(()),
        }
    }
}

impl DynamicUpstreamStore {
    /// 业务作用：创建一个空的动态实例目录，并返回可供发现任务与配置快照共享的句柄。
    ///
    /// 返回：内部通过 `ArcSwap` 发布不可变目录，数据面读取不等待发现侧 IO。
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 业务作用：获取一个服务当前的不可变实例切片。
    ///
    /// 参数说明：
    /// - `service`: 配置中的逻辑服务名，而不是 Nacos 的物理 dataId。
    ///
    /// 返回：服务存在时只 clone 一次 `Arc`；不存在时返回 `None`。不会按请求深拷贝实例列表。
    pub fn service_instances(&self, service: &str) -> Option<Arc<[Arc<UpstreamInstance>]>> {
        self.services
            .load()
            .get(service)
            .map(|state| state.instances.clone())
    }

    /// 业务作用：判断服务是否仍有实例，且最近一次发现连接确认未超过 stale TTL。
    pub fn service_fresh(&self, service: &str, stale_ttl_ms: u64) -> bool {
        let Some(state) = self.services.load().get(service).cloned() else {
            return false;
        };
        if state.instances.is_empty() {
            return false;
        }
        stale_ttl_ms == 0 || state.updated_at.elapsed().as_millis() as u64 <= stale_ttl_ms
    }

    /// 业务作用：原子替换一个动态服务的完整实例集，并保留未变化实例的 slow-start 起点。
    pub fn replace_service(&self, service: &str, mut instances: Vec<UpstreamInstance>) {
        // 串行化所有写者,避免与其它服务的并发 watch 写互相丢更新(见结构体注释)。
        let _write = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.services.load();
        if let Some(old) = current.get(service) {
            for inst in &mut instances {
                if let Some(prev) = old
                    .instances
                    .iter()
                    .find(|prev| prev.health_key == inst.health_key)
                {
                    inst.created_at = prev.created_at;
                    inst.feedback_generation = prev.feedback_generation;
                }
            }
        }
        // 发现更新是低频控制面操作；这里构造新的不可变切片，换取数据面无锁共享且不深拷贝。
        let instances = instances
            .into_iter()
            .map(|mut instance| {
                instance.bind_feedback_service(service);
                Arc::new(instance)
            })
            .collect::<Vec<_>>()
            .into();
        let mut next = current.as_ref().clone();
        next.insert(
            service.to_string(),
            DynamicServiceState {
                instances,
                updated_at: Instant::now(),
            },
        );
        self.services.store(Arc::new(next));
    }

    /// 业务作用：把一个控制面 response 中的多个动态服务作为同一事务发布，并清除该
    /// owner 本轮已省略的服务，避免请求看到半份 EDS SotW。
    ///
    /// 参数说明：
    /// - `managed_services`：是该 owner 独占的全部逻辑服务
    /// - `replacement`：是已完成 全量校验的新实例表，缺失 key 表示该服务当前没有 endpoint。
    ///
    /// 返回：无返回值；单次 `ArcSwap::store` 后所有读者同时观察新版本，未变化身份保留
    /// slow-start 起点。调用前必须先验证整份 response，函数本身不执行外部 IO。
    pub fn replace_managed_services(
        &self,
        managed_services: &[String],
        mut replacement: HashMap<String, Vec<UpstreamInstance>>,
    ) {
        // 同一 ADS response 必须只发布一次：逐服务 replace 会让并发请求观察到新旧 cluster
        // 混合状态，ACK 后也无法证明数据面实际对应完整 nonce。
        let _write = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.services.load();
        let mut next = current.as_ref().clone();
        for service in managed_services {
            let instances = replacement.remove(service).unwrap_or_default();
            let old = current.get(service);
            let instances = instances
                .into_iter()
                .map(|mut instance| {
                    if let Some(previous) = old.and_then(|state| {
                        state
                            .instances
                            .iter()
                            .find(|previous| previous.health_key == instance.health_key)
                    }) {
                        instance.created_at = previous.created_at;
                        instance.feedback_generation = previous.feedback_generation;
                    }
                    instance.bind_feedback_service(service);
                    Arc::new(instance)
                })
                .collect::<Vec<_>>()
                .into();
            next.insert(
                service.clone(),
                DynamicServiceState {
                    instances,
                    updated_at: Instant::now(),
                },
            );
        }
        self.services.store(Arc::new(next));
    }

    /// 业务作用：原子移除一个动态服务及其 freshness 状态。
    pub fn remove_service(&self, service: &str) {
        // 串行化写者(见结构体注释):否则 reconcile 的 remove 可能被并发 touch/replace 覆盖回退。
        let _write = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.services.load();
        if !current.contains_key(service) {
            return;
        }
        let mut next = current.as_ref().clone();
        next.remove(service);
        self.services.store(Arc::new(next));
    }

    /// 业务作用：「触活」一个服务的 last-known-good:仅刷新其 fresh 时间戳,不改实例列表。
    ///
    /// 由 Nacos watch 任务在**连接存活期间**周期性调用(discovery.rs)。维持租约有效期的原因：
    /// `service_fresh` 的 staleness 是从 `updated_at` 算的,而 `updated_at` 只在【实例变更】push 时前移;
    /// 一个稳定不变的服务(Nacos 不会重复推送相同数据)会在 `stale_ttl` 后被**误判 stale**,令 critical
    /// `/readyz` 无谓地抖到 503、被前置 LB 摘流。 的 stale_ttl 语义本是「watch 断线后 last-known-good 老化」
    /// ——即「距 watch 上次确认存活的时长」,而非「距上次数据变更的时长」。触活把二者对齐:watch 活着就保持 fresh,
    /// watch 一旦断(任务退出、停止触活),stale_ttl 到点才降级。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名(`lb://<service>` 抽出的名)。仅当该服务已存在且非空时触活
    ///   (空服务本就不该 fresh,触活它会掩盖「实例全没了」)。
    pub fn touch_service(&self, service: &str) {
        // 串行化写者(见结构体注释):触活也是 read-copy-update,并发写会丢别的服务的更新。
        let _write = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.services.load();
        // 服务不存在或当前为空:不触活。空 = 真的没有可用实例,应让它按 service_fresh 判为 not-fresh。
        let Some(state) = current.get(service) else {
            return;
        };
        if state.instances.is_empty() {
            return;
        }
        // 背景任务、低频(poll 间隔级),非请求热路径:整表 clone 换指针可接受(与 replace_service 同量级, 只约束热路径)。
        let mut next = current.as_ref().clone();
        if let Some(state) = next.get_mut(service) {
            state.updated_at = Instant::now();
        }
        self.services.store(Arc::new(next));
    }
}

/// 动态目录中一个服务的不可变发布版本。
///
/// 整个结构随外层 `ArcSwap<HashMap<...>>` 一次性替换，读请求不会观察到实例表与 freshness 撕裂。
#[derive(Clone)]
struct DynamicServiceState {
    /// 一次发现版本的不可变实例切片；请求只 clone 外层 `Arc`。
    instances: Arc<[Arc<UpstreamInstance>]>,
    /// 最近一次发现连接确认该服务仍新鲜的时刻。
    updated_at: Instant,
}

/// 一次配置快照内的上游目录。
#[derive(Clone)]
pub struct UpstreamDirectory {
    services: HashMap<String, ServiceSnapshot>,
    dynamic: Arc<DynamicUpstreamStore>,
    prewarm_scan_interval_ms: u64,
    /// 一致性哈希表缓存:服务名 → 与某一份实例切片绑定的环/表。
    ///
    /// 表的构建是 O(实例数 × 副本数),绝不能每请求重建;缓存条目持有构建时那份
    /// `Arc` 切片,既保证指针比较不会 ABA 误判,也保证实例目录换代后自动重建。
    /// 用 `Mutex` 而非 `ArcSwap`:重建只发生在实例集合变化时,常态是读命中。
    hash_tables: Arc<Mutex<HashMap<String, Arc<crate::upstream::hash::ConsistentHashTable>>>>,
}

impl Default for UpstreamDirectory {
    /// 业务作用：构造无服务的上游目录及共享发现容器，尚未加载配置时不产生可选实例。
    fn default() -> Self {
        Self {
            services: HashMap::new(),
            dynamic: DynamicUpstreamStore::new(),
            prewarm_scan_interval_ms: 1_000,
            hash_tables: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl UpstreamDirectory {
    /// 业务作用：仅使用静态实例构造目录；动态目录为空。
    pub fn build(cfg: &UpstreamsCfg) -> Result<Self> {
        Self::build_with_dynamic(cfg, DynamicUpstreamStore::new(), 30_000)
    }

    /// 业务作用：使用共享动态目录和统一 Nacos stale TTL 构造服务目录。
    pub fn build_with_dynamic(
        cfg: &UpstreamsCfg,
        dynamic: Arc<DynamicUpstreamStore>,
        nacos_stale_ttl_ms: u64,
    ) -> Result<Self> {
        Self::build_with_dynamic_at(cfg, dynamic, nacos_stale_ttl_ms, Path::new("."))
    }

    /// 业务作用：与 [`Self::build_with_dynamic`] 相同，并以 `cfg_path` 解析 TLS 相对路径。
    pub fn build_with_dynamic_at(
        cfg: &UpstreamsCfg,
        dynamic: Arc<DynamicUpstreamStore>,
        nacos_stale_ttl_ms: u64,
        cfg_path: &Path,
    ) -> Result<Self> {
        let mut discovery = DiscoveryCfg::default();
        discovery.nacos.enabled = true;
        discovery.nacos.stale_ttl_ms = nacos_stale_ttl_ms;
        Self::build_with_dynamic_at_discovery(cfg, dynamic, &discovery, cfg_path)
    }

    /// 业务作用：按每个 registry 的 stale TTL、协议/TLS、健康、预热和 locality 策略编译
    /// 完整服务目录；这是候选 Snapshot 发布前的统一 fail-closed 入口。
    ///
    /// 参数说明：
    /// - `cfg`：是上游声明
    /// - `dynamic`：是常驻发现事实源
    /// - `discovery`：提供各后端 freshness 契约
    /// - `cfg_path`：用于解析 TLS 相对路径。
    ///
    /// 返回：全部服务和实例校验成功时返回不可变目录，任一协议/zone/资源配置非法则失败。
    pub fn build_with_dynamic_at_discovery(
        cfg: &UpstreamsCfg,
        dynamic: Arc<DynamicUpstreamStore>,
        discovery: &DiscoveryCfg,
        cfg_path: &Path,
    ) -> Result<Self> {
        anyhow::ensure!(
            (100..=60_000).contains(&cfg.prewarm_scan_interval_ms),
            "upstreams.prewarm_scan_interval_ms must be within 100..=60000"
        );
        let mut services = HashMap::with_capacity(cfg.services.len());
        let subscription_instances = cfg
            .services
            .values()
            .filter(|service| {
                service
                    .load_feedback
                    .as_ref()
                    .is_some_and(|feedback| feedback.out_of_band.is_some())
            })
            .map(|service| service.instances.len())
            .sum::<usize>();
        anyhow::ensure!(
            subscription_instances <= load::subscription::MAX_SUBSCRIPTIONS,
            "ORCA static subscription capacity exceeds 256"
        );
        let window_services: Vec<_> = cfg
            .services
            .values()
            .filter(|service| service.outlier.is_some())
            .collect();
        anyhow::ensure!(
            window_services.len() <= 1024,
            "outlier service count exceeds 1024"
        );
        anyhow::ensure!(
            window_services
                .iter()
                .all(|service| service.instances.len() <= 4096),
            "outlier service instance count exceeds 4096"
        );
        anyhow::ensure!(
            window_services
                .iter()
                .map(|service| service.instances.len())
                .sum::<usize>()
                <= 65_536,
            "outlier instance count exceeds 65536"
        );
        for (name, svc) in &cfg.services {
            // 被动摘除会执行 `Instant + fail_timeout`；给外部配置一个宽松但有限的一年上限，
            // 防止 u64 极值把一次真实上游失败升级成进程 panic。
            const MAX_FAIL_TIMEOUT_MS: u64 = 365 * 24 * 60 * 60 * 1_000;
            anyhow::ensure!(
                svc.max_fails == 0
                    || (1..=MAX_FAIL_TIMEOUT_MS).contains(&svc.fail_timeout_ms),
                "service `{name}` fail_timeout_ms must be within 1..={MAX_FAIL_TIMEOUT_MS} when max_fails is positive"
            );
            let source = ServiceSource::parse(svc.source.as_deref().unwrap_or("static"))
                .with_context(|| format!("service `{name}` source"))?;
            match source {
                ServiceSource::Static => {}
                ServiceSource::Nacos => anyhow::ensure!(
                    discovery.nacos.enabled,
                    "service `{name}` source=nacos requires discovery.nacos.enabled=true"
                ),
                ServiceSource::Consul => anyhow::ensure!(
                    discovery.consul.enabled,
                    "service `{name}` source=consul requires discovery.consul.enabled=true"
                ),
                ServiceSource::Eureka => anyhow::ensure!(
                    discovery.eureka.enabled,
                    "service `{name}` source=eureka requires discovery.eureka.enabled=true"
                ),
                ServiceSource::Dns => {
                    anyhow::ensure!(
                        discovery.dns.enabled,
                        "service `{name}` source=dns requires discovery.dns.enabled=true"
                    );
                    anyhow::ensure!(
                        svc.registry_port.is_some_and(|port| port > 0),
                        "service `{name}` source=dns requires non-zero registry_port"
                    );
                }
                ServiceSource::Kubernetes => {
                    anyhow::ensure!(
                        discovery.kubernetes.enabled,
                        "service `{name}` source=kubernetes requires discovery.kubernetes.enabled=true"
                    );
                    anyhow::ensure!(
                        !(svc.registry_port.is_some() && svc.registry_port_name.is_some()),
                        "service `{name}` source=kubernetes cannot set both registry_port and registry_port_name"
                    );
                    anyhow::ensure!(
                        svc.registry_port.is_none_or(|port| port > 0),
                        "service `{name}` source=kubernetes registry_port cannot be zero"
                    );
                }
                // xDS transport 是否启用、bootstrap/owner 是否安全由配置层统一门禁；目录层只
                // 负责把该服务固定为动态 EDS 事实源，避免和任一本地 registry worker 双写。
                ServiceSource::Xds => {}
            }
            if source != ServiceSource::Static {
                anyhow::ensure!(
                    svc.instances.is_empty(),
                    "service `{name}` dynamic source cannot also declare static instances"
                );
            }
            let protocol = UpstreamProtocol::parse(svc.protocol.as_deref().unwrap_or("auto"))
                .with_context(|| format!("service `{name}` protocol"))?;
            if protocol.is_cgi() {
                // 记录协议不接受 HTTP 预热或 TLS 隐式降级；明文 TCP 的安全边界由部署网络提供。
                anyhow::ensure!(
                    svc.prewarm.is_none() && svc.tls.is_none(),
                    "CGI services do not support HTTP prewarm or TLS profiles"
                );
            }
            let scheme = svc.scheme.as_deref().unwrap_or("http").trim().to_string();
            anyhow::ensure!(
                !protocol.is_cgi() || scheme == "http",
                "CGI discovery requires a plaintext TCP address carrier"
            );
            validate_upstream_scheme(&scheme)
                .with_context(|| format!("service `{name}` scheme"))?;
            if source != ServiceSource::Static && protocol == UpstreamProtocol::H3 {
                anyhow::ensure!(
                    scheme == "https",
                    "service `{name}` protocol=h3 requires scheme=https for discovered instances"
                );
            }
            let mut tls_profile = build_service_tls_profile(cfg_path, name, svc)
                .with_context(|| format!("service `{name}` tls"))?;
            if protocol == UpstreamProtocol::H3 && tls_profile.is_none() {
                // Hyper 的 HTTPS connector 会隐式创建 native-root TLS config；H3 自有 Quinn
                // connector 必须显式持有同等 profile，才能把 CA/SNI/ALPN 纳入连接池身份。
                tls_profile = Some(
                    build_upstream_tls_profile(None, None, None, None)
                        .with_context(|| format!("service `{name}` HTTP/3 native TLS profile"))?,
                );
            }
            let prewarm = svc
                .prewarm
                .as_ref()
                .map(|cfg| UpstreamPrewarmPolicy::parse(cfg, name))
                .transpose()?;
            let locality = svc
                .locality
                .as_ref()
                .map(|cfg| UpstreamLocalityPolicy::parse(cfg, name))
                .transpose()?;
            let load_feedback = build_load_feedback(svc.load_feedback.as_ref())
                .with_context(|| format!("service `{name}` load_feedback"))?;
            if let Some(subscription) = &load_feedback.out_of_band {
                let skip_verify = svc.tls.as_ref().is_some_and(|tls| tls.insecure_skip_verify);
                // 即使当前目录为空也先验证协议和身份声明，不能等实例上线后才暴露不安全配置。
                subscription.validate_transport(
                    protocol,
                    source != ServiceSource::Static && scheme == "http",
                    skip_verify,
                )?;
                for instance in &svc.instances {
                    subscription.validate_transport(
                        protocol,
                        instance.uri.starts_with("http://"),
                        skip_verify,
                    )?;
                }
            }
            let active_health = match &svc.health_check {
                Some(cfg) => {
                    let policy = crate::upstream::health::ActiveHealthPolicy::parse(cfg)
                        .with_context(|| format!("service `{name}` health_check"))?;
                    // gRPC Health 必须在快照发布前绑定到 HTTP/2-capable transport；若等到
                    // 后台探测再失败，实例会被持续误摘且旧配置已失去 LKG 保护机会。
                    policy
                        .validate_protocol(protocol)
                        .with_context(|| format!("service `{name}` health_check transport"))?;
                    Some(policy)
                }
                None => None,
            };
            let mut instances = Vec::with_capacity(svc.instances.len());
            for inst in &svc.instances {
                let mut instance =
                    UpstreamInstance::try_from_cfg(inst, protocol, tls_profile.clone())
                        .with_context(|| {
                            format!("build static upstream instance for service `{name}`")
                        })?;
                instance.bind_feedback_service(name);
                instances.push(Arc::new(instance));
            }
            services.insert(
                name.clone(),
                ServiceSnapshot {
                    critical: svc.critical,
                    source,
                    lb_policy: LbPolicy::parse(
                        svc.lb_policy
                            .as_deref()
                            .or(svc.lb.as_deref())
                            .unwrap_or("round_robin"),
                    )
                    .with_context(|| format!("service `{name}` lb_policy"))?,
                    hash: build_hash_policy(svc)
                        .with_context(|| format!("service `{name}` hash_on"))?,
                    session_affinity: build_session_affinity(svc.session_affinity.as_ref())
                        .with_context(|| format!("service `{name}` session_affinity"))?,
                    load_feedback,
                    retry_budget: crate::runtime::admission::build_retry_budget(
                        svc.retry_budget.as_ref(),
                    )
                    .with_context(|| format!("service `{name}` retry_budget"))?,
                    adaptive_concurrency: crate::runtime::admission::build_adaptive_concurrency(
                        svc.adaptive_concurrency.as_ref(),
                    )
                    .with_context(|| format!("service `{name}` adaptive_concurrency"))?,
                    next_upstream: NextUpstreamPolicy::parse(
                        svc.next_upstream.as_deref(),
                        svc.next_upstream_tries,
                        svc.next_upstream_backoff_ms,
                    )
                    .with_context(|| format!("service `{name}` next_upstream"))?,
                    passive_health: if svc.outlier.is_some() {
                        PassiveHealthPolicy::disabled()
                    } else {
                        PassiveHealthPolicy {
                            max_fails: svc.max_fails,
                            fail_timeout_ms: svc.fail_timeout_ms,
                        }
                    },
                    outlier: svc
                        .outlier
                        .map(|policy| {
                            policy
                                .validate()
                                .with_context(|| format!("service `{name}` outlier"))?;
                            Ok::<_, anyhow::Error>(policy)
                        })
                        .transpose()?,
                    active_health,
                    prewarm,
                    locality,
                    instances: instances.into(),
                    protocol,
                    tls_profile,
                    nacos_service: svc.nacos_service.clone().unwrap_or_else(|| name.clone()),
                    registry_service: svc.registry_service.clone().unwrap_or_else(|| name.clone()),
                    registry_service_import: svc.registry_service_import,
                    registry_namespace: svc.registry_namespace.clone(),
                    registry_port: svc.registry_port,
                    registry_port_name: svc.registry_port_name.clone(),
                    scheme,
                    clusters: svc.clusters.clone(),
                    slow_start_ms: svc
                        .instances
                        .iter()
                        .map(|inst| inst.slow_start_ms)
                        .max()
                        .unwrap_or(0),
                    discovery_stale_ttl_ms: match source {
                        ServiceSource::Static => 0,
                        ServiceSource::Nacos => discovery.nacos.stale_ttl_ms,
                        ServiceSource::Consul => discovery.consul.stale_ttl_ms,
                        ServiceSource::Eureka => discovery.eureka.stale_ttl_ms,
                        ServiceSource::Dns => discovery.dns.stale_ttl_ms,
                        ServiceSource::Kubernetes => discovery.kubernetes.stale_ttl_ms,
                        // ADS 断线由 xDS 状态机与 readiness 管理；已 ACK 的 LKG 不按本地 TTL
                        // 静默过期，否则短暂控制面抖动会无依据清空仍可用的数据面端点。
                        ServiceSource::Xds => 0,
                    },
                },
            );
        }
        Ok(Self {
            services,
            dynamic,
            prewarm_scan_interval_ms: cfg.prewarm_scan_interval_ms,
            hash_tables: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 业务作用：取得与当前实例切片匹配的一致性哈希表,必要时重建并缓存。
    ///
    /// 只有实例切片换代(静态换版或发现刷新)才会重建;常态是一次指针比较后的读命中。
    /// 锁只覆盖缓存查改,表构建本身在锁外完成,避免大服务重建阻塞其它服务的选择。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名。
    /// - `policy`: 服务级 LB 策略,决定建环还是建 Maglev 表。
    /// - `hash`: 服务级哈希参数。
    /// - `instances`: 本次请求读到的实例切片。
    ///
    /// 返回：可用表;无任何可入表实例时返回 `None`,调用方回落常规 LB。
    fn hash_table_for(
        &self,
        service: &str,
        policy: LbPolicy,
        hash: &LbHashPolicy,
        instances: &Arc<[Arc<UpstreamInstance>]>,
    ) -> Option<Arc<crate::upstream::hash::ConsistentHashTable>> {
        if let Ok(cache) = self.hash_tables.lock() {
            if let Some(table) = cache.get(service) {
                if table.matches(instances) {
                    return Some(table.clone());
                }
            }
        }
        let locality = self
            .services
            .get(service)
            .and_then(|service| service.locality.as_ref());
        let raw_weight = |instance: &UpstreamInstance| {
            u64::from(instance.weight)
                * u64::from(locality.map_or(1, |policy| policy.multiplier(instance)))
        };
        // 百分比份额先消去公共倍率，不能因固定点放大使等价配置占用百倍虚拟节点。
        let divisor = if locality.is_some() {
            instances
                .iter()
                .filter(|instance| !instance.down && instance.weight > 0)
                .map(|instance| raw_weight(instance))
                .fold(0, gcd)
                .max(1)
        } else {
            1
        };
        let weight = |instance: &UpstreamInstance| raw_weight(instance) / divisor;
        let built = match policy {
            LbPolicy::Maglev => crate::upstream::hash::ConsistentHashTable::build_maglev_weighted(
                instances,
                hash.table_size,
                weight,
            ),
            _ => crate::upstream::hash::ConsistentHashTable::build_ring_weighted(
                instances,
                hash.replicas_per_weight,
                weight,
            ),
        }?;
        let built = Arc::new(built);
        if let Ok(mut cache) = self.hash_tables.lock() {
            cache.insert(service.to_string(), built.clone());
        }
        Some(built)
    }

    /// 业务作用：选择一个可用实例:先选 primary,primary 全不可用时才选 backup;`down` 实例永不进入候选。
    ///
    /// 参数说明：
    /// - `service`: `lb://service` 中的逻辑服务名。
    ///
    /// 返回：默认零负载/零游标下选中的共享实例；服务不存在或无候选时返回 `None`。
    pub fn select(&self, service: &str) -> Option<Arc<UpstreamInstance>> {
        self.select_instance(service, |_| 0, || 0)
    }

    /// 业务作用：按服务的 LB 策略选择实例:
    /// - `least_conn`：调用方按实例健康身份提供负载，按有效份额归一后取最小，同分时加权分散；
    /// - `round_robin`:调用方 `rr` 传入该服务的单调轮询计数,按实例有效权重轮转(含 slow_start);
    /// - `first`:取第一个候选。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名。
    /// - `load`: `least_conn` 的只读负载回调；其它策略不会调用。
    /// - `rr`：轮询、随机抽样及 least-connection 同分分散使用的单调游标，最多调用一次。
    ///
    /// 返回：只 clone 一个 `Arc` 的选中实例；无候选时返回 `None`。
    pub fn select_instance<F, R>(
        &self,
        service: &str,
        load: F,
        rr: R,
    ) -> Option<Arc<UpstreamInstance>>
    where
        F: FnMut(&str) -> u64,
        R: FnOnce() -> u64,
    {
        self.select_instance_where(service, |_| false, load, rr)
    }

    /// 业务作用：同 [`select_instance`](Self::select_instance),但排除本次请求已经尝试过的实例。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名。
    /// - `excluded`: 已尝试/摘除的 URI 或完整 `health_key`；仅借用扫描。
    /// - `load`: `least_conn` 的只读负载回调。
    /// - `rr`: WRR 的单调游标回调。
    ///
    /// 返回：选中的共享实例；所有候选均被排除时返回 `None`。
    pub fn select_instance_excluding<F, R>(
        &self,
        service: &str,
        excluded: &[String],
        load: F,
        rr: R,
    ) -> Option<Arc<UpstreamInstance>>
    where
        F: FnMut(&str) -> u64,
        R: FnOnce() -> u64,
    {
        self.select_instance_where(
            service,
            |key| excluded.iter().any(|excluded| excluded == key),
            load,
            rr,
        )
    }

    /// 业务作用：同 [`select_instance_excluding`](Self::select_instance_excluding),但允许调用方传入已持有的
    /// 排除集合迭代器,避免请求热路径为主动健康集合额外克隆一份 `Vec<String>`。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名。
    /// - `excluded`: 任意借用式排除项迭代器；非空 one-shot 迭代器会合并为一次临时集合。
    /// - `load`: `least_conn` 的只读负载回调。
    /// - `rr`: WRR 的单调游标回调。
    ///
    /// 返回：选中的共享实例；无候选时返回 `None`。
    pub fn select_instance_excluding_iter<'a, F, R, I>(
        &self,
        service: &str,
        excluded: I,
        load: F,
        rr: R,
    ) -> Option<Arc<UpstreamInstance>>
    where
        I: IntoIterator<Item = &'a str>,
        F: FnMut(&str) -> u64,
        R: FnOnce() -> u64,
    {
        let excluded = excluded.into_iter();
        if excluded.size_hint().1 == Some(0) {
            return self.select_instance_where(service, |_| false, load, rr);
        }
        // 任意 one-shot 迭代器无法被候选扫描重复借用；仅在确有排除项时构造集合，常见空路径零分配。
        let excluded = excluded.collect::<HashSet<_>>();
        self.select_instance_where(service, |key| excluded.contains(key), load, rr)
    }

    /// 业务作用：用调用方提供的借用式排除谓词，按健康、primary/backup、locality 和 LB
    /// 顺序选择一个真实实例；retry/hedge 可借此保证不重复命中同一身份。
    ///
    /// 该入口供数据面把「已尝试列表 + 被动摘除列表 + 主动健康集合」直接组合判断，避免每请求
    /// 合并成临时 `Vec`/`HashSet`。目录实例以共享 `Arc` 返回，选择本身不深拷贝 URI、TLS 或 metadata。
    ///
    /// 参数说明：
    /// - `service`: `lb://service` 中的逻辑服务名。
    /// - `is_excluded`: 输入 URI 或完整 `health_key`，返回 true 表示本次选择必须跳过。
    /// - `load`: `least_conn` 使用的实例在途计数读取器；其它策略不会调用。
    /// - `rr`：轮询、随机抽样及同分分散使用的单调游标。
    ///
    /// 返回：命中时只 clone 一个 `Arc<UpstreamInstance>`；服务缺失、目录过期或无候选时返回 `None`。
    pub fn select_instance_where<E, F, R>(
        &self,
        service: &str,
        is_excluded: E,
        load: F,
        rr: R,
    ) -> Option<Arc<UpstreamInstance>>
    where
        E: Fn(&str) -> bool,
        F: FnMut(&str) -> u64,
        R: FnOnce() -> u64,
    {
        self.select_instance_hinted(service, LbSelectHints::default(), is_excluded, load, rr)
    }

    /// 业务作用：带请求期提示的实例选择,是一致性哈希与会话保持的唯一入口。
    ///
    /// 选择优先级固定为「会话亲和 → 一致性哈希 → 服务级 LB」,且每一级都必须通过同一套
    /// 候选谓词。**亲和与哈希都只影响顺序,不影响可用性判定**:命中的实例若已不健康、
    /// 被摘除或不在允许 locality,直接降级到下一级,健康实例存在时绝不会粘死。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名。
    /// - `hints`: 请求期算好的哈希键与亲和令牌;两者都可缺失。
    /// - `is_excluded`: 排除谓词,输入 URI 或 `health_key`。
    /// - `load`: in-flight 计数读取器,仅 `least_conn`/P2C 调用。
    /// - `rr`：轮询、random/P2C 及 least-connection 同分抽样源。
    ///
    /// 返回：命中时只 clone 一个 `Arc<UpstreamInstance>`。
    pub fn select_instance_hinted<E, F, R>(
        &self,
        service: &str,
        hints: LbSelectHints,
        is_excluded: E,
        mut load: F,
        rr: R,
    ) -> Option<Arc<UpstreamInstance>>
    where
        E: Fn(&str) -> bool,
        F: FnMut(&str) -> u64,
        R: FnOnce() -> u64,
    {
        self.select_instance_observed(
            service,
            hints,
            is_excluded,
            |instance| load(&instance.health_key),
            rr,
        )
    }

    /// 业务作用：在同一候选实例上读取代际绑定的反馈，避免地址重用继承旧负载事实。
    ///
    /// 参数说明：
    /// - `service`：请求冻结的逻辑服务名。
    /// - `hints`：已计算的哈希与会话亲和提示。
    /// - `is_excluded`：对完整健康身份执行的排除判定。
    /// - `load`：借用候选实例读取同代反馈或在途计数，不复制实例元数据。
    /// - `rr`：轮询与随机抽样使用的单调游标。
    ///
    /// 返回：通过统一健康、层级和亲和门禁的共享实例；无候选时返回 None。
    pub fn select_instance_observed<E, F, R>(
        &self,
        service: &str,
        hints: LbSelectHints,
        is_excluded: E,
        load: F,
        rr: R,
    ) -> Option<Arc<UpstreamInstance>>
    where
        E: Fn(&str) -> bool,
        F: FnMut(&UpstreamInstance) -> u64,
        R: FnOnce() -> u64,
    {
        let svc = self.services.get(service)?;
        let instances = self.instances_for(service, svc);
        let slice = instances.as_slice();
        if slice.is_empty() {
            return None;
        }
        // 候选谓词与常规 LB 完全同源:亲和/哈希命中后仍要过健康、排除、backup 分层
        // 与 locality rank,不允许任何一级绕过可用性事实。
        let layer = CandidateLayer::resolve(slice, svc.locality.as_ref(), &is_excluded)?;
        let accept = |inst: &UpstreamInstance| layer.accepts(inst, &is_excluded);

        // ① 会话亲和:客户端带回令牌且对应实例仍可选时优先复用,保证同会话落同实例。
        if let Some(token) = hints.affinity {
            if svc.session_affinity.is_some() {
                if let Some(found) = slice.iter().find(|inst| {
                    crate::upstream::hash::stable_hash(inst.uri.as_bytes()) == token.endpoint_hash
                        && accept(inst.as_ref())
                }) {
                    return Some(found.clone());
                }
            }
        }

        // ② 一致性哈希:仅在服务声明了 ring_hash/maglev 且本次请求算出键时生效。
        if svc.lb_policy.requires_hash_key() {
            if let (Some(hash), Some(policy)) = (hints.hash, svc.hash.as_ref()) {
                if let Some(owned) = instances.as_arc(svc) {
                    if let Some(table) = self.hash_table_for(service, svc.lb_policy, policy, &owned)
                    {
                        if let Some(found) = table.select(hash, |inst| accept(inst)) {
                            return Some(found);
                        }
                    }
                }
            }
            // 无键、无表或探测预算耗尽:退回加权轮转保证可用性,不因缺键拒绝服务。
            return select_instance_from_slice(
                slice,
                LbPolicy::RoundRobin,
                svc.locality.as_ref(),
                is_excluded,
                load,
                rr,
            );
        }

        // ③ 常规 LB。
        select_instance_from_slice(
            slice,
            svc.lb_policy,
            svc.locality.as_ref(),
            is_excluded,
            load,
            rr,
        )
    }

    /// 业务作用：查询服务级 `proxy_next_upstream` 策略。
    pub fn next_upstream_policy(&self, service: &str) -> Option<&NextUpstreamPolicy> {
        self.services.get(service).map(|svc| &svc.next_upstream)
    }

    /// 业务作用：返回服务的被动失败阈值与临时摘除时长。
    pub fn passive_health_policy(&self, service: &str) -> Option<PassiveHealthPolicy> {
        self.services.get(service).map(|svc| svc.passive_health)
    }

    /// 业务作用：从同一实例目录取得窗口摘除组，负载反馈与被动健康不另建发现事实源。
    ///
    /// 参数说明：
    /// - `registry`：L7/L4 共用的进程运行态。
    /// - `service`：当前路由已经选定的逻辑服务。
    /// - `version`：该请求使用的已发布快照版本。
    ///
    /// 返回：未启用时为 None；启用时返回有界共享状态，旧发布代或容量不足拒绝选择。
    #[cfg(feature = "upstream-outlier")]
    pub fn outlier_group(
        &self,
        registry: &passive::Registry,
        service: &str,
        version: u64,
    ) -> Result<Option<Arc<passive::window::Group>>> {
        let snapshot = self
            .services
            .get(service)
            .context("outlier service is absent")?;
        let Some(policy) = snapshot.outlier else {
            return Ok(None);
        };
        registry
            .group(version, service, policy, || {
                match self.instances_for(service, snapshot) {
                    UpstreamInstances::Static(_) => snapshot.instances.clone(),
                    UpstreamInstances::Dynamic(instances) => instances,
                    UpstreamInstances::Empty => Arc::from([]),
                }
            })
            .map(Some)
            .context("outlier state capacity or publication authority unavailable")
    }

    /// 业务作用：当前服务是否真正需要请求期 in-flight 计数。其它 LB 策略不应维护一份永不读取的计数表。
    ///
    /// `least_conn` 与 P2C(`weighted_least_request`)都读该计数;其余策略不读,
    /// 避免为永不查询的表付出每请求的原子增减与 DashMap 争用。
    pub fn uses_least_conn(&self, service: &str) -> bool {
        self.services
            .get(service)
            .is_some_and(|svc| svc.lb_policy.uses_inflight())
    }

    /// 业务作用：返回服务的 retry budget 策略。
    ///
    /// 参数说明：
    /// - `service`：是逻辑服务名。
    ///
    /// 返回：已启用时返回策略,否则返回 `None`。
    pub fn retry_budget(
        &self,
        service: &str,
    ) -> Option<&crate::runtime::admission::RetryBudgetPolicy> {
        self.services
            .get(service)
            .and_then(|svc| svc.retry_budget.as_ref())
    }

    /// 业务作用：返回服务的自适应并发策略。
    ///
    /// 参数说明：
    /// - `service`：是逻辑服务名。
    ///
    /// 返回：已启用时返回策略,否则返回 `None`。
    pub fn adaptive_concurrency(
        &self,
        service: &str,
    ) -> Option<&crate::runtime::admission::AdaptiveConcurrencyPolicy> {
        self.services
            .get(service)
            .and_then(|svc| svc.adaptive_concurrency.as_ref())
    }

    /// 业务作用：返回服务的负载反馈策略,供数据面决定是否采集与使用反馈。
    ///
    /// 参数说明：
    /// - `service`：是逻辑服务名。
    ///
    /// 返回：已声明服务返回其策略,否则返回 `None`。
    pub fn load_feedback(
        &self,
        service: &str,
    ) -> Option<&crate::upstream::load::LoadFeedbackPolicy> {
        self.services.get(service).map(|svc| &svc.load_feedback)
    }

    /// 业务作用：统计当前候选中拥有新鲜反馈的比例,并给出 panic 判定与中性分数。
    ///
    /// **panic 安全阀**:只有少数实例有反馈时,按反馈调度会把全部流量压到那几个实例上,
    /// 反而制造热点。此时整服务停用反馈、回退基础算法。没有反馈的实例使用当前均值作为
    /// 中性分数,既不被优待也不被饿死——否则冷启动实例会永远拿不到样本、永远进不了候选。
    ///
    /// 参数说明：
    /// - `service`: 逻辑服务名。
    /// - `lookup`: 按完整健康身份读取反馈分数的回调。
    ///
    /// 返回：反馈可用时返回 `(中性分数)`;不可用或未启用时返回 `None`。
    pub fn load_feedback_baseline<F>(&self, service: &str, mut lookup: F) -> Option<u64>
    where
        F: FnMut(&str) -> Option<u64>,
    {
        self.load_feedback_baseline_observed(service, |instance| lookup(&instance.health_key))
    }

    /// 业务作用：用同代实例反馈计算整服务的样本覆盖率和中性分数，不把旧实例计入新代样本。
    ///
    /// 参数说明：
    /// - `service`：本次请求冻结的逻辑服务名。
    /// - `lookup`：借用实际候选读取版本与实例代际均匹配的反馈。
    ///
    /// 返回：样本覆盖满足策略时返回均值，否则返回 None 并使用基础负载算法。
    pub fn load_feedback_baseline_observed<F>(&self, service: &str, mut lookup: F) -> Option<u64>
    where
        F: FnMut(&UpstreamInstance) -> Option<u64>,
    {
        let svc = self.services.get(service)?;
        if !svc.load_feedback.enabled() {
            return None;
        }
        let instances = self.instances_for(service, svc);
        let slice = instances.as_slice();
        if slice.is_empty() {
            return None;
        }
        let mut fresh = 0usize;
        let mut total = 0u128;
        for inst in slice.iter().filter(|inst| inst.is_selectable()) {
            if let Some(score) = lookup(inst) {
                fresh += 1;
                total += score as u128;
            }
        }
        let selectable = slice.iter().filter(|inst| inst.is_selectable()).count();
        if selectable == 0 || fresh == 0 {
            return None;
        }
        let ratio_bp = (fresh as u64 * 10_000) / selectable as u64;
        if ratio_bp < svc.load_feedback.panic_threshold_bp as u64 {
            return None;
        }
        Some((total / fresh as u128) as u64)
    }

    /// 业务作用：返回服务声明的一致性哈希键来源,供请求期按受控来源求值。
    ///
    /// 参数说明：
    /// - `service`：是逻辑服务名。
    ///
    /// 返回：声明了 `ring_hash`/`maglev` 时返回来源,否则返回 `None`。
    pub fn hash_source(&self, service: &str) -> Option<&LbHashSource> {
        self.services
            .get(service)
            .and_then(|svc| svc.hash.as_ref())
            .map(|hash| &hash.source)
    }

    /// 业务作用：返回服务级会话保持策略,供请求期读取亲和令牌、响应期回写载体。
    ///
    /// 参数说明：
    /// - `service`：是逻辑服务名。
    ///
    /// 返回：已配置时返回策略,否则返回 `None`。
    pub fn session_affinity(&self, service: &str) -> Option<&SessionAffinityPolicy> {
        self.services
            .get(service)
            .and_then(|svc| svc.session_affinity.as_ref())
    }

    /// 业务作用：返回所有未就绪的关键服务名，供 `/readyz` 与真实 locality-aware 选择保持
    /// 同一可用性口径，避免前置 LB 把流量送给已无允许 zone 容量的节点。
    ///
    /// 「就绪」= 该 critical 服务至少有一个**既 selectable(healthy && !down)、又未被主动探测判死**的实例。
    /// 关键:与「选实例」用同一份可用集(`instances_for`,Nacos 已按 stale_ttl 门控),使 readyz 与 select
    /// 结果一致——实例全被主动探测判死/ Nacos watch 失联超 stale_ttl → 二者同时判「不可用」,
    /// 不会出现「select 返 503 但 readyz 仍 200」这种让前置 LB 误分流的不一致。
    ///
    /// 参数说明：
    /// - `active_unhealthy`：同一轮主动健康事实，按本服务当前策略与传输协议借用端点集合。
    ///
    /// 返回：所有没有可选实例的 critical service 名；空数组表示关键依赖已就绪。
    pub fn critical_not_ready(&self, active_unhealthy: &health::Rejections) -> Vec<String> {
        self.services
            .iter()
            .filter_map(|(name, svc)| {
                if !svc.critical {
                    return None;
                }
                // instances_for 已对 Nacos 做 stale_ttl 门控;这里再排除主动探测判死的实例,与选实例逻辑同源。
                let instances = self.instances_for(name, svc);
                let active_unhealthy =
                    active_unhealthy.service(name, self.active_health_identity(name));
                let has_usable = instances.as_slice().iter().any(|inst| {
                    inst.is_selectable()
                        && svc
                            .locality
                            .as_ref()
                            .is_none_or(|policy| policy.rank(inst).is_some())
                        && !active_unhealthy.contains(inst.uri.as_ref())
                        && !active_unhealthy.contains(inst.health_key.as_ref())
                });
                if has_usable {
                    None
                } else {
                    Some(name.clone())
                }
            })
            .collect()
    }

    /// 业务作用：返回当前配置快照声明的逻辑服务数量。
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// 业务作用：向数据面提供当前服务的探测权威，撤销策略后立即停止采用旧拒绝集合。
    ///
    /// 参数说明：
    /// - `service`：本次选择冻结的逻辑服务身份。
    ///
    /// 返回：规范策略与实际传输协议身份；未配置探测或服务不存在返回 None，不构造字符串。
    pub fn active_health_identity(&self, service: &str) -> Option<health::PolicyIdentity> {
        let service = self.services.get(service)?;
        Some(service.active_health.as_ref()?.identity(service.protocol))
    }

    /// 业务作用：向有界管理目录借用声明服务身份，避免为了遍历而复制全部服务名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前不可变服务目录的无序借用迭代器，不包含实例、metadata或凭据。
    pub(crate) fn declared_service_names(&self) -> impl Iterator<Item = &str> {
        self.services.keys().map(String::as_str)
    }

    /// 业务作用：返回后台发现/预热线程的扫描间隔。该值来自 yml，可随快照热更。
    pub(crate) fn prewarm_scan_interval_ms(&self) -> u64 {
        self.prewarm_scan_interval_ms
    }

    /// 业务作用：枚举指定逻辑服务当前可用、且配置了预热策略的实例。
    ///
    /// 动态服务沿用 `instances_for` 的 freshness 门控；因此失联超 stale TTL 的旧实例不会被
    /// 重新拨号。整个方法只在后台扫描调用，target 共享 URI/TLS `Arc`，不复制 metadata。
    pub(crate) fn prewarm_targets(&self, service: &str) -> Vec<UpstreamPrewarmTarget> {
        let Some(snapshot) = self.services.get(service) else {
            return Vec::new();
        };
        let Some(policy) = snapshot.prewarm.clone() else {
            return Vec::new();
        };
        self.instances_for(service, snapshot)
            .as_slice()
            .iter()
            .filter(|instance| instance.is_selectable())
            .map(|instance| UpstreamPrewarmTarget {
                base: instance.uri.clone(),
                health_key: instance.health_key.clone(),
                protocol: instance.protocol,
                connect_timeout_ms: instance.connect_timeout_ms,
                tls_profile: instance.tls_profile.clone(),
                policy: policy.clone(),
            })
            .collect()
    }

    /// 业务作用：收集当前可能被数据面选择的 service 与完整 `health_key`，供 reload 后低频回收
    /// 常驻 LB/预算表。Nacos 超过 stale TTL 时 `instances_for` 为空，旧 identity 仅在计数为 0
    /// 且无活跃 Arc handle 后才会被调用方删除。
    pub fn runtime_identities(&self) -> (HashSet<String>, HashSet<Arc<str>>) {
        let mut services = HashSet::with_capacity(self.services.len());
        let mut identities = HashSet::new();
        for (name, service) in &self.services {
            services.insert(name.clone());
            let instances = self.instances_for(name, service);
            identities.extend(
                instances
                    .as_slice()
                    .iter()
                    .map(|instance| instance.health_key.clone()),
            );
        }
        (services, identities)
    }

    /// 业务作用：生成 Admin 只读发现视图，列出 native 与 xDS 上游的当前实例和可选择数量。
    ///
    /// Admin 只读发现视图(  「Admin UI 展示服务/实例/metadata」):列出所有上游服务及其
    /// **当前**实例(static 来自 yml,nacos 来自动态目录的 last-known-good),供管理面/运维查看拓扑与健康。
    /// 只读、不进请求热路径;实例的 `healthy` 是发现/静态标记,主动探测的不健康态由 `/metrics` 的
    /// `gw_upstream_healthy{service}` 反映(此处不并入,避免管理视图与探测器强耦合)。
    ///
    /// 参数说明：
    /// - `route_refs`：是逻辑服务到 route id 的低频反向索引。
    ///
    /// 返回：按服务名稳定排序的 JSON；不会修改发现状态或触发外部查询。
    pub fn service_view_json(
        &self,
        route_refs: &HashMap<String, Vec<String>>,
    ) -> serde_json::Value {
        // 按服务名排序,输出稳定(便于 diff / 前端展示)。
        let mut names: Vec<&String> = self.services.keys().collect();
        names.sort();
        let services: Vec<serde_json::Value> = names
            .iter()
            .map(|name| {
                let svc = &self.services[*name];
                let source = match svc.source {
                    ServiceSource::Static => "static",
                    ServiceSource::Nacos => "nacos",
                    ServiceSource::Consul => "consul",
                    ServiceSource::Eureka => "eureka",
                    ServiceSource::Dns => "dns",
                    ServiceSource::Kubernetes => "kubernetes",
                    ServiceSource::Xds => "xds",
                };
                let current_instances = self.instances_for(name, svc);
                let instances: Vec<serde_json::Value> = current_instances
                    .as_slice()
                    .iter()
                    .map(|inst| {
                        serde_json::json!({
                            "uri": inst.uri.as_ref(),
                            "weight": inst.weight,
                            "down": inst.down,
                            "backup": inst.backup,
                            "healthy": inst.healthy,
                            "tls": inst.tls_profile.is_some(),
                            "tls_profile": inst.tls_profile.as_ref().map(|tls| tls.key.as_ref().to_string()),
                            "tls_server_name": inst.tls_profile.as_ref().and_then(|tls| tls.server_name.as_ref().map(|name| name.as_ref().to_string())),
                            "metadata": inst.metadata.clone(),
                            "locality": {
                                "region": inst.region.as_deref(),
                                "zone": inst.zone.as_deref(),
                                "subzone": inst.subzone.as_deref(),
                                "rank": svc.locality.as_ref().map(|policy| policy.rank(inst)),
                                "weight_multiplier": svc.locality.as_ref().map(|policy| policy.multiplier(inst)),
                            },
                        })
                    })
                    .collect();
                // `selectable_count` 与 `instances_for` 用**同一份可用集**,再扣掉 down/未 healthy
                // 的实例:管理面要回答的是"现在还有几个能被选中",而不是"目录里登记了几个"。
                // 主动探测判死的实例不在此扣除(见本函数头注释),那条口径由 /metrics 负责。
                let selectable = current_instances
                    .as_slice().iter()
                    .filter(|inst| {
                        inst.is_selectable()
                            && svc.locality.as_ref().is_none_or(|policy| policy.rank(inst).is_some())
                    })
                    .count();
                serde_json::json!({
                    "service": name,
                    "source": source,
                    "critical": svc.critical,
                    "lb_policy": svc.lb_policy.as_str(),
                    "locality": svc.locality.as_ref().map(|policy| policy.summary()),
                    "load_feedback": {
                        "mode": svc.load_feedback.feedback.as_str(),
                        "freshness_ms": svc.load_feedback.freshness_ms,
                        "min_samples": svc.load_feedback.min_samples,
                        "out_of_band": svc.load_feedback.out_of_band.is_some(),
                    },
                    "outlier": svc.outlier,
                    "route_refs": route_refs.get(*name).cloned().unwrap_or_default(),
                    "instance_count": instances.len(),
                    "selectable_count": selectable,
                    "instances": instances,
                })
            })
            .collect();
        serde_json::json!({
            "services": services
        })
    }

    /// 业务作用：判断逻辑服务是否已在当前快照中声明。
    ///
    /// 参数说明：
    /// - `service`: `lb://service` 去掉前缀后的服务名。
    pub fn has_service(&self, service: &str) -> bool {
        self.services.contains_key(service)
    }

    /// 业务作用：返回当前目录内全部 Nacos 服务的 watch 规格。
    pub fn nacos_watch_specs(&self) -> Vec<NacosWatchSpec> {
        self.services
            .iter()
            .filter_map(|(logical_service, svc)| {
                if svc.source != ServiceSource::Nacos {
                    return None;
                }
                Some(NacosWatchSpec {
                    logical_service: logical_service.clone(),
                    nacos_service: svc.nacos_service.clone(),
                    protocol: svc.protocol,
                    scheme: svc.scheme.clone(),
                    clusters: svc.clusters.clone(),
                    slow_start_ms: svc.slow_start_ms,
                    stale_ttl_ms: svc.discovery_stale_ttl_ms,
                    tls_profile: svc.tls_profile.clone(),
                })
            })
            .collect()
    }

    /// 业务作用：枚举 Consul/Eureka/DNS/K8s 后台轮询 worker 规格，并排除 xDS 独占服务以防双写。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅 native registry 服务的不可变 watch 规格。
    pub fn registry_watch_specs(&self) -> Vec<RegistryWatchSpec> {
        self.services
            .iter()
            .filter_map(|(logical_service, svc)| {
                let kind = match svc.source {
                    ServiceSource::Consul => RegistryKind::Consul,
                    ServiceSource::Eureka => RegistryKind::Eureka,
                    ServiceSource::Dns => RegistryKind::Dns,
                    ServiceSource::Kubernetes => RegistryKind::Kubernetes,
                    ServiceSource::Static | ServiceSource::Nacos | ServiceSource::Xds => {
                        return None;
                    }
                };
                Some(RegistryWatchSpec {
                    kind,
                    logical_service: logical_service.clone(),
                    registry_service: svc.registry_service.clone(),
                    service_import: svc.registry_service_import,
                    namespace: svc.registry_namespace.clone(),
                    port: svc.registry_port,
                    port_name: svc.registry_port_name.clone(),
                    protocol: svc.protocol,
                    scheme: svc.scheme.clone(),
                    slow_start_ms: svc.slow_start_ms,
                    stale_ttl_ms: svc.discovery_stale_ttl_ms,
                    tls_profile: svc.tls_profile.clone(),
                })
            })
            .collect()
    }

    /// 业务作用：枚举当前快照由 EDS 独占端点事实的逻辑服务，供单个 ADS task 建立
    /// physical cluster 到本地 service 的确定映射。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：每个 `source: xds` 服务的一份不可变转换规格；不包含 native registry 服务。
    pub fn xds_watch_specs(&self) -> Vec<XdsWatchSpec> {
        self.services
            .iter()
            .filter(|(_, svc)| svc.source == ServiceSource::Xds)
            .map(|(logical_service, svc)| XdsWatchSpec {
                logical_service: logical_service.clone(),
                cluster_name: svc.registry_service.clone(),
                protocol: svc.protocol,
                connect_timeout_ms: 0,
                scheme: svc.scheme.clone(),
                slow_start_ms: svc.slow_start_ms,
                tls_profile: svc.tls_profile.clone(),
            })
            .collect()
    }

    /// 业务作用：枚举配置了主动健康探测的服务及其当前实例，并传递实例的
    /// 真实传输协议，供后台以与数据面相同的 H1/H2/H3 语义探测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前快照中的服务、策略与可见实例列表；未配置探测的服务不返回。
    pub fn active_health_targets(&self) -> Vec<crate::upstream::health::HealthTarget> {
        self.services
            .iter()
            .filter_map(|(name, svc)| {
                let policy = svc.active_health.clone()?;
                let current_instances = self.instances_for(name, svc);
                let instances = current_instances
                    .as_slice()
                    .iter()
                    .map(|inst| crate::upstream::health::HealthInstanceTarget {
                        key: inst.health_key.to_string(),
                        uri: inst.uri.to_string(),
                        protocol: inst.protocol,
                        tls_profile: inst.tls_profile.clone(),
                    })
                    .collect::<Vec<_>>();
                Some(crate::upstream::health::HealthTarget {
                    service: name.clone(),
                    policy,
                    instances,
                })
            })
            .collect()
    }

    /// 业务作用：读取当前服务可参与数据面的不可变实例集合，并对需要 TTL 的 native
    /// registry 执行 freshness 门禁；xDS 则保留最近一次 ACK 的 LKG。
    ///
    /// 参数说明：
    /// - `service`：是动态表 key
    /// - `svc`：是同一快照中的来源与 freshness 策略。
    ///
    /// 返回：静态来源只借用快照切片；Nacos 来源只 clone 一次 `Arc`；过期/缺失时返回空视图。
    fn instances_for<'a>(
        &'a self,
        service: &str,
        svc: &'a ServiceSnapshot,
    ) -> UpstreamInstances<'a> {
        match svc.source {
            ServiceSource::Static => UpstreamInstances::Static(&svc.instances),
            // Nacos 实例也按 freshness 门控，让「选实例」与「readyz」读到一致的可用集。
            //   stale_ttl 内(watch 活着,由 touch_service 保鲜)沿用 last-known-good;超时(watch 失联太久)
            //   视为空 → select 返 None → 降级( watch 契约:超过 stale_ttl 进 degraded/empty,而非无限用旧实例)。
            //   若不门控,watch 死后 readyz 已 503、select 却还在转发到可能已消失的实例,二者不一致。
            ServiceSource::Nacos
            | ServiceSource::Consul
            | ServiceSource::Eureka
            | ServiceSource::Dns
            | ServiceSource::Kubernetes
            | ServiceSource::Xds => {
                if self
                    .dynamic
                    .service_fresh(service, svc.discovery_stale_ttl_ms)
                {
                    self.dynamic
                        .service_instances(service)
                        .map(UpstreamInstances::Dynamic)
                        .unwrap_or(UpstreamInstances::Empty)
                } else {
                    UpstreamInstances::Empty
                }
            }
        }
    }
}

/// 一次目录读取的实例视图。
///
/// 静态实例借用当前 `GatewaySnapshot`；动态实例持有发现侧发布的 `Arc`。两种分支都可安全跨越
/// 单次同步选择过程，且不会为了统一返回类型深拷贝实例列表。
enum UpstreamInstances<'a> {
    /// 借用配置快照中的静态实例切片。
    Static(&'a [Arc<UpstreamInstance>]),
    /// 持有 Nacos 最新不可变实例切片。
    Dynamic(Arc<[Arc<UpstreamInstance>]>),
    /// 服务没有新鲜实例。
    Empty,
}

impl UpstreamInstances<'_> {
    /// 业务作用：把不同所有权分支统一成只读切片，供 LB 同步扫描。
    ///
    /// 返回：有效期绑定到当前实例视图；不会 clone 或分配。
    fn as_slice(&self) -> &[Arc<UpstreamInstance>] {
        match self {
            Self::Static(instances) => instances,
            Self::Dynamic(instances) => instances,
            Self::Empty => &[],
        }
    }

    /// 业务作用：取得拥有所有权的实例切片,供一致性哈希表缓存按指针身份绑定代际。
    ///
    /// 参数说明：
    /// - `svc`：提供静态分支的原始 `Arc`。
    ///
    /// 返回：当前实例切片的共享句柄;无实例时返回 `None`。
    fn as_arc(&self, svc: &ServiceSnapshot) -> Option<Arc<[Arc<UpstreamInstance>]>> {
        match self {
            Self::Static(_) => Some(svc.instances.clone()),
            Self::Dynamic(instances) => Some(instances.clone()),
            Self::Empty => None,
        }
    }
}

/// 一个服务在单份不可变配置快照中的路由、重试、健康与发现策略。
///
/// 结构只在构建/reload 时创建；数据面通过 `GatewaySnapshot` 借用，不逐请求 clone。
#[derive(Clone)]
pub struct ServiceSnapshot {
    /// true 表示该服务无可用实例时 `/readyz` 必须失败。
    pub critical: bool,
    /// 实例来自静态 yml 还是 Nacos 动态目录。
    pub source: ServiceSource,
    /// primary/backup 候选内部使用的负载均衡算法。
    pub lb_policy: LbPolicy,
    /// 一致性哈希键来源与表参数;`ring_hash`/`maglev` 必需,其它策略为 None。
    pub hash: Option<LbHashPolicy>,
    /// 服务级会话保持;route 级策略优先于它(Gateway API 语义)。
    pub session_affinity: Option<SessionAffinityPolicy>,
    /// 后端负载反馈策略;`none` 时数据面不采集也不读取任何反馈状态。
    pub load_feedback: crate::upstream::load::LoadFeedbackPolicy,
    /// backend 级 retry budget;None 表示重试只受 `next_upstream_tries` 约束。
    pub retry_budget: Option<crate::runtime::admission::RetryBudgetPolicy>,
    /// 自适应并发策略;None 表示不做在途上限调节。
    pub adaptive_concurrency: Option<crate::runtime::admission::AdaptiveConcurrencyPolicy>,
    /// 连接/超时/指定 5xx 时的跨实例重试策略。
    pub next_upstream: NextUpstreamPolicy,
    /// 连续失败阈值和临时摘除窗口。
    pub passive_health: PassiveHealthPolicy,
    pub outlier: Option<passive::policy::Policy>,
    /// 主动健康探测策略;None = 未配置该服务的 health_check。
    pub active_health: Option<crate::upstream::health::ActiveHealthPolicy>,
    /// 新实例进入目录后使用对应 H1/H2/H2c/H3 业务池执行的一次性连接预热；None = 关闭。
    pub prewarm: Option<UpstreamPrewarmPolicy>,
    /// 可信拓扑候选分层与有效份额；None 保持全实例 LB。
    locality: Option<UpstreamLocalityPolicy>,
    /// 静态实例的不可变共享切片；每请求 LB 扫描只借用，不 clone 整表。
    pub instances: Arc<[Arc<UpstreamInstance>]>,
    /// 服务默认上游 HTTP 协议；构建实例时复制，避免请求期解析字符串。
    pub protocol: UpstreamProtocol,
    /// 服务级 HTTP 上游 TLS profile;static 与 Nacos 动态实例都会继承它。
    pub tls_profile: Option<UpstreamTlsProfile>,
    /// Nacos 物理服务名；可与网关逻辑服务名不同。
    pub nacos_service: String,
    /// Consul/Eureka/K8s 物理 service 名或 DNS host。
    pub registry_service: String,
    /// 是否使用 MCS ServiceImport 的 EndpointSlice label，且不回退 legacy Endpoints。
    pub registry_service_import: bool,
    /// K8s namespace 覆盖。
    pub registry_namespace: Option<String>,
    /// DNS 端口。
    pub registry_port: Option<u16>,
    /// K8s Endpoints 端口名。
    pub registry_port_name: Option<String>,
    /// Nacos 实例未显式 URI 时使用的 scheme。
    pub scheme: String,
    /// Nacos 订阅的 cluster 过滤列表。
    pub clusters: Vec<String>,
    /// 动态发现新实例的默认 slow-start 时长(ms)。
    pub slow_start_ms: u64,
    /// Nacos watch 失联后 last-known-good 最长可用时间(ms)。
    pub discovery_stale_ttl_ms: u64,
}

/// 构建期校验后的连接预热策略。
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamPrewarmPolicy {
    /// 每个实例期望预建的空闲连接数。
    pub connections: usize,
    /// 不含 authority 的固定 HEAD 探测 path。
    pub path: Arc<str>,
    /// 单批预热等待响应头的 deadline，单位毫秒。
    pub timeout_ms: u64,
}

impl UpstreamPrewarmPolicy {
    /// 业务作用：编译连接预热的并发和时间预算，关闭时不创建后台建连负载。
    fn parse(cfg: &UpstreamPrewarmCfg, service: &str) -> Result<Self> {
        anyhow::ensure!(
            (1..=32).contains(&cfg.connections),
            "service `{service}` prewarm.connections must be within 1..=32"
        );
        anyhow::ensure!(
            (10..=60_000).contains(&cfg.timeout_ms),
            "service `{service}` prewarm.timeout_ms must be within 10..=60000"
        );
        let path: http::uri::PathAndQuery = cfg
            .path
            .parse()
            .with_context(|| format!("service `{service}` prewarm.path"))?;
        anyhow::ensure!(
            path.path().starts_with('/') && cfg.path.len() <= 8 * 1024,
            "service `{service}` prewarm.path must be an absolute path <= 8192 bytes"
        );
        Ok(Self {
            connections: cfg.connections,
            path: Arc::from(cfg.path.as_str()),
            timeout_ms: cfg.timeout_ms,
        })
    }
}

/// 一次后台预热所需的共享实例身份。URI/TLS 配置只 clone `Arc`，不深拷贝证书或 metadata。
#[derive(Clone)]
pub(crate) struct UpstreamPrewarmTarget {
    pub base: Arc<str>,
    pub health_key: Arc<str>,
    pub protocol: UpstreamProtocol,
    pub connect_timeout_ms: u64,
    pub tls_profile: Option<UpstreamTlsProfile>,
    pub policy: UpstreamPrewarmPolicy,
}

/// 一个逻辑服务的实例事实来源。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSource {
    /// 主配置内声明的静态实例。
    Static,
    /// Nacos push/watch 实例。
    Nacos,
    /// Consul Health API 实例。
    Consul,
    /// Eureka 应用实例。
    Eureka,
    /// 系统 DNS A/AAAA 地址。
    Dns,
    /// Kubernetes Endpoints 实例。
    Kubernetes,
    /// xDS v3 EDS ClusterLoadAssignment 实例。
    Xds,
}

impl ServiceSource {
    /// 业务作用：把声明式服务来源编译成封闭枚举，防止未知 provider 在运行期退化成静态服务。
    ///
    /// 参数说明：
    /// - `raw`：是 `upstreams.services.*.source` 的规范小写值。
    ///
    /// 返回：已支持来源返回枚举；未知值返回带允许集合的构建错误。
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "static" | "" => Ok(Self::Static),
            "nacos" => Ok(Self::Nacos),
            "consul" => Ok(Self::Consul),
            "eureka" => Ok(Self::Eureka),
            "dns" => Ok(Self::Dns),
            "k8s" | "kubernetes" => Ok(Self::Kubernetes),
            "xds" => Ok(Self::Xds),
            other => anyhow::bail!(
                "unsupported upstream source `{other}` (static|nacos|consul|eureka|dns|kubernetes|xds)"
            ),
        }
    }
}

/// Nacos 后台订阅一个逻辑服务所需的不可变规格。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NacosWatchSpec {
    /// gateway 配置中的逻辑服务名。
    pub logical_service: String,
    /// Nacos 中的物理服务名。
    pub nacos_service: String,
    /// 转发使用的上游 HTTP 协议。
    pub protocol: UpstreamProtocol,
    /// 无显式 metadata URI 时拼接的 scheme。
    pub scheme: String,
    /// 允许订阅的 Nacos cluster 集合；空表示全部。
    pub clusters: Vec<String>,
    /// 新实例默认 slow-start 时长。
    pub slow_start_ms: u64,
    /// watch 失联后 last-known-good 最长保留时间。
    pub stale_ttl_ms: u64,
    /// 动态 HTTPS 实例共享的已验证 TLS profile。
    pub tls_profile: Option<UpstreamTlsProfile>,
}

/// EDS ClusterLoadAssignment 到一个本地逻辑服务的不可变转换规格。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct XdsWatchSpec {
    /// gateway 配置中的逻辑服务名。
    pub logical_service: String,
    /// management server 发布的 EDS cluster 名；缺省等于逻辑服务名。
    pub cluster_name: String,
    /// 转发使用的上游 HTTP 协议。
    pub protocol: UpstreamProtocol,
    /// CDS Cluster.connect_timeout；0 仅用于 EDS-only native cluster profile，保持既有连接行为。
    pub connect_timeout_ms: u64,
    /// EDS socket address 拼接 URI 时使用的 scheme。
    pub scheme: String,
    /// 新实例默认 slow-start 时长。
    pub slow_start_ms: u64,
    /// 动态 HTTPS 实例共享的已验证 TLS profile。
    pub tls_profile: Option<UpstreamTlsProfile>,
}

/// 非 Nacos 服务发现后端类型。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RegistryKind {
    /// Consul Health API。
    Consul,
    /// Eureka JSON API。
    Eureka,
    /// 系统 DNS resolver。
    Dns,
    /// Kubernetes Endpoints API。
    Kubernetes,
}

/// 后台轮询一个非 Nacos 逻辑服务所需的不可变规格。
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RegistryWatchSpec {
    /// 使用的注册中心后端。
    pub kind: RegistryKind,
    /// gateway 配置中的逻辑服务名。
    pub logical_service: String,
    /// 注册中心中的物理服务名或 DNS host。
    pub registry_service: String,
    /// Kubernetes worker 是否解析 MCS ServiceImport 派生 EndpointSlice。
    pub service_import: bool,
    /// Kubernetes namespace 覆盖。
    pub namespace: Option<String>,
    /// DNS 或 Kubernetes 数字端口。
    pub port: Option<u16>,
    /// Kubernetes 命名端口。
    pub port_name: Option<String>,
    /// 转发使用的上游 HTTP 协议。
    pub protocol: UpstreamProtocol,
    /// 实例 URI 使用的 scheme。
    pub scheme: String,
    /// 新实例默认 slow-start 时长。
    pub slow_start_ms: u64,
    /// 后端失联后 last-known-good 最长保留时间。
    pub stale_ttl_ms: u64,
    /// 动态 HTTPS 实例共享的已验证 TLS profile。
    pub tls_profile: Option<UpstreamTlsProfile>,
}

/// 非 Nacos 后端解析后的 provider-neutral 实例。
pub struct RegistryInstance {
    /// IP 字面量或已校验主机名。
    pub host: String,
    /// 服务端口。
    pub port: u16,
    /// 负载均衡权重；0 不参与主候选调度。
    pub weight: u32,
    /// 是否被注册中心或 metadata 强制下线。
    pub down: bool,
    /// 是否仅作为主实例不可用时的备用实例。
    pub backup: bool,
    /// 有界 provider metadata，仅供管理面展示和固定字段解释。
    pub metadata: HashMap<String, String>,
}

/// 一个逻辑服务的数据面负载均衡算法。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    /// 始终选择第一个可用候选。
    First,
    /// 按实例权重做平滑之外的低成本轮转选择。
    RoundRobin,
    /// 选择当前活动请求数最少的候选。
    LeastConn,
    /// 按权重随机选择;无状态、无共享游标,适合多进程/多节点同构部署。
    Random,
    /// power-of-two-choices:随机取两个候选,选在途请求/权重比更低者。
    /// 比全局 `least_conn` 少一次全候选扫描,且抗「羊群涌向同一最空实例」。
    WeightedLeastRequest,
    /// ketama 风格加权虚拟节点环;扩缩容只迁移该实例自身承担的 key。
    RingHash,
    /// Maglev 查找表;一致性与 ring 同级,份额分布更均匀,查找为 O(1)。
    Maglev,
}

impl LbPolicy {
    /// 业务作用：管理面展示用的稳定名称。刻意与 [`LbPolicy::parse`] 接受的**规范**写法一致
    /// (而不是别名 `wrr`/`least-conn`),使 `/admin/upstreams` 的输出可以原样写回配置。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::RoundRobin => "round_robin",
            Self::LeastConn => "least_conn",
            Self::Random => "random",
            Self::WeightedLeastRequest => "weighted_least_request",
            Self::RingHash => "ring_hash",
            Self::Maglev => "maglev",
        }
    }

    /// 业务作用：判断负载均衡策略是否依赖请求期哈希键，供构建期关闭无键退化路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：一致性哈希策略返回 true；其它策略返回 false。
    pub fn requires_hash_key(self) -> bool {
        matches!(self, Self::RingHash | Self::Maglev)
    }

    /// 业务作用：判断策略是否需要实例在途计数，避免无关算法维护额外热路径状态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`least_conn` 与 P2C 返回 true；其它策略返回 false。
    pub fn uses_inflight(self) -> bool {
        matches!(self, Self::LeastConn | Self::WeightedLeastRequest)
    }

    /// 业务作用：解析支持的负载均衡策略，未知名称不能静默退化成默认选择器。
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "first" => Ok(Self::First),
            "round_robin" | "round-robin" | "weighted" | "wrr" => Ok(Self::RoundRobin),
            "least_conn" | "least-conn" => Ok(Self::LeastConn),
            "random" => Ok(Self::Random),
            "weighted_least_request" | "weighted-least-request" | "least_request" | "p2c" => {
                Ok(Self::WeightedLeastRequest)
            }
            "ring_hash" | "ring-hash" | "ketama" => Ok(Self::RingHash),
            "maglev" => Ok(Self::Maglev),
            // `ip_hash` 是「以 remote_addr 为 hash key 的 ring_hash」的特例,由构建期
            // 展开成 ring_hash + hash_on=remote_addr,不在数据面另立一套选择路径。
            "ip_hash" | "ip-hash" => Ok(Self::RingHash),
            other => anyhow::bail!("unsupported lb policy `{other}`"),
        }
    }
}

/// 一致性哈希与会话保持的哈希键来源。
///
/// 只允许受控来源:未经信任的任意高基数字段会把哈希环与会话表变成放大面,
/// 也会让攻击者按需把流量钉到指定实例。header/cookie/变量名都必须在构建期声明。
#[derive(Clone, PartialEq, Eq)]
pub enum LbHashSource {
    /// 已完成鉴权的 consumer 身份;未认证请求视为无键。
    Consumer,
    /// 可信请求头的值;名字由配置固定,不接受请求期指定。
    Header(Arc<str>),
    /// 指定 cookie 的值。
    Cookie(Arc<str>),
    /// 经可信代理链与连接元数据判定的真实客户端 IP。
    RemoteAddr,
    /// 已编译变量的求值结果。
    Variable(Arc<str>),
}

impl LbHashSource {
    /// 业务作用：把已编译哈希来源还原为管理面展示和配置回写使用的稳定名称。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回不含运行态值的配置语义字符串。
    pub fn as_display(&self) -> String {
        match self {
            Self::Consumer => "consumer".to_string(),
            Self::Header(name) => format!("header:{name}"),
            Self::Cookie(name) => format!("cookie:{name}"),
            Self::RemoteAddr => "remote_addr".to_string(),
            Self::Variable(name) => format!("var:{name}"),
        }
    }

    /// 业务作用：解析配置声明的哈希来源,把不受支持的写法在构建期挡下。
    ///
    /// 参数说明：
    /// - `raw`：是 `hash_on` 原文。
    ///
    /// 返回：受支持来源;前缀未知或名字为空时返回错误。
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.eq_ignore_ascii_case("consumer") {
            return Ok(Self::Consumer);
        }
        if raw.eq_ignore_ascii_case("remote_addr") || raw.eq_ignore_ascii_case("remote-addr") {
            return Ok(Self::RemoteAddr);
        }
        for (prefix, build) in [
            (
                "header:",
                (|name: &str| Self::Header(name.into())) as fn(&str) -> Self,
            ),
            ("cookie:", |name: &str| Self::Cookie(name.into())),
            ("var:", |name: &str| Self::Variable(name.into())),
        ] {
            if let Some(name) = raw.strip_prefix(prefix) {
                let name = name.trim();
                anyhow::ensure!(!name.is_empty(), "lb hash_on `{raw}` 缺少名字");
                anyhow::ensure!(
                    name.len() <= 128 && name.chars().all(|c| c.is_ascii_graphic()),
                    "lb hash_on `{raw}` 名字必须是不超过 128 字节的可见 ASCII"
                );
                return Ok(build(name));
            }
        }
        anyhow::bail!(
            "unsupported lb hash_on `{raw}`(仅 consumer / remote_addr / header:<name> / cookie:<name> / var:<name>)"
        )
    }
}

/// 一致性哈希策略的键来源与表参数。
#[derive(Clone, PartialEq, Eq)]
pub struct LbHashPolicy {
    /// 哈希键来源。
    pub source: LbHashSource,
    /// ring-hash 每单位权重的虚拟节点数。
    pub replicas_per_weight: u32,
    /// Maglev 查找表长度(构建期归一到质数)。
    pub table_size: usize,
}

/// 会话保持的载体形态。
#[derive(Clone, PartialEq, Eq)]
pub enum SessionAffinityMode {
    /// 由网关生成并下发 cookie;客户端后续请求带回。
    Cookie {
        /// cookie 名。
        name: Arc<str>,
        /// 兼容原生配置的滚动有效期（秒）；0 表示不使用滚动 `Max-Age`。
        ttl_seconds: u64,
        /// 是否按绝对期限下发持久 cookie；开启后 `Max-Age` 只能递减。
        permanent: bool,
        /// 可选 `Path` 属性；backend 级策略必须省略，避免错误限制到某一条 Route。
        path: Option<Arc<str>>,
        /// 可选 `Domain` 属性。
        domain: Option<Arc<str>>,
        /// `SameSite` 属性,默认 `Lax`。
        same_site: Arc<str>,
        /// 是否置 `Secure`,默认开。
        secure: bool,
        /// 是否置 `HttpOnly`,默认开。
        http_only: bool,
    },
    /// 由客户端在指定请求头携带亲和令牌;网关在响应同名头回写。
    Header {
        /// 请求/响应头名。
        name: Arc<str>,
    },
}

/// 已校验的会话保持策略。
#[derive(Clone, PartialEq, Eq)]
pub struct SessionAffinityPolicy {
    /// 载体形态与属性。
    pub mode: SessionAffinityMode,
    /// 从首次建立会话起计算的绝对期限（秒）；0 表示关闭。
    pub absolute_timeout_seconds: u64,
    /// 从客户端最近一次有效使用令牌起计算的空闲期限（秒）；0 表示关闭。
    pub idle_timeout_seconds: u64,
}

/// 已解析且通过期限校验的会话保持令牌。
#[derive(Clone, Copy)]
pub struct SessionAffinityToken {
    /// 当前会话绑定的健康实例身份哈希。
    pub endpoint_hash: u64,
    /// 首次建立会话的 Unix 秒时间戳；无期限的兼容令牌为 0。
    pub issued_at_seconds: u64,
    /// 客户端上次获得令牌的 Unix 秒时间戳；无期限的兼容令牌为 0。
    pub touched_at_seconds: u64,
}

impl SessionAffinityPolicy {
    /// 业务作用：由实例身份派生**不可反推后端地址**的稳定亲和令牌。
    ///
    /// 采用无状态令牌而非服务端会话表：跨节点无需共享存储。启用绝对或空闲期限时，
    /// 令牌同时携带首次建立和最近使用时间；令牌不作为认证凭据，实际目标仍必须命中
    /// 当前服务的健康授权实例，因此客户端改写令牌不能构造任意上游地址。
    ///
    /// 参数说明：
    /// - `uri`：是实例的规范化 URI
    /// - `previous`：是本请求通过期限校验的旧令牌
    /// - `now_seconds`：是当前 Unix 秒。
    ///
    /// 返回：返回可下发文本及其结构化时间事实；无期限时文本保持十六位兼容格式。
    pub fn token_for(
        &self,
        uri: &str,
        previous: Option<SessionAffinityToken>,
        now_seconds: u64,
    ) -> (String, SessionAffinityToken) {
        let endpoint_hash = crate::upstream::hash::stable_hash(uri.as_bytes());
        if self.absolute_timeout_seconds == 0 && self.idle_timeout_seconds == 0 {
            let token = SessionAffinityToken {
                endpoint_hash,
                issued_at_seconds: 0,
                touched_at_seconds: 0,
            };
            return (format!("{endpoint_hash:016x}"), token);
        }
        let issued_at_seconds = previous
            .filter(|token| token.endpoint_hash == endpoint_hash)
            .map(|token| token.issued_at_seconds)
            .filter(|issued| *issued <= now_seconds)
            .unwrap_or(now_seconds);
        let token = SessionAffinityToken {
            endpoint_hash,
            issued_at_seconds,
            touched_at_seconds: now_seconds,
        };
        (
            format!("{endpoint_hash:016x}.{issued_at_seconds:016x}.{now_seconds:016x}"),
            token,
        )
    }

    /// 业务作用：解析客户端带回的会话令牌并执行绝对、空闲期限门禁，过期令牌不得
    /// 继续绕过常规负载均衡。
    ///
    /// 参数说明：
    /// - `raw`：是 cookie 或请求头中的原始值
    /// - `now_seconds`：是当前 Unix 秒。
    ///
    /// 返回：结构和期限均有效时返回实例及时间事实；其它情况返回 `None` 并回落常规 LB。
    pub fn parse_token(&self, raw: &str, now_seconds: u64) -> Option<SessionAffinityToken> {
        let raw = raw.trim();
        if self.absolute_timeout_seconds == 0 && self.idle_timeout_seconds == 0 {
            if raw.len() != 16 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            return u64::from_str_radix(raw, 16)
                .ok()
                .map(|endpoint_hash| SessionAffinityToken {
                    endpoint_hash,
                    issued_at_seconds: 0,
                    touched_at_seconds: 0,
                });
        }
        let mut fields = raw.split('.');
        let endpoint_hash = parse_affinity_token_field(fields.next()?)?;
        let issued_at_seconds = parse_affinity_token_field(fields.next()?)?;
        let touched_at_seconds = parse_affinity_token_field(fields.next()?)?;
        if fields.next().is_some()
            || issued_at_seconds > now_seconds
            || touched_at_seconds < issued_at_seconds
            || touched_at_seconds > now_seconds
        {
            return None;
        }
        if self.absolute_timeout_seconds > 0
            && now_seconds.saturating_sub(issued_at_seconds) >= self.absolute_timeout_seconds
        {
            return None;
        }
        if self.idle_timeout_seconds > 0
            && now_seconds.saturating_sub(touched_at_seconds) >= self.idle_timeout_seconds
        {
            return None;
        }
        Some(SessionAffinityToken {
            endpoint_hash,
            issued_at_seconds,
            touched_at_seconds,
        })
    }

    /// 业务作用：计算持久 cookie 在当前响应时仍可暴露的剩余绝对有效期，防止重复
    /// `Set-Cookie` 把 `absoluteTimeout` 误变成滚动期限。
    ///
    /// 参数说明：
    /// - `token`：是即将下发的新令牌
    /// - `now_seconds`：是同一响应固定读取的 Unix 秒。
    ///
    /// 返回：持久 cookie 返回至少一秒且不超过绝对期限的 `Max-Age`；其它模式返回 `None`。
    pub fn permanent_cookie_max_age(
        &self,
        token: SessionAffinityToken,
        now_seconds: u64,
    ) -> Option<u64> {
        let SessionAffinityMode::Cookie {
            permanent: true,
            ..
        } = &self.mode
        else {
            return None;
        };
        let elapsed = now_seconds.saturating_sub(token.issued_at_seconds);
        Some(self.absolute_timeout_seconds.saturating_sub(elapsed).max(1))
    }
}

/// 业务作用：解析定长十六进制令牌字段，避免宽松整数解析接受符号、空白或超长输入。
///
/// 参数说明：
/// - `raw`：是单个 endpoint 或时间戳字段。
///
/// 返回：恰好十六位十六进制时返回数值，否则返回 `None`。
fn parse_affinity_token_field(raw: &str) -> Option<u64> {
    if raw.len() != 16 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(raw, 16).ok()
}

/// 单次选择的请求期提示:一致性哈希键与会话亲和令牌。
///
/// 两者都是**可选**的:缺失时选择完全退回既有 LB,不产生失败。
#[derive(Clone, Copy, Default)]
pub struct LbSelectHints {
    /// 由配置来源算好的稳定哈希键。
    pub hash: Option<u64>,
    /// 客户端带回的会话亲和令牌。
    pub affinity: Option<SessionAffinityToken>,
}

/// `proxy_next_upstream` 的触发条件、尝试预算和退避策略。
#[derive(Clone, PartialEq, Eq)]
pub struct NextUpstreamPolicy {
    /// 连接或传输错误是否换实例。
    pub error: bool,
    /// deadline 超时是否换实例。
    pub timeout: bool,
    /// HTTP 502 是否换实例。
    pub http_502: bool,
    /// HTTP 503 是否换实例。
    pub http_503: bool,
    /// HTTP 504 是否换实例。
    pub http_504: bool,
    /// 非幂等请求是否也允许重试。
    pub non_idempotent: bool,
    /// 最大实际上游尝试数；0 表示受候选数限制而不另设上限。
    pub tries: usize,
    /// 相邻尝试之间的异步退避，单位毫秒。
    pub backoff_ms: u64,
}

impl NextUpstreamPolicy {
    /// 业务作用：编译重试触发条件、次数和退避，保证失败转移具有明确上限。
    fn parse(raw: Option<&[String]>, tries: usize, backoff_ms: u64) -> Result<Self> {
        let Some(items) = raw else {
            let mut policy = Self::default_retry();
            policy.tries = tries;
            policy.backoff_ms = backoff_ms;
            return Ok(policy);
        };
        let mut policy = Self::disabled();
        policy.tries = tries;
        policy.backoff_ms = backoff_ms;
        for item in items {
            match item.trim() {
                "" => {}
                "off" | "none" => {}
                "error" => policy.error = true,
                "timeout" => policy.timeout = true,
                "http_502" => policy.http_502 = true,
                "http_503" => policy.http_503 = true,
                "http_504" => policy.http_504 = true,
                "non_idempotent" => policy.non_idempotent = true,
                other => anyhow::bail!("unsupported next_upstream condition `{other}`"),
            }
        }
        Ok(policy)
    }

    /// 业务作用：为未显式声明的 `retry` 提供统一缺省策略，使配置反序列化与手动构造使用相同初值。
    fn default_retry() -> Self {
        Self {
            error: true,
            timeout: true,
            http_502: true,
            http_503: true,
            http_504: true,
            non_idempotent: false,
            tries: 3,
            backoff_ms: 0,
        }
    }

    /// 业务作用：构造不重试的转发策略，确保关闭重试时只执行一次上游尝试。
    fn disabled() -> Self {
        Self {
            error: false,
            timeout: false,
            http_502: false,
            http_503: false,
            http_504: false,
            non_idempotent: false,
            tries: 3,
            backoff_ms: 0,
        }
    }

    /// 业务作用：是否配置了至少一种实际重试触发条件。
    pub fn has_trigger(&self) -> bool {
        self.error || self.timeout || self.http_502 || self.http_503 || self.http_504
    }

    /// 业务作用：将配置的 tries 转换成内部最大尝试数。
    pub fn max_attempts(&self) -> usize {
        if self.tries == 0 {
            usize::MAX
        } else {
            self.tries.max(1)
        }
    }
}

/// 实例连续失败达到阈值后的临时摘除策略。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PassiveHealthPolicy {
    /// 触发摘除所需的连续失败数；0 关闭。
    pub max_fails: u32,
    /// 摘除持续时间，单位毫秒。
    pub fail_timeout_ms: u64,
}

impl PassiveHealthPolicy {
    /// 业务作用：返回不记录失败、也不摘除实例的策略。
    pub fn disabled() -> Self {
        Self {
            max_fails: 0,
            fail_timeout_ms: 0,
        }
    }

    /// 业务作用：策略是否同时具备非零阈值和摘除时长。
    pub fn enabled(self) -> bool {
        self.max_fails > 0 && self.fail_timeout_ms > 0
    }
}

/// 上游协议选择；记录协议与 HTTP 使用独立连接池身份。
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// 自动:普通 http 走 h1;gRPC(content-type=application/grpc)走 h2。
    Auto,
    /// 强制 HTTP/1.1。
    H1,
    /// 强制 HTTP/2(TLS 上游经 ALPN 协商 h2)。
    H2,
    /// 强制明文 HTTP/2 prior-knowledge(h2c)。
    H2c,
    /// 强制 HTTP/3 over QUIC；只允许 https:// 实例且要求编译 `http3` feature。
    H3,
    Fastcgi,
    Uwsgi,
    Scgi,
}

impl UpstreamProtocol {
    /// 业务作用：隔离固定脚本 transport 与 HTTP 专用外呼。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该协议是否属于 CGI 记录协议。
    pub(crate) fn is_cgi(self) -> bool {
        matches!(self, Self::Fastcgi | Self::Uwsgi | Self::Scgi)
    }

    /// 业务作用：将声明解析为已编译协议，防止静默降级。
    ///
    /// 参数说明：
    /// - `raw`：服务配置协议名。
    ///
    /// 返回：已知且 feature 可用的协议；未知或未启用时拒绝。
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "auto" => Ok(Self::Auto),
            "h1" | "http1" | "http/1.1" => Ok(Self::H1),
            "h2" | "http2" => Ok(Self::H2),
            "h2c" => Ok(Self::H2c),
            "fastcgi" | "uwsgi" | "scgi" => {
                let (kind, value) = match raw {
                    "fastcgi" => (crate::config::cgi::Protocol::Fastcgi, Self::Fastcgi),
                    "uwsgi" => (crate::config::cgi::Protocol::Uwsgi, Self::Uwsgi),
                    _ => (crate::config::cgi::Protocol::Scgi, Self::Scgi),
                };
                kind.validate_feature()?;
                Ok(value)
            }
            "h3" | "http3" => {
                #[cfg(feature = "http3")]
                {
                    Ok(Self::H3)
                }
                #[cfg(not(feature = "http3"))]
                {
                    anyhow::bail!(
                        "upstream protocol h3 requires a binary compiled with feature `http3`"
                    )
                }
            }
            other => {
                anyhow::bail!("unsupported upstream protocol `{other}` (auto|h1|h2|h2c|h3|fastcgi|uwsgi|scgi)")
            }
        }
    }
}

/// 发现侧发布的单个逻辑上游实例。
///
/// URI、身份键与 TLS profile 在配置/发现版本内不可变并通过 `Arc` 共享；请求选择只 clone 外层
/// `Arc<UpstreamInstance>`，避免把 metadata 和证书配置深拷贝进热路径。
#[derive(Clone)]
pub struct UpstreamInstance {
    /// 实际 dial 的规范化 URI；存入快照后只通过 `Arc` 在请求间共享。
    pub uri: Arc<str>,
    /// 主动健康检查状态 key。默认等于 uri;有 TLS profile 时纳入 profile key,避免不同上游 TLS 策略串状态。
    pub health_key: Arc<str>,
    /// 发现/静态配置声明的基础健康标记；主动与被动健康状态在常驻运行表中叠加。
    pub healthy: bool,
    /// WRR 基础权重；构建期保证至少为 1。
    pub weight: u32,
    /// true 表示运维强制下线，任何 LB 策略都不得选择。
    pub down: bool,
    /// true 表示仅在全部 primary 不可用时参与选择。
    pub backup: bool,
    /// 新实例从低权重逐步升到配置权重的时长(ms)。
    pub slow_start_ms: u64,
    /// 实例首次出现的时刻；同一身份的发现刷新会保留它，避免 slow-start 重置。
    created_at: Instant,
    /// 同地址退场再入场时递增的进程内代际，不依赖时钟分辨率区分两次加入。
    feedback_generation: u64,
    /// 控制面一次构造的服务内反馈身份；同一 endpoint 被多个逻辑服务引用时策略互不污染。
    feedback_key: Arc<str>,
    /// 上游 HTTP 协议偏好,由所属服务复制而来,转发层据此设请求版本。
    pub protocol: UpstreamProtocol,
    /// 建立 TCP transport 的独立超时；0 沿用 native connector 既有行为。
    pub connect_timeout_ms: u64,
    /// HTTP 上游 TLS profile( `proxy_ssl_*`),仅对 `https://` 实例生效。
    pub tls_profile: Option<UpstreamTlsProfile>,
    /// 可信配置/发现提供的 locality zone；None 表示未声明。
    pub zone: Option<Arc<str>>,
    /// 可信实例 region，缺失时不能作为分层模型的本区证据。
    pub region: Option<Arc<str>>,
    /// 可信实例 subzone，只有精确声明才享有本 subzone 优先。
    pub subzone: Option<Arc<str>>,
    /// 注册中心 metadata 或静态空 metadata;只供 admin 只读展示,不进入 metrics label。
    pub metadata: HashMap<String, String>,
}

impl UpstreamInstance {
    /// 业务作用：在目录发布前绑定服务内反馈身份，保留原健康和连接池身份不变。
    ///
    /// 参数说明：
    /// - `service`：拥有该实例的逻辑服务名。
    ///
    /// 返回：只在控制面分配一次键；长度前缀防止服务名与地址组合产生歧义。
    fn bind_feedback_service(&mut self, service: &str) {
        self.feedback_key = Arc::from(format!("{}:{service}{}", service.len(), self.health_key));
    }

    /// 业务作用：把静态实例及其可信 region/zone/subzone 注入统一实例模型，使静态与发现来源共享相同
    /// 的协议、TLS、健康身份和 locality 选择语义。
    ///
    /// 参数说明：
    /// - `cfg`：是静态实例声明
    /// - `protocol`：来自所属 service。
    /// - `tls_profile`：来自所属 service。
    ///
    /// 返回：URI、协议、TLS 与拓扑标签全部合法时返回实例，否则拒绝候选快照。
    fn try_from_cfg(
        cfg: &StaticInstanceCfg,
        protocol: UpstreamProtocol,
        tls_profile: Option<UpstreamTlsProfile>,
    ) -> Result<Self> {
        let mut metadata = HashMap::new();
        if let Some(zone) = &cfg.zone {
            metadata.insert("zone".to_owned(), zone.clone());
        }
        if let Some(region) = &cfg.region {
            metadata.insert("region".to_owned(), region.clone());
        }
        if let Some(subzone) = &cfg.subzone {
            metadata.insert("subzone".to_owned(), subzone.clone());
        }
        Self::try_from_parts(
            &cfg.uri,
            cfg.healthy,
            cfg.weight,
            cfg.down,
            cfg.backup,
            cfg.slow_start_ms,
            protocol,
            0,
            tls_profile,
            metadata,
            Instant::now(),
        )
    }

    // 参数逐项对应注册中心实例属性;保持此构造入口可读比把它们塞进位置不明的 tuple 更重要。
    #[allow(clippy::too_many_arguments)]
    /// 业务作用：从发现后端的规范化属性构造动态实例，并校验 URI、协议、TLS 与可信
    /// locality metadata，防止坏发现快照进入 LB。
    ///
    /// 参数说明：
    /// - `uri`：是规范化 endpoint
    /// - `weight`：是调度属性
    /// - `down`：是调度属性
    /// - `backup`：是调度属性
    /// - `slow_start_ms`：是调度属性
    /// - `protocol`：来自服务策略
    /// - `connect_timeout_ms`：来自服务策略
    /// - `tls_profile`：来自服务策略
    /// - `metadata`：携带只读发现属性与可选 region/zone/subzone。
    ///
    /// 返回：全部属性合法时返回带新加入时刻的实例，否则返回错误并保留旧发现版本。
    pub fn try_dynamic(
        uri: String,
        weight: u32,
        down: bool,
        backup: bool,
        slow_start_ms: u64,
        protocol: UpstreamProtocol,
        connect_timeout_ms: u64,
        tls_profile: Option<UpstreamTlsProfile>,
        metadata: HashMap<String, String>,
    ) -> Result<Self> {
        Self::try_from_parts(
            &uri,
            true,
            weight,
            down,
            backup,
            slow_start_ms,
            protocol,
            connect_timeout_ms,
            tls_profile,
            metadata,
            Instant::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// 业务作用：集中执行所有来源实例的 URI、协议、TLS 与拓扑校验并生成稳定健康身份。
    ///
    /// 参数说明：
    /// - `raw_uri`：待校验与规范化的上游 endpoint。
    /// - `healthy`：实例初始健康标记。
    /// - `weight`：负载均衡基础权重。
    /// - `down`：是否由配置显式摘除。
    /// - `backup`：是否只参与 backup 候选层。
    /// - `slow_start_ms`：新实例权重爬升时长毫秒数。
    /// - `protocol`：上游连接协议。
    /// - `connect_timeout_ms`：连接超时毫秒数，0 表示使用公共策略。
    /// - `tls_profile`：HTTPS 上游使用的可选 TLS 身份配置。
    /// - `metadata`：只读发现属性与可选分层拓扑标签。
    /// - `created_at`：慢启动计算使用的实例加入时刻。
    ///
    /// 返回：成功时返回可进入只读目录的实例；任何不安全组合或非法 zone 返回错误。
    fn try_from_parts(
        raw_uri: &str,
        healthy: bool,
        weight: u32,
        down: bool,
        backup: bool,
        slow_start_ms: u64,
        protocol: UpstreamProtocol,
        connect_timeout_ms: u64,
        tls_profile: Option<UpstreamTlsProfile>,
        metadata: HashMap<String, String>,
        created_at: Instant,
    ) -> Result<Self> {
        let uri: http::Uri = raw_uri
            .parse()
            .with_context(|| format!("invalid upstream uri `{raw_uri}`"))?;
        let scheme = uri.scheme_str();
        if protocol.is_cgi() {
            anyhow::ensure!(scheme == Some("http") && uri.port_u16().is_some()
                && uri.path() == "/" && uri.query().is_none() && tls_profile.is_none(),
                "CGI endpoints require an explicit TCP port, an http address carrier without path/query, and no TLS profile");
        }
        match scheme {
            Some("http") | Some("https") => {}
            Some(other) => anyhow::bail!("unsupported upstream scheme `{other}`"),
            None => anyhow::bail!("upstream uri `{raw_uri}` has no scheme"),
        }
        match (protocol, scheme) {
            (UpstreamProtocol::H2c, Some("https")) => {
                anyhow::bail!("upstream protocol h2c requires an http:// uri, got `{raw_uri}`")
            }
            (UpstreamProtocol::H2, Some("http")) => {
                anyhow::bail!(
                    "upstream protocol h2 requires an https:// uri; use h2c for `{raw_uri}`"
                )
            }
            (UpstreamProtocol::H3, Some("http")) => {
                anyhow::bail!("upstream protocol h3 requires an https:// uri, got `{raw_uri}`")
            }
            _ => {}
        }
        if uri.authority().is_none() {
            anyhow::bail!("upstream uri `{raw_uri}` has no authority");
        }
        if tls_profile.is_some() && scheme != Some("https") {
            anyhow::bail!("upstream tls profile requires an https:// uri, got `{raw_uri}`");
        }
        anyhow::ensure!(
            connect_timeout_ms == 0 || (1..=60_000).contains(&connect_timeout_ms),
            "upstream connect timeout must be 0 or within 1ms..=60s"
        );
        let uri = Arc::<str>::from(raw_uri.trim_end_matches('/'));
        let health_key = match &tls_profile {
            Some(profile) => Arc::<str>::from(format!("{uri}#{}", profile.key)),
            None if protocol.is_cgi() => Arc::<str>::from(format!("{uri}#cgi:{protocol:?}")),
            None => uri.clone(),
        };
        let zone = locality::metadata_value(&metadata, &["zone", "topology.kubernetes.io/zone"])
            .context("upstream instance locality zone")?;
        let region =
            locality::metadata_value(&metadata, &["region", "topology.kubernetes.io/region"])
                .context("upstream instance locality region")?;
        let subzone = locality::metadata_value(&metadata, &["subzone", "sub_zone"])
            .context("upstream instance locality subzone")?;
        Ok(Self {
            uri,
            feedback_key: health_key.clone(),
            health_key,
            healthy,
            weight: weight.max(1),
            down,
            backup,
            slow_start_ms,
            created_at,
            feedback_generation: next_feedback_generation(),
            protocol,
            connect_timeout_ms,
            tls_profile,
            zone,
            region,
            subzone,
            metadata,
        })
    }

    /// 业务作用：判断实例是否具有当前可选资格，禁用、非健康或无有效权重的实例不承接流量。
    fn is_selectable(&self) -> bool {
        self.healthy && !self.down
    }

    /// 业务作用：按本次选择冻结的时刻计算预热份额，保证总份额与选址扫描使用相同权重。
    ///
    /// 参数说明：
    /// - `now`：同一次选择共用的单调时刻。
    ///
    /// 返回：预热中的正份额或完整基础权重；未来创建时刻按刚入场处理。
    fn effective_weight_at(&self, now: Instant) -> u32 {
        if self.slow_start_ms == 0 || self.weight <= 1 {
            return self.weight;
        }
        let elapsed_ms = now
            .saturating_duration_since(self.created_at)
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if elapsed_ms >= self.slow_start_ms {
            return self.weight;
        }
        let elapsed = elapsed_ms.max(1) as u128;
        let slow_start = self.slow_start_ms.max(1) as u128;
        let numerator = self.weight as u128 * elapsed;
        let scaled = numerator.div_ceil(slow_start).clamp(1, self.weight as u128);
        scaled as u32
    }
}

/// 业务作用：为新实例授予不可复用的进程内反馈代际，避免相同时钟刻度下地址重入混用样本。
///
/// 参数说明: 无。
///
/// 返回：严格递增的身份序号；计数耗尽时停止创建，绝不回绕复用旧权威。
fn next_feedback_generation() -> u64 {
    static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    GENERATION
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |value| value.checked_add(1),
        )
        .expect("upstream feedback generation exhausted")
}

/// 业务作用：校验并构建服务级一致性哈希策略,把「策略要键但没声明键」挡在构建期。
///
/// `ip_hash` 是 `ring_hash` + `remote_addr` 的语法糖,在此展开,数据面不再有第二条分支。
///
/// 参数说明：
/// - `svc`：静态服务配置，包含负载均衡算法、哈希来源与算法资源上限。
///
/// 返回：需要哈希的策略返回已校验策略；不需要时返回 `None`；声明冲突时返回错误。
fn build_hash_policy(svc: &StaticServiceCfg) -> Result<Option<LbHashPolicy>> {
    let raw_policy = svc
        .lb_policy
        .as_deref()
        .or(svc.lb.as_deref())
        .unwrap_or("round_robin")
        .trim();
    let policy = LbPolicy::parse(raw_policy)?;
    if !policy.requires_hash_key() {
        anyhow::ensure!(
            svc.hash_on.is_none(),
            "hash_on 只能与 ring_hash/maglev/ip_hash 同用,当前 lb_policy=`{raw_policy}`"
        );
        return Ok(None);
    }
    let is_ip_hash = matches!(raw_policy, "ip_hash" | "ip-hash");
    let source = match (svc.hash_on.as_deref(), is_ip_hash) {
        // ip_hash 语义固定为源地址;再显式配 hash_on 只会制造两个事实源。
        (Some(_), true) => {
            anyhow::bail!("ip_hash 已固定按 remote_addr 哈希,不应再声明 hash_on")
        }
        (None, true) => LbHashSource::RemoteAddr,
        (Some(raw), false) => LbHashSource::parse(raw)?,
        // 没有键的一致性哈希会把全部流量钉到同一实例,必须构建期拒绝而不是运行期退化。
        (None, false) => anyhow::bail!("lb_policy=`{raw_policy}` 必须声明 hash_on"),
    };
    let replicas = svc.hash_ring_replicas.unwrap_or(100);
    anyhow::ensure!(
        (1..=crate::upstream::hash::MAX_REPLICAS_PER_UNIT_WEIGHT).contains(&replicas),
        "hash_ring_replicas 必须在 1..={} 之间",
        crate::upstream::hash::MAX_REPLICAS_PER_UNIT_WEIGHT
    );
    let table_size = svc.hash_table_size.unwrap_or(65_537);
    anyhow::ensure!(
        (1..=crate::upstream::hash::MAX_MAGLEV_TABLE).contains(&table_size),
        "hash_table_size 必须在 1..={} 之间",
        crate::upstream::hash::MAX_MAGLEV_TABLE
    );
    Ok(Some(LbHashPolicy {
        source,
        replicas_per_weight: replicas,
        table_size,
    }))
}

/// 业务作用：校验并构建后端负载反馈策略。
///
/// 所有阈值都在构建期钳制到合法区间并拒绝明显错误的组合,避免运行期出现
/// 「平滑系数为 0 导致 EWMA 永不更新」这类只能靠观察指标才能发现的静默失效。
///
/// 参数说明：
/// - `cfg`：是可选反馈配置。
///
/// 返回：未配置时返回关闭策略;非法阈值返回错误。
fn build_load_feedback(
    cfg: Option<&crate::config::model::LoadFeedbackCfg>,
) -> Result<crate::upstream::load::LoadFeedbackPolicy> {
    let mut policy = crate::upstream::load::LoadFeedbackPolicy::disabled();
    let Some(cfg) = cfg else {
        return Ok(policy);
    };
    policy.feedback =
        crate::upstream::load::LoadFeedback::parse(cfg.mode.as_deref().unwrap_or("none"))?;
    if let Some(freshness) = cfg.freshness_ms {
        anyhow::ensure!(
            (100..=3_600_000).contains(&freshness),
            "load_feedback.freshness_ms 必须在 100..=3600000"
        );
        policy.freshness_ms = freshness;
    }
    if let Some(min_samples) = cfg.min_samples {
        anyhow::ensure!(
            (1..=10_000).contains(&min_samples),
            "load_feedback.min_samples 必须在 1..=10000"
        );
        policy.min_samples = min_samples;
    }
    if let Some(smoothing) = cfg.smoothing_bp {
        anyhow::ensure!(
            (1..=10_000).contains(&smoothing),
            "load_feedback.smoothing_bp 必须在 1..=10000"
        );
        policy.smoothing_bp = smoothing;
    }
    if let Some(panic_bp) = cfg.panic_threshold_bp {
        anyhow::ensure!(
            panic_bp <= 10_000,
            "load_feedback.panic_threshold_bp 必须在 0..=10000"
        );
        policy.panic_threshold_bp = panic_bp;
    }
    if let Some(header) = cfg.orca_header.as_deref() {
        let header = header.trim().to_ascii_lowercase();
        anyhow::ensure!(
            !header.is_empty()
                && header.len() <= 128
                && header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "load_feedback.orca_header `{header}` 非法"
        );
        policy.orca_header = Arc::from(header.as_str());
    }
    anyhow::ensure!(
        policy.orca_header.as_ref() != load::report::BINARY_HEADER,
        "load_feedback.orca_header must not replace the standard binary header"
    );
    if let Some(subscription) = &cfg.out_of_band {
        anyhow::ensure!(
            policy.feedback == load::LoadFeedback::Utilization,
            "ORCA out_of_band requires utilization feedback"
        );
        subscription.validate()?;
        policy.out_of_band = Some(subscription.clone());
    }
    Ok(policy)
}

/// 业务作用：校验并构建会话保持策略,确保 cookie 默认带上安全属性。
///
/// `SameSite=None` 在现代浏览器上必须同时 `Secure`,否则 cookie 会被直接丢弃——
/// 与其让运维在生产上排查「亲和不生效」,不如构建期拒绝该组合。
///
/// 参数说明：
/// - `cfg`：是可选会话保持配置。
///
/// 返回：合法配置返回策略；未配置返回 `None`；非法组合返回错误。
fn build_session_affinity(
    cfg: Option<&crate::config::model::SessionAffinityCfg>,
) -> Result<Option<SessionAffinityPolicy>> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    let mode = cfg
        .mode
        .as_deref()
        .unwrap_or("cookie")
        .trim()
        .to_ascii_lowercase();
    let validate_name = |name: &str, what: &str| -> Result<()> {
        anyhow::ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "session_affinity {what} `{name}` 必须是不超过 128 字节的字母数字/`-`/`_`"
        );
        Ok(())
    };
    let absolute_timeout_seconds = cfg.absolute_timeout_seconds.unwrap_or(0);
    let idle_timeout_seconds = cfg.idle_timeout_seconds.unwrap_or(0);
    let legacy_ttl_seconds = cfg.ttl_seconds.unwrap_or(0);
    anyhow::ensure!(
        absolute_timeout_seconds <= 31_536_000 && idle_timeout_seconds <= 31_536_000,
        "session_affinity absolute/idle timeout 不得超过 365 天"
    );
    anyhow::ensure!(
        legacy_ttl_seconds == 0 || (absolute_timeout_seconds == 0 && idle_timeout_seconds == 0),
        "session_affinity ttl_seconds 不能与 absolute/idle timeout 同时配置"
    );
    match mode.as_str() {
        "cookie" => {
            let name = cfg
                .name
                .as_deref()
                .unwrap_or("naway_affinity")
                .trim()
                .to_string();
            validate_name(&name, "cookie 名")?;
            let same_site = cfg.same_site.as_deref().unwrap_or("Lax").trim().to_string();
            let normalized = match same_site.to_ascii_lowercase().as_str() {
                "lax" => "Lax",
                "strict" => "Strict",
                "none" => "None",
                other => {
                    anyhow::bail!("session_affinity same_site `{other}` 仅支持 Lax/Strict/None")
                }
            };
            let secure = cfg.secure.unwrap_or(true);
            anyhow::ensure!(
                normalized != "None" || secure,
                "session_affinity same_site=None 必须同时 secure=true,否则浏览器会丢弃该 cookie"
            );
            let path = if cfg.omit_path.unwrap_or(false) {
                anyhow::ensure!(
                    cfg.path.is_none(),
                    "session_affinity omit_path=true 不能同时配置 path"
                );
                None
            } else {
                let path = cfg.path.as_deref().unwrap_or("/").trim().to_string();
                anyhow::ensure!(
                    path.starts_with('/')
                        && path.len() <= 256
                        && !path.contains(|c: char| c.is_control() || c == ';'),
                    "session_affinity path `{path}` 必须以 / 开头且不含控制字符或 `;`"
                );
                Some(Arc::from(path.as_str()))
            };
            let domain = match cfg.domain.as_deref().map(str::trim) {
                Some(domain) if !domain.is_empty() => {
                    anyhow::ensure!(
                        domain.len() <= 253
                            && domain
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')),
                        "session_affinity domain `{domain}` 非法"
                    );
                    Some(Arc::from(domain))
                }
                _ => None,
            };
            let permanent = cfg.permanent_cookie.unwrap_or(false);
            anyhow::ensure!(
                !permanent || absolute_timeout_seconds > 0,
                "session_affinity permanent_cookie=true 必须配置 absolute_timeout_seconds"
            );
            Ok(Some(SessionAffinityPolicy {
                mode: SessionAffinityMode::Cookie {
                    name: Arc::from(name.as_str()),
                    ttl_seconds: legacy_ttl_seconds,
                    permanent,
                    path,
                    domain,
                    same_site: Arc::from(normalized),
                    secure,
                    http_only: cfg.http_only.unwrap_or(true),
                },
                absolute_timeout_seconds,
                idle_timeout_seconds,
            }))
        }
        "header" => {
            anyhow::ensure!(
                !cfg.permanent_cookie.unwrap_or(false) && cfg.ttl_seconds.unwrap_or(0) == 0,
                "session_affinity header 模式不能配置 cookie 有效期"
            );
            let name = cfg
                .name
                .as_deref()
                .unwrap_or("x-naway-affinity")
                .trim()
                .to_string();
            validate_name(&name, "header 名")?;
            Ok(Some(SessionAffinityPolicy {
                mode: SessionAffinityMode::Header {
                    name: Arc::from(name.to_ascii_lowercase().as_str()),
                },
                absolute_timeout_seconds,
                idle_timeout_seconds,
            }))
        }
        other => anyhow::bail!("session_affinity mode `{other}` 仅支持 cookie/header"),
    }
}

/// 一次选择所固定的候选层:primary/backup 分层结果与被选中的最优 locality rank。
///
/// 抽出来是为了让「会话亲和」「一致性哈希」「常规 LB」三条路径共用**同一套**候选判定,
/// 不出现某条路径绕过健康、排除或 locality 事实的可能。
struct CandidateLayer {
    use_backup: bool,
    locality_rank: usize,
    locality: Option<UpstreamLocalityPolicy>,
}

impl CandidateLayer {
    /// 业务作用：在给定实例切片上确定本次选择的候选层。
    ///
    /// 参数说明：
    /// - `instances`：是实例切片
    /// - `locality`：是可选 zone 策略
    /// - `is_excluded`：是排除谓词。
    ///
    /// 返回：存在任何可用候选时返回候选层,否则返回 `None`。
    fn resolve<E: Fn(&str) -> bool>(
        instances: &[Arc<UpstreamInstance>],
        locality: Option<&UpstreamLocalityPolicy>,
        is_excluded: &E,
    ) -> Option<Self> {
        let base = |inst: &UpstreamInstance, backup: bool| {
            inst.is_selectable()
                && inst.backup == backup
                && !is_excluded(inst.uri.as_ref())
                && (inst.health_key.as_ref() == inst.uri.as_ref()
                    || !is_excluded(inst.health_key.as_ref()))
        };
        let rank =
            |inst: &UpstreamInstance| locality.map(|policy| policy.rank(inst)).unwrap_or(Some(0));
        // primary 存在时绝不把流量泄漏给 backup;不在允许 locality 的 primary 不能阻塞可用 backup。
        let use_backup = !instances
            .iter()
            .any(|inst| base(inst.as_ref(), false) && rank(inst.as_ref()).is_some());
        let locality_rank = instances
            .iter()
            .filter(|inst| base(inst.as_ref(), use_backup))
            .filter_map(|inst| rank(inst.as_ref()))
            .min()?;
        Some(Self {
            use_backup,
            locality_rank,
            locality: locality.cloned(),
        })
    }

    /// 业务作用：判断一个实例是否属于本次候选层。
    ///
    /// 参数说明：
    /// - `inst`：是待判定实例
    /// - `is_excluded`：是排除谓词。
    ///
    /// 返回：健康、分层与 locality 全部满足时返回 `true`。
    fn accepts<E: Fn(&str) -> bool>(&self, inst: &UpstreamInstance, is_excluded: &E) -> bool {
        if !inst.is_selectable() || inst.backup != self.use_backup {
            return false;
        }
        if is_excluded(inst.uri.as_ref()) {
            return false;
        }
        if inst.health_key.as_ref() != inst.uri.as_ref() && is_excluded(inst.health_key.as_ref()) {
            return false;
        }
        self.locality
            .as_ref()
            .map(|policy| policy.rank(inst))
            .unwrap_or(Some(0))
            == Some(self.locality_rank)
    }
}

/// 业务作用：把健康、排除身份、primary/backup 与最优 locality rank 收敛成唯一候选层，
/// 再按负载选择实例；本区仍有可用候选时不向跨区泄漏流量，权重不能旁路准入。
///
/// 流程与不变式：
/// 1. 存在可用 primary 时，backup 不参与。
/// 2. `first`/`least_conn` 单次扫描，WRR 两次扫描总权重和目标位置，不建立候选 `Vec`。
/// 3. 只 clone 选中实例的 `Arc`，不深拷贝 URI、TLS profile 与 metadata。
///
/// 参数说明：
/// - `instances`：当前快照或发现版本的不可变实例切片。
/// - `policy`：服务级 LB 策略。
/// - `locality`：可选本区优先与有序跨区 failover 策略。
/// - `is_excluded`：按 URI 或完整身份键判断本次请求不可选择的实例。
/// - `load`：`least_conn` 的在途计数读取器。
/// - `rr`：轮询与随机分散游标，只有确需抽样或轮转时调用一次。
///
/// 返回：选中的共享实例；没有可用 primary/backup 时返回 `None`。
fn select_instance_from_slice<E, F, R>(
    instances: &[Arc<UpstreamInstance>],
    policy: LbPolicy,
    locality: Option<&UpstreamLocalityPolicy>,
    is_excluded: E,
    mut load: F,
    rr: R,
) -> Option<Arc<UpstreamInstance>>
where
    E: Fn(&str) -> bool,
    F: FnMut(&UpstreamInstance) -> u64,
    R: FnOnce() -> u64,
{
    // 单实例是静态配置和多数 sidecar 场景的绝对热路径。此时 primary/backup 分层、WRR
    // 权重和 least_conn 排序都不可能改变结果；直接校验唯一候选，避免先为 `use_backup`
    // 预扫描、再按策略扫描第二遍。实例仍必须通过 healthy/down 与全部摘除事实，不能把
    // 性能快路径变成健康检查旁路。返回只增加选中实例 Arc 的引用计数，不复制 URI/TLS。
    if let [inst] = instances {
        let inst = inst.as_ref();
        if !inst.is_selectable()
            || locality.is_some_and(|policy| policy.rank(inst).is_none())
            || is_excluded(inst.uri.as_ref())
        {
            return None;
        }
        // 无 TLS 时 health_key 与 URI 是同一个逻辑身份，重复调用排除谓词只会再次扫描
        // retry/passive 列表并哈希主动健康表；带 TLS profile 时二者不同，仍须分别检查。
        if inst.health_key.as_ref() != inst.uri.as_ref() && is_excluded(inst.health_key.as_ref()) {
            return None;
        }
        return Some(instances[0].clone());
    }
    let is_base_candidate = |inst: &UpstreamInstance, backup: bool| {
        inst.is_selectable()
            && inst.backup == backup
            && !is_excluded(inst.uri.as_ref())
            && (inst.health_key.as_ref() == inst.uri.as_ref()
                || !is_excluded(inst.health_key.as_ref()))
    };
    let locality_rank =
        |inst: &UpstreamInstance| locality.map(|policy| policy.rank(inst)).unwrap_or(Some(0));
    // primary 存在时绝不把流量泄漏给 backup；不在允许 locality 集合的 primary
    // 不能阻塞可用 backup，否则 fail-closed locality 会被错误解释为整服务不可用。
    let use_backup = !instances.iter().any(|inst| {
        is_base_candidate(inst.as_ref(), false) && locality_rank(inst.as_ref()).is_some()
    });
    let selected_locality_rank = instances
        .iter()
        .filter(|inst| is_base_candidate(inst.as_ref(), use_backup))
        .filter_map(|inst| locality_rank(inst.as_ref()))
        .min()?;
    let is_candidate = |inst: &UpstreamInstance, backup: bool| {
        is_base_candidate(inst, backup) && locality_rank(inst) == Some(selected_locality_rank)
    };
    let first = || {
        instances
            .iter()
            .find(|inst| is_candidate(inst.as_ref(), use_backup))
    };
    // 份额 = 实例有效权重(含 slow-start) × zone 倍率(含 weighted zone 与劣化折扣)。
    // 三个因子相乘,使「容量、健康实例数与显式权重共同决定份额」成为实际算式:
    // 实例数通过候选个数体现,权重与 zone 倍率通过本函数体现。
    let selection_time = std::cell::OnceCell::new();
    let raw_share = |inst: &UpstreamInstance| -> u64 {
        let zone_multiplier = locality.map(|policy| policy.multiplier(inst)).unwrap_or(1) as u64;
        let weight = if inst.slow_start_ms == 0 || inst.weight <= 1 {
            inst.weight
        } else {
            // 只在预热实例确实参与时读取一次时钟；跨扫描不能因时间推进改变份额边界。
            inst.effective_weight_at(*selection_time.get_or_init(Instant::now))
        };
        u64::from(weight) * zone_multiplier.max(1)
    };
    // 份额按最大公约数归一。zone 倍率被放大 100 倍以表达百分比,若不归一,
    // 权重总和会从个位数涨到上千。约分让常见份额维持短周期；
    // 大互质权重无法靠约分缩短，后续选择另用分散游标避免长期停留在前几个槽位。
    let share_divisor = {
        let mut divisor = 0u64;
        for inst in instances
            .iter()
            .filter(|inst| is_candidate(inst.as_ref(), use_backup))
        {
            divisor = gcd(divisor, raw_share(inst.as_ref()));
        }
        divisor.max(1)
    };
    let share_of = |inst: &UpstreamInstance| -> u64 {
        (raw_share(inst) / share_divisor).max(1)
    };
    match policy {
        LbPolicy::First => first().cloned(),
        LbPolicy::LeastConn => {
            let mut candidates = instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup));
            let first = candidates.next()?;
            let Some(second) = candidates.next() else {
                // 单候选结果恒定，不读取 DashMap/in-flight atomic。
                return Some(first.clone());
            };
            let mut best = first;
            let mut best_load = load(first);
            let mut best_weight = share_of(first).max(1);
            let mut tie_weight = u128::from(best_weight);
            let mut cursor = Some(rr);
            let mut entropy = None;
            for (index, inst) in std::iter::once(second).chain(candidates).enumerate() {
                let current_load = load(inst);
                let weight = share_of(inst).max(1);
                // 交叉相乘保留整数精度，不能把不同容量实例按原始连接数或截断除法比较。
                let comparison = (u128::from(current_load) * u128::from(best_weight))
                    .cmp(&(u128::from(best_load) * u128::from(weight)));
                let choose = match comparison {
                    std::cmp::Ordering::Less => {
                        tie_weight = u128::from(weight);
                        true
                    }
                    std::cmp::Ordering::Equal => {
                        tie_weight += u128::from(weight);
                        let seed = *entropy.get_or_insert_with(|| {
                            mix64(cursor
                                .take()
                                .expect("least-connection cursor consumed once")(
                            ))
                        });
                        // 空闲或同负载候选仍按份额分散，避免每次扫描都固定选择表首实例。
                        let upper = mix64(seed.wrapping_add(index as u64));
                        let lower = mix64(upper);
                        let draw = (u128::from(upper) << 64) | u128::from(lower);
                        draw % tie_weight < u128::from(weight)
                    }
                    std::cmp::Ordering::Greater => false,
                };
                if choose {
                    best = inst;
                    best_load = current_load;
                    best_weight = weight;
                }
            }
            Some(best.clone())
        }
        LbPolicy::RoundRobin => {
            let mut candidates = instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup));
            let only = candidates.next()?;
            if candidates.next().is_none() {
                // 一个候选时 RR/权重结果恒定，不能为形式上的轮转争用全局 AtomicU64，
                // 也不需要读取 slow-start 时钟。
                return Some(only.clone());
            }
            let total_weight = instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup))
                .map(|inst| u128::from(share_of(inst.as_ref())))
                .sum::<u128>();
            if total_weight == 0 {
                return first().cloned();
            }
            let cursor = rr();
            // 小周期保留逐槽轮询；大互质份额用位反转游标分散，避免连续多年只选表首。
            let mut slot = if total_weight <= 65_536 {
                u128::from(cursor) % total_weight
            } else {
                weighted_fraction_slot(total_weight, cursor.reverse_bits())
            };
            for inst in instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup))
            {
                let weight = u128::from(share_of(inst.as_ref()));
                if slot < weight {
                    return Some(inst.clone());
                }
                slot -= weight;
            }
            // 总份额和扫描使用同一快照、同一预热时刻；仅不稳定的外部排除谓词可能使扫描失配。
            first().cloned()
        }
        LbPolicy::Random => {
            let total_weight = instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup))
                .map(|inst| u128::from(share_of(inst.as_ref())))
                .sum::<u128>();
            if total_weight == 0 {
                return first().cloned();
            }
            // 熵来自单调游标经雪崩混合:不引入 RNG 依赖、无锁、无全局状态,
            // 且相邻请求不会像裸计数那样退化成严格轮转。
            let mut slot = weighted_fraction_slot(total_weight, mix64(rr()));
            for inst in instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup))
            {
                let weight = u128::from(share_of(inst.as_ref()));
                if slot < weight {
                    return Some(inst.clone());
                }
                slot -= weight;
            }
            first().cloned()
        }
        LbPolicy::WeightedLeastRequest => {
            // power-of-two-choices:只读两个候选的在途计数,避免全候选扫描,
            // 也避免所有 worker 同时涌向当前最空的那一个实例。
            let count = instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup))
                .count();
            if count == 0 {
                return None;
            }
            if count == 1 {
                return first().cloned();
            }
            let entropy = mix64(rr());
            let pick = |offset: u64| -> Option<&Arc<UpstreamInstance>> {
                let target = (offset % count as u64) as usize;
                instances
                    .iter()
                    .filter(|inst| is_candidate(inst.as_ref(), use_backup))
                    .nth(target)
            };
            let first_pick = pick(entropy)?;
            // 第二个候选强制与第一个不同:相同则退化成单点采样,失去 P2C 的抗长尾作用。
            let second_index = 1 + (mix64(entropy) % (count as u64 - 1));
            let second_pick = pick((entropy % count as u64 + second_index) % count as u64)?;
            // 比较「在途请求 / 有效权重」而非裸在途数:否则高权重大实例会被误判成更忙。
            // 交叉相乘保留容量比精度；大权重下整数除法会把两个负载都截断成零。
            let left = (u128::from(load(first_pick)) + 1) * u128::from(share_of(second_pick));
            let right = (u128::from(load(second_pick)) + 1) * u128::from(share_of(first_pick));
            Some(if left <= right {
                first_pick.clone()
            } else {
                second_pick.clone()
            })
        }
        // 一致性哈希在 `select_instance_hinted` 中已优先处理;能走到这里说明本次请求
        // 没有可用哈希键或表,按加权轮转保证可用性。
        LbPolicy::RingHash | LbPolicy::Maglev => select_instance_from_slice(
            instances,
            LbPolicy::RoundRobin,
            locality,
            is_excluded,
            load,
            rr,
        ),
    }
}

/// 业务作用：把无符号分数游标映射到完整份额区间，不截断超过 u64 的总权重。
///
/// 参数说明：
/// - `total`：以 u128 汇总的候选份额。
/// - `fraction`：分母为 2^64 的游标分子。
///
/// 返回：小于正总份额的索引；分拆乘法避免中间乘积溢出，零总份额返回零。
fn weighted_fraction_slot(total: u128, fraction: u64) -> u128 {
    let upper = total >> 64;
    let lower = total & u128::from(u64::MAX);
    upper * u128::from(fraction) + ((lower * u128::from(fraction)) >> 64)
}

/// 业务作用：求两个份额的最大公约数,用于把加权份额约到最简比例。
///
/// 参数说明：
/// - `left`：待约分的第一个非负份额。
/// - `right`：待约分的第二个非负份额。
///
/// 返回：最大公约数;两者皆为 0 时返回 0。
fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

/// 业务作用：把单调游标混合成分布良好的伪随机数,供 `random` 与 P2C 采样。
///
/// 使用固定的 splitmix64 终混：无外部依赖、无锁，同一输入在不同节点得到相同结果。
///
/// 参数说明：
/// - `value`：是单调游标当前值。
///
/// 返回：雪崩混合后的 64 位值。
fn mix64(value: u64) -> u64 {
    let mut hash = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

/// 业务作用：将 Nacos SDK 实例快照转换为排序稳定、已验证且携带可信 locality 的 gateway 实例。
///
/// 参数说明：
/// - `spec`：是逻辑服务 watch 契约
/// - `discovered`：是本轮完整 Nacos 实例快照。
///
/// 返回：全部实例合法时返回稳定排序结果；任一 URI/metadata 非法时拒绝整轮发现更新。
pub fn discovery_instances_to_upstreams(
    spec: &NacosWatchSpec,
    discovered: &[nasa::discovery::Instance],
) -> Result<Vec<UpstreamInstance>> {
    let mut instances = Vec::with_capacity(discovered.len());
    for inst in discovered {
        let uri = discovery_instance_uri(inst, &spec.scheme)
            .with_context(|| format!("nacos service `{}` instance", spec.nacos_service))?;
        let weight = f64_to_weight(inst.weight);
        let down = metadata_bool(inst, &["gateway.down", "down"]).unwrap_or(false);
        let backup = metadata_bool(inst, &["gateway.backup", "backup"]).unwrap_or(false);
        let slow_start_ms = metadata_u64(inst, &["gateway.slow_start_ms", "slow_start_ms"])
            .unwrap_or(spec.slow_start_ms);
        instances.push(UpstreamInstance::try_dynamic(
            uri,
            weight,
            down,
            backup,
            slow_start_ms,
            spec.protocol,
            0,
            spec.tls_profile.clone(),
            inst.metadata.clone(),
        )?);
    }
    instances.sort_by(|a, b| a.uri.cmp(&b.uri));
    Ok(instances)
}

/// 业务作用：将 Consul/Eureka/DNS/K8s 的中立实例转成与 Nacos 共用的上游类型和 locality 语义。
///
/// 参数说明：
/// - `spec`：是 registry watch 契约
/// - `discovered`：是本轮完整中立实例集合。
///
/// 返回：全部 endpoint/metadata 合法时返回稳定排序结果，否则拒绝整轮发现更新。
pub fn registry_instances_to_upstreams(
    spec: &RegistryWatchSpec,
    discovered: Vec<RegistryInstance>,
) -> Result<Vec<UpstreamInstance>> {
    let mut instances = Vec::with_capacity(discovered.len());
    for instance in discovered {
        anyhow::ensure!(instance.port > 0, "registry instance port cannot be zero");
        let host = instance.host.trim();
        anyhow::ensure!(!host.is_empty(), "registry instance host cannot be empty");
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{}", instance.port)
        } else {
            format!("{host}:{}", instance.port)
        };
        let uri = format!("{}://{authority}", spec.scheme);
        instances.push(UpstreamInstance::try_dynamic(
            uri,
            instance.weight.max(1),
            instance.down,
            instance.backup,
            spec.slow_start_ms,
            spec.protocol,
            0,
            spec.tls_profile.clone(),
            instance.metadata,
        )?);
    }
    instances.sort_by(|a, b| a.uri.cmp(&b.uri));
    instances.dedup_by(|a, b| a.health_key == b.health_key);
    Ok(instances)
}

/// 业务作用：把发现身份转换为可拨号 URI，统一地址族、协议与端口表示。
fn discovery_instance_uri(
    inst: &nasa::discovery::Instance,
    default_scheme: &str,
) -> Result<String> {
    if let Some(uri) = metadata_value(inst, &["gateway.uri", "uri", "url"]) {
        return Ok(uri.trim_end_matches('/').to_string());
    }
    let scheme = metadata_value(inst, &["gateway.scheme", "scheme"]).unwrap_or(default_scheme);
    validate_upstream_scheme(scheme)?;
    Ok(format!(
        "{scheme}://{}:{}",
        bracket_ipv6_host(&inst.ip),
        inst.port
    ))
}

/// 业务作用：拒绝不受支持的上游协议，避免编译成功但运行期无法正确转发。
fn validate_upstream_scheme(scheme: &str) -> Result<()> {
    match scheme {
        "http" | "https" => Ok(()),
        other => anyhow::bail!("unsupported upstream scheme `{other}` (http|https)"),
    }
}

/// 业务作用：把静态或动态 service TLS 配置构建成数据面可复用的上游身份与信任策略。
///
/// 参数说明：
/// - `cfg_path`：用于解析相对文件
/// - `name`：提供低敏错误上下文
/// - `svc`：是服务配置。
///
/// 返回：未配置 TLS 时返回空；材料和身份策略有效时返回 profile；非法配置拒绝快照。
fn build_service_tls_profile(
    cfg_path: &Path,
    name: &str,
    svc: &StaticServiceCfg,
) -> Result<Option<UpstreamTlsProfile>> {
    let Some(tls) = &svc.tls else {
        return Ok(None);
    };
    if tls.insecure_skip_verify {
        anyhow::ensure!(
            tls.ca_file.is_none()
                && tls.ca_pem.is_none()
                && tls.subject_alt_names.is_empty()
                && tls.client_cert_file.is_none()
                && tls.client_key_file.is_none()
                && tls.client_cert_pem.is_none()
                && tls.client_key_pem.is_none()
                && tls.spire.is_none(),
            "service `{name}` insecure_skip_verify cannot be combined with trust or client identity material"
        );
        // 关闭证书认证只保留传输加密；配置构建期必须拒绝任何看似仍会生效的信任或身份材料。
        return crate::tls::build_encryption_only_upstream_tls_profile(tls.server_name.as_deref())
            .map(Some)
            .with_context(|| {
                format!("build encryption-only upstream tls profile for service `{name}`")
            });
    }
    let ca_file = tls
        .ca_file
        .as_ref()
        .map(|path| resolve_relative(cfg_path, path));
    let client_cert_file = tls
        .client_cert_file
        .as_ref()
        .map(|path| resolve_relative(cfg_path, path));
    let client_key_file = tls
        .client_key_file
        .as_ref()
        .map(|path| resolve_relative(cfg_path, path));
    let mut profile = match &tls.spire {
        Some(spire) => {
            let source = crate::tls::spire::build_source(spire)
                .with_context(|| format!("build upstream SPIRE identity for service `{name}`"))?;
            crate::tls::build_upstream_tls_profile_with_spire(
                tls.server_name.as_deref(),
                ca_file.as_deref(),
                tls.ca_pem.as_deref(),
                &tls.subject_alt_names,
                client_cert_file.as_deref(),
                client_key_file.as_deref(),
                tls.client_cert_pem.as_deref(),
                tls.client_key_pem.as_deref(),
                source,
            )
        }
        None => build_upstream_tls_profile_with_material(
            tls.server_name.as_deref(),
            ca_file.as_deref(),
            tls.ca_pem.as_deref(),
            &tls.subject_alt_names,
            client_cert_file.as_deref(),
            client_key_file.as_deref(),
            tls.client_cert_pem.as_deref(),
            tls.client_key_pem.as_deref(),
        ),
    }
    .with_context(|| format!("build upstream tls profile for service `{name}`"))?;
    profile.client_identity_not_after = tls.client_identity_not_after;
    profile.client_identity_policy_identity = tls.client_identity_policy_identity;
    Ok(Some(profile))
}

/// 业务作用：为 IPv6 authority 保留方括号边界，避免主机中的冒号被误当作端口分隔符。
fn bracket_ipv6_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// 业务作用：把发现权重转换为调度可用的整数范围，非法或非正值不能获得有效份额。
fn f64_to_weight(weight: f64) -> u32 {
    if !weight.is_finite() || weight <= 0.0 {
        return 1;
    }
    weight.round().clamp(1.0, u32::MAX as f64) as u32
}

/// 业务作用：按兼容键顺序读取实例元数据，保持不同发现来源的统一字段语义。
fn metadata_value<'a>(inst: &'a nasa::discovery::Instance, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| inst.metadata.get(*key).map(String::as_str))
}

/// 业务作用：将实例元数据解释为明确布尔状态，不把任意文本隐式当作启用。
fn metadata_bool(inst: &nasa::discovery::Instance, keys: &[&str]) -> Option<bool> {
    metadata_value(inst, keys).and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    })
}

/// 业务作用：读取有界的无符号实例元数据，非法数值不进入调度预算。
fn metadata_u64(inst: &nasa::discovery::Instance, keys: &[&str]) -> Option<u64> {
    metadata_value(inst, keys).and_then(|v| v.trim().parse::<u64>().ok())
}
