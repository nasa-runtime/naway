//! 上游发现抽象、静态服务目录与动态发现目录。
//!
//! 数据面只读本地快照:静态实例来自 yml,Nacos 实例由 discovery manager watch 后写入
//! [`DynamicUpstreamStore`]。LB 选择逻辑不关心实例来源。

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::config::model::{
    DiscoveryCfg, StaticInstanceCfg, StaticServiceCfg, UpstreamLocalityCfg, UpstreamPrewarmCfg,
    UpstreamsCfg,
};
use crate::config::resolve_relative;
use crate::tls::{
    build_upstream_tls_profile, build_upstream_tls_profile_with_material, UpstreamTlsProfile,
};

/// 服务发现快照提供者。
pub trait ServiceRegistry: Send + Sync {
    /// 返回当前服务目录快照。实现方应保证调用不阻塞数据面热路径。
    fn snapshot(&self) -> UpstreamDirectory;
}

/// 静态服务发现后端:直接从 yml 的 `upstreams.services` 构建。
pub struct StaticRegistry {
    directory: UpstreamDirectory,
}

impl StaticRegistry {
    /// 校验配置并构造不再变化的静态服务目录。
    pub fn new(cfg: &UpstreamsCfg) -> Result<Self> {
        Ok(Self {
            directory: UpstreamDirectory::build(cfg)?,
        })
    }
}

impl ServiceRegistry for StaticRegistry {
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
/// 读路径仍走 `services.load()` 无锁,不受影响。
pub struct DynamicUpstreamStore {
    services: ArcSwap<HashMap<String, DynamicServiceState>>,
    write_lock: std::sync::Mutex<()>,
}

impl Default for DynamicUpstreamStore {
    fn default() -> Self {
        Self {
            services: ArcSwap::from_pointee(HashMap::new()),
            write_lock: std::sync::Mutex::new(()),
        }
    }
}

impl DynamicUpstreamStore {
    /// 创建一个空的动态实例目录，并返回可供发现任务与配置快照共享的句柄。
    ///
    /// 返回：内部通过 `ArcSwap` 发布不可变目录，数据面读取不等待发现侧 IO。
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 获取一个服务当前的不可变实例切片。
    ///
    /// # 参数
    /// - `service`: 配置中的逻辑服务名，而不是 Nacos 的物理 dataId。
    ///
    /// 返回：服务存在时只 clone 一次 `Arc`；不存在时返回 `None`。不会按请求深拷贝实例列表。
    pub fn service_instances(&self, service: &str) -> Option<Arc<[Arc<UpstreamInstance>]>> {
        self.services
            .load()
            .get(service)
            .map(|state| state.instances.clone())
    }

    /// 判断服务是否仍有实例，且最近一次发现连接确认未超过 stale TTL。
    pub fn service_fresh(&self, service: &str, stale_ttl_ms: u64) -> bool {
        let Some(state) = self.services.load().get(service).cloned() else {
            return false;
        };
        if state.instances.is_empty() {
            return false;
        }
        stale_ttl_ms == 0 || state.updated_at.elapsed().as_millis() as u64 <= stale_ttl_ms
    }

    /// 原子替换一个动态服务的完整实例集，并保留未变化实例的 slow-start 起点。
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
                }
            }
        }
        // 发现更新是低频控制面操作；这里构造新的不可变切片，换取数据面无锁共享且不深拷贝。
        let instances = instances
            .into_iter()
            .map(Arc::new)
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
    /// 参数说明：`managed_services` 是该 owner 独占的全部逻辑服务；`replacement` 是已完成
    /// 全量校验的新实例表，缺失 key 表示该服务当前没有 endpoint。
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
                    }
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

    /// 原子移除一个动态服务及其 freshness 状态。
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

    /// 「触活」一个服务的 last-known-good:仅刷新其 fresh 时间戳,不改实例列表。
    ///
    /// 由 Nacos watch 任务在**连接存活期间**周期性调用(discovery.rs)。存在的意义(N1):
    /// `service_fresh` 的 staleness 是从 `updated_at` 算的,而 `updated_at` 只在【实例变更】push 时前移;
    /// 一个稳定不变的服务(Nacos 不会重复推送相同数据)会在 `stale_ttl` 后被**误判 stale**,令 critical
    /// `/readyz` 无谓地抖到 503、被前置 LB 摘流。§5 的 stale_ttl 语义本是「watch 断线后 last-known-good 老化」
    /// ——即「距 watch 上次确认存活的时长」,而非「距上次数据变更的时长」。触活把二者对齐:watch 活着就保持 fresh,
    /// watch 一旦断(任务退出、停止触活),stale_ttl 到点才降级。
    ///
    /// # 参数
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
        // 背景任务、低频(poll 间隔级),非请求热路径:整表 clone 换指针可接受(与 replace_service 同量级,§15.7 只约束热路径)。
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
}

impl Default for UpstreamDirectory {
    fn default() -> Self {
        Self {
            services: HashMap::new(),
            dynamic: DynamicUpstreamStore::new(),
            prewarm_scan_interval_ms: 1_000,
        }
    }
}

impl UpstreamDirectory {
    /// 仅使用静态实例构造目录；动态目录为空。
    pub fn build(cfg: &UpstreamsCfg) -> Result<Self> {
        Self::build_with_dynamic(cfg, DynamicUpstreamStore::new(), 30_000)
    }

    /// 使用共享动态目录和统一 Nacos stale TTL 构造服务目录。
    pub fn build_with_dynamic(
        cfg: &UpstreamsCfg,
        dynamic: Arc<DynamicUpstreamStore>,
        nacos_stale_ttl_ms: u64,
    ) -> Result<Self> {
        Self::build_with_dynamic_at(cfg, dynamic, nacos_stale_ttl_ms, Path::new("."))
    }

    /// 与 [`Self::build_with_dynamic`] 相同，并以 `cfg_path` 解析 TLS 相对路径。
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
    /// 参数说明：`cfg` 是上游声明；`dynamic` 是常驻发现事实源；`discovery` 提供各后端
    /// freshness 契约；`cfg_path` 用于解析 TLS 相对路径。
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
            let scheme = svc.scheme.as_deref().unwrap_or("http").trim().to_string();
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
            let active_health = match &svc.health_check {
                Some(cfg) => {
                    let policy = crate::health::ActiveHealthPolicy::parse(cfg)
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
                instances.push(Arc::new(
                    UpstreamInstance::try_from_cfg(inst, protocol, tls_profile.clone())
                        .with_context(|| {
                            format!("build static upstream instance for service `{name}`")
                        })?,
                ));
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
                    next_upstream: NextUpstreamPolicy::parse(
                        svc.next_upstream.as_deref(),
                        svc.next_upstream_tries,
                        svc.next_upstream_backoff_ms,
                    )
                    .with_context(|| format!("service `{name}` next_upstream"))?,
                    passive_health: PassiveHealthPolicy {
                        max_fails: svc.max_fails,
                        fail_timeout_ms: svc.fail_timeout_ms,
                    },
                    active_health,
                    prewarm,
                    locality,
                    instances: instances.into(),
                    protocol,
                    tls_profile,
                    nacos_service: svc.nacos_service.clone().unwrap_or_else(|| name.clone()),
                    registry_service: svc.registry_service.clone().unwrap_or_else(|| name.clone()),
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
        })
    }

    /// 选择一个可用实例:先选 primary,primary 全不可用时才选 backup;`down` 实例永不进入候选。
    ///
    /// # 参数
    /// - `service`: `lb://service` 中的逻辑服务名。
    ///
    /// 返回：默认零负载/零游标下选中的共享实例；服务不存在或无候选时返回 `None`。
    pub fn select(&self, service: &str) -> Option<Arc<UpstreamInstance>> {
        self.select_instance(service, |_| 0, || 0)
    }

    /// 按服务的 LB 策略选择实例:
    /// - `least_conn`:调用方 `load` 按实例 `health_key` 传入在途计数,取最小;
    /// - `round_robin`:调用方 `rr` 传入该服务的单调轮询计数,按实例有效权重轮转(含 slow_start);
    /// - `first`:取第一个候选。
    ///
    /// # 参数
    /// - `service`: 逻辑服务名。
    /// - `load`: `least_conn` 的只读负载回调；其它策略不会调用。
    /// - `rr`: WRR 的单调游标回调；其它策略不会调用。
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

    /// 同 [`select_instance`](Self::select_instance),但排除本次请求已经尝试过的实例。
    ///
    /// # 参数
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

    /// 同 [`select_instance_excluding`](Self::select_instance_excluding),但允许调用方传入已持有的
    /// 排除集合迭代器,避免请求热路径为主动健康集合额外克隆一份 `Vec<String>`。
    ///
    /// # 参数
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
    /// # 参数
    /// - `service`: `lb://service` 中的逻辑服务名。
    /// - `is_excluded`: 输入 URI 或完整 `health_key`，返回 true 表示本次选择必须跳过。
    /// - `load`: `least_conn` 使用的实例在途计数读取器；其它策略不会调用。
    /// - `rr`: `round_robin` 使用的单调游标读取器；其它策略不会调用。
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
        let svc = self.services.get(service)?;
        let instances = self.instances_for(service, svc);
        select_instance_from_slice(
            instances.as_slice(),
            svc.lb_policy,
            svc.locality.as_ref(),
            is_excluded,
            load,
            rr,
        )
    }

    /// 查询服务级 `proxy_next_upstream` 策略。
    pub fn next_upstream_policy(&self, service: &str) -> Option<&NextUpstreamPolicy> {
        self.services.get(service).map(|svc| &svc.next_upstream)
    }

    /// 返回服务的被动失败阈值与临时摘除时长。
    pub fn passive_health_policy(&self, service: &str) -> Option<PassiveHealthPolicy> {
        self.services.get(service).map(|svc| svc.passive_health)
    }

    /// 当前服务是否真正需要请求期 in-flight 计数。其它 LB 策略不应维护一份永不读取的计数表。
    pub fn uses_least_conn(&self, service: &str) -> bool {
        self.services
            .get(service)
            .is_some_and(|svc| svc.lb_policy == LbPolicy::LeastConn)
    }

    /// 业务作用：返回所有未就绪的关键服务名，供 `/readyz` 与真实 locality-aware 选择保持
    /// 同一可用性口径，避免前置 LB 把流量送给已无允许 zone 容量的节点。
    ///
    /// 「就绪」= 该 critical 服务至少有一个**既 selectable(healthy && !down)、又未被主动探测判死**的实例。
    /// 关键:与「选实例」用**同一份可用集**(`instances_for`,Nacos 已按 stale_ttl 门控,N1),使 readyz 与 select
    /// 结果一致——实例全被主动探测判死(N2)/ Nacos watch 失联超 stale_ttl → 二者同时判「不可用」,
    /// 不会出现「select 返 503 但 readyz 仍 200」这种让前置 LB 误分流的不一致。
    ///
    /// # 参数
    /// - `active_unhealthy`: 主动健康探测当前判为不健康的 URI 集合(§5.1);传引用免拷贝,为空表示未配探测或全健康。
    ///
    /// 返回：所有没有可选实例的 critical service 名；空数组表示关键依赖已就绪。
    pub fn critical_not_ready(&self, active_unhealthy: &HashSet<String>) -> Vec<String> {
        self.services
            .iter()
            .filter_map(|(name, svc)| {
                if !svc.critical {
                    return None;
                }
                // instances_for 已对 Nacos 做 stale_ttl 门控;这里再排除主动探测判死的实例,与选实例逻辑同源。
                let instances = self.instances_for(name, svc);
                let has_usable = instances.as_slice().iter().any(|inst| {
                    inst.is_selectable()
                        && svc
                            .locality
                            .as_ref()
                            .is_none_or(|policy| policy.rank(inst.zone.as_deref()).is_some())
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

    /// 返回当前配置快照声明的逻辑服务数量。
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// 返回后台发现/预热线程的扫描间隔。该值来自 yml，可随快照热更。
    pub(crate) fn prewarm_scan_interval_ms(&self) -> u64 {
        self.prewarm_scan_interval_ms
    }

    /// 枚举指定逻辑服务当前可用、且配置了预热策略的实例。
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

    /// 收集当前可能被数据面选择的 service 与完整 `health_key`，供 reload 后低频回收
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
    /// Admin 只读发现视图(§14 / §34 V4「Admin UI 展示服务/实例/metadata」):列出所有上游服务及其
    /// **当前**实例(static 来自 yml,nacos 来自动态目录的 last-known-good),供管理面/运维查看拓扑与健康。
    /// 只读、不进请求热路径;实例的 `healthy` 是发现/静态标记,主动探测的不健康态由 `/metrics` 的
    /// `gw_upstream_healthy{service}` 反映(此处不并入,避免管理视图与探测器强耦合)。
    ///
    /// 参数说明：`route_refs` 是逻辑服务到 route id 的低频反向索引。
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
                        })
                    })
                    .collect();
                // `selectable_count` 与 `instances_for` 用**同一份可用集**,再扣掉 down/未 healthy
                // 的实例:管理面要回答的是"现在还有几个能被选中",而不是"目录里登记了几个"。
                // 主动探测判死的实例不在此扣除(见本函数头注释),那条口径由 /metrics 负责。
                let selectable = instances
                    .iter()
                    .filter(|inst| {
                        inst["down"] == serde_json::Value::Bool(false)
                            && inst["healthy"] == serde_json::Value::Bool(true)
                    })
                    .count();
                serde_json::json!({
                    "service": name,
                    "source": source,
                    "critical": svc.critical,
                    "lb_policy": svc.lb_policy.as_str(),
                    "route_refs": route_refs.get(*name).cloned().unwrap_or_default(),
                    "instance_count": instances.len(),
                    "selectable_count": selectable,
                    "instances": instances,
                })
            })
            .collect();
        serde_json::json!({ "services": services })
    }

    /// 判断逻辑服务是否已在当前快照中声明。
    ///
    /// # 参数
    /// - `service`: `lb://service` 去掉前缀后的服务名。
    pub fn has_service(&self, service: &str) -> bool {
        self.services.contains_key(service)
    }

    /// 返回当前目录内全部 Nacos 服务的 watch 规格。
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
    /// 参数说明：无。
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
    /// 参数说明：无。
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
    /// 参数说明：无。
    ///
    /// 返回：当前快照中的服务、策略与可见实例列表；未配置探测的服务不返回。
    pub fn active_health_targets(&self) -> Vec<crate::health::HealthTarget> {
        self.services
            .iter()
            .filter_map(|(name, svc)| {
                let policy = svc.active_health.clone()?;
                let current_instances = self.instances_for(name, svc);
                let instances = current_instances
                    .as_slice()
                    .iter()
                    .map(|inst| crate::health::HealthInstanceTarget {
                        key: inst.health_key.to_string(),
                        uri: inst.uri.to_string(),
                        protocol: inst.protocol,
                        tls_profile: inst.tls_profile.clone(),
                    })
                    .collect::<Vec<_>>();
                Some(crate::health::HealthTarget {
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
    /// 参数说明：`service` 是动态表 key；`svc` 是同一快照中的来源与 freshness 策略。
    ///
    /// 返回：静态来源只借用快照切片；Nacos 来源只 clone 一次 `Arc`；过期/缺失时返回空视图。
    fn instances_for<'a>(
        &'a self,
        service: &str,
        svc: &'a ServiceSnapshot,
    ) -> UpstreamInstances<'a> {
        match svc.source {
            ServiceSource::Static => UpstreamInstances::Static(&svc.instances),
            // ★N1:Nacos 实例也按 freshness 门控,让「选实例」与「readyz」读到一致的可用集★。
            //   stale_ttl 内(watch 活着,由 touch_service 保鲜)沿用 last-known-good;超时(watch 失联太久)
            //   视为空 → select 返 None → 降级(§5 watch 契约:超过 stale_ttl 进 degraded/empty,而非无限用旧实例)。
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
    /// 把不同所有权分支统一成只读切片，供 LB 同步扫描。
    ///
    /// 返回：有效期绑定到当前实例视图；不会 clone 或分配。
    fn as_slice(&self) -> &[Arc<UpstreamInstance>] {
        match self {
            Self::Static(instances) => instances,
            Self::Dynamic(instances) => instances,
            Self::Empty => &[],
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
    /// 连接/超时/指定 5xx 时的跨实例重试策略。
    pub next_upstream: NextUpstreamPolicy,
    /// 连续失败阈值和临时摘除窗口。
    pub passive_health: PassiveHealthPolicy,
    /// 主动健康探测策略(§5.1);None = 未配置该服务的 health_check。
    pub active_health: Option<crate::health::ActiveHealthPolicy>,
    /// 新实例进入目录后使用对应 H1/H2/H2c/H3 业务池执行的一次性连接预热；None = 关闭。
    pub prewarm: Option<UpstreamPrewarmPolicy>,
    /// V9 可信 zone-aware 选择与有序 failover；None 保持全实例 LB。
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

/// 已校验的 zone-aware locality 与 failover 顺序。
#[derive(Clone)]
struct UpstreamLocalityPolicy {
    local_zone: Arc<str>,
    failover_zones: Arc<[Arc<str>]>,
    allow_unlisted: bool,
}

impl UpstreamLocalityPolicy {
    /// 业务作用：把声明式 zone 顺序编译成只读策略，在快照发布前拒绝空值、
    /// 重复 zone 和过长标识，避免数据面出现模糊 failover 顺序。
    ///
    /// 参数说明：`cfg` 是 service 级 locality 声明；`service` 用于定位构建错误。
    ///
    /// 返回：成功时返回按 local→failover 排序的不可变策略；非法 zone 拒绝快照。
    fn parse(cfg: &UpstreamLocalityCfg, service: &str) -> Result<Self> {
        let local_zone = validate_zone(&cfg.local_zone)
            .with_context(|| format!("service `{service}` locality.local_zone"))?;
        let mut seen = HashSet::new();
        seen.insert(local_zone.clone());
        let mut failover_zones = Vec::with_capacity(cfg.failover_zones.len());
        for raw in &cfg.failover_zones {
            let zone = validate_zone(raw)
                .with_context(|| format!("service `{service}` locality.failover_zones"))?;
            anyhow::ensure!(
                seen.insert(zone.clone()),
                "service `{service}` locality contains duplicate zone `{zone}`"
            );
            failover_zones.push(Arc::<str>::from(zone));
        }
        Ok(Self {
            local_zone: Arc::from(local_zone),
            failover_zones: failover_zones.into(),
            allow_unlisted: cfg.allow_unlisted,
        })
    }

    /// 业务作用：将实例 zone 映射为本区优先、指定跨区次之、未列最后的稳定等级。
    ///
    /// 参数说明：`zone` 是可信配置或发现 metadata 中的实例 zone。
    ///
    /// 返回：可参与选择时返回越小越优先的 rank；未列且禁止降级时返回 None。
    fn rank(&self, zone: Option<&str>) -> Option<usize> {
        if zone == Some(self.local_zone.as_ref()) {
            return Some(0);
        }
        if let Some(index) = self
            .failover_zones
            .iter()
            .position(|candidate| zone == Some(candidate.as_ref()))
        {
            return Some(index + 1);
        }
        self.allow_unlisted
            .then_some(self.failover_zones.len().saturating_add(1))
    }
}

/// 校验并规范化一个 locality zone 标识。
///
/// 业务作用：对手写配置与发现 metadata 使用同一字节边界，防止空白/过长值
/// 进入快照或绕过 zone 精确比较。
///
/// 参数说明：`raw` 是外部 zone 字符串。
///
/// 返回：去除首尾空白的 zone；空值或超过 128 bytes 时返回错误。
fn validate_zone(raw: &str) -> Result<String> {
    let zone = raw.trim();
    anyhow::ensure!(!zone.is_empty(), "zone must not be empty");
    anyhow::ensure!(zone.len() <= 128, "zone must be <= 128 bytes");
    anyhow::ensure!(
        zone.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "zone must contain only ASCII letters, digits, '.', '_' or '-'"
    );
    Ok(zone.to_owned())
}

/// 构建期校验后的连接预热策略。
#[derive(Clone)]
pub struct UpstreamPrewarmPolicy {
    /// 每个实例期望预建的空闲连接数。
    pub connections: usize,
    /// 不含 authority 的固定 HEAD 探测 path。
    pub path: Arc<str>,
    /// 单批预热等待响应头的 deadline，单位毫秒。
    pub timeout_ms: u64,
}

impl UpstreamPrewarmPolicy {
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
    /// 参数说明：`raw` 是 `upstreams.services.*.source` 的规范小写值。
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
}

impl LbPolicy {
    /// 管理面展示用的稳定名称。刻意与 [`LbPolicy::parse`] 接受的**规范**写法一致
    /// (而不是别名 `wrr`/`least-conn`),使 `/admin/upstreams` 的输出可以原样写回配置。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::RoundRobin => "round_robin",
            Self::LeastConn => "least_conn",
        }
    }

    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "first" => Ok(Self::First),
            "round_robin" | "round-robin" | "weighted" | "wrr" => Ok(Self::RoundRobin),
            "least_conn" | "least-conn" => Ok(Self::LeastConn),
            other => anyhow::bail!("unsupported lb policy `{other}`"),
        }
    }
}

/// `proxy_next_upstream` 的触发条件、尝试预算和退避策略。
#[derive(Clone)]
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

    /// 是否配置了至少一种实际重试触发条件。
    pub fn has_trigger(&self) -> bool {
        self.error || self.timeout || self.http_502 || self.http_503 || self.http_504
    }

    /// 将配置的 tries 转换成内部最大尝试数。
    pub fn max_attempts(&self) -> usize {
        if self.tries == 0 {
            usize::MAX
        } else {
            self.tries.max(1)
        }
    }
}

/// 实例连续失败达到阈值后的临时摘除策略。
#[derive(Clone, Copy)]
pub struct PassiveHealthPolicy {
    /// 触发摘除所需的连续失败数；0 关闭。
    pub max_fails: u32,
    /// 摘除持续时间，单位毫秒。
    pub fail_timeout_ms: u64,
}

impl PassiveHealthPolicy {
    /// 返回不记录失败、也不摘除实例的策略。
    pub fn disabled() -> Self {
        Self {
            max_fails: 0,
            fail_timeout_ms: 0,
        }
    }

    /// 策略是否同时具备非零阈值和摘除时长。
    pub fn enabled(self) -> bool {
        self.max_fails > 0 && self.fail_timeout_ms > 0
    }
}

/// 上游 HTTP 协议选择：决定转发进入 Hyper H1/H2、raw H2c 还是 QUIC/H3 transport。
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
}

impl UpstreamProtocol {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "auto" => Ok(Self::Auto),
            "h1" | "http1" | "http/1.1" => Ok(Self::H1),
            "h2" | "http2" => Ok(Self::H2),
            "h2c" => Ok(Self::H2c),
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
                anyhow::bail!("unsupported upstream protocol `{other}` (auto|h1|h2|h2c|h3)")
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
    /// 上游 HTTP 协议偏好(review L1),由所属服务复制而来,转发层据此设请求版本。
    pub protocol: UpstreamProtocol,
    /// 建立 TCP transport 的独立超时；0 沿用 native connector 既有行为。
    pub connect_timeout_ms: u64,
    /// HTTP 上游 TLS profile(§36 `proxy_ssl_*`),仅对 `https://` 实例生效。
    pub tls_profile: Option<UpstreamTlsProfile>,
    /// 可信配置/发现提供的 locality zone；None 表示未声明。
    pub zone: Option<Arc<str>>,
    /// 注册中心 metadata 或静态空 metadata;只供 admin 只读展示,不进入 metrics label。
    pub metadata: HashMap<String, String>,
}

impl UpstreamInstance {
    /// 业务作用：把静态实例及其可信 zone 注入统一实例模型，使静态与发现来源共享完全相同
    /// 的协议、TLS、健康身份和 locality 选择语义。
    ///
    /// 参数说明：`cfg` 是静态实例声明；`protocol`/`tls_profile` 来自所属 service。
    ///
    /// 返回：URI、协议、TLS 与 zone 全部合法时返回实例，否则拒绝候选快照。
    fn try_from_cfg(
        cfg: &StaticInstanceCfg,
        protocol: UpstreamProtocol,
        tls_profile: Option<UpstreamTlsProfile>,
    ) -> Result<Self> {
        let mut metadata = HashMap::new();
        if let Some(zone) = &cfg.zone {
            metadata.insert("zone".to_owned(), zone.clone());
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
    /// 参数说明：`uri` 是规范化 endpoint；`weight/down/backup/slow_start_ms` 是调度属性；
    /// `protocol/connect_timeout_ms/tls_profile` 来自服务策略；`metadata` 携带只读发现属性与可选 zone。
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
    /// 业务作用：集中执行所有来源实例的 URI/协议/TLS/zone 校验并生成稳定 health identity。
    ///
    /// 参数说明：`raw_uri` 到 `created_at` 是已经规范化的 endpoint、调度、transport、metadata
    /// 与慢启动时刻；静态和动态入口都必须经过本函数。
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
            None => uri.clone(),
        };
        let zone = metadata
            .get("zone")
            .or_else(|| metadata.get("topology.kubernetes.io/zone"))
            .map(|zone| validate_zone(zone))
            .transpose()
            .context("upstream instance locality zone")?
            .map(Arc::<str>::from);
        Ok(Self {
            uri,
            health_key,
            healthy,
            weight: weight.max(1),
            down,
            backup,
            slow_start_ms,
            created_at,
            protocol,
            connect_timeout_ms,
            tls_profile,
            zone,
            metadata,
        })
    }

    fn is_selectable(&self) -> bool {
        self.healthy && !self.down
    }

    fn effective_weight(&self) -> u32 {
        if self.slow_start_ms == 0 || self.weight <= 1 {
            return self.weight;
        }
        let elapsed_ms = self.created_at.elapsed().as_millis() as u64;
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

/// 在共享实例切片上执行 primary/backup 分层与具体 LB 算法。
///
/// 业务作用：把健康、排除身份、primary/backup 与最优 locality rank 收敛成唯一候选层，
/// 再执行既有 LB，确保本区仍有容量时不泄漏跨区流量。
///
/// 流程与不变式：
/// 1. 先扫描是否存在可用 primary；只要存在，backup 就绝不参与。
/// 2. `first`/`least_conn` 单次扫描，WRR 两次扫描（总权重 + 定位），均不建立候选 `Vec`。
/// 3. 返回只 clone 选中实例的 `Arc`，URI、TLS profile 与 metadata 不做深拷贝。
///
/// # 参数
/// - `instances`: 当前快照/发现版本的不可变实例切片。
/// - `policy`: 服务级 LB 策略。
/// - `locality`: 可选本区优先与有序跨区 failover 策略。
/// - `is_excluded`: 按 URI 或完整身份键判断本次请求不可选择的实例。
/// - `load`: `least_conn` 的在途计数读取器。
/// - `rr`: WRR 的单调游标读取器，仅确有候选且策略为 WRR 时调用一次。
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
    F: FnMut(&str) -> u64,
    R: FnOnce() -> u64,
{
    // 单实例是静态配置和多数 sidecar 场景的绝对热路径。此时 primary/backup 分层、WRR
    // 权重和 least_conn 排序都不可能改变结果；直接校验唯一候选，避免先为 `use_backup`
    // 预扫描、再按策略扫描第二遍。实例仍必须通过 healthy/down 与全部摘除事实，不能把
    // 性能快路径变成健康检查旁路。返回只增加选中实例 Arc 的引用计数，不复制 URI/TLS。
    if let [inst] = instances {
        let inst = inst.as_ref();
        if !inst.is_selectable()
            || locality.is_some_and(|policy| policy.rank(inst.zone.as_deref()).is_none())
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
    let locality_rank = |inst: &UpstreamInstance| {
        locality
            .map(|policy| policy.rank(inst.zone.as_deref()))
            .unwrap_or(Some(0))
    };
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
            let mut best_load = load(first.health_key.as_ref());
            for inst in std::iter::once(second).chain(candidates) {
                let current_load = load(inst.health_key.as_ref());
                if current_load < best_load {
                    best = inst;
                    best_load = current_load;
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
                .map(|inst| inst.effective_weight() as u64)
                .sum::<u64>();
            if total_weight == 0 {
                return first().cloned();
            }
            let mut slot = rr() % total_weight;
            for inst in instances
                .iter()
                .filter(|inst| is_candidate(inst.as_ref(), use_backup))
            {
                let weight = inst.effective_weight() as u64;
                if slot < weight {
                    return Some(inst.clone());
                }
                slot -= weight;
            }
            // total_weight 与同一不可变切片计算，理论上不会走到这里；保底返回首候选避免竞态假设外泄。
            first().cloned()
        }
    }
}

/// 业务作用：将 Nacos SDK 实例快照转换为排序稳定、已验证且携带可信 locality 的 gateway 实例。
///
/// 参数说明：`spec` 是逻辑服务 watch 契约；`discovered` 是本轮完整 Nacos 实例快照。
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
/// 参数说明：`spec` 是 registry watch 契约；`discovered` 是本轮完整中立实例集合。
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

fn validate_upstream_scheme(scheme: &str) -> Result<()> {
    match scheme {
        "http" | "https" => Ok(()),
        other => anyhow::bail!("unsupported upstream scheme `{other}` (http|https)"),
    }
}

/// 业务作用：把静态或动态 service TLS 配置构建成数据面可复用的上游身份与信任策略。
///
/// 参数说明：`cfg_path` 用于解析相对文件；`name` 提供低敏错误上下文；`svc` 是服务配置。
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
    build_upstream_tls_profile_with_material(
        tls.server_name.as_deref(),
        ca_file.as_deref(),
        tls.ca_pem.as_deref(),
        &tls.subject_alt_names,
        client_cert_file.as_deref(),
        client_key_file.as_deref(),
        tls.client_cert_pem.as_deref(),
        tls.client_key_pem.as_deref(),
    )
    .with_context(|| format!("build upstream tls profile for service `{name}`"))
    .map(Some)
}

fn bracket_ipv6_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn f64_to_weight(weight: f64) -> u32 {
    if !weight.is_finite() || weight <= 0.0 {
        return 1;
    }
    weight.round().clamp(1.0, u32::MAX as f64) as u32
}

fn metadata_value<'a>(inst: &'a nasa::discovery::Instance, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| inst.metadata.get(*key).map(String::as_str))
}

fn metadata_bool(inst: &nasa::discovery::Instance, keys: &[&str]) -> Option<bool> {
    metadata_value(inst, keys).and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    })
}

fn metadata_u64(inst: &nasa::discovery::Instance, keys: &[&str]) -> Option<u64> {
    metadata_value(inst, keys).and_then(|v| v.trim().parse::<u64>().ok())
}

#[path = "../../tests/unit/upstream.rs"]
#[cfg(test)]
mod tests;
