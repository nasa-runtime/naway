//! 发现写者在串行门内领取和复验发布权，读者一次取得绑定、实例与新鲜度。

mod identity;
mod publisher;
pub(crate) use identity::BindingIdentity;
pub(crate) use publisher::ServicePublisher;
#[cfg(feature = "xds-client")]
pub(crate) use publisher::XdsPublisher;

use super::UpstreamInstance;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct DynamicUpstreamStore {
    pub(super) services: ArcSwap<HashMap<String, DynamicServiceState>>,
    /// 所有目录写入共用串行门，同时保存当前 EDS 整批发布者；不积累已退休身份。
    write_lock: Mutex<Option<Arc<()>>>,
}

impl Default for DynamicUpstreamStore {
    /// 业务作用：构造尚无获权写者或确认实例的动态目录。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无确认事实、无 EDS 发布权的空目录。
    fn default() -> Self {
        Self {
            services: ArcSwap::from_pointee(HashMap::new()),
            write_lock: Mutex::new(None),
        }
    }
}

impl DynamicUpstreamStore {
    /// 业务作用：建立由配置、发现任务及数据面共同持有的目录，读取不等待外部 I/O。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空目录的共享句柄；只有显式领取的发布者可以加入确认实例。
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 业务作用：向控制面提供当前已确认实例的共享切片，不复制实例或 metadata。
    ///
    /// 参数说明：
    /// - `service`：逻辑服务名。
    ///
    /// 返回：确认过的原始事实；数据面必须使用带当前绑定与 TTL 门的读取入口。
    pub fn service_instances(&self, service: &str) -> Option<Arc<[Arc<UpstreamInstance>]>> {
        self.services
            .load()
            .get(service)
            .filter(|state| state.confirmed)
            .map(|state| state.instances.clone())
    }

    /// 业务作用：从同一发布读取实例、来源权威和时间，杜绝用旧时间给另一切片续期。
    ///
    /// 参数说明：
    /// - `service`：本次选择的逻辑服务。
    /// - `binding`：当前配置编译出的发现绑定。
    /// - `stale_ttl_ms`：当前来源允许保留事实的期限，零表示不因本地 TTL 过期。
    ///
    /// 返回：当前绑定已确认且新鲜的非空共享实例；缺席、换代、未确认、过期或空集均不可选择。
    pub(super) fn current_instances(
        &self,
        service: &str,
        binding: Option<BindingIdentity>,
        stale_ttl_ms: u64,
    ) -> Option<Arc<[Arc<UpstreamInstance>]>> {
        let current = self.services.load();
        let state = current.get(service)?;
        if state.availability(binding, stale_ttl_ms, Instant::now()) != Availability::Available
            || state.instances.is_empty()
        {
            // 当前计划不能采纳未获权或过期事实；缺少端点也不能从旧目录补回实例。
            return None;
        }
        Some(state.instances.clone())
    }

    /// 业务作用：为一个 native 注册订阅取得唯一发布权，同时撤销同名旧写者。
    ///
    /// 参数说明：
    /// - `service`：当前逻辑服务名。
    /// - `binding`：同一已发布配置的来源及转换身份。
    ///
    /// 返回：只能写当前服务的发布句柄；换代不会把旧结果视为新发现，也不延长旧事实期限。
    pub(crate) fn claim_service(
        self: &Arc<Self>,
        service: &str,
        binding: BindingIdentity,
    ) -> ServicePublisher {
        let owner = Arc::new(());
        let _write = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let mut next = self.services.load().as_ref().clone();
        // 新 owner 先进入同一目录，旧发布、触活和退出随后都必须在这个门内失权。
        install_owner(&mut next, service, binding, &owner);
        self.services.store(Arc::new(next));
        ServicePublisher {
            store: self.clone(),
            service: Arc::from(service),
            binding,
            owner,
        }
    }

    /// 业务作用：为 EDS 原子批次接管完整服务集合，并撤销本代不再拥有的旧 EDS 服务。
    ///
    /// 参数说明：
    /// - `bindings`：本代已冻结的全部逻辑服务映射。
    ///
    /// 返回：只能整批发布这些映射的句柄；相同绑定沿用已确认 LKG 的原时间，不伪造一次新确认。
    #[cfg(feature = "xds-client")]
    pub(crate) fn claim_xds(
        self: &Arc<Self>,
        bindings: HashMap<String, BindingIdentity>,
    ) -> XdsPublisher {
        let owner = Arc::new(());
        let mut active = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let mut next = self.services.load().as_ref().clone();
        // 整批先切换权威，再发布目录；旧 stream 不能在新代领取后提交部分旧资源或续期。
        *active = Some(owner.clone());
        next.retain(|name, state| !state.binding.xds || bindings.contains_key(name));
        for (name, binding) in &bindings {
            install_owner(&mut next, name, *binding, &owner);
        }
        self.services.store(Arc::new(next));
        XdsPublisher {
            store: self.clone(),
            bindings: Arc::new(bindings),
            owner,
        }
    }

    /// 业务作用：在当前配置关闭 EDS 发布时撤销其同步权威，避免只中止任务后仍有迟到写入。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：清除当前 EDS 事实并停止后续写权；native 注册中心条目保持各自 owner。
    #[cfg(feature = "xds-client")]
    pub(crate) fn revoke_xds(&self) {
        let mut active = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        // 先撤销令牌再移除目录；旧 EDS 句柄既不能发布，也不能覆盖 native 已接管的服务。
        *active = None;
        let mut next = self.services.load().as_ref().clone();
        next.retain(|_, state| !state.binding.xds);
        self.services.store(Arc::new(next));
    }
}

#[derive(Clone)]
pub(super) struct DynamicServiceState {
    pub(super) instances: Arc<[Arc<UpstreamInstance>]>,
    pub(super) updated_at: Instant,
    pub(super) binding: BindingIdentity,
    pub(super) confirmed: bool,
    owner: Arc<()>,
}

#[derive(PartialEq, Eq)]
pub(super) enum Availability {
    Missing,
    Stale,
    Available,
}

impl DynamicServiceState {
    /// 业务作用：对数据面与管理观测使用同一绑定、确认及陈旧判据，未知不伪装成零实例。
    ///
    /// 参数说明：
    /// - `binding`：当前服务要求的配置身份。
    /// - `stale_ttl_ms`：允许沿用确认事实的期限。
    /// - `now`：本次目录读取冻结的时间。
    ///
    /// 返回：未获当前绑定确认时未知，超过 TTL 时过期，其余包括已确认空集均为可观察事实。
    pub(super) fn availability(
        &self,
        binding: Option<BindingIdentity>,
        stale_ttl_ms: u64,
        now: Instant,
    ) -> Availability {
        if binding != Some(self.binding) || !self.confirmed {
            // 旧来源和未确认空槽没有当前读权，不能暴露旧数量或把缺证据说成健康。
            return Availability::Missing;
        }
        if stale_ttl_ms != 0
            && now.saturating_duration_since(self.updated_at).as_millis() > u128::from(stale_ttl_ms)
        {
            return Availability::Stale;
        }
        Availability::Available
    }
}

/// 业务作用：在串行发布门内转交或建立单服务槽位，同绑定沿用确认事实，换绑定撤销旧实例。
///
/// 参数说明：
/// - `next`：尚未发布的完整目录。
/// - `service`：被接管的逻辑服务。
/// - `binding`：新写者获准发布的来源身份。
/// - `owner`：本次新领取的唯一令牌。
///
/// 返回：原地建立新 owner；领取自身不是发现确认，不推进被保留事实的时间。
fn install_owner(
    next: &mut HashMap<String, DynamicServiceState>,
    service: &str,
    binding: BindingIdentity,
    owner: &Arc<()>,
) {
    if let Some(state) = next
        .get_mut(service)
        .filter(|state| state.binding == binding)
    {
        state.owner = owner.clone();
        return;
    }
    // 来源或转换语义改变后必须重新取得确认；空槽表示未知，不冒充注册中心返回空集。
    next.insert(
        service.to_owned(),
        DynamicServiceState {
            instances: Arc::from([]),
            updated_at: Instant::now(),
            binding,
            confirmed: false,
            owner: owner.clone(),
        },
    );
}

/// 业务作用：冻结一次真实发现结果，保留同一端点的启动与反馈代际，身份仅在控制面分配。
///
/// 参数说明：
/// - `service`：拥有这些实例的逻辑服务。
/// - `previous`：同绑定、同 owner 下原已确认实例。
/// - `instances`：完整转换和校验通过的端点。
///
/// 返回：共享不可变实例切片；没有逐请求字符串构造或实例复制。
fn freeze_instances(
    service: &str,
    previous: &DynamicServiceState,
    instances: Vec<UpstreamInstance>,
) -> Arc<[Arc<UpstreamInstance>]> {
    instances
        .into_iter()
        .map(|mut instance| {
            if let Some(old) = previous
                .instances
                .iter()
                .find(|old| old.health_key == instance.health_key)
            {
                instance.created_at = old.created_at;
                instance.feedback_generation = old.feedback_generation;
            }
            instance.bind_feedback_service(service);
            Arc::new(instance)
        })
        .collect::<Vec<_>>()
        .into()
}
