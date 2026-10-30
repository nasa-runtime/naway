//! 发布句柄把真实写入、保鲜和退出限定在领取时的唯一 owner 内。

use super::{freeze_instances, BindingIdentity, DynamicServiceState, DynamicUpstreamStore};
use crate::upstream::UpstreamInstance;
#[cfg(feature = "xds-client")]
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub(crate) struct ServicePublisher {
    pub(super) store: Arc<DynamicUpstreamStore>,
    pub(super) service: Arc<str>,
    pub(super) binding: BindingIdentity,
    pub(super) owner: Arc<()>,
}

impl ServicePublisher {
    /// 业务作用：在原订阅仍拥有该服务时发布完整端点，失权结果不能覆盖新目录。
    ///
    /// 参数说明：
    /// - `instances`：按原冻结 spec 完整校验后的实例。
    ///
    /// 返回：持有同步发布权时原子替换并返回真；已被撤销或接管时无副作用返回假。
    pub(crate) fn publish(&self, instances: Vec<UpstreamInstance>) -> bool {
        let _write = self
            .store
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.store.services.load();
        let Some(previous) = current
            .get(self.service.as_ref())
            .filter(|state| self.owns(state))
        else {
            // 中止任务不是发布证明；同名新订阅接管后，旧网络结果即使有效也必须丢弃。
            return false;
        };
        let instances = freeze_instances(&self.service, previous, instances);
        let mut next = current.as_ref().clone();
        next.insert(
            self.service.to_string(),
            DynamicServiceState {
                instances,
                updated_at: Instant::now(),
                binding: self.binding,
                confirmed: true,
                owner: self.owner.clone(),
            },
        );
        self.store.services.store(Arc::new(next));
        true
    }

    /// 业务作用：仅由当前存活订阅延长已确认非空事实的 freshness，旧心跳不能给新来源续期。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前 owner 返回真，未确认或空集不更新时间；已失权返回假，调用方应结束旧订阅。
    pub(crate) fn touch(&self) -> bool {
        let _write = self
            .store
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.store.services.load();
        let Some(previous) = current
            .get(self.service.as_ref())
            .filter(|state| self.owns(state))
        else {
            // 旧连接仍活着不代表它有当前目录的续期权，不能让已失联的新来源永远新鲜。
            return false;
        };
        if !previous.confirmed || previous.instances.is_empty() {
            return true;
        }
        let mut next = current.as_ref().clone();
        next.get_mut(self.service.as_ref())
            .expect("owned service was present")
            .updated_at = Instant::now();
        self.store.services.store(Arc::new(next));
        true
    }

    /// 业务作用：订阅退休时只撤销自己仍拥有的条目，旧退出事件不能删除后来发布的实例。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：删除当前 owner 条目时为真；已经失权时保持新目录并返回假。
    pub(crate) fn revoke(&self) -> bool {
        let _write = self
            .store
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.store.services.load();
        if !current
            .get(self.service.as_ref())
            .is_some_and(|state| self.owns(state))
        {
            // 退出必须消费原 owner；不能把逻辑名称当作删除新一代目录的权限。
            return false;
        }
        let mut next = current.as_ref().clone();
        next.remove(self.service.as_ref());
        self.store.services.store(Arc::new(next));
        true
    }

    /// 业务作用：后台退避或重连前停止已退休订阅，真正发布时仍在串行门内再次复验。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：读取时原 owner 仍持有同一绑定为真；此结果不代替后续发布门。
    pub(crate) fn is_current(&self) -> bool {
        self.store
            .services
            .load()
            .get(self.service.as_ref())
            .is_some_and(|state| self.owns(state))
    }

    /// 业务作用：任务对账时同时核对新配置绑定，防止仍持有旧目录的任务阻止必要的重新订阅。
    ///
    /// 参数说明：
    /// - `binding`：新快照为该逻辑服务编译的发现身份。
    ///
    /// 返回：新绑定与原绑定相同且仍有当前发布权时为真，其余必须退休并重新领取。
    pub(crate) fn is_current_for(&self, binding: Option<BindingIdentity>) -> bool {
        binding == Some(self.binding) && self.is_current()
    }

    /// 业务作用：用不可复用的 owner 与固定绑定共同判定原订阅写权，防止同名来源回切后重获旧权。
    ///
    /// 参数说明：
    /// - `state`：同次目录读取中的服务条目。
    ///
    /// 返回：原 owner 和原绑定同时一致时为真。
    fn owns(&self, state: &DynamicServiceState) -> bool {
        Arc::ptr_eq(&state.owner, &self.owner) && state.binding == self.binding
    }
}

#[derive(Clone)]
#[cfg(feature = "xds-client")]
pub(crate) struct XdsPublisher {
    pub(super) store: Arc<DynamicUpstreamStore>,
    pub(super) bindings: Arc<HashMap<String, BindingIdentity>>,
    pub(super) owner: Arc<()>,
}

#[cfg(feature = "xds-client")]
impl XdsPublisher {
    /// 业务作用：将已完整验证的 EDS response 作为一个仍获权的批次发布，禁止失权后的部分应用。
    ///
    /// 参数说明：
    /// - `replacement`：本代所有服务的完整实例；省略受管服务表示该服务已确认没有端点。
    ///
    /// 返回：整批权威成立时单次发布并返回真；任一服务失权或含非受管键时无副作用返回假。
    pub(crate) fn publish(&self, mut replacement: HashMap<String, Vec<UpstreamInstance>>) -> bool {
        let active = self
            .store
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.store.services.load();
        if !self.owns(active.as_ref(), current.as_ref())
            || replacement
                .keys()
                .any(|key| !self.bindings.contains_key(key))
        {
            // ACK 必须以完整实际发布为前提；任一服务被新来源接管都使整批旧 response 失去写权。
            return false;
        }
        let mut next = current.as_ref().clone();
        for (service, binding) in self.bindings.iter() {
            let previous = current.get(service).expect("owned EDS service was present");
            let instances = freeze_instances(
                service,
                previous,
                replacement.remove(service).unwrap_or_default(),
            );
            next.insert(
                service.clone(),
                DynamicServiceState {
                    instances,
                    updated_at: Instant::now(),
                    binding: *binding,
                    confirmed: true,
                    owner: self.owner.clone(),
                },
            );
        }
        self.store.services.store(Arc::new(next));
        true
    }

    /// 业务作用：在 ADS 重连及 timer 前停止已退休批次，实际发布仍再次消费同步权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前 EDS owner 和每个受管服务均未被接管时为真。
    pub(crate) fn is_current(&self) -> bool {
        let active = self
            .store
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        self.owns(active.as_ref(), self.store.services.load().as_ref())
    }

    /// 业务作用：对单个已冻结目录核对完整 EDS 集合，不用在线服务子集缩小原发布权范围。
    ///
    /// 参数说明：
    /// - `active`：同一串行门中的当前 EDS owner。
    /// - `current`：同次读取的完整实例目录。
    ///
    /// 返回：批次与全部服务的 owner、绑定同时成立为真，空批次也必须持有当前 owner。
    fn owns(
        &self,
        active: Option<&Arc<()>>,
        current: &HashMap<String, DynamicServiceState>,
    ) -> bool {
        active.is_some_and(|active| Arc::ptr_eq(active, &self.owner))
            && self.bindings.iter().all(|(service, binding)| {
                current.get(service).is_some_and(|state| {
                    Arc::ptr_eq(&state.owner, &self.owner) && state.binding == *binding
                })
            })
    }
}
