//! 已发布的服务凭据独立于发现新鲜度，续租不重建订阅或延长端点事实。

use super::DynamicUpstreamStore;
use crate::tls::UpstreamTlsProfile;
use crate::upstream::{UpstreamDirectory, UpstreamInstance};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct TlsAuthority {
    pub(super) profile: Option<UpstreamTlsProfile>,
}

impl DynamicUpstreamStore {
    /// 业务作用：让当前发现实例采用已提交配置的凭据期限，保留同来源订阅和端点反馈身份。
    ///
    /// 参数说明：
    /// - `directory`：已经发布为活动配置的服务目录，不能传入尚未提交的候选。
    ///
    /// 返回：仅同步匹配绑定的TLS权限；不改变发现确认状态、更新时间或写者，未变化时不发布新表。
    pub(crate) fn reconcile_credentials(&self, directory: &UpstreamDirectory) {
        let _write = self
            .write_lock
            .lock()
            .expect("dynamic upstream write lock poisoned");
        let current = self.services.load();
        let mut next = None;
        for (name, service) in &directory.services {
            let Some(previous) = current
                .get(name)
                .filter(|state| Some(state.binding) == service.discovery_identity)
            else {
                // 新来源必须取得自己的确认，旧目录不能借一次凭据同步跨越绑定权威。
                continue;
            };
            if previous.tls_authority.as_ref().is_some_and(|authority| {
                same_lease(authority.profile.as_ref(), service.tls_profile.as_ref())
            }) {
                continue;
            }
            let next = next.get_or_insert_with(|| current.as_ref().clone());
            let state = next.get_mut(name).expect("matched dynamic service");
            if state.instances.iter().any(|instance| {
                !same_lease(instance.tls_profile.as_ref(), service.tls_profile.as_ref())
            }) {
                state.instances = rebind_instances(&state.instances, service.tls_profile.as_ref());
            }
            state.tls_authority = Some(TlsAuthority {
                profile: service.tls_profile.clone(),
            });
        }
        if let Some(next) = next {
            // 凭据更新只替换不可变实例；保留发现时间，不能为失联来源续命或恢复已过期事实。
            self.services.store(Arc::new(next));
        }
    }
}

/// 业务作用：识别同材料同授权策略是否已经采用当前截止点，避免周期对账重复复制实例壳。
///
/// 参数说明：
/// - `left`：目录实例或上次对账的TLS权限。
/// - `right`：当前已发布配置的TLS权限。
///
/// 返回：材料、策略和单调截止全部一致为真；本地无profile与带profile不同。
fn same_lease(left: Option<&UpstreamTlsProfile>, right: Option<&UpstreamTlsProfile>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.key == right.key
                && left.client_identity_policy_identity == right.client_identity_policy_identity
                && left.client_identity_not_after == right.client_identity_not_after
        }
        _ => false,
    }
}

/// 业务作用：在控制面更新凭据期限而不更改端点加入时刻、健康身份或负载反馈代际。
///
/// 参数说明：
/// - `instances`：仍属同一固定发现绑定的不可变端点。
/// - `profile`：该绑定已提交的当前TLS权限。
///
/// 返回：只为期限变化的端点构造新实例壳，metadata、URI、材料和不变实例继续共享。
fn rebind_instances(
    instances: &[Arc<UpstreamInstance>],
    profile: Option<&UpstreamTlsProfile>,
) -> Arc<[Arc<UpstreamInstance>]> {
    instances
        .iter()
        .map(|instance| {
            if same_lease(instance.tls_profile.as_ref(), profile) {
                return instance.clone();
            }
            let mut next = instance.as_ref().clone();
            next.tls_profile = profile.cloned();
            Arc::new(next)
        })
        .collect::<Vec<_>>()
        .into()
}
