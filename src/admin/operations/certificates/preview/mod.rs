//! 原提案预检只产生当前目标策略证明，审批与材料交付仍由各自权威决定。

mod request;
mod response;
mod source;

use super::{authorization::Scope, Error, Store};
use crate::{
    admin::{self, AdminState, BoxBody},
    config::GatewaySnapshot,
};
use std::sync::Arc;

pub(super) struct Context<'a> {
    pub state: &'a Arc<AdminState>,
    pub store: &'a Store,
    pub snapshot: &'a Arc<GatewaySnapshot>,
    pub request: &'a http::request::Parts,
    pub scope: &'a Scope,
    pub principal: &'a str,
}

/// 业务作用：在每个异步边界重新认证同一主体和管理 owner，旧凭据或旧存储不能继续分发候选。
///
/// 参数说明：
/// - `context`：当前请求原凭据、精确快照与共享存储。
///
/// 返回：原请求主体、配置及发行身份仍有效时成功；停机、换代或失权立即拒绝。
fn current(context: &Context<'_>) -> Result<(), Error> {
    // 配置和存储必须仍属于原请求的同一实例；停机或同内容换代也不能延续旧材料分发资格。
    if !context.state.mode.full_control_plane()
        || context.store.stopping.is_cancelled()
        || !Arc::ptr_eq(&context.state.snap.load_full(), context.snapshot)
        || !context
            .snapshot
            .admin_operations
            .as_ref()
            .is_some_and(|plan| {
                plan.config.certificates.enabled && plan.same_bootstrap(&context.store.plan)
            })
        || !context
            .state
            .operations
            .get()
            .is_some_and(|installed| std::ptr::eq(installed.as_ref(), context.store))
    {
        return Err(Error::Conflict);
    }
    // 有效签名或持久提案不能延长浏览器来源、令牌有效期和当前主体资格。
    let identity = admin::authenticate_admin_request(context.request, context.state)
        .map_err(|_| Error::Denied)?;
    if identity.principal_id.as_ref() != context.principal
        || admin::reject_untrusted_admin_browser_origin(context.request, context.state).is_some()
    {
        return Err(Error::Denied);
    }
    context
        .state
        .management
        .action_plan(context.snapshot, &context.store.plan.config.cluster_id)
        .map_err(|_| Error::Unavailable)?;
    Ok(())
}

/// 业务作用：只按原提案身份和空确认正文启动目标预检，不允许请求重新上传候选或改绑成员。
///
/// 参数说明：
/// - `context`：已经经过持久材料入口认证和配额门的当前请求。
/// - `id`：规范的原提案身份。
/// - `bytes`：受限 JSON 空对象。
/// - `permit`：正文接收前取得的真实整请求名额，后续随唯一材料持有者释放。
///
/// 返回：完整原目标的有限策略观察；不改变审批状态、不安装材料、不登记持久执行。
pub(super) async fn inspect(
    context: &Context<'_>,
    id: &str,
    bytes: &[u8],
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<http::Response<BoxBody>, Error> {
    request::inspect(context, id, bytes, permit).await
}
