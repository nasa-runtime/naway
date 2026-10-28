//! 单向层级请求执行；公共门禁完成后冻结上下文，只把唯一叶子交给终端业务管线。

use super::*;
use crate::control::ownership::{admission::Permit, state::Budget, Consumer, Owner, RequestScope};
use crate::routing::layers::{context::Context as LayerContext, Plan};

#[derive(Default)]
pub(super) struct Execution {
    pub chain: Option<Arc<[Arc<str>]>>,
    pub cors: Option<(Arc<Route>, Box<Parts>)>,
    pub permits: Vec<Permit>,
    owners: Vec<Owner>,
}

pub(super) struct Input<'a> {
    pub snap: &'a GatewaySnapshot,
    pub proxy: &'a crate::config::ProxyRuntime,
    pub plan: &'a Plan,
    pub client_ip: IpAddr,
    pub trusted_inbound: bool,
    pub downstream_proto: &'static str,
    pub request_id: &'a str,
    pub trace: &'a crate::observability::telemetry::ServerTrace,
    pub early: bool,
    pub tunnel: bool,
    pub started: Instant,
}

impl GatewayProxy {
    /// 业务作用：沿唯一父链执行公共安全门，完成后只交付一个叶子，任何拒绝都禁止尝试其它分支。
    ///
    /// 参数说明：
    /// - `input`：固定入口快照和可信连接事实。
    /// - `route`：从根路由推进到当前层的路由引用。
    /// - `parts`：当前管线内的唯一请求头。
    /// - `body`：当前管线内的唯一原始正文所有权槽。
    /// - `identity`：认证后冻结的调用身份。
    /// - `guards`：覆盖完整请求生命周期的各层准入名额。
    /// - `execution`：记录已执行层与变更的请求执行状态。
    ///
    /// 返回：成功为 None，route 已指向唯一叶子；失败返回有界响应，保留已访问链供审计且不发业务上游。
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_layers(
        &self,
        input: Input<'_>,
        route: &mut Arc<Route>,
        parts: &mut Parts,
        body: &mut Option<forward::ForwardBody>,
        identity: &mut AuthorizationIdentity,
        guards: &mut Vec<LimitConnGuard>,
        execution: &mut Execution,
    ) -> Option<Response<BoxBody>> {
        let mut context = LayerContext::default();
        parts
            .extensions
            .insert(crate::security::scopes::LayerLedger::default());
        for header in ["x-naway-workspace", "x-naway-tenant", "x-naway-environment"] {
            parts.headers.remove(header);
        }
        loop {
            let node = &input.plan.topology.nodes[&route.id];
            execution.chain = Some(node.chain.clone());
            // 早期请求与升级隧道没有本执行器的完整普通 HTTP 生命周期，不能先消耗公共策略再降级执行。
            if input.early {
                return Some(text_status(425, "too early"));
            }
            if input.tunnel {
                return Some(text_status(
                    400,
                    "layered routes require an HTTP body lifecycle",
                ));
            }
            // 每个选择阶段都复验配置权威；异步额度或认证结束后不能沿已撤销的父链开放下一层。
            if self.snap.load().version != input.snap.version {
                return Some(text_status(409, "layer authority changed"));
            }
            #[cfg(feature = "config-providers")]
            if route
                .provider_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Some(text_status(503, "configuration source unavailable"));
            }
            if let Some(response) =
                self.admit_layer_owner(&input, route, parts, identity, execution)
            {
                return Some(response);
            }
            if !node.config.branch {
                return None;
            }
            if route.cors.is_some() {
                execution.cors = Some((route.clone(), Box::new(parts.clone())));
            }
            if !route.permits_ip(input.client_ip) || !route.permits_referer(parts) {
                self.metrics.inc_acl_denied();
                return Some(text_status(403, "forbidden"));
            }
            if !route.permits_method(parts) {
                return Some(text_status(405, "method not allowed"));
            }
            if let Some(waf) = &route.waf {
                // 风险由实际 WAF 裁决产生，不读取客户端风险头；monitor 的命中不可被后代 clear 降低。
                let matched = waf.inspect_head(parts);
                context.observe_waf(matched.is_some());
                if let Some(matched) = matched {
                    if let Some(response) =
                        waf_head_decision(route, waf.enforces(), matched, self.metrics.as_ref())
                    {
                        return Some(response);
                    }
                }
            }
            if !identity.authenticated {
                if let Some(response) = self
                    .enforce_auth_chain(
                        input.snap,
                        input.proxy,
                        route,
                        parts,
                        body,
                        input.client_ip,
                        input.trusted_inbound,
                        input.downstream_proto,
                        input.request_id,
                        input.trace,
                        identity,
                        None,
                    )
                    .await
                {
                    return Some(response);
                }
                context.authenticated = identity.authenticated;
                context.consumer = identity.consumer.clone();
                context.claims = identity.jwt_claims.clone();
            }
            if let Some(response) = self
                .enforce_scoped_policies(
                    input.snap,
                    &input.proxy.id,
                    &route.id,
                    identity.authenticated,
                    identity.consumer.as_deref(),
                    parts,
                )
                .await
            {
                return Some(response);
            }
            if let Some(response) = self
                .enforce_limit_req(
                    parts,
                    route,
                    input.client_ip,
                    sentinel::AdmissionContext {
                        generation: input.snap.version,
                        body_upper: body
                            .as_ref()
                            .map_or(Some(0), |body| body.size_hint().upper()),
                        started: input.started,
                    },
                )
                .await
            {
                return Some(response);
            }
            if let Some(response) = self
                .enforce_limit_conn(parts, route, input.client_ip, guards)
                .await
            {
                return Some(response);
            }
            if let Some(cors) = route
                .cors
                .as_ref()
                .filter(|_| is_cors_preflight(parts, route))
            {
                return Some(cors_preflight_response(cors, parts));
            }
            if context.append(&node.config.context).is_err() {
                return Some(text_status(403, "trusted layer context unavailable"));
            }
            // 选择之后不回退；无命中与父层显式拒绝使用不同响应，不能借兄弟路由绕过已选中的策略。
            let Some(child) = input.plan.select(&route.id, parts, &context) else {
                return Some(text_status(404, "no matching child route"));
            };
            *route = child;
        }
    }

    /// 业务作用：为每个跨域层取得一次工作区名额，并复验父身份在子工作区的引用权限。
    ///
    /// 参数说明：
    /// - `input`：固定同代归属
    /// - `route`：固定同代归属
    /// - `parts`：接收当前层状态域
    /// - `identity`：不能被重映射
    /// - `execution`：持有所有已准入域。
    ///
    /// 返回：可进入该层为 None；缺少归属、容量或主体引用权限时返回闭合响应。
    fn admit_layer_owner(
        &self,
        input: &Input<'_>,
        route: &Route,
        parts: &mut Parts,
        identity: &AuthorizationIdentity,
        execution: &mut Execution,
    ) -> Option<Response<BoxBody>> {
        if let Some(subject) = &identity.consumer {
            match input
                .snap
                .ownership
                .resolve_consumer(&input.proxy.id, &route.id, subject.clone())
            {
                Ok(resolved) if resolved == *subject => {}
                _ => return Some(text_status(403, "frozen consumer outside child authority")),
            }
        }
        parts.extensions.insert(Consumer(identity.consumer.clone()));
        if !input.snap.ownership.enabled() {
            return None;
        }
        let Some(owner) = input.snap.ownership.route_owner(&input.proxy.id, &route.id) else {
            return Some(text_status(503, "workspace authority unavailable"));
        };
        if !execution.owners.contains(owner) {
            let permit = match self.workspace_runtime.acquire(&input.snap.ownership, owner) {
                Ok(permit) => permit,
                Err(_) => return Some(text_status(503, "workspace capacity unavailable")),
            };
            if let Some(permit) = permit {
                execution.permits.push(permit);
            }
            execution.owners.push(owner.clone());
        }
        parts.extensions.remove::<Budget>();
        match self.workspace_state.budget(&input.snap.ownership, owner) {
            Ok(Some(budget)) => {
                parts.extensions.insert(budget);
            }
            Ok(None) => {}
            Err(_) => return Some(text_status(503, "workspace state unavailable")),
        }
        parts.extensions.insert(owner.clone());
        parts.extensions.insert(RequestScope(format!(
            "{}:{}:{}",
            owner.namespace(),
            input.proxy.id,
            route.id
        )));
        None
    }
}
