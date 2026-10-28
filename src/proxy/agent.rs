#[cfg(feature = "agent-protocols")]
use super::AuthorizationIdentity;
use super::{forward, GatewayProxy};
use crate::ai::agent::transport::{Outbound, Transport};
#[cfg(feature = "agent-protocols")]
use crate::ai::agent::VerifiedAuth;
use crate::config::GatewaySnapshot;
use crate::routing::Route;
use crate::runtime::connections::{ConnGuard, LongProto};
#[cfg(feature = "agent-protocols")]
use crate::text_status;
use crate::{full_body, BoxBody};
use anyhow::{ensure, Context, Result};
use futures::future::BoxFuture;
#[cfg(feature = "agent-protocols")]
use http::request::Parts;
use http::{Request, Response};
#[cfg(feature = "agent-protocols")]
use nabudget::RequestBudget;
use std::net::IpAddr;
use std::sync::Arc;
#[cfg(feature = "agent-protocols")]
use std::time::Duration;

/// 工具副作用必须与一次显式预算预留对应，不允许通用上游策略额外复制调用。
#[derive(Clone, Copy)]
pub(super) struct SingleAttempt;

#[cfg(feature = "agent-protocols")]
pub(super) struct AgentRequest {
    pub snap: Arc<GatewaySnapshot>,
    pub route: Arc<Route>,
    pub proxy_id: Arc<str>,
    pub parts: Parts,
    pub body: BoxBody,
    pub identity: AuthorizationIdentity,
    pub client_ip: IpAddr,
    pub trusted_inbound: bool,
    pub client_cert_verified: bool,
    pub downstream_proto: &'static str,
    pub request_id: String,
}

struct GatewayTransport {
    state_budget: Option<crate::control::ownership::state::Budget>,
    gateway: Arc<GatewayProxy>,
    snap: Arc<GatewaySnapshot>,
    route: Arc<Route>,
    proxy_id: Arc<str>,
    guard: Arc<ConnGuard>,
    client_ip: IpAddr,
    trusted_inbound: bool,
    client_cert_verified: bool,
    downstream_proto: &'static str,
    request_id: String,
    deadline: tokio::time::Instant,
}

impl Transport for GatewayTransport {
    /// 业务作用：让 Agent 常驻索引继承路由工作区容量，不能以 session 初始化扩张其它域。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：入站冻结的预算借用。
    fn state_budget(&self) -> Option<&crate::control::ownership::state::Budget> {
        self.state_budget.as_ref()
    }
    /// 业务作用：将 AI 子动作观测绑定到固定路由，不把用户、会话或内容放进指标标签。
    ///
    /// 参数说明：
    /// - `protocol`：是协议动作
    /// - `method`：是协议动作
    /// - `target`：是已编译目录名称。
    ///
    /// 返回：有界指标生命周期守卫。
    fn observe(
        &self,
        protocol: &'static str,
        method: &str,
        target: &str,
    ) -> crate::observability::ai::Operation {
        crate::observability::ai::Operation::new(
            self.gateway.metrics.clone(),
            &self.route.id,
            protocol,
            method,
            target,
        )
    }
    /// 业务作用：让 Agent 子调用复用网关同代实例目录、TLS、连接池和流量预算。
    ///
    /// 参数说明：
    /// - `request`：只包含已编译目标和经过工具 schema 校验的实体。
    ///
    /// 返回：同代网络请求的响应；配置退休、管理关闭或网络失败时返回低敏错误。
    fn send(&self, request: Outbound) -> BoxFuture<'_, Result<Response<BoxBody>>> {
        Box::pin(async move {
            // 在产生外部副作用前重新确认权限代次，旧会话不得因持有 Arc 而绕过配置撤权。
            ensure!(self.live(), "Agent configuration retired");
            let proxy = self
                .snap
                .proxy(&self.proxy_id)
                .context("Agent listener unavailable")?;
            let mut parts = Request::builder()
                .method(request.method)
                .uri(&request.path)
                .body(())?
                .into_parts()
                .0;
            parts.headers = request.headers;
            parts.extensions.insert(SingleAttempt);
            let response = self
                .gateway
                .forward(forward::ForwardRequest {
                    snap: &self.snap,
                    proxy,
                    route: &self.route,
                    parts,
                    body: full_body(request.body),
                    upstream_override: Some(&request.target.upstream),
                    path_override: Some(&request.path),
                    inference_endpoints: None,
                    client_ip: self.client_ip,
                    client_ip_header: None,
                    trusted_inbound: self.trusted_inbound,
                    client_cert_verified: self.client_cert_verified,
                    downstream_proto: self.downstream_proto,
                    request_id: &self.request_id,
                    consumer: None,
                    downstream_upgrade: None,
                    limit_conn_guards: Vec::new(),
                    websocket_max_lifetime_ms: None,
                    websocket_frame_limits: None,
                    trace: None,
                })
                .await
                .map_err(|_| anyhow::anyhow!("Agent upstream transport failed"))?;
            ensure!(self.live(), "Agent configuration retired");
            Ok(response)
        })
    }

    /// 业务作用：将 Agent 权威绑定到当前快照与长连接管理，防止旧代结果在撤权后继续交付。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前快照代次相同且没有管理关闭请求时为 true。
    fn live(&self) -> bool {
        self.gateway.snap.load().version == self.snap.version
            && self.guard.requested_close_code().is_none()
    }

    /// 业务作用：向 Agent 子调用传播入站开始时确定的绝对截止时间。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：包含读取请求实体耗时的原始 deadline，不随子调用重新计时。
    fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
}

impl GatewayProxy {
    /// 业务作用：让有界 AI 治理子调用复用网关固定目标传输、同代快照与管理关闭权威。
    ///
    /// 参数说明：
    /// - `ctx`：是已认证 Chat 上下文
    /// - `deadline`：是整个请求的绝对截止时间。
    ///
    /// 返回：只允许当前快照执行和交付结果的独立凭据传输。
    pub(super) fn ai_transport(
        self: &Arc<Self>,
        ctx: &super::LlmForwardRequest<'_>,
        deadline: tokio::time::Instant,
    ) -> Arc<dyn Transport> {
        let guard = Arc::new(self.conn_registry.register(
            Arc::from(ctx.route.id.as_str()),
            ctx.client_ip,
            ctx.identity.consumer.clone(),
            ctx.snap.version,
            LongProto::Sse,
        ));
        Arc::new(GatewayTransport {
            state_budget: ctx.parts.extensions.get().cloned(),
            gateway: self.clone(),
            snap: ctx.snap.clone(),
            route: ctx.route.clone(),
            proxy_id: Arc::from(ctx.proxy.id.as_str()),
            guard,
            client_ip: ctx.client_ip,
            trusted_inbound: ctx.trusted_inbound,
            client_cert_verified: ctx.client_cert_verified,
            downstream_proto: ctx.downstream_proto,
            request_id: ctx.request_id.to_owned(),
            deadline,
        })
    }

    /// 业务作用：在通用认证完成后进入独立 Agent 协议，以总预算覆盖输入读取和全部子调用。
    ///
    /// 参数说明：
    /// - `ctx`：持有同代路由、冻结身份和唯一入站 body。
    ///
    /// 返回：协议结果；输入超限、非法媒体类型或总时限到期时不进入普通代理兜底。
    #[cfg(feature = "agent-protocols")]
    pub(super) async fn forward_agent(self: &Arc<Self>, ctx: AgentRequest) -> Response<BoxBody> {
        let plan = ctx
            .route
            .agent
            .as_ref()
            .expect("Agent route plan exists")
            .clone();
        if ctx.parts.method == http::Method::POST
            && (!ctx
                .parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .is_some_and(|value| value.trim() == "application/json")
                })
                || ctx
                    .parts
                    .headers
                    .contains_key(http::header::CONTENT_ENCODING))
        {
            return text_status(415, "Agent request must be uncompressed JSON");
        }
        let budget = RequestBudget::from_now(Duration::from_millis(plan.limits().deadline_ms));
        let _cancel = budget.cancel_on_drop();
        let collected = budget
            .run(crate::proxy::request_validation::collect_bounded(
                ctx.body,
                plan.limits().max_request_bytes as u64,
            ))
            .await;
        let body = match collected {
            Ok(Ok(body)) if !body.has_trailers() => body.bytes,
            Ok(Err(crate::proxy::request_validation::CollectError::TooLarge)) => {
                return text_status(413, "Agent request exceeds byte limit")
            }
            _ => return text_status(400, "Agent request could not be read within its budget"),
        };
        let guard = Arc::new(self.conn_registry.register(
            Arc::from(ctx.route.id.as_str()),
            ctx.client_ip,
            ctx.identity.consumer.clone(),
            ctx.snap.version,
            LongProto::Sse,
        ));
        let transport = Arc::new(GatewayTransport {
            state_budget: ctx.parts.extensions.get().cloned(),
            gateway: self.clone(),
            snap: ctx.snap,
            route: ctx.route,
            proxy_id: ctx.proxy_id,
            guard,
            client_ip: ctx.client_ip,
            trusted_inbound: ctx.trusted_inbound,
            client_cert_verified: ctx.client_cert_verified,
            downstream_proto: ctx.downstream_proto,
            request_id: ctx.request_id,
            deadline: budget.deadline(),
        });
        let auth = VerifiedAuth {
            authenticated: ctx.identity.authenticated,
            consumer: ctx.identity.consumer.as_deref(),
            claims: ctx.identity.jwt_claims.as_ref(),
        };
        match budget
            .run(plan.handle(ctx.parts, body, auth, transport))
            .await
        {
            Ok(response) => response,
            Err(_) => text_status(504, "Agent request deadline exceeded"),
        }
    }
}
