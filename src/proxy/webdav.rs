//! 文件协议终端复用统一身份、归属、审计和 HTTP 上游治理。

use super::*;
use crate::admin::audit::{AdminAuditPayload, WorkspaceAudit};
use crate::config::webdav::Mode;

pub(super) struct Input<'a> {
    pub forward: forward::ForwardRequest<'a>,
    pub identity: &'a AuthorizationIdentity,
    pub chain: Option<Arc<[Arc<str>]>>,
    pub tunnel: bool,
}

impl GatewayProxy {
    /// 业务作用：在公共安全管线之后执行唯一 DAV 终端，文件写必须先持久审计且始终持有同代权威。
    ///
    /// 参数说明：
    /// - `input`：同一请求的冻结身份、已发布配置、层级链和普通转发上下文。
    ///
    /// 返回：经过协议响应预算的本地或代理响应；审计和权威不满足时不启动业务副作用。
    pub(super) async fn execute_webdav(&self, input: Input<'_>) -> Response<BoxBody> {
        let mut ctx = input.forward;
        let plan = ctx
            .route
            .webdav
            .as_ref()
            .expect("selected DAV plan")
            .clone();
        if input.tunnel {
            return text_status(400, "WebDAV cannot upgrade or tunnel");
        }
        let write = crate::io::webdav::writable(&ctx.parts.method);
        // 秘密锁 token 只证明持锁条件，不能给匿名请求补充稳定身份或业务写权限。
        if write && (!input.identity.authenticated || input.identity.consumer.is_none()) {
            return text_status(403, "WebDAV writes require an authenticated consumer");
        }
        let owner = ctx.snap.ownership.route_owner(&ctx.proxy.id, &ctx.route.id);
        if ctx.snap.ownership.enabled() && owner.is_none() {
            return text_status(403, "WebDAV ownership unavailable");
        }
        let principal: Arc<str> = nasa::crypto::sha256(
            &serde_json::to_string(&(
                owner.map(|owner| owner.namespace()),
                input.identity.consumer.as_deref(),
            ))
            .expect("serializable identity scope"),
        )
        .into();
        let workspace = owner
            .and_then(|owner| ctx.snap.ownership.binding(&owner.workspace))
            .map(|binding| WorkspaceAudit {
                binding,
                candidate_sha256: nasa::crypto::sha256(&plan.semantic().to_string()),
                approved_by: None,
            });
        let method = ctx.parts.method.clone();
        let resource_digest = nasa::crypto::sha256(
            &serde_json::to_string(&(
                &ctx.proxy.id,
                &ctx.route.id,
                ctx.parts.uri.path(),
                ctx.parts
                    .headers
                    .get("destination")
                    .and_then(|value| value.to_str().ok()),
                ctx.request_id,
            ))
            .expect("serializable resource identity"),
        );
        let version = ctx.snap.version;
        let store = self.snap.clone();
        let proxy_id = ctx.proxy.id.clone();
        let chain = input.chain;
        #[cfg(feature = "config-providers")]
        let provider_deadline = ctx.route.provider_deadline;
        let authority: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            let current = store.load();
            if current.version != version {
                return false;
            }
            #[cfg(feature = "config-providers")]
            if provider_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return false;
            }
            chain.as_ref().is_none_or(|chain| {
                current
                    .proxy(&proxy_id)
                    .and_then(|proxy| proxy.router.layers.as_ref())
                    .is_some_and(|plan| plan.fresh(chain))
            })
        });
        let request = Request::from_parts(ctx.parts, ctx.body);
        let mut session = match plan
            .begin(request, ctx.downstream_proto, authority.clone())
            .await
        {
            Ok(session) => session,
            Err(response) => return response,
        };
        let deadline = session.deadline();
        let payload = |phase: &str, status| AdminAuditPayload {
            workspace: workspace.clone(),
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            principal: principal.to_string(),
            method: method.to_string(),
            path: "/webdav".into(),
            resource: "webdav".into(),
            action: "write".into(),
            phase: phase.into(),
            status,
            query_sha256: Some(resource_digest.clone()),
            config_version: version,
        };
        if write {
            // 完整 attempt 是副作用前置条件；取消只能留下待核对意图，不能让未审计写入继续执行。
            if !matches!(
                tokio::time::timeout_at(
                    deadline,
                    self.webdav_audit.record_webdav(payload("attempt", None))
                )
                .await,
                Ok(Ok(()))
            ) {
                return text_status(503, "WebDAV audit unavailable");
            }
        }
        // 审计可能等待磁盘或外部确认，完成后必须复验撤权，不能凭旧许可开始文件动作。
        let mut response = if !authority() || tokio::time::Instant::now() >= deadline {
            text_status(409, "WebDAV authority changed")
        } else if plan.cfg.mode == Mode::Local {
            session.local(principal.clone()).await
        } else {
            match session.proxy_request() {
                Ok(request) => {
                    (ctx.parts, ctx.body) = request.into_parts();
                    let response = match tokio::time::timeout_at(deadline, self.forward(ctx)).await
                    {
                        Ok(Ok(response)) => response,
                        Ok(Err(error)) => {
                            if error.is_upstream_error() {
                                self.metrics.inc_upstream_error();
                            }
                            text_status(error.status().as_u16(), error.message())
                        }
                        Err(_) => text_status(504, "WebDAV upstream deadline exceeded"),
                    };
                    session
                        .proxy_response(response, matches!(method.as_str(), "GET" | "HEAD"))
                        .await
                }
                Err(_) => text_status(400, "invalid WebDAV proxy mapping"),
            }
        };
        if write && response.status().is_server_error() {
            // 响应失败不能证明目录或远端没有发生变化，调用方须核对资源后再决定是否重试。
            response.headers_mut().insert(
                "x-naway-webdav-outcome",
                HeaderValue::from_static("indeterminate"),
            );
        }
        if write
            && !matches!(
                tokio::time::timeout_at(
                    deadline,
                    self.webdav_audit
                        .record_webdav(payload("completed", Some(response.status().as_u16())))
                )
                .await,
                Ok(Ok(()))
            )
        {
            // 文件或远端可能已经提交；不得把审计收据缺失说成回滚，也不能向客户端宣告确定成功。
            let mut uncertain = text_status(
                503,
                "WebDAV completion receipt unavailable; inspect resource before retry",
            );
            uncertain.headers_mut().insert(
                "x-naway-webdav-outcome",
                HeaderValue::from_static("indeterminate"),
            );
            return uncertain;
        }
        response
    }
}
