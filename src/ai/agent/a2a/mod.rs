mod catalog;
mod protocol;
mod rest;

use super::config::{A2aBinding, A2aCfg, LimitsCfg, SecurityCfg};
use super::identity::{validate_security, Acl, Identity};
use super::transport::{
    collect, hold, json_response, validate_limits, wait, Events, Target, Transport,
};
use crate::BoxBody;
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use http::{request::Parts, Method, Response};
use nabudget::RequestBudget;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub(super) struct Plan {
    pub security: SecurityCfg,
    pub limits: LimitsCfg,
    cfg: A2aCfg,
    target: Arc<Target>,
    card_target: Arc<Target>,
    base: String,
    private_authority: String,
    discovery: Acl,
    invocation: Acl,
    inflight: Arc<Semaphore>,
    control: Arc<Semaphore>,
    catalog: Arc<catalog::Catalog>,
}

/// 业务作用：在任务状态正式发布后累计固定状态指标，不把 task/context ID 变成时序标签。
///
/// 参数说明：
/// - `transport`：绑定路由
/// - `value`：是状态机已接受的对象。
///
/// 返回：有状态时记录一次低敏观测，纯消息或产物事件不补造状态。
fn observe_state(transport: &dyn Transport, value: &Value) {
    let state = match value.pointer("/status/state").and_then(Value::as_str) {
        Some("submitted") => "submitted",
        Some("working") => "working",
        Some("input-required") => "input-required",
        Some("auth-required") => "auth-required",
        Some("completed") => "completed",
        Some("canceled") => "canceled",
        Some("failed") => "failed",
        Some("rejected") => "rejected",
        _ => return,
    };
    transport.observe("a2a", "task.state", "").outcome(state);
}

impl Plan {
    /// 业务作用：输出 A2A 的显式协议、binding 和任务保留边界，不列出任务正文或内部 agent 地址。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：低敏协议与容量摘要。
    pub(super) fn summary(&self) -> Value {
        json!({
            "protocol":"a2a",
            "protocol_version":"0.3.0",
            "binding":if matches!(self.cfg.binding, A2aBinding::Jsonrpc) {
                "jsonrpc"
            } else {
                "rest"
            },
            "max_tasks":self.limits.max_sessions,
            "task_retention_ms":self.limits.session_ttl_ms,
            "max_inflight":self.limits.max_inflight
        })
    }
    /// 业务作用：冻结 A2A 协议版本、binding、对外地址与身份目录，禁止后端 card 改写实际外呼目标。
    ///
    /// 参数说明：
    /// - `cfg`：是完整路由策略
    /// - `dir`：是 SecretSource 基准目录。
    ///
    /// 返回：受限的 A2A 计划；非法认证声明、地址、版本或预算拒绝候选。
    pub(super) fn build(cfg: &A2aCfg, dir: &Path) -> Result<Arc<Self>> {
        ensure!(
            cfg.protocol_version == "0.3.0",
            "unsupported A2A protocol version"
        );
        validate_security(&cfg.security)?;
        validate_limits(&cfg.limits)?;
        let public: http::Uri = cfg.public_url.parse().context("invalid A2A public URL")?;
        ensure!(
            matches!(public.scheme_str(), Some("http" | "https"))
                && public
                    .authority()
                    .is_some_and(|authority| !authority.as_str().contains('@'))
                && public.query().is_none()
                && !cfg.public_url.contains(['#', '%', '\\', '{', '}', '$'])
                && cfg.public_url.len() <= 2048,
            "invalid A2A public URL"
        );
        ensure!(
            !public
                .path()
                .split('/')
                .any(|part| matches!(part, "." | "..")),
            "invalid A2A public path"
        );
        let target = Target::build(&cfg.target, dir)?;
        ensure!(
            !cfg.target.path.contains(['{', '}', '%']),
            "A2A target cannot be a template"
        );
        let mut card = cfg.target.clone();
        card.path = cfg.card_path.clone();
        let card_target = Target::build(&card, dir)?;
        ensure!(
            !cfg.card_path.contains(['{', '}', '%']),
            "invalid A2A card path"
        );
        validate_card_security(cfg)?;
        let private_authority = cfg
            .target
            .uri
            .parse::<http::Uri>()?
            .authority()
            .unwrap()
            .to_string();
        Ok(Arc::new(Self {
            security: cfg.security.clone(),
            limits: cfg.limits.clone(),
            cfg: cfg.clone(),
            target,
            card_target,
            base: public.path().trim_end_matches('/').to_owned(),
            private_authority,
            discovery: Acl::build(&cfg.discovery)?,
            invocation: Acl::build(&cfg.invocation)?,
            inflight: Arc::new(Semaphore::new(cfg.limits.max_inflight)),
            control: Arc::new(Semaphore::new(cfg.limits.max_inflight.min(16))),
            catalog: catalog::Catalog::new(cfg.limits.clone()),
        }))
    }

    /// 业务作用：为 A2A 请求和流占用同一个并发槽，并将发现与任务操作独立授权。
    ///
    /// 参数说明：
    /// - `parts`：是有界请求
    /// - `body`：是有界请求
    /// - `identity`：是本次认证主体
    /// - `transport`：绑定同代网关。
    ///
    /// 返回：绑定的协议结果或低敏错误；流结束前不返还并发容量。
    pub(super) async fn handle(
        self: &Arc<Self>,
        parts: Parts,
        body: Bytes,
        identity: Identity,
        transport: Arc<dyn Transport>,
    ) -> Response<BoxBody> {
        let action = protocol::decode(self.cfg.binding, &self.base, &parts, &body)
            .map(|call| call.method)
            .unwrap_or_else(|_| {
                if parts.method == Method::GET {
                    "agent/card".into()
                } else {
                    "unsupported".into()
                }
            });
        // 业务流占满并发槽时仍保留取消入口；独立控制槽同样有硬上限，不能成为无界外呼旁路。
        let slots = if action == "tasks/cancel" {
            &self.control
        } else {
            &self.inflight
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            return self.error(429, Value::Null, -32000, "A2A capacity exhausted");
        };
        let operation = transport.observe("a2a", &action, "");
        let response = self
            .handle_inner(parts, body, identity, transport.clone())
            .await;
        crate::observability::ai::response(
            hold(
                crate::ai::delivery::guard(response, move || transport.live()),
                permit,
            ),
            operation,
        )
    }

    /// 业务作用：在任何上游动作前完成 binding、能力、owner 和配额检查，再按当前动作租约交付结果。
    ///
    /// 参数说明：
    /// - `parts`：是唯一请求实体
    /// - `body`：是唯一请求实体
    /// - `identity`：不含凭据
    /// - `transport`：只访问固定目标。
    ///
    /// 返回：经过状态机校验的响应；明确拒绝、依赖故障或撤权不会回落透传。
    async fn handle_inner(
        self: &Arc<Self>,
        parts: Parts,
        body: Bytes,
        identity: Identity,
        transport: Arc<dyn Transport>,
    ) -> Response<BoxBody> {
        let budget = RequestBudget::until(transport.deadline());
        let _cancel = budget.cancel_on_drop();
        if parts.method == Method::GET
            && parts.uri.path() == format!("{}/.well-known/agent-card.json", self.base)
        {
            if !self.discovery.allows(&identity) {
                return self.error(403, Value::Null, -32000, "A2A discovery denied");
            }
            if parts.uri.query().is_some() || !body.is_empty() {
                return self.error(400, Value::Null, -32602, "Invalid A2A discovery request");
            }
            return match self.card(&budget, transport.as_ref()).await {
                Ok(card) => json_response(200, card),
                Err(_) => self.error(502, Value::Null, -32603, "A2A discovery unavailable"),
            };
        }
        let call = match protocol::decode(self.cfg.binding, &self.base, &parts, &body) {
            Ok(call) => call,
            Err(_) => {
                return self.error(
                    400,
                    Value::Null,
                    -32602,
                    "A2A method, binding or parameters not enabled",
                )
            }
        };
        if !self.invocation.allows(&identity) {
            return self.error(403, call.id, -32000, "A2A invocation denied");
        }
        let lease = match self.catalog.reserve(catalog::Reservation {
            owner: identity.key,
            task: call.task.as_deref(),
            context: call.context.as_deref(),
            method: &call.method,
            bytes: body.len(),
            deadline: transport.deadline(),
            state_budget: transport.state_budget(),
        }) {
            Ok(lease) => lease,
            // 不区分他人任务与不存在的任务，避免客户端利用 ID 探测其它主体的状态。
            Err(_) => {
                return self.error(
                    if call.task.is_some() || call.context.is_some() {
                        404
                    } else {
                        429
                    },
                    call.id,
                    -32001,
                    "A2A task unavailable or action budget denied",
                )
            }
        };
        let opened: Result<Response<BoxBody>> = async {
            let card = self.card(&lease.budget, transport.as_ref()).await?;
            ensure!(
                !call.streaming
                    || card.pointer("/capabilities/streaming") == Some(&Value::Bool(true)),
                "A2A streaming capability unavailable"
            );
            let (method, path, value) =
                protocol::outbound(&call, self.cfg.binding, &self.target.path)?;
            let mut request = self.target.request(
                method,
                if value.is_null() {
                    Bytes::new()
                } else {
                    Bytes::from(value.to_string())
                },
            );
            request.path = path;
            let response =
                wait(&lease.budget, transport.as_ref(), transport.send(request)).await??;
            ensure!(response.status().is_success(), "A2A upstream action failed");
            Ok(response)
        }
        .await;
        let response = match opened {
            Ok(response) => response,
            Err(_) => {
                return self.error(
                    502,
                    call.id,
                    -32603,
                    "A2A capability or upstream action unavailable",
                )
            }
        };
        if call.streaming {
            return match Events::new(
                response,
                self.limits.max_response_bytes,
                self.limits.max_frame_bytes,
            ) {
                Ok(events) => self.stream(call, lease, events, transport),
                Err(_) => self.error(502, call.id, -32603, "Invalid A2A event stream"),
            };
        }
        let result: Result<Value> = async {
            let bytes = collect(
                response,
                self.limits.max_response_bytes,
                &lease.budget,
                transport.as_ref(),
            )
            .await?;
            let value = protocol::result(
                self.cfg.binding,
                &call.id,
                serde_json::from_slice(&bytes)?,
                false,
            )?;
            ensure!(
                !value.to_string().contains(&self.private_authority),
                "A2A response contains a private endpoint"
            );
            ensure!(transport.live(), "A2A configuration retired");
            lease.publish(&value)?;
            observe_state(transport.as_ref(), &value);
            let value = protocol::envelope(self.cfg.binding, &call, value)?;
            ensure!(
                value.to_string().len() <= self.limits.max_response_bytes,
                "A2A encoded response exceeds budget"
            );
            Ok(value)
        }
        .await;
        tracing::info!(method = %call.method, outcome = if result.is_ok() {
            "completed"
        } else {
            "failed"
        }, "Agent A2A invocation");
        match result {
            Ok(value) => json_response(200, value),
            Err(_) => self.error(
                502,
                call.id,
                -32603,
                "A2A result rejected or action cancelled",
            ),
        }
    }

    /// 业务作用：发现固定 agent 的已知能力并生成网关 card，绝不公开上游路由、认证端点和签名。
    ///
    /// 参数说明：
    /// - `budget`：是当前动作绝对预算
    /// - `transport`：绑定配置与 drain 权威。
    ///
    /// 返回：只含批准字段和网关 URL 的 card；版本、能力或正文不一致时拒绝。
    async fn card(&self, budget: &RequestBudget, transport: &dyn Transport) -> Result<Value> {
        let response = wait(
            budget,
            transport,
            transport.send(self.card_target.request(Method::GET, Bytes::new())),
        )
        .await??;
        ensure!(response.status().is_success(), "A2A card unavailable");
        let bytes = collect(response, self.limits.max_response_bytes, budget, transport).await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value.get("protocolVersion").and_then(Value::as_str) == Some("0.3.0"),
            "A2A card protocol version mismatch"
        );
        let capabilities = &value["capabilities"];
        protocol::keys(
            capabilities,
            &[
                "streaming",
                "pushNotifications",
                "stateTransitionHistory",
                "extensions",
            ],
        )?;
        ensure!(
            ["streaming", "pushNotifications", "stateTransitionHistory"]
                .iter()
                .all(|key| capabilities.get(key).is_none_or(Value::is_boolean))
                && capabilities
                    .get("extensions")
                    .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
            "A2A capability not enabled"
        );
        let binding = if matches!(self.cfg.binding, A2aBinding::Jsonrpc) {
            "JSONRPC"
        } else {
            "HTTP+JSON"
        };
        let preferred = value
            .get("preferredTransport")
            .and_then(Value::as_str)
            .unwrap_or("JSONRPC");
        ensure!(
            preferred == binding
                || value
                    .get("additionalInterfaces")
                    .and_then(Value::as_array)
                    .is_some_and(|interfaces| interfaces.iter().any(|interface| interface
                        .get("transport")
                        .and_then(Value::as_str)
                        == Some(binding))),
            "A2A binding not supported by agent"
        );
        let mut card = json!({
            "protocolVersion":"0.3.0",
            "url":self.cfg.public_url,
            "preferredTransport":binding,
            "additionalInterfaces":[{
                "url":self.cfg.public_url,
                "transport":binding
            }],
            "capabilities":{
                "streaming":capabilities.get("streaming").and_then(Value::as_bool).unwrap_or(false),
                "pushNotifications":false,
                "stateTransitionHistory":false
            },
            "supportsAuthenticatedExtendedCard":false,
            "securitySchemes":self.cfg.card_security_schemes,
            "security":self.cfg.card_security
        });
        for key in ["name", "description", "version"] {
            let text = value
                .get(key)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty() && text.len() <= 4096)
                .context("A2A card text required")?;
            ensure!(
                !text.contains("://") && !text.contains(&self.private_authority),
                "A2A card contains a private address"
            );
            card[key] = json!(text);
        }
        for key in ["defaultInputModes", "defaultOutputModes"] {
            protocol::strings(&value[key], 32, 128)?;
            card[key] = value[key].clone();
        }
        let skills = value
            .get("skills")
            .and_then(Value::as_array)
            .filter(|skills| skills.len() <= 128)
            .context("A2A skills required")?;
        let mut output = Vec::new();
        for skill in skills {
            let mut item = json!({});
            for key in ["id", "name", "description"] {
                let text = skill
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|text| text.len() <= 4096)
                    .context("A2A skill text required")?;
                item[key] = json!(text);
            }
            protocol::strings(&skill["tags"], 32, 128)?;
            item["tags"] = skill["tags"].clone();
            for key in ["examples", "inputModes", "outputModes"] {
                if let Some(value) = skill.get(key) {
                    protocol::strings(value, 32, 4096)?;
                    item[key] = value.clone();
                }
            }
            ensure!(
                !item.to_string().contains("://")
                    && !item.to_string().contains(&self.private_authority),
                "A2A skill contains an endpoint"
            );
            output.push(item);
        }
        card["skills"] = json!(output);
        ensure!(
            card.to_string().len() <= self.limits.max_response_bytes,
            "A2A gateway card exceeds budget"
        );
        Ok(card)
    }

    /// 业务作用：把经逐事件状态门的 A2A 流交付下游，断开后保留有限任务索引用于重新订阅。
    ///
    /// 参数说明：
    /// - `call`：是绑定动作
    /// - `lease`：持有交付权限
    /// - `events`：是有界源
    /// - `transport`：复验配置。
    ///
    /// 返回：带背压的 SSE；事件 ID 不缓存，重新订阅仅请求上游后续状态。
    fn stream(
        self: &Arc<Self>,
        call: protocol::Call,
        lease: catalog::Lease,
        events: Events,
        transport: Arc<dyn Transport>,
    ) -> Response<BoxBody> {
        let state = Stream {
            plan: self.clone(),
            call,
            lease,
            events,
            transport,
            seen: false,
            finished: false,
        };
        let stream = futures::stream::unfold(state, |mut state| async move {
            if state.finished {
                return None;
            }
            let result: Result<Value> = async {
                let raw = state
                    .events
                    .next(&state.lease.budget, state.transport.as_ref())
                    .await?
                    .context("A2A stream ended before final state")?;
                let value = protocol::result(state.plan.cfg.binding, &state.call.id, raw, true)?;
                let kind = value["kind"].as_str().unwrap_or("");
                ensure!(
                    state.seen
                        || state.call.method == "tasks/resubscribe"
                        || matches!(kind, "task" | "message"),
                    "A2A initial stream event must establish a task"
                );
                ensure!(
                    !state.seen || !matches!(kind, "task" | "message"),
                    "A2A stream cannot replace an established task"
                );
                ensure!(
                    !value.to_string().contains(&state.plan.private_authority),
                    "A2A event contains a private endpoint"
                );
                state.lease.publish(&value)?;
                observe_state(state.transport.as_ref(), &value);
                state.seen = true;
                state.finished = kind == "message"
                    || value.get("final") == Some(&Value::Bool(true))
                    || value
                        .pointer("/status/state")
                        .and_then(Value::as_str)
                        .is_some_and(|state| {
                            catalog::terminal(state)
                                || matches!(state, "input-required" | "auth-required")
                        });
                protocol::envelope(state.plan.cfg.binding, &state.call, value)
            }
            .await;
            let frame = match result {
                Ok(value) => Ok(hyper::body::Frame::data(Bytes::from(format!(
                    "data: {value}\n\n"
                )))),
                Err(_) => {
                    state.finished = true;
                    Err::<_, crate::BoxError>(
                        anyhow::anyhow!("A2A event rejected or action cancelled").into(),
                    )
                }
            };
            Some((frame, state))
        });
        Response::builder()
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .header(http::header::CACHE_CONTROL, "no-store")
            .body(http_body_util::BodyExt::boxed(
                http_body_util::StreamBody::new(stream),
            ))
            .expect("fixed A2A event response")
    }

    /// 业务作用：将失败映射为所选 binding 的低敏错误，不反射任务正文或上游地址。
    ///
    /// 参数说明：
    /// - `status`：是拒绝分类
    /// - `code`：是拒绝分类
    /// - `id`：是受限 RPC 标识
    /// - `message`：是固定原因。
    ///
    /// 返回：不缓存的错误响应。
    fn error(&self, status: u16, id: Value, code: i64, message: &'static str) -> Response<BoxBody> {
        if matches!(self.cfg.binding, A2aBinding::Jsonrpc) {
            json_response(
                status,
                json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "error":{
                        "code":code,
                        "message":message
                    }
                }),
            )
        } else {
            json_response(
                status,
                json!({
                    "code":code,
                    "message":message
                }),
            )
        }
    }
}

struct Stream {
    plan: Arc<Plan>,
    call: protocol::Call,
    lease: catalog::Lease,
    events: Events,
    transport: Arc<dyn Transport>,
    seen: bool,
    finished: bool,
}

/// 业务作用：只发布显式配置的网关认证说明，不把上游认证凭据或授权服务暴露给调用者。
///
/// 参数说明：
/// - `cfg`：是路由 card 的认证描述。
///
/// 返回：每个授权需求均引用有效 API-Key/HTTP/OIDC 描述时成功；未知形式拒绝。
fn validate_card_security(cfg: &A2aCfg) -> Result<()> {
    ensure!(
        (1..=8).contains(&cfg.card_security_schemes.len())
            && (1..=8).contains(&cfg.card_security.len()),
        "A2A card must declare gateway authentication"
    );
    for (name, scheme) in &cfg.card_security_schemes {
        ensure!(
            super::tools::valid_name(name),
            "invalid A2A security scheme name"
        );
        match scheme.get("type").and_then(Value::as_str) {
            Some("apiKey") => {
                protocol::keys(scheme, &["type", "in", "name"])?;
                ensure!(
                    scheme.get("in").and_then(Value::as_str) == Some("header")
                        && scheme
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(
                                |name| http::HeaderName::from_bytes(name.as_bytes()).is_ok()
                            ),
                    "invalid A2A API-Key declaration"
                );
            }
            Some("http") => {
                protocol::keys(scheme, &["type", "scheme", "bearerFormat"])?;
                ensure!(
                    scheme
                        .get("scheme")
                        .and_then(Value::as_str)
                        .is_some_and(|scheme| matches!(scheme, "bearer" | "basic")),
                    "invalid A2A HTTP authentication"
                );
            }
            Some("openIdConnect") => {
                protocol::keys(scheme, &["type", "openIdConnectUrl"])?;
                let url: http::Uri = scheme
                    .get("openIdConnectUrl")
                    .and_then(Value::as_str)
                    .context("A2A OIDC URL required")?
                    .parse()?;
                ensure!(
                    url.scheme_str() == Some("https")
                        && url
                            .authority()
                            .is_some_and(|authority| !authority.as_str().contains('@')),
                    "invalid A2A OIDC URL"
                );
            }
            _ => anyhow::bail!("A2A card security scheme not enabled"),
        }
    }
    ensure!(
        cfg.card_security
            .iter()
            .all(|requirement| !requirement.is_empty()
                && requirement.iter().all(|(name, scopes)| cfg
                    .card_security_schemes
                    .contains_key(name)
                    && scopes.len() <= 32
                    && scopes
                        .iter()
                        .all(|scope| !scope.is_empty() && scope.len() <= 128))),
        "invalid A2A card security requirements"
    );
    Ok(())
}
