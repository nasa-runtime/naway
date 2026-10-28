mod semantic;

use super::config::{LimitsCfg, McpCfg, SecurityCfg};
use super::identity::{validate_security, Identity};
use super::tools::{rest_request, Backend, Tool};
use super::transport::{
    collect, hold, is_sse, json_response, validate_limits, wait, Events, Target, Transport,
};
use crate::{full_body, BoxBody};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Response};
use nabudget::RequestBudget;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::Instant;

pub(super) const VERSION: &str = "2025-11-25";

pub(super) struct Plan {
    pub security: SecurityCfg,
    pub limits: LimitsCfg,
    tools: BTreeMap<String, Arc<Tool>>,
    servers: BTreeMap<String, Arc<Target>>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    inflight: Arc<Semaphore>,
    control: Arc<Semaphore>,
}

struct Counters {
    calls: u64,
    bytes: u64,
    tools: HashMap<String, u64>,
    active: HashMap<String, ActiveEntry>,
}

#[derive(Clone)]
struct ActiveEntry {
    budget: RequestBudget,
    remote: Option<(Arc<Target>, Option<HeaderValue>)>,
}

struct Session {
    _workspace_lease: Option<crate::control::ownership::state::Lease>,
    owner: [u8; 32],
    ready: AtomicBool,
    expires: Instant,
    budget: RequestBudget,
    remote: Mutex<BTreeMap<String, Option<HeaderValue>>>,
    counters: Mutex<Counters>,
    sender: mpsc::Sender<Bytes>,
    receiver: Mutex<Option<mpsc::Receiver<Bytes>>>,
}

impl Drop for Session {
    /// 业务作用：会话从有界目录退场时取消其全部子调用，不把索引删除误当成远端副作用撤销。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：发出取消信号；已经执行的工具副作用保持不确定结果语义。
    fn drop(&mut self) {
        self.budget.cancel();
    }
}

struct ActiveCall {
    session: Arc<Session>,
    key: String,
    budget: RequestBudget,
}

struct PendingInitialization {
    plan: Arc<Plan>,
    id: String,
    session: Arc<Session>,
    transport: Arc<dyn Transport>,
    committed: bool,
}

impl Drop for PendingInitialization {
    /// 业务作用：客户端断开或总预算到期时撤销未发布的本地会话，并尽力释放远端会话。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未完成占位立即不可访问；远端关闭具有独立短时限，不恢复本地权限。
    fn drop(&mut self) {
        if !self.committed {
            self.plan.sessions.lock().remove(&self.id);
            self.session.budget.cancel();
            let plan = self.plan.clone();
            let session = self.session.clone();
            let transport = self.transport.clone();
            tokio::spawn(async move {
                plan.delete_remote(&session, transport.as_ref()).await;
            });
        }
    }
}

impl Drop for ActiveCall {
    /// 业务作用：调用完成或客户端取消后立即释放请求 ID，并终止其本地预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：移除 active 索引；不返还已经预留的副作用调用与字节预算。
    fn drop(&mut self) {
        self.budget.cancel();
        self.session.counters.lock().active.remove(&self.key);
    }
}

impl Plan {
    /// 业务作用：输出 MCP 当前能力与配额的低敏管理投影，不枚举会话和用户。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定协议、目录规模、会话上限和活动索引数量。
    pub(super) fn summary(&self) -> Value {
        json!({
            "protocol":"mcp",
            "protocol_version":VERSION,
            "tools":self.tools.len(),
            "servers":self.servers.len(),
            "sessions":self.sessions.lock().values().filter(|session| !session.budget.is_exhausted()).count(),
            "max_sessions":self.limits.max_sessions,
            "max_inflight":self.limits.max_inflight,
            "max_calls_per_session":self.limits.max_calls_per_session,
            "max_bytes_per_session":self.limits.max_bytes_per_session
        })
    }
    /// 业务作用：构建显式协议版本、固定工具聚合目录与有界会话 owner。
    ///
    /// 参数说明：
    /// - `cfg`：是路由 MCP 配置
    /// - `dir`：用于解析本地 schema 与 SecretSource。
    ///
    /// 返回：完整候选有效时返回计划；任何引用、版本或容量不一致拒绝候选，不创建远端会话。
    pub(super) fn build(cfg: &McpCfg, dir: &Path) -> Result<Arc<Self>> {
        ensure!(
            cfg.protocol_version == VERSION,
            "unsupported MCP protocol version"
        );
        validate_security(&cfg.security)?;
        validate_limits(&cfg.limits)?;
        ensure!(
            cfg.servers.len() <= 16 && cfg.tools.len() <= 256,
            "MCP directory exceeds limit"
        );
        ensure!(
            cfg.openapi.len() <= 16,
            "MCP OpenAPI catalog limit exceeded"
        );
        let mut definitions = cfg.tools.clone();
        for catalog in &cfg.openapi {
            definitions.extend(super::openapi::compile(catalog, dir)?);
            ensure!(definitions.len() <= 256, "MCP tool capacity exceeded");
        }
        let mut servers = BTreeMap::new();
        for server in &cfg.servers {
            ensure!(
                super::tools::valid_name(&server.id) && !servers.contains_key(&server.id),
                "duplicate or invalid MCP server id"
            );
            servers.insert(server.id.clone(), Target::build(&server.target, dir)?);
        }
        let mut tools = BTreeMap::new();
        let mut catalog_bytes = 0usize;
        for definition in &definitions {
            ensure!(
                definition.max_request_bytes <= cfg.limits.max_request_bytes
                    && definition.max_response_bytes <= cfg.limits.max_response_bytes,
                "MCP tool byte budget exceeds route budget"
            );
            let tool = Tool::build(definition, dir)?;
            if let Backend::Mcp {
                server,
                ..
            } = &tool.backend
            {
                ensure!(
                    servers.contains_key(server),
                    "MCP tool refers to an unknown server"
                );
            }
            catalog_bytes = catalog_bytes.saturating_add(tool.info().to_string().len());
            ensure!(!tools.contains_key(&tool.name), "duplicate MCP tool name");
            tools.insert(tool.name.clone(), Arc::new(tool));
        }
        ensure!(
            !tools.is_empty()
                && catalog_bytes.saturating_add(1024) <= cfg.limits.max_response_bytes,
            "MCP catalog is empty or exceeds response budget"
        );
        Ok(Arc::new(Self {
            security: cfg.security.clone(),
            limits: cfg.limits.clone(),
            tools,
            servers,
            sessions: Mutex::new(HashMap::new()),
            inflight: Arc::new(Semaphore::new(cfg.limits.max_inflight)),
            control: Arc::new(Semaphore::new(cfg.limits.max_inflight.min(16))),
        }))
    }

    /// 业务作用：执行 MCP HTTP 会话状态机，每个请求使用本次已验证身份重新授权。
    ///
    /// 参数说明：
    /// - `method`：是请求 head
    /// - `headers`：是请求 head
    /// - `body`：已受输入字节门约束
    /// - `identity`：已认证
    /// - `transport`：是同代网关外呼。
    ///
    /// 返回：协议响应或固定原因拒绝；未知方法不会进入普通代理路径。
    pub(super) async fn handle(
        self: &Arc<Self>,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
        identity: Identity,
        transport: Arc<dyn Transport>,
    ) -> Response<BoxBody> {
        let parsed = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        // 取消与关闭保留独立有界容量，业务槽全占用时仍能撤销正在执行的动作。
        let slots = if method == Method::DELETE
            || parsed.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        {
            &self.control
        } else {
            &self.inflight
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            return failure(429, Value::Null, -32000, "Agent capacity exhausted");
        };
        let action = if method == Method::GET {
            "notifications"
        } else if method == Method::DELETE {
            "terminate"
        } else {
            match parsed.get("method").and_then(Value::as_str) {
                Some("initialize") => "initialize",
                Some("notifications/initialized") => "initialized",
                Some("ping") => "ping",
                Some("tools/list") => "tools/list",
                Some("tools/call") => "tools/call",
                Some("notifications/cancelled") => "cancel",
                _ => "unsupported",
            }
        };
        let target = parsed
            .pointer("/params/name")
            .and_then(Value::as_str)
            .filter(|name| self.tools.contains_key(*name))
            .unwrap_or("");
        let operation = transport.observe("mcp", action, target);
        let response = self
            .handle_inner(method, headers, body, identity, transport.clone())
            .await;
        crate::observability::ai::response(
            hold(
                crate::ai::delivery::guard(response, move || transport.live()),
                permit,
            ),
            operation,
        )
    }

    /// 业务作用：在已持有并发配额时执行一次 MCP 请求，不把协议错误回落为普通 HTTP 代理。
    ///
    /// 参数说明：
    /// - `method`：是有界请求
    /// - `headers`：是有界请求
    /// - `body`：是有界请求
    /// - `identity`：是认证事实
    /// - `transport`：绑定当前配置。
    ///
    /// 返回：会话状态机允许的协议响应或固定错误。
    async fn handle_inner(
        self: &Arc<Self>,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
        identity: Identity,
        transport: Arc<dyn Transport>,
    ) -> Response<BoxBody> {
        if !transport.live() {
            return failure(503, Value::Null, -32000, "Agent configuration retired");
        }
        if method != Method::POST && method != Method::GET && method != Method::DELETE {
            return failure(405, Value::Null, -32600, "Unsupported MCP HTTP method");
        }
        if method == Method::POST
            && (!accepts(&headers, "application/json") || !accepts(&headers, "text/event-stream"))
        {
            return failure(
                406,
                Value::Null,
                -32600,
                "MCP requires JSON and SSE Accept types",
            );
        }
        let message: Value = if method == Method::POST {
            match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => return failure(400, Value::Null, -32700, "Invalid JSON"),
            }
        } else {
            Value::Null
        };
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        if method == Method::POST
            && (!valid_message(&message) || message.get("id").is_some_and(|id| !valid_id(id)))
        {
            return failure(400, Value::Null, -32600, "Invalid MCP request");
        }
        let name = message.get("method").and_then(Value::as_str).unwrap_or("");
        if name == "initialize" {
            if headers.contains_key("mcp-session-id") || id.is_null() {
                return failure(400, id, -32600, "Invalid MCP initialization");
            }
            return match self
                .initialize(&message, &identity, transport.clone())
                .await
            {
                Ok(session) => {
                    let mut response = json_response(
                        200,
                        json!({
                            "jsonrpc":"2.0",
                            "id":id,
                            "result":{
                                "protocolVersion":VERSION,
                                "capabilities":{
                                    "tools":{
                                        "listChanged":true
                                    }
                                },
                                "serverInfo":{
                                    "name":"naway",
                                    "version":env!("CARGO_PKG_VERSION")
                                }
                            }
                        }),
                    );
                    response.headers_mut().insert(
                        "mcp-session-id",
                        HeaderValue::from_str(&session).expect("random hex session id"),
                    );
                    response
                }
                Err(_) => failure(
                    400,
                    id,
                    -32602,
                    "MCP initialization or capability negotiation failed",
                ),
            };
        }
        if single_header(&headers, "mcp-protocol-version") != Some(VERSION) {
            return failure(400, id, -32602, "Unsupported MCP protocol version");
        }
        let Some(session_id) = single_header(&headers, "mcp-session-id") else {
            return failure(400, id, -32600, "MCP session required");
        };
        let session = {
            let mut sessions = self.sessions.lock();
            sessions.retain(|_, session| {
                session.expires > Instant::now() && !session.budget.is_cancelled()
            });
            sessions
                .get(session_id)
                .filter(|session| session.owner == identity.key)
                .cloned()
        };
        // 跨身份访问与过期会话使用同一 404，不能根据 session id 枚举其它主体的会话。
        let Some(session) = session else {
            return failure(404, id, -32000, "MCP session not found");
        };
        if method == Method::DELETE {
            session.budget.cancel();
            self.sessions.lock().remove(session_id);
            self.delete_remote(&session, transport.as_ref()).await;
            return empty(204);
        }
        if name == "notifications/initialized" && id.is_null() {
            session.ready.store(true, Ordering::Release);
            let _ = session.sender.try_send(Bytes::from_static(
                b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
            ));
            return empty(202);
        }
        if !session.ready.load(Ordering::Acquire) && name != "ping" {
            return failure(400, id, -32600, "MCP session is not initialized");
        }
        if method == Method::GET {
            if !accepts(&headers, "text/event-stream") || headers.contains_key("last-event-id") {
                return failure(400, id, -32600, "MCP event resumption is not supported");
            }
            return notifications(session, transport, &self.servers, &self.limits);
        }
        match name {
            "ping" if !id.is_null() => json_response(
                200,
                json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "result":{}
                }),
            ),
            "tools/list" if !id.is_null() => {
                if message.get("params").is_some_and(|params| {
                    !params.is_object()
                        || params.as_object().unwrap().keys().any(|key| key != "_meta")
                }) {
                    return failure(200, id, -32602, "MCP cursor is unsupported");
                }
                let tools = self
                    .tools
                    .values()
                    .filter(|tool| tool.discovery.allows(&identity))
                    .map(|tool| tool.info())
                    .collect::<Vec<_>>();
                json_response(
                    200,
                    json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "result":{
                            "tools":tools
                        }
                    }),
                )
            }
            "tools/call" if !id.is_null() => {
                self.call(&message, identity, session, transport).await
            }
            "notifications/cancelled" if id.is_null() => {
                let request_id = message.pointer("/params/requestId");
                if let Some(request_id) = request_id.filter(|id| valid_id(id)) {
                    let active = session
                        .counters
                        .lock()
                        .active
                        .get(&request_id.to_string())
                        .cloned();
                    if let Some(active) = active {
                        // 先停止本地结果交付，再尽力通知远端；远端取消不能被解释为已经撤销副作用。
                        active.budget.cancel();
                        if let Some((target, remote)) = active.remote {
                            let mut request = target.request(
                                Method::POST,
                                Bytes::from(
                                    json!({
                                        "jsonrpc":"2.0",
                                        "method":"notifications/cancelled",
                                        "params":{
                                            "requestId":request_id
                                        }
                                    })
                                    .to_string(),
                                ),
                            );
                            protocol_headers(&mut request.headers, remote.as_ref());
                            let budget = RequestBudget::from_now(Duration::from_millis(1000));
                            let _ =
                                wait(&budget, transport.as_ref(), transport.send(request)).await;
                        }
                    }
                    empty(202)
                } else {
                    failure(400, Value::Null, -32602, "Invalid MCP cancellation")
                }
            }
            _ => failure(200, id, -32601, "MCP method is not enabled"),
        }
    }

    /// 业务作用：先预留有界本地会话，再与全部固定 server 完成版本和能力协商，最后对客户端发布 session id。
    ///
    /// 参数说明：
    /// - `message`：是 initialize
    /// - `identity`：是会话 owner
    /// - `transport`：提供固定目标外呼。
    ///
    /// 返回：全部 server 初始化成功时返回随机会话标识；失败会移除本地占位并关闭已创建远端会话。
    async fn initialize(
        self: &Arc<Self>,
        message: &Value,
        identity: &Identity,
        transport: Arc<dyn Transport>,
    ) -> Result<String> {
        let params = message
            .get("params")
            .and_then(Value::as_object)
            .context("MCP initialize params required")?;
        ensure!(
            params.get("protocolVersion").and_then(Value::as_str) == Some(VERSION),
            "unsupported MCP version"
        );
        ensure!(
            params
                .get("capabilities")
                .and_then(Value::as_object)
                .is_some_and(|capabilities| capabilities.is_empty()),
            "unsupported MCP client capabilities"
        );
        ensure!(
            params
                .get("clientInfo")
                .and_then(Value::as_object)
                .is_some(),
            "MCP clientInfo required"
        );
        let id = nasa::crypto::generate_salt(24);
        let (sender, receiver) = mpsc::channel(32);
        let budget = RequestBudget::from_now(Duration::from_millis(self.limits.session_ttl_ms));
        self.sessions.lock().retain(|_, session| {
            session.expires > Instant::now() && !session.budget.is_cancelled()
        });
        // 工作区名额先于任何远端初始化，容量不足不能创建一个本地无法追踪的远端会话。
        let workspace_lease = transport
            .state_budget()
            .map(|budget| {
                budget
                    .acquire()
                    .map_err(|_| anyhow::anyhow!("workspace session capacity exhausted"))
            })
            .transpose()?;
        let session = Arc::new(Session {
            _workspace_lease: workspace_lease,
            owner: identity.key,
            ready: AtomicBool::new(false),
            expires: budget.deadline(),
            budget,
            remote: Mutex::new(BTreeMap::new()),
            counters: Mutex::new(Counters {
                calls: 0,
                bytes: 0,
                tools: HashMap::new(),
                active: HashMap::new(),
            }),
            sender,
            receiver: Mutex::new(Some(receiver)),
        });
        {
            let mut sessions = self.sessions.lock();
            // 占位与 per-identity 检查在同一把锁内完成，避免并发 initialize 越过公平配额。
            ensure!(
                sessions.len() < self.limits.max_sessions
                    && sessions
                        .values()
                        .filter(|session| session.owner == identity.key)
                        .count()
                        < self.limits.max_sessions_per_identity,
                "MCP session capacity exhausted"
            );
            ensure!(
                !sessions.contains_key(&id),
                "MCP session identifier collision"
            );
            sessions.insert(id.clone(), session.clone());
        }
        let mut pending = PendingInitialization {
            plan: self.clone(),
            id: id.clone(),
            session: session.clone(),
            transport: transport.clone(),
            committed: false,
        };
        let budget = session.budget.child(
            Duration::from_millis(self.limits.deadline_ms).min(
                transport
                    .deadline()
                    .saturating_duration_since(Instant::now()),
            ),
        );
        let result: Result<()> = async {
            for (name, target) in &self.servers {
                let request = json!({
                    "jsonrpc":"2.0",
                    "id":0,
                    "method":"initialize",
                    "params":{
                        "protocolVersion":VERSION,
                        "capabilities":{},
                        "clientInfo":{
                            "name":"naway",
                            "version":env!("CARGO_PKG_VERSION")
                        }
                    }
                });
                let response = wait(
                    &budget,
                    transport.as_ref(),
                    transport.send(target.request(Method::POST, Bytes::from(request.to_string()))),
                )
                .await??;
                ensure!(
                    response.status().is_success(),
                    "MCP server initialization failed"
                );
                let remote_id = response.headers().get("mcp-session-id").cloned();
                ensure!(
                    remote_id
                        .as_ref()
                        .is_none_or(|value| value.as_bytes().len() <= 256
                            && value.as_bytes().iter().all(|b| (0x21..=0x7e).contains(b))),
                    "invalid upstream MCP session"
                );
                ensure!(
                    response.headers().get_all("mcp-session-id").iter().count() <= 1,
                    "ambiguous upstream MCP session"
                );
                // 远端已分配资源时先记录关闭句柄，即使随后响应校验失败也能执行补偿。
                session
                    .remote
                    .lock()
                    .insert(name.clone(), remote_id.clone());
                let result = rpc_value(
                    response,
                    &json!(0),
                    self.limits.max_response_bytes,
                    &budget,
                    transport.as_ref(),
                    &session,
                )
                .await?;
                ensure!(
                    result.get("protocolVersion").and_then(Value::as_str) == Some(VERSION),
                    "MCP server version mismatch"
                );
                let capabilities = result
                    .get("capabilities")
                    .and_then(Value::as_object)
                    .context("MCP server capabilities required")?;
                ensure!(
                    capabilities.keys().all(|key| key == "tools")
                        && capabilities
                            .get("tools")
                            .and_then(Value::as_object)
                            .is_some_and(|tools| tools
                                .iter()
                                .all(|(key, value)| key == "listChanged" && value.is_boolean())),
                    "unsupported MCP server capabilities"
                );
                session
                    .remote
                    .lock()
                    .insert(name.clone(), remote_id.clone());
                let mut notification = target.request(
                    Method::POST,
                    Bytes::from_static(
                        b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
                    ),
                );
                protocol_headers(&mut notification.headers, remote_id.as_ref());
                let response =
                    wait(&budget, transport.as_ref(), transport.send(notification)).await??;
                ensure!(
                    response.status().as_u16() == 202,
                    "MCP server rejected initialized notification"
                );
            }
            ensure!(transport.live(), "MCP configuration retired");
            Ok(())
        }
        .await;
        if let Err(error) = result {
            // 协商没有完整成功时不能发布半完成会话；先撤本地访问面，再补偿关闭远端资源。
            self.sessions.lock().remove(&id);
            session.budget.cancel();
            self.delete_remote(&session, transport.as_ref()).await;
            pending.committed = true;
            return Err(error);
        }
        pending.committed = true;
        Ok(id)
    }

    /// 业务作用：在调用 ACL、schema 与会话配额均通过后执行一个固定工具，不自动重试副作用。
    ///
    /// 参数说明：
    /// - `message`：是 tools/call
    /// - `identity`：是当前认证身份
    /// - `session`：提供隔离预算
    /// - `transport`：是同代外呼。
    ///
    /// 返回：校验过的 CallToolResult 或固定协议错误，参数和响应不进入审计日志。
    async fn call(
        &self,
        message: &Value,
        identity: Identity,
        session: Arc<Session>,
        transport: Arc<dyn Transport>,
    ) -> Response<BoxBody> {
        let id = message["id"].clone();
        let Some(params) = message.get("params").and_then(Value::as_object) else {
            return failure(200, id, -32602, "MCP tool parameters required");
        };
        if params
            .keys()
            .any(|key| !matches!(key.as_str(), "name" | "arguments" | "_meta"))
        {
            return failure(200, id, -32602, "Unsupported MCP tool parameters");
        }
        let Some(tool) = params
            .get("name")
            .and_then(Value::as_str)
            .and_then(|name| self.tools.get(name))
        else {
            return failure(200, id, -32602, "MCP tool unavailable");
        };
        // Discovery 与 invocation 独立授权；获准看见某个名称不代表可以产生该工具的副作用。
        if !tool.invocation.allows(&identity) {
            return failure(403, id, -32000, "MCP tool invocation denied");
        }
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if tool.validate(&arguments).is_err() {
            return failure(
                200,
                id,
                -32602,
                "MCP arguments failed schema or byte budget",
            );
        }
        let budget = session.budget.child(
            Duration::from_millis(tool.deadline_ms.min(self.limits.deadline_ms)).min(
                transport
                    .deadline()
                    .saturating_duration_since(Instant::now()),
            ),
        );
        let key = id.to_string();
        let reserved = arguments.to_string().len() as u64 + tool.max_response_bytes as u64;
        {
            let mut counters = session.counters.lock();
            if counters.calls >= self.limits.max_calls_per_session
                || counters.bytes.saturating_add(reserved) > self.limits.max_bytes_per_session
                || counters.tools.get(&tool.name).copied().unwrap_or(0) >= tool.max_calls
                || counters.active.contains_key(&key)
            {
                return failure(
                    429,
                    id,
                    -32000,
                    "MCP session budget exhausted or request id active",
                );
            }
            // 在外呼前原子消耗调用与最坏响应预算；远端失败或取消不意味着副作用未发生，因此不退款重试。
            counters.calls += 1;
            counters.bytes += reserved;
            *counters.tools.entry(tool.name.clone()).or_default() += 1;
            let remote = match &tool.backend {
                Backend::Mcp {
                    server,
                    ..
                } => session
                    .remote
                    .lock()
                    .get(server)
                    .cloned()
                    .map(|remote| (self.servers[server].clone(), remote)),
                Backend::Rest {
                    ..
                } => None,
            };
            counters.active.insert(
                key.clone(),
                ActiveEntry {
                    budget: budget.clone(),
                    remote,
                },
            );
        }
        let active = ActiveCall {
            session: session.clone(),
            key,
            budget: budget.clone(),
        };
        if let Backend::Mcp {
            server,
            tool: name,
        } = &tool.backend
        {
            let target = &self.servers[server];
            let remote = session.remote.lock().get(server).cloned();
            let Some(remote) = remote else {
                return failure(200, id, -32603, "MCP server session unavailable");
            };
            let mut params = json!({
                "name":name,
                "arguments":arguments
            });
            let progress = message
                .pointer("/params/_meta/progressToken")
                .filter(|token| valid_id(token))
                .cloned();
            if let Some(progress) = &progress {
                params["_meta"] = json!({
                    "progressToken":progress
                });
            }
            let mut request = target.request(
                Method::POST,
                Bytes::from(
                    json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "method":"tools/call",
                        "params":params
                    })
                    .to_string(),
                ),
            );
            protocol_headers(&mut request.headers, remote.as_ref());
            let response = wait(&budget, transport.as_ref(), transport.send(request)).await;
            let Ok(Ok(response)) = response else {
                return failure(200, id, -32603, "MCP upstream call failed or was cancelled");
            };
            if !response.status().is_success() {
                return failure(200, id, -32603, "MCP upstream call failed");
            }
            if is_sse(&response) {
                return match Events::new(
                    response,
                    tool.max_response_bytes,
                    self.limits.max_frame_bytes,
                ) {
                    Ok(events) => {
                        call_stream(events, id, progress, tool.clone(), active, transport)
                    }
                    Err(_) => failure(200, id, -32603, "Invalid MCP event stream"),
                };
            }
            let result = rpc_value(
                response,
                &id,
                tool.max_response_bytes,
                &budget,
                transport.as_ref(),
                &session,
            )
            .await
            .and_then(|value| {
                validate_result(tool, &value)?;
                Ok(value)
            });
            tracing::info!(tool = %tool.name, side_effect = ?tool.side_effect, outcome = if result.is_ok() {
                "completed"
            } else {
                "failed"
            }, "Agent tool invocation");
            return match result {
                Ok(result) => json_response(
                    200,
                    json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "result":result
                    }),
                ),
                Err(_) => failure(
                    200,
                    id,
                    -32603,
                    "MCP tool execution failed or was cancelled",
                ),
            };
        }
        let _active = active;
        let result: Result<Value> = async {
            let result = match &tool.backend {
                Backend::Rest {
                    target,
                    method,
                } => {
                    let request = rest_request(target, method, &arguments)?;
                    let response =
                        wait(&budget, transport.as_ref(), transport.send(request)).await??;
                    ensure!(
                        response.status().is_success(),
                        "REST tool returned an error"
                    );
                    let body = collect(
                        response,
                        tool.max_response_bytes,
                        &budget,
                        transport.as_ref(),
                    )
                    .await?;
                    let value: Value =
                        serde_json::from_slice(&body).context("REST tool response must be JSON")?;
                    let structured = if value.is_object() {
                        value.clone()
                    } else {
                        json!({
                            "result":value
                        })
                    };
                    json!({
                        "content":[{
                            "type":"text",
                            "text":value.to_string()
                        }],
                        "structuredContent":structured,
                        "isError":false
                    })
                }
                Backend::Mcp {
                    ..
                } => unreachable!("MCP backend handled before REST execution"),
            };
            validate_result(tool, &result)?;
            ensure!(
                transport.live() && result.to_string().len() <= self.limits.max_response_bytes,
                "MCP result cannot be delivered"
            );
            Ok(result)
        }
        .await;
        tracing::info!(tool = %tool.name, side_effect = ?tool.side_effect, outcome = if result.is_ok() {
            "completed"
        } else {
            "failed"
        }, "Agent tool invocation");
        match result {
            Ok(result) => json_response(
                200,
                json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "result":result
                }),
            ),
            Err(_) => failure(
                200,
                id,
                -32603,
                "MCP tool execution failed or was cancelled",
            ),
        }
    }

    /// 业务作用：显式终止或协商失败后，尽力关闭只属于当前会话的远端资源。
    ///
    /// 参数说明：
    /// - `session`：是已经关闭本地访问的会话
    /// - `transport`：仍只允许固定目标。
    ///
    /// 返回：各 server 在独立短预算内收到 DELETE；失败不恢复本地会话，也不泄露上游正文。
    async fn delete_remote(&self, session: &Session, transport: &dyn Transport) {
        let remote = session.remote.lock().clone();
        let budget = RequestBudget::from_now(Duration::from_millis(1000));
        for (name, remote_id) in remote {
            let mut request = self.servers[&name].request(Method::DELETE, Bytes::new());
            protocol_headers(&mut request.headers, remote_id.as_ref());
            let _ = budget.run(transport.send(request)).await;
        }
    }
}

/// 业务作用：在交付工具结果前验证标准内容形态和配置声明的输出契约。
///
/// 参数说明：
/// - `tool`：是同代定义
/// - `value`：是尚未发送的 CallToolResult。
///
/// 返回：内容、结构化输出和字节预算均有效时成功；否则不交付结果。
fn validate_result(tool: &Tool, value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("MCP tool result must be an object")?;
    ensure!(
        object.keys().all(|key| matches!(
            key.as_str(),
            "content" | "structuredContent" | "isError" | "_meta"
        )),
        "unknown MCP tool result field"
    );
    ensure!(
        value.get("isError").is_none_or(Value::is_boolean),
        "invalid MCP tool outcome"
    );
    let content = value
        .get("content")
        .and_then(Value::as_array)
        .context("invalid MCP tool content")?;
    ensure!(content.len() <= 128, "MCP tool content capacity exceeded");
    for item in content {
        match item.get("type").and_then(Value::as_str) {
            Some("text") => ensure!(
                item.get("text").is_some_and(Value::is_string),
                "invalid MCP text content"
            ),
            Some("image" | "audio") => ensure!(
                item.get("data").is_some_and(Value::is_string)
                    && item.get("mimeType").is_some_and(Value::is_string),
                "invalid MCP media content"
            ),
            Some("resource_link") => ensure!(
                item.get("uri").is_some_and(Value::is_string)
                    && item.get("name").is_some_and(Value::is_string),
                "invalid MCP resource link"
            ),
            Some("resource") => ensure!(
                item.get("resource").is_some_and(|resource| resource
                    .get("uri")
                    .is_some_and(Value::is_string)
                    && (resource.get("text").is_some_and(Value::is_string)
                        || resource.get("blob").is_some_and(Value::is_string))),
                "invalid MCP resource content"
            ),
            _ => anyhow::bail!("MCP content capability not enabled"),
        }
    }
    ensure!(
        value.get("structuredContent").is_none_or(Value::is_object),
        "MCP structured content must be an object"
    );
    if let Some(schema) = &tool.output {
        ensure!(
            value
                .get("structuredContent")
                .is_some_and(|value| schema.is_valid(value)),
            "MCP tool output failed schema"
        );
    }
    ensure!(
        value.to_string().len() <= tool.max_response_bytes,
        "MCP tool result exceeds byte limit"
    );
    Ok(())
}

struct CallStream {
    events: Events,
    id: Value,
    progress: Option<Value>,
    tool: Arc<Tool>,
    active: ActiveCall,
    transport: Arc<dyn Transport>,
    finished: bool,
    completed: bool,
}

impl Drop for CallStream {
    /// 业务作用：流完成、协议失败或下游断开时记录低敏审计，参数与结果不写入日志。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅记录固定工具身份、副作用等级和最终交付状态；ActiveCall 随后释放取消权威。
    fn drop(&mut self) {
        tracing::info!(tool = %self.tool.name, side_effect = ?self.tool.side_effect, outcome = if self.completed {
            "completed"
        } else {
            "interrupted"
        }, "Agent tool invocation");
    }
}

/// 业务作用：按事件裁决 MCP 上游流，保持背压并将调用取消与响应实体生命周期绑定。
///
/// 参数说明：
/// - `events`：是有界上游
/// - `id`：绑定调用
/// - `progress`：绑定调用
/// - `tool`：校验输出
/// - `active`：提供持续权限。
/// - `transport`：提供持续权限。
///
/// 返回：仅包含批准通知和匹配结果的 SSE；未知能力、缺失结果或撤权会关闭实体。
fn call_stream(
    events: Events,
    id: Value,
    progress: Option<Value>,
    tool: Arc<Tool>,
    active: ActiveCall,
    transport: Arc<dyn Transport>,
) -> Response<BoxBody> {
    let state = CallStream {
        events,
        id,
        progress,
        tool,
        active,
        transport,
        finished: false,
        completed: false,
    };
    let stream = futures::stream::unfold(state, |mut state| async move {
        if state.finished {
            return None;
        }
        let result: Result<Value> = async {
            let value = state
                .events
                .next(&state.active.budget, state.transport.as_ref())
                .await?
                .context("MCP stream ended without a result")?;
            ensure!(
                value.get("jsonrpc").and_then(Value::as_str) == Some("2.0"),
                "invalid MCP stream version"
            );
            if value.get("method").is_some() {
                sanitize_notification(&value, state.progress.as_ref())
            } else {
                ensure!(
                    value.get("id") == Some(&state.id) && value.get("error").is_none(),
                    "unexpected MCP stream response"
                );
                let result = value.get("result").context("MCP stream result missing")?;
                validate_result(&state.tool, result)?;
                state.finished = true;
                state.completed = true;
                Ok(json!({
                    "jsonrpc":"2.0",
                    "id":state.id,
                    "result":result
                }))
            }
        }
        .await;
        let frame = match result {
            Ok(value) => Ok(hyper::body::Frame::data(Bytes::from(format!(
                "data: {value}\n\n"
            )))),
            Err(_) => {
                state.finished = true;
                Err::<_, crate::BoxError>(
                    anyhow::anyhow!("MCP event rejected or call cancelled").into(),
                )
            }
        };
        Some((frame, state))
    });
    Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(http_body_util::BodyExt::boxed(
            http_body_util::StreamBody::new(stream),
        ))
        .expect("fixed MCP stream response")
}

/// 业务作用：限制 server 通知为已协商能力，并删除进度消息中的任意文本与隐藏元数据。
///
/// 参数说明：
/// - `value`：是通知
/// - `progress`：是本调用实际请求的进度 token，None 禁止 progress。
///
/// 返回：规范化的低敏通知；请求注入、未知方法或 token 不匹配拒绝。
fn sanitize_notification(value: &Value, progress: Option<&Value>) -> Result<Value> {
    ensure!(
        value.get("jsonrpc").and_then(Value::as_str) == Some("2.0") && value.get("id").is_none(),
        "invalid MCP notification"
    );
    match value.get("method").and_then(Value::as_str) {
        Some("notifications/tools/list_changed") => Ok(json!({
            "jsonrpc":"2.0",
            "method":"notifications/tools/list_changed"
        })),
        Some("notifications/progress") => {
            let token = value
                .pointer("/params/progressToken")
                .context("MCP progress token missing")?;
            ensure!(progress == Some(token), "MCP progress token mismatch");
            let current = value
                .pointer("/params/progress")
                .and_then(Value::as_f64)
                .context("MCP progress missing")?;
            ensure!(
                current.is_finite() && current >= 0.0,
                "invalid MCP progress"
            );
            let mut params = json!({
                "progressToken":token,
                "progress":current
            });
            if let Some(total) = value.pointer("/params/total") {
                ensure!(
                    total
                        .as_f64()
                        .is_some_and(|total| total.is_finite() && total >= current),
                    "invalid MCP progress total"
                );
                params["total"] = total.clone();
            }
            Ok(json!({
                "jsonrpc":"2.0",
                "method":"notifications/progress",
                "params":params
            }))
        }
        _ => anyhow::bail!("MCP notification capability not enabled"),
    }
}

/// 业务作用：读取 JSON 或 SSE 包装的单一 RPC 结果，只接受当前调用的响应和已声明通知。
///
/// 参数说明：
/// - `response`：上游返回的 RPC 响应。
/// - `id`：必须匹配的请求 RPC 标识。
/// - `limit`：响应读取的字节硬上限。
/// - `budget`：本次调用的时间与资源预算。
/// - `transport`：固定后端与持续权限的传输环境。
/// - `session`：接收有界通知的当前会话。
///
/// 返回：唯一、匹配 ID 的 result；未知 capability/method、歧义响应或远端 error 均拒绝。
async fn rpc_value(
    response: Response<BoxBody>,
    id: &Value,
    limit: usize,
    budget: &RequestBudget,
    transport: &dyn Transport,
    session: &Session,
) -> Result<Value> {
    let values: Vec<Value> = if is_sse(&response) {
        let mut events = Events::new(response, limit, limit.min(64 * 1024))?;
        let mut values = Vec::new();
        while let Some(value) = events.next(budget, transport).await? {
            ensure!(values.len() < 64, "too many MCP events");
            values.push(value);
        }
        values
    } else {
        ensure!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))),
            "unsupported MCP response media type"
        );
        let bytes = collect(response, limit, budget, transport).await?;
        vec![serde_json::from_slice(&bytes)?]
    };
    let mut result = None;
    for value in values {
        ensure!(
            value.get("jsonrpc").and_then(Value::as_str) == Some("2.0"),
            "invalid MCP JSON-RPC version"
        );
        if let Some(method) = value.get("method").and_then(Value::as_str) {
            ensure!(
                value.get("id").is_none()
                    && matches!(
                        method,
                        "notifications/tools/list_changed" | "notifications/progress"
                    ),
                "MCP server method not enabled"
            );
            let notification = sanitize_notification(&value, None)?;
            session
                .sender
                .try_send(Bytes::from(format!("data: {notification}\n\n")))
                .map_err(|_| anyhow::anyhow!("MCP notification queue exhausted"))?;
        } else {
            ensure!(
                value.get("id") == Some(id) && result.is_none() && value.get("error").is_none(),
                "unexpected MCP RPC response"
            );
            result = value.get("result").cloned();
        }
    }
    result.context("MCP result missing")
}

/// 业务作用：统一注入已协商的协议和远端会话，不复用客户端会话索引。
///
/// 参数说明：
/// - `headers`：是全新的外呼头
/// - `session`：是该 server 返回的独立标识。
///
/// 返回：原位设置协议状态头，stateless server 不带会话头。
fn protocol_headers(headers: &mut HeaderMap, session: Option<&HeaderValue>) {
    headers.insert("mcp-protocol-version", HeaderValue::from_static(VERSION));
    if let Some(session) = session {
        headers.insert("mcp-session-id", session.clone());
    }
}

/// 业务作用：检查 MCP 请求 envelope，拒绝批处理和未知顶层协议字段。
///
/// 参数说明：
/// - `value`：是有界 JSON 文档。
///
/// 返回：明确的单请求或通知结构为 true；任何响应注入或数组批处理为 false。
fn valid_message(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        object
            .keys()
            .all(|key| matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
            && object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && object
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(|method| method.len() <= 128)
            && object.get("params").is_none_or(Value::is_object)
    })
}

/// 业务作用：限制活动 RPC 索引键，防止复杂 JSON 或超长文本进入会话状态表。
///
/// 参数说明：
/// - `id`：是 RPC 请求标识。
///
/// 返回：有界字符串或整数为 true；null、浮点和结构值为 false。
fn valid_id(id: &Value) -> bool {
    id.as_str()
        .is_some_and(|value| !value.is_empty() && value.len() <= 128)
        || id.as_i64().is_some()
        || id.as_u64().is_some()
}

/// 业务作用：拒绝重复或非法编码的协议状态头，不按客户端控制的顺序任选一个值。
///
/// 参数说明：
/// - `headers`：是 HTTP 请求头
/// - `name`：是固定协议头名。
///
/// 返回：唯一且有效 UTF-8 的字段值，否则 None。
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    (headers.get_all(name).iter().count() == 1)
        .then(|| headers.get(name)?.to_str().ok())
        .flatten()
}

/// 业务作用：检查客户端显式声明的 MCP 响应媒体类型，不把通配符当成协议协商。
///
/// 参数说明：
/// - `headers`：是请求头
/// - `mime`：是所需媒体类型。
///
/// 返回：至少一个 Accept 项明确包含该类型且未用 q=0 禁用时为 true。
fn accepts(headers: &HeaderMap, mime: &str) -> bool {
    headers
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| {
            let mut fields = value.split(';');
            fields
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case(mime))
                && fields.all(|field| {
                    let Some((key, value)) = field.trim().split_once('=') else {
                        return false;
                    };
                    !key.trim().eq_ignore_ascii_case("q")
                        || value
                            .trim()
                            .parse::<f64>()
                            .is_ok_and(|q| q.is_finite() && q > 0.0 && q <= 1.0)
                })
        })
}

/// 业务作用：以固定低敏原因表达 MCP 拒绝，不反射入参或上游错误正文。
///
/// 参数说明：
/// - `status`：是 HTTP 状态
/// - `id`：是受限 RPC 标识
/// - `code`：是固定错误分类。
/// - `message`：是固定错误分类。
///
/// 返回：不可共享缓存的 JSON-RPC error。
fn failure(status: u16, id: Value, code: i64, message: &'static str) -> Response<BoxBody> {
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
}

/// 业务作用：确认无结果的 MCP 通知或会话删除，不制造 JSON-RPC 响应对象。
///
/// 参数说明：
/// - `status`：是通知接受或删除成功的 HTTP 状态。
///
/// 返回：空实体且禁止共享缓存的响应。
fn empty(status: u16) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::new()))
        .expect("fixed MCP status")
}

/// 业务作用：为会话开放一个有界通知接收端，禁止同一通知被广播到多条连接。
///
/// 参数说明：
/// - `session`：当前已认证会话。
/// - `transport`：持续检查撤权与 drain 的传输权威。
/// - `servers`：允许本会话访问的服务目录。
/// - `limits`：通知队列与流生命周期预算。
///
/// 返回：SSE 通知响应；已有接收连接时拒绝，不复制接收队列。
fn notifications(
    session: Arc<Session>,
    transport: Arc<dyn Transport>,
    servers: &BTreeMap<String, Arc<Target>>,
    limits: &LimitsCfg,
) -> Response<BoxBody> {
    use http_body_util::BodyExt;
    let Some(receiver) = session.receiver.lock().take() else {
        return failure(
            409,
            Value::Null,
            -32000,
            "MCP notification stream already open",
        );
    };
    let mut tasks = Vec::new();
    for (name, target) in servers {
        let remote = session.remote.lock().get(name).cloned().flatten();
        let mut request = target.request(Method::GET, Bytes::new());
        protocol_headers(&mut request.headers, remote.as_ref());
        let session = session.clone();
        let transport = transport.clone();
        let limits = limits.clone();
        tasks.push(tokio::spawn(async move {
            let result: Result<()> = async {
                let opening = session
                    .budget
                    .child(Duration::from_millis(limits.deadline_ms));
                let response =
                    wait(&opening, transport.as_ref(), transport.send(request)).await??;
                // MCP server 可以不实现独立 GET 通知流；405 不影响其 POST 工具调用能力。
                if response.status() == http::StatusCode::METHOD_NOT_ALLOWED {
                    return Ok(());
                }
                ensure!(
                    response.status().is_success(),
                    "MCP notification source unavailable"
                );
                let mut events = Events::new(
                    response,
                    limits.max_bytes_per_session as usize,
                    limits.max_frame_bytes,
                )?;
                while let Some(value) = events.next(&session.budget, transport.as_ref()).await? {
                    let value = sanitize_notification(&value, None)?;
                    let bytes = Bytes::from(format!("data: {value}\n\n"));
                    {
                        let mut counters = session.counters.lock();
                        ensure!(
                            counters.bytes.saturating_add(bytes.len() as u64)
                                <= limits.max_bytes_per_session,
                            "MCP notification budget exhausted"
                        );
                        counters.bytes += bytes.len() as u64;
                    }
                    session
                        .sender
                        .try_send(bytes)
                        .map_err(|_| anyhow::anyhow!("MCP notification queue exhausted"))?;
                }
                Ok(())
            }
            .await;
            if result.is_err() {
                session.budget.cancel();
            }
        }));
    }
    Response::builder()
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(
            NotificationBody {
                session,
                receiver: Some(receiver),
                transport,
                tick: Box::pin(tokio::time::sleep(Duration::from_millis(100))),
                tasks,
            }
            .boxed(),
        )
        .expect("fixed MCP SSE response")
}

struct NotificationBody {
    session: Arc<Session>,
    receiver: Option<mpsc::Receiver<Bytes>>,
    transport: Arc<dyn Transport>,
    tick: std::pin::Pin<Box<tokio::time::Sleep>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for NotificationBody {
    /// 业务作用：断开 GET 连接时归还唯一通知接收端，让会话在未过期时可以重新连接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未消费通知保留在同一有界队列，不迁移到其它身份或会话。
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Some(receiver) = self.receiver.take() {
            *self.session.receiver.lock() = Some(receiver);
        }
    }
}

impl hyper::body::Body for NotificationBody {
    type Data = Bytes;
    type Error = crate::BoxError;
    /// 业务作用：在交付每条通知前复验会话和配置权威，空闲时也在固定小周期检查撤权。
    ///
    /// 参数说明：
    /// - `cx`：是下游背压驱动的任务上下文。
    ///
    /// 返回：一条已批准通知、等待或关闭；过期与撤权后不继续输出旧队列。
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::future::Future;
        use std::task::Poll;
        if !self.transport.live() || self.session.budget.is_exhausted() {
            return Poll::Ready(None);
        }
        if self.tick.as_mut().poll(cx).is_ready() {
            self.tick
                .as_mut()
                .reset(Instant::now() + Duration::from_millis(100));
            let _ = self.tick.as_mut().poll(cx);
        }
        self.receiver
            .as_mut()
            .expect("notification receiver present")
            .poll_recv(cx)
            .map(|message| message.map(|bytes| Ok(hyper::body::Frame::data(bytes))))
    }
}
