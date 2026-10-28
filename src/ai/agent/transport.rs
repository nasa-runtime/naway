#[cfg(feature = "agent-protocols")]
use super::config::LimitsCfg;
use super::config::TargetCfg;
#[cfg(feature = "agent-protocols")]
use crate::full_body;
use crate::BoxBody;
use anyhow::{ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderValue, Method, Response};
use http_body_util::BodyExt;
use nabudget::RequestBudget;
#[cfg(feature = "agent-protocols")]
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// 由同一网关数据面承接的 Agent 外呼，不允许替换成任意 URL 的独立客户端。
pub(crate) trait Transport: Send + Sync {
    /// 业务作用：向会话与任务索引提供请求冻结的工作区状态预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：工作区入口的预算；平台入口为空，不接受协议正文自报归属。
    fn state_budget(&self) -> Option<&crate::control::ownership::state::Budget> {
        None
    }
    /// 业务作用：向已批准的固定目标发出一次网关子调用。
    ///
    /// 参数说明：
    /// - `request`：持有固定目标、协议头和已校验实体。
    ///
    /// 返回：受同代权限约束的响应或低敏外呼失败，不承诺撤销远端副作用。
    fn send(&self, request: Outbound) -> BoxFuture<'_, Result<Response<BoxBody>>>;
    /// 业务作用：检查配置代次与管理关闭状态是否仍允许 Agent 产生或交付业务结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前身份所在快照仍有效且未被 drain 时为 true；否则禁止继续。
    fn live(&self) -> bool;
    /// 业务作用：把输入读取所消耗的时间计入后续工具和任务调用的总时限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：从入站开始计算的绝对请求截止时刻；独立会话通知仍由会话 TTL 限制。
    fn deadline(&self) -> tokio::time::Instant;
    /// 业务作用：为协议动作创建同路由低敏观测，不接收正文或主体 ID。
    ///
    /// 参数说明：
    /// - `protocol`：来自固定协议
    /// - `method`：来自固定协议
    /// - `target`：只使用已编译工具或来源名称。
    ///
    /// 返回：随动作或响应实体释放的观测守卫。
    fn observe(
        &self,
        protocol: &'static str,
        method: &str,
        target: &str,
    ) -> crate::observability::ai::Operation;
}

/// 外呼请求只包含已编译目标、明确方法和经过 schema 校验的参数。
pub(crate) struct Outbound {
    pub target: Arc<Target>,
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(PartialEq, Eq)]
pub(crate) struct Target {
    pub upstream: String,
    pub path: String,
    authorization: Option<HeaderValue>,
}

impl Target {
    /// 业务作用：冻结 Agent 后端 origin、路径与独立凭据，禁止下游参数影响网络目标。
    ///
    /// 参数说明：
    /// - `cfg`：是固定目标
    /// - `dir`：是 SecretSource 文件的配置目录。
    ///
    /// 返回：合法且凭据可解析时返回目标；模板、URL 身份或非法路径拒绝候选。
    pub(crate) fn build(cfg: &TargetCfg, dir: &Path) -> Result<Arc<Self>> {
        ensure!(
            cfg.uri.len() <= 2048 && !cfg.uri.contains('$') && !cfg.uri.contains('#'),
            "invalid Agent target origin"
        );
        let uri: http::Uri = cfg.uri.parse().context("invalid Agent target URI")?;
        ensure!(
            matches!(uri.scheme_str(), Some("http" | "https" | "lb"))
                && uri
                    .authority()
                    .is_some_and(|authority| !authority.as_str().contains('@'))
                && uri.path() == "/"
                && uri.query().is_none(),
            "Agent target must be a fixed origin"
        );
        ensure!(
            cfg.path.starts_with('/')
                && !cfg.path.starts_with("//")
                && cfg.path.len() <= 2048
                && !cfg.path.contains(['?', '#', '\\', '$'])
                && !cfg.path.chars().any(char::is_control)
                && !cfg.path.split('/').any(|part| part == "." || part == ".."),
            "invalid Agent target path"
        );
        let authorization = if cfg.api_key.is_empty() {
            None
        } else {
            let secret = crate::security::secret::resolve_text(
                &cfg.api_key,
                dir,
                "Agent target credential",
            )?;
            ensure!(!secret.is_empty(), "Agent target credential is empty");
            let mut value = HeaderValue::from_str(&format!("Bearer {secret}"))
                .map_err(|_| anyhow::anyhow!("invalid Agent target credential"))?;
            value.set_sensitive(true);
            Some(value)
        };
        Ok(Arc::new(Self {
            upstream: cfg.uri.clone(),
            path: cfg.path.clone(),
            authorization,
        }))
    }

    /// 业务作用：从固定目标生成全新的请求头，避免客户端 Authorization、Cookie 或会话头泄露到工具服务。
    ///
    /// 参数说明：
    /// - `method`：是已批准方法
    /// - `body`：是经过策略校验的有界实体。
    ///
    /// 返回：只含固定认证和 JSON 协商头的外呼；协议状态头由调用方显式添加。
    pub(crate) fn request(self: &Arc<Self>, method: Method, body: Bytes) -> Outbound {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        if let Some(value) = &self.authorization {
            headers.insert(http::header::AUTHORIZATION, value.clone());
        }
        Outbound {
            target: self.clone(),
            method,
            path: self.path.clone(),
            headers,
            body,
        }
    }
}

/// 业务作用：校验会话、调用与字节资源边界，拒绝可形成无限状态或超大单次分配的配置。
///
/// 参数说明：
/// - `limits`：是路由 Agent 配额。
///
/// 返回：所有配额有效且相互一致时成功；否则拒绝候选。
#[cfg(feature = "agent-protocols")]
pub(super) fn validate_limits(limits: &LimitsCfg) -> Result<()> {
    ensure!(
        (1..=4 * 1024 * 1024).contains(&limits.max_request_bytes)
            && (1..=16 * 1024 * 1024).contains(&limits.max_response_bytes)
            && (1..=1024 * 1024).contains(&limits.max_frame_bytes)
            && limits.max_frame_bytes <= limits.max_response_bytes,
        "invalid Agent body limits"
    );
    ensure!(
        (1..=16_384).contains(&limits.max_sessions)
            && (1..=limits.max_sessions).contains(&limits.max_sessions_per_identity)
            && (1..=4096).contains(&limits.max_inflight),
        "invalid Agent capacity limits"
    );
    ensure!(
        (1000..=3_600_000).contains(&limits.session_ttl_ms)
            && (1..=300_000).contains(&limits.deadline_ms)
            && (1..=100_000).contains(&limits.max_calls_per_session)
            && (1..=1024 * 1024 * 1024).contains(&limits.max_bytes_per_session),
        "invalid Agent lifetime limits"
    );
    ensure!(
        limits.max_bytes_per_session
            >= (limits.max_request_bytes + limits.max_response_bytes) as u64,
        "Agent lifetime byte budget must admit one maximum call"
    );
    Ok(())
}

/// 业务作用：在绝对调用预算和配置权威仍有效时读取有限响应，不将上游错误正文带入日志。
///
/// 参数说明：
/// - `response`：是上游响应
/// - `max_bytes`：是累计体积门
/// - `budget`：是共享调用预算
/// - `transport`：复验当前代次。
///
/// 返回：完整合法的有界字节；超时、撤权、trailer、压缩或超限一律拒绝。
pub(crate) async fn collect(
    response: Response<BoxBody>,
    max_bytes: usize,
    budget: &RequestBudget,
    transport: &dyn Transport,
) -> Result<Bytes> {
    ensure!(
        !response
            .headers()
            .contains_key(http::header::CONTENT_ENCODING),
        "compressed Agent response is unsupported"
    );
    let mut body = response.into_body();
    let mut bytes = BytesMut::new();
    loop {
        // 撤权检查与 deadline 共用等待门；旧配置不因慢上游而无限保留发送权限。
        ensure!(transport.live(), "Agent configuration retired");
        let frame = wait(budget, transport, body.frame()).await?;
        let Some(frame) = frame else {
            break;
        };
        let data = frame
            .map_err(|_| anyhow::anyhow!("Agent response read failed"))?
            .into_data()
            .map_err(|_| anyhow::anyhow!("Agent response trailers are unsupported"))?;
        ensure!(
            bytes.len().saturating_add(data.len()) <= max_bytes,
            "Agent response exceeds byte limit"
        );
        bytes.extend_from_slice(&data);
    }
    ensure!(transport.live(), "Agent configuration retired");
    Ok(bytes.freeze())
}

/// 业务作用：在等待上游期间同时复验绝对预算和配置权威，空闲连接不能延迟撤权。
///
/// 参数说明：
/// - `budget`：是父调用预算
/// - `transport`：提供同代权限
/// - `future`：是单次异步工作。
///
/// 返回：工作完成值；预算耗尽或撤权时丢弃未完成工作。
pub(crate) async fn wait<T>(
    budget: &RequestBudget,
    transport: &dyn Transport,
    future: impl std::future::Future<Output = T>,
) -> Result<T> {
    tokio::pin!(future);
    loop {
        ensure!(transport.live(), "Agent configuration retired");
        tokio::select! {
            result = budget.run(&mut future) => {
                ensure!(transport.live(), "Agent configuration retired");
                return result.map_err(Into::into);
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

/// 每个解析器只保留一个有界事件，原始头与 SSE 元数据不会未经校验直接下发。
#[cfg(feature = "agent-protocols")]
pub(super) struct Events {
    body: BoxBody,
    pending: BytesMut,
    total: usize,
    max_total: usize,
    max_frame: usize,
    ended: bool,
}

#[cfg(feature = "agent-protocols")]
impl Events {
    /// 业务作用：为已协商的事件流创建有界解析器，禁止压缩绕开实体预算。
    ///
    /// 参数说明：
    /// - `response`：是上游 SSE
    /// - `max_total`：分别限制总字节与单事件。
    /// - `max_frame`：分别限制总字节与单事件。
    ///
    /// 返回：独占响应实体的解析器；媒体类型或编码不合法时拒绝。
    pub(super) fn new(
        response: Response<BoxBody>,
        max_total: usize,
        max_frame: usize,
    ) -> Result<Self> {
        ensure!(
            is_sse(&response)
                && !response
                    .headers()
                    .contains_key(http::header::CONTENT_ENCODING),
            "invalid Agent SSE media type or encoding"
        );
        Ok(Self {
            body: response.into_body(),
            pending: BytesMut::new(),
            total: 0,
            max_total,
            max_frame,
            ended: false,
        })
    }

    /// 业务作用：读取一个完整且有界的 JSON 事件，再交协议状态机决定能否交付。
    ///
    /// 参数说明：
    /// - `budget`：在等待和事件交付前复验生命周期权威。
    /// - `transport`：在等待和事件交付前复验生命周期权威。
    ///
    /// 返回：完整事件或流结束；未知 SSE 字段、坏 UTF-8、半事件、trailer 与超限均拒绝。
    pub(super) async fn next(
        &mut self,
        budget: &RequestBudget,
        transport: &dyn Transport,
    ) -> Result<Option<Value>> {
        loop {
            ensure!(
                transport.live() && !budget.is_exhausted(),
                "Agent event authority expired"
            );
            let delimiter = self
                .pending
                .windows(2)
                .position(|bytes| bytes == b"\n\n")
                .map(|index| (index, 2))
                .into_iter()
                .chain(
                    self.pending
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n")
                        .map(|index| (index, 4)),
                )
                .min_by_key(|(index, _)| *index);
            if let Some((end, delimiter)) = delimiter {
                ensure!(end <= self.max_frame, "Agent event exceeds frame limit");
                let bytes = self.pending.split_to(end + delimiter);
                let text =
                    std::str::from_utf8(&bytes[..end]).context("Agent event is not UTF-8")?;
                let mut data = Vec::new();
                for line in text.lines() {
                    if let Some(value) = line.strip_prefix("data:") {
                        data.push(value.strip_prefix(' ').unwrap_or(value));
                    } else {
                        ensure!(
                            line.is_empty()
                                || line.starts_with(':')
                                || line.starts_with("id:")
                                || line.starts_with("retry:")
                                || matches!(line, "event: message" | "event:message"),
                            "unknown Agent SSE field"
                        );
                    }
                }
                if data.is_empty() {
                    continue;
                }
                return serde_json::from_str(&data.join("\n"))
                    .map(Some)
                    .map_err(|_| anyhow::anyhow!("invalid Agent event JSON"));
            }
            ensure!(
                self.pending.len() <= self.max_frame + 3,
                "Agent event exceeds frame limit"
            );
            if self.ended {
                ensure!(
                    self.pending.iter().all(u8::is_ascii_whitespace),
                    "incomplete Agent event"
                );
                return Ok(None);
            }
            match wait(budget, transport, self.body.frame()).await? {
                None => self.ended = true,
                Some(frame) => {
                    let data = frame
                        .map_err(|_| anyhow::anyhow!("Agent event read failed"))?
                        .into_data()
                        .map_err(|_| anyhow::anyhow!("Agent event trailers unsupported"))?;
                    self.total = self.total.saturating_add(data.len());
                    ensure!(
                        self.total <= self.max_total,
                        "Agent event stream exceeds byte limit"
                    );
                    self.pending.extend_from_slice(&data);
                }
            }
        }
    }
}

/// 业务作用：仅根据明确媒体类型选择事件解析，不猜测正文或按客户端要求改变上游语义。
///
/// 参数说明：
/// - `response`：是上游响应头。
///
/// 返回：媒体类型为 text/event-stream 时为 true。
#[cfg(feature = "agent-protocols")]
pub(super) fn is_sse(response: &Response<BoxBody>) -> bool {
    response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// 业务作用：在响应实体释放前保留调用并发槽，避免返回 SSE head 就提前返还容量。
///
/// 参数说明：
/// - `response`：是协议结果
/// - `permit`：是已取得的并发槽。
///
/// 返回：头不变、实体生命周期绑定配额的响应。
#[cfg(feature = "agent-protocols")]
pub(super) fn hold(
    response: Response<BoxBody>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response<BoxBody> {
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        http_body_util::BodyExt::boxed(HeldBody {
            body,
            _permit: permit,
        }),
    )
}

#[cfg(feature = "agent-protocols")]
struct HeldBody {
    body: BoxBody,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
#[cfg(feature = "agent-protocols")]
impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = crate::BoxError;
    /// 业务作用：保持下游背压与原始帧语义，同时让并发配额覆盖整个响应生命周期。
    ///
    /// 参数说明：
    /// - `cx`：是 HTTP body 的调度上下文。
    ///
    /// 返回：原始数据帧、失败或结束，不额外缓存正文。
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
}

/// 业务作用：生成不包含上游地址、凭据或参数原文的 JSON 协议响应。
///
/// 参数说明：
/// - `status`：是 HTTP 状态
/// - `value`：是已经过脱敏与协议校验的返回对象。
///
/// 返回：禁止共享缓存的 JSON 响应，避免跨身份复用会话或工具结果。
#[cfg(feature = "agent-protocols")]
pub(super) fn json_response(status: u16, value: Value) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::from(value.to_string())))
        .expect("fixed Agent response headers")
}
