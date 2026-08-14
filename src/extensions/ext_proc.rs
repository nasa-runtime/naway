//! Envoy External Processing 的配置契约、状态机与有界 protobuf 编解码。
//!
//! route 只有显式配置时才建立一条每请求双向流。扩展服务可以观察选定相位并返回受白名单
//! 约束的 header/body mutation、即时响应和动态 metadata；任何协议错序、越权 mutation 或
//! 明确拒绝都失败闭合，`fail_open` 只覆盖可分类的依赖故障。
#![cfg_attr(not(feature = "ext-proc"), allow(dead_code))]

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use http::header::{HeaderName, HeaderValue};
use http::Uri;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::model::{ExtProcBodyModeCfg, ExtProcCfg};

#[cfg(feature = "ext-proc")]
use bytes::{Buf, Bytes, BytesMut};
#[cfg(feature = "ext-proc")]
use http::{HeaderMap, Method, Response, StatusCode};
#[cfg(feature = "ext-proc")]
use http_body_util::BodyExt;
#[cfg(feature = "ext-proc")]
use prost::Message;
#[cfg(feature = "ext-proc")]
use tokio::sync::Mutex as AsyncMutex;

#[cfg(feature = "ext-proc")]
use crate::{full_body, BoxBody};

const PROCESS_PATH: &str = "/envoy.service.ext_proc.v3.ExternalProcessor/Process";
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_TOTAL_TIMEOUT_MS: u64 = 15 * 60_000;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 65_536;
const MAX_FAILURE_THRESHOLD: u32 = 10_000;
const MAX_MUTATION_HEADERS: usize = 128;
const MAX_METADATA_NAMESPACES: usize = 32;
const MAX_AUTHORIZATION_BYTES: usize = 16 * 1024;

/// 已构建的 route External Processing 计划。
pub(crate) struct ExtProcPlan {
    upstream: Arc<str>,
    authorization: Option<HeaderValue>,
    request_headers: bool,
    response_headers: bool,
    request_body: ExtProcBodyModeCfg,
    response_body: ExtProcBodyModeCfg,
    request_trailers: bool,
    response_trailers: bool,
    message_timeout: Duration,
    total_timeout: Duration,
    max_message_bytes: usize,
    max_total_bytes: usize,
    max_body_bytes: usize,
    fail_open: bool,
    mutation_headers: HashSet<HeaderName>,
    frozen_identity_headers: HashSet<HeaderName>,
    writable_metadata_namespaces: HashSet<String>,
    inference_endpoint_picker: bool,
    in_flight: Arc<Semaphore>,
    circuit: Mutex<CircuitState>,
    failure_threshold: u32,
    reset_timeout: Duration,
}

struct CircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    probe_in_flight: bool,
}

/// 一次 External Processing 在途与半开探测权威。
///
/// Drop 会释放并发槽；调用方必须在收到可分类结果后显式记账，避免取消路径永久占用半开状态。
pub(crate) struct ExtProcPermit {
    plan: Arc<ExtProcPlan>,
    _in_flight: OwnedSemaphorePermit,
    half_open_probe: bool,
    recorded: bool,
}

#[cfg(feature = "ext-proc")]
/// 当前请求共享的 External Processing 会话。
///
/// request/response streamed body task 通过同一异步锁串行“发送一条、接收唯一匹配响应”，既保留
/// gRPC 双向流状态，也避免多个相位并发读取时把响应交给错误 phase。
pub(crate) type SharedExtProcSession = Arc<AsyncMutex<ExtProcSession>>;
#[cfg(not(feature = "ext-proc"))]
pub(crate) type SharedExtProcSession = ();

#[cfg(feature = "ext-proc")]
/// 当前请求可跨相位读取的动态 metadata 快照。
#[derive(Clone, Default)]
pub(crate) struct ExtProcMetadata {
    namespaces: std::collections::HashMap<String, prost_types::Struct>,
}

#[cfg(feature = "ext-proc")]
impl ExtProcMetadata {
    /// 业务作用：读取 EPP 等处理器写入的单个字符串决策，不把完整 protobuf 结构暴露给数据面。
    ///
    /// 参数说明：`namespace` 与 `key` 必须是快照已授权的标准 metadata 身份。
    ///
    /// 返回：字段存在且类型为字符串时返回借用；缺失或类型不匹配返回 `None`。
    pub(crate) fn string(&self, namespace: &str, key: &str) -> Option<&str> {
        self.namespaces
            .get(namespace)?
            .fields
            .get(key)?
            .kind
            .as_ref()
            .and_then(|kind| match kind {
                prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                _ => None,
            })
    }
}

#[cfg(feature = "ext-proc")]
/// 一个已建立的标准 ExternalProcessor.Process 双向流。
pub(crate) struct ExtProcSession {
    plan: Arc<ExtProcPlan>,
    wire: Option<ExtProcWire>,
    permit: ExtProcPermit,
    started: Instant,
    sent_bytes: usize,
    received_bytes: usize,
    metadata: ExtProcMetadata,
    bypassed: bool,
    first_message: bool,
    pending_immediate: Option<Response<BoxBody>>,
}

#[cfg(feature = "ext-proc")]
/// gRPC response head 与可选状态码的异步交接通道。
type ExtProcResponseWait =
    tokio::sync::oneshot::Receiver<Result<(BoxBody, Option<u32>), ExtProcError>>;

#[cfg(feature = "ext-proc")]
/// 由普通 upstream 连接治理建立的 gRPC transport。
pub(crate) struct ExtProcWire {
    sender: Option<http_body_util::channel::Sender<Bytes, crate::BoxError>>,
    response: Option<BoxBody>,
    response_wait: Option<ExtProcResponseWait>,
    buffered: BytesMut,
    grpc_status: Option<u32>,
}

#[cfg(feature = "ext-proc")]
/// 一个 phase 经权限校验后的原子结果。
pub(crate) enum ExtProcAction {
    /// 继续当前 HTTP 管线，并一次性提交 header/body/trailer delta。
    Continue(ExtProcChanges),
    /// 立即终止请求并返回处理器生成的有界本地响应。
    Immediate(Response<BoxBody>),
}

#[cfg(feature = "ext-proc")]
/// 已验证的 External Processing 变更。
pub(crate) struct ExtProcChanges {
    header_set: Vec<(HeaderName, HeaderValue, HeaderAppendAction)>,
    header_remove: Vec<HeaderName>,
    body: Option<Bytes>,
    clear_body: bool,
    /// Inference EPP 可把一个 body phase 拆成多条有序响应；该标记只在接收状态机聚合期间存在。
    streamed_end_of_stream: Option<bool>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, Copy)]
enum HeaderAppendAction {
    AppendOrAdd,
    AddIfAbsent,
    OverwriteOrAdd,
    OverwriteIfExists,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExtProcPhase {
    RequestHeaders,
    RequestBody,
    RequestTrailers,
    ResponseHeaders,
    ResponseBody,
    ResponseTrailers,
}

/// External Processing 错误是否允许进入配置声明的依赖故障放行分支。
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ExtProcErrorClass {
    /// 连接、超时、服务状态和 circuit 容量等外部依赖故障。
    Dependency,
    /// 错序、重复响应、越权 mutation、畸形 protobuf 或明确拒绝。
    Protocol,
    /// 客户端输入或本地资源超过 route 声明的硬门。
    Input,
}

/// 带稳定安全分类的 External Processing 失败。
#[derive(Debug)]
pub(crate) struct ExtProcError {
    class: ExtProcErrorClass,
    source: anyhow::Error,
}

impl std::fmt::Display for ExtProcError {
    /// 业务作用：输出不包含认证材料与业务实体的低敏错误摘要。
    ///
    /// 参数说明：`formatter` 接收分类和底层安全错误文本。
    ///
    /// 返回：写入成功或格式化失败。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.class, self.source)
    }
}

impl std::error::Error for ExtProcError {}

impl ExtProcError {
    /// 业务作用：构造一个可由 `fail_open` 覆盖的依赖故障。
    ///
    /// 参数说明：`source` 是不含敏感数据的底层原因。
    ///
    /// 返回：分类为 Dependency 的错误。
    pub(crate) fn dependency(source: impl Into<anyhow::Error>) -> Self {
        Self {
            class: ExtProcErrorClass::Dependency,
            source: source.into(),
        }
    }

    /// 业务作用：构造一个必须失败闭合的处理器协议错误。
    ///
    /// 参数说明：`source` 描述错序、畸形或越权行为。
    ///
    /// 返回：分类为 Protocol 的错误。
    pub(crate) fn protocol(source: impl Into<anyhow::Error>) -> Self {
        Self {
            class: ExtProcErrorClass::Protocol,
            source: source.into(),
        }
    }

    /// 业务作用：构造一个必须失败闭合的本地输入或资源越界错误。
    ///
    /// 参数说明：`source` 描述输入拒绝原因。
    ///
    /// 返回：分类为 Input 的错误。
    pub(crate) fn input(source: impl Into<anyhow::Error>) -> Self {
        Self {
            class: ExtProcErrorClass::Input,
            source: source.into(),
        }
    }

    /// 业务作用：判断失败是否属于操作者明确允许放行的外部依赖故障。
    ///
    /// 参数说明：无。
    ///
    /// 返回：只有 Dependency 返回 true。
    pub(crate) fn may_fail_open(&self) -> bool {
        self.class == ExtProcErrorClass::Dependency
    }
}

impl ExtProcPlan {
    /// 业务作用：把 route 的 External Processing 声明编译为资源有界、权限冻结的运行计划。
    ///
    /// 参数说明：`cfg` 是 route 声明；`config_dir` 解析认证 SecretSource；`route_id` 只用于错误定位；
    /// `frozen_identity_headers` 是本地认证已拥有、扩展服务不得修改的动态 header 集合；
    /// `inference_endpoint_picker` 只为已经绑定 InferencePool 的控制器路由启用全双工 EPP 语义。
    ///
    /// 返回：配置自洽且制品带 `ext-proc` feature 时返回计划，否则拒绝候选快照。
    pub(crate) fn build(
        cfg: &ExtProcCfg,
        config_dir: &Path,
        route_id: &str,
        frozen_identity_headers: &HashSet<HeaderName>,
        inference_endpoint_picker: bool,
    ) -> Result<Self> {
        #[cfg(not(feature = "ext-proc"))]
        {
            let _ = (
                cfg,
                config_dir,
                route_id,
                frozen_identity_headers,
                inference_endpoint_picker,
            );
            bail!("route ext_proc requires the `ext-proc` feature");
        }
        #[cfg(feature = "ext-proc")]
        {
            if !cfg.request_headers
                && !cfg.response_headers
                && cfg.request_body == ExtProcBodyModeCfg::None
                && cfg.response_body == ExtProcBodyModeCfg::None
                && !cfg.request_trailers
                && !cfg.response_trailers
            {
                bail!("ext_proc must enable at least one processing phase");
            }
            if !(1..=MAX_TIMEOUT_MS).contains(&cfg.message_timeout_ms) {
                bail!("message_timeout_ms must be within 1..={MAX_TIMEOUT_MS}");
            }
            if !(cfg.message_timeout_ms..=MAX_TOTAL_TIMEOUT_MS).contains(&cfg.total_timeout_ms) {
                bail!(
                    "total_timeout_ms must be within message_timeout_ms..={MAX_TOTAL_TIMEOUT_MS}"
                );
            }
            if !(256..=MAX_MESSAGE_BYTES).contains(&cfg.max_message_bytes) {
                bail!("max_message_bytes must be within 256..={MAX_MESSAGE_BYTES}");
            }
            if !(cfg.max_message_bytes..=MAX_TOTAL_BYTES).contains(&cfg.max_total_bytes) {
                bail!("max_total_bytes must be within max_message_bytes..={MAX_TOTAL_BYTES}");
            }
            if !(1..=MAX_BODY_BYTES).contains(&cfg.max_body_bytes)
                || cfg.max_body_bytes > cfg.max_total_bytes
            {
                bail!("max_body_bytes must be within 1..=max_total_bytes and no more than {MAX_BODY_BYTES}");
            }
            if !(1..=MAX_IN_FLIGHT).contains(&cfg.max_in_flight) {
                bail!("max_in_flight must be within 1..={MAX_IN_FLIGHT}");
            }
            if !(1..=MAX_FAILURE_THRESHOLD).contains(&cfg.failure_threshold) {
                bail!("failure_threshold must be within 1..={MAX_FAILURE_THRESHOLD}");
            }
            if !(1..=MAX_TIMEOUT_MS).contains(&cfg.reset_timeout_ms) {
                bail!("reset_timeout_ms must be within 1..={MAX_TIMEOUT_MS}");
            }
            let upstream = compile_target(&cfg.target)?;
            let authorization = if cfg.authorization.trim().is_empty() {
                None
            } else {
                let secret = crate::secret::resolve_text(
                    cfg.authorization.as_str(),
                    config_dir,
                    &format!("route `{route_id}` ext_proc authorization"),
                )?;
                if secret.len() > MAX_AUTHORIZATION_BYTES {
                    bail!("authorization exceeds {MAX_AUTHORIZATION_BYTES} bytes");
                }
                let mut value = HeaderValue::from_str(&secret)
                    .context("ext_proc authorization is not a valid gRPC metadata value")?;
                value.set_sensitive(true);
                Some(value)
            };
            let mutation_headers = compile_headers(&cfg.mutation_headers)?;
            if mutation_headers
                .iter()
                .any(|header| frozen_identity_headers.contains(header))
            {
                bail!("mutation_headers cannot contain a locally authenticated identity header");
            }
            if cfg.writable_metadata_namespaces.len() > MAX_METADATA_NAMESPACES {
                bail!("writable_metadata_namespaces exceeds {MAX_METADATA_NAMESPACES} entries");
            }
            let mut writable_metadata_namespaces = HashSet::new();
            for namespace in &cfg.writable_metadata_namespaces {
                if namespace.is_empty()
                    || namespace.len() > 128
                    || !namespace.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
                    || !writable_metadata_namespaces.insert(namespace.clone())
                {
                    bail!("writable metadata namespaces must be unique safe ASCII names");
                }
            }
            Ok(Self {
                upstream: Arc::from(upstream),
                authorization,
                request_headers: cfg.request_headers,
                response_headers: cfg.response_headers,
                request_body: cfg.request_body,
                response_body: cfg.response_body,
                request_trailers: cfg.request_trailers,
                response_trailers: cfg.response_trailers,
                message_timeout: Duration::from_millis(cfg.message_timeout_ms),
                total_timeout: Duration::from_millis(cfg.total_timeout_ms),
                max_message_bytes: cfg.max_message_bytes,
                max_total_bytes: cfg.max_total_bytes,
                max_body_bytes: cfg.max_body_bytes,
                fail_open: cfg.fail_open,
                mutation_headers,
                frozen_identity_headers: frozen_identity_headers.clone(),
                writable_metadata_namespaces,
                inference_endpoint_picker,
                in_flight: Arc::new(Semaphore::new(cfg.max_in_flight)),
                circuit: Mutex::new(CircuitState {
                    consecutive_failures: 0,
                    open_until: None,
                    probe_in_flight: false,
                }),
                failure_threshold: cfg.failure_threshold,
                reset_timeout: Duration::from_millis(cfg.reset_timeout_ms),
            })
        }
    }

    /// 业务作用：在建流前同时取得 route 并发槽和 circuit 探测权威。
    ///
    /// 参数说明：`self` 必须来自当前 route 快照的共享计划。
    ///
    /// 返回：容量可用且 circuit 允许时返回 RAII permit；否则返回可分类依赖故障。
    pub(crate) fn acquire(self: &Arc<Self>) -> Result<ExtProcPermit, ExtProcError> {
        let now = Instant::now();
        let half_open_probe = {
            let mut circuit = self.circuit.lock();
            match circuit.open_until {
                Some(until) if now < until => {
                    return Err(ExtProcError::dependency(anyhow::anyhow!(
                        "ext_proc circuit is open"
                    )))
                }
                Some(_) if circuit.probe_in_flight => {
                    return Err(ExtProcError::dependency(anyhow::anyhow!(
                        "ext_proc half-open probe is already running"
                    )))
                }
                Some(_) => {
                    circuit.probe_in_flight = true;
                    true
                }
                None => false,
            }
        };
        let in_flight = match self.in_flight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                if half_open_probe {
                    self.circuit.lock().probe_in_flight = false;
                }
                return Err(ExtProcError::dependency(anyhow::anyhow!(
                    "ext_proc in-flight limit reached"
                )));
            }
        };
        Ok(ExtProcPermit {
            plan: self.clone(),
            _in_flight: in_flight,
            half_open_probe,
            recorded: false,
        })
    }

    /// 业务作用：判断当前 route 是否允许依赖故障绕过处理器。
    ///
    /// 参数说明：无。
    ///
    /// 返回：只反映显式配置，不改变 circuit 状态。
    pub(crate) fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// 业务作用：暴露已校验的扩展 service 目标，供普通 upstream 选择器复用。
    ///
    /// 参数说明：无。
    ///
    /// 返回：固定直连 origin 或 `lb://service`。
    pub(crate) fn upstream(&self) -> &str {
        &self.upstream
    }

    /// 业务作用：提供标准 ExternalProcessor.Process 路径，禁止配置把流发往任意方法。
    ///
    /// 参数说明：无。
    ///
    /// 返回：Envoy v3 标准 gRPC method path。
    pub(crate) const fn process_path(&self) -> &'static str {
        PROCESS_PATH
    }

    /// 业务作用：为扩展连接注入独立 SecretSource 凭据，不暴露给业务请求。
    ///
    /// 参数说明：无。
    ///
    /// 返回：存在配置时返回敏感 HeaderValue 借用。
    pub(crate) fn authorization(&self) -> Option<&HeaderValue> {
        self.authorization.as_ref()
    }

    /// 业务作用：提供单 phase 响应 deadline。
    ///
    /// 参数说明：无。
    ///
    /// 返回：已校验非零时长。
    pub(crate) fn message_timeout(&self) -> Duration {
        self.message_timeout
    }

    /// 业务作用：提供整条扩展流总 deadline。
    ///
    /// 参数说明：无。
    ///
    /// 返回：不短于单 phase 的已校验时长。
    pub(crate) fn total_timeout(&self) -> Duration {
        self.total_timeout
    }

    /// 业务作用：向协议编解码层提供单消息与累计字节硬门。
    ///
    /// 参数说明：无。
    ///
    /// 返回：`(max_message_bytes, max_total_bytes)`。
    pub(crate) fn wire_limits(&self) -> (usize, usize) {
        (self.max_message_bytes, self.max_total_bytes)
    }

    /// 业务作用：限制请求或响应 body 进入扩展处理路径的累计字节。
    ///
    /// 参数说明：无。
    ///
    /// 返回：已校验 body 上限。
    pub(crate) fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// 业务作用：暴露构建期冻结的相位选择，供请求状态机决定唯一消息顺序。
    ///
    /// 参数说明：无。
    ///
    /// 返回：request/response header、body 与 trailer 模式元组。
    pub(crate) fn phases(
        &self,
    ) -> (
        bool,
        ExtProcBodyModeCfg,
        bool,
        bool,
        ExtProcBodyModeCfg,
        bool,
    ) {
        (
            self.request_headers,
            self.request_body,
            self.request_trailers,
            self.response_headers,
            self.response_body,
            self.response_trailers,
        )
    }

    /// 业务作用：判断处理器返回的普通 header 是否落在当前路由的 mutation 权限内。
    ///
    /// 参数说明：`name` 是已通过 HTTP 语法解析的 header 名。
    ///
    /// 返回：普通路由只允许显式 allowlist；受控 InferencePool EPP 可回送非冻结请求头并重算 Content-Length。
    pub(crate) fn may_mutate_header(&self, name: &HeaderName) -> bool {
        let inference_content_length =
            self.inference_endpoint_picker && name == http::header::CONTENT_LENGTH;
        (self.mutation_headers.contains(name)
            || inference_content_length
            || (self.inference_endpoint_picker && !forbidden_mutation_header(name)))
            && !self.frozen_identity_headers.contains(name)
            && (!forbidden_mutation_header(name) || inference_content_length)
    }

    /// 业务作用：标识标准 InferencePool EPP 的全双工 buffered request 契约。
    ///
    /// 参数说明：无。
    ///
    /// 返回：只有控制器生成并由 InferencePool 路由门复验的计划返回 true。
    pub(crate) fn pipelines_buffered_request_body(&self) -> bool {
        self.inference_endpoint_picker
    }

    /// 业务作用：判断动态 metadata 顶层 namespace 是否允许写入当前请求上下文。
    ///
    /// 参数说明：`namespace` 是处理器响应顶层键。
    ///
    /// 返回：显式 allowlist 命中时为 true。
    pub(crate) fn may_write_metadata(&self, namespace: &str) -> bool {
        self.writable_metadata_namespaces.contains(namespace)
    }

    #[cfg(feature = "ext-proc")]
    /// 业务作用：编码首个 request_headers 消息，并创建仍受 route permit 约束的请求会话。
    ///
    /// 参数说明：`wire` 是普通 upstream 已建立的 gRPC transport；`permit` 持有并发和 circuit 权威；
    /// `parts` 是经认证授权后的请求 head；`end_of_stream` 表示没有后续 body/trailer。
    ///
    /// 返回：首个消息已由 transport 发送时返回共享会话；本地编码越界返回 Input 错误。
    pub(crate) fn start_session(
        self: &Arc<Self>,
        wire: ExtProcWire,
        permit: ExtProcPermit,
    ) -> SharedExtProcSession {
        Arc::new(AsyncMutex::new(ExtProcSession {
            plan: self.clone(),
            wire: Some(wire),
            permit,
            started: Instant::now(),
            sent_bytes: 0,
            received_bytes: 0,
            metadata: ExtProcMetadata::default(),
            bypassed: false,
            first_message: true,
            pending_immediate: None,
        }))
    }
}

#[cfg(feature = "ext-proc")]
impl ExtProcWire {
    /// 业务作用：封装已建立的 gRPC request sender 与 response body，并初始化有界解帧状态。
    ///
    /// 参数说明：`sender` 写入 HTTP/2 request DATA；`response_wait` 在上游 response head 到达后
    /// 提供 DATA/trailers，不要求服务端先发 response head 才能发送首条业务消息。
    ///
    /// 返回：可按 protobuf 消息边界发送和接收的 wire。
    pub(crate) fn new(
        sender: http_body_util::channel::Sender<Bytes, crate::BoxError>,
        response_wait: tokio::sync::oneshot::Receiver<Result<(BoxBody, Option<u32>), ExtProcError>>,
    ) -> Self {
        Self {
            sender: Some(sender),
            response: None,
            response_wait: Some(response_wait),
            buffered: BytesMut::new(),
            grpc_status: None,
        }
    }

    /// 业务作用：发送一条已编码 protobuf 消息，并保留 HTTP/2 channel 背压。
    ///
    /// 参数说明：`message` 是不含 gRPC 五字节 envelope 的 protobuf bytes。
    ///
    /// 返回：发送成功返回 envelope 字节数；request stream 已关闭时返回 Dependency 错误。
    async fn send(&mut self, message: Bytes) -> Result<usize, ExtProcError> {
        let length = message.len();
        let encoded = encode_grpc_frame(message)?;
        let wire_bytes = encoded.len();
        self.sender
            .as_mut()
            .context("ext_proc request stream is closed")
            .map_err(ExtProcError::dependency)?
            .send_data(encoded)
            .await
            .map_err(|_| {
                ExtProcError::dependency(anyhow::anyhow!(
                    "ext_proc request stream closed while sending {length} byte message"
                ))
            })?;
        Ok(wire_bytes)
    }

    /// 业务作用：读取恰好一条未压缩 gRPC response message，并验证 framing 与最终状态。
    ///
    /// 参数说明：`max_message_bytes` 是当前 route 单消息硬门。
    ///
    /// 返回：成功返回 protobuf bytes 和 wire 字节数；压缩、超限、截断与非零状态分类失败。
    async fn receive(&mut self, max_message_bytes: usize) -> Result<(Bytes, usize), ExtProcError> {
        if self.response.is_none() {
            let wait = self
                .response_wait
                .take()
                .context("ext_proc response head future is unavailable")
                .map_err(ExtProcError::dependency)?;
            let (response, grpc_status) = wait.await.map_err(|_| {
                ExtProcError::dependency(anyhow::anyhow!(
                    "ext_proc response head task ended unexpectedly"
                ))
            })??;
            self.response = Some(response);
            self.grpc_status = grpc_status;
        }
        loop {
            if self.buffered.len() >= 5 {
                if self.buffered[0] != 0 {
                    return Err(ExtProcError::protocol(anyhow::anyhow!(
                        "ext_proc returned compressed or invalid gRPC envelope"
                    )));
                }
                let declared = u32::from_be_bytes(
                    self.buffered[1..5]
                        .try_into()
                        .expect("gRPC envelope prefix length checked"),
                ) as usize;
                if declared > max_message_bytes {
                    return Err(ExtProcError::protocol(anyhow::anyhow!(
                        "ext_proc response exceeds max_message_bytes"
                    )));
                }
                if self.buffered.len() >= declared + 5 {
                    self.buffered.advance(5);
                    return Ok((self.buffered.split_to(declared).freeze(), declared + 5));
                }
            }
            let frame = self
                .response
                .as_mut()
                .expect("ext_proc response initialized above")
                .frame()
                .await;
            match frame {
                Some(Ok(frame)) if frame.is_data() => {
                    let data = frame
                        .into_data()
                        .expect("is_data guarantees data conversion");
                    if self
                        .buffered
                        .len()
                        .checked_add(data.len())
                        .is_none_or(|total| total > max_message_bytes.saturating_add(5))
                    {
                        return Err(ExtProcError::protocol(anyhow::anyhow!(
                            "ext_proc response frame exceeds message buffer"
                        )));
                    }
                    self.buffered.extend_from_slice(&data);
                }
                Some(Ok(frame)) if frame.is_trailers() => {
                    let trailers = frame
                        .into_trailers()
                        .expect("is_trailers guarantees trailer conversion");
                    self.grpc_status = Some(parse_grpc_status(&trailers)?);
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    return Err(ExtProcError::dependency(anyhow::anyhow!(
                        "read ext_proc response body: {error}"
                    )))
                }
                None => {
                    let status = self.grpc_status.unwrap_or(2);
                    return Err(classify_grpc_status(status, self.buffered.is_empty()));
                }
            }
        }
    }

    /// 业务作用：关闭本请求发送方向，使处理器能观察正常半关闭并释放流状态。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；response body 继续由 Drop 取消或读取最终状态。
    fn close_send(&mut self) {
        self.sender.take();
    }
}

#[cfg(feature = "ext-proc")]
impl ExtProcSession {
    /// 业务作用：判断会话是否因可放行依赖故障进入永久 bypass，后续相位不得再次访问处理器。
    ///
    /// 参数说明：无。
    ///
    /// 返回：已 bypass 返回 true。
    pub(crate) fn bypassed(&self) -> bool {
        self.bypassed
    }

    /// 业务作用：把依赖故障记入 circuit，并在显式 `fail_open` 时将当前请求切换为纯透传。
    ///
    /// 参数说明：`error` 必须来自发送、超时或服务状态等可分类依赖失败。
    ///
    /// 返回：允许绕过时返回 true；协议与输入错误或未配置放行时返回 false。
    pub(crate) fn apply_failure(&mut self, error: &ExtProcError) -> bool {
        if error.may_fail_open() {
            self.permit.record_dependency_failure();
            if self.plan.fail_open() {
                self.bypassed = true;
                self.wire.take();
                return true;
            }
        }
        false
    }

    /// 业务作用：发送一个 HTTP phase 并只接受同 phase 的唯一标准响应。
    ///
    /// 参数说明：`phase` 固定 oneof 类型；`head`、`body`、`trailers` 只使用与 phase 对应的一个输入。
    ///
    /// 返回：有效响应返回原子动作；依赖、超时、错序、重复语义或越权 mutation 分类失败。
    pub(crate) async fn process(
        &mut self,
        phase: ExtProcPhase,
        head: Option<(&Method, &Uri, &HeaderMap, bool)>,
        body: Option<(&Bytes, bool)>,
        trailers: Option<&HeaderMap>,
    ) -> Result<ExtProcAction, ExtProcError> {
        if self.bypassed {
            return Ok(ExtProcAction::Continue(ExtProcChanges::empty()));
        }
        self.send_phase(phase, head, body, trailers).await?;
        self.receive_phase(phase).await
    }

    /// 业务作用：按 Inference EPP 全双工合同连续发送 request headers 与 buffered body，
    /// 再按协议顺序接收两个响应，避免处理器等待完整调度输入时形成相位互锁。
    ///
    /// 参数说明：`head` 是完整请求头及其 EoS 事实；`body` 是有界收集后的实体，只有非 EoS
    /// 请求才会发送 body phase。
    ///
    /// 返回：返回 header 动作和可选 body 动作；错序、超时、越权 mutation 或非 EPP 计划均失败。
    pub(crate) async fn process_pipelined_request(
        &mut self,
        head: (&Method, &Uri, &HeaderMap, bool),
        body: &Bytes,
    ) -> Result<(ExtProcAction, Option<ExtProcAction>), ExtProcError> {
        if !self.plan.pipelines_buffered_request_body() {
            return Err(ExtProcError::protocol(anyhow::anyhow!(
                "ext_proc pipelined request is reserved for an inference endpoint picker"
            )));
        }
        if self.bypassed {
            return Ok((ExtProcAction::Continue(ExtProcChanges::empty()), None));
        }
        let end_of_stream = head.3;
        self.send_phase(ExtProcPhase::RequestHeaders, Some(head), None, None)
            .await?;
        if !end_of_stream {
            // EPP 只有取得完整模型请求后才能调度；先把有界 body 交付，再等待 header 决策，
            // 同时用标准 ProtocolConfiguration 明示该全双工顺序。
            self.send_phase(ExtProcPhase::RequestBody, None, Some((body, true)), None)
                .await?;
        }
        let headers = self.receive_phase(ExtProcPhase::RequestHeaders).await?;
        if matches!(headers, ExtProcAction::Immediate(_)) || end_of_stream {
            return Ok((headers, None));
        }
        let body = self.receive_phase(ExtProcPhase::RequestBody).await?;
        Ok((headers, Some(body)))
    }

    /// 业务作用：编码并发送单个 External Processing phase，统一首消息模式声明和累计发送预算。
    ///
    /// 参数说明：`phase` 与三类输入必须匹配，首条消息会携带冻结的 ProtocolConfiguration。
    ///
    /// 返回：消息在 deadline 内写入 HTTP/2 流时成功；编码、预算、连接或超时失败时分类返回。
    async fn send_phase(
        &mut self,
        phase: ExtProcPhase,
        head: Option<(&Method, &Uri, &HeaderMap, bool)>,
        body: Option<(&Bytes, bool)>,
        trailers: Option<&HeaderMap>,
    ) -> Result<(), ExtProcError> {
        if self.started.elapsed() >= self.plan.total_timeout() {
            return Err(ExtProcError::dependency(anyhow::anyhow!(
                "ext_proc total deadline exceeded"
            )));
        }
        let mut request = build_processing_request(phase, head, body, trailers, &self.metadata)?;
        if self.first_message {
            request.protocol_config = Some(protocol_configuration(&self.plan));
            self.first_message = false;
        }
        let encoded = encode_message(&request, self.plan.wire_limits().0)?;
        self.reserve_sent(encoded.len().saturating_add(5))?;
        let wire = self
            .wire
            .as_mut()
            .context("ext_proc wire is unavailable")
            .map_err(ExtProcError::dependency)?;
        let remaining = self
            .plan
            .total_timeout()
            .saturating_sub(self.started.elapsed());
        let deadline = self.plan.message_timeout().min(remaining);
        tokio::time::timeout(deadline, wire.send(encoded))
            .await
            .map_err(|_| ExtProcError::dependency(anyhow::anyhow!("ext_proc message timeout")))??;
        Ok(())
    }

    /// 业务作用：读取并提交当前预期 phase；普通处理器只接受一条响应，Inference EPP body
    /// 可按标准 `StreamedBodyResponse` 顺序返回多条分片，由此处在硬上限内合并后再原子交付。
    ///
    /// 参数说明：`phase` 是状态机当前唯一允许的响应类型。
    ///
    /// 返回：有效响应返回原子动作；超时、畸形、错序或越权响应分类失败。
    async fn receive_phase(&mut self, phase: ExtProcPhase) -> Result<ExtProcAction, ExtProcError> {
        let mut streamed_body = BytesMut::new();
        loop {
            let action = self.receive_single_phase(phase).await?;
            let ExtProcAction::Continue(mut changes) = action else {
                self.permit.record_success();
                return Ok(action);
            };
            let Some(end_of_stream) = changes.streamed_end_of_stream.take() else {
                self.permit.record_success();
                return Ok(ExtProcAction::Continue(changes));
            };
            let chunk = changes.body.take().unwrap_or_default();
            if streamed_body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|total| total > self.plan.max_body_bytes())
            {
                return Err(ExtProcError::protocol(anyhow::anyhow!(
                    "ext_proc streamed response exceeds max_body_bytes"
                )));
            }
            streamed_body.extend_from_slice(&chunk);
            if end_of_stream {
                changes.body = Some(streamed_body.freeze());
                self.permit.record_success();
                return Ok(ExtProcAction::Continue(changes));
            }
        }
    }

    /// 业务作用：读取并校验一个 phase 对应的单条处理器响应，供 EPP body 多响应聚合复用。
    ///
    /// 参数说明：`phase` 是当前唯一允许的响应 oneof 类型。
    ///
    /// 返回：返回尚未记入 circuit 的原子动作；调用方完成整组响应后统一记账。
    async fn receive_single_phase(
        &mut self,
        phase: ExtProcPhase,
    ) -> Result<ExtProcAction, ExtProcError> {
        if self.started.elapsed() >= self.plan.total_timeout() {
            return Err(ExtProcError::dependency(anyhow::anyhow!(
                "ext_proc total deadline exceeded"
            )));
        }
        let remaining = self
            .plan
            .total_timeout()
            .saturating_sub(self.started.elapsed());
        let deadline = self.plan.message_timeout().min(remaining);
        let wire = self
            .wire
            .as_mut()
            .context("ext_proc wire is unavailable")
            .map_err(ExtProcError::dependency)?;
        let (encoded, wire_bytes) =
            tokio::time::timeout(deadline, wire.receive(self.plan.wire_limits().0))
                .await
                .map_err(|_| {
                    ExtProcError::dependency(anyhow::anyhow!("ext_proc message timeout"))
                })??;
        self.reserve_received(wire_bytes)?;
        let mut response = ProcessingResponse::decode(encoded)
            .context("decode ext_proc ProcessingResponse")
            .map_err(ExtProcError::protocol)?;
        if response.mode_override.is_some()
            || response.override_message_timeout.is_some()
            || response.request_drain
        {
            return Err(ExtProcError::protocol(anyhow::anyhow!(
                "ext_proc returned a disabled protocol override"
            )));
        }
        self.apply_metadata(response.dynamic_metadata.take())?;
        validate_processing_response(&self.plan, phase, response)
    }

    /// 业务作用：正常完成最后一个配置相位后半关闭 request stream。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；不等待额外 ProcessingResponse，迟到或重复响应不会进入业务状态。
    pub(crate) fn finish(&mut self) {
        if let Some(wire) = self.wire.as_mut() {
            wire.close_send();
        }
    }

    /// 业务作用：保存 streamed request body 阶段的即时响应，交由主请求任务替换尚未发送的上游结果。
    ///
    /// 参数说明：`response` 已通过 status、header 权限和 body 上限复验。
    ///
    /// 返回：无返回值；后续重复即时响应按协议错序处理，不覆盖首个决定。
    pub(crate) fn set_pending_immediate(
        &mut self,
        response: Response<BoxBody>,
    ) -> Result<(), ExtProcError> {
        if self.pending_immediate.is_some() {
            return Err(ExtProcError::protocol(anyhow::anyhow!(
                "ext_proc returned more than one immediate response"
            )));
        }
        self.pending_immediate = Some(response);
        self.finish();
        Ok(())
    }

    /// 业务作用：在同步 request phase 已直接返回即时响应时终止后续 request/response phase。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；关闭发送方向并将会话标为不再访问处理器。
    pub(crate) fn finish_after_immediate(&mut self) {
        self.bypassed = true;
        self.finish();
    }

    /// 业务作用：由主请求任务一次性取得 streamed phase 已裁决的即时响应。
    ///
    /// 参数说明：无。
    ///
    /// 返回：存在时移动返回并清空槽位。
    pub(crate) fn take_pending_immediate(&mut self) -> Option<Response<BoxBody>> {
        self.pending_immediate.take()
    }

    /// 业务作用：导出当前请求已授权的动态 metadata，用于响应扩展和低敏观测消费者。
    ///
    /// 参数说明：无。
    ///
    /// 返回：共享会话内已验证 namespace 的克隆快照。
    pub(crate) fn metadata(&self) -> ExtProcMetadata {
        self.metadata.clone()
    }

    /// 业务作用：把网关实际选中的上游 endpoint 写入 EPP 可见的标准 `envoy.lb` metadata，
    /// 使响应阶段核对真实承载者，而不是复述请求阶段的建议目标。
    ///
    /// 参数说明：`endpoint` 是已经完成池成员校验并取得 reservation 的规范 authority。
    ///
    /// 返回：endpoint 长度在协议硬门内时写入并成功；异常长度返回 Input 错误且不发送响应相位。
    pub(crate) fn set_destination_endpoint_served(
        &mut self,
        endpoint: &str,
    ) -> Result<(), ExtProcError> {
        if endpoint.is_empty() || endpoint.len() > 512 {
            return Err(ExtProcError::input(anyhow::anyhow!(
                "served endpoint metadata has invalid length"
            )));
        }
        let namespace = self
            .metadata
            .namespaces
            .entry("envoy.lb".to_owned())
            .or_default();
        namespace.fields.insert(
            "x-gateway-destination-endpoint-served".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(endpoint.to_owned())),
            },
        );
        Ok(())
    }

    /// 业务作用：累计发往处理器的 wire 字节，阻止多相位请求绕过总传输预算。
    ///
    /// 参数说明：`bytes` 是本次完整 gRPC envelope 字节数。
    ///
    /// 返回：累计值仍在硬门内时成功；整数溢出或超限返回 Input 错误。
    fn reserve_sent(&mut self, bytes: usize) -> Result<(), ExtProcError> {
        self.sent_bytes = self
            .sent_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.plan.wire_limits().1)
            .ok_or_else(|| {
                ExtProcError::input(anyhow::anyhow!("ext_proc request wire budget exceeded"))
            })?;
        Ok(())
    }

    /// 业务作用：累计处理器响应 wire 字节，并与已发送字节共同执行整流预算。
    ///
    /// 参数说明：`bytes` 是本次完整 gRPC envelope 字节数。
    ///
    /// 返回：双向累计值仍在硬门内时成功；整数溢出或超限返回 Protocol 错误。
    fn reserve_received(&mut self, bytes: usize) -> Result<(), ExtProcError> {
        self.received_bytes = self
            .received_bytes
            .checked_add(bytes)
            .filter(|total| self.sent_bytes.saturating_add(*total) <= self.plan.wire_limits().1)
            .ok_or_else(|| {
                ExtProcError::protocol(anyhow::anyhow!("ext_proc total wire budget exceeded"))
            })?;
        Ok(())
    }

    /// 业务作用：只提交处理器获准写入的动态 metadata namespace，防止扩展伪造其它策略状态。
    ///
    /// 参数说明：`metadata` 是当前 ProcessingResponse 携带的结构化增量。
    ///
    /// 返回：全部 namespace 和值类型合法时原子并入会话；越权或类型错误返回 Protocol 错误。
    fn apply_metadata(
        &mut self,
        metadata: Option<prost_types::Struct>,
    ) -> Result<(), ExtProcError> {
        let Some(metadata) = metadata else {
            return Ok(());
        };
        for (namespace, value) in metadata.fields {
            if !self.plan.may_write_metadata(&namespace) {
                return Err(ExtProcError::protocol(anyhow::anyhow!(
                    "ext_proc attempted to write an unauthorized metadata namespace"
                )));
            }
            let prost_types::value::Kind::StructValue(value) = value
                .kind
                .context("ext_proc metadata namespace must contain a Struct")
                .map_err(ExtProcError::protocol)?
            else {
                return Err(ExtProcError::protocol(anyhow::anyhow!(
                    "ext_proc metadata namespace must contain a Struct"
                )));
            };
            self.metadata.namespaces.insert(namespace, value);
        }
        Ok(())
    }
}

#[cfg(feature = "ext-proc")]
impl ExtProcChanges {
    /// 业务作用：构造没有任何副作用的 continue 结果。
    ///
    /// 参数说明：无。
    ///
    /// 返回：空 delta。
    fn empty() -> Self {
        Self {
            header_set: Vec::new(),
            header_remove: Vec::new(),
            body: None,
            clear_body: false,
            streamed_end_of_stream: None,
        }
    }

    /// 业务作用：把已完整校验的 header delta 一次性交付，避免解析失败泄漏半套 mutation。
    ///
    /// 参数说明：`headers` 是当前请求或响应 head。
    ///
    /// 返回：无返回值；所有操作已在响应解析阶段通过权限和语法复验。
    pub(crate) fn apply_headers(&self, headers: &mut HeaderMap) {
        for name in &self.header_remove {
            headers.remove(name);
        }
        for (name, value, action) in &self.header_set {
            match action {
                HeaderAppendAction::AppendOrAdd => {
                    headers.append(name.clone(), value.clone());
                }
                HeaderAppendAction::AddIfAbsent if !headers.contains_key(name) => {
                    headers.insert(name.clone(), value.clone());
                }
                HeaderAppendAction::AddIfAbsent => {}
                HeaderAppendAction::OverwriteOrAdd => {
                    headers.insert(name.clone(), value.clone());
                }
                HeaderAppendAction::OverwriteIfExists if headers.contains_key(name) => {
                    headers.insert(name.clone(), value.clone());
                }
                HeaderAppendAction::OverwriteIfExists => {}
            }
        }
    }

    /// 业务作用：取得已验证的 body replacement 或 clear 指令。
    ///
    /// 参数说明：`original` 是当前 phase 的原始 body chunk。
    ///
    /// 返回：clear 返回空 Bytes，replace 返回处理器 bytes，无 mutation 复用原始 Bytes。
    pub(crate) fn apply_body(&self, original: Bytes) -> Bytes {
        if self.clear_body {
            Bytes::new()
        } else {
            self.body.clone().unwrap_or(original)
        }
    }

    /// 业务作用：判断当前 delta 是否已经接管原始实体。
    ///
    /// 参数说明：无。
    ///
    /// 返回：存在 replacement 或 clear 指令时返回 true。
    pub(crate) fn replaces_body(&self) -> bool {
        self.clear_body || self.body.is_some()
    }
}

impl ExtProcPermit {
    /// 业务作用：在处理器返回有效匹配响应后关闭半开态并清零连续失败。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；只更新本 route circuit 状态。
    pub(crate) fn record_success(&mut self) {
        let mut circuit = self.plan.circuit.lock();
        circuit.consecutive_failures = 0;
        circuit.open_until = None;
        circuit.probe_in_flight = false;
        self.recorded = true;
    }

    /// 业务作用：记录一次扩展依赖故障，并在阈值到达时阻止后续建流直到冷却结束。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；不会把协议拒绝或客户端输入计入可放行 circuit。
    pub(crate) fn record_dependency_failure(&mut self) {
        let mut circuit = self.plan.circuit.lock();
        circuit.probe_in_flight = false;
        circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
        if circuit.consecutive_failures >= self.plan.failure_threshold {
            circuit.open_until = Some(Instant::now() + self.plan.reset_timeout);
        }
        self.recorded = true;
    }
}

impl Drop for ExtProcPermit {
    /// 业务作用：确保取消、panic 展开或提前返回不会让 half-open 探测权威永久悬挂。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；并发槽由字段 Drop 自动归还。
    fn drop(&mut self) {
        if self.half_open_probe && !self.recorded {
            self.plan.circuit.lock().probe_in_flight = false;
        }
    }
}

/// 业务作用：验证 External Processing 目标只包含固定 origin 或命名 service，不接受动态 path/query。
///
/// 参数说明：`target` 是 route 配置的扩展服务目标。
///
/// 返回：成功返回去除尾斜杠的稳定目标；非法 scheme、userinfo、path、query 或 fragment 返回错误。
fn compile_target(target: &str) -> Result<String> {
    let target = target.trim().trim_end_matches('/');
    if let Some(service) = target.strip_prefix("lb://") {
        if service.is_empty()
            || service.len() > 253
            || !service
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            bail!("ext_proc lb target must contain a safe service name");
        }
        return Ok(target.to_owned());
    }
    let uri: Uri = target.parse().context("parse ext_proc target")?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        bail!(
            "ext_proc target must be an http(s) origin without userinfo, path, query or fragment"
        );
    }
    Ok(target.to_owned())
}

/// 业务作用：把 mutation header 字符串编译为唯一且无安全冻结项的权限集合。
///
/// 参数说明：`raw` 是 route 显式 allowlist。
///
/// 返回：全部名称合法且安全时返回集合；重复、越界或敏感头返回错误。
fn compile_headers(raw: &[String]) -> Result<HashSet<HeaderName>> {
    if raw.len() > MAX_MUTATION_HEADERS {
        bail!("mutation_headers exceeds {MAX_MUTATION_HEADERS} entries");
    }
    let mut names = HashSet::with_capacity(raw.len());
    for value in raw {
        let name = HeaderName::from_bytes(value.trim().as_bytes())
            .context("ext_proc mutation_headers contains an invalid name")?;
        if forbidden_mutation_header(&name) {
            bail!("ext_proc mutation_headers contains a security-frozen or framing header");
        }
        if !names.insert(name) {
            bail!("ext_proc mutation_headers contains a duplicate name");
        }
    }
    Ok(names)
}

/// 业务作用：冻结路由、身份、连接语义与实体 framing，避免处理器通过 header mutation 越权。
///
/// 参数说明：`name` 是已规范化的小写 HTTP header 名。
///
/// 返回：属于 hop-by-hop、伪头、身份凭据、目标或 framing 时返回 true。
fn forbidden_mutation_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with(':')
        || name.starts_with("x-forwarded-")
        || name.starts_with("x-naway-")
        || matches!(
            name,
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
                | "authorization"
                | "cookie"
                | "set-cookie"
                | "x-api-key"
                | "x-auth-token"
                | "x-client-cert-verified"
                | "x-user-id"
                | "x-consumer-id"
        )
}

/// 业务作用：暴露 External Processing Authorization SecretSource 的本地文件依赖，使配置热更新
/// 与当前 route 快照保持同一代。
///
/// 参数说明：`config_dir` 是主配置目录；`cfg` 提供可选认证来源。
///
/// 返回：文件型 SecretSource 返回规范依赖路径，其它来源返回 None。
pub(crate) fn dependency_path(config_dir: &Path, cfg: &ExtProcCfg) -> Option<std::path::PathBuf> {
    crate::secret::dependency_path(cfg.authorization.as_str(), config_dir)
}

#[cfg(feature = "ext-proc")]
/// 业务作用：把 HTTP phase 映射为 Envoy v3 `ProcessingRequest` 的唯一 oneof，并携带已授权 metadata。
///
/// 参数说明：`phase` 决定唯一 payload；`head`、`body`、`trailers` 必须与 phase 精确对应；
/// `metadata` 是前序响应积累的 namespace 快照。
///
/// 返回：输入组合正确时返回 protobuf 消息；调用错位或 header 编码失败返回 Input 错误。
fn build_processing_request(
    phase: ExtProcPhase,
    head: Option<(&Method, &Uri, &HeaderMap, bool)>,
    body: Option<(&Bytes, bool)>,
    trailers: Option<&HeaderMap>,
    metadata: &ExtProcMetadata,
) -> Result<ProcessingRequest, ExtProcError> {
    use processing_request::Request;
    let request = match phase {
        ExtProcPhase::RequestHeaders | ExtProcPhase::ResponseHeaders => {
            let (method, uri, headers, end_of_stream) = head
                .context("missing ext_proc head input")
                .map_err(ExtProcError::input)?;
            let headers = HttpHeaders {
                headers: Some(encode_header_map(
                    (phase == ExtProcPhase::RequestHeaders).then_some((method, uri)),
                    headers,
                )?),
                end_of_stream,
            };
            if phase == ExtProcPhase::RequestHeaders {
                Request::RequestHeaders(headers)
            } else {
                Request::ResponseHeaders(headers)
            }
        }
        ExtProcPhase::RequestBody | ExtProcPhase::ResponseBody => {
            let (body, end_of_stream) = body
                .context("missing ext_proc body input")
                .map_err(ExtProcError::input)?;
            let body = HttpBody {
                body: body.to_vec(),
                end_of_stream,
                end_of_stream_without_message: false,
                grpc_message_compressed: false,
            };
            if phase == ExtProcPhase::RequestBody {
                Request::RequestBody(body)
            } else {
                Request::ResponseBody(body)
            }
        }
        ExtProcPhase::RequestTrailers | ExtProcPhase::ResponseTrailers => {
            let trailers = HttpTrailers {
                trailers: Some(encode_header_map(
                    None,
                    trailers
                        .context("missing ext_proc trailers")
                        .map_err(ExtProcError::input)?,
                )?),
            };
            if phase == ExtProcPhase::RequestTrailers {
                Request::RequestTrailers(trailers)
            } else {
                Request::ResponseTrailers(trailers)
            }
        }
    };
    Ok(ProcessingRequest {
        request: Some(request),
        metadata_context: (!metadata.namespaces.is_empty()).then(|| Metadata {
            filter_metadata: metadata.namespaces.clone(),
        }),
        observability_mode: false,
        protocol_config: None,
    })
}

#[cfg(feature = "ext-proc")]
/// 业务作用：向处理器声明本 route 固定的 body 模式，禁止服务端自行扩大可见输入范围。
///
/// 参数说明：`plan` 是候选快照已验证的 phase 计划。
///
/// 返回：首条 ProcessingRequest 携带的标准 ProtocolConfiguration。
fn protocol_configuration(plan: &ExtProcPlan) -> ProtocolConfiguration {
    let (_, request_body, _, _, response_body, _) = plan.phases();
    ProtocolConfiguration {
        request_body_mode: match request_body {
            ExtProcBodyModeCfg::None => BodySendMode::None as i32,
            ExtProcBodyModeCfg::Buffered => BodySendMode::Buffered as i32,
            ExtProcBodyModeCfg::Streamed => BodySendMode::Streamed as i32,
        },
        response_body_mode: match response_body {
            ExtProcBodyModeCfg::None => BodySendMode::None as i32,
            ExtProcBodyModeCfg::Buffered => BodySendMode::Buffered as i32,
            ExtProcBodyModeCfg::Streamed => BodySendMode::Streamed as i32,
        },
        send_body_without_waiting_for_header_response: plan.inference_endpoint_picker,
    }
}

#[cfg(feature = "ext-proc")]
/// 业务作用：把 HTTP head 编码为 Envoy HeaderMap，并补齐标准 request 伪头供互操作处理器读取。
///
/// 参数说明：`request_line` 存在时提供 method/URI；`headers` 是当前业务 head。
///
/// 返回：所有值复制进单条 protobuf 消息；累计预算由外层编码后复验。
fn encode_header_map(
    request_line: Option<(&Method, &Uri)>,
    headers: &HeaderMap,
) -> Result<ProtoHeaderMap, ExtProcError> {
    let mut encoded = Vec::with_capacity(headers.len().saturating_add(4));
    if let Some((method, uri)) = request_line {
        encoded.push(raw_header(":method", method.as_str().as_bytes()));
        let path = uri
            .path_and_query()
            .map_or(uri.path(), |value| value.as_str());
        encoded.push(raw_header(":path", path.as_bytes()));
        if let Some(scheme) = uri.scheme_str() {
            encoded.push(raw_header(":scheme", scheme.as_bytes()));
        }
        if let Some(authority) = uri.authority() {
            encoded.push(raw_header(":authority", authority.as_str().as_bytes()));
        }
    }
    for (name, value) in headers {
        encoded.push(raw_header(name.as_str(), value.as_bytes()));
    }
    Ok(ProtoHeaderMap { headers: encoded })
}

#[cfg(feature = "ext-proc")]
/// 业务作用：以不损失非 UTF-8 值的 raw_value 形式编码标准 Envoy header。
///
/// 参数说明：`name` 是已验证名称；`value` 是 HTTP header 原始字节。
///
/// 返回：只设置一种值编码的 protobuf header。
fn raw_header(name: &str, value: &[u8]) -> ProtoHeaderValue {
    ProtoHeaderValue {
        key: name.to_owned(),
        value: String::new(),
        raw_value: value.to_vec(),
    }
}

#[cfg(feature = "ext-proc")]
/// 业务作用：验证 `ProcessingResponse` 的 oneof 与当前 phase 精确匹配，并编译全部 mutation。
///
/// 参数说明：`plan` 提供权限白名单；`phase` 是当前等待态；`response` 是唯一收到的消息。
///
/// 返回：匹配且全部 mutation 合法时返回原子动作；错序、空响应或越权行为返回 Protocol 错误。
fn validate_processing_response(
    plan: &ExtProcPlan,
    phase: ExtProcPhase,
    response: ProcessingResponse,
) -> Result<ExtProcAction, ExtProcError> {
    use processing_response::Response;
    match response
        .response
        .context("ext_proc response omitted response oneof")
        .map_err(ExtProcError::protocol)?
    {
        Response::ImmediateResponse(response)
            if matches!(
                phase,
                ExtProcPhase::RequestHeaders
                    | ExtProcPhase::RequestBody
                    | ExtProcPhase::RequestTrailers
            ) =>
        {
            validate_immediate_response(plan, response)
        }
        Response::RequestHeaders(response) if phase == ExtProcPhase::RequestHeaders => {
            validate_common_response(plan, phase, response.response)
        }
        Response::ResponseHeaders(response) if phase == ExtProcPhase::ResponseHeaders => {
            validate_common_response(plan, phase, response.response)
        }
        Response::RequestBody(response) if phase == ExtProcPhase::RequestBody => {
            validate_common_response(plan, phase, response.response)
        }
        Response::ResponseBody(response) if phase == ExtProcPhase::ResponseBody => {
            validate_common_response(plan, phase, response.response)
        }
        Response::RequestTrailers(response) if phase == ExtProcPhase::RequestTrailers => {
            Ok(ExtProcAction::Continue(validate_header_changes(
                plan,
                response.header_mutation,
                None,
                false,
            )?))
        }
        Response::ResponseTrailers(response) if phase == ExtProcPhase::ResponseTrailers => {
            Ok(ExtProcAction::Continue(validate_header_changes(
                plan,
                response.header_mutation,
                None,
                false,
            )?))
        }
        _ => Err(ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc response does not match the current processing phase"
        ))),
    }
}

#[cfg(feature = "ext-proc")]
/// 业务作用：校验通用 phase 响应并把允许的头部和实体变更编译成单次原子提交。
///
/// 参数说明：`plan` 提供权限与 body 模式；`phase` 固定当前状态；`response` 是处理器响应。
///
/// 返回：指令和 mutation 均合法时返回 Continue；不支持、错相位或越权行为返回 Protocol 错误。
fn validate_common_response(
    plan: &ExtProcPlan,
    phase: ExtProcPhase,
    response: Option<CommonResponse>,
) -> Result<ExtProcAction, ExtProcError> {
    let response = response.unwrap_or_default();
    if !matches!(response.status, 0 | 1)
        || response.clear_route_cache && !plan.inference_endpoint_picker
        || response.trailers.is_some()
    {
        return Err(ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc returned an unsupported common response directive"
        )));
    }
    let body_allowed = matches!(
        phase,
        ExtProcPhase::RequestBody | ExtProcPhase::ResponseBody
    ) || response.status == 1;
    let streamed_body = match phase {
        ExtProcPhase::RequestBody => plan.phases().1 == ExtProcBodyModeCfg::Streamed,
        ExtProcPhase::ResponseBody => plan.phases().4 == ExtProcBodyModeCfg::Streamed,
        _ => false,
    };
    if streamed_body
        && response.header_mutation.as_ref().is_some_and(|mutation| {
            !mutation.set_headers.is_empty() || !mutation.remove_headers.is_empty()
        })
    {
        return Err(ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc returned header mutation during STREAMED body processing"
        )));
    }
    let mut changes = validate_header_changes(
        plan,
        response.header_mutation,
        response.body_mutation,
        matches!(
            phase,
            ExtProcPhase::RequestBody | ExtProcPhase::ResponseBody
        ),
    )?;
    if !body_allowed && (changes.body.is_some() || changes.clear_body) {
        return Err(ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc returned body mutation for a non-replacing header phase"
        )));
    }
    if response.status == 1 && changes.body.is_none() && !changes.clear_body {
        // CONTINUE_AND_REPLACE 没有 body mutation 仍代表清空原实体。
        changes.clear_body = true;
    }
    Ok(ExtProcAction::Continue(changes))
}

#[cfg(feature = "ext-proc")]
/// 业务作用：复验处理器 header/body mutation 的权限、冲突、语法和资源上限。
///
/// 参数说明：`plan` 提供不可变 allowlist；`mutation` 与 `body_mutation` 是单 phase 增量；
/// `body_phase` 限定 streamed mutation 只能出现在实体相位。
///
/// 返回：全部操作合法时返回尚未提交的 delta；任一操作非法时不交付任何部分变更。
fn validate_header_changes(
    plan: &ExtProcPlan,
    mutation: Option<HeaderMutation>,
    body_mutation: Option<BodyMutation>,
    body_phase: bool,
) -> Result<ExtProcChanges, ExtProcError> {
    let mut changes = ExtProcChanges::empty();
    if let Some(mutation) = mutation {
        let mut touched = HashSet::new();
        for option in mutation.set_headers {
            let header = option
                .header
                .context("ext_proc set_headers omitted header")
                .map_err(ExtProcError::protocol)?;
            if plan.inference_endpoint_picker && header.key.starts_with(':') {
                // 标准 EPP 会回送原请求的 HTTP/2 pseudo-header；这些字段由网关路由状态机持有，
                // 忽略回显即可保持原值，不能把它们降格成普通 header 或交给处理器改写。
                continue;
            }
            let normalized_name = header.key.to_ascii_lowercase();
            let name = HeaderName::from_bytes(normalized_name.as_bytes())
                .context("ext_proc returned invalid header name")
                .map_err(ExtProcError::protocol)?;
            if plan.inference_endpoint_picker
                && forbidden_mutation_header(&name)
                && name != http::header::CONTENT_LENGTH
            {
                // EPP 契约会回送全部非 EPP-system-owned 请求头；网关静默保留原始冻结值，
                // 防止 hop-by-hop、身份或凭据字段因回显而中断请求，也不授予其 mutation 权限。
                continue;
            }
            let duplicate = !touched.insert(name.clone());
            if duplicate && plan.inference_endpoint_picker {
                // Trace propagator 先写新上下文，随后 EPP 可能回送同名旧请求头；保留首项可确保
                // 新 span 权威不被旧值覆盖，同时保持单一确定的下游 header。
                continue;
            }
            if !plan.may_mutate_header(&name) || duplicate {
                return Err(ExtProcError::protocol(anyhow::anyhow!(
                    "ext_proc attempted an unauthorized or duplicate header mutation: {name}"
                )));
            }
            let raw = match (header.value.is_empty(), header.raw_value.is_empty()) {
                (false, true) => header.value.into_bytes(),
                (true, _) => header.raw_value,
                (false, false) => {
                    return Err(ExtProcError::protocol(anyhow::anyhow!(
                        "ext_proc header set both value encodings"
                    )))
                }
            };
            if raw.is_empty() && !option.keep_empty_value {
                continue;
            }
            let mut value = HeaderValue::from_bytes(&raw)
                .context("ext_proc returned invalid header value")
                .map_err(ExtProcError::protocol)?;
            value
                .set_sensitive(name == http::header::AUTHORIZATION || name == http::header::COOKIE);
            let action = match option.append_action {
                0 if option.append.as_ref().is_some_and(|value| value.value) => {
                    HeaderAppendAction::AppendOrAdd
                }
                0 => HeaderAppendAction::OverwriteOrAdd,
                1 => HeaderAppendAction::AddIfAbsent,
                2 => HeaderAppendAction::OverwriteOrAdd,
                3 => HeaderAppendAction::OverwriteIfExists,
                _ => {
                    return Err(ExtProcError::protocol(anyhow::anyhow!(
                        "ext_proc returned unknown header append action"
                    )))
                }
            };
            changes.header_set.push((name, value, action));
        }
        for raw in mutation.remove_headers {
            if plan.inference_endpoint_picker && raw.starts_with(':') {
                continue;
            }
            let normalized_name = raw.to_ascii_lowercase();
            let name = HeaderName::from_bytes(normalized_name.as_bytes())
                .context("ext_proc returned invalid remove header name")
                .map_err(ExtProcError::protocol)?;
            if plan.inference_endpoint_picker && forbidden_mutation_header(&name) {
                continue;
            }
            if !plan.may_mutate_header(&name) || !touched.insert(name.clone()) {
                return Err(ExtProcError::protocol(anyhow::anyhow!(
                    "ext_proc attempted an unauthorized or conflicting header removal"
                )));
            }
            changes.header_remove.push(name);
        }
    }
    if let Some(body_mutation) = body_mutation {
        match body_mutation.mutation {
            Some(body_mutation::Mutation::Body(body)) => changes.body = Some(Bytes::from(body)),
            Some(body_mutation::Mutation::ClearBody(true)) => changes.clear_body = true,
            Some(body_mutation::Mutation::ClearBody(false)) | None => {}
            Some(body_mutation::Mutation::StreamedResponse(streamed))
                if plan.inference_endpoint_picker
                    && body_phase
                    && !streamed.grpc_message_compressed
                    && !streamed.end_of_stream_without_message =>
            {
                changes.body = Some(Bytes::from(streamed.body));
                changes.streamed_end_of_stream = Some(streamed.end_of_stream);
            }
            Some(body_mutation::Mutation::StreamedResponse(_)) => {
                return Err(ExtProcError::protocol(anyhow::anyhow!(
                    "ext_proc returned an unsupported streamed body response"
                )))
            }
        }
        if changes
            .body
            .as_ref()
            .is_some_and(|body| body.len() > plan.max_body_bytes())
        {
            return Err(ExtProcError::protocol(anyhow::anyhow!(
                "ext_proc body mutation exceeds max_body_bytes"
            )));
        }
    }
    Ok(changes)
}

#[cfg(feature = "ext-proc")]
/// 业务作用：把 request phase 的 ImmediateResponse 转为有界本地响应并执行同一 mutation 门禁。
///
/// 参数说明：`plan` 提供权限和实体预算；`response` 是处理器要求立即返回的响应。
///
/// 返回：状态、头和 body 全部合法时返回 Immediate；否则返回 Protocol 错误。
fn validate_immediate_response(
    plan: &ExtProcPlan,
    response: ImmediateResponse,
) -> Result<ExtProcAction, ExtProcError> {
    let code = response
        .status
        .context("ext_proc immediate response omitted status")
        .map_err(ExtProcError::protocol)?
        .code;
    let status = StatusCode::from_u16(u16::try_from(code).unwrap_or_default())
        .context("ext_proc immediate response returned invalid status")
        .map_err(ExtProcError::protocol)?;
    if response.body.len() > plan.max_body_bytes() {
        return Err(ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc immediate response body exceeds max_body_bytes"
        )));
    }
    let changes = validate_header_changes(plan, response.headers, None, false)?;
    let mut result = Response::new(full_body(Bytes::from(response.body)));
    *result.status_mut() = status;
    changes.apply_headers(result.headers_mut());
    result.headers_mut().remove(http::header::CONTENT_LENGTH);
    if !result.headers().contains_key(http::header::CONTENT_TYPE) {
        result.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    Ok(ExtProcAction::Immediate(result))
}

#[cfg(feature = "ext-proc")]
/// 业务作用：在分配 protobuf 缓冲区前执行单消息上限，防止扩展输入制造无界内存增长。
///
/// 参数说明：`message` 是待编码请求；`max_message_bytes` 是 route 硬门。
///
/// 返回：编码成功返回 protobuf bytes；预测或实际编码失败返回 Input 错误。
fn encode_message<M: Message>(
    message: &M,
    max_message_bytes: usize,
) -> Result<Bytes, ExtProcError> {
    let length = message.encoded_len();
    if length > max_message_bytes || length > u32::MAX as usize {
        return Err(ExtProcError::input(anyhow::anyhow!(
            "ext_proc request exceeds max_message_bytes"
        )));
    }
    let mut encoded = Vec::with_capacity(length);
    message
        .encode(&mut encoded)
        .context("encode ext_proc ProcessingRequest")
        .map_err(ExtProcError::input)?;
    Ok(Bytes::from(encoded))
}

#[cfg(feature = "ext-proc")]
/// 业务作用：为未压缩 protobuf 消息添加标准五字节 gRPC envelope。
///
/// 参数说明：`message` 是 protobuf payload。
///
/// 返回：长度可由 u32 表示时返回完整 DATA payload；否则返回 Input 错误。
fn encode_grpc_frame(message: Bytes) -> Result<Bytes, ExtProcError> {
    let length = u32::try_from(message.len())
        .context("ext_proc protobuf message exceeds gRPC framing")
        .map_err(ExtProcError::input)?;
    let mut frame = BytesMut::with_capacity(message.len() + 5);
    frame.extend_from_slice(&[0]);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&message);
    Ok(frame.freeze())
}

#[cfg(feature = "ext-proc")]
/// 业务作用：严格解析 gRPC 最终状态，避免缺失或畸形状态被当作成功流。
///
/// 参数说明：`headers` 是 HTTP response initial headers 或 trailers。
///
/// 返回：合法十进制状态码；缺失、非 ASCII 或非数字返回 Protocol 错误。
pub(crate) fn parse_grpc_status(headers: &HeaderMap) -> Result<u32, ExtProcError> {
    headers
        .get("grpc-status")
        .context("ext_proc gRPC trailers omitted grpc-status")
        .and_then(|value| value.to_str().context("ext_proc grpc-status is not ASCII"))
        .and_then(|value| {
            value
                .parse::<u32>()
                .context("ext_proc grpc-status is not numeric")
        })
        .map_err(ExtProcError::protocol)
}

#[cfg(feature = "ext-proc")]
/// 业务作用：按 gRPC 语义区分处理器明确拒绝/协议错误与可选依赖故障。
///
/// 参数说明：`status` 是最终码；`empty_buffer` 表示没有残缺 envelope。
///
/// 返回：可供 fail_open 门准确决策的分类错误。
pub(crate) fn classify_grpc_status(status: u32, empty_buffer: bool) -> ExtProcError {
    if !empty_buffer {
        return ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc gRPC stream ended with a truncated response"
        ));
    }
    match status {
        0 => ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc gRPC stream ended successfully before the required response"
        )),
        7 | 16 => ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc explicitly denied processor authorization"
        )),
        1 | 3 | 5 | 6 | 9 | 11 | 12 => ExtProcError::protocol(anyhow::anyhow!(
            "ext_proc returned protocol gRPC status {status}"
        )),
        _ => ExtProcError::dependency(anyhow::anyhow!(
            "ext_proc stream ended before the required response with gRPC status {status}"
        )),
    }
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProcessingRequest {
    #[prost(oneof = "processing_request::Request", tags = "2, 3, 4, 5, 6, 7")]
    request: Option<processing_request::Request>,
    #[prost(message, optional, tag = "8")]
    metadata_context: Option<Metadata>,
    #[prost(bool, tag = "10")]
    observability_mode: bool,
    #[prost(message, optional, tag = "11")]
    protocol_config: Option<ProtocolConfiguration>,
}

#[cfg(feature = "ext-proc")]
#[allow(clippy::enum_variant_names)]
mod processing_request {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Request {
        #[prost(message, tag = "2")]
        RequestHeaders(super::HttpHeaders),
        #[prost(message, tag = "3")]
        ResponseHeaders(super::HttpHeaders),
        #[prost(message, tag = "4")]
        RequestBody(super::HttpBody),
        #[prost(message, tag = "5")]
        ResponseBody(super::HttpBody),
        #[prost(message, tag = "6")]
        RequestTrailers(super::HttpTrailers),
        #[prost(message, tag = "7")]
        ResponseTrailers(super::HttpTrailers),
    }
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProcessingResponse {
    #[prost(oneof = "processing_response::Response", tags = "1, 2, 3, 4, 5, 6, 7")]
    response: Option<processing_response::Response>,
    #[prost(message, optional, tag = "8")]
    dynamic_metadata: Option<prost_types::Struct>,
    #[prost(message, optional, tag = "9")]
    mode_override: Option<ProcessingMode>,
    #[prost(message, optional, tag = "10")]
    override_message_timeout: Option<prost_types::Duration>,
    #[prost(bool, tag = "12")]
    request_drain: bool,
}

#[cfg(feature = "ext-proc")]
#[allow(clippy::enum_variant_names)]
mod processing_response {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Response {
        #[prost(message, tag = "1")]
        RequestHeaders(super::HeadersResponse),
        #[prost(message, tag = "2")]
        ResponseHeaders(super::HeadersResponse),
        #[prost(message, tag = "3")]
        RequestBody(super::BodyResponse),
        #[prost(message, tag = "4")]
        ResponseBody(super::BodyResponse),
        #[prost(message, tag = "5")]
        RequestTrailers(super::TrailersResponse),
        #[prost(message, tag = "6")]
        ResponseTrailers(super::TrailersResponse),
        #[prost(message, tag = "7")]
        ImmediateResponse(super::ImmediateResponse),
    }
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProtocolConfiguration {
    #[prost(enumeration = "BodySendMode", tag = "1")]
    request_body_mode: i32,
    #[prost(enumeration = "BodySendMode", tag = "2")]
    response_body_mode: i32,
    #[prost(bool, tag = "3")]
    send_body_without_waiting_for_header_response: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
enum BodySendMode {
    None = 0,
    Streamed = 1,
    Buffered = 2,
    BufferedPartial = 3,
    FullDuplexStreamed = 4,
    Grpc = 5,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProcessingMode {
    #[prost(int32, tag = "1")]
    request_header_mode: i32,
    #[prost(int32, tag = "2")]
    response_header_mode: i32,
    #[prost(int32, tag = "3")]
    request_body_mode: i32,
    #[prost(int32, tag = "4")]
    response_body_mode: i32,
    #[prost(int32, tag = "5")]
    request_trailer_mode: i32,
    #[prost(int32, tag = "6")]
    response_trailer_mode: i32,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct Metadata {
    #[prost(map = "string, message", tag = "1")]
    filter_metadata: std::collections::HashMap<String, prost_types::Struct>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct HttpHeaders {
    #[prost(message, optional, tag = "1")]
    headers: Option<ProtoHeaderMap>,
    #[prost(bool, tag = "3")]
    end_of_stream: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct HttpBody {
    #[prost(bytes = "vec", tag = "1")]
    body: Vec<u8>,
    #[prost(bool, tag = "2")]
    end_of_stream: bool,
    #[prost(bool, tag = "3")]
    end_of_stream_without_message: bool,
    #[prost(bool, tag = "4")]
    grpc_message_compressed: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct HttpTrailers {
    #[prost(message, optional, tag = "1")]
    trailers: Option<ProtoHeaderMap>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProtoHeaderMap {
    #[prost(message, repeated, tag = "1")]
    headers: Vec<ProtoHeaderValue>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProtoHeaderValue {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(bytes = "vec", tag = "3")]
    raw_value: Vec<u8>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ProtoHeaderValueOption {
    #[prost(message, optional, tag = "1")]
    header: Option<ProtoHeaderValue>,
    #[prost(message, optional, tag = "2")]
    append: Option<BoolValue>,
    #[prost(int32, tag = "3")]
    append_action: i32,
    #[prost(bool, tag = "4")]
    keep_empty_value: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct BoolValue {
    #[prost(bool, tag = "1")]
    value: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct HeadersResponse {
    #[prost(message, optional, tag = "1")]
    response: Option<CommonResponse>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct BodyResponse {
    #[prost(message, optional, tag = "1")]
    response: Option<CommonResponse>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct TrailersResponse {
    #[prost(message, optional, tag = "1")]
    header_mutation: Option<HeaderMutation>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct CommonResponse {
    #[prost(int32, tag = "1")]
    status: i32,
    #[prost(message, optional, tag = "2")]
    header_mutation: Option<HeaderMutation>,
    #[prost(message, optional, tag = "3")]
    body_mutation: Option<BodyMutation>,
    #[prost(message, optional, tag = "4")]
    trailers: Option<ProtoHeaderMap>,
    #[prost(bool, tag = "5")]
    clear_route_cache: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct HeaderMutation {
    #[prost(message, repeated, tag = "1")]
    set_headers: Vec<ProtoHeaderValueOption>,
    #[prost(string, repeated, tag = "2")]
    remove_headers: Vec<String>,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct BodyMutation {
    #[prost(oneof = "body_mutation::Mutation", tags = "1, 2, 3")]
    mutation: Option<body_mutation::Mutation>,
}

#[cfg(feature = "ext-proc")]
mod body_mutation {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Mutation {
        #[prost(bytes, tag = "1")]
        Body(Vec<u8>),
        #[prost(bool, tag = "2")]
        ClearBody(bool),
        #[prost(message, tag = "3")]
        StreamedResponse(super::StreamedBodyResponse),
    }
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct StreamedBodyResponse {
    #[prost(bytes = "vec", tag = "1")]
    body: Vec<u8>,
    #[prost(bool, tag = "2")]
    end_of_stream: bool,
    #[prost(bool, tag = "3")]
    end_of_stream_without_message: bool,
    #[prost(bool, tag = "4")]
    grpc_message_compressed: bool,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct ImmediateResponse {
    #[prost(message, optional, tag = "1")]
    status: Option<HttpStatus>,
    #[prost(message, optional, tag = "2")]
    headers: Option<HeaderMutation>,
    #[prost(bytes = "vec", tag = "3")]
    body: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    grpc_status: Option<GrpcStatus>,
    #[prost(string, tag = "5")]
    details: String,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct HttpStatus {
    #[prost(int32, tag = "1")]
    code: i32,
}

#[cfg(feature = "ext-proc")]
#[derive(Clone, PartialEq, Message)]
struct GrpcStatus {
    #[prost(uint32, tag = "1")]
    status: u32,
}
