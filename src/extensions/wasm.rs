//! Proxy-Wasm ABI v0.2.1 HTTP 插件运行时。
//!
//! 这个模块故意不提供 WASI：客体没有文件、环境变量、随机数或 socket 能力，
//! 只能通过明确白名单的 `env.proxy_*` ABI 与数据面交互。header phase 保持流式；只有
//! route 显式配置 request/response body phase 时才在 `max_body_bytes` 内聚合。客体指令
//! 在 blocking pool 执行，PAUSE 由 Tokio timer 驱动 `proxy_on_tick`，并共享单一墙钟
//! deadline。客体成功才原子交付整份 head/body，trap/fuel/epoch/内存/超时不会把半套
//! 变更泄漏给后续管线。

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use bytes::Bytes;
use ed25519_dalek::{Signature, VerifyingKey};
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasmtime::{
    Caller, Engine, Extern, ExternType, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

use crate::config::model::{
    WasmAttestationCfg, WasmModuleSourceCfg, WasmPluginCfg, WasmPluginPhaseCfg,
};
use crate::{full_body, BoxBody};

const PROXY_STATUS_OK: i32 = 0;
const PROXY_STATUS_NOT_FOUND: i32 = 1;
const PROXY_STATUS_BAD_ARGUMENT: i32 = 2;
const PROXY_STATUS_INVALID_MEMORY_ACCESS: i32 = 6;
const PROXY_STATUS_EMPTY: i32 = 7;
const PROXY_STATUS_CAS_MISMATCH: i32 = 8;
const PROXY_STATUS_INTERNAL_FAILURE: i32 = 10;
const PROXY_STATUS_UNIMPLEMENTED: i32 = 12;
const PROXY_ACTION_CONTINUE: i32 = 0;
const PROXY_ACTION_PAUSE: i32 = 1;
const MAP_REQUEST_HEADERS: i32 = 0;
const MAP_RESPONSE_HEADERS: i32 = 2;
const MAP_GRPC_RECEIVE_INITIAL_METADATA: i32 = 4;
const MAP_GRPC_RECEIVE_TRAILING_METADATA: i32 = 5;
const MAP_HTTP_CALLOUT_RESPONSE_HEADERS: i32 = 6;
const MAP_HTTP_CALLOUT_RESPONSE_TRAILERS: i32 = 7;
const BUFFER_HTTP_REQUEST_BODY: i32 = 0;
const BUFFER_HTTP_RESPONSE_BODY: i32 = 1;
const BUFFER_HTTP_CALLOUT_RESPONSE_BODY: i32 = 4;
const BUFFER_GRPC_RECEIVE: i32 = 5;
const BUFFER_VM_CONFIGURATION: i32 = 6;
const BUFFER_PLUGIN_CONFIGURATION: i32 = 7;

const MAX_PLUGIN_ID_BYTES: usize = 128;
const MAX_PLUGIN_CONFIG_BYTES: usize = 64 * 1024;
const MAX_MODULE_BYTES_HARD: usize = 64 * 1024 * 1024;
const MAX_MEMORY_BYTES_HARD: usize = 256 * 1024 * 1024;
const MAX_HEADER_BYTES_HARD: usize = 1024 * 1024;
const MAX_BODY_BYTES_HARD: usize = 16 * 1024 * 1024;
const MAX_LOCAL_RESPONSE_BODY_BYTES_HARD: usize = 1024 * 1024;
const MAX_MUTATIONS_HARD: usize = 1024;
const MAX_FUEL_HARD: u64 = 1_000_000_000;
const MAX_TIMEOUT_MS: u64 = 1_000;
const EPOCH_TICK_MS: u64 = 1;
const MAX_PLUGINS_PER_ROUTE: usize = 16;
const MAX_CALLOUT_CLUSTERS: usize = 32;
const MAX_CALLOUTS_HARD: usize = 32;
const MAX_SHARED_ENTRIES_HARD: usize = 65_536;
const MAX_SHARED_BYTES_HARD: usize = 64 * 1024 * 1024;
const MAX_SHARED_QUEUES_HARD: usize = 4096;
const MAX_QUEUE_ENTRIES_HARD: usize = 65_536;
const MAX_METRICS_HARD: usize = 4096;
const MAX_SHARED_KEY_BYTES: usize = 1024;
const MAX_METRIC_NAME_BYTES: usize = 256;
const MAX_WASM_SOURCE_REFERENCE_BYTES: usize = 4096;
const MAX_OCI_MANIFEST_BYTES: usize = 1024 * 1024;

static WASM_ENGINE: OnceLock<std::result::Result<Engine, String>> = OnceLock::new();
static WASM_CACHE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// 一条 route 的 Proxy-Wasm HTTP 链。相位已在构建期分组，数据面不每请求过滤枚举。
pub(crate) struct WasmPluginChain {
    request_headers: Arc<[Arc<WasmPlugin>]>,
    request_body: Arc<[Arc<WasmPlugin>]>,
    request_body_stream: Arc<[Arc<WasmPlugin>]>,
    response_headers: Arc<[Arc<WasmPlugin>]>,
    response_body: Arc<[Arc<WasmPlugin>]>,
    response_body_stream: Arc<[Arc<WasmPlugin>]>,
}

/// 响应回调需要的请求 head 快照。只有 route 显式声明 response plugin 时才创建；
/// `HeaderMap::clone` 共享 `HeaderValue` 字节，不复制请求 body。
#[derive(Clone)]
pub(crate) struct WasmRequestHeadSnapshot {
    headers: HeaderMap,
    method: String,
    path: String,
    authority: String,
    scheme: String,
}

/// 一条 phase 链的交付结果。`failed_open` 按插件计数，便于用低基数指标
/// 区分“全部成功 continue”与“跳过了失败插件仍 continue”。
pub(crate) struct WasmExecution {
    pub(crate) local_response: Option<Response<BoxBody>>,
    pub(crate) failed_open: u64,
    pub(crate) body: Option<Bytes>,
}

impl WasmPluginChain {
    /// 业务作用：构建、编译并验证 route 的全部 wasm 模块，按 HTTP phase 固化执行顺序。
    ///
    /// 参数说明：`cfgs` 是 route 插件声明，`config_dir` 解析模块文件，`route_id` 用于错误归因。
    ///
    /// 返回：全部模块与资源门有效时返回不可变链；任一失败则候选快照整体不上线。
    pub(crate) fn build(cfgs: &[WasmPluginCfg], config_dir: &Path, route_id: &str) -> Result<Self> {
        if cfgs.len() > MAX_PLUGINS_PER_ROUTE {
            bail!("route `{route_id}` supports at most {MAX_PLUGINS_PER_ROUTE} wasm plugins");
        }
        let mut ids = std::collections::HashSet::with_capacity(cfgs.len());
        let mut request_headers = Vec::new();
        let mut request_body = Vec::new();
        let mut request_body_stream = Vec::new();
        let mut response_headers = Vec::new();
        let mut response_body = Vec::new();
        let mut response_body_stream = Vec::new();
        for cfg in cfgs {
            if !ids.insert(cfg.id.as_str()) {
                bail!(
                    "route `{route_id}` contains duplicate wasm plugin id `{}`",
                    cfg.id
                );
            }
            let plugin = Arc::new(
                WasmPlugin::build(cfg, config_dir, route_id)
                    .with_context(|| format!("route `{route_id}` wasm plugin `{}`", cfg.id))?,
            );
            match cfg.phase {
                WasmPluginPhaseCfg::RequestHeaders => request_headers.push(plugin),
                WasmPluginPhaseCfg::RequestBody => request_body.push(plugin),
                WasmPluginPhaseCfg::RequestBodyStream => request_body_stream.push(plugin),
                WasmPluginPhaseCfg::ResponseHeaders => response_headers.push(plugin),
                WasmPluginPhaseCfg::ResponseBody => response_body.push(plugin),
                WasmPluginPhaseCfg::ResponseBodyStream => response_body_stream.push(plugin),
            }
        }
        if !request_body.is_empty() && !request_body_stream.is_empty() {
            bail!("route `{route_id}` cannot combine request_body and request_body_stream phases");
        }
        if !response_body.is_empty() && !response_body_stream.is_empty() {
            bail!(
                "route `{route_id}` cannot combine response_body and response_body_stream phases"
            );
        }
        Ok(Self {
            request_headers: request_headers.into(),
            request_body: request_body.into(),
            request_body_stream: request_body_stream.into(),
            response_headers: response_headers.into(),
            response_body: response_body.into(),
            response_body_stream: response_body_stream.into(),
        })
    }

    /// 业务作用：判断 route 是否需要保留请求 head，供响应头插件读取可信请求上下文。
    ///
    /// 参数说明：无。
    ///
    /// 返回：存在至少一个 `response_headers` 插件时返回 `true`。
    pub(crate) fn has_response_headers(&self) -> bool {
        !self.response_headers.is_empty()
    }

    /// 业务作用：判断 route 是否显式选择请求 body 聚合慢路径。
    ///
    /// 参数说明：无。
    ///
    /// 返回：存在至少一个 `request_body` 插件时返回 `true`。
    pub(crate) fn has_request_body(&self) -> bool {
        !self.request_body.is_empty()
    }

    /// 业务作用：判断 route 是否启用逐 frame 请求 body 插件，以便代理安装背压 wrapper。
    ///
    /// 参数说明：无。
    ///
    /// 返回：至少一个 `request_body_stream` 插件时返回 `true`。
    pub(crate) fn has_request_body_stream(&self) -> bool {
        !self.request_body_stream.is_empty()
    }

    /// 业务作用：判断 route 是否显式选择响应 body 聚合慢路径。
    ///
    /// 参数说明：无。
    ///
    /// 返回：存在至少一个 `response_body` 插件时返回 `true`。
    pub(crate) fn has_response_body(&self) -> bool {
        !self.response_body.is_empty()
    }

    /// 业务作用：判断 route 是否启用逐 frame 响应 body 插件，以便代理保持长流而不聚合。
    ///
    /// 参数说明：无。
    ///
    /// 返回：至少一个 `response_body_stream` 插件时返回 `true`。
    pub(crate) fn has_response_body_stream(&self) -> bool {
        !self.response_body_stream.is_empty()
    }

    /// 业务作用：给请求 body 收集器提供本链最大显式上限，保证聚合在分配前有硬门。
    ///
    /// 参数说明：无。
    ///
    /// 返回：请求 body 插件中的最大上限；无插件返回 0。
    pub(crate) fn request_body_limit(&self) -> usize {
        self.request_body
            .iter()
            .map(|plugin| plugin.limits.max_body_bytes)
            .max()
            .unwrap_or(0)
    }

    /// 业务作用：给响应 body 收集器提供本链最大显式上限，保证聚合在分配前有硬门。
    ///
    /// 参数说明：无。
    ///
    /// 返回：响应 body 插件中的最大上限；无插件返回 0。
    pub(crate) fn response_body_limit(&self) -> usize {
        self.response_body
            .iter()
            .map(|plugin| plugin.limits.max_body_bytes)
            .max()
            .unwrap_or(0)
    }

    /// 业务作用：在请求治理链执行 Proxy-Wasm 请求头 phase，并仅提交完整成功的 header 变更。
    ///
    /// 参数说明：`parts` 是当前请求 head，`scheme` 是可信入口协议，`end_of_stream` 标识无后续 body。
    ///
    /// 返回：继续、local response 或 fail-closed 错误；JIT 指令不会阻塞 Tokio I/O worker。
    pub(crate) async fn execute_request(
        &self,
        parts: &mut Parts,
        scheme: &str,
        end_of_stream: bool,
    ) -> Result<WasmExecution> {
        if self.request_headers.is_empty() {
            return Ok(WasmExecution {
                local_response: None,
                failed_open: 0,
                body: None,
            });
        }
        let plugins = self.request_headers.clone();
        let input = PhaseInput {
            phase: WasmPhase::RequestHeaders,
            current_headers: parts.headers.clone(),
            request_headers: None,
            method: parts.method.as_str().to_owned(),
            path: parts
                .uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/")
                .to_owned(),
            authority: parts
                .uri
                .authority()
                .map(|value| value.as_str())
                .or_else(|| parts.headers.get(http::header::HOST)?.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
            scheme: scheme.to_owned(),
            end_of_stream,
            body: None,
        };
        let outcome = execute_chain(&plugins, input).await?;
        match outcome.outcome {
            ChainOutcome::Continue(output) => {
                parts.headers = output.headers;
                Ok(WasmExecution {
                    local_response: None,
                    failed_open: outcome.failed_open,
                    body: output.body,
                })
            }
            ChainOutcome::Local(response) => Ok(WasmExecution {
                local_response: Some(response.into_http()?),
                failed_open: outcome.failed_open,
                body: None,
            }),
        }
    }

    /// 业务作用：在请求插件全部提交后捕获 response phase 可读的请求 head 快照。
    ///
    /// 参数说明：`parts` 是最终上游请求 head，`scheme` 是可信入口协议。
    ///
    /// 返回：有 response header/body 插件时返回共享底层字节的有界快照，否则不复制。
    pub(crate) fn capture_request_head(
        &self,
        parts: &Parts,
        scheme: &str,
    ) -> Option<WasmRequestHeadSnapshot> {
        (self.has_response_headers() || self.has_response_body() || self.has_response_body_stream())
            .then(|| WasmRequestHeadSnapshot {
                headers: parts.headers.clone(),
                method: parts.method.as_str().to_owned(),
                path: parts
                    .uri
                    .path_and_query()
                    .map(|value| value.as_str())
                    .unwrap_or("/")
                    .to_owned(),
                authority: parts
                    .uri
                    .authority()
                    .map(|value| value.as_str())
                    .or_else(|| parts.headers.get(http::header::HOST)?.to_str().ok())
                    .unwrap_or_default()
                    .to_owned(),
                scheme: scheme.to_owned(),
            })
    }

    /// 业务作用：执行响应头链，并只原子交付完成全部插件后的 response head。
    ///
    /// 参数说明：`response` 是当前响应，`request` 是上游请求发出前的有界只读快照，
    /// `end_of_stream` 标识响应没有后续 body。
    ///
    /// 返回：继续、local response 或 fail-closed 错误；此 phase 不 clone response body。
    pub(crate) async fn execute_response(
        &self,
        response: &mut Response<BoxBody>,
        request: WasmRequestHeadSnapshot,
        end_of_stream: bool,
    ) -> Result<WasmExecution> {
        if self.response_headers.is_empty() {
            return Ok(WasmExecution {
                local_response: None,
                failed_open: 0,
                body: None,
            });
        }
        let plugins = self.response_headers.clone();
        let input = PhaseInput {
            phase: WasmPhase::ResponseHeaders,
            current_headers: response.headers().clone(),
            request_headers: Some(request.headers),
            method: request.method,
            path: request.path,
            authority: request.authority,
            scheme: request.scheme,
            end_of_stream,
            body: None,
        };
        let outcome = execute_chain(&plugins, input).await?;
        match outcome.outcome {
            ChainOutcome::Continue(output) => {
                *response.headers_mut() = output.headers;
                Ok(WasmExecution {
                    local_response: None,
                    failed_open: outcome.failed_open,
                    body: output.body,
                })
            }
            ChainOutcome::Local(response) => Ok(WasmExecution {
                local_response: Some(response.into_http()?),
                failed_open: outcome.failed_open,
                body: None,
            }),
        }
    }

    /// 业务作用：在上游转发前执行完整请求 body 链，并原子提交 header/body 变更。
    ///
    /// 参数说明：`parts` 是已通过请求头插件的 head，`body` 已按 `request_body_limit` 有界聚合，
    /// `scheme` 是可信入口协议。
    ///
    /// 返回：继续时返回新 body；local response 或 fail-closed 错误阻止上游请求。
    pub(crate) async fn execute_request_body(
        &self,
        parts: &mut Parts,
        body: Bytes,
        scheme: &str,
    ) -> Result<WasmExecution> {
        if self.request_body.is_empty() {
            return Ok(WasmExecution {
                local_response: None,
                failed_open: 0,
                body: Some(body),
            });
        }
        let input = PhaseInput {
            phase: WasmPhase::RequestBody,
            current_headers: parts.headers.clone(),
            request_headers: None,
            method: parts.method.as_str().to_owned(),
            path: parts
                .uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/")
                .to_owned(),
            authority: parts
                .uri
                .authority()
                .map(|value| value.as_str())
                .or_else(|| parts.headers.get(http::header::HOST)?.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
            scheme: scheme.to_owned(),
            end_of_stream: true,
            body: Some(body),
        };
        let outcome = execute_chain(&self.request_body, input).await?;
        match outcome.outcome {
            ChainOutcome::Continue(output) => {
                parts.headers = output.headers;
                Ok(WasmExecution {
                    local_response: None,
                    failed_open: outcome.failed_open,
                    body: output.body,
                })
            }
            ChainOutcome::Local(response) => Ok(WasmExecution {
                local_response: Some(response.into_http()?),
                failed_open: outcome.failed_open,
                body: None,
            }),
        }
    }

    /// 业务作用：在下游响应提交前执行完整响应 body 链，并原子提交 response header/body 变更。
    ///
    /// 参数说明：`headers` 是当前响应头，`body` 已按 `response_body_limit` 有界聚合，
    /// `request` 是请求 head 有界快照。
    ///
    /// 返回：继续时返回新 body；插件也可生成 local response；trap/超时按 fail-open/closed 处理。
    pub(crate) async fn execute_response_body(
        &self,
        headers: &mut HeaderMap,
        body: Bytes,
        request: WasmRequestHeadSnapshot,
    ) -> Result<WasmExecution> {
        if self.response_body.is_empty() {
            return Ok(WasmExecution {
                local_response: None,
                failed_open: 0,
                body: Some(body),
            });
        }
        let input = PhaseInput {
            phase: WasmPhase::ResponseBody,
            current_headers: headers.clone(),
            request_headers: Some(request.headers),
            method: request.method,
            path: request.path,
            authority: request.authority,
            scheme: request.scheme,
            end_of_stream: true,
            body: Some(body),
        };
        let outcome = execute_chain(&self.response_body, input).await?;
        match outcome.outcome {
            ChainOutcome::Continue(output) => {
                *headers = output.headers;
                Ok(WasmExecution {
                    local_response: None,
                    failed_open: outcome.failed_open,
                    body: output.body,
                })
            }
            ChainOutcome::Local(response) => Ok(WasmExecution {
                local_response: Some(response.into_http()?),
                failed_open: outcome.failed_open,
                body: None,
            }),
        }
    }

    /// 业务作用：为请求 body 安装持久 Proxy-Wasm 逐 frame 会话，并移除可能失真的 Content-Length。
    ///
    /// 参数说明：`parts` 是已完成 head 治理的请求，`body` 是上游待拉取流，`scheme` 是可信入口协议。
    ///
    /// 返回：全部 fail-closed 插件 lifecycle 成功时返回容量 1 的背压 body；构建失败阻止上游请求。
    pub(crate) async fn wrap_request_body_stream(
        &self,
        parts: &mut Parts,
        body: BoxBody,
        scheme: &str,
    ) -> Result<BoxBody> {
        if self.request_body_stream.is_empty() {
            return Ok(body);
        }
        let input = PhaseInput {
            phase: WasmPhase::RequestBodyStream,
            current_headers: parts.headers.clone(),
            request_headers: None,
            method: parts.method.as_str().to_owned(),
            path: parts
                .uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/")
                .to_owned(),
            authority: parts
                .uri
                .authority()
                .map(|value| value.as_str())
                .or_else(|| parts.headers.get(http::header::HOST)?.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
            scheme: scheme.to_owned(),
            end_of_stream: false,
            body: None,
        };
        let session = StreamingChainSession::start(&self.request_body_stream, input).await?;
        // frame 可改变长度，必须在上游 head 提交前解除旧 framing，避免接收端按旧长度截断或串包。
        parts.headers.remove(http::header::CONTENT_LENGTH);
        Ok(spawn_streaming_body(body, session))
    }

    /// 业务作用：为响应 body 安装持久 Proxy-Wasm 逐 frame 会话，保持长流并以容量 1 施加下游背压。
    ///
    /// 参数说明：`headers` 是尚未提交的响应头，`body` 是上游响应流，`request` 是只读请求 head 快照。
    ///
    /// 返回：全部 fail-closed lifecycle 成功时返回 streaming body；失败时调用方生成 500，原 body 被取消。
    pub(crate) async fn wrap_response_body_stream(
        &self,
        headers: &mut HeaderMap,
        body: BoxBody,
        request: WasmRequestHeadSnapshot,
    ) -> Result<BoxBody> {
        if self.response_body_stream.is_empty() {
            return Ok(body);
        }
        let input = PhaseInput {
            phase: WasmPhase::ResponseBodyStream,
            current_headers: headers.clone(),
            request_headers: Some(request.headers),
            method: request.method,
            path: request.path,
            authority: request.authority,
            scheme: request.scheme,
            end_of_stream: false,
            body: None,
        };
        let session = StreamingChainSession::start(&self.response_body_stream, input).await?;
        // response frame 改写后总长度不可预知；先撤销旧值，避免向下游发布脏 framing。
        headers.remove(http::header::CONTENT_LENGTH);
        Ok(spawn_streaming_body(body, session))
    }
}

struct WasmPlugin {
    id: Arc<str>,
    module: Module,
    config: Arc<[u8]>,
    fail_open: bool,
    limits: InvocationLimits,
    callout_clusters: Arc<HashMap<String, CalloutCluster>>,
    shared: Arc<WasmSharedState>,
}

#[derive(Clone, Copy)]
struct InvocationLimits {
    max_memory_bytes: usize,
    max_fuel: u64,
    timeout_ms: u64,
    max_mutations: usize,
    max_header_bytes: usize,
    max_body_bytes: usize,
    max_local_response_body_bytes: usize,
    max_callouts: usize,
    max_callout_response_bytes: usize,
}

#[derive(Clone, Copy)]
struct SharedLimits {
    max_entries: usize,
    max_bytes: usize,
    max_queues: usize,
    max_queue_entries: usize,
    max_metrics: usize,
}

struct CalloutCluster {
    origin: reqwest::Url,
    client: reqwest::Client,
}

struct WasmSharedState {
    namespace: Arc<str>,
    limits: SharedLimits,
    inner: Mutex<SharedStateInner>,
}

#[derive(Default)]
struct SharedStateInner {
    data: HashMap<Vec<u8>, SharedValue>,
    properties: HashMap<Vec<u8>, Vec<u8>>,
    queues_by_name: HashMap<Vec<u8>, u32>,
    queues: HashMap<u32, SharedQueue>,
    metrics_by_name: HashMap<(i32, Vec<u8>), u32>,
    metrics: HashMap<u32, SharedMetric>,
    next_cas: u32,
    next_queue_id: u32,
    next_metric_id: u32,
    resident_bytes: usize,
}

struct SharedValue {
    value: Vec<u8>,
    cas: u32,
}

#[derive(Default)]
struct SharedQueue {
    values: VecDeque<Vec<u8>>,
}

struct SharedMetric {
    kind: i32,
    value: u64,
}

enum PendingCallout {
    Http(HttpCallout),
    Grpc(GrpcCallout),
}

enum CompletedCallout {
    Http {
        token: u32,
        response: CalloutResponse,
    },
    Grpc {
        token: u32,
        response: CalloutResponse,
    },
}

struct HttpCallout {
    token: u32,
    cluster: String,
    method: http::Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    timeout_ms: u64,
}

struct GrpcCallout {
    token: u32,
    cluster: String,
    service: String,
    method: String,
    metadata: HeaderMap,
    message: Bytes,
    timeout_ms: u64,
}

struct CalloutResponse {
    status: StatusCode,
    headers: HeaderMap,
    trailers: HeaderMap,
    body: Bytes,
    grpc_status: Option<u32>,
}

impl WasmSharedState {
    /// 业务作用：读取插件版本隔离命名空间中的 shared data，并返回 CAS 版本。
    ///
    /// 参数说明：`key` 是客体提供且已做长度门禁的二进制 key。
    ///
    /// 返回：命中时返回值与非零 CAS；不存在时返回空，不跨 route、租户或模块版本读取。
    fn get_data(&self, key: &[u8]) -> Option<(Vec<u8>, u32)> {
        self.inner
            .lock()
            .data
            .get(key)
            .map(|entry| (entry.value.clone(), entry.cas))
    }

    /// 业务作用：以可选 CAS 原子写入或删除 shared data，并在提交前执行条目与驻留字节硬门。
    ///
    /// 参数说明：`key` 是命名空间内 key，`value` 为写入值或删除，`cas` 为 0 或期望版本。
    ///
    /// 返回：写入成功返回 OK；版本竞争返回 CAS mismatch；资源越界不产生部分写。
    fn set_data(&self, key: Vec<u8>, value: Option<Vec<u8>>, cas: u32) -> Result<(), HostError> {
        let mut state = self.inner.lock();
        let current = state.data.get(&key);
        if cas != 0 && current.map(|entry| entry.cas) != Some(cas) {
            return Err(HostError::Status(PROXY_STATUS_CAS_MISMATCH));
        }
        let old_bytes = current.map_or(0, |entry| key.len() + entry.value.len());
        let new_bytes = value.as_ref().map_or(0, |value| key.len() + value.len());
        let new_entries = state.data.len()
            + state.properties.len()
            + usize::from(current.is_none() && value.is_some())
            - usize::from(current.is_some() && value.is_none());
        let resident = state
            .resident_bytes
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes);
        if new_entries > self.limits.max_entries || resident > self.limits.max_bytes {
            return Err(HostError::Status(PROXY_STATUS_INTERNAL_FAILURE));
        }
        match value {
            Some(value) => {
                let next = next_nonzero(&mut state.next_cas);
                state.data.insert(key, SharedValue { value, cas: next });
            }
            None => {
                state.data.remove(&key);
            }
        }
        state.resident_bytes = resident;
        Ok(())
    }

    /// 业务作用：注册命名空间内幂等 shared queue，并限制队列名称基数。
    ///
    /// 参数说明：`name` 是已做长度门禁的队列名。
    ///
    /// 返回：已有队列返回稳定 id；新队列在预算内分配 id，越界返回内部失败。
    fn register_queue(&self, name: Vec<u8>) -> Result<u32, HostError> {
        let mut state = self.inner.lock();
        if let Some(id) = state.queues_by_name.get(&name) {
            return Ok(*id);
        }
        if state.queues.len() >= self.limits.max_queues
            || state.resident_bytes.saturating_add(name.len()) > self.limits.max_bytes
        {
            return Err(HostError::Status(PROXY_STATUS_INTERNAL_FAILURE));
        }
        let id = next_nonzero(&mut state.next_queue_id);
        state.resident_bytes += name.len();
        state.queues_by_name.insert(name, id);
        state.queues.insert(id, SharedQueue::default());
        Ok(id)
    }

    /// 业务作用：只在当前隔离命名空间解析 shared queue，拒绝跨 VM/版本名称穿透。
    ///
    /// 参数说明：`vm_id` 是客体请求的 VM 命名空间，`name` 是队列名。
    ///
    /// 返回：当前 namespace 内命中返回 id；跨 namespace 或不存在返回空。
    fn resolve_queue(&self, vm_id: &[u8], name: &[u8]) -> Option<u32> {
        if !vm_id.is_empty() && vm_id != self.namespace.as_bytes() {
            return None;
        }
        self.inner.lock().queues_by_name.get(name).copied()
    }

    /// 业务作用：向 shared queue 原子追加一条消息，并同时执行消息数和全局驻留字节门禁。
    ///
    /// 参数说明：`id` 是本命名空间队列 id，`value` 是有界消息。
    ///
    /// 返回：成功入队返回 OK；队列缺失或满载时拒绝且不改变队列。
    fn enqueue(&self, id: u32, value: Vec<u8>) -> Result<(), HostError> {
        let mut state = self.inner.lock();
        let len = state
            .queues
            .get(&id)
            .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?
            .values
            .len();
        if len >= self.limits.max_queue_entries
            || state.resident_bytes.saturating_add(value.len()) > self.limits.max_bytes
        {
            return Err(HostError::Status(PROXY_STATUS_INTERNAL_FAILURE));
        }
        state.resident_bytes += value.len();
        state
            .queues
            .get_mut(&id)
            .expect("queue existence checked")
            .values
            .push_back(value);
        Ok(())
    }

    /// 业务作用：从 shared queue 原子取出最早消息并立即释放驻留字节预算。
    ///
    /// 参数说明：`id` 是当前命名空间队列 id。
    ///
    /// 返回：队列有数据时返回消息；空队列返回 EMPTY；未知 id 返回 NOT_FOUND。
    fn dequeue(&self, id: u32) -> Result<Vec<u8>, HostError> {
        let mut state = self.inner.lock();
        let queue = state
            .queues
            .get_mut(&id)
            .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
        let value = queue
            .values
            .pop_front()
            .ok_or(HostError::Status(PROXY_STATUS_EMPTY))?;
        state.resident_bytes = state.resident_bytes.saturating_sub(value.len());
        Ok(value)
    }

    /// 业务作用：定义插件内部低基数 metric，并以类型和名称保持幂等 id。
    ///
    /// 参数说明：`kind` 是 Proxy-Wasm metric 类型，`name` 是受限名称。
    ///
    /// 返回：已有定义返回原 id；类型非法或超过基数预算时拒绝。
    fn define_metric(&self, kind: i32, name: Vec<u8>) -> Result<u32, HostError> {
        if !matches!(kind, 0..=2) {
            return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT));
        }
        let mut state = self.inner.lock();
        if let Some(id) = state.metrics_by_name.get(&(kind, name.clone())) {
            return Ok(*id);
        }
        if state.metrics.len() >= self.limits.max_metrics {
            return Err(HostError::Status(PROXY_STATUS_INTERNAL_FAILURE));
        }
        let id = next_nonzero(&mut state.next_metric_id);
        state.metrics_by_name.insert((kind, name), id);
        state.metrics.insert(id, SharedMetric { kind, value: 0 });
        Ok(id)
    }

    /// 业务作用：按 metric 类型执行有溢出保护的增量更新。
    ///
    /// 参数说明：`id` 是已定义 metric，`offset` 是有符号增量。
    ///
    /// 返回：counter 只接受非负增量；溢出、未知 id 或 histogram 增量均拒绝。
    fn increment_metric(&self, id: u32, offset: i64) -> Result<(), HostError> {
        let mut state = self.inner.lock();
        let metric = state
            .metrics
            .get_mut(&id)
            .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
        if metric.kind == 2 || (metric.kind == 0 && offset < 0) {
            return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT));
        }
        metric.value = if offset >= 0 {
            metric.value.checked_add(offset as u64)
        } else {
            metric.value.checked_sub(offset.unsigned_abs())
        }
        .ok_or(HostError::Status(PROXY_STATUS_BAD_ARGUMENT))?;
        Ok(())
    }

    /// 业务作用：记录 gauge/histogram 值；counter 必须通过 increment 保持单调语义。
    ///
    /// 参数说明：`id` 是已定义 metric，`value` 是新值或 histogram observation。
    ///
    /// 返回：类型与 id 合法时更新，counter record 或未知 id 返回错误。
    fn record_metric(&self, id: u32, value: u64) -> Result<(), HostError> {
        let mut state = self.inner.lock();
        let metric = state
            .metrics
            .get_mut(&id)
            .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
        if metric.kind == 0 {
            return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT));
        }
        metric.value = value;
        Ok(())
    }

    /// 业务作用：读取插件内部 metric 当前值，避免把客体名称直接扩散为全局 label。
    ///
    /// 参数说明：`id` 是已定义 metric。
    ///
    /// 返回：命中返回当前值，未知 id 返回 NOT_FOUND。
    fn get_metric(&self, id: u32) -> Result<u64, HostError> {
        self.inner
            .lock()
            .metrics
            .get(&id)
            .map(|metric| metric.value)
            .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))
    }

    /// 业务作用：读取仅当前插件版本可见的自定义 property。
    ///
    /// 参数说明：`path` 是 NUL 分隔的 property 路径。
    ///
    /// 返回：命中返回副本，不存在返回空。
    fn get_property(&self, path: &[u8]) -> Option<Vec<u8>> {
        self.inner.lock().properties.get(path).cloned()
    }

    /// 业务作用：原子写入或删除插件自定义 property，并与 shared data 共用驻留字节预算。
    ///
    /// 参数说明：`path` 是隔离 property 路径，`value` 为写入值或删除。
    ///
    /// 返回：预算内成功提交；条目或字节越界时拒绝且保留原值。
    fn set_property(&self, path: Vec<u8>, value: Option<Vec<u8>>) -> Result<(), HostError> {
        let mut state = self.inner.lock();
        let current = state.properties.get(&path);
        let old_bytes = current.map_or(0, |value| path.len() + value.len());
        let new_bytes = value.as_ref().map_or(0, |value| path.len() + value.len());
        let new_entries = state.data.len()
            + state.properties.len()
            + usize::from(current.is_none() && value.is_some())
            - usize::from(current.is_some() && value.is_none());
        let resident = state
            .resident_bytes
            .saturating_sub(old_bytes)
            .saturating_add(new_bytes);
        if new_entries > self.limits.max_entries || resident > self.limits.max_bytes {
            return Err(HostError::Status(PROXY_STATUS_INTERNAL_FAILURE));
        }
        match value {
            Some(value) => {
                state.properties.insert(path, value);
            }
            None => {
                state.properties.remove(&path);
            }
        }
        state.resident_bytes = resident;
        Ok(())
    }
}

/// 业务作用：生成不会返回 0 的单调 ABI id/CAS，并允许计数器自然回绕后继续使用。
///
/// 参数说明：`counter` 是受互斥锁保护的下一 id。
///
/// 返回：返回本次非零 id，并把计数器推进到下一个非零值。
fn next_nonzero(counter: &mut u32) -> u32 {
    let current = (*counter).max(1);
    *counter = current.wrapping_add(1).max(1);
    current
}

impl WasmPlugin {
    /// 业务作用：从不可信模块文件构建插件，并在候选快照期验证 ABI、import 与全部资源门。
    ///
    /// 参数说明：`cfg` 是插件声明，`config_dir` 解析模块路径，`route_id` 用于错误归因。
    ///
    /// 返回：验证成功返回可复用编译模块；文件越界、ABI/import/配置非法时拒绝快照。
    fn build(cfg: &WasmPluginCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        validate_cfg(cfg)?;
        let (bytes, module_identity) = load_module_bytes(cfg, config_dir, route_id)?;
        let module_digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let engine = engine()?;
        let module = Module::from_binary(engine, &bytes)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("compile wasm module {module_identity}"))?;
        validate_imports(&module)?;
        let config = serde_json::to_vec(&cfg.config).context("serialize wasm plugin config")?;
        if config.len() > MAX_PLUGIN_CONFIG_BYTES {
            bail!("serialized plugin config exceeds {MAX_PLUGIN_CONFIG_BYTES} bytes");
        }
        let callout_clusters = Arc::new(build_callout_clusters(cfg, config_dir)?);
        let shared = Arc::new(WasmSharedState {
            namespace: Arc::from(format!(
                "{route_id}/{}/{}/{module_digest}",
                cfg.shared_namespace, cfg.id
            )),
            limits: SharedLimits {
                max_entries: cfg.max_shared_entries,
                max_bytes: cfg.max_shared_bytes,
                max_queues: cfg.max_shared_queues,
                max_queue_entries: cfg.max_queue_entries,
                max_metrics: cfg.max_metrics,
            },
            inner: Mutex::new(SharedStateInner {
                next_cas: 1,
                next_queue_id: 1,
                next_metric_id: 1,
                ..SharedStateInner::default()
            }),
        });
        let plugin = Self {
            id: Arc::from(cfg.id.as_str()),
            module,
            config: config.into(),
            fail_open: cfg.fail_open,
            limits: InvocationLimits {
                max_memory_bytes: cfg.max_memory_bytes,
                max_fuel: cfg.max_fuel,
                timeout_ms: cfg.timeout_ms,
                max_mutations: cfg.max_mutations,
                max_header_bytes: cfg.max_header_bytes,
                max_body_bytes: cfg.max_body_bytes,
                max_local_response_body_bytes: cfg.max_local_response_body_bytes,
                max_callouts: cfg.max_callouts,
                max_callout_response_bytes: cfg.max_callout_response_bytes,
            },
            callout_clusters,
            shared,
        };
        // 在候选快照构建期实例化一次：这会验证 import 精确签名、初始内存预算
        // 与 core start section。不调用 Proxy-Wasm lifecycle，避免 dry-run 触发业务行为。
        plugin
            .instantiate(HostState::validation(
                plugin.config.clone(),
                plugin.limits,
                plugin.callout_clusters.clone(),
                plugin.shared.clone(),
            ))
            .with_context(|| format!("validate wasm plugin `{}` for route `{route_id}`", cfg.id))?;
        Ok(plugin)
    }

    /// 业务作用：为单次调用创建隔离 Store/Instance，并安装 fuel、内存与 epoch 硬门。
    ///
    /// 参数说明：`state` 是本次调用独享、已完成输入预算校验的宿主状态。
    ///
    /// 返回：实例化成功返回独占运行态；链接签名或资源门失败返回错误。
    fn instantiate(&self, state: HostState) -> Result<(Store<HostState>, wasmtime::Instance)> {
        let mut store = Store::new(self.module.engine(), state);
        store.limiter(|state| &mut state.store_limits);
        store.set_fuel(self.limits.max_fuel)?;
        store.set_epoch_deadline(self.limits.timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));
        store.epoch_deadline_trap();
        let linker = build_linker(self.module.engine())?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(anyhow::Error::from)
            .context("instantiate Proxy-Wasm module")?;
        Ok((store, instance))
    }

    /// 业务作用：创建一次隔离实例、执行 lifecycle 与当前 HTTP phase 回调，并在 PAUSE 时保留可恢复状态。
    ///
    /// 参数说明：`input` 是本插件独享的 head/body 副本，失败时不会污染已提交链状态。
    ///
    /// 返回：同步完成返回最终结果；合法 PAUSE 返回持有 Store/Instance 的暂停态；trap/未知动作返回错误。
    fn start_invocation(&self, input: PhaseInput) -> Result<InvocationProgress> {
        let state = HostState::new(
            input,
            self.config.clone(),
            self.limits,
            self.callout_clusters.clone(),
            self.shared.clone(),
        )?;
        let (mut store, instance) = self.instantiate(state)?;

        // ABI marker 必须存在；不接受“长得像 Proxy-Wasm”但版本不明的客体。
        instance
            .get_typed_func::<(), ()>(&mut store, "proxy_abi_version_0_2_1")
            .map_err(anyhow::Error::from)
            .context("missing or invalid Proxy-Wasm ABI v0.2.1 marker")?
            .call(&mut store, ())
            .map_err(anyhow::Error::from)
            .context("call Proxy-Wasm ABI marker")?;
        if instance.get_func(&mut store, "_initialize").is_some() {
            call_optional_unit(&mut store, &instance, "_initialize")?;
        } else {
            call_optional_unit(&mut store, &instance, "_start")?;
        }

        call_optional_i32_pair_void(&mut store, &instance, "proxy_on_context_create", 1, 0)?;
        if !call_optional_i32_i32_bool(&mut store, &instance, "proxy_on_vm_start", 1, 0)? {
            bail!("proxy_on_vm_start rejected VM configuration");
        }
        if !call_optional_i32_i32_bool(
            &mut store,
            &instance,
            "proxy_on_configure",
            1,
            i32::try_from(self.config.len()).context("plugin config length")?,
        )? {
            bail!("proxy_on_configure rejected plugin configuration");
        }
        call_optional_i32_pair_void(&mut store, &instance, "proxy_on_context_create", 2, 1)?;

        let map_type = match store.data().phase {
            WasmPhase::RequestHeaders | WasmPhase::RequestBody => MAP_REQUEST_HEADERS,
            WasmPhase::ResponseHeaders | WasmPhase::ResponseBody => MAP_RESPONSE_HEADERS,
            WasmPhase::RequestBodyStream | WasmPhase::ResponseBodyStream => {
                bail!("streaming body phase requires a persistent session")
            }
        };
        let end_of_stream = i32::from(store.data().end_of_stream);
        let (callback, size) = match store.data().phase {
            WasmPhase::RequestHeaders => (
                "proxy_on_request_headers",
                i32::try_from(visible_header_count(store.data(), map_type)?)
                    .context("header count exceeds Proxy-Wasm ABI")?,
            ),
            WasmPhase::RequestBody => (
                "proxy_on_request_body",
                i32::try_from(store.data().body.as_ref().map_or(0, Bytes::len))
                    .context("request body exceeds Proxy-Wasm ABI")?,
            ),
            WasmPhase::ResponseHeaders => (
                "proxy_on_response_headers",
                i32::try_from(visible_header_count(store.data(), map_type)?)
                    .context("header count exceeds Proxy-Wasm ABI")?,
            ),
            WasmPhase::ResponseBody => (
                "proxy_on_response_body",
                i32::try_from(store.data().body.as_ref().map_or(0, Bytes::len))
                    .context("response body exceeds Proxy-Wasm ABI")?,
            ),
            WasmPhase::RequestBodyStream | WasmPhase::ResponseBodyStream => {
                unreachable!("streaming body phase was rejected before callback selection")
            }
        };
        let action = instance
            .get_typed_func::<(i32, i32, i32), i32>(&mut store, callback)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("missing or invalid `{callback}` export"))?
            .call(&mut store, (2, size, end_of_stream))
            .map_err(anyhow::Error::from)
            .with_context(|| format!("call `{callback}`"))?;

        progress_after_action(store, instance, action)
    }

    /// 业务作用：为逐 frame body phase 建立持久 HTTP context，使跨 frame shared context 与客体状态连续。
    ///
    /// 参数说明：`input` 固定请求/响应 head 与流方向，body 在每次 callback 前单独注入。
    ///
    /// 返回：lifecycle、ABI 与 callback 签名有效时返回会话实例；失败时该插件不进入流。
    fn start_streaming(self: Arc<Self>, input: PhaseInput) -> Result<StreamingPluginInstance> {
        if !matches!(
            input.phase,
            WasmPhase::RequestBodyStream | WasmPhase::ResponseBodyStream
        ) {
            bail!("persistent stream session requires a streaming body phase");
        }
        let state = HostState::new(
            input,
            self.config.clone(),
            self.limits,
            self.callout_clusters.clone(),
            self.shared.clone(),
        )?;
        let (mut store, instance) = self.instantiate(state)?;
        instance
            .get_typed_func::<(), ()>(&mut store, "proxy_abi_version_0_2_1")
            .map_err(anyhow::Error::from)
            .context("missing or invalid Proxy-Wasm ABI v0.2.1 marker")?
            .call(&mut store, ())
            .map_err(anyhow::Error::from)
            .context("call Proxy-Wasm ABI marker")?;
        if instance.get_func(&mut store, "_initialize").is_some() {
            call_optional_unit(&mut store, &instance, "_initialize")?;
        } else {
            call_optional_unit(&mut store, &instance, "_start")?;
        }
        call_optional_i32_pair_void(&mut store, &instance, "proxy_on_context_create", 1, 0)?;
        if !call_optional_i32_i32_bool(&mut store, &instance, "proxy_on_vm_start", 1, 0)? {
            bail!("proxy_on_vm_start rejected VM configuration");
        }
        if !call_optional_i32_i32_bool(
            &mut store,
            &instance,
            "proxy_on_configure",
            1,
            i32::try_from(self.config.len()).context("plugin config length")?,
        )? {
            bail!("proxy_on_configure rejected plugin configuration");
        }
        call_optional_i32_pair_void(&mut store, &instance, "proxy_on_context_create", 2, 1)?;
        let callback = match store.data().phase {
            WasmPhase::RequestBodyStream => "proxy_on_request_body",
            WasmPhase::ResponseBodyStream => "proxy_on_response_body",
            _ => unreachable!("stream phase checked before instantiation"),
        };
        instance
            .get_typed_func::<(i32, i32, i32), i32>(&mut store, callback)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("missing or invalid `{callback}` export"))?;
        Ok(StreamingPluginInstance {
            plugin: self,
            store,
            instance,
            cleaned: false,
        })
    }
}

struct StreamingPluginInstance {
    plugin: Arc<WasmPlugin>,
    store: Store<HostState>,
    instance: wasmtime::Instance,
    cleaned: bool,
}

enum StreamFrameProgress {
    Ready(Bytes),
    Paused,
}

impl StreamingPluginInstance {
    /// 业务作用：在持久 context 中执行一个 body frame callback，并为 PAUSE 保留同一实例。
    ///
    /// 参数说明：`body` 是当前 frame，`end_of_stream` 标识它是无 trailers 的最终 DATA。
    ///
    /// 返回：CONTINUE 返回原子改写后的当前 frame；PAUSE 返回暂停态；trap/越界立即失败。
    fn begin_frame(&mut self, body: Bytes, end_of_stream: bool) -> Result<StreamFrameProgress> {
        if body.len() > self.plugin.limits.max_body_bytes {
            bail!("Proxy-Wasm streaming frame exceeds max_body_bytes");
        }
        self.store.set_fuel(self.plugin.limits.max_fuel)?;
        self.store
            .set_epoch_deadline(self.plugin.limits.timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));
        let state = self.store.data_mut();
        state.body = Some(body);
        state.end_of_stream = end_of_stream;
        state.mutations = 0;
        state.continue_requested = false;
        state.done_requested = false;
        state.local_response = None;
        state.callout_response = None;
        let callback = match state.phase {
            WasmPhase::RequestBodyStream => "proxy_on_request_body",
            WasmPhase::ResponseBodyStream => "proxy_on_response_body",
            _ => bail!("stream instance phase changed unexpectedly"),
        };
        let body_size = i32::try_from(self.store.data().body.as_ref().map_or(0, Bytes::len))
            .context("stream frame exceeds ABI")?;
        let action = self
            .instance
            .get_typed_func::<(i32, i32, i32), i32>(&mut self.store, callback)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("missing or invalid `{callback}` export"))?
            .call(&mut self.store, (2, body_size, i32::from(end_of_stream)))
            .map_err(anyhow::Error::from)
            .with_context(|| format!("call `{callback}`"))?;
        self.progress_after_action(action)
    }

    /// 业务作用：解释逐 frame callback action，拒绝无恢复来源的 PAUSE 与 streaming local response。
    ///
    /// 参数说明：`action` 是客体返回的 Proxy-Wasm Action。
    ///
    /// 返回：CONTINUE/同步 resume 返回当前 frame；合法异步 PAUSE 保留；其它状态失败关闭。
    fn progress_after_action(&mut self, action: i32) -> Result<StreamFrameProgress> {
        if self.store.data().local_response.is_some() {
            bail!("streaming body callback cannot send a local response after head commit");
        }
        if action == PROXY_ACTION_CONTINUE
            || self.store.data().continue_requested
            || self.store.data().done_requested
        {
            self.store.data_mut().continue_requested = false;
            return Ok(StreamFrameProgress::Ready(
                self.store.data_mut().body.take().unwrap_or_default(),
            ));
        }
        if action != PROXY_ACTION_PAUSE {
            bail!("streaming body plugin returned unknown action {action}");
        }
        if self.store.data().pending_callouts.is_empty()
            && self.store.data().tick_period_ms.is_none()
        {
            bail!("streaming body plugin paused without an async callback source");
        }
        Ok(StreamFrameProgress::Paused)
    }

    /// 业务作用：取出 streaming callback 登记的下一项 callout，同时保持 Store/context 不变。
    ///
    /// 参数说明：无。
    ///
    /// 返回：有排队请求时返回最早项，否则返回空。
    fn take_callout(&mut self) -> Option<PendingCallout> {
        self.store.data_mut().pending_callouts.pop_front()
    }

    /// 业务作用：向 streaming context 投递 callout callback，再复验当前 frame 是否可恢复。
    ///
    /// 参数说明：`completed` 是固定 token 的有界响应。
    ///
    /// 返回：continue/done 返回当前 frame；仍有异步来源保持 PAUSE；trap 或悬空 PAUSE 返回错误。
    fn on_callout(&mut self, completed: CompletedCallout) -> Result<StreamFrameProgress> {
        deliver_callout(&mut self.store, &self.instance, completed)?;
        self.progress_after_async_callback()
    }

    /// 业务作用：执行 streaming PAUSE 的 timer callback，并在同一 context 中读取恢复信号。
    ///
    /// 参数说明：无。
    ///
    /// 返回：continue/done 返回当前 frame；否则在仍有 timer/callout 时继续暂停。
    fn on_tick(&mut self) -> Result<StreamFrameProgress> {
        self.store.set_fuel(self.plugin.limits.max_fuel)?;
        self.store
            .set_epoch_deadline(self.plugin.limits.timeout_ms.div_ceil(EPOCH_TICK_MS).max(1));
        call_optional_i32_void(&mut self.store, &self.instance, "proxy_on_tick", 1)?;
        self.progress_after_async_callback()
    }

    /// 业务作用：在 streaming 异步 callback 后保证 PAUSE 仍有明确恢复来源。
    ///
    /// 参数说明：无。
    ///
    /// 返回：已恢复时返回当前 frame；仍可恢复时返回 PAUSE；否则失败，防止 body 永久挂起。
    fn progress_after_async_callback(&mut self) -> Result<StreamFrameProgress> {
        if self.store.data().continue_requested || self.store.data().done_requested {
            self.store.data_mut().continue_requested = false;
            return Ok(StreamFrameProgress::Ready(
                self.store.data_mut().body.take().unwrap_or_default(),
            ));
        }
        if self.store.data().pending_callouts.is_empty()
            && self.store.data().tick_period_ms.is_none()
        {
            bail!("streaming async callback left frame paused without a resume source");
        }
        Ok(StreamFrameProgress::Paused)
    }

    /// 业务作用：读取 streaming PAUSE 的有界 timer 周期，供 Tokio 非阻塞等待。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回至少 1ms、且配置期已限制在 callback deadline 内的周期。
    fn tick_period(&self) -> Duration {
        Duration::from_millis(self.store.data().tick_period_ms.unwrap_or(1).max(1))
    }

    /// 业务作用：在 EOF 正常按 done→log→delete 清理持久 context，释放 Store 与共享引用。
    ///
    /// 参数说明：无。
    ///
    /// 返回：cleanup callback 正常时成功；trap 返回错误但实例仍被标记清理，避免重复副作用。
    fn finish(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.cleaned = true;
        let _ = call_optional_i32_bool(&mut self.store, &self.instance, "proxy_on_done", 2)?;
        call_optional_i32_void(&mut self.store, &self.instance, "proxy_on_log", 2)?;
        call_optional_i32_void(&mut self.store, &self.instance, "proxy_on_delete", 2)
    }
}

impl Drop for StreamingPluginInstance {
    fn drop(&mut self) {
        if !self.cleaned {
            // 下游取消或上游提前结束时仍执行有 fuel/epoch 门的 lifecycle，防止客体保留半完成状态。
            cleanup_invocation(&mut self.store, &self.instance);
            self.cleaned = true;
        }
    }
}

struct PausedInvocation {
    store: Store<HostState>,
    instance: wasmtime::Instance,
}

enum InvocationProgress {
    Finished(InvocationOutcome),
    Paused(PausedInvocation),
}

/// 业务作用：解释 phase action，保证 PAUSE 只有在可恢复 timer 已登记时才持有实例。
///
/// 参数说明：`store`/`instance` 是本次调用独占状态，`action` 是客体回调返回值。
///
/// 返回：Continue/local response 完成 lifecycle；PAUSE 返回暂停态；未知或不可恢复 PAUSE 返回错误。
fn progress_after_action(
    mut store: Store<HostState>,
    instance: wasmtime::Instance,
    action: i32,
) -> Result<InvocationProgress> {
    if store.data().local_response.is_some()
        || store.data().done_requested
        || action == PROXY_ACTION_CONTINUE
    {
        return finish_invocation(store, instance).map(InvocationProgress::Finished);
    }
    if action != PROXY_ACTION_PAUSE {
        cleanup_invocation(&mut store, &instance);
        bail!("plugin returned unknown action {action}");
    }
    if store.data().continue_requested {
        store.data_mut().continue_requested = false;
        return finish_invocation(store, instance).map(InvocationProgress::Finished);
    }
    if store.data().tick_period_ms.is_none() && store.data().pending_callouts.is_empty() {
        cleanup_invocation(&mut store, &instance);
        bail!("plugin returned PAUSE without registering an async callback");
    }
    if store.data().pending_callouts.is_empty()
        && instance.get_func(&mut store, "proxy_on_tick").is_none()
    {
        cleanup_invocation(&mut store, &instance);
        bail!("plugin returned PAUSE without exporting proxy_on_tick");
    }
    Ok(InvocationProgress::Paused(PausedInvocation {
        store,
        instance,
    }))
}

impl PausedInvocation {
    /// 业务作用：取出下一项客体已获 token 的 callout，交给 Tokio 网络栈执行。
    ///
    /// 参数说明：无。
    ///
    /// 返回：有排队 callout 时按登记顺序返回；没有时返回空并保留暂停实例。
    fn take_callout(&mut self) -> Option<PendingCallout> {
        self.store.data_mut().pending_callouts.pop_front()
    }

    /// 业务作用：把受控 callout 结果暴露给对应 ABI callback，并决定恢复、继续等待或结束。
    ///
    /// 参数说明：`completed` 包含固定 token 与已执行资源门禁的 HTTP/gRPC 响应。
    ///
    /// 返回：callback 请求 continue/local response 时完成；仍有异步权威时继续暂停；非法悬空 PAUSE 返回错误。
    fn on_callout(mut self, completed: CompletedCallout) -> Result<InvocationProgress> {
        deliver_callout(&mut self.store, &self.instance, completed)?;
        self.progress_after_async_callback()
    }

    /// 业务作用：在异步 callback 后复验恢复信号，防止没有 timer/callout 的暂停实例永久占用资源。
    ///
    /// 参数说明：无。
    ///
    /// 返回：continue/local response 完成生命周期；仍有 callback 来源时保留暂停；否则失败并清理。
    fn progress_after_async_callback(mut self) -> Result<InvocationProgress> {
        if self.store.data().local_response.is_some()
            || self.store.data().continue_requested
            || self.store.data().done_requested
        {
            self.store.data_mut().continue_requested = false;
            return finish_invocation(self.store, self.instance).map(InvocationProgress::Finished);
        }
        if self.store.data().pending_callouts.is_empty()
            && self.store.data().tick_period_ms.is_none()
        {
            cleanup_invocation(&mut self.store, &self.instance);
            bail!("Proxy-Wasm async callback left stream paused without a resume source");
        }
        Ok(InvocationProgress::Paused(self))
    }

    /// 业务作用：执行一次 timer callback，并在客体调用 `proxy_continue_stream` 后恢复原 phase。
    ///
    /// 参数说明：无。
    ///
    /// 返回：仍未请求恢复时保留暂停态；continue/local response 时完成 lifecycle；trap 返回错误并释放实例。
    fn on_tick(mut self) -> Result<InvocationProgress> {
        let ticks = self
            .store
            .data()
            .limits
            .timeout_ms
            .div_ceil(EPOCH_TICK_MS)
            .max(1);
        self.store.set_epoch_deadline(ticks);
        call_optional_i32_void(&mut self.store, &self.instance, "proxy_on_tick", 1)?;
        self.progress_after_async_callback()
    }

    /// 业务作用：读取客体登记的下一次 timer 周期，供 Tokio 定时器无阻塞等待。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回至少 1ms 的受配置上限周期。
    fn tick_period(&self) -> Duration {
        Duration::from_millis(self.store.data().tick_period_ms.unwrap_or(1).max(1))
    }

    /// 业务作用：异步等待超时后显式执行 done/log/delete，再释放暂停实例与 body 副本。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无返回值；cleanup trap 不覆盖 timeout 主错误。
    fn cancel(mut self) {
        cleanup_invocation(&mut self.store, &self.instance);
    }
}

/// 业务作用：在原 Store 上投递 HTTP/gRPC callout callback，并只在 callback 期间开放响应 map/buffer。
///
/// 参数说明：`store`/`instance` 是暂停上下文，`completed` 是已做资源门的固定 token 响应。
///
/// 返回：callback 正常结束返回 OK；缺失/错误签名或 trap 返回错误，响应视图随实例释放而不可复用。
fn deliver_callout(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    completed: CompletedCallout,
) -> Result<()> {
    let ticks = store
        .data()
        .limits
        .timeout_ms
        .div_ceil(EPOCH_TICK_MS)
        .max(1);
    store.set_epoch_deadline(ticks);
    match completed {
        CompletedCallout::Http { token, response } => {
            let header_count = i32::try_from(response.headers.len() + 1)
                .context("HTTP callout header count exceeds ABI")?;
            let body_size =
                i32::try_from(response.body.len()).context("HTTP callout body exceeds ABI")?;
            let trailer_count = i32::try_from(response.trailers.len())
                .context("HTTP callout trailer count exceeds ABI")?;
            store.data_mut().callout_response = Some(response);
            instance
                .get_typed_func::<(i32, i32, i32, i32, i32), ()>(
                    &mut *store,
                    "proxy_on_http_call_response",
                )
                .map_err(anyhow::Error::from)
                .context("missing or invalid proxy_on_http_call_response")?
                .call(
                    &mut *store,
                    (2, token as i32, header_count, body_size, trailer_count),
                )
                .map_err(anyhow::Error::from)
                .context("call proxy_on_http_call_response")?;
        }
        CompletedCallout::Grpc { token, response } => {
            let status = response.grpc_status.unwrap_or(13);
            let body_size =
                i32::try_from(response.body.len()).context("gRPC callout body exceeds ABI")?;
            store.data_mut().callout_response = Some(response);
            let callback = if status == 0 {
                "proxy_on_grpc_receive"
            } else {
                "proxy_on_grpc_close"
            };
            instance
                .get_typed_func::<(i32, i32, i32), ()>(&mut *store, callback)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("missing or invalid {callback}"))?
                .call(
                    &mut *store,
                    (
                        2,
                        token as i32,
                        if status == 0 {
                            body_size
                        } else {
                            status as i32
                        },
                    ),
                )
                .map_err(anyhow::Error::from)
                .with_context(|| format!("call {callback}"))?;
        }
    }
    store.data_mut().callout_response = None;
    Ok(())
}

/// 业务作用：正常结束一次 invocation，按 done→log→delete 顺序清理并原子取出结果。
///
/// 参数说明：`store`/`instance` 是完成或恢复后的独占实例。
///
/// 返回：local response 优先；否则返回最终 head/body。
fn finish_invocation(
    mut store: Store<HostState>,
    instance: wasmtime::Instance,
) -> Result<InvocationOutcome> {
    let local = store.data_mut().local_response.take();
    let _ = call_optional_i32_bool(&mut store, &instance, "proxy_on_done", 2)?;
    call_optional_i32_void(&mut store, &instance, "proxy_on_log", 2)?;
    call_optional_i32_void(&mut store, &instance, "proxy_on_delete", 2)?;
    if let Some(local) = local {
        Ok(InvocationOutcome::Local(local))
    } else {
        Ok(InvocationOutcome::Continue(store.data_mut().take_output()))
    }
}

/// 业务作用：异常/不可恢复 PAUSE 时尽力执行生命周期清理，不让回调错误掩盖原始失败。
///
/// 参数说明：`store`/`instance` 是即将释放的独占实例。
///
/// 返回：无返回值；cleanup trap 仅记录并继续释放内存。
fn cleanup_invocation(store: &mut Store<HostState>, instance: &wasmtime::Instance) {
    let _ = call_optional_i32_bool(store, instance, "proxy_on_done", 2);
    let _ = call_optional_i32_void(store, instance, "proxy_on_log", 2);
    let _ = call_optional_i32_void(store, instance, "proxy_on_delete", 2);
}

/// 业务作用：在 blocking pool 执行 Wasm 指令、在 Tokio timer 上等待 PAUSE，并受单一墙钟 deadline 约束。
///
/// 参数说明：`plugin` 是已编译实例模板，`input` 是本插件原子副本。
///
/// 返回：continue/local response 成功返回；join/trap/异步超时返回错误。请求取消会 Drop 暂停态，
/// Store/Instance 与 body 副本随 future 一起释放，不保留后台 registry 项。
async fn invoke_plugin(plugin: Arc<WasmPlugin>, input: PhaseInput) -> Result<InvocationOutcome> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(plugin.limits.timeout_ms);
    let start_plugin = plugin.clone();
    let started = tokio::task::spawn_blocking(move || start_plugin.start_invocation(input));
    let mut progress = tokio::time::timeout_at(deadline, started)
        .await
        .context("Proxy-Wasm invocation timeout")?
        .context("join Proxy-Wasm worker")??;
    loop {
        let mut paused = match progress {
            InvocationProgress::Finished(outcome) => return Ok(outcome),
            InvocationProgress::Paused(paused) => paused,
        };
        if let Some(callout) = paused.take_callout() {
            let completed =
                tokio::time::timeout_at(deadline, execute_pending_callout(&plugin, callout))
                    .await
                    .context("Proxy-Wasm callout exceeded invocation deadline")?;
            let callback = tokio::task::spawn_blocking(move || paused.on_callout(completed));
            progress = tokio::time::timeout_at(deadline, callback)
                .await
                .context("Proxy-Wasm callout callback timeout")?
                .context("join Proxy-Wasm callout callback worker")??;
            continue;
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(paused.tick_period()))
            .await
            .is_err()
        {
            // 超时先清 lifecycle 再释放 Store；不能把暂停实例留给后台 timer 或 registry。
            paused.cancel();
            bail!("Proxy-Wasm async resume timeout");
        }
        let tick = tokio::task::spawn_blocking(move || paused.on_tick());
        progress = tokio::time::timeout_at(deadline, tick)
            .await
            .context("Proxy-Wasm async callback timeout")?
            .context("join Proxy-Wasm async callback worker")??;
    }
}

struct StreamingChainSession {
    plugins: Vec<StreamingPluginInstance>,
}

struct CancelOnDropBody {
    inner: http_body_util::channel::Channel<Bytes, crate::BoxError>,
    cancellation: tokio_util::sync::CancellationToken,
}

impl hyper::body::Body for CancelOnDropBody {
    type Data = Bytes;
    type Error = crate::BoxError;

    /// 业务作用：把 channel frame 透明交付给下游，同时由外层 Drop 单独管理 producer 取消。
    ///
    /// 参数说明：`cx` 是下游 body poll 的唤醒上下文。
    ///
    /// 返回：返回 channel 当前 frame、错误、EOF 或 Pending，不改变插件执行语义。
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        hyper::body::Body::poll_frame(std::pin::Pin::new(&mut this.inner), cx)
    }
}

impl Drop for CancelOnDropBody {
    fn drop(&mut self) {
        // 下游取消必须立即打断 producer 对上游下一 frame 的等待，随后 session Drop 执行 lifecycle。
        self.cancellation.cancel();
    }
}

impl StreamingChainSession {
    /// 业务作用：在发布 streaming body 前完成全部插件 lifecycle，按 fail-open 原子筛除失败实例。
    ///
    /// 参数说明：`plugins` 是构建期固定顺序，`input` 固定流方向与只读 head。
    ///
    /// 返回：fail-closed lifecycle 失败则拒绝安装 body；否则返回持久实例链。
    async fn start(plugins: &[Arc<WasmPlugin>], input: PhaseInput) -> Result<Self> {
        let mut instances = Vec::with_capacity(plugins.len());
        for plugin in plugins {
            let plugin = plugin.clone();
            let plugin_id = plugin.id.clone();
            let fail_open = plugin.fail_open;
            let plugin_input = input.clone_for_plugin();
            let started = tokio::task::spawn_blocking(move || plugin.start_streaming(plugin_input))
                .await
                .context("join Proxy-Wasm streaming lifecycle worker")?;
            match started {
                Ok(instance) => instances.push(instance),
                Err(error) if fail_open => {
                    tracing::warn!(plugin = %plugin_id, %error, "Proxy-Wasm streaming plugin failed open during lifecycle");
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Proxy-Wasm streaming plugin `{plugin_id}` lifecycle failed")
                    });
                }
            }
        }
        Ok(Self { plugins: instances })
    }

    /// 业务作用：按固定顺序让每个持久插件处理当前 frame，并隔离 fail-open 的半完成改写。
    ///
    /// 参数说明：`body` 是当前 frame，`end_of_stream` 标识无 trailers 的最终 DATA。
    ///
    /// 返回：全部继续时返回最终 frame；fail-open 插件被永久摘除且沿用其输入；fail-closed 终止 body。
    async fn process_frame(&mut self, body: Bytes, end_of_stream: bool) -> Result<Bytes> {
        let mut current = body;
        let mut survivors = Vec::with_capacity(self.plugins.len());
        for instance in std::mem::take(&mut self.plugins) {
            let plugin_id = instance.plugin.id.clone();
            let fail_open = instance.plugin.fail_open;
            let original = current.clone();
            match process_stream_frame(instance, current, end_of_stream).await {
                Ok((instance, output)) => {
                    survivors.push(instance);
                    current = output;
                }
                Err(error) if fail_open => {
                    tracing::warn!(plugin = %plugin_id, %error, "Proxy-Wasm streaming frame failed open; plugin removed from stream");
                    current = original;
                }
                Err(error) => {
                    self.plugins = survivors;
                    return Err(error).with_context(|| {
                        format!("Proxy-Wasm streaming plugin `{plugin_id}` failed")
                    });
                }
            }
        }
        self.plugins = survivors;
        Ok(current)
    }

    /// 业务作用：在 body EOF 后完成所有持久插件 lifecycle，确保正常流不会依赖 Drop 补偿。
    ///
    /// 参数说明：无。
    ///
    /// 返回：全部 cleanup 成功返回 OK；任一 trap 返回错误并继续 Drop 其余实例。
    async fn finish(mut self) -> Result<()> {
        let instances = std::mem::take(&mut self.plugins);
        tokio::task::spawn_blocking(move || {
            for mut instance in instances {
                instance.finish()?;
            }
            Ok(())
        })
        .await
        .context("join Proxy-Wasm streaming cleanup worker")?
    }
}

/// 业务作用：在单一墙钟 deadline 内驱动一个持久插件的 frame callback、callout 与 timer 恢复。
///
/// 参数说明：`instance` 是当前流独占 context，`body`/`end_of_stream` 描述当前 frame。
///
/// 返回：恢复成功时连同实例返回改写 frame；trap、超时或悬空 PAUSE 返回错误并触发实例 cleanup。
async fn process_stream_frame(
    mut instance: StreamingPluginInstance,
    body: Bytes,
    end_of_stream: bool,
) -> Result<(StreamingPluginInstance, Bytes)> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(instance.plugin.limits.timeout_ms);
    let started = tokio::task::spawn_blocking(move || {
        let progress = instance.begin_frame(body, end_of_stream);
        (instance, progress)
    });
    let (mut instance, mut progress) = tokio::time::timeout_at(deadline, started)
        .await
        .context("Proxy-Wasm streaming callback timeout")?
        .context("join Proxy-Wasm streaming callback worker")?;
    loop {
        match progress? {
            StreamFrameProgress::Ready(output) => return Ok((instance, output)),
            StreamFrameProgress::Paused => {}
        }
        if let Some(callout) = instance.take_callout() {
            let plugin = instance.plugin.clone();
            let completed = tokio::time::timeout_at(
                deadline,
                execute_pending_callout(plugin.as_ref(), callout),
            )
            .await
            .context("Proxy-Wasm streaming callout timeout")?;
            let callback = tokio::task::spawn_blocking(move || {
                let progress = instance.on_callout(completed);
                (instance, progress)
            });
            (instance, progress) = tokio::time::timeout_at(deadline, callback)
                .await
                .context("Proxy-Wasm streaming callout callback timeout")?
                .context("join Proxy-Wasm streaming callout callback worker")?;
            continue;
        }
        let period = instance.tick_period();
        tokio::time::timeout_at(deadline, tokio::time::sleep(period))
            .await
            .context("Proxy-Wasm streaming async resume timeout")?;
        let tick = tokio::task::spawn_blocking(move || {
            let progress = instance.on_tick();
            (instance, progress)
        });
        (instance, progress) = tokio::time::timeout_at(deadline, tick)
            .await
            .context("Proxy-Wasm streaming timer callback timeout")?
            .context("join Proxy-Wasm streaming timer callback worker")?;
    }
}

/// 业务作用：用容量 1 的 channel 把上游 body、逐 frame Wasm 会话与下游 poll 背压连接起来。
///
/// 参数说明：`source` 是原 body，`session` 是已完成 lifecycle 的持久插件链。
///
/// 返回：返回不聚合完整 body 的 boxed stream；取消、源错误或插件失败都会停止 producer 并清理 context。
fn spawn_streaming_body(mut source: BoxBody, mut session: StreamingChainSession) -> BoxBody {
    let (mut sender, body) = http_body_util::channel::Channel::<Bytes, crate::BoxError>::new(1);
    let cancellation = tokio_util::sync::CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let mut saw_trailers = false;
        loop {
            let frame = tokio::select! {
                _ = worker_cancellation.cancelled() => return,
                frame = source.frame() => frame,
            };
            let Some(frame) = frame else {
                if !saw_trailers {
                    match session.process_frame(Bytes::new(), true).await {
                        Ok(output) if !output.is_empty() => {
                            let sent = tokio::select! {
                                _ = worker_cancellation.cancelled() => return,
                                sent = sender.send_data(output) => sent,
                            };
                            if sent.is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, "Proxy-Wasm streaming EOF callback failed");
                            sender.abort(Box::new(std::io::Error::other(
                                "Proxy-Wasm streaming EOF callback failed",
                            )));
                            return;
                        }
                    }
                }
                if let Err(error) = session.finish().await {
                    tracing::warn!(%error, "Proxy-Wasm streaming cleanup failed");
                    sender.abort(Box::new(std::io::Error::other(
                        "Proxy-Wasm streaming cleanup failed",
                    )));
                }
                return;
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => {
                    sender.abort(error);
                    return;
                }
            };
            if frame.is_data() {
                let data = frame
                    .into_data()
                    .expect("is_data guarantees data conversion");
                match session.process_frame(data, false).await {
                    Ok(output) => {
                        let sent = tokio::select! {
                            _ = worker_cancellation.cancelled() => return,
                            sent = sender.send_data(output) => sent,
                        };
                        if sent.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Proxy-Wasm streaming frame failed");
                        sender.abort(Box::new(std::io::Error::other(
                            "Proxy-Wasm streaming frame failed",
                        )));
                        return;
                    }
                }
            } else if let Ok(trailers) = frame.into_trailers() {
                saw_trailers = true;
                let sent = tokio::select! {
                    _ = worker_cancellation.cancelled() => return,
                    sent = sender.send_trailers(trailers) => sent,
                };
                if sent.is_err() {
                    return;
                }
            }
        }
    });
    BodyExt::boxed(CancelOnDropBody {
        inner: body,
        cancellation,
    })
}

/// 业务作用：在 Tokio 网络栈执行已通过 ABI 与白名单校验的 callout，并把传输失败收敛为可回调结果。
///
/// 参数说明：`plugin` 提供固定 cluster 能力与资源门，`callout` 是客体已取得 token 的请求。
///
/// 返回：总会返回同 token 的 HTTP/gRPC callback 结果；网络错误不会遗失 PAUSE 上下文或泄露任意 socket 权限。
async fn execute_pending_callout(plugin: &WasmPlugin, callout: PendingCallout) -> CompletedCallout {
    match callout {
        PendingCallout::Http(callout) => {
            let token = callout.token;
            let response = match execute_http_callout(plugin, callout).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(plugin = %plugin.id, token, %error, "Proxy-Wasm HTTP callout failed");
                    synthetic_http_callout_failure(StatusCode::BAD_GATEWAY)
                }
            };
            CompletedCallout::Http { token, response }
        }
        PendingCallout::Grpc(callout) => {
            let token = callout.token;
            let response = match execute_grpc_callout(plugin, callout).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(plugin = %plugin.id, token, %error, "Proxy-Wasm gRPC callout failed");
                    synthetic_grpc_callout_failure(14)
                }
            };
            CompletedCallout::Grpc { token, response }
        }
    }
}

/// 业务作用：向固定 cluster origin 发起一次受总 deadline、无重定向和响应字节门保护的 HTTP callout。
///
/// 参数说明：`plugin` 提供不可变能力表，`callout` 包含 origin-relative path 与有界 head/body。
///
/// 返回：成功返回完整有界 response head/body/trailers；TLS、超时、framing 或资源越界返回错误。
async fn execute_http_callout(
    plugin: &WasmPlugin,
    callout: HttpCallout,
) -> Result<CalloutResponse> {
    let cluster = plugin
        .callout_clusters
        .get(&callout.cluster)
        .context("callout cluster disappeared from immutable snapshot")?;
    let url = cluster
        .origin
        .join(&callout.path)
        .context("join callout origin-relative path")?;
    let response = cluster
        .client
        .request(callout.method, url)
        .headers(callout.headers)
        .body(callout.body)
        .timeout(Duration::from_millis(callout.timeout_ms))
        .send()
        .await
        .context("send Proxy-Wasm HTTP callout")?;
    collect_callout_response(
        response,
        plugin.limits.max_callout_response_bytes,
        plugin.limits.max_header_bytes,
    )
    .await
}

/// 业务作用：把 unary gRPC callout 编码为标准五字节 envelope，并验证返回的单消息与 grpc-status。
///
/// 参数说明：`plugin` 提供固定 cluster，`callout` 提供受限 service/method、metadata 与 protobuf message。
///
/// 返回：成功返回解帧后的 message 和 metadata；压缩、畸形 envelope、缺失状态或资源越界返回错误。
async fn execute_grpc_callout(
    plugin: &WasmPlugin,
    callout: GrpcCallout,
) -> Result<CalloutResponse> {
    let cluster = plugin
        .callout_clusters
        .get(&callout.cluster)
        .context("gRPC callout cluster disappeared from immutable snapshot")?;
    let path = format!("/{}/{}", callout.service, callout.method);
    let url = cluster
        .origin
        .join(&path)
        .context("join gRPC callout method path")?;
    let mut frame = Vec::with_capacity(callout.message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(
        &u32::try_from(callout.message.len())
            .context("gRPC callout message exceeds u32")?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&callout.message);
    let mut metadata = callout.metadata;
    metadata.remove(http::header::CONTENT_LENGTH);
    metadata.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    metadata.insert(http::header::TE, HeaderValue::from_static("trailers"));
    let response = cluster
        .client
        .post(url)
        .headers(metadata)
        .body(frame)
        .timeout(Duration::from_millis(callout.timeout_ms))
        .send()
        .await
        .context("send Proxy-Wasm gRPC callout")?;
    let mut response = collect_callout_response(
        response,
        plugin.limits.max_callout_response_bytes.saturating_add(5),
        plugin.limits.max_header_bytes,
    )
    .await?;
    let content_type = response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with("application/grpc") {
        bail!("gRPC callout returned non-gRPC content-type");
    }
    let grpc_status = parse_grpc_status(&response)
        .or_else(|| (!response.status.is_success()).then_some(14))
        .context("gRPC callout response omitted grpc-status")?;
    response.grpc_status = Some(grpc_status);
    if grpc_status == 0 {
        if response.body.len() < 5 || response.body[0] != 0 {
            bail!("gRPC callout returned missing or compressed unary envelope");
        }
        let declared = u32::from_be_bytes(
            response.body[1..5]
                .try_into()
                .expect("gRPC envelope prefix length checked"),
        ) as usize;
        if declared != response.body.len() - 5
            || declared > plugin.limits.max_callout_response_bytes
        {
            bail!("gRPC callout returned malformed or oversized unary envelope");
        }
        response.body = response.body.slice(5..);
    } else {
        response.body = Bytes::new();
    }
    Ok(response)
}

/// 业务作用：逐 frame 收集 callout response，同时保留 HTTP trailers 并在追加前执行资源硬门。
///
/// 参数说明：`response` 是 reqwest 已建立的响应，`max_body`/`max_headers` 是构建期预算。
///
/// 返回：成功返回完整有界响应；DATA、trailers 或 header 超限立即取消 body 并失败。
async fn collect_callout_response(
    response: reqwest::Response,
    max_body: usize,
    max_headers: usize,
) -> Result<CalloutResponse> {
    let response: http::Response<reqwest::Body> = response.into();
    let (parts, mut body) = response.into_parts();
    ensure_header_budget(&parts.headers, max_headers)?;
    let mut bytes = Vec::new();
    let mut trailers = HeaderMap::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("read Proxy-Wasm callout response frame")?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > max_body {
                bail!("Proxy-Wasm callout response exceeds max_callout_response_bytes");
            }
            bytes.extend_from_slice(data);
        }
        if let Some(received) = frame.trailers_ref() {
            for (name, value) in received {
                trailers.append(name.clone(), value.clone());
            }
            ensure_header_budget(&trailers, max_headers)?;
        }
    }
    Ok(CalloutResponse {
        status: parts.status,
        headers: parts.headers,
        trailers,
        body: Bytes::from(bytes),
        grpc_status: None,
    })
}

/// 业务作用：从 gRPC response trailers 优先、headers 兼容读取规范状态码。
///
/// 参数说明：`response` 是已完整收集且未向客体暴露的 callout 响应。
///
/// 返回：合法 0..=16 返回状态；缺失或畸形返回空并由调用方故障关闭。
fn parse_grpc_status(response: &CalloutResponse) -> Option<u32> {
    response
        .trailers
        .get("grpc-status")
        .or_else(|| response.headers.get("grpc-status"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value <= 16)
}

/// 业务作用：把已接受 HTTP callout 的传输失败转换为无敏感细节的确定性 callback 响应。
///
/// 参数说明：`status` 是宿主选择的网关错误状态。
///
/// 返回：返回空 body/trailers 与固定错误类别 header，供客体决定恢复或本地响应。
fn synthetic_http_callout_failure(status: StatusCode) -> CalloutResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-naway-callout-error"),
        HeaderValue::from_static("transport"),
    );
    CalloutResponse {
        status,
        headers,
        trailers: HeaderMap::new(),
        body: Bytes::new(),
        grpc_status: None,
    }
}

/// 业务作用：把已接受 gRPC callout 的传输失败转换为标准 grpc-status callback。
///
/// 参数说明：`status` 是受限 gRPC canonical status code。
///
/// 返回：返回不携带上游错误细节的空响应，避免敏感网络信息进入客体。
fn synthetic_grpc_callout_failure(status: u32) -> CalloutResponse {
    CalloutResponse {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        trailers: HeaderMap::new(),
        body: Bytes::new(),
        grpc_status: Some(status.min(16)),
    }
}

/// 业务作用：依次执行同一 HTTP phase 的插件，以成功结果推进链路并隔离 fail-open 半完成写。
///
/// 参数说明：`plugins` 是构建期固定顺序，`input` 是本 phase 的初始 head/body。
///
/// 返回：全部继续时返回最终原子输出；local response 短路；fail-closed 错误停止管线。
async fn execute_chain(
    plugins: &[Arc<WasmPlugin>],
    mut input: PhaseInput,
) -> Result<ChainExecution> {
    let mut failed_open = 0u64;
    for plugin in plugins {
        // 每个客体收到当前链路 head 的廉价 clone。成功才用返回 head 推进链路；
        // fail-open 时丢弃本客体的部分写，不会污染前一插件已提交的结果。
        let plugin_input = input.clone_for_plugin();
        match invoke_plugin(plugin.clone(), plugin_input).await {
            Ok(InvocationOutcome::Continue(output)) => {
                input.current_headers = output.headers;
                input.body = output.body;
            }
            Ok(InvocationOutcome::Local(response)) => {
                return Ok(ChainExecution {
                    outcome: ChainOutcome::Local(response),
                    failed_open,
                });
            }
            Err(error) if plugin.fail_open => {
                failed_open = failed_open.saturating_add(1);
                tracing::warn!(plugin = %plugin.id, %error, "Proxy-Wasm plugin failed open");
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Proxy-Wasm plugin `{}` failed", plugin.id));
            }
        }
    }
    Ok(ChainExecution {
        outcome: ChainOutcome::Continue(PhaseOutput {
            headers: input.current_headers,
            body: input.body,
        }),
        failed_open,
    })
}

struct ChainExecution {
    outcome: ChainOutcome,
    failed_open: u64,
}

enum ChainOutcome {
    Continue(PhaseOutput),
    Local(LocalResponse),
}

enum InvocationOutcome {
    Continue(PhaseOutput),
    Local(LocalResponse),
}

struct PhaseOutput {
    headers: HeaderMap,
    body: Option<Bytes>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WasmPhase {
    RequestHeaders,
    RequestBody,
    RequestBodyStream,
    ResponseHeaders,
    ResponseBody,
    ResponseBodyStream,
}

struct PhaseInput {
    phase: WasmPhase,
    current_headers: HeaderMap,
    request_headers: Option<HeaderMap>,
    method: String,
    path: String,
    authority: String,
    scheme: String,
    end_of_stream: bool,
    body: Option<Bytes>,
}

impl PhaseInput {
    /// 业务作用：为单个插件创建原子工作副本，避免 trap/fail-open 污染上一插件已提交状态。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回共享 Bytes/HeaderValue 底层字节、但可独立替换 head/body 的输入副本。
    fn clone_for_plugin(&self) -> Self {
        Self {
            phase: self.phase,
            current_headers: self.current_headers.clone(),
            request_headers: self.request_headers.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            authority: self.authority.clone(),
            scheme: self.scheme.clone(),
            end_of_stream: self.end_of_stream,
            body: self.body.clone(),
        }
    }
}

struct HostState {
    phase: WasmPhase,
    current_headers: HeaderMap,
    request_headers: Option<HeaderMap>,
    method: String,
    path: String,
    authority: String,
    scheme: String,
    end_of_stream: bool,
    body: Option<Bytes>,
    plugin_config: Arc<[u8]>,
    limits: InvocationLimits,
    mutations: usize,
    local_response: Option<LocalResponse>,
    tick_period_ms: Option<u64>,
    continue_requested: bool,
    done_requested: bool,
    effective_context: i32,
    pending_callouts: VecDeque<PendingCallout>,
    callout_count: usize,
    next_callout_token: u32,
    callout_response: Option<CalloutResponse>,
    callout_clusters: Arc<HashMap<String, CalloutCluster>>,
    shared: Arc<WasmSharedState>,
    store_limits: StoreLimits,
}

impl HostState {
    /// 业务作用：创建仅供 snapshot build 实例化校验的空宿主状态，不执行业务 lifecycle。
    ///
    /// 参数说明：`plugin_config` 是序列化配置，`limits` 是构建期已校验资源预算。
    ///
    /// 返回：返回可用于验证 import 精确签名与初始内存的状态。
    fn validation(
        plugin_config: Arc<[u8]>,
        limits: InvocationLimits,
        callout_clusters: Arc<HashMap<String, CalloutCluster>>,
        shared: Arc<WasmSharedState>,
    ) -> Self {
        Self {
            phase: WasmPhase::RequestHeaders,
            current_headers: HeaderMap::new(),
            request_headers: None,
            method: "GET".to_owned(),
            path: "/".to_owned(),
            authority: String::new(),
            scheme: "http".to_owned(),
            end_of_stream: true,
            body: None,
            plugin_config,
            limits,
            mutations: 0,
            local_response: None,
            tick_period_ms: None,
            continue_requested: false,
            done_requested: false,
            effective_context: 2,
            pending_callouts: VecDeque::new(),
            callout_count: 0,
            next_callout_token: 1,
            callout_response: None,
            callout_clusters,
            shared,
            store_limits: store_limits(limits),
        }
    }

    /// 业务作用：把单插件输入转为有资源边界的宿主状态，并在进入 Wasm 前复验 head/body 大小。
    ///
    /// 参数说明：`input` 是插件独享副本，`plugin_config` 是配置，`limits` 是硬预算。
    ///
    /// 返回：预算有效时返回运行态；越界时在客体指令执行前失败。
    fn new(
        input: PhaseInput,
        plugin_config: Arc<[u8]>,
        limits: InvocationLimits,
        callout_clusters: Arc<HashMap<String, CalloutCluster>>,
        shared: Arc<WasmSharedState>,
    ) -> Result<Self> {
        ensure_header_budget(&input.current_headers, limits.max_header_bytes)?;
        if let Some(headers) = &input.request_headers {
            ensure_header_budget(headers, limits.max_header_bytes)?;
        }
        if input
            .body
            .as_ref()
            .is_some_and(|body| body.len() > limits.max_body_bytes)
        {
            bail!("Proxy-Wasm body exceeds max_body_bytes");
        }
        Ok(Self {
            phase: input.phase,
            current_headers: input.current_headers,
            request_headers: input.request_headers,
            method: input.method,
            path: input.path,
            authority: input.authority,
            scheme: input.scheme,
            end_of_stream: input.end_of_stream,
            body: input.body,
            plugin_config,
            limits,
            mutations: 0,
            local_response: None,
            tick_period_ms: None,
            continue_requested: false,
            done_requested: false,
            effective_context: 2,
            pending_callouts: VecDeque::new(),
            callout_count: 0,
            next_callout_token: 1,
            callout_response: None,
            callout_clusters,
            shared,
            store_limits: store_limits(limits),
        })
    }

    fn take_current_headers(&mut self) -> HeaderMap {
        std::mem::take(&mut self.current_headers)
    }

    /// 业务作用：在插件成功结束时一次性取走可提交的 head/body，保持 fail-open 原子性。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回本次实例最终 header 与可选 body；调用后 HostState 中对应值为空。
    fn take_output(&mut self) -> PhaseOutput {
        PhaseOutput {
            headers: self.take_current_headers(),
            body: self.body.take(),
        }
    }

    fn headers(&self, map_type: i32) -> Option<&HeaderMap> {
        match map_type {
            MAP_REQUEST_HEADERS
                if matches!(
                    self.phase,
                    WasmPhase::RequestHeaders
                        | WasmPhase::RequestBody
                        | WasmPhase::RequestBodyStream
                ) =>
            {
                Some(&self.current_headers)
            }
            MAP_REQUEST_HEADERS => self.request_headers.as_ref(),
            MAP_RESPONSE_HEADERS
                if matches!(
                    self.phase,
                    WasmPhase::ResponseHeaders
                        | WasmPhase::ResponseBody
                        | WasmPhase::ResponseBodyStream
                ) =>
            {
                Some(&self.current_headers)
            }
            MAP_HTTP_CALLOUT_RESPONSE_HEADERS => self
                .callout_response
                .as_ref()
                .map(|response| &response.headers),
            MAP_GRPC_RECEIVE_INITIAL_METADATA => self
                .callout_response
                .as_ref()
                .map(|response| &response.headers),
            MAP_GRPC_RECEIVE_TRAILING_METADATA => self
                .callout_response
                .as_ref()
                .map(|response| &response.trailers),
            MAP_HTTP_CALLOUT_RESPONSE_TRAILERS => self
                .callout_response
                .as_ref()
                .map(|response| &response.trailers),
            _ => None,
        }
    }

    fn writable_headers(&mut self, map_type: i32) -> Option<&mut HeaderMap> {
        match map_type {
            MAP_REQUEST_HEADERS
                if matches!(
                    self.phase,
                    WasmPhase::RequestHeaders | WasmPhase::RequestBody
                ) =>
            {
                Some(&mut self.current_headers)
            }
            MAP_RESPONSE_HEADERS
                if matches!(
                    self.phase,
                    WasmPhase::ResponseHeaders | WasmPhase::ResponseBody
                ) =>
            {
                Some(&mut self.current_headers)
            }
            _ => None,
        }
    }

    fn count_mutation(&mut self) -> Result<()> {
        self.mutations = self.mutations.saturating_add(1);
        if self.mutations > self.limits.max_mutations {
            bail!("Proxy-Wasm mutation budget exceeded");
        }
        Ok(())
    }
}

fn store_limits(limits: InvocationLimits) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(limits.max_memory_bytes)
        .memories(1)
        .tables(4)
        .table_elements(65_536)
        .instances(1)
        .trap_on_grow_failure(true)
        .build()
}

struct LocalResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    grpc_status: Option<i32>,
}

impl LocalResponse {
    fn into_http(self) -> Result<Response<BoxBody>> {
        let mut response = Response::new(full_body(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        if let Some(status) = self.grpc_status {
            response.headers_mut().insert(
                HeaderName::from_static("grpc-status"),
                HeaderValue::from_str(&status.to_string()).context("encode grpc-status")?,
            );
        }
        Ok(response)
    }
}

/// 业务作用：初始化进程共享的 Wasm engine，并启动 epoch ticker 为扩展执行提供可抢占的时间边界。
///
/// 参数说明：无。
///
/// 返回：初始化成功时返回全局 engine；配置、线程或 engine 创建失败时返回错误并拒绝加载扩展。
fn engine() -> Result<&'static Engine> {
    match WASM_ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.wasm_multi_memory(false);
        let engine = Engine::new(&config).map_err(|error| error.to_string())?;
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("naway-wasm-epoch".to_owned())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                ticker.increment_epoch();
            })
            .map_err(|error| error.to_string())?;
        Ok(engine)
    }) {
        Ok(engine) => Ok(engine),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

/// 业务作用：把配置中的 callout 上游编译成无重定向、固定 TLS 信任与固定 origin 的能力表。
///
/// 参数说明：`cfg` 提供白名单声明，`config_dir` 用于解析 CA SecretSource。
///
/// 返回：全部 origin 与证书合法时返回不可变能力表；重复名称或可变 URL 组成会拒绝快照。
fn build_callout_clusters(
    cfg: &WasmPluginCfg,
    config_dir: &Path,
) -> Result<HashMap<String, CalloutCluster>> {
    if cfg.callout_clusters.len() > MAX_CALLOUT_CLUSTERS {
        bail!("callout_clusters supports at most {MAX_CALLOUT_CLUSTERS} entries");
    }
    let mut clusters = HashMap::with_capacity(cfg.callout_clusters.len());
    for cluster in &cfg.callout_clusters {
        if cluster.name.is_empty() || cluster.name.len() > MAX_PLUGIN_ID_BYTES {
            bail!("callout cluster name must contain 1..={MAX_PLUGIN_ID_BYTES} bytes");
        }
        let origin = reqwest::Url::parse(&cluster.origin)
            .with_context(|| format!("invalid callout cluster `{}` origin", cluster.name))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            bail!(
                "callout cluster `{}` origin must be an http(s) origin without credentials/path/query/fragment",
                cluster.name
            );
        }
        if origin.scheme() == "http" && !cluster.allow_cleartext {
            bail!(
                "callout cluster `{}` uses cleartext HTTP without allow_cleartext=true",
                cluster.name
            );
        }
        let mut client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if cluster.http2_prior_knowledge {
            if origin.scheme() != "http" || !cluster.allow_cleartext {
                bail!(
                    "callout cluster `{}` http2_prior_knowledge requires an explicitly allowed cleartext origin",
                    cluster.name
                );
            }
            client = client.http2_prior_knowledge();
        }
        if !cluster.ca_certificate.trim().is_empty() {
            let pem = crate::secret::resolve_text(
                &cluster.ca_certificate,
                config_dir,
                "Proxy-Wasm callout CA certificate",
            )?;
            let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
                .context("invalid Proxy-Wasm callout CA certificate")?;
            client = client.add_root_certificate(certificate);
        }
        if clusters
            .insert(
                cluster.name.clone(),
                CalloutCluster {
                    origin,
                    client: client.build().context("build Proxy-Wasm callout client")?,
                },
            )
            .is_some()
        {
            bail!("duplicate callout cluster `{}`", cluster.name);
        }
    }
    Ok(clusters)
}

/// 业务作用：在构建模块前校验 route 可配置预算，防止零上限或超硬门资源声明进入运行期。
///
/// 参数说明：`cfg` 是单个 Proxy-Wasm 插件配置。
///
/// 返回：全部标识、路径和资源预算合法时成功，否则拒绝候选快照。
fn validate_cfg(cfg: &WasmPluginCfg) -> Result<()> {
    if cfg.id.is_empty() || cfg.id.len() > MAX_PLUGIN_ID_BYTES {
        bail!("id must contain 1..={MAX_PLUGIN_ID_BYTES} bytes");
    }
    if cfg.module_file.trim().is_empty() == cfg.module_source.is_none() {
        bail!("exactly one of module_file or module_source must be configured");
    }
    if let Some(source) = &cfg.module_source {
        if source.reference.is_empty()
            || source.reference.len() > MAX_WASM_SOURCE_REFERENCE_BYTES
            || !matches!(source.timeout_ms, 100..=30_000)
        {
            bail!("module_source reference or timeout is outside safe bounds");
        }
        normalize_sha256(source.sha256.as_str(), "Wasm module sha256")?;
        let signature = !source.signature.trim().is_empty();
        let public_key = !source.public_key.trim().is_empty();
        if signature != public_key {
            bail!("module_source signature and public_key must be configured together");
        }
        if !signature && source.attestation.is_none() {
            bail!("remote Wasm source requires a signature or signed in-toto attestation");
        }
        if let Some(attestation) = &source.attestation {
            if attestation.statement.trim().is_empty()
                || attestation.signature.trim().is_empty()
                || attestation.public_key.trim().is_empty()
                || attestation.predicate_type.trim().is_empty()
                || attestation.predicate_type.len() > 1024
                || attestation.builder_id.trim().is_empty()
                || attestation.builder_id.len() > 1024
                || attestation.subject_name.len() > 1024
            {
                bail!("module_source attestation contains an empty or oversized trust constraint");
            }
        }
        if source.reference.starts_with("oci://") {
            parse_oci_reference(source)?;
        } else {
            validate_https_module_url(source.reference.as_str())?;
            if !source.manifest_sha256.trim().is_empty() {
                bail!("module_source manifest_sha256 is only valid for OCI references");
            }
        }
    }
    if !(1..=MAX_MODULE_BYTES_HARD).contains(&cfg.max_module_bytes) {
        bail!("max_module_bytes must be within 1..={MAX_MODULE_BYTES_HARD}");
    }
    if !(64 * 1024..=MAX_MEMORY_BYTES_HARD).contains(&cfg.max_memory_bytes) {
        bail!("max_memory_bytes must be within 65536..={MAX_MEMORY_BYTES_HARD}");
    }
    if !(1..=MAX_FUEL_HARD).contains(&cfg.max_fuel) {
        bail!("max_fuel must be within 1..={MAX_FUEL_HARD}");
    }
    if !(1..=MAX_TIMEOUT_MS).contains(&cfg.timeout_ms) {
        bail!("timeout_ms must be within 1..={MAX_TIMEOUT_MS}");
    }
    if !(1..=MAX_MUTATIONS_HARD).contains(&cfg.max_mutations) {
        bail!("max_mutations must be within 1..={MAX_MUTATIONS_HARD}");
    }
    if !(1..=MAX_HEADER_BYTES_HARD).contains(&cfg.max_header_bytes) {
        bail!("max_header_bytes must be within 1..={MAX_HEADER_BYTES_HARD}");
    }
    if !(1..=MAX_BODY_BYTES_HARD).contains(&cfg.max_body_bytes) {
        bail!("max_body_bytes must be within 1..={MAX_BODY_BYTES_HARD}");
    }
    if !(1..=MAX_LOCAL_RESPONSE_BODY_BYTES_HARD).contains(&cfg.max_local_response_body_bytes) {
        bail!(
            "max_local_response_body_bytes must be within 1..={MAX_LOCAL_RESPONSE_BODY_BYTES_HARD}"
        );
    }
    if !(1..=MAX_CALLOUTS_HARD).contains(&cfg.max_callouts) {
        bail!("max_callouts must be within 1..={MAX_CALLOUTS_HARD}");
    }
    if !(1..=MAX_BODY_BYTES_HARD).contains(&cfg.max_callout_response_bytes) {
        bail!("max_callout_response_bytes must be within 1..={MAX_BODY_BYTES_HARD}");
    }
    if !(1..=MAX_SHARED_ENTRIES_HARD).contains(&cfg.max_shared_entries) {
        bail!("max_shared_entries must be within 1..={MAX_SHARED_ENTRIES_HARD}");
    }
    if !(1..=MAX_SHARED_BYTES_HARD).contains(&cfg.max_shared_bytes) {
        bail!("max_shared_bytes must be within 1..={MAX_SHARED_BYTES_HARD}");
    }
    if !(1..=MAX_SHARED_QUEUES_HARD).contains(&cfg.max_shared_queues) {
        bail!("max_shared_queues must be within 1..={MAX_SHARED_QUEUES_HARD}");
    }
    if !(1..=MAX_QUEUE_ENTRIES_HARD).contains(&cfg.max_queue_entries) {
        bail!("max_queue_entries must be within 1..={MAX_QUEUE_ENTRIES_HARD}");
    }
    if !(1..=MAX_METRICS_HARD).contains(&cfg.max_metrics) {
        bail!("max_metrics must be within 1..={MAX_METRICS_HARD}");
    }
    if cfg.shared_namespace.len() > MAX_PLUGIN_ID_BYTES {
        bail!("shared_namespace exceeds {MAX_PLUGIN_ID_BYTES} bytes");
    }
    Ok(())
}

/// 业务作用：强制模块只使用明确白名单 hostcall，阻止 WASI、socket、文件和未知能力越权。
///
/// 参数说明：`module` 是已编译但尚未发布的候选模块。
///
/// 返回：全部 import 属于 `env` 函数白名单时成功，否则拒绝快照。
fn validate_imports(module: &Module) -> Result<()> {
    for import in module.imports() {
        if import.module() != "env" {
            bail!(
                "WASI/non-env import `{}.{}` is forbidden",
                import.module(),
                import.name()
            );
        }
        if !matches!(import.ty(), ExternType::Func(_)) || !supported_import(import.name()) {
            bail!("unsupported Proxy-Wasm import `env.{}`", import.name());
        }
    }
    Ok(())
}

/// 业务作用：判断一个 `env` import 是否属于 naway 明确实现的 Proxy-Wasm 能力面。
///
/// 参数说明：`name` 是客体请求的 import 名称。
///
/// 返回：受支持时返回 `true`；未知能力必须 fail closed。
fn supported_import(name: &str) -> bool {
    matches!(
        name,
        "proxy_log"
            | "proxy_get_log_level"
            | "proxy_get_current_time_nanoseconds"
            | "proxy_get_buffer_bytes"
            | "proxy_set_buffer_bytes"
            | "proxy_get_header_map_size"
            | "proxy_get_header_map_pairs"
            | "proxy_set_header_map_pairs"
            | "proxy_get_header_map_value"
            | "proxy_add_header_map_value"
            | "proxy_replace_header_map_value"
            | "proxy_remove_header_map_value"
            | "proxy_send_local_response"
            | "proxy_get_property"
            | "proxy_set_property"
            | "proxy_get_shared_data"
            | "proxy_set_shared_data"
            | "proxy_register_shared_queue"
            | "proxy_resolve_shared_queue"
            | "proxy_enqueue_shared_queue"
            | "proxy_dequeue_shared_queue"
            | "proxy_define_metric"
            | "proxy_increment_metric"
            | "proxy_record_metric"
            | "proxy_get_metric"
            | "proxy_http_call"
            | "proxy_grpc_call"
            | "proxy_grpc_cancel"
            | "proxy_grpc_stream"
            | "proxy_grpc_send"
            | "proxy_grpc_close"
            | "proxy_get_status"
            | "proxy_close_stream"
            | "proxy_call_foreign_function"
            | "proxy_set_tick_period_milliseconds"
            | "proxy_continue_stream"
            | "proxy_set_effective_context"
            | "proxy_done"
    )
}

/// 业务作用：构建无 WASI 的 Proxy-Wasm linker，集中安装有界 header/body/timer hostcall。
///
/// 参数说明：`engine` 是进程共享、开启 fuel 与 epoch interruption 的 Wasmtime engine。
///
/// 返回：全部 hostcall 签名注册成功时返回 linker，否则拒绝实例化。
fn build_linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    linker.func_wrap(
        "env",
        "proxy_log",
        |mut caller: Caller<'_, HostState>, level: i32, ptr: i32, size: i32| -> i32 {
            host_status((|| {
                let message = read_guest(&mut caller, ptr, size, 16 * 1024)?;
                let message = String::from_utf8_lossy(&message);
                match level {
                    0 | 1 => tracing::trace!(target: "naway::wasm", %message),
                    2 => tracing::debug!(target: "naway::wasm", %message),
                    3 => tracing::info!(target: "naway::wasm", %message),
                    4 => tracing::warn!(target: "naway::wasm", %message),
                    _ => tracing::error!(target: "naway::wasm", %message),
                }
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_log_level",
        |mut caller: Caller<'_, HostState>, out: i32| -> i32 {
            host_status(write_i32(&mut caller, out, 2))
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_current_time_nanoseconds",
        |mut caller: Caller<'_, HostState>, out: i32| -> i32 {
            host_status((|| {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .context("system clock before Unix epoch")?
                    .as_nanos();
                let nanos = u64::try_from(nanos).context("current time exceeds u64 nanos")?;
                write_bytes(&mut caller, out, &nanos.to_le_bytes())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_buffer_bytes",
        |mut caller: Caller<'_, HostState>,
         buffer_type: i32,
         start: i32,
         max_size: i32,
         out_ptr: i32,
         out_size: i32|
         -> i32 {
            host_status((|| {
                if start < 0 || max_size < 0 {
                    bail!("negative buffer slice");
                }
                let source: &[u8] = match buffer_type {
                    BUFFER_HTTP_REQUEST_BODY
                        if matches!(
                            caller.data().phase,
                            WasmPhase::RequestBody | WasmPhase::RequestBodyStream
                        ) =>
                    {
                        caller.data().body.as_deref().unwrap_or_default()
                    }
                    BUFFER_HTTP_RESPONSE_BODY
                        if matches!(
                            caller.data().phase,
                            WasmPhase::ResponseBody | WasmPhase::ResponseBodyStream
                        ) =>
                    {
                        caller.data().body.as_deref().unwrap_or_default()
                    }
                    BUFFER_HTTP_CALLOUT_RESPONSE_BODY => caller
                        .data()
                        .callout_response
                        .as_ref()
                        .map(|response| response.body.as_ref())
                        .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?,
                    BUFFER_GRPC_RECEIVE => caller
                        .data()
                        .callout_response
                        .as_ref()
                        .map(|response| response.body.as_ref())
                        .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?,
                    BUFFER_PLUGIN_CONFIGURATION => &caller.data().plugin_config,
                    BUFFER_VM_CONFIGURATION => &[],
                    _ => return Err(HostError::Status(PROXY_STATUS_NOT_FOUND).into()),
                };
                let start = start as usize;
                if start > source.len() {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let end = start.saturating_add(max_size as usize).min(source.len());
                let bytes = source[start..end].to_vec();
                allocate_guest_result(&mut caller, &bytes, out_ptr, out_size)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_set_buffer_bytes",
        |mut caller: Caller<'_, HostState>,
         buffer_type: i32,
         start: i32,
         size: i32,
         value_ptr: i32,
         value_size: i32|
         -> i32 {
            host_status((|| {
                if start < 0 || size < 0 {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let expected = match caller.data().phase {
                    WasmPhase::RequestBody | WasmPhase::RequestBodyStream => {
                        BUFFER_HTTP_REQUEST_BODY
                    }
                    WasmPhase::ResponseBody | WasmPhase::ResponseBodyStream => {
                        BUFFER_HTTP_RESPONSE_BODY
                    }
                    WasmPhase::RequestHeaders | WasmPhase::ResponseHeaders => {
                        return Err(HostError::Status(PROXY_STATUS_NOT_FOUND).into())
                    }
                };
                if buffer_type != expected {
                    return Err(HostError::Status(PROXY_STATUS_NOT_FOUND).into());
                }
                let max = caller.data().limits.max_body_bytes;
                let replacement = read_guest(&mut caller, value_ptr, value_size, max)?;
                let mut body = caller.data().body.as_deref().unwrap_or_default().to_vec();
                let start = start as usize;
                let end = start
                    .checked_add(size as usize)
                    .filter(|end| *end <= body.len())
                    .ok_or(HostError::Status(PROXY_STATUS_BAD_ARGUMENT))?;
                let new_len = body
                    .len()
                    .saturating_sub(end - start)
                    .saturating_add(replacement.len());
                if new_len > max {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                caller.data_mut().count_mutation()?;
                body.splice(start..end, replacement);
                caller.data_mut().body = Some(Bytes::from(body));
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_header_map_size",
        |mut caller: Caller<'_, HostState>, map_type: i32, out: i32| -> i32 {
            host_status((|| {
                let count = visible_header_count(caller.data(), map_type)?;
                write_i32(
                    &mut caller,
                    out,
                    i32::try_from(count).context("header count exceeds i32")?,
                )
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_header_map_pairs",
        |mut caller: Caller<'_, HostState>, map_type: i32, out_ptr: i32, out_size: i32| -> i32 {
            host_status((|| {
                let encoded = encode_header_pairs(caller.data(), map_type)?;
                allocate_guest_result(&mut caller, &encoded, out_ptr, out_size)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_set_header_map_pairs",
        |mut caller: Caller<'_, HostState>, map_type: i32, ptr: i32, size: i32| -> i32 {
            host_status((|| {
                let max = caller.data().limits.max_header_bytes;
                let raw = read_guest(&mut caller, ptr, size, max)?;
                let headers = decode_header_pairs(&raw, max)?;
                caller.data_mut().count_mutation()?;
                let target = caller
                    .data_mut()
                    .writable_headers(map_type)
                    .ok_or(HostError::Status(PROXY_STATUS_BAD_ARGUMENT))?;
                *target = headers;
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_header_map_value",
        |mut caller: Caller<'_, HostState>,
         map_type: i32,
         key_ptr: i32,
         key_size: i32,
         out_ptr: i32,
         out_size: i32|
         -> i32 {
            host_status((|| {
                let key = read_guest(&mut caller, key_ptr, key_size, 1024)?;
                let value = get_header_value(caller.data(), map_type, &key)?
                    .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
                allocate_guest_result(&mut caller, &value, out_ptr, out_size)
            })())
        },
    )?;
    for name in [
        "proxy_add_header_map_value",
        "proxy_replace_header_map_value",
    ] {
        let replace = name == "proxy_replace_header_map_value";
        linker.func_wrap(
            "env",
            name,
            move |mut caller: Caller<'_, HostState>,
                  map_type: i32,
                  key_ptr: i32,
                  key_size: i32,
                  value_ptr: i32,
                  value_size: i32|
                  -> i32 {
                host_status((|| {
                    let key = read_guest(&mut caller, key_ptr, key_size, 1024)?;
                    let max = caller.data().limits.max_header_bytes;
                    let value = read_guest(&mut caller, value_ptr, value_size, max)?;
                    if key.starts_with(b":") {
                        return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                    }
                    let name = HeaderName::from_bytes(&key).context("invalid header name")?;
                    let value = HeaderValue::from_bytes(&value).context("invalid header value")?;
                    caller.data_mut().count_mutation()?;
                    let headers = caller
                        .data_mut()
                        .writable_headers(map_type)
                        .ok_or(HostError::Status(PROXY_STATUS_BAD_ARGUMENT))?;
                    if replace {
                        headers.insert(name, value);
                    } else {
                        headers.append(name, value);
                    }
                    ensure_header_budget(headers, max)
                })())
            },
        )?;
    }
    linker.func_wrap(
        "env",
        "proxy_remove_header_map_value",
        |mut caller: Caller<'_, HostState>, map_type: i32, key_ptr: i32, key_size: i32| -> i32 {
            host_status((|| {
                let key = read_guest(&mut caller, key_ptr, key_size, 1024)?;
                if key.starts_with(b":") {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let name = HeaderName::from_bytes(&key).context("invalid header name")?;
                caller.data_mut().count_mutation()?;
                let headers = caller
                    .data_mut()
                    .writable_headers(map_type)
                    .ok_or(HostError::Status(PROXY_STATUS_BAD_ARGUMENT))?;
                headers.remove(name);
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_property",
        |mut caller: Caller<'_, HostState>,
         path_ptr: i32,
         path_size: i32,
         out_ptr: i32,
         out_size: i32|
         -> i32 {
            host_status((|| {
                let path = read_guest(&mut caller, path_ptr, path_size, MAX_SHARED_KEY_BYTES)?;
                let value = match path.as_slice() {
                    b"request\0method" => Some(caller.data().method.as_bytes().to_vec()),
                    b"request\0path" => Some(caller.data().path.as_bytes().to_vec()),
                    b"request\0host" => Some(caller.data().authority.as_bytes().to_vec()),
                    b"request\0scheme" => Some(caller.data().scheme.as_bytes().to_vec()),
                    b"plugin\0namespace" => {
                        Some(caller.data().shared.namespace.as_bytes().to_vec())
                    }
                    _ => caller.data().shared.get_property(&path),
                }
                .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
                allocate_guest_result(&mut caller, &value, out_ptr, out_size)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_set_property",
        |mut caller: Caller<'_, HostState>,
         path_ptr: i32,
         path_size: i32,
         value_ptr: i32,
         value_size: i32|
         -> i32 {
            host_status((|| {
                let path = read_guest(&mut caller, path_ptr, path_size, MAX_SHARED_KEY_BYTES)?;
                if !path.starts_with(b"plugin\0custom\0") {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let value = if value_ptr == 0 {
                    if value_size != 0 {
                        return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                    }
                    None
                } else {
                    let max_bytes = caller.data().shared.limits.max_bytes;
                    Some(read_guest(&mut caller, value_ptr, value_size, max_bytes)?)
                };
                caller.data().shared.set_property(path, value)?;
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_shared_data",
        |mut caller: Caller<'_, HostState>,
         key_ptr: i32,
         key_size: i32,
         out_ptr: i32,
         out_size: i32,
         out_cas: i32|
         -> i32 {
            host_status((|| {
                let key = read_guest(&mut caller, key_ptr, key_size, MAX_SHARED_KEY_BYTES)?;
                let (value, cas) = caller
                    .data()
                    .shared
                    .get_data(&key)
                    .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
                allocate_guest_result(&mut caller, &value, out_ptr, out_size)?;
                write_u32(&mut caller, out_cas, cas)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_set_shared_data",
        |mut caller: Caller<'_, HostState>,
         key_ptr: i32,
         key_size: i32,
         value_ptr: i32,
         value_size: i32,
         cas: i32|
         -> i32 {
            host_status((|| {
                let key = read_guest(&mut caller, key_ptr, key_size, MAX_SHARED_KEY_BYTES)?;
                if key.is_empty() {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let value = if value_ptr == 0 {
                    if value_size != 0 {
                        return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                    }
                    None
                } else {
                    let max_bytes = caller.data().shared.limits.max_bytes;
                    Some(read_guest(&mut caller, value_ptr, value_size, max_bytes)?)
                };
                caller.data().shared.set_data(key, value, cas as u32)?;
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_register_shared_queue",
        |mut caller: Caller<'_, HostState>, name_ptr: i32, name_size: i32, out_id: i32| -> i32 {
            host_status((|| {
                let name = read_guest(&mut caller, name_ptr, name_size, MAX_SHARED_KEY_BYTES)?;
                if name.is_empty() {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let id = caller.data().shared.register_queue(name)?;
                write_u32(&mut caller, out_id, id)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_resolve_shared_queue",
        |mut caller: Caller<'_, HostState>,
         vm_ptr: i32,
         vm_size: i32,
         name_ptr: i32,
         name_size: i32,
         out_id: i32|
         -> i32 {
            host_status((|| {
                let vm_id = read_guest(&mut caller, vm_ptr, vm_size, MAX_SHARED_KEY_BYTES)?;
                let name = read_guest(&mut caller, name_ptr, name_size, MAX_SHARED_KEY_BYTES)?;
                let id = caller
                    .data()
                    .shared
                    .resolve_queue(&vm_id, &name)
                    .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
                write_u32(&mut caller, out_id, id)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_enqueue_shared_queue",
        |mut caller: Caller<'_, HostState>, id: i32, value_ptr: i32, value_size: i32| -> i32 {
            host_status((|| {
                let value = if value_ptr == 0 {
                    if value_size != 0 {
                        return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                    }
                    Vec::new()
                } else {
                    let max_bytes = caller.data().shared.limits.max_bytes;
                    read_guest(&mut caller, value_ptr, value_size, max_bytes)?
                };
                caller.data().shared.enqueue(id as u32, value)?;
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_dequeue_shared_queue",
        |mut caller: Caller<'_, HostState>, id: i32, out_ptr: i32, out_size: i32| -> i32 {
            host_status((|| {
                let value = caller.data().shared.dequeue(id as u32)?;
                allocate_guest_result(&mut caller, &value, out_ptr, out_size)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_define_metric",
        |mut caller: Caller<'_, HostState>,
         kind: i32,
         name_ptr: i32,
         name_size: i32,
         out_id: i32|
         -> i32 {
            host_status((|| {
                let name = read_guest(&mut caller, name_ptr, name_size, MAX_METRIC_NAME_BYTES)?;
                if name.is_empty() {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let id = caller.data().shared.define_metric(kind, name)?;
                write_u32(&mut caller, out_id, id)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_increment_metric",
        |caller: Caller<'_, HostState>, id: i32, offset: i64| -> i32 {
            host_status(
                caller
                    .data()
                    .shared
                    .increment_metric(id as u32, offset)
                    .map_err(anyhow::Error::from),
            )
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_record_metric",
        |caller: Caller<'_, HostState>, id: i32, value: i64| -> i32 {
            host_status(
                caller
                    .data()
                    .shared
                    .record_metric(id as u32, value as u64)
                    .map_err(anyhow::Error::from),
            )
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_metric",
        |mut caller: Caller<'_, HostState>, id: i32, out_value: i32| -> i32 {
            host_status((|| {
                let value = caller.data().shared.get_metric(id as u32)?;
                write_u64(&mut caller, out_value, value)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_http_call",
        |mut caller: Caller<'_, HostState>,
         cluster_ptr: i32,
         cluster_size: i32,
         headers_ptr: i32,
         headers_size: i32,
         body_ptr: i32,
         body_size: i32,
         trailers_ptr: i32,
         trailers_size: i32,
         timeout_ms: i32,
         out_token: i32|
         -> i32 {
            host_status((|| {
                let cluster = String::from_utf8(read_guest(
                    &mut caller,
                    cluster_ptr,
                    cluster_size,
                    MAX_PLUGIN_ID_BYTES,
                )?)
                .context("callout cluster is not UTF-8")?;
                if !caller.data().callout_clusters.contains_key(&cluster)
                    || timeout_ms <= 0
                    || timeout_ms as u64 > caller.data().limits.timeout_ms
                    || caller.data().callout_count >= caller.data().limits.max_callouts
                {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let max_headers = caller.data().limits.max_header_bytes;
                let max_body = caller.data().limits.max_body_bytes;
                let raw_headers = read_guest(&mut caller, headers_ptr, headers_size, max_headers)?;
                let (method, path, headers) = decode_callout_headers(&raw_headers, max_headers)?;
                let body = read_guest(&mut caller, body_ptr, body_size, max_body)?;
                let trailers = read_guest(&mut caller, trailers_ptr, trailers_size, max_headers)?;
                if !trailers.is_empty() && trailers != [0, 0, 0, 0] {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let token = next_callout_token(caller.data_mut())?;
                caller
                    .data_mut()
                    .pending_callouts
                    .push_back(PendingCallout::Http(HttpCallout {
                        token,
                        cluster,
                        method,
                        path,
                        headers,
                        body: Bytes::from(body),
                        timeout_ms: timeout_ms as u64,
                    }));
                write_u32(&mut caller, out_token, token)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_grpc_call",
        |mut caller: Caller<'_, HostState>,
         cluster_ptr: i32,
         cluster_size: i32,
         service_ptr: i32,
         service_size: i32,
         method_ptr: i32,
         method_size: i32,
         metadata_ptr: i32,
         metadata_size: i32,
         message_ptr: i32,
         message_size: i32,
         timeout_ms: i32,
         out_token: i32|
         -> i32 {
            host_status((|| {
                let cluster = String::from_utf8(read_guest(
                    &mut caller,
                    cluster_ptr,
                    cluster_size,
                    MAX_PLUGIN_ID_BYTES,
                )?)
                .context("gRPC callout cluster is not UTF-8")?;
                let service =
                    String::from_utf8(read_guest(&mut caller, service_ptr, service_size, 1024)?)
                        .context("gRPC service is not UTF-8")?;
                let method =
                    String::from_utf8(read_guest(&mut caller, method_ptr, method_size, 256)?)
                        .context("gRPC method is not UTF-8")?;
                if !caller.data().callout_clusters.contains_key(&cluster)
                    || !valid_grpc_symbol(&service)
                    || !valid_grpc_symbol(&method)
                    || timeout_ms <= 0
                    || timeout_ms as u64 > caller.data().limits.timeout_ms
                    || caller.data().callout_count >= caller.data().limits.max_callouts
                {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let max_headers = caller.data().limits.max_header_bytes;
                let max_body = caller.data().limits.max_body_bytes;
                let raw_metadata =
                    read_guest(&mut caller, metadata_ptr, metadata_size, max_headers)?;
                let metadata = decode_header_pairs(&raw_metadata, max_headers)?;
                if metadata.keys().any(is_forbidden_callout_header) {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                let message = read_guest(&mut caller, message_ptr, message_size, max_body)?;
                let token = next_callout_token(caller.data_mut())?;
                caller
                    .data_mut()
                    .pending_callouts
                    .push_back(PendingCallout::Grpc(GrpcCallout {
                        token,
                        cluster,
                        service,
                        method,
                        metadata,
                        message: Bytes::from(message),
                        timeout_ms: timeout_ms as u64,
                    }));
                write_u32(&mut caller, out_token, token)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_grpc_cancel",
        |mut caller: Caller<'_, HostState>, token: i32| -> i32 {
            let before = caller.data().pending_callouts.len();
            caller
                .data_mut()
                .pending_callouts
                .retain(|callout| match callout {
                    PendingCallout::Http(callout) => callout.token != token as u32,
                    PendingCallout::Grpc(callout) => callout.token != token as u32,
                });
            if caller.data().pending_callouts.len() == before {
                PROXY_STATUS_NOT_FOUND
            } else {
                PROXY_STATUS_OK
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_grpc_stream",
        |_caller: Caller<'_, HostState>,
         _cluster_ptr: i32,
         _cluster_size: i32,
         _service_ptr: i32,
         _service_size: i32,
         _method_ptr: i32,
         _method_size: i32,
         _metadata_ptr: i32,
         _metadata_size: i32,
         _out_token: i32|
         -> i32 { PROXY_STATUS_UNIMPLEMENTED },
    )?;
    linker.func_wrap(
        "env",
        "proxy_grpc_send",
        |_caller: Caller<'_, HostState>,
         _token: i32,
         _message_ptr: i32,
         _message_size: i32,
         _end_stream: i32|
         -> i32 { PROXY_STATUS_UNIMPLEMENTED },
    )?;
    linker.func_wrap(
        "env",
        "proxy_grpc_close",
        |_caller: Caller<'_, HostState>, _token: i32| -> i32 { PROXY_STATUS_UNIMPLEMENTED },
    )?;
    linker.func_wrap(
        "env",
        "proxy_get_status",
        |mut caller: Caller<'_, HostState>, out_code: i32, out_ptr: i32, out_size: i32| -> i32 {
            host_status((|| {
                let code = caller
                    .data()
                    .callout_response
                    .as_ref()
                    .and_then(|response| response.grpc_status)
                    .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
                write_u32(&mut caller, out_code, code)?;
                allocate_guest_result(&mut caller, &[], out_ptr, out_size)
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_close_stream",
        |mut caller: Caller<'_, HostState>, stream_type: i32| -> i32 {
            let expected = match caller.data().phase {
                WasmPhase::RequestHeaders
                | WasmPhase::RequestBody
                | WasmPhase::RequestBodyStream => 0,
                WasmPhase::ResponseHeaders
                | WasmPhase::ResponseBody
                | WasmPhase::ResponseBodyStream => 1,
            };
            if stream_type != expected {
                return PROXY_STATUS_BAD_ARGUMENT;
            }
            caller.data_mut().done_requested = true;
            PROXY_STATUS_OK
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_call_foreign_function",
        |_caller: Caller<'_, HostState>,
         _name_ptr: i32,
         _name_size: i32,
         _arguments_ptr: i32,
         _arguments_size: i32,
         _out_ptr: i32,
         _out_size: i32|
         -> i32 { PROXY_STATUS_UNIMPLEMENTED },
    )?;
    linker.func_wrap(
        "env",
        "proxy_send_local_response",
        |mut caller: Caller<'_, HostState>,
         status: i32,
         details_ptr: i32,
         details_size: i32,
         body_ptr: i32,
         body_size: i32,
         headers_ptr: i32,
         headers_size: i32,
         grpc_status: i32|
         -> i32 {
            host_status((|| {
                let status = u16::try_from(status)
                    .ok()
                    .and_then(|status| StatusCode::from_u16(status).ok())
                    .ok_or(HostError::Status(PROXY_STATUS_BAD_ARGUMENT))?;
                // details 是调试字符串，只做越界/大小校验，绝不写入访问日志。
                let _ = read_guest(&mut caller, details_ptr, details_size, 4096)?;
                let max_body = caller.data().limits.max_local_response_body_bytes;
                let body = read_guest(&mut caller, body_ptr, body_size, max_body)?;
                let max_headers = caller.data().limits.max_header_bytes;
                let raw_headers = read_guest(&mut caller, headers_ptr, headers_size, max_headers)?;
                let headers = if raw_headers.is_empty() {
                    HeaderMap::new()
                } else {
                    decode_header_pairs(&raw_headers, max_headers)?
                };
                caller.data_mut().count_mutation()?;
                if matches!(
                    caller.data().phase,
                    WasmPhase::RequestBodyStream | WasmPhase::ResponseBodyStream
                ) {
                    return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
                }
                caller.data_mut().local_response = Some(LocalResponse {
                    status,
                    headers,
                    body: Bytes::from(body),
                    grpc_status: (grpc_status >= 0).then_some(grpc_status),
                });
                Ok(())
            })())
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_set_tick_period_milliseconds",
        |mut caller: Caller<'_, HostState>, period_ms: i32| -> i32 {
            if period_ms <= 0 || period_ms as u64 > caller.data().limits.timeout_ms {
                return PROXY_STATUS_BAD_ARGUMENT;
            }
            caller.data_mut().tick_period_ms = Some(period_ms as u64);
            PROXY_STATUS_OK
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_continue_stream",
        |mut caller: Caller<'_, HostState>, stream_type: i32| -> i32 {
            let expected = match caller.data().phase {
                WasmPhase::RequestHeaders
                | WasmPhase::RequestBody
                | WasmPhase::RequestBodyStream => 0,
                WasmPhase::ResponseHeaders
                | WasmPhase::ResponseBody
                | WasmPhase::ResponseBodyStream => 1,
            };
            if stream_type != expected {
                return PROXY_STATUS_BAD_ARGUMENT;
            }
            caller.data_mut().continue_requested = true;
            PROXY_STATUS_OK
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_set_effective_context",
        |mut caller: Caller<'_, HostState>, value: i32| -> i32 {
            if !matches!(value, 1 | 2) {
                return PROXY_STATUS_BAD_ARGUMENT;
            }
            caller.data_mut().effective_context = value;
            PROXY_STATUS_OK
        },
    )?;
    linker.func_wrap(
        "env",
        "proxy_done",
        |mut caller: Caller<'_, HostState>| -> i32 {
            caller.data_mut().done_requested = true;
            PROXY_STATUS_OK
        },
    )?;
    Ok(linker)
}

fn get_header_value(state: &HostState, map_type: i32, key: &[u8]) -> Result<Option<Vec<u8>>> {
    if key.starts_with(b":") {
        return Ok(match (map_type, key) {
            (MAP_REQUEST_HEADERS, b":method") => Some(state.method.as_bytes().to_vec()),
            (MAP_REQUEST_HEADERS, b":path") => Some(state.path.as_bytes().to_vec()),
            (MAP_REQUEST_HEADERS, b":authority") => Some(state.authority.as_bytes().to_vec()),
            (MAP_REQUEST_HEADERS, b":scheme") => Some(state.scheme.as_bytes().to_vec()),
            (MAP_HTTP_CALLOUT_RESPONSE_HEADERS, b":status") => state
                .callout_response
                .as_ref()
                .map(|response| response.status.as_u16().to_string().into_bytes()),
            _ => None,
        });
    }
    let name = HeaderName::from_bytes(key).context("invalid header name")?;
    Ok(state
        .headers(map_type)
        .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?
        .get(name)
        .map(|value| value.as_bytes().to_vec()))
}

fn visible_header_count(state: &HostState, map_type: i32) -> Result<usize> {
    let headers = state
        .headers(map_type)
        .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
    Ok(headers.len()
        + usize::from(map_type == MAP_REQUEST_HEADERS) * 4
        + usize::from(map_type == MAP_HTTP_CALLOUT_RESPONSE_HEADERS))
}

fn encode_header_pairs(state: &HostState, map_type: i32) -> Result<Vec<u8>> {
    let headers = state
        .headers(map_type)
        .ok_or(HostError::Status(PROXY_STATUS_NOT_FOUND))?;
    let count = visible_header_count(state, map_type)?;
    let max = state.limits.max_header_bytes;
    let mut encoded = Vec::with_capacity(header_bytes(headers).min(max));
    push_u32(&mut encoded, count, max)?;
    if map_type == MAP_REQUEST_HEADERS {
        for (key, value) in [
            (b":method".as_slice(), state.method.as_bytes()),
            (b":path".as_slice(), state.path.as_bytes()),
            (b":authority".as_slice(), state.authority.as_bytes()),
            (b":scheme".as_slice(), state.scheme.as_bytes()),
        ] {
            push_u32(&mut encoded, key.len(), max)?;
            push_u32(&mut encoded, value.len(), max)?;
        }
    } else if map_type == MAP_HTTP_CALLOUT_RESPONSE_HEADERS {
        let status = state
            .callout_response
            .as_ref()
            .context("missing HTTP callout response")?
            .status
            .as_u16()
            .to_string();
        push_u32(&mut encoded, b":status".len(), max)?;
        push_u32(&mut encoded, status.len(), max)?;
    }
    for (name, value) in headers {
        push_u32(&mut encoded, name.as_str().len(), max)?;
        push_u32(&mut encoded, value.as_bytes().len(), max)?;
    }
    if map_type == MAP_REQUEST_HEADERS {
        for (key, value) in [
            (b":method".as_slice(), state.method.as_bytes()),
            (b":path".as_slice(), state.path.as_bytes()),
            (b":authority".as_slice(), state.authority.as_bytes()),
            (b":scheme".as_slice(), state.scheme.as_bytes()),
        ] {
            push_pair_bytes(&mut encoded, key, value, max)?;
        }
    } else if map_type == MAP_HTTP_CALLOUT_RESPONSE_HEADERS {
        let status = state
            .callout_response
            .as_ref()
            .context("missing HTTP callout response")?
            .status
            .as_u16()
            .to_string();
        push_pair_bytes(&mut encoded, b":status", status.as_bytes(), max)?;
    }
    for (name, value) in headers {
        push_pair_bytes(
            &mut encoded,
            name.as_str().as_bytes(),
            value.as_bytes(),
            max,
        )?;
    }
    Ok(encoded)
}

fn decode_header_pairs(raw: &[u8], max: usize) -> Result<HeaderMap> {
    if raw.len() > max || raw.len() < 4 {
        bail!("invalid Proxy-Wasm header map size");
    }
    let count = read_u32(raw, 0)? as usize;
    if count > 4096 {
        bail!("Proxy-Wasm header count exceeds 4096");
    }
    let lengths_bytes = count
        .checked_mul(8)
        .and_then(|value| value.checked_add(4))
        .context("Proxy-Wasm header length table overflow")?;
    if lengths_bytes > raw.len() {
        bail!("truncated Proxy-Wasm header length table");
    }
    let mut lengths = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 4 + index * 8;
        lengths.push((
            read_u32(raw, offset)? as usize,
            read_u32(raw, offset + 4)? as usize,
        ));
    }
    let mut cursor = lengths_bytes;
    let mut headers = HeaderMap::with_capacity(count);
    for (key_len, value_len) in lengths {
        let key_end = cursor.checked_add(key_len).context("header key overflow")?;
        if key_end >= raw.len() || raw[key_end] != 0 {
            bail!("invalid Proxy-Wasm header key terminator");
        }
        let key = &raw[cursor..key_end];
        cursor = key_end + 1;
        let value_end = cursor
            .checked_add(value_len)
            .context("header value overflow")?;
        if value_end >= raw.len() || raw[value_end] != 0 {
            bail!("invalid Proxy-Wasm header value terminator");
        }
        let value = &raw[cursor..value_end];
        cursor = value_end + 1;
        if key.starts_with(b":") {
            bail!("set_header_map_pairs cannot mutate pseudo headers");
        }
        headers.append(
            HeaderName::from_bytes(key).context("invalid header name")?,
            HeaderValue::from_bytes(value).context("invalid header value")?,
        );
    }
    if cursor != raw.len() {
        bail!("trailing bytes in Proxy-Wasm header map");
    }
    ensure_header_budget(&headers, max)?;
    Ok(headers)
}

/// 业务作用：解析 HTTP callout 的 ABI header table，并把伪头固定为 method/path 而非普通 header。
///
/// 参数说明：`raw` 是客体序列化表，`max` 是插件 header 字节预算。
///
/// 返回：必须同时包含唯一 `:method` 与 `:path`；绝对 URL、authority 覆盖、hop-by-hop 与畸形表均拒绝。
fn decode_callout_headers(raw: &[u8], max: usize) -> Result<(http::Method, String, HeaderMap)> {
    if raw.len() > max || raw.len() < 4 {
        bail!("invalid Proxy-Wasm callout header map size");
    }
    let count = read_u32(raw, 0)? as usize;
    if count > 4096 {
        bail!("Proxy-Wasm callout header count exceeds 4096");
    }
    let lengths_bytes = count
        .checked_mul(8)
        .and_then(|value| value.checked_add(4))
        .context("Proxy-Wasm callout header length table overflow")?;
    if lengths_bytes > raw.len() {
        bail!("truncated Proxy-Wasm callout header length table");
    }
    let mut cursor = lengths_bytes;
    let mut method = None;
    let mut path = None;
    let mut headers = HeaderMap::with_capacity(count);
    for index in 0..count {
        let offset = 4 + index * 8;
        let key_len = read_u32(raw, offset)? as usize;
        let value_len = read_u32(raw, offset + 4)? as usize;
        let key_end = cursor
            .checked_add(key_len)
            .context("callout key overflow")?;
        if key_end >= raw.len() || raw[key_end] != 0 {
            bail!("invalid Proxy-Wasm callout key terminator");
        }
        let key = &raw[cursor..key_end];
        cursor = key_end + 1;
        let value_end = cursor
            .checked_add(value_len)
            .context("callout value overflow")?;
        if value_end >= raw.len() || raw[value_end] != 0 {
            bail!("invalid Proxy-Wasm callout value terminator");
        }
        let value = &raw[cursor..value_end];
        cursor = value_end + 1;
        match key {
            b":method" if method.is_none() => {
                method = Some(http::Method::from_bytes(value).context("invalid callout method")?);
            }
            b":path" if path.is_none() => {
                let candidate = std::str::from_utf8(value).context("callout path is not UTF-8")?;
                if !candidate.starts_with('/') || candidate.starts_with("//") {
                    bail!("callout path must be origin-relative");
                }
                path = Some(candidate.to_owned());
            }
            key if key.starts_with(b":") => {
                bail!("callout cannot override authority/scheme or duplicate pseudo headers");
            }
            _ => {
                let name = HeaderName::from_bytes(key).context("invalid callout header name")?;
                if is_forbidden_callout_header(&name) {
                    bail!("forbidden callout header `{name}`");
                }
                headers.append(
                    name,
                    HeaderValue::from_bytes(value).context("invalid callout header value")?,
                );
            }
        }
    }
    if cursor != raw.len() {
        bail!("trailing bytes in Proxy-Wasm callout header map");
    }
    ensure_header_budget(&headers, max)?;
    Ok((
        method.context("callout requires :method")?,
        path.context("callout requires :path")?,
        headers,
    ))
}

/// 业务作用：阻止 callout 客体控制连接级语义、目标 authority 或 framing。
///
/// 参数说明：`name` 是已完成 HTTP header 语法校验的名称。
///
/// 返回：属于 hop-by-hop、host 或长度 framing 字段时返回 `true`。
fn is_forbidden_callout_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// 业务作用：限制 gRPC callout 的 service/method 为协议符号，防止借字段注入 path/query。
///
/// 参数说明：`value` 是客体提供的 service 或 method 名称。
///
/// 返回：非空且只含 ASCII 字母数字、下划线和点时返回 `true`。
fn valid_grpc_symbol(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
}

/// 业务作用：为单次 invocation 分配受上限约束的非零 callout token。
///
/// 参数说明：`state` 是当前独占宿主状态。
///
/// 返回：预算内返回 token 并递增登记数；超过扇出上限返回 BAD_ARGUMENT。
fn next_callout_token(state: &mut HostState) -> Result<u32> {
    if state.callout_count >= state.limits.max_callouts {
        return Err(HostError::Status(PROXY_STATUS_BAD_ARGUMENT).into());
    }
    let token = state.next_callout_token.max(1);
    state.next_callout_token = token.wrapping_add(1).max(1);
    state.callout_count += 1;
    Ok(token)
}

fn push_pair_bytes(encoded: &mut Vec<u8>, key: &[u8], value: &[u8], max: usize) -> Result<()> {
    extend_bounded(encoded, key, max)?;
    extend_bounded(encoded, &[0], max)?;
    extend_bounded(encoded, value, max)?;
    extend_bounded(encoded, &[0], max)
}

fn push_u32(encoded: &mut Vec<u8>, value: usize, max: usize) -> Result<()> {
    let value = u32::try_from(value).context("Proxy-Wasm map field exceeds u32")?;
    extend_bounded(encoded, &value.to_le_bytes(), max)
}

fn extend_bounded(target: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<()> {
    if target.len().saturating_add(bytes.len()) > max {
        bail!("Proxy-Wasm encoded header map exceeds max_header_bytes");
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = raw
        .get(offset..offset.saturating_add(4))
        .context("truncated Proxy-Wasm u32")?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(bytes))
}

fn ensure_header_budget(headers: &HeaderMap, max: usize) -> Result<()> {
    if header_bytes(headers) > max {
        bail!("Proxy-Wasm header map exceeds max_header_bytes");
    }
    Ok(())
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers.iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(2)
    })
}

fn read_guest(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    size: i32,
    max: usize,
) -> Result<Vec<u8>> {
    if ptr < 0 || size < 0 || size as usize > max {
        return Err(HostError::Status(PROXY_STATUS_INVALID_MEMORY_ACCESS).into());
    }
    let memory = guest_memory(caller)?;
    let mut bytes = vec![0; size as usize];
    memory
        .read(&*caller, ptr as usize, &mut bytes)
        .map_err(|_| HostError::Status(PROXY_STATUS_INVALID_MEMORY_ACCESS))?;
    Ok(bytes)
}

fn allocate_guest_result(
    caller: &mut Caller<'_, HostState>,
    bytes: &[u8],
    out_ptr: i32,
    out_size: i32,
) -> Result<()> {
    let len = i32::try_from(bytes.len()).context("Proxy-Wasm result exceeds i32")?;
    let allocator = caller
        .get_export("proxy_on_memory_allocate")
        .or_else(|| caller.get_export("malloc"))
        .and_then(Extern::into_func)
        .context("guest must export proxy_on_memory_allocate or malloc")?
        .typed::<i32, i32>(&*caller)
        .map_err(anyhow::Error::from)
        .context("invalid Proxy-Wasm guest allocator signature")?;
    let ptr = allocator
        .call(&mut *caller, len)
        .map_err(anyhow::Error::from)
        .context("Proxy-Wasm guest allocator trapped")?;
    if ptr < 0 {
        bail!("Proxy-Wasm guest allocator returned a negative pointer");
    }
    write_bytes(caller, ptr, bytes)?;
    write_i32(caller, out_ptr, ptr)?;
    write_i32(caller, out_size, len)
}

fn write_i32(caller: &mut Caller<'_, HostState>, ptr: i32, value: i32) -> Result<()> {
    write_bytes(caller, ptr, &value.to_le_bytes())
}

/// 业务作用：按 Proxy-Wasm little-endian ABI 把无符号 32 位结果写回客体。
///
/// 参数说明：`caller` 提供客体内存，`ptr` 是输出地址，`value` 是 id/CAS/status。
///
/// 返回：写入成功返回 OK；越界地址返回 INVALID_MEMORY_ACCESS。
fn write_u32(caller: &mut Caller<'_, HostState>, ptr: i32, value: u32) -> Result<()> {
    write_bytes(caller, ptr, &value.to_le_bytes())
}

/// 业务作用：按 Proxy-Wasm little-endian ABI 把 metric 的无符号 64 位值写回客体。
///
/// 参数说明：`caller` 提供客体内存，`ptr` 是输出地址，`value` 是 metric 当前值。
///
/// 返回：写入成功返回 OK；越界地址返回 INVALID_MEMORY_ACCESS。
fn write_u64(caller: &mut Caller<'_, HostState>, ptr: i32, value: u64) -> Result<()> {
    write_bytes(caller, ptr, &value.to_le_bytes())
}

fn write_bytes(caller: &mut Caller<'_, HostState>, ptr: i32, bytes: &[u8]) -> Result<()> {
    if ptr < 0 {
        return Err(HostError::Status(PROXY_STATUS_INVALID_MEMORY_ACCESS).into());
    }
    guest_memory(caller)?
        .write(caller, ptr as usize, bytes)
        .map_err(|_| HostError::Status(PROXY_STATUS_INVALID_MEMORY_ACCESS))?;
    Ok(())
}

fn guest_memory(caller: &mut Caller<'_, HostState>) -> Result<Memory> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| HostError::Status(PROXY_STATUS_INVALID_MEMORY_ACCESS).into())
}

#[derive(Debug)]
enum HostError {
    Status(i32),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => write!(formatter, "Proxy-Wasm host status {status}"),
        }
    }
}

impl std::error::Error for HostError {}

fn host_status(result: Result<()>) -> i32 {
    match result {
        Ok(()) => PROXY_STATUS_OK,
        Err(error) => error
            .downcast_ref::<HostError>()
            .map(|error| match error {
                HostError::Status(status) => *status,
            })
            .unwrap_or(PROXY_STATUS_BAD_ARGUMENT),
    }
}

fn call_optional_unit(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    name: &str,
) -> Result<()> {
    let Some(func) = instance.get_func(&mut *store, name) else {
        return Ok(());
    };
    func.typed::<(), ()>(&*store)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("invalid `{name}` signature"))?
        .call(store, ())
        .map_err(anyhow::Error::from)
        .with_context(|| format!("call `{name}`"))
}

fn call_optional_i32_pair_void(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    name: &str,
    first: i32,
    second: i32,
) -> Result<()> {
    let Some(func) = instance.get_func(&mut *store, name) else {
        return Ok(());
    };
    func.typed::<(i32, i32), ()>(&*store)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("invalid `{name}` signature"))?
        .call(store, (first, second))
        .map_err(anyhow::Error::from)
        .with_context(|| format!("call `{name}`"))
}

fn call_optional_i32_i32_bool(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    name: &str,
    first: i32,
    second: i32,
) -> Result<bool> {
    let Some(func) = instance.get_func(&mut *store, name) else {
        return Ok(true);
    };
    Ok(func
        .typed::<(i32, i32), i32>(&*store)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("invalid `{name}` signature"))?
        .call(store, (first, second))
        .map_err(anyhow::Error::from)
        .with_context(|| format!("call `{name}`"))?
        != 0)
}

fn call_optional_i32_bool(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    name: &str,
    value: i32,
) -> Result<bool> {
    let Some(func) = instance.get_func(&mut *store, name) else {
        return Ok(true);
    };
    Ok(func
        .typed::<i32, i32>(&*store)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("invalid `{name}` signature"))?
        .call(store, value)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("call `{name}`"))?
        != 0)
}

fn call_optional_i32_void(
    store: &mut Store<HostState>,
    instance: &wasmtime::Instance,
    name: &str,
    value: i32,
) -> Result<()> {
    let Some(func) = instance.get_func(&mut *store, name) else {
        return Ok(());
    };
    func.typed::<i32, ()>(&*store)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("invalid `{name}` signature"))?
        .call(store, value)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("call `{name}`"))
}

/// 业务作用：从互斥的本地或远程来源装载模块，并在编译前完成全部供应链校验。
///
/// 参数说明：`cfg` 是插件声明；`config_dir` 解析本地来源；`route_id` 只提供低敏错误上下文。
///
/// 返回：返回已验证模块字节和安全日志身份；读取、下载、摘要、签名或证明失败会拒绝候选快照。
fn load_module_bytes(
    cfg: &WasmPluginCfg,
    config_dir: &Path,
    route_id: &str,
) -> Result<(Vec<u8>, String)> {
    let Some(source) = &cfg.module_source else {
        let module_file = resolve(config_dir, cfg.module_file.as_str());
        // 模块是控制面不可信文件；必须在分配前执行上限，而不是完整读取后才检查。
        let bytes =
            crate::bounded_io::read_file(&module_file, cfg.max_module_bytes, "Proxy-Wasm module")?;
        return Ok((bytes, module_file.display().to_string()));
    };

    let expected_digest = normalize_sha256(source.sha256.as_str(), "Wasm module sha256")?;
    if let Some(cache_path) = wasm_cache_path(source, config_dir, expected_digest.as_str()) {
        if let Ok(bytes) = crate::bounded_io::read_file(
            &cache_path,
            cfg.max_module_bytes,
            "Proxy-Wasm module cache",
        ) {
            if verify_remote_module(
                bytes.as_slice(),
                source,
                config_dir,
                expected_digest.as_str(),
            )
            .is_ok()
            {
                return Ok((bytes, format!("verified cache for route `{route_id}`")));
            }
        }
    }

    let fetch_source = source.clone();
    let fetch_dir = config_dir.to_path_buf();
    let max_module_bytes = cfg.max_module_bytes;
    // 候选构建可能由 Tokio 控制面任务触发；blocking client 放入隔离线程，避免嵌套 runtime
    // 或把 registry I/O 阻塞到数据面 worker。
    let bytes = std::thread::spawn(move || {
        fetch_remote_module(&fetch_source, &fetch_dir, max_module_bytes)
    })
    .join()
    .map_err(|_| anyhow!("Proxy-Wasm source worker panicked"))??;
    verify_remote_module(
        bytes.as_slice(),
        source,
        config_dir,
        expected_digest.as_str(),
    )?;
    if let Some(cache_path) = wasm_cache_path(source, config_dir, expected_digest.as_str()) {
        write_wasm_cache(
            cache_path.as_path(),
            bytes.as_slice(),
            expected_digest.as_str(),
        )?;
    }
    Ok((
        bytes,
        format!("verified remote source for route `{route_id}`"),
    ))
}

/// 业务作用：按 source scheme 选择固定 HTTPS 或 OCI Distribution 获取器。
///
/// 参数说明：`source` 提供固定引用、TLS 和凭据；`config_dir` 解析 SecretSource；
/// `max_module_bytes` 是读取前硬门。
///
/// 返回：网络与 registry 协议完整成功时返回原始 wasm；重定向、超限或不可变摘要不符返回错误。
fn fetch_remote_module(
    source: &WasmModuleSourceCfg,
    config_dir: &Path,
    max_module_bytes: usize,
) -> Result<Vec<u8>> {
    let client = build_wasm_source_client(source, config_dir)?;
    let authorization = resolve_wasm_authorization(source, config_dir)?;
    if source.reference.starts_with("https://") {
        let url = validate_https_module_url(source.reference.as_str())?;
        let (bytes, _) = fetch_bounded_source(
            &client,
            url.as_str(),
            "application/wasm, application/octet-stream",
            authorization.as_ref(),
            max_module_bytes,
            "Wasm HTTPS module",
        )?;
        return Ok(bytes);
    }
    if source.reference.starts_with("oci://") {
        return fetch_oci_module(&client, source, authorization.as_ref(), max_module_bytes);
    }
    bail!("Wasm module_source.reference must use https:// or oci://")
}

/// 业务作用：构建拒绝 redirect、共享固定 deadline 且只信任平台根与显式附加 CA 的客户端。
///
/// 参数说明：`source` 提供 deadline 与 CA SecretSource；`config_dir` 解析本地来源。
///
/// 返回：TLS 和配置有效时返回 blocking client；证书或 client 配置非法时返回错误。
fn build_wasm_source_client(
    source: &WasmModuleSourceCfg,
    config_dir: &Path,
) -> Result<reqwest::blocking::Client> {
    let timeout = Duration::from_millis(source.timeout_ms);
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .user_agent("naway-wasm-source/1");
    if !source.ca_certificate.trim().is_empty() {
        let pem = crate::secret::resolve_text(
            source.ca_certificate.as_str(),
            config_dir,
            "Proxy-Wasm source CA certificate",
        )?;
        let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
            .context("parse Proxy-Wasm source CA certificate")?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().context("build Proxy-Wasm source client")
}

/// 业务作用：解析只会发往模块来源的 registry credential，避免继承下游认证头。
///
/// 参数说明：`source` 提供 Authorization SecretSource；`config_dir` 解析本地来源。
///
/// 返回：空配置返回 None；合法 HTTP header value 返回敏感值；非法字符返回错误。
fn resolve_wasm_authorization(
    source: &WasmModuleSourceCfg,
    config_dir: &Path,
) -> Result<Option<reqwest::header::HeaderValue>> {
    if source.authorization.trim().is_empty() {
        return Ok(None);
    }
    let authorization = crate::secret::resolve_text(
        source.authorization.as_str(),
        config_dir,
        "Proxy-Wasm source authorization",
    )?;
    let mut value = reqwest::header::HeaderValue::from_str(authorization.as_str())
        .context("Proxy-Wasm source authorization is not a valid HTTP header value")?;
    value.set_sensitive(true);
    Ok(Some(value))
}

/// 业务作用：验证固定 HTTPS 模块 URL 不携带 userinfo、fragment 或非 HTTPS 降级入口。
///
/// 参数说明：`raw` 是配置提供的完整模块 URL。
///
/// 返回：目标结构稳定时返回解析 URL；非法或可能泄露凭据的 URL 返回错误。
fn validate_https_module_url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("parse Proxy-Wasm HTTPS source URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("Proxy-Wasm HTTPS source must be a fixed HTTPS URL without userinfo or fragment");
    }
    Ok(url)
}

/// 业务作用：执行一次无重定向 GET，并在预分配和读取阶段共同限制响应字节。
///
/// 参数说明：`client` 是固定 TLS client；`url` 是已验证目标；`accept` 是协议 media type；
/// `authorization` 是独立来源凭据；`max_bytes` 是硬门；`label` 只用于错误上下文。
///
/// 返回：2xx 且未超限时返回原始 body 与 response headers；其它状态或 I/O 失败返回错误。
fn fetch_bounded_source(
    client: &reqwest::blocking::Client,
    url: &str,
    accept: &str,
    authorization: Option<&reqwest::header::HeaderValue>,
    max_bytes: usize,
    label: &str,
) -> Result<(Vec<u8>, reqwest::header::HeaderMap)> {
    let mut request = client.get(url).header(reqwest::header::ACCEPT, accept);
    if let Some(authorization) = authorization {
        request = request.header(reqwest::header::AUTHORIZATION, authorization.clone());
    }
    let mut response = request.send().with_context(|| format!("fetch {label}"))?;
    if !response.status().is_success() {
        bail!("{label} returned non-success HTTP status");
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("{label} exceeds configured byte limit");
    }
    let headers = response.headers().clone();
    let mut bytes =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(max_bytes as u64) as usize);
    response
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    if bytes.len() > max_bytes {
        bail!("{label} exceeds configured byte limit");
    }
    Ok((bytes, headers))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    schema_version: u32,
    layers: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: String,
    size: u64,
}

struct ParsedOciReference {
    origin: String,
    repository: String,
    selector: String,
    manifest_digest: String,
    tagged: bool,
}

/// 业务作用：解析 OCI reference 并把 tag 绑定到显式 manifest digest，阻止可变 tag 直接发布。
///
/// 参数说明：`source` 包含 oci reference 与可选 manifest pin。
///
/// 返回：返回可安全拼接 Distribution API 的结构；歧义路径、未固定 tag 或摘要冲突返回错误。
fn parse_oci_reference(source: &WasmModuleSourceCfg) -> Result<ParsedOciReference> {
    let raw = source
        .reference
        .strip_prefix("oci://")
        .context("Proxy-Wasm OCI reference must start with oci://")?;
    let url = reqwest::Url::parse(format!("https://{raw}").as_str())
        .context("parse Proxy-Wasm OCI reference")?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().contains('%')
    {
        bail!("Proxy-Wasm OCI reference contains unsupported authority or escaped path data");
    }
    let path = url.path().trim_start_matches('/');
    let (repository, selector, tagged, manifest_digest) =
        if let Some((repository, digest)) = path.rsplit_once('@') {
            let digest = digest
                .strip_prefix("sha256:")
                .context("Proxy-Wasm OCI digest reference must use sha256")?;
            let digest = normalize_sha256(digest, "Proxy-Wasm OCI manifest digest")?;
            if !source.manifest_sha256.trim().is_empty()
                && !digest.eq_ignore_ascii_case(source.manifest_sha256.as_str())
            {
                bail!("Proxy-Wasm OCI digest reference conflicts with manifest_sha256");
            }
            (repository, format!("sha256:{digest}"), false, digest)
        } else {
            let slash = path.rfind('/').map_or(0, |index| index + 1);
            let colon = path[slash..]
                .rfind(':')
                .map(|index| slash + index)
                .context("Proxy-Wasm OCI tag reference must include an explicit tag")?;
            let repository = &path[..colon];
            let tag = &path[colon + 1..];
            let digest = normalize_sha256(
                source.manifest_sha256.as_str(),
                "Proxy-Wasm OCI tagged manifest_sha256",
            )?;
            (repository, tag.to_owned(), true, digest)
        };
    if repository.is_empty()
        || !repository
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || selector.is_empty()
        || !selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-'))
    {
        bail!("Proxy-Wasm OCI repository or reference contains unsupported characters");
    }
    Ok(ParsedOciReference {
        origin: url.origin().ascii_serialization(),
        repository: repository.to_owned(),
        selector,
        manifest_digest,
        tagged,
    })
}

/// 业务作用：按 OCI Distribution API 获取并验证 immutable manifest 与唯一 Wasm layer。
///
/// 参数说明：`client` 是固定 TLS client；`source` 提供 reference 和摘要；`authorization`
/// 是 registry 专用凭据；`max_module_bytes` 是 layer 读取硬门。
///
/// 返回：manifest、descriptor 和最终模块摘要全部一致时返回 raw wasm；协议或完整性异常返回错误。
fn fetch_oci_module(
    client: &reqwest::blocking::Client,
    source: &WasmModuleSourceCfg,
    authorization: Option<&reqwest::header::HeaderValue>,
    max_module_bytes: usize,
) -> Result<Vec<u8>> {
    let reference = parse_oci_reference(source)?;
    let manifest_url = format!(
        "{}/v2/{}/manifests/{}",
        reference.origin, reference.repository, reference.selector
    );
    let (manifest_bytes, manifest_headers) = fetch_bounded_source(
        client,
        manifest_url.as_str(),
        "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
        authorization,
        MAX_OCI_MANIFEST_BYTES,
        "Proxy-Wasm OCI manifest",
    )?;
    verify_sha256(
        manifest_bytes.as_slice(),
        reference.manifest_digest.as_str(),
        "Proxy-Wasm OCI manifest",
    )?;
    if let Some(header) = manifest_headers.get("docker-content-digest") {
        let header = header
            .to_str()
            .context("Proxy-Wasm OCI Docker-Content-Digest is not ASCII")?
            .strip_prefix("sha256:")
            .context("Proxy-Wasm OCI Docker-Content-Digest must use sha256")?;
        if !header.eq_ignore_ascii_case(reference.manifest_digest.as_str()) {
            bail!("Proxy-Wasm OCI Docker-Content-Digest does not match manifest pin");
        }
    } else if reference.tagged {
        bail!("Proxy-Wasm OCI tagged manifest omitted Docker-Content-Digest");
    }
    let manifest: OciManifest =
        serde_json::from_slice(&manifest_bytes).context("decode Proxy-Wasm OCI manifest")?;
    if manifest.schema_version != 2 {
        bail!("Proxy-Wasm OCI manifest schemaVersion must be 2");
    }
    let mut layers = manifest.layers.iter().filter(|layer| {
        matches!(
            layer.media_type.as_str(),
            "application/vnd.module.wasm.content.layer.v1+wasm"
                | "application/vnd.wasm.content.layer.v1+wasm"
                | "application/wasm"
        )
    });
    let layer = layers
        .next()
        .context("Proxy-Wasm OCI manifest contains no supported Wasm layer")?;
    if layers.next().is_some() {
        bail!("Proxy-Wasm OCI manifest contains more than one supported Wasm layer");
    }
    if layer.size > max_module_bytes as u64 {
        bail!("Proxy-Wasm OCI layer descriptor exceeds max_module_bytes");
    }
    let layer_digest = layer
        .digest
        .strip_prefix("sha256:")
        .context("Proxy-Wasm OCI layer digest must use sha256")?;
    let layer_digest = normalize_sha256(layer_digest, "Proxy-Wasm OCI layer digest")?;
    if !layer_digest.eq_ignore_ascii_case(source.sha256.as_str()) {
        bail!("Proxy-Wasm OCI layer digest does not match module sha256 pin");
    }
    let blob_url = format!(
        "{}/v2/{}/blobs/sha256:{}",
        reference.origin, reference.repository, layer_digest
    );
    let (bytes, headers) = fetch_bounded_source(
        client,
        blob_url.as_str(),
        "application/wasm, application/octet-stream",
        authorization,
        max_module_bytes,
        "Proxy-Wasm OCI layer",
    )?;
    if bytes.len() as u64 != layer.size {
        bail!("Proxy-Wasm OCI layer size does not match descriptor");
    }
    if let Some(header) = headers.get("docker-content-digest") {
        let header = header
            .to_str()
            .context("Proxy-Wasm OCI blob Docker-Content-Digest is not ASCII")?
            .strip_prefix("sha256:")
            .context("Proxy-Wasm OCI blob Docker-Content-Digest must use sha256")?;
        if !header.eq_ignore_ascii_case(layer_digest.as_str()) {
            bail!("Proxy-Wasm OCI blob digest header does not match descriptor");
        }
    }
    verify_sha256(
        bytes.as_slice(),
        layer_digest.as_str(),
        "Proxy-Wasm OCI layer",
    )?;
    Ok(bytes)
}

/// 业务作用：复验远程模块的固定摘要及所配置的全部独立供应链证明。
///
/// 参数说明：`bytes` 是候选模块；`source` 提供 pin 与证明；`config_dir` 解析 SecretSource；
/// `expected_digest` 是已规范化摘要。
///
/// 返回：摘要及所有已声明证明通过时成功；任一不匹配都会拒绝候选和 cache 命中。
fn verify_remote_module(
    bytes: &[u8],
    source: &WasmModuleSourceCfg,
    config_dir: &Path,
    expected_digest: &str,
) -> Result<()> {
    verify_sha256(bytes, expected_digest, "Proxy-Wasm module")?;
    if !source.signature.trim().is_empty() {
        verify_ed25519_secret(
            bytes,
            source.signature.as_str(),
            source.public_key.as_str(),
            config_dir,
            "Proxy-Wasm module",
        )?;
    }
    if let Some(attestation) = &source.attestation {
        verify_wasm_attestation(attestation, config_dir, expected_digest)?;
    }
    Ok(())
}

/// 业务作用：验证 detached Ed25519 signature，确保内容只能由固定 signer 授权。
///
/// 参数说明：`payload` 是精确验签字节；`signature_source`/`public_key_source` 是 Base64
/// SecretSource；`config_dir` 解析本地来源；`label` 提供低敏错误上下文。
///
/// 返回：key 长度、签名长度和密码学验证全部通过时成功，否则返回错误。
fn verify_ed25519_secret(
    payload: &[u8],
    signature_source: &str,
    public_key_source: &str,
    config_dir: &Path,
    label: &str,
) -> Result<()> {
    let signature =
        crate::secret::resolve_text(signature_source, config_dir, &format!("{label} signature"))?;
    let public_key = crate::secret::resolve_text(
        public_key_source,
        config_dir,
        &format!("{label} public key"),
    )?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .with_context(|| format!("decode {label} Ed25519 signature"))?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .with_context(|| format!("decode {label} Ed25519 public key"))?;
    let signature = Signature::from_slice(signature.as_slice())
        .with_context(|| format!("{label} Ed25519 signature must be 64 bytes"))?;
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow!("{label} Ed25519 public key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .with_context(|| format!("decode {label} Ed25519 public key"))?;
    key.verify_strict(payload, &signature)
        .with_context(|| format!("verify {label} Ed25519 signature"))
}

#[derive(Deserialize)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: serde_json::Value,
}

#[derive(Deserialize)]
struct InTotoSubject {
    name: String,
    digest: HashMap<String, String>,
}

/// 业务作用：验证签名 in-toto Statement v1 对模块摘要、predicate 和受信 builder 的绑定。
///
/// 参数说明：`cfg` 提供 statement、signer 与预期 provenance；`config_dir` 解析 SecretSource；
/// `expected_digest` 是最终模块摘要。
///
/// 返回：签名、statement 类型、subject、predicateType 与 builder 全部匹配时成功。
fn verify_wasm_attestation(
    cfg: &WasmAttestationCfg,
    config_dir: &Path,
    expected_digest: &str,
) -> Result<()> {
    let statement = crate::secret::resolve_text(
        cfg.statement.as_str(),
        config_dir,
        "Proxy-Wasm in-toto statement",
    )?;
    verify_ed25519_secret(
        statement.as_bytes(),
        cfg.signature.as_str(),
        cfg.public_key.as_str(),
        config_dir,
        "Proxy-Wasm in-toto statement",
    )?;
    let statement: InTotoStatement =
        serde_json::from_str(statement.as_str()).context("decode Proxy-Wasm in-toto statement")?;
    if statement.statement_type != "https://in-toto.io/Statement/v1" {
        bail!("Proxy-Wasm attestation must be an in-toto Statement v1");
    }
    if statement.predicate_type != cfg.predicate_type {
        bail!("Proxy-Wasm attestation predicateType does not match trusted configuration");
    }
    let subject_matches = statement.subject.iter().any(|subject| {
        (cfg.subject_name.is_empty() || subject.name == cfg.subject_name)
            && subject
                .digest
                .get("sha256")
                .is_some_and(|digest| digest.eq_ignore_ascii_case(expected_digest))
    });
    if !subject_matches {
        bail!("Proxy-Wasm attestation contains no matching sha256 subject");
    }
    let builder_id = statement
        .predicate
        .pointer("/builder/id")
        .or_else(|| statement.predicate.pointer("/runDetails/builder/id"))
        .and_then(serde_json::Value::as_str)
        .context("Proxy-Wasm attestation predicate omits builder id")?;
    if builder_id != cfg.builder_id {
        bail!("Proxy-Wasm attestation builder id does not match trusted configuration");
    }
    Ok(())
}

/// 业务作用：规范化完整 SHA-256 十六进制值，避免截断、算法混淆和歧义编码。
///
/// 参数说明：`raw` 是配置或协议摘要；`label` 提供低敏错误上下文。
///
/// 返回：恰好 64 个十六进制字符时返回小写值；其它格式返回错误。
fn normalize_sha256(raw: &str, label: &str) -> Result<String> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must contain exactly 64 hexadecimal characters");
    }
    Ok(raw.to_ascii_lowercase())
}

/// 业务作用：以常量长度摘要复验完整 payload，保证 registry、cache 和配置共享同一内容身份。
///
/// 参数说明：`bytes` 是候选内容；`expected` 是规范 SHA-256；`label` 提供错误上下文。
///
/// 返回：摘要完全匹配时成功，否则返回完整性错误。
fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<()> {
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("{label} does not match pinned sha256");
    }
    Ok(())
}

/// 业务作用：生成只由固定摘要决定的 cache 路径，避免远程 reference 进入文件名或造成路径穿越。
///
/// 参数说明：`source` 提供显式 cache 目录；`config_dir` 解析相对目录；`digest` 已完成格式校验。
///
/// 返回：cache 关闭时返回 None；开启时返回 `<digest>.wasm` 路径。
fn wasm_cache_path(
    source: &WasmModuleSourceCfg,
    config_dir: &Path,
    digest: &str,
) -> Option<PathBuf> {
    (!source.cache_dir.trim().is_empty())
        .then(|| resolve(config_dir, source.cache_dir.as_str()).join(format!("{digest}.wasm")))
}

/// 业务作用：把已完整验证的远程模块原子写入内容寻址 cache，避免崩溃留下可命中的半文件。
///
/// 参数说明：`path` 是摘要派生目标；`bytes` 已验摘要和证明；`digest` 用于并发结果复验。
///
/// 返回：原子发布并同步成功时返回；目录、写入或并发目标不一致时返回错误。
fn write_wasm_cache(path: &Path, bytes: &[u8], digest: &str) -> Result<()> {
    let parent = path
        .parent()
        .context("Proxy-Wasm cache path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create Proxy-Wasm cache directory {}", parent.display()))?;
    let sequence = WASM_CACHE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".{digest}.{}.{}.tmp", std::process::id(), sequence));
    let write_result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .with_context(|| format!("create Proxy-Wasm cache staging file {}", temp.display()))?;
        file.write_all(bytes)
            .context("write Proxy-Wasm cache staging file")?;
        file.sync_all()
            .context("sync Proxy-Wasm cache staging file")?;
        drop(file);
        match std::fs::rename(&temp, path) {
            Ok(()) => {}
            Err(error) if path.is_file() => {
                let existing = crate::bounded_io::read_file(
                    path,
                    bytes.len(),
                    "Proxy-Wasm concurrent cache entry",
                )?;
                verify_sha256(
                    existing.as_slice(),
                    digest,
                    "Proxy-Wasm concurrent cache entry",
                )?;
                std::fs::remove_file(&temp).with_context(|| {
                    format!("remove Proxy-Wasm cache staging file after {error}")
                })?;
            }
            Err(error) => return Err(error).context("publish Proxy-Wasm cache entry"),
        }
        if let Ok(directory) = std::fs::File::open(parent) {
            directory
                .sync_all()
                .context("sync Proxy-Wasm cache directory")?;
        }
        Ok(())
    })();
    if write_result.is_err() && temp.is_file() {
        let _ = std::fs::remove_file(&temp);
    }
    write_result
}

/// 业务作用：把配置相对路径解析到主配置目录，同时保留绝对部署路径。
///
/// 参数说明：`base` 是主配置目录；`raw` 是配置提供的路径。
///
/// 返回：可供候选构建或 watcher 使用的文件系统路径。
fn resolve(base: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// 业务作用：收集 Proxy-Wasm 候选构建依赖的本地文件，供 reload watcher 与配置指纹共用。
///
/// 参数说明：`config_dir` 是主配置目录；`cfg` 是单个插件声明。
///
/// 返回：本地模块及文件型凭据、签名和证明来源；远程 URL 与内容寻址 cache 不作为事件源。
pub(crate) fn dependency_paths(config_dir: &Path, cfg: &WasmPluginCfg) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if !cfg.module_file.trim().is_empty() {
        paths.push(resolve(config_dir, cfg.module_file.as_str()));
    }
    let Some(source) = &cfg.module_source else {
        return paths;
    };
    for raw in [
        source.authorization.as_str(),
        source.ca_certificate.as_str(),
        source.signature.as_str(),
        source.public_key.as_str(),
    ] {
        if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
            paths.push(path);
        }
    }
    if let Some(attestation) = &source.attestation {
        for raw in [
            attestation.statement.as_str(),
            attestation.signature.as_str(),
            attestation.public_key.as_str(),
        ] {
            if let Some(path) = crate::secret::dependency_path(raw, config_dir) {
                paths.push(path);
            }
        }
    }
    paths
}
