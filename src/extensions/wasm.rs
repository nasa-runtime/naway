//! V7 Proxy-Wasm ABI v0.2.1 头部插件运行时。
//!
//! 这个模块故意不提供 WASI：客体没有文件、环境变量、随机数或 socket 能力，
//! 只能通过明确白名单的 `env.proxy_*` 头部 ABI 与数据面交互。模块在快照构建期
//! 编译成 `Module`；请求期每条插件链只 clone 一份 `HeaderMap`（header value 底层字节
//! 依然共享），并在 blocking pool 中执行。客体成功才原子交付整份 head，trap/fuel/
//! epoch/内存越界不会把半套变更泄漏给后续管线。

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;
use http::{HeaderMap, Response, StatusCode};
use wasmtime::{
    Caller, Engine, Extern, ExternType, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

use crate::config::model::{WasmPluginCfg, WasmPluginPhaseCfg};
use crate::{full_body, BoxBody};

const PROXY_STATUS_OK: i32 = 0;
const PROXY_STATUS_NOT_FOUND: i32 = 1;
const PROXY_STATUS_BAD_ARGUMENT: i32 = 2;
const PROXY_STATUS_INVALID_MEMORY_ACCESS: i32 = 6;
const PROXY_STATUS_UNIMPLEMENTED: i32 = 12;
const PROXY_ACTION_CONTINUE: i32 = 0;
const PROXY_ACTION_PAUSE: i32 = 1;
const MAP_REQUEST_HEADERS: i32 = 0;
const MAP_RESPONSE_HEADERS: i32 = 2;
const BUFFER_PLUGIN_CONFIGURATION: i32 = 5;
const BUFFER_VM_CONFIGURATION: i32 = 6;

const MAX_PLUGIN_ID_BYTES: usize = 128;
const MAX_PLUGIN_CONFIG_BYTES: usize = 64 * 1024;
const MAX_MODULE_BYTES_HARD: usize = 64 * 1024 * 1024;
const MAX_MEMORY_BYTES_HARD: usize = 256 * 1024 * 1024;
const MAX_HEADER_BYTES_HARD: usize = 1024 * 1024;
const MAX_LOCAL_RESPONSE_BODY_BYTES_HARD: usize = 1024 * 1024;
const MAX_MUTATIONS_HARD: usize = 1024;
const MAX_FUEL_HARD: u64 = 1_000_000_000;
const MAX_TIMEOUT_MS: u64 = 1_000;
const EPOCH_TICK_MS: u64 = 1;
const MAX_PLUGINS_PER_ROUTE: usize = 16;

static WASM_ENGINE: OnceLock<std::result::Result<Engine, String>> = OnceLock::new();

/// 一条 route 的 Proxy-Wasm 头部链。相位已在构建期分组，数据面不每请求过滤枚举。
pub(crate) struct WasmPluginChain {
    request_headers: Arc<[Arc<WasmPlugin>]>,
    response_headers: Arc<[Arc<WasmPlugin>]>,
}

/// 响应回调需要的请求 head 快照。只有 route 显式声明 response plugin 时才创建；
/// `HeaderMap::clone` 共享 `HeaderValue` 字节，不复制请求 body。
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
}

impl WasmPluginChain {
    /// 构建、编译并验证 route 的全部 wasm 模块。任一模块失败则候选快照整体不上线。
    pub(crate) fn build(cfgs: &[WasmPluginCfg], config_dir: &Path, route_id: &str) -> Result<Self> {
        if cfgs.len() > MAX_PLUGINS_PER_ROUTE {
            bail!("route `{route_id}` supports at most {MAX_PLUGINS_PER_ROUTE} wasm plugins");
        }
        let mut ids = std::collections::HashSet::with_capacity(cfgs.len());
        let mut request_headers = Vec::new();
        let mut response_headers = Vec::new();
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
                WasmPluginPhaseCfg::ResponseHeaders => response_headers.push(plugin),
            }
        }
        Ok(Self {
            request_headers: request_headers.into(),
            response_headers: response_headers.into(),
        })
    }

    /// route 是否有响应头插件。
    pub(crate) fn has_response_headers(&self) -> bool {
        !self.response_headers.is_empty()
    }

    /// 在 blocking pool 执行请求头链，避免将同步 JIT 客体指令运行在 Tokio I/O worker 上。
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
        };
        let outcome = tokio::task::spawn_blocking(move || execute_chain(&plugins, input))
            .await
            .context("join Proxy-Wasm request-header worker")??;
        match outcome.outcome {
            ChainOutcome::Continue(headers) => {
                parts.headers = headers;
                Ok(WasmExecution {
                    local_response: None,
                    failed_open: outcome.failed_open,
                })
            }
            ChainOutcome::Local(response) => Ok(WasmExecution {
                local_response: Some(response.into_http()?),
                failed_open: outcome.failed_open,
            }),
        }
    }

    /// 在 request plugin 已提交后捕获 response phase 可读的 request map。
    pub(crate) fn capture_request_head(
        &self,
        parts: &Parts,
        scheme: &str,
    ) -> Option<WasmRequestHeadSnapshot> {
        self.has_response_headers()
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

    /// 执行响应头链。`request_headers` 是上游请求发出前的有界快照，
    /// 仅供客体读；真正可交付的只有 response head，不 clone response body。
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
        };
        let outcome = tokio::task::spawn_blocking(move || execute_chain(&plugins, input))
            .await
            .context("join Proxy-Wasm response-header worker")??;
        match outcome.outcome {
            ChainOutcome::Continue(headers) => {
                *response.headers_mut() = headers;
                Ok(WasmExecution {
                    local_response: None,
                    failed_open: outcome.failed_open,
                })
            }
            ChainOutcome::Local(response) => Ok(WasmExecution {
                local_response: Some(response.into_http()?),
                failed_open: outcome.failed_open,
            }),
        }
    }
}

struct WasmPlugin {
    id: Arc<str>,
    module: Module,
    config: Arc<[u8]>,
    fail_open: bool,
    limits: InvocationLimits,
}

#[derive(Clone, Copy)]
struct InvocationLimits {
    max_memory_bytes: usize,
    max_fuel: u64,
    timeout_ms: u64,
    max_mutations: usize,
    max_header_bytes: usize,
    max_local_response_body_bytes: usize,
}

impl WasmPlugin {
    fn build(cfg: &WasmPluginCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        validate_cfg(cfg)?;
        let module_file = resolve(config_dir, &cfg.module_file);
        // 模块是控制面不可信文件；必须在分配前执行上限，而不是 fs::read 后才检查。
        let bytes =
            crate::bounded_io::read_file(&module_file, cfg.max_module_bytes, "Proxy-Wasm module")?;
        let engine = engine()?;
        let module = Module::from_binary(engine, &bytes)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("compile wasm module {}", module_file.display()))?;
        validate_imports(&module)?;
        let config = serde_json::to_vec(&cfg.config).context("serialize wasm plugin config")?;
        if config.len() > MAX_PLUGIN_CONFIG_BYTES {
            bail!("serialized plugin config exceeds {MAX_PLUGIN_CONFIG_BYTES} bytes");
        }
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
                max_local_response_body_bytes: cfg.max_local_response_body_bytes,
            },
        };
        // 在候选快照构建期实例化一次：这会验证 import 精确签名、初始内存预算
        // 与 core start section。不调用 Proxy-Wasm lifecycle，避免 dry-run 触发业务行为。
        plugin
            .instantiate(HostState::validation(plugin.config.clone(), plugin.limits))
            .with_context(|| format!("validate wasm plugin `{}` for route `{route_id}`", cfg.id))?;
        Ok(plugin)
    }

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

    fn invoke(&self, input: PhaseInput) -> Result<InvocationOutcome> {
        let state = HostState::new(input, self.config.clone(), self.limits)?;
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
            WasmPhase::RequestHeaders => MAP_REQUEST_HEADERS,
            WasmPhase::ResponseHeaders => MAP_RESPONSE_HEADERS,
        };
        let header_count = i32::try_from(visible_header_count(store.data(), map_type)?)
            .context("header count exceeds Proxy-Wasm ABI")?;
        let end_of_stream = i32::from(store.data().end_of_stream);
        let callback = match store.data().phase {
            WasmPhase::RequestHeaders => "proxy_on_request_headers",
            WasmPhase::ResponseHeaders => "proxy_on_response_headers",
        };
        let action = instance
            .get_typed_func::<(i32, i32, i32), i32>(&mut store, callback)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("missing or invalid `{callback}` export"))?
            .call(&mut store, (2, header_count, end_of_stream))
            .map_err(anyhow::Error::from)
            .with_context(|| format!("call `{callback}`"))?;

        let local = store.data_mut().local_response.take();
        if local.is_none() && action != PROXY_ACTION_CONTINUE {
            if action == PROXY_ACTION_PAUSE {
                bail!("plugin returned PAUSE without a local response; body/async resume is unsupported");
            }
            bail!("plugin returned unknown action {action}");
        }
        let _ = call_optional_i32_bool(&mut store, &instance, "proxy_on_done", 2)?;
        call_optional_i32_void(&mut store, &instance, "proxy_on_log", 2)?;
        call_optional_i32_void(&mut store, &instance, "proxy_on_delete", 2)?;

        if let Some(local) = local {
            Ok(InvocationOutcome::Local(local))
        } else {
            Ok(InvocationOutcome::Continue(
                store.data_mut().take_current_headers(),
            ))
        }
    }
}

fn execute_chain(plugins: &[Arc<WasmPlugin>], mut input: PhaseInput) -> Result<ChainExecution> {
    let mut failed_open = 0u64;
    for plugin in plugins {
        // 每个客体收到当前链路 head 的廉价 clone。成功才用返回 head 推进链路；
        // fail-open 时丢弃本客体的部分写，不会污染前一插件已提交的结果。
        let plugin_input = input.clone_for_plugin();
        match plugin.invoke(plugin_input) {
            Ok(InvocationOutcome::Continue(headers)) => input.current_headers = headers,
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
        outcome: ChainOutcome::Continue(input.current_headers),
        failed_open,
    })
}

struct ChainExecution {
    outcome: ChainOutcome,
    failed_open: u64,
}

enum ChainOutcome {
    Continue(HeaderMap),
    Local(LocalResponse),
}

enum InvocationOutcome {
    Continue(HeaderMap),
    Local(LocalResponse),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WasmPhase {
    RequestHeaders,
    ResponseHeaders,
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
}

impl PhaseInput {
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
    plugin_config: Arc<[u8]>,
    limits: InvocationLimits,
    mutations: usize,
    local_response: Option<LocalResponse>,
    store_limits: StoreLimits,
}

impl HostState {
    fn validation(plugin_config: Arc<[u8]>, limits: InvocationLimits) -> Self {
        Self {
            phase: WasmPhase::RequestHeaders,
            current_headers: HeaderMap::new(),
            request_headers: None,
            method: "GET".to_owned(),
            path: "/".to_owned(),
            authority: String::new(),
            scheme: "http".to_owned(),
            end_of_stream: true,
            plugin_config,
            limits,
            mutations: 0,
            local_response: None,
            store_limits: store_limits(limits),
        }
    }

    fn new(input: PhaseInput, plugin_config: Arc<[u8]>, limits: InvocationLimits) -> Result<Self> {
        ensure_header_budget(&input.current_headers, limits.max_header_bytes)?;
        if let Some(headers) = &input.request_headers {
            ensure_header_budget(headers, limits.max_header_bytes)?;
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
            plugin_config,
            limits,
            mutations: 0,
            local_response: None,
            store_limits: store_limits(limits),
        })
    }

    fn take_current_headers(&mut self) -> HeaderMap {
        std::mem::take(&mut self.current_headers)
    }

    fn headers(&self, map_type: i32) -> Option<&HeaderMap> {
        match map_type {
            MAP_REQUEST_HEADERS if self.phase == WasmPhase::RequestHeaders => {
                Some(&self.current_headers)
            }
            MAP_REQUEST_HEADERS => self.request_headers.as_ref(),
            MAP_RESPONSE_HEADERS if self.phase == WasmPhase::ResponseHeaders => {
                Some(&self.current_headers)
            }
            _ => None,
        }
    }

    fn writable_headers(&mut self, map_type: i32) -> Option<&mut HeaderMap> {
        match map_type {
            MAP_REQUEST_HEADERS if self.phase == WasmPhase::RequestHeaders => {
                Some(&mut self.current_headers)
            }
            MAP_RESPONSE_HEADERS if self.phase == WasmPhase::ResponseHeaders => {
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

fn engine() -> Result<&'static Engine> {
    match WASM_ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.wasm_multi_memory(false);
        let engine = Engine::new(&config).map_err(|error| error.to_string())?;
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("nate-wasm-epoch".to_owned())
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

fn validate_cfg(cfg: &WasmPluginCfg) -> Result<()> {
    if cfg.id.is_empty() || cfg.id.len() > MAX_PLUGIN_ID_BYTES {
        bail!("id must contain 1..={MAX_PLUGIN_ID_BYTES} bytes");
    }
    if cfg.module_file.trim().is_empty() {
        bail!("module_file cannot be empty");
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
    if !(1..=MAX_LOCAL_RESPONSE_BODY_BYTES_HARD).contains(&cfg.max_local_response_body_bytes) {
        bail!(
            "max_local_response_body_bytes must be within 1..={MAX_LOCAL_RESPONSE_BODY_BYTES_HARD}"
        );
    }
    Ok(())
}

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

fn supported_import(name: &str) -> bool {
    matches!(
        name,
        "proxy_log"
            | "proxy_get_log_level"
            | "proxy_get_current_time_nanoseconds"
            | "proxy_get_buffer_bytes"
            | "proxy_get_header_map_size"
            | "proxy_get_header_map_pairs"
            | "proxy_set_header_map_pairs"
            | "proxy_get_header_map_value"
            | "proxy_add_header_map_value"
            | "proxy_replace_header_map_value"
            | "proxy_remove_header_map_value"
            | "proxy_send_local_response"
            | "proxy_set_tick_period_milliseconds"
            | "proxy_set_effective_context"
            | "proxy_done"
    )
}

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
                    0 | 1 => tracing::trace!(target: "nate::wasm", %message),
                    2 => tracing::debug!(target: "nate::wasm", %message),
                    3 => tracing::info!(target: "nate::wasm", %message),
                    4 => tracing::warn!(target: "nate::wasm", %message),
                    _ => tracing::error!(target: "nate::wasm", %message),
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
                let source = match buffer_type {
                    BUFFER_PLUGIN_CONFIGURATION => caller.data().plugin_config.clone(),
                    BUFFER_VM_CONFIGURATION => Arc::from([]),
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
    // 头部同步子集不提供 timer/async resume；显式返回 UNIMPLEMENTED，
    // 比伪装成功后让客体永久 PAUSE 更安全。
    for name in [
        "proxy_set_tick_period_milliseconds",
        "proxy_set_effective_context",
    ] {
        linker.func_wrap(
            "env",
            name,
            |_caller: Caller<'_, HostState>, _value: i32| -> i32 { PROXY_STATUS_UNIMPLEMENTED },
        )?;
    }
    linker.func_wrap(
        "env",
        "proxy_done",
        |_caller: Caller<'_, HostState>| -> i32 { PROXY_STATUS_UNIMPLEMENTED },
    )?;
    Ok(linker)
}

fn get_header_value(state: &HostState, map_type: i32, key: &[u8]) -> Result<Option<Vec<u8>>> {
    if key.starts_with(b":") {
        if map_type != MAP_REQUEST_HEADERS {
            return Ok(None);
        }
        return Ok(match key {
            b":method" => Some(state.method.as_bytes().to_vec()),
            b":path" => Some(state.path.as_bytes().to_vec()),
            b":authority" => Some(state.authority.as_bytes().to_vec()),
            b":scheme" => Some(state.scheme.as_bytes().to_vec()),
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
    Ok(headers.len() + usize::from(map_type == MAP_REQUEST_HEADERS) * 4)
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
        .and_then(Extern::into_func)
        .context("guest must export proxy_on_memory_allocate")?
        .typed::<i32, i32>(&*caller)
        .map_err(anyhow::Error::from)
        .context("invalid proxy_on_memory_allocate signature")?;
    let ptr = allocator
        .call(&mut *caller, len)
        .map_err(anyhow::Error::from)
        .context("proxy_on_memory_allocate trapped")?;
    if ptr < 0 {
        bail!("proxy_on_memory_allocate returned a negative pointer");
    }
    write_bytes(caller, ptr, bytes)?;
    write_i32(caller, out_ptr, ptr)?;
    write_i32(caller, out_size, len)
}

fn write_i32(caller: &mut Caller<'_, HostState>, ptr: i32, value: i32) -> Result<()> {
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

fn resolve(base: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// 返回当前快照依赖的 wasm 文件，供 reload watcher 与配置指纹共用。
pub(crate) fn dependency_path(config_dir: &Path, raw: &str) -> Option<PathBuf> {
    (!raw.trim().is_empty()).then(|| resolve(config_dir, raw))
}

#[path = "../../tests/unit/wasm.rs"]
#[cfg(test)]
mod tests;
