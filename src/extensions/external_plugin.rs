//! V7 外部 HTTP 头部插件协议、构建期校验与有界编解码。
//!
//! 该扩展面刻意不传业务 body：普通代理继续逐 frame 流式转发。请求只包含固定元数据和
//! 配置白名单头，响应只允许原子提交白名单头变更或生成有界本地响应。所有 JSON 都在硬
//! 上限内编码/读取；单 frame 响应直接复用 Hyper 的 `Bytes`，只有多 frame 才合并一次。

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};

use crate::config::model::{ExternalPluginCfg, ExternalPluginPhaseCfg};
use crate::{full_body, BoxBody};

const MAX_PLUGINS_PER_ROUTE: usize = 16;
const MAX_PLUGIN_ID_BYTES: usize = 128;
const MAX_HEADERS: usize = 32;
const MAX_PATH_BYTES: usize = 2048;
const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_LOCAL_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

/// 已构建的 route 外部插件链。相位在换版时分组，数据面不逐请求过滤枚举。
pub(crate) struct ExternalPluginChain {
    request_headers: Arc<[Arc<ExternalPlugin>]>,
    response_headers: Arc<[Arc<ExternalPlugin>]>,
    response_request_headers: Arc<[HeaderName]>,
}

/// 一次插件调用所需的已编码 JSON；`Bytes` 直接接管 writer 的唯一 Vec allocation。
pub(crate) struct ExternalPluginPayload {
    pub(crate) body: Bytes,
}

/// 响应相位所需的请求 head 最小快照。
///
/// 只保存所有响应插件 `include_request_headers` 的并集。`Method`/`Uri` clone 复用内部
/// backing，`HeaderValue::clone` 共享字节；不会复制请求 body 或整份 HeaderMap。
pub(crate) struct ExternalRequestHeadSnapshot {
    method: http::Method,
    uri: Uri,
    scheme: Arc<str>,
    headers: HeaderMap,
}

/// 插件响应经完整解析和权限校验后的原子动作。
pub(crate) enum ExternalPluginAction {
    /// 全部变更已验证，可以一次性交付给当前 head。
    Continue(HeaderChanges),
    /// 用本地响应短路当前管线。
    LocalResponse(Response<BoxBody>),
}

/// 已验证的头部 delta。解析失败时不会把其中任何一项写进数据面 head。
pub(crate) struct HeaderChanges {
    set: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

/// 已构建的一条外部 HTTP 插件。
pub(crate) struct ExternalPlugin {
    id: Arc<str>,
    upstream: Arc<str>,
    path: Arc<str>,
    timeout: Duration,
    fail_open: bool,
    authorization: Option<HeaderValue>,
    include_request_headers: Arc<[HeaderName]>,
    include_response_headers: Arc<[HeaderName]>,
    mutation_headers: HashSet<HeaderName>,
    max_header_value_bytes: usize,
    max_input_bytes: usize,
    max_response_bytes: usize,
    max_local_response_body_bytes: usize,
}

/// 本地输入错误不受 fail-open 控制；否则客户端可用超大/非法 allowlist 头绕过插件。
#[derive(Debug)]
pub(crate) enum ExternalPluginInputError {
    InvalidHeader,
    TooLarge,
    Encode,
}

impl ExternalPluginChain {
    /// 构建并校验一条 route 的外部插件链。
    pub(crate) fn build(
        cfgs: &[ExternalPluginCfg],
        config_dir: &Path,
        route_id: &str,
    ) -> Result<Self> {
        if cfgs.len() > MAX_PLUGINS_PER_ROUTE {
            bail!("route `{route_id}` supports at most {MAX_PLUGINS_PER_ROUTE} external plugins");
        }
        let mut ids = HashSet::with_capacity(cfgs.len());
        let mut request_headers = Vec::new();
        let mut response_headers = Vec::new();
        let mut response_request_headers = Vec::new();
        let mut response_request_names = HashSet::new();
        for cfg in cfgs {
            if !ids.insert(cfg.id.as_str()) {
                bail!(
                    "route `{route_id}` contains duplicate external plugin id `{}`",
                    cfg.id
                );
            }
            let plugin = Arc::new(
                ExternalPlugin::build(cfg, config_dir, route_id)
                    .with_context(|| format!("external plugin `{}`", cfg.id))?,
            );
            match cfg.phase {
                ExternalPluginPhaseCfg::RequestHeaders => request_headers.push(plugin),
                ExternalPluginPhaseCfg::ResponseHeaders => {
                    for name in plugin.include_request_headers.iter() {
                        if response_request_names.insert(name.clone()) {
                            response_request_headers.push(name.clone());
                        }
                    }
                    response_headers.push(plugin);
                }
            }
        }
        Ok(Self {
            request_headers: request_headers.into(),
            response_headers: response_headers.into(),
            response_request_headers: response_request_headers.into(),
        })
    }

    pub(crate) fn request_plugins(&self) -> &[Arc<ExternalPlugin>] {
        &self.request_headers
    }

    pub(crate) fn response_plugins(&self) -> &[Arc<ExternalPlugin>] {
        &self.response_headers
    }

    /// 请求插件成功交付后捕获响应相位所需的最小请求快照。
    pub(crate) fn capture_request_head(
        &self,
        parts: &Parts,
        scheme: &'static str,
    ) -> Option<ExternalRequestHeadSnapshot> {
        if self.response_headers.is_empty() {
            return None;
        }
        let mut headers = HeaderMap::with_capacity(self.response_request_headers.len());
        for name in self.response_request_headers.iter() {
            for value in parts.headers.get_all(name).iter() {
                headers.append(name.clone(), value.clone());
            }
        }
        Some(ExternalRequestHeadSnapshot {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            scheme: Arc::from(scheme),
            headers,
        })
    }
}

impl ExternalPlugin {
    fn build(cfg: &ExternalPluginCfg, config_dir: &Path, route_id: &str) -> Result<Self> {
        if cfg.id.is_empty()
            || cfg.id.len() > MAX_PLUGIN_ID_BYTES
            || !cfg
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("id must be 1..={MAX_PLUGIN_ID_BYTES} safe ASCII bytes");
        }
        if !(1..=MAX_TIMEOUT_MS).contains(&cfg.timeout_ms) {
            bail!("timeout_ms must be within 1..={MAX_TIMEOUT_MS}");
        }
        if !(1..=MAX_HEADER_VALUE_BYTES).contains(&cfg.max_header_value_bytes) {
            bail!("max_header_value_bytes must be within 1..={MAX_HEADER_VALUE_BYTES}");
        }
        if !(256..=MAX_INPUT_BYTES).contains(&cfg.max_input_bytes) {
            bail!("max_input_bytes must be within 256..={MAX_INPUT_BYTES}");
        }
        if !(16..=MAX_RESPONSE_BYTES).contains(&cfg.max_response_bytes) {
            bail!("max_response_bytes must be within 16..={MAX_RESPONSE_BYTES}");
        }
        if !(1..=MAX_LOCAL_RESPONSE_BODY_BYTES).contains(&cfg.max_local_response_body_bytes) {
            bail!(
                "max_local_response_body_bytes must be within 1..={MAX_LOCAL_RESPONSE_BODY_BYTES}"
            );
        }
        if cfg.phase == ExternalPluginPhaseCfg::RequestHeaders
            && !cfg.include_response_headers.is_empty()
        {
            bail!("request_headers phase cannot include response headers");
        }
        let (upstream, path) = compile_target(&cfg.target, &cfg.path)?;
        let include_request_headers = compile_headers(&cfg.include_request_headers, "include")?;
        let include_response_headers = compile_headers(&cfg.include_response_headers, "include")?;
        let mutation_headers = compile_headers(&cfg.mutation_headers, "mutate")?
            .into_iter()
            .collect();
        let authorization = if cfg.authorization.trim().is_empty() {
            None
        } else {
            let secret = crate::secret::resolve_text(
                cfg.authorization.as_str(),
                config_dir,
                &format!(
                    "route `{route_id}` external plugin `{}` authorization",
                    cfg.id
                ),
            )?;
            let mut value = HeaderValue::from_str(&secret)
                .context("authorization SecretSource is not a valid header value")?;
            value.set_sensitive(true);
            Some(value)
        };
        Ok(Self {
            id: Arc::from(cfg.id.as_str()),
            upstream: Arc::from(upstream),
            path: Arc::from(path),
            timeout: Duration::from_millis(cfg.timeout_ms),
            fail_open: cfg.fail_open,
            authorization,
            include_request_headers: include_request_headers.into(),
            include_response_headers: include_response_headers.into(),
            mutation_headers,
            max_header_value_bytes: cfg.max_header_value_bytes,
            max_input_bytes: cfg.max_input_bytes,
            max_response_bytes: cfg.max_response_bytes,
            max_local_response_body_bytes: cfg.max_local_response_body_bytes,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn upstream(&self) -> &str {
        &self.upstream
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) const fn fail_open(&self) -> bool {
        self.fail_open
    }

    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn authorization(&self) -> Option<&HeaderValue> {
        self.authorization.as_ref()
    }

    pub(crate) const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// 编码 request_headers phase 输入；只借用当前 head，不 clone header value。
    pub(crate) fn encode_request(
        &self,
        parts: &Parts,
        scheme: &str,
        route_id: &str,
    ) -> std::result::Result<ExternalPluginPayload, ExternalPluginInputError> {
        self.encode(PluginInput {
            phase: "request_headers",
            route_id,
            request: RequestInput {
                method: parts.method.as_str(),
                path: parts.uri.path(),
                query: parts.uri.query(),
                scheme,
                headers: IncludedHeaders {
                    headers: &parts.headers,
                    names: &self.include_request_headers,
                },
            },
            response: None,
        })
    }

    /// 编码 response_headers phase 输入；请求头来自最小快照，响应头直接借用当前响应。
    pub(crate) fn encode_response(
        &self,
        request: &ExternalRequestHeadSnapshot,
        response: &Response<BoxBody>,
        route_id: &str,
    ) -> std::result::Result<ExternalPluginPayload, ExternalPluginInputError> {
        self.encode(PluginInput {
            phase: "response_headers",
            route_id,
            request: RequestInput {
                method: request.method.as_str(),
                path: request.uri.path(),
                query: request.uri.query(),
                scheme: &request.scheme,
                headers: IncludedHeaders {
                    headers: &request.headers,
                    names: &self.include_request_headers,
                },
            },
            response: Some(ResponseInput {
                status: response.status().as_u16(),
                headers: IncludedHeaders {
                    headers: response.headers(),
                    names: &self.include_response_headers,
                },
            }),
        })
    }

    fn encode(
        &self,
        input: PluginInput<'_>,
    ) -> std::result::Result<ExternalPluginPayload, ExternalPluginInputError> {
        validate_included_headers(
            input.request.headers.headers,
            input.request.headers.names,
            self.max_header_value_bytes,
        )?;
        if let Some(response) = &input.response {
            validate_included_headers(
                response.headers.headers,
                response.headers.names,
                self.max_header_value_bytes,
            )?;
        }
        let mut writer = BoundedWriter::new(self.max_input_bytes);
        let encoded = serde_json::to_writer(&mut writer, &input);
        if writer.exceeded {
            return Err(ExternalPluginInputError::TooLarge);
        }
        encoded.map_err(|_| ExternalPluginInputError::Encode)?;
        Ok(ExternalPluginPayload {
            body: Bytes::from(writer.bytes),
        })
    }

    /// 严格解析并完整校验插件输出。调用方只有拿到本值后才能提交变更。
    pub(crate) fn parse_action(&self, body: &[u8]) -> Result<ExternalPluginAction> {
        let output: PluginOutput =
            serde_json::from_slice(body).context("decode external plugin response JSON")?;
        let changes = self.compile_changes(output.set_headers, output.remove_headers)?;
        match output.action {
            OutputAction::Continue => {
                if output.status.is_some() || output.body.is_some() || !output.headers.is_empty() {
                    bail!("continue action cannot contain local response fields");
                }
                Ok(ExternalPluginAction::Continue(changes))
            }
            OutputAction::LocalResponse => {
                if !changes.set.is_empty() || !changes.remove.is_empty() {
                    bail!("local_response action cannot contain continue mutations");
                }
                let status = StatusCode::from_u16(
                    output
                        .status
                        .context("local_response action requires status")?,
                )
                .context("local_response status is invalid")?;
                if status.is_informational() {
                    bail!("local_response status cannot be informational");
                }
                let body = output.body.unwrap_or_default();
                if body.len() > self.max_local_response_body_bytes {
                    bail!("local_response body exceeds configured limit");
                }
                let headers = self.compile_header_map(output.headers)?;
                let mut response = Response::new(full_body(Bytes::from(body)));
                *response.status_mut() = status;
                *response.headers_mut() = headers;
                Ok(ExternalPluginAction::LocalResponse(response))
            }
        }
    }

    fn compile_changes(
        &self,
        set_headers: BTreeMap<String, String>,
        remove_headers: Vec<String>,
    ) -> Result<HeaderChanges> {
        if set_headers.len().saturating_add(remove_headers.len()) > MAX_HEADERS {
            bail!("external plugin returned too many header mutations");
        }
        let mut set = Vec::with_capacity(set_headers.len());
        let mut remove = Vec::with_capacity(remove_headers.len());
        let mut seen = HashSet::with_capacity(set_headers.len() + remove_headers.len());
        for (raw_name, raw_value) in set_headers {
            let name = HeaderName::from_bytes(raw_name.as_bytes())
                .context("external plugin returned invalid header name")?;
            self.validate_mutation_name(&name)?;
            if raw_value.len() > self.max_header_value_bytes {
                bail!("external plugin returned an oversized header value");
            }
            let value = HeaderValue::from_str(&raw_value)
                .context("external plugin returned invalid header value")?;
            if !seen.insert(name.clone()) {
                bail!("external plugin returned duplicate header mutation");
            }
            set.push((name, value));
        }
        for raw_name in remove_headers {
            let name = HeaderName::from_bytes(raw_name.as_bytes())
                .context("external plugin returned invalid remove header name")?;
            self.validate_mutation_name(&name)?;
            if !seen.insert(name.clone()) {
                bail!("external plugin returned conflicting header mutations");
            }
            remove.push(name);
        }
        Ok(HeaderChanges { set, remove })
    }

    fn compile_header_map(&self, raw: BTreeMap<String, String>) -> Result<HeaderMap> {
        if raw.len() > MAX_HEADERS {
            bail!("external plugin returned too many local response headers");
        }
        let mut headers = HeaderMap::with_capacity(raw.len());
        for (raw_name, raw_value) in raw {
            let name = HeaderName::from_bytes(raw_name.as_bytes())
                .context("external plugin returned invalid local response header name")?;
            self.validate_mutation_name(&name)?;
            if raw_value.len() > self.max_header_value_bytes {
                bail!("external plugin returned an oversized local response header value");
            }
            let value = HeaderValue::from_str(&raw_value)
                .context("external plugin returned invalid local response header value")?;
            headers.insert(name, value);
        }
        Ok(headers)
    }

    fn validate_mutation_name(&self, name: &HeaderName) -> Result<()> {
        if !self.mutation_headers.contains(name) {
            bail!("external plugin attempted a header mutation outside its allowlist");
        }
        Ok(())
    }
}

impl HeaderChanges {
    /// 在全部 delta 校验通过后一次性写入请求 head。
    pub(crate) fn apply_request(self, parts: &mut Parts) {
        apply_changes(&mut parts.headers, self);
    }

    /// 在全部 delta 校验通过后一次性写入响应 head；body 不动、不 clone。
    pub(crate) fn apply_response(self, response: &mut Response<BoxBody>) {
        apply_changes(response.headers_mut(), self);
    }
}

fn apply_changes(headers: &mut HeaderMap, changes: HeaderChanges) {
    for name in changes.remove {
        headers.remove(name);
    }
    for (name, value) in changes.set {
        headers.insert(name, value);
    }
}

/// 外部插件成功响应只接受 JSON/vendor +json。
pub(crate) fn response_is_json(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let media_type = value.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("application/json")
        || (media_type.len() > "application/+json".len()
            && media_type
                .get(.."application/".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/"))
            && media_type
                .get(media_type.len().saturating_sub("+json".len())..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json")))
}

/// 业务作用：有界收集外部插件 JSON body，并接受符合 HTTP 语义的尾随元数据。
///
/// 参数说明：`body` 是插件响应流；`headers` 用于前置 Content-Length 门；`max_bytes` 是 JSON body 硬上限。
///
/// 返回：单 DATA frame 保持零拷贝，多 frame 只合并一次；trailers 不参与插件动作解析但会被安全消费。
pub(crate) async fn collect_response(
    mut body: BoxBody,
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<Bytes> {
    if headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > max_bytes)
    {
        bail!("external plugin response exceeds configured limit");
    }
    let mut first = None;
    let mut merged: Option<BytesMut> = None;
    let mut length = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| anyhow::anyhow!("read plugin response: {error}"))?;
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(_trailers) => {
                // 插件动作的唯一事实源是有界 JSON body；HTTP trailers 属于传输元数据。
                // 接受但不映射成业务 header，避免未经 mutation allowlist 的尾部字段越权写入请求。
                continue;
            }
        };
        length = length
            .checked_add(data.len())
            .context("plugin response size overflow")?;
        if length > max_bytes {
            bail!("external plugin response exceeds configured limit");
        }
        if data.is_empty() {
            continue;
        }
        match (&mut first, &mut merged) {
            (slot @ None, None) => *slot = Some(data),
            (first, slot @ None) => {
                let prior = first.take().expect("first plugin response frame exists");
                let mut buffer = BytesMut::with_capacity(length);
                buffer.extend_from_slice(&prior);
                buffer.extend_from_slice(&data);
                *slot = Some(buffer);
            }
            (_, Some(buffer)) => buffer.extend_from_slice(&data),
        }
    }
    Ok(merged
        .map(BytesMut::freeze)
        .unwrap_or_else(|| first.unwrap_or_default()))
}

#[derive(Serialize)]
struct PluginInput<'a> {
    phase: &'static str,
    route_id: &'a str,
    request: RequestInput<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<ResponseInput<'a>>,
}

#[derive(Serialize)]
struct RequestInput<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    scheme: &'a str,
    headers: IncludedHeaders<'a>,
}

#[derive(Serialize)]
struct ResponseInput<'a> {
    status: u16,
    headers: IncludedHeaders<'a>,
}

struct IncludedHeaders<'a> {
    headers: &'a HeaderMap,
    names: &'a [HeaderName],
}

impl Serialize for IncludedHeaders<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.names.len()))?;
        for name in self.names {
            map.serialize_entry(
                name.as_str(),
                &IncludedHeaderValues {
                    values: self.headers.get_all(name),
                },
            )?;
        }
        map.end()
    }
}

struct IncludedHeaderValues<'a> {
    values: http::header::GetAll<'a, HeaderValue>,
}

impl Serialize for IncludedHeaderValues<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(None)?;
        for value in self.values.iter() {
            sequence.serialize_element(value.to_str().map_err(serde::ser::Error::custom)?)?;
        }
        sequence.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginOutput {
    action: OutputAction,
    #[serde(default)]
    set_headers: BTreeMap<String, String>,
    #[serde(default)]
    remove_headers: Vec<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutputAction {
    Continue,
    LocalResponse,
}

struct BoundedWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(length) = self.bytes.len().checked_add(input.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("external plugin input size overflow"));
        };
        if length > self.max_bytes {
            self.exceeded = true;
            return Err(io::Error::other(
                "external plugin input exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_included_headers(
    headers: &HeaderMap,
    names: &[HeaderName],
    max_value_bytes: usize,
) -> std::result::Result<(), ExternalPluginInputError> {
    for name in names {
        for value in headers.get_all(name).iter() {
            if value.as_bytes().len() > max_value_bytes || value.to_str().is_err() {
                return Err(ExternalPluginInputError::InvalidHeader);
            }
        }
    }
    Ok(())
}

fn compile_target(target: &str, path: &str) -> Result<(String, String)> {
    let path = parse_path(path)?;
    if let Some(service) = target.strip_prefix("lb://") {
        if service.is_empty() || service.contains('/') {
            bail!("lb target must be exactly `lb://service`");
        }
        return Ok((target.to_owned(), path));
    }
    let uri = target.parse::<Uri>().context("invalid target URI")?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        bail!("target requires http/https authority or lb://service");
    }
    if uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        bail!("target must be an origin without path/query; use path field");
    }
    Ok((
        format!(
            "{}://{}",
            uri.scheme_str().expect("validated plugin scheme"),
            uri.authority().expect("validated plugin authority")
        ),
        path,
    ))
}

fn parse_path(path: &str) -> Result<String> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.bytes().any(|byte| byte <= 0x20)
    {
        bail!("path must be an absolute URI path within {MAX_PATH_BYTES} bytes");
    }
    let uri = path.parse::<Uri>().context("invalid plugin path")?;
    if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
        bail!("path cannot contain scheme/authority/query");
    }
    Ok(path.to_owned())
}

fn compile_headers(raw: &[String], operation: &str) -> Result<Vec<HeaderName>> {
    if raw.len() > MAX_HEADERS {
        bail!("header allowlist supports at most {MAX_HEADERS} names");
    }
    let mut seen = HashSet::with_capacity(raw.len());
    let mut names = Vec::with_capacity(raw.len());
    for value in raw {
        let name = HeaderName::from_bytes(value.as_bytes()).context("invalid header allowlist")?;
        if forbidden_header(&name) {
            bail!("external plugin cannot {operation} sensitive/framing header `{name}`");
        }
        if seen.insert(name.clone()) {
            names.push(name);
        }
    }
    Ok(names)
}

fn forbidden_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "host"
            | "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "trailer"
            | "te"
            | "content-length"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

/// 返回外部插件 Authorization SecretSource 的文件依赖，供 reload watcher 对账。
pub(crate) fn dependency_path(
    config_dir: &Path,
    cfg: &ExternalPluginCfg,
) -> Option<std::path::PathBuf> {
    crate::secret::dependency_path(cfg.authorization.as_str(), config_dir)
}
