//! V7 Open Policy Agent 外部授权策略、输入编码与有界 decision L1。
//!
//! OPA 是授权而不是认证：本模块只接收主管线已经验证出的 `consumer`，绝不从
//! `X-Auth-User`/Authorization/Cookie 等客户端头推导身份。业务 body 不进入 OPA；默认 HTTP
//! 代理仍保持流式。只有显式配置的少量 request header 会放进
//! `request_headers_untrusted`，提醒 Rego 作者这些值不是可信 principal。

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use http_body_util::BodyExt;
use nasa::cache::local_cache::BoundedLocalCache;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::config::model::OpaAuthorizationCfg;
use crate::BoxBody;

const MAX_OPA_TIMEOUT_MS: u64 = 60_000;
const MAX_OPA_HEADERS: usize = 32;
const MAX_OPA_HEADER_VALUE_BYTES: usize = 64 * 1024;
const MAX_OPA_INPUT_BYTES: usize = 1024 * 1024;
const MAX_OPA_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_OPA_CACHE_TTL_MS: u64 = 300_000;
const MAX_OPA_CACHE_ENTRIES: u64 = 1_000_000;
const MAX_OPA_POLICY_REVISION_BYTES: usize = 128;
const MAX_OPA_PATH_BYTES: usize = 2048;

/// 构建完成的 route 级 OPA 策略。
pub(crate) struct OpaPolicy {
    /// 已规范化的 OPA 上游 base；不含 Data API path。
    pub(crate) upstream: String,
    /// OPA Data API path。
    pub(crate) path: String,
    timeout: Duration,
    fail_open: bool,
    authorization: Option<HeaderValue>,
    include_headers: Vec<HeaderName>,
    max_header_value_bytes: usize,
    max_input_bytes: usize,
    max_response_bytes: usize,
    require_identity: bool,
    policy_salt: [u8; 32],
    cache: Option<OpaDecisionCache>,
}

struct OpaDecisionCache {
    entries: BoundedLocalCache<[u8; 32], CachedDecision>,
    ttl: Duration,
}

struct CachedDecision {
    decision: OpaDecision,
    expires_at: Instant,
}

/// OPA 的最终二值授权结果。transport/协议错误不伪装成 deny。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpaDecision {
    Allow,
    Deny,
}

/// 已准备的 OPA JSON request body。`Bytes` 接管 serializer 的 Vec allocation，不再复制。
pub(crate) struct OpaInputPayload {
    /// decision cache 的 SHA-256 key；不含 header/consumer 原文。
    pub(crate) cache_key: [u8; 32],
    /// `{ "input": ... }` JSON body。
    pub(crate) body: Bytes,
}

/// 一次 OPA 授权共享的只读输入视图。
///
/// cache-key 与 JSON serializer 必须消费同一份 context，避免未来新增字段时只更新一条
/// 路径而造成错误 cache 命中。所有字符串均借用 route/request snapshot，不在热路径 clone。
pub(crate) struct OpaRequestContext<'a> {
    parts: &'a Parts,
    client_ip: IpAddr,
    downstream_proto: &'a str,
    route_id: &'a str,
    authenticated: bool,
    consumer: Option<&'a str>,
}

impl<'a> OpaRequestContext<'a> {
    /// 创建请求级 OPA 输入视图；调用方须先冻结认证结果，不能传入未经验证的身份头。
    pub(crate) fn new(
        parts: &'a Parts,
        client_ip: IpAddr,
        downstream_proto: &'a str,
        route_id: &'a str,
        authenticated: bool,
        consumer: Option<&'a str>,
    ) -> Self {
        Self {
            parts,
            client_ip,
            downstream_proto,
            route_id,
            authenticated,
            consumer,
        }
    }
}

/// 构造 OPA input 前的本地请求错误；这些错误不受 fail-open 控制。
#[derive(Debug)]
pub(crate) enum OpaInputError {
    /// route 要求稳定身份，但已通过的认证方式没有 consumer。
    MissingIdentity,
    /// allowlist header 含非 UTF-8 或单值超过上限。
    InvalidHeader,
    /// input 在有界 writer 中达到 route 上限。
    TooLarge,
    /// 理论上不可达的 JSON serialization 错误。
    Encode,
}

impl OpaPolicy {
    /// 编译并校验 OPA route 配置；网络地址、header 和 SecretSource 均在换版前处理。
    pub(crate) fn build(
        cfg: &OpaAuthorizationCfg,
        config_dir: &Path,
        route_id: &str,
    ) -> Result<Self> {
        if !(1..=MAX_OPA_TIMEOUT_MS).contains(&cfg.timeout_ms) {
            bail!(
                "route `{route_id}` opa_authorization timeout_ms must be within 1..={MAX_OPA_TIMEOUT_MS}"
            );
        }
        if !(1..=MAX_OPA_HEADER_VALUE_BYTES).contains(&cfg.max_header_value_bytes) {
            bail!(
                "route `{route_id}` opa_authorization max_header_value_bytes must be within 1..={MAX_OPA_HEADER_VALUE_BYTES}"
            );
        }
        if !(256..=MAX_OPA_INPUT_BYTES).contains(&cfg.max_input_bytes) {
            bail!(
                "route `{route_id}` opa_authorization max_input_bytes must be within 256..={MAX_OPA_INPUT_BYTES}"
            );
        }
        if !(16..=MAX_OPA_RESPONSE_BYTES).contains(&cfg.max_response_bytes) {
            bail!(
                "route `{route_id}` opa_authorization max_response_bytes must be within 16..={MAX_OPA_RESPONSE_BYTES}"
            );
        }
        let (upstream, path) = compile_target(&cfg.target, &cfg.path, route_id)?;
        let include_headers = compile_headers(&cfg.include_headers, route_id)?;
        let authorization = if cfg.authorization.trim().is_empty() {
            None
        } else {
            let secret = crate::secret::resolve_text(
                cfg.authorization.as_str(),
                config_dir,
                &format!("route `{route_id}` opa_authorization authorization"),
            )?;
            let mut value = HeaderValue::from_str(&secret).with_context(|| {
                format!("route `{route_id}` opa_authorization authorization is not a header value")
            })?;
            value.set_sensitive(true);
            Some(value)
        };
        let cache = cfg
            .cache
            .as_ref()
            .map(|cache| {
                if !(1..=MAX_OPA_CACHE_TTL_MS).contains(&cache.ttl_ms) {
                    bail!(
                        "route `{route_id}` opa_authorization cache.ttl_ms must be within 1..={MAX_OPA_CACHE_TTL_MS}"
                    );
                }
                if !(1..=MAX_OPA_CACHE_ENTRIES).contains(&cache.max_entries) {
                    bail!(
                        "route `{route_id}` opa_authorization cache.max_entries must be within 1..={MAX_OPA_CACHE_ENTRIES}"
                    );
                }
                validate_policy_revision(cache.policy_revision.as_str(), route_id)?;
                Ok(OpaDecisionCache {
                    entries: BoundedLocalCache::new(cache.max_entries),
                    ttl: Duration::from_millis(cache.ttl_ms),
                })
            })
            .transpose()?;
        let policy_salt = policy_salt(
            upstream.as_str(),
            path.as_str(),
            cfg.cache
                .as_ref()
                .map(|cache| cache.policy_revision.as_str())
                .unwrap_or("cache-disabled"),
            include_headers.as_slice(),
            cfg.require_identity,
            authorization.as_ref(),
        );
        Ok(Self {
            upstream,
            path,
            timeout: Duration::from_millis(cfg.timeout_ms),
            fail_open: cfg.fail_open,
            authorization,
            include_headers,
            max_header_value_bytes: cfg.max_header_value_bytes,
            max_input_bytes: cfg.max_input_bytes,
            max_response_bytes: cfg.max_response_bytes,
            require_identity: cfg.require_identity,
            policy_salt,
            cache,
        })
    }

    /// OPA response head/body 的总 deadline。
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// transport/5xx/畸形响应是否放行。
    pub(crate) fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// 可选 OPA 服务 Authorization header。值已标 sensitive，日志不得格式化它。
    pub(crate) fn authorization(&self) -> Option<&HeaderValue> {
        self.authorization.as_ref()
    }

    /// OPA response body 上限。
    pub(crate) fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// 是否要求稳定 consumer。
    pub(crate) fn requires_identity(&self) -> bool {
        self.require_identity
    }

    /// 是否启用了本节点 decision cache。
    pub(crate) fn cache_enabled(&self) -> bool {
        self.cache.is_some()
    }

    /// 只计算 cache key 并验证所有输入字段；命中时不构造 JSON body。
    pub(crate) fn input_cache_key(
        &self,
        input: &OpaRequestContext<'_>,
    ) -> std::result::Result<[u8; 32], OpaInputError> {
        if self.require_identity && input.consumer.is_none() {
            return Err(OpaInputError::MissingIdentity);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"gw-opa-input-v1\0");
        hasher.update(self.policy_salt);
        hash_field(&mut hasher, input.parts.method.as_str().as_bytes());
        hash_field(&mut hasher, input.parts.uri.path().as_bytes());
        // Query 往往承载 resource/tenant/filter；漏入 key 会让同 path 的 allow 决策跨
        // query 复用。保留 raw query，避免 parse/re-encode 的语义差异和额外分配。
        hash_field(
            &mut hasher,
            input.parts.uri.query().unwrap_or_default().as_bytes(),
        );
        hash_field(&mut hasher, input.downstream_proto.as_bytes());
        hash_field(&mut hasher, input.route_id.as_bytes());
        hasher.update([u8::from(input.authenticated)]);
        match input.client_ip {
            IpAddr::V4(ip) => {
                hasher.update([4]);
                hasher.update(ip.octets());
            }
            IpAddr::V6(ip) => {
                hasher.update([6]);
                hasher.update(ip.octets());
            }
        }
        hash_field(&mut hasher, input.consumer.unwrap_or_default().as_bytes());
        let mut raw_bytes = 0usize;
        for name in &self.include_headers {
            hash_field(&mut hasher, name.as_str().as_bytes());
            for value in input.parts.headers.get_all(name).iter() {
                let value = value.to_str().map_err(|_| OpaInputError::InvalidHeader)?;
                if value.len() > self.max_header_value_bytes {
                    return Err(OpaInputError::InvalidHeader);
                }
                raw_bytes = raw_bytes
                    .checked_add(value.len())
                    .ok_or(OpaInputError::TooLarge)?;
                if raw_bytes > self.max_input_bytes {
                    return Err(OpaInputError::TooLarge);
                }
                hash_field(&mut hasher, value.as_bytes());
            }
            // 区分 `["ab","c"]` 与 `["ab","c",""]` 等尾部结构。
            hasher.update([0xff]);
        }
        Ok(hasher.finalize().into())
    }

    /// 在 cache miss 后一次性编码有界 JSON input。
    pub(crate) fn encode_input(
        &self,
        cache_key: [u8; 32],
        context: &OpaRequestContext<'_>,
    ) -> std::result::Result<OpaInputPayload, OpaInputError> {
        let input = OpaEnvelope {
            input: OpaInput {
                method: context.parts.method.as_str(),
                path: context.parts.uri.path(),
                query: context.parts.uri.query(),
                scheme: context.downstream_proto,
                route_id: context.route_id,
                client_ip: context.client_ip,
                authenticated: context.authenticated,
                consumer: context.consumer,
                request_headers_untrusted: IncludedHeaders {
                    headers: &context.parts.headers,
                    names: self.include_headers.as_slice(),
                },
            },
        };
        // 有界 writer 在 serializer 写入前检查剩余容量；恶意 header 的 JSON escaping 也不能
        // 先制造超大 Vec 再在事后发现超限。
        let mut writer = BoundedWriter::new(self.max_input_bytes);
        let encoded = serde_json::to_writer(&mut writer, &input);
        if writer.exceeded {
            return Err(OpaInputError::TooLarge);
        }
        encoded.map_err(|_| OpaInputError::Encode)?;
        Ok(OpaInputPayload {
            cache_key,
            body: Bytes::from(writer.bytes),
        })
    }

    /// 查 decision L1。过期 entry 立即失效并按 miss 处理。
    pub(crate) async fn cached_decision(&self, key: &[u8; 32]) -> Option<OpaDecision> {
        let cache = self.cache.as_ref()?;
        let entry = cache.entries.get(key).await?;
        if Instant::now() < entry.expires_at {
            return Some(entry.decision);
        }
        cache.entries.invalidate(key).await;
        None
    }

    /// 只缓存明确 allow/deny；调用方不得把 transport/解析错误传入。
    pub(crate) async fn store_decision(&self, key: [u8; 32], decision: OpaDecision) {
        let Some(cache) = &self.cache else {
            return;
        };
        cache
            .entries
            .insert(
                key,
                CachedDecision {
                    decision,
                    expires_at: Instant::now() + cache.ttl,
                },
            )
            .await;
    }
}

/// 检查 OPA 成功响应的 media type；允许 vendor `application/*+json`。
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

/// 读取 OPA 小响应并保持单 frame `Bytes` 零拷贝。trailers 对 decision contract 无定义，出现即拒绝。
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
        bail!("OPA response exceeds configured body limit");
    }
    let mut first: Option<Bytes> = None;
    let mut merged: Option<BytesMut> = None;
    let mut length = 0usize;
    while let Some(frame) = body.frame().await {
        // `BoxBody` 的统一错误类型是动态 trait object；显式转成 anyhow，同时保留
        // source 的可读文本，避免依赖 `Context` 对不同 anyhow 版本/trait object 的推导。
        let frame = frame.map_err(|error| anyhow::anyhow!("read OPA response frame: {error}"))?;
        let data = frame
            .into_data()
            .map_err(|_| anyhow::anyhow!("OPA response trailers are unsupported"))?;
        length = length
            .checked_add(data.len())
            .context("OPA response size overflow")?;
        if length > max_bytes {
            bail!("OPA response exceeds configured body limit");
        }
        if data.is_empty() {
            continue;
        }
        match (&mut first, &mut merged) {
            (slot @ None, None) => *slot = Some(data),
            (first, slot @ None) => {
                let prior = first.take().expect("first OPA response frame exists");
                let mut buffer = BytesMut::with_capacity(length);
                buffer.extend_from_slice(&prior);
                buffer.extend_from_slice(&data);
                *slot = Some(buffer);
            }
            (_, Some(buffer)) => buffer.extend_from_slice(&data),
        }
    }
    Ok(match merged {
        Some(buffer) => buffer.freeze(),
        None => first.unwrap_or_default(),
    })
}

/// 严格解析 OPA `{result:true}` 或 `{result:{allow:true}}`。缺失 result 是 undefined/error，
/// 不能静默当 deny，否则策略拼错会伪装成正常业务拒绝而难以告警。
pub(crate) fn parse_decision(body: &[u8]) -> Result<OpaDecision> {
    let response: OpaResponse = serde_json::from_slice(body).context("decode OPA response JSON")?;
    let allowed = match response.result {
        OpaResult::Boolean(allowed) => allowed,
        OpaResult::Object { allow } => allow,
    };
    Ok(if allowed {
        OpaDecision::Allow
    } else {
        OpaDecision::Deny
    })
}

#[derive(Serialize)]
struct OpaEnvelope<'a> {
    input: OpaInput<'a>,
}

#[derive(Serialize)]
struct OpaInput<'a> {
    method: &'a str,
    path: &'a str,
    /// 未解码的原始 query；None 与空 query 在 JSON 中明确区分。
    query: Option<&'a str>,
    scheme: &'a str,
    route_id: &'a str,
    client_ip: IpAddr,
    authenticated: bool,
    consumer: Option<&'a str>,
    request_headers_untrusted: IncludedHeaders<'a>,
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
            let value = value.to_str().map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(value)?;
        }
        sequence.end()
    }
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
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("OPA input size overflow"));
        };
        if next_len > self.max_bytes {
            self.exceeded = true;
            return Err(io::Error::other("OPA input exceeds configured limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Deserialize)]
struct OpaResponse {
    result: OpaResult,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OpaResult {
    Boolean(bool),
    Object { allow: bool },
}

fn compile_target(target: &str, path: &str, route_id: &str) -> Result<(String, String)> {
    let path = parse_policy_path(path, route_id)?;
    if let Some(service) = target.strip_prefix("lb://") {
        if service.is_empty() || service.contains('/') {
            bail!("route `{route_id}` opa_authorization lb target must be exactly `lb://service`");
        }
        return Ok((target.to_string(), path));
    }
    let uri = target.parse::<Uri>().with_context(|| {
        format!("route `{route_id}` opa_authorization invalid target `{target}`")
    })?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        bail!(
            "route `{route_id}` opa_authorization target requires http/https authority or lb://service"
        );
    }
    if uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        bail!(
            "route `{route_id}` opa_authorization target must be an origin without path/query; use path field"
        );
    }
    let authority = uri.authority().expect("validated OPA target authority");
    Ok((
        format!(
            "{}://{}",
            uri.scheme_str().expect("validated OPA target scheme"),
            authority
        ),
        path,
    ))
}

fn parse_policy_path(path: &str, route_id: &str) -> Result<String> {
    if path.is_empty()
        || path.len() > MAX_OPA_PATH_BYTES
        || !path.starts_with('/')
        || path.bytes().any(|byte| byte <= 0x20)
    {
        bail!(
            "route `{route_id}` opa_authorization path must be an absolute URI path within {MAX_OPA_PATH_BYTES} bytes"
        );
    }
    let uri = path
        .parse::<Uri>()
        .with_context(|| format!("route `{route_id}` opa_authorization invalid path `{path}`"))?;
    if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
        bail!("route `{route_id}` opa_authorization path cannot contain scheme/authority/query");
    }
    Ok(path.to_string())
}

fn compile_headers(raw: &[String], route_id: &str) -> Result<Vec<HeaderName>> {
    if raw.len() > MAX_OPA_HEADERS {
        bail!(
            "route `{route_id}` opa_authorization include_headers supports at most {MAX_OPA_HEADERS} names"
        );
    }
    let mut unique = HashSet::with_capacity(raw.len());
    let mut headers = Vec::with_capacity(raw.len());
    for value in raw {
        let name = value.parse::<HeaderName>().with_context(|| {
            format!("route `{route_id}` opa_authorization invalid header `{value}`")
        })?;
        if !opa_header_is_safe(&name) {
            bail!(
                "route `{route_id}` opa_authorization cannot include sensitive/body/hop header `{value}`"
            );
        }
        if unique.insert(name.clone()) {
            headers.push(name);
        }
    }
    headers.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    Ok(headers)
}

fn opa_header_is_safe(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "host"
            | "connection"
            | "content-length"
            | "content-type"
            | "transfer-encoding"
            | "expect"
            | "te"
            | "trailer"
            | "upgrade"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
    )
}

fn validate_policy_revision(value: &str, route_id: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_OPA_POLICY_REVISION_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!(
            "route `{route_id}` opa_authorization cache.policy_revision must be 1..={MAX_OPA_POLICY_REVISION_BYTES} visible bytes"
        );
    }
    Ok(())
}

fn policy_salt(
    upstream: &str,
    path: &str,
    revision: &str,
    headers: &[HeaderName],
    require_identity: bool,
    authorization: Option<&HeaderValue>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gw-opa-policy-v1\0");
    hash_field(&mut hasher, upstream.as_bytes());
    hash_field(&mut hasher, path.as_bytes());
    hash_field(&mut hasher, revision.as_bytes());
    hasher.update([u8::from(require_identity)]);
    for header in headers {
        hash_field(&mut hasher, header.as_str().as_bytes());
    }
    // 只把 credential 摘要折入 salt，永不把原值放进 cache key/log/metric。
    if let Some(value) = authorization {
        hasher.update(Sha256::digest(value.as_bytes()));
    }
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[path = "../../tests/unit/opa.rs"]
#[cfg(test)]
mod tests;
