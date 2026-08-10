//! V7 GraphQL-over-HTTP 查询预算守卫。
//!
//! 普通 route 不会进入本模块。显式配置 `graphql_guard` 后，GET 只借用 URI query，
//! POST 才在 route 独立硬上限内读取实体。lexer/parser 的 token、嵌套、fragment 展开和
//! complexity 都有预算；这样“先完整解析再看是否超限”不会把防护器本身变成 CPU/栈 DoS。

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{bail, Result};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::request::Parts;
use http::Method;
use serde::Deserialize;

use crate::config::model::GraphqlGuardCfg;
use crate::proxy::forward::ForwardBody;
use crate::proxy::request_validation::{buffered_body, collect_bounded, CollectError};

/// 控制面允许的 POST body 绝对上限。route 还可配置更小值。
const HARD_MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;
/// 解码后的 query 绝对上限；与 body 上限分离，因为 GET 没有 body。
const HARD_MAX_QUERY_BYTES: usize = 1024 * 1024;
/// token arena 的绝对上限，避免配置把解析器变成大内存消费者。
const HARD_MAX_TOKENS: usize = 262_144;
/// 所有递归入口都受这个 build-time 上限约束，防止 Rust 调用栈耗尽。
const HARD_MAX_DEPTH: usize = 128;
/// 单请求字段成本绝对上限；计算使用饱和加法，不会发生 usize wraparound。
const HARD_MAX_COMPLEXITY: usize = 10_000_000;

/// 构建期验证后的 GraphQL route 策略。
pub(crate) struct GraphqlGuardPolicy {
    max_body_bytes: u64,
    max_query_bytes: usize,
    max_tokens: usize,
    max_depth: usize,
    max_complexity: usize,
    allow_introspection: bool,
    allow_websocket_subscriptions: bool,
}

/// GraphQL 守卫的固定低基数结果。只由网关代码产生，绝不接受请求输入作为 label。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphqlGuardResult {
    /// 查询在所有预算内，可继续到上游。
    Allowed,
    /// HTTP envelope 或 GraphQL 文档结构无效。
    Invalid,
    /// body/query/token 资源预算超限。
    TooLarge,
    /// selection/fragment 递归深度超限。
    TooDeep,
    /// 展开 fragment 后字段成本超限。
    TooComplex,
    /// route 禁止 introspection 且可达选择包含 `__*` 字段。
    IntrospectionDenied,
    /// 下游 body transport 读取失败。
    BodyReadError,
}

/// 守卫短路信息。状态码和消息固定，避免把 parser 细节或请求片段回显给客户端。
pub(crate) struct GraphqlRejection {
    /// Prometheus 固定结果。
    pub(crate) result: GraphqlGuardResult,
    /// 下游 HTTP 状态码。
    pub(crate) status: u16,
    /// 无请求数据的稳定错误文本。
    pub(crate) message: &'static str,
}

/// 请求检查结果。Allowed 必须归还可继续转发的原 body 或同 allocation 重放 body。
pub(crate) enum GraphqlOutcome {
    /// 查询合法且资源预算内。
    Allowed(ForwardBody),
    /// 请求在访问上游前被拒绝。
    Rejected(GraphqlRejection),
}

impl GraphqlGuardPolicy {
    /// 编译 route 配置并拒绝无效或无法形成真实资源约束的预算。
    pub(crate) fn build(cfg: &GraphqlGuardCfg, route_id: &str) -> Result<Self> {
        if !(1..=HARD_MAX_BODY_BYTES).contains(&cfg.max_body_bytes) {
            bail!(
                "route `{route_id}` graphql_guard max_body_bytes must be within 1..={HARD_MAX_BODY_BYTES}"
            );
        }
        if !(1..=HARD_MAX_QUERY_BYTES).contains(&cfg.max_query_bytes) {
            bail!(
                "route `{route_id}` graphql_guard max_query_bytes must be within 1..={HARD_MAX_QUERY_BYTES}"
            );
        }
        if !(1..=HARD_MAX_TOKENS).contains(&cfg.max_tokens) || cfg.max_tokens > cfg.max_query_bytes
        {
            bail!(
                "route `{route_id}` graphql_guard max_tokens must be within 1..=min(max_query_bytes,{HARD_MAX_TOKENS})"
            );
        }
        if !(1..=HARD_MAX_DEPTH).contains(&cfg.max_depth) {
            bail!("route `{route_id}` graphql_guard max_depth must be within 1..={HARD_MAX_DEPTH}");
        }
        if !(1..=HARD_MAX_COMPLEXITY).contains(&cfg.max_complexity) {
            bail!(
                "route `{route_id}` graphql_guard max_complexity must be within 1..={HARD_MAX_COMPLEXITY}"
            );
        }
        Ok(Self {
            max_body_bytes: cfg.max_body_bytes,
            max_query_bytes: cfg.max_query_bytes,
            max_tokens: cfg.max_tokens,
            max_depth: cfg.max_depth,
            max_complexity: cfg.max_complexity,
            allow_introspection: cfg.allow_introspection,
            allow_websocket_subscriptions: cfg.allow_websocket_subscriptions,
        })
    }

    /// 构建期校验 degraphql 固定文档。查询形状不会随请求变化，因此只需在候选快照
    /// 发布前完成一次 lexer/parser/fragment 预算检查，运行期只编码 variables。
    pub(crate) fn validate_static_query(
        &self,
        query: &str,
        operation_name: Option<&str>,
    ) -> Result<()> {
        self.analyze(query, operation_name, false)
            .map_err(|rejection| anyhow::anyhow!(rejection.message))
    }

    /// 校验 GraphQL-over-HTTP envelope 与查询预算。
    ///
    /// GET 不接触 body。POST 聚合是 GraphQL 解析不可避免的显式慢路径：单 frame 直接
    /// 复用 `Bytes`，多 frame 只合并一次，成功后同一字节块连同 trailers 重放给上游。
    pub(crate) async fn inspect(&self, parts: &Parts, body: ForwardBody) -> GraphqlOutcome {
        match parts.method {
            Method::GET => {
                if is_graphql_websocket_upgrade(parts) {
                    return if self.allow_websocket_subscriptions {
                        // HTTP guard 无法在不终止透明隧道的情况下逐条重写 WebSocket；显式开关
                        // 把 message-level query budget 权威交给上游，握手前治理仍由网关执行。
                        GraphqlOutcome::Allowed(body)
                    } else {
                        GraphqlOutcome::Rejected(reject(
                            GraphqlGuardResult::Invalid,
                            403,
                            "GraphQL WebSocket subscriptions are disabled",
                        ))
                    };
                }
                let analysis = self.inspect_get(parts);
                match analysis {
                    Ok(()) => GraphqlOutcome::Allowed(body),
                    Err(rejection) => GraphqlOutcome::Rejected(rejection),
                }
            }
            Method::POST => self.inspect_post(parts, body).await,
            _ => GraphqlOutcome::Rejected(reject(
                GraphqlGuardResult::Invalid,
                405,
                "GraphQL route only accepts GET or POST",
            )),
        }
    }

    fn inspect_get(&self, parts: &Parts) -> std::result::Result<(), GraphqlRejection> {
        let raw = parts.uri.query().ok_or_else(|| {
            reject(
                GraphqlGuardResult::Invalid,
                400,
                "GraphQL query parameter is required",
            )
        })?;
        let mut query: Option<Cow<'_, str>> = None;
        let mut operation_name: Option<Cow<'_, str>> = None;
        for (name, value) in form_urlencoded::parse(raw.as_bytes()) {
            match name.as_ref() {
                "query" if query.is_none() => query = Some(value),
                "query" => {
                    return Err(reject(
                        GraphqlGuardResult::Invalid,
                        400,
                        "GraphQL query parameter must be unique",
                    ));
                }
                "operationName" if operation_name.is_none() => operation_name = Some(value),
                "operationName" => {
                    return Err(reject(
                        GraphqlGuardResult::Invalid,
                        400,
                        "GraphQL operationName parameter must be unique",
                    ));
                }
                _ => {}
            }
        }
        let query = query.ok_or_else(|| {
            reject(
                GraphqlGuardResult::Invalid,
                400,
                "GraphQL query parameter is required",
            )
        })?;
        self.analyze(query.as_ref(), operation_name.as_deref(), true)
    }

    async fn inspect_post(&self, parts: &Parts, body: ForwardBody) -> GraphqlOutcome {
        if content_length(parts).is_some_and(|length| length > self.max_body_bytes) {
            return GraphqlOutcome::Rejected(reject(
                GraphqlGuardResult::TooLarge,
                413,
                "GraphQL request body is too large",
            ));
        }
        let collected = match collect_bounded(body, self.max_body_bytes).await {
            Ok(collected) => collected,
            Err(CollectError::TooLarge) => {
                return GraphqlOutcome::Rejected(reject(
                    GraphqlGuardResult::TooLarge,
                    413,
                    "GraphQL request body is too large",
                ));
            }
            Err(CollectError::Read) => {
                return GraphqlOutcome::Rejected(reject(
                    GraphqlGuardResult::BodyReadError,
                    400,
                    "GraphQL request body read failed",
                ));
            }
        };
        let media_type = request_media_type(parts);
        let analysis = match media_type {
            Some(MediaType::Json) => {
                // `Cow<str>` lets serde_json borrow the common unescaped query directly from
                // `Bytes`; escaped JSON strings allocate only the decoded query, which is required.
                self.inspect_json_operations(&collected.bytes)
            }
            Some(MediaType::Graphql) => match std::str::from_utf8(&collected.bytes) {
                Ok(query) => self.analyze(query, None, false),
                Err(_) => Err(reject(
                    GraphqlGuardResult::Invalid,
                    400,
                    "GraphQL query is not UTF-8",
                )),
            },
            Some(MediaType::Multipart) => self.inspect_multipart(parts, &collected.bytes),
            None => Err(reject(
                GraphqlGuardResult::Invalid,
                415,
                "GraphQL request content-type is unsupported",
            )),
        };
        match analysis {
            Ok(()) => GraphqlOutcome::Allowed(buffered_body(collected)),
            Err(rejection) => GraphqlOutcome::Rejected(rejection),
        }
    }

    /// 业务作用：从 GraphQL multipart request 提取 operations JSON，并对每个 operation 执行同一预算门。
    ///
    /// 参数说明：`parts` 提供 multipart boundary；`body` 是已受 max_body_bytes 限制且将原样重放的实体。
    ///
    /// 返回：operations 唯一且所有查询通过时成功；MIME/envelope 非法或任一查询越界时返回固定拒绝。
    fn inspect_multipart(
        &self,
        parts: &Parts,
        body: &[u8],
    ) -> std::result::Result<(), GraphqlRejection> {
        let boundary = multipart_boundary(parts).ok_or_else(|| {
            reject(
                GraphqlGuardResult::Invalid,
                400,
                "GraphQL multipart boundary is invalid",
            )
        })?;
        let operations = multipart_named_part(body, boundary.as_bytes(), b"operations")
            .ok_or_else(|| {
                reject(
                    GraphqlGuardResult::Invalid,
                    400,
                    "GraphQL multipart operations part is invalid",
                )
            })?;
        self.inspect_json_operations(operations)
    }

    /// 业务作用：统一检查单 operation 与 GraphQL batch JSON envelope，避免 multipart 绕过查询预算。
    ///
    /// 参数说明：`bytes` 是普通 JSON body 或 multipart 的 operations part。
    ///
    /// 返回：每个 envelope 都通过 parser/depth/complexity 门时成功；空 batch 或 JSON 结构错误时拒绝。
    fn inspect_json_operations(&self, bytes: &[u8]) -> std::result::Result<(), GraphqlRejection> {
        let operations: JsonOperations<'_> = serde_json::from_slice(bytes).map_err(|_| {
            reject(
                GraphqlGuardResult::Invalid,
                400,
                "GraphQL JSON envelope is invalid",
            )
        })?;
        match operations {
            JsonOperations::One(envelope) => self.analyze(
                envelope.query.as_ref(),
                envelope.operation_name.as_deref(),
                false,
            ),
            JsonOperations::Many(envelopes) => {
                if envelopes.is_empty() {
                    return Err(reject(
                        GraphqlGuardResult::Invalid,
                        400,
                        "GraphQL JSON envelope is invalid",
                    ));
                }
                for envelope in envelopes {
                    self.analyze(
                        envelope.query.as_ref(),
                        envelope.operation_name.as_deref(),
                        false,
                    )?;
                }
                Ok(())
            }
        }
    }

    fn analyze(
        &self,
        query: &str,
        operation_name: Option<&str>,
        get_request: bool,
    ) -> std::result::Result<(), GraphqlRejection> {
        if query.is_empty() || query.len() > self.max_query_bytes {
            return Err(reject(
                GraphqlGuardResult::TooLarge,
                413,
                "GraphQL query is too large",
            ));
        }
        let mut parser =
            Parser::new(query, self.max_tokens, self.max_depth).map_err(map_analysis_error)?;
        let document = parser.parse_document().map_err(map_analysis_error)?;
        let operation = document
            .select_operation(operation_name)
            .map_err(map_analysis_error)?;
        if get_request && operation.kind != OperationKind::Query {
            return Err(reject(
                GraphqlGuardResult::Invalid,
                405,
                "GraphQL GET only permits query operations",
            ));
        }
        let stats = document
            .operation_stats(operation, self.max_depth, self.max_complexity)
            .map_err(map_analysis_error)?;
        if stats.depth > self.max_depth {
            return Err(map_analysis_error(AnalysisError::TooDeep));
        }
        if stats.complexity > self.max_complexity {
            return Err(map_analysis_error(AnalysisError::TooComplex));
        }
        if stats.introspection && !self.allow_introspection {
            return Err(reject(
                GraphqlGuardResult::IntrospectionDenied,
                403,
                "GraphQL introspection is disabled",
            ));
        }
        Ok(())
    }
}

fn reject(result: GraphqlGuardResult, status: u16, message: &'static str) -> GraphqlRejection {
    GraphqlRejection {
        result,
        status,
        message,
    }
}

fn map_analysis_error(error: AnalysisError) -> GraphqlRejection {
    match error {
        AnalysisError::Invalid => {
            reject(GraphqlGuardResult::Invalid, 400, "GraphQL query is invalid")
        }
        AnalysisError::TooManyTokens => reject(
            GraphqlGuardResult::TooLarge,
            413,
            "GraphQL query token budget exceeded",
        ),
        AnalysisError::TooDeep => reject(
            GraphqlGuardResult::TooDeep,
            400,
            "GraphQL query depth limit exceeded",
        ),
        AnalysisError::TooComplex => reject(
            GraphqlGuardResult::TooComplex,
            400,
            "GraphQL query complexity limit exceeded",
        ),
    }
}

fn content_length(parts: &Parts) -> Option<u64> {
    parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

#[derive(Clone, Copy)]
enum MediaType {
    Json,
    Graphql,
    Multipart,
}

fn request_media_type(parts: &Parts) -> Option<MediaType> {
    let content_type = parts.headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let media_type = content_type.split(';').next()?.trim();
    if media_type.eq_ignore_ascii_case("application/json")
        || (media_type.len() > "application/+json".len()
            && media_type
                .get(.."application/".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/"))
            && media_type
                .get(media_type.len().saturating_sub("+json".len())..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case("+json")))
    {
        Some(MediaType::Json)
    } else if media_type.eq_ignore_ascii_case("application/graphql") {
        Some(MediaType::Graphql)
    } else if media_type.eq_ignore_ascii_case("multipart/form-data") {
        Some(MediaType::Multipart)
    } else {
        None
    }
}

#[derive(Deserialize)]
struct JsonEnvelope<'a> {
    #[serde(borrow)]
    query: Cow<'a, str>,
    #[serde(default, rename = "operationName", borrow)]
    operation_name: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonOperations<'a> {
    One(#[serde(borrow)] JsonEnvelope<'a>),
    Many(#[serde(borrow)] Vec<JsonEnvelope<'a>>),
}

/// 业务作用：识别 GraphQL WebSocket upgrade，且只接受标准/legacy 两个明确 subprotocol。
///
/// 参数说明：`parts` 是尚未转交透明 WebSocket tunnel 的请求 head。
///
/// 返回：Upgrade/Connection 与 Sec-WebSocket-Protocol 同时满足时为 true，普通 GET 为 false。
fn is_graphql_websocket_upgrade(parts: &Parts) -> bool {
    let upgrade = parts
        .headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = parts
        .headers
        .get(http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    let protocol = parts
        .headers
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| matches!(token.trim(), "graphql-transport-ws" | "graphql-ws"))
        });
    upgrade && connection && protocol
}

/// 业务作用：从 Content-Type 读取并校验 multipart boundary，防止控制字符或超长分隔符进入扫描器。
///
/// 参数说明：`parts` 是 GraphQL POST 请求 head。
///
/// 返回：boundary 为 1..=70 个可见 ASCII 且不含 MIME 分隔危险字符时返回其值，否则 None。
fn multipart_boundary(parts: &Parts) -> Option<String> {
    let content_type = parts.headers.get(CONTENT_TYPE)?.to_str().ok()?;
    for parameter in content_type.split(';').skip(1) {
        let Some((name, raw)) = parameter.trim().split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let value = raw.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        if !value.is_empty()
            && value.len() <= 70
            && value
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte) && !matches!(byte, b'"' | b'\\'))
        {
            return Some(value.to_owned());
        }
        return None;
    }
    None
}

/// 业务作用：在有界 multipart 实体中定位唯一命名 part，并返回其 body slice。
///
/// 参数说明：`body` 是完整实体；`boundary` 已校验；`target` 是 Content-Disposition name。
///
/// 返回：目标 part 恰好出现一次且 MIME 边界完整时返回借用切片；缺失、重复或结构错误返回 None。
fn multipart_named_part<'a>(body: &'a [u8], boundary: &[u8], target: &[u8]) -> Option<&'a [u8]> {
    let mut marker = Vec::with_capacity(boundary.len() + 4);
    marker.extend_from_slice(b"--");
    marker.extend_from_slice(boundary);
    let mut cursor = 0usize;
    let mut found = None;
    while cursor < body.len() {
        let start = find_bytes(&body[cursor..], &marker)? + cursor;
        let after_marker = start.checked_add(marker.len())?;
        if body.get(after_marker..after_marker + 2) == Some(b"--") {
            break;
        }
        if body.get(after_marker..after_marker + 2) != Some(b"\r\n") {
            return None;
        }
        let headers_start = after_marker + 2;
        let headers_end = find_bytes(&body[headers_start..], b"\r\n\r\n")? + headers_start;
        let data_start = headers_end + 4;
        let mut next_marker = Vec::with_capacity(marker.len() + 2);
        next_marker.extend_from_slice(b"\r\n");
        next_marker.extend_from_slice(&marker);
        let data_end = find_bytes(&body[data_start..], &next_marker)? + data_start;
        let headers = &body[headers_start..headers_end];
        if multipart_headers_name(headers) == Some(target) {
            if found.is_some() {
                return None;
            }
            found = Some(&body[data_start..data_end]);
        }
        cursor = data_end + 2;
    }
    found
}

/// 业务作用：从单个 MIME part headers 中提取 Content-Disposition 的 name 参数。
///
/// 参数说明：`headers` 不含末尾空行，使用 CRLF 分隔。
///
/// 返回：唯一合法 name 的借用字节；缺失或畸形时 None。
fn multipart_headers_name(headers: &[u8]) -> Option<&[u8]> {
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let prefix = b"content-disposition:";
        if line.len() < prefix.len() || !line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            continue;
        }
        for parameter in line[prefix.len()..].split(|byte| *byte == b';') {
            let parameter = trim_ascii(parameter);
            let Some(value) = parameter.strip_prefix(b"name=\"") else {
                continue;
            };
            return value.strip_suffix(b"\"");
        }
    }
    None
}

/// 业务作用：在有界 MIME 字节中查找子串，不执行 UTF-8 假设。
///
/// 参数说明：`haystack` 是待扫描字节，`needle` 必须非空。
///
/// 返回：首次匹配偏移；不存在时 None。
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

/// 业务作用：去除 MIME 参数两侧 SP/HTAB，保持其余字节逐字语义。
///
/// 参数说明：`value` 是单个 header parameter 字节。
///
/// 返回：返回借用的裁剪切片。
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnalysisError {
    Invalid,
    TooManyTokens,
    TooDeep,
    TooComplex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Name(&'a str),
    Spread,
    Punct(u8),
    Scalar,
    Eof,
}

/// 借用输入的 GraphQL lexer。名字 token 只是 `&str` span；string/number 的内容对复杂度
/// 无意义，因此不解码、不分配。token 计数在产出时扣预算。
struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    offset: usize,
    produced: usize,
    max_tokens: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str, max_tokens: usize) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            offset: 0,
            produced: 0,
            max_tokens,
        }
    }

    fn next(&mut self) -> std::result::Result<Token<'a>, AnalysisError> {
        self.skip_ignored();
        if self.offset == self.bytes.len() {
            return Ok(Token::Eof);
        }
        let token = match self.bytes[self.offset] {
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => self.scan_name(),
            b'"' => {
                self.scan_string()?;
                Token::Scalar
            }
            b'-' | b'0'..=b'9' => {
                self.scan_number()?;
                Token::Scalar
            }
            b'.' if self.bytes.get(self.offset..self.offset + 3) == Some(b"...") => {
                self.offset += 3;
                Token::Spread
            }
            punct @ (b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{'
            | b'|' | b'}') => {
                self.offset += 1;
                Token::Punct(punct)
            }
            _ => return Err(AnalysisError::Invalid),
        };
        self.produced = self
            .produced
            .checked_add(1)
            .ok_or(AnalysisError::TooManyTokens)?;
        if self.produced > self.max_tokens {
            return Err(AnalysisError::TooManyTokens);
        }
        Ok(token)
    }

    fn skip_ignored(&mut self) {
        loop {
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b','))
            {
                self.offset += 1;
            }
            // UTF-8 BOM 只在文档开头合法。
            if self.offset == 0 && self.bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
                self.offset = 3;
                continue;
            }
            if self.bytes.get(self.offset) != Some(&b'#') {
                break;
            }
            self.offset += 1;
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| !matches!(byte, b'\r' | b'\n'))
            {
                self.offset += 1;
            }
        }
    }

    fn scan_name(&mut self) -> Token<'a> {
        let start = self.offset;
        self.offset += 1;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'0'..=b'9'))
        {
            self.offset += 1;
        }
        Token::Name(&self.input[start..self.offset])
    }

    fn scan_string(&mut self) -> std::result::Result<(), AnalysisError> {
        if self.bytes.get(self.offset..self.offset + 3) == Some(b"\"\"\"") {
            self.offset += 3;
            while self.offset < self.bytes.len() {
                // GraphQL block string 用反斜线转义连续三个引号；跳过四字节，避免把它
                // 错认成 terminator。内容本身不需要为预算分析解码。
                if self.bytes.get(self.offset..self.offset + 4) == Some(b"\\\"\"\"") {
                    self.offset += 4;
                } else if self.bytes.get(self.offset..self.offset + 3) == Some(b"\"\"\"") {
                    self.offset += 3;
                    return Ok(());
                } else {
                    self.offset += 1;
                }
            }
            return Err(AnalysisError::Invalid);
        }
        self.offset += 1;
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.offset += 1;
                    let escaped = self
                        .bytes
                        .get(self.offset)
                        .copied()
                        .ok_or(AnalysisError::Invalid)?;
                    if escaped == b'u' {
                        let digits = self
                            .bytes
                            .get(self.offset + 1..self.offset + 5)
                            .ok_or(AnalysisError::Invalid)?;
                        if !digits.iter().all(u8::is_ascii_hexdigit) {
                            return Err(AnalysisError::Invalid);
                        }
                        self.offset += 5;
                    } else if matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        self.offset += 1;
                    } else {
                        return Err(AnalysisError::Invalid);
                    }
                }
                b'\r' | b'\n' | 0x00..=0x1f => return Err(AnalysisError::Invalid),
                _ => self.offset += 1,
            }
        }
        Err(AnalysisError::Invalid)
    }

    fn scan_number(&mut self) -> std::result::Result<(), AnalysisError> {
        let start = self.offset;
        if self.bytes[self.offset] == b'-' {
            self.offset += 1;
        }
        match self.bytes.get(self.offset).copied() {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
                    self.offset += 1;
                }
            }
            _ => return Err(AnalysisError::Invalid),
        }
        if self.bytes.get(self.offset) == Some(&b'.') {
            self.offset += 1;
            let fraction_start = self.offset;
            while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
            if self.offset == fraction_start {
                return Err(AnalysisError::Invalid);
            }
        }
        if self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            self.offset += 1;
            if self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                self.offset += 1;
            }
            let exponent_start = self.offset;
            while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
            if self.offset == exponent_start {
                return Err(AnalysisError::Invalid);
            }
        }
        if self.offset == start
            || self.bytes.get(self.offset).is_some_and(
                |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'0'..=b'9' | b'.'),
            )
        {
            return Err(AnalysisError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationKind {
    Query,
    Mutation,
    Subscription,
}

struct Operation<'a> {
    kind: OperationKind,
    name: Option<&'a str>,
    selection_set: usize,
}

struct Fragment {
    selection_set: usize,
}

struct SelectionSet<'a> {
    selections: Vec<Selection<'a>>,
}

enum Selection<'a> {
    Field { name: &'a str, child: Option<usize> },
    FragmentSpread(&'a str),
    InlineFragment(usize),
}

struct Document<'a> {
    operations: Vec<Operation<'a>>,
    fragments: Vec<Fragment>,
    fragment_by_name: HashMap<&'a str, usize>,
    sets: Vec<SelectionSet<'a>>,
}

impl<'a> Document<'a> {
    fn select_operation(
        &self,
        requested: Option<&str>,
    ) -> std::result::Result<&Operation<'a>, AnalysisError> {
        if let Some(requested) = requested {
            if requested.is_empty() {
                return Err(AnalysisError::Invalid);
            }
            return self
                .operations
                .iter()
                .find(|operation| operation.name == Some(requested))
                .ok_or(AnalysisError::Invalid);
        }
        if self.operations.len() == 1 {
            Ok(&self.operations[0])
        } else {
            // GraphQL 要求多 operation 文档显式给 operationName；不能悄悄选择第一个。
            Err(AnalysisError::Invalid)
        }
    }

    fn operation_stats(
        &self,
        operation: &Operation<'a>,
        max_depth: usize,
        max_complexity: usize,
    ) -> std::result::Result<QueryStats, AnalysisError> {
        let mut states = vec![VisitState::Fresh; self.fragments.len()];
        let mut memo = vec![None; self.fragments.len()];
        self.set_stats(
            operation.selection_set,
            &mut states,
            &mut memo,
            1,
            max_depth,
            max_complexity,
        )
    }

    fn set_stats(
        &self,
        set_index: usize,
        states: &mut [VisitState],
        memo: &mut [Option<QueryStats>],
        recursion_depth: usize,
        max_depth: usize,
        max_complexity: usize,
    ) -> std::result::Result<QueryStats, AnalysisError> {
        if recursion_depth > max_depth {
            return Err(AnalysisError::TooDeep);
        }
        let mut total = QueryStats::default();
        for selection in &self.sets[set_index].selections {
            let stats = match selection {
                Selection::Field { name, child } => {
                    let child_stats = match child {
                        Some(child) => self.set_stats(
                            *child,
                            states,
                            memo,
                            recursion_depth + 1,
                            max_depth,
                            max_complexity,
                        )?,
                        None => QueryStats::default(),
                    };
                    QueryStats {
                        complexity: add_cost(1, child_stats.complexity, max_complexity),
                        depth: 1usize.saturating_add(child_stats.depth),
                        introspection: name.starts_with("__") || child_stats.introspection,
                    }
                }
                Selection::InlineFragment(child) => self.set_stats(
                    *child,
                    states,
                    memo,
                    recursion_depth + 1,
                    max_depth,
                    max_complexity,
                )?,
                Selection::FragmentSpread(name) => {
                    let fragment = self
                        .fragment_by_name
                        .get(name)
                        .copied()
                        .ok_or(AnalysisError::Invalid)?;
                    self.fragment_stats(
                        fragment,
                        states,
                        memo,
                        recursion_depth + 1,
                        max_depth,
                        max_complexity,
                    )?
                }
            };
            total.complexity = add_cost(total.complexity, stats.complexity, max_complexity);
            total.depth = total.depth.max(stats.depth);
            total.introspection |= stats.introspection;
            if total.complexity > max_complexity {
                return Err(AnalysisError::TooComplex);
            }
            if total.depth > max_depth {
                return Err(AnalysisError::TooDeep);
            }
        }
        Ok(total)
    }

    fn fragment_stats(
        &self,
        fragment_index: usize,
        states: &mut [VisitState],
        memo: &mut [Option<QueryStats>],
        recursion_depth: usize,
        max_depth: usize,
        max_complexity: usize,
    ) -> std::result::Result<QueryStats, AnalysisError> {
        if let Some(stats) = memo[fragment_index] {
            return Ok(stats);
        }
        match states[fragment_index] {
            VisitState::Visiting => return Err(AnalysisError::Invalid),
            VisitState::Done => return memo[fragment_index].ok_or(AnalysisError::Invalid),
            VisitState::Fresh => {}
        }
        states[fragment_index] = VisitState::Visiting;
        let stats = self.set_stats(
            self.fragments[fragment_index].selection_set,
            states,
            memo,
            recursion_depth,
            max_depth,
            max_complexity,
        )?;
        states[fragment_index] = VisitState::Done;
        memo[fragment_index] = Some(stats);
        Ok(stats)
    }
}

#[derive(Clone, Copy, Default)]
struct QueryStats {
    complexity: usize,
    depth: usize,
    introspection: bool,
}

#[derive(Clone, Copy)]
enum VisitState {
    Fresh,
    Visiting,
    Done,
}

fn add_cost(left: usize, right: usize, limit: usize) -> usize {
    left.saturating_add(right).min(limit.saturating_add(1))
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    current: Token<'a>,
    max_depth: usize,
    operations: Vec<Operation<'a>>,
    fragments: Vec<Fragment>,
    fragment_by_name: HashMap<&'a str, usize>,
    sets: Vec<SelectionSet<'a>>,
}

impl<'a> Parser<'a> {
    fn new(
        input: &'a str,
        max_tokens: usize,
        max_depth: usize,
    ) -> std::result::Result<Self, AnalysisError> {
        let mut lexer = Lexer::new(input, max_tokens);
        let current = lexer.next()?;
        Ok(Self {
            lexer,
            current,
            max_depth,
            operations: Vec::new(),
            fragments: Vec::new(),
            fragment_by_name: HashMap::new(),
            sets: Vec::new(),
        })
    }

    fn parse_document(&mut self) -> std::result::Result<Document<'a>, AnalysisError> {
        while self.current != Token::Eof {
            match self.current {
                Token::Punct(b'{') => {
                    let selection_set = self.parse_selection_set(1)?;
                    self.operations.push(Operation {
                        kind: OperationKind::Query,
                        name: None,
                        selection_set,
                    });
                }
                Token::Name("query") => self.parse_operation(OperationKind::Query)?,
                Token::Name("mutation") => self.parse_operation(OperationKind::Mutation)?,
                Token::Name("subscription") => self.parse_operation(OperationKind::Subscription)?,
                Token::Name("fragment") => self.parse_fragment()?,
                _ => return Err(AnalysisError::Invalid),
            }
        }
        if self.operations.is_empty() {
            return Err(AnalysisError::Invalid);
        }
        // Duplicate operation names make operationName ambiguous. Multiple anonymous operations
        // are also invalid and must not be resolved by file order.
        let mut operation_names = HashMap::new();
        let mut anonymous = 0usize;
        for operation in &self.operations {
            if let Some(name) = operation.name {
                if operation_names.insert(name, ()).is_some() {
                    return Err(AnalysisError::Invalid);
                }
            } else {
                anonymous += 1;
            }
        }
        if anonymous > 0 && self.operations.len() > 1 {
            return Err(AnalysisError::Invalid);
        }
        Ok(Document {
            operations: std::mem::take(&mut self.operations),
            fragments: std::mem::take(&mut self.fragments),
            fragment_by_name: std::mem::take(&mut self.fragment_by_name),
            sets: std::mem::take(&mut self.sets),
        })
    }

    fn parse_operation(&mut self, kind: OperationKind) -> std::result::Result<(), AnalysisError> {
        self.bump()?;
        let name = match self.current {
            Token::Name(name) => {
                self.bump()?;
                Some(name)
            }
            _ => None,
        };
        if self.current == Token::Punct(b'(') {
            self.skip_balanced(b'(', b')')?;
        }
        self.parse_directives()?;
        let selection_set = self.parse_selection_set(1)?;
        self.operations.push(Operation {
            kind,
            name,
            selection_set,
        });
        Ok(())
    }

    fn parse_fragment(&mut self) -> std::result::Result<(), AnalysisError> {
        self.bump()?;
        let name = self.take_name()?;
        if name == "on" || self.fragment_by_name.contains_key(name) {
            return Err(AnalysisError::Invalid);
        }
        self.expect_name("on")?;
        self.take_name()?; // type condition
        self.parse_directives()?;
        let selection_set = self.parse_selection_set(1)?;
        let index = self.fragments.len();
        self.fragments.push(Fragment { selection_set });
        self.fragment_by_name.insert(name, index);
        Ok(())
    }

    fn parse_selection_set(&mut self, nesting: usize) -> std::result::Result<usize, AnalysisError> {
        if nesting > self.max_depth {
            return Err(AnalysisError::TooDeep);
        }
        self.expect_punct(b'{')?;
        let mut selections = Vec::new();
        while self.current != Token::Punct(b'}') {
            if self.current == Token::Eof {
                return Err(AnalysisError::Invalid);
            }
            if self.current == Token::Spread {
                self.bump()?;
                match self.current {
                    Token::Name("on") => {
                        self.bump()?;
                        self.take_name()?;
                        self.parse_directives()?;
                        let child = self.parse_selection_set(nesting + 1)?;
                        selections.push(Selection::InlineFragment(child));
                    }
                    Token::Punct(b'@') => {
                        self.parse_directives()?;
                        let child = self.parse_selection_set(nesting + 1)?;
                        selections.push(Selection::InlineFragment(child));
                    }
                    Token::Name(name) => {
                        self.bump()?;
                        self.parse_directives()?;
                        selections.push(Selection::FragmentSpread(name));
                    }
                    _ => return Err(AnalysisError::Invalid),
                }
                continue;
            }
            let first_name = self.take_name()?;
            let field_name = if self.current == Token::Punct(b':') {
                self.bump()?;
                self.take_name()?
            } else {
                first_name
            };
            if self.current == Token::Punct(b'(') {
                self.skip_balanced(b'(', b')')?;
            }
            self.parse_directives()?;
            let child = if self.current == Token::Punct(b'{') {
                Some(self.parse_selection_set(nesting + 1)?)
            } else {
                None
            };
            selections.push(Selection::Field {
                name: field_name,
                child,
            });
        }
        self.bump()?;
        if selections.is_empty() {
            return Err(AnalysisError::Invalid);
        }
        let index = self.sets.len();
        self.sets.push(SelectionSet { selections });
        Ok(index)
    }

    fn parse_directives(&mut self) -> std::result::Result<(), AnalysisError> {
        while self.current == Token::Punct(b'@') {
            self.bump()?;
            self.take_name()?;
            if self.current == Token::Punct(b'(') {
                self.skip_balanced(b'(', b')')?;
            }
        }
        Ok(())
    }

    /// 跳过 variable/argument 的值语法，但仍逐 token 扣 CPU 预算，并用堆上小栈限制
    /// `()[]{}` 嵌套。这里不能递归，否则攻击者可在参数对象里绕开 selection 深度限制。
    fn skip_balanced(&mut self, open: u8, close: u8) -> std::result::Result<(), AnalysisError> {
        self.expect_punct(open)?;
        let mut stack = vec![close];
        while let Some(expected) = stack.last().copied() {
            match self.current {
                Token::Eof => return Err(AnalysisError::Invalid),
                Token::Punct(actual) if actual == expected => {
                    stack.pop();
                    self.bump()?;
                }
                Token::Punct(b'(') => {
                    stack.push(b')');
                    self.bump()?;
                }
                Token::Punct(b'[') => {
                    stack.push(b']');
                    self.bump()?;
                }
                Token::Punct(b'{') => {
                    stack.push(b'}');
                    self.bump()?;
                }
                Token::Punct(b')' | b']' | b'}') => return Err(AnalysisError::Invalid),
                _ => self.bump()?,
            }
            if stack.len() > self.max_depth {
                return Err(AnalysisError::TooDeep);
            }
        }
        Ok(())
    }

    fn expect_name(&mut self, expected: &str) -> std::result::Result<(), AnalysisError> {
        match self.current {
            Token::Name(actual) if actual == expected => self.bump(),
            _ => Err(AnalysisError::Invalid),
        }
    }

    fn take_name(&mut self) -> std::result::Result<&'a str, AnalysisError> {
        match self.current {
            Token::Name(name) => {
                self.bump()?;
                Ok(name)
            }
            _ => Err(AnalysisError::Invalid),
        }
    }

    fn expect_punct(&mut self, expected: u8) -> std::result::Result<(), AnalysisError> {
        if self.current != Token::Punct(expected) {
            return Err(AnalysisError::Invalid);
        }
        self.bump()
    }

    fn bump(&mut self) -> std::result::Result<(), AnalysisError> {
        self.current = self.lexer.next()?;
        Ok(())
    }
}
