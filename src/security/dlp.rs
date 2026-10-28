//! route 级 PII、凭据与 secret 检测、遮蔽和阻断。
//!
//! 未显式启用 body 方向时只检查配置声明的 head 字段；body 慢路径有独立字节、结构与
//! Content-Encoding 门。所有日志和指标只使用固定 rule/target，不记录命中原值。

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderMap, Uri};
use hyper::body::Body;
use regex::bytes::Regex;
use serde_json::Value;

use crate::config::model::{DlpCfg, DlpExclusionCfg};
use crate::proxy::forward::ForwardBody;
use crate::proxy::request_validation::{buffered_body, collect_bounded, CollectError};

const MAX_HEADER_TARGETS: usize = 64;
const MAX_RULES: usize = 16;
const MAX_EXCLUSIONS: usize = 256;
const MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REPLACEMENT_BYTES: usize = 128;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 100_000;

/// DLP 数据面的固定处置动作。
#[derive(Clone, Copy, Eq, PartialEq)]
enum DlpAction {
    /// 命中后停止当前方向。
    Block,
    /// 命中后用固定值替代敏感字段。
    Redact,
    /// 命中只记录固定原因，字节保持不变。
    Monitor,
}

/// 内置 DLP 固定规则。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum DlpRule {
    /// 电子邮箱。
    Email,
    /// 电话号码。
    Phone,
    /// 通过 Luhn 校验的银行卡号。
    CreditCard,
    /// 常见国家身份号码形态。
    NationalId,
    /// JWT compact token。
    Jwt,
    /// 常见云平台或 API key 前缀。
    ApiKey,
    /// PEM private key 标记。
    PrivateKey,
    /// 敏感字段名或 Bearer/Basic 凭据形态。
    Secret,
}

impl DlpRule {
    /// 业务作用：解析配置规则名并拒绝未知规则被静默忽略。
    ///
    /// 参数说明：
    /// - `value`：是配置规则名。
    ///
    /// 返回：已知规则返回固定枚举，未知名称返回 `None`。
    fn from_name(value: &str) -> Option<Self> {
        match value {
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "credit_card" => Some(Self::CreditCard),
            "national_id" => Some(Self::NationalId),
            "jwt" => Some(Self::Jwt),
            "api_key" => Some(Self::ApiKey),
            "private_key" => Some(Self::PrivateKey),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }

    /// 业务作用：为低敏日志提供编译期固定规则名称。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回不含命中数据的固定规则名。
    const fn name(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::CreditCard => "credit_card",
            Self::NationalId => "national_id",
            Self::Jwt => "jwt",
            Self::ApiKey => "api_key",
            Self::PrivateKey => "private_key",
            Self::Secret => "secret",
        }
    }
}

const ALL_RULES: [DlpRule; 8] = [
    DlpRule::PrivateKey,
    DlpRule::Jwt,
    DlpRule::ApiKey,
    DlpRule::Secret,
    DlpRule::CreditCard,
    DlpRule::NationalId,
    DlpRule::Email,
    DlpRule::Phone,
];

/// 一次 DLP 命中的固定审计信息。
#[derive(Clone, Copy)]
pub(crate) struct DlpMatch {
    /// 固定规则名。
    pub(crate) rule: &'static str,
    /// 固定方向/位置，不包含 header 或 query 参数名。
    pub(crate) target: &'static str,
}

/// head 检查及可选原地遮蔽结果。
pub(crate) enum DlpHeadOutcome {
    /// 没有命中。
    Allowed,
    /// monitor 命中，head 不变。
    Monitored(DlpMatch),
    /// redact 命中，所有匹配字段已遮蔽。
    Redacted(DlpMatch),
    /// block 命中，调用方必须停止当前方向。
    Blocked(DlpMatch),
}

/// body 检查及可选重放结果。
pub(crate) enum DlpBodyOutcome {
    /// 没有命中，重放原始实体。
    Allowed(ForwardBody),
    /// monitor 命中，重放原始实体。
    Monitored(ForwardBody, DlpMatch),
    /// redact 命中，重放遮蔽后的实体。
    Redacted(ForwardBody, DlpMatch),
    /// block 命中，原实体不得继续发送。
    Blocked(DlpMatch),
    /// 实体超过显式聚合上限。
    TooLarge,
    /// body transport 读取失败。
    ReadFailed,
    /// 声明检查的实体无法安全解析或使用不支持的 Content-Encoding/media type。
    Invalid,
}

/// 支持的有界 body 解析方式。
#[derive(Clone, Copy, Eq, PartialEq)]
enum BodyKind {
    /// JSON 或 `+json`。
    Json,
    /// URL encoded form。
    Form,
    /// UTF-8 文本；redact 时整体替换。
    Text,
}

/// 编译后的固定 detector 集合。
struct Detector {
    enabled: HashSet<DlpRule>,
    email: Regex,
    phone: Regex,
    national_id: Regex,
    jwt: Regex,
    api_key: Regex,
    secret: Regex,
}

mod semantic;

impl Detector {
    /// 业务作用：编译固定 DLP detector，并限制启用规则集合。
    ///
    /// 参数说明：
    /// - `values`：是启用规则名；空列表表示全部内置规则。
    ///
    /// 返回：规则合法且不重复时返回 detector；未知或超量配置返回错误。
    fn build(values: &[String]) -> Result<Self> {
        if values.len() > MAX_RULES {
            bail!("dlp.enabled_rules supports at most {MAX_RULES} entries");
        }
        let enabled = if values.is_empty() {
            ALL_RULES.into_iter().collect()
        } else {
            let mut enabled = HashSet::with_capacity(values.len());
            for value in values {
                let Some(rule) = DlpRule::from_name(value) else {
                    bail!("unknown dlp.enabled_rules value `{value}`");
                };
                if !enabled.insert(rule) {
                    bail!("dlp.enabled_rules contains duplicate rule `{value}`");
                }
            }
            enabled
        };
        Ok(Self {
            enabled,
            email: Regex::new(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")?,
            phone: Regex::new(r"(?:\+[0-9][0-9 ()-]{8,}[0-9]|[0-9]{2,4}[- ()][0-9 ()-]{5,}[0-9])")?,
            national_id: Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")?,
            jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}\b")?,
            api_key: Regex::new(
                r"(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})",
            )?,
            secret: Regex::new(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}=*")?,
        })
    }

    /// 业务作用：判断一个已知规则是否在当前值中命中，供例外逻辑继续检查后续规则。
    ///
    /// 参数说明：
    /// - `rule`：是固定规则
    /// - `value`：是待扫描字节。
    ///
    /// 返回：规则已启用且 detector 命中时返回 true。
    fn matches(&self, rule: DlpRule, value: &[u8]) -> bool {
        if !self.enabled.contains(&rule) {
            return false;
        }
        match rule {
            DlpRule::Email => self.email.is_match(value),
            DlpRule::Phone => self.phone.is_match(value),
            DlpRule::CreditCard => contains_luhn_card(value),
            DlpRule::NationalId => self.national_id.is_match(value),
            DlpRule::Jwt => self.jwt.is_match(value),
            DlpRule::ApiKey => self.api_key.is_match(value),
            DlpRule::PrivateKey => {
                contains_ascii_case_insensitive(value, b"-----BEGIN PRIVATE KEY-----")
                    || contains_ascii_case_insensitive(value, b"-----BEGIN RSA PRIVATE KEY-----")
                    || contains_ascii_case_insensitive(value, b"-----BEGIN EC PRIVATE KEY-----")
            }
            DlpRule::Secret => self.secret.is_match(value),
        }
    }

    /// 业务作用：识别结构化字段名本身是否声明了密码、token 或 secret 语义。
    ///
    /// 参数说明：
    /// - `key`：是解码后的 JSON/form/query 字段名。
    ///
    /// 返回：启用 secret 规则且名称敏感时返回该规则，否则返回 `None`。
    fn detect_key(&self, key: &str) -> Option<DlpRule> {
        if !self.enabled.contains(&DlpRule::Secret) {
            return None;
        }
        let key = key.to_ascii_lowercase().replace('-', "_");
        [
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "access_key",
            "authorization",
            "private_key",
        ]
        .into_iter()
        .any(|part| key == part || key.ends_with(format!("_{part}").as_str()))
        .then_some(DlpRule::Secret)
    }
}

/// 快照内不可变的 route DLP 策略。
#[derive(PartialEq, Eq)]
pub(crate) struct DlpPolicy {
    action: DlpAction,
    detector: Detector,
    request_headers: Vec<HeaderName>,
    response_headers: Vec<HeaderName>,
    inspect_query: bool,
    protect_log_path: bool,
    inspect_request_body: bool,
    inspect_response_body: bool,
    body_media_types: HashSet<String>,
    max_body_bytes: u64,
    replacement: String,
    replacement_header: HeaderValue,
    exclusions: HashSet<(DlpRule, String)>,
}

impl DlpPolicy {
    /// 业务作用：编译 route DLP 策略，冻结 detector、精确目标、遮蔽值与所有资源边界。
    ///
    /// 参数说明：
    /// - `cfg`：是 route DLP 声明。
    ///
    /// 返回：至少启用一个位置且全部规则/target 合法时返回不可变策略，否则拒绝候选。
    pub(crate) fn build(cfg: &DlpCfg) -> Result<Self> {
        let action = match cfg.action.as_str() {
            "block" => DlpAction::Block,
            "redact" => DlpAction::Redact,
            "monitor" => DlpAction::Monitor,
            value => bail!("dlp.action must be `block`, `redact` or `monitor`, got `{value}`"),
        };
        if !cfg.inspect_query
            && !cfg.protect_log_path
            && !cfg.inspect_request_body
            && !cfg.inspect_response_body
            && cfg.request_headers.is_empty()
            && cfg.response_headers.is_empty()
        {
            bail!("dlp must inspect at least one request, response or log location");
        }
        if !(1..=MAX_BODY_BYTES).contains(&cfg.max_body_bytes) {
            bail!("dlp.max_body_bytes must be in 1..={MAX_BODY_BYTES}");
        }
        if cfg.replacement.is_empty()
            || cfg.replacement.len() > MAX_REPLACEMENT_BYTES
            || !cfg
                .replacement
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            bail!("dlp.replacement must be printable ASCII in 1..={MAX_REPLACEMENT_BYTES} bytes");
        }
        let replacement_header = HeaderValue::from_str(cfg.replacement.as_str())
            .context("dlp.replacement is not a safe header value")?;
        let request_headers = parse_headers("dlp.request_headers", cfg.request_headers.as_slice())?;
        let response_headers =
            parse_headers("dlp.response_headers", cfg.response_headers.as_slice())?;
        let body_media_types = parse_body_media_types(cfg.body_media_types.as_slice())?;
        if (cfg.inspect_request_body || cfg.inspect_response_body) && body_media_types.is_empty() {
            bail!("dlp.body_media_types cannot be empty when body inspection is enabled");
        }
        let detector = Detector::build(cfg.enabled_rules.as_slice())?;
        let exclusions = parse_exclusions(cfg.exclusions.as_slice(), &detector)?;
        Ok(Self {
            action,
            detector,
            request_headers,
            response_headers,
            inspect_query: cfg.inspect_query,
            protect_log_path: cfg.protect_log_path,
            inspect_request_body: cfg.inspect_request_body,
            inspect_response_body: cfg.inspect_response_body,
            body_media_types,
            max_body_bytes: cfg.max_body_bytes,
            replacement: cfg.replacement.clone(),
            replacement_header,
            exclusions,
        })
    }

    /// 业务作用：检查并按策略原地遮蔽请求 header 与 query，阻断动作不发布半修改 head。
    ///
    /// 参数说明：
    /// - `parts`：是已匹配 route 的请求 head。
    ///
    /// 返回：返回固定允许、monitor、redact 或 block 终态。
    pub(crate) fn inspect_request_head(&self, parts: &mut Parts) -> DlpHeadOutcome {
        let mut first = None;
        for name in &self.request_headers {
            let target = format!("request_header:{}", name.as_str());
            if let Some(rule) =
                self.detect_header(parts.headers.get_all(name).iter(), target.as_str())
            {
                let matched = DlpMatch {
                    rule: rule.name(),
                    target: "request_header",
                };
                match self.action {
                    DlpAction::Block => return DlpHeadOutcome::Blocked(matched),
                    DlpAction::Monitor => return DlpHeadOutcome::Monitored(matched),
                    DlpAction::Redact => {
                        parts
                            .headers
                            .insert(name.clone(), self.replacement_header.clone());
                        first.get_or_insert(matched);
                    }
                }
            }
        }
        if self.inspect_query {
            match self.inspect_query(&parts.uri) {
                QueryOutcome::Allowed => {}
                QueryOutcome::Matched(matched) => match self.action {
                    DlpAction::Block => return DlpHeadOutcome::Blocked(matched),
                    DlpAction::Monitor => return DlpHeadOutcome::Monitored(matched),
                    DlpAction::Redact => return DlpHeadOutcome::Blocked(matched),
                },
                QueryOutcome::Redacted(uri, matched) => {
                    parts.uri = uri;
                    first.get_or_insert(matched);
                }
            }
        }
        first.map_or(DlpHeadOutcome::Allowed, DlpHeadOutcome::Redacted)
    }

    /// 业务作用：检查并按策略原地遮蔽选定响应 header，阻断时由调用方替换整个响应。
    ///
    /// 参数说明：
    /// - `headers`：是最终发送前的响应 header。
    ///
    /// 返回：返回固定允许、monitor、redact 或 block 终态。
    pub(crate) fn inspect_response_head(&self, headers: &mut HeaderMap) -> DlpHeadOutcome {
        let mut first = None;
        for name in &self.response_headers {
            let target = format!("response_header:{}", name.as_str());
            if let Some(rule) = self.detect_header(headers.get_all(name).iter(), target.as_str()) {
                let matched = DlpMatch {
                    rule: rule.name(),
                    target: "response_header",
                };
                match self.action {
                    DlpAction::Block => return DlpHeadOutcome::Blocked(matched),
                    DlpAction::Monitor => return DlpHeadOutcome::Monitored(matched),
                    DlpAction::Redact => {
                        headers.insert(name.clone(), self.replacement_header.clone());
                        first.get_or_insert(matched);
                    }
                }
            }
        }
        first.map_or(DlpHeadOutcome::Allowed, DlpHeadOutcome::Redacted)
    }

    /// 业务作用：有界检查请求 body，并在通过或 monitor/redact 后保留 trailers 重新交回主管线。
    ///
    /// 参数说明：
    /// - `parts`：提供 Content-Type/Encoding/Length
    /// - `body`：是当前请求体唯一所有权。
    ///
    /// 返回：未启用或无命中时重放原实体；命中返回处置终态；超限、读取或解析失败独立返回。
    pub(crate) async fn inspect_request_body(
        &self,
        parts: &Parts,
        body: ForwardBody,
    ) -> DlpBodyOutcome {
        self.inspect_body(
            &parts.headers,
            body,
            self.inspect_request_body,
            "request_body",
        )
        .await
    }

    /// 业务作用：有界检查响应 body，并在通过或 monitor/redact 后保留 trailers 重新发送。
    ///
    /// 参数说明：
    /// - `headers`：提供 Content-Type/Encoding/Length
    /// - `body`：是响应体唯一所有权。
    ///
    /// 返回：未启用或无命中时重放原实体；命中返回处置终态；超限、读取或解析失败独立返回。
    pub(crate) async fn inspect_response_body(
        &self,
        headers: &HeaderMap,
        body: ForwardBody,
    ) -> DlpBodyOutcome {
        self.inspect_body(headers, body, self.inspect_response_body, "response_body")
            .await
    }

    /// 业务作用：在 access log 构造前检测 path，并用固定路径替代任何命中值。
    ///
    /// 参数说明：
    /// - `uri`：是原始请求 URI。
    ///
    /// 返回：启用日志保护且 path 命中未豁免规则时返回固定 `/redacted` URI，否则返回 `None`。
    pub(crate) fn sanitized_log_uri(&self, uri: &Uri) -> Option<Uri> {
        if !self.protect_log_path {
            return None;
        }
        let rule = self.detect_unexcluded(uri.path().as_bytes(), "path_log")?;
        let _ = rule;
        Some(Uri::from_static("/redacted"))
    }

    /// 业务作用：判断是否启用了请求 body 慢路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：启用时返回 true。
    pub(crate) const fn inspects_request_body(&self) -> bool {
        self.inspect_request_body
    }

    /// 业务作用：判断是否启用了响应 body 慢路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：启用时返回 true。
    pub(crate) const fn inspects_response_body(&self) -> bool {
        self.inspect_response_body
    }

    /// 业务作用：在单一有界事务中收集、检测并按动作重放 body。
    ///
    /// 参数说明：
    /// - `headers`：描述实体
    /// - `body`：是唯一所有权
    /// - `enabled`：是方向开关
    /// - `target`：是固定 `request_body|response_body`。
    ///
    /// 返回：返回带重放 body 的允许/monitor/redact，或不再携带原始实体的失败终态。
    async fn inspect_body(
        &self,
        headers: &HeaderMap,
        body: ForwardBody,
        enabled: bool,
        target: &'static str,
    ) -> DlpBodyOutcome {
        if !enabled || body.is_end_stream() {
            return DlpBodyOutcome::Allowed(body);
        }
        if content_length_exceeds(headers, self.max_body_bytes) {
            return DlpBodyOutcome::TooLarge;
        }
        if has_non_identity_encoding(headers) {
            return DlpBodyOutcome::Invalid;
        }
        let Some(kind) = self.body_kind(headers) else {
            return DlpBodyOutcome::Invalid;
        };
        let collected = match collect_bounded(body, self.max_body_bytes).await {
            Ok(collected) => collected,
            Err(CollectError::TooLarge) => return DlpBodyOutcome::TooLarge,
            Err(CollectError::Read) => return DlpBodyOutcome::ReadFailed,
        };
        let transformed = match self.transform_body(kind, &collected.bytes, target) {
            Ok(value) => value,
            Err(()) => return DlpBodyOutcome::Invalid,
        };
        let Some((matched, redacted)) = transformed else {
            return DlpBodyOutcome::Allowed(buffered_body(collected));
        };
        match self.action {
            DlpAction::Block => DlpBodyOutcome::Blocked(matched),
            DlpAction::Monitor => DlpBodyOutcome::Monitored(buffered_body(collected), matched),
            DlpAction::Redact => {
                DlpBodyOutcome::Redacted(buffered_body(collected.replace_bytes(redacted)), matched)
            }
        }
    }

    /// 业务作用：按 media type 解析 body，并在 redact 模式生成安全重放字节。
    ///
    /// 参数说明：
    /// - `kind`：是已验证解析方式
    /// - `bytes`：是有界实体
    /// - `target`：是固定方向。
    ///
    /// 返回：无命中返回 `None`；命中返回第一固定原因和完整替代实体；语法/结构错误返回 `Err`。
    fn transform_body(
        &self,
        kind: BodyKind,
        bytes: &Bytes,
        target: &'static str,
    ) -> std::result::Result<Option<(DlpMatch, Bytes)>, ()> {
        match kind {
            BodyKind::Json => {
                let mut value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
                let mut budget = JsonBudget {
                    depth: 0,
                    nodes: 0,
                };
                let rule = self.inspect_json(&mut value, target, &mut budget)?;
                let Some(rule) = rule else {
                    return Ok(None);
                };
                let redacted = if self.action == DlpAction::Redact {
                    Bytes::from(serde_json::to_vec(&value).map_err(|_| ())?)
                } else {
                    bytes.clone()
                };
                Ok(Some((
                    DlpMatch {
                        rule: rule.name(),
                        target,
                    },
                    redacted,
                )))
            }
            BodyKind::Form => {
                let pairs = form_urlencoded::parse(bytes)
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>();
                let mut first = None;
                let mut serializer = form_urlencoded::Serializer::new(String::new());
                for (key, value) in pairs {
                    let rule = self
                        .detector
                        .detect_key(key.as_str())
                        .filter(|rule| !self.excluded(*rule, target))
                        .or_else(|| self.detect_unexcluded(value.as_bytes(), target));
                    if let Some(rule) = rule {
                        first.get_or_insert(rule);
                        serializer.append_pair(
                            key.as_str(),
                            if self.action == DlpAction::Redact {
                                self.replacement.as_str()
                            } else {
                                value.as_str()
                            },
                        );
                    } else {
                        serializer.append_pair(key.as_str(), value.as_str());
                    }
                }
                Ok(first.map(|rule| {
                    (
                        DlpMatch {
                            rule: rule.name(),
                            target,
                        },
                        Bytes::from(serializer.finish()),
                    )
                }))
            }
            BodyKind::Text => Ok(self.detect_unexcluded(bytes, target).map(|rule| {
                (
                    DlpMatch {
                        rule: rule.name(),
                        target,
                    },
                    if self.action == DlpAction::Redact {
                        Bytes::copy_from_slice(self.replacement.as_bytes())
                    } else {
                        bytes.clone()
                    },
                )
            })),
        }
    }

    /// 业务作用：有界遍历 JSON 字段名和字符串值，并在 redact 下替换完整敏感值。
    ///
    /// 参数说明：
    /// - `value`：是当前节点
    /// - `target`：是固定 body 方向
    /// - `budget`：约束深度和节点数。
    ///
    /// 返回：返回第一命中规则；无命中返回 `None`；结构预算耗尽返回 `Err`。
    fn inspect_json(
        &self,
        value: &mut Value,
        target: &str,
        budget: &mut JsonBudget,
    ) -> std::result::Result<Option<DlpRule>, ()> {
        budget.nodes = budget.nodes.saturating_add(1);
        if budget.nodes > MAX_JSON_NODES || budget.depth > MAX_JSON_DEPTH {
            return Err(());
        }
        match value {
            Value::String(text) => {
                let rule = self.detect_unexcluded(text.as_bytes(), target);
                if rule.is_some() && self.action == DlpAction::Redact {
                    *text = self.replacement.clone();
                }
                Ok(rule)
            }
            Value::Array(values) => {
                budget.depth += 1;
                let mut first = None;
                for value in values {
                    first = first.or(self.inspect_json(value, target, budget)?);
                }
                budget.depth -= 1;
                Ok(first)
            }
            Value::Object(values) => {
                budget.depth += 1;
                let mut first = None;
                for (key, value) in values {
                    let key_rule = self
                        .detector
                        .detect_key(key)
                        .filter(|rule| !self.excluded(*rule, target));
                    if let Some(rule) = key_rule {
                        first.get_or_insert(rule);
                        if self.action == DlpAction::Redact {
                            *value = Value::String(self.replacement.clone());
                            continue;
                        }
                    }
                    first = first.or(self.inspect_json(value, target, budget)?);
                }
                budget.depth -= 1;
                Ok(first)
            }
            _ => Ok(None),
        }
    }

    /// 业务作用：扫描一个 header 多值集合，并应用精确 target 例外。
    ///
    /// 参数说明：
    /// - `values`：是同名 header 全部值
    /// - `target`：是方向与小写名称。
    ///
    /// 返回：首个未豁免命中返回规则，否则返回 `None`。
    fn detect_header<'a>(
        &self,
        values: http::header::ValueIter<'a, HeaderValue>,
        target: &str,
    ) -> Option<DlpRule> {
        values
            .filter_map(|value| self.detect_unexcluded(value.as_bytes(), target))
            .next()
    }

    /// 业务作用：检查 query 参数值和敏感参数名，并在 redact 下保持顺序重建 URI。
    ///
    /// 参数说明：
    /// - `uri`：是当前请求 URI。
    ///
    /// 返回：无 query/命中返回允许；block/monitor 返回固定命中；redact 返回新 URI。
    fn inspect_query(&self, uri: &Uri) -> QueryOutcome {
        let Some(query) = uri.query() else {
            return QueryOutcome::Allowed;
        };
        let pairs = form_urlencoded::parse(query.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let mut first = None;
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            let target = format!("query:{key}");
            let rule = self
                .detector
                .detect_key(key.as_str())
                .filter(|rule| !self.excluded(*rule, target.as_str()))
                .or_else(|| self.detect_unexcluded(value.as_bytes(), target.as_str()));
            if let Some(rule) = rule {
                let matched = DlpMatch {
                    rule: rule.name(),
                    target: "query",
                };
                match self.action {
                    DlpAction::Block | DlpAction::Monitor => {
                        return QueryOutcome::Matched(matched);
                    }
                    DlpAction::Redact => {
                        first.get_or_insert(matched);
                        serializer.append_pair(key.as_str(), self.replacement.as_str());
                    }
                }
            } else {
                serializer.append_pair(key.as_str(), value.as_str());
            }
        }
        let Some(matched) = first else {
            return QueryOutcome::Allowed;
        };
        let query = serializer.finish();
        match replace_uri_query(uri, query.as_str()) {
            Some(uri) => QueryOutcome::Redacted(uri, matched),
            None => QueryOutcome::Matched(matched),
        }
    }

    /// 业务作用：按 Content-Type 选择已配置且受支持的 body 解析方式。
    ///
    /// 参数说明：
    /// - `headers`：是当前方向的实体 header。
    ///
    /// 返回：media type 被显式允许时返回解析方式；缺失、非法或未声明返回 `None`。
    fn body_kind(&self, headers: &HeaderMap) -> Option<BodyKind> {
        let media_type = headers
            .get(CONTENT_TYPE)?
            .to_str()
            .ok()?
            .split(';')
            .next()?
            .trim()
            .to_ascii_lowercase();
        let json_allowed = (media_type == "application/json"
            && self.body_media_types.contains("application/json"))
            || (media_type.starts_with("application/")
                && media_type.ends_with("+json")
                && self.body_media_types.contains("application/*+json"));
        let kind = if json_allowed {
            BodyKind::Json
        } else if media_type == "application/x-www-form-urlencoded"
            && self
                .body_media_types
                .contains("application/x-www-form-urlencoded")
        {
            BodyKind::Form
        } else if media_type.starts_with("text/")
            && (self.body_media_types.contains("text/*")
                || (media_type == "text/plain" && self.body_media_types.contains("text/plain")))
        {
            BodyKind::Text
        } else {
            return None;
        };
        Some(kind)
    }

    /// 业务作用：检测值中的第一条未被精确 target 豁免的规则。
    ///
    /// 参数说明：
    /// - `value`：是原始字节
    /// - `target`：是当前精确位置。
    ///
    /// 返回：首条未豁免规则，或 `None`。
    fn detect_unexcluded(&self, value: &[u8], target: &str) -> Option<DlpRule> {
        ALL_RULES
            .into_iter()
            .find(|rule| self.detector.matches(*rule, value) && !self.excluded(*rule, target))
    }

    /// 业务作用：判断固定规则在当前精确 target 是否显式豁免。
    ///
    /// 参数说明：
    /// - `rule`：是固定规则
    /// - `target`：是精确配置 target。
    ///
    /// 返回：存在对应例外时返回 true。
    fn excluded(&self, rule: DlpRule, target: &str) -> bool {
        self.exclusions.contains(&(rule, target.to_owned()))
    }
}

/// query 检查内部结果。
enum QueryOutcome {
    /// 无命中。
    Allowed,
    /// block 或 monitor 命中，URI 不变。
    Matched(DlpMatch),
    /// redact 命中并返回新 URI。
    Redacted(Uri, DlpMatch),
}

/// JSON 递归资源预算。
struct JsonBudget {
    depth: usize,
    nodes: usize,
}

/// 业务作用：解析无重复 header 目标并约束热路径扫描数量。
///
/// 参数说明：
/// - `field`：用于错误定位
/// - `values`：是配置 header 名。
///
/// 返回：全部名称合法且唯一时返回列表，否则返回错误。
fn parse_headers(field: &str, values: &[String]) -> Result<Vec<HeaderName>> {
    if values.len() > MAX_HEADER_TARGETS {
        bail!("{field} supports at most {MAX_HEADER_TARGETS} entries");
    }
    let mut seen = HashSet::with_capacity(values.len());
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let name = HeaderName::from_bytes(value.as_bytes())
            .with_context(|| format!("{field} contains invalid header name"))?;
        if !seen.insert(name.clone()) {
            bail!("{field} contains duplicate header name");
        }
        output.push(name);
    }
    Ok(output)
}

/// 业务作用：解析 body media type allowlist，并保留精确值与显式 wildcard 的差异。
///
/// 参数说明：
/// - `values`：是配置 media type。
///
/// 返回：只包含 JSON、form 或 text 受支持值且无重复时返回集合；未知值返回错误。
fn parse_body_media_types(values: &[String]) -> Result<HashSet<String>> {
    if values.len() > 16 {
        bail!("dlp.body_media_types supports at most 16 entries");
    }
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        match value.as_str() {
            "application/json"
            | "application/*+json"
            | "application/x-www-form-urlencoded"
            | "text/*"
            | "text/plain" => {}
            _ => bail!("unsupported dlp.body_media_types value `{value}`"),
        }
        if !output.insert(value.clone()) {
            bail!("dlp.body_media_types contains duplicate value `{value}`");
        }
    }
    Ok(output)
}

/// 业务作用：解析 rule+target 精确例外，拒绝未知规则、通配符、重复和未启用规则。
///
/// 参数说明：
/// - `values`：是例外声明
/// - `detector`：提供启用规则集合。
///
/// 返回：全部例外合法时返回固定集合，否则返回错误。
fn parse_exclusions(
    values: &[DlpExclusionCfg],
    detector: &Detector,
) -> Result<HashSet<(DlpRule, String)>> {
    if values.len() > MAX_EXCLUSIONS {
        bail!("dlp.exclusions supports at most {MAX_EXCLUSIONS} entries");
    }
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        let Some(rule) = DlpRule::from_name(value.rule.as_str()) else {
            bail!("unknown dlp exclusion rule `{}`", value.rule);
        };
        if !detector.enabled.contains(&rule) {
            bail!("dlp exclusion references disabled rule `{}`", value.rule);
        }
        if value.target.is_empty()
            || value.target.len() > 256
            || value.target.contains('*')
            || !valid_exclusion_target(value.target.as_str())
        {
            bail!("invalid dlp exclusion target `{}`", value.target);
        }
        if !output.insert((rule, value.target.clone())) {
            bail!("duplicate dlp exclusion");
        }
    }
    Ok(output)
}

/// 业务作用：验证 DLP 例外 target 只使用受支持的精确位置语法。
///
/// 参数说明：
/// - `target`：是配置值。
///
/// 返回：固定 body/path 或带非空名称的 header/query target 返回 true。
fn valid_exclusion_target(target: &str) -> bool {
    matches!(target, "request_body" | "response_body" | "path_log")
        || ["request_header:", "response_header:", "query:"]
            .into_iter()
            .any(|prefix| {
                target
                    .strip_prefix(prefix)
                    .is_some_and(|name| !name.is_empty())
            })
}

/// 业务作用：识别响应或请求声明长度是否已超过 body 聚合硬门。
///
/// 参数说明：
/// - `headers`：是实体 header
/// - `limit`：是显式字节上限。
///
/// 返回：任一 Content-Length 非法、重复不一致或超过上限时返回 true。
fn content_length_exceeds(headers: &HeaderMap, limit: u64) -> bool {
    let mut parsed = None;
    for value in headers.get_all(CONTENT_LENGTH).iter() {
        let Some(value) = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return true;
        };
        if parsed.is_some_and(|previous| previous != value) {
            return true;
        }
        parsed = Some(value);
    }
    parsed.is_some_and(|value| value > limit)
}

/// 业务作用：拒绝无法在当前慢路径安全还原的压缩实体。
///
/// 参数说明：
/// - `headers`：是实体 header。
///
/// 返回：Content-Encoding 缺失或单值 identity 返回 false，其它形态返回 true。
fn has_non_identity_encoding(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    match (values.next(), values.next()) {
        (None, _) => false,
        (Some(value), None) => value
            .to_str()
            .map(|value| !value.trim().eq_ignore_ascii_case("identity"))
            .unwrap_or(true),
        _ => true,
    }
}

/// 业务作用：以原 path 和重建 query 生成合法 URI，避免字符串拼接改变 scheme/authority。
///
/// 参数说明：
/// - `uri`：是当前 URI
/// - `query`：是 form serializer 生成的规范 query。
///
/// 返回：新 path-and-query 可解析时返回 URI，否则返回 `None`。
fn replace_uri_query(uri: &Uri, query: &str) -> Option<Uri> {
    let mut parts = uri.clone().into_parts();
    let path_and_query = format!("{}?{query}", uri.path()).parse().ok()?;
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).ok()
}

/// 业务作用：在 ASCII 不区分大小写下查找固定 private-key marker。
///
/// 参数说明：
/// - `haystack`：是待扫描值
/// - `needle`：是编译期 ASCII marker。
///
/// 返回：存在完整 marker 时返回 true。
fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

/// 业务作用：识别 13..=19 位、允许空格/短横线分隔且通过 Luhn 的银行卡候选。
///
/// 参数说明：
/// - `value`：是待扫描字节。
///
/// 返回：至少一个候选通过长度与 Luhn 校验时返回 true。
fn contains_luhn_card(value: &[u8]) -> bool {
    let mut digits = Vec::with_capacity(19);
    for byte in value.iter().copied().chain(std::iter::once(b'x')) {
        if byte.is_ascii_digit() {
            if digits.len() < 20 {
                digits.push(byte - b'0');
            }
        } else if matches!(byte, b' ' | b'-') && !digits.is_empty() {
            continue;
        } else if !digits.is_empty() {
            if (13..=19).contains(&digits.len()) && luhn_valid(digits.as_slice()) {
                return true;
            }
            digits.clear();
        }
    }
    false
}

/// 业务作用：对银行卡候选执行 Luhn 校验，降低普通长数字误报。
///
/// 参数说明：
/// - `digits`：是只含十进制数字的候选。
///
/// 返回：校验和可被十整除且不是全零时返回 true。
fn luhn_valid(digits: &[u8]) -> bool {
    if digits.iter().all(|digit| *digit == 0) {
        return false;
    }
    let parity = digits.len() % 2;
    let sum = digits
        .iter()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == parity {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                *digit
            }
        })
        .map(u32::from)
        .sum::<u32>();
    sum % 10 == 0
}
