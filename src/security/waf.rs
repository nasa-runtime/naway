//! route 级内置 API WAF。
//!
//! 未配置策略时本模块不进入数据面。head 检查只读取既有请求元数据；JSON/XML body
//! 检查必须由 route 显式开启，并复用有界聚合后的 `Bytes` 向上游重放。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::request::Parts;
use http::{HeaderName, Version};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::model::{WafCfg, WafRulePackCfg};
use crate::proxy::forward::ForwardBody;
use crate::proxy::request_validation::{buffered_body, collect_bounded, CollectError};

const MAX_WAF_BODY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WAF_VALUE_BYTES: usize = 256 * 1024;
const MAX_WAF_EXCLUSIONS: usize = 128;
const MAX_WAF_STRUCTURED_DEPTH: usize = 128;
const MAX_WAF_STRUCTURED_NODES: usize = 1_000_000;
const MAX_WAF_XML_ATTRIBUTES: usize = 100_000;
const MAX_WAF_RULE_PACK_BYTES: usize = 4 * 1024 * 1024;
const MAX_WAF_RULE_PACK_RULES: usize = 1024;
const MAX_WAF_RULE_PACK_PATTERNS: usize = 16_384;
const MAX_WAF_RULE_PACK_PATTERN_BYTES: usize = 512;
const MAX_WAF_RULE_PACK_COMPILE_MS: u64 = 5_000;
const MAX_WAF_RULE_PACK_TARGETS_PER_RULE: usize = 64;

/// WAF 的固定处置模式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WafMode {
    /// 命中后立即拒绝请求。
    Enforce,
    /// 命中后只记录结果，仍允许请求继续。
    Monitor,
}

/// 内置规则的固定标识。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum WafRule {
    /// SQL 注入特征。
    SqlInjection,
    /// 跨站脚本特征。
    CrossSiteScripting,
    /// shell/命令注入特征。
    CommandInjection,
    /// 服务端模板注入特征。
    TemplateInjection,
    /// 路径穿越特征。
    PathTraversal,
    /// HTTP framing 与 hop-by-hop 语义冲突。
    ProtocolSmuggling,
    /// 非法、重复编码或扫描预算溢出。
    AbnormalEncoding,
    /// 可覆盖路由或方法语义的危险 header。
    DangerousHeader,
    /// 非法或超预算 JSON document。
    JsonThreat,
    /// 非法、含 DTD/entity 或超预算 XML document。
    XmlThreat,
}

const ALL_RULES: [WafRule; 10] = [
    WafRule::SqlInjection,
    WafRule::CrossSiteScripting,
    WafRule::CommandInjection,
    WafRule::TemplateInjection,
    WafRule::PathTraversal,
    WafRule::ProtocolSmuggling,
    WafRule::AbnormalEncoding,
    WafRule::DangerousHeader,
    WafRule::JsonThreat,
    WafRule::XmlThreat,
];

impl WafRule {
    /// 业务作用：把固定规则映射为配置、日志和指标共同使用的稳定 id。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回不含请求数据的静态规则 id。
    const fn id(self) -> &'static str {
        match self {
            Self::SqlInjection => "sql_injection",
            Self::CrossSiteScripting => "xss",
            Self::CommandInjection => "command_injection",
            Self::TemplateInjection => "template_injection",
            Self::PathTraversal => "path_traversal",
            Self::ProtocolSmuggling => "protocol_smuggling",
            Self::AbnormalEncoding => "abnormal_encoding",
            Self::DangerousHeader => "dangerous_header",
            Self::JsonThreat => "json_threat",
            Self::XmlThreat => "xml_threat",
        }
    }

    /// 业务作用：解析配置中的规则 id，拒绝拼写错误导致策略静默缺失。
    ///
    /// 参数说明：
    /// - `value`：是 route 配置声明的规则 id。
    ///
    /// 返回：已知 id 返回固定规则；未知 id 返回 `None`。
    fn from_id(value: &str) -> Option<Self> {
        ALL_RULES.into_iter().find(|rule| rule.id() == value)
    }
}

/// 一次不携带原始请求值的 WAF 命中。
#[derive(Debug)]
pub(crate) struct WafMatch {
    /// 构建期验证且有界的规则 id，不含请求数据。
    pub(crate) rule: String,
    /// 固定或配置期有界的 target；不包含 header 值、URI 值或 body 内容。
    pub(crate) target: String,
}

/// 内置或外部规则包的确定命中身份。
enum DetectedRule {
    /// 编译期固定规则。
    Builtin(WafRule),
    /// 规则包中已验证的有界 id。
    External(Arc<str>),
}

/// 已规范化的外部 literal 规则。
#[derive(Clone)]
struct ExternalRule {
    order: usize,
    id: Arc<str>,
    patterns: Arc<[Box<[u8]>]>,
}

/// 按请求位置预索引的只读外部规则包。
struct ExternalRulePack {
    path: Vec<ExternalRule>,
    query: Vec<ExternalRule>,
    body: Vec<ExternalRule>,
    headers: Vec<ExternalRule>,
    named_headers: HashMap<String, Vec<ExternalRule>>,
    rule_targets: HashMap<String, HashSet<String>>,
}

/// 外部规则包顶层格式；未知字段必须拒绝，避免签名内容与执行语义脱节。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulePackDocument {
    schema_version: u32,
    id: String,
    rules: Vec<RulePackRule>,
}

/// 一条外部 ASCII literal 规则。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulePackRule {
    id: String,
    targets: Vec<String>,
    patterns: Vec<String>,
}

impl ExternalRulePack {
    /// 业务作用：在候选快照发布前完成规则包读取、摘要、签名、格式、预算和 target 索引构建。
    ///
    /// 参数说明：
    /// - `cfg`：声明真实性与资源门
    /// - `config_dir`：是本地文件和 SecretSource 路径基准。
    ///
    /// 返回：全部校验通过时返回只读索引；任何错误或超时拒绝候选并保留当前快照。
    fn load(cfg: &WafRulePackCfg, config_dir: &Path) -> Result<Self> {
        if !(1..=MAX_WAF_RULE_PACK_BYTES).contains(&cfg.max_pack_bytes)
            || !(1..=MAX_WAF_RULE_PACK_RULES).contains(&cfg.max_rules)
            || !(1..=MAX_WAF_RULE_PACK_PATTERNS).contains(&cfg.max_patterns)
            || !(1..=MAX_WAF_RULE_PACK_COMPILE_MS).contains(&cfg.max_compile_ms)
        {
            bail!("WAF rule pack resource bounds are invalid");
        }
        let deadline = Duration::from_millis(cfg.max_compile_ms);
        let started = Instant::now();
        let source = resolve_rule_pack_path(config_dir, cfg.source.as_str())?;
        let bytes =
            crate::io::bounded_io::read_file(&source, cfg.max_pack_bytes, "WAF rule pack source")?;
        verify_rule_pack_digest(bytes.as_slice(), cfg.sha256.as_str())?;
        verify_rule_pack_signature(bytes.as_slice(), cfg, config_dir)?;
        ensure_compile_deadline(started, deadline)?;

        let document: RulePackDocument =
            serde_json::from_slice(bytes.as_slice()).context("decode WAF rule pack JSON")?;
        if document.schema_version != 1 {
            bail!("WAF rule pack schema_version must be 1");
        }
        validate_rule_pack_id(document.id.as_str(), "pack id")?;
        if document.rules.is_empty() || document.rules.len() > cfg.max_rules {
            bail!("WAF rule pack rule count must be in 1..={}", cfg.max_rules);
        }

        let mut output = Self {
            path: Vec::new(),
            query: Vec::new(),
            body: Vec::new(),
            headers: Vec::new(),
            named_headers: HashMap::new(),
            rule_targets: HashMap::new(),
        };
        let mut rule_ids = HashSet::with_capacity(document.rules.len());
        let mut pattern_count = 0_usize;
        for (order, rule) in document.rules.into_iter().enumerate() {
            ensure_compile_deadline(started, deadline)?;
            validate_rule_pack_id(rule.id.as_str(), "rule id")?;
            if WafRule::from_id(rule.id.as_str()).is_some() || !rule_ids.insert(rule.id.clone()) {
                bail!(
                    "WAF rule pack rule id `{}` is duplicated or reserved",
                    rule.id
                );
            }
            if rule.targets.is_empty() || rule.targets.len() > MAX_WAF_RULE_PACK_TARGETS_PER_RULE {
                bail!(
                    "WAF rule pack rule `{}` target count must be in 1..={MAX_WAF_RULE_PACK_TARGETS_PER_RULE}",
                    rule.id
                );
            }
            if rule.patterns.is_empty() {
                bail!("WAF rule pack rule `{}` has no patterns", rule.id);
            }
            pattern_count = pattern_count
                .checked_add(rule.patterns.len())
                .context("WAF rule pack pattern count overflow")?;
            if pattern_count > cfg.max_patterns {
                bail!("WAF rule pack exceeds {} patterns", cfg.max_patterns);
            }

            let mut seen_patterns = HashSet::with_capacity(rule.patterns.len());
            let mut patterns = Vec::with_capacity(rule.patterns.len());
            for pattern in rule.patterns {
                let bytes = pattern.as_bytes();
                if !(2..=MAX_WAF_RULE_PACK_PATTERN_BYTES).contains(&bytes.len())
                    || !bytes
                        .iter()
                        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
                    || pattern.trim().is_empty()
                {
                    bail!(
                        "WAF rule pack rule `{}` pattern must be printable ASCII in 2..={MAX_WAF_RULE_PACK_PATTERN_BYTES} bytes",
                        rule.id
                    );
                }
                let normalized = ascii_lowercase(bytes).into_boxed_slice();
                if !seen_patterns.insert(normalized.clone()) {
                    bail!(
                        "WAF rule pack rule `{}` contains duplicate patterns",
                        rule.id
                    );
                }
                patterns.push(normalized);
            }
            let compiled = ExternalRule {
                order,
                id: Arc::from(rule.id.as_str()),
                patterns: Arc::from(patterns),
            };
            let mut seen_targets = HashSet::with_capacity(rule.targets.len());
            for target in rule.targets {
                let target = normalize_rule_pack_target(target.as_str())?;
                if !seen_targets.insert(target.clone()) {
                    bail!(
                        "WAF rule pack rule `{}` contains duplicate target `{target}`",
                        rule.id
                    );
                }
                match target.as_str() {
                    "path" => output.path.push(compiled.clone()),
                    "query" => output.query.push(compiled.clone()),
                    "body" => output.body.push(compiled.clone()),
                    "header" => output.headers.push(compiled.clone()),
                    _ => {
                        let name = target
                            .strip_prefix("header:")
                            .expect("rule pack target was normalized");
                        output
                            .named_headers
                            .entry(name.to_owned())
                            .or_default()
                            .push(compiled.clone());
                    }
                }
            }
            output.rule_targets.insert(rule.id, seen_targets);
        }
        ensure_compile_deadline(started, deadline)?;
        Ok(output)
    }

    /// 业务作用：按预索引 target 扫描外部 literal，并保持规则包声明顺序的确定优先级。
    ///
    /// 参数说明：
    /// - `normalized`：已规范化为 ASCII 小写的有界输入。
    /// - `target`：固定检查位置或规范化的 header 位置。
    /// - `exclusions`：当前路由显式允许的检查排除项。
    ///
    /// 返回：首条命中规则的已验证 id；无适用规则或 literal 未命中返回 `None`。
    fn detect(
        &self,
        normalized: &[u8],
        target: &str,
        exclusions: &[(String, String)],
    ) -> Option<Arc<str>> {
        let (primary, secondary) = match target {
            "path" => (self.path.as_slice(), None),
            "query" => (self.query.as_slice(), None),
            "body" => (self.body.as_slice(), None),
            _ => {
                let name = target.strip_prefix("header:")?;
                (
                    self.headers.as_slice(),
                    self.named_headers.get(name).map(Vec::as_slice),
                )
            }
        };
        let first = first_external_match(primary, normalized, target, exclusions);
        let second =
            secondary.and_then(|rules| first_external_match(rules, normalized, target, exclusions));
        match (first, second) {
            (Some((left_order, left)), Some((right_order, right))) => {
                Some(if left_order <= right_order {
                    left
                } else {
                    right
                })
            }
            (Some((_, rule)), None) | (None, Some((_, rule))) => Some(rule),
            (None, None) => None,
        }
    }

    /// 业务作用：验证 route 例外只引用规则包中存在且会作用于该精确位置的规则。
    ///
    /// 参数说明：
    /// - `rule`：是外部规则 id
    /// - `target`：是已规范化的精确例外位置。
    ///
    /// 返回：规则存在且 target 属于其声明范围时返回 true。
    fn applies_to(&self, rule: &str, target: &str) -> bool {
        self.rule_targets.get(rule).is_some_and(|targets| {
            targets.contains(target)
                || (target.starts_with("header:") && targets.contains("header"))
        })
    }
}

/// body 检查后的所有权结果。
pub(crate) enum WafBodyOutcome {
    /// 未命中或无需读取 body；返回可继续转发的请求体。
    Allowed(ForwardBody),
    /// monitor 模式命中；返回请求体及低敏命中信息。
    Monitored(ForwardBody, WafMatch),
    /// enforce 模式命中；已消费的请求体不得继续进入上游。
    Blocked(WafMatch),
    /// 声明或实际请求体超过显式聚合预算。
    TooLarge,
    /// 下游 body transport 读取失败。
    ReadFailed,
}

/// 快照内只读的 route 级 WAF 策略。
pub(crate) struct WafPolicy {
    /// 命中后的处置方式。
    mode: WafMode,
    /// 是否启用 JSON/XML 请求体慢路径。
    inspect_body: bool,
    /// 请求体聚合硬上限。
    max_body_bytes: u64,
    /// 单个值扫描硬上限。
    max_value_bytes: usize,
    /// 已启用的固定规则集合。
    rules: HashSet<WafRule>,
    /// 精确例外；构建期已规范化 header target。
    exclusions: Vec<(WafRule, String)>,
    /// 外部规则包的精确例外；id 和 target 都已在构建期复验。
    external_exclusions: Vec<(String, String)>,
    /// JSON 嵌套深度上限。
    max_json_depth: usize,
    /// JSON value 节点数上限。
    max_json_nodes: usize,
    /// XML 元素嵌套深度上限。
    max_xml_depth: usize,
    /// XML 事件节点数上限。
    max_xml_nodes: usize,
    /// XML 属性总数上限。
    max_xml_attributes: usize,
    /// 已验签、验摘要并按 target 预索引的外部 literal 规则。
    external_rules: Option<ExternalRulePack>,
}

impl WafPolicy {
    /// 业务作用：在快照切换前编译并验证 route WAF，防止无效规则或无界预算进入数据面。
    ///
    /// 参数说明：
    /// - `cfg`：是单条 route 的 WAF 声明
    /// - `config_dir`：是规则包与 SecretSource 的路径基准。
    ///
    /// 返回：配置有效时返回只读策略；模式、规则、例外或预算无效时返回错误并阻止换版。
    pub(crate) fn build(cfg: &WafCfg, config_dir: &Path) -> Result<Self> {
        let mode = match cfg.mode.as_str() {
            "enforce" => WafMode::Enforce,
            "monitor" => WafMode::Monitor,
            value => bail!("mode must be `enforce` or `monitor`, got `{value}`"),
        };
        if !(1..=MAX_WAF_BODY_BYTES).contains(&cfg.max_body_bytes) {
            bail!("max_body_bytes must be in 1..={MAX_WAF_BODY_BYTES}");
        }
        if !(1..=MAX_WAF_VALUE_BYTES).contains(&cfg.max_value_bytes) {
            bail!("max_value_bytes must be in 1..={MAX_WAF_VALUE_BYTES}");
        }
        validate_structured_budget(
            "max_json_depth",
            cfg.max_json_depth,
            MAX_WAF_STRUCTURED_DEPTH,
        )?;
        validate_structured_budget(
            "max_json_nodes",
            cfg.max_json_nodes,
            MAX_WAF_STRUCTURED_NODES,
        )?;
        validate_structured_budget("max_xml_depth", cfg.max_xml_depth, MAX_WAF_STRUCTURED_DEPTH)?;
        validate_structured_budget("max_xml_nodes", cfg.max_xml_nodes, MAX_WAF_STRUCTURED_NODES)?;
        validate_structured_budget(
            "max_xml_attributes",
            cfg.max_xml_attributes,
            MAX_WAF_XML_ATTRIBUTES,
        )?;

        let mut rules = HashSet::new();
        if cfg.enabled_rules.is_empty() {
            rules.extend(ALL_RULES);
        } else {
            for id in &cfg.enabled_rules {
                let Some(rule) = WafRule::from_id(id) else {
                    bail!("unknown enabled rule `{id}`");
                };
                if !rules.insert(rule) {
                    bail!("enabled rule `{id}` is duplicated");
                }
            }
        }
        let external_rules = cfg
            .rule_pack
            .as_ref()
            .map(|pack| ExternalRulePack::load(pack, config_dir))
            .transpose()?;
        if cfg.exclusions.len() > MAX_WAF_EXCLUSIONS {
            bail!("exclusions supports at most {MAX_WAF_EXCLUSIONS} entries");
        }
        let mut exclusions = Vec::with_capacity(cfg.exclusions.len());
        let mut external_exclusions = Vec::new();
        for exclusion in &cfg.exclusions {
            let target = normalize_exclusion_target(exclusion.target.as_str())?;
            if let Some(rule) = WafRule::from_id(exclusion.rule.as_str()) {
                if !rules.contains(&rule) {
                    bail!("exclusion references disabled rule `{}`", exclusion.rule);
                }
                if exclusions
                    .iter()
                    .any(|existing| existing == &(rule, target.clone()))
                {
                    bail!(
                        "duplicate WAF exclusion for rule `{}` target `{}`",
                        exclusion.rule,
                        exclusion.target
                    );
                }
                exclusions.push((rule, target));
            } else if external_rules
                .as_ref()
                .is_some_and(|pack| pack.applies_to(exclusion.rule.as_str(), target.as_str()))
            {
                if !external_exclusions
                    .iter()
                    .any(|existing| existing == &(exclusion.rule.clone(), target.clone()))
                {
                    external_exclusions.push((exclusion.rule.clone(), target));
                } else {
                    bail!(
                        "duplicate WAF exclusion for rule `{}` target `{}`",
                        exclusion.rule,
                        exclusion.target
                    );
                }
            } else {
                bail!(
                    "exclusion references unknown rule or inapplicable target `{}`",
                    exclusion.rule
                );
            }
        }

        Ok(Self {
            mode,
            inspect_body: cfg.inspect_body,
            max_body_bytes: cfg.max_body_bytes,
            max_value_bytes: cfg.max_value_bytes,
            rules,
            exclusions,
            external_exclusions,
            max_json_depth: cfg.max_json_depth,
            max_json_nodes: cfg.max_json_nodes,
            max_xml_depth: cfg.max_xml_depth,
            max_xml_nodes: cfg.max_xml_nodes,
            max_xml_attributes: cfg.max_xml_attributes,
            external_rules,
        })
    }

    /// 业务作用：告知请求管线命中后应拦截还是只观测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：`enforce` 模式返回 true，`monitor` 模式返回 false。
    pub(crate) const fn enforces(&self) -> bool {
        matches!(self.mode, WafMode::Enforce)
    }

    /// 业务作用：向 route 构建器暴露该策略是否会取得请求体所有权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：显式启用 JSON/XML body 检查时返回 true。
    pub(crate) const fn inspects_body(&self) -> bool {
        self.inspect_body
    }

    /// 业务作用：在认证和外部插件之前检查请求行与 headers，尽早拒绝协议歧义和常见攻击输入。
    ///
    /// 参数说明：
    /// - `parts`：是已通过 listener 基础语法校验的请求 head。
    ///
    /// 返回：首次确定命中返回低敏规则与 target；未命中返回 `None`。
    pub(crate) fn inspect_head(&self, parts: &Parts) -> Option<WafMatch> {
        if let Some(matched) = self.inspect_protocol(parts) {
            return Some(matched);
        }
        if let Some(matched) = self.inspect_uri_component(parts.uri.path().as_bytes(), "path") {
            return Some(matched);
        }
        if let Some(query) = parts.uri.query() {
            if let Some(matched) = self.inspect_uri_component(query.as_bytes(), "query") {
                return Some(matched);
            }
        }
        for (name, value) in &parts.headers {
            let target = format!("header:{}", name.as_str());
            if is_dangerous_header(name)
                && self.rule_applies(WafRule::DangerousHeader, target.as_str())
            {
                return Some(waf_match(WafRule::DangerousHeader, target));
            }
            if value.as_bytes().len() > self.max_value_bytes
                && self.rule_applies(WafRule::AbnormalEncoding, target.as_str())
            {
                return Some(waf_match(WafRule::AbnormalEncoding, target));
            }
            if let Some(rule) = self.inspect_plain_value(value.as_bytes(), target.as_str()) {
                return Some(waf_detected_match(rule, target));
            }
        }
        None
    }

    /// 业务作用：对显式开启的 JSON/XML 请求体执行有界聚合、攻击特征与结构预算检查。
    ///
    /// 参数说明：
    /// - `parts`：请求 head，用于判断 media type 与提前核对 Content-Length。
    /// - `body`：尚未被其它 body filter 消费的请求体。
    ///
    /// 返回：未启用或通过时归还可转发 body；monitor 命中时同时归还命中信息；违规、超限或读取失败时故障关闭。
    pub(crate) async fn inspect_body(&self, parts: &Parts, body: ForwardBody) -> WafBodyOutcome {
        if !self.inspect_body {
            return WafBodyOutcome::Allowed(body);
        }
        let Some(media_type) = structured_media_type(parts) else {
            return WafBodyOutcome::Allowed(body);
        };
        if declared_body_too_large(parts, self.max_body_bytes) {
            return WafBodyOutcome::TooLarge;
        }
        let collected = match collect_bounded(body, self.max_body_bytes).await {
            Ok(collected) => collected,
            Err(CollectError::TooLarge) => return WafBodyOutcome::TooLarge,
            Err(CollectError::Read) => return WafBodyOutcome::ReadFailed,
        };
        if collected.bytes.is_empty() {
            return WafBodyOutcome::Allowed(buffered_body(collected));
        }

        let matched = self
            .inspect_plain_value(collected.bytes.as_ref(), "body")
            .or_else(|| match media_type {
                StructuredMediaType::Json => self.inspect_json(collected.bytes.as_ref()),
                StructuredMediaType::Xml => self.inspect_xml(collected.bytes.as_ref()),
            })
            .map(|rule| waf_detected_match(rule, "body".to_owned()));
        match matched {
            None => WafBodyOutcome::Allowed(buffered_body(collected)),
            Some(matched) if self.enforces() => WafBodyOutcome::Blocked(matched),
            Some(matched) => WafBodyOutcome::Monitored(buffered_body(collected), matched),
        }
    }

    /// 业务作用：识别会造成不同 HTTP hop 对消息边界理解不一致的请求 head。
    ///
    /// 参数说明：
    /// - `parts`：是当前下游请求 head。
    ///
    /// 返回：存在 framing 冲突时返回 `protocol_smuggling` 命中，否则返回 `None`。
    fn inspect_protocol(&self, parts: &Parts) -> Option<WafMatch> {
        let target = "header:framing";
        if !self.rule_applies(WafRule::ProtocolSmuggling, target) {
            return None;
        }
        let has_length = parts.headers.contains_key(CONTENT_LENGTH);
        let has_transfer = parts.headers.contains_key(TRANSFER_ENCODING);
        if has_length && has_transfer {
            return Some(waf_match(WafRule::ProtocolSmuggling, target.to_owned()));
        }
        if invalid_content_lengths(parts) {
            return Some(waf_match(WafRule::ProtocolSmuggling, target.to_owned()));
        }
        if let Some(transfer) = parts.headers.get(TRANSFER_ENCODING) {
            let valid = transfer.to_str().ok().is_some_and(|value| {
                !matches!(parts.version, Version::HTTP_2 | Version::HTTP_3)
                    && value.eq_ignore_ascii_case("chunked")
            });
            if !valid {
                return Some(waf_match(WafRule::ProtocolSmuggling, target.to_owned()));
            }
        }
        if matches!(parts.version, Version::HTTP_2 | Version::HTTP_3)
            && parts.headers.contains_key(CONNECTION)
        {
            return Some(waf_match(WafRule::ProtocolSmuggling, target.to_owned()));
        }
        if connection_overrides_framing(parts) {
            return Some(waf_match(WafRule::ProtocolSmuggling, target.to_owned()));
        }
        None
    }

    /// 业务作用：规范化 URI component 后检查非法/双重 percent 编码与攻击特征，避免编码差异绕过。
    ///
    /// 参数说明：
    /// - `raw`：原始 path 或 query 字节。
    /// - `target`：固定 target 名称。
    ///
    /// 返回：首次适用规则命中；输入正常且无特征时返回 `None`。
    fn inspect_uri_component(&self, raw: &[u8], target: &'static str) -> Option<WafMatch> {
        if raw.len() > self.max_value_bytes && self.rule_applies(WafRule::AbnormalEncoding, target)
        {
            return Some(waf_match(WafRule::AbnormalEncoding, target.to_owned()));
        }
        let decoded = match percent_decode_once(raw) {
            Ok(decoded) => decoded,
            Err(()) if self.rule_applies(WafRule::AbnormalEncoding, target) => {
                return Some(waf_match(WafRule::AbnormalEncoding, target.to_owned()));
            }
            Err(()) => raw.to_vec(),
        };
        if contains_percent_escape(decoded.as_slice())
            && self.rule_applies(WafRule::AbnormalEncoding, target)
        {
            return Some(waf_match(WafRule::AbnormalEncoding, target.to_owned()));
        }
        self.inspect_plain_value(decoded.as_slice(), target)
            .map(|rule| waf_detected_match(rule, target.to_owned()))
    }

    /// 业务作用：按固定优先级检查一个已确定边界的值，保证首次命中可重复且不泄露原始输入。
    ///
    /// 参数说明：
    /// - `value`：待检查字节。
    /// - `target`：例外匹配使用的精确 target。
    ///
    /// 返回：首次启用且未被例外豁免的规则；无命中返回 `None`。
    fn inspect_plain_value(&self, value: &[u8], target: &str) -> Option<DetectedRule> {
        let normalized = ascii_lowercase(value);
        if let Some(rule) = [
            WafRule::SqlInjection,
            WafRule::CrossSiteScripting,
            WafRule::CommandInjection,
            WafRule::TemplateInjection,
            WafRule::PathTraversal,
        ]
        .into_iter()
        .find(|rule| {
            self.rule_applies(*rule, target) && signature_matches(*rule, normalized.as_slice())
        }) {
            return Some(DetectedRule::Builtin(rule));
        }
        self.external_rules
            .as_ref()
            .and_then(|pack| {
                pack.detect(
                    normalized.as_slice(),
                    target,
                    self.external_exclusions.as_slice(),
                )
            })
            .map(DetectedRule::External)
    }

    /// 业务作用：解析 JSON 并以迭代方式约束节点、深度和解码后字符串，防止结构炸弹与转义绕过。
    ///
    /// 参数说明：
    /// - `bytes`：是已通过请求体字节上限的完整 JSON entity。
    ///
    /// 返回：非法或超预算返回 `json_threat`；字符串命中返回对应攻击规则；通过返回 `None`。
    fn inspect_json(&self, bytes: &[u8]) -> Option<DetectedRule> {
        if !self.rule_applies(WafRule::JsonThreat, "body") && !self.has_body_signature_rules() {
            return None;
        }
        let value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) if self.rule_applies(WafRule::JsonThreat, "body") => {
                return Some(DetectedRule::Builtin(WafRule::JsonThreat));
            }
            Err(_) => return None,
        };
        let mut stack = vec![(&value, 1_usize)];
        let mut nodes = 0_usize;
        while let Some((value, depth)) = stack.pop() {
            nodes = nodes.saturating_add(1);
            if (nodes > self.max_json_nodes || depth > self.max_json_depth)
                && self.rule_applies(WafRule::JsonThreat, "body")
            {
                return Some(DetectedRule::Builtin(WafRule::JsonThreat));
            }
            match value {
                serde_json::Value::Array(items) => {
                    stack.extend(items.iter().map(|item| (item, depth.saturating_add(1))));
                }
                serde_json::Value::Object(entries) => {
                    for (key, value) in entries {
                        if key.len() > self.max_value_bytes
                            && self.rule_applies(WafRule::JsonThreat, "body")
                        {
                            return Some(DetectedRule::Builtin(WafRule::JsonThreat));
                        }
                        if let Some(rule) = self.inspect_plain_value(key.as_bytes(), "body") {
                            return Some(rule);
                        }
                        stack.push((value, depth.saturating_add(1)));
                    }
                }
                serde_json::Value::String(value) => {
                    if value.len() > self.max_value_bytes
                        && self.rule_applies(WafRule::JsonThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::JsonThreat));
                    }
                    if let Some(rule) = self.inspect_plain_value(value.as_bytes(), "body") {
                        return Some(rule);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// 业务作用：解析 XML 并拒绝 DTD、自定义 entity 与超预算结构，防止 XXE 和实体扩展攻击。
    ///
    /// 参数说明：
    /// - `bytes`：是已通过请求体字节上限的完整 XML entity。
    ///
    /// 返回：非法或超预算返回 `xml_threat`；文本命中返回对应攻击规则；通过返回 `None`。
    fn inspect_xml(&self, bytes: &[u8]) -> Option<DetectedRule> {
        if !self.rule_applies(WafRule::XmlThreat, "body") && !self.has_body_signature_rules() {
            return None;
        }
        let mut reader = Reader::from_reader(bytes);
        let mut open_elements: Vec<Vec<u8>> = Vec::new();
        let mut nodes = 0_usize;
        let mut attributes = 0_usize;
        let mut root_seen = false;
        let mut root_closed = false;
        loop {
            let event = match reader.read_event() {
                Ok(event) => event,
                Err(_) if self.rule_applies(WafRule::XmlThreat, "body") => {
                    return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                }
                Err(_) => return None,
            };
            nodes = nodes.saturating_add(1);
            if nodes > self.max_xml_nodes && self.rule_applies(WafRule::XmlThreat, "body") {
                return Some(DetectedRule::Builtin(WafRule::XmlThreat));
            }
            match event {
                Event::Start(element) => {
                    if (root_closed || (open_elements.is_empty() && root_seen))
                        && self.rule_applies(WafRule::XmlThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                    }
                    if open_elements.is_empty() {
                        root_seen = true;
                    }
                    open_elements.push(element.name().as_ref().to_vec());
                    if open_elements.len() > self.max_xml_depth
                        && self.rule_applies(WafRule::XmlThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                    }
                    if let Some(rule) = self.inspect_xml_element(&element, &mut attributes) {
                        return Some(rule);
                    }
                }
                Event::Empty(element) => {
                    if (root_closed || (open_elements.is_empty() && root_seen))
                        && self.rule_applies(WafRule::XmlThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                    }
                    if open_elements.is_empty() {
                        root_seen = true;
                        root_closed = true;
                    }
                    if let Some(rule) = self.inspect_xml_element(&element, &mut attributes) {
                        return Some(rule);
                    }
                }
                Event::End(element) => {
                    let expected = open_elements.pop();
                    if expected.as_deref() != Some(element.name().as_ref())
                        && self.rule_applies(WafRule::XmlThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                    }
                    if open_elements.is_empty() {
                        root_closed = true;
                    }
                }
                Event::Text(text) => {
                    let text = match text.decode() {
                        Ok(text) => text,
                        Err(_) if self.rule_applies(WafRule::XmlThreat, "body") => {
                            return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                        }
                        Err(_) => continue,
                    };
                    if open_elements.is_empty()
                        && !text.trim().is_empty()
                        && self.rule_applies(WafRule::XmlThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                    }
                    if let Some(rule) =
                        self.inspect_structured_text(text.as_bytes(), WafRule::XmlThreat)
                    {
                        return Some(rule);
                    }
                }
                Event::CData(text) => {
                    let text = match text.decode() {
                        Ok(text) => text,
                        Err(_) if self.rule_applies(WafRule::XmlThreat, "body") => {
                            return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                        }
                        Err(_) => continue,
                    };
                    if let Some(rule) =
                        self.inspect_structured_text(text.as_bytes(), WafRule::XmlThreat)
                    {
                        return Some(rule);
                    }
                }
                Event::DocType(_) if self.rule_applies(WafRule::XmlThreat, "body") => {
                    return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                }
                Event::PI(_) if self.rule_applies(WafRule::XmlThreat, "body") => {
                    return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                }
                Event::GeneralRef(reference)
                    if !is_predefined_or_numeric_entity(reference.as_ref())
                        && self.rule_applies(WafRule::XmlThreat, "body") =>
                {
                    return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                }
                Event::Eof => {
                    if (!root_seen || !root_closed || !open_elements.is_empty())
                        && self.rule_applies(WafRule::XmlThreat, "body")
                    {
                        return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                    }
                    return None;
                }
                _ => {}
            }
        }
    }

    /// 业务作用：检查 XML 元素名与属性并累计 document 级属性预算。
    ///
    /// 参数说明：
    /// - `element`：当前 start/empty element。
    /// - `attribute_count`：当前 document 已解析属性总数。
    ///
    /// 返回：结构超限或属性语法错误返回 `xml_threat`；攻击特征命中返回对应规则；通过返回 `None`。
    fn inspect_xml_element(
        &self,
        element: &quick_xml::events::BytesStart<'_>,
        attribute_count: &mut usize,
    ) -> Option<DetectedRule> {
        if let Some(rule) =
            self.inspect_structured_text(element.name().as_ref(), WafRule::XmlThreat)
        {
            return Some(rule);
        }
        for attribute in element.attributes() {
            *attribute_count = attribute_count.saturating_add(1);
            if *attribute_count > self.max_xml_attributes
                && self.rule_applies(WafRule::XmlThreat, "body")
            {
                return Some(DetectedRule::Builtin(WafRule::XmlThreat));
            }
            let attribute = match attribute {
                Ok(attribute) => attribute,
                Err(_) if self.rule_applies(WafRule::XmlThreat, "body") => {
                    return Some(DetectedRule::Builtin(WafRule::XmlThreat));
                }
                Err(_) => continue,
            };
            if let Some(rule) =
                self.inspect_structured_text(attribute.key.as_ref(), WafRule::XmlThreat)
            {
                return Some(rule);
            }
            if let Some(rule) =
                self.inspect_structured_text(attribute.value.as_ref(), WafRule::XmlThreat)
            {
                return Some(rule);
            }
        }
        None
    }

    /// 业务作用：统一执行结构化字段长度门禁与解码后攻击特征检查。
    ///
    /// 参数说明：
    /// - `value`：结构化 parser 交付的字段字节。
    /// - `limit_rule`：字段超限时使用的 JSON/XML 结构规则。
    ///
    /// 返回：超限或命中时返回规则；通过返回 `None`。
    fn inspect_structured_text(&self, value: &[u8], limit_rule: WafRule) -> Option<DetectedRule> {
        if value.len() > self.max_value_bytes && self.rule_applies(limit_rule, "body") {
            return Some(DetectedRule::Builtin(limit_rule));
        }
        self.inspect_plain_value(value, "body")
    }

    /// 业务作用：判断 body 是否至少启用一条内容攻击特征规则，避免仅结构规则关闭时无意义遍历。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：SQL/XSS/命令/模板/路径规则任一启用且未整体豁免 body 时返回 true。
    fn has_body_signature_rules(&self) -> bool {
        [
            WafRule::SqlInjection,
            WafRule::CrossSiteScripting,
            WafRule::CommandInjection,
            WafRule::TemplateInjection,
            WafRule::PathTraversal,
        ]
        .into_iter()
        .any(|rule| self.rule_applies(rule, "body"))
            || self
                .external_rules
                .as_ref()
                .is_some_and(|pack| !pack.body.is_empty())
    }

    /// 业务作用：同时执行规则启用与精确例外判断，防止例外跨 target 扩散。
    ///
    /// 参数说明：
    /// - `rule`：待应用的固定规则。
    /// - `target`：本次检查的精确 target。
    ///
    /// 返回：规则启用且不存在相同 rule/target 例外时返回 true。
    fn rule_applies(&self, rule: WafRule, target: &str) -> bool {
        self.rules.contains(&rule)
            && !self
                .exclusions
                .iter()
                .any(|(excluded_rule, excluded_target)| {
                    *excluded_rule == rule && excluded_target == target
                })
    }
}

/// 结构化请求体的固定 media type 分类。
#[derive(Clone, Copy)]
enum StructuredMediaType {
    /// JSON 或 `application/*+json`。
    Json,
    /// XML、`application/*+xml` 或 `text/xml`。
    Xml,
}

/// 业务作用：在一个 target 的规则索引中寻找声明顺序最靠前的 literal 命中。
///
/// 参数说明：
/// - `rules`：已保持规则包顺序
/// - `value`：是规范化后的有界输入
/// - `target`：用于跳过精确豁免而继续检查后续规则。
/// - `exclusions`：用于跳过精确豁免而继续检查后续规则。
///
/// 返回：返回规则顺序和 id；无命中返回 `None`。
fn first_external_match(
    rules: &[ExternalRule],
    value: &[u8],
    target: &str,
    exclusions: &[(String, String)],
) -> Option<(usize, Arc<str>)> {
    rules.iter().find_map(|rule| {
        if exclusions.iter().any(|(excluded_rule, excluded_target)| {
            excluded_rule == rule.id.as_ref() && excluded_target == target
        }) {
            return None;
        }
        rule.patterns
            .iter()
            .any(|pattern| {
                value
                    .windows(pattern.len())
                    .any(|window| window == pattern.as_ref())
            })
            .then(|| (rule.order, Arc::clone(&rule.id)))
    })
}

/// 业务作用：解析规则包本地来源，禁止 URL 或空路径绕开统一文件观察与有界读取。
///
/// 参数说明：
/// - `config_dir`：是主配置目录
/// - `raw`：是 source 配置值。
///
/// 返回：绝对路径原样返回，相对路径基于主配置目录解析；非法来源返回错误。
fn resolve_rule_pack_path(config_dir: &Path, raw: &str) -> Result<PathBuf> {
    if raw.trim().is_empty() || raw.contains("://") {
        bail!("WAF rule pack source must be a non-empty local path");
    }
    let path = Path::new(raw);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    })
}

/// 业务作用：复验规则包原始字节摘要，防止签名材料或部署文件错配。
///
/// 参数说明：
/// - `bytes`：是原始 JSON
/// - `expected`：是配置声明的 SHA-256 十六进制值。
///
/// 返回：摘要严格一致时成功；格式错误或内容不匹配返回错误。
fn verify_rule_pack_digest(bytes: &[u8], expected: &str) -> Result<()> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("WAF rule pack sha256 must contain exactly 64 hexadecimal characters");
    }
    let actual = Sha256::digest(bytes);
    let actual = actual
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("WAF rule pack sha256 does not match source bytes");
    }
    Ok(())
}

/// 业务作用：复验规则包原始字节的 detached Ed25519 signature，阻止未授权规则进入候选。
///
/// 参数说明：
/// - `bytes`：是原始 JSON
/// - `cfg`：提供 signature/public-key SecretSource。
/// - `config_dir`：提供 signature/public-key SecretSource。
///
/// 返回：签名、key 与 Base64 均合法且严格验签通过时成功，否则返回错误。
fn verify_rule_pack_signature(bytes: &[u8], cfg: &WafRulePackCfg, config_dir: &Path) -> Result<()> {
    let signature = crate::security::secret::resolve_text(
        cfg.signature.as_str(),
        config_dir,
        "WAF rule pack signature",
    )?;
    let public_key = crate::security::secret::resolve_text(
        cfg.public_key.as_str(),
        config_dir,
        "WAF rule pack public key",
    )?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .context("decode WAF rule pack signature")?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .context("decode WAF rule pack public key")?;
    let signature = Signature::from_slice(signature.as_slice())
        .context("WAF rule pack signature must be 64 bytes")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("WAF rule pack public key must be 32 bytes"))?;
    let public_key =
        VerifyingKey::from_bytes(&public_key).context("decode WAF rule pack public key")?;
    public_key
        .verify_strict(bytes, &signature)
        .context("verify WAF rule pack signature")
}

/// 业务作用：限制规则包和规则 id 为低敏、稳定、可安全记录的标识符。
///
/// 参数说明：
/// - `value`：是候选 id
/// - `field`：用于错误定位。
///
/// 返回：1..=128 字节且只含 ASCII 字母数字、点、下划线或连字符时成功。
fn validate_rule_pack_id(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("WAF rule pack {field} is invalid");
    }
    Ok(())
}

/// 业务作用：规范化规则包 target，拒绝模糊 wildcard 和非法 header 名扩大扫描范围。
///
/// 参数说明：
/// - `target`：是规则声明的位置。
///
/// 返回：固定 path/query/body/header 或精确小写 header target；非法值返回错误。
fn normalize_rule_pack_target(target: &str) -> Result<String> {
    if matches!(target, "path" | "query" | "body" | "header") {
        return Ok(target.to_owned());
    }
    let Some(name) = target.strip_prefix("header:") else {
        bail!("WAF rule pack target is unsupported");
    };
    if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("WAF rule pack header target must use a non-empty lowercase name");
    }
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid WAF rule pack header target"))?;
    Ok(format!("header:{name}"))
}

/// 业务作用：在候选构建检查点执行 wall-time 门禁，避免超预算规则包被发布。
///
/// 参数说明：
/// - `started`：是本轮起点
/// - `limit`：是 route 声明且受进程硬门约束的上限。
///
/// 返回：尚未超过上限时成功，超时返回错误并保留当前快照。
fn ensure_compile_deadline(started: Instant, limit: Duration) -> Result<()> {
    if started.elapsed() > limit {
        bail!("WAF rule pack compilation exceeded max_compile_ms");
    }
    Ok(())
}

/// 业务作用：收集规则包 source、signature 与 public key 的文件依赖，使独立替换进入统一热更新事务。
///
/// 参数说明：
/// - `config_dir`：是主配置目录
/// - `cfg`：是 route WAF 声明。
///
/// 返回：返回不含 secret 内容的本地依赖路径；未配置规则包或非文件 SecretSource 返回空集合。
pub(crate) fn dependency_paths(config_dir: &Path, cfg: &WafCfg) -> Vec<PathBuf> {
    let Some(pack) = &cfg.rule_pack else {
        return Vec::new();
    };
    let mut paths = Vec::with_capacity(3);
    if !pack.source.trim().is_empty() && !pack.source.contains("://") {
        let source = Path::new(pack.source.as_str());
        paths.push(if source.is_absolute() {
            source.to_path_buf()
        } else {
            config_dir.join(source)
        });
    }
    for value in [&pack.signature, &pack.public_key] {
        if let Some(path) = crate::security::secret::dependency_path(value, config_dir) {
            paths.push(path);
        }
    }
    paths
}

/// 业务作用：验证通用结构预算不为零且不超过进程硬上限。
///
/// 参数说明：
/// - `name`：用于构建期错误定位的配置键。
/// - `value`：配置值。
/// - `maximum`：进程允许的硬上限。
///
/// 返回：合法返回成功；为零或超限返回错误。
fn validate_structured_budget(name: &str, value: usize, maximum: usize) -> Result<()> {
    if !(1..=maximum).contains(&value) {
        bail!("{name} must be in 1..={maximum}");
    }
    Ok(())
}

/// 业务作用：验证并规范化 WAF 精确例外 target，拒绝通配符和大小写歧义。
///
/// 参数说明：
/// - `target`：是 route 配置中的例外 target。
///
/// 返回：合法 target 返回规范化字符串；非法 target 返回错误。
fn normalize_exclusion_target(target: &str) -> Result<String> {
    if matches!(target, "path" | "query" | "body" | "header:framing") {
        return Ok(target.to_owned());
    }
    let Some(name) = target.strip_prefix("header:") else {
        bail!(
            "exclusion target must be path, query, body, header:framing or header:<lowercase-name>"
        );
    };
    if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("header exclusion target must use a non-empty lowercase header name");
    }
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid header exclusion target `{target}`"))?;
    Ok(format!("header:{name}"))
}

/// 业务作用：构造不包含请求值的 WAF 命中记录。
///
/// 参数说明：
/// - `rule`：固定内置规则。
/// - `target`：固定或配置期有界 target。
///
/// 返回：可安全用于日志与固定结果指标的命中信息。
fn waf_match(rule: WafRule, target: String) -> WafMatch {
    WafMatch {
        rule: rule.id().to_owned(),
        target,
    }
}

/// 业务作用：把内置或外部规则身份转换为不含请求原值的命中记录。
///
/// 参数说明：
/// - `rule`：是候选构建期确定的规则身份
/// - `target`：是固定位置。
///
/// 返回：返回可安全写入低敏日志的有界规则 id 与 target。
fn waf_detected_match(rule: DetectedRule, target: String) -> WafMatch {
    match rule {
        DetectedRule::Builtin(rule) => waf_match(rule, target),
        DetectedRule::External(rule) => WafMatch {
            rule: rule.to_string(),
            target,
        },
    }
}

/// 业务作用：识别会覆盖方法或路由语义的客户端 header。
///
/// 参数说明：
/// - `name`：是入站 header 名。
///
/// 返回：命中固定危险 header 集合时返回 true。
fn is_dangerous_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "x-http-method-override" | "x-original-url" | "x-rewrite-url"
    )
}

/// 业务作用：检查重复 Content-Length 是否均为同一个有效十进制值。
///
/// 参数说明：
/// - `parts`：是当前请求 head。
///
/// 返回：语法无效、溢出或重复值不一致时返回 true。
fn invalid_content_lengths(parts: &Parts) -> bool {
    let mut expected = None;
    for value in parts.headers.get_all(CONTENT_LENGTH) {
        let Ok(value) = value.to_str() else {
            return true;
        };
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() || !item.bytes().all(|byte| byte.is_ascii_digit()) {
                return true;
            }
            let Ok(length) = item.parse::<u64>() else {
                return true;
            };
            match expected {
                Some(existing) if existing != length => return true,
                None => expected = Some(length),
                _ => {}
            }
        }
    }
    false
}

/// 业务作用：拒绝 Connection token 把 framing/authority 字段错误声明为逐跳字段。
///
/// 参数说明：
/// - `parts`：是当前请求 head。
///
/// 返回：Connection 引用了 Content-Length、Transfer-Encoding 或 Host 时返回 true。
fn connection_overrides_framing(parts: &Parts) -> bool {
    parts.headers.get(CONNECTION).is_some_and(|value| {
        value.to_str().ok().is_none_or(|value| {
            value.split(',').any(|token| {
                matches!(
                    token.trim().to_ascii_lowercase().as_str(),
                    "content-length" | "transfer-encoding" | "host"
                )
            })
        })
    })
}

/// 业务作用：把 URI percent 编码严格解码一次，保留一次解码后的安全检查语义。
///
/// 参数说明：
/// - `input`：是 path 或 query 原始字节。
///
/// 返回：所有 `%HH` 合法时返回解码字节；残缺或非十六进制 escape 返回错误。
fn percent_decode_once(input: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0_usize;
    while index < input.len() {
        if input[index] != b'%' {
            decoded.push(input[index]);
            index += 1;
            continue;
        }
        let high = input.get(index + 1).and_then(|byte| hex_value(*byte));
        let low = input.get(index + 2).and_then(|byte| hex_value(*byte));
        let (Some(high), Some(low)) = (high, low) else {
            return Err(());
        };
        decoded.push((high << 4) | low);
        index += 3;
    }
    Ok(decoded)
}

/// 业务作用：把单个 ASCII 十六进制字符转换为数值。
///
/// 参数说明：
/// - `byte`：是 percent escape 中的候选字符。
///
/// 返回：合法十六进制返回 0..=15；其它字节返回 `None`。
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 业务作用：识别一次解码后仍存在的 `%HH`，防止下游二次解码扩大语义。
///
/// 参数说明：
/// - `input`：是已经完成一次 percent 解码的字节。
///
/// 返回：仍包含完整 percent escape 时返回 true。
fn contains_percent_escape(input: &[u8]) -> bool {
    input.windows(3).any(|window| {
        window[0] == b'%' && hex_value(window[1]).is_some() && hex_value(window[2]).is_some()
    })
}

/// 业务作用：为 ASCII 规则匹配生成大小写无关表示，不对非 ASCII payload 做有损字符转换。
///
/// 参数说明：
/// - `input`：是有界待扫描值。
///
/// 返回：仅 ASCII 大写字母被转换为小写的同长度字节。
fn ascii_lowercase(input: &[u8]) -> Vec<u8> {
    input.iter().map(u8::to_ascii_lowercase).collect()
}

/// 业务作用：按固定规则执行保守的攻击特征匹配。
///
/// 参数说明：
/// - `rule`：待执行的固定规则。
/// - `value`：已转换为 ASCII 小写的有界值。
///
/// 返回：命中至少一个规则特征时返回 true；结构与协议规则返回 false。
fn signature_matches(rule: WafRule, value: &[u8]) -> bool {
    match rule {
        WafRule::SqlInjection => contains_any(
            value,
            &[
                b"union select",
                b"information_schema",
                b" or 1=1",
                b"' or '1'='1",
                b"\" or \"1\"=\"1",
                b"sleep(",
                b"benchmark(",
                b"pg_sleep(",
                b"waitfor delay",
                b"xp_cmdshell",
            ],
        ),
        WafRule::CrossSiteScripting => contains_any(
            value,
            &[
                b"<script",
                b"&lt;script",
                b"&#x3c;script",
                b"&#60;script",
                b"javascript:",
                b"onerror=",
                b"onload=",
                b"<svg",
            ],
        ),
        WafRule::CommandInjection => contains_any(
            value,
            &[
                b"$(", b"`/bin/", b";/bin/", b"|/bin/", b";cat ", b"|cat ", b";curl ", b"|curl ",
                b";wget ", b"|wget ",
            ],
        ),
        WafRule::TemplateInjection => {
            contains_any(value, &[b"{{", b"{%", b"${jndi:", b"${{", b"<#assign"])
        }
        WafRule::PathTraversal => contains_any(
            value,
            &[b"../", b"..\\", b"/etc/passwd", b"\\windows\\system32"],
        ),
        _ => false,
    }
}

/// 业务作用：在不构造正则状态机的前提下匹配少量固定 ASCII 特征。
///
/// 参数说明：
/// - `value`：已规范化的有界输入。
/// - `patterns`：编译期固定特征集合。
///
/// 返回：任一特征作为连续子串出现时返回 true。
fn contains_any(value: &[u8], patterns: &[&[u8]]) -> bool {
    patterns.iter().any(|pattern| {
        !pattern.is_empty()
            && value
                .windows(pattern.len())
                .any(|window| window == *pattern)
    })
}

/// 业务作用：从 Content-Type 识别唯一允许进入 body WAF 慢路径的结构化格式。
///
/// 参数说明：
/// - `parts`：是当前请求 head。
///
/// 返回：JSON/XML 返回固定分类；缺失、非 UTF-8 或其它 media type 返回 `None`。
fn structured_media_type(parts: &Parts) -> Option<StructuredMediaType> {
    let value = parts.headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let media_type = value.split(';').next()?.trim().to_ascii_lowercase();
    if media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    {
        Some(StructuredMediaType::Json)
    } else if media_type == "application/xml"
        || media_type == "text/xml"
        || (media_type.starts_with("application/") && media_type.ends_with("+xml"))
    {
        Some(StructuredMediaType::Xml)
    } else {
        None
    }
}

/// 业务作用：在读取请求体前利用可信解析后的 Content-Length 拒绝确定超限输入。
///
/// 参数说明：
/// - `parts`：当前请求 head。
/// - `limit`：route 显式 body 聚合上限。
///
/// 返回：任一声明长度超过上限或无法表示时返回 true。
fn declared_body_too_large(parts: &Parts, limit: u64) -> bool {
    parts.headers.get_all(CONTENT_LENGTH).iter().any(|value| {
        value.to_str().ok().is_none_or(|value| {
            value.split(',').any(|item| {
                item.trim()
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|length| length > limit)
            })
        })
    })
}

/// 业务作用：只允许 XML 预定义实体与数字字符引用，拒绝需要 DTD resolver 的自定义实体。
///
/// 参数说明：
/// - `reference`：位于 & 与 ; 之间的原始 XML 引用名。
///
/// 返回：预定义实体或合法十进制/十六进制字符引用返回 true。
fn is_predefined_or_numeric_entity(reference: &[u8]) -> bool {
    if matches!(reference, b"amp" | b"lt" | b"gt" | b"apos" | b"quot") {
        return true;
    }
    let Some(number) = reference.strip_prefix(b"#") else {
        return false;
    };
    if let Some(hex) = number
        .strip_prefix(b"x")
        .or_else(|| number.strip_prefix(b"X"))
    {
        !hex.is_empty() && hex.iter().all(|byte| byte.is_ascii_hexdigit())
    } else {
        !number.is_empty() && number.iter().all(|byte| byte.is_ascii_digit())
    }
}
