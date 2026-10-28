//! AI 内容分类规则与输出交付门。
//!
//! 本地规则是确定性检测，不替代语义模型。流式规则必须有可证明的最大匹配长度；
//! 对应文本尚可能参与后续命中时，承载它的完整 SSE event 不得交给下游。

mod semantic;
mod stream;

use anyhow::{ensure, Context, Result};
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;

pub(crate) use stream::{wrap_response, StreamGate};

/// 内容检测方向；响应规则同时约束非流式 JSON 与流式解码文本。
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

/// 低基数策略分类，不含 prompt、身份或命中原文。
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PromptInjection,
    Jailbreak,
    Pii,
    Secret,
    Content,
}

impl Category {
    /// 业务作用：把规则分类映射为固定观测标签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：与配置词表对应的固定分类，不输出规则或内容原文。
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::PromptInjection => "prompt_injection",
            Self::Jailbreak => "jailbreak",
            Self::Pii => "pii",
            Self::Secret => "secret",
            Self::Content => "content",
        }
    }
}

/// 一条内容阻断规则；三个检测来源必须且只能声明一个。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
    pub id: String,
    pub category: Category,
    pub directions: Vec<Direction>,
    #[serde(default)]
    pub contains: Option<String>,
    /// 正则必须有有限的最大匹配长度，不接受 `.*` 等无限匹配表达式。
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub detector: Option<DetectorCfg>,
}

/// 有限长度的常见敏感内容形态；只检测文本，不推断真实个人身份。
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorCfg {
    Email,
    Phone,
    NationalId,
    ApiKey,
    PrivateKey,
    Bearer,
}

/// 业务作用：为可选流式护栏提供默认延迟交付窗口。
///
/// 参数说明: 无。
///
/// 返回：4096 字节解码文本；未启用输出规则时不分配该窗口。
pub const fn default_window_bytes() -> usize {
    4096
}

struct Rule {
    category: Category,
    directions: Vec<Direction>,
    matcher: Regex,
    maximum_bytes: usize,
}

/// 构建期冻结的规则集合与流式安全窗口。
#[derive(PartialEq, Eq)]
pub(crate) struct Plan {
    rules: Vec<Rule>,
    window_bytes: usize,
}

impl Plan {
    /// 业务作用：为只配置外部裁决的流保留统一协议与窗口门，不添加本地文本规则。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空本地策略；外部执行器仍负责持续授权和内容判定。
    pub(crate) fn empty() -> Arc<Self> {
        Arc::new(Self {
            rules: Vec::new(),
            window_bytes: 0,
        })
    }
    /// 业务作用：编译结构化规则和兼容输出短语，证明响应窗口足以覆盖任何一次匹配。
    ///
    /// 参数说明：
    /// - `rules`：是分类策略
    /// - `legacy_response`：是既有输出短语
    /// - `window_bytes`：是解码文本保留量。
    ///
    /// 返回：有效策略返回不可变计划；重复 ID、无限匹配、空匹配或容量不足拒绝整个候选。
    pub(crate) fn build(
        rules: &[RuleCfg],
        legacy_response: &[String],
        window_bytes: usize,
    ) -> Result<Option<Arc<Self>>> {
        if rules.is_empty() && legacy_response.is_empty() {
            return Ok(None);
        }
        ensure!(
            rules.len() <= 64 && legacy_response.len() <= 64,
            "too many AI guardrail rules"
        );
        ensure!(
            (64..=65536).contains(&window_bytes),
            "AI stream_window_bytes must be within 64..=65536"
        );
        let mut ids = HashSet::new();
        let mut compiled = Vec::new();
        for rule in rules {
            ensure!(
                !rule.id.is_empty()
                    && rule.id.len() <= 64
                    && rule
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    && ids.insert(&rule.id),
                "AI rule id is invalid or duplicated"
            );
            ensure!(
                !rule.directions.is_empty()
                    && rule.directions.len() <= 2
                    && (rule.directions.len() != 2 || rule.directions[0] != rule.directions[1]),
                "AI rule directions must be nonempty and unique"
            );
            ensure!(
                usize::from(rule.contains.is_some())
                    + usize::from(rule.regex.is_some())
                    + usize::from(rule.detector.is_some())
                    == 1,
                "AI rule requires one detector"
            );
            let pattern = match (&rule.contains, &rule.regex, rule.detector) {
                (Some(value), _, _) => {
                    ensure!(
                        !value.is_empty() && value.len() <= 256,
                        "AI contains rule exceeds limit"
                    );
                    regex::escape(value)
                }
                (_, Some(value), _) => {
                    ensure!(value.len() <= 2048, "AI regex exceeds limit");
                    value.clone()
                }
                (_, _, Some(value)) => builtin(value).to_owned(),
                _ => unreachable!("exactly one detector was checked"),
            };
            compiled.push(compile_rule(
                &pattern,
                rule.category,
                rule.directions.clone(),
                window_bytes,
            )?);
        }
        for pattern in legacy_response {
            compiled.push(compile_rule(
                &regex::escape(pattern),
                Category::Content,
                vec![Direction::Response],
                window_bytes,
            )?);
        }
        let required_window = compiled
            .iter()
            .filter(|rule| rule.directions.contains(&Direction::Response))
            .map(|rule| rule.maximum_bytes.saturating_add(4))
            .max()
            .unwrap_or(0);
        Ok(Some(Arc::new(Self {
            rules: compiled,
            window_bytes: required_window.min(window_bytes),
        })))
    }

    /// 业务作用：识别当前方向是否需要内容扫描或延迟交付。
    ///
    /// 参数说明：
    /// - `direction`：是请求或响应方向。
    ///
    /// 返回：该方向存在规则时为 true；否则不接管 body 生命周期。
    pub(crate) fn enabled(&self, direction: Direction) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.directions.contains(&direction))
    }

    /// 业务作用：扫描已解码的文本，不把 JSON 转义形式误当成安全内容。
    ///
    /// 参数说明：
    /// - `direction`：是策略相位
    /// - `text`：是当前有界窗口或实体中的文本。
    ///
    /// 返回：首个命中的固定分类；未命中返回 None，不返回敏感片段。
    pub(crate) fn classify(&self, direction: Direction, text: &str) -> Option<Category> {
        self.rules
            .iter()
            .find(|rule| {
                rule.directions.contains(&direction) && rule.matcher.is_match(text.as_bytes())
            })
            .map(|rule| rule.category)
    }

    /// 业务作用：对 JSON 的每个文本值与字段名执行同代内容策略，覆盖工具参数和结构化输出。
    ///
    /// 参数说明：
    /// - `direction`：是策略相位
    /// - `value`：是已经受 body 大小限制的 JSON。
    ///
    /// 返回：命中时返回固定分类；所有字段通过时返回 None。
    pub(crate) fn inspect_json(&self, direction: Direction, value: &Value) -> Option<Category> {
        match value {
            Value::String(text) => self.classify(direction, text),
            Value::Array(values) => values
                .iter()
                .find_map(|value| self.inspect_json(direction, value)),
            Value::Object(values) => values.iter().find_map(|(key, value)| {
                self.classify(direction, key)
                    .or_else(|| self.inspect_json(direction, value))
            }),
            Value::Number(value) => self.classify(direction, &value.to_string()),
            _ => None,
        }
    }
}

/// 业务作用：为常见敏感形态提供有限长度的文本检测表达式。
///
/// 参数说明：
/// - `detector`：是配置显式选择的固定检测类型。
///
/// 返回：长度可证明有界的表达式；前缀足以识别凭据时不等待完整秘密到达。
fn builtin(detector: DetectorCfg) -> &'static str {
    match detector {
        DetectorCfg::Email => {
            r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,3}"
        }
        DetectorCfg::Phone => r"\+[0-9][0-9 ()-]{8,24}[0-9]",
        DetectorCfg::NationalId => r"[0-9]{3}-[0-9]{2}-[0-9]{4}",
        DetectorCfg::ApiKey => r"(?:sk-[a-z0-9_-]{16}|gh[pousr]_[a-z0-9]{16}|AKIA[0-9A-Z]{16})",
        DetectorCfg::PrivateKey => r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        DetectorCfg::Bearer => r"(?:bearer|basic)[ \t]{1,8}[a-z0-9._~+/-]{8}",
    }
}

/// 业务作用：证明检测规则的有限前瞻长度，再构造有界正则执行器。
///
/// 参数说明：
/// - `pattern`：是受限表达式
/// - `category`：定义裁决含义
/// - `directions`：定义裁决含义
/// - `window`：是延迟发送量。
///
/// 返回：成功返回编译规则；无法证明长度或表达式无效时拒绝，避免先泄露匹配前缀再阻断。
fn compile_rule(
    pattern: &str,
    category: Category,
    directions: Vec<Direction>,
    window: usize,
) -> Result<Rule> {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .unicode(false)
        .case_insensitive(true)
        .build()
        .parse(pattern)
        .context("invalid AI detector expression")?;
    let maximum = hir
        .properties()
        .maximum_len()
        .context("AI detector must have finite match length")?;
    ensure!(
        maximum > 0 && hir.properties().minimum_len().unwrap_or(0) > 0,
        "AI detector must not match empty text"
    );
    // 输出规则不能依赖窗口之外的未来字节；即使所有 chunk 很小也必须保留完整潜在命中。
    ensure!(
        !directions.contains(&Direction::Response) || maximum.saturating_add(4) <= window,
        "AI output detector exceeds stream window"
    );
    let matcher = RegexBuilder::new(pattern)
        .unicode(false)
        .case_insensitive(true)
        .size_limit(256 * 1024)
        .dfa_size_limit(512 * 1024)
        .build()
        .context("invalid AI detector")?;
    Ok(Rule {
        category,
        directions,
        matcher,
        maximum_bytes: maximum,
    })
}
