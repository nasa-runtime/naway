//! route 级 Bot 识别与挑战策略。
//!
//! 请求判断只使用已编译 glob、固定 header 集合、构建期解析的签名 secret 和共享有界限流器；
//! 原始 User-Agent、header、IP 与指纹均不进入日志或指标。

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use hmac::{Hmac, Mac};
use http::header::{HeaderName, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, HOST, USER_AGENT};
use http::request::Parts;
use sha2::{Digest, Sha256};

use crate::config::model::{BotCfg, BotRateCfg, TrustedSearchBotCfg};

const MAX_USER_AGENT_BYTES: usize = 4096;
const MAX_GLOB_RULES: usize = 256;
const MAX_GLOB_BYTES: usize = 512;
const MAX_HEADER_RULES: usize = 64;
const MAX_TRUSTED_BOTS: usize = 32;
const MAX_SIGNATURE_SKEW_SECS: u64 = 15 * 60;
const MAX_RATE_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_RATE_LIMIT: u64 = 10_000_000;
const MIN_SIGNATURE_SECRET_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Bot 数据面的固定低基数决策。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BotDecision {
    /// 策略允许普通客户端。
    Allowed,
    /// 搜索机器人声明通过逐请求 HMAC 复验。
    Trusted,
    /// User-Agent allow/deny 规则拒绝。
    UserAgentDenied,
    /// 稳定客户端指纹命中 denylist。
    FingerprintDenied,
    /// 可组合行为信号达到挑战门槛。
    BehaviorDenied,
    /// 客户端声称可信搜索机器人但签名复验失败。
    TrustedClaimInvalid,
    /// 有界 RateLimiter 拒绝当前客户端指纹。
    RateDenied,
}

impl BotDecision {
    /// 业务作用：判断固定决策是否需要挑战或阻断请求。
    ///
    /// 参数说明：无。
    ///
    /// 返回：普通允许与签名可信返回 false，其余决策返回 true。
    pub(crate) const fn denied(self) -> bool {
        !matches!(self, Self::Allowed | Self::Trusted)
    }

    /// 业务作用：为日志和固定基数指标提供不含客户端输入的稳定原因。
    ///
    /// 参数说明：无。
    ///
    /// 返回：返回编译期固定原因字符串。
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Trusted => "trusted",
            Self::UserAgentDenied => "user_agent",
            Self::FingerprintDenied => "fingerprint",
            Self::BehaviorDenied => "behavior",
            Self::TrustedClaimInvalid => "trusted_claim_invalid",
            Self::RateDenied => "rate",
        }
    }
}

/// 已编译的 Bot 速率信号。
pub(crate) struct BotRatePolicy {
    /// 窗口内基础令牌数。
    pub(crate) limit: u64,
    /// 固定统计窗口。
    pub(crate) window: Duration,
    /// 基础额度外的突发容量。
    pub(crate) burst: u64,
    /// 允许维护的最大活动指纹数。
    pub(crate) max_active_keys: usize,
    /// 活动表耗尽时是否显式 fail-open。
    pub(crate) active_keys_fail_open: bool,
}

/// 快照内不可变的 route Bot 策略。
pub(crate) struct BotPolicy {
    monitor: bool,
    allowed_user_agents: Option<GlobSet>,
    denied_user_agents: Option<GlobSet>,
    required_headers: Vec<HeaderName>,
    automation_headers: Vec<HeaderName>,
    fingerprint_headers: Vec<HeaderName>,
    denied_fingerprints: HashSet<[u8; 32]>,
    missing_user_agent_score: u32,
    browser_header_mismatch_score: u32,
    automation_header_score: u32,
    score_threshold: u32,
    trusted_search_bots: Vec<TrustedSearchBot>,
    /// 共享 RateLimiter 使用的有界规则；不存在时不维护客户端状态。
    pub(crate) rate: Option<BotRatePolicy>,
    /// 普通挑战使用的 4xx 状态码。
    pub(crate) challenge_status: u16,
    /// 固定、已验证的 `WWW-Authenticate` 值。
    pub(crate) challenge_header: HeaderValue,
}

impl BotPolicy {
    /// 业务作用：编译 route Bot 策略，冻结匹配器、header、指纹、签名 secret 与资源边界。
    ///
    /// 参数说明：`cfg` 是 route Bot 声明；`config_dir` 是 SecretSource 相对路径基准。
    ///
    /// 返回：全部规则无冲突且资源有界时返回不可变策略；未知模式、弱 secret、非法 header、
    /// glob 或预算会拒绝候选快照。
    pub(crate) fn build(cfg: &BotCfg, config_dir: &Path) -> Result<Self> {
        let monitor = match cfg.mode.as_str() {
            "enforce" => false,
            "monitor" => true,
            value => bail!("bot.mode must be `enforce` or `monitor`, got `{value}`"),
        };
        if cfg.score_threshold == 0 {
            bail!("bot.score_threshold must be greater than zero");
        }
        if cfg.missing_user_agent_score == 0
            && cfg.browser_header_mismatch_score == 0
            && cfg.automation_header_score == 0
            && cfg.allowed_user_agents.is_empty()
            && cfg.denied_user_agents.is_empty()
            && cfg.required_headers.is_empty()
            && cfg.denied_fingerprints.is_empty()
            && cfg.trusted_search_bots.is_empty()
            && cfg.rate.is_none()
        {
            bail!("bot policy must enable at least one matching, behavior, trust or rate signal");
        }
        let allowed_user_agents = build_globs(
            "bot.allowed_user_agents",
            cfg.allowed_user_agents.as_slice(),
        )?;
        let denied_user_agents =
            build_globs("bot.denied_user_agents", cfg.denied_user_agents.as_slice())?;
        reject_exact_overlap(
            "bot User-Agent",
            cfg.allowed_user_agents.as_slice(),
            cfg.denied_user_agents.as_slice(),
        )?;
        let required_headers =
            parse_headers("bot.required_headers", cfg.required_headers.as_slice())?;
        let automation_headers =
            parse_headers("bot.automation_headers", cfg.automation_headers.as_slice())?;
        let fingerprint_headers = parse_headers(
            "bot.fingerprint_headers",
            cfg.fingerprint_headers.as_slice(),
        )?;
        let denied_fingerprints = parse_fingerprints(cfg.denied_fingerprints.as_slice())?;
        let trusted_search_bots =
            build_trusted_bots(cfg.trusted_search_bots.as_slice(), config_dir)?;
        let rate = cfg.rate.as_ref().map(build_rate).transpose()?;
        if !(400..=499).contains(&cfg.challenge_status) || cfg.challenge_status == 429 {
            bail!("bot.challenge_status must be a 4xx status other than 429");
        }
        if cfg.challenge_realm.is_empty()
            || cfg.challenge_realm.len() > 64
            || !cfg
                .challenge_realm
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("bot.challenge_realm must be a 1..=64 byte ASCII token");
        }
        let challenge_header =
            HeaderValue::from_str(format!("NawayBot realm=\"{}\"", cfg.challenge_realm).as_str())
                .context("build bot challenge header")?;

        Ok(Self {
            monitor,
            allowed_user_agents,
            denied_user_agents,
            required_headers,
            automation_headers,
            fingerprint_headers,
            denied_fingerprints,
            missing_user_agent_score: cfg.missing_user_agent_score,
            browser_header_mismatch_score: cfg.browser_header_mismatch_score,
            automation_header_score: cfg.automation_header_score,
            score_threshold: cfg.score_threshold,
            trusted_search_bots,
            rate,
            challenge_status: cfg.challenge_status,
            challenge_header,
        })
    }

    /// 业务作用：在认证、插件和上游副作用前组合 User-Agent、header、指纹、行为与签名信号。
    ///
    /// 参数说明：`parts` 是当前请求 head；`client_ip` 是 trusted-proxy 规则确定的权威地址。
    ///
    /// 返回：返回固定允许、可信或挑战原因；任何可信机器人声明只有逐请求签名通过后才可信。
    pub(crate) fn evaluate_head(&self, parts: &Parts, client_ip: IpAddr) -> BotDecision {
        let user_agent = strict_text_header(&parts.headers, &USER_AGENT)
            .filter(|value| value.len() <= MAX_USER_AGENT_BYTES);
        let user_agent_value = user_agent.unwrap_or("");

        let mut claimed_trusted = false;
        for trusted in &self.trusted_search_bots {
            let claims_identity = user_agent
                .is_some_and(|value| trusted.user_agents.is_match(value))
                || (user_agent.is_none()
                    && parts.headers.get_all(&USER_AGENT).iter().any(|value| {
                        value
                            .to_str()
                            .is_ok_and(|value| trusted.user_agents.is_match(value))
                    }));
            if claims_identity {
                claimed_trusted = true;
                if user_agent.is_some_and(|value| trusted.verify(parts, client_ip, value)) {
                    return BotDecision::Trusted;
                }
            }
        }
        if claimed_trusted {
            return BotDecision::TrustedClaimInvalid;
        }

        if self
            .allowed_user_agents
            .as_ref()
            .is_some_and(|allowed| !allowed.is_match(user_agent_value))
            || self
                .denied_user_agents
                .as_ref()
                .is_some_and(|denied| denied.is_match(user_agent_value))
        {
            return BotDecision::UserAgentDenied;
        }
        if self
            .required_headers
            .iter()
            .any(|name| strict_text_header(&parts.headers, name).is_none())
        {
            return BotDecision::BehaviorDenied;
        }

        let fingerprint = self.fingerprint(parts, None);
        if self.denied_fingerprints.contains(&fingerprint) {
            return BotDecision::FingerprintDenied;
        }

        let mut score = 0_u32;
        if user_agent.is_none() || user_agent_value.is_empty() {
            score = score.saturating_add(self.missing_user_agent_score);
        }
        let browser_claim = user_agent_value.to_ascii_lowercase().contains("mozilla/");
        if browser_claim
            && (strict_text_header(&parts.headers, &ACCEPT).is_none()
                || strict_text_header(&parts.headers, &ACCEPT_LANGUAGE).is_none())
        {
            score = score.saturating_add(self.browser_header_mismatch_score);
        }
        for header in &self.automation_headers {
            if parts.headers.contains_key(header) {
                score = score.saturating_add(self.automation_header_score);
            }
        }
        if score >= self.score_threshold {
            BotDecision::BehaviorDenied
        } else {
            BotDecision::Allowed
        }
    }

    /// 业务作用：生成不暴露 IP 或 header 原值的稳定限流维度键。
    ///
    /// 参数说明：`parts` 是请求 head；`client_ip` 是权威客户端地址。
    ///
    /// 返回：返回当前策略字段与客户端 IP 的 SHA-256 前 64 位十六进制值。
    pub(crate) fn rate_key(&self, parts: &Parts, client_ip: IpAddr) -> String {
        let fingerprint = self.fingerprint(parts, Some(client_ip));
        let prefix = u64::from_be_bytes(
            fingerprint[..8]
                .try_into()
                .expect("SHA-256 digest prefix has eight bytes"),
        );
        format!("{prefix:016x}")
    }

    /// 业务作用：判断命中是否只观测而不改变业务请求。
    ///
    /// 参数说明：无。
    ///
    /// 返回：配置为 `monitor` 时返回 true。
    pub(crate) const fn monitor(&self) -> bool {
        self.monitor
    }

    /// 业务作用：返回速率挑战的 `Retry-After` 秒数，避免客户端立即重试放大压力。
    ///
    /// 参数说明：无。
    ///
    /// 返回：配置速率信号时返回向上取整且至少为一秒的窗口；未配置返回一秒。
    pub(crate) fn retry_after_secs(&self) -> u64 {
        self.rate
            .as_ref()
            .map(|rate| rate.window.as_secs().max(1))
            .unwrap_or(1)
    }

    /// 业务作用：按已验证字段顺序计算稳定 SHA-256 指纹，避免拼接歧义和原值外泄。
    ///
    /// 参数说明：`parts` 是请求 head；`client_ip` 仅在限流维度需要按地址隔离时提供。
    ///
    /// 返回：返回固定 32 字节摘要。
    fn fingerprint(&self, parts: &Parts, client_ip: Option<IpAddr>) -> [u8; 32] {
        let mut digest = Sha256::new();
        update_component(
            &mut digest,
            USER_AGENT.as_str().as_bytes(),
            parts
                .headers
                .get_all(&USER_AGENT)
                .iter()
                .map(HeaderValue::as_bytes),
        );
        for name in &self.fingerprint_headers {
            update_component(
                &mut digest,
                name.as_str().as_bytes(),
                parts
                    .headers
                    .get_all(name)
                    .iter()
                    .map(HeaderValue::as_bytes),
            );
        }
        if let Some(client_ip) = client_ip {
            update_component(
                &mut digest,
                b"client-ip",
                std::iter::once(client_ip.to_string()).map(String::into_bytes),
            );
        }
        digest.finalize().into()
    }
}

/// 已编译的单个可信搜索机器人签名规则。
struct TrustedSearchBot {
    user_agents: GlobSet,
    signature_secret: Vec<u8>,
    signature_header: HeaderName,
    timestamp_header: HeaderName,
    max_clock_skew: Duration,
}

impl TrustedSearchBot {
    /// 业务作用：复验可信搜索机器人逐请求签名，阻止只伪造 User-Agent 获得豁免。
    ///
    /// 参数说明：`parts` 是请求 head；`client_ip` 是权威地址；`user_agent` 已经过单值 UTF-8 校验。
    ///
    /// 返回：时间戳新鲜、header 单值、Base64URL 合法且 HMAC 覆盖地址、方法、authority、
    /// URI 与 User-Agent 时返回 true；任何异常返回 false。
    fn verify(&self, parts: &Parts, client_ip: IpAddr, user_agent: &str) -> bool {
        let Some(timestamp) = strict_text_header(&parts.headers, &self.timestamp_header)
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return false;
        };
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        if now.as_secs().abs_diff(timestamp) > self.max_clock_skew.as_secs() {
            return false;
        }
        let Some(signature) = strict_text_header(&parts.headers, &self.signature_header)
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        else {
            return false;
        };
        let mut verifier = match HmacSha256::new_from_slice(self.signature_secret.as_slice()) {
            Ok(verifier) => verifier,
            Err(_) => return false,
        };
        verifier.update(timestamp.to_string().as_bytes());
        verifier.update(b"\n");
        verifier.update(client_ip.to_string().as_bytes());
        verifier.update(b"\n");
        verifier.update(parts.method.as_str().as_bytes());
        verifier.update(b"\n");
        let authority = parts
            .uri
            .authority()
            .map(|value| value.as_str())
            .or_else(|| strict_text_header(&parts.headers, &HOST))
            .unwrap_or("");
        verifier.update(authority.as_bytes());
        verifier.update(b"\n");
        verifier.update(
            parts
                .uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/")
                .as_bytes(),
        );
        verifier.update(b"\n");
        verifier.update(user_agent.as_bytes());
        verifier.verify_slice(signature.as_slice()).is_ok()
    }
}

/// 业务作用：编译大小写不敏感的 User-Agent glob 集合，并约束规则数量与单值长度。
///
/// 参数说明：`field` 用于错误定位；`patterns` 是配置的 glob 列表。
///
/// 返回：空列表返回 `None`；全部 glob 合法且不重复时返回集合，否则拒绝候选。
fn build_globs(field: &str, patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    if patterns.len() > MAX_GLOB_RULES {
        bail!("{field} supports at most {MAX_GLOB_RULES} entries");
    }
    let mut seen = HashSet::with_capacity(patterns.len());
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if pattern.is_empty() || pattern.len() > MAX_GLOB_BYTES {
            bail!("{field} entries must be in 1..={MAX_GLOB_BYTES} bytes");
        }
        let identity = pattern.to_ascii_lowercase();
        if !seen.insert(identity) {
            bail!("{field} contains a duplicate glob");
        }
        builder.add(
            GlobBuilder::new(pattern)
                .case_insensitive(true)
                .literal_separator(false)
                .backslash_escape(true)
                .build()
                .with_context(|| format!("compile {field} glob"))?,
        );
    }
    Ok(Some(
        builder
            .build()
            .with_context(|| format!("build {field} glob set"))?,
    ))
}

/// 业务作用：拒绝 allow/deny 中完全相同的 User-Agent glob，避免处置优先级依赖实现细节。
///
/// 参数说明：`field` 用于错误定位；`allowed` 与 `denied` 是配置原值。
///
/// 返回：无精确冲突返回成功；忽略大小写后存在同值返回错误。
fn reject_exact_overlap(field: &str, allowed: &[String], denied: &[String]) -> Result<()> {
    let denied = denied
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if allowed
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .any(|value| denied.contains(&value))
    {
        bail!("{field} allowlist and denylist contain the same glob");
    }
    Ok(())
}

/// 业务作用：把配置 header 名编译为无重复的标准 HeaderName，拒绝歧义和过量字段。
///
/// 参数说明：`field` 用于错误定位；`values` 是配置 header 名。
///
/// 返回：全部名称合法且不重复时返回固定列表；否则返回错误。
fn parse_headers(field: &str, values: &[String]) -> Result<Vec<HeaderName>> {
    if values.len() > MAX_HEADER_RULES {
        bail!("{field} supports at most {MAX_HEADER_RULES} entries");
    }
    let mut seen = HashSet::with_capacity(values.len());
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let name = HeaderName::from_bytes(value.as_bytes())
            .with_context(|| format!("{field} contains invalid header name"))?;
        if !seen.insert(name.clone()) {
            bail!("{field} contains a duplicate header name");
        }
        output.push(name);
    }
    Ok(output)
}

/// 业务作用：解析指纹 denylist，并拒绝非规范十六进制和重复摘要。
///
/// 参数说明：`values` 是配置的 SHA-256 小写十六进制字符串。
///
/// 返回：全部摘要合法且唯一时返回固定集合；否则返回错误。
fn parse_fingerprints(values: &[String]) -> Result<HashSet<[u8; 32]>> {
    if values.len() > MAX_GLOB_RULES {
        bail!("bot.denied_fingerprints supports at most {MAX_GLOB_RULES} entries");
    }
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("bot.denied_fingerprints must contain lowercase SHA-256 hex");
        }
        let mut decoded = [0_u8; 32];
        for (index, slot) in decoded.iter_mut().enumerate() {
            let offset = index * 2;
            *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
                .context("decode bot denied fingerprint")?;
        }
        if !output.insert(decoded) {
            bail!("bot.denied_fingerprints contains a duplicate digest");
        }
    }
    Ok(output)
}

/// 业务作用：编译可信搜索机器人声明并在候选发布前解析签名 SecretSource。
///
/// 参数说明：`configs` 是声明列表；`config_dir` 是 SecretSource 路径基准。
///
/// 返回：名称、glob、header、时间窗和 secret 均合法时返回固定计划，否则拒绝候选。
fn build_trusted_bots(
    configs: &[TrustedSearchBotCfg],
    config_dir: &Path,
) -> Result<Vec<TrustedSearchBot>> {
    if configs.len() > MAX_TRUSTED_BOTS {
        bail!("bot.trusted_search_bots supports at most {MAX_TRUSTED_BOTS} entries");
    }
    let mut names = HashSet::with_capacity(configs.len());
    let mut output = Vec::with_capacity(configs.len());
    for config in configs {
        if config.name.is_empty()
            || config.name.len() > 64
            || !config
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("trusted search bot name must be a 1..=64 byte ASCII token");
        }
        if !names.insert(config.name.clone()) {
            bail!("duplicate trusted search bot name `{}`", config.name);
        }
        let Some(user_agents) = build_globs(
            "bot.trusted_search_bots.user_agents",
            config.user_agents.as_slice(),
        )?
        else {
            bail!("trusted search bot `{}` requires user_agents", config.name);
        };
        if !(1..=MAX_SIGNATURE_SKEW_SECS).contains(&config.max_clock_skew_secs) {
            bail!(
                "trusted search bot `{}` max_clock_skew_secs must be in 1..={MAX_SIGNATURE_SKEW_SECS}",
                config.name
            );
        }
        let secret = crate::secret::resolve_text(
            config.signature_secret.as_str(),
            config_dir,
            "bot trusted search signature",
        )?;
        if secret.len() < MIN_SIGNATURE_SECRET_BYTES {
            bail!(
                "trusted search bot `{}` signature_secret must be at least {MIN_SIGNATURE_SECRET_BYTES} bytes",
                config.name
            );
        }
        let signature_header = HeaderName::from_bytes(config.signature_header.as_bytes())
            .context("trusted search bot signature_header is invalid")?;
        let timestamp_header = HeaderName::from_bytes(config.timestamp_header.as_bytes())
            .context("trusted search bot timestamp_header is invalid")?;
        if signature_header == timestamp_header {
            bail!("trusted search bot signature and timestamp headers must differ");
        }
        output.push(TrustedSearchBot {
            user_agents,
            signature_secret: secret.into_bytes(),
            signature_header,
            timestamp_header,
            max_clock_skew: Duration::from_secs(config.max_clock_skew_secs),
        });
    }
    Ok(output)
}

/// 业务作用：编译 Bot 速率信号并约束令牌、窗口和活动维度资源。
///
/// 参数说明：`cfg` 是 route 速率声明。
///
/// 返回：全部边界合法时返回固定规则，否则拒绝候选。
fn build_rate(cfg: &BotRateCfg) -> Result<BotRatePolicy> {
    if !(1..=MAX_RATE_LIMIT).contains(&cfg.limit) {
        bail!("bot.rate.limit must be in 1..={MAX_RATE_LIMIT}");
    }
    if !(1..=MAX_RATE_WINDOW_MS).contains(&cfg.window_ms) {
        bail!("bot.rate.window_ms must be in 1..={MAX_RATE_WINDOW_MS}");
    }
    if cfg.burst > MAX_RATE_LIMIT {
        bail!("bot.rate.burst must be at most {MAX_RATE_LIMIT}");
    }
    if cfg.max_active_keys == 0 || cfg.max_active_keys > 1_000_000 {
        bail!("bot.rate.max_active_keys must be in 1..=1000000");
    }
    Ok(BotRatePolicy {
        limit: cfg.limit,
        window: Duration::from_millis(cfg.window_ms),
        burst: cfg.burst,
        max_active_keys: cfg.max_active_keys,
        active_keys_fail_open: cfg.active_keys_fail_open,
    })
}

/// 业务作用：读取严格单值 UTF-8 header，防止重复值拼接改变签名、身份或行为语义。
///
/// 参数说明：`headers` 是请求 header；`name` 是已验证名称。
///
/// 返回：恰有一个非空 UTF-8 值时返回该值；缺失、重复、空值或非法编码返回 `None`。
fn strict_text_header<'a>(headers: &'a http::HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok().filter(|value| !value.is_empty())
}

/// 业务作用：以长度前缀向 SHA-256 写入 header 名和值序列，避免不同字段组合产生拼接碰撞。
///
/// 参数说明：`digest` 是当前摘要；`name` 是字段名；`values` 是一个或多个原始字节值。
///
/// 返回：无；仅更新调用方摘要状态。
fn update_component<T, I>(digest: &mut Sha256, name: &[u8], values: I)
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item = T>,
{
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name);
    for value in values {
        let value = value.as_ref();
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(0_u64.to_be_bytes());
}
