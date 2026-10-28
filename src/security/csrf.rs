//! route 级浏览器 CSRF 来源与 token 门禁。
//!
//! 策略只读取请求 head，不读取或复制 body。token 原值、cookie、Origin 与 Referer 不进入日志或指标。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use http::header::{
    HeaderName, HeaderValue, AUTHORIZATION, CONTENT_LENGTH, COOKIE, HOST, ORIGIN, REFERER,
    SET_COOKIE,
};
use http::request::Parts;
use http::{HeaderMap, Method, StatusCode, Uri};
use sha2::Sha256;

use crate::config::model::CsrfCfg;
use crate::security::auth::constant_time_eq;

const MAX_METHODS: usize = 16;
const MAX_ALLOWED_ORIGINS: usize = 64;
const MAX_TOKEN_BYTES: usize = 512;
const TOKEN_NONCE_BYTES: usize = 32;
const MIN_SIGNING_SECRET_BYTES: usize = 32;
const MAX_TOKEN_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_FUTURE_SKEW_SECS: u64 = 60;

type HmacSha256 = Hmac<Sha256>;

/// CSRF 数据面的固定低基数决策。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CsrfDecision {
    /// 当前方法不受 CSRF 策略保护。
    SafeMethod,
    /// 来源与 token 均验证通过。
    Allowed,
    /// Origin/Referer 缺失、非法或不在 allowlist。
    OriginDenied,
    /// token header 或 cookie 缺失。
    TokenMissing,
    /// token 重复、格式错误、不相等、过期或签名无效。
    TokenInvalid,
}

impl CsrfDecision {
    /// 业务作用：判断固定 CSRF 决策是否应阻断状态变更请求。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：来源或 token 失败返回 true；安全方法与验证通过返回 false。
    pub(crate) const fn denied(self) -> bool {
        matches!(
            self,
            Self::OriginDenied | Self::TokenMissing | Self::TokenInvalid
        )
    }

    /// 业务作用：为低敏日志提供不含来源、cookie 或 token 的固定原因。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回编译期固定原因字符串。
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::SafeMethod => "safe_method",
            Self::Allowed => "allowed",
            Self::OriginDenied => "origin",
            Self::TokenMissing => "token_missing",
            Self::TokenInvalid => "token_invalid",
        }
    }
}

/// CSRF token 的固定验证方式。
#[derive(PartialEq, Eq)]
enum TokenMode {
    /// header 与 host-only cookie 携带相同随机 token。
    DoubleSubmit,
    /// header 与 cookie 携带相同、由网关 HMAC 签名的有时效 token。
    Signed {
        secret: Vec<u8>,
    },
}

/// 快照内不可变的 route CSRF 策略。
#[derive(PartialEq, Eq)]
pub(crate) struct CsrfPolicy {
    monitor: bool,
    methods: HashSet<Method>,
    same_origin: bool,
    allowed_origins: HashSet<String>,
    allow_referer_fallback: bool,
    allow_missing_origin: bool,
    mode: TokenMode,
    cookie_name: String,
    header_name: HeaderName,
    token_ttl_secs: u64,
    issue_on_safe_methods: bool,
}

impl CsrfPolicy {
    /// 业务作用：编译 CSRF 来源与 token 契约，并在快照发布前解析可选签名 SecretSource。
    ///
    /// 参数说明：
    /// - `cfg`：是 route CSRF 声明
    /// - `config_dir`：是 SecretSource 相对路径基准。
    ///
    /// 返回：方法、origin、cookie/header、token 模式和时效均合法时返回不可变策略；
    /// 弱 secret、歧义来源或危险 header 配置会拒绝候选。
    pub(crate) fn build(cfg: &CsrfCfg, config_dir: &Path) -> Result<Self> {
        let monitor = match cfg.mode.as_str() {
            "enforce" => false,
            "monitor" => true,
            value => bail!("csrf.mode must be `enforce` or `monitor`, got `{value}`"),
        };
        let methods = parse_methods(cfg.methods.as_slice())?;
        let (same_origin, allowed_origins) = parse_allowed_origins(cfg.allowed_origins.as_slice())?;
        if !cfg.allow_missing_origin && !same_origin && allowed_origins.is_empty() {
            bail!("csrf.allowed_origins cannot be empty unless allow_missing_origin is true");
        }
        if !cfg.cookie_name.starts_with("__Host-")
            || cfg.cookie_name.len() > 64
            || !cfg.cookie_name.bytes().all(is_cookie_name_byte)
        {
            bail!("csrf.cookie_name must be a <=64 byte token with the `__Host-` prefix");
        }
        let header_name = HeaderName::from_bytes(cfg.header_name.as_bytes())
            .context("csrf.header_name is invalid")?;
        if matches!(
            header_name,
            COOKIE | HOST | AUTHORIZATION | CONTENT_LENGTH | ORIGIN | REFERER
        ) {
            bail!("csrf.header_name cannot reuse a routing, credential, framing or origin header");
        }
        if !(1..=MAX_TOKEN_TTL_SECS).contains(&cfg.token_ttl_secs) {
            bail!("csrf.token_ttl_secs must be in 1..={MAX_TOKEN_TTL_SECS}");
        }
        let mode = match cfg.token_mode.as_str() {
            "double_submit" => {
                if !cfg.token_secret.is_empty() {
                    bail!("csrf.token_secret must be empty in double_submit mode");
                }
                TokenMode::DoubleSubmit
            }
            "signed" => {
                if cfg.token_secret.is_empty() {
                    bail!("csrf.token_secret is required in signed mode");
                }
                let secret = crate::security::secret::resolve_text(
                    cfg.token_secret.as_str(),
                    config_dir,
                    "csrf token secret",
                )?;
                if secret.len() < MIN_SIGNING_SECRET_BYTES {
                    bail!(
                        "csrf.token_secret must contain at least {MIN_SIGNING_SECRET_BYTES} bytes"
                    );
                }
                TokenMode::Signed {
                    secret: secret.into_bytes(),
                }
            }
            value => bail!("csrf.token_mode must be `double_submit` or `signed`, got `{value}`"),
        };
        Ok(Self {
            monitor,
            methods,
            same_origin,
            allowed_origins,
            allow_referer_fallback: cfg.allow_referer_fallback,
            allow_missing_origin: cfg.allow_missing_origin,
            mode,
            cookie_name: cfg.cookie_name.clone(),
            header_name,
            token_ttl_secs: cfg.token_ttl_secs,
            issue_on_safe_methods: cfg.issue_on_safe_methods,
        })
    }

    /// 业务作用：对状态变更请求执行来源与 token 双门禁，不读取请求 body。
    ///
    /// 参数说明：
    /// - `parts`：是请求 head
    /// - `downstream_scheme`：是 listener 确定的 `http|https`
    /// - `route_id`：绑定服务端签名 token 的 route 作用域。
    ///
    /// 返回：返回固定允许或拒绝原因；缺失与无效 token 分开观测，但都在 enforce 下故障关闭。
    pub(crate) fn evaluate(
        &self,
        parts: &Parts,
        downstream_scheme: &str,
        route_id: &str,
    ) -> CsrfDecision {
        if !self.methods.contains(&parts.method) {
            return CsrfDecision::SafeMethod;
        }
        if !self.origin_allowed(parts, downstream_scheme) {
            return CsrfDecision::OriginDenied;
        }
        let header_token = match strict_text_header(&parts.headers, &self.header_name) {
            Some(value) => value,
            None if parts.headers.contains_key(&self.header_name) => {
                return CsrfDecision::TokenInvalid;
            }
            None => return CsrfDecision::TokenMissing,
        };
        let cookie_token = match find_cookie(&parts.headers, self.cookie_name.as_str()) {
            CookieLookup::Missing => return CsrfDecision::TokenMissing,
            CookieLookup::Invalid => return CsrfDecision::TokenInvalid,
            CookieLookup::Found(value) => value,
        };
        if header_token.len() > MAX_TOKEN_BYTES
            || cookie_token.len() > MAX_TOKEN_BYTES
            || !constant_time_eq(header_token.as_bytes(), cookie_token.as_bytes())
        {
            return CsrfDecision::TokenInvalid;
        }
        let valid = match &self.mode {
            TokenMode::DoubleSubmit => decode_nonce(header_token).is_some(),
            TokenMode::Signed {
                secret,
            } => self.verify_signed(header_token, route_id, secret),
        };
        if valid {
            CsrfDecision::Allowed
        } else {
            CsrfDecision::TokenInvalid
        }
    }

    /// 业务作用：为成功的安全方法响应签发新 CSRF token，并禁止共享缓存存储每客户端 token。
    ///
    /// 参数说明：
    /// - `headers`：是最终响应 header
    /// - `route_id`：绑定签名作用域。
    ///
    /// 返回：随机数、时间或 header 构造成功时写入 token header、host-only cookie 与
    /// `Cache-Control: private, no-store`；失败返回错误且调用方应故障关闭响应。
    pub(crate) fn issue_response_token(
        &self,
        headers: &mut HeaderMap,
        route_id: &str,
    ) -> Result<()> {
        let mut nonce = [0_u8; TOKEN_NONCE_BYTES];
        getrandom::getrandom(&mut nonce).context("generate CSRF token nonce")?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let token = match &self.mode {
            TokenMode::DoubleSubmit => nonce,
            TokenMode::Signed {
                secret,
            } => {
                let timestamp = now_epoch()?;
                let payload = format!("{timestamp}.{nonce}");
                let signature = sign_token(payload.as_bytes(), route_id, secret)?;
                format!("{payload}.{}", URL_SAFE_NO_PAD.encode(signature))
            }
        };
        let token_header =
            HeaderValue::from_str(token.as_str()).context("build CSRF token header")?;
        let cookie = HeaderValue::from_str(
            format!(
                "{}={token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
                self.cookie_name, self.token_ttl_secs
            )
            .as_str(),
        )
        .context("build CSRF token cookie")?;
        headers.insert(self.header_name.clone(), token_header);
        headers.append(SET_COOKIE, cookie);
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        Ok(())
    }

    /// 业务作用：判断当前安全方法响应是否应签发 token，避免错误响应和状态变更响应产生凭据。
    ///
    /// 参数说明：
    /// - `method`：是原始请求方法
    /// - `status`：是最终响应状态。
    ///
    /// 返回：显式开启、方法不受保护且响应为成功或重定向时返回 true。
    pub(crate) fn should_issue(&self, method: &Method, status: StatusCode) -> bool {
        self.issue_on_safe_methods
            && !self.methods.contains(method)
            && (status.is_success() || status.is_redirection())
    }

    /// 业务作用：判断拒绝决策是否只记录而不改变业务响应。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置为 `monitor` 时返回 true。
    pub(crate) const fn monitor(&self) -> bool {
        self.monitor
    }

    /// 业务作用：验证请求来源是否满足显式 origin allowlist 或同源约束。
    ///
    /// 参数说明：
    /// - `parts`：是请求 head
    /// - `downstream_scheme`：是 listener 确定的 scheme。
    ///
    /// 返回：来源可验证且被允许时返回 true；歧义、`null`、跨源或缺失默认返回 false。
    fn origin_allowed(&self, parts: &Parts, downstream_scheme: &str) -> bool {
        let origin = if parts.headers.contains_key(&ORIGIN) {
            let Some(origin) = strict_text_header(&parts.headers, &ORIGIN) else {
                return false;
            };
            let Ok(origin) = normalize_origin(origin) else {
                return false;
            };
            origin
        } else if self.allow_referer_fallback && parts.headers.contains_key(&REFERER) {
            let Some(referer) = strict_text_header(&parts.headers, &REFERER) else {
                return false;
            };
            let Ok(origin) = origin_from_referer(referer) else {
                return false;
            };
            origin
        } else {
            return self.allow_missing_origin;
        };
        if self.allowed_origins.contains(origin.as_str()) {
            return true;
        }
        self.same_origin
            && request_origin(parts, downstream_scheme).is_some_and(|request| request == origin)
    }

    /// 业务作用：复验 route 绑定、带时效的服务端签名 token。
    ///
    /// 参数说明：
    /// - `token`：是 header/cookie 已常量时间对等的值
    /// - `route_id`：是签名作用域
    /// - `secret`：是构建期解析的 HMAC secret。
    ///
    /// 返回：格式、nonce、时效与 HMAC 全部有效时返回 true，任何异常返回 false。
    fn verify_signed(&self, token: &str, route_id: &str, secret: &[u8]) -> bool {
        let mut fields = token.split('.');
        let (Some(timestamp), Some(nonce), Some(signature), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        if decode_nonce(nonce).is_none() {
            return false;
        }
        let Some(timestamp_value) = timestamp.parse::<u64>().ok() else {
            return false;
        };
        let Ok(now) = now_epoch() else {
            return false;
        };
        if timestamp_value > now.saturating_add(MAX_FUTURE_SKEW_SECS)
            || now.saturating_sub(timestamp_value) > self.token_ttl_secs
        {
            return false;
        }
        let Some(signature) = URL_SAFE_NO_PAD.decode(signature).ok() else {
            return false;
        };
        let Ok(mut verifier) = HmacSha256::new_from_slice(secret) else {
            return false;
        };
        verifier.update(timestamp.as_bytes());
        verifier.update(b".");
        verifier.update(nonce.as_bytes());
        verifier.update(b"\n");
        verifier.update(route_id.as_bytes());
        verifier.verify_slice(signature.as_slice()).is_ok()
    }
}

/// 业务作用：返回 signed CSRF SecretSource 的文件依赖，供 watcher 与指纹同源轮换。
///
/// 参数说明：
/// - `config_dir`：是相对路径基准
/// - `cfg`：是 route CSRF 声明。
///
/// 返回：signed 文件型 secret 返回单路径；其它来源或模式返回空列表。
pub(crate) fn dependency_paths(config_dir: &Path, cfg: &CsrfCfg) -> Vec<PathBuf> {
    (cfg.token_mode == "signed")
        .then(|| crate::security::secret::dependency_path(cfg.token_secret.as_str(), config_dir))
        .flatten()
        .into_iter()
        .collect()
}

/// cookie 查找的三态结果。
enum CookieLookup<'a> {
    /// 没有目标 cookie。
    Missing,
    /// header 非 UTF-8、目标重复或 token 为空。
    Invalid,
    /// 恰有一个目标 cookie。
    Found(&'a str),
}

/// 业务作用：解析受保护方法集合并拒绝安全方法、重复值和过量配置。
///
/// 参数说明：
/// - `values`：是配置方法名。
///
/// 返回：合法状态变更方法返回集合；空、重复、非法或安全方法返回错误。
fn parse_methods(values: &[String]) -> Result<HashSet<Method>> {
    if values.is_empty() || values.len() > MAX_METHODS {
        bail!("csrf.methods must contain 1..={MAX_METHODS} entries");
    }
    let mut output = HashSet::with_capacity(values.len());
    for value in values {
        let method = Method::from_bytes(value.as_bytes()).context("csrf.methods is invalid")?;
        if value != method.as_str() || value.bytes().any(|byte| byte.is_ascii_lowercase()) {
            bail!("csrf.methods must use canonical uppercase method names");
        }
        if matches!(
            method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        ) {
            bail!("csrf.methods cannot include safe method `{method}`");
        }
        if !output.insert(method.clone()) {
            bail!("csrf.methods contains duplicate method `{method}`");
        }
    }
    Ok(output)
}

/// 业务作用：规范化来源 allowlist，并把动态同源规则与精确来源分开冻结。
///
/// 参数说明：
/// - `values`：是 `same-origin` 或精确 `scheme://authority` 列表。
///
/// 返回：规则合法且不重复时返回同源开关和规范来源集合，否则返回错误。
fn parse_allowed_origins(values: &[String]) -> Result<(bool, HashSet<String>)> {
    if values.len() > MAX_ALLOWED_ORIGINS {
        bail!("csrf.allowed_origins supports at most {MAX_ALLOWED_ORIGINS} entries");
    }
    let mut same_origin = false;
    let mut origins = HashSet::with_capacity(values.len());
    for value in values {
        if value == "same-origin" {
            if same_origin {
                bail!("csrf.allowed_origins contains duplicate `same-origin`");
            }
            same_origin = true;
            continue;
        }
        let origin = normalize_origin(value)
            .map_err(|()| anyhow::anyhow!("csrf.allowed_origins contains invalid origin"))?;
        if !origins.insert(origin) {
            bail!("csrf.allowed_origins contains duplicate origin");
        }
    }
    Ok((same_origin, origins))
}

/// 业务作用：把浏览器 Origin 严格规范为 `scheme://authority`，拒绝 `null`、路径和凭据。
///
/// 参数说明：
/// - `value`：是 Origin header 或配置值。
///
/// 返回：合法 HTTP(S) origin 返回规范字符串；其它形态返回错误。
fn normalize_origin(value: &str) -> std::result::Result<String, ()> {
    if value == "null" {
        return Err(());
    }
    let uri = value.parse::<Uri>().map_err(|_| ())?;
    if uri
        .path_and_query()
        .is_some_and(|path| path.as_str() != "/")
    {
        return Err(());
    }
    canonical_origin(
        uri.scheme_str().ok_or(())?,
        uri.authority().ok_or(())?.as_str(),
    )
}

/// 业务作用：从绝对 Referer URI 只提取 origin，丢弃 path/query 以避免敏感 URL 进入策略状态。
///
/// 参数说明：
/// - `value`：是 Referer header。
///
/// 返回：合法 HTTP(S) 绝对 URI 返回规范 origin，否则返回错误。
fn origin_from_referer(value: &str) -> std::result::Result<String, ()> {
    let uri = value.parse::<Uri>().map_err(|_| ())?;
    canonical_origin(
        uri.scheme_str().ok_or(())?,
        uri.authority().ok_or(())?.as_str(),
    )
}

/// 业务作用：从已验证 listener scheme 与请求 authority 构造当前请求的同源比较值。
///
/// 参数说明：
/// - `parts`：是请求 head
/// - `downstream_scheme`：只能来自 listener 事实。
///
/// 返回：authority 单值合法时返回规范 origin；缺失或非法返回 `None`。
fn request_origin(parts: &Parts, downstream_scheme: &str) -> Option<String> {
    let authority = parts
        .uri
        .authority()
        .map(|value| value.as_str())
        .or_else(|| strict_text_header(&parts.headers, &HOST))?;
    canonical_origin(downstream_scheme, authority).ok()
}

/// 业务作用：规范 HTTP(S) scheme、大小写主机、IPv6 括号与默认端口，保证同源比较语义稳定。
///
/// 参数说明：
/// - `scheme`：是协议
/// - `raw_authority`：是不含路径的 authority。
///
/// 返回：合法且不含 userinfo 时返回规范 origin；其它输入返回错误。
fn canonical_origin(scheme: &str, raw_authority: &str) -> std::result::Result<String, ()> {
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(());
    }
    if raw_authority.contains('@') {
        return Err(());
    }
    let authority = raw_authority
        .parse::<http::uri::Authority>()
        .map_err(|_| ())?;
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err(());
    }
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let port = authority.port_u16();
    let default_port = matches!(
        (scheme.as_str(), port),
        ("http", Some(80)) | ("https", Some(443))
    );
    match port {
        None => Ok(format!("{scheme}://{host}")),
        Some(_) if default_port => Ok(format!("{scheme}://{host}")),
        Some(port) => Ok(format!("{scheme}://{host}:{port}")),
    }
}

/// 业务作用：从一个或多个 Cookie header 中查找唯一目标 cookie，拒绝重复覆盖语义。
///
/// 参数说明：
/// - `headers`：是请求 header
/// - `name`：是已验证的 host-only cookie 名。
///
/// 返回：未找到、无效或唯一值三态结果。
fn find_cookie<'a>(headers: &'a HeaderMap, name: &str) -> CookieLookup<'a> {
    let mut found = None;
    for header in headers.get_all(&COOKIE).iter() {
        let Ok(header) = header.to_str() else {
            return CookieLookup::Invalid;
        };
        for pair in header.split(';') {
            let Some((candidate, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if candidate == name && (value.is_empty() || found.replace(value).is_some()) {
                return CookieLookup::Invalid;
            }
        }
    }
    found.map_or(CookieLookup::Missing, CookieLookup::Found)
}

/// 业务作用：读取严格单值非空 UTF-8 header，防止重复值改变来源或 token 语义。
///
/// 参数说明：
/// - `headers`：是请求 header
/// - `name`：是已验证名称。
///
/// 返回：恰有一个非空 UTF-8 值时返回该值，其它情况返回 `None`。
fn strict_text_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok().filter(|value| !value.is_empty())
}

/// 业务作用：验证 double-submit 或 signed token 的 nonce 具备固定 256-bit 编码形态。
///
/// 参数说明：
/// - `value`：是 Base64URL 无填充 nonce。
///
/// 返回：解码后恰为 32 字节时返回字节，否则返回 `None`。
fn decode_nonce(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .filter(|decoded| decoded.len() == TOKEN_NONCE_BYTES)
}

/// 业务作用：为服务端 CSRF token 生成绑定 route 的 HMAC-SHA256 签名。
///
/// 参数说明：
/// - `payload`：是规范 `timestamp.nonce`
/// - `route_id`：是签名作用域
/// - `secret`：是已解析密钥。
///
/// 返回：HMAC 初始化成功时返回固定 32 字节签名，否则返回错误。
fn sign_token(payload: &[u8], route_id: &str, secret: &[u8]) -> Result<[u8; 32]> {
    let mut signer = HmacSha256::new_from_slice(secret).context("initialize CSRF signer")?;
    signer.update(payload);
    signer.update(b"\n");
    signer.update(route_id.as_bytes());
    Ok(signer.finalize().into_bytes().into())
}

/// 业务作用：读取当前 Unix 秒供 signed token 签发与时效复验。
///
/// 参数说明: 无。
///
/// 返回：系统时间不早于 Unix epoch 时返回秒数，否则返回错误。
fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

/// 业务作用：验证 cookie 名字符集，防止分隔符注入响应 header。
///
/// 参数说明：
/// - `byte`：是 cookie 名的单个 ASCII 字节。
///
/// 返回：RFC token 安全集合内返回 true。
const fn is_cookie_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
