//! Open Policy Agent 授权策略、签名 bundle、输入编码与有界 decision cache。
//!
//! OPA 是授权而不是认证：本模块只接收主管线已经验证出的 `consumer`，绝不从
//! `X-Auth-User`/Authorization/Cookie 等客户端头推导身份。业务 body 只有显式 opt-in 才进入
//! OPA；默认 HTTP 代理仍保持流式。只有显式配置的少量 request header 会放进
//! `request_headers_untrusted`，提醒 Rego 作者这些值不是可信 principal。

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::expiry::ExpiringCache;
use crate::control::ownership::state::{Budget, Lease};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use ed25519_dalek::{Signature, VerifyingKey};
use flate2::read::GzDecoder;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use http_body_util::BodyExt;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::config::model::{OpaAuthorizationCfg, OpaBundleCfg, OpaEngineCfg, OpaObligationsCfg};
use crate::BoxBody;

mod semantic;

const MAX_OPA_TIMEOUT_MS: u64 = 60_000;
const MAX_OPA_HEADERS: usize = 32;
const MAX_OPA_HEADER_VALUE_BYTES: usize = 64 * 1024;
const MAX_OPA_INPUT_BYTES: usize = 1024 * 1024;
const MAX_OPA_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_OPA_CACHE_TTL_MS: u64 = 300_000;
const MAX_OPA_CACHE_ENTRIES: u64 = 1_000_000;
const MAX_OPA_POLICY_REVISION_BYTES: usize = 128;
const MAX_OPA_PATH_BYTES: usize = 2048;
const MAX_OPA_BODY_BYTES: usize = 1024 * 1024;
const MAX_OPA_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_OPA_BUNDLE_EXPANDED_BYTES: usize = 256 * 1024 * 1024;
const MAX_OPA_BUNDLE_FILES: usize = 4_096;
const MAX_OPA_OBLIGATION_ENTRIES: usize = 256;
const MAX_OPA_OBLIGATION_VALUE_BYTES: usize = 64 * 1024;
const MAX_OPA_OBLIGATION_BYTES: usize = 1024 * 1024;
const MAX_OPA_SINGLEFLIGHT_KEYS: usize = 65_536;
const MAX_OPA_DISTRIBUTED_ENTRIES: usize = 1_000_000;
const MAX_OPA_AUDIT_KEY_BYTES: usize = 64;

const FORBIDDEN_MUTATION_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
];

/// 构建完成的 route 级 OPA 策略。
pub(crate) struct OpaPolicy {
    workspace_budget: std::sync::OnceLock<Option<Budget>>,
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
    revision: Arc<str>,
    cache: Option<OpaDecisionCache>,
    input: OpaInputPlan,
    obligations: OpaObligationPlan,
    engine: OpaEngine,
    flights: DashMap<[u8; 32], Arc<OpaFlight>>,
    singleflight: bool,
    singleflight_wait: Duration,
    singleflight_max_keys: usize,
    distributed: Option<OpaDistributedCache>,
    backoff: OpaBackoff,
}

struct OpaDecisionCache {
    entries: ExpiringCache<[u8; 32], CachedDecision>,
    allow_ttl: Duration,
    deny_ttl: Duration,
}

struct CachedDecision {
    _workspace_lease: Option<Lease>,
    decision: OpaDecision,
    expires_at: Instant,
}

#[derive(Clone, PartialEq, Eq)]
struct OpaInputPlan {
    include_body: bool,
    max_body_bytes: usize,
    content_types: Arc<HashSet<String>>,
    include_jwt_claims: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct OpaObligationPlan {
    request_headers: Arc<HashSet<HeaderName>>,
    response_headers: Arc<HashSet<HeaderName>>,
    audit_metadata: Arc<HashSet<String>>,
    max_entries: usize,
    max_value_bytes: usize,
    max_bytes: usize,
}

#[derive(PartialEq, Eq)]
enum OpaEngine {
    External,
    #[cfg(feature = "opa-embedded")]
    Embedded(Box<EmbeddedOpa>),
}

#[cfg(feature = "opa-embedded")]
struct EmbeddedOpa {
    template: regorus::Engine,
    query: Arc<str>,
    bundle: BundleIdentity,
}

#[derive(PartialEq, Eq)]
struct OpaDistributedCache {
    collection: Arc<str>,
    max_entries: usize,
}

pub(crate) struct OpaFlight {
    _workspace_lease: Option<Lease>,
    finished: AtomicBool,
    notify: Notify,
}

/// 同 key miss 的节点内 single-flight 身份。
pub(crate) enum OpaFlightRole<'a> {
    /// 当前请求负责求值并在离开作用域时唤醒 follower。
    Leader(OpaFlightGuard<'a>),
    /// 当前请求等待已有 leader。
    Follower(Arc<OpaFlight>),
    /// single-flight 关闭或不同 key 表达到容量，独立求值。
    Bypass,
}

/// leader 的取消安全守卫；请求取消、超时或 panic 都会唤醒 follower。
pub(crate) struct OpaFlightGuard<'a> {
    policy: &'a OpaPolicy,
    key: [u8; 32],
    flight: Arc<OpaFlight>,
}

struct OpaBackoff {
    initial: Duration,
    max: Duration,
    failures: AtomicU32,
    retry_after_millis: AtomicU64,
}

/// 已验证 OPA obligations；只能通过 route 白名单编译器构造。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpaObligations {
    #[serde(default)]
    request_headers: HeaderObligations,
    #[serde(default)]
    response_headers: HeaderObligations,
    #[serde(default)]
    audit_metadata: BTreeMap<String, String>,
}

/// 一组已经过白名单复验的 header 原子变更。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderObligations {
    #[serde(default)]
    set: BTreeMap<String, String>,
    #[serde(default)]
    remove: Vec<String>,
}

/// OPA 的最终授权结果。transport/协议错误不伪装成 deny。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub(crate) enum OpaDecision {
    /// 放行，并可携带经过完整验证的副作用。
    Allow {
        #[serde(default)]
        obligations: OpaObligations,
    },
    /// 明确拒绝；拒绝结果不执行 obligations。
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
    jwt_claims: Option<&'a serde_json::Value>,
    request_body: Option<&'a serde_json::Value>,
}

impl<'a> OpaRequestContext<'a> {
    /// 业务作用：创建请求级 OPA 输入视图；调用方须先冻结认证结果，不能传入未经验证的身份头。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        parts: &'a Parts,
        client_ip: IpAddr,
        downstream_proto: &'a str,
        route_id: &'a str,
        authenticated: bool,
        consumer: Option<&'a str>,
        jwt_claims: Option<&'a serde_json::Value>,
        request_body: Option<&'a serde_json::Value>,
    ) -> Self {
        Self {
            parts,
            client_ip,
            downstream_proto,
            route_id,
            authenticated,
            consumer,
            jwt_claims,
            request_body,
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
    /// 业务作用：编译 route 级 OPA 策略，在候选快照发布前完成来源、签名、Rego 与所有资源门校验。
    ///
    /// 参数说明：
    /// - `cfg`：是声明配置
    /// - `config_dir`：解析文件依赖
    /// - `route_id`：提供错误定位。
    ///
    /// 返回：返回只读可执行策略；任一 bundle/签名/配置错误都会拒绝候选，从而保留旧快照。
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
        if !(1..=60_000).contains(&cfg.backoff_initial_ms)
            || !(cfg.backoff_initial_ms..=300_000).contains(&cfg.backoff_max_ms)
        {
            bail!(
                "route `{route_id}` opa_authorization backoff requires 1<=initial<=max<=300000ms"
            );
        }
        let (upstream, path, engine, revision) = match cfg.engine {
            OpaEngineCfg::External => {
                if cfg.bundle.is_some() {
                    bail!(
                        "route `{route_id}` external opa_authorization cannot declare bundle; use engine=embedded or publish the revision to the external OPA"
                    );
                }
                let (upstream, path) = compile_target(&cfg.target, &cfg.path, route_id)?;
                let revision = cfg
                    .cache
                    .as_ref()
                    .map(|cache| cache.policy_revision.trim())
                    .unwrap_or("cache-disabled");
                if cfg.cache.is_some() {
                    validate_policy_revision(revision, route_id)?;
                }
                (
                    upstream,
                    path,
                    OpaEngine::External,
                    Arc::<str>::from(revision),
                )
            }
            OpaEngineCfg::Embedded => {
                if !cfg.target.trim().is_empty() || !cfg.path.trim().is_empty() {
                    bail!(
                        "route `{route_id}` embedded opa_authorization must not declare target/path"
                    );
                }
                let bundle_cfg = cfg.bundle.as_ref().with_context(|| {
                    format!("route `{route_id}` embedded opa_authorization requires bundle")
                })?;
                let loaded = load_signed_bundle(bundle_cfg, config_dir, route_id)?;
                #[cfg(feature = "opa-embedded")]
                {
                    let revision = loaded.revision.clone();
                    let engine = OpaEngine::Embedded(Box::new(build_embedded_engine(
                        loaded,
                        bundle_cfg.query.as_str(),
                        route_id,
                    )?));
                    (String::new(), String::new(), engine, revision)
                }
                #[cfg(not(feature = "opa-embedded"))]
                {
                    let LoadedOpaBundle {
                        revision,
                        modules,
                        data,
                        identity,
                    } = loaded;
                    drop((revision, modules, data, identity));
                    bail!(
                        "route `{route_id}` engine=embedded requires binary feature `opa-embedded`"
                    );
                }
            }
        };
        let include_headers = compile_headers(&cfg.include_headers, route_id)?;
        let authorization = if cfg.engine == OpaEngineCfg::Embedded {
            if !cfg.authorization.trim().is_empty() {
                bail!(
                    "route `{route_id}` embedded opa_authorization must not declare authorization"
                );
            }
            None
        } else if cfg.authorization.trim().is_empty() {
            None
        } else {
            let secret = crate::security::secret::resolve_text(
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
                if !(1..=MAX_OPA_CACHE_TTL_MS).contains(&cache.deny_ttl_ms) {
                    bail!(
                        "route `{route_id}` opa_authorization cache.deny_ttl_ms must be within 1..={MAX_OPA_CACHE_TTL_MS}"
                    );
                }
                if !(1..=MAX_OPA_CACHE_ENTRIES).contains(&cache.max_entries) {
                    bail!(
                        "route `{route_id}` opa_authorization cache.max_entries must be within 1..={MAX_OPA_CACHE_ENTRIES}"
                    );
                }
                if !(1..=30_000).contains(&cache.singleflight_wait_ms) {
                    bail!(
                        "route `{route_id}` opa_authorization cache.singleflight_wait_ms must be within 1..=30000"
                    );
                }
                if !(1..=MAX_OPA_SINGLEFLIGHT_KEYS).contains(&cache.singleflight_max_keys) {
                    bail!(
                        "route `{route_id}` opa_authorization cache.singleflight_max_keys must be within 1..={MAX_OPA_SINGLEFLIGHT_KEYS}"
                    );
                }
                if cache.distributed
                    && !(1..=MAX_OPA_DISTRIBUTED_ENTRIES)
                        .contains(&cache.distributed_max_entries)
                {
                    bail!(
                        "route `{route_id}` opa_authorization cache.distributed_max_entries must be within 1..={MAX_OPA_DISTRIBUTED_ENTRIES}"
                    );
                }
                if cache.distributed {
                    validate_store_component(
                        cache.distributed_collection.as_str(),
                        "cache.distributed_collection",
                        route_id,
                    )?;
                }
                Ok(OpaDecisionCache {
                    entries: ExpiringCache::new(cache.max_entries),
                    allow_ttl: Duration::from_millis(cache.ttl_ms),
                    deny_ttl: Duration::from_millis(cache.deny_ttl_ms),
                })
            })
            .transpose()?;
        let input = compile_input_plan(cfg, route_id)?;
        let obligations = compile_obligation_plan(&cfg.obligations, route_id)?;
        let singleflight = cfg.cache.as_ref().is_some_and(|cache| cache.singleflight);
        let singleflight_wait = Duration::from_millis(
            cfg.cache
                .as_ref()
                .map(|cache| cache.singleflight_wait_ms)
                .unwrap_or(1),
        );
        let singleflight_max_keys = cfg
            .cache
            .as_ref()
            .map(|cache| cache.singleflight_max_keys)
            .unwrap_or(1);
        let distributed = cfg.cache.as_ref().and_then(|cache| {
            cache.distributed.then(|| OpaDistributedCache {
                collection: Arc::from(cache.distributed_collection.as_str()),
                max_entries: cache.distributed_max_entries,
            })
        });
        let policy_salt = policy_salt(
            upstream.as_str(),
            path.as_str(),
            revision.as_ref(),
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
            revision,
            cache,
            workspace_budget: std::sync::OnceLock::new(),
            input,
            obligations,
            engine,
            flights: DashMap::new(),
            singleflight,
            singleflight_wait,
            singleflight_max_keys,
            distributed,
            backoff: OpaBackoff {
                initial: Duration::from_millis(cfg.backoff_initial_ms),
                max: Duration::from_millis(cfg.backoff_max_ms),
                failures: AtomicU32::new(0),
                retry_after_millis: AtomicU64::new(0),
            },
        })
    }

    /// 业务作用：OPA response head/body 的总 deadline。
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 业务作用：transport/5xx/畸形响应是否放行。
    pub(crate) fn fail_open(&self) -> bool {
        self.fail_open
    }

    /// 业务作用：可选 OPA 服务 Authorization header。值已标 sensitive，日志不得格式化它。
    pub(crate) fn authorization(&self) -> Option<&HeaderValue> {
        self.authorization.as_ref()
    }

    /// 业务作用：OPA response body 上限。
    pub(crate) fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// 业务作用：是否要求稳定 consumer。
    pub(crate) fn requires_identity(&self) -> bool {
        self.require_identity
    }

    /// 业务作用：是否启用了本节点 decision cache。
    pub(crate) fn cache_enabled(&self) -> bool {
        self.cache.is_some()
    }

    /// 业务作用：判断本 route 是否显式要求聚合 request body，供主管线保持默认流式快路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：只有配置 opt-in 且构建期通过资源门时返回 true。
    pub(crate) fn includes_body(&self) -> bool {
        self.input.include_body
    }

    /// 业务作用：返回 request body 聚合硬上限，主管线在复制下一 frame 前使用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回候选快照中已验证的非零字节上限。
    pub(crate) fn max_body_bytes(&self) -> usize {
        self.input.max_body_bytes
    }

    /// 业务作用：复验 request body media type，防止把未声明的二进制或表单载荷误交给 JSON 策略。
    ///
    /// 参数说明：
    /// - `headers`：是未经 obligation 改写的原始请求头。
    ///
    /// 返回：关闭 body 输入时返回 true；开启时只接受显式 allowlist media type。
    pub(crate) fn permits_body_content_type(&self, headers: &HeaderMap) -> bool {
        if !self.input.include_body {
            return true;
        }
        let Some(media_type) = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
            })
        else {
            return false;
        };
        self.input.content_types.contains(media_type.as_str())
    }

    /// 业务作用：判断 OPA input 是否需要携带网关已验证的完整 JWT claims。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：显式 opt-in 时返回 true。
    pub(crate) fn includes_jwt_claims(&self) -> bool {
        self.input.include_jwt_claims
    }

    /// 业务作用：判断策略由外部 OPA 还是进程内 Rego 引擎求值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：外部模式返回 true；embedded 模式返回 false。
    pub(crate) fn is_external(&self) -> bool {
        matches!(self.engine, OpaEngine::External)
    }

    /// 业务作用：在进程内执行签名 bundle 的 Rego rule，并用与外部响应相同的 obligation contract 复验。
    ///
    /// 参数说明：
    /// - `payload`：是已经通过输入大小门的 `{input:...}` JSON。
    ///
    /// 返回：embedded 模式返回明确 decision；外部模式或解释器错误返回 dependency error。
    pub(crate) fn evaluate_embedded(&self, payload: &OpaInputPayload) -> Result<OpaDecision> {
        #[cfg(feature = "opa-embedded")]
        if let OpaEngine::Embedded(embedded) = &self.engine {
            let envelope: serde_json::Value =
                serde_json::from_slice(&payload.body).context("decode embedded OPA input")?;
            let input = envelope
                .get("input")
                .context("embedded OPA input envelope is missing input")?;
            // 每次求值 clone 已编译模板，仅替换 request-local input；不同 key 不共享可变解释器状态。
            let mut engine = embedded.template.clone();
            engine.set_input(regorus::Value::from_json_str(&serde_json::to_string(
                input,
            )?)?);
            let value = engine
                .eval_rule(embedded.query.to_string())
                .context("evaluate embedded OPA rule")?;
            let encoded = value.to_json_str().context("encode embedded OPA result")?;
            return self.parse_result_value(
                serde_json::from_str(&encoded).context("decode embedded OPA result")?,
            );
        }
        #[cfg(not(feature = "opa-embedded"))]
        let _ = payload;
        bail!("OPA policy does not use embedded engine")
    }

    /// 业务作用：解析并整体验证 OPA result，确保非法 obligation 在任何 header 变更前失败。
    ///
    /// 参数说明：
    /// - `body`：是外部 OPA Data API 的完整有界 JSON body。
    ///
    /// 返回：返回明确 allow/deny；缺失 result、未知字段、越权 mutation 或资源超限返回错误。
    pub(crate) fn parse_decision(&self, body: &[u8]) -> Result<OpaDecision> {
        let response: OpaResponse =
            serde_json::from_slice(body).context("decode OPA response JSON")?;
        match response.result {
            OpaResult::Boolean(allowed) => Ok(if allowed {
                OpaDecision::Allow {
                    obligations: OpaObligations::default(),
                }
            } else {
                OpaDecision::Deny
            }),
            OpaResult::Object(result) => self.parse_result_object(result),
        }
    }

    /// 业务作用：把 embedded rule 的原生值映射为统一 decision contract。
    ///
    /// 参数说明：
    /// - `value`：是 Regorus 返回的 JSON 等价值。
    ///
    /// 返回：boolean 或严格对象成功映射；undefined/其它类型和非法 obligations 返回错误。
    #[cfg(feature = "opa-embedded")]
    fn parse_result_value(&self, value: serde_json::Value) -> Result<OpaDecision> {
        match value {
            serde_json::Value::Bool(allowed) => Ok(if allowed {
                OpaDecision::Allow {
                    obligations: OpaObligations::default(),
                }
            } else {
                OpaDecision::Deny
            }),
            serde_json::Value::Object(_) => {
                let result: OpaResultObject =
                    serde_json::from_value(value).context("decode embedded OPA result object")?;
                self.parse_result_object(result)
            }
            _ => bail!("embedded OPA rule must return boolean or decision object"),
        }
    }

    /// 业务作用：整体验证对象 decision 与全部 obligations，任何单项越权时拒绝整次结果。
    ///
    /// 参数说明：
    /// - `result`：是严格反序列化但尚未做 route allowlist 校验的对象。
    ///
    /// 返回：合法 allow 携带规范化 obligations，deny 不携带副作用；非法对象返回 dependency error。
    fn parse_result_object(&self, result: OpaResultObject) -> Result<OpaDecision> {
        let obligations = result.obligations.unwrap_or_default();
        if !result.allow {
            if !obligations.is_empty() {
                bail!("OPA deny result must not contain obligations");
            }
            return Ok(OpaDecision::Deny);
        }
        self.obligations.validate(&obligations)?;
        Ok(OpaDecision::Allow {
            obligations,
        })
    }

    /// 业务作用：从节点内 single-flight 表取得 leader/follower 身份，表满时有界绕过而不增长内存。
    ///
    /// 参数说明：
    /// - `key`：是已覆盖 revision、身份与全部输入的稳定摘要。
    ///
    /// 返回：返回 leader guard、follower wait handle 或容量绕过标记。
    pub(crate) fn acquire_flight(&self, key: [u8; 32]) -> OpaFlightRole<'_> {
        if !self.singleflight {
            return OpaFlightRole::Bypass;
        }
        if let Some(existing) = self.flights.get(&key) {
            return OpaFlightRole::Follower(existing.clone());
        }
        if self.flights.len() >= self.singleflight_max_keys {
            return OpaFlightRole::Bypass;
        }
        let lease = match self
            .workspace_budget
            .get()
            .and_then(Option::as_ref)
            .map(Budget::acquire)
            .transpose()
        {
            Ok(lease) => lease,
            Err(_) => return OpaFlightRole::Bypass,
        };
        let flight = Arc::new(OpaFlight {
            _workspace_lease: lease,
            finished: AtomicBool::new(false),
            notify: Notify::new(),
        });
        match self.flights.entry(key) {
            Entry::Occupied(entry) => OpaFlightRole::Follower(entry.get().clone()),
            Entry::Vacant(entry) => {
                entry.insert(flight.clone());
                OpaFlightRole::Leader(OpaFlightGuard {
                    policy: self,
                    key,
                    flight,
                })
            }
        }
    }

    /// 业务作用：有界等待同 key leader 完成；Notify 前后复验 finished，避免 lost wakeup。
    ///
    /// 参数说明：
    /// - `flight`：是当前 key 的共享完成状态。
    ///
    /// 返回：leader 在 deadline 内结束返回 true，超时返回 false。
    pub(crate) async fn wait_flight(&self, flight: &Arc<OpaFlight>) -> bool {
        if flight.finished.load(Ordering::Acquire) {
            return true;
        }
        let notified = flight.notify.notified();
        if flight.finished.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::timeout(self.singleflight_wait, notified)
            .await
            .is_ok()
    }

    /// 业务作用：判断外部 OPA 是否处在连续故障退避窗，避免依赖宕机时每个请求继续放大流量。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前 monotonic deadline 尚未到达时返回 true。
    pub(crate) fn backoff_active(&self) -> bool {
        monotonic_millis() < self.backoff.retry_after_millis.load(Ordering::Acquire)
    }

    /// 业务作用：记录一次外部 OPA dependency failure，并指数增加有上限的下一次探测间隔。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；仅更新当前 snapshot 内 route 级退避状态。
    pub(crate) fn record_failure(&self) {
        let failures = self
            .backoff
            .failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
            .min(31);
        let multiplier = 1u32 << failures.saturating_sub(1);
        let delay = self
            .backoff
            .initial
            .checked_mul(multiplier)
            .unwrap_or(self.backoff.max)
            .min(self.backoff.max);
        self.backoff.retry_after_millis.store(
            monotonic_millis().saturating_add(delay.as_millis().min(u128::from(u64::MAX)) as u64),
            Ordering::Release,
        );
    }

    /// 业务作用：成功取得合法 decision 后解除 dependency 退避，让下一请求正常复用服务。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；清零失败计数与 deadline。
    pub(crate) fn record_success(&self) {
        self.backoff.failures.store(0, Ordering::Release);
        self.backoff.retry_after_millis.store(0, Ordering::Release);
    }

    /// 业务作用：返回跨节点 decision cache 配置，供代理层通过当前可换 DynamicStore 访问。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：未显式开启时返回 None；开启时返回经过命名与容量复验的 collection/上限。
    pub(crate) fn distributed_cache(&self) -> Option<(String, usize)> {
        self.distributed.as_ref().map(|cache| match self.budget() {
            Some(budget) => (
                format!(
                    "workspace-opa-{:x}",
                    Sha256::digest(budget.remote_scope().0.as_bytes())
                ),
                cache.max_entries.min(budget.remote_scope().1),
            ),
            None => (cache.collection.to_string(), cache.max_entries),
        })
    }

    /// 业务作用：提供已冻结的工作区预算，确保共享授权缓存与本地授权使用相同归属。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：工作区预算或平台 None。
    pub(crate) fn budget(&self) -> Option<&Budget> {
        self.workspace_budget.get().and_then(Option::as_ref)
    }

    /// 业务作用：把 decision key 编码为不泄露输入的固定 DynamicStore key。
    ///
    /// 参数说明：
    /// - `key`：是 SHA-256 decision 摘要。
    ///
    /// 返回：返回 64 字节小写十六进制 key。
    pub(crate) fn distributed_key(&self, key: &[u8; 32]) -> String {
        hex_digest(key)
    }

    /// 业务作用：编码跨节点 decision cache 值，绑定当前 revision 与绝对过期时间。
    ///
    /// 参数说明：
    /// - `decision`：必须是已经过本策略 obligation contract 验证的明确结果。
    ///
    /// 返回：返回有界 JSON；系统时间或编码失败时返回错误且不得写入 store。
    pub(crate) fn encode_distributed_decision(&self, decision: &OpaDecision) -> Result<Vec<u8>> {
        let ttl = self.decision_ttl(decision);
        let now = unix_millis()?;
        let expires_unix_ms = now.saturating_add(ttl.as_millis().min(u128::from(u64::MAX)) as u64);
        let encoded = serde_json::to_vec(&DistributedDecision {
            schema_version: 1,
            revision: self.revision.to_string(),
            expires_unix_ms,
            decision: decision.clone(),
        })
        .context("encode distributed OPA decision")?;
        if encoded.len() > self.max_response_bytes.min(256 * 1024) {
            bail!("distributed OPA decision exceeds value limit");
        }
        Ok(encoded)
    }

    /// 业务作用：复验跨节点 cache 值的 schema、revision、expiry 与 obligations，拒绝旧策略或被篡改值。
    ///
    /// 参数说明：
    /// - `encoded`：是 DynamicStore 返回的未信任字节。
    ///
    /// 返回：合法未过期值返回 decision；过期或 revision 不符返回 None；坏值返回错误供调用方删除。
    pub(crate) fn decode_distributed_decision(
        &self,
        encoded: &[u8],
    ) -> Result<Option<OpaDecision>> {
        if encoded.len() > self.max_response_bytes.min(256 * 1024) {
            bail!("distributed OPA decision exceeds value limit");
        }
        let entry: DistributedDecision =
            serde_json::from_slice(encoded).context("decode distributed OPA decision")?;
        if entry.schema_version != 1 {
            bail!("unsupported distributed OPA decision schema");
        }
        if entry.revision != self.revision.as_ref() || entry.expires_unix_ms <= unix_millis()? {
            return Ok(None);
        }
        if let OpaDecision::Allow {
            obligations,
        } = &entry.decision
        {
            self.obligations.validate(obligations)?;
        }
        Ok(Some(entry.decision))
    }

    /// 业务作用：绑定受信归属并计算包含工作区和全部授权输入的缓存摘要。
    ///
    /// 参数说明：
    /// - `input`：为主管线冻结身份后的请求上下文。
    ///
    /// 返回：安全缓存键或输入错误；命中阶段不构造 JSON body。
    pub(crate) fn input_cache_key(
        &self,
        input: &OpaRequestContext<'_>,
    ) -> std::result::Result<[u8; 32], OpaInputError> {
        let budget = self
            .workspace_budget
            .get_or_init(|| input.parts.extensions.get::<Budget>().cloned());
        if let Some(cache) = &self.cache {
            cache.entries.bind_budget(budget.as_ref());
        }
        if self.require_identity && input.consumer.is_none() {
            return Err(OpaInputError::MissingIdentity);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"gw-opa-input-v1\0");
        hasher.update(self.policy_salt);
        if let Some(scope) = input
            .parts
            .extensions
            .get::<crate::control::ownership::RequestScope>()
        {
            hash_field(&mut hasher, scope.0.as_bytes());
        }
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
        hash_optional_json(&mut hasher, input.jwt_claims)?;
        hash_optional_json(&mut hasher, input.request_body)?;
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

    /// 业务作用：在 cache miss 后一次性编码有界 JSON input。
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
                jwt_claims: context.jwt_claims,
                request_body: context.request_body,
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

    /// 业务作用：查 decision L1。过期 entry 立即失效并按 miss 处理。
    pub(crate) async fn cached_decision(&self, key: &[u8; 32]) -> Option<OpaDecision> {
        let cache = self.cache.as_ref()?;
        let entry = cache.entries.get(key).await?;
        if Instant::now() < entry.expires_at {
            return Some(entry.decision.clone());
        }
        cache.entries.invalidate(key).await;
        None
    }

    /// 业务作用：只缓存明确授权结果，并在真实插入前取得本工作区状态名额。
    ///
    /// 参数说明：
    /// - `key`：为受信归属摘要
    /// - `decision`：是经过校验的 allow/deny，不含依赖错误。
    ///
    /// 返回：容量足够时缓存到期值；不足时只跳过缓存，不改变本次授权决定。
    pub(crate) async fn store_decision(&self, key: [u8; 32], decision: OpaDecision) {
        let Some(cache) = &self.cache else {
            return;
        };
        let budget = self.workspace_budget.get().and_then(Option::as_ref);
        if !cache.entries.bind_budget(budget) {
            return;
        }
        let Ok(lease) = budget.map(Budget::acquire).transpose() else {
            return;
        };
        let ttl = match decision {
            OpaDecision::Allow {
                ..
            } => cache.allow_ttl,
            OpaDecision::Deny => cache.deny_ttl,
        };
        let expires_at = Instant::now() + ttl;
        cache
            .entries
            .insert(
                key,
                CachedDecision {
                    _workspace_lease: lease,
                    decision,
                    expires_at,
                },
                expires_at,
            )
            .await;
    }

    /// 业务作用：按 allow/deny 分离 TTL，避免负决策与正决策具有相同陈旧窗口。
    ///
    /// 参数说明：
    /// - `decision`：是明确 OPA 结果。
    ///
    /// 返回：返回当前 route cache 配置的对应 TTL；cache 关闭时返回零。
    pub(crate) fn decision_ttl(&self, decision: &OpaDecision) -> Duration {
        let Some(cache) = &self.cache else {
            return Duration::ZERO;
        };
        match decision {
            OpaDecision::Allow {
                ..
            } => cache.allow_ttl,
            OpaDecision::Deny => cache.deny_ttl,
        }
    }
}

impl Drop for OpaFlightGuard<'_> {
    /// 业务作用：结束当前 OPA 合并请求并唤醒等待者，只删除仍属于本次执行的占位。
    fn drop(&mut self) {
        self.flight.finished.store(true, Ordering::Release);
        self.flight.notify.notify_waiters();
        // 只移除仍指向本 guard 的 entry；同 key 新一代 flight 不得被旧 guard 误删。
        self.policy
            .flights
            .remove_if(&self.key, |_, current| Arc::ptr_eq(current, &self.flight));
    }
}

impl OpaObligationPlan {
    /// 业务作用：一次性复验 OPA 副作用的 header 白名单、凭据禁区、冲突与资源预算。
    ///
    /// 参数说明：
    /// - `obligations`：是策略返回的完整副作用集合。
    ///
    /// 返回：全部条目安全时成功；任一非法条目导致整次 decision 失败且调用方不得部分应用。
    fn validate(&self, obligations: &OpaObligations) -> Result<()> {
        let mut entries = 0usize;
        let mut bytes = 0usize;
        validate_header_obligations(
            &obligations.request_headers,
            self.request_headers.as_ref(),
            self,
            &mut entries,
            &mut bytes,
        )?;
        validate_header_obligations(
            &obligations.response_headers,
            self.response_headers.as_ref(),
            self,
            &mut entries,
            &mut bytes,
        )?;
        for (key, value) in &obligations.audit_metadata {
            entries = entries
                .checked_add(1)
                .context("OPA obligation count overflow")?;
            bytes = bytes
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .context("OPA obligation byte count overflow")?;
            if !self.audit_metadata.contains(key)
                || key.is_empty()
                || key.len() > MAX_OPA_AUDIT_KEY_BYTES
                || value.len() > self.max_value_bytes
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                bail!("OPA audit metadata is not allowed or exceeds configured bounds");
            }
        }
        if entries > self.max_entries || bytes > self.max_bytes {
            bail!("OPA obligations exceed configured aggregate bounds");
        }
        Ok(())
    }
}

impl OpaObligations {
    /// 业务作用：判断 decision 是否携带任何副作用，用于拒绝 deny+obligation 混合结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：三个 obligation 分组都为空时返回 true。
    fn is_empty(&self) -> bool {
        self.request_headers.set.is_empty()
            && self.request_headers.remove.is_empty()
            && self.response_headers.set.is_empty()
            && self.response_headers.remove.is_empty()
            && self.audit_metadata.is_empty()
    }

    /// 业务作用：在 OPA allow 后原子应用已验证的 request header mutations。
    ///
    /// 参数说明：
    /// - `headers`：是后续业务 filter 与 upstream 将读取的请求头。
    ///
    /// 返回：构建期/解析期已验证，因此无失败分支；remove 先执行，set 后形成唯一最终值。
    pub(crate) fn apply_request(&self, headers: &mut HeaderMap) {
        apply_header_obligations(headers, &self.request_headers);
    }

    /// 业务作用：在响应插件完成后、压缩前应用已验证的 response header mutations。
    ///
    /// 参数说明：
    /// - `headers`：是即将发送给下游的响应头。
    ///
    /// 返回：构建期/解析期已验证，因此无失败分支；不会修改 hop-by-hop、凭据或 framing header。
    pub(crate) fn apply_response(&self, headers: &mut HeaderMap) {
        apply_header_obligations(headers, &self.response_headers);
    }

    /// 业务作用：把配置允许的 metadata 暴露给固定审计事件，不作为 metric label 或授权输入回流。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回只读有序 metadata，便于稳定日志编码。
    pub(crate) fn audit_metadata(&self) -> &BTreeMap<String, String> {
        &self.audit_metadata
    }
}

/// 业务作用：检查 OPA 成功响应的 media type；允许 vendor `application/*+json`。
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

/// 业务作用：有界收集 OPA decision JSON，并兼容代理链附加的 HTTP trailers。
///
/// 参数说明：
/// - `body`：是 OPA 响应流
/// - `headers`：用于 Content-Length 前置门
/// - `max_bytes`：是 decision body 硬上限。
///
/// 返回：返回完整 JSON 字节；trailers 被安全消费但不参与授权决定，防止尾部元数据绕过 JSON contract。
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
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(_trailers) => {
                // OPA 决策只能来自 JSON result；接受传输 trailers 但绝不能把它解释成 allow/deny。
                continue;
            }
        };
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
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt_claims: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body: Option<&'a serde_json::Value>,
    request_headers_untrusted: IncludedHeaders<'a>,
}

struct IncludedHeaders<'a> {
    headers: &'a HeaderMap,
    names: &'a [HeaderName],
}

impl Serialize for IncludedHeaders<'_> {
    /// 业务作用：只序列化 OPA 输入白名单允许的头部，避免外部授权引擎取得未授权凭据。
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
    /// 业务作用：只序列化 OPA 输入白名单允许的头部，避免外部授权引擎取得未授权凭据。
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
    /// 业务作用：为 OPA 输入建立受字节上限约束的编码缓冲，容量门在追加过程中执行。
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    /// 业务作用：在 OPA 输入序列化时检查总字节数，超限立即停止编码。
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

    /// 业务作用：完成内存编码器的刷新合同，不触发外部 I/O。
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaResponse {
    result: OpaResult,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OpaResult {
    Boolean(bool),
    Object(OpaResultObject),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaResultObject {
    allow: bool,
    #[serde(default)]
    obligations: Option<OpaObligations>,
}

#[derive(Deserialize)]
struct OpaBundleManifest {
    #[serde(default)]
    revision: String,
}

struct LoadedOpaBundle {
    revision: Arc<str>,
    modules: BTreeMap<String, String>,
    data: serde_json::Value,
    identity: BundleIdentity,
}

/// 签名 bundle 的真实材料与构建边界；只用于候选比较，不代替签名或 Rego 验证。
#[derive(PartialEq, Eq)]
struct BundleIdentity {
    material: [u8; 32],
    signing_key: [u8; 32],
    max_bundle_bytes: usize,
    max_expanded_bytes: usize,
    max_files: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DistributedDecision {
    schema_version: u8,
    revision: String,
    expires_unix_ms: u64,
    decision: OpaDecision,
}

/// 业务作用：把 request body/claims 的 opt-in 配置编译为只读输入计划，并在换版前拒绝无界设置。
///
/// 参数说明：
/// - `cfg`：是 route OPA 配置
/// - `route_id`：提供错误定位。
///
/// 返回：返回规范化 media type 集与资源上限；非法或无意义配置返回错误。
fn compile_input_plan(cfg: &OpaAuthorizationCfg, route_id: &str) -> Result<OpaInputPlan> {
    if !(1..=MAX_OPA_BODY_BYTES).contains(&cfg.input.max_body_bytes) {
        bail!(
            "route `{route_id}` opa_authorization input.max_body_bytes must be within 1..={MAX_OPA_BODY_BYTES}"
        );
    }
    if cfg.input.content_types.is_empty() || cfg.input.content_types.len() > 32 {
        bail!(
            "route `{route_id}` opa_authorization input.content_types must contain 1..=32 values"
        );
    }
    let mut content_types = HashSet::with_capacity(cfg.input.content_types.len());
    for raw in &cfg.input.content_types {
        let media_type = raw.trim().to_ascii_lowercase();
        if media_type.is_empty()
            || media_type.len() > 128
            || media_type.contains(';')
            || media_type.contains('*')
            || !media_type.is_ascii()
            || !media_type.contains('/')
        {
            bail!("route `{route_id}` opa_authorization input content type `{raw}` is invalid");
        }
        if !content_types.insert(media_type) {
            bail!("route `{route_id}` opa_authorization input content type `{raw}` is duplicated");
        }
    }
    Ok(OpaInputPlan {
        include_body: cfg.input.include_body,
        max_body_bytes: cfg.input.max_body_bytes,
        content_types: Arc::new(content_types),
        include_jwt_claims: cfg.input.include_jwt_claims,
    })
}

/// 业务作用：编译 OPA obligation 白名单，提前排除凭据、hop-by-hop 与 framing header。
///
/// 参数说明：
/// - `cfg`：是 obligation 配置
/// - `route_id`：提供错误定位。
///
/// 返回：返回只读白名单与资源预算；危险、重复或越界名称返回错误。
fn compile_obligation_plan(cfg: &OpaObligationsCfg, route_id: &str) -> Result<OpaObligationPlan> {
    if !(1..=MAX_OPA_OBLIGATION_ENTRIES).contains(&cfg.max_entries)
        || !(1..=MAX_OPA_OBLIGATION_VALUE_BYTES).contains(&cfg.max_value_bytes)
        || !(1..=MAX_OPA_OBLIGATION_BYTES).contains(&cfg.max_bytes)
    {
        bail!("route `{route_id}` opa_authorization obligation bounds are invalid");
    }
    let request_headers =
        compile_mutation_headers(cfg.request_headers.as_slice(), "request_headers", route_id)?;
    let response_headers = compile_mutation_headers(
        cfg.response_headers.as_slice(),
        "response_headers",
        route_id,
    )?;
    let mut audit_metadata = HashSet::with_capacity(cfg.audit_metadata.len());
    if cfg.audit_metadata.len() > MAX_OPA_OBLIGATION_ENTRIES {
        bail!("route `{route_id}` opa_authorization audit_metadata allowlist is too large");
    }
    for key in &cfg.audit_metadata {
        if key.is_empty()
            || key.len() > MAX_OPA_AUDIT_KEY_BYTES
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || !audit_metadata.insert(key.clone())
        {
            bail!(
                "route `{route_id}` opa_authorization audit metadata key `{key}` is invalid or duplicated"
            );
        }
    }
    Ok(OpaObligationPlan {
        request_headers: Arc::new(request_headers),
        response_headers: Arc::new(response_headers),
        audit_metadata: Arc::new(audit_metadata),
        max_entries: cfg.max_entries,
        max_value_bytes: cfg.max_value_bytes,
        max_bytes: cfg.max_bytes,
    })
}

/// 业务作用：解析一组 header mutation allowlist，阻止 OPA 获得认证、连接或 framing 控制权。
///
/// 参数说明：
/// - `raw`：是名称列表
/// - `field`：仅用于错误定位。
/// - `route_id`：仅用于错误定位。
///
/// 返回：返回规范化 HeaderName 集；危险、重复或非法名称返回错误。
fn compile_mutation_headers(
    raw: &[String],
    field: &str,
    route_id: &str,
) -> Result<HashSet<HeaderName>> {
    if raw.len() > MAX_OPA_OBLIGATION_ENTRIES {
        bail!("route `{route_id}` opa_authorization {field} allowlist is too large");
    }
    let mut compiled = HashSet::with_capacity(raw.len());
    for name in raw {
        let parsed = name.parse::<HeaderName>().with_context(|| {
            format!("route `{route_id}` opa_authorization {field} contains invalid header `{name}`")
        })?;
        if FORBIDDEN_MUTATION_HEADERS.contains(&parsed.as_str()) || !compiled.insert(parsed) {
            bail!(
                "route `{route_id}` opa_authorization {field} contains forbidden or duplicate header `{name}`"
            );
        }
    }
    Ok(compiled)
}

/// 业务作用：验证一侧 header obligations 的名称、值、冲突及聚合预算。
///
/// 参数说明：
/// - `headers`：OPA 返回但尚未信任的头部义务。
/// - `allowlist`：当前路由允许修改的头名集合。
/// - `plan`：当前路由的 OPA 安全与资源计划。
/// - `entries`：请求与响应义务共用的条目计数。
/// - `bytes`：请求与响应义务共用的字节计数。
///
/// 返回：全部变更可原子应用时成功，否则返回 dependency error。
fn validate_header_obligations(
    headers: &HeaderObligations,
    allowlist: &HashSet<HeaderName>,
    plan: &OpaObligationPlan,
    entries: &mut usize,
    bytes: &mut usize,
) -> Result<()> {
    let mut seen = HashSet::with_capacity(headers.set.len() + headers.remove.len());
    for (name, value) in &headers.set {
        let parsed = name
            .parse::<HeaderName>()
            .context("OPA obligation contains invalid header name")?;
        if !allowlist.contains(&parsed)
            || FORBIDDEN_MUTATION_HEADERS.contains(&parsed.as_str())
            || !seen.insert(parsed)
            || value.len() > plan.max_value_bytes
            || HeaderValue::from_str(value).is_err()
        {
            bail!("OPA header obligation is forbidden, duplicated, or invalid");
        }
        *entries = entries
            .checked_add(1)
            .context("OPA obligation count overflow")?;
        *bytes = bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .context("OPA obligation byte count overflow")?;
    }
    for name in &headers.remove {
        let parsed = name
            .parse::<HeaderName>()
            .context("OPA obligation contains invalid header name")?;
        if !allowlist.contains(&parsed)
            || FORBIDDEN_MUTATION_HEADERS.contains(&parsed.as_str())
            || !seen.insert(parsed)
        {
            bail!("OPA header removal is forbidden or duplicated");
        }
        *entries = entries
            .checked_add(1)
            .context("OPA obligation count overflow")?;
        *bytes = bytes
            .checked_add(name.len())
            .context("OPA obligation byte count overflow")?;
    }
    Ok(())
}

/// 业务作用：应用已经完整验证的 header 变更；remove 先于 set，避免多值残留和部分状态。
///
/// 参数说明：
/// - `target`：是请求或响应头
/// - `changes`：是可信 obligations。
///
/// 返回：无；解析失败在先前验证后不可达，防御性跳过也不会放大权限。
fn apply_header_obligations(target: &mut HeaderMap, changes: &HeaderObligations) {
    for name in &changes.remove {
        if let Ok(name) = name.parse::<HeaderName>() {
            target.remove(name);
        }
    }
    for (name, value) in &changes.set {
        if let (Ok(name), Ok(value)) = (name.parse::<HeaderName>(), HeaderValue::from_str(value)) {
            target.insert(name, value);
        }
    }
}

/// 业务作用：读取、验证并有界解包标准 OPA tar.gz bundle，形成尚未发布的候选策略材料。
///
/// 参数说明：
/// - `cfg`：声明 bundle/签名/上限
/// - `config_dir`：解析相对路径
/// - `route_id`：定位错误。
///
/// 返回：签名、archive、manifest、Rego/data 全合法时返回候选；失败不会改变当前 snapshot。
fn load_signed_bundle(
    cfg: &OpaBundleCfg,
    config_dir: &Path,
    route_id: &str,
) -> Result<LoadedOpaBundle> {
    if !(1..=MAX_OPA_BUNDLE_BYTES).contains(&cfg.max_bundle_bytes)
        || !(1..=MAX_OPA_BUNDLE_EXPANDED_BYTES).contains(&cfg.max_expanded_bytes)
        || !(1..=MAX_OPA_BUNDLE_FILES).contains(&cfg.max_files)
    {
        bail!("route `{route_id}` OPA bundle resource bounds are invalid");
    }
    let source = resolve_bundle_path(config_dir, cfg.source.as_str())?;
    let compressed = crate::io::bounded_io::read_file(
        &source,
        cfg.max_bundle_bytes,
        &format!("route `{route_id}` OPA bundle"),
    )?;
    let signing_key = verify_bundle_signature(&compressed, cfg, config_dir, route_id)?;
    // 材料身份与验签、解包使用同一份字节，避免比较期间重读文件或序列化 Rego/data。
    let identity = BundleIdentity {
        material: Sha256::digest(&compressed).into(),
        signing_key,
        max_bundle_bytes: cfg.max_bundle_bytes,
        max_expanded_bytes: cfg.max_expanded_bytes,
        max_files: cfg.max_files,
    };

    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(compressed.as_slice())));
    let mut modules = BTreeMap::new();
    let mut data = serde_json::json!({});
    let mut manifest = None;
    let mut expanded = 0usize;
    let mut files = 0usize;
    for entry in archive.entries().context("read OPA bundle archive")? {
        let mut entry = entry.context("read OPA bundle entry")?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            bail!("route `{route_id}` OPA bundle links and special entries are forbidden");
        }
        files = files
            .checked_add(1)
            .context("OPA bundle file count overflow")?;
        if files > cfg.max_files {
            bail!("route `{route_id}` OPA bundle exceeds file-count limit");
        }
        let path = entry.path().context("decode OPA bundle entry path")?;
        validate_bundle_entry_path(path.as_ref(), route_id)?;
        let name = path
            .to_str()
            .context("OPA bundle entry path must be UTF-8")?
            .trim_start_matches("./")
            .to_string();
        let declared = usize::try_from(entry.size()).context("OPA bundle entry size overflow")?;
        expanded = expanded
            .checked_add(declared)
            .context("OPA bundle expanded size overflow")?;
        if expanded > cfg.max_expanded_bytes {
            bail!("route `{route_id}` OPA bundle exceeds expanded-size limit");
        }
        let mut bytes = Vec::with_capacity(declared.min(64 * 1024));
        entry
            .by_ref()
            .take(declared.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .context("read OPA bundle entry")?;
        if bytes.len() != declared {
            bail!("route `{route_id}` OPA bundle entry size is inconsistent");
        }
        if name == ".manifest" {
            if manifest.is_some() {
                bail!("route `{route_id}` OPA bundle contains duplicate manifest");
            }
            manifest = Some(
                serde_json::from_slice::<OpaBundleManifest>(&bytes)
                    .context("decode OPA bundle manifest")?,
            );
        } else if name.ends_with(".rego") {
            let source = String::from_utf8(bytes).context("OPA Rego module must be UTF-8")?;
            modules.insert(name, source);
        } else if name == "data.json" || name.ends_with("/data.json") {
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).context("decode OPA bundle data.json")?;
            merge_bundle_data(&mut data, Path::new(&name), value, route_id)?;
        }
    }
    if modules.is_empty() {
        bail!("route `{route_id}` OPA bundle contains no Rego module");
    }
    let digest_hex = hex_digest(&identity.material);
    let revision = manifest
        .map(|manifest| manifest.revision)
        .filter(|revision| !revision.trim().is_empty())
        .unwrap_or(digest_hex);
    validate_policy_revision(revision.as_str(), route_id)?;
    Ok(LoadedOpaBundle {
        revision: Arc::from(revision),
        modules,
        data,
        identity,
    })
}

/// 业务作用：验证 detached Ed25519 signature，防止未授权 bundle 在编译前进入候选策略。
///
/// 参数说明：
/// - `bundle`：未改写的 bundle 原始压缩字节。
/// - `cfg`：提供签名算法、密钥与签名来源的策略。
/// - `config_dir`：SecretSource 相对路径解析根。
/// - `route_id`：用于低敏错误定位的 route 标识。
///
/// 返回：签名严格匹配时返回实际固定公钥；长度、Base64、key 或签名错误均拒绝候选。
fn verify_bundle_signature(
    bundle: &[u8],
    cfg: &OpaBundleCfg,
    config_dir: &Path,
    route_id: &str,
) -> Result<[u8; 32]> {
    let signature = crate::security::secret::resolve_text(
        cfg.signature.as_str(),
        config_dir,
        &format!("route `{route_id}` OPA bundle signature"),
    )?;
    let public_key = crate::security::secret::resolve_text(
        cfg.public_key.as_str(),
        config_dir,
        &format!("route `{route_id}` OPA bundle public key"),
    )?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .context("decode OPA bundle Ed25519 signature")?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .context("decode OPA bundle Ed25519 public key")?;
    let signature = Signature::from_slice(signature.as_slice())
        .context("OPA bundle Ed25519 signature must be 64 bytes")?;
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("OPA bundle Ed25519 public key must be 32 bytes"))?;
    let key =
        VerifyingKey::from_bytes(&key_bytes).context("decode OPA bundle Ed25519 public key")?;
    key.verify_strict(bundle, &signature)
        .context("verify OPA bundle Ed25519 signature")?;
    Ok(key_bytes)
}

#[cfg(feature = "opa-embedded")]
/// 业务作用：把已验签 bundle 编译为可 clone 的 Regorus 模板，并在发布前验证 query 语法。
///
/// 参数说明：
/// - `bundle`：是候选材料
/// - `query`：是规则路径
/// - `route_id`：定位错误。
///
/// 返回：全部 module/data 编译成功时返回模板；任何 Rego/data/query 错误拒绝候选。
fn build_embedded_engine(
    bundle: LoadedOpaBundle,
    query: &str,
    route_id: &str,
) -> Result<EmbeddedOpa> {
    validate_embedded_query(query, route_id)?;
    let mut engine = regorus::Engine::new();
    for (name, source) in bundle.modules {
        engine
            .add_policy(name, source)
            .with_context(|| format!("route `{route_id}` compile OPA Rego module"))?;
    }
    engine
        .add_data(regorus::Value::from_json_str(&serde_json::to_string(
            &bundle.data,
        )?)?)
        .with_context(|| format!("route `{route_id}` compile OPA bundle data"))?;
    // 空 input 的 undefined 是合法业务结果；eval_rule 的语法/路径错误必须在换版前暴露。
    engine.set_input(regorus::Value::new_object());
    let _ = engine
        .eval_rule(query.to_string())
        .with_context(|| format!("route `{route_id}` validate embedded OPA query"))?;
    Ok(EmbeddedOpa {
        template: engine,
        query: Arc::from(query),
        bundle: bundle.identity,
    })
}

#[cfg(feature = "opa-embedded")]
/// 业务作用：限制 embedded query 为 `data.<package>.<rule>` 静态路径，禁止请求期动态表达式扩权。
///
/// 参数说明：
/// - `query`：是配置值
/// - `route_id`：定位错误。
///
/// 返回：静态标识符路径合法时成功，否则拒绝候选。
fn validate_embedded_query(query: &str, route_id: &str) -> Result<()> {
    let mut parts = query.split('.');
    if parts.next() != Some("data") {
        bail!("route `{route_id}` embedded OPA query must start with `data.`");
    }
    let rest = parts.collect::<Vec<_>>();
    if rest.len() < 2
        || rest.iter().any(|part| {
            part.is_empty()
                || !part.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
        })
    {
        bail!("route `{route_id}` embedded OPA query is not a static rule path");
    }
    Ok(())
}

/// 业务作用：把根或子目录 data.json 合并到 OPA data 文档，并拒绝类型冲突与覆盖。
///
/// 参数说明：
/// - `root`：是累计 data
/// - `path`：是 archive 路径
/// - `value`：是当前 JSON
/// - `route_id`：定位错误。
///
/// 返回：无冲突合并成功；非对象中间节点、重复 key 或根非对象返回错误。
fn merge_bundle_data(
    root: &mut serde_json::Value,
    path: &Path,
    value: serde_json::Value,
    route_id: &str,
) -> Result<()> {
    let mut target = root;
    let components = path.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(component) = component else {
            bail!("route `{route_id}` OPA bundle data path is invalid");
        };
        let key = component
            .to_str()
            .context("OPA bundle data path must be UTF-8")?;
        let object = target
            .as_object_mut()
            .context("OPA bundle data path conflicts with non-object value")?;
        target = object
            .entry(key.to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
    merge_json_object(target, value, route_id)
}

/// 业务作用：递归合并 OPA data object，拒绝后文件覆盖先前事实导致 archive 顺序依赖。
///
/// 参数说明：
/// - `target`：是累计节点
/// - `incoming`：是新节点
/// - `route_id`：定位冲突。
///
/// 返回：对象键互不冲突时成功；标量/数组重复或类型冲突返回错误。
fn merge_json_object(
    target: &mut serde_json::Value,
    incoming: serde_json::Value,
    route_id: &str,
) -> Result<()> {
    let incoming = incoming
        .as_object()
        .context("OPA bundle data.json root must be an object")?;
    let target = target
        .as_object_mut()
        .context("OPA bundle data target must be an object")?;
    for (key, value) in incoming {
        if target.contains_key(key) {
            bail!("route `{route_id}` OPA bundle data contains duplicate key `{key}`");
        }
        target.insert(key.clone(), value.clone());
    }
    Ok(())
}

/// 业务作用：拒绝 archive 绝对路径、父目录与平台前缀，防止 bundle 解包语义发生路径穿越。
///
/// 参数说明：
/// - `path`：是 tar entry path
/// - `route_id`：定位错误。
///
/// 返回：仅包含当前目录/普通组件且最终非空时成功。
fn validate_bundle_entry_path(path: &Path, route_id: &str) -> Result<()> {
    let mut normal = 0usize;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => normal += 1,
            _ => bail!("route `{route_id}` OPA bundle entry path traversal is forbidden"),
        }
    }
    if normal == 0 {
        bail!("route `{route_id}` OPA bundle entry path is empty");
    }
    Ok(())
}

/// 业务作用：解析 bundle 本地依赖路径，禁止 URL 或空来源混入同步候选构建。
///
/// 参数说明：
/// - `config_dir`：是根配置目录
/// - `raw`：是配置 path。
///
/// 返回：返回绝对或相对解析路径；空值与 URL 返回错误。
fn resolve_bundle_path(config_dir: &Path, raw: &str) -> Result<PathBuf> {
    if raw.trim().is_empty() || raw.contains("://") {
        bail!("OPA bundle source must be a non-empty local path");
    }
    let path = Path::new(raw);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    })
}

/// 业务作用：收集 OPA bundle、签名、公钥与外部凭据文件依赖，使独立替换也进入同一原子 reload。
///
/// 参数说明：
/// - `config_dir`：是根配置目录
/// - `cfg`：是 route OPA 配置。
///
/// 返回：返回不含 secret 内容的文件路径；literal/env source 不产生路径。
pub(crate) fn dependency_paths(config_dir: &Path, cfg: &OpaAuthorizationCfg) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(4);
    if let Some(path) = crate::security::secret::dependency_path(&cfg.authorization, config_dir) {
        paths.push(path);
    }
    if let Some(bundle) = &cfg.bundle {
        if !bundle.source.trim().is_empty() && !bundle.source.contains("://") {
            let source = Path::new(&bundle.source);
            paths.push(if source.is_absolute() {
                source.to_path_buf()
            } else {
                config_dir.join(source)
            });
        }
        for secret in [&bundle.signature, &bundle.public_key] {
            if let Some(path) = crate::security::secret::dependency_path(secret, config_dir) {
                paths.push(path);
            }
        }
    }
    paths
}

/// 业务作用：对可选 JSON 输入做无歧义流式哈希，确保 claims/body 变化必然形成不同 decision key。
///
/// 参数说明：
/// - `hasher`：是当前 key 摘要
/// - `value`：为可选可信 JSON。
///
/// 返回：序列化成功时更新摘要；理论编码错误映射为本地输入错误。
fn hash_optional_json(
    hasher: &mut Sha256,
    value: Option<&serde_json::Value>,
) -> std::result::Result<(), OpaInputError> {
    match value {
        Some(value) => {
            hasher.update([1]);
            serde_json::to_writer(DigestWriter(hasher), value)
                .map_err(|_| OpaInputError::Encode)?;
        }
        None => hasher.update([0]),
    }
    Ok(())
}

struct DigestWriter<'a>(&'a mut Sha256);

impl Write for DigestWriter<'_> {
    /// 业务作用：把策略身份相关字节直接送入摘要，避免为计算缓存身份再保存一份完整输入。
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：完成摘要写入接口的刷新合同，不改变已累计的策略身份。
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 业务作用：生成不含原始身份/输入的稳定十六进制摘要，可安全用作 DynamicStore key。
///
/// 参数说明：
/// - `bytes`：是固定长度密码学摘要。
///
/// 返回：返回小写十六进制字符串。
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing digest hex cannot fail");
    }
    output
}

/// 业务作用：验证 DynamicStore collection 组件，阻止分隔符注入其它业务命名空间。
///
/// 参数说明：
/// - `value`：是 collection
/// - `field`：定位错误。
/// - `route_id`：定位错误。
///
/// 返回：1..=128 的安全 ASCII 组件成功，否则返回错误。
fn validate_store_component(value: &str, field: &str, route_id: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("route `{route_id}` opa_authorization {field} is invalid");
    }
    Ok(())
}

/// 业务作用：提供进程内单调毫秒时钟，退避 deadline 不受系统时间回拨影响。
///
/// 参数说明: 无。
///
/// 返回：进程首次调用以来的饱和毫秒数。
fn monotonic_millis() -> u64 {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// 业务作用：生成跨节点可比较的绝对毫秒时间，用于 cache 值自描述过期而不依赖 store TTL 语义。
///
/// 参数说明: 无。
///
/// 返回：返回 UNIX epoch 毫秒；系统时间早于 epoch 时返回错误并禁止缓存。
fn unix_millis() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis()
        .min(u128::from(u64::MAX)) as u64)
}

/// 业务作用：冻结 OPA 固定调用目标，拒绝不支持协议或客户端可控目的地。
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

/// 业务作用：校验 OPA Data API 路径，明确目标策略而不开放任意外部接口。
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

/// 业务作用：编译 OPA 调用允许附带的头部，禁止覆盖传输关键字段。
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

/// 业务作用：识别授权输出允许修改的头名，保护认证、分帧和连接语义。
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

/// 业务作用：限制策略修订标识的格式，使缓存身份与观测标签保持有界。
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

/// 业务作用：把策略目标、修订和输入权限绑定到缓存域，防止不同授权合同复用旧决定。
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

/// 业务作用：为摘要输入添加字段边界，避免不同策略字段拼接成相同缓存身份。
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
