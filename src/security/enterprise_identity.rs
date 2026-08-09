//! 可选企业身份协议适配。
//!
//! SAML 与 LDAP 都在 route 构建期锁定信任源、资源门和身份 header allowlist；数据面只执行
//! 已编译计划。协议 feature 关闭时配置会被明确拒绝，默认制品不携带 XML Signature 或 LDAP client。

use std::path::Path;
#[cfg(feature = "enterprise-saml")]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
use std::time::Duration;

#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
use anyhow::Context;
use anyhow::{bail, Result};
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;

#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
const MAX_IDENTITY_VALUE_BYTES: usize = 256;
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
const MAX_IDENTITY_HEADERS: usize = 16;

/// 企业身份认证成功后生成的请求局部结果。
#[cfg_attr(
    not(any(feature = "enterprise-saml", feature = "enterprise-ldap")),
    allow(dead_code)
)]
pub(crate) enum EnterpriseAuthResult {
    /// 当前 policy 的凭据来源没有出现在请求中。
    Missing,
    /// 凭据出现但认证、协议或依赖校验失败；调用方必须 fail closed。
    Rejected,
    /// 身份经过协议验证，可作为本地认证主体并生成受信 header。
    Authenticated {
        consumer: Arc<str>,
        headers: Vec<(HeaderName, HeaderValue)>,
    },
}

/// route 级可选企业身份策略。
#[derive(Clone)]
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
pub(crate) enum EnterpriseAuthPolicy {
    #[cfg(feature = "enterprise-saml")]
    Saml(Arc<SamlPolicy>),
    #[cfg(feature = "enterprise-ldap")]
    Ldap(Arc<LdapPolicy>),
}

#[derive(Clone)]
#[cfg(not(any(feature = "enterprise-saml", feature = "enterprise-ldap")))]
pub(crate) struct EnterpriseAuthPolicy;

#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
impl EnterpriseAuthPolicy {
    /// 业务作用：按已编译协议验证当前请求，统一返回缺失、拒绝或可信主体。
    ///
    /// 参数说明：`parts` 是尚未接受外部授权 header 注入的请求 head。
    ///
    /// 返回：认证成功携带 consumer/身份头；凭据缺失与认证失败保持可区分状态。
    pub(crate) async fn authenticate(
        &self,
        parts: &Parts,
        _saml_response: Option<&str>,
    ) -> EnterpriseAuthResult {
        match self {
            #[cfg(feature = "enterprise-saml")]
            Self::Saml(policy) => policy.authenticate(parts, _saml_response),
            #[cfg(feature = "enterprise-ldap")]
            Self::Ldap(policy) => policy.authenticate(parts).await,
        }
    }

    /// 业务作用：声明本策略是否需要读取标准 SAML HTTP-POST form，以及允许的最大 form 字节数。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：body binding 的 SAML 策略返回有界 form 上限；header 兼容模式与 LDAP 返回 None。
    pub(crate) fn saml_form_body_limit(&self) -> Option<usize> {
        match self {
            #[cfg(feature = "enterprise-saml")]
            Self::Saml(policy) => policy
                .source_header
                .is_none()
                .then_some(policy.max_assertion_bytes.saturating_add(16 * 1024)),
            #[cfg(feature = "enterprise-ldap")]
            Self::Ldap(_) => None,
        }
    }

    /// 业务作用：列出本策略由网关拥有的身份 header，供认证结果提交前清除客户端同名值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回构建期去重后的 header 名切片。
    pub(crate) fn owned_headers(&self) -> &[HeaderName] {
        match self {
            #[cfg(feature = "enterprise-saml")]
            Self::Saml(policy) => policy.owned_headers.as_ref(),
            #[cfg(feature = "enterprise-ldap")]
            Self::Ldap(policy) => policy.owned_headers.as_ref(),
        }
    }
}

#[cfg(not(any(feature = "enterprise-saml", feature = "enterprise-ldap")))]
impl EnterpriseAuthPolicy {
    /// 业务作用：为默认制品保留统一调用面；协议配置会在构建期拒绝，因此该路径不可到达。
    ///
    /// 参数说明：`parts` 是请求 head，仅用于保持 feature 间签名一致。
    ///
    /// 返回：始终返回拒绝，防止不可达状态意外放行。
    pub(crate) async fn authenticate(
        &self,
        _parts: &Parts,
        _saml_response: Option<&str>,
    ) -> EnterpriseAuthResult {
        EnterpriseAuthResult::Rejected
    }

    /// 业务作用：默认制品不声明 SAML body 慢路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：始终返回 None。
    pub(crate) fn saml_form_body_limit(&self) -> Option<usize> {
        None
    }

    /// 业务作用：默认制品没有企业身份 header 所有权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：空切片。
    pub(crate) fn owned_headers(&self) -> &[HeaderName] {
        &[]
    }
}

/// 业务作用：解析 `saml_auth` route DSL，并在快照发布前验证 metadata 签名与 SP/IdP 绑定。
///
/// 参数说明：`spec` 是 filter 原文，`config_dir` 是文件型来源相对目录。
///
/// 返回：feature 启用且全部信任材料有效时返回策略；否则拒绝候选快照。
pub(crate) fn parse_saml_auth(spec: &str, config_dir: &Path) -> Result<EnterpriseAuthPolicy> {
    #[cfg(feature = "enterprise-saml")]
    {
        SamlPolicy::parse(spec, config_dir)
            .map(|policy| EnterpriseAuthPolicy::Saml(Arc::new(policy)))
    }
    #[cfg(not(feature = "enterprise-saml"))]
    {
        let _ = (spec, config_dir);
        bail!("saml_auth requires the enterprise-saml feature")
    }
}

/// 业务作用：解析 `ldap_auth` route DSL，并锁定 TLS、bind、搜索模板与并发资源门。
///
/// 参数说明：`spec` 是 filter 原文，`config_dir` 是 SecretSource 相对目录。
///
/// 返回：feature 启用且配置安全时返回策略；否则拒绝候选快照。
pub(crate) fn parse_ldap_auth(spec: &str, config_dir: &Path) -> Result<EnterpriseAuthPolicy> {
    #[cfg(feature = "enterprise-ldap")]
    {
        LdapPolicy::parse(spec, config_dir)
            .map(|policy| EnterpriseAuthPolicy::Ldap(Arc::new(policy)))
    }
    #[cfg(not(feature = "enterprise-ldap"))]
    {
        let _ = (spec, config_dir);
        bail!("ldap_auth requires the enterprise-ldap feature")
    }
}

#[cfg(feature = "enterprise-saml")]
pub(crate) struct SamlPolicy {
    sp: saml_rs::Saml<saml_rs::Sp>,
    idp: saml_rs::IdpDescriptor,
    source_header: Option<HeaderName>,
    mappings: Arc<Vec<IdentityMapping>>,
    owned_headers: Arc<Vec<HeaderName>>,
    clock_skew: saml_rs::ClockSkew,
    replay_ttl: Duration,
    replay: parking_lot::Mutex<std::collections::HashMap<String, std::time::SystemTime>>,
    max_assertion_bytes: usize,
}

#[cfg(feature = "enterprise-saml")]
impl SamlPolicy {
    /// 业务作用：构建严格 SAML SP，metadata 必须由固定证书签名，入站 Response 与 Assertion 都必须签名。
    ///
    /// 参数说明：`spec` 是 DSL 原文，`config_dir` 是 metadata/证书相对目录。
    ///
    /// 返回：返回不可变 SP/IdP 验证计划；缺失信任材料或弱配置返回错误。
    fn parse(spec: &str, config_dir: &Path) -> Result<Self> {
        use saml_rs::{
            AcsEndpoint, AuthnRequestSigningPolicy, CertificatePem, EntityId, IdpDescriptor,
            MetadataTrustPolicy, Saml, SpConfig, SpValidationPolicy,
        };

        let options = parse_options(spec, "saml_auth")?;
        validate_option_keys(
            &options,
            &[
                "metadata",
                "metadata_signing_cert",
                "idp_entity_id",
                "sp_entity_id",
                "acs",
                "header",
                "max_assertion_bytes",
                "clock_skew_secs",
                "replay_ttl_secs",
                "identity_headers",
            ],
            "saml_auth",
        )?;
        let metadata_source = required_option(&options, "metadata", "saml_auth")?;
        let metadata_certificate = required_option(&options, "metadata_signing_cert", "saml_auth")?;
        let idp_entity_id = required_option(&options, "idp_entity_id", "saml_auth")?;
        let sp_entity_id = required_option(&options, "sp_entity_id", "saml_auth")?;
        let acs = required_option(&options, "acs", "saml_auth")?;
        let source_header = option(&options, "header")
            .map(str::parse::<HeaderName>)
            .transpose()
            .context("saml_auth invalid header")?;
        let max_assertion_bytes = parse_usize_option(
            &options,
            "max_assertion_bytes",
            256 * 1024,
            1_024,
            1024 * 1024,
            "saml_auth",
        )?;
        let skew_secs = parse_i64_option(&options, "clock_skew_secs", 60, 0, 3_600, "saml_auth")?;
        let replay_ttl_secs =
            parse_u64_option(&options, "replay_ttl_secs", 300, 1, 86_400, "saml_auth")?;
        let mappings = parse_identity_mappings(option(&options, "identity_headers"))?;
        if source_header.as_ref().is_some_and(|source_header| {
            mappings
                .iter()
                .any(|mapping| mapping.header == *source_header)
        }) {
            bail!("saml_auth source header cannot also be an identity output header");
        }
        let owned_headers = mappings
            .iter()
            .map(|mapping| mapping.header.clone())
            .collect();

        let metadata = read_file_source(
            metadata_source,
            config_dir,
            max_assertion_bytes,
            "SAML metadata",
        )?;
        let certificate = crate::secret::resolve_text(
            metadata_certificate,
            config_dir,
            "SAML metadata signing certificate",
        )?;
        let trusted = [CertificatePem::new(certificate)];
        let idp = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new(idp_entity_id)?,
            &metadata,
            MetadataTrustPolicy::RequireSignature {
                trusted_certificates: &trusted,
            },
        )
        .context("validate pinned SAML IdP metadata")?;
        let mut inbound = SpValidationPolicy::strict();
        // 本策略只消费 IdP-initiated bearer Response，不创建 AuthnRequest；关闭出站签名不削弱
        // Response/Assertion 双签名、audience、destination、recipient 或时间验证。
        inbound.authn_requests = AuthnRequestSigningPolicy::DoNotSignForCompatibility;
        let sp = Saml::sp(
            SpConfig::builder(EntityId::try_new(sp_entity_id)?)
                .acs_endpoint(AcsEndpoint::post(acs)?)
                .validation(inbound)
                .build()?,
        )
        .context("build strict SAML service provider")?;
        Ok(Self {
            sp,
            idp,
            source_header,
            mappings: Arc::new(mappings),
            owned_headers: Arc::new(owned_headers),
            // 容差必须向两侧扩展有效窗：NotBefore 负偏移、NotOnOrAfter 正偏移；同号会缩短
            // 新断言的有效窗并把正常 IdP 响应错误拒绝。
            clock_skew: saml_rs::ClockSkew::from_millis(
                skew_secs.saturating_mul(-1_000),
                skew_secs.saturating_mul(1_000),
            ),
            replay_ttl: Duration::from_secs(replay_ttl_secs),
            replay: parking_lot::Mutex::new(std::collections::HashMap::new()),
            max_assertion_bytes,
        })
    }

    /// 业务作用：验证 HTTP POST binding 形式的 SAMLResponse bearer，防重放后提取 NameID/属性。
    ///
    /// 参数说明：`parts` 是请求 head，`saml_response` 是标准 HTTP-POST form 中有界提取的 Base64 值；
    /// 显式 `header=` 兼容模式只读取固定 header 并忽略该参数。
    ///
    /// 返回：双签名、信任、audience/recipient/time/replay 全部通过才返回可信身份；其它情况拒绝。
    fn authenticate(&self, parts: &Parts, saml_response: Option<&str>) -> EnterpriseAuthResult {
        use saml_rs::{BrowserInput, FormField, ReplayPolicy, SamlValidationContext, SsoResponse};

        let encoded = self.source_header.as_ref().map_or(saml_response, |header| {
            parts
                .headers
                .get(header)
                .and_then(|value| value.to_str().ok())
        });
        let Some(encoded) = encoded.map(str::trim) else {
            return EnterpriseAuthResult::Missing;
        };
        if encoded.is_empty() || encoded.len() > self.max_assertion_bytes {
            return EnterpriseAuthResult::Rejected;
        }
        let mut replay = SharedSamlReplay {
            state: &self.replay,
            max_entries: 100_000,
        };
        let validation = SamlValidationContext::new(
            std::time::SystemTime::now(),
            ReplayPolicy::RequireCache(&mut replay),
        )
        .with_clock_skew(self.clock_skew)
        .with_replay_retention(self.replay_ttl);
        let input =
            BrowserInput::<SsoResponse>::post(vec![FormField::new("SAMLResponse", encoded)]);
        let session = match self.sp.accept_unsolicited_sso(&self.idp, input, validation) {
            Ok(session) => session,
            Err(error) => {
                tracing::debug!(%error, "SAML response validation rejected");
                return EnterpriseAuthResult::Rejected;
            }
        };
        let Some(consumer) = bounded_identity(session.name_id().value()) else {
            return EnterpriseAuthResult::Rejected;
        };
        let mut headers = Vec::with_capacity(self.mappings.len());
        for mapping in self.mappings.iter() {
            let value = if mapping.source.as_ref() == "nameid" {
                session.name_id().value()
            } else {
                let Some(attribute) = session.attributes().get(mapping.source.as_ref()) else {
                    continue;
                };
                if attribute.values().len() != 1 {
                    return EnterpriseAuthResult::Rejected;
                }
                attribute.values()[0].as_str()
            };
            let Some(value) = bounded_header_value(value) else {
                return EnterpriseAuthResult::Rejected;
            };
            headers.push((mapping.header.clone(), value));
        }
        EnterpriseAuthResult::Authenticated { consumer, headers }
    }
}

#[cfg(feature = "enterprise-saml")]
struct SharedSamlReplay<'a> {
    state: &'a parking_lot::Mutex<std::collections::HashMap<String, std::time::SystemTime>>,
    max_entries: usize,
}

#[cfg(feature = "enterprise-saml")]
impl saml_rs::ReplayCache for SharedSamlReplay<'_> {
    fn check_and_store(
        &mut self,
        key: saml_rs::ReplayKey,
        expires_at: std::time::SystemTime,
    ) -> std::result::Result<(), saml_rs::SamlError> {
        let now = std::time::SystemTime::now();
        let mut state = self.state.lock();
        state.retain(|_, expiry| *expiry > now);
        let cache_key = key.cache_key();
        if state.contains_key(&cache_key) {
            return Err(saml_rs::SamlError::ReplayDetected { key: cache_key });
        }
        if state.len() >= self.max_entries {
            return Err(saml_rs::SamlError::Invalid(
                "SAML replay cache capacity reached".to_owned(),
            ));
        }
        state.insert(cache_key, expires_at);
        Ok(())
    }
}

#[cfg(feature = "enterprise-ldap")]
pub(crate) struct LdapPolicy {
    url: Arc<str>,
    settings: ldap3::LdapConnSettings,
    bind_dn: Arc<str>,
    bind_password: Arc<str>,
    base_dn: Arc<str>,
    user_filter: Arc<str>,
    mappings: Arc<Vec<IdentityMapping>>,
    owned_headers: Arc<Vec<HeaderName>>,
    timeout: Duration,
    permits: Arc<tokio::sync::Semaphore>,
    pool: tokio::sync::Mutex<Vec<ldap3::Ldap>>,
    max_connections: usize,
}

#[cfg(feature = "enterprise-ldap")]
impl LdapPolicy {
    /// 业务作用：编译 LDAP 目录认证计划，强制 LDAPS/StartTLS、服务 bind 与有界唯一用户搜索。
    ///
    /// 参数说明：`spec` 是 DSL 原文，`config_dir` 是 bind secret/CA 相对目录。
    ///
    /// 返回：返回带连接并发池和固定搜索模板的策略；明文 LDAP、匿名 bind 或无界参数返回错误。
    fn parse(spec: &str, config_dir: &Path) -> Result<Self> {
        let options = parse_options(spec, "ldap_auth")?;
        validate_option_keys(
            &options,
            &[
                "url",
                "starttls",
                "bind_dn",
                "bind_password",
                "base_dn",
                "user_filter",
                "timeout_ms",
                "max_connections",
                "identity_headers",
                "ca_certificate",
            ],
            "ldap_auth",
        )?;
        let url = required_option(&options, "url", "ldap_auth")?;
        let starttls = parse_bool_option(&options, "starttls", false, "ldap_auth")?;
        if !(url.starts_with("ldaps://") || url.starts_with("ldap://") && starttls) {
            bail!("ldap_auth requires ldaps:// or ldap:// with starttls=true");
        }
        let bind_dn = crate::secret::resolve_text(
            required_option(&options, "bind_dn", "ldap_auth")?,
            config_dir,
            "LDAP bind DN",
        )?;
        let bind_password = crate::secret::resolve_text(
            required_option(&options, "bind_password", "ldap_auth")?,
            config_dir,
            "LDAP bind password",
        )?;
        if bind_dn.is_empty() || bind_password.is_empty() {
            bail!("ldap_auth forbids anonymous service bind");
        }
        let base_dn = required_option(&options, "base_dn", "ldap_auth")?;
        let user_filter = option(&options, "user_filter").unwrap_or("(uid={username})");
        if user_filter.matches("{username}").count() != 1
            || user_filter.len() > 1_024
            || !user_filter.starts_with('(')
            || !user_filter.ends_with(')')
        {
            bail!("ldap_auth user_filter must be a bounded LDAP filter with one {{username}}");
        }
        let timeout_ms = parse_u64_option(&options, "timeout_ms", 1_000, 1, 60_000, "ldap_auth")?;
        let max_connections =
            parse_usize_option(&options, "max_connections", 32, 1, 1_024, "ldap_auth")?;
        let mappings = parse_identity_mappings(option(&options, "identity_headers"))?;
        let owned_headers = mappings
            .iter()
            .map(|mapping| mapping.header.clone())
            .collect();
        let mut settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(Duration::from_millis(timeout_ms))
            .set_starttls(starttls);
        if let Some(source) = option(&options, "ca_certificate") {
            let pem = crate::secret::resolve_text(source, config_dir, "LDAP CA certificate")?;
            settings = settings.set_config(ldap_tls_config(&pem)?);
        }
        Ok(Self {
            url: Arc::from(url),
            settings,
            bind_dn: Arc::from(bind_dn),
            bind_password: Arc::from(bind_password),
            base_dn: Arc::from(base_dn),
            user_filter: Arc::from(user_filter),
            mappings: Arc::new(mappings),
            owned_headers: Arc::new(owned_headers),
            timeout: Duration::from_millis(timeout_ms),
            permits: Arc::new(tokio::sync::Semaphore::new(max_connections)),
            pool: tokio::sync::Mutex::new(Vec::new()),
            max_connections,
        })
    }

    /// 业务作用：用 Basic 用户凭据执行服务 bind→唯一搜索→用户 bind，并复用已恢复服务身份的连接。
    ///
    /// 参数说明：`parts` 是请求 head，用户名只经 RFC 4515 转义后进入固定 filter 占位符。
    ///
    /// 返回：唯一目录项且用户 bind 成功才返回可信主体；坏凭据或依赖/超时均拒绝。
    async fn authenticate(&self, parts: &Parts) -> EnterpriseAuthResult {
        let Some((username, password)) = ldap_basic_credentials(parts) else {
            return EnterpriseAuthResult::Missing;
        };
        if username.is_empty()
            || username.len() > MAX_IDENTITY_VALUE_BYTES
            || password.is_empty()
            || password.len() > 4_096
        {
            return EnterpriseAuthResult::Rejected;
        }
        let Ok(permit) =
            tokio::time::timeout(self.timeout, self.permits.clone().acquire_owned()).await
        else {
            return EnterpriseAuthResult::Rejected;
        };
        let Ok(permit) = permit else {
            return EnterpriseAuthResult::Rejected;
        };
        let result = tokio::time::timeout(
            self.timeout,
            self.authenticate_inner(username.as_str(), password.as_str()),
        )
        .await;
        drop(permit);
        match result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                tracing::warn!(%error, "LDAP authentication dependency failed");
                EnterpriseAuthResult::Rejected
            }
            Err(_) => EnterpriseAuthResult::Rejected,
        }
    }

    /// 业务作用：在单一总期限内完成 LDAP bind/search，并只把恢复为服务身份的连接放回池。
    ///
    /// 参数说明：`username`/`password` 已通过请求级长度门，但仍属于不可信凭据。
    ///
    /// 返回：目录认证结果；网络/协议错误返回失败且连接不复用。
    async fn authenticate_inner(
        &self,
        username: &str,
        password: &str,
    ) -> Result<EnterpriseAuthResult> {
        use ldap3::{Scope, SearchEntry, SearchOptions};

        let mut ldap = match self.pool.lock().await.pop() {
            Some(ldap) => ldap,
            None => self.connect().await?,
        };
        let service = ldap
            .simple_bind(self.bind_dn.as_ref(), self.bind_password.as_ref())
            .await?;
        service.success().context("LDAP service bind rejected")?;
        let filter = self
            .user_filter
            .replace("{username}", &escape_ldap_filter(username));
        let mut attributes = self
            .mappings
            .iter()
            .map(|mapping| mapping.source.as_ref())
            .filter(|name| *name != "dn")
            .collect::<Vec<_>>();
        attributes.sort_unstable();
        attributes.dedup();
        ldap.with_search_options(
            SearchOptions::new()
                .sizelimit(2)
                .timelimit(self.timeout.as_secs().max(1).min(i32::MAX as u64) as i32),
        );
        let (entries, _) = ldap
            .search(self.base_dn.as_ref(), Scope::Subtree, &filter, attributes)
            .await?
            .success()
            .context("LDAP user search rejected")?;
        if entries.len() != 1 {
            self.return_service_connection(ldap).await;
            return Ok(EnterpriseAuthResult::Rejected);
        }
        let entry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SearchEntry::construct(entries.into_iter().next().expect("one LDAP entry"))
        }))
        .map_err(|_| anyhow::anyhow!("LDAP returned malformed search entry"))?;
        if entry.dn.is_empty() || entry.dn.len() > 4_096 {
            return Ok(EnterpriseAuthResult::Rejected);
        }
        let user_bind = ldap.simple_bind(&entry.dn, password).await?;
        if user_bind.rc != 0 {
            self.return_service_connection(ldap).await;
            return Ok(EnterpriseAuthResult::Rejected);
        }
        let Some(consumer) = bounded_identity(username) else {
            return Ok(EnterpriseAuthResult::Rejected);
        };
        let mut headers = Vec::with_capacity(self.mappings.len());
        for mapping in self.mappings.iter() {
            let value = if mapping.source.as_ref() == "dn" {
                entry.dn.as_str()
            } else {
                let Some(values) = entry.attrs.get(mapping.source.as_ref()) else {
                    continue;
                };
                if values.len() != 1 {
                    return Ok(EnterpriseAuthResult::Rejected);
                }
                values[0].as_str()
            };
            let Some(value) = bounded_header_value(value) else {
                return Ok(EnterpriseAuthResult::Rejected);
            };
            headers.push((mapping.header.clone(), value));
        }
        self.return_service_connection(ldap).await;
        Ok(EnterpriseAuthResult::Authenticated { consumer, headers })
    }

    /// 业务作用：创建启用证书验证的 LDAP transport，并把 driver 生命周期绑定到最后一个 handle。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：TLS/StartTLS 与 TCP 建立成功返回 LDAP handle；失败返回错误。
    async fn connect(&self) -> Result<ldap3::Ldap> {
        let (connection, ldap) =
            ldap3::LdapConnAsync::with_settings(self.settings.clone(), self.url.as_ref())
                .await
                .context("connect LDAP directory")?;
        tokio::spawn(async move {
            if let Err(error) = connection.drive().await {
                tracing::debug!(%error, "LDAP pooled connection closed");
            }
        });
        Ok(ldap)
    }

    /// 业务作用：把用户 bind 后的连接重新绑定为固定服务身份，避免下一请求继承前一用户权威。
    ///
    /// 参数说明：`ldap` 是本请求独占的连接 handle。
    ///
    /// 返回：无；恢复失败或池已满时直接丢弃连接，不发布半可信池状态。
    async fn return_service_connection(&self, mut ldap: ldap3::Ldap) {
        let reset = ldap
            .simple_bind(self.bind_dn.as_ref(), self.bind_password.as_ref())
            .await;
        if !matches!(reset, Ok(result) if result.rc == 0) {
            return;
        }
        let mut pool = self.pool.lock().await;
        if pool.len() < self.max_connections {
            pool.push(ldap);
        }
    }
}

#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
#[derive(Clone)]
struct IdentityMapping {
    source: Arc<str>,
    header: HeaderName,
}

/// 业务作用：解析企业身份属性到请求 header 的显式 allowlist，禁止覆盖凭据与传输控制字段。
///
/// 参数说明：`raw` 是可选逗号分隔 `attribute:Header`。
///
/// 返回：返回 0..=16 条唯一映射；非法属性或安全敏感/重复 header 返回错误。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn parse_identity_mappings(raw: Option<&str>) -> Result<Vec<IdentityMapping>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let mut mappings = Vec::new();
    let mut headers = std::collections::HashSet::new();
    for item in raw.split(',') {
        let (source, header) = item
            .split_once(':')
            .with_context(|| format!("identity mapping `{item}` must be attribute:Header"))?;
        if source.is_empty()
            || source.len() > 128
            || source.bytes().any(|byte| byte.is_ascii_control())
        {
            bail!("invalid enterprise identity attribute name");
        }
        let header = header
            .parse::<HeaderName>()
            .with_context(|| format!("invalid enterprise identity header `{header}`"))?;
        if crate::routing::is_forbidden_identity_header(&header) {
            bail!("enterprise identity cannot generate security/framing header `{header}`");
        }
        if !headers.insert(header.clone()) {
            bail!("duplicate enterprise identity header `{header}`");
        }
        mappings.push(IdentityMapping {
            source: Arc::from(source),
            header,
        });
    }
    if mappings.len() > MAX_IDENTITY_HEADERS {
        bail!("enterprise identity supports at most {MAX_IDENTITY_HEADERS} header mappings");
    }
    Ok(mappings)
}

/// 业务作用：把受信协议主体收敛为可用于配额/授权的有界 consumer。
///
/// 参数说明：`value` 是已通过 SAML/LDAP 认证的主体文本。
///
/// 返回：合法非空文本返回共享字符串；控制字符或超长值返回 None。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn bounded_identity(value: &str) -> Option<Arc<str>> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_IDENTITY_VALUE_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| Arc::from(value))
}

/// 业务作用：把受信属性转换为安全 HTTP header value，同时施加独立长度门。
///
/// 参数说明：`value` 是协议验证后的单值属性。
///
/// 返回：非空有界可编码值返回 HeaderValue；其它情况返回 None。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn bounded_header_value(value: &str) -> Option<HeaderValue> {
    (!value.is_empty() && value.len() <= MAX_IDENTITY_VALUE_BYTES)
        .then(|| HeaderValue::from_str(value).ok())
        .flatten()
}

#[cfg(feature = "enterprise-ldap")]
/// 业务作用：从标准 Basic header 解码 LDAP 用户凭据，不接受多段、NUL 或非 UTF-8。
///
/// 参数说明：`parts` 是下游请求 head。
///
/// 返回：合法 `username:password` 返回拥有值；缺失/畸形返回 None。
fn ldap_basic_credentials(parts: &Parts) -> Option<(String, String)> {
    use base64::Engine as _;

    let raw = parts
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    if decoded.contains(&0) {
        return None;
    }
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

#[cfg(feature = "enterprise-ldap")]
/// 业务作用：按 RFC 4515 转义用户输入，确保 filter 占位符不能改变 LDAP 表达式结构。
///
/// 参数说明：`value` 是未经信任的用户名。
///
/// 返回：返回只含安全字面量或 `\HH` 转义的 filter assertion value。
fn escape_ldap_filter(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if matches!(*byte, 0 | b'(' | b')' | b'*' | b'\\') || !byte.is_ascii() {
            write!(&mut escaped, "\\{byte:02x}")
                .expect("writing LDAP hex escape into String cannot fail");
        } else {
            escaped.push(char::from(*byte));
        }
    }
    escaped
}

#[cfg(feature = "enterprise-ldap")]
/// 业务作用：从固定 CA PEM 构造 LDAP rustls trust store，不回退到跳过证书验证。
///
/// 参数说明：`pem` 是构建期 SecretSource 解析的 CA certificate bundle。
///
/// 返回：至少一张 CA 成功导入时返回 ClientConfig；空或非法 bundle 返回错误。
fn ldap_tls_config(pem: &str) -> Result<Arc<tokio_rustls::rustls::ClientConfig>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse LDAP CA certificate PEM")?;
    if certificates.is_empty() {
        bail!("LDAP CA certificate bundle is empty");
    }
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).context("add LDAP CA certificate")?;
    }
    Ok(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
type Options = Vec<(String, String)>;

/// 业务作用：解析空白分隔的 route `key=value` 选项，并拒绝重复键以消除配置歧义。
///
/// 参数说明：`spec` 是 filter 原文，`command` 是应被剥离的指令名。
///
/// 返回：返回去引号后的唯一键值；位置参数、空值或重复键返回错误。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn parse_options(spec: &str, command: &str) -> Result<Options> {
    let rest = spec
        .trim()
        .strip_prefix(command)
        .context("enterprise identity command mismatch")?
        .trim();
    if rest.is_empty() {
        bail!("{command} requires options");
    }
    let mut options = Vec::new();
    for token in rest.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .with_context(|| format!("{command} option `{token}` must be key=value"))?;
        let value = value.trim_matches(|character| matches!(character, '\'' | '"'));
        if key.is_empty() || value.is_empty() {
            bail!("{command} option `{token}` cannot be empty");
        }
        if options.iter().any(|(existing, _)| existing == key) {
            bail!("{command} duplicate option `{key}`");
        }
        options.push((key.to_owned(), value.to_owned()));
    }
    Ok(options)
}

/// 业务作用：对协议 DSL 执行未知键拒绝，避免拼写错误被静默忽略并削弱预期安全门。
///
/// 参数说明：`options` 是已去重选项，`allowed` 是该协议固定键集，`command` 用于错误定位。
///
/// 返回：所有键均受支持时成功；遇到未知键返回错误。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn validate_option_keys(options: &Options, allowed: &[&str], command: &str) -> Result<()> {
    for (key, _) in options {
        if !allowed.contains(&key.as_str()) {
            bail!("{command} unsupported option `{key}`");
        }
    }
    Ok(())
}

/// 业务作用：读取可选 DSL 字段，不对敏感值做日志格式化。
///
/// 参数说明：`options` 是已去重选项，`key` 是固定配置键。
///
/// 返回：存在时返回借用值，否则 None。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn option<'a>(options: &'a Options, key: &str) -> Option<&'a str> {
    options
        .iter()
        .find_map(|(name, value)| (name == key).then_some(value.as_str()))
}

/// 业务作用：读取必需 DSL 字段，在构建期阻止不完整信任计划进入数据面。
///
/// 参数说明：`options` 是选项，`key` 是必需键，`command` 用于错误定位。
///
/// 返回：字段存在返回借用值；缺失返回错误。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn required_option<'a>(options: &'a Options, key: &str, command: &str) -> Result<&'a str> {
    option(options, key).with_context(|| format!("{command} requires {key}"))
}

/// 业务作用：解析带范围门的 u64 协议资源参数。
///
/// 参数说明：`options`/`key` 定位字段，`default` 是缺省值，`min`/`max` 是硬边界，`command` 用于报错。
///
/// 返回：范围内数值；格式或范围错误返回失败。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn parse_u64_option(
    options: &Options,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
    command: &str,
) -> Result<u64> {
    let value = option(options, key)
        .map(str::parse::<u64>)
        .transpose()
        .with_context(|| format!("{command} invalid {key}"))?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        bail!("{command} {key} must be in {min}..={max}");
    }
    Ok(value)
}

/// 业务作用：解析带范围门的 usize 协议资源参数。
///
/// 参数说明：与 `parse_u64_option` 相同，返回类型用于集合/字节容量。
///
/// 返回：范围内数值；格式或范围错误返回失败。
#[cfg(any(feature = "enterprise-saml", feature = "enterprise-ldap"))]
fn parse_usize_option(
    options: &Options,
    key: &str,
    default: usize,
    min: usize,
    max: usize,
    command: &str,
) -> Result<usize> {
    let value = option(options, key)
        .map(str::parse::<usize>)
        .transpose()
        .with_context(|| format!("{command} invalid {key}"))?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        bail!("{command} {key} must be in {min}..={max}");
    }
    Ok(value)
}

#[cfg(feature = "enterprise-saml")]
/// 业务作用：解析带范围门的 i64 时钟偏差参数。
///
/// 参数说明：`options`/`key` 定位字段，`default`/`min`/`max` 定义允许区间，`command` 用于报错。
///
/// 返回：范围内数值；格式或范围错误返回失败。
fn parse_i64_option(
    options: &Options,
    key: &str,
    default: i64,
    min: i64,
    max: i64,
    command: &str,
) -> Result<i64> {
    let value = option(options, key)
        .map(str::parse::<i64>)
        .transpose()
        .with_context(|| format!("{command} invalid {key}"))?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        bail!("{command} {key} must be in {min}..={max}");
    }
    Ok(value)
}

#[cfg(feature = "enterprise-ldap")]
/// 业务作用：解析显式布尔配置，禁止含糊真值造成 TLS 保护意外关闭。
///
/// 参数说明：`options`/`key` 定位字段，`default` 是缺省值，`command` 用于报错。
///
/// 返回：只接受 true/false/on/off/yes/no/1/0；其它文本返回错误。
fn parse_bool_option(options: &Options, key: &str, default: bool, command: &str) -> Result<bool> {
    match option(options, key) {
        None => Ok(default),
        Some(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "true" | "on" | "yes" | "1"
            ) =>
        {
            Ok(true)
        }
        Some(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "false" | "off" | "no" | "0"
            ) =>
        {
            Ok(false)
        }
        Some(_) => bail!("{command} {key} must be a boolean"),
    }
}

#[cfg(feature = "enterprise-saml")]
/// 业务作用：读取有界 UTF-8 metadata 文件，禁止把 XML 文档误当内联 DSL 或无界分配来源。
///
/// 参数说明：`source` 必须是 file/k8s-file/vault-agent 引用，`config_dir` 是相对目录，`max_bytes` 是实体门，`label` 用于错误上下文。
///
/// 返回：合法 UTF-8 文件内容；非文件来源、超限、NUL 或读取失败返回错误。
fn read_file_source(
    source: &str,
    config_dir: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<String> {
    let raw = ["file://", "k8s-file://", "vault-agent://"]
        .iter()
        .find_map(|prefix| source.strip_prefix(prefix))
        .with_context(|| format!("{label} must use a file SecretSource"))?;
    let path = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        config_dir.join(raw)
    };
    let bytes = crate::bounded_io::read_file(&path, max_bytes, label)?;
    if bytes.contains(&0) {
        bail!("{label} contains NUL");
    }
    String::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))
}
