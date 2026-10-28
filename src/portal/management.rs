//! 门户身份、团队角色与应用合同；所有授权依据来自已验证 SSO 结果和同代配置。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use base64::Engine as _;
use http::{request::Parts, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::security::enterprise_identity::{EnterpriseAuthPolicy, EnterpriseAuthResult};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementCfg {
    /// 运维固定的 IdP 身份域，用于隔离不同身份源中的相同 subject。
    pub identity_domain: String,
    pub sso: SsoCfg,
    pub allowed_origins: Vec<String>,
    pub teams: Vec<TeamCfg>,
    #[serde(default)]
    pub applications: Vec<ApplicationCfg>,
    pub max_sessions: usize,
    pub session_ttl_seconds: u64,
    pub bindings: Vec<Binding>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub product: String,
    pub version: String,
    pub operation: String,
    pub proxy: String,
    pub route: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SsoCfg {
    Oidc {
        filter: String,
        groups_claim: String,
    },
    Saml {
        filter: String,
        groups_header: String,
        acs_path: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamCfg {
    pub id: String,
    pub title: String,
    /// 一个已验证 IdP group 可映射到团队内固定角色，不能从任意客户端头取组。
    pub group_roles: BTreeMap<String, Role>,
    #[serde(default)]
    pub subject_roles: BTreeMap<String, Role>,
    pub max_applications: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Developer,
    Owner,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationCfg {
    pub id: String,
    pub team: String,
    pub title: String,
    pub consumer: String,
    pub plan: String,
    pub state: ApplicationState,
    #[serde(default)]
    pub redirect_uris: BTreeSet<String>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: String,
    /// 只持有高熵 API key 的摘要，管理读面仍不返回该字段。
    pub sha256: String,
    pub revoked: bool,
}

pub(crate) struct Management {
    pub cfg: ManagementCfg,
    quotas: BTreeMap<String, Value>,
    sso: Sso,
    sessions: parking_lot::Mutex<HashMap<String, Session>>,
}

enum Sso {
    Oidc(Box<crate::routing::OidcRpPolicy>),
    Saml(EnterpriseAuthPolicy),
}

struct Session {
    subject: String,
    groups: BTreeSet<String>,
    expires: Instant,
}

pub(crate) struct Actor {
    pub principal: Arc<str>,
    pub roles: BTreeMap<String, Role>,
}

pub(crate) enum Authentication {
    Actor(Actor),
    Response(Response<crate::BoxBody>),
}

impl Management {
    /// 业务作用：冻结身份源、团队授权与应用容量；管理写能力必须依赖现有审批与审计发布链。
    ///
    /// 参数说明：
    /// - `cfg`：是门户管理声明
    /// - `directory`：用于凭据和信任锚点解析。
    ///
    /// 返回：完整 SSO 和低基数目录；不支持的身份相位、角色或容量拒绝候选。
    pub fn build(cfg: &ManagementCfg, directory: &Path) -> Result<Self> {
        super::validate_token(&cfg.identity_domain, "portal identity domain")?;
        ensure!(
            (1..=16384).contains(&cfg.max_sessions)
                && (60..=86400).contains(&cfg.session_ttl_seconds),
            "invalid portal session budget"
        );
        ensure!(
            (1..=16).contains(&cfg.allowed_origins.len()),
            "portal requires bounded browser origins"
        );
        for origin in &cfg.allowed_origins {
            let uri = reqwest::Url::parse(origin)?;
            ensure!(
                uri.scheme() == "https"
                    && uri.origin().ascii_serialization() == *origin
                    && uri.username().is_empty()
                    && uri.password().is_none(),
                "portal browser origin must be an exact HTTPS origin"
            );
        }
        ensure!(
            (1..=256).contains(&cfg.teams.len()),
            "portal requires 1..=256 teams"
        );
        let mut teams = BTreeSet::new();
        for team in &cfg.teams {
            super::validate_token(&team.id, "team id")?;
            super::validate_text(&team.title, 1, 128, "team title")?;
            ensure!(teams.insert(&team.id), "duplicate portal team");
            ensure!(
                (1..=1024).contains(&team.max_applications),
                "invalid team application quota"
            );
            ensure!(
                team.group_roles.len() + team.subject_roles.len() <= 256,
                "team membership mapping capacity exceeded"
            );
            for key in team.group_roles.keys().chain(team.subject_roles.keys()) {
                super::validate_text(key, 1, 256, "team membership key")?;
            }
        }
        ensure!(
            cfg.applications.len() <= 4096,
            "portal application capacity exceeded"
        );
        let mut applications = BTreeSet::new();
        let mut consumers = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut counts = BTreeMap::new();
        for app in &cfg.applications {
            validate_application(app)?;
            ensure!(
                applications.insert(&app.id) && consumers.insert(&app.consumer),
                "application or consumer ownership is ambiguous"
            );
            let team = cfg
                .teams
                .iter()
                .find(|t| t.id == app.team)
                .context("unknown application team")?;
            let count = counts.entry(&app.team).or_insert(0);
            *count += 1;
            ensure!(
                *count <= team.max_applications,
                "team application quota exceeded"
            );
            for credential in &app.credentials {
                ensure!(
                    digests.insert(&credential.sha256),
                    "credential cannot belong to multiple applications"
                );
            }
        }
        let sso = match &cfg.sso {
            SsoCfg::Oidc {
                filter,
                groups_claim,
            } => {
                ensure!(
                    filter.starts_with("oidc_rp "),
                    "portal OIDC requires oidc_rp filter"
                );
                super::validate_text(groups_claim, 1, 128, "portal groups claim")?;
                // 检查编译后值而不是原始 token；同名参数覆盖不能改变门户入口或放大会话预算。
                let mut policy = crate::routing::parse_oidc_rp(filter, directory)?;
                policy.bind_portal(
                    &cfg.allowed_origins,
                    cfg.max_sessions,
                    Duration::from_secs(cfg.session_ttl_seconds),
                )?;
                Sso::Oidc(Box::new(policy))
            }
            SsoCfg::Saml {
                filter,
                groups_header,
                acs_path,
            } => {
                ensure!(
                    filter.starts_with("saml_auth ")
                        && acs_path == "/api/developer/account/callback",
                    "portal SAML requires dedicated ACS path"
                );
                let header: http::HeaderName = groups_header.parse()?;
                let policy =
                    crate::security::enterprise_identity::parse_saml_auth(filter, directory)?;
                ensure!(
                    policy.saml_form_body_limit().is_some(),
                    "portal SAML requires HTTP-POST binding"
                );
                let acs = reqwest::Url::parse(policy.saml_acs().context("missing SAML ACS")?)?;
                ensure!(
                    acs.scheme() == "https"
                        && acs.path() == acs_path
                        && acs.query().is_none()
                        && acs.fragment().is_none()
                        && acs.username().is_empty()
                        && acs.password().is_none()
                        && cfg
                            .allowed_origins
                            .contains(&acs.origin().ascii_serialization()),
                    "portal SAML ACS must match its dedicated callback and trusted origin"
                );
                ensure!(
                    policy.owned_headers().contains(&header),
                    "portal groups header must come from a signed SAML attribute mapping"
                );
                Sso::Saml(policy)
            }
        };
        Ok(Self {
            quotas: BTreeMap::new(),
            cfg: cfg.clone(),
            sso,
            sessions: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    /// 业务作用：只使用 SSO 验证结果生成门户主体和团队权限，不借用管理面 Bearer 或请求身份头。
    ///
    /// 参数说明：
    /// - `parts`：是原始请求 head
    /// - `saml_response`：仅由有界 ACS 表单解析提供
    /// - `replay`：为进程常驻断言去重域。
    ///
    /// 返回：已授权团队的主体，或协议登录/拒绝响应；无团队映射时为 403。
    pub async fn authenticate(
        &self,
        parts: &Parts,
        saml_response: Option<&str>,
        replay: &crate::security::enterprise_identity::PortalSamlReplay,
    ) -> Authentication {
        let (subject, groups) = match &self.sso {
            Sso::Oidc(policy) => match policy.authenticate(parts).await {
                crate::routing::OidcRpDecision::Response(response) => {
                    return Authentication::Response(response)
                }
                crate::routing::OidcRpDecision::Authenticated {
                    consumer,
                    claims,
                    ..
                } => {
                    let SsoCfg::Oidc {
                        groups_claim,
                        ..
                    } = &self.cfg.sso
                    else {
                        unreachable!()
                    };
                    let Some(groups) = claim_groups(claims.get(groups_claim)) else {
                        return denied(403);
                    };
                    (consumer.to_string(), groups)
                }
            },
            Sso::Saml(policy) => {
                if parts.uri.path() == "/api/developer/account/logout" {
                    if let Some(cookie) = session_cookie(parts) {
                        self.sessions.lock().remove(cookie);
                    }
                    return Authentication::Response(cookie_redirect(
                        "naway_portal_saml=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
                    ));
                }
                if let Some(encoded) = saml_response {
                    if parts.method != http::Method::POST
                        || parts.uri.path() != "/api/developer/account/callback"
                    {
                        return denied(400);
                    }
                    let EnterpriseAuthResult::Authenticated {
                        consumer,
                        headers,
                    } = policy.authenticate_portal_saml(parts, encoded, replay)
                    else {
                        return denied(401);
                    };
                    let SsoCfg::Saml {
                        groups_header,
                        ..
                    } = &self.cfg.sso
                    else {
                        unreachable!()
                    };
                    let values: Vec<_> = headers
                        .iter()
                        .filter(|(key, _)| key.as_str().eq_ignore_ascii_case(groups_header))
                        .collect();
                    if values.len() > 1 {
                        return denied(403);
                    }
                    let groups = values
                        .first()
                        .and_then(|(_, value)| value.to_str().ok())
                        .map(|v| BTreeSet::from([v.to_owned()]))
                        .unwrap_or_default();
                    let mut random = [0_u8; 32];
                    if getrandom::getrandom(&mut random).is_err() {
                        return denied(503);
                    }
                    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
                    let mut sessions = self.sessions.lock();
                    sessions.retain(|_, value| value.expires > Instant::now());
                    if sessions.len() >= self.cfg.max_sessions {
                        return denied(503);
                    }
                    // 验签、重放校验完成后才建立会话，旧快照退休会整体丢弃这些权限。
                    sessions.insert(
                        token.clone(),
                        Session {
                            subject: consumer.to_string(),
                            groups,
                            expires: Instant::now()
                                + Duration::from_secs(self.cfg.session_ttl_seconds),
                        },
                    );
                    return Authentication::Response(cookie_redirect(&format!("naway_portal_saml={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}", self.cfg.session_ttl_seconds)));
                }
                let Some(cookie) = session_cookie(parts) else {
                    return denied(401);
                };
                let mut sessions = self.sessions.lock();
                sessions.retain(|_, value| value.expires > Instant::now());
                let Some(session) = sessions.get(cookie) else {
                    return denied(401);
                };
                (session.subject.clone(), session.groups.clone())
            }
        };
        let mut roles = BTreeMap::new();
        for team in &self.cfg.teams {
            let role = team
                .subject_roles
                .get(&subject)
                .copied()
                .into_iter()
                .chain(
                    groups
                        .iter()
                        .filter_map(|group| team.group_roles.get(group).copied()),
                )
                .max();
            if let Some(role) = role {
                roles.insert(team.id.clone(), role);
            }
        }
        if roles.is_empty() {
            return denied(403);
        }
        let principal =
            nasa::crypto::sha256(&json!([self.cfg.identity_domain, subject]).to_string());
        Authentication::Actor(Actor {
            principal: Arc::from(format!("portal-{principal}")),
            roles,
        })
    }

    /// 业务作用：输出当前团队可见的应用元数据与凭据状态，绝不返回摘要或凭据原文。
    ///
    /// 参数说明：
    /// - `actor`：是本快照 SSO 验证形成的主体。
    ///
    /// 返回：仅包含有权团队的应用、额度套餐与订阅合同。
    pub fn applications(&self, actor: &Actor) -> Value {
        Value::Array(
            self.cfg
                .applications
                .iter()
                .filter(|app| actor.roles.contains_key(&app.team))
                .map(|app| {
                    json!({
                        "id":app.id,
                        "team":app.team,
                        "title":app.title,
                        "consumer":app.consumer,
                        "plan":app.plan,
                        "state":app.state,
                        "quota":self.quotas.get(&app.plan),
                        "redirect_uris":app.redirect_uris,
                        "subscriptions":app.subscriptions,
                        "credentials":app.credentials.iter().map(|key|json!({
                            "id":key.id,
                            "revoked":key.revoked
                        })).collect::<Vec<_>>()
                    })
                })
                .collect(),
        )
    }

    /// 业务作用：从同代绑定和已认证应用形成计量归因，客户端字段不能决定产品或团队。
    ///
    /// 参数说明：
    /// - `proxy`：为实际命中入口
    /// - `route`：为实际命中入口
    /// - `consumer`：为认证链主体
    /// - `generation`：为冻结配置代际。
    ///
    /// 返回：非产品入口为 None；产品入口缺少有效应用身份为错误；其它返回稳定合同维度。
    pub(crate) fn meter_attribution(
        &self,
        proxy: &str,
        route: &str,
        consumer: Option<&str>,
        generation: u64,
    ) -> Result<Option<super::meter::Attribution>> {
        let Some(binding) = self
            .cfg
            .bindings
            .iter()
            .find(|b| b.proxy == proxy && b.route == route)
        else {
            return Ok(None);
        };
        let app = self
            .cfg
            .applications
            .iter()
            .find(|app| {
                Some(app.consumer.as_str()) == consumer
                    && app.state == ApplicationState::Active
                    && app
                        .subscriptions
                        .iter()
                        .any(|s| s.product == binding.product && s.version == binding.version)
            })
            .context("meter product has no authorized application")?;
        Ok(Some(super::meter::Attribution {
            team: app.team.clone(),
            product: binding.product.clone(),
            version: binding.version.clone(),
            operation: binding.operation.clone(),
            application: app.id.clone(),
            consumer: app.consumer.clone(),
            plan: app.plan.clone(),
            config_generation: generation,
        }))
    }

    /// 业务作用：按当前团队角色冻结分析对象列表，导出要求团队 owner 权限。
    ///
    /// 参数说明：
    /// - `actor`：为已验证主体
    /// - `export`：选择明细导出权限。
    ///
    /// 返回：服务端认可的应用身份集合，空集也不扩大到全局查询。
    pub(crate) fn usage_applications(&self, actor: &Actor, export: bool) -> Vec<String> {
        self.cfg
            .applications
            .iter()
            .filter(|app| {
                actor
                    .roles
                    .get(&app.team)
                    .is_some_and(|role| !export || *role == Role::Owner)
            })
            .map(|app| app.id.clone())
            .collect()
    }
}

/// 业务作用：验证应用合同的身份、回调与凭据容量，拒绝开放重定向或重复 key 身份。
///
/// 参数说明：
/// - `app`：是待审批的完整应用声明。
///
/// 返回：安全格式满足时成功；没有网络、配置或凭据副作用。
pub(crate) fn validate_application(app: &ApplicationCfg) -> Result<()> {
    for id in [&app.id, &app.team, &app.consumer, &app.plan] {
        super::validate_token(id, "application identity")?;
    }
    super::validate_text(&app.title, 1, 128, "application title")?;
    ensure!(
        app.redirect_uris.len() <= 16
            && app.subscriptions.len() <= 128
            && app.credentials.len() <= 16,
        "application resource budget exceeded"
    );
    for redirect in &app.redirect_uris {
        let uri = reqwest::Url::parse(redirect)?;
        ensure!(
            redirect.len() <= 2048
                && uri.scheme() == "https"
                && uri.username().is_empty()
                && uri.password().is_none()
                && uri.fragment().is_none()
                && uri.host_str().is_some()
                && !redirect.contains('*'),
            "application redirect must be an exact HTTPS URL"
        );
    }
    let mut keys = BTreeSet::new();
    for key in &app.credentials {
        super::validate_token(&key.id, "credential id")?;
        ensure!(
            keys.insert(&key.id)
                && key.sha256.len() == 64
                && key
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid or duplicate credential digest"
        );
    }
    let mut subscriptions = BTreeSet::new();
    for sub in &app.subscriptions {
        super::validate_token(&sub.product, "subscription product")?;
        super::validate_token(&sub.version, "subscription version")?;
        ensure!(
            subscriptions.insert((&sub.product, &sub.version)),
            "duplicate application subscription"
        );
    }
    Ok(())
}

/// 业务作用：将已验证 OIDC group claim 限制为有界字符串集合，畸形类型不获得任何角色。
///
/// 参数说明：
/// - `value`：来自已验签且 issuer/audience/nonce 校验完成的 ID token。
///
/// 返回：缺少 claim 是空组；非法或超限为 None。
fn claim_groups(value: Option<&Value>) -> Option<BTreeSet<String>> {
    let Some(value) = value else {
        return Some(BTreeSet::new());
    };
    let groups = if let Some(group) = value.as_str() {
        vec![group]
    } else {
        value
            .as_array()?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
    };
    if groups.len() > 128
        || groups
            .iter()
            .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
    {
        return None;
    }
    Some(groups.into_iter().map(str::to_owned).collect())
}

/// 业务作用：只接受唯一且有界的门户会话 Cookie，重复同名值不参与身份选择。
///
/// 参数说明：
/// - `parts`：为原始请求 head。
///
/// 返回：唯一 Cookie 的借用值；缺失、重复或非法时为 None。
fn session_cookie(parts: &Parts) -> Option<&str> {
    let mut found = None;
    for value in parts.headers.get_all(http::header::COOKIE) {
        for item in value.to_str().ok()?.split(';') {
            let Some(value) = item.trim().strip_prefix("naway_portal_saml=") else {
                continue;
            };
            if found.is_some()
                || value.len() != 43
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

/// 业务作用：完成 SAML 会话设置或注销后只跳转固定门户，不接受客户端 return URL。
///
/// 参数说明：
/// - `cookie`：是本地生成的 Set-Cookie，不含身份 claim。
///
/// 返回：禁止缓存的同源 303 响应。
fn cookie_redirect(cookie: &str) -> Response<crate::BoxBody> {
    Response::builder()
        .status(303)
        .header(http::header::LOCATION, "/developer")
        .header(http::header::SET_COOKIE, cookie)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(crate::full_body(bytes::Bytes::new()))
        .expect("bounded portal redirect")
}

/// 业务作用：统一身份拒绝响应，避免泄露用户是否存在或断言内容。
///
/// 参数说明：
/// - `status`：为固定身份或容量错误状态。
///
/// 返回：无敏感详情的终止响应。
fn denied(status: u16) -> Authentication {
    Authentication::Response(crate::text_status(status, "portal identity unavailable"))
}

/// 业务作用：让 SSO 凭据、证书与 metadata 参与同一配置指纹和 watcher。
///
/// 参数说明：
/// - `cfg`：是身份声明
/// - `directory`：是文件相对根。
///
/// 返回：只读取声明路径的列表，不执行网络或读取秘密材料。
pub(crate) fn dependencies(cfg: &ManagementCfg, directory: &Path) -> Vec<PathBuf> {
    let filter = match &cfg.sso {
        SsoCfg::Oidc {
            filter,
            ..
        }
        | SsoCfg::Saml {
            filter,
            ..
        } => filter,
    };
    crate::security::secret::filter_dependency_paths(filter, directory)
}

/// 业务作用：把已批准应用凭据编译进既有认证与套餐管线，产品授权在认证相位生效而非事后补认证。
///
/// 参数说明：
/// - `policy`：为门户合同
/// - `gateway`：是候选
/// - `directory`：为信任材料根
/// - `products`：是冻结产品目录。
///
/// 返回：可运行管理模型；所有引用和权限校验通过后才修改候选路由，失败不发布。
pub(crate) fn build_and_apply(
    policy: &ManagementCfg,
    gateway: &mut crate::config::model::GatewayConfig,
    directory: &Path,
    products: &super::products::ProductCatalog,
) -> Result<Management> {
    use crate::config::model::{AdminResource, UsagePlanRouteCfg};
    ensure!(
        gateway.admin.auth.enabled
            && gateway.admin.rbac.enabled
            && gateway.admin.approval.enabled
            && (gateway
                .admin
                .approval
                .resources
                .contains(&AdminResource::Consumers)
                || (gateway.ownership.enabled
                    && policy.teams.iter().all(|team| gateway
                        .ownership
                        .objects
                        .get(&format!("team:{}", team.id))
                        .is_some_and(
                            |owner| owner.workspace != crate::control::ownership::PLATFORM
                        )))),
        "portal management requires authenticated RBAC and consumer maker-checker"
    );
    let mut runtime = Management::build(policy, directory)?;
    runtime.quotas = gateway
        .usage_plans
        .plans
        .iter()
        .map(|(id, plan)| {
            (
                id.clone(),
                json!({
                    "requests":plan.requests,
                    "window_ms":plan.window_ms,
                    "burst":plan.burst,
                    "remaining":null
                }),
            )
        })
        .collect();
    ensure!(
        policy.bindings.len() <= 4096,
        "product route binding capacity exceeded"
    );
    for app in &policy.applications {
        ensure!(
            gateway.usage_plans.plans.contains_key(&app.plan),
            "application references unknown usage plan"
        );
        for sub in &app.subscriptions {
            ensure!(
                products.permits(&sub.product, &sub.version, Some(&app.team), None),
                "application subscription is not authorized for its team"
            );
        }
        if let Some(existing) = gateway
            .usage_plans
            .consumers
            .insert(app.consumer.clone(), app.plan.clone())
        {
            ensure!(
                existing == app.plan,
                "application usage plan conflicts with consumer binding"
            );
        }
    }
    let mut routes = BTreeSet::new();
    for binding in &policy.bindings {
        for id in [
            &binding.product,
            &binding.version,
            &binding.proxy,
            &binding.route,
        ] {
            super::validate_token(id, "product route binding")?;
        }
        ensure!(
            routes.insert((&binding.proxy, &binding.route)),
            "one route cannot carry multiple product operations"
        );
        ensure!(
            products.permits(
                &binding.product,
                &binding.version,
                None,
                Some(&binding.operation)
            ),
            "binding references unavailable product operation"
        );
        let configured = if gateway.proxies.is_empty() {
            ensure!(binding.proxy == "default", "unknown product proxy");
            &mut gateway.routes
        } else {
            &mut gateway
                .proxies
                .iter_mut()
                .find(|p| p.id == binding.proxy)
                .context("unknown product proxy")?
                .routes
        };
        ensure!(
            configured.iter().filter(|r| r.id == binding.route).count() == 1,
            "product route must resolve exactly once"
        );
        let route = configured
            .iter_mut()
            .find(|r| r.id == binding.route)
            .expect("validated route");
        // 应用订阅不能被另一认证方式或内部重路由绕过；只有本目录生成的摘要凭据可形成该入口 consumer。
        ensure!(
            !route.filters.iter().any(|filter| [
                "api_key",
                "jwt_auth",
                "oidc_rp",
                "saml_auth",
                "ldap_auth",
                "basic_auth",
                "auth_basic",
                "auth_digest",
                "hmac_auth",
                "ext_authz",
                "auth_request",
                "satisfy",
                "reroute",
                "error_page",
                "x_accel_redirect"
            ]
            .iter()
            .any(|prefix| filter.trim_start().starts_with(prefix))),
            "product-managed route cannot declare another authentication or reroute authority"
        );
        ensure!(
            route.usage_plan.is_none(),
            "product-managed route inherits its application plan"
        );
        let mut keys = 0;
        for app in &policy.applications {
            if app.state != ApplicationState::Active
                || !app
                    .subscriptions
                    .iter()
                    .any(|s| s.product == binding.product && s.version == binding.version)
            {
                continue;
            }
            for credential in app.credentials.iter().filter(|k| !k.revoked) {
                route.filters.push(format!(
                    "api_key header=X-Api-Key sha256={} consumer={}",
                    credential.sha256, app.consumer
                ));
                keys += 1;
            }
        }
        ensure!(
            keys <= 256,
            "product operation credential capacity exceeded"
        );
        // 没有活动应用凭据时必须关闭业务入口；空认证集合不表示匿名开放。
        if keys == 0 {
            route.filters.push("return 403".to_owned());
        } else {
            route.usage_plan = Some(UsagePlanRouteCfg {
                default_plan: None,
                require_consumer: true,
            });
        }
    }
    Ok(runtime)
}
