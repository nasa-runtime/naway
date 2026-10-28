//! 固定层级的身份授权、额度与请求上下文策略；认证始终先于 group/consumer 选择。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use http::{request::Parts, HeaderName, HeaderValue};
use serde::Deserialize;

use crate::config::model::{GatewayConfig, UsagePlanCfg};
use crate::runtime::state::{RateLimitRequest, RateLimiter};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerGroupCfg {
    pub consumers: BTreeSet<String>,
    #[serde(default)]
    pub plan: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCfg {
    pub id: String,
    pub scope: Scope,
    /// 认证插件只在静态入口作用域物化；身份作用域不得事后重新认证或替换主体。
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(default)]
    pub require_authentication: bool,
    #[serde(default)]
    pub deny: bool,
    #[serde(default)]
    pub quota_plan: Option<String>,
    #[serde(default)]
    pub quota_per_consumer: bool,
    /// 显式集合采用交集语义；空集合拒绝所有产品，未声明不增加产品约束。
    #[serde(default)]
    pub products: Option<BTreeSet<String>>,
    /// 只允许网关上下文命名空间，不可改变认证、路由或 HTTP framing。
    #[serde(default)]
    pub request_headers: BTreeMap<String, Option<String>>,
    /// false 只停止继承上层上下文变换；认证、deny、产品授权与额度仍累积，不能由下层关闭。
    #[serde(default = "inherit_headers_by_default")]
    pub inherit_headers: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    #[serde(alias = "platform")]
    Global,
    Workspace {
        workspace: String,
    },
    Product {
        product: String,
        version: String,
    },
    Service {
        service: String,
    },
    Route {
        proxy: String,
        route: String,
    },
    Group {
        group: String,
    },
    Consumer {
        consumer: String,
    },
}

pub struct ScopeCatalog {
    routes: HashMap<String, HashMap<String, Arc<RoutePolicies>>>,
}

pub(crate) struct RoutePolicies {
    rules: Vec<Arc<Rule>>,
    product: Option<String>,
}

/// 层级路由单次请求的公共额度凭据；仅内部扩展能创建，客户端头不能模拟已执行状态。
#[derive(Clone, Default)]
pub(crate) struct LayerLedger(BTreeSet<String>);

struct Rule {
    id: String,
    rank: u8,
    consumers: Option<Arc<BTreeSet<String>>>,
    require_authentication: bool,
    deny: bool,
    products: Option<BTreeSet<String>>,
    quota: Option<UsagePlanCfg>,
    quota_per_consumer: bool,
    headers: Vec<(HeaderName, Option<HeaderValue>)>,
    inherit_headers: bool,
}

impl ScopeCatalog {
    /// 业务作用：编译 platform→workspace→product/service→route→group→consumer 的固定层级，拒绝同层歧义覆盖。
    ///
    /// 参数说明：
    /// - `gateway`：是完整候选；所有路由、产品绑定、group 和套餐均来自同一事实源。
    ///
    /// 返回：静态认证已加入候选路由，身份后策略形成有界索引；任一冲突丢弃整个候选。
    pub(crate) fn build_and_apply(gateway: &mut GatewayConfig) -> Result<Arc<Self>> {
        let ownership = crate::control::ownership::OwnershipCatalog::build(gateway)?;
        let cfg = gateway.usage_plans.policies.clone();
        ensure!(cfg.len() <= 512, "at most 512 scoped policies are allowed");
        let groups = &gateway.usage_plans.groups;
        ensure!(
            groups.len() <= 256
                && groups
                    .values()
                    .map(|group| group.consumers.len())
                    .sum::<usize>()
                    <= 100_000,
            "consumer group membership capacity exceeded"
        );
        for (id, group) in groups {
            token(id)?;
            ensure!(
                !group.consumers.is_empty(),
                "consumer group must not be empty"
            );
            for consumer in &group.consumers {
                token(consumer)?;
            }
        }
        let members: BTreeMap<_, _> = groups
            .iter()
            .map(|(id, group)| (id.as_str(), Arc::new(group.consumers.clone())))
            .collect();
        let mut ids = BTreeSet::new();
        let mut compiled = Vec::new();
        for policy in &cfg {
            token(&policy.id)?;
            ensure!(ids.insert(&policy.id), "duplicate scoped policy id");
            let (rank, consumers) = match &policy.scope {
                Scope::Global => (0, None),
                Scope::Workspace {
                    workspace,
                } => {
                    token(workspace)?;
                    ensure!(
                        gateway.ownership.enabled
                            && gateway.ownership.workspaces.contains_key(workspace),
                        "unknown workspace policy scope"
                    );
                    (1, None)
                }
                Scope::Product {
                    product,
                    version,
                } => {
                    token(product)?;
                    token(version)?;
                    (2, None)
                }
                Scope::Service {
                    service,
                } => {
                    token(service)?;
                    ensure!(
                        gateway.upstreams.services.contains_key(service),
                        "unknown service policy scope"
                    );
                    (2, None)
                }
                Scope::Route {
                    proxy,
                    route,
                } => {
                    token(proxy)?;
                    token(route)?;
                    (3, None)
                }
                Scope::Group {
                    group,
                } => {
                    token(group)?;
                    (
                        4,
                        Some(
                            members
                                .get(group.as_str())
                                .context("unknown policy consumer group")?
                                .clone(),
                        ),
                    )
                }
                Scope::Consumer {
                    consumer,
                } => {
                    token(consumer)?;
                    (5, Some(Arc::new(BTreeSet::from([consumer.clone()]))))
                }
            };
            ensure!(policy.authentication.len() <= 8 && (rank < 4 || policy.authentication.is_empty()),
                "authentication belongs to a static entry scope, never a post-authentication identity scope");
            for filter in &policy.authentication {
                ensure!(
                    filter.len() <= 4096
                        && [
                            "api_key ",
                            "auth_basic ",
                            "auth_digest ",
                            "jwt_auth ",
                            "oidc_rp ",
                            "saml_auth ",
                            "ldap_auth ",
                            "hmac_auth "
                        ]
                        .iter()
                        .any(|prefix| filter.starts_with(prefix)),
                    "scoped authentication must use an explicit supported identity filter"
                );
            }
            ensure!(
                !policy.quota_per_consumer || policy.quota_plan.is_some(),
                "per-consumer quota requires a plan"
            );
            let quota = policy
                .quota_plan
                .as_ref()
                .map(|id| {
                    gateway
                        .usage_plans
                        .plans
                        .get(id)
                        .cloned()
                        .context("unknown scope quota plan")
                })
                .transpose()?;
            if let Some(products) = &policy.products {
                ensure!(
                    products.len() <= 128,
                    "scoped product allowlist exceeds capacity"
                );
                for id in products {
                    token(id)?;
                    ensure!(
                        gateway
                            .developer_portal
                            .products
                            .iter()
                            .any(|p| &p.id == id),
                        "scoped allowlist references unknown product"
                    );
                }
            }
            ensure!(
                policy.request_headers.len() <= 16,
                "scoped context header capacity exceeded"
            );
            let mut headers = Vec::new();
            let mut names = BTreeSet::new();
            for (name, value) in &policy.request_headers {
                let name: HeaderName = name.parse()?;
                ensure!(
                    name.as_str().starts_with("x-naway-context-")
                        && name.as_str().len() <= 96
                        && names.insert(name.to_string()),
                    "scoped mutations require unique x-naway-context-* names"
                );
                let value = value
                    .as_ref()
                    .map(|value| {
                        ensure!(
                            value.len() <= 1024
                                && !["literal://", "env://", "file://", "${"]
                                    .iter()
                                    .any(|prefix| value.contains(prefix)),
                            "invalid scoped context value"
                        );
                        Ok(HeaderValue::from_str(value)?)
                    })
                    .transpose()?;
                headers.push((name, value));
            }
            compiled.push((
                policy,
                Arc::new(Rule {
                    id: format!("scope:{}", policy.id),
                    rank,
                    consumers,
                    require_authentication: policy.require_authentication
                        || !policy.authentication.is_empty(),
                    deny: policy.deny,
                    products: policy.products.clone(),
                    quota,
                    quota_per_consumer: policy.quota_per_consumer,
                    headers,
                    inherit_headers: policy.inherit_headers,
                }),
            ));
        }
        compiled.sort_by(|(a, ra), (b, rb)| (ra.rank, &a.id).cmp(&(rb.rank, &b.id)));
        let bindings = gateway
            .developer_portal
            .management
            .as_ref()
            .map(|m| m.bindings.clone())
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        let mut routes: HashMap<String, HashMap<String, Arc<RoutePolicies>>> = HashMap::new();
        let mut entries = 0;
        let mut apply = |proxy: &str, route: &mut crate::config::model::RouteCfg| -> Result<()> {
            let product = bindings
                .iter()
                .find(|b| b.proxy == proxy && b.route == route.id);
            let mut rules: Vec<Arc<Rule>> = Vec::new();
            let mut auth = Vec::new();
            for (policy, rule) in &compiled {
                let matches = match &policy.scope {
                    Scope::Workspace {
                        workspace,
                    } => ownership
                        .route_owner(proxy, &route.id)
                        .is_some_and(|owner| &owner.workspace == workspace),
                    Scope::Service {
                        service,
                    } => route.uri.strip_prefix("lb://") == Some(service.as_str()),
                    Scope::Product {
                        product: id,
                        version,
                    } => product.is_some_and(|b| &b.product == id && &b.version == version),
                    Scope::Route {
                        proxy: id,
                        route: name,
                    } => id == proxy && name == &route.id,
                    _ => true,
                };
                let shared = matches!(policy.scope, Scope::Global | Scope::Service {
                    ..
                });
                if !matches || !ownership.policy_applies(&policy.id, proxy, &route.id, shared) {
                    continue;
                }
                seen.insert(policy.id.clone());
                // 同层且主体集合相交时禁止冲突写；排序只保障稳定输出，不承担授权裁决。
                for prior in &rules {
                    if prior.rank == rule.rank && intersects(&prior.consumers, &rule.consumers) {
                        ensure!(
                            prior.inherit_headers == rule.inherit_headers,
                            "same-scope header inheritance conflicts"
                        );
                        ensure!(
                            !rule.headers.iter().any(|(name, value)| prior
                                .headers
                                .iter()
                                .any(|(other, previous)| name == other && value != previous)),
                            "same-scope context transformations conflict"
                        );
                    }
                }
                auth.extend(policy.authentication.iter().cloned());
                rules.push(rule.clone());
            }
            ensure!(
                rules.len() <= 32,
                "one route supports at most 32 scoped policies"
            );
            entries += rules.len();
            ensure!(entries <= 65536, "scoped route expansion capacity exceeded");
            if !auth.is_empty() {
                // 产品订阅拥有独立凭据集合，通用认证策略不能额外赋予绕过订阅的身份。
                ensure!(product.is_none(), "product-managed route owns authentication and rejects additional scoped authentication");
                ensure!(
                    !route.filters.iter().any(|s| [
                        "api_key",
                        "auth_basic",
                        "auth_digest",
                        "jwt_auth",
                        "oidc_rp",
                        "saml_auth",
                        "ldap_auth",
                        "hmac_auth",
                        "satisfy",
                        "ext_authz",
                        "auth_request"
                    ]
                    .iter()
                    .any(|p| s.trim_start().starts_with(p))),
                    "scoped authentication conflicts with route authority"
                );
                let mut kinds = BTreeSet::new();
                for filter in &auth {
                    ensure!(
                        kinds.insert(filter.split_whitespace().next()),
                        "multiple scoped authentication declarations of the same kind conflict"
                    );
                }
                route.filters.extend(auth);
            }
            if !rules.is_empty() {
                routes.entry(proxy.to_owned()).or_default().insert(
                    route.id.clone(),
                    Arc::new(RoutePolicies {
                        rules,
                        product: product.map(|b| b.product.clone()),
                    }),
                );
            }
            Ok(())
        };
        if gateway.proxies.is_empty() {
            for route in &mut gateway.routes {
                apply("default", route)?;
            }
        } else {
            for proxy in &mut gateway.proxies {
                for route in &mut proxy.routes {
                    apply(&proxy.id, route)?;
                }
            }
        }
        ensure!(
            seen.len() == cfg.len(),
            "scoped policy has no matching route or product deployment"
        );
        Ok(Arc::new(Self {
            routes,
        }))
    }

    /// 业务作用：按当前监听器和路由选择同代已编译策略，不从客户端 header 获取作用域。
    ///
    /// 参数说明：
    /// - `proxy`：来自已匹配快照。
    /// - `route`：来自已匹配快照。
    ///
    /// 返回：存在策略时借用共享计划；未启用时不分配。
    pub(crate) fn route(&self, proxy: &str, route: &str) -> Option<&Arc<RoutePolicies>> {
        if self.routes.is_empty() {
            return None;
        }
        self.routes.get(proxy)?.get(route)
    }
}

impl RoutePolicies {
    /// 业务作用：在认证完成后合并授权与额度，再发布有界上下文变换；deny 与产品 allowlist 不可被下层放宽。
    ///
    /// 参数说明：
    /// - `authenticated`：来自认证链
    /// - `consumer`：来自认证链
    /// - `parts`：仅接收上下文头
    /// - `limiter`：复用统一计数后端。
    ///
    /// 返回：全部门通过才改变请求头；拒绝为固定 HTTP 状态，额度计数表示各门收到的尝试，不做跨门回退。
    pub(crate) async fn enforce(
        &self,
        authenticated: bool,
        consumer: Option<&str>,
        parts: &mut Parts,
        limiter: &dyn RateLimiter,
    ) -> std::result::Result<(), u16> {
        let applicable = |rule: &&Arc<Rule>| {
            rule.consumers.as_ref().is_none_or(|members| {
                authenticated && consumer.is_some_and(|id| members.contains(id))
            })
        };
        let selected: Vec<_> = self.rules.iter().filter(applicable).collect();
        for rule in &selected {
            if rule.deny
                || rule.products.as_ref().is_some_and(|products| {
                    self.product
                        .as_ref()
                        .is_none_or(|product| !products.contains(product))
                })
            {
                return Err(403);
            }
            if (rule.require_authentication || rule.quota_per_consumer)
                && (!authenticated || consumer.is_none())
            {
                return Err(401);
            }
        }
        for rule in &selected {
            if let Some(plan) = &rule.quota {
                let scope = match parts.extensions.get::<crate::control::ownership::Owner>() {
                    Some(owner) => format!("{}:{}", owner.namespace(), rule.id),
                    None => rule.id.clone(),
                };
                if parts
                    .extensions
                    .get::<LayerLedger>()
                    .is_some_and(|ledger| ledger.0.contains(&scope))
                {
                    continue;
                }
                let key = if rule.quota_per_consumer {
                    format!(
                        "{}:{}",
                        scope,
                        nasa::crypto::sha256(consumer.expect("identity validated"))
                    )
                } else {
                    scope.clone()
                };
                let decision = limiter
                    .allow(RateLimitRequest {
                        warmup: None,
                        state_budget: parts.extensions.get(),
                        scope: &scope,
                        key: &key,
                        cost: 1,
                        limit: plan.requests,
                        window: Duration::from_millis(plan.window_ms),
                        burst: plan.burst,
                        max_active_keys: plan.max_active_keys,
                        active_keys_fail_open: false,
                    })
                    .await;
                if !decision.allowed {
                    return Err(429);
                }
                if let Some(ledger) = parts.extensions.get_mut::<LayerLedger>() {
                    if ledger.0.len() >= 256 {
                        return Err(503);
                    }
                    ledger.0.insert(scope);
                }
            }
        }
        // 所有策略拥有的上下文头先清除客户端值；未命中 group 也不能伪造该组的输出。
        for rule in &self.rules {
            for (name, _) in &rule.headers {
                parts.headers.remove(name);
            }
        }
        for rule in selected {
            if !rule.inherit_headers {
                // 只能重置网关上下文输出，前面已经通过的强制认证、授权和额度不会被撤销。
                for ancestor in &self.rules {
                    for (name, _) in &ancestor.headers {
                        parts.headers.remove(name);
                    }
                }
            }
            for (name, value) in &rule.headers {
                if let Some(value) = value {
                    parts.headers.insert(name.clone(), value.clone());
                } else {
                    parts.headers.remove(name);
                }
            }
        }
        Ok(())
    }
}

/// 业务作用：默认保留上层安全上下文，只有显式关闭的变换层才重建输出。
///
/// 参数说明: 无。
///
/// 返回：默认继承上下文头变换。
fn inherit_headers_by_default() -> bool {
    true
}

/// 业务作用：判定两条同级规则是否可能影响同一可信主体，避免相交 group 的隐式覆盖。
///
/// 参数说明：
/// - `left`：是冻结成员集合；None 表示全部主体。
/// - `right`：是冻结成员集合；None 表示全部主体。
///
/// 返回：存在共同主体或任一为全域时为 true。
fn intersects(left: &Option<Arc<BTreeSet<String>>>, right: &Option<Arc<BTreeSet<String>>>) -> bool {
    match (left, right) {
        (Some(a), Some(b)) => a.iter().any(|id| b.contains(id)),
        _ => true,
    }
}

/// 业务作用：固定作用域身份的 URL/索引语义，拒绝控制字符、超长值及任意表达式。
///
/// 参数说明：
/// - `value`：为受信配置中声明的标识符。
///
/// 返回：安全 ASCII 身份有效时成功，否则拒绝候选。
fn token(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "scope identity must be 1..=64 safe ASCII bytes"
    );
    Ok(())
}
