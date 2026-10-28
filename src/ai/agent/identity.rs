use super::config::{AclCfg, SecurityCfg};
use anyhow::{ensure, Result};
use http::HeaderMap;
use naauthz::{AuthzDecision, PolicySet, Principal, RequireMode, RoutePolicy};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

/// 仅由已认证事实建立的 Agent 身份；命名空间不包含原始 token 或 API key。
pub(crate) struct Identity {
    pub key: [u8; 32],
    consumer: Option<String>,
    groups: BTreeSet<String>,
    principal: Principal,
}

pub(crate) struct Acl {
    consumers: HashSet<String>,
    groups: HashSet<String>,
    scopes: Option<PolicySet>,
}

impl Acl {
    /// 业务作用：把工具发现或调用权限编译为固定身份维度与 nasa scope 策略。
    ///
    /// 参数说明：
    /// - `cfg`：是单一动作的 ACL，发现与调用分别构建，不能互相继承放行结果。
    ///
    /// 返回：明确且有界的策略；空规则未显式放行时拒绝配置，避免默认暴露工具。
    pub(crate) fn build(cfg: &AclCfg) -> Result<Self> {
        for values in [&cfg.consumers, &cfg.groups, &cfg.scopes] {
            ensure!(
                values.len() <= 64 && values.iter().all(|value| valid_label(value)),
                "invalid Agent ACL values"
            );
            ensure!(
                values.iter().collect::<HashSet<_>>().len() == values.len(),
                "duplicate Agent ACL values"
            );
        }
        ensure!(
            cfg.allow_authenticated
                || !cfg.consumers.is_empty()
                || !cfg.groups.is_empty()
                || !cfg.scopes.is_empty(),
            "Agent ACL needs an explicit authenticated grant or identity constraints"
        );
        let scopes = if cfg.scopes.is_empty() {
            None
        } else {
            Some(
                PolicySet::build(vec![RoutePolicy {
                    route_id: "agent-action".to_owned(),
                    required_scopes: cfg.scopes.iter().cloned().collect(),
                    mode: RequireMode::All,
                }])
                .map_err(|_| anyhow::anyhow!("invalid Agent scope policy"))?,
            )
        };
        Ok(Self {
            consumers: cfg.consumers.iter().cloned().collect(),
            groups: cfg.groups.iter().cloned().collect(),
            scopes,
        })
    }

    /// 业务作用：在每次发现和调用时重新检查已验证身份，禁止把会话存在当成授权缓存。
    ///
    /// 参数说明：
    /// - `identity`：是本次 HTTP 请求重新认证后冻结的身份。
    ///
    /// 返回：所有已配置维度同时满足才为 true；scope 未显式许可时失败闭合。
    pub(crate) fn allows(&self, identity: &Identity) -> bool {
        (self.consumers.is_empty()
            || identity
                .consumer
                .as_ref()
                .is_some_and(|value| self.consumers.contains(value)))
            && (self.groups.is_empty()
                || identity
                    .groups
                    .iter()
                    .any(|value| self.groups.contains(value)))
            && self.scopes.as_ref().is_none_or(|policy| {
                matches!(
                    policy.decide_explicit_policy("agent-action", &identity.principal),
                    Some(AuthzDecision::Permit)
                )
            })
    }
}

/// 业务作用：验证来源与固定租户，再把路由认证结果转为隔离身份，不读取客户端自报身份头。
///
/// 参数说明：
/// - `cfg`：路由身份与 Origin 策略。
/// - `headers`：只用于读取 Origin 的请求头。
/// - `authenticated`：已完成本地认证的结果标记。
/// - `consumer`：认证产生的稳定 consumer 身份。
/// - `claims`：已经验证的身份声明。
///
/// 返回：身份、租户与 Origin 全部有效时返回隔离主体；缺失、歧义或越权返回低敏错误。
pub(crate) fn verify(
    cfg: &SecurityCfg,
    headers: &HeaderMap,
    authenticated: bool,
    consumer: Option<&str>,
    claims: Option<&Value>,
) -> Result<Identity> {
    // 会话令牌只是索引；必须每次重新认证，防止被盗 session id 单独构成访问权。
    ensure!(authenticated, "Agent authentication required");
    if headers.contains_key(http::header::ORIGIN) {
        ensure!(
            headers.get_all(http::header::ORIGIN).iter().count() == 1,
            "ambiguous Agent Origin"
        );
        let origin = headers
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok());
        ensure!(
            origin
                .is_some_and(|origin| cfg.allowed_origins.iter().any(|allowed| allowed == origin)),
            "Agent Origin denied"
        );
    }
    if let Some(claim) = cfg.tenant_claim.as_ref() {
        // 租户不一致意味着当前凭据不拥有此路由；不能回落到默认租户或客户端 header。
        ensure!(
            claims
                .and_then(|value| value.get(claim))
                .and_then(Value::as_str)
                == Some(&cfg.tenant),
            "Agent tenant denied"
        );
    }
    let subject = claims
        .and_then(|value| value.get("sub"))
        .and_then(Value::as_str)
        .or(consumer)
        .filter(|value| valid_label(value))
        .ok_or_else(|| anyhow::anyhow!("Agent verified subject required"))?;
    let issuer = claims
        .and_then(|value| value.get("iss"))
        .and_then(Value::as_str)
        .unwrap_or("");
    ensure!(issuer.len() <= 2048, "Agent issuer exceeds limit");
    let mut groups = cfg
        .consumer_groups
        .get(consumer.unwrap_or(""))
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();
    if let Some(key) = cfg.groups_claim.as_ref() {
        groups.extend(claim_values(claims.and_then(|value| value.get(key)))?);
    }
    let scopes = claim_values(
        claims.and_then(|value| value.get(cfg.scopes_claim.as_deref().unwrap_or("scope"))),
    )?;
    let mut key = Sha256::new();
    for part in [cfg.tenant.as_str(), issuer, subject, consumer.unwrap_or("")] {
        key.update((part.len() as u64).to_be_bytes());
        key.update(part.as_bytes());
    }
    Ok(Identity {
        key: key.finalize().into(),
        consumer: consumer.map(str::to_owned),
        groups,
        principal: Principal {
            subject: Some(subject.to_owned()),
            tenant: Some(cfg.tenant.clone()),
            scopes,
            ..Principal::default()
        },
    })
}

/// 业务作用：校验身份配置的来源、基数与租户，防止候选策略持有无限 group 目录。
///
/// 参数说明：
/// - `cfg`：是路由安全配置。
///
/// 返回：合法配置成功；空租户、异常 claim 名称、无效 Origin 或超量映射拒绝。
pub(crate) fn validate_security(cfg: &SecurityCfg) -> Result<()> {
    ensure!(valid_label(&cfg.tenant), "invalid Agent tenant");
    ensure!(
        cfg.allowed_origins.len() <= 32 && cfg.consumer_groups.len() <= 1024,
        "Agent identity configuration exceeds limit"
    );
    for origin in &cfg.allowed_origins {
        let uri: http::Uri = origin.parse()?;
        ensure!(
            matches!(uri.scheme_str(), Some("http" | "https"))
                && uri.authority().is_some()
                && !uri.authority().unwrap().as_str().contains('@')
                && uri.path() == "/"
                && uri.query().is_none(),
            "invalid Agent allowed origin"
        );
    }
    for value in [&cfg.tenant_claim, &cfg.groups_claim, &cfg.scopes_claim]
        .into_iter()
        .flatten()
    {
        ensure!(valid_label(value), "invalid Agent claim name");
    }
    for (consumer, groups) in &cfg.consumer_groups {
        ensure!(
            valid_label(consumer)
                && groups.len() <= 64
                && groups.iter().all(|group| valid_label(group)),
            "invalid Agent group mapping"
        );
    }
    Ok(())
}

/// 业务作用：把已验签 claim 的字符串或字符串数组收敛为有界集合。
///
/// 参数说明：
/// - `value`：是单一 claim，缺失表示没有获得该维度权限。
///
/// 返回：规范化集合；非法类型、超长值或超量元素拒绝身份，不做宽松类型转换。
fn claim_values(value: Option<&Value>) -> Result<BTreeSet<String>> {
    let values = match value {
        None => Vec::new(),
        Some(Value::String(value)) => value.split_ascii_whitespace().map(str::to_owned).collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("invalid Agent identity claim"))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => anyhow::bail!("invalid Agent identity claim"),
    };
    ensure!(
        values.len() <= 64 && values.iter().all(|value| valid_label(value)),
        "Agent claim exceeds limit"
    );
    Ok(values.into_iter().collect())
}

/// 业务作用：限制进入权限目录和隔离键的身份标签。
///
/// 参数说明：
/// - `value`：是固定策略或已验证身份中的文本标签。
///
/// 返回：非空、有界且没有空白或控制字符时为 true。
fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
}
