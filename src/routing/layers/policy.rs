//! 层级策略与执行相位合同；父层只能产生受信上下文和公共门禁，不能拥有业务终端副作用。

use super::Topology;
use crate::config::{
    layers::{ContextCfg, MatchCfg, Risk},
    model::RouteCfg,
};
use crate::routing::{JwtVerifier, ParsedFilter, RequestHeaderOp, Route};
use anyhow::{ensure, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// 业务作用：在 filter 编译时拒绝分支拥有重写、外呼、缓存、返回或响应变换等终端行为。
///
/// 参数说明：
/// - `filter`：为现有原生编译器产生的强类型策略，不另行解析认证材料。
///
/// 返回：局部访问控制、本地认证、公共 CORS 与限额允许；其它策略拒绝分支配置。
pub(in crate::routing) fn branch_filter(filter: &ParsedFilter) -> Result<()> {
    ensure!(
        matches!(
            filter,
            ParsedFilter::None
                | ParsedFilter::Access(_)
                | ParsedFilter::ValidReferers(_)
                | ParsedFilter::LimitExcept(_)
                | ParsedFilter::BasicAuth(Some(_))
                | ParsedFilter::ApiKey(_)
                | ParsedFilter::JwtAuth(_)
                | ParsedFilter::Satisfy(_)
                | ParsedFilter::Cors(_)
                | ParsedFilter::LimitReq(_)
                | ParsedFilter::LimitConn(_)
        ),
        "route branch filter has terminal or unsupported side effects"
    );
    Ok(())
}

/// 业务作用：在建立执行器之前验证祖先身份、风险、策略继承和受保护请求头，拒绝子层降低父层约束。
///
/// 参数说明：
/// - `topology`：都来自同一候选，分别提供依赖路径、原始声明和已编译策略。
/// - `configs`：都来自同一候选，分别提供依赖路径、原始声明和已编译策略。
/// - `routes`：都来自同一候选，分别提供依赖路径、原始声明和已编译策略。
///
/// 返回：所有路径均可在单次选择中安全执行；身份重置、重复公共策略、非法相位或危险组合拒绝。
pub(super) fn validate(
    topology: &Topology,
    configs: &BTreeMap<&str, &RouteCfg>,
    routes: &BTreeMap<&str, &Arc<Route>>,
) -> Result<()> {
    for (id, node) in &topology.nodes {
        let route = routes[id.as_str()];
        let cfg = configs[id.as_str()];
        ensure!(
            !route.internal
                && route.early_data.is_none()
                && !route.x_accel_redirect
                && route.error_pages.is_empty(),
            "layer routes cannot use internal replay or early data"
        );
        if node.config.branch {
            branch_fields(cfg)?;
            ensure!(
                route.waf.as_ref().is_none_or(|waf| !waf.inspects_body()),
                "route branch WAF cannot inspect a body"
            );
        } else {
            ensure!(
                node.config.context.is_empty(),
                "leaf cannot publish context without a child"
            );
        }
        let mut authenticated = false;
        let mut claims = false;
        let mut consumer = false;
        let mut api_key = false;
        let mut protected = BTreeSet::new();
        let mut cors = false;
        let mut variables = BTreeSet::new();
        let mut filters = BTreeSet::new();
        let mut snippets = BTreeSet::new();
        let mut risks = BTreeSet::from([Risk::NotEvaluated]);
        for ancestor in node.chain.iter() {
            let scope = &topology.nodes[ancestor.as_ref()];
            let current = routes[ancestor.as_ref()];
            let config = configs[ancestor.as_ref()];
            for condition in &scope.config.matches {
                match condition {
                    MatchCfg::Authenticated {
                        value,
                    } => ensure!(
                        *value == authenticated,
                        "layer authentication condition is unreachable"
                    ),
                    MatchCfg::Consumer {
                        ..
                    } => ensure!(
                        consumer,
                        "layer consumer is unavailable before parent authentication"
                    ),
                    MatchCfg::Claim {
                        ..
                    }
                    | MatchCfg::ClaimContains {
                        ..
                    } => ensure!(
                        claims,
                        "layer claim is unavailable before parent JWT verification"
                    ),
                    MatchCfg::Risk {
                        equals,
                    } => {
                        ensure!(risks.contains(equals), "layer WAF condition is unreachable");
                        risks = BTreeSet::from([*equals]);
                    }
                    MatchCfg::Variable {
                        name,
                        ..
                    } => ensure!(
                        variables.contains(name),
                        "layer variable is unavailable before parent policy"
                    ),
                }
            }
            let local = local_authentication(current);
            // 父身份一经成功验证就不再交给后代重新认证；不同凭据组合也不能替换已授权主体。
            ensure!(
                !authenticated || !any_authentication(current),
                "child cannot replace frozen parent identity"
            );
            if scope.config.branch {
                ensure!(
                    current.hmac_auth.is_empty()
                        && current.enterprise_auth.is_empty()
                        && current.ext_authz.is_empty()
                        && current.oidc_rp.is_none()
                        && current
                            .jwt_auth
                            .iter()
                            .all(|policy| !matches!(policy.verifier, JwtVerifier::Remote(_))),
                    "route branch authentication requires local Basic, API-Key or JWT material"
                );
            }
            if local {
                authenticated = true;
                api_key = !current.api_keys.is_empty();
                claims = !current.jwt_auth.is_empty();
                consumer = claims
                    || current.basic_auth.is_some()
                    || current
                        .api_keys
                        .iter()
                        .any(|policy| policy.consumer.is_some());
            }
            // 子层可以借用父层冻结凭据，但必须在完整祖先链中存在真实本地 API-Key 认证来源。
            let needs_api_key = current.llm.as_ref().is_some_and(|llm| {
                llm.token_quota.as_ref().is_some_and(|quota| {
                    quota.dimension == crate::config::model::LlmQuotaDimensionCfg::ApiKey
                }) || llm.semantic_cache.as_ref().is_some_and(|cache| {
                    cache.scope == crate::config::model::LlmCacheScopeCfg::ApiKey
                })
            });
            ensure!(
                !needs_api_key || api_key,
                "layer LLM API-Key scope requires locally verified API-Key authority"
            );
            for (name, value) in &scope.config.context {
                ensure!(
                    !matches!(value, ContextCfg::Claim {
                        ..
                    }) || claims,
                    "trusted context claim requires successful JWT verification"
                );
                variables.insert(name.clone());
            }
            for policy in &current.jwt_auth {
                for mapping in policy.identity_headers.iter() {
                    ensure!(
                        !mapping.header.as_str().starts_with("x-naway-context-"),
                        "layer identity headers cannot use scoped policy context namespace"
                    );
                    protected.insert(mapping.header.as_str().to_owned());
                }
            }
            if current.cors.is_some() {
                ensure!(!cors, "child cannot replace or repeat parent CORS");
                cors = true;
            }
            for filter in &config.filters {
                let normalized = filter.split_whitespace().collect::<Vec<_>>().join(" ");
                ensure!(
                    filters.insert(normalized),
                    "layer path repeats a filter policy"
                );
            }
            for snippet in &config.resolved_snippets {
                ensure!(
                    snippets.insert(snippet),
                    "layer path repeats a shared middleware"
                );
            }
            if let Some(waf) = &current.waf {
                let mut after = BTreeSet::new();
                for risk in &risks {
                    after.insert(if *risk == Risk::NotEvaluated {
                        Risk::Clear
                    } else {
                        *risk
                    });
                }
                if !waf.enforces() {
                    after.insert(Risk::Matched);
                }
                risks = after;
            }
            // 公共缓存没有经过用户身份分区，已认证父路径不能借无认证 leaf 的表面配置开启共享响应。
            ensure!(
                !authenticated || current.http_cache.is_none(),
                "authenticated layer path cannot use public response cache"
            );
            ensure!(
                current.request_headers.iter().all(|operation| {
                    let name = match operation {
                        RequestHeaderOp::Set(value) | RequestHeaderOp::Add(value) => &value.name,
                        RequestHeaderOp::Remove(name) => name,
                    };
                    !protected.contains(name.as_str())
                }),
                "child request mutation overlaps frozen identity headers"
            );
            // 这些扩展能在认证后改写任意请求头；没有父身份命名约束时不能引入层级执行链。
            ensure!(
                current.wasm_plugins.is_none()
                    && current.external_plugins.is_none()
                    && current.ext_proc.is_none()
                    && current.opa_authorization.is_none(),
                "layer path does not accept external or arbitrary request mutation plugins"
            );
            ensure!(
                !authenticated
                    || (current.upstream_credentials.is_none()
                        && current.request_transform.is_none()
                        && current.pass_request_headers),
                "authenticated layer path cannot replace or remove frozen identity headers"
            );
        }
        let needs_consumer = route
            .usage_plan
            .as_ref()
            .is_some_and(|plan| plan.require_consumer)
            || route
                .casbin_authorization
                .as_ref()
                .is_some_and(|plan| plan.requires_identity())
            || route.agent.is_some()
            || cfg.llm.as_ref().is_some_and(|llm| llm.governance.is_some());
        ensure!(
            !needs_consumer || (authenticated && consumer),
            "layer leaf requires a locally verified consumer in its parent path or own policy"
        );
    }
    Ok(())
}

/// 业务作用：识别能在分支中完成且产生冻结身份的本地认证，不把外部鉴权头当作主体。
///
/// 参数说明：
/// - `route`：为已编译的原生认证计划。
///
/// 返回：Basic、API-Key 或 JWT 至少一种启用时为 true。
pub(super) fn local_authentication(route: &Route) -> bool {
    route.basic_auth.is_some() || !route.api_keys.is_empty() || !route.jwt_auth.is_empty()
}

/// 业务作用：检测子层所有认证入口，防止已冻结身份被另一认证协议重新解释。
///
/// 参数说明：
/// - `route`：为已编译的叶子或中间层。
///
/// 返回：任一种本地或远端认证启用时为 true。
fn any_authentication(route: &Route) -> bool {
    local_authentication(route)
        || !route.hmac_auth.is_empty()
        || !route.enterprise_auth.is_empty()
        || !route.ext_authz.is_empty()
        || route.oidc_rp.is_some()
}

/// 业务作用：限定分支声明为公开匹配、有限公共 filters 和 head WAF，任何终端配置都不能被静默忽略。
///
/// 参数说明：
/// - `route`：为本地强类型声明；认证和 filter 内容由现有编译器及分支 filter 门处理。
///
/// 返回：没有后端、计量、变换、插件、流式或外呼选项时通过；否则拒绝构建。
fn branch_fields(route: &RouteCfg) -> Result<()> {
    ensure!(
        route.uri.is_empty()
            && route.cgi.is_none()
            && route.webdav.is_none()
            && route.serve.is_none()
            && route.upstream_credentials.is_empty()
            && route.resolved_upstream_credentials.is_empty()
            && !route.preserve_host
            && route.gateway_redirect.is_none()
            && route.hedge.is_none()
            && route.request_validation.is_none()
            && route.request_transform.is_none()
            && route.response_transform.is_none()
            && route.response_contract.is_none()
            && route.geoip.is_none()
            && route.bot.is_none()
            && route.csrf.is_none()
            && route.dlp.is_none()
            && route.graphql_guard.is_none()
            && route.degraphql.is_none()
            && route.opa_authorization.is_none()
            && route.casbin_authorization.is_none()
            && route.wasm_plugins.is_empty()
            && route.script_plugins.is_empty()
            && route.external_plugins.is_empty()
            && route.ext_proc.is_none()
            && route.inference_pool.is_none()
            && route.bff_aggregation.is_none()
            && route.dubbo.is_none()
            && route.mock_response.is_none()
            && route.fault_injection.is_none()
            && route.usage_plan.is_none()
            && route.traffic_limit.is_none()
            && route.forward_proxy.is_none()
            && route.webtransport.is_none()
            && route.early_data.is_none()
            && route.ws_frame.is_none()
            && route.llm.is_none()
            && route.agent.is_none()
            && route.grpc_edge.is_none()
            && route.grpc_transcoding.is_none()
            && route.long_stream_idle_timeout_ms.is_none()
            && route.request_timeout_ms.is_none()
            && route.backend_request_timeout_ms.is_none()
            && route.long_stream_max_lifetime_ms == 0,
        "route branch contains terminal or unsupported configuration"
    );
    Ok(())
}
