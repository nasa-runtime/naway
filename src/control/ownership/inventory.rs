//! 从强类型候选提取对象与引用；组合资源继承父归属，动态来源仍须进入同一完整验证。

use anyhow::{ensure, Result};

use super::{Builder, PLATFORM};
use crate::config::model::{GatewayConfig, RouteCfg};
use crate::security::scopes::Scope;

/// 业务作用：枚举配置对象并收集跨对象引用，不依赖 HashMap 或文件声明顺序裁决授权。
///
/// 参数说明：
/// - `cfg`：为完整强类型候选
/// - `graph`：接收稳定对象与待复验边。
///
/// 返回：完成有界枚举；进程级资源被委派或组合对象错误转移时拒绝候选。
pub(super) fn collect(cfg: &GatewayConfig, graph: &mut Builder<'_>) -> Result<()> {
    for id in cfg.ownership.workspaces.keys() {
        let key = graph.add("workspace", id, None)?;
        ensure!(
            graph.objects[&key].owner.workspace == *id,
            "workspace identity cannot be reassigned"
        );
    }
    for name in [
        "gateway",
        "admin",
        "discovery",
        "config_source",
        "control_plane",
        "runtime_state",
        "access_log",
        "telemetry",
        "reload",
        "long_connections",
        "variables",
        "interface_guard",
        "sentinel",
        "portal_identity",
    ] {
        let key = graph.add("platform", name, None)?;
        ensure!(
            graph.objects[&key].owner.workspace == PLATFORM,
            "process-wide resource cannot be delegated"
        );
    }
    if cfg.proxies.is_empty() {
        let proxy = graph.add("proxy", "default", None)?;
        if let Some(tls) = cfg.server.as_ref().and_then(|server| server.tls.as_ref()) {
            let certificate = child(graph, "certificate", "default", &proxy)?;
            signer(graph, &certificate, tls.private_key_provider.as_ref())?;
            for cert in &tls.certs {
                signer(graph, &certificate, cert.private_key_provider.as_ref())?;
            }
        }
        for route in &cfg.routes {
            collect_route(graph, "default", &proxy, route)?;
        }
    } else {
        for proxy in &cfg.proxies {
            let owner = graph.add("proxy", &proxy.id, None)?;
            if let Some(tls) = &proxy.tls {
                let certificate = child(graph, "certificate", &proxy.id, &owner)?;
                signer(graph, &certificate, tls.private_key_provider.as_ref())?;
                for cert in &tls.certs {
                    signer(graph, &certificate, cert.private_key_provider.as_ref())?;
                }
            }
            for listener in &proxy.gateway_listeners {
                child(
                    graph,
                    "listener",
                    &format!("{}/{}", proxy.id, listener.id),
                    &owner,
                )?;
            }
            for route in &proxy.routes {
                collect_route(graph, &proxy.id, &owner, route)?;
            }
        }
    }
    for listener in &cfg.stream.listeners {
        let key = graph.add("stream_listener", &listener.id, None)?;
        backend(graph, &key, &listener.upstream)?;
        if let Some(tls) = &listener.tls {
            let certificate = child(graph, "stream_certificate", &listener.id, &key)?;
            signer(graph, &certificate, tls.private_key_provider.as_ref())?;
            for cert in &tls.certs {
                signer(graph, &certificate, cert.private_key_provider.as_ref())?;
            }
        }
        for route in &listener.routes {
            let key = child(
                graph,
                "stream_route",
                &format!("{}/{}", listener.id, route.id),
                &key,
            )?;
            backend(graph, &key, &route.upstream)?;
            for upstream in &route.weighted_upstreams {
                backend(graph, &key, &upstream.upstream)?;
            }
        }
    }
    for (id, service) in &cfg.upstreams.services {
        let key = graph.add("service", id, None)?;
        for credential in &service.upstream_credentials {
            graph.edge(&key, "credential", credential)?;
        }
        if service.tls.is_some() {
            child(graph, "upstream_certificate", id, &key)?;
        }
    }
    for credential in &cfg.upstream_credentials {
        let key = graph.add("credential", &credential.name, None)?;
        for value in [
            &credential.value,
            &credential.client_certificate,
            &credential.client_private_key,
        ] {
            secret(graph, &key, value)?;
        }
        for uri in &credential.allowed_backends {
            backend(graph, &key, uri)?;
        }
    }
    for provider in &cfg.secret_providers {
        let key = graph.add("secret_provider", &provider.name, None)?;
        if let Some(envelope) = &provider.envelope {
            graph.edge(&key, "crypto_provider", &envelope.crypto_provider)?;
        }
    }
    for provider in &cfg.crypto_providers {
        graph.add("crypto_provider", &provider.name, None)?;
    }
    // 门户会把应用映射物化为 consumer 套餐；预先声明 parent，保证展开前后仍为同一个 owner。
    if let Some(management) = &cfg.developer_portal.management {
        for team in &management.teams {
            graph.add("team", &team.id, None)?;
        }
        for application in &management.applications {
            let key = graph.add(
                "application",
                &application.id,
                Some(&format!("team:{}", application.team)),
            )?;
            graph.add("consumer", &application.consumer, Some(&key))?;
        }
    }
    for id in cfg.usage_plans.plans.keys() {
        graph.add("plan", id, None)?;
    }
    for (id, plan) in &cfg.usage_plans.consumers {
        let key = format!("consumer:{id}");
        if !graph.objects.contains_key(&key) {
            graph.add("consumer", id, None)?;
        }
        graph.edge(&key, "plan", plan)?;
    }
    let mut groups: Vec<_> = cfg.usage_plans.groups.iter().collect();
    groups.sort_by_key(|(id, _)| *id);
    for (id, group) in groups {
        let key = graph.add("group", id, None)?;
        if let Some(plan) = &group.plan {
            graph.edge(&key, "plan", plan)?;
        }
        for consumer in &group.consumers {
            let consumer_key = format!("consumer:{consumer}");
            if !graph.objects.contains_key(&consumer_key) {
                graph.add("consumer", consumer, Some(&key))?;
            } else if graph.objects[&consumer_key].parent.is_some()
                && !cfg.ownership.objects.contains_key(&consumer_key)
            {
                ensure!(
                    graph.objects[&consumer_key].owner == graph.objects[&key].owner,
                    "implicit consumer in multiple workspaces requires explicit ownership"
                );
            }
            graph.edge(&key, "consumer", consumer)?;
        }
    }
    for product in &cfg.developer_portal.products {
        let key = graph.add("product", &product.id, None)?;
        for version in &product.versions {
            let version_id = format!("{}/{}", product.id, version.id);
            let version_key = child(graph, "product_version", &version_id, &key)?;
            for team in &version.subscription_teams {
                graph.edge(&version_key, "team", team)?;
            }
            for document in &version.documents {
                child(
                    graph,
                    "document",
                    &format!("{version_id}/{}", document.id),
                    &version_key,
                )?;
            }
        }
    }
    for catalog in &cfg.developer_portal.catalogs {
        let key = graph.add("catalog", &catalog.id, None)?;
        graph.edge(&key, "proxy", &catalog.proxy_id)?;
        backend(graph, &key, &catalog.upstream)?;
        if let Some(plan) = catalog
            .usage_plan
            .as_ref()
            .and_then(|plan| plan.default_plan.as_ref())
        {
            graph.edge(&key, "plan", plan)?;
        }
    }
    if let Some(management) = &cfg.developer_portal.management {
        for application in &management.applications {
            let key = format!("application:{}", application.id);
            graph.edge(&key, "team", &application.team)?;
            graph.edge(&key, "plan", &application.plan)?;
            let consumer_key = format!("consumer:{}", application.consumer);
            if !graph.objects.contains_key(&consumer_key) {
                graph.add("consumer", &application.consumer, Some(&key))?;
            }
            graph.edge(&key, "consumer", &application.consumer)?;
            for subscription in &application.subscriptions {
                graph.edge(
                    &key,
                    "product_version",
                    &format!("{}/{}", subscription.product, subscription.version),
                )?;
            }
            for credential in &application.credentials {
                child(
                    graph,
                    "application_credential",
                    &format!("{}/{}", application.id, credential.id),
                    &key,
                )?;
            }
        }
        for binding in &management.bindings {
            graph.edge(
                &format!("route:{}/{}", binding.proxy, binding.route),
                "product_version",
                &format!("{}/{}", binding.product, binding.version),
            )?;
        }
    }
    for policy in &cfg.usage_plans.policies {
        let parent = match &policy.scope {
            Scope::Global => "platform:gateway".to_owned(),
            Scope::Workspace {
                workspace,
            } => format!("workspace:{workspace}"),
            Scope::Service {
                service,
            } => format!("service:{service}"),
            Scope::Product {
                product,
                ..
            } => format!("product:{product}"),
            Scope::Route {
                proxy,
                route,
            } => format!("route:{proxy}/{route}"),
            Scope::Group {
                group,
            } => format!("group:{group}"),
            Scope::Consumer {
                consumer,
            } => format!("consumer:{consumer}"),
        };
        ensure!(
            graph.objects.contains_key(&parent),
            "policy scope owner is absent"
        );
        let key = child(graph, "policy", &policy.id, &parent)?;
        if let Some(plan) = &policy.quota_plan {
            graph.edge(&key, "plan", plan)?;
        }
        if let Some(products) = &policy.products {
            for product in products {
                graph.edge(&key, "product", product)?;
            }
        }
    }
    for (id, snippet) in &cfg.snippets.definitions {
        let key = graph.add("snippet", id, None)?;
        for dependency in &snippet.uses {
            graph.edge(&key, "snippet", dependency)?;
        }
        for filter in &snippet.filters {
            if let Some(dependency) = crate::config::parse_snippet_reference(filter)? {
                graph.edge(&key, "snippet", dependency)?;
            }
        }
    }
    for id in cfg.variables.set.keys() {
        child(graph, "variable", id, "platform:variables")?;
    }
    for map in &cfg.variables.maps {
        child(graph, "variable_map", &map.name, "platform:variables")?;
    }
    Ok(())
}

/// 业务作用：登记 HTTP 路由及组合资源，提取后端、凭据和层级双向引用，避免跨域继承或曝光缺少授权。
///
/// 参数说明：
/// - `graph`：是候选图
/// - `proxy`：绑定入口
/// - `parent`：绑定入口
/// - `route`：是候选路由。
///
/// 返回：路由和引用完整登记；组合资源归属冲突或边数超限失败。
fn collect_route(
    graph: &mut Builder<'_>,
    proxy: &str,
    parent: &str,
    route: &RouteCfg,
) -> Result<()> {
    let id = format!("{proxy}/{}", route.id);
    let key = graph.add("route", &id, Some(parent))?;
    graph.edge(&key, "proxy", proxy)?;
    if let Some(parent) = route
        .layer
        .as_ref()
        .and_then(|layer| layer.parent_ref.as_ref())
    {
        let parent_id = format!("{proxy}/{parent}");
        // 继承父策略与公开子业务是两个授权方向；一侧同意不能替另一侧开放跨工作区入口。
        graph.edge(&key, "route", &parent_id)?;
        graph.edge(&format!("route:{parent_id}"), "route", &id)?;
    }
    for snippet in &route.resolved_snippets {
        graph.edge(&key, "snippet", snippet)?;
    }
    backend(graph, &key, &route.uri)?;
    for credential in &route.upstream_credentials {
        graph.edge(&key, "credential", credential)?;
    }
    if let Some(plan) = route
        .usage_plan
        .as_ref()
        .and_then(|plan| plan.default_plan.as_ref())
    {
        graph.edge(&key, "plan", plan)?;
    }
    if let Some(bff) = &route.bff_aggregation {
        for target in &bff.targets {
            backend(graph, &key, &target.uri)?;
        }
    }
    if let Some(llm) = &route.llm {
        for model in &llm.models {
            backend(graph, &key, &model.uri)?;
            for value in [
                &model.api_key,
                &model.aws_access_key_id,
                &model.aws_secret_access_key,
                &model.aws_session_token,
            ] {
                secret(graph, &key, value)?;
            }
        }
    }
    if let Some(agent) = &route.agent {
        use crate::ai::agent::config::{AgentCfg, ToolBackendCfg};
        match agent {
            AgentCfg::Mcp(config) => {
                for server in &config.servers {
                    backend(graph, &key, &server.target.uri)?;
                }
                for spec in &config.openapi {
                    backend(graph, &key, &spec.target.uri)?;
                }
                for tool in &config.tools {
                    if let ToolBackendCfg::Rest {
                        target,
                        ..
                    } = &tool.backend
                    {
                        backend(graph, &key, &target.uri)?;
                    }
                }
            }
            AgentCfg::A2a(config) => backend(graph, &key, &config.target.uri)?,
        }
    }
    for plugin in &route.wasm_plugins {
        child(graph, "wasm", &format!("{id}/{}", plugin.id), &key)?;
    }
    for plugin in &route.script_plugins {
        child(graph, "script", &format!("{id}/{}", plugin.id), &key)?;
    }
    for plugin in &route.external_plugins {
        let plugin_key = child(
            graph,
            "external_plugin",
            &format!("{id}/{}", plugin.id),
            &key,
        )?;
        backend(graph, &plugin_key, &plugin.target)?;
    }
    for (kind, exists) in [
        ("request_validation", route.request_validation.is_some()),
        ("request_transform", route.request_transform.is_some()),
        ("response_contract", route.response_contract.is_some()),
        ("response_transform", route.response_transform.is_some()),
        ("waf", route.waf.is_some()),
        ("geoip", route.geoip.is_some()),
        ("bot", route.bot.is_some()),
        ("csrf", route.csrf.is_some()),
        ("dlp", route.dlp.is_some()),
        ("graphql", route.graphql_guard.is_some()),
        ("degraphql", route.degraphql.is_some()),
        ("opa", route.opa_authorization.is_some()),
        ("casbin", route.casbin_authorization.is_some()),
        ("ext_proc", route.ext_proc.is_some()),
        ("bff", route.bff_aggregation.is_some()),
        ("dubbo", route.dubbo.is_some()),
        ("traffic_limit", route.traffic_limit.is_some()),
        ("llm", route.llm.is_some()),
        ("agent", route.agent.is_some()),
        ("grpc_edge", route.grpc_edge.is_some()),
        ("grpc_transcoding", route.grpc_transcoding.is_some()),
        ("webtransport", route.webtransport.is_some()),
        ("websocket", route.ws_frame.is_some()),
        ("static", route.serve.is_some()),
        ("filters", !route.filters.is_empty()),
    ] {
        if exists {
            child(graph, kind, &id, &key)?;
        }
    }
    Ok(())
}

/// 业务作用：让远程 SecretSource 的 provider 权威进入对象依赖图，防止凭据借远程引用跨域读取。
///
/// 参数说明：
/// - `graph`：为候选图
/// - `source`：为固定使用对象
/// - `value`：为尚未解析的配置文本。
///
/// 返回：本地 SecretSource 不创建跨对象引用；远程引用必须存在精确 provider。
fn secret(graph: &mut Builder<'_>, source: &str, value: &str) -> Result<()> {
    if let Some(reference) = value.strip_prefix("remote://") {
        let (provider, path) = reference
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid remote secret reference"))?;
        ensure!(
            !provider.is_empty() && !path.is_empty(),
            "invalid remote secret reference"
        );
        graph.edge(source, "secret_provider", provider)?;
    }
    Ok(())
}

/// 业务作用：绑定证书与不可导出私钥 provider 的引用权威，不因共享密码客户端隐式跨工作区授权。
///
/// 参数说明：
/// - `graph`：为候选证书归属
/// - `source`：为候选证书归属
/// - `reference`：为可选 signer 声明。
///
/// 返回：所有显式 signer 都进入依赖图，缺失与跨域未授权由统一构建拒绝。
fn signer(
    graph: &mut Builder<'_>,
    source: &str,
    reference: Option<&crate::config::model::ExternalPrivateKeyCfg>,
) -> Result<()> {
    if let Some(reference) = reference {
        graph.edge(source, "crypto_provider", &reference.provider)?;
    }
    Ok(())
}

/// 业务作用：让证书、插件与合同等组合资源严格继承父归属，不能单独转移以绕过父授权。
///
/// 参数说明：
/// - `graph`：是候选图
/// - `kind`：定位子资源
/// - `id`：定位子资源
/// - `parent`：定位组合对象。
///
/// 返回：子资源键；归属与父不一致时拒绝整个候选。
fn child(graph: &mut Builder<'_>, kind: &str, id: &str, parent: &str) -> Result<String> {
    let key = graph.add(kind, id, Some(parent))?;
    ensure!(
        graph.objects[&key].owner == graph.objects[parent].owner,
        "embedded object must inherit its parent owner"
    );
    Ok(key)
}

/// 业务作用：把命名服务 URI 变成依赖边，防止通过另一种协议入口绕过服务归属检查。
///
/// 参数说明：
/// - `graph`：正在构建的归属与引用关系图。
/// - `source`：声明引用关系的来源对象。
/// - `uri`：固定的候选后端 URI。
///
/// 返回：直连外部地址没有控制面对象引用；命名服务必须精确解析并在全图验证时存在。
fn backend(graph: &mut Builder<'_>, source: &str, uri: &str) -> Result<()> {
    if let Some(service) = uri.strip_prefix("lb://") {
        ensure!(
            !service.is_empty() && !service.contains(['/', '?', '#', '@']),
            "invalid owned service reference"
        );
        graph.edge(source, "service", service)?;
    }
    Ok(())
}
