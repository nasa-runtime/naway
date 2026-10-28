//! 来源声明只生成受限原生对象；协议执行、权限图和资源准备仍由统一快照构建器承担。

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::json;

use super::model::{identifier, Kind, Reference};
use super::registry::{Resolved, State, View};
use crate::config::model::{
    GatewayConfig, ProxyCfg, ReusableSnippetCfg, RouteCfg, StaticServiceCfg,
};
use crate::control::ownership::{config::ObjectCfg, Owner, OwnershipCatalog, PLATFORM};
use crate::io::net::Cidr;

/// 只由本地 bootstrap 建立的能力边界；远端对象不能扩大监听端口、后端范围或策略模板目录。
pub(super) struct Policy {
    pub listeners: BTreeSet<SocketAddr>,
    pub origins: BTreeSet<String>,
    pub networks: Vec<(Cidr, BTreeSet<u16>)>,
    pub templates: BTreeSet<String>,
    pub references: BTreeSet<Reference>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listener {
    listen: SocketAddr,
    #[serde(default)]
    server_names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    listener: Reference,
    service: Reference,
    predicates: Vec<String>,
    #[serde(default)]
    middlewares: Vec<Reference>,
    #[serde(default)]
    order: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    instances: Vec<Instance>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    lb: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    uri: String,
    weight: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Middleware {
    /// 模板只能来自本地已展开的 snippet，来源中不接受 Secret 值、文件路径或任意 filter DSL。
    templates: Vec<String>,
}

enum Spec {
    Listener(Listener),
    Route(Route),
    Service(Service),
    Middleware(Middleware),
}

pub(super) struct Report {
    pub active: BTreeSet<Reference>,
    pub withdrawn: BTreeSet<Reference>,
}

/// 业务作用：独立验证类型、公开断言及来源能力，尚未到齐的依赖不获得执行权。
///
/// 参数说明：
/// - `cfg`：是本地声明
/// - `view`：为待验证对象图
/// - `policies`：是冻结的来源能力。
///
/// 返回：强类型声明与不可用目录；不改写本地配置，任何非法字段或越权都拒绝。
fn parse_specs(
    cfg: &GatewayConfig,
    view: &View,
    policies: &BTreeMap<String, Policy>,
) -> Result<(BTreeMap<Reference, Spec>, Report)> {
    ensure!(
        cfg.ownership.enabled,
        "configuration providers require ownership"
    );
    // 先验证原生事实源，禁止本地对象暗中依赖可被远端撤回的派生对象而阻止安全撤路。
    OwnershipCatalog::build(cfg)?;
    ensure!(
        !cfg.proxies.is_empty() && cfg.routes.is_empty() && cfg.server.is_none(),
        "providers require explicit native proxies"
    );
    let mut specs = BTreeMap::new();
    let mut report = Report {
        active: BTreeSet::new(),
        withdrawn: BTreeSet::new(),
    };
    for (key, resolved) in &view.objects {
        validate_owner(cfg, &resolved.authority.owner)?;
        let policy = policies
            .get(&resolved.authority.source)
            .context("provider source policy missing")?;
        if resolved.state != State::Active {
            report.withdrawn.insert(key.clone());
            continue;
        }
        let value = resolved
            .object
            .declaration
            .spec
            .clone()
            .context("active provider spec missing")?;
        let spec = match key.kind {
            Kind::Listener => {
                let listener: Listener = serde_json::from_value(value)?;
                ensure!(
                    listener.listen.port() != 0 && policy.listeners.contains(&listener.listen),
                    "provider listener not authorized"
                );
                ensure!(
                    listener.server_names.len() <= 32
                        && listener.server_names.iter().all(|name| !name.is_empty()
                            && name.len() <= 253
                            && !name.chars().any(char::is_control)),
                    "provider server name budget reached"
                );
                Spec::Listener(listener)
            }
            Kind::Service => {
                let service: Service = serde_json::from_value(value)?;
                ensure!(
                    !service.instances.is_empty() && service.instances.len() <= 256,
                    "provider instance budget reached"
                );
                ensure!(
                    matches!(
                        service.protocol.as_deref(),
                        None | Some("auto" | "h1" | "h2" | "h2c")
                    ),
                    "unsupported provider upstream protocol"
                );
                ensure!(
                    matches!(
                        service.lb.as_deref(),
                        None | Some("round_robin" | "first" | "least_conn")
                    ),
                    "unsupported provider load balancing policy"
                );
                let mut endpoints = BTreeSet::new();
                for instance in &service.instances {
                    ensure!(
                        (1..=65535).contains(&instance.weight),
                        "provider instance weight out of range"
                    );
                    let origin = validate_origin(&instance.uri, policy)?;
                    ensure!(endpoints.insert(origin), "duplicate provider endpoint");
                }
                Spec::Service(service)
            }
            Kind::Middleware => {
                let middleware: Middleware = serde_json::from_value(value)?;
                ensure!(
                    !middleware.templates.is_empty() && middleware.templates.len() <= 16,
                    "provider template budget reached"
                );
                let mut unique = BTreeSet::new();
                for name in &middleware.templates {
                    ensure!(
                        policy.templates.contains(name) && unique.insert(name),
                        "provider template not authorized or repeated"
                    );
                    ensure!(
                        cfg.snippets.definitions.contains_key(name),
                        "provider template missing"
                    );
                    authorize_template(cfg, &resolved.authority.owner, name)?;
                }
                Spec::Middleware(middleware)
            }
            Kind::Route => {
                let route: Route = serde_json::from_value(value)?;
                ensure!(
                    !route.predicates.is_empty()
                        && route.predicates.len() <= 32
                        && route.predicates.iter().all(|value| value.len() <= 1024),
                    "provider predicate budget reached"
                );
                // 来源声明不能携带认证值或可执行变量；公开匹配子集仍交由原生 Router 验证具体语法。
                ensure!(
                    route.predicates.iter().all(|predicate| {
                        predicate.split_once('=').is_some_and(|(kind, value)| {
                            matches!(
                                kind,
                                "Path" | "PathExact" | "PathTemplate" | "Host" | "Method"
                            ) && !value.is_empty()
                                && !value.contains('$')
                                && !value.chars().any(char::is_control)
                        })
                    }),
                    "unsupported provider predicate; use public path, host or method matching"
                );
                // 尚在等待依赖的声明也必须先通过完整语法校验，不能借等待态存入非法可执行配置。
                for predicate in &route.predicates {
                    crate::routing::predicate::parse_predicate(predicate)?;
                }
                ensure!(
                    route.middlewares.len() <= 16,
                    "provider middleware budget reached"
                );
                validate_reference(key, &route.listener, Kind::Listener, policy)?;
                validate_reference(key, &route.service, Kind::Service, policy)?;
                let mut unique = BTreeSet::new();
                for reference in &route.middlewares {
                    ensure!(
                        unique.insert(reference),
                        "duplicate provider middleware reference"
                    );
                    validate_reference(key, reference, Kind::Middleware, policy)?;
                }
                Spec::Route(route)
            }
        };
        specs.insert(key.clone(), spec);
    }
    Ok((specs, report))
}

/// 业务作用：在优先级合并前审核一个来源，不能利用被遮蔽或冲突状态绕过声明的安全边界。
///
/// 参数说明：
/// - `cfg`：是本地声明
/// - `view`：是单来源视图
/// - `policies`：是冻结的来源能力。
///
/// 返回：该来源语法和权限合法时成功；不生成对象或更新来源水位。
pub(super) fn validate(
    cfg: &GatewayConfig,
    view: &View,
    policies: &BTreeMap<String, Policy>,
) -> Result<()> {
    parse_specs(cfg, view, policies).map(|_| ())
}

/// 业务作用：把已经合并的来源图编译为原生配置，不建立另一套数据面解释器。
///
/// 参数说明：
/// - `cfg`：是新读入的本地配置
/// - `view`：是同一事务的合并视图
/// - `policies`：是固定来源能力。
///
/// 返回：生成对象与撤回目录；冲突或依赖未齐的对象不开放路由，越权或非法声明拒绝整个候选。
pub(super) fn apply(
    cfg: &mut GatewayConfig,
    view: &View,
    policies: &BTreeMap<String, Policy>,
) -> Result<Report> {
    let (specs, mut report) = parse_specs(cfg, view, policies)?;
    let mut proxies: BTreeMap<Reference, ProxyCfg> = BTreeMap::new();
    ensure!(
        specs
            .keys()
            .filter(|key| key.kind == Kind::Listener)
            .count()
            <= 64,
        "provider listener capacity reached"
    );
    ensure!(
        specs.keys().filter(|key| key.kind == Kind::Route).count() <= 4096,
        "provider route capacity reached"
    );
    let mut expanded_bytes = 0usize;
    for (key, spec) in &specs {
        let resolved = &view.objects[key];
        let id = physical_id(key);
        match spec {
            Spec::Listener(listener) => {
                ensure!(
                    !cfg.proxies.iter().any(|proxy| proxy.id == id),
                    "provider listener collides with native object"
                );
                let proxy = serde_json::from_value(json!({
                    "id":id,
                    "listen":listener.listen.to_string(),
                    "server_names":listener.server_names
                }))?;
                assign(cfg, "proxy", &id, resolved)?;
                proxies.insert(key.clone(), proxy);
            }
            Spec::Service(service) => {
                ensure!(
                    !cfg.upstreams.services.contains_key(&id),
                    "provider service collides with native object"
                );
                let instances: Vec<_> = service
                    .instances
                    .iter()
                    .map(|instance| {
                        json!({
                            "uri":instance.uri,
                            "weight":instance.weight
                        })
                    })
                    .collect();
                let service: StaticServiceCfg = serde_json::from_value(json!({
                    "instances":instances,
                    "protocol":service.protocol,
                    "lb":service.lb
                }))?;
                assign(cfg, "service", &id, resolved)?;
                cfg.upstreams.services.insert(id, service);
            }
            Spec::Middleware(middleware) => {
                ensure!(
                    !cfg.snippets.definitions.contains_key(&id),
                    "provider middleware collides with native object"
                );
                assign(cfg, "snippet", &id, resolved)?;
                cfg.snippets.definitions.insert(
                    id,
                    ReusableSnippetCfg {
                        uses: middleware.templates.clone(),
                        filters: Vec::new(),
                    },
                );
            }
            Spec::Route(_) => continue,
        }
        report.active.insert(key.clone());
    }
    for (key, spec) in &specs {
        let Spec::Route(route) = spec else {
            continue;
        };
        let resolved = &view.objects[key];
        // 依赖未到齐、冲突、删除或过期都不能开放入口；先发布合法基础对象，避免来源相互等待而无法启动。
        if std::iter::once(&route.listener)
            .chain(std::iter::once(&route.service))
            .chain(&route.middlewares)
            .any(|reference| !specs.contains_key(reference))
        {
            report.withdrawn.insert(key.clone());
            continue;
        }
        let mut filters = Vec::new();
        let mut visited = BTreeSet::new();
        for reference in &route.middlewares {
            let Spec::Middleware(middleware) = &specs[reference] else {
                unreachable!()
            };
            for name in &middleware.templates {
                expand_template(cfg, name, &mut visited, &mut Vec::new(), &mut filters)?;
            }
        }
        let listener_id = physical_id(&route.listener);
        let id = physical_id(key);
        expanded_bytes += filters.iter().map(String::len).sum::<usize>();
        ensure!(
            expanded_bytes <= super::model::MAX_TOTAL_BYTES,
            "provider total expanded template budget reached"
        );
        let mut native: RouteCfg = serde_json::from_value(json!({
            "id":id,
            "uri":format!("lb://{}",physical_id(&route.service)),
            "predicates":route.predicates,
            "filters":filters,
            "order":route.order
        }))?;
        native.resolved_snippets = route.middlewares.iter().map(physical_id).collect();
        native.provider_deadline = std::iter::once(key)
            .chain(std::iter::once(&route.listener))
            .chain(std::iter::once(&route.service))
            .chain(&route.middlewares)
            .map(|reference| {
                view.objects[reference]
                    .valid_until
                    .context("active provider evidence deadline missing")
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min();
        assign(cfg, "route", &format!("{listener_id}/{id}"), resolved)?;
        // 跨来源命名空间已经由 bootstrap 精确授权，再把跨 owner 边交给统一权限图复验。
        grant(
            cfg,
            &resolved.authority.owner,
            &view.objects[&route.listener].authority.owner,
            format!("proxy:{listener_id}"),
        );
        grant(
            cfg,
            &resolved.authority.owner,
            &view.objects[&route.service].authority.owner,
            format!("service:{}", physical_id(&route.service)),
        );
        for reference in &route.middlewares {
            grant(
                cfg,
                &resolved.authority.owner,
                &view.objects[reference].authority.owner,
                format!("snippet:{}", physical_id(reference)),
            );
        }
        proxies
            .get_mut(&route.listener)
            .context("provider listener unavailable")?
            .routes
            .push(native);
        report.active.insert(key.clone());
    }
    cfg.proxies.extend(proxies.into_values());
    OwnershipCatalog::build(cfg)?;
    Ok(report)
}

/// 业务作用：验证 namespace 显式引用及平台精确授权，不接受隐式跨源查找或任意种类转换。
///
/// 参数说明：
/// - `source`：是引用者
/// - `target`：是目标和预期种类
/// - `kind`：是目标和预期种类
/// - `policy`：为固定的跨 namespace 权限。
///
/// 返回：引用合法且边被授权时成功；目标是否已到齐由完整依赖门裁决，缺席时不生成业务路由。
fn validate_reference(
    source: &Reference,
    target: &Reference,
    kind: Kind,
    policy: &Policy,
) -> Result<()> {
    ensure!(
        identifier(&target.namespace) && identifier(&target.name) && target.kind == kind,
        "invalid provider reference"
    );
    ensure!(
        source.namespace == target.namespace || policy.references.contains(target),
        "cross-namespace provider reference not authorized"
    );
    Ok(())
}

/// 业务作用：以来源中立 identity 生成无分隔符歧义的原生对象名称。
///
/// 参数说明：
/// - `key`：是已经验证的 namespace、种类和名称。
///
/// 返回：稳定、无路径和 URI 特殊字符的名称，不依赖到达顺序或来源实例。
pub(super) fn physical_id(key: &Reference) -> String {
    let kind = match key.kind {
        Kind::Listener => "listener",
        Kind::Route => "route",
        Kind::Service => "service",
        Kind::Middleware => "middleware",
    };
    format!(
        "provider_{}_{}_{kind}_{}",
        key.namespace.len(),
        key.namespace,
        key.name
    )
}

/// 业务作用：限制后端为本地授权的 HTTP origin，远端不能注入凭据、路径、端口或未授权网络。
///
/// 参数说明：
/// - `raw`：是远端实例 URI
/// - `policy`：为精确 origin 或 IP 网段与端口能力。
///
/// 返回：规范 origin；无法证实授权或携带请求级数据时拒绝。
pub(super) fn validate_origin(raw: &str, policy: &Policy) -> Result<String> {
    ensure!(
        raw.len() <= 2048
            && !raw.contains(['\\', '$', '#', '?'])
            && !raw.chars().any(char::is_control),
        "invalid provider backend URI"
    );
    let uri = reqwest::Url::parse(raw)?;
    let authority = raw
        .split_once("://")
        .map(|(_, tail)| tail.strip_suffix('/').unwrap_or(tail))
        .context("provider backend origin missing")?;
    ensure!(
        !authority.contains(['/', '@', '%']) && authority.is_ascii(),
        "provider backend must use a literal origin"
    );
    ensure!(
        matches!(uri.scheme(), "http" | "https")
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri.query().is_none()
            && uri.fragment().is_none()
            && uri.path() == "/",
        "provider backend must be an HTTP origin without credentials"
    );
    let origin = uri.origin().ascii_serialization();
    let ip = uri.host_str().and_then(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()
    });
    let authorized = ip
        .zip(uri.port_or_known_default())
        .is_some_and(|(ip, port)| {
            policy
                .networks
                .iter()
                .any(|(network, ports)| network.contains(ip) && ports.contains(&port))
        });
    ensure!(
        policy.origins.contains(&origin) || authorized,
        "provider backend not authorized"
    );
    Ok(origin)
}

/// 业务作用：复验来源 owner 的完整本地绑定，不能只按 workspace 字符串接受旧租户或旧环境身份。
///
/// 参数说明：
/// - `cfg`：是本地配置
/// - `owner`：是来源冻结身份。
///
/// 返回：三元归属仍与本地权威一致时成功，撤权或迁移立即拒绝候选。
fn validate_owner(cfg: &GatewayConfig, owner: &Owner) -> Result<()> {
    if owner.workspace == PLATFORM {
        ensure!(
            owner.tenant == PLATFORM && owner.environment == PLATFORM,
            "invalid platform provider owner"
        );
    } else {
        let binding = cfg
            .ownership
            .workspaces
            .get(&owner.workspace)
            .context("provider workspace missing")?;
        ensure!(
            binding.tenant == owner.tenant && binding.environment == owner.environment,
            "provider owner binding changed"
        );
    }
    Ok(())
}

/// 业务作用：将生成对象固定到来源 owner，禁止覆盖平台已有的对象归属声明。
///
/// 参数说明：
/// - `cfg`：接收新声明
/// - `kind`：定位原生对象
/// - `id`：定位原生对象
/// - `resolved`：是已经合并的归属证据。
///
/// 返回：新增唯一归属；碰撞拒绝，调用者丢弃整个候选。
fn assign(cfg: &mut GatewayConfig, kind: &str, id: &str, resolved: &Resolved) -> Result<()> {
    let key = format!("{kind}:{id}");
    ensure!(
        !cfg.ownership.objects.contains_key(&key),
        "provider ownership collides with native assignment"
    );
    cfg.ownership.objects.insert(
        key,
        ObjectCfg {
            workspace: resolved.authority.owner.workspace.clone(),
            name: None,
            labels: BTreeMap::new(),
        },
    );
    Ok(())
}

/// 业务作用：把已经获平台精确授权的跨来源边纳入原生引用图，保证最终构建继续检查同一 owner。
///
/// 参数说明：
/// - `cfg`：为候选
/// - `source`：为两端完整归属
/// - `target_owner`：为两端完整归属
/// - `target`：为原生稳定身份。
///
/// 返回：跨 owner 时增加一条精确边授权，同 owner 不增加任何权限。
fn grant(cfg: &mut GatewayConfig, source: &Owner, target_owner: &Owner, target: String) {
    if source != target_owner
        && !cfg
            .ownership
            .grants
            .iter()
            .any(|grant| grant.source_workspace == source.workspace && grant.target == target)
    {
        cfg.ownership
            .grants
            .push(crate::control::ownership::config::GrantCfg {
                source_workspace: source.workspace.clone(),
                target,
            });
    }
}

/// 业务作用：确认可复用的本地模板已有跨工作区授权，模板名称 allowlist 不等于读取其它租户策略的权限。
///
/// 参数说明：
/// - `cfg`：是本地权威
/// - `owner`：是 middleware 归属
/// - `name`：是本地 snippet 身份。
///
/// 返回：同 owner 或本地精确 grant 有效时成功，否则拒绝。
fn authorize_template(cfg: &GatewayConfig, owner: &Owner, name: &str) -> Result<()> {
    let target = format!("snippet:{name}");
    let workspace = cfg
        .ownership
        .objects
        .get(&target)
        .map(|object| object.workspace.as_str())
        .unwrap_or(PLATFORM);
    ensure!(
        workspace == owner.workspace
            || cfg
                .ownership
                .grants
                .iter()
                .any(|grant| grant.source_workspace == owner.workspace && grant.target == target),
        "provider template owner not authorized"
    );
    Ok(())
}

/// 业务作用：将本地策略模板按显式依赖展开，阻止循环、菱形重复执行与无限 filter 复制。
///
/// 参数说明：
/// - `cfg`：指定模板
/// - `name`：指定模板
/// - `visited`：记录一次路由的执行图
/// - `stack`：记录一次路由的执行图
/// - `filters`：接收原生策略。
///
/// 返回：最多十六层、二百五十六条和六十四 KiB 的策略链；重复执行或超预算拒绝。
fn expand_template(
    cfg: &GatewayConfig,
    name: &str,
    visited: &mut BTreeSet<String>,
    stack: &mut Vec<String>,
    filters: &mut Vec<String>,
) -> Result<()> {
    ensure!(
        stack.len() < 16 && !stack.iter().any(|item| item == name) && visited.insert(name.into()),
        "provider template cycle or repeated execution"
    );
    stack.push(name.into());
    let template = cfg
        .snippets
        .definitions
        .get(name)
        .context("provider template missing")?;
    for dependency in &template.uses {
        expand_template(cfg, dependency, visited, stack, filters)?;
    }
    for filter in &template.filters {
        if let Some(dependency) = crate::config::parse_snippet_reference(filter)? {
            expand_template(cfg, dependency, visited, stack, filters)?;
        } else {
            ensure!(
                filters.len() < 256
                    && filters
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                        .saturating_add(filter.len())
                        <= 65536,
                "provider expanded template budget reached"
            );
            filters.push(filter.clone());
        }
    }
    stack.pop();
    Ok(())
}
