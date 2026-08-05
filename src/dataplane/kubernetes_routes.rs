//! Kubernetes Ingress/Gateway API 控制面路由源。
//!
//! 远端对象绝不在请求线程解析。后台 controller 把受支持对象编译成一个有界 JSON 候选，
//! 以同目录原子 rename 发布；唯一 reload worker 随后重新读取、强类型反序列化并执行完整
//! build-then-swap。失败轮询保留 LKG，freshness 心跳与内容文件分离，因此健康轮询不会制造
//! 配置版本风暴，失联超过 TTL 又能让旧路由可靠退场。

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use bytes::BytesMut;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::model::{
    GatewayConfig, KubernetesDiscoveryCfg, KubernetesRouteSourceCfg, RouteCfg, StaticServiceCfg,
};
use crate::config::GatewaySnapshot;
use crate::reload::ReloadHandle;

const GENERATED_SCHEMA_VERSION: u32 = 1;
const MAX_GENERATED_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROUTE_OBJECTS_HARD: usize = 16_384;
const MAX_ROUTES_HARD: usize = 16_384;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedDocument {
    schema_version: u32,
    source_fingerprint: String,
    generation: String,
    routes: Vec<Value>,
    services: BTreeMap<String, Value>,
}

/// 校验路由源 bootstrap 契约。凭据和 API endpoint 的通用校验由 discovery builder 负责。
pub(crate) fn validate_config(
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    anyhow::ensure!(
        discovery.enabled,
        "kubernetes_routes.enabled requires discovery.kubernetes.enabled=true"
    );
    anyhow::ensure!(
        cfg.ingress_enabled || cfg.gateway_api_enabled,
        "kubernetes_routes requires ingress_enabled or gateway_api_enabled"
    );
    validate_safe_name("kubernetes_routes.target_proxy", &cfg.target_proxy, 128)?;
    validate_materialized_file(&cfg.materialized_file)?;
    anyhow::ensure!(
        (100..=3_600_000).contains(&cfg.poll_interval_ms),
        "kubernetes_routes.poll_interval_ms must be within 100..=3600000"
    );
    anyhow::ensure!(
        (50..=60_000).contains(&cfg.request_timeout_ms),
        "kubernetes_routes.request_timeout_ms must be within 50..=60000"
    );
    anyhow::ensure!(
        cfg.stale_ttl_ms == 0 || cfg.stale_ttl_ms >= cfg.poll_interval_ms,
        "kubernetes_routes.stale_ttl_ms must be 0 or at least poll_interval_ms"
    );
    anyhow::ensure!(
        (1..=16 * 1024 * 1024).contains(&cfg.max_response_bytes),
        "kubernetes_routes.max_response_bytes must be within 1..=16777216"
    );
    anyhow::ensure!(
        (1..=MAX_ROUTE_OBJECTS_HARD).contains(&cfg.max_objects),
        "kubernetes_routes.max_objects must be within 1..={MAX_ROUTE_OBJECTS_HARD}"
    );
    anyhow::ensure!(
        (1..=MAX_ROUTES_HARD).contains(&cfg.max_routes),
        "kubernetes_routes.max_routes must be within 1..={MAX_ROUTES_HARD}"
    );
    anyhow::ensure!(
        cfg.ingress_classes.len() <= 64,
        "kubernetes_routes.ingress_classes supports at most 64 entries"
    );
    for class in &cfg.ingress_classes {
        validate_kubernetes_name("kubernetes_routes.ingress_classes", class)?;
    }
    validate_controller_name(&cfg.gateway_controller_name)?;
    anyhow::ensure!(
        cfg.namespaces.len() <= 256,
        "kubernetes_routes.namespaces supports at most 256 entries"
    );
    for namespace in &cfg.namespaces {
        validate_kubernetes_name("kubernetes_routes.namespaces", namespace)?;
    }
    Ok(())
}

/// 将 controller 物化文件并入主配置候选。文件缺失/过期/来源签名不匹配都按“尚无远端
/// 路由”处理；文件结构损坏则拒绝候选，防止半写内容悄悄删掉当前路由。
pub(crate) fn apply_generated_routes(
    cfg: &mut GatewayConfig,
    config_dir: &Path,
) -> anyhow::Result<()> {
    validate_config(&cfg.kubernetes_routes, &cfg.discovery.kubernetes)?;
    if !cfg.kubernetes_routes.enabled {
        return Ok(());
    }
    ensure_target_proxy(cfg)?;
    let path = materialized_path(config_dir, &cfg.kubernetes_routes)?;
    let heartbeat = heartbeat_path(&path);
    if !path.exists() {
        return Ok(());
    }
    if cfg.kubernetes_routes.stale_ttl_ms > 0
        && !heartbeat_is_fresh(&heartbeat, cfg.kubernetes_routes.stale_ttl_ms)
    {
        tracing::warn!(file = %path.display(), "Kubernetes generated routes are stale; ignoring materialized LKG");
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect Kubernetes generated routes {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Kubernetes generated route file must be a regular non-symlink file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_GENERATED_FILE_BYTES as u64,
        "Kubernetes generated route file exceeds {MAX_GENERATED_FILE_BYTES} bytes"
    );
    let bytes = crate::bounded_io::read_file(
        &path,
        MAX_GENERATED_FILE_BYTES,
        "Kubernetes generated route file",
    )?;
    let document: GeneratedDocument =
        serde_json::from_slice(&bytes).context("decode Kubernetes generated route document")?;
    anyhow::ensure!(
        document.schema_version == GENERATED_SCHEMA_VERSION,
        "unsupported Kubernetes generated route schema_version {}",
        document.schema_version
    );
    let expected = source_fingerprint(&cfg.kubernetes_routes, &cfg.discovery.kubernetes);
    if document.source_fingerprint != expected {
        tracing::info!(file = %path.display(), "Kubernetes generated routes belong to an old source configuration; waiting for controller refresh");
        return Ok(());
    }
    anyhow::ensure!(
        document.routes.len() <= cfg.kubernetes_routes.max_routes,
        "Kubernetes generated routes exceed configured max_routes"
    );
    anyhow::ensure!(
        document.services.len() <= cfg.kubernetes_routes.max_routes,
        "Kubernetes generated services exceed configured max_routes"
    );
    let actual_generation = generation_digest(&document.routes, &document.services)?;
    anyhow::ensure!(
        actual_generation == document.generation,
        "Kubernetes generated route generation digest mismatch"
    );

    let mut routes = Vec::with_capacity(document.routes.len());
    for value in document.routes {
        routes.push(
            serde_json::from_value::<RouteCfg>(value)
                .context("decode generated Kubernetes route")?,
        );
    }
    for (name, value) in document.services {
        let service = serde_json::from_value::<StaticServiceCfg>(value)
            .with_context(|| format!("decode generated Kubernetes service `{name}`"))?;
        anyhow::ensure!(
            !cfg.upstreams.services.contains_key(&name),
            "Kubernetes generated service `{name}` collides with gateway.yml upstream"
        );
        cfg.upstreams.services.insert(name, service);
    }
    if cfg.proxies.is_empty() {
        cfg.routes.extend(routes);
    } else {
        cfg.proxies
            .iter_mut()
            .find(|proxy| proxy.id == cfg.kubernetes_routes.target_proxy)
            .expect("target proxy checked before merge")
            .routes
            .extend(routes);
    }
    Ok(())
}

/// 将物化文件纳入 reload 去重指纹；heartbeat 刻意不加入，健康轮询只刷新 freshness，
/// 不触发无意义的 snapshot 版本增长。
pub(crate) fn generated_dependency(cfg: &GatewayConfig, config_dir: &Path) -> Option<PathBuf> {
    cfg.kubernetes_routes
        .enabled
        .then(|| materialized_path(config_dir, &cfg.kubernetes_routes))
        .transpose()
        .ok()
        .flatten()
}

/// 启动 Kubernetes 路由 controller。配置通过 ArcSwap 读取，reload 后无需重建 task；远端
/// client 只在 endpoint/CA/token 变化时重建。
pub fn spawn_controller(
    snap: Arc<ArcSwap<GatewaySnapshot>>,
    cfg_path: PathBuf,
    reload: ReloadHandle,
) {
    tokio::spawn(async move {
        let config_dir = cfg_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let mut client_state: Option<(KubernetesDiscoveryCfg, reqwest::Client)> = None;
        let mut failure_since: Option<tokio::time::Instant> = None;
        let mut expired_published = false;
        loop {
            let current = snap.load();
            let route_cfg = current.kubernetes_routes.clone();
            let discovery = current.discovery.kubernetes.clone();
            drop(current);
            if !route_cfg.enabled {
                client_state = None;
                failure_since = None;
                expired_published = false;
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            if client_state
                .as_ref()
                .is_none_or(|(active, _)| active != &discovery)
            {
                match build_client(&discovery) {
                    Ok(client) => client_state = Some((discovery.clone(), client)),
                    Err(error) => {
                        tracing::error!(%error, "build Kubernetes route controller client failed");
                        tokio::time::sleep(Duration::from_millis(route_cfg.poll_interval_ms)).await;
                        continue;
                    }
                }
            }
            let client = &client_state
                .as_ref()
                .expect("client state populated above")
                .1;
            let attempt = tokio::time::timeout(
                Duration::from_millis(route_cfg.request_timeout_ms),
                fetch_and_compile(client, &route_cfg, &discovery),
            )
            .await;
            match attempt {
                Ok(Ok((routes, services))) => {
                    failure_since = None;
                    expired_published = false;
                    match publish_document(&config_dir, &route_cfg, &discovery, routes, services)
                        .await
                    {
                        Ok(changed) => {
                            if changed && !reload.trigger_file().await {
                                tracing::warn!(
                                    "reload worker stopped after Kubernetes route publish"
                                );
                                return;
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "publish Kubernetes generated routes failed")
                        }
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "Kubernetes route poll failed; keeping last-known-good");
                    mark_failure_and_maybe_expire(
                        &config_dir,
                        &route_cfg,
                        &discovery,
                        &reload,
                        &mut failure_since,
                        &mut expired_published,
                    )
                    .await;
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = route_cfg.request_timeout_ms,
                        "Kubernetes route poll timed out; keeping last-known-good"
                    );
                    mark_failure_and_maybe_expire(
                        &config_dir,
                        &route_cfg,
                        &discovery,
                        &reload,
                        &mut failure_since,
                        &mut expired_published,
                    )
                    .await;
                }
            }
            tokio::time::sleep(Duration::from_millis(route_cfg.poll_interval_ms)).await;
        }
    });
}

async fn mark_failure_and_maybe_expire(
    config_dir: &Path,
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
    reload: &ReloadHandle,
    failure_since: &mut Option<tokio::time::Instant>,
    expired_published: &mut bool,
) {
    let since = failure_since.get_or_insert_with(tokio::time::Instant::now);
    if cfg.stale_ttl_ms == 0
        || *expired_published
        || since.elapsed() < Duration::from_millis(cfg.stale_ttl_ms)
    {
        return;
    }
    match publish_document(config_dir, cfg, discovery, Vec::new(), BTreeMap::new()).await {
        Ok(_) => {
            *expired_published = true;
            let _ = reload.trigger_file().await;
            tracing::error!(
                stale_ttl_ms = cfg.stale_ttl_ms,
                "Kubernetes route LKG expired; published empty route set"
            );
        }
        Err(error) => tracing::error!(%error, "expire Kubernetes generated routes failed"),
    }
}

fn build_client(cfg: &KubernetesDiscoveryCfg) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if !cfg.ca_certificate.is_empty() {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(cfg.ca_certificate.as_bytes())
                .context("parse Kubernetes API CA")?,
        );
    }
    builder.build().context("build Kubernetes API client")
}

async fn fetch_and_compile(
    client: &reqwest::Client,
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
) -> anyhow::Result<(Vec<Value>, BTreeMap<String, Value>)> {
    let mut routes = Vec::new();
    let mut services = BTreeMap::new();
    if cfg.ingress_enabled {
        let value = fetch_resource(
            client,
            discovery,
            "/apis/networking.k8s.io/v1/ingresses",
            cfg.max_response_bytes,
        )
        .await?;
        compile_ingresses(&value, cfg, &mut routes, &mut services)?;
    }
    if cfg.gateway_api_enabled {
        let classes = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/gatewayclasses",
            cfg.max_response_bytes,
        )
        .await?;
        let gateways = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/gateways",
            cfg.max_response_bytes,
        )
        .await?;
        let http_routes = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/httproutes",
            cfg.max_response_bytes,
        )
        .await?;
        compile_gateway_api(
            &classes,
            &gateways,
            &http_routes,
            cfg,
            &mut routes,
            &mut services,
        )?;
    }
    anyhow::ensure!(
        routes.len() <= cfg.max_routes,
        "Kubernetes objects expand beyond max_routes"
    );
    routes.sort_by(|left, right| route_sort_key(left).cmp(route_sort_key(right)));
    Ok((routes, services))
}

async fn fetch_resource(
    client: &reqwest::Client,
    cfg: &KubernetesDiscoveryCfg,
    path: &str,
    max_bytes: usize,
) -> anyhow::Result<Value> {
    let url = format!("{}{}", cfg.api_server, path);
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if !cfg.bearer_token.is_empty() {
        request = request.bearer_auth(&cfg.bearer_token);
    }
    let response = request
        .send()
        .await
        .context("send Kubernetes API request")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(json!({"items": []}));
    }
    let status = response.status();
    if let Some(length) = response.content_length() {
        anyhow::ensure!(
            length <= max_bytes as u64,
            "Kubernetes API Content-Length exceeds max_response_bytes"
        );
    }
    let mut body = BytesMut::with_capacity(
        response
            .content_length()
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0)
            .min(max_bytes),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read Kubernetes API response")?;
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= max_bytes,
            "Kubernetes API response exceeds max_response_bytes"
        );
        body.extend_from_slice(&chunk);
    }
    anyhow::ensure!(status.is_success(), "Kubernetes API returned HTTP {status}");
    serde_json::from_slice(&body).context("decode Kubernetes API JSON")
}

fn compile_ingresses(
    value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    routes: &mut Vec<Value>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let items = resource_items(value, cfg.max_objects, "Ingress")?;
    for ingress in items {
        let (namespace, name) = object_identity(ingress, "Ingress")?;
        if !namespace_allowed(cfg, namespace) || !ingress_selected(ingress, cfg) {
            continue;
        }
        let annotations = ingress
            .pointer("/metadata/annotations")
            .and_then(Value::as_object);
        let scheme = annotations
            .and_then(|value| value.get("gateway.rust.dev/backend-scheme"))
            .and_then(Value::as_str)
            .unwrap_or("http");
        anyhow::ensure!(
            matches!(scheme, "http" | "https"),
            "Ingress {namespace}/{name} has unsupported backend scheme"
        );
        if let Some(default_backend) = ingress.pointer("/spec/defaultBackend") {
            push_ingress_route(
                namespace,
                name,
                None,
                "/",
                "Prefix",
                default_backend,
                scheme,
                routes,
                services,
            )?;
        }
        let rules = ingress
            .pointer("/spec/rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for rule in rules {
            let host = rule.get("host").and_then(Value::as_str);
            let paths = rule
                .pointer("/http/paths")
                .and_then(Value::as_array)
                .context("selected Ingress rule missing http.paths")?;
            for path in paths {
                let raw_path = path.get("path").and_then(Value::as_str).unwrap_or("/");
                let path_type = path
                    .get("pathType")
                    .and_then(Value::as_str)
                    .unwrap_or("Prefix");
                let backend = path
                    .get("backend")
                    .context("selected Ingress path missing backend")?;
                push_ingress_route(
                    namespace, name, host, raw_path, path_type, backend, scheme, routes, services,
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_ingress_route(
    namespace: &str,
    object_name: &str,
    host: Option<&str>,
    path: &str,
    path_type: &str,
    backend: &Value,
    scheme: &str,
    routes: &mut Vec<Value>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    validate_http_path(path)?;
    let service_name = backend
        .pointer("/service/name")
        .and_then(Value::as_str)
        .context("Ingress backend missing service.name")?;
    validate_kubernetes_name("Ingress backend service", service_name)?;
    let port = backend
        .pointer("/service/port")
        .context("Ingress backend missing service.port")?;
    let port = parse_backend_port(port, "Ingress")?;
    let logical = insert_generated_service(services, namespace, service_name, &port, scheme)?;
    let mut predicates = vec![path_predicate(path, path_type)?];
    if let Some(host) = host.filter(|value| !value.is_empty()) {
        predicates.push(format!("Host={host}"));
    }
    let id = stable_id(
        "k8s-ingress",
        &[namespace, object_name, host.unwrap_or(""), path, &logical],
    );
    routes.push(json!({
        "id": id,
        "uri": format!("lb://{logical}"),
        "predicates": predicates,
        "order": 0
    }));
    Ok(())
}

fn compile_gateway_api(
    classes_value: &Value,
    gateways_value: &Value,
    routes_value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    routes: &mut Vec<Value>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?;
    let selected_classes = classes
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let gateways = resource_items(gateways_value, cfg.max_objects, "Gateway")?;
    let mut selected_gateways = HashSet::new();
    for gateway in gateways {
        let (namespace, name) = object_identity(gateway, "Gateway")?;
        if !namespace_allowed(cfg, namespace) {
            continue;
        }
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if selected_classes.contains(class) {
            selected_gateways.insert((namespace.to_owned(), name.to_owned()));
        }
    }
    let http_routes = resource_items(routes_value, cfg.max_objects, "HTTPRoute")?;
    for http_route in http_routes {
        let (namespace, name) = object_identity(http_route, "HTTPRoute")?;
        if !namespace_allowed(cfg, namespace)
            || !http_route_attaches(http_route, namespace, &selected_gateways)?
        {
            continue;
        }
        let hostnames = http_route
            .pointer("/spec/hostnames")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .context("HTTPRoute hostname must be a string")
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let rules = http_route
            .pointer("/spec/rules")
            .and_then(Value::as_array)
            .context("selected HTTPRoute missing spec.rules")?;
        for (rule_index, rule) in rules.iter().enumerate() {
            anyhow::ensure!(
                rule.get("filters")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "HTTPRoute {namespace}/{name} filters are not supported; refusing to broaden semantics"
            );
            let backends = rule
                .get("backendRefs")
                .and_then(Value::as_array)
                .context("HTTPRoute rule missing backendRefs")?;
            anyhow::ensure!(
                backends.len() == 1,
                "HTTPRoute {namespace}/{name} requires exactly one backendRef"
            );
            let backend = &backends[0];
            let group = backend.get("group").and_then(Value::as_str).unwrap_or("");
            let kind = backend
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Service");
            anyhow::ensure!(
                group.is_empty() && kind == "Service",
                "HTTPRoute backendRef must target a core Service"
            );
            let service_name = backend
                .get("name")
                .and_then(Value::as_str)
                .context("HTTPRoute backendRef missing name")?;
            let backend_namespace = backend
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or(namespace);
            anyhow::ensure!(
                backend_namespace == namespace,
                "cross-namespace HTTPRoute backendRef requires ReferenceGrant support"
            );
            let port = backend
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value > 0)
                .context("HTTPRoute Service backendRef requires a valid numeric port")?;
            let logical = insert_generated_service(
                services,
                namespace,
                service_name,
                &BackendPort::Number(port),
                "http",
            )?;
            let matches = rule
                .get("matches")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| vec![json!({})]);
            for (match_index, route_match) in matches.iter().enumerate() {
                anyhow::ensure!(
                    route_match
                        .get("headers")
                        .and_then(Value::as_array)
                        .is_none_or(Vec::is_empty)
                        && route_match
                            .get("queryParams")
                            .and_then(Value::as_array)
                            .is_none_or(Vec::is_empty),
                    "HTTPRoute {namespace}/{name} header/query matches are unsupported; refusing to broaden semantics"
                );
                let path = route_match
                    .pointer("/path/value")
                    .and_then(Value::as_str)
                    .unwrap_or("/");
                let path_type = route_match
                    .pointer("/path/type")
                    .and_then(Value::as_str)
                    .unwrap_or("PathPrefix");
                validate_http_path(path)?;
                let mut predicates = vec![path_predicate(path, path_type)?];
                if !hostnames.is_empty() {
                    predicates.push(format!("Host={}", hostnames.join(",")));
                }
                if let Some(method) = route_match.get("method").and_then(Value::as_str) {
                    predicates.push(format!("Method={method}"));
                }
                let id = stable_id(
                    "k8s-httproute",
                    &[
                        namespace,
                        name,
                        &rule_index.to_string(),
                        &match_index.to_string(),
                        path,
                        &logical,
                    ],
                );
                routes.push(json!({
                    "id": id,
                    "uri": format!("lb://{logical}"),
                    "predicates": predicates,
                    "order": 0
                }));
            }
        }
    }
    Ok(())
}

fn http_route_attaches(
    route: &Value,
    route_namespace: &str,
    gateways: &HashSet<(String, String)>,
) -> anyhow::Result<bool> {
    let parents = route
        .pointer("/spec/parentRefs")
        .and_then(Value::as_array)
        .context("HTTPRoute missing spec.parentRefs")?;
    for parent in parents {
        let group = parent
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("gateway.networking.k8s.io");
        let kind = parent
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Gateway");
        if group != "gateway.networking.k8s.io" || kind != "Gateway" {
            continue;
        }
        let Some(name) = parent.get("name").and_then(Value::as_str) else {
            continue;
        };
        let namespace = parent
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(route_namespace);
        if gateways.contains(&(namespace.to_owned(), name.to_owned())) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone)]
enum BackendPort {
    Name(String),
    Number(u16),
}

fn parse_backend_port(value: &Value, source: &str) -> anyhow::Result<BackendPort> {
    if let Some(name) = value.get("name").and_then(Value::as_str) {
        validate_kubernetes_name(&format!("{source} backend port name"), name)?;
        return Ok(BackendPort::Name(name.to_owned()));
    }
    if let Some(number) = value
        .get("number")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value > 0)
    {
        return Ok(BackendPort::Number(number));
    }
    bail!("{source} backend port must contain name or number")
}

fn insert_generated_service(
    services: &mut BTreeMap<String, Value>,
    namespace: &str,
    service_name: &str,
    port: &BackendPort,
    scheme: &str,
) -> anyhow::Result<String> {
    validate_kubernetes_name("backend namespace", namespace)?;
    validate_kubernetes_name("backend service", service_name)?;
    let port_key = match port {
        BackendPort::Name(name) => format!("name-{name}"),
        BackendPort::Number(number) => format!("port-{number}"),
    };
    let logical = stable_id("k8s-svc", &[namespace, service_name, &port_key, scheme]);
    let mut value = json!({
        "source": "kubernetes",
        "registry_service": service_name,
        "registry_namespace": namespace,
        "scheme": scheme
    });
    match port {
        BackendPort::Name(name) => value["registry_port_name"] = json!(name),
        BackendPort::Number(number) => value["registry_port"] = json!(number),
    }
    match services.get(&logical) {
        Some(existing) => anyhow::ensure!(
            existing == &value,
            "generated Kubernetes service id collision for `{logical}`"
        ),
        None => {
            services.insert(logical.clone(), value);
        }
    }
    Ok(logical)
}

fn path_predicate(path: &str, path_type: &str) -> anyhow::Result<String> {
    match path_type {
        "Exact" => Ok(format!("PathExact={path}")),
        "Prefix" | "ImplementationSpecific" | "PathPrefix" => Ok(format!("Path={path}")),
        other => bail!("unsupported Kubernetes path type `{other}`"),
    }
}

fn validate_http_path(path: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.starts_with('/') && path.len() <= 2048 && !path.bytes().any(|byte| byte < 0x20),
        "Kubernetes route path must be an origin path within 2048 bytes"
    );
    Ok(())
}

fn ingress_selected(object: &Value, cfg: &KubernetesRouteSourceCfg) -> bool {
    let class = object
        .pointer("/spec/ingressClassName")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .pointer("/metadata/annotations/kubernetes.io~1ingress.class")
                .and_then(Value::as_str)
        });
    class.is_some_and(|class| cfg.ingress_classes.iter().any(|allowed| allowed == class))
}

fn resource_items<'a>(
    value: &'a Value,
    max_objects: usize,
    kind: &str,
) -> anyhow::Result<&'a [Value]> {
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .with_context(|| format!("Kubernetes {kind} list missing items array"))?;
    anyhow::ensure!(
        items.len() <= max_objects,
        "Kubernetes {kind} list exceeds max_objects"
    );
    Ok(items)
}

fn object_identity<'a>(object: &'a Value, kind: &str) -> anyhow::Result<(&'a str, &'a str)> {
    let namespace = object
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .with_context(|| format!("Kubernetes {kind} missing metadata.name"))?;
    validate_kubernetes_name(&format!("{kind} namespace"), namespace)?;
    validate_kubernetes_name(&format!("{kind} name"), name)?;
    Ok((namespace, name))
}

fn namespace_allowed(cfg: &KubernetesRouteSourceCfg, namespace: &str) -> bool {
    cfg.namespaces.is_empty() || cfg.namespaces.iter().any(|allowed| allowed == namespace)
}

fn route_sort_key(route: &Value) -> &str {
    route.get("id").and_then(Value::as_str).unwrap_or("")
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let readable = parts
        .iter()
        .flat_map(|part| part.bytes())
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        .take(32)
        .map(char::from)
        .collect::<String>();
    format!("{prefix}-{readable}-{}", hex_lower(&digest[..8]))
}

async fn publish_document(
    config_dir: &Path,
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
    routes: Vec<Value>,
    services: BTreeMap<String, Value>,
) -> anyhow::Result<bool> {
    let generation = generation_digest(&routes, &services)?;
    let document = GeneratedDocument {
        schema_version: GENERATED_SCHEMA_VERSION,
        source_fingerprint: source_fingerprint(cfg, discovery),
        generation,
        routes,
        services,
    };
    let bytes = serde_json::to_vec(&document).context("encode Kubernetes generated routes")?;
    anyhow::ensure!(
        bytes.len() <= MAX_GENERATED_FILE_BYTES,
        "Kubernetes generated routes exceed hard file limit"
    );
    let path = materialized_path(config_dir, cfg)?;
    let heartbeat = heartbeat_path(&path);
    let path_for_task = path.clone();
    let changed = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let unchanged = read_bounded_optional(&path_for_task, MAX_GENERATED_FILE_BYTES)?
            .is_some_and(|current| current == bytes);
        if !unchanged {
            atomic_write(&path_for_task, &bytes)?;
        }
        atomic_write(&heartbeat_path(&path_for_task), b"fresh\n")?;
        Ok(!unchanged)
    })
    .await
    .context("join Kubernetes materialization task")??;
    tracing::debug!(file = %path.display(), changed, "Kubernetes route snapshot materialized");
    // `heartbeat` is intentionally only used through metadata; keep the binding above explicit so
    // reviewers see freshness is published after the content file.
    let _ = heartbeat;
    Ok(changed)
}

fn generation_digest(
    routes: &[Value],
    services: &BTreeMap<String, Value>,
) -> anyhow::Result<String> {
    let bytes =
        serde_json::to_vec(&(routes, services)).context("encode route generation digest")?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

fn source_fingerprint(
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        cfg.target_proxy.as_str(),
        cfg.materialized_file.as_str(),
        cfg.gateway_controller_name.as_str(),
        discovery.api_server.as_str(),
        discovery.namespace.as_str(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    for value in &cfg.ingress_classes {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    for value in &cfg.namespaces {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update([
        u8::from(cfg.ingress_enabled),
        u8::from(cfg.gateway_api_enabled),
    ]);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn ensure_target_proxy(cfg: &GatewayConfig) -> anyhow::Result<()> {
    if cfg.proxies.is_empty() {
        anyhow::ensure!(
            cfg.kubernetes_routes.target_proxy == "default",
            "legacy server routes require kubernetes_routes.target_proxy=default"
        );
    } else {
        anyhow::ensure!(
            cfg.proxies
                .iter()
                .any(|proxy| proxy.id == cfg.kubernetes_routes.target_proxy),
            "kubernetes_routes.target_proxy `{}` does not exist",
            cfg.kubernetes_routes.target_proxy
        );
    }
    Ok(())
}

fn validate_materialized_file(value: &str) -> anyhow::Result<()> {
    let path = Path::new(value);
    let mut components = path.components();
    let one =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    anyhow::ensure!(
        one && value.len() <= 128,
        "kubernetes_routes.materialized_file must be one relative file name"
    );
    Ok(())
}

fn materialized_path(config_dir: &Path, cfg: &KubernetesRouteSourceCfg) -> anyhow::Result<PathBuf> {
    validate_materialized_file(&cfg.materialized_file)?;
    Ok(config_dir.join(&cfg.materialized_file))
}

fn heartbeat_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .expect("validated materialized path has a file name")
        .to_os_string();
    name.push(".fresh");
    path.with_file_name(name)
}

fn heartbeat_is_fresh(path: &Path, ttl_ms: u64) -> bool {
    fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age <= Duration::from_millis(ttl_ms))
}

fn read_bounded_optional(path: &Path, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "materialized path must be a regular non-symlink file"
    );
    anyhow::ensure!(
        metadata.len() <= max_bytes as u64,
        "materialized file too large"
    );
    // symlink policy 在上面按路径校验；实际读取仍使用 max+1 句柄上限，防文件在 metadata 后增长。
    let bytes = crate::bounded_io::read_file(path, max_bytes, "Kubernetes materialized file")?;
    Ok(Some(bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .context("materialized path has no file name")?
        .to_string_lossy();
    let temp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> anyhow::Result<()> {
        let mut file = options
            .open(&temp)
            .with_context(|| format!("create {}", temp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temp.display()))?;
        fs::rename(&temp, path).with_context(|| format!("publish {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_safe_name(field: &str, value: &str, max: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= max
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/')
            }),
        "{field} must be 1..={max} safe ASCII characters"
    );
    Ok(())
}

fn validate_kubernetes_name(field: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "{field} is not a valid Kubernetes DNS name"
    );
    Ok(())
}

fn validate_controller_name(value: &str) -> anyhow::Result<()> {
    let Some((domain, name)) = value.split_once('/') else {
        bail!("kubernetes_routes.gateway_controller_name must be domain/name");
    };
    validate_kubernetes_name("gateway controller domain", domain)?;
    validate_safe_name("gateway controller name", name, 63)
}

#[path = "../../tests/unit/kubernetes_routes.rs"]
#[cfg(test)]
mod tests;
