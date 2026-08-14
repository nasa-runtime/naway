//! Kubernetes Ingress/Gateway API 控制面路由源。
//!
//! 远端对象绝不在请求线程解析。后台 controller 把受支持对象编译成一个有界 JSON 候选，
//! 以同目录原子 rename 发布；唯一 reload worker 随后重新读取、强类型反序列化并执行完整
//! build-then-swap。失败轮询保留 LKG，freshness 心跳与内容文件分离，因此健康轮询不会制造
//! 配置版本风暴，失联超过 TTL 又能让旧路由可靠退场。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use base64::Engine as _;
use bytes::BytesMut;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::model::{
    ClientAuthCfg, GatewayConfig, GatewayListenerCfg, Http3Cfg, KubernetesDiscoveryCfg,
    KubernetesRouteSourceCfg, RouteCfg, SniCertCfg, StaticServiceCfg, StreamListenerCfg, TlsCfg,
};
use crate::config::GatewaySnapshot;
use crate::reload::ReloadHandle;

const GENERATED_SCHEMA_VERSION: u32 = 5;
const MAX_GENERATED_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROUTE_OBJECTS_HARD: usize = 16_384;
const MAX_ROUTES_HARD: usize = 16_384;
const MAX_TLS_SECRET_BYTES: usize = 4 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedDocument {
    schema_version: u32,
    source_fingerprint: String,
    generation: String,
    routes: Vec<Value>,
    services: BTreeMap<String, Value>,
    #[serde(default)]
    stream_listeners: Vec<Value>,
    #[serde(default)]
    proxy_tls: Option<GeneratedProxyTls>,
    #[serde(default)]
    http_proxies: Vec<GeneratedHttpProxy>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedHttpProxy {
    id: String,
    listen: String,
    plain_enabled: bool,
    routes: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    gateway_listeners: Vec<GeneratedGatewayListener>,
    #[serde(default)]
    tls: Option<GeneratedProxyTls>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedGatewayListener {
    id: String,
    #[serde(default)]
    hostname: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedProxyTls {
    listen: String,
    cert_file: String,
    key_file: String,
    #[serde(default)]
    certs: Vec<GeneratedSniCert>,
    #[serde(default)]
    client_ca_file: Option<String>,
    #[serde(default)]
    require_client_certificate: bool,
    #[serde(default)]
    allow_untrusted_client_certificate: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedSniCert {
    server_names: Vec<String>,
    cert_file: String,
    key_file: String,
}

struct PollCompilation {
    routes: Vec<Value>,
    services: BTreeMap<String, Value>,
    stream_listeners: Vec<Value>,
    stream_tls_plans: BTreeMap<String, GatewayTlsPlan>,
    diagnostics: Vec<RouteDiagnostic>,
    watch_resources: Vec<WatchResource>,
    finalizers: Vec<FinalizerIntent>,
    control_statuses: Vec<ControlStatusIntent>,
    infrastructure: Vec<GatewayInfrastructureIntent>,
    http_proxies: Vec<GatewayHttpProxyPlan>,
}

struct ControlStatusIntent {
    api_version: String,
    kind: String,
    plural: String,
    namespace: Option<String>,
    name: String,
    status: Value,
}

struct GatewayInfrastructureIntent {
    namespace: String,
    name: String,
    gateway_name: String,
    gateway_uid: String,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
}

/// Kubernetes LIST 与后续 watch 之间的连续性凭据。
#[derive(Clone)]
struct WatchResource {
    /// 已完成完整 LIST 的 collection 路径。
    path: String,
    /// LIST 返回且通过字符门禁的 `metadata.resourceVersion`。
    resource_version: String,
}

#[derive(Clone)]
struct FinalizerIntent {
    api_version: String,
    plural: String,
    namespace: String,
    name: String,
    resource_version: String,
    operation: FinalizerOperation,
    finalizers_present: bool,
    finalizer_index: Option<usize>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FinalizerOperation {
    Add,
    Remove,
}

const GATEWAY_FINALIZER: &str = "gateway.rust.dev/naway";

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
        cfg.gateway_api_version == "v1.5.1",
        "kubernetes_routes.gateway_api_version must be v1.5.1"
    );
    anyhow::ensure!(
        !cfg.inference_gateway_enabled || cfg.gateway_api_enabled,
        "inference_gateway_enabled requires gateway_api_enabled=true"
    );
    anyhow::ensure!(
        cfg.inference_extension_version == "v1.5.0",
        "kubernetes_routes.inference_extension_version must be v1.5.0"
    );
    #[cfg(not(feature = "inference-gateway"))]
    anyhow::ensure!(
        !cfg.inference_gateway_enabled,
        "InferencePool resources require the inference-gateway feature"
    );
    #[cfg(not(feature = "gateway-api-experimental"))]
    anyhow::ensure!(
        !cfg.gateway_api_experimental && !cfg.gateway_mesh_interception_ready,
        "Gateway API experimental resources require the gateway-api-experimental feature"
    );
    anyhow::ensure!(
        !cfg.gateway_mesh_interception_ready || cfg.gateway_api_experimental,
        "gateway_mesh_interception_ready requires gateway_api_experimental=true"
    );
    cfg.gateway_bind_address
        .parse::<std::net::IpAddr>()
        .context("kubernetes_routes.gateway_bind_address must be an IP address")?;
    let mesh_bind_address = cfg
        .gateway_mesh_bind_address
        .parse::<std::net::IpAddr>()
        .context("kubernetes_routes.gateway_mesh_bind_address must be an IP address")?;
    anyhow::ensure!(
        cfg.gateway_mesh_port > 0,
        "kubernetes_routes.gateway_mesh_port must be non-zero"
    );
    anyhow::ensure!(
        !cfg.gateway_mesh_interception_ready || mesh_bind_address.is_loopback(),
        "gateway_mesh_interception_ready requires a loopback gateway_mesh_bind_address"
    );
    cfg.gateway_stream_bind_address
        .parse::<std::net::IpAddr>()
        .context("kubernetes_routes.gateway_stream_bind_address must be an IP address")?;
    anyhow::ensure!(
        cfg.gateway_stream_bind_addresses.len() <= 256,
        "kubernetes_routes.gateway_stream_bind_addresses supports at most 256 entries"
    );
    let mut stream_addresses = HashSet::new();
    for address in &cfg.gateway_stream_bind_addresses {
        address.parse::<std::net::IpAddr>().with_context(|| {
            format!(
                "kubernetes_routes.gateway_stream_bind_addresses contains invalid IP `{address}`"
            )
        })?;
        anyhow::ensure!(
            stream_addresses.insert(address),
            "kubernetes_routes.gateway_stream_bind_addresses contains duplicate `{address}`"
        );
    }
    anyhow::ensure!(
        matches!(cfg.grpc_backend_protocol.as_str(), "h2c" | "h2"),
        "kubernetes_routes.grpc_backend_protocol must be h2c or h2"
    );
    anyhow::ensure!(
        (5..=600).contains(&cfg.watch_timeout_seconds),
        "kubernetes_routes.watch_timeout_seconds must be within 5..=600"
    );
    anyhow::ensure!(
        (100..=60_000).contains(&cfg.deletion_drain_timeout_ms),
        "kubernetes_routes.deletion_drain_timeout_ms must be within 100..=60000"
    );
    anyhow::ensure!(
        (1..=MAX_ROUTE_OBJECTS_HARD).contains(&cfg.max_status_updates),
        "kubernetes_routes.max_status_updates must be within 1..={MAX_ROUTE_OBJECTS_HARD}"
    );
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
        (1..=GENERATED_SCHEMA_VERSION).contains(&document.schema_version),
        "unsupported Kubernetes generated route schema_version {}",
        document.schema_version
    );
    let expected = source_fingerprint(&cfg.kubernetes_routes, &cfg.discovery.kubernetes);
    if document.source_fingerprint != expected {
        tracing::info!(file = %path.display(), "Kubernetes generated routes belong to an old source configuration; waiting for controller refresh");
        return Ok(());
    }
    anyhow::ensure!(
        document
            .http_proxies
            .iter()
            .try_fold(document.routes.len(), |total, proxy| total
                .checked_add(proxy.routes.len()))
            .is_some_and(|total| total <= cfg.kubernetes_routes.max_routes),
        "Kubernetes generated routes exceed configured max_routes"
    );
    anyhow::ensure!(
        document.services.len() <= cfg.kubernetes_routes.max_routes,
        "Kubernetes generated services exceed configured max_routes"
    );
    let actual_generation = match document.schema_version {
        1 => legacy_generation_digest(&document.routes, &document.services)?,
        2 => generation_digest(
            &document.routes,
            &document.services,
            &document.stream_listeners,
        )?,
        3 => generation_digest_with_tls(
            &document.routes,
            &document.services,
            &document.stream_listeners,
            &document.proxy_tls,
        )?,
        _ => generation_digest_current(
            &document.routes,
            &document.services,
            &document.stream_listeners,
            &document.proxy_tls,
            &document.http_proxies,
        )?,
    };
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
    for value in document.stream_listeners {
        let listener: StreamListenerCfg =
            serde_json::from_value(value).context("decode generated Kubernetes stream listener")?;
        validate_generated_stream_listener(&listener, &cfg.kubernetes_routes, config_dir)?;
        cfg.stream.listeners.push(listener);
    }
    if !document.http_proxies.is_empty() {
        anyhow::ensure!(
            !cfg.proxies.is_empty(),
            "multiple generated Gateway HTTP listeners require proxies[] configuration"
        );
        let target_index = cfg
            .proxies
            .iter()
            .position(|proxy| proxy.id == cfg.kubernetes_routes.target_proxy)
            .expect("target proxy checked before merge");
        let target_template = cfg.proxies[target_index].clone();
        for generated in document.http_proxies {
            validate_generated_http_proxy(&generated, &cfg.kubernetes_routes, config_dir)?;
            let gateway_listeners = generated
                .gateway_listeners
                .iter()
                .map(|listener| GatewayListenerCfg {
                    id: listener.id.clone(),
                    hostname: listener.hostname.clone(),
                })
                .collect::<Vec<_>>();
            let generated_routes = generated
                .routes
                .into_iter()
                .map(|value| {
                    serde_json::from_value::<RouteCfg>(value)
                        .context("decode generated Kubernetes listener route")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if generated.plain_enabled
                && generated.tls.is_none()
                && plain_listener_matches_target(&generated.listen, &target_template.listen)?
            {
                anyhow::ensure!(
                    target_template.tls.is_none(),
                    "generated HTTP listener cannot reuse a target proxy that also exposes TLS"
                );
                anyhow::ensure!(
                    target_template.gateway_listeners.is_empty(),
                    "generated HTTP listener collides with static target Gateway listeners"
                );
                cfg.proxies[target_index].gateway_listeners = gateway_listeners;
                cfg.proxies[target_index].routes.extend(generated_routes);
                continue;
            }
            let mut proxy = target_template.clone();
            proxy.id = generated.id;
            proxy.listen = generated.listen;
            proxy.plain_enabled = generated.plain_enabled;
            proxy.tls = generated.tls.map(generated_tls_cfg);
            proxy.http3 = Http3Cfg::default();
            proxy.server_names.clear();
            proxy.gateway_listeners = gateway_listeners;
            proxy.routes = generated_routes;
            proxy.redirect_https = false;
            proxy.hsts_max_age = 0;
            cfg.proxies.push(proxy);
        }
    }
    if let Some(generated) = document.proxy_tls {
        validate_generated_tls(&generated, &cfg.kubernetes_routes, config_dir)?;
        let tls = TlsCfg {
            listen: generated.listen,
            cert_file: generated.cert_file,
            key_file: generated.key_file,
            private_key_provider: None,
            spire: None,
            keypair_manifest_file: None,
            certs: generated
                .certs
                .into_iter()
                .map(|cert| SniCertCfg {
                    server_names: cert.server_names,
                    cert_file: cert.cert_file,
                    key_file: cert.key_file,
                    private_key_provider: None,
                    ocsp_stapling: None,
                })
                .collect(),
            client_auth: None,
            ocsp_stapling: None,
            session_tickets: None,
            acme: None,
        };
        if cfg.proxies.is_empty() {
            let server = cfg
                .server
                .as_mut()
                .context("generated Kubernetes TLS requires legacy server")?;
            anyhow::ensure!(
                server.tls.is_none(),
                "Kubernetes generated TLS collides with gateway.yml server.tls"
            );
            server.tls = Some(tls);
        } else {
            let proxy = cfg
                .proxies
                .iter_mut()
                .find(|proxy| proxy.id == cfg.kubernetes_routes.target_proxy)
                .expect("target proxy checked before merge");
            anyhow::ensure!(
                proxy.tls.is_none(),
                "Kubernetes generated TLS collides with gateway.yml target proxy tls"
            );
            proxy.tls = Some(tls);
        }
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

/// 业务作用：复验物化的独立 HTTP/HTTPS proxy 没有越过 controller 地址、路由预算
/// 或 TLS-only 拓扑边界，防本地文档篡改绑定任意端口身份。
///
/// 参数说明：`proxy` 是 schema 中的单 listener 候选；`cfg` 固定地址所有权；
/// `config_dir` 用于 TLS 私钥路径边界复验。
///
/// 返回：plain 与 TLS 形态互斥、listen 合法且所有 TLS 路径受控时成功，否则拒绝整份候选。
fn validate_generated_http_proxy(
    proxy: &GeneratedHttpProxy,
    cfg: &KubernetesRouteSourceCfg,
    config_dir: &Path,
) -> anyhow::Result<()> {
    validate_safe_name("generated Gateway proxy id", &proxy.id, 64)?;
    anyhow::ensure!(
        proxy.routes.len() <= cfg.max_routes,
        "generated Gateway proxy routes exceed max_routes"
    );
    let listen = proxy
        .listen
        .parse::<std::net::SocketAddr>()
        .context("generated Gateway HTTP listen is invalid")?;
    let expected_ip = cfg
        .gateway_bind_address
        .parse::<std::net::IpAddr>()
        .context("configured Gateway bind address is invalid")?;
    let expected_mesh_ip = cfg
        .gateway_mesh_bind_address
        .parse::<std::net::IpAddr>()
        .context("configured Gateway mesh bind address is invalid")?;
    anyhow::ensure!(
        (listen.ip() == expected_ip
            || (listen.ip() == expected_mesh_ip && listen.port() == cfg.gateway_mesh_port))
            && listen.port() > 0,
        "generated Gateway HTTP listen escapes configured bind address"
    );
    anyhow::ensure!(
        proxy.plain_enabled == proxy.tls.is_none(),
        "generated Gateway proxy must be either plain-only or TLS-only"
    );
    anyhow::ensure!(
        proxy.gateway_listeners.len() <= 128,
        "generated Gateway listener metadata exceeds hard limit"
    );
    let mut listener_ids = HashSet::new();
    let mut listener_hostnames = HashSet::new();
    for listener in &proxy.gateway_listeners {
        validate_safe_name("generated Gateway listener id", &listener.id, 253)?;
        anyhow::ensure!(
            listener_ids.insert(listener.id.as_str()),
            "generated Gateway listener id is duplicated"
        );
        if let Some(hostname) = listener.hostname.as_deref() {
            anyhow::ensure!(
                normalize_hostname(hostname)? == hostname,
                "generated Gateway listener hostname is not normalized"
            );
        }
        anyhow::ensure!(
            listener_hostnames.insert(listener.hostname.as_deref()),
            "generated Gateway listener hostname is duplicated"
        );
    }
    if let Some(tls) = &proxy.tls {
        anyhow::ensure!(
            tls.listen == proxy.listen,
            "generated Gateway TLS-only proxy listen mismatch"
        );
        validate_generated_tls(tls, cfg, config_dir)?;
    }
    Ok(())
}

/// 业务作用：判断 controller 的 plain listener 能否安全复用 bootstrap target socket，
/// 避免 wildcard target 与同端口具体地址被重复绑定。
///
/// 参数说明：`generated` 是 controller 具体 listen；`target` 是 gateway.yml target listen。
///
/// 返回：端口相同且 target IP 等于或覆盖 generated IP 时为 true；地址非法返回错误。
fn plain_listener_matches_target(generated: &str, target: &str) -> anyhow::Result<bool> {
    let generated = generated
        .parse::<std::net::SocketAddr>()
        .context("parse generated Gateway plain listen")?;
    let target = target
        .parse::<std::net::SocketAddr>()
        .context("parse Kubernetes target proxy listen")?;
    Ok(generated.port() == target.port()
        && (generated.ip() == target.ip() || target.ip().is_unspecified()))
}

/// 业务作用：把已通过路径与摘要复验的生成 TLS 描述转成标准 ProxyCfg TLS，
/// 使后续 snapshot builder 继续执行证书加载和 listener two-phase 门禁。
///
/// 参数说明：`generated` 仅含 controller 专属相对路径和 SNI 映射。
///
/// 返回：字段无损转换为静态 TlsCfg；不产生文件 I/O 或隐式 ACME。
fn generated_tls_cfg(generated: GeneratedProxyTls) -> TlsCfg {
    TlsCfg {
        listen: generated.listen,
        cert_file: generated.cert_file,
        key_file: generated.key_file,
        private_key_provider: None,
        spire: None,
        keypair_manifest_file: None,
        certs: generated
            .certs
            .into_iter()
            .map(|cert| SniCertCfg {
                server_names: cert.server_names,
                cert_file: cert.cert_file,
                key_file: cert.key_file,
                private_key_provider: None,
                ocsp_stapling: None,
            })
            .collect(),
        client_auth: generated.client_ca_file.map(|ca_file| ClientAuthCfg {
            mode: if generated.allow_untrusted_client_certificate {
                "insecure_fallback".to_owned()
            } else if generated.require_client_certificate {
                "require".to_owned()
            } else {
                "optional".to_owned()
            },
            ca_file,
            crl_files: Vec::new(),
            revocation_mode: "off".to_owned(),
            enforce_crl_expiration: true,
            ocsp: None,
            allowed_spiffe_ids: Vec::new(),
            allowed_spiffe_trust_domains: Vec::new(),
        }),
        ocsp_stapling: None,
        session_tickets: None,
        acme: None,
    }
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
            let mut watch_resources = Vec::new();
            match attempt {
                Ok(Ok(compilation)) => {
                    let PollCompilation {
                        routes,
                        services,
                        stream_listeners,
                        stream_tls_plans,
                        diagnostics,
                        watch_resources: compiled_watch_resources,
                        finalizers,
                        control_statuses,
                        infrastructure,
                        http_proxies,
                    } = compilation;
                    if route_cfg.finalizers_enabled {
                        // 新接管对象必须先拿到删除门禁，随后才允许把其路由发布到数据面；否则对象
                        // 可在两步之间消失，controller 将失去先撤路由再完成删除的权威。
                        if let Err(error) = apply_finalizer_intents(
                            client,
                            &discovery,
                            &finalizers,
                            FinalizerOperation::Add,
                            route_cfg.request_timeout_ms,
                        )
                        .await
                        {
                            tracing::warn!(%error, "add Gateway API Route finalizer failed; keeping LKG");
                            mark_failure_and_maybe_expire(
                                &config_dir,
                                &route_cfg,
                                &discovery,
                                &reload,
                                &mut failure_since,
                                &mut expired_published,
                            )
                            .await;
                            tokio::time::sleep(Duration::from_millis(route_cfg.poll_interval_ms))
                                .await;
                            continue;
                        }
                    }
                    failure_since = None;
                    expired_published = false;
                    let previous_snapshot_version = snap.load().version;
                    match publish_document(
                        &config_dir,
                        &route_cfg,
                        &discovery,
                        routes,
                        services,
                        stream_listeners,
                        stream_tls_plans,
                        http_proxies,
                    )
                    .await
                    {
                        Ok(changed) => {
                            if changed && !reload.trigger_file().await {
                                tracing::warn!(
                                    "reload worker stopped after Kubernetes route publish"
                                );
                                return;
                            }
                            let published = !changed
                                || wait_for_snapshot_advance(
                                    &snap,
                                    previous_snapshot_version,
                                    route_cfg.deletion_drain_timeout_ms,
                                )
                                .await;
                            let infrastructure_published = if published {
                                // 数据面 generation 已可见后再创建基础设施锚点；Gateway status
                                // 必须等锚点传播成功才推进，避免 Accepted 已最新但用户 metadata
                                // 尚未落到任何生成资源的半完成状态。
                                match publish_gateway_infrastructure(
                                    client,
                                    &discovery,
                                    &route_cfg,
                                    &infrastructure,
                                )
                                .await
                                {
                                    Ok(()) => true,
                                    Err(error) => {
                                        tracing::warn!(%error, "publish Gateway infrastructure failed");
                                        false
                                    }
                                }
                            } else {
                                false
                            };
                            if route_cfg.finalizers_enabled && published {
                                // 删除 finalizer 只能在候选已从数据面发布后解除；超时保留 finalizer，
                                // 由下轮 relist 继续恢复，绝不猜测 reload 已成功。
                                if let Err(error) = apply_finalizer_intents(
                                    client,
                                    &discovery,
                                    &finalizers,
                                    FinalizerOperation::Remove,
                                    route_cfg.request_timeout_ms,
                                )
                                .await
                                {
                                    tracing::warn!(%error, "remove drained Gateway API Route finalizer failed");
                                }
                            } else if route_cfg.finalizers_enabled && !published {
                                tracing::warn!(
                                    timeout_ms = route_cfg.deletion_drain_timeout_ms,
                                    "Gateway API deletion drain did not observe snapshot publish; retaining finalizer"
                                );
                            }
                            if route_cfg.status_updates_enabled {
                                if let Err(error) = publish_route_statuses(
                                    client,
                                    &discovery,
                                    &route_cfg,
                                    &diagnostics,
                                )
                                .await
                                {
                                    tracing::warn!(%error, "publish Gateway API Route status failed");
                                }
                                if published && infrastructure_published {
                                    if let Err(error) = publish_control_statuses(
                                        client,
                                        &discovery,
                                        &route_cfg,
                                        &control_statuses,
                                    )
                                    .await
                                    {
                                        tracing::warn!(%error, "publish Gateway API Gateway status failed");
                                    }
                                }
                            }
                            watch_resources = compiled_watch_resources;
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
            if route_cfg.watch_enabled && !watch_resources.is_empty() {
                if let Err(error) =
                    wait_for_watch_change(client, &discovery, &route_cfg, &watch_resources).await
                {
                    tracing::warn!(%error, "Kubernetes watch ended with error; relisting after poll interval");
                    tokio::time::sleep(Duration::from_millis(route_cfg.poll_interval_ms)).await;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(route_cfg.poll_interval_ms)).await;
            }
        }
    });
}

/// 业务作用：累计 Kubernetes 控制面连续失败时间，并在陈旧上限到达后撤销由该来源生成的路由。
///
/// 参数说明：`config_dir`/`cfg`/`discovery` 固定物化目标与来源；`reload` 串行发布空候选；
/// `failure_since` 和 `expired_published` 跨轮保存失败代际状态。
///
/// 返回：无；未到陈旧上限时保留 last-known-good，到期后只尝试发布一次空候选，发布失败留待
/// 下一轮继续恢复，不能用未确认状态覆盖数据面。
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
    match publish_document(
        config_dir,
        cfg,
        discovery,
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
    )
    .await
    {
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

/// 业务作用：等待 reload worker 发布比物化前更新的快照，作为解除删除 finalizer 的最小证据。
///
/// 参数说明：`snap` 是唯一数据面快照指针；`previous_version` 是发布前版本；`timeout_ms`
/// 限制 controller 等待时间。
///
/// 返回：观察到严格递增版本时为 true；超时返回 false，调用方必须保留 finalizer。
async fn wait_for_snapshot_advance(
    snap: &Arc<ArcSwap<GatewaySnapshot>>,
    previous_version: u64,
    timeout_ms: u64,
) -> bool {
    tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        loop {
            if snap.load().version > previous_version {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

/// 业务作用：并发观察本轮所有 Kubernetes collection，任一变化立即触发完整 relist/recompile。
///
/// 参数说明：transport 参数固定 API endpoint/凭据；`cfg` 固定 watch deadline/响应预算；
/// `resources` 携带每个 LIST 的 resourceVersion。
///
/// 返回：任一 watch 收到事件、bookmark、410 或正常超时时成功返回并 relist；transport/RBAC 错误返回错误。
async fn wait_for_watch_change(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    cfg: &KubernetesRouteSourceCfg,
    resources: &[WatchResource],
) -> anyhow::Result<()> {
    let mut watchers = FuturesUnordered::new();
    for resource in resources.iter().cloned() {
        watchers.push(watch_one_resource(client, discovery, cfg, resource));
    }
    let total_timeout = Duration::from_secs(u64::from(cfg.watch_timeout_seconds))
        .saturating_add(Duration::from_millis(cfg.request_timeout_ms));
    tokio::time::timeout(total_timeout, watchers.next())
        .await
        .context("Kubernetes watch wall timeout")?
        .context("Kubernetes watch set is empty")??;
    Ok(())
}

/// 业务作用：从指定 LIST resourceVersion 建立一个有界 watch，并在首个事件后交回 relist 权。
///
/// 参数说明：transport 与预算来自固定 controller 配置；`resource` 是安全 collection path/version。
///
/// 返回：首个完整事件、服务端 watch timeout、连接正常结束或 410 Gone 均成功唤醒；
/// 其它非 2xx、读取错误或首事件超过响应预算时返回失败。
async fn watch_one_resource(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    cfg: &KubernetesRouteSourceCfg,
    resource: WatchResource,
) -> anyhow::Result<()> {
    let separator = if resource.path.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!(
        "{}{}{separator}watch=true&allowWatchBookmarks=true&resourceVersion={}&timeoutSeconds={}",
        discovery.api_server, resource.path, resource.resource_version, cfg.watch_timeout_seconds
    );
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if !discovery.bearer_token.is_empty() {
        request = request.bearer_auth(&discovery.bearer_token);
    }
    let response = request.send().await.context("send Kubernetes watch")?;
    if response.status() == reqwest::StatusCode::GONE {
        return Ok(());
    }
    anyhow::ensure!(
        response.status().is_success(),
        "Kubernetes watch returned HTTP {}",
        response.status()
    );
    let mut stream = response.bytes_stream();
    let mut event_bytes = 0_usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read Kubernetes watch event")?;
        let event_fragment = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |index| index.saturating_add(1));
        event_bytes = event_bytes
            .checked_add(event_fragment)
            .context("Kubernetes watch event byte count overflow")?;
        anyhow::ensure!(
            event_bytes <= cfg.max_response_bytes,
            "Kubernetes watch event exceeds max_response_bytes"
        );
        if event_fragment < chunk.len() || chunk.last() == Some(&b'\n') {
            break;
        }
    }
    Ok(())
}

/// 业务作用：为 Kubernetes 路由控制器构建禁重定向并绑定声明式 CA 的 HTTP client。
///
/// 参数说明：`cfg` 提供 API server 信任根；Bearer token 在每次请求处单独注入。
///
/// 返回：CA 与 client 配置有效时返回复用连接的 client，否则拒绝启动控制器。
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

/// 业务作用：从同一轮 Kubernetes API 快照编译 Ingress、Gateway API 与 TLS 材料，
/// 形成尚未发布的完整候选 generation。
///
/// 参数说明：`client` 是受 CA/redirect 门保护的 API client；`cfg` 固定接管范围与
/// 对象预算；`discovery` 提供 API endpoint 和认证材料。
///
/// 返回：所有对象、引用、状态意图和文件材料均可安全表达时返回候选；任一全局门禁
/// 失败则返回错误，由上层保留 last-known-good。
async fn fetch_and_compile(
    client: &reqwest::Client,
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
) -> anyhow::Result<PollCompilation> {
    let mut routes = Vec::new();
    let mut http_listener_routes = BTreeMap::new();
    let mut services = BTreeMap::new();
    let mut stream_listeners = Vec::new();
    let mut stream_tls_plans = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut watch_resources = Vec::new();
    let mut finalizers = Vec::new();
    let mut control_statuses = Vec::new();
    let mut infrastructure = Vec::new();
    let mut http_proxies = Vec::new();
    if cfg.ingress_enabled {
        let value = fetch_resource(
            client,
            discovery,
            "/apis/networking.k8s.io/v1/ingresses",
            cfg.max_response_bytes,
        )
        .await?;
        push_watch_resource(
            &mut watch_resources,
            "/apis/networking.k8s.io/v1/ingresses",
            &value,
        )?;
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
        let listener_sets = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/listenersets",
            cfg.max_response_bytes,
        )
        .await?;
        let backend_tls_policies = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/backendtlspolicies",
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
        let grpc_routes = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/grpcroutes",
            cfg.max_response_bytes,
        )
        .await?;
        let tls_routes = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/tlsroutes",
            cfg.max_response_bytes,
        )
        .await?;
        let tcp_routes = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1alpha2/tcproutes",
            cfg.max_response_bytes,
        )
        .await?;
        let udp_routes = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1alpha2/udproutes",
            cfg.max_response_bytes,
        )
        .await?;
        let reference_grants = fetch_resource(
            client,
            discovery,
            "/apis/gateway.networking.k8s.io/v1/referencegrants",
            cfg.max_response_bytes,
        )
        .await?;
        let namespaces = fetch_resource(
            client,
            discovery,
            "/api/v1/namespaces",
            cfg.max_response_bytes,
        )
        .await?;
        let backend_tls_config_maps = fetch_backend_tls_config_maps(
            client,
            discovery,
            &classes,
            &gateways,
            &backend_tls_policies,
            &reference_grants,
            cfg,
            &mut watch_resources,
        )
        .await?;
        let secrets = fetch_gateway_secrets(
            client,
            discovery,
            &classes,
            &gateways,
            &listener_sets,
            &namespaces,
            &reference_grants,
            cfg,
        )
        .await?;
        let frontend_validation = build_gateway_frontend_validation_catalog(
            &classes,
            &gateways,
            &reference_grants,
            &backend_tls_config_maps,
            cfg,
        )?;
        let data_plane_gateways =
            gateways_with_resolved_frontend_validation(&gateways, &frontend_validation, cfg)?;
        let blocked_frontend_sockets = unresolved_frontend_validation_sockets(
            &classes,
            &gateways,
            &listener_sets,
            &namespaces,
            &frontend_validation,
            cfg,
        )?;
        let mut gateway_tls_plans = build_gateway_tls_plans(
            &classes,
            &data_plane_gateways,
            &listener_sets,
            &reference_grants,
            &namespaces,
            &secrets,
            &frontend_validation,
            cfg,
        )?;
        gateway_tls_plans.retain(|listen, _| !blocked_frontend_sockets.contains(listen));
        stream_tls_plans = build_gateway_stream_tls_plans(
            &classes,
            &gateways,
            &listener_sets,
            &reference_grants,
            &namespaces,
            &secrets,
            cfg,
        )?;
        let gateway_listeners = build_gateway_listener_plans_with_listener_sets(
            &classes,
            &data_plane_gateways,
            &listener_sets,
            &namespaces,
            cfg,
        )?;
        let gateway_backend_clients =
            build_gateway_backend_client_catalog(&gateways, &secrets, cfg)?;
        let service_objects = fetch_resource(
            client,
            discovery,
            "/api/v1/services",
            cfg.max_response_bytes,
        )
        .await?;
        let (inference_pools, inference_pods) = if cfg.inference_gateway_enabled {
            (
                fetch_resource(
                    client,
                    discovery,
                    "/apis/inference.networking.k8s.io/v1/inferencepools",
                    cfg.max_response_bytes,
                )
                .await?,
                fetch_resource(client, discovery, "/api/v1/pods", cfg.max_response_bytes).await?,
            )
        } else {
            (json!({"items": []}), json!({"items": []}))
        };
        let (service_imports, backend_traffic_policies) = if cfg.gateway_api_experimental {
            (
                fetch_resource(
                    client,
                    discovery,
                    "/apis/multicluster.x-k8s.io/v1alpha1/serviceimports",
                    cfg.max_response_bytes,
                )
                .await?,
                fetch_resource(
                    client,
                    discovery,
                    "/apis/gateway.networking.x-k8s.io/v1alpha1/xbackendtrafficpolicies",
                    cfg.max_response_bytes,
                )
                .await?,
            )
        } else {
            (json!({"items": []}), json!({"items": []}))
        };
        for (path, value) in [
            (
                "/apis/gateway.networking.k8s.io/v1/gatewayclasses",
                &classes,
            ),
            ("/apis/gateway.networking.k8s.io/v1/gateways", &gateways),
            (
                "/apis/gateway.networking.k8s.io/v1/listenersets",
                &listener_sets,
            ),
            (
                "/apis/gateway.networking.k8s.io/v1/backendtlspolicies",
                &backend_tls_policies,
            ),
            (
                "/apis/gateway.networking.k8s.io/v1/httproutes",
                &http_routes,
            ),
            (
                "/apis/gateway.networking.k8s.io/v1/grpcroutes",
                &grpc_routes,
            ),
            ("/apis/gateway.networking.k8s.io/v1/tlsroutes", &tls_routes),
            (
                "/apis/gateway.networking.k8s.io/v1alpha2/tcproutes",
                &tcp_routes,
            ),
            (
                "/apis/gateway.networking.k8s.io/v1alpha2/udproutes",
                &udp_routes,
            ),
            (
                "/apis/gateway.networking.k8s.io/v1/referencegrants",
                &reference_grants,
            ),
            ("/api/v1/namespaces", &namespaces),
            ("/api/v1/services", &service_objects),
            (
                "/apis/inference.networking.k8s.io/v1/inferencepools",
                &inference_pools,
            ),
            ("/api/v1/pods", &inference_pods),
            (
                "/apis/multicluster.x-k8s.io/v1alpha1/serviceimports",
                &service_imports,
            ),
            (
                "/apis/gateway.networking.x-k8s.io/v1alpha1/xbackendtrafficpolicies",
                &backend_traffic_policies,
            ),
        ] {
            if cfg.status_updates_enabled
                && (path.contains("gatewayclasses")
                    || path.ends_with("/gateways")
                    || path.ends_with("/listenersets")
                    || path.ends_with("/backendtlspolicies")
                    || path.ends_with("/xbackendtrafficpolicies")
                    || path.ends_with("/inferencepools")
                    || path.ends_with("routes"))
            {
                // status subresource 更新也会推进 resourceVersion；避免 controller 被自己的写入
                // 持续唤醒。Route/Gateway spec 仍由有界 poll relist 收敛，依赖资源继续实时 watch。
                continue;
            }
            push_watch_resource(&mut watch_resources, path, value)?;
        }
        compile_gateway_api_full_with_listener_sets(
            &classes,
            &data_plane_gateways,
            &listener_sets,
            &http_routes,
            &grpc_routes,
            &tls_routes,
            &tcp_routes,
            &udp_routes,
            &reference_grants,
            &namespaces,
            &service_objects,
            &inference_pools,
            &inference_pods,
            &service_imports,
            &backend_tls_policies,
            &backend_traffic_policies,
            &backend_tls_config_maps,
            &gateway_backend_clients,
            cfg,
            &mut routes,
            &mut http_listener_routes,
            &mut services,
            &mut stream_listeners,
            &mut diagnostics,
        )?;
        let published_stream_sockets = stream_listeners
            .iter()
            .filter_map(|listener| listener.get("listen").and_then(Value::as_str))
            .collect::<HashSet<_>>();
        // 没有已接纳 Route 的终止 listener 不创建空 TLS socket；仅保留即将发布 socket 的
        // 身份计划，避免证书存在但无转发权威时阻断同轮 status 收敛。
        stream_tls_plans.retain(|listen, _| published_stream_sockets.contains(listen.as_str()));
        http_proxies = build_gateway_http_proxy_plans(
            std::mem::take(&mut http_listener_routes),
            gateway_tls_plans,
            gateway_listeners,
            cfg,
        )?;
        if cfg.status_updates_enabled {
            control_statuses = build_control_status_intents_with_listener_sets(
                &classes,
                &gateways,
                &listener_sets,
                &reference_grants,
                &namespaces,
                &secrets,
                &frontend_validation,
                cfg,
                &diagnostics,
            )?;
            let service_catalog = build_service_catalog(&service_objects, cfg.max_objects)?;
            let backend_tls_catalog = build_backend_tls_catalog(
                &backend_tls_policies,
                &backend_tls_config_maps,
                &service_catalog,
                cfg,
            )?;
            control_statuses.extend(build_backend_tls_status_intents(
                &backend_tls_catalog,
                &classes,
                &gateways,
                &listener_sets,
                &http_routes,
                &tls_routes,
                &namespaces,
                &service_catalog,
                cfg,
            )?);
            let service_import_catalog =
                build_service_import_catalog(&service_imports, cfg.max_objects)?;
            let backend_traffic_catalog = build_backend_traffic_catalog(
                &backend_traffic_policies,
                &service_catalog,
                &service_import_catalog,
                cfg,
            )?;
            control_statuses.extend(build_backend_traffic_status_intents(
                &backend_traffic_catalog,
                cfg,
            )?);
            if cfg.inference_gateway_enabled {
                let inference_catalog = build_inference_pool_catalog(
                    &inference_pools,
                    &inference_pods,
                    &service_catalog,
                    cfg,
                )?;
                control_statuses.extend(build_inference_pool_status_intents(
                    &classes,
                    &gateways,
                    &listener_sets,
                    &namespaces,
                    &http_routes,
                    &inference_pools,
                    &inference_catalog,
                    cfg,
                )?);
            }
            anyhow::ensure!(
                control_statuses.len() <= cfg.max_status_updates,
                "Gateway control status updates exceed max_status_updates"
            );
        }
        infrastructure = build_gateway_infrastructure_intents(&classes, &gateways, cfg)?;
        if cfg.finalizers_enabled {
            finalizers = collect_finalizer_intents(
                cfg,
                &diagnostics,
                [
                    (&http_routes, "gateway.networking.k8s.io/v1", "httproutes"),
                    (&grpc_routes, "gateway.networking.k8s.io/v1", "grpcroutes"),
                    (&tls_routes, "gateway.networking.k8s.io/v1", "tlsroutes"),
                    (
                        &tcp_routes,
                        "gateway.networking.k8s.io/v1alpha2",
                        "tcproutes",
                    ),
                    (
                        &udp_routes,
                        "gateway.networking.k8s.io/v1alpha2",
                        "udproutes",
                    ),
                ],
            )?;
        }
    }
    let generated_route_count = http_proxies.iter().try_fold(routes.len(), |total, proxy| {
        total
            .checked_add(proxy.routes.len())
            .context("Kubernetes generated route count overflow")
    })?;
    anyhow::ensure!(
        generated_route_count <= cfg.max_routes,
        "Kubernetes objects expand beyond max_routes"
    );
    // HTTPRoute 同等 specificity 时必须按对象年龄/名称和 rule 声明顺序裁决；各编译器
    // 已按该规则稳定地产生 routes，不能再用哈希 id 重排，否则会把较晚 rule 提到前面。
    stream_listeners.sort_by(|left, right| route_sort_key(left).cmp(route_sort_key(right)));
    Ok(PollCompilation {
        routes,
        services,
        stream_listeners,
        stream_tls_plans,
        diagnostics,
        watch_resources,
        finalizers,
        control_statuses,
        infrastructure,
        http_proxies,
    })
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

/// 业务作用：仅读受管 Gateway 与获授权 ListenerSet certificateRefs 明确引用的 Secret，
/// 避免为 TLS 终止申请 cluster-wide Secret 列表权限。
///
/// 参数说明：Gateway API 与 Namespace 参数是同轮 LIST；transport 参数限定 API
/// endpoint、凭据与单响应大小；`cfg` 限定 controller 和 namespace 边界。
///
/// 返回：返回按 namespace/name 索引的有界 Secret 目录；404 保留为缺失证据，
/// RBAC、transport、身份不一致或引用数超限时拒绝本轮候选。
#[allow(clippy::too_many_arguments)]
async fn fetch_gateway_secrets(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    namespaces_value: &Value,
    reference_grants_value: &Value,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<SecretCatalog> {
    let selected_classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    let catalog = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let mut references = BTreeSet::new();
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (gateway_namespace, _) = object_identity(gateway, "Gateway")?;
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class)
            || !namespace_allowed(cfg, gateway_namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        for listener in gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("selected Gateway missing spec.listeners")?
        {
            let Some(certificate_refs) = listener
                .pointer("/tls/certificateRefs")
                .and_then(Value::as_array)
            else {
                continue;
            };
            anyhow::ensure!(
                certificate_refs.len() <= 64,
                "Gateway listener supports at most 64 certificateRefs"
            );
            for reference in certificate_refs {
                if !reference
                    .get("group")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                    || reference
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("Secret")
                        != "Secret"
                {
                    continue;
                }
                let name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .context("Gateway certificateRef missing name")?;
                let namespace = reference
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(gateway_namespace);
                validate_kubernetes_name("Gateway certificateRef namespace", namespace)?;
                validate_kubernetes_name("Gateway certificateRef Secret", name)?;
                if namespace != gateway_namespace
                    && !grants.permits_reference(
                        gateway_namespace,
                        "Gateway",
                        namespace,
                        "Secret",
                        name,
                    )?
                {
                    // 授权门禁必须先于 Secret GET；否则响应状态或时序会泄露目标
                    // namespace 中对象是否存在。
                    continue;
                }
                references.insert((namespace.to_owned(), name.to_owned()));
            }
        }
        if let Some(reference) = gateway.pointer("/spec/tls/backend/clientCertificateRef") {
            if reference
                .get("group")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
                && reference
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("Secret")
                    == "Secret"
            {
                let name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .context("Gateway backend clientCertificateRef missing name")?;
                validate_kubernetes_name("Gateway backend client certificate Secret", name)?;
                references.insert((gateway_namespace.to_owned(), name.to_owned()));
            }
        }
    }
    for listener_set in resource_items(listener_sets_value, cfg.max_objects, "ListenerSet")? {
        let (listener_set_namespace, listener_set_name) =
            object_identity(listener_set, "ListenerSet")?;
        if !catalog
            .listener_set_decisions
            .get(&(
                listener_set_namespace.to_owned(),
                listener_set_name.to_owned(),
            ))
            .is_some_and(|decision| decision.allowed)
        {
            continue;
        }
        for listener in listener_set
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("selected ListenerSet missing spec.listeners")?
        {
            let Some(certificate_refs) = listener
                .pointer("/tls/certificateRefs")
                .and_then(Value::as_array)
            else {
                continue;
            };
            anyhow::ensure!(
                certificate_refs.len() <= 64,
                "ListenerSet listener supports at most 64 certificateRefs"
            );
            for reference in certificate_refs {
                if !reference
                    .get("group")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                    || reference
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("Secret")
                        != "Secret"
                {
                    continue;
                }
                let secret_name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .context("ListenerSet certificateRef missing name")?;
                let secret_namespace = reference
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(listener_set_namespace);
                validate_kubernetes_name("ListenerSet certificateRef namespace", secret_namespace)?;
                validate_kubernetes_name("ListenerSet certificateRef Secret", secret_name)?;
                if secret_namespace != listener_set_namespace
                    && !grants.permits_reference(
                        listener_set_namespace,
                        "ListenerSet",
                        secret_namespace,
                        "Secret",
                        secret_name,
                    )?
                {
                    // 未获得 ReferenceGrant 时不得探测跨 namespace Secret 是否存在。
                    continue;
                }
                references.insert((secret_namespace.to_owned(), secret_name.to_owned()));
            }
        }
    }
    anyhow::ensure!(
        references.len() <= cfg.max_objects,
        "Gateway certificateRefs exceed max_objects"
    );
    let mut pending =
        futures::stream::iter(references.into_iter().map(|(namespace, name)| async move {
            let path = format!("/api/v1/namespaces/{namespace}/secrets/{name}");
            let object = fetch_resource(client, discovery, &path, cfg.max_response_bytes).await?;
            anyhow::Ok((namespace, name, object))
        }))
        .buffer_unordered(16);
    let mut catalog = SecretCatalog::default();
    while let Some(result) = pending.next().await {
        let (namespace, name, object) = result?;
        if object.get("items").is_some() {
            continue;
        }
        let (actual_namespace, actual_name) = object_identity(&object, "Secret")?;
        anyhow::ensure!(
            actual_namespace == namespace && actual_name == name,
            "Kubernetes Secret response identity mismatch"
        );
        catalog.objects.insert((namespace, name), object);
    }
    Ok(catalog)
}

/// 业务作用：只读取 BackendTLSPolicy 或 Gateway frontend validation 明确引用的 ConfigMap，
/// 并为每个名称建立服务端 field selector watch，避免暴露 namespace 中无关配置数据。
///
/// 参数说明：Gateway API LIST 来自同轮；transport 参数限定 API endpoint、认证与响应预算；
/// `watch_resources` 接收精确名称集合的 resourceVersion。
///
/// 返回：返回引用目标的有界 ConfigMap 目录；404 表示缺失引用，RBAC、身份错配或超限时失败。
#[allow(clippy::too_many_arguments)]
async fn fetch_backend_tls_config_maps(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    classes_value: &Value,
    gateways_value: &Value,
    policies_value: &Value,
    reference_grants_value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    watch_resources: &mut Vec<WatchResource>,
) -> anyhow::Result<ConfigMapCatalog> {
    let mut references = BTreeSet::new();
    let selected_classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, _) = object_identity(gateway, "Gateway")?;
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class)
            || !namespace_allowed(cfg, namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let mut validations = Vec::new();
        if let Some(validation) = gateway.pointer("/spec/tls/frontend/default/validation") {
            validations.push(validation);
        }
        for per_port in gateway
            .pointer("/spec/tls/frontend/perPort")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(validation) = per_port.pointer("/tls/validation") {
                validations.push(validation);
            }
        }
        for validation in validations {
            for reference in validation
                .get("caCertificateRefs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if !reference
                    .get("group")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                    || reference
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("ConfigMap")
                        != "ConfigMap"
                {
                    continue;
                }
                let name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .context("Gateway frontend CA reference missing name")?;
                let target_namespace = reference
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(namespace);
                validate_kubernetes_name("Gateway frontend CA namespace", target_namespace)?;
                validate_kubernetes_name("Gateway frontend CA ConfigMap", name)?;
                if target_namespace != namespace
                    && !grants.permits_reference(
                        namespace,
                        "Gateway",
                        target_namespace,
                        "ConfigMap",
                        name,
                    )?
                {
                    // 未授权引用不得通过 GET 时序泄露目标 ConfigMap 是否存在。
                    continue;
                }
                references.insert((target_namespace.to_owned(), name.to_owned()));
            }
        }
    }
    for policy in resource_items(policies_value, cfg.max_objects, "BackendTLSPolicy")? {
        let (namespace, _) = object_identity(policy, "BackendTLSPolicy")?;
        if !namespace_allowed(cfg, namespace)
            || policy.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        for reference in policy
            .pointer("/spec/validation/caCertificateRefs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !reference
                .get("group")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
                || reference
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("ConfigMap")
                    != "ConfigMap"
            {
                continue;
            }
            let name = reference
                .get("name")
                .and_then(Value::as_str)
                .context("BackendTLSPolicy caCertificateRef missing name")?;
            validate_kubernetes_name("BackendTLSPolicy ConfigMap", name)?;
            references.insert((namespace.to_owned(), name.to_owned()));
        }
    }
    anyhow::ensure!(
        references.len() <= cfg.max_objects,
        "BackendTLSPolicy ConfigMap refs exceed max_objects"
    );
    let mut pending =
        futures::stream::iter(references.into_iter().map(|(namespace, name)| async move {
            let path = format!(
                "/api/v1/namespaces/{namespace}/configmaps?fieldSelector=metadata.name%3D{name}"
            );
            let list = fetch_resource(client, discovery, &path, cfg.max_response_bytes).await?;
            anyhow::Ok((namespace, name, path, list))
        }))
        .buffer_unordered(16);
    let mut catalog = ConfigMapCatalog::default();
    while let Some(result) = pending.next().await {
        let (namespace, name, path, list) = result?;
        push_watch_resource(watch_resources, &path, &list)?;
        let objects = resource_items(&list, 1, "ConfigMap")?;
        if let Some(object) = objects.first() {
            let (actual_namespace, actual_name) = object_identity(object, "ConfigMap")?;
            anyhow::ensure!(
                actual_namespace == namespace && actual_name == name,
                "Kubernetes ConfigMap response identity mismatch"
            );
            catalog.objects.insert((namespace, name), object.clone());
        }
    }
    Ok(catalog)
}

/// 业务作用：记录 LIST 的 resourceVersion，供下一轮 watch 从完整候选之后开始观察变化。
///
/// 参数说明：`output` 接收 watch 入口；`path` 是固定 Kubernetes collection；`value` 是 LIST 响应。
///
/// 返回：resourceVersion 存在且字符安全时加入集合；API 未提供版本时跳过 watch、仍保留轮询。
fn push_watch_resource(
    output: &mut Vec<WatchResource>,
    path: &str,
    value: &Value,
) -> anyhow::Result<()> {
    let Some(resource_version) = value
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    anyhow::ensure!(
        !resource_version.is_empty()
            && resource_version.len() <= 128
            && resource_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "Kubernetes LIST resourceVersion is invalid"
    );
    output.push(WatchResource {
        path: path.to_owned(),
        resource_version: resource_version.to_owned(),
    });
    Ok(())
}

/// 业务作用：从本轮 Route 列表生成 finalizer 增删意图，删除态始终优先于新接管。
///
/// 参数说明：`cfg` 提供 namespace 与 mutation 预算；`diagnostics` 标识已解析对象；`lists`
/// 是各 Route kind 的完整 LIST 与 REST 身份。
///
/// 返回：返回带 resourceVersion 前置条件的有界意图；坏 metadata 时拒绝本轮候选。
fn collect_finalizer_intents<const N: usize>(
    cfg: &KubernetesRouteSourceCfg,
    diagnostics: &[RouteDiagnostic],
    lists: [(&Value, &str, &str); N],
) -> anyhow::Result<Vec<FinalizerIntent>> {
    let accepted = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.accepted && diagnostic.resolved_refs)
        .filter_map(|diagnostic| {
            Some((
                diagnostic.kind.clone(),
                diagnostic
                    .object
                    .pointer("/metadata/namespace")
                    .and_then(Value::as_str)
                    .unwrap_or("default")
                    .to_owned(),
                diagnostic
                    .object
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)?
                    .to_owned(),
            ))
        })
        .collect::<HashSet<_>>();
    let mut output = Vec::new();
    for (list, api_version, plural) in lists {
        for object in resource_items(list, cfg.max_objects, plural)? {
            let (namespace, name) = object_identity(object, plural)?;
            if !namespace_allowed(cfg, namespace) {
                continue;
            }
            let kind = object
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or(match plural {
                    "httproutes" => "HTTPRoute",
                    "grpcroutes" => "GRPCRoute",
                    "tlsroutes" => "TLSRoute",
                    "tcproutes" => "TCPRoute",
                    "udproutes" => "UDPRoute",
                    _ => "",
                });
            let resource_version = object
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .context("Gateway Route finalizer requires metadata.resourceVersion")?;
            let finalizers = object
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array);
            let finalizer_index = finalizers
                .and_then(|values| values.iter().position(|value| value == GATEWAY_FINALIZER));
            let has_finalizer = finalizer_index.is_some();
            let deleting = object.pointer("/metadata/deletionTimestamp").is_some();
            let should_own =
                accepted.contains(&(kind.to_owned(), namespace.to_owned(), name.to_owned()));
            let operation = if deleting && has_finalizer {
                Some(FinalizerOperation::Remove)
            } else if !deleting && should_own && !has_finalizer {
                Some(FinalizerOperation::Add)
            } else {
                None
            };
            if let Some(operation) = operation {
                output.push(FinalizerIntent {
                    api_version: api_version.to_owned(),
                    plural: plural.to_owned(),
                    namespace: namespace.to_owned(),
                    name: name.to_owned(),
                    resource_version: resource_version.to_owned(),
                    operation,
                    finalizers_present: finalizers.is_some(),
                    finalizer_index,
                });
            }
        }
    }
    anyhow::ensure!(
        output.len() <= cfg.max_status_updates,
        "Gateway API finalizer mutations exceed max_status_updates"
    );
    Ok(output)
}

/// 业务作用：构造 GatewayClass/Gateway/ListenerSet 的 owned status，公开 listener 冲突、支持 kind 与附着计数。
///
/// 参数说明：LIST、Secret 目录与 Route 诊断来自同轮；`cfg` 固定 controller
/// identity/bind address 与 mutation 预算。
///
/// 返回：返回有界 Server-Side Apply 意图；对象结构或 listener 语义异常时拒绝本轮 status。
#[allow(clippy::too_many_arguments)]
fn build_control_status_intents_with_listener_sets(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    reference_grants_value: &Value,
    namespaces_value: &Value,
    secrets: &SecretCatalog,
    frontend_validation: &GatewayFrontendValidationCatalog,
    cfg: &KubernetesRouteSourceCfg,
    diagnostics: &[RouteDiagnostic],
) -> anyhow::Result<Vec<ControlStatusIntent>> {
    let transition_time = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("format Gateway status timestamp")?;
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
    let catalog = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    let active_listeners = catalog
        .listeners
        .iter()
        .map(|listener| {
            (
                listener.parent_kind.clone(),
                listener.parent_namespace.clone(),
                listener.parent_name.clone(),
                listener.section_name.clone(),
            )
        })
        .collect::<HashSet<_>>();
    let mut valid_listener_sets = HashSet::new();
    for listener_set in resource_items(listener_sets_value, cfg.max_objects, "ListenerSet")? {
        let (namespace, name) = object_identity(listener_set, "ListenerSet")?;
        let key = (namespace.to_owned(), name.to_owned());
        let Some(decision) = catalog.listener_set_decisions.get(&key) else {
            continue;
        };
        if !decision.allowed {
            continue;
        }
        let listeners = listener_set
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("ListenerSet missing spec.listeners")?;
        let mut any_valid = false;
        for listener in listeners {
            let section = listener
                .get("name")
                .and_then(Value::as_str)
                .context("ListenerSet listener missing name")?;
            let protocol = listener
                .get("protocol")
                .and_then(Value::as_str)
                .context("ListenerSet listener missing protocol")?;
            let active = active_listeners.contains(&(
                "ListenerSet".to_owned(),
                namespace.to_owned(),
                name.to_owned(),
                section.to_owned(),
            ));
            let references =
                listener_reference_condition(listener, namespace, "ListenerSet", secrets, &grants)?;
            let kinds = parse_allowed_kinds(listener, protocol)?;
            any_valid |= active && references.resolved && !kinds.has_invalid;
        }
        if any_valid {
            valid_listener_sets.insert(key);
        }
    }
    let mut output = Vec::new();
    for class in classes.iter().filter(|class| {
        class
            .pointer("/spec/controllerName")
            .and_then(Value::as_str)
            == Some(cfg.gateway_controller_name.as_str())
    }) {
        let name = class
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("GatewayClass missing metadata.name")?;
        let generation = class
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        output.push(ControlStatusIntent {
            api_version: "gateway.networking.k8s.io/v1".to_owned(),
            kind: "GatewayClass".to_owned(),
            plural: "gatewayclasses".to_owned(),
            namespace: None,
            name: name.to_owned(),
            status: json!({"conditions":[gateway_condition(
                "Accepted", true, "Accepted", "controller accepts this GatewayClass",
                generation, &transition_time
            )]}),
        });
    }
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, name) = object_identity(gateway, "Gateway")?;
        if gateway.pointer("/metadata/deletionTimestamp").is_some() {
            continue;
        }
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class) || !namespace_allowed(cfg, namespace) {
            continue;
        }
        let generation = gateway
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let address_decision = catalog
            .address_decisions
            .get(&(namespace.to_owned(), name.to_owned()))
            .context("selected Gateway missing address decision")?;
        let raw_listeners = gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("Gateway missing spec.listeners")?;
        let addresses = if address_decision.static_requested {
            address_decision
                .status_addresses
                .iter()
                .map(|address| json!({"type":address.address_type,"value":address.value}))
                .collect::<Vec<_>>()
        } else {
            let mut addresses = catalog
                .listeners
                .iter()
                .filter(|listener| {
                    listener.gateway_namespace == namespace && listener.gateway_name == name
                })
                .map(|listener| listener.bind_address.clone())
                .collect::<BTreeSet<_>>();
            if addresses.is_empty() {
                addresses.insert(cfg.gateway_bind_address.clone());
            }
            addresses
                .into_iter()
                .map(|value| json!({"type":"IPAddress","value":value}))
                .collect::<Vec<_>>()
        };
        let mut listener_statuses = Vec::new();
        let mut accepted_count = 0_usize;
        let mut programmed_count = 0_usize;
        for listener in raw_listeners {
            let section = listener
                .get("name")
                .and_then(Value::as_str)
                .context("Gateway listener missing name")?;
            let protocol = listener
                .get("protocol")
                .and_then(Value::as_str)
                .context("Gateway listener missing protocol")?;
            let mode_supported = gateway_listener_mode_supported(listener, protocol);
            let frontend = frontend_validation.listeners.get(&(
                namespace.to_owned(),
                name.to_owned(),
                listener
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .context("Gateway listener has invalid port")?,
            ));
            let listener_active = active_listeners.contains(&(
                "Gateway".to_owned(),
                namespace.to_owned(),
                name.to_owned(),
                section.to_owned(),
            ));
            let accepted = mode_supported
                && address_decision.accepted
                && frontend.is_none_or(|decision| decision.resolved)
                && (listener_active || !address_decision.usable);
            accepted_count += usize::from(accepted);
            let reference_condition =
                listener_reference_condition(listener, namespace, "Gateway", secrets, &grants)?;
            let allowed_kinds = parse_allowed_kinds(listener, protocol)?;
            let programmed = accepted
                && address_decision.usable
                && listener_active
                && reference_condition.resolved
                && !allowed_kinds.has_invalid;
            programmed_count += usize::from(programmed);
            let kinds = if mode_supported {
                allowed_kinds
                    .supported
                    .iter()
                    .map(|kind| json!({"group":"gateway.networking.k8s.io","kind":kind}))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let listener_key = (
                "Gateway".to_owned(),
                namespace.to_owned(),
                name.to_owned(),
                section.to_owned(),
            );
            let attached_routes = diagnostics
                .iter()
                // Route 一旦被 listener 接纳就计入 attachedRoutes；backendRef 未解析只会
                // 阻止该 Route 进入数据面，不能抹掉控制面附件关系，否则运维者会误判
                // listener 没有流量对象并绕过故障处置。
                .filter(|diagnostic| diagnostic.accepted)
                .filter(|diagnostic| diagnostic.attached_listeners.contains(&listener_key))
                .count();
            let reason = if frontend.is_some_and(|decision| !decision.resolved) {
                frontend
                    .expect("frontend decision was checked above")
                    .accepted_reason
            } else if !address_decision.accepted {
                "UnsupportedAddress"
            } else if !mode_supported {
                "UnsupportedValue"
            } else if accepted {
                "Accepted"
            } else {
                "PortUnavailable"
            };
            let message = if frontend.is_some_and(|decision| !decision.resolved) {
                frontend
                    .expect("frontend decision was checked above")
                    .message
            } else if !address_decision.accepted {
                "Gateway contains an address type unsupported by this controller"
            } else if !mode_supported {
                "listener TLS mode is not supported by this controller"
            } else if accepted {
                "listener is owned by this controller"
            } else {
                "listener conflicts with an earlier listener on the same socket"
            };
            let (resolved, resolved_reason, resolved_message) =
                if let Some(frontend) = frontend.filter(|decision| !decision.resolved) {
                    (false, frontend.resolved_reason, frontend.message)
                } else if allowed_kinds.has_invalid {
                    (
                        false,
                        "InvalidRouteKinds",
                        "listener contains Route kinds unsupported by its protocol",
                    )
                } else {
                    (
                        reference_condition.resolved,
                        reference_condition.reason,
                        reference_condition.message,
                    )
                };
            listener_statuses.push(json!({
                "name": section,
                "supportedKinds": kinds,
                "attachedRoutes": attached_routes,
                "conditions": [
                    gateway_condition("Accepted", accepted, reason, message, generation, &transition_time),
                    gateway_condition(
                        "Programmed",
                        programmed,
                        if programmed { "Programmed" } else if !address_decision.accepted { "UnsupportedAddress" } else if !address_decision.usable { "AddressNotUsable" } else if !reference_condition.resolved { reference_condition.reason } else { reason },
                        if programmed { "listener is present in the candidate bundle" } else if !address_decision.accepted { "Gateway address type is unsupported" } else if !address_decision.usable { "Gateway address cannot be bound by this controller" } else if !reference_condition.resolved { reference_condition.message } else { message },
                        generation,
                        &transition_time
                    ),
                    gateway_condition(
                        "ResolvedRefs",
                        resolved,
                        resolved_reason,
                        resolved_message,
                        generation,
                        &transition_time
                    )
                ]
            }));
        }
        let accepted = address_decision.accepted && accepted_count > 0;
        let programmed = address_decision.usable && programmed_count > 0;
        let attached_listener_sets = valid_listener_sets
            .iter()
            .filter(|listener_set_key| {
                catalog
                    .listener_set_decisions
                    .get(*listener_set_key)
                    .is_some_and(|decision| {
                        decision.gateway_namespace == namespace && decision.gateway_name == name
                    })
            })
            .count();
        let (accepted_reason, accepted_message) = if !address_decision.accepted {
            (
                "UnsupportedAddress",
                "Gateway contains an address type unsupported by this controller",
            )
        } else if accepted {
            ("Accepted", "at least one listener is accepted")
        } else {
            ("ListenersNotValid", "no listener can be accepted")
        };
        let (programmed_reason, programmed_message) = if !address_decision.accepted {
            ("UnsupportedAddress", "Gateway address type is unsupported")
        } else if !address_decision.usable {
            (
                "AddressNotUsable",
                "one or more requested Gateway addresses cannot be bound",
            )
        } else if programmed {
            (
                "Programmed",
                "accepted listeners are present in the candidate bundle",
            )
        } else {
            ("AddressNotAssigned", "no listener is programmed")
        };
        let backend_client_reference =
            gateway_backend_client_reference_condition(gateway, namespace, secrets)?;
        let mut gateway_conditions = vec![
            gateway_condition(
                "Accepted",
                accepted,
                accepted_reason,
                accepted_message,
                generation,
                &transition_time,
            ),
            gateway_condition(
                "Programmed",
                programmed,
                programmed_reason,
                programmed_message,
                generation,
                &transition_time,
            ),
            gateway_condition(
                "ResolvedRefs",
                backend_client_reference.resolved,
                backend_client_reference.reason,
                backend_client_reference.message,
                generation,
                &transition_time,
            ),
        ];
        if frontend_validation
            .insecure_gateways
            .contains(&(namespace.to_owned(), name.to_owned()))
        {
            gateway_conditions.push(gateway_condition(
                "InsecureFrontendValidationMode",
                true,
                "ConfigurationChanged",
                "frontend client certificate validation allows insecure fallback",
                generation,
                &transition_time,
            ));
        }
        output.push(ControlStatusIntent {
            api_version: "gateway.networking.k8s.io/v1".to_owned(),
            kind: "Gateway".to_owned(),
            plural: "gateways".to_owned(),
            namespace: Some(namespace.to_owned()),
            name: name.to_owned(),
            status: json!({
                "addresses":addresses,
                "conditions":gateway_conditions,
                "attachedListenerSets":attached_listener_sets,
                "listeners":listener_statuses
            }),
        });
    }
    for listener_set in resource_items(listener_sets_value, cfg.max_objects, "ListenerSet")? {
        let (namespace, name) = object_identity(listener_set, "ListenerSet")?;
        if listener_set
            .pointer("/metadata/deletionTimestamp")
            .is_some()
        {
            continue;
        }
        let key = (namespace.to_owned(), name.to_owned());
        let Some(decision) = catalog.listener_set_decisions.get(&key) else {
            continue;
        };
        let generation = listener_set
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let valid = valid_listener_sets.contains(&key);
        let listeners = listener_set
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("ListenerSet missing spec.listeners")?;
        let mut listener_statuses = Vec::new();
        if decision.allowed {
            for listener in listeners {
                let section = listener
                    .get("name")
                    .and_then(Value::as_str)
                    .context("ListenerSet listener missing name")?;
                let protocol = listener
                    .get("protocol")
                    .and_then(Value::as_str)
                    .context("ListenerSet listener missing protocol")?;
                let conflict_reason = decision.listener_reasons.get(section).copied().flatten();
                let active = active_listeners.contains(&(
                    "ListenerSet".to_owned(),
                    namespace.to_owned(),
                    name.to_owned(),
                    section.to_owned(),
                ));
                let references = listener_reference_condition(
                    listener,
                    namespace,
                    "ListenerSet",
                    secrets,
                    &grants,
                )?;
                let kinds = parse_allowed_kinds(listener, protocol)?;
                let accepted = active && conflict_reason.is_none();
                let programmed = accepted && references.resolved && !kinds.has_invalid;
                let accepted_reason = conflict_reason.unwrap_or(if accepted {
                    "Accepted"
                } else {
                    "UnsupportedValue"
                });
                let (resolved, resolved_reason, resolved_message) = if kinds.has_invalid {
                    (
                        false,
                        "InvalidRouteKinds",
                        "listener contains Route kinds unsupported by its protocol",
                    )
                } else {
                    (references.resolved, references.reason, references.message)
                };
                let programmed_reason = conflict_reason.unwrap_or(if programmed {
                    "Programmed"
                } else {
                    resolved_reason
                });
                let supported_kinds = kinds
                    .supported
                    .iter()
                    .map(|kind| json!({"group":"gateway.networking.k8s.io","kind":kind}))
                    .collect::<Vec<_>>();
                let listener_key = (
                    "ListenerSet".to_owned(),
                    namespace.to_owned(),
                    name.to_owned(),
                    section.to_owned(),
                );
                let attached_routes = diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.accepted)
                    .filter(|diagnostic| diagnostic.attached_listeners.contains(&listener_key))
                    .count();
                listener_statuses.push(json!({
                    "name":section,
                    "supportedKinds":supported_kinds,
                    "attachedRoutes":attached_routes,
                    "conditions":[
                        gateway_condition(
                            "Accepted",
                            accepted,
                            accepted_reason,
                            if accepted { "listener is accepted by its parent Gateway" } else { "listener conflicts with a higher-precedence listener" },
                            generation,
                            &transition_time
                        ),
                        gateway_condition(
                            "Programmed",
                            programmed,
                            programmed_reason,
                            if programmed { "listener is present in the candidate bundle" } else { "listener cannot be programmed" },
                            generation,
                            &transition_time
                        ),
                        gateway_condition(
                            "ResolvedRefs",
                            resolved,
                            resolved_reason,
                            resolved_message,
                            generation,
                            &transition_time
                        ),
                        gateway_condition(
                            "Conflicted",
                            conflict_reason.is_some(),
                            conflict_reason.unwrap_or("NoConflicts"),
                            if conflict_reason.is_some() { "listener conflicts with a higher-precedence listener" } else { "listener has no conflicts" },
                            generation,
                            &transition_time
                        )
                    ]
                }));
            }
        }
        let (accepted_reason, accepted_message) = if !decision.allowed {
            (
                "NotAllowed",
                "parent Gateway does not allow this ListenerSet",
            )
        } else if valid {
            ("Accepted", "at least one listener is valid")
        } else {
            ("ListenersNotValid", "no listener can be programmed")
        };
        let programmed_reason = if !decision.allowed {
            "NotAllowed"
        } else if valid {
            "Programmed"
        } else {
            "ListenersNotValid"
        };
        output.push(ControlStatusIntent {
            api_version: "gateway.networking.k8s.io/v1".to_owned(),
            kind: "ListenerSet".to_owned(),
            plural: "listenersets".to_owned(),
            namespace: Some(namespace.to_owned()),
            name: name.to_owned(),
            status: json!({
                "conditions":[
                    gateway_condition("Accepted", valid, accepted_reason, accepted_message, generation, &transition_time),
                    gateway_condition("Programmed", valid, programmed_reason, accepted_message, generation, &transition_time)
                ],
                "listeners":listener_statuses
            }),
        });
    }
    anyhow::ensure!(
        output.len() <= cfg.max_status_updates,
        "Gateway control status updates exceed max_status_updates"
    );
    Ok(output)
}

/// 业务作用：复验 Gateway 上游客户端证书引用，避免状态宣称引用已解析而数据面没有可用 mTLS 身份。
///
/// 参数说明：`gateway` 与 `secrets` 来自同轮；`namespace` 是 Gateway 的可信 namespace。
///
/// 返回：未声明或 Secret 身份完整时为 ResolvedRefs；类型、缺失或证书错误返回失败条件而不泄露材料。
fn gateway_backend_client_reference_condition(
    gateway: &Value,
    namespace: &str,
    secrets: &SecretCatalog,
) -> anyhow::Result<ListenerReferenceCondition> {
    let Some(reference) = gateway.pointer("/spec/tls/backend/clientCertificateRef") else {
        return Ok(ListenerReferenceCondition {
            resolved: true,
            reason: "ResolvedRefs",
            message: "Gateway backend client certificate reference is resolved",
        });
    };
    if !reference
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
        || reference
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Secret")
            != "Secret"
    {
        return Ok(ListenerReferenceCondition {
            resolved: false,
            reason: "InvalidKind",
            message: "Gateway backend client certificate must reference a core Secret",
        });
    }
    let name = reference
        .get("name")
        .and_then(Value::as_str)
        .context("Gateway backend clientCertificateRef missing name")?;
    let resolved = secrets
        .tls_material(namespace, name)
        .ok()
        .flatten()
        .is_some();
    Ok(ListenerReferenceCondition {
        resolved,
        reason: if resolved {
            "ResolvedRefs"
        } else {
            "InvalidCertificateRef"
        },
        message: if resolved {
            "Gateway backend client certificate reference is resolved"
        } else {
            "Gateway backend client certificate Secret is missing or invalid"
        },
    })
}

/// 业务作用：把 Gateway infrastructure 的 label/annotation 解析为有界字符串映射，
/// 防止用户 metadata 通过控制器生成资源形成无界对象或控制字符注入。
///
/// 参数说明：`infrastructure` 是 `spec.infrastructure`；`field` 为 `labels` 或
/// `annotations`；`max_value_len` 按 Kubernetes 对应字段限制取值。
///
/// 返回：字段缺失时返回空映射；键值数量与字符边界合法时返回稳定排序映射，否则拒绝候选。
fn gateway_infrastructure_metadata(
    infrastructure: &Value,
    field: &str,
    max_value_len: usize,
) -> anyhow::Result<BTreeMap<String, String>> {
    let Some(value) = infrastructure.get(field) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .with_context(|| format!("Gateway infrastructure.{field} must be an object"))?;
    anyhow::ensure!(
        object.len() <= 64,
        "Gateway infrastructure.{field} exceeds 64 entries"
    );
    let mut output = BTreeMap::new();
    for (key, value) in object {
        let value = value
            .as_str()
            .with_context(|| format!("Gateway infrastructure.{field}[{key}] must be a string"))?;
        anyhow::ensure!(
            !key.is_empty()
                && key.len() <= 253
                && !key.chars().any(char::is_control)
                && value.len() <= max_value_len
                && !value.chars().any(char::is_control),
            "Gateway infrastructure.{field} contains an invalid key or value"
        );
        output.insert(key.clone(), value.to_owned());
    }
    Ok(output)
}

/// 业务作用：为声明 `spec.infrastructure` 的受管 Gateway 构造同 namespace
/// ServiceAccount 锚点计划，使用户 metadata 有真实生成资源承载并由 Gateway GC 回收。
///
/// 参数说明：GatewayClass/Gateway 来自同轮 LIST；`cfg` 限定 controller 与 namespace 范围。
///
/// 返回：返回有界、稳定命名且包含 Gateway ownerReference 的 apply 意图；缺 UID、非法
/// metadata 或对象超限时拒绝整轮候选。
fn build_gateway_infrastructure_intents(
    classes_value: &Value,
    gateways_value: &Value,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<Vec<GatewayInfrastructureIntent>> {
    let selected_classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let mut output = Vec::new();
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, gateway_name) = object_identity(gateway, "Gateway")?;
        if !namespace_allowed(cfg, namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class) {
            continue;
        }
        let Some(infrastructure) = gateway.pointer("/spec/infrastructure") else {
            continue;
        };
        let gateway_uid = gateway
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .context("Gateway with infrastructure missing metadata.uid")?;
        anyhow::ensure!(
            !gateway_uid.is_empty()
                && gateway_uid.len() <= 128
                && gateway_uid
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "Gateway infrastructure owner UID is invalid"
        );
        let mut labels = gateway_infrastructure_metadata(infrastructure, "labels", 63)?;
        let annotations = gateway_infrastructure_metadata(infrastructure, "annotations", 4096)?;
        // 标准 gateway-name label 必须由 controller 盖章，用户同名 metadata 不能把
        // 锚点关联到其它 Gateway，避免删除与审计归属混淆。
        labels.insert(
            "gateway.networking.k8s.io/gateway-name".to_owned(),
            gateway_name.to_owned(),
        );
        let name = stable_id("naway-gateway", &[namespace, gateway_name]);
        validate_kubernetes_name("Gateway infrastructure ServiceAccount", &name)?;
        output.push(GatewayInfrastructureIntent {
            namespace: namespace.to_owned(),
            name,
            gateway_name: gateway_name.to_owned(),
            gateway_uid: gateway_uid.to_owned(),
            labels,
            annotations,
        });
    }
    anyhow::ensure!(
        output.len() <= cfg.max_status_updates,
        "Gateway infrastructure intents exceed max_status_updates"
    );
    Ok(output)
}

/// 业务作用：用 Server-Side Apply 创建或收敛 Gateway 基础设施 ServiceAccount 锚点，
/// 传播用户 metadata，同时避免生成可自动挂载凭据的运行身份。
///
/// 参数说明：transport 参数固定 Kubernetes API endpoint/凭据；`cfg` 提供写预算；
/// `intents` 来自同轮受管 Gateway 快照。
///
/// 返回：全部锚点 apply 成功时返回成功；RBAC、冲突或 transport 失败时返回错误，调用方
/// 不得推进对应 Gateway status。
async fn publish_gateway_infrastructure(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    cfg: &KubernetesRouteSourceCfg,
    intents: &[GatewayInfrastructureIntent],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        intents.len() <= cfg.max_status_updates,
        "Gateway infrastructure applies exceed max_status_updates"
    );
    for intent in intents {
        let url = format!(
            "{}/api/v1/namespaces/{}/serviceaccounts/{}?fieldManager=naway-gateway-controller&force=true",
            discovery.api_server, intent.namespace, intent.name
        );
        let body = json!({
            "apiVersion":"v1",
            "kind":"ServiceAccount",
            "metadata":{
                "namespace":intent.namespace,
                "name":intent.name,
                "labels":intent.labels,
                "annotations":intent.annotations,
                "ownerReferences":[{
                    "apiVersion":"gateway.networking.k8s.io/v1",
                    "kind":"Gateway",
                    "name":intent.gateway_name,
                    "uid":intent.gateway_uid,
                    "controller":false,
                    "blockOwnerDeletion":false
                }]
            },
            "automountServiceAccountToken":false
        });
        let mut request = client
            .patch(url)
            .timeout(Duration::from_millis(cfg.request_timeout_ms))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/apply-patch+yaml",
            )
            .body(
                serde_json::to_vec(&body)
                    .context("encode Gateway infrastructure ServiceAccount apply")?,
            );
        if !discovery.bearer_token.is_empty() {
            request = request.bearer_auth(&discovery.bearer_token);
        }
        let response = request
            .send()
            .await
            .context("send Gateway infrastructure ServiceAccount apply")?;
        anyhow::ensure!(
            response.status().is_success(),
            "Gateway infrastructure ServiceAccount apply returned HTTP {}",
            response.status()
        );
    }
    Ok(())
}

/// 业务作用：构造符合 metav1.Condition 必填字段的 Gateway 状态项。
///
/// 参数说明：condition 类型、状态、reason/message、generation 与 transition_time 均来自本轮冻结事实。
///
/// 返回：返回可直接进入 status subresource 的 JSON condition。
fn gateway_condition(
    condition_type: &str,
    status: bool,
    reason: &str,
    message: &str,
    generation: i64,
    transition_time: &str,
) -> Value {
    json!({
        "type": condition_type,
        "status": if status { "True" } else { "False" },
        "observedGeneration": generation,
        "lastTransitionTime": transition_time,
        "reason": reason,
        "message": message
    })
}

/// 业务作用：按被已接纳 HTTPRoute 引用的 Gateway 生成 InferencePool parent status，并在
/// 引用撤销后删除本控制器旧条目，同时保留其它控制器已有的原子列表成员。
///
/// 参数说明：Gateway、Route、namespace 与 pool 目录均来自同轮 LIST；`cfg` 固定控制器身份。
///
/// 返回：每个 InferencePool 返回一个有界 status apply 意图；关联父级超过协议上限时拒绝本轮。
#[allow(clippy::too_many_arguments)]
fn build_inference_pool_status_intents(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    namespaces_value: &Value,
    http_routes_value: &Value,
    pools_value: &Value,
    pools: &InferencePoolCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<Vec<ControlStatusIntent>> {
    let transition_time = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("format InferencePool status timestamp")?;
    let namespaces = build_namespace_catalog(namespaces_value, cfg.max_objects)?;
    let gateways = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let routes = resource_items(http_routes_value, cfg.max_objects, "HTTPRoute")?;
    let mut output = Vec::new();
    for pool_object in resource_items(pools_value, cfg.max_objects, "InferencePool")? {
        let (pool_namespace, pool_name) = object_identity(pool_object, "InferencePool")?;
        let resolved = pools
            .pools
            .get(&(pool_namespace.to_owned(), pool_name.to_owned()))
            .is_some_and(|pool| pool.resolved);
        let mut parents = BTreeSet::new();
        for route in routes {
            let (route_namespace, _) = object_identity(route, "HTTPRoute")?;
            if route.pointer("/metadata/deletionTimestamp").is_some()
                || !namespace_allowed(cfg, route_namespace)
            {
                continue;
            }
            let references_pool = route
                .pointer("/spec/rules")
                .and_then(Value::as_array)
                .is_some_and(|rules| {
                    rules.iter().any(|rule| {
                        rule.get("backendRefs")
                            .and_then(Value::as_array)
                            .is_some_and(|backends| {
                                backends.iter().any(|backend| {
                                    backend.get("group").and_then(Value::as_str)
                                        == Some("inference.networking.k8s.io")
                                        && backend.get("kind").and_then(Value::as_str)
                                            == Some("InferencePool")
                                        && backend.get("name").and_then(Value::as_str)
                                            == Some(pool_name)
                                        && backend
                                            .get("namespace")
                                            .and_then(Value::as_str)
                                            .unwrap_or(route_namespace)
                                            == pool_namespace
                                })
                            })
                    })
                });
            if !references_pool {
                continue;
            }
            for attached in
                attached_listeners(route, route_namespace, "HTTPRoute", &gateways, &namespaces)?
            {
                parents.insert((
                    attached.listener.gateway_namespace,
                    attached.listener.gateway_name,
                ));
            }
        }
        anyhow::ensure!(
            parents.len() <= 32,
            "InferencePool {pool_namespace}/{pool_name} exceeds 32 parent Gateways"
        );
        let generation = pool_object
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let existing_parents = pool_object
            .pointer("/status/parents")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut parent_statuses = existing_parents
            .iter()
            .filter(|parent| {
                parent.get("controllerName").and_then(Value::as_str)
                    != Some(cfg.gateway_controller_name.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        for (gateway_namespace, gateway_name) in parents {
            let parent_ref = json!({
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "namespace": gateway_namespace,
                "name": gateway_name
            });
            let existing = existing_parents.iter().find(|parent| {
                parent.get("controllerName").and_then(Value::as_str)
                    == Some(cfg.gateway_controller_name.as_str())
                    && parent.get("parentRef") == Some(&parent_ref)
            });
            let message = if resolved {
                "InferencePool is referenced by an accepted HTTPRoute"
            } else {
                "InferencePool endpointPickerRef is unresolved"
            };
            let (accepted_transition, _) = condition_transition_time(
                existing,
                "Accepted",
                "True",
                "Accepted",
                message,
                generation,
                &transition_time,
            );
            let resolved_status = if resolved { "True" } else { "False" };
            let resolved_reason = if resolved {
                "ResolvedRefs"
            } else {
                "InvalidExtensionRef"
            };
            let (resolved_transition, _) = condition_transition_time(
                existing,
                "ResolvedRefs",
                resolved_status,
                resolved_reason,
                message,
                generation,
                &transition_time,
            );
            parent_statuses.push(json!({
                "parentRef": parent_ref,
                "controllerName": cfg.gateway_controller_name,
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "True",
                        "observedGeneration": generation,
                        "lastTransitionTime": accepted_transition,
                        "reason": "Accepted",
                        "message": message
                    },
                    {
                        "type": "ResolvedRefs",
                        "status": resolved_status,
                        "observedGeneration": generation,
                        "lastTransitionTime": resolved_transition,
                        "reason": resolved_reason,
                        "message": message
                    }
                ]
            }));
        }
        anyhow::ensure!(
            parent_statuses.len() <= 32,
            "InferencePool {pool_namespace}/{pool_name} status exceeds 32 parent entries"
        );
        output.push(ControlStatusIntent {
            api_version: "inference.networking.k8s.io/v1".to_owned(),
            kind: "InferencePool".to_owned(),
            plural: "inferencepools".to_owned(),
            namespace: Some(pool_namespace.to_owned()),
            name: pool_name.to_owned(),
            status: json!({"parents": parent_statuses}),
        });
    }
    Ok(output)
}

/// 业务作用：以独立 field manager 发布本 controller 拥有的 Route parent conditions，
/// 不覆盖其它 Gateway controller 的 status entries。
///
/// 参数说明：`client`/`discovery` 是固定 API transport；`cfg` 提供 controllerName 与写预算；
/// `diagnostics` 是本轮逐对象编译结论。
///
/// 返回：全部 status apply 成功时返回成功；任一冲突/RBAC/transport 失败返回错误并等待下轮恢复。
async fn publish_route_statuses(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    cfg: &KubernetesRouteSourceCfg,
    diagnostics: &[RouteDiagnostic],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        diagnostics.len() <= cfg.max_status_updates,
        "Gateway API status updates exceed max_status_updates"
    );
    for diagnostic in diagnostics {
        publish_route_status(client, discovery, cfg, diagnostic).await?;
    }
    Ok(())
}

/// 业务作用：用独立 field manager 发布 GatewayClass/Gateway status，不取得 spec 或其它 controller 字段所有权。
///
/// 参数说明：transport 参数固定 API endpoint/凭据；`cfg` 提供 mutation 预算；`intents` 是本轮状态。
///
/// 返回：全部 status apply 成功时返回成功；RBAC、冲突或 transport 失败等待下轮恢复。
async fn publish_control_statuses(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    cfg: &KubernetesRouteSourceCfg,
    intents: &[ControlStatusIntent],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        intents.len() <= cfg.max_status_updates,
        "Gateway control status updates exceed max_status_updates"
    );
    for intent in intents {
        let path = match intent.namespace.as_deref() {
            Some(namespace) => format!(
                "/apis/{}/namespaces/{}/{}/{}/status",
                intent.api_version, namespace, intent.plural, intent.name
            ),
            None => format!(
                "/apis/{}/{}/{}/status",
                intent.api_version, intent.plural, intent.name
            ),
        };
        let url = format!(
            "{}{}?fieldManager=naway-gateway-controller",
            discovery.api_server, path
        );
        let mut metadata = json!({"name":intent.name});
        if let Some(namespace) = intent.namespace.as_deref() {
            metadata["namespace"] = json!(namespace);
        }
        let mut request = client
            .patch(url)
            .timeout(Duration::from_millis(cfg.request_timeout_ms))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/apply-patch+yaml",
            )
            .body(
                serde_json::to_vec(&json!({
                    "apiVersion":intent.api_version,
                    "kind":intent.kind,
                    "metadata":metadata,
                    "status":intent.status
                }))
                .context("encode Gateway control status apply")?,
            );
        if !discovery.bearer_token.is_empty() {
            request = request.bearer_auth(&discovery.bearer_token);
        }
        let response = request
            .send()
            .await
            .context("send Gateway control status apply")?;
        anyhow::ensure!(
            response.status().is_success(),
            "Gateway control status apply returned HTTP {}",
            response.status()
        );
    }
    Ok(())
}

/// 业务作用：按 resourceVersion 前置条件提交 Route finalizer 增删，避免并发 controller 覆盖 metadata。
///
/// 参数说明：transport 参数固定 API endpoint/凭据；`intents` 来自同轮 LIST；`operation`
/// 限定本次只执行 add 或 remove 阶段；`request_timeout_ms` 限制单次外部写入的最长等待。
///
/// 返回：全部 JSON Patch 成功时返回成功；任何冲突保留对象原状态并由下轮 relist 恢复。
async fn apply_finalizer_intents(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    intents: &[FinalizerIntent],
    operation: FinalizerOperation,
    request_timeout_ms: u64,
) -> anyhow::Result<()> {
    for intent in intents
        .iter()
        .filter(|intent| intent.operation == operation)
    {
        let mut patch = vec![json!({
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": intent.resource_version
        })];
        match operation {
            FinalizerOperation::Add if intent.finalizers_present => patch.push(json!({
                "op": "add",
                "path": "/metadata/finalizers/-",
                "value": GATEWAY_FINALIZER
            })),
            FinalizerOperation::Add => patch.push(json!({
                "op": "add",
                "path": "/metadata/finalizers",
                "value": [GATEWAY_FINALIZER]
            })),
            FinalizerOperation::Remove => {
                let index = intent
                    .finalizer_index
                    .context("remove finalizer intent missing index")?;
                patch.push(json!({
                    "op": "test",
                    "path": format!("/metadata/finalizers/{index}"),
                    "value": GATEWAY_FINALIZER
                }));
                patch.push(json!({
                    "op": "remove",
                    "path": format!("/metadata/finalizers/{index}")
                }));
            }
        }
        let url = format!(
            "{}/apis/{}/namespaces/{}/{}/{}",
            discovery.api_server, intent.api_version, intent.namespace, intent.plural, intent.name
        );
        let mut request = client
            .patch(url)
            .timeout(Duration::from_millis(request_timeout_ms))
            .header(reqwest::header::CONTENT_TYPE, "application/json-patch+json")
            .body(serde_json::to_vec(&patch).context("encode Gateway Route finalizer patch")?);
        if !discovery.bearer_token.is_empty() {
            request = request.bearer_auth(&discovery.bearer_token);
        }
        let response = request
            .send()
            .await
            .context("send Gateway Route finalizer patch")?;
        anyhow::ensure!(
            response.status().is_success(),
            "Gateway Route finalizer patch returned HTTP {}",
            response.status()
        );
    }
    Ok(())
}

/// 业务作用：通过 status subresource 的 Server-Side Apply 提交单个 Route condition 所有权。
///
/// 参数说明：transport 参数固定 API endpoint/凭据；`cfg` 提供 controllerName；`diagnostic`
/// 包含对象 generation、parentRefs 与编译结论。
///
/// 返回：API server 接受 apply 时成功；缺身份、坏 parentRef 或非 2xx 响应返回错误。
async fn publish_route_status(
    client: &reqwest::Client,
    discovery: &KubernetesDiscoveryCfg,
    cfg: &KubernetesRouteSourceCfg,
    diagnostic: &RouteDiagnostic,
) -> anyhow::Result<()> {
    let namespace = diagnostic
        .object
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let name = diagnostic
        .object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .context("Gateway Route status object missing metadata.name")?;
    let generation = diagnostic
        .object
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let parents = diagnostic
        .object
        .pointer("/spec/parentRefs")
        .and_then(Value::as_array)
        .context("Gateway Route status object missing parentRefs")?;
    let transition_time = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("format Gateway Route condition timestamp")?;
    let mut parent_statuses = Vec::new();
    let mut all_current = true;
    for parent in parents {
        let group = parent
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("gateway.networking.k8s.io");
        let kind = parent
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Gateway");
        let gateway_parent =
            group == "gateway.networking.k8s.io" && matches!(kind, "Gateway" | "ListenerSet");
        let mesh_parent = (group.is_empty() && kind == "Service")
            || (group == "multicluster.x-k8s.io" && kind == "ServiceImport");
        if !gateway_parent && !mesh_parent {
            continue;
        }
        let parent_ref = normalized_parent_ref(parent, namespace)?;
        let parent_namespace = parent
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(namespace);
        let parent_name = parent
            .get("name")
            .and_then(Value::as_str)
            .context("Gateway Route parentRef missing name")?;
        let parent_section = parent
            .get("sectionName")
            .and_then(Value::as_str)
            .unwrap_or("");
        // 未指定 sectionName 的 parentRef 授权该 parent 上任一匹配 listener；状态判断必须沿用
        // 数据面附件语义，否则路由已发布时仍会对外声明 NoMatchingParent。
        let parent_attached = diagnostic.attached_listeners.iter().any(
            |(attached_kind, attached_namespace, attached_name, attached_section)| {
                attached_kind == kind
                    && attached_namespace == parent_namespace
                    && attached_name == parent_name
                    && (parent_section.is_empty() || attached_section == parent_section)
            },
        );
        let parent_accepted = diagnostic.accepted && parent_attached;
        let detached_reason = if mesh_parent && !cfg.gateway_mesh_interception_ready {
            "UnsupportedValue"
        } else {
            "NoMatchingParent"
        };
        let accepted_reason = if parent_accepted {
            "Accepted"
        } else if diagnostic.accepted {
            detached_reason
        } else {
            diagnostic.reason.as_str()
        };
        let resolved_reason = if diagnostic.resolved_refs {
            "ResolvedRefs"
        } else {
            diagnostic.reason.as_str()
        };
        let existing_parent = diagnostic
            .object
            .pointer("/status/parents")
            .and_then(Value::as_array)
            .and_then(|parents| {
                parents.iter().find(|existing| {
                    existing.get("controllerName").and_then(Value::as_str)
                        == Some(cfg.gateway_controller_name.as_str())
                        && existing.get("parentRef") == Some(&parent_ref)
                })
            });
        let accepted_status = if parent_accepted { "True" } else { "False" };
        let resolved_status = if diagnostic.resolved_refs {
            "True"
        } else {
            "False"
        };
        let (accepted_transition, accepted_current) = condition_transition_time(
            existing_parent,
            "Accepted",
            accepted_status,
            accepted_reason,
            &diagnostic.message,
            generation,
            &transition_time,
        );
        let (resolved_transition, resolved_current) = condition_transition_time(
            existing_parent,
            "ResolvedRefs",
            resolved_status,
            resolved_reason,
            &diagnostic.message,
            generation,
            &transition_time,
        );
        all_current &= accepted_current && resolved_current;
        parent_statuses.push(json!({
            "parentRef": parent_ref,
            "controllerName": cfg.gateway_controller_name,
            "conditions": [
                {
                    "type": "Accepted",
                    "status": accepted_status,
                    "observedGeneration": generation,
                    "lastTransitionTime": accepted_transition,
                    "reason": accepted_reason,
                    "message": diagnostic.message
                },
                {
                    "type": "ResolvedRefs",
                    "status": resolved_status,
                    "observedGeneration": generation,
                    "lastTransitionTime": resolved_transition,
                    "reason": resolved_reason,
                    "message": diagnostic.message
                }
            ]
        }));
    }
    if all_current {
        return Ok(());
    }
    let url = format!(
        "{}/apis/{}/namespaces/{}/{}/{}/status?fieldManager=naway-gateway-controller",
        discovery.api_server, diagnostic.api_version, namespace, diagnostic.plural, name
    );
    let mut request = client
        .patch(url)
        .timeout(Duration::from_millis(cfg.request_timeout_ms))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/apply-patch+yaml",
        )
        .body(
            serde_json::to_vec(&json!({
                "apiVersion": diagnostic.api_version,
                "kind": diagnostic.kind,
                "metadata": {"name": name, "namespace": namespace},
                "status": {"parents": parent_statuses}
            }))
            .context("encode Gateway Route status apply")?,
        );
    if !discovery.bearer_token.is_empty() {
        request = request.bearer_auth(&discovery.bearer_token);
    }
    let response = request
        .send()
        .await
        .context("send Gateway Route status apply")?;
    anyhow::ensure!(
        response.status().is_success(),
        "Gateway Route status apply returned HTTP {}",
        response.status()
    );
    Ok(())
}

/// 业务作用：复用未变化 condition 的 lastTransitionTime，并判断本轮是否需要写 API server。
///
/// 参数说明：`parent` 是当前 controller 的旧 parent status；其余参数是期望 condition 字段；
/// `now` 是本轮统一时间。
///
/// 返回：字段完全一致时返回旧时间与 true；变化或缺失时返回当前时间与 false。
#[allow(clippy::too_many_arguments)]
fn condition_transition_time(
    parent: Option<&Value>,
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
    generation: i64,
    now: &str,
) -> (String, bool) {
    let existing = parent
        .and_then(|parent| parent.get("conditions"))
        .and_then(Value::as_array)
        .and_then(|conditions| {
            conditions.iter().find(|condition| {
                condition.get("type").and_then(Value::as_str) == Some(condition_type)
            })
        });
    let current = existing.is_some_and(|condition| {
        condition.get("status").and_then(Value::as_str) == Some(status)
            && condition.get("reason").and_then(Value::as_str) == Some(reason)
            && condition.get("message").and_then(Value::as_str) == Some(message)
            && condition.get("observedGeneration").and_then(Value::as_i64) == Some(generation)
    });
    let transition = existing
        .filter(|_| current)
        .and_then(|condition| condition.get("lastTransitionTime"))
        .and_then(Value::as_str)
        .unwrap_or(now)
        .to_owned();
    (transition, current)
}

/// 业务作用：补齐 parentRef 的标准默认 group/kind/namespace，使 status list-map key 跨节点一致。
///
/// 参数说明：`parent` 是 spec.parentRefs 单项；`route_namespace` 用于缺省 namespace。
///
/// 返回：parent name 与 sectionName 合法时返回规范 JSON；坏引用返回错误。
fn normalized_parent_ref(parent: &Value, route_namespace: &str) -> anyhow::Result<Value> {
    let name = parent
        .get("name")
        .and_then(Value::as_str)
        .context("Gateway Route parentRef missing name")?;
    let mut output = json!({
        "group": parent.get("group").and_then(Value::as_str).unwrap_or("gateway.networking.k8s.io"),
        "kind": parent.get("kind").and_then(Value::as_str).unwrap_or("Gateway"),
        "namespace": parent.get("namespace").and_then(Value::as_str).unwrap_or(route_namespace),
        "name": name
    });
    if let Some(section) = parent.get("sectionName").and_then(Value::as_str) {
        output["sectionName"] = json!(section);
    }
    if let Some(port) = parent.get("port").and_then(Value::as_u64) {
        output["port"] = json!(port);
    }
    Ok(output)
}

/// 业务作用：把受管 Ingress 按稳定对象顺序编译为共享 HTTP Route/Service IR。
///
/// 参数说明：`value` 是完整 Ingress LIST；`cfg` 限定接管范围；`routes` 与
/// `services` 接收候选，不直接发布数据面。
///
/// 返回：所有受管 backend/path 可安全表达时成功；坏引用、越界路径或协议配置返回错误。
fn compile_ingresses(
    value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    routes: &mut Vec<Value>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let mut items = resource_items(value, cfg.max_objects, "Ingress")?
        .iter()
        .collect::<Vec<_>>();
    items.sort_by_key(|object| object_order_key(object));
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
        "preserve_host": true,
        "predicates": predicates,
        "order": 0
    }));
    Ok(())
}

#[derive(Clone)]
enum AllowedNamespaces {
    Same,
    All,
    Selector(Value),
}

#[derive(Clone)]
struct GatewayListener {
    gateway_namespace: String,
    gateway_name: String,
    parent_group: String,
    parent_kind: String,
    parent_namespace: String,
    parent_name: String,
    section_name: String,
    protocol: String,
    parent_port: u16,
    port: u16,
    bind_address: String,
    hostname: Option<String>,
    tls_mode: Option<String>,
    allowed_namespaces: AllowedNamespaces,
    allowed_kinds: BTreeSet<String>,
}

struct AllowedRouteKinds {
    supported: BTreeSet<String>,
    has_invalid: bool,
}

struct GatewayCatalog {
    gateways: HashSet<(String, String)>,
    listener_sets: HashSet<(String, String)>,
    mesh_parents: HashSet<(String, String, String, String)>,
    mesh_interception_ready: bool,
    mesh_source_namespace_header: String,
    listeners: Vec<GatewayListener>,
    address_decisions: HashMap<(String, String), GatewayAddressDecision>,
    listener_set_decisions: HashMap<(String, String), ListenerSetDecision>,
}

struct ListenerSetDecision {
    gateway_namespace: String,
    gateway_name: String,
    allowed: bool,
    listener_reasons: BTreeMap<String, Option<&'static str>>,
}

struct GatewayAddressDecision {
    static_requested: bool,
    accepted: bool,
    usable: bool,
    bind_address: Option<String>,
    status_addresses: Vec<GatewayAssignedAddress>,
}

struct GatewayAssignedAddress {
    address_type: String,
    value: String,
}

#[derive(Default)]
struct NamespaceCatalog {
    labels: HashMap<String, BTreeMap<String, String>>,
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
struct ServiceCatalog {
    ports: HashMap<(String, String), BTreeMap<(u16, String), Option<String>>>,
    port_names: HashMap<(String, String), BTreeMap<String, u16>>,
    service_types: HashMap<(String, String), String>,
}

/// 同轮 InferencePool 身份到已验证后端与 EPP 计划的只读目录。
#[derive(Default)]
struct InferencePoolCatalog {
    pools: HashMap<(String, String), InferencePoolBackend>,
}

/// 一个 InferencePool 可原子写入生成文档的完整后端计划。
#[derive(Clone)]
struct InferencePoolBackend {
    resolved: bool,
    pool_service: Value,
    pool_logical: String,
    epp_service: Value,
    epp_logical: String,
    fail_open: bool,
}

/// 同轮 ServiceImport 身份到端口、协议和具名端口的只读目录。
#[derive(Default)]
struct ServiceImportCatalog {
    /// namespace/name 到数字端口、L4 protocol 与可选 appProtocol 的映射。
    ports: HashMap<(String, String), BTreeMap<(u16, String), Option<String>>>,
    /// namespace/name 下的具名端口到数字端口映射。
    port_names: HashMap<(String, String), BTreeMap<String, u16>>,
}

/// `XBackendTrafficPolicy.targetRefs` 的完整后端身份。
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BackendTrafficTargetKey {
    /// 目标 API group；core Service 使用空串。
    group: String,
    /// 目标 kind，仅接受 Service 或 ServiceImport。
    kind: String,
    /// 策略与目标共同所在的 namespace。
    namespace: String,
    /// 目标对象名。
    name: String,
}

/// 已可无损表达为 Naway 服务配置的后端流量策略。
#[derive(Clone)]
struct BackendTrafficPolicyConfig {
    /// 可选的共享重试预算。
    retry_budget: Option<Value>,
    /// 可选的 cookie 或 header 会话保持配置。
    session_affinity: Option<Value>,
}

/// 单个 targetRef 的接纳与引用解析结论。
struct BackendTrafficTargetDecision {
    /// 完整目标身份。
    key: BackendTrafficTargetKey,
    /// 当前策略是否取得该目标的唯一所有权。
    accepted: bool,
    /// 目标是否存在且属于受支持资源。
    resolved_refs: bool,
    /// 写入 Accepted condition 的稳定原因。
    accepted_reason: &'static str,
    /// 写入 ResolvedRefs condition 的稳定原因。
    resolved_reason: &'static str,
    /// 有界且不含敏感信息的诊断文本。
    message: String,
}

/// 一个策略对象及其所有目标的确定性裁决结果。
struct BackendTrafficPolicyDecision {
    /// 原对象 metadata，用于生成 status owner 意图。
    object: Value,
    /// 每个 targetRef 的独立 condition 事实。
    targets: Vec<BackendTrafficTargetDecision>,
    /// 语法有效时的原生配置；策略体无效时为空且不得占用目标。
    config: Option<BackendTrafficPolicyConfig>,
}

/// 全部后端流量策略及每个目标唯一赢家的只读目录。
#[derive(Default)]
struct BackendTrafficCatalog {
    /// 按稳定对象顺序保存的策略及 status 事实。
    policies: Vec<BackendTrafficPolicyDecision>,
    /// 目标到最早有效策略下标的映射。
    selected: BTreeMap<BackendTrafficTargetKey, usize>,
}

#[derive(Default)]
struct SecretCatalog {
    objects: HashMap<(String, String), Value>,
}

#[derive(Default)]
struct ConfigMapCatalog {
    objects: HashMap<(String, String), Value>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct BackendTlsTargetKey {
    namespace: String,
    service: String,
    section_name: Option<String>,
}

struct BackendTlsPolicyDecision {
    object: Value,
    targets: Vec<BackendTlsTargetKey>,
    accepted: bool,
    resolved_refs: bool,
    accepted_reason: &'static str,
    resolved_reason: &'static str,
    message: &'static str,
    server_name: Option<String>,
    ca_pem: Option<String>,
    subject_alt_names: Vec<String>,
}

#[derive(Default)]
struct BackendTlsCatalog {
    policies: Vec<BackendTlsPolicyDecision>,
    selected: BTreeMap<BackendTlsTargetKey, usize>,
}

#[derive(Default)]
struct GatewayBackendClientCatalog {
    materials: HashMap<(String, String), TlsSecretMaterial>,
}

#[derive(Clone)]
struct GatewayFrontendValidationDecision {
    resolved: bool,
    accepted_reason: &'static str,
    resolved_reason: &'static str,
    message: &'static str,
    ca_pem: Option<Vec<u8>>,
    allow_insecure_fallback: bool,
}

#[derive(Default)]
struct GatewayFrontendValidationCatalog {
    listeners: HashMap<(String, String, u16), GatewayFrontendValidationDecision>,
    insecure_gateways: HashSet<(String, String)>,
}

#[derive(Clone)]
struct TlsSecretMaterial {
    certificate_chain: Vec<u8>,
    private_key: Vec<u8>,
}

struct GatewayTlsIdentity {
    server_names: BTreeSet<String>,
    material: TlsSecretMaterial,
}

struct GatewayTlsPlan {
    listen: String,
    identities: Vec<GatewayTlsIdentity>,
    client_auth: Option<GatewayFrontendClientAuthPlan>,
}

#[derive(Clone, Eq, PartialEq)]
struct GatewayFrontendClientAuthPlan {
    ca_pem: Vec<u8>,
    require_client_certificate: bool,
    allow_untrusted_client_certificate: bool,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct HttpListenerKey {
    protocol: String,
    bind_address: String,
    port: u16,
}

struct GatewayHttpProxyPlan {
    id: String,
    listen: String,
    plain_enabled: bool,
    routes: Vec<Value>,
    gateway_listeners: Vec<GatewayListenerPlan>,
    tls: Option<GatewayTlsPlan>,
}

struct GatewayListenerPlan {
    id: String,
    hostname: Option<String>,
}

struct ListenerReferenceCondition {
    resolved: bool,
    reason: &'static str,
    message: &'static str,
}

impl SecretCatalog {
    /// 业务作用：从 Kubernetes TLS Secret 解码并复验可用的服务端身份，作为
    /// Gateway listener 进入 Programmed 状态的密钥门禁。
    ///
    /// 参数说明：`namespace`/`name` 是已经语法校验的 certificateRef 目标。
    ///
    /// 返回：Secret 缺失时返回 None；`tls.crt`/`tls.key` 完整、有界且匹配时返回
    /// 内存材料；编码、PEM 或密钥匹配错误均失败闭合。
    fn tls_material(
        &self,
        namespace: &str,
        name: &str,
    ) -> anyhow::Result<Option<TlsSecretMaterial>> {
        let Some(secret) = self.objects.get(&(namespace.to_owned(), name.to_owned())) else {
            return Ok(None);
        };
        let certificate = secret
            .pointer("/data/tls.crt")
            .and_then(Value::as_str)
            .context("Gateway TLS Secret missing tls.crt")?;
        let private_key = secret
            .pointer("/data/tls.key")
            .and_then(Value::as_str)
            .context("Gateway TLS Secret missing tls.key")?;
        anyhow::ensure!(
            certificate.len() <= MAX_TLS_SECRET_BYTES.saturating_mul(2)
                && private_key.len() <= MAX_TLS_SECRET_BYTES.saturating_mul(2),
            "Gateway TLS Secret encoded material exceeds hard limit"
        );
        let certificate_chain = base64::engine::general_purpose::STANDARD
            .decode(certificate)
            .context("decode Gateway TLS certificate")?;
        let private_key = base64::engine::general_purpose::STANDARD
            .decode(private_key)
            .context("decode Gateway TLS private key")?;
        anyhow::ensure!(
            !certificate_chain.is_empty()
                && !private_key.is_empty()
                && certificate_chain.len() <= MAX_TLS_SECRET_BYTES
                && private_key.len() <= MAX_TLS_SECRET_BYTES,
            "Gateway TLS Secret decoded material is empty or exceeds hard limit"
        );
        crate::tls::validate_server_identity_bytes(&certificate_chain, &private_key)?;
        Ok(Some(TlsSecretMaterial {
            certificate_chain,
            private_key,
        }))
    }
}

/// 业务作用：把已通过 listener/ReferenceGrant/Secret 门禁的 HTTPS 身份按 socket
/// 汇总为可原子发布的独立 proxy TLS 计划。
///
/// 参数说明：Gateway API LIST 与 `secrets` 来自同轮；`cfg` 限定 controller、
/// namespace、bind address 和对象预算。
///
/// 返回：返回 listen 到证书计划的稳定映射；同一 socket 的证书按内容去重，
/// 没有可编程 HTTPS listener 时返回空映射；证书语义异常时拒绝候选并保留 LKG。
#[allow(clippy::too_many_arguments)]
fn build_gateway_tls_plans(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    reference_grants_value: &Value,
    namespaces_value: &Value,
    secrets: &SecretCatalog,
    frontend_validation: &GatewayFrontendValidationCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<BTreeMap<String, GatewayTlsPlan>> {
    let catalog = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let active = catalog
        .listeners
        .iter()
        .map(|listener| {
            (
                (
                    listener.parent_kind.clone(),
                    listener.parent_namespace.clone(),
                    listener.parent_name.clone(),
                    listener.section_name.clone(),
                ),
                listener.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    let mut client_auth_by_listen = BTreeMap::<String, GatewayFrontendClientAuthPlan>::new();
    let selected_classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let mut identities_by_listen = BTreeMap::<String, BTreeMap<String, GatewayTlsIdentity>>::new();
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, gateway_name) = object_identity(gateway, "Gateway")?;
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class) || !namespace_allowed(cfg, namespace) {
            continue;
        }
        for listener in gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("Gateway missing spec.listeners")?
        {
            let Some(section) = listener.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(active_listener) = active.get(&(
                "Gateway".to_owned(),
                namespace.to_owned(),
                gateway_name.to_owned(),
                section.to_owned(),
            )) else {
                continue;
            };
            let frontend = frontend_validation.listeners.get(&(
                namespace.to_owned(),
                gateway_name.to_owned(),
                active_listener.port,
            ));
            if frontend.is_some_and(|decision| !decision.resolved) {
                continue;
            }
            if active_listener.protocol != "HTTPS"
                || !listener_reference_condition(listener, namespace, "Gateway", secrets, &grants)?
                    .resolved
            {
                continue;
            }
            let ip = active_listener
                .bind_address
                .parse::<std::net::IpAddr>()
                .context("parse Gateway HTTPS bind address")?;
            let listen = std::net::SocketAddr::new(ip, active_listener.port).to_string();
            if let Some(decision) = frontend.filter(|decision| decision.resolved) {
                let plan = GatewayFrontendClientAuthPlan {
                    ca_pem: decision
                        .ca_pem
                        .clone()
                        .expect("resolved frontend validation has CA"),
                    require_client_certificate: !decision.allow_insecure_fallback,
                    allow_untrusted_client_certificate: decision.allow_insecure_fallback,
                };
                if let Some(existing) = client_auth_by_listen.get(&listen) {
                    anyhow::ensure!(
                        existing == &plan,
                        "Gateway HTTPS socket has incompatible frontend client CA policies"
                    );
                } else {
                    client_auth_by_listen.insert(listen.clone(), plan);
                }
            }
            let identities = identities_by_listen.entry(listen).or_default();
            let references = listener
                .pointer("/tls/certificateRefs")
                .and_then(Value::as_array)
                .expect("resolved HTTPS listener has certificateRefs");
            for reference in references {
                let name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("resolved certificateRef has name");
                let secret_namespace = reference
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(namespace);
                let material = secrets
                    .tls_material(secret_namespace, name)?
                    .context("resolved Gateway certificate Secret disappeared from snapshot")?;
                let digest = tls_identity_digest(&material);
                let server_names = match active_listener.hostname.as_deref() {
                    Some(hostname) => BTreeSet::from([hostname.to_owned()]),
                    None => certificate_server_names(&material.certificate_chain)?,
                };
                identities
                    .entry(digest)
                    .and_modify(|identity| {
                        identity.server_names.extend(server_names.iter().cloned());
                    })
                    .or_insert(GatewayTlsIdentity {
                        server_names,
                        material,
                    });
            }
        }
    }
    for listener_set in resource_items(listener_sets_value, cfg.max_objects, "ListenerSet")? {
        let (namespace, listener_set_name) = object_identity(listener_set, "ListenerSet")?;
        for listener in listener_set
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("ListenerSet missing spec.listeners")?
        {
            let Some(section) = listener.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(active_listener) = active.get(&(
                "ListenerSet".to_owned(),
                namespace.to_owned(),
                listener_set_name.to_owned(),
                section.to_owned(),
            )) else {
                continue;
            };
            let frontend = frontend_validation.listeners.get(&(
                active_listener.gateway_namespace.clone(),
                active_listener.gateway_name.clone(),
                active_listener.port,
            ));
            if frontend.is_some_and(|decision| !decision.resolved) {
                continue;
            }
            if active_listener.protocol != "HTTPS"
                || !listener_reference_condition(
                    listener,
                    namespace,
                    "ListenerSet",
                    secrets,
                    &grants,
                )?
                .resolved
            {
                continue;
            }
            let ip = active_listener
                .bind_address
                .parse::<std::net::IpAddr>()
                .context("parse ListenerSet HTTPS bind address")?;
            let listen = std::net::SocketAddr::new(ip, active_listener.port).to_string();
            if let Some(decision) = frontend.filter(|decision| decision.resolved) {
                let plan = GatewayFrontendClientAuthPlan {
                    ca_pem: decision
                        .ca_pem
                        .clone()
                        .expect("resolved frontend validation has CA"),
                    require_client_certificate: !decision.allow_insecure_fallback,
                    allow_untrusted_client_certificate: decision.allow_insecure_fallback,
                };
                if let Some(existing) = client_auth_by_listen.get(&listen) {
                    anyhow::ensure!(
                        existing == &plan,
                        "Gateway HTTPS socket has incompatible frontend client CA policies"
                    );
                } else {
                    client_auth_by_listen.insert(listen.clone(), plan);
                }
            }
            let identities = identities_by_listen.entry(listen).or_default();
            let references = listener
                .pointer("/tls/certificateRefs")
                .and_then(Value::as_array)
                .expect("resolved ListenerSet HTTPS listener has certificateRefs");
            for reference in references {
                let secret_name = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("resolved ListenerSet certificateRef has name");
                let secret_namespace = reference
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(namespace);
                let material = secrets
                    .tls_material(secret_namespace, secret_name)?
                    .context("resolved ListenerSet certificate Secret disappeared from snapshot")?;
                let digest = tls_identity_digest(&material);
                let server_names = match active_listener.hostname.as_deref() {
                    Some(hostname) => BTreeSet::from([hostname.to_owned()]),
                    None => certificate_server_names(&material.certificate_chain)?,
                };
                identities
                    .entry(digest)
                    .and_modify(|identity| {
                        identity.server_names.extend(server_names.iter().cloned());
                    })
                    .or_insert(GatewayTlsIdentity {
                        server_names,
                        material,
                    });
            }
        }
    }
    let mut plans = BTreeMap::new();
    for (listen, identities) in identities_by_listen {
        anyhow::ensure!(
            !identities.is_empty() && identities.len() <= cfg.max_objects,
            "Gateway TLS identity set for {listen} is empty or exceeds max_objects"
        );
        plans.insert(
            listen.clone(),
            GatewayTlsPlan {
                client_auth: client_auth_by_listen.remove(&listen),
                listen,
                identities: identities.into_values().collect(),
            },
        );
    }
    Ok(plans)
}

/// 业务作用：为 Gateway API `TLS`/`Terminate` listener 汇总服务端证书身份，供 stream
/// preread 选路后执行下游 TLS 终止。
///
/// 参数说明：Gateway API LIST、Secret 目录和 `cfg` 来自同轮冻结快照。
///
/// 返回：返回 listen 到 TLS 身份计划的稳定映射；证书引用未解析的 listener 不进入候选，
/// 材料异常或同 socket 身份超限时拒绝整轮发布。
#[allow(clippy::too_many_arguments)]
fn build_gateway_stream_tls_plans(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    reference_grants_value: &Value,
    namespaces_value: &Value,
    secrets: &SecretCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<BTreeMap<String, GatewayTlsPlan>> {
    let catalog = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let active = catalog
        .listeners
        .iter()
        .map(|listener| {
            (
                (
                    listener.parent_kind.clone(),
                    listener.parent_namespace.clone(),
                    listener.parent_name.clone(),
                    listener.section_name.clone(),
                ),
                listener.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let selected_classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    let mut identities = BTreeMap::<String, BTreeMap<String, GatewayTlsIdentity>>::new();
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, gateway_name) = object_identity(gateway, "Gateway")?;
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class)
            || !namespace_allowed(cfg, namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        for listener in gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("Gateway missing spec.listeners")?
        {
            let Some(section) = listener.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(active_listener) = active.get(&(
                "Gateway".to_owned(),
                namespace.to_owned(),
                gateway_name.to_owned(),
                section.to_owned(),
            )) else {
                continue;
            };
            append_gateway_stream_tls_identity(
                listener,
                namespace,
                "Gateway",
                active_listener,
                secrets,
                &grants,
                &mut identities,
            )?;
        }
    }
    for listener_set in resource_items(listener_sets_value, cfg.max_objects, "ListenerSet")? {
        let (namespace, name) = object_identity(listener_set, "ListenerSet")?;
        for listener in listener_set
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("ListenerSet missing spec.listeners")?
        {
            let Some(section) = listener.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(active_listener) = active.get(&(
                "ListenerSet".to_owned(),
                namespace.to_owned(),
                name.to_owned(),
                section.to_owned(),
            )) else {
                continue;
            };
            append_gateway_stream_tls_identity(
                listener,
                namespace,
                "ListenerSet",
                active_listener,
                secrets,
                &grants,
                &mut identities,
            )?;
        }
    }
    identities
        .into_iter()
        .map(|(listen, values)| {
            anyhow::ensure!(
                !values.is_empty() && values.len() <= cfg.max_objects,
                "Gateway stream TLS identity set for {listen} is empty or exceeds max_objects"
            );
            Ok((
                listen.clone(),
                GatewayTlsPlan {
                    listen,
                    identities: values.into_values().collect(),
                    client_auth: None,
                },
            ))
        })
        .collect()
}

/// 业务作用：把一个已裁决 `TLS`/`Terminate` listener 的 Secret 身份合并到 socket 计划，
/// 并保持 SNI 与证书内容的一致映射。
///
/// 参数说明：`listener` 是原始声明；`active_listener` 是冲突裁决后的网络身份；其余参数
/// 提供引用授权、Secret 材料与输出集合。
///
/// 返回：非终止 listener 或引用未解析时不修改输出；有效身份按摘要去重后成功加入，
/// 证书语义异常时返回错误并阻止半完成 TLS socket 发布。
#[allow(clippy::too_many_arguments)]
fn append_gateway_stream_tls_identity(
    listener: &Value,
    source_namespace: &str,
    source_kind: &str,
    active_listener: &GatewayListener,
    secrets: &SecretCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    identities_by_listen: &mut BTreeMap<String, BTreeMap<String, GatewayTlsIdentity>>,
) -> anyhow::Result<()> {
    if active_listener.protocol != "TLS"
        || listener.pointer("/tls/mode").and_then(Value::as_str) != Some("Terminate")
        || !listener_reference_condition(listener, source_namespace, source_kind, secrets, grants)?
            .resolved
    {
        return Ok(());
    }
    let ip = active_listener
        .bind_address
        .parse::<std::net::IpAddr>()
        .context("parse Gateway TLS terminate bind address")?;
    let listen = std::net::SocketAddr::new(ip, active_listener.port).to_string();
    let references = listener
        .pointer("/tls/certificateRefs")
        .and_then(Value::as_array)
        .expect("resolved TLS terminate listener has certificateRefs");
    for reference in references {
        let name = reference
            .get("name")
            .and_then(Value::as_str)
            .expect("resolved TLS terminate certificateRef has name");
        let namespace = reference
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(source_namespace);
        let material = secrets
            .tls_material(namespace, name)?
            .context("resolved TLS terminate Secret disappeared from snapshot")?;
        let digest = tls_identity_digest(&material);
        let server_names = match active_listener.hostname.as_deref() {
            Some(hostname) => BTreeSet::from([hostname.to_owned()]),
            None => certificate_server_names(&material.certificate_chain)?,
        };
        identities_by_listen
            .entry(listen.clone())
            .or_default()
            .entry(digest)
            .and_modify(|identity| {
                identity.server_names.extend(server_names.iter().cloned());
            })
            .or_insert(GatewayTlsIdentity {
                server_names,
                material,
            });
    }
    Ok(())
}

/// 业务作用：从已裁决冲突的 Gateway HTTP/HTTPS listener 构造共享 socket 的逻辑权威表，
/// 供请求层隔离 Host 路由，并在 HTTPS 上判断 TLS SNI 是否选择同一 listener。
///
/// 参数说明：`classes_value`/`gateways_value` 来自同轮 LIST；`cfg` 限定 controller、
/// namespace、绑定地址与对象预算。
///
/// 返回：按 HTTP/HTTPS socket 返回稳定 listener 身份与可选 hostname；网络层不可区分的同
/// hostname listener 会归并为同一权威桶，预算越界则拒绝整轮候选。
fn build_gateway_listener_plans_with_listener_sets(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    namespaces_value: &Value,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<BTreeMap<HttpListenerKey, Vec<GatewayListenerPlan>>> {
    let catalog = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let mut plans = BTreeMap::<HttpListenerKey, Vec<GatewayListenerPlan>>::new();
    let mut hostnames = BTreeMap::<HttpListenerKey, BTreeSet<Option<String>>>::new();
    for listener in catalog
        .listeners
        .into_iter()
        .filter(|listener| matches!(listener.protocol.as_str(), "HTTP" | "HTTPS"))
    {
        let listener_id = gateway_listener_id(&listener);
        let key = HttpListenerKey {
            protocol: listener.protocol,
            bind_address: listener.bind_address,
            port: listener.port,
        };
        let hostname = listener.hostname;
        // 同 socket、同 hostname 的 listener 无法由 HTTP/TLS 请求区分，必须共享权威
        // 身份；把它们当作冲突会阻断其他 Gateway 的状态发布并冻结整个数据面。
        if hostnames
            .entry(key.clone())
            .or_default()
            .insert(hostname.clone())
        {
            plans.entry(key).or_default().push(GatewayListenerPlan {
                id: listener_id,
                hostname: hostname.clone(),
            });
        }
    }
    anyhow::ensure!(
        plans.values().all(|listeners| listeners.len() <= 128),
        "Gateway HTTP socket exceeds 128 logical listeners"
    );
    Ok(plans)
}

/// 业务作用：把每个 HTTP/HTTPS listener 的独立路由表与证书计划组合成互不串流量的
/// proxy 候选，作为动态端口和 listener isolation 的数据面边界。
///
/// 参数说明：`listener_routes` 按协议/socket 分区；`tls_plans` 只含证书引用已解析的
/// HTTPS socket；`cfg` 提供对象和路由预算。
///
/// 返回：HTTP listener 总会生成 plain proxy；HTTPS 仅在证书计划存在时生成 TLS-only
/// proxy；同权威桶中除 id 外完全等价的路由会合并，孤立证书、数量超限或地址异常时拒绝候选。
fn build_gateway_http_proxy_plans(
    listener_routes: BTreeMap<HttpListenerKey, Vec<Value>>,
    mut tls_plans: BTreeMap<String, GatewayTlsPlan>,
    mut gateway_listeners: BTreeMap<HttpListenerKey, Vec<GatewayListenerPlan>>,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<Vec<GatewayHttpProxyPlan>> {
    let mut plans = Vec::new();
    for (key, routes) in listener_routes {
        anyhow::ensure!(
            routes.len() <= cfg.max_routes,
            "Gateway listener route table exceeds max_routes"
        );
        let routes = deduplicate_equivalent_gateway_routes(routes)?;
        let ip = key
            .bind_address
            .parse::<std::net::IpAddr>()
            .context("parse Gateway HTTP listener bind address")?;
        let listen = std::net::SocketAddr::new(ip, key.port).to_string();
        let gateway_listeners = gateway_listeners.remove(&key).unwrap_or_default();
        let (plain_enabled, tls) = match key.protocol.as_str() {
            "HTTP" => (true, None),
            "HTTPS" => {
                let Some(tls) = tls_plans.remove(&listen) else {
                    // 证书引用未解析时 listener status 已明确失败；不能建立一个无身份的
                    // TLS socket，也不能把其 route 泄漏到同端口明文 proxy。
                    continue;
                };
                (false, Some(tls))
            }
            other => bail!("Gateway HTTP proxy protocol `{other}` is unsupported"),
        };
        plans.push(GatewayHttpProxyPlan {
            id: stable_id(
                "k8s-listener",
                &[
                    key.protocol.as_str(),
                    key.bind_address.as_str(),
                    &key.port.to_string(),
                ],
            ),
            listen,
            plain_enabled,
            routes,
            gateway_listeners,
            tls,
        });
    }
    anyhow::ensure!(
        tls_plans.is_empty(),
        "Gateway TLS plan has no matching HTTPS listener route table"
    );
    anyhow::ensure!(
        gateway_listeners.is_empty(),
        "Gateway listener metadata has no matching HTTP route table"
    );
    anyhow::ensure!(
        plans.len() <= cfg.max_objects,
        "Gateway generated HTTP proxy count exceeds max_objects"
    );
    Ok(plans)
}

/// 业务作用：合并共享 socket 权威桶中行为完全相同的 Gateway 路由，避免多个网络层
/// 不可区分的 Gateway 对象把等价规则重复提交给 Router 冲突门禁。
///
/// 参数说明：`routes` 是同一协议、地址和端口下已经完成 listener 身份限定的 Route IR。
///
/// 返回：保留每种完整行为的首条路由并维持原有 specificity 顺序；只有 `id` 不同的路由
/// 才能合并，结构异常或序列化失败时拒绝候选，动作不同的同 predicate 冲突继续由 Router 拒绝。
fn deduplicate_equivalent_gateway_routes(routes: Vec<Value>) -> anyhow::Result<Vec<Value>> {
    let mut fingerprints = BTreeSet::new();
    let mut output = Vec::with_capacity(routes.len());
    for route in routes {
        let mut comparable = route.clone();
        comparable
            .as_object_mut()
            .context("generated Gateway route must be an object")?
            .remove("id")
            .context("generated Gateway route missing id")?;
        let fingerprint = serde_json::to_string(&comparable)
            .context("serialize generated Gateway route fingerprint")?;
        if fingerprints.insert(fingerprint) {
            output.push(route);
        }
    }
    Ok(output)
}

/// 业务作用：为 TLS 身份生成不泄露 Kubernetes 对象名的稳定内容标识，供不可变
/// 版本目录去重。
///
/// 参数说明：`material` 是已通过 rustls 匹配复验的证书链与私钥。
///
/// 返回：返回覆盖 cert/key 边界的 SHA-256 小写十六进制摘要。
fn tls_identity_digest(material: &TlsSecretMaterial) -> String {
    let mut hasher = Sha256::new();
    hasher.update((material.certificate_chain.len() as u64).to_le_bytes());
    hasher.update(&material.certificate_chain);
    hasher.update((material.private_key.len() as u64).to_le_bytes());
    hasher.update(&material.private_key);
    hex_lower(&hasher.finalize())
}

/// 业务作用：从已验证的 leaf certificate 提取 DNS SAN，使无 hostname listener 也能
/// 在多证书时按 SNI 选择正确身份。
///
/// 参数说明：`certificate_chain` 是 PEM 证书链，第一张必须是 leaf。
///
/// 返回：返回经 Gateway hostname 规则规范化的 DNS SAN 集合；PEM/X.509 解析失败
/// 时拒绝候选，空 SAN 返回空集合并仅可作为默认证书。
fn certificate_server_names(certificate_chain: &[u8]) -> anyhow::Result<BTreeSet<String>> {
    let mut reader = std::io::Cursor::new(certificate_chain);
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parse Gateway TLS leaf PEM")?
        .context("Gateway TLS certificate chain is empty")?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("parse Gateway TLS leaf X.509: {error}"))?;
    let mut names = BTreeSet::new();
    for extension in certificate.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            extension.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(name) = name {
                    names.insert(normalize_hostname(name)?);
                }
            }
        }
    }
    Ok(names)
}

struct ReferenceGrantCatalog<'a> {
    grants: &'a [Value],
}

#[derive(Clone)]
struct AttachedListener {
    listener: GatewayListener,
}

#[derive(Clone)]
struct BackendTarget {
    logical: String,
    weight: u32,
    filters: Vec<String>,
    inference_pool: Option<Value>,
    ext_proc: Option<Value>,
}

#[derive(Default)]
struct HttpFilterPlan {
    filters: Vec<String>,
    gateway_redirect: Option<Value>,
}

#[derive(Default)]
struct L4ListenerPlan {
    id: String,
    listen: String,
    protocol: String,
    tls_passthrough: bool,
    tls_termination: bool,
    routes: Vec<Value>,
}

#[derive(Clone)]
struct RouteDiagnostic {
    object: Value,
    api_version: String,
    kind: String,
    plural: String,
    accepted: bool,
    resolved_refs: bool,
    reason: String,
    message: String,
    attached_listeners: BTreeSet<(String, String, String, String)>,
}

impl RouteDiagnostic {
    /// 业务作用：记录单个 Gateway Route 的稳定 condition 结论，供 status owner 独立发布。
    ///
    /// 参数说明：`object` 保留 parentRefs/resourceVersion；协议身份指定 status endpoint；
    /// `accepted`/`resolved_refs` 与 reason/message 描述本轮编译结论。
    ///
    /// 返回：返回不含敏感数据、可跨节点一致重建的诊断记录。
    #[allow(clippy::too_many_arguments)]
    fn new(
        object: &Value,
        api_version: &str,
        kind: &str,
        plural: &str,
        accepted: bool,
        resolved_refs: bool,
        reason: &str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            object: object.clone(),
            api_version: api_version.to_owned(),
            kind: kind.to_owned(),
            plural: plural.to_owned(),
            accepted,
            resolved_refs,
            reason: reason.to_owned(),
            message: bounded_status_message(message.into()),
            attached_listeners: BTreeSet::new(),
        }
    }

    /// 业务作用：冻结本轮真正接纳 Route 的 listener 集合，使各 listener 的
    /// `attachedRoutes` 不会被同一 parent 下无 hostname 交集的其它 listener 放大。
    ///
    /// 参数说明：`listeners` 已通过 parent、namespace、kind 与 hostname 全部门禁。
    ///
    /// 返回：返回携带稳定 listener 身份集合的诊断记录，供状态发布阶段精确计数。
    fn with_attached_listeners(mut self, listeners: &[AttachedListener]) -> Self {
        self.attached_listeners = listeners
            .iter()
            .map(|attached| {
                (
                    attached.listener.parent_kind.clone(),
                    attached.listener.parent_namespace.clone(),
                    attached.listener.parent_name.clone(),
                    attached.listener.section_name.clone(),
                )
            })
            .collect();
        self
    }
}

/// 业务作用：限制写回 Kubernetes condition 的 message，避免远端对象内容放大 status 与日志。
///
/// 参数说明：`message` 是不含 secret 的编译诊断。
///
/// 返回：返回最多 1024 个 UTF-8 字节边界内的消息。
fn bounded_status_message(mut message: String) -> String {
    if message.len() <= 1024 {
        return message;
    }
    let mut end = 1024;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message
}

/// 业务作用：把编译错误归一为 Gateway API condition reason，避免把高基数内部错误当协议枚举。
///
/// 参数说明：`message` 是构建期错误文本。
///
/// 返回：返回标准 RefNotPermitted、BackendNotFound、InvalidKind 或 UnsupportedValue。
fn diagnostic_reason(message: &str) -> &'static str {
    if message.contains("ReferenceGrant") || message.contains("not permitted") {
        "RefNotPermitted"
    } else if message.contains("does not exist") || message.contains("has no port") {
        "BackendNotFound"
    } else if message.contains("must target core Service") {
        "InvalidKind"
    } else {
        "UnsupportedValue"
    }
}

/// 业务作用：把 Gateway API 各 Route 类型编译为统一 HTTP/L4 候选，并在任何外部副作用前
/// 完成 listener、namespace、ReferenceGrant、Service port 与 filter 安全门校验。
///
/// 参数说明：各 `*_value` 是同一轮完整 LIST 结果；`cfg` 固定控制器边界；`routes`、
/// `services`、`stream_listeners` 接收可由标准 snapshot builder 再验证的候选 IR。
///
/// 返回：所有受管对象均能安全编译时成功；任何越权引用或不支持语义返回错误，调用方保留 LKG。
#[allow(clippy::too_many_arguments)]
fn compile_gateway_api_full_with_listener_sets(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    http_routes_value: &Value,
    grpc_routes_value: &Value,
    tls_routes_value: &Value,
    tcp_routes_value: &Value,
    udp_routes_value: &Value,
    reference_grants_value: &Value,
    namespaces_value: &Value,
    service_objects_value: &Value,
    inference_pools_value: &Value,
    inference_pods_value: &Value,
    service_imports_value: &Value,
    backend_tls_policies_value: &Value,
    backend_traffic_policies_value: &Value,
    backend_tls_config_maps: &ConfigMapCatalog,
    gateway_backend_clients: &GatewayBackendClientCatalog,
    cfg: &KubernetesRouteSourceCfg,
    _routes: &mut Vec<Value>,
    http_listener_routes: &mut BTreeMap<HttpListenerKey, Vec<Value>>,
    services: &mut BTreeMap<String, Value>,
    stream_listeners: &mut Vec<Value>,
    diagnostics: &mut Vec<RouteDiagnostic>,
) -> anyhow::Result<()> {
    let namespaces = build_namespace_catalog(namespaces_value, cfg.max_objects)?;
    let service_catalog = build_service_catalog(service_objects_value, cfg.max_objects)?;
    let inference_pools = cfg
        .inference_gateway_enabled
        .then(|| {
            build_inference_pool_catalog(
                inference_pools_value,
                inference_pods_value,
                &service_catalog,
                cfg,
            )
        })
        .transpose()?;
    let service_import_catalog =
        build_service_import_catalog(service_imports_value, cfg.max_objects)?;
    let backend_traffic = build_backend_traffic_catalog(
        backend_traffic_policies_value,
        &service_catalog,
        &service_import_catalog,
        cfg,
    )?;
    let backend_tls = build_backend_tls_catalog(
        backend_tls_policies_value,
        backend_tls_config_maps,
        &service_catalog,
        cfg,
    )?;
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    let mut gateways = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    extend_gateway_catalog_with_mesh_parents(
        &mut gateways,
        http_routes_value,
        grpc_routes_value,
        &service_catalog,
        &service_import_catalog,
        cfg,
    )?;
    for listener in &gateways.listeners {
        if matches!(listener.protocol.as_str(), "HTTP" | "HTTPS") {
            http_listener_routes
                .entry(HttpListenerKey {
                    protocol: listener.protocol.clone(),
                    bind_address: listener.bind_address.clone(),
                    port: listener.port,
                })
                .or_default();
        }
    }
    compile_http_routes(
        http_routes_value,
        cfg,
        &gateways,
        &namespaces,
        &service_catalog,
        &service_import_catalog,
        inference_pools.as_ref(),
        &backend_traffic,
        &grants,
        http_listener_routes,
        services,
        diagnostics,
    )?;
    compile_grpc_routes(
        grpc_routes_value,
        cfg,
        &gateways,
        &namespaces,
        &service_catalog,
        &service_import_catalog,
        &backend_traffic,
        &grants,
        http_listener_routes,
        services,
        diagnostics,
    )?;
    apply_backend_tls_policies(services, &backend_tls, &service_catalog)?;
    apply_gateway_backend_client_certificates(
        http_listener_routes,
        services,
        &gateways,
        gateway_backend_clients,
    )?;
    let mut l4 = BTreeMap::new();
    compile_l4_routes(
        "TLSRoute",
        tls_routes_value,
        cfg,
        &gateways,
        &namespaces,
        &service_catalog,
        &service_import_catalog,
        &backend_traffic,
        &grants,
        services,
        &mut l4,
        diagnostics,
    )?;
    compile_l4_routes(
        "TCPRoute",
        tcp_routes_value,
        cfg,
        &gateways,
        &namespaces,
        &service_catalog,
        &service_import_catalog,
        &backend_traffic,
        &grants,
        services,
        &mut l4,
        diagnostics,
    )?;
    compile_l4_routes(
        "UDPRoute",
        udp_routes_value,
        cfg,
        &gateways,
        &namespaces,
        &service_catalog,
        &service_import_catalog,
        &backend_traffic,
        &grants,
        services,
        &mut l4,
        diagnostics,
    )?;
    // L4 Service 只有在 Route 后端解析后才进入候选；此处必须复用同轮策略快照完成
    // TLS 升级，避免终止后的明文误发到要求加密的后端端口。
    apply_backend_tls_policies(services, &backend_tls, &service_catalog)?;
    for plan in l4.into_values() {
        let mut listener = json!({
            "id": plan.id,
            "listen": plan.listen,
            "protocol": plan.protocol,
            "reject_all": plan.routes.is_empty(),
            "routes": plan.routes
        });
        if plan.tls_passthrough {
            listener["preread"] = json!({"ssl_preread": true});
        }
        stream_listeners.push(listener);
    }
    Ok(())
}

/// 业务作用：建立 namespace label 快照，供 listener `allowedRoutes.namespaces.selector` 判权。
///
/// 参数说明：`value` 是 Namespace LIST；`max_objects` 限制不可信对象规模。
///
/// 返回：对象与 label 均合法时返回只读目录，否则拒绝本轮候选。
fn build_namespace_catalog(value: &Value, max_objects: usize) -> anyhow::Result<NamespaceCatalog> {
    let mut catalog = NamespaceCatalog::default();
    for namespace in resource_items(value, max_objects, "Namespace")? {
        let name = namespace
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("Namespace missing metadata.name")?;
        validate_kubernetes_name("Namespace name", name)?;
        let labels = namespace
            .pointer("/metadata/labels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .map(|(key, value)| {
                        value
                            .as_str()
                            .map(|value| (key.clone(), value.to_owned()))
                            .context("Namespace label value must be a string")
                    })
                    .collect::<anyhow::Result<BTreeMap<_, _>>>()
            })
            .transpose()?
            .unwrap_or_default();
        catalog.labels.insert(name.to_owned(), labels);
    }
    Ok(catalog)
}

/// 业务作用：冻结本轮 Service 数字端口、L4 protocol 与 appProtocol，防 Route 引用
/// 不存在或协议不匹配的端口后仍发布脏路由。
///
/// 参数说明：`value` 是 core/v1 Service LIST；`max_objects` 是对象硬上限。
///
/// 返回：返回 namespace/name 到有效端口协议及应用协议的目录；坏对象使整轮候选失败。
fn build_service_catalog(value: &Value, max_objects: usize) -> anyhow::Result<ServiceCatalog> {
    let mut catalog = ServiceCatalog::default();
    for service in resource_items(value, max_objects, "Service")? {
        let (namespace, name) = object_identity(service, "Service")?;
        let service_type = service
            .pointer("/spec/type")
            .and_then(Value::as_str)
            .unwrap_or("ClusterIP");
        anyhow::ensure!(
            matches!(
                service_type,
                "ClusterIP" | "NodePort" | "LoadBalancer" | "ExternalName"
            ),
            "Service {namespace}/{name} has invalid type"
        );
        let mut ports = BTreeMap::new();
        let mut port_names = BTreeMap::new();
        for port in service
            .pointer("/spec/ports")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(number) = port
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0)
            {
                let protocol = port
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("TCP")
                    .to_ascii_uppercase();
                anyhow::ensure!(
                    matches!(protocol.as_str(), "TCP" | "UDP" | "SCTP"),
                    "Service {namespace}/{name} port {number} has invalid protocol"
                );
                let app_protocol = port
                    .get("appProtocol")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Some(app_protocol) = &app_protocol {
                    anyhow::ensure!(
                        !app_protocol.is_empty() && app_protocol.len() <= 63,
                        "Service {namespace}/{name} port {number} appProtocol has invalid length"
                    );
                }
                anyhow::ensure!(
                    ports
                        .insert((number, protocol.clone()), app_protocol)
                        .is_none(),
                    "Service {namespace}/{name} repeats {protocol} port {number}"
                );
                if let Some(port_name) = port.get("name").and_then(Value::as_str) {
                    validate_kubernetes_name("Service port name", port_name)?;
                    anyhow::ensure!(
                        port_names.insert(port_name.to_owned(), number).is_none(),
                        "Service {namespace}/{name} repeats port name {port_name}"
                    );
                }
            }
        }
        catalog
            .ports
            .insert((namespace.to_owned(), name.to_owned()), ports);
        catalog.service_types.insert(
            (namespace.to_owned(), name.to_owned()),
            service_type.to_owned(),
        );
        catalog
            .port_names
            .insert((namespace.to_owned(), name.to_owned()), port_names);
    }
    Ok(catalog)
}

/// 业务作用：把 InferencePool、Ready Pod 与 EPP Service 的同轮事实编译为静态池目录和
/// 标准 External Processing 计划，避免选择器、端口与扩展引用跨 LIST 版本拼接。
///
/// 参数说明：`pools_value`、`pods_value` 和 `service_catalog` 来自同一轮 relist；`cfg`
/// 提供对象与 endpoint 预算。
///
/// 返回：全部池合同合法时返回只读目录；未知字段、非法选择器、ExternalName EPP、坏端口
/// 或重复身份拒绝整轮候选并保留已发布版本。
fn build_inference_pool_catalog(
    pools_value: &Value,
    pods_value: &Value,
    service_catalog: &ServiceCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<InferencePoolCatalog> {
    let pods = resource_items(pods_value, cfg.max_objects, "Pod")?;
    let mut catalog = InferencePoolCatalog::default();
    for pool in resource_items(pools_value, cfg.max_objects, "InferencePool")? {
        let (namespace, name) = object_identity(pool, "InferencePool")?;
        let spec = pool.get("spec").context("InferencePool missing spec")?;
        ensure_json_object_fields(
            spec,
            "InferencePool spec",
            &[
                "selector",
                "targetPorts",
                "appProtocol",
                "endpointPickerRef",
            ],
        )?;
        let selector = spec
            .get("selector")
            .context("InferencePool missing spec.selector")?;
        ensure_json_object_fields(selector, "InferencePool selector", &["matchLabels"])?;
        let match_labels = selector
            .get("matchLabels")
            .and_then(Value::as_object)
            .context("InferencePool selector.matchLabels must be an object")?;
        anyhow::ensure!(
            (1..=64).contains(&match_labels.len()),
            "InferencePool {namespace}/{name} selector requires 1..=64 labels"
        );
        let match_labels = match_labels
            .iter()
            .map(|(key, value)| {
                anyhow::ensure!(
                    !key.is_empty() && key.len() <= 253,
                    "InferencePool {namespace}/{name} selector key has invalid length"
                );
                let value = value
                    .as_str()
                    .context("InferencePool selector.matchLabels values must be strings")?;
                anyhow::ensure!(
                    value.len() <= 63,
                    "InferencePool {namespace}/{name} selector value is too long"
                );
                Ok((key.clone(), value.to_owned()))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let target_ports = spec
            .get("targetPorts")
            .and_then(Value::as_array)
            .context("InferencePool targetPorts must be an array")?;
        anyhow::ensure!(
            (1..=8).contains(&target_ports.len()),
            "InferencePool {namespace}/{name} targetPorts requires 1..=8 entries"
        );
        let mut ports = BTreeSet::new();
        for port in target_ports {
            ensure_json_object_fields(port, "InferencePool targetPort", &["number"])?;
            let number = port
                .get("number")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value > 0)
                .context("InferencePool targetPort.number must be within 1..=65535")?;
            anyhow::ensure!(
                ports.insert(number),
                "InferencePool {namespace}/{name} repeats target port {number}"
            );
        }
        let app_protocol = spec
            .get("appProtocol")
            .and_then(Value::as_str)
            .unwrap_or("http");
        let protocol = match app_protocol {
            "http" => None,
            "kubernetes.io/h2c" => Some("h2c"),
            other => bail!("InferencePool {namespace}/{name} appProtocol `{other}` is unsupported"),
        };
        let endpoint_picker = spec
            .get("endpointPickerRef")
            .context("InferencePool missing endpointPickerRef")?;
        ensure_json_object_fields(
            endpoint_picker,
            "InferencePool endpointPickerRef",
            &["group", "kind", "name", "port", "failureMode"],
        )?;
        anyhow::ensure!(
            endpoint_picker
                .get("group")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty(),
            "InferencePool {namespace}/{name} EPP group must be core"
        );
        anyhow::ensure!(
            endpoint_picker
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Service")
                == "Service",
            "InferencePool {namespace}/{name} EPP kind must be Service"
        );
        let epp_name = endpoint_picker
            .get("name")
            .and_then(Value::as_str)
            .context("InferencePool endpointPickerRef missing name")?;
        validate_kubernetes_name("InferencePool EPP Service", epp_name)?;
        let epp_port_value = endpoint_picker
            .get("port")
            .context("InferencePool Service endpointPickerRef requires port")?;
        ensure_json_object_fields(epp_port_value, "InferencePool EPP port", &["number"])?;
        let epp_port = epp_port_value
            .get("number")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .context("InferencePool EPP port.number must be within 1..=65535")?;
        let service_key = (namespace.to_owned(), epp_name.to_owned());
        let epp_resolved = service_catalog
            .ports
            .get(&service_key)
            .is_some_and(|ports| ports.contains_key(&(epp_port, "TCP".to_owned())))
            && service_catalog
                .service_types
                .get(&service_key)
                .is_some_and(|service_type| service_type != "ExternalName");
        let fail_open = match endpoint_picker
            .get("failureMode")
            .and_then(Value::as_str)
            .unwrap_or("FailClose")
        {
            "FailOpen" => true,
            "FailClose" => false,
            other => {
                bail!("InferencePool {namespace}/{name} EPP failureMode `{other}` is unsupported")
            }
        };
        if !epp_resolved {
            let key = (namespace.to_owned(), name.to_owned());
            anyhow::ensure!(
                catalog
                    .pools
                    .insert(
                        key,
                        InferencePoolBackend {
                            resolved: false,
                            pool_service: Value::Null,
                            pool_logical: String::new(),
                            epp_service: Value::Null,
                            epp_logical: String::new(),
                            fail_open,
                        },
                    )
                    .is_none(),
                "InferencePool {namespace}/{name} is duplicated"
            );
            continue;
        }

        let mut instances = Vec::new();
        for pod in pods {
            let (pod_namespace, _) = object_identity(pod, "Pod")?;
            if pod_namespace != namespace
                || pod
                    .pointer("/metadata/deletionTimestamp")
                    .is_some_and(|value| !value.is_null())
                || pod.pointer("/status/phase").and_then(Value::as_str) != Some("Running")
            {
                continue;
            }
            let pod_labels = pod.pointer("/metadata/labels").and_then(Value::as_object);
            if !match_labels.iter().all(|(key, expected)| {
                pod_labels
                    .and_then(|labels| labels.get(key))
                    .and_then(Value::as_str)
                    == Some(expected.as_str())
            }) {
                continue;
            }
            let ready = pod
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition.get("type").and_then(Value::as_str) == Some("Ready")
                            && condition.get("status").and_then(Value::as_str) == Some("True")
                    })
                });
            if !ready {
                continue;
            }
            let pod_ip = pod
                .pointer("/status/podIP")
                .and_then(Value::as_str)
                .context("Ready InferencePool Pod missing status.podIP")?
                .parse::<std::net::IpAddr>()
                .context("Ready InferencePool Pod has invalid status.podIP")?;
            for port in &ports {
                instances.push(json!({
                    "uri": format!("http://{}", std::net::SocketAddr::new(pod_ip, *port))
                }));
                anyhow::ensure!(
                    instances.len() <= cfg.max_objects,
                    "InferencePool {namespace}/{name} expands beyond max_objects endpoints"
                );
            }
        }
        instances.sort_by(|left, right| {
            left.get("uri")
                .and_then(Value::as_str)
                .cmp(&right.get("uri").and_then(Value::as_str))
        });
        let pool_logical = stable_id("k8s-inference-pool", &[namespace, name, app_protocol]);
        let mut pool_service = json!({"instances": instances});
        if let Some(protocol) = protocol {
            pool_service["protocol"] = json!(protocol);
        }
        let mut generated_epp = BTreeMap::new();
        let epp_logical = insert_generated_service_with_protocol(
            &mut generated_epp,
            namespace,
            epp_name,
            &BackendPort::Number(epp_port),
            "https",
            Some("h2"),
        )?;
        let mut epp_service = generated_epp
            .remove(&epp_logical)
            .context("generated EPP service disappeared")?;
        // EPP 的 HTTPS 端点使用启动期动态自签证书；同 namespace 的 core Service 与发现实例
        // 已限定目标权威，因此这里只关闭证书身份认证，仍使用 TLS/H2 保护传输和握手完整性。
        epp_service["tls"] = json!({"insecure_skip_verify": true});
        let key = (namespace.to_owned(), name.to_owned());
        anyhow::ensure!(
            catalog
                .pools
                .insert(
                    key,
                    InferencePoolBackend {
                        resolved: true,
                        pool_service,
                        pool_logical,
                        epp_service,
                        epp_logical,
                        fail_open,
                    },
                )
                .is_none(),
            "InferencePool {namespace}/{name} is duplicated"
        );
    }
    Ok(catalog)
}

/// 业务作用：冻结 MCS ServiceImport 的端口与协议目录，使跨集群后端和本地 Service
/// 经过同一引用、权重及 transport 校验链。
///
/// 参数说明：`value` 是 multicluster.x-k8s.io/v1alpha1 ServiceImport LIST；
/// `max_objects` 是对象硬上限。
///
/// 返回：返回可路由的 ClusterSetIP ServiceImport 目录；Headless、坏端口或重复身份
/// 使本轮候选失败闭合。
fn build_service_import_catalog(
    value: &Value,
    max_objects: usize,
) -> anyhow::Result<ServiceImportCatalog> {
    let mut catalog = ServiceImportCatalog::default();
    for service in resource_items(value, max_objects, "ServiceImport")? {
        ensure_json_object_fields(
            service,
            "ServiceImport",
            &["apiVersion", "kind", "metadata", "spec", "status"],
        )?;
        anyhow::ensure!(
            service.get("apiVersion").and_then(Value::as_str)
                == Some("multicluster.x-k8s.io/v1alpha1")
                && service.get("kind").and_then(Value::as_str) == Some("ServiceImport"),
            "ServiceImport resource identity is unsupported"
        );
        let (namespace, name) = object_identity(service, "ServiceImport")?;
        let spec = service.get("spec").context("ServiceImport missing spec")?;
        ensure_json_object_fields(
            spec,
            "ServiceImport spec",
            &[
                "ips",
                "ports",
                "sessionAffinity",
                "sessionAffinityConfig",
                "type",
            ],
        )?;
        anyhow::ensure!(
            service.pointer("/spec/type").and_then(Value::as_str) == Some("ClusterSetIP"),
            "ServiceImport {namespace}/{name} must use type ClusterSetIP"
        );
        anyhow::ensure!(
            service
                .pointer("/spec/sessionAffinity")
                .and_then(Value::as_str)
                .is_none_or(|value| value == "None")
                && service.pointer("/spec/sessionAffinityConfig").is_none(),
            "ServiceImport {namespace}/{name} sessionAffinity is unsupported"
        );
        let mut ports = BTreeMap::new();
        let mut port_names = BTreeMap::new();
        for port in service
            .pointer("/spec/ports")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            ensure_json_object_fields(
                &port,
                "ServiceImport port",
                &["appProtocol", "name", "port", "protocol"],
            )?;
            let number = port
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0)
                .context("ServiceImport port must be a non-zero number")?;
            let protocol = port
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("TCP")
                .to_ascii_uppercase();
            anyhow::ensure!(
                matches!(protocol.as_str(), "TCP" | "UDP" | "SCTP"),
                "ServiceImport {namespace}/{name} port {number} has invalid protocol"
            );
            let app_protocol = port
                .get("appProtocol")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(app_protocol) = &app_protocol {
                anyhow::ensure!(
                    !app_protocol.is_empty() && app_protocol.len() <= 63,
                    "ServiceImport {namespace}/{name} port {number} appProtocol has invalid length"
                );
            }
            anyhow::ensure!(
                ports
                    .insert((number, protocol.clone()), app_protocol)
                    .is_none(),
                "ServiceImport {namespace}/{name} repeats {protocol} port {number}"
            );
            if let Some(port_name) = port.get("name").and_then(Value::as_str) {
                validate_kubernetes_name("ServiceImport port name", port_name)?;
                anyhow::ensure!(
                    port_names.insert(port_name.to_owned(), number).is_none(),
                    "ServiceImport {namespace}/{name} repeats port name {port_name}"
                );
            }
        }
        anyhow::ensure!(
            !ports.is_empty(),
            "ServiceImport {namespace}/{name} has no usable ports"
        );
        catalog
            .ports
            .insert((namespace.to_owned(), name.to_owned()), ports);
        catalog
            .port_names
            .insert((namespace.to_owned(), name.to_owned()), port_names);
    }
    Ok(catalog)
}

/// 业务作用：把 HTTPRoute/GRPCRoute 的 Service 与 ServiceImport parent 物化为独立
/// Mesh listener 权威，只有透明流量捕获已就绪时才开放业务路由。
///
/// 参数说明：Route 与 backend 目录来自同轮 LIST；`catalog` 接收合成 listener；
/// `cfg` 固定受保护 socket 和源 namespace header。
///
/// 返回：所有 mesh parent、sectionName 与 port 可解析且不会占用 Gateway socket 时成功；
/// 未就绪时只记录 parent 存在性供 status 拒绝，不生成可达 listener。
#[allow(clippy::too_many_arguments)]
fn extend_gateway_catalog_with_mesh_parents(
    catalog: &mut GatewayCatalog,
    http_routes: &Value,
    grpc_routes: &Value,
    services: &ServiceCatalog,
    service_imports: &ServiceImportCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<()> {
    let mesh_ip = cfg
        .gateway_mesh_bind_address
        .parse::<std::net::IpAddr>()
        .context("parse Gateway mesh bind address")?;
    let mesh_socket = std::net::SocketAddr::new(mesh_ip, cfg.gateway_mesh_port);
    anyhow::ensure!(
        !catalog.listeners.iter().any(|listener| {
            listener.bind_address == cfg.gateway_mesh_bind_address
                && listener.port == cfg.gateway_mesh_port
        }),
        "Gateway mesh listener conflicts with a Gateway API listener socket"
    );
    let mut synthesized = BTreeSet::new();
    for (route_kind, value) in [("HTTPRoute", http_routes), ("GRPCRoute", grpc_routes)] {
        for route in resource_items(value, cfg.max_objects, route_kind)? {
            let (route_namespace, _) = object_identity(route, route_kind)?;
            if !namespace_allowed(cfg, route_namespace)
                || route.pointer("/metadata/deletionTimestamp").is_some()
            {
                continue;
            }
            let parents = route
                .pointer("/spec/parentRefs")
                .and_then(Value::as_array)
                .context("Gateway Route missing spec.parentRefs")?;
            for parent in parents {
                let group = parent
                    .get("group")
                    .and_then(Value::as_str)
                    .unwrap_or("gateway.networking.k8s.io");
                let kind = parent
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("Gateway");
                let service_import = group == "multicluster.x-k8s.io" && kind == "ServiceImport";
                if !(group.is_empty() && kind == "Service") && !service_import {
                    continue;
                }
                let name = parent
                    .get("name")
                    .and_then(Value::as_str)
                    .context("Mesh Route parentRef missing name")?;
                let namespace = parent
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(route_namespace);
                validate_kubernetes_name("Mesh parent namespace", namespace)?;
                validate_kubernetes_name("Mesh parent name", name)?;
                let (ports, port_names) = if service_import {
                    (&service_imports.ports, &service_imports.port_names)
                } else {
                    (&services.ports, &services.port_names)
                };
                let identity = (namespace.to_owned(), name.to_owned());
                let available_ports = ports.get(&identity).with_context(|| {
                    format!("Mesh parent {kind} {namespace}/{name} does not exist")
                })?;
                let section = parent.get("sectionName").and_then(Value::as_str);
                let declared_port = parent
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok());
                let named_port = section
                    .map(|section| {
                        validate_kubernetes_name("Mesh parent sectionName", section)?;
                        port_names
                            .get(&identity)
                            .and_then(|names| names.get(section))
                            .copied()
                            .with_context(|| {
                                format!(
                                    "Mesh parent {kind} {namespace}/{name} has no port named {section}"
                                )
                            })
                    })
                    .transpose()?;
                if let (Some(declared), Some(named)) = (declared_port, named_port) {
                    anyhow::ensure!(
                        declared == named,
                        "Mesh parent sectionName and port select different Service ports"
                    );
                }
                let parent_port = declared_port.or(named_port).unwrap_or(0);
                if parent_port != 0 {
                    anyhow::ensure!(
                        available_ports.contains_key(&(parent_port, "TCP".to_owned())),
                        "Mesh parent {kind} {namespace}/{name} has no TCP port {parent_port}"
                    );
                }
                catalog.mesh_parents.insert((
                    group.to_owned(),
                    kind.to_owned(),
                    namespace.to_owned(),
                    name.to_owned(),
                ));
                if !cfg.gateway_mesh_interception_ready {
                    continue;
                }
                let hostname = if service_import {
                    format!("{name}.{namespace}.svc.clusterset.local")
                } else {
                    format!("{name}.{namespace}.svc.cluster.local")
                };
                let synthesis_key = (
                    group.to_owned(),
                    kind.to_owned(),
                    namespace.to_owned(),
                    name.to_owned(),
                    section.unwrap_or("").to_owned(),
                    parent_port,
                    hostname.clone(),
                );
                if !synthesized.insert(synthesis_key) {
                    continue;
                }
                catalog.listeners.push(GatewayListener {
                    gateway_namespace: namespace.to_owned(),
                    gateway_name: name.to_owned(),
                    parent_group: group.to_owned(),
                    parent_kind: kind.to_owned(),
                    parent_namespace: namespace.to_owned(),
                    parent_name: name.to_owned(),
                    section_name: section.unwrap_or("").to_owned(),
                    protocol: "HTTP".to_owned(),
                    parent_port,
                    port: mesh_socket.port(),
                    bind_address: mesh_socket.ip().to_string(),
                    hostname: Some(hostname),
                    tls_mode: None,
                    allowed_namespaces: AllowedNamespaces::All,
                    allowed_kinds: ["HTTPRoute".to_owned(), "GRPCRoute".to_owned()]
                        .into_iter()
                        .collect(),
                });
            }
        }
    }
    Ok(())
}

/// 业务作用：把 Gateway API BackendTrafficPolicy 的重试与会话字段编译为 Naway
/// 原生服务策略，确保所有 Route 类型共享同一份执行结果。
///
/// 参数说明：`policy` 是已通过对象身份门禁的策略对象；`default_session_name` 是
/// 未显式命名时按 policy 身份生成的隔离名称。
///
/// 返回：字段组合可由原生策略精确表达时返回配置；未知或越界值拒绝当前候选。
fn compile_backend_traffic_policy_config(
    policy: &Value,
    default_session_name: &str,
) -> anyhow::Result<BackendTrafficPolicyConfig> {
    ensure_json_object_fields(
        policy,
        "XBackendTrafficPolicy",
        &["apiVersion", "kind", "metadata", "spec", "status"],
    )?;
    let spec = policy
        .get("spec")
        .context("XBackendTrafficPolicy missing spec")?;
    ensure_json_object_fields(
        spec,
        "XBackendTrafficPolicy spec",
        &["retryConstraint", "sessionPersistence", "targetRefs"],
    )?;
    let retry_budget = policy
        .pointer("/spec/retryConstraint")
        .map(|constraint| -> anyhow::Result<Value> {
            ensure_json_object_fields(constraint, "retryConstraint", &["budget", "minRetryRate"])?;
            if let Some(budget) = constraint.get("budget") {
                ensure_json_object_fields(
                    budget,
                    "retryConstraint budget",
                    &["interval", "percent"],
                )?;
            }
            if let Some(minimum) = constraint.get("minRetryRate") {
                ensure_json_object_fields(
                    minimum,
                    "retryConstraint minRetryRate",
                    &["count", "interval"],
                )?;
            }
            let percent = constraint
                .pointer("/budget/percent")
                .and_then(Value::as_u64)
                .unwrap_or(20);
            anyhow::ensure!(percent <= 100, "retry budget percent exceeds 100");
            let interval_ms = constraint
                .pointer("/budget/interval")
                .and_then(Value::as_str)
                .unwrap_or("10s");
            let interval_ms = parse_gateway_duration_ms(interval_ms)?;
            anyhow::ensure!(
                (1_000..=3_600_000).contains(&interval_ms),
                "retry budget interval must be within 1s..=1h"
            );
            let min_count = constraint
                .pointer("/minRetryRate/count")
                .and_then(Value::as_u64)
                .unwrap_or(10);
            anyhow::ensure!(
                (1..=1_000_000).contains(&min_count),
                "minRetryRate count is out of range"
            );
            let min_interval_ms = constraint
                .pointer("/minRetryRate/interval")
                .and_then(Value::as_str)
                .unwrap_or("1s");
            let min_interval_ms = parse_gateway_duration_ms(min_interval_ms)?;
            anyhow::ensure!(
                (1..=3_600_000).contains(&min_interval_ms),
                "minRetryRate interval must be within 1ms..=1h"
            );
            let minimum = u128::from(min_count)
                .saturating_mul(u128::from(interval_ms))
                .div_ceil(u128::from(min_interval_ms));
            let minimum = u64::try_from(minimum)
                .context("minRetryRate exceeds local retry budget capacity")?;
            anyhow::ensure!(
                minimum <= 1_000_000,
                "minRetryRate exceeds one million retries per budget interval"
            );
            Ok(json!({
                "enabled": true,
                "budget_percent": percent,
                "min_retry_concurrency": 1,
                "min_retries_per_window": minimum.max(1),
                "window_ms": interval_ms
            }))
        })
        .transpose()?;

    let session_affinity = policy
        .pointer("/spec/sessionPersistence")
        .map(|session| compile_session_persistence_config(session, default_session_name))
        .transpose()?;
    anyhow::ensure!(
        retry_budget.is_some() || session_affinity.is_some(),
        "BackendTrafficPolicy must configure retryConstraint or sessionPersistence"
    );
    Ok(BackendTrafficPolicyConfig {
        retry_budget,
        session_affinity,
    })
}

/// 业务作用：为实验 API 的对象字段执行白名单校验，防止 CRD 转换或宽松 mock 留下的
/// 未知字段被 controller 静默忽略后产生近似配置。
///
/// 参数说明：`value` 是待校验对象；`context` 标识错误位置；`allowed` 是当前固定协议版本
/// 明确接受的字段集合。
///
/// 返回：对象形态且所有字段均在白名单时返回成功；其它输入返回错误，由调用方发布拒绝状态。
fn ensure_json_object_fields(value: &Value, context: &str, allowed: &[&str]) -> anyhow::Result<()> {
    let fields = value
        .as_object()
        .with_context(|| format!("{context} must be an object"))?;
    for field in fields.keys() {
        anyhow::ensure!(
            allowed.contains(&field.as_str()),
            "{context} contains unknown field `{field}`"
        );
    }
    Ok(())
}

/// 业务作用：把 Gateway API `SessionPersistence` 精确编译为原生无状态会话策略，
/// 使 backend policy 与 Route rule 共用同一套期限和 cookie 安全语义。
///
/// 参数说明：`session` 是标准字段对象；`default_name` 是按声明作用域生成的稳定名称，
/// 防止未指定 `sessionName` 时不同策略共享同一载体。
///
/// 返回：字段结构、期限与载体组合合法时返回原生配置；未知字段、零期限或非法组合
/// 返回错误，调用方不得发布近似语义。
fn compile_session_persistence_config(
    session: &Value,
    default_name: &str,
) -> anyhow::Result<Value> {
    let fields = session
        .as_object()
        .context("sessionPersistence must be an object")?;
    for field in fields.keys() {
        anyhow::ensure!(
            matches!(
                field.as_str(),
                "absoluteTimeout" | "cookieConfig" | "idleTimeout" | "sessionName" | "type"
            ),
            "sessionPersistence contains unknown field `{field}`"
        );
    }
    let mode = session
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("Cookie");
    anyhow::ensure!(
        matches!(mode, "Cookie" | "Header"),
        "sessionPersistence type must be Cookie or Header"
    );
    let name = session
        .get("sessionName")
        .and_then(Value::as_str)
        .unwrap_or(default_name);
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "sessionPersistence sessionName is invalid"
    );
    let absolute_ms = session
        .get("absoluteTimeout")
        .map(|value| {
            value
                .as_str()
                .context("sessionPersistence absoluteTimeout must be a duration string")
                .and_then(parse_gateway_duration_ms)
        })
        .transpose()?;
    let idle_ms = session
        .get("idleTimeout")
        .map(|value| {
            value
                .as_str()
                .context("sessionPersistence idleTimeout must be a duration string")
                .and_then(parse_gateway_duration_ms)
        })
        .transpose()?;
    anyhow::ensure!(
        absolute_ms.is_none_or(|value| value > 0) && idle_ms.is_none_or(|value| value > 0),
        "sessionPersistence timeouts must be greater than zero"
    );
    let cookie_config = session.get("cookieConfig");
    if let Some(cookie_config) = cookie_config {
        let cookie_fields = cookie_config
            .as_object()
            .context("sessionPersistence cookieConfig must be an object")?;
        anyhow::ensure!(
            cookie_fields.keys().all(|field| field == "lifetimeType"),
            "sessionPersistence cookieConfig contains an unknown field"
        );
    }
    let lifetime = session
        .pointer("/cookieConfig/lifetimeType")
        .and_then(Value::as_str)
        .unwrap_or("Session");
    anyhow::ensure!(
        matches!(lifetime, "Session" | "Permanent"),
        "sessionPersistence cookie lifetimeType is invalid"
    );
    anyhow::ensure!(
        mode == "Cookie" || cookie_config.is_none(),
        "sessionPersistence cookieConfig requires Cookie type"
    );
    anyhow::ensure!(
        lifetime != "Permanent" || absolute_ms.is_some(),
        "Permanent sessionPersistence requires absoluteTimeout"
    );
    let absolute_timeout_seconds = absolute_ms.map(|value| value.div_ceil(1_000)).unwrap_or(0);
    let idle_timeout_seconds = idle_ms.map(|value| value.div_ceil(1_000)).unwrap_or(0);
    anyhow::ensure!(
        absolute_timeout_seconds <= 31_536_000 && idle_timeout_seconds <= 31_536_000,
        "sessionPersistence timeout exceeds 365 days"
    );
    Ok(json!({
        "mode": mode.to_ascii_lowercase(),
        "name": name,
        "ttl_seconds": 0,
        "absolute_timeout_seconds": absolute_timeout_seconds,
        "idle_timeout_seconds": idle_timeout_seconds,
        "permanent_cookie": mode == "Cookie" && lifetime == "Permanent",
        "omit_path": true,
        "same_site": "Strict",
        "secure": true,
        "http_only": true
    }))
}

/// 业务作用：让 HTTPRoute/GRPCRoute rule 的内联会话策略覆盖 backend policy，且通过
/// 独立逻辑服务隔离作用域，避免同一 backend 被其它 Route 意外继承。
///
/// 参数说明：`rule` 与对象身份生成稳定作用域；`cookie_path` 是该 HTTP match 的规范化
/// 路径；`backends`/`services` 是尚未合并到全局候选的本 rule 子结果。
///
/// 返回：未配置时保持原结果；单 backend 配置成功时替换为隔离服务；多 backend 当前
/// 无法在路由选择前保证跨服务粘滞，因而明确拒绝而不发布近似行为。
#[allow(clippy::too_many_arguments)]
fn apply_inline_session_persistence(
    rule: &Value,
    route_namespace: &str,
    route_name: &str,
    route_kind: &str,
    rule_index: usize,
    cookie_path: &str,
    backends: &mut [BackendTarget],
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let Some(session) = rule.get("sessionPersistence") else {
        return Ok(());
    };
    anyhow::ensure!(
        backends.len() == 1,
        "{route_kind} {route_namespace}/{route_name} inline sessionPersistence with multiple backendRefs is unsupported"
    );
    let default_name = stable_id(
        "naway-session",
        &[
            route_kind,
            route_namespace,
            route_name,
            &rule_index.to_string(),
        ],
    );
    let mut session_affinity = compile_session_persistence_config(session, default_name.as_str())?;
    if session_affinity.get("mode").and_then(Value::as_str) == Some("cookie") {
        session_affinity["omit_path"] = Value::Bool(false);
        session_affinity["path"] = Value::String(cookie_path.to_owned());
    }
    let backend = backends
        .first_mut()
        .expect("single backend was checked above");
    let mut service = services
        .get(backend.logical.as_str())
        .cloned()
        .context("inline sessionPersistence backend service disappeared")?;
    service["session_affinity"] = session_affinity;
    let scoped_logical = stable_id(
        "k8s-inline-session",
        &[
            route_kind,
            route_namespace,
            route_name,
            &rule_index.to_string(),
            backend.logical.as_str(),
        ],
    );
    if let Some(existing) = services.get(scoped_logical.as_str()) {
        anyhow::ensure!(
            existing == &service,
            "inline sessionPersistence generated conflicting service definitions"
        );
    } else {
        services.insert(scoped_logical.clone(), service);
    }
    backend.logical = scoped_logical;
    Ok(())
}

/// 业务作用：冻结 BackendTrafficPolicy 的目标、冲突赢家和原生服务策略，使数据面应用
/// 与 status 条件来自同一轮确定性裁决。
///
/// 参数说明：策略、Service 与 ServiceImport 目录来自同轮 LIST；`cfg` 固定接管范围。
///
/// 返回：返回按目标索引的策略目录；对象结构异常时拒绝本轮，目标缺失或冲突则记录条件。
fn build_backend_traffic_catalog(
    policies_value: &Value,
    services: &ServiceCatalog,
    service_imports: &ServiceImportCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<BackendTrafficCatalog> {
    let mut objects = resource_items(policies_value, cfg.max_objects, "XBackendTrafficPolicy")?
        .iter()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object_order_key(object));
    let mut catalog = BackendTrafficCatalog::default();
    for policy in objects {
        anyhow::ensure!(
            policy.get("apiVersion").and_then(Value::as_str)
                == Some("gateway.networking.x-k8s.io/v1alpha1")
                && policy.get("kind").and_then(Value::as_str) == Some("XBackendTrafficPolicy"),
            "BackendTrafficPolicy resource identity is unsupported"
        );
        let (namespace, policy_name) = object_identity(policy, "XBackendTrafficPolicy")?;
        if !namespace_allowed(cfg, namespace)
            || policy.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let default_session_name = stable_id("naway-session", &[namespace, policy_name]);
        let (config, config_error) =
            match compile_backend_traffic_policy_config(policy, default_session_name.as_str()) {
                Ok(config) => (Some(config), None),
                Err(error) => (None, Some(bounded_status_message(error.to_string()))),
            };
        let target_refs = policy
            .pointer("/spec/targetRefs")
            .and_then(Value::as_array)
            .context("BackendTrafficPolicy missing spec.targetRefs")?;
        anyhow::ensure!(
            (1..=16).contains(&target_refs.len()),
            "BackendTrafficPolicy targetRefs must contain 1..=16 entries"
        );
        let policy_index = catalog.policies.len();
        let mut targets = Vec::new();
        let mut unique = BTreeSet::new();
        for target in target_refs {
            ensure_json_object_fields(
                target,
                "BackendTrafficPolicy targetRef",
                &["group", "kind", "name"],
            )?;
            let group = target
                .get("group")
                .and_then(Value::as_str)
                .context("BackendTrafficPolicy targetRef missing group")?;
            let kind = target
                .get("kind")
                .and_then(Value::as_str)
                .context("BackendTrafficPolicy targetRef missing kind")?;
            let name = target
                .get("name")
                .and_then(Value::as_str)
                .context("BackendTrafficPolicy targetRef missing name")?;
            validate_kubernetes_name("BackendTrafficPolicy target", name)?;
            let key = BackendTrafficTargetKey {
                group: group.to_owned(),
                kind: kind.to_owned(),
                namespace: namespace.to_owned(),
                name: name.to_owned(),
            };
            anyhow::ensure!(
                unique.insert(key.clone()),
                "BackendTrafficPolicy repeats a targetRef"
            );
            let supported = (group.is_empty() && kind == "Service")
                || (group == "multicluster.x-k8s.io" && kind == "ServiceImport");
            let exists = if group.is_empty() && kind == "Service" {
                services
                    .ports
                    .contains_key(&(namespace.to_owned(), name.to_owned()))
            } else if group == "multicluster.x-k8s.io" && kind == "ServiceImport" {
                service_imports
                    .ports
                    .contains_key(&(namespace.to_owned(), name.to_owned()))
            } else {
                false
            };
            let conflict =
                supported && exists && config.is_some() && catalog.selected.contains_key(&key);
            let (accepted, resolved_refs, accepted_reason, resolved_reason, message) = if !supported
            {
                (
                    false,
                    false,
                    "InvalidTargetRef",
                    "InvalidKind",
                    "targetRef kind is not supported".to_owned(),
                )
            } else if !exists {
                (
                    false,
                    false,
                    "InvalidTargetRef",
                    "BackendNotFound",
                    "targetRef backend does not exist".to_owned(),
                )
            } else if let Some(message) = config_error.as_ref() {
                (
                    false,
                    true,
                    "UnsupportedValue",
                    "ResolvedRefs",
                    message.clone(),
                )
            } else if conflict {
                (
                    false,
                    true,
                    "Conflicted",
                    "ResolvedRefs",
                    "an older policy already owns this backend".to_owned(),
                )
            } else {
                // 只有目标和策略体都有效时才能取得 backend 权威；无效策略只发布拒绝状态，
                // 不能遮挡同一目标后续仍可生效的合法策略。
                catalog.selected.insert(key.clone(), policy_index);
                (
                    true,
                    true,
                    "Accepted",
                    "ResolvedRefs",
                    "policy is accepted for this backend".to_owned(),
                )
            };
            targets.push(BackendTrafficTargetDecision {
                key,
                accepted,
                resolved_refs,
                accepted_reason,
                resolved_reason,
                message,
            });
        }
        catalog.policies.push(BackendTrafficPolicyDecision {
            object: policy.clone(),
            targets,
            config,
        });
    }
    Ok(catalog)
}

/// 业务作用：把 BackendTLSPolicy 的目标、信任材料和冲突规则冻结为同一轮只读裁决，
/// 使状态发布与数据面选择使用完全一致的赢家。
///
/// 参数说明：`policies_value`、`config_maps` 与 `services` 来自同轮发现；`cfg` 固定接管范围和预算。
///
/// 返回：返回按目标索引的策略目录；对象规模或受管字段结构异常时失败，引用失效则记录条件而非污染 LKG。
fn build_backend_tls_catalog(
    policies_value: &Value,
    config_maps: &ConfigMapCatalog,
    services: &ServiceCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<BackendTlsCatalog> {
    let mut objects = resource_items(policies_value, cfg.max_objects, "BackendTLSPolicy")?
        .iter()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object_order_key(object));
    let mut catalog = BackendTlsCatalog::default();
    for policy in objects {
        let (namespace, _) = object_identity(policy, "BackendTLSPolicy")?;
        if !namespace_allowed(cfg, namespace)
            || policy.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let target_refs = policy
            .pointer("/spec/targetRefs")
            .and_then(Value::as_array)
            .context("BackendTLSPolicy missing spec.targetRefs")?;
        anyhow::ensure!(
            !target_refs.is_empty() && target_refs.len() <= 16,
            "BackendTLSPolicy targetRefs must contain 1..=16 entries"
        );
        let mut targets = Vec::new();
        let mut target_valid = true;
        for target in target_refs {
            let group = target.get("group").and_then(Value::as_str).unwrap_or("");
            let kind = target
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Service");
            let service = target
                .get("name")
                .and_then(Value::as_str)
                .context("BackendTLSPolicy targetRef missing name")?;
            validate_kubernetes_name("BackendTLSPolicy target Service", service)?;
            let section_name = target
                .get("sectionName")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if group.is_empty()
                && kind == "Service"
                && services
                    .ports
                    .contains_key(&(namespace.to_owned(), service.to_owned()))
                && section_name.as_ref().is_none_or(|section| {
                    services
                        .port_names
                        .get(&(namespace.to_owned(), service.to_owned()))
                        .is_some_and(|names| names.contains_key(section))
                })
            {
                targets.push(BackendTlsTargetKey {
                    namespace: namespace.to_owned(),
                    service: service.to_owned(),
                    section_name,
                });
            } else {
                target_valid = false;
            }
        }
        targets.sort();
        targets.dedup();

        let validation = policy
            .pointer("/spec/validation")
            .context("BackendTLSPolicy missing spec.validation")?;
        let server_name = validation
            .get("hostname")
            .and_then(Value::as_str)
            .map(normalize_hostname)
            .transpose()?;
        let subject_alt_names = parse_backend_tls_subject_alt_names(validation)?;
        let ca_refs = validation
            .get("caCertificateRefs")
            .and_then(Value::as_array);
        let system_roots = validation
            .get("wellKnownCACertificates")
            .and_then(Value::as_str);
        let mut accepted = target_valid && !targets.is_empty();
        let mut resolved_refs = true;
        let mut accepted_reason = if accepted {
            "Accepted"
        } else {
            "TargetNotFound"
        };
        let mut resolved_reason = "ResolvedRefs";
        let mut message = if accepted {
            "BackendTLSPolicy is accepted"
        } else {
            "BackendTLSPolicy target Service or section does not exist"
        };
        let mut ca_pem = None;
        match (ca_refs, system_roots) {
            (Some(refs), None) if refs.len() == 1 => {
                let reference = &refs[0];
                let group = reference.get("group").and_then(Value::as_str).unwrap_or("");
                let kind = reference
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("ConfigMap");
                if !group.is_empty() || kind != "ConfigMap" {
                    accepted = false;
                    resolved_refs = false;
                    accepted_reason = "NoValidCACertificate";
                    resolved_reason = "InvalidKind";
                    message = "BackendTLSPolicy CA reference kind is unsupported";
                } else {
                    let name = reference
                        .get("name")
                        .and_then(Value::as_str)
                        .context("BackendTLSPolicy caCertificateRef missing name")?;
                    validate_kubernetes_name("BackendTLSPolicy ConfigMap", name)?;
                    let pem = config_maps
                        .objects
                        .get(&(namespace.to_owned(), name.to_owned()))
                        .and_then(|object| object.pointer("/data/ca.crt"))
                        .and_then(Value::as_str);
                    if pem.is_some_and(valid_backend_tls_ca_pem) {
                        ca_pem = pem.map(str::to_owned);
                    } else {
                        accepted = false;
                        resolved_refs = false;
                        accepted_reason = "NoValidCACertificate";
                        resolved_reason = "InvalidCACertificateRef";
                        message = "BackendTLSPolicy CA ConfigMap is missing or invalid";
                    }
                }
            }
            (None, Some("System")) => {}
            _ => {
                accepted = false;
                resolved_refs = false;
                accepted_reason = "NoValidCACertificate";
                resolved_reason = "InvalidCACertificateRef";
                message = "BackendTLSPolicy must select exactly one supported CA source";
            }
        }

        // 相同 target+section 只能由最早对象取得权威；整 Service 与具体 section 属于不同作用域。
        let conflicted = targets
            .iter()
            .any(|target| catalog.selected.contains_key(target));
        if conflicted {
            accepted = false;
            accepted_reason = "Conflicted";
            message = "BackendTLSPolicy conflicts with an older policy for the same target";
        }
        let policy_index = catalog.policies.len();
        if !conflicted && target_valid && !targets.is_empty() {
            for target in &targets {
                catalog.selected.insert(target.clone(), policy_index);
            }
        }
        catalog.policies.push(BackendTlsPolicyDecision {
            object: policy.clone(),
            targets,
            accepted,
            resolved_refs,
            accepted_reason,
            resolved_reason,
            message,
            server_name,
            ca_pem,
            subject_alt_names,
        });
    }
    anyhow::ensure!(
        catalog.policies.len() <= cfg.max_objects,
        "managed BackendTLSPolicy objects exceed max_objects"
    );
    Ok(catalog)
}

/// 业务作用：把 BackendTLSPolicy `subjectAltNames` 转换为上游 TLS verifier 的显式类型格式。
///
/// 参数说明：`validation` 是已经通过 CRD 结构校验的 validation 对象。
///
/// 返回：返回至多五个 `dns:`/`uri:` 身份；缺字段返回空，未知类型或缺值失败。
fn parse_backend_tls_subject_alt_names(validation: &Value) -> anyhow::Result<Vec<String>> {
    let Some(names) = validation.get("subjectAltNames").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    anyhow::ensure!(
        names.len() <= 5,
        "BackendTLSPolicy subjectAltNames exceeds 5 entries"
    );
    names
        .iter()
        .map(|name| match name.get("type").and_then(Value::as_str) {
            Some("Hostname") => name
                .get("hostname")
                .and_then(Value::as_str)
                .context("BackendTLSPolicy Hostname SAN missing hostname")
                .and_then(normalize_hostname)
                .map(|value| format!("dns:{value}")),
            Some("URI") => name
                .get("uri")
                .and_then(Value::as_str)
                .context("BackendTLSPolicy URI SAN missing uri")
                .map(|value| format!("uri:{value}")),
            _ => bail!("BackendTLSPolicy subjectAltName type is unsupported"),
        })
        .collect()
}

/// 业务作用：本地复验 ConfigMap `ca.crt` 能否形成非空 rustls 信任库，避免坏策略拖垮整份路由快照。
///
/// 参数说明：`pem` 是受 Kubernetes 响应上限约束的候选 CA bundle。
///
/// 返回：材料在独立 CA 大小门内、包含证书且全部可导入时为 true，否则为 false。
fn valid_backend_tls_ca_pem(pem: &str) -> bool {
    if pem.is_empty() || pem.len() > MAX_TLS_SECRET_BYTES {
        return false;
    }
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let Ok(certs) = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()
    else {
        return false;
    };
    if certs.is_empty() {
        return false;
    }
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    certs
        .into_iter()
        .all(|certificate| roots.add(certificate).is_ok())
}

/// 业务作用：按 Gateway HTTPS 端口解析 frontend client certificate validation，
/// 把默认值、perPort 覆盖、ReferenceGrant 和 CA 有效性冻结成数据面与状态共用裁决。
///
/// 参数说明：Gateway API LIST、ConfigMap 目录与 `cfg` 来自同轮完整发现。
///
/// 返回：返回每个已配置 HTTPS listener 的验证结论；坏引用只关闭受影响端口，不阻断其它 listener。
fn build_gateway_frontend_validation_catalog(
    classes_value: &Value,
    gateways_value: &Value,
    reference_grants_value: &Value,
    config_maps: &ConfigMapCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<GatewayFrontendValidationCatalog> {
    let selected_classes = resource_items(classes_value, cfg.max_objects, "GatewayClass")?
        .iter()
        .filter(|class| {
            class
                .pointer("/spec/controllerName")
                .and_then(Value::as_str)
                == Some(cfg.gateway_controller_name.as_str())
        })
        .filter_map(|class| class.pointer("/metadata/name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let grants = ReferenceGrantCatalog {
        grants: resource_items(reference_grants_value, cfg.max_objects, "ReferenceGrant")?,
    };
    let mut catalog = GatewayFrontendValidationCatalog::default();
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, gateway_name) = object_identity(gateway, "Gateway")?;
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class)
            || !namespace_allowed(cfg, namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        for listener in gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("Gateway missing spec.listeners")?
        {
            if listener.get("protocol").and_then(Value::as_str) != Some("HTTPS") {
                continue;
            }
            let port = listener
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
                .context("Gateway HTTPS listener has invalid port")?;
            let Some(validation) = gateway_frontend_validation_for_port(gateway, port) else {
                continue;
            };
            let allow_insecure_fallback =
                validation.get("mode").and_then(Value::as_str) == Some("AllowInsecureFallback");
            if allow_insecure_fallback {
                catalog
                    .insecure_gateways
                    .insert((namespace.to_owned(), gateway_name.to_owned()));
            }
            let references = validation
                .get("caCertificateRefs")
                .and_then(Value::as_array);
            let mut decision = GatewayFrontendValidationDecision {
                resolved: false,
                accepted_reason: "NoValidCACertificate",
                resolved_reason: "InvalidCACertificateRef",
                message: "Gateway frontend CA reference is missing or invalid",
                ca_pem: None,
                allow_insecure_fallback,
            };
            if let Some(references) = references.filter(|references| references.len() == 1) {
                let reference = &references[0];
                let group = reference.get("group").and_then(Value::as_str).unwrap_or("");
                let kind = reference
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("ConfigMap");
                if !group.is_empty() || kind != "ConfigMap" {
                    decision.resolved_reason = "InvalidCACertificateKind";
                    decision.message = "Gateway frontend CA must reference a core ConfigMap";
                } else {
                    let name = reference
                        .get("name")
                        .and_then(Value::as_str)
                        .context("Gateway frontend CA reference missing name")?;
                    let target_namespace = reference
                        .get("namespace")
                        .and_then(Value::as_str)
                        .unwrap_or(namespace);
                    let permitted = target_namespace == namespace
                        || grants.permits_reference(
                            namespace,
                            "Gateway",
                            target_namespace,
                            "ConfigMap",
                            name,
                        )?;
                    if !permitted {
                        decision.resolved_reason = "RefNotPermitted";
                        decision.message =
                            "Gateway frontend CA cross-namespace reference is not permitted";
                    } else if let Some(pem) = config_maps
                        .objects
                        .get(&(target_namespace.to_owned(), name.to_owned()))
                        .and_then(|object| object.pointer("/data/ca.crt"))
                        .and_then(Value::as_str)
                        .filter(|pem| valid_backend_tls_ca_pem(pem))
                    {
                        decision.resolved = true;
                        decision.accepted_reason = "Accepted";
                        decision.resolved_reason = "ResolvedRefs";
                        decision.message =
                            "Gateway frontend client certificate validation is resolved";
                        decision.ca_pem = Some(pem.as_bytes().to_vec());
                    }
                }
            }
            catalog.listeners.insert(
                (namespace.to_owned(), gateway_name.to_owned(), port),
                decision,
            );
        }
    }
    Ok(catalog)
}

/// 业务作用：从数据面候选中移除前端客户端 CA 未解析的 HTTPS listener，同时保留同一
/// Gateway 上不受该配置影响的 HTTP 或其它端口。
///
/// 参数说明：`gateways_value` 是本轮 Gateway LIST；`frontend_validation` 是同轮引用裁决；
/// `cfg` 提供对象预算。
///
/// 返回：返回仅供数据面编译的 Gateway LIST 副本；对象结构异常时拒绝整轮候选，原始对象
/// 始终保留给状态发布。
fn gateways_with_resolved_frontend_validation(
    gateways_value: &Value,
    frontend_validation: &GatewayFrontendValidationCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<Value> {
    let mut filtered = gateways_value.clone();
    let gateways = filtered
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("Kubernetes Gateway list missing items array")?;
    anyhow::ensure!(
        gateways.len() <= cfg.max_objects,
        "Kubernetes Gateway list exceeds max_objects"
    );
    for gateway in gateways {
        let (namespace, name) = object_identity(gateway, "Gateway")?;
        let namespace = namespace.to_owned();
        let name = name.to_owned();
        let listeners = gateway
            .pointer_mut("/spec/listeners")
            .and_then(Value::as_array_mut)
            .context("Gateway missing spec.listeners")?;
        listeners.retain(|listener| {
            let Some(port) = listener
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
            else {
                return true;
            };
            let unresolved = listener.get("protocol").and_then(Value::as_str) == Some("HTTPS")
                && frontend_validation
                    .listeners
                    .get(&(namespace.clone(), name.clone(), port))
                    .is_some_and(|decision| !decision.resolved);
            if unresolved {
                // 引用失败状态必须先撤下对应 listener 的路由和身份，防止共享 socket 上的
                // 其它有效 Gateway 证书让该 listener 继续接受流量。
                return false;
            }
            true
        });
    }
    Ok(filtered)
}

/// 业务作用：定位包含未解析前端客户端 CA 配置的 TLS socket，确保共享该 socket 的其它
/// Gateway 身份不会让失败 listener 仍完成 TLS 握手。
///
/// 参数说明：Gateway API LIST 与 `frontend_validation` 来自同轮发现；`cfg` 固定 controller
/// 和绑定地址边界。
///
/// 返回：返回必须整体停止接受 TLS 的 listen 集合；目录构建或地址解析失败时拒绝整轮候选。
fn unresolved_frontend_validation_sockets(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    namespaces_value: &Value,
    frontend_validation: &GatewayFrontendValidationCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<BTreeSet<String>> {
    let catalog = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let mut blocked = BTreeSet::new();
    for listener in catalog
        .listeners
        .iter()
        .filter(|listener| listener.protocol == "HTTPS")
    {
        let unresolved = frontend_validation
            .listeners
            .get(&(
                listener.gateway_namespace.clone(),
                listener.gateway_name.clone(),
                listener.port,
            ))
            .is_some_and(|decision| !decision.resolved);
        if !unresolved {
            continue;
        }
        let ip = listener
            .bind_address
            .parse::<std::net::IpAddr>()
            .context("parse unresolved Gateway frontend validation bind address")?;
        // TLS 客户端认证在 CertificateRequest 阶段早于 HTTP listener 选择；同 socket
        // 无法只拒绝其中一个无 hostname listener，因此必须先停整个 socket，避免绕过 CA 门禁。
        blocked.insert(std::net::SocketAddr::new(ip, listener.port).to_string());
    }
    Ok(blocked)
}

/// 业务作用：为 Gateway HTTPS 端口选择 perPort validation，并在没有覆盖时回退 default。
///
/// 参数说明：`gateway` 是受管 Gateway；`port` 是当前 HTTPS listener 端口。
///
/// 返回：配置了端口级或默认 validation 时返回引用，否则返回 None。
fn gateway_frontend_validation_for_port(gateway: &Value, port: u16) -> Option<&Value> {
    gateway
        .pointer("/spec/tls/frontend/perPort")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.get("port").and_then(Value::as_u64) == Some(u64::from(port)))
        })
        .and_then(|entry| entry.pointer("/tls/validation"))
        .or_else(|| gateway.pointer("/spec/tls/frontend/default/validation"))
}

/// 业务作用：把目标端口的 BackendTLSPolicy 权威覆写到已生成 Kubernetes Service，
/// 保证路由引用、TLS SNI、信任根与显式 SAN 在同一候选 generation 生效。
///
/// 参数说明：`services` 是 HTTP Route 已生成的候选上游；策略和 Service 目录来自同轮发现。
///
/// 返回：所有生成服务均可映射回声明端口时成功；结构或端口身份不一致时拒绝候选。
fn apply_backend_tls_policies(
    services: &mut BTreeMap<String, Value>,
    policies: &BackendTlsCatalog,
    service_catalog: &ServiceCatalog,
) -> anyhow::Result<()> {
    for service in services.values_mut() {
        if service.get("source").and_then(Value::as_str) != Some("kubernetes") {
            continue;
        }
        if service
            .get("registry_service_import")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let namespace = service
            .get("registry_namespace")
            .and_then(Value::as_str)
            .context("generated Kubernetes service missing registry_namespace")?;
        let name = service
            .get("registry_service")
            .and_then(Value::as_str)
            .context("generated Kubernetes service missing registry_service")?;
        let section_name =
            if let Some(name) = service.get("registry_port_name").and_then(Value::as_str) {
                Some(name.to_owned())
            } else if let Some(number) = service
                .get("registry_port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
            {
                service_catalog
                    .port_names
                    .get(&(namespace.to_owned(), name.to_owned()))
                    .and_then(|names| {
                        names.iter().find_map(|(name, candidate)| {
                            (*candidate == number).then(|| name.clone())
                        })
                    })
            } else {
                None
            };
        let exact = BackendTlsTargetKey {
            namespace: namespace.to_owned(),
            service: name.to_owned(),
            section_name,
        };
        let whole = BackendTlsTargetKey {
            namespace: namespace.to_owned(),
            service: name.to_owned(),
            section_name: None,
        };
        let Some(policy_index) = policies
            .selected
            .get(&exact)
            .or_else(|| policies.selected.get(&whole))
        else {
            continue;
        };
        let policy = &policies.policies[*policy_index];
        // 策略一旦取得目标权威就必须切换 HTTPS；即使 CA 引用失效，也要失败闭合而不能回退明文。
        service["scheme"] = json!("https");
        if service.get("protocol").and_then(Value::as_str) == Some("h2c") {
            service["protocol"] = json!("h2");
        }
        service
            .as_object_mut()
            .expect("generated Kubernetes service is an object")
            .remove("tls");
        if policy.resolved_refs {
            let server_name = policy
                .server_name
                .as_deref()
                .context("resolved BackendTLSPolicy missing hostname")?;
            service["tls"] = json!({
                "server_name": server_name,
                "ca_pem": policy.ca_pem,
                "subject_alt_names": policy.subject_alt_names
            });
        }
    }
    Ok(())
}

/// 业务作用：解析受管 Gateway 的上游客户端身份，确保只有完整、匹配的 Secret 能被 TLS 后端使用。
///
/// 参数说明：Gateway LIST 与 Secret 目录来自同轮；`cfg` 固定接管 namespace 和对象预算。
///
/// 返回：返回 Gateway 到客户端证书材料的有界映射；未声明或引用失效时不产生材料。
fn build_gateway_backend_client_catalog(
    gateways_value: &Value,
    secrets: &SecretCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<GatewayBackendClientCatalog> {
    let mut catalog = GatewayBackendClientCatalog::default();
    for gateway in resource_items(gateways_value, cfg.max_objects, "Gateway")? {
        let (namespace, name) = object_identity(gateway, "Gateway")?;
        if !namespace_allowed(cfg, namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let Some(reference) = gateway.pointer("/spec/tls/backend/clientCertificateRef") else {
            continue;
        };
        if !reference
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
            || reference
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Secret")
                != "Secret"
        {
            continue;
        }
        let secret_name = reference
            .get("name")
            .and_then(Value::as_str)
            .context("Gateway backend clientCertificateRef missing name")?;
        if let Some(material) = secrets.tls_material(namespace, secret_name)? {
            catalog
                .materials
                .insert((namespace.to_owned(), name.to_owned()), material);
        }
    }
    Ok(catalog)
}

/// 业务作用：按 Route 实际附着的 Gateway 为 HTTPS Service 派生独立客户端身份上游，
/// 防止共享 Service 时一个 Gateway 的私钥泄漏到另一个 Gateway 的连接池。
///
/// 参数说明：listener 路由和 Gateway 目录确定权威归属；`services` 已应用 BackendTLSPolicy；
/// `clients` 只含已复验 Secret 材料。
///
/// 返回：成功时原子改写 Route 的逻辑 Service 引用并加入内容寻址副本；结构异常时拒绝候选。
fn apply_gateway_backend_client_certificates(
    listener_routes: &mut BTreeMap<HttpListenerKey, Vec<Value>>,
    services: &mut BTreeMap<String, Value>,
    gateways: &GatewayCatalog,
    clients: &GatewayBackendClientCatalog,
) -> anyhow::Result<()> {
    if clients.materials.is_empty() {
        return Ok(());
    }
    let listener_gateways = gateways
        .listeners
        .iter()
        .map(|listener| {
            (
                gateway_listener_id(listener),
                (
                    listener.gateway_namespace.clone(),
                    listener.gateway_name.clone(),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut additions = BTreeMap::new();
    for route in listener_routes.values_mut().flatten() {
        let Some(listener_id) = generated_route_listener_id(route) else {
            continue;
        };
        let Some(gateway) = listener_gateways.get(listener_id) else {
            continue;
        };
        let Some(material) = clients.materials.get(gateway) else {
            continue;
        };
        let Some(logical) = route
            .get("uri")
            .and_then(Value::as_str)
            .and_then(|uri| uri.strip_prefix("lb://"))
        else {
            continue;
        };
        let base = services.get(logical).with_context(|| {
            format!("Gateway backend client identity missing Service `{logical}`")
        })?;
        if base.get("scheme").and_then(Value::as_str) != Some("https") {
            continue;
        }
        let digest = tls_identity_digest(material);
        let derived = stable_id(
            "k8s-mtls-svc",
            &[logical, gateway.0.as_str(), gateway.1.as_str(), &digest],
        );
        let mut value = base.clone();
        if !value.get("tls").is_some_and(Value::is_object) {
            value["tls"] = json!({});
        }
        value["tls"]["client_cert_pem"] =
            json!(String::from_utf8(material.certificate_chain.clone())
                .context("Gateway backend client certificate PEM is not UTF-8")?);
        value["tls"]["client_key_pem"] = json!(String::from_utf8(material.private_key.clone())
            .context("Gateway backend client private key PEM is not UTF-8")?);
        match additions.get(&derived).or_else(|| services.get(&derived)) {
            Some(existing) => anyhow::ensure!(
                existing == &value,
                "Gateway backend client Service identity collision"
            ),
            None => {
                additions.insert(derived.clone(), value);
            }
        }
        route["uri"] = json!(format!("lb://{derived}"));
    }
    services.extend(additions);
    Ok(())
}

/// 业务作用：读取编译器写入的内部 listener predicate，恢复单条生成路由的 Gateway 权威。
///
/// 参数说明：`route` 是已经完成 listener 隔离的 HTTP/GRPC Route IR。
///
/// 返回：找到精确内部标记时返回 listener id；重定向或非 Gateway 路由返回 None。
fn generated_route_listener_id(route: &Value) -> Option<&str> {
    const PREFIX: &str = "Header=x-naway-gateway-listener,exact,";
    route
        .get("predicates")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|predicate| predicate.strip_prefix(PREFIX))
}

/// 业务作用：为每个 BackendTLSPolicy 发布按受影响 Gateway 分组的 ancestor conditions，
/// 让策略接受、引用解析和冲突裁决与实际数据面权威保持一致。
///
/// 参数说明：策略目录、Gateway/HTTPRoute/TLSRoute/Namespace LIST 与 Service 目录来自同轮；
/// `cfg` 固定 controller identity。
///
/// 返回：返回有界 BackendTLSPolicy status 意图；附件或对象身份异常时拒绝本轮状态发布。
#[allow(clippy::too_many_arguments)]
fn build_backend_tls_status_intents(
    policies: &BackendTlsCatalog,
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    http_routes_value: &Value,
    tls_routes_value: &Value,
    namespaces_value: &Value,
    services: &ServiceCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<Vec<ControlStatusIntent>> {
    let gateways = build_gateway_catalog_with_listener_sets(
        classes_value,
        gateways_value,
        listener_sets_value,
        namespaces_value,
        cfg,
    )?;
    let namespaces = build_namespace_catalog(namespaces_value, cfg.max_objects)?;
    let http_routes = resource_items(http_routes_value, cfg.max_objects, "HTTPRoute")?;
    let tls_routes = resource_items(tls_routes_value, cfg.max_objects, "TLSRoute")?;
    let transition_time = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("format BackendTLSPolicy status timestamp")?;
    let mut output = Vec::new();
    for policy in &policies.policies {
        let (namespace, name) = object_identity(&policy.object, "BackendTLSPolicy")?;
        let generation = policy
            .object
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let mut ancestors = BTreeSet::new();
        for (route_kind, routes) in [("HTTPRoute", http_routes), ("TLSRoute", tls_routes)] {
            for route in routes {
                let (route_namespace, _) = object_identity(route, route_kind)?;
                if !policy.targets.iter().any(|target| {
                    route_references_backend_tls_target(route, route_namespace, target, services)
                }) {
                    continue;
                }
                for attached in
                    attached_listeners(route, route_namespace, route_kind, &gateways, &namespaces)?
                {
                    ancestors.insert((
                        attached.listener.gateway_namespace,
                        attached.listener.gateway_name,
                    ));
                }
            }
        }
        // Gateway API 为 ancestor status 设置固定上限；稳定截断防止异常拓扑制造无界状态对象。
        let ancestor_statuses = ancestors
            .into_iter()
            .take(16)
            .map(|(gateway_namespace, gateway_name)| {
                json!({
                    "ancestorRef": {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "namespace": gateway_namespace,
                        "name": gateway_name
                    },
                    "controllerName": cfg.gateway_controller_name,
                    "conditions": [
                        gateway_condition(
                            "Accepted",
                            policy.accepted,
                            policy.accepted_reason,
                            policy.message,
                            generation,
                            &transition_time,
                        ),
                        gateway_condition(
                            "ResolvedRefs",
                            policy.resolved_refs,
                            policy.resolved_reason,
                            policy.message,
                            generation,
                            &transition_time,
                        )
                    ]
                })
            })
            .collect::<Vec<_>>();
        output.push(ControlStatusIntent {
            api_version: "gateway.networking.k8s.io/v1".to_owned(),
            kind: "BackendTLSPolicy".to_owned(),
            plural: "backendtlspolicies".to_owned(),
            namespace: Some(namespace.to_owned()),
            name: name.to_owned(),
            status: json!({"ancestors": ancestor_statuses}),
        });
    }
    anyhow::ensure!(
        output.len() <= cfg.max_status_updates,
        "BackendTLSPolicy status updates exceed max_status_updates"
    );
    Ok(output)
}

/// 业务作用：为 BackendTrafficPolicy 的每个 targetRef 发布独立 ancestor condition，
/// 使部分目标冲突或缺失时不会掩盖同一策略的其它有效目标。
///
/// 参数说明：`policies` 是本轮数据面使用的确定性策略目录；`cfg` 提供 controller identity
/// 与状态条目预算。
///
/// 返回：返回 XBackendTrafficPolicy status 意图；资源身份或条目预算异常时拒绝本轮状态发布。
fn build_backend_traffic_status_intents(
    policies: &BackendTrafficCatalog,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<Vec<ControlStatusIntent>> {
    let transition_time = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("format BackendTrafficPolicy status timestamp")?;
    let mut output = Vec::new();
    for policy in &policies.policies {
        let (namespace, name) = object_identity(&policy.object, "XBackendTrafficPolicy")?;
        anyhow::ensure!(
            policy.object.get("apiVersion").and_then(Value::as_str)
                == Some("gateway.networking.x-k8s.io/v1alpha1")
                && policy.object.get("kind").and_then(Value::as_str)
                    == Some("XBackendTrafficPolicy"),
            "BackendTrafficPolicy resource identity is unsupported"
        );
        let generation = policy
            .object
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let ancestors = policy
            .targets
            .iter()
            .map(|target| {
                json!({
                    "ancestorRef": {
                        "group": target.key.group,
                        "kind": target.key.kind,
                        "namespace": target.key.namespace,
                        "name": target.key.name
                    },
                    "controllerName": cfg.gateway_controller_name,
                    "conditions": [
                        gateway_condition(
                            "Accepted",
                            target.accepted,
                            target.accepted_reason,
                            target.message.as_str(),
                            generation,
                            &transition_time,
                        ),
                        gateway_condition(
                            "ResolvedRefs",
                            target.resolved_refs,
                            target.resolved_reason,
                            target.message.as_str(),
                            generation,
                            &transition_time,
                        )
                    ]
                })
            })
            .collect::<Vec<_>>();
        output.push(ControlStatusIntent {
            api_version: "gateway.networking.x-k8s.io/v1alpha1".to_owned(),
            kind: "XBackendTrafficPolicy".to_owned(),
            plural: "xbackendtrafficpolicies".to_owned(),
            namespace: Some(namespace.to_owned()),
            name: name.to_owned(),
            status: json!({"ancestors": ancestors}),
        });
    }
    anyhow::ensure!(
        output.len() <= cfg.max_status_updates,
        "BackendTrafficPolicy status updates exceed max_status_updates"
    );
    Ok(output)
}

/// 业务作用：判断 HTTPRoute 或 TLSRoute 是否消费策略目标端口，避免给无关 Gateway
/// 发布虚假 ancestor 状态。
///
/// 参数说明：Route 和目标均来自同轮；`route_namespace` 是 Route 身份；`services` 解析 sectionName 到端口。
///
/// 返回：任一主 backendRef 指向目标 Service 且端口落入策略作用域时为 true；结构缺失时为 false。
fn route_references_backend_tls_target(
    route: &Value,
    route_namespace: &str,
    target: &BackendTlsTargetKey,
    services: &ServiceCatalog,
) -> bool {
    let section_port = target.section_name.as_ref().and_then(|section| {
        services
            .port_names
            .get(&(target.namespace.clone(), target.service.clone()))
            .and_then(|names| names.get(section))
            .copied()
    });
    route
        .pointer("/spec/rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| rule.get("backendRefs").and_then(Value::as_array))
        .flatten()
        .any(|backend| {
            let group = backend.get("group").and_then(Value::as_str).unwrap_or("");
            let kind = backend
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("Service");
            let namespace = backend
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or(route_namespace);
            let name = backend.get("name").and_then(Value::as_str);
            let port = backend
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok());
            group.is_empty()
                && kind == "Service"
                && namespace == target.namespace
                && name == Some(target.service.as_str())
                && target
                    .section_name
                    .as_ref()
                    .is_none_or(|_| port == section_port)
        })
}

/// 业务作用：判断 Gateway listener 是否由 stream 数据面承载，为地址池分配、socket
/// 冲突门禁与状态发布提供同一协议边界。
///
/// 参数说明：`protocol` 是已校验的 Gateway listener protocol。
///
/// 返回：TLS/TCP/UDP 返回 true，HTTP/HTTPS 返回 false。
fn is_gateway_stream_protocol(protocol: &str) -> bool {
    matches!(protocol, "TLS" | "TCP" | "UDP")
}

/// 业务作用：在创建任何 listener socket 前裁决 Gateway `spec.addresses`，只允许控制器
/// 明确配置的 IP 被静态占用，并为空 IPAddress 请求分配默认地址。
///
/// 参数说明：`gateway` 是当前 controller 接管的 Gateway；`cfg` 提供允许绑定的 HTTP 与
/// stream 地址集合。
///
/// 返回：无静态请求时返回动态分配决策；类型不支持时 `accepted=false`，地址无法绑定或
/// 当前实现无法同时承载多个不同地址时 `usable=false`；结构或 IP 语法异常时拒绝整轮候选。
fn gateway_address_decision(
    gateway: &Value,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<GatewayAddressDecision> {
    let Some(addresses) = gateway.pointer("/spec/addresses") else {
        return Ok(GatewayAddressDecision {
            static_requested: false,
            accepted: true,
            usable: true,
            bind_address: None,
            status_addresses: Vec::new(),
        });
    };
    let addresses = addresses
        .as_array()
        .context("Gateway spec.addresses must be an array")?;
    if addresses.is_empty() {
        return Ok(GatewayAddressDecision {
            static_requested: false,
            accepted: true,
            usable: true,
            bind_address: None,
            status_addresses: Vec::new(),
        });
    }
    anyhow::ensure!(
        addresses.len() <= 16,
        "Gateway spec.addresses exceeds 16 entries"
    );

    let mut allowed = BTreeSet::from([
        cfg.gateway_bind_address.clone(),
        cfg.gateway_stream_bind_address.clone(),
    ]);
    allowed.extend(cfg.gateway_stream_bind_addresses.iter().cloned());
    let mut assigned = BTreeSet::new();
    for address in addresses {
        let address_type = address
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("IPAddress");
        if address_type != "IPAddress" {
            // 不支持的类型是 Gateway 级接纳失败，必须在任何 socket 产生前停止；否则
            // status 虽然拒绝，旧/新请求仍可能从已开放 listener 进入业务路由。
            return Ok(GatewayAddressDecision {
                static_requested: true,
                accepted: false,
                usable: false,
                bind_address: None,
                status_addresses: Vec::new(),
            });
        }
        let raw_value = match address.get("value") {
            Some(value) => value
                .as_str()
                .context("Gateway IPAddress value must be a string")?,
            None => "",
        };
        let value = if raw_value.trim().is_empty() {
            cfg.gateway_bind_address.clone()
        } else {
            raw_value
                .parse::<std::net::IpAddr>()
                .context("Gateway IPAddress value is invalid")?
                .to_string()
        };
        assigned.insert(value);
    }

    let usable = assigned.len() == 1 && assigned.iter().all(|value| allowed.contains(value));
    if !usable {
        // 只有完整地址集合都能原子绑定时才可发布任何 listener；部分成功会让 status 地址与
        // 实际入口不一致，并在重启或节点差异下形成半完成数据面。
        return Ok(GatewayAddressDecision {
            static_requested: true,
            accepted: true,
            usable: false,
            bind_address: None,
            status_addresses: Vec::new(),
        });
    }
    let bind_address = assigned
        .into_iter()
        .next()
        .context("usable Gateway address decision missing address")?;
    Ok(GatewayAddressDecision {
        static_requested: true,
        accepted: true,
        usable: true,
        bind_address: Some(bind_address.clone()),
        status_addresses: vec![GatewayAssignedAddress {
            address_type: "IPAddress".to_owned(),
            value: bind_address,
        }],
    })
}

/// 业务作用：选择本 controller 拥有的 Gateway，并把 listener 附着边界编译为稳定目录。
///
/// 参数说明：`classes_value` 与 `gateways_value` 来自同轮 LIST；`cfg` 提供 controllerName
/// 和 namespace 接管范围。
///
/// 返回：返回可由当前数据面安全承载并已获得地址的 listener 目录；不支持的 TLS mode 与地址池耗尽
/// listener 会被排除并由状态层报告，结构、端口、protocol 或 allowedRoutes 异常时拒绝候选。
fn build_gateway_catalog_with_listener_sets(
    classes_value: &Value,
    gateways_value: &Value,
    listener_sets_value: &Value,
    namespaces_value: &Value,
    cfg: &KubernetesRouteSourceCfg,
) -> anyhow::Result<GatewayCatalog> {
    let namespaces = build_namespace_catalog(namespaces_value, cfg.max_objects)?;
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
    let mut objects = resource_items(gateways_value, cfg.max_objects, "Gateway")?
        .iter()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object_order_key(object));
    let mut gateways = HashSet::new();
    let mut listener_sets = HashSet::new();
    let mut listeners = Vec::new();
    let mut address_decisions = HashMap::new();
    let mut listener_set_decisions = HashMap::new();
    let mut port_families: HashMap<(String, String, u16), String> = HashMap::new();
    #[allow(clippy::type_complexity)]
    let mut owner_slots: HashMap<(String, String, u16), Vec<(String, Option<String>)>> =
        HashMap::new();
    let mut stream_gateway_index = 0_usize;
    for gateway in objects.iter().copied() {
        let (namespace, name) = object_identity(gateway, "Gateway")?;
        if !namespace_allowed(cfg, namespace)
            || gateway.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let class = gateway
            .pointer("/spec/gatewayClassName")
            .and_then(Value::as_str)
            .context("Gateway missing spec.gatewayClassName")?;
        if !selected_classes.contains(class) {
            continue;
        }
        let gateway_key = (namespace.to_owned(), name.to_owned());
        gateways.insert(gateway_key.clone());
        let address_decision = gateway_address_decision(gateway, cfg)?;
        let address_ready = address_decision.accepted && address_decision.usable;
        let static_bind_address = address_decision
            .static_requested
            .then(|| address_decision.bind_address.clone())
            .flatten();
        address_decisions.insert(gateway_key, address_decision);
        if !address_ready {
            // 地址类型或可用性是 Gateway 级 socket 门禁；在地址未满足前不得让任何
            // listener 进入候选，否则状态失败期间仍可能保留可达业务路由。
            continue;
        }
        let raw_listeners = gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("selected Gateway missing spec.listeners")?;
        anyhow::ensure!(
            raw_listeners.len() <= 64,
            "Gateway {namespace}/{name} exceeds 64 listeners"
        );
        let has_stream_listener = raw_listeners.iter().any(|listener| {
            listener
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| {
                    is_gateway_stream_protocol(protocol)
                        && gateway_listener_mode_supported(listener, protocol)
                })
        });
        let stream_bind_address = if !has_stream_listener {
            None
        } else if let Some(address) = static_bind_address.as_deref() {
            Some(address)
        } else if cfg.gateway_stream_bind_addresses.is_empty() {
            Some(cfg.gateway_stream_bind_address.as_str())
        } else {
            let address = cfg
                .gateway_stream_bind_addresses
                .get(stream_gateway_index)
                .map(String::as_str);
            stream_gateway_index = stream_gateway_index.saturating_add(1);
            address
        };
        for listener in raw_listeners {
            let section_name = listener
                .get("name")
                .and_then(Value::as_str)
                .context("Gateway listener missing name")?;
            validate_safe_name("Gateway listener name", section_name, 63)?;
            let protocol = listener
                .get("protocol")
                .and_then(Value::as_str)
                .context("Gateway listener missing protocol")?;
            anyhow::ensure!(
                matches!(protocol, "HTTP" | "HTTPS" | "TLS" | "TCP" | "UDP"),
                "Gateway {namespace}/{name} listener `{section_name}` protocol `{protocol}` is unsupported"
            );
            if !gateway_listener_mode_supported(listener, protocol) {
                // TLS termination 与 passthrough 的密钥边界完全不同；未实现的 mode 不得占用
                // socket 或宣称可附着 TLSRoute，否则控制面会把明文目标错误发布给透传数据面。
                continue;
            }
            let port = listener
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0)
                .context("Gateway listener requires a non-zero port")?;
            let family = protocol.to_owned();
            let transport = if protocol == "UDP" { "udp" } else { "tcp" };
            let bind_address = if let Some(address) = static_bind_address.as_deref() {
                address
            } else if is_gateway_stream_protocol(protocol) {
                let Some(address) = stream_bind_address else {
                    // 地址池耗尽后不能复用其它 Gateway 的地址，否则重叠 SNI/TCP 路由会跨
                    // Gateway 泄漏；让后续 listener 保持未接纳，等待扩容地址池。
                    tracing::warn!(
                        gateway_namespace = namespace,
                        gateway_name = name,
                        listener = section_name,
                        protocol,
                        "Gateway stream address pool exhausted"
                    );
                    continue;
                };
                address
            } else {
                cfg.gateway_bind_address.as_str()
            };
            let key = (bind_address.to_owned(), transport.to_owned(), port);
            if let Some(existing) = port_families.get(&key) {
                if existing != &family {
                    // 同一地址和端口上混入不同协议会导致部分节点按对象顺序选择不同解释；固定由
                    // 最早 Gateway listener 获得所有权，后续 listener 不进入候选。独立的 stream
                    // 地址允许 TLS passthrough 与 HTTPS termination 在同一端口安全共存。
                    tracing::warn!(
                        gateway_namespace = namespace,
                        gateway_name = name,
                        listener = section_name,
                        protocol,
                        port,
                        owner_protocol = existing,
                        "Gateway listener conflicts with an earlier listener"
                    );
                    continue;
                }
            } else {
                port_families.insert(key, family);
            }
            let hostname = listener
                .get("hostname")
                .and_then(Value::as_str)
                .map(normalize_hostname)
                .transpose()?;
            let allowed_namespaces = parse_allowed_namespaces(listener)?;
            let allowed_kinds = parse_allowed_kinds(listener, protocol)?;
            listeners.push(GatewayListener {
                gateway_namespace: namespace.to_owned(),
                gateway_name: name.to_owned(),
                parent_group: "gateway.networking.k8s.io".to_owned(),
                parent_kind: "Gateway".to_owned(),
                parent_namespace: namespace.to_owned(),
                parent_name: name.to_owned(),
                section_name: section_name.to_owned(),
                protocol: protocol.to_owned(),
                parent_port: port,
                port,
                bind_address: bind_address.to_owned(),
                hostname: hostname.clone(),
                tls_mode: listener
                    .pointer("/tls/mode")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                allowed_namespaces,
                allowed_kinds: allowed_kinds.supported,
            });
            owner_slots
                .entry((namespace.to_owned(), name.to_owned(), port))
                .or_default()
                .push((protocol.to_owned(), hostname));
        }
    }

    let mut listener_set_objects =
        resource_items(listener_sets_value, cfg.max_objects, "ListenerSet")?
            .iter()
            .collect::<Vec<_>>();
    listener_set_objects.sort_by_key(|object| object_order_key(object));
    for listener_set in listener_set_objects {
        let (namespace, name) = object_identity(listener_set, "ListenerSet")?;
        if !namespace_allowed(cfg, namespace)
            || listener_set
                .pointer("/metadata/deletionTimestamp")
                .is_some()
        {
            continue;
        }
        let parent = listener_set
            .pointer("/spec/parentRef")
            .context("ListenerSet missing spec.parentRef")?;
        let parent_group = parent
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("gateway.networking.k8s.io");
        let parent_kind = parent
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Gateway");
        let gateway_name = parent
            .get("name")
            .and_then(Value::as_str)
            .context("ListenerSet parentRef missing name")?;
        let gateway_namespace = parent
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(namespace);
        validate_kubernetes_name("ListenerSet parent Gateway namespace", gateway_namespace)?;
        validate_kubernetes_name("ListenerSet parent Gateway name", gateway_name)?;
        let parent_gateway = objects.iter().copied().find(|gateway| {
            object_identity(gateway, "Gateway")
                .is_ok_and(|identity| identity == (gateway_namespace, gateway_name))
        });
        let selected_parent = parent_group == "gateway.networking.k8s.io"
            && parent_kind == "Gateway"
            && gateways.contains(&(gateway_namespace.to_owned(), gateway_name.to_owned()));
        let allowed = if selected_parent {
            listener_set_namespace_allowed(
                parent_gateway.context("selected ListenerSet parent Gateway missing")?,
                gateway_namespace,
                namespace,
                &namespaces,
            )?
        } else {
            false
        };
        let decision_key = (namespace.to_owned(), name.to_owned());
        let mut decision = ListenerSetDecision {
            gateway_namespace: gateway_namespace.to_owned(),
            gateway_name: gateway_name.to_owned(),
            allowed,
            listener_reasons: BTreeMap::new(),
        };
        if !allowed {
            // Gateway owner 没有显式授权时，ListenerSet 不得占用 parent socket，也不能成为
            // Route 的有效 parent；状态层仍会向对象发布 NotAllowed 以便配置方收敛。
            listener_set_decisions.insert(decision_key, decision);
            continue;
        }
        let raw_listeners = listener_set
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .context("selected ListenerSet missing spec.listeners")?;
        anyhow::ensure!(
            raw_listeners.len() <= 64,
            "ListenerSet {namespace}/{name} exceeds 64 listeners"
        );
        let address_decision = address_decisions
            .get(&(gateway_namespace.to_owned(), gateway_name.to_owned()))
            .context("ListenerSet parent Gateway missing address decision")?;
        let static_bind_address = address_decision.bind_address.as_deref();
        for listener in raw_listeners {
            let section_name = listener
                .get("name")
                .and_then(Value::as_str)
                .context("ListenerSet listener missing name")?;
            validate_safe_name("ListenerSet listener name", section_name, 63)?;
            let protocol = listener
                .get("protocol")
                .and_then(Value::as_str)
                .context("ListenerSet listener missing protocol")?;
            anyhow::ensure!(
                matches!(protocol, "HTTP" | "HTTPS" | "TLS" | "TCP" | "UDP"),
                "ListenerSet {namespace}/{name} listener `{section_name}` protocol `{protocol}` is unsupported"
            );
            let port = listener
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0)
                .context("ListenerSet listener requires a non-zero port")?;
            let hostname = listener
                .get("hostname")
                .and_then(Value::as_str)
                .map(normalize_hostname)
                .transpose()?;
            let slot_key = (gateway_namespace.to_owned(), gateway_name.to_owned(), port);
            let conflict = owner_slots.get(&slot_key).and_then(|slots| {
                if slots
                    .iter()
                    .any(|(owner_protocol, _)| owner_protocol != protocol)
                {
                    Some("ProtocolConflict")
                } else if slots.iter().any(|(owner_protocol, owner_hostname)| {
                    owner_protocol == protocol && owner_hostname == &hostname
                }) {
                    Some("HostnameConflict")
                } else {
                    None
                }
            });
            let mode_supported = gateway_listener_mode_supported(listener, protocol);
            let reason = conflict.or((!mode_supported).then_some("UnsupportedValue"));
            decision
                .listener_reasons
                .insert(section_name.to_owned(), reason);
            if reason.is_some() || !address_decision.accepted || !address_decision.usable {
                // 冲突或 parent 地址未就绪时必须先停止 listener 发布，防止低优先级
                // ListenerSet 抢占 Gateway socket 或在状态失败时残留可达路由。
                continue;
            }
            let bind_address = if let Some(address) = static_bind_address {
                address
            } else if is_gateway_stream_protocol(protocol) {
                listeners
                    .iter()
                    .find(|candidate| {
                        candidate.gateway_namespace == gateway_namespace
                            && candidate.gateway_name == gateway_name
                            && is_gateway_stream_protocol(&candidate.protocol)
                    })
                    .map(|candidate| candidate.bind_address.as_str())
                    .or_else(|| {
                        cfg.gateway_stream_bind_addresses
                            .first()
                            .map(String::as_str)
                    })
                    .unwrap_or(cfg.gateway_stream_bind_address.as_str())
            } else {
                cfg.gateway_bind_address.as_str()
            };
            let transport = if protocol == "UDP" { "udp" } else { "tcp" };
            let socket_key = (bind_address.to_owned(), transport.to_owned(), port);
            if let Some(owner_protocol) = port_families.get(&socket_key) {
                if owner_protocol != protocol {
                    decision
                        .listener_reasons
                        .insert(section_name.to_owned(), Some("ProtocolConflict"));
                    continue;
                }
            } else {
                port_families.insert(socket_key, protocol.to_owned());
            }
            let allowed_namespaces = parse_allowed_namespaces(listener)?;
            let allowed_kinds = parse_allowed_kinds(listener, protocol)?;
            listeners.push(GatewayListener {
                gateway_namespace: gateway_namespace.to_owned(),
                gateway_name: gateway_name.to_owned(),
                parent_group: "gateway.networking.k8s.io".to_owned(),
                parent_kind: "ListenerSet".to_owned(),
                parent_namespace: namespace.to_owned(),
                parent_name: name.to_owned(),
                section_name: section_name.to_owned(),
                protocol: protocol.to_owned(),
                parent_port: port,
                port,
                bind_address: bind_address.to_owned(),
                hostname: hostname.clone(),
                tls_mode: listener
                    .pointer("/tls/mode")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                allowed_namespaces,
                allowed_kinds: allowed_kinds.supported,
            });
            owner_slots
                .entry(slot_key)
                .or_default()
                .push((protocol.to_owned(), hostname));
        }
        listener_sets.insert(decision_key.clone());
        listener_set_decisions.insert(decision_key, decision);
    }
    Ok(GatewayCatalog {
        gateways,
        listener_sets,
        mesh_parents: HashSet::new(),
        mesh_interception_ready: cfg.gateway_mesh_interception_ready,
        mesh_source_namespace_header: "x-naway-mesh-source-namespace".to_owned(),
        listeners,
        address_decisions,
        listener_set_decisions,
    })
}

/// 业务作用：判断 Gateway listener 的 TLS mode 是否可由当前数据面安全实现，供数据面目录
/// 与状态发布共用同一接纳边界。
///
/// 参数说明：`listener` 是原始 Gateway listener；`protocol` 是其已校验协议。
///
/// 返回：TLS listener 在 `Passthrough` 或 `Terminate` mode 下返回 true；其它协议返回 true。
fn gateway_listener_mode_supported(listener: &Value, protocol: &str) -> bool {
    protocol != "TLS"
        || matches!(
            listener.pointer("/tls/mode").and_then(Value::as_str),
            Some("Passthrough" | "Terminate")
        )
}

/// 业务作用：执行 Gateway `allowedListeners` 的命名空间授权，阻止未经 parent owner
/// 同意的 ListenerSet 扩展网络入口。
///
/// 参数说明：`gateway` 提供授权策略；`gateway_namespace` 与 `listener_set_namespace`
/// 是两端可信身份；`namespaces` 提供 Selector 所需的同轮标签事实。
///
/// 返回：策略明确允许时返回 true；缺省/None 返回 false，Selector 结构或 namespace
/// 证据异常时返回错误并拒绝本轮候选。
fn listener_set_namespace_allowed(
    gateway: &Value,
    gateway_namespace: &str,
    listener_set_namespace: &str,
    namespaces: &NamespaceCatalog,
) -> anyhow::Result<bool> {
    let Some(policy) = gateway.pointer("/spec/allowedListeners/namespaces") else {
        return Ok(false);
    };
    match policy.get("from").and_then(Value::as_str).unwrap_or("None") {
        "None" => Ok(false),
        "Same" => Ok(gateway_namespace == listener_set_namespace),
        "All" => Ok(true),
        "Selector" => {
            let selector = policy
                .get("selector")
                .context("Gateway allowedListeners Selector requires selector")?;
            let labels = namespaces
                .labels
                .get(listener_set_namespace)
                .with_context(|| {
                    format!("ListenerSet Namespace `{listener_set_namespace}` missing from LIST")
                })?;
            label_selector_matches(selector, labels)
        }
        other => bail!("Gateway allowedListeners.namespaces.from `{other}` is unsupported"),
    }
}

/// 业务作用：解析 listener namespace policy，保证跨 namespace Route 必须由 Gateway owner 显式授权。
///
/// 参数说明：`listener` 是 Gateway spec.listeners 的单项。
///
/// 返回：Same/All/Selector 合法时返回策略；未知枚举或缺 selector 时失败闭合。
fn parse_allowed_namespaces(listener: &Value) -> anyhow::Result<AllowedNamespaces> {
    let Some(namespaces) = listener.pointer("/allowedRoutes/namespaces") else {
        return Ok(AllowedNamespaces::Same);
    };
    match namespaces
        .get("from")
        .and_then(Value::as_str)
        .unwrap_or("Same")
    {
        "Same" => Ok(AllowedNamespaces::Same),
        "All" => Ok(AllowedNamespaces::All),
        "Selector" => namespaces
            .get("selector")
            .cloned()
            .map(AllowedNamespaces::Selector)
            .context("Gateway listener Selector requires selector"),
        other => bail!("Gateway listener allowedRoutes.namespaces.from `{other}` is unsupported"),
    }
}

/// 业务作用：固定 listener 可附着 Route kind，防不同协议对象误接到同一数据面解释器。
///
/// 参数说明：`listener` 提供可选 kinds；`protocol` 决定缺省 kind。
///
/// 返回：返回与 listener protocol 兼容的 kind 集合，并标记被忽略的非法 kind；仅结构超限时
/// 拒绝候选，确保单个非法声明不会阻断其余对象的状态发布与数据面更新。
fn parse_allowed_kinds(listener: &Value, protocol: &str) -> anyhow::Result<AllowedRouteKinds> {
    let defaults = match protocol {
        "HTTP" | "HTTPS" => vec!["HTTPRoute", "GRPCRoute"],
        "TLS" => vec!["TLSRoute"],
        "TCP" => vec!["TCPRoute"],
        "UDP" => vec!["UDPRoute"],
        _ => Vec::new(),
    };
    let Some(kinds) = listener
        .pointer("/allowedRoutes/kinds")
        .and_then(Value::as_array)
    else {
        return Ok(AllowedRouteKinds {
            supported: defaults.into_iter().map(str::to_owned).collect(),
            has_invalid: false,
        });
    };
    anyhow::ensure!(
        kinds.len() <= 16,
        "Gateway listener supports at most 16 route kinds"
    );
    let mut supported = BTreeSet::new();
    let mut has_invalid = false;
    for route_kind in kinds {
        let group = route_kind
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("gateway.networking.k8s.io");
        let kind = route_kind.get("kind").and_then(Value::as_str);
        if group == "gateway.networking.k8s.io" && kind.is_some_and(|kind| defaults.contains(&kind))
        {
            supported.insert(kind.expect("kind was checked above").to_owned());
        } else {
            // 非法 Route kind 只能关闭该 kind 的附着权限；若让错误上抛到整轮 reconcile，
            // 其它 Gateway 会继续承载旧路由且当前对象无法得到 InvalidRouteKinds 状态。
            has_invalid = true;
        }
    }
    Ok(AllowedRouteKinds {
        supported,
        has_invalid,
    })
}

/// 业务作用：按 parentRef、sectionName、allowedKinds 与 namespace policy 计算 Route 的授权 listener。
///
/// 参数说明：`route` 是任意 Gateway Route；`route_namespace`/`route_kind` 是可信对象身份；
/// `gateways` 与 `namespaces` 是同轮完整目录。
///
/// 返回：返回所有明确授权且协议匹配的 listener；坏 parentRef 结构返回错误。
fn attached_listeners(
    route: &Value,
    route_namespace: &str,
    route_kind: &str,
    gateways: &GatewayCatalog,
    namespaces: &NamespaceCatalog,
) -> anyhow::Result<Vec<AttachedListener>> {
    let parents = route
        .pointer("/spec/parentRefs")
        .and_then(Value::as_array)
        .context("Gateway Route missing spec.parentRefs")?;
    let mut attached = Vec::new();
    for parent in parents {
        let group = parent
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("gateway.networking.k8s.io");
        let kind = parent
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Gateway");
        let gateway_parent =
            group == "gateway.networking.k8s.io" && matches!(kind, "Gateway" | "ListenerSet");
        let mesh_parent = (group.is_empty() && kind == "Service")
            || (group == "multicluster.x-k8s.io" && kind == "ServiceImport");
        if !gateway_parent && !mesh_parent {
            continue;
        }
        let name = parent
            .get("name")
            .and_then(Value::as_str)
            .context("Gateway Route parentRef missing name")?;
        let namespace = parent
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(route_namespace);
        let parent_exists = match kind {
            "Gateway" => gateways
                .gateways
                .contains(&(namespace.to_owned(), name.to_owned())),
            "ListenerSet" => gateways
                .listener_sets
                .contains(&(namespace.to_owned(), name.to_owned())),
            "Service" | "ServiceImport" => gateways.mesh_parents.contains(&(
                group.to_owned(),
                kind.to_owned(),
                namespace.to_owned(),
                name.to_owned(),
            )),
            _ => false,
        };
        if !parent_exists || (mesh_parent && !gateways.mesh_interception_ready) {
            continue;
        }
        let section = parent.get("sectionName").and_then(Value::as_str);
        let port = parent.get("port").and_then(Value::as_u64);
        for listener in gateways.listeners.iter().filter(|listener| {
            listener.parent_group == group
                && listener.parent_kind == kind
                && listener.parent_namespace == namespace
                && listener.parent_name == name
                && section.is_none_or(|section| section == listener.section_name)
                && port.is_none_or(|port| port == u64::from(listener.parent_port))
                && listener.allowed_kinds.contains(route_kind)
        }) {
            if namespace_policy_allows(
                &listener.allowed_namespaces,
                &listener.parent_namespace,
                route_namespace,
                namespaces,
            )? {
                attached.push(AttachedListener {
                    listener: listener.clone(),
                });
            }
        }
    }
    attached.sort_by(|left, right| {
        (
            left.listener.gateway_namespace.as_str(),
            left.listener.parent_group.as_str(),
            left.listener.parent_kind.as_str(),
            left.listener.parent_namespace.as_str(),
            left.listener.parent_name.as_str(),
            left.listener.section_name.as_str(),
        )
            .cmp(&(
                right.listener.gateway_namespace.as_str(),
                right.listener.parent_group.as_str(),
                right.listener.parent_kind.as_str(),
                right.listener.parent_namespace.as_str(),
                right.listener.parent_name.as_str(),
                right.listener.section_name.as_str(),
            ))
    });
    attached.dedup_by(|left, right| {
        left.listener.parent_group == right.listener.parent_group
            && left.listener.parent_kind == right.listener.parent_kind
            && left.listener.parent_namespace == right.listener.parent_namespace
            && left.listener.parent_name == right.listener.parent_name
            && left.listener.section_name == right.listener.section_name
            && left.listener.hostname == right.listener.hostname
    });
    Ok(attached)
}

/// 业务作用：区分“parent 不存在/section/port 不匹配”和“listener 存在但策略拒绝”，
/// 以 Gateway API 标准 reason 暴露真实附件门禁。
///
/// 参数说明：Route 身份与 Gateway/Namespace 目录来自同轮快照，`route_kind` 决定
/// allowedRoutes kind 判定。
///
/// 返回：至少一个目标 listener 因 kind 或 namespace policy 拒绝时返回
/// `NotAllowedByListeners`；没有目标 listener 时返回 `NoMatchingParent`；坏引用返回错误。
fn attachment_rejection_reason(
    route: &Value,
    route_namespace: &str,
    route_kind: &str,
    gateways: &GatewayCatalog,
    namespaces: &NamespaceCatalog,
) -> anyhow::Result<&'static str> {
    let parents = route
        .pointer("/spec/parentRefs")
        .and_then(Value::as_array)
        .context("Gateway Route missing spec.parentRefs")?;
    for parent in parents {
        let group = parent
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("gateway.networking.k8s.io");
        let kind = parent
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Gateway");
        let gateway_parent =
            group == "gateway.networking.k8s.io" && matches!(kind, "Gateway" | "ListenerSet");
        let mesh_parent = (group.is_empty() && kind == "Service")
            || (group == "multicluster.x-k8s.io" && kind == "ServiceImport");
        if !gateway_parent && !mesh_parent {
            continue;
        }
        let name = parent
            .get("name")
            .and_then(Value::as_str)
            .context("Gateway Route parentRef missing name")?;
        let namespace = parent
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(route_namespace);
        let parent_exists = match kind {
            "Gateway" => gateways
                .gateways
                .contains(&(namespace.to_owned(), name.to_owned())),
            "ListenerSet" => gateways
                .listener_sets
                .contains(&(namespace.to_owned(), name.to_owned())),
            "Service" | "ServiceImport" => gateways.mesh_parents.contains(&(
                group.to_owned(),
                kind.to_owned(),
                namespace.to_owned(),
                name.to_owned(),
            )),
            _ => false,
        };
        if !parent_exists {
            continue;
        }
        if mesh_parent && !gateways.mesh_interception_ready {
            return Ok("UnsupportedValue");
        }
        let section = parent.get("sectionName").and_then(Value::as_str);
        let port = parent.get("port").and_then(Value::as_u64);
        for listener in gateways.listeners.iter().filter(|listener| {
            listener.parent_group == group
                && listener.parent_kind == kind
                && listener.parent_namespace == namespace
                && listener.parent_name == name
                && section.is_none_or(|section| section == listener.section_name)
                && port.is_none_or(|port| port == u64::from(listener.parent_port))
        }) {
            let namespace_allowed = namespace_policy_allows(
                &listener.allowed_namespaces,
                &listener.parent_namespace,
                route_namespace,
                namespaces,
            )?;
            if !listener.allowed_kinds.contains(route_kind) || !namespace_allowed {
                return Ok("NotAllowedByListeners");
            }
        }
    }
    Ok("NoMatchingParent")
}

/// 业务作用：执行 Gateway API namespace selector，避免缺失 namespace 证据时放宽跨租户附着。
///
/// 参数说明：`policy` 是 listener 已编译策略；`gateway_namespace` 与 `route_namespace` 是两端身份；
/// `catalog` 是同轮 Namespace label 事实源。
///
/// 返回：明确满足策略时返回 true；Selector 引用缺失 namespace 或非法表达式时失败闭合。
fn namespace_policy_allows(
    policy: &AllowedNamespaces,
    gateway_namespace: &str,
    route_namespace: &str,
    catalog: &NamespaceCatalog,
) -> anyhow::Result<bool> {
    match policy {
        AllowedNamespaces::Same => Ok(gateway_namespace == route_namespace),
        AllowedNamespaces::All => Ok(true),
        AllowedNamespaces::Selector(selector) => {
            let labels = catalog
                .labels
                .get(route_namespace)
                .with_context(|| format!("Namespace `{route_namespace}` missing from LIST"))?;
            label_selector_matches(selector, labels)
        }
    }
}

/// 业务作用：实现 Kubernetes LabelSelector 的 matchLabels/matchExpressions 核心语义。
///
/// 参数说明：`selector` 是 API 对象中的 LabelSelector；`labels` 是目标 namespace 的冻结标签。
///
/// 返回：所有 selector 条件满足时为 true；未知 operator 或坏结构返回错误。
fn label_selector_matches(
    selector: &Value,
    labels: &BTreeMap<String, String>,
) -> anyhow::Result<bool> {
    if let Some(match_labels) = selector.get("matchLabels").and_then(Value::as_object) {
        for (key, expected) in match_labels {
            let expected = expected
                .as_str()
                .context("LabelSelector matchLabels value must be a string")?;
            if labels.get(key).map(String::as_str) != Some(expected) {
                return Ok(false);
            }
        }
    }
    for expression in selector
        .get("matchExpressions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let key = expression
            .get("key")
            .and_then(Value::as_str)
            .context("LabelSelector expression missing key")?;
        let operator = expression
            .get("operator")
            .and_then(Value::as_str)
            .context("LabelSelector expression missing operator")?;
        let values = expression
            .get("values")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .context("LabelSelector expression value must be a string")
                    })
                    .collect::<anyhow::Result<HashSet<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let matches = match operator {
            "In" => labels.get(key).is_some_and(|value| values.contains(value)),
            "NotIn" => labels.get(key).is_none_or(|value| !values.contains(value)),
            "Exists" => labels.contains_key(key),
            "DoesNotExist" => !labels.contains_key(key),
            other => bail!("LabelSelector operator `{other}` is unsupported"),
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 业务作用：规范化 Gateway hostname 并验证 wildcard 只出现在最左标签。
///
/// 参数说明：`hostname` 是 Gateway/Route 声明的 DNS hostname。
///
/// 返回：合法时返回小写且去除尾点的值，否则拒绝候选。
fn normalize_hostname(hostname: &str) -> anyhow::Result<String> {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let dns = normalized.strip_prefix("*.").unwrap_or(&normalized);
    validate_kubernetes_name("Gateway API hostname", dns)?;
    anyhow::ensure!(
        !dns.contains('*') && normalized.len() <= 253,
        "Gateway API hostname wildcard is invalid"
    );
    Ok(normalized)
}

/// 业务作用：求 Route hostname 与所有已授权 listener hostname 的安全交集。
///
/// 参数说明：`route` 提供可选 spec.hostnames；`listeners` 是通过 parent/namespace 门的 listener。
///
/// 返回：返回最具体且去重的 hostname；空集合表示无 hostname 限制或不存在交集，由第二个值区分。
fn intersect_route_hostnames(
    route: &Value,
    listeners: &[AttachedListener],
) -> anyhow::Result<(Vec<String>, bool)> {
    let route_hostnames = normalized_route_hostnames(route)?;
    let mut output = BTreeSet::new();
    let mut unrestricted = false;
    for listener in listeners {
        match listener.listener.hostname.as_deref() {
            None if route_hostnames.is_empty() => unrestricted = true,
            None => output.extend(route_hostnames.iter().cloned()),
            Some(listener_hostname) if route_hostnames.is_empty() => {
                output.insert(listener_hostname.to_owned());
            }
            Some(listener_hostname) => {
                for route_hostname in &route_hostnames {
                    if let Some(hostname) = hostname_intersection(listener_hostname, route_hostname)
                    {
                        output.insert(hostname);
                    }
                }
            }
        }
    }
    Ok((output.into_iter().collect(), unrestricted))
}

/// 业务作用：规范化 Route 声明的 hostname 集合，供 listener 接纳与最终 Host predicate
/// 使用同一份协议语义。
///
/// 参数说明：`route` 是 HTTPRoute、GRPCRoute 或 TLSRoute 对象。
///
/// 返回：没有声明时返回空集合；非法类型、DNS 名或 wildcard 返回错误并拒绝该对象。
fn normalized_route_hostnames(route: &Value) -> anyhow::Result<Vec<String>> {
    Ok(route
        .pointer("/spec/hostnames")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .context("Gateway Route hostname must be a string")
                        .and_then(normalize_hostname)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default())
}

/// 业务作用：从已通过 parent/namespace/kind 门禁的 listener 中剔除与 Route hostname
/// 无交集者，避免状态计数与实际可路由范围分裂。
///
/// 参数说明：`route` 提供可选 hostnames；`listeners` 是上一阶段的授权候选。
///
/// 返回：返回真正接纳 Route 的 listener；坏 hostname 返回错误并拒绝该对象。
fn listeners_with_hostname_intersection(
    route: &Value,
    listeners: &[AttachedListener],
) -> anyhow::Result<Vec<AttachedListener>> {
    let route_hostnames = normalized_route_hostnames(route)?;
    if route_hostnames.is_empty() {
        return Ok(listeners.to_vec());
    }
    let mut accepted = Vec::new();
    for listener in listeners {
        let intersects = listener
            .listener
            .hostname
            .as_deref()
            .is_none_or(|hostname| {
                route_hostnames
                    .iter()
                    .any(|route_hostname| hostname_intersection(hostname, route_hostname).is_some())
            });
        if intersects {
            accepted.push(listener.clone());
        }
    }
    Ok(accepted)
}

/// 业务作用：计算两个已规范化 Gateway hostname pattern 的最具体交集。
///
/// 参数说明：`left` 与 `right` 是 exact hostname 或最左 `*.` wildcard。
///
/// 返回：有交集时返回最具体 pattern，无交集时返回 None。
fn hostname_intersection(left: &str, right: &str) -> Option<String> {
    match (left.strip_prefix("*."), right.strip_prefix("*.")) {
        (None, None) => left.eq_ignore_ascii_case(right).then(|| left.to_owned()),
        (Some(suffix), None) => hostname_matches_wildcard(right, suffix).then(|| right.to_owned()),
        (None, Some(suffix)) => hostname_matches_wildcard(left, suffix).then(|| left.to_owned()),
        (Some(left_suffix), Some(right_suffix)) => {
            if left_suffix == right_suffix || left_suffix.ends_with(&format!(".{right_suffix}")) {
                Some(left.to_owned())
            } else if right_suffix.ends_with(&format!(".{left_suffix}")) {
                Some(right.to_owned())
            } else {
                None
            }
        }
    }
}

/// 业务作用：判断 exact hostname 是否落在 Gateway wildcard 后缀内。
///
/// 参数说明：`hostname` 是 exact 值；`suffix` 是去掉 `*.` 的规范化后缀。
///
/// 返回：至少存在一个额外左侧标签且后缀一致时为 true。
fn hostname_matches_wildcard(hostname: &str, suffix: &str) -> bool {
    hostname
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

/// 业务作用：按实际 HTTP socket 对已接纳 listener 分组，使同一 Route 在每个端口上只获得
/// 该端口 listener 的 hostname 权限，避免跨端口合并 hostname 后扩大路由范围。
///
/// 参数说明：`listeners` 是已通过 parent、namespace、kind 与 hostname 接纳门禁的 listener。
///
/// 返回：返回稳定排序的 socket 到 listener 集合映射；同 socket 的多个 listener 保留供协议交集计算。
fn group_http_listeners(
    listeners: &[AttachedListener],
) -> BTreeMap<HttpListenerKey, Vec<AttachedListener>> {
    let mut groups = BTreeMap::new();
    for attached in listeners {
        groups
            .entry(HttpListenerKey {
                protocol: attached.listener.protocol.clone(),
                bind_address: attached.listener.bind_address.clone(),
                port: attached.listener.port,
            })
            .or_insert_with(Vec::new)
            .push(attached.clone());
    }
    groups
}

/// 业务作用：为 Gateway listener 所属的 socket hostname 权威桶生成跨轮询稳定标识，
/// 同时供路由 predicate 与请求层 listener 选择表使用。
///
/// 参数说明：`listener` 是已通过冲突裁决的 Gateway listener。
///
/// 返回：返回长度受稳定 ID 编码约束的权威桶身份；同 socket、同 hostname 的多个
/// Gateway listener 返回相同值，因为数据面无法从请求中区分这些对象。
fn gateway_listener_id(listener: &GatewayListener) -> String {
    let port = listener.port.to_string();
    stable_id(
        "gateway-listener",
        &[
            listener.protocol.as_str(),
            listener.bind_address.as_str(),
            port.as_str(),
            listener.hostname.as_deref().unwrap_or(""),
        ],
    )
}

/// 业务作用：把同 socket 的 Route 限定到其实际附着 listener，防止较宽 wildcard
/// route 在 Host 已选中更具体 listener 后继续越权匹配。
///
/// 参数说明：`routes` 是单个 listener hostname 交集生成的 Route IR；`listener_id`
/// 必须与运行期 socket 选择表使用同一稳定身份。
///
/// 返回：所有 Route 都具有合法 id/predicates 时写入内部 listener predicate 并成功；
/// IR 结构异常时拒绝整轮候选。
fn scope_routes_to_gateway_listener(routes: &mut [Value], listener_id: &str) -> anyhow::Result<()> {
    for route in routes {
        let original_id = route
            .get("id")
            .and_then(Value::as_str)
            .context("generated Gateway route missing id")?;
        route["id"] = Value::String(stable_id("gateway-route", &[original_id, listener_id]));
        route
            .get_mut("predicates")
            .and_then(Value::as_array_mut)
            .context("generated Gateway route missing predicates")?
            .push(Value::String(format!(
                "Header=x-naway-gateway-listener,exact,{listener_id}"
            )));
    }
    Ok(())
}

/// 业务作用：区分 Mesh parent 与 Gateway/ListenerSet parent，确保两类 listener
/// 使用各自的隔离凭据和状态语义。
///
/// 参数说明：`listener` 是已解析的合成或真实 listener。
///
/// 返回：Service 或 ServiceImport parent 返回 true。
fn is_mesh_listener(listener: &GatewayListener) -> bool {
    (listener.parent_group.is_empty() && listener.parent_kind == "Service")
        || (listener.parent_group == "multicluster.x-k8s.io"
            && listener.parent_kind == "ServiceImport")
}

/// 业务作用：把 Mesh Route 限定到目标 Service，并为 consumer Route 增加受信源 namespace
/// 门禁，防止其它 namespace 借同一透明 listener 越权使用规则。
///
/// 参数说明：`routes` 是单个 mesh parent 产生的 IR；`listener` 固定目标身份；
/// `route_namespace` 区分 producer/consumer；`source_header` 只在受保护 listener 上可信。
///
/// 返回：所有 Route 结构完整时写入稳定 parent 身份；consumer 额外写入 namespace predicate。
fn scope_routes_to_mesh_parent(
    routes: &mut [Value],
    listener: &GatewayListener,
    route_namespace: &str,
    source_header: &str,
) -> anyhow::Result<()> {
    for route in routes {
        let original_id = route
            .get("id")
            .and_then(Value::as_str)
            .context("generated Mesh route missing id")?;
        route["id"] = Value::String(stable_id(
            "mesh-route",
            &[
                original_id,
                listener.parent_group.as_str(),
                listener.parent_kind.as_str(),
                listener.parent_namespace.as_str(),
                listener.parent_name.as_str(),
                listener.section_name.as_str(),
                &listener.parent_port.to_string(),
            ],
        ));
        if route_namespace != listener.parent_namespace {
            route
                .get_mut("predicates")
                .and_then(Value::as_array_mut)
                .context("generated Mesh route missing predicates")?
                .push(Value::String(format!(
                    "Header={source_header},exact,{route_namespace}"
                )));
        }
    }
    Ok(())
}

/// 业务作用：提供 Gateway listener 冲突解析的稳定对象顺序，不依赖 API LIST 返回顺序。
///
/// 参数说明：`object` 是 Kubernetes 对象。
///
/// 返回：返回 creationTimestamp、namespace、name 组成的稳定排序键。
fn object_order_key(object: &Value) -> (String, String, String) {
    (
        object
            .pointer("/metadata/creationTimestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        object
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_owned(),
        object
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    )
}

/// 业务作用：把 HTTPRoute 的匹配、标准 filter 与带权 backendRefs 展开为统一 Route IR。
///
/// 参数说明：目录参数均来自同轮 LIST；`routes` 与 `services` 接收候选，不直接发布数据面。
///
/// 返回：全部授权引用可解析时成功；无授权 parent 的对象被忽略，非法已接管对象失败闭合。
#[allow(clippy::too_many_arguments)]
fn compile_http_routes(
    value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    gateways: &GatewayCatalog,
    namespaces: &NamespaceCatalog,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    inference_pools: Option<&InferencePoolCatalog>,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    listener_routes: &mut BTreeMap<HttpListenerKey, Vec<Value>>,
    services: &mut BTreeMap<String, Value>,
    diagnostics: &mut Vec<RouteDiagnostic>,
) -> anyhow::Result<()> {
    let mut objects = resource_items(value, cfg.max_objects, "HTTPRoute")?
        .iter()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object_order_key(object));
    for route in objects {
        let (namespace, name) = object_identity(route, "HTTPRoute")?;
        if !namespace_allowed(cfg, namespace)
            || route.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let attached = attached_listeners(route, namespace, "HTTPRoute", gateways, namespaces)?;
        if attached.is_empty() {
            let reason =
                attachment_rejection_reason(route, namespace, "HTTPRoute", gateways, namespaces)?;
            diagnostics.push(RouteDiagnostic::new(
                route,
                "gateway.networking.k8s.io/v1",
                "HTTPRoute",
                "httproutes",
                false,
                true,
                reason,
                if reason == "NotAllowedByListeners" {
                    "matching listeners reject this Route kind or namespace"
                } else {
                    "no listener matched parentRefs sectionName or port"
                },
            ));
            continue;
        }
        let attached = listeners_with_hostname_intersection(route, &attached)?;
        if attached.is_empty() {
            diagnostics.push(RouteDiagnostic::new(
                route,
                "gateway.networking.k8s.io/v1",
                "HTTPRoute",
                "httproutes",
                false,
                true,
                "NoMatchingListenerHostname",
                "route hostnames do not intersect any permitted listener hostname",
            ));
            continue;
        }
        let mut object_services = BTreeMap::new();
        let mut routes_by_listener = BTreeMap::new();
        let compile_result = (|| -> anyhow::Result<Option<String>> {
            let rules = route
                .pointer("/spec/rules")
                .and_then(Value::as_array)
                .context("selected HTTPRoute missing spec.rules")?;
            anyhow::ensure!(
                rules.len() <= 64,
                "HTTPRoute {namespace}/{name} exceeds 64 rules"
            );
            let mut first_error = None;
            // socket 之间独立求交集，同 socket 内再按逻辑 listener 编译并加内部身份
            // predicate；这样端口之间不串 hostname，较宽 wildcard 也不能抢走更具体 listener 的请求。
            for (key, listener_group) in group_http_listeners(&attached) {
                let socket_routes = routes_by_listener.entry(key).or_insert_with(Vec::new);
                let mut compiled_listener_ids = BTreeSet::new();
                for attached_listener in listener_group {
                    let (hostnames, unrestricted_hostname) =
                        intersect_route_hostnames(route, std::slice::from_ref(&attached_listener))?;
                    let listener_id = gateway_listener_id(&attached_listener.listener);
                    // 一个 Route 可通过多个 parentRef 附着到网络层等价的 listener；重复
                    // 编译会制造同 ID route，并使选择顺序依赖 Kubernetes LIST 顺序。
                    if !compiled_listener_ids.insert(listener_id.clone()) {
                        continue;
                    }
                    let mut object_routes = Vec::new();
                    for (rule_index, rule) in rules.iter().enumerate() {
                        let mut rule_routes = Vec::new();
                        let mut rule_services = BTreeMap::new();
                        match compile_http_route_rule(
                            rule,
                            namespace,
                            name,
                            rule_index,
                            &hostnames,
                            unrestricted_hostname,
                            service_catalog,
                            service_import_catalog,
                            inference_pools,
                            backend_traffic,
                            grants,
                            &mut rule_routes,
                            &mut rule_services,
                        ) {
                            Ok(()) => {
                                merge_generated_services(&mut object_services, rule_services)?;
                                object_routes.extend(rule_routes);
                            }
                            Err(error) => {
                                let message = error.to_string();
                                if first_error.is_none() {
                                    first_error = Some(message);
                                }
                                // 已接纳但无效的 rule 必须保留匹配面并本地返回 500；只移除
                                // 该 rule 会把请求落到较宽 sibling/default route，形成越权转发。
                                if let Ok(mut fallback) = compile_invalid_http_rule_routes(
                                    rule,
                                    namespace,
                                    name,
                                    rule_index,
                                    &hostnames,
                                    unrestricted_hostname,
                                ) {
                                    object_routes.append(&mut fallback);
                                }
                            }
                        }
                    }
                    if is_mesh_listener(&attached_listener.listener) {
                        scope_routes_to_mesh_parent(
                            &mut object_routes,
                            &attached_listener.listener,
                            namespace,
                            &gateways.mesh_source_namespace_header,
                        )?;
                    } else {
                        scope_routes_to_gateway_listener(&mut object_routes, &listener_id)?;
                    }
                    socket_routes.extend(object_routes);
                }
            }
            Ok(first_error)
        })();
        match compile_result {
            Ok(first_error) => {
                merge_generated_services(services, object_services)?;
                for (key, object_routes) in routes_by_listener {
                    listener_routes
                        .entry(key)
                        .or_default()
                        .extend(object_routes);
                }
                let (resolved, reason, message) = match first_error {
                    Some(message) => (false, diagnostic_reason(&message), message),
                    None => (
                        true,
                        "ResolvedRefs",
                        "all parent and backend references resolved".to_owned(),
                    ),
                };
                diagnostics.push(
                    RouteDiagnostic::new(
                        route,
                        "gateway.networking.k8s.io/v1",
                        "HTTPRoute",
                        "httproutes",
                        true,
                        resolved,
                        reason,
                        message,
                    )
                    .with_attached_listeners(&attached),
                );
            }
            Err(error) => diagnostics.push(
                RouteDiagnostic::new(
                    route,
                    "gateway.networking.k8s.io/v1",
                    "HTTPRoute",
                    "httproutes",
                    true,
                    false,
                    diagnostic_reason(&error.to_string()),
                    error.to_string(),
                )
                .with_attached_listeners(&attached),
            ),
        }
    }
    Ok(())
}

/// 业务作用：把 HTTPRoute 的单条 rule 编译为可独立提交的路由与服务子候选，
/// 使坏 rule 不会撤销同一对象内的合法 sibling rule。
///
/// 参数说明：`rule`/`rule_index` 标识声明项；对象身份与 hostname 约束用于生成稳定
/// predicate/id；目录参数负责 filter/backend 判权；输出仅在本 rule 全部成功后由调用方合并。
///
/// 返回：所有 match、filter 与 backendRef 均有效时填充子候选并成功；任一项无效时
/// 返回错误，调用方丢弃整个子候选且发布精确 500 fallback。
#[allow(clippy::too_many_arguments)]
fn compile_http_route_rule(
    rule: &Value,
    namespace: &str,
    route_name: &str,
    rule_index: usize,
    hostnames: &[String],
    unrestricted_hostname: bool,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    inference_pools: Option<&InferencePoolCatalog>,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    routes: &mut Vec<Value>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    let (request_timeout_ms, backend_request_timeout_ms) = compile_http_timeouts(rule)?;
    let matches = rule
        .get("matches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![json!({})]);
    anyhow::ensure!(
        matches.len() <= 64,
        "HTTPRoute {namespace}/{route_name} rule exceeds 64 matches"
    );
    for (match_index, route_match) in matches.iter().enumerate() {
        let path = route_match
            .pointer("/path/value")
            .and_then(Value::as_str)
            .unwrap_or("/");
        let path_type = route_match
            .pointer("/path/type")
            .and_then(Value::as_str)
            .unwrap_or("PathPrefix");
        validate_http_path(path)?;
        let filter_plan = compile_http_filters(
            rule,
            namespace,
            route_name,
            "HTTPRoute",
            path,
            path_type,
            service_catalog,
            service_import_catalog,
            backend_traffic,
            grants,
            services,
        )?;
        let mut predicates = http_match_predicates(
            route_match,
            namespace,
            route_name,
            hostnames,
            unrestricted_hostname,
        )?;
        let order = gateway_route_order(path, path_type, route_match);
        if let Some(redirect) = filter_plan.gateway_redirect {
            anyhow::ensure!(
                rule.get("backendRefs")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "HTTPRoute {namespace}/{route_name} RequestRedirect cannot combine with backendRefs"
            );
            routes.push(json!({
                "id": stable_id("k8s-httproute-redirect", &[namespace, route_name, &rule_index.to_string(), &match_index.to_string(), path]),
                "predicates": predicates,
                "filters": filter_plan.filters,
                "gateway_redirect": redirect,
                "request_timeout_ms": request_timeout_ms,
                "backend_request_timeout_ms": backend_request_timeout_ms,
                "order": order
            }));
            continue;
        }
        let mut backends = compile_backend_refs(
            rule,
            namespace,
            route_name,
            "HTTPRoute",
            "http",
            None,
            service_catalog,
            service_import_catalog,
            inference_pools,
            backend_traffic,
            grants,
            services,
        )?;
        apply_inline_session_persistence(
            rule,
            namespace,
            route_name,
            "HTTPRoute",
            rule_index,
            normalized_path_element_prefix(path),
            &mut backends,
            services,
        )?;
        let group = stable_id(
            "gateway-weight",
            &[
                namespace,
                route_name,
                &rule_index.to_string(),
                &match_index.to_string(),
            ],
        );
        for (backend_index, backend) in backends.iter().enumerate() {
            if backends.len() > 1 {
                predicates.push(format!("Weight={group},{}", backend.weight));
            }
            let mut filters = filter_plan.filters.clone();
            filters.extend(backend.filters.iter().cloned());
            routes.push(json!({
                "id": stable_id("k8s-httproute", &[namespace, route_name, &rule_index.to_string(), &match_index.to_string(), &backend_index.to_string(), &backend.logical]),
                "uri": format!("lb://{}", backend.logical),
                "preserve_host": true,
                "predicates": predicates,
                "filters": filters,
                "inference_pool": backend.inference_pool,
                "ext_proc": backend.ext_proc,
                "request_timeout_ms": request_timeout_ms,
                "backend_request_timeout_ms": backend_request_timeout_ms,
                "order": order
            }));
            if backends.len() > 1 {
                predicates.pop();
            }
        }
    }
    Ok(())
}

/// 业务作用：为已接纳但无法编译的 HTTPRoute rule 生成同匹配面的本地 500 响应，
/// 防止请求穿透到更宽路由或错误返回 404。
///
/// 参数说明：`rule`/对象身份确定稳定 id 与匹配条件；`hostnames` 和
/// `unrestricted_hostname` 来自已接纳 listener 的交集。
///
/// 返回：match 仍可安全解析时返回一组无上游副作用的 500 mock route；match 本身
/// 非法时返回错误且不扩大任何路由范围。
fn compile_invalid_http_rule_routes(
    rule: &Value,
    namespace: &str,
    route_name: &str,
    rule_index: usize,
    hostnames: &[String],
    unrestricted_hostname: bool,
) -> anyhow::Result<Vec<Value>> {
    let matches = rule
        .get("matches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![json!({})]);
    anyhow::ensure!(
        matches.len() <= 64,
        "HTTPRoute {namespace}/{route_name} invalid rule exceeds 64 matches"
    );
    let mut routes = Vec::with_capacity(matches.len());
    for (match_index, route_match) in matches.iter().enumerate() {
        let path = route_match
            .pointer("/path/value")
            .and_then(Value::as_str)
            .unwrap_or("/");
        let path_type = route_match
            .pointer("/path/type")
            .and_then(Value::as_str)
            .unwrap_or("PathPrefix");
        validate_http_path(path)?;
        let predicates = http_match_predicates(
            route_match,
            namespace,
            route_name,
            hostnames,
            unrestricted_hostname,
        )?;
        routes.push(json!({
            "id": stable_id("k8s-httproute-invalid", &[namespace, route_name, &rule_index.to_string(), &match_index.to_string(), path]),
            "predicates": predicates,
            "mock_response": {"status": 500, "body": ""},
            "order": gateway_route_order(path, path_type, route_match)
        }));
    }
    Ok(routes)
}

/// 业务作用：把 HTTPRoute 单个 match 转为与其它配置源共用的 predicate DSL。
///
/// 参数说明：`route_match` 是单条 match；对象身份用于诊断；`hostnames` 是 listener 交集；
/// `unrestricted_hostname` 表示至少一个 listener 没有 hostname 门。
///
/// 返回：所有 path/method/header/query 匹配可无损表达时返回 predicate 列表。
fn http_match_predicates(
    route_match: &Value,
    namespace: &str,
    name: &str,
    hostnames: &[String],
    unrestricted_hostname: bool,
) -> anyhow::Result<Vec<String>> {
    let path = route_match
        .pointer("/path/value")
        .and_then(Value::as_str)
        .unwrap_or("/");
    let path_type = route_match
        .pointer("/path/type")
        .and_then(Value::as_str)
        .unwrap_or("PathPrefix");
    let mut predicates = vec![path_predicate(path, path_type)?];
    if !unrestricted_hostname && !hostnames.is_empty() {
        predicates.push(format!("Host={}", hostnames.join(",")));
    }
    if let Some(method) = route_match.get("method").and_then(Value::as_str) {
        predicates.push(format!("Method={method}"));
    }
    append_http_route_header_matches(route_match, namespace, name, &mut predicates)?;
    append_http_route_query_matches(route_match, namespace, name, &mut predicates)?;
    Ok(predicates)
}

/// 业务作用：为 Gateway API 路由计算稳定优先级，使 exact、长 path 和更多匹配条件优先。
///
/// 参数说明：`path`/`path_type` 是标准 path match；`route_match` 提供 method/header/query 数量。
///
/// 返回：返回越具体越小的 order，且不会因对象 LIST 顺序改变。
fn gateway_route_order(path: &str, path_type: &str, route_match: &Value) -> i32 {
    let exact = i32::from(path_type == "Exact");
    let path_chars = i32::try_from(path.len().min(4096)).unwrap_or(4096);
    let method = i32::from(route_match.get("method").is_some());
    let headers = route_match
        .get("headers")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let query = route_match
        .get("queryParams")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let headers = i32::try_from(headers.min(16)).unwrap_or(16);
    let query = i32::try_from(query.min(16)).unwrap_or(16);
    // 每一层基数都大于下一层的最大值，严格保持 exact、path 长度、method、header 数、
    // query 数的规范优先级；不能用简单加权，否则根路径 method 会压过更长的 path。
    let score = ((((exact * 4097 + path_chars) * 2 + method) * 17 + headers) * 17) + query;
    -score
}

/// 业务作用：把 HTTPRoute rule 的总请求与单次上游时限编译成 route deadline，
/// 并在发布前固定零值关闭和上下界关系。
///
/// 参数说明：`rule` 是单条 HTTPRouteRule，timeouts 缺失表示沿用实现默认。
///
/// 返回：返回 request/backendRequest 的可选毫秒值；格式非法、溢出或 backendRequest
/// 大于非零 request 时拒绝当前 rule。
fn compile_http_timeouts(rule: &Value) -> anyhow::Result<(Option<u64>, Option<u64>)> {
    let Some(timeouts) = rule.get("timeouts") else {
        return Ok((None, None));
    };
    let timeouts = timeouts
        .as_object()
        .context("HTTPRoute timeouts must be an object")?;
    for field in timeouts.keys() {
        anyhow::ensure!(
            matches!(field.as_str(), "request" | "backendRequest"),
            "HTTPRoute timeouts contains unknown field `{field}`"
        );
    }
    let request = timeouts
        .get("request")
        .map(|value| {
            value
                .as_str()
                .context("HTTPRoute timeouts.request must be a duration string")
                .and_then(parse_gateway_duration_ms)
        })
        .transpose()?;
    let backend = timeouts
        .get("backendRequest")
        .map(|value| {
            value
                .as_str()
                .context("HTTPRoute timeouts.backendRequest must be a duration string")
                .and_then(parse_gateway_duration_ms)
        })
        .transpose()?;
    if let (Some(request), Some(backend)) = (request, backend) {
        anyhow::ensure!(
            request == 0 || backend <= request,
            "HTTPRoute backendRequest timeout cannot exceed request timeout"
        );
    }
    Ok((request, backend))
}

/// 业务作用：解析 Gateway API Duration 的严格子集，避免宽松 duration parser 接受
/// 负数、小数或协议未声明单位。
///
/// 参数说明：`raw` 必须由一到四个 `1..=5` 位整数与 h/m/s/ms 单位组成。
///
/// 返回：返回 checked 累加后的毫秒值；空串、坏单位、组件过多或算术溢出均失败。
fn parse_gateway_duration_ms(raw: &str) -> anyhow::Result<u64> {
    let bytes = raw.as_bytes();
    let mut index = 0_usize;
    let mut components = 0_usize;
    let mut total = 0_u64;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        anyhow::ensure!(
            index > start && index - start <= 5,
            "Gateway API duration `{raw}` has an invalid number"
        );
        let number = raw[start..index]
            .parse::<u64>()
            .context("parse Gateway API duration number")?;
        let multiplier = if raw[index..].starts_with("ms") {
            index += 2;
            1_u64
        } else if index < bytes.len() {
            let multiplier = match bytes[index] {
                b'h' => 3_600_000_u64,
                b'm' => 60_000_u64,
                b's' => 1_000_u64,
                _ => bail!("Gateway API duration `{raw}` has an invalid unit"),
            };
            index += 1;
            multiplier
        } else {
            bail!("Gateway API duration `{raw}` is missing a unit");
        };
        components += 1;
        anyhow::ensure!(
            components <= 4,
            "Gateway API duration `{raw}` exceeds four components"
        );
        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .context("Gateway API duration component overflow")?,
            )
            .context("Gateway API duration overflow")?;
    }
    anyhow::ensure!(components > 0, "Gateway API duration cannot be empty");
    Ok(total)
}

/// 业务作用：把 Gateway API HTTPRoute 标准 filter 编译到统一 header/path/mirror/redirect 计划。
///
/// 参数说明：`rule` 是单条 HTTPRoute rule；对象与 path 信息用于引用授权和 prefix rewrite；
/// 目录参数用于解析 mirror backend；`services` 接收镜像服务 IR。
///
/// 返回：所有 filter 均受支持且组合无歧义时返回计划；ExtensionRef/未知 filter 失败闭合。
#[allow(clippy::too_many_arguments)]
fn compile_http_filters(
    rule: &Value,
    namespace: &str,
    route_name: &str,
    route_kind: &str,
    matched_path: &str,
    matched_path_type: &str,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<HttpFilterPlan> {
    let filters = rule
        .get("filters")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(
        filters.len() <= 16,
        "{route_kind} {namespace}/{route_name} exceeds 16 filters"
    );
    let mut plan = HttpFilterPlan::default();
    let mut seen = HashSet::new();
    for filter in filters {
        let filter_type = filter
            .get("type")
            .and_then(Value::as_str)
            .context("Gateway API filter missing type")?;
        if filter_type != "RequestMirror" {
            anyhow::ensure!(
                seen.insert(filter_type.to_owned()),
                "{route_kind} {namespace}/{route_name} repeats filter type `{filter_type}`"
            );
        }
        match filter_type {
            "RequestHeaderModifier" => compile_header_modifier(
                filter
                    .get("requestHeaderModifier")
                    .context("RequestHeaderModifier body missing")?,
                true,
                &mut plan.filters,
            )?,
            "ResponseHeaderModifier" => compile_header_modifier(
                filter
                    .get("responseHeaderModifier")
                    .context("ResponseHeaderModifier body missing")?,
                false,
                &mut plan.filters,
            )?,
            "URLRewrite" => compile_url_rewrite(
                filter
                    .get("urlRewrite")
                    .context("URLRewrite body missing")?,
                matched_path,
                matched_path_type,
                &mut plan.filters,
            )?,
            "RequestRedirect" => {
                anyhow::ensure!(
                    plan.gateway_redirect.is_none(),
                    "{route_kind} {namespace}/{route_name} has multiple RequestRedirect filters"
                );
                plan.gateway_redirect = Some(compile_request_redirect(
                    filter
                        .get("requestRedirect")
                        .context("RequestRedirect body missing")?,
                    matched_path,
                    matched_path_type,
                )?);
            }
            "RequestMirror" => {
                let mirror = filter
                    .get("requestMirror")
                    .context("RequestMirror body missing")?;
                let backend = mirror
                    .get("backendRef")
                    .context("RequestMirror missing backendRef")?;
                let target = compile_backend_ref(
                    backend,
                    namespace,
                    route_name,
                    route_kind,
                    "http",
                    None,
                    service_catalog,
                    service_import_catalog,
                    None,
                    backend_traffic,
                    grants,
                    services,
                )?;
                let sample = mirror_sample(mirror)?;
                plan.filters.push(format!(
                    "mirror uri=lb://{} sample={sample} body=on max_body_bytes=1048576",
                    target.logical
                ));
            }
            "CORS" => {
                anyhow::ensure!(
                    route_kind == "HTTPRoute",
                    "{route_kind} {namespace}/{route_name} cannot use the HTTPRoute CORS filter"
                );
                plan.filters.push(compile_gateway_cors(
                    filter.get("cors").context("CORS body missing")?,
                )?);
            }
            "ExtensionRef" => {
                bail!("{route_kind} {namespace}/{route_name} ExtensionRef is unsupported")
            }
            other => bail!("{route_kind} {namespace}/{route_name} filter `{other}` is unsupported"),
        }
    }
    anyhow::ensure!(
        !(plan.gateway_redirect.is_some()
            && plan.filters.iter().any(|filter| {
                filter.starts_with("rewrite ") || filter.starts_with("gateway_rewrite_full_path ")
            })),
        "{route_kind} {namespace}/{route_name} cannot combine RequestRedirect with URLRewrite"
    );
    Ok(plan)
}

/// 业务作用：把标准 Gateway API CORS filter 编码为统一 route DSL，并在对象隔离阶段完成校验。
///
/// 参数说明：`cors` 是 HTTPRoute filter 的 `cors` 对象。
///
/// 返回：字段和协议约束合法时返回不可被变量展开的 base64url JSON 指令，否则拒绝当前对象。
fn compile_gateway_cors(cors: &Value) -> anyhow::Result<String> {
    let object = cors.as_object().context("CORS body must be an object")?;
    for key in object.keys() {
        anyhow::ensure!(
            matches!(
                key.as_str(),
                "allowOrigins"
                    | "allowMethods"
                    | "allowHeaders"
                    | "exposeHeaders"
                    | "allowCredentials"
                    | "maxAge"
            ),
            "CORS contains unknown field `{key}`"
        );
    }
    let origins = gateway_cors_array(object, "allowOrigins", 64)?;
    anyhow::ensure!(
        !(origins.iter().any(|origin| origin == "*") && origins.len() > 1),
        "CORS allowOrigins cannot combine `*` with other origins"
    );
    for origin in &origins {
        if origin != "*" {
            crate::routing::parse_gateway_cors_origin(origin)
                .with_context(|| format!("CORS allowOrigins contains `{origin}`"))?;
        }
    }
    let methods = gateway_cors_array(object, "allowMethods", 9)?;
    anyhow::ensure!(
        !(methods.iter().any(|method| method == "*") && methods.len() > 1),
        "CORS allowMethods cannot combine `*` with other methods"
    );
    for method in &methods {
        if method != "*" {
            http::Method::from_bytes(method.as_bytes())
                .with_context(|| format!("CORS allowMethods contains invalid `{method}`"))?;
        }
    }
    let allow_headers = gateway_cors_array(object, "allowHeaders", 64)?;
    let expose_headers = gateway_cors_array(object, "exposeHeaders", 64)?;
    for (field, headers) in [
        ("allowHeaders", allow_headers.as_slice()),
        ("exposeHeaders", expose_headers.as_slice()),
    ] {
        anyhow::ensure!(
            !(headers.iter().any(|header| header == "*") && headers.len() > 1),
            "CORS {field} cannot combine `*` with other headers"
        );
        for header in headers {
            if header != "*" {
                http::HeaderName::from_bytes(header.as_bytes())
                    .with_context(|| format!("CORS {field} contains invalid `{header}`"))?;
            }
        }
    }
    let allow_credentials = match object.get("allowCredentials") {
        Some(value) => value
            .as_bool()
            .context("CORS allowCredentials must be boolean")?,
        None => false,
    };
    let max_age = match object.get("maxAge") {
        Some(value) => {
            let seconds = value.as_u64().context("CORS maxAge must be an integer")?;
            anyhow::ensure!(
                seconds > 0 && seconds <= i32::MAX as u64,
                "CORS maxAge is out of range"
            );
            Some(seconds)
        }
        None => None,
    };
    let payload = json!({
        "allow_origins": origins,
        "allow_methods": methods,
        "allow_headers": allow_headers,
        "expose_headers": expose_headers,
        "allow_credentials": allow_credentials,
        "max_age": max_age.unwrap_or(5)
    });
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).context("encode CORS payload")?);
    Ok(format!("gateway_cors_b64 {encoded}"))
}

/// 业务作用：读取 Gateway API CORS 的有界字符串数组，使对象级诊断先于快照发布。
///
/// 参数说明：`object` 是 CORS 对象；`field` 是标准字段名；`max_items` 是 API 上限。
///
/// 返回：缺省字段返回空列表；类型、数量和元素长度合法时返回字符串列表。
fn gateway_cors_array(
    object: &serde_json::Map<String, Value>,
    field: &str,
    max_items: usize,
) -> anyhow::Result<Vec<String>> {
    let Some(value) = object.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .with_context(|| format!("CORS {field} must be an array"))?;
    anyhow::ensure!(
        values.len() <= max_items,
        "CORS {field} exceeds {max_items} items"
    );
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .with_context(|| format!("CORS {field} entry must be a string"))?;
            anyhow::ensure!(
                !value.is_empty() && value.len() <= 4096,
                "CORS {field} entry has invalid length"
            );
            Ok(value.to_owned())
        })
        .collect()
}

/// 业务作用：把 Gateway API RequestMirror 的 percent/fraction 转为统一 0..=1 采样率。
///
/// 参数说明：`mirror` 是 RequestMirror filter body；未声明比例表示镜像全部请求。
///
/// 返回：比例合法且不同时声明两种形式时返回采样率，否则拒绝候选。
fn mirror_sample(mirror: &Value) -> anyhow::Result<f64> {
    anyhow::ensure!(
        !(mirror.get("percent").is_some() && mirror.get("fraction").is_some()),
        "RequestMirror cannot combine percent and fraction"
    );
    if let Some(percent) = mirror.get("percent").and_then(Value::as_u64) {
        anyhow::ensure!(
            percent <= 100,
            "RequestMirror percent must be within 0..=100"
        );
        return Ok(percent as f64 / 100.0);
    }
    if let Some(fraction) = mirror.get("fraction") {
        let numerator = fraction
            .get("numerator")
            .and_then(Value::as_u64)
            .context("RequestMirror fraction missing numerator")?;
        let denominator = fraction
            .get("denominator")
            .and_then(Value::as_u64)
            .context("RequestMirror fraction missing denominator")?;
        anyhow::ensure!(
            denominator > 0 && numerator <= denominator,
            "RequestMirror fraction is invalid"
        );
        return Ok(numerator as f64 / denominator as f64);
    }
    Ok(1.0)
}

/// 业务作用：把标准 HeaderModifier 的 add/set/remove 精确编码为字面量操作，避免外部值获得模板能力。
///
/// 参数说明：`modifier` 是标准 filter body；`request` 区分请求与响应执行点；`output` 接收有序 DSL。
///
/// 返回：名称、值、条目数和 framing 安全门全部通过时成功，否则拒绝候选。
fn compile_header_modifier(
    modifier: &Value,
    request: bool,
    output: &mut Vec<String>,
) -> anyhow::Result<()> {
    let prefix = if request {
        "gateway_request_header"
    } else {
        "gateway_response_header"
    };
    let mut count = 0_usize;
    for (field, operation) in [("set", "set"), ("add", "add")] {
        for entry in modifier
            .get(field)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            count = count.saturating_add(1);
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .context("HeaderModifier entry missing name")?;
            let value = entry
                .get("value")
                .and_then(Value::as_str)
                .context("HeaderModifier entry missing value")?;
            validate_gateway_mutation_header(name, request)?;
            http::HeaderValue::from_str(value).context("HeaderModifier value is invalid")?;
            anyhow::ensure!(
                value.len() <= 8192,
                "HeaderModifier value exceeds 8192 bytes"
            );
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
            output.push(format!("{prefix}_{operation}_b64 {name} {encoded}"));
        }
    }
    for name in modifier
        .get("remove")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        count = count.saturating_add(1);
        let name = name
            .as_str()
            .context("HeaderModifier remove entry must be a string")?;
        validate_gateway_mutation_header(name, request)?;
        output.push(format!("{prefix}_remove {name}"));
    }
    anyhow::ensure!(count <= 32, "HeaderModifier supports at most 32 operations");
    Ok(())
}

/// 业务作用：阻止 Gateway API header mutation 改写 hop-by-hop、framing 与网关可信身份头。
///
/// 参数说明：`name` 是外部声明 header；`request` 区分请求侧的额外 Host/凭据禁区。
///
/// 返回：普通 end-to-end header 返回成功；危险 header 失败闭合。
fn validate_gateway_mutation_header(name: &str, request: bool) -> anyhow::Result<()> {
    let name = name
        .parse::<http::HeaderName>()
        .with_context(|| format!("HeaderModifier name `{name}` is invalid"))?;
    let forbidden = matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "te"
            | "trailer"
            | "x-client-cert-verified"
    ) || (request
        && matches!(
            name.as_str(),
            "authorization" | "proxy-authorization" | "cookie"
        ));
    anyhow::ensure!(
        !forbidden,
        "HeaderModifier cannot mutate protected header `{name}`"
    );
    Ok(())
}

/// 业务作用：把 URLRewrite 映射为现有 path prefix rewrite 与 Host set，不建立第二条转发路径。
///
/// 参数说明：`rewrite` 是 filter body；`matched_path`/`matched_path_type` 固定匹配边界；
/// `output` 接收统一 filter DSL。
///
/// 返回：hostname 与 path modifier 可无损表示时成功，否则拒绝候选。
fn compile_url_rewrite(
    rewrite: &Value,
    matched_path: &str,
    matched_path_type: &str,
    output: &mut Vec<String>,
) -> anyhow::Result<()> {
    if let Some(hostname) = rewrite.get("hostname").and_then(Value::as_str) {
        let hostname = normalize_hostname(hostname)?;
        anyhow::ensure!(
            !hostname.starts_with("*."),
            "URLRewrite hostname cannot be wildcard"
        );
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hostname);
        output.push(format!("gateway_request_header_set_b64 host {encoded}"));
    }
    if let Some(path) = rewrite.get("path") {
        let kind = path
            .get("type")
            .and_then(Value::as_str)
            .context("URLRewrite path missing type")?;
        match kind {
            "ReplaceFullPath" => {
                let replacement = path
                    .get("replaceFullPath")
                    .and_then(Value::as_str)
                    .context("URLRewrite ReplaceFullPath missing value")?;
                validate_http_path(replacement)?;
                output.push(format!("gateway_rewrite_full_path {replacement}"));
            }
            "ReplacePrefixMatch" => {
                anyhow::ensure!(
                    matched_path_type == "PathPrefix",
                    "URLRewrite ReplacePrefixMatch requires PathPrefix match"
                );
                let replacement = path
                    .get("replacePrefixMatch")
                    .and_then(Value::as_str)
                    .context("URLRewrite ReplacePrefixMatch missing value")?;
                validate_http_path(replacement)?;
                output.push(format!(
                    "rewrite {} {replacement}",
                    normalized_path_element_prefix(matched_path)
                ));
            }
            other => bail!("URLRewrite path type `{other}` is unsupported"),
        }
    }
    Ok(())
}

/// 业务作用：编译 RequestRedirect 的动态 authority/path 规则，保留未覆盖 path 与 query。
///
/// 参数说明：`redirect` 是 filter body；`matched_path`/`matched_path_type` 提供 prefix 替换证据。
///
/// 返回：返回可直接反序列化为 GatewayRedirectCfg 的 JSON；非法组合失败闭合。
fn compile_request_redirect(
    redirect: &Value,
    matched_path: &str,
    matched_path_type: &str,
) -> anyhow::Result<Value> {
    let mut output = json!({
        "status_code": redirect.get("statusCode").and_then(Value::as_u64).unwrap_or(302)
    });
    if let Some(scheme) = redirect.get("scheme").and_then(Value::as_str) {
        anyhow::ensure!(
            matches!(scheme, "http" | "https"),
            "RequestRedirect scheme is invalid"
        );
        output["scheme"] = json!(scheme);
    }
    if let Some(hostname) = redirect.get("hostname").and_then(Value::as_str) {
        let hostname = normalize_hostname(hostname)?;
        anyhow::ensure!(
            !hostname.starts_with("*."),
            "RequestRedirect hostname cannot be wildcard"
        );
        output["hostname"] = json!(hostname);
    }
    if let Some(port) = redirect.get("port").and_then(Value::as_u64) {
        let port = u16::try_from(port)
            .ok()
            .filter(|port| *port > 0)
            .context("RequestRedirect port is invalid")?;
        output["port"] = json!(port);
    }
    if let Some(path) = redirect.get("path") {
        match path
            .get("type")
            .and_then(Value::as_str)
            .context("RequestRedirect path missing type")?
        {
            "ReplaceFullPath" => {
                let replacement = path
                    .get("replaceFullPath")
                    .and_then(Value::as_str)
                    .context("RequestRedirect ReplaceFullPath missing value")?;
                validate_http_path(replacement)?;
                output["replace_full_path"] = json!(replacement);
            }
            "ReplacePrefixMatch" => {
                anyhow::ensure!(
                    matched_path_type == "PathPrefix",
                    "RequestRedirect ReplacePrefixMatch requires PathPrefix match"
                );
                let replacement = path
                    .get("replacePrefixMatch")
                    .and_then(Value::as_str)
                    .context("RequestRedirect ReplacePrefixMatch missing value")?;
                validate_http_path(replacement)?;
                output["replace_prefix_match"] = json!(replacement);
                output["matched_prefix"] = json!(normalized_path_element_prefix(matched_path));
            }
            other => bail!("RequestRedirect path type `{other}` is unsupported"),
        }
    }
    Ok(output)
}

/// 业务作用：解析一条 Gateway Route rule 的带权 Service backendRefs，并验证至少一个正权重目标。
///
/// 参数说明：对象身份决定 ReferenceGrant from；`scheme`/`protocol` 固定生成 service transport；
/// 目录参数用于验证 Service 与 port；`services` 接收去重后的统一上游定义。
///
/// 返回：返回一到十六个有序后端；缺失、越权、全零或越界权重时失败闭合。
#[allow(clippy::too_many_arguments)]
fn compile_backend_refs(
    rule: &Value,
    route_namespace: &str,
    route_name: &str,
    route_kind: &str,
    scheme: &str,
    protocol: Option<&str>,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    inference_pools: Option<&InferencePoolCatalog>,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<Vec<BackendTarget>> {
    let backends = rule
        .get("backendRefs")
        .and_then(Value::as_array)
        .context("Gateway Route rule missing backendRefs")?;
    anyhow::ensure!(
        (1..=16).contains(&backends.len()),
        "{route_kind} {route_namespace}/{route_name} requires 1..=16 backendRefs"
    );
    let targets = backends
        .iter()
        .map(|backend| {
            compile_backend_ref(
                backend,
                route_namespace,
                route_name,
                route_kind,
                scheme,
                protocol,
                service_catalog,
                service_import_catalog,
                inference_pools,
                backend_traffic,
                grants,
                services,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(
        targets.iter().any(|target| target.weight > 0),
        "{route_kind} {route_namespace}/{route_name} backendRefs cannot all have zero weight"
    );
    Ok(targets)
}

/// 业务作用：验证单个 Service backendRef 的 kind、namespace 授权、存在性、数字 port
/// 与 Route 所需 L4 protocol。
///
/// 参数说明：`backend` 是 BackendRef；Route 身份用于授权诊断；transport 参数写入统一 service；
/// 目录参数是同轮事实；`services` 接收去重定义。
///
/// 返回：引用被明确授权且目标存在时返回逻辑服务与权重，否则不发布任何半完成引用。
#[allow(clippy::too_many_arguments)]
fn compile_backend_ref(
    backend: &Value,
    route_namespace: &str,
    route_name: &str,
    route_kind: &str,
    scheme: &str,
    protocol: Option<&str>,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    inference_pools: Option<&InferencePoolCatalog>,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    services: &mut BTreeMap<String, Value>,
) -> anyhow::Result<BackendTarget> {
    let mut backend_filters = Vec::new();
    let raw_filters = backend
        .get("filters")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(
        raw_filters.len() <= 16,
        "Gateway Route backendRef supports at most 16 filters"
    );
    for filter in raw_filters {
        let filter_type = filter
            .get("type")
            .and_then(Value::as_str)
            .context("Gateway Route backendRef filter missing type")?;
        anyhow::ensure!(
            route_kind == "HTTPRoute" && filter_type == "RequestHeaderModifier",
            "{route_kind} backendRef filter `{filter_type}` is unsupported"
        );
        compile_header_modifier(
            filter
                .get("requestHeaderModifier")
                .context("backendRef RequestHeaderModifier body missing")?,
            true,
            &mut backend_filters,
        )?;
    }
    let group = backend.get("group").and_then(Value::as_str).unwrap_or("");
    let kind = backend
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Service");
    let service_import = group == "multicluster.x-k8s.io" && kind == "ServiceImport";
    let inference_pool = group == "inference.networking.k8s.io" && kind == "InferencePool";
    anyhow::ensure!(
        (group.is_empty() && kind == "Service")
            || service_import
            || (route_kind == "HTTPRoute" && inference_pool),
        "{route_kind} {route_namespace}/{route_name} backendRef must target Service, ServiceImport, or HTTPRoute InferencePool"
    );
    let service_name = backend
        .get("name")
        .and_then(Value::as_str)
        .context("Gateway Route backendRef missing name")?;
    validate_kubernetes_name("Gateway Route backend Service", service_name)?;
    let backend_namespace = backend
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(route_namespace);
    validate_kubernetes_name("Gateway Route backend namespace", backend_namespace)?;
    if backend_namespace != route_namespace {
        anyhow::ensure!(
            grants.permits_group_reference(
                route_namespace,
                route_kind,
                backend_namespace,
                group,
                kind,
                service_name
            )?,
            "{route_kind} {route_namespace}/{route_name} backendRef to {backend_namespace}/{service_name} is not permitted by ReferenceGrant"
        );
    }
    let weight = backend.get("weight").and_then(Value::as_u64).unwrap_or(1);
    let weight = u32::try_from(weight).context("Gateway Route backend weight exceeds u32")?;
    anyhow::ensure!(
        weight <= 1_000_000,
        "Gateway Route backend weight exceeds 1000000"
    );
    if inference_pool {
        let pools = inference_pools
            .context("HTTPRoute InferencePool backend requires inference_gateway_enabled=true")?;
        let pool = pools
            .pools
            .get(&(backend_namespace.to_owned(), service_name.to_owned()))
            .with_context(|| {
                format!(
                    "HTTPRoute {route_namespace}/{route_name} InferencePool {backend_namespace}/{service_name} does not exist or is unresolved"
                )
            })?;
        anyhow::ensure!(
            pool.resolved,
            "HTTPRoute {route_namespace}/{route_name} InferencePool {backend_namespace}/{service_name} has an unresolved EPP Service"
        );
        // InferencePool 的 HTTPRoute port 按固定合同不参与后端选择；EPP 返回的 IP 或
        // IP:port 仍会与池的 targetPorts 实例目录求交，不能借此越出声明端口。
        if let Some(port) = backend.get("port") {
            anyhow::ensure!(
                port.as_u64()
                    .and_then(|value| u16::try_from(value).ok())
                    .is_some_and(|value| value > 0),
                "HTTPRoute InferencePool backendRef port must be a valid number when present"
            );
        }
        for (logical, value) in [
            (&pool.pool_logical, &pool.pool_service),
            (&pool.epp_logical, &pool.epp_service),
        ] {
            match services.get(logical) {
                Some(existing) => anyhow::ensure!(
                    existing == value,
                    "generated Kubernetes service id collision for `{logical}`"
                ),
                None => {
                    services.insert(logical.clone(), value.clone());
                }
            }
        }
        let ext_proc = json!({
            "target": format!("lb://{}", pool.epp_logical),
            "fail_open": pool.fail_open,
            "request_headers": true,
            "response_headers": true,
            "request_body": "buffered",
            "response_body": "none",
            "message_timeout_ms": 2000,
            "total_timeout_ms": 900000,
            "max_message_bytes": 16777216,
            "max_total_bytes": 67108864,
            "max_body_bytes": 16777216,
            "max_in_flight": 4096,
            "failure_threshold": 5,
            "reset_timeout_ms": 1000,
            "mutation_headers": [
                "x-gateway-destination-endpoint",
                "traceparent",
                "tracestate",
                "baggage"
            ],
            "writable_metadata_namespaces": ["envoy.lb"]
        });
        return Ok(BackendTarget {
            logical: pool.pool_logical.clone(),
            weight,
            filters: backend_filters,
            inference_pool: Some(json!({"max_selected_endpoints": 256})),
            ext_proc: Some(ext_proc),
        });
    }
    let port = backend
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0)
        .context("Gateway Route Service backendRef requires a valid numeric port")?;
    let ports = if service_import {
        &service_import_catalog.ports
    } else {
        &service_catalog.ports
    }
        .get(&(backend_namespace.to_owned(), service_name.to_owned()))
        .with_context(|| {
            format!(
                "{route_kind} {route_namespace}/{route_name} backend {kind} {backend_namespace}/{service_name} does not exist"
            )
        })?;
    let service_protocol = if route_kind == "UDPRoute" {
        "UDP"
    } else {
        "TCP"
    };
    let port_key = (port, service_protocol.to_owned());
    anyhow::ensure!(
        ports.contains_key(&port_key),
        "{route_kind} {route_namespace}/{route_name} backend {kind} {backend_namespace}/{service_name} has no {service_protocol} port {port}"
    );
    let app_protocol = ports.get(&port_key).and_then(Option::as_deref);
    let (scheme, protocol) = backend_transport(route_kind, scheme, protocol, app_protocol)?;
    let target_key = BackendTrafficTargetKey {
        group: group.to_owned(),
        kind: kind.to_owned(),
        namespace: backend_namespace.to_owned(),
        name: service_name.to_owned(),
    };
    let traffic_policy = backend_traffic
        .selected
        .get(&target_key)
        .and_then(|index| backend_traffic.policies[*index].config.as_ref());
    let logical = insert_generated_service_with_protocol_and_kind(
        services,
        backend_namespace,
        service_name,
        &BackendPort::Number(port),
        scheme,
        protocol,
        service_import,
        traffic_policy,
    )?;
    Ok(BackendTarget {
        logical,
        weight,
        filters: backend_filters,
        inference_pool: None,
        ext_proc: None,
    })
}

/// 业务作用：把 Service `appProtocol` 收敛为 Naway 已验证的上游 scheme/transport，
/// 防止声明 h2c 或 WebSocket 后仍按普通 HTTP/1 误连。
///
/// 参数说明：`route_kind` 限定 Gateway Route 类型；默认 transport 来自调用方；
/// `app_protocol` 来自同轮 Service port。
///
/// 返回：缺省 appProtocol 时保留调用方设置；GRPCRoute 接受与其明文 HTTP/2 transport
/// 一致的 `kubernetes.io/h2c`；HTTPRoute 的标准 HTTP/HTTPS/h2c/WS/WSS 返回对应 transport；
/// 未知值或与 Route transport 冲突时失败闭合。
fn backend_transport<'a>(
    route_kind: &str,
    default_scheme: &'a str,
    default_protocol: Option<&'a str>,
    app_protocol: Option<&str>,
) -> anyhow::Result<(&'a str, Option<&'a str>)> {
    let Some(app_protocol) = app_protocol else {
        return Ok((default_scheme, default_protocol));
    };
    if route_kind == "GRPCRoute" {
        anyhow::ensure!(
            app_protocol.eq_ignore_ascii_case("kubernetes.io/h2c")
                && default_scheme == "http"
                && default_protocol == Some("h2c"),
            "GRPCRoute backend Service appProtocol `{app_protocol}` conflicts with configured backend transport"
        );
        return Ok(("http", Some("h2c")));
    }
    anyhow::ensure!(
        route_kind == "HTTPRoute",
        "{route_kind} backend Service appProtocol `{app_protocol}` is unsupported"
    );
    match app_protocol.to_ascii_lowercase().as_str() {
        "http" => Ok(("http", None)),
        "https" => Ok(("https", None)),
        "kubernetes.io/h2c" => Ok(("http", Some("h2c"))),
        "kubernetes.io/ws" => Ok(("http", Some("h1"))),
        "kubernetes.io/wss" => Ok(("https", Some("h1"))),
        other => bail!("HTTPRoute backend Service appProtocol `{other}` is unsupported"),
    }
}

impl ReferenceGrantCatalog<'_> {
    /// 业务作用：执行通用 Gateway API ReferenceGrant 双边授权，使 Gateway 引用 Secret
    /// 与 Route 引用 Service 共用同一个跨 namespace 安全不变量。
    ///
    /// 参数说明：`from_namespace`/`from_kind` 描述引用者；`to_namespace`/`to_kind`/
    /// `to_name` 描述 core API 目标。
    ///
    /// 返回：目标 namespace 内至少一个 grant 同时精确匹配 from/to 时为 true；坏 grant
    /// 结构返回错误，防止通过宽松解析扩大授权。
    fn permits_reference(
        &self,
        from_namespace: &str,
        from_kind: &str,
        to_namespace: &str,
        to_kind: &str,
        to_name: &str,
    ) -> anyhow::Result<bool> {
        self.permits_group_reference(
            from_namespace,
            from_kind,
            to_namespace,
            "",
            to_kind,
            to_name,
        )
    }

    /// 业务作用：执行带显式 API group 的 ReferenceGrant 双边授权，使 ServiceImport
    /// 与 core Service 采用相同的跨 namespace 最小权限门禁。
    ///
    /// 参数说明：from 身份描述引用者；to 身份完整描述目标 group、kind 和 name。
    ///
    /// 返回：目标 namespace 内存在精确匹配的授权时返回 true；结构异常返回错误。
    #[allow(clippy::too_many_arguments)]
    fn permits_group_reference(
        &self,
        from_namespace: &str,
        from_kind: &str,
        to_namespace: &str,
        to_group: &str,
        to_kind: &str,
        to_name: &str,
    ) -> anyhow::Result<bool> {
        for grant in self.grants {
            let (namespace, _) = object_identity(grant, "ReferenceGrant")?;
            if namespace != to_namespace {
                continue;
            }
            let from_matches = grant
                .pointer("/spec/from")
                .and_then(Value::as_array)
                .context("ReferenceGrant missing spec.from")?
                .iter()
                .any(|from| {
                    from.get("group").and_then(Value::as_str) == Some("gateway.networking.k8s.io")
                        && from.get("kind").and_then(Value::as_str) == Some(from_kind)
                        && from.get("namespace").and_then(Value::as_str) == Some(from_namespace)
                });
            if !from_matches {
                continue;
            }
            let to_matches = grant
                .pointer("/spec/to")
                .and_then(Value::as_array)
                .context("ReferenceGrant missing spec.to")?
                .iter()
                .any(|to| {
                    to.get("group").and_then(Value::as_str).unwrap_or("") == to_group
                        && to.get("kind").and_then(Value::as_str) == Some(to_kind)
                        && to
                            .get("name")
                            .and_then(Value::as_str)
                            .is_none_or(|name| name == to_name)
                });
            if to_matches {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// 业务作用：计算单个 Gateway 或 ListenerSet listener 的证书引用门禁，将语法、跨租户授权、
/// Secret 存在性和密钥可用性统一映射为 Gateway API condition。
///
/// 参数说明：`listener` 是 listener 单项；`source_namespace`/`source_kind` 是引用者
/// 身份；`secrets`/`grants` 来自同轮快照。
///
/// 返回：非 TLS 终止 listener 或所有 certificateRefs 已授权且有效时返回已解析；
/// 跨 namespace 未授权返回 RefNotPermitted，其它证书问题返回 InvalidCertificateRef。
fn listener_reference_condition(
    listener: &Value,
    source_namespace: &str,
    source_kind: &str,
    secrets: &SecretCatalog,
    grants: &ReferenceGrantCatalog<'_>,
) -> anyhow::Result<ListenerReferenceCondition> {
    let protocol = listener.get("protocol").and_then(Value::as_str);
    let terminates_tls = protocol == Some("HTTPS")
        || (protocol == Some("TLS")
            && listener.pointer("/tls/mode").and_then(Value::as_str) == Some("Terminate"));
    if !terminates_tls {
        return Ok(ListenerReferenceCondition {
            resolved: true,
            reason: "ResolvedRefs",
            message: "listener references are resolved",
        });
    }
    let Some(tls) = listener.get("tls") else {
        return Ok(ListenerReferenceCondition {
            resolved: false,
            reason: "InvalidCertificateRef",
            message: "TLS termination listener requires a valid certificate reference",
        });
    };
    if tls
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("Terminate")
        != "Terminate"
    {
        return Ok(ListenerReferenceCondition {
            resolved: false,
            reason: "InvalidCertificateRef",
            message: "listener requires TLS termination",
        });
    }
    let Some(references) = tls.get("certificateRefs").and_then(Value::as_array) else {
        return Ok(ListenerReferenceCondition {
            resolved: false,
            reason: "InvalidCertificateRef",
            message: "TLS termination listener requires a valid certificate reference",
        });
    };
    if references.is_empty() || references.len() > 64 {
        return Ok(ListenerReferenceCondition {
            resolved: false,
            reason: "InvalidCertificateRef",
            message: "TLS termination listener certificate reference count is invalid",
        });
    }
    for reference in references {
        let group = reference.get("group").and_then(Value::as_str).unwrap_or("");
        let kind = reference
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("Secret");
        let Some(name) = reference.get("name").and_then(Value::as_str) else {
            return Ok(ListenerReferenceCondition {
                resolved: false,
                reason: "InvalidCertificateRef",
                message: "TLS termination listener certificate reference is malformed",
            });
        };
        let namespace = reference
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or(source_namespace);
        if !group.is_empty()
            || kind != "Secret"
            || validate_kubernetes_name("Gateway certificateRef namespace", namespace).is_err()
            || validate_kubernetes_name("Gateway certificateRef Secret", name).is_err()
        {
            return Ok(ListenerReferenceCondition {
                resolved: false,
                reason: "InvalidCertificateRef",
                message: "TLS termination listener certificate reference is malformed",
            });
        }
        if namespace != source_namespace
            && !grants.permits_reference(
                source_namespace,
                source_kind,
                namespace,
                "Secret",
                name,
            )?
        {
            // 跨 namespace Secret 必须先取得目标租户授权；未授权时不能用 Secret
            // 存在性或解析结果作为旁路证据。
            return Ok(ListenerReferenceCondition {
                resolved: false,
                reason: "RefNotPermitted",
                message: "cross-namespace certificate reference is not permitted",
            });
        }
        if secrets
            .tls_material(namespace, name)
            .ok()
            .flatten()
            .is_none()
        {
            return Ok(ListenerReferenceCondition {
                resolved: false,
                reason: "InvalidCertificateRef",
                message: "TLS termination listener certificate reference is unavailable or invalid",
            });
        }
    }
    Ok(ListenerReferenceCondition {
        resolved: true,
        reason: "ResolvedRefs",
        message: "listener references are resolved",
    })
}

/// 业务作用：把 GRPCRoute service/method/header 匹配与带权后端编译为原生 HTTP/2 L7 Route。
///
/// 参数说明：所有目录来自同轮 LIST；`routes`/`services` 接收统一 IR。
///
/// 返回：只接受可由 native gRPC path/header 语义表达的对象；越权或不支持 filter 时失败闭合。
#[allow(clippy::too_many_arguments)]
fn compile_grpc_routes(
    value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    gateways: &GatewayCatalog,
    namespaces: &NamespaceCatalog,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    listener_routes: &mut BTreeMap<HttpListenerKey, Vec<Value>>,
    services: &mut BTreeMap<String, Value>,
    diagnostics: &mut Vec<RouteDiagnostic>,
) -> anyhow::Result<()> {
    let mut objects = resource_items(value, cfg.max_objects, "GRPCRoute")?
        .iter()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object_order_key(object));
    for route in objects {
        let (namespace, name) = object_identity(route, "GRPCRoute")?;
        if !namespace_allowed(cfg, namespace)
            || route.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let attached = attached_listeners(route, namespace, "GRPCRoute", gateways, namespaces)?;
        if attached.is_empty() {
            let reason =
                attachment_rejection_reason(route, namespace, "GRPCRoute", gateways, namespaces)?;
            diagnostics.push(RouteDiagnostic::new(
                route,
                "gateway.networking.k8s.io/v1",
                "GRPCRoute",
                "grpcroutes",
                false,
                true,
                reason,
                if reason == "NotAllowedByListeners" {
                    "matching listeners reject this Route kind or namespace"
                } else {
                    "no listener matched parentRefs sectionName or port"
                },
            ));
            continue;
        }
        let attached = listeners_with_hostname_intersection(route, &attached)?;
        if attached.is_empty() {
            diagnostics.push(RouteDiagnostic::new(
                route,
                "gateway.networking.k8s.io/v1",
                "GRPCRoute",
                "grpcroutes",
                false,
                true,
                "NoMatchingListenerHostname",
                "route hostnames do not intersect any permitted listener hostname",
            ));
            continue;
        }
        let mut object_services = BTreeMap::new();
        let mut routes_by_listener = BTreeMap::new();
        let compile_result = (|| -> anyhow::Result<()> {
            let rules = route
                .pointer("/spec/rules")
                .and_then(Value::as_array)
                .context("selected GRPCRoute missing spec.rules")?;
            anyhow::ensure!(
                rules.len() <= 64,
                "GRPCRoute {namespace}/{name} exceeds 64 rules"
            );
            for (key, listener_group) in group_http_listeners(&attached) {
                let socket_routes = routes_by_listener.entry(key).or_insert_with(Vec::new);
                let mut compiled_listener_ids = BTreeSet::new();
                for attached_listener in listener_group {
                    let (hostnames, unrestricted_hostname) =
                        intersect_route_hostnames(route, std::slice::from_ref(&attached_listener))?;
                    let listener_id = gateway_listener_id(&attached_listener.listener);
                    // 同 socket、同 hostname 的 listener 共享请求权威，避免为同一
                    // GRPCRoute 生成重复 ID 与不稳定的匹配顺序。
                    if !compiled_listener_ids.insert(listener_id.clone()) {
                        continue;
                    }
                    let mut object_routes = Vec::new();
                    for (rule_index, rule) in rules.iter().enumerate() {
                        let filter_plan = compile_http_filters(
                            rule,
                            namespace,
                            name,
                            "GRPCRoute",
                            "/",
                            "PathPrefix",
                            service_catalog,
                            service_import_catalog,
                            backend_traffic,
                            grants,
                            &mut object_services,
                        )?;
                        anyhow::ensure!(
                            filter_plan.gateway_redirect.is_none()
                                && !filter_plan.filters.iter().any(|filter| {
                                    filter.starts_with("rewrite ")
                                        || filter.starts_with("gateway_rewrite_full_path ")
                                }),
                            "GRPCRoute {namespace}/{name} does not support redirect or URL rewrite"
                        );
                        let scheme = if cfg.grpc_backend_protocol == "h2" {
                            "https"
                        } else {
                            "http"
                        };
                        let mut backends = compile_backend_refs(
                            rule,
                            namespace,
                            name,
                            "GRPCRoute",
                            scheme,
                            Some(cfg.grpc_backend_protocol.as_str()),
                            service_catalog,
                            service_import_catalog,
                            None,
                            backend_traffic,
                            grants,
                            &mut object_services,
                        )?;
                        apply_inline_session_persistence(
                            rule,
                            namespace,
                            name,
                            "GRPCRoute",
                            rule_index,
                            "/",
                            &mut backends,
                            &mut object_services,
                        )?;
                        let matches = rule
                            .get("matches")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_else(|| vec![json!({})]);
                        anyhow::ensure!(matches.len() <= 64, "GRPCRoute match count exceeds 64");
                        for (match_index, route_match) in matches.iter().enumerate() {
                            let path_predicate_value = grpc_method_predicate(route_match)?;
                            let mut predicates =
                                vec![path_predicate_value, "Method=POST".to_owned()];
                            predicates
                                .push("Header=content-type,prefix,application/grpc".to_owned());
                            if !unrestricted_hostname && !hostnames.is_empty() {
                                predicates.push(format!("Host={}", hostnames.join(",")));
                            }
                            append_http_route_header_matches(
                                route_match,
                                namespace,
                                name,
                                &mut predicates,
                            )?;
                            let group = stable_id(
                                "gw-grpc-weight",
                                &[
                                    namespace,
                                    name,
                                    &rule_index.to_string(),
                                    &match_index.to_string(),
                                ],
                            );
                            for (backend_index, backend) in backends.iter().enumerate() {
                                if backends.len() > 1 {
                                    predicates.push(format!("Weight={group},{}", backend.weight));
                                }
                                let mut filters = filter_plan.filters.clone();
                                filters.extend(backend.filters.iter().cloned());
                                object_routes.push(json!({
                                "id": stable_id("k8s-grpcroute", &[namespace, name, &rule_index.to_string(), &match_index.to_string(), &backend_index.to_string(), &backend.logical]),
                                "uri": format!("lb://{}", backend.logical),
                                "preserve_host": true,
                                "predicates": predicates,
                                "filters": filters,
                                "order": grpc_route_order(route_match, &hostnames, unrestricted_hostname)
                            }));
                                if backends.len() > 1 {
                                    predicates.pop();
                                }
                            }
                        }
                    }
                    if is_mesh_listener(&attached_listener.listener) {
                        scope_routes_to_mesh_parent(
                            &mut object_routes,
                            &attached_listener.listener,
                            namespace,
                            &gateways.mesh_source_namespace_header,
                        )?;
                    } else {
                        scope_routes_to_gateway_listener(&mut object_routes, &listener_id)?;
                    }
                    socket_routes.extend(object_routes);
                }
            }
            Ok(())
        })();
        match compile_result {
            Ok(()) => {
                merge_generated_services(services, object_services)?;
                for (key, object_routes) in routes_by_listener {
                    listener_routes
                        .entry(key)
                        .or_default()
                        .extend(object_routes);
                }
                diagnostics.push(
                    RouteDiagnostic::new(
                        route,
                        "gateway.networking.k8s.io/v1",
                        "GRPCRoute",
                        "grpcroutes",
                        true,
                        true,
                        "ResolvedRefs",
                        "all parent and backend references resolved",
                    )
                    .with_attached_listeners(&attached),
                );
            }
            Err(error) => diagnostics.push(
                RouteDiagnostic::new(
                    route,
                    "gateway.networking.k8s.io/v1",
                    "GRPCRoute",
                    "grpcroutes",
                    true,
                    false,
                    diagnostic_reason(&error.to_string()),
                    error.to_string(),
                )
                .with_attached_listeners(&attached),
            ),
        }
    }
    Ok(())
}

/// 业务作用：把 GRPCRoute method match 变成标准 `/package.Service/Method` path predicate。
///
/// 参数说明：`route_match` 是单个 GRPCRouteMatch。
///
/// 返回：返回 path predicate；非法 service/method 字符或 method 无 service 时失败。
fn grpc_method_predicate(route_match: &Value) -> anyhow::Result<String> {
    let method = route_match.get("method");
    let service = method
        .and_then(|method| method.get("service"))
        .and_then(Value::as_str);
    let method_name = method
        .and_then(|method| method.get("method"))
        .and_then(Value::as_str);
    for (field, value) in [("service", service), ("method", method_name)] {
        if let Some(value) = value {
            anyhow::ensure!(
                !value.is_empty()
                    && value.len() <= 256
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_')
                    }),
                "GRPCRoute {field} is invalid"
            );
        }
    }
    match (service, method_name) {
        (Some(service), Some(method)) => Ok(format!("PathExact=/{service}/{method}")),
        (Some(service), None) => Ok(format!("Path=/{service}/")),
        (None, None) => Ok("Path=/".to_owned()),
        (None, Some(_)) => bail!("GRPCRoute method name requires service"),
    }
}

/// 业务作用：把 GRPCRoute 规范的 hostname、service、method、header 五级优先关系编码为路由顺序。
///
/// 参数说明：`route_match` 提供 method/header 条件；`hostnames` 是父 listener 与 Route 的交集；
/// `unrestricted_hostname` 表示该 Route 同时附着到无 hostname 限制的 listener。
///
/// 返回：数值越小优先级越高；同分继续由对象年龄、namespace/name 与规则声明顺序稳定裁决。
fn grpc_route_order(route_match: &Value, hostnames: &[String], unrestricted_hostname: bool) -> i32 {
    let (exact_hostname, hostname_chars) = if unrestricted_hostname {
        (0_i32, 0_i32)
    } else {
        hostnames
            .iter()
            .map(|hostname| {
                (
                    i32::from(!hostname.starts_with("*.")),
                    i32::try_from(hostname.len().min(253)).unwrap_or(253),
                )
            })
            .max()
            .unwrap_or((0, 0))
    };
    let service_chars = route_match
        .pointer("/method/service")
        .and_then(Value::as_str)
        .map(|value| i32::try_from(value.len().min(256)).unwrap_or(256))
        .unwrap_or(0);
    let method_chars = route_match
        .pointer("/method/method")
        .and_then(Value::as_str)
        .map(|value| i32::try_from(value.len().min(256)).unwrap_or(256))
        .unwrap_or(0);
    let header_matches = route_match
        .get("headers")
        .and_then(Value::as_array)
        .map(|values| i32::try_from(values.len().min(16)).unwrap_or(16))
        .unwrap_or(0);

    // 各字段用大于下一字段最大值的基数编码，保持规范要求的字典序；范围上限来自
    // Gateway API schema，最大分数小于 i32::MAX，不会因溢出反转优先级。
    let score = ((((exact_hostname * 254) + hostname_chars) * 257 + service_chars) * 257
        + method_chars)
        * 17
        + header_matches;
    -score
}

/// 业务作用：把 TLSRoute/TCPRoute/UDPRoute 编译为既有 stream listener/route IR。
///
/// 参数说明：`route_kind` 决定 listener protocol 与 SNI 语义；目录参数用于附着和引用判权；
/// `services`/`listeners` 接收完整候选。
///
/// 返回：单后端 L4 规则可安全表达时成功；多后端、filter 或协议冲突失败闭合。
#[allow(clippy::too_many_arguments)]
fn compile_l4_routes(
    route_kind: &str,
    value: &Value,
    cfg: &KubernetesRouteSourceCfg,
    gateways: &GatewayCatalog,
    namespaces: &NamespaceCatalog,
    service_catalog: &ServiceCatalog,
    service_import_catalog: &ServiceImportCatalog,
    backend_traffic: &BackendTrafficCatalog,
    grants: &ReferenceGrantCatalog<'_>,
    services: &mut BTreeMap<String, Value>,
    listeners: &mut BTreeMap<String, L4ListenerPlan>,
    diagnostics: &mut Vec<RouteDiagnostic>,
) -> anyhow::Result<()> {
    let mut objects = resource_items(value, cfg.max_objects, route_kind)?
        .iter()
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| object_order_key(object));
    for route in objects {
        let (namespace, name) = object_identity(route, route_kind)?;
        if !namespace_allowed(cfg, namespace)
            || route.pointer("/metadata/deletionTimestamp").is_some()
        {
            continue;
        }
        let attached = attached_listeners(route, namespace, route_kind, gateways, namespaces)?;
        if attached.is_empty() {
            let reason =
                attachment_rejection_reason(route, namespace, route_kind, gateways, namespaces)?;
            diagnostics.push(RouteDiagnostic::new(
                route,
                l4_api_version(route_kind),
                route_kind,
                l4_plural(route_kind),
                false,
                true,
                reason,
                if reason == "NotAllowedByListeners" {
                    "matching listeners reject this Route kind or namespace"
                } else {
                    "no listener matched parentRefs sectionName or port"
                },
            ));
            continue;
        }
        let attached = if route_kind == "TLSRoute" {
            listeners_with_hostname_intersection(route, &attached)?
        } else {
            attached
        };
        if attached.is_empty() {
            diagnostics.push(RouteDiagnostic::new(
                route,
                l4_api_version(route_kind),
                route_kind,
                l4_plural(route_kind),
                false,
                true,
                "NoMatchingListenerHostname",
                "route hostnames do not intersect any permitted listener hostname",
            ));
            continue;
        }
        let hostnames = if route_kind == "TLSRoute" {
            intersect_route_hostnames(route, &attached)?.0
        } else {
            Vec::new()
        };
        let mut object_services = BTreeMap::new();
        let mut object_listeners = BTreeMap::new();
        for attached_listener in &attached {
            let listener = &attached_listener.listener;
            let expected_protocol = match route_kind {
                "TLSRoute" => "TLS",
                "TCPRoute" => "TCP",
                "UDPRoute" => "UDP",
                _ => unreachable!("caller limits L4 kinds"),
            };
            if listener.protocol != expected_protocol {
                continue;
            }
            let transport = if route_kind == "UDPRoute" {
                "udp"
            } else {
                "tcp"
            };
            let key = format!("{}:{transport}:{}", listener.bind_address, listener.port);
            let socket = std::net::SocketAddr::new(
                listener
                    .bind_address
                    .parse()
                    .expect("Gateway listener bind address validated before compilation"),
                listener.port,
            );
            object_listeners
                .entry(key.clone())
                .or_insert_with(|| L4ListenerPlan {
                    id: stable_id("k8s-gateway-listener", &[&key]),
                    listen: socket.to_string(),
                    protocol: transport.to_owned(),
                    tls_passthrough: route_kind == "TLSRoute",
                    tls_termination: listener.tls_mode.as_deref() == Some("Terminate"),
                    routes: Vec::new(),
                });
        }
        let compile_result = (|| -> anyhow::Result<()> {
            anyhow::ensure!(
                route_kind != "TLSRoute" || !hostnames.is_empty(),
                "TLSRoute {namespace}/{name} requires at least one hostname"
            );
            let rules = route
                .pointer("/spec/rules")
                .and_then(Value::as_array)
                .context("Gateway L4 Route missing spec.rules")?;
            anyhow::ensure!(
                rules.len() == 1,
                "{route_kind} {namespace}/{name} requires exactly one rule"
            );
            let rule = &rules[0];
            anyhow::ensure!(
                rule.get("filters")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "{route_kind} {namespace}/{name} filters are unsupported"
            );
            let backends = compile_backend_refs(
                rule,
                namespace,
                name,
                route_kind,
                "http",
                None,
                service_catalog,
                service_import_catalog,
                None,
                backend_traffic,
                grants,
                &mut object_services,
            )?;
            let positive_backends = backends
                .iter()
                .filter(|backend| backend.weight > 0)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                !positive_backends.is_empty(),
                "{route_kind} {namespace}/{name} requires at least one positive-weight backendRef"
            );
            let target = format!("lb://{}", positive_backends[0].logical);
            let weighted_upstreams = positive_backends
                .iter()
                .map(|backend| {
                    json!({
                        "upstream": format!("lb://{}", backend.logical),
                        "weight": backend.weight
                    })
                })
                .collect::<Vec<_>>();
            for attached_listener in &attached {
                let listener = &attached_listener.listener;
                let expected_protocol = match route_kind {
                    "TLSRoute" => "TLS",
                    "TCPRoute" => "TCP",
                    "UDPRoute" => "UDP",
                    _ => unreachable!("caller limits L4 kinds"),
                };
                if listener.protocol != expected_protocol {
                    continue;
                }
                let transport = if route_kind == "UDPRoute" {
                    "udp"
                } else {
                    "tcp"
                };
                let key = format!("{}:{transport}:{}", listener.bind_address, listener.port);
                let plan = object_listeners
                    .get_mut(&key)
                    .expect("Gateway listener plan created before backend resolution");
                anyhow::ensure!(
                    plan.tls_passthrough == (route_kind == "TLSRoute"),
                    "Gateway L4 listener {key} mixes TLS passthrough and raw TCP"
                );
                if route_kind == "TLSRoute" {
                    for hostname in &hostnames {
                        if plan.routes.iter().any(|existing| {
                            existing.get("sni").and_then(Value::as_str) == Some(hostname.as_str())
                        }) {
                            // 对同一 SNI 的竞争由 creationTimestamp/namespace/name 稳定排序决定，后到对象
                            // 不得覆盖已发布目标，避免多节点因 LIST 顺序产生分歧。
                            continue;
                        }
                        plan.routes.push(json!({
                            "id": stable_id("k8s-tlsroute", &[namespace, name, hostname]),
                            "sni": hostname,
                            "default": false,
                            "terminate_tls": listener.tls_mode.as_deref() == Some("Terminate"),
                            "upstream": target,
                            "weighted_upstreams": weighted_upstreams
                        }));
                    }
                } else if plan.routes.is_empty() {
                    plan.routes.push(json!({
                        "id": stable_id(if route_kind == "TCPRoute" { "k8s-tcproute" } else { "k8s-udproute" }, &[namespace, name]),
                        "default": true,
                        "upstream": target,
                        "weighted_upstreams": weighted_upstreams
                    }));
                }
            }
            Ok(())
        })();
        // Gateway listener 的生命周期独立于 Route 后端解析；即使引用无效也保留空路由 socket，
        // 让客户端得到确定的连接拒绝，并避免一个坏 Route 误伤整个 Gateway 的可达性。
        merge_l4_listeners(listeners, object_listeners)?;
        match compile_result {
            Ok(()) => {
                merge_generated_services(services, object_services)?;
                diagnostics.push(
                    RouteDiagnostic::new(
                        route,
                        l4_api_version(route_kind),
                        route_kind,
                        l4_plural(route_kind),
                        true,
                        true,
                        "ResolvedRefs",
                        "all parent and backend references resolved",
                    )
                    .with_attached_listeners(&attached),
                );
            }
            Err(error) => diagnostics.push(
                RouteDiagnostic::new(
                    route,
                    l4_api_version(route_kind),
                    route_kind,
                    l4_plural(route_kind),
                    true,
                    false,
                    diagnostic_reason(&error.to_string()),
                    error.to_string(),
                )
                .with_attached_listeners(&attached),
            ),
        }
    }
    Ok(())
}

/// 业务作用：返回 L4 Route kind 对应的 Kubernetes REST plural。
///
/// 参数说明：`route_kind` 只允许调用方传入 TLSRoute/TCPRoute/UDPRoute。
///
/// 返回：返回固定小写 plural；其它值触发内部不变量错误。
fn l4_plural(route_kind: &str) -> &'static str {
    match route_kind {
        "TLSRoute" => "tlsroutes",
        "TCPRoute" => "tcproutes",
        "UDPRoute" => "udproutes",
        _ => unreachable!("unsupported L4 route kind"),
    }
}

/// 业务作用：固定 Gateway API v1.5.1 各 L4 Route 的 served API version。
///
/// 参数说明：`route_kind` 只允许 TLSRoute/TCPRoute/UDPRoute。
///
/// 返回：TLSRoute 返回稳定 `v1`；实验 TCP/UDP Route 返回 `v1alpha2`。
fn l4_api_version(route_kind: &str) -> &'static str {
    match route_kind {
        "TLSRoute" => "gateway.networking.k8s.io/v1",
        "TCPRoute" | "UDPRoute" => "gateway.networking.k8s.io/v1alpha2",
        _ => unreachable!("unsupported L4 route kind"),
    }
}

/// 业务作用：把单对象生成的 Service 定义事务性合并到本轮完整候选。
///
/// 参数说明：`destination` 是本轮已接受对象定义；`source` 是当前对象临时定义。
///
/// 返回：同名定义一致时成功；摘要碰撞或语义不一致时拒绝整轮候选。
fn merge_generated_services(
    destination: &mut BTreeMap<String, Value>,
    source: BTreeMap<String, Value>,
) -> anyhow::Result<()> {
    for (name, value) in source {
        match destination.get(&name) {
            Some(existing) => anyhow::ensure!(
                existing == &value,
                "generated Kubernetes service id collision for `{name}`"
            ),
            None => {
                destination.insert(name, value);
            }
        }
    }
    Ok(())
}

/// 业务作用：按 listener socket 合并单个 L4 Route 候选，并保持最早对象的冲突所有权。
///
/// 参数说明：`destination` 是稳定排序后已接受 listener；`source` 是当前对象临时 listener。
///
/// 返回：协议形态一致时合并非冲突 SNI；TCP/UDP 默认路由冲突保留既有 winner。
fn merge_l4_listeners(
    destination: &mut BTreeMap<String, L4ListenerPlan>,
    source: BTreeMap<String, L4ListenerPlan>,
) -> anyhow::Result<()> {
    for (key, mut incoming) in source {
        let Some(existing) = destination.get_mut(&key) else {
            destination.insert(key, incoming);
            continue;
        };
        anyhow::ensure!(
            existing.protocol == incoming.protocol
                && existing.listen == incoming.listen
                && existing.tls_passthrough == incoming.tls_passthrough,
            "Gateway L4 listener `{key}` has conflicting protocol ownership"
        );
        if existing.tls_passthrough {
            existing.tls_termination |= incoming.tls_termination;
            for route in incoming.routes.drain(..) {
                let sni = route.get("sni").and_then(Value::as_str);
                if !existing
                    .routes
                    .iter()
                    .any(|current| current.get("sni").and_then(Value::as_str) == sni)
                {
                    existing.routes.push(route);
                }
            }
        }
    }
    Ok(())
}

/// 业务作用：把 Gateway API HTTPHeaderMatch 无损映射为 Naway Header predicate。
///
/// 参数说明：`route_match` 是单个 HTTPRoute match；`namespace`/`route_name` 用于诊断；
/// `predicates` 接收构建期编译前的稳定 DSL。
///
/// 返回：Exact/RegularExpression 均成功映射时返回成功；缺字段或非法类型时拒绝整份候选快照。
fn append_http_route_header_matches(
    route_match: &Value,
    namespace: &str,
    route_name: &str,
    predicates: &mut Vec<String>,
) -> anyhow::Result<()> {
    let Some(headers) = route_match.get("headers").and_then(Value::as_array) else {
        return Ok(());
    };
    for header in headers {
        let name = header
            .get("name")
            .and_then(Value::as_str)
            .with_context(|| {
                format!("HTTPRoute {namespace}/{route_name} header match missing name")
            })?;
        let value = header
            .get("value")
            .and_then(Value::as_str)
            .with_context(|| {
                format!("HTTPRoute {namespace}/{route_name} header match missing value")
            })?;
        let op = match header
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("Exact")
        {
            "Exact" => "exact",
            "RegularExpression" => "regex",
            other => anyhow::bail!(
                "HTTPRoute {namespace}/{route_name} header match type `{other}` is unsupported"
            ),
        };
        predicates.push(format!("Header={name},{op},{value}"));
    }
    Ok(())
}

/// 业务作用：把 Gateway API HTTPQueryParamMatch 映射为解码后、多值安全的 Query predicate。
///
/// 参数说明：`route_match` 是单个 HTTPRoute match；`namespace`/`route_name` 用于诊断；
/// `predicates` 接收构建期编译前的稳定 DSL。
///
/// 返回：Exact/RegularExpression 均成功映射时返回成功；缺字段或非法类型时拒绝整份候选快照。
fn append_http_route_query_matches(
    route_match: &Value,
    namespace: &str,
    route_name: &str,
    predicates: &mut Vec<String>,
) -> anyhow::Result<()> {
    let Some(query_params) = route_match.get("queryParams").and_then(Value::as_array) else {
        return Ok(());
    };
    for query in query_params {
        let name = query.get("name").and_then(Value::as_str).with_context(|| {
            format!("HTTPRoute {namespace}/{route_name} query match missing name")
        })?;
        let value = query
            .get("value")
            .and_then(Value::as_str)
            .with_context(|| {
                format!("HTTPRoute {namespace}/{route_name} query match missing value")
            })?;
        let op = match query.get("type").and_then(Value::as_str).unwrap_or("Exact") {
            "Exact" => "exact",
            "RegularExpression" => "regex",
            other => anyhow::bail!(
                "HTTPRoute {namespace}/{route_name} query match type `{other}` is unsupported"
            ),
        };
        predicates.push(format!("Query={name},{op},{value}"));
    }
    Ok(())
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
    insert_generated_service_with_protocol(services, namespace, service_name, port, scheme, None)
}

/// 业务作用：生成并去重 Kubernetes Service 上游定义，同时固定需要的 HTTP transport。
///
/// 参数说明：`services` 是候选服务表；目标身份与 `port` 已完成授权；`scheme`/`protocol`
/// 决定 discovery 实例 URI 与连接协议。
///
/// 返回：无碰撞时返回稳定逻辑名；同名摘要对应不同定义时拒绝候选。
fn insert_generated_service_with_protocol(
    services: &mut BTreeMap<String, Value>,
    namespace: &str,
    service_name: &str,
    port: &BackendPort,
    scheme: &str,
    protocol: Option<&str>,
) -> anyhow::Result<String> {
    insert_generated_service_with_protocol_and_kind(
        services,
        namespace,
        service_name,
        port,
        scheme,
        protocol,
        false,
        None,
    )
}

/// 业务作用：生成 Service 或 ServiceImport 的统一发现定义，并在对象落表前应用
/// BackendTrafficPolicy 的唯一冲突赢家。
///
/// 参数说明：后端身份、端口与 transport 已完成引用校验；`service_import` 选择 MCS
/// EndpointSlice 语义；`traffic_policy` 是同轮确定的原生策略。
///
/// 返回：无碰撞时返回稳定逻辑名；相同逻辑身份出现不同定义时拒绝整个候选。
#[allow(clippy::too_many_arguments)]
fn insert_generated_service_with_protocol_and_kind(
    services: &mut BTreeMap<String, Value>,
    namespace: &str,
    service_name: &str,
    port: &BackendPort,
    scheme: &str,
    protocol: Option<&str>,
    service_import: bool,
    traffic_policy: Option<&BackendTrafficPolicyConfig>,
) -> anyhow::Result<String> {
    validate_kubernetes_name("backend namespace", namespace)?;
    validate_kubernetes_name("backend service", service_name)?;
    let port_key = match port {
        BackendPort::Name(name) => format!("name-{name}"),
        BackendPort::Number(number) => format!("port-{number}"),
    };
    let logical = stable_id(
        if service_import { "k8s-mcs" } else { "k8s-svc" },
        &[
            namespace,
            service_name,
            &port_key,
            scheme,
            protocol.unwrap_or("auto"),
        ],
    );
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
    if let Some(protocol) = protocol {
        value["protocol"] = json!(protocol);
    }
    if service_import {
        value["registry_service_import"] = json!(true);
    }
    if let Some(policy) = traffic_policy {
        if let Some(retry_budget) = &policy.retry_budget {
            value["retry_budget"] = retry_budget.clone();
        }
        if let Some(session_affinity) = &policy.session_affinity {
            value["session_affinity"] = session_affinity.clone();
        }
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

/// 业务作用：把 Kubernetes path type 映射为共享 predicate DSL，同时保留 Prefix 的
/// 完整 path element 边界。
///
/// 参数说明：`path` 是已验证的绝对路径；`path_type` 来自 Ingress 或 Gateway API。
///
/// 返回：Exact/Prefix/ImplementationSpecific 可无损表达时返回 DSL；未知类型返回错误。
fn path_predicate(path: &str, path_type: &str) -> anyhow::Result<String> {
    match path_type {
        "Exact" => Ok(format!("PathExact={path}")),
        "Prefix" | "PathPrefix" => Ok(format!(
            "PathElementPrefix={}",
            normalized_path_element_prefix(path)
        )),
        "ImplementationSpecific" => Ok(format!("Path={path}")),
        other => bail!("unsupported Kubernetes path type `{other}`"),
    }
}

/// 业务作用：按 Gateway API/Ingress 规则忽略非根 Prefix 的尾斜杠，使匹配与 prefix
/// rewrite 使用同一边界。
///
/// 参数说明：`path` 是以 `/` 开头的已验证 Prefix。
///
/// 返回：根路径保持 `/`；其它路径去除全部尾斜杠后返回借用切片。
fn normalized_path_element_prefix(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        path.trim_end_matches('/')
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

/// 业务作用：将同轮 Kubernetes 编译结果与 TLS 身份原子物化，供 reload worker 验证并发布。
///
/// 参数说明：`config_dir` 与 `cfg` 限定文件边界；其余集合均来自同一冻结快照，
/// `discovery` 用于绑定生成物与当前 API 发现结果。
///
/// 返回：生成内容变化并完成原子替换时返回 true；内容未变返回 false；证书物化、
/// 路径校验或写入失败时返回错误，旧版本继续服务。
#[allow(clippy::too_many_arguments)]
async fn publish_document(
    config_dir: &Path,
    cfg: &KubernetesRouteSourceCfg,
    discovery: &KubernetesDiscoveryCfg,
    routes: Vec<Value>,
    services: BTreeMap<String, Value>,
    mut stream_listeners: Vec<Value>,
    mut stream_tls_plans: BTreeMap<String, GatewayTlsPlan>,
    http_proxies: Vec<GatewayHttpProxyPlan>,
) -> anyhow::Result<bool> {
    let path = materialized_path(config_dir, cfg)?;
    let heartbeat = heartbeat_path(&path);
    let fingerprint = source_fingerprint(cfg, discovery);
    let path_for_task = path.clone();
    let changed = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        // 证书与私钥必须先完整落盘，再发布引用它们的 document；反向顺序
        // 会让 reload worker 看见半完成 TLS 身份，导致新 listener 握手失败。
        for listener in &mut stream_listeners {
            let listen = listener
                .get("listen")
                .and_then(Value::as_str)
                .context("generated Gateway stream listener missing listen")?;
            let Some(plan) = stream_tls_plans.remove(listen) else {
                continue;
            };
            let generated = materialize_gateway_tls(&path_for_task, plan)?;
            listener["tls"] = json!({
                "cert_file": generated.cert_file,
                "key_file": generated.key_file,
                "certs": generated.certs,
                "handshake_timeout_ms": 10_000
            });
        }
        anyhow::ensure!(
            stream_tls_plans.is_empty(),
            "Gateway stream TLS plan has no matching listener"
        );
        let http_proxies = http_proxies
            .into_iter()
            .map(|plan| {
                let tls = plan
                    .tls
                    .map(|tls| materialize_gateway_tls(&path_for_task, tls))
                    .transpose()?;
                Ok(GeneratedHttpProxy {
                    id: plan.id,
                    listen: plan.listen,
                    plain_enabled: plan.plain_enabled,
                    routes: plan.routes,
                    gateway_listeners: plan
                        .gateway_listeners
                        .into_iter()
                        .map(|listener| GeneratedGatewayListener {
                            id: listener.id,
                            hostname: listener.hostname,
                        })
                        .collect(),
                    tls,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let proxy_tls = None;
        let generation = generation_digest_current(
            &routes,
            &services,
            &stream_listeners,
            &proxy_tls,
            &http_proxies,
        )?;
        let document = GeneratedDocument {
            schema_version: GENERATED_SCHEMA_VERSION,
            source_fingerprint: fingerprint,
            generation,
            routes,
            services,
            stream_listeners,
            proxy_tls,
            http_proxies,
        };
        let bytes = serde_json::to_vec(&document).context("encode Kubernetes generated routes")?;
        anyhow::ensure!(
            bytes.len() <= MAX_GENERATED_FILE_BYTES,
            "Kubernetes generated routes exceed hard file limit"
        );
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
    // heartbeat 只通过元数据参与 freshness 判定；保留显式绑定以锁定“内容先发布、freshness 后发布”的顺序。
    let _ = heartbeat;
    Ok(changed)
}

fn generation_digest(
    routes: &[Value],
    services: &BTreeMap<String, Value>,
    stream_listeners: &[Value],
) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(&(routes, services, stream_listeners))
        .context("encode route generation digest")?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

/// 业务作用：为当前 Kubernetes 物化 schema 计算同时覆盖 L7、L4 和 TLS listener 的
/// 完整性摘要。
///
/// 参数说明：所有参数均是即将原子发布的结构化候选，`proxy_tls` 只含路径与
/// SNI 映射，不包含私钥字节。
///
/// 返回：序列化成功时返回 SHA-256 摘要；结构无法编码时拒绝发布。
fn generation_digest_with_tls(
    routes: &[Value],
    services: &BTreeMap<String, Value>,
    stream_listeners: &[Value],
    proxy_tls: &Option<GeneratedProxyTls>,
) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(&(routes, services, stream_listeners, proxy_tls))
        .context("encode route and TLS generation digest")?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

/// 业务作用：为当前物化 schema 计算覆盖独立 HTTP/HTTPS proxy 路由与 TLS 身份的
/// 完整性摘要，防止局部替换 listener 后仍通过旧摘要。
///
/// 参数说明：各字段均是同一 generation 即将原子写入的完整候选。
///
/// 返回：稳定 JSON 编码成功时返回 SHA-256；无法编码时拒绝发布。
fn generation_digest_current(
    routes: &[Value],
    services: &BTreeMap<String, Value>,
    stream_listeners: &[Value],
    proxy_tls: &Option<GeneratedProxyTls>,
    http_proxies: &[GeneratedHttpProxy],
) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(&(routes, services, stream_listeners, proxy_tls, http_proxies))
        .context("encode route, listener and TLS generation digest")?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

/// 业务作用：兼容读取旧物化文档的摘要，允许 controller 在首次新轮询前平滑启动。
///
/// 参数说明：`routes` 与 `services` 是旧 schema 唯一参与摘要的两个域。
///
/// 返回：序列化成功时返回旧摘要；编码失败时拒绝旧候选而保留现有快照。
fn legacy_generation_digest(
    routes: &[Value],
    services: &BTreeMap<String, Value>,
) -> anyhow::Result<String> {
    let bytes =
        serde_json::to_vec(&(routes, services)).context("encode legacy route generation digest")?;
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
        cfg.gateway_api_version.as_str(),
        cfg.inference_extension_version.as_str(),
        cfg.gateway_bind_address.as_str(),
        cfg.gateway_stream_bind_address.as_str(),
        cfg.grpc_backend_protocol.as_str(),
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
    for value in &cfg.gateway_stream_bind_addresses {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update([
        u8::from(cfg.ingress_enabled),
        u8::from(cfg.gateway_api_enabled),
        u8::from(cfg.inference_gateway_enabled),
        u8::from(cfg.status_updates_enabled),
        u8::from(cfg.finalizers_enabled),
    ]);
    hasher.update(cfg.watch_timeout_seconds.to_le_bytes());
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

/// 业务作用：将 Gateway TLS 身份写入 controller 专属的不可变内容目录，并构造
/// 不含密钥字节的物化文档引用。
///
/// 参数说明：`document_path` 是已校验的物化文档路径；`plan` 包含同一
/// TLS socket 上的已验证身份。
///
/// 返回：所有 cert/key 均以目录 0700、文件 0600 完整发布后返回路径描述；
/// 任一写入或权限复验失败时不发布新 document；无可判定 SNI 的额外身份仅保留为
/// 已校验材料，不覆盖确定性的默认证书。
fn materialize_gateway_tls(
    document_path: &Path,
    plan: GatewayTlsPlan,
) -> anyhow::Result<GeneratedProxyTls> {
    anyhow::ensure!(
        !plan.identities.is_empty(),
        "Gateway TLS plan has no identities"
    );
    let parent = document_path.parent().unwrap_or_else(|| Path::new("."));
    let document_name = document_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Kubernetes materialized file name is not UTF-8")?;
    let root_name = format!(".{document_name}.tls");
    let root = parent.join(&root_name);
    ensure_private_directory(&root)?;
    let mut generated = Vec::with_capacity(plan.identities.len());
    for identity in plan.identities {
        let digest = tls_identity_digest(&identity.material);
        let directory = root.join(&digest);
        ensure_private_directory(&directory)?;
        let certificate_path = directory.join("cert.pem");
        let private_key_path = directory.join("key.pem");
        write_private_file_if_changed(&certificate_path, &identity.material.certificate_chain)?;
        write_private_file_if_changed(&private_key_path, &identity.material.private_key)?;
        generated.push(GeneratedSniCert {
            server_names: identity.server_names.into_iter().collect(),
            cert_file: format!("{root_name}/{digest}/cert.pem"),
            key_file: format!("{root_name}/{digest}/key.pem"),
        });
    }
    // 同一共享 socket 上多个无 hostname listener 无法由 ClientHello 区分；选择内容摘要
    // 排序后的稳定默认身份，避免一次无 SAN 证书使其它 Gateway 的已验证配置整体下线。
    // 只有具备明确名称的身份进入 SNI 表，防止空匹配覆盖或随机抢占默认证书。
    let default = generated
        .first()
        .context("Gateway TLS generated identity set is empty")?;
    let cert_file = default.cert_file.clone();
    let key_file = default.key_file.clone();
    let certs = if generated.len() > 1 {
        generated
            .into_iter()
            .filter(|cert| !cert.server_names.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let (client_ca_file, require_client_certificate, allow_untrusted_client_certificate) =
        match plan.client_auth {
            Some(client_auth) => {
                let digest = hex_lower(&Sha256::digest(&client_auth.ca_pem));
                let directory = root.join(format!("client-auth-{digest}"));
                ensure_private_directory(&directory)?;
                let ca_path = directory.join("ca.pem");
                write_private_file_if_changed(&ca_path, &client_auth.ca_pem)?;
                (
                    Some(format!("{root_name}/client-auth-{digest}/ca.pem")),
                    client_auth.require_client_certificate,
                    client_auth.allow_untrusted_client_certificate,
                )
            }
            None => (None, false, false),
        };
    Ok(GeneratedProxyTls {
        listen: plan.listen,
        cert_file,
        key_file,
        certs,
        client_ca_file,
        require_client_certificate,
        allow_untrusted_client_certificate,
    })
}

/// 业务作用：创建或复验仅当前用户可访问的 TLS 物化目录，防止私钥被同机
/// 其它账户读取。
///
/// 参数说明：`path` 必须位于已校验物化文档的同目录下。
///
/// 返回：目录存在且 Unix 模式已收紧为 0700 时成功；创建或 chmod 失败时
/// 拒绝 TLS 发布。
fn ensure_private_directory(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "TLS material directory must be a non-symlink directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)
            .with_context(|| format!("create TLS material dir {}", path.display()))?,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect TLS material dir {}", path.display()))
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod TLS material dir {}", path.display()))?;
    }
    Ok(())
}

/// 业务作用：仅在 TLS 物化内容变化时执行原子替换，避免 controller 健康轮询
/// 制造 secret watcher 风暴。
///
/// 参数说明：`path` 是 controller 专属 cert/key 路径；`bytes` 是已验证的 PEM。
///
/// 返回：内容相同时不改变 inode/mtime；不同时以 0600 临时文件 + rename 发布；
/// 读写错误阻断新路由文档。
fn write_private_file_if_changed(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if read_bounded_optional(path, MAX_TLS_SECRET_BYTES)?.is_some_and(|current| current == bytes) {
        return Ok(());
    }
    atomic_write(path, bytes)
}

/// 业务作用：复验物化 document 中的 TLS 路径和 socket 仍在 controller 所有权边界内，
/// 防止被篡改的本地文档读取任意私钥或绑定额外地址。
///
/// 参数说明：`tls` 是 document 声明；`cfg` 固定 bind IP 与物化文件名。
///
/// 返回：所有路径均是专属目录下的相对 cert/key 且 listen IP 一致时成功；
/// 越界、结构过大或地址不一致时拒绝候选。
fn validate_generated_tls(
    tls: &GeneratedProxyTls,
    cfg: &KubernetesRouteSourceCfg,
    config_dir: &Path,
) -> anyhow::Result<()> {
    let listen = tls
        .listen
        .parse::<std::net::SocketAddr>()
        .context("generated Kubernetes TLS listen is invalid")?;
    let expected_ip = cfg
        .gateway_bind_address
        .parse::<std::net::IpAddr>()
        .context("configured Gateway bind address is invalid")?;
    anyhow::ensure!(
        listen.ip() == expected_ip && listen.port() > 0,
        "generated Kubernetes TLS listen escapes configured bind address"
    );
    anyhow::ensure!(
        tls.certs.len() <= cfg.max_objects,
        "generated Kubernetes TLS identities exceed max_objects"
    );
    validate_generated_tls_path(&tls.cert_file, cfg, config_dir)?;
    validate_generated_tls_path(&tls.key_file, cfg, config_dir)?;
    for cert in &tls.certs {
        anyhow::ensure!(
            !cert.server_names.is_empty() && cert.server_names.len() <= 64,
            "generated Kubernetes SNI identity has invalid server_names"
        );
        for name in &cert.server_names {
            anyhow::ensure!(
                normalize_hostname(name)? == *name,
                "generated Kubernetes SNI hostname is not normalized"
            );
        }
        validate_generated_tls_path(&cert.cert_file, cfg, config_dir)?;
        validate_generated_tls_path(&cert.key_file, cfg, config_dir)?;
    }
    Ok(())
}

/// 业务作用：复验物化 document 中的 stream listener 没有越过 Gateway controller
/// 配置的专用绑定地址，防止本地候选借 reload 绑定额外接口。
///
/// 参数说明：`listener` 是已反序列化的生成配置；`cfg` 固定 stream 地址所有权边界。
///
/// 返回：listen 使用配置地址且端口非零时成功；地址越界或格式错误时拒绝整个候选。
fn validate_generated_stream_listener(
    listener: &StreamListenerCfg,
    cfg: &KubernetesRouteSourceCfg,
    config_dir: &Path,
) -> anyhow::Result<()> {
    let listen = listener
        .listen
        .parse::<std::net::SocketAddr>()
        .context("generated Kubernetes stream listen is invalid")?;
    let expected_ips = if cfg.gateway_stream_bind_addresses.is_empty() {
        BTreeSet::from([cfg
            .gateway_stream_bind_address
            .parse::<std::net::IpAddr>()
            .context("configured Gateway stream bind address is invalid")?])
    } else {
        cfg.gateway_stream_bind_addresses
            .iter()
            .map(|address| {
                address
                    .parse::<std::net::IpAddr>()
                    .context("configured Gateway stream address pool contains an invalid IP")
            })
            .collect::<anyhow::Result<BTreeSet<_>>>()?
    };
    anyhow::ensure!(
        expected_ips.contains(&listen.ip()) && listen.port() > 0,
        "generated Kubernetes stream listen escapes configured bind address"
    );
    let has_no_forward_target = listener.routes.is_empty() && listener.upstream.trim().is_empty();
    anyhow::ensure!(
        listener.reject_all == has_no_forward_target,
        "generated Kubernetes stream reject_all must exactly represent a missing forward target"
    );
    if let Some(tls) = &listener.tls {
        validate_generated_tls_path(&tls.cert_file, cfg, config_dir)?;
        validate_generated_tls_path(&tls.key_file, cfg, config_dir)?;
        anyhow::ensure!(
            tls.certs.len() <= cfg.max_objects,
            "generated Kubernetes stream TLS identities exceed max_objects"
        );
        for identity in &tls.certs {
            anyhow::ensure!(
                !identity.server_names.is_empty() && identity.server_names.len() <= 64,
                "generated Kubernetes stream SNI identity has invalid server_names"
            );
            for name in &identity.server_names {
                anyhow::ensure!(
                    normalize_hostname(name)? == *name,
                    "generated Kubernetes stream SNI hostname is not normalized"
                );
            }
            validate_generated_tls_path(&identity.cert_file, cfg, config_dir)?;
            validate_generated_tls_path(&identity.key_file, cfg, config_dir)?;
        }
    }
    Ok(())
}

/// 业务作用：限定单个生成 TLS 文件只能落在当前 materialized_file 的专属目录。
///
/// 参数说明：`value` 是 document 中的相对路径；`cfg` 提供专属目录前缀。
///
/// 返回：路径恰为“专属目录/六十四位摘要/cert.pem|key.pem”时成功；绝对路径、
/// 父目录跳转或非预期文件名均失败闭合。
fn validate_generated_tls_path(
    value: &str,
    cfg: &KubernetesRouteSourceCfg,
    config_dir: &Path,
) -> anyhow::Result<()> {
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    let expected_root = format!(".{}.tls", cfg.materialized_file);
    let valid = matches!(components.as_slice(), [
        Component::Normal(root),
        Component::Normal(digest),
        Component::Normal(file)
    ] if *root == std::ffi::OsStr::new(&expected_root)
        && digest.to_str().is_some_and(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        && matches!(file.to_str(), Some("cert.pem" | "key.pem")));
    anyhow::ensure!(
        valid,
        "generated Kubernetes TLS path escapes owned directory"
    );
    let root = config_dir.join(components[0].as_os_str());
    let directory = root.join(components[1].as_os_str());
    let file = directory.join(components[2].as_os_str());
    for directory in [&root, &directory] {
        let metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("inspect generated TLS directory {}", directory.display()))?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "generated TLS directory must be a non-symlink directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "generated TLS directory permissions are too broad"
            );
        }
    }
    let metadata = fs::symlink_metadata(&file)
        .with_context(|| format!("inspect generated TLS file {}", file.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "generated TLS material must be a non-symlink regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "generated TLS material permissions are too broad"
        );
    }
    Ok(())
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
