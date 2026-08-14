//! V7 开发者门户、OpenAPI 目录与自动路由物化。
//!
//! OpenAPI 文件只在 build-then-swap 阶段读取和解析。每个 operation 被翻译成现有
//! [`RouteCfg`]，因此认证、Usage Plan、schema 校验、上游池与热更仍只有一套执行语义。
//! 数据面不会在请求期查 catalog，也不会重新解析 OpenAPI。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use serde::Serialize;
use serde_json::Value;

use crate::config::model::{
    DeveloperCatalogCfg, DeveloperKeyApplicationsCfg, GatewayConfig, RequestValidationCfg, RouteCfg,
};

const MAX_CATALOGS: usize = 64;
const MAX_OPERATIONS: usize = 4_096;
const MAX_VALIDATION_BODY_BYTES: u64 = 16 * 1024 * 1024;
const HTTP_METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// 当前不可变快照公开的开发者门户读模型。
pub struct DeveloperPortalRuntime {
    enabled: bool,
    public_catalog: bool,
    catalogs: Arc<[DeveloperCatalogRuntime]>,
    key_applications: Option<DeveloperKeyApplicationsRuntime>,
    usage_plan_ids: Arc<HashSet<Arc<str>>>,
}

/// 一份已读取且有界的 API 文档。
pub struct DeveloperCatalogRuntime {
    /// URL 中使用的稳定 id。
    pub id: Arc<str>,
    /// 门户展示标题。
    pub title: Arc<str>,
    /// 门户展示描述。
    pub description: Arc<str>,
    /// 原始 OpenAPI 文件。`Bytes` 从唯一 `Vec<u8>` 接管，不做第二次文档拷贝。
    pub document: Bytes,
    /// 与文件扩展名一致的响应 Content-Type。
    pub content_type: &'static str,
    /// 只供目录页面展示的有界 operation 摘要。
    pub operations: Arc<[DeveloperOperationRuntime]>,
}

/// 门户展示的一条 OpenAPI operation。
pub struct DeveloperOperationRuntime {
    /// Stable operation id from OpenAPI, or a deterministic gateway-generated fallback.
    pub id: Arc<str>,
    /// Uppercase HTTP method displayed in the catalog.
    pub method: Arc<str>,
    /// OpenAPI path template used by the generated route.
    pub path: Arc<str>,
    /// Bounded human-readable summary; empty when the document does not declare one.
    pub summary: Arc<str>,
}

/// key 申请控制面预算与独立凭据。
pub struct DeveloperKeyApplicationsRuntime {
    /// Resolved portal-only Bearer secret. It is never serialized into catalog responses.
    pub authorization_token: Arc<[u8]>,
    /// Validated DynamicStore collection holding pending application records.
    pub collection: Arc<str>,
    /// Hard request-body limit for one JSON application.
    pub max_body_bytes: usize,
    /// Atomic collection capacity; an existing application id may still be overwritten at capacity.
    pub max_pending: usize,
}

/// 经过严格字段边界校验的 key 申请；不会直接生成或返回任何 secret。
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeveloperKeyApplication {
    /// Catalog being requested; must name a catalog in the current immutable snapshot.
    pub catalog_id: String,
    /// Stable external applicant identifier used, with catalog id, to derive an idempotency key.
    pub applicant_id: String,
    /// Optional bounded display label. It is metadata only and never becomes an identity.
    #[serde(default)]
    pub display_name: String,
    /// Optional plan request; when present it must name a configured Usage Plan.
    #[serde(default)]
    pub requested_plan: Option<String>,
}

impl DeveloperPortalRuntime {
    /// 读取所有 catalog、生成普通 routes，并构造门户只读快照。
    pub(crate) fn build_and_apply(cfg: &mut GatewayConfig, config_dir: &Path) -> Result<Arc<Self>> {
        let portal = cfg.developer_portal.clone();
        if !portal.enabled {
            anyhow::ensure!(
                portal.catalogs.is_empty() && !portal.key_applications.enabled,
                "developer_portal is disabled but catalogs/key_applications are configured"
            );
            anyhow::ensure!(
                !portal.public_catalog,
                "developer_portal.public_catalog requires enabled=true"
            );
            return Ok(Arc::new(Self::disabled()));
        }
        anyhow::ensure!(
            (1..=MAX_CATALOGS).contains(&portal.catalogs.len()),
            "developer_portal catalogs must be within 1..={MAX_CATALOGS}"
        );
        anyhow::ensure!(
            (1024..=8 * 1024 * 1024).contains(&portal.max_document_bytes),
            "developer_portal.max_document_bytes must be within 1024..=8388608"
        );

        let key_applications = build_key_applications(&portal.key_applications, config_dir)?;
        let usage_plan_ids = Arc::new(
            cfg.usage_plans
                .plans
                .keys()
                .map(|id| Arc::<str>::from(id.as_str()))
                .collect::<HashSet<_>>(),
        );
        let mut catalog_ids = HashSet::with_capacity(portal.catalogs.len());
        let mut catalogs = Vec::with_capacity(portal.catalogs.len());
        let mut total_operations = 0_usize;
        for catalog in &portal.catalogs {
            validate_token(&catalog.id, "developer catalog id")?;
            anyhow::ensure!(
                catalog_ids.insert(catalog.id.as_str()),
                "duplicate developer catalog id `{}`",
                catalog.id
            );
            let (runtime, routes) = build_catalog(catalog, config_dir, portal.max_document_bytes)?;
            total_operations = total_operations
                .checked_add(routes.len())
                .context("developer portal operation count overflow")?;
            anyhow::ensure!(
                total_operations <= MAX_OPERATIONS,
                "developer_portal supports at most {MAX_OPERATIONS} operations"
            );
            append_generated_routes(cfg, &catalog.proxy_id, routes)?;
            catalogs.push(runtime);
        }
        Ok(Arc::new(Self {
            enabled: true,
            public_catalog: portal.public_catalog,
            catalogs: catalogs.into(),
            key_applications,
            usage_plan_ids,
        }))
    }

    fn disabled() -> Self {
        Self {
            enabled: false,
            public_catalog: false,
            catalogs: Arc::from([]),
            key_applications: None,
            usage_plan_ids: Arc::new(HashSet::new()),
        }
    }

    /// Whether the portal was enabled in the successfully published snapshot.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether read-only catalog assets may bypass normal admin authentication.
    pub fn public_catalog(&self) -> bool {
        self.public_catalog
    }

    /// Return the separately authenticated pending-application endpoint policy, if enabled.
    pub fn key_applications(&self) -> Option<&DeveloperKeyApplicationsRuntime> {
        self.key_applications.as_ref()
    }

    /// Borrow one immutable catalog by stable id without allocating on the request path.
    pub fn catalog(&self, id: &str) -> Option<&DeveloperCatalogRuntime> {
        self.catalogs
            .iter()
            .find(|catalog| catalog.id.as_ref() == id)
    }

    /// 构造门户 catalog JSON。只复制有界展示字段，不复制 OpenAPI 文档正文。
    pub fn catalog_json(&self) -> Value {
        Value::Array(
            self.catalogs
                .iter()
                .map(|catalog| {
                    let operations = catalog
                        .operations
                        .iter()
                        .map(|operation| {
                            serde_json::json!({
                                "id": operation.id.as_ref(),
                                "method": operation.method.as_ref(),
                                "path": operation.path.as_ref(),
                                "summary": operation.summary.as_ref(),
                            })
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({
                        "id": catalog.id.as_ref(),
                        "title": catalog.title.as_ref(),
                        "description": catalog.description.as_ref(),
                        "openapi_url": format!("/api/developer/catalogs/{}/openapi", catalog.id),
                        "operations": operations,
                    })
                })
                .collect(),
        )
    }

    /// 解析并验证不可信申请 JSON。字段校验发生在写 DynamicStore 之前。
    pub fn parse_application(&self, bytes: &[u8]) -> Result<DeveloperKeyApplication> {
        let application: DeveloperKeyApplication =
            serde_json::from_slice(bytes).context("key application must be valid JSON")?;
        anyhow::ensure!(
            self.catalog(&application.catalog_id).is_some(),
            "unknown catalog_id"
        );
        validate_text(&application.applicant_id, 1, 128, "applicant_id")?;
        anyhow::ensure!(
            !application.applicant_id.chars().any(char::is_control),
            "applicant_id must not contain control characters"
        );
        validate_text(&application.display_name, 0, 128, "display_name")?;
        if let Some(plan) = application.requested_plan.as_deref() {
            validate_token(plan, "requested_plan")?;
            anyhow::ensure!(self.usage_plan_ids.contains(plan), "unknown requested_plan");
        }
        Ok(application)
    }
}

fn build_key_applications(
    cfg: &DeveloperKeyApplicationsCfg,
    config_dir: &Path,
) -> Result<Option<DeveloperKeyApplicationsRuntime>> {
    if !cfg.enabled {
        anyhow::ensure!(
            cfg.authorization_token.is_empty(),
            "disabled developer key_applications must not contain authorization_token"
        );
        return Ok(None);
    }
    validate_token(&cfg.collection, "key application collection")?;
    anyhow::ensure!(
        (1024..=64 * 1024).contains(&cfg.max_body_bytes),
        "developer key application max_body_bytes must be within 1024..=65536"
    );
    anyhow::ensure!(
        (1..=100_000).contains(&cfg.max_pending),
        "developer key application max_pending must be within 1..=100000"
    );
    let token = crate::secret::resolve_text(
        &cfg.authorization_token,
        config_dir,
        "developer key application authorization_token",
    )?;
    anyhow::ensure!(
        (16..=64 * 1024).contains(&token.len()),
        "developer key application authorization_token must resolve to 16..=65536 bytes"
    );
    Ok(Some(DeveloperKeyApplicationsRuntime {
        authorization_token: Arc::from(token.into_bytes()),
        collection: Arc::from(cfg.collection.as_str()),
        max_body_bytes: cfg.max_body_bytes,
        max_pending: cfg.max_pending,
    }))
}

fn build_catalog(
    cfg: &DeveloperCatalogCfg,
    config_dir: &Path,
    max_document_bytes: usize,
) -> Result<(DeveloperCatalogRuntime, Vec<RouteCfg>)> {
    anyhow::ensure!(
        (1..=MAX_VALIDATION_BODY_BYTES).contains(&cfg.max_validation_body_bytes),
        "developer catalog `{}` max_validation_body_bytes must be within 1..=16777216",
        cfg.id
    );
    anyhow::ensure!(
        !cfg.upstream.trim().is_empty(),
        "developer catalog `{}` upstream cannot be empty",
        cfg.id
    );
    let path = resolve_relative(config_dir, &cfg.openapi_file);
    // 先在同一文件句柄上做 max+1 有界读取，阻断 metadata→fs::read 的替换/增长竞态。
    // naml 当前按路径解析 OpenAPI；这份预检保证正常静态文件不会让解析器无界分配。
    let raw = crate::bounded_io::read_file(&path, max_document_bytes, "developer catalog OpenAPI")?;
    let document: Value = crate::config::loader(&path)
        .preserve_unresolved_placeholders(true)
        .load()
        .with_context(|| format!("parse developer catalog OpenAPI {}", path.display()))?;
    let version = document
        .get("openapi")
        .and_then(Value::as_str)
        .context("developer catalog requires string `openapi`")?;
    anyhow::ensure!(
        version.starts_with("3."),
        "developer catalog only supports OpenAPI 3.x, got `{version}`"
    );
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .context("developer catalog requires object `paths`")?;

    let info = document.get("info").and_then(Value::as_object);
    let title = non_empty_or(
        &cfg.title,
        info.and_then(|value| value.get("title"))
            .and_then(Value::as_str),
        &cfg.id,
    );
    let description = non_empty_or(
        &cfg.description,
        info.and_then(|value| value.get("description"))
            .and_then(Value::as_str),
        "",
    );
    validate_text(&title, 1, 256, "developer catalog title")?;
    validate_text(&description, 0, 4096, "developer catalog description")?;

    let mut routes = Vec::new();
    let mut operations = Vec::new();
    let mut operation_ids = HashSet::new();
    for (path_template, path_item) in paths {
        let path_object = path_item
            .as_object()
            .with_context(|| format!("OpenAPI path `{path_template}` must be an object"))?;
        anyhow::ensure!(
            !path_object.contains_key("$ref"),
            "OpenAPI path-item $ref is not supported by portal route generation"
        );
        for method in HTTP_METHODS {
            let Some(operation) = path_object.get(method) else {
                continue;
            };
            let operation = operation.as_object().with_context(|| {
                format!("OpenAPI operation {method} {path_template} must be an object")
            })?;
            let display_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{} {}", method.to_ascii_uppercase(), path_template));
            validate_text(&display_id, 1, 256, "OpenAPI operation id")?;
            anyhow::ensure!(
                operation_ids.insert(display_id.clone()),
                "developer catalog `{}` has duplicate operation id `{display_id}`",
                cfg.id
            );
            let summary = operation
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or("");
            validate_text(summary, 0, 1024, "OpenAPI operation summary")?;
            let route_hash_input = format!("{method}\0{path_template}");
            let route_hash = nasa::crypto::sha256(&route_hash_input);
            let route_id = format!("portal-{}-{}-{}", cfg.id, method, &route_hash[..16]);
            let has_request_body = operation.contains_key("requestBody");
            routes.push(RouteCfg {
                traffic_limit: None,
                forward_proxy: None,
                webtransport: None,
                early_data: None,
                ws_frame: None,
                id: route_id,
                uri: cfg.upstream.clone(),
                serve: None,
                predicates: vec![
                    if path_template.contains('{') {
                        format!("PathTemplate={path_template}")
                    } else {
                        format!("PathExact={path_template}")
                    },
                    format!("Method={}", method.to_ascii_uppercase()),
                ],
                filters: cfg.filters.clone(),
                upstream_credentials: Vec::new(),
                resolved_upstream_credentials: Vec::new(),
                preserve_host: false,
                gateway_redirect: None,
                hedge: None,
                request_validation: Some(RequestValidationCfg {
                    openapi_file: Some(cfg.openapi_file.clone()),
                    operation_path: Some(path_template.clone()),
                    operation_method: Some(method.to_owned()),
                    max_body_bytes: if has_request_body {
                        cfg.max_validation_body_bytes
                    } else {
                        0
                    },
                    ..RequestValidationCfg::default()
                }),
                request_transform: None,
                response_transform: None,
                response_contract: None,
                waf: None,
                geoip: None,
                bot: None,
                csrf: None,
                dlp: None,
                graphql_guard: None,
                degraphql: None,
                opa_authorization: None,
                casbin_authorization: None,
                wasm_plugins: Vec::new(),
                external_plugins: Vec::new(),
                ext_proc: None,
                inference_pool: None,
                bff_aggregation: None,
                dubbo: None,
                mock_response: None,
                fault_injection: None,
                usage_plan: cfg.usage_plan.clone(),
                llm: None,
                grpc_edge: None,
                grpc_transcoding: None,
                long_stream_idle_timeout_ms: None,
                request_timeout_ms: None,
                backend_request_timeout_ms: None,
                long_stream_max_lifetime_ms: 0,
                order: cfg.order,
            });
            operations.push(DeveloperOperationRuntime {
                id: Arc::from(display_id),
                method: Arc::from(method.to_ascii_uppercase()),
                path: Arc::from(path_template.as_str()),
                summary: Arc::from(summary),
            });
        }
    }
    anyhow::ensure!(
        !routes.is_empty(),
        "developer catalog `{}` contains no HTTP operations",
        cfg.id
    );
    let content_type = match path.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("json") => "application/json",
        _ => "application/yaml",
    };
    Ok((
        DeveloperCatalogRuntime {
            id: Arc::from(cfg.id.as_str()),
            title: Arc::from(title),
            description: Arc::from(description),
            document: Bytes::from(raw),
            content_type,
            operations: operations.into(),
        },
        routes,
    ))
}

fn append_generated_routes(
    cfg: &mut GatewayConfig,
    proxy_id: &str,
    routes: Vec<RouteCfg>,
) -> Result<()> {
    if cfg.proxies.is_empty() {
        anyhow::ensure!(
            proxy_id == "default",
            "developer catalog proxy_id `{proxy_id}` requires a matching proxies[].id; legacy server uses `default`"
        );
        cfg.routes.extend(routes);
        return Ok(());
    }
    let proxy = cfg
        .proxies
        .iter_mut()
        .find(|proxy| proxy.id == proxy_id)
        .with_context(|| format!("developer catalog references unknown proxy_id `{proxy_id}`"))?;
    proxy.routes.extend(routes);
    Ok(())
}

fn resolve_relative(config_dir: &Path, file: &str) -> PathBuf {
    let path = Path::new(file);
    if path.is_absolute() {
        path.to_owned()
    } else {
        config_dir.join(path)
    }
}

fn non_empty_or(configured: &str, document: Option<&str>, fallback: &str) -> String {
    if configured.trim().is_empty() {
        document
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(fallback)
            .to_owned()
    } else {
        configured.to_owned()
    }
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "{label} must be 1..=64 safe ASCII bytes"
    );
    Ok(())
}

fn validate_text(value: &str, min: usize, max: usize, label: &str) -> Result<()> {
    if !(min..=max).contains(&value.len())
        || value
            .chars()
            .any(|character| character == '\0' || (character.is_control() && character != '\n'))
    {
        bail!("{label} must be {min}..={max} bytes without control characters");
    }
    Ok(())
}
