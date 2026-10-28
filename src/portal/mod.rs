//! 开发者门户、产品目录与 OpenAPI 自动路由物化。
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

pub mod management;
pub use crate::observability::meter;
pub mod products;

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
    pub products: products::ProductCatalog,
    pub(crate) management: Option<management::Management>,
}

/// 一份已读取且有界的 API 文档。
pub struct DeveloperCatalogRuntime {
    /// URL 中使用的稳定 id。
    pub id: Arc<str>,
    /// 门户展示标题。
    pub title: Arc<str>,
    /// 门户展示描述。
    pub description: Arc<str>,
    /// 去除运行地址、凭据和未部署操作后的 OpenAPI 投影。
    pub document: Bytes,
    /// 投影统一以 JSON 交付，不执行文档内的 HTML。
    pub content_type: &'static str,
    /// 只供目录页面展示的有界 operation 摘要。
    pub operations: Arc<[DeveloperOperationRuntime]>,
}

/// 门户展示的一条 OpenAPI operation。
pub struct DeveloperOperationRuntime {
    /// OpenAPI 的稳定 operation 标识；缺省时由网关确定性生成。
    pub id: Arc<str>,
    /// 目录展示的大写 HTTP 方法。
    pub method: Arc<str>,
    /// 生成路由使用的 OpenAPI 路径模板。
    pub path: Arc<str>,
    /// 有界可读摘要；源文档未声明时为空。
    pub summary: Arc<str>,
}

/// key 申请控制面预算与独立凭据。
pub struct DeveloperKeyApplicationsRuntime {
    /// 已物化且仅供门户使用的 Bearer 凭据，不得序列化进目录响应。
    pub authorization_token: Arc<[u8]>,
    /// 保存待处理申请的已验证 DynamicStore 集合。
    pub collection: Arc<str>,
    /// 单份 JSON 申请的请求体字节硬上限。
    pub max_body_bytes: usize,
    /// 原子检查的集合容量上限；满额时仍允许覆盖已有申请标识。
    pub max_pending: usize,
}

/// 经过严格字段边界校验的 key 申请；不会直接生成或返回任何 secret。
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeveloperKeyApplication {
    /// 申请访问的目录标识，必须存在于当前不可变快照。
    pub catalog_id: String,
    /// 外部申请人的稳定标识，与目录标识共同构成幂等键。
    pub applicant_id: String,
    /// 可选有界展示名，只是元数据，不能作为身份依据。
    #[serde(default)]
    pub display_name: String,
    /// 可选目标计划；声明时必须引用已配置的 Usage Plan。
    #[serde(default)]
    pub requested_plan: Option<String>,
}

impl DeveloperPortalRuntime {
    /// 业务作用：冻结产品和 catalog，并将显式 OpenAPI 部署转换为普通 routes。
    ///
    /// 参数说明：
    /// - `cfg`：是未发布候选
    /// - `config_dir`：是文档根。
    ///
    /// 返回：所有文档和目录合法时返回只读门户；失败只丢弃候选，不影响线上快照。
    pub(crate) fn build_and_apply(cfg: &mut GatewayConfig, config_dir: &Path) -> Result<Arc<Self>> {
        let portal = cfg.developer_portal.clone();
        if !portal.enabled {
            anyhow::ensure!(
                portal.catalogs.is_empty()
                    && portal.products.is_empty()
                    && portal.management.is_none()
                    && !portal.key_applications.enabled,
                "developer_portal is disabled but catalogs/key_applications are configured"
            );
            anyhow::ensure!(
                !portal.public_catalog,
                "developer_portal.public_catalog requires enabled=true"
            );
            return Ok(Arc::new(Self::disabled()));
        }
        anyhow::ensure!(
            portal.catalogs.len() <= MAX_CATALOGS && (!portal.catalogs.is_empty() || !portal.products.is_empty()),
            "developer_portal requires catalogs or products, with at most {MAX_CATALOGS} route catalogs"
        );
        anyhow::ensure!(
            (1024..=8 * 1024 * 1024).contains(&portal.max_document_bytes),
            "developer_portal.max_document_bytes must be within 1024..=8388608"
        );

        let products = products::ProductCatalog::build(
            &portal.products,
            config_dir,
            portal.max_document_bytes,
        )?;
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
        let management = portal
            .management
            .as_ref()
            .map(|policy| management::build_and_apply(policy, cfg, config_dir, &products))
            .transpose()?;
        Ok(Arc::new(Self {
            enabled: true,
            public_catalog: portal.public_catalog,
            catalogs: catalogs.into(),
            key_applications,
            usage_plan_ids,
            products,
            management,
        }))
    }

    /// 业务作用：关闭门户时不建立目录或凭据资源。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有公开入口均不可用的空快照。
    fn disabled() -> Self {
        Self {
            enabled: false,
            public_catalog: false,
            catalogs: Arc::from([]),
            key_applications: None,
            usage_plan_ids: Arc::new(HashSet::new()),
            products: products::ProductCatalog::build(&[], Path::new("."), 1024)
                .expect("empty product catalog"),
            management: None,
        }
    }

    /// 业务作用：判定已发布快照是否开放门户功能。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：构建成功且门户启用时为 true。
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 业务作用：判定公共目录是否允许匿名读取，不赋予管理或私有资源权限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置显式允许公共读时为 true。
    pub fn public_catalog(&self) -> bool {
        self.public_catalog
    }

    /// 业务作用：提供独立认证的旧版待审批申请策略。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：启用时返回冻结策略；关闭时为 None。
    pub fn key_applications(&self) -> Option<&DeveloperKeyApplicationsRuntime> {
        self.key_applications.as_ref()
    }

    /// 业务作用：按稳定目录身份查询已发布合同。
    ///
    /// 参数说明：
    /// - `id`：为目录身份。
    ///
    /// 返回：存在时返回共享目录，否则为 None。
    pub fn catalog(&self, id: &str) -> Option<&DeveloperCatalogRuntime> {
        self.catalogs
            .iter()
            .find(|catalog| catalog.id.as_ref() == id)
    }

    /// 业务作用：生成目录展示数据，不携带原始配置、上游地址或凭据。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界摘要数组，不复制合同正文。
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

    /// 业务作用：在写入待审批存储前验证旧版申请的字段、目录与套餐引用。
    ///
    /// 参数说明：
    /// - `bytes`：为已经过请求长度门的 JSON。
    ///
    /// 返回：字段和引用合法时返回申请；非法输入不产生存储副作用。
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

/// 业务作用：冻结旧版申请接口的独立凭据和存储容量，避免与管理身份混用。
///
/// 参数说明：
/// - `cfg`：为申请策略
/// - `config_dir`：用于解析 SecretSource。
///
/// 返回：启用时返回合法策略，关闭时为 None；畸形预算或凭据拒绝候选。
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
    let token = crate::security::secret::resolve_text(
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

/// 业务作用：将有界 OpenAPI 合同编译为统一路由与安全公开投影。
///
/// 参数说明：
/// - `cfg`：固定目录、上游及路由策略
/// - `config_dir`：为文档根
/// - `max_document_bytes`：限制读取及展开。
///
/// 返回：全部操作可物化时返回目录与路由；失败不产生局部发布。
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
    let raw =
        crate::io::bounded_io::read_file(&path, max_document_bytes, "developer catalog OpenAPI")?;
    let document = crate::config::document::parse(&raw, max_document_bytes)
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
                layer: None,
                cgi: None,
                webdav: None,
                media: None,
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
                resolved_snippets: Vec::new(),
                #[cfg(feature = "config-providers")]
                provider_deadline: None,
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
                script_plugins: Vec::new(),
                external_plugins: Vec::new(),
                ext_proc: None,
                inference_pool: None,
                bff_aggregation: None,
                dubbo: None,
                mock_response: None,
                fault_injection: None,
                usage_plan: cfg.usage_plan.clone(),
                llm: None,
                agent: None,
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
    // 旧 catalog 也只公开实际部署的合同；原始 servers、认证配置和扩展不进入匿名读面。
    let mut projected_source = document.clone();
    for operation in &operations {
        projected_source["paths"][operation.path.as_ref()][operation.method.to_ascii_lowercase()]
            ["operationId"] = Value::String(operation.id.to_string());
    }
    let projection = products::project_api(
        &products::DocumentCfg {
            id: cfg.id.clone(),
            format: products::Format::Openapi,
            file: cfg.openapi_file.clone(),
            operations: operations
                .iter()
                .map(|operation| operation.id.to_string())
                .collect(),
        },
        &projected_source,
        max_document_bytes,
    )?
    .0;
    Ok((
        DeveloperCatalogRuntime {
            id: Arc::from(cfg.id.as_str()),
            title: Arc::from(title),
            description: Arc::from(description),
            document: projection.body,
            content_type: projection.content_type,
            operations: operations.into(),
        },
        routes,
    ))
}

/// 业务作用：把完整生成结果绑定到唯一监听器，保持与显式路由相同的构建校验。
///
/// 参数说明：
/// - `cfg`：为候选
/// - `proxy_id`：为监听器身份
/// - `routes`：为未发布路由。
///
/// 返回：引用存在时修改候选；未知监听器返回错误。
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

/// 业务作用：以配置根解释受信文档路径，避免进程 cwd 改变引用语义。
///
/// 参数说明：
/// - `config_dir`：为配置根
/// - `file`：为受信文件声明。
///
/// 返回：保留绝对路径或补全后的路径，不执行 I/O。
fn resolve_relative(config_dir: &Path, file: &str) -> PathBuf {
    let path = Path::new(file);
    if path.is_absolute() {
        path.to_owned()
    } else {
        config_dir.join(path)
    }
}

/// 业务作用：固定展示字段的配置、文档和缺省优先级。
///
/// 参数说明：
/// - `configured`：为显式覆盖
/// - `document`：为合同字段
/// - `fallback`：为最终缺省。
///
/// 返回：按优先级选择非空内容，长度和内容由调用方统一验证。
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

/// 业务作用：限制目录与资源身份，使其安全用于固定 URL 段和有界索引。
///
/// 参数说明：
/// - `value`：为身份
/// - `label`：是固定错误上下文。
///
/// 返回：安全 ASCII 且长度合规时成功，否则拒绝。
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

/// 业务作用：限制展示文本的字节预算与控制字符，避免不可信内容扩大目录资源占用。
///
/// 参数说明：
/// - `value`：为文本
/// - `min`：为字节范围
/// - `max`：为字节范围
/// - `label`：为错误上下文。
///
/// 返回：满足边界时成功；控制字符或越界返回错误。
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
