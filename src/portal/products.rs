//! 与路由身份分离的 API 产品目录、版本合同和公开文档投影。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// 产品身份独立于部署路由；版本和订阅只引用这个稳定身份。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductCfg {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub versions: Vec<VersionCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionCfg {
    pub id: String,
    pub lifecycle: Lifecycle,
    pub visibility: Visibility,
    #[serde(default)]
    pub deprecated_at: Option<String>,
    /// 允许订阅的团队；空集合不等于允许任意团队。
    #[serde(default)]
    pub subscription_teams: BTreeSet<String>,
    #[serde(default)]
    pub compare_to: Option<String>,
    pub documents: Vec<DocumentCfg>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Draft,
    Active,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentCfg {
    pub id: String,
    pub format: Format,
    pub file: String,
    /// API 文档只发布显式选择的 operation；Markdown 必须为空。
    #[serde(default)]
    pub operations: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Openapi,
    Asyncapi,
    Markdown,
}

pub struct ProductCatalog {
    products: Vec<Product>,
}

struct Product {
    id: String,
    title: String,
    description: String,
    versions: Vec<Version>,
}

struct Version {
    cfg: VersionCfg,
    documents: Vec<Document>,
    contracts: BTreeMap<String, String>,
    diff: Option<Value>,
}

pub struct Document {
    pub id: String,
    pub format: Format,
    pub body: Bytes,
    pub content_type: &'static str,
    operations: Vec<Value>,
}

impl ProductCatalog {
    /// 业务作用：复验应用订阅属于当前产品版本且团队在显式订阅范围内。
    ///
    /// 参数说明：
    /// - `product`：是固定合同身份
    /// - `version`：是固定合同身份
    /// - `team`：是应用 owner
    /// - `operation`：可限定部署操作。
    ///
    /// 返回：仅 active/deprecated 版本和显式授权团队可返回 true；未知合同拒绝。
    pub(crate) fn permits(
        &self,
        product: &str,
        version: &str,
        team: Option<&str>,
        operation: Option<&str>,
    ) -> bool {
        self.products
            .iter()
            .find(|p| p.id == product)
            .and_then(|p| p.versions.iter().find(|v| v.cfg.id == version))
            .is_some_and(|v| {
                matches!(v.cfg.lifecycle, Lifecycle::Active | Lifecycle::Deprecated)
                    && team.is_none_or(|team| v.cfg.subscription_teams.contains(team))
                    && operation.is_none_or(|operation| v.contracts.contains_key(operation))
            })
    }
    /// 业务作用：在候选阶段冻结产品身份、版本生命周期与有界文档，不从路由名称推断产品。
    ///
    /// 参数说明：
    /// - `configs`：是受信配置声明
    /// - `directory`：是配置根
    /// - `max_bytes`：为单份文档预算。
    ///
    /// 返回：全部引用、合同与投影有效时返回不可变目录；失败不发布任何局部产品。
    pub fn build(configs: &[ProductCfg], directory: &Path, max_bytes: usize) -> Result<Self> {
        ensure!(
            (1024..=8 * 1024 * 1024).contains(&max_bytes),
            "product document budget must be 1024..=8388608"
        );
        ensure!(configs.len() <= 128, "at most 128 API products are allowed");
        let mut products = Vec::new();
        let mut ids = BTreeSet::new();
        let mut total_documents = 0_usize;
        let mut total_bytes = 0_usize;
        for config in configs {
            super::validate_token(&config.id, "product id")?;
            super::validate_text(&config.title, 1, 256, "product title")?;
            super::validate_text(&config.description, 0, 4096, "product description")?;
            ensure!(ids.insert(&config.id), "duplicate product id");
            ensure!(
                (1..=32).contains(&config.versions.len()),
                "product requires 1..=32 versions"
            );
            let mut versions = Vec::new();
            let mut version_ids = BTreeSet::new();
            for version in &config.versions {
                super::validate_token(&version.id, "product version")?;
                ensure!(version_ids.insert(&version.id), "duplicate product version");
                ensure!(
                    (1..=16).contains(&version.documents.len()),
                    "version requires 1..=16 documents"
                );
                ensure!(
                    version.subscription_teams.len() <= 128,
                    "too many subscription teams"
                );
                for team in &version.subscription_teams {
                    super::validate_token(team, "subscription team")?;
                }
                ensure!(
                    (version.lifecycle == Lifecycle::Deprecated) == version.deprecated_at.is_some(),
                    "deprecated lifecycle requires deprecated_at; other lifecycles must omit it"
                );
                if let Some(time) = &version.deprecated_at {
                    chrono::DateTime::parse_from_rfc3339(time)
                        .context("deprecated_at must be RFC3339")?;
                }
                let mut document_ids = BTreeSet::new();
                let mut documents = Vec::new();
                let mut contracts = BTreeMap::new();
                for document in &version.documents {
                    super::validate_token(&document.id, "product document id")?;
                    ensure!(
                        document_ids.insert(&document.id),
                        "duplicate product document id"
                    );
                    total_documents += 1;
                    ensure!(total_documents <= 512, "product document capacity exceeded");
                    let (built, extracted) = build_document(document, directory, max_bytes)?;
                    total_bytes = total_bytes
                        .checked_add(built.body.len())
                        .context("product byte overflow")?;
                    ensure!(
                        total_bytes <= 32 * 1024 * 1024,
                        "product projection exceeds 32 MiB"
                    );
                    for (id, contract) in extracted {
                        ensure!(
                            contracts.insert(id, contract).is_none(),
                            "duplicate operation identity in product version"
                        );
                    }
                    ensure!(
                        contracts.len() <= 4096,
                        "version operation capacity exceeded"
                    );
                    documents.push(built);
                }
                versions.push(Version {
                    cfg: version.clone(),
                    documents,
                    contracts,
                    diff: None,
                });
            }
            // 比较基线必须属于同一产品且不同于目标版本，不能用另一产品的合同掩盖不兼容变化。
            for index in 0..versions.len() {
                if let Some(base_id) = &versions[index].cfg.compare_to {
                    ensure!(
                        base_id != &versions[index].cfg.id,
                        "version cannot compare to itself"
                    );
                    let baseline = versions
                        .iter()
                        .find(|v| &v.cfg.id == base_id)
                        .context("unknown product comparison version")?;
                    let candidate = &versions[index];
                    let removed: Vec<_> = baseline
                        .contracts
                        .keys()
                        .filter(|id| !candidate.contracts.contains_key(*id))
                        .cloned()
                        .collect();
                    let added: Vec<_> = candidate
                        .contracts
                        .keys()
                        .filter(|id| !baseline.contracts.contains_key(*id))
                        .cloned()
                        .collect();
                    let changed: Vec<_> = candidate
                        .contracts
                        .iter()
                        .filter(|(id, value)| {
                            baseline.contracts.get(*id).is_some_and(|old| old != *value)
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    let diff = json!({
                        "base": base_id,
                        "removed": removed,
                        "added": added,
                        "changed": changed,
                        "backward_compatible": removed.is_empty() && changed.is_empty(),
                        "comparison": "conservative_operation_contract"
                    });
                    versions[index].diff = Some(diff);
                }
            }
            products.push(Product {
                id: config.id.clone(),
                title: config.title.clone(),
                description: config.description.clone(),
                versions,
            });
        }
        Ok(Self {
            products,
        })
    }

    /// 业务作用：生成当前调用方可见的目录，不把订阅团队或私有版本暴露给匿名浏览者。
    ///
    /// 参数说明：
    /// - `privileged`：只允许由已通过管理认证及资源权限检查的入口传入。
    ///
    /// 返回：有界产品与版本摘要；匿名不可见产品完全省略，且不泄露其比较基线。
    pub fn json(&self, privileged: bool) -> Value {
        self.project_catalog(
            |v| visible(v, privileged),
            if privileged {
                "/api/products"
            } else {
                "/api/developer/products"
            },
        )
    }

    /// 业务作用：向已验证团队公开其可订阅的私有合同，草稿仍只属于管理读面。
    ///
    /// 参数说明：
    /// - `teams`：必须来自当前 SSO 主体的冻结团队角色。
    ///
    /// 返回：公开版本与获授权私有版本的低敏目录，不携带其它团队列表。
    pub(crate) fn team_json(&self, teams: &BTreeSet<&str>) -> Value {
        self.project_catalog(
            |v| team_visible(v, teams),
            "/api/developer/account/products",
        )
    }

    /// 业务作用：用同一可见性规则投影目录、文档地址和比较基线，防止差异字段泄露隐藏版本。
    ///
    /// 参数说明：
    /// - `permits`：是调用方权限裁决
    /// - `prefix`：是固定入口前缀。
    ///
    /// 返回：只含裁决允许版本的目录 JSON。
    fn project_catalog(&self, permits: impl Fn(&Version) -> bool, prefix: &str) -> Value {
        Value::Array(self.products.iter().filter_map(|product| {
            let visible: Vec<_> = product.versions.iter().filter(|v| permits(v)).collect();
            if visible.is_empty() {
                 return None;
            }
            let versions: Vec<_> = visible.iter().map(|version| {
                let diff = version.diff.as_ref().filter(|diff| visible.iter().any(|v| Some(v.cfg.id.as_str()) == diff["base"].as_str()));
                let documents: Vec<_> = version.documents.iter().map(|doc| json!({
                    "id": doc.id,
                    "format": doc.format,
                    "operations": doc.operations,
                    "url": format!("{}/{}/versions/{}/documents/{}", prefix, product.id, version.cfg.id, doc.id),
                })).collect();
                json!({
                    "id": version.cfg.id,
                    "lifecycle": version.cfg.lifecycle,
                    "visibility": version.cfg.visibility,
                    "deprecated_at": version.cfg.deprecated_at,
                    "documents": documents,
                    "compatibility_diff": diff
                })
            }).collect();
            Some(json!({
                "id": product.id,
                "title": product.title,
                "description": product.description,
                "versions": versions
            }))
        }).collect())
    }

    /// 业务作用：读取同一可见性边界内的冻结文档，避免直接文件出口绕过私有版本隐藏规则。
    ///
    /// 参数说明：
    /// - `product`：固定 URL 段中的产品标识。
    /// - `version`：固定 URL 段中的产品文档版本。
    /// - `document`：固定 URL 段中的文档标识。
    /// - `privileged`：管理认证是否授予特权，不能来自客户端自报字段。
    ///
    /// 返回：可见文档的共享字节；不存在或未授权统一为 None。
    pub fn document(
        &self,
        product: &str,
        version: &str,
        document: &str,
        privileged: bool,
    ) -> Option<&Document> {
        self.products
            .iter()
            .find(|p| p.id == product)?
            .versions
            .iter()
            .find(|v| v.cfg.id == version && visible(v, privileged))?
            .documents
            .iter()
            .find(|d| d.id == document)
    }

    /// 业务作用：将团队私有文档下载限制为与团队目录相同的权限集合。
    ///
    /// 参数说明：
    /// - `product`：固定 URL 段中的产品标识。
    /// - `version`：固定 URL 段中的产品文档版本。
    /// - `document`：固定 URL 段中的文档标识。
    /// - `teams`：已经验证的角色所允许的团队集合。
    ///
    /// 返回：可见文档；不存在和越权统一为 None。
    pub(crate) fn team_document(
        &self,
        product: &str,
        version: &str,
        document: &str,
        teams: &BTreeSet<&str>,
    ) -> Option<&Document> {
        self.products
            .iter()
            .find(|p| p.id == product)?
            .versions
            .iter()
            .find(|v| v.cfg.id == version && team_visible(v, teams))?
            .documents
            .iter()
            .find(|d| d.id == document)
    }
}

/// 业务作用：私有产品只向显式订阅团队开放，团队身份不赋予草稿发布权。
///
/// 参数说明：
/// - `version`：是冻结合同
/// - `teams`：是授权团队集合。
///
/// 返回：非草稿且公开或授权团队匹配时允许。
fn team_visible(version: &Version, teams: &BTreeSet<&str>) -> bool {
    version.cfg.lifecycle != Lifecycle::Draft
        && (version.cfg.visibility == Visibility::Public
            || version
                .cfg
                .subscription_teams
                .iter()
                .any(|team| teams.contains(team.as_str())))
}

/// 业务作用：固定匿名目录边界，草稿即使误写 public 也不能在发布前出现在门户。
///
/// 参数说明：
/// - `version`：是冻结合同
/// - `privileged`：表示经过授权的管理读。
///
/// 返回：管理读可见全部版本；匿名只可见非草稿且明确公开的版本。
fn visible(version: &Version, privileged: bool) -> bool {
    privileged
        || (version.cfg.visibility == Visibility::Public
            && version.cfg.lifecycle != Lifecycle::Draft)
}

/// 业务作用：从一次有界读取中生成低敏 API 合同，不执行 YAML imports、环境替换或远端引用。
///
/// 参数说明：
/// - `cfg`：选择格式与 operation allowlist
/// - `directory`：是配置根
/// - `max_bytes`：是读取硬门。
///
/// 返回：只包含选择操作的投影及独立合同摘要；畸形、未知格式或不支持的引用拒绝候选。
fn build_document(
    cfg: &DocumentCfg,
    directory: &Path,
    max_bytes: usize,
) -> Result<(Document, BTreeMap<String, String>)> {
    for id in &cfg.operations {
        super::validate_text(id, 1, 256, "operation identity")?;
    }
    let raw = crate::io::bounded_io::read_file(
        &super::resolve_relative(directory, &cfg.file),
        max_bytes,
        "product document",
    )?;
    if cfg.format == Format::Markdown {
        ensure!(
            cfg.operations.is_empty(),
            "Markdown cannot declare operations"
        );
        let text = std::str::from_utf8(&raw).context("Markdown must be UTF-8")?;
        // Markdown 按纯文本交付，不执行 HTML、远端图片或脚本；拒绝配置凭据引用误入公开正文。
        ensure!(
            !["literal://", "env://", "file://", "-----BEGIN", "${"]
                .iter()
                .any(|p| text.contains(p)),
            "Markdown contains a private source marker"
        );
        super::validate_text(text, 1, max_bytes, "Markdown")?;
        return Ok((
            Document {
                id: cfg.id.clone(),
                format: cfg.format,
                body: raw.into(),
                content_type: "text/plain; charset=utf-8",
                operations: Vec::new(),
            },
            BTreeMap::new(),
        ));
    }
    ensure!(
        !cfg.operations.is_empty() && cfg.operations.len() <= 4096,
        "API document requires 1..=4096 explicit operations"
    );
    let source = crate::config::document::parse(&raw, max_bytes)?;
    project_api(cfg, &source, max_bytes)
}

/// 业务作用：从同一次有界解析结果生成显式 operation 的公开合同，旧 catalog 和产品目录共用脱敏边界。
///
/// 参数说明：
/// - `cfg`：指定文档身份及已部署操作
/// - `source`：是不可变原文树
/// - `max_bytes`：限制引用展开。
///
/// 返回：JSON 合同及操作摘要；未知操作、远程引用或私有来源标记拒绝整个候选。
pub(super) fn project_api(
    cfg: &DocumentCfg,
    source: &Value,
    max_bytes: usize,
) -> Result<(Document, BTreeMap<String, String>)> {
    let mut contracts = BTreeMap::new();
    let mut operations = Vec::new();
    let mut projection = json!({});
    let mut budget = ProjectionBudget {
        nodes: 0,
        bytes: 0,
        max_bytes,
    };
    match cfg.format {
        Format::Openapi => {
            let version = source["openapi"]
                .as_str()
                .context("missing OpenAPI version")?;
            ensure!(
                version.starts_with("3.0.") || version.starts_with("3.1."),
                "only OpenAPI 3.0/3.1 catalogs are supported"
            );
            projection["openapi"] = json!(version);
            projection["paths"] = json!({});
            let paths = source["paths"]
                .as_object()
                .context("OpenAPI paths must be an object")?;
            for (path, item) in paths {
                for method in super::HTTP_METHODS {
                    let Some(operation) = item.get(method) else {
                        continue;
                    };
                    let Some(id) = operation["operationId"].as_str() else {
                        continue;
                    };
                    if !cfg.operations.contains(id) {
                        continue;
                    }
                    ensure!(
                        path.starts_with('/')
                            && !path.starts_with("//")
                            && !path.contains(['?', '#']),
                        "invalid operation path"
                    );
                    let mut projected =
                        project_operation(operation, source, 0, &mut budget, false)?;
                    if let Some(parameters) = item.get("parameters") {
                        let inherited =
                            project_operation(parameters, source, 0, &mut budget, false)?;
                        let list = projected
                            .as_object_mut()
                            .context("operation must be an object")?
                            .entry("parameters")
                            .or_insert(json!([]))
                            .as_array_mut()
                            .context("parameters must be an array")?;
                        // OpenAPI operation 参数按 (name, in) 覆盖 path 参数，重复追加会改变合同验证语义。
                        for parameter in inherited
                            .as_array()
                            .context("path parameters must be an array")?
                        {
                            ensure!(
                                parameter["name"].is_string() && parameter["in"].is_string(),
                                "invalid path parameter identity"
                            );
                            if !list.iter().any(|own| {
                                own["name"] == parameter["name"] && own["in"] == parameter["in"]
                            }) {
                                list.push(parameter.clone());
                            }
                        }
                    }
                    let contract = json!({
                        "path": path,
                        "method": method,
                        "operation": projected
                    });
                    ensure!(
                        contracts
                            .insert(id.to_owned(), nasa::crypto::sha256(&contract.to_string()))
                            .is_none(),
                        "duplicate operationId"
                    );
                    operations.push(json!({
                        "id": id,
                        "method": method.to_ascii_uppercase(),
                        "path": path
                    }));
                    if projection["paths"].get(path).is_none() {
                        projection["paths"][path] = json!({});
                    }
                    projection["paths"][path][method] = projected;
                }
            }
        }
        Format::Asyncapi => {
            ensure!(
                source["asyncapi"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("3.0.")),
                "only AsyncAPI 3.0 catalogs are supported"
            );
            projection["asyncapi"] = source["asyncapi"].clone();
            projection["operations"] = json!({});
            projection["channels"] = json!({});
            let all = source["operations"]
                .as_object()
                .context("AsyncAPI operations must be an object")?;
            for id in &cfg.operations {
                let operation = all.get(id).context("unknown selected AsyncAPI operation")?;
                let action = operation["action"]
                    .as_str()
                    .context("AsyncAPI operation action missing")?;
                ensure!(
                    matches!(action, "send" | "receive"),
                    "invalid AsyncAPI action"
                );
                let channel_ref = operation["channel"]["$ref"]
                    .as_str()
                    .context("AsyncAPI channel must be a local reference")?;
                ensure!(
                    channel_ref.starts_with("#/channels/"),
                    "AsyncAPI channel must reference local channels"
                );
                let channel = source
                    .pointer(&channel_ref[1..])
                    .context("unknown AsyncAPI channel")?;
                let channel_name = channel_ref
                    .strip_prefix("#/channels/")
                    .context("invalid channel reference")?;
                ensure!(
                    !channel_name.contains(['/', '~']),
                    "escaped channel ids are not supported"
                );
                ensure!(
                    operation.get("reply").is_none(),
                    "AsyncAPI reply channels require separately published operations"
                );
                let messages = channel["messages"]
                    .as_object()
                    .context("AsyncAPI channel messages missing")?;
                let mut selected = serde_json::Map::new();
                let prefix = format!("{channel_ref}/messages/");
                if let Some(refs) = operation.get("messages") {
                    for reference in refs
                        .as_array()
                        .context("AsyncAPI operation messages must be references")?
                    {
                        ensure!(
                            reference.as_object().is_some_and(|v| v.len() == 1),
                            "invalid AsyncAPI message reference"
                        );
                        let name = reference["$ref"]
                            .as_str()
                            .and_then(|s| s.strip_prefix(&prefix))
                            .context("AsyncAPI operation messages must reference its channel")?;
                        ensure!(
                            !name.contains(['/', '~']),
                            "escaped message ids are not supported"
                        );
                        selected.insert(
                            name.to_owned(),
                            messages
                                .get(name)
                                .context("unknown AsyncAPI message")?
                                .clone(),
                        );
                    }
                } else {
                    selected = messages.clone();
                }
                let mut selected_channel = channel.clone();
                selected_channel["messages"] = Value::Object(selected);
                let projected_channel =
                    project_operation(&selected_channel, source, 0, &mut budget, false)?;
                let mut selected_operation = operation.clone();
                let fields = selected_operation
                    .as_object_mut()
                    .context("AsyncAPI operation must be an object")?;
                fields.remove("channel");
                fields.remove("messages");
                // message 引用必须保留为当前 channel 下的引用；只展开被选消息，不能把同 channel 的私有消息一并公开。
                let mut projected =
                    project_operation(&selected_operation, source, 0, &mut budget, false)?;
                projected["channel"] = json!({
                    "$ref": channel_ref
                });
                if let Some(messages) = operation.get("messages") {
                    projected["messages"] = messages.clone();
                }
                let contract = json!({
                    "operation": projected,
                    "channel": projected_channel
                });
                contracts.insert(id.clone(), nasa::crypto::sha256(&contract.to_string()));
                operations.push(json!({
                    "id": id,
                    "action": action,
                    "channel": channel_name
                }));
                if let Some(existing) = projection["channels"].get_mut(channel_name) {
                    existing["messages"]
                        .as_object_mut()
                        .context("invalid projected messages")?
                        .extend(
                            projected_channel["messages"]
                                .as_object()
                                .context("invalid projected messages")?
                                .clone(),
                        );
                } else {
                    projection["channels"][channel_name] = projected_channel;
                }
                projection["operations"][id] = projected;
            }
        }
        Format::Markdown => unreachable!(),
    }
    ensure!(
        contracts.keys().cloned().collect::<BTreeSet<_>>() == cfg.operations,
        "selected API operation is missing"
    );
    let title = source["info"]["title"]
        .as_str()
        .context("API info.title missing")?;
    let version = source["info"]["version"]
        .as_str()
        .context("API info.version missing")?;
    super::validate_text(title, 1, 256, "API title")?;
    super::validate_text(version, 1, 128, "API version")?;
    projection["info"] = json!({
        "title": title,
        "version": version
    });
    let bytes = serde_json::to_vec(&projection)?;
    ensure!(
        bytes.len() <= max_bytes,
        "expanded API projection exceeds document budget"
    );
    Ok((
        Document {
            id: cfg.id.clone(),
            format: cfg.format,
            body: bytes.into(),
            content_type: "application/json",
            operations,
        },
        contracts,
    ))
}

/// 业务作用：展开本地合同引用并剥离服务器、认证、示例和扩展，防止内部目标及凭据进入公开 API 文档。
///
/// 参数说明：
/// - `value`：是待投影节点
/// - `root`：用于本地引用
/// - `depth`：限制整份文档展开
/// - `budget`：限制整份文档展开
/// - `names`：表示本层键是业务属性名称，不能当成协议字段裁剪。
///
/// 返回：不含私有运行信息的合同树；远端引用、递归或预算耗尽全部拒绝。
fn project_operation(
    value: &Value,
    root: &Value,
    depth: usize,
    budget: &mut ProjectionBudget,
    names: bool,
) -> Result<Value> {
    budget.nodes += 1;
    budget.bytes = budget
        .bytes
        .saturating_add(value.as_str().map_or(8, str::len));
    ensure!(
        depth <= 32 && budget.nodes <= 65536 && budget.bytes <= budget.max_bytes,
        "API reference expansion budget exceeded"
    );
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").filter(|_| !names) {
                ensure!(
                    object.len() == 1,
                    "reference siblings require an explicitly inlined contract"
                );
                let pointer = reference
                    .as_str()
                    .filter(|r| r.starts_with("#/"))
                    .context("only local API references are supported")?;
                return project_operation(
                    root.pointer(&pointer[1..])
                        .context("unresolved API reference")?,
                    root,
                    depth + 1,
                    budget,
                    false,
                );
            }
            let mut output = serde_json::Map::new();
            for (key, child) in object {
                if !names
                    && (key.starts_with("x-")
                        || matches!(
                            key.as_str(),
                            "servers"
                                | "security"
                                | "securitySchemes"
                                | "externalDocs"
                                | "links"
                                | "callbacks"
                                | "examples"
                                | "example"
                                | "default"
                                | "bindings"
                                | "traits"
                        ))
                {
                    continue;
                }
                budget.bytes = budget.bytes.saturating_add(key.len());
                let child_names = !names
                    && matches!(
                        key.as_str(),
                        "properties"
                            | "patternProperties"
                            | "$defs"
                            | "definitions"
                            | "headers"
                            | "content"
                            | "responses"
                            | "messages"
                    );
                output.insert(
                    key.clone(),
                    project_operation(child, root, depth + 1, budget, child_names)?,
                );
            }
            Ok(Value::Object(output))
        }
        Value::Array(values) => values
            .iter()
            .map(|v| project_operation(v, root, depth + 1, budget, false))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::String(text) => {
            ensure!(
                !["literal://", "env://", "file://", "-----BEGIN", "${"]
                    .iter()
                    .any(|p| text.contains(p)),
                "API contract contains a private source marker"
            );
            Ok(value.clone())
        }
        _ => Ok(value.clone()),
    }
}

struct ProjectionBudget {
    nodes: usize,
    bytes: usize,
    max_bytes: usize,
}
