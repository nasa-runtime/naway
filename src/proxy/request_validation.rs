//! V5 路由级 OpenAPI / JSON Schema 请求校验。
//!
//! 该能力被明确归入 `架构规范` 的 slow path：只有 route 显式配置后才构造 JSON
//! envelope 或读取 body。schema 在快照构建时编译成只读 validator，请求阶段只借用 head；
//! body 必须有硬上限，校验后复用同一份 [`Bytes`] 交给上游。

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE};
use http::request::Parts;
use http::HeaderMap;
use http_body_util::BodyExt;
use serde_json::{json, Map, Value};

use crate::config::loader;
use crate::config::model::RequestValidationCfg;
use crate::{BoxBody, BoxError};

use super::forward::ForwardBody;

/// 单 route 允许的最大 schema 校验 body。控制面还能配置更小值；该硬上限约束并发内存。
const MAX_VALIDATION_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// 编译后的请求校验计划。`jsonschema::Validator` 可在线程间共享，reload 时随旧快照退场。
pub(crate) struct RequestValidationPlan {
    /// 可选 head validator 与它的实例构造方式。
    head: Option<HeadValidation>,
    /// 可选 JSON body validator。
    body: Option<jsonschema::Validator>,
    /// body 是否必须非空。
    body_required: bool,
    /// body 聚合硬上限；只有 `body.is_some()` 时非零。
    max_body_bytes: u64,
    /// OpenAPI 声明的 JSON media types；显式 body schema 固定接受 JSON / `+json`。
    body_media_types: Vec<String>,
}

struct HeadValidation {
    validator: jsonschema::Validator,
    mode: HeadMode,
}

enum HeadMode {
    /// 路由内联 schema 的稳定、无类型转换 envelope。
    Raw,
    /// OpenAPI operation 的参数解码计划。
    OpenApi(OpenApiHeadPlan),
}

struct OpenApiHeadPlan {
    path_template: String,
    parameters: Vec<ParameterPlan>,
}

struct OpenApiCompilation {
    head: Option<HeadValidation>,
    body_schema: Option<Value>,
    body_required: bool,
    body_media_types: Vec<String>,
}

struct ParameterPlan {
    location: ParameterLocation,
    name: String,
    decode: ParameterDecode,
}

#[derive(Clone, Copy)]
enum ParameterLocation {
    Query,
    Header,
    Path,
    Cookie,
}

enum ParameterDecode {
    Scalar(ScalarKind),
    Array {
        item: ScalarKind,
        /// `explode=false`/header simple style 使用逗号分隔；`explode=true` 保留重复参数。
        comma_separated: bool,
    },
}

#[derive(Clone, Copy)]
enum ScalarKind {
    String,
    Integer,
    Number,
    Boolean,
}

/// schema 慢路径结果。错误种类由入口稳定映射为 400/413，不得冒充上游 502。
pub(super) enum ValidationOutcome {
    /// 校验成功；body 可能仍为原始流，也可能是复用已聚合 [`Bytes`] 的 boxed body。
    Valid(ForwardBody),
    /// head、JSON 语法、Content-Type 或 schema 不符合契约。
    BadRequest(&'static str),
    /// 声明或实际 body 超过 route 的显式校验上限。
    TooLarge,
    /// 下游 body transport 读取失败。它不是上游错误，统一返回 400。
    BodyReadFailed,
}

impl RequestValidationPlan {
    /// 从 route 配置构建并编译校验器。
    ///
    /// 文件路径相对主配置目录解析；所有外部 `$ref` 在 build-then-swap 阶段拒绝，避免
    /// reload 后的数据面触发网络或文件 resolver。
    pub(crate) fn build(
        cfg: &RequestValidationCfg,
        config_dir: &Path,
        route_id: &str,
    ) -> Result<Self> {
        let explicit = cfg.head_schema.is_some()
            || cfg.head_schema_file.is_some()
            || cfg.body_schema.is_some()
            || cfg.body_schema_file.is_some();
        if cfg.openapi_file.is_some() && explicit {
            bail!("route `{route_id}` request_validation openapi_file is mutually exclusive with explicit head/body schema");
        }
        let path_selector = cfg.operation_path.is_some() || cfg.operation_method.is_some();
        if cfg.operation_path.is_some() != cfg.operation_method.is_some() {
            bail!("route `{route_id}` request_validation operation_path and operation_method must be configured together");
        }
        if cfg.openapi_file.is_none() && (cfg.operation_id.is_some() || path_selector) {
            bail!("route `{route_id}` OpenAPI operation selector requires openapi_file");
        }
        if cfg.openapi_file.is_some() && (cfg.operation_id.is_some() == path_selector) {
            bail!("route `{route_id}` request_validation openapi_file requires exactly one selector: operation_id or operation_path+operation_method");
        }
        if cfg.head_schema.is_some() && cfg.head_schema_file.is_some() {
            bail!("route `{route_id}` request_validation head_schema and head_schema_file are mutually exclusive");
        }
        if cfg.body_schema.is_some() && cfg.body_schema_file.is_some() {
            bail!("route `{route_id}` request_validation body_schema and body_schema_file are mutually exclusive");
        }

        let (head, body_schema, openapi_body_required, body_media_types) = if let Some(file) =
            &cfg.openapi_file
        {
            let path = resolve_schema_path(config_dir, file);
            let document = load_value(&path)
                .with_context(|| format!("route `{route_id}` OpenAPI {}", path.display()))?;
            let selector = OpenApiOperationSelector {
                operation_id: cfg.operation_id.as_deref(),
                path: cfg.operation_path.as_deref(),
                method: cfg.operation_method.as_deref(),
            };
            let selector_label = selector.label();
            let compiled = compile_openapi_operation(&document, selector).with_context(|| {
                format!("route `{route_id}` OpenAPI operation {selector_label}")
            })?;
            (
                compiled.head,
                compiled.body_schema,
                compiled.body_required,
                compiled.body_media_types,
            )
        } else {
            let head_schema = load_schema_source(
                cfg.head_schema.as_ref(),
                cfg.head_schema_file.as_deref(),
                config_dir,
                "head",
                route_id,
            )?;
            let body_schema = load_schema_source(
                cfg.body_schema.as_ref(),
                cfg.body_schema_file.as_deref(),
                config_dir,
                "body",
                route_id,
            )?;
            let head = head_schema
                .map(|schema| {
                    compile_validator(schema, "head").map(|validator| HeadValidation {
                        validator,
                        mode: HeadMode::Raw,
                    })
                })
                .transpose()?;
            (
                head,
                body_schema,
                true,
                vec!["application/json".to_string()],
            )
        };

        if head.is_none() && body_schema.is_none() {
            bail!("route `{route_id}` request_validation must define head_schema, body_schema, or openapi_file");
        }
        let body = body_schema
            .map(|schema| compile_validator(schema, "body"))
            .transpose()?;
        let max_body_bytes = if body.is_some() {
            if !(1..=MAX_VALIDATION_BODY_BYTES).contains(&cfg.max_body_bytes) {
                bail!(
                    "route `{route_id}` request_validation with body schema requires max_body_bytes within 1..={MAX_VALIDATION_BODY_BYTES}"
                );
            }
            cfg.max_body_bytes
        } else {
            if cfg.max_body_bytes != 0 {
                bail!("route `{route_id}` request_validation max_body_bytes is only valid with a body schema");
            }
            0
        };

        Ok(Self {
            head,
            body,
            body_required: cfg.body_required.unwrap_or(openapi_body_required),
            max_body_bytes,
            body_media_types,
        })
    }

    /// 是否会读取 request body。用于构建期排除 body 未纳入 key 的公共响应缓存组合。
    pub(crate) fn validates_body(&self) -> bool {
        self.body.is_some()
    }

    /// 校验请求 head，并在确有 body schema 时有界收集/校验 body。
    ///
    /// 默认 route 不会调用本函数。配置了 head-only schema 时 `ForwardBody` 原样返回；配置
    /// body schema 时才发生一次必要的聚合，返回值继续持有同一引用计数字节块。
    pub(super) async fn validate(&self, parts: &Parts, body: ForwardBody) -> ValidationOutcome {
        if let Some(head) = &self.head {
            let instance = match build_head_instance(parts, &head.mode) {
                Ok(instance) => instance,
                Err(message) => return ValidationOutcome::BadRequest(message),
            };
            if let Err(error) = head.validator.validate(&instance) {
                tracing::debug!(
                    instance_path = %error.instance_path(),
                    schema_path = %error.schema_path(),
                    "request head schema validation failed"
                );
                return ValidationOutcome::BadRequest("request head schema validation failed");
            }
        }

        let Some(validator) = &self.body else {
            return ValidationOutcome::Valid(body);
        };
        if content_length(parts).is_some_and(|length| length > self.max_body_bytes) {
            return ValidationOutcome::TooLarge;
        }
        let collected = match collect_bounded(body, self.max_body_bytes).await {
            Ok(collected) => collected,
            Err(CollectError::TooLarge) => return ValidationOutcome::TooLarge,
            Err(CollectError::Read) => return ValidationOutcome::BodyReadFailed,
        };
        if collected.bytes.is_empty() && !self.body_required {
            return ValidationOutcome::Valid(buffered_body(collected));
        }
        if collected.bytes.is_empty() {
            return ValidationOutcome::BadRequest("request JSON body is required");
        }
        if !request_media_type_is_json(parts, self.body_media_types.as_slice()) {
            return ValidationOutcome::BadRequest("request body content-type is not JSON");
        }

        // `serde_json` 直接借用 Bytes 的切片解析输入，不先构造 String。Value 本身的树分配是
        // JSON Schema 校验不可避免的 slow-path 成本；原始 Bytes 仍原样复用给上游。
        let value: Value = match serde_json::from_slice(collected.bytes.as_ref()) {
            Ok(value) => value,
            Err(error) => {
                tracing::debug!(
                    line = error.line(),
                    column = error.column(),
                    "request JSON parse failed"
                );
                return ValidationOutcome::BadRequest("request body is not valid JSON");
            }
        };
        if let Err(error) = validator.validate(&value) {
            tracing::debug!(
                instance_path = %error.instance_path(),
                schema_path = %error.schema_path(),
                "request body schema validation failed"
            );
            return ValidationOutcome::BadRequest("request body schema validation failed");
        }
        ValidationOutcome::Valid(buffered_body(collected))
    }
}

/// 从 inline/file 二选一来源读取 schema。
fn load_schema_source(
    inline: Option<&Value>,
    file: Option<&str>,
    config_dir: &Path,
    label: &str,
    route_id: &str,
) -> Result<Option<Value>> {
    if let Some(value) = inline {
        return Ok(Some(value.clone()));
    }
    let Some(file) = file else {
        return Ok(None);
    };
    let path = resolve_schema_path(config_dir, file);
    load_value(&path)
        .with_context(|| {
            format!(
                "route `{route_id}` request_validation {label} schema {}",
                path.display()
            )
        })
        .map(Some)
}

/// 使用 nasa YAML loader 读取 JSON/YAML Value，与网关配置的占位符/格式行为保持一致。
fn load_value(path: &Path) -> Result<Value> {
    loader(path)
        .preserve_unresolved_placeholders(true)
        .load()
        .with_context(|| format!("load schema document {}", path.display()))
}

fn resolve_schema_path(config_dir: &Path, file: &str) -> std::path::PathBuf {
    let path = Path::new(file);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

/// 编译 validator，并显式禁止外部引用。
fn compile_validator(schema: Value, label: &str) -> Result<jsonschema::Validator> {
    reject_external_refs(&schema, label)?;
    jsonschema::validator_for(&schema)
        .map_err(|error| anyhow::anyhow!("compile {label} JSON Schema: {error}"))
}

fn reject_external_refs(value: &Value, label: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(key.as_str(), "$ref" | "$dynamicRef") {
                    let reference = child
                        .as_str()
                        .with_context(|| format!("{label} schema {key} must be a string"))?;
                    if !reference.starts_with("#/") && reference != "#" {
                        bail!("{label} schema external reference `{reference}` is forbidden");
                    }
                }
                reject_external_refs(child, label)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_external_refs(child, label)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct OpenApiOperationSelector<'a> {
    operation_id: Option<&'a str>,
    path: Option<&'a str>,
    method: Option<&'a str>,
}

impl OpenApiOperationSelector<'_> {
    fn matches(&self, path: &str, method: &str, operation: &Value) -> bool {
        self.operation_id.is_some_and(|operation_id| {
            operation.get("operationId").and_then(Value::as_str) == Some(operation_id)
        }) || self.path.is_some_and(|expected| expected == path)
            && self
                .method
                .is_some_and(|expected| expected.eq_ignore_ascii_case(method))
    }

    fn label(&self) -> String {
        self.operation_id.map_or_else(
            || {
                format!(
                    "{} {}",
                    self.method.unwrap_or("<missing>"),
                    self.path.unwrap_or("<missing>")
                )
            },
            |id| format!("operationId `{id}`"),
        )
    }
}

/// 返回 `(head, body_schema, body_required, JSON media types)`。
fn compile_openapi_operation(
    document: &Value,
    selector: OpenApiOperationSelector<'_>,
) -> Result<OpenApiCompilation> {
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .context("OpenAPI document requires object `paths`")?;
    let mut found = None;
    for (path_template, path_item) in paths {
        let Some(path_object) = path_item.as_object() else {
            continue;
        };
        for method in [
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ] {
            let Some(operation) = path_object.get(method) else {
                continue;
            };
            if selector.matches(path_template, method, operation) {
                if found.is_some() {
                    bail!("duplicate OpenAPI operation selector {}", selector.label());
                }
                found = Some((path_template.as_str(), method, path_object, operation));
            }
        }
    }
    let (path_template, method, path_item, operation) =
        found.with_context(|| format!("OpenAPI operation {} not found", selector.label()))?;

    let mut parameters = Vec::new();
    if let Some(values) = path_item.get("parameters") {
        append_openapi_parameters(document, values, &mut parameters)?;
    }
    if let Some(values) = operation.get("parameters") {
        append_openapi_parameters(document, values, &mut parameters)?;
    }
    // operation-level parameter overrides同名 path-level 参数。
    let mut unique = HashMap::new();
    for parameter in parameters {
        unique.insert(
            (parameter.location as u8, parameter.name.clone()),
            parameter,
        );
    }
    let parameters = unique.into_values().collect::<Vec<_>>();

    let components = document
        .get("components")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut query_properties = Map::new();
    let mut header_properties = Map::new();
    let mut path_properties = Map::new();
    let mut cookie_properties = Map::new();
    let mut query_required = Vec::new();
    let mut header_required = Vec::new();
    let mut path_required = Vec::new();
    let mut cookie_required = Vec::new();
    for parameter in &parameters {
        let (schema, required) =
            openapi_parameter_schema(document, operation, path_item, parameter)?;
        match parameter.location {
            ParameterLocation::Query => {
                query_properties.insert(parameter.name.clone(), schema);
                if required {
                    query_required.push(Value::String(parameter.name.clone()));
                }
            }
            ParameterLocation::Header => {
                header_properties.insert(parameter.name.clone(), schema);
                if required {
                    header_required.push(Value::String(parameter.name.clone()));
                }
            }
            ParameterLocation::Path => {
                path_properties.insert(parameter.name.clone(), schema);
                path_required.push(Value::String(parameter.name.clone()));
            }
            ParameterLocation::Cookie => {
                cookie_properties.insert(parameter.name.clone(), schema);
                if required {
                    cookie_required.push(Value::String(parameter.name.clone()));
                }
            }
        }
    }

    let head_schema = json!({
        "type": "object",
        "properties": {
            "method": {"const": method.to_ascii_uppercase()},
            "path": {"type": "string"},
            "query": object_schema(query_properties, query_required, false),
            "headers": object_schema(header_properties, header_required, true),
            "path_params": object_schema(path_properties, path_required, false)
            ,"cookies": object_schema(cookie_properties, cookie_required, false)
        },
        "required": ["method", "path", "query", "headers", "path_params", "cookies"],
        "additionalProperties": false,
        "components": components
    });
    let head = Some(HeadValidation {
        validator: compile_validator(head_schema, "OpenAPI request head")?,
        mode: HeadMode::OpenApi(OpenApiHeadPlan {
            path_template: path_template.to_string(),
            parameters,
        }),
    });

    let (body_schema, required, media_types) = openapi_request_body(document, operation)?;
    Ok(OpenApiCompilation {
        head,
        body_schema,
        body_required: required,
        body_media_types: media_types,
    })
}

fn object_schema(properties: Map<String, Value>, required: Vec<Value>, allow_extra: bool) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": allow_extra
    })
}

/// OpenAPI 参数先只收集位置/名字/解码策略；schema 在第二遍查找，避免复制进 runtime plan。
fn append_openapi_parameters(
    document: &Value,
    values: &Value,
    output: &mut Vec<ParameterPlan>,
) -> Result<()> {
    let values = values
        .as_array()
        .context("OpenAPI parameters must be an array")?;
    for raw in values {
        let parameter = resolve_local_object(document, raw, "parameter")?;
        let location = match parameter.get("in").and_then(Value::as_str) {
            Some("query") => ParameterLocation::Query,
            Some("header") => ParameterLocation::Header,
            Some("path") => ParameterLocation::Path,
            Some("cookie") => ParameterLocation::Cookie,
            Some(other) => bail!("unsupported OpenAPI parameter location `{other}`"),
            None => bail!("OpenAPI parameter requires `in`"),
        };
        let mut name = parameter
            .get("name")
            .and_then(Value::as_str)
            .context("OpenAPI parameter requires string `name`")?
            .to_string();
        if matches!(location, ParameterLocation::Header) {
            name.make_ascii_lowercase();
        }
        if matches!(location, ParameterLocation::Cookie)
            && parameter
                .get("style")
                .and_then(Value::as_str)
                .is_some_and(|style| style != "form")
        {
            bail!("OpenAPI cookie parameters only support form style");
        }
        let schema = parameter
            .get("schema")
            .context("OpenAPI parameter requires `schema`")?;
        let resolved_schema = resolve_local_value(document, schema, "parameter schema")?;
        let decode = parameter_decode(parameter, resolved_schema)?;
        output.push(ParameterPlan {
            location,
            name,
            decode,
        });
    }
    Ok(())
}

/// 重新查找该 parameter 的 schema/required。operation 参数优先于 path-item 参数。
fn openapi_parameter_schema(
    document: &Value,
    operation: &Value,
    path_item: &Map<String, Value>,
    plan: &ParameterPlan,
) -> Result<(Value, bool)> {
    let candidates = operation
        .get("parameters")
        .into_iter()
        .chain(path_item.get("parameters"));
    for values in candidates {
        let Some(values) = values.as_array() else {
            continue;
        };
        for raw in values {
            let parameter = resolve_local_object(document, raw, "parameter")?;
            let Some(location) = parameter.get("in").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = parameter.get("name").and_then(Value::as_str) else {
                continue;
            };
            let same_location = matches!(
                (plan.location, location),
                (ParameterLocation::Query, "query")
                    | (ParameterLocation::Header, "header")
                    | (ParameterLocation::Path, "path")
                    | (ParameterLocation::Cookie, "cookie")
            );
            if same_location && name.eq_ignore_ascii_case(&plan.name) {
                let schema = parameter
                    .get("schema")
                    .context("OpenAPI parameter requires schema")?
                    .clone();
                let required = parameter
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    || matches!(plan.location, ParameterLocation::Path);
                return Ok((schema, required));
            }
        }
    }
    bail!(
        "OpenAPI parameter `{}` disappeared while compiling",
        plan.name
    )
}

fn parameter_decode(parameter: &Map<String, Value>, schema: &Value) -> Result<ParameterDecode> {
    let schema_type = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string");
    if schema_type == "array" {
        let item = schema
            .get("items")
            .context("OpenAPI array parameter requires items")?;
        let item = scalar_kind(item)?;
        let explode = parameter
            .get("explode")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| parameter.get("in").and_then(Value::as_str) == Some("query"));
        Ok(ParameterDecode::Array {
            item,
            comma_separated: !explode
                || parameter.get("in").and_then(Value::as_str) == Some("header"),
        })
    } else {
        Ok(ParameterDecode::Scalar(scalar_kind(schema)?))
    }
}

fn scalar_kind(schema: &Value) -> Result<ScalarKind> {
    match schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string")
    {
        "string" => Ok(ScalarKind::String),
        "integer" => Ok(ScalarKind::Integer),
        "number" => Ok(ScalarKind::Number),
        "boolean" => Ok(ScalarKind::Boolean),
        other => bail!(
            "OpenAPI parameter type `{other}` is not supported; use primitive or primitive array"
        ),
    }
}

fn openapi_request_body(
    document: &Value,
    operation: &Value,
) -> Result<(Option<Value>, bool, Vec<String>)> {
    let Some(raw) = operation.get("requestBody") else {
        return Ok((None, false, Vec::new()));
    };
    let body = resolve_local_object(document, raw, "requestBody")?;
    let content = body
        .get("content")
        .and_then(Value::as_object)
        .context("OpenAPI requestBody requires object `content`")?;
    let mut media_types = content
        .keys()
        .filter(|media| media_type_is_json(media))
        .cloned()
        .collect::<Vec<_>>();
    media_types.sort();
    let selected = media_types
        .first()
        .context("OpenAPI requestBody has no application/json or +json content")?;
    let schema = content
        .get(selected)
        .and_then(|media| media.get("schema"))
        .context("OpenAPI JSON requestBody requires schema")?
        .clone();
    for media_type in &media_types {
        let candidate = content
            .get(media_type)
            .and_then(|media| media.get("schema"))
            .context("OpenAPI JSON requestBody requires schema for every JSON media type")?;
        if candidate != &schema {
            bail!(
                "OpenAPI requestBody JSON media types use different schemas; split them into separate gateway routes"
            );
        }
    }
    let wrapper = json!({
        "allOf": [schema],
        "components": document.get("components").cloned().unwrap_or_else(|| json!({}))
    });
    Ok((
        Some(wrapper),
        body.get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        media_types,
    ))
}

fn resolve_local_object<'a>(
    document: &'a Value,
    value: &'a Value,
    label: &str,
) -> Result<&'a Map<String, Value>> {
    resolve_local_value(document, value, label)?
        .as_object()
        .with_context(|| format!("OpenAPI {label} must be an object"))
}

fn resolve_local_value<'a>(
    document: &'a Value,
    value: &'a Value,
    label: &str,
) -> Result<&'a Value> {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return Ok(value);
    };
    let pointer = reference.strip_prefix('#').with_context(|| {
        format!("OpenAPI {label} external reference `{reference}` is forbidden")
    })?;
    document
        .pointer(pointer)
        .with_context(|| format!("OpenAPI {label} unresolved reference `{reference}`"))
}

fn build_head_instance(parts: &Parts, mode: &HeadMode) -> std::result::Result<Value, &'static str> {
    match mode {
        HeadMode::Raw => build_raw_head_instance(parts),
        HeadMode::OpenApi(plan) => build_openapi_head_instance(parts, plan),
    }
}

fn build_raw_head_instance(parts: &Parts) -> std::result::Result<Value, &'static str> {
    let query = raw_query_values(parts)?;
    let mut headers = Map::new();
    for name in parts.headers.keys() {
        let values = parts
            .headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().map(|value| Value::String(value.to_string())))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "request header is not valid UTF-8")?;
        headers.insert(name.as_str().to_ascii_lowercase(), Value::Array(values));
    }
    Ok(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": query,
        "headers": headers,
        "path_params": {}
    }))
}

fn build_openapi_head_instance(
    parts: &Parts,
    plan: &OpenApiHeadPlan,
) -> std::result::Result<Value, &'static str> {
    let query_values = parsed_query_pairs(parts)?;
    let path_values = extract_path_parameters(plan.path_template.as_str(), parts.uri.path())?;
    let cookie_values = parsed_cookie_pairs(parts)?;
    let mut query = Map::new();
    let mut headers = Map::new();
    let mut path_params = Map::new();
    let mut cookies = Map::new();
    for parameter in &plan.parameters {
        let values = match parameter.location {
            ParameterLocation::Query => query_values
                .get(parameter.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
            ParameterLocation::Header => {
                let values = parts
                    .headers
                    .get_all(parameter.name.as_str())
                    .iter()
                    .map(|value| value.to_str().map(str::to_owned))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| "request header is not valid UTF-8")?;
                // 这个临时 Vec 只活到本轮参数解码。HeaderMap 不提供稳定的借用 slice；不 clone
                // 整张 head，且只为 OpenAPI 明确声明的 header 分配。
                if let Some(value) = decode_parameter(values.as_slice(), &parameter.decode)? {
                    headers.insert(parameter.name.clone(), value);
                }
                continue;
            }
            ParameterLocation::Path => path_values
                .get(parameter.name.as_str())
                .map(std::slice::from_ref)
                .unwrap_or_default(),
            ParameterLocation::Cookie => cookie_values
                .get(parameter.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
        };
        if let Some(value) = decode_parameter(values, &parameter.decode)? {
            match parameter.location {
                ParameterLocation::Query => {
                    query.insert(parameter.name.clone(), value);
                }
                ParameterLocation::Path => {
                    path_params.insert(parameter.name.clone(), value);
                }
                ParameterLocation::Cookie => {
                    cookies.insert(parameter.name.clone(), value);
                }
                ParameterLocation::Header => unreachable!("handled above"),
            }
        }
    }
    Ok(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": query,
        "headers": headers,
        "path_params": path_params,
        "cookies": cookies
    }))
}

/// 业务作用：按 OpenAPI cookie `form` 序列化规则读取全部 Cookie header，保留同名值顺序并严格解码。
///
/// 参数说明：`parts` 是下游请求 head。
///
/// 返回：合法 cookie 组成 name→values；缺少等号、非法 percent 编码、UTF-8 或控制字符返回 400 类错误。
fn parsed_cookie_pairs(
    parts: &Parts,
) -> std::result::Result<HashMap<String, Vec<String>>, &'static str> {
    let mut values: HashMap<String, Vec<String>> = HashMap::new();
    for header in parts.headers.get_all(COOKIE) {
        let header = header
            .to_str()
            .map_err(|_| "request cookie header is not valid UTF-8")?;
        for item in header.split(';') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (name, value) = item
                .split_once('=')
                .ok_or("request cookie item requires name=value")?;
            if name.is_empty() || !valid_percent_encoding(name) || !valid_percent_encoding(value) {
                return Err("request cookie has invalid percent encoding");
            }
            let name = percent_encoding::percent_decode_str(name)
                .decode_utf8()
                .map_err(|_| "request cookie name is not valid UTF-8")?
                .into_owned();
            let value = percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map_err(|_| "request cookie value is not valid UTF-8")?
                .into_owned();
            if name.is_empty()
                || name.bytes().any(|byte| byte.is_ascii_control())
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err("request cookie contains a control character");
            }
            values.entry(name).or_default().push(value);
        }
    }
    Ok(values)
}

/// 业务作用：拒绝不完整 `%XX`，避免宽松解码让校验值与上游解释不同。
///
/// 参数说明：`value` 是尚未解码的 cookie name 或 value。
///
/// 返回：每个 `%` 后都恰有两个十六进制字符时返回 true。
fn valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn raw_query_values(parts: &Parts) -> std::result::Result<Map<String, Value>, &'static str> {
    let pairs = parsed_query_pairs(parts)?;
    Ok(pairs
        .into_iter()
        .map(|(key, values)| {
            (
                key,
                Value::Array(values.into_iter().map(Value::String).collect()),
            )
        })
        .collect())
}

fn parsed_query_pairs(
    parts: &Parts,
) -> std::result::Result<HashMap<String, Vec<String>>, &'static str> {
    let mut values: HashMap<String, Vec<String>> = HashMap::new();
    let Some(query) = parts.uri.query() else {
        return Ok(values);
    };
    // `form_urlencoded` 对无转义 key/value 使用 Cow 借用；这里只在 schema slow path 最终转成
    // JSON 所有权字符串，不影响默认代理路径。
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        values
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    Ok(values)
}

fn extract_path_parameters(
    template: &str,
    actual: &str,
) -> std::result::Result<HashMap<String, String>, &'static str> {
    let template_segments = template.trim_matches('/').split('/').collect::<Vec<_>>();
    let actual_segments = actual.trim_matches('/').split('/').collect::<Vec<_>>();
    if template_segments.len() != actual_segments.len() {
        return Err("request path does not match OpenAPI operation template");
    }
    let mut values = HashMap::new();
    for (expected, actual) in template_segments.into_iter().zip(actual_segments) {
        if let Some(name) = expected
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            // Path 已在入口规范化并拒绝 encoded slash；只对当前 segment 做 percent decode。
            let decoded = percent_encoding::percent_decode_str(actual)
                .decode_utf8()
                .map_err(|_| "request path parameter is not valid UTF-8")?
                .into_owned();
            values.insert(name.to_string(), decoded);
        } else if expected != actual {
            return Err("request path does not match OpenAPI operation template");
        }
    }
    Ok(values)
}

fn decode_parameter(
    values: &[String],
    decode: &ParameterDecode,
) -> std::result::Result<Option<Value>, &'static str> {
    if values.is_empty() {
        return Ok(None);
    }
    match decode {
        ParameterDecode::Scalar(kind) => {
            if values.len() != 1 {
                return Err("request contains duplicate scalar parameter");
            }
            decode_scalar(values[0].as_str(), *kind).map(Some)
        }
        ParameterDecode::Array {
            item,
            comma_separated,
        } => {
            let mut decoded = Vec::new();
            for value in values {
                if *comma_separated {
                    for item_value in value.split(',') {
                        decoded.push(decode_scalar(item_value, *item)?);
                    }
                } else {
                    decoded.push(decode_scalar(value, *item)?);
                }
            }
            Ok(Some(Value::Array(decoded)))
        }
    }
}

fn decode_scalar(value: &str, kind: ScalarKind) -> std::result::Result<Value, &'static str> {
    match kind {
        ScalarKind::String => Ok(Value::String(value.to_string())),
        ScalarKind::Integer => value
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| "request parameter is not an integer"),
        ScalarKind::Number => value
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or("request parameter is not a finite number"),
        ScalarKind::Boolean => match value {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err("request parameter is not a boolean"),
        },
    }
}

fn content_length(parts: &Parts) -> Option<u64> {
    parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn request_media_type_is_json(parts: &Parts, allowed: &[String]) -> bool {
    let Some(content_type) = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    allowed
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&media_type))
        || (allowed == ["application/json"] && media_type_is_json(media_type.as_str()))
}

fn media_type_is_json(media_type: &str) -> bool {
    let media_type = media_type.to_ascii_lowercase();
    media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

#[derive(Debug)]
pub(crate) enum CollectError {
    TooLarge,
    Read,
}

pub(crate) struct CollectedBody {
    /// 原请求实体。常见单 frame 情况直接复用 Hyper 交付的引用计数 allocation。
    pub(crate) bytes: Bytes,
    /// 原请求 trailers；校验慢路径不得静默丢弃协议元数据。
    trailers: Option<HeaderMap>,
}

impl CollectedBody {
    pub(crate) fn has_trailers(&self) -> bool {
        self.trailers.is_some()
    }
}

/// 已验证 body 的两帧以内重放体：首帧复用聚合 [`Bytes`]，次帧保留原请求 trailers。
struct BufferedRequestBody {
    bytes: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl hyper::body::Body for BufferedRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        if let Some(bytes) = self.bytes.take() {
            if !bytes.is_empty() {
                return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))));
            }
        }
        if let Some(trailers) = self.trailers.take() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::trailers(trailers))));
        }
        std::task::Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.as_ref().is_none_or(Bytes::is_empty) && self.trailers.is_none()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = hyper::body::SizeHint::new();
        hint.set_exact(self.bytes.as_ref().map_or(0, |bytes| bytes.len() as u64));
        hint
    }
}

pub(crate) fn buffered_body(collected: CollectedBody) -> BoxBody {
    BufferedRequestBody {
        bytes: Some(collected.bytes),
        trailers: collected.trailers,
    }
    .boxed()
}

/// 有界聚合 body，并对常见单 frame body 保持零拷贝。
pub(crate) async fn collect_bounded(
    body: ForwardBody,
    max_body_bytes: u64,
) -> std::result::Result<CollectedBody, CollectError> {
    let mut body = body;
    let mut first: Option<Bytes> = None;
    let mut merged: Option<BytesMut> = None;
    let mut trailers: Option<HeaderMap> = None;
    let mut length = 0_u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| CollectError::Read)?;
        let frame = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if let Ok(next) = frame.into_trailers() {
                    if let Some(existing) = &mut trailers {
                        existing.extend(next);
                    } else {
                        trailers = Some(next);
                    }
                }
                // Trailers 不属于 JSON entity，但必须在验证后原样重放，不能让 opt-in filter
                // 静默改变 HTTP 语义。
                continue;
            }
        };
        let data = frame;
        let frame_len = u64::try_from(data.len()).map_err(|_| CollectError::TooLarge)?;
        length = length
            .checked_add(frame_len)
            .ok_or(CollectError::TooLarge)?;
        if length > max_body_bytes {
            return Err(CollectError::TooLarge);
        }
        if data.is_empty() {
            continue;
        }
        match (&mut first, &mut merged) {
            (slot @ None, None) => *slot = Some(data),
            (first, slot @ None) => {
                let prior = first.take().expect("first body frame exists");
                let capacity = usize::try_from(length).map_err(|_| CollectError::TooLarge)?;
                let mut buffer = BytesMut::with_capacity(capacity);
                buffer.extend_from_slice(prior.as_ref());
                buffer.extend_from_slice(data.as_ref());
                *slot = Some(buffer);
            }
            (_, Some(buffer)) => buffer.extend_from_slice(data.as_ref()),
        }
    }
    let bytes = match merged {
        Some(buffer) => buffer.freeze(),
        None => first.unwrap_or_default(),
    };
    Ok(CollectedBody { bytes, trailers })
}
