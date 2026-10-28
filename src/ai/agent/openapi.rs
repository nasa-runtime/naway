use super::config::{OpenApiCfg, ToolBackendCfg, ToolCfg};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

const DOCUMENT_LIMIT: usize = 2 * 1024 * 1024;

/// 业务作用：只把显式允许的 OpenAPI operation 转换为固定目标工具，不执行文档中的 server 或认证定义。
///
/// 参数说明：
/// - `cfg`：是文档、固定目标与操作授权
/// - `dir`：是配置目录。
///
/// 返回：有界、无外部引用的工具定义；歧义操作、复杂参数编码或未知文档版本拒绝候选。
pub(super) fn compile(cfg: &OpenApiCfg, dir: &Path) -> Result<Vec<ToolCfg>> {
    ensure!(
        !cfg.file.is_empty() && (1..=256).contains(&cfg.operations.len()),
        "invalid OpenAPI tool catalog"
    );
    let bytes = crate::io::bounded_io::read_file(
        &dir.join(&cfg.file),
        DOCUMENT_LIMIT,
        "Agent OpenAPI document",
    )?;
    let doc = crate::config::document::parse(&bytes, DOCUMENT_LIMIT)?;
    ensure!(
        doc.get("openapi")
            .and_then(Value::as_str)
            .is_some_and(|version| version.starts_with("3.0.") || version.starts_with("3.1.")),
        "unsupported tool OpenAPI version"
    );
    let paths = doc
        .get("paths")
        .and_then(Value::as_object)
        .context("OpenAPI paths required")?;
    let mut operations = BTreeMap::new();
    for (path, item) in paths {
        let item = resolve(item, &doc, &mut HashSet::new(), 0, &mut 0)?;
        for method in ["get", "post", "put", "patch", "delete"] {
            if let Some(operation) = item.get(method) {
                if let Some(id) = operation.get("operationId").and_then(Value::as_str) {
                    ensure!(
                        !operations.contains_key(id),
                        "ambiguous OpenAPI operationId"
                    );
                    operations.insert(
                        id.to_owned(),
                        (
                            path.clone(),
                            method.to_uppercase(),
                            item.get("parameters").cloned(),
                            operation.clone(),
                        ),
                    );
                }
            }
        }
    }
    let mut tools = Vec::new();
    for selected in &cfg.operations {
        let (path, method, shared, operation) = operations
            .get(&selected.operation_id)
            .context("selected OpenAPI operation not found")?;
        let mut properties = Map::new();
        let mut required = Vec::new();
        let mut parameters = BTreeMap::new();
        for list in [shared.as_ref(), operation.get("parameters")]
            .into_iter()
            .flatten()
        {
            let list = list
                .as_array()
                .context("OpenAPI parameters must be an array")?;
            ensure!(list.len() <= 64, "OpenAPI parameter capacity exceeded");
            let mut seen = HashSet::new();
            for parameter in list {
                let location = parameter
                    .get("in")
                    .and_then(Value::as_str)
                    .context("OpenAPI parameter location required")?;
                let name = parameter
                    .get("name")
                    .and_then(Value::as_str)
                    .context("OpenAPI parameter name required")?;
                ensure!(
                    matches!(location, "path" | "query") && super::tools::valid_name(name),
                    "unsupported OpenAPI tool parameter"
                );
                let key = (location.to_owned(), name.to_owned());
                ensure!(seen.insert(key.clone()), "duplicate OpenAPI parameter");
                ensure!(
                    parameter.get("allowReserved") != Some(&Value::Bool(true))
                        && parameter.get("style").is_none_or(|style| style
                            == if location == "path" {
                                "simple"
                            } else {
                                "form"
                            }),
                    "unsupported OpenAPI parameter encoding"
                );
                let schema = parameter
                    .get("schema")
                    .context("OpenAPI parameter schema required")?;
                ensure!(
                    schema
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(
                            kind,
                            "string" | "number" | "integer" | "boolean"
                        )),
                    "OpenAPI tool parameter must be scalar"
                );
                let mandatory = parameter.get("required") == Some(&Value::Bool(true));
                ensure!(
                    location != "path" || mandatory,
                    "OpenAPI path parameter must be required"
                );
                parameters.insert(key, (schema.clone(), mandatory));
            }
        }
        for location in ["path", "query"] {
            let mut fields = Map::new();
            let mut mandatory = Vec::new();
            for ((kind, name), (schema, needed)) in &parameters {
                if kind == location {
                    fields.insert(name.clone(), schema.clone());
                    if *needed {
                        mandatory.push(name.clone());
                    }
                }
            }
            if !fields.is_empty() {
                if !mandatory.is_empty() {
                    required.push(location);
                }
                properties.insert(
                    location.into(),
                    json!({
                        "type":"object",
                        "properties":fields,
                        "required":mandatory,
                        "additionalProperties":false
                    }),
                );
            }
        }
        // 路径占位符必须与同代 schema 一一对应，避免发布可发现但不能安全调用的工具。
        let mut remaining = path.as_str();
        let mut placeholders = HashSet::new();
        while let Some(start) = remaining.find('{') {
            let rest = &remaining[start + 1..];
            let end = rest.find('}').context("invalid OpenAPI path template")?;
            let name = &rest[..end];
            ensure!(
                parameters.contains_key(&("path".into(), name.into())),
                "OpenAPI path lacks parameter schema"
            );
            placeholders.insert(name.to_owned());
            remaining = &rest[end + 1..];
        }
        ensure!(
            parameters
                .keys()
                .all(|(kind, name)| kind != "path" || placeholders.contains(name)),
            "OpenAPI path parameter not used"
        );
        if let Some(body) = operation.get("requestBody") {
            ensure!(method != "GET", "GET tool cannot declare a request body");
            let content = body
                .get("content")
                .and_then(Value::as_object)
                .context("OpenAPI requestBody content required")?;
            ensure!(content.len() == 1, "OpenAPI tool body must use JSON only");
            let schema = content
                .get("application/json")
                .and_then(|value| value.get("schema"))
                .context("OpenAPI JSON body schema required")?;
            properties.insert("body".into(), schema.clone());
            if body.get("required") == Some(&Value::Bool(true)) {
                required.push("body");
            }
        }
        let mut target = cfg.target.clone();
        target.path = format!("{}{}", target.path.trim_end_matches('/'), path);
        let description = operation
            .get("description")
            .or_else(|| operation.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or(&selected.operation_id)
            .to_owned();
        tools.push(ToolCfg {
            name: selected.name.clone(),
            description,
            input_schema: json!({
                "type":"object",
                "properties":properties,
                "required":required,
                "additionalProperties":false
            }),
            output_schema: None,
            discovery: selected.discovery.clone(),
            invocation: selected.invocation.clone(),
            side_effect: selected.side_effect,
            deadline_ms: selected.deadline_ms,
            max_calls_per_session: selected.max_calls_per_session,
            max_request_bytes: selected.max_request_bytes,
            max_response_bytes: selected.max_response_bytes,
            backend: ToolBackendCfg::Rest {
                target,
                method: method.clone(),
            },
        });
    }
    Ok(tools)
}

/// 业务作用：展开文档内引用并限制展开工作量，使工具候选不依赖运行时网络或无限递归。
///
/// 参数说明：
/// - `value`：是当前节点
/// - `doc`：是同一文档
/// - `active`：检测引用环
/// - `depth`：限制展开。
/// - `nodes`：限制展开。
///
/// 返回：展开后的 JSON Schema/operation；循环、外部引用、超限或歧义引用拒绝。
fn resolve(
    value: &Value,
    doc: &Value,
    active: &mut HashSet<String>,
    depth: usize,
    nodes: &mut usize,
) -> Result<Value> {
    *nodes += 1;
    ensure!(
        depth <= 32 && *nodes <= 16_384,
        "OpenAPI expansion exceeds limit"
    );
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref") {
                let reference = reference
                    .as_str()
                    .filter(|value| value.starts_with("#/"))
                    .context("OpenAPI external references are forbidden")?;
                ensure!(
                    object.len() == 1 && active.insert(reference.to_owned()),
                    "ambiguous or cyclic OpenAPI reference"
                );
                let result = resolve(
                    doc.pointer(&reference[1..])
                        .context("OpenAPI reference not found")?,
                    doc,
                    active,
                    depth + 1,
                    nodes,
                )?;
                active.remove(reference);
                return Ok(result);
            }
            ensure!(
                !object.contains_key("$dynamicRef") && !object.contains_key("$id"),
                "unsupported OpenAPI schema identity"
            );
            let mut output = Map::new();
            for (key, value) in object {
                output.insert(key.clone(), resolve(value, doc, active, depth + 1, nodes)?);
            }
            if output.remove("nullable") == Some(Value::Bool(true)) {
                let kind = output
                    .get("type")
                    .and_then(Value::as_str)
                    .context("nullable OpenAPI schema requires a type")?
                    .to_owned();
                output.insert("type".into(), json!([kind, "null"]));
            }
            Ok(Value::Object(output))
        }
        Value::Array(values) => values
            .iter()
            .map(|value| resolve(value, doc, active, depth + 1, nodes))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        value => Ok(value.clone()),
    }
}
