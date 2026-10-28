use super::config::{SideEffect, ToolBackendCfg, ToolCfg};
use super::identity::Acl;
use super::transport::{Outbound, Target};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use http::Method;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

pub(super) struct Tool {
    pub name: String,
    pub discovery: Acl,
    pub invocation: Acl,
    pub deadline_ms: u64,
    pub max_calls: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub backend: Backend,
    pub side_effect: SideEffect,
    info: Value,
    input: jsonschema::Validator,
    pub output: Option<jsonschema::Validator>,
}

pub(super) enum Backend {
    Rest {
        target: Arc<Target>,
        method: Method,
    },
    Mcp {
        server: String,
        tool: String,
    },
}

impl Tool {
    /// 业务作用：冻结工具身份、schema、独立 ACL 和外呼副作用预算。
    ///
    /// 参数说明：
    /// - `cfg`：是工具定义
    /// - `dir`：是固定凭据文件的基准目录。
    ///
    /// 返回：可执行的不可变工具；未知方法、远程 schema、无界预算或不一致副作用声明拒绝候选。
    pub(super) fn build(cfg: &ToolCfg, dir: &Path) -> Result<Self> {
        ensure!(
            valid_name(&cfg.name) && cfg.description.len() <= 4096,
            "invalid MCP tool metadata"
        );
        ensure!(
            (1..=300_000).contains(&cfg.deadline_ms)
                && (1..=100_000).contains(&cfg.max_calls_per_session)
                && (1..=4 * 1024 * 1024).contains(&cfg.max_request_bytes)
                && (1..=16 * 1024 * 1024).contains(&cfg.max_response_bytes),
            "invalid MCP tool budget"
        );
        ensure!(
            cfg.input_schema.get("type").and_then(Value::as_str) == Some("object"),
            "MCP input schema must describe an object"
        );
        let input = schema(&cfg.input_schema)?;
        let output = cfg.output_schema.as_ref().map(schema).transpose()?;
        let backend = match &cfg.backend {
            ToolBackendCfg::Rest {
                target,
                method,
            } => {
                let method = Method::from_bytes(method.as_bytes())?;
                ensure!(
                    matches!(
                        method,
                        Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
                    ),
                    "unsupported REST tool method"
                );
                ensure!(
                    !matches!(cfg.side_effect, SideEffect::ReadOnly) || method == Method::GET,
                    "read_only REST tool must use GET"
                );
                Backend::Rest {
                    target: Target::build(target, dir)?,
                    method,
                }
            }
            ToolBackendCfg::Mcp {
                server,
                tool,
            } => {
                ensure!(
                    valid_name(server) && valid_name(tool),
                    "invalid MCP backend reference"
                );
                Backend::Mcp {
                    server: server.clone(),
                    tool: tool.clone(),
                }
            }
        };
        let info = json!({
            "name":cfg.name,
            "description":cfg.description,
            "inputSchema":cfg.input_schema,
            "annotations":{
                "readOnlyHint":matches!(cfg.side_effect, SideEffect::ReadOnly),
                "destructiveHint":matches!(cfg.side_effect, SideEffect::Destructive),
                "idempotentHint":!matches!(cfg.side_effect, SideEffect::Destructive),
                "openWorldHint":false
            }
        });
        let mut info = info;
        if let Some(output) = &cfg.output_schema {
            info["outputSchema"] = output.clone();
        }
        Ok(Self {
            name: cfg.name.clone(),
            discovery: Acl::build(&cfg.discovery)?,
            invocation: Acl::build(&cfg.invocation)?,
            deadline_ms: cfg.deadline_ms,
            max_calls: cfg.max_calls_per_session,
            max_request_bytes: cfg.max_request_bytes,
            max_response_bytes: cfg.max_response_bytes,
            backend,
            side_effect: cfg.side_effect,
            info,
            input,
            output,
        })
    }

    /// 业务作用：只暴露批准的工具描述，不公开后端 URL、凭据或内部 server 身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：工具能力和 schema 的不可变公开投影。
    pub(super) fn info(&self) -> &Value {
        &self.info
    }

    /// 业务作用：在任何预算消耗或外部副作用之前校验工具参数。
    ///
    /// 参数说明：
    /// - `arguments`：是本次 JSON-RPC 的 arguments 对象。
    ///
    /// 返回：满足固定 schema 和字节门时成功；错误只描述类型，不输出参数原文。
    pub(super) fn validate(&self, arguments: &Value) -> Result<()> {
        ensure!(
            arguments.is_object() && self.input.is_valid(arguments),
            "MCP arguments failed schema"
        );
        ensure!(
            serde_json::to_vec(arguments)?.len() <= self.max_request_bytes,
            "MCP arguments exceed byte limit"
        );
        Ok(())
    }
}

/// 业务作用：把 schema 验证过的 REST 参数映射到固定路径、query 和 body，不接受任意目标 URL。
///
/// 参数说明：
/// - `target`：是固定 origin/path
/// - `method`：是固定方法
/// - `arguments`：只允许 path/query/body 三个容器。
///
/// 返回：只向既定目标发送的请求；路径穿越、未知根字段或不适合 GET 的 body 拒绝。
pub(super) fn rest_request(
    target: &Arc<Target>,
    method: &Method,
    arguments: &Value,
) -> Result<Outbound> {
    let object = arguments
        .as_object()
        .context("REST tool arguments must be an object")?;
    ensure!(
        object
            .keys()
            .all(|key| matches!(key.as_str(), "path" | "query" | "body")),
        "unknown REST tool argument container"
    );
    let mut path = target.path.clone();
    let mut used = std::collections::HashSet::new();
    while let Some(begin) = path.find('{') {
        let end = path[begin..]
            .find('}')
            .map(|offset| begin + offset)
            .context("invalid REST path template")?;
        let name = path[begin + 1..end].to_owned();
        let value = arguments
            .get("path")
            .and_then(|value| value.get(&name))
            .context("missing REST path argument")?;
        let value = scalar(value)?;
        // 编码不能替代路径授权：部分服务会再次解码 %2F/%2E，故先拒绝所有可能跨 segment 的值。
        ensure!(
            !value.is_empty()
                && value != "."
                && value != ".."
                && !value.contains(['/', '\\', '%', '?', '#']),
            "unsafe REST path argument"
        );
        let encoded =
            percent_encoding::utf8_percent_encode(&value, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        path.replace_range(begin..=end, &encoded);
        used.insert(name);
    }
    ensure!(!path.contains('}'), "invalid REST path template");
    if let Some(values) = arguments.get("path") {
        let values = values.as_object().context("REST path must be an object")?;
        ensure!(
            values.keys().all(|key| used.contains(key)),
            "unused REST path argument"
        );
    }
    if let Some(values) = arguments.get("query") {
        let values = values.as_object().context("REST query must be an object")?;
        ensure!(values.len() <= 64, "REST query exceeds limit");
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (key, value) in values {
            ensure!(key.len() <= 128, "REST query key exceeds limit");
            query.append_pair(key, &scalar(value)?);
        }
        let query = query.finish();
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query);
        }
    }
    ensure!(path.len() <= 16 * 1024, "REST tool path exceeds limit");
    ensure!(
        *method != Method::GET || arguments.get("body").is_none(),
        "GET tool cannot send a body"
    );
    let body = arguments
        .get("body")
        .map(serde_json::to_vec)
        .transpose()?
        .map(Bytes::from)
        .unwrap_or_default();
    let mut request = target.request(method.clone(), body);
    request.path = path;
    Ok(request)
}

/// 业务作用：把已授权的 query/path 标量编码成文本，不隐式序列化对象或集合。
///
/// 参数说明：
/// - `value`：是单个参数值。
///
/// 返回：有界字符串、数字或布尔文本；其它类型拒绝，避免复杂 query 语义与目标重解释。
fn scalar(value: &Value) -> Result<String> {
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(_) | Value::Bool(_) => value.to_string(),
        _ => anyhow::bail!("REST parameter must be scalar"),
    };
    ensure!(
        value.len() <= 4096 && !value.chars().any(char::is_control),
        "REST parameter exceeds limit"
    );
    Ok(value)
}

/// 业务作用：限制 MCP 公开名称，保持协议索引、工具目录和指标标签的稳定身份。
///
/// 参数说明：
/// - `name`：是配置中的 tool 或 server 名称。
///
/// 返回：符合 ASCII 工具名称字符集且不超长时为 true。
pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// 业务作用：编译本地 JSON Schema，拒绝任何会读取网络或磁盘的引用。
///
/// 参数说明：
/// - `value`：是大小与引用受控的 schema 对象。
///
/// 返回：合法 schema 的只读验证器；非法 schema 错误不附带原文。
fn schema(value: &Value) -> Result<jsonschema::Validator> {
    ensure!(
        serde_json::to_vec(value)?.len() <= 128 * 1024,
        "MCP schema exceeds limit"
    );
    check_refs(value, 0)?;
    jsonschema::validator_for(value).map_err(|_| anyhow::anyhow!("invalid MCP JSON schema"))
}

/// 业务作用：在编译 schema 前拒绝外部引用和超深结构，避免候选构建产生隐式外呼。
///
/// 参数说明：
/// - `value`：是当前 schema 节点
/// - `depth`：是遍历深度。
///
/// 返回：只含本地引用且结构有界时成功；否则拒绝整个工具定义。
fn check_refs(value: &Value, depth: usize) -> Result<()> {
    ensure!(depth <= 32, "MCP schema exceeds depth limit");
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if matches!(key.as_str(), "$ref" | "$dynamicRef") {
                    ensure!(
                        value
                            .as_str()
                            .is_some_and(|reference| reference.starts_with('#')),
                        "MCP schema external references are forbidden"
                    );
                }
                check_refs(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                check_refs(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
