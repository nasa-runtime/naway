use super::super::config::A2aBinding;
use anyhow::{ensure, Context, Result};
use http::request::Parts;
use serde_json::{json, Value};

pub(super) struct Call {
    pub id: Value,
    pub method: String,
    pub params: Value,
    pub task: Option<String>,
    pub context: Option<String>,
    pub streaming: bool,
}

/// 业务作用：把明确选择的 A2A binding 归一化为固定方法与有界任务引用，拒绝任意路径和未知能力。
///
/// 参数说明：
/// - `binding`：是路由 binding
/// - `base`：是对外入口路径
/// - `parts`：是入站请求。
/// - `body`：是入站请求。
///
/// 返回：经过语法与能力门的调用，不含客户端可选择的后端地址。
pub(super) fn decode(binding: A2aBinding, base: &str, parts: &Parts, body: &[u8]) -> Result<Call> {
    ensure!(
        !parts.headers.contains_key("a2a-extensions"),
        "A2A extensions are not enabled"
    );
    let (id, method, params) = match binding {
        A2aBinding::Jsonrpc => {
            ensure!(
                parts.method == http::Method::POST
                    && parts.uri.path().trim_end_matches('/') == base
                    && parts.uri.query().is_none(),
                "invalid A2A RPC endpoint"
            );
            let value: Value = serde_json::from_slice(body)?;
            keys(&value, &["jsonrpc", "id", "method", "params"])?;
            ensure!(
                value.get("jsonrpc").and_then(Value::as_str) == Some("2.0"),
                "invalid A2A JSON-RPC version"
            );
            let id = value.get("id").context("A2A request id required")?;
            ensure!(
                id.as_str()
                    .is_some_and(|id| !id.is_empty() && id.len() <= 128)
                    || id.as_i64().is_some()
                    || id.as_u64().is_some(),
                "invalid A2A request id"
            );
            (
                id.clone(),
                value
                    .get("method")
                    .and_then(Value::as_str)
                    .context("A2A method required")?
                    .to_owned(),
                value.get("params").cloned().unwrap_or_else(|| json!({})),
            )
        }
        A2aBinding::Rest => {
            let suffix = parts
                .uri
                .path()
                .strip_prefix(base)
                .context("invalid A2A REST base")?;
            if matches!(suffix, "/v1/message:send" | "/v1/message:stream") {
                ensure!(
                    parts.method == http::Method::POST && parts.uri.query().is_none(),
                    "invalid A2A message endpoint"
                );
                (
                    Value::Null,
                    if suffix.ends_with(":stream") {
                        "message/stream"
                    } else {
                        "message/send"
                    }
                    .into(),
                    super::rest::decode_request(serde_json::from_slice(body)?)?,
                )
            } else {
                let path = suffix
                    .strip_prefix("/v1/tasks/")
                    .context("A2A REST capability not enabled")?;
                let (task, method) = if let Some(task) = path.strip_suffix(":cancel") {
                    (task, "tasks/cancel")
                } else if let Some(task) = path.strip_suffix(":subscribe") {
                    (task, "tasks/resubscribe")
                } else {
                    (path, "tasks/get")
                };
                ensure!(valid_id(task), "invalid A2A task path");
                let mut params = json!({
                    "id":task
                });
                if method == "tasks/get" {
                    ensure!(
                        parts.method == http::Method::GET && body.is_empty(),
                        "invalid A2A task query"
                    );
                    if let Some(query) = parts.uri.query() {
                        let values: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
                        ensure!(
                            values.len() == 1 && values[0].0 == "historyLength",
                            "unsupported A2A task query"
                        );
                        params["historyLength"] = json!(values[0].1.parse::<u64>()?);
                    }
                } else {
                    ensure!(
                        parts.method == http::Method::POST && parts.uri.query().is_none(),
                        "invalid A2A task action"
                    );
                    if !body.is_empty() {
                        let value: Value = serde_json::from_slice(body)?;
                        keys(&value, &["name"])?;
                        ensure!(
                            value
                                .get("name")
                                .is_none_or(|name| name == &format!("tasks/{task}")),
                            "A2A task path and body differ"
                        );
                    }
                }
                (Value::Null, method.into(), params)
            }
        }
    };
    let (task, context) = match method.as_str() {
        "message/send" | "message/stream" => {
            keys(&params, &["message", "configuration"])?;
            let message = params.get("message").context("A2A message required")?;
            validate_message(message, "user")?;
            if let Some(configuration) = params.get("configuration") {
                keys(
                    configuration,
                    &["acceptedOutputModes", "historyLength", "blocking"],
                )?;
                history(configuration.get("historyLength"))?;
                ensure!(
                    configuration.get("blocking").is_none_or(Value::is_boolean),
                    "invalid A2A blocking mode"
                );
                if let Some(modes) = configuration.get("acceptedOutputModes") {
                    strings(modes, 16, 128)?;
                }
            }
            (
                optional_id(message, "taskId")?,
                optional_id(message, "contextId")?,
            )
        }
        "tasks/get" | "tasks/cancel" | "tasks/resubscribe" => {
            keys(
                &params,
                if method == "tasks/get" {
                    &["id", "historyLength"]
                } else {
                    &["id"]
                },
            )?;
            history(params.get("historyLength"))?;
            (
                Some(optional_id(&params, "id")?.context("A2A task id required")?),
                None,
            )
        }
        _ => anyhow::bail!("A2A method not enabled"),
    };
    let streaming = matches!(method.as_str(), "message/stream" | "tasks/resubscribe");
    if streaming {
        ensure!(
            !parts.headers.contains_key("last-event-id"),
            "A2A event-id replay is not enabled"
        );
    }
    Ok(Call {
        id,
        method,
        params,
        task,
        context,
        streaming,
    })
}

/// 业务作用：将统一调用编码为所选上游 binding，固定路径之外不读取客户端 URI。
///
/// 参数说明：
/// - `call`：是已批准动作
/// - `binding`：是固定 binding
/// - `base`：是固定后端入口。
///
/// 返回：方法、路径与有界 JSON 实体；不会产生重定向或动态 origin。
pub(super) fn outbound(
    call: &Call,
    binding: A2aBinding,
    base: &str,
) -> Result<(http::Method, String, Value)> {
    if matches!(binding, A2aBinding::Jsonrpc) {
        return Ok((
            http::Method::POST,
            base.into(),
            json!({
                "jsonrpc":"2.0",
                "id":call.id,
                "method":call.method,
                "params":call.params
            }),
        ));
    }
    let base = base.trim_end_matches('/');
    Ok(match call.method.as_str() {
        "message/send" => (
            http::Method::POST,
            format!("{base}/v1/message:send"),
            super::rest::encode_request(call.params.clone())?,
        ),
        "message/stream" => (
            http::Method::POST,
            format!("{base}/v1/message:stream"),
            super::rest::encode_request(call.params.clone())?,
        ),
        "tasks/get" => {
            let mut path = format!("{base}/v1/tasks/{}", call.task.as_deref().unwrap());
            if let Some(length) = call.params.get("historyLength") {
                path.push_str(&format!("?historyLength={length}"));
            }
            (http::Method::GET, path, Value::Null)
        }
        _ => {
            let task = call.task.as_deref().unwrap();
            (
                http::Method::POST,
                format!(
                    "{base}/v1/tasks/{task}:{}",
                    if call.method == "tasks/cancel" {
                        "cancel"
                    } else {
                        "subscribe"
                    }
                ),
                json!({
                    "name":format!("tasks/{task}")
                }),
            )
        }
    })
}

/// 业务作用：从绑定响应提取标准 A2A 值，并在任何状态发布前验证内容和标识。
///
/// 参数说明：
/// - `binding`：是当前请求绑定
/// - `id`：是当前请求绑定
/// - `value`：是未交付响应
/// - `streaming`：控制事件能力。
///
/// 返回：合法 task、message 或 stream event；未知能力和远端错误不透传原文。
pub(super) fn result(
    binding: A2aBinding,
    id: &Value,
    value: Value,
    streaming: bool,
) -> Result<Value> {
    let value = match binding {
        A2aBinding::Jsonrpc => {
            keys(&value, &["jsonrpc", "id", "result", "error"])?;
            ensure!(
                value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                    && value.get("id") == Some(id)
                    && value.get("error").is_none(),
                "A2A RPC result failed"
            );
            value.get("result").cloned().context("A2A result missing")?
        }
        A2aBinding::Rest => super::rest::decode_result(value, streaming)?,
    };
    match value.get("kind").and_then(Value::as_str) {
        Some("task") => {
            keys(
                &value,
                &["kind", "id", "contextId", "status", "artifacts", "history"],
            )?;
            required_id(&value, "id")?;
            required_id(&value, "contextId")?;
            status(&value["status"])?;
            if let Some(message) = value.pointer("/status/message") {
                same_context(message, &value)?;
            }
            if let Some(items) = value.get("artifacts") {
                for item in array(items, 128)? {
                    artifact(item)?;
                }
            }
            if let Some(items) = value.get("history") {
                for item in array(items, 128)? {
                    validate_message(item, "")?;
                    same_context(item, &value)?;
                }
            }
        }
        Some("message") => validate_message(&value, "agent")?,
        Some("status-update") if streaming => {
            keys(&value, &["kind", "taskId", "contextId", "status", "final"])?;
            required_id(&value, "taskId")?;
            required_id(&value, "contextId")?;
            status(&value["status"])?;
            // 嵌套状态消息必须受事件的同一任务权威约束，不能携带其它会话的引用。
            if let Some(message) = value.pointer("/status/message") {
                same_context(message, &value)?;
            }
            ensure!(
                value.get("final").is_some_and(Value::is_boolean),
                "A2A status event final flag required"
            );
        }
        Some("artifact-update") if streaming => {
            keys(
                &value,
                &[
                    "kind",
                    "taskId",
                    "contextId",
                    "artifact",
                    "append",
                    "lastChunk",
                ],
            )?;
            required_id(&value, "taskId")?;
            required_id(&value, "contextId")?;
            artifact(&value["artifact"])?;
            ensure!(
                value.get("append").is_none_or(Value::is_boolean)
                    && value.get("lastChunk").is_none_or(Value::is_boolean),
                "invalid A2A artifact flags"
            );
        }
        _ => anyhow::bail!("A2A response capability not enabled"),
    }
    Ok(value)
}

/// 业务作用：编码已授权、已发布的协议结果，不附带上游头或内部地址。
///
/// 参数说明：
/// - `binding`：是调用契约
/// - `call`：是调用契约
/// - `value`：是已校验结果。
///
/// 返回：对应 binding 的 JSON envelope。
pub(super) fn envelope(binding: A2aBinding, call: &Call, value: Value) -> Result<Value> {
    if matches!(binding, A2aBinding::Jsonrpc) {
        return Ok(json!({
            "jsonrpc":"2.0",
            "id":call.id,
            "result":value
        }));
    }
    if matches!(call.method.as_str(), "tasks/get" | "tasks/cancel") {
        return super::rest::encode_value(value);
    }
    let key = match value["kind"].as_str().unwrap_or("") {
        "task" => "task",
        "message" => "message",
        "status-update" => "statusUpdate",
        _ => "artifactUpdate",
    };
    let mut object = serde_json::Map::new();
    object.insert(key.into(), super::rest::encode_value(value)?);
    Ok(Value::Object(object))
}

/// 业务作用：约束消息形态和输入能力，文件仅接受内联 bytes，禁止请求任意远端文件 URI。
///
/// 参数说明：
/// - `value`：是消息
/// - `role`：非空时限制发送角色。
///
/// 返回：有界已知内容成功；扩展、未知字段或角色注入拒绝。
fn validate_message(value: &Value, role: &str) -> Result<()> {
    keys(
        value,
        &["kind", "messageId", "role", "parts", "taskId", "contextId"],
    )?;
    ensure!(
        value.get("kind").and_then(Value::as_str) == Some("message"),
        "A2A message kind required"
    );
    let actual = value.get("role").and_then(Value::as_str).unwrap_or("");
    ensure!(
        matches!(actual, "user" | "agent") && (role.is_empty() || role == actual),
        "A2A message role denied"
    );
    required_id(value, "messageId")?;
    optional_id(value, "taskId")?;
    optional_id(value, "contextId")?;
    parts(&value["parts"])
}

/// 业务作用：验证有界内容片段，不允许 URI 文件使上游代替调用者访问任意网络地址。
///
/// 参数说明：
/// - `value`：是消息或产物的 parts。
///
/// 返回：仅已知内联 text/data/file 类型通过。
fn parts(value: &Value) -> Result<()> {
    let values = array(value, 128)?;
    ensure!(!values.is_empty(), "A2A parts cannot be empty");
    for value in values {
        match value.get("kind").and_then(Value::as_str) {
            Some("text") => {
                keys(value, &["kind", "text"])?;
                ensure!(
                    value.get("text").is_some_and(Value::is_string),
                    "invalid A2A text"
                );
            }
            Some("data") => {
                keys(value, &["kind", "data"])?;
                ensure!(
                    value.get("data").is_some_and(Value::is_object),
                    "invalid A2A data"
                );
            }
            Some("file") => {
                use base64::Engine as _;
                keys(value, &["kind", "file"])?;
                let file = &value["file"];
                keys(file, &["name", "mimeType", "bytes"])?;
                ensure!(
                    file.get("bytes").is_some_and(Value::is_string)
                        && file.get("mimeType").is_none_or(Value::is_string)
                        && file.get("name").is_none_or(Value::is_string),
                    "invalid A2A inline file"
                );
                base64::engine::general_purpose::STANDARD
                    .decode(file["bytes"].as_str().unwrap())
                    .context("invalid A2A base64 file")?;
            }
            _ => anyhow::bail!("A2A part capability not enabled"),
        }
    }
    Ok(())
}

/// 业务作用：校验任务状态与可选状态消息，不接受未知状态绕过终态门。
///
/// 参数说明：
/// - `value`：是 TaskStatus。
///
/// 返回：已知状态及合法附属字段通过。
fn status(value: &Value) -> Result<()> {
    keys(value, &["state", "message", "timestamp"])?;
    ensure!(
        value
            .get("state")
            .and_then(Value::as_str)
            .is_some_and(|state| matches!(
                state,
                "submitted"
                    | "working"
                    | "input-required"
                    | "auth-required"
                    | "completed"
                    | "canceled"
                    | "failed"
                    | "rejected"
            )),
        "A2A state not enabled"
    );
    ensure!(
        value
            .get("timestamp")
            .is_none_or(|value| value.as_str().is_some_and(|value| value.len() <= 64)),
        "invalid A2A timestamp"
    );
    if let Some(message) = value.get("message") {
        validate_message(message, "agent")?;
    }
    Ok(())
}

/// 业务作用：校验产物身份和内容，不保存或重新获取产物正文。
///
/// 参数说明：
/// - `value`：是 Artifact。
///
/// 返回：有界标准产物成功。
fn artifact(value: &Value) -> Result<()> {
    keys(value, &["artifactId", "name", "description", "parts"])?;
    required_id(value, "artifactId")?;
    ensure!(
        ["name", "description"]
            .iter()
            .all(|key| value.get(key).is_none_or(Value::is_string)),
        "invalid A2A artifact text"
    );
    parts(&value["parts"])
}

/// 业务作用：防止任务历史或状态消息混入其它任务或上下文的引用。
///
/// 参数说明：
/// - `message`：是嵌套消息
/// - `task`：是当前任务或状态事件。
///
/// 返回：引用省略或一致时成功。
fn same_context(message: &Value, task: &Value) -> Result<()> {
    ensure!(
        message
            .get("taskId")
            .is_none_or(|id| Some(id) == task.get("id").or_else(|| task.get("taskId")))
            && message
                .get("contextId")
                .is_none_or(|id| Some(id) == task.get("contextId")),
        "A2A nested message context mismatch"
    );
    Ok(())
}

/// 业务作用：关闭未知协议字段，避免未授权扩展或推送 URL 进入上游。
///
/// 参数说明：
/// - `value`：是协议对象
/// - `allowed`：是本实现声明的字段集。
///
/// 返回：对象字段全部已知时成功。
pub(super) fn keys(value: &Value, allowed: &[&str]) -> Result<()> {
    ensure!(
        value
            .as_object()
            .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str()))),
        "unknown A2A protocol field"
    );
    Ok(())
}

/// 业务作用：限制集合大小，保证单个结构不会突破事件处理预算。
///
/// 参数说明：
/// - `value`：是数组
/// - `max`：是能力上限。
///
/// 返回：合法数组的只读视图。
fn array(value: &Value, max: usize) -> Result<&Vec<Value>> {
    let values = value.as_array().context("A2A array required")?;
    ensure!(values.len() <= max, "A2A array capacity exceeded");
    Ok(values)
}

/// 业务作用：限制公开描述中的字符串集合，不隐式转换其它 JSON 类型。
///
/// 参数说明：
/// - `value`：是集合
/// - `max`：是数量与单项长度上限。
/// - `length`：是数量与单项长度上限。
///
/// 返回：有界字符串数组成功。
pub(super) fn strings(value: &Value, max: usize, length: usize) -> Result<()> {
    ensure!(
        array(value, max)?
            .iter()
            .all(|value| value.as_str().is_some_and(|value| value.len() <= length)),
        "invalid A2A string array"
    );
    Ok(())
}

/// 业务作用：限制历史消息请求数量，避免上游无界查询。
///
/// 参数说明：
/// - `value`：是可选 historyLength。
///
/// 返回：省略或有限整数时成功。
fn history(value: Option<&Value>) -> Result<()> {
    ensure!(
        value.is_none_or(|value| value.as_u64().is_some_and(|value| value <= 128)),
        "A2A history exceeds limit"
    );
    Ok(())
}

/// 业务作用：约束可出现在路径与状态表中的协议标识。
///
/// 参数说明：
/// - `value`：是任务、上下文或消息标识。
///
/// 返回：有界安全 ASCII 名称为 true。
pub(super) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// 业务作用：读取可选标识时执行严格类型和路径字符校验。
///
/// 参数说明：
/// - `value`：是对象
/// - `key`：是固定协议字段。
///
/// 返回：省略或合法标识；空值、复杂值和非法字符拒绝。
fn optional_id(value: &Value, key: &str) -> Result<Option<String>> {
    value
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|id| valid_id(id))
                .map(str::to_owned)
                .context("invalid A2A identifier")
        })
        .transpose()
}

/// 业务作用：确认协议要求的任务、上下文、消息或产物标识存在。
///
/// 参数说明：
/// - `value`：是对象
/// - `key`：是必填标识字段。
///
/// 返回：合法标识存在时成功。
fn required_id(value: &Value, key: &str) -> Result<()> {
    optional_id(value, key)?.context("A2A identifier required")?;
    Ok(())
}
