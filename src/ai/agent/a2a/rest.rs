//! A2A HTTP+JSON 使用 Protobuf JSON 字段与枚举；业务授权统一在规范化对象上执行。

use super::protocol::keys;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

/// 业务作用：把 REST 发送请求归一化到与 JSON-RPC 共用的消息授权合同。
///
/// 参数说明：
/// - `value`：是有界 Protobuf JSON 请求。
///
/// 返回：规范化参数；未知扩展、推送配置和不合法 oneof 拒绝。
pub(super) fn decode_request(mut value: Value) -> Result<Value> {
    keys(&value, &["message", "configuration", "metadata"])?;
    empty_optional(&mut value, "metadata", false)?;
    let request = value
        .as_object_mut()
        .context("A2A REST object required")?
        .remove("message")
        .context("A2A REST request required")?;
    value["message"] = convert(request, "message", false)?;
    if let Some(configuration) = value.get("configuration") {
        keys(
            configuration,
            &["acceptedOutputModes", "historyLength", "blocking"],
        )?;
    }
    Ok(value)
}

/// 业务作用：把经过授权的统一消息编码为上游 REST 请求，不照搬另一 binding 的字段。
///
/// 参数说明：
/// - `value`：是已经通过消息和配置校验的参数。
///
/// 返回：固定 Protobuf JSON 形态。
pub(super) fn encode_request(mut value: Value) -> Result<Value> {
    let message = value
        .as_object_mut()
        .context("A2A message object required")?
        .remove("message")
        .context("A2A message required")?;
    value["message"] = convert(message, "message", true)?;
    Ok(value)
}

/// 业务作用：提取 REST 的消息、任务或流事件 oneof，拒绝多分支与未知负载。
///
/// 参数说明：
/// - `value`：是上游 REST 结果
/// - `streaming`：表示是否允许事件分支。
///
/// 返回：供同一状态机校验的标准 A2A 对象。
pub(super) fn decode_result(value: Value, streaming: bool) -> Result<Value> {
    if value.get("id").is_some() && value.get("status").is_some() && !streaming {
        return convert(value, "task", false);
    }
    keys(
        &value,
        if streaming {
            &["task", "message", "statusUpdate", "artifactUpdate"]
        } else {
            &["task", "message"]
        },
    )?;
    let object = value.as_object().context("A2A REST response required")?;
    ensure!(object.len() == 1, "ambiguous A2A REST result");
    let (key, payload) = object.iter().next().unwrap();
    convert(
        payload.clone(),
        match key.as_str() {
            "task" => "task",
            "message" => "message",
            "statusUpdate" => "status-update",
            _ => "artifact-update",
        },
        false,
    )
}

/// 业务作用：把已确认的消息或任务编码为 REST Protobuf JSON，保留状态发布后的同一业务值。
///
/// 参数说明：
/// - `value`：是已验证的标准对象。
///
/// 返回：不含 JSON-RPC kind 标记的协议实体。
pub(super) fn encode_value(value: Value) -> Result<Value> {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .context("A2A kind required")?
        .to_owned();
    convert(value, &kind, true)
}

/// 业务作用：严格转换已声明的消息、任务、状态和产物字段，保持两种 binding 的授权语义一致。
///
/// 参数说明：
/// - `value`：是单个对象
/// - `kind`：是固定结构
/// - `wire`：为 true 时编码 Protobuf JSON。
///
/// 返回：转换对象；未知字段、角色、状态或文件 URI 立即失败。
fn convert(mut value: Value, kind: &str, wire: bool) -> Result<Value> {
    ensure!(value.is_object(), "A2A object required");
    if !wire {
        let fields: &[&str] = match kind {
            "message" => &[
                "messageId",
                "contextId",
                "taskId",
                "role",
                "content",
                "metadata",
                "extensions",
            ],
            "task" => &[
                "id",
                "contextId",
                "status",
                "artifacts",
                "history",
                "metadata",
            ],
            "status-update" => &["taskId", "contextId", "status", "final", "metadata"],
            "artifact-update" => &[
                "taskId",
                "contextId",
                "artifact",
                "append",
                "lastChunk",
                "metadata",
            ],
            "status" => &["state", "message", "timestamp"],
            "artifact" => &[
                "artifactId",
                "name",
                "description",
                "parts",
                "metadata",
                "extensions",
            ],
            _ => anyhow::bail!("unsupported A2A REST structure"),
        };
        keys(&value, fields)?;
        empty_optional(&mut value, "metadata", false)?;
        empty_optional(&mut value, "extensions", true)?;
    }
    if matches!(
        kind,
        "message" | "task" | "status-update" | "artifact-update"
    ) {
        if wire {
            value.as_object_mut().unwrap().remove("kind");
        } else {
            value["kind"] = json!(kind);
        }
    }
    match kind {
        "message" => {
            let role = value.get("role").context("A2A role required")?;
            let role = if wire {
                match role.as_str() {
                    Some("user") => "ROLE_USER",
                    Some("agent") => "ROLE_AGENT",
                    _ => anyhow::bail!("A2A role denied"),
                }
            } else {
                match role.as_str() {
                    Some("ROLE_USER") => "user",
                    Some("ROLE_AGENT") => "agent",
                    _ if role == &json!(1) => "user",
                    _ if role == &json!(2) => "agent",
                    _ => anyhow::bail!("A2A role denied"),
                }
            };
            value["role"] = json!(role);
            let source = if wire {
                "parts"
            } else {
                "content"
            };
            let target = if wire {
                "content"
            } else {
                "parts"
            };
            let parts = value
                .as_object_mut()
                .unwrap()
                .remove(source)
                .context("A2A message content required")?;
            value[target] = convert_parts(parts, wire)?;
            if !wire {
                for key in ["taskId", "contextId"] {
                    if value.get(key).and_then(Value::as_str) == Some("") {
                        value.as_object_mut().unwrap().remove(key);
                    }
                }
            }
        }
        "task" => {
            child(&mut value, "status", "status", wire)?;
            children(&mut value, "history", "message", wire)?;
            children(&mut value, "artifacts", "artifact", wire)?;
        }
        "status-update" => {
            child(&mut value, "status", "status", wire)?;
            if !wire && value.get("final").is_none() {
                value["final"] = json!(false);
            }
        }
        "artifact-update" => child(&mut value, "artifact", "artifact", wire)?,
        "status" => {
            let states = [
                ("submitted", "TASK_STATE_SUBMITTED", 1),
                ("working", "TASK_STATE_WORKING", 2),
                ("completed", "TASK_STATE_COMPLETED", 3),
                ("failed", "TASK_STATE_FAILED", 4),
                ("canceled", "TASK_STATE_CANCELLED", 5),
                ("input-required", "TASK_STATE_INPUT_REQUIRED", 6),
                ("rejected", "TASK_STATE_REJECTED", 7),
                ("auth-required", "TASK_STATE_AUTH_REQUIRED", 8),
            ];
            let raw = value.get("state").context("A2A state required")?;
            let state = states
                .iter()
                .find(|(plain, encoded, number)| {
                    if wire {
                        raw.as_str() == Some(*plain)
                    } else {
                        raw.as_str() == Some(*encoded) || raw.as_u64() == Some(*number)
                    }
                })
                .context("A2A state not enabled")?;
            value["state"] = json!(if wire {
                state.1
            } else {
                state.0
            });
            let source = "message";
            let target = "message";
            if let Some(message) = value.as_object_mut().unwrap().remove(source) {
                value[target] = convert(message, "message", wire)?;
            }
        }
        "artifact" => {
            let parts = value
                .as_object_mut()
                .unwrap()
                .remove("parts")
                .context("A2A artifact parts required")?;
            value["parts"] = convert_parts(parts, wire)?;
        }
        _ => anyhow::bail!("A2A structure not enabled"),
    }
    Ok(value)
}

/// 业务作用：转换内联内容 oneof，不允许把文件 URI 或附加字段藏入结构转换。
///
/// 参数说明：
/// - `value`：是有界片段数组
/// - `wire`：选择编码方向。
///
/// 返回：仅包含 text/data/内联 file 的片段数组。
fn convert_parts(value: Value, wire: bool) -> Result<Value> {
    let parts = value.as_array().context("A2A parts array required")?;
    ensure!(parts.len() <= 128, "A2A parts capacity exceeded");
    parts
        .iter()
        .map(|part| {
            if wire {
                Ok(match part.get("kind").and_then(Value::as_str) {
                    Some("text") => json!({
                        "text":part["text"]
                    }),
                    Some("data") => json!({
                        "data":{
                            "data":part["data"]
                        }
                    }),
                    Some("file") => {
                        let file = &part["file"];
                        let mut result = json!({
                            "fileWithBytes":file["bytes"]
                        });
                        if let Some(mime) = file.get("mimeType") {
                            result["mimeType"] = mime.clone();
                        }
                        json!({
                            "file":result
                        })
                    }
                    _ => anyhow::bail!("A2A part not enabled"),
                })
            } else {
                keys(part, &["text", "data", "file"])?;
                ensure!(
                    part.as_object().unwrap().len() == 1,
                    "ambiguous A2A content part"
                );
                if let Some(text) = part.get("text") {
                    Ok(json!({
                        "kind":"text",
                        "text":text
                    }))
                } else if let Some(data) = part.get("data") {
                    keys(data, &["data"])?;
                    Ok(json!({
                        "kind":"data",
                        "data":data["data"]
                    }))
                } else {
                    let file = &part["file"];
                    keys(file, &["fileWithBytes", "mimeType"])?;
                    let mut result = json!({
                        "bytes":file.get("fileWithBytes").context("A2A inline file required")?
                    });
                    if let Some(mime) = file.get("mimeType") {
                        result["mimeType"] = mime.clone();
                    }
                    Ok(json!({
                        "kind":"file",
                        "file":result
                    }))
                }
            }
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

/// 业务作用：转换可选嵌套对象，不对缺失字段补造业务状态。
///
/// 参数说明：
/// - `value`：是父对象
/// - `key`：是字段
/// - `kind`：决定固定转换。
/// - `wire`：决定固定转换。
///
/// 返回：存在时替换为转换结果。
fn child(value: &mut Value, key: &str, kind: &str, wire: bool) -> Result<()> {
    if let Some(item) = value.as_object_mut().unwrap().remove(key) {
        value[key] = convert(item, kind, wire)?;
    }
    Ok(())
}

/// 业务作用：转换有界历史或产物列表，避免嵌套集合绕过统一容量门。
///
/// 参数说明：
/// - `value`：是列表位置
/// - `key`：是列表位置
/// - `kind`：决定固定转换。
/// - `wire`：决定固定转换。
///
/// 返回：存在时替换列表；非数组或超限失败。
fn children(value: &mut Value, key: &str, kind: &str, wire: bool) -> Result<()> {
    if let Some(items) = value.as_object_mut().unwrap().remove(key) {
        let items = items.as_array().context("A2A list required")?;
        ensure!(items.len() <= 128, "A2A list capacity exceeded");
        value[key] = Value::Array(
            items
                .iter()
                .map(|item| convert(item.clone(), kind, wire))
                .collect::<Result<_>>()?,
        );
    }
    Ok(())
}

/// 业务作用：接受 Protobuf 默认空容器，同时拒绝尚未声明能力的实际 metadata 或 extension 内容。
///
/// 参数说明：
/// - `value`：是对象
/// - `key`：是可选字段
/// - `array`：指定空集合形态。
///
/// 返回：空字段被规范化省略；非空或类型错误失败。
fn empty_optional(value: &mut Value, key: &str, array: bool) -> Result<()> {
    if let Some(item) = value
        .as_object_mut()
        .context("A2A object required")?
        .remove(key)
    {
        ensure!(
            if array {
                item.as_array().is_some_and(Vec::is_empty)
            } else {
                item.as_object().is_some_and(serde_json::Map::is_empty)
            },
            "A2A extension capability not enabled"
        );
    }
    Ok(())
}
