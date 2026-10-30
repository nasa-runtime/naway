//! 密钥动作只修改显式路由声明；撤销保留认证方式，秘密引用不在草稿阶段求值。

use super::{hex, objects::Object, Domain, Error};
use crate::routing::api_key::declaration::{self, Material, Source};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_FILTERS: usize = 4096;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Edit {
    Inspect {},
    Add {
        consumer: String,
        source: SourceKind,
        name: String,
        sha256: String,
    },
    SetEnabled {
        index: usize,
        fingerprint: String,
        enabled: bool,
    },
    Remove {
        index: usize,
        fingerprint: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SourceKind {
    Header,
    Query,
}

#[derive(Serialize)]
pub(super) struct Entry<'a> {
    index: usize,
    fingerprint: String,
    source: SourceKind,
    name: String,
    consumer: Option<&'a str>,
    enabled: bool,
    material: &'static str,
}

/// 业务作用：限制密钥动作仅作用于已授权 Gateway 的显式路由，不能借选择器修改其它领域。
///
/// 参数说明：
/// - `object`：精确入口与路由身份。
/// - `domain`：当前请求已授权的配置领域。
///
/// 返回：Gateway 路由成功；其它身份拒绝且不改变候选。
pub(super) fn validate_object(object: &Object, domain: Domain) -> Result<(), Error> {
    // 通用草稿入口不能让密钥动作取得其它领域或非路由对象的修改资格。
    if domain != Domain::Gateway || !matches!(object, Object::Route { .. }) {
        return Err(Error::Invalid);
    }
    object.validate(domain)
}

/// 业务作用：借用有界的原始处理链，缺失表示空链但不把非法类型隐式改成列表。
///
/// 参数说明：
/// - `route`：当前显式路由对象。
///
/// 返回：最多4096条声明；类型不符、非字符串或超量均拒绝整个动作。
fn filters(route: &Value) -> Result<&[Value], Error> {
    let mapping = route.as_object().ok_or(Error::Invalid)?;
    let filters = match mapping.get("filters") {
        None => &[][..],
        Some(value) => value.as_array().ok_or(Error::Invalid)?.as_slice(),
    };
    if filters.len() > MAX_FILTERS || filters.iter().any(|value| !value.is_string()) {
        return Err(Error::Invalid);
    }
    Ok(filters)
}

/// 业务作用：建立低敏密钥目录，共用运行时的严格声明解释且不读取环境、文件或秘密提供者。
///
/// 参数说明：
/// - `route`：当前候选的显式路由。
///
/// 返回：来源、主体、状态与准确选择证明；任何 API-Key 声明非法时不返回部分目录。
pub(super) fn inspect(route: &Value) -> Result<Vec<Entry<'_>>, Error> {
    let mut entries = Vec::new();
    for (index, value) in filters(route)?.iter().enumerate() {
        let raw = value.as_str().ok_or(Error::Invalid)?;
        if !declaration::accepts(raw) {
            continue;
        }
        let parsed = declaration::parse(raw).map_err(|_| Error::Invalid)?;
        let (source, name) = match parsed.source {
            Source::Header(name) => (SourceKind::Header, name.as_str().to_owned()),
            Source::Query(name) => (SourceKind::Query, name.to_owned()),
        };
        // 来源和主体必须是原文中的明确值；未求值模板不能被展示为已确认身份。
        if unresolved(&name) || parsed.consumer.is_some_and(unresolved) {
            return Err(Error::Invalid);
        }
        entries.push(Entry {
            index,
            fingerprint: hex(&Sha256::digest(raw.as_bytes())),
            source,
            name,
            consumer: parsed.consumer,
            enabled: parsed.enabled,
            material: match parsed.material {
                Material::Secret(_) => "secret_source",
                Material::Sha256(_) => "sha256",
            },
        });
    }
    Ok(entries)
}

/// 业务作用：识别需要配置求值的身份片段，防止草稿替操作者选择实际秘密或主体。
///
/// 参数说明：
/// - `value`：原始来源名或消费者身份。
///
/// 返回：含配置占位符时为真，调用者必须拒绝该结构化动作。
fn unresolved(value: &str) -> bool {
    value.contains("${") || value.contains("#{") || value.contains("{{")
}

/// 业务作用：约束新增字段为独立字面 token，防止空白、引号或求值符号注入其它认证参数。
///
/// 参数说明：
/// - `value`：新增来源名或消费者身份。
///
/// 返回：1至128字节且只含字母、数字、下划线、短横线、点或斜线时为真。
fn literal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-./".contains(&byte))
}

/// 业务作用：只对当前精确声明进行单个密钥动作，认证保护不能通过移除最后一条而隐式消失。
///
/// 参数说明：
/// - `route`：当前草稿中的唯一显式路由对象。
/// - `edit`：摘要新增、准确声明的状态调整或删除。
///
/// 返回：声明实际改变为真；同状态保留原文，选择过期、最后一条删除或非法输入拒绝。
pub(super) fn patch(route: &mut Value, edit: Edit) -> Result<bool, Error> {
    let entries = inspect(route)?;
    match edit {
        Edit::Inspect {} => Err(Error::Invalid),
        Edit::Add {
            consumer,
            source,
            name,
            sha256,
        } => {
            if !literal(&consumer)
                || !literal(&name)
                || sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || filters(route)?.len() == MAX_FILTERS
            {
                return Err(Error::Invalid);
            }
            let source = match source {
                SourceKind::Header => "header",
                SourceKind::Query => "query",
            };
            let raw =
                format!("api_key {source}={name} sha256={sha256} consumer={consumer} enabled=true");
            declaration::parse(&raw).map_err(|_| Error::Invalid)?;
            let mapping = route.as_object_mut().ok_or(Error::Invalid)?;
            mapping
                .entry("filters")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or(Error::Invalid)?
                .push(Value::String(raw));
            Ok(true)
        }
        Edit::SetEnabled {
            index,
            fingerprint,
            enabled,
        } => {
            let entry = selected(&entries, index, &fingerprint)?;
            if entry.enabled == enabled {
                return Ok(false);
            }
            let raw = filters(route)?[index].as_str().ok_or(Error::Invalid)?;
            let replacement = set_enabled(raw, enabled);
            declaration::parse(&replacement).map_err(|_| Error::Invalid)?;
            route["filters"][index] = replacement.into();
            Ok(true)
        }
        Edit::Remove {
            index,
            fingerprint,
        } => {
            selected(&entries, index, &fingerprint)?;
            // 认证方式的存在性依赖至少一条声明；撤销最后一把必须用禁用状态保留拒绝门。
            if entries.len() <= 1 {
                return Err(Error::Conflict);
            }
            route["filters"]
                .as_array_mut()
                .ok_or(Error::Invalid)?
                .remove(index);
            Ok(true)
        }
    }
}

/// 业务作用：复验数组位置和完整声明身份，防止旧列表选择作用于已移动或替换的凭据。
///
/// 参数说明：
/// - `entries`：对当前原文重新解析的低敏目录。
/// - `index`：读取目录时的处理链位置。
/// - `fingerprint`：读取目录时的完整声明 SHA-256。
///
/// 返回：两项同时匹配的当前条目；任何不一致拒绝修改。
fn selected<'a>(
    entries: &'a [Entry<'_>],
    index: usize,
    fingerprint: &str,
) -> Result<&'a Entry<'a>, Error> {
    entries
        .iter()
        .find(|entry| entry.index == index && entry.fingerprint == fingerprint)
        .ok_or(Error::Conflict)
}

/// 业务作用：仅替换已验证的 enabled token，保留秘密材料、参数顺序和其余字节。
///
/// 参数说明：
/// - `raw`：已经严格解析且没有重复参数的原声明。
/// - `enabled`：凭据是否可参与认证匹配。
///
/// 返回：状态改变后的声明；原文没有 enabled 时在末尾显式追加。
fn set_enabled(raw: &str, enabled: bool) -> String {
    let mut output = raw.to_owned();
    let replacement = format!("enabled={enabled}");
    let arguments = raw
        .trim_start()
        .strip_prefix("api_key")
        .expect("checked directive");
    let arguments = arguments
        .trim_start()
        .strip_prefix('=')
        .unwrap_or(arguments)
        .trim_start();
    if let Some(token) = arguments
        .split_whitespace()
        .find(|token| token.starts_with("enabled="))
    {
        let start = token.as_ptr() as usize - raw.as_ptr() as usize;
        output.replace_range(start..start + token.len(), &replacement);
    } else {
        output.push(' ');
        output.push_str(&replacement);
    }
    output
}
