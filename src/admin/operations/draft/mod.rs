//! 只编辑调用者提交的原始声明，结果继续交给共享提案和原目标的完整构建器。

mod objects;

use super::model::{hex, Domain, Error};
use crate::admin::{self, AdminState, BoxBody};
use bytes::Bytes;
use http::{Response, StatusCode};
use objects::Object;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_FIELDS: usize = 128;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    candidate: String,
    action: Action,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Inspect {
        #[serde(default)]
        object: Option<Object>,
    },
    Patch {
        object: Object,
        fields: Map<String, Value>,
        #[serde(default)]
        remove: Vec<String>,
    },
    Create {
        object: Object,
        fields: Map<String, Value>,
    },
    Delete {
        object: Object,
    },
}

/// 业务作用：使草稿解析与编码占用真实候选许可，取消 HTTP 等待不会释放仍在运行的工作单元。
///
/// 参数说明：
/// - `state`：提供与完整候选共用的两个任务名额。
/// - `domain`：经过当前主体授权的提案领域。
/// - `bytes`：有界 JSON 请求，转交阻塞工作单元持有。
/// - `max_bytes`：共享提案的单候选容量。
/// - `cluster_id`：当前操作库的共享集群身份，供调用方防止跨入口混用响应。
/// - `scope`：本次已授权的精确平台或工作区范围。
///
/// 返回：原文声明编辑结果；忙碌、非法或输出超限均不落库、不读文件、不发布配置。
pub(super) async fn handle(
    state: &AdminState,
    domain: Domain,
    bytes: Bytes,
    max_bytes: usize,
    cluster_id: &str,
    scope: &str,
) -> Result<Response<BoxBody>, Error> {
    let permit = state
        .candidate_builds
        .acquire()
        .map_err(|_| Error::Unavailable)?;
    let cluster_id = cluster_id.to_owned();
    let scope = scope.to_owned();
    permit
        .spawn(move |_| {
            let mut value = process(domain, &bytes, max_bytes)?;
            value["cluster_id"] = cluster_id.into();
            value["scope"] = scope.into();
            value["domain"] = domain.identity().0.into();
            let encoded = serde_json::to_vec(&value).map_err(|_| Error::Invalid)?;
            if encoded.len() > MAX_RESPONSE_BYTES {
                return Err(Error::Capacity);
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(admin::full_body(Bytes::from(encoded)))
                .expect("build draft response"))
        })
        .await
        .map_err(|_| Error::Unavailable)?
}

/// 业务作用：在无配置求值的原文树上定位并编辑一个显式对象，保留其它声明及未修改字段。
///
/// 参数说明：
/// - `domain`：限定可操作的对象种类。
/// - `bytes`：仅含调用者原文和有限动作的 JSON。
/// - `max_bytes`：NAML 输入、展开和最终候选输出上限。
///
/// 返回：有限目录、选中字段或完整候选及摘要；任何失败不返回部分编辑或底层错误链。
fn process(domain: Domain, bytes: &[u8], max_bytes: usize) -> Result<Value, Error> {
    let Request {
        candidate,
        action,
    } = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if candidate.is_empty() || candidate.len() > max_bytes {
        return Err(Error::Invalid);
    }
    let base_sha256 = hex(&Sha256::digest(candidate.as_bytes()));
    let mut document = crate::config::document::parse(candidate.as_bytes(), max_bytes)
        .map_err(|_| Error::Invalid)?;
    let catalog = objects::catalog(&document, domain)?;
    if let Action::Inspect {
        object,
    } = action
    {
        let fields = match object.as_ref() {
            Some(object) => {
                if !catalog.contains(object) {
                    return Err(Error::Missing);
                }
                objects::find_mut(&mut document, object)?.take()
            }
            None => Value::Null,
        };
        return Ok(serde_json::json!({
            "schema_version": 1,
            "validation": "declaration_only",
            "published": false,
            "base_sha256": base_sha256,
            "objects": catalog,
            "selected": object,
            "fields": fields
        }));
    }
    let changed = match action {
        Action::Inspect {
            ..
        } => unreachable!("inspection handled above"),
        Action::Patch {
            object,
            fields,
            remove,
        } => {
            if !catalog.contains(&object) {
                return Err(Error::Missing);
            }
            patch(objects::find_mut(&mut document, &object)?, fields, remove)?
        }
        Action::Create {
            object,
            fields,
        } => {
            object.validate(domain)?;
            if catalog.contains(&object) {
                return Err(Error::Conflict);
            }
            validate_fields(fields.keys().map(String::as_str))?;
            objects::create(&mut document, &object, fields)?;
            true
        }
        Action::Delete {
            object,
        } => {
            if !catalog.contains(&object) {
                return Err(Error::Missing);
            }
            objects::delete(&mut document, &object)?;
            true
        }
    };
    let candidate = if changed {
        // 身份目录先复验，重复或超量声明不能靠删除再创建绕过整个候选的对象预算。
        objects::catalog(&document, domain)?;
        crate::config::document::encode(&document, max_bytes).map_err(|_| Error::Invalid)?
    } else {
        candidate
    };
    let candidate_sha256 = hex(&Sha256::digest(candidate.as_bytes()));
    Ok(serde_json::json!({
        "schema_version": 1,
        "validation": "declaration_only",
        "published": false,
        "base_sha256": base_sha256,
        "candidate_sha256": candidate_sha256,
        "changed": changed,
        "candidate": candidate
    }))
}

/// 业务作用：限制单对象字段编辑规模与身份边界，不把点号或斜线解释成嵌套路径。
///
/// 参数说明：
/// - `fields`：本次直接字段名，来自设置或移除列表。
///
/// 返回：有界且互不重复的普通字段成功；稳定 id、空名或控制字符拒绝。
fn validate_fields<'a>(fields: impl Iterator<Item = &'a str>) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for field in fields {
        if field == "id"
            || field.is_empty()
            || field.len() > 128
            || field.chars().any(char::is_control)
            || !seen.insert(field)
            || seen.len() > MAX_FIELDS
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// 业务作用：应用明确字段设置和移除，只有真实声明变化才触发一次 YAML 编码。
///
/// 参数说明：
/// - `object`：唯一显式对象，不包含其它节点或文件的配置。
/// - `fields`：要移动到对象中的完整字段值，null 保持为实际 null。
/// - `remove`：明确撤销的字段，不能与设置字段重叠。
///
/// 返回：真实变化为 true；空动作、重叠字段或非对象目标拒绝。
fn patch(
    object: &mut Value,
    fields: Map<String, Value>,
    remove: Vec<String>,
) -> Result<bool, Error> {
    if fields.is_empty() && remove.is_empty() {
        return Err(Error::Invalid);
    }
    validate_fields(fields.keys().chain(remove.iter()).map(String::as_str))?;
    let mapping = object.as_object_mut().ok_or(Error::Invalid)?;
    let mut changed = false;
    for (key, value) in fields {
        if mapping.get(&key) != Some(&value) {
            mapping.insert(key, value);
            changed = true;
        }
    }
    for key in remove {
        changed |= mapping.remove(&key).is_some();
    }
    Ok(changed)
}
