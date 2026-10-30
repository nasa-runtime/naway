//! 草稿对象用类型化身份定位，客户端不能提供任意文档路径。

use super::{Domain, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MAX_OBJECTS: usize = 1024;

#[derive(Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Object {
    Route {
        proxy: String,
        id: String,
    },
    Proxy {
        id: String,
    },
    Service {
        name: String,
    },
    Credential {
        name: String,
    },
    SecretProvider {
        name: String,
    },
    Stream {
        id: String,
    },
    Flow {
        id: String,
    },
    Degrade {
        id: String,
    },
    InterfaceRule {
        id: String,
    },
}

impl Object {
    /// 业务作用：限制显式对象身份并绑定所属领域，避免跨领域编辑或解释路径字符。
    ///
    /// 参数说明：
    /// - `domain`：入口已授权的唯一提案领域。
    ///
    /// 返回：名称有界且领域一致时成功；分隔符按普通身份字符保留，不做路径解码。
    pub(super) fn validate(&self, domain: Domain) -> Result<(), Error> {
        let (expected, id, parent) = match self {
            Self::Route {
                proxy,
                id,
            } => (Domain::Gateway, id, Some(proxy)),
            Self::Proxy {
                id,
            }
            | Self::Stream {
                id,
            } => (Domain::Gateway, id, None),
            Self::Service {
                name,
            }
            | Self::Credential {
                name,
            }
            | Self::SecretProvider {
                name,
            } => (Domain::Gateway, name, None),
            Self::Flow {
                id,
            }
            | Self::Degrade {
                id,
            } => (Domain::Sentinel, id, None),
            Self::InterfaceRule {
                id,
            } => (Domain::InterfaceGuard, id, None),
        };
        if domain != expected || !valid_name(id) || parent.is_some_and(|value| !valid_name(value)) {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// 业务作用：取得集合内的稳定键，服务使用 mapping key，具名材料使用 name，其它对象使用 id。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用调用者声明中的业务身份，不拼接代理与路由名称。
    fn id(&self) -> &str {
        match self {
            Self::Route {
                id,
                ..
            }
            | Self::Proxy {
                id,
            }
            | Self::Stream {
                id,
            }
            | Self::Flow {
                id,
            }
            | Self::Degrade {
                id,
            }
            | Self::InterfaceRule {
                id,
            } => id,
            Self::Service {
                name,
            }
            | Self::Credential {
                name,
            }
            | Self::SecretProvider {
                name,
            } => name,
        }
    }

    /// 业务作用：区分数组对象的稳定身份字段与服务 mapping key，编辑不能隐式改名。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：数组对象使用 id 或 name；服务身份由父 mapping 持有。
    fn identity_field(&self) -> Option<&'static str> {
        match self {
            Self::Service {
                ..
            } => None,
            Self::Credential {
                ..
            }
            | Self::SecretProvider {
                ..
            } => Some("name"),
            _ => Some("id"),
        }
    }

    /// 业务作用：在原文修改前拒绝对稳定身份的字段动作，不能通过嵌套或列表操作绕过选择器。
    ///
    /// 参数说明：
    /// - `fields`：普通字段或精确路径的第一段，仅借用调用者声明。
    ///
    /// 返回：全部字段均不改变对象身份时成功；身份只能在显式新建对象时由选择器提供。
    pub(super) fn protect_identity<'a>(
        &self,
        fields: impl Iterator<Item = &'a str>,
    ) -> Result<(), Error> {
        for field in fields {
            if Some(field) == self.identity_field() {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}

/// 业务作用：拒绝空身份、超长标识与控制字符，目录输出只能包含有限可展示文本。
///
/// 参数说明：
/// - `name`：原始声明标识。
///
/// 返回：非空且最多 256 字节的无控制字符标识为真。
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
}

/// 业务作用：枚举唯一显式对象并先拒绝重复，任何编辑都不能只命中歧义声明的第一项。
///
/// 参数说明：
/// - `document`：没有求值或导入展开的原文树。
/// - `domain`：限定唯一文档类别。
///
/// 返回：按类型化身份排序的有限目录；畸形集合、混合入口或重复身份失败闭合。
pub(super) fn catalog(document: &Value, domain: Domain) -> Result<BTreeSet<Object>, Error> {
    if !document.is_object() {
        return Err(Error::Invalid);
    }
    let mut catalog = BTreeSet::new();
    let mut insert = |object: Object| -> Result<(), Error> {
        object.validate(domain)?;
        if !catalog.insert(object) || catalog.len() > MAX_OBJECTS {
            return Err(Error::Invalid);
        }
        Ok(())
    };
    match domain {
        Domain::Gateway => {
            let proxies = array(document.get("proxies"))?;
            let root_routes = array(document.get("routes"))?;
            if !proxies.is_empty() && !root_routes.is_empty() {
                return Err(Error::Invalid);
            }
            if proxies.is_empty() {
                for route in root_routes {
                    insert(Object::Route {
                        proxy: "default".into(),
                        id: object_id(route)?.into(),
                    })?;
                }
            }
            for proxy in proxies {
                let id = object_id(proxy)?;
                insert(Object::Proxy {
                    id: id.into(),
                })?;
                for route in array(proxy.get("routes"))? {
                    insert(Object::Route {
                        proxy: id.into(),
                        id: object_id(route)?.into(),
                    })?;
                }
            }
            if let Some(upstreams) = document.get("upstreams") {
                if !upstreams.is_object() {
                    return Err(Error::Invalid);
                }
                if let Some(services) = upstreams.get("services") {
                    for (name, value) in services.as_object().ok_or(Error::Invalid)? {
                        if !value.is_object() {
                            return Err(Error::Invalid);
                        }
                        insert(Object::Service {
                            name: name.clone(),
                        })?;
                    }
                }
            }
            if let Some(stream) = document.get("stream") {
                if !stream.is_object() {
                    return Err(Error::Invalid);
                }
                for listener in array(stream.get("listeners"))? {
                    insert(Object::Stream {
                        id: object_id(listener)?.into(),
                    })?;
                }
            }
            for value in array(document.get("upstream_credentials"))? {
                insert(Object::Credential {
                    name: object_name(value)?.into(),
                })?;
            }
            for value in array(document.get("secret_providers"))? {
                insert(Object::SecretProvider {
                    name: object_name(value)?.into(),
                })?;
            }
        }
        Domain::Sentinel => {
            for rule in array(document.get("flow"))? {
                insert(Object::Flow {
                    id: object_id(rule)?.into(),
                })?;
            }
            for rule in array(document.get("degrade"))? {
                insert(Object::Degrade {
                    id: object_id(rule)?.into(),
                })?;
            }
        }
        Domain::InterfaceGuard => {
            for rule in array(document.get("rules"))? {
                insert(Object::InterfaceRule {
                    id: object_id(rule)?.into(),
                })?;
            }
        }
    }
    Ok(catalog)
}

/// 业务作用：把未声明集合视为空目录，显式错误类型不能被隐藏成空集合。
///
/// 参数说明：
/// - `value`：可选原文集合。
///
/// 返回：借用原数组或空切片；null、标量与 mapping 均拒绝。
fn array(value: Option<&Value>) -> Result<&[Value], Error> {
    match value {
        None => Ok(&[]),
        Some(value) => value.as_array().map(Vec::as_slice).ok_or(Error::Invalid),
    }
}

/// 业务作用：读取显式对象身份，不从数组位置或其它展示字段生成管理键。
///
/// 参数说明：
/// - `value`：单个原文对象。
///
/// 返回：合法 id 的借用；对象或身份不完整时拒绝整个目录。
fn object_id(value: &Value) -> Result<&str, Error> {
    value
        .as_object()
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .filter(|id| valid_name(id))
        .ok_or(Error::Invalid)
}

/// 业务作用：只接受显式具名凭据或秘密源，禁止从位置、端点或秘密内容推导管理身份。
///
/// 参数说明：
/// - `value`：具名集合中的一个原始对象。
///
/// 返回：合法 name 的借用；字段缺失、类型错误或名称超限拒绝目录。
fn object_name(value: &Value) -> Result<&str, Error> {
    value
        .as_object()
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .filter(|name| valid_name(name))
        .ok_or(Error::Invalid)
}

/// 业务作用：取得已验证唯一身份的原对象，服务键和代理路由身份分别定位。
///
/// 参数说明：
/// - `document`：已经完成完整目录校验的原文树。
/// - `object`：已确认存在的类型化身份。
///
/// 返回：原对象的可变借用；身份缺失或类型不一致时拒绝。
pub(super) fn find_mut<'a>(
    document: &'a mut Value,
    object: &Object,
) -> Result<&'a mut Value, Error> {
    if let Object::Service {
        name,
    } = object
    {
        return services_mut(document, false)?
            .get_mut(name)
            .ok_or(Error::Missing);
    }
    collection_mut(document, object, false)?
        .iter_mut()
        .find(|value| {
            value
                .get(object.identity_field().expect("array identity"))
                .and_then(Value::as_str)
                == Some(object.id())
        })
        .ok_or(Error::Missing)
}

/// 业务作用：只在合法 mapping 父对象中建立指定集合，不覆盖已有非对象声明。
///
/// 参数说明：
/// - `parent`：已经定位的父对象。
/// - `key`：实现内部固定的集合字段。
/// - `default`：字段缺失且允许创建时使用的空集合。
///
/// 返回：原字段借用；不允许创建且字段缺失时返回不存在。
fn child<'a>(
    parent: &'a mut Value,
    key: &str,
    default: Option<Value>,
) -> Result<&'a mut Value, Error> {
    let parent = parent.as_object_mut().ok_or(Error::Invalid)?;
    if let Some(default) = default {
        Ok(parent.entry(key).or_insert(default))
    } else {
        parent.get_mut(key).ok_or(Error::Missing)
    }
}

/// 业务作用：定位具名服务的 mapping，只在显式创建动作中补齐缺失集合。
///
/// 参数说明：
/// - `document`：原文树。
/// - `create`：允许补齐 upstreams/services 空 mapping 的显式创建标记。
///
/// 返回：服务 mapping 的原地借用；已有非 mapping 值拒绝。
fn services_mut(document: &mut Value, create: bool) -> Result<&mut Map<String, Value>, Error> {
    let upstreams = child(
        document,
        "upstreams",
        create.then(|| Value::Object(Map::new())),
    )?;
    child(
        upstreams,
        "services",
        create.then(|| Value::Object(Map::new())),
    )?
    .as_object_mut()
    .ok_or(Error::Invalid)
}

/// 业务作用：按固定对象类型选择集合，路由追加必须归属于已存在的显式父入口。
///
/// 参数说明：
/// - `document`：已完成目录唯一性校验的原文树。
/// - `object`：实现可识别的独立类型化身份。
/// - `create`：仅允许补齐当前父对象的缺失集合，不创建新的路由父入口。
///
/// 返回：原数组借用；跨集合、未知父对象与非数组字段拒绝。
fn collection_mut<'a>(
    document: &'a mut Value,
    object: &Object,
    create: bool,
) -> Result<&'a mut Vec<Value>, Error> {
    let (parent, key) = match object {
        Object::Route {
            proxy,
            ..
        } => {
            if array(document.get("proxies"))?.is_empty() {
                if proxy != "default" {
                    return Err(Error::Missing);
                }
                (document, "routes")
            } else {
                let parent = document
                    .get_mut("proxies")
                    .and_then(Value::as_array_mut)
                    .and_then(|values| {
                        values
                            .iter_mut()
                            .find(|value| value.get("id").and_then(Value::as_str) == Some(proxy))
                    })
                    .ok_or(Error::Missing)?;
                (parent, "routes")
            }
        }
        Object::Proxy {
            ..
        } => (document, "proxies"),
        Object::Credential {
            ..
        } => (document, "upstream_credentials"),
        Object::SecretProvider {
            ..
        } => (document, "secret_providers"),
        Object::Stream {
            ..
        } => (
            child(
                document,
                "stream",
                create.then(|| Value::Object(Map::new())),
            )?,
            "listeners",
        ),
        Object::Flow {
            ..
        } => (document, "flow"),
        Object::Degrade {
            ..
        } => (document, "degrade"),
        Object::InterfaceRule {
            ..
        } => (document, "rules"),
        Object::Service {
            ..
        } => return Err(Error::Invalid),
    };
    child(parent, key, create.then(|| Value::Array(Vec::new())))?
        .as_array_mut()
        .ok_or(Error::Invalid)
}

/// 业务作用：将显式新对象移入其唯一父集合，稳定身份由选择器写入而非自由字段覆盖。
///
/// 参数说明：
/// - `document`：已证明目标不存在的原文树。
/// - `object`：合法且属于当前领域的新身份。
/// - `fields`：不含稳定身份字段的业务声明，所有值直接移入。
///
/// 返回：新增成功；已有目标、父对象缺失或集合形态错误拒绝。
pub(super) fn create(
    document: &mut Value,
    object: &Object,
    mut fields: Map<String, Value>,
) -> Result<(), Error> {
    object.protect_identity(fields.keys().map(String::as_str))?;
    if let Object::Service {
        name,
    } = object
    {
        let services = services_mut(document, true)?;
        if services.contains_key(name) {
            return Err(Error::Conflict);
        }
        services.insert(name.clone(), Value::Object(fields));
    } else {
        fields.insert(
            object.identity_field().expect("array identity").into(),
            Value::String(object.id().into()),
        );
        collection_mut(document, object, true)?.push(Value::Object(fields));
    }
    Ok(())
}

/// 业务作用：仅移除显式选中的一个声明，其余字段与对象保持原值供完整构建器检查引用关系。
///
/// 参数说明：
/// - `document`：已证明目标唯一存在的原文树。
/// - `object`：用户明确选择的删除对象。
///
/// 返回：精确删除成功；引用是否允许删除由后续目标预检裁决，本函数不发布路由。
pub(super) fn delete(document: &mut Value, object: &Object) -> Result<(), Error> {
    if let Object::Service {
        name,
    } = object
    {
        services_mut(document, false)?
            .remove(name)
            .ok_or(Error::Missing)?;
    } else {
        let collection = collection_mut(document, object, false)?;
        let index = collection
            .iter()
            .position(|value| {
                value
                    .get(object.identity_field().expect("array identity"))
                    .and_then(Value::as_str)
                    == Some(object.id())
            })
            .ok_or(Error::Missing)?;
        collection.remove(index);
    }
    Ok(())
}
