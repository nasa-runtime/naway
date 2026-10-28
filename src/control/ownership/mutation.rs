//! 工作区声明变更只定位已授权对象，不允许委派入口编辑平台 bootstrap 或归属授权表。

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{
    config::{Action, Role},
    OwnershipCatalog,
};

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Patch {
        object: String,
        fields: Map<String, Value>,
    },
    Delete {
        object: String,
    },
    CreateRoute {
        proxy: String,
        route: Value,
    },
    Delegate {
        members: std::collections::BTreeMap<String, Role>,
    },
    Rollback {
        object: String,
        version: u64,
    },
}

impl OwnershipCatalog {
    /// 业务作用：在归档副本上应用单工作区变更，不能借路径、显示名或属性覆盖取得其它 owner 的权威。
    ///
    /// 参数说明：
    /// - `document`：为当前归档副本
    /// - `principal`：为认证主体
    /// - `workspace`：为端点范围
    /// - `mutation`：为有界声明动作。
    ///
    /// 返回：只修改获准对象的声明；权限、引用形态或可委派字段不合规时失败，调用方丢弃副本。
    pub fn mutate(
        &self,
        document: &mut Value,
        principal: &str,
        workspace: &str,
        mutation: Mutation,
    ) -> Result<()> {
        let action = if matches!(mutation, Mutation::Delegate {
            ..
        }) {
            Action::Delegate
        } else {
            Action::Write
        };
        ensure!(
            self.allows(principal, workspace, action),
            "workspace action denied"
        );
        match mutation {
            Mutation::Rollback {
                ..
            } => anyhow::bail!("rollback requires an authorized archive"),
            Mutation::Patch {
                object,
                fields,
            } => {
                let owner = self
                    .objects
                    .get(&object)
                    .context("owned object is absent")?;
                ensure!(
                    owner.owner.workspace == workspace,
                    "object is outside workspace"
                );
                validate_fields(&owner.kind, &fields)?;
                let target = find_object_mut(document, &object)
                    .context("object is not editable in this declaration")?;
                let mapping = target.as_object_mut().context("object is not a mapping")?;
                for (key, value) in fields {
                    if value.is_null() {
                        mapping.remove(&key);
                    } else {
                        mapping.insert(key, value);
                    }
                }
            }
            Mutation::Delete {
                object,
            } => {
                let owner = self
                    .objects
                    .get(&object)
                    .context("owned object is absent")?;
                ensure!(
                    owner.owner.workspace == workspace,
                    "object is outside workspace"
                );
                delete_object(document, &object)?;
                if let Some(assignments) = document
                    .get_mut("ownership")
                    .and_then(|v| v.get_mut("objects"))
                    .and_then(Value::as_object_mut)
                {
                    assignments.remove(&object);
                    // 组合对象没有独立生存期；只撤掉同 owner 且由此对象包含的显式子声明。
                    for (key, child) in &self.objects {
                        if owner.kind == "route"
                            && child.owner.workspace == workspace
                            && child.parent.as_deref() == Some(object.as_str())
                        {
                            assignments.remove(key);
                        }
                    }
                }
            }
            Mutation::CreateRoute {
                proxy,
                route,
            } => {
                let owner = self
                    .objects
                    .get(&format!("proxy:{proxy}"))
                    .context("proxy is absent")?;
                ensure!(
                    owner.owner.workspace == workspace,
                    "proxy is outside workspace"
                );
                let mapping = route.as_object().context("route must be an object")?;
                let id = mapping
                    .get("id")
                    .and_then(Value::as_str)
                    .context("route id is required")?;
                super::token(id)?;
                ensure!(
                    !self.objects.contains_key(&format!("route:{proxy}/{id}")),
                    "route already exists"
                );
                let mut fields = mapping.clone();
                fields.remove("id");
                validate_fields("route", &fields)?;
                let routes =
                    route_array_mut(document, &proxy).context("proxy routes are not explicit")?;
                routes.push(route);
            }
            Mutation::Delegate {
                members,
            } => {
                ensure!(
                    !members.is_empty()
                        && members.len() <= 256
                        && members.values().any(|role| *role == Role::Administrator),
                    "invalid delegated membership"
                );
                let target = document
                    .get_mut("ownership")
                    .and_then(|v| v.get_mut("workspaces"))
                    .and_then(|v| v.get_mut(workspace))
                    .context("workspace declaration unavailable")?;
                target["members"] = serde_json::to_value(members)?;
            }
        }
        Ok(())
    }

    /// 业务作用：只恢复仍属当前域的显式对象业务字段，不恢复旧成员、grant、凭据或其它租户配置。
    ///
    /// 参数说明：
    /// - `document`：是当前候选
    /// - `previous`：是同一历史归档及其权限图
    /// - `previous_catalog`：是同一历史归档及其权限图
    /// - `principal`：为当前认证范围
    /// - `workspace`：为当前认证范围
    /// - `object`：为稳定对象键。
    ///
    /// 返回：当前管理员可回滚同 owner 对象；已转移、删除、越权或历史归属不明时拒绝。
    pub fn rollback_object(
        &self,
        document: &mut Value,
        previous: &Value,
        previous_catalog: &Self,
        principal: &str,
        workspace: &str,
        object: &str,
    ) -> Result<()> {
        ensure!(
            self.allows(principal, workspace, Action::Rollback),
            "workspace rollback denied"
        );
        let current = self
            .objects
            .get(object)
            .context("rollback object is absent")?;
        let old = previous_catalog
            .objects
            .get(object)
            .context("archived object is absent")?;
        // 相同显示名不等于相同权威；owner 的租户、环境和工作区三元组必须完全一致。
        ensure!(
            current.owner.workspace == workspace && current.owner == old.owner,
            "rollback owner changed"
        );
        let mut archive = previous.clone();
        let old_fields = find_object_mut(&mut archive, object)
            .and_then(|v| v.as_object())
            .context("archived declaration unavailable")?;
        let current_fields = find_object_mut(document, object)
            .and_then(Value::as_object_mut)
            .context("current declaration unavailable")?;
        let mut fields: Map<String, Value> = current_fields
            .keys()
            .chain(old_fields.keys())
            .filter(|key| allowed_field(&current.kind, key))
            .map(|key| {
                (
                    key.clone(),
                    old_fields.get(key).cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
        // 缺失字段以显式 null 撤回当前覆盖；完整 builder 仍复验历史目标在今天的依赖图中合法。
        validate_fields(&current.kind, &fields)?;
        for (key, value) in std::mem::take(&mut fields) {
            if value.is_null() {
                current_fields.remove(&key);
            } else {
                current_fields.insert(key, value);
            }
        }
        Ok(())
    }

    /// 业务作用：输出当前工作区可编辑的业务声明，不导出认证材料、文件路径和进程级配置。
    ///
    /// 参数说明：
    /// - `document`：为冻结归档
    /// - `principal`：为已认证读取范围。
    /// - `workspace`：为已认证读取范围。
    ///
    /// 返回：明确可重放字段及稳定对象身份；未授权时失败。
    pub fn export(&self, document: &Value, principal: &str, workspace: &str) -> Result<Value> {
        self.export_page(document, principal, workspace, 0, 128)
    }

    /// 业务作用：限制脱敏导出的单页对象数，保留可重放的授权业务字段。
    ///
    /// 参数说明：
    /// - `document`：为归档
    /// - `principal`：为权限范围
    /// - `workspace`：为权限范围
    /// - `offset`：为同代分页预算。
    /// - `limit`：为同代分页预算。
    ///
    /// 返回：最多 128 个对象的声明和续页偏移；越权或非法预算失败。
    pub fn export_page(
        &self,
        document: &Value,
        principal: &str,
        workspace: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Value> {
        ensure!(
            self.allows(principal, workspace, Action::Read),
            "workspace read denied"
        );
        ensure!(
            (1..=128).contains(&limit) && offset <= 65_536,
            "invalid export page"
        );
        let mut source = document.clone();
        let mut values = Vec::new();
        let mut page = self
            .objects
            .values()
            .filter(|object| object.owner.workspace == workspace)
            .skip(offset);
        for object in page.by_ref().take(limit) {
            let Some(value) =
                find_object_mut(&mut source, &object.key).and_then(|value| value.as_object())
            else {
                continue;
            };
            let fields: Map<String, Value> = value
                .iter()
                .filter(|(key, _)| allowed_field(&object.kind, key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if !fields.is_empty() {
                values.push(serde_json::json!({
                    "action":"patch",
                    "object":object.key,
                    "fields":fields
                }));
            }
        }
        let next = page.next().map(|_| offset + limit);
        Ok(serde_json::json!({
            "workspace":workspace,
            "patches":values,
            "next_offset":next
        }))
    }
}

/// 业务作用：限制委派编辑到业务字段，文件/SecretSource、任意插件代码和平台绑定只由平台配置管理。
///
/// 参数说明：
/// - `kind`：为已登记对象种类
/// - `field`：是单层字段名。
///
/// 返回：已定义安全编辑合同的字段为 true，其它字段拒绝而非静默忽略。
fn allowed_field(kind: &str, field: &str) -> bool {
    match kind {
        "route" => matches!(
            field,
            "uri"
                | "predicates"
                | "order"
                | "usage_plan"
                | "request_timeout_ms"
                | "backend_request_timeout_ms"
                | "long_stream_idle_timeout_ms"
                | "long_stream_max_lifetime_ms"
        ),
        "service" => matches!(field, "instances" | "lb_policy" | "lb" | "lb_hash_key"),
        "plan" => matches!(
            field,
            "requests" | "window_ms" | "burst" | "max_active_keys"
        ),
        "group" => matches!(field, "consumers" | "plan"),
        "policy" => matches!(
            field,
            "require_authentication"
                | "deny"
                | "quota_plan"
                | "quota_per_consumer"
                | "products"
                | "request_headers"
                | "inherit_headers"
        ),
        _ => false,
    }
}

/// 业务作用：拒绝越过字段合同、注入 SecretSource 或将共享服务授权替换为任意直连目标的变更。
///
/// 参数说明：
/// - `kind`：为已授权对象种类
/// - `fields`：为本次字段集合。
///
/// 返回：声明形态安全时成功；完整类型和依赖关系仍由唯一快照 builder 复验。
fn validate_fields(kind: &str, fields: &Map<String, Value>) -> Result<()> {
    ensure!(
        !fields.is_empty()
            && fields.len() <= 16
            && fields.keys().all(|key| allowed_field(kind, key)),
        "field is not delegable"
    );
    if kind == "route" {
        if let Some(uri) = fields.get("uri") {
            ensure!(
                uri.as_str().is_some_and(|uri| uri.starts_with("lb://")),
                "delegated route requires a named service reference"
            );
        }
        if let Some(predicates) = fields.get("predicates").filter(|value| !value.is_null()) {
            let predicates = predicates
                .as_array()
                .context("predicates must be an array")?;
            ensure!(
                predicates.len() <= 32
                    && predicates
                        .iter()
                        .all(|value| value.as_str().is_some_and(|value| value.len() <= 1024)),
                "predicate capacity exceeded"
            );
        }
    }
    if kind == "service" {
        if let Some(instances) = fields.get("instances").filter(|value| !value.is_null()) {
            let instances = instances.as_array().context("instances must be an array")?;
            ensure!(instances.len() <= 256, "instance capacity exceeded");
            for instance in instances {
                let instance = instance.as_object().context("instance must be an object")?;
                ensure!(
                    instance.keys().all(|key| matches!(
                        key.as_str(),
                        "uri" | "healthy" | "weight" | "down" | "backup" | "slow_start_ms" | "zone"
                    )),
                    "instance field is not delegable"
                );
            }
        }
    }
    // 委派文档不会进行环境展开；显式禁止插值，防止下一次主配置加载将文本升级为 SecretSource。
    let encoded = serde_json::to_string(fields)?;
    ensure!(
        encoded.len() <= 64 * 1024 && !encoded.contains("${"),
        "delegated declaration exceeds budget or contains interpolation"
    );
    Ok(())
}

/// 业务作用：精确定位已存在的工作区业务对象，避免使用客户端 JSON Pointer 修改任意字段。
///
/// 参数说明：
/// - `document`：是归档副本
/// - `object`：是经过归属检查的稳定对象键。
///
/// 返回：支持委派的显式声明；不存在、派生对象或平台对象返回 None。
pub(super) fn find_object_mut<'a>(document: &'a mut Value, object: &str) -> Option<&'a mut Value> {
    let (kind, id) = object.split_once(':')?;
    match kind {
        "route" => {
            let (proxy, route) = id.split_once('/')?;
            route_array_mut(document, proxy)?
                .iter_mut()
                .find(|value| value.get("id").and_then(Value::as_str) == Some(route))
        }
        "service" => document
            .get_mut("upstreams")?
            .get_mut("services")?
            .get_mut(id),
        "plan" => document
            .get_mut("usage_plans")?
            .get_mut("plans")?
            .get_mut(id),
        "group" => document
            .get_mut("usage_plans")?
            .get_mut("groups")?
            .get_mut(id),
        "policy" => document
            .get_mut("usage_plans")?
            .get_mut("policies")?
            .as_array_mut()?
            .iter_mut()
            .find(|value| value.get("id").and_then(Value::as_str) == Some(id)),
        _ => None,
    }
}

/// 业务作用：定位固定入口下的路由数组，区分兼容单入口与显式多入口声明。
///
/// 参数说明：
/// - `document`：是候选副本
/// - `proxy`：是配置中的稳定入口身份。
///
/// 返回：唯一显式路由数组，不创建新的监听器或改变根路由集合。
pub(super) fn route_array_mut<'a>(
    document: &'a mut Value,
    proxy: &str,
) -> Option<&'a mut Vec<Value>> {
    if document
        .get("proxies")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        if proxy != "default" {
            return None;
        }
        document.get_mut("routes")?.as_array_mut()
    } else {
        document
            .get_mut("proxies")?
            .as_array_mut()?
            .iter_mut()
            .find(|value| value.get("id").and_then(Value::as_str) == Some(proxy))?
            .get_mut("routes")?
            .as_array_mut()
    }
}

/// 业务作用：删除单个可委派声明；入边、共享 grant 与组合依赖必须在完整 builder 中重新证明合法。
///
/// 参数说明：
/// - `document`：是副本
/// - `object`：是已通过 owner 检查的稳定对象。
///
/// 返回：精确删除成功；不支持的资源与不存在的目标失败。
fn delete_object(document: &mut Value, object: &str) -> Result<()> {
    let (kind, id) = object.split_once(':').context("invalid object identity")?;
    match kind {
        "route" => {
            let (proxy, id) = id.split_once('/').context("invalid route identity")?;
            let routes = route_array_mut(document, proxy).context("route declaration absent")?;
            let index = routes
                .iter()
                .position(|value| value.get("id").and_then(Value::as_str) == Some(id))
                .context("route absent")?;
            routes.remove(index);
        }
        "service" | "plan" | "group" => {
            let (section, collection) = match kind {
                "service" => ("upstreams", "services"),
                "plan" => ("usage_plans", "plans"),
                _ => ("usage_plans", "groups"),
            };
            let map = document
                .get_mut(section)
                .and_then(|value| value.get_mut(collection))
                .and_then(Value::as_object_mut)
                .context("object declaration absent")?;
            ensure!(map.remove(id).is_some(), "object absent");
        }
        "policy" => {
            let policies = document
                .get_mut("usage_plans")
                .and_then(|value| value.get_mut("policies"))
                .and_then(Value::as_array_mut)
                .context("policy declaration absent")?;
            let index = policies
                .iter()
                .position(|value| value.get("id").and_then(Value::as_str) == Some(id))
                .context("policy absent")?;
            policies.remove(index);
        }
        _ => anyhow::bail!("object is not deletable through delegation"),
    }
    Ok(())
}
