//! 门户成员角色动作只选择固定映射，原始身份键不解释为路径或外部引用。

use super::{Domain, Error, objects::Object};
use crate::portal::management::Role;
use serde::Deserialize;
use serde_json::{Map, Value};

const MAX_MEMBERS: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Field {
    GroupRoles,
    SubjectRoles,
}

impl Field {
    /// 业务作用：将成员类别绑定到团队中固定的原生映射，不接受调用者提供的任意路径。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：组或 subject 的原生配置字段名，不进行拼接和路径解析。
    fn name(&self) -> &'static str {
        match self {
            Self::GroupRoles => "group_roles",
            Self::SubjectRoles => "subject_roles",
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Edit {
    Insert {
        key: String,
        role: Role,
    },
    Replace {
        key: String,
        role: Role,
    },
    Remove {
        key: String,
    },
}

/// 业务作用：将成员角色动作限制在 Gateway 门户团队，不能借固定映射修改产品或其它领域。
///
/// 参数说明：
/// - `object`：调用者明确选中的团队身份。
/// - `domain`：入口已授权的提案领域。
///
/// 返回：Gateway 的有界门户团队身份成功；其它对象或领域拒绝。
pub(super) fn validate_object(object: &Object, domain: Domain) -> Result<(), Error> {
    // 成员授权只属于团队，不能让相同 id 的其它对象获得角色映射修改资格。
    if domain != Domain::Gateway || !matches!(object, Object::PortalTeam { .. }) {
        return Err(Error::Invalid);
    }
    object.validate(domain)
}

/// 业务作用：仅修改一个原文成员角色，两类映射共用原生容量，未编辑子树留在服务端原始声明中。
///
/// 参数说明：
/// - `team`：由稳定身份选择的原始门户团队。
/// - `field`：固定的组或 subject 角色映射。
/// - `edit`：有明确已存在或未存在前提的单个成员动作。
///
/// 返回：真实角色声明改变时为 true，相同角色替换为 false；错型、重复、缺席、非法键或容量不足拒绝。
pub(super) fn patch(team: &mut Value, field: Field, edit: Edit) -> Result<bool, Error> {
    let key = match &edit {
        Edit::Insert {
            key,
            ..
        }
        | Edit::Replace {
            key,
            ..
        }
        | Edit::Remove {
            key,
        } => key,
    };
    // SSO 身份按原始 UTF-8 字节约束；斜线和点是普通字符，不能借长 subject 扩大固定字段边界。
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    let mapping = team.as_object_mut().ok_or(Error::Invalid)?;
    let mut total = 0;
    for name in ["group_roles", "subject_roles"] {
        total += match mapping.get(name) {
            None => 0,
            Some(value) => value.as_object().ok_or(Error::Invalid)?.len(),
        };
    }
    // 两类映射共同决定成员权限，错型或超量原文不能在局部动作中被静默覆盖为另一份授权。
    if total > MAX_MEMBERS {
        return Err(Error::Capacity);
    }
    let field = field.name();
    match edit {
        Edit::Insert {
            key,
            role,
        } => {
            if mapping
                .get(field)
                .is_some_and(|value| value.get(&key).is_some())
            {
                return Err(Error::Conflict);
            }
            if total == MAX_MEMBERS {
                return Err(Error::Capacity);
            }
            // 只有明确插入可以补缺失映射，新成员只取得本次提交的角色，不继承相邻成员权限。
            let values = mapping
                .entry(field)
                .or_insert_with(|| Value::Object(Map::new()));
            values
                .as_object_mut()
                .ok_or(Error::Invalid)?
                .insert(key, serde_json::to_value(role).map_err(|_| Error::Invalid)?);
            Ok(true)
        }
        Edit::Replace {
            key,
            role,
        } => {
            let values = mapping
                .get_mut(field)
                .ok_or(Error::Missing)?
                .as_object_mut()
                .ok_or(Error::Invalid)?;
            let current = values.get_mut(&key).ok_or(Error::Missing)?;
            let value = serde_json::to_value(role).map_err(|_| Error::Invalid)?;
            if *current == value {
                return Ok(false);
            }
            *current = value;
            Ok(true)
        }
        Edit::Remove {
            key,
        } => {
            let values = mapping
                .get_mut(field)
                .ok_or(Error::Missing)?
                .as_object_mut()
                .ok_or(Error::Invalid)?;
            // 删除最后项保留显式空映射，不把撤销解释为缺省授权，也不迁移应用或改动另一类成员。
            values.remove(&key).ok_or(Error::Missing)?;
            Ok(true)
        }
    }
}
