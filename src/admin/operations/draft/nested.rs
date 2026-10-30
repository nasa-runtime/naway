use super::{Error, MAX_FIELDS};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Edit {
    Set {
        path: Vec<String>,
        value: Value,
    },
    Remove {
        path: Vec<String>,
    },
}

impl Edit {
    /// 业务作用：借用完整字段路径供同批冲突校验，不复制声明键或目标子树。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：设置或移除动作共同的精确映射键序列。
    pub(super) fn path(&self) -> &[String] {
        match self {
            Self::Set {
                path,
                ..
            }
            | Self::Remove {
                path,
            } => path,
        }
    }
}

/// 业务作用：在单个草稿对象中批量编辑有限子字段，未知声明仍留在服务端原文树中。
///
/// 参数说明：
/// - `object`：已按领域与稳定身份选中的原始对象。
/// - `edits`：不超过字段容量的显式设置或移除动作。
///
/// 返回：有真实声明变化时为 true；非法、重复或互为祖先的路径拒绝，调用方丢弃局部文档。
pub(super) fn patch(object: &mut Value, edits: Vec<Edit>) -> Result<bool, Error> {
    if edits.is_empty() || edits.len() > MAX_FIELDS {
        return Err(Error::Invalid);
    }
    let mut paths = Vec::with_capacity(edits.len());
    for edit in &edits {
        let path = edit.path();
        if path.is_empty()
            || path.len() > 8
            || path[0] == "id"
            || path
                .iter()
                .any(|key| key.is_empty() || key.len() > 128 || key.chars().any(char::is_control))
        {
            return Err(Error::Invalid);
        }
        paths.push(path);
    }
    paths.sort_unstable();
    // 祖先替换与子项编辑同时出现时没有唯一意图，先拒绝整批而不是依赖动作顺序。
    if paths.windows(2).any(|pair| pair[1].starts_with(pair[0])) {
        return Err(Error::Invalid);
    }
    let mut changed = false;
    for edit in edits {
        changed |= match edit {
            Edit::Set {
                path,
                value,
            } => apply(object, &path, Some(value))?,
            Edit::Remove {
                path,
            } => apply(object, &path, None)?,
        };
    }
    Ok(changed)
}

/// 业务作用：沿已验证的有限映射路径移动一个新值，绝不把现有标量或数组隐式转换成对象。
///
/// 参数说明：
/// - `object`：当前路径对应的原始子树。
/// - `path`：至少一段且总深度不超过八段的剩余路径。
/// - `value`：设置的新值；None 表示移除，JSON null 仍为实际值。
///
/// 返回：仅真实设置或删除返回 true；缺失删除不创建父对象，非法祖先使整个候选编辑失败。
fn apply(object: &mut Value, path: &[String], value: Option<Value>) -> Result<bool, Error> {
    let mapping = object.as_object_mut().ok_or(Error::Invalid)?;
    let key = &path[0];
    if path.len() == 1 {
        return Ok(match value {
            Some(value) if mapping.get(key) != Some(&value) => {
                mapping.insert(key.clone(), value);
                true
            }
            Some(_) => false,
            None => mapping.remove(key).is_some(),
        });
    }
    if !mapping.contains_key(key) {
        if value.is_none() {
            return Ok(false);
        }
        // 只为明确设置补充缺失的映射，现有 null、数组和标量保留其原始语义并在下一步拒绝。
        mapping.insert(key.clone(), Value::Object(Map::new()));
    }
    apply(
        mapping.get_mut(key).ok_or(Error::Invalid)?,
        &path[1..],
        value,
    )
}
