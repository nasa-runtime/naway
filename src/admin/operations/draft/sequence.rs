//! 有序列表动作只移动指定元素，未编辑子树始终保留在服务端原始声明中。

use super::{nested, Error};
use serde::Deserialize;
use serde_json::{Map, Value};

const MAX_ITEMS: usize = 4096;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Edit {
    Insert {
        index: usize,
        value: Value,
    },
    Set {
        index: usize,
        value: Value,
    },
    Remove {
        index: usize,
    },
    Move {
        from: usize,
        to: usize,
    },
    Patch {
        index: usize,
        edits: Vec<nested::Edit>,
    },
}

/// 业务作用：在一个草稿对象中编辑单个有序列表，不从浏览器展示值重建未修改元素。
///
/// 参数说明：
/// - `object`：已按领域和稳定身份选择的原始对象。
/// - `path`：显式映射键组成的列表位置，不解析数组索引或路径分隔符。
/// - `edit`：一个以当前原文为基准的序列动作。
///
/// 返回：实际声明改变时为 true；非法路径、索引、容量或元素类型拒绝整个局部文档。
pub(super) fn patch(object: &mut Value, path: &[String], edit: Edit) -> Result<bool, Error> {
    if path.is_empty()
        || path.len() > 8
        || path[0] == "id"
        || path
            .iter()
            .any(|key| key.is_empty() || key.len() > 128 || key.chars().any(char::is_control))
    {
        return Err(Error::Invalid);
    }
    if let Edit::Patch {
        edits,
        ..
    } = &edit
    {
        if edits
            .iter()
            .any(|edit| path.len() + 1 + edit.path().len() > 8)
        {
            return Err(Error::Invalid);
        }
    }
    let create = matches!(
        edit,
        Edit::Insert {
            index: 0,
            ..
        }
    );
    let items = locate(object, path, create)?;
    if items.len() > MAX_ITEMS {
        return Err(Error::Capacity);
    }
    match edit {
        Edit::Insert {
            index,
            value,
        } => {
            if index > items.len() {
                return Err(Error::Invalid);
            }
            if items.len() == MAX_ITEMS {
                return Err(Error::Capacity);
            }
            items.insert(index, value);
            Ok(true)
        }
        Edit::Set {
            index,
            value,
        } => {
            let current = items.get_mut(index).ok_or(Error::Invalid)?;
            if *current == value {
                return Ok(false);
            }
            *current = value;
            Ok(true)
        }
        Edit::Remove {
            index,
        } => {
            if index >= items.len() {
                return Err(Error::Invalid);
            }
            items.remove(index);
            Ok(true)
        }
        Edit::Move {
            from,
            to,
        } => {
            // 目标下标表示移动后的最终位置；先完整检查，不能删除元素后才发现越界。
            if from >= items.len() || to >= items.len() {
                return Err(Error::Invalid);
            }
            if items[from.min(to)..=from.max(to)]
                .iter()
                .all(|value| value == &items[from])
            {
                return Ok(false);
            }
            let value = items.remove(from);
            items.insert(to, value);
            Ok(true)
        }
        Edit::Patch {
            index,
            edits,
        } => nested::patch(items.get_mut(index).ok_or(Error::Invalid)?, edits),
    }
}

/// 业务作用：只沿映射定位列表，首次插入可补缺失祖先，已有类型不被隐式替换。
///
/// 参数说明：
/// - `object`：当前路径的原始声明子树。
/// - `path`：已校验且非空的剩余映射路径。
/// - `create`：是否为缺失列表的首次零下标插入。
///
/// 返回：借用原列表；父类型错误或无权创建的缺失位置拒绝，不读外部配置。
fn locate<'a>(
    object: &'a mut Value,
    path: &[String],
    create: bool,
) -> Result<&'a mut Vec<Value>, Error> {
    let mapping = object.as_object_mut().ok_or(Error::Invalid)?;
    let key = &path[0];
    if !mapping.contains_key(key) {
        if !create {
            return Err(Error::Invalid);
        }
        // 仅缺失字段可以补声明；null 或其它已声明类型不能因为插入动作而失去原始语义。
        let value = if path.len() == 1 {
            Value::Array(Vec::new())
        } else {
            Value::Object(Map::new())
        };
        mapping.insert(key.clone(), value);
    }
    let value = mapping.get_mut(key).ok_or(Error::Invalid)?;
    if path.len() == 1 {
        value.as_array_mut().ok_or(Error::Invalid)
    } else {
        locate(value, &path[1..], create)
    }
}
