//! 消费者套餐绑定保留原生字符串形态，字段投影只服务于显式草稿编辑。

use super::{objects, Error};
use serde_json::{Map, Value};

/// 业务作用：把原生套餐字符串移入有界字段视图，避免把控件投影写回配置。
///
/// 参数说明：
/// - `value`：完整目录已经验证的原套餐字符串。
///
/// 返回：只有 plan 字段的展示对象，原值所有权移交，不复制其它消费者映射。
pub(super) fn fields(value: Value) -> Value {
    Value::Object(Map::from_iter([("plan".into(), value)]))
}

/// 业务作用：只接受明确的套餐名称，把创建控件的字段对象转换为原生绑定值。
///
/// 参数说明：
/// - `fields`：必须且只能包含字符串 plan 的字段输入。
///
/// 返回：转移套餐字符串；额外字段、缺失值或不合法名称原子拒绝。
pub(super) fn create(mut fields: Map<String, Value>) -> Result<Value, Error> {
    if fields.len() != 1 {
        return Err(Error::Invalid);
    }
    let value = fields.remove("plan").ok_or(Error::Invalid)?;
    if !value.as_str().is_some_and(objects::valid_name) {
        return Err(Error::Invalid);
    }
    Ok(value)
}

/// 业务作用：只替换消费者的显式套餐，解除绑定必须删除对象而不能留下空投影。
///
/// 参数说明：
/// - `current`：已验证的原生套餐字符串。
/// - `fields`：用户明确设置的套餐字段。
/// - `remove`：字段移除请求；消费者绑定不允许部分移除。
///
/// 返回：值变化时原地移交新值；同值或空设置保留原文，非法字段拒绝且不更改绑定。
pub(super) fn patch(
    current: &mut Value,
    fields: Map<String, Value>,
    remove: Vec<String>,
) -> Result<bool, Error> {
    // 移除 plan 不能变成无套餐消费者；只有对象删除才明确解除显式绑定。
    if !remove.is_empty() {
        return Err(Error::Invalid);
    }
    if fields.is_empty() {
        return Ok(false);
    }
    let next = create(fields)?;
    if *current == next {
        return Ok(false);
    }
    *current = next;
    Ok(true)
}
