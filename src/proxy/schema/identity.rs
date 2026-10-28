//! 以类型与字段边界表达 Schema 身份，不构造中间 JSON 字符串或递归调用栈。

use std::fmt::Write;

use serde_json::Value;
use sha2::{Digest, Sha256};

enum Part<'a> {
    Value(&'a Value),
    Key(&'a str),
}

struct NumberWriter<'a>(&'a mut Sha256);

impl std::fmt::Write for NumberWriter<'_> {
    /// 业务作用：把 JSON 数字的精确表示直接送入摘要，避免经浮点转换丢失整数边界。
    ///
    /// 参数说明：
    /// - `part`：数字格式化器生成的当前表示片段。
    ///
    /// 返回：片段已进入摘要；不分配中间字符串，不拒绝格式化输出。
    fn write_str(&mut self, part: &str) -> std::fmt::Result {
        self.0.update(part.as_bytes());
        Ok(())
    }
}

/// 业务作用：冻结实际 Schema 的结构身份，使对象键次序不制造差异，同时保持数组和类型边界。
///
/// 参数说明：
/// - `schema`：本次编译实际消费的已解析材料。
///
/// 返回：固定 SHA-256 身份；只借用节点和键，不克隆值或编码完整 JSON。
pub(super) fn of(schema: &Value) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut pending = vec![Part::Value(schema)];
    while let Some(part) = pending.pop() {
        match part {
            Part::Key(key) => {
                hash.update([7]);
                hash.update((key.len() as u64).to_be_bytes());
                hash.update(key.as_bytes());
            }
            Part::Value(value) => match value {
                Value::Null => hash.update([0]),
                Value::Bool(false) => hash.update([1]),
                Value::Bool(true) => hash.update([2]),
                Value::Number(number) => {
                    hash.update([3]);
                    write!(NumberWriter(&mut hash), "{number}")
                        .expect("digest writer accepts every number fragment");
                    // 数字表示不含 NUL；终止字节隔开后续节点，避免相邻数值拼接歧义。
                    hash.update([0]);
                }
                Value::String(value) => {
                    hash.update([4]);
                    hash.update((value.len() as u64).to_be_bytes());
                    hash.update(value.as_bytes());
                }
                Value::Array(values) => {
                    hash.update([5]);
                    hash.update((values.len() as u64).to_be_bytes());
                    pending.extend(values.iter().rev().map(Part::Value));
                }
                Value::Object(values) => {
                    hash.update([6]);
                    hash.update((values.len() as u64).to_be_bytes());
                    let mut entries: Vec<_> = values.iter().collect();
                    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
                    for (key, value) in entries.into_iter().rev() {
                        pending.push(Part::Value(value));
                        pending.push(Part::Key(key));
                    }
                }
            },
        }
    }
    hash.finalize().into()
}
