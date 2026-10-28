//! 工具身份借用现有 metadata 与 Schema 文档，不复制或重新编码供客户端使用的目录。

use super::{Acl, Backend, SideEffect, Tool, Value};

#[derive(PartialEq, Eq)]
struct Identity<'a> {
    name: &'a str,
    discovery: &'a Acl,
    invocation: &'a Acl,
    deadline_ms: u64,
    max_calls: u64,
    max_request_bytes: usize,
    max_response_bytes: usize,
    backend: &'a Backend,
    side_effect: SideEffect,
    info: &'a Value,
}

impl Tool {
    /// 业务作用：穷尽冻结工具的授权与外呼边界，以已保存的实际 Schema 代表同次编译的验证器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整借用身份；输入输出 Schema 已存在于 info，比较不重新编译验证器或执行工具。
    fn semantic_identity(&self) -> Identity<'_> {
        let Self {
            name,
            discovery,
            invocation,
            deadline_ms,
            max_calls,
            max_request_bytes,
            max_response_bytes,
            backend,
            side_effect,
            info,
            input: _,
            output: _,
        } = self;
        Identity {
            name,
            discovery,
            invocation,
            deadline_ms: *deadline_ms,
            max_calls: *max_calls,
            max_request_bytes: *max_request_bytes,
            max_response_bytes: *max_response_bytes,
            backend,
            side_effect: *side_effect,
            info,
        }
    }
}

impl PartialEq for Tool {
    /// 业务作用：比较批准工具的实际执行合同，覆盖目录描述、Schema、权限、目标与副作用声明。
    ///
    /// 参数说明：
    /// - `other`：已完成 Schema、方法和预算验证的候选工具。
    ///
    /// 返回：全部固定字段相同时为真；不访问会话调用余额或序列化目录。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

impl Eq for Tool {}
