//! 已编译 Schema 与构建时材料身份共存，控制面比较不复制或序列化完整文档。

mod identity;

use anyhow::Result;
use serde_json::Value;

pub(super) struct CompiledSchema {
    validator: jsonschema::Validator,
    identity: [u8; 32],
}

impl CompiledSchema {
    /// 业务作用：将已完成引用边界校验的 Schema 编译为共享验证器，并冻结同一材料的比较身份。
    ///
    /// 参数说明：
    /// - `schema`：调用方已拒绝外部引用或完成受控目录展开的 Schema。
    ///
    /// 返回：编译成功时返回验证器与固定身份；非法 Schema 返回错误，不保留原文副本。
    pub(super) fn build(schema: &Value) -> Result<Self> {
        let validator = jsonschema::validator_for(schema)?;
        Ok(Self {
            validator,
            identity: identity::of(schema),
        })
    }
}

impl std::ops::Deref for CompiledSchema {
    type Target = jsonschema::Validator;

    /// 业务作用：数据面直接借用已编译验证器，避免比较身份介入请求校验。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一计划中的只读验证器引用，不重建或复制 Schema。
    fn deref(&self) -> &Self::Target {
        &self.validator
    }
}

impl PartialEq for CompiledSchema {
    /// 业务作用：按实际编译材料比较校验计划，不访问编译器内部状态。
    ///
    /// 参数说明：
    /// - `other`：编译选项相同的候选 Schema。
    ///
    /// 返回：规范材料身份相同时为真；摘要不代替对请求或响应的验证。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            identity,
            validator: _,
        } = self;
        identity == &other.identity
    }
}

impl Eq for CompiledSchema {}
