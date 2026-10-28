//! 已编译 Schema 与构建时材料身份共存，控制面比较不复制或序列化完整文档。

mod identity;

use anyhow::Result;
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct CompiledSchema {
    validator: jsonschema::Validator,
    identity: [u8; 32],
    linear_patterns: bool,
}

impl CompiledSchema {
    /// 业务作用：将已完成引用边界校验的 Schema 编译为共享验证器，并冻结同一材料的比较身份。
    ///
    /// 参数说明：
    /// - `schema`：调用方已拒绝外部引用或完成受控目录展开的 Schema。
    ///
    /// 返回：编译成功时返回验证器与固定身份；非法 Schema 返回错误，不保留原文副本。
    pub(crate) fn build(schema: &Value) -> Result<Self> {
        let validator = jsonschema::validator_for(schema)?;
        Ok(Self {
            validator,
            identity: identity::of(schema),
            linear_patterns: false,
        })
    }

    /// 业务作用：为消息治理冻结非回溯正则验证器，避免共享 Schema 身份时放宽原有 CPU 边界。
    ///
    /// 参数说明：
    /// - `schema`：调用方已完成深度、规模和引用限制的消息 Schema。
    ///
    /// 返回：保留实际编译选项与材料身份；不支持的正则或非法 Schema 拒绝候选。
    pub(crate) fn build_linear(schema: &Value) -> Result<Self> {
        let validator = jsonschema::options()
            .with_pattern_options(jsonschema::PatternOptions::regex())
            .build(schema)?;
        Ok(Self {
            validator,
            identity: identity::of(schema),
            linear_patterns: true,
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
    /// - `other`：已经冻结编译选项与材料身份的候选 Schema。
    ///
    /// 返回：规范材料身份及编译选项相同时为真；摘要不代替对请求或响应的验证。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            identity,
            linear_patterns,
            validator: _,
        } = self;
        identity == &other.identity && linear_patterns == &other.linear_patterns
    }
}

impl Eq for CompiledSchema {}
