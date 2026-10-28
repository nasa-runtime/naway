//! Casbin 比较实际模型、策略材料与输入边界，不复制授权引擎。

use super::CasbinPolicy;

impl PartialEq for CasbinPolicy {
    /// 业务作用：识别本地授权模型、策略文件和请求输入声明的变化。
    ///
    /// 参数说明：
    /// - `other`：已通过模型编译和参数元数校验的候选计划。
    ///
    /// 返回：全部声明与原读取点材料身份相同时为真，不重读文件、不执行 matcher。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            material_identity,
            arguments,
            require_identity,
            fail_open,
            max_argument_bytes,
            max_input_bytes,
            // Enforcer 的只读模型与策略由同次构建生成的材料身份表达。
            enforcer: _,
        } = self;
        material_identity == &other.material_identity
            && arguments == &other.arguments
            && require_identity == &other.require_identity
            && fail_open == &other.fail_open
            && max_argument_bytes == &other.max_argument_bytes
            && max_input_bytes == &other.max_input_bytes
    }
}

impl Eq for CasbinPolicy {}
