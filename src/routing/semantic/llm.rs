//! 模型调用与内容治理的策略身份来自冻结计划，不从管理摘要推断完整配置。

use super::Route;

impl Route {
    /// 业务作用：识别 LLM 模型、实际凭据、安全策略、费用预算和治理内容变化。
    ///
    /// 参数说明：
    /// - `candidate`：同路由身份下已经完成模型与治理构建的候选计划。
    ///
    /// 返回：LLM 全部冻结字段一致时为真，不读取缓存条目、token 余额或模型延迟样本。
    pub(crate) fn same_llm_configuration(&self, candidate: &Self) -> bool {
        self.llm == candidate.llm
    }
}
