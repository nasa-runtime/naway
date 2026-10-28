//! Agent 路由比较实际协议计划，不读取面向客户端的会话或任务运行状态。

use super::Route;

impl Route {
    /// 业务作用：识别 MCP/A2A 身份、目录、工具合同和资源边界变化。
    ///
    /// 参数说明：
    /// - `candidate`：同路由身份下已完整构建的 Agent 候选。
    ///
    /// 返回：协议类型和全部冻结执行参数相同时为真，不触发远端发现或工具调用。
    pub(crate) fn same_agent_configuration(&self, candidate: &Self) -> bool {
        self.agent == candidate.agent
    }
}
