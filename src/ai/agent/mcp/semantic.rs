//! MCP 的固定目录与权限独立于会话索引和并发许可，配置审查不等待正在执行的工具。

use super::{Arc, BTreeMap, LimitsCfg, Plan, SecurityCfg, Target, Tool};

#[derive(PartialEq, Eq)]
struct Identity<'a> {
    security: &'a SecurityCfg,
    limits: &'a LimitsCfg,
    tools: &'a BTreeMap<String, Arc<Tool>>,
    servers: &'a BTreeMap<String, Arc<Target>>,
}

impl Plan {
    /// 业务作用：穷尽投影 MCP 固定参数，防止会话和控制许可被当作候选配置内容。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：借用真实工具和后端目录的身份，不分配目录副本、不读取会话锁。
    fn semantic_identity(&self) -> Identity<'_> {
        let Self {
            security,
            limits,
            tools,
            servers,
            sessions: _,
            inflight: _,
            control: _,
        } = self;
        Identity {
            security,
            limits,
            tools,
            servers,
        }
    }
}

impl PartialEq for Plan {
    /// 业务作用：识别 MCP 身份、调用预算和工具执行合同的变化，支持发布前配置审查。
    ///
    /// 参数说明：
    /// - `other`：已经完整编译 OpenAPI 和显式工具声明的候选计划。
    ///
    /// 返回：全部实际目录和固定参数相同时为真，不初始化远端会话或占用业务槽。
    fn eq(&self, other: &Self) -> bool {
        self.semantic_identity() == other.semantic_identity()
    }
}

impl Eq for Plan {}
