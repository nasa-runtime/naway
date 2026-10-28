//! 显式路由脚本在隔离的阻塞任务内运行，沙箱输出通过完整验证后才发布。
mod budget;
mod circuit;
mod contract;
pub(crate) mod metrics;
mod plan;
mod vm;
pub(crate) use contract::Context;
pub(crate) use plan::Chain;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Input,
    Output,
    Instructions,
    Cpu,
    Memory,
    Allocations,
    Deadline,
    Cancelled,
    Capacity,
    Script,
    Dependency,
}
impl std::fmt::Display for Failure {
    /// 业务作用：对外只输出固定类别，不泄漏客体错误中的源码、路径或请求数据。
    ///
    /// 参数说明：
    /// - `out`：错误文本目标。
    ///
    /// 返回：固定低敏拒绝描述。
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "script rejected: {self:?}")
    }
}
impl std::error::Error for Failure {}
impl Failure {
    /// 业务作用：为固定遥测目录提供拒绝类别，避免使用可变错误文本作标签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：预定义低基数结果名。
    pub fn outcome(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Instructions => "instructions",
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Allocations => "allocations",
            Self::Deadline => "deadline",
            Self::Cancelled => "cancelled",
            Self::Capacity => "capacity",
            Self::Script => "script",
            Self::Dependency => "dependency",
        }
    }
}
