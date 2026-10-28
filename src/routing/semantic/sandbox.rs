//! 客体扩展按已编译的能力和实际材料比较，控制面不执行客体或读取共享运行状态。

use super::Route;

impl Route {
    /// 业务作用：识别 Wasm 与 Lua 的相位顺序、实际源码、权限和资源预算变化。
    ///
    /// 参数说明：
    /// - `candidate`：完成模块信任、沙箱能力与预算校验的候选路由。
    ///
    /// 返回：所有客体计划一致时为真；不读取连接池、共享目录或熔断锁。
    pub(crate) fn same_sandbox_configuration(&self, candidate: &Self) -> bool {
        let same = self.wasm_plugins == candidate.wasm_plugins;
        #[cfg(feature = "lua-scripts")]
        let same = same && self.script_plugins == candidate.script_plugins;
        same
    }
}
