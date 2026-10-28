//! 外部处理链直接比较实际执行计划，差异输出不包含插件凭据或可见业务头。

use super::Route;

impl Route {
    /// 业务作用：识别 HTTP 外部插件、标准 ext_proc 和 InferencePool 的完整参数及执行权限变化。
    ///
    /// 参数说明：
    /// - `candidate`：完成同代理配置构建和身份冻结的候选路由。
    ///
    /// 返回：所有外部处理声明一致时为真；不调用插件、获取并发槽或读取熔断锁。
    pub(crate) fn same_external_configuration(&self, candidate: &Self) -> bool {
        self.external_plugins == candidate.external_plugins
            && self.ext_proc == candidate.ext_proc
            && self.inference_pool == candidate.inference_pool
    }
}
