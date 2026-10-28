//! 终端聚合与 RPC 转换的完整计划直接参与比较，复用冻结字节与已解析凭据。

use super::Route;

impl Route {
    /// 业务作用：识别 BFF 子请求合同与 Dubbo 调用计划变化，保持管理审查与实际后端行为一致。
    ///
    /// 参数说明：
    /// - `candidate`：同代理和路由身份下已经验证的候选快照。
    ///
    /// 返回：聚合目标、调用映射、实际凭据与执行预算都一致时为真，不触碰运行状态。
    pub(crate) fn same_backend_configuration(&self, candidate: &Self) -> bool {
        self.bff_aggregation == candidate.bff_aggregation && self.dubbo == candidate.dubbo
    }
}
