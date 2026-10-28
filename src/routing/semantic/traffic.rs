//! 流量治理比较冻结的完整账本声明与套餐绑定，不读取额度、队列或活动请求。

use super::Route;

impl Route {
    /// 业务作用：识别双向带宽、成本配额、套餐归属与静态故障响应的完整策略变化。
    ///
    /// 参数说明：
    /// - `candidate`：已通过共享作用域一致性与套餐引用校验的候选路由。
    ///
    /// 返回：全部声明及冻结账本身份相同时为真；借用比较不会消费额度或复制响应正文。
    pub(crate) fn same_traffic_configuration(&self, candidate: &Self) -> bool {
        // state_key 与 bound_scope 决定实际共享账本，必须连同各字段比较，不能仅凭指纹推断等价。
        self.traffic_limit == candidate.traffic_limit
            && self.usage_plan == candidate.usage_plan
            && self.mock_response == candidate.mock_response
            && self.fault_injection == candidate.fault_injection
    }
}
