//! 边缘消息与 descriptor 转码只比较冻结权限和预算，运行期会话不属于配置差异。

use super::Route;

impl Route {
    /// 业务作用：识别 gRPC 边缘 action、授权、消息边界与 descriptor 转码合同变化。
    ///
    /// 参数说明：
    /// - `candidate`：同路由身份下已经通过制品和协议校验的候选计划。
    ///
    /// 返回：两个协议域的全部固定参数一致时为真，不读取在线会话、投递队列或 relay 状态。
    pub(crate) fn same_grpc_configuration(&self, candidate: &Self) -> bool {
        self.grpc_edge == candidate.grpc_edge && self.grpc_transcoding == candidate.grpc_transcoding
    }
}
