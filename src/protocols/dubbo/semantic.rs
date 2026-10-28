//! 配置比较只读取已编译调用合同，连接池和请求序号不属于策略声明。

use super::DubboPlan;

impl PartialEq for DubboPlan {
    /// 业务作用：识别调用签名、实际附件、编解码权限与资源预算的变化，避免同名路由掩盖 RPC 合同差异。
    ///
    /// 参数说明：
    /// - `other`：已经完成凭据解析与协议校验的候选调用计划。
    ///
    /// 返回：全部固定字段相同时为真，不获取空闲连接池锁或读取运行期请求序号。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            interface,
            method,
            parameter_types,
            version,
            group,
            attachments,
            serialization,
            max_request_body_bytes,
            max_request_frame_bytes,
            max_response_body_bytes,
            connect_timeout,
            request_timeout,
            max_idle_connections,
            next_request_id: _,
            idle: _,
        } = self;
        interface == &other.interface
            && method == &other.method
            && parameter_types == &other.parameter_types
            && version == &other.version
            && group == &other.group
            && attachments == &other.attachments
            && serialization == &other.serialization
            && max_request_body_bytes == &other.max_request_body_bytes
            && max_request_frame_bytes == &other.max_request_frame_bytes
            && max_response_body_bytes == &other.max_response_body_bytes
            && connect_timeout == &other.connect_timeout
            && request_timeout == &other.request_timeout
            && max_idle_connections == &other.max_idle_connections
    }
}

impl Eq for DubboPlan {}
