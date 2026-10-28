//! 外部处理策略比较与活动流、熔断计数和半开权威隔离。

use super::ExtProcPlan;

impl PartialEq for ExtProcPlan {
    /// 业务作用：识别处理器相位、实际认证、修改权限和资源边界变化，不等待正在处理的业务流。
    ///
    /// 参数说明：
    /// - `other`：已经验证标准协议与权限边界的候选计划。
    ///
    /// 返回：全部冻结声明一致时为真；并发上限直接读取构建值，当前许可与熔断状态不参与比较。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            upstream,
            authorization,
            request_headers,
            response_headers,
            request_body,
            response_body,
            request_trailers,
            response_trailers,
            message_timeout,
            total_timeout,
            max_message_bytes,
            max_total_bytes,
            max_body_bytes,
            fail_open,
            mutation_headers,
            frozen_identity_headers,
            writable_metadata_namespaces,
            inference_endpoint_picker,
            max_in_flight,
            in_flight: _,
            circuit: _,
            failure_threshold,
            reset_timeout,
        } = self;
        upstream == &other.upstream
            && authorization == &other.authorization
            && request_headers == &other.request_headers
            && response_headers == &other.response_headers
            && request_body == &other.request_body
            && response_body == &other.response_body
            && request_trailers == &other.request_trailers
            && response_trailers == &other.response_trailers
            && message_timeout == &other.message_timeout
            && total_timeout == &other.total_timeout
            && max_message_bytes == &other.max_message_bytes
            && max_total_bytes == &other.max_total_bytes
            && max_body_bytes == &other.max_body_bytes
            && fail_open == &other.fail_open
            && mutation_headers == &other.mutation_headers
            && frozen_identity_headers == &other.frozen_identity_headers
            && writable_metadata_namespaces == &other.writable_metadata_namespaces
            && inference_endpoint_picker == &other.inference_endpoint_picker
            && max_in_flight == &other.max_in_flight
            && failure_threshold == &other.failure_threshold
            && reset_timeout == &other.reset_timeout
    }
}

impl Eq for ExtProcPlan {}
