//! 反射配置的身份在有界读取时冻结，比较保留实际 HTTP 映射次序且不重新编码 protobuf。

use super::GrpcTranscodingPlan;
#[cfg(feature = "grpc-descriptor")]
use super::{GoogleHttpBinding, ResolvedGrpcMethod};

impl PartialEq for GrpcTranscodingPlan {
    /// 业务作用：比较 descriptor 的实际材料、读取边界、已授权 RPC 与转码预算，避免同路径变更被遗漏。
    ///
    /// 参数说明：
    /// - `other`：已经通过 descriptor 与白名单校验的候选计划。
    ///
    /// 返回：全部固定输入与执行规则一致时为真；关闭制品无法构造业务实例。
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "grpc-descriptor")]
        {
            let Self {
                descriptor_identity,
                max_descriptor_bytes,
                methods,
                connect_json,
                google_http,
            } = self;
            // 方法反射对象由同次材料身份覆盖；身份不一致时不能只凭 RPC 名称判定消息合同相同。
            descriptor_identity == &other.descriptor_identity
                && max_descriptor_bytes == &other.max_descriptor_bytes
                && connect_json == &other.connect_json
                && google_http == &other.google_http
                && methods.len() == other.methods.len()
                && methods
                    .iter()
                    .zip(other.methods.iter())
                    .all(|(a, b)| same_method(a, b))
        }
        #[cfg(not(feature = "grpc-descriptor"))]
        {
            let _ = other;
            true
        }
    }
}

impl Eq for GrpcTranscodingPlan {}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：在 descriptor 身份已经相同后比较单个 RPC 的实际选择和消息转换边界。
///
/// 参数说明：
/// - `current`：当前快照的已授权方法。
/// - `candidate`：候选快照中同一有效次序的方法。
///
/// 返回：路径、输入输出策略、流预算和有序 HTTP 映射一致时为真，不访问请求状态。
fn same_method(current: &ResolvedGrpcMethod, candidate: &ResolvedGrpcMethod) -> bool {
    let ResolvedGrpcMethod {
        method: _,
        rpc_path,
        reject_unknown_fields,
        max_input_message_bytes,
        max_output_message_bytes,
        max_json_bytes,
        max_stream_messages,
        max_stream_buffer_bytes,
        http_bindings,
    } = current;
    rpc_path == &candidate.rpc_path
        && reject_unknown_fields == &candidate.reject_unknown_fields
        && max_input_message_bytes == &candidate.max_input_message_bytes
        && max_output_message_bytes == &candidate.max_output_message_bytes
        && max_json_bytes == &candidate.max_json_bytes
        && max_stream_messages == &candidate.max_stream_messages
        && max_stream_buffer_bytes == &candidate.max_stream_buffer_bytes
        && http_bindings.len() == candidate.http_bindings.len()
        && http_bindings
            .iter()
            .zip(candidate.http_bindings.iter())
            .all(|(a, b)| same_binding(a, b))
}

#[cfg(feature = "grpc-descriptor")]
/// 业务作用：比较已编译 REST 到 RPC 的匹配规则及字段归属，保留首个命中规则的优先级。
///
/// 参数说明：
/// - `current`：当前 HTTP 映射。
/// - `candidate`：候选中同一有效次序的 HTTP 映射。
///
/// 返回：HTTP 方法、规范正则、路径字段和正文归属相同时为真，无需重建匹配器。
fn same_binding(current: &GoogleHttpBinding, candidate: &GoogleHttpBinding) -> bool {
    let GoogleHttpBinding {
        method,
        path_regex,
        path_fields,
        body_field,
    } = current;
    method == candidate.method
        && path_regex.as_str() == candidate.path_regex.as_str()
        && path_fields == &candidate.path_fields
        && body_field == &candidate.body_field
}
