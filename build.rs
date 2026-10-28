/// 业务作用：仅为启用节点管理的制品生成统一门面的类型化协议及其描述符。
///
/// 参数说明: 无。
///
/// 返回：协议或受管生成合同不成立时终止构建，默认制品不运行协议生成器。
fn main() {
    #[cfg(feature = "admin-grpc")]
    nagrpc_build::compile("proto/naway/management/v1/management.proto")
        .expect("节点管理协议必须完整生成");
}
