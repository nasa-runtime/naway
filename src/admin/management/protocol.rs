//! 类型化管理事实仅描述当前节点，不把JSON文档嵌入protobuf传输。

use super::security;
use crate::admin::cluster::facts::Facts;
use nasa::grpc::Status;

nasa::grpc::include_proto!("naway.management.v1");

/// 业务作用：将本进程的真实当前事实编码为固定管理协议，不从注册目录推测运行状态。
///
/// 参数说明：
/// - `facts`：当前启动实例和同代配置读面。
/// - `node_id`：管理计划显式声明且已验证的本机身份。
///
/// 返回：无秘密的类型化消息；数量使用协议固定整数范围。
pub(super) fn encode(facts: Facts, node_id: &str) -> NodeFacts {
    NodeFacts {
        node_id: node_id.into(),
        boot_id: facts.boot_id,
        mode: match facts.mode.as_str() {
            "admin" => Mode::Admin,
            "data" => Mode::Data,
            "sidecar" => Mode::Sidecar,
            _ => Mode::AllInOne,
        } as i32,
        ready: facts.ready,
        config_version: facts.config_version,
        config_fingerprint: facts
            .config_fingerprint
            .and_then(|value| u64::from_str_radix(&value, 16).ok()),
        discovery_enabled: facts.discovery_enabled,
        configuration_enabled: facts.configuration_enabled,
        proxies: facts.proxies.min(u32::MAX as usize) as u32,
        routes: facts.routes.min(u32::MAX as usize) as u32,
        services: facts.services.min(u32::MAX as usize) as u32,
    }
}

/// 业务作用：校验远端协议事实的完整边界后转为管理读面，未知角色不能参与健康汇总。
///
/// 参数说明：
/// - `value`：经过传输字节上限限制但尚未取得业务信任的消息。
///
/// 返回：完整合法事实；非法身份、角色或数量返回InvalidArgument且不更新样本时间。
pub(super) fn decode(value: NodeFacts) -> Result<Facts, Status> {
    let mode = match Mode::try_from(value.mode) {
        Ok(Mode::Admin) => "admin",
        Ok(Mode::Data) => "data",
        Ok(Mode::AllInOne) => "all-in-one",
        Ok(Mode::Sidecar) => "sidecar",
        _ => return Err(Status::invalid_argument("invalid node mode")),
    };
    if !security::identifier(&value.node_id)
        || !security::identifier(&value.boot_id)
        || [value.proxies, value.routes, value.services]
            .into_iter()
            .any(|count| count > 1_000_000)
    {
        return Err(Status::invalid_argument("invalid node facts"));
    }
    Ok(Facts {
        schema_version: 1,
        node_id: Some(value.node_id),
        boot_id: value.boot_id,
        mode: mode.into(),
        ready: value.ready,
        config_version: value.config_version,
        config_fingerprint: value
            .config_fingerprint
            .map(|value| format!("{value:016x}")),
        discovery_enabled: value.discovery_enabled,
        configuration_enabled: value.configuration_enabled,
        proxies: value.proxies as usize,
        routes: value.routes as usize,
        services: value.services as usize,
    })
}
