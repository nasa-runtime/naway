//! 管理报告中的持久基线编码与验证，不把格式合法当成动作授权。

use super::protocol;
use crate::{admin::cluster::facts::Facts, control::baseline::NodeBaseline};
use nasa::grpc::Status;
use std::sync::Arc;

/// 业务作用：将已确认的低敏基线转换为固定protobuf字段，避免嵌套JSON或整数精度损失。
///
/// 参数说明：
/// - `value`：本机只读观察得到的当前受保护基线。
///
/// 返回：格式完整时返回类型化证明；非法内部声明不发送。
pub(super) fn encode(value: &NodeBaseline) -> Option<protocol::NodeBaseline> {
    if !value.valid() {
        return None;
    }
    let documents_sha256 = value
        .documents_sha256
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("validated hex"), 16)
                .expect("validated digest")
        })
        .collect();
    Some(protocol::NodeBaseline {
        schema: value.schema,
        cluster_id: value.cluster_id.clone(),
        store_id: value.store_id.clone(),
        node_admission_epoch: value.node_admission_epoch.parse().expect("validated epoch"),
        documents_sha256,
    })
}

/// 业务作用：在报告序号提交前验证基线及发行集群，错误消息不能刷新旧节点事实年龄。
///
/// 参数说明：
/// - `supported`：发送方是否声明具备类型化基线协议。
/// - `value`：与本次报告同时提交的可选基线。
/// - `facts`：已验证的同次节点及配置事实。
/// - `cluster`：当前已授权接收计划的发行集群，未启用发行者身份时为空。
///
/// 返回：完整合法基线或明确缺失；角色、格式、集群不符时拒绝整个报告。
pub(super) fn decode(
    supported: bool,
    value: Option<protocol::NodeBaseline>,
    facts: &Facts,
    cluster: Option<&str>,
) -> Result<Option<Arc<NodeBaseline>>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    // 持久节点事实只属于当前发行集群；身份握手没有开启时不能接受外来的动作基线声明。
    if !supported
        || value.schema != 1
        || facts.mode == "admin"
        || facts.config_version == 0
        || facts.config_fingerprint.is_none()
        || cluster != Some(value.cluster_id.as_str())
    {
        return Err(Status::invalid_argument("invalid node baseline binding"));
    }
    let digest: [u8; 32] = value
        .documents_sha256
        .try_into()
        .map_err(|_| Status::invalid_argument("invalid node baseline digest"))?;
    let baseline = NodeBaseline::from_parts(
        value.cluster_id,
        value.store_id,
        value.node_admission_epoch,
        &digest,
    );
    if !baseline.valid() {
        return Err(Status::invalid_argument("invalid node baseline"));
    }
    Ok(Some(Arc::new(baseline)))
}
