//! 本地文件决定的类型化上报；整份报告通过验证后才刷新当前观察。

use super::protocol;
use crate::{
    admin::cluster::facts::Facts,
    control::{
        baseline::NodeBaseline,
        publication_status::{PublicationStatus, Storage},
    },
};
use nasa::grpc::Status;
use std::sync::Arc;

/// 业务作用：把同次磁盘观察编码为固定字段，避免正文复制和JSON中转。
///
/// 参数说明：
/// - `value`：已绑定活动快照的本机文件决定观察。
///
/// 返回：合法的有界协议字段；非法内部组合不发送。
pub(super) fn encode(value: &PublicationStatus) -> Option<protocol::PublicationObservation> {
    use protocol::PublicationState as State;
    if !value.valid() {
        return None;
    }
    let state = match value.state {
        "unsupported" => State::Unsupported,
        "disabled" => State::Disabled,
        "uninitialized" => State::Uninitialized,
        "unavailable" => State::Unavailable,
        "protected" => State::Protected,
        "idle" => State::Idle,
        "preparing" => State::Preparing,
        "forward" => State::Forward,
        "backward" => State::Backward,
        _ => return None,
    };
    Some(protocol::PublicationObservation {
        schema: value.schema,
        state: state as i32,
        storage: value
            .storage
            .as_ref()
            .map(|storage| protocol::PublicationStorage {
                cluster_id: storage.cluster_id.clone(),
                store_id: storage.store_id.clone(),
                node_admission_epoch: storage
                    .node_admission_epoch
                    .parse()
                    .expect("validated epoch"),
                revision: storage.revision.parse().expect("validated revision"),
                operation_id: storage.operation_id.clone(),
            }),
    })
}

/// 业务作用：在推进报告序号前验证文件决定及其同次基线，矛盾或异集群状态不能刷新节点事实。
///
/// 参数说明：
/// - `value`：该报告携带的可选观察；缺席表示旧协议能力。
/// - `supported`：发送方是否声明节点持久基线协议。
/// - `facts`：已经验证的同次节点、启动和配置身份。
/// - `cluster`：本接收端当前发行集群，未启用时为空。
/// - `baseline`：同次已经验证的可选发布基线。
///
/// 返回：可共享的当前观察；无元数据状态不含旧提交证据，任何冲突拒绝整份报告。
pub(super) fn decode(
    value: Option<protocol::PublicationObservation>,
    supported: bool,
    facts: &Facts,
    cluster: Option<&str>,
    baseline: Option<&NodeBaseline>,
) -> Result<Arc<PublicationStatus>, Status> {
    use protocol::PublicationState as State;
    let Some(value) = value else {
        return Ok(Arc::new(PublicationStatus::empty("unsupported")));
    };
    let state = match State::try_from(value.state) {
        Ok(State::Unsupported) => "unsupported",
        Ok(State::Disabled) => "disabled",
        Ok(State::Uninitialized) => "uninitialized",
        Ok(State::Unavailable) => "unavailable",
        Ok(State::Protected) => "protected",
        Ok(State::Idle) => "idle",
        Ok(State::Preparing) => "preparing",
        Ok(State::Forward) => "forward",
        Ok(State::Backward) => "backward",
        _ => return Err(Status::invalid_argument("invalid publication state")),
    };
    let observation = PublicationStatus {
        schema: value.schema,
        state,
        storage: value.storage.map(|storage| Storage {
            cluster_id: storage.cluster_id,
            store_id: storage.store_id,
            node_admission_epoch: storage.node_admission_epoch.to_string(),
            revision: storage.revision.to_string(),
            operation_id: storage.operation_id,
        }),
    };
    if !observation.valid()
        || (state != "unsupported" && (!supported || facts.mode == "admin"))
        || observation.storage.as_ref().is_some_and(|storage| {
            cluster != Some(storage.cluster_id.as_str())
                || facts.config_version == 0
                || facts.config_fingerprint.is_none()
        })
    {
        return Err(Status::invalid_argument("invalid publication binding"));
    }
    // 同一报告不能同时宣称待恢复和可受理；基线与状态不得拼接自不同存储或代际。
    if baseline.is_some_and(|baseline| {
        state != "idle"
            || !observation.storage.as_ref().is_some_and(|storage| {
                baseline.cluster_id == storage.cluster_id
                    && baseline.store_id == storage.store_id
                    && baseline.node_admission_epoch == storage.node_admission_epoch
            })
    }) {
        return Err(Status::invalid_argument("publication baseline differs"));
    }
    Ok(Arc::new(observation))
}
