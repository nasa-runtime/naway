//! 独立服务事实使用有限字段直接计算摘要，只在网络边界构造协议消息。

use crate::admin::management::protocol;
use crate::upstream::observation::{Availability, Counts, Row, Snapshot};
use nasa::grpc::Status;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: usize = 32;

/// 业务作用：为协商成功的服务事实追加独立摘要域，缺能力时保持原样本摘要。
///
/// 参数说明：
/// - `hash`：已累计指标与路由的摘要状态。
/// - `snapshot`：当前有界服务目录，None 表示未提供该能力。
///
/// 返回：原地追加完整身份、分类和计数，不生成中间文档。
pub(super) fn digest(hash: &mut Sha256, snapshot: Option<&Snapshot>) {
    let Some(snapshot) = snapshot else {
        return;
    };
    hash.update(b"naway-service-state\0");
    hash.update([u8::from(snapshot.capacity)]);
    hash.update((snapshot.rows.len() as u64).to_be_bytes());
    for row in &snapshot.rows {
        for value in [&row.service, &row.workspace, &row.source] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update([
            u8::from(row.critical),
            u8::from(row.active_probes),
            availability(row.availability) as u8,
            u8::from(row.counts.is_some()),
        ]);
        if let Some(counts) = row.counts {
            for value in [
                counts.instances,
                counts.configured_selectable,
                counts.manually_down,
                counts.backup,
                counts.active_rejected,
            ] {
                hash.update(value.to_be_bytes());
            }
        }
    }
}

/// 业务作用：把原生发现状态映射到固定协议编号，避免以任意文本表示可用性。
///
/// 参数说明：
/// - `value`：已验证的当前发现状态。
///
/// 返回：协议定义的非零状态，不把未知变成已知零。
fn availability(value: Availability) -> i32 {
    match value {
        Availability::Available => protocol::service_state::Availability::Available as i32,
        Availability::Missing => protocol::service_state::Availability::Missing as i32,
        Availability::Stale => protocol::service_state::Availability::Stale as i32,
    }
}

/// 业务作用：在单次发送边界复制有限服务身份并移动固定计数，不传输实例地址。
///
/// 参数说明：
/// - `row`：本次采样中已排序的服务事实。
///
/// 返回：类型化消息，缺失与过期保留无计数状态。
pub(super) fn encode(row: &Row) -> protocol::ServiceState {
    protocol::ServiceState {
        service: row.service.clone(),
        workspace: row.workspace.clone(),
        source: row.source.clone(),
        critical: row.critical,
        active_probes: row.active_probes,
        availability: availability(row.availability),
        counts: row.counts.map(|counts| protocol::ServiceCounts {
            instances: counts.instances,
            configured_selectable: counts.configured_selectable,
            manually_down: counts.manually_down,
            backup: counts.backup,
            active_rejected: counts.active_rejected,
        }),
    }
}

/// 业务作用：移动有限协议字段，拒绝未知状态和过长身份后交由完整样本校验分类约束。
///
/// 参数说明：
/// - `row`：已受分片字节预算约束的服务消息。
///
/// 返回：原生事实；非法消息拒绝整次上传，不能发布部分目录。
pub(super) fn decode(row: protocol::ServiceState) -> Result<Row, Status> {
    if [&row.service, &row.workspace]
        .into_iter()
        .any(|name| name.is_empty() || name.len() > 128 || name.chars().any(char::is_control))
        || row.source.len() > 16
    {
        return Err(Status::invalid_argument("invalid service identity"));
    }
    let availability = match protocol::service_state::Availability::try_from(row.availability) {
        Ok(protocol::service_state::Availability::Available) => Availability::Available,
        Ok(protocol::service_state::Availability::Missing) => Availability::Missing,
        Ok(protocol::service_state::Availability::Stale) => Availability::Stale,
        _ => return Err(Status::invalid_argument("invalid service availability")),
    };
    Ok(Row {
        service: row.service,
        workspace: row.workspace,
        source: row.source,
        critical: row.critical,
        active_probes: row.active_probes,
        availability,
        counts: row.counts.map(|counts| Counts {
            instances: counts.instances,
            configured_selectable: counts.configured_selectable,
            manually_down: counts.manually_down,
            backup: counts.backup,
            active_rejected: counts.active_rejected,
        }),
    })
}
