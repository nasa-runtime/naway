//! 业务命令与独立释放共享有界身份字段转换，不为传输重新编码 JSON 或候选原文。

use crate::{
    admin::management::protocol,
    control::{
        actions::{
            command::{Delivery, Intent},
            domain::Domain,
        },
        baseline::NodeBaseline,
    },
};
use nasa::grpc::Status;

/// 业务作用：直接移动冻结意图到类型化字段，业务和释放保留完全相同的原始目标声明。
///
/// 参数说明：
/// - intent：已经由业务合同验证的原意图。
///
/// 返回：包含完整 u64 代际与固定摘要的消息；仅转换字段，不重读当前节点。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode_intent(intent: Intent) -> protocol::ActionIntent {
    protocol::ActionIntent {
        operation_id: intent.operation_id,
        proposal_epoch: intent.proposal_epoch,
        target_index: intent.target_index,
        target_count: intent.target_count,
        domain: match intent.domain {
            Domain::Gateway => protocol::ActionDomain::Gateway,
            Domain::Sentinel => protocol::ActionDomain::Sentinel,
            Domain::InterfaceGuard => protocol::ActionDomain::InterfaceGuard,
        } as i32,
        node_id: intent.node_id,
        original_boot_id: intent.original_boot_id,
        baseline: Some(encode_baseline(intent.baseline)),
        base_version: intent.base_version,
        base_fingerprint: intent.base_fingerprint,
        candidate_bytes: intent.candidate_bytes,
        candidate_sha256: intent.candidate_sha256.to_vec(),
        scope: intent.scope,
        creator: intent.creator,
        reviewer: intent.reviewer,
        authority_sha256: intent.authority_sha256.to_vec(),
    }
}

/// 业务作用：在签名验证前封闭意图的枚举和固定宽度字段，不把缺失基线解释为当前基线。
///
/// 参数说明：
/// - intent：受管理消息上限约束、尚未信任的字段。
///
/// 返回：待验真的完整意图；未知领域、协议或摘要长度均拒绝。
pub(super) fn decode_intent(intent: protocol::ActionIntent) -> Result<Intent, Status> {
    let baseline = intent
        .baseline
        .ok_or_else(|| Status::invalid_argument("missing node baseline"))?;
    if baseline.schema != 1 {
        return Err(Status::invalid_argument("invalid node baseline schema"));
    }
    let domain = match protocol::ActionDomain::try_from(intent.domain) {
        Ok(protocol::ActionDomain::Gateway) => Domain::Gateway,
        Ok(protocol::ActionDomain::Sentinel) => Domain::Sentinel,
        Ok(protocol::ActionDomain::InterfaceGuard) => Domain::InterfaceGuard,
        _ => return Err(Status::invalid_argument("invalid node action domain")),
    };
    Ok(Intent {
        operation_id: intent.operation_id,
        proposal_epoch: intent.proposal_epoch,
        target_index: intent.target_index,
        target_count: intent.target_count,
        domain,
        node_id: intent.node_id,
        original_boot_id: intent.original_boot_id,
        baseline: NodeBaseline::from_parts(
            baseline.cluster_id,
            baseline.store_id,
            baseline.node_admission_epoch,
            &fixed(baseline.documents_sha256)?,
        ),
        base_version: intent.base_version,
        base_fingerprint: intent.base_fingerprint,
        candidate_bytes: intent.candidate_bytes,
        candidate_sha256: fixed(intent.candidate_sha256)?,
        scope: intent.scope,
        creator: intent.creator,
        reviewer: intent.reviewer,
        authority_sha256: fixed(intent.authority_sha256)?,
    })
}

/// 业务作用：移动原租约投递声明，传输层不能延长期限或改选当前接收会话。
///
/// 参数说明：
/// - delivery：已通过原合同的当前投递。
///
/// 返回：固定协议字段；会话仅复制32字节到 protobuf 的必要容器。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode_delivery(delivery: Delivery) -> protocol::ActionDelivery {
    protocol::ActionDelivery {
        issuer_node_id: delivery.issuer_node_id,
        receiving_boot_id: delivery.receiving_boot_id,
        fence: delivery.fence,
        session: delivery.session.to_vec(),
        issued_at_ms: delivery.issued_at_ms,
        expires_at_ms: delivery.expires_at_ms,
        resolve_compensation: delivery.resolve_compensation,
    }
}

/// 业务作用：拒绝会话长度歧义，业务类型对投递方向和期限的限制留给其独立合同。
///
/// 参数说明：
/// - delivery：有界但尚未验证签名的投递字段。
///
/// 返回：固定宽度正确的原声明；不授予当前会话或写入权威。
pub(super) fn decode_delivery(delivery: protocol::ActionDelivery) -> Result<Delivery, Status> {
    Ok(Delivery {
        issuer_node_id: delivery.issuer_node_id,
        receiving_boot_id: delivery.receiving_boot_id,
        fence: delivery.fence,
        session: fixed(delivery.session)?,
        issued_at_ms: delivery.issued_at_ms,
        expires_at_ms: delivery.expires_at_ms,
        resolve_compensation: delivery.resolve_compensation,
    })
}

/// 业务作用：禁止摘要与会话在字段转换时被截断或补零，避免不同 wire 内容合并为同一声明。
///
/// 参数说明：
/// - `bytes`：从当前 protobuf 消息移动得到的固定宽度字段。
///
/// 返回：精确三十二字节时成功，否则拒绝整个 offer。
fn fixed(bytes: Vec<u8>) -> Result<[u8; 32], Status> {
    bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("invalid node command fixed field"))
}

/// 业务作用：移动已经验证的基线身份，只对固定摘要作字节转换，避免复制整份元数据。
///
/// 参数说明：
/// - `value`：刚由命令合同确认格式的节点基线。
///
/// 返回：保留完整 u64 代际与 SHA-256 的类型化字段，不重新读取节点状态。
#[cfg(feature = "admin-operations-workflow-pgsql")]
fn encode_baseline(value: NodeBaseline) -> protocol::NodeBaseline {
    let documents_sha256 = value
        .documents_sha256
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).expect("validated digest text"),
                16,
            )
            .expect("validated digest")
        })
        .collect();
    protocol::NodeBaseline {
        schema: value.schema,
        cluster_id: value.cluster_id,
        store_id: value.store_id,
        node_admission_epoch: value
            .node_admission_epoch
            .parse()
            .expect("validated node epoch"),
        documents_sha256,
    }
}
