//! 预览传输边界只移动类型字段，原文与差异不会嵌套为 JSON 消息。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::node::within_budget;
use super::{
    command::{Command, Intent},
    Reason,
};
use crate::{
    admin::{
        diff::model::{Changes, Summary},
        management::protocol,
    },
    control::{actions::domain::Domain, baseline::NodeBaseline},
};
#[cfg(feature = "admin-operations-workflow-pgsql")]
use nasa::grpc::Status;

/// 业务作用：把受消息字节上限保护的预览声明转换为原生命令，并重新核对全部字段合同。
///
/// 参数说明：
/// - `value`：来自当前管理通道的有限预览 offer。
///
/// 返回：移动原有分配的命令与签名；缺失基线、未知领域或非法固定长度拒绝。
pub(super) fn decode(value: protocol::PreviewOffer) -> Result<(Command, String), Reason> {
    if value.schema != 1 {
        return Err(Reason::Denied);
    }
    let baseline = value.baseline.ok_or(Reason::Denied)?;
    let digest: [u8; 32] = baseline
        .documents_sha256
        .try_into()
        .map_err(|_| Reason::Denied)?;
    let command = Command {
        intent: Intent {
            proposal: value.proposal,
            epoch: value.epoch,
            index: value.target_index,
            count: value.target_count,
            domain: match protocol::ActionDomain::try_from(value.domain) {
                Ok(protocol::ActionDomain::Gateway) => Domain::Gateway,
                Ok(protocol::ActionDomain::Sentinel) => Domain::Sentinel,
                Ok(protocol::ActionDomain::InterfaceGuard) => Domain::InterfaceGuard,
                _ => return Err(Reason::Denied),
            },
            node: value.node_id,
            boot: value.boot_id,
            baseline: NodeBaseline::from_parts(
                baseline.cluster_id,
                baseline.store_id,
                baseline.node_admission_epoch,
                &digest,
            ),
            version: value.base_version,
            fingerprint: value.base_fingerprint,
            candidate_bytes: value.candidate_bytes,
            candidate_sha256: value
                .candidate_sha256
                .try_into()
                .map_err(|_| Reason::Denied)?,
            scope: value.scope,
            creator: value.creator,
            principal: value.principal,
            authority: value
                .authority_sha256
                .try_into()
                .map_err(|_| Reason::Denied)?,
        },
        issuer: value.issuer_node_id,
        session: value.session.try_into().map_err(|_| Reason::Denied)?,
        issued_at_ms: value.issued_at_ms,
        expires_at_ms: value.expires_at_ms,
    };
    if baseline.schema != 1 || command.message().is_err() {
        return Err(Reason::Denied);
    }
    Ok((command, value.signature))
}

/// 业务作用：仅在远程交付边界编码已签名命令的有限元数据，候选原文仍由独立共享槽持有。
///
/// 参数说明：
/// - `command`：原生且完整验证的预览命令。
/// - `signature`：与该命令完整消息摘要绑定的证明。
///
/// 返回：有限协议消息；本机路径不调用此转换。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn encode(command: &Command, signature: &str) -> Result<protocol::PreviewOffer, Status> {
    command
        .message()
        .map_err(|_| Status::invalid_argument("invalid preview command"))?;
    let intent = &command.intent;
    let baseline = crate::admin::management::baseline::encode(&intent.baseline)
        .ok_or_else(|| Status::invalid_argument("invalid preview baseline"))?;
    Ok(protocol::PreviewOffer {
        schema: 1,
        proposal: intent.proposal.clone(),
        epoch: intent.epoch,
        target_index: intent.index,
        target_count: intent.count,
        domain: match intent.domain {
            Domain::Gateway => protocol::ActionDomain::Gateway,
            Domain::Sentinel => protocol::ActionDomain::Sentinel,
            Domain::InterfaceGuard => protocol::ActionDomain::InterfaceGuard,
        } as i32,
        node_id: intent.node.clone(),
        boot_id: intent.boot.clone(),
        baseline: Some(baseline),
        base_version: intent.version,
        base_fingerprint: intent.fingerprint,
        candidate_bytes: intent.candidate_bytes,
        candidate_sha256: intent.candidate_sha256.to_vec(),
        scope: intent.scope.clone(),
        creator: intent.creator.clone(),
        principal: intent.principal.clone(),
        authority_sha256: intent.authority.to_vec(),
        issuer_node_id: command.issuer.clone(),
        session: command.session.to_vec(),
        issued_at_ms: command.issued_at_ms,
        expires_at_ms: command.expires_at_ms,
        signature: signature.to_owned(),
    })
}

/// 业务作用：将完整原生差异移入传输响应，不复制对象身份字符串。
///
/// 参数说明：
/// - `summary`：已完成实际构建与结果预算核对的摘要。
///
/// 返回：五个领域均存在的有限消息，不包含配置正文或秘密。
pub(super) fn summary(summary: Summary) -> protocol::PreviewSummary {
    protocol::PreviewSummary {
        current_version: summary.current_version,
        candidate_version: summary.candidate_version,
        routes: Some(changes(summary.routes)),
        upstreams: Some(changes(summary.upstreams)),
        listeners: Some(changes(summary.listeners)),
        sentinel: Some(changes(summary.sentinel)),
        interface_guard: Some(changes(summary.interface_guard)),
    }
}

/// 业务作用：从完整结果消息恢复原生差异，缺失领域或错误版本不能冒充空变化。
///
/// 参数说明：
/// - `value`：已受管理消息大小限制的完整摘要。
/// - `version`：原投递冻结的活动配置版本。
///
/// 返回：版本与全部容量门成立的原生摘要，异常拒绝且不填补缺失领域。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn decode_summary(
    value: protocol::PreviewSummary,
    version: u64,
) -> Result<Summary, Status> {
    let missing = || Status::invalid_argument("preview result incomplete");
    let summary = Summary {
        current_version: value.current_version,
        candidate_version: value.candidate_version,
        routes: native_changes(value.routes.ok_or_else(missing)?),
        upstreams: native_changes(value.upstreams.ok_or_else(missing)?),
        listeners: native_changes(value.listeners.ok_or_else(missing)?),
        sentinel: native_changes(value.sentinel.ok_or_else(missing)?),
        interface_guard: native_changes(value.interface_guard.ok_or_else(missing)?),
    };
    if summary.current_version != version
        || version.checked_add(1) != Some(summary.candidate_version)
        || !within_budget(&summary)
    {
        return Err(Status::invalid_argument("preview result contract differs"));
    }
    Ok(summary)
}

/// 业务作用：在网络边界移动同一领域的增删改数组，保留原有排序和字符串分配。
///
/// 参数说明：
/// - `value`：一个完整领域的原生身份列表。
///
/// 返回：直接持有原数组的协议值，不重新编码或克隆列表。
fn changes(value: Changes) -> protocol::PreviewChanges {
    protocol::PreviewChanges {
        added: value.added,
        removed: value.removed,
        changed: value.changed,
    }
}

/// 业务作用：让接收结果恢复原生列表时保持原分配，后续只在 HTTP 边界编码。
///
/// 参数说明：
/// - `value`：单领域完整协议列表。
///
/// 返回：移动数组的原生领域，外层仍须统一验证版本、身份与容量。
#[cfg(feature = "admin-operations-workflow-pgsql")]
fn native_changes(value: protocol::PreviewChanges) -> Changes {
    Changes {
        added: value.added,
        removed: value.removed,
        changed: value.changed,
    }
}

/// 业务作用：将节点低敏失败类别映射为固定协议值，不发送内部错误链。
///
/// 参数说明：
/// - `reason`：当前工作明确观测到的有限拒绝原因。
///
/// 返回：对应传输状态；成功只能由完整摘要路径另外产生。
pub(super) fn status(reason: Reason) -> protocol::PreviewStatus {
    match reason {
        #[cfg(feature = "admin-operations-workflow-pgsql")]
        Reason::Unsupported => protocol::PreviewStatus::Unsupported,
        Reason::Disabled => protocol::PreviewStatus::Disabled,
        Reason::Unavailable => protocol::PreviewStatus::Unavailable,
        Reason::Capacity => protocol::PreviewStatus::Capacity,
        Reason::Expired => protocol::PreviewStatus::Expired,
        Reason::Denied => protocol::PreviewStatus::Denied,
        Reason::BaselineChanged => protocol::PreviewStatus::BaselineChanged,
        Reason::CandidateInvalid => protocol::PreviewStatus::CandidateInvalid,
    }
}

/// 业务作用：严格解释远端失败类别，未知协议值不能被当作成功或零差异。
///
/// 参数说明：
/// - `value`：完整已绑定结果的状态枚举。
///
/// 返回：已知失败类别；成功或未知值由外层按完整摘要合同裁决。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn reason(value: i32) -> Option<Reason> {
    match protocol::PreviewStatus::try_from(value).ok()? {
        protocol::PreviewStatus::Unsupported => Some(Reason::Unsupported),
        protocol::PreviewStatus::Disabled => Some(Reason::Disabled),
        protocol::PreviewStatus::Unavailable => Some(Reason::Unavailable),
        protocol::PreviewStatus::Capacity => Some(Reason::Capacity),
        protocol::PreviewStatus::Expired => Some(Reason::Expired),
        protocol::PreviewStatus::Denied => Some(Reason::Denied),
        protocol::PreviewStatus::BaselineChanged => Some(Reason::BaselineChanged),
        protocol::PreviewStatus::CandidateInvalid => Some(Reason::CandidateInvalid),
        protocol::PreviewStatus::Unspecified | protocol::PreviewStatus::Succeeded => None,
    }
}
