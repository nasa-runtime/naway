//! 网络边界复用原生公开条件结构，候选预检的独立签名和原 pair 条件不能被省略。

use super::{
    command::{Command, Intent, Pair},
    Reason,
};
use crate::admin::management::{material, protocol};
#[cfg(feature = "admin-operations-pgsql")]
use crate::tls::keypair::{conditions::Batch, preview::Proof};
use nasa::grpc::codegen::prost::Message;
#[cfg(feature = "admin-operations-pgsql")]
use nasa::grpc::Status;
use std::sync::Arc;

/// 业务作用：恢复独立候选预检声明，内层条件结构仅承载字段而不携带另一用途的签名。
///
/// 参数说明：
/// - `value`：受管理消息上限约束的完整预检 offer。
///
/// 返回：未获执行权的原生命令与外层签名；错域、缺条件或超量均拒绝。
pub(super) fn decode(value: protocol::MaterialPreviewOffer) -> Result<(Command, String), Reason> {
    if value.schema != 1 || value.encoded_len() > 24 * 1024 {
        return Err(Reason::Denied);
    }
    let original = value.original.ok_or(Reason::Denied)?;
    if !original.signature.is_empty() {
        return Err(Reason::Denied);
    }
    let (original, _) = material::wire::decode(original).map_err(Reason::from)?;
    let command = Command {
        intent: Arc::new(Intent {
            original: original.intent,
            proposal: value.proposal_id,
            store: value.store_id,
            epoch: value.admission_epoch,
            creator: value.creator,
            proposal_authority: value
                .proposal_authority_sha256
                .try_into()
                .map_err(|_| Reason::Denied)?,
            proposal_intent: value
                .proposal_intent_sha256
                .try_into()
                .map_err(|_| Reason::Denied)?,
            pairs: value
                .pairs
                .into_iter()
                .map(|pair| Pair {
                    certificate_etag: pair.certificate_etag,
                    material_generation: pair.material_generation,
                })
                .collect(),
            candidate_bytes: value.candidate_bytes,
            candidate_sha256: value
                .candidate_sha256
                .try_into()
                .map_err(|_| Reason::Denied)?,
        }),
        issuer: original.issuer,
        session: original.session,
        issued_at_ms: original.issued_at_ms,
        expires_at_ms: original.expires_at_ms,
    };
    command.message().map_err(|_| Reason::Denied)?;
    Ok((command, value.signature))
}

/// 业务作用：只在实际网络边界编码完整签名字段，原生投递槽不保存重复 protobuf 对象。
///
/// 参数说明：
/// - `command`：当前已经获权的完整原提案与节点批次。
/// - `signature`：绑定外层独立材料预检域的证明。
///
/// 返回：有限元数据；超过控制消息预算或非法声明均不投递秘密。
#[cfg(feature = "admin-operations-pgsql")]
pub(super) fn encode(
    command: &Command,
    signature: &str,
) -> Result<protocol::MaterialPreviewOffer, Status> {
    command
        .message()
        .map_err(|_| Status::invalid_argument("invalid material preview command"))?;
    let intent = &command.intent;
    let value = protocol::MaterialPreviewOffer {
        schema: 1,
        original: Some(material::wire::encode(&command.conditions(), "")?),
        proposal_id: intent.proposal.clone(),
        store_id: intent.store.clone(),
        admission_epoch: intent.epoch,
        creator: intent.creator.clone(),
        proposal_authority_sha256: intent.proposal_authority.to_vec(),
        proposal_intent_sha256: intent.proposal_intent.to_vec(),
        pairs: intent
            .pairs
            .iter()
            .map(|pair| protocol::MaterialPreviewPair {
                certificate_etag: pair.certificate_etag.clone(),
                material_generation: pair.material_generation.clone(),
            })
            .collect(),
        candidate_bytes: intent.candidate_bytes,
        candidate_sha256: intent.candidate_sha256.to_vec(),
        signature: signature.into(),
    };
    if value.encoded_len() > 24 * 1024 {
        return Err(Status::resource_exhausted(
            "material preview command capacity",
        ));
    }
    Ok(value)
}

/// 业务作用：成功证明必须保留全部原材料条件和完整影响，不能用新观察条件替换旧提案基线。
///
/// 参数说明：
/// - `batch`：已经解码或本机生成的完整公开条件。
/// - `intent`：原签名批次和全部原 pair 条件。
/// - `impact`：原节点声明的完整影响摘要。
///
/// 返回：数量、来源、原条件和独立影响散列全部一致时接管原生结果；异常整节点拒绝。
#[cfg(feature = "admin-operations-pgsql")]
pub(super) fn proof(batch: Batch, intent: &Intent, impact: &[u8]) -> Result<Proof, Reason> {
    material::wire::validate(&batch, &intent.original).map_err(Reason::from)?;
    if batch.entries.len() != intent.pairs.len()
        || !batch
            .entries
            .iter()
            .zip(&intent.pairs)
            .all(|(entry, pair)| {
                let group = &batch.groups[entry.group];
                group.certificate_etag == pair.certificate_etag
                    && group.material_generation.as_deref()
                        == Some(pair.material_generation.as_str())
            })
    {
        return Err(Reason::MaterialChanged);
    }
    let expected = crate::control::material::conditions::digest(&batch);
    if impact != expected {
        return Err(Reason::ImpactUnproven);
    }
    Ok(Proof {
        conditions: batch,
        impact: expected,
    })
}

/// 业务作用：把固定拒绝原因映射为独立候选预检协议，不输出底层文件或密码学诊断。
///
/// 参数说明：
/// - `reason`：实际节点的明确业务失败。
///
/// 返回：仅失败状态，成功必须另外携带完整条件和影响证明。
pub(super) fn status(reason: Reason) -> protocol::MaterialPreviewStatus {
    use protocol::MaterialPreviewStatus as Status;
    match reason {
        Reason::Unsupported => Status::Unsupported,
        Reason::Disabled => Status::Disabled,
        Reason::Unavailable => Status::Unavailable,
        Reason::Capacity => Status::Capacity,
        Reason::Expired => Status::Expired,
        Reason::Denied => Status::Denied,
        Reason::BaselineChanged => Status::BaselineChanged,
        Reason::TargetAbsent => Status::TargetAbsent,
        Reason::ExternalSource => Status::ExternalSource,
        Reason::Storage => Status::Storage,
        Reason::ImpactUnproven => Status::ImpactUnproven,
        Reason::MaterialChanged => Status::MaterialChanged,
        Reason::CandidateInvalid => Status::CandidateInvalid,
    }
}

/// 业务作用：拒绝协议未知状态，缺少原条件的回报不能被解释为预检成功。
///
/// 参数说明：
/// - `value`：远端原目标回报的状态枚举。
///
/// 返回：已知失败原因；成功和未知值不进入失败解码路径。
#[cfg(feature = "admin-operations-pgsql")]
pub(super) fn reason(value: i32) -> Option<Reason> {
    use protocol::MaterialPreviewStatus as Status;
    Some(match Status::try_from(value).ok()? {
        Status::Unsupported => Reason::Unsupported,
        Status::Disabled => Reason::Disabled,
        Status::Unavailable => Reason::Unavailable,
        Status::Capacity => Reason::Capacity,
        Status::Expired => Reason::Expired,
        Status::Denied => Reason::Denied,
        Status::BaselineChanged => Reason::BaselineChanged,
        Status::TargetAbsent => Reason::TargetAbsent,
        Status::ExternalSource => Reason::ExternalSource,
        Status::Storage => Reason::Storage,
        Status::ImpactUnproven => Reason::ImpactUnproven,
        Status::MaterialChanged => Reason::MaterialChanged,
        Status::CandidateInvalid => Reason::CandidateInvalid,
        Status::Succeeded | Status::Unspecified => return None,
    })
}
