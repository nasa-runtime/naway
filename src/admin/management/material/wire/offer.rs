//! 原始索引和节点基线直接进入有界协议，接收时不补齐任何默认权威。

use super::{native_target, target};
use crate::{
    admin::management::{
        baseline,
        material::{
            Reason,
            command::{Command, Intent, Query},
        },
        protocol,
    },
    control::baseline::NodeBaseline,
};
use nasa::grpc::{Status, codegen::prost::Message};

/// 业务作用：在验签前按原生字段恢复整批意图，非法字段不进入文件读取或任务名额。
///
/// 参数说明：
/// - `value`：同一受信连接接收的材料条件声明。
///
/// 返回：完整命令和独立签名；字段缺失、未知身份、超限或无效基线均拒绝。
pub(in crate::admin::management) fn decode(
    value: protocol::MaterialConditionsOffer,
) -> Result<(Command, String), Reason> {
    if value.schema != 1 || value.encoded_len() > 24 * 1024 {
        return Err(Reason::Denied);
    }
    let baseline = value.baseline.ok_or(Reason::Denied)?;
    if baseline.schema != 1 {
        return Err(Reason::Denied);
    }
    let digest: [u8; 32] = baseline
        .documents_sha256
        .try_into()
        .map_err(|_| Reason::Denied)?;
    let mut indices = Vec::with_capacity(value.targets.len());
    let mut targets = Vec::with_capacity(value.targets.len());
    for value in value.targets {
        indices.push(value.index);
        targets.push(native_target(value.target)?);
    }
    let command = Command {
        intent: std::sync::Arc::new(Intent {
            query_kind: if value.installations {
                Query::Installations
            } else {
                Query::Conditions
            },
            query: value.query_id,
            count: value.target_count,
            indices,
            targets,
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
            scope: value.scope,
            principal: value.principal,
            authority: value
                .authority_sha256
                .try_into()
                .map_err(|_| Reason::Denied)?,
        }),
        issuer: value.issuer_node_id,
        session: value.session.try_into().map_err(|_| Reason::Denied)?,
        issued_at_ms: value.issued_at_ms,
        expires_at_ms: value.expires_at_ms,
    };
    command.message().map_err(|_| Reason::Denied)?;
    Ok((command, value.signature))
}

/// 业务作用：在远程边界生成一次有限声明，消息只包含原逻辑目标与基线。
///
/// 参数说明：
/// - `command`：当前已获权并签名的完整命令。
/// - `signature`：绑定全部字段的材料条件证明。
///
/// 返回：保留原索引与分母的协议消息；任何无效或超量命令拒绝。
pub(in crate::admin::management) fn encode(
    command: &Command,
    signature: &str,
) -> Result<protocol::MaterialConditionsOffer, Status> {
    command
        .message()
        .map_err(|_| Status::invalid_argument("invalid material conditions command"))?;
    let intent = &command.intent;
    let value = protocol::MaterialConditionsOffer {
        installations: intent.query_kind == Query::Installations,
        schema: 1,
        query_id: intent.query.clone(),
        target_count: intent.count,
        targets: intent
            .indices
            .iter()
            .zip(&intent.targets)
            .map(|(index, value)| protocol::MaterialConditionsTarget {
                index: *index,
                target: Some(target(value.clone())),
            })
            .collect(),
        node_id: intent.node.clone(),
        boot_id: intent.boot.clone(),
        baseline: Some(
            baseline::encode(&intent.baseline)
                .ok_or_else(|| Status::invalid_argument("invalid material conditions baseline"))?,
        ),
        base_version: intent.version,
        base_fingerprint: intent.fingerprint,
        scope: intent.scope.clone(),
        principal: intent.principal.clone(),
        authority_sha256: intent.authority.to_vec(),
        issuer_node_id: command.issuer.clone(),
        session: command.session.to_vec(),
        issued_at_ms: command.issued_at_ms,
        expires_at_ms: command.expires_at_ms,
        signature: signature.to_owned(),
    };
    if value.encoded_len() > 24 * 1024 {
        return Err(Status::resource_exhausted(
            "material conditions command capacity",
        ));
    }
    Ok(value)
}
