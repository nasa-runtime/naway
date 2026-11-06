//! 完整材料结果直接转换原生公开事实，稳定结论由原收据投影而不接受单独状态字符串。

#[cfg(feature = "admin-operations-workflow-pgsql")]
use super::fields;
use super::{report_fields as values, wire};
#[cfg(feature = "admin-operations-workflow-pgsql")]
use crate::{
    admin::management::actions::fields as common,
    control::material::execution::{
        absence::Absence, observation::Evidence, receipt::Expected, release::Proof, report::Source,
    },
};
use crate::{
    admin::management::{material::wire as material, protocol, MAX_MESSAGE},
    control::{
        actions::receipt::Outcome,
        material::{
            execution::{
                command::Step, effect::Admission, position::Position, receipt::Receipt,
                report::Report,
            },
            node::Intent,
        },
    },
};
use nasa::grpc::{codegen::prost::Message, Status};
#[cfg(feature = "admin-operations-workflow-pgsql")]
use nasa::saga::StepPhase;
#[cfg(feature = "admin-operations-workflow-pgsql")]
use std::sync::Arc;

/// 业务作用：在网络边界借用完整原报告，所有历史受理和收据与同一原head一起交付。
///
/// 参数说明：
/// - `report`：本机已经原子读取的公开材料事实。
/// - `intent`：原任务冻结的完整节点意图。
/// - `position`：原物理节点位置与总数。
///
/// 返回：32KiB总预算内的完整报告；任何缺项、矛盾或超量整份拒绝。
pub(super) fn encode(
    report: &Report,
    intent: &Intent,
    position: Position,
) -> Result<protocol::MaterialExecutionReport, Status> {
    report
        .validate(intent, position)
        .map_err(|_| values::invalid())?;
    let value = protocol::MaterialExecutionReport {
        schema: report.schema,
        revision: report.revision,
        position: Some(protocol::MaterialActionPosition {
            index: position.index,
            count: position.count,
        }),
        intent_sha256: report.intent_sha256.to_vec(),
        fence: report.fence,
        stage: values::stage(report.stage),
        prepared: report.prepared,
        direction: values::direction(report.direction),
        sources: report
            .sources
            .iter()
            .zip(&report.protocols)
            .map(|(source, protocols)| protocol::MaterialExecutionSource {
                source_id: source.source_id.clone(),
                forward: source.forward.clone(),
                backward: source.backward.clone(),
                protocols: protocols.iter().copied().map(values::protocols).collect(),
            })
            .collect(),
        admissions: report
            .admissions
            .iter()
            .map(|admission| encode_admission(admission, intent, position))
            .collect::<Result<_, _>>()?,
        receipts: report
            .receipts
            .iter()
            .map(|receipt| encode_receipt(receipt, intent, position))
            .collect::<Result<_, _>>()?,
        absence: report
            .absence
            .as_ref()
            .map(|proof| protocol::MaterialExecutionAbsence {
                step: match proof.step() {
                    Step::Prepare => protocol::MaterialExecutionStep::Prepare,
                    Step::Apply => protocol::MaterialExecutionStep::Apply,
                } as i32,
                effect_id: proof.effect_id().into(),
                definition_digest: proof.definition_digest().into(),
            }),
        protection: values::reason(report.protection),
        release: report
            .release
            .as_ref()
            .map(|proof| protocol::MaterialExecutionRelease {
                definition_digest: proof.definition_digest().into(),
                terminal: values::terminal(proof.terminal()),
            }),
    };
    require_capacity(&value)?;
    Ok(value)
}

/// 业务作用：只在完整报告与发行端原意图一致时恢复历史事实，网络状态不直接推进NASA。
///
/// 参数说明：
/// - `value`：同一原head的完整类型化报告。
/// - `intent`：发行端保留的原节点意图，不能由报告替换。
/// - `position`：发行端冻结的物理节点位置。
///
/// 返回：已经通过原生合同的完整报告；调用者仍须持久化后才能确认接收。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(super) fn decode(
    value: protocol::MaterialExecutionReport,
    intent: &Intent,
    position: Position,
) -> Result<Report, Status> {
    require_capacity(&value)?;
    let received_position = fields::decode_position(value.position)?;
    let intent_sha256 = common::fixed(value.intent_sha256)?;
    // 原完整意图由共享任务所有，报告只能绑定它；任何错位都在恢复历史身份之前拒绝。
    if received_position != position
        || intent_sha256
            != position
                .fingerprint(intent)
                .map_err(|_| values::invalid())?
        || value.admissions.len() > 2
        || value.admissions.len() + value.receipts.len() > 4
        || value.sources.len() > intent.conditions.groups.len()
    {
        return Err(values::invalid());
    }
    let mut sources = Vec::with_capacity(value.sources.len());
    let mut protocols = Vec::with_capacity(value.sources.len());
    for source in value.sources {
        protocols.push(
            source
                .protocols
                .into_iter()
                .map(values::native_protocols)
                .collect::<Result<Vec<_>, _>>()?,
        );
        sources.push(Source {
            source_id: source.source_id,
            forward: source.forward,
            backward: source.backward,
        });
    }
    let mut report = Report {
        schema: value.schema,
        revision: value.revision,
        position,
        intent_sha256,
        fence: value.fence,
        stage: values::native_stage(value.stage)?,
        prepared: value.prepared,
        direction: values::native_direction(value.direction)?,
        sources,
        protocols,
        admissions: value
            .admissions
            .into_iter()
            .map(|identity| {
                Admission::restore(intent, position, wire::decode_identity(identity)?)
                    .map_err(|_| values::invalid())
            })
            .collect::<Result<_, _>>()?,
        receipts: Vec::with_capacity(value.receipts.len()),
        absence: value
            .absence
            .map(|proof| {
                let step = match protocol::MaterialExecutionStep::try_from(proof.step) {
                    Ok(protocol::MaterialExecutionStep::Prepare) => Step::Prepare,
                    Ok(protocol::MaterialExecutionStep::Apply) => Step::Apply,
                    _ => return Err(values::invalid()),
                };
                Absence::restore(
                    intent,
                    position,
                    step,
                    proof.effect_id,
                    proof.definition_digest,
                )
                .map_err(|_| values::invalid())
            })
            .transpose()?,
        protection: values::native_reason(value.protection)?,
        release: value
            .release
            .map(|proof| {
                Proof::restore(
                    intent,
                    position,
                    proof.definition_digest,
                    values::native_terminal(proof.terminal)?,
                )
                .map_err(|_| values::invalid())
            })
            .transpose()?,
    };
    let forward: Vec<_> = report
        .sources
        .iter()
        .map(|source| source.forward.as_str())
        .collect();
    let backward: Vec<_> = report
        .sources
        .iter()
        .filter_map(|source| source.backward.as_deref())
        .collect();
    for receipt in value.receipts {
        let admission = Admission::restore(
            intent,
            position,
            wire::decode_identity(receipt.admission.ok_or_else(values::invalid)?)?,
        )
        .map_err(|_| values::invalid())?;
        let phase = admission
            .validate(intent, position)
            .map_err(|_| values::invalid())?
            .phase;
        let expected = Expected {
            intent,
            position,
            generations: if phase == StepPhase::Compensate {
                &backward
            } else {
                &forward
            },
            protocols: &report.protocols,
        };
        report.receipts.push(Arc::new(decode_receipt(
            receipt.outcome,
            receipt.reason,
            receipt.evidence,
            admission,
            &expected,
        )?));
    }
    report
        .validate(intent, position)
        .map_err(|_| values::invalid())?;
    Ok(report)
}

/// 业务作用：直接编码历史受理身份，不制造带当前会话或期限的执行命令。
///
/// 参数说明：
/// - `admission`：原报告中的历史业务受理。
/// - `intent`：完整原意图。
/// - `position`：原节点物理位置。
///
/// 返回：保留原attempt及恢复操作的有界身份；无法派生时拒绝。
fn encode_admission(
    admission: &Admission,
    intent: &Intent,
    position: Position,
) -> Result<protocol::ActionIdentity, Status> {
    wire::encode_identity(
        &admission
            .envelope(intent, position)
            .map_err(|_| values::invalid())?,
    )
}

/// 业务作用：交付原稳定收据及完整实际监听观察，文件方向本身不能被编码为应用成功。
///
/// 参数说明：
/// - `receipt`：报告已经验证的原稳定事实。
/// - `intent`：完整原意图。
/// - `position`：原物理节点位置。
///
/// 返回：类型化历史收据；证据无法完整表达时拒绝。
fn encode_receipt(
    receipt: &Receipt,
    intent: &Intent,
    position: Position,
) -> Result<protocol::MaterialExecutionReceipt, Status> {
    Ok(protocol::MaterialExecutionReceipt {
        admission: Some(encode_admission(receipt.admission(), intent, position)?),
        outcome: match receipt.outcome() {
            Outcome::Succeeded => protocol::ActionOutcome::Succeeded,
            Outcome::Rejected => protocol::ActionOutcome::Rejected,
            Outcome::Halted => protocol::ActionOutcome::Halted,
        } as i32,
        reason: values::reason(receipt.reason()),
        evidence: receipt
            .evidence()
            .map(|evidence| -> Result<_, Status> {
                Ok(protocol::MaterialExecutionEvidence {
                    boot_id: evidence.boot_id().into(),
                    observed: Some(
                        material::encode_observed(evidence.observed())
                            .map_err(|_| values::invalid())?,
                    ),
                })
            })
            .transpose()?,
    })
}

/// 业务作用：按原方向完整验证网络收据，Pending或缺少实际协议证据不能结算任何效果。
///
/// 参数说明：
/// - `outcome`：传输中的稳定结果枚举。
/// - `reason`：原低敏拒绝或保护原因。
/// - `evidence`：同一真实boot的完整安装观察。
/// - `admission`：原持久业务身份。
/// - `expected`：同一原报告的方向、代与协议分母。
///
/// 返回：完整原生收据；不自相一致、未知枚举或证据缺项拒绝。
#[cfg(feature = "admin-operations-workflow-pgsql")]
fn decode_receipt(
    outcome: i32,
    reason: i32,
    evidence: Option<protocol::MaterialExecutionEvidence>,
    admission: Admission,
    expected: &Expected<'_>,
) -> Result<Receipt, Status> {
    let outcome = match protocol::ActionOutcome::try_from(outcome) {
        Ok(protocol::ActionOutcome::Succeeded) => Outcome::Succeeded,
        Ok(protocol::ActionOutcome::Rejected) => Outcome::Rejected,
        Ok(protocol::ActionOutcome::Halted) => Outcome::Halted,
        _ => return Err(values::invalid()),
    };
    let evidence = evidence
        .map(|evidence| {
            let observed =
                material::decode_observed(evidence.observed.ok_or_else(values::invalid)?)
                    .map_err(|_| values::invalid())?;
            Evidence::new(
                evidence.boot_id,
                expected.intent,
                expected.generations,
                expected.protocols,
                observed,
            )
            .map(Arc::new)
            .map_err(|_| values::invalid())
        })
        .transpose()?;
    Receipt::settle(
        admission,
        expected,
        outcome,
        values::native_reason(reason)?,
        evidence,
    )
    .map_err(|_| values::invalid())
}

/// 业务作用：维持原管理通道总预算，完整事实无法容纳时拒绝整份而不省略历史或协议。
///
/// 参数说明：
/// - `value`：实际待传输或已收到的完整报告。
///
/// 返回：已知schema且实际编码不超限时成功；其它情况拒绝。
fn require_capacity(value: &protocol::MaterialExecutionReport) -> Result<(), Status> {
    if value.schema != 1 || value.encoded_len() > MAX_MESSAGE {
        return Err(values::invalid());
    }
    Ok(())
}
