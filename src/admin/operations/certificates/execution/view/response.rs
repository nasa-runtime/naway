//! 状态响应只借用低敏事实，材料摘要、命令载荷和文件位置不会进入HTTP编码。

use super::{Node, View};
use crate::{
    admin::{
        operations::{certificates::impact::encoding, model::Error},
        BoxBody,
    },
    control::material::{
        execution::{
            observation::{Evidence, Protocols},
            receipt::Reason,
            report::Source,
            state::{self, Direction, Stage},
        },
        node::{Intent, Selection},
    },
};
use http::{Response, StatusCode};
use nasaga_backend::SagaStepRow;
use serde::Serialize;

#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    cluster_id: &'a str,
    scope: &'a str,
    proposal_id: &'a str,
    execution_started: bool,
    execution: Option<Execution<'a>>,
}

#[derive(Serialize)]
struct Execution<'a> {
    operation_id: &'a str,
    impact_id: &'a str,
    lifecycle: &'a str,
    terminal: Option<&'a str>,
    business_status: &'a str,
    control_state: &'a str,
    direction: &'a str,
    current_step: Option<&'a str>,
    instance_version: String,
    control_version: String,
    target_count: u32,
    node_count: usize,
    reported_count: usize,
    released_count: usize,
    nodes: Vec<NodeView<'a>>,
    steps: Vec<Step<'a>>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Serialize)]
struct Step<'a> {
    name: &'a str,
    ordinal: u32,
    forward: &'a str,
    compensation: &'a str,
    resolution: &'a str,
    cancel: &'a str,
}

#[derive(Serialize)]
struct NodeView<'a> {
    node_id: &'a str,
    node_index: usize,
    original_boot_id: &'a str,
    selections: &'a [Selection],
    sources: &'a crate::tls::keypair::conditions::Batch,
    reported: bool,
    report_revision: Option<String>,
    stage: Option<Stage>,
    direction: Option<Direction>,
    protection: Option<Reason>,
    required_protocols: Option<&'a [Vec<Protocols>]>,
    generations: Option<&'a [Source]>,
    effects: [Effect<'a>; 4],
    released: bool,
}

#[derive(Serialize)]
struct Effect<'a> {
    step: &'static str,
    direction: &'static str,
    state: &'static str,
    reason: Option<Reason>,
    evidence: Option<&'a Evidence>,
}

impl View {
    /// 业务作用：在唯一输出边界编码完整原节点状态，缺报告、受理未决和稳定收据保持不同语义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：有界且不可缓存的完整响应；编码超量整份拒绝，不输出秘密摘要或内部载荷。
    pub(in crate::admin::operations::certificates::execution) fn response(
        &self,
    ) -> Result<Response<BoxBody>, Error> {
        let execution = self
            .operation
            .as_ref()
            .map(|operation| {
                let first = &operation.frozen.nodes[0];
                Ok::<_, Error>(Execution {
                    operation_id: &first.operation_id,
                    impact_id: &first.impact_id,
                    lifecycle: &operation.lifecycle,
                    terminal: operation.terminal.as_deref(),
                    business_status: operation.instance.status.as_str(),
                    control_state: operation.instance.control_state.as_str(),
                    direction: operation.instance.direction.as_str(),
                    current_step: operation
                        .instance
                        .current_step
                        .as_ref()
                        .map(|step| step.as_str()),
                    instance_version: operation.instance.version.to_string(),
                    control_version: operation.instance.control_version.to_string(),
                    target_count: first.target_count,
                    node_count: operation.nodes.len(),
                    reported_count: operation
                        .nodes
                        .iter()
                        .filter(|node| node.report.is_some())
                        .count(),
                    released_count: operation.nodes.iter().filter(|node| node.released).count(),
                    nodes: operation
                        .nodes
                        .iter()
                        .zip(&operation.frozen.nodes)
                        .enumerate()
                        .map(|(index, (node, intent))| {
                            node_view(node, intent, index, operation.nodes.len())
                        })
                        .collect::<Result<_, _>>()?,
                    steps: operation.steps.iter().map(step_view).collect(),
                    created_at_ms: operation.created,
                    updated_at_ms: operation.updated,
                })
            })
            .transpose()?;
        encode(&Envelope {
            schema_version: 1,
            cluster_id: &self.cluster,
            scope: &self.scope,
            proposal_id: &self.proposal,
            execution_started: execution.is_some(),
            execution,
        })
    }
}

/// 业务作用：把原报告的四个效果分别投影，后来补偿成功不能覆盖原正向未知。
///
/// 参数说明：
/// - `node`：已通过完整报告及共享身份检查的持久节点事实。
/// - `intent`：原完整节点意图，提供逻辑目标和来源分母。
/// - `index`：原物理节点序号。
/// - `count`：原物理节点总数。
///
/// 返回：借用式低敏投影；协议和材料代只来自原报告，无报告时明确为空。
fn node_view<'a>(
    node: &'a Node,
    intent: &'a Intent,
    index: usize,
    count: usize,
) -> Result<NodeView<'a>, Error> {
    let position = crate::control::material::execution::position::Position {
        index: index as u32,
        count: count as u32,
    };
    let mut effects = [
        ("prepare", "forward"),
        ("apply", "forward"),
        ("prepare", "compensation"),
        ("apply", "compensation"),
    ]
    .map(|(step, direction)| Effect {
        step,
        direction,
        state: "unconfirmed",
        reason: None,
        evidence: None,
    });
    if let Some(report) = &node.report {
        for admission in &report.admissions {
            let identity = admission
                .validate(intent, position)
                .map_err(|_| Error::Unavailable)?;
            let slot =
                state::slot(admission.step(), identity.phase).map_err(|_| Error::Unavailable)?;
            effects[slot].state = "admitted";
        }
        for receipt in &report.receipts {
            let slot = state::slot(
                receipt.step(),
                receipt
                    .phase(intent, position)
                    .map_err(|_| Error::Unavailable)?,
            )
            .map_err(|_| Error::Unavailable)?;
            effects[slot].state = match receipt.outcome() {
                crate::control::actions::receipt::Outcome::Succeeded => "succeeded",
                crate::control::actions::receipt::Outcome::Rejected => "rejected",
                crate::control::actions::receipt::Outcome::Halted => "halted",
            };
            effects[slot].reason = receipt.reason();
            effects[slot].evidence = receipt.evidence();
        }
        if let Some(absence) = &report.absence {
            let slot = state::slot(absence.step(), nasa::saga::StepPhase::Execute)
                .map_err(|_| Error::Unavailable)?;
            effects[slot].state = "not_admitted";
        }
    }
    Ok(NodeView {
        node_id: &intent.node_id,
        node_index: index,
        original_boot_id: &intent.original_boot_id,
        selections: &intent.selections,
        sources: &intent.conditions,
        reported: node.report.is_some(),
        report_revision: node
            .report
            .as_ref()
            .map(|report| report.revision.to_string()),
        stage: node.report.as_ref().map(|report| report.stage),
        direction: node.report.as_ref().and_then(|report| report.direction),
        protection: node.report.as_ref().and_then(|report| report.protection),
        required_protocols: node
            .report
            .as_ref()
            .map(|report| report.protocols.as_slice()),
        generations: node.report.as_ref().map(|report| report.sources.as_slice()),
        effects,
        released: node.released,
    })
}

/// 业务作用：只交付NASA当前步骤的有限状态，原受理未决与工作流未知分别显示。
///
/// 参数说明：
/// - `step`：同一只读快照内的完整原定义步骤。
///
/// 返回：无命令、错误载荷或事件正文的借用投影。
fn step_view(step: &SagaStepRow) -> Step<'_> {
    Step {
        name: step.step.as_str(),
        ordinal: step.ordinal,
        forward: step.forward_status.as_str(),
        compensation: step.compensation_status.as_str(),
        resolution: step.resolution_status.as_str(),
        cancel: step.cancel_status.as_str(),
    }
}

/// 业务作用：按全批证明和全部原报告的总上界编码一次，超量不能返回缺少节点的成功视图。
///
/// 参数说明：
/// - `value`：已经验证的公开借用投影。
///
/// 返回：完整私有JSON或容量错误；不建立中间Value树。
pub(in crate::admin::operations::certificates::execution) fn encode(
    value: &impl Serialize,
) -> Result<Response<BoxBody>, Error> {
    let bytes = encoding::bytes(
        value,
        crate::config::operations::certificates::impact::MAX_PROOF_BYTES + 128 * 128 * 1024 + 65536,
    )?;
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(crate::admin::full_body(bytes.into()))
        .map_err(|_| Error::Unavailable)
}
