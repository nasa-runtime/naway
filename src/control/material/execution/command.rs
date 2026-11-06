//! 材料命令独立绑定完整审批意图、原节点步骤和当前投递，配置动作签名不能复用。

use super::{definition, position::Position};
use crate::control::{actions::command::Delivery, material::node::Intent};
use anyhow::{ensure, Result};
use nasa::saga::{EffectId, StepPhase};
use nasaga_runtime_core::VerifiedIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

/// 独立材料工作流的一次原生投递；完整审批意图共享保存，正文不进入命令元数据。
#[derive(Clone)]
pub(crate) struct Command {
    pub schema: u32,
    pub envelope: nasaga_runtime_core::SagaCommandEnvelope,
    pub intent: Arc<Intent>,
    pub position: Position,
    pub delivery: Delivery,
}

/// 每个物理节点只执行一次整批准备和应用，逻辑目标数量不改变步骤数量。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Step {
    Prepare,
    Apply,
}

/// 已由NASA重新派生的效果身份及待验签消息，不代表当前租约或本机权限仍成立。
pub(crate) struct Validated {
    identity: VerifiedIdentity,
    step: Step,
    intent_sha256: [u8; 32],
    resolve_compensation: bool,
    message: String,
}

impl Command {
    /// 业务作用：按NASA重新派生命令身份，并将原节点整批意图与独立材料工作流绑定后交给验签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原身份、步骤和规范签名消息；格式、步骤、定义或期限跨度不符拒绝，不授予当前写权。
    pub(crate) fn validate(&self) -> Result<Validated> {
        let intent_sha256 = self.position.fingerprint(&self.intent)?;
        let definition = definition::cached(self.position.count as usize)?;
        // 有限窗口约束单次签名的可重放时间，部署不能通过延长期限把旧会话变成长期写权。
        ensure!(
            self.schema == 1
                && self.envelope.payload.is_none()
                && self.envelope.raw_payload.is_none()
                && crate::config::operations::token(&self.delivery.issuer_node_id, 128)
                && crate::config::operations::token(&self.delivery.receiving_boot_id, 128)
                && (1..=i64::MAX as u64).contains(&self.delivery.fence)
                && self.delivery.issued_at_ms > 0
                && self.delivery.expires_at_ms <= i64::MAX as u64
                && self
                    .delivery
                    .expires_at_ms
                    .checked_sub(self.delivery.issued_at_ms)
                    .is_some_and(|span| (1..=20_000).contains(&span)),
            "invalid material execution delivery"
        );
        // 必须由NASA复验原effect与command，持久去重槽不能采信发行者自报的派生身份。
        let identity = self.envelope.verified()?;
        ensure!(
            identity.saga_id.as_str() == self.intent.operation_id
                && identity.tenant.as_str() == self.intent.baseline.cluster_id
                && identity.workflow == *definition.name()
                && identity.definition_version == definition.version()
                && identity.definition_digest == definition.digest()
                && identity.phase != StepPhase::Cancel
                && (!self.delivery.resolve_compensation || identity.phase == StepPhase::Resolve),
            "material execution workflow differs"
        );
        let step = if identity.step.as_str() == Step::Prepare.name(self.position) {
            Step::Prepare
        } else if identity.step.as_str() == Step::Apply.name(self.position) {
            Step::Apply
        } else {
            anyhow::bail!("material execution node step differs");
        };
        let mut hash = Sha256::new();
        hash.update(b"naway-material-execution-command\0");
        hash.update(self.schema.to_be_bytes());
        for bytes in [
            intent_sha256.as_slice(),
            self.envelope.saga_id.as_bytes(),
            self.envelope.tenant_id.as_bytes(),
            self.envelope.workflow.as_bytes(),
            &self.envelope.definition_version.to_be_bytes(),
            self.envelope.definition_digest.as_bytes(),
            self.envelope.step.as_bytes(),
            self.envelope.phase.as_bytes(),
            &self.envelope.attempt.to_be_bytes(),
            self.envelope.effect_id.as_bytes(),
            self.envelope.command_id.as_bytes(),
            &[u8::from(self.envelope.recovery_operation_id.is_some())],
            self.envelope
                .recovery_operation_id
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            self.delivery.issuer_node_id.as_bytes(),
            self.delivery.receiving_boot_id.as_bytes(),
            &self.delivery.fence.to_be_bytes(),
            &self.delivery.session,
            &self.delivery.issued_at_ms.to_be_bytes(),
            &self.delivery.expires_at_ms.to_be_bytes(),
            &[u8::from(self.delivery.resolve_compensation)],
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        let mut message = String::with_capacity(64);
        for byte in hash.finalize() {
            message.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            message.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        Ok(Validated {
            identity,
            step,
            intent_sha256,
            resolve_compensation: self.delivery.resolve_compensation,
            message,
        })
    }
}

impl Step {
    /// 业务作用：按原节点位置派生唯一步骤名，多个逻辑材料目标共用一次节点准备或决定。
    ///
    /// 参数说明：
    /// - `position`：已经校验的冻结节点位置。
    ///
    /// 返回：独立材料定义中的有限步骤名，不从节点名或文件名拼接。
    pub(crate) fn name(self, position: Position) -> String {
        let phase = match self {
            Self::Prepare => "prepare",
            Self::Apply => "apply",
        };
        format!("{phase}-{:03}", position.index)
    }
}

impl Validated {
    /// 业务作用：让受理与收据只使用同次NASA已证身份，不能重新解释原网络字段。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原命令身份的借用，不复制候选或完整审批树。
    pub(crate) fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }

    /// 业务作用：为节点执行器区分整批准备与整批文件决定，phase本身不能代替业务步骤。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已经绑定原节点索引的有限步骤。
    pub(crate) fn step(&self) -> Step {
        self.step
    }

    /// 业务作用：提供同时绑定原审批、完整来源与节点位置的效果意图摘要，重投不会改变此身份。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：固定原生摘要引用，不序列化意图或公开秘密字段。
    pub(crate) fn intent_sha256(&self) -> &[u8; 32] {
        &self.intent_sha256
    }

    /// 业务作用：将独立材料签名域交给受信发行者和验证器，旧配置或预检签名不能取得执行权。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：覆盖完整原身份与当前投递的规范摘要文本。
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// 业务作用：查询只定位签名明确选择的执行或补偿效果，不把Resolve自身写成稳定业务结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一原步骤的Execute或Compensate效果，二者不能互相回答。
    pub(crate) fn resolved_effect(&self) -> EffectId {
        EffectId::derive(
            &self.identity.saga_id,
            self.identity.definition_version,
            &self.identity.step,
            if self.resolve_compensation {
                StepPhase::Compensate
            } else {
                StepPhase::Execute
            },
        )
    }
}
