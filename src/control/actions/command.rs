//! 命令身份与签名内容的共同合同；验真本身不授予节点写入资格。

use super::domain::Domain;
use crate::{config::operations::token, control::baseline::NodeBaseline};
use anyhow::{ensure, Result};
use nasa::saga::{EffectId, StepPhase, WorkflowDefinition};
use nasaga_runtime_core::{SagaCommandEnvelope, VerifiedIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub operation_id: String,
    pub proposal_epoch: u64,
    pub target_index: u32,
    pub target_count: u32,
    pub domain: Domain,
    pub node_id: String,
    pub original_boot_id: String,
    pub baseline: NodeBaseline,
    pub base_version: u64,
    pub base_fingerprint: u64,
    pub candidate_bytes: u32,
    pub candidate_sha256: [u8; 32],
    pub scope: String,
    pub creator: String,
    pub reviewer: String,
    pub authority_sha256: [u8; 32],
}

/// 当前投递的权威声明，不能代替原意图或跨会话复用。
#[derive(Clone)]
pub(crate) struct Delivery {
    pub issuer_node_id: String,
    pub receiving_boot_id: String,
    pub fence: u64,
    pub session: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub resolve_compensation: bool,
}

pub(crate) struct Command {
    pub schema: u32,
    pub envelope: SagaCommandEnvelope,
    pub intent: Intent,
    pub delivery: Delivery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Step {
    Prepare,
    Apply,
}

/// 已核对的命令身份；仍须验证发行签名、当前权限、租约和持久槽。
pub(crate) struct Validated {
    identity: VerifiedIdentity,
    step: Step,
    forward_effect: EffectId,
    resolve_compensation: bool,
    intent_sha256: [u8; 32],
    message: String,
}

impl Intent {
    /// 业务作用：给跨 attempt 与发行者不变的业务意图建立身份，防止同一效果改绑正文或目标。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：所有有限字段合法时返回域分隔摘要；非法声明不产生可持久受理的身份。
    pub(crate) fn fingerprint(&self) -> Result<[u8; 32]> {
        ensure!(
            self.operation_id.len() == 32
                && self
                    .operation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                && (1..=i64::MAX as u64).contains(&self.proposal_epoch)
                && (1..=crate::config::operations::MAX_TARGETS as u32).contains(&self.target_count)
                && self.target_index < self.target_count
                && crate::admin::management::valid_node_id(&self.node_id)
                && crate::admin::management::valid_node_id(&self.original_boot_id)
                && self.baseline.valid()
                && self.base_version > 0
                && (1..=1024 * 1024).contains(&self.candidate_bytes)
                && (self.scope == "platform"
                    || self
                        .scope
                        .strip_prefix("workspace.")
                        .is_some_and(|workspace| token(workspace, 118)))
                && token(&self.creator, 128)
                && token(&self.reviewer, 128)
                && self.creator != self.reviewer,
            "invalid node action intent"
        );
        let mut digest = Sha256::new();
        digest.update(b"naway-node-action-intent\0");
        digest.update(1_u32.to_be_bytes());
        for field in [
            self.operation_id.as_bytes(),
            &self.proposal_epoch.to_be_bytes(),
            &self.target_index.to_be_bytes(),
            &self.target_count.to_be_bytes(),
            self.domain.identity().0.as_bytes(),
            self.node_id.as_bytes(),
            self.original_boot_id.as_bytes(),
            &self.baseline.schema.to_be_bytes(),
            self.baseline.cluster_id.as_bytes(),
            self.baseline.store_id.as_bytes(),
            self.baseline.node_admission_epoch.as_bytes(),
            self.baseline.documents_sha256.as_bytes(),
            &self.base_version.to_be_bytes(),
            &self.base_fingerprint.to_be_bytes(),
            &self.candidate_bytes.to_be_bytes(),
            &self.candidate_sha256,
            self.scope.as_bytes(),
            self.creator.as_bytes(),
            self.reviewer.as_bytes(),
            &self.authority_sha256,
        ] {
            field_digest(&mut digest, field);
        }
        Ok(digest.finalize().into())
    }
}

impl Command {
    /// 业务作用：复用 NASA 派生身份并绑定唯一目标、冻结定义和完整投递声明，阻止自报效果或错步骤进入节点槽。
    ///
    /// 参数说明：
    /// - `definition`：本机按冻结目标数量构造的不可变工作流，不来自命令正文。
    ///
    /// 返回：可供签名与验签的固定摘要及已证身份；不检查当前时钟、签名或执行权限，不产生外部副作用。
    pub(crate) fn validate(&self, definition: &WorkflowDefinition) -> Result<Validated> {
        let intent_sha256 = self.intent.fingerprint()?;
        ensure!(
            self.schema == 1
                && self.envelope.payload.is_none()
                && self.envelope.raw_payload.is_none()
                && crate::admin::management::valid_node_id(&self.delivery.issuer_node_id)
                && crate::admin::management::valid_node_id(&self.delivery.receiving_boot_id)
                && (1..=i64::MAX as u64).contains(&self.delivery.fence)
                && self.delivery.issued_at_ms > 0
                && self.delivery.expires_at_ms > self.delivery.issued_at_ms
                && self.delivery.expires_at_ms <= i64::MAX as u64,
            "invalid node action delivery"
        );
        // 自报 effect/command 不能污染去重槽；必须先由 NASA 按完整身份重新派生。
        let identity = self
            .envelope
            .verified()
            .map_err(|_| anyhow::anyhow!("invalid node action identity"))?;
        ensure!(
            identity.saga_id.as_str() == self.intent.operation_id
                && identity.tenant.as_str() == self.intent.baseline.cluster_id
                && identity.workflow.as_str()
                    == format!("naway-config-targets-{}", self.intent.target_count)
                && identity.workflow == *definition.name()
                && identity.definition_version == definition.version()
                && identity.definition_digest == definition.digest()
                && identity.phase != StepPhase::Cancel
                && (!self.delivery.resolve_compensation || identity.phase == StepPhase::Resolve),
            "node action workflow differs"
        );
        let step = if identity.step.as_str() == format!("prepare-{:03}", self.intent.target_index) {
            Step::Prepare
        } else if identity.step.as_str() == format!("apply-{:03}", self.intent.target_index) {
            Step::Apply
        } else {
            anyhow::bail!("node action target step differs");
        };
        // Resolve 与 Compensate 都有自己的效果身份，读取正向事实时必须明确派生 Execute 身份。
        let forward_effect = EffectId::derive(
            &identity.saga_id,
            identity.definition_version,
            &identity.step,
            StepPhase::Execute,
        );
        let mut digest = Sha256::new();
        digest.update(b"naway-node-action-command\0");
        digest.update(self.schema.to_be_bytes());
        for field in [
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
        ] {
            field_digest(&mut digest, field);
        }
        // 正向旧消息保持同一摘要；补偿查询追加独立标记，忽略新字段的接收器也无法验过签名。
        if self.delivery.resolve_compensation {
            field_digest(&mut digest, b"naway-resolution-compensation\0");
        }
        let mut message = String::with_capacity(64);
        for byte in digest.finalize() {
            message.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            message.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        Ok(Validated {
            identity,
            step,
            forward_effect,
            resolve_compensation: self.delivery.resolve_compensation,
            intent_sha256,
            message,
        })
    }
}

impl Validated {
    /// 业务作用：只把 NASA 已重新派生的命令身份交给后续收据和结果适配器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同次验证的强类型身份引用，不复制 envelope 或候选正文。
    pub(crate) fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }

    /// 业务作用：区分目标预检与应用步骤，避免使用相同 phase 时误调另一种业务副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已经绑定目标索引的有限步骤。
    pub(crate) fn step(&self) -> Step {
        self.step
    }

    /// 业务作用：让查询与补偿定位原正向效果，避免把只读轮询身份保存成业务终态。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：同一 Saga、定义和步骤派生的 Execute 效果引用。
    pub(crate) fn forward_effect(&self) -> &EffectId {
        &self.forward_effect
    }

    /// 业务作用：按签名中的查询方向派生真实业务效果，隔离发布成功和补偿成功两种事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：该步骤的 Execute 或 Compensate 效果；不使用 Resolve 自身身份查询收据。
    pub(crate) fn resolved_effect(&self) -> EffectId {
        if self.resolve_compensation {
            EffectId::derive(
                &self.identity.saga_id,
                self.identity.definition_version,
                &self.identity.step,
                StepPhase::Compensate,
            )
        } else {
            self.forward_effect
        }
    }

    /// 业务作用：提供独立于 attempt 和发行者的业务意图身份，用于持久重复受理比较。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：包含候选和权限声明的固定 SHA-256，不含原文副本。
    pub(crate) fn intent_sha256(&self) -> &[u8; 32] {
        &self.intent_sha256
    }

    /// 业务作用：将固定签名域交给 NASA 密码组件，握手或另一投递的证明不能复用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：覆盖本次全部身份和投递字段的规范摘要文本。
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// 业务作用：为相邻身份字段加入固定长度边界，避免拼接歧义产生同一签名内容。
///
/// 参数说明：
/// - `digest`：当前独立签名域的摘要累加器。
/// - `bytes`：有界字段的原始字节，不创建中间编码副本。
///
/// 返回：只更新摘要，不保留输入或触发序列化。
pub(super) fn field_digest(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
