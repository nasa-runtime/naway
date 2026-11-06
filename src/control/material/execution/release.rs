//! 材料终态释放绑定独立签名域，业务执行收据或旧配置释放都不能授权删除秘密责任。

use super::{definition, position::Position};
use crate::control::{actions::command::Delivery, material::node::Intent};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

/// 允许核对本机责任的有限共享终态，名称本身不授予秘密清理权。
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Terminal {
    Completed,
    Compensated,
}

/// 当前会话下独立签名的材料释放请求，绑定完整原意图、物理位置与共享终态。
#[derive(Clone)]
pub(crate) struct Release {
    pub schema: u32,
    pub intent: Arc<Intent>,
    pub position: Position,
    pub definition_digest: String,
    pub terminal: Terminal,
    pub delivery: Delivery,
}

/// 清理决定保存的原终态证明；重启只沿已提交责任清理，不继承旧窗口的新增写权。
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    schema: u32,
    intent_sha256: [u8; 32],
    definition_digest: String,
    terminal: Terminal,
}

/// 独立释放域的规范消息和待持久证明，仍须验证当前共享终态与真实节点责任。
pub(crate) struct Validated {
    pub proof: Proof,
    pub message: String,
}

impl Release {
    /// 业务作用：把原材料意图、安全共享终态及本次投递绑定独立释放签名，重启不复用旧期限。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：待验签消息和终态证明；格式或跨度不符拒绝，不替代当前共享终态与节点事实核验。
    pub(crate) fn validate(&self) -> Result<Validated> {
        let intent_sha256 = self.position.fingerprint(&self.intent)?;
        let definition = definition::cached(self.position.count as usize)?;
        ensure!(
            self.schema == 1
                && self.definition_digest == definition.digest()
                && !self.delivery.resolve_compensation
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
            "material terminal release differs"
        );
        let mut digest = Sha256::new();
        digest.update(b"naway-material-terminal-release\0");
        digest.update(self.schema.to_be_bytes());
        let terminal = match self.terminal {
            Terminal::Completed => 1u8,
            Terminal::Compensated => 2u8,
        };
        for field in [
            intent_sha256.as_slice(),
            definition.name().as_str().as_bytes(),
            &definition.version().get().to_be_bytes(),
            self.definition_digest.as_bytes(),
            &[terminal],
            self.delivery.issuer_node_id.as_bytes(),
            self.delivery.receiving_boot_id.as_bytes(),
            &self.delivery.fence.to_be_bytes(),
            &self.delivery.session,
            &self.delivery.issued_at_ms.to_be_bytes(),
            &self.delivery.expires_at_ms.to_be_bytes(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        let mut message = String::with_capacity(64);
        for byte in digest.finalize() {
            message.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            message.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        Ok(Validated {
            proof: Proof {
                schema: 1,
                intent_sha256,
                definition_digest: self.definition_digest.clone(),
                terminal: self.terminal,
            },
            message,
        })
    }
}

impl Proof {
    /// 业务作用：恢复节点报告中的原清理声明，不把历史终态证明当成新的秘密删除授权。
    ///
    /// 参数说明：
    /// - `intent`：共享任务独立保留的完整原意图。
    /// - `position`：原物理节点位置。
    /// - `definition_digest`：原清理决定保存的独立定义摘要。
    /// - `terminal`：原共享终态声明。
    ///
    /// 返回：与原任务一致的历史证明；定义或意图不符拒绝，实际终态关系仍由报告验证。
    #[cfg(feature = "admin-operations-workflow-pgsql")]
    pub(crate) fn restore(
        intent: &Intent,
        position: Position,
        definition_digest: String,
        terminal: Terminal,
    ) -> Result<Self> {
        let proof = Self {
            schema: 1,
            intent_sha256: position.fingerprint(intent)?,
            definition_digest,
            terminal,
        };
        proof.validate(intent, position)?;
        Ok(proof)
    }

    /// 业务作用：交付清理事实原定义摘要，传输不重新借用当前任务或配置动作定义。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原独立定义摘要的借用。
    pub(crate) fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    /// 业务作用：从已提交清理事实核对原意图与终态，旧签名或临时会话不参与重启后的精确清理。
    ///
    /// 参数说明：
    /// - `intent`：原动作完整材料意图。
    /// - `position`：原物理节点步骤位置。
    ///
    /// 返回：格式、原意图及独立工作流一致时成功；不自行承认共享终态或授予文件方向。
    pub(crate) fn validate(&self, intent: &Intent, position: Position) -> Result<()> {
        ensure!(
            self.schema == 1
                && self.intent_sha256 == position.fingerprint(intent)?
                && self.definition_digest == definition::cached(position.count as usize)?.digest(),
            "material cleanup proof differs"
        );
        Ok(())
    }

    /// 业务作用：让节点将共享终态与本机实际效果配对，整体完成不能借补偿事实释放。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原受理共享终态的有限类别。
    pub(crate) fn terminal(&self) -> Terminal {
        self.terminal
    }
}
