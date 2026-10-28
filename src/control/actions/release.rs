//! 安全终态释放使用独立证明，不占用工作流的业务效果身份。

use super::command::{field_digest, Delivery, Intent};
use anyhow::{ensure, Result};
use nasa::saga::WorkflowDefinition;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Terminal {
    Completed,
    Compensated,
}

#[derive(Clone)]
pub(crate) struct Release {
    pub schema: u32,
    pub intent: Intent,
    pub definition_digest: String,
    pub terminal: Terminal,
    pub delivery: Delivery,
}

pub(crate) struct Validated {
    pub intent_sha256: [u8; 32],
    pub message: String,
}

impl Release {
    /// 业务作用：将原业务意图、安全终态和当前投递绑定到独立签名域，释放不能冒充业务执行结果。
    ///
    /// 参数说明：
    /// - definition：本机按冻结目标数量构造的不可变工作流。
    ///
    /// 返回：全部有限字段成立时返回规范摘要；不代替签名、时钟、当前权限或共享终态验证。
    pub(crate) fn validate(&self, definition: &WorkflowDefinition) -> Result<Validated> {
        let intent_sha256 = self.intent.fingerprint()?;
        ensure!(
            self.schema == 1
                && definition.name().as_str()
                    == format!("naway-config-targets-{}", self.intent.target_count)
                && self.definition_digest == definition.digest()
                && !self.delivery.resolve_compensation
                && crate::admin::management::valid_node_id(&self.delivery.issuer_node_id)
                && crate::admin::management::valid_node_id(&self.delivery.receiving_boot_id)
                && (1..=i64::MAX as u64).contains(&self.delivery.fence)
                && self.delivery.issued_at_ms > 0
                && self.delivery.expires_at_ms > self.delivery.issued_at_ms
                && self.delivery.expires_at_ms <= i64::MAX as u64,
            "invalid node terminal release"
        );
        let mut digest = Sha256::new();
        digest.update(b"naway-node-terminal-release\0");
        digest.update(self.schema.to_be_bytes());
        let terminal = match self.terminal {
            Terminal::Completed => 1,
            Terminal::Compensated => 2,
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
            field_digest(&mut digest, field);
        }
        let mut message = String::with_capacity(64);
        for byte in digest.finalize() {
            message.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            message.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        Ok(Validated {
            intent_sha256,
            message,
        })
    }
}
