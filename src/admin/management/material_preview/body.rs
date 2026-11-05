//! 秘密分片只进入一份可清零材料帧，失败与取消不保留受控缓冲区。

use super::{command::Command, Reason};
use crate::control::material::Material;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(super) const CHUNK: usize = 16 * 1024;

pub(super) struct Body {
    message: String,
    expected: usize,
    sha256: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
    digest: Sha256,
    ended: bool,
    failed: bool,
}

impl Body {
    /// 业务作用：为已经验签并持有实际工作许可的原目标建立唯一秘密接收帧。
    ///
    /// 参数说明：
    /// - `command`：通过原会话验签的完整材料声明。
    /// - `message`：已验证的独立预检消息摘要。
    ///
    /// 返回：容量等于签名长度的接收器，尚未拥有可用于 TLS 构建的候选。
    pub(super) fn new(command: &Command, message: String) -> Self {
        Self {
            message,
            expected: command.intent.candidate_bytes as usize,
            sha256: command.intent.candidate_sha256,
            bytes: Zeroizing::new(Vec::with_capacity(command.intent.candidate_bytes as usize)),
            digest: Sha256::new(),
            ended: false,
            failed: false,
        }
    }

    /// 业务作用：按实际接收字节取得下一分片位置，远端不能跳过或重放候选的一部分。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前已确认的连续长度，不超过签名容量。
    pub(super) fn offset(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// 业务作用：核对原消息和精确连续边界，任何矛盾片段永久撤销当前候选。
    ///
    /// 参数说明：
    /// - `message`：当前分片声明的原预检消息。
    /// - `offset`：分片起始位置。
    /// - `eof`：发送方声明的精确结束标记。
    /// - `bytes`：网络边界接管后可清零的有界分片。
    ///
    /// 返回：合法推进时告知是否完成；失败也清零已接收材料及本分片，不允许后续恢复拼接。
    pub(super) fn push(
        &mut self,
        message: &str,
        offset: u32,
        eof: bool,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<bool, Reason> {
        let end = self.bytes.len().checked_add(bytes.len());
        if self.failed
            || self.ended
            || message != self.message
            || offset != self.offset()
            || bytes.is_empty()
            || bytes.len() > CHUNK
            || !end.is_some_and(|end| end <= self.expected && eof == (end == self.expected))
        {
            self.failed = true;
            use zeroize::Zeroize;
            self.bytes.zeroize();
            return Err(Reason::CandidateInvalid);
        }
        self.digest.update(&bytes);
        self.bytes.extend_from_slice(&bytes);
        self.ended = eof;
        Ok(eof)
    }

    /// 业务作用：摘要、完整帧和精确结束都成立后移动唯一材料分配，不经 JSON 或 Base64 重编码。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：后续仍需原条件与 TLS 策略门的材料；截断、摘要或帧错误时原缓冲区自动清零。
    pub(super) fn finish(self) -> Result<Material, Reason> {
        if self.failed
            || !self.ended
            || self.bytes.len() != self.expected
            || self.digest.finalize()[..] != self.sha256
        {
            return Err(Reason::CandidateInvalid);
        }
        let material = Material(self.bytes);
        material.parts().map_err(|_| Reason::CandidateInvalid)?;
        Ok(material)
    }
}
