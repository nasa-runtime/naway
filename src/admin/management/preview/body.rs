//! 预览正文在完整签名长度和摘要成立前不会进入构建器。

use super::{session::Work, Reason};
use crate::admin::management::protocol;
use bytes::Bytes;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: usize = 16 * 1024;

pub(super) struct Body {
    message: String,
    expected: usize,
    sha256: [u8; 32],
    bytes: Vec<u8>,
    digest: Sha256,
    ended: bool,
    failed: bool,
}

impl Body {
    /// 业务作用：只为已经验签且持有实际容量的预览分配一份有界原文。
    ///
    /// 参数说明：
    /// - `work`：固定候选长度、摘要和投递消息的已获权工作。
    ///
    /// 返回：尚未取得任何有效候选的分片接收器，分配量严格等于签名长度。
    pub(super) fn new(work: &Work) -> Self {
        Self {
            message: work.message.clone(),
            expected: work.command.intent.candidate_bytes as usize,
            sha256: work.command.intent.candidate_sha256,
            bytes: Vec::with_capacity(work.command.intent.candidate_bytes as usize),
            digest: Sha256::new(),
            ended: false,
            failed: false,
        }
    }

    /// 业务作用：按已确认连续字节生成下一分片偏移，不能由远端自报进度改变本地接收事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不超过签名总长度的已接收字节数。
    pub(super) fn offset(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// 业务作用：核对原投递、连续偏移、分片容量和精确 EOF，矛盾片段永久封闭本接收器。
    ///
    /// 参数说明：
    /// - `part`：同一受信管理通道返回的有限预览正文片段。
    ///
    /// 返回：成功推进时告知是否完整；身份或边界异常拒绝且不允许后续拼接恢复。
    pub(super) fn push(&mut self, part: protocol::PreviewDataResponse) -> Result<bool, Reason> {
        let end = self.bytes.len().checked_add(part.body.len());
        if self.failed
            || self.ended
            || part.offer_id != self.message
            || part.offset != self.offset()
            || part.body.is_empty()
            || part.body.len() > CHUNK
            || !end.is_some_and(|end| end <= self.expected && part.eof == (end == self.expected))
        {
            self.failed = true;
            return Err(Reason::CandidateInvalid);
        }
        self.digest.update(&part.body);
        self.bytes.extend_from_slice(&part.body);
        self.ended = part.eof;
        Ok(self.ended)
    }

    /// 业务作用：只有完整正文与签名摘要相同才把原分配移动给候选构建，避免重新编码全文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整有效的共享 Bytes；截断、已失败或摘要不符时拒绝并释放原文。
    pub(super) fn finish(self) -> Result<Bytes, Reason> {
        if self.failed
            || !self.ended
            || self.bytes.len() != self.expected
            || self.digest.finalize()[..] != self.sha256
        {
            return Err(Reason::CandidateInvalid);
        }
        Ok(self.bytes.into())
    }
}
