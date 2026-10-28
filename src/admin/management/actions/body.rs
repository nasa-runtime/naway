//! 候选原文按签名长度分片接收，完整身份、EOF 与摘要一致前不得交给配置构建器。

use crate::admin::management::protocol;
use crate::control::actions::command::{Intent, Validated};
use bytes::Bytes;
use nasa::grpc::Status;
use sha2::{Digest, Sha256};

pub(super) const CHUNK: usize = 16 * 1024;

pub(super) struct Body {
    offer_id: String,
    expected: usize,
    sha256: [u8; 32],
    bytes: Vec<u8>,
    digest: Sha256,
    ended: bool,
    failed: bool,
}

impl Body {
    /// 业务作用：为已授权命令只分配一份有界候选原文，保持下载身份与签名声明一致。
    ///
    /// 参数说明：
    /// - `intent`：当前命令的原始业务意图。
    /// - `validated`：同一命令已完成合同与签名核验后的视图。
    ///
    /// 返回：未完成的接收器；意图不匹配拒绝。调用方须先持有真实动作容量及当前授权。
    pub(super) fn new(intent: &Intent, validated: &Validated) -> Result<Self, Status> {
        // 长度来自原签名意图，不能用未复验声明或另一个命令的验证视图申请内存。
        if intent.fingerprint().ok().as_ref() != Some(validated.intent_sha256()) {
            return Err(Status::invalid_argument("candidate intent differs"));
        }
        let expected = intent.candidate_bytes as usize;
        Ok(Self {
            offer_id: validated.message().into(),
            expected,
            sha256: intent.candidate_sha256,
            bytes: Vec::with_capacity(expected),
            digest: Sha256::new(),
            ended: false,
            failed: false,
        })
    }

    /// 业务作用：读取已经验证的连续原文字节数，不把网络请求的偏移当成接收事实。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：下一请求应使用的精确偏移，始终不超过签名总长度。
    pub(super) fn offset(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// 业务作用：在追加前核对投递身份、连续偏移、分片预算和终止位置，错误后封闭整份接收器。
    ///
    /// 参数说明：
    /// - `part`：同一管理通道返回的单个有界原文分片。
    ///
    /// 返回：成功后推进偏移；完整正文时为 true，任何差异拒绝且不能继续拼接。
    pub(super) fn push(&mut self, part: protocol::ActionDataResponse) -> Result<bool, Status> {
        let end = self.bytes.len().checked_add(part.body.len());
        if self.failed
            || self.ended
            || part.offer_id != self.offer_id
            || part.offset != self.offset()
            || part.body.is_empty()
            || part.body.len() > CHUNK
            || !end.is_some_and(|end| end <= self.expected && part.eof == (end == self.expected))
        {
            // 不完整或矛盾传输不能通过后来的合法分片恢复信任，否则会隐藏错会话和截断证据。
            self.failed = true;
            return Err(Status::data_loss("candidate chunk contract differs"));
        }
        self.digest.update(&part.body);
        self.bytes.extend_from_slice(&part.body);
        self.ended = part.eof;
        Ok(self.ended)
    }

    /// 业务作用：只把完整且与签名 SHA 一致的原文交给候选构建器，不二次序列化或复制全文。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：消耗接收器并交付共享 Bytes；提前结束、错误或摘要不符均丢弃候选。
    pub(super) fn finish(self) -> Result<Bytes, Status> {
        if self.failed
            || !self.ended
            || self.bytes.len() != self.expected
            || self.digest.finalize()[..] != self.sha256
        {
            return Err(Status::data_loss("candidate body integrity differs"));
        }
        Ok(Bytes::from(self.bytes))
    }
}
