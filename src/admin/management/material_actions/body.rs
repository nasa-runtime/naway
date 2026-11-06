//! 秘密分片只进入一份精确预分配清零帧，接收器和产物共同持有原节点实际许可。

use super::{Content, Work};
use crate::control::material::Material;
use nasa::grpc::Status;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub(super) const CHUNK: usize = 16 * 1024;

pub(super) struct Body {
    message: String,
    expected: usize,
    sha256: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
    digest: Sha256,
    ended: bool,
    failed: bool,
    work: Arc<Work>,
}

impl Body {
    /// 业务作用：仅为已验签且取得真实节点名额的工作分配一份候选，不从裸网络长度申请秘密内存。
    ///
    /// 参数说明：
    /// - `work`：原受信会话、完整命令及独占许可，下载循环仍须逐次复验当前写权。
    ///
    /// 返回：精确签名容量的唯一接收器；原合同不成立拒绝，不分配候选。
    pub(super) fn new(work: Arc<Work>) -> Result<Self, Status> {
        let checked = work
            .command()
            .validate()
            .map_err(|_| Status::invalid_argument("material download contract differs"))?;
        if checked.step() != crate::control::material::execution::command::Step::Prepare
            || checked.identity().phase != nasa::saga::StepPhase::Execute
        {
            return Err(Status::invalid_argument(
                "material download requires preparation",
            ));
        }
        let intent = &work.command().intent;
        Ok(Self {
            message: checked.message().into(),
            expected: intent.candidate_bytes as usize,
            sha256: intent.candidate_sha256,
            bytes: Zeroizing::new(Vec::with_capacity(intent.candidate_bytes as usize)),
            digest: Sha256::new(),
            ended: false,
            failed: false,
            work,
        })
    }

    /// 业务作用：让后续分片只请求原帧的精确连续位置，不能跳过尚未接收的秘密部分。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已确认连续字节数，始终不超过原签名容量。
    pub(super) fn offset(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// 业务作用：核对消息身份、连续偏移与精确EOF，任何矛盾分片永久封闭并清零该接收器。
    ///
    /// 参数说明：
    /// - `message`：分片声明的完整材料投递摘要。
    /// - `offset`：分片起始位置。
    /// - `eof`：发送者声明的精确帧末尾。
    /// - `bytes`：网络边界接管后立即纳入清零的有界分片。
    ///
    /// 返回：完整合法推进后告知是否结束；错误不允许后来分片恢复资格，当前分片同样自动清零。
    pub(super) fn push(
        &mut self,
        message: &str,
        offset: u32,
        eof: bool,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<bool, Status> {
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
            self.bytes.zeroize();
            return Err(Status::data_loss("material chunk contract differs"));
        }
        self.digest.update(&bytes);
        self.bytes.extend_from_slice(&bytes);
        self.ended = eof;
        Ok(eof)
    }

    /// 业务作用：只有完整帧与签名摘要一致才移交唯一分配，候选保留原工作许可直到秘密清零。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：不经JSON或Base64重编码的共享产物；截断、摘要或帧错误清零材料并释放实际名额。
    pub(super) fn finish(self) -> Result<Arc<Content>, Status> {
        if self.failed
            || !self.ended
            || self.bytes.len() != self.expected
            || self.digest.finalize()[..] != self.sha256
        {
            return Err(Status::data_loss("material candidate integrity differs"));
        }
        let material = Material(self.bytes);
        material
            .parts()
            .map_err(|_| Status::data_loss("material candidate frame differs"))?;
        Ok(Arc::new(Content::downloaded(
            material,
            self.sha256,
            self.work,
        )))
    }
}
