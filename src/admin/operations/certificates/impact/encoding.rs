//! 持久证明和 HTTP 投影各自在唯一输出边界编码，增长前检查真实字节预算。

use super::Error;
use std::io::{self, Write};

struct Buffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for Buffer {
    /// 业务作用：编码器写入前限制总字节，不能先构造超量 JSON 再判断审批存储是否容纳。
    ///
    /// 参数说明：
    /// - `bytes`：序列化器提供的当前有限片段。
    ///
    /// 返回：整体仍在预算内才接收片段；超量保持原缓冲且立即拒绝编码。
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("material impact encoding capacity"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// 业务作用：内存编码不持有外部写入责任，结束时无需触发文件或网络副作用。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：原缓冲已经包含全部接收片段，直接确认完成。
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 业务作用：借用原生证明或公开投影编码一次，不创建 Value 树或重复复制来源数组。
///
/// 参数说明：
/// - `value`：当前存储或响应边界的原生对象。
/// - `limit`：调用方代码固定的完整编码字节预算。
///
/// 返回：唯一完整缓冲；超量或编码失败不返回部分对象。
pub(in crate::admin::operations::certificates) fn bytes(
    value: &impl serde::Serialize,
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let mut buffer = Buffer {
        bytes: Vec::with_capacity(8192.min(limit)),
        limit,
    };
    serde_json::to_writer(&mut buffer, value).map_err(|_| Error::Capacity)?;
    Ok(buffer.bytes)
}
