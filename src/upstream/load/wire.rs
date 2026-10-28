//! ORCA 的单请求和服务端流 gRPC framing；完整报告直接借用，只有跨帧报告才有界缓存。

use super::report;
use bytes::Bytes;

pub(crate) const METHOD: &str = "/xds.service.orca.v3.OpenRcaService/StreamCoreMetrics";

/// 业务作用：将已校验的报告间隔编码成一次订阅请求，不使用通用序列化中间结构。
///
/// 参数说明：
/// - `interval_ms`：配置中的报告间隔。
///
/// 返回：一个包含 Duration 的标准 gRPC 请求帧，后续重连共享同一 Bytes。
pub(crate) fn request(interval_ms: u64) -> Bytes {
    let mut duration = Vec::with_capacity(16);
    duration.push(8);
    put_varint(&mut duration, interval_ms / 1000);
    duration.push(16);
    put_varint(&mut duration, (interval_ms % 1000) * 1_000_000);
    let mut output = Vec::with_capacity(duration.len() + 7);
    output.push(0);
    output.extend_from_slice(&((duration.len() + 2) as u32).to_be_bytes());
    output.push(10);
    output.push(duration.len() as u8);
    output.extend_from_slice(&duration);
    Bytes::from(output)
}

/// 业务作用：编码订阅请求中固定数量的非负 Duration 字段。
///
/// 参数说明：
/// - `output`：仅在创建订阅时使用的小型缓冲。
/// - `value`：已在配置期限制的秒或纳秒值。
///
/// 返回：追加最短 protobuf varint，不影响业务载荷。
fn put_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        output.push(value as u8 | 128);
        value >>= 7;
    }
    output.push(value as u8);
}

pub(crate) struct Decoder {
    header: [u8; 5],
    header_len: usize,
    length: Option<usize>,
    partial: Vec<u8>,
    limit: usize,
}

impl Decoder {
    /// 业务作用：为单个已授权 ORCA 流建立固定上界的增量解帧状态。
    ///
    /// 参数说明：
    /// - `limit`：已验证的单报告字节预算。
    ///
    /// 返回：不预分配报告缓存的空状态，完整网络帧走借用解析。
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            header: [0; 5],
            header_len: 0,
            length: None,
            partial: Vec::new(),
            limit: limit.min(report::MAX_REPORT_BYTES),
        }
    }

    /// 业务作用：增量消费至多一份报告，使调用者能逐报告执行速率、权限和调度让出门。
    ///
    /// 参数说明：
    /// - `input`：当前 HTTP/2 DATA 的借用片段，成功读取后推进。
    ///
    /// 返回：完整合法报告返回数值；分片未齐返回 None；压缩、超长或畸形报告终止订阅。
    pub(crate) fn next(&mut self, input: &mut &[u8]) -> Result<Option<u32>, ()> {
        if self.length.is_none() {
            let count = (5 - self.header_len).min(input.len());
            self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
            self.header_len += count;
            *input = &input[count..];
            if self.header_len < 5 {
                return Ok(None);
            }
            let length = u32::from_be_bytes(self.header[1..].try_into().map_err(|_| ())?) as usize;
            if self.header[0] != 0 || length > self.limit {
                return Err(());
            }
            self.length = Some(length);
        }
        let length = self.length.ok_or(())?;
        let remaining = length - self.partial.len();
        if self.partial.is_empty() && input.len() >= length {
            let value = report::parse_protobuf(&input[..length]).ok_or(())?;
            *input = &input[length..];
            self.reset();
            return Ok(Some(value));
        }
        if self.partial.capacity() == 0 {
            self.partial = Vec::with_capacity(self.limit);
        }
        let count = remaining.min(input.len());
        self.partial.extend_from_slice(&input[..count]);
        *input = &input[count..];
        if self.partial.len() != length {
            return Ok(None);
        }
        let value = report::parse_protobuf(&self.partial).ok_or(())?;
        self.reset();
        Ok(Some(value))
    }

    /// 业务作用：完成报告后复用分片缓存，同时清除前一帧长度，防止跨消息拼接。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：解码器回到帧边界，保留的容量不超过创建时预算。
    fn reset(&mut self) {
        self.header_len = 0;
        self.length = None;
        self.partial.clear();
    }
}
