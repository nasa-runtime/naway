//! 压缩消息在交付前完整校验；解码工作集、展开比例和单次CPU工作均受硬界约束。

use super::FrameError;
use crate::runtime::traffic_limit::resources::Retained;
use flate2::{Decompress, FlushDecompress, Status};

const CHUNK: usize = 16 * 1024;
const CODEC_BYTES: u64 = 128 * 1024;
// 恢复被线路省略的空stored块，再追加本地终止块，使残缺输入不能伪装成合法前缀。
const TAIL: [u8; 9] = [0, 0, 255, 255, 1, 0, 0, 255, 255];

/// 业务作用：恢复一条独立压缩消息，在发布任何内容前验证全部DEFLATE段并限制展开资源。
///
/// 参数说明：
/// - `payload`：已经移除WebSocket掩码的整条压缩载荷，不包含帧头。
/// - `maximum`：该处理链允许的解压后字节硬上限。
/// - `ratio`：解压字节与实际压缩载荷字节之比的硬上限。
/// - `retained`：消息原有容量名额，解码沿用而不新建等待者。
/// - `resident`：原始载荷及既有消息缓冲已经占用的逻辑字节数。
///
/// 返回：唯一解压后缓冲；畸形、截断、超界或资源不足失败，调用方必须关闭连接。
pub(crate) async fn inflate(
    payload: &[u8],
    maximum: usize,
    ratio: u32,
    retained: &mut Retained,
    resident: u64,
) -> Result<Vec<u8>, FrameError> {
    let bound = maximum.min(payload.len().saturating_mul(ratio as usize));
    let base = resident
        .checked_add(CODEC_BYTES)
        .ok_or(FrameError::ResourceCapacity)?;
    if !retained.resize(base) {
        return Err(FrameError::ResourceCapacity);
    }
    let mut codec = Decompress::new(false);
    let mut output = Vec::new();
    let segments = [payload, TAIL.as_slice()];
    let mut segment = 0;
    let mut offset = 0;
    loop {
        while segment < segments.len() && offset == segments[segment].len() {
            segment += 1;
            offset = 0;
        }
        // 即便已经达到允许体积，也保留一个探测字节；多出的输出必须被发现而不是静默截断。
        let step = CHUNK.min(bound.saturating_sub(output.len()).saturating_add(1));
        let previous = output.len();
        let required = previous
            .checked_add(step)
            .ok_or(FrameError::DecompressionBomb)?;
        if output.capacity() < required {
            let capacity = required
                .max(output.capacity().saturating_mul(2))
                .min(bound.saturating_add(1));
            let bytes = base
                .checked_add(capacity as u64)
                .ok_or(FrameError::ResourceCapacity)?;
            // 先取得进程字节预算再分配；高压缩比或并发连接不能在失败后才补记物理内存。
            if !retained.resize(bytes) || output.try_reserve_exact(capacity - previous).is_err() {
                return Err(FrameError::ResourceCapacity);
            }
        }
        output.resize(required, 0);
        let input = segments.get(segment).map_or(&[][..], |bytes| {
            &bytes[offset..bytes.len().min(offset.saturating_add(CHUNK))]
        });
        let (before_in, before_out) = (codec.total_in(), codec.total_out());
        let status = codec
            .decompress(input, &mut output[previous..], FlushDecompress::None)
            .map_err(|_| FrameError::InvalidCompression)?;
        let consumed = (codec.total_in() - before_in) as usize;
        let produced = (codec.total_out() - before_out) as usize;
        output.truncate(previous + produced);
        offset += consumed;
        if output.len() > bound {
            return Err(FrameError::DecompressionBomb);
        }
        if status == Status::StreamEnd {
            if (segment == 1 && offset == TAIL.len()) || segment == segments.len() {
                return Ok(output);
            }
            // RFC允许同消息内出现BFINAL=1；后续段仍属于同一消息，只保留其32KiB字典历史。
            // 这不授予下一条消息继承字典的权限，每次调用都创建独立解码器。
            codec.reset(false);
            codec
                .set_dictionary(&output[output.len().saturating_sub(32 * 1024)..])
                .map_err(|_| FrameError::InvalidCompression)?;
        } else if consumed == 0 && produced == 0 {
            return Err(FrameError::InvalidCompression);
        }
        // 每轮最多读写固定块；空块洪泛和高展开输入都必须让出执行器，外层绝对期限才能生效。
        tokio::task::yield_now().await;
    }
}
