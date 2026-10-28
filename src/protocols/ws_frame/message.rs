//! 只有显式消息治理才聚合；完整校验与动作先于第一字节输出，丢弃不会破坏后续消息。

use super::{
    plugins, FrameDisposition, FrameError, FramePolicy, FrameStats, GovernOutcome, HeaderOutcome,
    MessageAssembler, OpCode,
};
use crate::runtime::traffic_limit::resources::Retained;
use bytes::Bytes;
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) struct Context<'a> {
    pub policy: &'a FramePolicy,
    pub stats: &'a FrameStats,
    pub from_client: bool,
    pub compressed: bool,
    pub consumer: Option<&'a str>,
    pub writing: &'a AtomicBool,
}

enum End {
    Closed,
    Protocol(FrameError),
    Io(io::Error),
}

impl From<io::Error> for End {
    /// 业务作用：保留套接字错误，不把传输终止误记成业务策略拒绝。
    ///
    /// 参数说明：
    /// - `error`：当前方向的读写失败。
    ///
    /// 返回：调用方可直接结束连接的传输错误。
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// 业务作用：在原有长连接生命周期内执行完整消息事务，任何拒绝都发生在该消息输出前。
///
/// 参数说明：
/// - `reader`：当前方向的源读端。
/// - `writer`：当前方向的目标写端。
/// - `context`：固定的身份、方向、策略、计数和帧写入边界。
///
/// 返回：对端关闭或治理拒绝有明确分类，I/O 错误保持原类型；取消时写入边界保留半帧事实。
pub(crate) async fn govern<R, W>(
    mut reader: R,
    mut writer: W,
    context: Context<'_>,
) -> io::Result<GovernOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match transfer(&mut reader, &mut writer, &context).await {
        Ok(()) | Err(End::Closed) => Ok(GovernOutcome::Closed),
        Err(End::Protocol(error)) => {
            context.stats.record_message(false);
            Ok(GovernOutcome::Violation(error))
        }
        Err(End::Io(error)) => Err(error),
    }
}

/// 业务作用：按首字节固定消息期限，控制帧继续合法透传而不能续期或进入业务插件。
///
/// 参数说明：
/// - `reader`：源读端。
/// - `writer`：目标写端。
/// - `context`：本次连接方向冻结的治理上下文。
///
/// 返回：持续转发直至关闭、协议拒绝、期限耗尽或传输失败。
async fn transfer<R, W>(reader: &mut R, writer: &mut W, context: &Context<'_>) -> Result<(), End>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let policy = context.policy;
    let chain = if context.from_client {
        &policy.client_plugins
    } else {
        &policy.server_plugins
    };
    let mut flow = chain.flow();
    let mut assembler = MessageAssembler::default();
    let mut payload = Vec::new();
    let mut retained = None;
    let mut active_budget: Option<nabudget::RequestBudget> = None;
    loop {
        let mut raw = [0_u8; super::MAX_HEADER_BYTES];
        let first = match &active_budget {
            Some(budget) => budget
                .run(reader.read(&mut raw[..1]))
                .await
                .map_err(|_| End::Protocol(FrameError::MessageDeadline))??,
            None => reader.read(&mut raw[..1]).await?,
        };
        if first == 0 {
            return Err(End::Closed);
        }
        let budget = active_budget
            .get_or_insert_with(|| {
                nabudget::RequestBudget::from_now(Duration::from_millis(policy.message_timeout_ms))
            })
            .clone();
        read(reader, &mut raw[1..2], &budget).await?;
        let extra = match raw[1] & 0x7f {
            126 => 2,
            127 => 8,
            _ => 0,
        } + if raw[1] & 0x80 != 0 {
            4
        } else {
            0
        };
        read(reader, &mut raw[2..2 + extra], &budget).await?;
        let header =
            match super::parse_header(&raw[..2 + extra], context.from_client, context.compressed) {
                HeaderOutcome::Header(header) => header,
                HeaderOutcome::Invalid(error) => return Err(End::Protocol(error)),
                HeaderOutcome::Incomplete => {
                    return Err(End::Protocol(FrameError::NonCanonicalLength))
                }
            };
        let disposition = assembler.accept(policy, &header).map_err(End::Protocol)?;
        let mask = header.masked.then(|| {
            raw[header.header_len - 4..header.header_len]
                .try_into()
                .expect("fixed mask")
        });
        if header.opcode.is_control() {
            let mut control = [0_u8; super::MAX_HEADER_BYTES + super::MAX_CONTROL_PAYLOAD];
            control[..header.header_len].copy_from_slice(&raw[..header.header_len]);
            let end = header.header_len + header.payload_len as usize;
            read(reader, &mut control[header.header_len..end], &budget).await?;
            if header.opcode == OpCode::Close {
                let mut decoded = [0_u8; super::MAX_CONTROL_PAYLOAD];
                decoded[..header.payload_len as usize]
                    .copy_from_slice(&control[header.header_len..end]);
                unmask(&mut decoded[..header.payload_len as usize], mask);
                super::validate_close_payload(&decoded[..header.payload_len as usize])
                    .map_err(End::Protocol)?;
            }
            // 只有完整合法控制帧才写出；取消 write_all 后保留 writing=true，外层不得追加 Close。
            context.writing.store(true, Ordering::Release);
            budget
                .run(writer.write_all(&control[..end]))
                .await
                .map_err(|_| End::Protocol(FrameError::MessageDeadline))??;
            context.writing.store(false, Ordering::Release);
            if header.opcode == OpCode::Close {
                return Ok(());
            }
            if !assembler.in_message() {
                active_budget = None;
            }
            continue;
        }
        let held = retained.get_or_insert_with(|| Retained::acquire(0));
        let held = held
            .as_mut()
            .ok_or(End::Protocol(FrameError::ResourceCapacity))?;
        let frame_bytes = usize::try_from(header.payload_len)
            .map_err(|_| End::Protocol(FrameError::MessageTooLarge))?;
        let required = payload
            .len()
            .checked_add(frame_bytes)
            .ok_or(End::Protocol(FrameError::MessageTooLarge))?;
        if required > payload.capacity() {
            let capacity = required
                .max(payload.capacity().saturating_mul(2))
                .min(policy.max_message_bytes as usize);
            // 分配前同时覆盖旧新缓冲的短暂重叠，客户端声明的大长度不能跳过进程字节门。
            if !held.resize(
                (capacity as u64)
                    .saturating_mul(2)
                    .saturating_add(32 * 1024),
            ) {
                return Err(End::Protocol(FrameError::ResourceCapacity));
            }
            payload.reserve_exact(capacity - payload.len());
        }
        let start = payload.len();
        payload.resize(required, 0);
        read(reader, &mut payload[start..], &budget).await?;
        unmask(&mut payload[start..], mask);
        let FrameDisposition::MessageComplete {
            opcode,
            compressed,
            ..
        } = disposition
        else {
            continue;
        };
        let mut held = retained
            .take()
            .flatten()
            .expect("message capacity reserved");
        if compressed {
            let inflated = budget
                .run(super::deflate::inflate(
                    &payload,
                    policy.max_message_bytes as usize,
                    policy.max_decompress_ratio,
                    &mut held,
                    payload.capacity() as u64,
                ))
                .await
                .map_err(|_| End::Protocol(FrameError::MessageDeadline))?
                .map_err(End::Protocol)?;
            payload = inflated;
        }
        if opcode == OpCode::Text && std::str::from_utf8(&payload).is_err() {
            return Err(End::Protocol(FrameError::InvalidUtf8));
        }
        // 变换可能保留原正文并产生新正文，保留额在整个插件链和发送阶段持续有效。
        let extra_output = if chain.is_empty() {
            0
        } else {
            2 * policy.max_plugin_payload_bytes as u64
        };
        if !held.resize(
            (payload.capacity() as u64)
                .saturating_add(extra_output)
                .saturating_add(32 * 1024),
        ) {
            return Err(End::Protocol(FrameError::ResourceCapacity));
        }
        let held = Arc::new(held);
        let body = Bytes::from(std::mem::take(&mut payload));
        let result = flow
            .apply(
                body,
                plugins::Context {
                    consumer: context.consumer,
                    from_client: context.from_client,
                    opcode,
                    policy,
                    budget: &budget,
                    stats: context.stats,
                },
                held.clone(),
            )
            .await;
        let body = match result {
            Ok(body) => body,
            Err(plugins::Failure::Drop) => {
                context.stats.record_message(false);
                active_budget = None;
                continue;
            }
            Err(plugins::Failure::Denied) if policy.on_violation == super::MessageAction::Drop => {
                context.stats.record_message(false);
                active_budget = None;
                continue;
            }
            Err(plugins::Failure::Denied | plugins::Failure::Close) => {
                return Err(End::Protocol(FrameError::PolicyDenied))
            }
            Err(plugins::Failure::Capacity) => {
                return Err(End::Protocol(FrameError::ResourceCapacity))
            }
            Err(plugins::Failure::Deadline) => {
                return Err(End::Protocol(FrameError::MessageDeadline))
            }
            Err(plugins::Failure::Dependency | plugins::Failure::Invalid) => {
                return Err(End::Protocol(FrameError::PluginFailure))
            }
        };
        if body.len() as u64 > policy.max_message_bytes {
            return Err(End::Protocol(FrameError::MessageTooLarge));
        }
        if (body.len() as u64).max(1).div_ceil(policy.max_frame_bytes)
            > u64::from(policy.max_fragments)
        {
            // 变换或解压后的输出也必须遵守帧预算，不能在已经输出前缀后才发现无法合法分片。
            return Err(End::Protocol(FrameError::TooManyFragments));
        }
        if opcode == OpCode::Text && std::str::from_utf8(&body).is_err() {
            return Err(End::Protocol(FrameError::InvalidUtf8));
        }
        send(writer, &body, opcode, context, &budget).await?;
        context.stats.record_message(true);
        active_budget = None;
    }
}

/// 业务作用：消息读入始终服从首字节固定的截止点，分片与控制帧不能重新获得完整预算。
///
/// 参数说明：
/// - `reader`：当前源读端。
/// - `buffer`：已计入容量的目标切片。
/// - `budget`：本条消息的固定期限。
///
/// 返回：全部字节读入成功，或明确的期限与传输失败。
async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    budget: &nabudget::RequestBudget,
) -> Result<(), End> {
    budget
        .run(reader.read_exact(buffer))
        .await
        .map_err(|_| End::Protocol(FrameError::MessageDeadline))??;
    Ok(())
}

/// 业务作用：在唯一消息缓冲中移除客户端掩码，避免为协议校验再复制完整载荷。
///
/// 参数说明：
/// - `payload`：当前帧的完整载荷。
/// - `mask`：该帧头声明的掩码；服务端方向为空。
///
/// 返回：原位恢复消息字节，长度与容量不变。
fn unmask(payload: &mut [u8], mask: Option<[u8; 4]>) {
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
}

/// 业务作用：把已经批准的完整消息按帧上限输出，客户端方向使用新随机掩码且不重新压缩正文。
///
/// 参数说明：
/// - `writer`：目标写端。
/// - `body`：最终不可变消息；下游方向直接借用 Bytes。
/// - `opcode`：原始消息类别，后续分片使用 Continuation。
/// - `context`：方向、帧大小与取消边界。
/// - `budget`：整条消息剩余交付期限。
///
/// 返回：所有帧完整交付才清除写入标志；中断保留半帧事实，不追加协议控制帧。
async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
    opcode: OpCode,
    context: &Context<'_>,
    budget: &nabudget::RequestBudget,
) -> Result<(), End> {
    let mut offset = 0;
    let mut scratch = [0_u8; 16 * 1024];
    loop {
        let count = (body.len() - offset).min(context.policy.max_frame_bytes as usize);
        let last = offset + count == body.len();
        let mut header = [0_u8; super::MAX_HEADER_BYTES];
        header[0] = if last {
            0x80
        } else {
            0
        } | if offset > 0 {
            0
        } else if opcode == OpCode::Text {
            1
        } else {
            2
        };
        let mask_bit = if context.from_client {
            0x80
        } else {
            0
        };
        let mut length = 2;
        if count < 126 {
            header[1] = mask_bit | count as u8;
        } else if count <= u16::MAX as usize {
            header[1] = mask_bit | 126;
            header[2..4].copy_from_slice(&(count as u16).to_be_bytes());
            length = 4;
        } else {
            header[1] = mask_bit | 127;
            header[2..10].copy_from_slice(&(count as u64).to_be_bytes());
            length = 10;
        }
        let mut mask = [0_u8; 4];
        if context.from_client {
            getrandom::getrandom(&mut mask)
                .map_err(|_| End::Io(io::Error::other("WebSocket masking entropy unavailable")))?;
            header[length..length + 4].copy_from_slice(&mask);
            length += 4;
        }
        context.writing.store(true, Ordering::Release);
        let write = async {
            writer.write_all(&header[..length]).await?;
            let mut sent = 0;
            while sent < count {
                let take = (count - sent).min(scratch.len());
                let chunk = &body[offset + sent..offset + sent + take];
                if context.from_client {
                    for (index, byte) in chunk.iter().enumerate() {
                        scratch[index] = byte ^ mask[(sent + index) % 4];
                    }
                    writer.write_all(&scratch[..take]).await?;
                } else {
                    writer.write_all(chunk).await?;
                }
                sent += take;
                tokio::task::yield_now().await;
            }
            Ok::<(), io::Error>(())
        };
        budget
            .run(write)
            .await
            .map_err(|_| End::Protocol(FrameError::MessageDeadline))??;
        context.writing.store(false, Ordering::Release);
        if last {
            return Ok(());
        }
        offset += count;
    }
}
