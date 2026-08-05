//! V8-8 浏览器 WS→内部 gRPC 边缘桥接(架构规范 §25.2 边界 A / naway.md)。
//!
//! 浏览器拿不到 HTTP/2 trailers,也没法发原生 gRPC 帧,所以 Web 端用 WebSocket 进
//! 同一条订阅路径。**只换传输外壳**:鉴权、身份 claim、group 索引、双维队列预算、
//! 治理关闭全部复用 `EdgeHub`——桥接不是第二套订阅实现。
//!
//! 帧契约:每条广播 = 一个 **binary** WS 帧,内容是与 native gRPC 订阅者**字节一致**的
//! `[5B prefix + payload]`(不剥前缀:浏览器侧同一份解码逻辑既能读桥接也能读原生流,
//! 且网关继续不解析业务 payload)。收尾用 Close 帧携带治理原因码。
//!
//! 服务端只写不读:入站数据帧一律忽略(v1 订阅语义全在 URL query + 鉴权头),
//! 但必须响应 Ping 与 Close(RFC 6455 §5.5),否则浏览器会判连接失活。

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use http::header::{HeaderName, HeaderValue};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::conn_registry::ConnGuard;
use crate::edge_hub::{EdgeCloseReason, EdgeSubscription};

/// RFC 6455 握手魔数。
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// 入站控制帧载荷上限(RFC 6455 §5.5:控制帧 ≤125B)。
const MAX_CONTROL_PAYLOAD: usize = 125;
/// 入站数据帧读取上限:桥接不消费上行业务数据,超限即关连接,不做无界读取。
const MAX_INBOUND_FRAME_BYTES: u64 = 64 * 1024;

/// 计算 `Sec-WebSocket-Accept`(SHA-1 走 nasa::crypto,仓内不自造密码学实现)。
pub fn accept_key(client_key: &str) -> Option<String> {
    let digest_hex = nasa::crypto::sha1(&format!("{client_key}{WS_GUID}"));
    let digest = hex_to_bytes(&digest_hex)?;
    Some(base64_encode(&digest))
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// 标准 base64(带填充)。仓内已有手写 Basic-Auth 解码器,这是同级的编码工具,
/// 不属于密码学实现。
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// 从 `?group=room-1` 形态的 query 取单个参数(不做 percent-decode:group id
/// 的字符集在 edge 侧本就限定为可见 ASCII 且不含 `%`)。
pub fn query_param<'q>(query: Option<&'q str>, name: &str) -> Option<&'q str> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then_some(value)
    })
}

/// 编码一个 binary 帧(服务端→客户端:不掩码,RFC 6455 §5.1)。
fn binary_frame(payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(payload.len() + 10);
    frame.put_u8(0x82); // FIN + opcode=binary
    put_len(&mut frame, payload.len());
    frame.extend_from_slice(payload);
    frame.freeze()
}

fn put_len(frame: &mut BytesMut, len: usize) {
    if len < 126 {
        frame.put_u8(len as u8);
    } else if len <= u16::MAX as usize {
        frame.put_u8(126);
        frame.put_u16(len as u16);
    } else {
        frame.put_u8(127);
        frame.put_u64(len as u64);
    }
}

/// 编码 Close 帧(带状态码与 UTF-8 原因)。
fn close_frame(code: u16, reason: &str) -> Bytes {
    let reason = &reason.as_bytes()[..reason.len().min(MAX_CONTROL_PAYLOAD - 2)];
    let mut frame = BytesMut::with_capacity(reason.len() + 4);
    frame.put_u8(0x88); // FIN + opcode=close
    frame.put_u8((reason.len() + 2) as u8);
    frame.put_u16(code);
    frame.extend_from_slice(reason);
    frame.freeze()
}

/// 编码 Pong(回显客户端 Ping 载荷)。
fn pong_frame(payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(payload.len() + 2);
    frame.put_u8(0x8A);
    frame.put_u8(payload.len() as u8);
    frame.extend_from_slice(payload);
    frame.freeze()
}

/// 治理关闭原因 → WS Close 码(§6.1 语义与 gRPC trailer 对齐:策略封禁=1008,
/// 其余按 1001 going away——浏览器据此决定是否退避重连)。
fn close_code(reason: EdgeCloseReason) -> (u16, &'static str) {
    match reason {
        EdgeCloseReason::Policy => (1008, "policy"),
        EdgeCloseReason::Drain => (1001, "gateway draining"),
        EdgeCloseReason::MaxAge => (1001, "gateway max age"),
        EdgeCloseReason::Idle => (1001, "idle timeout"),
        EdgeCloseReason::SlowConsumer => (1008, "slow consumer"),
        EdgeCloseReason::Normal => (1001, "closed"),
    }
}

/// 桥接握手响应头(101 Switching Protocols)。
pub fn handshake_headers(accept: &str) -> Option<Vec<(HeaderName, HeaderValue)>> {
    Some(vec![
        (http::header::UPGRADE, HeaderValue::from_static("websocket")),
        (
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        ),
        (
            HeaderName::from_static("sec-websocket-accept"),
            HeaderValue::from_str(accept).ok()?,
        ),
    ])
}

/// 升级完成后的桥接主循环。
///
/// # 参数
/// - `upgraded`: 已升级的 TCP 连接。
/// - `subscription`: 已登记的 edge 订阅(与 native 路径同一份索引/ring)。
/// - `guard`: §6.1 注册表守卫(close_by_* / drain 的关闭源;LongProto::Ws 语义)。
/// - `idle_timeout`/`max_lifetime`: route 级治理窗口,0 表示不限。
pub async fn run_bridge(
    upgraded: Upgraded,
    subscription: EdgeSubscription,
    guard: ConnGuard,
    idle_timeout: Duration,
    max_lifetime: Duration,
) {
    let mut io = TokioIo::new(upgraded);
    let mut close_wait = guard.closed();
    let ring = subscription.ring().clone();
    let deadline = (!max_lifetime.is_zero()).then(|| tokio::time::Instant::now() + max_lifetime);
    let mut inbound = [0u8; 1024];
    let mut inbound_buf = BytesMut::new();

    let reason = loop {
        // 空闲预算:0 表示不限,用一个远期 sleep 占位保持 select 分支形状一致。
        let idle = if idle_timeout.is_zero() {
            Duration::from_secs(86_400)
        } else {
            idle_timeout
        };
        let next_frame = std::future::poll_fn(|cx| ring.poll_pop(cx));
        tokio::select! {
            biased;
            // §6.1 注册表关闭:CloseNotified 是 poll 风格(检查码 → 登记 waker → 复查),
            // 封住"检查与登记之间被关闭"的竞态。**必须用 requested_close_code**:
            // ws_close_code() 未关闭时也返回默认 1001,拿它当哨兵会让桥接刚建就自关。
            reason = std::future::poll_fn(|cx| {
                if let Some(code) = guard.requested_close_code() {
                    return std::task::Poll::Ready(code);
                }
                close_wait.subscribe_if_needed(cx);
                match guard.requested_close_code() {
                    Some(code) => std::task::Poll::Ready(code),
                    None => std::task::Poll::Pending,
                }
            }) => {
                break match reason {
                    1008 => EdgeCloseReason::Policy,
                    _ => EdgeCloseReason::Drain,
                };
            }
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            } => break EdgeCloseReason::MaxAge,
            popped = next_frame => {
                match popped {
                    Ok(frame) => {
                        // 与 native 订阅者字节一致:整帧原样进一个 binary 帧。
                        if io.write_all(&binary_frame(&frame.bytes)).await.is_err()
                            || io.flush().await.is_err()
                        {
                            break EdgeCloseReason::Normal;
                        }
                    }
                    Err(reason) => break reason,
                }
            }
            read = tokio::time::timeout(idle, io.read(&mut inbound)) => {
                match read {
                    // 空闲到界:与 native 订阅同一治理语义。
                    Err(_) if !idle_timeout.is_zero() => break EdgeCloseReason::Idle,
                    Err(_) => continue,
                    Ok(Ok(0)) => break EdgeCloseReason::Normal,
                    Ok(Ok(n)) => {
                        inbound_buf.extend_from_slice(&inbound[..n]);
                        if inbound_buf.len() as u64 > MAX_INBOUND_FRAME_BYTES {
                            break EdgeCloseReason::Normal;
                        }
                        match handle_inbound(&mut inbound_buf, &mut io).await {
                            InboundOutcome::Continue => {}
                            InboundOutcome::Closed => break EdgeCloseReason::Normal,
                        }
                    }
                    Ok(Err(_)) => break EdgeCloseReason::Normal,
                }
            }
        }
    };

    // 先摘索引再收尾:与 native 路径同序,关闭期间不再有帧进入本 ring。
    drop(subscription);
    drop(guard);
    let (code, text) = close_code(reason);
    let _ = io.write_all(&close_frame(code, text)).await;
    let _ = io.flush().await;
    let _ = io.shutdown().await;
}

enum InboundOutcome {
    Continue,
    Closed,
}

/// 解析入站帧:Close→回 Close 并结束;Ping→回 Pong;数据帧丢弃(v1 无上行语义)。
async fn handle_inbound<I>(buf: &mut BytesMut, io: &mut I) -> InboundOutcome
where
    I: tokio::io::AsyncWrite + Unpin,
{
    loop {
        let Some((opcode, payload, consumed)) = parse_frame(buf) else {
            return InboundOutcome::Continue;
        };
        let _ = buf.split_to(consumed);
        match opcode {
            0x8 => return InboundOutcome::Closed,
            0x9 if io.write_all(&pong_frame(&payload)).await.is_err()
                || io.flush().await.is_err() =>
            {
                return InboundOutcome::Closed
            }
            // Ping 已回 Pong;0xA=Pong 与数据帧在 v1 无上行语义,静默丢弃。
            _ => {}
        }
    }
}

/// 解析一个完整入站帧,返回 (opcode, 已解掩码的 payload, 消费字节数)。
/// 不完整返回 None(等更多字节)。客户端帧必须掩码(RFC 6455 §5.1),
/// 未掩码视为协议错——但 v1 只丢弃它,不做协议惩罚。
fn parse_frame(buf: &BytesMut) -> Option<(u8, Vec<u8>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let len_flag = (buf[1] & 0x7f) as usize;
    let mut cursor = 2usize;
    let payload_len = match len_flag {
        126 => {
            if buf.len() < cursor + 2 {
                return None;
            }
            let len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
            cursor += 2;
            len
        }
        127 => {
            if buf.len() < cursor + 8 {
                return None;
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[cursor..cursor + 8]);
            cursor += 8;
            u64::from_be_bytes(raw) as usize
        }
        other => other,
    };
    let mask = if masked {
        if buf.len() < cursor + 4 {
            return None;
        }
        let mask = [
            buf[cursor],
            buf[cursor + 1],
            buf[cursor + 2],
            buf[cursor + 3],
        ];
        cursor += 4;
        Some(mask)
    } else {
        None
    };
    if buf.len() < cursor + payload_len {
        return None;
    }
    let mut payload = buf[cursor..cursor + payload_len].to_vec();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Some((opcode, payload, cursor + payload_len))
}

/// 桥接握手所需的请求校验:必须是 HTTP/1.1 GET + 合法 WS 升级头。
pub fn upgrade_key(parts: &http::request::Parts) -> Option<String> {
    if parts.version != http::Version::HTTP_11 || parts.method != http::Method::GET {
        return None;
    }
    let upgrade_ok = parts
        .headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection_ok = parts
        .headers
        .get(http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    let version_ok = parts
        .headers
        .get("sec-websocket-version")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "13");
    if !upgrade_ok || !connection_ok || !version_ok {
        return None;
    }
    parts
        .headers
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
