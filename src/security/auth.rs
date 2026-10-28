//! 认证相关的轻量工具。
//!
//! 先服务 HTTP Basic、Bearer token 与 API-Key 这类不需要 body 的认证方式;这些校验必须能在上游前短路,
//! 避免破坏数据面零拷贝/少拷贝路径。

use http::HeaderMap;

/// 业务作用：常量时间字节串比较,避免凭据校验出现明显早停时序差异。
///
/// 参数说明：
/// - `left`: 左侧字节串。
/// - `right`: 右侧字节串。
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for idx in 0..left.len().max(right.len()) {
        let a = left.get(idx).copied().unwrap_or_default();
        let b = right.get(idx).copied().unwrap_or_default();
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

/// 业务作用：判断 `Authorization: Basic ...` 是否匹配期望的 `user:password` 字节串。
///
/// 参数说明：
/// - `headers`: 请求头集合。
/// - `expected`: 构建期拼好的 `user:password` 字节串。
pub fn basic_authorization_matches(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(value) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let mut parts = value.trim().splitn(2, char::is_whitespace);
    let Some(scheme) = parts.next() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Some(encoded) = parts.next() else {
        return false;
    };
    let Some(decoded) = decode_base64(encoded.trim()) else {
        return false;
    };
    constant_time_eq(decoded.as_slice(), expected)
}

/// 业务作用：判断 `Authorization: Bearer ...` 是否匹配期望 token。
///
/// 参数说明：
/// - `headers`: 请求头集合。
/// - `expected`: 构建期保存的 token 字节串。
pub fn bearer_authorization_matches(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(value) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let mut parts = value.trim().splitn(2, char::is_whitespace);
    let Some(scheme) = parts.next() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let Some(token) = parts.next() else {
        return false;
    };
    constant_time_eq(token.trim().as_bytes(), expected)
}

/// 业务作用：生成 header quoted-string 可用的值。
///
/// 参数说明：
/// - `value`: 原始 header 参数值。
pub fn escape_header_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 业务作用：解码 Basic Auth 使用的 base64 字符串。
///
/// 参数说明：
/// - `raw`: `Authorization: Basic` 后的 base64 载荷。
fn decode_base64(raw: &str) -> Option<Vec<u8>> {
    let clean = raw.trim();
    if clean.is_empty() || !clean.len().is_multiple_of(4) {
        return None;
    }
    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let chunk_count = bytes.len() / 4;
    for (chunk_idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut value = 0_u32;
        for (idx, byte) in chunk.iter().enumerate() {
            let sextet = if *byte == b'=' {
                if idx < 2
                    || chunk_idx + 1 != chunk_count
                    || chunk[idx..].iter().any(|b| *b != b'=')
                {
                    return None;
                }
                0
            } else {
                base64_value(*byte)? as u32
            };
            value = (value << 6) | sextet;
        }
        out.push(((value >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((value >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((value & 0xff) as u8);
        }
    }
    Some(out)
}

/// 业务作用：取 base64 字符的 6-bit 值。
///
/// 参数说明：
/// - `byte`: base64 字符。
fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
