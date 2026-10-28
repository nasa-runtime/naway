//! 请求内容解码策略的构建期校验。

use super::Policy;
use anyhow::{ensure, Context, Result};
use std::collections::BTreeMap;

/// 业务作用：将显式请求解压声明编译为有硬边界的策略，坏配置不得进入数据面。
///
/// 参数说明：
/// - `args`：移除指令名称后的配置内容。
///
/// 返回：合法策略；off 返回 None，未知或重复选项拒绝候选配置。
pub(crate) fn parse(args: &str) -> Result<Option<Policy>> {
    if args.trim().eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let mut options = BTreeMap::new();
    for token in args.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .context("request_decompression requires named options")?;
        ensure!(
            [
                "algorithms",
                "max_encoded_bytes",
                "max_decoded_bytes",
                "max_ratio",
                "timeout_ms",
                "chunk_bytes"
            ]
            .contains(&key),
            "unsupported request_decompression option"
        );
        ensure!(
            !value.is_empty() && options.insert(key, value).is_none(),
            "empty or duplicate request_decompression option"
        );
    }
    let algorithms = options.get("algorithms").copied().unwrap_or("gzip,br");
    let mut gzip = false;
    let mut brotli = false;
    for coding in algorithms.split(',') {
        match coding {
            "gzip" if !gzip => gzip = true,
            "br" if !brotli => brotli = true,
            _ => anyhow::bail!("request_decompression supports unique gzip,br algorithms"),
        }
    }
    let encoded = bytes(options.get("max_encoded_bytes").copied().unwrap_or("16m"))?;
    let decoded = bytes(options.get("max_decoded_bytes").copied().unwrap_or("64m"))?;
    let chunk = bytes(options.get("chunk_bytes").copied().unwrap_or("16k"))?;
    let ratio = options
        .get("max_ratio")
        .copied()
        .unwrap_or("100")
        .parse::<u64>()
        .context("invalid decompression max_ratio")?;
    let timeout_ms = options
        .get("timeout_ms")
        .copied()
        .unwrap_or("30000")
        .parse::<u64>()
        .context("invalid decompression timeout_ms")?;
    ensure!(
        (1..=1 << 30).contains(&encoded) && (1..=1 << 30).contains(&decoded),
        "decompression byte limits must be 1..1GiB"
    );
    ensure!(
        (1024..=65536).contains(&chunk),
        "decompression chunk_bytes must be 1..64KiB"
    );
    ensure!(
        (1..=1000).contains(&ratio),
        "decompression max_ratio must be 1..1000"
    );
    ensure!(
        (1..=300_000).contains(&timeout_ms),
        "decompression timeout_ms must be 1..300000"
    );
    Ok(Some(Policy {
        gzip,
        brotli,
        encoded,
        decoded,
        ratio,
        timeout_ms,
        chunk: chunk as usize,
    }))
}

/// 业务作用：解析整数二进制字节预算，拒绝负数、溢出与隐式小数舍入。
///
/// 参数说明：
/// - `raw`：十进制整数，可带 k/m/g 后缀。
///
/// 返回：完整字节数或配置错误。
fn bytes(raw: &str) -> Result<u64> {
    let (number, scale) = match raw.as_bytes().last() {
        Some(b'k' | b'K') => (&raw[..raw.len() - 1], 1_u64 << 10),
        Some(b'm' | b'M') => (&raw[..raw.len() - 1], 1_u64 << 20),
        Some(b'g' | b'G') => (&raw[..raw.len() - 1], 1_u64 << 30),
        _ => (raw, 1),
    };
    ensure!(
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid decompression byte limit"
    );
    number
        .parse::<u64>()?
        .checked_mul(scale)
        .context("decompression byte limit overflow")
}
