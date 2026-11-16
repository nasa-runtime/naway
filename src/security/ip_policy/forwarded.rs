//! Forwarded 与 XFF 共享同一有界信任链。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::segments::Segments;
use http::request::Parts;

use crate::config::ip_policy::ForwardedHeader;
use crate::io::net::{any_contains, canonical_ip, Cidr};

/// 业务作用：为未声明来源策略的既有配置保持 XFF 行为，不隐式新增 Forwarded 信任。
///
/// 参数说明：
/// - `parts`：原始请求。
/// - `trusted`：当前入口已授予信任的代理网段。
///
/// 返回：最近非可信的有效 XFF 地址；没有可用地址时由调用方继续使用连接地址。
pub(super) fn legacy_xff(parts: &Parts, trusted: &[Cidr]) -> Option<IpAddr> {
    let value = parts.headers.get("x-forwarded-for")?.to_str().ok()?;
    for entry in value.rsplit(',') {
        if let Ok(ip) = entry.trim().parse::<IpAddr>() {
            if !any_contains(trusted, ip) {
                return Some(canonical_ip(ip));
            }
        }
    }
    None
}

/// 业务作用：把所有同名来源头合成固定容量的借用链，并从最近代理向客户端复验。
///
/// 参数说明：
/// - `parts`：原始请求头。
/// - `trusted`：当前入口信任的代理网段。
/// - `maximum`：已经构建期验证的 1 至 64 元素上限。
/// - `header`：配置明确选择的来源头，不接受另一种头补齐身份。
///
/// 返回：最近非可信地址；缺少选定头、没有客户端地址、坏编码、歧义或超限时返回错误。
pub(super) fn resolve(
    parts: &Parts,
    trusted: &[Cidr],
    maximum: usize,
    header: ForwardedHeader,
) -> Result<Option<IpAddr>, ()> {
    let standardized = header == ForwardedHeader::Forwarded;
    let name = if standardized {
        "forwarded"
    } else {
        "x-forwarded-for"
    };
    let mut entries = [None; 64];
    let mut count = 0;
    for value in parts.headers.get_all(name) {
        let value = value.to_str().map_err(|_| ())?;
        for entry in Segments::new(value, b',') {
            let entry = entry?;
            if count == maximum || entry.trim().is_empty() {
                // 不用截断链或另一种头补齐身份；缺少完整证据时拒绝代理来源声明。
                return Err(());
            }
            entries[count] = Some(entry.trim());
            count += 1;
        }
    }
    if count == 0 {
        // 显式来源策略不能用缺失头回落到可能拥有更宽权限的代理地址。
        return Err(());
    }
    for entry in entries[..count].iter().rev() {
        let entry = entry.ok_or(())?;
        let ip = if standardized {
            forwarded_for(entry)?
        } else {
            entry.parse().map_err(|_| ())?
        };
        if !any_contains(trusted, ip) {
            return Ok(Some(canonical_ip(ip)));
        }
    }
    Err(())
}

/// 业务作用：解析单个 Forwarded 元素的唯一 for 参数，不把 obfuscated 或 unknown 当成客户端。
///
/// 参数说明：
/// - `entry`：一个逗号分隔的来源元素。
///
/// 返回：唯一合法的 IPv4/IPv6 地址；重复 for、缺失、坏引号或非地址表示返回错误。
fn forwarded_for(entry: &str) -> Result<IpAddr, ()> {
    let mut address = None;
    let mut names = [None; 16];
    let mut count = 0;
    for parameter in Segments::new(entry, b';') {
        let parameter = parameter?.trim();
        if parameter.is_empty() {
            continue;
        }
        let (key, value) = parameter.split_once('=').ok_or(())?;
        let key = key.trim();
        let value = value.trim();
        if count == names.len() || key.len() > 64 || !is_token(key) || value.len() > 1024 {
            return Err(());
        }
        if names[..count]
            .iter()
            .flatten()
            .any(|name: &&str| name.eq_ignore_ascii_case(key))
        {
            // 任意参数重复都会失去唯一解释，不允许不同解析器选择不同 for、host 或 proto。
            return Err(());
        }
        names[count] = Some(key);
        count += 1;
        let value = parameter_value(value)?;
        if !key.eq_ignore_ascii_case("for") {
            continue;
        }
        address = Some(parse_address(value)?);
    }
    address.ok_or(())
}

/// 业务作用：解析来源地址及可选端口，只保留经过语法验证的 IP。
///
/// 参数说明：
/// - `value`：已解除外层引号的 for 值。
///
/// 返回：合法字面 IP 或带端口地址；域名、未知标记、端口越界和残余文本返回错误。
fn parse_address(value: &str) -> Result<IpAddr, ()> {
    if let Ok(ip) = value.parse::<Ipv4Addr>() {
        return Ok(IpAddr::V4(ip));
    }
    if let Some(bracketed) = value.strip_prefix('[') {
        let (address, port) = bracketed.split_once(']').ok_or(())?;
        let ip = address
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| ())?;
        if !port.is_empty() {
            validate_port(port.strip_prefix(':').ok_or(())?)?;
        }
        return Ok(ip);
    }
    let (address, port) = value.split_once(':').ok_or(())?;
    validate_port(port)?;
    address.parse::<Ipv4Addr>().map(IpAddr::V4).map_err(|_| ())
}

/// 业务作用：验证端口表示而不把端口纳入 IP 权限，允许协议规定的 obfuscated port。
///
/// 参数说明：
/// - `value`：节点标识冒号后的完整端口文本。
///
/// 返回：u16 十进制端口或非空下划线标识合法，其它文本返回错误。
fn validate_port(value: &str) -> Result<(), ()> {
    if (!value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok())
        || value.strip_prefix('_').is_some_and(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Ok(());
    }
    Err(())
}

/// 业务作用：验证参数值的 token 或 quoted-string 外层，保留原始切片供地址解析。
///
/// 参数说明：
/// - `value`：去除外侧空白后的完整参数值。
///
/// 返回：合法时借用 token 或引号内部；坏引号、控制字节和非法 token 返回错误。
fn parameter_value(value: &str) -> Result<&str, ()> {
    if let Some(quoted) = value.strip_prefix('"') {
        let quoted = quoted.strip_suffix('"').ok_or(())?;
        let mut escaped = false;
        for byte in quoted.bytes() {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' || (byte < 32 && byte != b'\t') || byte == 127 {
                return Err(());
            }
        }
        return (!escaped).then_some(quoted).ok_or(());
    }
    is_token(value).then_some(value).ok_or(())
}

/// 业务作用：限定 HTTP 参数名称和值的 token 字符，不接受分隔符突破字段边界。
///
/// 参数说明：
/// - `value`：待验证的 ASCII token。
///
/// 返回：非空且全部字符属于 HTTP token 时为 true。
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}
