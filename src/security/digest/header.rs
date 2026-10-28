//! Digest 凭据的有界借用解析；只有 quoted-pair 需要构造解转义文本。

use http::HeaderMap;
use std::borrow::Cow;

pub(super) struct Credentials<'a> {
    fields: [Option<Cow<'a, str>>; 11],
}

const NAMES: [&str; 11] = [
    "username",
    "realm",
    "nonce",
    "uri",
    "response",
    "cnonce",
    "opaque",
    "algorithm",
    "qop",
    "nc",
    "userhash",
];

impl<'a> Credentials<'a> {
    /// 业务作用：严格解析唯一 Digest 认证头，拒绝歧义字段，避免不同中间层产生不同认证结论。
    /// 参数说明：
    /// - `headers`：未经插件改写的下游请求头。
    ///
    /// 返回：所有必需字段及引号语义合法时返回借用视图；缺失、重复或超限返回 None。
    pub(super) fn parse(headers: &'a HeaderMap) -> Option<Self> {
        let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
        let raw = values.next()?.to_str().ok()?;
        if values.next().is_some() || raw.len() > 8192 {
            return None;
        }
        let (scheme, mut rest) = raw.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Digest") {
            return None;
        }
        let mut fields = std::array::from_fn(|_| None);
        loop {
            rest = rest.trim_start_matches([' ', '\t']);
            let end = rest.bytes().take_while(|byte| token(*byte)).count();
            let name = rest.get(..end)?;
            let index = NAMES
                .iter()
                .position(|candidate| name.eq_ignore_ascii_case(candidate))?;
            if fields[index].is_some() {
                return None;
            }
            rest = rest[end..]
                .trim_start_matches([' ', '\t'])
                .strip_prefix('=')?
                .trim_start_matches([' ', '\t']);
            let quoted = rest.starts_with('"');
            if quoted != (index < 7) {
                return None;
            }
            let value = if quoted {
                rest = &rest[1..];
                let bytes = rest.as_bytes();
                let mut end = 0;
                let mut escaped = false;
                while end < bytes.len() && bytes[end] != b'"' {
                    if !(0x20..=0x7e).contains(&bytes[end]) {
                        return None;
                    }
                    if bytes[end] == b'\\' {
                        escaped = true;
                        end += 1;
                        if !bytes
                            .get(end)
                            .is_some_and(|byte| (0x20..=0x7e).contains(byte))
                        {
                            return None;
                        }
                    }
                    end += 1;
                }
                if bytes.get(end) != Some(&b'"') {
                    return None;
                }
                let value = &rest[..end];
                rest = &rest[end + 1..];
                if escaped {
                    let mut decoded = String::with_capacity(value.len());
                    let mut bytes = value.bytes();
                    while let Some(byte) = bytes.next() {
                        decoded.push(if byte == b'\\' {
                            bytes.next()?
                        } else {
                            byte
                        } as char);
                    }
                    Cow::Owned(decoded)
                } else {
                    Cow::Borrowed(value)
                }
            } else {
                let end = rest.bytes().take_while(|byte| token(*byte)).count();
                if end == 0 {
                    return None;
                }
                let value = &rest[..end];
                rest = &rest[end..];
                Cow::Borrowed(value)
            };
            fields[index] = Some(value);
            rest = rest.trim_start_matches([' ', '\t']);
            if rest.is_empty() {
                break;
            }
            rest = rest.strip_prefix(',')?;
            if rest.trim().is_empty() {
                return None;
            }
        }
        if fields[..10].iter().any(Option::is_none) {
            return None;
        }
        Some(Self {
            fields,
        })
    }

    /// 业务作用：借用固定协议字段，调用方无需复制认证头或建立动态键表。
    /// 参数说明：
    /// - `name`：解析器定义的字段名。
    ///
    /// 返回：已解析字段；未提供的可选字段为空字符串。
    pub(super) fn get(&self, name: &str) -> &str {
        NAMES
            .iter()
            .position(|candidate| *candidate == name)
            .and_then(|index| self.fields[index].as_deref())
            .unwrap_or("")
    }
}

/// 业务作用：限定 HTTP token 字符，分隔符与控制字符不能混入字段名或无引号值。
/// 参数说明：
/// - `byte`：当前 ASCII 字节。
///
/// 返回：属于 HTTP token 字母表时为 true。
fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
