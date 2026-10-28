//! 有界 Java Properties 文本解码；仅形成声明树，不执行占位符或 Spring 表达式。
use anyhow::{ensure, Context, Result};
use serde_json::{Map, Value};

enum Part {
    Key(String),
    Index(usize),
}

/// 业务作用：将 UTF-8 Properties 的转义、续行和索引声明转换为与 YAML 相同的配置树。
///
/// 参数说明：
/// - `bytes`：最多 1MiB 的文件原文。
///
/// 返回：无重复键、无冲突形态的文档；未知业务属性由同一强类型翻译器拒绝。
pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() <= super::MAX_SOURCE_BYTES,
        "SCG properties exceeds byte budget"
    );
    let text = std::str::from_utf8(bytes)
        .context("SCG properties must be UTF-8; use Unicode escapes for legacy encodings")?;
    let mut root = Value::Null;
    let mut logical = String::new();
    let mut continued = false;
    let mut count = 0usize;
    for physical in text.lines() {
        let line = physical.trim_start_matches([' ', '\t', '\u{c}']);
        if !continued && (line.is_empty() || line.starts_with(['#', '!'])) {
            continue;
        }
        logical.push_str(line);
        ensure!(
            logical.len() <= 16384,
            "SCG properties logical line exceeds 16KiB"
        );
        let trailing = logical
            .as_bytes()
            .iter()
            .rev()
            .take_while(|b| **b == b'\\')
            .count();
        continued = trailing % 2 == 1;
        if continued {
            logical.pop();
            continue;
        }
        count += 1;
        ensure!(count <= 8192, "SCG properties entry count exceeds 8192");
        let (key, value) = split(&logical)?;
        let parts = path(&unescape(key)?)?;
        insert(&mut root, &parts, Value::String(unescape(value)?))?;
        logical.clear();
    }
    ensure!(!continued, "SCG properties has an incomplete continuation");
    ensure!(count > 0, "SCG properties is empty");
    Ok(root)
}

/// 业务作用：识别首个未转义分隔符，保留值中的空格、等号和冒号。
///
/// 参数说明：
/// - `line`：已合并续行的单条声明。
///
/// 返回：原始键和值切片；缺少键拒绝。
fn split(line: &str) -> Result<(&str, &str)> {
    let mut escaped = false;
    let mut separator = None;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if matches!(c, '=' | ':' | ' ' | '\t' | '\u{c}') {
            separator = Some(i);
            break;
        }
    }
    let (key, rest) = separator.map_or((line, ""), |i| (&line[..i], &line[i..]));
    ensure!(!key.is_empty(), "SCG properties key is empty");
    let rest = rest.trim_start_matches([' ', '\t', '\u{c}']);
    let rest = rest
        .strip_prefix(['=', ':'])
        .unwrap_or(rest)
        .trim_start_matches([' ', '\t', '\u{c}']);
    Ok((key, rest))
}

/// 业务作用：按 Properties 字符与 UTF-16 转义规则解码，拒绝孤立代理项和残缺转义。
///
/// 参数说明：
/// - `raw`：单个原始键或值。
///
/// 返回：合法 Unicode 字符串，不做任何环境或引用展开。
fn unescape(raw: &str) -> Result<String> {
    let mut chars = raw.chars();
    let mut units = Vec::new();
    while let Some(c) = chars.next() {
        let value = if c == '\\' {
            match chars
                .next()
                .context("SCG properties escape is incomplete")?
            {
                'u' => {
                    let mut value = 0u16;
                    for _ in 0..4 {
                        let digit = chars
                            .next()
                            .and_then(|c| c.to_digit(16))
                            .context("SCG Unicode escape requires four hex digits")?;
                        value = (value << 4) | digit as u16;
                    }
                    units.push(value);
                    continue;
                }
                't' => '\t',
                'n' => '\n',
                'r' => '\r',
                'f' => '\u{c}',
                other => other,
            }
        } else {
            c
        };
        let mut buf = [0u16; 2];
        units.extend_from_slice(value.encode_utf16(&mut buf));
    }
    String::from_utf16(&units).context("SCG properties contains an unpaired Unicode surrogate")
}

/// 业务作用：把固定层级和有界列表索引解析为结构路径，args 后的点属于参数名而非新层级。
///
/// 参数说明：
/// - `key`：已经转义解码的 Properties 键。
///
/// 返回：最多 16 层路径；空段、非规范索引和未知括号形态拒绝。
fn path(key: &str) -> Result<Vec<Part>> {
    ensure!(
        key.len() <= 1024 && key.is_ascii(),
        "SCG property key must be bounded ASCII"
    );
    let mut rest = key;
    let mut parts = Vec::new();
    while !rest.is_empty() {
        ensure!(parts.len() < 16, "SCG property path exceeds depth limit");
        let end = rest.find(['.', '[']).unwrap_or(rest.len());
        let name = &rest[..end];
        ensure!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "SCG property path contains invalid segment"
        );
        parts.push(Part::Key(name.to_owned()));
        rest = &rest[end..];
        if name == "args" {
            let argument = if let Some(s) = rest.strip_prefix('.') {
                s.to_owned()
            } else if rest.starts_with('[') && rest.ends_with(']') {
                rest[1..rest.len() - 1].to_owned()
            } else {
                anyhow::bail!("SCG args requires a named parameter")
            };
            ensure!(
                !argument.is_empty()
                    && argument
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "SCG argument property key is invalid"
            );
            parts.push(Part::Key(argument));
            break;
        }
        if rest.starts_with('[') {
            let end = rest
                .find(']')
                .context("SCG property list index is incomplete")?;
            let raw = &rest[1..end];
            let index = raw
                .parse::<usize>()
                .context("SCG property list index is invalid")?;
            ensure!(
                index < 256 && raw == index.to_string(),
                "SCG property list index exceeds bounds or is noncanonical"
            );
            parts.push(Part::Index(index));
            rest = &rest[end + 1..];
        }
        if !rest.is_empty() {
            rest = rest
                .strip_prefix('.')
                .context("SCG property path is invalid")?;
            ensure!(
                !rest.is_empty(),
                "SCG property path ends in an empty segment"
            );
        }
    }
    Ok(parts)
}

/// 业务作用：插入唯一结构位置，拒绝重复属性、标量与容器冲突，不接受后写覆盖。
///
/// 参数说明：
/// - `target`：尚未发布的文档节点。
/// - `parts`：已验证且深度有界的路径。
/// - `value`：单个字面量值。
///
/// 返回：成功插入，或冲突时拒绝整份来源；数组空洞留待强类型模型拒绝。
fn insert(target: &mut Value, parts: &[Part], value: Value) -> Result<()> {
    let Some((first, rest)) = parts.split_first() else {
        ensure!(
            target.is_null(),
            "SCG properties contains a duplicate or conflicting key"
        );
        *target = value;
        return Ok(());
    };
    match first {
        Part::Key(key) => {
            if target.is_null() {
                *target = Value::Object(Map::new());
            }
            let map = target
                .as_object_mut()
                .context("SCG properties object conflicts with scalar/list")?;
            insert(map.entry(key).or_insert(Value::Null), rest, value)
        }
        Part::Index(index) => {
            if target.is_null() {
                *target = Value::Array(Vec::new());
            }
            let array = target
                .as_array_mut()
                .context("SCG properties list conflicts with scalar/object")?;
            if array.len() <= *index {
                array.resize(index + 1, Value::Null);
            }
            insert(&mut array[*index], rest, value)
        }
    }
}
