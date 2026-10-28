//! 路径只在构建期展开为受限原生正则；不在数据面部署第二套配置解释器。
use anyhow::{ensure, Result};

/// 业务作用：把可证明等价的 Spring 路径片段编译为原始 URI 正则，保留百分号编码与 matrix 参数语义。
///
/// 参数说明：
/// - `patterns`：1..16 个绝对路径模式。
/// - `trailing`：来源的尾斜杠选项，true 的跨实现语义不稳定而拒绝。
///
/// 返回：有界全串正则；仅支持普通 ASCII 字面量、完整变量段、完整星号段与末尾双星号。
pub(super) fn paths(patterns: &[String], trailing: Option<bool>) -> Result<String> {
    ensure!(
        trailing != Some(true),
        "SCG Path matchTrailingSlash=true is not losslessly portable; use false and explicit native path alternatives"
    );
    let mut alternatives = Vec::new();
    for pattern in patterns {
        ensure!(
            pattern.len() <= 512 && pattern.starts_with('/') && !pattern.contains("//"),
            "SCG Path requires a bounded absolute pattern without empty interior segments"
        );
        let mut result = String::new();
        if pattern == "/" {
            alternatives.push("/".to_owned());
            continue;
        }
        let segments = pattern[1..].split('/').collect::<Vec<_>>();
        for (i, segment) in segments.iter().enumerate() {
            if *segment == "**" {
                ensure!(
                    i + 1 == segments.len(),
                    "SCG Path double wildcard must be last; use explicit native PathRegex for other patterns"
                );
                result.push_str("(?:/.*)?");
                continue;
            }
            result.push('/');
            if segment.is_empty() {
                ensure!(i + 1 == segments.len(), "SCG Path empty segment");
                continue;
            }
            if *segment == "*" {
                result.push_str("[^/;]*");
            } else if segment.starts_with('{') && segment.ends_with('}') {
                let name = &segment[1..segment.len() - 1];
                ensure!(
                    !name.is_empty()
                        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                    "SCG Path variable constraints require native PathRegex and explicit variable extraction"
                );
                result.push_str("[^/;]+");
            } else {
                ensure!(
                    *segment != "."
                        && *segment != ".."
                        && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)),
                    "SCG Path mixed wildcards, constrained variables or encoded patterns require explicit native PathRegex"
                );
                for byte in segment.bytes() {
                    result.push_str("(?:");
                    result.push_str(&regex::escape(&(byte as char).to_string()));
                    result.push('|');
                    result.push('%');
                    for c in format!("{byte:02X}").chars() {
                        if c.is_ascii_alphabetic() {
                            result.push('[');
                            result.push(c);
                            result.push(c.to_ascii_lowercase());
                            result.push(']');
                        } else {
                            result.push(c);
                        }
                    }
                    result.push(')');
                }
            }
            result.push_str("(?:;[^/]*)?");
        }
        alternatives.push(result);
    }
    let result = format!("\\A(?:{})\\z", alternatives.join("|"));
    ensure!(
        result.len() <= 32768,
        "SCG expanded Path exceeds regex budget"
    );
    regex::RegexBuilder::new(&result)
        .size_limit(2 << 20)
        .build()
        .map_err(|_| anyhow::anyhow!("SCG Path expansion exceeds native regex limits"))?;
    Ok(result)
}

/// 业务作用：限制 Java 正则到无引擎差异的 ASCII 子集，并强制整串匹配而非子串搜索。
///
/// 参数说明：
/// - `raw`：来源模式。
///
/// 返回：适合原生 Header 匹配器的表达式；高级标志、Unicode 类、回溯引用和控制语义拒绝。
pub(super) fn header_regex(raw: &str) -> Result<String> {
    ensure!(
        raw.len() <= 1024
            && raw.is_ascii()
            && !raw.contains("(?")
            && !raw.contains("&&")
            && !raw.contains("[^")
            && !raw.contains("++")
            && !raw.contains("*+")
            && !raw.contains("?+")
            && !raw.contains("}+"),
        "SCG Header Java regex extensions require an explicit native Header regex"
    );
    let mut result = String::from("\\A(?:");
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escape = chars
                .next()
                .ok_or_else(|| anyhow::anyhow!("SCG regex escape is incomplete"))?;
            match escape {
                'd' => result.push_str("[0-9]"),
                'w' => result.push_str("[A-Za-z0-9_]"),
                '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$'
                | '\\' => {
                    result.push('\\');
                    result.push(escape);
                }
                _ => anyhow::bail!(
                    "SCG Header regex escape is not portable; use explicit native Header regex"
                ),
            }
        } else {
            ensure!(
                !c.is_control() && c != '.',
                "SCG Header wildcard or control semantics require explicit native Header regex"
            );
            result.push(c);
        }
    }
    result.push_str(")\\z");
    regex::Regex::new(&result).map_err(|_| {
        anyhow::anyhow!("SCG Header regex is not supported by native bounded matching")
    })?;
    Ok(result)
}
