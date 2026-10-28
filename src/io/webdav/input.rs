//! WebDAV 资源地址和 XML 的共同输入门；代理与本地模式使用同一规范化规则。

use crate::config::model::ServerLimitsCfg;
use crate::config::webdav::WebDavCfg;
use anyhow::{bail, ensure, Context, Result};
use http::{request::Parts, HeaderMap, Uri};
use quick_xml::events::Event;

/// 业务作用：读取唯一的协议控制头，避免前后端对重复头采用不同条件。
///
/// 参数说明：
/// - `headers`：已通过入口通用检查的请求头。
/// - `name`：固定 WebDAV 控制头名称。
///
/// 返回：唯一的可见 ASCII 值；重复、控制字符或超过 4096 字节时拒绝。
pub(super) fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    ensure!(values.next().is_none(), "duplicate WebDAV control header");
    let value = value.to_str()?;
    ensure!(
        value.len() <= 4096 && value.bytes().all(|b| (0x20..0x7f).contains(&b)),
        "invalid WebDAV control header"
    );
    Ok(Some(value))
}

/// 业务作用：按完整路径段边界剥离挂载点，防止同前缀其它根被视为当前资源。
///
/// 参数说明：
/// - `path`：已经规范化的资源路径。
/// - `prefix`：构建期验证的挂载前缀。
///
/// 返回：以斜杠开头的相对资源路径；不属于挂载点时拒绝。
pub(super) fn suffix<'a>(path: &'a str, prefix: &str) -> Result<&'a str> {
    if prefix == "/" {
        return Ok(path);
    }
    let suffix = path
        .strip_prefix(prefix)
        .context("WebDAV resource outside mount")?;
    ensure!(
        suffix.is_empty() || suffix.starts_with('/'),
        "WebDAV resource outside mount boundary"
    );
    Ok(if suffix.is_empty() {
        "/"
    } else {
        suffix
    })
}

/// 业务作用：把已验证资源映射到一个固定前缀，不再解释资源中的模板或编码。
///
/// 参数说明：
/// - `path`：规范化源路径。
/// - `from`：源挂载点。
/// - `to`：目标挂载点。
///
/// 返回：保留相对资源与尾斜杠的目标路径；跨根时拒绝。
pub(super) fn map_path(path: &str, from: &str, to: &str) -> Result<String> {
    let rest = suffix(path, from)?;
    Ok(if to == "/" {
        rest.to_string()
    } else {
        format!("{to}{rest}")
    })
}

/// 业务作用：让 Destination、If tagged resource 与主请求经过同一入口路径规范化。
///
/// 参数说明：
/// - `raw`：客户端提供的资源 URI。
/// - `parts`：原始请求 head，提供当前公开 authority。
/// - `scheme`：入口实际 HTTP scheme，不读取代理伪造头。
/// - `cfg`：挂载点及深度预算。
///
/// 返回：同 authority、同挂载点的规范路径；query、fragment、越域或危险编码均拒绝。
pub(super) fn resource(raw: &str, parts: &Parts, scheme: &str, cfg: &WebDavCfg) -> Result<String> {
    ensure!(
        raw.len() <= 4096 && !raw.contains('#'),
        "invalid WebDAV resource URI"
    );
    let uri: Uri = raw.parse()?;
    ensure!(
        uri.query().is_none(),
        "WebDAV resources cannot contain query"
    );
    if let Some(authority) = uri.authority() {
        let expected = parts
            .uri
            .authority()
            .map(|a| a.as_str())
            .or(single(&parts.headers, "host")?)
            .context("WebDAV request has no authority")?;
        // Destination 只允许改写同一公开站点内的资源，不能成为跨主机写入或 SSRF 跳板。
        ensure!(
            uri.scheme_str() == Some(scheme)
                && authority.as_str().eq_ignore_ascii_case(expected)
                && !authority.as_str().contains('@'),
            "cross-origin WebDAV resource is forbidden"
        );
    } else {
        ensure!(
            uri.scheme().is_none() && raw.starts_with('/') && !raw.starts_with("//"),
            "invalid relative WebDAV resource"
        );
    }
    let (mut normalized, _) = http::Request::new(()).into_parts();
    normalized.uri = uri;
    let limits = ServerLimitsCfg {
        max_path_bytes: 4096,
        max_path_segments: 64,
        ..Default::default()
    };
    ensure!(
        crate::proxy::normalize_request_path(&mut normalized, &limits),
        "unsafe WebDAV resource path"
    );
    let path = normalized.uri.path();
    let rest = suffix(path, &cfg.mount_prefix)?;
    ensure!(
        rest.split('/').filter(|s| !s.is_empty()).count() <= cfg.max_path_depth,
        "WebDAV path depth exceeded"
    );
    // 解码只用于检查文件名；实际协议 URI 保持规范编码，文件系统层仍独立检查组件。
    let decoded = percent_encoding::percent_decode_str(rest).decode_utf8()?;
    ensure!(
        !decoded.split('/').any(|s| s.starts_with('.')),
        "WebDAV dot resources are forbidden"
    );
    Ok(path.to_string())
}

/// 业务作用：在任何资源副作用前验证方法与条件头的有限控制面。
///
/// 参数说明：
/// - `parts`：原始请求 head。
/// - `scheme`：真实入口 scheme。
/// - `cfg`：路由方法和资源预算。
///
/// 返回：所有声明满足受限 DAV 合同时成功；不解析或读取实体。
pub(super) fn validate_head(parts: &Parts, scheme: &str, cfg: &WebDavCfg) -> Result<()> {
    ensure!(
        cfg.methods.iter().any(|m| m == parts.method.as_str()),
        "WebDAV method is not allowed"
    );
    resource(parts.uri.path(), parts, scheme, cfg)?;
    ensure!(
        parts.uri.query().is_none(),
        "WebDAV resource query is unsupported"
    );
    ensure!(
        !parts.headers.contains_key("content-range")
            && !parts.headers.contains_key("x-update-range")
            && !parts.headers.contains_key("x-expected-entity-length"),
        "partial WebDAV writes are unsupported"
    );
    ensure!(
        !parts.headers.contains_key("content-encoding"),
        "encoded WebDAV entity is unsupported"
    );
    let depth = single(&parts.headers, "depth")?;
    ensure!(
        depth.is_none_or(|d| matches!(d, "0" | "1" | "infinity")),
        "invalid WebDAV Depth"
    );
    match parts.method.as_str() {
        "PROPFIND" => ensure!(
            matches!(depth, Some("0" | "1")),
            "PROPFIND requires bounded Depth 0 or 1"
        ),
        "LOCK" | "COPY" => ensure!(depth != Some("1"), "LOCK/COPY Depth must be 0 or infinity"),
        "MOVE" | "DELETE" => ensure!(
            depth.is_none_or(|d| d == "infinity"),
            "MOVE/DELETE Depth must be infinity"
        ),
        // 文件读取不遍历后代；允许客户端显式声明 Depth 0，不由此开放递归集合读取。
        "GET" | "HEAD" => ensure!(depth.is_none_or(|d| d == "0"), "file read Depth must be 0"),
        _ => ensure!(depth.is_none(), "unexpected WebDAV Depth"),
    }
    let destination = single(&parts.headers, "destination")?;
    if matches!(parts.method.as_str(), "COPY" | "MOVE") {
        resource(
            destination.context("WebDAV Destination required")?,
            parts,
            scheme,
            cfg,
        )?;
    } else {
        ensure!(destination.is_none(), "unexpected WebDAV Destination");
    }
    if let Some(overwrite) = single(&parts.headers, "overwrite")? {
        ensure!(
            matches!(parts.method.as_str(), "COPY" | "MOVE") && matches!(overwrite, "T" | "F"),
            "invalid WebDAV Overwrite"
        );
    }
    for name in ["if", "lock-token", "timeout"] {
        single(&parts.headers, name)?;
    }
    Ok(())
}

/// 业务作用：只重写 If 条件中的资源标签，保留锁 token 与 ETag 的标准语义。
///
/// 参数说明：
/// - `value`：唯一且经过头字节预算的 If 值。
/// - `map`：将同源资源标签转换到目标根的回调。
///
/// 返回：有界重写后的条件；未知 token scheme、未闭合标签或过多条件拒绝。
pub(super) fn map_if(value: &str, mut map: impl FnMut(&str) -> Result<String>) -> Result<String> {
    ensure!(
        !value.is_empty() && value.len() <= 4096,
        "WebDAV If exceeds budget"
    );
    let mut output = String::with_capacity(value.len());
    let mut rest = value.trim();
    let tagged = rest.starts_with('<');
    let (mut groups, mut conditions) = (0, 0);
    while !rest.is_empty() {
        groups += 1;
        ensure!(groups <= 32, "WebDAV If group budget exceeded");
        if !output.is_empty() {
            output.push(' ');
        }
        if tagged {
            let tag = take_tag(&mut rest)?;
            output.push('<');
            output.push_str(&map(tag)?);
            output.push_str("> ");
        }
        ensure!(rest.starts_with('('), "WebDAV If requires nonempty lists");
        while rest.starts_with('(') {
            conditional_list(&mut rest, &mut output, &mut conditions)?;
            if rest.starts_with('(') {
                output.push(' ');
            }
        }
        ensure!(
            tagged || rest.is_empty(),
            "WebDAV If mixes tagged and untagged lists"
        );
        ensure!(output.len() <= 8192, "rewritten WebDAV If exceeds budget");
    }
    Ok(output)
}

/// 业务作用：解析一个完整 URI 尖括号 token，不吞入其它条件的分隔符。
///
/// 参数说明：
/// - `rest`：尚未消费的有界 If 文本，成功后推进到后续条件。
///
/// 返回：不含尖括号的单个 URI；缺失、控制字符或超长时拒绝。
fn take_tag<'a>(rest: &mut &'a str) -> Result<&'a str> {
    let raw = rest.strip_prefix('<').context("WebDAV If tag required")?;
    let end = raw.find('>').context("unterminated WebDAV If tag")?;
    let tag = &raw[..end];
    ensure!(
        !tag.is_empty()
            && tag.len() <= 2048
            && !tag.contains('<')
            && tag.bytes().all(|b| (0x21..0x7f).contains(&b)),
        "invalid WebDAV If tag"
    );
    *rest = raw[end + 1..].trim_start();
    Ok(tag)
}

/// 业务作用：解析有界条件列表，保留 Not、锁 token 与 opaque ETag 而不将 ETag 内容解释成 URI。
///
/// 参数说明：
/// - `rest`：以左括号起始的剩余 If 文本。
/// - `output`：只追加语义等价的规范表示。
/// - `conditions`：整个 If 头已消费条件数，最多 64。
///
/// 返回：完整非空列表成功；嵌套、歧义、未知 token 或未闭合条件拒绝。
fn conditional_list(rest: &mut &str, output: &mut String, conditions: &mut usize) -> Result<()> {
    *rest = rest
        .strip_prefix('(')
        .context("WebDAV If list required")?
        .trim_start();
    output.push('(');
    let mut local = 0;
    while !rest.starts_with(')') {
        local += 1;
        *conditions += 1;
        ensure!(
            *conditions <= 64 && !rest.is_empty(),
            "WebDAV If condition budget or syntax exceeded"
        );
        if local > 1 {
            output.push(' ');
        }
        if let Some(after) = rest.strip_prefix("Not") {
            ensure!(
                after.starts_with(char::is_whitespace),
                "invalid WebDAV If negation"
            );
            *rest = after.trim_start();
            output.push_str("Not ");
        }
        if rest.starts_with('<') {
            let tag = take_tag(rest)?;
            ensure!(
                tag.starts_with("urn:uuid:") || tag.starts_with("opaquelocktoken:"),
                "unsupported WebDAV state token"
            );
            output.push('<');
            output.push_str(tag);
            output.push('>');
        } else {
            let after = rest
                .strip_prefix('[')
                .context("WebDAV If state token or ETag required")?;
            let quoted = after.strip_prefix("W/").unwrap_or(after);
            let content = quoted
                .strip_prefix('"')
                .context("WebDAV If quoted ETag required")?;
            let end = content.find('"').context("unterminated WebDAV If ETag")?;
            ensure!(
                content[..end].bytes().all(|b| (0x21..0x7f).contains(&b)),
                "invalid WebDAV If ETag"
            );
            let after_quote = &content[end + 1..];
            let remaining = after_quote
                .strip_prefix(']')
                .context("WebDAV If ETag end required")?;
            let consumed = rest.len() - remaining.len();
            output.push_str(&rest[..consumed]);
            *rest = remaining.trim_start();
        }
    }
    ensure!(local > 0, "empty WebDAV If list");
    *rest = rest[1..].trim_start();
    output.push(')');
    Ok(())
}

/// 业务作用：在标准 XML 树解析前关闭实体入口，并约束深度、节点、属性与总字节。
///
/// 参数说明：
/// - `bytes`：已按字节预算收集的协议 XML，不是文件实体。
/// - `cfg`：XML 节点及嵌套上限。
/// - `limit`：本次请求或 multistatus 响应的字节上限。
///
/// 返回：空体或完整受限 UTF-8 XML 成功；DTD、PI、自定义实体、超限或不完整文档拒绝。
pub(super) fn validate_xml(bytes: &[u8], cfg: &WebDavCfg, limit: usize) -> Result<()> {
    ensure!(bytes.len() <= limit, "WebDAV XML bytes exceeded");
    if bytes.is_empty() {
        return Ok(());
    }
    std::str::from_utf8(bytes).context("WebDAV XML must be UTF-8")?;
    let mut reader = quick_xml::Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let (mut depth, mut nodes, mut roots) = (0usize, 0usize, 0usize);
    loop {
        let event = reader.read_event()?;
        let empty = matches!(&event, Event::Empty(_));
        if !matches!(&event, Event::Eof | Event::End(_) | Event::Decl(_)) {
            nodes += 1;
            ensure!(
                nodes <= cfg.max_xml_nodes,
                "WebDAV XML node budget exceeded"
            );
        }
        match event {
            Event::Start(node) | Event::Empty(node) => {
                ensure!(
                    nodes <= cfg.max_xml_nodes && depth < cfg.max_xml_depth,
                    "WebDAV XML structural budget exceeded"
                );
                if depth == 0 {
                    roots += 1;
                }
                ensure!(
                    roots <= 1 && node.name().as_ref().len() <= 256,
                    "invalid WebDAV XML root/name"
                );
                let mut count = 0;
                for attribute in node.attributes() {
                    let attribute = attribute?;
                    count += 1;
                    ensure!(
                        count <= 32 && attribute.key.as_ref().len() <= 256,
                        "WebDAV XML attribute budget exceeded"
                    );
                    attribute.normalized_value(quick_xml::XmlVersion::Implicit1_0)?;
                }
                if !empty {
                    depth += 1;
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).context("unmatched WebDAV XML end")?;
            }
            Event::GeneralRef(reference) => {
                let text = reference.decode()?;
                ensure!(
                    matches!(text.as_ref(), "amp" | "lt" | "gt" | "quot" | "apos")
                        || reference.resolve_char_ref()?.is_some(),
                    "WebDAV custom entity forbidden"
                );
            }
            Event::DocType(_) | Event::PI(_) => {
                bail!("WebDAV DTD and processing instructions forbidden")
            }
            Event::Decl(decl) => {
                ensure!(
                    reader.buffer_position() <= 128 && nodes == 0 && depth == 0,
                    "misplaced WebDAV XML declaration"
                );
                ensure!(
                    decl.version()?.as_ref() == b"1.0",
                    "WebDAV XML version must be 1.0"
                );
                if let Some(encoding) = decl.encoding() {
                    ensure!(
                        encoding?.eq_ignore_ascii_case(b"UTF-8"),
                        "WebDAV XML encoding must be UTF-8"
                    );
                }
            }
            Event::Text(text) if depth == 0 => ensure!(
                text.iter().all(u8::is_ascii_whitespace),
                "WebDAV XML text outside root"
            ),
            Event::CData(_) if depth == 0 => bail!("WebDAV XML CDATA outside root"),
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(roots == 1 && depth == 0, "incomplete WebDAV XML document");
    Ok(())
}
