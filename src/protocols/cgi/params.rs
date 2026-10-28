//! CGI 参数仅取固定声明和规范化连接元数据，HTTP 头只能进入显式白名单。
use super::Input;
use crate::BoxBody;
use anyhow::{ensure, Result};
use http::request::Parts;
use hyper::body::Body;

struct Parameters {
    values: Vec<(String, String)>,
    remaining: usize,
    max_count: usize,
}

impl Parameters {
    /// 业务作用：在复制请求属性前预扣参数空间，超限输入不能先产生大块分配。
    ///
    /// 参数说明：
    /// - `name`：固定或经白名单归一化的唯一环境变量名。
    /// - `value`：尚未复制的受限属性值。
    ///
    /// 返回：预算和 NUL 检查通过时追加参数；失败时不复制值。
    fn push(&mut self, name: &str, value: &str) -> Result<()> {
        let bytes = name
            .len()
            .checked_add(value.len())
            .and_then(|n| n.checked_add(8));
        ensure!(
            self.values.len() < self.max_count && bytes.is_some_and(|n| n <= self.remaining),
            "CGI parameter budget exceeded"
        );
        ensure!(
            !name.contains('\0') && !value.contains('\0'),
            "CGI parameter contains NUL"
        );
        self.remaining -= bytes.expect("checked parameter budget");
        self.values.push((name.to_owned(), value.to_owned()));
        Ok(())
    }
}

/// 业务作用：验证无需聚合即可确定的实体长度。
///
/// 参数说明：
/// - `parts`：最终上游请求 head。
/// - `body`：待流式发送的实体。
///
/// 返回：可信长度；未知、重复或自相矛盾的长度明确拒绝。
pub(super) fn length(parts: &Parts, body: &BoxBody) -> Result<u64> {
    let values = parts.headers.get_all(http::header::CONTENT_LENGTH);
    ensure!(
        values.iter().count() <= 1,
        "CGI requires one unambiguous Content-Length"
    );
    let declared = values
        .iter()
        .next()
        .map(|v| -> Result<u64> {
            let raw = v.to_str()?;
            ensure!(
                !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()),
                "invalid CGI Content-Length"
            );
            Ok(raw.parse()?)
        })
        .transpose()?;
    let exact = body
        .size_hint()
        .exact()
        .or_else(|| body.is_end_stream().then_some(0));
    ensure!(
        !matches!((declared, exact), (Some(a), Some(b)) if a != b),
        "CGI Content-Length differs from entity"
    );
    declared.or(exact).ok_or_else(|| {
        anyhow::anyhow!("CGI requires a known body length; streaming chunked input is not buffered")
    })
}

/// 业务作用：构造预算内且名称唯一的环境变量，不将请求路径解释为可执行脚本。
///
/// 参数说明：
/// - `parts`：经过原生策略的请求 head。
/// - `body`：尚未消费的实体流。
/// - `input`：固定脚本、真实 IP、scheme 和规范化 URI。
///
/// 返回：稳定顺序的变量及已验证长度；超限、NUL或歧义头拒绝。
pub(super) fn build(
    parts: &Parts,
    body: &BoxBody,
    input: &Input,
) -> Result<(Vec<(String, String)>, u64)> {
    let length = length(parts, body)?;
    let cfg = &input.plan.config;
    let mut vars = Parameters {
        values: Vec::with_capacity(cfg.max_params),
        remaining: cfg.max_param_bytes,
        max_count: cfg.max_params,
    };
    vars.push("CONTENT_LENGTH", &length.to_string())?;
    if cfg.protocol == crate::config::cgi::Protocol::Scgi {
        vars.push("SCGI", "1")?;
    }
    for (name, value) in [
        ("GATEWAY_INTERFACE", "CGI/1.1"),
        ("SCRIPT_FILENAME", cfg.script_filename.as_str()),
        ("DOCUMENT_ROOT", cfg.script_root.as_str()),
        ("SCRIPT_NAME", cfg.script_name.as_str()),
        ("PATH_INFO", input.uri.path()),
        (
            "REQUEST_URI",
            input
                .uri
                .path_and_query()
                .map(|v| v.as_str())
                .unwrap_or("/"),
        ),
        ("QUERY_STRING", input.uri.query().unwrap_or("")),
        ("REQUEST_METHOD", parts.method.as_str()),
        (
            "HTTPS",
            if input.https {
                "on"
            } else {
                "off"
            },
        ),
        ("SERVER_SOFTWARE", "naway"),
        ("SERVER_NAME", cfg.server_name.as_str()),
    ] {
        vars.push(name, value)?;
    }
    vars.push("REMOTE_ADDR", &input.client_ip.to_string())?;
    vars.push("SERVER_PROTOCOL", &format!("{:?}", input.version))?;
    vars.push(
        "SERVER_PORT",
        &cfg.server_port
            .unwrap_or(if input.https {
                443
            } else {
                80
            })
            .to_string(),
    )?;
    if let Some(content_type) = parts.headers.get(http::header::CONTENT_TYPE) {
        vars.push("CONTENT_TYPE", content_type.to_str()?)?;
    }
    for raw in &cfg.request_headers {
        let values = parts.headers.get_all(raw);
        // CGI 环境没有通用的重复 HTTP header 表示法；不可猜测 cookie 或认证头的拼接语义。
        ensure!(
            values.iter().count() <= 1,
            "duplicate allowlisted CGI request header"
        );
        if let Some(value) = values.iter().next() {
            vars.push(
                &format!("HTTP_{}", raw.to_ascii_uppercase().replace('-', "_")),
                value.to_str()?,
            )?;
        }
    }
    let vars = vars.values;
    Ok((vars, length))
}
