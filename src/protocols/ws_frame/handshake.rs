//! 压缩两端都禁止跨消息字典，丢弃或改写一条消息不能改变下一条消息的解码权威。

use anyhow::{bail, ensure, Result};
use http::{HeaderMap, HeaderValue};

const EXTENSIONS: &str = "sec-websocket-extensions";

#[derive(Clone, Copy, Default)]
struct Parameters {
    server_no_context: bool,
    server_window: Option<u8>,
    client_window: Option<Option<u8>>,
}

/// 只来自本次客户端握手的提议，上游不能自行授予未提议的扩展。
pub(crate) struct Offer(Option<Parameters>);

impl Offer {
    /// 业务作用：在进入上游前选择唯一可理解的压缩合同，原未知扩展不会穿过帧治理。
    ///
    /// 参数说明：
    /// - `headers`：客户端握手头，选中后替换为禁止字典继承的标准提议。
    /// - `enabled`：路由是否显式开放 permessage-deflate。
    ///
    /// 返回：本次提议证据；过长或畸形压缩声明拒绝握手，关闭态移除所有扩展。
    pub(crate) fn prepare(headers: &mut HeaderMap, enabled: bool) -> Result<Self> {
        let mut selected = None;
        if enabled {
            let mut bytes = 0usize;
            let mut offers = 0usize;
            for value in headers.get_all(EXTENSIONS) {
                bytes = bytes.saturating_add(value.as_bytes().len());
                ensure!(
                    bytes <= 8192,
                    "WebSocket extension declaration exceeds limit"
                );
                for entry in value.to_str()?.split(',') {
                    offers += 1;
                    ensure!(offers <= 32, "too many WebSocket extension offers");
                    if entry.split(';').next().map(str::trim) == Some("permessage-deflate") {
                        let parameters = parse(entry, false)?;
                        if selected.is_none() {
                            selected = Some(parameters);
                        }
                    }
                }
            }
        }
        // 只转发已编译能力能解释的扩展；未知 RSV 语义不能穿过本地校验边界。
        headers.remove(EXTENSIONS);
        if let Some(parameters) = selected {
            headers.insert(EXTENSIONS, encode(parameters, false)?);
        }
        Ok(Self(selected))
    }

    /// 业务作用：在发送101前复验上游的协商结果，并向客户端约束每条消息独立压缩。
    ///
    /// 参数说明：
    /// - `headers`：上游101响应头，接受时规范化为同一已验证合同。
    ///
    /// 返回：实际协商压缩时为真，未接受时为假；未提议扩展、重复参数与跨消息字典拒绝升级。
    pub(crate) fn accept(self, headers: &mut HeaderMap) -> Result<bool> {
        let mut values = headers.get_all(EXTENSIONS).iter();
        let Some(value) = values.next() else {
            return Ok(false);
        };
        ensure!(
            values.next().is_none(),
            "multiple WebSocket extension responses"
        );
        let offered = self
            .0
            .ok_or_else(|| anyhow::anyhow!("unsolicited WebSocket extension"))?;
        ensure!(
            value.as_bytes().len() <= 1024,
            "WebSocket extension response exceeds limit"
        );
        let accepted = parse(value.to_str()?, true)?;
        // 丢消息或重写内容会使双方历史不同；服务端不得继续引用先前消息的字典。
        ensure!(
            accepted.server_no_context,
            "WebSocket server context takeover is not allowed"
        );
        if let Some(maximum) = offered.server_window {
            ensure!(
                accepted.server_window.is_some_and(|bits| bits <= maximum),
                "WebSocket server window exceeds offer"
            );
        }
        ensure!(
            accepted.client_window.is_none() || offered.client_window.is_some(),
            "unsolicited WebSocket client window"
        );
        // 客户端必须支持此响应参数；上游允许字典继承时仍能接收每条消息从空字典开始的编码。
        headers.insert(EXTENSIONS, encode(accepted, true)?);
        Ok(true)
    }
}

/// 业务作用：完整解释一个压缩扩展，拒绝含糊参数而不猜测双方的字典或窗口约定。
///
/// 参数说明：
/// - `raw`：一个扩展声明，不包含其它逗号分隔扩展。
/// - `response`：响应必须为窗口参数提供数值，提议允许 client_max_window_bits 不带值。
///
/// 返回：有限固定字段；未知、重复、非法窗口或带值的布尔参数失败。
fn parse(raw: &str, response: bool) -> Result<Parameters> {
    let mut items = raw.split(';');
    ensure!(
        items.next().map(str::trim) == Some("permessage-deflate"),
        "unsupported WebSocket extension"
    );
    let mut parameters = Parameters::default();
    let mut seen = 0u8;
    for item in items {
        let (key, value) = item
            .trim()
            .split_once('=')
            .map_or((item.trim(), None), |(key, value)| {
                (key.trim(), Some(value.trim()))
            });
        let mask = match key {
            "server_no_context_takeover" => 1,
            "client_no_context_takeover" => 2,
            "server_max_window_bits" => 4,
            "client_max_window_bits" => 8,
            _ => bail!("unsupported WebSocket compression parameter"),
        };
        ensure!(
            seen & mask == 0,
            "duplicate WebSocket compression parameter"
        );
        seen |= mask;
        match mask {
            1 | 2 => {
                ensure!(
                    value.is_none(),
                    "context takeover parameter cannot have a value"
                );
                if mask == 1 {
                    parameters.server_no_context = true;
                }
            }
            4 => parameters.server_window = Some(window(value)?),
            _ => {
                parameters.client_window = Some(if value.is_none() && !response {
                    None
                } else {
                    Some(window(value)?)
                })
            }
        }
    }
    Ok(parameters)
}

/// 业务作用：限制 DEFLATE 字典大小到协议支持的精确十进制值，禁止非规范数字别名。
///
/// 参数说明：
/// - `value`：可选的原始参数值，允许协议规定的 quoted-string 数字。
///
/// 返回：8到15的窗口位数；缺失、转义、前导零或越界拒绝。
fn window(value: Option<&str>) -> Result<u8> {
    let raw = value.ok_or_else(|| anyhow::anyhow!("WebSocket window value is missing"))?;
    let raw = raw
        .strip_prefix('"')
        .and_then(|raw| raw.strip_suffix('"'))
        .unwrap_or(raw);
    ensure!(
        matches!(raw, "8" | "9" | "10" | "11" | "12" | "13" | "14" | "15"),
        "invalid WebSocket compression window"
    );
    Ok(raw.parse()?)
}

/// 业务作用：只在握手阶段编码固定压缩参数，消息路径不重新解析或生成 HTTP 合同。
///
/// 参数说明：
/// - `parameters`：已完整验证的窗口约束。
/// - `response`：响应不允许无值窗口；提议可以携带客户端的无值能力声明。
///
/// 返回：同时约束两个方向无字典继承的唯一扩展头；非法输出不会部分发布。
fn encode(parameters: Parameters, response: bool) -> Result<HeaderValue> {
    use std::fmt::Write as _;
    let mut value =
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover".to_owned();
    if let Some(bits) = parameters.server_window {
        write!(value, "; server_max_window_bits={bits}")?;
    }
    match parameters.client_window {
        Some(Some(bits)) => write!(value, "; client_max_window_bits={bits}")?,
        Some(None) => {
            ensure!(
                !response,
                "WebSocket response requires a client window value"
            );
            value.push_str("; client_max_window_bits");
        }
        None => {}
    }
    Ok(HeaderValue::from_str(&value)?)
}
