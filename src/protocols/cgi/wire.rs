//! 单请求记录 codec 与严格收尾。实体只在固定块和有界通道中暂存。
use crate::{
    config::cgi::{CgiCfg, Protocol},
    BoxBody, BoxError,
};
use anyhow::Result;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Frame;
use std::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{mpsc, oneshot},
};

type Head = http::response::Parts;
type Sender = mpsc::Sender<Result<Frame<Bytes>, BoxError>>;
type HeadSender = Option<oneshot::Sender<Result<Head, BoxError>>>;
static FAILURES: [AtomicU64; 3] = [const {
    AtomicU64::new(0)
}; 3];
const CHUNK: usize = 16 * 1024;

/// 业务作用：在记录边界保留可直接进入流式 body 的稳定错误类型。
/// 参数说明：
/// - `condition`：协议边界必须满足的条件。
/// - `message`：失败时使用的固定错误描述。
///
/// 返回：条件不成立时立即终止当前会话。
macro_rules! ensure {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message.into());
        }
    };
}

/// 业务作用：记录不带脚本、参数或身份的协议失败事实。
///
/// 参数说明：
/// - `protocol`：固定 codec 种类。
///
/// 返回：该协议计数增加一次。
pub(super) fn record_failure(protocol: Protocol) {
    FAILURES[index(protocol)].fetch_add(1, Ordering::Relaxed);
}
/// 业务作用：把有限协议集映射到固定指标槽位。
///
/// 参数说明：
/// - `protocol`：固定 codec 种类。
///
/// 返回：三种协议之一的固定索引。
fn index(protocol: Protocol) -> usize {
    match protocol {
        Protocol::Fastcgi => 0,
        Protocol::Uwsgi => 1,
        Protocol::Scgi => 2,
    }
}
/// 业务作用：读取有限协议失败总数供公共指标出口复用。
///
/// 参数说明: 无。
///
/// 返回：固定顺序的三个累加计数。
pub(crate) fn failures() -> [u64; 3] {
    std::array::from_fn(|i| FAILURES[i].load(Ordering::Relaxed))
}

/// 业务作用：限制一次 I/O 单元的持续时间，半包或静默对端不能永久持有资源。
///
/// 参数说明：
/// - `cfg`：协议 deadline 声明。
/// - `future`：有界 I/O 操作。
///
/// 返回：操作成功值或 I/O/超时错误。
async fn io<T>(
    cfg: &CgiCfg,
    future: impl Future<Output = std::io::Result<T>>,
) -> Result<T, BoxError> {
    Ok(tokio::time::timeout(Duration::from_millis(cfg.idle_timeout_ms), future).await??)
}

/// 业务作用：编码请求头与流式正文，强制声明长度和实际发送长度一致。
///
/// 参数说明：
/// - `write`：独占连接发送端。
/// - `body`：原始实体流。
/// - `variables`：已验证的环境变量。
/// - `length`：必须精确满足的实体长度。
/// - `cfg`：记录协议及资源预算。
///
/// 返回：所有输入及结束记录成功送出后归还发送端；任何错误禁止连接复用。
pub(super) async fn write_request(
    mut write: OwnedWriteHalf,
    mut body: BoxBody,
    variables: &[(String, String)],
    length: u64,
    cfg: &CgiCfg,
) -> Result<OwnedWriteHalf, BoxError> {
    match cfg.protocol {
        #[cfg(feature = "fastcgi")]
        Protocol::Fastcgi => {
            record(
                &mut write,
                1,
                &[0, 1, u8::from(cfg.keep_conn), 0, 0, 0, 0, 0],
                cfg,
            )
            .await?;
            let mut params = Vec::with_capacity(cfg.max_param_bytes);
            for (name, value) in variables {
                fcgi_length(name.len(), &mut params);
                fcgi_length(value.len(), &mut params);
                params.extend_from_slice(name.as_bytes());
                params.extend_from_slice(value.as_bytes());
            }
            for chunk in params.chunks(CHUNK) {
                record(&mut write, 4, chunk, cfg).await?;
            }
            record(&mut write, 4, &[], cfg).await?;
        }
        #[cfg(feature = "uwsgi")]
        Protocol::Uwsgi => {
            let mut params = Vec::with_capacity(cfg.max_param_bytes);
            for (name, value) in variables {
                params.extend_from_slice(&(name.len() as u16).to_le_bytes());
                params.extend_from_slice(name.as_bytes());
                params.extend_from_slice(&(value.len() as u16).to_le_bytes());
                params.extend_from_slice(value.as_bytes());
            }
            ensure!(
                params.len() <= 65535,
                "uwsgi variable block exceeds wire length"
            );
            let size = (params.len() as u16).to_le_bytes();
            // modifier 0/0 是唯一许可的 WSGI 请求；其它 modifier 可执行控制命令，不能由配置或请求指定。
            io(cfg, write.write_all(&[0, size[0], size[1], 0])).await?;
            io(cfg, write.write_all(&params)).await?;
        }
        #[cfg(feature = "scgi")]
        Protocol::Scgi => {
            let mut params = Vec::with_capacity(cfg.max_param_bytes);
            for (name, value) in variables {
                params.extend_from_slice(name.as_bytes());
                params.push(0);
                params.extend_from_slice(value.as_bytes());
                params.push(0);
            }
            io(
                cfg,
                write.write_all(format!("{}:", params.len()).as_bytes()),
            )
            .await?;
            io(cfg, write.write_all(&params)).await?;
            io(cfg, write.write_all(b",")).await?;
        }
        #[allow(unreachable_patterns)]
        _ => return Err("CGI codec not compiled".into()),
    }
    let mut sent = 0u64;
    let mut empty_frames = 0;
    while let Some(frame) =
        tokio::time::timeout(Duration::from_millis(cfg.idle_timeout_ms), body.frame()).await?
    {
        let data = frame?
            .into_data()
            .map_err(|_| "CGI request trailers are not supported")?;
        sent = sent
            .checked_add(data.len() as u64)
            .ok_or("CGI request length overflow")?;
        ensure!(sent <= length, "CGI request exceeds Content-Length");
        if data.is_empty() {
            empty_frames += 1;
            ensure!(empty_frames <= 1024, "CGI empty frame budget exceeded");
        }
        for chunk in data.chunks(CHUNK) {
            #[cfg(feature = "fastcgi")]
            if cfg.protocol == Protocol::Fastcgi {
                record(&mut write, 5, chunk, cfg).await?;
                continue;
            }
            io(cfg, write.write_all(chunk)).await?;
        }
    }
    ensure!(sent == length, "CGI request ended before Content-Length");
    #[cfg(feature = "fastcgi")]
    if cfg.protocol == Protocol::Fastcgi {
        record(&mut write, 5, &[], cfg).await?;
    }
    io(cfg, write.flush()).await?;
    Ok(write)
}

/// 业务作用：编码 FastCGI 参数长度的标准短/长表示。
///
/// 参数说明：
/// - `len`：已受参数总量门约束的长度。
/// - `out`：有界参数块。
///
/// 返回：向块追加长度，不接触实体。
#[cfg(feature = "fastcgi")]
fn fcgi_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        out.extend_from_slice(&((len as u32) | 0x8000_0000).to_be_bytes());
    }
}

/// 业务作用：写入单个 request-id 固定为1的记录，明确不支持 multiplexing。
///
/// 参数说明：
/// - `write`：独占连接发送端。
/// - `kind`：协议记录类型。
/// - `data`：固定上限的记录内容。
/// - `cfg`：协议 deadline 声明。
///
/// 返回：完整写入记录；部分失败时连接必须丢弃。
#[cfg(feature = "fastcgi")]
async fn record(
    write: &mut OwnedWriteHalf,
    kind: u8,
    data: &[u8],
    cfg: &CgiCfg,
) -> Result<(), BoxError> {
    ensure!(data.len() <= 65535, "FastCGI record exceeds wire length");
    let length = (data.len() as u16).to_be_bytes();
    io(cfg, async {
        write
            .write_all(&[1, kind, 0, 1, length[0], length[1], 0, 0])
            .await?;
        write.write_all(data).await
    })
    .await
}

struct Decoder {
    header: Vec<u8>,
    parsed: bool,
    pending: Option<Bytes>,
    expected: Option<u64>,
    received: u64,
    no_body: bool,
}
impl Decoder {
    /// 业务作用：初始化固定上限的响应头与末块暂存。
    ///
    /// 参数说明：
    /// - `head`：原请求是否为 HEAD。
    ///
    /// 返回：未发布响应头的解析状态。
    fn new(head: bool) -> Self {
        Self {
            header: Vec::new(),
            parsed: false,
            pending: None,
            expected: None,
            received: 0,
            no_body: head,
        }
    }
    /// 业务作用：解析有界响应头并流式转交正文，末块保留到会话结束复验。
    ///
    /// 参数说明：
    /// - `data`：单块协议输出。
    /// - `cfg`：响应解析预算。
    /// - `head`：只能发布一次的响应头出口。
    /// - `tx`：有界实体出口。
    ///
    /// 返回：合法块成功推进；畸形头、长度或取消使整个会话失败。
    async fn push(
        &mut self,
        mut data: Bytes,
        cfg: &CgiCfg,
        head: &mut HeadSender,
        tx: &Sender,
    ) -> Result<(), BoxError> {
        if !self.parsed {
            let mut consumed = 0;
            while consumed < data.len() {
                ensure!(
                    self.header.len() < cfg.max_header_bytes,
                    "CGI response headers exceed byte budget"
                );
                self.header.push(data[consumed]);
                consumed += 1;
                if self.header.ends_with(b"\r\n\r\n") {
                    let parts = parse_headers(&self.header, cfg)?;
                    self.expected = parts
                        .headers
                        .get(http::header::CONTENT_LENGTH)
                        .map(|v| -> Result<u64, BoxError> {
                            Ok(v.to_str()?.parse()?)
                        })
                        .transpose()?;
                    self.no_body |= parts.status == StatusCode::NO_CONTENT
                        || parts.status == StatusCode::NOT_MODIFIED;
                    head.take()
                        .ok_or("CGI response headers repeated")?
                        .send(Ok(parts))
                        .map_err(|_| "CGI downstream canceled")?;
                    self.parsed = true;
                    self.header.clear();
                    break;
                }
            }
            data = data.slice(consumed..);
        }
        if data.is_empty() {
            return Ok(());
        }
        ensure!(
            self.parsed && !self.no_body,
            "CGI returned data for a bodyless response"
        );
        self.received = self
            .received
            .checked_add(data.len() as u64)
            .ok_or("CGI response length overflow")?;
        ensure!(
            self.expected.is_none_or(|n| self.received <= n),
            "CGI response exceeds Content-Length"
        );
        for chunk in data.chunks(CHUNK) {
            if let Some(previous) = self.pending.replace(Bytes::copy_from_slice(chunk)) {
                tx.send(Ok(Frame::data(previous)))
                    .await
                    .map_err(|_| "CGI downstream canceled")?;
            }
        }
        Ok(())
    }
    /// 业务作用：仅在记录/连接结束且长度一致时允许发布最后一块实体。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未发布的固定末块；短正文或缺响应头拒绝。
    fn finish(self) -> Result<Option<Bytes>, BoxError> {
        ensure!(self.parsed, "CGI response ended before headers");
        ensure!(
            self.no_body || self.expected.is_none_or(|n| n == self.received),
            "CGI response ended before Content-Length"
        );
        Ok(self.pending)
    }
}

/// 业务作用：解析 CGI MIME 或标准 uWSGI HTTP 响应头，拒绝跳跃 framing 和响应拆分。
///
/// 参数说明：
/// - `raw`：预算内完整响应头。
/// - `cfg`：协议和头条数上限。
///
/// 返回：规范状态与端到端头；歧义长度、非法状态和 hop-by-hop 头拒绝。
fn parse_headers(raw: &[u8], cfg: &CgiCfg) -> Result<Head, BoxError> {
    let text = std::str::from_utf8(raw)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut response = Response::new(());
    let mut explicit_status = false;
    if cfg.protocol == Protocol::Uwsgi {
        let first = lines.next().ok_or("uwsgi missing HTTP status")?;
        ensure!(
            first.starts_with("HTTP/1.1 ") || first.starts_with("HTTP/1.0 "),
            "uwsgi response requires an HTTP status line"
        );
        *response.status_mut() = parse_status(&first[9..])?;
        explicit_status = true;
    }
    let mut count = 0;
    for line in lines {
        count += 1;
        ensure!(
            count <= cfg.max_headers,
            "CGI response header count exceeded"
        );
        let (name, value) = line
            .split_once(':')
            .ok_or("CGI response header missing colon")?;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = value.trim_matches([' ', '\t']);
        if name.as_str() == "status" {
            ensure!(
                !explicit_status && cfg.protocol != Protocol::Uwsgi,
                "CGI status is ambiguous"
            );
            *response.status_mut() = parse_status(value)?;
            explicit_status = true;
            continue;
        }
        // chunked 或连接级头不能穿过记录协议桥；需要由网关依据下游协议重新编码。
        ensure!(
            !matches!(
                name.as_str(),
                "transfer-encoding"
                    | "connection"
                    | "trailer"
                    | "upgrade"
                    | "keep-alive"
                    | "proxy-connection"
            ),
            "CGI hop-by-hop response header is forbidden"
        );
        if name == http::header::CONTENT_LENGTH {
            ensure!(
                !response.headers().contains_key(&name)
                    && !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit()),
                "ambiguous CGI Content-Length"
            );
            let _: u64 = value.parse()?;
        }
        response
            .headers_mut()
            .append(name, HeaderValue::from_str(value)?);
    }
    if !explicit_status && response.headers().contains_key(http::header::LOCATION) {
        *response.status_mut() = StatusCode::FOUND;
    }
    ensure!(
        !(response.status() == StatusCode::NO_CONTENT
            && response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .is_some_and(|v| v != "0")),
        "CGI 204 has nonzero entity length"
    );
    Ok(response.into_parts().0)
}

/// 业务作用：限制 CGI 状态为单个终态，禁止 interim 和协议升级。
///
/// 参数说明：
/// - `value`：状态码及可选 reason。
///
/// 返回：200至599终态；非法格式或控制字符拒绝。
fn parse_status(value: &str) -> Result<StatusCode, BoxError> {
    ensure!(
        value.len() >= 3
            && value.as_bytes()[..3].iter().all(u8::is_ascii_digit)
            && (value.len() == 3 || value.as_bytes()[3] == b' ')
            && !value.bytes().any(|b| b < 32 || b == 127),
        "invalid CGI status"
    );
    let code = StatusCode::from_bytes(&value.as_bytes()[..3])?;
    ensure!(
        (200..=599).contains(&code.as_u16()),
        "CGI interim or upgrade response forbidden"
    );
    Ok(code)
}

/// 业务作用：读取独占会话响应并复验完整协议结束，STDERR 永不混入业务正文。
///
/// 参数说明：
/// - `read`：独占连接接收端。
/// - `cfg`：记录和解析预算。
/// - `head_request`：原请求是否禁止实体输出。
/// - `head`：单次响应头出口。
/// - `tx`：有界正文出口。
///
/// 返回：完整接收端和最后一块正文；畸形记录、半包、诊断超限和取消均失败。
pub(super) async fn read_response(
    mut read: OwnedReadHalf,
    cfg: &CgiCfg,
    head_request: bool,
    head: &mut HeadSender,
    tx: &Sender,
) -> Result<(OwnedReadHalf, Option<Bytes>), BoxError> {
    let mut decoder = Decoder::new(head_request);
    #[cfg(feature = "fastcgi")]
    if cfg.protocol == Protocol::Fastcgi {
        let mut stdout_closed = false;
        let mut stderr_seen = false;
        let mut stderr_closed = false;
        let mut stderr_bytes = 0usize;
        let mut records = 0usize;
        loop {
            records += 1;
            ensure!(records <= 1_048_576, "FastCGI record count exceeded");
            let mut header = [0u8; 8];
            io(cfg, read.read_exact(&mut header)).await?;
            ensure!(
                header[0] == 1 && header[2..4] == [0, 1],
                "invalid FastCGI version or request id"
            );
            let len = u16::from_be_bytes([header[4], header[5]]) as usize;
            let mut payload = vec![0; len];
            io(cfg, async {
                read.read_exact(&mut payload).await?;
                let mut padding = [0u8; 255];
                read.read_exact(&mut padding[..header[6] as usize]).await
            })
            .await?;
            match header[1] {
                6 => {
                    ensure!(!stdout_closed, "FastCGI STDOUT after terminator");
                    if len == 0 {
                        stdout_closed = true;
                    } else {
                        decoder.push(Bytes::from(payload), cfg, head, tx).await?;
                    }
                }
                7 => {
                    ensure!(!stderr_closed, "FastCGI STDERR after terminator");
                    stderr_seen = true;
                    stderr_bytes += len;
                    ensure!(
                        stderr_bytes <= cfg.max_stderr_bytes,
                        "FastCGI STDERR exceeds budget"
                    );
                    if len == 0 {
                        stderr_closed = true;
                    }
                }
                3 => {
                    // PHP-FPM 用 END_REQUEST 本身结束输出流，不发送空 STDOUT/STDERR；只能显式启用。
                    // 仍须完整解析响应头、精确核对已声明实体长度，并等上传完成后才发布最后一块。
                    let php_fpm =
                        cfg.fastcgi_termination == crate::config::cgi::FastcgiTermination::PhpFpm;
                    ensure!(
                        len == 8 && (php_fpm || (stdout_closed && (!stderr_seen || stderr_closed))),
                        "FastCGI premature END_REQUEST"
                    );
                    // reserved 字节不是应用状态，不能把未初始化的保留区域解释为失败码。
                    ensure!(
                        payload[..5] == [0; 5],
                        "FastCGI application or protocol status is not complete"
                    );
                    if stderr_bytes != 0 {
                        // 后端诊断可能带请求秘密；只输出独立错误流的字节事实，绝不回显内容。
                        tracing::warn!(
                            protocol = "fastcgi",
                            bytes = stderr_bytes,
                            "CGI backend diagnostic stream received"
                        );
                    }
                    return Ok((read, decoder.finish()?));
                }
                _ => return Err("unexpected FastCGI record type".into()),
            }
        }
    }
    let mut buffer = [0u8; CHUNK];
    loop {
        let n = io(cfg, read.read(&mut buffer)).await?;
        if n == 0 {
            return Ok((read, decoder.finish()?));
        }
        decoder
            .push(Bytes::copy_from_slice(&buffer[..n]), cfg, head, tx)
            .await?;
    }
}
