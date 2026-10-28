//! MASQUE / CONNECT-UDP capsule、WebTransport 会话预算与安全 0-RTT 门。
//!
//! 这三件事被放在一起,因为它们共享同一条底线:**能力不因为底层库支持就自动开放**。
//! QUIC 栈本身能做 datagram、能做 0-RTT,但这些能力一旦无条件打开:
//! - datagram 会变成无界重组缓冲的入口;
//! - CONNECT-UDP 会变成不受 SSRF 约束的 UDP 出口;
//! - 0-RTT 会让**可重放**的请求执行带副作用的操作。
//!
//! 因此本模块的每个入口都是先判定、后放行,且默认全部关闭。

mod semantic;

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::protocols::forward_proxy::{ConnectTarget, DenyReason, ForwardProxyPolicy};

/// 单个 capsule 允许的最大长度。超过直接断流,不预分配。
///
/// capsule 的长度字段由对端提供,若照着它去 `with_capacity`,一个 8 字节的头就能
/// 让网关分配数 GB 内存——这是最廉价的远程 OOM 触发方式。
pub const MAX_CAPSULE_LEN: u64 = 64 * 1024;
/// 单个 HTTP datagram 的最大载荷。
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_527;

/// HTTP/3 adapter 写入请求扩展的 CONNECT-UDP 内部标记。
///
/// 业务作用：让统一请求管线在完成 ACL、认证、授权与配额后进入 UDP 终端准备分支，避免把
/// extended CONNECT 误交给 Hyper 的 TCP upgrade 机制。
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectUdpRequest;

/// 统一治理管线返回给 HTTP/3 adapter 的 CONNECT-UDP 不可变执行计划。
///
/// 业务作用：冻结已匹配 route、逐次 DNS 复验结果与隧道预算，使发送 2xx 后的数据面只按已
/// 校验 IP 建立 UDP socket，不再解析主机名或读取新快照。
#[derive(Clone)]
#[cfg(feature = "http3")]
pub(crate) struct ConnectUdpPlan {
    /// 贯穿 session 的工作区名额；握手响应结束不归还在途容量。
    pub(crate) _workspace_permit: Option<crate::control::ownership::admission::Permit>,
    /// 命中的 route，用于低敏运行日志。
    pub(crate) route_id: std::sync::Arc<str>,
    /// 已解析目标；只用于固定 host/port 观测，不参与第二次 DNS 解析。
    pub(crate) target: ConnectTarget,
    /// 本请求新解析且全部通过 SSRF 门的候选地址。
    pub(crate) addresses: std::sync::Arc<[std::net::SocketAddr]>,
    /// 与 route 同一快照的隧道超时和字节预算。
    pub(crate) policy: std::sync::Arc<ForwardProxyPolicy>,
    /// 与管理面共用的长连接登记；Drop 时撤销，关闭通知用于 reload drain 与应急封禁。
    pub(crate) guard: std::sync::Arc<crate::runtime::connections::ConnGuard>,
}

/// HTTP/3 adapter 写入请求扩展的 WebTransport 内部标记。
///
/// 业务作用：把 WebTransport extended CONNECT 与普通 CONNECT/Hyper upgrade 分开，使统一
/// route 管线先完成认证授权和配额，再把 session 控制权交还 HTTP/3 adapter。
#[derive(Clone, Copy, Debug)]
pub(crate) struct WebTransportRequest;

/// HTTP/3 adapter 写入请求扩展的真实 early-data 标记。
///
/// 业务作用：只承载 Quinn 接收流提供的 0-RTT 事实，统一代理管线不得根据客户端可伪造
/// header 构造该标记。
#[derive(Clone, Copy, Debug)]
pub(crate) struct EarlyDataRequest;

/// HTTP/3 adapter 写入请求扩展的 early-data 实体标记。
///
/// 业务作用：表示 adapter 在执行任何 route 副作用前已观察到 DATA 或 trailers，使代理管线
/// 能稳定返回 425；客户端省略 `Content-Length` 也不能把 early 实体伪装成空请求。
#[derive(Clone, Copy, Debug)]
pub(crate) struct EarlyDataRequestBody;

/// 统一治理管线返回给 HTTP/3 adapter 的 WebTransport 不可变执行计划。
///
/// 业务作用：冻结 route、上游 URL、Origin 结果、TLS 信任和长连接撤权句柄，防止 2xx 后
/// 再从客户端字段或新快照改变上游 session 身份。
#[derive(Clone)]
#[cfg(feature = "http3")]
pub(crate) struct WebTransportPlan {
    /// 贯穿 session 的工作区名额；握手响应结束不归还在途容量。
    pub(crate) _workspace_permit: Option<crate::control::ownership::admission::Permit>,
    /// 命中的 route，用于低敏运行日志与连接治理。
    pub(crate) route_id: std::sync::Arc<str>,
    /// 已在请求管线校验且规范化的 Origin，只传给固定上游。
    pub(crate) origin: std::sync::Arc<str>,
    /// 与 route 同一快照的固定上游和资源预算。
    pub(crate) policy: std::sync::Arc<WebTransportPolicy>,
    /// 管理面可关闭的长连接登记；Drop 时自动撤销。
    pub(crate) guard: std::sync::Arc<crate::runtime::connections::ConnGuard>,
}

/// 构建期冻结的 WebTransport 真上游策略。
///
/// 业务作用：把可影响拨号目标、浏览器来源与 TLS 信任的配置全部移出请求热路径；运行时只
/// 允许连接固定 HTTPS URL，客户端无法把网关变成任意 QUIC 出口。
#[derive(Clone)]
pub struct WebTransportPolicy {
    upstream: std::sync::Arc<str>,
    allowed_origins: std::sync::Arc<[String]>,
    roots: std::sync::Arc<tokio_rustls::rustls::RootCertStore>,
    trust_identity: [u8; 32],
    /// 上游 QUIC 与 session 建立总时限。
    pub connect_timeout_ms: u64,
    /// 单 session stream、DATAGRAM、字节与空闲预算。
    pub budget: WebTransportBudget,
    /// session 从接受起的最长存活时间；0 表示不额外限制。
    pub max_lifetime_ms: u64,
}

impl WebTransportPolicy {
    /// 业务作用：从 route 配置构建固定 WebTransport 上游、Origin allowlist 与 TLS 信任快照。
    ///
    /// 参数说明：
    /// - `cfg`：是 route 的 WebTransport 声明
    /// - `config_dir`：是相对 CA 路径的受控根。
    ///
    /// 返回：全部 URL、来源、证书和预算合法时返回只读策略；任一失败拒绝候选快照。
    pub fn build(cfg: &crate::config::model::WebTransportCfg, config_dir: &Path) -> Result<Self> {
        let upstream: http::Uri = cfg
            .upstream
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid WebTransport upstream URL: {error}"))?;
        anyhow::ensure!(
            upstream.scheme_str() == Some("https") && upstream.authority().is_some(),
            "webtransport.upstream must be an absolute https URL"
        );
        anyhow::ensure!(
            !upstream
                .authority()
                .expect("authority presence checked above")
                .as_str()
                .contains('@'),
            "webtransport.upstream must not contain userinfo"
        );
        anyhow::ensure!(
            !cfg.allowed_origins.is_empty(),
            "webtransport.allowed_origins must not be empty"
        );
        anyhow::ensure!(
            cfg.allowed_origins.len() <= 256,
            "webtransport.allowed_origins exceeds 256 entries"
        );
        let mut allowed_origins = Vec::with_capacity(cfg.allowed_origins.len());
        for raw in &cfg.allowed_origins {
            let origin = normalize_origin(raw)?;
            anyhow::ensure!(
                !allowed_origins.contains(&origin),
                "webtransport.allowed_origins contains duplicate origin `{origin}`"
            );
            allowed_origins.push(origin);
        }
        let budget = WebTransportBudget {
            max_bidi_streams: cfg.max_bidi_streams,
            max_uni_streams: cfg.max_uni_streams,
            max_datagram_queue: cfg.max_datagram_queue,
            max_datagram_bytes: cfg.max_datagram_bytes,
            max_bytes: cfg.max_bytes,
            idle_timeout_ms: cfg.idle_timeout_ms,
        };
        budget.validate()?;
        anyhow::ensure!(
            (1..=60_000).contains(&cfg.connect_timeout_ms),
            "webtransport.connect_timeout_ms must be within 1..=60000"
        );
        anyhow::ensure!(
            cfg.max_lifetime_ms <= 7 * 24 * 60 * 60 * 1_000,
            "webtransport.max_lifetime_ms must not exceed 7 days"
        );
        let roots = load_webtransport_roots(cfg.ca_file.as_deref(), config_dir)?;
        let trust_identity = semantic::trust_identity(&roots);
        Ok(Self {
            upstream: std::sync::Arc::from(cfg.upstream.as_str()),
            allowed_origins: allowed_origins.into(),
            roots: std::sync::Arc::new(roots),
            trust_identity,
            connect_timeout_ms: cfg.connect_timeout_ms,
            budget,
            max_lifetime_ms: cfg.max_lifetime_ms,
        })
    }

    /// 业务作用：校验浏览器 WebTransport session 的权威 Origin，防止跨站页面借用户凭据
    /// 建立长期双向通道。
    ///
    /// 参数说明：
    /// - `headers`：是经过通用 header 预算检查的 CONNECT 请求头。
    ///
    /// 返回：唯一 Origin 命中 allowlist 时返回规范化值；缺失、重复、非法或越权时返回错误。
    pub fn authorize_origin(&self, headers: &http::HeaderMap) -> Result<std::sync::Arc<str>> {
        let mut values = headers.get_all(http::header::ORIGIN).iter();
        let raw = values
            .next()
            .ok_or_else(|| anyhow::anyhow!("WebTransport Origin header is required"))?;
        anyhow::ensure!(
            values.next().is_none(),
            "WebTransport Origin must be singular"
        );
        let raw = raw
            .to_str()
            .map_err(|_| anyhow::anyhow!("WebTransport Origin is not valid ASCII"))?;
        let normalized = normalize_origin(raw)?;
        anyhow::ensure!(
            self.allowed_origins.contains(&normalized),
            "WebTransport Origin is not allowed"
        );
        Ok(std::sync::Arc::from(normalized))
    }

    /// 业务作用：读取构建期冻结的固定上游 URL。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回包含 HTTPS authority 与 session path 的 URL。
    pub fn upstream(&self) -> &str {
        self.upstream.as_ref()
    }

    /// 业务作用：为每个上游 QUIC endpoint 提供同一快照内冻结的信任根。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回只读 rustls 根证书集合；不包含客户端可控材料。
    pub fn roots(&self) -> std::sync::Arc<tokio_rustls::rustls::RootCertStore> {
        self.roots.clone()
    }
}

/// 业务作用：把配置 Origin 归一为只含 scheme 与 authority 的稳定比较键。
///
/// 参数说明：
/// - `raw`：是配置或请求头中的单个 Origin。
///
/// 返回：合法 HTTP(S) origin 的小写形式；通配符、路径、query、fragment 或 userinfo 返回错误。
fn normalize_origin(raw: &str) -> Result<String> {
    anyhow::ensure!(
        raw == raw.trim(),
        "WebTransport Origin must not contain outer whitespace"
    );
    anyhow::ensure!(
        !raw.contains('*'),
        "WebTransport Origin wildcard is forbidden"
    );
    let uri: http::Uri = raw
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid WebTransport Origin: {error}"))?;
    let scheme = uri
        .scheme_str()
        .filter(|scheme| matches!(*scheme, "http" | "https"))
        .ok_or_else(|| anyhow::anyhow!("WebTransport Origin must use http or https"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("WebTransport Origin must contain authority"))?;
    anyhow::ensure!(
        !authority.as_str().contains('@'),
        "WebTransport Origin userinfo is forbidden"
    );
    anyhow::ensure!(
        uri.path_and_query()
            .is_none_or(|value| value.as_str() == "/"),
        "WebTransport Origin must not contain path or query"
    );
    Ok(format!("{scheme}://{authority}").to_ascii_lowercase())
}

/// 业务作用：在候选构建期加载 WebTransport 上游信任根，使坏 CA 永远不会进入请求热路径。
///
/// 参数说明：
/// - `ca_file`：是可选自定义 PEM
/// - `config_dir`：解析相对路径。
///
/// 返回：至少包含一个合法根证书的 store；读取或解析失败时拒绝候选快照。
fn load_webtransport_roots(
    ca_file: Option<&str>,
    config_dir: &Path,
) -> Result<tokio_rustls::rustls::RootCertStore> {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    if let Some(raw) = ca_file.filter(|value| !value.trim().is_empty()) {
        let path = resolve_webtransport_path(config_dir, raw);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read WebTransport CA `{}`", path.display()))?;
        let mut reader = BufReader::new(bytes.as_slice());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("parse WebTransport CA `{}`", path.display()))?;
        anyhow::ensure!(
            !certificates.is_empty(),
            "WebTransport CA `{}` contains no certificates",
            path.display()
        );
        for certificate in certificates {
            roots
                .add(certificate)
                .with_context(|| format!("add WebTransport CA `{}`", path.display()))?;
        }
    } else {
        let result = rustls_native_certs::load_native_certs();
        for certificate in result.certs {
            let _ = roots.add(certificate);
        }
        anyhow::ensure!(
            !roots.is_empty(),
            "system trust store contains no usable WebTransport CA"
        );
    }
    Ok(roots)
}

/// 业务作用：按主配置目录解析 WebTransport CA，保证构建与 dependency watcher 使用同一路径。
///
/// 参数说明：
/// - `config_dir`：是主配置目录
/// - `raw`：是用户声明路径。
///
/// 返回：绝对路径保持不变，相对路径固定拼到配置目录。
pub(crate) fn resolve_webtransport_path(config_dir: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

// ---------------------------------------------------------------------------
// QUIC 变长整数与 capsule 编解码
// ---------------------------------------------------------------------------

/// 业务作用：解码 RFC 9000 第 16 节定义的 QUIC 变长整数。
///
/// 参数说明：
/// - `input`：是待解码字节；解码成功后会前移。
///
/// 返回：解码出的值;输入不足以容纳完整整数时返回 `None`——
/// 这里必须返回"数据不够"而不是尽力而为地解析半个整数,
/// 半个整数会被当成一个合法的小值,后续长度判定全部失真。
pub fn decode_varint(input: &mut &[u8]) -> Option<u64> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &input[1..len] {
        value = (value << 8) | *byte as u64;
    }
    *input = &input[len..];
    Some(value)
}

/// 业务作用：编码 QUIC 变长整数。
///
/// 参数说明：
/// - `value`：是待编码值
/// - `out`：是输出缓冲。
///
/// 返回：编码成功返回 `Ok`;超出变长整数可表示范围(2^62-1)时返回错误。
pub fn encode_varint(value: u64, out: &mut Vec<u8>) -> Result<()> {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => bail!("varint 超出可表示范围"),
    }
    Ok(())
}

/// capsule 解析结果。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CapsuleOutcome {
    /// 成功解析出一个完整 capsule。
    Capsule {
        /// capsule 类型。
        kind: u64,
        /// capsule 载荷。
        payload: Vec<u8>,
    },
    /// 当前缓冲还不足以构成完整 capsule,需要更多字节。
    Incomplete,
    /// capsule 声明的长度超过上限,必须断流。
    TooLarge {
        /// 对端声明的长度。
        declared: u64,
    },
}

/// 业务作用：从缓冲中解析一个 capsule(RFC 9297)。
///
/// 参数说明：
/// - `input`：是已接收字节；成功解析时前移到下一个 capsule。
///
/// 返回：解析结果。声明长度超过 `MAX_CAPSULE_LEN` 时返回 `TooLarge`,
/// **且不做任何按声明长度的预分配**——按对端声明的长度分配内存,
/// 等于把内存控制权交给对端。
pub fn parse_capsule(input: &mut &[u8]) -> CapsuleOutcome {
    let mut cursor = *input;
    let Some(kind) = decode_varint(&mut cursor) else {
        return CapsuleOutcome::Incomplete;
    };
    let Some(len) = decode_varint(&mut cursor) else {
        return CapsuleOutcome::Incomplete;
    };
    if len > MAX_CAPSULE_LEN {
        return CapsuleOutcome::TooLarge {
            declared: len,
        };
    }
    let len = len as usize;
    if cursor.len() < len {
        return CapsuleOutcome::Incomplete;
    }
    let payload = cursor[..len].to_vec();
    *input = &cursor[len..];
    CapsuleOutcome::Capsule {
        kind,
        payload,
    }
}

/// DATAGRAM capsule 类型(RFC 9297)。
pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

/// 业务作用：从 DATAGRAM capsule 载荷中取出 context id 与 UDP payload。
///
/// 参数说明：
/// - `payload`：是 DATAGRAM capsule 的载荷。
///
/// 返回：`(context_id, udp_payload)`;载荷缺少 context id 或 payload 超限时返回 `None`。
/// **datagram 之间彼此独立,这里不做任何跨 datagram 的重组**:
/// UDP 本就允许乱序丢失,按序重组既无从判断边界,又会形成无界缓冲。
pub fn parse_datagram_capsule(payload: &[u8]) -> Option<(u64, &[u8])> {
    let mut cursor = payload;
    let context_id = decode_varint(&mut cursor)?;
    if cursor.len() > MAX_DATAGRAM_PAYLOAD {
        return None;
    }
    Some((context_id, cursor))
}

// ---------------------------------------------------------------------------
// CONNECT-UDP 目标
// ---------------------------------------------------------------------------

/// 业务作用：从 CONNECT-UDP 的 URI template 路径中解析目标(RFC 9298)。
///
/// 形如 `/.well-known/masque/udp/{host}/{port}/`。目标由请求方指定,因此
/// **必须复用 CONNECT 的同一套 allowlist 与 SSRF 判定**:UDP 出口能打到的内网
/// 与 TCP 完全一样，给它另开一套宽松规则会绕过 CONNECT 已建立的目标安全边界。
///
/// 参数说明：
/// - `path`：是请求路径。
///
/// 返回：解析出的目标;路径形态不合法时返回 `MalformedAuthority`。
pub fn parse_connect_udp_path(path: &str) -> Result<ConnectTarget, DenyReason> {
    const PREFIX: &str = "/.well-known/masque/udp/";
    let rest = path
        .strip_prefix(PREFIX)
        .ok_or(DenyReason::MalformedAuthority)?;
    let mut segments = rest.split('/');
    let host = segments.next().ok_or(DenyReason::MalformedAuthority)?;
    let port = segments.next().ok_or(DenyReason::MalformedAuthority)?;
    // template 之后只允许空段(结尾斜杠);出现其它内容说明客户端在拼接额外路径。
    if segments.any(|extra| !extra.is_empty()) {
        return Err(DenyReason::MalformedAuthority);
    }
    if host.is_empty() || port.is_empty() {
        return Err(DenyReason::MalformedAuthority);
    }
    let host = percent_decode(host)?;
    // 解码后再出现分隔符说明是编码绕过尝试(`%2f`、`%3a` 等),直接拒绝。
    if host.contains('/') || host.contains(':') || host.contains('%') || host.contains('\\') {
        return Err(DenyReason::MalformedAuthority);
    }
    let port: u16 = port.parse().map_err(|_| DenyReason::MalformedAuthority)?;
    if port == 0 {
        return Err(DenyReason::MalformedAuthority);
    }
    Ok(ConnectTarget {
        host,
        port,
    })
}

/// 业务作用：有界解码 CONNECT-UDP host 路径段，仅接受合法的两位十六进制转义。
///
/// 参数说明：
/// - `raw`：是尚未解码的单个路径段。
///
/// 返回：合法 UTF-8 字符串；转义或编码非法时返回 `MalformedAuthority`。
fn percent_decode(raw: &str) -> Result<String, DenyReason> {
    if !raw.contains('%') {
        return Ok(raw.to_string());
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return Err(DenyReason::MalformedAuthority);
            }
            let hex = std::str::from_utf8(&bytes[idx + 1..idx + 3])
                .map_err(|_| DenyReason::MalformedAuthority)?;
            let value = u8::from_str_radix(hex, 16).map_err(|_| DenyReason::MalformedAuthority)?;
            out.push(value);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    String::from_utf8(out).map_err(|_| DenyReason::MalformedAuthority)
}

/// 业务作用：对 CONNECT-UDP 目标执行与 CONNECT 完全一致的目标校验。
///
/// 参数说明：
/// - `policy`：是复用的正向代理目标策略
/// - `target`：是已解析的 UDP 目标。
///
/// 返回：通过校验的地址列表;任一环节不通过返回拒绝原因。
pub async fn resolve_connect_udp(
    policy: &ForwardProxyPolicy,
    target: &ConnectTarget,
) -> Result<Vec<std::net::SocketAddr>, DenyReason> {
    policy.check_authority(target)?;
    policy.resolve_checked(target).await
}

// ---------------------------------------------------------------------------
// WebTransport 会话预算
// ---------------------------------------------------------------------------

/// 单个 WebTransport 会话的资源预算。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebTransportBudget {
    /// 会话内允许的最大并发双向流数。
    pub max_bidi_streams: u64,
    /// 会话内允许的最大并发单向流数。
    pub max_uni_streams: u64,
    /// 待发 datagram 队列长度上限。
    pub max_datagram_queue: u64,
    /// 单个 datagram payload 上限。
    pub max_datagram_bytes: usize,
    /// 会话累计字节上限;0 表示不限制。
    pub max_bytes: u64,
    /// 会话空闲上限(ms)。
    pub idle_timeout_ms: u64,
}

impl WebTransportBudget {
    /// 业务作用：校验会话预算,拒绝"等于不设限"的取值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：合法返回 `Ok`;流数、队列或 idle 为 0 时返回错误——
    /// 未设限的会话可以被单个客户端用来耗尽整个进程的流与内存配额。
    pub fn validate(&self) -> Result<()> {
        if self.max_bidi_streams == 0 && self.max_uni_streams == 0 {
            bail!("webtransport 会话必须至少允许一种流类型");
        }
        if self.max_bidi_streams > 4_096 || self.max_uni_streams > 4_096 {
            bail!("webtransport 单类 stream 上限不得超过 4096");
        }
        if self.max_datagram_queue == 0 {
            bail!("webtransport.max_datagram_queue 必须大于 0");
        }
        if self.max_datagram_queue > 4_096 {
            bail!("webtransport.max_datagram_queue 不得超过 4096");
        }
        if !(1..=MAX_DATAGRAM_PAYLOAD).contains(&self.max_datagram_bytes) {
            bail!("webtransport.max_datagram_bytes 必须位于 1..={MAX_DATAGRAM_PAYLOAD}");
        }
        if self
            .max_datagram_queue
            .saturating_mul(self.max_datagram_bytes as u64)
            > 16 * 1024 * 1024
        {
            bail!("webtransport 单方向 DATAGRAM 队列字节预算不得超过 16 MiB");
        }
        if self.idle_timeout_ms == 0 {
            bail!("webtransport.idle_timeout_ms 必须大于 0:无 idle 上限的会话不会被回收");
        }
        Ok(())
    }
}

/// 会话准入结果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionAdmission {
    /// 允许。
    Accepted,
    /// 流数超限。
    StreamLimit,
    /// datagram 队列已满;按 RFC 语义丢弃而不是排队,避免无界缓冲。
    DatagramQueueFull,
    /// datagram 载荷超过协议与实现上限。
    PayloadTooLarge,
    /// 会话字节预算耗尽。
    ByteBudgetExhausted,
}

/// WebTransport 会话运行态。
#[derive(Debug, Default)]
pub struct WebTransportSession {
    bidi_streams: AtomicU64,
    uni_streams: AtomicU64,
    queued_datagrams: AtomicU64,
    used_bytes: AtomicU64,
    /// 会话建立时冻结的客户端身份指纹。
    identity: Mutex<Option<String>>,
}

impl WebTransportSession {
    /// 业务作用：在会话建立时冻结客户端身份。
    ///
    /// 连接迁移(QUIC 换地址)后客户端 IP 会变,但**身份不随之改变**:
    /// 迁移是传输层事件,不是重新认证。若让身份跟着新地址走,攻击者只要
    /// 触发一次迁移就能让会话被当成另一个主体。
    ///
    /// 参数说明：
    /// - `fingerprint`：是握手期确定的身份指纹。
    ///
    /// 返回：无返回值。
    pub fn freeze_identity(&self, fingerprint: String) {
        let mut identity = self
            .identity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if identity.is_none() {
            *identity = Some(fingerprint);
        }
    }

    /// 业务作用：给出会话身份;迁移后仍返回握手期冻结的值。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：握手期冻结的身份指纹。
    pub fn identity(&self) -> Option<String> {
        self.identity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// 业务作用：申请打开一条流。
    ///
    /// 参数说明：
    /// - `budget`：是会话预算
    /// - `bidirectional`：表示是否为双向流。
    ///
    /// 返回：允许时返回 `Accepted` 并已占用名额;超限返回 `StreamLimit`。
    pub fn open_stream(
        &self,
        budget: &WebTransportBudget,
        bidirectional: bool,
    ) -> SessionAdmission {
        let (counter, limit) = if bidirectional {
            (&self.bidi_streams, budget.max_bidi_streams)
        } else {
            (&self.uni_streams, budget.max_uni_streams)
        };
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return SessionAdmission::StreamLimit;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return SessionAdmission::Accepted,
                Err(observed) => current = observed,
            }
        }
    }

    /// 业务作用：归还一条已关闭的流名额。
    ///
    /// 参数说明：
    /// - `bidirectional`：表示是否为双向流。
    ///
    /// 返回：无返回值。
    pub fn close_stream(&self, bidirectional: bool) {
        let counter = if bidirectional {
            &self.bidi_streams
        } else {
            &self.uni_streams
        };
        let mut current = counter.load(Ordering::Relaxed);
        while current > 0 {
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// 业务作用：为一个待发 datagram 申请队列位置并记账字节。
    ///
    /// 参数说明：
    /// - `budget`：是会话预算
    /// - `len`：是 datagram 载荷长度。
    ///
    /// 返回：允许返回 `Accepted`;队列满返回 `DatagramQueueFull`(应当**丢弃**该
    /// datagram 而不是排队——datagram 本就是不可靠语义,为它做无界缓冲既违背协议
    /// 语义又是内存放大);字节预算耗尽返回 `ByteBudgetExhausted`。
    pub fn enqueue_datagram(&self, budget: &WebTransportBudget, len: usize) -> SessionAdmission {
        if len > budget.max_datagram_bytes {
            return SessionAdmission::PayloadTooLarge;
        }
        let mut queued = self.queued_datagrams.load(Ordering::Relaxed);
        loop {
            if queued >= budget.max_datagram_queue {
                return SessionAdmission::DatagramQueueFull;
            }
            match self.queued_datagrams.compare_exchange_weak(
                queued,
                queued + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => queued = observed,
            }
        }
        if budget.max_bytes > 0 {
            let len = len as u64;
            let mut used = self.used_bytes.load(Ordering::Relaxed);
            loop {
                let Some(next) = used.checked_add(len) else {
                    self.dequeue_datagram();
                    return SessionAdmission::ByteBudgetExhausted;
                };
                if next > budget.max_bytes {
                    // 队列位置与累计字节必须作为一个准入事务。字节门拒绝时先归还位置，
                    // 否则重复的大包能在没有任何有效 datagram 入队时耗尽队列。
                    self.dequeue_datagram();
                    return SessionAdmission::ByteBudgetExhausted;
                }
                match self.used_bytes.compare_exchange_weak(
                    used,
                    next,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => used = observed,
                }
            }
        }
        SessionAdmission::Accepted
    }

    /// 业务作用：datagram 发出后归还队列位置。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无返回值。
    pub fn dequeue_datagram(&self) {
        let mut queued = self.queued_datagrams.load(Ordering::Relaxed);
        while queued > 0 {
            match self.queued_datagrams.compare_exchange_weak(
                queued,
                queued - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => queued = observed,
            }
        }
    }

    /// 业务作用：读取当前排队 datagram 数，供容量与背压观测。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：尚未完成发送的 datagram 数量。
    pub fn queued_datagrams(&self) -> u64 {
        self.queued_datagrams.load(Ordering::Relaxed)
    }

    /// 业务作用：为 stream 或成功转发的 DATAGRAM 原子占用会话累计字节预算。
    ///
    /// 参数说明：
    /// - `budget`：是当前快照预算
    /// - `len`：是即将交付给对端的 payload 字节数。
    ///
    /// 返回：允许时返回 `Accepted` 并推进累计值；溢出或超过上限返回
    /// `ByteBudgetExhausted`，原计数保持不变。
    pub fn admit_bytes(&self, budget: &WebTransportBudget, len: usize) -> SessionAdmission {
        if budget.max_bytes == 0 {
            return SessionAdmission::Accepted;
        }
        let len = len as u64;
        let mut used = self.used_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = used.checked_add(len) else {
                return SessionAdmission::ByteBudgetExhausted;
            };
            if next > budget.max_bytes {
                return SessionAdmission::ByteBudgetExhausted;
            }
            match self.used_bytes.compare_exchange_weak(
                used,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return SessionAdmission::Accepted,
                Err(observed) => used = observed,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 安全 0-RTT
// ---------------------------------------------------------------------------

/// 0-RTT 拒绝原因。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EarlyDataDenial {
    /// route 未显式开启 0-RTT。
    NotEnabled,
    /// 方法非幂等。
    NonIdempotentMethod,
    /// 请求携带敏感凭据。
    SensitiveCredential,
    /// 命中重放。
    Replayed,
    /// 缺少一次性 nonce。
    MissingNonce,
    /// 缺少 RFC 8470 `Early-Data: 1` 声明。
    MissingIndicator,
    /// `Early-Data` 重复或值非法。
    InvalidIndicator,
    /// nonce 编码、长度或多值语义非法。
    InvalidNonce,
    /// early request 仍尝试携带实体。
    RequestBody,
}

impl EarlyDataDenial {
    /// 业务作用：给出低基数拒绝原因标签。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：稳定标签,可用作指标维度。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotEnabled => "not_enabled",
            Self::NonIdempotentMethod => "non_idempotent_method",
            Self::SensitiveCredential => "sensitive_credential",
            Self::Replayed => "replayed",
            Self::MissingNonce => "missing_nonce",
            Self::MissingIndicator => "missing_indicator",
            Self::InvalidIndicator => "invalid_indicator",
            Self::InvalidNonce => "invalid_nonce",
            Self::RequestBody => "request_body",
        }
    }
}

/// route 级 0-RTT 执行计划。
///
/// 业务作用：把显式 early-data 开关与 anti-replay 保留时间固化到不可变
/// route 快照；方法、认证与 body 互斥门由 Router 在构建同一候选时完成。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlyDataRoutePolicy {
    replay_window: Duration,
}

impl EarlyDataRoutePolicy {
    /// 业务作用：编译 route 的 early-data 去重窗口，拒绝无法约束内存或长期
    /// 占用共享账本的时间范围。
    ///
    /// 参数说明：
    /// - `cfg`：是 route 的 0-RTT 声明。
    ///
    /// 返回：关闭时返回 `None`；开启且窗口在 1 秒到 10 分钟时返回计划，
    /// 超界则拒绝候选路由。
    pub fn build(
        cfg: &crate::config::model::EarlyDataRouteCfg,
    ) -> Result<Option<EarlyDataRoutePolicy>> {
        if !cfg.enabled {
            return Ok(None);
        }
        anyhow::ensure!(
            (1_000..=600_000).contains(&cfg.replay_window_ms),
            "early_data.replay_window_ms must be within 1000..=600000"
        );
        Ok(Some(Self {
            replay_window: Duration::from_millis(cfg.replay_window_ms),
        }))
    }

    /// 业务作用：返回一次性 nonce 必须留在本地或共享去重账本中的时间。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：返回构建期已验证的有界时间。
    pub fn replay_window(&self) -> Duration {
        self.replay_window
    }
}

// ---------------------------------------------------------------------------
// 支持矩阵
// ---------------------------------------------------------------------------

/// 协议能力。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    /// WebTransport over HTTP/3。
    WebTransport,
    /// CONNECT-UDP / MASQUE。
    ConnectUdp,
    /// 应用可见 QUIC DATAGRAM。
    Datagram,
    /// TLS 1.3 0-RTT early data。
    EarlyData,
}

impl Capability {
    /// 业务作用：解析配置中的能力名。
    ///
    /// 参数说明：
    /// - `raw`：为配置字符串。
    ///
    /// 返回：识别成功返回能力;未知取值返回错误。写错一个能力名而被静默忽略,
    /// 运维会以为该能力已开启,这类偏差通常要到线上才暴露。
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "webtransport" => Ok(Self::WebTransport),
            "connect_udp" | "masque" => Ok(Self::ConnectUdp),
            "datagram" => Ok(Self::Datagram),
            "early_data" | "0rtt" => Ok(Self::EarlyData),
            other => bail!(
                "未知 QUIC 扩展能力 `{other}`,可选 webtransport|connect_udp|datagram|early_data"
            ),
        }
    }

    /// 业务作用：给出能力的稳定配置与日志名称。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：低基数、向后兼容的能力名称。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebTransport => "webtransport",
            Self::ConnectUdp => "connect_udp",
            Self::Datagram => "datagram",
            Self::EarlyData => "early_data",
        }
    }
}

/// 下游协议形态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// HTTP/1.1。
    Http1,
    /// HTTP/2。
    Http2,
    /// HTTP/3(QUIC)。
    Http3,
}

/// 业务作用：判定某能力在给定传输上是否受支持。
///
/// 参数说明：
/// - `capability`：是待判定能力
/// - `transport`：是下游传输。
///
/// 返回：受支持返回 true。
pub fn is_supported(capability: Capability, transport: Transport) -> bool {
    match capability {
        // 这三者都建立在 QUIC 之上,在 TCP 传输上没有等价形态。
        Capability::WebTransport | Capability::ConnectUdp | Capability::Datagram => {
            transport == Transport::Http3
        }
        // early data 依赖 TLS 1.3 会话恢复;h1/h2 上的 early data 不在本模块治理范围内。
        Capability::EarlyData => transport == Transport::Http3,
    }
}

/// 业务作用：在构建期校验"能力 × 传输"组合。
///
/// 参数说明：
/// - `capability`：是声明启用的能力
/// - `transport`：是该 listener 的下游传输。
///
/// 返回：受支持返回 `Ok`;不受支持返回错误。
///
/// 这里**必须报错而不是静默退化**成普通 HTTP/3 或普通反代:静默退化会让运维
/// 以为 WebTransport 已经在跑,实际客户端全部落到了另一条路径上,
/// 而这种偏差通常要到线上才被发现。
pub fn check_support(capability: Capability, transport: Transport) -> Result<()> {
    if is_supported(capability, transport) {
        return Ok(());
    }
    bail!(
        "能力 `{}` 在当前下游传输上不受支持,不能静默退化;请改用 HTTP/3 listener 或关闭该能力",
        capability.as_str()
    );
}

/// 业务作用：给出 datagram 背压与丢包的可观测计数器。
#[derive(Debug, Default)]
pub struct DatagramStats {
    /// 因队列满被丢弃的 datagram 数。
    pub dropped_queue_full: AtomicU64,
    /// 因超出载荷上限被拒的 datagram 数。
    pub dropped_oversized: AtomicU64,
    /// 因会话累计字节预算耗尽被拒的 datagram 数。
    pub dropped_byte_budget: AtomicU64,
    /// 成功转发的 datagram 数。
    pub forwarded: AtomicU64,
}

impl DatagramStats {
    /// 业务作用：登记一次 datagram 处置结果,使丢弃在指标上可见。
    ///
    /// datagram 的丢弃是正常语义而不是故障,但**不可见的丢弃**会让容量问题
    /// 表现为"应用偶发丢消息",极难定位。因此每一种丢弃都要单独计数。
    ///
    /// 参数说明：
    /// - `outcome`：是会话准入结果。
    ///
    /// 返回：无返回值。
    pub fn record(&self, outcome: SessionAdmission) {
        match outcome {
            SessionAdmission::Accepted => increment_saturating(&self.forwarded),
            SessionAdmission::DatagramQueueFull => increment_saturating(&self.dropped_queue_full),
            SessionAdmission::PayloadTooLarge => increment_saturating(&self.dropped_oversized),
            SessionAdmission::ByteBudgetExhausted => {
                increment_saturating(&self.dropped_byte_budget)
            }
            // 流准入结果不属于 datagram 处置，调用方误传时不污染 datagram 指标。
            SessionAdmission::StreamLimit => {}
        };
    }
}

/// 业务作用：给出 datagram 空闲会话的默认回收扫描周期，在回收及时性与扫描开销间取界。
///
/// 参数说明: 无。
///
/// 返回：默认 500ms 扫描周期。
pub fn datagram_idle_sweep() -> Duration {
    Duration::from_millis(500)
}

/// 业务作用：饱和递增可观测计数器，避免极长进程运行后回绕为低值误导告警。
///
/// 参数说明：
/// - `counter`：是待递增原子计数器。
///
/// 返回：无；计数达到 `u64::MAX` 后保持最大值。
fn increment_saturating(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
