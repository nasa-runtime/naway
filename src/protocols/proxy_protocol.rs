//! PROXY protocol v1/v2 解析。
//!
//! 该协议头在 TCP 建连后、TLS/HTTP 之前由前置 L4 LB 写入,用于把真实客户端地址传给网关。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::config::ProxyProtocolRuntimeCfg;
use crate::io::net;

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V1_MAX_LEN: usize = 108;

/// 写给上游的 PROXY protocol 版本。
#[derive(Clone, Copy)]
pub enum ProxyProtocolWriteVersion {
    /// 文本 v1 头。
    V1,
    /// 二进制 v2 头。
    V2,
}

/// 连接级地址信息。`real_peer` 优先来自可信 PROXY 头,否则等于 TCP 对端。
#[derive(Clone)]
pub struct ConnInfo {
    /// 内核 accept 得到的直接 TCP 对端。
    pub tcp_peer: SocketAddr,
    /// 经可信 PROXY 头还原后的客户端地址；无头时等于 `tcp_peer`。
    pub real_peer: SocketAddr,
    /// 地址是否来自已经校验来源的 PROXY protocol 头。
    pub via_proxy_protocol: bool,
    /// mTLS:本连接是否出示了【经 CA 校验通过】的客户端证书。TLS 握手后由 accept loop 置位;
    /// 明文/无 client_auth 恒 false。数据面据此向上游注入 `X-Client-Cert-Verified`。
    pub client_cert_verified: bool,
    /// TLS 握手完成后由 rustls 提供的规范化 SNI；明文、HTTP/3 或未携带 SNI 时为 None。
    /// 该值来自 ClientHello，不能由同一连接上的 HTTP 请求头覆盖。
    pub tls_server_name: Option<Arc<str>>,
}

/// 业务作用：按配置剥离 PROXY protocol 头。禁用时不读流,直接返回 TCP 对端。
pub async fn strip_proxy_protocol(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: &ProxyProtocolRuntimeCfg,
) -> Result<(TcpStream, ConnInfo)> {
    if !cfg.enabled {
        return Ok((stream, ConnInfo::plain(peer)));
    }
    // 只有落在 accept_from(构建期已解析成 Cidr)内的直连对端才允许携带 PROXY 头;否则 fail-closed。
    if !net::any_contains(cfg.accept_from.as_slice(), peer.ip()) {
        bail!("peer {peer} is not in proxy_protocol.accept_from");
    }
    let timeout = Duration::from_millis(cfg.timeout_ms.max(1));
    let info = tokio::time::timeout(timeout, read_proxy_header(&mut stream, peer, cfg))
        .await
        .context("proxy protocol read timeout")??;
    Ok((stream, info))
}

impl ConnInfo {
    /// 业务作用：从内核 accept 地址构造未经过 PROXY protocol 的连接信息。
    ///
    /// 禁用 PROXY protocol 的 listener 可在 accept loop 直接使用它，不必为了调用一个立即
    /// 返回的 async parser 额外创建 task。所有地址仍来自内核，不能伪造 `via_proxy_protocol`。
    pub fn plain(peer: SocketAddr) -> Self {
        Self {
            tcp_peer: peer,
            real_peer: peer,
            via_proxy_protocol: false,
            client_cert_verified: false,
            tls_server_name: None,
        }
    }
}

/// 业务作用：编码发往上游的 PROXY protocol 头。
///
/// 参数说明：
/// - `src`: 真实客户端地址。
/// - `dst`: 下游连接在本网关上的本地地址,表示客户端原始连接目标。
/// - `version`: 写出的 PROXY protocol 版本。
pub fn encode_proxy_protocol_header(
    src: SocketAddr,
    dst: SocketAddr,
    version: ProxyProtocolWriteVersion,
) -> Result<Vec<u8>> {
    match version {
        ProxyProtocolWriteVersion::V1 => encode_proxy_protocol_v1(src, dst),
        ProxyProtocolWriteVersion::V2 => encode_proxy_protocol_v2(src, dst),
    }
}

/// 业务作用：编码 PROXY protocol v1 文本头。
fn encode_proxy_protocol_v1(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>> {
    let proto = match (src.ip(), dst.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
        (IpAddr::V6(_), IpAddr::V6(_)) => "TCP6",
        _ => bail!("PROXY protocol v1 cannot encode mixed address families"),
    };
    Ok(format!(
        "PROXY {proto} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    )
    .into_bytes())
}

/// 业务作用：编码 PROXY protocol v2 二进制头。
fn encode_proxy_protocol_v2(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(V2_SIGNATURE);
    out.push(0x21);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
            out.push(0x11);
            out.extend_from_slice(&12_u16.to_be_bytes());
            out.extend_from_slice(&src_ip.octets());
            out.extend_from_slice(&dst_ip.octets());
        }
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
            out.push(0x21);
            out.extend_from_slice(&36_u16.to_be_bytes());
            out.extend_from_slice(&src_ip.octets());
            out.extend_from_slice(&dst_ip.octets());
        }
        _ => bail!("PROXY protocol v2 cannot encode mixed address families"),
    }
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    Ok(out)
}

/// 业务作用：在固定字节与时间预算内读取 PROXY protocol 头，保留后续业务字节供真实协议栈消费。
async fn read_proxy_header(
    stream: &mut TcpStream,
    peer: SocketAddr,
    cfg: &ProxyProtocolRuntimeCfg,
) -> Result<ConnInfo> {
    // 只先读 12 字节：v2 签名恰为 12 字节，而 v1 最短头 `PROXY UNKNOWN\r\n` 为 15 字节，
    //   只读共同可判别的长度，避免把 v1 UNKNOWN 头后的业务字节当作协议头吞掉。
    let mut head = [0_u8; 12];
    stream
        .read_exact(&mut head)
        .await
        .context("read proxy protocol prefix")?;
    if head == *V2_SIGNATURE {
        if !cfg.allow_v2 {
            bail!("PROXY protocol v2 is disabled for this listener");
        }
        return parse_v2(stream, peer).await;
    }
    if head.starts_with(b"PROXY ") {
        if !cfg.allow_v1 {
            bail!("PROXY protocol v1 is disabled for this listener");
        }
        return parse_v1(stream, peer, head.to_vec()).await;
    }
    bail!("missing PROXY protocol header");
}

/// 业务作用：验证文本 PROXY 头的地址族、端口和结束边界，不把畸形身份当作客户端来源。
async fn parse_v1(stream: &mut TcpStream, peer: SocketAddr, mut line: Vec<u8>) -> Result<ConnInfo> {
    while !line.ends_with(b"\n") {
        if line.len() >= V1_MAX_LEN {
            bail!("PROXY protocol v1 header too long");
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
    }
    let line = std::str::from_utf8(&line)
        .context("PROXY protocol v1 header is not utf-8")?
        .trim_end_matches(['\r', '\n']);
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 || parts[0] != "PROXY" {
        bail!("invalid PROXY protocol v1 header");
    }
    if parts[1] == "UNKNOWN" {
        return Ok(ConnInfo::plain(peer));
    }
    if parts.len() != 6 || (parts[1] != "TCP4" && parts[1] != "TCP6") {
        bail!("unsupported PROXY protocol v1 header `{line}`");
    }
    let src_ip: IpAddr = parts[2]
        .parse()
        .with_context(|| format!("invalid PROXY source ip `{}`", parts[2]))?;
    let src_port: u16 = parts[4]
        .parse()
        .with_context(|| format!("invalid PROXY source port `{}`", parts[4]))?;
    Ok(ConnInfo {
        tcp_peer: peer,
        real_peer: SocketAddr::new(src_ip, src_port),
        via_proxy_protocol: true,
        client_cert_verified: false,
        tls_server_name: None,
    })
}

/// 业务作用：解析二进制 PROXY 头并验证长度与地址族，未支持的输入不能改变连接身份。
async fn parse_v2(stream: &mut TcpStream, peer: SocketAddr) -> Result<ConnInfo> {
    // 12 字节签名已在 read_proxy_header 消费,这里续读 4 字节头(ver_cmd / fam / len)。
    let mut hdr = [0_u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .context("read PROXY protocol v2 header")?;
    let ver_cmd = hdr[0];
    if ver_cmd >> 4 != 0x2 {
        bail!("invalid PROXY protocol v2 version");
    }
    let fam = hdr[1];
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read PROXY protocol v2 payload")?;
    if ver_cmd & 0x0f == 0x00 {
        return Ok(ConnInfo::plain(peer));
    }
    if ver_cmd & 0x0f != 0x01 {
        bail!("unsupported PROXY protocol v2 command");
    }
    match fam {
        0x11 if payload.len() >= 12 => {
            let src = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(ConnInfo {
                tcp_peer: peer,
                real_peer: SocketAddr::new(IpAddr::V4(src), port),
                via_proxy_protocol: true,
                client_cert_verified: false,
                tls_server_name: None,
            })
        }
        0x21 if payload.len() >= 36 => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[0..16]).expect("slice len"));
            let port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(ConnInfo {
                tcp_peer: peer,
                real_peer: SocketAddr::new(IpAddr::V6(src), port),
                via_proxy_protocol: true,
                client_cert_verified: false,
                tls_server_name: None,
            })
        }
        0x00 => Ok(ConnInfo::plain(peer)),
        _ => bail!("unsupported PROXY protocol v2 address family/protocol 0x{fam:02x}"),
    }
}
