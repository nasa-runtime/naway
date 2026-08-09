use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use bytes::{Buf, Bytes};
use futures::future::join_all;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{lookup_host, TcpListener};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// 业务作用：在正式 Docker 横评中提供固定 HTTP/1 keepalive 上游或 HTTP/3 并发客户端，
/// 保证 Naway 与 Envoy 使用同一 workload、同一网络和同一计时边界。
///
/// 参数说明: 无。
///
/// 返回：子命令完成时返回成功；参数、TLS、QUIC 或协议错误会使进程非零退出。
#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("backend") => {
            let listen = required_arg(&args, "--listen")?
                .parse::<SocketAddr>()
                .context("parse backend --listen")?;
            run_backend(listen).await
        }
        Some("client") => run_client(&args).await,
        _ => bail!(
            "usage: local_h3_benchmark backend --listen ADDR | client --target HOST:PORT --ca FILE --requests N --concurrency N --connections N --warmup N --label NAME"
        ),
    }
}

/// 业务作用：读取必填 CLI 参数并拒绝缺值，防止性能脚本默默使用不同默认值造成不可比结果。
///
/// 参数说明：`args` 是完整 argv；`name` 是形如 `--target` 的键。
///
/// 返回：成功时借用参数值；缺少键或值时返回明确错误。
fn required_arg<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .with_context(|| format!("missing {name}"))?;
    args.get(index + 1)
        .map(String::as_str)
        .with_context(|| format!("missing value for {name}"))
}

/// 业务作用：启动无业务计算、固定小响应的 HTTP/1 keepalive 上游，把 H3 横评成本聚焦在
/// 两个代理的数据面而不是后端连接重建或应用延迟。
///
/// 参数说明：`listen` 是 Docker network 内对 Naway/Envoy 同时可达的地址。
///
/// 返回：listener 运行到进程终止；accept 失败时返回错误。
async fn run_backend(listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind benchmark backend {listen}"))?;
    loop {
        let (stream, _) = listener.accept().await.context("accept backend socket")?;
        tokio::spawn(async move {
            let service = service_fn(|_request| async move {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"h3-ok"))))
            });
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// 业务作用：解析并执行单个代理的 H3 负载轮次，预热不计时，正式区间只包含完成指定
/// request/response 的时间，最终输出一行机器可读 JSON。
///
/// 参数说明：`args` 包含 target、CA、请求数、并发、物理连接数、预热数和实现标签。
///
/// 返回：所有响应为 HTTP 200 且完整排空时返回成功，否则 fail closed。
async fn run_client(args: &[String]) -> Result<()> {
    let target = required_arg(args, "--target")?;
    let ca_file = Path::new(required_arg(args, "--ca")?);
    let requests = parse_positive(args, "--requests")?;
    let concurrency = parse_positive(args, "--concurrency")?;
    let connections = parse_positive(args, "--connections")?;
    let warmup = parse_positive(args, "--warmup")?;
    let label = required_arg(args, "--label")?;
    if connections > concurrency {
        bail!("--connections must not exceed --concurrency");
    }
    let server_name = args
        .iter()
        .position(|arg| arg == "--server-name")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or("localhost");

    let address = lookup_host(target)
        .await
        .with_context(|| format!("resolve benchmark target {target}"))?
        .next()
        .with_context(|| format!("target {target} resolved no address"))?;
    let certificate = read_first_certificate(ca_file)?;
    let endpoint = h3_client_endpoint(certificate)?;
    let mut senders = Vec::with_capacity(connections);
    let mut driver_tasks = Vec::with_capacity(connections);
    for connection_index in 0..connections {
        let connection = endpoint
            .connect(address, server_name)
            .with_context(|| format!("start benchmark QUIC connect {connection_index}"))?
            .await
            .with_context(|| format!("complete benchmark QUIC handshake {connection_index}"))?;
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .with_context(|| format!("start benchmark HTTP/3 client {connection_index}"))?;
        senders.push(sender);
        driver_tasks.push(tokio::spawn(async move { driver.wait_idle().await }));
    }

    let authority = format!("https://{server_name}/bench");
    issue_requests(&senders, warmup, concurrency, &authority).await?;
    let started = Instant::now();
    let mut latencies = issue_requests(&senders, requests, concurrency, &authority).await?;
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    let p99_index = ((latencies.len() * 99).div_ceil(100)).saturating_sub(1);
    let p99_us = latencies[p99_index];
    let elapsed_seconds = elapsed.as_secs_f64();
    let rps = requests as f64 / elapsed_seconds;
    println!(
        "{}",
        serde_json::json!({
            "label": label,
            "requests": requests,
            "concurrency": concurrency,
            "connections": connections,
            "warmup": warmup,
            "elapsed_seconds": elapsed_seconds,
            "rps": rps,
            "p99_us": p99_us,
        })
    );

    endpoint.close(quinn::VarInt::from_u32(0), b"benchmark complete");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join_all(driver_tasks)).await;
    Ok(())
}

/// 业务作用：解析严格正整数预算，拒绝 0 请求/0 并发产生除零或无效性能结论。
///
/// 参数说明：`args` 是 argv；`name` 是待解析的预算键。
///
/// 返回：有效 `usize`；缺值、非数字或 0 返回错误。
fn parse_positive(args: &[String], name: &str) -> Result<usize> {
    let value = required_arg(args, name)?
        .parse::<usize>()
        .with_context(|| format!("parse {name}"))?;
    if value == 0 {
        bail!("{name} must be positive");
    }
    Ok(value)
}

/// 业务作用：读取测试 CA 的首张 PEM 证书，确保负载客户端真实校验代理身份而不是使用
/// `danger_accept_invalid_certs` 放宽安全路径。
///
/// 参数说明：`path` 是只读挂载的 CA/服务端自签证书文件。
///
/// 返回：首张 DER 证书；文件为空或解析失败时返回错误。
fn read_first_certificate(path: &Path) -> Result<Vec<u8>> {
    let pem = std::fs::read(path).with_context(|| format!("read CA {}", path.display()))?;
    let certificate = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .context("CA contains no certificate")?
        .context("parse benchmark CA certificate")?;
    Ok(certificate.to_vec())
}

/// 业务作用：创建仅信任本轮证书、ALPN 固定为 `h3` 的客户端 endpoint，保证 Envoy 或
/// Naway 不能降级为 TCP/H2 后仍被基准计为成功。
///
/// 参数说明：`certificate_der` 是本轮代理共同使用的受信身份。
///
/// 返回：绑定随机 UDP 端口且配置好 QUIC TLS 的 endpoint。
fn h3_client_endpoint(certificate_der: Vec<u8>) -> Result<quinn::Endpoint> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der))
        .context("add benchmark CA")?;
    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("build benchmark QUIC TLS")?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid wildcard UDP"))
        .context("bind benchmark client UDP")?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
}

/// 业务作用：以固定 worker 数在指定 QUIC connection 集合上均匀并发多路复用请求，并为每个
/// 完成请求记录端到端延迟；请求分配总数精确，不把失败或少发请求换成更高 RPS。
///
/// 参数说明：`senders` 是全部已握手 H3 sender；`requests`/`concurrency` 是总量和 worker 数；
/// `uri` 是两个代理共用的 HTTPS 请求目标。worker 按序固定到连接，避免调度抖动改变连接分布。
///
/// 返回：每个成功请求的微秒延迟，共恰好 `requests` 项；任一请求失败则整轮失败。
async fn issue_requests(
    senders: &[h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>],
    requests: usize,
    concurrency: usize,
    uri: &str,
) -> Result<Vec<u64>> {
    if senders.is_empty() {
        bail!("benchmark requires at least one HTTP/3 sender");
    }
    let workers = concurrency.min(requests);
    let tasks = (0..workers).map(|worker| {
        let mut sender = senders[worker % senders.len()].clone();
        let worker_requests = requests / workers + usize::from(worker < requests % workers);
        let uri = uri.to_owned();
        async move {
            let mut latencies = Vec::with_capacity(worker_requests);
            for _ in 0..worker_requests {
                let started = Instant::now();
                let request = Request::builder()
                    .method("GET")
                    .uri(uri.as_str())
                    .body(())
                    .context("build benchmark request")?;
                let mut stream = sender
                    .send_request(request)
                    .await
                    .context("send benchmark request headers")?;
                stream.finish().await.context("finish benchmark request")?;
                let response = stream
                    .recv_response()
                    .await
                    .context("receive benchmark response headers")?;
                if response.status() != StatusCode::OK {
                    bail!("benchmark response status {}", response.status());
                }
                while let Some(mut data) = stream
                    .recv_data()
                    .await
                    .context("receive benchmark response DATA")?
                {
                    let remaining = data.remaining();
                    let _ = data.copy_to_bytes(remaining);
                }
                let _ = stream
                    .recv_trailers()
                    .await
                    .context("receive benchmark response trailers")?;
                latencies.push(started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
            }
            Ok::<_, anyhow::Error>(latencies)
        }
    });
    let mut latencies = Vec::with_capacity(requests);
    for result in join_all(tasks).await {
        latencies.extend(result?);
    }
    if latencies.len() != requests {
        bail!(
            "benchmark completed {} requests, expected {requests}",
            latencies.len()
        );
    }
    Ok(latencies)
}
