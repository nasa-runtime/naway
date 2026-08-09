//! HTTP/3/QUIC 下游协议适配层。
//!
//! 本模块只负责 QUIC/H3 frame 与网关统一 `BoxBody` 之间的流式桥接；路由、鉴权、限流、
//! gRPC 与上游选择仍全部进入 [`GatewayProxy`]，避免产生第二套治理实现。

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::{Buf, Bytes};
use h3::error::Code;
use http::header::HOST;
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::config::{Http3RuntimeCfg, TlsRuntimeCfg};
use crate::metrics::Metrics;
use crate::proxy::GatewayProxy;
use crate::proxy_protocol::ConnInfo;
use crate::tls::build_server_config;
use crate::{BoxBody, BoxError};

/// HTTP/3 禁止转发到 wire 的 hop-by-hop header；后两个没有 `http::header` 常量。
const H3_FORBIDDEN_HEADERS: [&str; 5] = [
    "connection",
    "transfer-encoding",
    "upgrade",
    "keep-alive",
    "proxy-connection",
];

/// 单个 H3 request stream 的观测 RAII 边界。
struct Http3StreamMetrics {
    metrics: Arc<Metrics>,
    success: bool,
}

impl Http3StreamMetrics {
    /// 业务作用：在创建 request task 前增加活跃 H3 stream gauge。
    ///
    /// 参数说明：`metrics` 是进程级低基数指标集。
    ///
    /// 返回：默认失败的 guard；只有响应 FIN 完整写出才可标记成功。
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.inc_http3_stream();
        Self {
            metrics,
            success: false,
        }
    }

    /// 业务作用：标记当前 H3 response 已完整写出，供 Drop 记录成功结果。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无。
    fn complete(&mut self) {
        self.success = true;
    }
}

impl Drop for Http3StreamMetrics {
    /// 业务作用：在成功、协议错误、取消或 task panic 的统一边界归还 stream gauge。
    ///
    /// 参数说明：无。
    ///
    /// 返回：无；同时累加固定 success/error 结果。
    fn drop(&mut self) {
        self.metrics.finish_http3_stream(self.success);
    }
}

/// 构造绑定到既有 TLS 端口 UDP socket 的 QUIC server endpoint。
///
/// 业务作用：复用已校验 TLS 身份并强制 ALPN `h3`，同时把 stream 数、idle timeout 和接收
/// window 固化为 transport 硬门；任一配置转换失败时拒绝整个 listener prepare。
///
/// 参数说明：`tls` 提供证书/私钥与 mTLS 身份；`http3` 提供已校验资源预算；`socket` 是
/// supervisor prepare 阶段预绑定、已设为 nonblocking 的 UDP socket。
///
/// 返回：成功时返回尚未启动 accept loop 的 endpoint；失败时不发布半完成 HTTP/3 listener。
pub fn build_server_endpoint(
    tls: &TlsRuntimeCfg,
    http3: &Http3RuntimeCfg,
    socket: UdpSocket,
) -> Result<PreparedServerEndpoint> {
    let tls_config = build_server_config(tls)?;
    let server_config = build_quic_server_config(tls_config, http3)?;

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        // prepare 阶段只绑定并启动 UDP driver，不安装 server identity；即使旧/new SO_REUSEPORT
        // socket 暂时并存，候选也会拒绝 Initial，直到 topology commit 显式 activate。
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("create prepared HTTP/3 QUIC endpoint")?;
    Ok(PreparedServerEndpoint {
        endpoint,
        server_config,
    })
}

/// prepare 阶段已绑定但尚未接受 QUIC Initial 的 endpoint。
///
/// 业务作用：把可能失败的 socket/runtime/TLS 构造提前完成，同时在 reload publish 前保持
/// server config 为空，防止 SO_REUSEPORT 候选抢走旧 generation 流量。
pub struct PreparedServerEndpoint {
    endpoint: quinn::Endpoint,
    server_config: quinn::ServerConfig,
}

impl PreparedServerEndpoint {
    /// 在 topology commit 点开放新 QUIC handshake。
    ///
    /// 业务作用：把 server identity 发布与 listener generation 切换对齐；调用前候选只占端口但
    /// 不响应业务 Initial，调用后 endpoint 才进入 accept loop。
    ///
    /// 参数说明：无。
    ///
    /// 返回：已安装同版 TLS/transport 配置的 Quinn endpoint。
    pub fn activate(self) -> quinn::Endpoint {
        self.endpoint.set_server_config(Some(self.server_config));
        self.endpoint
    }
}

/// 把一份已完整校验的 rustls 身份转换为 QUIC server 配置。
///
/// 业务作用：启动绑定与证书热换共用同一个 ALPN/transport 预算构造器，避免轮换后意外恢复
/// h1/h2 ALPN、DATAGRAM 或无界 receive window。
///
/// 参数说明：`tls_config` 是通用 TLS loader 的完整结果；`http3` 是同 generation 资源计划。
///
/// 返回：成功时返回可交给 Quinn 新握手使用的配置；转换失败时调用方必须保留旧配置。
fn build_quic_server_config(
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    http3: &Http3RuntimeCfg,
) -> Result<quinn::ServerConfig> {
    let mut tls_config = (*tls_config).clone();
    // QUIC TLS 不能与 TCP 的 h1/h2 ALPN 混用；只发布 h3，避免协商出 transport 无法承载的协议。
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .context("convert rustls config into QUIC TLS config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let idle_timeout =
        quinn::IdleTimeout::try_from(Duration::from_millis(http3.max_idle_timeout_ms))
            .context("convert HTTP/3 max_idle_timeout_ms into QUIC idle timeout")?;
    let bidi_streams = quinn::VarInt::from_u64(u64::from(http3.max_bidi_streams_per_connection))
        .context("convert HTTP/3 bidi stream budget into QUIC VarInt")?;
    let stream_window = quinn::VarInt::from_u64(
        u64::try_from(http3.max_stream_buffer_bytes)
            .context("HTTP/3 stream buffer budget exceeds u64")?,
    )
    .context("convert HTTP/3 stream buffer budget into QUIC VarInt")?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidi_streams)
        // H3 必须保留 control/QPACK 单向流；设为固定小上限，拒绝 WebTransport/MASQUE 扩张。
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(8))
        .stream_receive_window(stream_window)
        // aggregate receive window 不得大于单 stream 配置预算，避免并发 stream 把内存上限相乘。
        .receive_window(stream_window)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0);
    let pending_total = u64::try_from(http3.max_pending_handshakes)
        .context("HTTP/3 pending handshake count exceeds u64")?
        .checked_mul(http3.max_pending_handshake_bytes)
        .context("HTTP/3 pending handshake memory budget overflow")?;
    let mut validation_tokens = quinn::ValidationTokenConfig::default();
    // 0-RTT 首版关闭时不发跨连接 NEW_TOKEN；否则长寿命 validation token 会绕过 `retry=always`
    // 的逐次来源验证，并把密钥轮换语义扩大到两周缓存。
    validation_tokens.sent(0);
    server_config
        .transport_config(Arc::new(transport))
        .max_incoming(http3.max_pending_handshakes)
        .incoming_buffer_size(http3.max_pending_handshake_bytes)
        .incoming_buffer_size_total(pending_total)
        .validation_token_config(validation_tokens)
        .retry_token_lifetime(Duration::from_secs(http3.retry_token_lifetime_seconds))
        .migration(true);
    Ok(server_config)
}

/// 启动 HTTP/3 证书材料 watcher，新配置只作用于后续 QUIC handshake。
///
/// 业务作用：证书/私钥/SNI/mTLS CA 或 manifest 原子切换后更新 endpoint server config，并按
/// 固定周期生成新的 Retry token 主密钥；构建或 QUIC 转换失败时保留旧身份，已建立 connection
/// 永不因轮换被中断。
///
/// 参数说明：`tls` 是材料来源；`http3` 固化 transport 预算；`shutdown` 绑定 watcher 与当前
/// listener generation 生命周期。
///
/// 返回：配置更新 receiver；accept loop 必须串行应用它，sender 随 generation 停止而释放。
pub fn spawn_cert_watcher(
    tls: TlsRuntimeCfg,
    http3: Http3RuntimeCfg,
    shutdown: watch::Receiver<bool>,
) -> watch::Receiver<Option<quinn::ServerConfig>> {
    let (updates, receiver) = watch::channel(None);
    let material = Arc::new(Mutex::new(build_server_config(&tls).ok()));
    let cert_material = material.clone();
    let cert_updates = updates.clone();
    let cert_http3 = http3.clone();
    crate::tls::spawn_cert_material_watcher_until(
        tls,
        move |tls_config| {
            let mut current = cert_material.lock();
            let server_config = build_quic_server_config(tls_config.clone(), &cert_http3)?;
            *current = Some(tls_config);
            // callback 不持有 Endpoint；accept loop 串行应用更新，停机后 sender 释放，不可能把
            // 已经 set_server_config(None) 的旧 generation 重新打开。
            cert_updates.send_replace(Some(server_config));
            Ok(())
        },
        shutdown.clone(),
    );
    tokio::spawn(async move {
        let period = Duration::from_secs(http3.retry_token_rotation_seconds);
        let mut rotation = tokio::time::interval(period);
        rotation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `interval` 首次 tick 立即就绪；初始 endpoint 已有随机密钥，不需要 commit 后立刻再换一次。
        rotation.tick().await;
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = rotation.tick() => {
                    let current = material.lock();
                    let Some(tls_config) = current.as_ref() else {
                        continue;
                    };
                    match build_quic_server_config(tls_config.clone(), &http3) {
                        Ok(server_config) => {
                            // 新 key 只服务后续 Initial；轮换瞬间携带旧 token 的客户端会被当作
                            // 未验证来源重新 Retry，不会降级成无认证放行。
                            updates.send_replace(Some(server_config));
                            tracing::info!("HTTP/3 Retry token key rotated");
                        }
                        Err(error) => tracing::warn!(
                            error = %format!("{error:#}"),
                            "HTTP/3 Retry token key rotation failed; keeping previous config"
                        ),
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    });
    receiver
}

/// 驱动一条已完成 QUIC 握手的 HTTP/3 连接。
///
/// 业务作用：逐 stream 接收请求并派生有界 task；每个请求都复用 [`GatewayProxy`] 的单快照
/// 治理管线，连接迁移期间继续使用握手时固化的可信 peer，避免身份随 path rebinding 漂移。
///
/// 参数说明：`connection` 是 Quinn 连接；`proxy` 是共享网关执行器；`proxy_id` 标识逻辑
/// listener；`initial_peer` 是握手接受时的地址；`max_header_bytes` 是 H3/QPACK header 硬门；
/// `metrics` 记录固定协议结果；`shutdown` 在 listener 换代或进程停机时触发 GOAWAY。
///
/// 返回：连接正常关闭时成功；H3 control stream 或连接级协议错误时返回错误供 accept task 记录。
pub async fn serve_connection(
    connection: quinn::Connection,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    initial_peer: SocketAddr,
    max_header_bytes: usize,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let quic_connection = connection.clone();
    let mut builder = h3::server::builder();
    builder
        .max_field_section_size(u64::try_from(max_header_bytes).unwrap_or(u64::MAX))
        .enable_extended_connect(false)
        .enable_datagram(false)
        .enable_webtransport(false)
        .max_webtransport_sessions(0);
    let mut connection = builder
        .build(h3_quinn::Connection::new(connection))
        .await
        .context("initialize HTTP/3 connection")?;

    let mut draining = false;
    let mut migration_observed = false;
    loop {
        let accepted = if draining {
            connection.accept().await
        } else {
            tokio::select! {
                accepted = connection.accept() => accepted,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        // 先发送 GOAWAY，随后继续 poll accept 直到已接收 stream 全部释放；直接
                        // drop connection 会把可安全完成的 gRPC/上传流错误重置。
                        connection
                            .shutdown(0)
                            .await
                            .context("send HTTP/3 GOAWAY")?;
                        draining = true;
                    }
                    continue;
                }
            }
        };
        let Some(resolver) = accepted.context("accept HTTP/3 request")? else {
            return Ok(());
        };
        if !migration_observed && quic_connection.remote_address() != initial_peer {
            // 业务安全身份仍使用 initial_peer；迁移只做低基数观测，不更写 ACL/rate key。
            migration_observed = true;
            metrics.inc_quic_migration();
        }
        let proxy = proxy.clone();
        let proxy_id = proxy_id.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut stream_metrics = Http3StreamMetrics::new(metrics);
            match serve_request(resolver, proxy, proxy_id, initial_peer).await {
                Ok(()) => stream_metrics.complete(),
                Err(error) => {
                    tracing::debug!(peer = %initial_peer, %error, "HTTP/3 request stream closed with error");
                }
            }
        });
    }
}

/// 解析并代理单个 HTTP/3 request stream。
///
/// 业务作用：把 H3 HEADERS/DATA/trailers 无聚合转换成统一请求，再把治理管线响应按原顺序写回
/// H3 stream；取消或 frame 错误会终止双向 stream，不能留下半完成响应。
///
/// 参数说明：`resolver` 持有尚未解析的 H3 请求；`proxy`/`proxy_id` 指向统一数据面；
/// `initial_peer` 是连接握手期固化的客户端地址。
///
/// 返回：完整写完 response HEADERS/body/trailers 后成功；请求解析、治理 body 或发送失败时返回错误。
async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    initial_peer: SocketAddr,
) -> Result<()> {
    let (mut request, stream) = resolver
        .resolve_request()
        .await
        .context("resolve HTTP/3 request headers")?;
    request.extensions_mut().insert(initial_peer);
    *request.version_mut() = Version::HTTP_3;
    // 既有虚拟主机路由以 Host 为统一输入；H3 authority 是等价权威字段，只在 Host 缺失时映射。
    if !request.headers().contains_key(HOST) {
        if let Some(authority) = request.uri().authority() {
            let host = http::HeaderValue::from_str(authority.as_str())
                .context("convert HTTP/3 authority into Host header")?;
            request.headers_mut().insert(HOST, host);
        }
    }
    let request_method = request.method().clone();
    let (send, recv) = stream.split();
    let (parts, ()) = request.into_parts();
    let request = Request::from_parts(parts, H3RequestBody::new(recv).boxed());
    let response = match proxy
        .handle_boxed(request, ConnInfo::plain(initial_peer), "https", proxy_id)
        .await
    {
        Ok(response) => response,
        Err(never) => match never {},
    };
    send_response(send, response, &request_method).await
}

/// 把统一网关响应流写回一个 HTTP/3 request stream。
///
/// 业务作用：保持 DATA/trailers 的顺序与背压，并在任何 body/send 失败时同时终止发送和接收方向，
/// 避免上游继续生产客户端已无法消费的数据。
///
/// 参数说明：`stream` 是该请求独占的 H3 send half；`response` 是统一管线生成的流式响应；
/// `request_method` 用于落实 HEAD/无 body 状态语义。
///
/// 返回：成功表示 FIN 已写出；失败表示 stream 已用 `H3_INTERNAL_ERROR` 终止。
async fn send_response(
    mut stream: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    response: Response<BoxBody>,
    request_method: &Method,
) -> Result<()> {
    let (mut parts, mut body) = response.into_parts();
    parts.version = Version::HTTP_3;
    strip_forbidden_headers(&mut parts.headers);
    let status = parts.status;
    stream
        .send_response(Response::from_parts(parts, ()))
        .await
        .context("send HTTP/3 response headers")?;

    if !http_response_allows_body(request_method, status) {
        // HEAD、1xx、204、304 的 payload 在 HTTP 语义上不存在；不 poll 上游 body，Drop 会把
        // 无效生产及时取消，防止 H3 adapter 绕过 Hyper h1/h2 driver 原有的抑制逻辑。
        return stream
            .finish()
            .await
            .context("finish bodyless HTTP/3 response");
    }

    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                stream.stop_stream(Code::H3_INTERNAL_ERROR);
                anyhow::bail!("read gateway response body: {error}");
            }
        };
        match frame.into_data() {
            Ok(data) => stream
                .send_data(data)
                .await
                .context("send HTTP/3 response DATA")?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    stream
                        .send_trailers(trailers)
                        .await
                        .context("send HTTP/3 response trailers")?;
                }
            }
        }
    }
    stream.finish().await.context("finish HTTP/3 response")
}

/// 判断最终 HTTP/3 响应是否允许发送 DATA/trailers。
///
/// 业务作用：在自有 H3 wire adapter 中复刻 HTTP 通用无 body 规则，防止 HEAD/204/304 把上游
/// payload 错发给客户端并破坏 stream 边界。
///
/// 参数说明：`request_method` 是原请求方法；`status` 是最终响应状态。
///
/// 返回：true 表示可继续发送 body frame，false 表示 HEADERS 后应直接 FIN。
fn http_response_allows_body(request_method: &Method, status: StatusCode) -> bool {
    request_method != Method::HEAD
        && !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
}

/// 移除 RFC 9114 禁止出现在 HTTP/3 消息中的连接级 header。
///
/// 业务作用：防止 h1 上游返回的 hop-by-hop 元数据穿透到 H3 wire 形成协议错误或错误连接语义。
///
/// 参数说明：`headers` 是即将编码成 QPACK field section 的响应 header 集。
///
/// 返回：无返回值；原地删除固定禁用集合，其余 end-to-end header 保持不变。
fn strip_forbidden_headers(headers: &mut HeaderMap) {
    for name in H3_FORBIDDEN_HEADERS {
        headers.remove(name);
    }
}

/// 把 H3 receive half 暴露为 `http_body::Body`，不预读也不聚合请求 payload。
struct H3RequestBody {
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    data_done: bool,
    trailers_done: bool,
}

impl H3RequestBody {
    /// 创建一个按 DATA→trailers 顺序消费的 H3 请求体。
    ///
    /// 业务作用：把 request stream 的唯一所有权绑定到 Body 生命周期；下游取消时 Drop 会停止
    /// 继续读取，从而把背压和取消传播给 QUIC。
    ///
    /// 参数说明：`stream` 是单个 H3 请求独占的 receive half。
    ///
    /// 返回：尚未读取任何 frame 的流式 Body。
    fn new(stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>) -> Self {
        Self {
            stream,
            data_done: false,
            trailers_done: false,
        }
    }
}

impl Body for H3RequestBody {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按 H3 DATA→trailers 顺序逐帧推进请求体，并把协议错误交给统一代理管线。
    ///
    /// 参数说明：`cx` 是当前请求 task 的唤醒上下文。
    ///
    /// 返回：下一帧、流结束或协议错误；Pending 时不预读后续 QUIC 数据。
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if !self.data_done {
            match self.stream.poll_recv_data(cx) {
                Poll::Ready(Ok(Some(mut data))) => {
                    // h3 API 隐藏具体 Buf 类型；h3-quinn 实际返回 Bytes，copy_to_bytes 因而只做
                    // 引用计数切片，不复制 payload，同时把适配层输出稳定为统一 Bytes 类型。
                    let remaining = data.remaining();
                    return Poll::Ready(Some(Ok(Frame::data(data.copy_to_bytes(remaining)))));
                }
                Poll::Ready(Ok(None)) => self.data_done = true,
                Poll::Ready(Err(error)) => {
                    self.data_done = true;
                    self.trailers_done = true;
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.trailers_done {
            match self.stream.poll_recv_trailers(cx) {
                Poll::Ready(Ok(Some(trailers))) => {
                    self.trailers_done = true;
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                Poll::Ready(Ok(None)) => self.trailers_done = true,
                Poll::Ready(Err(error)) => {
                    self.trailers_done = true;
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(None)
    }

    /// 业务作用：向上游准确暴露 H3 请求体是否已消费完 trailers，避免提前结束流。
    ///
    /// 参数说明：无。
    ///
    /// 返回：只有 DATA 与 trailers 阶段均结束时为 true。
    fn is_end_stream(&self) -> bool {
        self.trailers_done
    }

    /// 业务作用：H3 未声明 Content-Length 时保持未知长度，禁止适配层臆测并触发错误聚合。
    ///
    /// 参数说明：无。
    ///
    /// 返回：默认未知长度提示；显式 Content-Length 仍由请求 header 进入既有校验。
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[path = "../../tests/unit/http3.rs"]
#[cfg(test)]
mod tests;
