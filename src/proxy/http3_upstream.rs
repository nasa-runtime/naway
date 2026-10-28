//! HTTP/3 上游连接与流式 body 适配。
//!
//! 本模块只实现 H3 transport/pool；上游选择、重试、健康、鉴权与响应治理仍由 `forward`
//! 的唯一请求管线负责，避免 `protocol: h3` 形成第二套路由语义。

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::{Buf, Bytes};
use http::{Request, Response, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use super::forward::{PhysicalConnectionBudget, PhysicalConnectionSlot};
use crate::observability::metrics::Metrics;
use crate::tls::UpstreamTlsProfile;
use crate::{BoxBody, BoxError};

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3RecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type H3SendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

/// 一个结构化上游身份的 H3 multiplex client。
///
/// connection 槽只在首次请求或 GOAWAY/错误后重建时加锁；稳态请求 clone `SendRequest` 后并行
/// 开 stream，不把 DATA frame 串行到全局 mutex。
pub(super) struct UpstreamH3Client {
    host: Arc<str>,
    port: u16,
    server_name: Arc<str>,
    tls_profile: UpstreamTlsProfile,
    max_response_header_bytes: usize,
    stream_receive_window_bytes: u32,
    connection_receive_window_bytes: u32,
    idle_timeout_ms: u64,
    physical_budget: Arc<PhysicalConnectionBudget>,
    metrics: Arc<Metrics>,
    connection: tokio::sync::Mutex<Option<Arc<UpstreamH3Connection>>>,
}

/// 已建立且可多路复用的上游 H3 connection generation。
struct UpstreamH3Connection {
    sender: H3Sender,
    usable: Arc<AtomicBool>,
}

/// 一代上游 H3 物理 transport 的 driver 寿命。
struct UpstreamH3TransportLifetime {
    /// Endpoint 必须活到 driver 退出，否则 cache 换代可提前关闭仍在 drain 的 UDP connection。
    _endpoint: quinn::Endpoint,
    /// 物理连接预算覆盖握手到 driver 完整退出，不按 request stream 数重复计费。
    _slot: PhysicalConnectionSlot,
    /// transport Drop 与 active gauge 归还的同一 RAII 边界。
    metrics: Arc<Metrics>,
}

impl Drop for UpstreamH3TransportLifetime {
    /// 业务作用：H3 driver 已观察 connection close 并退出后归还上游 H3 active gauge。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；物理预算随同一结构继续由 `_slot` Drop 归还。
    fn drop(&mut self) {
        self.metrics.dec_upstream_http3_connection();
    }
}

impl UpstreamH3Client {
    /// 构建尚未拨号的 H3 client generation。
    ///
    /// 业务作用：在 cache miss/reload 时固化 authority、TLS identity 与 transport 预算；构造过程
    /// 不做 DNS/UDP I/O，首个真实请求才拨号。
    ///
    /// 参数说明：
    /// - `base`：已经验证的 HTTPS 上游实例 URI。
    /// - `tls_profile`：native/custom CA 或 mTLS 客户端身份策略。
    /// - `max_response_header_bytes`：响应头累计字节上限。
    /// - `stream_receive_window_bytes`：单个 QUIC 流接收窗口字节数。
    /// - `connection_receive_window_bytes`：整条 QUIC 连接接收窗口字节数。
    /// - `idle_timeout_ms`：连接空闲超时毫秒数。
    /// - `physical_budget`：按完整上游身份共享的物理连接预算。
    /// - `metrics`：固定上游协议观测指标。
    ///
    /// 返回：成功时返回可共享 client；URI/SNI 无法转换时拒绝候选 cache entry。
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        base: &str,
        tls_profile: UpstreamTlsProfile,
        max_response_header_bytes: usize,
        stream_receive_window_bytes: u32,
        connection_receive_window_bytes: u32,
        idle_timeout_ms: u64,
        physical_budget: Arc<PhysicalConnectionBudget>,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<Self>> {
        let uri: http::Uri = base
            .parse()
            .with_context(|| format!("parse HTTP/3 upstream base `{base}`"))?;
        anyhow::ensure!(
            uri.scheme_str() == Some("https"),
            "HTTP/3 upstream requires an https:// URI"
        );
        let host = uri.host().context("HTTP/3 upstream URI requires host")?;
        let port = uri.port_u16().unwrap_or(443);
        let server_name = tls_profile
            .server_name
            .as_deref()
            .unwrap_or(host)
            .to_string();
        Ok(Arc::new(Self {
            host: Arc::from(host),
            port,
            server_name: Arc::from(server_name),
            tls_profile,
            max_response_header_bytes,
            stream_receive_window_bytes,
            connection_receive_window_bytes,
            idle_timeout_ms,
            physical_budget,
            metrics,
            connection: tokio::sync::Mutex::new(None),
        }))
    }

    /// 发送一条上游 H3 请求并在响应头到达后返回流式 response body。
    ///
    /// 业务作用：在同一 QUIC connection 上并发 multiplex 请求；上传 DATA/trailers 与响应头接收
    /// 并行驱动，TTFB 前不聚合 body。GOAWAY/已关闭 generation 在开 stream 失败后重连一次，且
    /// 此时 body 尚未被消费，不会重放已产生副作用的数据。
    ///
    /// 参数说明：
    /// - `request`：已由唯一 forward 管线完成 URI/header/版本改写。
    ///
    /// 返回：成功时响应 body 继续逐帧读取 H3 DATA/trailers；DNS/TLS/QUIC/H3/上传失败返回错误。
    pub(super) async fn request(
        &self,
        request: Request<BoxBody>,
    ) -> Result<Response<UpstreamH3Body>, BoxError> {
        let (parts, body) = request.into_parts();
        let head = Request::from_parts(parts, ());
        let mut last_error = None;
        let mut selected = None;
        for _ in 0..2 {
            let connection = self.connection().await?;
            let mut sender = connection.sender.clone();
            match sender.send_request(head.clone()).await {
                Ok(stream) => {
                    selected = Some((connection, stream));
                    break;
                }
                Err(error) => {
                    self.metrics.inc_upstream_http3_connection_error();
                    connection.usable.store(false, Ordering::Release);
                    self.invalidate(&connection).await;
                    last_error = Some(error);
                }
            }
        }
        let Some((connection, stream)) = selected else {
            return Err(Box::new(last_error.expect("two H3 open attempts recorded")) as BoxError);
        };
        let (send, mut recv) = stream.split();
        let mut upload = tokio::spawn(upload_request_body(send, body));
        let mut upload_done = false;
        let response = loop {
            if upload_done {
                break recv
                    .recv_response()
                    .await
                    .map_err(|error| Box::new(error) as BoxError)?;
            }
            tokio::select! {
                response = recv.recv_response() => {
                    break response.map_err(|error| Box::new(error) as BoxError)?;
                }
                result = &mut upload => {
                    upload_done = true;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => return Err(Box::new(error) as BoxError),
                    }
                }
            }
        };
        let (mut parts, ()) = response.into_parts();
        parts.version = Version::HTTP_3;
        Ok(Response::from_parts(
            parts,
            UpstreamH3Body {
                _connection: connection,
                recv,
                upload: (!upload_done).then_some(upload),
                data_done: false,
                trailers_done: false,
                failed: false,
            },
        ))
    }

    /// 取得当前可用 connection，必要时由单一 owner 完成 DNS、TLS 与 H3 建连。
    ///
    /// 业务作用：避免冷启动并发请求重复建立 QUIC socket；driver 已观察 GOAWAY/close 时新请求
    /// 建新 generation，旧 response stream 继续持有自身 connection 自然 drain。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：可 clone sender 的 connection；资源预算、DNS、TLS 或 H3 初始化失败时返回错误。
    async fn connection(&self) -> Result<Arc<UpstreamH3Connection>, BoxError> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = current
            .as_ref()
            .filter(|connection| connection.usable.load(Ordering::Acquire))
        {
            return Ok(connection.clone());
        }
        let connection = match self.connect().await {
            Ok(connection) => connection,
            Err(error) => {
                self.metrics.inc_upstream_http3_connection_error();
                return Err(error);
            }
        };
        *current = Some(connection.clone());
        Ok(connection)
    }

    /// 清除仍指向指定失败 generation 的 cache 槽。
    ///
    /// 业务作用：开 stream 观察 GOAWAY/close 后只撤下同一 generation，不能误删并发请求已经
    /// 建好的替代连接。
    ///
    /// 参数说明：
    /// - `failed`：是刚刚开 stream 失败的 connection。
    ///
    /// 返回：无；不匹配时保留较新的 generation。
    async fn invalidate(&self, failed: &Arc<UpstreamH3Connection>) {
        let mut current = self.connection.lock().await;
        if current
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, failed))
        {
            *current = None;
        }
    }

    /// 建立一条带严格物理预算的 QUIC/H3 connection。
    ///
    /// 业务作用：把 DNS、UDP socket、TLS identity、ALPN、receive window、idle 和 H3 control
    /// driver 作为一个原子 generation 构建；任一步失败都由 RAII 归还物理名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：握手与 H3 SETTINGS 初始化完成的 connection；失败不发布半完成 sender。
    async fn connect(&self) -> Result<Arc<UpstreamH3Connection>, BoxError> {
        let target = tokio::net::lookup_host((self.host.as_ref(), self.port))
            .await
            .map_err(|error| Box::new(error) as BoxError)?
            .next()
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "HTTP/3 upstream DNS returned no address",
                )) as BoxError
            })?;
        // DNS 成功后、任何 UDP/handshake 副作用前占位；连接建立失败会随局部 slot Drop 归还。
        let slot = self
            .physical_budget
            .try_acquire()
            .map_err(|error| Box::new(error) as BoxError)?;
        let bind = match target.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let mut endpoint =
            quinn::Endpoint::client(bind).map_err(|error| Box::new(error) as BoxError)?;
        endpoint.set_default_client_config(self.quic_client_config()?);
        let quic = endpoint
            .connect(target, self.server_name.as_ref())
            .map_err(|error| Box::new(error) as BoxError)?
            .await
            .map_err(|error| Box::new(error) as BoxError)?;
        let mut builder = h3::client::builder();
        builder
            .max_field_section_size(
                u64::try_from(self.max_response_header_bytes).unwrap_or(u64::MAX),
            )
            .enable_extended_connect(false)
            .enable_datagram(false);
        let (mut driver, sender) = builder
            .build(h3_quinn::Connection::new(quic))
            .await
            .map_err(|error| Box::new(error) as BoxError)?;
        let usable = Arc::new(AtomicBool::new(true));
        let driver_usable = usable.clone();
        let driver_metrics = self.metrics.clone();
        self.metrics.inc_upstream_http3_connection();
        let lifetime = Arc::new(UpstreamH3TransportLifetime {
            _endpoint: endpoint,
            _slot: slot,
            metrics: self.metrics.clone(),
        });
        tokio::spawn(async move {
            // driver 自身必须持有物理预算；仅从 cache 移除 sender 不代表旧 connection
            // 已 drain，提前归还会让 reload/GOAWAY 期间突破 max_connections_per_upstream。
            let _driver_lifetime = lifetime;
            let error = driver.wait_idle().await;
            // control stream 先标记不可用；既有 request stream 由各自 handle 继续 drain，新请求重连。
            driver_usable.store(false, Ordering::Release);
            driver_metrics.inc_upstream_http3_goaway();
            tracing::debug!(%error, "HTTP/3 upstream connection driver stopped");
        });
        Ok(Arc::new(UpstreamH3Connection {
            sender,
            usable,
        }))
    }

    /// 构建本 generation 的 Quinn client TLS/transport 配置。
    ///
    /// 业务作用：强制 ALPN `h3`、关闭 DATAGRAM，并把响应流/连接 receive window 与 idle 预算
    /// 下沉到 QUIC；TLS profile 的 CA、SNI 与客户端证书语义保持不变。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：可安装到 client endpoint 的配置；TLS/VarInt/idle 转换失败时拒绝拨号。
    fn quic_client_config(&self) -> Result<quinn::ClientConfig, BoxError> {
        let mut tls = (*self.tls_profile.client_config).clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| Box::new(error) as BoxError)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let stream_window = quinn::VarInt::from_u64(u64::from(self.stream_receive_window_bytes))
            .map_err(|error| Box::new(error) as BoxError)?;
        let connection_window =
            quinn::VarInt::from_u64(u64::from(self.connection_receive_window_bytes))
                .map_err(|error| Box::new(error) as BoxError)?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(0))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(8))
            .stream_receive_window(stream_window)
            .receive_window(connection_window)
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0);
        if self.idle_timeout_ms > 0 {
            let idle = quinn::IdleTimeout::try_from(Duration::from_millis(self.idle_timeout_ms))
                .map_err(|error| Box::new(error) as BoxError)?;
            transport.max_idle_timeout(Some(idle));
        } else {
            transport.max_idle_timeout(None);
        }
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}

/// 把统一请求 body 逐帧写入 H3 send half。
///
/// 业务作用：DATA/trailers 保持原顺序与 QUIC 背压；下游取消时 task 被 response body Drop abort，
/// send half 随之释放并让上游观察 request cancellation。
///
/// 参数说明：
/// - `send`：是单 request 独占发送半边
/// - `body`：是过滤器处理后的统一流式 body。
///
/// 返回：FIN 写完时成功；body 或 H3 send 错误会 reset 当前 stream 并返回错误。
async fn upload_request_body(mut send: H3SendStream, mut body: BoxBody) -> Result<(), BoxError> {
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                return Err(error);
            }
        };
        match frame.into_data() {
            Ok(data) => send
                .send_data(data)
                .await
                .map_err(|error| Box::new(error) as BoxError)?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers)
                        .await
                        .map_err(|error| Box::new(error) as BoxError)?;
                }
            }
        }
    }
    send.finish()
        .await
        .map_err(|error| Box::new(error) as BoxError)
}

/// H3 response receive half 与仍在进行的 request upload task。
pub(super) struct UpstreamH3Body {
    /// 保持该 generation sender/可用状态；cache 换版不影响在途 stream 的归属。
    /// 真实 Endpoint/物理预算由独立 H3 driver task 持有到 connection close。
    _connection: Arc<UpstreamH3Connection>,
    recv: H3RecvStream,
    upload: Option<tokio::task::JoinHandle<Result<(), BoxError>>>,
    data_done: bool,
    trailers_done: bool,
    failed: bool,
}

impl UpstreamH3Body {
    /// 终止尚未完成的上游 request upload。
    ///
    /// 业务作用：响应结束、下游取消或读取失败后不允许请求 body task 继续占用 QUIC stream/预算。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；已完成或不存在的 task 不做操作。
    fn abort_upload(&mut self) {
        if let Some(upload) = self.upload.take() {
            upload.abort();
        }
    }
}

impl Drop for UpstreamH3Body {
    /// 业务作用：下游提前放弃响应时立即取消尚在上传的请求 body，防止已取消
    /// 的业务请求继续产生上游副作用或占用 QUIC stream。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；若 upload task 未完成则将其 abort。
    fn drop(&mut self) {
        self.abort_upload();
    }
}

impl Body for UpstreamH3Body {
    type Data = Bytes;
    type Error = BoxError;

    /// 业务作用：按 DATA→trailers 顺序暴露上游 H3 response，并把并发 request upload 错误映射到
    /// 同一 body；任何失败都终止另一方向，避免半完成 stream。
    ///
    /// 参数说明：
    /// - `cx`：是当前下游消费者的唤醒上下文。
    ///
    /// 返回：下一帧、流结束或 transport/upload 错误；Pending 时不预读 QUIC payload。
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        if let Some(upload) = self.upload.as_mut() {
            match Pin::new(upload).poll(cx) {
                Poll::Ready(Ok(Ok(()))) => self.upload = None,
                Poll::Ready(Ok(Err(error))) => {
                    self.failed = true;
                    self.upload = None;
                    self.recv
                        .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Err(error)) => {
                    self.failed = true;
                    self.upload = None;
                    self.recv
                        .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                    return Poll::Ready(Some(Err(Box::new(error) as BoxError)));
                }
                Poll::Pending => {}
            }
        }
        if !self.data_done {
            match self.recv.poll_recv_data(cx) {
                Poll::Ready(Ok(Some(mut data))) => {
                    let remaining = data.remaining();
                    return Poll::Ready(Some(Ok(Frame::data(data.copy_to_bytes(remaining)))));
                }
                Poll::Ready(Ok(None)) => self.data_done = true,
                Poll::Ready(Err(error)) => {
                    self.failed = true;
                    self.abort_upload();
                    return Poll::Ready(Some(Err(Box::new(error) as BoxError)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.trailers_done {
            match self.recv.poll_recv_trailers(cx) {
                Poll::Ready(Ok(Some(trailers))) => {
                    self.trailers_done = true;
                    self.abort_upload();
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                Poll::Ready(Ok(None)) => self.trailers_done = true,
                Poll::Ready(Err(error)) => {
                    self.failed = true;
                    self.abort_upload();
                    return Poll::Ready(Some(Err(Box::new(error) as BoxError)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.abort_upload();
        Poll::Ready(None)
    }

    /// 业务作用：只在 DATA/trailers 都消费完后向下游报告 EOF，防止 trailers 被截断。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整结束或失败后为 true，否则 false。
    fn is_end_stream(&self) -> bool {
        self.failed || self.trailers_done
    }

    /// 业务作用：H3 response 未知长度时保持未知，禁止 adapter 为流式响应臆测并聚合。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认未知长度提示；Content-Length 继续由响应 header 表达。
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
