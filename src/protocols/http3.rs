//! HTTP/3/QUIC 下游协议适配层。
//!
//! 本模块只负责 QUIC/H3 frame 与网关统一 `BoxBody` 之间的流式桥接；路由、鉴权、限流、
//! gRPC 与上游选择仍全部进入 [`GatewayProxy`]，避免产生第二套治理实现。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::error::Code;
use http::header::HOST;
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::config::{Http3RuntimeCfg, TlsRuntimeCfg};
use crate::observability::metrics::Metrics;
use crate::protocols::proxy_protocol::ConnInfo;
use crate::proxy::GatewayProxy;
use crate::tls::build_server_config;
use crate::{full_body, BoxBody, BoxError};

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
    /// 参数说明：
    /// - `metrics`：是进程级低基数指标集。
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
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn complete(&mut self) {
        self.success = true;
    }
}

impl Drop for Http3StreamMetrics {
    /// 业务作用：在成功、协议错误、取消或 task panic 的统一边界归还 stream gauge。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；同时累加固定 success/error 结果。
    fn drop(&mut self) {
        self.metrics.finish_http3_stream(self.success);
    }
}

/// 单个 WebTransport session 的观测 RAII 边界。
struct WebTransportSessionMetrics {
    metrics: Arc<Metrics>,
    success: bool,
}

impl WebTransportSessionMetrics {
    /// 业务作用：在上下游 session 都已建立后登记活跃会话，避免把认证或连接失败算成业务会话。
    ///
    /// 参数说明：
    /// - `metrics`：是进程级低基数指标集。
    ///
    /// 返回：默认错误终态的 guard；完整收口后由调用方标记成功。
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.inc_webtransport_session();
        Self {
            metrics,
            success: false,
        }
    }

    /// 业务作用：标记 WebTransport session 已按协议关闭、超时、撤权或停机路径完整收口。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；Drop 时记录固定成功终态。
    fn complete(&mut self) {
        self.success = true;
    }
}

impl Drop for WebTransportSessionMetrics {
    /// 业务作用：在所有 WebTransport 终态归还活跃 gauge 并登记成功或错误结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无。
    fn drop(&mut self) {
        self.metrics.finish_webtransport_session(self.success);
    }
}

/// 构造绑定到既有 TLS 端口 UDP socket 的 QUIC server endpoint。
///
/// 业务作用：复用已校验 TLS 身份并强制 ALPN `h3`，同时把 stream 数、idle timeout 和接收
/// window 固化为 transport 硬门；任一配置转换失败时拒绝整个 listener prepare。
///
/// 参数说明：
/// - `tls`：提供证书/私钥与 mTLS 身份
/// - `http3`：提供已校验资源预算
/// - `socket`：是 supervisor prepare 阶段预绑定、已设为 nonblocking 的 UDP socket。
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
    /// 参数说明: 无。
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
/// 参数说明：
/// - `tls_config`：是通用 TLS loader 的完整结果
/// - `http3`：是同 generation 资源计划。
///
/// 返回：成功时返回可交给 Quinn 新握手使用的配置；转换失败时调用方必须保留旧配置。
fn build_quic_server_config(
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    http3: &Http3RuntimeCfg,
) -> Result<quinn::ServerConfig> {
    let mut tls_config = (*tls_config).clone();
    // QUIC TLS 不能与 TCP 的 h1/h2 ALPN 混用；只发布 h3，避免协商出 transport 无法承载的协议。
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC 只能用最大 early-data 尺寸表示“由 transport 自身控制流量”；route 门禁还会在
    // 任何认证、插件或上游副作用前复验方法、凭据、实体与一次性 nonce。
    tls_config.max_early_data_size = if http3.zero_rtt {
        u32::MAX
    } else {
        0
    };
    // 服务端响应必须等到握手确认后才可交付；即使客户端 early data 最终被拒绝，也不能让
    // 未认证握手收到半程响应并形成协议状态分叉。
    tls_config.send_half_rtt_data = false;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .context("convert rustls config into QUIC TLS config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let idle_timeout =
        quinn::IdleTimeout::try_from(Duration::from_millis(http3.max_idle_timeout_ms))
            .context("convert HTTP/3 max_idle_timeout_ms into QUIC idle timeout")?;
    let bidi_streams = quinn::VarInt::from_u64(u64::from(http3.max_bidi_streams_per_connection))
        .context("convert HTTP/3 bidi stream budget into QUIC VarInt")?;
    let uni_streams = quinn::VarInt::from_u64(u64::from(http3.max_uni_streams_per_connection))
        .context("convert HTTP/3 uni stream budget into QUIC VarInt")?;
    let stream_window = quinn::VarInt::from_u64(
        u64::try_from(http3.max_stream_buffer_bytes)
            .context("HTTP/3 stream buffer budget exceeds u64")?,
    )
    .context("convert HTTP/3 stream buffer budget into QUIC VarInt")?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidi_streams)
        // H3 至少消费 control/QPACK 单向流；剩余名额是 WebTransport 的
        // 真实传输上限，不能用一个固定小常量让 route 声明的预算永久无法到达。
        .max_concurrent_uni_streams(uni_streams)
        .stream_receive_window(stream_window)
        // aggregate receive window 不得大于单 stream 配置预算，避免并发 stream 把内存上限相乘。
        .receive_window(stream_window);
    if http3.datagram {
        let datagram_buffer = http3
            .max_datagram_queue
            .saturating_mul(http3.max_datagram_bytes)
            .min(16 * 1024 * 1024);
        // Quinn 的内部 DATAGRAM 缓冲与应用层每 session 队列各自有界；前者吸收 driver 调度抖动，
        // 后者在 session 归属已知后执行精确丢弃，任一层都不能按连接数无界放大。
        transport
            .datagram_receive_buffer_size(Some(datagram_buffer))
            .datagram_send_buffer_size(datagram_buffer);
    } else {
        transport
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0);
    }
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
/// 参数说明：
/// - `tls`：是材料来源
/// - `http3`：固化 transport 预算
/// - `shutdown`：绑定 watcher 与当前 listener generation 生命周期。
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
    let session_tls = tls.clone();
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
        let session_period = Duration::from_secs(http3.early_data_session_rotation_seconds);
        let mut session_rotation = tokio::time::interval(session_period);
        session_rotation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `interval` 首次 tick 立即就绪；初始 endpoint 已有随机密钥，不需要 commit 后立刻再换一次。
        rotation.tick().await;
        session_rotation.tick().await;
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
                _ = session_rotation.tick(), if http3.zero_rtt => {
                    // 有状态 session id 是一次性凭据，但未使用项仍可能在客户端保存；周期性发布
                    // 新 storage 代会统一撤销旧项，并保持已建立 connection 完全不受影响。
                    match build_server_config(&session_tls).and_then(|tls_config| {
                        let server_config = build_quic_server_config(tls_config.clone(), &http3)?;
                        Ok((tls_config, server_config))
                    }) {
                        Ok((tls_config, server_config)) => {
                            *material.lock() = Some(tls_config);
                            updates.send_replace(Some(server_config));
                            tracing::info!("HTTP/3 early-data session generation rotated");
                        }
                        Err(error) => tracing::warn!(
                            error = %format!("{error:#}"),
                            "HTTP/3 early-data session rotation failed; keeping previous config"
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
/// 参数说明：
/// - `connection`：已经接纳的 Quinn 连接。
/// - `proxy`：统一网关执行器。
/// - `proxy_id`：逻辑 listener 标识。
/// - `initial_peer`：握手时冻结的客户端地址。
/// - `http3`：H3 与 QPACK 资源上限等入口策略。
/// - `metrics`：固定协议结果指标。
/// - `shutdown`：入口换代或停机时触发 GOAWAY 的信号。
///
/// 返回：连接正常关闭时成功；H3 control stream 或连接级协议错误时返回错误供 accept task 记录。
pub async fn serve_connection(
    connection: quinn::Connection,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    initial_peer: SocketAddr,
    http3: Http3RuntimeCfg,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let quic_connection = connection.clone();
    let mut builder = h3::server::builder();
    builder
        .max_field_section_size(u64::try_from(http3.max_request_header_bytes).unwrap_or(u64::MAX))
        .enable_extended_connect(http3.connect_udp || http3.webtransport)
        .enable_datagram(http3.datagram)
        .enable_webtransport(http3.webtransport)
        .max_webtransport_sessions(u64::from(http3.webtransport));
    let (tracked_connection, early_streams) =
        crate::protocols::h3_quinn_tracked::Connection::new(connection);
    let mut connection = builder
        .build(tracked_connection)
        .await
        .context("initialize HTTP/3 connection")?;

    let extensions = Arc::new(QuicExtensionContext::new(
        quic_connection.clone(),
        &http3,
        metrics.clone(),
    ));
    if http3.datagram {
        let dispatcher = extensions.dispatcher.clone();
        let datagram_connection = quic_connection.clone();
        tokio::spawn(async move {
            receive_h3_datagrams(datagram_connection, dispatcher).await;
        });
    }

    let mut draining = false;
    let mut migration_observed = false;
    let mut resolvers = JoinSet::new();
    loop {
        let resolved = tokio::select! {
            accepted = connection.accept() => {
                let accepted = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if error.is_h3_no_error() => return Ok(()),
                    Err(error) => return Err(error).context("accept HTTP/3 request"),
                };
                let Some(resolver) = accepted else {
                    return Ok(());
                };
                // RequestResolver 拥有独立 stream 与共享 QPACK 状态；并发解析避免一个被阻塞的
                // field section 阻止同连接其它 stream 进入。任务总量仍受 QUIC bidi 硬门限制。
                resolvers.spawn(async move {
                    resolver.resolve_request().await
                });
                continue;
            }
            resolved = resolvers.join_next(), if !resolvers.is_empty() => {
                let resolved = resolved.expect("non-empty resolver set yields a task");
                resolved.context("HTTP/3 request resolver task failed")?
            }
            changed = shutdown.changed(), if !draining => {
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
        };
        let (mut request, stream) = match resolved {
            Ok(resolved) => resolved,
            Err(h3::error::StreamError::ConnectionError(error)) if error.is_h3_no_error() => {
                return Ok(());
            }
            Err(h3::error::StreamError::ConnectionError(error)) => {
                return Err(error).context("resolve HTTP/3 request headers");
            }
            Err(error) => {
                // HeaderTooBig、RESET 与单 request frame 错误只终止对应 stream；升级为
                // connection close 会让一个坏请求驱逐同连接其它无关请求。
                tracing::debug!(%initial_peer, %error, "HTTP/3 request stream rejected during header resolution");
                continue;
            }
        };
        // 0-RTT 身份必须取自 Quinn stream 属性，不能信任客户端能够自行添加的 `Early-Data`
        // header。证据按 stream id 一次性消费，避免后续内部请求复用同一放行事实。
        if early_streams.take(stream.id()) {
            request
                .extensions_mut()
                .insert(crate::protocols::masque::EarlyDataRequest);
        }
        prepare_h3_request(&mut request, initial_peer)?;
        let protocol = request.extensions().get::<h3::ext::Protocol>().copied();
        if !migration_observed && quic_connection.remote_address() != initial_peer {
            // 业务安全身份仍使用 initial_peer；迁移只做低基数观测，不更写 ACL/rate key。
            migration_observed = true;
            metrics.inc_quic_migration();
        }
        if protocol == Some(h3::ext::Protocol::WEB_TRANSPORT) {
            let mut stream_metrics = Http3StreamMetrics::new(metrics.clone());
            let result = serve_webtransport(
                request,
                stream,
                proxy,
                proxy_id,
                WebTransportConnection {
                    connection,
                    initial_peer,
                    extensions,
                    shutdown,
                },
            )
            .await;
            if result.is_ok() {
                stream_metrics.complete();
            }
            return result;
        }
        let proxy = proxy.clone();
        let proxy_id = proxy_id.clone();
        let metrics = metrics.clone();
        let extensions = extensions.clone();
        let request_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut stream_metrics = Http3StreamMetrics::new(metrics);
            match serve_resolved_request(
                request,
                stream,
                proxy,
                proxy_id,
                initial_peer,
                extensions,
                request_shutdown,
            )
            .await
            {
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
/// 参数说明：
/// - `request`：已经解析的 H3 请求头。
/// - `stream`：该请求对应的 H3 双向流。
/// - `proxy`：统一网关执行器。
/// - `proxy_id`：逻辑 listener 标识。
/// - `initial_peer`：连接握手时冻结的客户端地址。
/// - `extensions`：支持 DATAGRAM 等能力的连接扩展。
/// - `shutdown`：入口换代或停机的撤销信号。
///
/// 返回：完整写完 response HEADERS/body/trailers 后成功；请求解析、治理 body 或发送失败时返回错误。
async fn serve_resolved_request(
    mut request: Request<()>,
    mut stream: h3::server::RequestStream<
        crate::protocols::h3_quinn_tracked::BidiStream<Bytes>,
        Bytes,
    >,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    initial_peer: SocketAddr,
    extensions: Arc<QuicExtensionContext>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let protocol = request.extensions().get::<h3::ext::Protocol>().copied();
    if protocol == Some(h3::ext::Protocol::CONNECT_UDP) {
        return serve_connect_udp(
            request,
            stream,
            proxy,
            proxy_id,
            initial_peer,
            extensions,
            shutdown,
        )
        .await;
    }
    if request
        .extensions()
        .get::<crate::protocols::masque::EarlyDataRequest>()
        .is_some()
    {
        // early route 的安全合同是空实体。必须在进入统一管线前读到 FIN，客户端即使省略
        // Content-Length，也不能让 DATA 或 trailers 在网关已经执行上游后才被发现。
        let has_entity = match stream
            .recv_data()
            .await
            .context("inspect early HTTP/3 request body")?
        {
            Some(_) => true,
            None => stream
                .recv_trailers()
                .await
                .context("inspect early HTTP/3 request trailers")?
                .is_some(),
        };
        if has_entity {
            request
                .extensions_mut()
                .insert(crate::protocols::masque::EarlyDataRequestBody);
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

/// 业务作用：把 H3 authority 与可信连接身份一次性映射到统一路由输入。
///
/// 参数说明：
/// - `request`：是已解码的 H3 HEADERS
/// - `initial_peer`：是握手完成时冻结的对端地址。
///
/// 返回：Host 可安全构造时成功；非法 authority 返回错误并阻止请求进入治理管线。
fn prepare_h3_request(request: &mut Request<()>, initial_peer: SocketAddr) -> Result<()> {
    request.extensions_mut().insert(initial_peer);
    *request.version_mut() = Version::HTTP_3;
    // 虚拟主机路由统一读取 Host；只在缺失时从等价 authority 映射，不能覆盖已解码字段。
    if !request.headers().contains_key(HOST) {
        if let Some(authority) = request.uri().authority() {
            let host = http::HeaderValue::from_str(authority.as_str())
                .context("convert HTTP/3 authority into Host header")?;
            request.headers_mut().insert(HOST, host);
        }
    }
    Ok(())
}

/// 保持上游 WebTransport UDP endpoint 与 session 同寿命。
///
/// 业务作用：Quinn connection 依赖 endpoint 驱动；把两者放进同一所有权对象，避免上游
/// session 建立后 endpoint 提前 Drop 导致所有 stream 被动关闭。
struct WebTransportUpstream {
    _endpoint: wtransport::Endpoint<wtransport::endpoint::endpoint_side::Client>,
    connection: Arc<wtransport::Connection>,
}

/// WebTransport stream 名额的 RAII 守卫。
///
/// 业务作用：无论正常 EOF、上游失败、取消或 task abort 都归还 session stream 计数，避免
/// 迟到错误把会话永久锁死在并发上限。
struct WebTransportStreamLease {
    state: Arc<crate::protocols::masque::WebTransportSession>,
    bidirectional: bool,
}

impl Drop for WebTransportStreamLease {
    /// 业务作用：在 stream 所有终态统一归还对应方向的并发名额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；计数已为零时底层实现保持不变。
    fn drop(&mut self) {
        self.state.close_stream(self.bidirectional);
    }
}

/// WebTransport 独占移交的连接权威；原始身份、DATAGRAM 分派与关闭信号必须来自同一连接。
struct WebTransportConnection {
    connection: h3::server::Connection<crate::protocols::h3_quinn_tracked::Connection, Bytes>,
    initial_peer: SocketAddr,
    extensions: Arc<QuicExtensionContext>,
    shutdown: watch::Receiver<bool>,
}

/// 业务作用：执行经统一 route 管线授权的 WebTransport CONNECT，并桥接真实上游 session。
///
/// 参数说明：
/// - `request`：是下游 H3 CONNECT 与连接所有权
/// - `stream`：是下游 H3 CONNECT 与连接所有权
/// - `proxy`：执行公共安全治理
/// - `proxy_id`：执行公共安全治理
/// - `session`：同一 H3 连接的独占所有权、迁移前身份、DATAGRAM 分发表与关闭信号。
///
/// 返回：上下游 session 正常结束时成功；治理拒绝会发送对应 HTTP 响应，上游建连或 relay
/// 失败时返回错误并关闭两个 QUIC 连接。
async fn serve_webtransport(
    request: Request<()>,
    stream: h3::server::RequestStream<crate::protocols::h3_quinn_tracked::BidiStream<Bytes>, Bytes>,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    session: WebTransportConnection,
) -> Result<()> {
    let WebTransportConnection {
        connection,
        initial_peer,
        extensions,
        shutdown,
    } = session;
    anyhow::ensure!(
        request.method() == Method::CONNECT,
        "WebTransport protocol requires CONNECT method"
    );
    // H3 session accept 仍需持有原始 Protocol extension；治理请求只复制一次小型 CONNECT head，
    // body 永远为空且不会复制任何业务 stream/datagram payload。
    let mut route_request = Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone())
        .version(request.version())
        .body(full_body(Bytes::new()))
        .context("build WebTransport governance request")?;
    *route_request.headers_mut() = request.headers().clone();
    route_request.extensions_mut().insert(initial_peer);
    route_request
        .extensions_mut()
        .insert(crate::protocols::masque::WebTransportRequest);
    if request
        .extensions()
        .get::<crate::protocols::masque::EarlyDataRequest>()
        .is_some()
    {
        route_request
            .extensions_mut()
            .insert(crate::protocols::masque::EarlyDataRequest);
    }
    let mut response = match proxy
        .clone()
        .handle_boxed(
            route_request,
            ConnInfo::plain(initial_peer),
            "https",
            proxy_id.clone(),
        )
        .await
    {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let Some(plan) = response
        .extensions_mut()
        .remove::<crate::protocols::masque::WebTransportPlan>()
    else {
        let (send, _recv) = stream.split();
        return send_response(send, response, &Method::CONNECT).await;
    };

    // 上游必须先完成 TLS、SETTINGS 与 session 2xx，之后才能向下游确认成功；反过来会留下
    // “客户端已成功、网关却没有后端”的半完成长连接。
    let upstream = match connect_webtransport_upstream(plan.policy.as_ref(), plan.origin.as_ref())
        .await
    {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::debug!(route = %plan.route_id, %error, "WebTransport upstream unavailable");
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::from_static(
                    b"WebTransport upstream unavailable",
                )))
                .expect("fixed WebTransport upstream response");
            let (send, _recv) = stream.split();
            return send_response(send, response, &Method::CONNECT).await;
        }
    };
    let stream_id = stream.send_id().into_inner();
    let queue = usize::try_from(plan.policy.budget.max_datagram_queue)
        .context("convert WebTransport DATAGRAM queue")?;
    let (datagrams, incoming_datagrams) = mpsc::channel(queue);
    anyhow::ensure!(
        extensions
            .dispatcher
            .register(stream_id, datagrams, DatagramProtocol::WebTransport,),
        "WebTransport stream id is already registered"
    );
    let _registration = DatagramRegistration {
        dispatcher: extensions.dispatcher.clone(),
        stream_id,
    };
    let downstream =
        match h3_webtransport::server::WebTransportSession::accept(request, stream, connection)
            .await
        {
            Ok(session) => Arc::new(session),
            Err(error) => {
                upstream
                    .connection
                    .close(wtransport::VarInt::from_u32(0), b"downstream rejected");
                return Err(error).context("accept downstream WebTransport session");
            }
        };
    let mut session_metrics =
        WebTransportSessionMetrics::new(extensions.dispatcher.metrics.clone());
    let result = relay_webtransport(
        downstream,
        upstream.connection.clone(),
        incoming_datagrams,
        extensions.clone(),
        stream_id,
        proxy,
        proxy_id,
        initial_peer,
        plan,
        shutdown,
    )
    .await;
    if result.is_ok() {
        session_metrics.complete();
    }
    upstream
        .connection
        .close(wtransport::VarInt::from_u32(0), b"gateway session closed");
    // 当前实现每条下游 QUIC connection 只允许一个 WebTransport session；结束时关闭连接，
    // 使所有残余 stream 都取得一致终态，不留下失去 session owner 的普通 H3 请求。
    extensions
        .connection
        .close(quinn::VarInt::from_u32(0), b"WebTransport session closed");
    result
}

/// 业务作用：使用构建期冻结的 HTTPS URL 与信任根建立真实上游 WebTransport session。
///
/// 参数说明：
/// - `policy`：提供固定目标、TLS 与资源门
/// - `origin`：是下游已通过 allowlist 的来源。
///
/// 返回：连接成功时返回同时持有 endpoint 与 session 的对象；DNS、TLS、SETTINGS、非 2xx 或
/// deadline 失败时返回错误，调用方不得向下游发送成功响应。
async fn connect_webtransport_upstream(
    policy: &crate::protocols::masque::WebTransportPolicy,
    origin: &str,
) -> Result<WebTransportUpstream> {
    let tls = wtransport::tls::client::build_default_tls_config(policy.roots(), None);
    let mut transport = wtransport::config::QuicTransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(
            u32::try_from(policy.budget.max_bidi_streams)
                .context("convert WebTransport bidi stream budget")?,
        ))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(
            u32::try_from(policy.budget.max_uni_streams)
                .context("convert WebTransport uni stream budget")?,
        ));
    let datagram_buffer = usize::try_from(
        policy
            .budget
            .max_datagram_queue
            .saturating_mul(policy.budget.max_datagram_bytes as u64),
    )
    .context("convert WebTransport DATAGRAM buffer budget")?;
    transport
        .datagram_receive_buffer_size(Some(datagram_buffer))
        .datagram_send_buffer_size(datagram_buffer);
    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_custom_tls_and_transport(tls, transport)
        .max_idle_timeout(Some(Duration::from_millis(policy.budget.idle_timeout_ms)))
        .map_err(|_| anyhow::anyhow!("invalid WebTransport upstream idle timeout"))?
        .build();
    let endpoint = wtransport::Endpoint::client(config).context("create WebTransport endpoint")?;
    let options = wtransport::endpoint::ConnectOptions::builder(policy.upstream())
        .add_header("origin", origin)
        .build();
    let connection = tokio::time::timeout(
        Duration::from_millis(policy.connect_timeout_ms),
        endpoint.connect(options),
    )
    .await
    .context("WebTransport upstream connect timeout")?
    .context("connect WebTransport upstream")?;
    Ok(WebTransportUpstream {
        _endpoint: endpoint,
        connection: Arc::new(connection),
    })
}

/// 业务作用：在一个 WebTransport session 内双向接收 stream/datagram，并按共享硬门转发。
///
/// 参数说明：
/// - `downstream`：已经完成握手的下游 WebTransport session。
/// - `upstream`：已经完成握手的上游 WebTransport session。
/// - `incoming_datagrams`：连接级分发给本 session 的有界消息队列。
/// - `extensions`：用于向下游发送 DATAGRAM 的连接扩展。
/// - `stream_id`：当前 WebTransport session 绑定的 stream 标识。
/// - `proxy`：普通 H3 请求共用的网关执行器。
/// - `proxy_id`：逻辑 listener 标识。
/// - `initial_peer`：握手时冻结的下游地址。
/// - `plan`：固定后端与双向传输预算。
/// - `shutdown`：入口换代或停机的撤销信号。
///
/// 返回：正常关闭、idle/lifetime 或撤权返回成功；协议、stream relay 和连接错误返回失败。
#[allow(clippy::too_many_arguments)]
async fn relay_webtransport(
    downstream: Arc<
        h3_webtransport::server::WebTransportSession<
            crate::protocols::h3_quinn_tracked::Connection,
            Bytes,
        >,
    >,
    upstream: Arc<wtransport::Connection>,
    mut incoming_datagrams: mpsc::Receiver<Bytes>,
    extensions: Arc<QuicExtensionContext>,
    stream_id: u64,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    initial_peer: SocketAddr,
    plan: crate::protocols::masque::WebTransportPlan,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let budget = plan.policy.budget;
    let metrics = extensions.dispatcher.metrics.clone();
    let state = Arc::new(crate::protocols::masque::WebTransportSession::default());
    state.freeze_identity(initial_peer.ip().to_string());
    let started_ms = crate::upstream::load::monotonic_ms();
    let last_activity = Arc::new(AtomicU64::new(started_ms));
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    let session_id = downstream.session_id();
    let relay_result = loop {
        let timeout = webtransport_next_timeout(
            last_activity.load(Ordering::Acquire),
            started_ms,
            budget.idle_timeout_ms,
            plan.policy.max_lifetime_ms,
        );
        tokio::select! {
            _ = plan.guard.closed() => break Ok(()),
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
            _ = tokio::time::sleep(timeout) => {
                let now = crate::upstream::load::monotonic_ms();
                let idle = now.saturating_sub(last_activity.load(Ordering::Acquire));
                let lifetime = now.saturating_sub(started_ms);
                if idle >= budget.idle_timeout_ms
                    || (plan.policy.max_lifetime_ms > 0
                        && lifetime >= plan.policy.max_lifetime_ms)
                {
                    break Ok(());
                }
            }
            accepted = downstream.accept_bi() => {
                let accepted = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) if webtransport_downstream_closed_normally(&extensions.connection) => {
                        break Ok(());
                    }
                    Err(error) => return Err(error).context("accept downstream WebTransport bidi stream"),
                };
                match accepted {
                    Some(h3_webtransport::server::AcceptedBi::BidiStream(id, mut stream)) => {
                        if id != session_id
                            || state.open_stream(&budget, true)
                                != crate::protocols::masque::SessionAdmission::Accepted
                        {
                            // 已被 transport 接受的流必须显式 RESET/STOP；只 Drop 会让对端无法
                            // 区分容量拒绝与调度延迟，并可能继续发送直至 flow-control 耗尽。
                            h3::quic::RecvStream::stop_sending(
                                &mut stream,
                                Code::H3_REQUEST_REJECTED.value(),
                            );
                            h3::quic::SendStream::<Bytes>::reset(
                                &mut stream,
                                Code::H3_REQUEST_REJECTED.value(),
                            );
                            metrics.inc_webtransport_stream_rejected(true);
                            continue;
                        }
                        metrics.inc_webtransport_stream(true);
                        last_activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
                        let upstream = upstream.clone();
                        let state = state.clone();
                        let activity = last_activity.clone();
                        tasks.spawn(async move {
                            let _lease = WebTransportStreamLease {
                                state: state.clone(),
                                bidirectional: true,
                            };
                            let opening = upstream.open_bi().await.context("open upstream bidi stream")?;
                            let peer = wtransport::stream::BiStream::join(
                                opening.await.context("initialize upstream bidi stream")?,
                            );
                            relay_webtransport_bidi(stream, peer, state, budget, activity).await
                        });
                    }
                    Some(h3_webtransport::server::AcceptedBi::Request(mut request, stream)) => {
                        prepare_h3_request(&mut request, initial_peer)?;
                        if request.extensions().get::<h3::ext::Protocol>()
                            == Some(&h3::ext::Protocol::WEB_TRANSPORT)
                        {
                            let response = Response::builder()
                                .status(StatusCode::TOO_MANY_REQUESTS)
                                .body(full_body(Bytes::from_static(b"one WebTransport session per connection")))
                                .expect("fixed WebTransport session capacity response");
                            let (send, _recv) = stream.split();
                            tasks.spawn(async move {
                                send_response(send, response, &Method::CONNECT).await
                            });
                        } else {
                            let proxy = proxy.clone();
                            let proxy_id = proxy_id.clone();
                            let extensions = extensions.clone();
                            let request_shutdown = shutdown.clone();
                            let metrics = extensions.dispatcher.metrics.clone();
                            tasks.spawn(async move {
                                let mut stream_metrics = Http3StreamMetrics::new(metrics);
                                let result = serve_resolved_request(
                                    request,
                                    stream,
                                    proxy,
                                    proxy_id,
                                    initial_peer,
                                    extensions,
                                    request_shutdown,
                                )
                                .await;
                                if result.is_ok() {
                                    stream_metrics.complete();
                                }
                                result
                            });
                        }
                    }
                    None => break Ok(()),
                }
            }
            accepted = downstream.accept_uni() => {
                let accepted = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) if webtransport_downstream_closed_normally(&extensions.connection) => {
                        break Ok(());
                    }
                    Err(error) => return Err(error).context("accept downstream WebTransport uni stream"),
                };
                let Some((id, mut stream)) = accepted else {
                    break Ok(());
                };
                if id != session_id
                    || state.open_stream(&budget, false)
                        != crate::protocols::masque::SessionAdmission::Accepted
                {
                    h3::quic::RecvStream::stop_sending(
                        &mut stream,
                        Code::H3_REQUEST_REJECTED.value(),
                    );
                    metrics.inc_webtransport_stream_rejected(false);
                    continue;
                }
                metrics.inc_webtransport_stream(false);
                last_activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
                let upstream = upstream.clone();
                let state = state.clone();
                let activity = last_activity.clone();
                tasks.spawn(async move {
                    let _lease = WebTransportStreamLease {
                        state: state.clone(),
                        bidirectional: false,
                    };
                    let opening = upstream.open_uni().await.context("open upstream uni stream")?;
                    let peer = opening.await.context("initialize upstream uni stream")?;
                    copy_webtransport_direction(stream, peer, state, budget, activity).await
                });
            }
            accepted = upstream.accept_bi() => {
                let (mut peer_send, peer_recv) = match accepted {
                    Ok(stream) => stream,
                    Err(error) if webtransport_upstream_closed_normally(&error) => break Ok(()),
                    Err(error) => return Err(error).context("accept upstream bidi stream"),
                };
                if state.open_stream(&budget, true)
                    != crate::protocols::masque::SessionAdmission::Accepted
                {
                    let _ = peer_send.reset(wtransport::VarInt::from_u32(0));
                    peer_recv.stop(wtransport::VarInt::from_u32(0));
                    metrics.inc_webtransport_stream_rejected(true);
                    continue;
                }
                metrics.inc_webtransport_stream(true);
                let peer = wtransport::stream::BiStream::join((peer_send, peer_recv));
                last_activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
                let downstream = downstream.clone();
                let state = state.clone();
                let activity = last_activity.clone();
                tasks.spawn(async move {
                    let _lease = WebTransportStreamLease {
                        state: state.clone(),
                        bidirectional: true,
                    };
                    let stream = downstream
                        .open_bi(downstream.session_id())
                        .await
                        .context("open downstream bidi stream")?;
                    relay_webtransport_bidi(stream, peer, state, budget, activity).await
                });
            }
            accepted = upstream.accept_uni() => {
                let peer = match accepted {
                    Ok(stream) => stream,
                    Err(error) if webtransport_upstream_closed_normally(&error) => break Ok(()),
                    Err(error) => return Err(error).context("accept upstream uni stream"),
                };
                if state.open_stream(&budget, false)
                    != crate::protocols::masque::SessionAdmission::Accepted
                {
                    peer.stop(wtransport::VarInt::from_u32(0));
                    metrics.inc_webtransport_stream_rejected(false);
                    continue;
                }
                metrics.inc_webtransport_stream(false);
                last_activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
                let downstream = downstream.clone();
                let state = state.clone();
                let activity = last_activity.clone();
                tasks.spawn(async move {
                    let _lease = WebTransportStreamLease {
                        state: state.clone(),
                        bidirectional: false,
                    };
                    let stream = downstream
                        .open_uni(downstream.session_id())
                        .await
                        .context("open downstream uni stream")?;
                    copy_webtransport_direction(peer, stream, state, budget, activity).await
                });
            }
            datagram = incoming_datagrams.recv() => {
                let Some(payload) = datagram else {
                    break Ok(());
                };
                if payload.len() > budget.max_datagram_bytes {
                    metrics.inc_webtransport_datagram_drop();
                    continue;
                }
                if state.admit_bytes(&budget, payload.len())
                    != crate::protocols::masque::SessionAdmission::Accepted
                {
                    metrics.inc_webtransport_datagram_drop();
                    break Ok(());
                }
                if upstream.send_datagram(payload.as_ref()).is_ok() {
                    last_activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
                    metrics.inc_webtransport_datagram(true);
                } else {
                    metrics.inc_webtransport_datagram_drop();
                }
            }
            datagram = upstream.receive_datagram() => {
                let datagram = match datagram {
                    Ok(datagram) => datagram,
                    Err(error) if webtransport_upstream_closed_normally(&error) => break Ok(()),
                    Err(error) => return Err(error).context("receive upstream WebTransport DATAGRAM"),
                };
                let payload = datagram.payload();
                if payload.len() > budget.max_datagram_bytes {
                    metrics.inc_webtransport_datagram_drop();
                    continue;
                }
                if state.admit_bytes(&budget, payload.len())
                    != crate::protocols::masque::SessionAdmission::Accepted
                {
                    metrics.inc_webtransport_datagram_drop();
                    break Ok(());
                }
                let mut wire = Vec::with_capacity(payload.len().saturating_add(8));
                crate::protocols::masque::encode_varint(stream_id / 4, &mut wire)?;
                wire.extend_from_slice(payload.as_ref());
                if extensions.connection.send_datagram(Bytes::from(wire)).is_ok() {
                    last_activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
                    metrics.inc_webtransport_datagram(false);
                } else {
                    metrics.inc_webtransport_datagram_drop();
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(_))) if webtransport_downstream_closed_normally(&extensions.connection) => break Ok(()),
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(error).context("WebTransport stream task failed"),
                    None => {}
                }
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tracing::debug!(route = %plan.route_id, "WebTransport session closed");
    relay_result
}

/// 业务作用：区分下游主动结束 WebTransport 与 QUIC/HTTP3 协议故障，使正常关闭不污染错误率。
///
/// 参数说明：
/// - `connection`：是承载该 session 的下游 Quinn connection。
///
/// 返回：对端 application close 或网关已主动关闭时返回 true；transport、协议、超时错误返回 false。
fn webtransport_downstream_closed_normally(connection: &quinn::Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::LocallyClosed)
    )
}

/// 业务作用：区分上游 WebTransport 正常 application close 与连接或协议故障。
///
/// 参数说明：
/// - `error`：是 wtransport 接收流或数据报时返回的连接终态。
///
/// 返回：远端或本地应用主动关闭时返回 true；网络、HTTP3、超时与容量故障返回 false。
fn webtransport_upstream_closed_normally(error: &wtransport::error::ConnectionError) -> bool {
    matches!(
        error,
        wtransport::error::ConnectionError::ApplicationClosed(_)
            | wtransport::error::ConnectionError::LocallyClosed
    )
}

/// 业务作用：计算 WebTransport 下一次 idle/lifetime 复验等待，避免每个 packet 创建独立 timer。
///
/// 参数说明：
/// - `last_activity_ms`：是单调时钟
/// - `started_ms`：是单调时钟
/// - `idle_ms`：是硬门。
/// - `lifetime_ms`：是硬门。
///
/// 返回：返回到最近门限的非负等待时间；已到期时返回零时长。
fn webtransport_next_timeout(
    last_activity_ms: u64,
    started_ms: u64,
    idle_ms: u64,
    lifetime_ms: u64,
) -> Duration {
    let now = crate::upstream::load::monotonic_ms();
    let idle_remaining = last_activity_ms.saturating_add(idle_ms).saturating_sub(now);
    let remaining = if lifetime_ms > 0 {
        idle_remaining.min(started_ms.saturating_add(lifetime_ms).saturating_sub(now))
    } else {
        idle_remaining
    };
    Duration::from_millis(remaining)
}

/// 业务作用：在一条 WebTransport 双向 stream 上同时桥接两个方向并共享会话字节预算。
///
/// 参数说明：
/// - `left`：是下游与上游 stream
/// - `right`：是下游与上游 stream
/// - `state`：是 session 共享硬门
/// - `budget`：是 session 共享硬门
/// - `activity`：发布成功写入的单调时间。
///
/// 返回：双向 EOF 时成功；任一方向 I/O 或累计字节超限时失败并让 session owner 收口。
async fn relay_webtransport_bidi<L, R>(
    left: L,
    right: R,
    state: Arc<crate::protocols::masque::WebTransportSession>,
    budget: crate::protocols::masque::WebTransportBudget,
    activity: Arc<AtomicU64>,
) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (left_read, left_write) = tokio::io::split(left);
    let (right_read, right_write) = tokio::io::split(right);
    tokio::try_join!(
        copy_webtransport_direction(
            left_read,
            right_write,
            state.clone(),
            budget,
            activity.clone(),
        ),
        copy_webtransport_direction(right_read, left_write, state, budget, activity),
    )?;
    Ok(())
}

/// 业务作用：逐块转发 WebTransport stream，不聚合业务消息，并在写入前执行共享字节硬门。
///
/// 参数说明：
/// - `reader`：是单方向流
/// - `writer`：是单方向流
/// - `state`：提供全 session 累计额度
/// - `budget`：提供全 session 累计额度
/// - `activity`：只在真实写成功后推进。
///
/// 返回：EOF 与半关闭完成时成功；读取、写入或预算耗尽时返回错误。
async fn copy_webtransport_direction<R, W>(
    mut reader: R,
    mut writer: W,
    state: Arc<crate::protocols::masque::WebTransportSession>,
    budget: crate::protocols::masque::WebTransportBudget,
    activity: Arc<AtomicU64>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let length = reader
            .read(&mut buffer)
            .await
            .context("read WebTransport stream")?;
        if length == 0 {
            writer
                .shutdown()
                .await
                .context("finish WebTransport stream")?;
            return Ok(());
        }
        anyhow::ensure!(
            state.admit_bytes(&budget, length)
                == crate::protocols::masque::SessionAdmission::Accepted,
            "WebTransport session byte budget exhausted"
        );
        writer
            .write_all(&buffer[..length])
            .await
            .context("write WebTransport stream")?;
        activity.store(crate::upstream::load::monotonic_ms(), Ordering::Release);
    }
}

/// 单条 QUIC connection 的扩展协议共享运行态。
///
/// 业务作用：集中持有 DATAGRAM stream-id 分发表与 CONNECT-UDP socket 准入，确保 request task
/// 之间共享同一连接预算，不会因并发 stream 各建一份计数而突破上限。
struct QuicExtensionContext {
    connection: quinn::Connection,
    dispatcher: Arc<H3DatagramDispatcher>,
    connect_udp_slots: Arc<Semaphore>,
    max_datagram_queue: usize,
    max_datagram_bytes: usize,
}

impl QuicExtensionContext {
    /// 业务作用：按已校验 HTTP/3 计划构造单连接扩展运行态。
    ///
    /// 参数说明：
    /// - `connection`：是原始 Quinn 句柄
    /// - `http3`：提供会话与 DATAGRAM 硬门
    /// - `metrics`：接收固定低基数处置结果。
    ///
    /// 返回：返回尚无活动 session 的共享上下文，不启动外部 I/O。
    fn new(connection: quinn::Connection, http3: &Http3RuntimeCfg, metrics: Arc<Metrics>) -> Self {
        Self {
            connection,
            dispatcher: Arc::new(H3DatagramDispatcher::new(
                crate::protocols::masque::MAX_DATAGRAM_PAYLOAD,
                metrics,
            )),
            connect_udp_slots: Arc::new(Semaphore::new(http3.max_connect_udp_sessions)),
            max_datagram_queue: http3.max_datagram_queue,
            max_datagram_bytes: http3.max_datagram_bytes,
        }
    }
}

/// connection-wide HTTP/3 DATAGRAM 到 request stream 的有界分发表。
struct H3DatagramDispatcher {
    sessions: Mutex<HashMap<u64, DatagramSink>>,
    max_datagram_bytes: usize,
    metrics: Arc<Metrics>,
}

/// HTTP/3 DATAGRAM 所属的扩展协议。
#[derive(Clone, Copy)]
enum DatagramProtocol {
    ConnectUdp,
    WebTransport,
}

/// 一个活动 request stream 的有界 DATAGRAM 投递目标。
#[derive(Clone)]
struct DatagramSink {
    sender: mpsc::Sender<Bytes>,
    protocol: DatagramProtocol,
}

/// 活动 DATAGRAM 映射的 RAII 守卫。
///
/// 业务作用：保证 H3 response 写失败、relay 错误、取消与 panic unwind 都撤销 stream-id 映射，
/// 防止关闭队列永久留在连接级表中并吞掉后续迟到报文。
struct DatagramRegistration {
    dispatcher: Arc<H3DatagramDispatcher>,
    stream_id: u64,
}

impl Drop for DatagramRegistration {
    /// 业务作用：在所有 session 终态统一撤销 DATAGRAM 分发表权威。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：无；Drop 可重复安全执行，缺失条目不报错。
    fn drop(&mut self) {
        self.dispatcher.unregister(self.stream_id);
    }
}

impl H3DatagramDispatcher {
    /// 业务作用：创建空分发表并冻结单 payload 上限。
    ///
    /// 参数说明：
    /// - `max_datagram_bytes`：是 UDP payload 上限
    /// - `metrics`：记录固定转发/丢弃结果。
    ///
    /// 返回：返回不持有 session 的 dispatcher。
    fn new(max_datagram_bytes: usize, metrics: Arc<Metrics>) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_datagram_bytes,
            metrics,
        }
    }

    /// 业务作用：把一个 request stream 登记为 DATAGRAM 唯一消费者。
    ///
    /// 参数说明：
    /// - `stream_id`：是 client-initiated bidi stream id
    /// - `sender`：是该 session 有界队列
    /// - `protocol`：冻结丢弃指标的协议归属。
    ///
    /// 返回：首次登记成功返回 true；重复 id 返回 false，防止数据报被后到 task 劫持。
    fn register(
        &self,
        stream_id: u64,
        sender: mpsc::Sender<Bytes>,
        protocol: DatagramProtocol,
    ) -> bool {
        let mut sessions = self.sessions.lock();
        if sessions.contains_key(&stream_id) {
            return false;
        }
        sessions.insert(
            stream_id,
            DatagramSink {
                sender,
                protocol,
            },
        );
        true
    }

    /// 业务作用：在 session 终止时撤销 stream-id 权威映射。
    ///
    /// 参数说明：
    /// - `stream_id`：是不再接收 DATAGRAM 的 request stream。
    ///
    /// 返回：无；后续迟到报文按无 session 丢弃。
    fn unregister(&self, stream_id: u64) {
        self.sessions.lock().remove(&stream_id);
    }

    /// 业务作用：解析 Quarter Stream ID 并把单个 DATAGRAM 非阻塞投递给对应 session。
    ///
    /// 参数说明：
    /// - `datagram`：是 Quinn 收到的完整 HTTP/3 DATAGRAM wire payload。
    ///
    /// 返回：无；畸形、未知 stream、超限或队列满都按不可靠语义丢弃并计数，不阻塞其它 session。
    fn dispatch(&self, datagram: Bytes) {
        let mut cursor = datagram.as_ref();
        let Some(quarter_stream_id) = crate::protocols::masque::decode_varint(&mut cursor) else {
            self.metrics.inc_http3_datagram_drop();
            return;
        };
        let Some(stream_id) = quarter_stream_id.checked_mul(4) else {
            self.metrics.inc_http3_datagram_drop();
            return;
        };
        let consumed = datagram.len().saturating_sub(cursor.len());
        let payload = datagram.slice(consumed..);
        let sink = self.sessions.lock().get(&stream_id).cloned();
        let Some(sink) = sink else {
            self.metrics.inc_http3_datagram_drop();
            return;
        };
        // CONNECT-UDP payload 还包含 Context ID，WebTransport payload 则没有；dispatcher 只做
        // 协议绝对上限，各 session 随后执行自己的更小配置门。
        if payload.len() > self.max_datagram_bytes.saturating_add(8) {
            self.inc_datagram_drop(sink.protocol);
            return;
        }
        match sink.sender.try_send(payload) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                self.inc_datagram_drop(sink.protocol);
            }
        }
    }

    /// 业务作用：把已归属 session 的 DATAGRAM 丢弃计入正确协议，避免 WebTransport 污染
    /// CONNECT-UDP 指标并掩盖各自的容量问题。
    ///
    /// 参数说明：
    /// - `protocol`：是注册 session 时冻结的协议身份。
    ///
    /// 返回：无；只更新对应固定计数器。
    fn inc_datagram_drop(&self, protocol: DatagramProtocol) {
        match protocol {
            DatagramProtocol::ConnectUdp => self.metrics.inc_connect_udp_datagram_drop(),
            DatagramProtocol::WebTransport => self.metrics.inc_webtransport_datagram_drop(),
        }
    }
}

/// 业务作用：独占读取一条 QUIC connection 的 DATAGRAM 并送入 stream-id 分发表。
///
/// 参数说明：
/// - `connection`：提供 Quinn datagram 接口
/// - `dispatcher`：持有活动 session 队列。
///
/// 返回：无；连接关闭即停止，错误不会重启第二个 reader 与当前 generation 争抢报文。
async fn receive_h3_datagrams(
    connection: quinn::Connection,
    dispatcher: Arc<H3DatagramDispatcher>,
) {
    while let Ok(datagram) = connection.read_datagram().await {
        dispatcher.dispatch(datagram);
    }
}

/// 业务作用：执行已通过统一 route 安全管线的 CONNECT-UDP session，并在同一 request stream
/// 生命周期内桥接 HTTP/3 DATAGRAM、DATAGRAM capsule 与单个已校验 UDP 目标。
///
/// 参数说明：
/// - `request`：是 extended CONNECT head 与控制流
/// - `stream`：是 extended CONNECT head 与控制流
/// - `proxy`：执行 统一治理
/// - `proxy_id`：执行 统一治理
/// - `initial_peer`：是迁移前冻结身份
/// - `extensions`：是连接级有界运行态
/// - `shutdown`：在 listener 换代时结束会话。
///
/// 返回：会话正常收尾时成功；配置未开放、治理拒绝、socket 或 H3 协议失败时返回错误。
async fn serve_connect_udp(
    mut request: Request<()>,
    mut stream: h3::server::RequestStream<
        crate::protocols::h3_quinn_tracked::BidiStream<Bytes>,
        Bytes,
    >,
    proxy: Arc<GatewayProxy>,
    proxy_id: Arc<str>,
    initial_peer: SocketAddr,
    extensions: Arc<QuicExtensionContext>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    anyhow::ensure!(
        request.method() == Method::CONNECT,
        "CONNECT-UDP protocol requires CONNECT method"
    );
    let permit = match extensions.connect_udp_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let response = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(full_body(Bytes::from_static(
                    b"CONNECT-UDP session limit reached",
                )))
                .expect("fixed CONNECT-UDP capacity response");
            let (send, _recv) = stream.split();
            return send_response(send, response, &Method::CONNECT).await;
        }
    };
    request
        .extensions_mut()
        .insert(crate::protocols::masque::ConnectUdpRequest);
    let (parts, ()) = request.into_parts();
    let request = Request::from_parts(parts, full_body(Bytes::new()));
    let mut response = match proxy
        .handle_boxed(request, ConnInfo::plain(initial_peer), "https", proxy_id)
        .await
    {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let Some(plan) = response
        .extensions_mut()
        .remove::<crate::protocols::masque::ConnectUdpPlan>()
    else {
        let (send, _recv) = stream.split();
        return send_response(send, response, &Method::CONNECT).await;
    };
    let socket = match connect_checked_udp(plan.addresses.as_ref(), plan.policy.connect_timeout())
        .await
    {
        Ok(socket) => socket,
        Err(error) => {
            tracing::debug!(route = %plan.route_id, %error, "CONNECT-UDP socket preparation failed");
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::from_static(
                    b"CONNECT-UDP target unavailable",
                )))
                .expect("fixed CONNECT-UDP target response");
            let (send, _recv) = stream.split();
            return send_response(send, response, &Method::CONNECT).await;
        }
    };
    let stream_id = stream.send_id().into_inner();
    let (datagrams, incoming_datagrams) = mpsc::channel(extensions.max_datagram_queue);
    anyhow::ensure!(
        extensions
            .dispatcher
            .register(stream_id, datagrams, DatagramProtocol::ConnectUdp),
        "CONNECT-UDP stream id is already registered"
    );
    let _registration = DatagramRegistration {
        dispatcher: extensions.dispatcher.clone(),
        stream_id,
    };

    let (mut response_parts, _) = response.into_parts();
    response_parts.version = Version::HTTP_3;
    strip_forbidden_headers(&mut response_parts.headers);
    stream
        .send_response(Response::from_parts(response_parts, ()))
        .await
        .context("send CONNECT-UDP response")?;
    let (send, recv) = stream.split();
    relay_connect_udp(
        send,
        recv,
        socket,
        incoming_datagrams,
        extensions.connection.clone(),
        stream_id,
        extensions.max_datagram_bytes,
        plan,
        permit,
        extensions.dispatcher.metrics.clone(),
        shutdown,
    )
    .await
}

/// 业务作用：按已校验地址创建 connected UDP socket，禁止把原始 hostname 再交给系统解析。
///
/// 参数说明：
/// - `addresses`：是同一请求刚完成 SSRF 复验的地址
/// - `timeout`：限制本地 socket 准备。
///
/// 返回：首个可用地址对应的 connected socket；所有地址都失败时返回错误且不得发送 2xx。
async fn connect_checked_udp(
    addresses: &[SocketAddr],
    timeout: Duration,
) -> Result<tokio::net::UdpSocket> {
    for address in addresses {
        let bind = match address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let Ok(socket) = tokio::net::UdpSocket::bind(bind).await else {
            continue;
        };
        // 这里只连接本请求已经逐个校验的 IP；绝不使用 host:port 触发第二次 DNS 解析。
        if matches!(
            tokio::time::timeout(timeout, socket.connect(*address)).await,
            Ok(Ok(()))
        ) {
            return Ok(socket);
        }
    }
    anyhow::bail!("CONNECT-UDP target is unreachable")
}

/// 业务作用：在一个 CONNECT-UDP session 内执行双向数据报转发、capsule fallback、共享字节
/// 预算、idle/lifetime 与 shutdown 门，任何终态都关闭控制 stream 并归还 session 准入。
///
/// 参数说明：
/// - `send`：CONNECT 控制流的下游发送端。
/// - `recv`：CONNECT 控制流的下游接收端。
/// - `socket`：已按验证后的固定 IP 建连的 UDP socket。
/// - `incoming_datagrams`：仅属于当前 stream 的有界 DATAGRAM 队列。
/// - `connection`：用于发送 QUIC DATAGRAM 的连接。
/// - `stream_id`：当前 CONNECT stream 的 wire 标识。
/// - `max_datagram_bytes`：单条 DATAGRAM 字节上限。
/// - `plan`：固定目标与隧道资源策略。
/// - `_permit`：整个隧道生命周期内持有的准入配额。
/// - `metrics`：固定协议结果指标。
/// - `shutdown`：入口换代或停机的撤销信号。
///
/// 返回：正常超时、客户端结束或 shutdown 返回成功；H3/UDP I/O 错误返回失败。
#[allow(clippy::too_many_arguments)]
async fn relay_connect_udp(
    mut send: h3::server::RequestStream<
        crate::protocols::h3_quinn_tracked::SendStream<Bytes>,
        Bytes,
    >,
    mut recv: h3::server::RequestStream<crate::protocols::h3_quinn_tracked::RecvStream, Bytes>,
    socket: tokio::net::UdpSocket,
    mut incoming_datagrams: mpsc::Receiver<Bytes>,
    connection: quinn::Connection,
    stream_id: u64,
    max_datagram_bytes: usize,
    plan: crate::protocols::masque::ConnectUdpPlan,
    _permit: OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let started = tokio::time::Instant::now();
    let mut last_activity = started;
    let mut used_bytes = 0_u64;
    let mut udp_buffer = vec![0_u8; max_datagram_bytes.saturating_add(1)];
    let mut capsule_buffer = BytesMut::new();
    let close = plan.guard.closed();
    tokio::pin!(close);
    loop {
        let idle_deadline = (plan.policy.idle_timeout_ms > 0)
            .then(|| last_activity + Duration::from_millis(plan.policy.idle_timeout_ms));
        let lifetime_deadline = (plan.policy.max_lifetime_ms > 0)
            .then(|| started + Duration::from_millis(plan.policy.max_lifetime_ms));
        let deadline = match (idle_deadline, lifetime_deadline) {
            (Some(idle), Some(lifetime)) => idle.min(lifetime),
            (Some(deadline), None) | (None, Some(deadline)) => deadline,
            (None, None) => started + Duration::from_secs(365 * 24 * 60 * 60),
        };
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = &mut close => break,
            incoming = incoming_datagrams.recv() => {
                let Some(datagram) = incoming else {
                    break;
                };
                let mut payload = datagram.as_ref();
                let Some(context_id) = crate::protocols::masque::decode_varint(&mut payload) else {
                    metrics.inc_connect_udp_datagram_drop();
                    continue;
                };
                let Some(next_used) = connect_udp_next_bytes(
                    used_bytes,
                    payload.len(),
                    plan.policy.max_bytes,
                ) else {
                    metrics.inc_connect_udp_datagram_drop();
                    continue;
                };
                if context_id != 0 || payload.len() > max_datagram_bytes {
                    metrics.inc_connect_udp_datagram_drop();
                    continue;
                }
                socket.send(payload).await.context("send CONNECT-UDP payload")?;
                used_bytes = next_used;
                last_activity = tokio::time::Instant::now();
                metrics.inc_connect_udp_datagram(true);
            }
            received = socket.recv(&mut udp_buffer) => {
                let length = received.context("receive CONNECT-UDP payload")?;
                let Some(next_used) = connect_udp_next_bytes(
                    used_bytes,
                    length,
                    plan.policy.max_bytes,
                ) else {
                    metrics.inc_connect_udp_datagram_drop();
                    continue;
                };
                if length > max_datagram_bytes {
                    metrics.inc_connect_udp_datagram_drop();
                    continue;
                }
                let mut wire = Vec::with_capacity(length.saturating_add(16));
                crate::protocols::masque::encode_varint(stream_id / 4, &mut wire)?;
                crate::protocols::masque::encode_varint(0, &mut wire)?;
                wire.put_slice(&udp_buffer[..length]);
                match connection.send_datagram(Bytes::from(wire)) {
                    Ok(()) => {
                        used_bytes = next_used;
                        last_activity = tokio::time::Instant::now();
                        metrics.inc_connect_udp_datagram(false);
                    }
                    Err(quinn::SendDatagramError::TooLarge
                        | quinn::SendDatagramError::UnsupportedByPeer
                        | quinn::SendDatagramError::Disabled) => {
                        metrics.inc_connect_udp_datagram_drop();
                    }
                    Err(quinn::SendDatagramError::ConnectionLost(error)) => {
                        return Err(error).context("send CONNECT-UDP DATAGRAM");
                    }
                }
            }
            frame = recv.recv_data() => {
                let Some(mut frame) = frame.context("receive CONNECT-UDP capsule DATA")? else {
                    break;
                };
                if capsule_buffer.len().saturating_add(frame.remaining())
                    > crate::protocols::masque::MAX_CAPSULE_LEN as usize + 16
                {
                    anyhow::bail!("CONNECT-UDP capsule buffer exceeds limit");
                }
                capsule_buffer.extend_from_slice(&frame.copy_to_bytes(frame.remaining()));
                loop {
                    let mut cursor = capsule_buffer.as_ref();
                    match crate::protocols::masque::parse_capsule(&mut cursor) {
                        crate::protocols::masque::CapsuleOutcome::Incomplete => break,
                        crate::protocols::masque::CapsuleOutcome::TooLarge {
                            ..
                        } => {
                            anyhow::bail!("CONNECT-UDP capsule exceeds limit");
                        }
                        crate::protocols::masque::CapsuleOutcome::Capsule {
                            kind, payload
                        } => {
                            let consumed = capsule_buffer.len().saturating_sub(cursor.len());
                            capsule_buffer.advance(consumed);
                            if kind != crate::protocols::masque::CAPSULE_TYPE_DATAGRAM {
                                continue;
                            }
                            let Some((context_id, payload)) = crate::protocols::masque::parse_datagram_capsule(&payload) else {
                                metrics.inc_connect_udp_datagram_drop();
                                continue;
                            };
                            let Some(next_used) = connect_udp_next_bytes(
                                used_bytes,
                                payload.len(),
                                plan.policy.max_bytes,
                            ) else {
                                metrics.inc_connect_udp_datagram_drop();
                                continue;
                            };
                            if context_id != 0 || payload.len() > max_datagram_bytes {
                                metrics.inc_connect_udp_datagram_drop();
                                continue;
                            }
                            socket.send(payload).await.context("send CONNECT-UDP capsule payload")?;
                            used_bytes = next_used;
                            last_activity = tokio::time::Instant::now();
                            metrics.inc_connect_udp_datagram(true);
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }
    recv.stop_sending(Code::H3_NO_ERROR);
    send.finish()
        .await
        .context("finish CONNECT-UDP response stream")?;
    tracing::debug!(
        route = %plan.route_id,
        host = %plan.target.host,
        port = plan.target.port,
        used_bytes,
        "CONNECT-UDP session closed"
    );
    Ok(())
}

/// 业务作用：让 CONNECT-UDP 两个方向共享一份累计字节预算，避免分别计数造成双倍放行。
///
/// 参数说明：
/// - `used`：是已转发总量
/// - `length`：是候选 payload 大小
/// - `maximum`：为零时表示不限制。
///
/// 返回：预算允许时返回成功发送后的新累计值；溢出或超限返回 None，原计数不变。
fn connect_udp_next_bytes(used: u64, length: usize, maximum: u64) -> Option<u64> {
    let next = used.checked_add(length as u64)?;
    if maximum > 0 && next > maximum {
        return None;
    }
    Some(next)
}

/// 把统一网关响应流写回一个 HTTP/3 request stream。
///
/// 业务作用：保持 DATA/trailers 的顺序与背压，并在任何 body/send 失败时同时终止发送和接收方向，
/// 避免上游继续生产客户端已无法消费的数据。
///
/// 参数说明：
/// - `stream`：是该请求独占的 H3 send half
/// - `response`：是统一管线生成的流式响应
/// - `request_method`：用于落实 HEAD/无 body 状态语义。
///
/// 返回：成功表示 FIN 已写出；失败表示 stream 已用 `H3_INTERNAL_ERROR` 终止。
async fn send_response(
    mut stream: h3::server::RequestStream<
        crate::protocols::h3_quinn_tracked::SendStream<Bytes>,
        Bytes,
    >,
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
/// 参数说明：
/// - `request_method`：是原请求方法
/// - `status`：是最终响应状态。
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
/// 参数说明：
/// - `headers`：是即将编码成 QPACK field section 的响应 header 集。
///
/// 返回：无返回值；原地删除固定禁用集合，其余 end-to-end header 保持不变。
fn strip_forbidden_headers(headers: &mut HeaderMap) {
    for name in H3_FORBIDDEN_HEADERS {
        headers.remove(name);
    }
}

/// 把 H3 receive half 暴露为 `http_body::Body`，不预读也不聚合请求 payload。
struct H3RequestBody {
    stream: h3::server::RequestStream<crate::protocols::h3_quinn_tracked::RecvStream, Bytes>,
    data_done: bool,
    trailers_done: bool,
}

impl H3RequestBody {
    /// 创建一个按 DATA→trailers 顺序消费的 H3 请求体。
    ///
    /// 业务作用：把 request stream 的唯一所有权绑定到 Body 生命周期；下游取消时 Drop 会停止
    /// 继续读取，从而把背压和取消传播给 QUIC。
    ///
    /// 参数说明：
    /// - `stream`：是单个 H3 请求独占的 receive half。
    ///
    /// 返回：尚未读取任何 frame 的流式 Body。
    fn new(
        stream: h3::server::RequestStream<crate::protocols::h3_quinn_tracked::RecvStream, Bytes>,
    ) -> Self {
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
    /// 参数说明：
    /// - `cx`：是当前请求 task 的唤醒上下文。
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
    /// 参数说明: 无。
    ///
    /// 返回：只有 DATA 与 trailers 阶段均结束时为 true。
    fn is_end_stream(&self) -> bool {
        self.trailers_done
    }

    /// 业务作用：H3 未声明 Content-Length 时保持未知长度，禁止适配层臆测并触发错误聚合。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认未知长度提示；显式 Content-Length 仍由请求 header 进入既有校验。
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
