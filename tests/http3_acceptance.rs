#![cfg(feature = "http3")]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use futures::future::join_all;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// V9-1：真实 QUIC/H3 客户端必须能通过 Naway 把流式 DATA 与 trailers 送到既有 HTTP 上游，
/// 并收到同一治理管线生成的响应；同时验证 UDP/TCP 同端口、TLS ALPN、H3 body 桥和证书
/// 热换只影响新握手、不断开既有 H3 connection。
#[tokio::test]
async fn downstream_http3_streams_request_through_existing_proxy_pipeline() {
    let (upstream_addr, upstream_started, upstream_cancelled, upstream_hits) =
        spawn_h3_probe_upstream().await;
    let data_addr = unused_tcp_addr();
    let tls_addr = unused_tcp_addr();
    let admin_addr = unused_tcp_addr();
    let dir = temp_dir("downstream-http3");
    let certificate_der =
        write_http3_gateway_config(&dir, data_addr, tls_addr, admin_addr, upstream_addr);
    let mut child = spawn_gateway(&dir).await;
    wait_for_health(admin_addr, &mut child).await;
    let tls_response = tls_h1_response(tls_addr, certificate_der.clone()).await;
    assert!(
        tls_response
            .to_ascii_lowercase()
            .contains(&format!("alt-svc: h3=\":{}\"; ma=86400", tls_addr.port())),
        "TLS h1 response did not advertise the committed QUIC listener: {tls_response}"
    );

    let endpoint = quic_client_endpoint(certificate_der.clone());
    let quic = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(tls_addr, "localhost")
            .expect("start QUIC connect"),
    )
    .await
    .expect("QUIC handshake timeout")
    .expect("complete QUIC handshake");
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(quic))
        .await
        .expect("start HTTP/3 client");
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });

    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/h3")
        .body(())
        .expect("build HTTP/3 request");
    let mut stream = sender
        .send_request(request)
        .await
        .expect("send HTTP/3 request headers");
    stream
        .send_data(Bytes::from_static(b"h3-stream-"))
        .await
        .expect("send first HTTP/3 DATA");
    stream
        .send_data(Bytes::from_static(b"body"))
        .await
        .expect("send second HTTP/3 DATA");
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-request-finish", http::HeaderValue::from_static("yes"));
    stream
        .send_trailers(trailers)
        .await
        .expect("send HTTP/3 request trailers");
    stream.finish().await.expect("finish HTTP/3 request");

    let response = stream
        .recv_response()
        .await
        .expect("receive HTTP/3 response headers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-seen-request-trailer"], "yes");
    assert!(
        !response.headers().contains_key(http::header::ALT_SVC),
        "HTTP/3 response must not repeat Alt-Svc advertisement"
    );
    let mut response_body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .expect("receive HTTP/3 response DATA")
    {
        let length = chunk.remaining();
        response_body.extend_from_slice(&chunk.copy_to_bytes(length));
    }
    assert_eq!(response_body, b"h3-stream-body");
    assert!(stream
        .recv_trailers()
        .await
        .expect("receive optional HTTP/3 response trailers")
        .is_none());

    let malformed_endpoint = quic_client_endpoint(certificate_der.clone());
    let malformed_quic = tokio::time::timeout(
        Duration::from_secs(5),
        malformed_endpoint
            .connect(tls_addr, "localhost")
            .expect("start malformed probe QUIC connect"),
    )
    .await
    .expect("malformed probe QUIC handshake timeout")
    .expect("complete malformed probe QUIC handshake");
    let raw_malformed_quic = malformed_quic.clone();
    let (mut malformed_driver, malformed_sender) =
        h3::client::new(h3_quinn::Connection::new(malformed_quic))
            .await
            .expect("start malformed probe H3 client");
    let malformed_driver_task = tokio::spawn(async move { malformed_driver.wait_idle().await });
    let hits_before_malformed = upstream_hits.load(Ordering::Acquire);
    let (mut malformed_send, mut malformed_recv) = raw_malformed_quic
        .open_bi()
        .await
        .expect("open raw malformed H3 request stream");
    // DATA 在首个 HEADERS 之前违反 RFC 9114 消息顺序；server 必须按协议错误
    // scope 终止 stream/connection，不能让半解析请求进入统一路由。
    malformed_send
        .write_all(&[0x00, 0x01, 0x00])
        .await
        .expect("write malformed H3 frame sequence");
    malformed_send
        .finish()
        .expect("finish malformed H3 send side");
    let mut reset_probe = [0_u8; 1];
    let malformed_result = tokio::time::timeout(
        Duration::from_secs(3),
        malformed_recv.read(&mut reset_probe),
    )
    .await
    .expect("malformed H3 stream must be rejected promptly");
    assert!(
        matches!(malformed_result, Err(_) | Ok(None)),
        "malformed request stream produced response bytes instead of being terminated"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        upstream_hits.load(Ordering::Acquire),
        hits_before_malformed,
        "malformed H3 stream reached the upstream routing pipeline"
    );

    drop(malformed_sender);
    malformed_endpoint.close(quinn::VarInt::from_u32(0), b"malformed probe complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), malformed_driver_task).await;

    let qpack_endpoint = quic_client_endpoint(certificate_der);
    let mut qpack_quic = None;
    for _ in 0..100 {
        let attempt = qpack_endpoint
            .connect(tls_addr, "localhost")
            .expect("start bad-QPACK QUIC connect");
        if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_millis(250), attempt).await
        {
            qpack_quic = Some(connection);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let qpack_quic = qpack_quic.expect("bad-QPACK probe must obtain released per-IP slot");
    let raw_qpack_quic = qpack_quic.clone();
    let (mut qpack_driver, qpack_sender) = h3::client::new(h3_quinn::Connection::new(qpack_quic))
        .await
        .expect("start bad-QPACK H3 control streams");
    let qpack_driver_task = tokio::spawn(async move { qpack_driver.wait_idle().await });
    let hits_before_bad_qpack = upstream_hits.load(Ordering::Acquire);
    let (mut qpack_send, mut qpack_recv) = raw_qpack_quic
        .open_bi()
        .await
        .expect("open raw bad-QPACK request stream");
    // HEADERS frame 声明 1 byte payload，但 0xff 是截断的 QPACK 整数前缀；server
    // 必须在 QPACK decode 边界拒绝，不能把半解码 header 发布到路由管线。
    qpack_send
        .write_all(&[0x01, 0x01, 0xff])
        .await
        .expect("write malformed QPACK field section");
    qpack_send.finish().expect("finish bad-QPACK send side");
    let bad_qpack_result =
        tokio::time::timeout(Duration::from_secs(3), qpack_recv.read(&mut reset_probe))
            .await
            .expect("bad QPACK stream/connection must be rejected promptly");
    assert!(
        matches!(bad_qpack_result, Err(_) | Ok(None)),
        "bad QPACK request produced response bytes instead of being terminated"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        upstream_hits.load(Ordering::Acquire),
        hits_before_bad_qpack,
        "bad QPACK request reached the upstream routing pipeline"
    );
    drop(qpack_sender);
    qpack_endpoint.close(quinn::VarInt::from_u32(0), b"bad-QPACK probe complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), qpack_driver_task).await;

    let rotated_certificate_der = write_http3_identity(&dir);
    let rotated_endpoint = quic_client_endpoint(rotated_certificate_der.clone());
    let mut rotated_connection = None;
    for _ in 0..200 {
        let attempt = rotated_endpoint
            .connect(tls_addr, "localhost")
            .expect("start rotated certificate QUIC connect");
        if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_millis(250), attempt).await
        {
            rotated_connection = Some(connection);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let rotated_connection = rotated_connection
        .expect("new QUIC handshakes must observe the hot-swapped certificate within 10 seconds");

    let saturated_endpoint = quic_client_endpoint(rotated_certificate_der);
    let saturated = tokio::time::timeout(
        Duration::from_millis(750),
        saturated_endpoint
            .connect(tls_addr, "localhost")
            .expect("start per-IP saturation probe"),
    )
    .await;
    assert!(
        !matches!(saturated, Ok(Ok(_))),
        "third same-IP QUIC connection bypassed max_connections_per_ip=2"
    );
    rotated_connection.close(quinn::VarInt::from_u32(0), b"release per-IP slot");

    let mut reused_connection = None;
    for _ in 0..100 {
        let attempt = saturated_endpoint
            .connect(tls_addr, "localhost")
            .expect("retry connection after per-IP slot release");
        if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_millis(250), attempt).await
        {
            reused_connection = Some(connection);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let reused_connection = reused_connection
        .expect("closing one QUIC connection must return its per-IP slot within 5 seconds");

    let oversized_value = "x".repeat(9 * 1024);
    let oversized_request = Request::builder()
        .method("GET")
        .uri("https://localhost/oversized-header")
        .header("x-oversized", oversized_value)
        .body(())
        .expect("build oversized H3 request");
    let hits_before_oversized = upstream_hits.load(Ordering::Acquire);
    assert!(
        sender.send_request(oversized_request).await.is_err(),
        "peer SETTINGS did not enforce max_request_header_bytes=8192"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        upstream_hits.load(Ordering::Acquire),
        hits_before_oversized,
        "oversized H3 header reached the upstream routing pipeline"
    );
    let rebound = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind replacement client UDP socket for migration");
    rebound
        .set_nonblocking(true)
        .expect("set migration socket nonblocking");
    endpoint
        .rebind(rebound)
        .expect("rebind client endpoint to exercise QUIC connection migration");

    let old_request = Request::builder()
        .method("GET")
        .uri("https://localhost/h3")
        .body(())
        .expect("build request on pre-rotation connection");
    let mut old_stream = sender
        .send_request(old_request)
        .await
        .expect("pre-rotation H3 connection must remain usable");
    old_stream
        .finish()
        .await
        .expect("finish request on pre-rotation connection");
    let old_response = old_stream
        .recv_response()
        .await
        .expect("receive response on pre-rotation connection");
    assert_eq!(old_response.status(), StatusCode::OK);
    while old_stream
        .recv_data()
        .await
        .expect("drain response on pre-rotation connection")
        .is_some()
    {}

    let cancel_request = Request::builder()
        .method("POST")
        .uri("https://localhost/cancel")
        .body(())
        .expect("build cancellable HTTP/3 request");
    let mut cancelled_stream = sender
        .send_request(cancel_request)
        .await
        .expect("send cancellable HTTP/3 headers");
    cancelled_stream
        .send_data(Bytes::from_static(b"partial"))
        .await
        .expect("send partial cancellable body");
    tokio::time::timeout(Duration::from_secs(3), upstream_started.notified())
        .await
        .expect("upstream must observe partial body before cancellation probe resets the stream");
    let cancellation = upstream_cancelled.notified();
    cancelled_stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    cancelled_stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    tokio::time::timeout(Duration::from_secs(3), cancellation)
        .await
        .expect("client stream cancellation must release the upstream request body");

    drop(sender);
    reused_connection.close(quinn::VarInt::from_u32(0), b"test complete");
    saturated_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    rotated_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), driver_task).await;
    stop_gateway(child).await;
}

/// V9-2：真实 H3 downstream 与独立 H3 upstream 必须通过同一代理管线全流式交换 DATA/trailers。
#[tokio::test]
async fn downstream_http3_to_upstream_http3_is_streaming_and_preserves_trailers() {
    let data_addr = unused_tcp_addr();
    let tls_addr = unused_tcp_addr();
    let admin_addr = unused_tcp_addr();
    let dir = temp_dir("h3-to-h3");
    std::fs::create_dir_all(&dir).expect("create H3-to-H3 test dir");
    let (upstream_addr, upstream_connections) = spawn_real_h3_upstream(&dir).await;
    let gateway_certificate_der =
        write_h3_to_h3_gateway_config(&dir, data_addr, tls_addr, admin_addr, upstream_addr);
    let mut child = spawn_gateway(&dir).await;
    wait_for_health(admin_addr, &mut child).await;
    for _ in 0..100 {
        if upstream_connections.load(Ordering::Acquire) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        upstream_connections.load(Ordering::Acquire),
        1,
        "H3 prewarm did not establish exactly one multiplex connection"
    );

    let endpoint = quic_client_endpoint(gateway_certificate_der);
    let quic = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(tls_addr, "localhost")
            .expect("start downstream H3-to-H3 connect"),
    )
    .await
    .expect("downstream H3-to-H3 handshake timeout")
    .expect("complete downstream H3-to-H3 handshake");
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(quic))
        .await
        .expect("start downstream H3-to-H3 client");
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });
    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/h3-to-h3")
        .body(())
        .expect("build H3-to-H3 request");
    let mut stream = sender
        .send_request(request)
        .await
        .expect("send H3-to-H3 request headers");
    stream
        .send_data(Bytes::from_static(b"upstream-h3-"))
        .await
        .expect("send H3-to-H3 first DATA");
    stream
        .send_data(Bytes::from_static(b"stream"))
        .await
        .expect("send H3-to-H3 second DATA");
    let mut request_trailers = http::HeaderMap::new();
    request_trailers.insert("x-h3-request-finish", http::HeaderValue::from_static("yes"));
    stream
        .send_trailers(request_trailers)
        .await
        .expect("send H3-to-H3 request trailers");
    stream.finish().await.expect("finish H3-to-H3 request");

    let response = stream
        .recv_response()
        .await
        .expect("receive H3-to-H3 response headers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-upstream-transport"], "h3");
    assert_eq!(response.headers()["x-seen-request-trailer"], "yes");
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .expect("receive H3-to-H3 response DATA")
    {
        let length = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(length));
    }
    assert_eq!(body, b"upstream-h3-stream");
    let response_trailers = stream
        .recv_trailers()
        .await
        .expect("receive H3-to-H3 response trailers")
        .expect("H3 upstream response trailer must survive both adapters");
    assert_eq!(response_trailers["x-h3-response-finish"], "yes");

    let concurrent = (0..8).map(|index| {
        let mut sender = sender.clone();
        async move {
            let request = Request::builder()
                .method("GET")
                .uri(format!("https://localhost/mux/{index}"))
                .body(())
                .expect("build multiplex H3 request");
            let mut stream = sender
                .send_request(request)
                .await
                .expect("open multiplex H3 request stream");
            stream.finish().await.expect("finish multiplex H3 request");
            let response = stream
                .recv_response()
                .await
                .expect("receive multiplex H3 response");
            assert_eq!(response.status(), StatusCode::OK);
            while stream
                .recv_data()
                .await
                .expect("drain multiplex H3 response")
                .is_some()
            {}
            let _ = stream
                .recv_trailers()
                .await
                .expect("receive multiplex H3 trailers");
        }
    });
    join_all(concurrent).await;
    assert_eq!(
        upstream_connections.load(Ordering::Acquire),
        1,
        "concurrent requests did not multiplex on one upstream QUIC connection"
    );

    let goaway_request = Request::builder()
        .method("GET")
        .uri("https://localhost/goaway")
        .body(())
        .expect("build upstream GOAWAY trigger request");
    let mut goaway_stream = sender
        .send_request(goaway_request)
        .await
        .expect("send upstream GOAWAY trigger request");
    goaway_stream
        .finish()
        .await
        .expect("finish upstream GOAWAY trigger request");
    assert_eq!(
        goaway_stream
            .recv_response()
            .await
            .expect("receive response before upstream GOAWAY")
            .status(),
        StatusCode::OK
    );
    while goaway_stream
        .recv_data()
        .await
        .expect("drain response before upstream GOAWAY")
        .is_some()
    {}
    let _ = goaway_stream
        .recv_trailers()
        .await
        .expect("receive trailers before upstream GOAWAY");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after_goaway = Request::builder()
        .method("GET")
        .uri("https://localhost/after-goaway")
        .body(())
        .expect("build request after upstream GOAWAY");
    let mut after_goaway_stream = sender
        .send_request(after_goaway)
        .await
        .expect("send downstream request after upstream GOAWAY");
    after_goaway_stream
        .finish()
        .await
        .expect("finish request after upstream GOAWAY");
    assert_eq!(
        after_goaway_stream
            .recv_response()
            .await
            .expect("receive response after upstream H3 reconnect")
            .status(),
        StatusCode::OK
    );
    while after_goaway_stream
        .recv_data()
        .await
        .expect("drain response after upstream H3 reconnect")
        .is_some()
    {}
    let _ = after_goaway_stream
        .recv_trailers()
        .await
        .expect("receive trailers after upstream H3 reconnect");
    assert_eq!(
        upstream_connections.load(Ordering::Acquire),
        2,
        "new request after GOAWAY did not establish a replacement upstream connection"
    );

    drop(sender);
    endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), driver_task).await;
    stop_gateway(child).await;
}

/// V9-4 回归 listener two-phase：候选 TCP 端口可绑但同端口 UDP 被占用时，
/// reload 必须整代拒绝并保留旧 H3；随后 100 次 SIGHUP 不得杀死已恢复的 TCP/UDP listener。
#[cfg(unix)]
#[tokio::test]
async fn http3_udp_bind_failure_rolls_back_and_reload_storm_keeps_old_listener() {
    let (upstream_addr, _, _, _) = spawn_h3_probe_upstream().await;
    let data_addr = unused_tcp_addr();
    let tls_addr = unused_tcp_addr();
    let admin_addr = unused_tcp_addr();
    let conflict_addr = unused_tcp_addr();
    let udp_blocker =
        std::net::UdpSocket::bind(conflict_addr).expect("occupy candidate HTTP/3 UDP port only");
    let dir = temp_dir("http3-udp-rollback");
    let certificate_der =
        write_http3_gateway_config(&dir, data_addr, tls_addr, admin_addr, upstream_addr);
    let config_path = dir.join("gateway.yml");
    let original = std::fs::read_to_string(&config_path).expect("read original H3 config");
    let candidate = original.replacen(
        &format!("listen: \"{tls_addr}\""),
        &format!("listen: \"{conflict_addr}\""),
        1,
    );
    assert_ne!(candidate, original, "TLS listener address was not replaced");

    let mut child = spawn_gateway(&dir).await;
    wait_for_health(admin_addr, &mut child).await;
    assert_eq!(
        h3_get_status(tls_addr, certificate_der.clone(), "/before-reload").await,
        StatusCode::OK
    );

    std::fs::write(&config_path, candidate).expect("publish UDP-conflicting candidate config");
    signal_reload(&child);
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert!(
        child
            .try_wait()
            .expect("poll gateway after bad reload")
            .is_none(),
        "UDP bind failure terminated the running gateway"
    );
    assert_eq!(
        h3_get_status(tls_addr, certificate_der.clone(), "/after-bad-reload").await,
        StatusCode::OK,
        "old H3 generation did not survive candidate UDP bind failure"
    );

    std::fs::write(&config_path, original).expect("restore valid H3 listener config");
    for _ in 0..100 {
        signal_reload(&child);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        child
            .try_wait()
            .expect("poll gateway after reload storm")
            .is_none(),
        "reload storm terminated the gateway"
    );
    assert_eq!(
        h3_get_status(tls_addr, certificate_der.clone(), "/after-reload-storm").await,
        StatusCode::OK
    );
    let tls_response = tls_h1_response(tls_addr, certificate_der).await;
    assert!(tls_response.contains("200 OK"), "{tls_response}");

    drop(udp_blocker);
    let old_endpoint = quic_client_endpoint(read_current_identity_der(&dir));
    let old_quic = tokio::time::timeout(
        Duration::from_secs(5),
        old_endpoint
            .connect(tls_addr, "localhost")
            .expect("start pre-drain H3 connection"),
    )
    .await
    .expect("pre-drain H3 handshake timeout")
    .expect("complete pre-drain H3 handshake");
    let (mut old_driver, mut old_sender) = h3::client::new(h3_quinn::Connection::new(old_quic))
        .await
        .expect("start pre-drain H3 client");
    let old_driver_task = tokio::spawn(async move { old_driver.wait_idle().await });

    let valid_candidate = std::fs::read_to_string(&config_path)
        .expect("read restored H3 config")
        .replacen(
            &format!("listen: \"{tls_addr}\""),
            &format!("listen: \"{conflict_addr}\""),
            1,
        );
    std::fs::write(&config_path, valid_candidate).expect("publish valid H3 topology candidate");
    signal_reload(&child);
    tokio::time::sleep(Duration::from_millis(750)).await;
    let active_certificate = read_current_identity_der(&dir);
    assert_eq!(
        h3_get_status(
            conflict_addr,
            active_certificate.clone(),
            "/after-successful-reload"
        )
        .await,
        StatusCode::OK,
        "new H3 generation did not activate after UDP conflict was removed"
    );
    let new_tls_response = tls_h1_response(conflict_addr, active_certificate).await;
    assert!(
        new_tls_response
            .to_ascii_lowercase()
            .contains(&format!("alt-svc: h3=\":{}\"", conflict_addr.port())),
        "new TCP generation did not advertise its matching UDP authority: {new_tls_response}"
    );

    let old_rejected = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let request = Request::builder()
                .method("GET")
                .uri("https://localhost/after-goaway")
                .body(())
                .expect("build post-GOAWAY request");
            match old_sender.send_request(request).await {
                Err(_) => return true,
                Ok(mut stream) => {
                    let _ = stream.finish().await;
                    let _ = stream.recv_response().await;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        old_rejected,
        "old H3 generation kept accepting request streams after topology GOAWAY"
    );
    drop(old_sender);
    old_endpoint.close(quinn::VarInt::from_u32(0), b"drain probe complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), old_driver_task).await;
    stop_gateway(child).await;
}

/// V9-3 64 MiB 双向慢流回归：下游 H3 与上游 H3 同时按 DATA frame 背压推进，
/// 不聚合 request/response body；断言完整字节数、trailer 与网关 RSS 增长不超 64 MiB。
#[tokio::test]
async fn http3_to_http3_large_slow_duplex_stream_has_bounded_rss() {
    const PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
    const CHUNK_BYTES: usize = 64 * 1024;
    const MAX_RSS_GROWTH_KIB: u64 = 64 * 1024;

    let data_addr = unused_tcp_addr();
    let tls_addr = unused_tcp_addr();
    let admin_addr = unused_tcp_addr();
    let dir = temp_dir("h3-large-duplex");
    std::fs::create_dir_all(&dir).expect("create H3 large-stream test dir");
    let (upstream_addr, upstream_connections) = spawn_real_h3_upstream(&dir).await;
    let gateway_certificate_der =
        write_h3_to_h3_gateway_config(&dir, data_addr, tls_addr, admin_addr, upstream_addr);
    let mut child = spawn_gateway(&dir).await;
    wait_for_health(admin_addr, &mut child).await;
    for _ in 0..100 {
        if upstream_connections.load(Ordering::Acquire) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let pid = child.id().expect("H3 large-stream gateway PID");
    let baseline = process_rss_kib(pid).await;

    let endpoint = quic_client_endpoint(gateway_certificate_der);
    let quic = endpoint
        .connect(tls_addr, "localhost")
        .expect("start large-stream QUIC connect")
        .await
        .expect("complete large-stream QUIC connect");
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(quic))
        .await
        .expect("start large-stream H3 client");
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });
    let transfer = tokio::spawn(async move {
        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/stream-large")
            .body(())
            .expect("build large H3 request");
        let stream = sender
            .send_request(request)
            .await
            .expect("send large H3 request headers");
        let (mut send, mut recv) = stream.split();
        let upload = tokio::spawn(async move {
            let chunk = Bytes::from(vec![0x5a; CHUNK_BYTES]);
            for _ in 0..(PAYLOAD_BYTES / CHUNK_BYTES) {
                send.send_data(chunk.clone())
                    .await
                    .expect("send large H3 DATA chunk");
                // 制造持续慢上传，让测试能观察背压下的常驻内存，而非瞬时将数据写完。
                tokio::task::yield_now().await;
            }
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-large-finish", http::HeaderValue::from_static("yes"));
            send.send_trailers(trailers)
                .await
                .expect("send large H3 request trailers");
            send.finish().await.expect("finish large H3 request");
        });
        let response = recv
            .recv_response()
            .await
            .expect("receive large H3 response headers");
        assert_eq!(response.status(), StatusCode::OK);
        let mut received = 0_usize;
        let mut paced_mib = 0_usize;
        while let Some(mut data) = recv
            .recv_data()
            .await
            .expect("receive large H3 response DATA")
        {
            received = received.saturating_add(data.remaining());
            let remaining = data.remaining();
            let _ = data.copy_to_bytes(remaining);
            let completed_mib = received / (1024 * 1024);
            if completed_mib > paced_mib {
                paced_mib = completed_mib;
                // 每 MiB 暂停一次足以让 QUIC receive window 多次闭环；不按每个 MTU 切片
                // sleep，否则 debug 测试会把 64 MiB 人为拖到数分钟。
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let trailers = recv
            .recv_trailers()
            .await
            .expect("receive large H3 response trailers")
            .expect("large H3 response trailer exists");
        assert_eq!(trailers["x-large-finish"], "yes");
        upload.await.expect("join large H3 upload");
        received
    });

    let mut peak = baseline;
    while !transfer.is_finished() {
        peak = peak.max(process_rss_kib(pid).await);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let received = transfer.await.expect("join H3 large duplex transfer");
    assert_eq!(received, PAYLOAD_BYTES);
    let growth = peak.saturating_sub(baseline);
    eprintln!(
        "http3_stream_rss payload_mib={} baseline_kib={baseline} peak_kib={peak} growth_kib={growth}",
        PAYLOAD_BYTES / 1024 / 1024
    );
    assert!(
        growth <= MAX_RSS_GROWTH_KIB,
        "HTTP/3 64 MiB slow duplex stream grew RSS by {growth} KiB"
    );

    endpoint.close(quinn::VarInt::from_u32(0), b"large stream complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), driver_task).await;
    stop_gateway(child).await;
}

/// V9-3 长稳态压力：在固定主连接持续代理请求的同时，反复打满/归还 per-IP 连接槽并改变
/// 客户端 UDP 源端口。关键断言是业务无 5xx、拒绝门持续生效、迁移后旧连接可用、连接/stream
/// gauge 最终归零且 Naway RSS 增长有界；默认 ignored，正式门显式运行至少 60 秒。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicit long-running HTTP/3 exhaustion and migration stress gate"]
async fn http3_long_connection_exhaustion_and_path_churn_recovers_all_resources() {
    const MAX_RSS_GROWTH_KIB: u64 = 64 * 1024;

    let stress_seconds = http3_stress_seconds();
    let (upstream_addr, _upstream_started, _upstream_cancelled, upstream_hits) =
        spawn_h3_probe_upstream().await;
    let data_addr = unused_tcp_addr();
    let tls_addr = unused_tcp_addr();
    let admin_addr = unused_tcp_addr();
    let dir = temp_dir("h3-long-exhaustion");
    let certificate_der =
        write_http3_gateway_config(&dir, data_addr, tls_addr, admin_addr, upstream_addr);
    let mut child = spawn_gateway(&dir).await;
    wait_for_health(admin_addr, &mut child).await;
    let pid = child.id().expect("H3 stress gateway PID");
    let baseline_rss = process_rss_kib(pid).await;

    let main_endpoint = quic_client_endpoint(certificate_der.clone());
    let main_connection = connect_quic_with_released_slot(&main_endpoint, tls_addr).await;
    let (mut main_driver, mut main_sender) =
        h3::client::new(h3_quinn::Connection::new(main_connection))
            .await
            .expect("start long-running H3 client");
    let main_driver_task = tokio::spawn(async move { main_driver.wait_idle().await });

    let churn_endpoint = quic_client_endpoint(certificate_der.clone());
    let saturation_endpoint = quic_client_endpoint(certificate_der);
    let mut churn_connection = connect_quic_with_released_slot(&churn_endpoint, tls_addr).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(stress_seconds);
    let mut iterations = 0_u64;
    let mut peak_rss = baseline_rss;
    while tokio::time::Instant::now() < deadline {
        let saturated = tokio::time::timeout(
            Duration::from_millis(250),
            saturation_endpoint
                .connect(tls_addr, "localhost")
                .expect("start long stress saturation probe"),
        )
        .await;
        assert!(
            !matches!(saturated, Ok(Ok(_))),
            "third same-IP QUIC connection bypassed the hard gate during long stress"
        );

        if iterations.is_multiple_of(4) {
            let rebound = std::net::UdpSocket::bind("127.0.0.1:0")
                .expect("bind long stress migration UDP socket");
            rebound
                .set_nonblocking(true)
                .expect("set long stress migration socket nonblocking");
            main_endpoint
                .rebind(rebound)
                .expect("rebind long-running H3 client endpoint");
        }
        send_h3_get_on_existing_connection(&mut main_sender, iterations).await;

        // 每轮都归还并重新取得第二个槽，证明拒绝风暴不会泄漏 peer/global connection RAII。
        churn_connection.close(quinn::VarInt::from_u32(0), b"rotate stress slot");
        churn_connection = connect_quic_with_released_slot(&churn_endpoint, tls_addr).await;
        iterations = iterations.saturating_add(1);
        if iterations.is_multiple_of(8) {
            peak_rss = peak_rss.max(process_rss_kib(pid).await);
        }
    }
    assert!(
        iterations >= 10,
        "long H3 stress completed too few iterations: {iterations}"
    );

    churn_connection.close(quinn::VarInt::from_u32(0), b"stress complete");
    drop(main_sender);
    main_endpoint.close(quinn::VarInt::from_u32(0), b"stress complete");
    churn_endpoint.close(quinn::VarInt::from_u32(0), b"stress complete");
    saturation_endpoint.close(quinn::VarInt::from_u32(0), b"stress complete");
    let _ = tokio::time::timeout(Duration::from_secs(2), main_driver_task).await;

    let mut metrics = String::new();
    for _ in 0..200 {
        metrics = raw_admin_get(admin_addr, "/metrics")
            .await
            .expect("read H3 stress metrics");
        if prometheus_metric(&metrics, "gw_quic_connections_active") == 0
            && prometheus_metric(&metrics, "gw_http3_streams_active") == 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        prometheus_metric(&metrics, "gw_quic_connections_active"),
        0,
        "QUIC connection gauge did not recover after long exhaustion stress"
    );
    assert_eq!(
        prometheus_metric(&metrics, "gw_http3_streams_active"),
        0,
        "HTTP/3 stream gauge did not recover after path churn"
    );
    assert!(
        prometheus_metric(&metrics, "gw_quic_migrations_total") >= 1,
        "repeated client source-port changes produced no observed QUIC migration"
    );
    assert!(
        prometheus_metric(&metrics, "gw_quic_handshakes_total{result=\"rejected\"}") >= iterations,
        "per-IP saturation attempts were not rejected at the handshake gate"
    );
    assert_eq!(
        prometheus_metric(&metrics, "gw_http3_requests_total{result=\"success\"}"),
        iterations,
        "long-running H3 requests were lost or misclassified"
    );
    assert_eq!(
        upstream_hits.load(Ordering::Acquire),
        iterations,
        "connection churn changed the exact number of upstream requests"
    );
    peak_rss = peak_rss.max(process_rss_kib(pid).await);
    let rss_growth = peak_rss.saturating_sub(baseline_rss);
    eprintln!(
        "http3_long_stress seconds={stress_seconds} iterations={iterations} baseline_kib={baseline_rss} peak_kib={peak_rss} growth_kib={rss_growth}"
    );
    assert!(
        rss_growth <= MAX_RSS_GROWTH_KIB,
        "HTTP/3 exhaustion/path churn grew gateway RSS by {rss_growth} KiB"
    );
    stop_gateway(child).await;
}

/// 业务作用：读取长稳态门的显式时长，并限制异常环境变量，防止 CI 误配成零时长假绿或
/// 无界占用测试机。
///
/// 参数说明：无。
///
/// 返回：5–600 秒内的压力时长；未配置时为 30 秒，非法值使测试失败。
fn http3_stress_seconds() -> u64 {
    let seconds = std::env::var("NAWAY_H3_STRESS_SECONDS")
        .map(|value| {
            value
                .parse::<u64>()
                .expect("NAWAY_H3_STRESS_SECONDS is an integer")
        })
        .unwrap_or(30);
    assert!(
        (5..=600).contains(&seconds),
        "NAWAY_H3_STRESS_SECONDS must be within 5..=600"
    );
    seconds
}

/// 业务作用：等待 per-IP 槽真实归还后建立一条 QUIC 连接，让长压区分暂态 CONNECTION_REFUSED
/// 与连接预算永久泄漏。
///
/// 参数说明：`endpoint` 是复用的客户端 UDP endpoint；`addr` 是网关 QUIC 地址。
///
/// 返回：5 秒内成功握手的连接；持续拒绝表示资源没有恢复并使测试失败。
async fn connect_quic_with_released_slot(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
) -> quinn::Connection {
    for _ in 0..100 {
        let attempt = endpoint
            .connect(addr, "localhost")
            .expect("start QUIC connection after slot release");
        if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_millis(250), attempt).await
        {
            return connection;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("QUIC connection slot did not recover within the stress deadline");
}

/// 业务作用：在同一长寿命 H3 connection 上发送并完整排空一次 GET，证明 UDP source-port
/// 切换和旁路连接耗尽不会把既有业务流静默丢弃或遗留活跃 stream。
///
/// 参数说明：`sender` 是长寿命连接的 stream opener；`sequence` 进入 path 便于定位失败轮次。
///
/// 返回：收到 200 且 DATA/trailers 完整结束时返回；任何协议或状态错误使测试失败。
async fn send_h3_get_on_existing_connection(
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    sequence: u64,
) {
    let request = Request::builder()
        .method("GET")
        .uri(format!("https://localhost/stress/{sequence}"))
        .body(())
        .expect("build long stress H3 request");
    let mut stream = sender
        .send_request(request)
        .await
        .expect("send long stress H3 request headers");
    stream
        .finish()
        .await
        .expect("finish long stress H3 request");
    let response = stream
        .recv_response()
        .await
        .expect("receive long stress H3 response headers");
    assert_eq!(response.status(), StatusCode::OK);
    while stream
        .recv_data()
        .await
        .expect("drain long stress H3 response DATA")
        .is_some()
    {}
    let _ = stream
        .recv_trailers()
        .await
        .expect("drain long stress H3 response trailers");
}

/// 业务作用：读取一条无 label 或固定 label 的 Prometheus 数值，确保长压用的是管理面实际
/// 资源计数而不是测试进程自己的估算。
///
/// 参数说明：`metrics` 是 `/metrics` 文本；`name` 是完整 metric 名及可选固定 label 集。
///
/// 返回：匹配行的整数值；缺失、重复或非整数使测试失败。
fn prometheus_metric(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name} ");
    let mut matches = metrics
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()));
    let value = matches
        .next()
        .unwrap_or_else(|| panic!("metric `{name}` is missing"));
    assert!(matches.next().is_none(), "metric `{name}` is duplicated");
    value
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("metric `{name}` is not an integer: {value}"))
}

/// 通过新建真实 QUIC/H3 connection 发送一次 GET。
///
/// 业务作用：为 listener 换代/回滚测试提供独立新握手探针，避免旧 connection
/// 存活掩盖 UDP endpoint 已停收 Initial 的错误。
///
/// 参数说明：`addr` 是网关 UDP/TLS 地址；`certificate_der` 是唯一信任根；
/// `path` 是本次请求路径。
///
/// 返回：在 deadline 内收到的 H3 状态码；握手或协议失败则使测试失败。
async fn h3_get_status(addr: SocketAddr, certificate_der: Vec<u8>, path: &str) -> StatusCode {
    let endpoint = quic_client_endpoint(certificate_der);
    let quic = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(addr, "localhost")
            .expect("start H3 GET probe handshake"),
    )
    .await
    .expect("H3 GET probe handshake timeout")
    .expect("complete H3 GET probe handshake");
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(quic))
        .await
        .expect("start H3 GET probe client");
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });
    let request = Request::builder()
        .method("GET")
        .uri(format!("https://localhost{path}"))
        .body(())
        .expect("build H3 GET probe request");
    let mut stream = sender
        .send_request(request)
        .await
        .expect("send H3 GET probe headers");
    stream.finish().await.expect("finish H3 GET probe request");
    let status = stream
        .recv_response()
        .await
        .expect("receive H3 GET probe response")
        .status();
    while stream
        .recv_data()
        .await
        .expect("drain H3 GET probe body")
        .is_some()
    {}
    let _ = stream
        .recv_trailers()
        .await
        .expect("drain H3 GET probe trailers");
    drop(sender);
    endpoint.close(quinn::VarInt::from_u32(0), b"GET probe complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), driver_task).await;
    status
}

/// 向测试子进程发送一次 SIGHUP reload。
///
/// 业务作用：走生产同款信号入口，验证唯一 reload worker 的合并与 two-phase 语义。
///
/// 参数说明：`child` 是正在运行的 Naway 子进程。
///
/// 返回：无；系统拒绝发送或子进程无 PID 时使测试失败。
#[cfg(unix)]
fn signal_reload(child: &Child) {
    let pid = child.id().expect("running gateway child has PID") as libc::pid_t;
    // SAFETY: PID 来自当前测试刚创建且尚未 wait 的子进程，仅发送非破坏性 SIGHUP。
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(result, 0, "send SIGHUP to gateway child");
}

/// 启动真实 Quinn/h3 TLS 上游，逐帧回显请求并生成 response trailer。
///
/// 业务作用：为 V9-2 提供独立于 Naway 上游 client 的协议端点，证明 `protocol: h3` 不是把
/// HTTP/1 fixture 换名字，而是真实 QUIC/TLS/H3 wire 互操作。
///
/// 参数说明：`dir` 用于写网关将信任的上游 CA PEM。
///
/// 返回：真实 UDP/QUIC 监听地址；后台 server task 随测试 runtime 结束。
async fn spawn_real_h3_upstream(dir: &Path) -> (SocketAddr, Arc<AtomicU64>) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate H3 upstream certificate");
    let certificate_der = certificate
        .serialize_der()
        .expect("serialize H3 upstream certificate DER");
    std::fs::write(
        dir.join("upstream-ca.pem"),
        certificate
            .serialize_pem()
            .expect("serialize H3 upstream certificate PEM"),
    )
    .expect("write H3 upstream CA");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));
    let mut tls = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate_der)], key)
        .expect("build H3 upstream TLS config");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .expect("build H3 upstream QUIC crypto");
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().expect("H3 upstream bind address"),
    )
    .expect("bind H3 upstream endpoint");
    let addr = endpoint.local_addr().expect("H3 upstream local address");
    let connections = Arc::new(AtomicU64::new(0));
    let connections_for_task = connections.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let connections = connections_for_task.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                connections.fetch_add(1, Ordering::AcqRel);
                let Ok(mut h3) = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                let (goaway, mut goaway_rx) = tokio::sync::mpsc::unbounded_channel();
                loop {
                    let resolver = tokio::select! {
                        accepted = h3.accept() => match accepted {
                            Ok(Some(resolver)) => resolver,
                            Ok(None) | Err(_) => return,
                        },
                        signal = goaway_rx.recv() => {
                            if signal.is_some() {
                                let _ = h3.shutdown(0).await;
                            }
                            return;
                        }
                    };
                    let goaway = goaway.clone();
                    tokio::spawn(async move {
                        let Ok((request, stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let trigger_goaway = request.uri().path() == "/goaway";
                        let (mut send, mut recv) = stream.split();
                        if request.uri().path() == "/stream-large" {
                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .header("x-upstream-transport", "h3")
                                .body(())
                                .expect("build streaming H3 upstream response");
                            if send.send_response(response).await.is_err() {
                                return;
                            }
                            while let Ok(Some(mut data)) = recv.recv_data().await {
                                let length = data.remaining();
                                if send.send_data(data.copy_to_bytes(length)).await.is_err() {
                                    return;
                                }
                            }
                            let saw_finish =
                                recv.recv_trailers()
                                    .await
                                    .ok()
                                    .flatten()
                                    .is_some_and(|trailers| {
                                        trailers
                                            .get("x-large-finish")
                                            .is_some_and(|value| value == "yes")
                                    });
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert(
                                "x-large-finish",
                                http::HeaderValue::from_static(if saw_finish {
                                    "yes"
                                } else {
                                    "no"
                                }),
                            );
                            if send.send_trailers(trailers).await.is_err() {
                                return;
                            }
                            let _ = send.finish().await;
                            return;
                        }
                        let mut body = Vec::new();
                        while let Ok(Some(mut data)) = recv.recv_data().await {
                            let length = data.remaining();
                            body.extend_from_slice(&data.copy_to_bytes(length));
                        }
                        let saw_trailer = recv
                            .recv_trailers()
                            .await
                            .ok()
                            .flatten()
                            .and_then(|trailers| trailers.get("x-h3-request-finish").cloned())
                            .is_some_and(|value| value == "yes");
                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .header("x-upstream-transport", "h3")
                            .header(
                                "x-seen-request-trailer",
                                if saw_trailer { "yes" } else { "no" },
                            )
                            .body(())
                            .expect("build H3 upstream response");
                        if send.send_response(response).await.is_err() {
                            return;
                        }
                        if send.send_data(Bytes::from(body)).await.is_err() {
                            return;
                        }
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert(
                            "x-h3-response-finish",
                            http::HeaderValue::from_static("yes"),
                        );
                        if send.send_trailers(trailers).await.is_err() {
                            return;
                        }
                        let _ = send.finish().await;
                        if trigger_goaway {
                            let _ = goaway.send(());
                        }
                    });
                }
            });
        }
    });
    (addr, connections)
}

/// 启动会读取请求 DATA/trailers 并回显 body 的 HTTP/1 上游。
///
/// 业务作用：作为 H3 适配验收探针，证明请求没有在 QUIC listener 被聚合改写或丢失 trailers。
///
/// 参数说明：无。
///
/// 返回：上游监听地址；后台 task 在测试 runtime 结束时自动取消。
async fn spawn_h3_probe_upstream() -> (
    SocketAddr,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
    Arc<AtomicU64>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/3 probe upstream");
    let addr = listener.local_addr().expect("HTTP/3 probe upstream addr");
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicU64::new(0));
    let started_for_task = started.clone();
    let cancelled_for_task = cancelled.clone();
    let hits_for_task = hits.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept HTTP/3 probe upstream");
            let started = started_for_task.clone();
            let cancelled = cancelled_for_task.clone();
            let hits = hits_for_task.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let started = started.clone();
                    let cancelled = cancelled.clone();
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::AcqRel);
                        let cancellation_probe = request.uri().path() == "/cancel";
                        let mut body = request.into_body();
                        let mut bytes = Vec::new();
                        let mut saw_trailer = false;
                        while let Some(frame) = body.frame().await {
                            let frame = match frame {
                                Ok(frame) => frame,
                                Err(_) if cancellation_probe => break,
                                Err(error) => panic!("read proxied request frame: {error}"),
                            };
                            match frame.into_data() {
                                Ok(data) => {
                                    bytes.extend_from_slice(&data);
                                    if cancellation_probe {
                                        started.notify_one();
                                    }
                                }
                                Err(frame) => {
                                    if let Ok(trailers) = frame.into_trailers() {
                                        saw_trailer = trailers
                                            .get("x-request-finish")
                                            .is_some_and(|value| value == "yes");
                                    }
                                }
                            }
                        }
                        if cancellation_probe {
                            cancelled.notify_one();
                        }
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header(
                                    "x-seen-request-trailer",
                                    if saw_trailer { "yes" } else { "no" },
                                )
                                .body(Full::new(Bytes::from(bytes)))
                                .expect("build HTTP/3 probe response"),
                        )
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, started, cancelled, hits)
}

/// 写入最小 HTTP/3 网关配置及 localhost 自签证书。
///
/// 业务作用：固定测试使用的 TLS/QUIC 身份和资源门，避免依赖开发机现有配置或证书。
///
/// 参数说明：`dir` 是隔离目录；三个 listener 地址分别承载明文、TLS/H3 与管理面；
/// `upstream_addr` 是回显探针地址。
///
/// 返回：客户端根证书需要信任的 DER 字节。
fn write_http3_gateway_config(
    dir: &Path,
    data_addr: SocketAddr,
    tls_addr: SocketAddr,
    admin_addr: SocketAddr,
    upstream_addr: SocketAddr,
) -> Vec<u8> {
    std::fs::create_dir_all(dir.join("tls")).expect("create HTTP/3 test dir");
    let certificate_der = write_http3_identity(dir);
    std::fs::write(
        dir.join("interface-guard.yml"),
        "schema_version: 1\nrules: []\n",
    )
    .expect("write HTTP/3 interface guard");
    std::fs::write(
        dir.join("gateway.yml"),
        format!(
            r#"schema_version: 1
admin:
  listen: "{admin_addr}"
  expose_metrics: true
interface_guard_file: "interface-guard.yml"
proxies:
  - id: main
    listen: "{data_addr}"
    tls:
      listen: "{tls_addr}"
      cert_file: "tls/server.crt"
      key_file: "tls/server.key"
    http3:
      enabled: true
      advertise_alt_svc: true
      retry: always
      max_connections: 32
      max_connections_per_ip: 2
      max_pending_handshakes: 16
      max_pending_handshake_bytes: 16384
      max_bidi_streams_per_connection: 8
      max_request_header_bytes: 8192
      max_stream_buffer_bytes: 65536
    routes:
      - id: h3
        uri: "lb://svc"
        predicates:
          - "Path=/"
upstreams:
  services:
    svc:
      protocol: h2c
      instances:
        - uri: "http://{upstream_addr}"
"#,
        ),
    )
    .expect("write HTTP/3 gateway config");
    certificate_der
}

/// 写入下游 H3→上游 H3 的最小网关配置。
///
/// 业务作用：显式选择 `protocol: h3`、自定义上游 CA 与 SNI，锁定 H3 pool 的 authority/TLS
/// identity 分池入口，同时保留普通 listener 的同端口 TCP+UDP 结构。
///
/// 参数说明：`dir` 是测试根目录；`data_addr`/`tls_addr`/`admin_addr` 是网关 listener；
/// `upstream_addr` 是真实 QUIC 上游地址。
///
/// 返回：下游 H3 client 需要信任的网关证书 DER。
fn write_h3_to_h3_gateway_config(
    dir: &Path,
    data_addr: SocketAddr,
    tls_addr: SocketAddr,
    admin_addr: SocketAddr,
    upstream_addr: SocketAddr,
) -> Vec<u8> {
    std::fs::create_dir_all(dir.join("tls")).expect("create H3-to-H3 gateway TLS dir");
    let certificate_der = write_http3_identity(dir);
    std::fs::write(
        dir.join("interface-guard.yml"),
        "schema_version: 1\nrules: []\n",
    )
    .expect("write H3-to-H3 interface guard");
    std::fs::write(
        dir.join("gateway.yml"),
        format!(
            r#"schema_version: 1
admin:
  listen: "{admin_addr}"
  expose_metrics: true
interface_guard_file: "interface-guard.yml"
proxies:
  - id: main
    listen: "{data_addr}"
    tls:
      listen: "{tls_addr}"
      cert_file: "tls/server.crt"
      key_file: "tls/server.key"
    http3:
      enabled: true
      advertise_alt_svc: true
      retry: always
      max_connections: 32
      max_connections_per_ip: 8
      max_pending_handshakes: 16
      max_pending_handshake_bytes: 16384
      max_bidi_streams_per_connection: 8
      max_stream_buffer_bytes: 65536
    routes:
      - id: h3-to-h3
        uri: "lb://svc"
        predicates:
          - "Path=/"
upstreams:
  services:
    svc:
      protocol: h3
      prewarm:
        connections: 8
        path: /prewarm
        timeout_ms: 2000
      tls:
        server_name: localhost
        ca_file: "upstream-ca.pem"
      instances:
        - uri: "https://{upstream_addr}"
"#,
        ),
    )
    .expect("write H3-to-H3 gateway config");
    certificate_der
}

/// 写入一代新的 localhost TLS 身份并返回证书 DER。
///
/// 业务作用：启动与运行中轮换共用同一材料写入路径，使验收覆盖真实 notify watcher 和
/// QUIC `set_server_config`，而不是直接调用内部发布函数。
///
/// 参数说明：`dir` 是包含 `tls/` 的测试根目录。
///
/// 返回：新证书 DER；对应私钥与 PEM 已替换到网关配置引用的位置。
fn write_http3_identity(dir: &Path) -> Vec<u8> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate HTTP/3 test certificate");
    let certificate_der = certificate
        .serialize_der()
        .expect("serialize HTTP/3 test DER");
    std::fs::write(
        dir.join("tls/server.crt"),
        certificate
            .serialize_pem()
            .expect("serialize HTTP/3 test PEM"),
    )
    .expect("write HTTP/3 certificate");
    std::fs::write(
        dir.join("tls/server.key"),
        certificate.serialize_private_key_pem(),
    )
    .expect("write HTTP/3 private key");
    certificate_der
}

/// 读取当前测试 TLS 证书的 DER，不触发证书轮换。
///
/// 业务作用：listener topology 测试在同一 identity 上只改地址，避免证书 watcher
/// 事件与 SIGHUP 竞速掩盖 TCP/UDP two-phase 结论。
///
/// 参数说明：`dir` 是包含 `tls/server.crt` 的测试配置根目录。
///
/// 返回：当前 PEM 中首张证书的 DER；读取/解析失败使测试失败。
fn read_current_identity_der(dir: &Path) -> Vec<u8> {
    let pem = std::fs::read(dir.join("tls/server.crt")).expect("read current H3 certificate PEM");
    let certificate = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .expect("current H3 certificate exists")
        .expect("parse current H3 certificate");
    certificate.to_vec()
}

/// 创建只信任单代证书的 H3 client endpoint。
///
/// 业务作用：让证书热换验收以真实握手结果区分新旧 identity，避免根仓同时信任两代造成假绿。
///
/// 参数说明：`certificate_der` 是客户端唯一信任的 localhost 根证书。
///
/// 返回：已绑定 loopback UDP 且默认 ALPN 为 `h3` 的 Quinn endpoint。
fn quic_client_endpoint(certificate_der: Vec<u8>) -> quinn::Endpoint {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der))
        .expect("add HTTP/3 test certificate");
    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .expect("build QUIC client TLS config");
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client UDP addr"))
        .expect("bind HTTP/3 client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}

/// 启动带 `http3` feature 的当前 Naway 测试二进制。
///
/// 业务作用：让验收覆盖真实 main listener supervisor，而不是只测试 library 内部适配对象。
///
/// 参数说明：`dir` 必须包含本用例生成的 `gateway.yml`。
///
/// 返回：带 kill-on-drop 的子进程，断言失败也不会遗留 listener。
async fn spawn_gateway(dir: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_naway"))
        .arg("--config")
        .arg(dir.join("gateway.yml"))
        .env("GW_PIDFILE", dir.join("gateway.pid"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn HTTP/3 gateway")
}

/// 等待管理面 readiness，期间同时监控网关是否提前退出。
///
/// 业务作用：确保 QUIC endpoint 已完成 prepare/commit 后才发起握手，避免用固定 sleep 制造竞态。
///
/// 参数说明：`admin_addr` 是管理端口；`child` 用于检测构建或绑定失败。
///
/// 返回：readiness 为 200 时返回；12 秒内未就绪则让测试失败。
async fn wait_for_health(admin_addr: SocketAddr, child: &mut Child) {
    for _ in 0..240 {
        if let Some(status) = child.try_wait().expect("poll HTTP/3 gateway") {
            panic!("HTTP/3 gateway exited before ready: {status}");
        }
        if let Ok(response) = raw_http(admin_addr).await {
            if response.contains("200 OK") {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("HTTP/3 gateway did not become ready");
}

/// 读取指定子进程的当前 RSS。
///
/// 业务作用：采样真实 Naway 子进程而非测试 client/upstream，用于证明大 H3 body
/// 在慢消费者下不会按 payload 线性常驻。
///
/// 参数说明：`pid` 是正在运行的 Naway 子进程 ID。
///
/// 返回：`ps` 报告的 RSS KiB；命令失败或输出非数字时使测试失败。
async fn process_rss_kib(pid: u32) -> u64 {
    let pid = pid.to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", pid.as_str()])
        .output()
        .await
        .expect("run ps for HTTP/3 RSS probe");
    assert!(output.status.success(), "ps failed: {output:?}");
    String::from_utf8(output.stdout)
        .expect("HTTP/3 RSS output is UTF-8")
        .trim()
        .parse()
        .expect("parse HTTP/3 RSS KiB")
}

/// 读取一次管理面 readiness 响应。
///
/// 业务作用：为启动门提供真实 socket 证据，连接失败只表示尚未就绪而不是测试 panic。
///
/// 参数说明：`addr` 是管理面 TCP 地址。
///
/// 返回：成功时返回完整响应文本，连接或读取失败原样返回。
async fn raw_http(addr: SocketAddr) -> std::io::Result<String> {
    raw_admin_get(addr, "/readyz").await
}

/// 业务作用：读取管理面指定 GET 路径，供 readiness 与资源指标共用同一真实 TCP 探针。
///
/// 参数说明：`addr` 是管理面地址；`path` 是以 `/` 开头的固定测试路径。
///
/// 返回：完整 HTTP 响应文本；连接、写入或读取失败原样返回。
async fn raw_admin_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// 通过同端口 TCP/TLS 发起一次 h1 请求并读取完整响应。
///
/// 业务作用：验证 Alt-Svc 只在已提交 QUIC endpoint 对应的 TLS authority 上发布，而不是只在
/// 配置对象里生成但未进入真实响应。
///
/// 参数说明：`addr` 是 TCP TLS 地址；`certificate_der` 是本测试生成的受信任根。
///
/// 返回：完整 HTTP/1 响应文本，供用例断言 Alt-Svc 端口和缓存时间。
async fn tls_h1_response(addr: SocketAddr, certificate_der: Vec<u8>) -> String {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der))
        .expect("add TLS h1 test certificate");
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.expect("connect TLS h1 port");
    let mut tls = connector
        .connect(
            ServerName::try_from("localhost".to_owned()).expect("TLS h1 server name"),
            tcp,
        )
        .await
        .expect("complete TLS h1 handshake");
    tls.write_all(b"GET /h3 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write TLS h1 request");
    let mut response = Vec::new();
    tls.read_to_end(&mut response)
        .await
        .expect("read TLS h1 response");
    String::from_utf8_lossy(&response).into_owned()
}

/// 停止测试网关并回收子进程。
///
/// 业务作用：释放 TCP/UDP 同端口资源，避免污染同进程后续验收。
///
/// 参数说明：`child` 是本用例独占的网关进程。
///
/// 返回：无；kill/wait 失败只影响清理，不覆盖主断言。
async fn stop_gateway(mut child: Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

/// 申请一个当前未使用的 loopback TCP 端口。
///
/// 业务作用：为隔离测试生成 listener 地址；TLS 端口随后同时用于 QUIC UDP。
///
/// 参数说明：无。
///
/// 返回：释放临时探针 socket 后的 loopback 地址。
fn unused_tcp_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind unused HTTP/3 port");
    let addr = listener.local_addr().expect("unused HTTP/3 addr");
    drop(listener);
    addr
}

/// 创建本次验收独占的临时目录路径。
///
/// 业务作用：隔离证书、配置与 pidfile，避免并发测试互相覆盖。
///
/// 参数说明：`name` 是便于失败排查的短标签。
///
/// 返回：带进程 id 与纳秒时间戳的未创建路径。
fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("naway-{name}-{}-{nanos}", std::process::id()))
}
