#![cfg(feature = "http3")]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

/// curl/quiche 与 Envoy 必须分别通过真实 QUIC 访问 Naway，不能把仓内 Quinn client
/// 同时当作服务端正确性和外部互操作证据。
#[tokio::test]
#[ignore = "requires Docker, curl-http3 image and Envoy image"]
async fn curl_and_envoy_interoperate_with_naway_http3() {
    let dir = live_temp_dir("curl-envoy");
    let upstream_addr = spawn_live_upstream().await;
    let data_addr = unused_tcp_addr();
    let tls_addr = unused_tcp_addr();
    let admin_addr = unused_tcp_addr();
    write_live_gateway_config(&dir, data_addr, tls_addr, admin_addr, upstream_addr);
    let mut gateway = spawn_live_gateway(&dir).await;
    wait_for_http_status(admin_addr, "/readyz", "200 OK", &mut gateway).await;

    let curl_output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host",
            "host.docker.internal:host-gateway",
            "ghcr.io/macbre/curl-http3:latest",
            "curl",
            "--http3-only",
            "--insecure",
            "--silent",
            "--show-error",
            "--write-out",
            "\n%{http_version}\n",
            &format!("https://host.docker.internal:{}/live", tls_addr.port()),
        ])
        .output()
        .await
        .expect("run independent curl HTTP/3 client");
    assert!(
        curl_output.status.success(),
        "curl HTTP/3 failed: {}",
        String::from_utf8_lossy(&curl_output.stderr)
    );
    let curl_stdout = String::from_utf8_lossy(&curl_output.stdout);
    assert!(curl_stdout.contains("live-h3-ok"), "{curl_stdout}");
    assert!(
        curl_stdout.lines().any(|line| line.trim() == "3"),
        "curl did not report HTTP/3: {curl_stdout}"
    );

    let envoy_port = unused_tcp_addr().port();
    let envoy_admin_port = unused_tcp_addr().port();
    write_envoy_h3_client_config(&dir, tls_addr.port());
    validate_envoy_config(&dir).await;
    let container_name = format!("naway-h3-live-{}", std::process::id());
    let envoy = start_envoy_h3_client(&dir, &container_name, envoy_port, envoy_admin_port).await;

    let envoy_addr = SocketAddr::from(([127, 0, 0, 1], envoy_port));
    let mut response = None;
    for _ in 0..200 {
        if let Ok(value) = raw_http(envoy_addr, "/live").await {
            if value.contains("200 OK") && value.contains("live-h3-ok") {
                response = Some(value);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        response.is_some(),
        "Envoy did not proxy over upstream HTTP/3"
    );

    let stats_addr = SocketAddr::from(([127, 0, 0, 1], envoy_admin_port));
    let stats = raw_http(stats_addr, "/stats?filter=upstream_cx_http3_total")
        .await
        .expect("read Envoy HTTP/3 stats");
    assert!(
        stats.lines().any(|line| {
            line.contains("cluster.naway_h3.upstream_cx_http3_total")
                && !line.trim_end().ends_with(": 0")
        }),
        "Envoy response was not backed by an HTTP/3 connection: {stats}"
    );

    stop_container(&container_name).await;
    drop(envoy);
    gateway.start_kill().expect("stop live HTTP/3 gateway");
}

/// 业务作用：为 live 矩阵提供最小 HTTP/1 上游，使外部 H3 客户端必须穿过 Naway
/// 完整路由与上游转发，而不是命中测试内直接响应。
///
/// 参数说明: 无。
///
/// 返回：已监听的 loopback 地址；后台任务随测试 runtime 结束。
async fn spawn_live_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind live upstream");
    let addr = listener.local_addr().expect("read live upstream address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let body = b"live-h3-ok";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    addr
}

/// 业务作用：生成外部互操作专用的 Naway 配置与 TLS 身份，固定 HTTP/3 资源门并隔离
/// 开发机现有 listener、证书和上游。
///
/// 参数说明：`dir` 是测试目录；`data_addr`、`tls_addr`、`admin_addr` 是三类 listener；
/// `upstream_addr` 是真实 HTTP/1 回显上游。
///
/// 返回：文件全部原子写入成功后返回；失败使测试立即终止。
fn write_live_gateway_config(
    dir: &Path,
    data_addr: SocketAddr,
    tls_addr: SocketAddr,
    admin_addr: SocketAddr,
    upstream_addr: SocketAddr,
) {
    std::fs::create_dir_all(dir.join("tls")).expect("create live HTTP/3 TLS directory");
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate live HTTP/3 certificate");
    std::fs::write(
        dir.join("tls/server.crt"),
        certificate
            .serialize_pem()
            .expect("serialize live certificate"),
    )
    .expect("write live certificate");
    std::fs::write(
        dir.join("tls/server.key"),
        certificate.serialize_private_key_pem(),
    )
    .expect("write live private key");
    std::fs::write(
        dir.join("interface-guard.yml"),
        "schema_version: 1\nrules: []\n",
    )
    .expect("write live interface guard");
    std::fs::write(
        dir.join("gateway.yml"),
        format!(
            r#"schema_version: 1
admin:
  listen: "{admin_addr}"
  expose_metrics: true
interface_guard_file: "interface-guard.yml"
proxies:
  - id: live
    listen: "{data_addr}"
    tls:
      listen: "{tls_addr}"
      cert_file: "tls/server.crt"
      key_file: "tls/server.key"
    http3:
      enabled: true
      advertise_alt_svc: true
      retry: always
      max_connections: 256
      max_connections_per_ip: 64
      max_pending_handshakes: 64
      max_pending_handshake_bytes: 16384
      max_bidi_streams_per_connection: 128
      max_stream_buffer_bytes: 65536
    routes:
      - id: live
        uri: "lb://live"
        predicates: ["Path=/"]
upstreams:
  services:
    live:
      protocol: h1
      instances:
        - uri: "http://{upstream_addr}"
"#,
        ),
    )
    .expect("write live HTTP/3 gateway config");
}

/// 业务作用：生成 Envoy 作为独立 HTTP/3 client 的固定配置；客户端先以 HTTP/1 进入
/// Envoy，只有 Envoy→Naway 一跳使用 QUIC，因此 stats 能独立证明互操作协议。
///
/// 参数说明：`dir` 包含 Naway 自签证书；`naway_port` 是宿主 UDP/TLS 端口。
///
/// 返回：Envoy YAML 写入成功后返回。
fn write_envoy_h3_client_config(dir: &Path, naway_port: u16) {
    std::fs::write(
        dir.join("envoy-h3-client.yaml"),
        format!(
            r#"admin:
  address:
    socket_address: {{ address: 0.0.0.0, port_value: 9901 }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 10000 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                route_config:
                  name: live
                  virtual_hosts:
                    - name: live
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: naway_h3 }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: naway_h3
      connect_timeout: 3s
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      load_assignment:
        cluster_name: naway_h3
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: host.docker.internal
                      port_value: {naway_port}
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http3_protocol_options: {{}}
      transport_socket:
        name: envoy.transport_sockets.quic
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicUpstreamTransport
          upstream_tls_context:
            sni: localhost
            common_tls_context:
              alpn_protocols: ["h3"]
              validation_context:
                trusted_ca:
                  filename: /work/tls/server.crt
"#,
        ),
    )
    .expect("write Envoy HTTP/3 client config");
}

/// 业务作用：在启动 live container 前让 Envoy 自身解析配置，避免把 YAML/type URL 错误
/// 误判为 Naway 的 HTTP/3 互操作失败。
///
/// 参数说明：`dir` 是映射为 container `/work` 的测试目录。
///
/// 返回：Envoy validate 成功时返回；失败时携带 stderr 终止测试。
async fn validate_envoy_config(dir: &Path) {
    let mount = format!("{}:/work:ro", dir.display());
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            "envoyproxy/envoy:v1.35.3",
            "envoy",
            "--mode",
            "validate",
            "-c",
            "/work/envoy-h3-client.yaml",
        ])
        .output()
        .await
        .expect("validate Envoy HTTP/3 config");
    assert!(
        output.status.success(),
        "Envoy HTTP/3 config invalid: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// 业务作用：启动固定版本 Envoy，使它把宿主 HTTP/1 请求转成到 Naway 的 HTTP/3；容器
/// 名称和端口均由当前测试隔离，避免误停用户已有容器。
///
/// 参数说明：`dir` 是只读配置目录；`name` 是本测试唯一容器名；两个 host port 分别发布
/// Envoy data/admin listener。
///
/// 返回：已成功启动的 container guard；后续 readiness 仍由请求循环验证。
async fn start_envoy_h3_client(
    dir: &Path,
    name: &str,
    data_port: u16,
    admin_port: u16,
) -> LiveContainer {
    let mount = format!("{}:/work:ro", dir.display());
    let data_publish = format!("127.0.0.1:{data_port}:10000/tcp");
    let admin_publish = format!("127.0.0.1:{admin_port}:9901/tcp");
    let output = Command::new("docker")
        .args([
            "run",
            "--detach",
            "--rm",
            "--name",
            name,
            "--add-host",
            "host.docker.internal:host-gateway",
            "-v",
            &mount,
            "-p",
            &data_publish,
            "-p",
            &admin_publish,
            "envoyproxy/envoy:v1.35.3",
            "envoy",
            "-c",
            "/work/envoy-h3-client.yaml",
            "--concurrency",
            "1",
            "--log-level",
            "warning",
        ])
        .output()
        .await
        .expect("start Envoy HTTP/3 client container");
    assert!(
        output.status.success(),
        "start Envoy failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    LiveContainer {
        name: name.to_owned(),
    }
}

/// 业务作用：显式停止本测试创建的单个 Envoy 容器，让 `--rm` 回收端口和挂载引用。
///
/// 参数说明：`name` 必须是当前测试按进程 ID 生成的精确名称。
///
/// 返回：容器停止或已经退出均视为完成。
async fn stop_container(name: &str) {
    let _ = Command::new("docker").args(["stop", name]).output().await;
}

/// 业务作用：测试 panic 时也只清理按精确名称创建的 live 容器，避免残留 UDP/TCP 端口。
struct LiveContainer {
    name: String,
}

impl Drop for LiveContainer {
    /// 业务作用：为异常退出提供最后一道定向清理，不使用通配符或触碰其他容器。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：Drop 不传播 Docker 错误；正常路径已经异步停止容器。
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["stop", self.name.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// 业务作用：启动带 `http3` feature 的当前测试二进制，覆盖真实 main/supervisor/listener
/// 发布路径而不是 library 内对象。
///
/// 参数说明：`dir` 必须包含 live `gateway.yml`。
///
/// 返回：kill-on-drop 子进程，测试退出不会留下 Naway listener。
async fn spawn_live_gateway(dir: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_naway"))
        .arg("--config")
        .arg(dir.join("gateway.yml"))
        .env("GW_PIDFILE", dir.join("gateway.pid"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn live HTTP/3 gateway")
}

/// 业务作用：用真实管理 socket 等待 Naway 候选完成 TCP+UDP 原子提交，同时监控子进程
/// 是否提前失败，消除固定 sleep 的启动竞态。
///
/// 参数说明：`addr`/`path`/`status` 是期望管理响应；`child` 用于检测异常退出。
///
/// 返回：12 秒内看到目标状态即返回，否则使测试失败。
async fn wait_for_http_status(addr: SocketAddr, path: &str, status: &str, child: &mut Child) {
    for _ in 0..240 {
        if let Some(exit) = child.try_wait().expect("poll live gateway") {
            panic!("live HTTP/3 gateway exited before ready: {exit}");
        }
        if raw_http(addr, path)
            .await
            .is_ok_and(|response| response.contains(status))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("live HTTP/3 gateway did not become ready");
}

/// 业务作用：读取一次简单 HTTP/1 管理或 Envoy 响应，避免 live test 依赖宿主 curl 的
/// HTTP/3 编译选项。
///
/// 参数说明：`addr` 是目标 TCP 地址；`path` 是 origin-form 请求路径。
///
/// 返回：连接成功时返回完整响应；连接/read 错误原样返回供 readiness 重试。
async fn raw_http(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: live\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// 业务作用：通过 bind(0) 让操作系统选择当前可用 loopback TCP 端口，降低并行测试冲突。
///
/// 参数说明: 无。
///
/// 返回：释放临时 socket 后的候选地址；真正 bind 仍由被测进程完成。
fn unused_tcp_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral live port");
    listener.local_addr().expect("read ephemeral live port")
}

/// 业务作用：为每次外部 live run 创建唯一文件命名空间，隔离证书、PID 和 Envoy 配置。
///
/// 参数说明：`name` 是便于诊断的场景名，不参与安全决策。
///
/// 返回：位于系统临时目录、包含进程 ID 与纳秒时间戳的唯一目录。
fn live_temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("live test clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "naway-http3-live-{name}-{}-{nanos}",
        std::process::id()
    ))
}
