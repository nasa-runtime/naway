//! 探测连接池随当前目录回收，协议客户端仅在实际需要时构造。

use super::{ActiveHealthPolicy, HealthInstanceTarget, HealthKind, HealthTarget};
use crate::tls::UpstreamTlsProfile;
use crate::upstream::UpstreamProtocol;
use bytes::Bytes;
use http_body_util::{Empty, Full};
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::ServerName;

pub(super) type ProbeHttpClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;
pub(super) type ProbeGrpcClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
const MAX_TLS_CLIENTS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum HttpTransport {
    Auto,
    H1,
    H2,
}

impl HttpTransport {
    /// 业务作用：把实例的 HTTP 协议约束映射为探测连接行为，明文 H2c 必须使用 prior knowledge。
    ///
    /// 参数说明：
    /// - `protocol`：实例实际声明的传输协议。
    ///
    /// 返回：自动协商、仅 H1 或强制 H2；非 HTTP 探针不会使用本映射建立连接。
    fn from_protocol(protocol: UpstreamProtocol) -> Self {
        match protocol {
            UpstreamProtocol::H1 => Self::H1,
            UpstreamProtocol::H2 | UpstreamProtocol::H2c => Self::H2,
            _ => Self::Auto,
        }
    }
}

pub(super) enum ProbeClient {
    Direct,
    Http(ProbeHttpClient),
    Grpc(ProbeGrpcClient),
}

#[derive(Default)]
pub(super) struct ClientSet {
    http: HashMap<HttpTransport, ProbeHttpClient>,
    grpc: Option<ProbeGrpcClient>,
    http_tls: HashMap<(HttpTransport, Arc<str>), ProbeHttpClient>,
    grpc_tls: HashMap<Arc<str>, ProbeGrpcClient>,
}

impl ClientSet {
    /// 业务作用：当前轮次取得目录权后撤销不用的池，旧探测借用可自然结束但不再供新探测复用。
    ///
    /// 参数说明：
    /// - `targets`：当前完整服务及探测目录。
    ///
    /// 返回：仅保留当前协议和 TLS 身份；不预先构建任何客户端。
    pub(super) fn retain(&mut self, targets: &[HealthTarget]) {
        let mut http_tls = HashSet::new();
        let mut grpc_tls = HashSet::new();
        let mut http = HashSet::new();
        let mut grpc = false;
        for target in targets {
            for instance in &target.instances {
                match target.policy.kind {
                    HealthKind::Http if instance.protocol != UpstreamProtocol::H3 => {
                        let transport = HttpTransport::from_protocol(instance.protocol);
                        if let Some(profile) = &instance.tls_profile {
                            http_tls.insert((transport, profile.key.as_ref()));
                        } else {
                            http.insert(transport);
                        }
                    }
                    HealthKind::Grpc => {
                        if let Some(profile) = &instance.tls_profile {
                            grpc_tls.insert(profile.key.as_ref());
                        } else {
                            grpc = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        // 协议或身份已失去当前目录授权时撤下整个池，避免同地址新探针复用旧传输协商结果。
        self.http_tls
            .retain(|(transport, key), _| http_tls.contains(&(*transport, key.as_ref())));
        self.grpc_tls
            .retain(|key, _| grpc_tls.contains(key.as_ref()));
        self.http.retain(|transport, _| http.contains(transport));
        if !grpc {
            self.grpc = None;
        }
    }

    /// 业务作用：按实际网络探针惰性取得独立协议池，直接传输不创建 HTTP 或 gRPC 客户端。
    ///
    /// 参数说明：
    /// - `instance`：当前实例的实际传输协议与已验证 TLS 材料。
    /// - `policy`：决定探测协议的当前策略。
    ///
    /// 返回：对应探针的客户端；HTTP 三种传输共用一个 TLS 容量上限，满额时仅由当前请求持有。
    pub(super) fn for_target(
        &mut self,
        instance: &HealthInstanceTarget,
        policy: &ActiveHealthPolicy,
    ) -> ProbeClient {
        match policy.kind {
            HealthKind::Http if instance.protocol != UpstreamProtocol::H3 => {
                let transport = HttpTransport::from_protocol(instance.protocol);
                let client = match &instance.tls_profile {
                    Some(profile) => {
                        cached_client(&mut self.http_tls, (transport, profile.key.clone()), || {
                            build_probe_http_client(Some(profile), transport)
                        })
                    }
                    None => self
                        .http
                        .entry(transport)
                        .or_insert_with(|| build_probe_http_client(None, transport))
                        .clone(),
                };
                ProbeClient::Http(client)
            }
            HealthKind::Grpc => {
                let client = match &instance.tls_profile {
                    Some(profile) => cached_client(&mut self.grpc_tls, profile.key.clone(), || {
                        build_probe_grpc_client(Some(profile))
                    }),
                    None => self
                        .grpc
                        .get_or_insert_with(|| build_probe_grpc_client(None))
                        .clone(),
                };
                ProbeClient::Grpc(client)
            }
            _ => ProbeClient::Direct,
        }
    }
}

/// 业务作用：在协议独立的缓存中复用实际 TLS 身份，并限制配置轮换或大目录带来的常驻池数量。
///
/// 参数说明：
/// - `cache`：当前协议仍获准保留的客户端。
/// - `key`：固定传输方式与材料身份，不复制证书或密钥。
/// - `build`：当前协议的惰性客户端构造器。
///
/// 返回：已有共享客户端或本次新建客户端；满额不驱逐在用条目，不改变探测结果。
fn cached_client<K: Eq + Hash, C: Clone>(
    cache: &mut HashMap<K, C>,
    key: K,
    build: impl FnOnce() -> C,
) -> C {
    if let Some(client) = cache.get(&key) {
        return client.clone();
    }
    let client = build();
    if cache.len() < MAX_TLS_CLIENTS {
        cache.insert(key, client.clone());
    }
    client
}

/// 业务作用：使用已经验证的 TLS 材料与实例协议建立 connector，禁止显式 H1/H2 约束自动降级。
///
/// 参数说明：
/// - `profile`：实际 TLS 材料；为空时采用内置公共信任根。
/// - `transport`：当前探针获准使用的 HTTP 协议。
///
/// 返回：与数据面协议和服务端身份一致的 connector，不进行网络 I/O。
fn probe_connector(
    profile: Option<&UpstreamTlsProfile>,
    transport: HttpTransport,
) -> HttpsConnector<HttpConnector> {
    let builder = match profile {
        None => hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots(),
        Some(profile) => {
            let mut config = profile.client_config.as_ref().clone();
            config.alpn_protocols.clear();
            hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(config)
        }
    }
    .https_or_http();
    let builder =
        if let Some(server_name) = profile.and_then(|profile| profile.server_name.as_ref()) {
            let name = ServerName::try_from(server_name.as_ref().to_string())
                .expect("validated upstream tls server_name");
            builder.with_server_name_resolver(FixedServerNameResolver::new(name))
        } else {
            builder
        };
    match transport {
        HttpTransport::Auto => builder.enable_http1().enable_http2().build(),
        HttpTransport::H1 => builder.enable_http1().build(),
        HttpTransport::H2 => builder.enable_http2().build(),
    }
}

/// 业务作用：构建普通 HTTP 主动探测池，协议由当前实例决定，明文 H2c 不回退到 H1。
///
/// 参数说明：
/// - `profile`：实际 TLS 身份；None 使用内置公共根证书。
/// - `transport`：自动协商、显式 H1 或强制 H2。
///
/// 返回：保留一个空闲连接且空闲期有界的共享客户端，H2/H2c 使用 prior knowledge。
fn build_probe_http_client(
    profile: Option<&UpstreamTlsProfile>,
    transport: HttpTransport,
) -> ProbeHttpClient {
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .http2_only(transport == HttpTransport::H2)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30));
    builder.build(probe_connector(profile, transport))
}

/// 业务作用：构建标准 gRPC Health 专用池，强制 h2/h2c，禁止健康请求退化到 HTTP/1.1。
///
/// 参数说明：
/// - `profile`：gRPC 上游 TLS 身份；None 使用内置公共根证书或明文 h2c。
///
/// 返回：请求 body 为有界 protobuf frame、transport 强制 HTTP/2 的共享客户端。
pub(super) fn build_probe_grpc_client(profile: Option<&UpstreamTlsProfile>) -> ProbeGrpcClient {
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .http2_only(true)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30));
    builder.build(probe_connector(profile, HttpTransport::H2))
}
