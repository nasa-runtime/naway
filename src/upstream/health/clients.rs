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
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::ServerName;

pub(super) type ProbeHttpClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;
pub(super) type ProbeGrpcClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
const MAX_TLS_CLIENTS: usize = 64;

pub(super) enum ProbeClient {
    Direct,
    Http(ProbeHttpClient),
    Grpc(ProbeGrpcClient),
}

#[derive(Default)]
pub(super) struct ClientSet {
    http: Option<ProbeHttpClient>,
    grpc: Option<ProbeGrpcClient>,
    http_tls: HashMap<Arc<str>, ProbeHttpClient>,
    grpc_tls: HashMap<Arc<str>, ProbeGrpcClient>,
}

impl ClientSet {
    /// 业务作用：当前轮次取得目录权后撤销不用的池，旧探测借用可自然结束但不再供新探测复用。
    ///
    /// 参数说明：
    /// - `targets`：当前完整服务及探测目录。
    ///
    /// 返回：仅保留当前类型和 TLS 身份；不预先构建任何客户端。
    pub(super) fn retain(&mut self, targets: &[HealthTarget]) {
        let mut http_tls = HashSet::new();
        let mut grpc_tls = HashSet::new();
        let mut http = false;
        let mut grpc = false;
        for target in targets {
            for instance in &target.instances {
                let (default, profiles) = match target.policy.kind {
                    HealthKind::Http if instance.protocol != UpstreamProtocol::H3 => {
                        (&mut http, &mut http_tls)
                    }
                    HealthKind::Grpc => (&mut grpc, &mut grpc_tls),
                    _ => continue,
                };
                if let Some(profile) = &instance.tls_profile {
                    profiles.insert(profile.key.as_ref());
                } else {
                    *default = true;
                }
            }
        }
        // 旧配置不再有复用授权；删除缓存只释放本层持有，不截断已发起请求的借用。
        self.http_tls
            .retain(|key, _| http_tls.contains(key.as_ref()));
        self.grpc_tls
            .retain(|key, _| grpc_tls.contains(key.as_ref()));
        if !http {
            self.http = None;
        }
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
    /// 返回：对应探针的客户端；TLS 缓存满额时仅由当前请求持有，不将本地容量当成上游失败。
    pub(super) fn for_target(
        &mut self,
        instance: &HealthInstanceTarget,
        policy: &ActiveHealthPolicy,
    ) -> ProbeClient {
        match policy.kind {
            HealthKind::Http if instance.protocol != UpstreamProtocol::H3 => {
                let client = match &instance.tls_profile {
                    Some(profile) => {
                        cached_client(&mut self.http_tls, profile, build_probe_http_client)
                    }
                    None => self
                        .http
                        .get_or_insert_with(|| build_probe_http_client(None))
                        .clone(),
                };
                ProbeClient::Http(client)
            }
            HealthKind::Grpc => {
                let client = match &instance.tls_profile {
                    Some(profile) => {
                        cached_client(&mut self.grpc_tls, profile, build_probe_grpc_client)
                    }
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
/// - `profile`：已解析的实际证书、信任根和服务端身份。
/// - `build`：当前协议的客户端构造器。
///
/// 返回：已有共享客户端或本次新建客户端；满额不驱逐在用条目，不改变探测结果。
fn cached_client<C: Clone>(
    cache: &mut HashMap<Arc<str>, C>,
    profile: &UpstreamTlsProfile,
    build: fn(Option<&UpstreamTlsProfile>) -> C,
) -> C {
    if let Some(client) = cache.get(&profile.key) {
        return client.clone();
    }
    let client = build(Some(profile));
    if cache.len() < MAX_TLS_CLIENTS {
        cache.insert(profile.key.clone(), client.clone());
    }
    client
}

/// 业务作用：构建普通 HTTP 主动探测 client，并复用配置构建期已解析好的 TLS 材料，
/// 使 H1/H2 HTTP 健康路径与业务证书身份一致。
///
/// 参数说明：
/// - `profile`：是 HTTP 上游 TLS profile；None 使用内置公共根证书。
///
/// 返回：可按 scheme/ALPN 使用 H1 或 H2 的 Hyper client。
pub(super) fn build_probe_http_client(profile: Option<&UpstreamTlsProfile>) -> ProbeHttpClient {
    let connector = match profile {
        None => hyper_rustls::HttpsConnectorBuilder::new()
            // 使用内置公共信任根，让未开放系统钥匙串的运行环境仍可构建探测客户端。
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build(),
        Some(profile) => {
            let mut config = profile.client_config.as_ref().clone();
            config.alpn_protocols.clear();
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http();
            let builder = if let Some(server_name) = &profile.server_name {
                let name = ServerName::try_from(server_name.as_ref().to_string())
                    .expect("validated upstream tls server_name");
                builder.with_server_name_resolver(FixedServerNameResolver::new(name))
            } else {
                builder
            };
            builder.enable_http1().enable_http2().build()
        }
    };
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30))
        .build(connector)
}

/// 业务作用：构建标准 gRPC Health 专用 client，强制 h2/h2c prior knowledge，禁止健康
/// 请求因连接池协商或明文 scheme 静默退化到 HTTP/1.1。
///
/// 参数说明：
/// - `profile`：是 gRPC 上游 TLS profile；None 使用内置公共根证书或明文 h2c。
///
/// 返回：请求 body 为有界 protobuf frame、transport 强制 HTTP/2 的 Hyper client。
pub(super) fn build_probe_grpc_client(profile: Option<&UpstreamTlsProfile>) -> ProbeGrpcClient {
    let connector = match profile {
        None => hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http2()
            .build(),
        Some(profile) => {
            let mut config = profile.client_config.as_ref().clone();
            config.alpn_protocols.clear();
            let builder = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http();
            let builder = if let Some(server_name) = &profile.server_name {
                let name = ServerName::try_from(server_name.as_ref().to_string())
                    .expect("validated upstream tls server_name");
                builder.with_server_name_resolver(FixedServerNameResolver::new(name))
            } else {
                builder
            };
            builder.enable_http2().build()
        }
    };
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .http2_only(true)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(30));
    builder.build(connector)
}
