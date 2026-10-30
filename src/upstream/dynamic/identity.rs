//! 发现绑定在配置构建期冻结，数据面只比较固定身份，不解析来源或重新散列策略。

use crate::config::model::{DiscoveryCfg, NacosDiscoveryCfg};
use crate::tls::UpstreamTlsProfile;
use crate::upstream::{ServiceSnapshot, ServiceSource, UpstreamProtocol, XdsWatchSpec};
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BindingIdentity {
    pub(super) xds: bool,
    digest: [u8; 32],
}

impl BindingIdentity {
    /// 业务作用：冻结当前逻辑服务实际授权的实例来源与转换策略，防止新配置采纳旧绑定目录。
    ///
    /// 参数说明：
    /// - `name`：当前逻辑服务身份。
    /// - `service`：已解析协议、TLS 和来源映射的服务计划。
    /// - `discovery`：已解析凭据和传输配置的注册中心计划。
    ///
    /// 返回：动态来源的固定身份；静态服务不从动态目录读取，返回空。
    pub(crate) fn service(
        name: &str,
        service: &ServiceSnapshot,
        discovery: &DiscoveryCfg,
    ) -> Option<Self> {
        let ServiceSnapshot {
            source,
            protocol,
            tls_profile,
            nacos_service,
            registry_service,
            registry_service_import,
            registry_namespace,
            registry_port,
            registry_port_name,
            scheme,
            clusters,
            slow_start_ms,
            discovery_stale_ttl_ms,
            discovery_identity: _,
            // 这些字段治理已选实例，不改变实例来源或转换，因此不撤销合法发现事实。
            critical: _,
            lb_policy: _,
            hash: _,
            session_affinity: _,
            load_feedback: _,
            retry_budget: _,
            adaptive_concurrency: _,
            next_upstream: _,
            passive_health: _,
            outlier: _,
            active_health: _,
            prewarm: _,
            locality: _,
            instances: _,
        } = service;
        if *source == ServiceSource::Static {
            return None;
        }
        if *source == ServiceSource::Xds {
            return Some(Self::xds_fields(
                name,
                registry_service,
                *protocol,
                scheme,
                *slow_start_ms,
                0,
                tls_profile,
            ));
        }
        let mut sink = HashSink::new();
        (
            name,
            source,
            protocol,
            tls_profile,
            tls_profile
                .as_ref()
                .and_then(|tls| tls.client_identity_policy_identity),
            scheme,
            slow_start_ms,
            discovery_stale_ttl_ms,
        )
            .hash(&mut sink);
        match source {
            ServiceSource::Nacos => {
                (nacos_service, clusters).hash(&mut sink);
                hash_nacos(&discovery.nacos, &mut sink);
            }
            ServiceSource::Consul
            | ServiceSource::Eureka
            | ServiceSource::Dns
            | ServiceSource::Kubernetes => {
                (
                    registry_service,
                    registry_service_import,
                    registry_namespace,
                    registry_port,
                    registry_port_name,
                )
                    .hash(&mut sink);
                match source {
                    ServiceSource::Consul => discovery.consul.hash(&mut sink),
                    ServiceSource::Eureka => discovery.eureka.hash(&mut sink),
                    ServiceSource::Dns => discovery.dns.hash(&mut sink),
                    ServiceSource::Kubernetes => discovery.kubernetes.hash(&mut sink),
                    _ => unreachable!("native polling source was matched"),
                }
            }
            ServiceSource::Static | ServiceSource::Xds => {
                unreachable!("non-native source returned")
            }
        }
        Some(Self {
            xds: false,
            digest: sink.0.finalize().into(),
        })
    }

    /// 业务作用：让 EDS 发布者使用与当前服务相同的映射身份，协议或实例转换变化不能继承旧数据。
    ///
    /// 参数说明：
    /// - `spec`：本代已冻结的单服务 EDS 映射。
    ///
    /// 返回：只在控制面计算的身份，不携带资源版本、nonce 或观测时间。
    pub(crate) fn xds(spec: &XdsWatchSpec) -> Self {
        let XdsWatchSpec {
            logical_service,
            cluster_name,
            protocol,
            connect_timeout_ms,
            scheme,
            slow_start_ms,
            tls_profile,
        } = spec;
        Self::xds_fields(
            logical_service,
            cluster_name,
            *protocol,
            scheme,
            *slow_start_ms,
            *connect_timeout_ms,
            tls_profile,
        )
    }

    /// 业务作用：统一配置侧与 EDS 侧的字段编码，避免两个入口产生不一致的绑定判据。
    ///
    /// 参数说明：
    /// - `logical`：逻辑服务名。
    /// - `physical`：EDS cluster 名。
    /// - `protocol`：实例实际传输协议。
    /// - `scheme`：实例 URI 的固定 scheme。
    /// - `slow_start`：新实例的启动权重周期。
    /// - `connect_timeout`：实例连接时限。
    /// - `tls`：已解析的实际 TLS 身份。
    ///
    /// 返回：不依赖文件路径、时间或任务调度次序的进程内固定身份。
    fn xds_fields(
        logical: &str,
        physical: &str,
        protocol: UpstreamProtocol,
        scheme: &str,
        slow_start: u64,
        connect_timeout: u64,
        tls: &Option<UpstreamTlsProfile>,
    ) -> Self {
        let mut sink = HashSink::new();
        (
            logical,
            physical,
            protocol,
            scheme,
            slow_start,
            connect_timeout,
            tls,
            tls.as_ref()
                .and_then(|tls| tls.client_identity_policy_identity),
        )
            .hash(&mut sink);
        Self {
            xds: true,
            digest: sink.0.finalize().into(),
        }
    }
}

/// 业务作用：借用 Nacos 订阅配置写入身份，不复制密码，并排除独立自注册任务的配置。
///
/// 参数说明：
/// - `cfg`：已完成加载的 Nacos 配置。
/// - `sink`：本服务的构建期散列器。
///
/// 返回：无；影响订阅与实例有效期的所有字段进入同一固定身份。
fn hash_nacos(cfg: &NacosDiscoveryCfg, sink: &mut HashSink) {
    let NacosDiscoveryCfg {
        enabled,
        server_addr,
        namespace,
        group,
        app_name,
        discovery_ip,
        self_register: _,
        username,
        password,
        poll_interval_ms,
        stale_ttl_ms,
        reconnect_backoff_ms,
    } = cfg;
    (
        enabled,
        server_addr,
        namespace,
        group,
        app_name,
        discovery_ip,
        username,
        password,
        poll_interval_ms,
        stale_ttl_ms,
        reconnect_backoff_ms,
    )
        .hash(sink);
}

struct HashSink(Sha256);

impl HashSink {
    /// 业务作用：为发现绑定开启独立散列域，不生成中间序列化文档。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅供当前进程配置与发布者比较的散列器，不作为持久或线上协议格式。
    fn new() -> Self {
        Self(Sha256::new_with_prefix(b"naway-discovery-binding\0"))
    }
}

impl Hasher for HashSink {
    /// 业务作用：满足标准 Hash 输入接口，完整绑定身份仍使用全部 SHA-256 输出。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：当前散列的前八字节，不改变正在构建的完整身份。
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        u64::from_be_bytes(
            digest[..8]
                .try_into()
                .expect("SHA-256 contains eight bytes"),
        )
    }

    /// 业务作用：直接消费标准 Hash 的带类型结构输入，避免字段值复制或文档编码。
    ///
    /// 参数说明：
    /// - `bytes`：被借用字段提供的当前输入片段。
    ///
    /// 返回：无；原地推进本次构建期 SHA-256。
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}
