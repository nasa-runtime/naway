//! 仅包含管理端实际发布和接收的 Envoy v3 消息字段；不携带任意扩展配置。

use prost::Message;
use prost_types::{Any, Duration};
use std::collections::BTreeMap;

pub(crate) const LDS: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
pub(crate) const RDS: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub(crate) const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub(crate) const EDS: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
pub(crate) const SDS: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
pub(crate) const WRAPPED: &str = "type.googleapis.com/envoy.service.discovery.v3.Resource";
pub(crate) const TYPES: [&str; 5] = [CDS, EDS, SDS, LDS, RDS];

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DiscoveryRequest {
    #[prost(string, tag = "1")]
    pub version_info: String,
    #[prost(message, optional, tag = "2")]
    pub node: Option<Node>,
    #[prost(string, repeated, tag = "3")]
    pub resource_names: Vec<String>,
    #[prost(string, tag = "4")]
    pub type_url: String,
    #[prost(string, tag = "5")]
    pub response_nonce: String,
    #[prost(message, optional, tag = "6")]
    pub error_detail: Option<RpcStatus>,
    #[prost(message, repeated, tag = "7")]
    pub resource_locators: Vec<Empty>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DiscoveryResponse {
    #[prost(string, tag = "1")]
    pub version_info: String,
    #[prost(message, repeated, tag = "2")]
    pub resources: Vec<Any>,
    #[prost(string, tag = "4")]
    pub type_url: String,
    #[prost(string, tag = "5")]
    pub nonce: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DeltaRequest {
    #[prost(message, optional, tag = "1")]
    pub node: Option<Node>,
    #[prost(string, tag = "2")]
    pub type_url: String,
    #[prost(string, repeated, tag = "3")]
    pub resource_names_subscribe: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub resource_names_unsubscribe: Vec<String>,
    #[prost(btree_map = "string, string", tag = "5")]
    pub initial_resource_versions: BTreeMap<String, String>,
    #[prost(string, tag = "6")]
    pub response_nonce: String,
    #[prost(message, optional, tag = "7")]
    pub error_detail: Option<RpcStatus>,
    #[prost(message, repeated, tag = "8")]
    pub resource_locators_subscribe: Vec<Empty>,
    #[prost(message, repeated, tag = "9")]
    pub resource_locators_unsubscribe: Vec<Empty>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DeltaResponse {
    #[prost(string, tag = "1")]
    pub system_version_info: String,
    #[prost(message, repeated, tag = "2")]
    pub resources: Vec<Resource>,
    #[prost(string, tag = "4")]
    pub type_url: String,
    #[prost(string, tag = "5")]
    pub nonce: String,
    #[prost(string, repeated, tag = "6")]
    pub removed_resources: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Resource {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(message, optional, tag = "2")]
    pub resource: Option<Any>,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(message, optional, tag = "6")]
    pub ttl: Option<Duration>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Node {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, repeated, tag = "10")]
    pub client_features: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RpcStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Empty {}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ConfigSource {
    #[prost(message, optional, tag = "3")]
    pub ads: Option<Empty>,
    #[prost(int32, tag = "6")]
    pub resource_api_version: i32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Address {
    #[prost(message, optional, tag = "1")]
    pub socket_address: Option<SocketAddress>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SocketAddress {
    #[prost(string, tag = "2")]
    pub address: String,
    #[prost(uint32, tag = "3")]
    pub port_value: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Listener {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "2")]
    pub address: Option<Address>,
    #[prost(message, repeated, tag = "3")]
    pub filter_chains: Vec<FilterChain>,
    #[prost(message, optional, tag = "4")]
    pub per_connection_buffer_limit_bytes: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct FilterChain {
    #[prost(message, repeated, tag = "3")]
    pub filters: Vec<NetworkFilter>,
    #[prost(message, optional, tag = "6")]
    pub transport_socket: Option<TransportSocket>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct NetworkFilter {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "4")]
    pub typed_config: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct HttpConnectionManager {
    #[prost(string, tag = "2")]
    pub stat_prefix: String,
    #[prost(message, optional, tag = "3")]
    pub rds: Option<Rds>,
    #[prost(message, repeated, tag = "5")]
    pub http_filters: Vec<NetworkFilter>,
    #[prost(message, optional, tag = "14")]
    pub use_remote_address: Option<bool>,
    #[prost(message, optional, tag = "25")]
    pub internal_address_config: Option<Empty>,
    #[prost(message, optional, tag = "29")]
    pub max_request_headers_kb: Option<u32>,
    #[prost(message, optional, tag = "30")]
    pub normalize_path: Option<bool>,
    #[prost(message, optional, tag = "24")]
    pub stream_idle_timeout: Option<Duration>,
    #[prost(bool, tag = "33")]
    pub merge_slashes: bool,
    #[prost(int32, tag = "45")]
    pub path_with_escaped_slashes_action: i32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Rds {
    #[prost(message, optional, tag = "1")]
    pub config_source: Option<ConfigSource>,
    #[prost(string, tag = "2")]
    pub route_config_name: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RouteConfiguration {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, repeated, tag = "2")]
    pub virtual_hosts: Vec<VirtualHost>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct VirtualHost {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, repeated, tag = "2")]
    pub domains: Vec<String>,
    #[prost(message, repeated, tag = "3")]
    pub routes: Vec<Route>,
    #[prost(string, repeated, tag = "13")]
    pub request_headers_to_remove: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Route {
    #[prost(message, optional, tag = "1")]
    pub r#match: Option<RouteMatch>,
    #[prost(message, optional, tag = "2")]
    pub route: Option<RouteAction>,
    #[prost(string, tag = "14")]
    pub name: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RouteMatch {
    #[prost(oneof = "PathMatch", tags = "1, 2")]
    pub path: Option<PathMatch>,
    #[prost(message, optional, tag = "4")]
    pub case_sensitive: Option<bool>,
    #[prost(message, repeated, tag = "6")]
    pub headers: Vec<HeaderMatcher>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(crate) enum PathMatch {
    #[prost(string, tag = "1")]
    Prefix(String),
    #[prost(string, tag = "2")]
    Exact(String),
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct HeaderMatcher {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "4")]
    pub exact_match: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RouteAction {
    #[prost(string, tag = "1")]
    pub cluster: String,
    #[prost(string, tag = "6")]
    pub host_rewrite_literal: String,
    #[prost(message, optional, tag = "8")]
    pub timeout: Option<Duration>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Cluster {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int32, tag = "2")]
    pub discovery_type: i32,
    #[prost(message, optional, tag = "3")]
    pub eds_cluster_config: Option<EdsConfig>,
    #[prost(message, optional, tag = "4")]
    pub connect_timeout: Option<Duration>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EdsConfig {
    #[prost(message, optional, tag = "1")]
    pub eds_config: Option<ConfigSource>,
    #[prost(string, tag = "2")]
    pub service_name: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Assignment {
    #[prost(string, tag = "1")]
    pub cluster_name: String,
    #[prost(message, repeated, tag = "2")]
    pub endpoints: Vec<LocalityEndpoints>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct LocalityEndpoints {
    #[prost(message, repeated, tag = "2")]
    pub lb_endpoints: Vec<LbEndpoint>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct LbEndpoint {
    #[prost(message, optional, tag = "1")]
    pub endpoint: Option<Endpoint>,
    #[prost(int32, tag = "2")]
    pub health_status: i32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Endpoint {
    #[prost(message, optional, tag = "1")]
    pub address: Option<Address>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TransportSocket {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "3")]
    pub typed_config: Option<Any>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DownstreamTlsContext {
    #[prost(message, optional, tag = "1")]
    pub common_tls_context: Option<CommonTlsContext>,
    #[prost(message, optional, tag = "2")]
    pub require_client_certificate: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct CommonTlsContext {
    #[prost(string, repeated, tag = "4")]
    pub alpn_protocols: Vec<String>,
    #[prost(message, repeated, tag = "6")]
    pub tls_certificate_sds_secret_configs: Vec<SdsConfig>,
    #[prost(message, optional, tag = "7")]
    pub validation_context_sds_secret_config: Option<SdsConfig>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SdsConfig {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "2")]
    pub sds_config: Option<ConfigSource>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Secret {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, optional, tag = "2")]
    pub tls_certificate: Option<TlsCertificate>,
    #[prost(message, optional, tag = "4")]
    pub validation_context: Option<ValidationContext>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TlsCertificate {
    #[prost(message, optional, tag = "1")]
    pub certificate_chain: Option<DataSource>,
    #[prost(message, optional, tag = "2")]
    pub private_key: Option<DataSource>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ValidationContext {
    #[prost(message, optional, tag = "1")]
    pub trusted_ca: Option<DataSource>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DataSource {
    #[prost(bytes = "vec", tag = "2")]
    pub inline_bytes: Vec<u8>,
}

/// 业务作用：为已构建的固定资源编码标准 Any，不允许调用方插入未经校验的远端原始字节。
///
/// 参数说明：
/// - `url`：固定的 Envoy 消息类型。
/// - `value`：本地投影生成的强类型资源。
///
/// 返回：可放入 ADS 响应的完整资源。
pub(crate) fn pack(url: &str, value: &impl Message) -> Any {
    Any {
        type_url: url.to_owned(),
        value: value.encode_to_vec(),
    }
}

/// 业务作用：把有界毫秒配置编码为 protobuf 时长，统一 TTL 与超时的单位。
///
/// 参数说明：
/// - `ms`：已完成上限校验的毫秒数。
///
/// 返回：非负规范化时长，0 表示显式关闭对应期限。
pub(crate) fn duration(ms: u64) -> Duration {
    Duration {
        seconds: (ms / 1000) as i64,
        nanos: ((ms % 1000) * 1_000_000) as i32,
    }
}

/// 业务作用：让派生资源的依赖继续通过同一 ADS 权威获取，禁止隐藏的文件或第二管理端来源。
///
/// 参数说明: 无。
///
/// 返回：只声明 ADS 和 v3 API 的配置源。
pub(crate) fn ads() -> ConfigSource {
    ConfigSource {
        ads: Some(Empty {}),
        resource_api_version: 2,
    }
}
