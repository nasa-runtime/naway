//! 传输协议适配与协议资源门禁。

#[cfg(any(feature = "fastcgi", feature = "uwsgi", feature = "scgi"))]
pub(crate) mod cgi;

pub(crate) mod dubbo;
pub mod forward_proxy;
pub(crate) mod grpc_transcoding;
#[cfg(feature = "http3")]
pub(crate) mod h3_quinn_tracked;
#[cfg(feature = "http3")]
pub mod http3;
#[cfg(feature = "kafka-governance")]
pub mod kafka;
pub mod masque;
#[cfg(feature = "mqtt-governance")]
pub mod mqtt;
pub mod proxy_protocol;
pub mod ws_frame;
