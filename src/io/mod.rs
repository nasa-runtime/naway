//! 流式 IO、响应类型、静态资源与有界读取。

pub(crate) mod bounded_io;
pub(crate) mod compression;
#[cfg(feature = "media-streaming")]
pub mod media;
pub mod net;
pub(crate) mod request_decompression;
pub mod resp;
pub mod static_serve;
#[cfg(feature = "webdav")]
pub mod webdav;
