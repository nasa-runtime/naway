//! 命名扩展仅提供已经实现的路由终结器权威，不装载外部代码或解释任意配置。

mod state;
mod wire;

pub(crate) use wire::translate_resources;
pub(super) use wire::{translate_filter, validate_source_wire, ExtensionConfigSource};

pub(crate) const ECDS_TYPE_URL: &str =
    "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig";
