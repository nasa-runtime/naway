//! 受控策略插件、Wasm 与外部处理器。

pub(crate) mod degraphql;
pub(crate) mod ext_proc;
pub(crate) mod external_plugin;
pub(crate) mod graphql;
pub(crate) mod resources;
#[cfg(feature = "lua-scripts")]
pub(crate) mod scripts;
pub(crate) mod wasm;
