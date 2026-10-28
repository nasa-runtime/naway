//! 类型化动作交付与有界正文，不把网络确认解释为持久效果。

mod admission;
mod body;
mod client;
#[cfg(feature = "admin-operations-workflow-pgsql")]
mod delivery;
mod execution;
mod fields;
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(in crate::admin) mod local;
mod release;
mod release_wire;
mod result;
mod window;

pub(in crate::admin) use admission::Work;
pub(super) use client::Channel;
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(in crate::admin::management) use delivery::Offer;
mod wire;

/// 已认证接收槽当前持有的地址身份，不包含写权或永久节点资格。
#[cfg(feature = "admin-operations-workflow-pgsql")]
pub(in crate::admin) struct ActionSession {
    pub(in crate::admin) boot: String,
    pub(in crate::admin) token: [u8; 32],
}
