//! 集群配置对象目录只公开固定摘要，不把配置声明解释为运行健康或完整配置一致。

mod model;
mod read;
mod scopes;
pub(super) mod workspace;
pub(super) use read::read;

#[cfg(feature = "admin-grpc")]
pub(in crate::admin) use model::{digest, MAX_BYTES, MAX_OBJECTS};
pub(in crate::admin) use model::{Catalog, Entry};
pub(in crate::admin) use scopes::{scope_digest, ScopeAuthority};

use crate::config::GatewaySnapshot;
use std::sync::{Arc, Weak};

pub(in crate::admin) struct Runtime {
    local: parking_lot::Mutex<Option<(Weak<GatewaySnapshot>, Arc<Catalog>)>>,
    requests: tokio::sync::Semaphore,
}

impl Default for Runtime {
    /// 业务作用：限制同一进程的目录聚合并发，观察者数量不能无限放大控制面内存。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：八个同步读取槽与空的本机目录缓存。
    fn default() -> Self {
        Self {
            local: parking_lot::Mutex::new(None),
            requests: tokio::sync::Semaphore::new(8),
        }
    }
}

impl Runtime {
    /// 业务作用：让上报与本机目录读取共享同代对象摘要，不在每次心跳重新扫描或编码配置。
    ///
    /// 参数说明：
    /// - `snapshot`：唯一已发布的不可变配置。
    ///
    /// 返回：同代共享目录；过量对象明确标记容量不足，绝不交付截断清单。
    pub(in crate::admin) fn local(&self, snapshot: &Arc<GatewaySnapshot>) -> Arc<Catalog> {
        let mut local = self.local.lock();
        if let Some((owner, catalog)) = local.as_ref() {
            if owner
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, snapshot))
            {
                return catalog.clone();
            }
        }
        let catalog = Arc::new(model::collect(snapshot));
        *local = Some((Arc::downgrade(snapshot), catalog.clone()));
        catalog
    }
}
