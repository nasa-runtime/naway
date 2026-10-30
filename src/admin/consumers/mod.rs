//! 消费者目录只保留已编译的低敏凭据绑定，不枚举外部身份源或读取密钥材料。

mod model;
pub(super) mod read;

#[cfg(any(test, feature = "admin-grpc"))]
pub(in crate::admin) use model::digest;
#[cfg(feature = "admin-grpc")]
pub(in crate::admin) use model::MAX_ENTRIES;
pub(in crate::admin) use model::{Directory, Entry, MAX_BYTES};

use crate::config::GatewaySnapshot;
use std::sync::{Arc, Weak};

#[derive(Default)]
pub(in crate::admin) struct Runtime {
    local: parking_lot::Mutex<Option<(Weak<GatewaySnapshot>, Arc<Directory>)>>,
}

impl Runtime {
    /// 业务作用：让全部管理接收端和本机读取共享同代消费者目录，不按心跳重复收集身份。
    ///
    /// 参数说明：
    /// - `snapshot`：已发布的完整不可变执行计划。
    ///
    /// 返回：同代共享目录；过量声明只影响观察能力，不改变实际认证策略。
    pub(in crate::admin) fn local(&self, snapshot: &Arc<GatewaySnapshot>) -> Arc<Directory> {
        let mut local = self.local.lock();
        if let Some((owner, directory)) = local.as_ref() {
            if owner
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, snapshot))
            {
                return directory.clone();
            }
        }
        let directory = Arc::new(model::collect(snapshot));
        *local = Some((Arc::downgrade(snapshot), directory.clone()));
        directory
    }
}
